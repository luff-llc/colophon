package works.luff.colophon.testapp

import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.HttpRequest
import com.luff.colophon.session.HomeLimits
import com.luff.colophon.session.HomeTransport
import com.luff.colophon.session.HomeTransportException
import com.luff.colophon.session.HttpHomeTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Base64

/** What this device last heard from its home, as the transport saw it (the engine verifies everything). */
data class HomeSighting(
    val head: Head? = null,
    val last: Answer? = null,
    val lastRefusal: Answer? = null,
    val transportError: String? = null,
    val requests: Int = 0,
) {
    data class Head(val seq: Long, val issued: String, val atMs: Long)
    data class Answer(val method: String, val path: String, val status: Int, val detail: String, val atMs: Long)
}

class HomeObserver {
    @Volatile private var state = HomeSighting()
    fun snapshot(): HomeSighting = state
    @Synchronized fun reset() { state = HomeSighting() }

    @Synchronized fun record(method: String, path: String, answer: HttpAnswer) {
        val status = answer.status.toInt()
        val seen = HomeSighting.Answer(method, path, status, if (status >= 400) refusalDetail(answer.body) else "", System.currentTimeMillis())
        val head = if ((path.endsWith("/head") || path.contains("/records/heads/")) && status == 200) head(answer.body) else null
        // A 401 asks for a call (the session then sends one); it is not a refusal.
        state = state.copy(last = seen, requests = state.requests + 1, transportError = null,
            lastRefusal = if (status >= 400 && status != 401) seen else state.lastRefusal, head = head ?: state.head)
    }
    @Synchronized fun record(error: Throwable) { state = state.copy(transportError = error.toString()) }

    private fun refusalDetail(body: ByteArray): String =
        try { JSONObject(String(body)).optString("result").ifEmpty { null } } catch (_: Exception) { null }
            ?: String(body.copyOf(minOf(body.size, 200)))

    /** A signed head is an envelope whose `body` is base64 JSON with `authority.seq` and `issued`. */
    private fun head(data: ByteArray): HomeSighting.Head? = try {
        val text = JSONObject(String(data)).getString("body")
        val bytes = try { Base64.getDecoder().decode(text) } catch (_: Exception) { Base64.getUrlDecoder().decode(text) }
        val body = JSONObject(String(bytes))
        fun find(o: JSONObject, key: String): Any? {
            if (o.has(key)) return o.get(key)
            for (k in o.keys()) { val child = o.opt(k); if (child is JSONObject) find(child, key)?.let { return it } }
            return null
        }
        val seq = (find(body, "seq") as? Number)?.toLong()
        seq?.let { HomeSighting.Head(it, (find(body, "issued") as? String) ?: "-", System.currentTimeMillis()) }
    } catch (_: Exception) { null }
}

/**
 * The session's transport to the home. When `reachPrefix` is set, a URL under the account's home prefix (the `https`
 * name the account appoints) goes to the same path under `reachPrefix`: a relay on the Mac, which the emulator reaches
 * through `adb reverse` on its own loopback. Plain `http` only to a loopback address (the SDK's rule).
 */
class MappedTransport(homePrefix: String, reachPrefix: String, private val observer: HomeObserver) : HomeTransport {
    private val home = if (homePrefix.endsWith("/")) homePrefix else "$homePrefix/"
    private val reach = if (reachPrefix.isEmpty() || reachPrefix.endsWith("/")) reachPrefix else "$reachPrefix/"
    private val inner = HttpHomeTransport(allowingLoopbackHttp = reach.isNotEmpty())

    override suspend fun send(request: HttpRequest): HttpAnswer {
        var url = request.url
        if (reach.isNotEmpty()) {
            if (!url.startsWith(home)) throw HomeTransportException.InvalidRequest("not under the home prefix: $url")
            url = reach + url.removePrefix(home)
        }
        val method = when (request.method) { HttpMethod.GET -> "GET"; HttpMethod.POST -> "POST"; HttpMethod.PUT -> "PUT" }
        val path = try { URI(request.url).path } catch (_: Exception) { request.url }
        return try {
            inner.send(request.copy(url = url)).also { observer.record(method, path, it) }
        } catch (e: Exception) {
            observer.record(e); throw e
        }
    }
}

/** Asks the home service for the home's signed member request for a new account (it provisions the slot first). */
object Provisioner {
    class Failure(message: String) : Exception(message)

    suspend fun memberRequest(service: String, slot: String, base: String, account: String): ByteArray = withContext(Dispatchers.IO) {
        if (!(service.startsWith("https://") || HomeLimits.isAllowed(service, true))) {
            throw Failure("The home service URL must be https, or http on this device's loopback: $service")
        }
        val connection = URL(service).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = 15_000; connection.readTimeout = 30_000
            connection.instanceFollowRedirects = false
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            val body = JSONObject().put("slot", slot).put("base", base).put("account", account).toString().toByteArray()
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            if (status != 200) throw Failure("The home service answered $status: ${String(bytes.copyOf(minOf(bytes.size, 300)))}")
            bytes
        } finally { connection.disconnect() }
    }
}
