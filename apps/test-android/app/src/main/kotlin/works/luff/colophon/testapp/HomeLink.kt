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
        val seen = HomeSighting.Answer(method, path, status, if (status >= 400) (ResultCode.of(answer.body) ?: "no result") else "", System.currentTimeMillis())
        val head = if ((path.endsWith("/head") || path.contains("/records/heads/")) && status == 200) head(answer.body) else null
        // A 401 asks for a call (the session then sends one); it is not a refusal.
        state = state.copy(last = seen, requests = state.requests + 1, transportError = null,
            lastRefusal = if (status >= 400 && status != 401) seen else state.lastRefusal, head = head ?: state.head)
    }
    @Synchronized fun record(error: Throwable) { state = state.copy(transportError = error.toString()) }

    /** A head's `issued` as a plain UTC date, or "-": nothing else from a response body is kept. */
    companion object {
        private val DATE = Regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z\$")
        fun plainDate(value: Any?): String = (value as? String)?.takeIf { it.length <= 30 && DATE.matches(it) } ?: "-"
    }

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
        seq?.let { HomeSighting.Head(it, plainDate(find(body, "issued")), System.currentTimeMillis()) }
    } catch (_: Exception) { null }
}

/**
 * The session's transport to the home. When `reachPrefix` is set, a URL under the account's home prefix (the `https`
 * name the account appoints) goes to the same path under `reachPrefix`: a relay on the Mac, which the emulator reaches
 * through `adb reverse` on its own loopback. Plain `http` only to a loopback address (the SDK's rule).
 */
class MappedTransport(homePrefix: String, reachPrefix: String, private val observer: HomeObserver, inner: HomeTransport? = null) : HomeTransport {
    private val home = if (homePrefix.endsWith("/")) homePrefix else "$homePrefix/"
    private val reach = if (reachPrefix.isEmpty() || reachPrefix.endsWith("/")) reachPrefix else "$reachPrefix/"
    // `inner` is for tests; by default HttpHomeTransport, loopback http allowed only when a reach prefix is set.
    private val inner: HomeTransport = inner ?: HttpHomeTransport(allowingLoopbackHttp = reach.isNotEmpty())

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

    suspend fun memberRequest(service: String, token: String, slot: String, base: String, account: String): ByteArray = withContext(Dispatchers.IO) {
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
            if (token.isNotEmpty()) connection.setRequestProperty("Authorization", "Bearer $token")
            val body = JSONObject().put("slot", slot).put("base", base).put("account", account).toString().toByteArray()
            // A fixed length, never a chunked body: the staging home refuses chunked requests (411).
            connection.setFixedLengthStreamingMode(body.size)
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            if (status != 200) throw Failure("The home service answered $status")
            bytes
        } finally { connection.disconnect() }
    }
}

/**
 * The one thing from a refusal body the app shows or logs: its `result`, and only when it is a result the spec's §1
 * grammar allows (`ok`, `malformed`, `badSignature`, `newerFormat`, `unavailable`, `refused:<reason>` with a short
 * alphanumeric reason). Anything else, and every other byte of the body, is dropped: a hostile home could put record
 * or call bytes there. The iPhone app's `ResultCode` is the same rule.
 */
object ResultCode {
    private val NAMED = setOf("ok", "malformed", "badSignature", "newerFormat", "unavailable")
    private val REFUSED = Regex("^refused:[a-z][A-Za-z0-9]{0,47}$")
    fun isValid(text: String): Boolean = text in NAMED || REFUSED.matches(text)
    fun of(body: ByteArray): String? {
        if (body.size > 64 * 1024) return null
        val result = try { JSONObject(String(body)).opt("result") as? String } catch (_: Exception) { null } ?: return null
        return result.takeIf { isValid(it) }
    }
}
