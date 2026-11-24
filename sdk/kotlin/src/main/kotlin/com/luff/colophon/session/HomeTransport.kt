package com.luff.colophon.session

import com.luff.colophon.ExchangeFault
import com.luff.colophon.Header
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.HttpRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * Performs the HTTP requests the engine returns for a home (`ExchangeStep.request`). The engine owns every decision:
 * this only moves bytes. Implement it to test with an in-process home.
 */
fun interface HomeTransport {
    suspend fun send(request: HttpRequest): HttpAnswer
}

sealed class HomeTransportException(message: String) : IOException(message) {
    class Offline(val reason: String) : HomeTransportException(reason)
    class InvalidRequest(val reason: String) : HomeTransportException(reason)
    /** The response passed the bound for its kind of request ([HomeLimits.responseBytes]); it was refused unread. */
    class ResponseTooLarge(val limit: Int) : HomeTransportException("response over $limit bytes")
    /** The endpoint is not `https` (plain `http` only to a loopback address with the testing option). */
    class InsecureEndpoint(val url: String) : HomeTransportException("not https: $url")
}

/** The bounds a session holds a home to, so that a hostile or broken home cannot take memory or hold a pass. */
object HomeLimits {
    /** The most bytes of one response: the signed head 64 KiB, a blob chunk 1 MiB, a record 41 MiB, anything else 32 MiB. */
    fun responseBytes(url: String): Int {
        val path = try { URI(url).path ?: url } catch (_: Exception) { url }
        return when {
            path.endsWith("/head") || path.contains("/records/heads/") -> 64 * 1024
            path.contains("/records/blobs/") -> 1024 * 1024
            path.contains("/records/") -> 41 * 1024 * 1024
            else -> 32 * 1024 * 1024
        }
    }
    /** Steps (requests and calls) in one pass with one home, and passes in one exchange. */
    const val STEPS_PER_PASS = 20_000
    const val PASSES = 4
    /** The longest one exchange with one home may take. */
    const val EXCHANGE_TIME_MS = 180_000L

    /**
     * `https`, or `http` to a loopback address when `allowingLoopbackHttp` (tests): `localhost`, a literal IPv4 address
     * in `127.0.0.0/8` (four decimal octets) or the literal `::1`. Parsed, never matched by prefix: a name such as
     * `127.attacker.example` is a remote host.
     */
    fun isAllowed(endpoint: String, allowingLoopbackHttp: Boolean): Boolean {
        val uri = try { URI(endpoint) } catch (_: Exception) { return false }
        val scheme = uri.scheme?.lowercase() ?: return false
        val host = uri.host?.lowercase()?.takeIf { it.isNotEmpty() } ?: return false
        if (scheme == "https") return true
        if (scheme != "http" || !allowingLoopbackHttp) return false
        return isLoopbackLiteral(host)
    }
    internal fun isLoopbackLiteral(host: String): Boolean {
        if (host == "localhost") return true
        val h = host.removePrefix("[").removeSuffix("]")
        if (h == "::1" || h == "0:0:0:0:0:0:0:1") return true
        val parts = h.split('.')
        if (parts.size != 4) return false
        val octets = parts.map { p ->
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' } || (p.length > 1 && p[0] == '0')) return false
            p.toInt()
        }
        return octets.all { it in 0..255 } && octets[0] == 127
    }
}

/**
 * `HttpURLConnection` (no cookies, no cache, no redirects: a redirect is a fault the engine reports), available on
 * the JVM and on Android. Only `https` is sent unless `allowingLoopbackHttp` permits plain `http` to a loopback
 * address. A response is read in pieces and refused as soon as it passes [HomeLimits.responseBytes]. Blocking I/O runs
 * on `Dispatchers.IO` and is interrupted when the caller is cancelled.
 */
class HttpHomeTransport(
    private val allowingLoopbackHttp: Boolean = false,
    private val connectTimeoutMs: Int = 30_000,
    private val readTimeoutMs: Int = 60_000,
) : HomeTransport {
    override suspend fun send(request: HttpRequest): HttpAnswer = runInterruptible(Dispatchers.IO) {
        if (!HomeLimits.isAllowed(request.url, allowingLoopbackHttp)) throw HomeTransportException.InsecureEndpoint(request.url)
        val url = try { URL(request.url) } catch (_: Exception) { throw HomeTransportException.InvalidRequest("not a URL") }
        val limit = HomeLimits.responseBytes(request.url)
        val connection = try { url.openConnection() as HttpURLConnection } catch (e: IOException) { throw HomeTransportException.Offline(e.message ?: "offline") }
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.requestMethod = when (request.method) { HttpMethod.GET -> "GET"; HttpMethod.POST -> "POST"; HttpMethod.PUT -> "PUT" }
            for (h in request.headers) connection.setRequestProperty(h.name, h.value)
            if (request.method != HttpMethod.GET) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(request.body.size)
                connection.outputStream.use { it.write(request.body) }
            }
            val status = connection.responseCode
            if (connection.contentLengthLong > limit) throw HomeTransportException.ResponseTooLarge(limit)
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val body = ByteArrayOutputStream()
            stream?.use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    if (body.size() + n > limit) throw HomeTransportException.ResponseTooLarge(limit)
                    body.write(buffer, 0, n)
                }
            }
            val headers = connection.headerFields.flatMap { (name, values) -> if (name == null) listOf() else values.map { Header(name, it) } }
            HttpAnswer(status.toUInt(), headers, body.toByteArray())
        } catch (e: HomeTransportException) {
            throw e
        } catch (e: IOException) {
            throw HomeTransportException.Offline(e.message ?: e.javaClass.simpleName)
        } finally {
            connection.disconnect()
        }
    }
}

/** Something this host refused about a home on its own account (beside the engine's `ExchangeFault`s). */
sealed class HomeProblem {
    /** The configured endpoint is not `https`; the home is not contacted. */
    data class InsecureEndpoint(val url: String) : HomeProblem()
    /** A response passed its bound and was refused unread. */
    data class ResponseTooLarge(val limit: Int) : HomeProblem()
    /** A pass with this home took more than [HomeLimits.STEPS_PER_PASS] steps; it was stopped. */
    data class TooManySteps(val steps: Int) : HomeProblem()
    /** An exchange with this home took longer than [HomeLimits.EXCHANGE_TIME_MS]; it was stopped. */
    data class TooSlow(val seconds: Int) : HomeProblem()
    /** A request needed a call this host cannot bind to its exact request. No call was sent. */
    data class CallNotBound(val why: String) : HomeProblem()
    /** This device's own check of the call refused it, by the home's rule over what the device holds. No call was sent. */
    data class CallRefused(val code: String) : HomeProblem()
    /** The engine still had a request outstanding after the pass was abandoned and run again once: the pass could not finish, and the exchange failed. */
    object StillWaiting : HomeProblem() { override fun toString() = "StillWaiting" }
    /**
     * A home refused a request of this device with a `refused:<reason>` result (spec §14, §19). [code] is the result as
     * the home gave it, validated against the result grammar and bounded ([HomeRefusal]); a name this session does not
     * know, the reserved `refused:overQuota`, `refused:noEntitlement`, `refused:closed`, `refused:notProvisioned` and
     * `refused:subscriptionLapsed`
     * included, is shown as received. It refuses only that request: an unverified remote claim, never a verified state of
     * the account (`refused:closed` is not evidence that anything was deleted; `refused:revoked` is not proof of
     * revocation). A refused call (401/403) ends the pass; any other refusal lets it go on. [retryAfterSeconds] is the
     * home's `Retry-After`, honoured: the home is not contacted again before then.
     */
    data class RemoteCallRefused(val code: String, val retryAfterSeconds: Int? = null) : HomeProblem()
    /**
     * The home answered `503 {"result":"unavailable"}`: the home is not available (a stopped home answers so, §13.6). It
     * says nothing about this device or the account; the exchange is retried with backoff.
     */
    data class HomeUnavailable(val retryAfterSeconds: Int?) : HomeProblem()
    /**
     * This device asked to join and holds no grant for itself, and a home (or its own check) answered `refused:revoked`:
     * in 0.5 that is the result for a member no grant names (`refused:notGranted` is reserved), so the device is waiting
     * for approval, not revoked. A device that holds its own verified revocation is [SessionPhase.Denied].
     */
    object WaitingForApproval : HomeProblem() { override fun toString() = "WaitingForApproval" }
}

/**
 * The one thing a session reads from a home's error answer: its `result`, only when it is a result the spec's §1 grammar
 * allows (`ok`, `malformed`, `badSignature`, `newerFormat`, `unavailable`, or `refused:<reason>` with a reason of a
 * lower-case letter then letters and digits, at most 48 characters), from a JSON body of at most 64 KiB. Every other byte
 * of the body is dropped, never echoed. With it, `Retry-After` in whole seconds (1 to 86,400).
 */
data class HomeRefusal(val status: Int, val code: String?, val retryAfterSeconds: Int?) {
    /** `503` with `{"result":"unavailable"}`: the home is not available. */
    val isHomeUnavailable: Boolean get() = status == 503 && code == "unavailable"

    companion object {
        val NAMED = setOf("ok", "malformed", "badSignature", "newerFormat", "unavailable")
        /** Null for a success, or an answer that carries neither a valid result nor a `Retry-After`. */
        fun of(status: Int, headers: List<Header>, body: ByteArray): HomeRefusal? {
            if (status < 400) return null
            val code = result(body)
            val retry = headers.firstOrNull { it.name.equals("retry-after", ignoreCase = true) }?.let { seconds(it.value) }
            if (code == null && retry == null) return null
            return HomeRefusal(status, code, retry)
        }
        fun isValid(text: String): Boolean {
            if (text in NAMED) return true
            if (!text.startsWith("refused:") || text.length > 8 + 48) return false
            val reason = text.substring(8)
            if (reason.isEmpty() || reason[0] !in 'a'..'z') return false
            return reason.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' }
        }
        internal fun result(body: ByteArray): String? {
            if (body.size > 64 * 1024) return null
            val text = Json.obj(body.toString(Charsets.UTF_8))?.string("result") ?: return null
            return if (isValid(text)) text else null
        }
        internal fun seconds(text: String): Int? {
            val t = text.trim()
            if (t.isEmpty() || t.length > 6 || !t.all { it in '0'..'9' }) return null
            return t.toInt().takeIf { it in 1..86_400 }
        }
    }
}

/** Words a host may show for a home's state. */
object HomeWords {
    /** [HomeProblem.HomeUnavailable]: the home answered `503 {"result":"unavailable"}`. */
    const val UNAVAILABLE = "The home is not available right now. This app will try again."
}

internal class HomeProblemException(val problem: HomeProblem) : Exception(problem.toString())

data class HomeIssue(val home: String, val problem: HomeProblem)

/** A fault a home raised that the engine did not follow, for the person (or the log) to see. */
data class HomeFault(val home: String, val fault: ExchangeFault)

sealed class HomeSyncState {
    object Disabled : HomeSyncState() { override fun toString() = "Disabled" }
    object Idle : HomeSyncState() { override fun toString() = "Idle" }
    object Syncing : HomeSyncState() { override fun toString() = "Syncing" }
    object Unauthorized : HomeSyncState() { override fun toString() = "Unauthorized" }
    data class Offline(val reason: String) : HomeSyncState()
    data class Error(val reason: String) : HomeSyncState()
}
