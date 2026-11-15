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

    /** `https`, or `http` to `localhost`, `127.0.0.0/8` or `::1` when `allowingLoopbackHttp` (tests). */
    fun isAllowed(endpoint: String, allowingLoopbackHttp: Boolean): Boolean {
        val uri = try { URI(endpoint) } catch (_: Exception) { return false }
        val scheme = uri.scheme?.lowercase() ?: return false
        val host = uri.host?.lowercase()?.takeIf { it.isNotEmpty() } ?: return false
        if (scheme == "https") return true
        if (scheme != "http" || !allowingLoopbackHttp) return false
        return host == "localhost" || host.endsWith(".localhost") || host == "::1" || host == "[::1]" || host.startsWith("127.")
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
