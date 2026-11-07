package org.luff.colophon

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.security.MessageDigest

/**
 * A Colophon 0.3 HTTP exchange endpoint (spec §8): one library slot URL and its storage token.
 * The token grants relay storage only; it is never library membership.
 */
data class RelayEndpoint(val url: String, val token: String?) {
    override fun toString(): String = "RelayEndpoint(url=$url, token=${if (token == null) "none" else "<redacted>"})"
}

class RelayHttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String>,
    val body: ByteArray?,
    val timeoutMillis: Int,
)

/** Header names are lowercased. */
class RelayHttpResponse(val status: Int, val headers: Map<String, String> = emptyMap(), val body: ByteArray = ByteArray(0))

/**
 * The HTTP seam. Blocking; the session calls it off its own thread. Throw
 * [RelayException.Offline] for transport failures.
 */
fun interface RelayTransport {
    fun send(request: RelayHttpRequest): RelayHttpResponse
}

/** `java.net.HttpURLConnection` transport: no third-party HTTP dependency. */
class HttpUrlConnectionTransport(private val maximumResponseBytes: Int = 17 * 1024 * 1024) : RelayTransport {
    override fun send(request: RelayHttpRequest): RelayHttpResponse {
        val connection = try {
            URI(request.url).toURL().openConnection() as HttpURLConnection
        } catch (error: Exception) {
            throw RelayException.ProtocolViolation("Invalid relay URL")
        }
        try {
            connection.requestMethod = request.method
            connection.connectTimeout = 10_000
            connection.readTimeout = request.timeoutMillis
            connection.useCaches = false
            connection.instanceFollowRedirects = false
            for ((name, value) in request.headers) connection.setRequestProperty(name, value)
            val body = request.body
            if (body != null) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream: InputStream? = if (status >= 400) connection.errorStream else connection.inputStream
            val bytes = stream?.use { readBounded(it) } ?: ByteArray(0)
            val headers = connection.headerFields.entries
                .filter { it.key != null && it.value.isNotEmpty() }
                .associate { it.key.lowercase() to it.value.last() }
            return RelayHttpResponse(status, headers, bytes)
        } catch (error: RelayException) {
            throw error
        } catch (error: IOException) {
            throw RelayException.Offline(error.message ?: error.toString())
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (out.size() + read > maximumResponseBytes) throw RelayException.ProtocolViolation("Oversized relay response")
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}

sealed class RelayException(message: String) : Exception(message) {
    /** The relay could not be reached. Never evidence that a library is empty. */
    class Offline(val reason: String) : RelayException("The relay is unreachable: $reason")
    /** The relay refused the storage token (401/403). */
    class Unauthorized : RelayException("The relay refused this device's storage token.")
    /** The relay cannot continue the cursor (410). */
    class CursorReset : RelayException("The relay reset its change feed.")
    /** The slot holds a different library than the local store. */
    class DifferentLibrary : RelayException("The relay holds a different library than this device.")
    /** 429 or 503; `retryAfterSeconds` when the relay said. */
    class Busy(val retryAfterSeconds: Long?) : RelayException("The relay is busy. Sync will retry.")
    class ProtocolViolation(detail: String) : RelayException("The relay sent an invalid response: $detail")
    class Server(val status: Int, detail: String) : RelayException("The relay failed ($status): $detail")
}

/** Typed client for the §8.2 endpoints. Holds no state beyond the endpoint. */
class RelayClient(val endpoint: RelayEndpoint, private val transport: RelayTransport = HttpUrlConnectionTransport()) {
    data class Entry(val path: String, val size: Long?, val sha256: String?, val deleted: Boolean)
    data class ChangePage(val entries: List<Entry>, val cursor: String, val more: Boolean)
    enum class PutResult { CREATED, PRESENT, CONFLICT }

    private val base = endpoint.url.trimEnd('/')

    private fun request(method: String, suffix: String, body: ByteArray? = null, headers: Map<String, String> = emptyMap(), timeoutMillis: Int = 30_000): RelayHttpResponse {
        val all = headers.toMutableMap()
        endpoint.token?.let { all["Authorization"] = "Bearer $it" }
        return transport.send(RelayHttpRequest(method, base + suffix, all, body, timeoutMillis))
    }

    private fun check(response: RelayHttpResponse, vararg allowed: Int) {
        if (response.status in allowed) return
        when (response.status) {
            401, 403 -> throw RelayException.Unauthorized()
            410 -> throw RelayException.CursorReset()
            429, 503 -> throw RelayException.Busy(response.headers["retry-after"]?.toLongOrNull())
            else -> {
                val detail = try {
                    (JsonParser(response.body.decodeToString()).parseValue() as? Json.Obj)?.string("error")
                } catch (_: Exception) {
                    null
                }
                throw RelayException.Server(response.status, detail ?: "")
            }
        }
    }

    /** `GET {base}`: proves the slot and token are accepted. */
    fun info(): ByteArray = request("GET", "").also { check(it, 200) }.body

    fun changes(after: String?, limit: Int = 500, wait: Int = 0, namespaces: List<String> = emptyList()): ChangePage {
        val query = StringBuilder("?limit=$limit")
        if (!after.isNullOrEmpty()) query.append("&after=").append(URLEncoder.encode(after, Charsets.UTF_8))
        if (wait > 0) query.append("&wait=$wait")
        for (namespace in namespaces) {
            query.append("&namespace=").append(URLEncoder.encode(namespace, Charsets.UTF_8))
        }
        val response = request("GET", "/changes$query", timeoutMillis = (wait + 30) * 1000)
        check(response, 200)
        return try {
            val root = JsonParser(response.body.decodeToString()).parseValue() as Json.Obj
            val entries = root.array("entries").map { item ->
                val entry = item as Json.Obj
                Entry(
                    path = entry.string("path") ?: throw IllegalArgumentException("path"),
                    size = (entry.fields["size"] as? Json.Number)?.raw?.toLongOrNull(),
                    sha256 = entry.string("sha256"),
                    deleted = entry.bool("deleted") == true,
                )
            }
            ChangePage(entries, root.string("cursor") ?: throw IllegalArgumentException("cursor"), root.bool("more") == true)
        } catch (error: Exception) {
            throw RelayException.ProtocolViolation("Unreadable change page")
        }
    }

    /** Exact stored bytes, or null when the relay has no record at [path]. */
    fun get(path: String): ByteArray? {
        val response = request("GET", "/records/$path")
        if (response.status == 404) return null
        check(response, 200)
        if (response.body.size > AtomicFile.MAX_RECORD_BYTES) throw RelayException.ProtocolViolation("Oversized record")
        return response.body
    }

    fun putIfAbsent(path: String, bytes: ByteArray): PutResult {
        val headers = mutableMapOf("Content-Type" to "application/octet-stream")
        if (!path.startsWith("state/")) headers["If-None-Match"] = "*"
        val response = request(
            "PUT", "/records/$path", bytes,
            headers, 60_000,
        )
        return when (response.status) {
            201 -> PutResult.CREATED
            200 -> PutResult.PRESENT
            412 -> PutResult.CONFLICT
            else -> {
                check(response)
                PutResult.CONFLICT
            }
        }
    }
}

internal fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
