package com.luff.colophon.hosts

import com.luff.colophon.Header
import com.luff.colophon.HttpAnswer
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.net.http.WebSocketHandshakeException
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.CompletionStage
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * The stream's socket on the JVM: `java.net.http.WebSocket` (Java 11+). Not available on Android, which has no
 * `java.net.http`; this file is in the JVM module only (`src/jvm`), never in the Android library.
 *
 * What it reports and what it cannot:
 * - A refused upgrade is reported with [SocketHandlers.refused] carrying the HTTP status and headers. The JDK discards
 *   the refused answer's body, so the body is empty: a `403 {"result":"refused:revoked"}` reads to the core as a 403
 *   without a result (it backs off and mints again, within its budget and breaker) instead of ending access at once; a
 *   revoked member still learns it from its next exchange pass, and close 1008 still ends a live stream.
 * - A close code the JDK refuses to send from a client (1002, for example) is sent as 1000; the stream host still tells
 *   the core the code it asked for.
 * - Messages are joined from their fragments and bounded by `maxMessage` characters; a longer one fails the socket
 *   (reported as a transport failure).
 * - Binary messages are ignored: the home sends only text.
 */
class JdkWebSocketFactory(
    private val client: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build(),
    private val maxMessage: Int = 64 * 1024,
) : SocketFactory {
    override fun open(url: String, handlers: SocketHandlers): HostSocket {
        val ended = AtomicBoolean(false)
        fun end(code: Int?) { if (ended.compareAndSet(false, true)) handlers.closed(code) }
        val text = StringBuilder()
        val listener = object : WebSocket.Listener {
            override fun onOpen(webSocket: WebSocket) { if (!ended.get()) handlers.open(); webSocket.request(1) }
            override fun onText(webSocket: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
                if (ended.get()) return null
                if (text.length + data.length > maxMessage) { webSocket.abort(); end(null); return null }
                text.append(data)
                if (last) { val m = text.toString(); text.setLength(0); handlers.message(m) }
                webSocket.request(1)
                return null
            }
            override fun onBinary(webSocket: WebSocket, data: java.nio.ByteBuffer, last: Boolean): CompletionStage<*>? { webSocket.request(1); return null }
            override fun onClose(webSocket: WebSocket, statusCode: Int, reason: String): CompletionStage<*>? {
                // 1005 (no code) and 1006 (abnormal) are never sent on the wire: no code.
                end(if (statusCode == 1005 || statusCode == 1006) null else statusCode)
                return null
            }
            override fun onError(webSocket: WebSocket, error: Throwable) = end(null)
        }
        val opening: CompletableFuture<WebSocket> = client.newWebSocketBuilder().buildAsync(URI(url), listener)
        val socket = AtomicReference<WebSocket?>(null)
        val closed = AtomicBoolean(false)
        opening.whenComplete { ws, error ->
            if (ws != null) {
                socket.set(ws)
                // Closed while it opened: the upgrade is abandoned and the connection dropped.
                if (closed.get()) ws.abort()
                return@whenComplete
            }
            if (closed.get()) return@whenComplete
            val cause = (error as? CompletionException)?.cause ?: error
            val refused = cause as? WebSocketHandshakeException
            if (refused != null) {
                val response = refused.response
                if (ended.compareAndSet(false, true)) {
                    val headers = response.headers().map().flatMap { (name, values) -> values.map { Header(name, it) } }.take(256)
                    handlers.refused(HttpAnswer(response.statusCode().toUInt(), headers, ByteArray(0)))
                }
            } else end(null)
        }
        // One send at a time: the JDK refuses a send while the previous one is outstanding.
        var tail: CompletableFuture<*> = opening
        val sendLock = Any()
        return object : HostSocket {
            override fun send(text: String) {
                val ws = socket.get() ?: throw IllegalStateException("the socket is not open")
                if (closed.get() || ended.get()) throw IllegalStateException("the socket is closed")
                synchronized(sendLock) { tail = tail.handle { _, _ -> null }.thenCompose { ws.sendText(text, true) } }
            }
            override fun close(code: Int) {
                if (!closed.compareAndSet(false, true)) return
                ended.set(true)
                // Still opening: the completion above drops the connection when it arrives.
                val ws = socket.get() ?: return
                val sent = try { ws.sendClose(code, "") } catch (_: IllegalArgumentException) { ws.sendClose(WebSocket.NORMAL_CLOSURE, "") }
                sent.whenComplete { _, _ -> ws.abort() }
            }
        }
    }
}
