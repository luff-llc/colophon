package com.luff.colophon.hosts

import com.luff.colophon.HttpAnswer
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicIntegerArray
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The JDK socket reports every send's outcome exactly once: a peer that accepts the upgrade and then drops the
 * connection (a reset) while the client sends as fast as it can leaves no send without an outcome and none with two.
 */
class JdkSocketTest {
    @Test(timeout = 60_000) fun eachSendEndsExactlyOnceWhenThePeerDropsTheConnection() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val opened = CountDownLatch(1)
            val closed = CountDownLatch(1)
            val peer = Thread {
                server.accept().use { s ->
                    val input = s.getInputStream()
                    val head = StringBuilder()
                    while (!head.endsWith("\r\n\r\n")) { val b = input.read(); if (b < 0) return@use; head.append(b.toChar()) }
                    val key = head.lines().first { it.lowercase().startsWith("sec-websocket-key:") }.substringAfter(':').trim()
                    val accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray()))
                    s.getOutputStream().apply { write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n".toByteArray()); flush() }
                    opened.await(10, TimeUnit.SECONDS)
                    Thread.sleep(20)
                    s.setSoLinger(true, 0) // a reset, not a close handshake
                }
            }.apply { start() }
            val socket = JdkWebSocketFactory().open("ws://127.0.0.1:${server.localPort}/stream", object : SocketHandlers {
                override fun open() = opened.countDown()
                override fun message(text: String) {}
                override fun refused(answer: HttpAnswer) = closed.countDown()
                override fun closed(code: Int?) = closed.countDown()
            })
            assertTrue(opened.await(10, TimeUnit.SECONDS), "the upgrade completed")
            val total = 5_000
            val outcomes = AtomicIntegerArray(total)
            val carried = AtomicIntegerArray(total)
            var thrown = 0
            for (i in 0 until total) {
                try { socket.send("m$i".repeat(20)) { ok -> outcomes.incrementAndGet(i); if (ok) carried.incrementAndGet(i) } } catch (_: IllegalStateException) { thrown++; outcomes.incrementAndGet(i) }
            }
            assertTrue(closed.await(20, TimeUnit.SECONDS), "the reset was reported")
            val end = System.currentTimeMillis() + 20_000
            while ((0 until total).any { outcomes.get(it) == 0 }) { check(System.currentTimeMillis() < end) { "a send has no outcome" }; Thread.sleep(5) }
            Thread.sleep(200)
            assertEquals(listOf(), (0 until total).filter { outcomes.get(it) != 1 }, "every send ended exactly once")
            val handed = (0 until total).count { carried.get(it) == 1 }
            println("jdk socket: $handed handed to the connection, ${total - handed - thrown} failed after they were queued, $thrown refused at once")
            socket.close(1000)
            peer.join(5_000)
        }
    }
}
