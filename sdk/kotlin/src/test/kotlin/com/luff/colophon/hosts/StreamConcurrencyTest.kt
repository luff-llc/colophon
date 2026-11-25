package com.luff.colophon.hosts

import com.luff.colophon.AccountEngine
import com.luff.colophon.HomeStream
import com.luff.colophon.NoHandle
import com.luff.colophon.StreamConfig
import com.luff.colophon.StreamStatus
import com.luff.colophon.StreamStep
import com.luff.colophon.StreamEvent
import com.luff.colophon.streamDefaultConfig
import kotlinx.coroutines.asCoroutineDispatcher
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The stream client is driven only from its host's own serial context, even when cells on other threads send frames
 * all at once: real threads, a real `HomeStream`, the stream host on its own thread. Every client call is recorded
 * with the thread it ran on; every frame a cell handed over is carried once, in the order that cell gave it.
 */
class StreamConcurrencyTest {
    /** The real client, recording the thread of every call the host makes. */
    private class Recording(base: String, config: StreamConfig) : HomeStream("h", base, config, null) {
        val threads: MutableSet<String> = Collections.synchronizedSet(HashSet())
        private fun on() { threads.add(Thread.currentThread().name) }
        override fun next(nowMs: Long): StreamStep { on(); return super.next(nowMs) }
        override fun onFrame(text: String, nowMs: Long): List<StreamEvent> { on(); return super.onFrame(text, nowMs) }
        override fun status(): StreamStatus { on(); return super.status() }
        override fun polling(): Boolean { on(); return super.polling() }
        override fun cursor(): String? { on(); return super.cursor() }
        override fun sessionFrame(frame: String, id: String?): String { on(); return super.sessionFrame(frame, id) }
        override fun subscribe(namespace: String, cell: String, id: String?): String { on(); return super.subscribe(namespace, cell, id) }
    }

    @Test(timeout = 120_000) fun cellsSendingFromManyThreadsNeverCallTheClientOffItsOwnContext() {
        repeat(5) { round ->
            val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "stream-host-$round") }
            val dispatcher = executor.asCoroutineDispatcher()
            val client = Recording("https://home.test/v1/accounts/x", streamDefaultConfig())
            val sent: MutableList<String> = Collections.synchronizedList(ArrayList())
            var handlers: SocketHandlers? = null
            val opened = CountDownLatch(1)
            val socket = SocketFactory { _, h ->
                handlers = h; opened.countDown()
                object : HostSocket { override fun send(text: String, done: (Boolean) -> Unit) { sent.add(text); done(true) }; override fun close(code: Int) {} }
            }
            val engine = object : AccountEngine(NoHandle) { override fun headSeq(): ULong = 5uL }
            val account = object : HostAccount {
                override val account = "a".repeat(64); override val member = "m"
                override fun engine() = engine
                override suspend fun streamCall(home: String) = """{"a call":1}""".toByteArray()
                override suspend fun exchange() {}
                override suspend fun signRaw(body: ByteArray) = ByteArray(64)
            }
            val host = HomeStreamHost.withClient(StreamHostOptions(HostAccess.of(account), "h", socket, TicketTransport(), SystemHostClock, dispatcher = dispatcher), client)
            host.start()
            opened.await()
            val numbers = FrameNumbers()
            handlers!!.open(); handlers!!.message(numbers.hello())
            val end = System.currentTimeMillis() + 10_000
            while (!host.live) { check(System.currentTimeMillis() < end) { "the stream did not go live" }; Thread.sleep(1) }

            // Eight cells send 300 frames each, all at once, while the home keeps sending frames of its own.
            val senders = 8; val each = 300
            val start = CountDownLatch(1)
            val accepted = AtomicInteger(); val refused = AtomicInteger()
            val cells = (0 until senders).map { k ->
                Thread {
                    start.await()
                    repeat(each) { i ->
                        val frame = """{"account":"${"a".repeat(64)}","cell":"now-playing","namespace":"listening.podcasts","n":${k * 10_000 + i + 1}}"""
                        if (host.sendSession(frame)) accepted.incrementAndGet() else refused.incrementAndGet()
                    }
                }.apply { start() }
            }
            val home = Thread { start.await(); repeat(500) { handlers!!.message(numbers.frame(mapOf("type" to "pong", "t" to it))) } }.apply { start() }
            start.countDown()
            cells.forEach { it.join() }; home.join()
            val carried = { synchronized(sent) { sent.count { it.startsWith("{\"type\":\"session\"") } } }
            while (carried() < accepted.get()) { check(System.currentTimeMillis() < end + 20_000) { "frames were not carried" }; Thread.sleep(2) }

            assertEquals(setOf("stream-host-$round"), client.threads.toSet(), "every client call ran on the stream host's own thread")
            // Bounded: what was not refused at once was carried; nothing was dropped silently.
            assertEquals(senders * each, accepted.get() + refused.get())
            assertTrue(accepted.get() >= HomeStreamHost.MAX_PENDING_FRAMES)
            // Each cell's carried frames are carried once, in the order it gave them.
            val bySender = synchronized(sent) { sent.toList() }.filter { it.startsWith("{\"type\":\"session\"") }
                .map { (Regex("\"n\":(\\d+)").find(it)!!.groupValues[1].toInt() - 1).let { n -> n / 10_000 to n % 10_000 } }
                .groupBy({ it.first }, { it.second })
            assertEquals(accepted.get(), bySender.values.sumOf { it.size })
            for ((k, carriedOf) in bySender) assertEquals(carriedOf.sorted().distinct(), carriedOf, "sender $k")
            assertTrue(host.live)
            host.stop()
            Thread.sleep(20)
            executor.shutdown()
        }
    }
}
