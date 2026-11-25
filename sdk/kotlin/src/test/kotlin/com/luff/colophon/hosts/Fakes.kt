package com.luff.colophon.hosts

import com.luff.colophon.Header
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpRequest
import com.luff.colophon.session.HomeTransport
import com.luff.colophon.session.Json
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.coroutines.CoroutineContext

/**
 * A serial context the test drives: every task a host posts waits here until [settle] or [run] runs it, on the test
 * thread, one at a time (the Kotlin counterpart of the JavaScript tests' microtask queue). Work that leaves for another
 * thread (an engine lane, a JNA call) comes back as a task.
 */
class ManualLoop {
    private val tasks = LinkedBlockingQueue<Runnable>()
    val dispatcher: CoroutineDispatcher = object : CoroutineDispatcher() {
        override fun dispatch(context: CoroutineContext, block: Runnable) { tasks.add(block) }
    }
    /** Runs every task queued (and every task those queue); with `quietMs`, keeps waiting that long for more. */
    fun settle(quietMs: Long = 0) {
        while (true) {
            val t = tasks.poll() ?: (if (quietMs > 0) tasks.poll(quietMs, TimeUnit.MILLISECONDS) else null) ?: return
            t.run()
        }
    }
    /** Runs `block` on this context to completion, driving the loop meanwhile. */
    fun <T> run(timeoutMs: Long = 30_000, block: suspend CoroutineScope.() -> T): T {
        val d = start(block)
        val end = System.currentTimeMillis() + timeoutMs
        while (!d.isCompleted) {
            check(System.currentTimeMillis() < end) { "the loop did not finish within $timeoutMs ms" }
            tasks.poll(5, TimeUnit.MILLISECONDS)?.run()
        }
        @Suppress("OPT_IN_USAGE") return d.getCompleted()
    }
    fun <T> start(block: suspend CoroutineScope.() -> T): Deferred<T> = CoroutineScope(dispatcher).async(block = block)
    /** Drives the loop until `condition`, up to `ms` of real time. */
    fun until(what: String, ms: Long = 10_000, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + ms
        while (!condition()) {
            check(System.currentTimeMillis() < end) { "$what did not happen within $ms ms" }
            tasks.poll(5, TimeUnit.MILLISECONDS)?.run()
        }
    }
}

/** A clock the test moves. Timers fire, in due order, only inside [advance]; the loop settles after each. */
class ManualClock(private val loop: ManualLoop) : HostClock {
    var mono = 10_000L
    var wall = System.currentTimeMillis()
    private class Timer(val at: Long, val run: () -> Unit, val id: Long)
    private val timers = ArrayList<Timer>()
    private var nextId = 0L
    override fun monoMs() = mono
    override fun wallMs() = wall
    override fun setTimer(ms: Long, run: () -> Unit): () -> Unit = synchronized(timers) {
        val t = Timer(mono + maxOf(0, ms), run, nextId++)
        timers.add(t)
        return { synchronized(timers) { timers.remove(t) } }
    }
    /** Moves both clocks by `ms`, firing every timer that falls due on the way. */
    fun advance(ms: Long, quietMs: Long = 0) {
        val end = mono + ms
        loop.settle(quietMs)
        while (true) {
            val t = synchronized(timers) { timers.sortedWith(compareBy({ it.at }, { it.id })).firstOrNull()?.takeIf { it.at <= end }?.also { timers.remove(it) } } ?: break
            wall += t.at - mono; mono = t.at
            t.run()
            loop.settle(quietMs)
        }
        wall += end - mono; mono = end
        loop.settle(quietMs)
    }
    /** Sets the monotonic clock without firing anything (a reset clock may go back). */
    fun jump(to: Long) { mono = to }
    val pending: Int get() = synchronized(timers) { timers.size }
}

class FakeSocket(val url: String, val handlers: SocketHandlers) : HostSocket {
    val sent = ArrayList<String>()
    var closedWith: Int? = null
    override fun send(text: String) { sent.add(text) }
    override fun close(code: Int) { closedWith = code }
}
/** Records every socket the host opens; the test drives them. */
class Sockets {
    val all = ArrayList<FakeSocket>()
    val factory = SocketFactory { url, handlers -> FakeSocket(url, handlers).also { all.add(it) } }
    val last: FakeSocket get() = all.lastOrNull() ?: error("no socket")
}

/** The home's frames as the stream numbers them. */
class FrameNumbers {
    private var n = 0
    fun hello(extra: Map<String, Any?> = mapOf()): String {
        n = 0
        return frame(linkedMapOf<String, Any?>("type" to "hello", "protocol" to "colophon/home-stream/6", "account" to "a".repeat(64), "home" to "h", "instance" to "i1",
            "cursor" to "i1.0", "head" to null, "notice" to 0, "principal" to "m", "expiresAt" to null, "namespaces" to listOf("listening.podcasts"),
            "limits" to mapOf("pingMs" to 20_000, "idleMs" to 60_000)).apply { putAll(extra) })
    }
    fun frame(fields: Map<String, Any?>): String { n++; return Json.write(LinkedHashMap(fields).apply { put("n", n) }, sorted = false) }
}

const val TICKET = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT"
fun answer(status: Int, body: Any? = mapOf<String, Any?>(), headers: List<Header> = listOf()) =
    HttpAnswer(status.toUInt(), headers, Json.write(body).toByteArray())

/** Answers the ticket request with `answer` (default: a ticket) and records what was asked. */
class TicketTransport : HomeTransport {
    val requests = ArrayList<HttpRequest>()
    var answer: suspend () -> HttpAnswer = { answer(200, mapOf("ticket" to TICKET, "path" to "/stream", "expires" to "2030-01-01T00:00:00Z")) }
    override suspend fun send(request: HttpRequest): HttpAnswer { requests.add(request); return answer() }
}

/**
 * A claim store whose writes complete when the test says ([hold], [hang]), after a delay on the manual clock, or fail.
 * It applies the compare-and-set when a write lands, as the contract requires, and records how many saves were ever in
 * flight at once.
 */
class TestStore(initial: StoredClaim? = null, private val clock: HostClock? = null) : ClaimStore {
    @Volatile var value: String? = initial?.claim
    @Volatile var heldFence: Fence? = initial?.fence
    var fenceFailures = 0
    var fenceHang = false
    var fenceReads = 0
    val writes = ArrayList<String>()
    val fences = ArrayList<Fence>()
    var hold = false
    var delayMs = 0L
    var failures = 0
    var hang = 0
    var inflight = 0
    var maxInflight = 0
    var refused = 0
    private val waiting = ArrayList<CompletableDeferred<Unit>>()
    val hung = ArrayList<CompletableDeferred<Unit>>()
    override suspend fun load(): StoredClaim? = heldFence?.let { StoredClaim(value, it) }
    override suspend fun fence(): Fence? {
        fenceReads++
        if (fenceFailures > 0) { fenceFailures--; throw java.io.IOException("the disk is busy") }
        if (fenceHang) CompletableDeferred<Unit>().await()
        return heldFence
    }
    override suspend fun save(record: StoredClaim, expected: Fence?): SaveResult {
        inflight++; maxInflight = maxOf(maxInflight, inflight)
        try {
            record.claim?.let { writes.add(it) }
            fences.add(record.fence)
            if (failures > 0) { failures--; throw java.io.IOException("the disk is full") }
            if (hang > 0) { hang--; CompletableDeferred<Unit>().also { hung.add(it) }.await() }
            if (hold) CompletableDeferred<Unit>().also { waiting.add(it) }.await()
            if (delayMs > 0) {
                val done = CompletableDeferred<Unit>()
                val c = clock
                if (c != null) c.setTimer(delayMs) { done.complete(Unit) } else Thread { Thread.sleep(delayMs); done.complete(Unit) }.start()
                done.await()
            }
            val next = compareAndSet(load(), record, expected)
            if (next == null) { refused++; return SaveResult.STALE }
            value = next.claim; heldFence = next.fence
            return SaveResult.STORED
        } finally {
            inflight--
        }
    }
    /** Completes every held write. */
    fun release() { hold = false; val w = waiting.toList(); waiting.clear(); w.forEach { it.complete(Unit) } }
    val heldWrites: Int get() = waiting.size
}
