package com.luff.colophon.hosts

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.EmptyCoroutineContext

/**
 * The clocks and timers a 0.6 host drives the core with. Both state machines take time as an argument and keep no
 * timer of their own, so the host owns these; tests inject a manual clock and step it.
 */
interface HostClock {
    /** Monotonic milliseconds, never negative and never going back while the process runs (every stream and session timer). */
    fun monoMs(): Long
    /** Wall-clock milliseconds since the Unix epoch (delegation windows, member expiry, account views). */
    fun wallMs(): Long
    /**
     * Runs `run` once, `ms` from now on the monotonic clock, on any thread (the hosts move it onto their own serial
     * context). Returns the function that cancels it.
     */
    fun setTimer(ms: Long, run: () -> Unit): () -> Unit
}

/**
 * The JVM's clocks: `System.nanoTime()` from the first use (monotonic) and `System.currentTimeMillis()`, with one
 * shared daemon timer thread. On Android, `System.nanoTime()` is `CLOCK_MONOTONIC`, which stops while the device
 * sleeps: use the Android SDK's `AndroidHostClock` (`elapsedRealtime`, which counts sleep) there.
 */
object SystemHostClock : HostClock {
    private val origin = System.nanoTime()
    private val timers = ScheduledThreadPoolExecutor(1, ThreadFactory { r -> Thread(r, "colophon-host-timer").apply { isDaemon = true } })
        .apply { removeOnCancelPolicy = true }
    override fun monoMs(): Long = (System.nanoTime() - origin) / 1_000_000
    override fun wallMs(): Long = System.currentTimeMillis()
    override fun setTimer(ms: Long, run: () -> Unit): () -> Unit {
        val f = timers.schedule({ run() }, ms.coerceAtLeast(0), TimeUnit.MILLISECONDS)
        return { f.cancel(false) }
    }
}

/** The serial context a host runs on when none is given: one task at a time on the default pool. */
internal fun serialDispatcher(): CoroutineDispatcher = Dispatchers.Default.limitedParallelism(1)

/**
 * One host's serial queue. Jobs run one at a time on `dispatcher` (which must run one task at a time: every coroutine of
 * the host runs there too, so no job and no continuation ever overlap). Events for listeners are delivered between
 * jobs, before the next job, and a job never runs inside another: whatever a listener, store, socket or timer does
 * becomes a later job. Safe to call from any thread.
 */
internal class SerialQueue(private val dispatcher: CoroutineDispatcher, private val failed: (Throwable) -> Unit) {
    private val jobs = ConcurrentLinkedQueue<() -> Unit>()
    private val events = ConcurrentLinkedQueue<() -> Unit>()
    private val scheduled = AtomicBoolean(false)

    fun job(job: () -> Unit) { jobs.add(job); schedule() }
    /** A listener delivery: runs before the next job. A listener's failure is its own. */
    fun event(delivery: () -> Unit) { events.add(delivery); schedule() }
    fun clearJobs() = jobs.clear()

    private fun schedule() {
        if (scheduled.compareAndSet(false, true)) dispatcher.dispatch(EmptyCoroutineContext, Runnable { drain() })
    }
    private fun drain() {
        try {
            while (true) {
                val e = events.poll()
                if (e != null) { try { e() } catch (_: Throwable) {}; continue }
                val j = jobs.poll() ?: break
                try { j() } catch (t: Throwable) { failed(t) }
            }
        } finally {
            scheduled.set(false)
            if (events.isNotEmpty() || jobs.isNotEmpty()) schedule()
        }
    }
}

/**
 * One timer that is always set to the latest deadline it was given: [at] replaces whatever was scheduled before, and
 * [clear] cancels it. Confined to its host's serial context: `post` moves the firing there.
 */
internal class Deadline(private val clock: HostClock, private val post: (() -> Unit) -> Unit, private val run: () -> Unit) {
    private var cancel: (() -> Unit)? = null
    private var token = 0L
    var due: Long? = null; private set

    /** Fires `run` at monotonic `due` (at once if it has passed); null clears it. */
    fun at(due: Long?) {
        if (due == this.due && cancel != null) return
        clear()
        if (due == null) return
        this.due = due
        val mine = ++token
        cancel = clock.setTimer((due - clock.monoMs()).coerceAtLeast(0)) {
            post { if (mine == token) { cancel = null; this.due = null; run() } }
        }
    }
    fun clear() { cancel?.invoke(); cancel = null; due = null; token++ }
}
