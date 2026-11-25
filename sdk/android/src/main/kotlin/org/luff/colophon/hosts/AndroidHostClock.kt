package org.luff.colophon.hosts

import android.os.SystemClock
import com.luff.colophon.hosts.HostClock
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit

/**
 * The hosts' clock on Android. Monotonic time is `SystemClock.elapsedRealtime()` (`CLOCK_BOOTTIME`), which keeps counting
 * while the device sleeps, so a holder that was asleep for a minute is judged a minute later, never as if no time had
 * passed (`System.nanoTime()` is `CLOCK_MONOTONIC` on Android and stops in deep sleep). It is reset only by a reboot,
 * which is a new process: the hosts make new endpoints from the stored claim (§S6).
 *
 * Timers run on one daemon thread. A timer cannot fire while the CPU is suspended (Doze, or the screen off with no wake
 * lock); it fires when the device next runs, late, and the core is then given the true time. Nothing here holds a wake
 * lock: an app that must stay responsive while playing keeps its own foreground service (docs/hosts-06.md §6).
 */
object AndroidHostClock : HostClock {
    private val timers = ScheduledThreadPoolExecutor(1, ThreadFactory { r -> Thread(r, "colophon-host-timer").apply { isDaemon = true } })
        .apply { removeOnCancelPolicy = true }
    override fun monoMs(): Long = SystemClock.elapsedRealtime()
    override fun wallMs(): Long = System.currentTimeMillis()
    override fun setTimer(ms: Long, run: () -> Unit): () -> Unit {
        val f = timers.schedule({ run() }, ms.coerceAtLeast(0), TimeUnit.MILLISECONDS)
        return { f.cancel(false) }
    }
}
