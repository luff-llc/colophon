package com.luff.colophon.session

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

/**
 * A refresh moves `Ready` to `Refreshing` while it runs, and a finished refresh never leaves it there. Before the fix a
 * refresh that ended without applying a snapshot (its caller's scope cancelled) left the session `Refreshing` until some
 * later refresh. The Swift SDK's `RefreshPhaseTests` is the same test. No time passes: the worker's gate is held by the
 * test, so the refresh is in flight exactly as long as the test says.
 */
class RefreshPhaseTest {
    @Test(timeout = 60_000) fun aCancelledRefreshPutsReadyBack() = runBlocking<Unit> {
        val device = Device()
        try {
            device.session.create()
            device.session.flushExternalChanges() // no batch refresh of the creation's own writes is left to run
            assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
            val gate = device.session.worker.gate
            gate.lock()
            val refresh = launch(start = CoroutineStart.UNDISPATCHED) { device.session.refresh() }
            device.session.state.first { it.phase == SessionPhase.Refreshing }
            refresh.cancel()
            gate.unlock()
            refresh.join()
            assertEquals(SessionPhase.Ready, device.session.phase, "a cancelled refresh left ${device.describe()}")
            device.session.refresh()
            assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
        } finally { device.close() }
    }

    /** A write refusal still permits reads: its own refresh must restore Ready without another refresh. */
    @Test(timeout = 60_000) fun aRefusedCommandRefreshPutsReadyBack() = runBlocking<Unit> {
        val first = Device()
        val second = Device(medium = first.medium)
        try {
            first.session.create()
            second.session.restore()
            approveByScan(second.session, first.session, """{"records":[{"namespace":"notes","access":"read"}]}""")
            second.session.flushExternalChanges()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
            val holds = RefreshHolds(setOf(1))
            second.session.refreshWillFinish = { holds.reached() }
            assertFailsWith<com.luff.colophon.AccountException.Denied> { note(second.session, "refused") }
            holds.waiting(1)
            assertEquals(SessionPhase.Refreshing, second.session.phase, second.describe())
            holds.release(1)
            assertNotNull(second.session.refusalRefresh).join()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
        } finally { second.close(); first.close() }
    }

    /**
     * The refreshes held at [ColophonSession.refreshWillFinish], numbered in the order they reach it: a held one waits there
     * (its worker has answered, its outcome is not published) until the test releases it, with or without an error.
     */
    class RefreshHolds(private val holding: Set<Int>) {
        private var count = 0
        private val arrived = HashMap<Int, CompletableDeferred<Unit>>()
        private val gates = HashMap<Int, CompletableDeferred<Unit>>()
        private fun arrival(n: Int) = synchronized(this) { arrived.getOrPut(n) { CompletableDeferred() } }
        private fun gate(n: Int) = synchronized(this) { gates.getOrPut(n) { CompletableDeferred() } }
        suspend fun reached() {
            val n = synchronized(this) { ++count }
            if (n !in holding) return
            arrival(n).complete(Unit)
            gate(n).await()
        }
        suspend fun waiting(n: Int) = arrival(n).await()
        fun release(n: Int, error: Exception? = null) { if (error == null) gate(n).complete(Unit) else gate(n).completeExceptionally(error) }
    }

    /**
     * R1 is held after its worker answered; another refresh publishes `Ready`; R2 marks `Refreshing` and is held. R1, now
     * stale, finishes or fails afterwards. Returns both refresh jobs, with R2 still held.
     */
    private suspend fun CoroutineScope.staleRefresh(device: Device, holds: RefreshHolds): Pair<Job, Job> {
        device.session.create()
        device.session.flushExternalChanges()
        assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
        device.session.refreshWillFinish = { holds.reached() }
        val r1 = launch { device.session.refresh() }
        holds.waiting(1)
        assertEquals(SessionPhase.Refreshing, device.session.phase, device.describe())
        device.session.refresh() // the second to reach the hold, not held: it publishes `Ready`
        assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
        val r2 = launch { device.session.refresh() }
        holds.waiting(3)
        assertEquals(SessionPhase.Refreshing, device.session.phase, device.describe())
        return r1 to r2
    }

    @Test(timeout = 60_000) fun aStaleRefreshThatFinishesIsDroppedAndThePhaseFollowsTheNewerOne() = runBlocking<Unit> {
        val device = Device()
        try {
            val holds = RefreshHolds(setOf(1, 3))
            val (r1, r2) = staleRefresh(device, holds)
            holds.release(1)
            r1.join()
            assertEquals(SessionPhase.Refreshing, device.session.phase, "a stale refresh published ${device.describe()} while a newer one runs")
            holds.release(3)
            r2.join()
            assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
        } finally { device.close() }
    }

    @Test(timeout = 60_000) fun aStaleRefreshThatFailsIsDroppedAndACancelledNewerOnePutsReadyBack() = runBlocking<Unit> {
        val device = Device()
        try {
            val holds = RefreshHolds(setOf(1, 3))
            val (r1, r2) = staleRefresh(device, holds)
            holds.release(1, StorageException.Unavailable("the disk is gone"))
            r1.join()
            assertEquals(SessionPhase.Refreshing, device.session.phase, "a stale refresh's failure published ${device.describe()}")
            r2.cancel()
            r2.join()
            assertEquals(SessionPhase.Ready, device.session.phase, "a cancelled refresh left ${device.describe()}")
        } finally { device.close() }
    }

    /** A medium whose writes fail while [failing] is set. */
    class FailingWrites(private val inner: MemoryMedium) : RecordMedium by inner {
        @Volatile var failing = false
        override fun write(writes: List<MediumWrite>) { if (failing) throw StorageException.Unavailable("the disk is gone"); inner.write(writes) }
    }

    /**
     * A command that fails while a refresh is in flight, with a failure that sets a phase, keeps that phase: the refresh's
     * ready snapshot, older than the failure, does not hide it.
     */
    @Test(timeout = 60_000) fun aCommandFailureDuringARefreshKeepsThePhaseItSet() = runBlocking<Unit> {
        val medium = MemoryMedium()
        val storage = FailingWrites(medium)
        val device = Device(medium = medium, storage = storage)
        try {
            device.session.create()
            device.session.flushExternalChanges()
            assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
            val holds = RefreshHolds(setOf(1))
            device.session.refreshWillFinish = { holds.reached() }
            val refresh = launch { device.session.refresh() }
            holds.waiting(1)
            storage.failing = true
            assertFailsWith<StorageException> { note(device.session, "b") }
            storage.failing = false
            assertEquals(SessionPhase.Retry, device.session.phase, device.describe())
            holds.release(1)
            refresh.join()
            assertEquals(SessionPhase.Retry, device.session.phase, "the refresh replaced the failure's phase: ${device.describe()}")
            assertNotNull(device.session.lastError)
        } finally { device.close() }
    }
}
