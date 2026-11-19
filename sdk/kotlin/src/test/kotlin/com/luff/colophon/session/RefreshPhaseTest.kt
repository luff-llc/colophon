package com.luff.colophon.session

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertEquals

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
}
