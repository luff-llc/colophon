package com.luff.colophon.session

import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * `view(namespace)` is fenced as `query` is: a fold that comes back after the session locked is refused, never handed
 * to a screen that no longer may show it. Before the fence `view` returned the old fold. The Swift session's
 * `ViewFenceTests` is the same test.
 */
class ViewFenceTest {
    @Test(timeout = 60_000) fun aViewThatReturnsAfterLockIsStale() = runBlocking<Unit> {
        val d = Device()
        try {
            d.session.create()
            assertEquals(SessionPhase.Ready, d.session.phase, d.describe())
            d.session.view("notes")
            d.session.afterViewForTests = { d.session.lock() }
            assertFailsWith<SessionError.StaleRevision> { d.session.view("notes") }
            d.session.afterViewForTests = null
            assertEquals(SessionPhase.Locked, d.session.phase)
            assertFailsWith<SessionError.NotReady> { d.session.view("notes") }
        } finally {
            d.close()
        }
    }
}
