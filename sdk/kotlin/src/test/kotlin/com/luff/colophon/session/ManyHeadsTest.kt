package com.luff.colophon.session

import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A device that syncs with its home for days (0.5.7), against the REAL relay on a clock the test moves. Each sync fetches
 * a newer head from the home, a new envelope over the same history. Before 0.5.7 the account held every one, and after 64
 * every exchange failed `malformed: too many head envelopes`; now it keeps the heads a reader needs (spec §13.3) and keeps
 * syncing, writing, and reopening from its saved state. The account's own heal of an old saved state is
 * `v05_relay_heads.rs` (Rust). The same journey runs in Swift (`ManyHeadsTests.swift`).
 */
class ManyHeadsTest {
    private val now = AtomicLong(Instant.parse("2026-11-20T09:00:00Z").toEpochMilli())
    private val clock = { now.get() }

    @Test(timeout = 600_000)
    fun aDeviceThatSyncedForDaysKeepsSyncing() = runBlocking<Unit> {
        val relay = RelayHome("https://heads.test/v1/accounts/kotlin", clockSource = clock)
        val devices = ArrayList<Device>()
        try {
            val first = Device(homes = listOf(HomeConfiguration("${relay.base}/", request = { a -> relay.start(a); relay.memberRequest(a) },
                transport = relay.transport())), createWithoutHome = false, history = HistoryAccess.MEMBERS, now = clock).also { devices.add(it) }
            first.session.create(); first.session.stopSync()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            note(first.session, "a")
            repeat(80) { i ->
                now.addAndGet(150_000)
                relay.tick()
                assertTrue(first.session.syncNow(), "sync $i: ${first.describe()}")
                assertTrue(first.session.homeFaults.isEmpty() && first.session.homeIssues.isEmpty(), "sync $i: ${first.describe()}")
            }
            note(first.session, "b")
            now.addAndGet(1_000); relay.tick()
            assertTrue(first.session.syncNow(), first.describe())
            first.session.flushCheckpoint()

            // A relaunch from the saved state keeps syncing.
            first.session.shutdown()
            val again = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir,
                homes = listOf(HomeConfiguration("${relay.base}/", transport = relay.transport())), createWithoutHome = false, now = clock).also { devices.add(it) }
            again.session.restore(); again.session.stopSync()
            now.addAndGet(150_000); relay.tick()
            assertTrue(again.session.syncNow(), again.describe())
            assertTrue(again.session.homeFaults.isEmpty(), again.describe())
            assertEquals(2, admitted(again.session))
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }
}
