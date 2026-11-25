package com.luff.colophon.hosts

import com.luff.colophon.StreamStatusKind
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The session rules that matter when devices come and go, end to end through the Kotlin hosts and a real home: a holder
 * restarted from what it stored, a holder that goes offline past the holder timeout and returns, a pass while both
 * stores are slow and frames keep arriving, and a member revoked mid-session (js/test06/scenarios.test.ts). A fast
 * policy (beat 400 ms, holder timeout 1.5 s, ask timeout 300 ms) keeps the waits short; the rules are the defaults'.
 */
class ScenariosTest {
    private val holderFrames = setOf("state", "beat", "msg", "refuse", "pass", "decline")
    private fun holderFramesSent(m: Member, from: Double, to: Double = Double.MAX_VALUE) = m.sentKinds(from, to).filter { it in holderFrames }
    private fun <T> wait(d: kotlinx.coroutines.Deferred<T>): T = runBlocking { d.await() }

    @Test(timeout = 240_000) fun restartLapseSlowStoreAndRevocationOverARealHome() = World.make().use { w ->
        val a = w.a; val b = w.b
        val policy = World.fastPolicy()
        val ask = 300
        // Each write in step 3 takes this long: less than askTimeoutMs, since an asker that hears no holder frame for
        // askTimeoutMs after its ask may take (§S5), and a holder sends nothing while its write is outstanding.
        val slow = 200L
        a.startStream(); b.startStream()
        a.whenTrue("A's stream is live") { a.stream.live }
        b.whenTrue("B's stream is live") { b.stream.live }
        a.join(policy); b.join(policy)

        // A plays.
        val first = Anchor("ep-2", "show-1", 60_000, 1000, true, nowMs())
        a.appState = first.bytes()
        wait(a.cell.take(a.appState))
        a.until<CellEvent.BecameHolder>()
        b.until<CellEvent.HolderChanged> { it.claim?.holder == a.id }

        // 1. A restarts from its stored claim (a new endpoint, session key and randomness). It holds locally, gated,
        //    sends no holder frame, waits out askTimeoutMs, then retakes with the state its application kept (§S6).
        val stored = a.store.value
        assertEquals(a.id, (com.luff.colophon.session.Json.obj(stored!!)!!["claim"] as Map<*, *>)["holder"])
        a.cell.close()
        val restarted = t()
        a.join(policy)
        assertTrue(a.cell.state.gated, "a restarted holder is gated")
        val retook = a.until<CellEvent.BecameHolder>(restarted)
        assertEquals("take", retook.second.via)
        assertFalse(a.cell.state.gated)
        assertTrue(retook.first - restarted >= ask)
        val takeSent = a.logSince(restarted).first { (it.second as? CellHostEvent.Sent)?.kind == "take" }
        assertTrue(takeSent.first - restarted >= ask)
        assertEquals(listOf(), holderFramesSent(a, restarted, takeSent.first))
        assertEquals(first, Anchor.of(retook.second.snapshot))
        b.until<CellEvent.HolderChanged>(restarted) { it.claim?.holder == a.id && it.claim.term > 1 }
        println("restart: A rejoined from its stored claim and retook after ${"%.0f".format(retook.first - restarted)} ms (askTimeoutMs $ask)")

        // 2. A goes offline while holder, past the holder timeout. B sees the holder lapse and takes; A returns, and
        //    yields to B's greater claim without acting as holder.
        val offline = t()
        a.network.down()
        val lapsed = b.until<CellEvent.HolderLapsed>(offline) { it.holder == a.id }
        assertTrue(lapsed.first - offline >= 1400)
        val pressed = t()
        wait(b.cell.take())
        val tookOver = b.until<CellEvent.BecameHolder>(pressed)
        println("lapse: B saw A lapse ${"%.0f".format(lapsed.first - offline)} ms after A went offline; B's take -> B holding ${"%.1f".format(tookOver.first - pressed)} ms")
        assertEquals("take", tookOver.second.via)
        assertEquals(first, Anchor.of(tookOver.second.snapshot))
        // A, cut off, still acts locally as holder (sessions §S0 rule 1).
        assertTrue(a.cell.state.isHolder)
        Thread.sleep(500)
        a.network.restore()
        val back = t()
        a.stream.retryNow()
        val yielded = a.until<CellEvent.Yielded>(back, 15_000)
        assertEquals(listOf(), holderFramesSent(a, back))
        assertFalse(a.cell.state.isHolder)
        assertEquals(b.id, a.cell.state.holder)
        assertTrue(a.sentKinds(back).contains("hello"))
        // What A held reaches B's application (G11).
        b.until<CellEvent.Displaced>(back) { it.from == a.id }
        println("return: A yielded ${"%.0f".format(yielded.first - back)} ms after its network came back, sending no holder frame")

        // 3. A pass while both stores take 500 ms per write, with frames arriving during the writes. B's application
        //    passes to A when A asks; nothing a Persist holds back is released before its write completes.
        a.store.delayMs = slow; b.store.delayMs = slow
        b.appState = first.copy(positionMs = 90_000, at = nowMs()).bytes()
        val passedAt = java.util.concurrent.atomic.AtomicReference(0.0)
        b.cell.events { event ->
            if (event !is CellEvent.AskReceived || !b.cell.state.isHolder || passedAt.get() > 0) return@events
            passedAt.set(t())
            val playing = Anchor.of(b.appState)!!
            val now = nowMs()
            b.appState = playing.copy(positionMs = playing.project(now, 0), playing = false, at = now).bytes()
            b.cell.pass(event.from, b.appState!!)
            // A command while that pass is being written waits for the write (session:persistPending).
            b.cell.presence("""{"label":"Kitchen","playing":false}""".toByteArray())
        }
        val asked = t()
        wait(a.cell.ask())
        val gotIt = a.until<CellEvent.BecameHolder>(asked, 15_000)
        val passed = passedAt.get()
        assertEquals("pass", gotIt.second.via)
        assertContentEquals(b.appState, gotIt.second.snapshot)
        fun persistAt(m: Member, from: Double, phase: PersistPhase) = m.logSince(from).first { (it.second as? CellHostEvent.Persist)?.phase == phase }.first
        val bPersist = persistAt(b, passed, PersistPhase.STARTED)
        val bStored = persistAt(b, bPersist, PersistPhase.STORED)
        val bPassSent = b.logSince(passed).first { (it.second as? CellHostEvent.Sent)?.kind == "pass" }.first
        assertTrue(bStored - bPersist >= slow - 10, "B's write took ${bStored - bPersist} ms")
        assertTrue(bPassSent >= bStored, "B's pass is sent only after its write completes")
        val aPersist = persistAt(a, asked, PersistPhase.STARTED)
        val aStored = persistAt(a, aPersist, PersistPhase.STORED)
        val aAck = a.logSince(aPersist).first { (it.second as? CellHostEvent.Sent)?.kind == "ack" }.first
        assertTrue(aAck >= aStored, "A's ack is sent only after its write completes")
        fun kept(m: Member, from: Double, to: Double) = m.logSince(from, to + 0.001).mapNotNull { (it.second as? CellHostEvent.Queued)?.input }
        val keptA = kept(a, aPersist, aStored); val keptB = kept(b, bPersist, bStored)
        val ticks = (a.logSince(asked) + b.logSince(asked)).count { (it.second as? CellHostEvent.Queued)?.input == QueuedInput.TICK }
        assertTrue(ticks < 10)
        val held = b.logSince(passed).count { it.second is CellHostEvent.CommandHeld }
        println("slow store: B's pass waited ${"%.0f".format(bPassSent - bPersist)} ms for its write; inputs kept behind the writes: A $keptA; B $keptB; commands held: $held; A holding ${"%.0f".format(gotIt.first - asked)} ms after asking")
        assertTrue(keptA.count { it == QueuedInput.FRAME } + keptB.count { it == QueuedInput.FRAME } > 0, "frames were kept behind a write")
        assertTrue(held > 0, "a command was held behind B's write")
        runCatching { b.until<CellEvent.PresenceChanged>(passed) }
        assertEquals(listOf(), (a.logSince(0.0) + b.logSince(0.0)).filter { (it.second as? CellHostEvent.Drop)?.reason == "queueFull" })
        assertFalse(b.cell.state.isHolder)
        a.store.delayMs = 0; b.store.delayMs = 0
        Thread.sleep(300)

        // 4. B revokes A mid-session (A holds the cell), by a real authority change on B's device, nothing injected.
        //    a. B holds the new head before the home does. A still sends over its socket; the home still carries the
        //       frame, and B's endpoint, under the new head, drops it on arrival, changing nothing.
        //    b. Once the home holds the revocation it ends A's stream: A's frames no longer leave the device.
        //    c. A's own poll brings the revocation in: its endpoint reports the stale view and A is not entitled.
        val revoking = t()
        runBlocking { b.device.session.revoke(a.id) }
        b.cell.host.accountChanged()
        b.whenTrue("B installs the new head") { b.logSince(revoking).any { it.second is CellHostEvent.Account } }
        assertTrue(a.stream.live)
        val dropsBefore = b.cell.host.stats.drops
        val viewBefore = b.whenTrue("B's view") { b.cell.host.current != null }.let { b.cell.host.current!!.viewJson() }
        val overTheWire = t()
        wait(a.cell.publish(first.copy(positionMs = 95_000, at = nowMs()).bytes()))
        assertNotNull(a.logSince(overTheWire).firstOrNull { (it.second as? CellHostEvent.Sent)?.kind == "msg" }, "A's frame left the device")
        b.whenTrue("B drops A's frame") { b.cell.host.stats.drops > dropsBefore }
        val refusal = b.logSince(overTheWire).mapNotNull { (it.second as? CellHostEvent.Drop)?.reason }
        assertEquals(viewBefore, b.cell.host.current!!.viewJson())
        assertTrue(b.events.none { it.first >= overTheWire && it.second is CellEvent.Message })
        // b. The home learns the revocation and ends A's stream.
        assertTrue(runBlocking { var ok = false; repeat(40) { if (!ok) { ok = b.device.session.syncNow() && b.device.session.homeIssues.isEmpty(); if (!ok) Thread.sleep(150) } }; ok })
        a.whenTrue("A's stream stops being live", 15_000) { !a.stream.live }
        val status = a.stream.status
        val afterHome = t()
        wait(a.cell.publish(first.copy(positionMs = 97_000, at = nowMs()).bytes()))
        assertEquals(0, a.logSince(afterHome).count { it.second is CellHostEvent.Sent })
        assertTrue(a.logSince(afterHome).any { (it.second as? CellHostEvent.Unsent)?.reason == "carrier" })
        // c. A's poll (the app's own timer; the stream is not live) brings the revocation in.
        val polled = t()
        runBlocking { a.device.session.syncNow() }
        runCatching { wait(a.cell.publish(first.copy(positionMs = 99_000, at = nowMs()).bytes())) }
        val stale = a.logSince(polled).firstOrNull { it.second is CellHostEvent.Stale }
        val account = a.logSince(polled).firstOrNull { it.second is CellHostEvent.Account }
        assertNotNull(stale, "A's endpoint reported the stale view")
        assertNotNull(account)
        assertTrue(account.first >= stale.first)
        assertFalse((account.second as CellHostEvent.Account).entitled)
        a.whenTrue("A's state shows it is not entitled") { !a.cell.state.entitled }
        assertTrue(status.kind != StreamStatusKind.LIVE)
        println("revocation: A's frame crossed the home and B dropped it (${refusal.joinToString(",")}); then the home ended A's stream (${status.kind}${status.blocked?.let { "/$it" } ?: ""}); A reported stale, then entitled=${(account.second as CellHostEvent.Account).entitled}")
    }
}
