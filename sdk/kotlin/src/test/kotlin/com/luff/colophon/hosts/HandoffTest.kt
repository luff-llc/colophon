package com.luff.colophon.hosts

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The flagship behaviour of 0.6, end to end through the Kotlin hosts: two members of one account, each with its own
 * stream host over a real WebSocket (`java.net.http`) to a real home, hand a `now-playing` cell over. A plays and
 * publishes its anchor; B's "play" asks, A's application pauses and passes its stopped position, B continues from it,
 * and A, no longer holder, sends no holder frame (js/test06/handoff.test.ts).
 */
class HandoffTest {
    private val holderFrames = setOf("state", "beat", "msg", "refuse", "pass", "decline")

    @Test(timeout = 180_000) fun handoffBetweenTwoLiveDevicesContinuesFromTheHoldersLastState() = World.make().use { w ->
        val a = w.a; val b = w.b
        a.startStream(); b.startStream()
        a.whenTrue("A's stream is live") { a.stream.live }
        b.whenTrue("B's stream is live") { b.stream.live }
        a.join(); b.join()
        a.whenTrue("A is subscribed") { a.sentKinds(0.0).contains("hello") }

        // A plays: it takes the cell and publishes its anchor on its own clock.
        val start = Anchor("ep-1", "show-1", 1_234_567, 1250, true, nowMs())
        a.appState = start.bytes()
        a.cell.take(a.appState).also { kotlinx.coroutines.runBlocking { it.await() } }
        a.until<CellEvent.BecameHolder>()
        assertTrue(a.cell.state.isHolder)
        b.until<CellEvent.HolderChanged> { it.claim?.holder == a.id }
        val last = start.copy(positionMs = 1_240_000, at = nowMs())
        a.appState = last.bytes()
        kotlinx.coroutines.runBlocking { a.cell.publish(last.bytes()).await() }
        b.until<CellEvent.Message> { Anchor.of(it.payload)?.positionMs == last.positionMs }
        assertEquals(last, Anchor.of(b.cell.state.state))

        // B measures its clock offset to A, to project A's position on its own clock.
        kotlinx.coroutines.runBlocking { b.cell.ping(a.id).await() }
        val offset = b.until<CellEvent.OffsetChanged> { it.peer == a.id }.second

        // A's application, as §S12 has it: when another device asks to play, A pauses and passes its stopped position.
        val stopped = java.util.concurrent.atomic.AtomicReference<Anchor?>()
        a.cell.events { event ->
            if (event !is CellEvent.AskReceived || !a.cell.state.isHolder) return@events
            val now = nowMs()
            val playing = Anchor.of(a.appState)!!
            val s = playing.copy(positionMs = playing.project(now, 0), playing = false, at = now)
            stopped.set(s)
            a.appState = s.bytes()
            a.cell.pass(event.from, s.bytes())
        }

        // B's "play": it asks the holder for the role (a take never displaces a holder that is live and answering, §S5).
        val pressed = t()
        kotlinx.coroutines.runBlocking { b.cell.ask().await() }
        val held = b.until<CellEvent.BecameHolder>(pressed)
        val seen = a.until<CellEvent.Yielded>(pressed)
        val toHolding = held.first - pressed; val toObserved = seen.first - pressed
        println("handoff (default policy, real home over java.net.http WebSocket): B's play (ask) -> A observes it is no longer holder ${"%.1f".format(toObserved)} ms; -> B holding ${"%.1f".format(toHolding)} ms")

        // B starts from exactly A's last state: A's stopped position, which B now plays on from.
        assertEquals("pass", held.second.via)
        val resumed = Anchor.of(held.second.snapshot)!!
        assertEquals(stopped.get(), resumed)
        assertTrue(resumed.positionMs >= last.positionMs)
        assertTrue(b.cell.state.isHolder)
        assertEquals(b.id, b.cell.state.holder)
        val playingOnB = resumed.copy(playing = true, at = nowMs())
        b.appState = playingOnB.bytes()
        kotlinx.coroutines.runBlocking { b.cell.publish(playingOnB.bytes()).await() }
        // A follows B's anchor and projects B's position on its own clock, within the offset's error bound.
        val followed = Anchor.of(a.until<CellEvent.Message>(seen.first) { Anchor.of(it.payload)?.playing == true }.second.payload)!!
        assertEquals(resumed.positionMs, followed.positionMs)
        assertTrue(followed.project(nowMs(), -offset.offset) >= resumed.positionMs - 2 * (offset.error + 1))

        // A is no longer holder and acts as none: no holder frame after it passed, other than resending its pass.
        assertTrue(!a.cell.state.isHolder)
        assertEquals(b.id, a.cell.state.holder)
        Thread.sleep(1500)
        assertEquals(listOf(), a.sentKinds(seen.first).filter { it in holderFrames && it != "pass" })
        assertEquals(listOf(), a.logSince(0.0).filter { it.second is CellHostEvent.Drop })
        assertTrue(toHolding < 1000, "B holding $toHolding ms after its ask")
        assertTrue(toObserved < 2000, "A observed $toObserved ms after B's ask")
    }
}
