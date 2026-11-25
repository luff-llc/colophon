package com.luff.colophon.hosts

import com.luff.colophon.session.Device
import com.luff.colophon.session.Json
import com.luff.colophon.session.MemoryMedium
import com.luff.colophon.session.SessionPhase
import com.luff.colophon.session.approveByScan
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import java.util.Base64
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

const val NS = "listening.podcasts"
const val CELL = "now-playing"
fun b64(text: String): String = Base64.getEncoder().encodeToString(text.toByteArray())
fun cmd(vararg fields: Pair<String, Any?>): String = Json.write(linkedMapOf(*fields))

/** Every frame one cell sends reaches every other attached cell, in order, as a later task on the loop. */
class LoopCarrier(private val loop: ManualLoop) {
    val cells = LinkedHashSet<StreamCell>()
    val carried = ArrayList<Pair<StreamCell?, String>>()
    var paused = false
    private val backlog = ArrayList<() -> Unit>()
    /** A carrier view for one cell, so the carrier knows who sent each frame. */
    fun view(): CellCarrier {
        var mine: StreamCell? = null
        return object : CellCarrier {
            override fun attach(cell: StreamCell) { mine = cell; cells.add(cell); post { cell.linkUp() } }
            override fun detach(cell: StreamCell) { cells.remove(cell) }
            override fun sendSession(frame: String, lost: () -> Unit): Boolean { send(mine, frame); return true }
        }
    }
    private fun post(run: () -> Unit) = loop.dispatcher.dispatch(kotlin.coroutines.EmptyCoroutineContext, Runnable { run() })
    private fun send(from: StreamCell?, frame: String) {
        carried.add(from to frame)
        val deliver = { for (c in cells.toList()) if (c !== from) c.deliver(frame) }
        if (paused) backlog.add(deliver) else post(deliver)
    }
    fun resume() { paused = false; backlog.toList().also { backlog.clear() }.forEach { post(it) } }
}

/**
 * The cell host's reference loop against real endpoints of two members of a local account, over an in-memory carrier,
 * with a manual clock and stores whose writes the test completes (the matrix of js/test06/cell-host.test.ts).
 */
class CellHostTest {
    companion object {
        lateinit var first: Device
        lateinit var second: Device
        @BeforeClass @JvmStatic fun accounts() = runBlocking {
            first = Device(namespaces = listOf(NS))
            first.session.create()
            second = Device(medium = first.medium, namespaces = listOf(NS))
            second.session.restore()
            approveByScan(second.session, first.session)
            second.session.refresh()
            check(second.session.phase == SessionPhase.Ready) { second.describe() }
        }
        @AfterClass @JvmStatic fun close() = runBlocking { first.close(); second.close() }
    }

    inner class Pair2(extraA: (CellHostOptions) -> CellHostOptions = { it }) {
        val loop = ManualLoop()
        val clock = ManualClock(loop)
        val carrier = LoopCarrier(loop)
        val stores = mapOf("a" to TestStore(clock = clock), "b" to TestStore(clock = clock))
        val logs = mapOf("a" to ArrayList<CellHostEvent>(), "b" to ArrayList())
        fun options(device: Device, which: String, store: ClaimStore = stores.getValue(which), carrierView: CellCarrier = carrier.view()) =
            CellHostOptions(com.luff.colophon.hosts.accountOf(device.session), carrierView, NS, CELL, store, clock = clock, dispatcher = loop.dispatcher)
        val a: SessionCellHost = loop.run { SessionCellHost.open(extraA(options(first, "a"))) { logs.getValue("a").add(it) } }
        val b: SessionCellHost = loop.run { SessionCellHost.open(options(second, "b")) { logs.getValue("b").add(it) } }
        val la get() = logs.getValue("a")
        val lb get() = logs.getValue("b")
        val sa get() = stores.getValue("a")
        val sb get() = stores.getValue("b")
        init { settle() }
        fun settle() = loop.settle(20)
        fun <T> await(d: Deferred<T>): T = loop.run { d.await() }
        fun close() {
            a.close(); b.close(); settle()
            assertTrue(sa.maxInflight <= 1 && sb.maxInflight <= 1, "never two saves of one cell in flight")
        }
    }
    private fun shape(e: CellHostEvent): String = when (e) {
        is CellHostEvent.Session -> "event:${e.name}"
        is CellHostEvent.Sent -> "sent:${e.kind}"
        is CellHostEvent.Persist -> "persist:${e.phase.name.lowercase()}"
        else -> e.javaClass.simpleName.replaceFirstChar { it.lowercase() }
    }
    private fun failure(d: Deferred<*>): CellHostError.Code? = if (!d.isCompleted) null else d.getCompletionExceptionOrNull()?.let { (it as? CellHostError)?.code }

    @Test fun aPersistHoldsBackWhatFollowsItUntilItsDurableWriteCompletes() {
        val r = Pair2()
        r.sa.hold = true
        val mark = r.la.size
        r.await(r.a.command("take", cmd("command" to "take", "state" to b64("anchor-0"))))
        r.settle()
        assertEquals(listOf("persist:started"), r.la.drop(mark).map(::shape))
        assertEquals(1, r.sa.heldWrites)
        assertNotNull(r.a.current!!.awaitingPersist())
        r.sa.release(); r.settle()
        assertEquals(listOf("persist:started", "persist:stored", "sent:take", "sent:state", "event:becameHolder"),
            r.la.drop(mark).map(::shape).filter { it != "event:holderChanged" }.take(5))
        assertNull(r.a.current!!.awaitingPersist())
        assertEquals(r.sa.value, r.a.storedClaim)
        assertTrue(r.lb.any { it is CellHostEvent.Session && it.name == "holderChanged" })
        r.close()
    }

    @Test fun whileAWriteIsInProgressFramesAndATickAreKeptAndACommandHeld() {
        val r = Pair2()
        r.sa.hold = true
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        r.await(r.b.command("presence", cmd("command" to "presence", "payload" to b64("""{"label":"Kitchen"}"""))))
        r.settle()
        val publishing = r.a.command("publish", cmd("command" to "publish", "id" to "AAAAAAAAAAAAAAAAAAAAAA", "payload" to b64("anchor-1")))
        r.settle()
        r.clock.advance(6_000, 5)
        val kept = r.la.filterIsInstance<CellHostEvent.Queued>().map { it.input }
        assertTrue(QueuedInput.FRAME in kept)
        assertTrue(kept.count { it == QueuedInput.TICK } <= 1)
        assertTrue(r.la.any { it is CellHostEvent.CommandHeld && it.command == "publish" })
        assertFalse(r.la.any { it is CellHostEvent.Sent && it.kind == "msg" })
        val mark = r.la.size
        r.sa.release()
        r.await(publishing); r.settle()
        val after = r.la.drop(mark).map(::shape)
        assertEquals(0, after.indexOf("persist:stored"))
        assertTrue(after.indexOf("event:becameHolder") < after.indexOf("event:presenceChanged"))
        assertTrue(after.indexOf("event:presenceChanged") < after.indexOf("sent:msg"))
        assertTrue(r.la.none { it is CellHostEvent.Drop })
        r.close()
    }

    @Test fun aFailedWriteIsRetriedAndNeverAcknowledgedUntilItSucceeds() {
        val r = Pair2()
        r.sa.failures = 2
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        r.settle()
        fun failed() = r.la.count { it is CellHostEvent.Persist && it.phase == PersistPhase.FAILED }
        assertEquals(1, failed())
        assertFalse(r.la.any { it is CellHostEvent.Sent && it.kind == "take" })
        r.clock.advance(250, 5)
        assertEquals(2, failed())
        assertNotNull(r.a.current!!.awaitingPersist())
        r.clock.advance(250, 5)
        assertEquals(1, r.la.count { it is CellHostEvent.Persist && it.phase == PersistPhase.STORED })
        assertTrue(r.la.any { it is CellHostEvent.Sent && it.kind == "take" })
        assertEquals(3, r.sa.writes.size)
        r.close()
    }

    @Test fun aStaleViewIsReplacedAndTheInputRuns() = runBlocking {
        val r = Pair2()
        // A third member is approved on A's device: A's engine has a new authority head.
        val third = Device(medium = first.medium, namespaces = listOf(NS))
        third.session.restore()
        approveByScan(third.session, first.session)
        val mark = r.la.size
        r.await(r.b.command("presence", cmd("command" to "presence", "payload" to b64("""{"label":"Car"}"""))))
        r.settle()
        val after = r.la.drop(mark).map(::shape)
        assertTrue(after.indexOf("stale") >= 0, after.toString())
        assertTrue(after.indexOf("account") > after.indexOf("stale"))
        assertTrue("event:presenceChanged" in after)
        assertEquals(1, r.a.stats.stale)
        third.close()
        r.close()
    }

    @Test fun aClockThatGoesBackRebuildsFromTheStoredClaimAndTheRestartedHolderIsGated() {
        val r = Pair2()
        r.await(r.a.command("take", cmd("command" to "take", "state" to b64("anchor-0"))))
        r.settle()
        assertTrue(r.a.current!!.isHolder())
        val key = r.a.current!!.keyId()
        r.clock.jump(r.clock.mono - 5_000)
        r.await(r.b.command("presence", cmd("command" to "presence", "payload" to b64("{}"))))
        r.loop.until("the rebuild") { r.la.any { it is CellHostEvent.Rebuilt } && r.a.phase == SessionCellHost.Phase.OPEN && r.a.current?.joined() == true }
        assertTrue(r.la.any { it is CellHostEvent.Rebuilt && it.reason == RebuildReason.CLOCK_BACKWARDS })
        assertNotEquals(key, r.a.current!!.keyId())
        assertEquals(true, Json.obj(r.a.current!!.viewJson())!!["gated"])
        // It waits out askTimeoutMs, then retakes.
        r.clock.advance(2_000, 5)
        assertEquals(false, Json.obj(r.a.current!!.viewJson())!!["gated"])
        assertTrue(r.a.current!!.isHolder())
        r.close()
    }

    @Test fun framesReachTheEndpointAsTheCarriedTextAReserialisedFrameWouldDiffer() {
        val r = Pair2()
        r.await(r.a.command("take", cmd("command" to "take", "state" to b64("anchor-0"))))
        r.settle()
        val sent = r.carrier.carried.filter { it.first === r.a }.map { it.second }
        assertTrue(sent.isNotEmpty())
        val frame = sent.last()
        assertEquals(frame, Frames.sessionFrameText("""{"type":"session","frame":$frame,"retained":true}"""))
        assertEquals(frame, Frames.sessionFrameText("""{"n":7, "type":"session", "frame" : $frame }"""))
        assertNull(Frames.sessionFrameText("""{"type":"session","frame":$frame,"frame":$frame}"""))
        // A frame whose text is not canonical (an escape a parser decodes): re-serialising would make it canonical.
        val escaped = frame.replace("\"cell\":\"now-playing\"", "\"cell\":\"now\\u002dplaying\"")
        assertNotEquals(frame, escaped)
        val message = """{"type":"session","frame":$escaped}"""
        assertEquals(escaped, Frames.sessionFrameText(message))
        @Suppress("UNCHECKED_CAST")
        assertEquals(frame, Json.write(Json.obj(message)!!["frame"] as Map<String, Any?>, sorted = false), "re-serialising gives the sender's bytes")
        val drops = r.b.stats.drops
        r.b.deliver(Frames.sessionFrameText(message)!!)
        r.settle()
        assertEquals(drops + 1, r.b.stats.drops)
        r.close()
    }

    @Test fun listenersThatCallBackIntoTheHostNeverReEnterTheEndpoint() {
        val r = Pair2()
        var lastFrame: String? = null
        var calls = 0
        r.a.on { e ->
            calls++
            if (e is CellHostEvent.Sent) lastFrame = e.frame
            r.a.accountChanged(); r.a.linkUp()
            lastFrame?.let { if (calls < 200) r.b.deliver(it) }
            if (calls < 20) r.a.command("presence", cmd("command" to "presence", "payload" to b64("{}")))
            if (e is CellHostEvent.Persist && e.phase == PersistPhase.STARTED) {
                // A backwards clock and an input while the write is under way: the rebuild waits for that write.
                r.clock.jump(r.clock.mono - 1_000)
                r.a.deliver(lastFrame ?: "{}")
            }
        }
        r.sa.hold = true
        r.await(r.a.command("take", cmd("command" to "take", "state" to b64("anchor-0"))))
        r.settle()
        assertTrue(r.a.writePending)
        assertTrue(r.la.any { it is CellHostEvent.Rebuilt })
        assertNull(r.a.current, "rebuilt only once the write completes")
        r.sa.release()
        r.loop.until("the rebuild") { r.a.phase == SessionCellHost.Phase.OPEN && r.a.current != null }
        r.settle()
        assertEquals(first.session.memberId, (Json.obj(r.a.storedClaim!!)!!["claim"] as Map<*, *>)["holder"])
        assertEquals(first.session.memberId, Json.obj(r.a.current!!.claimJson()!!)!!["holder"])
        assertEquals(listOf(), r.la.filterIsInstance<CellHostEvent.Error>())
        r.close()
    }

    @Test fun aDelegationThatCannotBeSignedFailsOpenAndLeavesNothingAttached() {
        val loop = ManualLoop()
        val carrier = LoopCarrier(loop)
        val real = accountOf(first.session)
        val account = object : HostAccount by real { override suspend fun signRaw(body: ByteArray): ByteArray = throw IllegalStateException("the key is unavailable") }
        val failed = runCatching { loop.run { SessionCellHost.open(CellHostOptions(account, carrier.view(), NS, CELL, TestStore(), clock = ManualClock(loop), dispatcher = loop.dispatcher)) } }
        assertTrue(failed.isFailure)
        loop.settle()
        assertEquals(0, carrier.cells.size)
    }

    @Test fun aRebuildThatFailsLeavesTheCellFailed() {
        val r = Pair2()
        val real = accountOf(first.session)
        r.a.replaceForTests(account = object : HostAccount by real { override suspend fun signRaw(body: ByteArray): ByteArray = throw IllegalStateException("the key is unavailable") })
        r.clock.jump(r.clock.mono - 1_000)
        val held = r.a.command("presence", cmd("command" to "presence", "payload" to b64("{}")))
        r.loop.until("the failure") { r.a.phase == SessionCellHost.Phase.FAILED }
        r.settle()
        assertTrue(r.la.any { it is CellHostEvent.Failed && it.reason == FailReason.REBUILD })
        assertEquals(CellHostError.Code.FAILED, failure(held))
        assertEquals(CellHostError.Code.FAILED, failure(r.a.command("ask", cmd("command" to "ask"))))
        assertFalse(r.a in r.carrier.cells)
        r.close()
    }

    @Test fun aStoreThatKeepsFailingFailsTheCell() {
        val r = Pair2 { CellHostOptions(it.account, it.carrier, NS, CELL, it.store, clock = it.clock, dispatcher = it.dispatcher, persistAttempts = 3) }
        r.sa.failures = 1_000
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        val waiting = r.a.command("publish", cmd("command" to "publish", "id" to "AAAAAAAAAAAAAAAAAAAAAA", "payload" to b64("x")))
        r.settle()
        r.clock.advance(250, 5); r.clock.advance(250, 5)
        assertEquals(3, r.la.count { it is CellHostEvent.Persist && it.phase == PersistPhase.FAILED })
        assertTrue(r.la.any { it is CellHostEvent.Failed && it.reason == FailReason.STORE })
        assertFalse(r.la.any { it is CellHostEvent.Sent && it.kind == "take" })
        assertEquals(CellHostError.Code.FAILED, failure(waiting))
        assertNull(r.a.current)
        r.close()
    }

    @Test fun commandAdmissionIsBoundedAndKeepsOrder() {
        val r = Pair2 { CellHostOptions(it.account, it.carrier, NS, CELL, it.store, clock = it.clock, dispatcher = it.dispatcher, maxCommands = 2) }
        r.sa.hold = true
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        val one = r.a.command("publish", cmd("command" to "publish", "id" to "AAAAAAAAAAAAAAAAAAAAAA", "payload" to b64("1")))
        val two = r.a.command("publish", cmd("command" to "publish", "id" to "AQAAAAAAAAAAAAAAAAAAAA", "payload" to b64("2")))
        assertEquals(CellHostError.Code.COMMAND_QUEUE_FULL, failure(r.a.command("publish", cmd("command" to "publish", "id" to "AgAAAAAAAAAAAAAAAAAAAA", "payload" to b64("3")))))
        r.sa.release()
        r.await(one); r.await(two); r.settle()
        val messages = r.la.filterIsInstance<CellHostEvent.Session>().filter { it.name == "message" }.map { it.fields["payload"] }
        assertEquals(listOf(b64("1"), b64("2")), messages)
        r.close()
    }

    @Test fun afterANewHeadThatRemovesAMemberItsFramesAreDroppedAndChangeNothing() = runBlocking {
        val r = Pair2()
        val third = Device(medium = first.medium, namespaces = listOf(NS))
        third.session.restore()
        approveByScan(third.session, first.session)
        third.session.refresh(); second.session.refresh()
        val thirdHost = r.loop.run { SessionCellHost.open(CellHostOptions(accountOf(third.session), r.carrier.view(), NS, CELL, TestStore(), clock = r.clock, dispatcher = r.loop.dispatcher)) }
        r.settle()
        r.carrier.paused = true
        r.await(thirdHost.command("presence", cmd("command" to "presence", "payload" to b64("""{"label":"Old phone"}"""))))
        val sealed = r.carrier.carried.last { it.first === thirdHost }.second
        thirdHost.close(); r.settle()
        first.session.revoke(third.session.memberId!!)
        second.session.refresh()
        r.b.accountChanged(); r.settle()
        assertTrue(r.lb.any { it is CellHostEvent.Account })
        val mark = r.lb.size
        val view = r.b.current!!.viewJson()
        r.b.deliver(sealed); r.settle()
        val judged = r.lb.drop(mark).filter { it is CellHostEvent.Drop || it is CellHostEvent.Queued || it is CellHostEvent.Missed || it is CellHostEvent.Session }
        assertEquals(listOf("drop"), judged.map(::shape))
        assertEquals(view, r.b.current!!.viewJson())
        third.close()
        r.close()
    }

    @Test fun inputsRunInAdmissionOrderCommandFrameCommandFromAListener() {
        val r = Pair2()
        r.await(r.a.command("take", cmd("command" to "take", "state" to null))); r.settle()
        r.carrier.paused = true
        r.await(r.b.command("presence", cmd("command" to "presence", "payload" to b64("""{"label":"Hall"}"""))))
        val frame = r.carrier.carried.last().second
        var fired = false
        r.a.on { e ->
            if (fired || e !is CellHostEvent.Sent || e.kind != "presence") return@on
            fired = true
            r.a.command("publish", cmd("command" to "publish", "id" to "AAAAAAAAAAAAAAAAAAAAAA", "payload" to b64("1")))
            r.a.deliver(frame)
            r.a.command("publish", cmd("command" to "publish", "id" to "AQAAAAAAAAAAAAAAAAAAAA", "payload" to b64("2")))
        }
        val mark = r.la.size
        r.await(r.a.command("presence", cmd("command" to "presence", "payload" to b64("""{"label":"Desk"}"""))))
        r.settle()
        val order = r.la.drop(mark).map(::shape).filter { it == "sent:msg" || it == "event:presenceChanged" }
        assertEquals(listOf("sent:msg", "event:presenceChanged", "sent:msg"), order)
        r.close()
    }

    @Test fun behindAWriteAHeldCommandKeepsItsPlaceALaterFrameRunsAtTheAcknowledgement() {
        val r = Pair2()
        r.carrier.paused = true
        r.await(r.b.command("presence", cmd("command" to "presence", "payload" to b64("""{"label":"Hall"}"""))))
        val frame = r.carrier.carried.last().second
        r.sa.hold = true
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        val mark = r.la.size
        val one = r.a.command("publish", cmd("command" to "publish", "id" to "AAAAAAAAAAAAAAAAAAAAAA", "payload" to b64("1")))
        r.a.deliver(frame)
        val two = r.a.command("publish", cmd("command" to "publish", "id" to "AQAAAAAAAAAAAAAAAAAAAA", "payload" to b64("2")))
        r.settle()
        r.sa.release()
        r.await(one); r.await(two); r.settle()
        val wanted = setOf("commandHeld", "queued", "persist:stored", "event:becameHolder", "event:presenceChanged", "sent:msg")
        assertEquals(listOf("commandHeld", "queued", "persist:stored", "event:becameHolder", "event:presenceChanged", "sent:msg", "sent:msg"),
            r.la.drop(mark).map(::shape).filter { it in wanted })
        r.close()
    }

    @Test fun aWriteThatNeverSettlesCountsAsFailedAtItsDeadline() {
        val r = Pair2 { CellHostOptions(it.account, it.carrier, NS, CELL, it.store, clock = it.clock, dispatcher = it.dispatcher, persistAttempts = 3, persistTimeoutMs = 1_000) }
        r.a.replaceForTests(store = object : ClaimStore by r.sa {
            override suspend fun save(record: StoredClaim, expected: Fence?): SaveResult = CompletableDeferred<SaveResult>().await()
        })
        r.await(r.a.command("take", cmd("command" to "take", "state" to null))); r.settle()
        r.clock.advance(999)
        assertEquals(0, r.la.count { it is CellHostEvent.Persist && it.phase == PersistPhase.FAILED })
        r.clock.advance(1)
        assertEquals(listOf(CellHostError.Code.TIMEOUT), r.la.filterIsInstance<CellHostEvent.Persist>().filter { it.phase == PersistPhase.FAILED }.map { (it.error as CellHostError).code })
        r.clock.advance(250 + 1_000 + 250 + 1_000)
        assertTrue(r.la.any { it is CellHostEvent.Failed && it.reason == FailReason.STORE })
        assertFalse(r.la.any { it is CellHostEvent.Sent && it.kind == "take" })
        r.close()
    }

    @Test fun oneSaveAtATimeAnOverdueAttemptIsWaitedForALateSuccessIsSavedAgain() {
        val r = Pair2 { CellHostOptions(it.account, it.carrier, NS, CELL, it.store, clock = it.clock, dispatcher = it.dispatcher, persistTimeoutMs = 1_000) }
        val store = r.sa
        val before = store.writes.size
        store.hang = 1
        r.await(r.a.command("take", cmd("command" to "take", "state" to null))); r.settle()
        r.clock.advance(1_000)
        assertEquals(1, r.la.count { it is CellHostEvent.Persist && it.phase == PersistPhase.FAILED })
        assertEquals(1, store.writes.size - before)
        r.clock.advance(3_000)
        assertEquals(1, store.writes.size - before, "no second save while the first is in flight")
        store.hung.removeAt(0).complete(Unit)
        r.settle(); r.clock.advance(0)
        assertEquals(1, r.la.count { it is CellHostEvent.Persist && it.phase == PersistPhase.STORED })
        assertEquals(2, store.writes.size - before)
        r.await(r.a.command("release", cmd("command" to "release"))); r.settle()
        assertEquals(true, Json.obj(store.value!!)!!["released"])
        assertEquals(1, store.maxInflight)
        for (k in 1 until store.fences.size) assertTrue(store.fences[k] > store.fences[k - 1], "fences rise: ${store.fences}")
        r.close()
    }

    @Test fun aStoreThatAnswersStaleAndCannotBeReadUsesUpTheAttemptsAndFailsClosed() {
        val r = Pair2 { CellHostOptions(it.account, it.carrier, NS, CELL, it.store, clock = it.clock, dispatcher = it.dispatcher, persistAttempts = 3) }
        // Every save is stale, `load` fails, and `fence` keeps answering the fence the host holds (so the beat check
        // finds nothing wrong): the host cannot tell whose fence is held.
        var saves = 0
        r.a.replaceForTests(store = object : ClaimStore by r.sa {
            override suspend fun load(): StoredClaim? = throw java.io.IOException("the disk is unreadable")
            override suspend fun save(record: StoredClaim, expected: Fence?): SaveResult { saves++; return SaveResult.STALE }
        })
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        r.settle()
        assertEquals(1, saves, "no immediate second save: an unknown adoption waits for the retry")
        r.clock.advance(249, 5)
        assertEquals(1, saves)
        r.clock.advance(1, 5)
        assertEquals(2, saves)
        r.clock.advance(250, 5)
        assertEquals(3, saves)
        assertTrue(r.la.any { it is CellHostEvent.Failed && it.reason == FailReason.STORE })
        assertEquals(3, r.la.count { it is CellHostEvent.Persist && it.phase == PersistPhase.FAILED })
        r.clock.advance(10_000, 5)
        assertEquals(3, saves, "nothing more once failed")
        assertFalse(r.la.any { it is CellHostEvent.Sent && it.kind == "take" })
        r.close()
    }

    @Test fun aStoreThatAnswersStaleWhileHoldingTheHostsOwnFenceCannotLoopForever() {
        val r = Pair2 { CellHostOptions(it.account, it.carrier, NS, CELL, it.store, clock = it.clock, dispatcher = it.dispatcher, persistAttempts = 4) }
        // Stale, yet the record held is the host's own fence: each is adopted, and each is charged.
        var saves = 0
        r.a.replaceForTests(store = object : ClaimStore by r.sa {
            override suspend fun save(record: StoredClaim, expected: Fence?): SaveResult { saves++; return SaveResult.STALE }
        })
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        r.settle()
        assertEquals(4, saves)
        assertTrue(r.la.any { it is CellHostEvent.Failed && it.reason == FailReason.STORE })
        r.close()
    }

    @Test fun anOldInstancesSaveThatSettlesLateIsRefusedAcrossAReplacement() {
        val loop = ManualLoop(); val clock = ManualClock(loop); val carrier = LoopCarrier(loop)
        val store = TestStore(clock = clock)
        fun options() = CellHostOptions(accountOf(first.session), carrier.view(), NS, CELL, store, clock = clock, dispatcher = loop.dispatcher, persistTimeoutMs = 1_000)
        val old = loop.run { SessionCellHost.open(options()) }
        store.hang = 1
        loop.run { old.command("take", cmd("command" to "take", "state" to null)).await() }
        loop.settle(); old.close(); loop.settle()
        val replacement = loop.run { SessionCellHost.open(options()) }
        loop.run { replacement.command("take", cmd("command" to "take", "state" to null)).await() }
        loop.settle(20); clock.advance(1_000, 5)
        loop.run { replacement.command("release", cmd("command" to "release")).await() }
        loop.settle(20)
        val newest = store.value
        assertEquals(true, Json.obj(newest!!)!!["released"])
        store.hung.removeAt(0).complete(Unit); loop.settle()
        assertEquals(1, store.refused)
        assertEquals(newest, store.value)
        replacement.close(); loop.settle()
    }

    @Test fun anInstanceWhoseReservationIsRefusedDoesNotOpen() {
        val loop = ManualLoop(); val carrier = LoopCarrier(loop)
        val store = object : ClaimStore by TestStore() { override suspend fun save(record: StoredClaim, expected: Fence?) = SaveResult.STALE }
        val failed = runCatching { loop.run { SessionCellHost.open(CellHostOptions(accountOf(first.session), carrier.view(), NS, CELL, store, clock = ManualClock(loop), dispatcher = loop.dispatcher)) } }
        assertEquals(CellHostError.Code.SUPERSEDED, (failed.exceptionOrNull() as? CellHostError)?.code)
        assertEquals(0, carrier.cells.size)
    }

    @Test fun closeAndFailureCancelTheRetryAndDeadlineTimers() {
        for (ending in listOf("close", "fail")) {
            val loop = ManualLoop(); val clock = ManualClock(loop)
            val store = TestStore(clock = clock)
            val host = loop.run { SessionCellHost.open(CellHostOptions(accountOf(first.session), LoopCarrier(loop).view(), NS, CELL, store, clock = clock, dispatcher = loop.dispatcher,
                persistAttempts = 2, persistTimeoutMs = 1_000)) }
            store.failures = 1; store.hang = 1
            loop.run { host.command("take", cmd("command" to "take", "state" to null)).await() }
            loop.settle()
            if (ending == "close") { host.close(); loop.settle() } else {
                clock.advance(250); clock.advance(1_000)
                assertEquals(SessionCellHost.Phase.FAILED, host.phase)
            }
            assertEquals(0, clock.pending, "$ending leaves no timer")
            assertEquals(1, store.maxInflight)
            host.close(); loop.settle()
        }
    }

    @Test fun theFenceCheckRunsEveryBeatEvenWhileAWriteIsInFlight() {
        val r = Pair2()
        r.sa.hold = true
        r.await(r.a.command("take", cmd("command" to "take", "state" to null)))
        val reads = r.sa.fenceReads
        r.clock.advance(5_000 * 3)
        assertEquals(3, r.sa.fenceReads - reads)
        assertEquals(SessionCellHost.Phase.OPEN, r.a.phase)
        r.sa.release(); r.settle()
        r.clock.advance(5_000)
        assertEquals(SessionCellHost.Phase.OPEN, r.a.phase)
        r.close()
    }

    @Test fun fenceChecksThatKeepFailingOrNeverAnswerFailTheCellClosedThreeBeatsAfterTheFirstMiss() {
        for (mode in listOf("reject", "hang", "once")) {
            val r = Pair2()
            val opened = r.clock.mono
            when (mode) { "reject" -> r.sa.fenceFailures = 3; "once" -> r.sa.fenceFailures = 1; "hang" -> r.sa.fenceHang = true }
            var failedAt: Long? = null
            r.a.on { if (it is CellHostEvent.Failed && failedAt == null) failedAt = r.clock.mono }
            repeat(48) { r.clock.advance(1_000) }
            val failed = r.la.filterIsInstance<CellHostEvent.Failed>().firstOrNull()
            if (mode == "once") { assertNull(failed, mode); r.close(); continue }
            assertEquals(FailReason.STORE, failed?.reason, mode)
            val firstRead = opened + 5_000
            // A rejected read is a miss at once (reads at beats 1, 2 and 3); an unanswered one at the end of its beat.
            assertEquals(if (mode == "hang") 15_000L else 10_000L, failedAt!! - firstRead, mode)
            r.close()
        }
    }

    @Test fun cellSessionPublishesTypedState() {
        val loop = ManualLoop(); val clock = ManualClock(loop); val carrier = LoopCarrier(loop)
        val cell = loop.run { CellSession.join(CellHostOptions(accountOf(first.session), carrier.view(), NS, CELL, TestStore(clock = clock), clock = clock, dispatcher = loop.dispatcher)) }
        loop.settle(20)
        val events = ArrayList<CellEvent>()
        cell.events { events.add(it) }
        loop.run { cell.take("anchor".toByteArray()).await() }
        loop.settle(20)
        assertTrue(cell.state.isHolder && !cell.state.gated && cell.state.joined && cell.state.canWrite)
        assertEquals(first.session.memberId, cell.state.holder)
        assertContentEquals("anchor".toByteArray(), (events.filterIsInstance<CellEvent.BecameHolder>().single()).snapshot)
        val id = loop.run { cell.publish("next".toByteArray()).await() }
        loop.settle(20)
        assertContentEquals("next".toByteArray(), cell.state.state)
        assertContentEquals(id, events.filterIsInstance<CellEvent.Message>().last().id)
        loop.run { cell.leave() }
        loop.settle()
        if (cell.host.phase != SessionCellHost.Phase.CLOSED) fail("left")
    }
}
