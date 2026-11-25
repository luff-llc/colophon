package com.luff.colophon.hosts

import com.luff.colophon.session.Device
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The fence across independent store clients: two clients of the same storage racing to open (in every interleaving of
 * their transactions a fake can force), a rebuild racing an open, a superseded holder stopping within one beat, threads
 * racing the memory store's compare-and-set, and fences out of range refused (js/test06/claim-fence.test.ts).
 */
class ClaimFenceTest {
    companion object {
        const val BEAT = 400L
        val policy = """{"beatMs":$BEAT,"holderTimeoutMs":1500,"askTimeoutMs":300,"presenceTimeoutMs":1500,"retainMs":60000,"tail":256,"maxPayload":8192,"fold":"latest","take":"free"}"""
        lateinit var device: Device
        @BeforeClass @JvmStatic fun account() = runBlocking { device = Device(namespaces = listOf(NS)); device.session.create() }
        @AfterClass @JvmStatic fun close() = runBlocking { device.close() }
    }

    /** A carrier that carries nothing (these tests are about the store). */
    private fun nowhere(loop: ManualLoop) = object : CellCarrier {
        override fun attach(cell: StreamCell) { loop.dispatcher.dispatch(kotlin.coroutines.EmptyCoroutineContext, Runnable { cell.linkUp() }) }
        override fun detach(cell: StreamCell) {}
        override fun sendSession(frame: String, lost: () -> Unit) = true
    }

    /**
     * One storage and any number of client handles on it. Each read and each compare-and-set is one transaction,
     * applied atomically when the test lets it run; transactions of different handles interleave in the order it picks.
     */
    class SteppedStorage {
        var record: StoredClaim? = null
        var gated = true
        val pending = ArrayList<Pair<String, () -> Unit>>()
        fun handle(tag: String): ClaimStore = object : ClaimStore {
            private suspend fun <T> step(body: () -> T): T {
                val done = CompletableDeferred<T>()
                val run = { try { done.complete(body()) } catch (e: Throwable) { done.completeExceptionally(e) }; Unit }
                synchronized(this@SteppedStorage) { if (gated) pending.add(tag to run) else run() }
                return done.await()
            }
            override suspend fun load() = step { record }
            override suspend fun fence() = step { record?.fence }
            override suspend fun save(record: StoredClaim, expected: Fence?) = step {
                val next = compareAndSet(this@SteppedStorage.record, record, expected)
                if (next == null) SaveResult.STALE else { this@SteppedStorage.record = next; SaveResult.STORED }
            }
        }
        /** Runs one pending transaction of `tag`, driving `loop` until it has been issued. */
        fun release(loop: ManualLoop, tag: String) {
            loop.until("$tag issues a transaction") { synchronized(this) { pending.any { it.first == tag } } }
            val run = synchronized(this) { pending.removeAt(pending.indexOfFirst { it.first == tag }).second }
            run(); loop.settle()
        }
        fun free() { val all = synchronized(this) { gated = false; pending.toList().also { pending.clear() } }; all.forEach { it.second() } }
    }

    /** Every order of `a` copies of A and `b` copies of B. */
    private fun interleavings(a: Int, b: Int): List<List<String>> = when {
        a == 0 -> listOf(List(b) { "B" })
        b == 0 -> listOf(List(a) { "A" })
        else -> interleavings(a - 1, b).map { listOf("A") + it } + interleavings(a, b - 1).map { listOf("B") + it }
    }

    private fun open(loop: ManualLoop, clock: ManualClock, store: ClaimStore, log: MutableList<CellHostEvent>? = null): Deferred<SessionCellHost> =
        loop.start { SessionCellHost.open(CellHostOptions(HostAccess.of(device.session), nowhere(loop), NS, CELL, store, policy, clock, dispatcher = loop.dispatcher)) { log?.add(it) } }

    /** The hosts still acting once every watch has had a beat to look. */
    private fun survivors(loop: ManualLoop, clock: ManualClock, hosts: List<SessionCellHost>): List<SessionCellHost> {
        loop.until("opens and rebuilds finish") { hosts.none { it.phase == SessionCellHost.Phase.OPENING || it.phase == SessionCellHost.Phase.REBUILDING } }
        clock.advance(BEAT + 1, 10)
        return hosts.filter { it.phase == SessionCellHost.Phase.OPEN }
    }
    private fun <T> settled(loop: ManualLoop, d: Deferred<T>): T? { loop.until("the open settles") { d.isCompleted }; return if (d.getCompletionExceptionOrNull() != null) null else d.getCompleted() }

    @Test fun twoClientsOpenAtOnceInEveryInterleavingExactlyOneHoldsTheCell() {
        for (order in interleavings(2, 2)) {
            val storage = SteppedStorage(); val loop = ManualLoop(); val clock = ManualClock(loop)
            val opens = listOf(open(loop, clock, storage.handle("A")), open(loop, clock, storage.handle("B")))
            // Each open's first two transactions (its load and its reservation) run in this order; then everything runs.
            for (tag in order) storage.release(loop, tag)
            storage.free()
            val hosts = opens.mapNotNull { settled(loop, it) }
            assertEquals(1, survivors(loop, clock, hosts).size, "order $order")
            hosts.forEach { it.close() }; loop.settle()
        }
    }

    @Test fun aRebuildRacesAnOpenInEveryInterleavingExactlyOneHoldsTheCell() {
        for (order in interleavings(1, 2)) {
            val storage = SteppedStorage(); storage.gated = false
            val loop = ManualLoop(); val clock = ManualClock(loop)
            val a = settled(loop, open(loop, clock, storage.handle("A")))!!
            synchronized(storage) { storage.gated = true }
            // A rebuilds (its clock went back), reserving a new generation, while B opens.
            clock.jump(clock.mono - 1_000)
            a.linkDown()
            val b = open(loop, clock, storage.handle("B"))
            for (tag in order) storage.release(loop, tag)
            storage.free()
            val hosts = listOfNotNull(a, settled(loop, b))
            clock.advance(1_000, 10)
            assertEquals(1, survivors(loop, clock, hosts).size, "order $order")
            hosts.forEach { it.close() }; loop.settle()
        }
    }

    @Test fun aSupersededHolderStopsWithinOneBeatAndSendsNothingAfter() {
        val store = MemoryClaimStore(); val loop = ManualLoop(); val clock = ManualClock(loop)
        val log = ArrayList<CellHostEvent>()
        val a = settled(loop, open(loop, clock, store, log))!!
        loop.run { a.command("take", cmd("command" to "take", "state" to null)).await() }
        loop.settle(10)
        val replaced = clock.mono
        val b = settled(loop, open(loop, clock, store))!!
        clock.advance(BEAT, 5)
        val failed = log.indexOfFirst { it is CellHostEvent.Failed && it.reason == FailReason.SUPERSEDED }
        assertTrue(failed >= 0)
        assertTrue(clock.mono - replaced <= BEAT)
        repeat(10) { clock.advance(BEAT) }
        assertEquals(listOf(), log.drop(failed).filterIsInstance<CellHostEvent.Sent>())
        assertEquals(SessionCellHost.Phase.FAILED, a.phase)
        assertEquals(SessionCellHost.Phase.OPEN, b.phase)
        a.close(); b.close(); loop.settle()
    }

    @Test fun threadsRacingTheMemoryStoreFromOneFenceStoreExactlyOnce() = runBlocking {
        val store = MemoryClaimStore(StoredClaim(null, Fence(3, 7)))
        repeat(20) { round ->
            val held = store.fence()
            val start = CountDownLatch(1)
            val stored = AtomicInteger()
            val threads = (0 until 8).map { k ->
                Thread {
                    start.await()
                    runBlocking { if (store.save(StoredClaim("c$round.$k", Fence(held!!.generation + 1, 0)), held) == SaveResult.STORED) stored.incrementAndGet() }
                }.apply { start() }
            }
            start.countDown(); threads.forEach { it.join() }
            assertEquals(1, stored.get(), "round $round")
        }
        // A save that does not rise, or expects another fence, writes nothing.
        val held = store.load()!!
        assertEquals(SaveResult.STALE, store.save(StoredClaim("x", held.fence), held.fence))
        assertEquals(SaveResult.STALE, store.save(StoredClaim("x", Fence(held.fence.generation + 1, 0)), Fence(0, 0)))
        assertEquals(SaveResult.STALE, store.save(StoredClaim("x", Fence(held.fence.generation + 1, 0)), null))
        assertEquals(held, store.load())
    }

    @Test fun fencesOutOfRangeAreRefused() {
        for (v in listOf(-1L, Fence.MAX + 1, Long.MAX_VALUE, Long.MIN_VALUE)) {
            assertFailsWith<IllegalArgumentException> { Fence(v, 0) }
            assertFailsWith<IllegalArgumentException> { Fence(0, v) }
        }
        Fence(Fence.MAX, Fence.MAX)
        assertTrue(Fence(2, 0) > Fence(1, 99) && Fence(1, 2) > Fence(1, 1))
    }
}
