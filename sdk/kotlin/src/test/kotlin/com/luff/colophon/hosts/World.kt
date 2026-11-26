package com.luff.colophon.hosts

import com.luff.colophon.session.Device
import com.luff.colophon.session.HistoryAccess
import com.luff.colophon.session.HomeConfiguration
import com.luff.colophon.session.HomeTransport
import com.luff.colophon.session.HomeTransportException
import com.luff.colophon.session.Json
import com.luff.colophon.session.MemoryMedium
import com.luff.colophon.session.RelayHome
import com.luff.colophon.session.SessionPhase
import com.luff.colophon.session.approveByScan
import com.luff.colophon.sessionDefaultPolicy
import kotlinx.coroutines.runBlocking
import java.io.IOException
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Milliseconds on the hosts' own monotonic clock (what every anchor and measurement here uses). */
fun nowMs(): Long = SystemHostClock.monoMs()
/** Fractional milliseconds on a monotonic clock, for event times and measurements. */
fun t(): Double = System.nanoTime() / 1e6

/** A device's network: when down, sockets fail and requests are offline. */
class Network(private val relay: RelayHome) {
    @Volatile var up = true
    private val open = Collections.synchronizedSet(LinkedHashSet<() -> Unit>())
    private val jdk = JdkWebSocketFactory()
    /** Sockets reaching the relay on loopback for the account's `https` name, over the JVM's real WebSocket. */
    fun sockets() = SocketFactory { url, handlers ->
        val local = url.replaceFirst("wss://", "ws://").replace(relay.base.removePrefix("https://"), "127.0.0.1:${relay.port}/v1/libraries/home")
        if (!up) {
            Thread { handlers.closed(null) }.start()
            return@SocketFactory object : HostSocket { override fun send(text: String, done: (Boolean) -> Unit) = throw IOException("offline"); override fun close(code: Int) {} }
        }
        val ended = AtomicBoolean(false)
        var entry: () -> Unit = {}
        val inner = jdk.open(local, object : SocketHandlers {
            override fun open() { if (!ended.get()) handlers.open() }
            override fun message(text: String) { if (!ended.get()) handlers.message(text) }
            override fun refused(answer: com.luff.colophon.HttpAnswer) { if (ended.compareAndSet(false, true)) { open.remove(entry); handlers.refused(answer) } }
            override fun closed(code: Int?) { if (ended.compareAndSet(false, true)) { open.remove(entry); handlers.closed(code) } }
        })
        entry = { if (ended.compareAndSet(false, true)) { inner.close(1000); open.remove(entry); handlers.closed(null) } }
        open.add(entry)
        object : HostSocket {
            override fun send(text: String, done: (Boolean) -> Unit) { if (!up) throw IOException("offline"); inner.send(text, done) }
            override fun close(code: Int) { ended.set(true); open.remove(entry); inner.close(code) }
        }
    }
    fun transport(inner: HomeTransport) = HomeTransport { request -> if (up) inner.send(request) else throw HomeTransportException.Offline("the network is down") }
    fun down() { up = false; synchronized(open) { open.toList() }.forEach { it() } }
    fun restore() { up = true }
}

/** One member: its session, network, stream host and (once joined) its cell. */
class Member(val name: String, val device: Device, val relay: RelayHome) {
    lateinit var stream: HomeStreamHost
    lateinit var cell: CellSession
    val network = Network(relay)
    val store = TestStore()
    val log: MutableList<Pair<Double, CellHostEvent>> = Collections.synchronizedList(ArrayList())
    val events: MutableList<Pair<Double, CellEvent>> = Collections.synchronizedList(ArrayList())
    /** The application's own state (its last anchor), kept to supply on join after a restart (§S12). */
    @Volatile var appState: ByteArray? = null
    val id: String get() = device.session.memberId!!

    fun startStream() = runBlocking {
        val session = device.session
        val home = session.worker.requireEngine().run { it.exchangeHomes() }.first()
        val transport = transportOf(session, home.id) ?: error("the home has a transport")
        stream = HomeStreamHost(StreamHostOptions(HostAccess.of(session), home.id, network.sockets(), network.transport(transport)))
        stream.start()
    }
    fun join(policy: String? = null) = runBlocking {
        cell = CellSession.join(CellHostOptions(HostAccess.of(device.session), stream.carrier(), NS, CELL, store, policy, state = { appState }))
        cell.host.on { log.add(t() to it) }
        cell.events { events.add(t() to it) }
    }
    /** The first event (at or after `since`) of type `T` matching `match`, waiting up to `ms`. */
    inline fun <reified T : CellEvent> until(since: Double = 0.0, ms: Long = 10_000, crossinline match: (T) -> Boolean = { true }): Pair<Double, T> {
        val end = System.currentTimeMillis() + ms
        while (true) {
            val found = synchronized(events) { events.firstOrNull { it.first >= since && it.second is T && match(it.second as T) } }
            @Suppress("UNCHECKED_CAST") if (found != null) return found as Pair<Double, T>
            check(System.currentTimeMillis() < end) { "$name: no ${T::class.simpleName} within $ms ms; saw ${synchronized(events) { events.filter { it.first >= since }.map { it.second.javaClass.simpleName } }}" }
            Thread.sleep(5)
        }
    }
    /** Waits for `condition`, up to `ms`; returns when it held. */
    fun whenTrue(what: String, ms: Long = 10_000, condition: () -> Boolean): Double {
        val end = System.currentTimeMillis() + ms
        while (!condition()) { check(System.currentTimeMillis() < end) { "$name: $what did not happen within $ms ms" }; Thread.sleep(5) }
        return t()
    }
    fun logSince(from: Double, to: Double = Double.MAX_VALUE) = synchronized(log) { log.filter { it.first >= from && it.first < to } }
    /** Plaintext kinds of the frames this member handed to the carrier in [from, to). */
    fun sentKinds(from: Double, to: Double = Double.MAX_VALUE) = logSince(from, to).mapNotNull { (it.second as? CellHostEvent.Sent)?.kind }
    fun close() = runBlocking {
        runCatching { cell.close() }; runCatching { stream.stop() }
        device.close()
    }
}

/**
 * The end-to-end world: a real home (relay/server.js on Bun with the Rust home module built from this tree, bound on a
 * port of its own choosing), an account with two members A and B entitled to write `listening.podcasts`, each with
 * its own `ColophonSession`, a [HomeStreamHost] over a real WebSocket and a `now-playing` cell. B holds the same owner
 * key as A (one person's two devices), so B can revoke A; the history is public, so a revoked A can still read it.
 *
 * Real: the relay and its home module, the JDK WebSocket over loopback, both sessions and engines, their passes, ticket
 * calls, delegations and authority changes. Not real: [Network] (it rewrites the account's `https` name to loopback
 * and can cut a member off), in-memory record media, [TestStore] (an in-memory claim store whose writes can be
 * delayed) and the relay's test clock.
 */
class World private constructor(val relay: RelayHome, val a: Member, val b: Member, private val ticking: Thread) {
    companion object {
        private fun authorityOnly(medium: MemoryMedium) = MemoryMedium(medium.snapshot().filterKeys { it.startsWith("authority/") })
        private suspend fun settle(device: Device, tries: Int = 40): Boolean {
            repeat(tries) {
                if (device.session.syncNow() && device.session.homeIssues.isEmpty() && device.session.homeFaults.isEmpty()) return true
                Thread.sleep(150)
            }
            return false
        }
        private suspend fun untilApproved(device: Device) {
            repeat(20) {
                device.session.syncNow(); device.session.refresh()
                if (device.session.phase == SessionPhase.Ready) return
                Thread.sleep(100)
            }
            error("the device did not learn its approval through the home: ${device.describe()}")
        }

        fun make(): World = runBlocking {
            val relay = RelayHome("https://home-0.test/v1/accounts/kt06-${UUID.randomUUID().toString().take(8)}", port = 0)
            // The relay runs on a test clock set by each request; keep it moving so its rate buckets refill and timers run.
            val ticking = Thread { try { while (true) { relay.touch(); Thread.sleep(20) } } catch (_: InterruptedException) {} }.apply { isDaemon = true; start() }
            try {
                val first = Device(namespaces = listOf(NS), history = HistoryAccess.EVERYONE, homes = listOf(HomeConfiguration("${relay.base}/", label = "Relay",
                    request = { account -> relay.start(account); relay.memberRequest(account) }, transport = relay.transport())))
                first.session.create()
                first.session.stopSync()
                check(first.session.phase == SessionPhase.Ready) { "A is ready: ${first.describe()}\n${relay.errors()}" }
                check(settle(first)) { first.describe() + "\n" + relay.errors() }
                val second = Device(medium = authorityOnly(first.medium), owner = first.owner, namespaces = listOf(NS),
                    homes = listOf(HomeConfiguration("${relay.base}/", transport = relay.transport())))
                second.session.restore()
                second.session.stopSync()
                approveByScan(second.session, first.session)
                check(settle(first)) { first.describe() }
                untilApproved(second)
                check(settle(second)) { second.describe() }
                World(relay, Member("A", first, relay), Member("B", second, relay), ticking)
            } catch (e: Throwable) {
                ticking.interrupt()
                throw AssertionError("the world could not be made: ${e.message}\nrelay stderr:\n${relay.errors()}", e).also { relay.stop() }
            }
        }

        /** A fast policy for scenarios that wait out timeouts: the default with shorter timers. */
        fun fastPolicy(): String {
            @Suppress("UNCHECKED_CAST") val p = Json.parse(sessionDefaultPolicy()) as Map<String, Any?>
            return Json.write(p + mapOf("beatMs" to 400, "holderTimeoutMs" to 1500, "askTimeoutMs" to 300, "presenceTimeoutMs" to 1500))
        }
    }

    /** Runs `body`, and on failure adds the relay's standard error to the report. Always stops everything. */
    fun use(body: (World) -> Unit) {
        try { body(this) } catch (e: Throwable) {
            throw AssertionError("${e.message}\nrelay stderr (last lines):\n${relay.errors()}", e)
        } finally {
            a.close(); b.close(); ticking.interrupt(); relay.stop()
        }
    }
}

/** The `now-playing` anchor (sessions §S12). */
data class Anchor(val episode: String, val show: String, val positionMs: Long, val ratePermille: Long, val playing: Boolean, val at: Long) {
    fun bytes(): ByteArray = Json.write(mapOf("episode" to episode, "show" to show, "positionMs" to positionMs, "ratePermille" to ratePermille, "playing" to playing, "at" to at)).toByteArray()
    /** The projected position at `now` (`offset`: the holder's clock minus this member's; 0 for the holder itself). */
    fun project(now: Long, offset: Long): Long = if (playing) positionMs + ratePermille * (now + offset - at) / 1000 else positionMs
    companion object {
        fun of(bytes: ByteArray?): Anchor? = bytes?.let { Json.obj(String(it)) }?.let {
            Anchor(it["episode"] as String, it["show"] as String, (it["positionMs"] as Number).toLong(), (it["ratePermille"] as Number).toLong(), it["playing"] as Boolean, (it["at"] as Number).toLong())
        }
    }
}
