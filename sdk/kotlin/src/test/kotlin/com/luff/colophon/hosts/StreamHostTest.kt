package com.luff.colophon.hosts

import com.luff.colophon.AccountEngine
import com.luff.colophon.AccountException
import com.luff.colophon.Header
import com.luff.colophon.HomeStream
import com.luff.colophon.HttpMethod
import com.luff.colophon.NoHandle
import com.luff.colophon.StreamBlockedKind
import com.luff.colophon.StreamEventKind
import com.luff.colophon.StreamStatusKind
import com.luff.colophon.session.Json
import com.luff.colophon.streamDefaultConfig
import kotlinx.coroutines.CompletableDeferred
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The stream host against the core's real [HomeStream] (made directly, no engine), with a fake socket, ticket
 * transport and clock: every step kind, refusals and close codes, the polling fallback, session routing, and that no
 * ticket leaves except in the socket URL (the matrix of js/test06/stream-host.test.ts).
 */
class StreamHostTest {
    private val base = "https://home.test/v1/accounts/x"

    private inner class Rig(streamCall: (suspend () -> ByteArray)? = null, cursor: String? = null, socket: SocketFactory? = null) {
        val loop = ManualLoop()
        val clock = ManualClock(loop)
        val sockets = Sockets()
        val transport = TicketTransport()
        @Volatile var seq = 5uL
        val passes = ArrayList<Long>()
        var exchange: suspend () -> Unit = { passes.add(clock.mono) }
        val engine = object : AccountEngine(NoHandle) { override fun headSeq(): ULong = seq }
        val account = object : HostAccount {
            override val account = "a".repeat(64)
            override val member = "m"
            override fun engine(): AccountEngine = engine
            override suspend fun streamCall(home: String): ByteArray = streamCall?.invoke() ?: """{"a call":1}""".toByteArray()
            override suspend fun exchange() = this@Rig.exchange()
            override suspend fun signRaw(body: ByteArray) = ByteArray(64)
        }
        val cursors = ArrayList<String?>()
        val host = HomeStreamHost(StreamHostOptions(account, "h", socket ?: sockets.factory, transport, clock, saveCursor = { cursors.add(it) },
            client = HomeStream("h", base, streamDefaultConfig(), cursor), dispatcher = loop.dispatcher))
        val events = ArrayList<StreamHostEvent>()
        init { host.on { events.add(it) } }
        val frames = FrameNumbers()
        fun kinds() = events.mapNotNull { (it as? StreamHostEvent.Event)?.event?.kind }
        fun settle() = loop.settle()
        /** Mints, connects and says hello. */
        fun live() {
            settle()
            sockets.last.handlers.open()
            sockets.last.handlers.message(frames.hello())
            settle()
        }
        fun untilBackoffEnds() = clock.advance(host.status.until!! - clock.mono)
    }

    @Test fun needTicketCallConnectWake() {
        val r = Rig()
        assertTrue(r.host.polling)
        r.host.start(); r.settle()
        assertEquals(1, r.transport.requests.size)
        val request = r.transport.requests[0]
        assertEquals(HttpMethod.POST to "$base/stream/ticket", request.method to request.url)
        assertEquals(1, r.sockets.all.size)
        assertEquals("wss://home.test/v1/accounts/x/stream?ticket=$TICKET", r.sockets.last.url)
        val connect = r.events.filterIsInstance<StreamHostEvent.Connect>().single()
        assertFalse(connect.url.contains(TICKET))
        r.sockets.last.handlers.open()
        r.sockets.last.handlers.message(r.frames.hello())
        r.settle()
        assertTrue(r.host.live); assertFalse(r.host.polling)
        assertTrue(StreamEventKind.CONNECTED in r.kinds())
        // The first hello wakes a pass, coalesced over 250 ms; then `on_history`.
        assertEquals(0, r.passes.size)
        r.clock.advance(250)
        assertEquals(1, r.passes.size)
        assertTrue(r.events.any { it is StreamHostEvent.Pass && it.seq == 5uL })
        // No event, status or log line carries the ticket.
        assertFalse(r.events.joinToString().contains(TICKET))
        r.host.stop(); r.settle()
    }

    @Test fun pingAfterPingMsCloseAfterIdleMsThenBackoffAndANewTicket() {
        val r = Rig()
        r.host.start(); r.live()
        r.clock.advance(20_000)
        assertTrue(r.sockets.last.sent.any { Json.obj(it)?.get("type") == "ping" })
        r.clock.advance(40_001)
        assertEquals(1001, r.sockets.last.closedWith)
        assertEquals(StreamStatusKind.BACKOFF, r.host.status.kind)
        assertTrue(r.host.polling)
        val until = r.host.status.until!!
        assertTrue(until > r.clock.mono)
        r.untilBackoffEnds()
        assertEquals(2, r.transport.requests.size)
        assertEquals(2, r.sockets.all.size)
        r.host.stop(); r.settle()
    }

    @Test fun aGapInFrameNumbersClosesWith1002() {
        val r = Rig()
        r.host.start(); r.live()
        r.sockets.last.handlers.message("""{"type":"head","home":"h","seq":9,"digest":"d","n":5}""")
        r.settle()
        assertTrue(StreamEventKind.VIOLATION in r.kinds())
        assertEquals(1002, r.sockets.last.closedWith)
        r.host.stop(); r.settle()
    }

    @Test fun closeCodes1008BlocksUntilTheHistoryChanges1012And1000BackOff() {
        val r = Rig()
        r.host.start(); r.live()
        r.sockets.last.handlers.closed(1008); r.settle()
        assertEquals(StreamStatusKind.BLOCKED, r.host.status.kind)
        assertEquals(StreamBlockedKind.ACCESS_ENDED, r.host.status.blocked)
        assertTrue(r.host.polling)
        r.clock.advance(600_000)
        assertEquals(1, r.transport.requests.size)
        r.host.historyChanged(); r.settle()
        assertEquals(1, r.transport.requests.size)
        r.seq = 6uL
        r.host.historyChanged(); r.settle()
        assertEquals(2, r.transport.requests.size)
        r.live()
        r.sockets.last.handlers.closed(1012); r.settle()
        assertEquals(StreamStatusKind.BACKOFF, r.host.status.kind)
        r.untilBackoffEnds()
        assertEquals(3, r.transport.requests.size)
        r.live()
        r.sockets.last.handlers.closed(1000); r.settle()
        assertEquals(StreamStatusKind.BACKOFF, r.host.status.kind)
        r.host.stop(); r.settle()
    }

    @Test fun aTransportFailureBacksOff() {
        val r = Rig()
        r.host.start(); r.settle()
        r.sockets.last.handlers.closed(null); r.settle()
        assertEquals(StreamStatusKind.BACKOFF, r.host.status.kind)
        assertTrue(StreamEventKind.DOWN in r.kinds())
        r.host.stop(); r.settle()
    }

    @Test fun refusals403RevokedEndsAccess429BacksOffAtLeastRetryAfter() {
        val r = Rig()
        r.host.start(); r.settle()
        r.sockets.last.handlers.refused(answer(429, mapOf("result" to "refused:rateLimited"), listOf(Header("retry-after", "30"))))
        r.settle()
        assertEquals(StreamStatusKind.BACKOFF, r.host.status.kind)
        assertTrue(r.host.status.until!! - r.clock.mono >= 30_000)
        r.untilBackoffEnds()
        r.sockets.last.handlers.refused(answer(403, mapOf("result" to "refused:revoked")))
        r.settle()
        assertEquals(StreamBlockedKind.ACCESS_ENDED, r.host.status.blocked)
        // As the JVM socket reports it: the status without the body backs off instead.
        val jdk = Rig()
        jdk.host.start(); jdk.settle()
        jdk.sockets.last.handlers.refused(answer(403, null).copy(body = ByteArray(0)))
        jdk.settle()
        assertEquals(StreamStatusKind.BACKOFF, jdk.host.status.kind)
        r.host.stop(); jdk.host.stop(); r.settle(); jdk.settle()
    }

    @Test fun ticketAnswers404Unsupported403RefusedAFailedCallBacksOff() {
        val unsupported = Rig()
        unsupported.transport.answer = { answer(404) }
        unsupported.host.start(); unsupported.settle()
        assertEquals(StreamBlockedKind.UNSUPPORTED, unsupported.host.status.blocked)
        assertTrue(unsupported.host.polling)
        assertEquals(0, unsupported.sockets.all.size)
        unsupported.host.stop()

        val refused = Rig()
        refused.transport.answer = { answer(403, mapOf("result" to "refused:revoked")) }
        refused.host.start(); refused.settle()
        assertEquals(StreamBlockedKind.REFUSED, refused.host.status.blocked)
        assertEquals("refused:revoked", refused.host.status.refused)
        refused.host.stop()

        val failing = Rig(streamCall = { throw AccountException.Unavailable("unavailable", "no fresh head") })
        failing.host.start(); failing.settle()
        assertTrue(failing.events.any { it is StreamHostEvent.TicketCallFailed && it.code == "unavailable" })
        assertEquals(StreamStatusKind.BACKOFF, failing.host.status.kind)
        assertEquals(0, failing.transport.requests.size)
        failing.host.stop()
        // A transport that throws is `on_ticket(None)`: backoff.
        val offline = Rig()
        offline.transport.answer = { throw java.io.IOException("offline") }
        offline.host.start(); offline.settle()
        assertEquals(StreamStatusKind.BACKOFF, offline.host.status.kind)
        offline.host.stop()
    }

    @Test fun needTicketCallRepeatsWhileTheCallIsSigned() {
        var calls = 0
        val sign = CompletableDeferred<ByteArray>()
        val r = Rig(streamCall = { calls++; sign.await() })
        r.host.start(); r.settle()
        r.clock.advance(5_000)
        assertEquals(1, calls)
        assertEquals(0, r.transport.requests.size)
        sign.complete("""{"a call":1}""".toByteArray())
        r.settle()
        assertEquals(1, calls)
        assertEquals(1, r.transport.requests.size)
        assertEquals(1, r.sockets.all.size)
        r.host.stop(); r.settle()
    }

    @Test fun waitingArmsTheTimerFromWakeAtACallNeverSignedCountsAsFailed() {
        var calls = 0
        val r = Rig(streamCall = { calls++; CompletableDeferred<ByteArray>().await() })
        r.host.start(); r.settle()
        assertEquals(StreamStatusKind.CONNECTING, r.host.status.kind)
        r.clock.advance(59_000)
        assertEquals(StreamStatusKind.CONNECTING, r.host.status.kind)
        r.clock.advance(1_100)
        assertEquals(1, calls)
        assertEquals(StreamStatusKind.BACKOFF, r.host.status.kind)
        r.host.stop(); r.settle()
    }

    @Test fun stopFromAListenerOrInsideTheFactoryLeavesNoTicketBearingSocketOpen() {
        val r = Rig()
        r.host.on { if (it is StreamHostEvent.Connect) r.host.stop() }
        r.host.start(); r.settle()
        assertEquals(1, r.sockets.all.size)
        assertEquals(1000, r.sockets.last.closedWith)
        r.clock.advance(120_000)
        assertEquals(1, r.sockets.all.size)

        // Stopped from inside the socket factory, before it returned: closed at once, never announced.
        lateinit var host: HomeStreamHost
        var made: FakeSocket? = null
        val s = Rig(socket = { url, handlers -> FakeSocket(url, handlers).also { made = it; host.stop() } })
        host = s.host
        s.host.start(); s.settle()
        assertEquals(1000, made?.closedWith)
        assertTrue(s.events.none { it is StreamHostEvent.Connect })

        // Stopped from another thread while the upgrade is outstanding: the socket is closed at once.
        val t = Rig()
        t.host.start(); t.settle()
        val opening = t.sockets.last
        Thread { t.host.stop() }.apply { start(); join() }
        assertEquals(1000, opening.closedWith)
        opening.handlers.open(); opening.handlers.message(t.frames.hello()); t.settle()
        assertFalse(t.host.live)
    }

    @Test fun listenersThatCallBackIntoTheHostDoNotBreakTheLoop() {
        val r = Rig()
        r.host.on { r.host.status; r.host.polling; r.host.historyChanged(); r.host.sendSession("{}") }
        r.host.start(); r.live()
        r.clock.advance(250)
        assertTrue(r.host.live)
        assertTrue(r.passes.isNotEmpty())
        r.host.stop(); r.settle()
    }

    @Test fun cursorsAreSavedAndPresentedOnReconnect() {
        val r = Rig(cursor = "i1.3")
        r.host.start(); r.settle()
        assertTrue(r.sockets.last.url.contains("after=i1.3"))
        r.sockets.last.handlers.open()
        r.sockets.last.handlers.message(r.frames.hello())
        r.sockets.last.handlers.message(r.frames.frame(mapOf("type" to "change", "cursor" to "i1.4", "entry" to mapOf("path" to "records/x", "size" to 1, "sha256" to "0".repeat(64)))))
        r.settle()
        assertTrue("i1.4" in r.cursors)
        assertEquals("i1.4", r.host.cursor)
        r.host.stop(); r.settle()
    }

    @Test fun cellsSubscribedWhenLiveLinkUpOnTheAckFramesRoutedAsTheirOwnText() {
        val r = Rig()
        val log = ArrayList<String>()
        val delivered = ArrayList<String>()
        val cell = object : StreamCell {
            override val namespace = "listening.podcasts"; override val cell = "now-playing"
            override fun deliver(frame: String) { delivered.add(frame) }
            override fun linkUp() { log.add("up") }
            override fun linkDown() { log.add("down") }
        }
        r.host.attach(cell)
        assertFalse(r.host.sendSession("{}"))
        r.host.start(); r.live()
        val subscribe = r.sockets.last.sent.mapNotNull { Json.obj(it) }.first { it["type"] == "subscribe" }
        assertEquals("listening.podcasts" to "now-playing", subscribe["namespace"] to subscribe["cell"])
        assertEquals(listOf(), log)
        r.sockets.last.handlers.message(r.frames.frame(mapOf("type" to "subscribed", "namespace" to "listening.podcasts", "cell" to "now-playing")))
        r.settle()
        assertEquals(listOf("up"), log)
        // The frame inside the message, character for character, spacing and all.
        val frame = """{"account":"${"a".repeat(64)}","cell":"now-playing","namespace":"listening.podcasts","n":1}"""
        r.sockets.last.handlers.message("""{"type":"session","frame":$frame,"retained":true,"n":3}""")
        r.settle()
        assertEquals(listOf(frame), delivered)
        // A frame for a cell nobody attached is reported, not delivered.
        r.sockets.last.handlers.message("""{"type":"session","frame":{"namespace":"listening.podcasts","cell":"other"},"n":4}""")
        r.settle()
        assertTrue(r.events.any { it is StreamHostEvent.Unrouted && it.reason == "noCell" })
        assertTrue(r.host.sendSession(frame))
        assertEquals("""{"type":"session","frame":$frame}""", r.sockets.last.sent.last())
        r.sockets.last.handlers.closed(1011); r.settle()
        assertEquals(listOf("up", "down"), log)
        assertFalse(r.host.sendSession(frame))
        r.host.stop(); r.settle()
    }

    @Test fun aPassWokenDuringAPassRunsOnceMoreAfterIt() {
        val r = Rig()
        var running = 0
        var release = CompletableDeferred<Unit>()
        r.exchange = { running++; release.await(); running-- }
        r.host.start(); r.live()
        r.clock.advance(250)
        assertEquals(1, running)
        r.sockets.last.handlers.message(r.frames.frame(mapOf("type" to "head", "home" to "h", "seq" to 6, "digest" to "d")))
        r.clock.advance(250)
        assertEquals(1, running)
        val first = release; release = CompletableDeferred(); first.complete(Unit); r.settle()
        assertEquals(1, running)
        release.complete(Unit); r.settle()
        assertEquals(2, r.events.count { it is StreamHostEvent.Pass })
        r.host.stop(); r.settle()
    }

    @Test fun aSocketThatCannotBeMadeIsATransportFailure() {
        val r = Rig(socket = { _, _ -> throw java.io.IOException("no route") })
        r.host.start(); r.settle()
        assertEquals(StreamStatusKind.BACKOFF, r.host.status.kind)
        assertNotNull(r.kinds().firstOrNull { it == StreamEventKind.DOWN })
        r.host.stop(); r.settle()
    }
}
