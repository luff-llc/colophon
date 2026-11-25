package com.luff.colophon.hosts

import com.luff.colophon.AccountException
import com.luff.colophon.HomeStream
import com.luff.colophon.HttpAnswer
import com.luff.colophon.StreamConfig
import com.luff.colophon.StreamEvent
import com.luff.colophon.StreamEventKind
import com.luff.colophon.StreamStatus
import com.luff.colophon.StreamStatusKind
import com.luff.colophon.StreamStepKind
import com.luff.colophon.session.HomeTransport
import com.luff.colophon.session.HttpHomeTransport
import com.luff.colophon.session.Json
import com.luff.colophon.session.code
import com.luff.colophon.streamDefaultConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/** A session cell as the stream carries it ([SessionCellHost] implements it). Every call only enqueues. */
interface StreamCell {
    val namespace: String
    val cell: String
    /** A frame for this cell, as the text the home carried. */
    fun deliver(frame: String)
    /** The home carries this cell's frames to and from this device now (subscribed on a live stream). */
    fun linkUp()
    /** It no longer does. */
    fun linkDown()
}

/** What a stream host reports. None of these carries a ticket or an unredacted URL. */
sealed class StreamHostEvent {
    /** Every event the core returned, in order (`Session` included, after it was routed). */
    data class Event(val event: StreamEvent) : StreamHostEvent()
    /** The stream's status changed. */
    data class Status(val status: StreamStatus) : StreamHostEvent()
    /** A socket is being opened; `url` is the core's redacted form. */
    data class Connect(val url: String) : StreamHostEvent()
    /** An exchange pass the stream woke finished (`seq`: the verified head after it), or failed (`error`). */
    data class Pass(val seq: ULong?, val error: Throwable?) : StreamHostEvent()
    /** The ticket call could not be made or signed; the core was told (`ticket_call_failed`). */
    data class TicketCallFailed(val code: String) : StreamHostEvent()
    /** A `session` message whose frame could not be taken out (`noFrame`), or that names no attached cell (`noCell`). */
    data class Unrouted(val reason: String) : StreamHostEvent()
}

class StreamHostOptions(
    val account: HostAccount,
    /** The home's member ID. */
    val home: String,
    /** Opens the WebSocket (`JdkWebSocketFactory` on the JVM; on Android, see docs/hosts-06.md §6). */
    val socket: SocketFactory,
    /** Where ticket requests go: the transport the session uses for this home ([transportOf]). */
    val transport: HomeTransport = HttpHomeTransport(),
    val clock: HostClock = SystemHostClock,
    /** Adjusts the documented configuration (`streamDefaultConfig()`) before the client is made. */
    val configure: ((StreamConfig) -> StreamConfig)? = null,
    /** The resume cursor saved from an earlier `Cursor` event. */
    val cursor: String? = null,
    /** Persists each `Cursor` event next to the exchange checkpoint (null: forget the saved one). */
    val saveCursor: (suspend (String?) -> Unit)? = null,
    /** The client, when the host does not make it from the engine (tests: `HomeStream(home, base, config, cursor)`). */
    val client: HomeStream? = null,
    /** The serial context the host runs on; it must run one task at a time. Default: one lane of `Dispatchers.Default`. */
    val dispatcher: CoroutineDispatcher? = null,
)

/**
 * The Kotlin host of the 0.6 home stream (docs/colophon-0.6-sync-stream.md §2): one per home. It owns the socket, the
 * ticket request and the timer, and does exactly what the core's [HomeStream] says, step by step. Every policy (when
 * to mint, how long to back off, when to ping, when to wake a pass, when to give up) is the core's; nothing here
 * retries, waits or caps on its own.
 *
 * Every input (a socket report, a timer, a ticket answer, a finished pass, a call of the public API) is one job on the
 * host's serial queue, so the client is driven one call at a time; listeners hear events between jobs, on that
 * context, and anything they call becomes a later job.
 */
class HomeStreamHost(options: StreamHostOptions) {
    val home: String = options.home
    private val account = options.account
    private val transport = options.transport
    private val openSocket = options.socket
    private val clock = options.clock
    private val saveCursor = options.saveCursor
    private val dispatcher = options.dispatcher ?: serialDispatcher()
    private val serial = SerialQueue(dispatcher) {}
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val client: HomeStream = options.client ?: run {
        val config = streamDefaultConfig().let { options.configure?.invoke(it) ?: it }
        account.engine().streamClient(options.home, config, options.cursor)
    }
    private val timer = Deadline(clock, serial::job) { pump() }
    private val listeners = CopyOnWriteArrayList<(StreamHostEvent) -> Unit>()
    private val cells = ConcurrentHashMap<String, StreamCell>()
    /** Cells the home acknowledged a subscription for on the current connection (serial context only). */
    private val subscribed = HashSet<String>()
    /** Guards the hand-over of the socket between the loop and [stop]. */
    private val lock = Any()
    @Volatile private var socket: HostSocket? = null
    /** Bumped whenever the current socket is replaced or closed: reports from an older socket are ignored. */
    private var generation = 0
    @Volatile private var started = false
    @Volatile private var stopped = false
    private var passing = false
    private var passAgain = false
    private var lastStatus: StreamStatusKind? = null
    @Volatile private var lastStatusValue: StreamStatus = StreamStatus(StreamStatusKind.CONNECTING, null, null, null)

    /** Starts driving the stream. */
    fun start() = serial.job { if (!started && !stopped) { started = true; pump() } }

    /** Stops: closes the socket (1000) at once, cancels the timer and the call in flight, and frees the client. */
    fun stop() {
        val s: HostSocket?
        synchronized(lock) {
            if (stopped) return
            stopped = true
            s = socket; socket = null
        }
        try { s?.close(1000) } catch (_: Exception) {}
        scope.cancel()
        serial.job {
            timer.clear()
            generation++
            allDown()
            try { client.close() } catch (_: Exception) {}
        }
    }

    /** Calls `listener` (on the host's context) with every event; returns the function that stops it. */
    fun on(listener: (StreamHostEvent) -> Unit): () -> Unit { listeners.add(listener); return { listeners.remove(listener) } }
    /** Calls `listener` after every exchange pass this host ran (cells install a new view from it). */
    fun onPass(listener: () -> Unit): () -> Unit = on { if (it is StreamHostEvent.Pass) listener() }
    private fun emit(event: StreamHostEvent) = serial.event { for (l in listeners) try { l(event) } catch (_: Exception) {} }

    /** Where the stream stands. */
    val status: StreamStatus get() = if (stopped) lastStatusValue else try { client.status().also { lastStatusValue = it } } catch (_: Exception) { lastStatusValue }
    /** Whether the app's ordinary poll timer should run (always, unless the stream is live). */
    val polling: Boolean get() = if (stopped) true else try { client.polling() } catch (_: Exception) { true }
    /** The resume cursor held now. */
    val cursor: String? get() = try { client.cursor() } catch (_: Exception) { null }
    val live: Boolean get() = !stopped && status.kind == StreamStatusKind.LIVE

    /** Try again now: foreground entry, a network change or an explicit user action, never a timer (the core bounds it). */
    fun retryNow() = serial.job { if (!stopped) { client.retryNow(); pump() } }
    /** The account's verified history moved outside a pass this host woke (the app's own poll): tell the core. */
    fun historyChanged() = serial.job {
        if (stopped) return@job
        try { client.onHistory(account.engine().headSeq()) } catch (_: Exception) {}
        pump()
    }

    // Cells

    /** Carries `cell` on this stream: subscribed whenever the stream is live, its frames delivered to it. */
    fun attach(cell: StreamCell) {
        val k = key(cell.namespace, cell.cell)
        check(cells.putIfAbsent(k, cell) == null) { "a cell ${cell.namespace}/${cell.cell} is already attached" }
        serial.job { if (live && cells[k] === cell) sendClient { client.subscribe(cell.namespace, cell.cell, null) } }
    }
    /** Stops carrying `cell` (unsubscribes when live). */
    fun detach(cell: StreamCell) {
        val k = key(cell.namespace, cell.cell)
        if (!cells.remove(k, cell)) return
        serial.job {
            if (subscribed.remove(k)) cell.linkDown()
            if (live) sendClient { client.unsubscribe(cell.namespace, cell.cell, null) }
        }
    }
    /**
     * Sends one sealed session frame (a `Send` effect's bytes as text), carried verbatim. False when the stream is not
     * live or the frame was refused before sending: to the session that is loss, which its own rules repair. Callable
     * from any thread (a cell's own context).
     */
    fun sendSession(frame: String): Boolean {
        if (!live) return false
        return sendClient { client.sessionFrame(frame, null) }
    }
    private fun sendClient(build: () -> String): Boolean {
        val s = socket ?: return false
        val text = try { build() } catch (_: Exception) { return false }
        return try { s.send(text); true } catch (_: Exception) { false }
    }

    // The loop (serial context only)

    private fun now(): Long = clock.monoMs()

    /** Asks the core what to do, does it, and asks again, until it says to wait or sleep. */
    private fun pump() {
        if (!started || stopped) return
        // Every step but Waiting and Sleep changes the core's state, so this ends; the bound only guards a defect.
        for (n in 0 until 1000) {
            if (stopped) return
            val step = client.next(now())
            when (step.kind) {
                StreamStepKind.WAKE -> runPass()
                StreamStepKind.NEED_TICKET_CALL -> mint()
                StreamStepKind.CONNECT -> connect(step.url ?: "", step.logUrl ?: "")
                StreamStepKind.SEND -> step.text?.let { t -> sendClient { t } }
                StreamStepKind.CLOSE -> close((step.code ?: 1000u).toInt())
                // Both carry `wake_at`, when to ask again at the latest (a coalesced wake while a call is signed, say).
                StreamStepKind.WAITING -> { timer.at(step.wakeAt); checkStatus(); return }
                StreamStepKind.SLEEP -> { timer.at(earliest(step.until, step.wakeAt)); checkStatus(); return }
            }
            checkStatus()
        }
    }

    /** `NeedTicketCall`: sign the call, send the ticket request, hand the core the answer. */
    private fun mint() {
        scope.launch {
            val call = try { account.streamCall(home) } catch (e: CancellationException) { throw e } catch (e: Exception) {
                serial.job { if (!stopped) { handle(client.ticketCallFailed(now())); emit(StreamHostEvent.TicketCallFailed(codeOf(e))); pump() } }
                return@launch
            }
            serial.job {
                if (stopped) return@job
                val request = try { client.ticketRequest(call, now()) } catch (e: Exception) {
                    // The core refused to build the request (no ticket call outstanding): it is told the call failed.
                    handle(client.ticketCallFailed(now())); emit(StreamHostEvent.TicketCallFailed(codeOf(e))); pump()
                    return@job
                }
                scope.launch {
                    val answer: HttpAnswer? = try { transport.send(request) } catch (e: CancellationException) { throw e } catch (_: Exception) { null }
                    serial.job { if (!stopped) { handle(client.onTicket(answer, now())); pump() } }
                }
            }
        }
    }

    /** `Connect`: open the socket at `url` (never logged) and report what it does. */
    private fun connect(url: String, logUrl: String) {
        val mine = ++generation
        val current = { mine == generation && !stopped }
        val ended = { synchronized(lock) { socket = null }; generation++; allDown() }
        val handlers = object : SocketHandlers {
            override fun open() = serial.job { if (current()) { client.onOpen(now()); pump() } }
            override fun message(text: String) = serial.job { if (current()) { handle(client.onFrame(text, now())); pump() } }
            override fun refused(answer: HttpAnswer) = serial.job { if (current()) { ended(); handle(client.onRefused(answer, now())); pump() } }
            override fun closed(code: Int?) = serial.job { if (current()) { ended(); handle(client.onClosed(code?.toUInt(), now())); pump() } }
        }
        val s = try { openSocket.open(url, handlers) } catch (_: Exception) {
            // A socket that cannot even be made is a transport failure, reported as any other.
            handlers.closed(null)
            return
        }
        // The socket carries the ticket: it is owned (kept, or closed at once) before any listener hears of it.
        val kept = synchronized(lock) { if (stopped || mine != generation) false else { socket = s; true } }
        if (!kept) { try { s.close(1000) } catch (_: Exception) {}; return }
        emit(StreamHostEvent.Connect(logUrl))
    }

    /** `Close`: close the socket, then tell the core. */
    private fun close(code: Int) {
        val s = synchronized(lock) { socket.also { socket = null } }
        generation++
        try { s?.close(code) } catch (_: Exception) {}
        allDown()
        handle(client.onClosed(code.toUInt(), now()))
    }

    /** `Wake`: one ordinary exchange pass, then `on_history`. A wake during a pass runs one more after it. */
    private fun runPass() {
        if (passing) { passAgain = true; return }
        passing = true
        scope.launch {
            var failure: Throwable? = null
            try { account.exchange() } catch (e: CancellationException) { throw e } catch (e: Exception) { failure = e }
            serial.job {
                if (stopped) return@job
                var seq: ULong? = null
                try { seq = account.engine().headSeq(); client.onHistory(seq) } catch (e: Exception) { if (failure == null) failure = e }
                passing = false
                emit(StreamHostEvent.Pass(seq, failure))
                if (passAgain) { passAgain = false; runPass() }
                pump()
            }
        }
    }

    /** The core's events, in order. */
    private fun handle(events: List<StreamEvent>) {
        for (event in events) {
            if (stopped) return
            when (event.kind) {
                StreamEventKind.CONNECTED -> {
                    // The hello arrived: the stream is live. Subscribe every attached cell.
                    subscribed.clear()
                    for (cell in cells.values) sendClient { client.subscribe(cell.namespace, cell.cell, null) }
                }
                StreamEventKind.CURSOR -> saveCursor?.let { save -> scope.launch { try { save(event.cursor) } catch (e: CancellationException) { throw e } catch (_: Exception) {} } }
                StreamEventKind.SESSION -> route(event.text ?: "")
                StreamEventKind.ACK -> acknowledged(event.json)
                else -> {}
            }
            emit(StreamHostEvent.Event(event))
        }
    }
    private fun acknowledged(json: String?) {
        val v = Json.obj(json ?: "") ?: return
        val namespace = v["namespace"] as? String ?: return
        val name = v["cell"] as? String ?: return
        val k = key(namespace, name)
        val cell = cells[k] ?: return
        if (v["type"] == "subscribed" && subscribed.add(k)) cell.linkUp()
        if (v["type"] == "unsubscribed" && subscribed.remove(k)) cell.linkDown()
    }
    /** A `session` message: its frame's own text to the cell it names. */
    private fun route(message: String) {
        val frame = Frames.sessionFrameText(message) ?: return emit(StreamHostEvent.Unrouted("noFrame"))
        val where = Frames.frameCell(frame)
        val cell = where?.let { cells[key(it.first, it.second)] } ?: return emit(StreamHostEvent.Unrouted("noCell"))
        cell.deliver(frame)
    }

    private fun allDown() {
        val up = subscribed.toList()
        subscribed.clear()
        for (k in up) cells[k]?.linkDown()
    }
    private fun checkStatus() {
        if (stopped) return
        val status = this.status
        if (status.kind == lastStatus) return
        lastStatus = status.kind
        if (status.kind != StreamStatusKind.LIVE) allDown()
        emit(StreamHostEvent.Status(status))
    }

    private companion object {
        fun key(namespace: String, cell: String) = "$namespace\n$cell"
        fun earliest(a: Long?, b: Long?): Long? = if (a == null) b else if (b == null) a else minOf(a, b)
        fun codeOf(e: Throwable): String = (e as? AccountException)?.code ?: e.javaClass.simpleName
    }
}
