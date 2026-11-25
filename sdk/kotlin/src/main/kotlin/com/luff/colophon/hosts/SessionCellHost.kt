package com.luff.colophon.hosts

import com.luff.colophon.AccountEngine
import com.luff.colophon.AccountException
import com.luff.colophon.SessionAccountView
import com.luff.colophon.SessionClock
import com.luff.colophon.SessionEffectKind
import com.luff.colophon.SessionEndpoint
import com.luff.colophon.SessionStep
import com.luff.colophon.session.Json
import com.luff.colophon.session.code
import com.luff.colophon.sessionDefaultPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList

/** What carries a cell's frames: a [HomeStreamHost], or anything with the same calls. */
interface CellCarrier {
    fun attach(cell: StreamCell)
    fun detach(cell: StreamCell)
    /** Sends one sealed frame verbatim; false when it could not be sent now (loss, to the session). Any thread. */
    fun sendSession(frame: String): Boolean
    /** Calls `listener` after every exchange pass the carrier ran (a [HomeStreamHost]'s `Wake`); null when it runs none. */
    fun onPass(listener: () -> Unit): (() -> Unit)? = null
}

/** A [HomeStreamHost] as a cell's carrier. */
fun HomeStreamHost.carrier(): CellCarrier = object : CellCarrier {
    override fun attach(cell: StreamCell) = this@carrier.attach(cell)
    override fun detach(cell: StreamCell) = this@carrier.detach(cell)
    override fun sendSession(frame: String) = this@carrier.sendSession(frame)
    override fun onPass(listener: () -> Unit) = this@carrier.onPass(listener)
}

/** Why an endpoint was made again. */
enum class RebuildReason { CLOCK_BACKWARDS, WRONG_VIEW, SESSION_CHANGED }
/** Why a cell host stopped acting: its writes kept failing (`STORE`), a rebuild failed, or another instance holds the cell. */
enum class FailReason { STORE, REBUILD, SUPERSEDED }
/** The input kept behind a `Persist`. */
enum class QueuedInput { FRAME, TICK, LINK }
enum class PersistPhase { STARTED, STORED, FAILED }

/** What a cell host reports. Session events carry application state: show them, never log them. */
sealed class CellHostEvent {
    /** An `Event` effect: the core's event JSON (`json`), its tag (`name`) and the parsed object. */
    data class Session(val name: String, val json: String, val fields: Map<String, Any?>) : CellHostEvent()
    /** A frame was handed to the carrier (`frame` is the sealed text, `kind` its plaintext kind). */
    data class Sent(val kind: String, val frame: String) : CellHostEvent()
    /** A frame was not sent: the core could not seal it (`reason` its code), or the carrier was down (`carrier`). */
    data class Unsent(val kind: String, val reason: String, val frame: String? = null) : CellHostEvent()
    /** A received frame was dropped (the §S3 code; `queueFull` when it could not be kept behind a write). */
    data class Drop(val reason: String, val helloTo: String? = null) : CellHostEvent()
    /** Effects decided under an older authority head were dropped instead of released. */
    data class Discarded(val count: Int) : CellHostEvent()
    /** An input was kept behind the `Persist` being written. */
    data class Queued(val input: QueuedInput) : CellHostEvent()
    /** A `Persist` write started, completed (and was acknowledged), or failed (and will be retried). */
    data class Persist(val phase: PersistPhase, val ack: ULong, val error: Throwable? = null) : CellHostEvent()
    /** A command waits for the write in progress (`session:persistPending`). */
    data class CommandHeld(val command: String) : CellHostEvent()
    /** The endpoint's view was older than the engine's head (`session:staleAccount`). */
    data object Stale : CellHostEvent()
    /** A new view was installed: what this member may do now. */
    data class Account(val entitled: Boolean, val canWrite: Boolean, val seq: ULong) : CellHostEvent()
    /** The endpoint was made again from the stored claim. */
    data class Rebuilt(val reason: RebuildReason) : CellHostEvent()
    /** A frame arrived while the endpoint was being made again: not judged (loss). */
    data object Missed : CellHostEvent()
    /**
     * The cell stopped acting: its endpoint is gone, it sends nothing and is detached, and every held or new command is
     * refused. Open a new host to take part again (from the last stored claim, so the restart rules apply).
     */
    data class Failed(val reason: FailReason, val error: Throwable? = null) : CellHostEvent()
    /** Something the host could not do (`code` as the core spells it). */
    data class Error(val code: String, val during: String) : CellHostEvent()
}

class CellHostOptions(
    val account: HostAccount,
    val carrier: CellCarrier,
    val namespace: String,
    val cell: String,
    val store: ClaimStore,
    /** The §S1 policy as JSON (default `sessionDefaultPolicy()`); every member of a cell uses the same one. */
    val policy: String? = null,
    val clock: HostClock = SystemHostClock,
    /** The application's state for the cell, given with `join` (a restarted holder retakes with it, §S6). */
    val state: () -> ByteArray? = { null },
    /** How long a delegation is valid (at most 86,400,000 ms; default that). It is renewed an hour before it ends. */
    val delegationMs: Long = DAY,
    /** How long to wait before writing a `Persist` again after its write failed. */
    val persistRetryMs: Long = 250,
    /** Consecutive failed or overdue writes of one `Persist` after which the cell fails. */
    val persistAttempts: Int = 20,
    /** How long one write may take before it counts as failed; a late success is not acknowledged. */
    val persistTimeoutMs: Long = 10_000,
    /** Consecutive failed or overdue fence checks (one a beat) after which the cell fails closed. */
    val fenceCheckMisses: Int = 3,
    /** The most commands held at once; one more is refused with `COMMAND_QUEUE_FULL`. */
    val maxCommands: Int = 64,
    /** Host randomness. The session key and the `fresh` seed are new on every start. */
    val random: (Int) -> ByteArray = { n -> ByteArray(n).also { SecureRandom().nextBytes(it) } },
    /** The serial context the host runs on; it must run one task at a time. Default: one lane of `Dispatchers.Default`. */
    val dispatcher: CoroutineDispatcher? = null,
) {
    companion object { const val DAY = 86_400_000L }
}

/** A command the host refused or could not run. */
class CellHostError(val code: Code, message: String) : Exception(message) {
    enum class Code { CLOSED, FAILED, COMMAND_QUEUE_FULL, NOT_RUN, TIMEOUT, SUPERSEDED }
}

/**
 * The Kotlin host of one 0.6 session cell: it owns a [SessionEndpoint] and runs the reference host loop of
 * docs/bindings-05.md §10 exactly (docs/hosts-06.md §3).
 *
 * - Every input (a frame, a timer at the step's `next_deadline`, a carrier change, an application command, a completed
 *   write) is one job on one serial queue. Jobs run one at a time and never inside another, and events reach listeners
 *   only between jobs, so no listener, store, socket or timer callback can re-enter the endpoint. Every coroutine of
 *   the host runs on the same serial context, so a suspension never lets a job overlap the host's state.
 * - The step a call returns is carried out in order: `Send` to the carrier, `Event` to the application, `Persist` to the
 *   store. A `Persist` is acknowledged (`persisted`) only when its durable write has completed, never on seeing the step.
 * - `session:staleAccount` installs a fresh view (`set_account`) and the input runs again; `session:persistPending`
 *   holds the command, in order, until the write completes; `session:clockBackwards` and `session:wrongView` discard the
 *   endpoint and make a new one from the stored claim (§S6).
 * - Drops, discarded effects and unsent frames are reported, never thrown away silently.
 */
class SessionCellHost private constructor(options: CellHostOptions) : StreamCell {
    override val namespace: String = options.namespace
    override val cell: String = options.cell
    val me: String = options.account.member
    private var account: HostAccount = options.account
    private val carrier = options.carrier
    private var store: ClaimStore = options.store
    private val policy: String = options.policy ?: sessionDefaultPolicy()
    private val clock = options.clock
    private val stateOf = options.state
    private val delegationMs = minOf(options.delegationMs, CellHostOptions.DAY)
    private val persistRetryMs = options.persistRetryMs
    private val persistAttempts = maxOf(1, options.persistAttempts)
    private val persistTimeoutMs = maxOf(1L, options.persistTimeoutMs)
    private val maxCommands = maxOf(1, options.maxCommands)
    private val random = options.random
    private val dispatcher = options.dispatcher ?: serialDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val listeners = CopyOnWriteArrayList<(CellHostEvent) -> Unit>()
    private val serial = SerialQueue(dispatcher) { t -> emit(CellHostEvent.Error(codeOf(t), "job")) }
    private val tickTimer = Deadline(clock, ::enqueue) { whenOpen { drive("tick", QueuedInput.TICK) { e, engine, c -> e.tick(engine, c) } } }
    private val renewTimer = Deadline(clock, ::enqueue) { whenOpen { renew() } }

    enum class Phase { OPENING, OPEN, REBUILDING, FAILED, CLOSED }
    @Volatile var phase: Phase = Phase.OPENING; private set
    private var endpoint: SessionEndpoint? = null
    /** The authority head (seq and digest) of the view installed last, and this member's session number in it. */
    private var installed: Triple<ULong, String, ULong?>? = null
    /** The last `persisted_json` whose durable write completed: what a new endpoint starts from. */
    @Volatile var storedClaim: String? = null; private set
    /** Completes when the write in progress has ended (stored, or given up); set before any store code runs. */
    private var writing: CompletableDeferred<Unit>? = null
    /** This instance's fencing generation and its save count within it. */
    private var generation = 1L
    private var seq = 0L
    /** The fence this instance last saw held: what every save it makes expects (compare-and-set). */
    private var heldFence: Fence? = null
    private val watchMs: Long = (Json.obj(policy)?.get("beatMs") as? Number)?.toLong()?.takeIf { it > 0 } ?: 5_000
    private val watchMisses = maxOf(1, options.fenceCheckMisses)
    /** Every retry and deadline timer that is waiting, cancelled on close and on failure. */
    private val waits = LinkedHashSet<Wait>()
    private val admitted = LinkedHashSet<Held>()
    private val held = ArrayList<Held>()
    private var carrierUp = false
    private var attached = false
    private var stopPassListener: (() -> Unit)? = null

    /** Statistics for tests and diagnostics. */
    class Stats { var calls = 0; var queued = 0; var drops = 0; var stale = 0; var rebuilt = 0; var persisted = 0; var held = 0 }
    val stats = Stats()

    private inner class Held(val name: String, val json: String, val result: CompletableDeferred<Unit>?) {
        // Settled after the events the command's step produced have reached the listeners (they are queued first).
        fun resolve() { if (result != null) { synchronized(admitted) { admitted.remove(this) }; serial.event { result.complete(Unit) } } }
        fun reject(error: Throwable) { if (result != null) { synchronized(admitted) { admitted.remove(this) }; serial.event { result.completeExceptionally(error) } } }
    }

    companion object {
        private const val RENEW_BEFORE = 3_600_000L
        private fun codeOf(e: Throwable): String = (e as? AccountException)?.code ?: e.javaClass.simpleName
        fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
        fun base64url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        /** Bytes of standard or URL-safe base64, padded or not. */
        fun unbase64(text: String): ByteArray = Base64.getDecoder().decode(text.replace('-', '+').replace('_', '/').let { it + "=".repeat((4 - it.length % 4) % 4) })

        /**
         * Starts a session for this member in the cell: loads the stored claim, reserves this instance's fence, makes
         * the endpoint, has the member key sign its delegation, attaches to the carrier and joins with the application's
         * state. If any of that fails the host is closed (detached, its endpoint freed) and the error is thrown.
         */
        suspend fun open(options: CellHostOptions, listener: ((CellHostEvent) -> Unit)? = null): SessionCellHost {
            val host = SessionCellHost(options)
            if (listener != null) host.on(listener)
            val join: Deferred<Unit>
            try {
                join = withContext(host.dispatcher) {
                    val stored = host.store.load()
                    host.storedClaim = stored?.claim
                    host.heldFence = stored?.fence
                    host.generation = stored?.fence?.generation ?: 0
                    host.reserve(stored?.claim)
                    host.build()
                    if (host.phase != Phase.OPENING) throw CellHostError(CellHostError.Code.CLOSED, "the cell host was closed while it opened")
                    host.phase = Phase.OPEN
                    host.attached = true
                    host.carrier.attach(host)
                    host.stopPassListener = host.carrier.onPass { host.accountChanged() }
                    host.armTick(host.endpoint?.nextDeadline())
                    host.watch()
                    host.command("join", Json.write(mapOf("command" to "join", "state" to host.stateValue())))
                }
                join.await()
            } catch (e: Throwable) {
                withContext(host.dispatcher + NonCancellable) { host.closeNow() }
                throw e
            }
            return host
        }
    }

    fun on(listener: (CellHostEvent) -> Unit): () -> Unit { listeners.add(listener); return { listeners.remove(listener) } }

    /** The endpoint's read-only state, or null while it is being made again (or after the host ended). Read it from a listener or the host's context. */
    val current: SessionEndpoint? get() = endpoint
    /** Whether a `Persist` write is in progress. */
    val writePending: Boolean get() = writing != null

    // The queue

    private fun enqueue(job: () -> Unit) { if (phase != Phase.CLOSED) serial.job(job) }
    private fun emit(event: CellHostEvent) {
        serial.event { for (l in listeners) try { l(event) } catch (_: Exception) {} }
    }
    private val over: Boolean get() = phase == Phase.CLOSED || phase == Phase.FAILED
    private inline fun whenOpen(body: () -> Unit) { if (phase == Phase.OPEN && endpoint != null) body() }

    // Inputs (any thread)

    /**
     * An application command (§S10) as the core's JSON, tagged by `command`. It takes its place in the input queue now;
     * the result completes once the endpoint ran it, and fails at once when the host is closed or failed, or when
     * `maxCommands` are already waiting.
     */
    fun command(name: String, json: String): Deferred<Unit> {
        val result = CompletableDeferred<Unit>()
        val p = phase
        if (p == Phase.CLOSED || p == Phase.FAILED) {
            result.completeExceptionally(CellHostError(if (p == Phase.CLOSED) CellHostError.Code.CLOSED else CellHostError.Code.FAILED, "the cell host is ${p.name.lowercase()}"))
            return result
        }
        val c = Held(name, json, result)
        val full = synchronized(admitted) { if (admitted.size >= maxCommands) true else { admitted.add(c); false } }
        if (full) {
            result.completeExceptionally(CellHostError(CellHostError.Code.COMMAND_QUEUE_FULL, "$maxCommands commands are already waiting"))
            return result
        }
        serial.job { admit(c) }
        return result
    }
    override fun deliver(frame: String) = enqueue {
        if (phase == Phase.REBUILDING) { emit(CellHostEvent.Missed); return@enqueue }
        val bytes = Frames.frameBytes(frame)
        whenOpen { drive("receive", QueuedInput.FRAME) { e, engine, c -> e.receive(bytes, engine, c) } }
    }
    override fun linkUp() = enqueue { carrierUp = true; whenOpen { drive("linkUp", QueuedInput.LINK) { e, engine, c -> e.linkUp(engine, c) } } }
    override fun linkDown() = enqueue { carrierUp = false; whenOpen { drive("linkDown", QueuedInput.LINK) { e, engine, c -> e.linkDown(engine, c) } } }
    /** The account's verified head may have moved (after an exchange pass): install a fresh view if it did. */
    fun accountChanged() = enqueue {
        whenOpen {
            val (seq, digest) = try { val engine = account.engine(); engine.headSeq() to engine.headDigest() }
                catch (e: Exception) { emit(CellHostEvent.Error(codeOf(e), "accountChanged")); return@enqueue }
            val i = installed
            if (i != null && i.first == seq && i.second == digest) return@enqueue
            install()
            drainCommands()
        }
    }

    /** Ends this member's part: `leave` (a holder releases the role), then detaches and drops the endpoint. */
    suspend fun leave() {
        try { command("leave", """{"command":"leave"}""").await() } finally { close() }
    }
    /** Stops at once, as a process that ends would: no `leave`; the stored claim is what a restart starts from. */
    fun close() {
        if (over) return
        serial.job { closeNow() }
    }
    private fun closeNow() = end(Phase.CLOSED, CellHostError(CellHostError.Code.CLOSED, "the cell host is closed"))

    private fun end(to: Phase, why: CellHostError) {
        if (phase == Phase.CLOSED || phase == Phase.FAILED) return
        phase = to
        tickTimer.clear(); renewTimer.clear()
        for (w in waits.toList()) w.stop()
        stopPassListener?.invoke(); stopPassListener = null
        if (attached) { attached = false; try { carrier.detach(this) } catch (_: Exception) {} }
        held.clear()
        for (c in synchronized(admitted) { admitted.toList() }) c.reject(why)
        if (to == Phase.CLOSED) serial.clearJobs()
        val e = endpoint; endpoint = null
        try { e?.close() } catch (_: Exception) {}
    }
    private fun fail(reason: FailReason, error: Throwable? = null) {
        if (over) return
        end(Phase.FAILED, CellHostError(CellHostError.Code.FAILED, "the cell host failed (${reason.name.lowercase()})"))
        emit(CellHostEvent.Failed(reason, error))
    }

    // The loop (serial context only)

    private fun clockNow() = SessionClock(maxOf(0L, clock.monoMs()).toULong(), clock.wallMs())
    private fun armTick(due: ULong?) {
        if (phase != Phase.OPEN || endpoint == null) { tickTimer.clear(); return }
        tickTimer.at(due?.toLong())
    }

    /**
     * One endpoint call and its step. `session:staleAccount` installs a fresh view and runs the input once more; a
     * backwards clock or another engine's view makes the endpoint again. A command's other errors are the caller's.
     * Returns whether the input ran.
     */
    private fun drive(during: String, input: QueuedInput?, again: Boolean = true, call: (SessionEndpoint, AccountEngine, SessionClock) -> SessionStep): Boolean {
        val e = endpoint
        if (e == null || phase != Phase.OPEN) return false
        val engine = try { account.engine() } catch (x: Exception) { emit(CellHostEvent.Error(codeOf(x), during)); return false }
        val step = try {
            stats.calls++
            call(e, engine, clockNow())
        } catch (x: Exception) {
            val c = codeOf(x)
            if (c == "session:staleAccount" && again) {
                stats.stale++
                emit(CellHostEvent.Stale)
                if (!install()) return false
                return drive(during, input, false, call)
            }
            if (c == "session:clockBackwards") { rebuild(RebuildReason.CLOCK_BACKWARDS); return false }
            if (c == "session:wrongView") { rebuild(RebuildReason.WRONG_VIEW); return false }
            if (input == null && during == "command") throw x
            emit(CellHostEvent.Error(c, during))
            return false
        }
        if (input != null && step.queued) { stats.queued++; emit(CellHostEvent.Queued(input)) }
        handle(step)
        return true
    }

    /** Carries out a step's effects in order, reports its drops and discards, and arms the timer from it. */
    private fun handle(step: SessionStep) {
        for (effect in step.effects) {
            when (effect.kind) {
                SessionEffectKind.SEND -> {
                    val kind = effect.frameKind ?: ""
                    val frame = Frames.frameText(effect.bytes)
                    if (frame == null) { emit(CellHostEvent.Unsent(kind, "encoding")); continue }
                    val sent = try { carrier.sendSession(frame) } catch (_: Exception) { false }
                    emit(if (sent) CellHostEvent.Sent(kind, frame) else CellHostEvent.Unsent(kind, "carrier", frame))
                }
                SessionEffectKind.EVENT -> {
                    val json = effect.eventJson ?: "{}"
                    val fields = Json.obj(json) ?: mapOf()
                    emit(CellHostEvent.Session(fields["event"] as? String ?: effect.event ?: "unknown", json, fields))
                }
                // A step's effects end at its first Persist; its acknowledgement ID is the step's.
                SessionEffectKind.PERSIST -> {
                    val json = effect.persistedJson; val ack = step.awaitingPersist
                    if (json != null && ack != null) write(json, ack)
                }
                SessionEffectKind.UNSENT -> emit(CellHostEvent.Unsent(effect.frameKind ?: "", effect.unsent ?: "unknown"))
            }
        }
        for (d in step.drops) { stats.drops++; emit(CellHostEvent.Drop(d.reason, d.helloTo)) }
        if (step.discarded > 0u) emit(CellHostEvent.Discarded(step.discarded.toInt()))
        // While a Persist is outstanding the step carries no deadline: nothing to tick until its acknowledgement.
        armTick(step.nextDeadline)
    }

    private sealed class Outcome {
        data class Done(val result: SaveResult) : Outcome()
        data class Err(val error: Throwable) : Outcome()
        data object Fired : Outcome()
        data object Cancelled : Outcome()
    }

    /**
     * The durable write of one `Persist`; only its completion, as a later job, acknowledges it. One save is in flight at
     * a time: an attempt that passes its deadline counts as failed, and the next one starts only once it has settled (a
     * save that never settles uses up the attempts and fails the cell without another save being issued). A save that
     * succeeds only after its deadline is not acknowledged: the claim is saved again under the next fence.
     */
    private fun write(json: String, ack: ULong) {
        val endpoint = this.endpoint
        val ended = CompletableDeferred<Unit>()
        // Marked before any store code runs, so nothing can see "no write" while this one is under way.
        writing = ended
        emit(CellHostEvent.Persist(PersistPhase.STARTED, ack))
        scope.launch {
            try {
                var failures = 0
                fun failed(error: Throwable): Boolean {
                    failures++
                    emit(CellHostEvent.Persist(PersistPhase.FAILED, ack, error))
                    if (failures < persistAttempts) return false
                    enqueue { writing = null; fail(FailReason.STORE, error) }
                    return true
                }
                while (true) {
                    if (over) return@launch
                    val save = save(StoredClaim(json, Fence(generation, ++seq)))
                    var late = false
                    var result: Outcome
                    while (true) {
                        val deadline = Wait(persistTimeoutMs)
                        val r = select { save.onAwait { it }; deadline.done.onAwait { if (it) Outcome.Fired else Outcome.Cancelled } }
                        deadline.cancel()
                        if (r == Outcome.Cancelled) return@launch
                        if (r == Outcome.Fired) {
                            late = true
                            if (failed(CellHostError(CellHostError.Code.TIMEOUT, "the store did not finish a write within $persistTimeoutMs ms"))) return@launch
                            continue
                        }
                        result = r
                        break
                    }
                    if (result is Outcome.Err) {
                        // A failed write may still have been written: what is held now is read before the next attempt.
                        adopt()
                        if (failed(result.error)) return@launch
                        if (!Wait(persistRetryMs).done.await()) return@launch
                        continue
                    }
                    if ((result as Outcome.Done).result == SaveResult.STALE) {
                        // Stale against this instance's own earlier save (one it could not see complete) is adopted and
                        // saved again; anything else means another instance holds the cell.
                        if (adopt()) continue
                        enqueue { writing = null; fail(FailReason.SUPERSEDED) }
                        return@launch
                    }
                    if (late) continue
                    break
                }
                // Stored: a restart starts from it, whatever happens to this endpoint.
                storedClaim = json
                enqueue {
                    writing = null
                    if (this@SessionCellHost.endpoint !== endpoint || phase != Phase.OPEN) return@enqueue
                    stats.persisted++
                    emit(CellHostEvent.Persist(PersistPhase.STORED, ack))
                    try { drive("persisted", null) { e, engine, c -> e.persisted(ack, engine, c) } } catch (x: Exception) { emit(CellHostEvent.Error(codeOf(x), "persisted")) }
                    drainCommands()
                }
            } finally {
                ended.complete(Unit)
            }
        }
    }

    /**
     * Takes the next generation by compare-and-set from the fence last seen held, saving `claim` under
     * `{generation, 0}`. Another instance that reserved first makes it stale: `SUPERSEDED`.
     */
    private suspend fun reserve(claim: String?) {
        val next = generation + 1
        if (!Fence.isValid(next)) throw CellHostError(CellHostError.Code.FAILED, "the fence generation is exhausted")
        generation = next; seq = 0
        val deadline = Wait(persistTimeoutMs)
        val save = save(StoredClaim(claim, Fence(next, 0)))
        val r = select { save.onAwait { it }; deadline.done.onAwait { if (it) Outcome.Fired else Outcome.Cancelled } }
        deadline.cancel()
        when (r) {
            Outcome.Fired, Outcome.Cancelled -> throw CellHostError(CellHostError.Code.TIMEOUT, "the store did not reserve this host's fence in time")
            is Outcome.Err -> throw r.error
            is Outcome.Done -> if (r.result == SaveResult.STALE) throw CellHostError(CellHostError.Code.SUPERSEDED, "another instance of this cell reserved the fence first")
        }
    }
    /** One compare-and-set save from the fence last seen held; never throws. A stored save moves that fence. */
    private fun save(record: StoredClaim): Deferred<Outcome> = scope.async {
        try {
            val s = store.save(record, heldFence)
            if (s == SaveResult.STORED) heldFence = record.fence
            Outcome.Done(s)
        } catch (e: CancellationException) { throw e } catch (e: Throwable) { Outcome.Err(e) }
    }
    /**
     * Reads the held fence after a save this instance could not see complete. True when it is one of this instance's
     * own (adopted as the fence to expect); false when another instance's.
     */
    private suspend fun adopt(): Boolean {
        val now = try { store.load() } catch (e: CancellationException) { throw e } catch (_: Exception) { return true }
        val f = now?.fence
        if (f != null && f.generation == generation && f.seq <= seq) { heldFence = f; return true }
        return f == heldFence
    }
    /**
     * Checks, every beat, that the store still holds this instance's fence, by reading the fence alone. It is never
     * skipped: while a write is in flight the held fence may be that write's (one of this instance's own). Another
     * instance's fence fails the cell as `SUPERSEDED` within one beat. One read starts each beat and must answer within
     * it; after `fenceCheckMisses` consecutive beats whose read failed or did not answer, the cell fails closed (`STORE`).
     */
    private fun watch() {
        scope.launch {
            var misses = 0
            if (!Wait(watchMs).done.await()) return@launch
            while (!over) {
                val beat = Wait(watchMs)
                val read = scope.async {
                    try { Outcome.Done(SaveResult.STORED) to store.fence() } catch (e: CancellationException) { throw e } catch (e: Throwable) { Outcome.Err(e) to null }
                }
                val r: Pair<Outcome, Fence?> = select { read.onAwait { it }; beat.done.onAwait { (if (it) Outcome.Fired else Outcome.Cancelled) to null } }
                if (r.first == Outcome.Cancelled || over) { beat.cancel(); return@launch }
                if (r.first is Outcome.Done) {
                    misses = 0
                    if (!mine(r.second)) { beat.cancel(); enqueue { fail(FailReason.SUPERSEDED) }; return@launch }
                } else {
                    misses++
                    if (misses >= watchMisses) {
                        beat.cancel()
                        val error = (r.first as? Outcome.Err)?.error ?: CellHostError(CellHostError.Code.TIMEOUT, "the store did not answer a fence check in time")
                        enqueue { fail(FailReason.STORE, error) }
                        return@launch
                    }
                }
                if (r.first != Outcome.Fired && !beat.done.await()) return@launch
            }
        }
    }
    /** Whether `f` is a fence this instance saved (the one it last saw held, or one of its current generation's). */
    private fun mine(f: Fence?): Boolean {
        if (f == null) return false
        if (f == heldFence) return true
        return f.generation == generation && f.seq <= seq
    }

    /** A timer that close and failure cancel: `done` is true when it fired, false when it was cancelled. */
    private inner class Wait(ms: Long) {
        val done = CompletableDeferred<Boolean>()
        private var stopTimer: () -> Unit = {}
        init {
            if (over) done.complete(false) else {
                waits.add(this)
                stopTimer = clock.setTimer(ms) { serial.job { waits.remove(this); done.complete(true) } }
            }
        }
        /** Close and failure: it never fires. */
        fun stop() { stopTimer(); waits.remove(this); done.complete(false) }
        /** The waiter no longer needs it. */
        fun cancel() { stopTimer(); waits.remove(this) }
    }

    /** A command at its place in the input queue: run now, or held behind an earlier held command. */
    private fun admit(c: Held) {
        if (over) { c.reject(CellHostError(if (phase == Phase.FAILED) CellHostError.Code.FAILED else CellHostError.Code.CLOSED, "the cell host is ${phase.name.lowercase()}")); return }
        held.add(c)
        if (held.size == 1) drainCommands()
    }
    /** Runs held commands in order; one refused with `session:persistPending` waits for the write to complete. */
    private fun drainCommands() {
        while (held.isNotEmpty() && phase == Phase.OPEN && endpoint != null) {
            val c = held[0]
            val ran = try {
                drive("command", null) { e, engine, clock -> e.command(c.json, engine, clock) }
            } catch (x: Exception) {
                if (codeOf(x) == "session:persistPending") { stats.held++; emit(CellHostEvent.CommandHeld(c.name)); return }
                held.removeAt(0)
                c.reject(x)
                continue
            }
            // Not run because the endpoint is being made again (or the host ended): it stays first in line, or was refused.
            if (!ran && phase != Phase.OPEN) return
            held.removeAt(0)
            if (ran) c.resolve() else c.reject(CellHostError(CellHostError.Code.NOT_RUN, "the ${c.name} command could not be run"))
        }
    }

    // Views, delegation and rebuilding

    /** Installs the engine's current view (`set_account`). False when the endpoint is being made again instead. */
    private fun install(): Boolean {
        val e = endpoint ?: return false
        val engine: AccountEngine; val view: SessionAccountView
        try {
            engine = account.engine()
            view = engine.sessionAccount(namespace, clock.wallMs())
        } catch (x: Exception) { emit(CellHostEvent.Error(codeOf(x), "install")); return false }
        try {
            val session = view.sessionOf(me)
            val seq = engine.headSeq(); val digest = engine.headDigest()
            // A new session number needs a new session key (sessions §S2): a new endpoint.
            val before = installed?.third
            if (installed != null && session != null && before != null && session != before) { rebuild(RebuildReason.SESSION_CHANGED); return false }
            val step = try { e.setAccount(view, engine, clockNow()) } catch (x: AccountException) {
                when (x.code) {
                    "session:clockBackwards" -> rebuild(RebuildReason.CLOCK_BACKWARDS)
                    "session:wrongView" -> rebuild(RebuildReason.WRONG_VIEW)
                    else -> emit(CellHostEvent.Error(x.code, "install"))
                }
                return false
            }
            installed = Triple(seq, digest, session ?: before)
            handle(step)
            emit(CellHostEvent.Account(e.entitled(), e.canWrite(), seq))
            return true
        } catch (x: Exception) {
            emit(CellHostEvent.Error(codeOf(x), "install"))
            return false
        } finally {
            view.close()
        }
    }

    /** Makes the endpoint from the stored claim with new randomness, and installs a signed delegation. */
    private suspend fun build() {
        val engine = account.engine()
        val made: SessionEndpoint
        val view = engine.sessionAccount(namespace, clock.wallMs())
        try {
            val keyRandom = random(32); val seed = random(16)
            try {
                made = SessionEndpoint(account.account, namespace, cell, me, policy, storedClaim, view, keyRandom, seed, clockNow())
            } finally { keyRandom.fill(0); seed.fill(0) }
            installed = Triple(engine.headSeq(), engine.headDigest(), view.sessionOf(me))
        } finally {
            view.close()
        }
        endpoint = made
        val notBefore = clock.wallMs() - 60_000
        val body = made.beginDelegation(notBefore, notBefore + delegationMs)
        val signature = account.signRaw(body)
        if (endpoint !== made) throw CellHostError(CellHostError.Code.CLOSED, "the cell host ended while its delegation was signed")
        made.finishDelegation(body, signature, clockNow())
        armRenewal(notBefore + delegationMs)
    }
    private fun armRenewal(expires: Long) {
        renewTimer.at(clock.monoMs() + maxOf(60_000L, expires - clock.wallMs() - RENEW_BEFORE))
    }
    /** Signs a new delegation for the same session key before the old one ends. */
    private fun renew() {
        val e = endpoint ?: return
        val notBefore = clock.wallMs() - 60_000
        val expires = notBefore + delegationMs
        val body = try { e.beginDelegation(notBefore, expires) } catch (x: Exception) { emit(CellHostEvent.Error(codeOf(x), "delegation")); return }
        scope.launch {
            val signature = try { account.signRaw(body) } catch (x: CancellationException) { throw x } catch (x: Exception) { emit(CellHostEvent.Error(codeOf(x), "delegation")); return@launch }
            enqueue {
                if (endpoint !== e || phase != Phase.OPEN) return@enqueue
                try { e.finishDelegation(body, signature, clockNow()); armRenewal(expires) } catch (x: Exception) { emit(CellHostEvent.Error(codeOf(x), "delegation")) }
            }
        }
    }

    /**
     * Discards the endpoint and makes a new one from the last stored claim (after the write in progress, if any, ends),
     * then joins again with the application's state. Frames that arrive meanwhile are not judged (`Missed`). If the new
     * endpoint cannot be made, the cell fails.
     */
    private fun rebuild(reason: RebuildReason) {
        if (phase != Phase.OPEN) return
        phase = Phase.REBUILDING
        stats.rebuilt++
        emit(CellHostEvent.Rebuilt(reason))
        tickTimer.clear(); renewTimer.clear()
        val old = endpoint; endpoint = null
        try { old?.close() } catch (_: Exception) {}
        val inFlight = writing
        scope.launch {
            try {
                inFlight?.await()
                if (phase != Phase.REBUILDING) return@launch
                // The new endpoint takes a new generation by compare-and-set, like an open.
                reserve(storedClaim)
                build()
            } catch (e: CancellationException) { throw e } catch (e: Throwable) {
                val superseded = e is CellHostError && e.code == CellHostError.Code.SUPERSEDED
                enqueue { if (phase == Phase.REBUILDING) fail(if (superseded) FailReason.SUPERSEDED else FailReason.REBUILD, e) }
                return@launch
            }
            enqueue {
                if (phase != Phase.REBUILDING) return@enqueue
                phase = Phase.OPEN
                held.add(0, Held("join", Json.write(mapOf("command" to "join", "state" to stateValue())), null))
                armTick(endpoint?.nextDeadline())
                if (carrierUp) drive("linkUp", QueuedInput.LINK) { e, engine, c -> e.linkUp(engine, c) }
                drainCommands()
            }
        }
    }

    private fun stateValue(): String? = stateOf()?.let { base64(it) }

    /** Tests only: replaces the account or the store (a key that stops signing, a store that never answers). */
    internal fun replaceForTests(account: HostAccount? = null, store: ClaimStore? = null) {
        if (account != null) this.account = account
        if (store != null) this.store = store
    }
}
