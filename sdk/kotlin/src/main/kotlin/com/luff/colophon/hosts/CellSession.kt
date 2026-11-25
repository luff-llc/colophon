package com.luff.colophon.hosts

import com.luff.colophon.session.Json
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList

/** A claim (§S4): taken (`rank` 0) or passed (`rank` 1, with `via`). */
data class Claim(val term: Long, val rank: Int, val holder: String, val via: String? = null) {
    companion object {
        fun of(value: Any?): Claim? {
            @Suppress("UNCHECKED_CAST") val m = value as? Map<String, Any?> ?: return null
            return Claim((m["term"] as? Number ?: return null).toLong(), (m["rank"] as? Number ?: return null).toInt(), m["holder"] as? String ?: return null, m["via"] as? String)
        }
    }
}

/** What the application sees of a cell. Replaced, never changed in place, on every change. */
data class CellState(
    /** The member has joined. */
    val joined: Boolean = false,
    /** This member's view of the holder (null: no holder). */
    val holder: String? = null,
    /** This member acts as holder (locally, even while [gated]). Show the role as held only when `isHolder && !gated`. */
    val isHolder: Boolean = false,
    /**
     * A holder that may not send holder frames yet: it restarted holding its stored claim, or came back after being
     * out of contact, and waits out `askTimeoutMs` before it retakes or yields (sessions §S6).
     */
    val gated: Boolean = false,
    /** The greatest claim this member accepted. */
    val claim: Claim? = null,
    /** The cell's state as this member holds it (for `fold: latest`, the last payload or snapshot). */
    val state: ByteArray? = null,
    /** The position of [state] in the ordered lane. */
    val seq: Long = 0,
    /** The member holds a `records` entry for the namespace (it may send). */
    val entitled: Boolean = false,
    /** The member may hold and submit (`write` access). */
    val canWrite: Boolean = false,
) {
    override fun equals(other: Any?): Boolean {
        if (other !is CellState) return false
        val sameState = state?.let { mine -> other.state?.contentEquals(mine) ?: false } ?: (other.state == null)
        return joined == other.joined && holder == other.holder && isHolder == other.isHolder && gated == other.gated &&
            claim == other.claim && seq == other.seq && entitled == other.entitled && canWrite == other.canWrite && sameState
    }
    override fun hashCode(): Int = listOf(joined, holder, isHolder, gated, claim, seq, entitled, canWrite, state?.contentHashCode()).hashCode()
    /** No application state in a string (it may be logged). */
    override fun toString() = "CellState(joined=$joined, holder=$holder, isHolder=$isHolder, gated=$gated, claim=$claim, seq=$seq, entitled=$entitled, canWrite=$canWrite)"
}

/** The core's events (§S10), with bytes decoded. Payloads and snapshots are application state: show them, never log them. */
sealed class CellEvent {
    data class BecameHolder(val claim: Claim?, val snapshot: ByteArray?, val via: String) : CellEvent()
    data class Yielded(val to: Claim?) : CellEvent()
    data class HolderChanged(val claim: Claim?) : CellEvent()
    data class AskReceived(val from: String) : CellEvent()
    data class Declined(val from: String) : CellEvent()
    data class Message(val claim: Claim?, val seq: Long, val origin: String, val id: ByteArray?, val payload: ByteArray?) : CellEvent()
    data class Snapshot(val claim: Claim?, val seq: Long, val snapshot: ByteArray?) : CellEvent()
    data class Refused(val id: ByteArray?, val reason: String) : CellEvent()
    data class PresenceChanged(val member: String, val payload: ByteArray?) : CellEvent()
    data class HolderLapsed(val holder: String) : CellEvent()
    data class OffsetChanged(val peer: String, val offset: Long, val error: Long) : CellEvent()
    data class LatePass(val from: String, val claim: Claim?, val snapshot: ByteArray?) : CellEvent()
    data class Displaced(val from: String, val claim: Claim?, val seq: Long, val snapshot: ByteArray?) : CellEvent()
    data class SubmitFailed(val id: ByteArray?) : CellEvent()
    data class Rejected(val command: String, val reason: String) : CellEvent()
    /** An event this SDK does not know, as the core's JSON fields. */
    data class Other(val name: String, val fields: Map<String, Any?>) : CellEvent()

    companion object {
        /** An event's JSON fields (an `Event` effect) as a typed event. */
        fun of(name: String, f: Map<String, Any?>): CellEvent {
            fun s(k: String) = f[k] as? String ?: ""
            fun n(k: String) = (f[k] as? Number)?.toLong() ?: 0
            fun b(k: String) = (f[k] as? String)?.let { runCatching { SessionCellHost.unbase64(it) }.getOrNull() }
            fun c(k: String) = Claim.of(f[k])
            return when (name) {
                "becameHolder" -> BecameHolder(c("claim"), b("snapshot"), s("via"))
                "yielded" -> Yielded(c("to"))
                "holderChanged" -> HolderChanged(c("claim"))
                "askReceived" -> AskReceived(s("from"))
                "declined" -> Declined(s("from"))
                "message" -> Message(c("claim"), n("seq"), s("origin"), b("id"), b("payload"))
                "snapshot" -> Snapshot(c("claim"), n("seq"), b("snapshot"))
                "refused" -> Refused(b("id"), s("reason"))
                "presenceChanged" -> PresenceChanged(s("member"), b("payload"))
                "holderLapsed" -> HolderLapsed(s("holder"))
                "offsetChanged" -> OffsetChanged(s("peer"), n("offset"), n("error"))
                "latePass" -> LatePass(s("from"), c("claim"), b("snapshot"))
                "displaced" -> Displaced(s("from"), c("claim"), n("seq"), b("snapshot"))
                "submitFailed" -> SubmitFailed(b("id"))
                "rejected" -> Rejected(s("command"), s("reason"))
                else -> Other(name, f)
            }
        }
    }
}

/**
 * A small typed API over one session cell: join, observe the holder, the claim and the state, take, ask, pass,
 * publish, submit, leave. It decides nothing: every call is a core command, and what it publishes comes from the
 * endpoint. Each command takes its place in the cell's input queue when it is called (so commands issued from a
 * listener keep their order among frames); the returned value completes once the endpoint has run it.
 */
class CellSession private constructor(val host: SessionCellHost) {
    @Volatile private var current = CellState()
    private val listeners = CopyOnWriteArrayList<(CellState) -> Unit>()
    private val eventListeners = CopyOnWriteArrayList<(CellEvent) -> Unit>()

    companion object {
        private val random = SecureRandom()
        private fun randomId() = ByteArray(16).also { random.nextBytes(it) }

        /** Joins the cell ([SessionCellHost.open]) and starts publishing its state. */
        suspend fun join(options: CellHostOptions): CellSession {
            var session: CellSession? = null
            val early = ArrayList<CellHostEvent>()
            val lock = Any()
            val host = SessionCellHost.open(options) { e -> synchronized(lock) { session?.hostEvent(e) ?: early.add(e) } }
            val s = CellSession(host)
            synchronized(lock) { for (e in early) s.hostEvent(e); session = s }
            s.refresh()
            return s
        }
    }

    /** The cell as this member sees it now. */
    val state: CellState get() = current
    /** Called after every change of [state] (on the host's context); returns the function that stops it. */
    fun subscribe(listener: (CellState) -> Unit): () -> Unit { listeners.add(listener); return { listeners.remove(listener) } }
    /** Called with every core event, in order (on the host's context); returns the function that stops it. */
    fun events(listener: (CellEvent) -> Unit): () -> Unit { eventListeners.add(listener); return { eventListeners.remove(listener) } }

    private fun cmd(name: String, vararg fields: Pair<String, Any?>): Deferred<Unit> =
        host.command(name, Json.write(linkedMapOf<String, Any?>("command" to name).apply { putAll(fields) }))

    /** Takes the role as soon as §S5 allows (at once when there is no live holder), from `state` or the cell's own. */
    fun take(state: ByteArray? = null): Deferred<Unit> = cmd("take", "state" to state?.let { SessionCellHost.base64(it) })
    /** Asks the holder for the role (a handoff between live devices: the holder answers with [pass]). */
    fun ask(): Deferred<Unit> = cmd("ask")
    /** Passes the role to `to`, an asker, with the final state (the application stopped what the role controls first). */
    fun pass(to: String, snapshot: ByteArray): Deferred<Unit> = cmd("pass", "to" to to, "snapshot" to SessionCellHost.base64(snapshot))
    /** Declines an asker. */
    fun decline(to: String): Deferred<Unit> = cmd("decline", "to" to to)
    /** Gives up the role without a successor. */
    fun release(): Deferred<Unit> = cmd("release")
    /** Orders a message as holder (for `fold: latest`, the new state). Completes with its id. */
    fun publish(payload: ByteArray, id: ByteArray = randomId()): Deferred<ByteArray> =
        cmd("publish", "id" to SessionCellHost.base64url(id), "payload" to SessionCellHost.base64(payload)).then(id)
    /** Asks the holder to order a message (delivery is at least once). Completes with its id. */
    fun submit(payload: ByteArray, id: ByteArray = randomId()): Deferred<ByteArray> =
        cmd("submit", "id" to SessionCellHost.base64url(id), "payload" to SessionCellHost.base64(payload)).then(id)
    /** Publishes this member's presence. */
    fun presence(payload: ByteArray): Deferred<Unit> = cmd("presence", "payload" to SessionCellHost.base64(payload))
    /** Measures the round trip and clock offset to `to` (an [CellEvent.OffsetChanged] follows). */
    fun ping(to: String): Deferred<Unit> = cmd("ping", "to" to to)
    /** Leaves the session (a holder releases the role) and ends the endpoint. */
    suspend fun leave() = host.leave()
    /** Stops at once without leaving, as a process that ends would. */
    fun close() = host.close()

    private fun Deferred<Unit>.then(id: ByteArray): Deferred<ByteArray> {
        val out = CompletableDeferred<ByteArray>()
        invokeOnCompletion { e -> if (e == null) out.complete(id) else out.completeExceptionally(e) }
        return out
    }

    private fun hostEvent(event: CellHostEvent) {
        if (event is CellHostEvent.Session) {
            val typed = CellEvent.of(event.name, event.fields)
            for (l in eventListeners) try { l(typed) } catch (_: Exception) {}
        }
        if (event is CellHostEvent.Session || event is CellHostEvent.Account || event is CellHostEvent.Rebuilt || event is CellHostEvent.Persist) refresh()
    }
    private fun refresh() {
        val e = host.current ?: return
        val next = try {
            val view = Json.obj(e.viewJson()) ?: return
            CellState(joined = e.joined(), holder = view["holder"] as? String, isHolder = e.isHolder(), gated = e.gated(), claim = Claim.of(view["accepted"]),
                state = (view["state"] as? String)?.let { SessionCellHost.unbase64(it) }, seq = (view["seq"] as? Number)?.toLong() ?: 0,
                entitled = e.entitled(), canWrite = e.canWrite())
        } catch (_: Exception) { return }
        if (next == current) return
        current = next
        for (l in listeners) try { l(next) } catch (_: Exception) {}
    }
}
