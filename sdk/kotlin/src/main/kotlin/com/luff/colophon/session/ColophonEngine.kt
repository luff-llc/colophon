package com.luff.colophon.session

import com.luff.colophon.AccountAction
import com.luff.colophon.AccountCreation
import com.luff.colophon.AccountDenialReason
import com.luff.colophon.AccountEngine
import com.luff.colophon.AccountException
import com.luff.colophon.AccountIdentity
import com.luff.colophon.Changes
import com.luff.colophon.HostSource
import com.luff.colophon.ListedPath
import com.luff.colophon.SavedState
import com.luff.colophon.Written
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** The typed code of every engine error (`malformed`, `refused:<reason>`, `denied:<reason>`, ...). */
val AccountException.code: String
    get() = when (this) {
        is AccountException.Malformed -> code
        is AccountException.BadSignature -> code
        is AccountException.NewerFormat -> code
        is AccountException.Unavailable -> code
        is AccountException.Refused -> code
        is AccountException.Host -> code
        is AccountException.Reentered -> code
        is AccountException.Consumed -> code
        is AccountException.WrongObject -> code
        is AccountException.Bound -> code
        is AccountException.Internal -> code
        is AccountException.Denied -> code
        is AccountException.Integrity -> code
        is AccountException.Locked -> code
    }

/**
 * One `AccountEngine` on its own serial dispatcher (a single-lane view of `Dispatchers.IO`): never on the main
 * thread, and calls to one engine are strictly ordered. The Kotlin twin of the Swift SDK's `ColophonEngine` actor.
 *
 * Threads and callbacks (docs/bindings-05.md §3a): a `HostSource` callback runs on this lane while the engine is
 * inside a call. It must do its own I/O and return; it must not call back into this engine, and must not wait on
 * anything that does (a main-thread hop, a mutex held by a coroutine waiting for this engine).
 *
 * Lifecycle: [lock] before the last reference goes. Dropping it leaves the keys to UniFFI's cleaner at no fixed time.
 */
class ColophonEngine private constructor(val account: String, val identity: AccountIdentity, label: String) {
    @Suppress("OPT_IN_USAGE")
    private val lane: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1, label)
    @Volatile private var engine: AccountEngine? = null

    companion object {
        /** Opens the engine over `source` on its own lane. See `AccountEngine.open` for the arguments. */
        suspend fun open(label: String = "colophon-engine", source: HostSource, listing: List<ListedPath>, identity: AccountIdentity,
                         account: String, namespaces: List<String> = listOf(), batch: ULong = 0u, saved: SavedState? = null,
                         deviceKey: SecretBytes, nowMs: Long): ColophonEngine {
            val e = ColophonEngine(account, identity, label)
            withContext(e.lane) {
                e.engine = deviceKey.lend { key ->
                    AccountEngine.open(source, listing, identity, account, namespaces, batch,
                        saved ?: SavedState(ByteArray(0), ByteArray(0), listOf()), key, nowMs)
                }
            }
            return e
        }

        /**
         * Opens the engine over the stores `creation.takeResult()` returned (stored and listed by the host), unlocked
         * as the creation left it (`AccountCreation.open_engine`): the owner is asked once at first run. One shot.
         */
        suspend fun openCreated(creation: AccountCreation, label: String = "colophon-engine", source: HostSource, listing: List<ListedPath>,
                                account: String, identity: AccountIdentity, namespaces: List<String> = listOf(), batch: ULong = 0u,
                                deviceKey: SecretBytes, nowMs: Long): ColophonEngine {
            val e = ColophonEngine(account, identity, label)
            withContext(e.lane) { e.engine = deviceKey.lend { key -> creation.openEngine(source, listing, namespaces, batch, key, nowMs) } }
            return e
        }
    }

    /** Runs `body` on the engine's lane. A locked or discarded engine is `AccountException.Locked`. */
    suspend fun <T> run(body: (AccountEngine) -> T): T = withContext(lane) {
        val e = engine ?: throw AccountException.Locked("locked", "this engine was locked or discarded; open a new one")
        body(e)
    }

    val isLocked: Boolean get() = engine == null

    /** Overwrites the engine's keys and opened plaintext and releases it. Further calls are `Locked`. */
    suspend fun lock() = withContext(lane + NonCancellable) {
        val e = engine ?: return@withContext
        engine = null
        try { e.lock() } catch (_: AccountException) {}
        e.close()
    }

    /** Drops the engine after a call that ended in `Integrity` (it is unusable; `lock` is not called). */
    suspend fun discard() = withContext(lane + NonCancellable) { engine?.close(); engine = null }

    suspend fun finishUnlockSlot(index: ULong, secrets: List<HostUnlockSecret>): Changes =
        try { run { e -> secrets.withRecords { e.finishUnlockSlot(index, it) } } } finally { secrets.closeAll() }

    suspend fun finishUnlockEpochs(answers: List<HostEpochAnswer>): Changes =
        try { run { e -> answers.withRecords { e.finishUnlockEpochs(it) } } } finally { answers.closeAll() }

    /**
     * An action from `begin` to `Written`: prepare, answer PRF requests, sign every step, finish. The key ceremonies
     * in between run in `custody`, off the engine's lane, so a person's pause never holds the engine. A write refused
     * for access reasons throws `AccountException.Denied` (a value in the bindings). A failed finish changes nothing
     * and consumes the action. `then` runs with the finished stores inside the same uncancellable step.
     */
    suspend fun execute(custody: KeyCustody, then: (suspend (Written) -> Unit)? = null, begin: (AccountEngine) -> AccountAction): Written {
        val action = run(begin)
        try {
            run { action.denial() }?.let { d ->
                throw AccountException.Denied("denied:" + (d.reasonRaw ?: d.reason.wire), d.reason, d.reasonRaw, d.detail)
            }
            val requests = run { action.prfRequests() }
            if (requests.isNotEmpty()) {
                val answers = custody.answer(requests)
                try { run { e -> answers.withRecords { e.providePrf(action, it) } } } finally { answers.closeAll() }
            }
            val signatures = custody.sign(run { action.steps() })
            // The finish and what the caller does with its stores (`then`: persist them) are one uncancellable step: a
            // cancelled caller never leaves the engine ahead of the disk. Waiting on the person above stays cancellable.
            return withContext(NonCancellable) {
                val written = this@ColophonEngine.run { it.finish(action, signatures) }
                then?.invoke(written)
                written
            }
        } finally {
            action.close()
        }
    }
}

/** The §19 access reason as the protocol writes it. */
internal val AccountDenialReason.wire: String
    get() = when (this) {
        AccountDenialReason.NOT_GRANTED -> "notGranted"
        AccountDenialReason.REVOKED -> "revoked"
        AccountDenialReason.EXPIRED -> "expired"
        AccountDenialReason.BUDGET_SPENT -> "budgetSpent"
        AccountDenialReason.NOT_READABLE -> "notReadable"
        AccountDenialReason.UNAVAILABLE -> "unavailable"
        AccountDenialReason.UNKNOWN -> "unknown"
    }
