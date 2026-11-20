package com.luff.colophon

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

/**
 * How long a passkey adapter waits, after it creates a passkey, for the credential provider to offer it.
 *
 * Some providers (Google Password Manager on Android) save a new passkey asynchronously: for a moment after a
 * successful create, a get that names the new credential finds nothing. Before the first get for a credential it
 * created in this process, the adapter polls the provider without UI every [pollIntervalMillis] until it offers the
 * credential, for at most [timeoutMillis]. Where the provider cannot be polled (Android before 14), it waits
 * [fallbackMillis] instead. A timeout never fails: the get runs and reports its own result. [NONE] turns the wait off.
 */
data class PasskeyReadyWait(
    val pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS,
    val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
    val fallbackMillis: Long = DEFAULT_FALLBACK_MILLIS,
) {
    init {
        require(pollIntervalMillis > 0) { "pollIntervalMillis must be positive" }
        require(timeoutMillis >= 0) { "timeoutMillis must not be negative" }
        require(fallbackMillis >= 0) { "fallbackMillis must not be negative" }
    }

    companion object {
        const val DEFAULT_POLL_INTERVAL_MILLIS: Long = 400
        const val DEFAULT_TIMEOUT_MILLIS: Long = 15_000
        const val DEFAULT_FALLBACK_MILLIS: Long = 2_500
        /** No wait: the first get follows the create at once. */
        val NONE = PasskeyReadyWait(timeoutMillis = 0, fallbackMillis = 0)
    }
}

/**
 * The credential IDs created and not yet waited for. Pure Kotlin: the adapter supplies the probe (on Android,
 * `prepareGetCredential` with `hasCredentialResults`), tests supply the clock. [pending] is shared by every adapter
 * in the process ([processWide]), so a get through a new adapter instance still waits for a passkey created
 * through another. An entry expires [PENDING_MARGIN_MILLIS] after the timeout (the provider has had its time), and
 * at most [MAX_PENDING] are kept, the oldest dropped first. Two gets naming the same new credential share one wait.
 */
internal class CreatedPasskeys(
    private val timing: PasskeyReadyWait,
    private val pending: MutableMap<String, Pending> = HashMap(),
    private val now: () -> Long = { System.nanoTime() / 1_000_000 },
    private val sleep: suspend (Long) -> Unit = { delay(it) },
    /** Runs the whole wait, each probe included, for at most the given milliseconds. */
    private val bound: suspend (Long, suspend () -> Unit) -> Unit = { millis, block -> withTimeoutOrNull(millis) { block() } },
) {
    /** A created credential: when, and the wait in progress for it (true when it ended, false when cancelled). */
    internal class Pending(val createdAt: Long) { var wait: CompletableDeferred<Boolean>? = null }

    companion object {
        const val PENDING_MARGIN_MILLIS: Long = 60_000
        const val MAX_PENDING: Int = 16
        /** The process's created, not yet offered credentials; guarded by synchronizing on the map itself. */
        val processWide: MutableMap<String, Pending> = HashMap()
    }

    /** Record the credential of a successful create (its WebAuthn registration response JSON). */
    fun created(registrationResponseJson: String) {
        val id = runCatching { keyObject(registrationResponseJson.toByteArray()).string("rawId") }.getOrNull() ?: return
        synchronized(pending) {
            pending[normal(id)] = Pending(now())
            prune()
            while (pending.size > MAX_PENDING) {
                val oldest = pending.entries.filter { it.value.wait == null }.minByOrNull { it.value.createdAt } ?: break
                pending.remove(oldest.key)
            }
        }
    }

    /**
     * Before a get: when its `allowCredentials` names a credential created here and not yet waited for, wait until
     * [probe] says the provider offers it, the timeout passes, or (with no probe, or a probe that fails) the fixed
     * fallback passes. A second get for the same credential joins the first one's wait. Never throws except for
     * cancellation; a cancelled wait leaves the credential pending.
     */
    suspend fun beforeGet(requestJson: String, probe: (suspend () -> Boolean)?) {
        val ids = runCatching {
            keyObject(requestJson.toByteArray()).array("allowCredentials")
                .mapNotNull { (it as? KeyJson.Obj)?.string("id")?.let(::normal) }
        }.getOrNull().orEmpty()
        while (true) {
            val mine = CompletableDeferred<Boolean>()
            // Select and claim under one lock: either join a wait in progress, or own a new one.
            val joined = synchronized(pending) {
                prune()
                val entries = ids.mapNotNull { pending[it] }
                if (entries.isEmpty()) return
                entries.firstNotNullOfOrNull { it.wait } ?: run { entries.forEach { it.wait = mine }; null }
            }
            if (joined != null) {
                if (joined.await()) return
                continue // its owner was cancelled: the credential is still pending, so wait for it here
            }
            try {
                if (probe == null) pause(timing.fallbackMillis) else poll(probe)
            } catch (error: Throwable) {
                synchronized(pending) { pending.values.forEach { if (it.wait === mine) it.wait = null } }
                mine.complete(false)
                throw error
            }
            synchronized(pending) { pending.entries.removeAll { it.value.wait === mine } }
            mine.complete(true)
            return
        }
    }

    private suspend fun poll(probe: suspend () -> Boolean) {
        if (timing.timeoutMillis == 0L) return
        val deadline = now() + timing.timeoutMillis
        bound(timing.timeoutMillis) {
            while (true) {
                val ready = try {
                    probe()
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Exception) {
                    // The provider cannot be asked (for example a missing permission): wait the fixed time instead.
                    pause(minOf(timing.fallbackMillis, (deadline - now()).coerceAtLeast(0)))
                    return@bound
                }
                if (ready) return@bound
                val remaining = deadline - now()
                if (remaining <= 0) return@bound
                sleep(minOf(timing.pollIntervalMillis, remaining))
            }
        }
    }

    /** Drop entries the provider has had its time for; never one with a wait in progress. Hold the lock. */
    private fun prune() {
        val oldest = now() - (maxOf(timing.timeoutMillis, timing.fallbackMillis) + PENDING_MARGIN_MILLIS)
        pending.entries.removeAll { it.value.wait == null && it.value.createdAt < oldest }
    }

    private suspend fun pause(millis: Long) { if (millis > 0) sleep(millis) }

    private fun normal(id: String) = id.trimEnd('=')
}
