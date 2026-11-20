package com.luff.colophon

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay

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
 * through another.
 */
internal class CreatedPasskeys(
    private val timing: PasskeyReadyWait,
    private val pending: MutableSet<String> = HashSet(),
    private val now: () -> Long = { System.nanoTime() / 1_000_000 },
    private val sleep: suspend (Long) -> Unit = { delay(it) },
) {
    companion object {
        /** The process's created, not yet offered credentials; guarded by synchronizing on the set itself. */
        val processWide: MutableSet<String> = HashSet()
    }

    /** Record the credential of a successful create (its WebAuthn registration response JSON). */
    fun created(registrationResponseJson: String) {
        val id = runCatching { keyObject(registrationResponseJson.toByteArray()).string("rawId") }.getOrNull() ?: return
        synchronized(pending) { pending.add(normal(id)) }
    }

    /**
     * Before a get: when its `allowCredentials` names a credential created here and not yet waited for, wait until
     * [probe] says the provider offers it, the timeout passes, or (with no probe, or a probe that fails) the fixed
     * fallback passes. Never throws except for cancellation; a cancelled wait leaves the credential pending.
     */
    suspend fun beforeGet(requestJson: String, probe: (suspend () -> Boolean)?) {
        val ids = runCatching {
            keyObject(requestJson.toByteArray()).array("allowCredentials")
                .mapNotNull { (it as? KeyJson.Obj)?.string("id")?.let(::normal) }
        }.getOrNull().orEmpty()
        val waiting = synchronized(pending) { ids.filter { it in pending } }
        if (waiting.isEmpty()) return
        if (probe == null) pause(timing.fallbackMillis) else poll(probe)
        synchronized(pending) { pending.removeAll(waiting.toSet()) }
    }

    private suspend fun poll(probe: suspend () -> Boolean) {
        if (timing.timeoutMillis == 0L) return
        val start = now()
        val deadline = start + timing.timeoutMillis
        while (true) {
            val ready = try {
                probe()
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                // The provider cannot be asked (for example a missing permission): wait the fixed time instead.
                pause(minOf(timing.fallbackMillis, (deadline - now()).coerceAtLeast(0)))
                return
            }
            if (ready) return
            val remaining = deadline - now()
            if (remaining <= 0) return
            sleep(minOf(timing.pollIntervalMillis, remaining))
        }
    }

    private suspend fun pause(millis: Long) { if (millis > 0) sleep(millis) }

    private fun normal(id: String) = id.trimEnd('=')
}
