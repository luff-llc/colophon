package org.luff.colophon.keys

import com.luff.colophon.BindingException
import java.util.concurrent.CancellationException

/** Portable outcomes carried in BindingException.KeyProvider across the W5 callback. */
enum class KeyOutcome(val value: String) {
    CANCELLED("cancelled"), PRESENCE_FAILED("presenceFailed"), UNSUPPORTED_HERE("unsupportedHere"),
    CREDENTIAL_MISSING("credentialMissing"), HARDWARE_UNAVAILABLE("hardwareUnavailable"),
}

/** Read a portable provider outcome, including after a trip across the native callback. */
fun keyOutcome(error: Throwable): KeyOutcome? = (error as? BindingException.KeyProvider)?.detail?.let { detail ->
    KeyOutcome.entries.firstOrNull { detail.startsWith("${it.value}:") }
}

internal fun keyFailure(outcome: KeyOutcome, detail: String): Nothing =
    throw BindingException.KeyProvider("${outcome.value}: $detail")

internal inline fun <T> keyCall(block: () -> T): T = try { block() } catch (error: Exception) {
    if (keyOutcome(error) != null) throw error
    var cause: Throwable? = error
    var outcome = KeyOutcome.HARDWARE_UNAVAILABLE
    while (cause != null) {
        when {
            cause is CancellationException -> { outcome = KeyOutcome.CANCELLED; break }
            cause.javaClass.simpleName in setOf("UserNotAuthenticatedException", "KeyPermanentlyInvalidatedException") -> {
                outcome = KeyOutcome.PRESENCE_FAILED; break
            }
        }
        cause = cause.cause
    }
    keyFailure(outcome, error.message ?: "Key operation failed")
}
