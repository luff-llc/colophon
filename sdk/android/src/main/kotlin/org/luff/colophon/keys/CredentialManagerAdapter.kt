package org.luff.colophon.keys

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.*
import androidx.credentials.exceptions.domerrors.*
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import com.luff.colophon.CreatedPasskeys
import com.luff.colophon.PasskeyReadyWait
import java.util.concurrent.CancellationException

/**
 * Thin AndroidX boundary. Supply an Activity context for interactive ceremonies.
 *
 * Some providers (Google Password Manager) save a new passkey asynchronously, so a get right after a create finds
 * nothing. Before the first get for a passkey created in this process (through any adapter), it waits per
 * [readyWait]: on Android 14 and later it polls `prepareGetCredential` without UI until the provider offers the
 * credential (this needs `CREDENTIAL_MANAGER_QUERY_CANDIDATE_CREDENTIALS`, which the library's manifest declares);
 * before 14 it waits the fixed fallback. A get for any other passkey is never delayed.
 */
class CredentialManagerAdapter(private val context: Context,
                               private val manager: CredentialManager = CredentialManager.create(context),
                               readyWait: PasskeyReadyWait = PasskeyReadyWait()) : CredentialClient {
    private val created = CreatedPasskeys(readyWait, CreatedPasskeys.processWide)

    override suspend fun create(requestJson: String): String = ceremony {
        val response = manager.createCredential(context, CreatePublicKeyCredentialRequest(requestJson))
        (response as? CreatePublicKeyCredentialResponse)?.registrationResponseJson
            ?: keyFailure(KeyOutcome.UNSUPPORTED_HERE, "Expected public-key registration")
    }.also(created::created)
    override suspend fun get(requestJson: String): String {
        // Outside the ceremony, so a cancelled caller sees its own cancellation, not a key failure.
        created.beforeGet(requestJson, readyProbe(requestJson))
        return ceremony {
            val response = manager.getCredential(context, getRequest(requestJson))
            (response.credential as? PublicKeyCredential)?.authenticationResponseJson
                ?: keyFailure(KeyOutcome.CREDENTIAL_MISSING, "Expected public-key credential")
        }
    }
    private fun getRequest(requestJson: String) = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson)))
    /** No UI: does the provider offer a credential for this get yet? Null before Android 14. */
    private fun readyProbe(requestJson: String): (suspend () -> Boolean)? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) ({ offers(requestJson) }) else null
    /**
     * Asks with `preferImmediatelyAvailableCredentials`, documented as not "falling back to discovering remote
     * options", so that the hybrid "use another device" entry, which satisfied a plain probe at once on a tested
     * phone, should not count. Whether `hasCredentialResults` honours it is not yet proven on a device.
     */
    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private suspend fun offers(requestJson: String): Boolean =
        manager.prepareGetCredential(GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson)),
                                                          preferImmediatelyAvailableCredentials = true))
            .hasCredentialResults(PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL)
    private suspend fun <T> ceremony(block: suspend () -> T): T = try { block() } catch (error: Exception) {
        if (keyOutcome(error) != null) throw error
        val dom = when (error) {
            is CreatePublicKeyCredentialDomException -> error.domError
            is GetPublicKeyCredentialDomException -> error.domError
            else -> null
        }
        val outcome = when {
            error is CancellationException || error is CreateCredentialCancellationException || error is GetCredentialCancellationException || dom is AbortError -> KeyOutcome.CANCELLED
            error is NoCredentialException -> KeyOutcome.CREDENTIAL_MISSING
            error is CreateCredentialUnsupportedException || error is GetCredentialUnsupportedException ||
                error is CreateCredentialProviderConfigurationException || error is GetCredentialProviderConfigurationException ||
                error is CreateCredentialNoCreateOptionException || dom is NotSupportedError -> KeyOutcome.UNSUPPORTED_HERE
            error is CreateCredentialInterruptedException || error is GetCredentialInterruptedException ||
                dom is NotAllowedError || dom is SecurityError -> KeyOutcome.PRESENCE_FAILED
            else -> KeyOutcome.HARDWARE_UNAVAILABLE
        }
        keyFailure(outcome, error.message ?: "Credential Manager failed")
    }
}

/** Current APK signer origins, sorted for a controller's spec §2.2 origins allowlist. */
fun appPasskeyOrigins(context: Context): List<String> = keyCall {
    val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
    val signers = info.signingInfo?.apkContentsSigners
        ?: keyFailure(KeyOutcome.HARDWARE_UNAVAILABLE, "APK signing certificates unavailable")
    if (signers.isEmpty()) keyFailure(KeyOutcome.HARDWARE_UNAVAILABLE, "APK signing certificates unavailable")
    signers.map { apkKeyHashOrigin(it.toByteArray()) }.distinct().sorted()
}
