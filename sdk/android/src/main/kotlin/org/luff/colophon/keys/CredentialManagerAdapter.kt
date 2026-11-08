package org.luff.colophon.keys

import android.content.Context
import android.content.pm.PackageManager
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
import java.util.concurrent.CancellationException

/** Thin AndroidX boundary. Supply an Activity context for interactive ceremonies. */
class CredentialManagerAdapter(private val context: Context,
                               private val manager: CredentialManager = CredentialManager.create(context)) : CredentialClient {
    override suspend fun create(requestJson: String): String = ceremony {
        val response = manager.createCredential(context, CreatePublicKeyCredentialRequest(requestJson))
        (response as? CreatePublicKeyCredentialResponse)?.registrationResponseJson
            ?: keyFailure(KeyOutcome.UNSUPPORTED_HERE, "Expected public-key registration")
    }
    override suspend fun get(requestJson: String): String = ceremony {
        val response = manager.getCredential(context, GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson))))
        (response.credential as? PublicKeyCredential)?.authenticationResponseJson
            ?: keyFailure(KeyOutcome.CREDENTIAL_MISSING, "Expected public-key credential")
    }
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
