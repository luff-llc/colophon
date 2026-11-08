package org.luff.colophon.keys

import com.luff.colophon.KeyForm
import com.luff.colophon.KeyJson
import com.luff.colophon.WebauthnResult
import com.luff.colophon.keyObject
import com.luff.colophon.keyQuote
import com.luff.colophon.parseRegistration
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Suspends for platform UI. Implementations return Credential Manager's original JSON. */
interface CredentialClient {
    /** Perform CreatePublicKeyCredentialRequest. */
    suspend fun create(requestJson: String): String
    /** Perform GetPublicKeyCredentialOption, preserving extension outputs. */
    suspend fun get(requestJson: String): String
}

/**
 * Async passkey controller for the native begin/finish APIs. It deliberately does not block
 * Credential Manager UI inside W5's synchronous ControllerProvider callback.
 */
class PasskeyProvider private constructor(descriptor: ByteArray, private val credentials: CredentialClient) {
    private val key = descriptor.copyOf()
    private val fields = keyObject(key)
    private val rp = required(fields, "rp")
    private val credential = Base64.getDecoder().decode(required(fields, "credential"))
    /** The authority signature form. */
    val form: KeyForm get() = KeyForm.WEBAUTHN
    /** Descriptor parsed by the core; add this app's origin to the controller before publication. */
    fun descriptor(): ByteArray = key.copyOf()
    /** Public signing point, for selecting native signing steps. */
    fun signingPublicKey(): ByteArray = Base64.getDecoder().decode(required(fields, "signing"))

    /** Exact core challenge; every get allows only this one credential and requires UV. */
    suspend fun assert(challenge: String, prfSalt: ByteArray? = null): WebauthnResult {
        require(prfSalt == null || prfSalt.size == 32) { "PRF salt must be 32 bytes" }
        val extension = prfSalt?.let { ",\"extensions\":{\"prf\":{\"eval\":{\"first\":\"${url(it)}\"}}}" }.orEmpty()
        val request = """{"challenge":${keyQuote(challenge)},"rpId":${keyQuote(rp)},"allowCredentials":[{"type":"public-key","id":"${url(credential)}"}],"userVerification":"required"$extension}"""
        val result = keyObject(keyCall { credentials.get(request) }.toByteArray())
        if (!decode(required(result, "rawId")).contentEquals(credential)) keyFailure(KeyOutcome.CREDENTIAL_MISSING, "Unexpected credential")
        val response = obj(result, "response")
        val output = if (prfSalt == null) null else {
            val first = optionalObj(optionalObj(optionalObj(result, "clientExtensionResults"), "prf"), "results")?.string("first")
                ?: keyFailure(KeyOutcome.UNSUPPORTED_HERE, "WebAuthn PRF missing results.first")
            decode(first).also { if (it.size != 32) keyFailure(KeyOutcome.UNSUPPORTED_HERE, "WebAuthn PRF result must be 32 bytes") }
        }
        return WebauthnResult(decode(required(response, "signature")), decode(required(response, "authenticatorData")),
            decode(required(response, "clientDataJSON")), output)
    }

    companion object {
        /** Register ES256. No registration-time PRF output is retained or used. */
        suspend fun register(rp: String, rpName: String, userID: ByteArray, userName: String, displayName: String,
                             credentials: CredentialClient, challenge: ByteArray = ByteArray(32).also(SecureRandom()::nextBytes)): PasskeyProvider {
            val request = """{"rp":{"id":${keyQuote(rp)},"name":${keyQuote(rpName)}},"user":{"id":"${url(userID)}","name":${keyQuote(userName)},"displayName":${keyQuote(displayName)}},"challenge":"${url(challenge)}","pubKeyCredParams":[{"type":"public-key","alg":-7}],"attestation":"none","authenticatorSelection":{"userVerification":"required","residentKey":"preferred"},"extensions":{"prf":{}}}"""
            val result = keyObject(keyCall { credentials.create(request) }.toByteArray())
            val attestation = decode(required(obj(result, "response"), "attestationObject"))
            val key = parseRegistration(attestation, rp)
            if (!decode(required(result, "rawId")).contentEquals(Base64.getDecoder().decode(required(keyObject(key), "credential")))) {
                keyFailure(KeyOutcome.CREDENTIAL_MISSING, "Registration credential does not match attestation")
            }
            return PasskeyProvider(key, credentials)
        }

        /** Restore the core-validated descriptor persisted by the host, without registering again. */
        fun restore(descriptor: ByteArray, credentials: CredentialClient): PasskeyProvider {
            require(required(keyObject(descriptor), "form") == "webauthn") { "Expected WebAuthn descriptor" }
            return PasskeyProvider(descriptor, credentials)
        }
    }
}

/** SHA-256 of the DER APK signing certificate, encoded as the exact Android WebAuthn origin. */
fun apkKeyHashOrigin(signingCertificate: ByteArray): String =
    "android:apk-key-hash:" + url(MessageDigest.getInstance("SHA-256").digest(signingCertificate))

internal fun url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
private fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
private fun required(value: KeyJson.Obj, name: String): String = value.string(name)
    ?: throw com.luff.colophon.BindingException.InvalidData("Missing $name")
private fun obj(value: KeyJson.Obj, name: String): KeyJson.Obj = optionalObj(value, name)
    ?: throw com.luff.colophon.BindingException.InvalidData("Missing $name")
private fun optionalObj(value: KeyJson.Obj?, name: String): KeyJson.Obj? = value?.fields?.get(name) as? KeyJson.Obj
