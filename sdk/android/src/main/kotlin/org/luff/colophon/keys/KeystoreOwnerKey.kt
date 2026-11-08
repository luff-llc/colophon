package org.luff.colophon.keys

import android.security.keystore.KeyProperties
import com.luff.colophon.ControllerProvider
import com.luff.colophon.KeyForm
import com.luff.colophon.KeyProvider
import com.luff.colophon.WebauthnResult
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement

/** Positive validity window: the host authenticates once before an action's signing rounds. */
data class OwnerPresence(val validitySeconds: Int = 30,
                         val authenticationTypes: Int = KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL) {
    init {
        require(validitySeconds > 0) { "Authentication validity must be positive" }
        require(authenticationTypes != 0 && authenticationTypes and
            (KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL).inv() == 0)
    }
}
/** Separate Android Keystore purposes; agreement requires API 31+. */
enum class OwnerKeyUsage { SIGN, AGREE }
/** Loaded opaque JCA handles and their actual persisted authentication/hardware policy. */
data class StoredOwnerKey(val pair: KeyPair, val presence: OwnerPresence, val strongBox: Boolean)
/** Capability failure permitting retry in the platform TEE, never software. */
class StrongBoxUnavailableException(cause: Throwable? = null) : Exception("StrongBox unavailable", cause)

/** Injectable Keystore boundary. load must fail for a present but inaccessible alias. */
interface OwnerKeyStore {
    /** Android API level, checked before loading or generating keys. */
    val apiLevel: Int
    /** Null means absent, never an inaccessible or invalidated key. */
    fun load(alias: String): StoredOwnerKey?
    /** Generate a non-exportable P-256 key with this purpose and authentication policy. */
    fun generate(alias: String, usage: OwnerKeyUsage, strongBox: Boolean, presence: OwnerPresence): StoredOwnerKey
    /** Delete only an alias created by a failed creation attempt. */
    fun delete(alias: String)
}

/**
 * Raw owner controller, separate from the content member. Both independent P-256 private keys
 * stay in Android Keystore. Authenticate through BiometricPrompt/device credentials before an
 * action; the positive validity window covers its signing and ECDH rounds.
 */
class KeystoreOwnerKey private constructor(private val signing: StoredOwnerKey, private val agreement: StoredOwnerKey) : ControllerProvider, KeyProvider {
    /** True when both keys reside in StrongBox; otherwise custody is Android Keystore/TEE. */
    val usedStrongBox: Boolean get() = signing.strongBox && agreement.strongBox
    /** Persisted authentication validity shared by both keys. */
    val presence: OwnerPresence get() = signing.presence
    override fun form(): KeyForm = KeyForm.RAW
    override fun signingPublicKey(): ByteArray = point(signing.pair.public as ECPublicKey)
    override fun agreementPublicKey(): ByteArray = point(agreement.pair.public as ECPublicKey)
    override fun descriptor(): ByteArray =
        """{"form":"raw","signing":"${base64(signingPublicKey())}","agreement":"${base64(agreementPublicKey())}"}""".toByteArray()
    override fun sign(body: ByteArray): ByteArray = keyCall {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(signing.pair.private)
        signer.update(body)
        rawSignature(signer.sign())
    }
    override fun agree(peer: ByteArray): ByteArray = keyCall {
        require(peer.size == 65 && peer[0] == 4.toByte()) { "Expected P-256 point" }
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val public = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(
            ECPoint(BigInteger(1, peer.copyOfRange(1, 33)), BigInteger(1, peer.copyOfRange(33, 65))), params))
        val private = agreement.pair.private
        val ka = if (private.javaClass.name.contains("AndroidKeyStore")) KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
            else KeyAgreement.getInstance("ECDH")
        ka.init(private)
        ka.doPhase(public, true)
        val secret = ka.generateSecret()
        when {
            secret.size == 32 -> secret
            secret.size in 1..31 -> ByteArray(32 - secret.size) + secret
            secret.size == 33 && secret[0] == 0.toByte() -> secret.copyOfRange(1, 33)
            else -> keyFailure(KeyOutcome.HARDWARE_UNAVAILABLE, "Invalid P-256 ECDH output")
        }
    }
    override fun assert(challenge: String, prfSalt: ByteArray?): WebauthnResult =
        keyFailure(KeyOutcome.UNSUPPORTED_HERE, "Raw keys do not provide WebAuthn assertions")

    companion object {
        /** Open a dedicated owner alias pair. Existing partial/lost keys are never replaced. */
        @Synchronized
        fun openOrCreate(aliasPrefix: String, presence: OwnerPresence = OwnerPresence(), store: OwnerKeyStore = AndroidOwnerKeyStore()): KeystoreOwnerKey = keyCall {
            require(aliasPrefix.isNotEmpty() && aliasPrefix.length < 80 && aliasPrefix.all { it.isLetterOrDigit() || it in "._-" }) { "Invalid owner alias prefix" }
            if (store.apiLevel < 31) keyFailure(KeyOutcome.UNSUPPORTED_HERE, "Keystore agreement requires API 31+")
            val signingAlias = "$aliasPrefix.owner.signing"
            val agreementAlias = "$aliasPrefix.owner.agreement"
            val signing = store.load(signingAlias)
            val agreement = store.load(agreementAlias)
            if ((signing == null) != (agreement == null)) keyFailure(KeyOutcome.CREDENTIAL_MISSING, "Incomplete owner alias pair")
            val keys = if (signing != null && agreement != null) signing to agreement else {
                fun generate(strong: Boolean): Pair<StoredOwnerKey, StoredOwnerKey> {
                    try {
                        return store.generate(signingAlias, OwnerKeyUsage.SIGN, strong, presence) to
                            store.generate(agreementAlias, OwnerKeyUsage.AGREE, strong, presence)
                    } catch (error: Exception) {
                        // Cleanup failures stop the fallback, preserving evidence of an incomplete pair.
                        store.delete(signingAlias)
                        store.delete(agreementAlias)
                        throw error
                    }
                }
                try { generate(true) } catch (_: StrongBoxUnavailableException) { generate(false) }
            }
            if (keys.first.presence != presence || keys.second.presence != presence) keyFailure(KeyOutcome.PRESENCE_FAILED, "Existing owner authentication policy differs")
            val result = KeystoreOwnerKey(keys.first, keys.second)
            if (result.signingPublicKey().contentEquals(result.agreementPublicKey())) keyFailure(KeyOutcome.HARDWARE_UNAVAILABLE, "Owner signing and agreement keys must differ")
            result
        }
    }
}
private fun base64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
private fun coordinate(value: BigInteger): ByteArray {
    val bytes = value.toByteArray()
    require(bytes.size <= 33)
    return ByteArray(32).also { bytes.copyInto(it, maxOf(0, 32 - bytes.size), maxOf(0, bytes.size - 32)) }
}
private fun point(public: ECPublicKey): ByteArray = byteArrayOf(4) + coordinate(public.w.affineX) + coordinate(public.w.affineY)
private fun rawSignature(der: ByteArray): ByteArray {
    require(der.size in 8..72 && der[0] == 0x30.toByte() && der[1].toInt() == der.size - 2)
    var offset = 2
    fun scalar(): ByteArray {
        require(offset + 2 <= der.size && der[offset++] == 2.toByte())
        val length = der[offset++].toInt()
        require(length in 1..33 && offset + length <= der.size)
        val value = BigInteger(1, der.copyOfRange(offset, offset + length))
        offset += length
        require(value.signum() > 0 && value.bitLength() <= 256)
        return coordinate(value)
    }
    val raw = scalar() + scalar()
    require(offset == der.size)
    return raw
}
