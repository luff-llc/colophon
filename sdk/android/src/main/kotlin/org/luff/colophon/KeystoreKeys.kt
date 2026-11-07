package org.luff.colophon

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.luff.colophon.BindingException
import com.luff.colophon.KeyProvider
import com.luff.colophon.PlatformKeys
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.spec.ECGenParameterSpec

/**
 * Non-exportable P-256 signing and agreement keys in Android Keystore.
 * StrongBox is requested first. A [ProviderException] or [InvalidAlgorithmParameterException]
 * (including a StrongBox HAL that rejects [KeyProperties.PURPOSE_AGREE_KEY]) falls back to the TEE.
 * Construction does not touch Keystore. The first provider call, on the session thread, does.
 * An incomplete alias pair fails closed and is left in place. Hardware failure does not mint a
 * software key. Replacing a lost alias pair is refused by the session journal, not by generating
 * a second identity for an existing library.
 */
class KeystoreKeys private constructor(
    private val load: () -> Loaded,
) : KeyProvider {
    private class Loaded(val keys: PlatformKeys, val strongBox: Boolean)
    private val loaded by lazy { load() }

    /** True only after the provider has been materialized and StrongBox generation succeeded. */
    val usedStrongBox: Boolean get() = loaded.strongBox

    override fun signingPublicKey(): ByteArray = loaded.keys.signingPublicKey()
    override fun agreementPublicKey(): ByteArray = loaded.keys.agreementPublicKey()
    override fun sign(body: ByteArray): ByteArray = loaded.keys.sign(body)
    override fun agree(peer: ByteArray): ByteArray = loaded.keys.agree(peer)

    companion object {
        private const val STORE = "AndroidKeyStore"

        @Suppress("UNUSED_PARAMETER")
        fun openOrCreate(context: Context, aliasPrefix: String): KeystoreKeys {
            val prefix = aliasPrefix.trim()
            require(prefix.isNotEmpty() && prefix.length < 80 && prefix.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }) {
                "Invalid Keystore alias prefix"
            }
            return KeystoreKeys { materialize(prefix) }
        }

        private fun materialize(prefix: String): Loaded {
            return try {
                val signingAlias = "$prefix.signing"
                val agreementAlias = "$prefix.agreement"
                val store = KeyStore.getInstance(STORE).apply { load(null) }
                val hasSigning = store.containsAlias(signingAlias)
                val hasAgreement = store.containsAlias(agreementAlias)
                if (hasSigning != hasAgreement) {
                    throw BindingException.KeyProvider("Incomplete Keystore identity for $prefix")
                }
                if (hasSigning) {
                    Loaded(
                        PlatformKeys(loadPair(store, signingAlias), loadPair(store, agreementAlias)),
                        strongBoxUsed(store, signingAlias),
                    )
                } else {
                    create(signingAlias, agreementAlias)
                }
            } catch (error: BindingException) {
                throw error
            } catch (error: Exception) {
                throw BindingException.KeyProvider(error.message ?: "Keystore operation failed")
            }
        }

        private fun create(signingAlias: String, agreementAlias: String): Loaded {
            val store = KeyStore.getInstance(STORE).apply { load(null) }
            val strongBox = generateIdentity(
                signingAlias,
                agreementAlias,
                generate = { alias, purpose, strong -> generate(alias, purpose, strong) },
                deletePartial = {
                    deleteQuietly(store, signingAlias)
                    deleteQuietly(store, agreementAlias)
                },
            )
            val reloaded = KeyStore.getInstance(STORE).apply { load(null) }
            return Loaded(
                PlatformKeys(loadPair(reloaded, signingAlias), loadPair(reloaded, agreementAlias)),
                strongBox,
            )
        }

        /**
         * Returns whether the identity is StrongBox-backed. Deletes aliases this attempt created
         * before falling back or rethrowing. An exception that is not a StrongBox/provider
         * capability failure is not retried on the TEE.
         */
        internal fun generateIdentity(
            signingAlias: String,
            agreementAlias: String,
            generate: (alias: String, purpose: Int, strongBox: Boolean) -> Unit,
            deletePartial: () -> Unit,
        ): Boolean {
            return try {
                generate(signingAlias, KeyProperties.PURPOSE_SIGN, true)
                generate(agreementAlias, KeyProperties.PURPOSE_AGREE_KEY, true)
                true
            } catch (error: Exception) {
                deletePartial()
                if (!isStrongBoxUnavailable(error)) throw error
                try {
                    generate(signingAlias, KeyProperties.PURPOSE_SIGN, false)
                    generate(agreementAlias, KeyProperties.PURPOSE_AGREE_KEY, false)
                    false
                } catch (fallback: Exception) {
                    deletePartial()
                    throw fallback
                }
            }
        }

        private fun generate(alias: String, purpose: Int, strongBox: Boolean) {
            val builder = KeyGenParameterSpec.Builder(alias, purpose)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setInvalidatedByBiometricEnrollment(false)
            if (purpose and KeyProperties.PURPOSE_SIGN != 0) {
                builder.setDigests(KeyProperties.DIGEST_SHA256)
            }
            if (strongBox) builder.setIsStrongBoxBacked(true)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, STORE).apply {
                initialize(builder.build())
                generateKeyPair()
            }
        }

        private fun loadPair(store: KeyStore, alias: String): KeyPair {
            val private = store.getKey(alias, null) as? PrivateKey
                ?: throw BindingException.KeyProvider("Missing Keystore private key $alias")
            val public = store.getCertificate(alias)?.publicKey
                ?: throw BindingException.KeyProvider("Missing Keystore certificate $alias")
            return KeyPair(public, private)
        }

        private fun strongBoxUsed(store: KeyStore, alias: String): Boolean {
            val key = store.getKey(alias, null) ?: return false
            return try {
                val factory = KeyFactory.getInstance(key.algorithm, STORE)
                val info = factory.getKeySpec(key, KeyInfo::class.java)
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } catch (_: Exception) {
                false
            }
        }

        internal fun isStrongBoxUnavailable(error: Throwable): Boolean {
            var current: Throwable? = error
            while (current != null) {
                if (current is ProviderException || current is InvalidAlgorithmParameterException) return true
                if (current.javaClass.name.contains("StrongBoxUnavailable")) return true
                val message = current.message?.lowercase().orEmpty()
                if ("strongbox" in message && ("unavailable" in message || "not available" in message)) return true
                current = current.cause
            }
            return false
        }

        private fun deleteQuietly(store: KeyStore, alias: String) {
            try {
                if (store.containsAlias(alias)) store.deleteEntry(alias)
            } catch (_: Exception) {
            }
        }
    }
}
