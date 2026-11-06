package org.luff.colophon

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.luff.colophon.BindingException
import com.luff.colophon.KeyProvider
import com.luff.colophon.PlatformKeys
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * Non-exportable P-256 signing and agreement keys in Android Keystore.
 * StrongBox is used when the device provides it; otherwise the TEE-backed Keystore.
 * Missing or unreadable existing aliases fail closed and never mint a replacement identity.
 */
class KeystoreKeys private constructor(
    private val delegate: PlatformKeys,
    val usedStrongBox: Boolean,
) : KeyProvider by delegate {
    companion object {
        private const val STORE = "AndroidKeyStore"

        @Suppress("UNUSED_PARAMETER")
        fun openOrCreate(context: Context, aliasPrefix: String): KeystoreKeys {
            val prefix = aliasPrefix.trim()
            require(prefix.isNotEmpty() && prefix.length < 80 && prefix.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }) {
                "Invalid Keystore alias prefix"
            }
            val signingAlias = "$prefix.signing"
            val agreementAlias = "$prefix.agreement"
            val store = KeyStore.getInstance(STORE).apply { load(null) }
            val hasSigning = store.containsAlias(signingAlias)
            val hasAgreement = store.containsAlias(agreementAlias)
            if (hasSigning != hasAgreement) {
                throw BindingException.KeyProvider("Incomplete Keystore identity for $prefix")
            }
            return try {
                if (hasSigning) {
                    KeystoreKeys(PlatformKeys(loadPair(store, signingAlias), loadPair(store, agreementAlias)), strongBoxUsed(store, signingAlias))
                } else {
                    create(signingAlias, agreementAlias)
                }
            } catch (error: BindingException) {
                throw error
            } catch (error: Exception) {
                throw BindingException.KeyProvider(error.message ?: "Keystore operation failed")
            }
        }

        private fun create(signingAlias: String, agreementAlias: String): KeystoreKeys {
            val store = KeyStore.getInstance(STORE).apply { load(null) }
            val strongBox = try {
                generate(signingAlias, KeyProperties.PURPOSE_SIGN, strongBox = true)
                generate(agreementAlias, KeyProperties.PURPOSE_AGREE_KEY, strongBox = true)
                true
            } catch (error: Exception) {
                deleteQuietly(store, signingAlias)
                deleteQuietly(store, agreementAlias)
                if (!isStrongBoxUnavailable(error)) throw error
                try {
                    generate(signingAlias, KeyProperties.PURPOSE_SIGN, strongBox = false)
                    generate(agreementAlias, KeyProperties.PURPOSE_AGREE_KEY, strongBox = false)
                    false
                } catch (fallback: Exception) {
                    deleteQuietly(store, signingAlias)
                    deleteQuietly(store, agreementAlias)
                    throw fallback
                }
            }
            val reloaded = KeyStore.getInstance(STORE).apply { load(null) }
            return KeystoreKeys(
                PlatformKeys(loadPair(reloaded, signingAlias), loadPair(reloaded, agreementAlias)),
                strongBox,
            )
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

        private fun isStrongBoxUnavailable(error: Throwable): Boolean {
            var current: Throwable? = error
            while (current != null) {
                if (current is StrongBoxUnavailableException) return true
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
