package org.luff.colophon.keys

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.spec.ECGenParameterSpec

/** Android Keystore adapter. No software key generation or export is permitted. */
class AndroidOwnerKeyStore : OwnerKeyStore {
    override val apiLevel: Int get() = Build.VERSION.SDK_INT
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    override fun load(alias: String): StoredOwnerKey? {
        val store = store()
        if (!store.containsAlias(alias)) return null
        val private = store.getKey(alias, null) as? PrivateKey
            ?: keyFailure(KeyOutcome.CREDENTIAL_MISSING, "Missing owner private key")
        val public = store.getCertificate(alias)?.publicKey
            ?: keyFailure(KeyOutcome.CREDENTIAL_MISSING, "Missing owner certificate")
        val info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(private, KeyInfo::class.java)
        if (!info.isUserAuthenticationRequired || info.userAuthenticationValidityDurationSeconds <= 0) {
            keyFailure(KeyOutcome.PRESENCE_FAILED, "Owner key requires a positive authentication validity window")
        }
        if (info.securityLevel != KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT &&
            info.securityLevel != KeyProperties.SECURITY_LEVEL_STRONGBOX) keyFailure(KeyOutcome.HARDWARE_UNAVAILABLE, "Owner key is not hardware-backed")
        return StoredOwnerKey(KeyPair(public, private), OwnerPresence(info.userAuthenticationValidityDurationSeconds, info.userAuthenticationType),
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX)
    }
    override fun generate(alias: String, usage: OwnerKeyUsage, strongBox: Boolean, presence: OwnerPresence): StoredOwnerKey {
        val purpose = if (usage == OwnerKeyUsage.SIGN) KeyProperties.PURPOSE_SIGN else KeyProperties.PURPOSE_AGREE_KEY
        val builder = KeyGenParameterSpec.Builder(alias, purpose)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(presence.validitySeconds, presence.authenticationTypes)
            .setIsStrongBoxBacked(strongBox)
        if (usage == OwnerKeyUsage.SIGN) builder.setDigests(KeyProperties.DIGEST_SHA256)
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(builder.build()); generateKeyPair()
            }
        } catch (error: ProviderException) {
            if (strongBox) throw StrongBoxUnavailableException(error) else throw error
        } catch (error: InvalidAlgorithmParameterException) {
            if (strongBox) throw StrongBoxUnavailableException(error) else throw error
        }
        return load(alias) ?: keyFailure(KeyOutcome.HARDWARE_UNAVAILABLE, "Generated owner key missing")
    }
    override fun delete(alias: String) { store().deleteEntry(alias) }
}
