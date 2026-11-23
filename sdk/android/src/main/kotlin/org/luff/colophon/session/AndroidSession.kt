package org.luff.colophon.session

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.luff.colophon.KeyDescriptorView
import com.luff.colophon.PublicKeys
import com.luff.colophon.SignForm
import com.luff.colophon.session.AsyncKeyProvider
import com.luff.colophon.session.DeviceSecretStore
import com.luff.colophon.session.FolderMedium
import com.luff.colophon.session.Json
import com.luff.colophon.session.KeyAssertion
import com.luff.colophon.session.KeyCustodyException
import com.luff.colophon.session.P256
import com.luff.colophon.session.SecretBytes
import com.luff.colophon.session.StorageException
import com.luff.colophon.session.asAsync
import com.luff.colophon.session.list
import com.luff.colophon.session.string
import org.luff.colophon.KeystoreKeys
import org.luff.colophon.KeystorePresence
import org.luff.colophon.keys.PasskeyProvider
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The Android pieces of the 0.5 session (`com.luff.colophon.session`): where an app keeps the account's records and the
 * session's private state, its member key in Android Keystore, the device key that seals saved state, and the person's
 * passkey through Credential Manager.
 */
object AndroidSession {
    /** The account's record store: app-private, outside backups (`noBackupFilesDir`). One process per library. */
    fun medium(context: Context, library: String = "library"): FolderMedium =
        FolderMedium(File(context.noBackupFilesDir, "colophon/${check(library)}/records"))

    /** The session's private directory (journal, sealed saved state), beside the records. */
    fun privateDirectory(context: Context, library: String = "library"): File =
        File(context.noBackupFilesDir, "colophon/${check(library)}/session").apply { mkdirs() }

    /**
     * This app's member key: a non-exportable P-256 signing key and agreement key in Android Keystore (StrongBox
     * first, then the TEE; API 31+ for the agreement key), from the 0.4 `KeystoreKeys`. The first use, not this call,
     * touches Keystore; the session calls it off the main thread.
     */
    fun memberKeys(context: Context, aliasPrefix: String, presence: KeystorePresence? = null): AsyncKeyProvider =
        KeystoreKeys.openOrCreate(context, aliasPrefix, presence).asAsync()

    /** The device key store, wrapped by an Android Keystore AES key, in app-private storage. */
    fun deviceSecrets(context: Context, alias: String = "org.luff.colophon.device-key"): DeviceSecretStore =
        KeystoreDeviceSecrets(File(context.noBackupFilesDir, "colophon/device-keys"), KeystoreDeviceSecrets.androidKeystoreKey(alias))

    private fun check(library: String): String {
        require(library.isNotEmpty() && library.length <= 64 && library.all { it.isLetterOrDigit() || it == '-' || it == '_' }) { "invalid library name" }
        return library
    }
}

/**
 * The 32-byte device key that seals saved state (spec §17.2), one per account, kept as `iv || AES-256-GCM(key)` in an
 * app-private file and unwrapped by `wrappingKey` (an Android Keystore key that never leaves the device). A cache key,
 * not an identity: if the Keystore key is lost the file no longer opens, a fresh key is made, and the engine replays
 * the history instead of resuming.
 */
class KeystoreDeviceSecrets(private val directory: File, private val wrappingKey: () -> SecretKey) : DeviceSecretStore {
    private fun file(account: String): File {
        require(account.length == 64 && account.all { it in '0'..'9' || it in 'a'..'f' }) { "an account ID is 64 hex" }
        return File(directory, "$account.key")
    }

    @Synchronized override fun key(account: String): SecretBytes {
        val f = file(account)
        if (f.isFile) {
            val stored = f.readBytes()
            val opened = try { open(stored) } catch (_: Exception) { null }
            if (opened != null && opened.size == 32) return SecretBytes.adopt(opened)
            opened?.fill(0)
        }
        val fresh = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            directory.mkdirs()
            val tmp = File(directory, ".${f.name}.tmp")
            FileOutputStream(tmp).use { it.write(seal(fresh)); it.fd.sync() }
            if (!tmp.renameTo(f)) throw StorageException.Unavailable("cannot store the device key")
        } catch (e: Exception) {
            fresh.fill(0)
            throw if (e is StorageException) e else StorageException.Unavailable("cannot store the device key: ${e.message}")
        }
        return SecretBytes.adopt(fresh)
    }

    @Synchronized override fun remove(account: String) { file(account).delete() }

    private fun seal(key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        return cipher.iv + cipher.doFinal(key)
    }
    private fun open(stored: ByteArray): ByteArray {
        require(stored.size == 12 + 32 + 16) { "not a sealed device key" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(128, stored.copyOfRange(0, 12)))
        return cipher.doFinal(stored.copyOfRange(12, stored.size))
    }

    companion object {
        /** An AES-256-GCM key in Android Keystore under `alias`, created on first use (randomized IVs, no user authentication). */
        fun androidKeystoreKey(alias: String): () -> SecretKey = {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (store.getKey(alias, null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build())
                generateKey()
            }
        }
    }
}

/**
 * The person's passkey as a 0.5 controller: Credential Manager assertions through the 0.4 `PasskeyProvider` (one
 * credential allowed per get, user verification required), with the WebAuthn PRF extension for slots.
 *
 * Implemented: signing steps (an assertion over the step's challenge), PRF requests at creation and for a new slot
 * (one assertion evaluating the request's salt; `results.first` is the output), and opening a PRF slot (an assertion
 * over a fresh random challenge evaluating the slot's salt). A missing PRF result is `KeyCustodyException.Unsupported`,
 * never a fallback secret. Not implemented: the Swift move's two-salt ceremony (one assertion evaluating the new salt
 * first and the old second), ECDH and raw signatures (a passkey has neither). Proven only with a synthetic
 * Credential Manager client in a JVM test; not run against Credential Manager on a device or emulator.
 *
 * `authorityOrigins` is the controller's `authorityOrigins` (spec §18: the authority-ceremony origin, the bare `rp`
 * origin and the app's platform origin, `appPasskeyOrigins(context)`).
 */
class PasskeyController(private val passkey: PasskeyProvider, private val authorityOrigins: List<String> = listOf()) : AsyncKeyProvider {
    private val descriptor = Json.obj(passkey.descriptor().toString(Charsets.UTF_8)) ?: throw IllegalArgumentException("not a passkey descriptor")
    private val signing = Base64.getDecoder().decode(descriptor.string("signing") ?: throw IllegalArgumentException("no signing point"))
    override val form: SignForm get() = SignForm.WEBAUTHN
    override val supportsPrf: Boolean get() = true
    override suspend fun publicKeys(): PublicKeys = PublicKeys(signing.copyOf(), ByteArray(0))
    override suspend fun keyDescriptor(): KeyDescriptorView = KeyDescriptorView(
        SignForm.WEBAUTHN, signing.copyOf(), null, descriptor.string("rp"),
        Base64.getDecoder().decode(descriptor.string("credential") ?: throw IllegalArgumentException("no credential")),
        origins, authorityOrigins.distinct().sorted())
    /**
     * `origins`: the registration's own, plus every platform origin among `authorityOrigins` (`android:apk-key-hash:...`):
     * the core admits a platform authority origin only when `origins` names it too (spec §3.1).
     */
    private val origins: List<String> get() =
        ((descriptor.list("origins") ?: listOf()).filterIsInstance<String>() + authorityOrigins.filter { !it.startsWith("https://") }).distinct().sorted()
    /** A WebAuthn assertion is required so its authenticator data and client data are kept: no raw signature. */
    override suspend fun sign(body: ByteArray): ByteArray = throw KeyCustodyException.Unsupported()
    override suspend fun sharedSecret(peer: ByteArray): SecretBytes = throw KeyCustodyException.Unsupported()
    override suspend fun assert(challenge: String, prfSalt: ByteArray?): KeyAssertion {
        val r = passkey.assert(challenge, prfSalt)
        return KeyAssertion(r.signature, r.authenticatorData, r.clientData, r.prf?.let { SecretBytes.adopt(it) })
    }
    override suspend fun prf(salt: ByteArray): SecretBytes? =
        assert(P256.base64url(ByteArray(32).also(SecureRandom()::nextBytes)), salt).prf
}

