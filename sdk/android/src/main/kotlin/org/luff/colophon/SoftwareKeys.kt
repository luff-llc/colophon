package org.luff.colophon

import com.luff.colophon.BindingException
import com.luff.colophon.KeyProvider
import com.luff.colophon.PlatformKeys
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Software P-256 provider for tests and hosts that explicitly opt out of Keystore.
 * [stored] does not touch the file until the first provider call. An existing file that
 * cannot be decoded fails closed and is never replaced.
 */
class SoftwareKeys private constructor(private val load: () -> PlatformKeys) : KeyProvider {
    private val delegate by lazy { load() }

    override fun signingPublicKey(): ByteArray = delegate.signingPublicKey()
    override fun agreementPublicKey(): ByteArray = delegate.agreementPublicKey()
    override fun sign(body: ByteArray): ByteArray = delegate.sign(body)
    override fun agree(peer: ByteArray): ByteArray = delegate.agree(peer)

    companion object {
        private val fileLock = Any()

        fun ephemeral(): SoftwareKeys {
            val signing = generate()
            val agreement = generate()
            return SoftwareKeys { PlatformKeys(signing, agreement) }
        }

        fun stored(file: File): SoftwareKeys = SoftwareKeys {
            synchronized(fileLock) {
                if (file.exists()) {
                    load(file)
                } else {
                    val signing = generate()
                    val agreement = generate()
                    val parent = file.parentFile
                    if (parent != null && !parent.exists() && !parent.mkdirs()) {
                        throw BindingException.KeyProvider("Cannot create ${parent.path}")
                    }
                    AtomicFile.write(encode(signing, agreement), file)
                    PlatformKeys(signing, agreement)
                }
            }
        }

        private fun generate(): KeyPair =
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

        private fun encode(signing: KeyPair, agreement: KeyPair): ByteArray {
            fun sizeOf(pair: KeyPair) = 8 + pair.private.encoded.size + pair.public.encoded.size
            val buffer = ByteBuffer.allocate(sizeOf(signing) + sizeOf(agreement))
            fun put(pair: KeyPair) {
                val private = pair.private.encoded
                val public = pair.public.encoded
                buffer.putInt(private.size)
                buffer.put(private)
                buffer.putInt(public.size)
                buffer.put(public)
            }
            put(signing)
            put(agreement)
            return buffer.array()
        }

        private fun load(file: File): PlatformKeys {
            try {
                val bytes = AtomicFile.read(file, 16 * 1024)
                val buffer = ByteBuffer.wrap(bytes)
                fun chunk(): ByteArray {
                    require(buffer.remaining() >= 4) { "Truncated software key file" }
                    val size = buffer.int
                    require(size in 1..2048 && buffer.remaining() >= size) { "Invalid software key file" }
                    val out = ByteArray(size)
                    buffer.get(out)
                    return out
                }
                val factory = KeyFactory.getInstance("EC")
                fun pair(): KeyPair {
                    val private = factory.generatePrivate(PKCS8EncodedKeySpec(chunk()))
                    val public = factory.generatePublic(X509EncodedKeySpec(chunk()))
                    return KeyPair(public, private)
                }
                val signing = pair()
                val agreement = pair()
                require(!buffer.hasRemaining()) { "Trailing bytes in software key file" }
                return PlatformKeys(signing, agreement)
            } catch (error: BindingException) {
                throw error
            } catch (error: Exception) {
                throw BindingException.KeyProvider(error.message ?: "Corrupt software key file")
            }
        }
    }
}
