package com.luff.colophon.session

import com.luff.colophon.KeyDescriptorView
import com.luff.colophon.PublicKeys
import com.luff.colophon.SignForm
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.concurrent.atomic.AtomicInteger

/**
 * A software WebAuthn authenticator for tests: the assertions a platform passkey makes (authenticator data with UP and
 * UV, client data over the core's challenge, a DER signature) and a deterministic PRF. A test double, not a key store.
 */
class TestPasskey(val rp: String = "id.luff.works", val credential: ByteArray = byteArrayOf(1, 2, 3)) : AsyncKeyProvider {
    private val key = P256.generate()
    private val signing = P256.point(key.public as ECPublicKey)
    private val assertions = AtomicInteger()
    val assertCount: Int get() = assertions.get()
    override val form: SignForm get() = SignForm.WEBAUTHN
    override val supportsPrf: Boolean get() = true
    override suspend fun publicKeys() = PublicKeys(signing.copyOf(), ByteArray(0))
    override suspend fun sign(body: ByteArray): ByteArray = throw KeyCustodyException.Unsupported()
    override suspend fun sharedSecret(peer: ByteArray): SecretBytes = throw KeyCustodyException.Unsupported()
    override suspend fun keyDescriptor() = KeyDescriptorView(SignForm.WEBAUTHN, signing.copyOf(), null, rp, credential.copyOf(), listOf(), listOf())
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun prfOutput(salt: ByteArray) = SecretBytes.adopt(sha("test-prf".toByteArray() + salt))
    override suspend fun assert(challenge: String, prfSalt: ByteArray?): KeyAssertion {
        assertions.incrementAndGet()
        val clientData = "{\"challenge\":\"$challenge\",\"origin\":\"https://$rp\",\"type\":\"webauthn.get\"}".toByteArray()
        val authData = sha(rp.toByteArray()) + byteArrayOf(0x05, 0, 0, 0, 0)
        val der = java.security.Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(authData + sha(clientData)); sign() }
        return KeyAssertion(der, authData, clientData, prfSalt?.let { prfOutput(it) })
    }
    override suspend fun prf(salt: ByteArray): SecretBytes? = prfOutput(salt)
}
