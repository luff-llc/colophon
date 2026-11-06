package com.luff.colophon

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.AlgorithmParameters
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/** JCA handles; private keys are never exported. Android hosts can supply Keystore KeyPairs. */
class PlatformKeys(private val signing: KeyPair, private val agreement: KeyPair) : KeyProvider {
    override fun signingPublicKey(): ByteArray = point(signing.public as ECPublicKey)
    override fun agreementPublicKey(): ByteArray = point(agreement.public as ECPublicKey)
    override fun sign(body: ByteArray): ByteArray = providerCall {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(signing.private)
        signature.update(body)
        derToRaw(signature.sign())
    }
    override fun agree(peer: ByteArray): ByteArray = providerCall {
        require(peer.size == 65 && peer[0] == 4.toByte()) { "Expected uncompressed P-256 point" }
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val publicKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(
            ECPoint(BigInteger(1, peer.copyOfRange(1, 33)), BigInteger(1, peer.copyOfRange(33, 65))), parameters))
        KeyAgreement.getInstance("ECDH").apply { init(agreement.private); doPhase(publicKey, true) }.generateSecret()
    }
    companion object {
        /** Software-only generation. Android apps should supply their own Keystore handles. */
        fun software(): PlatformKeys {
            fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return PlatformKeys(pair(), pair())
        }
        private fun scalar(value: BigInteger): ByteArray {
            val bytes = value.toByteArray()
            return ByteArray(32).also { bytes.copyInto(it, maxOf(0, 32 - bytes.size), maxOf(0, bytes.size - 32)) }
        }
        private fun point(key: ECPublicKey) = byteArrayOf(4) + scalar(key.w.affineX) + scalar(key.w.affineY)
        // P-256 DER signatures fit in a short-form sequence (at most 72 bytes).
        private fun derToRaw(der: ByteArray): ByteArray {
            require(der.size in 8..72 && der[0] == 0x30.toByte() && der[1].toInt() == der.size - 2)
            var offset = 2
            fun integer(): ByteArray {
                require(der[offset++].toInt() == 2)
                val length = der[offset++].toInt()
                require(length in 1..33 && offset + length <= der.size)
                val value = BigInteger(1, der.copyOfRange(offset, offset + length))
                offset += length
                require(value.bitLength() <= 256)
                return scalar(value)
            }
            val raw = integer() + integer()
            require(offset == der.size)
            return raw
        }
        private inline fun <T> providerCall(block: () -> T): T = try { block() } catch (error: Exception) {
            throw BindingException.KeyProvider(error.message ?: "Platform key operation failed")
        }
    }
}

fun KeyProvider.publicKeys() = PublicKeys(signingPublicKey(), agreementPublicKey())
