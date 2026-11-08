package com.luff.colophon

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Adapts a raw controller's separate signing and agreement handles to the controller interface. */
class RawControllerProvider(private val keys: KeyProvider) : ControllerProvider {
    override fun descriptor(): ByteArray = rawDescriptor(keys.publicKeys())
    override fun form(): KeyForm = KeyForm.RAW
    override fun sign(body: ByteArray): ByteArray = keys.sign(body)
    override fun agree(peer: ByteArray): ByteArray = keys.agree(peer)
    override fun assert(challenge: String, prfSalt: ByteArray?): WebauthnResult =
        throw BindingException.KeyProvider("Raw controllers do not provide WebAuthn assertions")
}

/** Stable controller ID, derived from the descriptor's signing point. */
fun ControllerProvider.controllerID(): String = keyID(controllerPublic().signing)

// Signing and agreement points from the external provider; the core validates protocol use.
internal fun ControllerProvider.controllerPublic(): PublicKeys {
    val descriptor = keyObject(descriptor())
    val signing = descriptor.string("signing") ?: throw BindingException.InvalidData("Missing signing key")
    return PublicKeys(Base64.getDecoder().decode(signing), descriptor.string("agreement")?.let { Base64.getDecoder().decode(it) } ?: byteArrayOf())
}

internal fun keyID(signing: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(signing)
    .take(16).joinToString("") { "%02x".format(it.toInt() and 255) }

internal fun rawDescriptor(keys: PublicKeys): ByteArray =
    """{"form":"raw","signing":"${Base64.getEncoder().encodeToString(keys.signing)}","agreement":"${Base64.getEncoder().encodeToString(keys.agreement)}"}""".toByteArray()

internal fun controllerJSON(provider: ControllerProvider, label: String, roles: List<String>): ByteArray =
    """{"key":${provider.descriptor().toString(Charsets.UTF_8)},"label":${keyQuote(label)},"roles":[${roles.joinToString(",", transform = ::keyQuote)}]}""".toByteArray()

internal fun signAction(action: HostAction, member: KeyProvider?, controllers: List<ControllerProvider>): List<SignatureResult> {
    val available = controllers.map { it.controllerPublic().signing to it }
    return action.signingSteps().map { step ->
        if (member != null && step.signingKey.contentEquals(member.signingPublicKey())) {
            if (step.form != KeyForm.RAW) throw BindingException.InvalidData("Member signing form")
            SignatureResult(member.sign(step.body), null)
        } else {
            val provider = available.firstOrNull { it.first.contentEquals(step.signingKey) }?.second
                ?: throw BindingException.KeyProvider("No provider for required controller")
            if (provider.form() != step.form) throw BindingException.KeyProvider("Controller form mismatch")
            if (step.form == KeyForm.RAW) SignatureResult(provider.sign(step.body), null)
            else {
                val assertion = provider.assert(step.challenge ?: throw BindingException.InvalidData("Missing WebAuthn challenge"), null)
                SignatureResult(assertion.signature, assertion)
            }
        }
    }
}

/**
 * Opens one complete current vault route using only the supplied controllers.
 * PRF providers must return results.first explicitly; there is no fallback derivation.
 */
fun NativeLibrary.unlockVault(providers: List<ControllerProvider>) {
    val available = providers.associateBy { it.controllerID() }
    val option = beginUnlockSlots().firstOrNull { option -> option.inputs.all { input ->
        when (input) {
            is SlotInput.Ecdh -> available[input.controller]?.form() == KeyForm.RAW
            is SlotInput.Prf -> available[input.controller]?.form() == KeyForm.WEBAUTHN
        }
    } } ?: throw BindingException.KeyProvider("No openable vault slot for these controllers")
    val secrets = mutableListOf<SlotSecret>()
    try {
        option.inputs.forEach { input ->
            secrets.add(when (input) {
                is SlotInput.Ecdh -> SlotSecret.Ecdh(available.getValue(input.controller).agree(input.enc))
                is SlotInput.Prf -> {
                    val challenge = ByteArray(32).also(SecureRandom()::nextBytes)
                    val assertion = available.getValue(input.controller).assert(Base64.getUrlEncoder().withoutPadding().encodeToString(challenge), input.salt)
                    SlotSecret.Prf(assertion.prf ?: throw BindingException.KeyProvider("WebAuthn PRF unsupported or missing results.first"))
                }
            })
        }
        finishUnlockSlot(option, secrets)
    } finally {
        secrets.forEach { when (it) { is SlotSecret.Ecdh -> it.secret.fill(0); is SlotSecret.Prf -> it.output.fill(0) } }
    }
}
