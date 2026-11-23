package com.luff.colophon.session

import com.luff.colophon.AccountSigningStep
import com.luff.colophon.EpochAgreement
import com.luff.colophon.EpochAnswer
import com.luff.colophon.KeyDescriptorView
import com.luff.colophon.KeyProvider
import com.luff.colophon.PrfAnswer
import com.luff.colophon.PrfRequest
import com.luff.colophon.PublicKeys
import com.luff.colophon.SignForm
import com.luff.colophon.Signature
import com.luff.colophon.StepRole
import com.luff.colophon.UnlockInput
import com.luff.colophon.UnlockKind
import com.luff.colophon.UnlockSecret
import com.luff.colophon.accountKeyId
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement
import kotlin.coroutines.cancellation.CancellationException

/**
 * Secret bytes the SDK owns and overwrites with zeros on [close]. PRF outputs, ECDH results, epoch shares, the
 * device-held sealed-state key and action entropy live in one until the one export call that takes them.
 *
 * What it cannot reach: a copy the JVM made before the bytes were handed over (a JCA provider's own buffers), the
 * garbage collector moving the array before it is wiped, and the UniFFI lowering copy (the Rust side overwrites that
 * one through its zero-on-free allocator). [toString] is redacted.
 */
class SecretBytes private constructor(private var bytes: ByteArray?) : AutoCloseable {
    val size: Int get() = bytes?.size ?: 0
    /** Lends the bytes for one call. They must not escape [body]. */
    fun <R> lend(body: (ByteArray) -> R): R = body(bytes ?: throw IllegalStateException("secret already wiped"))
    override fun close() { bytes?.fill(0); bytes = null }
    override fun toString(): String = "SecretBytes(redacted)"
    companion object {
        private val random = SecureRandom()
        /** Takes ownership of `bytes` (no copy): the caller must not keep using its own reference. */
        fun adopt(bytes: ByteArray): SecretBytes = SecretBytes(bytes)
        fun random(count: Int): SecretBytes = SecretBytes(ByteArray(count).also(random::nextBytes))
    }
}

/** Runs `body` with `count` bytes of fresh entropy, wiped afterwards (refusals included). */
inline fun <R> withEntropy(count: Int, body: (ByteArray) -> R): R {
    if (count == 0) return body(ByteArray(0))
    val bytes = ByteArray(count).also(java.security.SecureRandom()::nextBytes)
    try { return body(bytes) } finally { bytes.fill(0) }
}

/** Lends several secrets at once, closing all of them afterwards. */
internal fun <R> lendAll(secrets: List<SecretBytes>, body: (List<ByteArray>) -> R): R {
    try {
        val arrays = secrets.map { s -> s.lend { it } }
        return body(arrays)
    } finally {
        secrets.forEach { it.close() }
    }
}

/**
 * A WebAuthn get result: the signed bytes exactly as the authenticator returned them, and the PRF output
 * (`results.first`) when a salt was evaluated.
 */
class KeyAssertion(val signature: ByteArray, val authenticatorData: ByteArray, val clientData: ByteArray, val prf: SecretBytes?) {
    /** The assertion without its PRF output, as a signature step takes it. */
    val signatureValue: Signature get() = Signature(signature, authenticatorData, clientData)
    override fun toString(): String = "KeyAssertion(redacted)"
}

/**
 * A key the host holds. Suspends for authentication, a platform key store or a KMS. Raw signatures are `r || s`;
 * WebAuthn assertions keep DER and the original signed bytes. Public points are X9.63 uncompressed; ECDH returns
 * the 32-byte x coordinate. The Kotlin twin of the Swift SDK's `AsyncKeyProvider`.
 */
interface AsyncKeyProvider {
    /** Raw ES256 or WebAuthn assertions. */
    val form: SignForm get() = SignForm.RAW
    /** Whether a WebAuthn get can also evaluate a PRF salt on this provider. */
    val supportsPrf: Boolean get() = false
    suspend fun publicKeys(): PublicKeys
    suspend fun sign(body: ByteArray): ByteArray
    /** Raw 32-byte ECDH with this provider's agreement key. */
    suspend fun sharedSecret(peer: ByteArray): SecretBytes
    /** The key as the protocol writes it (spec §3.1). Raw keys are described by [publicKeys]. */
    suspend fun keyDescriptor(): KeyDescriptorView {
        val keys = publicKeys()
        return KeyDescriptorView(SignForm.RAW, keys.signing, keys.agreement.takeIf { it.isNotEmpty() }, null, null, listOf(), listOf())
    }
    /** A WebAuthn get restricted to this credential over `challenge` (base64url), evaluating `prfSalt` when given. Null: unsupported. */
    suspend fun assert(challenge: String, prfSalt: ByteArray?): KeyAssertion? = null
    /** The PRF output of an existing route for `salt`. Null: unsupported (never a fallback secret). */
    suspend fun prf(salt: ByteArray): SecretBytes? = null
}

/** A provider failure, classified at its origin (the session keeps storage and core errors apart from it). */
class SessionKeyFailure(val detail: String, cause: Throwable? = null) : Exception(detail, cause)

/** Wraps a provider so that its failures arrive as [SessionKeyFailure] (cancellation passes through). */
internal class SessionKeys(val base: AsyncKeyProvider) : AsyncKeyProvider {
    private inline fun <T> classify(body: () -> T): T = try { body() } catch (e: CancellationException) { throw e } catch (e: SessionKeyFailure) { throw e } catch (e: Exception) {
        throw SessionKeyFailure(e.message ?: e.javaClass.simpleName, e)
    }
    override val form: SignForm get() = base.form
    override val supportsPrf: Boolean get() = base.supportsPrf
    override suspend fun publicKeys() = classify { base.publicKeys() }
    override suspend fun sign(body: ByteArray) = classify { base.sign(body) }
    override suspend fun sharedSecret(peer: ByteArray) = classify { base.sharedSecret(peer) }
    override suspend fun keyDescriptor() = classify { base.keyDescriptor() }
    override suspend fun assert(challenge: String, prfSalt: ByteArray?) = classify { base.assert(challenge, prfSalt) }
    override suspend fun prf(salt: ByteArray) = classify { base.prf(salt) }
}

/** P-256 helpers shared by the software keys and the platform adapters. */
object P256 {
    val parameters: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    }
    fun generate(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    fun scalar(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        require(value.signum() >= 0 && value.bitLength() <= 256) { "not a P-256 field element" }
        return ByteArray(32).also { bytes.copyInto(it, maxOf(0, 32 - bytes.size), maxOf(0, bytes.size - 32)) }
    }
    /** The X9.63 uncompressed point of a public key. */
    fun point(key: ECPublicKey): ByteArray = byteArrayOf(4) + scalar(key.w.affineX) + scalar(key.w.affineY)
    fun publicKey(point: ByteArray): java.security.PublicKey {
        require(point.size == 65 && point[0] == 4.toByte()) { "expected an uncompressed P-256 point" }
        val w = ECPoint(BigInteger(1, point.copyOfRange(1, 33)), BigInteger(1, point.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(w, parameters))
    }
    /** A DER ECDSA signature as raw `r || s` (P-256 DER fits a short-form sequence of at most 72 bytes). */
    fun derToRaw(der: ByteArray): ByteArray {
        require(der.size in 8..72 && der[0] == 0x30.toByte() && der[1].toInt() == der.size - 2) { "not a P-256 DER signature" }
        var offset = 2
        fun integer(): ByteArray {
            require(der[offset++].toInt() == 2) { "not a DER integer" }
            val length = der[offset++].toInt()
            require(length in 1..33 && offset + length <= der.size) { "bad DER integer length" }
            val value = BigInteger(1, der.copyOfRange(offset, offset + length))
            offset += length
            return scalar(value)
        }
        val raw = integer() + integer()
        require(offset == der.size) { "trailing DER bytes" }
        return raw
    }
    /** ES256 over `body` with any JCA private key (a Keystore key included), as raw `r || s`. */
    fun sign(key: PrivateKey, body: ByteArray): ByteArray = java.security.Signature.getInstance("SHA256withECDSA").run {
        initSign(key); update(body); derToRaw(sign())
    }
    /** ECDH with a JCA private key: the 32-byte x coordinate. */
    fun agree(key: PrivateKey, peer: ByteArray, provider: String? = null): ByteArray {
        val agreement = if (provider == null) KeyAgreement.getInstance("ECDH") else KeyAgreement.getInstance("ECDH", provider)
        agreement.init(key)
        agreement.doPhase(publicKey(peer), true)
        val secret = agreement.generateSecret()
        return when {
            secret.size == 32 -> secret
            secret.size == 33 && secret[0] == 0.toByte() -> secret.copyOfRange(1, 33).also { secret.fill(0) }
            secret.size in 1 until 32 -> (ByteArray(32 - secret.size) + secret).also { secret.fill(0) }
            else -> throw IllegalArgumentException("unexpected ECDH secret length ${secret.size}")
        }
    }
    fun base64url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

/**
 * Software P-256 keys in process memory: for tests and previews. Production member keys on Android are Keystore
 * keys (`KeystoreMemberKeys` in the Android library); no accessor here exports a private scalar.
 */
class SoftwareKeys private constructor(private val signing: KeyPair, private val agreement: KeyPair) : AsyncKeyProvider {
    constructor() : this(P256.generate(), P256.generate())
    private val publics = PublicKeys(P256.point(signing.public as ECPublicKey), P256.point(agreement.public as ECPublicKey))
    override suspend fun publicKeys(): PublicKeys = PublicKeys(publics.signing.copyOf(), publics.agreement.copyOf())
    override suspend fun sign(body: ByteArray): ByteArray = P256.sign(signing.private, body)
    override suspend fun sharedSecret(peer: ByteArray): SecretBytes = SecretBytes.adopt(P256.agree(agreement.private, peer))
    /** The key ID without suspending (the first 32 hex of SHA-256 of the signing point). */
    val id: String get() = accountKeyId(publics.signing)
    override fun toString(): String = "SoftwareKeys($id)"
}

/** A 0.4 [KeyProvider] (for example the Android Keystore keys of `org.luff.colophon.KeystoreKeys`) as an [AsyncKeyProvider]. */
class SyncKeyProviderAdapter(private val keys: KeyProvider) : AsyncKeyProvider {
    override suspend fun publicKeys(): PublicKeys = PublicKeys(keys.signingPublicKey(), keys.agreementPublicKey())
    override suspend fun sign(body: ByteArray): ByteArray = keys.sign(body)
    override suspend fun sharedSecret(peer: ByteArray): SecretBytes = SecretBytes.adopt(keys.agree(peer))
}
fun KeyProvider.asAsync(): AsyncKeyProvider = SyncKeyProviderAdapter(this)

sealed class KeyCustodyException(message: String) : Exception(message) {
    /** The engine asked for a key this host does not hold (its ID is public). */
    class NoKey(val id: String) : KeyCustodyException("This device does not hold the key $id.")
    class MissingChallenge : KeyCustodyException("A WebAuthn step carried no challenge.")
    /** The provider cannot do what was asked (no PRF, no assertion, an unknown signing form). */
    class Unsupported : KeyCustodyException("This key cannot perform the requested ceremony.")
}

/** The host's answer to a `PrfRequest`, its output held as [SecretBytes] until the export call that takes it. */
class HostPrfAnswer(val authenticatorData: ByteArray, val clientData: ByteArray, val signature: ByteArray, val output: SecretBytes) {
    override fun toString() = "HostPrfAnswer(redacted)"
}
class HostUnlockSecret(val kind: UnlockKind, val secret: SecretBytes) { override fun toString() = "HostUnlockSecret(redacted)" }
class HostEpochAnswer(val namespace: String, val epoch: ULong, val shared: SecretBytes) { override fun toString() = "HostEpochAnswer(redacted)" }

/** Lends the secrets to the generated records for exactly one export call, then wipes them. */
/** Wipes every secret of these answers (idempotent); for a path that never reached the export call. */
@JvmName("closePrf") fun List<HostPrfAnswer>.closeAll() = forEach { it.output.close() }
@JvmName("closeUnlock") fun List<HostUnlockSecret>.closeAll() = forEach { it.secret.close() }
@JvmName("closeEpochs") fun List<HostEpochAnswer>.closeAll() = forEach { it.shared.close() }

fun <R> List<HostPrfAnswer>.withRecords(body: (List<PrfAnswer>) -> R): R =
    lendAll(map { it.output }) { outs -> body(mapIndexed { n, a -> PrfAnswer(a.authenticatorData, a.clientData, a.signature, outs[n]) }) }
@JvmName("withUnlockRecords")
fun <R> List<HostUnlockSecret>.withRecords(body: (List<UnlockSecret>) -> R): R =
    lendAll(map { it.secret }) { outs -> body(mapIndexed { n, a -> UnlockSecret(a.kind, outs[n]) }) }
@JvmName("withEpochRecords")
fun <R> List<HostEpochAnswer>.withRecords(body: (List<EpochAnswer>) -> R): R =
    lendAll(map { it.shared }) { outs -> body(mapIndexed { n, a -> EpochAnswer(a.namespace, a.epoch, outs[n]) }) }

/**
 * The host's key custody for one engine operation: the providers it holds, by key ID. The engine never calls a key
 * provider (docs/bindings-05.md §8): it returns exact bodies to sign, PRF requests, unlock inputs and epoch
 * agreements, and this type answers them, so raw keys and passkeys are driven the same way.
 */
class KeyCustody internal constructor(
    val providers: Map<String, AsyncKeyProvider>,
    private val possessionPrf: TransitionPossessionPrf?,
) {
    constructor(providers: Map<String, AsyncKeyProvider>) : this(providers, null)

    companion object {
        suspend fun of(list: List<AsyncKeyProvider>): KeyCustody = KeyCustody(list.associateBy { keyId(it) })
        suspend fun keyId(provider: AsyncKeyProvider): String = accountKeyId(provider.publicKeys().signing)
    }
    fun provider(id: String): AsyncKeyProvider = providers[id] ?: throw KeyCustodyException.NoKey(id)
    fun holds(id: String) = providers.containsKey(id)
    fun merging(id: String, provider: AsyncKeyProvider) = KeyCustody(providers + (id to provider))

    /**
     * Builds one answer per item; if any item fails (a provider throws, a prompt is cancelled), every secret built so
     * far is wiped before the failure propagates.
     */
    private inline fun <I, A> collect(items: List<I>, secretOf: (A) -> SecretBytes, make: (I) -> A): List<A> {
        val out = ArrayList<A>(items.size)
        try {
            for (item in items) out.add(make(item))
            return out
        } catch (e: Throwable) {
            out.forEach { secretOf(it).close() }
            throw e
        }
    }

    /** One signature per step, in order: raw `r||s`, or the WebAuthn assertion for the step's challenge. */
    suspend fun sign(steps: List<AccountSigningStep>): List<Signature> = steps.map { step ->
        val provider = provider(step.signer)
        when (step.form) {
            SignForm.RAW -> Signature(provider.sign(step.body), null, null)
            SignForm.WEBAUTHN -> {
                val challenge = step.challenge ?: throw KeyCustodyException.MissingChallenge()
                if (possessionPrf != null && step.role == StepRole.POSSESSION && step.signer == possessionPrf.controller) {
                    return@map possessionPrf.sign(challenge, provider)
                }
                val result = provider.assert(challenge, null) ?: throw KeyCustodyException.Unsupported()
                result.prf?.close()
                result.signatureValue
            }
            SignForm.UNKNOWN -> throw KeyCustodyException.Unsupported()
        }
    }

    /** One assertion per request, evaluating the request's salt: `results.first` is the PRF output. */
    suspend fun answer(requests: List<PrfRequest>): List<HostPrfAnswer> = collect(requests, { it.output }) { request ->
        possessionPrf?.takeAnswer(request)?.let { return@collect it }
        val result = provider(request.controller).assert(P256.base64url(request.challenge), request.salt) ?: throw KeyCustodyException.Unsupported()
        val prf = result.prf
        if (prf == null || prf.size != 32) { prf?.close(); throw KeyCustodyException.Unsupported() }
        HostPrfAnswer(result.authenticatorData, result.clientData, result.signature, prf)
    }

    /** The raw results of a slot's routes, in input order: ECDH against `enc`, or the PRF of `salt`. */
    suspend fun answerUnlock(inputs: List<UnlockInput>): List<HostUnlockSecret> = collect(inputs, { it.secret }) { input ->
        val provider = provider(input.controller)
        when (input.kind) {
            UnlockKind.ECDH -> HostUnlockSecret(UnlockKind.ECDH, provider.sharedSecret(input.enc))
            UnlockKind.PRF -> {
                val prf = provider.prf(input.salt)
                if (prf == null || prf.size != 32) { prf?.close(); throw KeyCustodyException.Unsupported() }
                HostUnlockSecret(UnlockKind.PRF, prf)
            }
        }
    }

    /** The ECDH results a member's host performs to open its epoch shares. */
    suspend fun answerEpochs(agreements: List<EpochAgreement>): List<HostEpochAnswer> = collect(agreements, { it.shared }) {
        HostEpochAnswer(it.namespace, it.epoch, provider(it.recipient).sharedSecret(it.peer))
    }
}

/** One appointment's in-memory PRF evidence, consumed by the matching slot request. */
internal class TransitionPossessionPrf(val controller: String) : AutoCloseable {
    private val salt = ByteArray(32).also(SecureRandom()::nextBytes)
    class Input(val salt: ByteArray, val challenge: ByteArray)
    private var cached: Pair<Input, HostPrfAnswer>? = null
    val input: Input? get() = cached?.first

    suspend fun sign(challenge: String, provider: AsyncKeyProvider): Signature {
        val bytes = Base64.getUrlDecoder().decode(challenge)
        if (bytes.size != 32) throw KeyCustodyException.MissingChallenge()
        val result = provider.assert(challenge, salt) ?: throw KeyCustodyException.Unsupported()
        val output = result.prf
        if (output?.size == 32) {
            close()
            cached = Input(salt, bytes) to HostPrfAnswer(result.authenticatorData, result.clientData, result.signature, output)
        } else {
            output?.close()
        }
        return result.signatureValue
    }

    fun takeAnswer(request: PrfRequest): HostPrfAnswer? {
        val (input, answer) = cached ?: return null
        if (request.controller != controller || !request.salt.contentEquals(input.salt) ||
            !request.challenge.contentEquals(input.challenge)) return null
        cached = null
        return answer
    }

    override fun close() {
        cached?.second?.output?.close()
        cached = null
    }
}
