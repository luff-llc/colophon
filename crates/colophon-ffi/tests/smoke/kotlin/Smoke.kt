// Kotlin/JVM smoke test over the generated typed 0.5 bindings. See ../README.md for how to run it.
import com.luff.colophon.*
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature as JSignature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.KeyAgreement
import java.security.KeyFactory
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

var failures = 0
fun check(ok: Boolean, what: String) { println((if (ok) "PASS " else "FAIL ") + what); if (!ok) failures++ }
fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)
fun fresh(n: Int) = ByteArray(n).also { java.security.SecureRandom().nextBytes(it) }
fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
fun pad(x: BigInteger): ByteArray { val b = x.toByteArray().dropWhile { it == 0.toByte() }.toByteArray(); return ByteArray(32 - b.size) + b }
fun point(k: KeyPair): ByteArray { val w = (k.public as ECPublicKey).w; return byteArrayOf(4) + pad(w.affineX) + pad(w.affineY) }
fun sign(k: KeyPair, body: ByteArray): ByteArray = JSignature.getInstance("SHA256withECDSAinP1363Format").run { initSign(k.private); update(body); sign() }
fun ecdh(k: KeyPair, peerPoint: ByteArray): ByteArray {
    val params = (k.public as ECPublicKey).params
    val w = ECPoint(BigInteger(1, peerPoint.copyOfRange(1, 33)), BigInteger(1, peerPoint.copyOfRange(33, 65)))
    val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(w, params))
    return KeyAgreement.getInstance("ECDH").run { init(k.private); doPhase(pub, true); generateSecret() }
}

class Throwing : HostSource {
    override fun read(path: String): ByteArray = throw IllegalStateException("not an AccountException")
    override fun readBlob(path: String): ByteArray = ByteArray(0)
}
class Mem(val files: Map<String, ByteArray>) : HostSource {
    override fun read(path: String): ByteArray = files[path] ?: throw AccountException.Host("host", "missing $path")
    override fun readBlob(path: String): ByteArray = files[path] ?: ByteArray(0)
}

fun main() {
    val empty = SavedState(ByteArray(0), ByteArray(0), listOf())
    check(accountDefaultPolicy().contains("recoveryDelay"), "accountDefaultPolicy")
    try {
        AccountCreation.begin(CreateParams("x", listOf(), listOf(), listOf(), null, null, null, false, "", listOf(), listOf()), "controller:00", 0, ByteArray(1))
        check(false, "short entropy")
    } catch (e: AccountException.Bound) { check(e.code == "bound", "short entropy is AccountException.Bound") }

    val mac = p256(); val macAgree = p256()
    val id = accountKeyId(point(mac))
    val lap = p256(); val lapAgree = p256(); val lapId = accountKeyId(point(lap))
    val keys = mapOf(id to mac, lapId to lap)
    fun controller(sig: KeyPair, agr: KeyPair, label: String, roles: String) =
        """{"key":{"form":"raw","signing":"${b64(point(sig))}","agreement":"${b64(point(agr))}"},"label":"$label","roles":[$roles]}"""
    fun signAll(steps: List<AccountSigningStep>) = steps.map { Signature(sign(keys[it.signer]!!, it.body), null, null) }
    val now = System.currentTimeMillis()
    val params = CreateParams("Kotlin smoke", listOf("notes"), listOf(controller(mac, macAgree, "Mac", "\"approve\",\"control\"")),
        listOf(SlotPlan(listOf(id), "Mac")), null, null, null, false, "", listOf(id), listOf(id))
    val creation = AccountCreation.begin(params, "controller:$id", now, fresh(96))
    var rounds = 0
    while (true) { rounds++; if (creation.provideSignatures(signAll(creation.steps())) == CreateStage.DONE) break }
    check(rounds == 2, "creation in two rounds")
    val created = creation.takeResult()
    check(created.account.length == 64, "account id")

    val files = created.stores.associate { it.path to it.bytes }
    val listing = files.keys.sorted().map { ListedPath(it, "") }
    val engine = AccountEngine.open(Mem(files), listing, "controller:$id", created.account, listOf(), 0u, empty, fresh(32), now)
    check(engine.openInfo().mode == OpenMode.COLD, "engine over a Kotlin source (OpenMode enum)")
    val slot = engine.slots()[0]
    val inputs = engine.beginUnlockSlot(slot.index)
    check(inputs.size == 1 && inputs[0].kind == UnlockKind.ECDH, "the slot asks for one ECDH")
    engine.finishUnlockSlot(slot.index, listOf(UnlockSecret(UnlockKind.ECDH, ecdh(macAgree, inputs[0].enc))))
    check(engine.isUnlocked(), "unlocked from the host's ECDH result")
    check(engine.status().code == "ok" && engine.controllers().size == 1, "typed status and controllers")

    val action = engine.beginAddController(controller(lap, lapAgree, "Laptop", "\"approve\""), AddMode.IMMEDIATE, listOf(id), RuleKind.CONTROL, ByteArray(0))
    val steps = action.steps()
    check(steps.size == 2 && steps.any { it.role == StepRole.POSSESSION }, "typed steps")
    val sigs = signAll(steps)
    val written = engine.finish(action, sigs)
    check(written.stores.isNotEmpty() && written.changes.controllersAdded == listOf(lapId), "typed stores and changes")
    try { engine.finish(action, sigs); check(false, "replay") } catch (e: AccountException.Consumed) { check(e.code == "consumed", "replay is Consumed") }

    // The calls the engine forwards: a due-transition pass, then pairing, seed transfer and lock.
    val files2 = files.toMutableMap().also { m -> written.stores.forEach { m[it.path] = it.bytes } }
    check(engine.recordDue().isEmpty(), "recordDue: nothing is due")
    val listing2 = files2.keys.sorted().map { ListedPath(it, "") }
    val engine2 = AccountEngine.open(Mem(files2), listing2, "controller:$lapId", created.account, listOf(), 0u, empty, fresh(32), now)
    val tkey = PairingTransferKey.create(fresh(32))
    val joiner = AccountPairing.join(created.account, tkey.public(), fresh(32))
    val limiter = PairingFailureLimiter.fromState("")
    val existing = AccountPairing.existingReceiveCommitment(created.account, joiner.commitment(), limiter, now)
    val na = existing.sendNonce(fresh(32))
    val reveal = joiner.receiveNonce(na)!!
    val digits = existing.receiveReveal(reveal.e, reveal.nb, limiter, now)
    check(digits == joiner.digits(), "both devices show the same six digits")
    existing.confirm(); joiner.confirm()
    val sealed = engine.transferSeed(existing, fresh(32))
    check(!engine2.isUnlocked(), "the second device holds no seed yet")
    engine2.acceptSeedTransfer(tkey, joiner, sealed)
    check(engine2.isUnlocked(), "the seed transferred through the exports unlocks the second engine")
    engine.lock()
    check(engine.isLocked(), "lock: the engine reports it is locked")
    try { engine.save(fresh(32)); check(false, "a locked engine saves") } catch (e: AccountException) { check(true, "a locked engine refuses to save (typed AccountException)") }

    try { AccountEngine.open(Throwing(), listing, "controller:$id", created.account, listOf(), 0u, empty, fresh(32), now); check(false, "throwing source") }
    catch (e: AccountException) { println("  throwing source -> $e"); check(e is AccountException.Host, "a foreign Kotlin exception from the callback arrives as Host") }
    try { AccountEngine.open(Mem(mapOf()), listing, "controller:$id", created.account, listOf(), 0u, empty, fresh(32), now); check(false, "missing") }
    catch (e: AccountException.Host) { check(e.detail.contains("missing"), "the host's own message reaches the caller: ${e.detail}") }
    println(if (failures == 0) "ALL PASS" else "$failures FAILED")
    kotlin.system.exitProcess(if (failures == 0) 0 else 1)
}
