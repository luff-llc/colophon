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
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECParameterSpec
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.io.File

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
        AccountCreation.begin(CreateParams("x", listOf(), listOf(), listOf(), null, null, null, false, "", listOf(), listOf()), AccountIdentity(AccountIdentityKind.CONTROLLER, "00"), 0, ByteArray(1))
        check(false, "short entropy")
    } catch (e: AccountException.Bound) { check(e.code == "bound", "short entropy is AccountException.Bound") }

    val mac = p256(); val macAgree = p256()
    val id = accountKeyId(point(mac))
    val lap = p256(); val lapAgree = p256(); val lapId = accountKeyId(point(lap))
    val keys = mapOf(id to mac, lapId to lap)
    fun controller(sig: KeyPair, agr: KeyPair, label: String, roles: List<ControllerRole>) =
        ControllerSpec(KeyDescriptorView(SignForm.RAW, point(sig), point(agr), null, null, listOf(), listOf()), label, roles, false, null, listOf())
    fun ctl(id: String) = AccountIdentity(AccountIdentityKind.CONTROLLER, id)
    fun signAll(steps: List<AccountSigningStep>) = steps.map { Signature(sign(keys[it.signer]!!, it.body), null, null) }
    val now = System.currentTimeMillis()
    val params = CreateParams("Kotlin smoke", listOf("notes"), listOf(controller(mac, macAgree, "Mac", listOf(ControllerRole.APPROVE, ControllerRole.CONTROL))),
        listOf(SlotPlan(listOf(id), "Mac")), null, null, null, false, "", listOf(id), listOf(id))
    val creation = AccountCreation.begin(params, ctl(id), now, fresh(96))
    var rounds = 0
    while (true) { rounds++; if (creation.provideSignatures(signAll(creation.steps())) == CreateStage.DONE) break }
    check(rounds == 2, "creation in two rounds")
    val created = creation.takeResult()
    check(created.account.length == 64, "account id")

    val files = created.stores.associate { it.path to it.bytes }
    val listing = files.keys.sorted().map { ListedPath(it, null) }
    val engine = AccountEngine.open(Mem(files), listing, ctl(id), created.account, listOf(), 0u, empty, fresh(32), now)
    check(engine.openInfo().mode == OpenMode.COLD, "engine over a Kotlin source (OpenMode enum)")
    val slot = engine.slots()[0]
    val inputs = engine.beginUnlockSlot(slot.index)
    check(inputs.size == 1 && inputs[0].kind == UnlockKind.ECDH, "the slot asks for one ECDH")
    engine.finishUnlockSlot(slot.index, listOf(UnlockSecret(UnlockKind.ECDH, ecdh(macAgree, inputs[0].enc))))
    check(engine.isUnlocked(), "unlocked from the host's ECDH result")
    check(engine.status().kind == StatusKind.OK && engine.controllers().size == 1, "typed status and controllers")
    check(engine.controllers()[0].roles == listOf(ControllerRole.APPROVE, ControllerRole.CONTROL) && engine.identity().kind == AccountIdentityKind.CONTROLLER, "roles and identity are enums")

    val action = engine.beginAddController(controller(lap, lapAgree, "Laptop", listOf(ControllerRole.APPROVE)), AddMode.IMMEDIATE, listOf(id), RuleKind.CONTROL, ByteArray(0))
    val steps = action.steps()
    check(steps.size == 2 && steps.any { it.role == StepRole.POSSESSION } && action.kind() == ActionKind.ADD_CONTROLLER, "typed steps; the action's kind is an enum")
    val sigs = signAll(steps)
    val written = engine.finish(action, sigs)
    check(written.stores.isNotEmpty() && written.changes.controllersAdded == listOf(lapId), "typed stores and changes")
    try { engine.finish(action, sigs); check(false, "replay") } catch (e: AccountException.Consumed) { check(e.code == "consumed", "replay is Consumed") }

    // The calls the engine forwards: a due-transition pass, then pairing, seed transfer and lock.
    val files2 = files.toMutableMap().also { m -> written.stores.forEach { m[it.path] = it.bytes } }
    check(engine.recordDue().isEmpty(), "recordDue: nothing is due")
    val listing2 = files2.keys.sorted().map { ListedPath(it, null) }
    val engine2 = AccountEngine.open(Mem(files2), listing2, ctl(lapId), created.account, listOf(), 0u, empty, fresh(32), now)
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
    try { engine.save(fresh(32)); check(false, "a locked engine saves") } catch (e: AccountException.Locked) { check(e.code == "locked", "a locked engine refuses to save with AccountException.Locked") }
    try { engine.beginRekey(listOf("notes"), listOf(id), fresh(32)); check(false, "a locked engine prepares") } catch (e: AccountException.Locked) { check(true, "a locked engine refuses to prepare an action") }

    try { AccountEngine.open(Throwing(), listing, ctl(id), created.account, listOf(), 0u, empty, fresh(32), now); check(false, "throwing source") }
    catch (e: AccountException) { println("  throwing source -> $e"); check(e is AccountException.Host, "a foreign Kotlin exception from the callback arrives as Host") }
    try { AccountEngine.open(Mem(mapOf()), listing, ctl(id), created.account, listOf(), 0u, empty, fresh(32), now); check(false, "missing") }
    catch (e: AccountException.Host) { check(e.detail.contains("missing"), "the host's own message reaches the caller: ${e.detail}") }

    // The successor genesis of a Swift keyring library (the repository's conformance fixture),
    // through the export: one passkey assertion rebuilds the passkey's slot and opens the Swift slot.
    fun readB64(o: String, k: String, within: String? = null): ByteArray {
        // A tiny reader for the flat fixture JSON (no JSON library is on the class path).
        var text = File(o).readText()
        if (within != null) text = Regex("\"$within\"\\s*:\\s*\\{([^}]*)\\}").find(text)!!.groupValues[1]
        val m = Regex("\"$k\"\\s*:\\s*\"([^\"]*)\"").find(text) ?: error("no $k in $o")
        return Base64.getDecoder().decode(m.groupValues[1])
    }
    val repo = System.getenv("COLOPHON_REPO") ?: "."
    val fixture = "$repo/conformance/keyring"
    val ecParams = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    fun privateOf(scalar: ByteArray) = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, scalar), ecParams))
    val expected = File("$fixture/expected.json").readText()
    fun who(name: String) = Regex("\"$name\"\\s*:\\s*\"([0-9a-f]{32})\"").find(expected)!!.groupValues[1]
    val ownerId = who("owner"); val webauthnId = who("webauthn")
    val ownerKey = privateOf(readB64("$fixture/keys.json", "signingKey", "owner"))
    val passkey = privateOf(readB64("$fixture/keys.json", "webauthnScalar"))
    val entries = File("$fixture/library/authority").listFiles()!!.sortedBy { it.name }.map {
        var b = it.readBytes(); if (b.isNotEmpty() && b.last() == 10.toByte()) b = b.copyOf(b.size - 1); ByteString(b) }
    val swiftSource = SwiftSource.read(entries)
    val policyText = accountDefaultPolicy().replace(Regex("\"recoveryDelay\"\\s*:\\s*\\d+"), "\"recoveryDelay\":3600")
    val successor = SwiftSuccessorCreation.begin(swiftSource,
        SwiftSuccessorParams("Library", listOf("reading.saved"), false, listOf(OriginsFor(webauthnId, listOf("https://id.luff.works"))), listOf(),
            1uL, 1uL, 1uL, false, policyText, listOf(ownerId), listOf(ownerId), now - 60_000, listOf()),
        now, fresh(64))
    check(successor.stage() == CreateStage.PRF, "the successor genesis asks for a passkey ceremony first")
    val ceremonies = successor.ceremonies(); val requests = successor.prfRequests()
    check(ceremonies.size == 1 && requests.size == 1 && ceremonies[0].userVerification && successor.unpaired().isEmpty(),
        "one passkey, one ceremony: one assertion rebuilds the slot and opens the Swift slot")
    val cer = ceremonies[0]
    val sha = MessageDigest.getInstance("SHA-256")
    val authData = sha.digest(cer.rp.toByteArray()) + byteArrayOf(5, 0, 0, 0, 0)
    val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(cer.challenge)
    val clientData = """{"challenge":"$challenge","origin":"https://${cer.rp}","type":"webauthn.get"}""".toByteArray()
    val assertion = JSignature.getInstance("SHA256withECDSA").run { initSign(passkey); update(authData + sha.digest(clientData)); sign() }
    successor.providePrf(listOf(PrfAnswer(authData, clientData, assertion, sha.digest(cer.newSalt))))
    swiftSource.finishOpenSlot(cer.oldSlot, listOf(UnlockSecret(UnlockKind.PRF, readB64("$fixture/keys.json", "prfOutput"))))
    check(swiftSource.openNamespaceKeys() >= 1uL, "the Swift vault opened by the second output of the same assertion")
    val ssteps = successor.steps()
    check(ssteps.map { it.role } == listOf(StepRole.PRIMARY, StepRole.HANDOVER), "the genesis and the handover are the steps")
    check(successor.provideSignatures(ssteps.map { Signature(JSignature.getInstance("SHA256withECDSAinP1363Format").run { initSign(ownerKey); update(it.body); sign() }, null, null) }) == CreateStage.DONE,
        "the successor genesis is signed and checked")
    val moved = successor.takeResult()
    check(moved.stores.any { it.path == "authority/00000001.json" } && moved.stores.any { it.path.startsWith("predecessor/authority/") },
        "the genesis and the predecessor entries are handed back to store")
    val mfiles = moved.stores.associate { it.path to it.bytes }
    val mengine = AccountEngine.open(Mem(mfiles), mfiles.keys.sorted().map { ListedPath(it, null) }, ctl(ownerId), moved.account, listOf(), 0u, empty, fresh(32), now)
    check(mengine.swiftSuccession().stage == MoveStage.WINDOW_NOT_OPEN, "the successor reports the Swift succession (stage WINDOW_NOT_OPEN)")
    try { mengine.beginSwiftFreeze(listOf(ownerId), now, listOf()); check(false, "F before the due time") }
    catch (e: AccountException) { check(true, "F is refused before the succession is due (a typed AccountException; earlierAttempts is an argument)") }
    check(accountMapSwiftRole("service") == AccountMemberKind.SERVER && accountMapSwiftRole("robot") == null, "the Swift role to member kind map is exported")
    check(engine2.controllers()[0].key.signing.size == 65, "a controller carries its key descriptor")
    println(if (failures == 0) "ALL PASS" else "$failures FAILED")
    kotlin.system.exitProcess(if (failures == 0) 0 else 1)
}
