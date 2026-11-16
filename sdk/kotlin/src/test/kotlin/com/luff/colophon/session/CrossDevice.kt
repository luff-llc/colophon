package com.luff.colophon.session

import com.luff.colophon.*
import kotlinx.coroutines.runBlocking
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPrivateKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Collections

/** Test-only JSON-line device. Its synthetic keys and cache key survive a process restart, in its own directory. */
private fun decode(s: String) = Base64.getDecoder().decode(s)
private fun encode(b: ByteArray) = Base64.getEncoder().encodeToString(b)
private fun emit(v: Any?) { println(Json.write(v)); System.out.flush() }
private fun event(v: Any?): Map<String, Any?> {
    emit(v)
    val reply = Json.obj(readln()) ?: error("event reply is not JSON")
    check(reply["error"] == null) { "event failed" }
    return reply
}
private class StoredKeys(private val directory: File, private val name: String) : AsyncKeyProvider {
    private fun pair(suffix: String): java.security.KeyPair {
        val privateFile = File(directory, "$name-$suffix-private")
        val publicFile = File(directory, "$name-$suffix-public")
        if (!privateFile.exists()) {
            val key = P256.generate()
            privateFile.writeBytes(key.private.encoded); publicFile.writeBytes(key.public.encoded)
        }
        val factory = KeyFactory.getInstance("EC")
        return java.security.KeyPair(factory.generatePublic(X509EncodedKeySpec(publicFile.readBytes())),
            factory.generatePrivate(PKCS8EncodedKeySpec(privateFile.readBytes())))
    }
    private val signing = pair("signing")
    private val agreement = pair("agreement")
    override suspend fun publicKeys() = PublicKeys(P256.point(signing.public as ECPublicKey), P256.point(agreement.public as ECPublicKey))
    override suspend fun sign(body: ByteArray) = P256.sign(signing.private, body)
    override suspend fun sharedSecret(peer: ByteArray) = SecretBytes.adopt(P256.agree(agreement.private, peer))
}
private class RemoteOwner(private val keys: PublicKeys) : AsyncKeyProvider {
    override suspend fun publicKeys() = keys
    override suspend fun sign(body: ByteArray) = decode(event(mapOf("event" to "sign", "body" to encode(body))).string("signature")!!)
    override suspend fun sharedSecret(peer: ByteArray): SecretBytes = error("remote ECDH not offered")
}
private class FileSecrets(private val directory: File) : DeviceSecretStore {
    override fun key(account: String): SecretBytes {
        val file = File(directory, "device-secret-$account")
        if (!file.exists()) withEntropy(32) { file.writeBytes(it) }
        return SecretBytes.adopt(file.readBytes())
    }
    override fun remove(account: String) { File(directory, "device-secret-$account").delete() }
}
private class CrossDriver {
    var session: ColophonSession? = null
    private lateinit var owner: StoredKeys
    private var pairing: AccountPairing? = null
    private var transferKey: PairingTransferKey? = null
    private val limiter = PairingFailureLimiter.fromState("")
    private val refused = Collections.synchronizedList(ArrayList<String>())
    private fun state(): Map<String, Any?> {
        val s = session ?: return mapOf()
        val phase = when (s.phase) {
            SessionPhase.Ready -> "ready"; SessionPhase.Locked -> "locked"; SessionPhase.Denied -> "denied"
            is SessionPhase.WaitingForApproval -> "waiting"; else -> s.phase.toString()
        }
        return mapOf("phase" to phase, "account" to s.libraryId, "member" to s.memberId, "homes" to s.homes.size,
            "error" to s.lastError, "issues" to s.homeIssues.map { (it.problem as? HomeProblem.CallRefused)?.code ?: it.problem.toString() },
            "faults" to s.homeFaults.map { it.fault.toString() }, "refusals" to synchronized(refused) { refused.toList() },
            "pending" to s.notices.pending.map { mapOf("digest" to it.digest, "vetoable" to it.vetoable) })
    }
    @Suppress("UNCHECKED_CAST")
    suspend fun run(c: Map<String, Any?>): Any? {
        fun text(key: String) = c.string(key) ?: error("missing $key")
        fun data(key: String) = decode(text(key))
        if (text("op") == "init") {
            val root = File(text("root")); val directory = File(root, "private").apply { mkdirs() }
            val member = StoredKeys(directory, "member"); owner = StoredKeys(directory, "owner")
            val configs = (c["homes"] as List<Map<String, String>>).map { h ->
                val base = h.getValue("base")
                val signing = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, decode(h.getValue("secret"))), P256.parameters))
                val transport = HttpHomeTransport(allowingLoopbackHttp = true)
                HomeConfiguration("$base/", request = { account ->
                    event(mapOf("event" to "provision", "account" to account))
                    AccountRequest.prepare(RequestSpec(account, decode(h.getValue("signing")), decode(h.getValue("agreement")), "Cross home",
                        AccountMemberKind.SERVER, "{\"serves\":[\"home\"]}", accountFormatDate(System.currentTimeMillis() - 5000), null, null, listOf("$base/"))).use {
                        it.finish(Signature(P256.sign(signing, it.step().body), null, null)).raw
                    }
                }, transport = HomeTransport { request ->
                    check(request.url.startsWith("$base/")) { "wrong home" }
                    val answer = transport.send(HttpRequest(request.ticket, request.home, request.method,
                        h.getValue("local") + request.url.substring(base.length), request.headers, request.body))
                    if (answer.status == 403u) refused.add(Json.obj(answer.body.toString(Charsets.UTF_8))?.string("result") ?: "missing-result")
                    answer
                })
            }
            val extra = (c["extra"] as? Map<String, String>)?.let {
                listOf(AdditionalController(RemoteOwner(PublicKeys(decode(it.getValue("signing")), decode(it.getValue("agreement")))), "Other platform owner"))
            } ?: listOf()
            session = ColophonSession(SessionConfiguration(memberLabel = "Kotlin cross device", namespaces = listOf("reading.saved"),
                medium = FolderMedium(File(root, "records")), privateDirectory = directory, keys = member, ownerController = owner,
                homes = configs, additionalControllers = extra, deviceSecrets = FileSecrets(directory),
                history = if (text("history") == "members") HistoryAccess.MEMBERS else HistoryAccess.EVERYONE, headQuorum = configs.size))
            val p = owner.publicKeys()
            return mapOf("signing" to encode(p.signing), "agreement" to encode(p.agreement))
        }
        if (text("op") == "sign") return encode(owner.sign(data("body")))
        when (text("op")) {
            "join" -> {
                pairing?.close(); transferKey?.close()
                transferKey = PairingTransferKey.create(data("entropy"))
                val e = transferKey!!.public()
                if (text("mode") == "qr") {
                    pairing = AccountPairing.joinQr(text("account"), e, data("nb"))
                    return mapOf("qr" to encode(pairing!!.qrPayload()), "e" to encode(e))
                }
                pairing = AccountPairing.join(text("account"), e, data("nb"))
                return mapOf("commitment" to encode(pairing!!.commitment()), "e" to encode(e))
            }
            "scan" -> {
                pairing?.close()
                pairing = if (text("mode") == "qr") AccountPairing.existingScanQr(text("account"), data("qr"), limiter, 1000)
                    else AccountPairing.existingReceiveCommitment(text("account"), data("commitment"), limiter, 1000)
                return true
            }
            "nonce" -> return encode(pairing!!.sendNonce(data("na")))
            "receiveNonce" -> {
                val r = pairing!!.receiveNonce(data("na"))
                return if (r == null) mapOf("stage" to pairing!!.stage().name.lowercase()) else mapOf("e" to encode(r.e), "nb" to encode(r.nb), "digits" to pairing!!.digits())
            }
            "reveal" -> return pairing!!.receiveReveal(data("e"), data("nb"), limiter, 1000)
            "confirm" -> {
                val matches = pairing!!.digits() == text("digits")
                if (matches) pairing!!.confirm() else pairing!!.reject(limiter, 1000)
                return mapOf("accepted" to matches, "stage" to pairing!!.stage().name.lowercase())
            }
            "pairingStage" -> return pairing!!.stage().name.lowercase()
        }
        val s = session ?: error("not initialized")
        when (text("op")) {
            "create" -> s.create()
            "restore" -> s.restore()
            "refresh" -> s.refresh()
            "sync" -> { refused.clear(); s.syncNow(); s.refresh() }
            "request" -> return encode(s.exportRequest())
            "approve" -> { s.importRequest(data("request")); s.approve(s.requests.first()) }
            "revoke" -> s.revoke(text("member"))
            "write" -> s.perform(DomainCommand("reading.saved", "capture", data("payload").toString(Charsets.UTF_8)), s.observedRevision)
            "read" -> return encode(s.query("reading.saved", "read").toByteArray(Charsets.UTF_8))
            "putBlob" -> return s.putBlob(data("bytes"), "reading.saved", "application/octet-stream", text("reference"), c["required"] as Boolean).digest
            "availability" -> return if (s.blobAvailability("reading.saved", text("digest")) == BlobAvailabilityState.Available) "available" else "missing"
            "blob" -> return encode(s.blobData("reading.saved", text("digest")))
            "prefetch" -> s.prefetchBlob("reading.saved", text("digest"))
            "propose" -> return s.proposeTransition(text("change"))
            "veto" -> s.veto(text("digest"))
            "transfer" -> { val sealed = s.transferSeed(pairing!!); return mapOf("enc" to encode(sealed.enc), "ciphertext" to encode(sealed.ciphertext)) }
            "accept" -> s.acceptSeedTransfer(transferKey!!, pairing!!, SealedSeed(data("enc"), data("ciphertext")), "Kotlin paired owner")
            "checkpoint" -> s.flushCheckpoint()
            "lock" -> { s.flushCheckpoint(); s.lock() }
            "state" -> {}
            else -> error("unknown operation")
        }
        s.stopSync()
        return state()
    }
}

/** Run by Bun using the test runtime classpath; not included in any published SDK artifact. */
fun main() = runBlocking {
    val driver = CrossDriver()
    try {
        while (true) {
            val line = readlnOrNull() ?: break
            try { emit(mapOf("ok" to true, "value" to driver.run(Json.obj(line) ?: error("command is not JSON")))) }
            catch (e: Exception) { emit(mapOf("ok" to false, "error" to "${e.javaClass.simpleName}: ${e.message}")) }
        }
    } finally { driver.session?.shutdown() }
}
