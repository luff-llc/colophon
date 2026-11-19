package com.luff.colophon.session

import com.luff.colophon.AccountPairing
import com.luff.colophon.accountRequestInfo
import java.io.File
import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** One device of a test account: a session over its own medium, with software keys and a private directory. */
class Device(
    val medium: MemoryMedium = MemoryMedium(),
    val member: SoftwareKeys = SoftwareKeys(),
    val owner: SoftwareKeys = SoftwareKeys(),
    homes: List<HomeConfiguration> = listOf(),
    createWithoutHome: Boolean = true,
    additional: List<AdditionalController> = listOf(),
    namespaces: List<String> = listOf("notes"),
    services: List<ServiceTerms> = listOf(),
    libraryNamespaces: List<String>? = null,
    history: HistoryAccess? = null,
    headQuorum: Int? = null,
    val secrets: DeviceSecretStore = MemoryDeviceSecrets(),
    val dir: File = Files.createTempDirectory("colophon-kotlin-device-").toFile(),
    storage: RecordMedium = medium,
    now: () -> Long = { System.currentTimeMillis() },
) {
    val session = ColophonSession(SessionConfiguration(
        memberLabel = "Test device", namespaces = namespaces, services = services, libraryNamespaces = libraryNamespaces, medium = storage, privateDirectory = dir, keys = member,
        ownerController = owner, homes = homes, createWithoutHome = createWithoutHome, additionalControllers = additional,
        deviceSecrets = secrets, history = history, headQuorum = headQuorum, now = now))

    suspend fun close() { session.shutdown(); dir.deleteRecursively() }

    fun describe(): String = session.state.value.let { s ->
        "phase ${s.phase} error ${s.lastError ?: "-"} issues ${s.homeIssues} faults ${s.homeFaults.map { "${it.fault.kind} ${it.fault.status ?: ""} ${it.fault.code ?: ""}" }}"
    }
}

/** The number of admitted records in a namespace's fold (`view_json`). */
suspend fun admitted(session: ColophonSession, namespace: String = "notes"): Int {
    val v = Json.obj(session.view(namespace)) ?: error("view is not JSON")
    check(v["ok"] == true) { "view refused: $v" }
    return v.obj("value")?.list("admitted")?.size ?: error("no admitted list: $v")
}

/** A note, written as the Rust journey writes it. */
suspend fun note(session: ColophonSession, id: String): WriteReceipt =
    session.perform(DomainCommand("notes", "note.put", Json.write(mapOf("id" to id, "text" to id))), session.observedRevision)

// Pairing before approval (§7.3, §9.1)

/**
 * The six-digit code between a joining device and an approving one, each through its own session, with the messages passed
 * between them as an app would carry them: the request with the commitment, the nonce, the reveal. Both screens' digits
 * are compared and both devices confirm. Returns the request the approving device approves and its confirmed pairing.
 */
suspend fun pairByCode(joining: ColophonSession, approving: ColophonSession): Pair<AccessRequest, AccountPairing> {
    val raw = joining.exportRequest()
    val j = joining.beginJoinPairing()
    val start = approving.beginApproval(j.commitment())
    val reveal = assertNotNull(j.receiveNonce(start.nonce))
    val code = approving.approvalCode(start.pairing, reveal.e, reveal.nb)
    assertEquals(j.digits(), code, "both screens show the same six digits")
    assertTrue(code.length == 6 && code.all { it.isDigit() })
    j.confirm(); start.pairing.confirm()
    val info = accountRequestInfo(raw)
    return AccessRequest(info.member, info.label, info.kind, info.termsJson, info.raw) to start.pairing
}

/** Pairs by the code and approves. */
suspend fun approveByCode(joining: ColophonSession, approving: ColophonSession, termsJson: String? = null) {
    val (request, pairing) = pairByCode(joining, approving)
    approving.approve(request, pairing, termsJson)
}

/** The scan path: the approving device scans the joining device's request (its canonical envelope) and approves it. */
suspend fun approveByScan(joining: ColophonSession, approving: ColophonSession, termsJson: String? = null) {
    val scanned = approving.scanRequest(joining.exportRequest())
    approving.approve(scanned.request, scanned.pairing, termsJson)
}
