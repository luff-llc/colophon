package com.luff.colophon.session

import java.io.File
import java.nio.file.Files

/** One device of a test account: a session over its own medium, with software keys and a private directory. */
class Device(
    val medium: MemoryMedium = MemoryMedium(),
    val member: SoftwareKeys = SoftwareKeys(),
    val owner: SoftwareKeys = SoftwareKeys(),
    homes: List<HomeConfiguration> = listOf(),
    createWithoutHome: Boolean = true,
    additional: List<AdditionalController> = listOf(),
    namespaces: List<String> = listOf("notes"),
    history: HistoryAccess? = null,
    headQuorum: Int? = null,
    val secrets: DeviceSecretStore = MemoryDeviceSecrets(),
    val dir: File = Files.createTempDirectory("colophon-kotlin-device-").toFile(),
    storage: RecordMedium = medium,
) {
    val session = ColophonSession(SessionConfiguration(
        memberLabel = "Test device", namespaces = namespaces, medium = storage, privateDirectory = dir, keys = member,
        ownerController = owner, homes = homes, createWithoutHome = createWithoutHome, additionalControllers = additional,
        deviceSecrets = secrets, history = history, headQuorum = headQuorum))

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
