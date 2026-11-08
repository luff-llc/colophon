package org.luff.colophon

import com.luff.colophon.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

internal fun encodeKeyJSON(value: KeyJson): String = when (value) {
    is KeyJson.Obj -> value.fields.entries.joinToString(",", "{", "}") { keyQuote(it.key) + ":" + encodeKeyJSON(it.value) }
    is KeyJson.Array -> value.items.joinToString(",", "[", "]", transform = ::encodeKeyJSON)
    is KeyJson.Text -> keyQuote(value.value)
    is KeyJson.Number -> value.raw
    is KeyJson.Bool -> value.value.toString()
    KeyJson.Null -> "null"
}

/** Enables a host kit through a normal control-rule change, independently of blocked genesis support. */
internal fun enableTestKit(lib: ColophonLibrary, kit: ControllerProvider, second: ControllerProvider? = null) {
    lib.unlockVault()
    val ring = keyObject(lib.keyring())
    val extra = listOfNotNull(kit to listOf("recover"), second?.let { it to listOf("approve", "control") })
    val controllers = ring.array("controllers") + extra.map { (provider, roles) -> keyObject(controllerJSON(provider, "Kit", roles)) }
    val slots = ring.array("slots") + extra.map { (provider, roles) ->
        keyObject(lib.native.buildSealedSlot(controllerJSON(provider, "Kit", roles), "Kit", null, ByteArray(32).also(java.security.SecureRandom()::nextBytes)))
    }
    val sorted = controllers.sortedBy {
        val key = (it as KeyJson.Obj).fields.getValue("key") as KeyJson.Obj
        keyID(java.util.Base64.getDecoder().decode(key.string("signing")))
    }
    val changed = KeyJson.Obj(ring.fields + mapOf("controllers" to KeyJson.Array(sorted), "slots" to KeyJson.Array(slots),
        "recoverThreshold" to KeyJson.Number("1"), "threshold" to KeyJson.Number(if (second == null) "1" else "2")))
    lib.changeKeyring(encodeKeyJSON(changed).toByteArray())
}

class ControllerSessionBridgeTest {
    @Test fun engineApprovesAndRevokesWithPersistedSeparateController() = runBlocking {
        val home = Files.createTempDirectory("colophon-controller-bridge").toFile()
        try {
            val store = MemoryRecordStore()
            fun config(name: String) = SessionConfiguration(name, namespaces = listOf("notes"), privateHome = File(home, name),
                keys = SoftwareKeys.stored(File(home, "$name.member")), store = store,
                ownerController = RawControllerProvider(SoftwareKeys.stored(File(home, "$name.controller"))))
            val original = SessionWorker(config("original"))
            var snapshot = original.create()
            val memberID = snapshot.core!!.me.id
            snapshot = original.write(DomainCommand("notes", "createNotebook", """{"id":"n","title":"History"}""".toByteArray()), snapshot.revision).second
            original.saveCheckpoint(); original.closeCoreNow()
            val reopened = SessionWorker(config("original"))
            assertEquals(SessionPhase.Ready, reopened.restore().phase)
            ColophonLibrary.open(store.read(store.paths().filter { it.startsWith("authority/") }), config("original").keys).use {
                val ring = keyObject(it.keyring())
                val controllers = ring.array("controllers").map { controller ->
                    val value = controller as KeyJson.Obj
                    KeyJson.Obj(value.fields + ("label" to KeyJson.Text("Relabeled controller")))
                }
                val changed = KeyJson.Obj(ring.fields + ("controllers" to KeyJson.Array(controllers)))
                reopened.changeKeyring(encodeKeyJSON(changed).toByteArray(), null, listOf(config("original").ownerController!!))
            }
            val joining = SessionWorker(config("joining"))
            assertTrue(joining.restore().phase is SessionPhase.WaitingForApproval)
            val request = reopened.refresh().core!!.requests.single()
            val approved = reopened.approve(request.record, null)
            assertEquals(memberID, approved.core!!.me.id)
            assertEquals(2, approved.core!!.members.size)
            assertEquals(SessionPhase.Ready, joining.refresh().phase)
            assertTrue(joining.core.query("notes", "read", "{}".toByteArray()).decodeToString().contains("History"))
            reopened.revoke(request.id)
            assertEquals(SessionPhase.Denied, joining.refresh().phase)
            reopened.closeCoreNow(); joining.closeCoreNow()
        } finally { home.deleteRecursively() }
    }

    @Test fun sessionKitRestorePublishesAuthorityAndGrantsNewMember() = runBlocking {
        val home = Files.createTempDirectory("colophon-controller-kit").toFile()
        try {
            val member = SoftwareKeys.ephemeral(); val owner = RawControllerProvider(SoftwareKeys.ephemeral())
            val kit = RawControllerProvider(SoftwareKeys.ephemeral())
            val records = ColophonLibrary.create(member, "Keys", "Original", listOf("notes"), owner).use { lib ->
                lib.write("notes", "createNotebook", """{"id":"n","title":"Kit history"}""".toByteArray()).get()
                enableTestKit(lib, kit)
                lib.records
            }
            val store = MemoryRecordStore(records)
            val replacementKeys = SoftwareKeys.ephemeral(); val replacementOwner = RawControllerProvider(SoftwareKeys.ephemeral())
            val configuration = SessionConfiguration("Replacement", namespaces = listOf("notes"), privateHome = home,
                keys = replacementKeys, ownerController = replacementOwner, store = store)
            val session = SessionWorker(configuration)
            assertTrue(session.restore().phase is SessionPhase.WaitingForApproval)
            assertEquals(SessionPhase.Ready, session.restoreFromKit(listOf(kit)).phase)
            assertTrue(session.core.query("notes", "read", "{}".toByteArray()).decodeToString().contains("Kit history"))
            session.saveCheckpoint(); session.closeCoreNow()
            val reopened = SessionWorker(configuration)
            assertEquals(SessionPhase.Ready, reopened.restore().phase)
            val request = ColophonLibrary.requestAccess(reopened.core.snapshot(listOf("notes"), emptyMap()).libraryID,
                SoftwareKeys.ephemeral(), "Agent", MemberKind.AGENT, listOf("notes"), listOf(Access.READ))
            reopened.approve(request.record, null)
            assertEquals(3, reopened.core.snapshot(listOf("notes"), emptyMap()).members.size)
            reopened.closeCoreNow()
        } finally { home.deleteRecursively() }
    }

    @Test fun memberOnlyConfigurationCannotCreateAuthority() = runBlocking {
        val home = Files.createTempDirectory("colophon-controller-required").toFile()
        try {
            val store = MemoryRecordStore()
            val worker = SessionWorker(SessionConfiguration("Member", namespaces = listOf("notes"), privateHome = home,
                keys = SoftwareKeys.ephemeral(), store = store))
            try { worker.create(); fail("Creation needs a separate controller") }
            catch (_: BindingException.KeyProvider) { }
            assertTrue(store.paths().isEmpty())
        } finally { home.deleteRecursively() }
    }

    @Test fun presenceWindowMustAllowBothSigningRounds() {
        assertEquals(30, KeystorePresence(30).validitySeconds)
        try { KeystorePresence(0); fail("Invalid validity") } catch (_: IllegalArgumentException) { }
        try { KeystorePresence(30, 0); fail("Invalid authentication types") } catch (_: IllegalArgumentException) { }
    }
}
