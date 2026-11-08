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

class ControllerSessionBridgeTest {
    @Test fun revocationKeepsAdmittedContentAndRejectsLaterOfflineWrites() = runBlocking {
        val home = Files.createTempDirectory("colophon-controller-kept").toFile()
        val memberKeys = SoftwareKeys.ephemeral()
        val ownerKeys = SoftwareKeys.ephemeral()
        val store = MemoryRecordStore()
        val configuration = SessionConfiguration("Owner", namespaces = listOf("reading.saved"), privateHome = home,
            keys = ownerKeys, ownerController = RawControllerProvider(SoftwareKeys.ephemeral()), store = store)
        val owner = SessionWorker(configuration)
        try {
            val created = owner.create()
            owner.write(DomainCommand.saveLink("from-owner", "https://example.com/owner", "Owner"), created.revision)
            val request = ColophonLibrary.requestAccess(created.core!!.libraryID, memberKeys, "Member", MemberKind.APP,
                listOf("reading.saved"), listOf(Access.READ, Access.WRITE))
            owner.approve(request.record, null)
            ColophonLibrary.open(store.read(), memberKeys).use { offline ->
                val written = mutableListOf<String>()
                offline.write("reading.saved", "capture",
                    """{"id":"from-member","url":"https://example.com/member","title":"Member"}""".toByteArray(), written).get()
                val accepted = offline.recordsAt(written)
                store.append(accepted)
                owner.refresh()
                val acceptedBody = java.util.Base64.getDecoder().decode(keyObject(accepted.values.single()).string("body"))
                val acceptedDigest = java.security.MessageDigest.getInstance("SHA-256").digest(acceptedBody)
                    .joinToString("") { "%02x".format(it.toInt() and 255) }
                owner.revoke(request.id)
                val revocation = store.read(store.paths().filter { it.startsWith("authority/") }).values.map {
                    keyObject(java.util.Base64.getDecoder().decode(keyObject(it).string("body")))
                }.single { it.string("kind") == "revoke" }
                assertEquals(setOf(acceptedDigest), revocation.stringList("kept").toSet())

                written.clear()
                offline.write("reading.saved", "capture",
                    """{"id":"after-revocation","url":"https://example.com/late","title":"Late"}""".toByteArray(), written).get()
                store.append(offline.recordsAt(written))
                owner.refresh()
                fun links(worker: SessionWorker) = decodeSavedLinks(worker.core.query("reading.saved", "read", "{}".toByteArray()), 100)
                    .map { it.id }.sorted()
                assertEquals(listOf("from-member", "from-owner"), links(owner))
                ColophonLibrary.open(store.read(), ownerKeys).use { verified ->
                    val view = verified.view("reading.saved").get()
                    assertTrue((view.held + view.refused).any { it.author == request.id && it.reason.contains("revoked", ignoreCase = true) })
                }
                owner.saveCheckpoint()
                owner.closeCoreNow()
                val reopened = SessionWorker(configuration)
                try {
                    assertEquals(SessionPhase.Ready, reopened.restore().phase)
                    assertEquals(listOf("from-member", "from-owner"), links(reopened))
                } finally { reopened.closeCoreNow() }
            }
        } finally { owner.closeCoreNow(); home.deleteRecursively() }
    }

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
            val store = MemoryRecordStore()
            val originalConfig = SessionConfiguration.app(home, "Original", listOf("notes"), member,
                ownerController = owner, recoveryKit = kit, recoveryLabel = "Offline backup").copy(store = store)
            val original = SessionWorker(originalConfig)
            val created = original.create()
            assertEquals(SessionPhase.Ready, created.phase)
            assertEquals(4, store.paths().count { it.startsWith("authority/") })
            val genesis = keyObject(java.util.Base64.getDecoder().decode(
                keyObject(store.read(listOf("authority/00000001.json")).getValue("authority/00000001.json")).string("body")))
            val ring = genesis.fields.getValue("keyring") as KeyJson.Obj
            assertEquals("1", (ring.fields["recoverThreshold"] as KeyJson.Number).raw)
            assertEquals(2, ring.array("controllers").size)
            val kitSlot = ring.array("slots").map { it as KeyJson.Obj }.single { it.stringList("controllers") == listOf(kit.controllerID()) }
            assertEquals("sealed", kitSlot.string("kind"))
            assertEquals("Offline backup", kitSlot.string("label"))
            original.write(DomainCommand("notes", "createNotebook", """{"id":"n","title":"Kit history"}""".toByteArray()), created.revision)
            original.closeCoreNow()
            val replacementKeys = SoftwareKeys.ephemeral(); val replacementOwner = RawControllerProvider(SoftwareKeys.ephemeral())
            val configuration = SessionConfiguration("Replacement", namespaces = listOf("notes"), privateHome = File(home, "replacement"),
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
