package org.luff.colophon

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.luff.colophon.MemberKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyStore
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class SessionInstrumentedTest {
    private lateinit var root: File
    private val aliases = mutableListOf<String>()

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        root = File(context.filesDir, "colophon-instrumented-${UUID.randomUUID()}")
        assertTrue(root.mkdirs())
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in aliases) {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        }
    }

    private fun keys(prefix: String): KeystoreKeys {
        aliases += "$prefix.signing"
        aliases += "$prefix.agreement"
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        return KeystoreKeys.openOrCreate(context, prefix)
    }

    @Test
    fun keystoreCreateWriteQueryRevokeAndColdReopen() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val ownerKeys = keys("colophon.owner.${UUID.randomUUID()}")
        assertEquals(65, ownerKeys.signingPublicKey().size)
        assertEquals(64, ownerKeys.sign("body".toByteArray()).size)

        val libraryDir = File(root, "library")
        val store = FileRecordStore(libraryDir)
        val ownerHome = File(root, "owner")
        val owner = ColophonSession(
            SessionConfiguration(
                memberLabel = "Android owner",
                namespaces = listOf("reading.saved", "notes"),
                privateHome = ownerHome,
                keys = ownerKeys,
                store = store,
            ),
        )
        owner.restore()
        assertEquals(SessionPhase.NoLibrary, owner.phase.value)
        owner.create()
        assertEquals(SessionPhase.Ready, owner.phase.value)
        owner.perform(DomainCommand.saveLink(url = "https://example.com/a", title = "A"), owner.observedRevision)
        val links = NamespaceStore.savedLinks(owner).load(SavedLinksQuery())
        assertEquals(1, links.size)
        assertEquals("https://example.com/a", links[0].url)

        val memberKeys = keys("colophon.member.${UUID.randomUUID()}")
        val memberHome = File(root, "member")
        val member = ColophonSession(
            SessionConfiguration(
                memberLabel = "Android member",
                memberKind = MemberKind.APP,
                namespaces = listOf("reading.saved", "notes"),
                privateHome = memberHome,
                keys = memberKeys,
                store = store,
            ),
        )
        member.restore()
        assertTrue(member.phase.value is SessionPhase.WaitingForApproval)
        owner.refresh()
        val request = owner.requests.value.first()
        owner.approve(request)
        member.refresh()
        assertEquals(SessionPhase.Ready, member.phase.value)

        owner.revoke(request.id)
        member.refresh()
        assertEquals(SessionPhase.Denied, member.phase.value)

        val reopened = ColophonSession(
            SessionConfiguration(
                memberLabel = "Android owner",
                namespaces = listOf("reading.saved", "notes"),
                privateHome = ownerHome,
                keys = KeystoreKeys.openOrCreate(context, aliases[0].removeSuffix(".signing")),
                store = FileRecordStore(libraryDir),
            ),
        )
        reopened.restore()
        assertEquals(SessionPhase.Ready, reopened.phase.value)
        assertEquals(1, NamespaceStore.savedLinks(reopened).load(SavedLinksQuery()).size)
        val stored = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val private = stored.getKey(aliases[0], null)
        assertTrue(private != null)
        assertEquals("Keystore private keys are non-exportable", null, private?.encoded)
        assertFalse("This image has no StrongBox; generation must fall back to the TEE", ownerKeys.usedStrongBox)
    }

    @Test
    fun keystoreMaterialIsDeferredAndAPartialOrMissingIdentityFailsClosed() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefix = "colophon.lazy.${UUID.randomUUID()}"
        aliases += "$prefix.signing"
        aliases += "$prefix.agreement"
        val deferred = KeystoreKeys.openOrCreate(context, prefix)
        val before = keystore()
        assertFalse(before.containsAlias("$prefix.signing"))
        assertFalse(before.containsAlias("$prefix.agreement"))
        assertEquals(65, deferred.signingPublicKey().size)
        val created = keystore()
        assertTrue(created.containsAlias("$prefix.signing"))
        assertTrue(created.containsAlias("$prefix.agreement"))
        assertEquals(null, created.getKey("$prefix.signing", null)?.encoded)

        val libraryDir = File(root, "library")
        val home = File(root, "home")
        val session = ColophonSession(
            SessionConfiguration(
                memberLabel = "Owner",
                namespaces = listOf("reading.saved"),
                privateHome = home,
                keys = deferred,
                store = FileRecordStore(libraryDir),
            ),
        )
        session.restore()
        session.create()
        session.perform(DomainCommand.saveLink(url = "https://example.com/k", title = "K"), session.observedRevision)
        val beforeRecords = recordPaths(libraryDir)
        session.close()

        created.deleteEntry("$prefix.agreement")
        val incomplete = ColophonSession(
            SessionConfiguration(
                memberLabel = "Owner",
                namespaces = listOf("reading.saved"),
                privateHome = home,
                keys = KeystoreKeys.openOrCreate(context, prefix),
                store = FileRecordStore(libraryDir),
            ),
        )
        incomplete.restore()
        assertTrue("incomplete alias must fail closed: ${incomplete.phase.value}", incomplete.phase.value is SessionPhase.Failed)
        assertFalse(incomplete.phase.value is SessionPhase.WaitingForApproval)
        val afterIncomplete = keystore()
        assertTrue("the surviving alias must be left in place", afterIncomplete.containsAlias("$prefix.signing"))
        assertFalse("the missing alias must not be recreated or deleted as a pair", afterIncomplete.containsAlias("$prefix.agreement"))
        assertEquals(beforeRecords, recordPaths(libraryDir))
        incomplete.close()

        afterIncomplete.deleteEntry("$prefix.signing")
        val missing = ColophonSession(
            SessionConfiguration(
                memberLabel = "Owner",
                namespaces = listOf("reading.saved"),
                privateHome = home,
                keys = KeystoreKeys.openOrCreate(context, prefix),
                store = FileRecordStore(libraryDir),
            ),
        )
        missing.restore()
        assertTrue("a lost alias pair must not pair as a new member: ${missing.phase.value}", missing.phase.value is SessionPhase.Failed)
        assertFalse(missing.phase.value is SessionPhase.WaitingForApproval)
        assertEquals(beforeRecords, recordPaths(libraryDir))
        missing.close()
    }

    @Test
    fun renameAt2ReportsEexistAndShorterConflictsStayPut() {
        val from = File(root, "from.json")
        val to = File(root, "to.json")
        from.writeBytes("body".toByteArray())
        assertEquals("renameat2 must succeed on this image", 0, AtomicFile.renameNoReplace(from.path, to.path))
        assertTrue(to.isFile)
        assertFalse(from.exists())

        val staged = File(root, "staged.json")
        staged.writeBytes("short".toByteArray())
        assertEquals(
            "EEXIST must be captured inside the native call, not reported as -1",
            17,
            AtomicFile.renameNoReplace(staged.path, to.path),
        )
        assertEquals("body", to.readText())

        val linkSource = File(root, "link-source")
        linkSource.writeBytes("x".toByteArray())
        try {
            Files.createLink(File(root, "link-dest").toPath(), linkSource.toPath())
            fail("link(2) is denied for private app files; publication must use renameat2")
        } catch (_: Exception) {
        }

        val published = File(root, "published.json")
        AtomicFile.write("longer-record".toByteArray(), published, immutable = true)
        try {
            AtomicFile.write("short".toByteArray(), published, immutable = true)
            fail("expected conflict")
        } catch (error: StorageException) {
            assertTrue(
                "shorter conflict must be Conflict, not ${error.javaClass.simpleName}: ${error.message}",
                error is StorageException.Conflict,
            )
        }
        assertEquals("longer-record", published.readText())
        AtomicFile.write("longer-record".toByteArray(), published, immutable = true)

        val store = FileRecordStore(File(root, "records"))
        val path = "authority/00000001.json"
        store.append(mapOf(path to "longer-record".toByteArray()))
        store.append(mapOf(path to "longer-record".toByteArray()))
        try {
            store.append(mapOf(path to "no".toByteArray()))
            fail("expected conflict")
        } catch (error: StorageException) {
            assertTrue(error is StorageException.Conflict)
        }
        assertEquals("longer-record", File(root, "records/authority/00000001.json").readText())
    }

    @Test
    fun unreadableDirectoryAndInternalSymlinkAreNotAnEmptyLibrary() {
        val folder = File(root, "library")
        val authority = File(folder, "authority")
        assertTrue(authority.mkdirs())
        File(authority, "00000001.json").writeBytes("one".toByteArray())
        val outside = File(root, "outside.json")
        outside.writeBytes("secret".toByteArray())
        Files.createSymbolicLink(File(authority, "00000002.json").toPath(), outside.toPath())
        try {
            FileRecordStore(folder).read()
            fail("an internal symlink must be rejected")
        } catch (error: StorageException) {
            assertTrue(error is StorageException.InvalidPath)
        }
        assertEquals("secret", outside.readText())
        assertTrue(File(authority, "00000002.json").delete())

        Files.setPosixFilePermissions(authority.toPath(), emptySet())
        try {
            val read = FileRecordStore(folder).read()
            fail("unreadable directory returned ${read.keys}")
        } catch (error: StorageException) {
            assertTrue("was ${error.javaClass.simpleName}: ${error.message}", error is StorageException.Unavailable)
        } finally {
            Files.setPosixFilePermissions(
                authority.toPath(),
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
            )
        }
    }

    private fun keystore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun recordPaths(folder: File): Set<String> {
        val prefix = folder.canonicalFile.path + File.separator
        return folder.walkTopDown()
            .filter { it.isFile }
            .map { it.canonicalFile.path.removePrefix(prefix) }
            .toSet()
    }
}
