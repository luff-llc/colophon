package org.luff.colophon

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.luff.colophon.MemberKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
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
    }
}
