package org.luff.colophon.session

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.luff.colophon.session.ColophonSession
import com.luff.colophon.session.DomainCommand
import com.luff.colophon.session.Json
import com.luff.colophon.session.SessionConfiguration
import com.luff.colophon.session.SessionPhase
import com.luff.colophon.session.blobData
import com.luff.colophon.session.list
import com.luff.colophon.session.obj
import com.luff.colophon.session.putBlob
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.UUID

/**
 * The 0.5 session on Android itself: the native library from the AAR, the member and owner keys in Android Keystore
 * (signing and ECDH done by Keystore), the device key sealed by a Keystore AES key, and the record store in
 * app-private storage; create, write, read a blob, lock and unlock, and a cold reopen from what is stored. No home.
 */
@RunWith(AndroidJUnit4::class)
class OnDeviceSessionTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val tag = "colophon-test-${UUID.randomUUID().toString().take(8)}"
    private val library = tag.replace("colophon-test-", "t")

    private fun session() = ColophonSession(SessionConfiguration(
        memberLabel = "Android device", namespaces = listOf("notes"), medium = AndroidSession.medium(context, library),
        privateDirectory = AndroidSession.privateDirectory(context, library), keys = AndroidSession.memberKeys(context, "$tag.member"),
        ownerController = AndroidSession.memberKeys(context, "$tag.owner"), createWithoutHome = true,
        deviceSecrets = AndroidSession.deviceSecrets(context, "$tag.device")))

    private suspend fun notes(s: ColophonSession) = Json.obj(s.view("notes"))!!.obj("value")!!.list("admitted")!!.size

    @After fun tearDown() {
        File(context.noBackupFilesDir, "colophon/$library").deleteRecursively()
        File(context.noBackupFilesDir, "colophon/device-keys").deleteRecursively()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in store.aliases().toList()) if (alias.startsWith(tag)) store.deleteEntry(alias)
    }

    @Test fun createWriteLockAndReopenWithKeystoreKeys() = runBlocking<Unit> {
        val first = session()
        first.create()
        assertEquals("${first.state.value}", SessionPhase.Ready, first.phase)
        first.perform(DomainCommand("notes", "note.put", "{\"id\":\"a\",\"text\":\"a\"}"), first.observedRevision)
        val bytes = ByteArray(100_000) { (it % 251).toByte() }
        val blob = first.putBlob(bytes, "notes", "application/octet-stream", "r")
        assertArrayEquals(bytes, first.blobData("notes", blob.digest))
        assertEquals(2, notes(first))
        first.lock()
        assertEquals(SessionPhase.Locked, first.phase)
        first.unlock()
        assertEquals(SessionPhase.Ready, first.phase)
        first.flushCheckpoint()
        first.shutdown()
        assertTrue(AndroidSession.privateDirectory(context, library).listFiles()!!.any { it.name.startsWith("saved-") })

        val again = session()
        again.restore()
        assertEquals("${again.state.value}", SessionPhase.Ready, again.phase)
        assertEquals(2, notes(again))
        again.perform(DomainCommand("notes", "note.put", "{\"id\":\"b\",\"text\":\"b\"}"), again.observedRevision)
        assertEquals(3, notes(again))
        again.shutdown()
    }
}
