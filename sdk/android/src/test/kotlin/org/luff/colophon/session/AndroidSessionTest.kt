package org.luff.colophon.session

import com.luff.colophon.session.ColophonSession
import com.luff.colophon.session.DomainCommand
import com.luff.colophon.session.Json
import com.luff.colophon.session.MemoryDeviceSecrets
import com.luff.colophon.session.MemoryMedium
import com.luff.colophon.session.P256
import com.luff.colophon.session.SessionConfiguration
import com.luff.colophon.session.SessionFailure
import com.luff.colophon.session.SessionKeyFailure
import com.luff.colophon.session.SessionPhase
import com.luff.colophon.session.SoftwareKeys
import com.luff.colophon.session.list
import com.luff.colophon.session.obj
import com.luff.colophon.session.string
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.luff.colophon.keys.CredentialClient
import org.luff.colophon.keys.PasskeyProvider
import org.luff.colophon.keys.apkKeyHashOrigin
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import javax.crypto.KeyGenerator

/**
 * A synthetic Credential Manager client: a software P-256 credential that answers `get` requests the way a platform
 * authenticator does (authenticator data for the rp with UP and UV, client data naming the challenge and origin, a DER
 * ES256 signature over both, and the PRF extension's `results.first` when a salt is asked for). Not a device.
 */
private class SyntheticCredentials(private val prfSupported: Boolean = true, private val origin: String = "https://id.luff.works") : CredentialClient {
    val key = P256.generate()
    val rp = "id.luff.works"
    val credential = byteArrayOf(1)
    var gets = 0
    var prfGets = 0
    val descriptor: ByteArray get() = Json.write(mapOf("credential" to Base64.getEncoder().encodeToString(credential), "form" to "webauthn", "rp" to rp,
        "signing" to Base64.getEncoder().encodeToString(P256.point(key.public as java.security.interfaces.ECPublicKey)))).toByteArray()
    override suspend fun create(requestJson: String): String = throw UnsupportedOperationException("registration is not used here")
    override suspend fun get(requestJson: String): String {
        gets++
        val request = Json.obj(requestJson)!!
        val challenge = request.string("challenge")!!
        val salt = request.obj("extensions")?.obj("prf")?.obj("eval")?.string("first")
        val sha = MessageDigest.getInstance("SHA-256")
        val authData = sha.digest(rp.toByteArray()) + byteArrayOf(5, 0, 0, 0, 0)
        val clientData = Json.write(mapOf("type" to "webauthn.get", "challenge" to challenge, "origin" to origin)).toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(authData + sha.digest(clientData)); sign() }
        val url = { b: ByteArray -> P256.base64url(b) }
        val response = mutableMapOf<String, Any?>("rawId" to url(credential), "response" to mapOf(
            "signature" to url(signature), "authenticatorData" to url(authData), "clientDataJSON" to url(clientData)))
        if (salt != null && prfSupported) {
            prfGets++
            val output = sha.digest("synthetic-prf".toByteArray() + Base64.getUrlDecoder().decode(salt))
            response["clientExtensionResults"] = mapOf("prf" to mapOf("results" to mapOf("first" to url(output))))
        }
        return Json.write(response)
    }
}

class AndroidSessionTest {
    private fun session(medium: MemoryMedium, owner: com.luff.colophon.session.AsyncKeyProvider, dir: File = Files.createTempDirectory("colophon-android-session-").toFile()) =
        ColophonSession(SessionConfiguration(memberLabel = "Android test", namespaces = listOf("notes"), medium = medium, privateDirectory = dir,
            keys = SoftwareKeys(), ownerController = owner, createWithoutHome = true, deviceSecrets = MemoryDeviceSecrets()))

    @Test fun aPasskeyOwnerCreatesWithItsPrfSlotAndApprovesADevice() = runBlocking<Unit> {
        val credentials = SyntheticCredentials()
        val owner = PasskeyController(PasskeyProvider.restore(credentials.descriptor, credentials), listOf("https://id.luff.works"))
        val medium = MemoryMedium()
        val first = session(medium, owner)
        val second = session(medium, SoftwareKeys())
        try {
            first.create()
            assertEquals("${first.state.value}", SessionPhase.Ready, first.phase)
            val atCreation = credentials.gets
            assertTrue("the creation asked the passkey for its PRF and its signature", credentials.prfGets >= 1 && atCreation >= 2)
            first.perform(DomainCommand("notes", "note.put", "{\"id\":\"a\",\"text\":\"a\"}"), first.observedRevision)
            second.restore()
            assertTrue("${second.phase}", second.phase is SessionPhase.WaitingForApproval)
            first.refresh()
            first.approve(first.requests.single())
            assertTrue("approving opened the owner's PRF slot and signed with an assertion", credentials.prfGets >= 2 && credentials.gets >= atCreation + 2)
            second.refresh()
            assertEquals("${second.state.value}", SessionPhase.Ready, second.phase)
            val view = Json.obj(second.view("notes"))!!
            assertEquals(1, view.obj("value")!!.list("admitted")!!.size)
        } finally { first.shutdown(); second.shutdown() }
    }

    // The documented call for a real Android app: its assertions carry the app's platform origin, which must be in
    // `origins` as well as `authorityOrigins` (spec §3.1; core descriptor.rs general rule).
    @Test fun anAndroidAppOriginCreatesAndApproves() = runBlocking<Unit> {
        val appOrigin = apkKeyHashOrigin(ByteArray(64) { 3 })
        val credentials = SyntheticCredentials(origin = appOrigin)
        val owner = PasskeyController(PasskeyProvider.restore(credentials.descriptor, credentials), listOf(appOrigin, "https://id.luff.works"))
        val d = owner.keyDescriptor()
        assertEquals(listOf(appOrigin), d.origins)
        val medium = MemoryMedium()
        val first = session(medium, owner)
        val second = session(medium, SoftwareKeys())
        try {
            first.create()
            assertEquals("${first.state.value}", SessionPhase.Ready, first.phase)
            second.restore()
            first.refresh()
            first.approve(first.requests.single())
            second.refresh()
            assertEquals("${second.state.value}", SessionPhase.Ready, second.phase)
        } finally { first.shutdown(); second.shutdown() }
    }

    @Test fun aPasskeyWithoutPrfFailsCreationAndWritesNothing() = runBlocking<Unit> {
        val credentials = SyntheticCredentials(prfSupported = false)
        val medium = MemoryMedium()
        val first = session(medium, PasskeyController(PasskeyProvider.restore(credentials.descriptor, credentials)))
        try {
            first.create()
            val phase = first.phase
            assertTrue("$phase", phase is SessionPhase.Failed && phase.error is SessionFailure.KeysUnavailable)
            assertTrue("nothing is stored for a creation that could not build its slot", medium.listing().isEmpty())
        } finally { first.shutdown() }
    }

    @Test fun deviceKeysAreWrappedAndAReplacedWrappingKeyStartsAgain() {
        val dir = Files.createTempDirectory("colophon-android-device-keys-").toFile()
        try {
            val aes = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            val store = KeystoreDeviceSecrets(dir) { aes }
            val account = "ab".repeat(32)
            val one = store.key(account).lend { it.copyOf() }
            val two = store.key(account).lend { it.copyOf() }
            assertArrayEquals("the same key on every open", one, two)
            assertEquals(12 + 32 + 16, File(dir, "$account.key").length())
            assertTrue("the file is sealed, not the key", !File(dir, "$account.key").readBytes().toList().windowed(32).any { it == one.toList() })
            val other = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            val three = KeystoreDeviceSecrets(dir) { other }.key(account).lend { it.copyOf() }
            assertNotEquals("a lost wrapping key means a fresh device key (the history replays)", one.toList(), three.toList())
        } finally { dir.deleteRecursively() }
    }
}
