package com.luff.colophon

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.*

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
        keyID(Base64.getDecoder().decode(key.string("signing")))
    }
    val changed = KeyJson.Obj(ring.fields + mapOf("controllers" to KeyJson.Array(sorted), "slots" to KeyJson.Array(slots),
        "recoverThreshold" to KeyJson.Number("1"), "threshold" to KeyJson.Number(if (second == null) "1" else "2")))
    lib.changeKeyring(encodeKeyJSON(changed).toByteArray())
}

class ControllerSessionTest {
    private class Counted(private val delegate: KeyProvider = PlatformKeys.software()) : KeyProvider by delegate {
        var signs = 0
        var agreements = 0
        override fun sign(body: ByteArray): ByteArray { signs++; return delegate.sign(body) }
        override fun agree(peer: ByteArray): ByteArray { agreements++; return delegate.agree(peer) }
    }

    @Test fun twoRoundsSeparateContentAndAuthorityAndReopen() {
        val member = Counted(); val owner = Counted(); val controller = RawControllerProvider(owner)
        ColophonLibrary.create(member, "Keys", "Phone", listOf("notes"), controller).use { lib ->
            assertEquals(1, member.signs)
            assertEquals(4, owner.signs)
            assertEquals(0, owner.agreements)
            assertEquals(1, lib.members().size)
            assertNotEquals(lib.me().id, controller.controllerID())
            assertTrue(lib.keyring().decodeToString().contains("\"recoverThreshold\":0"))
            val genesis = keyObject(Base64.getDecoder().decode(keyObject(lib.records.getValue("authority/00000001.json")).string("body")))
            assertEquals("colophon/authority/4", genesis.string("protocol"))
            val layout = keyObject(Base64.getDecoder().decode(keyObject(lib.records.getValue("authority/00000004.json")).string("body")))
            assertEquals("2", (layout.fields["layout"] as KeyJson.Number).raw)
            lib.write("notes", "createNotebook", """{"id":"n","title":"Notebook"}""".toByteArray()).get()
            assertEquals(2, member.signs); assertEquals(4, owner.signs)
            ColophonLibrary.open(lib.records, member, controller).use { reopened ->
                val joining = PlatformKeys.software()
                val request = ColophonLibrary.requestAccess(lib.id, joining, "App", MemberKind.APP, listOf("notes"), listOf(Access.READ, Access.WRITE))
                reopened.approve(request.record).get()
                assertEquals(1, owner.agreements)
                assertEquals(5, owner.signs)
                ColophonLibrary.open(reopened.records, joining).use { assertTrue(it.view("notes").get().state.decodeToString().contains("Notebook")) }
                reopened.revoke(request.id).get()
                assertEquals(6, owner.signs)
            }
            ColophonLibrary.open(lib.records, member).use { opened ->
                assertTrue(opened.view("notes") is Outcome.Success)
                val before = opened.records.keys
                assertFailsWith<BindingException.KeyProvider> { opened.revoke(opened.me().id) }
                assertEquals(before, opened.records.keys)
            }
        }
    }

    @Test fun kitGenesisFailsBeforeSigningAndReusedPrincipalFails() {
        val member = Counted(); val controller = RawControllerProvider(Counted())
        assertFailsWith<BindingException.InvalidData> {
            ColophonLibrary.create(member, "Keys", "Phone", listOf("notes"), controller, RawControllerProvider(PlatformKeys.software()))
        }
        assertEquals(0, member.signs)
        assertFailsWith<BindingException.InvalidData> {
            ColophonLibrary.create(member, "Keys", "Phone", listOf("notes"), RawControllerProvider(member))
        }
    }

    @Test fun kitRestoresNewDeviceAndReadsHistory() = kitRestore(false)
    @Test fun lowerRecoveryQuorumAddsOnlyApproval() = kitRestore(true)

    private fun kitRestore(approveOnly: Boolean) {
        val member = PlatformKeys.software(); val controller = RawControllerProvider(PlatformKeys.software())
        val kit = RawControllerProvider(PlatformKeys.software())
        ColophonLibrary.create(member, "Keys", "Original", listOf("notes"), controller).use { lib ->
            lib.write("notes", "createNotebook", """{"id":"n","title":"History"}""".toByteArray()).get()
            enableTestKit(lib, kit, if (approveOnly) RawControllerProvider(PlatformKeys.software()) else null)
            val replacement = RawControllerProvider(PlatformKeys.software()); val newMember = PlatformKeys.software()
            ColophonLibrary.restoreFromKit(lib.records, newMember, replacement, "Replacement", listOf("notes"), listOf(kit)).use { restored ->
                assertTrue(restored.view("notes").get().state.decodeToString().contains("History"))
                val added = keyObject(restored.keyring()).array("controllers").map { it as KeyJson.Obj }.first {
                    keyID(Base64.getDecoder().decode((it.fields["key"] as KeyJson.Obj).string("signing"))) == replacement.controllerID()
                }
                assertEquals(if (approveOnly) listOf("approve") else listOf("approve", "control"), added.stringList("roles"))
                restored.write("notes", "addNote", """{"id":"a","notebook":"n","text":"Restored"}""".toByteArray()).get()
            }
        }
    }

    @Test fun removalRotatesVaultAndRetainedControllerReadsHistory() {
        val member = PlatformKeys.software(); val owner = RawControllerProvider(PlatformKeys.software())
        val retained = RawControllerProvider(PlatformKeys.software()); val kit = RawControllerProvider(PlatformKeys.software())
        ColophonLibrary.create(member, "Keys", "Original", listOf("notes"), owner).use { lib ->
            lib.write("notes", "createNotebook", """{"id":"n","title":"History"}""".toByteArray()).get()
            enableTestKit(lib, kit)
            lib.unlockVault()
            val added = controllerJSON(retained, "Retained", listOf("approve", "control"))
            val slot = lib.native.buildSealedSlot(added, "Retained", null, ByteArray(32) { 61 })
            lib.native.beginAddController(added, slot, listOf(owner.controllerID()), java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS).toString()).use {
                lib.native.finishAuthority(it, it.signControllerWith(owner))
            }
            val seed = ByteArray(32) { 62 }
            val slots = listOf(added, controllerJSON(kit, "Kit", listOf("recover"))).mapIndexed { index, controller ->
                lib.native.buildSealedSlot(controller, "Replacement slot", seed, ByteArray(32) { (63 + index).toByte() })
            }
            lib.removeController(owner.controllerID(), seed, slots)
            ColophonLibrary.open(lib.records, member, retained).use { opened ->
                opened.unlockVault()
                assertTrue(opened.view("notes").get().state.decodeToString().contains("History"))
                assertFailsWith<BindingException.KeyProvider> { opened.native.unlockVault(listOf(owner)) }
                val request = ColophonLibrary.requestAccess(opened.id, PlatformKeys.software(), "Reader", MemberKind.APP, listOf("notes"), listOf(Access.READ))
                opened.approve(request.record).get()
            }
        }
    }

    @Test fun externalWebauthnProviderUnlocksPrfAndApproves() {
        val member = PlatformKeys.software(); val owner = RawControllerProvider(PlatformKeys.software()); val passkey = TestAssertionProvider()
        ColophonLibrary.create(member, "Keys", "Device", listOf("notes"), owner).use { lib ->
            lib.unlockVault()
            val slot = lib.native.beginPrfSlot(passkey.descriptor(), ByteArray(32) { 51 }).use {
                lib.native.finishPrfSlot(it, passkey.assert(it.challenge(), it.salt()), "Passkey", null, ByteArray(32) { 52 })
            }
            lib.native.beginAddPasskey(controllerJSON(passkey, "Passkey", listOf("approve", "control")), slot, listOf(owner.controllerID()), java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS).toString()).use {
                lib.native.finishAuthority(it, it.signControllerWith(owner))
            }
            ColophonLibrary.open(lib.records, member, passkey).use { opened ->
                val request = ColophonLibrary.requestAccess(opened.id, PlatformKeys.software(), "Agent", MemberKind.AGENT, listOf("notes"), listOf(Access.READ))
                val before = opened.records.keys
                passkey.missingPrf = true
                assertFailsWith<BindingException.KeyProvider> { opened.approve(request.record) }
                assertEquals(before, opened.records.keys)
                passkey.missingPrf = false
                opened.approve(request.record).get()
                assertEquals(3, passkey.prfCalls)
                assertEquals(1, passkey.authorityCalls)
            }
        }
    }
}

internal class TestAssertionProvider : ControllerProvider {
    private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val public = PlatformKeys(pair, KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()).signingPublicKey()
    var prfCalls = 0; var authorityCalls = 0; var missingPrf = false
    override fun descriptor() = """{"form":"webauthn","signing":"${Base64.getEncoder().encodeToString(public)}","rp":"id.luff.works","credential":"AQ=="}""".toByteArray()
    override fun form() = KeyForm.WEBAUTHN
    override fun agree(peer: ByteArray): ByteArray = error("WebAuthn cannot agree")
    override fun sign(body: ByteArray): ByteArray = error("WebAuthn cannot raw-sign")
    override fun assert(challenge: String, prfSalt: ByteArray?): WebauthnResult {
        if (prfSalt == null) authorityCalls++ else { assertEquals(32, prfSalt.size); prfCalls++ }
        val client = """{"type":"webauthn.get","challenge":"$challenge","origin":"https://id.luff.works"}""".toByteArray()
        val auth = MessageDigest.getInstance("SHA-256").digest("id.luff.works".toByteArray()) + byteArrayOf(5, 0, 0, 0, 0)
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(pair.private); update(auth + MessageDigest.getInstance("SHA-256").digest(client))
        }.sign()
        return WebauthnResult(signature, auth, client, if (prfSalt != null && !missingPrf) ByteArray(32) { 77 } else null)
    }
}
