package org.luff.colophon.keys

import com.luff.colophon.*
import java.security.KeyPairGenerator
import java.security.ProviderException
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.Assert.*

private fun assertContentEquals(expected: ByteArray?, actual: ByteArray?) = assertArrayEquals(expected, actual)
private inline fun <reified T : Throwable> assertFailsWith(block: () -> Unit): T {
    try { block() } catch (error: Throwable) {
        if (error is T) return error
        throw AssertionError("Expected ${T::class.java.name}, got ${error.javaClass.name}", error)
    }
    throw AssertionError("Expected ${T::class.java.name}")
}

class KeyProvidersTest {
    private val f = W7Fixture
    private fun repeated(value: Int) = ByteArray(32) { value.toByte() }
    private fun b64(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun sign(action: HostAction, name: String): List<SignatureResult> {
        val expected = f.signing.getValue(name)
        assertEquals(expected.size, action.signingSteps().size)
        action.signingSteps().zip(expected).forEach { (step, result) -> assertContentEquals(result.body, step.body) }
        return expected.map { it.result }
    }
    private inner class Credentials : CredentialClient {
        val requests = mutableListOf<KeyJson.Obj>()
        var missingPRF = false
        var outputSize = 32
        var rawID = "AQ"
        var error: Exception? = null
        var rp = "id.luff.works"
        override suspend fun create(requestJson: String): String {
            error?.let { throw it }
            requests.add(keyObject(requestJson.toByteArray()))
            return """{"rawId":"$rawID","response":{"attestationObject":"${b64(f.registration)}"},"clientExtensionResults":{"prf":{"results":{"first":"${b64(repeated(99))}"}}}}"""
        }
        override suspend fun get(requestJson: String): String {
            error?.let { throw it }
            val request = keyObject(requestJson.toByteArray())
            requests.add(request)
            assertEquals(rp, request.string("rpId"))
            assertEquals("required", request.string("userVerification"))
            val allowed = request.array("allowCredentials")
            assertEquals(1, allowed.size)
            assertEquals("AQ", (allowed.single() as KeyJson.Obj).string("id"))
            val p = f.prf[0].result
            val ext = if (missingPRF) "" else """, "clientExtensionResults":{"prf":{"results":{"first":"${b64(ByteArray(outputSize) { 71 })}"}}}"""
            return """{"rawId":"$rawID","response":{"signature":"${b64(p.signature)}","authenticatorData":"${b64(p.authenticatorData)}","clientDataJSON":"${b64(p.clientData)}"}$ext}"""
        }
    }
    @Test fun registrationAssertionAndSlotOpening(): Unit = runBlocking {
        val credentials = Credentials()
        val provider = PasskeyProvider.register("id.luff.works", "Colophon", byteArrayOf(1), "user", "User", credentials)
        assertEquals(KeyForm.WEBAUTHN, provider.form)
        val registration = credentials.requests.single()
        assertEquals("none", registration.string("attestation"))
        val parameters = registration.array("pubKeyCredParams").single() as KeyJson.Obj
        assertEquals("-7", (parameters.fields.getValue("alg") as KeyJson.Number).raw)
        assertFalse(provider.descriptor().decodeToString().contains("agreement"))
        val first = beginCreate(f.member, f.owner, repeated(21), "Keys", "Device", listOf("notes"), "2026-11-08T12:00:00Z", repeated(22))
        val final = first.use { it.advanceCreate(sign(it, "create").map { it.signature }) }
        val records = final.use { it.finishAuthority(sign(it, "createFinal")) }
        NativeLibrary.open(records, f.member).use { lib ->
            val option = lib.beginUnlockSlots().first()
            lib.finishUnlockSlot(option, listOf(SlotSecret.Ecdh(f.ownerSecret)))
            val slot = lib.beginPrfSlot(provider.descriptor(), repeated(31)).use { action ->
                assertEquals(f.prf[0].challenge, action.challenge())
                val assertion = provider.assert(action.challenge(), action.salt())
                assertContentEquals(f.prf[0].result.prf, assertion.prf)
                assertContentEquals(f.prf[0].result.clientData, assertion.clientData)
                val request = credentials.requests.last()
                assertEquals(action.challenge(), request.string("challenge"))
                val extensions = request.fields.getValue("extensions") as KeyJson.Obj
                val prf = extensions.fields.getValue("prf") as KeyJson.Obj
                assertEquals(b64(action.salt()), (prf.fields.getValue("eval") as KeyJson.Obj).string("first"))
                lib.finishPrfSlot(action, assertion, "Passkey", null, repeated(32))
            }
            val ownerID = (option.inputs.single() as SlotInput.Ecdh).controller
            lib.beginAddPasskey(f.passkey, slot, listOf(ownerID), "2026-11-08T12:00:00Z").use {
                lib.finishAuthority(it, sign(it, "addPasskey"))
            }
            NativeLibrary.open(lib.records(), f.member).use { opened ->
                val prfOption = opened.beginUnlockSlots().first { it.inputs.singleOrNull() is SlotInput.Prf }
                assertFailsWith<BindingException.InvalidData> { opened.finishUnlockSlot(prfOption, listOf(SlotSecret.Prf(repeated(0)))) }
                val input = prfOption.inputs.single() as SlotInput.Prf
                val output = provider.assert(b64(repeated(91)), input.salt).prf!!
                opened.finishUnlockSlot(prfOption, listOf(SlotSecret.Prf(output)))
            }
        }
    }
    @Test fun passkeyMissingOutputsForeignCredentialAndCancellation() = runBlocking {
        val credentials = Credentials()
        val provider = PasskeyProvider.register("id.luff.works", "Colophon", byteArrayOf(1), "u", "U", credentials)
        credentials.missingPRF = true
        assertEquals(KeyOutcome.UNSUPPORTED_HERE, keyOutcome(assertFailsWith<BindingException.KeyProvider> { provider.assert(f.prf[0].challenge, repeated(1)) }))
        assertNull(provider.assert(f.prf[0].challenge).prf)
        credentials.missingPRF = false
        credentials.outputSize = 31
        assertEquals(KeyOutcome.UNSUPPORTED_HERE, keyOutcome(assertFailsWith<BindingException.KeyProvider> { provider.assert(f.prf[0].challenge, repeated(1)) }))
        credentials.rawID = "Ag"
        assertEquals(KeyOutcome.CREDENTIAL_MISSING, keyOutcome(assertFailsWith<BindingException.KeyProvider> { provider.assert(f.prf[0].challenge) }))
        credentials.error = CancellationException("cancel")
        assertEquals(KeyOutcome.CANCELLED, keyOutcome(assertFailsWith<BindingException.KeyProvider> { provider.assert(f.prf[0].challenge) }))
    }
    @Test fun registrationParserAndOrigin() = runBlocking {
        val credentials = Credentials()
        assertFailsWith<BindingException.InvalidData> { PasskeyProvider.register("foreign.example", "Foreign", byteArrayOf(1), "u", "U", credentials) }
        credentials.rawID = "Ag"
        assertEquals(KeyOutcome.CREDENTIAL_MISSING, keyOutcome(assertFailsWith<BindingException.KeyProvider> {
            PasskeyProvider.register("id.luff.works", "Colophon", byteArrayOf(1), "u", "U", credentials)
        }))
        assertEquals("android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", apkKeyHashOrigin(byteArrayOf()))
    }
    private class Store(override val apiLevel: Int = 35) : OwnerKeyStore {
        val keys = mutableMapOf<String, StoredOwnerKey>()
        val generations = mutableListOf<Triple<String, OwnerKeyUsage, Boolean>>()
        val deleted = mutableListOf<String>()
        var strongBoxAvailable = true
        var loadError: Exception? = null
        var generationError: Exception? = null
        var deleteError: Exception? = null
        override fun load(alias: String): StoredOwnerKey? { loadError?.let { throw it }; return keys[alias] }
        override fun generate(alias: String, usage: OwnerKeyUsage, strongBox: Boolean, presence: OwnerPresence): StoredOwnerKey {
            generations.add(Triple(alias, usage, strongBox))
            if (usage == OwnerKeyUsage.AGREE) generationError?.let { throw it }
            if (strongBox && !strongBoxAvailable && usage == OwnerKeyUsage.AGREE) throw StrongBoxUnavailableException()
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return StoredOwnerKey(pair, presence, strongBox).also { keys[alias] = it }
        }
        override fun delete(alias: String) { deleteError?.let { throw it }; deleted.add(alias); keys.remove(alias) }
    }
    @Test fun keystoreOwnerCreatesAndSignsAnActionWithOnePresencePolicy() {
        val store = Store()
        val owner = KeystoreOwnerKey.openOrCreate("app", OwnerPresence(45), store)
        assertTrue(owner.usedStrongBox)
        assertEquals(45, owner.presence.validitySeconds)
        assertEquals(listOf(OwnerKeyUsage.SIGN, OwnerKeyUsage.AGREE), store.generations.map { it.second })
        assertNotEquals(store.generations[0].first, store.generations[1].first)
        assertFalse(owner.signingPublicKey().contentEquals(owner.agreementPublicKey()))
        assertEquals(64, owner.sign("body".toByteArray()).size)
        val member = PlatformKeys.software()
        ColophonLibrary.create(member, "Keys", "Owner", listOf("notes"), owner).use { library ->
            library.unlockVault(listOf(owner))
            assertTrue(library.records.isNotEmpty())
        }
        val reopened = KeystoreOwnerKey.openOrCreate("app", OwnerPresence(45), store)
        assertContentEquals(owner.signingPublicKey(), reopened.signingPublicKey())
        assertEquals(2, store.generations.size)
        assertContentEquals(owner.agree(member.agreementPublicKey()), member.agree(owner.agreementPublicKey()))
        assertEquals(KeyOutcome.PRESENCE_FAILED, keyOutcome(assertFailsWith<BindingException.KeyProvider> { KeystoreOwnerKey.openOrCreate("app", OwnerPresence(46), store) }))
    }
    @Test fun strongBoxFallbackAndLostKeysFailClosed() {
        val store = Store().apply { strongBoxAvailable = false }
        assertFalse(KeystoreOwnerKey.openOrCreate("owner", store = store).usedStrongBox)
        assertEquals(listOf(true, true, false, false), store.generations.map { it.third })
        assertEquals(2, store.deleted.size)
        store.keys.remove("owner.owner.agreement")
        assertEquals(KeyOutcome.CREDENTIAL_MISSING, keyOutcome(assertFailsWith<BindingException.KeyProvider> { KeystoreOwnerKey.openOrCreate("owner", store = store) }))
        assertEquals(4, store.generations.size)
        assertEquals(KeyOutcome.UNSUPPORTED_HERE, keyOutcome(assertFailsWith<BindingException.KeyProvider> { KeystoreOwnerKey.openOrCreate("old", store = Store(30)) }))
        store.loadError = ProviderException("unavailable")
        assertEquals(KeyOutcome.HARDWARE_UNAVAILABLE, keyOutcome(assertFailsWith<BindingException.KeyProvider> { KeystoreOwnerKey.openOrCreate("owner", store = store) }))
        assertEquals(4, store.generations.size)
    }
    private class UserNotAuthenticatedException : Exception("Authenticate again")
    @Test fun nonCapabilityFailureAndCleanupFailureNeverRetryGeneration() {
        val failed = Store().apply { generationError = ProviderException("hardware failed") }
        assertEquals(KeyOutcome.HARDWARE_UNAVAILABLE, keyOutcome(assertFailsWith<BindingException.KeyProvider> {
            KeystoreOwnerKey.openOrCreate("failed", store = failed)
        }))
        assertEquals(listOf(true, true), failed.generations.map { it.third })
        assertTrue(failed.keys.isEmpty())
        val cleanup = Store().apply { strongBoxAvailable = false; deleteError = ProviderException("cannot delete") }
        assertEquals(KeyOutcome.HARDWARE_UNAVAILABLE, keyOutcome(assertFailsWith<BindingException.KeyProvider> {
            KeystoreOwnerKey.openOrCreate("cleanup", store = cleanup)
        }))
        assertEquals(listOf(true, true), cleanup.generations.map { it.third })
        assertEquals(1, cleanup.keys.size)
    }
    @Test fun authenticationFailureMapsThroughCallbackSafely() {
        val store = Store().apply { loadError = UserNotAuthenticatedException() }
        assertEquals(KeyOutcome.PRESENCE_FAILED, keyOutcome(assertFailsWith<BindingException.KeyProvider> { KeystoreOwnerKey.openOrCreate("owner", store = store) }))
    }
}
