package com.luff.colophon

import java.security.MessageDigest
import java.util.Base64
import kotlin.test.*

class Keys04Test {
    @Test fun keyringJourney() {
        val f = Keys04Fixture
        val now = "2026-11-08T12:00:00Z"
        fun repeated(value: Int) = ByteArray(32) { value.toByte() }
        fun id(signing: ByteArray) = MessageDigest.getInstance("SHA-256").digest(signing).take(16).joinToString("") { "%02x".format(it.toInt() and 255) }
        fun descriptorID(controller: ByteArray): String {
            val signing = Regex("\"signing\":\"([^\"]+)\"").find(controller.decodeToString())!!.groupValues[1]
            return id(Base64.getDecoder().decode(signing))
        }
        val ownerID = id(f.owner.signing)
        val recoveryID = descriptorID(f.recovery)
        val passkeyID = descriptorID(f.passkey)
        fun signatures(action: HostAction, name: String): List<SignatureResult> {
            val expected = f.signing.getValue(name)
            val steps = action.signingSteps()
            assertEquals(expected.size, steps.size)
            return steps.zip(expected).map { (actual, expected) ->
                assertContentEquals(expected.body, actual.body)
                expected.result
            }
        }
        fun commit(lib: NativeLibrary, action: HostAction, name: String) { action.use { lib.finishAuthority(it,signatures(it,name)) } }
        fun unlock(lib: NativeLibrary, id: String, secret: ByteArray) {
            val option = lib.beginUnlockSlots().first { o -> o.inputs.all { it is SlotInput.Ecdh && it.controller == id } }
            lib.finishUnlockSlot(option, listOf(SlotSecret.Ecdh(secret)))
        }
        val first = beginCreate(f.member,f.owner,repeated(21),"Keys","Device",listOf("notes"),now,repeated(22))
        val final = first.use { it.advanceCreate(signatures(it,"create").map { it.signature }) }
        val records = final.use { it.finishAuthority(signatures(it,"createFinal")) }
        NativeLibrary.open(records,f.member).use { lib ->
            unlock(lib,ownerID,f.ownerSecret)
            val parsed = parseRegistration(f.registration,"id.luff.works").decodeToString()
            assertTrue(parsed.contains("\"form\":\"webauthn\""))
            assertFailsWith<BindingException.InvalidData> { parseRegistration(f.registration,"foreign.example") }
            var prfIndex = 0
            fun prf(seed: ByteArray?, byte: Int): ByteArray {
                val key = Regex("\"key\":(\\{[^}]+})").find(f.passkey.decodeToString())!!.groupValues[1].toByteArray()
                val action = lib.beginPrfSlot(key,repeated(byte))
                return action.use {
                    val expected=f.prf[prfIndex++]
                    assertEquals(expected.challenge,it.challenge()); assertContentEquals(expected.salt,it.salt())
                    lib.finishPrfSlot(it,expected.result,"Passkey",seed,repeated(byte+1))
                }
            }
            val passkeySlot=prf(null,31)
            commit(lib,lib.beginAddPasskey(f.passkey,passkeySlot,listOf(ownerID),now),"addPasskey")
            NativeLibrary.open(lib.records(),f.member).use { opened ->
                val option=opened.beginUnlockSlots().first { o->o.inputs.any { it is SlotInput.Prf } }
                assertFailsWith<BindingException.InvalidData> { opened.finishUnlockSlot(option,listOf(SlotSecret.Prf(repeated(0)))) }
                opened.finishUnlockSlot(option,listOf(SlotSecret.Prf(repeated(71))))
            }
            val recoverySlot=lib.buildSealedSlot(f.recovery,"Recovery",null,repeated(33))
            assertTrue(recoverySlot.isNotEmpty())
            commit(lib,lib.beginKeyring(f.recoveryKeyring,null,listOf(ownerID),now,repeated(34)),"enableRecovery")
            val rotated=prf(repeated(41),35)
            val recoveryRotated=lib.buildSealedSlot(f.recovery,"Recovery",repeated(41),repeated(37))
            commit(lib,lib.beginRemoveController(ownerID,repeated(41),listOf(rotated,recoveryRotated),listOf(ownerID),now,repeated(38)),"removeDevice")
            NativeLibrary.open(lib.records(),f.member).use { recovering ->
                unlock(recovering,recoveryID,f.recoverySecret)
                val addedSlot=recovering.buildSealedSlot(f.added,"Replacement",null,repeated(39))
                commit(recovering,recovering.beginRecoveryAdd(f.added,addedSlot,listOf(recoveryID),now),"recoveryAdd")
                commit(recovering,recovering.prepareAuthority("""{"kind":"layout","layout":2}""".toByteArray(),passkeyID,listOf(passkeyID),now),"passkeyLayout")
                val actual=recovering.records()
                assertEquals(f.records.keys,actual.keys)
                for ((path,bytes) in f.records) assertContentEquals(bytes,actual[path],path)
                NativeLibrary.open(actual,f.member).use { unlock(it,descriptorID(f.added),f.addedSecret) }
            }
        }
    }
}
