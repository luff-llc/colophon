package org.luff.colophon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test
import java.security.InvalidAlgorithmParameterException
import java.security.ProviderException

class KeystoreFallbackTest {
    @Test
    fun strongBoxPurposeFailureFallsBackToTheTee() {
        val calls = mutableListOf<Boolean>()
        var deletes = 0
        val used = KeystoreKeys.generateIdentity(
            "alias.signing",
            "alias.agreement",
            generate = { _, _, strongBox ->
                calls.add(strongBox)
                if (strongBox && calls.count { it } == 2) {
                    throw ProviderException("KM_ERROR_UNSUPPORTED_PURPOSE")
                }
            },
            deletePartial = { deletes += 1 },
        )
        assertFalse(used)
        assertEquals(listOf(true, true, false, false), calls)
        assertEquals(1, deletes)
    }

    @Test
    fun invalidAlgorithmParameterOnStrongBoxFallsBack() {
        val calls = mutableListOf<Boolean>()
        val used = KeystoreKeys.generateIdentity(
            "alias.signing",
            "alias.agreement",
            generate = { _, _, strongBox ->
                calls.add(strongBox)
                if (strongBox) throw InvalidAlgorithmParameterException("PURPOSE_AGREE_KEY")
            },
            deletePartial = {},
        )
        assertFalse(used)
        assertEquals(listOf(true, false, false), calls)
    }

    @Test
    fun unrelatedGenerationFailureDoesNotFallBack() {
        val calls = mutableListOf<Boolean>()
        var deletes = 0
        try {
            KeystoreKeys.generateIdentity(
                "alias.signing",
                "alias.agreement",
                generate = { _, _, strongBox ->
                    calls.add(strongBox)
                    throw IllegalStateException("keystore locked")
                },
                deletePartial = { deletes += 1 },
            )
            fail("expected the original failure")
        } catch (error: IllegalStateException) {
            assertEquals("keystore locked", error.message)
        }
        assertEquals(listOf(true), calls)
        assertEquals(1, deletes)
    }

    @Test
    fun providerExceptionDuringTeeFallbackStillDeletesThePartialIdentity() {
        var deletes = 0
        try {
            KeystoreKeys.generateIdentity(
                "alias.signing",
                "alias.agreement",
                generate = { _, _, strongBox ->
                    if (strongBox) throw ProviderException("StrongBox unavailable")
                    throw IllegalStateException("tee failed")
                },
                deletePartial = { deletes += 1 },
            )
            fail("expected tee failure")
        } catch (_: IllegalStateException) {
        }
        assertEquals(2, deletes)
    }
}
