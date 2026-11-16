package com.luff.colophon.session

import com.luff.colophon.*
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.*

/** §7.3/7.4 through Kotlin's generated exports and session; no hand-built confirmed pairing. */
class PairingTest {
    private val account = "ab".repeat(32)
    private val now = 1_000L
    private val na = ByteArray(32) { it.toByte() }
    private val nb = ByteArray(32) { (it + 32).toByte() }
    private fun key() = PairingTransferKey.create(ByteArray(32) { 17 })
    private fun hash(vararg parts: ByteArray) = MessageDigest.getInstance("SHA-256").run { parts.forEach { update(it) }; digest() }
    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    @Test fun commitmentAndSixDigitsUseExactlyTheSpecBytes() {
        key().use { key ->
            val e = key.public()
            AccountPairing.join(account, e, nb).use { joiner ->
                assertContentEquals(hash("colophon/pair/5".toByteArray(), account.toByteArray(), e, nb), joiner.commitment())
                PairingFailureLimiter.fromState("").use { limiter ->
                    AccountPairing.existingReceiveCommitment(account, joiner.commitment(), limiter, now).use { existing ->
                        val reveal = assertNotNull(joiner.receiveNonce(existing.sendNonce(na)))
                        assertContentEquals(e, reveal.e); assertContentEquals(nb, reveal.nb)
                        val shown = existing.receiveReveal(reveal.e, reveal.nb, limiter, now)
                        val digest = hash("colophon/pair-code/5".toByteArray(), account.toByteArray(), e, na, nb)
                        val number = digest.take(4).fold(0L) { n, b -> (n shl 8) or (b.toLong() and 255) }
                        assertEquals((number % 1_000_000).toString().padStart(6, '0'), shown)
                        assertEquals(shown, joiner.digits())
                        existing.confirm(); joiner.confirm()
                        assertEquals(PairingStage.CONFIRMED, existing.stage()); assertEquals(PairingStage.CONFIRMED, joiner.stage())
                        assertFailsWith<AccountException> { existing.receiveReveal(e, nb, limiter, now) }
                    }
                }
            }
        }
    }

    @Test fun qrHasExactCanonicalBytesAndBothNoncesConfirmIt() {
        key().use { key ->
            AccountPairing.joinQr(account, key.public(), nb).use { joiner ->
                val expected = "{\"account\":\"$account\",\"e\":\"${b64(key.public())}\",\"nB\":\"${b64(nb)}\",\"protocol\":\"colophon/pair-qr/5\"}"
                val payload = joiner.qrPayload()
                assertContentEquals(expected.toByteArray(), payload)
                PairingFailureLimiter.fromState("").use { limiter ->
                    AccountPairing.existingScanQr(account, joiner.qrPayload(), limiter, now).use { existing ->
                        assertNull(joiner.receiveNonce(existing.sendNonce(na)))
                        assertEquals(PairingStage.CONFIRMED, existing.stage()); assertEquals(PairingStage.CONFIRMED, joiner.stage())
                    }
                    val wrong = assertFailsWith<AccountException.Malformed> { AccountPairing.existingScanQr("cd".repeat(32), payload, limiter, now) }
                    assertEquals("pairing:wrongAccount", wrong.code)
                    assertFailsWith<AccountException> { AccountPairing.existingScanQr(account, (expected + "\n").toByteArray(), limiter, now) }
                    assertFailsWith<AccountException> { AccountPairing.existingScanQr(account, expected.replace("pair-qr/5", "pair-qr/4").toByteArray(), limiter, now) }
                }
            }
        }
    }

    @Test fun mismatchedCommitmentConsumesTheOnlyReveal() {
        key().use { key ->
            AccountPairing.join(account, key.public(), nb).use { joiner ->
                PairingFailureLimiter.fromState("").use { limiter ->
                    AccountPairing.existingReceiveCommitment(account, joiner.commitment(), limiter, now).use { existing ->
                        joiner.receiveNonce(existing.sendNonce(na))
                        val e = assertFailsWith<AccountException.Malformed> { existing.receiveReveal(key.public(), ByteArray(32), limiter, now) }
                        assertEquals("pairing:commitmentMismatch", e.code)
                        assertEquals(PairingStage.SPENT, existing.stage())
                        assertFailsWith<AccountException> { existing.receiveReveal(key.public(), nb, limiter, now) }
                    }
                }
            }
        }
    }

    @Test fun rejectingCodesPersistsTheFiveFailuresPerHourLimit() {
        key().use { key ->
            PairingFailureLimiter.fromState("").use { limiter ->
                repeat(5) {
                    AccountPairing.join(account, key.public(), nb).use { joiner ->
                        AccountPairing.existingReceiveCommitment(account, joiner.commitment(), limiter, now).use { existing ->
                            val reveal = assertNotNull(joiner.receiveNonce(existing.sendNonce(na)))
                            existing.receiveReveal(reveal.e, reveal.nb, limiter, now)
                            existing.reject(limiter, now)
                            assertEquals(PairingStage.SPENT, existing.stage())
                            assertFailsWith<AccountException> { existing.confirm() }
                        }
                    }
                }
                assertFalse(limiter.mayStart(now))
                PairingFailureLimiter.fromState(limiter.toState()).use { restored ->
                    assertFalse(restored.mayStart(now))
                    val e = assertFailsWith<AccountException.Refused> { AccountPairing.existingReceiveCommitment(account, ByteArray(32), restored, now) }
                    assertEquals("pairing:limit", e.code)
                    assertTrue(restored.mayStart(now + 3_600_001))
                }
            }
        }
    }

    @Test fun seedTransferRequiresTheConfirmedPairingAndCreatesAnIndependentOwnerSlot() = runBlocking {
        val first = Device()
        val owner = SoftwareKeys()
        var second: Device? = null
        try {
            first.session.create()
            first.session.addController(owner, "Paired owner")
            val account = assertNotNull(first.session.libraryId)
            second = Device(medium = first.medium.copy(), owner = owner)
            second.session.restore()
            key().use { key ->
                PairingFailureLimiter.fromState("").use { limiter ->
                    AccountPairing.join(account, key.public(), nb).use { joiner ->
                        AccountPairing.existingReceiveCommitment(account, joiner.commitment(), limiter, now).use { existing ->
                            val reveal = assertNotNull(joiner.receiveNonce(existing.sendNonce(na)))
                            existing.receiveReveal(reveal.e, reveal.nb, limiter, now)
                            assertFailsWith<AccountException> { first.session.transferSeed(existing) }
                            existing.confirm(); joiner.confirm()
                            val sealed = first.session.transferSeed(existing)
                            AccountPairing.joinQr(account, key.public(), ByteArray(32) { 9 }).use { other ->
                                AccountPairing.existingScanQr(account, other.qrPayload(), limiter, now).use { scanner ->
                                    other.receiveNonce(scanner.sendNonce(na))
                                    val before = second.medium.snapshot()
                                    assertFailsWith<AccountException> { second.session.acceptSeedTransfer(key, other, sealed, "Wrong") }
                                    val after = second.medium.snapshot()
                                    assertEquals(before.keys, after.keys)
                                    before.forEach { (path, bytes) -> assertContentEquals(bytes, after.getValue(path)) }
                                }
                            }
                            second.session.acceptSeedTransfer(key, joiner, sealed, "Paired owner")
                            // Its own request, read as the scan path does: the device that holds the owner key made it (§9.1).
                            approveByScan(second.session, second.session)
                            assertEquals(SessionPhase.Ready, second.session.phase)
                        }
                    }
                }
            }
        } finally { second?.close(); first.close() }
    }
}
