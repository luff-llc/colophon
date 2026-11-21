package com.luff.colophon

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.*

/** The wait after a create, on a fake clock: no test sleeps on real time. */
class PasskeyReadinessTest {
    private class Clock {
        var millis = 0L
        val sleeps = mutableListOf<Long>()
        val sleep: suspend (Long) -> Unit = { sleeps.add(it); millis += it }
    }
    private fun created(id: String) = """{"rawId":"$id","response":{"attestationObject":"AA"}}"""
    private fun get(id: String) = """{"challenge":"c","rpId":"id.luff.works","allowCredentials":[{"type":"public-key","id":"$id"}],"userVerification":"required"}"""

    @Test fun waitEndsAsSoonAsTheProviderOffersTheCredential() = runBlocking {
        val clock = Clock()
        val gate = CreatedPasskeys(PasskeyReadyWait(), HashMap(), clock::millis, clock.sleep)
        gate.created(created("AQ"))
        var probes = 0
        gate.beforeGet(get("AQ")) { probes++; probes == 4 }
        assertEquals(4, probes)
        assertEquals(listOf(400L, 400L, 400L), clock.sleeps)
        // Waited once: the next get on the same credential is not delayed.
        gate.beforeGet(get("AQ")) { fail("no second wait") }
        assertEquals(1200L, clock.millis)
    }

    @Test fun timeoutProceedsToTheGet() = runBlocking {
        val clock = Clock()
        val gate = CreatedPasskeys(PasskeyReadyWait(), HashMap(), clock::millis, clock.sleep)
        gate.created(created("AQ"))
        var probes = 0
        gate.beforeGet(get("AQ")) { probes++; false } // returns normally: the get runs next
        assertEquals(PasskeyReadyWait.DEFAULT_TIMEOUT_MILLIS, clock.millis)
        assertEquals(39, probes) // at 0, 400, ..., 14 800, then once more at 15 000
        assertTrue(clock.sleeps.all { it <= PasskeyReadyWait.DEFAULT_POLL_INTERVAL_MILLIS })
    }

    @Test fun noWaitForAGetWithoutAPriorCreate() = runBlocking {
        val clock = Clock()
        val gate = CreatedPasskeys(PasskeyReadyWait(), HashMap(), clock::millis, clock.sleep)
        gate.beforeGet(get("AQ")) { fail("an existing passkey is not probed") }
        gate.beforeGet(get("AQ"), null)
        // A create of another credential does not delay this one either.
        gate.created(created("Ag"))
        gate.beforeGet(get("AQ")) { fail("another credential is not probed") }
        assertEquals(0L, clock.millis)
        assertTrue(clock.sleeps.isEmpty())
    }

    @Test fun withoutAProbeTheFixedFallbackIsUsed() = runBlocking {
        val clock = Clock()
        val gate = CreatedPasskeys(PasskeyReadyWait(), HashMap(), clock::millis, clock.sleep)
        gate.created(created("AQ=="))       // padding does not change the credential
        gate.beforeGet(get("AQ"), null)    // Android before 14
        assertEquals(listOf(PasskeyReadyWait.DEFAULT_FALLBACK_MILLIS), clock.sleeps)
        gate.beforeGet(get("AQ"), null)
        assertEquals(1, clock.sleeps.size)
    }

    @Test fun aProbeThatFailsFallsBackToTheFixedWait() = runBlocking {
        val clock = Clock()
        val gate = CreatedPasskeys(PasskeyReadyWait(fallbackMillis = 1_000), HashMap(), clock::millis, clock.sleep)
        gate.created(created("AQ"))
        gate.beforeGet(get("AQ")) { throw SecurityException("permission missing") }
        assertEquals(listOf(1_000L), clock.sleeps)
    }

    @Test fun cancellingTheCallerCancelsTheWait() = runBlocking {
        val clock = Clock()
        val sleeping = CompletableDeferred<Unit>()
        var block = true
        val gate = CreatedPasskeys(PasskeyReadyWait(), HashMap(), clock::millis, sleep = {
            if (block) { sleeping.complete(Unit); awaitCancellation() } else clock.sleep(it)
        })
        gate.created(created("AQ"))
        var finished = false
        val caller = launch(start = CoroutineStart.UNDISPATCHED) { gate.beforeGet(get("AQ")) { false }; finished = true }
        sleeping.await()
        caller.cancel()
        caller.join()
        assertTrue(caller.isCancelled)
        assertFalse(finished)
        // A cancelled wait leaves the credential pending: the next get still waits for it.
        block = false
        var probes = 0
        gate.beforeGet(get("AQ")) { probes++; true }
        assertEquals(1, probes)
    }

    @Test fun aNewAdapterInTheSameProcessStillWaits() = runBlocking {
        val clock = Clock()
        val shared = HashMap<String, CreatedPasskeys.Pending>()
        CreatedPasskeys(PasskeyReadyWait(), shared, clock::millis, clock.sleep).created(created("AQ"))
        var probes = 0
        CreatedPasskeys(PasskeyReadyWait(), shared, clock::millis, clock.sleep).beforeGet(get("AQ")) { probes++; probes == 2 }
        assertEquals(2, probes)
        assertTrue(shared.isEmpty())
    }

    @Test fun aProbeThatNeverReturnsIsBoundedByTheTimeout() = runBlocking {
        val clock = Clock()
        var bounded = 0L
        // On the fake clock: the bound lets the wait start, then the timeout passes and the wait is cut off.
        val gate = CreatedPasskeys(PasskeyReadyWait(), HashMap(), clock::millis, clock.sleep) { millis, block ->
            bounded = millis
            coroutineScope {
                val wait = launch(start = CoroutineStart.UNDISPATCHED) { block() }
                clock.millis += millis
                wait.cancel()
            }
        }
        gate.created(created("AQ"))
        var probes = 0
        gate.beforeGet(get("AQ")) { probes++; awaitCancellation() } // returns: the get runs next
        assertEquals(1, probes)
        assertEquals(PasskeyReadyWait.DEFAULT_TIMEOUT_MILLIS, bounded)
        gate.beforeGet(get("AQ")) { fail("waited once") }
    }

    @Test fun theDefaultBoundCutsOffAStuckProbe() = runBlocking {
        // The real withTimeoutOrNull, with a 50 ms timeout so the test stays short.
        val gate = CreatedPasskeys(PasskeyReadyWait(timeoutMillis = 50))
        gate.created(created("AQ"))
        val started = System.nanoTime()
        gate.beforeGet(get("AQ")) { awaitCancellation() }
        assertTrue(System.nanoTime() - started < 5_000_000_000L)
    }

    @Test fun anUnassertedPasskeyExpires() = runBlocking {
        val clock = Clock()
        val pending = HashMap<String, CreatedPasskeys.Pending>()
        val gate = CreatedPasskeys(PasskeyReadyWait(), pending, clock::millis, clock.sleep)
        gate.created(created("AQ"))
        clock.millis += PasskeyReadyWait.DEFAULT_TIMEOUT_MILLIS + CreatedPasskeys.PENDING_MARGIN_MILLIS + 1
        gate.created(created("Ag")) // creating prunes
        assertEquals(setOf("Ag"), pending.keys)
        gate.beforeGet(get("AQ")) { fail("an expired credential is not probed") }
        clock.millis += PasskeyReadyWait.DEFAULT_TIMEOUT_MILLIS + CreatedPasskeys.PENDING_MARGIN_MILLIS + 1
        gate.beforeGet(get("Ag")) { fail("expiry also applies before a get") }
        assertTrue(pending.isEmpty())
    }

    @Test fun theRecordIsCapped() = runBlocking {
        val clock = Clock()
        val pending = HashMap<String, CreatedPasskeys.Pending>()
        val gate = CreatedPasskeys(PasskeyReadyWait(), pending, clock::millis, clock.sleep)
        repeat(CreatedPasskeys.MAX_PENDING + 4) { clock.millis += 1; gate.created(created("id$it")) }
        assertEquals(CreatedPasskeys.MAX_PENDING, pending.size)
        assertFalse("id0" in pending)   // the oldest go first
        assertTrue("id${CreatedPasskeys.MAX_PENDING + 3}" in pending)
    }

    @Test fun twoGetsForTheSameNewPasskeyShareOneWait() = runBlocking {
        val clock = Clock()
        val release = CompletableDeferred<Unit>()
        val gate = CreatedPasskeys(PasskeyReadyWait(), HashMap(), clock::millis, clock.sleep)
        gate.created(created("AQ"))
        var probes = 0
        val first = launch(start = CoroutineStart.UNDISPATCHED) { gate.beforeGet(get("AQ")) { probes++; release.await(); true } }
        var secondProbed = false
        val second = launch(start = CoroutineStart.UNDISPATCHED) { gate.beforeGet(get("AQ")) { secondProbed = true; true } }
        assertTrue(second.isActive) // waiting on the first one's wait
        release.complete(Unit)
        first.join(); second.join()
        assertEquals(1, probes)
        assertFalse(secondProbed)
    }

    @Test fun noneTurnsTheWaitOff() = runBlocking {
        val clock = Clock()
        val gate = CreatedPasskeys(PasskeyReadyWait.NONE, HashMap(), clock::millis, clock.sleep)
        gate.created(created("AQ"))
        gate.beforeGet(get("AQ")) { fail("no probe with the wait off") }
        gate.created(created("Ag"))
        gate.beforeGet(get("Ag"), null)
        assertTrue(clock.sleeps.isEmpty())
    }

    @Test fun timingsAreValidated() {
        assertFailsWith<IllegalArgumentException> { PasskeyReadyWait(pollIntervalMillis = 0) }
        assertFailsWith<IllegalArgumentException> { PasskeyReadyWait(timeoutMillis = -1) }
        assertFailsWith<IllegalArgumentException> { PasskeyReadyWait(fallbackMillis = -1) }
        assertEquals(PasskeyReadyWait(400, 15_000, 2_500), PasskeyReadyWait())
    }
}
