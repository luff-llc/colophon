package com.luff.colophon.session

import com.luff.colophon.AccountMemberKind
import com.luff.colophon.AccountRequest
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.RequestSpec
import com.luff.colophon.Signature
import com.luff.colophon.accountFormatDate
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Test
import java.util.Collections
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A pass cancelled while a request is in flight (the app stops syncing, a scope ends) must not leave the engine with
 * an outstanding request: the next pass starts again from the head. Before the fix the cancelled caller skipped
 * `exchange_abort`, every later pass got `Waiting`, and the session reported a clean sync that moved nothing.
 */
class ExchangeCancelTest {
    @Test(timeout = 60_000) fun aCancelledPassIsAbandonedAndTheNextOneStartsClean() = runBlocking<Unit> {
        val endpoint = "https://fake-home.test/v1/accounts/k/"
        val homeKeys = SoftwareKeys()
        val seen = Collections.synchronizedList(ArrayList<String>())
        val firstRequest = CompletableDeferred<Unit>()
        val transport = HomeTransport { request ->
            seen.add("${request.method} ${request.url}")
            if (seen.size == 1) { firstRequest.complete(Unit); awaitCancellation() }
            HttpAnswer(503u, listOf(), ByteArray(0))
        }
        val home = HomeConfiguration(endpoint, request = { account ->
            val p = homeKeys.publicKeys()
            val spec = RequestSpec(account, p.signing, p.agreement, "Fake home", AccountMemberKind.SERVER, "{\"serves\":[\"home\"]}",
                accountFormatDate(System.currentTimeMillis() - 5_000), null, null, listOf(endpoint))
            AccountRequest.prepare(spec).use { r -> r.finish(Signature(homeKeys.sign(r.step().body), null, null)).raw }
        }, transport = transport)
        val d = Device(homes = listOf(home), createWithoutHome = false)
        try {
            d.session.create()
            assertEquals(SessionPhase.Ready, d.session.phase, d.describe())
            assertEquals(1, d.session.homes.size)
            // The background loop's first pass is now waiting on the home; stopping the loop cancels it mid-request.
            withTimeout(20_000) { firstRequest.await() }
            d.session.stopSync()
            val ok = d.session.syncNow()
            assertFalse(ok && seen.size == 1, "the next pass sent nothing: the engine still held the cancelled request")
            assertTrue(seen.size >= 2, "the next pass reached the home: $seen")
            assertTrue(seen[1] == "${HttpMethod.GET} ${endpoint}head", "the next pass starts again from the head: $seen")
        } finally {
            d.close()
        }
    }
}
