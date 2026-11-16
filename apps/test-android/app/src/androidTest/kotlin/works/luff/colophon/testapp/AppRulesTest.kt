package works.luff.colophon.testapp

import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.HttpRequest
import com.luff.colophon.session.HomeTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Deflater

/** The app's own rules, on the device (org.json is the platform's): no home needed. */
@RunWith(AndroidJUnit4::class)
class AppRulesTest {
    private fun request(body: String) = HttpRequest(1u, "h", HttpMethod.PUT, "https://home.test/v1/libraries/t1/records/ops/a.json", listOf(), body.toByteArray())

    @Test fun aRefusalShowsOnlyAResultTheSpecAllows() = runBlocking {
        val observer = HomeObserver()
        // A home that echoes what it was sent (a record, a call envelope) in its refusal.
        val echo = HomeTransport { r -> val b = String(r.body); HttpAnswer(400u, listOf(), "{\"result\":\"refused:SECRET-$b\",\"body\":\"$b\"}".toByteArray()) }
        MappedTransport("https://home.test/v1/libraries/", "", observer, echo).send(request("sealed-record-bytes"))
        val refusal = observer.snapshot().lastRefusal!!
        assertEquals(400, refusal.status)
        assertEquals("no result", refusal.detail)
        assertFalse(refusal.detail.contains("sealed-record-bytes"))
        val plain = HomeTransport { HttpAnswer(403u, listOf(), "{\"result\":\"refused:revoked\",\"extra\":\"x\"}".toByteArray()) }
        MappedTransport("https://home.test/v1/libraries/", "", observer, plain).send(request("x"))
        assertEquals("refused:revoked", observer.snapshot().lastRefusal!!.detail)
    }

    @Test fun theResultGrammar() {
        for (good in listOf("ok", "malformed", "badSignature", "newerFormat", "unavailable", "refused:revoked", "refused:outOfScope")) assertTrue(good, ResultCode.isValid(good))
        for (bad in listOf("", "refused:", "refused:Revoked", "refused:a b", "refused:<script>", "refused:" + "a".repeat(49), "error", "OK", "refused:revoked\n")) {
            assertFalse(bad, ResultCode.isValid(bad))
        }
        assertNull(ResultCode.of("not json".toByteArray()))
        assertEquals("-", HomeObserver.plainDate("2026-11-16T03:38:25Z<b>"))
        assertEquals("2026-11-16T03:38:25.872Z", HomeObserver.plainDate("2026-11-16T03:38:25.872Z"))
    }

    @Test fun aDecompressionBombIsRefused() {
        val deflater = Deflater(Deflater.BEST_COMPRESSION, true)
        deflater.setInput(ByteArray(40 * 1024 * 1024)); deflater.finish()
        val out = ByteArrayOutputStream(); val buf = ByteArray(8192)
        while (!deflater.finished()) out.write(buf, 0, deflater.deflate(buf))
        deflater.end()
        val text = PairingPayload.INVITE + Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray())
        val failure = runCatching { PairingPayload.decodeInvite(text) }.exceptionOrNull()
        assertTrue("$failure", failure is PairingPayload.Failure)
    }

    /** A link only fills the confirmation screen: no settings, no files, no request; a bad history stores nothing either. */
    @Test fun aJoinLinkStoresNothingUntilConfirmed() = runBlocking {
        val model = ApplicationProvider.getApplicationContext<TestApplication>().model
        withContext(Dispatchers.Main) {
            model.resetDevice()
            val invite = PairingPayload.encode(PairingPayload.Invite("https://home.test/v1/libraries/", "tlink", "a".repeat(64), mapOf("authority/00000001.json" to "{}".toByteArray())))
            model.open(Uri.parse("colophontest://join?p=$invite"))
            assertNotNull(model.pendingInvite)
            assertEquals("home.test", model.pendingInvite!!.host)
            assertNull("nothing stored before confirmation", model.settings.slot)
            assertFalse("no history written", model.paths.records.exists())
            assertNull(model.session)
            model.confirmJoin()
            assertNull(model.settings.slot)
            assertFalse(model.paths.records.exists())
            assertNotNull(model.actionError)
            model.cancelJoin()
            model.resetDevice()
        }
    }

    /** A request link needs an owner device; on a device without an account it is refused, never imported. */
    @Test fun aRequestLinkIsNeverImportedByItself() = runBlocking {
        val model = ApplicationProvider.getApplicationContext<TestApplication>().model
        withContext(Dispatchers.Main) {
            model.resetDevice()
            model.open(Uri.parse("colophontest://request?p=CTR1.abc"))
            assertNull(model.pendingRequestText)
            assertNotNull(model.actionError)
        }
    }
}
