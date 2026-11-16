package works.luff.colophon.testapp

import android.net.Uri
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests of the flows one device can run alone, against the local home service (apps/test-home), which
 * `scripts/build-test-android.sh --test` starts and makes reachable with `adb reverse`. Views are found by tag and
 * driven on the main thread (no Espresso: it is not on the dependency allowlist). The `script…` steps are single steps
 * of the two-device run, given their input with `-e note <text>`; they are skipped unless `-e step <name>` asks for them.
 */
@RunWith(AndroidJUnit4::class)
class TestAppUiTest {
    private val model get() = ApplicationProvider.getApplicationContext<TestApplication>().model
    private val args get() = InstrumentationRegistry.getArguments()
    private lateinit var scenario: ActivityScenario<MainActivity>

    private fun <T> onMain(block: (MainActivity) -> T): T {
        var out: T? = null
        scenario.onActivity { out = block(it) }
        @Suppress("UNCHECKED_CAST") return out as T
    }
    private fun view(tag: String): View? = onMain { it.window.decorView.findViewWithTag<View>(tag) }
    private fun click(tag: String) = onMain { a -> (a.window.decorView.findViewWithTag<View>(tag) ?: throw AssertionError("no view $tag")).performClick() }
    private fun type(tag: String, text: String) = onMain { a -> (a.window.decorView.findViewWithTag<EditText>(tag) ?: throw AssertionError("no field $tag")).setText(text) }
    private fun textOf(tag: String): String? = onMain { a -> (a.window.decorView.findViewWithTag<View>(tag) as? TextView)?.text?.toString() }
    private fun waitFor(what: String, seconds: Int = 60, condition: () -> Boolean) {
        val until = System.currentTimeMillis() + seconds * 1000L
        while (System.currentTimeMillis() < until) { if (condition()) return; Thread.sleep(250) }
        throw AssertionError("timed out waiting for $what; banner: ${textOf("banner")}; log: ${model.log.takeLast(8).joinToString(" | ") { it.text }}")
    }
    private fun main(block: suspend () -> Unit) = runBlocking { withContext(Dispatchers.Main) { block() } }

    private fun start(reset: Boolean) {
        if (reset) main { model.resetDevice() }
        scenario = ActivityScenario.launch(MainActivity::class.java)
    }

    private fun create() {
        waitFor("the setup screen", 20) { view("createDeviceKey") != null }
        args.getString("token")?.let { token -> type("provisionerToken", token) }
        click("createDeviceKey")
        waitFor("the account; is apps/test-home running and reversed?", 90) { view("addNote")?.isEnabled == true }
    }

    private fun addNote(text: String) {
        click("addNote")
        waitFor("the editor", 10) { view("noteText") != null }
        type("noteText", text)
        click("saveNote")
        waitFor("the note $text", 30) { view("note-$text") != null }
    }

    /** Create an account (Keystore owner key), add, edit and delete a note, sync, lock and unlock, sign out. */
    @Test fun oneDeviceJourney() {
        assumeTrue(args.getString("step") == null)
        start(reset = true)
        create()
        addNote("first note")

        click("note-first note")
        waitFor("the editor", 10) { view("noteText") != null }
        type("noteText", "edited note")
        click("saveNote")
        waitFor("the edit", 30) { view("note-edited note") != null }
        assertTrue("the old text is gone", view("note-first note") == null)

        click("note-edited note")
        waitFor("the editor", 10) { view("deleteNote") != null }
        click("deleteNote")
        waitFor("the note to go", 30) { view("addNote") != null && view("note-edited note") == null }

        click("tabStatus")
        waitFor("phase Ready", 10) { textOf("phase") == "Ready" }
        click("syncNow")
        waitFor("a complete sync", 60) { textOf("syncOutcome")?.startsWith("Last sync: complete") == true }
        waitFor("the last head", 10) { textOf("lastHead")?.startsWith("seq ") == true }

        click("lock")
        click("tabNotes")
        waitFor("the locked notes", 20) { view("unlock") != null }
        click("unlock")
        waitFor("the notes again", 20) { view("addNote")?.isEnabled == true }

        // The sign-out button asks in a dialog (outside the activity's views); the test makes the confirmed call.
        main { model.signOut() }
        waitFor("setup after sign out", 30) { view("createDeviceKey") != null }
        assertTrue("the local account is wiped", !model.paths.account.exists())
        scenario.close()
    }

    // MARK: Steps of the two-device run (am instrument -e step <name> [-e note <text>])

    private val note get() = args.getString("note") ?: "note from Android"

    @Test fun scriptCreateAndInvite() {
        assumeTrue(args.getString("step") == "create")
        start(reset = true)
        create()
        click("tabDevices")
        click("showInvite")
        waitFor("the invite", 20) { view("copyPayload") != null }
        scenario.close()
    }

    @Test fun scriptApprove() {
        assumeTrue(args.getString("step") == "approve")
        start(reset = false)
        args.getString("request")?.let { p -> main { model.open(Uri.parse("colophontest://request?p=$p")) } }
        waitFor("the tabs", 30) { view("tabDevices") != null }
        click("tabDevices")
        // The link only shows the request: import it, confirm the codes, then approve.
        waitFor("the linked request", 30) { view("importLinked") != null }
        click("importLinked")
        waitFor("a waiting request", 60) { view("codesMatch") != null }
        assertTrue("Approve waits for the codes", view("approve")?.isEnabled == false)
        click("codesMatch")
        waitFor("Approve enabled", 10) { view("approve")?.isEnabled == true }
        click("approve")
        waitFor("the approval", 60) { view("approve") == null && model.busy == null }
        scenario.close()
    }

    /** Step: a join link was opened; confirm it on the confirmation screen and wait for the pairing code. */
    @Test fun scriptConfirmJoin() {
        assumeTrue(args.getString("step") == "confirmJoin")
        start(reset = false)
        // The link as the system would deliver it, in this process (`am instrument` restarts the app, so a link opened
        // before the step would be lost with the process).
        args.getString("invite")?.let { p -> main { model.open(Uri.parse("colophontest://join?p=$p")) } }
        waitFor("the confirmation screen", 30) { view("confirmJoin") != null }
        assertTrue("the host is shown", textOf("confirmHost")?.isNotEmpty() == true)
        click("confirmJoin")
        waitFor("the pairing code", 60) { view("pairingCode") != null }
        scenario.close()
    }

    @Test fun scriptWrite() {
        assumeTrue(args.getString("step") == "write")
        start(reset = false)
        waitFor("the notes", 60) { view("addNote")?.isEnabled == true }
        addNote(note)
        main { model.sync() }
        assertTrue("the note did not reach the home: ${model.lastSync?.detail}", model.lastSync?.kind == SyncOutcome.Kind.COMPLETE)
        scenario.close()
    }

    @Test fun scriptSee() {
        assumeTrue(args.getString("step") == "see")
        start(reset = false)
        waitFor("the notes", 60) { view("addNote")?.isEnabled == true }
        waitFor("the other device's note $note", 90) {
            if (view("note-$note") != null) true else { main { model.sync() }; view("note-$note") != null }
        }
        scenario.close()
    }
}
