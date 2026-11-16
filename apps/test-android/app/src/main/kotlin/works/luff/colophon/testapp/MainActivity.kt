package works.luff.colophon.testapp

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.provider.MediaStore
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.luff.colophon.session.ObservedRevision
import com.luff.colophon.session.SessionPhase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.lang.ref.WeakReference
import java.text.DateFormat
import java.util.Date

/**
 * The whole app in one activity, built in code with platform views (Jetpack Compose is not on the dependency allowlist).
 * Each screen has a static part (fields keep what the person typed) and a dynamic part rebuilt whenever the model
 * changes. Every view a test touches carries a tag.
 */
class MainActivity : Activity() {
    enum class Screen { SETUP, CONFIRM_JOIN, WAITING, NOTES, EDIT, DEVICES, STATUS, LOG }

    val model: AppModel get() = (application as TestApplication).model
    private lateinit var root: LinearLayout
    private lateinit var tabs: LinearLayout
    private lateinit var banner: TextView
    private lateinit var content: LinearLayout
    private var dynamic: LinearLayout? = null
    private var screen: Screen? = null
    private var chosen = Screen.NOTES
    private var editing: Note? = null
    private var editObserved: ObservedRevision? = null
    private var editPhoto: ByteArray? = null
    private var renderJob: Job? = null
    private var syncJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; fitsSystemWindows = true }
        tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        banner = TextView(this).apply { setPadding(24, 8, 24, 8); tag = "banner" }
        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 8, 24, 48) }
        root.addView(tabs)
        root.addView(banner)
        root.addView(ScrollView(this).apply { addView(content); tag = "scroll" }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
        intent?.data?.let { uri -> model.scope.launch { model.open(uri) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.data?.let { uri -> model.scope.launch { model.open(uri) } }
    }

    override fun onStart() {
        super.onStart()
        model.activity = WeakReference(this)
        renderJob = model.scope.launch { model.changes.collectLatest { render() } }
        // Automatic sync while the app is in front, besides the session's own loop; unlock on return.
        syncJob = model.scope.launch {
            if (model.session?.phase == SessionPhase.Locked) model.unlock()
            while (true) { delay(15_000); model.session?.requestSync() }
        }
    }

    override fun onStop() {
        renderJob?.cancel(); syncJob?.cancel()
        // Lock in the background: no secret held while away.
        if (model.session?.phase == SessionPhase.Ready && !isChangingConfigurations) model.scope.launch { model.lock() }
        super.onStop()
    }

    private fun currentScreen(): Screen {
        val session = model.session
        if (model.settings.slot == null) return if (model.pendingInvite != null) Screen.CONFIRM_JOIN else Screen.SETUP
        if (session?.phase is SessionPhase.WaitingForApproval) return Screen.WAITING
        return chosen
    }

    fun go(next: Screen) { chosen = next; render() }

    fun render() {
        val now = currentScreen()
        banner.text = listOfNotNull(model.busy?.let { "$it…" }, model.actionError).joinToString("\n")
        banner.setTextColor(if (model.actionError != null) Color.RED else Color.GRAY)
        banner.visibility = if (banner.text.isEmpty()) View.GONE else View.VISIBLE
        if (now != screen) {
            screen = now
            content.removeAllViews()
            buildTabs(now)
            when (now) {
                Screen.SETUP -> setupScreen()
                Screen.CONFIRM_JOIN -> confirmJoinScreen()
                Screen.WAITING -> waitingScreen()
                Screen.NOTES -> notesScreen()
                Screen.EDIT -> editScreen()
                Screen.DEVICES -> devicesScreen()
                Screen.STATUS -> statusScreen()
                Screen.LOG -> {}
            }
            dynamic = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            content.addView(dynamic)
        }
        dynamic?.let { d ->
            d.removeAllViews()
            when (now) {
                Screen.NOTES -> notesList(d)
                Screen.DEVICES -> devicesList(d)
                Screen.STATUS -> statusList(d)
                Screen.WAITING -> waitingList(d)
                Screen.LOG -> logList(d)
                else -> {}
            }
        }
    }

    private fun buildTabs(now: Screen) {
        tabs.removeAllViews()
        if (now == Screen.SETUP || now == Screen.CONFIRM_JOIN || now == Screen.WAITING) return
        for ((label, target) in listOf("Notes" to Screen.NOTES, "Devices" to Screen.DEVICES, "Status" to Screen.STATUS, "Log" to Screen.LOG)) {
            tabs.addView(Button(this).apply {
                text = label; tag = "tab$label"; isEnabled = target != now
                setOnClickListener { go(target) }
            }, LinearLayout.LayoutParams(0, -2, 1f))
        }
    }

    // MARK: Building blocks

    private fun ViewGroup.text(value: String, size: Float = 14f, bold: Boolean = false, mono: Boolean = false, tag: String? = null, color: Int? = null): TextView =
        TextView(context).apply {
            text = value; textSize = size; setTextIsSelectable(true); setPadding(0, 6, 0, 6)
            if (bold) setTypeface(typeface, Typeface.BOLD)
            if (mono) typeface = Typeface.MONOSPACE
            tag?.let { this.tag = it }
            color?.let { setTextColor(it) }
        }.also { addView(it) }
    private fun ViewGroup.header(value: String) = text(value, 16f, bold = true).apply { setPadding(0, 24, 0, 4) }
    private fun ViewGroup.button(label: String, tag: String? = null, action: () -> Unit): Button =
        Button(context).apply { text = label; tag?.let { this.tag = it }; setOnClickListener { action() } }.also { addView(it) }
    private fun ViewGroup.field(hint: String, value: String, tag: String, lines: Int = 1): EditText =
        EditText(context).apply {
            this.hint = hint; setText(value); this.tag = tag; textSize = 13f
            if (lines > 1) { minLines = 2; maxLines = lines; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE }
            else inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        }.also { addView(it) }
    private fun ViewGroup.row(label: String, value: String, tag: String? = null) {
        text(label, 12f, color = Color.GRAY)
        text(value, 13f, tag = tag)
    }
    private fun launch(block: suspend () -> Unit) { model.scope.launch { block() } }

    private fun ViewGroup.payload(text: String) {
        qr(text)?.let { bitmap ->
            addView(ImageView(context).apply { setImageBitmap(bitmap); tag = "qr"; adjustViewBounds = true }, LinearLayout.LayoutParams(-1, -2))
        } ?: text("Too large for one QR code (${text.length} characters): copy and paste it instead.", color = Color.rgb(200, 120, 0))
        addView(HorizontalScrollView(context).apply {
            addView(TextView(context).apply { this.text = text.take(120) + if (text.length > 120) "…" else ""; typeface = Typeface.MONOSPACE; textSize = 10f; tag = "payload" })
        })
        button("Copy", "copyPayload") {
            (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("Colophon test", text))
        }
    }

    private fun qr(text: String): Bitmap? = try {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L, EncodeHintType.MARGIN to 2))
        val scale = 6
        Bitmap.createBitmap(matrix.width * scale, matrix.height * scale, Bitmap.Config.RGB_565).apply {
            for (x in 0 until width) for (y in 0 until height) setPixel(x, y, if (matrix[x / scale, y / scale]) Color.BLACK else Color.WHITE)
        }
    } catch (_: Exception) { null }

    private fun scan(then: (String) -> Unit) {
        pendingScan = then
        @Suppress("DEPRECATION") startActivityForResult(Intent(this, ScanActivity::class.java), SCAN)
    }
    private var pendingScan: ((String) -> Unit)? = null

    @Deprecated("platform Activity result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data == null) return
        when (requestCode) {
            SCAN -> data.getStringExtra(ScanActivity.RESULT)?.let { pendingScan?.invoke(it) }
            PHOTO -> data.data?.let { uri ->
                launch {
                    editPhoto = withContext(Dispatchers.IO) {
                        contentResolver.openInputStream(uri)?.use { input ->
                            val bitmap = BitmapFactory.decodeStream(input) ?: return@use null
                            val scale = minOf(1f, 1600f / maxOf(bitmap.width, bitmap.height))
                            val resized = Bitmap.createScaledBitmap(bitmap, (bitmap.width * scale).toInt().coerceAtLeast(1), (bitmap.height * scale).toInt().coerceAtLeast(1), true)
                            ByteArrayOutputStream().also { resized.compress(Bitmap.CompressFormat.JPEG, 70, it) }.toByteArray()
                        }
                    }
                    if (editPhoto == null) model.actionError = "That image could not be read."
                    screen = null; render()
                }
            }
        }
    }

    // MARK: Setup

    private fun setupScreen() {
        content.header("Home")
        val prefix = content.field("Home URL prefix (https://…/)", model.settings.homePrefix, "homePrefix")
        val reach = content.field("Reach over (empty: as named)", model.settings.reachPrefix, "reachPrefix")
        val provisioner = content.field("Home service (provisions a new account's home)", model.settings.provisioner, "provisioner")
        val token = content.field("Home service token (printed at its start-up)", model.settings.provisionerToken, "provisionerToken").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val presets = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        presets.button("Use staging", "useStaging") { prefix.setText(BuildDefaults.stagingPrefix); reach.setText(""); provisioner.setText(BuildDefaults.stagingProvisioner) }
        presets.button("Use this Mac") { prefix.setText(BuildDefaults.homePrefix); reach.setText(BuildDefaults.reachPrefix); provisioner.setText(BuildDefaults.provisioner) }
        content.addView(presets)
        content.text("A new account gets the slot “t…” under the prefix. “Reach over” sends the home's requests there instead (a relay on the Mac, through adb reverse); leave it empty for a real https home.", 12f, color = Color.GRAY)
        fun save() = model.updateHome(prefix.text.toString(), reach.text.toString(), provisioner.text.toString(), token.text.toString())
        content.header("New account")
        content.button("Create with a passkey", "createPasskey") { save(); launch { model.create(OwnerChoice.PASSKEY) } }
        if (TestOwner.AVAILABLE) {
            content.button("Create with a Keystore owner key (test only)", "createDeviceKey") { save(); launch { model.create(OwnerChoice.DEVICE_KEY) } }
        }
        content.text("Passkey: relying party ${BuildDefaults.relyingParty}; it works only where that domain lists this app (see the README).", 12f, color = Color.GRAY)
        content.header("Join an account")
        val invite = content.field("Paste an invite (CTJ1.…)", "", "invite", lines = 6)
        content.button("Join", "join") { launch { model.prepareJoin(invite.text.toString()) } }
        content.button("Scan") { scan { text -> launch { model.prepareJoin(text) } } }
    }

    // MARK: Confirm a join (a link, a scan or a paste only fills this screen; nothing is stored until Ask to join)

    private fun confirmJoinScreen() {
        val pending = model.pendingInvite ?: return
        content.header("Ask to join this account?")
        content.row("Home", pending.host, "confirmHost")
        content.row("Account", pending.accountShort, "confirmAccount")
        content.text("This device will store the account's history, then ask the account's owner device to approve it.", 13f)
        content.text(TrustWords.INVITE, 12f, color = Color.rgb(200, 120, 0))
        content.button("Ask to join", "confirmJoin") { launch { model.confirmJoin() } }
        content.button("Cancel", "cancelJoin") { model.cancelJoin(); render() }
    }

    // MARK: Waiting

    private fun waitingScreen() {
        content.header("Waiting for approval")
        content.button("Check for approval", "checkApproval") { launch { model.sync() } }
        content.button("Status") { go(Screen.STATUS); chosen = Screen.STATUS }
    }
    private fun waitingList(d: LinearLayout) {
        val code = (model.session?.phase as? SessionPhase.WaitingForApproval)?.code ?: "-"
        d.text(code, 32f, mono = true, tag = "pairingCode")
        d.text("On the owner device: Devices, then scan this code or paste this request. Approve only if it shows the same code.", 12f)
        d.text(TrustWords.WAITING, 12f, color = Color.GRAY)
        model.shownPayload?.takeIf { it.startsWith(PairingPayload.REQUEST) }?.let { d.payload(it) }
            ?: d.button("Show this device's request", "showRequest") { launch { model.requestPayload() } }
        model.lastSync?.let { syncOutcome(d, it) }
    }

    private fun syncOutcome(d: LinearLayout, outcome: SyncOutcome) {
        d.text("Last sync: ${outcome.kind.name.lowercase()} at ${DateFormat.getTimeInstance().format(Date(outcome.atMs))}", 13f, bold = true,
            tag = "syncOutcome", color = if (outcome.kind == SyncOutcome.Kind.COMPLETE) Color.rgb(0, 140, 0) else Color.rgb(200, 120, 0))
        d.text(outcome.detail, 11f)
    }

    // MARK: Notes

    private fun notesScreen() {
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        bar.button("Add", "addNote") { editing = null; editPhoto = null; editObserved = model.session?.observedRevision; go(Screen.EDIT) }
        bar.button("Sync", "syncNotes") { launch { model.sync() } }
        content.addView(bar)
    }
    private fun notesList(d: LinearLayout) {
        val session = model.session ?: return
        (content.findViewWithTag<View>("addNote") as? Button)?.isEnabled = session.hasUsableContent && model.busy == null
        when (val phase = session.phase) {
            SessionPhase.Locked -> { d.text("Locked", 20f, bold = true); d.button("Unlock", "unlock") { launch { model.unlock() } }; return }
            SessionPhase.Ready, SessionPhase.Refreshing, SessionPhase.Retry, SessionPhase.WaitingForDownload -> {}
            else -> { d.text("Not ready. Phase: $phase\n${session.lastError ?: ""}", tag = "notReady"); return }
        }
        model.notesProblem?.let { d.text(it, color = Color.RED, tag = "notesProblem") }
        model.lastSync?.let { syncOutcome(d, it) }
        if (model.notes.isEmpty() && model.notesProblem == null) d.text("No notes yet.", color = Color.GRAY)
        for (note in model.notes) {
            val item = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 16, 0, 16); tag = "note-${note.text}" }
            item.text(note.text.ifEmpty { "(empty)" }, 16f).setTextIsSelectable(false)
            item.text("${if (note.photo != null) "[photo] " else ""}by ${note.authorLabel} · ${note.author.take(8)}", 12f, color = Color.GRAY).setTextIsSelectable(false)
            item.setOnClickListener { editing = note; editPhoto = null; editObserved = model.session?.observedRevision; go(Screen.EDIT) }
            d.addView(item)
        }
    }

    private fun editScreen() {
        val note = editing
        content.header(if (note == null) "New note" else "Edit note")
        val field = content.field("Note", note?.text ?: "", "noteText", lines = 8)
        val image = ImageView(this).apply { adjustViewBounds = true; maxHeight = 600 }
        content.addView(image, LinearLayout.LayoutParams(-1, -2))
        editPhoto?.let { bytes -> image.setImageBitmap(BitmapFactory.decodeByteArray(bytes, 0, bytes.size)) }
        if (editPhoto == null && note?.photo != null) launch {
            try {
                val bytes = model.photo(note)
                val bitmap = withContext(Dispatchers.Default) { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }
                image.setImageBitmap(bitmap)
            } catch (e: Exception) { content.text("The photo is not here yet: ${AppModel.message(e)}", color = Color.RED) }
        }
        content.button(if (note?.photo == null && editPhoto == null) "Attach a photo" else "Replace the photo") {
            @Suppress("DEPRECATION") startActivityForResult(Intent(MediaStore.ACTION_PICK_IMAGES).setType("image/*"), PHOTO)
        }
        content.button("Save", "saveNote") {
            val observed = editObserved ?: return@button
            launch { if (model.saveNote(note?.id, field.text.toString(), editPhoto, note?.photo, observed)) go(Screen.NOTES) }
        }
        content.button("Cancel") { go(Screen.NOTES) }
        if (note != null) {
            content.text("Written by ${note.authorLabel} (${note.author}) at ${note.created}", 12f)
            content.button("Delete", "deleteNote") { launch { model.deleteNote(note); go(Screen.NOTES) } }
        }
    }

    // MARK: Devices

    private fun devicesScreen() {
        if (!model.isOwner) {
            content.text("This device joined the account with a member key only: it cannot add, approve or revoke devices.", 13f)
            return
        }
        content.header("1. The new device scans or pastes this")
        content.button("Add a device: show the invite", "showInvite") { launch { try { model.invitePayload() } catch (e: Exception) { model.actionError = AppModel.message(e); render() } } }
        content.header("2. Then take its request")
        val request = content.field("Paste its request (CTR1.…)", "", "requestField", lines = 4)
        content.button("Import request", "importRequest") { launch { model.importRequest(request.text.toString()); request.setText("") } }
        content.button("Scan") { scan { text -> launch { model.importRequest(text) } } }
    }
    private fun devicesList(d: LinearLayout) {
        val session = model.session ?: return
        if (model.isOwner) {
            model.shownPayload?.takeIf { it.startsWith(PairingPayload.INVITE) }?.let { d.header("Invite"); d.payload(it) }
            model.pendingRequestText?.let { pending ->
                d.header("A request arrived by link")
                d.text("It is not imported until you choose to. Import it only if you expect a device to join.", 12f)
                d.button("Import it", "importLinked") { launch { model.importRequest(pending) } }
                d.button("Ignore") { model.pendingRequestText = null; render() }
            }
            if (model.visibleRequests.isNotEmpty()) { d.header("3. Compare the codes"); d.text(TrustWords.APPROVE, 12f, color = Color.GRAY) }
            for (request in model.visibleRequests) {
                val confirmed = request.id in model.confirmedCodes
                d.text(request.pairingCode, 24f, mono = true, tag = "requestCode")
                d.text("${request.label} · ${request.id}", 12f)
                d.button(if (confirmed) "Codes match ✓" else "The codes match", "codesMatch") { model.confirmCodes(request); render() }.isEnabled = !confirmed
                d.button("Approve", "approve") { launch { model.approve(request) } }.isEnabled = confirmed
                d.button("Reject", "reject") { model.reject(request); render() }
            }
        }
        d.header("Members")
        for (member in session.state.value.members) {
            d.text("${member.label}${if (member.id == session.memberId) " (this device)" else ""}${if (member.revokedAt != null) " — revoked" else ""}")
            d.text("${member.kind} · ${member.id}", 12f, color = Color.GRAY)
            if (model.isOwner && member.revokedAt == null && member.id != session.memberId && !member.home) {
                d.button("Revoke ${member.label}") { launch { model.revoke(member) } }
            }
        }
    }

    // MARK: Status

    private fun statusScreen() {
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        bar.button("Sync now", "syncNow") { launch { model.sync() } }
        bar.button("Lock", "lock") { launch { model.lock() } }
        bar.button("Unlock") { launch { model.unlock() } }
        content.addView(bar)
        val bar2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        bar2.button("Sign out", "signOut") {
            AlertDialog.Builder(this).setMessage("Wipe this device's account state? The account and other devices are unchanged.")
                .setPositiveButton("Sign out") { _, _ -> launch { model.signOut() } }.setNegativeButton("Cancel", null).show()
        }
        bar2.button("Reset this device", "reset") {
            AlertDialog.Builder(this).setMessage("Reset this device to the build's defaults?")
                .setPositiveButton("Reset") { _, _ -> launch { model.resetDevice() } }.setNegativeButton("Cancel", null).show()
        }
        content.addView(bar2)
    }
    private fun statusList(d: LinearLayout) {
        val session = model.session
        val time = DateFormat.getDateTimeInstance()
        if (session != null) {
            val s = session.state.value
            d.header("Session")
            d.row("Phase", "${s.phase}", "phase")
            d.row("Account", s.libraryId ?: "-")
            d.row("This device's key", s.memberId ?: "-")
            d.row("Owner", model.settings.owner?.wire ?: "-")
            d.row("Sync state", "${s.syncState}")
            d.row("Last synced", s.lastSyncedMs?.let { time.format(Date(it)) } ?: "never")
            d.row("Session error", s.lastError ?: "none")
            d.row("Home faults", s.homeFaults.joinToString("\n") { AppModel.describe(it) }.ifEmpty { "none" })
            d.row("Home issues", s.homeIssues.joinToString("\n") { "${it.home.take(8)}: ${it.problem}" }.ifEmpty { "none" })
            d.row("Held / refused notes", "${model.heldRefused.first} / ${model.heldRefused.second}")
            if (s.notices.noHome) d.text("This account has no home.", color = Color.RED)
            if (s.duties.soleDevice) d.text("This account has one control key: a stolen device could not be vetoed.", 12f)
        }
        d.header("Home")
        d.row("URL", model.settings.homeBase ?: "-")
        d.row("Reached over", model.settings.reachPrefix.ifEmpty { "as named" })
        val sighting = model.observer.snapshot()
        d.row("Last head", sighting.head?.let { "seq ${it.seq}, issued ${it.issued}, fetched ${time.format(Date(it.atMs))}" } ?: "none fetched yet", "lastHead")
        sighting.last?.let { d.row("Last answer", "${it.status}: ${it.method} ${it.path}") }
        sighting.lastRefusal?.let { d.row("Last refusal", "${it.status} at ${time.format(Date(it.atMs))}: ${it.method} ${it.path} ${it.detail}") }
        sighting.transportError?.let { d.row("Transport error", it) }
        d.row("Requests sent", "${sighting.requests}")
        d.header("Last sync")
        model.lastSync?.let { syncOutcome(d, it) } ?: d.text("Not run from this screen yet")
        if (session != null) {
            val s = session.state.value
            d.header("Pending changes")
            if (s.notices.pending.isEmpty()) d.text("None")
            for (p in s.notices.pending) {
                d.text("${p.components.joinToString()} by ${p.signers.joinToString { it.label }}")
                d.text("veto deadline: ${p.vetoDeadlineMs?.let { time.format(Date(it)) } ?: "-"} · due: ${p.dueMs?.let { time.format(Date(it)) } ?: "-"}", 12f)
                d.text(p.digest, 10f)
                if (p.vetoable) d.button("Veto") { launch { model.veto(p) } }
            }
            d.header("Homes the account names")
            for (h in s.homes) d.row(h.label, "${h.status} · ${h.endpoints.joinToString(" ")} · ${h.id}")
        }
    }

    private fun logList(d: LinearLayout) {
        val time = DateFormat.getTimeInstance()
        d.header("Log (last 200 events)")
        for (entry in model.log.reversed()) d.text("${time.format(Date(entry.atMs))}  ${entry.text}", 12f)
    }

    companion object {
        const val SCAN = 1
        const val PHOTO = 2
    }
}

/** What the pairing does and does not prove, the same words as the iPhone app. Until a signed invite and the §7.3
 *  ceremony land in the SDKs, an invite is not authenticated. */
object TrustWords {
    const val INVITE = "Join only with an invite you got in person or over a channel you trust. The invite is not signed: it does not prove who made it, or that the home and the account are theirs."
    const val WAITING = "The code lets the owner device check that the request it received is this device's, unchanged. It does not prove that the invite came from the person you think."
    const val APPROVE = "Compare this code with the one on the joining device. A matching code shows the request came from that device unchanged; it does not prove who holds the device. Confirm only after checking; reject if the codes differ."
}
