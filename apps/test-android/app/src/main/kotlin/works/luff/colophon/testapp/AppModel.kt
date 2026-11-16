package works.luff.colophon.testapp

import android.app.Activity
import android.app.Application
import android.content.Context
import com.luff.colophon.AccountMember
import com.luff.colophon.AccountMemberKind
import com.luff.colophon.AuthorityObjects
import com.luff.colophon.ByteString
import com.luff.colophon.accountVerifyHistory
import com.luff.colophon.Pending
import com.luff.colophon.PublicKeys
import com.luff.colophon.session.AccessRequest
import com.luff.colophon.session.AsyncKeyProvider
import com.luff.colophon.session.ColophonSession
import com.luff.colophon.session.DomainCommand
import com.luff.colophon.session.FolderMedium
import com.luff.colophon.session.HomeConfiguration
import com.luff.colophon.session.HomeFault
import com.luff.colophon.session.HomeProblem
import com.luff.colophon.session.MediumWrite
import com.luff.colophon.session.ObservedRevision
import com.luff.colophon.session.SecretBytes
import com.luff.colophon.session.SessionConfiguration
import com.luff.colophon.session.SessionError
import com.luff.colophon.session.SessionPhase
import com.luff.colophon.session.SessionState
import com.luff.colophon.session.blobData
import com.luff.colophon.session.putBlob
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.luff.colophon.keys.CredentialClient
import org.luff.colophon.keys.CredentialManagerAdapter
import org.luff.colophon.keys.PasskeyProvider
import org.luff.colophon.keys.appPasskeyOrigins
import org.luff.colophon.session.AndroidSession
import org.luff.colophon.session.KeystoreDeviceSecrets
import org.luff.colophon.session.PasskeyController
import java.lang.ref.WeakReference
import java.security.KeyStore
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class TestApplication : Application() {
    lateinit var model: AppModel
    override fun onCreate() {
        super.onCreate()
        model = AppModel(this)
    }
}

data class LogEntry(val atMs: Long, val text: String)

/** One sync the app asked for: `complete` only when the pass succeeded and no home fault or issue is left. */
data class SyncOutcome(val atMs: Long, val kind: Kind, val detail: String) {
    enum class Kind { COMPLETE, INCOMPLETE, FAILED }
}

/**
 * The app's state around the one session. Every session call is a suspend call made from `scope` (main dispatcher); the
 * session runs its work on its own lane, and file work here runs on `Dispatchers.IO`.
 */
class AppModel(private val app: Context) {
    companion object {
        const val PREFIX = "works.luff.colophon.testapp"
        const val MEMBER_ALIAS = "$PREFIX.member"
        const val OWNER_ALIAS = "$PREFIX.owner"
        const val DEVICE_KEY_ALIAS = "$PREFIX.device-key"
        const val ATTEMPT_LIMIT = 5
        fun message(e: Throwable): String = "${e.javaClass.simpleName}: ${e.message ?: ""}".trim()
        /** A home problem in words: a home's refusal of this device's call is the home's claim, not a verified revocation. */
        fun describe(p: HomeProblem): String = when (p) {
            is HomeProblem.RemoteCallRefused -> "the home refused this device's call (${if (ResultCode.isValid(p.code)) p.code else "no result"}): the home's claim, not a verified revocation; local notes and keys are unchanged"
            HomeProblem.StillWaiting -> "a pass could not finish: the engine was still waiting"
            else -> p.toString()
        }
        fun describe(f: HomeFault): String = with(f.fault) {
            "$kind" + (status?.let { " $it" } ?: "") + (code?.let { " $it" } ?: "") + (why?.let { " ($it)" } ?: "")
        }
    }

    val paths = Paths(app)
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    val observer = HomeObserver()
    /** Bumped whenever something on screen may have changed. */
    val changes = MutableStateFlow(0L)

    var settings: Settings = paths.loadSettings(); private set
    var session: ColophonSession? = null; private set
    val log = ArrayDeque<LogEntry>()
    var notes: List<Note> = listOf(); private set
    var notesProblem: String? = null; private set
    var heldRefused = 0 to 0; private set
    var lastSync: SyncOutcome? = null; private set
    var busy: String? = null; private set
    var actionError: String? = null
    var shownPayload: String? = null; private set
    private var watch: Job? = null
    /** The activity in front, for Credential Manager's UI. */
    var activity: WeakReference<Activity> = WeakReference(null)

    val isOwner: Boolean get() = settings.owner == OwnerChoice.PASSKEY || settings.owner == OwnerChoice.DEVICE_KEY

    init {
        if (settings.slot != null) openSession(null)
        record("app started; home prefix ${settings.homePrefix}, reach ${settings.reachPrefix.ifEmpty { "-" }}")
    }

    private fun bump() { changes.value = changes.value + 1 }

    fun record(text: String) {
        log.addLast(LogEntry(System.currentTimeMillis(), text))
        while (log.size > 200) log.removeFirst()
        if (BuildConfig.DEBUG) {
            // Debug builds mirror the log to files/log.txt for scripted runs (the same non-secret lines).
            val line = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(Date()) + " " + text + "\n"
            scope.launch(Dispatchers.IO) { synchronized(paths) { try { paths.logFile.appendText(line) } catch (_: Exception) {} } }
        }
        bump()
    }

    // MARK: Session

    private fun ownerKeys(): AsyncKeyProvider = when (settings.owner) {
        OwnerChoice.PASSKEY -> settings.passkeyDescriptor?.let {
            PasskeyController(PasskeyProvider.restore(it.toByteArray(), ActivityCredentials()), passkeyOrigins())
        } ?: NoOwner
        OwnerChoice.DEVICE_KEY -> TestOwner.keys(app, OWNER_ALIAS) ?: NoOwner
        OwnerChoice.NONE, null -> NoOwner
    }
    private fun passkeyOrigins(): List<String> = runCatching { appPasskeyOrigins(app) }.getOrDefault(listOf()) + "https://${BuildDefaults.relyingParty}"

    /** Builds the one session for this install's account. `request` is set only when this device creates the account. */
    private fun openSession(request: (suspend (String) -> ByteArray)?) {
        val base = settings.homeBase ?: return
        val transport = MappedTransport(settings.homePrefix, settings.reachPrefix, observer)
        val home = HomeConfiguration("$base/", label = "Test home", request = request, transport = transport)
        paths.session.mkdirs()
        val configuration = SessionConfiguration(
            memberLabel = "Android test app", memberKind = AccountMemberKind.APP, namespaces = listOf(NotesFold.NAMESPACE),
            medium = FolderMedium(paths.records), privateDirectory = paths.session,
            keys = AndroidSession.memberKeys(app, MEMBER_ALIAS), ownerController = ownerKeys(), homes = listOf(home),
            deviceSecrets = KeystoreDeviceSecrets(paths.deviceKeys, KeystoreDeviceSecrets.androidKeystoreKey(DEVICE_KEY_ALIAS)))
        val session = ColophonSession(configuration)
        this.session = session
        var seen: SessionState? = null
        watch?.cancel()
        watch = scope.launch {
            session.state.collect { now ->
                val before = seen; seen = now
                if (before?.phase != now.phase) record("phase ${now.phase}")
                if (before?.lastError != now.lastError && now.lastError != null) record("session error: ${now.lastError}")
                if (before?.syncState != now.syncState) record("sync state ${now.syncState}")
                if (before?.homeFaults != now.homeFaults) record("home faults: ${now.homeFaults.joinToString("; ") { describe(it) }.ifEmpty { "none" }}")
                if (before?.homeIssues != now.homeIssues) record("home issues: ${now.homeIssues.joinToString("; ") { describe(it.problem) }.ifEmpty { "none" }}")
                if (before?.notices?.pending?.size != now.notices.pending.size) record("pending changes: ${now.notices.pending.size}")
                if (before?.members?.size != now.members.size) record("members: ${now.members.size}")
                if (before?.requests?.size != now.requests.size) record("requests waiting: ${now.requests.size}")
                if (before?.namespaceRevisions?.get(NotesFold.NAMESPACE) != now.namespaceRevisions[NotesFold.NAMESPACE]) reloadNotes()
                bump()
            }
        }
        scope.launch { session.restore() }
    }

    private suspend fun perform(label: String, body: suspend () -> Unit) {
        busy = label; actionError = null; bump()
        try { body() } catch (e: CancellationException) { throw e } catch (e: Exception) {
            actionError = "$label failed: ${message(e)}"; record(actionError!!)
        } finally { busy = null; bump() }
    }

    fun updateHome(prefix: String, reach: String, provisioner: String, token: String) {
        if (settings.slot != null) return
        settings = settings.copy(homePrefix = prefix.trim(), reachPrefix = reach.trim(), provisioner = provisioner.trim(), provisionerToken = token.trim())
        paths.save(settings)
    }

    // MARK: Create and join

    suspend fun create(owner: OwnerChoice) = perform("Create account") {
        if (settings.provisioner.isEmpty()) throw Provisioner.Failure("Set the home service URL first: it provisions the home for the new account.")
        if (owner == OwnerChoice.DEVICE_KEY && !TestOwner.AVAILABLE) throw Provisioner.Failure("this build has no test owner key")
        var next = settings.copy(slot = Settings.newSlot(), owner = owner)
        if (owner == OwnerChoice.PASSKEY) next = next.copy(passkeyDescriptor = registerPasskey())
        val base = next.homeBase!!
        val service = next.provisioner
        val token = next.provisionerToken
        val slot = next.slot!!
        settings = next
        withContext(Dispatchers.IO) { paths.save(next) }
        record("creating an account at $base (owner: ${owner.wire})")
        openSession { account -> Provisioner.memberRequest(service, token, slot, base, account) }
        val session = session ?: return@perform
        session.create()
        if (session.phase != SessionPhase.Ready) {
            throw Provisioner.Failure("the account was not created: phase ${session.phase}, ${session.lastError ?: "no error given"}")
        }
        record("account ${session.libraryId} created; this device's member ${session.memberId}")
    }

    /** Registers a passkey with Credential Manager and keeps its core-parsed descriptor (public). */
    private suspend fun registerPasskey(): String {
        val userID = ByteArray(32).also(SecureRandom()::nextBytes)
        val provider = PasskeyProvider.register(BuildDefaults.relyingParty, "Colophon test", userID, "Colophon test", "Colophon test", ActivityCredentials())
        return String(provider.descriptor())
    }

    /** An invite that a link, a scan or a paste brought, waiting for the person to confirm. Nothing is stored until then. */
    class PendingInvite(val text: String, val invite: PairingPayload.Invite) {
        val host: String get() = try { java.net.URI(invite.homePrefix).host ?: invite.homePrefix } catch (_: Exception) { invite.homePrefix }
        val accountShort: String get() = invite.account.take(8) + "…" + invite.account.takeLast(4)
    }
    var pendingInvite: PendingInvite? = null; private set
    /** A request a link brought, shown in Devices for the person to import or ignore; never imported by the link. */
    var pendingRequestText: String? = null
    /** Requests whose code the person said matches on both screens, this run only. */
    val confirmedCodes = HashSet<String>()

    /** Decodes an invite (bounded) and shows it for confirmation. Stores nothing. */
    suspend fun prepareJoin(text: String) = perform("Read invite") {
        checkAttempts()
        try {
            val pending = PendingInvite(text, PairingPayload.decodeInvite(text))
            pendingInvite = pending
            record("invite read: home ${pending.host}, account ${pending.accountShort}; waiting for confirmation")
        } catch (e: Exception) { countFailure(); throw e }
    }
    fun cancelJoin() { pendingInvite = null; record("invite dismissed") }

    /**
     * The person confirmed: verify the invite's history in memory first, and only when it verifies and names the account
     * the invite claims, store it and the settings, open the session and show this device's request.
     */
    suspend fun confirmJoin() {
        val pending = pendingInvite ?: return
        perform("Join account") {
            checkAttempts()
            val invite = pending.invite
            val now = System.currentTimeMillis()
            val verified = withContext(Dispatchers.Default) {
                val entries = invite.history.toSortedMap().values.map { ByteString(it) }
                accountVerifyHistory(AuthorityObjects(entries, listOf(), listOf(), listOf()), now).account
            }
            if (verified != invite.account) {
                countFailure()
                throw Provisioner.Failure("the invite's history does not verify as account ${pending.accountShort}; nothing was stored")
            }
            val next = settings.copy(homePrefix = invite.homePrefix, slot = invite.slot, owner = OwnerChoice.NONE)
            withContext(Dispatchers.IO) {
                paths.records.mkdirs()
                FolderMedium(paths.records).write(invite.history.toSortedMap().map { MediumWrite(it.key, it.value) })
                paths.save(next)
            }
            settings = next
            pendingInvite = null
            record("joining account ${invite.account} at ${next.homeBase} with ${invite.history.size} verified history entries")
            openSession(null)
            val session = session ?: return@perform
            session.restore()
            if (session.libraryId != invite.account) throw Provisioner.Failure("the stored history is for account ${session.libraryId ?: "none"}, not ${invite.account}")
            requestPayload()
        }
    }

    // Attempts: spec §7.3 allows an existing side no more than 5 failed sessions an hour; the apps hold both sides to it.
    private fun recentFailures(): List<Long> = settings.failures.filter { System.currentTimeMillis() - it < 3_600_000 }
    private fun checkAttempts() {
        if (recentFailures().size >= ATTEMPT_LIMIT) throw Provisioner.Failure("$ATTEMPT_LIMIT pairing attempts failed or were rejected in the last hour: wait before trying again")
    }
    private fun countFailure() {
        settings = settings.copy(failures = recentFailures() + System.currentTimeMillis())
        try { paths.save(settings) } catch (_: Exception) {}
    }

    suspend fun invitePayload(): String {
        val session = session ?: throw SessionError.NotReady()
        val account = session.libraryId ?: throw SessionError.NotReady()
        val history = withContext(Dispatchers.IO) {
            val medium = FolderMedium(paths.records)
            medium.listing().filter { PairingPayload.isHistoryPath(it.path) }.associate { it.path to medium.read(it.path) }
        }
        val text = PairingPayload.encode(PairingPayload.Invite(settings.homePrefix, settings.slot!!, account, history))
        show(text, "invite (${history.size} history entries, ${text.length} characters)")
        return text
    }

    suspend fun requestPayload(): String {
        val session = session ?: throw SessionError.NotReady()
        val text = PairingPayload.encodeRequest(session.exportRequest())
        show(text, "request (${text.length} characters)")
        return text
    }

    private suspend fun show(text: String, what: String) {
        shownPayload = text
        record("showing $what")
        if (BuildConfig.DEBUG) withContext(Dispatchers.IO) { paths.outbox.writeText(text) }
    }

    suspend fun importRequest(text: String) = perform("Import request") {
        val session = session ?: throw SessionError.NotReady()
        checkAttempts()
        pendingRequestText = null
        val request = try { PairingPayload.decodeRequest(text) } catch (e: Exception) { countFailure(); throw e }
        session.importRequest(request)
        record("imported a request; waiting: ${session.requests.joinToString { "${it.label} ${it.pairingCode}" }}")
    }

    /** The person says the code on this screen and on the joining device are the same. */
    fun confirmCodes(request: AccessRequest) { confirmedCodes.add(request.id); record("codes confirmed for ${request.label} ${request.pairingCode}") }

    /** Discards a request: it is hidden from now on and counts as a failed attempt. */
    fun reject(request: AccessRequest) {
        confirmedCodes.remove(request.id)
        settings = settings.copy(rejected = settings.rejected + request.id)
        countFailure()
        record("rejected the request ${request.label} ${request.pairingCode}")
    }

    /** The requests waiting, without the ones the person rejected. */
    val visibleRequests: List<AccessRequest> get() = (session?.requests ?: listOf()).filter { it.id !in settings.rejected }

    suspend fun approve(request: AccessRequest) = perform("Approve ${request.pairingCode}") {
        val session = session ?: throw SessionError.NotReady()
        if (request.id !in confirmedCodes) throw Provisioner.Failure("confirm that the codes match first")
        session.approve(request)
        record("approved ${request.label} ${request.id}")
        sync()
    }

    suspend fun revoke(member: AccountMember) = perform("Revoke ${member.label}") {
        val session = session ?: throw SessionError.NotReady()
        session.revoke(member.id)
        record("revoked ${member.label} ${member.id}")
        sync()
    }

    suspend fun veto(pending: Pending) = perform("Veto") {
        (session ?: throw SessionError.NotReady()).veto(pending.digest)
        record("vetoed ${pending.digest}")
    }

    // MARK: Sync

    suspend fun sync() {
        val session = session ?: return
        val ok = session.syncNow()
        val faults = session.homeFaults.map { describe(it) }
        val issues = session.homeIssues.map { describe(it.problem) }
        val sighting = observer.snapshot()
        val parts = mutableListOf("phase ${session.phase}", "sync state ${session.state.value.syncState}")
        if (faults.isNotEmpty()) parts += "faults: " + faults.joinToString("; ")
        if (issues.isNotEmpty()) parts += "issues: " + issues.joinToString("; ")
        sighting.lastRefusal?.takeIf { System.currentTimeMillis() - it.atMs < 30_000 }?.let {
            parts += "last refusal: ${it.status} ${it.method} ${it.path} ${it.detail}"
        }
        sighting.transportError?.let { parts += "transport: $it" }
        parts += sighting.head?.let { "home head seq ${it.seq} issued ${it.issued}" } ?: "no head read yet"
        val kind = if (!ok) SyncOutcome.Kind.FAILED else if (faults.isEmpty() && issues.isEmpty()) SyncOutcome.Kind.COMPLETE else SyncOutcome.Kind.INCOMPLETE
        lastSync = SyncOutcome(System.currentTimeMillis(), kind, parts.joinToString("\n"))
        record("sync ${kind.name.lowercase()}: ${parts.joinToString(" | ")}")
    }

    // MARK: Notes

    fun reloadNotes() {
        val session = session ?: return
        scope.launch {
            if (!session.hasUsableContent) { notes = listOf(); notesProblem = null; bump(); return@launch }
            try {
                val labels = session.state.value.members.associate { it.id to it.label }
                val folded = NotesFold.fold(session.view(NotesFold.NAMESPACE), labels)
                notes = folded.notes; heldRefused = folded.held to folded.refused; notesProblem = null
            } catch (e: CancellationException) { throw e } catch (e: Exception) { notesProblem = message(e) }
            bump()
        }
    }

    suspend fun saveNote(id: String?, text: String, photo: ByteArray?, keep: Note.Photo?, observed: ObservedRevision): Boolean {
        var saved = false
        perform(if (id == null) "Add note" else "Save note") {
            val session = session ?: throw SessionError.NotReady()
            val noteId = id ?: UUID.randomUUID().toString()
            var attached = keep
            if (photo != null) {
                val blob = session.putBlob(photo, NotesFold.NAMESPACE, "image/jpeg", noteId, required = true)
                attached = Note.Photo(blob.digest, blob.mediaType, blob.size)
            }
            val receipt = session.perform(DomainCommand(NotesFold.NAMESPACE, NotesFold.KIND, NotesFold.payload(noteId, text, attached)), observed)
            record("note ${noteId.take(8)} written: $receipt")
            saved = true
            reloadNotes()
            session.requestSync()
        }
        return saved
    }

    suspend fun deleteNote(note: Note) = perform("Delete note") {
        val session = session ?: throw SessionError.NotReady()
        val receipt = session.perform(DomainCommand(NotesFold.NAMESPACE, NotesFold.KIND, NotesFold.payload(note.id, "", null, deleted = true)), session.observedRevision)
        record("note ${note.id.take(8)} deleted: $receipt")
        reloadNotes()
        session.requestSync()
    }

    suspend fun photo(note: Note): ByteArray {
        val session = session ?: throw SessionError.NotReady()
        return session.blobData(NotesFold.NAMESPACE, note.photo?.digest ?: throw SessionError.NotReady())
    }

    // MARK: Lock, sign out, reset

    suspend fun lock() { session?.lock(); record("locked") }
    suspend fun unlock() { session?.unlock(); record("unlock: phase ${session?.phase}") }

    /** Wipes this device's account: records, the session's private state, member, owner and device keys. Home settings stay. */
    suspend fun signOut() = perform("Sign out") {
        stopSession()
        wipeAccount()
        settings = settings.copy(slot = null, owner = null, passkeyDescriptor = null)
        withContext(Dispatchers.IO) { paths.save(settings) }
        record("signed out: local account state wiped")
    }

    /** Sign out, and forget the settings and the log too. */
    suspend fun resetDevice() = perform("Reset this device") {
        stopSession()
        wipeAccount()
        withContext(Dispatchers.IO) { paths.root.deleteRecursively(); paths.outbox.delete(); paths.logFile.delete() }
        settings = Settings()
        log.clear()
        record("device reset to the build's defaults")
    }

    private suspend fun stopSession() {
        session?.let { it.stopSync(); it.shutdown() }
        watch?.cancel(); watch = null
        session = null; notes = listOf(); lastSync = null; shownPayload = null
        observer.reset()
    }

    private suspend fun wipeAccount() = withContext(Dispatchers.IO) {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in store.aliases().toList()) if (alias.startsWith(PREFIX)) store.deleteEntry(alias)
        if (paths.account.exists() && !paths.account.deleteRecursively()) throw IllegalStateException("cannot delete the account's files")
    }

    // MARK: Links

    /** `colophontest://join?p=CTJ1.…` and `colophontest://request?p=CTR1.…` (QR codes and scripted runs). */
    suspend fun open(uri: android.net.Uri) {
        if (uri.scheme != "colophontest") return
        val p = uri.getQueryParameter("p") ?: return
        record("opened link ${uri.host}")
        when {
            // A link only fills a screen the person must confirm: it never joins, imports or approves by itself.
            uri.host == "join" && settings.slot == null -> prepareJoin(p)
            uri.host == "request" && isOwner -> { pendingRequestText = p; record("a request arrived by link: shown in Devices, not imported") }
            else -> { actionError = "This link does not fit this device's state (${uri.host})."; bump() }
        }
    }

    /** Credential Manager needs the activity in front; this looks it up at each ceremony. */
    private inner class ActivityCredentials : CredentialClient {
        private fun adapter() = CredentialManagerAdapter(activity.get() ?: throw IllegalStateException("no activity for the passkey prompt"))
        override suspend fun create(requestJson: String): String = adapter().create(requestJson)
        override suspend fun get(requestJson: String): String = adapter().get(requestJson)
    }
}

/** A device that joined an account holds no owner key: every owner step fails plainly. */
object NoOwner : AsyncKeyProvider {
    override suspend fun publicKeys(): PublicKeys = throw SessionError.OwnerRequired()
    override suspend fun sign(body: ByteArray): ByteArray = throw SessionError.OwnerRequired()
    override suspend fun sharedSecret(peer: ByteArray): SecretBytes = throw SessionError.OwnerRequired()
}

