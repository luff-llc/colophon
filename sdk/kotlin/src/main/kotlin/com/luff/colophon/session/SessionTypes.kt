package com.luff.colophon.session

import com.luff.colophon.AccessKind
import com.luff.colophon.AccountMember
import com.luff.colophon.AccountMemberKind
import com.luff.colophon.AccountPairing
import com.luff.colophon.ControllerRole
import com.luff.colophon.Home
import com.luff.colophon.Notices
import com.luff.colophon.Owed
import com.luff.colophon.Pending
import com.luff.colophon.SeenActivation
import java.io.File

/** Where the session stands. The engine decides every verdict; the session only chooses what to show. */
sealed class SessionPhase {
    object Opening : SessionPhase() { override fun toString() = "Opening" }
    object NoLibrary : SessionPhase() { override fun toString() = "NoLibrary" }
    object Creating : SessionPhase() { override fun toString() = "Creating" }
    object WaitingForDownload : SessionPhase() { override fun toString() = "WaitingForDownload" }
    /** This device asked to join and is not approved yet. It shows no code of its own: the six-digit code appears only while it pairs with the approving device (`ColophonSession.beginJoinPairing()`). */
    object WaitingForApproval : SessionPhase() { override fun toString() = "WaitingForApproval" }
    /** A revoked member, or a grant that no longer allows reading. */
    object Denied : SessionPhase() { override fun toString() = "Denied" }
    data class Unavailable(val reason: String) : SessionPhase()
    /** Authenticated content of a newer format than this client evaluates. Nothing is changed or lost. */
    object UpdateRequired : SessionPhase() { override fun toString() = "UpdateRequired" }
    /**
     * New in 0.5 (freeze package): this account was moved to a newer format. A layout raise (spec §20) became final in
     * the history this device verified, so this app must be updated to continue with the account. A verified state, never
     * a home's word or a refusal. What the device holds stays readable ([ColophonSession.hasUsableContent]), as of the stop;
     * nothing is written and no exchange runs; it persists across relaunch; lock and sign-out still work. [seq] is the
     * raising activation's, [layout] the one it names (null: an entry of a newer format, not a raise).
     */
    data class Stopped(val seq: Long, val layout: Long?) : SessionPhase()
    object Ready : SessionPhase() { override fun toString() = "Ready" }
    /** A refresh is in flight; previously verified content is still usable. */
    object Refreshing : SessionPhase() { override fun toString() = "Refreshing" }
    object Retry : SessionPhase() { override fun toString() = "Retry" }
    /** [ColophonSession.lock] ran: content is hidden and no secret is held. */
    object Locked : SessionPhase() { override fun toString() = "Locked" }
    data class Failed(val error: SessionFailure) : SessionPhase()

    internal val usable: Boolean get() = this == Ready || this == Refreshing || this == WaitingForDownload || this == Retry || this is Stopped
    /** True in the stopped phase: this app must be updated to continue with this account. */
    val isStopped: Boolean get() = this is Stopped
}

sealed class SessionFailure {
    data class KeysUnavailable(val detail: String) : SessionFailure()
    data class Other(val detail: String) : SessionFailure()
    val message: String
        get() = when (this) {
            is KeysUnavailable -> "Your identity keys are unavailable. Unlock this device or restore key access, then retry. $detail"
            is Other -> detail
        }
}

sealed class SessionError(message: String) : Exception(message) {
    class NotReady : SessionError("The library is not ready. Restore access and retry.")
    class StaleRevision : SessionError("The library changed while this action was open. Review the current values and try again.")
    class DestinationChanged : SessionError("The selected library or member changed. Start this action again.")
    class InvalidCommand : SessionError("This command is invalid.")
    /** The account would be created without a home and the host did not opt out (spec §18). */
    class NoHome : SessionError("This account has no home. Without one there is no witness of time or order for your changes; add a home before relying on it.")
    /** A step needs the owner controller and this configuration holds none the account's keyring names. */
    class OwnerRequired : SessionError("This step needs the account owner's key.")
    /** A configured home's endpoint is not `https`. */
    class InsecureHome : SessionError("A home must be reached over HTTPS. This one is not, so it was not used.")
}

/** A command is bound to the context and revision observed before the person's action began. */
data class ObservedRevision(val context: String, val revision: Long)

/** One write: the namespace, the record kind and the JSON object payload, passed to the engine as written. */
class DomainCommand(val namespace: String, val kind: String, val payloadJson: String) {
    init {
        if (Json.obj(payloadJson) == null) throw SessionError.InvalidCommand()
    }
}

sealed class WriteReceipt {
    /** The signed record is durable in this device's store. Homes receive it on the next exchange. */
    data class Saved(val operationId: String) : WriteReceipt()
    object Queued : WriteReceipt() { override fun toString() = "Queued" }
}

/** A delivery route a host registers with each home (§17.5: at least two, on different devices or services). */
data class DeliveryRoute(val kind: Kind, val address: String, val reaches: String) {
    enum class Kind { PUSH, EMAIL, SMS, WEBHOOK, OTHER }
}

/** A home the account names, as this host reaches it. */
class HomeConfiguration(
    /** The home's base URL, as the account names it (`Home.endpoints`). */
    val endpoint: String,
    val label: String = "Home",
    /**
     * Asks the home service for its signed member request (§9.1) for a new account, to appoint it when this host
     * creates the account. The session calls it with the new account's ID. Null: the home is not appointed here.
     */
    val request: (suspend (account: String) -> ByteArray)? = null,
    /** Storage bearer token (access to the home's store only, never membership). */
    val bearerToken: String? = null,
    transport: HomeTransport? = null,
    /** Testing option: allow a plain `http` endpoint on a loopback address. */
    val allowsLoopbackHttp: Boolean = false,
    val deliveryRoutes: List<DeliveryRoute> = listOf(),
    /** Registers routes with the home; false when it offers no registration. Null: not offered (the relay has none yet). */
    val registerRoutes: (suspend (account: String, routes: List<DeliveryRoute>) -> Boolean)? = null,
) {
    val transport: HomeTransport = transport ?: HttpHomeTransport(allowingLoopbackHttp = allowsLoopbackHttp)
    val isAllowed: Boolean get() = HomeLimits.isAllowed(endpoint, allowsLoopbackHttp)
}

/** Who may read an account's history at its homes (`policy.history`, spec §13.4). */
enum class HistoryAccess(val wire: String) { EVERYONE("public"), MEMBERS("members") }

/** One `services` entry of a member's terms (spec §10.1): an audience and the purposes (or `["*"]`) it may call there. */
data class ServiceTerms(val audience: String, val purposes: List<String>)

/**
 * What an approver grants of a request that asks for `services`, narrowing it (spec §10.1, §10.3): `services` keeps
 * entries for audiences the request names with purposes it asks (null: as requested); `expires` (a §2.2 date) and
 * `conditionsJson` (a JSON array of §10.4 predicates) are added. Everything else in the request is kept. A grant wider
 * than the request is `SessionError.InvalidCommand`, and nothing is signed.
 */
data class ServiceGrant(val services: List<ServiceTerms>? = null, val expires: String? = null, val conditionsJson: String? = null)

/**
 * A home's door refused a provisioning request (`ColophonSession.provisionRequest`): `status` is the HTTP status and
 * `code` the `result` it gave when valid (for a refused grant call, the core's code, such as `refused:revoked`; a 403 is
 * final, never retried on another path). `retryAfterSeconds` is its `Retry-After`.
 */
class ProvisionRefusal(val status: Int, val code: String?, val retryAfterSeconds: Int?) :
    Exception("the home refused to provision: $status${code?.let { " $it" } ?: ""}")

/** A further controller the account is created with (spec §18). It signs its own possession proof at creation. */
/** What [ColophonSession.appointHomes] left the account with. */
sealed class HomesAppointment {
    /** The homes are current, the added controller (if any) is current with its own slot, and the session syncs with them. */
    object Done : HomesAppointment() { override fun toString() = "Done" }
    /**
     * Not done yet: a home was already current, so the transitions have a delay and a veto window (or an activation waits to
     * be final). [transitions] are the digests of the pending transitions of this owner that carry what was asked, sorted
     * (empty when only finality is awaited). Call `appointHomes` again with the same arguments later to finish.
     */
    data class Pending(val transitions: List<String>) : HomesAppointment()
}

class AdditionalController(val provider: AsyncKeyProvider, val label: String, val roles: List<ControllerRole> = listOf(ControllerRole.APPROVE, ControllerRole.CONTROL))

/** The session's configuration: one per process and account. */
class SessionConfiguration(
    val memberLabel: String,
    val memberKind: AccountMemberKind = AccountMemberKind.APP,
    val namespaces: List<String>,
    val access: Set<AccessKind> = setOf(AccessKind.READ, AccessKind.WRITE),
    /**
     * Services this member asks for (spec §10.1 `services`): each an audience and the purposes it may call there. Its
     * request's terms then carry them, beside `records` when `namespaces` is not empty (a member that only signs calls,
     * such as a test rig, asks for no namespace). `ColophonSession.signCall` signs only for what is asked here.
     */
    val services: List<ServiceTerms> = listOf(),
    libraryNamespaces: List<String>? = null,
    /** The account's record store: `FolderMedium` (app-private storage) or `MemoryMedium` (tests). */
    val medium: RecordMedium,
    /** A private directory for the session journal and the sealed saved state (never synchronised, never shared). */
    val privateDirectory: File,
    /** This app's content member key. Never reused as a controller. */
    val keys: AsyncKeyProvider,
    /** The person's controller key (a passkey or an owner key): asked only for owner operations. */
    val ownerController: AsyncKeyProvider,
    /** An optional recovery kit controller (`recover` only, with its own slot). */
    val recoveryKeys: AsyncKeyProvider? = null,
    /** Spec §18: a host creates every account with at least one home and warns when there is none. */
    val homes: List<HomeConfiguration> = listOf(),
    /** Explicit opt-out of §18 (tests). The account then reports `noHome`. */
    val createWithoutHome: Boolean = false,
    val additionalControllers: List<AdditionalController> = listOf(),
    /** Where the 32-byte device key that seals saved state is kept. */
    val deviceSecrets: DeviceSecretStore,
    /** `policy.recoveryDelay` (seconds) of a new account. */
    val recoveryDelay: Long? = null,
    /** `policy.history` of a new account. */
    val history: HistoryAccess? = null,
    /** `policy.headQuorum` of a new account. */
    val headQuorum: Int? = null,
    /** The clock in milliseconds, for tests. Everything the engine judges by time uses it. */
    val now: () -> Long = { System.currentTimeMillis() },
) {
    val libraryNamespaces: List<String> = libraryNamespaces ?: namespaces
}

/**
 * A member's request for access, as an approver sees it. It carries no code: approving it spends a confirmed pairing for
 * exactly its key (spec §9.1), from the six-digit code (`beginApproval`, `approvalCode`) or from scanning the request on
 * the joining device's screen (`scanRequest`).
 */
data class AccessRequest(
    /** The member's key ID. */
    val id: String,
    val label: String,
    val kind: AccountMemberKind,
    val termsJson: String,
    /** The request exactly as signed (the canonical envelope); the joining device shows it as a QR code (`exportRequest()`). */
    val record: ByteArray,
) {
    val namespaces: List<String> get() = records.map { it.first }
    val access: Set<AccessKind> get() = if (records.any { it.second == "write" }) setOf(AccessKind.READ, AccessKind.WRITE) else setOf(AccessKind.READ)
    /** The services the request asks for (spec §10.1), read from its terms. */
    val services: List<ServiceTerms> get() = SessionWorker.requestedServices(termsJson)
    private val records: List<Pair<String, String>>
        get() = Json.obj(termsJson)?.list("records")?.mapNotNull { e ->
            @Suppress("UNCHECKED_CAST") val m = e as? Map<String, Any?> ?: return@mapNotNull null
            m.string("namespace")?.let { it to (m.string("access") ?: "read") }
        } ?: listOf()
    override fun equals(other: Any?) = other is AccessRequest && other.id == id && other.record.contentEquals(record)
    override fun hashCode() = id.hashCode()
}

/** The approving device's half of the six-digit code (§7.3): the session it opened when the commitment arrived, and the nonce to send back. */
class ApprovalStart(val pairing: AccountPairing, val nonce: ByteArray)

/** A request scanned from the joining device's screen, with the confirmed pairing that scan made (§7.3, §9.1). Nothing is stored for it. */
class ScannedRequest(val request: AccessRequest, val pairing: AccountPairing)

/** What a person may be shown about this account that is not content (§17.5, §18). */
data class SessionNotices(val notices: Notices) {
    /** Transitions still pending, with signers, first-seen seq, deadline and `vetoable`. */
    val pending: List<Pending> get() = notices.pending
    /** Activations no key on this device signed that the person has not seen. */
    val unseenActivations: List<SeenActivation> get() = notices.activations
    /** The account names no home: warn (spec §18). */
    val noHome: Boolean get() = notices.noHome
    val owed: List<Owed> get() = notices.owed
    companion object {
        val empty = SessionNotices(Notices(listOf(), listOf(), listOf(), listOf(), false, false))
    }
}

data class RouteState(val home: String, val label: String, val registered: Boolean, val detail: String)

/** The outcome of submitting a transition, veto or `suspend` to every current home (§17.5). */
data class Submission(val obj: String, val kind: Kind, val receipted: Int, val homes: Int, val finished: Boolean) {
    enum class Kind { TRANSITION, VETO, SUSPEND }
    val complete: Boolean get() = homes > 0 && receipted >= homes
}

/** A transition fewer than `headQuorum` homes receipted within 300 s of its `issued`: dead (§17.5). */
data class DeadTransition(val digest: String, val receipted: Int, val quorum: Int, val canResign: Boolean)

/** The removal follow-up of one activation that removed controllers (§17.5), as the person is shown it. */
data class RemovalCard(val seq: ULong, val removed: List<String>, val members: List<Item>, val controllers: List<Item>) {
    data class Item(val id: String, val label: String)
}

/** What a host must do and say beyond the engine's notices (§17.5). */
data class HostDuties(
    /** The account has one control key: a stolen sole device can't be vetoed. */
    val soleDevice: Boolean = false,
    val routes: List<RouteState> = listOf(),
    val submissions: List<Submission> = listOf(),
    val deadTransitions: List<DeadTransition> = listOf(),
    val removals: List<RemovalCard> = listOf(),
    val homeLabels: Map<String, String> = mapOf(),
    /** How often the session polls the homes: `recoveryDelay` / 6, or 15 s while something is pending. */
    val pollIntervalMs: Long = 600_000,
)

/** Everything the session publishes, as one value. */
data class SessionState(
    val phase: SessionPhase = SessionPhase.Opening,
    val revision: Long = 0,
    val namespaceRevisions: Map<String, ULong> = mapOf(),
    val libraryId: String? = null,
    val memberId: String? = null,
    val members: List<AccountMember> = listOf(),
    val requests: List<AccessRequest> = listOf(),
    val lastError: String? = null,
    val context: String = "",
    val notices: SessionNotices = SessionNotices.empty,
    val homes: List<Home> = listOf(),
    val duties: HostDuties = HostDuties(),
    val syncState: HomeSyncState = HomeSyncState.Disabled,
    val lastSyncedMs: Long? = null,
    val homeFaults: List<HomeFault> = listOf(),
    val homeIssues: List<HomeIssue> = listOf(),
)
