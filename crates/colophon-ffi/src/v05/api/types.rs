//! The typed values of the 0.5 surface: records and C-like enums, defined once. UniFFI derives
//! `Record` and `Enum` from them; the wasm build exposes the same records as classes with
//! typed getters and setters (`Uint8Array` for bytes, `bigint` for 64-bit integers) and the
//! same enums as numeric enums. A value that the protocol or a domain leaves open (terms,
//! policy documents, record payloads, view and query results) stays UTF-8 JSON in a `*_json`
//! field or a `String`, as in 0.4.
//!
//! No record here has `Debug`, `Clone` or `Serialize`: some carry secrets the host supplied
//! (`UnlockSecret`, `PrfAnswer`, `EpochAnswer`), and those are wiped by the call that consumes
//! them.
use super::fault::AccountError;

/// A plain record. On the web build every field is a getter and a setter, the class has a
/// constructor taking every field in order, and the record is `Clone` (wasm-bindgen's getters
/// clone their field). `secret_record!` is the same without `Clone`.
macro_rules! record {
    ($(#[$m:meta])* pub struct $n:ident { $( $(#[$fm:meta])* pub $f:ident : $t:ty ),* $(,)? }) => {
        $(#[$m])*
        #[cfg_attr(feature = "web05", derive(Clone))]
        #[cfg_attr(feature = "native05", derive(uniffi::Record))]
        #[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen(getter_with_clone))]
        pub struct $n { $( $(#[$fm])* pub $f: $t ),* }
        #[cfg(feature = "web05")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl $n {
            /// Every field, in order.
            #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
            #[allow(clippy::too_many_arguments)]
            pub fn new($($f: $t),*) -> $n { $n { $($f),* } }
        }
    };
}
/// A record that carries a secret the host supplied: never `Clone`, never `Debug`.
macro_rules! secret_record {
    ($(#[$m:meta])* pub struct $n:ident { $( $(#[$fm:meta])* pub $f:ident : $t:ty ),* $(,)? }) => {
        $(#[$m])*
        #[cfg_attr(feature = "native05", derive(uniffi::Record))]
        #[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen(getter_with_clone))]
        pub struct $n { $( $(#[$fm])* pub $f: $t ),* }
        #[cfg(feature = "web05")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl $n {
            /// Every field, in order.
            #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
            #[allow(clippy::too_many_arguments)]
            pub fn new($($f: $t),*) -> $n { $n { $($f),* } }
        }
    };
}
/// A C-like enum.
macro_rules! cenum {
    ($(#[$m:meta])* pub enum $n:ident { $( $(#[$vm:meta])* $v:ident ),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[cfg_attr(feature = "native05", derive(uniffi::Enum))]
        #[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
        pub enum $n { $( $(#[$vm])* $v ),* }
    };
}

cenum! {
    /// What a signature is for in a batch.
    pub enum StepRole { Primary, Cosignature, Possession, Handover }
}
cenum! {
    /// The signature form a signer uses. `Unknown` is a form a newer writer made: it can be
    /// shown and counted, never created or checked here.
    pub enum SignForm { Raw, Webauthn, Unknown }
}
cenum! {
    /// A controller's role (§6.1). `Unknown` is a role a newer writer made.
    pub enum ControllerRole { Approve, Control, Recover, Sign, Unknown }
}
cenum! {
    /// What kind of action a prepared action is.
    pub enum ActionKind {
        Approve, Renew, RenewShares, Revoke, EndSessions, EndMySessions, Rekey, Keyring,
        AddController, AddSlot, RotateVault, RemoveController, Transition, Veto, Suspend, Resolve,
        Write, Propose, Resolution, Import, Link, Call
    }
}
cenum! {
    /// What step of moving an old library a prepared move is. `Finished` once it was finished or
    /// consumed.
    pub enum MoveKind { Upgrade, SwiftVeto, SwiftFreeze, SwiftMigration, RenewShares, Finished }
}
cenum! {
    /// How a vault slot opens. `Unknown` is a Swift slot of a form this reader does not know.
    pub enum SlotKind { Sealed, Prf, Combined, Unknown }
}
cenum! {
    /// Whether a home is serving, or its removal has not activated finally.
    pub enum HomeStatus { Home, RevocationPending, Unknown }
}
cenum! {
    /// Why access was refused (§19 access reasons). `Unknown` is a reason a newer writer made;
    /// the raw text is in `reason_raw`.
    pub enum AccountDenialReason { NotGranted, Revoked, Expired, BudgetSpent, NotReadable, Unavailable, Unknown }
}
cenum! {
    /// The check of §4.3 that failed in a WebAuthn assertion, in the order of the spec's steps.
    pub enum SignatureCheck {
        Point, RawLength, Scalar, Der, Verify, ClientData, ClientDataBound, UnknownForm, Type,
        Challenge, Origin, CrossOrigin, RelyingParty, UserPresence, UserVerification, Form,
        CallOrigin
    }
}
cenum! {
    /// How a threshold counts signers.
    pub enum CountBy { Keys, Holders }
}
cenum! {
    /// The kind of an identity: a session is a controller or a member.
    pub enum AccountIdentityKind { Controller, Member }
}
cenum! {
    /// The §1 result of a verification, without the refusal's reason.
    pub enum StatusKind { Ok, Held, Refused, Malformed, BadSignature, NewerFormat, Unavailable }
}
cenum! {
    /// What the engine judged a record to be (§11.5), without the reason.
    pub enum VerdictKind { Admitted, Held, Refused, NewerFormat, Malformed, BadSignature, Unavailable }
}
cenum! {
    /// A member's kind.
    pub enum AccountMemberKind { Device, App, Agent, Server, Unknown }
}
cenum! {
    /// An HTTP method.
    pub enum HttpMethod { Get, Post, Put }
}
cenum! {
    /// How an engine open treated saved state.
    pub enum OpenMode { Cold, Resumed, Invalidated }
}
cenum! {
    /// What the exchange asks the host to do next.
    pub enum ExchangeStepKind { Request, Waiting, NeedCall, Done }
}
cenum! {
    /// What a home did that the engine did not follow.
    pub enum ExchangeFaultKind {
        Rollback, Fork, BadObject, ForeignAccount, NoProgress, Mismatch, Refused, Conflict, Race,
        Unauthorized, Redirect, Malformed, CursorReset, More, HeadAhead, Status
    }
}
cenum! {
    /// What became of a live candidate.
    pub enum LiveVerdictKind { Current, Superseded, Retained, Equivocation, Quarantined, Refused, Invalid }
}
cenum! {
    /// How much of a blob is held locally.
    pub enum BlobState { Complete, Partial, Missing, Inaccessible }
}
cenum! {
    /// What a session is in the verified history.
    pub enum StandingKind { Controller, Member, Unknown }
}
cenum! {
    /// Which of a revoked member's records a revocation keeps.
    pub enum KeepMode { Everything, Nothing, Explicit }
}
cenum! {
    /// The route of a slot an unlock needs the host to answer.
    pub enum UnlockKind { Ecdh, Prf }
}
cenum! {
    /// Where a creation stands.
    pub enum CreateStage { Prf, Genesis, Rekey, Done, Spent }
}
cenum! {
    /// Where a pairing session stands.
    pub enum PairingStage {
        Joiner, Revealed, QrJoiner, Waiting, AwaitingReveal, Code, Scanned, Confirmed, Spent
    }
}
cenum! {
    /// The rule a transition is counted under.
    pub enum RuleKind { Control, Recovery }
}
cenum! {
    /// How a controller is added.
    pub enum AddMode { Immediate, Transition }
}
cenum! {
    /// Which rule a set of signers is chosen for.
    pub enum SignerNeed { Member, Rekey, Control, Recovery, KeyringAdd, Veto }
}
cenum! {
    /// Which check `account_webauthn_check` applies.
    pub enum CheckKind { Authority, Call, SwiftPredecessor }
}
cenum! {
    /// The authority rule a signature is checked for.
    pub enum AuthorityRuleKind {
        Control, Recovery, KeyringEntry, Transition, Veto, Handover, Single, Suspend, Possession
    }
}
cenum! {
    /// Whether a write may be levelled as a write or a proposal.
    pub enum WriteLevel { Write, Propose }
}
cenum! {
    /// The access a grant gives.
    pub enum AccessKind { Read, Write }
}

record! {
    /// Exact bytes the host stores at a path.
    pub struct Store { pub path: String, pub bytes: Vec<u8> }
}
record! {
    /// A listed path with the provider's content-version token (none for none).
    pub struct ListedPath { pub path: String, pub version: Option<String> }
}
record! {
    /// One byte string (a list of them cannot be a field on every platform).
    pub struct ByteString { pub bytes: Vec<u8> }
}
record! {
    /// A key as the protocol writes it (§3.1), the one form the surface uses everywhere.
    /// `raw` keys have `agreement`; `webauthn` keys have `rp`, `credential` and `origins`.
    pub struct KeyDescriptorView {
        pub form: SignForm,
        pub signing: Vec<u8>,
        pub agreement: Option<Vec<u8>>,
        pub rp: Option<String>,
        pub credential: Option<Vec<u8>>,
        pub origins: Vec<String>,
        pub authority_origins: Vec<String>,
    }
}
record! {
    /// Who a session is: a controller of the keyring or a member, with its 32-hex key ID.
    pub struct AccountIdentity { pub kind: AccountIdentityKind, pub id: String }
}
record! {
    /// A controller to add, in the typed form (§6.1): the key as a descriptor, never base64
    /// protocol JSON. `verification` is only for a `webauthn` key; `audiences` only for a `sign`
    /// controller (a `sign` role is alone); `holder` is optional text.
    pub struct ControllerSpec {
        pub key: KeyDescriptorView,
        pub label: String,
        pub roles: Vec<ControllerRole>,
        pub verification: bool,
        pub holder: Option<String>,
        pub audiences: Vec<String>,
    }
}
record! {
    /// The verdict on a record the engine holds or would hold: its kind, and the reason after
    /// `held:` or `refused:` when there is one.
    pub struct RecordVerdict { pub kind: VerdictKind, pub reason: Option<String> }
}
record! {
    /// The exact body and signer of one signature the host makes.
    pub struct AccountSigningStep {
        pub path: String,
        pub body: Vec<u8>,
        pub signer: String,
        pub role: StepRole,
        pub form: SignForm,
        pub descriptor: Option<KeyDescriptorView>,
        pub signing_key: Vec<u8>,
        pub challenge: Option<String>,
        pub uv: bool,
    }
}
record! {
    /// A signature the host made over a step's body: raw `r||s`, or DER with the assertion.
    pub struct Signature {
        pub signature: Vec<u8>,
        pub authenticator_data: Option<Vec<u8>>,
        pub client_data: Option<Vec<u8>>,
    }
}
record! {
    /// The assertion the host must make for a new PRF route (§7.2).
    pub struct PrfRequest {
        pub controller: String,
        pub rp: String,
        pub credential: Vec<u8>,
        pub salt: Vec<u8>,
        pub challenge: Vec<u8>,
    }
}
secret_record! {
    /// The host's answer to a `PrfRequest`. `output` is the 32-byte `results.first`: a secret,
    /// consumed and wiped by the call it is passed to.
    pub struct PrfAnswer {
        pub authenticator_data: Vec<u8>,
        pub client_data: Vec<u8>,
        pub signature: Vec<u8>,
        pub output: Vec<u8>,
    }
}
record! {
    /// One route of a slot the host answers: `Ecdh` against `enc`, or `Prf` with `salt`.
    pub struct UnlockInput {
        pub kind: UnlockKind,
        pub controller: String,
        pub enc: Vec<u8>,
        pub salt: Vec<u8>,
    }
}
secret_record! {
    /// The host's raw result for one `UnlockInput`, in input order: a secret, consumed and wiped.
    pub struct UnlockSecret { pub kind: UnlockKind, pub secret: Vec<u8> }
}
record! {
    /// One ECDH a member's host performs to open a share.
    pub struct EpochAgreement {
        pub namespace: String,
        pub epoch: u64,
        pub recipient: String,
        pub recipient_point: Vec<u8>,
        pub peer: Vec<u8>,
    }
}
secret_record! {
    /// The host's raw ECDH result for one share: a secret, consumed and wiped.
    pub struct EpochAnswer { pub namespace: String, pub epoch: u64, pub shared: Vec<u8> }
}
record! {
    /// A controller a slot names.
    pub struct SlotController { pub id: String, pub label: String }
}
record! {
    /// One slot of the current vault, as a chooser shows it.
    pub struct SlotInfo {
        pub index: u64,
        pub kind: SlotKind,
        pub kind_raw: Option<String>,
        pub label: String,
        pub controllers: Vec<SlotController>,
    }
}
record! {
    /// What a slot is built for: its controllers and label.
    pub struct SlotPlan { pub controllers: Vec<String>, pub label: String }
}
record! {
    /// The verdict on the verified history.
    pub struct Status {
        pub seq: u64,
        pub code: String,
        pub kind: StatusKind,
        pub reason: Option<String>,
        pub stop_seq: Option<u64>,
        pub detail: Option<String>,
        pub rollback: bool,
        /// Set when this reader is stopped for the account (§1 "A stop"): a verified state, not a
        /// fault. The account was moved to a newer format; what this device holds stays
        /// readable and nothing new is built (writes `NewerFormat`, calls and exchange passes
        /// `Unavailable`).
        pub stopped: Option<AccountStop>,
    }
}
record! {
    /// Where a reader stopped (§1 "A stop", §20): the seq of the activation whose final raise
    /// stopped it (or of the entry it judged `newerFormat`), and the layout the raise names
    /// (none for an entry of a newer format that is not a raise). Only from the verified
    /// history, never from a home's answer.
    pub struct AccountStop {
        pub seq: u64,
        pub layout: Option<u64>,
    }
}
record! {
    /// An entry that joined the verified branch.
    pub struct EntryChange { pub seq: u64, pub kind: String }
}
record! {
    /// A namespace whose fold changed, with its new revision.
    pub struct NamespaceRevision { pub namespace: String, pub revision: u64 }
}
record! {
    /// A head a home sent that was refused.
    pub struct RefusedHead { pub home: String, pub code: String }
}
record! {
    /// What a call changed in the account.
    pub struct Changes {
        pub authority_from_seq: u64,
        pub authority_to_seq: u64,
        pub entries: Vec<EntryChange>,
        pub members_added: Vec<String>,
        pub members_revoked: Vec<String>,
        pub controllers_added: Vec<String>,
        pub controllers_removed: Vec<String>,
        pub vault_changed: bool,
        pub policy_changed: bool,
        pub reorganized: bool,
        pub namespaces: Vec<NamespaceRevision>,
        pub pending_added: Vec<String>,
        pub pending_gone: Vec<String>,
        pub pending_now: Vec<String>,
        pub heads_accepted: Vec<String>,
        pub heads_refused: Vec<RefusedHead>,
        pub foreign: u64,
        pub status: Option<Status>,
    }
}
record! {
    /// What a finished action produced: store these bytes at these paths, in order. `artifact`
    /// is the envelope of a link or a call (§12), which is not stored: for the host to use.
    pub struct Written {
        pub stores: Vec<Store>,
        pub changes: Changes,
        pub artifact: Option<Vec<u8>>,
    }
}
record! {
    /// A controller of the verified keyring.
    pub struct Controller {
        pub id: String,
        pub label: String,
        pub roles: Vec<ControllerRole>,
        pub roles_raw: Vec<String>,
        pub key: KeyDescriptorView,
        pub form: SignForm,
        pub verification: bool,
        pub holder: Option<String>,
        pub has_slot: bool,
        pub provisional: bool,
        pub suspended: bool,
        /// The seq of the entry that added it (1 for the genesis).
        pub added_seq: u64,
        /// The controllers that signed that entry (empty for the genesis or a recording entry).
        pub added_by: Vec<String>,
    }
}
record! {
    /// What a grant allows (the 0.4 shape).
    pub struct AccountGrant {
        pub namespaces: Vec<String>,
        pub access: Vec<AccessKind>,
        pub expires: Option<String>,
        pub write_budget: Option<u64>,
        pub import: bool,
    }
}
record! {
    /// A member with its standing.
    pub struct AccountMember {
        pub id: String,
        pub label: String,
        pub kind: AccountMemberKind,
        pub kind_raw: Option<String>,
        pub grant: Option<AccountGrant>,
        pub since: u64,
        pub revoked_at: Option<u64>,
        pub writes: u64,
        pub expires_ms: Option<i64>,
        pub provisional: bool,
        pub home: bool,
        pub session: u64,
        /// The controllers that signed the entry that granted it (empty for a recording entry).
        pub granted_by: Vec<String>,
    }
}
record! {
    /// What this session is. Exactly one of `controller`, `member`, `unknown_id` is set, by `kind`.
    pub struct Standing {
        pub kind: StandingKind,
        pub controller: Option<Controller>,
        pub member: Option<AccountMember>,
        pub unknown_id: Option<String>,
    }
}
record! {
    /// A home the account names.
    pub struct Home {
        pub id: String,
        pub label: String,
        pub status: HomeStatus,
        pub status_raw: Option<String>,
        pub endpoints: Vec<String>,
        pub primary: bool,
    }
}
record! {
    /// The effective policy (§6.3).
    pub struct Policy {
        pub threshold: u64,
        pub recover_threshold: u64,
        pub add_threshold: u64,
        pub count_by_holders: bool,
        pub call_window: u64,
        pub head_max_age: u64,
        pub head_quorum: u64,
        pub link_max_age: u64,
        pub member_rule: String,
        pub recovery_delay: u64,
        pub primary_home: Option<String>,
    }
}
record! {
    /// A signer with its label.
    pub struct Signer { pub id: String, pub label: String }
}
record! {
    /// A pending transition, as §17.5 says it must be shown.
    pub struct Pending {
        pub digest: String,
        pub by: String,
        pub signers: Vec<Signer>,
        pub issued_ms: i64,
        pub anchor_seq: u64,
        pub first_seen_seq: Option<u64>,
        pub due_ms: Option<i64>,
        pub veto_deadline_ms: Option<i64>,
        pub full_set: Option<bool>,
        pub components: Vec<String>,
        pub removes: Vec<String>,
        pub adds: Vec<String>,
        pub vetoes: Vec<String>,
        pub vetoable: bool,
    }
}
record! {
    /// When a home receipted an object.
    pub struct Receipted { pub home: String, pub received_ms: i64 }
}
record! {
    /// An activation the person has not seen.
    pub struct SeenActivation {
        pub seq: u64,
        pub transition: String,
        pub signers: Vec<String>,
        pub components: Vec<String>,
        pub receipted: Vec<Receipted>,
    }
}
record! {
    /// The removal follow-up of one activation that removed controllers (§17.5).
    pub struct RemovalFollowUp {
        pub seq: u64,
        pub anchor_seq: u64,
        pub removed: Vec<String>,
        pub members: Vec<String>,
        pub controllers: Vec<String>,
    }
}
record! {
    /// A share a member is owed (§9.4).
    pub struct Owed {
        pub member: String,
        pub namespace: String,
        pub epoch: u64,
        pub provisional: bool,
    }
}
record! {
    /// What the person must be shown (§17.5).
    pub struct Notices {
        pub pending: Vec<Pending>,
        pub activations: Vec<SeenActivation>,
        pub owed: Vec<Owed>,
        pub controllers_without_slot: Vec<String>,
        pub vault_retiring: bool,
        pub no_home: bool,
    }
}
record! {
    /// A write refused for access reasons: `reason` is one of notGranted, revoked, expired,
    /// budgetSpent, notReadable, unavailable.
    pub struct AccountDenial { pub reason: AccountDenialReason, pub reason_raw: Option<String>, pub detail: String }
}
record! {
    /// Facts about a prepared action a host may show or follow up on.
    pub struct HeadRef { pub namespace: String, pub digest: String }
}
record! {
    /// Facts about a prepared action.
    pub struct ActionInfo {
        pub name: String,
        pub rekey_owed: bool,
        pub owed_namespaces: Vec<String>,
        pub walk_incomplete: bool,
        pub kept: Vec<String>,
        pub heads: Vec<HeadRef>,
    }
}
record! {
    /// Work the engine did.
    pub struct EngineStats {
        pub records_read: u64,
        pub signatures_verified: u64,
        pub payloads_decrypted: u64,
        pub walked_last: u64,
        pub folds_applied_last: u64,
        pub ignored_paths: u64,
        pub held_paths: u64,
        pub unread_paths: u64,
    }
}
record! {
    /// How the open treated saved state: `mode`, and why when it was invalidated.
    pub struct OpenInfo { pub mode: OpenMode, pub reason: Option<String> }
}
record! {
    /// One sealed part of saved state.
    pub struct SavedPart { pub namespace: String, pub bytes: Vec<u8> }
}
record! {
    /// The sealed state a host stores between sessions (caches sealed under the device key).
    /// An empty `verifier` and `checkpoint` mean "no saved state".
    pub struct SavedState {
        pub verifier: Vec<u8>,
        pub checkpoint: Vec<u8>,
        pub parts: Vec<SavedPart>,
    }
}
record! {
    /// Two candidates at a seq a `resolve` may choose between.
    pub struct ForkCandidate { pub seq: u64, pub first: String, pub second: String }
}
record! {
    /// A header of an HTTP message.
    pub struct Header { pub name: String, pub value: String }
}
record! {
    /// A request for the host to send.
    pub struct HttpRequest {
        pub ticket: u64,
        pub home: String,
        pub method: HttpMethod,
        pub url: String,
        pub headers: Vec<Header>,
        pub body: Vec<u8>,
    }
}
record! {
    /// A request that needs a fresh `Authorization: Colophon` call built for exactly it: the
    /// call's audience, purpose and `args` (`{"method","path","body"}`: the method, `path`, and
    /// `body_sha256`). `exchange_begin_call` builds it from these; `url` is `audience` + `path`.
    pub struct CallNeed {
        pub ticket: u64,
        pub home: String,
        pub audience: String,
        pub purpose: String,
        pub method: HttpMethod,
        pub url: String,
        pub path: String,
        pub body_sha256: String,
    }
}
record! {
    /// The next step of an exchange pass. `request` is set for `Request`, `need` for `NeedCall`.
    pub struct ExchangeStep {
        pub kind: ExchangeStepKind,
        pub request: Option<HttpRequest>,
        pub need: Option<CallNeed>,
    }
}
record! {
    /// What the host got back.
    pub struct HttpAnswer { pub status: u32, pub headers: Vec<Header>, pub body: Vec<u8> }
}
record! {
    /// A fault of a home. Which fields are set depends on `kind`: `path` (Mismatch, Conflict,
    /// Race), `feed` (NoProgress, More), `code` (BadObject, Refused), `what` (Refused), `why`
    /// (Malformed), `purpose` and `audience` (Unauthorized), `endpoints` (Redirect), `status`
    /// (Status).
    pub struct ExchangeFault {
        pub kind: ExchangeFaultKind,
        pub home: String,
        pub path: Option<String>,
        pub feed: Option<String>,
        pub code: Option<String>,
        pub what: Option<String>,
        pub why: Option<String>,
        pub purpose: Option<String>,
        pub audience: Option<String>,
        pub endpoints: Vec<String>,
        pub status: Option<u32>,
    }
}
record! {
    /// What one answer produced.
    pub struct Report {
        pub store: Vec<Store>,
        pub changes: Changes,
        pub faults: Vec<ExchangeFault>,
    }
}
record! {
    /// The verdict on a live candidate; `detail` carries the `Quarantined` or `Refused` reason
    /// code or the `Invalid` explanation.
    pub struct LiveVerdict { pub path: String, pub kind: LiveVerdictKind, pub detail: Option<String> }
}
record! {
    /// A live candidate refused for being below its slot's witness.
    pub struct StaleLive { pub path: String, pub generation: u64 }
}
record! {
    /// A live head the verifier accepted.
    pub struct LiveHead {
        pub path: String,
        pub digest: String,
        pub author: String,
        pub namespace: String,
        pub slot: String,
        pub generation: u64,
    }
}
record! {
    /// The slot a live replacement is conditional on (`If-Match`): the sha256 of its bytes.
    pub struct Replaces { pub path: String, pub sha256: String }
}
record! {
    /// A finished live write.
    pub struct LiveWritten {
        pub stores: Vec<Store>,
        pub replaces: Option<Replaces>,
        pub changes: Changes,
    }
}
record! {
    /// How much of a blob is held locally.
    pub struct BlobAvailability {
        pub state: BlobState,
        pub present: u64,
        pub total: u64,
        pub detail: Option<String>,
    }
}
record! {
    /// A sealed chunk to store before the manifest is published.
    pub struct BlobChunk { pub path: String, pub bytes: Vec<u8> }
}
record! {
    /// Progress of the integrity audit.
    pub struct VerifyProgress { pub checked: u64, pub remaining: u64 }
}
record! {
    /// Which of a revoked member's records a revocation keeps (§9.5).
    pub struct RevokeKeep { pub mode: KeepMode, pub kept: Vec<String>, pub heads: Vec<HeadRef> }
}
record! {
    /// What to create. `controllers` are typed (§6.1);
    /// `policy_json` the §6.3 policy document (empty: the §18 person default).
    pub struct CreateParams {
        pub label: String,
        pub namespaces: Vec<String>,
        pub controllers: Vec<ControllerSpec>,
        pub slots: Vec<SlotPlan>,
        pub threshold: Option<u64>,
        pub recover_threshold: Option<u64>,
        pub add_threshold: Option<u64>,
        pub count_by_holders: bool,
        pub policy_json: String,
        pub signers: Vec<String>,
        pub rekey_signers: Vec<String>,
    }
}
record! {
    /// A created account: its ID and everything to store.
    pub struct Created { pub account: String, pub stores: Vec<Store> }
}
record! {
    /// A member's request (§9.1). `custody` and `operator` are empty for none.
    pub struct RequestSpec {
        pub account: String,
        pub signing: Vec<u8>,
        pub agreement: Vec<u8>,
        pub label: String,
        pub kind: AccountMemberKind,
        pub terms_json: String,
        pub created: String,
        pub custody: Option<String>,
        pub operator: Option<String>,
        pub endpoints: Vec<String>,
    }
}
record! {
    /// A history read (`colophon.history.read`) by a member that holds no history yet: the
    /// account, the entry it was given as `asOf`, its signing point, the home's base (the
    /// audience) and the path relative to it, which must serve the history. `request_id` is 32
    /// random bytes.
    pub struct HistoryReadSpec {
        pub account: String,
        pub as_of_seq: u64,
        pub as_of_digest: String,
        pub signing: Vec<u8>,
        pub audience: String,
        pub path: String,
        pub request_id: Vec<u8>,
        pub created: String,
    }
}
record! {
    /// A finished history read: the URL it is bound to, the `Authorization` header value and
    /// the envelope.
    pub struct HistoryReadCall {
        pub url: String,
        pub authorization: String,
        pub envelope: Vec<u8>,
    }
}
record! {
    /// What a joining device accepted: `admitted` with the entries to store, or not admitted
    /// yet (the history names no member with its ID), with nothing to store.
    pub struct JoinedHistory {
        pub admitted: bool,
        pub stores: Vec<Store>,
    }
}
record! {
    /// A current WebAuthn controller (present, final, not suspended) of a history read with a
    /// passkey before admission: its ID, label, roles, descriptor as the history names it, UV
    /// requirement, and whether a slot of the current vault is held by it alone.
    pub struct PasskeyControllerView {
        pub id: String,
        pub label: String,
        pub roles: Vec<ControllerRole>,
        pub roles_raw: Vec<String>,
        pub key: KeyDescriptorView,
        pub verification: bool,
        pub own_slot: bool,
    }
}
record! {
    /// A history a device that is not a member yet read with a passkey (0.5.7): the entries to
    /// store, the controller whose passkey signed the reads, and every current WebAuthn
    /// controller at the tip (the signer included).
    pub struct PasskeyHistoryView {
        pub stores: Vec<Store>,
        pub signer: PasskeyControllerView,
        pub controllers: Vec<PasskeyControllerView>,
    }
}
record! {
    /// One page of a home's history: entries as canonical bytes, and whether more follow.
    pub struct HistoryPage {
        pub entries: Vec<ByteString>,
        pub more: bool,
    }
}
record! {
    /// A verified request as an approver sees it.
    pub struct RequestInfo {
        pub raw: Vec<u8>,
        pub member: String,
        pub label: String,
        pub kind: AccountMemberKind,
        pub kind_raw: Option<String>,
        pub terms_json: String,
    }
}
record! {
    /// The authority objects of an account, for the history verifier.
    pub struct AuthorityObjects {
        pub entries: Vec<ByteString>,
        pub pending: Vec<ByteString>,
        pub heads: Vec<ByteString>,
        pub predecessor: Vec<ByteString>,
    }
}
record! {
    /// A conflict the verifier decided (§8.6).
    pub struct Conflict { pub seq: u64, pub standing: String, pub losing: Vec<String> }
}
record! {
    /// The history verifier's verdict, with no host identity.
    pub struct HistoryReport {
        pub code: String,
        pub kind: StatusKind,
        pub reason: Option<String>,
        pub seq: u64,
        pub detail: Option<String>,
        pub rollback: bool,
        pub account: Option<String>,
        pub branch: Vec<String>,
        pub conflicts: Vec<Conflict>,
        pub held_until_ms: Option<i64>,
    }
}
record! {
    /// How `account_webauthn_check` judges a signature. `kind` selects the fields used:
    /// `rule`, `verification`, `sign_controller` for Authority; `origins`, `uv_required` for
    /// Call; `uv_required` for SwiftPredecessor.
    pub struct WebauthnMode {
        pub kind: CheckKind,
        pub rule: AuthorityRuleKind,
        pub verification: bool,
        pub sign_controller: bool,
        pub origins: Vec<String>,
        pub uv_required: bool,
    }
}
record! {
    /// A verified WebAuthn assertion.
    pub struct WebauthnOk { pub uv: bool, pub origin: String, pub counter: u32 }
}
record! {
    /// An entry of a verified Swift predecessor.
    pub struct SwiftEntry {
        pub seq: Option<u64>,
        pub digest: String,
        pub issued_ms: i64,
        pub layout: Option<u64>,
    }
}
record! {
    /// A verified Swift predecessor history.
    pub struct SwiftPredecessor { pub account: String, pub entries: Vec<SwiftEntry> }
}
record! {
    /// The 0.5 settings an in-place upgrade adds (§16.1). `count_by` is `keys` or `holders`.
    pub struct UpgradeParams {
        pub policy_json: String,
        pub add_threshold: u64,
        pub count_by: CountBy,
        pub issued_ms: i64,
        pub signers: Vec<String>,
    }
}
record! {
    /// The 0.4 account's authority records, by path.
    pub struct LegacyHistory { pub records: Vec<Store> }
}
record! {
    /// The pairing reveal a joiner sends: its ephemeral point and nonce.
    pub struct PairingReveal { pub e: Vec<u8>, pub nb: Vec<u8> }
}

cenum! {
    /// Where a Swift succession stands.
    pub enum MoveStage { WindowNotOpen, Waiting, Due, Frozen, Verified, Vetoed, Migrated }
}
record! {
    /// The succession window and the times derived from it.
    pub struct SuccessionTiming {
        pub window_start_ms: i64,
        pub window_end_ms: i64,
        pub recovery_delay_s: u64,
        pub veto_deadline_ms: i64,
        pub due_ms: i64,
        pub quorum: u64,
        pub homes: Vec<String>,
        pub vetoers: Vec<String>,
        pub keys_needed: u64,
    }
}
record! {
    /// The Swift succession an account claims (§15.1).
    pub struct SwiftSuccession {
        pub stage: MoveStage,
        pub format: String,
        pub predecessor: String,
        pub head_seq: u64,
        pub head_digest: String,
        pub genesis_digest: String,
        pub handover_count: u64,
        pub authorized: bool,
        pub vetoed: bool,
        pub verified_seq: Option<u64>,
        pub verified_digest: Option<String>,
        pub timing: Option<SuccessionTiming>,
    }
}
record! {
    /// The `authorityOrigins` of one carried WebAuthn controller (1 to 32 strictly ascending
    /// origins).
    pub struct OriginsFor { pub controller: String, pub origins: Vec<String> }
}
record! {
    /// The agreement point of one carried raw controller whose agreement key the predecessor
    /// does not show.
    pub struct AgreementFor { pub controller: String, pub agreement: Vec<u8> }
}
record! {
    /// What the host chooses for the genesis of the account that succeeds a Swift library
    /// (§15.1, §16.2). The predecessor's controllers are carried with the roles they held.
    pub struct SwiftSuccessorParams {
        pub label: String,
        pub namespaces: Vec<String>,
        pub include_stewards: bool,
        pub authority_origins: Vec<OriginsFor>,
        pub agreements: Vec<AgreementFor>,
        pub threshold: Option<u64>,
        pub recover_threshold: Option<u64>,
        pub add_threshold: Option<u64>,
        pub count_by_holders: bool,
        pub policy_json: String,
        pub signers: Vec<String>,
        pub handover: Vec<String>,
        pub issued_ms: i64,
        pub earlier_attempts: Vec<AuthorityObjects>,
    }
}
record! {
    /// One passkey ceremony that rebuilds one slot (§7.2): ONE WebAuthn assertion over
    /// `challenge` that evaluates `new_salt` first and `old_salt` second. Its first PRF output
    /// answers `prf_requests[request]`; its second opens the Swift slot `old_slot` through
    /// `SwiftSource.finish_open_slot`. `user_verification` is required.
    pub struct SwiftCeremony {
        pub request: u64,
        pub old_slot: u64,
        pub controller: String,
        pub rp: String,
        pub credential: Vec<u8>,
        pub old_salt: Vec<u8>,
        pub new_salt: Vec<u8>,
        pub challenge: Vec<u8>,
        pub user_verification: bool,
    }
}
record! {
    /// What a finished move step produced. `stores` are to be stored in the account's store as
    /// given: F at `predecessor/authority/<seq>.json`, a copier's shares at
    /// `authority/<seq>.json`, the migration at `transitions/<digest>.json`, a veto at
    /// `vetoes/<digest>.json` (`veto_path`). For F, `frozen_entry` is also the exact Swift bytes
    /// the Swift side appends to the predecessor.
    pub struct MoveResult {
        pub stores: Vec<Store>,
        pub veto: Option<Vec<u8>>,
        pub veto_path: Option<String>,
        pub frozen_entry: Option<Vec<u8>>,
        pub frozen_seq: Option<u64>,
        pub succession_verified: bool,
        pub changes: Option<Changes>,
    }
}

record! {
    /// A sealed seed (an HPKE box): public, only the paired device can open it.
    pub struct SealedSeed { pub enc: Vec<u8>, pub ciphertext: Vec<u8> }
}
record! {
    /// A fault of the record source the host must show: it changed bytes it must never change.
    pub struct SourceFault { pub path: String, pub what: String }
}
record! {
    /// The origins a call-ceremony `rp` may use.
    pub struct CallOrigin { pub rp: String, pub origins: Vec<String> }
}
record! {
    /// What the verifier of a call is configured with (§12.3).
    pub struct CallTarget {
        pub audiences: Vec<String>,
        pub call_origins: Vec<CallOrigin>,
        pub controller_purposes: Vec<String>,
        pub home_endpoints: Vec<String>,
    }
}
record! {
    /// One slot of a Swift keyring. `controller` is the one it names, `problem` why it cannot be read.
    pub struct SwiftSlotInfo {
        pub index: u64,
        pub kind: SlotKind,
        pub kind_raw: Option<String>,
        pub label: String,
        pub controller: Option<String>,
        pub problem: Option<String>,
    }
}
record! {
    /// An epoch of a Swift namespace and the seq of the entry that introduced it.
    pub struct SwiftEpoch { pub namespace: String, pub epoch: u64, pub seq: u64 }
}
record! {
    /// A Swift predecessor member as the fold has it at the head.
    pub struct SwiftMemberInfo {
        pub id: String,
        pub label: String,
        pub role: Option<String>,
        pub revoked: bool,
        pub budget: bool,
    }
}
record! {
    /// A Swift operation as the source reader judged it, for the host's translator.
    pub struct SwiftOpInfo {
        pub source_library: String,
        pub author_id: String,
        pub author_label: String,
        pub operation_id: String,
        pub signed_body_digest: String,
        pub kind: String,
        pub version: u64,
        pub payload_json: String,
        pub admitted_order: u64,
    }
}
record! {
    /// An output of a translated record: a destination module operation and its clean payload.
    /// `baseline` is a trusted importer receipt, never inferred from a payload.
    pub struct SwiftChild { pub key: String, pub kind: String, pub payload_json: String, pub baseline: bool }
}
record! {
    /// A source occurrence key reserved as `(category, destination id)`.
    pub struct SwiftIdentity { pub source_key: String, pub category: String, pub destination_id: String }
}
record! {
    /// What the host's translator says about one admitted Swift operation: everything an import
    /// batch can carry. The core adds the batch key and the evidence binding it to its source;
    /// a translator can change the representation, never add a record or drop one silently.
    pub struct SwiftBatch {
        pub children: Vec<SwiftChild>,
        pub alternatives_json: Vec<String>,
        pub identities: Vec<SwiftIdentity>,
        pub blobs_json: Vec<String>,
        pub outcome: String,
        pub evidence_json: String,
    }
}
record! {
    /// A source record the plan omitted, with the reason.
    pub struct SwiftOmission { pub namespace: String, pub source_digest: String, pub reason: String }
}
record! {
    /// How many source records a namespace holds.
    pub struct NamespaceCount { pub namespace: String, pub count: u64 }
}
record! {
    /// An import write of a copy plan, to be signed by the copying member.
    pub struct CopyItem { pub namespace: String, pub source_digest: String, pub key: String, pub payload_json: String }
}
record! {
    /// One namespace of a migration (§15.4).
    pub struct MigratedNamespace { pub namespace: String, pub source: u64, pub copied: Vec<String>, pub omitted: u64 }
}
record! {
    /// A source record not copied.
    pub struct Omitted { pub source_digest: String, pub reason: String }
}
record! {
    /// What a finished copy holds.
    pub struct CopyOutcome {
        pub namespaces: Vec<MigratedNamespace>,
        pub omitted: Vec<Omitted>,
        pub blobs_not_copied: Vec<String>,
    }
}
record! {
    /// A predecessor member's fate in a migration: `dropped` empty means it rejoins.
    pub struct MigratedMemberInput {
        pub id: String,
        pub label: String,
        pub kind: AccountMemberKind,
        pub dropped: Option<String>,
    }
}

// --- The 0.6 home stream (`stream.rs`) ---------------------------------------------------------

record! {
    /// The host's choices for one stream; `stream_default_config` gives the documented values.
    pub struct StreamConfig {
        pub backoff_base_ms: i64,
        pub backoff_cap_ms: i64,
        pub coalesce_ms: i64,
        pub seed: u64,
        pub ping_ms: i64,
        pub idle_ms: i64,
        pub stable_ms: i64,
        pub mint_budget: u32,
        pub mint_window_ms: i64,
        pub safety_poll_ms: i64,
        pub suspend_after: u32,
        pub suspend_ms: i64,
        pub max_mints_per_day: u32,
        pub retry_allowance: u32,
    }
}
cenum! {
    /// What the host does next for a stream.
    pub enum StreamStepKind { Wake, NeedTicketCall, Connect, Send, Close, Waiting, Sleep }
}
record! {
    /// The next thing to do. `url` (Connect) carries the ticket, a bearer credential: open the
    /// socket with it and log `log_url` (the ticket redacted) instead. `text` is set for Send,
    /// `code` for Close, `until` for Sleep (absent: nothing is scheduled). `wake_at`, on every
    /// step, is when to call `next` again at the latest even if nothing happens (absent: only an
    /// answer, a frame, a close or a new history moves the stream). A `NeedTicketCall` is handed
    /// out once: until the host answers it, `next` returns `Waiting`, and an answer that never
    /// comes counts as a failed call after `SIGN_TIMEOUT_MS`.
    pub struct StreamStep {
        pub kind: StreamStepKind,
        pub url: Option<String>,
        pub log_url: Option<String>,
        pub text: Option<String>,
        pub code: Option<u32>,
        pub until: Option<i64>,
        pub wake_at: Option<i64>,
    }
}
cenum! {
    /// Why a stream will not be tried again until the history changes.
    pub enum StreamBlockedKind { AccessEnded, Released, Refused, Unsupported }
}
cenum! {
    /// Where a stream stands.
    pub enum StreamStatusKind { Backoff, Connecting, Live, Closing, Blocked, Throttled, Suspended }
}
record! {
    /// Where a stream stands. `until` is set for Backoff, Throttled and Suspended; `blocked`
    /// for Blocked, with `refused` the home's result of a refused ticket mint.
    pub struct StreamStatus {
        pub kind: StreamStatusKind,
        pub until: Option<i64>,
        pub blocked: Option<StreamBlockedKind>,
        pub refused: Option<String>,
    }
}
cenum! {
    /// What a frame or a transport event told the host.
    pub enum StreamEventKind {
        Connected, Cursor, Notice, Route, Session, Ack, Error, Resync, Bye, Violation, Down, Blocked
    }
}
record! {
    /// One stream event. Connected: `principal`, `expires_at`. Cursor: `cursor` (absent: forget
    /// the saved one). Notice, Route, Ack: the frame as JSON in `json`. Session: the server's
    /// message byte for byte in `text`, for the session layer. Error: `code` and `reference`.
    /// Resync, Bye, Violation: `reason`. Down: `retry_at`. Blocked: `blocked` and `refused`.
    pub struct StreamEvent {
        pub kind: StreamEventKind,
        pub principal: Option<String>,
        pub expires_at: Option<i64>,
        pub cursor: Option<String>,
        pub json: Option<String>,
        pub text: Option<String>,
        pub code: Option<String>,
        pub reference: Option<String>,
        pub reason: Option<String>,
        pub retry_at: Option<i64>,
        pub blocked: Option<StreamBlockedKind>,
        pub refused: Option<String>,
    }
}

// --- 0.6 sessions (`sessions.rs`) --------------------------------------------------------------

record! {
    /// The host's clocks at a call: monotonic ms (every session timer) and wall-clock ms since
    /// the Unix epoch (delegation windows, member expiry).
    pub struct SessionClock { pub mono_ms: u64, pub wall_ms: i64 }
}
cenum! {
    /// One effect for the host, in order.
    pub enum SessionEffectKind { Send, Persist, Event, Unsent }
}
record! {
    /// One effect. Send: broadcast `bytes` (the sealed frame) to every member of the cell;
    /// `to` is advice and `frame_kind` names the plaintext kind for logs. Persist: store
    /// `persisted_json` before carrying out any later effect, and pass it back when the
    /// endpoint is made again. Event: tell the application `event_json` (tagged by `event`, the
    /// same JSON the conformance vectors use). Unsent: a frame of `frame_kind` could not be
    /// sealed, for the reason `unsent`; to the protocol that is loss.
    pub struct SessionEffect {
        pub kind: SessionEffectKind,
        pub bytes: Vec<u8>,
        pub to: Option<String>,
        pub frame_kind: Option<String>,
        pub persisted_json: Option<String>,
        pub event: Option<String>,
        pub event_json: Option<String>,
        pub unsent: Option<String>,
    }
}
record! {
    /// A received frame that was dropped: the §S3 reason code (as in the wire vectors) and the
    /// member §S3 asks this one to send `hello` to, if any. Silent on the wire.
    pub struct SessionDrop { pub reason: String, pub hello_to: Option<String> }
}
record! {
    /// What one endpoint call produced: `effects` in order (perform them in order); `drops` the
    /// frames this call judged and dropped, in order, with their reasons (`queueFull` for a frame
    /// that could not be kept). `awaiting_persist` is set only on the step whose last effect is a
    /// `Persist`: it is that `Persist`'s acknowledgement ID, to pass to `persisted` once the
    /// host's durable write of that effect has completed, and no other step ever carries it.
    /// `persist_outstanding` says a `Persist` is still unacknowledged after this call (this one's
    /// or an earlier one's); `queued` says this call's input is kept to run after it. `discarded`
    /// counts effects decided under an older authority head that were dropped, not released.
    /// `next_deadline` is when to call `tick` next after this call (absent while a `Persist` is
    /// outstanding: the step that acknowledges it carries the real one).
    pub struct SessionStep {
        pub effects: Vec<SessionEffect>,
        pub drops: Vec<SessionDrop>,
        pub awaiting_persist: Option<u64>,
        pub persist_outstanding: bool,
        pub queued: bool,
        pub discarded: u32,
        pub next_deadline: Option<u64>,
    }
}
record! {
    /// One §S7 clock sample: round trip, offset (`peer ≈ mine + offset`) and error, ms.
    pub struct SessionClockSample { pub rtt: u64, pub offset: i64, pub error: u64 }
}

// --- Argument limits ---------------------------------------------------------------------------

/// Most items in any list argument.
pub const MAX_LIST: usize = 262_144;
/// Most items in a list of names (signers, namespaces, controllers).
pub const MAX_NAMES: usize = 256;
/// Largest binary argument: 40 MiB.
pub const MAX_BYTES: usize = 40 << 20;
/// Largest domain JSON document: 1 MiB (a record payload, an import batch, a translated batch).
/// Chosen from the core's own bounds: a record payload is at most 1 MiB canonical
/// (`domains/saved` validation, `Engine::begin_import`) and an import batch is at most
/// `MAX_BATCH_BYTES` = 1 MiB, so no legitimate value needs more. It was 4 MiB, which let one
/// item peak at 192 MiB. Checked on the raw length before anything is parsed.
pub const MAX_JSON: usize = 1 << 20;

pub(crate) type R<T> = Result<T, AccountError>;

pub(crate) fn names(v: Vec<String>, what: &str) -> R<Vec<String>> {
    if v.len() > MAX_NAMES {
        return Err(AccountError::bound(&format!("{what} names too many")));
    }
    Ok(v)
}
pub(crate) fn list_len<T>(v: &[T], what: &str) -> R<()> {
    if v.len() > MAX_LIST {
        return Err(AccountError::bound(&format!("{what} is too long")));
    }
    Ok(())
}
pub(crate) fn bytes_ok(b: &[u8], max: usize, what: &str) -> R<()> {
    if b.len() > max {
        Err(AccountError::bound(&format!("{what} is too large")))
    } else {
        Ok(())
    }
}
pub(crate) fn fixed<const N: usize>(b: &[u8], what: &str) -> R<[u8; N]> {
    b.try_into()
        .map_err(|_| AccountError::bound(&format!("{what} must be exactly {N} bytes")))
}
/// Largest authority-protocol JSON document (policy, terms, a `change`, a slot): 1 MiB, the
/// authority body bound of §2.4 (`bounds::AUTHORITY_BODY`). Nothing that goes into one authority
/// entry can be larger, so no legitimate value of this kind needs more.
pub const MAX_AUTH_JSON: usize = 1 << 20;
/// Most items in a list of JSON documents (slots, alternatives, blob manifests) and in a
/// translated batch's children.
pub const MAX_JSON_ITEMS: usize = 4096;

/// The most a parse may cost, by the count of `within_budget`: 32 MiB. Chosen from the largest legitimate
/// values: a 1 MiB payload of any shape costs at most about 17 MiB (524,288 one-byte-plus-comma
/// numbers at 32 bytes each, or 175,000 short-key entries at about 100 bytes each); an import
/// batch is at most 1 MiB (`MAX_BATCH_BYTES`) and an authority body at most 1 MiB, so the same.
/// The budget leaves twofold room over those and refuses only a document that costs more than
/// any legitimate one can, **when the parse reaches that point and never before**: a compact
/// document of small numbers is as welcome as the same one with spaces.
pub const PARSE_BUDGET: usize = 32 << 20;

/// The cost of parsing `text`, counted as the text is scanned and abandoned the moment it passes
/// the budget: 32 bytes per value (a `serde_json::Value`), a string's bytes, 64 bytes per object
/// entry (the map node and key). A value is a comma, an opener's container and its first element,
/// so the count over-estimates a little and never under-estimates. It is a count over the raw
/// text, not a shape rule: a compact array of small numbers and the same with spaces cost alike.
fn within_budget(text: &str) -> bool {
    let (mut cost, mut in_str, mut esc) = (32usize, false, false);
    for &b in text.as_bytes() {
        if in_str {
            cost += 1;
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else {
            match b {
                b'"' => in_str = true,
                b',' => cost += 32,
                b'{' | b'[' => cost += 64,
                b':' => cost += 64,
                _ => {}
            }
        }
        if cost > PARSE_BUDGET {
            return false;
        }
    }
    true
}

/// Parse a JSON document: its raw length is checked first, then its cost under the budget,
/// which refuses (`Bound`) only a document that costs more than any legitimate one can.
pub(crate) fn json_doc(text: &str, cap: usize, what: &str) -> R<serde_json::Value> {
    if text.len() > cap {
        return Err(AccountError::bound(&format!(
            "{what} is over {} KiB",
            cap >> 10
        )));
    }
    if !within_budget(text) {
        return Err(AccountError::bound(&format!(
            "{what} costs more to parse than any legitimate document: over {} MiB",
            PARSE_BUDGET >> 20
        )));
    }
    serde_json::from_str(text).map_err(|_| AccountError::bad(format!("{what} is not JSON")))
}
/// A value the core itself produced and the host passes back (a `CopyItem`'s payload): no
/// host-argument bound applies, only a length ceiling against a corrupted call.
pub(crate) fn core_json(text: &str, what: &str) -> R<serde_json::Value> {
    if text.len() > (16 << 20) {
        return Err(AccountError::bound(&format!("{what} is over 16 MiB")));
    }
    serde_json::from_str(text).map_err(|_| AccountError::bad(format!("{what} is not JSON")))
}
/// A domain document (a record payload, an import batch, a translated child): at most 1 MiB.
pub(crate) fn json(text: &str, what: &str) -> R<serde_json::Value> {
    json_doc(text, MAX_JSON, what)
}
/// An authority-protocol document (policy, terms, a `change`, a slot): at most 1 MiB.
pub(crate) fn auth_json(text: &str, what: &str) -> R<serde_json::Value> {
    json_doc(text, MAX_AUTH_JSON, what)
}
/// A list of JSON documents, bounded in total before any item is parsed: at most `max_items`
/// items whose raw lengths sum to at most `cap` (each item is then at most `cap` too).
pub(crate) fn json_list(
    items: &[String],
    cap: usize,
    max_items: usize,
    what: &str,
) -> R<Vec<serde_json::Value>> {
    if items.len() > max_items {
        return Err(AccountError::bound(&format!("{what}: too many items")));
    }
    let total = items
        .iter()
        .try_fold(0usize, |t, i| t.checked_add(i.len()))
        .ok_or_else(|| AccountError::bound(&format!("{what} is too large")))?;
    if total > cap {
        return Err(AccountError::bound(&format!(
            "{what}: the items together are over {} KiB",
            cap >> 10
        )));
    }
    items.iter().map(|i| json_doc(i, cap, what)).collect()
}
pub(crate) fn json_or_null(text: &str, what: &str) -> R<serde_json::Value> {
    if text.is_empty() {
        Ok(serde_json::Value::Null)
    } else {
        json(text, what)
    }
}
pub(crate) fn to_json(v: &serde_json::Value) -> R<String> {
    serde_json::to_string(v).map_err(|_| AccountError::internal("a result could not be written"))
}
/// Overwrite a secret the host passed.
pub(crate) fn wipe(v: &mut [u8]) {
    v.fill(0);
    std::hint::black_box(&*v);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn small_values_are_accepted_whatever_their_shape() {
        // 600 small numbers, compact (1.2 KB): the checker's case, refused by the density rule.
        let nums: Vec<String> = (0..600).map(|i| (i % 10).to_string()).collect();
        let doc = format!("[{}]", nums.join(","));
        assert!(doc.len() < 1300);
        assert!(json(&doc, "x").is_ok());
        // 100,000 small numbers.
        let doc = format!("[{}0]", "1,".repeat(99_999));
        assert!(json(&doc, "x").is_ok());
        // One long string of the whole 1 MiB.
        let doc = format!("\"{}\"", "a".repeat(MAX_JSON - 2));
        assert!(json(&doc, "x").is_ok());
        // An import batch at the core's own maximum (1 MiB): records of 7 bytes and more.
        let rec = "{\"id\":\"a1\",\"t\":\"x\"},";
        let mut batch = String::from("{\"children\":[");
        while batch.len() + rec.len() + 8 < MAX_JSON {
            batch.push_str(rec);
        }
        batch.push_str("{}]}");
        assert!(batch.len() <= MAX_JSON);
        assert!(json(&batch, "x").is_ok());
        // A document one byte over the length cap is `Bound`; garbage is `Malformed`.
        assert!(matches!(
            json(&"a".repeat(MAX_JSON + 1), "x"),
            Err(AccountError::Bound { .. })
        ));
        assert!(matches!(
            json("{", "x"),
            Err(AccountError::Malformed { .. })
        ));
        assert!(matches!(
            json("[1] 2", "x"),
            Err(AccountError::Malformed { .. })
        ));
    }
    #[test]
    fn a_parse_is_refused_only_once_the_budget_is_passed() {
        // Under the 1 MiB length cap no document can cost 32 MiB (a 1 MiB array of one-digit
        // numbers costs 16 MiB), so the budget is a backstop. With a larger cap it bites, and
        // only when the running cost passes it: 8 MiB of `0,` is 4 million values.
        let big = format!("[{}0]", "0,".repeat(4 << 20));
        assert!(matches!(
            json_doc(&big, 16 << 20, "x"),
            Err(AccountError::Bound { .. })
        ));
        // The same shape at 2 MiB (1 million values, 32 MiB) is within a hair; at 1 MiB it is
        // well inside.
        let fits = format!("[{}0]", "0,".repeat(MAX_JSON / 2 - 1));
        assert!(json_doc(&fits, 2 << 20, "x").is_ok());
    }
}
