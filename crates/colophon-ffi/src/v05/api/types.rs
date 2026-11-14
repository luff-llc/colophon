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
    /// The signature form a signer uses.
    pub enum SignForm { Raw, Webauthn }
}
cenum! {
    /// A member's kind.
    pub enum AccountMemberKind { Device, App, Agent, Server }
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
    /// A listed path with the provider's content-version token (empty for none).
    pub struct ListedPath { pub path: String, pub version: String }
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
        pub kind: String,
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
        pub stop_seq: Option<u64>,
        pub detail: Option<String>,
        pub rollback: bool,
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
        pub roles: Vec<String>,
        pub form: SignForm,
        pub verification: bool,
        pub holder: Option<String>,
        pub has_slot: bool,
        pub provisional: bool,
        pub suspended: bool,
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
        pub grant: Option<AccountGrant>,
        pub since: u64,
        pub revoked_at: Option<u64>,
        pub writes: u64,
        pub expires_ms: Option<i64>,
        pub provisional: bool,
        pub home: bool,
        pub session: u64,
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
        pub status: String,
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
    pub struct AccountDenial { pub reason: String, pub detail: String }
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
    /// A request that needs a fresh `Authorization: Colophon` call built for exactly it.
    pub struct CallNeed {
        pub ticket: u64,
        pub home: String,
        pub audience: String,
        pub purpose: String,
        pub method: HttpMethod,
        pub url: String,
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
    /// What to create. `controllers_json` holds one protocol controller object (§6.1) per item;
    /// `policy_json` the §6.3 policy document (empty: the §18 person default).
    pub struct CreateParams {
        pub label: String,
        pub namespaces: Vec<String>,
        pub controllers_json: Vec<String>,
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
        pub custody: String,
        pub operator: String,
        pub endpoints: Vec<String>,
    }
}
record! {
    /// A verified request as an approver sees it.
    pub struct RequestInfo {
        pub raw: Vec<u8>,
        pub member: String,
        pub label: String,
        pub kind: AccountMemberKind,
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
        pub count_by: String,
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
    /// What a finished step of a move produced: bytes to store, and for F the exact Swift
    /// entry (`frozen_entry`) the host appends to the predecessor.
    pub struct MoveResult {
        pub stores: Vec<Store>,
        pub veto: Option<Vec<u8>>,
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
        pub kind: String,
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

// --- Argument limits ---------------------------------------------------------------------------

/// Most items in any list argument.
pub const MAX_LIST: usize = 262_144;
/// Most items in a list of names (signers, namespaces, controllers).
pub const MAX_NAMES: usize = 256;
/// Largest binary argument: 40 MiB.
pub const MAX_BYTES: usize = 40 << 20;
/// Largest JSON text argument: 4 MiB (a document the host edits: policy, terms, controller,
/// a record payload). Checked on the raw length before it is parsed.
pub const MAX_JSON: usize = 4 << 20;

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
/// Parse a JSON argument after its raw length is checked against the cap.
pub(crate) fn json(text: &str, what: &str) -> R<serde_json::Value> {
    if text.len() > MAX_JSON {
        return Err(AccountError::bound(&format!("{what} is over 4 MiB")));
    }
    serde_json::from_str(text).map_err(|_| AccountError::bad(format!("{what} is not JSON")))
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
