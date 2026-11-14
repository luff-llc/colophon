//! The 0.5 account: the counterpart of the 0.4 `Library`. One in-memory object an app session
//! holds. It opens an account from its objects, unlocks it, performs every action as *prepare,
//! then finish*, merges incoming objects, and answers views and queries.
//!
//! It is sans-IO: no storage, no network, no clock, no RNG. Seeds, nonces and the time are
//! arguments. The storage engine, record sources, on-disk checkpoints, blobs and home exchange
//! are [`crate::v05::engine`] (E6), built on this account.
//!
//! **Incremental judgement (E6).** A merge of records that sort after everything held resumes
//! the walk of [`judge_records`](crate::v05::records::judge_records) from its last state; a merge
//! of earlier ones walks again without repeating a signature check or a decryption
//! ([`records::JudgeCache`](crate::v05::records::JudgeCache)); a namespace fold is extended, not
//! redone, when the operations it folded are the first of those it folds now. Each answer is
//! the one a full judgement gives (`tests/v05_account_engine.rs`). Authority changes, new keys
//! and a changed standing of any member rebuild from the memo, as before.
//!
//! # What the core guarantees, exactly, and what the host is trusted with
//!
//! The core never returns seed bytes or a raw ECDH output through its API. An opened seed can
//! be sealed only to controllers of its own account's verified keyring (it records the account
//! it was opened under, and a state of another account is refused), to a new vault the host
//! itself creates at rotation, or to a device the person confirmed by pairing. The host is
//! trusted with the seed during rotation and transfer: it supplies the new seed's entropy and
//! so can read what is sealed to it, and it performs the QR scan, so a payload it builds is a
//! pairing it confirmed. The core does not, and cannot, stop a host that performs the ECDH and
//! PRF work from computing a seed it was never meant to hold; it bounds what the *core's own
//! functions* will seal.
//!
//! In this module that means: the account holds the vault seeds and the epoch keys as the
//! opaque types of [`vault`](crate::v05::vault) and [`records`](crate::v05::records) (private
//! fields, no accessor, no `Serialize`, redacted `Debug`, erased on drop). Nothing in this
//! module returns either, and [`Account`]'s `Debug` prints counts only. A seed is installed
//! only when it is new or was opened under this account. A new epoch is sealed only to the
//! recipients the verified state names (§7.1). **Holding an `Account` is as trusted as holding
//! the keys it has opened:** a grant's `shares` are sealed before the controller signs, so a
//! host that drives the account can have them sealed to a member it is preparing to admit and
//! that member can read the raw key. The host is likewise trusted with the seeds it supplies
//! for new epochs, new vaults and slots (it can recompute what they make), and with the ECDH
//! results and PRF outputs it passes in. Hosts MUST pass a fresh seed per action.
//!
//! **Erasure is best effort.** The crate forbids `unsafe` and has no zeroizing dependency. The
//! seeds, ECDH and PRF outputs and epoch keys this module holds are the opaque types of
//! `v05::vault` and `v05::records`, which overwrite their bytes on drop with ordinary writes
//! that `std::hint::black_box` only discourages the optimizer from removing. The entropy seeds
//! a host passes to `begin_*` are plain arrays: a prepared action keeps the ones it still
//! needs until it is finished or dropped, and does not overwrite them.
//!
//! No accessor reaches the seed, the epoch keys or what a prepared action will sign:
//!
//! ```compile_fail
//! fn read(a: &colophon_core::v05::account::Account) {
//!     let _ = &a.seeds; // private: there is no accessor of any visibility for the seed
//! }
//! ```
//!
//! ```compile_fail
//! fn read(a: &colophon_core::v05::account::Account) {
//!     let _ = &a.d.keys; // private: the epoch keys never leave the account
//! }
//! ```
//!
//! ```compile_fail
//! fn read(a: &mut colophon_core::v05::account::PendingAction) {
//!     a.steps()[0].body_mut(); // a step's body cannot be changed between prepare and finish
//! }
//! ```
//!
//! # Prepare, then finish
//!
//! Every action is `Account::begin_*`, which returns a [`PendingAction`], and
//! [`Account::finish`], which takes the host's signatures. A [`PendingAction`] has private
//! fields and read-only accessors: what the host signs ([`PendingAction::steps`]), the PRF
//! assertions it must make first ([`PendingAction::prf_requests`]), and nothing it can change
//! between the two calls. `finish` hands the signatures to the write side, which assembles the
//! exact bytes and verifies them under the history verifier **before** returning them. The
//! account then re-verifies the result over its *current* objects (they may have changed
//! since `begin`), and only when that verdict accepts the new object does the account change.
//! A failure at any step leaves the account exactly as it was.
//!
//! # State is a function of the object set
//!
//! The account holds every object it is given (up to fixed bounds) and derives its state from
//! them, so the verdict, the namespace folds and everything read through [`Account::view`] do
//! not depend on the order objects arrive in, nor on which valid objects a verifier holds
//! beyond the set. A merge that makes the history refuse is reported, and the account keeps
//! reading the verified prefix; writes are refused until the history is clean again.
//! **Stored state is a cache authenticated by a device-held key; without it the account
//! replays** (see [`Account::open`] and `stored.rs`): the exported bytes are protected as 0.4
//! protects its checkpoints, and are never trusted on their bare bytes. What does
//! depend on arrival order is local memory only (the head high-water marks of §13.3, and the
//! seq at which a pending transition was first held, §17.5), never a verdict.
//!
//! # The 0.4 calls and their 0.5 answers
//!
//! | 0.4 (`Library`, `NativeLibrary`, `NativeEngine`) | 0.5 |
//! | --- | --- |
//! | `begin_create`, `begin_create_with`, `advance_create` | [`Creation::begin`], [`Creation::provide_prf`], [`Creation::provide_signatures`]: genesis, the first `rekey` and the first slots, in as many rounds as the ceremonies need |
//! | `open`, `open_with_checkpoints` | [`Account::open`] (objects, records, optional stored state and its key, identity, clock) |
//! | `id`, `identity`, `me` | [`Account::id`], [`Account::identity`], [`Account::me`] |
//! | `records`, `authority` | [`Account::objects`], [`Account::records`] (held public objects), [`Account::controllers`], [`Account::policy`] |
//! | `set_read_scope` | [`Account::set_read_scope`] |
//! | `merge`, `merge_with_changes`, `changes`, `finish_with_changes` | [`Account::merge`] returns [`Changes`]; [`Account::finish`] returns it too |
//! | `revision`, `applied_operations` | [`Account::revision`] |
//! | `checkpoint`, `restore_checkpoint`, `set_checkpoint_policy` | [`engine::Engine::save`](crate::v05::engine::Engine::save) for the on-disk namespace checkpoint (E6). The verifier's persisted state (§17.2), authenticated under a device-held key as 0.4 protects its checkpoints: [`Account::export_persisted`] and the stored bytes and key given to [`Account::open`] |
//! | `query`, `view` | [`Account::query`], [`Account::view`] |
//! | `finish`, `finish_authority` | [`Account::finish`] (one call; WebAuthn assertions travel in [`SignatureResult`]) |
//! | `begin_unlock_slot`, `finish_unlock_slot`, `begin_unlock_slots` | [`Account::slots`], [`Account::begin_unlock_slot`], [`Account::finish_unlock_slot`] |
//! | `begin_unlock`, `finish_unlock`, `finish_unlock_many` | the vault: [`Account::finish_unlock_slot`] opens every epoch the seed reaches; a member: [`Account::begin_unlock_epochs`], [`Account::finish_unlock_epochs`] |
//! | `build_sealed_slot`, `begin_prf_slot`, `finish_prf_slot`, `begin_combined_slot`, `finish_combined_slot`, `finish_prf_part`, `finish_prf_slot_for` | [`Account::begin_add_slot`] (self-slot, §8.4) and the slots built inside [`Creation`], [`Account::begin_add_controller`], [`Account::begin_rotate_vault`] and removals, all through [`PendingAction::prf_requests`] and [`Account::provide_prf`] |
//! | `begin_request`, `finish_request` | [`prepare_request`], [`finish_request`] (no account needed: the member's side) |
//! | `begin_approve` | [`Account::begin_approve`] (a `grant` with shares) |
//! | `begin_revoke` | [`Account::begin_revoke`] (with `kept` and `heads`; reports the `rekey` owed while the vault retires) |
//! | `begin_rekey` | [`Account::begin_rekey`] |
//! | `begin_keyring`, `begin_thresholds` | [`Account::begin_keyring`] (immediate additive entries), [`Account::begin_transition`] with [`Change`] (thresholds, policy, homes, vault) |
//! | `begin_add_controller`, `begin_recovery_add`, `begin_add_passkey` | [`Account::begin_add_controller`] (immediate `approve`/`sign`, or a transition for `control`/`recover`), with [`Account::transfer_seed`] and [`Account::accept_seed_transfer`] for §7.4 |
//! | `begin_remove_controller` | [`Account::begin_remove_controller`] (`plan_rotation`, the `vault` component) and [`Account::begin_rotate_vault`] (the `vault` entry) |
//! | `select_controller`, `eligible_signers`, `prepare_authority` | gone in 0.5: the caller names the signers (controller IDs) and the write side checks the rule of §8.4 and refuses a set that does not meet it. [`Account::suggest_signers`] picks a set that meets a rule from the keys a host can sign with |
//! | `begin_import_grant`, `begin_import`, `import_*`, `reconcile_import_prefix` | `import` is a `terms` field in 0.5 (§9.3, §10.1): [`Account::begin_approve`] carries it; import batches: [`engine::Engine::begin_import`](crate::v05::engine::Engine::begin_import) |
//! | `begin_write`, `written_operation*`, `live_generation` | [`Account::begin_write`] (a `/5` operation); live stamps and live generations are the engine's: [`engine::Engine::begin_live_write`](crate::v05::engine::Engine::begin_live_write), judged by [`live`](crate::v05::live) |
//! | `begin_layout` | gone in 0.5: a `/5` account is at layout 2 from genesis (§11.8) |
//! | `members`, `me` | [`Account::members`], [`Account::me`], [`Account::controllers`] |
//! | `tools`, `begin_call` | [`Account::tools`]; calls: [`Account::begin_link`], [`Account::begin_call`] (§12) |
//! | `ledger` | [`Account::ledger`] |
//! | `begin_blob`, `open_blob_chunk`, `read_blob_chunk`, `NativeBlobWriter` | [`engine::Engine::begin_blob`](crate::v05::engine::Engine::begin_blob), [`read_blob`](crate::v05::engine::Engine::read_blob) (E6) |
//! | `NativeEngine::*`, `RecordSource`, `verify_batch`, `records_at`, `update_versions` | [`engine::Engine`](crate::v05::engine::Engine) (E6) |
//! | `NativeCheckpoint*` | [`engine::Engine::save`](crate::v05::engine::Engine::save) seals under the host's device-held key; there is no member-signed ticket (see `engine::seal`) |
//! | `vault_public`, `webauthn_prf_input`, `parse_registration` | already in `v05::vault`, `v05::slots` and `keys` |
//! | `KeyProvider::sign_with`, `sign_controller_with`, `HostAction::sign_with` | gone in 0.5: the core never calls into a key provider (§3.4, §17.1). The host reads [`PendingAction::steps`] (each step's exact body, signer and WebAuthn challenge) and passes the signatures to [`Account::finish`] |
//! | `PendingBatch::record_paths`, `HostAction::record_paths` | [`Finished::record_paths`] (the paths of what a finish produced: `authority/<seq>.json`, `transitions/<digest>.json`, `vetoes/<digest>.json`, `ops/…`); before finish, [`SigningStep::path`] |
//! | `migration.rs`: `import_legacy_batch`, `bind_legacy_import_state` | the upgrade tooling step (plan step 8), not the account: legacy import batches are `import` records written through [`Account::begin_write`] once the account is upgraded |
//! | the 0.4 → 0.5 in-place `upgrade` entry (§16.1) and the Swift keyring upgrade (§16.2) | `moving.rs` (package E8): [`Account::begin_upgrade`] (an associated function: a plain 0.4 history is not an account yet) and the Swift succession steps [`Account::swift_succession`], [`Account::begin_swift_veto`], [`Account::begin_swift_freeze`] and [`Account::finish_move`], [`Account::accept_predecessor_entry`], [`Account::begin_swift_copy_write`] and [`Account::finish_swift_copy_write`], [`Account::begin_swift_migration`] |
//! | §15 succession (`successor` transition, `handover`, the freezing `layout`, `migration` entry) and §16.2 Swift succession | the Swift form is `moving.rs` (above); the `/5` form (`begin_successor`, `begin_succession_*`) is still not built here. The account reads a succession's `successor` and `migration` through the verifier's state |
//! | §15 exit and the clean copy (§15.3, the drain window) | the copying itself is the engine's and a home's ([`engine::exchange`](crate::v05::engine::exchange), §13–§14); the account's part is the `successor` and `migration` entries above |
//! | (new) pending transitions | [`Account::pending`], [`Account::begin_transition`], [`Account::begin_veto`], [`Account::begin_suspend`], [`Account::record_due`] (the determined `activate`, `vetoed` and `final`), [`Account::begin_resolve`] and [`Account::fork_candidates`] |
//! | (new) notices (§17.5) | [`Account::pending`], [`Account::notices`] |
//! | (new) shares owed | [`Account::owed_shares`], [`Account::begin_renew`] |
//! | (new) proposals (§11.6) | [`Account::proposals`], [`Account::begin_propose`], [`Account::begin_resolution`] |
mod action;
mod create;
mod derived;
pub(crate) use derived::wipe_value;
mod moving;
mod read;
mod stored;
mod unlock;

pub use action::{
    ActionInfo, AddController, AddMode, CallTarget, Change, Finished, KeyringEdit, PendingAction,
    RevokeKeep, SignerChoice,
};
pub use create::{default_policy, CreateParams, CreateProgress, Creation};
pub use moving::{CopyWrite, MoveStage, Moved, PendingMove, SwiftSuccession};
pub use read::Standing;
pub use read::{
    ControllerInfo, HomeInfo, LedgerLine, MemberInfo, Notices, OwedInfo, PendingTransition, Policy,
    ProposalInfo, SeenActivation,
};
pub use unlock::{EpochAgreement, EpochSecret, SlotOption};

use crate::v05::calls::AccountView;
use crate::v05::history::{Objects, Persisted, Stop, Verdict};
use crate::v05::ids::{is_key_id, AccountId};
use crate::v05::records::HeldRecord;
use crate::v05::write::{SignatureResult, SigningStep};
use crate::v05::{require, Result};
use derived::{Derived, Inputs};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use unlock::SeedRing;

/// Most authority entries, pending objects, heads and records an account holds. Bounds are
/// checked before anything is allocated for an incoming set.
pub const MAX_OBJECTS: usize = 262_144;
/// Most bytes of all held objects together.
pub const MAX_TOTAL_BYTES: usize = 1 << 30;
/// Largest single held record envelope.
pub const MAX_RECORD_BYTES: usize = 16_777_216 + 4_096;
/// Largest single authority entry or pending object envelope.
pub const MAX_OBJECT_BYTES: usize = 2_097_152 + 4_096;

pub use crate::v05::history::Objects as AccountObjects;

/// Who this session is: public values only. A controller reads through the vault; a member
/// reads through the shares of its terms. An ID the account does not (yet) know is a
/// prospective identity, as 0.4 allowed ([`Account::me`] says so).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Identity {
    /// A controller's ID (the key ID of its signing point).
    Controller(String),
    /// A member's ID.
    Member(String),
}
impl Identity {
    /// The 32-hex key ID.
    pub fn id(&self) -> &str {
        match self {
            Self::Controller(i) | Self::Member(i) => i,
        }
    }
}

/// Objects an account is given: authority entries, pending transitions, vetoes and receipts,
/// heads, the predecessor of a successor, and held records.
#[derive(Clone, Debug, Default)]
pub struct Incoming {
    /// Authority-side objects.
    pub objects: Objects,
    /// Operation headers.
    pub records: Vec<HeldRecord>,
}

/// Where the verifier stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// The highest verified authority seq.
    pub seq: u64,
    /// The §1 result of the verification: `ok`, `held`, `refused:fork`, or a failure's code.
    pub code: String,
    /// The seq the code refers to, when the verification stopped.
    pub stop_seq: Option<u64>,
    /// A stop's diagnostic.
    pub detail: Option<String>,
    /// The persisted high-water mark is not on the verified branch (§13.3).
    pub rollback: bool,
}
impl Status {
    /// True when nothing stops writing.
    pub fn is_clean(&self) -> bool {
        self.code == "ok" && !self.rollback
    }
    fn of(v: &Verdict) -> Self {
        let (stop_seq, detail) = match &v.stop {
            None => (None, None),
            Some(Stop::Failed { seq, failure }) => (Some(*seq), Some(failure.detail().to_string())),
            Some(Stop::Held { seq, why }) => (Some(*seq), Some(why.clone())),
            Some(Stop::Fork { seq }) => (Some(*seq), None),
        };
        Self {
            seq: v.branch.len() as u64,
            code: v.code(),
            stop_seq,
            detail,
            rollback: v.rollback,
        }
    }
}

/// The work of the latest derivation, and the sum since the account opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// The latest judgement of the held records.
    pub last: crate::v05::records::JudgeStats,
    /// All judgements since the account was opened.
    pub total: crate::v05::records::JudgeStats,
    /// Operations applied to namespace folds by the latest build (the rest were reused).
    pub fold_applied: u64,
}

/// One namespace's fold, as a sealed checkpoint carries it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldSnapshot {
    /// The namespace.
    pub namespace: String,
    /// The hash of the verified standing it was made under, hex.
    pub print: String,
    /// The domain state.
    pub state: serde_json::Value,
    /// The digests folded, in fold order.
    pub order: Vec<String>,
    /// The highest clock folded.
    pub clock: u64,
    /// Operations applied.
    pub applied: u64,
    /// The admitted operations.
    pub admitted: Vec<crate::model::OperationView>,
}

/// What a merge, an unlock or a finished action changed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    /// Authority entries and what they changed.
    pub authority: AuthorityChanges,
    /// Namespace name to its new local revision, for each namespace whose fold changed.
    pub namespaces: BTreeMap<String, u64>,
    /// Pending transitions.
    pub pending: PendingChanges,
    /// Heads accepted or refused (§13.3).
    pub heads: HeadChanges,
    /// Objects ignored because they belong to another account: a genesis that is not this
    /// account's (an account is identified by its genesis, §5.1).
    pub foreign: usize,
    /// The verifier's standing after the change.
    pub status: Option<Status>,
}
impl Changes {
    /// True when nothing changed.
    pub fn is_empty(&self) -> bool {
        self.authority == AuthorityChanges::default()
            && self.namespaces.is_empty()
            && self.pending.added.is_empty()
            && self.pending.gone.is_empty()
            && self.heads == HeadChanges::default()
            && self.foreign == 0
    }
}
/// What changed in the authority history.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityChanges {
    /// Verified seq before and after.
    pub seq: (u64, u64),
    /// New verified entries: `(seq, kind)`.
    pub entries: Vec<(u64, String)>,
    /// Members admitted.
    pub members_added: Vec<String>,
    /// Members revoked.
    pub members_revoked: Vec<String>,
    /// Controllers added.
    pub controllers_added: Vec<String>,
    /// Controllers removed.
    pub controllers_removed: Vec<String>,
    /// The vault changed.
    pub vault_changed: bool,
    /// The policy changed.
    pub policy_changed: bool,
    /// The history was displaced: an entry that was verified is no longer on the branch.
    pub reorganized: bool,
}
/// What changed in the pending transitions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChanges {
    /// Transitions newly held: body digests.
    pub added: Vec<String>,
    /// Transitions no longer pending (recorded, or not held).
    pub gone: Vec<String>,
    /// Every transition pending now: body digests.
    pub now: Vec<String>,
}
/// What changed in the heads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadChanges {
    /// Homes whose head was accepted.
    pub accepted: Vec<String>,
    /// Heads refused: `(home or empty, result code)`.
    pub refused: Vec<(String, String)>,
}

/// What an account holds in memory, in bytes (computed, not measured).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeldBytes {
    /// The record envelopes and their paths.
    pub records: usize,
    /// The opened plaintexts the judgement keeps (as JSON).
    pub plaintext: usize,
    /// The operation views the namespace folds keep (as JSON).
    pub folds: usize,
}

/// The 0.5 account. See the module documentation.
pub struct Account {
    me: Identity,
    now_ms: i64,
    objects: Objects,
    records: Vec<HeldRecord>,
    /// Live-state candidates (0.3 §5.1) at `state/` paths.
    live: Vec<HeldRecord>,
    /// Namespace folds taken back from a sealed checkpoint.
    fold_seed: BTreeMap<String, (String, derived::Folded)>,
    persisted: Persisted,
    seeds: SeedRing,
    scope: Option<BTreeSet<String>>,
    d: Derived,
    /// Local memory for display only (§17.5): the verified seq at which each pending
    /// transition was first held. Never an input to a verdict.
    first_seen: BTreeMap<String, u64>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Account({}, seq {}, {} seeds, ..)",
            self.d.auth.account().as_str(),
            self.d.verdict.branch.len(),
            self.seeds.len()
        )
    }
}

fn check_identity(me: &Identity) -> Result<()> {
    require(is_key_id(me.id()), "an identity is a 32-hex key ID")
}

/// Bounds on an incoming set, before any copy is made.
fn check_bounds(held: &Objects, records: &[HeldRecord], more: &Incoming) -> Result<()> {
    let count =
        |o: &Objects| o.entries.len() + o.pending.len() + o.heads.len() + o.predecessor.len();
    let incoming = count(&more.objects) + more.records.len();
    require(
        incoming <= MAX_OBJECTS
            && count(held)
                .saturating_add(records.len())
                .saturating_add(incoming)
                <= MAX_OBJECTS * 2,
        "too many objects",
    )?;
    let mut total = 0usize;
    for (list, cap) in [
        (&more.objects.entries, MAX_OBJECT_BYTES),
        (&more.objects.pending, MAX_OBJECT_BYTES),
        (&more.objects.heads, MAX_OBJECT_BYTES),
        (&more.objects.predecessor, MAX_OBJECT_BYTES),
    ] {
        for b in list {
            require(b.len() <= cap, "an object exceeds its bound")?;
            total = total.saturating_add(b.len());
        }
    }
    for r in &more.records {
        require(
            r.bytes.len() <= MAX_RECORD_BYTES,
            "a record exceeds its bound",
        )?;
        require(r.path.len() <= 512, "a record path exceeds its bound")?;
        total = total.saturating_add(r.bytes.len());
    }
    let held_total: usize = [&held.entries, &held.pending, &held.heads, &held.predecessor]
        .iter()
        .flat_map(|l| l.iter())
        .map(Vec::len)
        .sum::<usize>()
        + records.iter().map(|r| r.bytes.len()).sum::<usize>();
    require(
        held_total.saturating_add(total) <= MAX_TOTAL_BYTES,
        "the held objects exceed their total bound",
    )
}

/// Hold `from` with `into`, as a set, in one canonical order (by bytes). The verifier takes the
/// first of several envelopes over one body (§8.6: equality is body bytes), so the order the
/// objects are held in decides which it takes; a canonical order makes that a function of the
/// set and not of the order they arrived in.
fn union(into: &mut Objects, from: &Objects) -> bool {
    let mut grew = false;
    for (dst, src) in [
        (&mut into.entries, &from.entries),
        (&mut into.pending, &from.pending),
        (&mut into.heads, &from.heads),
        (&mut into.predecessor, &from.predecessor),
    ] {
        let mut seen: BTreeSet<Vec<u8>> = dst.iter().cloned().collect();
        for b in src {
            if seen.insert(b.clone()) {
                dst.push(b.clone());
                grew = true;
            }
        }
        dst.sort();
    }
    grew
}
/// Of several held byte strings at one path, drop those that are no record at all (they do not
/// parse, or their signature, account or path is wrong) when another held string at that path is
/// one. A keyless party's garbage twin of a real record then changes nothing, whichever arrived
/// first; with nothing better at the path it stays, as evidence. Returns `None` when nothing is
/// dropped. A function of the held set and the verdicts, so of the set alone.
fn without_junk(records: &[HeldRecord], d: &Derived) -> Option<Vec<HeldRecord>> {
    use crate::v05::records::Outcome as Verdict;
    let junk = |i: usize| matches!(d.judgement.records[i].outcome, Verdict::Invalid(_));
    if d.judgement.records.len() != records.len() || !(0..records.len()).any(junk) {
        return None;
    }
    let mut good: BTreeSet<&str> = BTreeSet::new();
    for (i, r) in records.iter().enumerate() {
        if !junk(i) {
            good.insert(r.path.as_str());
        }
    }
    let keep: Vec<HeldRecord> = records
        .iter()
        .enumerate()
        .filter(|(i, r)| !junk(*i) || !good.contains(r.path.as_str()))
        .map(|(_, r)| r.clone())
        .collect();
    (keep.len() != records.len()).then_some(keep)
}
fn union_records(into: &mut Vec<HeldRecord>, from: &[HeldRecord]) {
    // `into` is sorted by (path, bytes): a new record is found by binary search, so a merge
    // costs the new records, not the held ones.
    let mut added: Vec<&HeldRecord> = Vec::new();
    let mut fresh: BTreeSet<(&str, &[u8])> = BTreeSet::new();
    for r in from {
        let key = (r.path.as_str(), r.bytes.as_slice());
        let present = into
            .binary_search_by(|h| (h.path.as_str(), h.bytes.as_slice()).cmp(&key))
            .is_ok();
        if !present && fresh.insert(key) {
            added.push(r);
        }
    }
    if added.is_empty() {
        return;
    }
    into.extend(added.into_iter().cloned());
    into.sort_by(|a, b| (&a.path, &a.bytes).cmp(&(&b.path, &b.bytes)));
}

impl Account {
    /// Open an account from its objects and records as `me` at the clock `now_ms`, and
    /// optionally the verifier's stored state (§17.2): the bytes [`Account::export_persisted`]
    /// made and the same 32-byte device-held key.
    ///
    /// **Stored state is a cache authenticated by a device-held key; without it the account
    /// replays.** With no key, a wrong key, a failed tag, an unknown format, a blob for another
    /// account or identity, or any shape failure, the account silently replays the history from
    /// the objects it is given (it is never an error that stops it opening), and the per-home
    /// head marks are lost. Only a blob whose tag verified supplies its retained objects, its
    /// folded state and its head marks. An account with no verified genesis does not open.
    pub fn open(
        objects: Objects,
        records: Vec<HeldRecord>,
        stored: Option<(&[u8], &[u8; 32])>,
        me: Identity,
        now_ms: i64,
    ) -> Result<Self> {
        check_identity(&me)?;
        crate::v05::write::check_issued(now_ms)?;
        let given = Incoming { objects, records };
        check_bounds(&Objects::default(), &[], &given)?;
        if let Some((bytes, _)) = stored {
            require(
                bytes.len() <= MAX_TOTAL_BYTES,
                "the stored state exceeds its bound",
            )?;
        }
        let verified = stored.and_then(|(b, k)| stored::unprotect(b, k, &me));
        if let Some((kept, account)) = verified {
            let persisted = match kept {
                stored::Stored::Readable(p) => *p,
                // A format change made the saved state unreadable: replay from the objects, and
                // carry over the head marks (local memory no replay can recompute).
                stored::Stored::Unreadable(old) => Persisted::rebuild(&given.objects, &old, now_ms),
            };
            let tried = Self::open_with(&given, persisted, &me, now_ms)
                .ok()
                .filter(|a| a.d.auth.account().as_str() == account);
            if let Some(a) = tried {
                return Ok(a);
            }
        }
        Self::open_with(&given, Persisted::default(), &me, now_ms)
    }

    fn open_with(
        given: &Incoming,
        persisted: Persisted,
        me: &Identity,
        now_ms: i64,
    ) -> Result<Self> {
        let mut all = Objects::default();
        if let Some(p) = persisted.objects() {
            check_bounds(
                &Objects::default(),
                &[],
                &Incoming {
                    objects: p.clone(),
                    records: Vec::new(),
                },
            )?;
            union(&mut all, p);
        }
        union(&mut all, &given.objects);
        let mut held = Vec::new();
        union_records(&mut held, &given.records);
        let seeds = SeedRing::default();
        let scope = None;
        let d = Derived::build(
            &Inputs {
                objects: &all,
                records: &held,
                live: &[],
                persisted: &persisted,
                now_ms,
                seeds: &seeds,
                me,
                scope: &scope,
                fold_seed: &BTreeMap::new(),
            },
            None,
            None,
        )?;
        let mut d = d;
        if let Some(keep) = without_junk(&held, &d) {
            held = keep;
            d = Derived::build(
                &Inputs {
                    objects: &all,
                    records: &held,
                    live: &[],
                    persisted: &persisted,
                    now_ms,
                    seeds: &seeds,
                    me,
                    scope: &scope,
                    fold_seed: &BTreeMap::new(),
                },
                None,
                None,
            )?;
        }
        let persisted = if crate::v05::history::succession_status(d.auth.state())
            .is_some_and(|s| s.verified.is_some())
        {
            persisted.with_succession_verified()
        } else {
            persisted
        };
        let mut a = Self {
            me: me.clone(),
            now_ms,
            objects: all,
            records: held,
            live: Vec::new(),
            fold_seed: BTreeMap::new(),
            persisted,
            seeds,
            scope,
            d,
            first_seen: BTreeMap::new(),
        };
        a.note_pending();
        Ok(a)
    }

    /// Hold `new` records by extending the derivation in place, when that gives exactly what a
    /// rebuild over the grown set would (see [`Derived::extend`]): the clock is the one the
    /// derivation was made at, no record already held at a path is junk the new ones would
    /// replace, and every new record parses and binds to the account. Work is proportional to
    /// the new records (and a search for each), not to the records held. Returns the
    /// namespace revisions before, or `None` with nothing changed when it cannot.
    pub(super) fn extend_records(
        &mut self,
        new: &[HeldRecord],
        now: i64,
    ) -> Option<BTreeMap<String, u64>> {
        if now != self.now_ms {
            return None;
        }
        let mut fresh: Vec<&HeldRecord> = Vec::new();
        let mut seen: BTreeSet<(&str, &[u8])> = BTreeSet::new();
        for r in new {
            let key = (r.path.as_str(), r.bytes.as_slice());
            let held = self
                .records
                .binary_search_by(|h| (h.path.as_str(), h.bytes.as_slice()).cmp(&key))
                .is_ok();
            if !held && seen.insert(key) {
                fresh.push(r);
            }
        }
        let before: BTreeMap<String, u64> = self
            .d
            .folded
            .keys()
            .map(|k| (k.clone(), self.d.revision_of_ns(k)))
            .collect();
        if fresh.is_empty() {
            return Some(before);
        }
        fresh.sort_by(|a, b| (&a.path, &a.bytes).cmp(&(&b.path, &b.bytes)));
        let placed: Vec<(usize, &HeldRecord)> = fresh
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let at = self.records.partition_point(|h| {
                    (h.path.as_str(), h.bytes.as_slice()) < (r.path.as_str(), r.bytes.as_slice())
                });
                (at + i, *r)
            })
            .collect();
        // A held byte string at one of these paths that is no record at all would be dropped
        // by the rebuild once a record is held beside it: leave that to the rebuild.
        for (_, r) in &placed {
            let from = self
                .records
                .partition_point(|h| h.path.as_str() < r.path.as_str());
            for (i, h) in self.records.iter().enumerate().skip(from) {
                if h.path != r.path {
                    break;
                }
                let junk =
                    self.d.judgement.records.get(i).is_none_or(|j| {
                        matches!(j.outcome, crate::v05::records::Outcome::Invalid(_))
                    });
                if junk {
                    return None;
                }
            }
        }
        let total = self.records.len() + placed.len();
        let ok = self.d.extend(
            &Inputs {
                objects: &self.objects,
                records: &self.records,
                live: &self.live,
                persisted: &self.persisted,
                now_ms: now,
                seeds: &self.seeds,
                me: &self.me,
                scope: &self.scope,
                fold_seed: &self.fold_seed,
            },
            &placed,
            total,
        );
        if !ok {
            return None;
        }
        if placed.len() <= 16 {
            for (pos, r) in &placed {
                self.records.insert(*pos, (*r).clone());
            }
        } else {
            let old = std::mem::take(&mut self.records);
            let mut merged: Vec<HeldRecord> = Vec::with_capacity(total);
            let mut old_it = old.into_iter();
            let mut at = 0usize;
            for (pos, r) in &placed {
                while at < *pos {
                    if let Some(o) = old_it.next() {
                        merged.push(o);
                    }
                    at += 1;
                }
                merged.push((*r).clone());
                at += 1;
            }
            merged.extend(old_it);
            self.records = merged;
        }
        Some(before)
    }

    /// The judgement of exactly these bytes at `path`, when they are held.
    pub(super) fn judged_exact(
        &self,
        path: &str,
        bytes: &[u8],
    ) -> Option<&crate::v05::records::Judged> {
        let i = self
            .records
            .binary_search_by(|r| (r.path.as_str(), r.bytes.as_slice()).cmp(&(path, bytes)))
            .ok()?;
        self.d.judgement.records.get(i)
    }

    /// What changed when `before` (namespace revisions) became what the derivation holds, the
    /// objects and the verified history being as they were.
    pub(super) fn changes_since(&self, before: &BTreeMap<String, u64>) -> Changes {
        let mut c = self.diff(&self.d, &self.objects);
        for name in self.d.folded.keys() {
            let rev = self.d.revision_of_ns(name);
            if before.get(name) != Some(&rev) {
                c.namespaces.insert(name.clone(), rev);
            }
        }
        c.status = Some(Status::of(&self.d.verdict));
        c
    }

    /// Rebuild a candidate from candidate inputs without touching `self`.
    fn candidate(
        &self,
        objects: &Objects,
        records: &[HeldRecord],
        persisted: &Persisted,
        now_ms: i64,
    ) -> Result<Derived> {
        self.candidate_with(objects, records, persisted, now_ms, None)
    }
    fn candidate_with(
        &self,
        objects: &Objects,
        records: &[HeldRecord],
        persisted: &Persisted,
        now_ms: i64,
        extra: Option<&crate::v05::records::EpochKeys>,
    ) -> Result<Derived> {
        Derived::build(
            &Inputs {
                objects,
                records,
                live: &self.live,
                persisted,
                now_ms,
                seeds: &self.seeds,
                me: &self.me,
                scope: &self.scope,
                fold_seed: &self.fold_seed,
            },
            Some(&self.d),
            extra,
        )
    }

    fn note_pending(&mut self) {
        let seq = self.d.verdict.branch.len() as u64;
        let now: BTreeSet<String> = self.pending_digests();
        self.first_seen.retain(|d, _| now.contains(d));
        for d in now {
            self.first_seen.entry(d).or_insert(seq);
        }
    }

    /// Commit a candidate derived state built over (`objects`, `records`, `persisted`, `now_ms`),
    /// returning what changed. Nothing in `self` changes if this is not called.
    fn commit(
        &mut self,
        d: Derived,
        objects: Objects,
        records: Vec<HeldRecord>,
        persisted: Persisted,
        now_ms: i64,
    ) -> Changes {
        let mut changes = self.diff(&d, &objects);
        // §15.1: a verifier that has seen the succession verified keeps it. The fact is stored
        // with the persisted verifier state, never re-derived and never lost when heads age.
        let mut persisted = persisted;
        if crate::v05::history::succession_status(d.auth.state())
            .is_some_and(|s| s.verified.is_some())
        {
            persisted = persisted.with_succession_verified();
        }
        self.d = d;
        self.objects = objects;
        self.records = records;
        self.persisted = persisted;
        self.now_ms = now_ms;
        self.note_pending();
        let now = self.pending_digests();
        changes.pending.gone.retain(|g| !now.contains(g));
        changes.status = Some(Status::of(&self.d.verdict));
        changes
    }

    /// Rebuild over the current inputs (a seed or key was added): the derived keys and folds.
    pub(super) fn rebuild_in_place(&mut self) -> Result<Changes> {
        let d = self.candidate(&self.objects, &self.records, &self.persisted, self.now_ms)?;
        let (o, r, p, n) = (
            self.objects.clone(),
            self.records.clone(),
            self.persisted.clone(),
            self.now_ms,
        );
        Ok(self.commit(d, o, r, p, n))
    }

    /// Hold epoch keys opened through `v05::records`' own paths (a member's shares): they join
    /// the derived state and the folds are rebuilt.
    pub(super) fn install_keys(&mut self, keys: crate::v05::records::EpochKeys) -> Result<Changes> {
        let d = self.candidate_with(
            &self.objects,
            &self.records,
            &self.persisted,
            self.now_ms,
            Some(&keys),
        )?;
        let (o, r, p, n) = (
            self.objects.clone(),
            self.records.clone(),
            self.persisted.clone(),
            self.now_ms,
        );
        Ok(self.commit(d, o, r, p, n))
    }

    fn pending_digests(&self) -> BTreeSet<String> {
        read::pending_transitions(&self.d.effective, self.d.auth.state())
            .into_iter()
            .map(|t| t.digest)
            .collect()
    }

    fn diff(&self, new: &Derived, new_objects: &Objects) -> Changes {
        let old = &self.d;
        let (os, ns) = (old.auth.state(), new.auth.state());
        let mut c = Changes::default();
        let (ob, nb) = (&old.verdict.branch, &new.verdict.branch);
        c.authority.seq = (ob.len() as u64, nb.len() as u64);
        let common = ob.iter().zip(nb).take_while(|(a, b)| a == b).count();
        c.authority.reorganized = common < ob.len();
        let kinds = read::entry_kinds(new_objects, nb);
        for (i, d) in nb.iter().enumerate().skip(common) {
            c.authority.entries.push((
                i as u64 + 1,
                kinds.get(d).cloned().unwrap_or_else(|| "unknown".into()),
            ));
        }
        let ids = |s: &crate::v05::history::State, revoked: bool| -> BTreeSet<String> {
            s.members()
                .iter()
                .filter(|m| m.revoked_seq.is_some() == revoked)
                .map(|m| m.request.member_id())
                .collect()
        };
        c.authority.members_added = ids(ns, false)
            .difference(&ids(os, false))
            .cloned()
            .collect();
        c.authority.members_revoked = ids(ns, true).difference(&ids(os, true)).cloned().collect();
        let ctl = |s: &crate::v05::history::State| -> BTreeSet<String> {
            s.keyring().controllers.keys().cloned().collect()
        };
        c.authority.controllers_added = ctl(ns).difference(&ctl(os)).cloned().collect();
        c.authority.controllers_removed = ctl(os).difference(&ctl(ns)).cloned().collect();
        c.authority.vault_changed = os.keyring().vault != ns.keyring().vault;
        c.authority.policy_changed = os.keyring().policy != ns.keyring().policy;
        for name in new.folded.keys() {
            let before = old
                .folded
                .contains_key(name)
                .then(|| old.revision_of_ns(name));
            let rev = new.revision_of_ns(name);
            if before != Some(rev) {
                c.namespaces.insert(name.clone(), rev);
            }
        }
        let was: BTreeSet<String> = self.pending_digests();
        let now: BTreeSet<String> = read::pending_transitions(&new.effective, ns)
            .into_iter()
            .map(|t| t.digest)
            .collect();
        c.pending.added = now.difference(&was).cloned().collect();
        c.pending.gone = was.difference(&now).cloned().collect();
        c.pending.now = now.iter().cloned().collect();
        c
    }

    // -----------------------------------------------------------------------------------------
    // Reading the account's standing.

    /// The account ID.
    pub fn id(&self) -> &AccountId {
        self.d.auth.account()
    }
    /// This session's identity.
    pub fn identity(&self) -> &Identity {
        &self.me
    }
    /// The clock the account was last advanced to, in ms.
    pub fn now_ms(&self) -> i64 {
        self.now_ms
    }
    /// The body digest of the genesis (seq 1): the account's identity is derived from it.
    pub fn objects_first(&self) -> String {
        self.d.verdict.branch.first().cloned().unwrap_or_default()
    }
    /// The head of the verified history: its seq and body digest. A home's head names it
    /// (§13.2); a call's `asOf` is at most it (§12.2).
    pub fn head(&self) -> (u64, String) {
        let h = &self.d.verdict.branch;
        (h.len() as u64, h.last().cloned().unwrap_or_default())
    }
    /// Where the verifier stands.
    pub fn status(&self) -> Status {
        Status::of(&self.d.verdict)
    }
    /// The body digests of the verified branch, in seq order (seq 1 first).
    pub fn branch_digests(&self) -> &[String] {
        &self.d.verdict.branch
    }
    /// The held authority-side objects: public bytes an engine stores.
    pub fn objects(&self) -> &Objects {
        &self.objects
    }
    /// What this account holds in memory, computed: the record envelopes, the opened plaintexts
    /// the judgement keeps, and the operation views the namespace folds keep.
    pub fn held_bytes(&self) -> HeldBytes {
        let (plaintext, folds) = derived::held_bytes(&self.d);
        HeldBytes {
            records: self
                .records
                .iter()
                .map(|r| r.path.len() + r.bytes.len())
                .sum(),
            plaintext,
            folds,
        }
    }
    /// Rebuild the derivation from nothing over the inputs held and require it to equal the one
    /// maintained incrementally: the judgement of every record, the proposals, the write index,
    /// the live judgement and every namespace fold. A diagnostic for hosts and tests; it costs
    /// as much as a cold open.
    pub fn verify_derivation(&self) -> Result<()> {
        let fresh = Derived::build(
            &Inputs {
                objects: &self.objects,
                records: &self.records,
                live: &self.live,
                persisted: &self.persisted,
                now_ms: self.now_ms,
                seeds: &self.seeds,
                me: &self.me,
                scope: &self.scope,
                fold_seed: &BTreeMap::new(),
            },
            None,
            Some(&self.d.keys),
        )?;
        let (mine, theirs) = (derived::fingerprint(&self.d), derived::fingerprint(&fresh));
        if mine != theirs {
            let part = mine
                .iter()
                .zip(&theirs)
                .find(|(a, b)| a != b)
                .map_or_else(|| "its parts".to_string(), |(a, _)| a.0.clone());
            return Err(crate::v05::malformed(format!(
                "the maintained derivation differs from a rebuild over the same inputs: {part}"
            )));
        }
        for ns in self.d.auth.namespaces() {
            require(
                self.durable_clock(ns) == self.highest_admitted_clock(ns),
                "the durable clock index differs from the judged records",
            )?;
        }
        // What readers see with live heads is what one plain fold of the merged order gives.
        for ns in self.d.folded.keys() {
            let Some(o) = self.d.overlaid(ns) else {
                continue;
            };
            let Some((rev, state, _)) = derived::reference_merged(&self.d, ns) else {
                continue;
            };
            require(
                rev == o.revision
                    && state == serde_json::to_string(&o.fold.state).unwrap_or_default(),
                "the live overlay differs from a fold of the merged order",
            )?;
        }
        Ok(())
    }
    /// The held record headers: public bytes an engine stores.
    pub fn records(&self) -> &[HeldRecord] {
        &self.records
    }
    /// A change token for a namespace's fold: a function of the admitted operations folded and
    /// their order, so two accounts holding the same objects have the same token however the
    /// objects arrived. It is not a counter. 0 when nothing is folded here.
    pub fn revision(&self, namespace: &str) -> u64 {
        self.d.revision_of_ns(namespace)
    }
    /// The work the latest derivation did, so a host and a test can see that a merge of new
    /// records judged and folded only what is new (E6's incremental judgement).
    pub fn work(&self) -> Work {
        let (last, total) = {
            let c = self
                .d
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (c.last_run(), c.totals())
        };
        Work {
            last,
            total,
            fold_applied: self.d.fold_applied,
        }
    }
    /// Move the verifier's resume point to the current verified state, in memory (the sealed
    /// export is [`Account::export_persisted`]). Later merges then verify only the entries
    /// after it instead of the whole history (§13.3, §17.2). Crate-private: the engine calls it
    /// after it has loaded, and it changes no verdict (the account tests show a resumed
    /// verifier and a replaying one agree).
    pub(crate) fn checkpoint_verifier(&mut self) {
        self.persisted = Persisted::checkpoint(&self.objects, &self.persisted, self.now_ms);
    }
    /// What this device may remember of the held records' crypto, for the engine's sealed
    /// checkpoint (crate-private: a caller could not tell it from verified state).
    pub(crate) fn export_judge_memo(&self) -> Vec<crate::v05::records::RecordMemo> {
        self.d
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .export_memo(&self.records)
    }
    /// Take a memo back from a checkpoint whose seal verified.
    pub(crate) fn import_judge_memo(&mut self, memo: Vec<crate::v05::records::RecordMemo>) {
        self.d
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .import_memo(memo);
    }
    /// The current live heads (0.3 §5.1): verified, current, folded.
    pub fn live_heads(&self) -> &[crate::v05::live::LiveHead] {
        &self.d.live.heads
    }
    /// The verdict on each live-state candidate held: `(path, verdict)`.
    pub fn live_verdicts(&self) -> &[(String, crate::v05::live::LiveVerdict)] {
        &self.d.live.verdicts
    }
    /// Hold live-state candidates (`state/<author>/<namespace>/<slot>.json` envelopes) and
    /// judge them with the history (0.3 §5.1). They are held as a set, so the heads are a
    /// function of what is held. What is held is pruned as a function of the set (see the
    /// code): never more than [`crate::v05::live::MAX_CANDIDATES_PER_PATH`] byte strings per
    /// path and 16,384 in all; a merge past either bound is refused whole. Nothing changes on
    /// failure.
    pub fn merge_live(&mut self, candidates: Vec<HeldRecord>, now_ms: i64) -> Result<Changes> {
        crate::v05::write::check_issued(now_ms)?;
        require(
            candidates.len() <= 16_384
                && candidates
                    .iter()
                    .all(|c| c.bytes.len() <= MAX_RECORD_BYTES && c.path.len() <= 512),
            "a live candidate exceeds its bound",
        )?;
        // The clock where the derivation was made: the slots the candidates are at are judged
        // again and no other thing is (a slot's verdict reads only its own candidates, the
        // verified history, the keys and the durable index).
        if now_ms.max(self.now_ms) == self.now_ms {
            return self.merge_live_slots(candidates);
        }
        self.merge_live_whole(candidates, now_ms)
    }

    /// [`Account::merge_live`] judging only the slots the candidates are at. The same set is
    /// held, and the same verdicts and heads result, as [`Account::merge_live_whole`] gives
    /// (`tests/v05_incremental.rs` compares them after every step): the merge, the pruning
    /// of what can no longer matter and the bounds are decided per path, and a failed merge
    /// changes nothing.
    fn merge_live_slots(&mut self, candidates: Vec<HeldRecord>) -> Result<Changes> {
        use crate::v05::live::{judge_group, prune_group};
        let mut by_path: BTreeMap<String, Vec<HeldRecord>> = BTreeMap::new();
        for c in candidates {
            by_path.entry(c.path.clone()).or_default().push(c);
        }
        // The union per path, and what it adds.
        struct Group {
            path: String,
            from: usize,
            to: usize,
            union: Vec<HeldRecord>,
        }
        let mut groups: Vec<Group> = Vec::new();
        let mut added = 0usize;
        for (path, new) in by_path {
            let from = self
                .live
                .partition_point(|h| h.path.as_str() < path.as_str());
            let to = from
                + self.live[from..]
                    .iter()
                    .take_while(|h| h.path == path)
                    .count();
            let mut union: Vec<HeldRecord> = self.live[from..to].to_vec();
            union_records(&mut union, &new);
            if union.len() == to - from {
                continue;
            }
            added += union.len() - (to - from);
            groups.push(Group {
                path,
                from,
                to,
                union,
            });
        }
        require(
            self.live.len().saturating_add(added) <= 32_768,
            "too many live candidates",
        )?;
        // The namespaces the candidates are in: only their change tokens can move.
        let touched: BTreeSet<String> = groups
            .iter()
            .flat_map(|g| g.union.iter())
            .filter_map(|c| crate::v05::records::OperationHeader::parse(&c.bytes).ok())
            .map(|(h, _)| h.namespace)
            .filter(|n| self.d.folded.contains_key(n))
            .collect();
        let before: BTreeMap<String, u64> = touched
            .iter()
            .map(|k| (k.clone(), self.d.revision_of_ns(k)))
            .collect();
        // Judge each path, keep what can still matter, judge what is kept.
        let mut done: Vec<(Group, Vec<HeldRecord>, crate::v05::live::GroupJudgement)> = Vec::new();
        {
            let mut cache = self
                .d
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for g in groups {
                let j = judge_group(
                    &self.d.auth,
                    &self.d.keys,
                    &self.d.durable,
                    &g.union,
                    None,
                    Some(&mut cache),
                );
                let keep = prune_group(&g.union, &j);
                let (keep, j) = if keep.len() != g.union.len() {
                    let j = judge_group(
                        &self.d.auth,
                        &self.d.keys,
                        &self.d.durable,
                        &keep,
                        None,
                        Some(&mut cache),
                    );
                    (keep, j)
                } else {
                    (g.union.clone(), j)
                };
                done.push((g, keep, j));
            }
        }
        let mut total = self.live.len();
        for (g, keep, _) in &done {
            require(
                keep.len() <= crate::v05::live::MAX_CANDIDATES_PER_PATH,
                "too many live candidates",
            )?;
            total = total - (g.to - g.from) + keep.len();
        }
        require(total <= 16_384, "too many live candidates")?;
        // Nothing can fail from here: splice the groups in, last position first so the
        // positions of the earlier ones hold.
        done.sort_by(|a, b| (b.0.from, &b.0.path).cmp(&(a.0.from, &a.0.path)));
        for (g, keep, j) in done {
            let jumped = j
                .verdicts
                .iter()
                .any(|v| matches!(v, crate::v05::live::LiveVerdict::Refused("clockJump")));
            self.d.live.verdicts.splice(
                g.from..g.to,
                keep.iter()
                    .zip(j.verdicts)
                    .map(|(c, v)| (c.path.clone(), v)),
            );
            self.d.set_head_of(&g.path, j.head);
            self.d
                .live_idx
                .set_group(&g.path, j.metas.into_iter().flatten().collect(), jumped);
            self.live.splice(g.from..g.to, keep);
        }
        let mut c = self.diff(&self.d, &self.objects);
        // `diff` of a derivation with itself names no namespace: the touched ones are compared.
        for name in &touched {
            let rev = self.d.revision_of_ns(name);
            if before.get(name) != Some(&rev) {
                c.namespaces.insert(name.clone(), rev);
            }
        }
        c.status = Some(Status::of(&self.d.verdict));
        Ok(c)
    }

    /// [`Account::merge_live`] judging every held live candidate and rebuilding the derivation.
    fn merge_live_whole(&mut self, candidates: Vec<HeldRecord>, now_ms: i64) -> Result<Changes> {
        let mut live = self.live.clone();
        union_records(&mut live, &candidates);
        require(live.len() <= 32_768, "too many live candidates")?;
        let now = now_ms.max(self.now_ms);
        let build = |this: &Self, live: &[HeldRecord]| {
            Derived::build(
                &Inputs {
                    objects: &this.objects,
                    records: &this.records,
                    live,
                    persisted: &this.persisted,
                    now_ms: now,
                    seeds: &this.seeds,
                    me: &this.me,
                    scope: &this.scope,
                    fold_seed: &this.fold_seed,
                },
                Some(&this.d),
                None,
            )
        };
        let mut d = build(self, &live)?;
        // Keep what can still matter, as a function of the set: a candidate that is no live
        // record at all is dropped, and of the valid ones a slot keeps its two highest
        // generations (the head, and the one that takes over if the head stops being valid).
        let mut keep: Vec<HeldRecord> = Vec::new();
        let mut superseded: BTreeMap<String, Vec<(u64, usize)>> = BTreeMap::new();
        for (i, (c, (_, v))) in live.iter().zip(&d.live.verdicts).enumerate() {
            match v {
                crate::v05::live::LiveVerdict::Invalid(_) => {}
                crate::v05::live::LiveVerdict::Superseded => {
                    let g = crate::v05::records::OperationHeader::parse(&c.bytes)
                        .map_or(0, |(h, _)| h.clock);
                    superseded.entry(c.path.clone()).or_default().push((g, i));
                }
                _ => keep.push(c.clone()),
            }
        }
        for list in superseded.values_mut() {
            list.sort_by(|a, b| b.cmp(a));
            for (_, i) in list.iter().take(2) {
                keep.push(live[*i].clone());
            }
        }
        keep.sort_by(|a, b| (&a.path, &a.bytes).cmp(&(&b.path, &b.bytes)));
        let mut per: BTreeMap<&str, usize> = BTreeMap::new();
        for c in &keep {
            *per.entry(c.path.as_str()).or_default() += 1;
        }
        require(
            keep.len() <= 16_384
                && per
                    .values()
                    .all(|n| *n <= crate::v05::live::MAX_CANDIDATES_PER_PATH),
            "too many live candidates",
        )?;
        if keep.len() != live.len() {
            live = keep;
            d = build(self, &live)?;
        }
        let (o, r, p) = (
            self.objects.clone(),
            self.records.clone(),
            self.persisted.clone(),
        );
        let c = self.commit(d, o, r, p, now);
        self.live = live;
        Ok(c)
    }
    /// The position of the judgement that stands for `path`: several held byte strings can sit at
    /// one path (a garbage twin beside the real record), and the first that is a record at all
    /// stands for it (the first of all when none is). The held records are sorted by path, so
    /// this is a search and not a pass.
    fn judged_index(&self, path: &str) -> Option<usize> {
        let from = self.records.partition_point(|r| r.path.as_str() < path);
        let mut first = None;
        for (i, r) in self.records.iter().enumerate().skip(from) {
            if r.path != path {
                break;
            }
            let bad = matches!(
                self.d.judgement.records.get(i)?.outcome,
                crate::v05::records::Outcome::Invalid(_)
            );
            if !bad {
                return Some(i);
            }
            first.get_or_insert(i);
        }
        first
    }
    /// The verdict on the held record at `path`, as the §11.5 spelling (`admitted`,
    /// `refused:…`, `held:…`), or `None` when no held record is at that path.
    pub fn record_verdict(&self, path: &str) -> Option<String> {
        let i = self.judged_index(path)?;
        self.d.judgement.records.get(i).map(|j| j.outcome.code())
    }
    /// Whether `bytes` at `path` would be a record of this account (see
    /// [`crate::v05::records`]): not garbage, not another account's, not a bad signature. One
    /// signature check, nothing is held.
    pub fn would_hold(&self, path: &str, bytes: &[u8]) -> bool {
        crate::v05::records::is_record_candidate(
            &self.d.auth,
            &HeldRecord {
                path: path.to_string(),
                bytes: bytes.to_vec(),
            },
        )
    }
    /// The verdict on exactly these bytes at `path`, when the account holds them: `None` when it
    /// does not hold this byte string there.
    pub fn verdict_of(&self, path: &str, bytes: &[u8]) -> Option<String> {
        let i = self
            .records
            .binary_search_by(|r| (r.path.as_str(), r.bytes.as_slice()).cmp(&(path, bytes)))
            .ok()?;
        self.d.judgement.records.get(i).map(|j| j.outcome.code())
    }
    /// The highest clock of an admitted, authenticated operation in `namespace` (0 if none): a
    /// writer's next clock is one past it (§11.4).
    pub fn highest_admitted_clock(&self, namespace: &str) -> u64 {
        self.d
            .judgement
            .records
            .iter()
            .filter(|j| {
                j.outcome == crate::v05::records::Outcome::Admitted
                    && j.plaintext.is_some()
                    && j.namespace.as_deref() == Some(namespace)
            })
            .map(|j| j.clock)
            .max()
            .unwrap_or(0)
    }
    /// The highest generation among the live candidates held for `author`'s `slot` in
    /// `namespace` that are live records at all (0 if none): a new sample goes above it, so a
    /// writer never reuses a generation an equivocation spoiled.
    pub fn live_generation_floor(&self, author: &str, namespace: &str, slot: &str) -> u64 {
        let path = crate::v05::live::live_path(author, namespace, slot);
        self.d.live_idx.floor(&path)
    }
    /// Whether a live candidate held names this epoch and nonce (a nonce is never used twice
    /// under a key).
    pub(crate) fn live_nonce_used(&self, epoch: u64, nonce: &[u8]) -> bool {
        self.d.live_idx.has_nonce(epoch, nonce)
    }
    /// Whether a header held (a record or a live candidate) uses this namespace, epoch and
    /// nonce.
    pub(crate) fn durable_nonce_used(&self, namespace: &str, epoch: u64, nonce: &[u8]) -> bool {
        self.d
            .windex
            .nonces
            .contains(&(namespace.to_string(), epoch, nonce.to_vec()))
    }
    /// The current live head at `path`, when there is one.
    pub fn live_head_at(&self, path: &str) -> Option<&crate::v05::live::LiveHead> {
        self.d.live.heads.iter().find(|h| h.path == path)
    }
    /// The highest admitted durable clock of `namespace`, from the index the live judgement
    /// reads (it equals [`Account::highest_admitted_clock`]; `verify_derivation` checks that).
    pub(crate) fn durable_clock(&self, namespace: &str) -> u64 {
        self.d.durable.highest(namespace)
    }
    /// What the live judgement would say of `candidate` held with the live candidates now held,
    /// without holding it. `unsigned` skips the signature check (the write side's own header
    /// before the host signed it).
    pub(crate) fn preview_live(
        &self,
        candidate: HeldRecord,
        unsigned: bool,
    ) -> Result<crate::v05::live::LiveVerdict> {
        // The slot's own candidates with this one: no other slot's verdict reads them.
        let from = self
            .live
            .partition_point(|h| h.path.as_str() < candidate.path.as_str());
        let to = from
            + self.live[from..]
                .iter()
                .take_while(|h| h.path == candidate.path)
                .count();
        let mut group: Vec<HeldRecord> = self.live[from..to].to_vec();
        union_records(&mut group, std::slice::from_ref(&candidate));
        let at = group
            .iter()
            .position(|c| c.path == candidate.path && c.bytes == candidate.bytes)
            .ok_or_else(|| crate::v05::malformed("candidate not held"))?;
        let mut cache = self
            .d
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let j = crate::v05::live::judge_group(
            &self.d.auth,
            &self.d.keys,
            &self.d.durable,
            &group,
            unsigned.then_some(at),
            Some(&mut cache),
        );
        Ok(j.verdicts
            .get(at)
            .cloned()
            .unwrap_or(crate::v05::live::LiveVerdict::Invalid("not judged".into())))
    }
    /// The namespace folds, for the engine's sealed checkpoint: what a resumed open reuses
    /// instead of folding every operation again. Crate-private (it holds plaintext state).
    pub(crate) fn export_folds(&self) -> Vec<FoldSnapshot> {
        let print = crate::v05::engine::hex(&self.d.print);
        self.d
            .folded
            .iter()
            .filter_map(|(ns, f)| {
                Some(FoldSnapshot {
                    namespace: ns.clone(),
                    print: print.clone(),
                    state: serde_json::to_value(&f.fold.state).ok()?,
                    order: f.fold.order.clone(),
                    clock: f.fold.clock,
                    applied: f.fold.applied,
                    admitted: f.admitted.clone(),
                })
            })
            .collect()
    }
    /// Take namespace folds back from a checkpoint whose seal verified. They are used only
    /// when the verified standing they were made under (the print) and the operations folded
    /// are exactly those the judgement now yields, as a prefix.
    pub(crate) fn import_folds(&mut self, snaps: Vec<FoldSnapshot>) {
        for s in snaps {
            let Ok(state) = serde_json::from_value(s.state) else {
                continue;
            };
            let hashes = crate::engine::prefix_hashes(&s.order);
            let fold = crate::engine::Namespace {
                revision: 0,
                state,
                order: s.order,
                hashes,
                clock: s.clock,
                checkpoints: Vec::new(),
                applied: s.applied,
            };
            self.fold_seed.insert(
                s.namespace,
                (
                    s.print,
                    derived::Folded {
                        revision: 0,
                        fold,
                        admitted: s.admitted,
                        keys: Vec::new(),
                    },
                ),
            );
        }
    }
    /// Whether this account has seen its succession verified (§15.1), kept in its persisted
    /// verifier state.
    pub fn succession_seen_verified(&self) -> bool {
        self.persisted.succession_verified()
    }
    /// The record-layer view of the verified history, for the engine (crate-private: it holds
    /// no secret, but the engine must not take verified state from a caller, so it reads this).
    pub(crate) fn record_authority(&self) -> &crate::v05::records::RecordAuthority {
        &self.d.auth
    }
    /// The epoch keys this account holds, for the engine's blob and live-state work.
    /// Crate-private: nothing outside the crate can read a key through it.
    pub(crate) fn epoch_keys(&self) -> &crate::v05::records::EpochKeys {
        &self.d.keys
    }
    /// Restrict which namespaces this session folds and unlocks (as 0.4's read scope).
    pub fn set_read_scope(&mut self, namespaces: Vec<String>) -> Result<Changes> {
        for n in &namespaces {
            require(
                crate::v05::terms::valid_namespace(n),
                "invalid namespace in the read scope",
            )?;
        }
        let old = self.scope.replace(namespaces.into_iter().collect());
        match self.rebuild_in_place() {
            Ok(c) => Ok(c),
            Err(e) => {
                self.scope = old;
                Err(e)
            }
        }
    }

    /// Advance the clock. A clock that does not move forward changes nothing. Time decides
    /// what is held, due, expired and suspended, so the account is rebuilt.
    pub fn advance(&mut self, now_ms: i64) -> Result<Changes> {
        crate::v05::write::check_issued(now_ms)?;
        if now_ms <= self.now_ms {
            return Ok(Changes::default());
        }
        let d = self.candidate(&self.objects, &self.records, &self.persisted, now_ms)?;
        let (o, r, p) = (
            self.objects.clone(),
            self.records.clone(),
            self.persisted.clone(),
        );
        Ok(self.commit(d, o, r, p, now_ms))
    }

    /// The verified view calls are evaluated over (§12.3), at the account's clock.
    pub(super) fn call_view(&self) -> Result<AccountView> {
        AccountView::from_history_verifier(&self.d.verdict, &self.d.effective, self.now_ms)
    }

    /// Merge incoming objects at the clock `now_ms` (never backwards). Objects are held as a
    /// set; the verdict is a function of that set. Nothing changes if the merge cannot be
    /// applied (an over-bound set, or a set with no verified genesis).
    ///
    /// Heads are also checked against the held history and this account's high-water marks
    /// (§13.3); a refused head is reported in [`Changes::heads`].
    pub fn merge(&mut self, incoming: Incoming, now_ms: i64) -> Result<Changes> {
        crate::v05::write::check_issued(now_ms)?;
        check_bounds(&self.objects, &self.records, &incoming)?;
        let now = now_ms.max(self.now_ms);
        // Another account's genesis is not part of this account's object set.
        let mut incoming = incoming;
        let ours = self.d.verdict.branch.first().cloned();
        let before = incoming.objects.entries.len();
        incoming.objects.entries.retain(|b| {
            let Ok(e) = crate::v05::history::envelope::AuthEnvelope::parse(
                b,
                crate::v05::encoding::bounds::AUTHORITY_BODY,
                crate::v05::encoding::bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            ) else {
                return true;
            };
            let genesis = e.value.get("seq").and_then(serde_json::Value::as_u64) == Some(1);
            !genesis || Some(&e.digest) == ours.as_ref()
        });
        let foreign = before - incoming.objects.entries.len();
        let only_records = incoming.objects.entries.is_empty()
            && incoming.objects.pending.is_empty()
            && incoming.objects.heads.is_empty()
            && incoming.objects.predecessor.is_empty();
        if only_records {
            // New records after nothing else: the derivation is extended, not rebuilt, and no
            // held record or object is copied.
            if let Some(before) = self.extend_records(&incoming.records, now) {
                let mut c = self.changes_since(&before);
                c.foreign = foreign;
                return Ok(c);
            }
        }
        let mut objects = self.objects.clone();
        let mut records = self.records.clone();
        union(&mut objects, &incoming.objects);
        union_records(&mut records, &incoming.records);
        let mut d = self.candidate(&objects, &records, &self.persisted, now)?;
        if let Some(keep) = without_junk(&records, &d) {
            records = keep;
            d = self.candidate(&objects, &records, &self.persisted, now)?;
        }
        let mut persisted = self.persisted.clone();
        let mut heads = HeadChanges::default();
        {
            let state = d.auth.state();
            let homes: Vec<(String, Vec<u8>)> = state
                .current_homes()
                .iter()
                .map(|m| (m.request.member_id(), m.request.signing.clone()))
                .collect();
            for h in &incoming.objects.heads {
                let ctx = crate::v05::heads::HeadContext {
                    account: d.auth.account(),
                    history: state.history(),
                    homes: &homes,
                    now_ms: now,
                };
                match persisted.accept_head(h, ctx) {
                    Ok(head) => heads.accepted.push(head.by().to_string()),
                    Err(e) => heads
                        .refused
                        .push((crate::v05::heads::head_by(h).unwrap_or_default(), e.code())),
                }
            }
        }
        heads.accepted.sort();
        heads.accepted.dedup();
        heads.refused.sort();
        heads.refused.dedup();
        let mut c = self.commit(d, objects, records, persisted, now);
        c.heads = heads;
        c.foreign = foreign;
        Ok(c)
    }

    // -----------------------------------------------------------------------------------------
    // Persisted verifier state (§17.2).

    /// The verifier's persisted state (§17.2), protected under the host's 32-byte device-held
    /// `key` and bound to this account and identity, for the host to store atomically.
    /// `nonce_seed` is fresh host entropy for this export. The bytes carry the retained objects
    /// and the head marks; they are a cache, and [`Account::open`] replays without the key.
    /// The account resumes from the checkpoint it made from now on.
    pub fn export_persisted(&mut self, key: &[u8; 32], nonce_seed: [u8; 32]) -> Result<Vec<u8>> {
        let p = Persisted::checkpoint(&self.objects, &self.persisted, self.now_ms);
        let bytes = stored::protect(
            &p,
            self.d.auth.account().as_str(),
            &self.me,
            key,
            nonce_seed,
        )?;
        self.persisted = p;
        Ok(bytes)
    }
}

/// What the host must sign for the step at `index`, and with which key (a convenience over
/// [`PendingAction::steps`] for hosts that show a list).
pub fn describe_step(step: &SigningStep) -> (String, String, bool) {
    (
        step.path().to_string(),
        step.signer().to_string(),
        step.challenge().is_some(),
    )
}

/// Prepare a membership request (§9.1) for a member who may not hold the account (its side is
/// public values only). See [`crate::v05::write::calls::prepare_request`].
pub fn prepare_request(
    spec: &crate::v05::write::calls::RequestSpec<'_>,
) -> Result<crate::v05::write::calls::PreparedRequest> {
    crate::v05::write::calls::prepare_request(spec)
}

/// A verified request, as an approver sees it before it grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequest {
    /// The envelope bytes, to hand to [`Account::begin_approve`].
    pub raw: Vec<u8>,
    /// The member ID the grant would create.
    pub member: String,
    /// The label.
    pub label: String,
    /// `device`, `app`, `agent` or `server`.
    pub kind: String,
    /// The terms asked for, as JSON.
    pub terms: serde_json::Value,
}

/// Finish a request: assemble the envelope and parse it as an approver would.
pub fn finish_request(
    prepared: &crate::v05::write::calls::PreparedRequest,
    signature: &SignatureResult,
) -> Result<AccessRequest> {
    let raw = crate::v05::write::calls::finish_request(prepared, signature)?;
    request_info(&raw)
}

/// Parse a request envelope: shape, terms and signature under `member.signing`.
pub fn request_info(raw: &[u8]) -> Result<AccessRequest> {
    let req = crate::v05::members::Request::parse(raw, false)?;
    req.unknown.check()?;
    let body = crate::v05::encoding::strict_parse(&req.body)?;
    Ok(AccessRequest {
        raw: raw.to_vec(),
        member: req.member_id(),
        label: req.label.clone(),
        kind: body
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        terms: body.get("terms").cloned().unwrap_or_default(),
    })
}
