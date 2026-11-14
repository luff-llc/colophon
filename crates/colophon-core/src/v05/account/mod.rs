//! The 0.5 account: the counterpart of the 0.4 `Library`. One in-memory object an app session
//! holds. It opens an account from its objects, unlocks it, performs every action as *prepare,
//! then finish*, merges incoming objects, and answers views and queries.
//!
//! It is sans-IO: no storage, no network, no clock, no RNG. Seeds, nonces and the time are
//! arguments. The storage engine, record sources, on-disk checkpoints, blobs and relay cursors
//! are the next package (E6).
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
//! | `checkpoint`, `restore_checkpoint`, `set_checkpoint_policy` | E6 for on-disk namespace checkpoints. The verifier's persisted state (§17.2), authenticated under a device-held key as 0.4 protects its checkpoints: [`Account::export_persisted`] and the stored bytes and key given to [`Account::open`] |
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
//! | `begin_import_grant`, `begin_import`, `import_*`, `reconcile_import_prefix` | `import` is a `terms` field in 0.5 (§9.3, §10.1): [`Account::begin_approve`] carries it; import batches belong to E6 |
//! | `begin_write`, `written_operation*`, `live_generation` | [`Account::begin_write`] (a `/5` operation); live stamps and live generations belong to E6 |
//! | `begin_layout` | gone in 0.5: a `/5` account is at layout 2 from genesis (§11.8) |
//! | `members`, `me` | [`Account::members`], [`Account::me`], [`Account::controllers`] |
//! | `tools`, `begin_call` | [`Account::tools`]; calls: [`Account::begin_link`], [`Account::begin_call`] (§12) |
//! | `ledger` | [`Account::ledger`] |
//! | `begin_blob`, `open_blob_chunk`, `read_blob_chunk`, `NativeBlobWriter` | E6 (blobs) |
//! | `NativeEngine::*`, `RecordSource`, `verify_batch`, `records_at`, `update_versions` | E6 (the storage engine) |
//! | `NativeCheckpoint*` | E6 |
//! | `vault_public`, `webauthn_prf_input`, `parse_registration` | already in `v05::vault`, `v05::slots` and `keys` |
//! | (new) pending transitions | [`Account::pending`], [`Account::begin_transition`], [`Account::begin_veto`], [`Account::begin_suspend`], [`Account::record_due`] (the determined `activate`, `vetoed` and `final`), [`Account::begin_resolve`] and [`Account::fork_candidates`] |
//! | (new) notices (§17.5) | [`Account::pending`], [`Account::notices`] |
//! | (new) shares owed | [`Account::owed_shares`], [`Account::begin_renew`] |
//! | (new) proposals (§11.6) | [`Account::proposals`], [`Account::begin_propose`], [`Account::begin_resolution`] |
mod action;
mod create;
mod derived;
mod read;
mod stored;
mod unlock;

pub use action::{
    ActionInfo, AddController, AddMode, CallTarget, Change, Finished, KeyringEdit, PendingAction,
    RevokeKeep, SignerChoice,
};
pub use create::{default_policy, CreateParams, CreateProgress, Creation};
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

/// The 0.5 account. See the module documentation.
pub struct Account {
    me: Identity,
    now_ms: i64,
    objects: Objects,
    records: Vec<HeldRecord>,
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
fn union_records(into: &mut Vec<HeldRecord>, from: &[HeldRecord]) {
    let mut seen: BTreeSet<(String, Vec<u8>)> = into
        .iter()
        .map(|r| (r.path.clone(), r.bytes.clone()))
        .collect();
    for r in from {
        if seen.insert((r.path.clone(), r.bytes.clone())) {
            into.push(r.clone());
        }
    }
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
        if let Some((persisted, account)) = verified {
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
                persisted: &persisted,
                now_ms,
                seeds: &seeds,
                me,
                scope: &scope,
            },
            None,
            None,
        )?;
        let mut a = Self {
            me: me.clone(),
            now_ms,
            objects: all,
            records: held,
            persisted,
            seeds,
            scope,
            d,
            first_seen: BTreeMap::new(),
        };
        a.note_pending();
        Ok(a)
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
                persisted,
                now_ms,
                seeds: &self.seeds,
                me: &self.me,
                scope: &self.scope,
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
        for (name, f) in &new.folded {
            let before = old.folded.get(name).map(|b| b.revision);
            if before != Some(f.revision) {
                c.namespaces.insert(name.clone(), f.revision);
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
    /// The held authority-side objects: public bytes an engine stores.
    pub fn objects(&self) -> &Objects {
        &self.objects
    }
    /// The held record headers: public bytes an engine stores.
    pub fn records(&self) -> &[HeldRecord] {
        &self.records
    }
    /// The local revision of a namespace's fold (it rises whenever its admitted operations
    /// change); 0 when it is not folded here.
    pub fn revision(&self, namespace: &str) -> u64 {
        self.d.folded.get(namespace).map_or(0, |f| f.revision)
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
        let mut objects = self.objects.clone();
        let mut records = self.records.clone();
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
        union(&mut objects, &incoming.objects);
        union_records(&mut records, &incoming.records);
        let d = self.candidate(&objects, &records, &self.persisted, now)?;
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
