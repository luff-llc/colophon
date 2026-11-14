//! Moving a library into this account: the §16.1 in-place upgrade of a 0.4 account and the §15.3
//! steps of a Swift succession (§16.2), each a thin composition of the merged builders with the
//! account's own verified state.
//!
//! **The order of a Swift succession** (§15.3, §16.2), and what refuses what:
//!
//! 1. *Preflight.* Before any account exists: [`SwiftLibrary::read`] verifies the predecessor
//!    with the Swift verifier; [`swift_slotted_controllers`] and [`swift_carried_controllers`]
//!    say what must be carried.
//! 2. *The successor genesis with its hand-over.* `prepare_swift_genesis` (it needs the new
//!    slots, built from a new seed, §7.1, one assertion per passkey).
//! 3. *Homes and the genesis receipts.* The account's ordinary `begin_transition` with a `homes`
//!    change opens the window; each home receipts the genesis (`prepare_genesis_receipt`).
//! 4. *The wait.* [`Account::swift_succession`] says the stage, the window, the due time, the
//!    veto deadline and the predecessor keys that may veto; [`Account::begin_swift_veto`] is the
//!    owner's defence, signed by predecessor keys under their Swift descriptors.
//! 5. *F.* [`Account::begin_swift_freeze`] and [`Account::finish_move`]: F's exact Swift-format
//!    bytes, for the Swift side to append; [`Account::accept_predecessor_entry`] then takes F
//!    into the account's predecessor objects.
//! 6. *The record copy.* [`Account::begin_swift_copy_write`] and
//!    [`Account::finish_swift_copy_write`], one import write at a time from a
//!    [`CopyPlan`](crate::v05::swift_copy::CopyPlan), refused until the succession is verified.
//! 7. *`migration`.* [`Account::begin_swift_migration`] takes a finished [`CopyResult`], which
//!    exists only once every source record was written or omitted: the counts and view digests
//!    are the copy's own.
//!
//! Each step refuses out of order, by the reason in the error. Nothing here signs, holds a
//! secret or keeps a clock: the host signs each step's exact bytes and passes the time.
use super::{Account, Changes, Finished, Incoming, PendingAction};
use crate::model::Records as Legacy;
use crate::v05::encoding::{decode_base64, strict_parse};
use crate::v05::encoding::{digest, parse_date};
use crate::v05::history::swift;
use crate::v05::history::{
    succession_status, verify_history, Objects, Persisted, SuccessionStatus,
};
use crate::v05::records::{Level, OperationHeader};
use crate::v05::swift_copy::{CopyItem, CopyPlan, CopyResult, Destination, DestinationBatch};
use crate::v05::write::authority::PendingBatch;
use crate::v05::write::records::prepare_renew_shares;
use crate::v05::write::succession::{
    prepare_migration, prepare_swift_freeze, Frozen, MigratedMember, MigrationParams,
    PendingFreeze, SwiftFreezeParams,
};
use crate::v05::write::swift_veto::{prepare_swift_veto, PendingSwiftVeto, SwiftVetoParams};
use crate::v05::write::upgrade::{prepare_upgrade, PendingUpgrade, UpgradeParams};
use crate::v05::write::{SignatureResult, SigningStep};
use crate::v05::{malformed, require, Failure, Result};
use serde_json::json;
use std::collections::BTreeMap;

/// Where a Swift succession stands, from the account's verified state and clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveStage {
    /// The genesis claims a predecessor, and no successor entry has left the account with
    /// `headQuorum` homes: the window has not opened (§15.1 step 2).
    WindowNotOpen,
    /// The window is open and the succession is not yet due: it may still be vetoed until the
    /// deadline.
    Waiting,
    /// The succession is due and not vetoed: F may be written.
    Due,
    /// F is built and held by this account but the succession is not verified yet (the homes'
    /// fresh heads are missing). F is never built a second time.
    Frozen,
    /// The succession is verified (F is written, the homes' fresh heads covered it at some
    /// moment). Once verified it stays verified (§15.1), however old the heads become.
    Verified,
    /// A valid veto is recorded: the succession is never verified.
    Vetoed,
    /// The `migration` entry is recorded.
    Migrated,
}

/// The succession this account claims, for the host and the person (§15.1 steps 2 and 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwiftSuccession {
    /// Where it stands now.
    pub stage: MoveStage,
    /// The verifier's facts: the predecessor, the head, the handover count, the window, the due
    /// time, the veto deadline, the predecessor keys that may veto and how many a veto needs.
    pub status: SuccessionStatus,
}

/// A prepared step of the move that is signed and then finished by [`Account::finish_move`].
#[derive(Debug)]
pub enum PendingMove {
    /// F, the freezing `layout` entry of the Swift predecessor.
    Freeze(PendingFreeze),
    /// The `migration` transition on the successor.
    Migration(PendingBatch),
    /// A shares-only `renew` (§9.4).
    Shares(PendingBatch),
}
impl PendingMove {
    /// What the host signs, in order.
    pub fn steps(&self) -> &[SigningStep] {
        match self {
            Self::Freeze(f) => f.steps(),
            Self::Migration(b) | Self::Shares(b) => b.steps(),
        }
    }
}

/// What a finished step of the move produced.
#[derive(Debug)]
pub enum Moved {
    /// F's exact Swift-format bytes. They go to the Swift side's append; the account takes them
    /// in with [`Account::accept_predecessor_entry`].
    Frozen(Frozen),
    /// The `migration` transition is held; it activates after its delay ([`Account::record_due`]).
    Migration(Box<Changes>),
    /// The shares-only `renew` is held.
    Shares(Box<Changes>),
}

/// The Swift entries of `all` up to `head_seq`, by their `seq`.
fn up_to(all: &[Vec<u8>], head_seq: u64) -> Vec<Vec<u8>> {
    let seq_of = |b: &Vec<u8>| -> Option<u64> {
        let env = strict_parse(b).ok()?;
        let body = decode_base64(env.get("body")?.as_str()?, 1_048_576).ok()?;
        strict_parse(&body).ok()?.get("seq")?.as_u64()
    };
    all.iter()
        .filter(|b| seq_of(b).is_some_and(|n| n <= head_seq))
        .cloned()
        .collect()
}

impl Account {
    /// §16.1: prepare the in-place `upgrade` of a 0.4 account whose `authority/*.json` records
    /// are `history`. A 0.4 account is not yet an `Account` (a plain 0.4 history is not a 0.5
    /// history), so this takes no `self`; open the account over the entries plus the one this
    /// returns once it is finished. See `write::upgrade::prepare_upgrade` for the refusals.
    pub fn begin_upgrade(
        history: &Legacy,
        params: &UpgradeParams,
        now_ms: i64,
    ) -> Result<PendingUpgrade> {
        prepare_upgrade(history, params, now_ms)
    }

    /// The stage of the Swift succession this account claims. Refused for an account with no
    /// predecessor, and for one whose predecessor is not Swift.
    pub fn swift_succession(&self) -> Result<SwiftSuccession> {
        let status = succession_status(self.d.auth.state())
            .ok_or_else(|| malformed("this account has no predecessor"))?;
        require(
            status.format == crate::v05::write::succession::SWIFT_FORMAT,
            "this account's predecessor is not a Swift library",
        )?;
        let stage = if self.d.auth.state().migration.is_some() {
            MoveStage::Migrated
        } else if status.vetoed {
            MoveStage::Vetoed
        } else if self.verified_ever(&status) {
            MoveStage::Verified
        } else if self.f_held(&status) {
            MoveStage::Frozen
        } else {
            match &status.timing {
                None => MoveStage::WindowNotOpen,
                Some(t) if self.now_ms >= t.due_ms => MoveStage::Due,
                Some(_) => MoveStage::Waiting,
            }
        };
        Ok(SwiftSuccession { stage, status })
    }

    /// §15.1: "a verifier that has persisted a verified succession keeps it". The account derives
    /// that from its held objects instead of a stored flag: the succession is verified if it
    /// verifies now, or verified at the moment any held head was issued (heads only age; F, the
    /// receipts and the history they covered are held for ever). A recorded veto overrides.
    fn verified_ever(&self, status: &SuccessionStatus) -> bool {
        if status.verified.is_some() {
            return true;
        }
        if status.vetoed {
            return false;
        }
        let mut times: Vec<i64> = self
            .objects
            .heads
            .iter()
            .filter_map(|h| {
                let env = strict_parse(h).ok()?;
                let body = decode_base64(env.get("body")?.as_str()?, 65_536).ok()?;
                parse_date(strict_parse(&body).ok()?.get("issued")?.as_str()?)
            })
            .collect();
        times.sort_unstable();
        times.dedup();
        times.into_iter().rev().take(64).any(|t| {
            verify_history(&self.objects, &Persisted::default(), t)
                .state
                .and_then(|st| succession_status(&st))
                .is_some_and(|s| s.verified.is_some())
        })
    }

    /// The account already holds an F that names it (built here or appended by the Swift side).
    fn f_held(&self, status: &SuccessionStatus) -> bool {
        swift::verify(&self.objects.predecessor)
            .ok()
            .and_then(|h| h.entries.get(status.head_seq as usize).cloned())
            .is_some_and(|e| e.value["successor"] == self.d.auth.account().as_str())
    }

    fn stage_is(&self, allowed: &[MoveStage], why: &str) -> Result<SwiftSuccession> {
        let s = self.swift_succession()?;
        if allowed.contains(&s.stage) {
            Ok(s)
        } else {
            Err(malformed(format!("{why}: the succession is {:?}", s.stage)))
        }
    }

    /// §15.1 step 3: the owner's veto of this account's succession, signed by predecessor keys
    /// under their Swift descriptors. Refused outside the wait (before the window opens, after
    /// the due time, after F or a recorded veto), for a key that is not eligible, and for fewer
    /// keys than the `handover` had.
    pub fn begin_swift_veto(&self, params: &SwiftVetoParams) -> Result<PendingSwiftVeto> {
        self.stage_is(&[MoveStage::Waiting], "a veto is made during the wait")?;
        prepare_swift_veto(&self.objects, self.now_ms, params)
    }

    /// §15.1 step 5: prepare F. `signers` are predecessor controller IDs. Refused before the
    /// succession is due (and by the builder for every other reason it names: a held valid veto,
    /// fewer receipts than `headQuorum`, signers below the Swift `layout` rule).
    pub fn begin_swift_freeze(
        &self,
        earlier_attempts: Vec<Objects>,
        signers: Vec<String>,
        issued_ms: i64,
    ) -> Result<PendingMove> {
        let s = self.stage_is(
            &[MoveStage::Due],
            "F is written once the succession is due, and only once",
        )?;
        let p = prepare_swift_freeze(
            &SwiftFreezeParams {
                predecessor: up_to(&self.objects.predecessor, s.status.head_seq),
                successor: self.objects.clone(),
                issued_ms,
                signers,
                earlier_attempts,
            },
            self.now_ms,
        )?;
        Ok(PendingMove::Freeze(p))
    }

    /// Take F (or any predecessor entry) the Swift side wrote into the account's predecessor
    /// objects. The verifier then judges the succession over it.
    pub fn accept_predecessor_entry(&mut self, entry: Vec<u8>, now_ms: i64) -> Result<Changes> {
        self.merge(
            Incoming {
                objects: Objects {
                    predecessor: vec![entry],
                    ..Objects::default()
                },
                records: Vec::new(),
            },
            now_ms,
        )
    }

    /// §15.3 step 3 and 5: one import write of a copy plan, by this session's member, who must
    /// hold the `import` term (§9.3). Refused until the succession is verified (the predecessor
    /// is frozen: nothing more is written there), for an item the plan does not hold pending,
    /// and for a session that is not a member with `import`. The returned write carries its
    /// item: it can be finished only as that item.
    pub fn begin_swift_copy_write(
        &self,
        plan: &CopyPlan,
        item: &CopyItem,
        seed: [u8; 32],
    ) -> Result<CopyWrite> {
        self.stage_is(
            &[MoveStage::Verified],
            "records are copied after F, once the succession is verified",
        )?;
        require(
            self.swift_succession()?.status.predecessor == plan.library(),
            "the plan is for another predecessor library",
        )?;
        require(
            plan.is_pending(item),
            "that is not a pending write of this plan",
        )?;
        let me = match &self.me {
            super::Identity::Member(id) => id.clone(),
            super::Identity::Controller(_) => {
                return Err(malformed("this session is a controller"))
            }
        };
        require(
            self.d.auth.member(&me).is_some_and(|m| m.terms.import()),
            "the copying member holds no `import` term (§9.3)",
        )?;
        let action = match self.begin_write(
            &item.namespace,
            crate::imports::BATCH_KIND,
            item.payload.clone(),
            Level::Write,
            seed,
        )? {
            Ok(a) => a,
            Err(d) => return Err(Failure::Unavailable(format!("{}: {}", d.reason, d.detail))),
        };
        let body_digest = digest(
            action
                .steps()
                .first()
                .ok_or_else(|| malformed("the write has no step"))?
                .body(),
        );
        Ok(CopyWrite {
            action,
            item: item.clone(),
            body_digest,
        })
    }

    /// Finish an import write as the item it was begun for. The finished header's body digest
    /// must be the one the host was asked to sign; the plan records it against its source, and
    /// when the destination does not take the batch (its own validator refuses it) the item is
    /// omitted `importInvalid` instead of counted. A failure changes nothing.
    pub fn finish_swift_copy_write(
        &mut self,
        plan: &mut CopyPlan,
        write: CopyWrite,
        signatures: Vec<SignatureResult>,
    ) -> Result<Finished> {
        let CopyWrite {
            action,
            item,
            body_digest,
        } = write;
        require(
            plan.is_pending(&item),
            "that is not a pending write of this plan",
        )?;
        let done = self.finish(action, signatures)?;
        let record = done
            .records
            .first()
            .ok_or_else(|| malformed("the finished write holds no header"))?;
        let (header, _) = OperationHeader::parse(&record.bytes)?;
        require(
            header.digest() == body_digest && header.namespace == item.namespace,
            "the signed write is not the one prepared for this item",
        )?;
        let taken = match self.query(&item.namespace, "importReceipt", json!({"key": item.key})) {
            Ok(crate::model::Outcome::Success { value, .. }) => !value.is_null(),
            _ => true,
        };
        if taken {
            plan.record_written(&item.source_digest, &header)?;
        } else {
            plan.record_omitted(
                &item.namespace,
                &item.source_digest,
                "importInvalid: the destination did not take the batch",
            )?;
        }
        Ok(done)
    }

    /// What this account's readable namespaces hold of the copy of `library`: every admitted
    /// `colophon.importBatch` whose evidence names it, with its destination header digest and
    /// whether the destination's import fold took it (`importReceipt`). A [`CopyPlan`] is rebuilt
    /// from this plus the predecessor, so an interrupted copy continues without duplicating or
    /// losing a record; [`CopyPlan::finish`] reconciles against it.
    pub fn swift_copy_destination(&self, library: &str) -> Result<Destination> {
        let mut digests: BTreeMap<String, String> = BTreeMap::new();
        for r in &self.records {
            if let Ok((h, _)) = OperationHeader::parse(&r.bytes) {
                digests.insert(h.id.clone(), h.digest());
            }
        }
        let mut batches = Vec::new();
        for ns in self.d.auth.namespaces().to_vec() {
            let Ok(crate::model::Outcome::Success { value: view, .. }) = self.view(&ns) else {
                continue;
            };
            for op in view.admitted {
                if op.kind != crate::imports::BATCH_KIND
                    || op.payload["evidence"]["sourceLibrary"] != library
                {
                    continue;
                }
                let (Some(dest), Some(key)) = (digests.get(&op.id), op.payload["key"].as_str())
                else {
                    continue;
                };
                let valid = matches!(
                    self.query(&ns, "importReceipt", json!({"key": key})),
                    Ok(crate::model::Outcome::Success { value, .. }) if value["publication"] == op.id
                );
                if let Some(b) = DestinationBatch::new(ns.clone(), dest.clone(), valid, op.payload)
                {
                    batches.push(b);
                }
            }
        }
        Ok(Destination::from_batches(batches))
    }

    /// Finish a copy: the plan reconciled with what this account actually holds (see
    /// [`CopyPlan::finish`]). The only way to a [`CopyResult`].
    pub fn finish_swift_copy(&self, plan: CopyPlan) -> Result<CopyResult> {
        let d = self.swift_copy_destination(plan.library())?;
        plan.finish(&d)
    }

    /// §9.4, shares only: seal the epochs a member is owed (the copying member, provisional when
    /// they were made) without touching its expiry.
    pub fn begin_swift_copier_shares(
        &self,
        member: &str,
        signers: &[String],
        seed: [u8; 32],
    ) -> Result<PendingMove> {
        Ok(PendingMove::Shares(prepare_renew_shares(
            &self.d.effective,
            self.now_ms,
            signers,
            self.now_ms,
            member,
            &self.d.keys,
            seed,
        )?))
    }

    /// §15.4: prepare the `migration` transition from a finished copy. `members` is each
    /// predecessor member's fate. Refused unless the succession is verified and no `migration` is
    /// recorded; the builder refuses counts that do not add up, a drain window before F, a
    /// member with a `budget` caveat that is not dropped, and every other reason it names.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_swift_migration(
        &self,
        copy: &CopyResult,
        members: Vec<MigratedMember>,
        drain_from_ms: i64,
        drain_until_ms: i64,
        issued_ms: i64,
        signers: Vec<String>,
    ) -> Result<PendingMove> {
        self.stage_is(
            &[MoveStage::Verified],
            "the migration is written after F and the copy",
        )?;
        let batch = prepare_migration(
            &self.objects,
            self.now_ms,
            &MigrationParams {
                predecessor: self.objects.predecessor.clone(),
                drain_from_ms,
                drain_until_ms,
                namespaces: copy.namespaces().to_vec(),
                omitted: copy.omitted().to_vec(),
                members,
                issued_ms,
                signers,
            },
        )?;
        Ok(PendingMove::Migration(batch))
    }

    /// Finish a step of the move with the host's signatures. F is returned as bytes **and held**:
    /// the account takes it into its predecessor objects at once, so it can never build a
    /// second, different F. The migration transition and the shares entry are merged. A failure
    /// changes nothing.
    pub fn finish_move(
        &mut self,
        pending: PendingMove,
        signatures: Vec<SignatureResult>,
    ) -> Result<Moved> {
        match pending {
            PendingMove::Freeze(f) => {
                let frozen = f.finish(signatures)?;
                self.accept_predecessor_entry(frozen.entry.clone(), self.now_ms)?;
                Ok(Moved::Frozen(frozen))
            }
            PendingMove::Migration(b) => {
                Ok(Moved::Migration(Box::new(self.merge_batch(b, signatures)?)))
            }
            PendingMove::Shares(b) => Ok(Moved::Shares(Box::new(self.merge_batch(b, signatures)?))),
        }
    }

    fn merge_batch(
        &mut self,
        b: PendingBatch,
        signatures: Vec<SignatureResult>,
    ) -> Result<Changes> {
        let r = b.finish(signatures)?;
        self.merge(
            Incoming {
                objects: Objects {
                    entries: r.entries.iter().map(|(_, e)| e.clone()).collect(),
                    pending: r.pending,
                    ..Objects::default()
                },
                records: Vec::new(),
            },
            self.now_ms,
        )
    }

    /// The Swift predecessor's verified history as this account holds it, for a host that shows
    /// the person the predecessor's last entries before they confirm (§15.1 step 3).
    pub fn swift_predecessor(&self) -> Result<swift::History> {
        swift::verify(&self.objects.predecessor)
    }
}

/// An import write begun for one item of a plan: it carries the item and the digest of the body
/// the host signs, so it can be finished only as that item.
pub struct CopyWrite {
    action: PendingAction,
    item: CopyItem,
    body_digest: String,
}
impl std::fmt::Debug for CopyWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CopyWrite({:?})", self.item)
    }
}
impl CopyWrite {
    /// What the host signs: the header body, signed raw by the copying member.
    pub fn steps(&self) -> &[SigningStep] {
        self.action.steps()
    }
    /// The item this write is for.
    pub fn item(&self) -> &CopyItem {
        &self.item
    }
}
