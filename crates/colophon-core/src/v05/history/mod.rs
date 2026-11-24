//! The authority history verifier (§8), following §8.7's state table.
//!
//! Sans-IO: [`verify_history`] takes the object set (entries, pending transitions, vetoes and
//! receipts, heads), the versioned folded state and retained objects of §17.2, and the
//! verifier's clock. The high-water mark detects rollback and never selects a branch. The verdict is a function of
//! those inputs only: it doesn't depend on the order of the objects (a property test checks
//! that), and nothing in this module reads a clock or storage.
//!
//! Succession inputs include the predecessor history through its final entry. The caller
//! supplies all receipts, fresh heads and clocks. No peer checkpoint is trusted.
pub mod envelope;
pub mod home;
pub mod keyring;
mod state;
pub(crate) mod succession;
pub mod swift;
pub(crate) mod upgrade;
pub mod work;

pub use state::{
    check_pending_transition, check_pending_veto, Activation, Claim, HomeStatus, MemberRecord,
    NotCurrent, Principal, State, Suspension,
};
pub(crate) use state::{check_pending_veto_with, check_transition, TCheck};
pub use succession::{succession_status, SuccessionStatus, SuccessionTiming};

use crate::v05::{Failure, Unknown};
use envelope::AuthEnvelope;
use std::collections::BTreeMap;

/// How a transition is timed at a state (§8.7 "Times"), for the builders of recording entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionTiming {
    /// The transition's body digest.
    pub digest: String,
    /// The transition's `by`.
    pub by: String,
    /// The signer units.
    pub units: Vec<String>,
    /// Its due time, in ms.
    pub due_ms: i64,
    /// Its veto deadline, in ms.
    pub deadline_ms: i64,
    /// A full set: not vetoable, due at its latest receipt.
    pub full_set: bool,
    /// Removal-only (§8.7).
    pub removal_only: bool,
}

/// Judge `transition` with its chosen `receipts` at state `s` (§8.7 "Validity of T at an
/// entry E") and report its timing. The same judgement `activate`, `vetoed` and `suspend`
/// make; any failure is that entry's failure.
pub fn transition_timing(
    s: &State,
    transition: &[u8],
    receipts: &[Vec<u8>],
) -> Result<TransitionTiming, Failure> {
    let t = state::check_transition(s, transition, receipts, true, true)?;
    Ok(TransitionTiming {
        digest: t.digest,
        by: t.by,
        units: t.units.into_iter().collect(),
        due_ms: t.due_ms,
        deadline_ms: t.deadline_ms,
        full_set: t.full_set,
        removal_only: t.removal_only,
    })
}

/// The homes whose receipts an entry recording the held `transition` in `s` need not carry: the
/// homes a full set revokes, as its witnesses leave them out (§8.7 validity 2); none otherwise.
pub(crate) fn transition_receipt_exempt(s: &State, transition: &[u8]) -> Vec<String> {
    state::transition_receipt_exempt(s, transition)
}

/// Check a held transition the way a home does before it receipts it: the transition's own
/// checks, its unknown content, that it is not already recorded, and that its delta would
/// apply at the head (a transition that would be void at activation is refused here).
pub fn check_admissible_transition(s: &State, transition: &[u8]) -> Result<(), Failure> {
    state::admission_transition(s, transition).map(|_| ())
}

/// Judge a receipt of `object` (issued at `object_issued_ms`) as the verifier does (§13.5): shape,
/// a current home's key, the object, the window. Returns the home and `received`. The write side
/// uses this one function, so a builder never treats a receipt differently from the verifier.
pub fn check_receipt(
    s: &State,
    bytes: &[u8],
    object: &str,
    object_issued_ms: i64,
) -> Result<(String, i64), Failure> {
    state::check_receipt(s, bytes, object, object_issued_ms)
}

/// The members a transition's `change` would add, judged as at activation in `s` with
/// `issued_ms` (§9.3 "A grant inside a transition"): the same function the verifier applies, so
/// the write side refuses at prepare what a verifier would find void.
pub(crate) fn check_transition_members(
    s: &State,
    change: &serde_json::Map<String, serde_json::Value>,
    issued_ms: i64,
) -> Result<(), Failure> {
    state::transition_members(s, change, s.seq() + 1, issued_ms).map(|_| ())
}

impl State {
    /// The `issued` of the last verified entry, in ms.
    pub fn last_issued_ms(&self) -> i64 {
        self.last_issued()
    }
}

/// What the verifier holds.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Objects {
    /// Authority entry envelopes, any order, possibly conflicting.
    pub entries: Vec<Vec<u8>>,
    /// Transitions, vetoes and receipts held outside the history.
    pub pending: Vec<Vec<u8>>,
    /// Head envelopes.
    pub heads: Vec<Vec<u8>>,
    /// Predecessor authority envelopes through F, supplied by the caller.
    #[serde(default)]
    pub predecessor: Vec<Vec<u8>>,
}

/// Locally trusted verifier state (§17.2). Persist atomically; never accept a checkpoint
/// supplied by a peer. The retained objects allow earlier conflicts to be reconsidered.
#[derive(Clone, Debug, Default)]
pub struct Persisted {
    /// The highest accepted `(seq, digest)`.
    pub high_water: Option<(u64, String)>,
    checkpoint: Option<Checkpoint>,
    /// Per home member ID, the highest `(seq, digest)` of a head accepted from it (§13.3).
    head_marks: BTreeMap<String, (u64, String)>,
    /// This verifier saw the succession verified (§15.1: "a verifier that has persisted a
    /// verified succession keeps it"): never re-derived, never lost when heads age.
    succession_verified: bool,
    /// The stop this verifier once verified for the account (§1 "A stop"): `(seq, layout)`. A floor,
    /// as the head marks are: local memory that evidence going missing never undoes.
    stop_floor: Option<(u64, Option<u64>)>,
    /// This build folded the checkpoint's state from the genesis of its own objects, under these
    /// rules ([`FOLD_RULES`]; directly, or by resuming a checkpoint that was). Never stored in the
    /// checkpoint: a checkpoint read from bytes may have been written by another verifier, so it
    /// is not known until it is rebuilt or verified again, or a host proves it for those exact
    /// bytes (`HomeState::vouch_fold`).
    folded_here: bool,
}

/// Checkpoint format. 2 added `held_until`; 3 added the successor fields; 4 added the per-home
/// head high-water marks and the fork a `resolve` names; 6 (E12) holds in the state's `points`
/// every key a transition or vault rotation added, which a format-5 state lacks; 7 (the freeze
/// package) holds the state's `layout` and the seq at which the reader is stopped (§1 "A stop").
/// A checkpoint of another format is refused, and the caller rebuilds it from its retained objects.
const CHECKPOINT_VERSION: u32 = 7;

/// The verification rules this build folds a history by. A host that keeps a checkpoint across
/// processes may store it beside the checkpoint as part of its proof that this build folded that
/// checkpoint from genesis ([`Persisted::folded_here`]); a checkpoint stored with another value,
/// or with none, is not taken as this build's fold until it is verified again. (The home module
/// also binds its proof to the SHA-256 of the module it runs as, so a rebuilt module verifies its
/// checkpoints again even where this value did not change.)
///
/// **Change it whenever a verdict can change**: any change to what an entry, a transition, a veto,
/// a receipt, a head or a predecessor is judged to be, to how a conflict or a fork is decided, or
/// to what the folded state holds, even where the checkpoint format stays the same. Raise the
/// revision (`r1` → `r2`) for a change in code; nothing checks that, so it is the author's to do.
/// The digest after it is that of the conformance vectors of the history verifier
/// (`conformance/0.5/{rules,upgrade,succession}`): the test
/// `the_fold_rules_name_the_conformance_vectors` fails until it is updated when any of their files
/// changes, which catches a rule change that changes a vector, not one that changes only code.
pub const FOLD_RULES: &str = "colophon-0.5-fold/r1/ba2e2d0905d50136";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Checkpoint {
    version: u32,
    now_ms: i64,
    state: Option<State>,
    objects: Objects,
    conflicts: bool,
    /// Earliest time a candidate held at a decided seq comes due (format 2).
    held_until: Option<i64>,
    high_water: Option<(u64, String)>,
    /// Per home, the highest accepted head (format 4).
    head_marks: BTreeMap<String, (u64, String)>,
    /// The succession was seen verified (additive: absent means not seen).
    #[serde(default)]
    succession_verified: bool,
    /// The seq at which the verdict stopped the reader (format 7, [`Verdict::stopped`]).
    stopped: Option<u64>,
    /// The stop this verifier once verified, kept as a floor (additive: absent means none).
    #[serde(default)]
    stop_floor: Option<(u64, Option<u64>)>,
}

impl Persisted {
    /// A rollback marker without a folded state.
    pub fn high_water(seq: u64, digest: String) -> Self {
        Self {
            high_water: Some((seq, digest)),
            checkpoint: None,
            head_marks: BTreeMap::new(),
            succession_verified: false,
            stop_floor: None,
            folded_here: false,
        }
    }

    /// The seq at which the checkpointed verdict stopped the reader (§1 "A stop",
    /// [`Verdict::stopped`]), so a host that reads its checkpoint before replaying can refuse
    /// to build and answer nothing new.
    pub fn stopped(&self) -> Option<u64> {
        self.checkpoint.as_ref().and_then(|cp| cp.stopped)
    }

    /// Whether this verifier saw its account's succession verified (§15.1).
    pub fn succession_verified(&self) -> bool {
        self.succession_verified
    }
    /// The stop this verifier once verified for the account, `(seq, layout)` (§1 "A stop"): a floor
    /// that holds even when the evidence of the raise is no longer held. Never cleared.
    pub fn stop_floor(&self) -> Option<(u64, Option<u64>)> {
        self.stop_floor
    }
    /// Record a verified stop as the floor. Monotone: the first stop recorded stays.
    pub fn with_stop_floor(mut self, seq: u64, layout: Option<u64>) -> Self {
        if self.stop_floor.is_none() {
            self.stop_floor = Some((seq, layout));
        }
        self
    }
    /// Record that the succession was seen verified. Monotone: never cleared.
    pub fn with_succession_verified(mut self) -> Self {
        self.succession_verified = true;
        self
    }

    /// This verifier's high-water mark for `home`: the highest head `(seq, digest)` it accepted.
    pub fn head_mark(&self, home: &str) -> Option<(u64, &str)> {
        self.head_marks.get(home).map(|(s, d)| (*s, d.as_str()))
    }

    /// Set the mark for `home` (the verifier's own storage; never taken from a peer).
    pub fn with_head_mark(mut self, home: &str, seq: u64, digest: &str) -> Self {
        self.head_marks.insert(home.into(), (seq, digest.into()));
        self
    }

    /// Verify a head (§13.3) against the held history and this verifier's mark for its home,
    /// without recording it: a head behind the mark is `refused:rollback`.
    pub fn check_head(
        &self,
        envelope: &[u8],
        ctx: crate::v05::heads::HeadContext<'_>,
    ) -> crate::v05::Result<crate::v05::heads::Head> {
        let by = crate::v05::heads::head_by(envelope);
        let mark = by.as_deref().and_then(|b| self.head_mark(b));
        crate::v05::heads::verify_head_with_mark(envelope, ctx, mark)
    }

    /// [`Persisted::check_head`], then raise the mark for the head's home when it is higher.
    /// Persist the result with the checkpoint.
    pub fn accept_head(
        &mut self,
        envelope: &[u8],
        ctx: crate::v05::heads::HeadContext<'_>,
    ) -> crate::v05::Result<crate::v05::heads::Head> {
        let head = self.check_head(envelope, ctx)?;
        let higher = self
            .head_marks
            .get(head.by())
            .is_none_or(|(seq, _)| head.seq() > *seq);
        if higher {
            self.head_marks.insert(
                head.by().to_string(),
                (head.seq(), head.digest().to_string()),
            );
        }
        Ok(head)
    }

    /// Save a verdict and the exact objects used to obtain it. Verification is repeated here
    /// so callers cannot accidentally pair a folded state with a different object set.
    pub fn checkpoint(objects: &Objects, previous: &Self, now_ms: i64) -> Self {
        let all = merged_objects(objects, previous);
        work::verification();
        let (verdict, resumed) = match resume_unchanged(objects, previous, now_ms) {
            Some(v) => (v, true),
            None => replay_resumed(objects, previous, now_ms),
        };
        let high_water = previous
            .high_water
            .clone()
            .filter(|(seq, _)| *seq >= verdict.branch.len() as u64)
            .or_else(|| {
                verdict
                    .branch
                    .last()
                    .map(|d| (verdict.branch.len() as u64, d.clone()))
            });
        Self {
            high_water: high_water.clone(),
            head_marks: previous.head_marks.clone(),
            succession_verified: previous.succession_verified,
            stop_floor: previous.stop_floor,
            folded_here: !resumed || previous.folded_here,
            checkpoint: Some(Checkpoint {
                version: CHECKPOINT_VERSION,
                now_ms,
                state: verdict.state,
                objects: all,
                conflicts: !verdict.conflicts.is_empty()
                    || matches!(verdict.stop, Some(Stop::Fork { .. })),
                held_until: verdict.held_until,
                high_water,
                head_marks: previous.head_marks.clone(),
                succession_verified: previous.succession_verified,
                stopped: verdict.stopped,
                stop_floor: previous.stop_floor,
            }),
        }
    }

    /// Serialize a locally trusted checkpoint, including its format version.
    pub fn to_bytes(&self) -> crate::v05::Result<Vec<u8>> {
        let cp = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| crate::v05::malformed("no folded checkpoint"))?;
        let mut cp = cp.clone();
        cp.high_water = self.high_water.clone();
        cp.head_marks = self.head_marks.clone();
        cp.succession_verified = self.succession_verified;
        cp.stop_floor = self.stop_floor;
        serde_json::to_vec(&cp).map_err(|e| crate::v05::malformed(e.to_string()))
    }

    /// Restore bytes from the caller's trusted storage, never from the network.
    pub fn from_bytes(bytes: &[u8]) -> crate::v05::Result<Self> {
        let cp: Checkpoint =
            serde_json::from_slice(bytes).map_err(|e| crate::v05::malformed(e.to_string()))?;
        crate::v05::require(
            cp.version == CHECKPOINT_VERSION,
            "unknown checkpoint version",
        )?;
        if let Some(state) = &cp.state {
            state.check_checkpoint_shape()?;
        }
        check_head_marks(&cp.head_marks)?;
        Ok(Self {
            high_water: cp.high_water.clone(),
            head_marks: cp.head_marks.clone(),
            succession_verified: cp.succession_verified,
            stop_floor: cp.stop_floor,
            folded_here: false,
            checkpoint: Some(cp),
        })
    }

    /// Rebuild a checkpoint from retained objects after a format change or a refused checkpoint,
    /// **carrying over the head marks** of `old` (§17.2): marks are local memory that no replay
    /// can recompute, so they are read from the old bytes of any format, ignoring what does not
    /// parse or fails the shape check. Never call this with bytes from a peer.
    pub fn rebuild(objects: &Objects, old: &[u8], now_ms: i64) -> Self {
        let marks = serde_json::from_slice::<serde_json::Value>(old)
            .ok()
            .and_then(|v| v.get("head_marks").cloned())
            .and_then(|m| serde_json::from_value::<BTreeMap<String, (u64, String)>>(m).ok())
            .filter(|m| check_head_marks(m).is_ok())
            .unwrap_or_default();
        let kept = serde_json::from_slice::<serde_json::Value>(old)
            .ok()
            .and_then(|v| {
                v.get("succession_verified")
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false);
        let floor = serde_json::from_slice::<serde_json::Value>(old)
            .ok()
            .and_then(|v| v.get("stop_floor").cloned())
            .and_then(|f| serde_json::from_value::<Option<(u64, Option<u64>)>>(f).ok())
            .flatten();
        let previous = Self {
            head_marks: marks,
            succession_verified: kept,
            stop_floor: floor,
            ..Self::default()
        };
        Self::checkpoint(objects, &previous, now_ms)
    }

    /// Objects retained for rollback, conflict reconsideration and call-view construction.
    pub fn objects(&self) -> Option<&Objects> {
        self.checkpoint.as_ref().map(|cp| &cp.objects)
    }

    /// Whether this build's verifier folded the checkpoint's state from the genesis of its own
    /// objects ([`FOLD_RULES`]), directly or by resuming a checkpoint that it folded. Clear for
    /// a checkpoint read from bytes, until [`Persisted::verified_again`] or a host's own proof
    /// for those exact bytes says otherwise.
    pub fn folded_here(&self) -> bool {
        self.folded_here
    }

    /// This verifier's local memory without the checkpoint: the high-water mark, the head marks,
    /// the succession flag and the stop floor, which no replay recomputes. [`verify_history`] over
    /// the checkpoint's objects with it is the replay from genesis, with nothing saved resumed.
    pub fn without_fold(&self) -> Self {
        Self {
            high_water: self.high_water.clone(),
            checkpoint: None,
            head_marks: self.head_marks.clone(),
            succession_verified: self.succession_verified,
            stop_floor: self.stop_floor,
            folded_here: false,
        }
    }

    /// Take this checkpoint as this build's fold. Only for a caller holding proof, made by this
    /// build for these exact checkpoint bytes, that it is (`HomeState::vouch_fold`).
    pub(crate) fn assume_folded_here(&mut self) {
        self.folded_here = true;
    }

    /// This checkpoint, taken as this build's fold, when it was read from `stored` and a replay
    /// of its own objects from genesis at the checkpoint's clock, with the same local memory
    /// (high-water mark, head marks, succession flag, stop floor), serializes to exactly `stored`,
    /// byte for byte. `None` when it holds no fold or anything differs: a fold an older verifier
    /// made under other rules, or the same checkpoint written in another form (other spacing or
    /// key order, a field this build does not read).
    pub fn verified_again(&self, stored: &[u8]) -> Option<Self> {
        let cp = self.checkpoint.as_ref()?;
        let memory = Self {
            head_marks: self.head_marks.clone(),
            succession_verified: self.succession_verified,
            stop_floor: self.stop_floor,
            ..Self::default()
        };
        let mut again = Self::checkpoint(&cp.objects, &memory, cp.now_ms);
        again.high_water = self.high_water.clone();
        let same = again.folded_here && again.to_bytes().is_ok_and(|a| a == stored);
        same.then(|| {
            let mut vouched = self.clone();
            vouched.folded_here = true;
            vouched
        })
    }
}

/// Head marks are local storage, so this is corruption detection: member IDs, seqs and digests of
/// the right shape, and a bounded count (§8.7 allows 8 homes; marks of revoked homes may linger).
fn check_head_marks(marks: &BTreeMap<String, (u64, String)>) -> crate::v05::Result<()> {
    let hex = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    crate::v05::require(
        marks.len() <= 64
            && marks.iter().all(|(home, (seq, digest))| {
                hex(home, 32)
                    && (1..=crate::v05::encoding::bounds::MAX_INTEGER).contains(seq)
                    && hex(digest, 64)
            }),
        "invalid head marks",
    )
}

fn merged_objects(objects: &Objects, persisted: &Persisted) -> Objects {
    let mut all = persisted.objects().cloned().unwrap_or_default();
    for (dst, src) in [
        (&mut all.entries, &objects.entries),
        (&mut all.pending, &objects.pending),
        (&mut all.heads, &objects.heads),
        (&mut all.predecessor, &objects.predecessor),
    ] {
        let mut seen: std::collections::BTreeSet<Vec<u8>> = dst.iter().cloned().collect();
        for bytes in src {
            if seen.insert(bytes.clone()) {
                dst.push(bytes.clone());
            }
        }
    }
    all
}

/// Why verification stopped before the end of the branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The entry at `seq` failed with `failure`.
    Failed {
        /// Seq of the failing entry.
        seq: u64,
        /// The §8.5 result.
        failure: Failure,
    },
    /// The entry at `seq` is held.
    Held {
        /// Seq of the held entry.
        seq: u64,
        /// Why.
        why: String,
    },
    /// An unresolved fork at `seq` (§8.6 rule 3).
    Fork {
        /// Seq of the conflict.
        seq: u64,
    },
}

/// The verdict over an object set.
#[derive(Clone, Debug)]
pub struct Verdict {
    /// The verified branch: body digests from seq 1.
    pub branch: Vec<String>,
    /// The folded state at the last verified entry (absent when the genesis failed).
    pub state: Option<State>,
    /// Why verification stopped, if it did before the branch ended.
    pub stop: Option<Stop>,
    /// The persisted high-water mark is not on this branch, or beyond it (§13.3).
    pub rollback: bool,
    /// Conflicts decided by §8.6, as `(seq, standing digest, losing digests)`.
    pub conflicts: Vec<(u64, String, Vec<String>)>,
    /// The earliest clock time at which a candidate that was held at an already decided seq
    /// is judged again (§8.1, §17.2). A resumed verifier replays once the clock reaches it.
    pub held_until: Option<i64>,
    /// `Some(seq)` when the reader is **stopped** for the account (§1 "A stop"): its verdict on
    /// the authority entry at `seq` is `newerFormat` (its verified history ends before it), or the
    /// activation at `seq` raised the layout above 2 and is final on the verified branch (the
    /// branch runs through the entry that made it final; nothing after is applied). A raise that
    /// is still provisional stops nothing. A stopped reader trusts nothing new: every call it
    /// verifies is `unavailable`
    /// whatever seq the call names (§12.3 step 4), it accepts no head (§13.3), admits no record
    /// or live candidate it had not admitted before the stop (each is held, §11.5), answers no
    /// question of currency, membership or access, and its host builds nothing. What it showed
    /// before may stay on screen, marked as from a stopped account. A home follows §13.6.
    /// Derived from [`Verdict::stop`]; [`Persisted`] carries it in the checkpoint.
    pub stopped: Option<u64>,
}
impl Verdict {
    /// True when the reader is stopped for the account ([`Verdict::stopped`], §1 "A stop").
    pub fn is_stopped(&self) -> bool {
        self.stopped.is_some()
    }
    /// The §1 result code of the verification: `ok`, `held`, `refused:fork` or a failure's.
    pub fn code(&self) -> String {
        match &self.stop {
            None => "ok".into(),
            Some(Stop::Failed { failure, .. }) => failure.code(),
            Some(Stop::Held { .. }) => "held".into(),
            Some(Stop::Fork { .. }) => "refused:fork".into(),
        }
    }
    /// The seq the code refers to: the stopping entry, or the last verified seq.
    pub fn seq(&self) -> u64 {
        match &self.stop {
            Some(Stop::Failed { seq, .. })
            | Some(Stop::Held { seq, .. })
            | Some(Stop::Fork { seq }) => *seq,
            None => self.branch.len() as u64,
        }
    }
}

/// A parsed entry with its header.
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub env: AuthEnvelope,
    pub seq: u64,
    pub previous: Option<String>,
    pub issued: i64,
    pub by: String,
    pub kind: String,
    pub size: usize,
    /// The exact envelope bytes: several envelopes over one body are one object (§2.2), and
    /// the verifier judges them in byte order.
    pub raw: Vec<u8>,
}

fn parse_entry(bytes: &[u8]) -> Result<Entry, Failure> {
    use crate::v05::encoding::bounds::AUTHORITY_BODY;
    let env = AuthEnvelope::parse(
        bytes,
        AUTHORITY_BODY,
        AUTHORITY_BODY.saturating_mul(2),
        false,
    )?;
    let (h, _) = crate::v05::members::AuthorityHeader::split(env.value.clone())?;
    if h.protocol != "colophon/authority/5" {
        return Err(if h.protocol == "colophon/authority/4" {
            crate::v05::malformed("a /4 entry outside the upgrade prefix")
        } else {
            crate::v05::malformed("not a colophon/authority/5 entry")
        });
    }
    Ok(Entry {
        raw: bytes.to_vec(),
        size: env.body.len(),
        env,
        seq: h.seq,
        previous: h.previous,
        issued: h.issued.1,
        by: h.by,
        kind: h.kind,
    })
}

/// Verify an account's history from its object set, the persisted state and the clock.
pub fn verify_history(objects: &Objects, persisted: &Persisted, now_ms: i64) -> Verdict {
    work::verification();
    if let Some(verdict) = resume_unchanged(objects, persisted, now_ms) {
        return verdict;
    }
    replay_resumed(objects, persisted, now_ms).0
}

/// [`verify_history`] without its shortcut for an unchanged checkpoint
/// ([`resumes_unchanged`]), for tests that compare the two. Never needed otherwise.
#[doc(hidden)]
pub fn verify_history_in_full(objects: &Objects, persisted: &Persisted, now_ms: i64) -> Verdict {
    replay_resumed(objects, persisted, now_ms).0
}

/// Whether [`verify_history`] answers from the checkpoint alone: the checkpoint
/// is this build's fold ([`Persisted::folded_here`]), nothing comes in, and it holds a quiet state
/// (no conflict, held candidate or stop, no `/4` prefix or predecessor, one entry per verified
/// seq) at a clock not behind it. Its verdict is then a replay's from genesis of the checkpoint's
/// objects at `now_ms`.
pub fn resumes_unchanged(objects: &Objects, persisted: &Persisted, now_ms: i64) -> bool {
    resume_point(objects, persisted, now_ms).is_some()
}

/// The checkpointed state [`replay_resumed`] would resume from and fold nothing onto, when that is
/// certain without reading a held object: this process folded the checkpoint itself
/// (`Persisted::folded_here`), nothing comes in with the call (no entry, pending
/// object, head or predecessor entry), the checkpoint holds a state at no conflict, no held
/// candidate and no stop, the clock has not gone back from it, the account neither upgraded
/// in place nor claims a predecessor, and the checkpoint holds exactly one entry per verified
/// seq.
///
/// Every state a checkpoint holds was verified from the objects it holds (they are merged into
/// it before the verdict is taken, and none is ever dropped), so each verified seq has at least
/// one held entry, the one whose digest the history names. That holds for checkpoints this process
/// folded; one read from bytes may come from another verifier, or be inconsistent, and is never
/// taken here until it is rebuilt. With as many entries as seqs, every
/// held entry is that entry: none sits beyond the history, none fails to parse, and none is a
/// `/4` genesis. [`replay_resumed`] would then resume from the checkpoint's state (the conditions of its
/// own fast path hold), find no candidate after it, and leave it as it is: no `/4` prefix to
/// bootstrap, no succession to finish. What it adds (the rollback mark, a final layout raise)
/// is added here the same way.
fn resume_point<'a>(objects: &Objects, persisted: &'a Persisted, now_ms: i64) -> Option<&'a State> {
    let cp = persisted.checkpoint.as_ref()?;
    let saved = cp.state.as_ref()?;
    let quiet = persisted.folded_here
        && objects.entries.is_empty()
        && objects.pending.is_empty()
        && objects.heads.is_empty()
        && objects.predecessor.is_empty()
        && !cp.conflicts
        && cp.held_until.is_none()
        && cp.stopped.is_none()
        && persisted.stop_floor.is_none()
        && now_ms >= cp.now_ms
        && saved.upgrade_seq.is_none()
        && saved.succession.is_none()
        && cp.objects.entries.len() == saved.history().len();
    quiet.then_some(saved)
}

/// [`verify_history`] from an unchanged checkpoint ([`resume_point`]): the verdict [`replay_resumed`]
/// gives there, without parsing the held objects.
fn resume_unchanged(objects: &Objects, persisted: &Persisted, now_ms: i64) -> Option<Verdict> {
    let saved = resume_point(objects, persisted, now_ms)?;
    let mut verdict = Verdict {
        branch: saved.history().to_vec(),
        state: None,
        stop: None,
        rollback: false,
        conflicts: Vec::new(),
        held_until: None,
        stopped: None,
    };
    let mut st = saved.clone();
    st.prepared = crate::v05::signature::PreparedKeys::default();
    let st = Some(st);
    finish_verdict(&mut verdict, st, persisted);
    Some(verdict)
}

/// What [`replay_resumed`] does after its fold, apart from the succession: the rollback mark against
/// the persisted high water, a final layout raise as the stop, and the state.
fn finish_verdict(verdict: &mut Verdict, st: Option<State>, persisted: &Persisted) {
    if let Some((hw_seq, hw_digest)) = &persisted.high_water {
        let on_branch = usize::try_from(hw_seq.saturating_sub(1))
            .ok()
            .and_then(|i| verdict.branch.get(i));
        verdict.rollback = on_branch != Some(hw_digest);
    }
    // A final layout raise on the verified branch stops the reader at the raising activation,
    // whatever entry follows it (§1 "A stop", §20). The branch and the state run through the
    // entry that made the raise final; the stop names the raise.
    if let Some(r) = st.as_ref().and_then(State::stopped_at) {
        verdict.stop = Some(Stop::Failed {
            seq: r,
            failure: Failure::NewerFormat(format!(
                "the account raised its layout above 2 at seq {r}, and that is final"
            )),
        });
    }
    verdict.state = st;
    verdict.stopped = stopped_at(&verdict.stop);
}

/// The verifier: every held object parsed and the history folded, resuming from the checkpoint
/// where that is safe. Also says whether it resumed the checkpoint's state.
fn replay_resumed(objects: &Objects, persisted: &Persisted, now_ms: i64) -> (Verdict, bool) {
    work::replay();
    let incoming = objects;
    let all_objects = merged_objects(objects, persisted);
    let objects = &all_objects;
    // Parse every entry; group candidates by (seq, previous). Unparseable entries are kept as
    // failures at their seq when nothing valid stands there.
    let mut by_seq: BTreeMap<u64, Vec<Result<Entry, Failure>>> = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut parse_failures: BTreeMap<u64, (String, Failure)> = BTreeMap::new();
    for bytes in &objects.entries {
        match parse_entry(bytes) {
            Ok(e) => {
                // One body under several envelopes is one object (§2.2); every envelope is
                // kept and judged, in byte order, so that a keyless envelope over a real
                // body can never stand in for it.
                if seen.insert(bytes.clone()) {
                    by_seq.entry(e.seq).or_default().push(Ok(e));
                }
            }
            Err(f) => {
                // Position from the raw body when the header doesn't parse. Several failures at
                // one seq: the one with the lowest envelope digest, so input order never matters.
                let seq = state::raw_seq(bytes).unwrap_or(0);
                let d = crate::v05::encoding::digest(bytes);
                match parse_failures.get(&seq) {
                    Some((old, _)) if old <= &d => {}
                    _ => {
                        parse_failures.insert(seq, (d, f));
                    }
                }
            }
        }
    }
    // Sort candidates at each seq by body digest so iteration never depends on input order.
    for list in by_seq.values_mut() {
        list.sort_by(|a, b| match (a, b) {
            (Ok(x), Ok(y)) => (&x.env.digest, &x.raw).cmp(&(&y.env.digest, &y.raw)),
            _ => std::cmp::Ordering::Equal,
        });
    }
    let pending = state::Pending::parse(&objects.pending);
    let heads = state::HeadSet::parse(&objects.heads);
    let mut verdict = Verdict {
        branch: Vec::new(),
        state: None,
        stop: None,
        rollback: false,
        conflicts: Vec::new(),
        held_until: None,
        stopped: None,
    };
    let mut st: Option<State> = None;
    let mut resumed = false;
    if let Some(result) = upgrade::bootstrap(objects, now_ms) {
        match result {
            Ok(saved) => {
                verdict.branch = saved.history().to_vec();
                st = Some(saved);
            }
            Err(stop) => {
                verdict.stop = Some(stop);
                verdict.stopped = stopped_at(&verdict.stop);
                return (verdict, false);
            }
        }
    }
    // Fast path: append to the verified folded state. An earlier candidate, new head,
    // prior conflict, or backwards clock requires replay of the retained objects. In
    // particular a high-water marker never freezes a provisional branch. Nor does a candidate
    // held beside a valid one: a fold resumed past it would not visit it again, so its due time
    // would be lost from the checkpoint the resumed verdict makes, and with it the replay that
    // judges the candidate once it is due.
    if let Some(cp) = &persisted.checkpoint {
        if let Some(saved) = &cp.state {
            let retained: std::collections::BTreeSet<&Vec<u8>> =
                cp.objects.entries.iter().collect();
            let safe = !cp.conflicts
                && cp.held_until.is_none()
                && now_ms >= cp.now_ms
                && incoming
                    .predecessor
                    .iter()
                    .all(|h| cp.objects.predecessor.contains(h))
                && incoming.heads.iter().all(|h| cp.objects.heads.contains(h))
                && incoming.entries.iter().all(|b| {
                    retained.contains(b)
                        || parse_entry(b).is_ok_and(|e| e.seq > saved.history().len() as u64)
                });
            if safe {
                verdict.branch = saved.history().to_vec();
                st = Some(saved.clone());
                resumed = true;
            }
        }
    }
    let prepared = crate::v05::signature::PreparedKeys::default();
    if let Some(s) = &mut st {
        s.prepared = prepared.clone();
    }
    let folder = Folder {
        prepared,
        by_seq: &by_seq,
        parse_failures: &parse_failures,
        pending: &pending,
        heads: &heads,
        predecessor: &objects.predecessor,
        now_ms,
    };
    let mut st = folder.run(st, &mut verdict, true);
    // Finishing the succession changes only the state, so the rollback mark, which reads the
    // branch, is the same whether it is set before or after.
    if !matches!(verdict.stop, Some(Stop::Fork { .. })) {
        if let Some(s) = &mut st {
            succession::finish(s, objects, now_ms);
        }
    }
    finish_verdict(&mut verdict, st, persisted);
    (verdict, resumed)
}

/// §1 "A stop": the seq of the authority entry whose verdict is `newerFormat`.
fn stopped_at(stop: &Option<Stop>) -> Option<u64> {
    match stop {
        Some(Stop::Failed {
            seq,
            failure: Failure::NewerFormat(_),
        }) => Some(*seq),
        _ => None,
    }
}

/// What a fold over the held entries needs: the candidates by seq, the held objects and the clock.
struct Folder<'a> {
    prepared: crate::v05::signature::PreparedKeys,
    by_seq: &'a BTreeMap<u64, Vec<Result<Entry, Failure>>>,
    parse_failures: &'a BTreeMap<u64, (String, Failure)>,
    pending: &'a state::Pending,
    heads: &'a state::HeadSet,
    predecessor: &'a [Vec<u8>],
    now_ms: i64,
}

impl Folder<'_> {
    /// Extend `verdict.branch` (the verified prefix, whose folded state is `st`) as far as the
    /// held entries allow. With `lookahead`, an unresolved fork is first offered to the
    /// `resolve` activations on its branches (§8.6 rule 3).
    fn run(&self, mut st: Option<State>, verdict: &mut Verdict, lookahead: bool) -> Option<State> {
        let now_ms = self.now_ms;
        let mut seq = verdict.branch.len() as u64 + 1;
        loop {
            let prev = verdict.branch.last().cloned();
            let candidates: Vec<&Entry> = self
                .by_seq
                .get(&seq)
                .map(|l| {
                    l.iter()
                        .filter_map(|r| r.as_ref().ok())
                        .filter(|e| e.previous == prev)
                        .collect()
                })
                .unwrap_or_default();
            if candidates.is_empty() {
                if let Some((_, f)) = self.parse_failures.get(&seq) {
                    verdict.stop = Some(Stop::Failed {
                        seq,
                        failure: f.clone(),
                    });
                }
                break;
            }
            // Judge every candidate against the state before it. The envelopes over one body
            // are one candidate: it is valid when any of them is (the first in byte order that
            // verifies), and an envelope that does not verify is ignored. Only when none
            // verifies is the result that of the first.
            let mut valid: Vec<(&Entry, State)> = Vec::new();
            let mut first_failure: Option<(Stop, &Entry)> = None;
            let mut held_at: Option<i64> = None;
            let mut groups: Vec<Vec<&Entry>> = Vec::new();
            for e in &candidates {
                match groups.last_mut() {
                    Some(g) if g[0].env.digest == e.env.digest => g.push(e),
                    _ => groups.push(vec![e]),
                }
            }
            for group in &groups {
                let mut chosen_ok: Option<(&Entry, State)> = None;
                let mut first_result: Option<(&Entry, state::Outcome)> = None;
                for e in group {
                    let r = match &st {
                        None => state::genesis(e, now_ms, self.predecessor, &self.prepared),
                        Some(s) => state::apply(
                            s,
                            e,
                            self.pending,
                            self.heads,
                            by_seq_all(self.by_seq),
                            now_ms,
                        ),
                    };
                    match r {
                        Ok(next) => {
                            chosen_ok = Some((*e, next));
                            break;
                        }
                        Err(o) => {
                            if first_result.is_none() {
                                first_result = Some((*e, o));
                            }
                        }
                    }
                }
                if let Some(v) = chosen_ok {
                    valid.push(v);
                    continue;
                }
                match first_result {
                    Some((e, state::Outcome::Fail(f))) => {
                        if first_failure.is_none() {
                            first_failure = Some((Stop::Failed { seq, failure: f }, e));
                        }
                    }
                    Some((e, state::Outcome::Held(why))) => {
                        let t = state::release_time(st.as_ref(), e);
                        held_at = Some(held_at.map_or(t, |h| h.min(t)));
                        if first_failure.is_none()
                            || matches!(first_failure, Some((Stop::Failed { .. }, _)))
                        {
                            first_failure = Some((Stop::Held { seq, why }, e));
                        }
                    }
                    None => {}
                }
            }
            if !valid.is_empty() {
                if let Some(t) = held_at {
                    verdict.held_until = Some(verdict.held_until.map_or(t, |h| h.min(t)));
                }
            }
            let chosen = match valid.len() {
                0 => {
                    verdict.stop = first_failure.map(|(s, _)| s);
                    break;
                }
                1 => valid.pop(),
                _ => match &st {
                    Some(s) => {
                        let standing = state::resolve_conflict(
                            s,
                            &valid,
                            self.heads,
                            by_seq_all(self.by_seq),
                            self.pending,
                            now_ms,
                        )
                        .or_else(|| {
                            if lookahead {
                                self.resolved_by_activation(&valid, verdict, seq)
                            } else {
                                None
                            }
                        });
                        match standing {
                            Some(i) => {
                                let losers = valid
                                    .iter()
                                    .enumerate()
                                    .filter(|(j, _)| *j != i)
                                    .map(|(_, (e, _))| e.env.digest.clone())
                                    .collect();
                                verdict.conflicts.push((
                                    seq,
                                    valid[i].0.env.digest.clone(),
                                    losers,
                                ));
                                Some(valid.swap_remove(i))
                            }
                            None => {
                                verdict.stop = Some(Stop::Fork { seq });
                                break;
                            }
                        }
                    }
                    None => {
                        verdict.stop = Some(Stop::Fork { seq });
                        break;
                    }
                },
            };
            let Some((e, next)) = chosen else { break };
            verdict.branch.push(e.env.digest.clone());
            st = Some(next);
            seq += 1;
        }
        st
    }

    /// §8.6 rule 3: a fork stays unresolved "until a `resolve` transition activates on one
    /// branch". Fold each valid candidate's own branch forward (no nested look-ahead, so a later
    /// unresolved conflict ends that branch) and find the candidate that **keeps itself**: its
    /// branch holds an activation of a `resolve` whose `kept` is the candidate's entry at this
    /// seq. A candidate is eligible when it keeps itself and no other candidate's branch holds
    /// an activation after the fork that homes witnessed (a `final` entry with heads): a
    /// `resolve` never discards such a branch. One eligible candidate stands, whatever the
    /// number of candidates. Two or none leave the fork.
    fn resolved_by_activation(
        &self,
        valid: &[(&Entry, State)],
        verdict: &Verdict,
        seq: u64,
    ) -> Option<usize> {
        let mut keeps = Vec::new();
        let mut protected = Vec::new();
        for (e, next) in valid.iter() {
            let mut sub = Verdict {
                branch: verdict.branch.clone(),
                state: None,
                stop: None,
                rollback: false,
                conflicts: Vec::new(),
                held_until: None,
                stopped: None,
            };
            sub.branch.push(e.env.digest.clone());
            let end = self.run(Some(next.clone()), &mut sub, false);
            keeps.push(end.as_ref().is_some_and(|n| {
                n.resolved_forks()
                    .iter()
                    .any(|(q, d)| *q == seq && *d == e.env.digest)
            }));
            protected.push(
                end.as_ref()
                    .is_some_and(|n| n.activations().iter().any(|a| a.seq > seq && a.witnessed)),
            );
        }
        let eligible: Vec<usize> = (0..valid.len())
            .filter(|&i| keeps[i] && (0..valid.len()).all(|j| j == i || !protected[j]))
            .collect();
        match eligible.as_slice() {
            [i] => Some(*i),
            _ => None,
        }
    }
}

fn by_seq_all(by_seq: &BTreeMap<u64, Vec<Result<Entry, Failure>>>) -> Vec<&Entry> {
    // One entry per body: the envelopes over a body are one object (§2.2).
    let mut seen = std::collections::BTreeSet::new();
    by_seq
        .values()
        .flatten()
        .filter_map(|r| r.as_ref().ok())
        .filter(|e| seen.insert(&e.env.digest))
        .collect()
}

/// The most namespaces a 0.5 genesis declares (§8.2). The verifier, account creation and
/// genesis preparation share it, so the writer never creates an account its verifier refuses.
pub const MAX_NAMESPACES: usize = 64;

/// The diagnostic of a genesis that declares more than [`MAX_NAMESPACES`] namespaces.
pub const TOO_MANY_NAMESPACES: &str = "too many namespaces: a genesis declares at most 64 (§8.2)";

/// `malformed` with [`TOO_MANY_NAMESPACES`] when `count` exceeds [`MAX_NAMESPACES`].
pub fn check_namespace_count(count: usize) -> Result<(), Failure> {
    crate::v05::require(count <= MAX_NAMESPACES, TOO_MANY_NAMESPACES)
}

/// Unknown content found in an authority entry's kind fields by the pre-scan (§8.5 step 4).
pub(crate) fn prescan(kind: &str, body: &serde_json::Value) -> Unknown {
    crate::v05::prescan::authority_fields(kind, body).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// The entries of a candidate vector's `rules/<name>/records/authority/`.
    fn vector(name: &str) -> Objects {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/0.5/rules")
            .join(name)
            .join("records/authority");
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        Objects {
            entries: files.iter().map(|p| std::fs::read(p).unwrap()).collect(),
            ..Objects::default()
        }
    }
    const NOW: i64 = 1_795_132_800_000; // 2026-11-20T00:00:00Z

    /// §1 "A stop": a `newerFormat` authority entry stops the reader at its seq, and the
    /// checkpoint carries it across a save and a load.
    #[test]
    fn a_newer_format_entry_stops_the_reader_and_the_checkpoint_keeps_it() {
        let objects = vector("f3-layout-3");
        let v = verify_history(&objects, &Persisted::default(), NOW);
        assert_eq!(v.code(), "newerFormat");
        assert_eq!(v.stopped, Some(2));
        assert!(v.is_stopped());
        let cp = Persisted::checkpoint(&objects, &Persisted::default(), NOW);
        assert_eq!(cp.stopped(), Some(2));
        let back = Persisted::from_bytes(&cp.to_bytes().unwrap()).unwrap();
        assert_eq!(back.stopped(), Some(2));
        // Resuming from the checkpoint stops again at the same entry.
        let again = verify_history(&Objects::default(), &back, NOW);
        assert_eq!(again.stopped, Some(2));
    }

    /// Other failures do not stop the reader: `malformed` and `badSignature` are not a stop.
    #[test]
    fn other_failures_are_not_a_stop() {
        for name in ["f3-layout-2", "f3-layout-3-no-consent"] {
            let v = verify_history(&vector(name), &Persisted::default(), NOW);
            assert_ne!(v.code(), "ok", "{name}");
            assert_eq!(v.stopped, None, "{name}");
        }
        let ok = verify_history(
            &vector("f2-unknown-kind-single-approve"),
            &Persisted::default(),
            NOW,
        );
        assert_eq!(ok.stopped, None);
    }

    /// A checkpoint of the format before 7 is refused, so it is rebuilt from its objects.
    #[test]
    fn a_format_6_checkpoint_is_refused() {
        let objects = vector("f3-layout-3");
        let cp = Persisted::checkpoint(&objects, &Persisted::default(), NOW);
        let mut v: serde_json::Value = serde_json::from_slice(&cp.to_bytes().unwrap()).unwrap();
        v["version"] = serde_json::json!(6);
        assert!(Persisted::from_bytes(&serde_json::to_vec(&v).unwrap()).is_err());
    }

    /// Every object of a vector: its entries, every `branch-*` entry, and its held objects
    /// (`objects/head*.json` as heads, the rest as pending), as the conformance runner loads them.
    fn case(name: &str) -> Objects {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/0.5/rules")
            .join(name);
        let files = |d: std::path::PathBuf| -> Vec<Vec<u8>> {
            let mut p: Vec<_> = std::fs::read_dir(d)
                .map(|r| r.map(|e| e.unwrap().path()).collect())
                .unwrap_or_default();
            p.sort();
            p.iter().map(|p| std::fs::read(p).unwrap()).collect()
        };
        let mut o = Objects {
            entries: files(dir.join("records/authority")),
            ..Objects::default()
        };
        let mut subs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        subs.sort();
        for p in subs {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            if n.starts_with("branch-") {
                o.entries.extend(files(p.join("authority")));
            }
        }
        let mut held: Vec<_> = std::fs::read_dir(dir.join("objects"))
            .map(|r| r.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default();
        held.sort();
        for p in held {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            if n.starts_with("head") {
                o.heads.push(std::fs::read(&p).unwrap());
            } else {
                o.pending.push(std::fs::read(&p).unwrap());
            }
        }
        o
    }

    fn summary(v: &Verdict) -> (String, u64, Option<u64>, Vec<String>) {
        (v.code(), v.seq(), v.stopped, v.branch.clone())
    }

    /// The order guard over every F2 and F3 vector: the verdict, the seq, the stop and the
    /// branch are the same for the entries reversed, sorted by bytes and shuffled (a fixed
    /// permutation per vector), with the heads and pending objects reordered too.
    #[test]
    fn f2_and_f3_verdicts_do_not_depend_on_object_order() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5/rules");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("f2-") || n.starts_with("f3-"))
            .collect();
        names.sort();
        assert!(names.len() >= 25, "{names:?}");
        for name in names {
            let base = case(&name);
            let want = summary(&verify_history(&base, &Persisted::default(), NOW));
            let mut orders: Vec<Objects> = Vec::new();
            let mut rev = base.clone();
            rev.entries.reverse();
            rev.heads.reverse();
            rev.pending.reverse();
            orders.push(rev);
            let mut sorted = base.clone();
            sorted.entries.sort();
            sorted.heads.sort();
            sorted.pending.sort();
            orders.push(sorted);
            let mut shuffled = base.clone();
            let n = shuffled.entries.len();
            for i in 0..n {
                // A fixed permutation: swap i with (7i + 3) mod n.
                shuffled.entries.swap(i, (7 * i + 3) % n);
            }
            orders.push(shuffled);
            for (k, objs) in orders.iter().enumerate() {
                let got = summary(&verify_history(objs, &Persisted::default(), NOW));
                assert_eq!(got, want, "{name}, order {k}");
            }
        }
    }

    /// A checkpoint taken while a layout raise is provisional, then the veto arrives late (the
    /// `vetoed` entry and an entry after it): the resumed verdict equals a full replay's, and
    /// nothing stops.
    #[test]
    fn a_late_veto_after_a_provisional_raise_checkpoint_matches_replay() {
        let all = case("f3-raise-vetoed");
        let provisional = case("f3-raise-provisional");
        let cp = Persisted::checkpoint(&provisional, &Persisted::default(), NOW);
        assert_eq!(cp.stopped(), None);
        let resumed = Persisted::from_bytes(&cp.to_bytes().unwrap()).unwrap();
        let late = verify_history(&all, &resumed, NOW);
        let full = verify_history(&all, &Persisted::default(), NOW);
        assert_eq!(summary(&late), summary(&full));
        assert_eq!(full.code(), "ok");
        assert_eq!(full.stopped, None);
        assert_eq!(full.branch.len(), 4);
    }
}
