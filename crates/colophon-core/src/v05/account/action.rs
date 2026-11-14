//! Actions: every one is `begin_*` (returns a [`PendingAction`]: the PRF assertions the host
//! must make first, then the exact bytes to sign) and [`Account::finish`] (takes the
//! signatures and applies the verified result).
//!
//! Each `begin_*` is a thin composition of a write-side function (`v05::write`) with the
//! account's own verified state: no function here takes a `State`, a keyring, a member's terms
//! or a session number from the caller. `finish` verifies the exact bytes it returns (the write
//! side runs the verifier over them), then re-verifies them over the account's *current*
//! objects before anything changes, so an action prepared against a history that has since
//! moved is refused by the verifier and leaves the account as it was.
use super::{Account, Changes, Incoming};
use crate::crypto::Entropy;
use crate::v05::calls::CallConfig;
use crate::v05::descriptor::{Controller, MemberRule, Role};
use crate::v05::encoding::bounds;
use crate::v05::history::envelope::AuthEnvelope;
use crate::v05::history::keyring::Keyring;
use crate::v05::history::Stop;
use crate::v05::ids::AccountId;
use crate::v05::records::{EpochKeys, HeldRecord, Level};
use crate::v05::slots::{
    plan_rotation, PrfRequest, PrfResult, Slot, SlotBuild, SlotPlan, SlotTarget,
};
use crate::v05::vault::VaultSeed;
use crate::v05::write::authority::{
    choose_receipts, prepare_activate, prepare_end_sessions_by_member, prepare_final,
    prepare_resolve, prepare_signed, prepare_suspend, prepare_transition, prepare_veto,
    prepare_vetoed, PendingBatch, TransitionParams, TransitionRule, VetoParams,
};
use crate::v05::write::calls::{
    finish_call, finish_link, prepare_call, prepare_link, CallSignerSpec, CallSpec, LinkSpec,
    PreparedCall, PreparedLink,
};
use crate::v05::write::records::{
    prepare_grant, prepare_operation, prepare_rekey, prepare_renew, prepare_resolution,
    prepare_revoke, Keep, OperationSpec, PreparedOperation,
};
use crate::v05::write::{format_date, KeptHead, Kind, SignatureResult, SigningStep};
use crate::v05::{malformed, require, Failure, Reason, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Facts about a prepared action a host may need to show or follow up on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActionInfo {
    /// A `revoke` while the vault is retiring carries no epochs (§8.3): a `rekey` of
    /// [`ActionInfo::owed_namespaces`] is owed once the new vault is in place.
    pub rekey_owed: bool,
    /// The namespaces a `rekey` is owed for.
    pub owed_namespaces: Vec<String>,
    /// A `revoke`'s walk meets a header this host does not hold (§9.5).
    pub walk_incomplete: bool,
    /// A `revoke`'s `kept` digests.
    pub kept: Vec<String>,
    /// A `revoke`'s `heads`: `(namespace, digest)`.
    pub heads: Vec<(String, String)>,
    /// What the action is, for display.
    pub name: String,
}

/// Which of a revoked member's records the revocation keeps (§9.5).
#[derive(Clone, Debug)]
pub enum RevokeKeep {
    /// Every header this host holds (every fork head, at most 16 per namespace).
    Everything,
    /// Nothing.
    Nothing,
    /// Exactly these `kept` digests and `(namespace, digest)` heads.
    Explicit {
        /// Digests kept by name.
        kept: Vec<String>,
        /// Walk starting points.
        heads: Vec<(String, String)>,
    },
}

/// A `change` object of a pending transition (§8.7): a JSON object of components. The
/// constructors build the common ones; the verifier judges the result at finish.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Change(pub Map<String, Value>);
impl Change {
    /// Thresholds: any of `threshold`, `recoverThreshold`, `addThreshold`.
    pub fn thresholds(threshold: Option<u64>, recover: Option<u64>, add: Option<u64>) -> Self {
        let mut k = Map::new();
        if let Some(v) = threshold {
            k.insert("threshold".into(), json!(v));
        }
        if let Some(v) = recover {
            k.insert("recoverThreshold".into(), json!(v));
        }
        if let Some(v) = add {
            k.insert("addThreshold".into(), json!(v));
        }
        Self(Map::from_iter([("keyring".to_string(), Value::Object(k))]))
    }
    /// `policy` fields to set (a `null` `primaryHome` clears it).
    pub fn policy(fields: Value) -> Self {
        Self(Map::from_iter([("policy".to_string(), fields)]))
    }
    /// Add controllers (their protocol JSON).
    pub fn add_controllers(controllers: Vec<Value>) -> Self {
        Self(Map::from_iter([(
            "keyring".to_string(),
            json!({"add": controllers}),
        )]))
    }
    /// Remove controllers, optionally keeping some a removed key planted (§8.3).
    pub fn remove_controllers(ids: Vec<String>, keep: Vec<String>) -> Self {
        let mut k = Map::new();
        k.insert("remove".into(), json!(ids));
        if !keep.is_empty() {
            k.insert("keep".into(), json!(keep));
        }
        Self(Map::from_iter([("keyring".to_string(), Value::Object(k))]))
    }
    /// Appoint or revoke homes (`appoint` takes grant-like objects; `revoke` member IDs).
    pub fn homes(fields: Value) -> Self {
        Self(Map::from_iter([("homes".to_string(), fields)]))
    }
    /// Add another component set to this one (components of the same name merge their
    /// members, the right-hand side winning).
    pub fn and(mut self, other: Change) -> Self {
        for (k, v) in other.0 {
            match (self.0.get_mut(&k), v) {
                (Some(Value::Object(a)), Value::Object(b)) => a.extend(b),
                (_, v) => {
                    self.0.insert(k, v);
                }
            }
        }
        self
    }
}

/// Which rule a set of signers is chosen for (see [`Account::suggest_signers`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerChoice {
    /// A member action (`grant`, `renew`, `revoke`, `endSessions`): one `approve` controller
    /// under `memberRule: single`; `threshold` `control` units under `control`.
    Member,
    /// A `rekey`.
    Rekey,
    /// A transition under the control rule.
    Control,
    /// A transition under the recovery rule.
    Recovery,
    /// An immediate additive `keyring` entry: `addThreshold` `control` units.
    KeyringAdd,
    /// A veto or `suspend`: any one `control` or `recover` controller.
    Veto,
}

/// How a controller is added (§8.4, §17.3).
#[derive(Clone, Debug)]
pub enum AddMode {
    /// At once by an immediate `keyring` entry: `approve` and `sign` roles only.
    Immediate {
        /// The signers.
        signers: Vec<String>,
    },
    /// As a pending transition under `rule`, for `control` and `recover` roles.
    Transition {
        /// The signers.
        signers: Vec<String>,
        /// The rule they are counted under.
        rule: TransitionRule,
    },
}

/// A controller to add, as its protocol JSON, and how.
#[derive(Clone, Debug)]
pub struct AddController {
    /// The controller object (§6.1). The new key signs a possession proof (a step).
    pub controller: Value,
    /// How it is added.
    pub mode: AddMode,
}

/// A prepared action. Its fields are private: a host reads what to do through the accessors
/// and can change nothing between `begin_*` and [`Account::finish`].
pub struct PendingAction {
    account: AccountId,
    info: ActionInfo,
    stage: Stage,
}
enum Stage {
    /// PRF assertions are needed before the bodies can be built.
    Prf(Box<PrfStage>),
    /// Bodies are built; the signatures are due.
    Sign(Box<SignStage>),
}
struct PrfStage {
    builds: Vec<SlotBuild>,
    requests: Vec<PrfRequest>,
    plan: Plan,
}
/// What to do with the built slots.
enum Plan {
    /// A self-slot `keyring` entry: slots appended, signed by `signer`.
    AddSlot { signer: String },
    /// A vault entry from a new seed.
    VaultEntry {
        new_seed: VaultSeed,
        signer: String,
        seal: [u8; 32],
    },
    /// A transition that removes controllers and rotates at once.
    RemoveRotate {
        new_seed: VaultSeed,
        seal: [u8; 32],
        signers: Vec<String>,
        rule: TransitionRule,
        remove: Vec<String>,
        keep: Vec<String>,
    },
}
struct SignStage {
    work: Work,
    steps: Vec<SigningStep>,
    /// Keys made by the action (a `rekey`, a `revoke`'s epochs), held after it is accepted.
    keys: EpochKeys,
    /// A seed made by the action (a rotation), held after it is accepted.
    seed: Option<VaultSeed>,
}
enum Work {
    Batch(PendingBatch),
    Operation(Box<PreparedOperation>),
    Link(Box<PreparedLink>),
    Call(Box<PreparedCall>, Box<CallTarget>),
}

/// What a call's verifier is configured with (§12.3): the target service's own audiences,
/// origins and purposes. The account cannot know them.
#[derive(Clone, Debug, Default)]
pub struct CallTarget {
    /// The verifier's own audiences; defaults to the call's audience.
    pub audiences: Vec<String>,
    /// Call-ceremony origins per `rp`.
    pub call_origins: std::collections::BTreeMap<String, Vec<String>>,
    /// Purposes allowed for controller calls.
    pub controller_purposes: Vec<String>,
    /// The verifier's own home endpoints, when it is a home.
    pub home_endpoints: Vec<String>,
}

impl std::fmt::Debug for PendingAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PendingAction({}, {})",
            self.info.name,
            match &self.stage {
                Stage::Prf(p) => format!("{} PRF requests", p.requests.len()),
                Stage::Sign(s) => format!("{} steps", s.steps.len()),
            }
        )
    }
}

impl PendingAction {
    /// What the action is.
    pub fn info(&self) -> &ActionInfo {
        &self.info
    }
    /// The PRF assertions to make first (§7.2), in order. Empty once none are needed.
    pub fn prf_requests(&self) -> &[PrfRequest] {
        match &self.stage {
            Stage::Prf(p) => &p.requests,
            Stage::Sign(_) => &[],
        }
    }
    /// The exact bodies to sign, in the order the signatures come back. Empty while PRF
    /// assertions are still needed, and for a recording entry (a body only).
    pub fn steps(&self) -> &[SigningStep] {
        match &self.stage {
            Stage::Prf(_) => &[],
            Stage::Sign(s) => &s.steps,
        }
    }
    /// The account this action is for.
    pub fn account(&self) -> &AccountId {
        &self.account
    }
}

/// What a finished action produced: the bytes to store and publish, and what changed.
#[derive(Clone, Debug)]
pub struct Finished {
    /// Authority entries with their seq.
    pub entries: Vec<(u64, Vec<u8>)>,
    /// Transitions and vetoes held outside the history.
    pub pending: Vec<Vec<u8>>,
    /// Record headers.
    pub records: Vec<HeldRecord>,
    /// A link or call envelope, which is not stored in the account.
    pub artifact: Option<Vec<u8>>,
    /// What the action changed in the account.
    pub changes: Changes,
    /// The action's facts.
    pub info: ActionInfo,
}

fn unavailable(why: &str) -> Failure {
    Failure::Unavailable(why.into())
}

impl Account {
    // -----------------------------------------------------------------------------------------
    // Shared helpers.

    /// Writes need a clean history and no rollback (§13.3).
    fn require_writable(&self) -> Result<()> {
        self.d.auth.require_clean()?;
        if self.d.verdict.rollback {
            return Err(Failure::Refused(Reason::Rollback));
        }
        Ok(())
    }

    fn me_member(&self) -> Result<String> {
        match &self.me {
            super::Identity::Member(id) => Ok(id.clone()),
            super::Identity::Controller(_) => Err(malformed("this session is a controller")),
        }
    }

    fn current_seed(&self) -> Result<&VaultSeed> {
        let k = self.d.auth.state().keyring();
        self.seeds
            .current(&crate::v05::vault::VaultPublic::from_pair(&k.vault))
            .ok_or_else(crate::v05::vault::locked)
    }

    fn pending_for(&self, name: &str, work: Work, steps: Vec<SigningStep>) -> PendingAction {
        PendingAction {
            account: self.d.auth.account().clone(),
            info: ActionInfo {
                name: name.into(),
                ..ActionInfo::default()
            },
            stage: Stage::Sign(Box::new(SignStage {
                work,
                steps,
                keys: EpochKeys::new(),
                seed: None,
            })),
        }
    }

    fn batch_action(&self, name: &str, batch: PendingBatch) -> PendingAction {
        let steps = batch.steps().to_vec();
        self.pending_for(name, Work::Batch(batch), steps)
    }

    /// The signers a rule needs, chosen from `available` controller IDs (the keys the host
    /// can sign with), or an error naming that none suffice.
    pub fn suggest_signers(&self, available: &[String], need: SignerChoice) -> Result<Vec<String>> {
        let k = self.d.auth.state().keyring();
        let st = self.d.auth.state();
        let usable: Vec<&Controller> = available
            .iter()
            .filter_map(|id| k.controllers.get(id))
            .filter(|c| {
                st.controller_provisional(&c.id()).is_none()
                    && !st
                        .active_suspensions(self.now_ms)
                        .iter()
                        .any(|s| s.key == c.id())
            })
            .collect();
        let pick = |role: &Role, count: u64, any_of: &[Role]| -> Option<Vec<String>> {
            let mut units = BTreeSet::new();
            let mut ids = Vec::new();
            for c in &usable {
                if (c.has(role) || any_of.iter().any(|r| c.has(r))) && units.insert(k.unit_of(c)) {
                    ids.push(c.id());
                }
                if ids.len() as u64 >= count {
                    return Some(ids);
                }
            }
            None
        };
        let found = match need {
            SignerChoice::Member | SignerChoice::Rekey => {
                if k.policy.member_rule() == MemberRule::Control {
                    pick(&Role::Control, k.threshold, &[])
                } else {
                    pick(&Role::Approve, 1, &[]).or_else(|| {
                        (need == SignerChoice::Rekey)
                            .then(|| pick(&Role::Control, 1, &[Role::Recover]))
                            .flatten()
                    })
                }
            }
            SignerChoice::Control => pick(&Role::Control, k.threshold, &[]),
            SignerChoice::Recovery => pick(&Role::Recover, k.recover_threshold.max(1), &[]),
            SignerChoice::KeyringAdd => pick(&Role::Control, k.add_threshold, &[]),
            SignerChoice::Veto => pick(&Role::Control, 1, &[Role::Recover]),
        };
        found.ok_or_else(|| {
            Failure::BadSignature("no set of the available keys meets the rule".into())
        })
    }

    // -----------------------------------------------------------------------------------------
    // Members.

    /// Admit a member (§9.2): a `grant` with `shares` sealing every historical epoch of every
    /// granted namespace to its agreement key. `request` is the member's signed request.
    pub fn begin_approve(
        &self,
        request: &[u8],
        terms: Value,
        signers: &[String],
        seed: [u8; 32],
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let batch = prepare_grant(
            &self.objects,
            self.now_ms,
            signers,
            self.now_ms,
            request,
            terms,
            &self.d.keys,
            seed,
        )?;
        Ok(self.batch_action("approve", batch))
    }

    /// Extend a member's expiry (§9.4), sealing the epochs no earlier object sealed to it.
    pub fn begin_renew(
        &self,
        member: &str,
        expires_ms: i64,
        signers: &[String],
        seed: [u8; 32],
    ) -> Result<PendingAction> {
        self.require_writable()?;
        crate::v05::write::check_issued(expires_ms)?;
        let batch = prepare_renew(
            &self.objects,
            self.now_ms,
            signers,
            self.now_ms,
            member,
            &format_date(expires_ms),
            &self.d.keys,
            seed,
        )?;
        Ok(self.batch_action("renew", batch))
    }

    /// End a member (§9.5): `kept` and `heads` from the headers this account holds, and, unless
    /// the vault is retiring, a new epoch sealed without the member. While the vault is
    /// retiring the entry carries no epochs and the action's [`ActionInfo`] says a `rekey` is
    /// owed.
    pub fn begin_revoke(
        &self,
        member: &str,
        keep: &RevokeKeep,
        signers: &[String],
        seed: [u8; 32],
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let keep = match keep {
            RevokeKeep::Everything => Keep::Everything,
            RevokeKeep::Nothing => Keep::Nothing,
            RevokeKeep::Explicit { kept, heads } => Keep::Explicit {
                kept: kept.clone(),
                heads: heads
                    .iter()
                    .map(|(n, d)| KeptHead {
                        namespace: n.clone(),
                        digest: d.clone(),
                    })
                    .collect(),
            },
        };
        let prepared = prepare_revoke(
            &self.objects,
            &self.records,
            self.now_ms,
            signers,
            self.now_ms,
            member,
            &keep,
            seed,
        )?;
        let info = ActionInfo {
            rekey_owed: prepared.rekey_owed(),
            owed_namespaces: prepared.owed_namespaces().to_vec(),
            walk_incomplete: prepared.walk_incomplete(),
            kept: prepared.kept().to_vec(),
            heads: prepared
                .heads()
                .iter()
                .map(|h| (h.namespace.clone(), h.digest.clone()))
                .collect(),
            name: "revoke".into(),
        };
        let (batch, keys) = prepared.into_parts();
        let steps = batch.steps().to_vec();
        let mut a = self.pending_for("revoke", Work::Batch(batch), steps);
        a.info = info;
        if let Stage::Sign(s) = &mut a.stage {
            s.keys = keys;
        }
        Ok(a)
    }

    /// End every link under a member (§9.6), signed by the approvers.
    pub fn begin_end_sessions(&self, member: &str, signers: &[String]) -> Result<PendingAction> {
        self.require_writable()?;
        let batch = prepare_signed(
            &self.objects,
            self.now_ms,
            Kind::EndSessions {
                member: member.to_string(),
            },
            self.now_ms,
            signers,
        )?;
        Ok(self.batch_action("endSessions", batch))
    }

    /// End this member's own sessions (§8.4 "Member rule"): signed by the member's key.
    pub fn begin_end_my_sessions(&self) -> Result<PendingAction> {
        self.require_writable()?;
        let me = self.me_member()?;
        let batch = prepare_end_sessions_by_member(&self.objects, self.now_ms, &me, self.now_ms)?;
        Ok(self.batch_action("endSessions", batch))
    }

    /// Introduce new epochs (§8.2, §11.1) in `namespaces`, sealed to the vault and the members
    /// with access. Refused while the vault is retiring (§8.3).
    pub fn begin_rekey(
        &self,
        namespaces: &[String],
        signers: &[String],
        seed: [u8; 32],
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let (batch, keys) = prepare_rekey(
            &self.objects,
            self.now_ms,
            signers,
            self.now_ms,
            namespaces,
            seed,
        )?;
        let mut a = self.batch_action("rekey", batch);
        if let Stage::Sign(s) = &mut a.stage {
            s.keys = keys;
        }
        Ok(a)
    }

    // -----------------------------------------------------------------------------------------
    // The keyring.

    fn raw_keyring_edit(
        &self,
        edit: impl FnOnce(&mut Map<String, Value>) -> Result<()>,
    ) -> Result<Value> {
        let mut v = self.d.auth.state().keyring().raw.clone();
        let m = v
            .as_object_mut()
            .ok_or_else(|| malformed("the keyring is not an object"))?;
        edit(m)?;
        // Controllers stay sorted by ID (§6.2).
        if let Some(list) = m.get_mut("controllers").and_then(Value::as_array_mut) {
            let mut keyed = Vec::new();
            for c in list.drain(..) {
                let id = Controller::parse(c.clone(), "controller")?.id();
                keyed.push((id, c));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            list.extend(keyed.into_iter().map(|(_, c)| c));
        }
        Ok(v)
    }

    /// An immediate `keyring` entry (§8.4): add a controller (`approve` or `sign` only), append
    /// slots, tighten policy. `edit` names the changes; the verifier judges that they only add
    /// or tighten.
    pub fn begin_keyring(&self, edit: &KeyringEdit, signers: &[String]) -> Result<PendingAction> {
        self.require_writable()?;
        let new = self.raw_keyring_edit(|m| {
            if !edit.add_controllers.is_empty() {
                let list = m
                    .get_mut("controllers")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| malformed("controllers"))?;
                list.extend(edit.add_controllers.iter().cloned());
            }
            if !edit.add_slots.is_empty() {
                let list = m
                    .get_mut("slots")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| malformed("slots"))?;
                list.extend(edit.add_slots.iter().cloned());
            }
            if let Some(Value::Object(p)) = &edit.policy {
                let policy = m
                    .get_mut("policy")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| malformed("policy"))?;
                for (k, v) in p {
                    policy.insert(k.clone(), v.clone());
                }
            }
            Ok(())
        })?;
        let batch = prepare_signed(
            &self.objects,
            self.now_ms,
            Kind::Keyring { keyring: new },
            self.now_ms,
            signers,
        )?;
        Ok(self.batch_action("keyring", batch))
    }

    /// Add a controller (§8.4, §17.3): at once as `approve` or `sign` by an immediate entry, or
    /// as a pending transition (an `approve`-only add may also be proposed as `control`
    /// later). The new key signs a possession proof; its slot is a self-slot entry it signs
    /// after it is in the keyring ([`Account::begin_add_slot`]), on a device that holds the
    /// seed ([`Account::transfer_seed`], [`Account::accept_seed_transfer`]).
    pub fn begin_add_controller(&self, add: &AddController) -> Result<PendingAction> {
        match &add.mode {
            AddMode::Immediate { signers } => self.begin_keyring(
                &KeyringEdit {
                    add_controllers: vec![add.controller.clone()],
                    ..KeyringEdit::default()
                },
                signers,
            ),
            AddMode::Transition { signers, rule } => self.begin_transition(
                &Change::add_controllers(vec![add.controller.clone()]),
                signers,
                *rule,
            ),
        }
    }

    /// Build a slot of the current vault for a controller `signer` (a current, non-`sign`
    /// controller) and append it by a self-slot `keyring` entry (§8.4). The account must hold
    /// the current seed. PRF routes need assertions first ([`PendingAction::prf_requests`]).
    pub fn begin_add_slot(
        &self,
        signer: &str,
        plan: SlotPlan,
        entropy: [u8; 32],
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let seed = self.current_seed()?;
        let target = SlotTarget::verified(self.d.auth.state(), seed)?;
        let build = SlotBuild::begin(&plan, &target, entropy)?;
        self.start_prf(
            "slot",
            vec![build],
            Plan::AddSlot {
                signer: signer.to_string(),
            },
        )
    }

    /// A rotation of the retiring vault by a `vault` entry (§8.3). The host supplies the new
    /// seed's entropy. The new vault's slots are `plans`, or by default every `sealed` slot of
    /// the current keyring (the one naming `signer` among them). A `rekey` of every namespace
    /// follows ([`Account::begin_rekey`]).
    pub fn begin_rotate_vault(
        &self,
        signer: &str,
        new_seed: [u8; 32],
        plans: Option<Vec<SlotPlan>>,
        entropy: [u8; 32],
    ) -> Result<PendingAction> {
        self.require_writable()?;
        require(
            self.d.auth.state().vault_retiring(),
            "the vault is not retiring (§8.3)",
        )?;
        let old = self.current_seed()?;
        let new = VaultSeed::from_host_random(new_seed);
        let plans = match plans {
            Some(p) => p,
            None => self
                .d
                .auth
                .state()
                .keyring()
                .slots
                .iter()
                .filter_map(|v| Slot::from_value(v).ok())
                .filter(|s| matches!(s, Slot::Sealed { .. }))
                .map(|s| SlotPlan {
                    controllers: s.controllers().to_vec(),
                    label: s.label().to_string(),
                })
                .collect(),
        };
        let target = SlotTarget::rotation(self.d.auth.state(), &new, old)?;
        let mut e = Entropy::new(entropy);
        let mut builds = Vec::new();
        for p in &plans {
            builds.push(SlotBuild::begin(
                p,
                &target,
                e.take::<32>().map_err(|e| malformed(e.to_string()))?,
            )?);
        }
        let seal = e.take::<32>().map_err(|e| malformed(e.to_string()))?;
        self.start_prf(
            "vault",
            builds,
            Plan::VaultEntry {
                new_seed: new,
                signer: signer.to_string(),
                seal,
            },
        )
    }

    /// Remove controllers by a pending transition (§8.3, §8.7). Where a removed controller was
    /// named by a slot and `rotate` carries a new seed's entropy, the transition rotates the
    /// vault at once: slots are rebuilt for the controllers that remain
    /// ([`plan_rotation`](crate::v05::slots::plan_rotation)) and `previousVault` carries the
    /// old seed. Without `rotate` the vault retires at activation and a `vault` entry follows
    /// ([`Account::begin_rotate_vault`]).
    pub fn begin_remove_controller(
        &self,
        remove: &[String],
        keep: &[String],
        signers: &[String],
        rule: TransitionRule,
        rotate: Option<([u8; 32], [u8; 32])>,
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let Some((new_seed, entropy)) = rotate else {
            return self.begin_transition(
                &Change::remove_controllers(remove.to_vec(), keep.to_vec()),
                signers,
                rule,
            );
        };
        let st = self.d.auth.state();
        let before = st.keyring();
        // The keyring the activation yields, as far as slots go (§8.3).
        let after = Keyring::parse(
            {
                let mut raw = before.raw.clone();
                let m = raw.as_object_mut().ok_or_else(|| malformed("keyring"))?;
                if let Some(list) = m.get_mut("controllers").and_then(Value::as_array_mut) {
                    list.retain(|c| {
                        Controller::parse(c.clone(), "c")
                            .map(|c| !remove.contains(&c.id()))
                            .unwrap_or(true)
                    });
                }
                if let Some(list) = m.get_mut("slots").and_then(Value::as_array_mut) {
                    list.retain(|s| {
                        Slot::from_value(s)
                            .map(|s| !s.controllers().iter().any(|c| remove.contains(c)))
                            .unwrap_or(true)
                    });
                }
                raw
            },
            0,
        )?;
        let plan = plan_rotation(before, &after, &[])?;
        if plan.lost.is_empty() {
            // No slotted controller is removed: nothing to rotate.
            return self.begin_transition(
                &Change::remove_controllers(remove.to_vec(), keep.to_vec()),
                signers,
                rule,
            );
        }
        let old = self.current_seed()?;
        let new = VaultSeed::from_host_random(new_seed);
        let target = SlotTarget::rotation(st, &new, old)?;
        let mut e = Entropy::new(entropy);
        let mut builds = Vec::new();
        for p in &plan.rebuild {
            builds.push(SlotBuild::begin(
                p,
                &target,
                e.take::<32>().map_err(|e| malformed(e.to_string()))?,
            )?);
        }
        let seal = e.take::<32>().map_err(|e| malformed(e.to_string()))?;
        self.start_prf(
            "removeController",
            builds,
            Plan::RemoveRotate {
                new_seed: new,
                seal,
                signers: signers.to_vec(),
                rule,
                remove: remove.to_vec(),
                keep: keep.to_vec(),
            },
        )
    }

    fn start_prf(&self, name: &str, builds: Vec<SlotBuild>, plan: Plan) -> Result<PendingAction> {
        let requests: Vec<PrfRequest> = builds
            .iter()
            .flat_map(|b| b.prf_requests().iter().cloned())
            .collect();
        let stage = PrfStage {
            builds,
            requests,
            plan,
        };
        let action = PendingAction {
            account: self.d.auth.account().clone(),
            info: ActionInfo {
                name: name.into(),
                ..ActionInfo::default()
            },
            stage: Stage::Prf(Box::new(stage)),
        };
        if action.prf_requests().is_empty() {
            return self.provide_prf(action, Vec::new());
        }
        Ok(action)
    }

    /// Give the PRF assertions and outputs (one per [`PendingAction::prf_requests`], in order)
    /// and get the action with its bodies built, ready to sign. The slots are built, opened
    /// again with the same outputs and checked against the vault before any body is made.
    pub fn provide_prf(
        &self,
        action: PendingAction,
        mut results: Vec<PrfResult>,
    ) -> Result<PendingAction> {
        require(
            &action.account == self.d.auth.account(),
            "the action is for another account",
        )?;
        let Stage::Prf(stage) = action.stage else {
            return Err(malformed("this action needs no PRF assertions"));
        };
        let PrfStage {
            builds,
            requests,
            plan,
        } = *stage;
        require(
            results.len() == requests.len(),
            "one assertion and output per PRF request",
        )?;
        let mut slots = Vec::new();
        for b in builds {
            let n = b.prf_requests().len();
            let mine: Vec<PrfResult> = results.drain(..n).collect();
            let slot = match &plan {
                Plan::AddSlot { .. } => b.finish(self.current_seed()?, &mine)?,
                Plan::VaultEntry { new_seed, .. } | Plan::RemoveRotate { new_seed, .. } => {
                    b.finish(new_seed, &mine)?
                }
            };
            slots.push(slot);
        }
        let mut out = match plan {
            Plan::AddSlot { signer } => {
                let new = self.raw_keyring_edit(|m| {
                    let list = m
                        .get_mut("slots")
                        .and_then(Value::as_array_mut)
                        .ok_or_else(|| malformed("slots"))?;
                    for s in &slots {
                        list.push(s.to_value()?);
                    }
                    Ok(())
                })?;
                let batch = prepare_signed(
                    &self.objects,
                    self.now_ms,
                    Kind::Keyring { keyring: new },
                    self.now_ms,
                    &[signer],
                )?;
                self.batch_action("slot", batch)
            }
            Plan::VaultEntry {
                new_seed,
                signer,
                seal,
            } => {
                let old = self.current_seed()?;
                let previous = old.seal_previous(&new_seed, &mut Entropy::new(seal))?;
                let batch = prepare_signed(
                    &self.objects,
                    self.now_ms,
                    Kind::Vault {
                        vault: new_seed.public()?.to_value(),
                        slots: slots
                            .iter()
                            .map(Slot::to_value)
                            .collect::<std::result::Result<_, _>>()?,
                        previous_vault: previous.to_value(),
                    },
                    self.now_ms,
                    &[signer],
                )?;
                let mut a = self.batch_action("vault", batch);
                if let Stage::Sign(s) = &mut a.stage {
                    s.seed = Some(new_seed);
                }
                a
            }
            Plan::RemoveRotate {
                new_seed,
                seal,
                signers,
                rule,
                remove,
                keep,
            } => {
                let old = self.current_seed()?;
                let previous = old.seal_previous(&new_seed, &mut Entropy::new(seal))?;
                let mut change = Change::remove_controllers(remove, keep).0;
                change.insert(
                    "vault".into(),
                    json!({
                        "vault": new_seed.public()?.to_value(),
                        "slots": slots
                            .iter()
                            .map(Slot::to_value)
                            .collect::<std::result::Result<Vec<_>, _>>()?,
                        "previousVault": previous.to_value(),
                    }),
                );
                let batch = prepare_transition(
                    &self.objects,
                    self.now_ms,
                    &TransitionParams {
                        anchor: None,
                        issued_ms: self.now_ms,
                        signers,
                        rule,
                        change: Value::Object(change),
                    },
                )?;
                let mut a = self.batch_action("removeController", batch);
                if let Stage::Sign(s) = &mut a.stage {
                    s.seed = Some(new_seed);
                }
                a
            }
        };
        out.info.name = action.info.name;
        Ok(out)
    }

    // -----------------------------------------------------------------------------------------
    // Pending transitions (§8.7).

    /// Propose a pending transition (§8.7) anchored on the head: thresholds, policy, homes,
    /// controllers, a vault change. A possession proof is a step for every controller it adds.
    pub fn begin_transition(
        &self,
        change: &Change,
        signers: &[String],
        rule: TransitionRule,
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let batch = prepare_transition(
            &self.objects,
            self.now_ms,
            &TransitionParams {
                anchor: None,
                issued_ms: self.now_ms,
                signers: signers.to_vec(),
                rule,
                change: Value::Object(change.0.clone()),
            },
        )?;
        Ok(self.batch_action("transition", batch))
    }

    fn pending_bytes(&self, digest: &str) -> Result<Vec<u8>> {
        self.objects
            .pending
            .iter()
            .find(|b| {
                AuthEnvelope::parse(
                    b,
                    bounds::TRANSITION_ENVELOPE,
                    bounds::TRANSITION_ENVELOPE,
                    true,
                )
                .is_ok_and(|e| e.digest == digest)
            })
            .cloned()
            .ok_or_else(|| unavailable("no held transition with that digest"))
    }

    /// Veto a held transition (§8.7), signed by `control` or `recover` controllers.
    pub fn begin_veto(&self, transition: &str, signers: &[String]) -> Result<PendingAction> {
        self.require_writable()?;
        let bytes = self.pending_bytes(transition)?;
        let env = AuthEnvelope::parse(
            &bytes,
            bounds::TRANSITION_ENVELOPE,
            bounds::TRANSITION_ENVELOPE,
            true,
        )?;
        let issued = env
            .value
            .get("issued")
            .and_then(Value::as_str)
            .and_then(crate::v05::encoding::parse_date)
            .ok_or_else(|| malformed("issued"))?;
        let receipts = choose_receipts(
            self.d.auth.state(),
            &self.objects.pending,
            &env.digest,
            issued,
            None,
        )?;
        let batch = prepare_veto(
            &self.objects,
            self.now_ms,
            &VetoParams {
                transition: bytes,
                transition_receipts: receipts,
                issued_ms: self.now_ms,
                signers: signers.to_vec(),
            },
        )?;
        Ok(self.batch_action("veto", batch))
    }

    /// Suspend `key` while the held transition that removes it is pending (§8.7).
    pub fn begin_suspend(
        &self,
        key: &str,
        transition: &str,
        signer: &str,
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let batch = prepare_suspend(
            &self.objects,
            self.now_ms,
            key,
            transition,
            self.now_ms,
            signer,
        )?;
        Ok(self.batch_action("suspend", batch))
    }

    /// The candidates held at the seq where the history forks: `(seq, body digest, previous)`.
    pub fn fork_candidates(&self) -> Vec<(u64, String, String)> {
        let Some(Stop::Fork { seq }) = &self.d.verdict.stop else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for b in &self.objects.entries {
            if let Ok(e) = AuthEnvelope::parse(
                b,
                bounds::AUTHORITY_BODY,
                bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            ) {
                if e.value.get("seq").and_then(Value::as_u64) == Some(*seq) {
                    out.push((
                        *seq,
                        e.digest,
                        e.value
                            .get("previous")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    ));
                }
            }
        }
        out.sort();
        out
    }

    /// Resolve a fork (§8.6, §8.7): a transition on the branch ending at `anchor` that keeps
    /// the entry `kept` at the forked seq. Works while the history is stopped at the fork.
    pub fn begin_resolve(
        &self,
        anchor: (u64, String),
        kept: (u64, String),
        signers: &[String],
        rule: TransitionRule,
    ) -> Result<PendingAction> {
        if self.d.verdict.rollback {
            return Err(Failure::Refused(Reason::Rollback));
        }
        let batch = prepare_resolve(
            &self.objects,
            self.now_ms,
            anchor,
            kept,
            self.now_ms,
            signers.to_vec(),
            rule,
        )?;
        Ok(self.batch_action("resolve", batch))
    }

    /// Record everything now determined (§8.6, §8.7): the `activate` of each due transition,
    /// the `vetoed` of each vetoed one, the `final` of each activation witnessed by heads.
    /// These bodies are unsigned and have exactly one possible value, so two homes holding the
    /// same objects build the same bytes. Returns each recorded entry; applies each.
    pub fn record_due(&mut self) -> Result<Vec<Finished>> {
        let mut out = Vec::new();
        // Bounded by the number of held pending objects and activations.
        for _ in 0..self.objects.pending.len() + self.d.auth.state().activations().len() + 8 {
            if let Some(batch) = self.next_recording() {
                let action = self.batch_action("record", batch);
                out.push(self.finish(action, Vec::new())?);
            } else if let Some((seq, env)) = self.next_fork_activation() {
                let finished = Finished {
                    entries: vec![(seq, env.clone())],
                    pending: Vec::new(),
                    records: Vec::new(),
                    artifact: None,
                    changes: Changes::default(),
                    info: ActionInfo {
                        name: "record".into(),
                        ..ActionInfo::default()
                    },
                };
                let extra = Incoming {
                    objects: crate::v05::history::Objects {
                        entries: vec![env],
                        ..Default::default()
                    },
                    records: Vec::new(),
                };
                out.push(self.apply_extra(extra, finished, EpochKeys::new(), None)?);
            } else {
                break;
            }
        }
        Ok(out)
    }

    /// While the history stands at a fork, the one entry that can be recorded is the
    /// `activate` of a due `resolve` transition on the branch it keeps (§8.6 rule 3). The
    /// write-side builders fold one branch and refuse a forked history, so the body is made
    /// here from the branch the transition is anchored on, with the same fields `activate`
    /// has: the receipts §8.7 chooses, `by` the transition's, `issued` the later of its due
    /// time and the preceding entry's.
    fn next_fork_activation(&self) -> Option<(u64, Vec<u8>)> {
        use crate::v05::write::{envelope, Header};
        if !matches!(self.d.verdict.stop, Some(Stop::Fork { .. })) || self.d.verdict.rollback {
            return None;
        }
        let mut by_digest: std::collections::BTreeMap<String, (u64, Option<String>, Vec<u8>)> =
            Default::default();
        for b in &self.objects.entries {
            if let Ok(e) = AuthEnvelope::parse(
                b,
                bounds::AUTHORITY_BODY,
                bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            ) {
                by_digest.insert(
                    e.digest.clone(),
                    (
                        e.value.get("seq").and_then(Value::as_u64).unwrap_or(0),
                        e.value
                            .get("previous")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        b.clone(),
                    ),
                );
            }
        }
        let mut transitions: Vec<(AuthEnvelope, Vec<u8>)> = Vec::new();
        for b in &self.objects.pending {
            if let Ok(e) = AuthEnvelope::parse(
                b,
                bounds::TRANSITION_ENVELOPE,
                bounds::TRANSITION_ENVELOPE,
                true,
            ) {
                if e.value.get("protocol").and_then(Value::as_str) == Some("colophon/transition/5")
                    && e.value
                        .get("change")
                        .and_then(|c| c.get("resolve"))
                        .is_some()
                {
                    transitions.push((e, b.clone()));
                }
            }
        }
        transitions.sort_by(|a, b| a.0.digest.cmp(&b.0.digest));
        for (t, bytes) in transitions {
            let anchor = t.value.get("anchor")?;
            let (a_seq, a_digest) = (
                anchor.get("seq")?.as_u64()?,
                anchor.get("digest")?.as_str()?.to_string(),
            );
            let mut branch = Vec::new();
            let mut at = Some(a_digest.clone());
            while let Some(d) = at {
                let Some((seq, prev, raw)) = by_digest.get(&d) else {
                    branch.clear();
                    break;
                };
                branch.push((*seq, raw.clone()));
                at = prev.clone();
            }
            branch.reverse();
            if branch.len() as u64 != a_seq || branch.first().map(|(s, _)| *s) != Some(1) {
                continue;
            }
            let scoped = crate::v05::history::Objects {
                entries: branch.into_iter().map(|(_, b)| b).collect(),
                pending: self.objects.pending.clone(),
                heads: self.objects.heads.clone(),
                predecessor: self.objects.predecessor.clone(),
            };
            let verdict = crate::v05::history::verify_history(
                &scoped,
                &crate::v05::history::Persisted::default(),
                self.now_ms,
            );
            if verdict.stop.is_some() {
                continue;
            }
            let state = verdict.state?;
            let issued_t = t
                .value
                .get("issued")
                .and_then(Value::as_str)
                .and_then(crate::v05::encoding::parse_date)?;
            let receipts =
                choose_receipts(&state, &self.objects.pending, &t.digest, issued_t, None).ok()?;
            let timing = crate::v05::history::transition_timing(&state, &bytes, &receipts).ok()?;
            if timing.due_ms > self.now_ms {
                continue;
            }
            let issued = timing.due_ms.max(state.last_issued_ms());
            let body = Kind::Activate {
                transition: bytes,
                receipts,
            }
            .body(&Header {
                seq: a_seq + 1,
                previous: Some(a_digest),
                issued: format_date(issued),
                by: timing.by,
            })
            .ok()?;
            let env = envelope(&body, None, &[], &[], &[]).ok()?;
            return Some((a_seq + 1, env));
        }
        None
    }

    fn next_recording(&self) -> Option<PendingBatch> {
        if self.require_writable().is_err() {
            return None;
        }
        let st = self.d.auth.state();
        let pending = super::read::pending_transitions(&self.objects, st);
        // The vetoes held for each transition, lowest digest first.
        let mut vetoes: Vec<(String, String)> = Vec::new();
        for b in &self.objects.pending {
            if let Ok(e) = AuthEnvelope::parse(b, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true) {
                if e.value.get("protocol").and_then(Value::as_str) == Some("colophon/veto/5") {
                    if let Some(t) = e.value.get("transition").and_then(Value::as_str) {
                        vetoes.push((t.to_string(), e.digest));
                    }
                }
            }
        }
        vetoes.sort();
        for t in &pending {
            for (td, vd) in vetoes.iter().filter(|(td, _)| *td == t.digest) {
                if let Ok(b) = prepare_vetoed(&self.objects, self.now_ms, td, vd) {
                    return Some(b);
                }
            }
            if let Ok(b) = prepare_activate(&self.objects, self.now_ms, &t.digest) {
                return Some(b);
            }
        }
        for a in st.activations() {
            if !a.final_ {
                if let Ok(b) = prepare_final(&self.objects, self.now_ms, a.seq) {
                    return Some(b);
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------------------------
    // Records.

    /// Write a `/5` operation (§11.2): the header with its AAD, the nonce from `seed`, the
    /// ciphertext, and the exact bytes this member's key signs. The member's role fence, the
    /// domain module's schema for the kind and the epoch key are checked before a host is
    /// asked to sign.
    pub fn begin_write(
        &self,
        namespace: &str,
        kind: &str,
        payload: Value,
        level: Level,
        seed: [u8; 32],
    ) -> Result<std::result::Result<PendingAction, crate::model::Denial>> {
        self.require_writable()?;
        let me = self.me_member()?;
        if let Some(d) = self.authorize_level(namespace, level) {
            return Ok(Err(d));
        }
        require(payload.is_object(), "operation payload must be an object")?;
        let member = self
            .d
            .auth
            .member(&me)
            .ok_or(Failure::Refused(Reason::NotGranted))?;
        if !kind.starts_with("colophon.") {
            require(
                crate::domain::role_allows(
                    namespace,
                    kind,
                    super::derived::model_kind(&member.request.kind),
                ),
                "an authenticated app or device is required for this kind",
            )?;
        }
        if let Some(module) = crate::domain::module(namespace) {
            if let Some(spec) = module.operations().iter().find(|s| s.name == kind) {
                require(
                    crate::domain::validate_input(&spec.input_schema, &payload),
                    "the payload does not match the operation schema",
                )?;
            }
        }
        let latest = self.d.auth.latest_epoch(namespace);
        if latest == 0
            || self
                .d
                .keys
                .get(self.d.auth.account(), namespace, latest)
                .is_none()
        {
            return Ok(Err(crate::model::Denial {
                reason: "unavailable".into(),
                detail: "Unlock the namespace epoch before writing".into(),
            }));
        }
        let prepared = prepare_operation(
            &self.objects,
            &self.records,
            &self.d.keys,
            self.now_ms,
            &OperationSpec {
                namespace,
                author: &me,
                level,
                kind,
                payload,
                clock: None,
            },
            seed,
        )?;
        let steps = vec![prepared.step().clone()];
        Ok(Ok(self.pending_for(
            "write",
            Work::Operation(Box::new(prepared)),
            steps,
        )))
    }

    /// Propose a record (§11.6): admitted like a write, folded only if accepted.
    pub fn begin_propose(
        &self,
        namespace: &str,
        kind: &str,
        payload: Value,
        seed: [u8; 32],
    ) -> Result<std::result::Result<PendingAction, crate::model::Denial>> {
        self.begin_write(namespace, kind, payload, Level::Propose, seed)
    }

    /// Accept or decline proposals (§11.6): a `colophon.accept` or `colophon.decline` write.
    pub fn begin_resolution(
        &self,
        namespace: &str,
        accept: bool,
        proposals: &[String],
        seed: [u8; 32],
    ) -> Result<PendingAction> {
        self.require_writable()?;
        let me = self.me_member()?;
        let prepared = prepare_resolution(
            &self.objects,
            &self.records,
            &self.d.keys,
            self.now_ms,
            &me,
            namespace,
            accept,
            proposals,
            None,
            seed,
        )?;
        let steps = vec![prepared.step().clone()];
        Ok(self.pending_for("resolution", Work::Operation(Box::new(prepared)), steps))
    }

    // -----------------------------------------------------------------------------------------
    // Links and calls (§12).

    /// A link (§12.1) from this member, or from the last link of its chain `prior`, to
    /// `to_signing`. The member, the parent key, the session number and the policy come from
    /// the verified history; the caller names the narrower terms and the window.
    pub fn begin_link(
        &self,
        prior: &[Vec<u8>],
        to_signing: &[u8],
        terms: Value,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<PendingAction> {
        let me = self.me_member()?;
        crate::v05::write::check_issued(not_before_ms)?;
        crate::v05::write::check_issued(expires_ms)?;
        let view = self.call_view()?;
        let m = self
            .d
            .auth
            .member(&me)
            .ok_or(Failure::Refused(Reason::Revoked))?;
        let session = prior.is_empty().then_some(m.end_sessions.len() as u64);
        let (nb, ex, cr) = (
            format_date(not_before_ms),
            format_date(expires_ms),
            format_date(self.now_ms),
        );
        let prepared = prepare_link(
            &view,
            &LinkSpec {
                account: self.d.auth.account(),
                member: &me,
                prior,
                to_signing,
                terms,
                session,
                not_before: &nb,
                expires: &ex,
                created: &cr,
            },
        )?;
        let steps = vec![prepared.step().clone()];
        Ok(self.pending_for("link", Work::Link(Box::new(prepared)), steps))
    }

    /// A call (§12.2) signed by this session's key (a member's, a link's key if `links` are
    /// given with `key`, or a controller's). `asOf` is the head of the verified history.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_call(
        &self,
        key: &[u8],
        links: &[Vec<u8>],
        audience: &str,
        purpose: &str,
        args: Value,
        request_id: [u8; 32],
        target: CallTarget,
    ) -> Result<PendingAction> {
        let view = self.call_view()?;
        let st = self.d.auth.state();
        let seq = st.history().len() as u64;
        let digest = st
            .history()
            .last()
            .cloned()
            .ok_or_else(|| unavailable("no history"))?;
        let (signer, webauthn) = match &self.me {
            super::Identity::Member(id) => (CallSignerSpec::Member(id.clone()), false),
            super::Identity::Controller(id) => {
                let c = st
                    .keyring()
                    .controllers
                    .get(id)
                    .ok_or(Failure::Refused(Reason::Revoked))?;
                (
                    CallSignerSpec::Controller(id.clone()),
                    c.key().webauthn().is_some(),
                )
            }
        };
        let created = format_date(self.now_ms);
        let prepared = prepare_call(&CallSpec {
            account: self.d.auth.account(),
            as_of: (seq, &digest),
            signer,
            key,
            links,
            audience,
            purpose,
            args,
            request_id,
            created: &created,
            webauthn,
        })?;
        let _ = view;
        let steps = vec![prepared.step().clone()];
        let mut target = target;
        if target.audiences.is_empty() {
            target.audiences = vec![audience.to_string()];
        }
        Ok(self.pending_for(
            "call",
            Work::Call(Box::new(prepared), Box::new(target)),
            steps,
        ))
    }

    // -----------------------------------------------------------------------------------------
    // Finish.

    /// Finish an action with the host's signatures, one per step in order: assemble, verify,
    /// and apply. Nothing changes unless the verifier accepts the result over the account's
    /// current objects.
    pub fn finish(
        &mut self,
        action: PendingAction,
        signatures: Vec<SignatureResult>,
    ) -> Result<Finished> {
        require(
            &action.account == self.d.auth.account(),
            "the action is for another account",
        )?;
        let info = action.info;
        let Stage::Sign(stage) = action.stage else {
            return Err(malformed("the PRF assertions have not been provided"));
        };
        let SignStage {
            work, keys, seed, ..
        } = *stage;
        let mut finished = Finished {
            entries: Vec::new(),
            pending: Vec::new(),
            records: Vec::new(),
            artifact: None,
            changes: Changes::default(),
            info,
        };
        let mut extra = Incoming::default();
        match work {
            Work::Batch(batch) => {
                let r = batch.finish(signatures)?;
                extra.objects.entries = r.entries.iter().map(|(_, e)| e.clone()).collect();
                extra.objects.pending = r.pending.clone();
                finished.entries = r.entries;
                finished.pending = r.pending;
            }
            Work::Operation(op) => {
                require(signatures.len() == 1, "one signature per step")?;
                let done = op.finish(
                    signatures
                        .into_iter()
                        .next()
                        .ok_or_else(|| malformed("signature"))?,
                )?;
                let rec = HeldRecord {
                    path: done.path,
                    bytes: done.envelope,
                };
                extra.records.push(rec.clone());
                finished.records.push(rec);
            }
            Work::Link(l) => {
                require(signatures.len() == 1, "one signature per step")?;
                let view = self.call_view()?;
                let sig = signatures
                    .into_iter()
                    .next()
                    .ok_or_else(|| malformed("signature"))?;
                finished.artifact = Some(finish_link(&l, &sig, &view, self.now_ms)?);
                return Ok(finished);
            }
            Work::Call(c, target) => {
                require(signatures.len() == 1, "one signature per step")?;
                let view = self.call_view()?;
                let sig = signatures
                    .into_iter()
                    .next()
                    .ok_or_else(|| malformed("signature"))?;
                let cfg = CallConfig {
                    now_ms: self.now_ms,
                    audiences: &target.audiences,
                    call_origins: &target.call_origins,
                    controller_purposes: &target.controller_purposes,
                    home_endpoints: &target.home_endpoints,
                };
                finished.artifact = Some(finish_call(&c, &sig, &view, &cfg)?);
                return Ok(finished);
            }
        }
        self.apply_extra(extra, finished, keys, seed)
    }

    /// Re-verify over the current objects: the candidate must hold and accept the new object.
    /// Only then does anything in the account change.
    fn apply_extra(
        &mut self,
        extra: Incoming,
        mut finished: Finished,
        keys: EpochKeys,
        seed: Option<VaultSeed>,
    ) -> Result<Finished> {
        let mut objects = self.objects.clone();
        let mut records = self.records.clone();
        super::union(&mut objects, &extra.objects);
        super::union_records(&mut records, &extra.records);
        let d = self.candidate_with(
            &objects,
            &records,
            &self.persisted,
            self.now_ms,
            Some(&keys),
        )?;
        let before_clean = self.d.verdict.stop.is_none();
        match &d.verdict.stop {
            None | Some(Stop::Held { .. }) => {}
            Some(_) if !before_clean => {}
            Some(Stop::Fork { .. }) => return Err(Failure::Refused(Reason::Fork)),
            Some(Stop::Failed { failure, .. }) => return Err(failure.clone()),
        }
        for (seq, bytes) in &finished.entries {
            let digest = super::derived::entry_digest(bytes)
                .ok_or_else(|| malformed("the finished entry does not parse"))?;
            let at = usize::try_from(*seq)
                .ok()
                .and_then(|s| s.checked_sub(1))
                .ok_or_else(|| malformed("seq"))?;
            require(
                d.verdict.branch.get(at) == Some(&digest),
                "the account's history moved on since this action was prepared",
            )?;
        }
        let persisted = self.persisted.clone();
        let now = self.now_ms;
        finished.changes = self.commit(d, objects, records, persisted, now);
        if let Some(s) = seed {
            let account = self.d.auth.account().clone();
            self.seeds.install(s, &account)?;
            let (publics, boxes) =
                super::unlock::vault_chain(&self.objects.entries, &self.d.verdict.branch);
            self.seeds.close_chain(&account, &publics, &boxes);
            let more = self.rebuild_in_place()?;
            finished.changes = merge_changes(finished.changes, more);
        }
        Ok(finished)
    }
}

fn merge_changes(mut a: Changes, b: Changes) -> Changes {
    for (k, v) in b.namespaces {
        a.namespaces.insert(k, v);
    }
    a.status = b.status.or(a.status);
    a
}

/// An immediate `keyring` entry (§8.4): what to add or tighten.
#[derive(Clone, Debug, Default)]
pub struct KeyringEdit {
    /// Controllers to add (`approve` and `sign` only), by their protocol JSON.
    pub add_controllers: Vec<Value>,
    /// Slots to append (already built, naming only controllers of the new keyring).
    pub add_slots: Vec<Value>,
    /// Policy fields to set (lowering windows, tightening `history` or `memberRule`).
    pub policy: Option<Value>,
}
