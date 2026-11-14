//! Creating an account (§7.2, §8.2, §8.4): the genesis with its keyring, policy, homes and
//! first slots, then the first `rekey` that introduces epoch 1 in every declared namespace
//! (§8.2: seq 2 must be a `rekey` when the account declares namespaces).
//!
//! 0.4's `begin_create` / `advance_create` shape, in as many rounds as the ceremonies need:
//! PRF slots need an assertion over a fresh core challenge **before** the genesis body exists
//! (§7.2: the slot is built, opened again and checked before it is published), then the host
//! signs the genesis (the control rule, plus a possession proof for every other controller),
//! then signs the `rekey`. The new seed is made from the host's bytes and lives inside the
//! [`Creation`] and, afterwards, the [`Account`]; it is never returned.
use super::{Account, Identity};
use crate::crypto::Entropy;
use crate::v05::descriptor::{Controller, Role};
use crate::v05::history::Objects;
use crate::v05::records::EpochKeys;
use crate::v05::slots::{PrfRequest, PrfResult, SlotBuild, SlotPlan, SlotTarget};
use crate::v05::vault::VaultSeed;
use crate::v05::write::authority::{prepare_genesis, GenesisParams, PendingBatch};
use crate::v05::write::records::prepare_rekey;
use crate::v05::write::{SignatureResult, SigningStep};
use crate::v05::{malformed, require, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// What to create. Everything here is public except the two entropy seeds, which the host
/// draws fresh for this one action.
#[derive(Clone, Debug)]
pub struct CreateParams {
    /// 1–200 bytes.
    pub label: String,
    /// Declared namespaces, sorted and distinct.
    pub namespaces: Vec<String>,
    /// The controllers, as protocol JSON (§6.1). They are sorted by ID here.
    pub controllers: Vec<Value>,
    /// The first slots (§7.2): at least one, each naming only non-`sign` controllers.
    pub slots: Vec<SlotPlan>,
    /// `threshold` (default 1).
    pub threshold: Option<u64>,
    /// `recoverThreshold` (default 1 when any controller has `recover`, else 0).
    pub recover_threshold: Option<u64>,
    /// `addThreshold` (default 1).
    pub add_threshold: Option<u64>,
    /// `countBy: holders` (default false: `keys`).
    pub count_by_holders: bool,
    /// The policy (§6.3) as protocol JSON; `None` is the §18 person default.
    pub policy: Option<Value>,
    /// The signers of the genesis: the first is `by`; together they meet the control rule.
    pub signers: Vec<String>,
    /// The signers of the first `rekey`.
    pub rekey_signers: Vec<String>,
    /// The new vault seed's bytes: 32 fresh random bytes (§7.1).
    pub vault_seed: [u8; 32],
    /// Fresh entropy for the slots (§7.2).
    pub entropy: [u8; 32],
    /// Fresh entropy for the first epochs (§11.1).
    pub epoch_seed: [u8; 32],
}

/// The §18 person policy defaults, as protocol JSON.
pub fn default_policy() -> Value {
    json!({
        "callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
        "linkMaxAge": 86400, "memberRule": "single",
        "rate": {"account": {"bytes": 16777216, "entries": 256},
                 "signer": {"bytes": 4194304, "entries": 64}},
        "recoveryDelay": 259200
    })
}

/// A creation in progress.
pub struct Creation {
    params: CreateParams,
    me: Identity,
    now_ms: i64,
    seed: VaultSeed,
    stage: CStage,
}
enum CStage {
    Prf {
        builds: Vec<SlotBuild>,
        requests: Vec<PrfRequest>,
        controllers: BTreeMap<String, Controller>,
    },
    Genesis {
        batch: PendingBatch,
        steps: Vec<SigningStep>,
    },
    Rekey {
        objects: Objects,
        batch: PendingBatch,
        keys: EpochKeys,
        steps: Vec<SigningStep>,
    },
}

/// Where a creation stands after a round.
pub enum CreateProgress {
    /// Another round: read [`Creation::steps`] (or [`Creation::prf_requests`]) again.
    Continue(Box<Creation>),
    /// The account exists, opened as the identity the creation named, with its seed held.
    Done(Box<Account>),
}

impl std::fmt::Debug for Creation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Creation({})",
            match &self.stage {
                CStage::Prf { .. } => "awaiting PRF",
                CStage::Genesis { .. } => "awaiting the genesis signatures",
                CStage::Rekey { .. } => "awaiting the rekey signatures",
            }
        )
    }
}

impl Creation {
    /// Start a creation at the clock `now_ms`, to be opened as `me` (a controller of the new
    /// keyring, or a member the account will have).
    pub fn begin(params: CreateParams, me: Identity, now_ms: i64) -> Result<Self> {
        crate::v05::write::check_issued(now_ms)?;
        require(
            (1..=200).contains(&params.label.len()),
            "the label is 1 to 200 bytes",
        )?;
        require(!params.slots.is_empty(), "an account is created with a slot")?;
        require(
            params.namespaces.windows(2).all(|w| w[0] < w[1])
                && params
                    .namespaces
                    .iter()
                    .all(|n| crate::v05::terms::valid_namespace(n)),
            "namespaces are sorted, distinct and valid",
        )?;
        let mut controllers = BTreeMap::new();
        for c in &params.controllers {
            let c = Controller::parse(c.clone(), "controller")?;
            require(
                controllers.insert(c.id(), c).is_none(),
                "a controller appears twice",
            )?;
        }
        let seed = VaultSeed::from_host_random(params.vault_seed);
        let target = SlotTarget::genesis(&seed, &controllers)?;
        let mut e = Entropy::new(params.entropy);
        let mut builds = Vec::new();
        for plan in &params.slots {
            builds.push(SlotBuild::begin(
                plan,
                &target,
                e.take::<32>().map_err(|e| malformed(e.to_string()))?,
            )?);
        }
        let requests = builds
            .iter()
            .flat_map(|b| b.prf_requests().iter().cloned())
            .collect();
        let c = Self {
            params,
            me,
            now_ms,
            seed,
            stage: CStage::Prf {
                builds,
                requests,
                controllers,
            },
        };
        if c.prf_requests().is_empty() {
            return c.provide_prf(Vec::new());
        }
        Ok(c)
    }

    /// The PRF assertions to make, in order (§7.2). Empty once none are needed.
    pub fn prf_requests(&self) -> &[PrfRequest] {
        match &self.stage {
            CStage::Prf { requests, .. } => requests,
            _ => &[],
        }
    }

    /// The exact bodies to sign now: the genesis with its possession proofs, then the `rekey`.
    pub fn steps(&self) -> &[SigningStep] {
        match &self.stage {
            CStage::Genesis { steps, .. } | CStage::Rekey { steps, .. } => steps,
            CStage::Prf { .. } => &[],
        }
    }

    /// Give the PRF assertions and outputs, one per request in order: the slots are built,
    /// opened again and checked, and the genesis body is made.
    pub fn provide_prf(self, mut results: Vec<PrfResult>) -> Result<Self> {
        let Self {
            params,
            me,
            now_ms,
            seed,
            stage,
        } = self;
        let CStage::Prf {
            builds,
            requests,
            controllers,
        } = stage
        else {
            return Err(malformed("this creation needs no PRF assertions"));
        };
        require(
            results.len() == requests.len(),
            "one assertion and output per PRF request",
        )?;
        let mut slots = Vec::new();
        for b in builds {
            let n = b.prf_requests().len();
            let mine: Vec<PrfResult> = results.drain(..n).collect();
            slots.push(b.finish(&seed, &mine)?.to_value()?);
        }
        let any_recover = controllers.values().any(|c| c.has(&Role::Recover));
        let mut keyed: Vec<(String, Value)> = Vec::new();
        for c in &params.controllers {
            keyed.push((Controller::parse(c.clone(), "controller")?.id(), c.clone()));
        }
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        let keyring = json!({
            "controllers": keyed.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
            "threshold": params.threshold.unwrap_or(1),
            "recoverThreshold": params.recover_threshold.unwrap_or(u64::from(any_recover)),
            "addThreshold": params.add_threshold.unwrap_or(1),
            "countBy": if params.count_by_holders { "holders" } else { "keys" },
            "policy": params.policy.clone().unwrap_or_else(default_policy),
            "vault": seed.public()?.to_value(),
            "slots": slots,
        });
        let batch = prepare_genesis(
            &GenesisParams {
                label: params.label.clone(),
                namespaces: params.namespaces.clone(),
                keyring,
                issued_ms: now_ms,
                signers: params.signers.clone(),
            },
            now_ms,
        )?;
        Ok(Self {
            params,
            me,
            now_ms,
            seed,
            stage: CStage::Genesis {
                steps: batch.steps().to_vec(),
                batch,
            },
        })
    }

    /// Give the signatures for [`Creation::steps`], in order. After the genesis there is a
    /// second round (the first `rekey`) when namespaces are declared; then the account.
    pub fn provide_signatures(self, signatures: Vec<SignatureResult>) -> Result<CreateProgress> {
        let Self {
            params,
            me,
            now_ms,
            seed,
            stage,
        } = self;
        match stage {
            CStage::Prf { .. } => Err(malformed("the PRF assertions have not been provided")),
            CStage::Genesis { batch, .. } => {
                let records = batch.finish(signatures)?;
                let objects = Objects {
                    entries: records.entries.iter().map(|(_, e)| e.clone()).collect(),
                    ..Objects::default()
                };
                if params.namespaces.is_empty() {
                    let account = open_created(objects, me, now_ms, seed)?;
                    return Ok(CreateProgress::Done(Box::new(account)));
                }
                let (batch, keys) = prepare_rekey(
                    &objects,
                    now_ms,
                    &params.rekey_signers,
                    now_ms,
                    &params.namespaces,
                    params.epoch_seed,
                )?;
                let steps = batch.steps().to_vec();
                Ok(CreateProgress::Continue(Box::new(Self {
                    params,
                    me,
                    now_ms,
                    seed,
                    stage: CStage::Rekey {
                        objects,
                        batch,
                        keys,
                        steps,
                    },
                })))
            }
            CStage::Rekey {
                mut objects,
                batch,
                keys,
                ..
            } => {
                let records = batch.finish(signatures)?;
                objects
                    .entries
                    .extend(records.entries.iter().map(|(_, e)| e.clone()));
                drop(keys);
                let account = open_created(objects, me, now_ms, seed)?;
                Ok(CreateProgress::Done(Box::new(account)))
            }
        }
    }
}

fn open_created(objects: Objects, me: Identity, now_ms: i64, seed: VaultSeed) -> Result<Account> {
    let mut account = Account::open(objects, Vec::new(), None, me, now_ms)?;
    let id = account.id().clone();
    account.adopt_seed(seed, &id)?;
    Ok(account)
}
