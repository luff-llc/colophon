//! The genesis of the account that succeeds a Swift library (§15.1, §16.2, §16.3): every
//! controller that had a vault slot is carried with a rebuilt slot (one passkey assertion each),
//! the predecessor's keys sign the `handover`, and the result is the successor account's ID and
//! the objects to store. Every later step of the move (`swift_succession`, the veto, F, the
//! copy, the migration) needs an account made this way: its genesis names the Swift library.
use super::convert as cv;
use super::fault::AccountError;
use super::session::SwiftSource;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::write::succession::{
    CarryOptions, SuccessorGenesis, SwiftSuccessor, SwiftSuccessorParams as CoreParams,
};
use std::collections::BTreeMap;

type R<T> = Result<T, AccountError>;

enum Stage {
    Open(Box<SwiftSuccessor>, CreateStage),
    Done(Box<SuccessorGenesis>),
    Spent,
}

/// A successor genesis in progress. One-shot at each step: a step that fails ends it.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SwiftSuccessorCreation {
    st: Cell<Stage>,
}

fn core_params(p: SwiftSuccessorParams) -> R<CoreParams> {
    let mut authority_origins = BTreeMap::new();
    if p.authority_origins.len() > MAX_NAMES || p.agreements.len() > MAX_NAMES {
        return Err(AccountError::bound("too many carried controllers"));
    }
    for o in p.authority_origins {
        authority_origins.insert(o.controller, names(o.origins, "origins")?);
    }
    let mut agreements = BTreeMap::new();
    for a in p.agreements {
        bytes_ok(&a.agreement, 65, "an agreement point")?;
        agreements.insert(a.controller, a.agreement);
    }
    Ok(CoreParams {
        label: p.label,
        namespaces: names(p.namespaces, "namespaces")?,
        carry: CarryOptions {
            include_stewards: p.include_stewards,
            authority_origins,
            agreements,
        },
        threshold: p.threshold,
        recover_threshold: p.recover_threshold,
        add_threshold: p.add_threshold,
        count_by_holders: p.count_by_holders,
        policy: if p.policy_json.is_empty() {
            None
        } else {
            Some(auth_json(&p.policy_json, "policy")?)
        },
        signers: names(p.signers, "signers")?,
        handover: names(p.handover, "handover")?,
        issued_ms: p.issued_ms,
        earlier_attempts: cv::earlier_attempts(p.earlier_attempts)?,
    })
}

impl SwiftSuccessorCreation {
    pub(crate) fn begin_inner(
        source: &SwiftSource,
        params: SwiftSuccessorParams,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> R<Self> {
        let mut entropy = entropy;
        let r = guard(|| {
            if entropy.len() != 64 {
                return Err(AccountError::bound(
                    "a successor genesis takes 64 bytes: the new vault seed, the slots' entropy",
                ));
            }
            let seeds = [
                fixed::<32>(&entropy[..32], "vault seed")?,
                fixed::<32>(&entropy[32..], "slot entropy")?,
            ];
            let p = core_params(params)?;
            let c = source.with_library(|lib, entries| {
                Ok(SwiftSuccessor::begin(
                    lib,
                    entries.to_vec(),
                    p,
                    seeds[0],
                    seeds[1],
                    now_ms,
                )?)
            })?;
            let stage = if c.prf_requests().is_empty() {
                CreateStage::Genesis
            } else {
                CreateStage::Prf
            };
            Ok(Self {
                st: Cell::new(Stage::Open(Box::new(c), stage)),
            })
        });
        wipe(&mut entropy);
        r
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SwiftSuccessorCreation {
    /// Where the genesis stands: `Prf` (assertions are needed first), `Genesis` (sign the
    /// steps), `Done` (take the result) or `Spent`.
    pub fn stage(&self) -> Result<CreateStage, AccountError> {
        guard(|| {
            Ok(match &*self.st.lock()? {
                Stage::Open(_, s) => *s,
                Stage::Done(_) => CreateStage::Done,
                Stage::Spent => CreateStage::Spent,
            })
        })
    }
    /// The PRF assertions to make first, in order; empty when none.
    pub fn prf_requests(&self) -> Result<Vec<PrfRequest>, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::Open(c, _) => Ok(cv::prf_requests(c.prf_requests())),
            _ => Ok(vec![]),
        })
    }
    /// The requests that rebuild a slot of a passkey the Swift library already had: ONE
    /// assertion each answers the request (the new salt first) and opens the Swift slot
    /// (the old salt second).
    pub fn ceremonies(&self) -> Result<Vec<SwiftCeremony>, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::Open(c, _) => Ok(c
                .ceremonies()
                .iter()
                .map(|x| SwiftCeremony {
                    request: x.request as u64,
                    old_slot: x.old_slot as u64,
                    controller: x.ceremony.controller.clone(),
                    rp: x.ceremony.rp.clone(),
                    credential: x.ceremony.credential.clone(),
                    old_salt: x.ceremony.old_salt.clone(),
                    new_salt: x.ceremony.new_request.salt.to_vec(),
                    challenge: x.ceremony.new_request.challenge.to_vec(),
                    user_verification: x.ceremony.user_verification,
                })
                .collect()),
            _ => Ok(vec![]),
        })
    }
    /// Controllers whose new request has no old PRF route: their assertion evaluates the new
    /// salt only.
    pub fn unpaired(&self) -> Result<Vec<String>, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::Open(c, _) => Ok(c.unpaired().to_vec()),
            _ => Ok(vec![]),
        })
    }
    /// The exact bodies to sign: the genesis (with its possession proofs), then the `handover`
    /// signatures of the predecessor's keys.
    pub fn steps(&self) -> Result<Vec<AccountSigningStep>, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::Open(c, _) => Ok(cv::steps(c.steps())),
            _ => Ok(vec![]),
        })
    }
    /// Give the PRF answers (consumed and wiped), one per request in order.
    pub fn provide_prf(&self, results: Vec<PrfAnswer>) -> Result<(), AccountError> {
        guard(|| {
            let r = cv::prf_answers(results)?;
            let mut g = self.st.lock()?;
            let Stage::Open(c, _) = std::mem::replace(&mut *g, Stage::Spent) else {
                return Err(AccountError::consumed("this genesis is done or failed"));
            };
            *g = Stage::Open(Box::new(c.provide_prf(r)?), CreateStage::Genesis);
            Ok(())
        })
    }
    /// Give the signatures for `steps`, in order. The genesis is checked by the history verifier
    /// over the predecessor before it is accepted. Returns `Done`.
    pub fn provide_signatures(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<CreateStage, AccountError> {
        guard(|| {
            let sigs = cv::signatures(signatures)?;
            let mut g = self.st.lock()?;
            let Stage::Open(c, _) = std::mem::replace(&mut *g, Stage::Spent) else {
                return Err(AccountError::consumed("this genesis is done or failed"));
            };
            *g = Stage::Done(Box::new(c.finish(sigs)?));
            Ok(CreateStage::Done)
        })
    }
    /// The successor account's ID and the objects to store: the genesis at
    /// `authority/00000001.json` and the predecessor's entries at
    /// `predecessor/authority/<seq>.json`. The new seed is gone: open an `AccountEngine` over the
    /// stores and unlock it by a slot.
    pub fn take_result(&self) -> Result<Created, AccountError> {
        guard(|| {
            let mut g = self.st.lock()?;
            match std::mem::replace(&mut *g, Stage::Spent) {
                Stage::Done(r) => {
                    let mut stores = vec![Store {
                        path: "authority/00000001.json".into(),
                        bytes: r.genesis.clone(),
                    }];
                    for (seq, bytes) in &r.predecessor {
                        stores.push(Store {
                            path: format!("predecessor/authority/{seq:08}.json"),
                            bytes: bytes.clone(),
                        });
                    }
                    Ok(Created {
                        account: r.account.clone(),
                        stores,
                    })
                }
                other => {
                    *g = other;
                    Err(AccountError::consumed("the genesis is not finished"))
                }
            }
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl SwiftSuccessorCreation {
    /// Start the genesis of the account that succeeds the Swift library `source` read, at
    /// `now_ms`. `entropy` is 64 fresh bytes: the new vault's seed, then the slots' entropy
    /// (wiped).
    #[uniffi::constructor]
    pub fn begin(
        source: std::sync::Arc<SwiftSource>,
        params: SwiftSuccessorParams,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::begin_inner(&source, params, now_ms, entropy).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SwiftSuccessorCreation {
    /// Start the genesis of the account that succeeds the Swift library `source` read.
    pub fn begin(
        source: &SwiftSource,
        params: SwiftSuccessorParams,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> Result<SwiftSuccessorCreation, AccountError> {
        Self::begin_inner(source, params, now_ms, entropy)
    }
}
