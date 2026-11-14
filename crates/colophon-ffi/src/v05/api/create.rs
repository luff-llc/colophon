//! Creating an account: genesis, the first `rekey` and the first slots, in as many rounds as
//! the ceremonies need. The host never holds a half-built account: it reads what to do now
//! (PRF assertions, then bodies to sign), answers, and finally takes the account.
use super::account::{identity, AccountCore};
use super::action::{prf_requests_json, prf_results, signatures, steps_json};
use super::fault::AccountError;
use super::json::*;
use super::{guard, lock};
use colophon_core::v05::account::{default_policy, CreateParams, CreateProgress, Creation};
use colophon_core::v05::slots::SlotPlan;
use serde_json::Value;
use std::sync::Mutex;

type R<T> = Result<T, AccountError>;

enum Stage {
    Open(Box<Creation>),
    Done(Box<colophon_core::v05::account::Account>),
    Spent,
}

/// A creation in progress. One-shot at each step: a step that fails ends the creation.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountCreation {
    st: Mutex<Stage>,
}

impl AccountCreation {
    fn begin_inner(
        params: String,
        identity_text: String,
        now_ms: i64,
        mut entropy: Vec<u8>,
    ) -> R<Self> {
        guard(|| {
            if entropy.len() != 96 {
                return Err(AccountError::bound(
                    "creation takes 96 bytes: the vault seed, the slot entropy, the epoch seed",
                ));
            }
            let seeds: [[u8; 32]; 3] = [
                fixed::<32>(&entropy[..32], "vault seed")?,
                fixed::<32>(&entropy[32..64], "slot entropy")?,
                fixed::<32>(&entropy[64..], "epoch seed")?,
            ];
            entropy.fill(0);
            let v = parse(&params, "params")?;
            obj(&v, "params")?;
            let slots = list(&v, "slots")?
                .iter()
                .map(|s| {
                    Ok(SlotPlan {
                        controllers: names(s, "controllers")?,
                        label: text(s, "label")?.to_string(),
                    })
                })
                .collect::<R<Vec<_>>>()?;
            let opt_u = |k: &str| -> R<Option<u64>> {
                match v.get(k) {
                    None | Some(Value::Null) => Ok(None),
                    Some(x) => x
                        .as_u64()
                        .map(Some)
                        .ok_or_else(|| AccountError::bad(format!("`{k}` must be an integer"))),
                }
            };
            let p = CreateParams {
                label: text(&v, "label")?.to_string(),
                namespaces: names(&v, "namespaces")?,
                controllers: list(&v, "controllers")?.to_vec(),
                slots,
                threshold: opt_u("threshold")?,
                recover_threshold: opt_u("recoverThreshold")?,
                add_threshold: opt_u("addThreshold")?,
                count_by_holders: boolean(&v, "countByHolders", false)?,
                policy: v.get("policy").filter(|p| !p.is_null()).cloned(),
                signers: names(&v, "signers")?,
                rekey_signers: names(&v, "rekeySigners")?,
                vault_seed: seeds[0],
                entropy: seeds[1],
                epoch_seed: seeds[2],
            };
            let c = Creation::begin(p, identity(&identity_text)?, now_ms)?;
            Ok(Self {
                st: Mutex::new(Stage::Open(Box::new(c))),
            })
        })
    }
    fn provide_signatures_inner(&self, text_in: String) -> R<String> {
        guard(|| {
            let sigs = signatures(&text_in)?;
            let mut g = lock(&self.st)?;
            let Stage::Open(c) = std::mem::replace(&mut *g, Stage::Spent) else {
                return Err(AccountError::consumed("this creation is done or failed"));
            };
            match c.provide_signatures(sigs)? {
                CreateProgress::Continue(c) => {
                    *g = Stage::Open(c);
                    Ok("continue".into())
                }
                CreateProgress::Done(a) => {
                    *g = Stage::Done(a);
                    Ok("done".into())
                }
            }
        })
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountCreation {
    /// `prf`, `genesis`, `rekey`, `done` or `spent`.
    pub fn stage(&self) -> Result<String, AccountError> {
        guard(|| {
            Ok(match &*lock(&self.st)? {
                Stage::Open(c) => {
                    if !c.prf_requests().is_empty() {
                        "prf"
                    } else if c.steps().len() > 1 || format!("{c:?}").contains("genesis") {
                        "genesis"
                    } else {
                        "rekey"
                    }
                }
                Stage::Done(_) => "done",
                Stage::Spent => "spent",
            }
            .into())
        })
    }
    /// The PRF assertions to make first, as JSON; empty when none.
    pub fn prf_requests(&self) -> Result<String, AccountError> {
        guard(|| match &*lock(&self.st)? {
            Stage::Open(c) => to_string(&prf_requests_json(c.prf_requests())),
            _ => Ok("[]".into()),
        })
    }
    /// The exact bodies to sign now, as JSON steps.
    pub fn steps(&self) -> Result<String, AccountError> {
        guard(|| match &*lock(&self.st)? {
            Stage::Open(c) => to_string(&steps_json(c.steps())),
            _ => Ok("[]".into()),
        })
    }
    /// Give the PRF assertions and outputs, one per request in order.
    pub fn provide_prf(&self, results: String) -> Result<(), AccountError> {
        guard(|| {
            let r = prf_results(&results)?;
            let mut g = lock(&self.st)?;
            let Stage::Open(c) = std::mem::replace(&mut *g, Stage::Spent) else {
                return Err(AccountError::consumed("this creation is done or failed"));
            };
            *g = Stage::Open(Box::new(c.provide_prf(r)?));
            Ok(())
        })
    }
    /// Give the signatures for `steps`, in order. Returns `continue` (read `steps` again: the
    /// next round) or `done` (take the account).
    pub fn provide_signatures(&self, signatures: String) -> Result<String, AccountError> {
        self.provide_signatures_inner(signatures)
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountCreation {
    /// Start a creation. `params` is JSON: `label`, `namespaces`, `controllers` (protocol
    /// JSON), `slots` (`[{"controllers":[ids],"label"}]`), optional `threshold`,
    /// `recoverThreshold`, `addThreshold`, `countByHolders`, `policy`, and `signers` and
    /// `rekeySigners` (controller IDs). `identity` is `controller:<id>` or `member:<id>`.
    /// `entropy` is 96 fresh bytes: the new vault's seed, the slots' entropy, the first
    /// epochs' seed. The host chose the vault seed and so can read what is sealed to it.
    #[uniffi::constructor]
    pub fn begin(
        params: String,
        identity: String,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::begin_inner(params, identity, now_ms, entropy).map(std::sync::Arc::new)
    }
    /// The finished account, opened as the identity the creation named with its seed held.
    /// Store `AccountCore.stores()` before anything else.
    pub fn take_account(&self) -> Result<std::sync::Arc<AccountCore>, AccountError> {
        self.take_inner().map(std::sync::Arc::new)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountCreation {
    pub fn begin(
        params: String,
        identity: String,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> Result<AccountCreation, AccountError> {
        Self::begin_inner(params, identity, now_ms, entropy)
    }
    pub fn take_account(&self) -> Result<AccountCore, AccountError> {
        self.take_inner()
    }
}
impl AccountCreation {
    fn take_inner(&self) -> R<AccountCore> {
        guard(|| {
            let mut g = lock(&self.st)?;
            match std::mem::replace(&mut *g, Stage::Spent) {
                Stage::Done(a) => Ok(AccountCore::from(*a)),
                other => {
                    *g = other;
                    Err(AccountError::consumed("the creation is not finished"))
                }
            }
        })
    }
}

/// The §18 person default policy, as JSON, for a host that shows or adjusts it.
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn account_default_policy() -> Result<String, AccountError> {
    guard(|| to_string(&default_policy()))
}
