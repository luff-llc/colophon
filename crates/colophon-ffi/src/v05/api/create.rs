//! Creating an account: genesis, the first `rekey` and the first slots, in as many rounds as
//! the ceremonies need. This is the one place an account is made before any store exists: the
//! result is the account ID and everything to store, and the session then opens an
//! `AccountEngine` over those stores and unlocks it by a slot as any session does.
use super::convert as cv;
use super::engine::identity_of as identity_of_record;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::account::{
    default_policy, Account, CreateParams as CoreParams, CreateProgress, Creation,
};
use colophon_core::v05::encoding::{digest, strict_parse};
use colophon_core::v05::slots::SlotPlan as CoreSlotPlan;
use serde_json::Value;

type R<T> = Result<T, AccountError>;

enum Stage {
    Open(Box<Creation>, CreateStage),
    Done(Box<Account>),
    /// The result was taken: the account is kept, unlocked, for `open_engine`.
    Taken(Box<Account>),
    Spent,
}

/// A creation in progress. One-shot at each step: a step that fails ends the creation.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountCreation {
    st: Cell<Stage>,
}

fn body_of(env: &[u8]) -> R<Value> {
    let v = strict_parse(env)?;
    let text = v
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| AccountError::internal("an object without a body"))?;
    let raw = colophon_core::v05::encoding::decode_base64(text, 1 << 22)?;
    Ok(strict_parse(&raw)?)
}
/// Where a pending object (a transition, veto or receipt) is stored.
pub(crate) fn pending_path(p: &[u8]) -> R<String> {
    let b = body_of(p)?;
    let raw = colophon_core::v05::encoding::decode_base64(
        strict_parse(p)?
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        1 << 22,
    )?;
    Ok(match b.get("protocol").and_then(Value::as_str) {
        Some("colophon/veto/5") => format!("vetoes/{}.json", digest(&raw)),
        Some("colophon/receipt/5") => format!(
            "receipts/{}/{}.receipt.json",
            b.get("object").and_then(Value::as_str).unwrap_or_default(),
            b.get("by").and_then(Value::as_str).unwrap_or_default()
        ),
        _ => format!("transitions/{}.json", digest(&raw)),
    })
}
/// Where everything an account holds is stored.
fn account_stores(a: &Account) -> R<Vec<Store>> {
    let mut out = Vec::new();
    let o = a.objects();
    for e in &o.entries {
        let seq = body_of(e)?
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| AccountError::internal("an entry without a seq"))?;
        out.push(Store {
            path: format!("authority/{seq:08}.json"),
            bytes: e.clone(),
        });
    }
    for p in &o.pending {
        out.push(Store {
            path: pending_path(p)?,
            bytes: p.clone(),
        });
    }
    for r in a.records() {
        out.push(Store {
            path: r.path.clone(),
            bytes: r.bytes.clone(),
        });
    }
    Ok(out)
}

impl AccountCreation {
    fn begin_inner(
        params: CreateParams,
        identity_of: AccountIdentity,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> R<Self> {
        let mut entropy = entropy;
        let r = guard(|| {
            if entropy.len() != 96 {
                return Err(AccountError::bound(
                    "creation takes 96 bytes: the vault seed, the slot entropy, the epoch seed",
                ));
            }
            let seeds = [
                fixed::<32>(&entropy[..32], "vault seed")?,
                fixed::<32>(&entropy[32..64], "slot entropy")?,
                fixed::<32>(&entropy[64..], "epoch seed")?,
            ];
            if params.controllers.len() > 64 {
                return Err(AccountError::bound("a keyring has at most 64 controllers"));
            }
            let controllers = params
                .controllers
                .iter()
                .map(cv::controller_value)
                .collect::<R<Vec<_>>>()?;
            let p = CoreParams {
                label: params.label,
                namespaces: names(params.namespaces, "namespaces")?,
                controllers,
                slots: params
                    .slots
                    .into_iter()
                    .map(|s| {
                        Ok(CoreSlotPlan {
                            controllers: names(s.controllers, "slot controllers")?,
                            label: s.label,
                        })
                    })
                    .collect::<R<Vec<_>>>()?,
                threshold: params.threshold,
                recover_threshold: params.recover_threshold,
                add_threshold: params.add_threshold,
                count_by_holders: params.count_by_holders,
                policy: if params.policy_json.is_empty() {
                    None
                } else {
                    Some(auth_json(&params.policy_json, "policy")?)
                },
                signers: names(params.signers, "signers")?,
                rekey_signers: names(params.rekey_signers, "rekey signers")?,
                vault_seed: seeds[0],
                entropy: seeds[1],
                epoch_seed: seeds[2],
            };
            let c = Creation::begin(p, identity_of_record(&identity_of)?, now_ms)?;
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
impl AccountCreation {
    /// Where the creation stands.
    pub fn stage(&self) -> Result<CreateStage, AccountError> {
        guard(|| {
            Ok(match &*self.st.lock()? {
                Stage::Open(_, s) => *s,
                Stage::Done(_) | Stage::Taken(_) => CreateStage::Done,
                Stage::Spent => CreateStage::Spent,
            })
        })
    }
    /// The PRF assertions to make first; empty when none.
    pub fn prf_requests(&self) -> Result<Vec<PrfRequest>, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::Open(c, _) => Ok(cv::prf_requests(c.prf_requests())),
            _ => Ok(vec![]),
        })
    }
    /// The exact bodies to sign now.
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
                return Err(AccountError::consumed("this creation is done or failed"));
            };
            *g = Stage::Open(Box::new(c.provide_prf(r)?), CreateStage::Genesis);
            Ok(())
        })
    }
    /// Give the signatures for `steps`, in order. Returns the next stage: `Rekey` (read `steps`
    /// again) or `Done` (take the result).
    pub fn provide_signatures(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<CreateStage, AccountError> {
        guard(|| {
            let sigs = cv::signatures(signatures)?;
            let mut g = self.st.lock()?;
            let Stage::Open(c, _) = std::mem::replace(&mut *g, Stage::Spent) else {
                return Err(AccountError::consumed("this creation is done or failed"));
            };
            Ok(match c.provide_signatures(sigs)? {
                CreateProgress::Continue(c) => {
                    *g = Stage::Open(c, CreateStage::Rekey);
                    CreateStage::Rekey
                }
                CreateProgress::Done(a) => {
                    *g = Stage::Done(a);
                    CreateStage::Done
                }
            })
        })
    }
    /// The created account: its ID and every object and record to store. Store them, then
    /// call `open_engine` for the session over them, unlocked as the creation left it (the owner
    /// is not asked again). The creation keeps the unlocked account until then, or until it is
    /// dropped.
    pub fn take_result(&self) -> Result<Created, AccountError> {
        guard(|| {
            let mut g = self.st.lock()?;
            match std::mem::replace(&mut *g, Stage::Spent) {
                Stage::Done(a) => {
                    let created = Created {
                        account: a.id().as_str().to_string(),
                        stores: account_stores(&a)?,
                    };
                    *g = Stage::Taken(a);
                    Ok(created)
                }
                other => {
                    *g = other;
                    Err(AccountError::consumed("the creation is not finished"))
                }
            }
        })
    }
}

impl AccountCreation {
    pub(crate) fn open_engine_inner(
        &self,
        source: Box<dyn super::HostSource>,
        listing: Vec<ListedPath>,
        namespaces: Vec<String>,
        batch: u64,
        key: Vec<u8>,
        now_ms: i64,
    ) -> R<super::engine::AccountEngine> {
        let mut key = key;
        let taken = guard(|| {
            let mut g = self.st.lock()?;
            match std::mem::replace(&mut *g, Stage::Spent) {
                Stage::Taken(a) | Stage::Done(a) => Ok(a),
                other => {
                    *g = other;
                    Err(AccountError::consumed(
                        "the creation is not finished, or its engine was opened",
                    ))
                }
            }
        });
        let account = match taken {
            Ok(a) => a,
            Err(e) => {
                wipe(&mut key);
                return Err(e);
            }
        };
        super::engine::AccountEngine::open_created_inner(
            source, listing, *account, namespaces, batch, key, now_ms,
        )
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountCreation {
    /// The session over the stores `take_result` returned (the host stored them and lists them),
    /// unlocked as the creation left it, its records loaded: a passkey owner is asked once at
    /// first run. The engine checks that the source holds exactly what the creation made. One
    /// shot: the creation is spent after it, and dropped without it the unlocked account goes.
    /// Arguments as `AccountEngine.open` (no identity: the creation's; no saved state).
    pub fn open_engine(
        &self,
        source: Box<dyn super::HostSource>,
        listing: Vec<ListedPath>,
        namespaces: Vec<String>,
        batch: u64,
        key: Vec<u8>,
        now_ms: i64,
    ) -> Result<std::sync::Arc<super::engine::AccountEngine>, AccountError> {
        self.open_engine_inner(source, listing, namespaces, batch, key, now_ms)
            .map(std::sync::Arc::new)
    }
    /// Start a creation as `identity` (a controller of the new keyring, or a member the account
    /// will have) at `now_ms`. `entropy` is 96 fresh bytes: the new vault's seed, the slots' entropy, the first epochs'
    /// seed (wiped). The host chose the vault seed and so can read what is sealed to it.
    #[uniffi::constructor]
    pub fn begin(
        params: CreateParams,
        identity: AccountIdentity,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::begin_inner(params, identity, now_ms, entropy).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountCreation {
    /// Start a creation as `identity` at `now_ms`.
    pub fn begin(
        params: CreateParams,
        identity: AccountIdentity,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> Result<AccountCreation, AccountError> {
        Self::begin_inner(params, identity, now_ms, entropy)
    }
}

/// The §18 person default policy as a JSON document, for a host that shows or adjusts it.
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn account_default_policy() -> Result<String, AccountError> {
    guard(|| to_json(&default_policy()))
}

/// A typed controller as its protocol JSON (§6.1), for a host that puts it in the `keyring.add` of
/// a `change` it builds itself (§8.7), for example beside `homes.appoint` in one transition. The
/// same JSON `begin_add_controller` and creation use; the core validates it again when it signs.
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn account_controller_json(controller: ControllerSpec) -> Result<String, AccountError> {
    guard(|| to_json(&cv::controller_value(&controller)?))
}
