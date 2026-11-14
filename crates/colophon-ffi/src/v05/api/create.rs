//! Creating an account: genesis, the first `rekey` and the first slots, in as many rounds as
//! the ceremonies need. This is the one place an account is made before any store exists: the
//! result is the account ID and everything to store, and the session then opens an
//! `AccountEngine` over those stores and unlocks it by a slot as any session does.
use super::convert as cv;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::account::{
    default_policy, Account, CreateParams as CoreParams, CreateProgress, Creation, Identity,
};
use colophon_core::v05::encoding::{digest, strict_parse};
use colophon_core::v05::slots::SlotPlan as CoreSlotPlan;
use serde_json::Value;

type R<T> = Result<T, AccountError>;

enum Stage {
    Open(Box<Creation>, CreateStage),
    Done(Box<Account>),
    Spent,
}

/// A creation in progress. One-shot at each step: a step that fails ends the creation.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountCreation {
    st: Cell<Stage>,
}

fn identity(text: &str) -> R<Identity> {
    let (kind, id) = text
        .split_once(':')
        .ok_or_else(|| AccountError::bad("identity is `controller:<id>` or `member:<id>`"))?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AccountError::bad("identity names a 32-hex key ID"));
    }
    match kind {
        "controller" => Ok(Identity::Controller(id.into())),
        "member" => Ok(Identity::Member(id.into())),
        _ => Err(AccountError::bad(
            "identity is `controller:<id>` or `member:<id>`",
        )),
    }
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
        identity_text: String,
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
            let controllers = params
                .controllers_json
                .iter()
                .map(|c| json(c, "a controller"))
                .collect::<R<Vec<_>>>()?;
            if controllers.len() > MAX_NAMES {
                return Err(AccountError::bound("too many controllers"));
            }
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
                    Some(json(&params.policy_json, "policy")?)
                },
                signers: names(params.signers, "signers")?,
                rekey_signers: names(params.rekey_signers, "rekey signers")?,
                vault_seed: seeds[0],
                entropy: seeds[1],
                epoch_seed: seeds[2],
            };
            let c = Creation::begin(p, identity(&identity_text)?, now_ms)?;
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
                Stage::Done(_) => CreateStage::Done,
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
    /// The created account: its ID and every object and record to store. The seed the creation
    /// held is dropped; open an `AccountEngine` over the stores and unlock it by a slot.
    pub fn take_result(&self) -> Result<Created, AccountError> {
        guard(|| {
            let mut g = self.st.lock()?;
            match std::mem::replace(&mut *g, Stage::Spent) {
                Stage::Done(a) => Ok(Created {
                    account: a.id().as_str().to_string(),
                    stores: account_stores(&a)?,
                }),
                other => {
                    *g = other;
                    Err(AccountError::consumed("the creation is not finished"))
                }
            }
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountCreation {
    /// Start a creation as `identity` (`controller:<id>` or `member:<id>`) at `now_ms`.
    /// `entropy` is 96 fresh bytes: the new vault's seed, the slots' entropy, the first epochs'
    /// seed (wiped). The host chose the vault seed and so can read what is sealed to it.
    #[uniffi::constructor]
    pub fn begin(
        params: CreateParams,
        identity: String,
        now_ms: i64,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::begin_inner(params, identity, now_ms, entropy).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountCreation {
    /// Start a creation as `identity` (`controller:<id>` or `member:<id>`) at `now_ms`.
    pub fn begin(
        params: CreateParams,
        identity: String,
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
