//! Moving an old library: the 0.4 in-place upgrade (§16.1) and the Swift succession (§16.2,
//! §15.1). Each step is prepared with exact bodies the host signs and finished from the core's
//! own retained state. The Swift copy (`CopyPlan` and its translator) is not exported here.
use super::account::{changes_json, AccountCore};
use super::action::{signatures, step_json, steps_json};
use super::fault::AccountError;
use super::json::*;
use super::{guard, lock};
use colophon_core::v05::account::{Account, MoveStage, Moved, PendingMove};
use colophon_core::v05::write::succession::PendingFreeze;
use colophon_core::v05::write::swift_veto::{PendingSwiftVeto, SwiftVetoParams};
use colophon_core::v05::write::upgrade::{PendingUpgrade, UpgradeParams};
use serde_json::{json, Value};
use std::sync::Mutex;

type R<T> = Result<T, AccountError>;

enum Prepared {
    Upgrade(PendingUpgrade),
    Veto(PendingSwiftVeto),
    Move(PendingMove),
}

/// A prepared step of moving an old library. One-shot.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountMove {
    st: Mutex<Option<Prepared>>,
    owner: u64,
}

impl AccountMove {
    fn upgrade_inner(history: String, params: String, now_ms: i64) -> R<Self> {
        guard(|| {
            let h = parse(&history, "the 0.4 history")?;
            let o = obj(&h, "the 0.4 history")?;
            if o.len() > MAX_LIST {
                return Err(AccountError::bound("too many records"));
            }
            let mut legacy = colophon_core::model::Records::new();
            for (path, v) in o {
                let s = v
                    .as_str()
                    .ok_or_else(|| AccountError::bad("a record is base64"))?;
                legacy.insert(path.clone(), decode(s, "record")?);
            }
            let p = parse(&params, "the upgrade settings")?;
            let up = UpgradeParams {
                policy: p.get("policy").cloned().unwrap_or(Value::Null),
                add_threshold: uint(&p, "addThreshold")?,
                count_by: text(&p, "countBy")?.to_string(),
                issued_ms: int(&p, "issuedMs")?,
                signers: names(&p, "signers")?,
            };
            let pending = Account::begin_upgrade(&legacy, &up, now_ms)?;
            Ok(Self {
                st: Mutex::new(Some(Prepared::Upgrade(pending))),
                owner: 0,
            })
        })
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountMove {
    /// What this step is: `upgrade`, `swiftVeto`, `swiftFreeze`, `swiftMigration`, `renewShares`.
    pub fn kind(&self) -> Result<String, AccountError> {
        guard(|| {
            Ok(match lock(&self.st)?.as_ref() {
                None => "spent",
                Some(Prepared::Upgrade(_)) => "upgrade",
                Some(Prepared::Veto(_)) => "swiftVeto",
                Some(Prepared::Move(PendingMove::Freeze(_))) => "swiftFreeze",
                Some(Prepared::Move(PendingMove::Migration(_))) => "swiftMigration",
                Some(Prepared::Move(PendingMove::Shares(_))) => "renewShares",
            }
            .into())
        })
    }
    /// The exact bodies to sign, as JSON steps.
    pub fn steps(&self) -> Result<String, AccountError> {
        guard(|| {
            let g = lock(&self.st)?;
            let s = g
                .as_ref()
                .ok_or_else(|| AccountError::consumed("this step is finished"))?;
            to_string(&steps_json(match s {
                Prepared::Upgrade(u) => u.steps(),
                Prepared::Veto(v) => v.steps(),
                Prepared::Move(m) => m.steps(),
            }))
        })
    }
    /// Finish an upgrade or a veto (not tied to an account) with the host's signatures. An
    /// upgrade returns `{"entries":[{seq,bytes}]}`: store each at `authority/<seq>.json`, then
    /// open the account over the 0.4 entries plus this one. A veto returns `{"veto": base64}`.
    /// A step of a move is finished on its account by `AccountCore.finish_move`.
    pub fn finish(&self, signatures_json: String) -> Result<String, AccountError> {
        guard(|| {
            let sigs = signatures(&signatures_json)?;
            let mut g = lock(&self.st)?;
            match g.take() {
                Some(Prepared::Upgrade(u)) => {
                    let r = u.finish(sigs)?;
                    to_string(&json!({
                        "entries": r.entries.iter().map(|(s, b)| json!({"seq": s, "bytes": enc(b)})).collect::<Vec<_>>(),
                        "pending": bytes_list(&r.pending),
                        "evidence": bytes_list(&r.evidence),
                    }))
                }
                Some(Prepared::Veto(v)) => {
                    to_string(&json!({"veto": enc(&v.finish(sigs)?)}))
                }
                Some(other) => {
                    *g = Some(other);
                    Err(AccountError::bad(
                        "this step is finished on its account with finish_move",
                    ))
                }
                None => Err(AccountError::consumed("this step is finished")),
            }
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountMove {
    /// Prepare the in-place upgrade (§16.1) of a 0.4 account. `history` is the JSON object
    /// `{"authority/00000001.json": base64, ...}` of its authority records; `params` is
    /// `{"policy","addThreshold","countBy","issuedMs","signers"}`; `now_ms` the clock. A plain
    /// 0.4 history is not an account yet, so this takes none.
    #[uniffi::constructor]
    pub fn begin_upgrade(
        history: String,
        params: String,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::upgrade_inner(history, params, now_ms).map(std::sync::Arc::new)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountMove {
    pub fn begin_upgrade(
        history: String,
        params: String,
        now_ms: i64,
    ) -> Result<AccountMove, AccountError> {
        Self::upgrade_inner(history, params, now_ms)
    }
}

fn stage_name(s: MoveStage) -> &'static str {
    match s {
        MoveStage::WindowNotOpen => "windowNotOpen",
        MoveStage::Waiting => "waiting",
        MoveStage::Due => "due",
        MoveStage::Frozen => "frozen",
        MoveStage::Verified => "verified",
        MoveStage::Vetoed => "vetoed",
        MoveStage::Migrated => "migrated",
    }
}

impl AccountCore {
    fn wrap_move(&self, p: Prepared) -> AccountMove {
        AccountMove {
            st: Mutex::new(Some(p)),
            owner: self.owner,
        }
    }
    fn veto_inner(&self, issued_ms: i64, signers: String) -> R<AccountMove> {
        guard(|| {
            let s = names_of(&parse(&signers, "signers")?, "signers")?;
            let p = lock(&self.acc)?.begin_swift_veto(&SwiftVetoParams {
                issued_ms,
                signers: s,
            })?;
            Ok(self.wrap_move(Prepared::Veto(p)))
        })
    }
    fn freeze_inner(&self, signers: String, issued_ms: i64) -> R<AccountMove> {
        guard(|| {
            let s = names_of(&parse(&signers, "signers")?, "signers")?;
            let p = lock(&self.acc)?.begin_swift_freeze(Vec::new(), s, issued_ms)?;
            Ok(self.wrap_move(Prepared::Move(p)))
        })
    }
    fn shares_inner(&self, member: String, signers: String, mut entropy: Vec<u8>) -> R<AccountMove> {
        guard(|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            entropy.fill(0);
            let s = names_of(&parse(&signers, "signers")?, "signers")?;
            let p = lock(&self.acc)?.begin_swift_copier_shares(&member, &s, seed)?;
            Ok(self.wrap_move(Prepared::Move(p)))
        })
    }
    fn finish_move_inner(&self, step: &AccountMove, signatures_json: String) -> R<String> {
        guard(|| {
            let sigs = signatures(&signatures_json)?;
            if step.owner != self.owner {
                return Err(AccountError::wrong_object(
                    "this step was prepared by another account object",
                ));
            }
            let p = match lock(&step.st)?.take() {
                Some(Prepared::Move(m)) => m,
                Some(other) => {
                    *lock(&step.st)? = Some(other);
                    return Err(AccountError::bad("this step is not finished on an account"));
                }
                None => return Err(AccountError::consumed("this step is finished")),
            };
            match lock(&self.acc)?.finish_move(p, sigs)? {
                Moved::Frozen(f) => to_string(&json!({
                    "moved": "frozen", "entry": enc(&f.entry), "seq": f.seq,
                    "successionVerified": f.succession_verified,
                })),
                Moved::Migration(c) => to_string(&json!({"moved": "migration", "changes": ser_value!(*c)?})),
                Moved::Shares(c) => to_string(&json!({"moved": "shares", "changes": ser_value!(*c)?})),
            }
        })
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountCore {
    /// Where the Swift succession this account claims stands: `{"stage", "status":{..}}`.
    pub fn swift_succession(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = lock(&self.acc)?.swift_succession()?;
            let st = &s.status;
            to_string(&json!({
                "stage": stage_name(s.stage),
                "status": {
                    "format": st.format, "predecessor": st.predecessor, "headSeq": st.head_seq,
                    "headDigest": st.head_digest, "genesisDigest": st.genesis_digest,
                    "handoverCount": st.handover_count, "authorized": st.authorized,
                    "vetoed": st.vetoed, "verified": st.verified.as_ref().map(|(s, d)| json!([s, d])),
                    "timing": st.timing.as_ref().map(|t| json!({
                        "windowStartMs": t.window_start_ms, "windowEndMs": t.window_end_ms,
                        "recoveryDelayS": t.recovery_delay_s, "vetoDeadlineMs": t.veto_deadline_ms,
                        "dueMs": t.due_ms, "quorum": t.quorum, "homes": t.homes,
                        "vetoers": t.vetoers, "keysNeeded": t.keys_needed})),
                },
            }))
        })
    }
    /// The verified Swift predecessor history this account holds, for showing a person the
    /// last entries before they confirm.
    pub fn swift_predecessor(&self) -> Result<String, AccountError> {
        guard(|| {
            let h = lock(&self.acc)?.swift_predecessor()?;
            to_string(&json!({"account": h.account, "entries": h.entries.iter().map(|r| json!({
                "seq": r.value.get("seq"), "digest": r.digest, "issuedMs": r.issued_ms,
                "layout": r.value.get("layout")})).collect::<Vec<_>>()}))
        })
    }
    /// Take F (or any predecessor entry) the Swift side wrote into this account's predecessor
    /// objects; the verifier then judges the succession over it.
    pub fn accept_predecessor_entry(&self, entry: Vec<u8>, now_ms: i64) -> Result<String, AccountError> {
        guard(|| {
            bounded(&entry, 3 << 20, "an entry")?;
            changes_json(&lock(&self.acc)?.accept_predecessor_entry(entry, now_ms)?)
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountCore {
    /// Prepare the owner's veto of this account's Swift succession (§15.1 step 3): `signers`
    /// is a JSON array of predecessor controller IDs.
    pub fn begin_swift_veto(
        &self,
        issued_ms: i64,
        signers: String,
    ) -> Result<std::sync::Arc<AccountMove>, AccountError> {
        self.veto_inner(issued_ms, signers).map(std::sync::Arc::new)
    }
    /// Prepare F (§15.1 step 5): the freezing `layout` entry of the Swift predecessor.
    pub fn begin_swift_freeze(
        &self,
        signers: String,
        issued_ms: i64,
    ) -> Result<std::sync::Arc<AccountMove>, AccountError> {
        self.freeze_inner(signers, issued_ms).map(std::sync::Arc::new)
    }
    /// Seal the epochs a copying member is owed (§9.4), without touching its expiry.
    pub fn begin_swift_copier_shares(
        &self,
        member: String,
        signers: String,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<AccountMove>, AccountError> {
        self.shares_inner(member, signers, entropy).map(std::sync::Arc::new)
    }
    /// Finish a step of the move on this account. F is returned as bytes and held at once.
    pub fn finish_move(
        &self,
        step: std::sync::Arc<AccountMove>,
        signatures: String,
    ) -> Result<String, AccountError> {
        self.finish_move_inner(&step, signatures)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountCore {
    pub fn begin_swift_veto(&self, issued_ms: i64, signers: String) -> Result<AccountMove, AccountError> {
        self.veto_inner(issued_ms, signers)
    }
    pub fn begin_swift_freeze(&self, signers: String, issued_ms: i64) -> Result<AccountMove, AccountError> {
        self.freeze_inner(signers, issued_ms)
    }
    pub fn begin_swift_copier_shares(
        &self,
        member: String,
        signers: String,
        entropy: Vec<u8>,
    ) -> Result<AccountMove, AccountError> {
        self.shares_inner(member, signers, entropy)
    }
    pub fn finish_move(&self, step: &AccountMove, signatures: String) -> Result<String, AccountError> {
        self.finish_move_inner(step, signatures)
    }
}
#[allow(dead_code)]
fn _u(_: PendingFreeze) {
    let _ = step_json;
}
