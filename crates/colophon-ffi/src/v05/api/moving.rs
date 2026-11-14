//! Moving an old library: the 0.4 in-place upgrade (§16.1) and the Swift succession (§16.2,
//! §15.1). Each step is prepared with exact bodies the host signs and finished from the core's
//! own retained state. Finishing needs no account: it returns the bytes to store (and, for F,
//! the exact Swift entry). `todo` until the core's engine forwards `accept_predecessor_entry`
//! and a finish for the move steps (branch `engine-0.5-e9`): the account taking F in at once.
use super::convert as cv;
use super::create::pending_path;
use super::engine::AccountEngine;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::account::{Account, MoveStage as CoreStage, PendingMove};
use colophon_core::v05::write::swift_veto::{PendingSwiftVeto, SwiftVetoParams};
use colophon_core::v05::write::upgrade::{PendingUpgrade, UpgradeParams as CoreUpgrade};

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
    st: Cell<Option<Prepared>>,
}

fn stage(s: CoreStage) -> MoveStage {
    match s {
        CoreStage::WindowNotOpen => MoveStage::WindowNotOpen,
        CoreStage::Waiting => MoveStage::Waiting,
        CoreStage::Due => MoveStage::Due,
        CoreStage::Frozen => MoveStage::Frozen,
        CoreStage::Verified => MoveStage::Verified,
        CoreStage::Vetoed => MoveStage::Vetoed,
        CoreStage::Migrated => MoveStage::Migrated,
    }
}
fn entries_stores(entries: &[(u64, Vec<u8>)], pending: &[Vec<u8>]) -> R<Vec<Store>> {
    let mut out: Vec<Store> = entries
        .iter()
        .map(|(seq, b)| Store {
            path: format!("authority/{seq:08}.json"),
            bytes: b.clone(),
        })
        .collect();
    for p in pending {
        out.push(Store {
            path: pending_path(p)?,
            bytes: p.clone(),
        });
    }
    Ok(out)
}

impl AccountMove {
    fn upgrade_inner(history: LegacyHistory, params: UpgradeParams, now_ms: i64) -> R<Self> {
        guard(|| {
            list_len(&history.records, "records")?;
            let mut legacy = colophon_core::model::Records::new();
            for r in history.records {
                bytes_ok(&r.bytes, MAX_BYTES, "a record")?;
                legacy.insert(r.path, r.bytes);
            }
            let up = CoreUpgrade {
                policy: json(&params.policy_json, "the policy")?,
                add_threshold: params.add_threshold,
                count_by: params.count_by,
                issued_ms: params.issued_ms,
                signers: names(params.signers, "signers")?,
            };
            let pending = Account::begin_upgrade(&legacy, &up, now_ms)?;
            Ok(Self {
                st: Cell::new(Some(Prepared::Upgrade(pending))),
            })
        })
    }
    fn of(p: Prepared) -> Self {
        Self {
            st: Cell::new(Some(p)),
        }
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountMove {
    /// What this step is: `upgrade`, `swiftVeto`, `swiftFreeze`, `swiftMigration`, `renewShares`
    /// (empty once finished).
    pub fn kind(&self) -> Result<String, AccountError> {
        guard(|| {
            Ok(match self.st.lock()?.as_ref() {
                None => "",
                Some(Prepared::Upgrade(_)) => "upgrade",
                Some(Prepared::Veto(_)) => "swiftVeto",
                Some(Prepared::Move(PendingMove::Freeze(_))) => "swiftFreeze",
                Some(Prepared::Move(PendingMove::Migration(_))) => "swiftMigration",
                Some(Prepared::Move(PendingMove::Shares(_))) => "renewShares",
            }
            .into())
        })
    }
    /// The exact bodies to sign.
    pub fn steps(&self) -> Result<Vec<AccountSigningStep>, AccountError> {
        guard(|| {
            let g = self.st.lock()?;
            let s = g
                .as_ref()
                .ok_or_else(|| AccountError::consumed("this step is finished"))?;
            Ok(cv::steps(match s {
                Prepared::Upgrade(u) => u.steps(),
                Prepared::Veto(v) => v.steps(),
                Prepared::Move(m) => m.steps(),
            }))
        })
    }
    /// Finish with the host's signatures. `stores` are to be stored as given. An upgrade's entry
    /// goes to `authority/<seq>.json` beside the 0.4 entries. A veto returns `veto`. F returns
    /// `frozen_entry`: the exact Swift bytes the host appends to the predecessor and then gives
    /// the account (`todo`: `accept_predecessor_entry`).
    pub fn finish(&self, signatures: Vec<Signature>) -> Result<MoveResult, AccountError> {
        guard(|| {
            let sigs = cv::signatures(signatures)?;
            let mut g = self.st.lock()?;
            let none = |stores| MoveResult {
                stores,
                veto: None,
                frozen_entry: None,
                frozen_seq: None,
                succession_verified: false,
            };
            match g.take() {
                Some(Prepared::Upgrade(u)) => {
                    let r = u.finish(sigs)?;
                    Ok(none(entries_stores(&r.entries, &r.pending)?))
                }
                Some(Prepared::Veto(v)) => Ok(MoveResult {
                    veto: Some(v.finish(sigs)?),
                    ..none(vec![])
                }),
                Some(Prepared::Move(PendingMove::Freeze(f))) => {
                    let fr = f.finish(sigs)?;
                    Ok(MoveResult {
                        frozen_entry: Some(fr.entry),
                        frozen_seq: Some(fr.seq),
                        succession_verified: fr.succession_verified,
                        ..none(vec![])
                    })
                }
                Some(Prepared::Move(PendingMove::Migration(b) | PendingMove::Shares(b))) => {
                    let r = b.finish(sigs)?;
                    Ok(none(entries_stores(&r.entries, &r.pending)?))
                }
                None => Err(AccountError::consumed("this step is finished")),
            }
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountMove {
    /// Prepare the in-place upgrade (§16.1) of a 0.4 account from its authority records. A
    /// plain 0.4 history is not an account yet, so this needs no engine.
    #[uniffi::constructor]
    pub fn begin_upgrade(
        history: LegacyHistory,
        params: UpgradeParams,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::upgrade_inner(history, params, now_ms).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountMove {
    /// Prepare the in-place upgrade (§16.1) of a 0.4 account from its authority records.
    pub fn begin_upgrade(
        history: LegacyHistory,
        params: UpgradeParams,
        now_ms: i64,
    ) -> Result<AccountMove, AccountError> {
        Self::upgrade_inner(history, params, now_ms)
    }
}

impl AccountEngine {
    fn swift_prepare(&self, f: impl FnOnce(&Account) -> R<Prepared>) -> R<AccountMove> {
        self.acct(f).map(AccountMove::of)
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountEngine {
    /// Where the Swift succession this account claims stands.
    pub fn swift_succession(&self) -> Result<SwiftSuccession, AccountError> {
        self.acct(|a| {
            let s = a.swift_succession()?;
            let st = &s.status;
            Ok(SwiftSuccession {
                stage: stage(s.stage),
                format: st.format.clone(),
                predecessor: st.predecessor.clone(),
                head_seq: st.head_seq,
                head_digest: st.head_digest.clone(),
                genesis_digest: st.genesis_digest.clone(),
                handover_count: st.handover_count as u64,
                authorized: st.authorized,
                vetoed: st.vetoed,
                verified_seq: st.verified.as_ref().map(|(s, _)| *s),
                verified_digest: st.verified.as_ref().map(|(_, d)| d.clone()),
                timing: st.timing.as_ref().map(|t| SuccessionTiming {
                    window_start_ms: t.window_start_ms,
                    window_end_ms: t.window_end_ms,
                    recovery_delay_s: t.recovery_delay_s,
                    veto_deadline_ms: t.veto_deadline_ms,
                    due_ms: t.due_ms,
                    quorum: t.quorum as u64,
                    homes: t.homes.clone(),
                    vetoers: t.vetoers.iter().cloned().collect(),
                    keys_needed: t.keys_needed as u64,
                }),
            })
        })
    }
    /// The verified Swift predecessor history this account holds.
    pub fn swift_predecessor(&self) -> Result<SwiftPredecessor, AccountError> {
        self.acct(|a| {
            let h = a.swift_predecessor()?;
            Ok(SwiftPredecessor {
                account: h.account.clone(),
                entries: h
                    .entries
                    .iter()
                    .map(|r| SwiftEntry {
                        seq: r.value.get("seq").and_then(serde_json::Value::as_u64),
                        digest: r.digest.clone(),
                        issued_ms: r.issued_ms,
                        layout: r.value.get("layout").and_then(serde_json::Value::as_u64),
                    })
                    .collect(),
            })
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// Prepare the owner's veto of this account's Swift succession (§15.1 step 3).
    pub fn begin_swift_veto(
        &self,
        issued_ms: i64,
        signers: Vec<String>,
    ) -> Result<std::sync::Arc<AccountMove>, AccountError> {
        let s = names(signers, "signers")?;
        self.swift_prepare(|a| {
            Ok(Prepared::Veto(a.begin_swift_veto(&SwiftVetoParams {
                issued_ms,
                signers: s,
            })?))
        })
        .map(std::sync::Arc::new)
    }
    /// Prepare F (§15.1 step 5): the freezing `layout` entry of the Swift predecessor.
    pub fn begin_swift_freeze(
        &self,
        signers: Vec<String>,
        issued_ms: i64,
    ) -> Result<std::sync::Arc<AccountMove>, AccountError> {
        let s = names(signers, "signers")?;
        self.swift_prepare(|a| {
            Ok(Prepared::Move(a.begin_swift_freeze(
                Vec::new(),
                s,
                issued_ms,
            )?))
        })
        .map(std::sync::Arc::new)
    }
    /// Seal the epochs a copying member is owed (§9.4). 32 fresh bytes (wiped).
    pub fn begin_swift_copier_shares(
        &self,
        member: String,
        signers: Vec<String>,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<AccountMove>, AccountError> {
        let mut entropy = entropy;
        let r = (|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            let s = names(signers, "signers")?;
            self.swift_prepare(|a| {
                Ok(Prepared::Move(
                    a.begin_swift_copier_shares(&member, &s, seed)?,
                ))
            })
        })();
        wipe(&mut entropy);
        r.map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    /// Prepare the owner's veto of this account's Swift succession (§15.1 step 3).
    pub fn begin_swift_veto(
        &self,
        issued_ms: i64,
        signers: Vec<String>,
    ) -> Result<AccountMove, AccountError> {
        let s = names(signers, "signers")?;
        self.swift_prepare(|a| {
            Ok(Prepared::Veto(a.begin_swift_veto(&SwiftVetoParams {
                issued_ms,
                signers: s,
            })?))
        })
    }
    /// Prepare F (§15.1 step 5): the freezing `layout` entry of the Swift predecessor.
    pub fn begin_swift_freeze(
        &self,
        signers: Vec<String>,
        issued_ms: i64,
    ) -> Result<AccountMove, AccountError> {
        let s = names(signers, "signers")?;
        self.swift_prepare(|a| {
            Ok(Prepared::Move(a.begin_swift_freeze(
                Vec::new(),
                s,
                issued_ms,
            )?))
        })
    }
    /// Seal the epochs a copying member is owed (§9.4). 32 fresh bytes (wiped).
    pub fn begin_swift_copier_shares(
        &self,
        member: String,
        signers: Vec<String>,
        entropy: Vec<u8>,
    ) -> Result<AccountMove, AccountError> {
        let mut entropy = entropy;
        let r = (|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            let s = names(signers, "signers")?;
            self.swift_prepare(|a| {
                Ok(Prepared::Move(
                    a.begin_swift_copier_shares(&member, &s, seed)?,
                ))
            })
        })();
        wipe(&mut entropy);
        r
    }
}
