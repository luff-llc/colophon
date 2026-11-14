//! Moving an old library: the 0.4 in-place upgrade (§16.1) and the Swift succession (§16.2,
//! §15.1). Each step is prepared with exact bodies the host signs and finished from the core's
//! own retained state. An upgrade or a veto finishes on its own (it needs no account); F, a
//! copier's shares and a migration finish on the engine (`finish_move`), which holds what they
//! change.
use super::convert as cv;
use super::create::pending_path;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::account::{Account, MoveStage as CoreStage, PendingMove};
use colophon_core::v05::write::swift_veto::PendingSwiftVeto;
use colophon_core::v05::write::upgrade::{PendingUpgrade, UpgradeParams as CoreUpgrade};
#[allow(unused_imports)]
use std::sync::Arc;

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

pub(crate) fn stage(s: CoreStage) -> MoveStage {
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
    pub(crate) fn of_move(p: PendingMove) -> Self {
        Self::of(Prepared::Move(p))
    }
    pub(crate) fn take_move(&self) -> R<PendingMove> {
        let mut g = self.st.lock()?;
        match g.take() {
            Some(Prepared::Move(m)) => Ok(m),
            Some(other) => {
                *g = Some(other);
                Err(AccountError::bad(
                    "this step is finished on its own: finish",
                ))
            }
            None => Err(AccountError::consumed("this step is finished")),
        }
    }
    pub(crate) fn of_veto(v: PendingSwiftVeto) -> Self {
        Self::of(Prepared::Veto(v))
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
                changes: None,
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
                Some(m @ Prepared::Move(_)) => {
                    *g = Some(m);
                    Err(AccountError::bad(
                        "this step is finished on the engine that prepared it: finish_move",
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
