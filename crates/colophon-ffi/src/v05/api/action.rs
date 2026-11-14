//! A prepared action: what to sign, held by the core until it is finished.
//!
//! The host reads copies of the exact bodies and signs them. It cannot alter what is held:
//! finishing takes the signatures only, and the core assembles the bytes from its own retained
//! state and verifies them under the history verifier before anything changes.
use super::convert as cv;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::account::PendingAction;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
/// A process-unique number for an engine, so an action finished on another session than the one
/// that prepared it is refused.
pub(crate) fn next_owner() -> u64 {
    NEXT_OWNER.fetch_add(1, Ordering::Relaxed)
}

pub(crate) struct ActState {
    pub pending: Option<PendingAction>,
    pub denial: Option<AccountDenial>,
    pub owner: u64,
    pub kind: String,
}

/// A prepared action. One-shot: finishing (or a failed finish) consumes it.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountAction {
    pub(crate) st: Cell<ActState>,
}

impl AccountAction {
    pub(crate) fn ready(pending: PendingAction, owner: u64, kind: &str) -> Self {
        Self {
            st: Cell::new(ActState {
                pending: Some(pending),
                denial: None,
                owner,
                kind: kind.into(),
            }),
        }
    }
    pub(crate) fn denied(d: &colophon_core::model::Denial, owner: u64, kind: &str) -> Self {
        Self {
            st: Cell::new(ActState {
                pending: None,
                denial: Some(cv::denial(d)),
                owner,
                kind: kind.into(),
            }),
        }
    }
    /// Take the pending action out for finishing, checking it belongs to `owner`.
    pub(crate) fn take(&self, owner: u64) -> Result<PendingAction, AccountError> {
        let mut s = self.st.lock()?;
        if s.owner != owner {
            return Err(AccountError::wrong_object(
                "this action was prepared by another session",
            ));
        }
        s.pending
            .take()
            .ok_or_else(|| AccountError::consumed("this action is finished, failed or denied"))
    }
    pub(crate) fn put_back(&self, p: PendingAction) -> Result<(), AccountError> {
        self.st.lock()?.pending = Some(p);
        Ok(())
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountAction {
    /// What kind of action this is (`approve`, `revoke`, `write`, ...).
    pub fn kind(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.st.lock()?.kind.clone()))
    }
    /// The access refusal of a write the account would not allow, or none. A denied action has
    /// no steps and cannot be finished.
    pub fn denial(&self) -> Result<Option<AccountDenial>, AccountError> {
        guard(|| {
            Ok(self.st.lock()?.denial.as_ref().map(|d| AccountDenial {
                reason: d.reason.clone(),
                detail: d.detail.clone(),
            }))
        })
    }
    /// The action's facts for display; none once it is finished or denied.
    pub fn info(&self) -> Result<Option<ActionInfo>, AccountError> {
        guard(|| {
            let s = self.st.lock()?;
            Ok(s.pending.as_ref().map(|p| cv::action_info(p.info())))
        })
    }
    /// The account this action is for (empty once finished or denied).
    pub fn account(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = self.st.lock()?;
            Ok(s.pending
                .as_ref()
                .map(|p| p.account().as_str().to_string())
                .unwrap_or_default())
        })
    }
    /// The exact bodies to sign, in the order the signatures are returned. Empty while PRF
    /// assertions are still needed.
    pub fn steps(&self) -> Result<Vec<AccountSigningStep>, AccountError> {
        guard(|| {
            let s = self.st.lock()?;
            Ok(s.pending
                .as_ref()
                .map(|p| cv::steps(p.steps()))
                .unwrap_or_default())
        })
    }
    /// The PRF assertions to make before the bodies exist; empty when none.
    pub fn prf_requests(&self) -> Result<Vec<PrfRequest>, AccountError> {
        guard(|| {
            let s = self.st.lock()?;
            Ok(s.pending
                .as_ref()
                .map(|p| cv::prf_requests(p.prf_requests()))
                .unwrap_or_default())
        })
    }
}
