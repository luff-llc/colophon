//! The error every export returns: a typed variant plus the protocol's code string.
use super::types::{AccountDenialReason, SignatureCheck};
use colophon_core::v05::Failure;

/// A failed call. `code` is the protocol result code of §1 and §19 (`malformed`, `badSignature`,
/// `newerFormat`, `unavailable`, `refused:<reason>`) or one of the binding's own codes (`host`,
/// `reentered`, `consumed`, `wrongObject`, `bound`, `locked`, `integrity`, `internal`). Hosts branch on the variant or
/// the code, never on `detail`, which is for logs and never carries key material.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "native05", derive(uniffi::Error))]
pub enum AccountError {
    Malformed {
        code: String,
        detail: String,
    },
    /// `check` names the failed WebAuthn check of §4.3 when `code` is `badSignature:<check>`.
    BadSignature {
        code: String,
        check: Option<SignatureCheck>,
        detail: String,
    },
    NewerFormat {
        code: String,
        detail: String,
    },
    Unavailable {
        code: String,
        detail: String,
    },
    /// `reason` is the §19 spelling without the prefix (`audience`, `window`, `replay`, ...).
    Refused {
        code: String,
        reason: String,
        detail: String,
    },
    /// A host callback failed or returned something unusable.
    Host {
        code: String,
        detail: String,
    },
    /// A callback called back into the object that was calling it.
    Reentered {
        code: String,
        detail: String,
    },
    /// A prepared action or one-shot object was already used.
    Consumed {
        code: String,
        detail: String,
    },
    /// An object of another session or account was passed.
    WrongObject {
        code: String,
        detail: String,
    },
    /// An argument exceeded a bound or had the wrong length.
    Bound {
        code: String,
        detail: String,
    },
    Internal {
        code: String,
        detail: String,
    },
    /// The grant or key does not allow it now: `reason` is notGranted, revoked, expired,
    /// budgetSpent, notReadable or unavailable.
    Denied {
        code: String,
        reason: AccountDenialReason,
        reason_raw: Option<String>,
        detail: String,
    },
    /// The engine found its own source or home inconsistent and is unusable: discard it and
    /// open a new one. Not a mistake in the call.
    Integrity {
        code: String,
        detail: String,
    },
    /// `lock` was called: the engine no longer unlocks, loads, saves, prepares or finishes
    /// anything. Open a new engine.
    Locked {
        code: String,
        detail: String,
    },
}
impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}
impl std::error::Error for AccountError {}

fn cap(s: &str) -> String {
    s.chars().take(512).collect()
}
impl AccountError {
    pub fn code(&self) -> String {
        match self {
            Self::Refused { code, .. }
            | Self::Malformed { code, .. }
            | Self::BadSignature { code, .. }
            | Self::NewerFormat { code, .. }
            | Self::Unavailable { code, .. }
            | Self::Host { code, .. }
            | Self::Reentered { code, .. }
            | Self::Consumed { code, .. }
            | Self::WrongObject { code, .. }
            | Self::Bound { code, .. }
            | Self::Internal { code, .. }
            | Self::Denied { code, .. }
            | Self::Integrity { code, .. }
            | Self::Locked { code, .. } => code.clone(),
        }
    }
    /// The §19 reason of a `Refused` or `Denied`, else none.
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Refused { reason, .. } => Some(reason.clone()),
            Self::Denied {
                reason, reason_raw, ..
            } => Some(super::convert::denial_reason_text(*reason, reason_raw)),
            _ => None,
        }
    }
    pub fn detail(&self) -> String {
        self.detail_text()
    }
    /// The variant's name, for a host that shows a class.
    pub fn kind(&self) -> String {
        match self {
            Self::Malformed { .. } => "Malformed",
            Self::BadSignature { .. } => "BadSignature",
            Self::NewerFormat { .. } => "NewerFormat",
            Self::Unavailable { .. } => "Unavailable",
            Self::Refused { .. } => "Refused",
            Self::Host { .. } => "Host",
            Self::Reentered { .. } => "Reentered",
            Self::Consumed { .. } => "Consumed",
            Self::WrongObject { .. } => "WrongObject",
            Self::Bound { .. } => "Bound",
            Self::Internal { .. } => "Internal",
            Self::Denied { .. } => "Denied",
            Self::Integrity { .. } => "Integrity",
            Self::Locked { .. } => "Locked",
        }
        .into()
    }
    pub(crate) fn detail_text(&self) -> String {
        match self {
            Self::Refused { detail, .. }
            | Self::Malformed { detail, .. }
            | Self::BadSignature { detail, .. }
            | Self::NewerFormat { detail, .. }
            | Self::Unavailable { detail, .. }
            | Self::Host { detail, .. }
            | Self::Reentered { detail, .. }
            | Self::Consumed { detail, .. }
            | Self::WrongObject { detail, .. }
            | Self::Bound { detail, .. }
            | Self::Internal { detail, .. }
            | Self::Denied { detail, .. }
            | Self::Integrity { detail, .. }
            | Self::Locked { detail, .. } => detail.clone(),
        }
    }
    pub fn denied(reason: &str, detail: &str) -> Self {
        let (r, raw) = super::convert::denial_reason(reason);
        Self::Denied {
            code: format!("denied:{reason}"),
            reason: r,
            reason_raw: raw,
            detail: cap(detail),
        }
    }
    pub fn locked() -> Self {
        Self::Locked {
            code: "locked".into(),
            detail: "the engine is locked: open a new one".into(),
        }
    }
    pub fn integrity(detail: impl AsRef<str>) -> Self {
        Self::Integrity {
            code: "integrity".into(),
            detail: cap(detail.as_ref()),
        }
    }
    pub fn host(detail: impl AsRef<str>) -> Self {
        Self::Host {
            code: "host".into(),
            detail: cap(detail.as_ref()),
        }
    }
    pub fn reentered() -> Self {
        Self::Reentered {
            code: "reentered".into(),
            detail: "a host callback called back into the object that was calling it".into(),
        }
    }
    pub fn consumed(what: &str) -> Self {
        Self::Consumed {
            code: "consumed".into(),
            detail: cap(what),
        }
    }
    pub fn wrong_object(what: &str) -> Self {
        Self::WrongObject {
            code: "wrongObject".into(),
            detail: cap(what),
        }
    }
    pub fn bound(what: &str) -> Self {
        Self::Bound {
            code: "bound".into(),
            detail: cap(what),
        }
    }
    pub fn internal(what: &str) -> Self {
        Self::Internal {
            code: "internal".into(),
            detail: cap(what),
        }
    }
    /// A malformed argument the host passed (JSON, base64, a wrong length).
    pub fn bad(what: impl AsRef<str>) -> Self {
        Self::Malformed {
            code: "malformed".into(),
            detail: cap(what.as_ref()),
        }
    }
}
impl From<Failure> for AccountError {
    fn from(f: Failure) -> Self {
        let code = f.code();
        let detail = cap(f.detail());
        match f {
            Failure::Malformed(_) => Self::Malformed { code, detail },
            Failure::BadSignature(_) => Self::BadSignature {
                code,
                check: None,
                detail,
            },
            Failure::NewerFormat(_) => Self::NewerFormat { code, detail },
            Failure::Unavailable(_) => Self::Unavailable { code, detail },
            Failure::Refused(r) => Self::Refused {
                code,
                reason: r.as_str().into(),
                detail,
            },
        }
    }
}
impl From<colophon_core::Error> for AccountError {
    fn from(e: colophon_core::Error) -> Self {
        Self::Unavailable {
            code: "unavailable".into(),
            detail: cap(&e.0),
        }
    }
}

/// Every §19 refusal reason, for the shared-names test.
pub const REFUSAL_REASONS: [&str; 20] = [
    "audience",
    "window",
    "replay",
    "conflict",
    "fork",
    "revoked",
    "expired",
    "ended",
    "notNarrower",
    "outOfScope",
    "origin",
    "rollback",
    "notGranted",
    "wrongEpoch",
    "clockJump",
    "budgetSpent",
    "wrongFormat",
    "invalidPayload",
    "caveatedLive",
    "vaultLocked",
];

/// A foreign exception that is not an `AccountError` (a Swift or Kotlin callback that threw
/// something else) is a host failure, not a crash.
#[cfg(feature = "native05")]
impl From<uniffi::UnexpectedUniFFICallbackError> for AccountError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        // The foreign error's own message, first line only: a Kotlin exception's reason carries
        // its whole stack trace.
        Self::host(e.reason.lines().next().unwrap_or_default())
    }
}
