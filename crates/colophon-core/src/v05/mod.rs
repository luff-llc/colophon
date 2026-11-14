//! Colophon 0.5 (candidate, revision 6): the foundation layers.
//!
//! **Not released, not frozen.** This module implements the parts of
//! `spec/colophon-0.5.md` that the reviewers consider stable: canonical encoding (§2),
//! identifiers and descriptors (§3, §5, §6.1, §6.3), signatures including WebAuthn (§4),
//! member and grant shapes with terms (§9, §10), `/5` operation headers (§11.2–§11.5 as far as
//! they need no namespace key rotation) and calls (§12) as a pure function over a given view.
//!
//! Deliberately **not** here: authority replay (§8.5), pending transitions (§8.7), conflict and
//! fork classification (§8.6), upgrade (§16.1) and succession (§15, §16.2–§16.3). The call
//! pipeline takes "is this controller pending addition or removal" as an input instead of
//! computing it. See `spec/colophon-0.5-implementation-notes.md`.
//!
//! The 0.4 engine is untouched. This module shares only the strict duplicate-refusing JSON
//! parser (`keys::strict_json`) and the `p256`, `sha2`, `base64` and `aes-gcm` primitives.

pub mod build;
pub mod calls;
pub mod descriptor;
pub mod encoding;
pub mod floor;
pub mod heads;
pub mod history;
pub mod ids;
pub mod members;
pub mod prescan;
pub mod records;
pub mod replay;
pub mod signature;
pub mod terms;

/// A refusal reason (§19). The protocol spelling is `refused:<reason>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    /// §12.3 step 3: the audience is not one of the verifier's.
    Audience,
    /// §12.3 steps 3–4: `created` outside the window.
    Window,
    /// §12.4: the same reservation key with the same body digest.
    Replay,
    /// §12.4: the same reservation key with a different body digest.
    Conflict,
    /// §8.6, §12.3, §13.3: a fork.
    Fork,
    /// §12.3 step 5 and §11.5: the signer is absent, removed or revoked.
    Revoked,
    /// §12.3 steps 5–6: a member or link has expired or is not yet valid.
    Expired,
    /// §12.3 step 6: the first link names an earlier session number.
    Ended,
    /// §12.3 step 6: link terms do not narrow their parent.
    NotNarrower,
    /// §12.3 steps 5 and 7: role, audience, purpose or condition not allowed.
    OutOfScope,
    /// §12.3 step 5: a WebAuthn controller call from a non-call origin.
    Origin,
    /// §13.3: a head behind the high-water mark.
    Rollback,
    /// §11.5: the author has no records entry covering the level.
    NotGranted,
    /// §11.5: the epoch was not current at the cited seq.
    WrongEpoch,
    /// §11.4: a clock more than 1,024 above the highest earlier admitted clock.
    ClockJump,
    /// §11.5: the member's `writes` budget is spent.
    BudgetSpent,
    /// §11.5: the header is fenced out by format.
    WrongFormat,
    /// §11.5, 0.3 §5: the payload doesn't authenticate or doesn't match its header.
    InvalidPayload,
}
impl Reason {
    /// The reason's protocol spelling, without the `refused:` prefix.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audience => "audience",
            Self::Window => "window",
            Self::Replay => "replay",
            Self::Conflict => "conflict",
            Self::Fork => "fork",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Ended => "ended",
            Self::NotNarrower => "notNarrower",
            Self::OutOfScope => "outOfScope",
            Self::Origin => "origin",
            Self::Rollback => "rollback",
            Self::NotGranted => "notGranted",
            Self::WrongEpoch => "wrongEpoch",
            Self::ClockJump => "clockJump",
            Self::BudgetSpent => "budgetSpent",
            Self::WrongFormat => "wrongFormat",
            Self::InvalidPayload => "invalidPayload",
        }
    }
}

/// A failed 0.5 check (§1). Diagnostics never contain private key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The bytes or structure break a rule.
    Malformed(String),
    /// A required signature, assertion, possession proof or key binding failed.
    BadSignature(String),
    /// Authenticated content of a known protocol that this reader doesn't know.
    NewerFormat(String),
    /// Something needed could not be obtained. Never evidence of anything.
    Unavailable(String),
    /// Well-formed and authentic, but not permitted.
    Refused(Reason),
}
impl Failure {
    /// The exact protocol result code, for example `malformed` or `refused:audience`.
    pub fn code(&self) -> String {
        match self {
            Self::Malformed(_) => "malformed".into(),
            Self::BadSignature(_) => "badSignature".into(),
            Self::NewerFormat(_) => "newerFormat".into(),
            Self::Unavailable(_) => "unavailable".into(),
            Self::Refused(reason) => format!("refused:{}", reason.as_str()),
        }
    }
    /// The diagnostic, when there is one.
    pub fn detail(&self) -> &str {
        match self {
            Self::Malformed(s)
            | Self::BadSignature(s)
            | Self::NewerFormat(s)
            | Self::Unavailable(s) => s,
            Self::Refused(reason) => reason.as_str(),
        }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(_) => f.write_str(&self.code()),
            other => write!(f, "{}: {}", other.code(), other.detail()),
        }
    }
}
impl std::error::Error for Failure {}

/// A 0.5 result.
pub type Result<T> = std::result::Result<T, Failure>;

pub(crate) fn malformed(reason: impl Into<String>) -> Failure {
    Failure::Malformed(reason.into())
}
pub(crate) fn bad_signature(reason: impl Into<String>) -> Failure {
    Failure::BadSignature(reason.into())
}
pub(crate) fn require(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(malformed(reason))
    }
}

/// Unknown content found while parsing (§2.3). It is reported as `newerFormat` only after the
/// object has been authenticated and authorized (§1); parsers collect it here instead.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Unknown(pub Vec<String>);
impl Unknown {
    /// Record one unknown field, kind, form, role, term or value by its path.
    pub fn push(&mut self, path: impl Into<String>) {
        self.0.push(path.into());
    }
    /// True when nothing unknown was found.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// `Err(newerFormat)` naming the first unknown item, or `Ok`.
    pub fn check(&self) -> Result<()> {
        match self.0.first() {
            None => Ok(()),
            Some(path) => Err(Failure::NewerFormat(format!("unknown content: {path}"))),
        }
    }
}
