//! Session keys (§S2): the in-memory signing key, its `colophon/session-key/6` delegation
//! signed by the member key in the host, and what a verifier needs from the account.
//!
//! The member's private key never enters the core (0.5 §3.4): the core builds the exact
//! delegation body ([`SessionKey::delegation_body`]), the host signs it `raw` with the member
//! key, and the core verifies the result before using it ([`Delegation::verify`]). The session
//! key itself is generated from host randomness, held only in memory, never serialized, and
//! zeroized on drop.
use super::types::MemberId;
use crate::v05::encoding::{bounds, canonical, encode_base64, parse_date, Obj};
use crate::v05::history::{Claim as PrincipalClaim, State};
use crate::v05::ids::{key_id, AccountId};
use crate::v05::signature::{verify_raw, RawEnvelope};
use crate::v05::terms::{valid_namespace, Access};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// The `protocol` of a delegation body.
pub const SESSION_KEY_PROTOCOL: &str = "colophon/session-key/6";
/// The longest delegation window, `expires − notBefore`, in ms (§S2: 86,400 s).
pub const MAX_WINDOW_MS: i64 = 86_400_000;
/// How far a verifier's clock may be outside the window (§S2: 60 s).
pub const CLOCK_SLACK_MS: i64 = 60_000;
/// The largest delegation body, canonical bytes.
pub const MAX_DELEGATION_BODY: usize = 1_024;

/// One member as a session verifier sees it at its accepted authority head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMember {
    /// The member's signing point (65 bytes, uncompressed).
    pub signing: Vec<u8>,
    /// The member's current session number (0.5 §9.6).
    pub session: u64,
    /// The member's expiry, ms since the Unix epoch, when it has one.
    pub expires_ms: Option<i64>,
    /// Its `records` access by namespace (0.5 §10.1).
    pub records: BTreeMap<String, Access>,
}

/// The members of one account that are current at the verifier's accepted authority head
/// (§S1, §S2). A member absent from the view is not current: revoked, suspended,
/// provisional or unknown. The host builds a new view whenever that head changes and gives
/// it to the core before any frame received after the change (§S1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionAccount {
    account: String,
    members: BTreeMap<MemberId, SessionMember>,
}
impl SessionAccount {
    /// An empty view of `account` (64 hex): nobody is entitled.
    pub fn new(account: &str) -> Self {
        Self {
            account: account.to_owned(),
            members: BTreeMap::new(),
        }
    }
    /// Add or replace a current member.
    pub fn with_member(
        mut self,
        signing: &[u8],
        session: u64,
        expires_ms: Option<i64>,
        records: &[(&str, Access)],
    ) -> Self {
        self.members.insert(
            key_id(signing),
            SessionMember {
                signing: signing.to_vec(),
                session,
                expires_ms,
                records: records
                    .iter()
                    .map(|(n, a)| ((*n).to_owned(), *a))
                    .collect(),
            },
        );
        self
    }
    /// The view of a verified 0.5 history state: every member that
    /// [`State::current_principal`] calls current at `at_ms`, with its session number (the
    /// count of its `endSessions`) and its `records` entries.
    pub fn from_history_state(account: &AccountId, state: &State, at_ms: i64) -> Self {
        let mut view = Self::new(account.as_str());
        for m in state.members() {
            let id = m.request.member_id();
            if state
                .current_principal(&id, PrincipalClaim::Member, at_ms)
                .is_err()
            {
                continue;
            }
            let records = m
                .terms
                .records()
                .unwrap_or_default()
                .iter()
                .map(|r| (r.namespace.clone(), r.access))
                .collect();
            view.members.insert(
                id,
                SessionMember {
                    signing: m.request.signing.clone(),
                    session: m.end_sessions.len() as u64,
                    expires_ms: m.expires_ms,
                    records,
                },
            );
        }
        view
    }
    /// The account (64 hex).
    pub fn account(&self) -> &str {
        &self.account
    }
    /// A current member.
    pub fn member(&self, id: &str) -> Option<&SessionMember> {
        self.members.get(id)
    }
    /// The member's access to `namespace` when it is current at `wall_ms` and holds a
    /// `records` entry for it (§S1 "who may join").
    pub fn access(&self, id: &str, namespace: &str, wall_ms: i64) -> Option<Access> {
        let m = self.members.get(id)?;
        if m.expires_ms.is_some_and(|e| wall_ms > e) {
            return None;
        }
        m.records.get(namespace).copied()
    }
    /// Members whose entry for `namespace` has access `write` (§S1 "who may hold or
    /// submit"), sorted.
    pub fn writers(&self, namespace: &str, wall_ms: i64) -> Vec<MemberId> {
        self.members
            .keys()
            .filter(|id| self.access(id, namespace, wall_ms) == Some(Access::Write))
            .cloned()
            .collect()
    }
}

/// A §2.2 date for `ms` since the Unix epoch: `YYYY-MM-DDTHH:mm:ssZ`, or with `.sss` when the
/// milliseconds are not zero. `None` outside years 0001–9999.
pub fn format_date(ms: i64) -> Option<String> {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (hh, mm, ss, milli) = (
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1_000 % 60,
        rem % 1_000,
    );
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    if !(1..=9_999).contains(&y) {
        return None;
    }
    let base = format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}");
    Some(if milli == 0 {
        format!("{base}Z")
    } else {
        format!("{base}.{milli:03}Z")
    })
}

/// A parsed `colophon/session-key/6` body (§S2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationBody {
    /// The account (64 hex).
    pub account: String,
    /// The delegating member's ID.
    pub member: MemberId,
    /// The member's session number when it signed.
    pub session: u64,
    /// The session key's signing point (65 bytes).
    pub key: Vec<u8>,
    /// The namespace the key may speak in.
    pub namespace: String,
    /// The first moment, ms since the Unix epoch.
    pub not_before_ms: i64,
    /// The last moment, ms since the Unix epoch.
    pub expires_ms: i64,
}
impl DelegationBody {
    /// Parse a body: canonical, closed, every field in its grammar, `notBefore ≤ expires` and
    /// `expires − notBefore ≤ 86,400 s`.
    pub fn parse(value: Value) -> Result<Self, String> {
        let mut o = Obj::new(value, "delegation").map_err(|e| e.to_string())?;
        let protocol = o.string("protocol").map_err(|e| e.to_string())?;
        let account = o.string("account").map_err(|e| e.to_string())?;
        let member = o.key_id("member").map_err(|e| e.to_string())?;
        let session = o.uint("session").map_err(|e| e.to_string())?;
        let key = o.bytes("key", 65).map_err(|e| e.to_string())?;
        let namespace = o.string("namespace").map_err(|e| e.to_string())?;
        let (_, not_before_ms) = o.date("notBefore").map_err(|e| e.to_string())?;
        let (_, expires_ms) = o.date("expires").map_err(|e| e.to_string())?;
        o.finish_closed().map_err(|e| e.to_string())?;
        if protocol != SESSION_KEY_PROTOCOL {
            return Err("unknown protocol".into());
        }
        if !super::wire::valid_account(&account) {
            return Err("account is not 64 lowercase hex".into());
        }
        if !valid_namespace(&namespace) {
            return Err("invalid namespace".into());
        }
        if !crate::v05::descriptor::valid_point(&key) {
            return Err("key is not a valid uncompressed P-256 point".into());
        }
        if expires_ms < not_before_ms {
            return Err("expires is before notBefore".into());
        }
        if expires_ms - not_before_ms > MAX_WINDOW_MS {
            return Err("the window is longer than 86,400 s".into());
        }
        Ok(Self {
            account,
            member,
            session,
            key,
            namespace,
            not_before_ms,
            expires_ms,
        })
    }
    /// The session key's ID.
    pub fn key_id(&self) -> String {
        key_id(&self.key)
    }
    /// Whether `wall_ms` is within the window widened by 60 s on each side (§S2).
    pub fn in_window(&self, wall_ms: i64) -> bool {
        wall_ms >= self.not_before_ms.saturating_sub(CLOCK_SLACK_MS)
            && wall_ms <= self.expires_ms.saturating_add(CLOCK_SLACK_MS)
    }
}

/// A delegation envelope (`{"body","signature"}`, 0.5 §4.1) and its parsed body. Parsing
/// checks shape only; [`Delegation::verify`] checks the signature and the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    /// The envelope's canonical JSON bytes, as carried in a frame's `delegation`.
    pub envelope: Vec<u8>,
    /// The exact body bytes the member key signed.
    pub body_bytes: Vec<u8>,
    /// The raw signature.
    pub signature: Vec<u8>,
    /// The parsed body.
    pub body: DelegationBody,
}
impl Delegation {
    /// Parse an envelope given as its canonical JSON bytes.
    pub fn parse(envelope: &[u8]) -> Result<Self, String> {
        let env = RawEnvelope::parse_bounded(
            envelope,
            MAX_DELEGATION_BODY,
            super::wire::MAX_DELEGATION_BYTES,
            true,
        )
        .map_err(|e| e.to_string())?;
        let body = DelegationBody::parse(env.value)?;
        Ok(Self {
            envelope: envelope.to_vec(),
            body_bytes: env.body,
            signature: env.signature,
            body,
        })
    }
    /// Assemble the envelope for body bytes and the host's raw signature, and parse it.
    pub fn assemble(body: &[u8], signature: &[u8]) -> Result<Self, String> {
        let mut m = Map::new();
        m.insert("body".into(), encode_base64(body).into());
        m.insert("signature".into(), encode_base64(signature).into());
        let envelope = canonical(&Value::Object(m)).map_err(|e| e.to_string())?;
        Self::parse(&envelope)
    }
    /// The session key's ID.
    pub fn key_id(&self) -> String {
        self.body.key_id()
    }
    /// Whether the member named is still current in `view` with a `records` entry for the
    /// namespace and the same session number (the per-history re-check of §S2).
    pub fn holds_in(&self, view: &SessionAccount, wall_ms: i64) -> bool {
        let b = &self.body;
        b.account == view.account()
            && view.access(&b.member, &b.namespace, wall_ms).is_some()
            && view.member(&b.member).is_some_and(|m| m.session == b.session)
    }
    /// §S2 acceptance for a frame in `namespace` at `wall_ms`: the envelope verifies under the
    /// member's key in `view`, the member is current with a `records` entry for `namespace`,
    /// `session` equals its session number, and the clock is within the window ± 60 s.
    pub fn verify(&self, view: &SessionAccount, namespace: &str, wall_ms: i64) -> Result<(), String> {
        let b = &self.body;
        if b.account != view.account() {
            return Err("another account".into());
        }
        if b.namespace != namespace {
            return Err("another namespace".into());
        }
        let Some(member) = view.member(&b.member) else {
            return Err("not a current member".into());
        };
        if view.access(&b.member, namespace, wall_ms).is_none() {
            return Err("no records entry for the namespace".into());
        }
        if member.session != b.session {
            return Err("another session number".into());
        }
        if !b.in_window(wall_ms) {
            return Err("outside its window".into());
        }
        verify_raw(&member.signing, &self.body_bytes, &self.signature)
            .map_err(|e| e.to_string())
    }
}

/// Why a session key could not be made or used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The 32 random bytes are not a valid P-256 scalar (probability about 2^-32): draw again.
    Scalar,
    /// The key has numbered 2^53 − 1 frames; a new session needs a new key.
    Exhausted,
    /// A date is outside years 0001–9999, or the window is invalid.
    Window,
}
impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyError::Scalar => "the random bytes are not a P-256 scalar",
            KeyError::Exhausted => "the session key has used every n",
            KeyError::Window => "invalid delegation window",
        })
    }
}
impl std::error::Error for KeyError {}

/// A session key: a P-256 signing key made fresh from host randomness each time a session
/// starts, held only in memory, never serialized, never cloned, zeroized on drop (the inner
/// `SigningKey` zeroizes its scalar). It numbers the frames it signs from 1, so no `(key, n)`
/// pair, and therefore no AES-GCM nonce under its derived key, is ever used twice.
pub struct SessionKey {
    signing: SigningKey,
    point: Vec<u8>,
    id: String,
    last_n: u64,
}
impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("id", &self.id)
            .field("last_n", &self.last_n)
            .finish_non_exhaustive()
    }
}
impl SessionKey {
    /// Make a key from 32 fresh random bytes from the host. The bytes are wiped whatever the
    /// result.
    pub fn generate(random: &mut [u8; 32]) -> Result<Self, KeyError> {
        let signing = SigningKey::from_slice(random.as_slice());
        random.zeroize();
        let signing = signing.map_err(|_| KeyError::Scalar)?;
        let point = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let id = key_id(&point);
        Ok(Self {
            signing,
            point,
            id,
            last_n: 0,
        })
    }
    /// The key ID (0.5 §3.1).
    pub fn id(&self) -> &str {
        &self.id
    }
    /// The uncompressed signing point.
    pub fn point(&self) -> &[u8] {
        &self.point
    }
    /// The highest `n` numbered so far (0 before the first frame).
    pub fn last_n(&self) -> u64 {
        self.last_n
    }
    /// Take the next `n`. Never returns the same value twice for this key.
    pub(crate) fn next_n(&mut self) -> Result<u64, KeyError> {
        if self.last_n >= super::types::MAX_INT {
            return Err(KeyError::Exhausted);
        }
        self.last_n += 1;
        Ok(self.last_n)
    }
    /// A raw ES256 signature (0.5 §4.2) over `body`. Deterministic (RFC 6979).
    pub(crate) fn sign(&self, body: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing.sign(body);
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
    /// The exact `colophon/session-key/6` body for the host to sign `raw` with the member key.
    pub fn delegation_body(
        &self,
        account: &str,
        member: &str,
        session: u64,
        namespace: &str,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<Vec<u8>, KeyError> {
        if expires_ms < not_before_ms || expires_ms - not_before_ms > MAX_WINDOW_MS {
            return Err(KeyError::Window);
        }
        if session > bounds::MAX_INTEGER {
            return Err(KeyError::Window);
        }
        let nb = format_date(not_before_ms).ok_or(KeyError::Window)?;
        let ex = format_date(expires_ms).ok_or(KeyError::Window)?;
        // Dates are written at their own precision; check they read back exactly.
        if parse_date(&nb) != Some(not_before_ms) || parse_date(&ex) != Some(expires_ms) {
            return Err(KeyError::Window);
        }
        let mut m = Map::new();
        m.insert("protocol".into(), SESSION_KEY_PROTOCOL.into());
        m.insert("account".into(), account.into());
        m.insert("member".into(), member.into());
        m.insert("session".into(), session.into());
        m.insert("key".into(), encode_base64(&self.point).into());
        m.insert("namespace".into(), namespace.into());
        m.insert("notBefore".into(), nb.into());
        m.insert("expires".into(), ex.into());
        canonical(&Value::Object(m)).map_err(|_| KeyError::Window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        for s in [
            "2026-11-22T10:00:00Z",
            "1970-01-01T00:00:00Z",
            "2000-02-29T23:59:59.999Z",
            "0001-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            let ms = parse_date(s).unwrap_or(i64::MIN);
            assert_eq!(format_date(ms).as_deref(), Some(s));
        }
        assert_eq!(format_date(-62_135_596_800_001), None);
    }
}
