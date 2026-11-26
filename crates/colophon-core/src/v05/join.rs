//! Joining at an invite's head (§9.1, §12.2, §13.4): what a device needs to fetch and accept an
//! account's history after it was admitted, when all it was given is the account ID, a home and
//! the head of the history `(seq, entry digest)`.
//!
//! The device asks to join with a membership request (§9.1), which names only the account ID and
//! its own keys. Once an owner approved it, the device reads `GET {base}/authority` with a
//! `colophon.history.read` call signed by its member key whose `asOf` is the head it was given
//! ([`crate::v05::write::calls::prepare_history_read`]); until the approval reaches the home, the
//! home refuses the call (`refused:revoked`: no grant names the key). This module reads the
//! home's pages and accepts the history only when it verifies completely and contains the head
//! ([`verify_at_head`]).
//!
//! Sans-IO: no clock, no network, no storage.
use crate::v05::encoding::{bounds, canonical, is_digest, strict_parse};
use crate::v05::history::envelope::AuthEnvelope;
use crate::v05::history::{verify_history, Objects, Persisted, Stop};
use crate::v05::ids::AccountId;
use crate::v05::{malformed, require, Failure, Reason, Result};
use serde_json::Value;

/// Entries a home serves in one page of `GET {base}/authority` (the engine's page).
pub const PAGE: u64 = 64;

/// The most entries a joining device accepts in one history (`2^18`, 4,096 full pages): four
/// times the §2.4 portability floor of 65,536 authority entries a verifier must handle, so no
/// account within the floor is refused. Beyond it the history is `unavailable` (§2.4: "answers
/// `unavailable` beyond them, never partial validity").
pub const MAX_ENTRIES: usize = 1 << 18;

/// The largest authority entry envelope a joining device accepts: twice the §2.4 authority body
/// bound (1 MiB), the envelope bound every authority parser here applies
/// (`AuthEnvelope::parse(_, AUTHORITY_BODY, 2 * AUTHORITY_BODY, _)`). A larger entry is
/// `malformed`.
pub const MAX_ENTRY_BYTES: usize = bounds::AUTHORITY_BODY * 2;

/// The most entry bytes a joining device holds for one history: 256 MiB, the §2.4 portability
/// floor for envelopes ("256 MiB of envelopes"), so every account a verifier must accept fits.
/// Beyond it the history is `unavailable`, checked while paging and again before verifying,
/// so a home that pages forever or sends large pages costs at most this much memory.
pub const MAX_HISTORY_BYTES: usize = 256 * 1024 * 1024;

/// Fails `unavailable` when `entries` pass [`MAX_ENTRIES`] or [`MAX_HISTORY_BYTES`], and
/// `malformed` when one entry passes [`MAX_ENTRY_BYTES`]: the check a host runs while paging
/// and the core runs again before any copy.
pub fn check_history_size(count: usize, bytes: usize) -> Result<()> {
    if count > MAX_ENTRIES || bytes > MAX_HISTORY_BYTES {
        return Err(Failure::Unavailable(
            "the history passes what a joining device holds (2^18 entries, 256 MiB)".into(),
        ));
    }
    Ok(())
}

/// The path, relative to the home's base, of the history page after `after` entries.
pub fn history_page_path(after: u64) -> String {
    format!("/authority?after={after}&limit={PAGE}")
}

/// One page of a home's history (`{"entries":[…],"receipts":[…],"more":bool}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    /// The entry envelopes, as canonical bytes, in the order served.
    pub entries: Vec<Vec<u8>>,
    /// The home says more entries follow.
    pub more: bool,
}

/// Parse one page of `GET {base}/authority`: at most [`PAGE`] entries, each an object written
/// back as its canonical bytes (an authority envelope is canonical JSON, so these are the bytes
/// the home holds). Receipts are not read: a joining device needs the entries only.
pub fn parse_history_page(body: &[u8]) -> Result<HistoryPage> {
    let v = strict_parse(body)?;
    let list = match &v["entries"] {
        Value::Array(list) => list,
        _ => return Err(malformed("a history page has an `entries` array")),
    };
    require(
        list.len() as u64 <= PAGE,
        "a history page has at most 64 entries",
    )?;
    let entries = list
        .iter()
        .map(|e| {
            require(e.is_object(), "a history entry is an object")?;
            let bytes = canonical(e)?;
            require(
                bytes.len() <= MAX_ENTRY_BYTES,
                "a history entry exceeds the authority envelope bound",
            )?;
            Ok(bytes)
        })
        .collect::<Result<Vec<_>>>()?;
    let more = match &v["more"] {
        Value::Bool(b) => *b,
        Value::Null => false,
        _ => return Err(malformed("`more` is a boolean")),
    };
    Ok(HistoryPage { entries, more })
}

/// What [`verify_at_head`] decided about a fetched history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtHead {
    /// The history verifies, holds the invite's head, ends at the home's signed head and
    /// grants this member from exactly its request: each entry to store at
    /// `authority/<seq, eight digits>.json`, in seq order.
    Admitted(Vec<(String, Vec<u8>)>),
    /// The history verifies and ends at the home's signed head, but names no member with this
    /// ID: not admitted yet (a home whose history is public serves it before the approval).
    NotAdmitted,
}

/// Verify `entries` (taken, never copied) after the size checks; returns the verdict and the
/// objects holding the entries.
fn verified(entries: Vec<Vec<u8>>, now_ms: i64) -> Result<(crate::v05::history::Verdict, Objects)> {
    let mut bytes = 0usize;
    for e in &entries {
        require(
            e.len() <= MAX_ENTRY_BYTES,
            "a history entry exceeds the authority envelope bound",
        )?;
        bytes = bytes.saturating_add(e.len());
    }
    check_history_size(entries.len(), bytes)?;
    let objects = Objects {
        entries,
        ..Default::default()
    };
    let verdict = verify_history(&objects, &Persisted::default(), now_ms);
    match &verdict.stop {
        None => {}
        Some(Stop::Failed { failure, .. }) => return Err(failure.clone()),
        Some(Stop::Held { why, .. }) => {
            return Err(Failure::Unavailable(format!("the history is held: {why}")))
        }
        Some(Stop::Fork { .. }) => return Err(Failure::Refused(Reason::Fork)),
    }
    require(
        verdict.state.is_some(),
        "the history has no verified genesis",
    )?;
    Ok((verdict, objects))
}

/// Accept a fetched history only when it verifies completely, holds the invite's head, ends at
/// the home's signed head and grants this device from exactly the request it made:
///
/// - the history verifier's verdict is `ok` (otherwise its own failure, `held` as
///   `unavailable`, a fork as `refused:fork`);
/// - it is the history of `account` (another account: `refused:fork`; the device asked to join
///   that account, by an ID it was shown);
/// - every entry fetched is on the verified branch (an entry beside it: `refused:fork`);
/// - the branch is at least `seq` long (shorter: `unavailable`, a rolled-back history), and
///   its entry `seq` has the body digest `head` (another: `refused:fork`);
/// - `signed_head` (the body of `GET {base}/head`) verifies (§13.3) as a fresh head of a current
///   home whose endpoints name `base` (any other signer, a home that was removed included, is
///   `badSignature`), and names exactly the branch tip: a head beyond the tip
///   is `refused:rollback` (the home serves less than it signed); a head behind it is
///   `unavailable` (fetch again);
/// - `member` (the key ID of the key that signed the reads) is the member `request` names (else
///   `refused:conflict`: a request of another member), and that member is current at the tip (§8.5) and was granted
///   with exactly `request` (the same body bytes): revoked, expired or provisional is
///   `refused:revoked` / `refused:expired`, a grant of another request `refused:conflict`.
///   A history that names no member with this ID is [`AtHead::NotAdmitted`].
#[allow(clippy::too_many_arguments)]
pub fn verify_at_head(
    account: &AccountId,
    seq: u64,
    head: &str,
    member: &str,
    request: &[u8],
    base: &str,
    signed_head: &[u8],
    entries: Vec<Vec<u8>>,
    now_ms: i64,
) -> Result<AtHead> {
    use crate::v05::history::{Claim, NotCurrent, Principal};
    require(seq >= 1, "the invite's seq is at least 1")?;
    require(is_digest(head), "the invite's head is 64 lowercase hex")?;
    let request = crate::v05::members::Request::parse(request, false)?;
    require(
        &request.account == account,
        "the request names another account",
    )?;
    let accepted = accept_at_head(account, seq, head, base, signed_head, entries, now_ms)?;
    let state = accepted.state()?;
    // This device, granted from exactly its request and current at the tip (§8.5).
    let id = request.member_id();
    if id != member {
        return Err(Failure::Refused(Reason::Conflict));
    }
    match state.current_principal(&id, Claim::Member, now_ms) {
        Ok(Principal::Member(m)) | Ok(Principal::Home(m)) => {
            if m.request.body != request.body {
                return Err(Failure::Refused(Reason::Conflict));
            }
        }
        Ok(Principal::Controller(_)) => return Err(Failure::Refused(Reason::Conflict)),
        Err(NotCurrent::Absent) => return Ok(AtHead::NotAdmitted),
        Err(NotCurrent::Expired) => return Err(Failure::Refused(Reason::Expired)),
        Err(_) => return Err(Failure::Refused(Reason::Revoked)),
    }
    accepted.files().map(AtHead::Admitted)
}

/// A fetched history that verifies completely, is the account's, holds `(seq, head)` and ends at
/// the home's fresh signed head: the verdict, and each fetched entry at its place on the branch.
struct AcceptedAtHead {
    verdict: crate::v05::history::Verdict,
    stored: Vec<Option<Vec<u8>>>,
}
impl AcceptedAtHead {
    fn state(&self) -> Result<&crate::v05::history::State> {
        self.verdict
            .state
            .as_ref()
            .ok_or_else(|| malformed("the history has no verified genesis"))
    }
    /// Each entry to store at `authority/<seq, eight digits>.json`, in seq order.
    fn files(self) -> Result<Vec<(String, Vec<u8>)>> {
        self.stored
            .into_iter()
            .enumerate()
            .map(|(i, e)| {
                let e = e.ok_or_else(|| malformed("an entry on the branch was not fetched"))?;
                Ok((format!("authority/{:08}.json", i + 1), e))
            })
            .collect()
    }
}

/// The checks [`verify_at_head`] and [`verify_with_passkey`] share, in this order: the verdict is
/// `ok`, the history is `account`'s, every entry is on the branch, the branch holds `head` at
/// `seq`, and `signed_head` is a fresh head of a current home serving at `base` naming exactly the
/// branch tip.
#[allow(clippy::too_many_arguments)]
fn accept_at_head(
    account: &AccountId,
    seq: u64,
    head: &str,
    base: &str,
    signed_head: &[u8],
    entries: Vec<Vec<u8>>,
    now_ms: i64,
) -> Result<AcceptedAtHead> {
    use crate::v05::heads::{verify_head, HeadContext};
    let (verdict, objects) = verified(entries, now_ms)?;
    let state = verdict
        .state
        .as_ref()
        .ok_or_else(|| malformed("the history has no verified genesis"))?;
    if state.account() != account {
        return Err(Failure::Refused(Reason::Fork));
    }
    let index = usize::try_from(seq - 1).map_err(|_| malformed("seq is out of range"))?;
    let at_head = verdict.branch.get(index).ok_or_else(|| {
        Failure::Unavailable("the history does not reach the invite's head".into())
    })?;
    if at_head != head {
        return Err(Failure::Refused(Reason::Fork));
    }
    // Each fetched entry, by its digest's place on the branch (one map, O(n)): an entry off the
    // branch is `refused:fork`, the same entry twice `malformed`.
    let index_of: std::collections::HashMap<&str, usize> = verdict
        .branch
        .iter()
        .enumerate()
        .map(|(i, d)| (d.as_str(), i))
        .collect();
    let mut stored: Vec<Option<Vec<u8>>> = vec![None; verdict.branch.len()];
    for e in objects.entries {
        let env = AuthEnvelope::parse(&e, bounds::AUTHORITY_BODY, MAX_ENTRY_BYTES, false)?;
        let i = *index_of
            .get(env.digest.as_str())
            .ok_or(Failure::Refused(Reason::Fork))?;
        let slot = &mut stored[i];
        require(slot.is_none(), "a history entry is served twice")?;
        *slot = Some(e);
    }
    // The tip is the home's signed head (§13.3), from a current home that serves at `base`.
    let base = base.trim_end_matches('/');
    let homes: Vec<(String, Vec<u8>)> = state
        .current_homes()
        .into_iter()
        .filter(|m| m.expires_ms.is_none_or(|e| now_ms <= e))
        .filter(|m| {
            m.request
                .endpoints
                .as_ref()
                .is_some_and(|es| es.iter().any(|e| e.trim_end_matches('/') == base))
        })
        .map(|m| (m.request.member_id(), m.request.signing.clone()))
        .collect();
    // No current home serving at `base` leaves `homes` empty, and the head's signer is then
    // refused like any other non-home (`badSignature`).
    let head_env = canonical(&strict_parse(signed_head)?)?;
    let tip = verdict.branch.len() as u64;
    let signed = match verify_head(
        &head_env,
        HeadContext {
            account,
            history: &verdict.branch,
            homes: &homes,
            now_ms,
        },
    ) {
        Ok(h) => h,
        // A head beyond what was served: the home holds (and signed) more than it gave.
        Err(Failure::Unavailable(_)) => return Err(Failure::Refused(Reason::Rollback)),
        Err(e) => return Err(e),
    };
    let max_age = state.keyring().policy.head_max_age();
    if !signed.fresh(now_ms, max_age) {
        return Err(Failure::Unavailable("the home's signed head is not fresh".into()));
    }
    if signed.seq() != tip {
        return Err(Failure::Unavailable(
            "the home's signed head is behind the history it served".into(),
        ));
    }
    Ok(AcceptedAtHead { verdict, stored })
}

// ---------------------------------------------------------------------------------------------
// Reading the history with a passkey before admission (Colophon 0.5.7, §12.3, §13.4).

/// A current WebAuthn controller of a history accepted by [`verify_with_passkey`]: present,
/// final and not suspended at the tip (§8.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyController {
    /// The controller ID (the key ID of its signing point).
    pub id: String,
    /// Its descriptor as the history names it (`rp`, credential, origins, authority origins).
    pub key: crate::v05::descriptor::KeyDescriptor,
    /// Its label.
    pub label: String,
    /// Its roles, as the protocol spells them.
    pub roles: Vec<String>,
    /// UV is required on its signatures.
    pub verification: bool,
    /// Some slot of the current vault is held by this controller alone (a PRF slot it opens).
    pub own_slot: bool,
}

/// What [`verify_with_passkey`] accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyHistory {
    /// Each entry to store at `authority/<seq, eight digits>.json`, in seq order.
    pub files: Vec<(String, Vec<u8>)>,
    /// The controller whose passkey signed the reads.
    pub signer: PasskeyController,
    /// Every current WebAuthn controller at the tip, the signer included, by ID.
    pub controllers: Vec<PasskeyController>,
}

/// The points a passkey assertion over `body` could have been made by, for `rp`
/// ([`crate::v05::signature::assertion_points`]). With `key_id`, exactly the one point with that
/// key ID, else `badSignature`. A device that knows a passkey only from a discoverable get uses
/// this to learn its signing point before it signs a call naming it; the point is a candidate
/// only, until a history that verifies names it as a current controller.
pub fn passkey_points(
    body: &[u8],
    rp: &str,
    authenticator_data: &[u8],
    client_data: &[u8],
    signature: &[u8],
    key_id: Option<&str>,
) -> Result<Vec<Vec<u8>>> {
    use crate::v05::signature::{assertion_points, AssertionBytes, SigFailure};
    let points = assertion_points(
        body,
        rp,
        AssertionBytes {
            authenticator_data,
            client_data,
        },
        signature,
    )
    .map_err(|e| match e {
        SigFailure::ClientDataBound => malformed("clientData exceeds 8,192 bytes"),
        e => Failure::BadSignature(format!("passkey assertion: {e}")),
    })?;
    match key_id {
        None => Ok(points),
        Some(id) => {
            let found: Vec<Vec<u8>> = points
                .into_iter()
                .filter(|p| crate::v05::ids::key_id(p) == id)
                .collect();
            if found.is_empty() {
                return Err(Failure::BadSignature(
                    "the assertion was not made by the passkey with that key ID".into(),
                ));
            }
            Ok(found)
        }
    }
}

/// Accept a history read with a passkey's `colophon.history.read` calls (signed by `signing`):
/// every check of [`verify_at_head`] up to and including the home's fresh signed head, at
/// `(seq, head)` (an invite's head, or `(1, account ID)`: the genesis, which every history of the
/// account holds), and then the signer: a current WebAuthn controller at the tip whose signing
/// point is `signing` (anything else, a removed, provisional or suspended controller included, is
/// `refused:revoked`). Nothing about any member is judged: the device is not one yet.
#[allow(clippy::too_many_arguments)]
pub fn verify_with_passkey(
    account: &AccountId,
    seq: u64,
    head: &str,
    signing: &[u8],
    base: &str,
    signed_head: &[u8],
    entries: Vec<Vec<u8>>,
    now_ms: i64,
) -> Result<PasskeyHistory> {
    require(seq >= 1, "the given seq is at least 1")?;
    require(is_digest(head), "the given head is 64 lowercase hex")?;
    require(
        signing.len() == 65 && signing[0] == 4,
        "the passkey's signing point is an uncompressed P-256 point",
    )?;
    let accepted = accept_at_head(account, seq, head, base, signed_head, entries, now_ms)?;
    let controllers = current_passkeys(accepted.state()?, now_ms);
    let id = crate::v05::ids::key_id(signing);
    let signer = controllers
        .iter()
        .find(|c| c.id == id && c.key.signing() == signing)
        .cloned()
        .ok_or(Failure::Refused(Reason::Revoked))?;
    Ok(PasskeyHistory {
        files: accepted.files()?,
        signer,
        controllers,
    })
}

/// Every current WebAuthn controller of `state` at `now_ms`, by ID.
fn current_passkeys(state: &crate::v05::history::State, now_ms: i64) -> Vec<PasskeyController> {
    use crate::v05::descriptor::Role;
    use crate::v05::history::{Claim, Principal};
    use crate::v05::slots::Slot;
    let keyring = state.keyring();
    let own: std::collections::BTreeSet<String> = keyring
        .slots
        .iter()
        .filter_map(|v| Slot::from_value(v).ok())
        .filter(|s| s.controllers().len() == 1)
        .flat_map(|s| s.controllers().to_vec())
        .collect();
    keyring
        .controllers
        .values()
        .filter(|c| c.key().webauthn().is_some())
        .filter(|c| {
            matches!(
                state.current_principal(
                    &c.id(),
                    Claim::Controller {
                        roles: &[],
                        suspended_ok: false,
                    },
                    now_ms,
                ),
                Ok(Principal::Controller(_))
            )
        })
        .map(|c| PasskeyController {
            id: c.id(),
            key: c.key().clone(),
            label: c.label().to_string(),
            roles: c
                .roles()
                .iter()
                .map(|r| match r {
                    Role::Approve => "approve".to_string(),
                    Role::Control => "control".into(),
                    Role::Recover => "recover".into(),
                    Role::Sign => "sign".into(),
                    Role::Unknown(s) => s.clone(),
                })
                .collect(),
            verification: c.verification(),
            own_slot: own.contains(&c.id()),
        })
        .collect()
}

/// The descriptor of controller `id` in a verified history, when it is a current WebAuthn
/// controller (present, final, not suspended, §8.5): its `rp`, credential and origins, read
/// from the history rather than from an invite. `None` for a removed, provisional, suspended or
/// raw controller, or an ID the keyring does not hold.
pub fn current_webauthn_controller(
    entries: Vec<Vec<u8>>,
    id: &str,
    now_ms: i64,
) -> Result<Option<crate::v05::descriptor::KeyDescriptor>> {
    use crate::v05::history::{Claim, Principal};
    let (verdict, _) = verified(entries, now_ms)?;
    let state = verdict
        .state
        .as_ref()
        .ok_or_else(|| malformed("the history has no verified genesis"))?;
    Ok(
        match state.current_principal(
            id,
            Claim::Controller {
                roles: &[],
                suspended_ok: false,
            },
            now_ms,
        ) {
            Ok(Principal::Controller(c)) if c.key().webauthn().is_some() => Some(c.key().clone()),
            _ => None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use crate::v05::write::calls::{prepare_history_read, HistoryReadSpec, EMPTY_BODY_SHA256};

    #[test]
    fn page_path_and_parse() {
        assert_eq!(history_page_path(0), "/authority?after=0&limit=64");
        let page = parse_history_page(br#"{"entries":[{"b":1,"a":2}],"receipts":[],"more":true}"#)
            .expect("a page");
        assert_eq!(page.entries, vec![br#"{"a":2,"b":1}"#.to_vec()]);
        assert!(page.more);
        assert!(parse_history_page(br#"{"entries":[1]}"#).is_err());
        assert!(parse_history_page(br#"{"more":false}"#).is_err());
        let many = format!("{{\"entries\":[{}]}}", vec!["{}"; 65].join(","));
        assert!(parse_history_page(many.as_bytes()).is_err());
    }

    #[test]
    fn size_bounds() {
        assert!(check_history_size(MAX_ENTRIES, MAX_HISTORY_BYTES).is_ok());
        assert_eq!(check_history_size(MAX_ENTRIES + 1, 0).err().map(|e| e.code()).as_deref(), Some("unavailable"));
        assert_eq!(check_history_size(1, MAX_HISTORY_BYTES + 1).err().map(|e| e.code()).as_deref(), Some("unavailable"));
        let big = format!("{{\"entries\":[{{\"p\":\"{}\"}}]}}", "a".repeat(MAX_ENTRY_BYTES));
        assert_eq!(parse_history_page(big.as_bytes()).err().map(|e| e.code()).as_deref(), Some("malformed"));
        let entry = vec![b'{'; MAX_ENTRY_BYTES + 1];
        let err = verified(vec![entry], 0).err().map(|e| e.code());
        assert_eq!(err.as_deref(), Some("malformed"));
    }

    #[test]
    fn empty_body_digest() {
        use sha2::{Digest, Sha256};
        let hex: String = Sha256::digest(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, EMPTY_BODY_SHA256);
    }

    #[test]
    fn history_read_only_at_a_history_path() {
        let account = AccountId::parse(&"ab".repeat(32)).expect("an ID");
        let key = p256::SecretKey::from_slice(&[1u8; 32])
            .expect("a scalar")
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let spec = |path: &'static str| HistoryReadSpec {
            account: &account,
            as_of: (1, "cd".repeat(32).leak()),
            signing: &key,
            audience: "https://home.test/v1/x/",
            path,
            request_id: [7; 32],
            created: "2026-11-20T00:00:00Z",
        };
        let p = prepare_history_read(&spec("/authority?after=0&limit=64")).expect("a history read");
        assert_eq!(p.url(), "https://home.test/v1/x/authority?after=0&limit=64");
        let body: serde_json::Value = serde_json::from_slice(p.step().body()).expect("json");
        assert_eq!(body["purpose"], "colophon.history.read");
        assert_eq!(body["audience"], "https://home.test/v1/x");
        assert_eq!(body["args"]["method"], "GET");
        assert_eq!(body["args"]["body"], EMPTY_BODY_SHA256);
        assert!(prepare_history_read(&spec("/changes")).is_err());
        assert!(prepare_history_read(&spec("/records/notes/x")).is_err());
    }

    fn passkey() -> (crate::keys::testing::SyntheticAuthenticator, Vec<u8>) {
        let a = crate::keys::testing::SyntheticAuthenticator::new().expect("an authenticator");
        let point = p256::ecdsa::SigningKey::from_slice(&[1; 32])
            .expect("a scalar")
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (a, point)
    }

    #[test]
    fn passkey_points_recover_the_signing_point() {
        let (a, point) = passkey();
        let body = [9u8; 32];
        for high_s in [false, true] {
            let s = a
                .assertion(&body, "id.luff.works", "https://id.luff.works", 0x05, high_s)
                .expect("an assertion");
            let ad = &s.assertion.authenticator_data;
            let cd = &s.assertion.client_data;
            let all = passkey_points(&body, "id.luff.works", ad, cd, &s.signature, None).expect("points");
            assert!(all.contains(&point), "the passkey's point is a candidate");
            assert!(all.len() <= 4);
            let id = crate::v05::ids::key_id(&point);
            let one = passkey_points(&body, "id.luff.works", ad, cd, &s.signature, Some(&id)).expect("the point");
            assert_eq!(one, vec![point.clone()]);
            let other = "00".repeat(16);
            let code = passkey_points(&body, "id.luff.works", ad, cd, &s.signature, Some(&other))
                .err()
                .map(|e| e.code());
            assert_eq!(code.as_deref(), Some("badSignature"));
        }
    }

    #[test]
    fn passkey_points_check_the_assertion_first() {
        let (a, _) = passkey();
        let body = [9u8; 32];
        let s = a
            .assertion(&body, "id.luff.works", "https://id.luff.works", 0x05, false)
            .expect("an assertion");
        let (ad, cd) = (&s.assertion.authenticator_data, &s.assertion.client_data);
        let code = |r: Result<Vec<Vec<u8>>>| r.err().map(|e| e.code());
        // Another relying party, another challenge, no user presence, a broken signature.
        assert_eq!(code(passkey_points(&body, "evil.example", ad, cd, &s.signature, None)).as_deref(), Some("badSignature"));
        assert_eq!(code(passkey_points(&[8u8; 32], "id.luff.works", ad, cd, &s.signature, None)).as_deref(), Some("badSignature"));
        let absent = a
            .assertion(&body, "id.luff.works", "https://id.luff.works", 0x04, false)
            .expect("an assertion");
        assert_eq!(
            code(passkey_points(&body, "id.luff.works", &absent.assertion.authenticator_data, &absent.assertion.client_data, &absent.signature, None)).as_deref(),
            Some("badSignature")
        );
        let mut der = s.signature.clone();
        der.push(0);
        assert_eq!(code(passkey_points(&body, "id.luff.works", ad, cd, &der, None)).as_deref(), Some("badSignature"));
        // A registration's clientData is not a get.
        let create = crate::v05::encoding::canonical(&serde_json::json!({
            "type": "webauthn.create",
            "challenge": crate::v05::signature::challenge(&body),
            "origin": "https://id.luff.works",
        }))
        .expect("json");
        let c = a.sign_bytes(ad.clone(), create.clone(), false).expect("bytes");
        assert_eq!(code(passkey_points(&body, "id.luff.works", ad, &create, &c.signature, None)).as_deref(), Some("badSignature"));
    }

    #[test]
    fn passkey_history_read_is_a_controller_call() {
        use crate::v05::write::calls::{finish_history_read, prepare_passkey_history_read};
        use crate::v05::write::SignatureResult;
        let (a, point) = passkey();
        let account = AccountId::parse(&"ab".repeat(32)).expect("an ID");
        let spec = HistoryReadSpec {
            account: &account,
            as_of: (1, account.as_str()),
            signing: &point,
            audience: "https://home.test/v1/x/",
            path: "/authority?after=0&limit=64",
            request_id: [7; 32],
            created: "2026-11-20T00:00:00Z",
        };
        let p = prepare_passkey_history_read(&spec).expect("a passkey history read");
        let body: serde_json::Value = serde_json::from_slice(p.step().body()).expect("json");
        assert_eq!(body["signer"]["controller"], crate::v05::ids::key_id(&point));
        assert_eq!(body["purpose"], "colophon.history.read");
        assert_eq!(body["asOf"]["digest"], account.as_str());
        assert!(p.step().challenge().is_some(), "the step asks for an assertion");
        let s = a
            .assertion(p.step().body(), "id.luff.works", "https://id.luff.works", 0x05, false)
            .expect("an assertion");
        let raw = SignatureResult { signature: s.signature.clone(), assertion: None };
        assert!(finish_history_read(&p, &raw).is_err(), "a passkey read needs its assertion");
        let sig = SignatureResult {
            signature: s.signature,
            assertion: Some((s.assertion.authenticator_data, s.assertion.client_data)),
        };
        let env = finish_history_read(&p, &sig).expect("an envelope");
        let call = crate::v05::calls::Call::parse(&env).expect("a call");
        assert!(matches!(call.signer, crate::v05::calls::CallSigner::Controller(_)));
        // Possession is checked: an assertion by another key is refused.
        let other = crate::keys::testing::SyntheticAuthenticator::from_scalar(&[2; 32]).expect("another");
        let o = other
            .assertion(p.step().body(), "id.luff.works", "https://id.luff.works", 0x05, false)
            .expect("an assertion");
        let wrong = SignatureResult {
            signature: o.signature,
            assertion: Some((o.assertion.authenticator_data, o.assertion.client_data)),
        };
        assert_eq!(finish_history_read(&p, &wrong).err().map(|e| e.code()).as_deref(), Some("badSignature"));
    }
}
