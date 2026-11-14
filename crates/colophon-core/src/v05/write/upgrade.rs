//! The in-place upgrade of a 0.4 account to 0.5 (§16.1): prepare, then finish.
//!
//! One `upgrade` entry is appended to a verified 0.4 history, signed under the 0.4 control rule
//! with UV, after which the account is a 0.5 account with the same keys, vault, slots, members and
//! records. The entry is a `/4` body (`protocol` `colophon/authority/4`, the 0.3 date format with
//! milliseconds), so none of the `/5` body builders apply.
//!
//! **What this module guarantees.**
//! * [`prepare_upgrade`] takes the 0.4 history, verifies it with the released 0.4 verifier
//!   (`authority::Authority::replay`, unchanged), derives every carried field of the new keyring
//!   from that verified history (never from the caller), and runs the verifier's own body check
//!   ([`upgrade::check_upgrade_body`]) and its own signer rule ([`upgrade::signers_meet_rule`])
//!   on the body before any host is asked to sign. It refuses an upgrade at seq 2, an upgrade of an
//!   account that already holds a `/5` or `upgrade` entry, a signer below the rule and a setting
//!   out of range with the verifier's reason.
//! * [`PendingUpgrade::finish`] assembles the envelope from the host's signatures, runs
//!   `v05::history::verify_history` over the 0.4 entries plus the new one, and returns the entry
//!   only when the account verifies as 0.5 at that entry with the same controllers, threshold,
//!   recover threshold, vault, slots and members as the 0.4 account. The bytes returned are the
//!   bytes that were verified. Nothing is returned on failure.
//! * No secret passes through here: the module sees public keyrings, bodies and signatures.
//!
//! **What the host is trusted with.** Signing the exact bytes of each step with the controller's
//! key; holding the 0.4 entries it passes in (they are verified here, not trusted); and the
//! §16.1 rule that it MUST NOT write the entry until every app writing to the library reads 0.5
//! (nothing in a history shows that).
use super::authority::step_with_uv;
use super::{envelope, format_date, Records, Signature, SignatureResult, SigningStep, StepRole};
use crate::authority::Authority;
use crate::model::Records as Legacy;
use crate::v05::encoding::{canonical, digest};
use crate::v05::history::keyring::Keyring;
use crate::v05::history::upgrade::{check_upgrade_body, signers_meet_rule};
use crate::v05::history::{verify_history, Objects, Persisted};
use crate::v05::{bad_signature, malformed, require, Failure, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// The protocol marker of the entry: a `/4` body (§16.1).
pub const UPGRADE_PROTOCOL: &str = "colophon/authority/4";

/// The 0.5 settings an upgrade adds to the carried keyring (§16.1, §18).
#[derive(Clone, Debug)]
pub struct UpgradeParams {
    /// The whole §6.3 `policy` object, in §18's ranges.
    pub policy: Value,
    /// `addThreshold`, 1 to the control threshold.
    pub add_threshold: u64,
    /// `countBy`: `keys` or `holders` (`holders` needs a holder on every controller, which a 0.4
    /// controller does not have, so the verifier refuses it here).
    pub count_by: String,
    /// `issued`, in ms; not earlier than the previous entry's.
    pub issued_ms: i64,
    /// Controller IDs that sign: the first is `by`, the rest cosign. They meet the 0.4 control
    /// rule: each holds `control`, and there are at least `threshold` of them.
    pub signers: Vec<String>,
}

/// The 0.3 date format of a `/4` body: always `.sss` (§16.1 incorporates 0.4's rules).
fn legacy_date(ms: i64) -> String {
    let s = format_date(ms);
    if s.contains('.') {
        s
    } else {
        format!("{}.000Z", &s[..s.len() - 1])
    }
}

/// Exact signing work for one upgrade, and what finishing it needs. The fields are private.
#[derive(Debug)]
pub struct PendingUpgrade {
    steps: Vec<SigningStep>,
    entries: Vec<Vec<u8>>,
    body: Vec<u8>,
    seq: u64,
    prior_keyring: Value,
    prior_members: BTreeSet<String>,
    now_ms: i64,
}

/// Prepare the `upgrade` entry (§16.1) on `history`, a 0.4 account's `authority/*.json` records.
/// `now_ms` is the clock the verifier holds an `issued` in the future against.
pub fn prepare_upgrade(history: &Legacy, p: &UpgradeParams, now_ms: i64) -> Result<PendingUpgrade> {
    super::check_issued(p.issued_ms)?;
    let prior = Authority::replay(history).map_err(|e| match crate::keys::ErrorCode::of(&e) {
        Some(crate::keys::ErrorCode::BadSignature) => Failure::BadSignature(e.to_string()),
        Some(crate::keys::ErrorCode::NewerFormat) => Failure::NewerFormat(format!(
            "the history is not a plain 0.4 history (already upgraded, or newer): {e}"
        )),
        _ => malformed(e.to_string()),
    })?;
    let entries: Vec<Vec<u8>> = history
        .iter()
        .filter(|(path, _)| path.starts_with("authority/"))
        .map(|(_, bytes)| bytes.clone())
        .collect();
    let genesis = entries
        .first()
        .ok_or_else(|| malformed("the history holds no genesis"))?;
    let genesis_body = body_of(genesis)?;
    let account = digest(&genesis_body);
    let prior_keyring =
        serde_json::to_value(&prior.keyring).map_err(|e| malformed(e.to_string()))?;
    // Every carried field comes from the verified prior keyring.
    let mut keyring = prior_keyring.clone();
    keyring["addThreshold"] = json!(p.add_threshold);
    keyring["countBy"] = json!(p.count_by);
    keyring["policy"] = p.policy.clone();
    // The signers.
    let distinct: BTreeSet<&String> = p.signers.iter().collect();
    require(
        !p.signers.is_empty() && distinct.len() == p.signers.len(),
        "upgrade signers: at least one, each once",
    )?;
    let uv: Vec<(String, Option<bool>)> = p
        .signers
        .iter()
        .map(|s| {
            let webauthn = prior
                .keyring
                .controller(s)
                .is_some_and(|c| c.key.is_webauthn());
            (s.clone(), webauthn.then_some(true))
        })
        .collect();
    if !signers_meet_rule(&prior, &uv) {
        return Err(bad_signature("upgrade requires the 0.4 control rule"));
    }
    let by = p.signers[0].clone();
    let body_value = json!({
        "protocol": UPGRADE_PROTOCOL,
        "seq": prior.latest + 1,
        "previous": prior.last_digest,
        "issued": legacy_date(p.issued_ms),
        "by": by,
        "kind": "upgrade",
        "account": account,
        "keyring": keyring,
    });
    // The verifier's own body check: seq, previous, account, issued, closed fields, the 0.5
    // keyring (ranges of §18), and every carried field equal.
    check_upgrade_body(&prior, &body_value, &account)?;
    let body = canonical(&body_value)?;
    require(
        body.len() <= crate::v05::encoding::bounds::AUTHORITY_BODY,
        "authority body exceeds 1,048,576 bytes",
    )?;
    // Steps: the 0.5 view of each controller's key, which is the same descriptor.
    let new = Keyring::parse(keyring, 1)?;
    let path = format!("authority/{:08}.json", prior.latest + 1);
    let mut steps = Vec::new();
    for (i, id) in p.signers.iter().enumerate() {
        let c = new
            .controllers
            .get(id)
            .ok_or_else(|| bad_signature("a signer is not a controller"))?;
        steps.push(step_with_uv(
            &path,
            &body,
            c,
            if i == 0 {
                StepRole::Primary
            } else {
                StepRole::Cosignature
            },
            true,
        ));
    }
    Ok(PendingUpgrade {
        steps,
        entries,
        body,
        seq: prior.latest + 1,
        prior_keyring,
        prior_members: prior.members.keys().cloned().collect(),
        now_ms,
    })
}

fn body_of(env: &[u8]) -> Result<Vec<u8>> {
    let v: Value = crate::keys::strict_json::parse(env).map_err(|e| malformed(e.to_string()))?;
    let b = v
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("entry has no body"))?;
    crate::v05::encoding::decode_base64(b, 1_048_576)
}

impl PendingUpgrade {
    /// The signing work, read-only: the primary, then the cosignatures. Every WebAuthn step
    /// asks for UV.
    pub fn steps(&self) -> &[SigningStep] {
        &self.steps
    }
    /// The entry's seq.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Assemble the envelope from `signatures` (one per step, in order), verify the whole
    /// history as a 0.5 account, and return the entry. Nothing is returned unless the account
    /// verifies at this entry, upgraded, with the same keyring fields and members.
    pub fn finish(self, signatures: Vec<SignatureResult>) -> Result<Records> {
        require(
            signatures.len() == self.steps.len(),
            "one signature per step",
        )?;
        let (mut primary, mut cosigs) = (None, Vec::new());
        for (step, sig) in self.steps.iter().zip(signatures) {
            if sig.assertion.is_some() != step.challenge().is_some() {
                return Err(bad_signature(
                    "an assertion is present if and only if the signer is webauthn",
                ));
            }
            let s = Signature {
                signer: step.signer().to_string(),
                signature: sig.signature,
                assertion: sig.assertion,
            };
            match step.role() {
                StepRole::Primary => primary = Some(s),
                _ => cosigs.push(s),
            }
        }
        let env = envelope(&self.body, primary.as_ref(), &cosigs, &[], &[])?;
        let mut objects = Objects {
            entries: self.entries.clone(),
            ..Objects::default()
        };
        objects.entries.push(env.clone());
        let verdict = verify_history(&objects, &Persisted::default(), self.now_ms);
        match &verdict.stop {
            None => {}
            Some(crate::v05::history::Stop::Failed { failure, .. }) => return Err(failure.clone()),
            Some(crate::v05::history::Stop::Held { why, .. }) => {
                return Err(super::unavailable(format!("held: {why}")))
            }
            Some(crate::v05::history::Stop::Fork { .. }) => {
                return Err(Failure::Refused(crate::v05::Reason::Fork))
            }
        }
        let state = verdict
            .state
            .ok_or_else(|| malformed("the history holds no genesis"))?;
        require(
            verdict.branch.len() as u64 == self.seq
                && verdict.branch.last() == Some(&digest(&self.body))
                && state.upgrade_seq == Some(self.seq),
            "the account does not verify as upgraded at this entry",
        )?;
        for f in [
            "controllers",
            "threshold",
            "recoverThreshold",
            "vault",
            "slots",
        ] {
            require(
                state.keyring().raw[f] == self.prior_keyring[f],
                "the upgraded account's keyring differs from the 0.4 account's",
            )?;
        }
        let members: BTreeSet<String> = state
            .members()
            .iter()
            .map(|m| m.request.member_id())
            .collect();
        require(
            members == self.prior_members,
            "the upgraded account's members differ from the 0.4 account's",
        )?;
        Ok(Records {
            entries: vec![(self.seq, env)],
            ..Records::default()
        })
    }
}
