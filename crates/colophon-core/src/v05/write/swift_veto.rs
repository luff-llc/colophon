//! The veto of a Swift succession, signed by predecessor keys (§15.1 steps 3 and 4).
//!
//! A thief who writes a premature or foreign freezing entry, or who takes the root, can start a
//! succession of the owner's library. The owner's defence is a `colophon/veto/5` object whose
//! `transition` is the successor genesis's body digest, signed by as many keys as the genesis's
//! `handover` has signers, each an eligible key of §15.1 step 3, **under its predecessor (Swift)
//! descriptor**: `rpID` as `rp`, the general origin rule (§4.3), no `origins`, and user
//! verification. The successor's homes then receipt it and a home records it as
//! `successionVetoed` ([`super::succession::prepare_succession_vetoed`]); after that the
//! succession is never verified.
//!
//! **What is guaranteed.** The eligible keys, their descriptors, the count, the window and the
//! deadline are the verifier's own (`history::succession::eligible_veto_keys`,
//! `succession_status`, `swift::check`): nothing is re-implemented from caller facts.
//! [`PendingSwiftVeto::finish`] checks every signature with the verifier's `swift::check` over
//! the descriptors the rule names, and returns the envelope only when it would verify as a
//! veto. No secret passes through here. **The host is trusted** with signing exactly the bytes of
//! each step with the key the step names, and with showing the person the predecessor's last
//! entries before they confirm (§15.1 step 3, "Limit").
use super::authority::step_with_uv;
use super::{envelope, format_date, veto_body, Signature, SignatureResult, SigningStep, StepRole};
use crate::v05::descriptor::Controller;
use crate::v05::encoding::{bounds, digest};
use crate::v05::history::envelope::{AuthEnvelope, SigItem};
use crate::v05::history::succession::eligible_veto_keys;
use crate::v05::history::swift;
use crate::v05::history::{succession_status, verify_history, Objects, Persisted, Stop};
use crate::v05::{bad_signature, malformed, require, Failure, Reason, Result};
use std::collections::BTreeMap;

/// Inputs of [`prepare_swift_veto`].
#[derive(Clone, Debug)]
pub struct SwiftVetoParams {
    /// `issued`, in ms: at or after the window's start and before the veto deadline.
    pub issued_ms: i64,
    /// Predecessor controller IDs that sign: the first is `by`. As many as `handover` had.
    pub signers: Vec<String>,
}

/// A veto being signed. Fields are private.
#[derive(Debug)]
pub struct PendingSwiftVeto {
    steps: Vec<SigningStep>,
    body: Vec<u8>,
    eligible: BTreeMap<String, Vec<Controller>>,
}

fn unavailable(why: &str) -> Failure {
    Failure::Unavailable(why.into())
}

/// Prepare a veto of the succession the successor `objects` claim, signed by predecessor keys.
///
/// Refused, each with its reason: no succession or no window yet (nothing to veto); a signer that
/// is not an eligible key of §15.1 step 3; fewer signers than `handover` had; an `issued` before
/// the window or at or after the veto deadline (the succession is then due or past); and a
/// succession that is already vetoed or verified.
pub fn prepare_swift_veto(
    objects: &Objects,
    now_ms: i64,
    p: &SwiftVetoParams,
) -> Result<PendingSwiftVeto> {
    super::check_issued(p.issued_ms)?;
    let verdict = verify_history(objects, &Persisted::default(), now_ms);
    match &verdict.stop {
        None | Some(Stop::Failed { .. }) => {}
        Some(Stop::Held { why, .. }) => return Err(unavailable(&format!("held: {why}"))),
        Some(Stop::Fork { .. }) => return Err(Failure::Refused(Reason::Fork)),
    }
    let state = verdict
        .state
        .ok_or_else(|| malformed("the held objects hold no genesis"))?;
    let status =
        succession_status(&state).ok_or_else(|| malformed("this account has no predecessor"))?;
    require(
        status.format == super::succession::SWIFT_FORMAT,
        "only a Swift succession is vetoed by predecessor keys",
    )?;
    require(
        !status.vetoed && status.verified.is_none(),
        "the succession is already vetoed or verified",
    )?;
    let t = status
        .timing
        .as_ref()
        .ok_or_else(|| unavailable("the succession window has not opened: nothing to veto yet"))?;
    require(
        p.issued_ms >= t.window_start_ms,
        "a veto is issued at or after the succession window's start",
    )?;
    require(
        p.issued_ms < t.veto_deadline_ms,
        "the veto deadline has passed (§15.1 step 3)",
    )?;
    let distinct: std::collections::BTreeSet<&String> = p.signers.iter().collect();
    require(
        !p.signers.is_empty() && distinct.len() == p.signers.len(),
        "a veto has signers, each once",
    )?;
    require(
        p.signers.len() >= status.handover_count && status.handover_count > 0,
        "a veto needs as many keys as the handover had",
    )?;
    let eligible = eligible_veto_keys(&state)
        .ok_or_else(|| unavailable("the succession window has not opened"))?;
    let mut steps = Vec::new();
    let by = p.signers[0].clone();
    let body = veto_body(
        state.account().as_str(),
        &status.genesis_digest,
        &format_date(p.issued_ms),
        &by,
        &p.signers,
    )?;
    let path = format!("vetoes/{}.json", digest(&body));
    for (i, id) in p.signers.iter().enumerate() {
        let c = eligible.get(id).and_then(|v| v.first()).ok_or_else(|| {
            bad_signature("a vetoer is not an eligible predecessor key (§15.1 step 3)")
        })?;
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
    Ok(PendingSwiftVeto {
        steps,
        body,
        eligible,
    })
}

impl PendingSwiftVeto {
    /// The signing work, read-only: the primary, then the cosignatures. Every step asks for user
    /// verification, and a WebAuthn step's `rp` is the predecessor controller's `rpID`.
    pub fn steps(&self) -> &[SigningStep] {
        &self.steps
    }
    /// The veto's body digest: the object homes receipt and `successionVetoed` embeds.
    pub fn digest(&self) -> String {
        digest(&self.body)
    }
    /// Assemble the envelope from `signatures` (one per step, in order), check each under a
    /// descriptor §15.1 step 3 names with the Swift verifier's own check, and return it.
    pub fn finish(self, signatures: Vec<SignatureResult>) -> Result<Vec<u8>> {
        require(
            signatures.len() == self.steps.len(),
            "one signature per step",
        )?;
        let mut primary = None;
        let mut cosigs = Vec::new();
        for (st, sig) in self.steps.iter().zip(signatures) {
            if sig.assertion.is_some() != st.challenge().is_some() {
                return Err(bad_signature(
                    "an assertion is present if and only if the signer is webauthn",
                ));
            }
            let s = Signature {
                signer: st.signer().to_string(),
                signature: sig.signature,
                assertion: sig.assertion,
            };
            match st.role() {
                StepRole::Primary => primary = Some(s),
                _ => cosigs.push(s),
            }
        }
        let env = envelope(&self.body, primary.as_ref(), &cosigs, &[], &[])?;
        let parsed = AuthEnvelope::parse(&env, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true)?;
        require(
            parsed.additions.is_empty() && parsed.handover.is_empty(),
            "a succession veto carries only signatures",
        )?;
        for sig in parsed.primary.iter().chain(&parsed.cosignatures) {
            let item: &SigItem = sig;
            let ok = self.eligible.get(&item.signer).is_some_and(|cs| {
                cs.iter()
                    .any(|c| swift::check(c, &parsed.body, item, true).is_ok())
            });
            if !ok {
                return Err(bad_signature(
                    "a veto signature does not verify under its predecessor descriptor",
                ));
            }
        }
        Ok(env)
    }
}
