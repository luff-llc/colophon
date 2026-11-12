//! Heads (§13.2–§13.3): parsing and verification against a held history.
//!
//! Not here: the persisted high-water mark and `refused:rollback`, equivocation evidence
//! objects, and quorum across forks (§13.3 persistence and §8.6, outside this step).
use super::encoding::{bounds, Obj};
use super::ids::AccountId;
use super::signature::RawEnvelope;
use super::{bad_signature, require, Failure, Reason, Result, Unknown};

/// A verified head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// The home member ID that signed it.
    pub by: String,
    /// The covered seq.
    pub seq: u64,
    /// The body digest at `seq`.
    pub digest: String,
    /// `issued`, in ms.
    pub issued_ms: i64,
    /// Body digest of the head itself.
    pub body_digest: String,
}

/// What a head is checked against.
#[derive(Clone, Copy, Debug)]
pub struct HeadContext<'a> {
    /// The account.
    pub account: &'a AccountId,
    /// Body digests of the held, verified history, `history[0]` being seq 1.
    pub history: &'a [String],
    /// Current, unexpired homes in the latest held history: `(member ID, signing point)`.
    pub homes: &'a [(String, Vec<u8>)],
    /// The verifier's clock, in ms.
    pub now_ms: i64,
}

/// Verify a head envelope (§13.3): bounds and shape; `by` a current unexpired home whose key
/// verifies the signature (else `badSignature`); `issued` at most 60 s ahead; and the held
/// history contains `authority.seq` with that digest (different: `refused:fork`; not held:
/// `unavailable`). Freshness is [`Head::fresh`].
pub fn verify_head(envelope: &[u8], ctx: HeadContext<'_>) -> Result<Head> {
    let env = RawEnvelope::parse(envelope, bounds::HEAD_BODY, false)?;
    let mut o = Obj::new(env.value.clone(), "head")?;
    require(
        o.string("protocol")? == "colophon/head/5",
        "not a colophon/head/5 head",
    )?;
    let account = AccountId::parse(&o.string("account")?)?;
    let mut a = o.obj("authority")?;
    let seq = a.uint("seq")?;
    require(seq >= 1, "authority.seq must be at least 1")?;
    let digest = a.digest("digest")?;
    a.finish_closed()?;
    let (_, issued_ms) = o.date("issued")?;
    let by = o.key_id("by")?;
    let mut unknown = Unknown::default();
    o.finish(&mut unknown);
    require(&account == ctx.account, "head names another account")?;
    let Some((_, signing)) = ctx.homes.iter().find(|(id, _)| id == &by) else {
        return Err(bad_signature("head not signed by a current home"));
    };
    env.verify(signing)
        .map_err(|e| bad_signature(e.to_string()))?;
    unknown.check()?;
    if issued_ms > ctx.now_ms + 60_000 {
        return Err(Failure::Unavailable(
            "head issued more than 60 s ahead".into(),
        ));
    }
    let held = usize::try_from(seq - 1)
        .ok()
        .and_then(|i| ctx.history.get(i));
    match held {
        None => Err(Failure::Unavailable(
            "history not held up to the head".into(),
        )),
        Some(d) if d != &digest => Err(Failure::Refused(Reason::Fork)),
        Some(_) => Ok(Head {
            by,
            seq,
            digest,
            issued_ms,
            body_digest: super::encoding::digest(&env.body),
        }),
    }
}
impl Head {
    /// Fresh while `now − issued ≤ headMaxAge` (§13.3).
    pub fn fresh(&self, now_ms: i64, head_max_age_s: u64) -> bool {
        now_ms - self.issued_ms
            <= i64::try_from(head_max_age_s)
                .unwrap_or(i64::MAX)
                .saturating_mul(1_000)
    }
}
