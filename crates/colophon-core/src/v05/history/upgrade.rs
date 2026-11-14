//! The incorporated `/4` prefix (§16.1), verified by the released engine.
use super::{keyring::Keyring, state, Objects, State, Stop};
use crate::v05::{encoding, malformed, require, Failure, Result};
use crate::{authority::Authority, keys::AuthorityEnvelope, model::Records};
use serde_json::Value;
use std::collections::BTreeMap;

fn failure(e: crate::Error) -> Failure {
    match crate::keys::ErrorCode::of(&e) {
        Some(crate::keys::ErrorCode::BadSignature) => Failure::BadSignature(e.to_string()),
        Some(crate::keys::ErrorCode::NewerFormat) => Failure::NewerFormat(e.to_string()),
        _ => malformed(e.to_string()),
    }
}

/// The 0.4 control rule an `upgrade` is signed under (§16.1): at least `threshold` signers,
/// each a current controller holding `control`, none with a WebAuthn assertion that lacks UV.
/// `signers` is `(controller ID, uv)` with `uv` `None` for a raw signature. The one definition of
/// the rule: [`check_upgrade`] applies it to the verified signatures and the write side applies it
/// before it asks a host to sign.
pub(crate) fn signers_meet_rule(prior: &Authority, signers: &[(String, Option<bool>)]) -> bool {
    !signers.is_empty()
        && signers.len() >= prior.keyring.threshold as usize
        && signers.iter().all(|(id, uv)| {
            *uv != Some(false)
                && prior
                    .keyring
                    .controller(id)
                    .is_some_and(|c| c.roles.contains(&crate::authority::Role::Control))
        })
}

fn check_upgrade(
    prior: &Authority,
    env: &AuthorityEnvelope,
    value: &Value,
    account: &str,
) -> Result<Keyring> {
    let signers = env
        .verify_all(|id| prior.keyring.controller(id).map(|c| &c.key), true)
        .map_err(failure)?;
    require(!signers.is_empty(), "unsigned upgrade")?;
    let ids: Vec<(String, Option<bool>)> = signers.iter().map(|s| (s.id.clone(), s.uv)).collect();
    if !signers_meet_rule(prior, &ids) {
        return Err(crate::v05::bad_signature(
            "upgrade requires the 0.4 control rule",
        ));
    }
    env.check_known_fields().map_err(failure)?;
    check_upgrade_body(prior, value, account)
}

/// Everything about an `upgrade` body that does not depend on its signatures (§16.1): the
/// closed field set, `seq` (not 2, the next one), `previous`, `account`, `issued`, the 0.5
/// keyring and its carried fields. The write side runs it on the body it is about to ask a host
/// to sign.
pub(crate) fn check_upgrade_body(
    prior: &Authority,
    value: &Value,
    account: &str,
) -> Result<Keyring> {
    let mut fields = encoding::Obj::new(value.clone(), "upgrade")?;
    for f in [
        "protocol", "seq", "previous", "issued", "by", "kind", "account", "keyring",
    ] {
        fields.value(f)?;
    }
    let mut unknown = crate::v05::Unknown::default();
    fields.finish(&mut unknown);
    unknown.check()?;
    require(
        value["seq"].as_u64() == Some(prior.latest + 1) && prior.latest >= 2,
        "upgrade cannot be seq 2",
    )?;
    require(
        value["previous"] == prior.last_digest && value["account"] == account,
        "upgrade binding",
    )?;
    let issued = encoding::parse_date(
        value["issued"]
            .as_str()
            .ok_or_else(|| malformed("issued"))?,
    )
    .ok_or_else(|| malformed("issued"))?;
    let previous = prior
        .entries
        .last()
        .ok_or_else(|| malformed("missing prefix"))?;
    require(
        issued >= encoding::parse_date(&previous.issued).ok_or_else(|| malformed("issued"))?,
        "upgrade issued before prefix",
    )?;
    let k = Keyring::parse(value["keyring"].clone(), 1)?;
    k.unknown.check()?;
    let old = serde_json::to_value(&prior.keyring).map_err(|e| malformed(e.to_string()))?;
    for f in [
        "controllers",
        "threshold",
        "recoverThreshold",
        "vault",
        "slots",
    ] {
        require(
            k.raw[f] == old[f],
            "upgrade changes a carried keyring field",
        )?;
    }
    Ok(k)
}

/// None means this is an ordinary `/5` history. Every prefix candidate is actually replayed.
pub(super) fn bootstrap(
    objects: &Objects,
    now_ms: i64,
) -> Option<std::result::Result<State, Stop>> {
    type Candidate = (Vec<u8>, AuthorityEnvelope, Value);
    let mut groups: BTreeMap<u64, BTreeMap<String, Candidate>> = BTreeMap::new();
    let mut legacy = false;
    for bytes in &objects.entries {
        if let Ok(env) = AuthorityEnvelope::from_json(bytes) {
            if let Ok(v) = env.body_value() {
                if v["seq"] == 1 && v["protocol"] == "colophon/authority/4" {
                    legacy = true;
                }
                if v["protocol"] == "colophon/authority/4" {
                    if let Some(seq) = v["seq"].as_u64() {
                        groups
                            .entry(seq)
                            .or_default()
                            .entry(encoding::digest(&env.body))
                            .or_insert((bytes.clone(), env, v));
                    }
                }
            }
        }
    }
    if !legacy {
        return None;
    }
    let run = || -> std::result::Result<State, Stop> {
        let mut records = Records::new();
        let mut seq = 1;
        let mut account = String::new();
        loop {
            let Some(candidates) = groups.get(&seq) else {
                return Err(Stop::Failed {
                    seq,
                    failure: Failure::Unavailable("upgrade prefix is incomplete".into()),
                });
            };
            let mut accepted = Vec::new();
            let mut first = None;
            for (digest, (bytes, env, value)) in candidates {
                let mut proposed = records.clone();
                proposed.insert(format!("authority/{seq:08}.json"), bytes.clone());
                let result = if value["kind"] == "upgrade" {
                    Authority::replay(&records)
                        .map_err(failure)
                        .and_then(|prior| {
                            let k = check_upgrade(&prior, env, value, &account)?;
                            state::from_upgrade(&prior, k, &proposed, seq)
                        })
                        .map(Some)
                } else {
                    Authority::replay(&proposed).map_err(failure).map(|_| None)
                };
                match result {
                    Ok(state) => accepted.push((digest, proposed, state)),
                    Err(f) if first.is_none() => first = Some(f),
                    Err(_) => {}
                }
            }
            if accepted.len() > 1 {
                return Err(Stop::Fork { seq });
            }
            let Some((digest, proposed, state)) = accepted.pop() else {
                return Err(Stop::Failed {
                    seq,
                    failure: first.unwrap_or_else(|| malformed("no prefix candidate")),
                });
            };
            if seq == 1 {
                account.clone_from(digest);
            }
            if let Some(state) = state {
                if state.last_issued() > now_ms.saturating_add(60_000) {
                    return Err(Stop::Held {
                        seq,
                        why: "future upgrade".into(),
                    });
                }
                return Ok(state);
            }
            records = proposed;
            seq += 1;
        }
    };
    Some(run())
}
