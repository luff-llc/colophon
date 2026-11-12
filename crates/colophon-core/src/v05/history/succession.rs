//! Succession claims, handover, witnessed windows and terminal predecessors (§15).
use super::{
    envelope::{embedded_bytes, AuthEnvelope},
    swift, Entry, Objects, State,
};
use crate::v05::descriptor::{Controller, Role};
use crate::v05::encoding::{bounds, Obj};
use crate::v05::signature::{verify_authority_signature, AuthorityRule, Checked, RawEnvelope};
use crate::v05::{bad_signature, malformed, require, Failure, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Succession {
    pub claim: Value,
    pub genesis: Vec<u8>,
    pub genesis_digest: String,
    pub genesis_issued: i64,
    pub swift: Option<swift::History>,
    pub head_seq: u64,
    pub carried_keys: BTreeMap<String, Controller>,
    pub handover_count: usize,
    pub authorized: bool,
    pub window: Option<Window>,
    pub vetoed: bool,
    pub verified: Option<(u64, String)>,
    pub evidence_after_final: Vec<u64>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Window {
    pub start: i64,
    pub delay: u64,
    pub quorum: usize,
    pub homes: BTreeMap<String, Vec<u8>>,
}
impl Succession {
    pub fn carried(&self, id: &str, c: &Controller) -> bool {
        self.carried_keys.get(id).is_some_and(|old| {
            if self.claim["format"] == "colophon/authority/5" {
                return old.key() == c.key();
            }
            old.key().signing() == c.key().signing()
                && match (old.key().webauthn(), c.key().webauthn()) {
                    (Some(a), Some(b)) => a.rp() == b.rp() && a.credential() == b.credential(),
                    (None, None) => true,
                    _ => false,
                }
        })
    }
}

pub(super) fn prepare(e: &Entry, predecessor: &[Vec<u8>], now: i64) -> Result<Option<Succession>> {
    let Some(claim) = e.env.value.get("predecessor") else {
        require(e.env.handover.is_empty(), "handover without predecessor")?;
        return Ok(None);
    };
    let mut o = Obj::new(claim.clone(), "predecessor")?;
    let format = o.string("format")?;
    let account = o.string("account")?;
    let mut h = o.obj("head")?;
    let seq = h.uint("seq")?;
    let head = h.digest("digest")?;
    require(seq >= 1, "predecessor head sequence")?;
    h.finish_closed()?;
    o.finish_closed()?;
    let mut p = Succession {
        claim: claim.clone(),
        genesis: e.env.body.clone(),
        genesis_digest: e.env.digest.clone(),
        genesis_issued: e.issued,
        swift: None,
        head_seq: seq,
        carried_keys: Default::default(),
        handover_count: e.env.handover.len(),
        authorized: false,
        window: None,
        vetoed: false,
        verified: None,
        evidence_after_final: Vec::new(),
    };
    if predecessor.is_empty() {
        return Err(Failure::Unavailable("predecessor history required".into()));
    }
    match format.as_str() {
        "colophon/swift-keyring/2" => {
            let prefix: Vec<Vec<u8>> = predecessor
                .iter()
                .filter(|b| super::state::raw_seq(b).is_some_and(|n| n <= seq.saturating_add(1)))
                .cloned()
                .collect();
            let history = swift::verify(&prefix)?;
            p.evidence_after_final = predecessor
                .iter()
                .filter_map(|b| super::state::raw_seq(b))
                .filter(|n| *n > seq.saturating_add(1))
                .collect();
            p.evidence_after_final.sort_unstable();
            p.evidence_after_final.dedup();
            require(history.account == account, "Swift predecessor account")?;
            let idx = usize::try_from(seq - 1).map_err(|_| malformed("predecessor sequence"))?;
            let r = history
                .entries
                .get(idx)
                .ok_or_else(|| Failure::Unavailable("predecessor head missing".into()))?;
            require(r.digest == head, "predecessor head digest")?;
            require(e.issued >= r.issued_ms, "genesis before predecessor head")?;
            let s = &history.states[idx];
            p.carried_keys = s.controllers.clone();
            let k = super::keyring::Keyring::parse(e.env.value["keyring"].clone(), 1)?;
            let mut ids = BTreeSet::new();
            for item in &e.env.handover {
                let old = s
                    .controllers
                    .get(&item.signer)
                    .ok_or_else(|| bad_signature("foreign handover key"))?;
                let c = k.controllers.get(&item.signer).unwrap_or(old);
                if !p.carried(&item.signer, c) {
                    return Err(bad_signature("handover descriptor binding"));
                }
                if verify_authority_signature(
                    c,
                    &e.env.body,
                    &item.signature,
                    item.assertion_bytes(),
                    AuthorityRule::Handover,
                )? != Checked::Verified
                {
                    return Err(Failure::NewerFormat("handover key form".into()));
                }
                let _ = old;
                ids.insert(item.signer.clone());
            }
            let recover_set: BTreeSet<String> = s
                .controllers
                .iter()
                .filter(|(_, c)| c.has(&Role::Recover))
                .map(|(id, _)| id.clone())
                .collect();
            let new_set: BTreeSet<String> = k
                .controllers
                .iter()
                .filter(|(_, c)| c.has(&Role::Recover))
                .map(|(id, _)| id.clone())
                .collect();
            let consent = recover_set == new_set && k.recover_threshold >= s.recover_threshold
                || ids.intersection(&recover_set).count() as u64 >= s.recover_threshold;
            p.authorized = if s.adopted {
                ids.iter()
                    .filter(|id| s.controllers[*id].has(&Role::Control))
                    .count() as u64
                    >= s.threshold
                    && consent
            } else {
                ids.contains(&s.root)
            };
            p.swift = Some(history);
        }
        "colophon/authority/5" => {
            let objects = Objects {
                entries: predecessor.to_vec(),
                ..Default::default()
            };
            let v = super::verify_history(&objects, &Default::default(), now);
            let Some(s) = v.state else {
                return Err(Failure::Unavailable("predecessor not verified".into()));
            };
            require(
                s.account().as_str() == account
                    && s.history().get((seq - 1) as usize) == Some(&head),
                "predecessor binding",
            )?;
            if matches!(v.stop,Some(super::Stop::Fork {seq:n}) if n<=seq+1) {
                return Err(Failure::Refused(crate::v05::Reason::Fork));
            }
            p.carried_keys = s
                .ever
                .iter()
                .filter_map(|(id, cs)| {
                    cs.iter()
                        .rev()
                        .find(|(n, _)| *n <= seq)
                        .and_then(|(_, c)| c.as_ref().map(|c| (id.clone(), c.clone())))
                })
                .collect();
            p.authorized = s.successor.as_deref()
                == Some(crate::v05::ids::AccountId::of_genesis(&e.env.body).as_str())
                && s.history().len() as u64 == seq + 1;
            if p.authorized {
                p.verified = Some((seq + 1, s.history().last().cloned().unwrap_or_default()));
            }
            require(
                e.env.handover.is_empty(),
                "handover only for Swift predecessor",
            )?;
        }
        f => return Err(Failure::NewerFormat(format!("predecessor format {f}"))),
    }
    Ok(Some(p))
}
pub(super) fn observe_window(s: &mut State, e: &Entry) {
    let Some(p) = &s.succession else { return };
    if p.swift.is_none() || p.window.is_some() {
        return;
    }
    let quorum = s.keyring.policy.head_quorum() as usize;
    let homes: BTreeMap<String, Vec<u8>> = s
        .current_homes()
        .iter()
        .map(|m| (m.request.member_id(), m.request.signing.clone()))
        .collect();
    if homes.len() >= quorum && quorum > 0 {
        let w = Window {
            start: e.issued,
            delay: s.keyring.policy.recovery_delay(),
            quorum,
            homes,
        };
        if let Some(p) = &mut s.succession {
            p.window = Some(w);
        }
    }
}
fn receipts(
    s: &State,
    w: &Window,
    list: &[Value],
    object: &str,
    issued: i64,
    deadline: i64,
) -> Result<i64> {
    require(list.len() == w.quorum, "succession receipt quorum")?;
    let mut last = String::new();
    let mut latest = issued;
    for value in list {
        let bytes = embedded_bytes(value, "receipt", bounds::RECEIPT_ENVELOPE)?;
        let env = RawEnvelope::parse_bounded(
            &bytes,
            bounds::RECEIPT_BODY,
            bounds::RECEIPT_ENVELOPE,
            true,
        )?;
        let mut o = Obj::new(env.value.clone(), "receipt")?;
        require(
            o.string("protocol")? == "colophon/receipt/5"
                && o.string("account")? == s.account().as_str(),
            "succession receipt binding",
        )?;
        require(o.digest("object")? == object, "succession receipt object")?;
        let (_, at) = o.date("received")?;
        let by = o.key_id("by")?;
        o.finish_closed()?;
        let key = w
            .homes
            .get(&by)
            .ok_or_else(|| malformed("succession receipt home"))?;
        env.verify(key).map_err(|e| bad_signature(e.to_string()))?;
        require(
            by > last && at >= issued && at <= issued.saturating_add(300_000) && at < deadline,
            "succession receipt window or order",
        )?;
        last = by;
        latest = latest.max(at);
    }
    Ok(latest)
}
fn eligible(p: &Succession, w: &Window) -> BTreeMap<String, Vec<Controller>> {
    let mut out: BTreeMap<String, Vec<Controller>> = BTreeMap::new();
    let Some(h) = &p.swift else { return out };
    let end = (p.head_seq as usize).min(h.states.len());
    let cutoff = w
        .start
        .saturating_sub((w.delay as i64).saturating_mul(1000));
    let mut effective = i64::MIN;
    let mut last_removal = None;
    for i in 0..end {
        effective = effective.max(h.entries[i].issued_ms);
        if effective >= cutoff {
            for state in h.states[i.saturating_sub(1)..=i].iter() {
                for (id, c) in &state.controllers {
                    out.entry(id.clone()).or_default().push(c.clone());
                }
            }
        }
        if i > 0
            && h.states[i - 1]
                .controllers
                .keys()
                .any(|id| !h.states[i].controllers.contains_key(id))
        {
            last_removal = Some(i - 1);
        }
    }
    if end > 0 {
        // State at cutoff includes the last entry before it, and all keys at head.
        let at = (0..end)
            .rev()
            .find(|i| {
                h.entries[..=*i]
                    .iter()
                    .map(|e| e.issued_ms)
                    .max()
                    .unwrap_or(i64::MIN)
                    <= cutoff
            })
            .unwrap_or(0);
        for i in [Some(at), Some(end - 1), last_removal]
            .into_iter()
            .flatten()
        {
            for (id, c) in &h.states[i].controllers {
                out.entry(id.clone()).or_default().push(c.clone());
            }
        }
    }
    out
}
pub(super) fn vetoed(s: &State, e: &Entry) -> Result<State> {
    require(e.env.primary.is_none(), "successionVetoed unsigned")?;
    let p = s
        .succession
        .as_ref()
        .ok_or_else(|| malformed("successionVetoed without predecessor"))?;
    require(
        !p.vetoed && p.swift.is_some(),
        "successionVetoed once and only for Swift",
    )?;
    let w = p
        .window
        .as_ref()
        .ok_or_else(|| malformed("succession window absent"))?;
    require(p.genesis_issued <= w.start, "genesis after window")?;
    let deadline = w
        .start
        .saturating_add((w.delay as i64).saturating_mul(1000));
    let due = deadline.saturating_add(300_000);
    let mut o = super::super::members::AuthorityHeader::split(e.env.value.clone())?.1;
    let bytes = embedded_bytes(&o.value("veto")?, "veto", bounds::VETO_ENVELOPE)?;
    let rs = o.array("receipts")?;
    let gs = o.array("genesisReceipts")?;
    o.finish_closed()?;
    receipts(s, w, &gs, &p.genesis_digest, w.start, i64::MAX)?;
    let v = AuthEnvelope::parse(&bytes, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true)?;
    let mut vo = Obj::new(v.value.clone(), "succession veto")?;
    require(
        vo.string("protocol")? == "colophon/veto/5"
            && vo.string("account")? == s.account().as_str()
            && vo.digest("transition")? == p.genesis_digest,
        "succession veto binding",
    )?;
    let (_, issued) = vo.date("issued")?;
    let by = vo.key_id("by")?;
    let ids = vo.array("signers")?;
    vo.finish_closed()?;
    let signers = v.signer_ids();
    require(
        ids == signers
            .iter()
            .map(|s| Value::String(s.clone()))
            .collect::<Vec<_>>(),
        "succession veto signers",
    )?;
    require(
        e.by == by && signers.len() >= p.handover_count && p.handover_count > 0,
        "succession veto count or by",
    )?;
    require(
        issued >= w.start && issued < deadline,
        "succession veto deadline",
    )?;
    let keys = eligible(p, w);
    for sig in v.primary.iter().chain(&v.cosignatures) {
        let cs = keys
            .get(&sig.signer)
            .ok_or_else(|| malformed("ineligible succession vetoer"))?;
        if !cs
            .iter()
            .any(|c| swift::check(c, &v.body, sig, true).is_ok())
        {
            return Err(bad_signature("succession veto signature"));
        }
    }
    require(
        v.additions.is_empty() && v.handover.is_empty(),
        "succession veto envelope",
    )?;
    let latest = receipts(s, w, &rs, &v.digest, issued, deadline)?;
    require(
        e.issued == s.last_issued().max(latest) && e.issued <= due.saturating_add(604_800_000),
        "successionVetoed determined issued",
    )?;
    let mut n = s.clone();
    if let Some(p) = &mut n.succession {
        p.vetoed = true;
        p.verified = None;
    }
    Ok(n)
}

pub(super) fn finish(s: &mut State, objects: &Objects, now: i64) {
    let Some(mut p) = s.succession.clone() else {
        return;
    };
    if p.verified.is_some() || p.swift.is_none() {
        return;
    }
    let Some(w) = &p.window else { return };
    if !p.authorized || p.vetoed || p.genesis_issued > w.start {
        return;
    }
    let due = w
        .start
        .saturating_add(300_000)
        .saturating_add((w.delay as i64).saturating_mul(1000));
    if now < due {
        return;
    }
    // Genesis receipts may be external objects or embedded in a veto recording.
    let rs: BTreeMap<String, Value> = objects
        .pending
        .iter()
        .filter_map(|b| {
            let env = RawEnvelope::parse(b, bounds::RECEIPT_BODY, false).ok()?;
            if env.value["object"] != p.genesis_digest {
                return None;
            }
            let by = env.value["by"].as_str()?.to_string();
            let canonical =
                crate::v05::encoding::canonical(&serde_json::from_slice::<Value>(b).ok()?).ok()?;
            Some((
                by,
                Value::String(crate::v05::encoding::encode_base64(&canonical)),
            ))
        })
        .collect();
    let chosen: Vec<Value> = rs
        .values()
        .filter(|r| {
            receipts(
                s,
                &Window {
                    quorum: 1,
                    ..w.clone()
                },
                std::slice::from_ref(r),
                &p.genesis_digest,
                w.start,
                i64::MAX,
            )
            .is_ok()
        })
        .take(w.quorum)
        .cloned()
        .collect();
    if receipts(s, w, &chosen, &p.genesis_digest, w.start, i64::MAX).is_err() {
        return;
    }
    let h = match &p.swift {
        Some(h) => h,
        None => return,
    };
    let Some(f) = h.entries.get(p.head_seq as usize) else {
        return;
    };
    if f.value["kind"] != "layout"
        || f.value["layout"].as_u64().unwrap_or(0) <= 2
        || f.value["successor"] != s.account().as_str()
        || f.issued_ms <= due
    {
        return;
    }
    for (id, key) in &w.homes {
        let covered = objects.heads.iter().any(|bytes| {
            let Ok(env) = RawEnvelope::parse(bytes, bounds::HEAD_BODY, false) else {
                return false;
            };
            let v = &env.value;
            let Some(at) = v["issued"]
                .as_str()
                .and_then(crate::v05::encoding::parse_date)
            else {
                return false;
            };
            let Some(n) = v["authority"]["seq"].as_u64() else {
                return false;
            };
            v["protocol"] == "colophon/head/5"
                && v["account"] == s.account().as_str()
                && v["by"] == *id
                && at > due
                && at <= now.saturating_add(60_000)
                && at >= now.saturating_sub((s.keyring.policy.head_max_age() as i64) * 1000)
                && n >= 2
                && s.history()
                    .get(n.saturating_sub(1) as usize)
                    .is_some_and(|d| v["authority"]["digest"] == *d)
                && env.verify(key).is_ok()
        });
        if !covered {
            return;
        }
    }
    p.verified = Some((p.head_seq + 1, f.digest.clone()));
    s.succession = Some(p);
}

pub(super) fn migration(s: &mut State, value: &Value) -> Result<()> {
    require(
        s.succession.is_some() && s.migration.is_none(),
        "migration needs predecessor and occurs once",
    )?;
    let p = s
        .succession
        .as_ref()
        .ok_or_else(|| malformed("migration predecessor"))?;
    require(!p.vetoed, "migration after succession veto")?;
    let mut o = Obj::new(value.clone(), "migration")?;
    let mut pred = o.obj("predecessor")?;
    require(
        pred.string("format")? == p.claim["format"]
            && pred.string("account")? == p.claim["account"],
        "migration predecessor binding",
    )?;
    let mut final_ = pred.obj("final")?;
    require(final_.uint("seq")? == p.head_seq + 1, "migration final seq")?;
    final_.digest("digest")?;
    final_.finish_closed()?;
    pred.finish_closed()?;
    let mut drain = o.obj("drain")?;
    let (_, from) = drain.date("from")?;
    let (_, until) = drain.date("until")?;
    drain.finish_closed()?;
    require(
        until >= from && until.saturating_sub(from) <= 2_592_000_000,
        "migration drain window",
    )?;
    let mut namespaces = BTreeSet::new();
    for n in o.array("namespaces")? {
        let mut n = Obj::new(n, "migration namespace")?;
        let ns = n.string("namespace")?;
        require(
            crate::v05::terms::valid_namespace(&ns) && namespaces.insert(ns),
            "migration namespace",
        )?;
        let source = n.uint("source")?;
        let copied = n.uint("copied")?;
        let omitted = n.uint("omitted")?;
        require(
            copied.checked_add(omitted) == Some(source),
            "migration counts",
        )?;
        n.digest("view")?;
        n.finish_closed()?;
    }
    let omitted = o.array("omitted")?;
    require(omitted.len() <= 4096, "migration omitted bound")?;
    for x in omitted {
        let mut x = Obj::new(x, "migration omission")?;
        x.digest("ref")?;
        require(!x.string("reason")?.is_empty(), "migration omission reason")?;
        x.finish_closed()?;
    }
    let mut ids = BTreeSet::new();
    for c in o.array("controllers")? {
        let mut c = Obj::new(c, "migration controller")?;
        require(
            ids.insert(c.key_id("id")?),
            "migration duplicate controller",
        )?;
        require(c.value("slot")?.is_boolean(), "migration slot flag")?;
        c.finish_closed()?;
    }
    ids.clear();
    for m in o.array("members")? {
        let mut m = Obj::new(m, "migration member")?;
        require(ids.insert(m.key_id("id")?), "migration duplicate member")?;
        require(
            (1..=200).contains(&m.string("label")?.len()),
            "migration member label",
        )?;
        require(
            ["device", "app", "agent", "server"].contains(&m.string("kind")?.as_str()),
            "migration member kind",
        )?;
        match m.string("outcome")?.as_str() {
            "rejoin" => {}
            "dropped" => {
                require(!m.string("reason")?.is_empty(), "migration drop reason")?;
            }
            _ => return Err(malformed("migration member outcome")),
        }
        m.finish_closed()?;
    }
    o.finish_closed()?;

    s.migration = Some(value.clone());
    Ok(())
}
