//! Exact-byte Swift keyring predecessor verification (§16.3).
//! No storage, clocks or platform APIs. Unknown historical fields are ignored.
use super::envelope::SigItem;
use crate::v05::descriptor::{Controller, Role};
use crate::v05::encoding::{decode_base64, digest, strict_parse};
use crate::v05::signature::{verify_raw, webauthn_check, CheckMode};
use crate::v05::{bad_signature, malformed, require, Failure, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
/// Folded predecessor authority at one sequence.
pub struct Snapshot {
    /// Historical `controllers`.
    pub controllers: BTreeMap<String, Controller>,
    /// Historical `threshold`.
    pub threshold: u64,
    /// Historical `recover_threshold`.
    pub recover_threshold: u64,
    /// Historical `root`.
    pub root: String,
    /// Historical `recovery`.
    pub recovery: String,
    /// Historical `stewards`.
    pub stewards: BTreeSet<String>,
    /// Historical `steward_threshold`.
    pub steward_threshold: u64,
    /// Historical `adopted`.
    pub adopted: bool,
    /// Historical `layout`.
    pub layout: u64,
    /// Historical `raw_keyring`.
    pub raw_keyring: Value,
    /// Current member namespaces, for the control-only share rule.
    pub members: BTreeMap<String, Vec<String>>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
/// Exact signed historical record.
pub struct Record {
    /// Historical `body`.
    pub body: Vec<u8>,
    /// Historical `value`.
    pub value: Value,
    /// Historical `digest`.
    pub digest: String,
    /// Historical `issued_ms`.
    pub issued_ms: i64,
    /// Historical `signatures`.
    pub signatures: Vec<SigItem>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
/// Verified historical records and their folded states.
pub struct History {
    /// Historical `account`.
    pub account: String,
    /// Historical `entries`.
    pub entries: Vec<Record>,
    /// State after each entry. Entries after a freezing layout remain verifiable until
    /// the caller establishes a verified succession (§15.1).
    pub states: Vec<Snapshot>,
}
fn text<'a>(v: &'a Value, f: &str) -> Result<&'a str> {
    v[f].as_str().ok_or_else(|| malformed(format!("Swift {f}")))
}
fn num(v: &Value, f: &str) -> Result<u64> {
    v[f].as_u64()
        .filter(|n| *n < 1 << 53)
        .ok_or_else(|| malformed(format!("Swift {f}")))
}
/// A `threshold` (§16.3), read as the Swift source reads its `Int?`: absent or `null` is nil,
/// which `AuthorityState` turns into 0; a string, boolean, array, object or integer beyond 64 bits
/// is a `DecodingError` there, so the history can't be read (`malformed` here). Foundation's
/// decoder also takes `2.0` or `1e1` as an integer, but shipped Swift writers always write plain
/// integers, so any other number form is `malformed` here too. A negative integer decodes, and
/// with the quorum rule's `threshold > 0` guard it behaves as 0.
fn steward_threshold(v: &Value) -> Result<u64> {
    match v.get("threshold") {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(|i| u64::try_from(i).unwrap_or(0))
            .ok_or_else(|| malformed("Swift threshold")),
        Some(_) => Err(malformed("Swift threshold")),
    }
}
fn point(v: &Value, f: &str) -> Result<Vec<u8>> {
    let p = decode_base64(text(v, f)?, 65)?;
    require(crate::v05::descriptor::valid_point(&p), "Swift point")?;
    Ok(p)
}
fn identity(v: &Value, roles: Value) -> Result<Controller> {
    point(v, "agreement")?;
    Controller::parse(
        json!({"key":{"form":"raw","signing":text(v,"signing")?},"label":"Predecessor identity","roles":roles}),
        "Swift identity",
    )
}
fn controller(v: &Value) -> Result<Controller> {
    let key = match text(v, "kind")? {
        "p256" => json!({"form":"raw","signing":text(v,"key")?}),
        "webauthn" => {
            json!({"form":"webauthn","signing":text(v,"key")?,"rp":text(v,"rpID")?,"credential":text(v,"credential")?})
        }
        k => return Err(Failure::NewerFormat(format!("Swift controller kind {k}"))),
    };
    let mut raw = json!({"key":key,"label":v["label"].as_str().unwrap_or("Predecessor controller"),"roles":v["roles"]});
    if let Some(value) = v.get("verification") {
        raw["verification"] = value.clone();
    }
    let c = Controller::parse(raw, "Swift controller")?;
    c.unknown().check()?;
    Ok(c)
}
fn item(v: &Value, signer: String) -> Result<SigItem> {
    let assertion = match v.get("assertion") {
        None => None,
        Some(a) => Some((
            decode_base64(text(a, "authenticatorData")?, 8192)?,
            decode_base64(text(a, "clientData")?, 8192)?,
        )),
    };
    Ok(SigItem {
        signer,
        signature: decode_base64(text(v, "signature")?, 80)?,
        assertion,
    })
}
/// Verify a historical signature with the general origin rule.
pub fn check(c: &Controller, body: &[u8], item: &SigItem, uv: bool) -> Result<()> {
    match item.assertion_bytes() {
        None if c.key().webauthn().is_none() => {
            verify_raw(c.key().signing(), body, &item.signature)
                .map_err(|e| bad_signature(e.to_string()))
        }
        Some(a) if c.key().webauthn().is_some() => webauthn_check(
            c.key(),
            body,
            &item.signature,
            a,
            CheckMode::SwiftPredecessor {
                uv_required: uv || c.verification(),
            },
        )
        .map(|_| ())
        .map_err(|e| bad_signature(e.to_string())),
        _ => Err(bad_signature("Swift assertion form")),
    }
}
fn slot_shape(s: &Value, combined: bool) -> Result<()> {
    match text(s, "kind")? {
        "sealed" => {
            require(
                s.get("recipient").is_some() && s.get("sealed").is_some(),
                "Swift incomplete sealed slot",
            )?;
        }
        "prf" => {
            require(
                !decode_base64(text(s, "credential")?, 1_048_576)?.is_empty()
                    && decode_base64(text(s, "salt")?, 32)?.len() == 32,
                "Swift incomplete PRF slot",
            )?;
            if !combined {
                require(s.get("box").is_some(), "Swift PRF box")?;
            }
        }
        "combined" if !combined => {
            let parts = s["parts"]
                .as_array()
                .ok_or_else(|| malformed("Swift combined parts"))?;
            require(
                parts.len() >= 2 && s.get("box").is_some(),
                "Swift combined slot",
            )?;
            for part in parts {
                slot_shape(part, true)?;
            }
        }
        k => return Err(Failure::NewerFormat(format!("Swift slot kind {k}"))),
    }
    Ok(())
}
fn slots(v: &Value, _controllers: &BTreeMap<String, Controller>) -> Result<()> {
    for s in v["slots"]
        .as_array()
        .ok_or_else(|| malformed("Swift slots"))?
    {
        slot_shape(s, false)?;
    }
    Ok(())
}

fn new_keyring(v: &Value, old: &Snapshot) -> Result<Snapshot> {
    let mut n = old.clone();
    n.controllers.clear();
    for x in v["controllers"]
        .as_array()
        .ok_or_else(|| malformed("Swift controllers"))?
    {
        let c = controller(x)?;
        require(
            n.controllers.insert(c.id(), c).is_none(),
            "Swift duplicate controller",
        )?;
    }
    let controls = n
        .controllers
        .values()
        .filter(|c| c.has(&Role::Control))
        .count() as u64;
    let recovers = n
        .controllers
        .values()
        .filter(|c| c.has(&Role::Recover))
        .count() as u64;
    n.threshold = num(v, "threshold")?;
    n.recover_threshold = v
        .get("recoverThreshold")
        .map(|_| num(v, "recoverThreshold"))
        .transpose()?
        .unwrap_or(1);
    require(
        n.threshold >= 1 && n.threshold <= controls,
        "Swift control threshold",
    )?;
    if v.get("recoverThreshold").is_some() {
        require(
            n.recover_threshold >= 2
                && n.recover_threshold <= recovers
                && n.threshold >= n.recover_threshold,
            "Swift recovery threshold",
        )?;
    }
    point(&v["vault"], "signing")?;
    point(&v["vault"], "agreement")?;
    slots(v, &n.controllers)?;
    n.adopted = true;
    n.raw_keyring = json!({"controllers":v["controllers"],"threshold":v["threshold"],"recoverThreshold":n.recover_threshold,"vault":v["vault"],"slots":v["slots"]});
    Ok(n)
}
fn multiset_subset(a: &[Value], b: &[Value]) -> bool {
    let mut rest = b.to_vec();
    for x in a {
        let Some(i) = rest.iter().position(|y| y == x) else {
            return false;
        };
        rest.remove(i);
    }
    true
}
/// Replay a predecessor in any arrival order. Duplicate body envelopes are idempotent;
/// differing bodies at a sequence are rejected as a fork, never selected by arrival.
pub fn verify(entries: &[Vec<u8>]) -> Result<History> {
    let mut parsed: BTreeMap<u64, BTreeMap<String, Record>> = BTreeMap::new();
    for bytes in entries {
        require(bytes.len() <= 2_097_152, "Swift envelope bound")?;
        let outer = strict_parse(bytes)?;
        let body = decode_base64(text(&outer, "body")?, 1_048_576)?;
        let value = strict_parse(&body)?;
        let seq = num(&value, "seq")?;
        let issued = text(&value, "issued")?;
        require(
            issued.len() == 20 && issued.ends_with('Z'),
            "Swift date format",
        )?;
        let issued_ms =
            crate::v05::encoding::parse_date(issued).ok_or_else(|| malformed("Swift date"))?;
        let signer = if value["by"] == "controller" {
            text(&value, "signer")?.to_string()
        } else {
            String::new()
        };
        let mut signatures = vec![item(&outer, signer)?];
        if let Some(cos) = outer.get("cosignatures") {
            for c in cos
                .as_array()
                .ok_or_else(|| malformed("Swift cosignatures"))?
            {
                signatures.push(item(c, text(c, "signer")?.into())?);
            }
        }
        let record = Record {
            digest: digest(&body),
            body,
            value,
            issued_ms,
            signatures,
        };
        parsed
            .entry(seq)
            .or_default()
            .entry(record.digest.clone())
            .or_insert(record);
    }
    let mut out = History {
        account: String::new(),
        entries: Vec::new(),
        states: Vec::new(),
    };
    for (seq, candidates) in parsed {
        require(seq == out.entries.len() as u64 + 1, "Swift sequence gap")?;
        let mut valid = Vec::new();
        let mut first = None;
        for e in candidates.into_values() {
            match append(&out, e) {
                Ok(next) => valid.push(next),
                Err(e) if first.is_none() => first = Some(e),
                Err(_) => {}
            }
        }
        if valid.len() > 1 {
            return Err(Failure::Refused(crate::v05::Reason::Fork));
        }
        let (e, next) = valid
            .pop()
            .ok_or_else(|| first.unwrap_or_else(|| malformed("Swift missing entry")))?;
        if seq == 1 {
            out.account = e.digest[..32].into();
        }
        out.states.push(next);
        out.entries.push(e);
    }
    require(!out.entries.is_empty(), "Swift empty predecessor")?;
    Ok(out)
}
/// The rule for a `layout` entry in an adopted keyring library (§16.3): every signer holds
/// `control`, and there are at least `threshold` of them. (UV is demanded of each signature
/// separately.) The one definition: [`append`] applies it to a verified record and the write side
/// applies it before it asks a host to sign the freezing entry F.
pub(crate) fn layout_signers_meet_rule(s: &Snapshot, ids: &BTreeSet<String>) -> bool {
    let controls = |id: &String| s.controllers.get(id).is_some_and(|c| c.has(&Role::Control));
    ids.iter().filter(|id| controls(id)).count() as u64 >= s.threshold
        && ids.iter().all(controls)
}

fn append(out: &History, mut e: Record) -> Result<(Record, Snapshot)> {
    let seq = out.entries.len() as u64 + 1;
    let mut current = out.states.last().cloned();
    let v = &e.value;
    let kind = text(v, "kind")?;
    if seq == 1 {
        require(
            kind == "genesis" && v["by"] == "root" && v.get("previous").is_none(),
            "Swift genesis",
        )?;
        let root = identity(&v["root"], json!(["approve", "control"]))?;
        let recovery = identity(&v["recovery"], json!(["recover"]))?;
        let mut controllers = BTreeMap::new();
        let rid = root.id();
        let kid = recovery.id();
        controllers.insert(rid.clone(), root);
        controllers.insert(kid.clone(), recovery);
        let mut stewards = BTreeSet::new();
        for s in v
            .get("stewards")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let c = identity(s, json!(["recover"]))?;
            stewards.insert(c.id());
            controllers.insert(c.id(), c);
        }
        current = Some(Snapshot {
            controllers,
            threshold: 1,
            recover_threshold: 1,
            root: rid,
            recovery: kid,
            stewards,
            steward_threshold: steward_threshold(v)?,
            adopted: false,
            layout: v["layout"].as_u64().unwrap_or(1),
            raw_keyring: Value::Null,
            members: BTreeMap::new(),
        });
        require(
            current
                .as_ref()
                .is_some_and(|s| (1..=2).contains(&s.layout)),
            "Swift genesis layout",
        )?;
    } else {
        require(
            v["previous"].as_str() == out.entries.last().map(|x| x.digest.as_str()),
            "Swift previous",
        )?;
    }
    // `threshold` is one optional field of every entry in Swift, whatever the kind.
    steward_threshold(v)?;
    let s = current
        .as_ref()
        .ok_or_else(|| malformed("Swift missing genesis"))?;
    let by = text(v, "by")?;
    let mut uv = false;
    if !s.adopted {
        e.signatures[0].signer = match by {
            "root" => s.root.clone(),
            "recovery" if kind == "handover" => s.recovery.clone(),
            "quorum" if kind == "handover" => s
                .stewards
                .iter()
                .find(|id| {
                    s.controllers
                        .get(*id)
                        .is_some_and(|c| check(c, &e.body, &e.signatures[0], false).is_ok())
                })
                .cloned()
                .ok_or_else(|| bad_signature("Swift steward primary"))?,
            x => return Err(Failure::NewerFormat(format!("Swift by {x}"))),
        };
        if by != "quorum" {
            require(
                e.signatures.len() == 1,
                "Swift root rule has no cosignatures",
            )?;
        }
    } else {
        require(by == "controller", "Swift adopted by")?;
        uv = matches!(kind, "keyring" | "layout");
    }
    let mut ids = BTreeSet::new();
    for i in &e.signatures {
        require(ids.insert(i.signer.clone()), "Swift duplicate signer")?;
        let c = s
            .controllers
            .get(&i.signer)
            .ok_or_else(|| bad_signature("Swift foreign signer"))?;
        check(c, &e.body, i, uv)?;
    }
    let control = ids
        .iter()
        .filter(|id| s.controllers[*id].has(&Role::Control))
        .count() as u64
        >= s.threshold;
    if s.adopted {
        let allowed = match kind {
            "grant" | "revoke" => {
                ids.len() == 1 && ids.iter().all(|id| s.controllers[id].has(&Role::Approve))
            }
            "shareKey" => {
                ids.len() == 1
                    && ids.iter().all(|id| {
                        s.controllers[id].has(&Role::Approve)
                            || (s.controllers[id].has(&Role::Control)
                                && (v["memberID"].as_str()
                                    == s.raw_keyring["vault"]["signing"]
                                        .as_str()
                                        .and_then(|b| decode_base64(b, 65).ok())
                                        .map(|p| crate::v05::ids::key_id(&p))
                                        .as_deref()
                                    || s.members
                                        .get(v["memberID"].as_str().unwrap_or_default())
                                        .is_some_and(|ns| ns.iter().any(|n| v["namespace"] == *n))))
                    })
            }
            "layout" => layout_signers_meet_rule(s, &ids),
            "keyring" => {
                let next = new_keyring(v, s)?;
                let recovery = ids.len() as u64 >= s.recover_threshold
                    && ids.iter().all(|id| s.controllers[id].has(&Role::Recover));
                let only_adds = s
                    .controllers
                    .iter()
                    .all(|(id, c)| next.controllers.get(id) == Some(c))
                    && next.threshold == s.threshold
                    && next.recover_threshold == s.recover_threshold
                    && next.raw_keyring["vault"] == s.raw_keyring["vault"]
                    && multiset_subset(
                        s.raw_keyring["slots"].as_array().unwrap_or(&Vec::new()),
                        next.raw_keyring["slots"].as_array().unwrap_or(&Vec::new()),
                    )
                    && (s.recover_threshold >= s.threshold
                        || next
                            .controllers
                            .iter()
                            .filter(|(id, _)| !s.controllers.contains_key(*id))
                            .all(|(_, c)| c.roles() == [Role::Approve]));
                let consent = next.recover_threshold >= s.recover_threshold
                    || ids
                        .iter()
                        .filter(|id| s.controllers[*id].has(&Role::Recover))
                        .count() as u64
                        >= s.recover_threshold;
                (control && consent) || (recovery && only_adds)
            }
            other => return Err(Failure::NewerFormat(format!("Swift kind {other}"))),
        };
        if !allowed {
            return Err(bad_signature("Swift authority rule"));
        }
    } else if by == "quorum"
        && (s.steward_threshold == 0
            || !ids.is_subset(&s.stewards)
            || (ids.len() as u64) < s.steward_threshold)
    {
        return Err(bad_signature("Swift steward quorum"));
    }
    let mut next = s.clone();
    match kind {
        "genesis" if seq == 1 => {}
        "keyring" => {
            next = new_keyring(v, s)?;
        }
        "layout" => {
            let layout = num(v, "layout")?;
            require(layout > s.layout, "Swift layout must increase")?;
            next.layout = layout;
        }
        "handover" if !s.adopted => {
            let c = identity(&v["root"], json!(["approve", "control"]))?;
            next.controllers.remove(&s.root);
            next.root = c.id();
            next.controllers.insert(c.id(), c);
        }
        "rotateRecovery" if !s.adopted => {
            let c = identity(&v["recovery"], json!(["recover"]))?;
            next.controllers.remove(&s.recovery);
            next.recovery = c.id();
            next.controllers.insert(c.id(), c);
        }
        "stewards" if !s.adopted => {
            for id in &s.stewards {
                if id != &s.root && id != &s.recovery {
                    next.controllers.remove(id);
                }
            }
            next.stewards.clear();
            for v in v
                .get("stewards")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let c = identity(v, json!(["recover"]))?;
                next.stewards.insert(c.id());
                next.controllers.insert(c.id(), c);
            }
            next.steward_threshold = steward_threshold(v)?;
        }
        "grant" => {
            if let Some(role) = v.get("role").and_then(Value::as_str) {
                if !["device", "app", "web", "agent", "service"].contains(&role) {
                    return Err(Failure::NewerFormat(format!("Swift role {role}")));
                }
            }
            if let Some(custody) = v.get("custody").and_then(Value::as_str) {
                if !["hardware", "platform", "software", "custodial"].contains(&custody) {
                    return Err(Failure::NewerFormat(format!("Swift custody {custody}")));
                }
            }
            if let Some(member) = v.get("member") {
                let signing = point(member, "signing")?;
                point(member, "agreement")?;
                let mut ns = Vec::new();
                for n in v
                    .get("namespaces")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    ns.push(
                        n.as_str()
                            .ok_or_else(|| malformed("Swift namespace"))?
                            .to_string(),
                    );
                }
                next.members.insert(crate::v05::ids::key_id(&signing), ns);
            }
        }
        "revoke" => {
            if let Some(id) = v.get("memberID").and_then(Value::as_str) {
                next.members.remove(id);
            }
        }
        "shareKey" => {}
        other => return Err(Failure::NewerFormat(format!("Swift kind {other}"))),
    }
    Ok((e, next))
}
