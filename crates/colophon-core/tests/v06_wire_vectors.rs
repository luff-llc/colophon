//! Wire conformance vectors for 0.6 sessions (`conformance/0.6-sessions/wire/`).
//!
//! The test (1) rebuilds `vectors.json` from fixed keys and inputs and compares it with the
//! checked-in file, and (2) checks the file from its JSON alone, as another runtime would:
//! every positive frame opens to its plaintext with the stated `writer`, every negative frame
//! is dropped with the stated reason, and every intermediate value (frame key, nonce, AAD,
//! signed body) matches. `COLOPHON_REGEN_VECTORS=1` rewrites the file.
#![allow(clippy::unwrap_used)]
mod v06_codec_support;

use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::hex;
use colophon_core::v05::terms::Access;
use colophon_core::v06::session::codec::{
    frame_key, frame_key_info, nonce, Attach, CellId, EpochKeys, EpochTable, Receiver, Sender,
};
use colophon_core::v06::session::keys::{Delegation, SessionAccount, SessionKey};
use colophon_core::v06::session::wire::{encode_body, WireFrame, MAX_FRAME_BYTES};
use colophon_core::v06::session::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use v06_codec_support::*;

const SESSION_SCALAR: [u8; 32] = [0x11; 32];
const READER_SESSION_SCALAR: [u8; 32] = [0x14; 32];
const OTHER_EPOCH_KEY: [u8; 32] = [0x24; 32];

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.6-sessions/wire/vectors.json")
}
fn s(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

fn bodies(w: &World) -> Vec<(&'static str, Body, Option<String>, bool)> {
    let c = claim(3, &w.a);
    let passed = Claim::passed(4, &w.b.id, &w.a.id);
    let anchor = bytes(r#"{"at":98765432,"episode":"ep-1","playing":true,"positionMs":1234567,"ratePermille":1250,"show":"show-1"}"#);
    let b = Some(w.b.id.clone());
    vec![
        ("hello", Body::Hello { fresh: id("fresh-1"), echo: vec![id("fresh-0")], seen: Some(Seen { claim: c.clone(), seq: Some(7) }), heard: None, lapsed: false }, None, false),
        ("hello-unsynced", Body::Hello { fresh: id("fresh-2"), echo: vec![], seen: Some(Seen { claim: passed.clone(), seq: None }), heard: None, lapsed: true }, b.clone(), false),
        ("state", Body::State { claim: c.clone(), seq: 7, snapshot: anchor.clone() }, None, true),
        ("beat", Body::Beat { claim: c.clone(), seq: 7 }, None, true),
        ("msg", Body::Msg { claim: c.clone(), seq: 8, origin: w.b.id.clone(), id: id("submit-1"), payload: anchor.clone() }, None, false),
        ("submit", Body::Submit { id: id("submit-1"), payload: Bytes(vec![0, 1, 2, 0xfe, 0xff]) }, None, false),
        ("refuse", Body::Refuse { id: id("submit-1"), reason: "busy".into() }, b.clone(), false),
        ("presence", Body::Presence { payload: bytes(r#"{"label":"Kitchen iPad","playing":false}"#) }, None, false),
        ("ask", Body::Ask { claim: c.clone() }, None, false),
        ("pass", Body::Pass { claim: c.clone(), next: passed.clone(), seq: 9, snapshot: anchor }, None, false),
        ("decline", Body::Decline { claim: c.clone() }, b.clone(), false),
        ("take", Body::Take { claim: claim(5, &w.a) }, None, false),
        ("ping", Body::Ping { t: 1_000 }, b.clone(), false),
        ("pong", Body::Pong { t: 2_040, echo: 1_000, hold: 3 }, b.clone(), false),
        ("yielded", Body::Yielded { claim: c.clone(), seq: 9, snapshot: Bytes::default() }, b.clone(), false),
        ("ack", Body::Ack { yielded: None, passed: Some(passed) }, b, false),
        ("bye-release", Body::Bye { claim: Some(c), leaving: false }, None, false),
        ("bye-leave", Body::Bye { claim: None, leaving: true }, None, false),
    ]
}

fn view(w: &World) -> SessionAccount {
    w.view()
}

/// Build the vector file.
fn build() -> Value {
    let w = world();
    let v = view(&w);
    let ep = epochs();
    let key = SessionKey::generate(&mut SESSION_SCALAR.clone()).unwrap();
    let key_id = key.id().to_owned();
    let point = key.point().to_vec();
    let mut tx = Sender::new(cell(), &w.a.id, key);
    let dbody = tx.delegation_body(0, t0(), t0() + 86_400_000).unwrap();
    let dsig = host_sign(&w.a, &dbody);
    tx.install(&dbody, &dsig, &v, t0()).unwrap();
    let envelope = tx.delegation().unwrap().envelope.clone();
    let fk = frame_key(&EPOCH_KEY, &cell(), &key_id);

    let mut frames = Vec::new();
    let mut sealed = Vec::new();
    for (name, body, to, retain) in bodies(&w) {
        let plaintext = encode_body(&body).unwrap();
        let attach = if name == "ping" { Attach::Never } else if name.starts_with("hello") { Attach::Always } else { Attach::IfFits };
        let bytes = tx.seal_plaintext(to.as_deref(), retain, &plaintext, attach, &ep, t0()).unwrap();
        let wf = WireFrame::parse(&bytes).unwrap();
        frames.push(json!({
            "name": name,
            "plaintext": s(&plaintext),
            "to": to,
            "retain": retain,
            "n": wf.outer.n,
            "nonce": hex(&nonce(wf.outer.n)),
            "aad": s(&wf.outer.aad()),
            "ciphertext": STANDARD.encode(&wf.ciphertext),
            "signedBody": s(&wf.signed_body()),
            "signature": STANDARD.encode(wf.signature),
            "frame": s(&bytes),
            "writer": true,
        }));
        sealed.push(bytes);
    }
    // A read-only member's frame opens, with writer = false: the machine then ignores it for
    // anything that needs a writer.
    let rkey = SessionKey::generate(&mut READER_SESSION_SCALAR.clone()).unwrap();
    let mut rtx = Sender::new(cell(), &w.r.id, rkey);
    let rbody = rtx.delegation_body(0, t0(), t0() + 3_600_000).unwrap();
    rtx.install(&rbody, &host_sign(&w.r, &rbody), &v, t0()).unwrap();
    let rplain = encode_body(&Body::Take { claim: claim(6, &w.r) }).unwrap();
    let rbytes = rtx.seal_plaintext(None, false, &rplain, Attach::Always, &ep, t0()).unwrap();
    let rwf = WireFrame::parse(&rbytes).unwrap();
    frames.push(json!({
        "name": "take-from-reader",
        "plaintext": s(&rplain),
        "to": null,
        "retain": false,
        "n": 1,
        "nonce": hex(&nonce(1)),
        "aad": s(&rwf.outer.aad()),
        "ciphertext": STANDARD.encode(&rwf.ciphertext),
        "signedBody": s(&rwf.signed_body()),
        "signature": STANDARD.encode(rwf.signature),
        "frame": s(&rbytes),
        "writer": false,
    }));

    // Negative vectors. `accept` frames are opened first by a fresh receiver.
    let first = s(&sealed[0]);
    let beat = sealed[3].clone();
    let mut neg = Vec::new();
    let mut push = |name: &str, accept: Vec<String>, frame: Vec<u8>, drop: &str, extra: Value| {
        let mut o = json!({"name": name, "accept": accept, "frame": s(&frame), "drop": drop});
        if let Value::Object(e) = extra {
            for (k, v) in e {
                o[k] = v;
            }
        }
        neg.push(o);
    };
    push("replay", vec![first.clone()], sealed[0].clone(), "replay", json!({}));
    push("ciphertext-bit", vec![], edit(&beat, |m| flip_b64(m.get_mut("ciphertext").unwrap(), 3)), "signature", json!({}));
    push("signature-bit", vec![], edit(&beat, |m| flip_b64(m.get_mut("signature").unwrap(), 9)), "signature", json!({}));
    push("n-changed", vec![], edit(&beat, |m| { m.insert("n".into(), json!(99)); }), "signature", json!({}));
    push("to-added", vec![], edit(&beat, |m| { m.insert("to".into(), json!(w.c.id)); }), "signature", json!({}));
    push("retain-removed", vec![], edit(&beat, |m| { m.remove("retain"); }), "signature", json!({}));
    push("delegation-body-bit", vec![], edit(&beat, |m| flip_b64(m.get_mut("delegation").unwrap().get_mut("body").unwrap(), 20)), "delegation", json!({}));
    push("delegation-stripped", vec![], edit(&beat, |m| { m.remove("delegation"); }), "noKey", json!({}));
    push("unknown-field", vec![], edit(&beat, |m| { m.insert("hint".into(), json!("x")); }), "malformed", json!({}));
    push("not-canonical", vec![], s(&beat).replacen(",", ", ", 1).into_bytes(), "malformed", json!({}));
    push("retain-false", vec![], edit(&beat, |m| { m.insert("retain".into(), json!(false)); }), "malformed", json!({}));
    let mut big = vec![b' '; MAX_FRAME_BYTES + 1];
    big[0] = b'{';
    big[MAX_FRAME_BYTES] = b'}';
    push("oversize", vec![], big, "oversize", json!({}));
    push("other-cell", vec![], edit(&beat, |m| { m.insert("cell".into(), json!("up-next")); }), "cell", json!({}));
    push("other-account", vec![], edit(&beat, |m| { m.insert("account".into(), json!(OTHER_ACCOUNT)); }), "account", json!({}));
    push("clock-past-window", vec![first.clone()], beat.clone(), "keyWindow", json!({"clockMs": t0() + 86_400_000 + 60_001}));
    push("clock-before-window", vec![first.clone()], beat.clone(), "keyWindow", json!({"clockMs": t0() - 60_001}));
    push("payload-over-max", vec![], sealed[7].clone(), "range", json!({"maxPayload": 8}));
    // Correctly signed frames with bad plaintexts or keys.
    let mut bad = |plain: &[u8], table: &EpochTable| tx.seal_plaintext(None, false, plain, Attach::Always, table, t0()).unwrap();
    let wrong_key = EpochTable::new().with(NS, 1, OTHER_EPOCH_KEY);
    let epoch2 = EpochTable::new().with(NS, 2, OTHER_EPOCH_KEY);
    let p_unknown_field = bad(br#"{"kind":"ping","t":1,"x":true}"#, &ep);
    let p_unknown_kind = bad(br#"{"kind":"wave"}"#, &ep);
    let p_big_int = bad(br#"{"kind":"ping","t":9007199254740992}"#, &ep);
    let p_null_claim = bad(br#"{"claim":null,"kind":"bye","leaving":true}"#, &ep);
    let p_heard = bad(&encode_body(&Body::Hello { fresh: id("x"), echo: vec![], seen: None, heard: Some(Heard::Live), lapsed: false }).unwrap(), &ep);
    let p_wrong_key = bad(br#"{"kind":"ping","t":1}"#, &wrong_key);
    let p_epoch2 = bad(br#"{"kind":"ping","t":1}"#, &epoch2);
    // Too old: the highest n accepted, then one 129 below it.
    let mut old = Vec::new();
    for i in 0..200u64 {
        let b = tx.seal_plaintext(None, false, format!(r#"{{"kind":"ping","t":{i}}}"#).as_bytes(), Attach::IfFits, &ep, t0()).unwrap();
        old.push(b);
    }
    let n_of = |b: &[u8]| json(b)["n"].as_u64().unwrap();
    let hi = old.last().unwrap().clone();
    let top = n_of(&hi);
    let lo = old.iter().find(|b| n_of(b) == top - 129).unwrap().clone();
    let edge = old.iter().find(|b| n_of(b) == top - 128).unwrap().clone();
    push("plaintext-unknown-field", vec![], p_unknown_field, "plaintext", json!({}));
    push("plaintext-unknown-kind", vec![], p_unknown_kind, "unknownKind", json!({}));
    push("plaintext-integer-over-2^53-1", vec![], p_big_int, "range", json!({}));
    push("plaintext-bye-claim-null", vec![], p_null_claim, "plaintext", json!({}));
    push("plaintext-hello-heard", vec![], p_heard, "plaintext", json!({}));
    push("wrong-epoch-key", vec![], p_wrong_key, "open", json!({}));
    push("missing-epoch", vec![], p_epoch2, "noEpoch", json!({}));
    push("more-than-128-below", vec![s(&hi)], lo, "tooOld", json!({}));
    // Exactly 128 below is still inside the window: a positive case, with `drop` null.
    push("exactly-128-below", vec![s(&hi)], edge, "", json!({}));
    if let Some(last) = neg.last_mut() {
        last["drop"] = Value::Null;
    }

    json!({
        "format": "colophon/session-wire-vectors/6",
        "spec": "colophon-0.6-sessions revision 14, §S2 and §S3",
        "account": ACCOUNT,
        "namespace": NS,
        "cell": CELL,
        "maxPayload": 8192,
        "clockMs": t0(),
        "epochs": [{"epoch": 1, "key": hex(&EPOCH_KEY)}],
        "members": [
            {"name": "a", "privateKey": hex(&[1; 32]), "signing": STANDARD.encode(&w.a.point), "id": w.a.id, "session": 0, "access": "write"},
            {"name": "b", "privateKey": hex(&[2; 32]), "signing": STANDARD.encode(&w.b.point), "id": w.b.id, "session": 0, "access": "write"},
            {"name": "c", "privateKey": hex(&[3; 32]), "signing": STANDARD.encode(&w.c.point), "id": w.c.id, "session": 0, "access": "write"},
            {"name": "r", "privateKey": hex(&[4; 32]), "signing": STANDARD.encode(&w.r.point), "id": w.r.id, "session": 0, "access": "read"},
        ],
        "receiver": w.b.id,
        "sessionKey": {
            "member": w.a.id,
            "privateKey": hex(&SESSION_SCALAR),
            "signing": STANDARD.encode(&point),
            "id": key_id,
            "info": s(&frame_key_info(&cell(), &key_id)),
            "frameKey": hex(&*fk),
        },
        "delegation": {
            "body": s(&dbody),
            "signature": STANDARD.encode(&dsig),
            "envelope": s(&envelope),
        },
        "frames": frames,
        "negative": neg,
        "views": views_json(&w),
        "scenarios": scenarios(&w),
    })
}

/// Named account views: members with session numbers and access (scenarios switch them).
fn views_json(w: &World) -> Value {
    let m = |x: &Member, session: u64, access: &str| json!({"id": x.id, "signing": STANDARD.encode(&x.point), "session": session, "access": access});
    json!({
        "default": [m(&w.a, 0, "write"), m(&w.b, 0, "write"), m(&w.c, 0, "write"), m(&w.r, 0, "read")],
        "aSession1": [m(&w.a, 1, "write"), m(&w.b, 0, "write"), m(&w.c, 0, "write"), m(&w.r, 0, "read")],
        "aRead": [m(&w.a, 0, "read"), m(&w.b, 0, "write"), m(&w.c, 0, "write"), m(&w.r, 0, "read")],
        "withoutA": [m(&w.b, 0, "write"), m(&w.c, 0, "write"), m(&w.r, 0, "read")],
    })
}
fn view_of(v: &Value, ns: &str, account: &str) -> SessionAccount {
    let mut view = SessionAccount::new(account);
    for m in v.as_array().unwrap() {
        let signing = STANDARD.decode(m["signing"].as_str().unwrap()).unwrap();
        let access = if m["access"] == "write" { Access::Write } else { Access::Read };
        view = view.with_member(&signing, m["session"].as_u64().unwrap(), None, &[(ns, access)]);
    }
    view
}

/// One sealed frame: a fresh sender for member `m` whose session key comes from `scalar`.
fn keyed(m: &Member, scalar: u8, session: u64, nb: i64, ex: i64) -> Sender {
    let w = world();
    let mut view = w.view();
    if session > 0 {
        view = view.with_member(&m.point, session, None, &[(NS, Access::Write)]);
    }
    let key = SessionKey::generate(&mut [scalar; 32]).unwrap();
    let mut tx = Sender::new(cell(), &m.id, key);
    let body = tx.delegation_body(session, nb, ex).unwrap();
    tx.install(&body, &host_sign(m, &body), &view, t0()).unwrap();
    tx
}
fn ping(tx: &mut Sender, from: &Member, t: u64) -> String {
    let f = Frame { from: from.id.clone(), to: None, retain: false, body: Body::Ping { t } };
    s(&tx.seal(&f, &epochs(), t0()).unwrap())
}
fn open(frame: &str, expect: Value) -> Value {
    json!({"open": frame, "expect": expect})
}
fn dropped(code: &str) -> Value {
    json!({"drop": code})
}

/// Multi-step receiver scenarios (revision 15): key lifecycle, probes, entitlement changes,
/// renewal and the read-only member's frames.
fn scenarios(w: &World) -> Value {
    let mut out = Vec::new();
    let day = t0() + 86_400_000;

    // Eviction replay: five keys of a; the fifth closes the first; the first key's frames,
    // its hello included, are dropped at its floor; a new frame above the floor reopens it.
    let mut keys: Vec<Sender> = (0..5).map(|i| keyed(&w.a, 0x30 + i, 0, t0(), day)).collect();
    let hello = Body::Hello { fresh: id("a-old"), echo: vec![id("b-fresh")], seen: None, heard: None, lapsed: false };
    let k1: Vec<String> = [hello, Body::Ping { t: 1 }, Body::Ping { t: 2 }]
        .into_iter()
        .map(|body| s(&keys[0].seal(&Frame { from: w.a.id.clone(), to: None, retain: false, body }, &epochs(), t0()).unwrap()))
        .collect();
    let mut steps: Vec<Value> = k1.iter().map(|f| open(f, json!({"drop": null, "closed": null}))).collect();
    for (i, k) in keys.iter_mut().enumerate().skip(1) {
        let closed = if i == 4 { json!(keys_id(0x30)) } else { Value::Null };
        steps.push(open(&ping(k, &w.a, 1), json!({"drop": null, "closed": closed})));
    }
    for f in &k1 {
        steps.push(open(f, dropped("floor")));
    }
    steps.push(open(&ping(&mut keys[0], &w.a, 3), json!({"drop": null, "closed": keys_id(0x31)})));
    out.push(json!({"name": "eviction-replay", "steps": steps}));

    // Probes: a frame without a delegation from an entitled member asks for a hello; the same
    // from a fake member ID or a member without the namespace does not.
    let mut tx = keyed(&w.a, 0x40, 0, t0(), day);
    let stripped = edit(&ping(&mut tx, &w.a, 1).into_bytes(), |m| { m.remove("delegation"); });
    let fake = edit(&stripped, |m| { m.insert("from".into(), json!(member(77).id)); });
    let other_ns = edit(&stripped, |m| { m.insert("from".into(), json!(w.x.id)); });
    let reader = edit(&stripped, |m| { m.insert("from".into(), json!(w.r.id)); });
    out.push(json!({"name": "probe-only-entitled", "steps": [
        open(&s(&stripped), json!({"drop": "noKey", "helloTo": w.a.id})),
        open(&s(&fake), json!({"drop": "noKey", "helloTo": null})),
        open(&s(&other_ns), json!({"drop": "noKey", "helloTo": null})),
        open(&s(&reader), json!({"drop": "noKey", "helloTo": w.r.id})),
    ]}));

    // A reader's frames open, with writer false: the machine ignores every claim in them.
    let mut rtx = keyed(&w.r, 0x41, 0, t0(), day);
    let max = Claim::new(MAX_TERM, 0, &w.r.id);
    let mut rsteps = Vec::new();
    for body in [
        Body::Hello { fresh: id("r"), echo: vec![], seen: Some(Seen { claim: max.clone(), seq: Some(0) }), heard: None, lapsed: false },
        Body::Bye { claim: Some(max.clone()), leaving: false },
        Body::Yielded { claim: max.clone(), seq: 0, snapshot: bytes("x") },
        Body::Take { claim: max.clone() },
    ] {
        let f = rtx.seal(&Frame { from: w.r.id.clone(), to: None, retain: false, body }, &epochs(), t0()).unwrap();
        rsteps.push(open(&s(&f), json!({"drop": null, "writer": false})));
    }
    out.push(json!({"name": "reader-claims", "steps": rsteps}));

    // Entitlement changes: reduced to read, a's frames open with writer false; a new session
    // number retires a's key (even under a delegation signed again for the new number);
    // without a, a's frames fail their delegation.
    let mut tx = keyed(&w.a, 0x42, 0, t0(), day);
    let f1 = ping(&mut tx, &w.a, 1);
    let f2 = ping(&mut tx, &w.a, 2);
    let f3 = ping(&mut tx, &w.a, 3);
    let body = s(&tx.delegation_body(0, t0(), day).unwrap()).replace("\"session\":0", "\"session\":1");
    let d1 = Delegation::assemble(body.as_bytes(), &host_sign(&w.a, body.as_bytes())).unwrap();
    let f4 = s(&edit(&ping(&mut tx, &w.a, 4).into_bytes(), |m| { m.insert("delegation".into(), json(&d1.envelope)); }));
    out.push(json!({"name": "entitlement-change", "steps": [
        open(&f1, json!({"drop": null, "writer": true})),
        {"setView": "aRead", "expect": {"forgottenMembers": [], "closedKeys": []}},
        open(&f2, json!({"drop": null, "writer": false})),
        {"setView": "aSession1", "expect": {"forgottenMembers": [], "closedKeys": [[w.a.id, keys_id(0x42)]]}},
        open(&f3, dropped("retired")),
        open(&f4, dropped("retired")),
        {"setView": "withoutA", "expect": {"forgottenMembers": [w.a.id], "closedKeys": []}},
        open(&f4, dropped("delegation")),
    ]}));

    // Floor exhaustion: 64 keys of c; the 65th is refused; expiry of the first 32 (one hour
    // windows, plus 60 s) frees room for it.
    let hour = t0() + 3_600_000;
    let mut fsteps = Vec::new();
    for i in 0..64u8 {
        let ex = if i < 32 { hour } else { day };
        let mut k = keyed(&w.c, 0x50 + i, 0, t0(), ex);
        fsteps.push(open(&ping(&mut k, &w.c, 1), json!({"drop": null})));
    }
    let mut extra = keyed(&w.c, 0xa0, 0, t0(), day);
    let e1 = ping(&mut extra, &w.c, 1);
    fsteps.push(open(&e1, dropped("keyLimit")));
    fsteps.push(json!({"expire": hour + 60_001, "expect": {"expired": 32}}));
    fsteps.push(json!({"open": e1, "clockMs": hour + 60_001, "expect": {"drop": null}}));
    out.push(json!({"name": "floor-exhaustion", "steps": fsteps}));

    // Renewal: a renewed delegation for the same key keeps its window; an old frame
    // re-wrapped with the renewed delegation is still a replay.
    let mut tx = keyed(&w.a, 0x43, 0, t0(), day);
    let old = ping(&mut tx, &w.a, 1);
    let nb = t0() + 1_000;
    let body = tx.delegation_body(0, nb, nb + 86_400_000).unwrap();
    let w0 = world();
    tx.install(&body, &host_sign(&w.a, &body), &w0.view(), nb).unwrap();
    let renewed = s(&tx.seal(&Frame { from: w.a.id.clone(), to: None, retain: false, body: Body::Ping { t: 2 } }, &epochs(), nb).unwrap());
    let rewrapped = s(&edit(old.as_bytes(), |m| { m.insert("delegation".into(), json(renewed.as_bytes())["delegation"].clone()); }));
    out.push(json!({"name": "delegation-renewal", "steps": [
        open(&old, json!({"drop": null})),
        {"open": renewed, "clockMs": nb, "expect": {"drop": null}},
        {"open": rewrapped, "clockMs": nb, "expect": {"drop": "replay"}},
    ]}));

    // Pass acknowledgement on the wire: `ack {passed}` from the member the pass named.
    let mut btx = keyed(&w.b, 0x44, 0, t0(), day);
    let ack = Body::Ack { yielded: None, passed: Some(Claim::passed(4, &w.b.id, &w.a.id)) };
    let f = btx.seal(&Frame { from: w.b.id.clone(), to: Some(w.a.id.clone()), retain: false, body: ack }, &epochs(), t0()).unwrap();
    out.push(json!({"name": "pass-ack", "receiver": w.a.id, "steps": [open(&s(&f), json!({"drop": null, "writer": true}))]}));
    Value::Array(out)
}

fn keys_id(scalar: u8) -> String {
    SessionKey::generate(&mut [scalar; 32]).unwrap().id().to_owned()
}

/// Check a vector file from its JSON alone.
fn check(v: &Value) {
    let st = |x: &Value| x.as_str().unwrap().to_owned();
    let unhex = |x: &Value| -> Vec<u8> {
        let t = x.as_str().unwrap();
        (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect()
    };
    let account = st(&v["account"]);
    let ns = st(&v["namespace"]);
    let c = CellId::new(&account, &ns, &st(&v["cell"]));
    let mut view = SessionAccount::new(&account);
    for m in v["members"].as_array().unwrap() {
        let signing = STANDARD.decode(st(&m["signing"])).unwrap();
        let access = if m["access"] == "write" { Access::Write } else { Access::Read };
        view = view.with_member(&signing, m["session"].as_u64().unwrap(), None, &[(&ns, access)]);
    }
    let mut table = EpochTable::new();
    for e in v["epochs"].as_array().unwrap() {
        let k: [u8; 32] = unhex(&e["key"]).try_into().unwrap();
        table = table.with(&ns, e["epoch"].as_u64().unwrap(), k);
    }
    let clock = v["clockMs"].as_i64().unwrap();
    let max = v["maxPayload"].as_u64().unwrap();
    let me = st(&v["receiver"]);
    // Intermediate values.
    let sk = &v["sessionKey"];
    let epoch_key: [u8; 32] = unhex(&v["epochs"][0]["key"]).try_into().unwrap();
    assert_eq!(st(&sk["info"]).into_bytes(), frame_key_info(&c, &st(&sk["id"])));
    assert_eq!(hex(&*frame_key(&epoch_key, &c, &st(&sk["id"]))), st(&sk["frameKey"]));
    let mut scalar: [u8; 32] = unhex(&sk["privateKey"]).try_into().unwrap();
    let key = SessionKey::generate(&mut scalar).unwrap();
    assert_eq!(key.id(), st(&sk["id"]));
    assert_eq!(STANDARD.encode(key.point()), st(&sk["signing"]));
    // Positive frames, in order, through one receiver.
    let mut rx = Receiver::new(c.clone(), &me);
    for f in v["frames"].as_array().unwrap() {
        let bytes = st(&f["frame"]).into_bytes();
        let w = WireFrame::parse(&bytes).unwrap();
        assert_eq!(w.outer.aad(), st(&f["aad"]).into_bytes(), "{}", f["name"]);
        assert_eq!(w.signed_body(), st(&f["signedBody"]).into_bytes());
        assert_eq!(hex(&nonce(w.outer.n)), st(&f["nonce"]));
        let o = rx.open(&bytes, &view, clock, &table, max).unwrap_or_else(|d| panic!("{}: {d:?}", f["name"]));
        assert_eq!(encode_body(&o.frame.body).unwrap(), st(&f["plaintext"]).into_bytes());
        assert_eq!(o.writer, f["writer"].as_bool().unwrap(), "{}", f["name"]);
    }
    // Scenarios, each against a fresh receiver (by default the file's `receiver`).
    let views = &v["views"];
    for sc in v["scenarios"].as_array().unwrap() {
        let name = st(&sc["name"]);
        let who = sc.get("receiver").map_or(me.clone(), st);
        let mut rx = Receiver::new(c.clone(), &who);
        let mut view = view_of(&views["default"], &ns, &account);
        for (k, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let ex = &step["expect"];
            let what = format!("{name} step {k}");
            if let Some(vn) = step.get("setView") {
                view = view_of(&views[vn.as_str().unwrap()], &ns, &account);
                let gone = rx.set_account(&view, clock);
                let members: Vec<String> = ex["forgottenMembers"].as_array().unwrap().iter().map(st).collect();
                let keys: Vec<(String, String)> = ex["closedKeys"].as_array().unwrap().iter().map(|p| (st(&p[0]), st(&p[1]))).collect();
                assert_eq!(gone.members, members, "{what}");
                assert_eq!(gone.keys, keys, "{what}");
                continue;
            }
            if let Some(at) = step.get("expire") {
                let n = rx.expire(at.as_i64().unwrap()).len() as u64;
                assert_eq!(n, ex["expired"].as_u64().unwrap(), "{what}");
                continue;
            }
            let at = step.get("clockMs").and_then(Value::as_i64).unwrap_or(clock);
            let before = rx.clone();
            match (rx.open(st(&step["open"]).as_bytes(), &view, at, &table, max), ex["drop"].as_str()) {
                (Ok(o), None) => {
                    if let Some(wr) = ex.get("writer") {
                        assert_eq!(o.writer, wr.as_bool().unwrap(), "{what}");
                    }
                    if let Some(cl) = ex.get("closed") {
                        assert_eq!(o.closed.as_deref(), cl.as_str(), "{what}");
                    }
                }
                (Err(d), Some(code)) => {
                    assert_eq!(d.reason.code(), code, "{what}");
                    assert_eq!(rx, before, "{what}: a drop changed state");
                    if let Some(h) = ex.get("helloTo") {
                        assert_eq!(d.hello_to.as_deref(), h.as_str(), "{what}");
                    }
                }
                (got, want) => panic!("{what}: got {got:?}, want drop {want:?}"),
            }
        }
    }
    // Negative frames, each against a fresh receiver.
    for n in v["negative"].as_array().unwrap() {
        let mut rx = Receiver::new(c.clone(), &me);
        let at = n.get("clockMs").and_then(Value::as_i64).unwrap_or(clock);
        let maxp = n.get("maxPayload").and_then(Value::as_u64).unwrap_or(max);
        for a in n["accept"].as_array().unwrap() {
            rx.open(st(a).as_bytes(), &view, clock, &table, max).unwrap();
        }
        let before = rx.clone();
        let got = rx.open(st(&n["frame"]).as_bytes(), &view, at, &table, maxp);
        match n["drop"].as_str() {
            Some(code) => {
                let d = got.expect_err(&st(&n["name"]));
                assert_eq!(d.reason.code(), code, "{}", n["name"]);
                assert_eq!(rx, before, "{}", n["name"]);
            }
            None => {
                got.unwrap();
            }
        }
    }
}

#[test]
fn wire_vectors() {
    let built = build();
    check(&built);
    let p = path();
    let text = format!("{}\n", serde_json::to_string_pretty(&built).unwrap());
    if std::env::var("COLOPHON_REGEN_VECTORS").is_ok() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &text).unwrap();
    }
    let old = std::fs::read_to_string(&p)
        .unwrap_or_else(|_| panic!("missing {p:?}; run with COLOPHON_REGEN_VECTORS=1"));
    assert_eq!(old, text, "vectors changed; run with COLOPHON_REGEN_VECTORS=1 and review");
    check(&serde_json::from_str(&old).unwrap());
    // EpochKeys is object safe for hosts.
    let _: &dyn EpochKeys = &epochs();
}
