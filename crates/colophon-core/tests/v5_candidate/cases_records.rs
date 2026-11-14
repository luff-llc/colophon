//! Namespace vectors (plan step V1 item 2): epoch seals and shares, `/5` headers with AAD,
//! author chains, `revoke` with `kept` and `heads`, `renew` with shares, proposals and
//! resolutions in each order, and the `/3` records of an in-place upgraded account.
//!
//! **Independent of the engine.** Nothing here calls `colophon_core::v05`. Canonical JSON,
//! signatures, the operation ID, AES-GCM and the epoch seals (RFC 9180 through the 0.4
//! `hpke.rs`, which the spec says is unchanged) are written out from the specification text.
//! Every expected outcome below was decided from the text of §9.5, §11 and §16.1 before the
//! engine was run against it; where a comment says so, the text does not decide and the vector
//! does not exist.
//!
//! Layout of one case: `records/<name>/records/authority/NNNNNNNN.json` (the authority
//! history), `records/<name>/ops/<author>/<namespace>/<clock>-<id>.json` (the held headers),
//! and `records/<name>/case.json` with `holders` (members whose agreement scalar opens the
//! seals addressed to them: public test secrets), and `expected`.
#![allow(clippy::unwrap_used)]
use super::kit::*;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use colophon_core::{crypto::Entropy, hpke::SealedKey};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const NS: &str = "notes";

fn name_seed(label: &str) -> [u8; 32] {
    sha_raw(format!("colophon-0.5-candidate/records/{label}").as_bytes())
        .try_into()
        .unwrap()
}

#[derive(Clone)]
struct Member {
    sign: Key,
    agree: Key,
}
fn member(name: &str) -> Member {
    Member {
        sign: derived(&format!("rec/{name}/signing")),
        agree: derived(&format!("rec/{name}/agreement")),
    }
}

/// How an operation header is damaged after it was encrypted correctly.
#[derive(Clone, Copy, PartialEq)]
enum Tamper {
    None,
    /// `created` of the header changed (an AAD field) and the header re-signed.
    Created,
    /// `level` of the header changed from `write` to `propose`.
    Level,
    /// `previous` of the header changed.
    Previous,
    /// Encrypted under a key that is not the epoch key.
    WrongKey,
    /// The plaintext's clock differs from the header's.
    PlainClock,
    /// The ID is not the content-derived ID (plaintext and header agree on it).
    BadId,
}

#[derive(Clone)]
struct Op<'a> {
    author: &'a Member,
    level: &'a str,
    clock: u64,
    epoch: u64,
    authority: u64,
    created: i64,
    kind: &'a str,
    payload: Value,
    previous: Option<String>,
    nonce: &'a str,
    tamper: Tamper,
    deliver: bool,
    /// Header `epoch` of the cited epoch, but encrypted under this epoch's key.
    key_epoch: Option<u64>,
    /// The clock the file is stored under, when it differs from the header's.
    path_clock: Option<u64>,
    /// Store this envelope under `ops.twin/` (a second body at the same path).
    twin: bool,
    /// Also store a high-S twin envelope over the same body under `ops.twin/` (§2.2).
    high_s: bool,
}
impl<'a> Op<'a> {
    fn new(author: &'a Member, clock: u64, authority: u64, nonce: &'a str) -> Self {
        Op {
            author,
            level: "write",
            clock,
            epoch: 1,
            authority,
            created: 60 + clock as i64,
            kind: "addNote",
            payload: json!({"text": format!("note {clock}")}),
            previous: None,
            nonce,
            tamper: Tamper::None,
            deliver: true,
            key_epoch: None,
            path_clock: None,
            twin: false,
            high_s: false,
        }
    }
}

#[derive(Clone)]
struct Out1 {
    path: String,
    digest: String,
    id: String,
}

struct Ra {
    chain: Chain,
    acct: String,
    lib: String,
    ctrl: Key,
    vault_id: String,
    vault_agree: Vec<u8>,
    keys: BTreeMap<(String, u64), [u8; 32]>,
    ops: Vec<(String, Vec<u8>)>,
    holders: Vec<Value>,
    expected: Map<String, Value>,
    opened: Vec<String>,
    label: String,
    twins: Vec<(String, Vec<u8>)>,
    by_digest: Map<String, Value>,
    second: Option<Key>,
}

impl Ra {
    fn new(label: &str) -> Ra {
        Ra::build(label, None)
    }
    /// With a second controller (approve, control, recover) that proves possession at genesis.
    fn build(label: &str, second: Option<Key>) -> Ra {
        let a = A.clone();
        let mut ctrls = vec![ctrl(
            &a,
            &["approve", "control", "recover"],
            Some("Mac"),
            json!({}),
        )];
        if let Some(k) = &second {
            ctrls.push(ctrl(
                k,
                &["approve", "control", "recover"],
                Some("Second"),
                json!({}),
            ));
        }
        let kr = keyring(
            ctrls,
            Kr {
                rt: 1,
                ..Kr::default()
            },
        );
        let mut chain = Chain::new();
        let adds: Vec<Key> = second.iter().cloned().collect();
        let opt = match adds.first() {
            Some(k) => Opt {
                adds: sg![*k],
                ..Opt::default()
            },
            None => Opt::default(),
        };
        genesis(
            &mut chain,
            &kr,
            sg![a],
            Gen {
                label: "Records",
                namespaces: vec![NS],
                opt,
                ..Gen::default()
            },
        );
        let acct = account_id(&chain);
        let vault_signing = unb64(G4["keyring"]["vault"]["signing"].as_str().unwrap());
        let vault_agree = unb64(G4["keyring"]["vault"]["agreement"].as_str().unwrap());
        Ra {
            lib: acct[..32].to_string(),
            acct,
            chain,
            ctrl: a,
            vault_id: key_id(&vault_signing),
            vault_agree,
            keys: BTreeMap::new(),
            ops: Vec::new(),
            holders: Vec::new(),
            expected: Map::new(),
            opened: Vec::new(),
            label: label.to_string(),
            twins: Vec::new(),
            by_digest: Map::new(),
            second,
        }
    }
    fn key_for(&mut self, ns: &str, epoch: u64) -> [u8; 32] {
        let label = format!("{}/{ns}/{epoch}/key", self.label);
        *self
            .keys
            .entry((ns.to_string(), epoch))
            .or_insert_with(|| name_seed(&label))
    }
    /// `{enc, ciphertext}`: the epoch key sealed to `agreement` with the §11.1 `info`/AAD.
    fn seal(&mut self, ns: &str, epoch: u64, rid: &str, agreement: &[u8]) -> Value {
        let key = self.key_for(ns, epoch);
        let info = format!("colophon/epoch/3\n{}\n{ns}\n{epoch}\n{rid}", self.lib);
        let mut ent = Entropy::new(name_seed(&format!(
            "{}/{ns}/{epoch}/seal/{rid}/{}",
            self.label,
            self.chain.envs.len()
        )));
        let s = SealedKey::seal(agreement, &key, info.as_bytes(), &mut ent).unwrap();
        json!({"enc": b64(&s.enc), "ciphertext": b64(&s.ciphertext)})
    }
    fn epoch_obj(&mut self, ns: &str, epoch: u64, to: &[(&str, Vec<u8>)]) -> Value {
        let mut seals = Map::new();
        for (rid, point) in to {
            seals.insert(rid.to_string(), self.seal(ns, epoch, rid, point));
        }
        json!({"namespace": ns, "epoch": epoch, "seals": seals})
    }
    fn add(&mut self, kind: &str, at: i64, fields: Value) -> i64 {
        let a = self.ctrl.clone();
        self.chain
            .add(kind, &a, &ts(at), &a, Opt::default(), fields);
        self.chain.envs.len() as i64
    }
    /// An epoch sealed to the vault and `others`.
    fn rekey(&mut self, at: i64, epoch: u64, others: &[&Member]) -> i64 {
        let mut to: Vec<(String, Vec<u8>)> =
            vec![(self.vault_id.clone(), self.vault_agree.clone())];
        to.extend(
            others
                .iter()
                .map(|m| (m.sign.id.clone(), m.agree.point.clone())),
        );
        let refs: Vec<(&str, Vec<u8>)> = to.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
        let e = self.epoch_obj(NS, epoch, &refs);
        self.add("rekey", at, json!({"epochs": [e]}))
    }
    fn grant(
        &mut self,
        at: i64,
        m: &Member,
        kind: &str,
        terms: Value,
        share_epochs: &[u64],
    ) -> i64 {
        let req = request(
            &self.acct,
            &m.sign,
            &m.agree,
            kind,
            terms.clone(),
            "member",
            None,
        );
        let shares: Vec<Value> = share_epochs
            .iter()
            .map(|e| self.epoch_obj(NS, *e, &[(m.sign.id.as_str(), m.agree.point.clone())]))
            .collect();
        self.add(
            "grant",
            at,
            json!({"request": req, "terms": terms, "shares": shares}),
        )
    }
    fn holder(&mut self, m: &Member) {
        self.holders
            .push(json!({"member": m.sign.id, "agreement": b64(&m.agree.scalar)}));
    }
    fn op(&mut self, s: Op) -> Out1 {
        let ns = NS;
        let nonce: Vec<u8> =
            sha_raw(format!("{}/nonce/{}", self.label, s.nonce).as_bytes())[..12].to_vec();
        let created = ts(s.created);
        let mut plain = json!({"id": "", "kind": s.kind, "v": 1, "clock": s.clock,
                               "authority": s.authority, "created": created, "payload": s.payload});
        let preimage = json!({"purpose": "colophon/operation-id/3", "namespace": ns, "author": s.author.sign.id,
                              "epoch": s.epoch, "nonce": nonce.iter().map(|b| json!(*b)).collect::<Vec<_>>(),
                              "operation": plain});
        let mut id = sha(&canonical(&preimage))[..32].to_string();
        if s.tamper == Tamper::BadId {
            id = sha(format!("{}/badid/{}", self.label, s.nonce).as_bytes())[..32].to_string();
        }
        plain["id"] = json!(id);
        if s.tamper == Tamper::PlainClock {
            plain["clock"] = json!(s.clock + 1);
        }
        let aad = canonical(&json!({
            "account": self.acct, "author": s.author.sign.id, "authority": s.authority, "clock": s.clock,
            "created": created, "epoch": s.epoch, "id": id, "level": s.level, "namespace": ns,
            "previous": s.previous, "protocol": "colophon/operation/5"}));
        let key = if s.tamper == Tamper::WrongKey {
            name_seed(&format!("{}/wrong-key", self.label))
        } else {
            self.key_for(ns, s.key_epoch.unwrap_or(s.epoch))
        };
        let ct = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &canonical(&plain),
                    aad: &aad,
                },
            )
            .unwrap();
        let mut h_created = created.clone();
        let mut h_level = s.level.to_string();
        let mut h_previous = s.previous.clone();
        match s.tamper {
            Tamper::Created => h_created = ts(s.created + 1),
            Tamper::Level => h_level = "propose".into(),
            Tamper::Previous => h_previous = Some(sha(b"another header")),
            _ => {}
        }
        let body = json!({"protocol": "colophon/operation/5", "account": self.acct, "namespace": ns,
                          "author": s.author.sign.id, "epoch": s.epoch, "id": id, "clock": s.clock,
                          "authority": s.authority, "created": h_created, "level": h_level,
                          "previous": h_previous, "nonce": b64(&nonce), "ciphertext": b64(&ct)});
        let bytes = canonical(&body);
        let env = json!({"body": b64(&bytes), "signature": b64(&s.author.sign.sign(&bytes))});
        let path = format!(
            "ops/{}/{ns}/{:012}-{id}.json",
            s.author.sign.id,
            s.path_clock.unwrap_or(s.clock)
        );
        if s.deliver {
            let list = if s.twin {
                &mut self.twins
            } else {
                &mut self.ops
            };
            list.push((path.clone(), canonical(&env)));
        }
        if s.high_s {
            let sig = s.author.sign.sign(&bytes);
            let mut s_part: [u8; 32] = sig[32..].try_into().unwrap();
            s_part = sub32(&N, &s_part);
            let mut twin_sig = sig[..32].to_vec();
            twin_sig.extend_from_slice(&s_part);
            let twin = json!({"body": b64(&bytes), "signature": b64(&twin_sig)});
            self.twins.push((path.clone(), canonical(&twin)));
        }
        Out1 {
            path,
            digest: sha(&bytes),
            id,
        }
    }
    fn expect(&mut self, o: &Out1, outcome: &str) {
        self.expected.insert(o.path.clone(), json!(outcome));
    }
    fn expect_digest(&mut self, o: &Out1, outcome: &str) {
        self.by_digest.insert(o.digest.clone(), json!(outcome));
    }
    fn expect_opened(&mut self, o: &Out1) {
        self.expected.insert(o.path.clone(), json!("admitted"));
        self.opened.push(o.path.clone());
    }
    fn write_case(
        self,
        out: &mut Out,
        name: &str,
        description: &str,
        sections: &[&str],
        extra: Value,
    ) {
        for (i, env) in self.chain.envs.iter().enumerate() {
            write(
                out,
                &format!("records/{name}/records/authority/{:08}.json", i + 1),
                env,
            );
        }
        for (path, bytes) in &self.ops {
            let mut d = bytes.clone();
            d.push(b'\n');
            write_raw(out, &format!("records/{name}/{path}"), d);
        }
        for (path, bytes) in &self.twins {
            let mut d = bytes.clone();
            d.push(b'\n');
            write_raw(
                out,
                &format!(
                    "records/{name}/ops.twin/{}",
                    path.trim_start_matches("ops/")
                ),
                d,
            );
        }
        let mut expected = json!({
            "history": "ok",
            "records": Value::Object(self.expected.clone()),
            "opened": self.opened,
        });
        if !self.by_digest.is_empty() {
            expected["byDigest"] = Value::Object(self.by_digest.clone());
        }
        if let Value::Object(m) = extra {
            for (k, v) in m {
                expected[k] = v;
            }
        }
        write(
            out,
            &format!("records/{name}/case.json"),
            &json!({"description": description, "sections": sections,
                    "verifier": {"now": ts(30_000)}, "holders": self.holders, "expected": expected}),
        );
    }
}

fn w_terms() -> Value {
    json!({"records": [{"namespace": NS, "access": "write"}]})
}
fn r_terms() -> Value {
    json!({"records": [{"namespace": NS, "access": "read"}]})
}
fn p_terms() -> Value {
    json!({"records": [{"namespace": NS, "access": "propose"}]})
}

pub fn part(out: &mut Out) {
    shares_and_epochs(out);
    header_aad(out);
    missing_key(out);
    author_chain(out);
    revoke_cases(out);
    duplicates(out);
    retiring(out);
    renew_shares(out);
    proposals(out);
    legacy(out);
}

/// Rekey and grant shares (§11.1, §9.2), the epoch current at the cited seq, the grant start,
/// access levels, and a future claim.
fn shares_and_epochs(out: &mut Out) {
    let (w, r) = (member("w"), member("r"));
    let mut a = Ra::new("shares");
    a.rekey(10, 1, &[]); // seq 2: epoch 1, the vault only
    a.grant(20, &w, "device", w_terms(), &[1]); // seq 3
    a.grant(30, &r, "app", r_terms(), &[1]); // seq 4
    a.rekey(40, 2, &[&w, &r]); // seq 5: epoch 2 to the vault and both members
    a.holder(&w);
    // Epoch 1 current at 3 and 4; epoch 2 from 5.
    let w1 = a.op(Op::new(&w, 1, 3, "w1"));
    a.expect_opened(&w1);
    let mut s = Op::new(&w, 2, 5, "w2");
    s.epoch = 2;
    let w2 = a.op(s);
    a.expect_opened(&w2);
    let w3 = a.op(Op::new(&w, 3, 5, "w3")); // epoch 1 cited at 5
    a.expect(&w3, "refused:wrongEpoch");
    let mut s = Op::new(&w, 4, 3, "w4");
    s.epoch = 2; // epoch 2 cited at 3
    let w4 = a.op(s);
    a.expect(&w4, "refused:wrongEpoch");
    let w5 = a.op(Op::new(&w, 5, 2, "w5")); // before the grant at seq 3
    a.expect(&w5, "refused:notGranted");
    let mut s = Op::new(&w, 6, 9, "w6");
    s.epoch = 2; // authority 9: newer than this replica (5)
    let w6 = a.op(s);
    a.expect(&w6, "held:authorityBehind");
    // A reader holds `read`: neither a write nor a proposal.
    let mut s = Op::new(&r, 7, 5, "r1");
    s.epoch = 2;
    let r1 = a.op(s);
    a.expect(&r1, "refused:notGranted");
    let mut s = Op::new(&r, 8, 5, "r2");
    s.epoch = 2;
    s.level = "propose";
    let r2 = a.op(s);
    a.expect(&r2, "refused:notGranted");
    a.write_case(
        out,
        "shares-and-epochs",
        "Rekey and grant shares. Epoch 1 is sealed to the vault, then to each member by its grant's shares; epoch 2 to the vault and both members. The writer opens its seals with its own agreement key. Epoch 1 is current at seqs 3-4 and epoch 2 from seq 5 (§11.5 step 5); a cite before the grant is notGranted; a cite newer than the replica is held authorityBehind; a read-only member can neither write nor propose.",
        &["7.1", "9.2", "11.1", "11.5"],
        json!({}),
    );
}

/// `/5` headers with AAD (§11.2) and the post-open checks (§11.3).
fn header_aad(out: &mut Out) {
    let w = member("w");
    let mut a = Ra::new("aad");
    a.rekey(10, 1, &[]);
    a.grant(20, &w, "device", w_terms(), &[1]);
    a.holder(&w);
    let ok = a.op(Op::new(&w, 1, 3, "ok"));
    a.expect_opened(&ok);
    for (clock, label, tamper, why) in [
        (2, "created", Tamper::Created, "created"),
        (3, "level", Tamper::Level, "level"),
        (4, "previous", Tamper::Previous, "previous"),
        (5, "wrongkey", Tamper::WrongKey, "key"),
        (6, "plainclock", Tamper::PlainClock, "plaintext clock"),
        (7, "badid", Tamper::BadId, "ID"),
    ] {
        let mut s = Op::new(&w, clock, 3, label);
        s.tamper = tamper;
        let o = a.op(s);
        a.expect(&o, "refused:invalidPayload");
        let _ = why;
    }
    // A header stored at a path that does not match its clock is not a record (§11.2).
    let mut s = Op::new(&w, 8, 3, "path");
    s.path_clock = Some(9);
    let wrong = a.op(s);
    a.expect(&wrong, "malformed");
    a.write_case(
        out,
        "header-aad",
        "Headers with AAD. One honest header opens. Six are encrypted correctly and then damaged: an AAD field of the header changed and re-signed (created, level, previous) does not authenticate; a key that is not the epoch key; a plaintext clock that differs from the header's; an ID that is not content-derived. Each is refused invalidPayload and still reserves its slot (0.3 section 5).",
        &["11.2", "11.3", "11.8"],
        json!({}),
    );
}

fn missing_key(out: &mut Out) {
    let w = member("w");
    let mut a = Ra::new("missing");
    a.rekey(10, 1, &[]);
    a.grant(20, &w, "device", w_terms(), &[1]);
    // No holder: nobody can open epoch 1, so a header that passes steps 1-8 is held.
    let o = a.op(Op::new(&w, 1, 3, "m1"));
    a.expect(&o, "held:unavailable");
    a.write_case(
        out,
        "missing-key",
        "A header that passes admission steps 1-8 whose epoch key the reader cannot open is held unavailable (§11.5).",
        &["11.5"],
        json!({}),
    );
}

fn author_chain(out: &mut Out) {
    let (w, w2) = (member("w"), member("w2"));
    let mut a = Ra::new("chain");
    a.rekey(10, 1, &[]);
    a.grant(20, &w, "device", w_terms(), &[1]);
    a.grant(21, &w2, "device", w_terms(), &[1]);
    a.holder(&w);
    let c1 = a.op(Op::new(&w, 1, 4, "c1"));
    let c2 = a.op(Op {
        previous: Some(c1.digest.clone()),
        ..Op::new(&w, 2, 4, "c2")
    });
    let c3 = a.op(Op {
        previous: Some(c2.digest.clone()),
        ..Op::new(&w, 3, 4, "c3")
    });
    // A second header chained on c2: the author now has two maximal heads (c3 and c4).
    let c4 = a.op(Op {
        previous: Some(c2.digest.clone()),
        ..Op::new(&w, 4, 4, "c4")
    });
    let d1 = a.op(Op::new(&w2, 5, 4, "d1"));
    for o in [&c1, &c2, &c3, &c4, &d1] {
        a.expect_opened(o); // one epoch key opens every header of the epoch, whoever wrote it
    }
    // The second writer's own chain is independent of the first's.
    let mut heads = vec![c3.digest.clone(), c4.digest.clone()];
    heads.sort();
    a.write_case(
        out,
        "author-chain",
        "Author chains (§11.2). `previous` is the digest of the author's preceding header body in the namespace. The first writer has c1, c2 (previous c1), c3 and c4 (both previous c2): two maximal heads, so that writer MUST stop. The second writer's chain is separate. Every header is admitted and opens under the one epoch key; the chain heads are what is checked.",
        &["11.2"],
        json!({"chains": {format!("{}/{NS}", w.sign.id): heads, format!("{}/{NS}", w2.sign.id): [d1.digest]}}),
    );
}

fn heads_json(heads: &[(&str, &str)]) -> Value {
    let mut v: Vec<(String, String)> = heads
        .iter()
        .map(|(n, d)| (n.to_string(), d.to_string()))
        .collect();
    v.sort();
    json!(v
        .into_iter()
        .map(|(n, d)| json!({"namespace": n, "digest": d}))
        .collect::<Vec<_>>())
}

/// The revocation entry: epoch 2 sealed to the vault only (the writer is excluded).
fn revoke_entry(a: &mut Ra, at: i64, w: &Member, kept: &[&str], heads: &[(&str, &str)]) -> i64 {
    let mut kept: Vec<String> = kept.iter().map(|s| s.to_string()).collect();
    kept.sort();
    let (vid, vag) = (a.vault_id.clone(), a.vault_agree.clone());
    let e2 = a.epoch_obj(NS, 2, &[(vid.as_str(), vag)]);
    a.add(
        "revoke",
        at,
        json!({"member": w.sign.id, "kept": kept, "heads": heads_json(heads), "epochs": [e2]}),
    )
}

fn revoke_cases(out: &mut Out) {
    let (w, r) = (member("w"), member("r"));
    // --- kept by digest and by walk; backdated; citing the revocation or later.
    let mut a = Ra::new("revoke-kept");
    a.rekey(10, 1, &[]); // 2
    a.grant(20, &w, "device", w_terms(), &[1]); // 3
    a.grant(21, &r, "app", r_terms(), &[1]); // 4
    a.holder(&w);
    let d1 = a.op(Op::new(&w, 1, 3, "d1"));
    let d2 = a.op(Op {
        previous: Some(d1.digest.clone()),
        ..Op::new(&w, 2, 3, "d2")
    });
    let d3 = a.op(Op {
        previous: Some(d2.digest.clone()),
        ..Op::new(&w, 3, 3, "d3")
    });
    let d4 = a.op(Op {
        previous: Some(d3.digest.clone()),
        ..Op::new(&w, 4, 3, "d4")
    });
    let f = a.op(Op::new(&w, 5, 3, "f"));
    let mut sg_ = Op::new(&w, 6, 5, "g");
    sg_.epoch = 2;
    let g = a.op(sg_);
    let seq = revoke_entry(&mut a, 40, &w, &[&f.digest, &g.digest], &[(NS, &d3.digest)]); // 5
    assert_eq!(seq, 5);
    a.grant(50, &member("late"), "app", r_terms(), &[1, 2]); // 6
    let mut sh = Op::new(&w, 7, 6, "h");
    sh.epoch = 2;
    let h = a.op(sh);
    for o in [&d1, &d2, &d3, &f] {
        a.expect_opened(o);
    }
    a.expect(&d4, "held:revokedBackdated");
    a.expect(&g, "refused:revoked");
    a.expect(&h, "refused:revoked");
    a.write_case(
        out,
        "revoke-kept-heads",
        "A revoke with `kept` [f, g] and `heads` [d3]. The walk from d3 reaches d3, d2, d1 (kept); f is kept by digest. d4 follows d3 and is not kept: held revokedBackdated. g is in `kept` but cites the revocation seq: refused revoked (a kept record citing the revocation or later is refused). h cites a later seq and is not kept: refused revoked.",
        &["9.5", "11.5"],
        json!({}),
    );

    // --- a walk through a refused header.
    let mut a = Ra::new("revoke-refused");
    a.rekey(10, 1, &[]);
    a.grant(20, &w, "device", w_terms(), &[1]); // 3
    a.holder(&w);
    let x1 = a.op(Op::new(&w, 1, 3, "x1"));
    let mut s = Op::new(&w, 2, 3, "x2");
    s.epoch = 2; // refused: epoch 2 is not current at seq 3
    s.previous = Some(x1.digest.clone());
    let x2 = a.op(s);
    let x3 = a.op(Op {
        previous: Some(x2.digest.clone()),
        ..Op::new(&w, 3, 3, "x3")
    });
    revoke_entry(&mut a, 40, &w, &[], &[(NS, &x3.digest)]); // 4
    a.expect_opened(&x1);
    a.expect(&x2, "refused:wrongEpoch");
    a.expect_opened(&x3);
    a.write_case(
        out,
        "revoke-walk-refused-header",
        "The walk follows `previous` through any header whose digest matches, admitted or not. x1 <- x2 <- x3 with head x3: x2 cites epoch 2 at seq 3 and is refused wrongEpoch, yet the walk passes through it, so x1 is kept. A kept record still passes every other admission check: x2 stays refused.",
        &["9.5", "11.5"],
        json!({}),
    );

    // --- a missing intermediate header, and a missing head.
    for (name, drop) in [
        ("revoke-missing-intermediate", "b"),
        ("revoke-missing-head", "c"),
    ] {
        let mut a = Ra::new(name);
        a.rekey(10, 1, &[]);
        a.grant(20, &w, "device", w_terms(), &[1]);
        a.holder(&w);
        let x = a.op(Op::new(&w, 1, 3, "a"));
        let y = a.op(Op {
            deliver: drop != "b",
            previous: Some(x.digest.clone()),
            ..Op::new(&w, 2, 3, "b")
        });
        let z = a.op(Op {
            deliver: drop != "c",
            previous: Some(y.digest.clone()),
            ..Op::new(&w, 3, 3, "c")
        });
        revoke_entry(&mut a, 40, &w, &[], &[(NS, &z.digest)]);
        if drop == "b" {
            a.expect(&x, "held:unavailable");
            a.expect_opened(&z);
        } else {
            a.expect(&x, "held:unavailable");
            a.expect(&y, "held:unavailable");
        }
        a.write_case(
            out,
            name,
            if drop == "b" {
                "a <- b <- c with head c; the reader does not hold b. The head itself is held and reached (c admitted); a cannot be decided because the walk meets a missing intermediate: held unavailable, never as not kept (§9.5)."
            } else {
                "a <- b <- c with head c; the reader does not hold c, the head itself. No walk can start: the records it would decide are held unavailable, never as not kept (§9.5)."
            },
            &["9.5"],
            json!({}),
        );
    }

    // --- a fork: both heads, and one head only.
    for (name, both) in [("revoke-fork-heads", true), ("revoke-fork-one-head", false)] {
        let mut a = Ra::new(name);
        a.rekey(10, 1, &[]);
        a.grant(20, &w, "device", w_terms(), &[1]);
        a.holder(&w);
        let root = a.op(Op::new(&w, 1, 3, "root"));
        let b1 = a.op(Op {
            previous: Some(root.digest.clone()),
            ..Op::new(&w, 2, 3, "b1")
        });
        let b2 = a.op(Op {
            previous: Some(root.digest.clone()),
            ..Op::new(&w, 3, 3, "b2")
        });
        let heads: Vec<(&str, &str)> = if both {
            vec![(NS, &b1.digest), (NS, &b2.digest)]
        } else {
            vec![(NS, &b1.digest)]
        };
        revoke_entry(&mut a, 40, &w, &[], &heads);
        a.expect_opened(&root);
        a.expect_opened(&b1);
        if both {
            a.expect_opened(&b2);
        } else {
            a.expect(&b2, "held:revokedBackdated");
        }
        a.write_case(
            out,
            name,
            if both {
                "Two fork heads b1 and b2 over a common root, both named in `heads`: every branch is kept."
            } else {
                "Two fork heads, only b1 named: the root and b1 are kept; b2 is not reached and not kept (held revokedBackdated), so no fork head is silently dropped by the approver's host."
            },
            &["9.5"],
            json!({}),
        );
    }

    // --- sixteen heads in one namespace, and seventeen.
    for (name, n) in [("revoke-16-heads", 16u64), ("revoke-17-heads", 17u64)] {
        let mut a = Ra::new(name);
        a.rekey(10, 1, &[]);
        a.grant(20, &w, "device", w_terms(), &[1]);
        a.holder(&w);
        let root = a.op(Op::new(&w, 1, 3, "root"));
        let mut tips = Vec::new();
        for i in 0..n {
            let o = a.op(Op {
                previous: Some(root.digest.clone()),
                ..Op::new(&w, 2 + i, 3, &format!("t{i}"))
            });
            tips.push(o);
        }
        let heads: Vec<(&str, &str)> = tips.iter().map(|t| (NS, t.digest.as_str())).collect();
        revoke_entry(&mut a, 40, &w, &[], &heads);
        if n == 16 {
            a.expect_opened(&root);
            for t in &tips {
                a.expect_opened(t);
            }
            a.write_case(
                out,
                name,
                "Sixteen fork heads over one root in one namespace, all named in `heads`: the most §9.5 allows. Every branch is kept.",
                &["9.5"],
                json!({}),
            );
        } else {
            a.write_case(
                out,
                name,
                "Seventeen heads in one namespace: more than 16 is malformed at the revoke entry (§9.5); the history stops at seq 4.",
                &["9.5"],
                json!({"history": {"result": "malformed", "seq": 4}, "records": {}, "opened": []}),
            );
        }
    }
}

fn renew_shares(out: &mut Out) {
    let w = member("w");
    let mut a = Ra::new("renew");
    a.rekey(10, 1, &[]); // 2
    let terms = json!({"records": [{"namespace": NS, "access": "write"}], "expires": ts(300)});
    a.grant(20, &w, "device", terms, &[1]); // 3
    a.rekey(400, 2, &[]); // 4: W's expiry (300) has passed: the epoch goes to the vault only
    let e2 = a.epoch_obj(NS, 2, &[(w.sign.id.as_str(), w.agree.point.clone())]);
    a.add(
        "renew",
        450,
        json!({"member": w.sign.id, "expires": ts(7200), "shares": [e2]}),
    ); // 5
    a.holder(&w);
    let w1 = a.op(Op::new(&w, 1, 3, "w1"));
    a.expect_opened(&w1);
    let mut s = Op::new(&w, 2, 5, "w2");
    s.epoch = 2;
    s.created = 500;
    let w2 = a.op(s);
    a.expect_opened(&w2);
    let mut s = Op::new(&w, 3, 5, "w3");
    s.epoch = 2;
    s.created = 10_000;
    let w3 = a.op(s);
    a.expect(&w3, "refused:expired");
    let mut s = Op::new(&w, 4, 3, "w4");
    s.created = 400; // after the old expiry, within the renewed one
    let w4 = a.op(s);
    a.expect_opened(&w4);
    a.write_case(
        out,
        "renew-shares",
        "Renew with shares (§9.4). The writer expires at +300 s; epoch 2 is introduced at +400 s and sealed to the vault only; the renew at +450 s extends the expiry to +7200 s and its `shares` seal epoch 2 to the writer. The writer opens epoch 2 through the renew's share. A record created at +400 s (after the old expiry, before the renewed one) is admitted: the latest verified expiry decides (§11.5 step 2); one created at +10000 s is refused expired.",
        &["9.4", "11.1", "11.5"],
        json!({}),
    );
}

fn prop_world(label: &str) -> (Ra, Member, Member, Member) {
    let (p, o, o2) = (member("p"), member("o"), member("o2"));
    let mut a = Ra::new(label);
    a.rekey(10, 1, &[]); // 2
    a.grant(20, &p, "agent", p_terms(), &[1]); // 3
    a.grant(21, &o, "device", w_terms(), &[1]); // 4
    let kinds = json!({"records": [{"namespace": NS, "access": "write",
                       "kinds": ["addTask", "colophon.accept", "colophon.decline"]}]});
    a.grant(22, &o2, "device", kinds, &[1]); // 5
    a.holder(&p);
    a.holder(&o);
    a.holder(&o2);
    (a, p, o, o2)
}
fn resolution<'a>(
    who: &'a Member,
    clock: u64,
    kind: &'a str,
    ids: &[&str],
    nonce: &'a str,
) -> Op<'a> {
    Op {
        kind,
        payload: json!({"proposals": ids}),
        ..Op::new(who, clock, 5, nonce)
    }
}
fn proposal_op<'a>(p: &'a Member, clock: u64) -> Op<'a> {
    Op {
        level: "propose",
        ..Op::new(p, clock, 5, "prop")
    }
}
fn prop_state(
    id: &str,
    proposer: &str,
    state: Value,
    evidence: &[&str],
    ignored: &[&str],
) -> Value {
    json!({"id": id, "proposer": proposer, "kind": "addNote", "state": state,
           "evidence": evidence, "ignored": ignored})
}

fn proposals(out: &mut Out) {
    // accept: valid; and the proposer's own accept is refused (it holds `propose`, not `write`).
    let (mut a, p, o, _) = prop_world("prop-accept");
    let pr = a.op(proposal_op(&p, 1));
    let ac = a.op(resolution(&o, 2, "colophon.accept", &[&pr.id], "acc"));
    let own = a.op(resolution(&p, 3, "colophon.accept", &[&pr.id], "own"));
    a.expect_opened(&pr);
    a.expect_opened(&ac);
    a.expect(&own, "refused:notGranted");
    let st = prop_state(
        &pr.id,
        &p.sign.id,
        json!({"accepted": {"by": o.sign.id, "resolution": ac.id, "at": [2, o.sign.id, ac.id]}}),
        &[],
        &[],
    );
    a.write_case(out, "proposal-accept", "A proposal (clock 1) and an accept by a writer (clock 2): the proposal is accepted and folded once at the accept's position, attributed to the proposer. The proposer's own accept is a `write` record by a member that holds only `propose`: refused notGranted, so it resolves nothing.", &["11.6"], json!({"proposals": [st], "heldResolutions": []}));

    let (mut a, p, o, _) = prop_world("prop-decline");
    let pr = a.op(proposal_op(&p, 1));
    let de = a.op(resolution(&o, 2, "colophon.decline", &[&pr.id], "dec"));
    a.expect_opened(&pr);
    a.expect_opened(&de);
    let st = prop_state(
        &pr.id,
        &p.sign.id,
        json!({"declined": {"by": o.sign.id, "resolution": de.id}}),
        &[],
        &[],
    );
    a.write_case(
        out,
        "proposal-decline",
        "A proposal and a decline with a higher clock: declined.",
        &["11.6"],
        json!({"proposals": [st], "heldResolutions": []}),
    );

    // resolution whose clock is not higher: equal, and lower.
    for (name, pclock, rclock, why) in [
        ("proposal-resolution-clock-equal", 3u64, 3u64, "equal to"),
        ("proposal-resolution-clock-lower", 5u64, 3u64, "lower than"),
    ] {
        let (mut a, p, o, _) = prop_world(name);
        let pr = a.op(proposal_op(&p, pclock));
        let ac = a.op(resolution(&o, rclock, "colophon.accept", &[&pr.id], "acc"));
        a.expect_opened(&pr);
        a.expect_opened(&ac);
        let st = prop_state(&pr.id, &p.sign.id, json!("pending"), &[], &[&ac.id]);
        a.write_case(out, name, &format!("An accept whose clock is {why} the proposal's. Both records are admitted, but the accept resolves nothing (§11.6: its clock must exceed the proposal's): the proposal stays pending and the accept is ignored."), &["11.6"], json!({"proposals": [st], "heldResolutions": []}));
    }

    // two resolutions: the first valid one in fold order wins; the later is evidence.
    let (mut a, p, o, _) = prop_world("prop-two-resolutions");
    let pr = a.op(proposal_op(&p, 1));
    let de = a.op(resolution(&o, 2, "colophon.decline", &[&pr.id], "dec"));
    let ac = a.op(resolution(&o, 3, "colophon.accept", &[&pr.id], "acc"));
    for x in [&pr, &de, &ac] {
        a.expect_opened(x);
    }
    let st = prop_state(
        &pr.id,
        &p.sign.id,
        json!({"declined": {"by": o.sign.id, "resolution": de.id}}),
        &[&ac.id],
        &[],
    );
    a.write_case(out, "proposal-two-resolutions", "A decline (clock 2) and an accept (clock 3), both valid: the first in fold order wins, so the proposal is declined and the later accept is evidence only. An acceptance is never final: had the decline arrived later it would still win; the verdict depends on the set, not the arrival order.", &["11.6"], json!({"proposals": [st], "heldResolutions": []}));

    // a resolver that may not write the proposal's kind.
    let (mut a, p, o, o2) = prop_world("prop-resolver-kinds");
    let pr = a.op(proposal_op(&p, 1));
    let bad = a.op(resolution(&o2, 2, "colophon.accept", &[&pr.id], "bad"));
    let good = a.op(resolution(&o, 3, "colophon.accept", &[&pr.id], "good"));
    for x in [&pr, &bad, &good] {
        a.expect_opened(x);
    }
    let st = prop_state(
        &pr.id,
        &p.sign.id,
        json!({"accepted": {"by": o.sign.id, "resolution": good.id, "at": [3, o.sign.id, good.id]}}),
        &[],
        &[&bad.id],
    );
    a.write_case(out, "proposal-resolver-kinds", "The first accept (clock 2) is by a writer whose `kinds` do not include the proposal's kind addNote: it may not write that kind, so it resolves nothing (§11.6) though the record itself is admitted. The second (clock 3) is by an unrestricted writer and resolves the proposal.", &["10.1", "11.6"], json!({"proposals": [st], "heldResolutions": []}));

    // a resolution naming a proposal the reader lacks is held for it.
    let (mut a, _p, o, _) = prop_world("prop-missing");
    let ghost = "e".repeat(32);
    let ac = a.op(resolution(&o, 2, "colophon.accept", &[&ghost], "acc"));
    a.expect_opened(&ac);
    a.write_case(out, "proposal-missing", "An accept naming a proposal the reader does not hold: the accept record is admitted and the resolution is held for the proposal (§11.6); nothing is folded.", &["11.6"], json!({"proposals": [], "heldResolutions": [{"resolution": ac.id, "proposal": ghost}]}));
}

// ---------------------------------------------------------------------------------------------
// Legacy `/3` records of an in-place upgraded account (§11.5, §16.1).

struct Legacy {
    envs: Vec<Vec<u8>>,
    bodies: Vec<Vec<u8>>,
    acct: String,
    lib: String,
    ctrl: Key,
    vault_id: String,
    vault_agree: Vec<u8>,
    keys: BTreeMap<u64, [u8; 32]>,
    label: String,
    ops: Vec<(String, Vec<u8>)>,
    expected: Map<String, Value>,
    opened: Vec<String>,
    holders: Vec<Value>,
}
impl Legacy {
    fn new(label: &str) -> Legacy {
        let g_env = read_json(&v4().join("keys/genesis-one-raw/records/authority/00000001.json"));
        let g_body = body_of(&g_env);
        let acct = sha(&g_body);
        let vault_signing = unb64(G4["keyring"]["vault"]["signing"].as_str().unwrap());
        Legacy {
            lib: acct[..32].to_string(),
            acct,
            envs: vec![env_bytes(&g_env)],
            bodies: vec![g_body],
            ctrl: software(G4["by"].as_str().unwrap()).unwrap(),
            vault_id: key_id(&vault_signing),
            vault_agree: unb64(G4["keyring"]["vault"]["agreement"].as_str().unwrap()),
            keys: BTreeMap::new(),
            label: label.to_string(),
            ops: Vec::new(),
            expected: Map::new(),
            opened: Vec::new(),
            holders: Vec::new(),
        }
    }
    fn key_for(&mut self, epoch: u64) -> [u8; 32] {
        let label = format!("legacy/{}/{epoch}", self.label);
        *self.keys.entry(epoch).or_insert_with(|| name_seed(&label))
    }
    fn seal(&mut self, epoch: u64, rid: &str, agreement: &[u8]) -> Value {
        let key = self.key_for(epoch);
        let info = format!("colophon/epoch/3\n{}\n{NS}\n{epoch}\n{rid}", self.lib);
        let mut ent = Entropy::new(name_seed(&format!(
            "legacy/{}/seal/{epoch}/{rid}",
            self.label
        )));
        let s = SealedKey::seal(agreement, &key, info.as_bytes(), &mut ent).unwrap();
        json!({"enc": b64(&s.enc), "ciphertext": b64(&s.ciphertext)})
    }
    fn epoch_obj(&mut self, epoch: u64, to: &[(&str, Vec<u8>)]) -> Value {
        let mut seals = Map::new();
        for (rid, p) in to {
            seals.insert(rid.to_string(), self.seal(epoch, rid, p));
        }
        json!({"namespace": NS, "epoch": epoch, "seals": seals})
    }
    /// Append an entry; `legacy` bodies are `colophon/authority/4`, others `/5`.
    fn push(&mut self, protocol: &str, kind: &str, issued: &str, fields: Value) -> usize {
        let seq = self.envs.len() + 1;
        let mut body = json!({"protocol": protocol, "seq": seq, "previous": sha(self.bodies.last().unwrap()),
                              "issued": issued, "by": self.ctrl.id, "kind": kind});
        for (k, v) in fields.as_object().unwrap() {
            body[k] = v.clone();
        }
        let env = envelope(&body, &self.ctrl);
        self.bodies.push(body_of(&env));
        self.envs.push(env_bytes(&env));
        seq
    }
    fn rekey4(&mut self) {
        let e1 = self.epoch_obj(1, &[(&self.vault_id.clone(), self.vault_agree.clone())]);
        self.push(
            "colophon/authority/4",
            "rekey",
            "2026-11-11T08:00:30.000Z",
            json!({"epochs": [e1]}),
        );
    }
    fn grant4(&mut self, w: &Member) -> usize {
        let body = json!({"protocol": "colophon/request/3", "libraryID": self.lib,
                          "member": {"signing": b64(&w.sign.point), "agreement": b64(&w.agree.point)},
                          "label": "Legacy device", "kind": "device", "namespaces": [NS],
                          "access": ["read", "write"], "created": "2026-11-11T08:00:40.000Z"});
        let env = envelope(&body, &w.sign);
        let share = self.epoch_obj(1, &[(w.sign.id.as_str(), w.agree.point.clone())]);
        self.push(
            "colophon/authority/4",
            "grant",
            "2026-11-11T08:00:50.000Z",
            json!({"request": b64(&env_bytes(&env)), "grant": {"namespaces": [NS], "access": ["read", "write"]},
                   "shares": [share]}),
        )
    }
    fn revoke4(&mut self, w: &Member, kept: &[&str]) -> usize {
        let mut kept: Vec<String> = kept.iter().map(|s| s.to_string()).collect();
        kept.sort();
        let e2 = self.epoch_obj(2, &[(&self.vault_id.clone(), self.vault_agree.clone())]);
        self.push(
            "colophon/authority/4",
            "revoke",
            "2026-11-11T08:30:00.000Z",
            json!({"memberID": w.sign.id, "kept": kept, "epochs": [e2]}),
        )
    }
    fn upgrade(&mut self) -> usize {
        let mut keyring5 = G4["keyring"].clone();
        keyring5["addThreshold"] = json!(1);
        keyring5["countBy"] = json!("keys");
        keyring5["policy"] = default_policy();
        self.push(
            "colophon/authority/4",
            "upgrade",
            "2026-11-11T09:00:00.000Z",
            json!({"account": self.acct, "keyring": keyring5}),
        )
    }
    fn grant5(&mut self, n: &Member, seconds: i64) -> usize {
        let terms = w_terms();
        let req = request(
            &self.acct,
            &n.sign,
            &n.agree,
            "device",
            terms.clone(),
            "New device",
            None,
        );
        let share = self.epoch_obj(1, &[(n.sign.id.as_str(), n.agree.point.clone())]);
        self.push(
            "colophon/authority/5",
            "grant",
            &ts(seconds),
            json!({"request": req, "terms": terms, "shares": [share]}),
        )
    }
    fn revoke5(&mut self, w: &Member, kept: &[&str], seconds: i64) -> usize {
        let mut kept: Vec<String> = kept.iter().map(|s| s.to_string()).collect();
        kept.sort();
        let e2 = self.epoch_obj(2, &[(&self.vault_id.clone(), self.vault_agree.clone())]);
        self.push(
            "colophon/authority/5",
            "revoke",
            &ts(seconds),
            json!({"member": w.sign.id, "kept": kept, "heads": [], "epochs": [e2]}),
        )
    }
    /// A `/3` header (0.3 section 5) by `who`, or a `/5` one when `v5`.
    #[allow(clippy::too_many_arguments)]
    fn op(
        &mut self,
        who: &Member,
        v5: bool,
        clock: u64,
        authority: u64,
        epoch: u64,
        library: Option<&str>,
        nonce: &str,
    ) -> (String, String) {
        let nonce_b: Vec<u8> =
            sha_raw(format!("legacy/{}/nonce/{nonce}", self.label).as_bytes())[..12].to_vec();
        let created3 = "2026-11-11T08:10:00.000Z";
        let created5 = ts(600 + clock as i64);
        let created = if v5 {
            created5.clone()
        } else {
            created3.to_string()
        };
        let mut plain = json!({"id": "", "kind": "addNote", "v": 1, "clock": clock, "authority": authority,
                               "created": created, "payload": {"text": nonce}});
        let preimage = json!({"purpose": "colophon/operation-id/3", "namespace": NS, "author": who.sign.id,
                              "epoch": epoch, "nonce": nonce_b.iter().map(|b| json!(*b)).collect::<Vec<_>>(),
                              "operation": plain});
        let id = sha(&canonical(&preimage))[..32].to_string();
        plain["id"] = json!(id);
        let lib = library
            .map(str::to_string)
            .unwrap_or_else(|| self.lib.clone());
        let aad = if v5 {
            canonical(
                &json!({"account": self.acct, "author": who.sign.id, "authority": authority, "clock": clock,
                              "created": created, "epoch": epoch, "id": id, "level": "write", "namespace": NS,
                              "previous": Value::Null, "protocol": "colophon/operation/5"}),
            )
        } else {
            canonical(
                &json!({"author": who.sign.id, "authority": authority, "clock": clock, "created": created,
                              "epoch": epoch, "id": id, "library": lib, "namespace": NS,
                              "protocol": "colophon/operation/3"}),
            )
        };
        let key = self.key_for(epoch);
        let ct = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce_b),
                Payload {
                    msg: &canonical(&plain),
                    aad: &aad,
                },
            )
            .unwrap();
        let body = if v5 {
            json!({"protocol": "colophon/operation/5", "account": self.acct, "namespace": NS, "author": who.sign.id,
                   "epoch": epoch, "id": id, "clock": clock, "authority": authority, "created": created,
                   "level": "write", "previous": Value::Null, "nonce": b64(&nonce_b), "ciphertext": b64(&ct)})
        } else {
            json!({"protocol": "colophon/operation/3", "library": lib, "namespace": NS, "author": who.sign.id,
                   "epoch": epoch, "id": id, "clock": clock, "authority": authority, "created": created,
                   "nonce": b64(&nonce_b), "ciphertext": b64(&ct)})
        };
        let bytes = canonical(&body);
        let env = json!({"body": b64(&bytes), "signature": b64(&who.sign.sign(&bytes))});
        let path = format!("ops/{}/{NS}/{clock:012}-{id}.json", who.sign.id);
        let mut d = canonical(&env);
        d.push(b'\n');
        self.ops.push((path.clone(), d));
        (path, sha(&bytes))
    }
    fn expect(&mut self, path: &str, outcome: &str) {
        self.expected.insert(path.to_string(), json!(outcome));
    }
    fn expect_opened(&mut self, path: &str) {
        self.expected.insert(path.to_string(), json!("admitted"));
        self.opened.push(path.to_string());
    }
    fn write_case(self, out: &mut Out, name: &str, description: &str, sections: &[&str]) {
        for (i, e) in self.envs.iter().enumerate() {
            let mut d = e.clone();
            d.push(b'\n');
            write_raw(
                out,
                &format!("records/{name}/records/authority/{:08}.json", i + 1),
                d,
            );
        }
        for (path, d) in self.ops {
            write_raw(out, &format!("records/{name}/{path}"), d);
        }
        write(
            out,
            &format!("records/{name}/case.json"),
            &json!({"description": description, "sections": sections,
                    "verifier": {"now": ts(30_000)}, "holders": self.holders,
                    "legacyLibraryID": self.lib, "accountID": self.acct,
                    "expected": {"history": "ok", "records": Value::Object(self.expected), "opened": self.opened}}),
        );
    }
}

fn legacy(out: &mut Out) {
    let (w, n) = (member("lw"), member("ln"));
    let holders = |l: &mut Legacy, ms: &[&Member]| {
        for m in ms {
            l.holders
                .push(json!({"member": m.sign.id, "agreement": b64(&m.agree.scalar)}));
        }
    };
    // --- upgraded: the fence in both directions.
    let mut l = Legacy::new("admit");
    l.rekey4(); // 2
    l.grant4(&w); // 3
    let up = l.upgrade(); // 4
    assert_eq!(up, 4);
    l.grant5(&n, 3700); // 5
    holders(&mut l, &[&w, &n]);
    let (a1, _) = l.op(&w, false, 1, 3, 1, None, "l1");
    let (a2, _) = l.op(&w, false, 2, 4, 1, None, "l2");
    let (a3, _) = l.op(&w, false, 3, 3, 1, Some(&"0".repeat(32)), "l3");
    let (a4, _) = l.op(&w, false, 4, 5, 1, None, "l4");
    let (b1, _) = l.op(&n, true, 5, 5, 1, None, "n1");
    let (b2, _) = l.op(&w, true, 6, 3, 1, None, "n2");
    let (b3, _) = l.op(&w, true, 7, 4, 1, None, "n3");
    let (b4, _) = l.op(&w, false, 8, 1, 1, None, "l5");
    l.expect_opened(&a1);
    l.expect(&a2, "refused:wrongFormat");
    l.expect(&a3, "refused:wrongFormat");
    l.expect(&a4, "refused:wrongFormat");
    l.expect_opened(&b1);
    l.expect(&b2, "refused:wrongFormat");
    l.expect_opened(&b3);
    l.expect(&b4, "refused:notGranted");
    l.write_case(out, "upgraded-fence", "An account upgraded in place at seq 4 (§16.1, §11.5). A `/3` record citing authority 3 (before the upgrade) with the legacy library ID is admitted and opens under the legacy epoch share. A `/3` record citing the upgrade seq (4) or later (5), or naming another library, is refused wrongFormat. A `/5` record citing authority before the upgrade (3) is refused wrongFormat; one citing the upgrade seq (4) by the carried-over member, or later by a member granted after the upgrade, is admitted. A `/3` record citing authority 1, before the writer's grant at seq 3, is refused notGranted.", &["11.5", "16.1"]);

    // --- revoked after the upgrade, with a legacy digest in `kept`.
    let mut l = Legacy::new("revoked-after");
    l.rekey4();
    l.grant4(&w);
    l.upgrade(); // 4
    holders(&mut l, &[&w]);
    let (k1, kd) = l.op(&w, false, 1, 3, 1, None, "k1");
    let (k2, _) = l.op(&w, false, 2, 3, 1, None, "k2");
    let r = l.revoke5(&w, &[&kd], 3700); // 5
    assert_eq!(r, 5);
    l.expect_opened(&k1);
    l.expect(&k2, "held:revokedBackdated");
    l.write_case(out, "upgraded-revoked-after", "A carried-over member revoked after the upgrade (seq 5) by a `/5` revoke whose `kept` names the digest of one `/3` header (§9.5: any header digest, `/3` or `/5`). That `/3` record is kept and admitted; the other cites authority 3, is not kept and is held revokedBackdated.", &["9.5", "11.5", "16.1"]);

    // --- revoked before the upgrade (a 0.4 `kept`), then upgraded.
    let mut l = Legacy::new("revoked-before");
    l.rekey4();
    l.grant4(&w);
    let (m1, md) = l.op(&w, false, 1, 3, 1, None, "m1");
    let (m2, _) = l.op(&w, false, 2, 3, 1, None, "m2");
    let (m3, _) = l.op(&w, false, 3, 4, 2, None, "m3");
    let rv = l.revoke4(&w, &[&md]); // 4
    assert_eq!(rv, 4);
    l.upgrade(); // 5
    holders(&mut l, &[&w]);
    l.expect_opened(&m1);
    l.expect(&m2, "held:revokedBackdated");
    l.expect(&m3, "refused:revoked");
    l.write_case(out, "upgraded-revoked-before", "A member revoked by a 0.4 `revoke` at seq 4 with `kept` [m1], then the upgrade at seq 5. Its `/3` records citing authority 3 are decided by the carried-over revocation: m1 is kept and admitted, m2 is held revokedBackdated, and m3 (citing the revocation seq 4, which is before the upgrade) is refused revoked.", &["9.5", "11.5", "16.1"]);
}

/// Two bodies by one author with one operation ID and clock at one path (they differ only in
/// `level`, which is in the AAD but not in the ID), and one body under two envelopes (a high-S
/// twin, §2.2). The verdict is a function of the set: the lowest body digest wins the ID.
fn duplicates(out: &mut Out) {
    let w = member("w");
    let mut a = Ra::new("same-id");
    a.rekey(10, 1, &[]);
    a.grant(20, &w, "device", w_terms(), &[1]);
    a.holder(&w);
    let x = a.op(Op::new(&w, 1, 3, "x"));
    let y = a.op(Op {
        level: "propose",
        twin: true,
        ..Op::new(&w, 1, 3, "x")
    });
    assert_eq!(x.path, y.path);
    let (low, high) = if x.digest < y.digest {
        (&x, &y)
    } else {
        (&y, &x)
    };
    a.expect_digest(low, "admitted");
    a.expect_digest(high, "refused:duplicateID");
    let proposals = if low.digest == y.digest {
        json!([{"id": y.id, "proposer": w.sign.id, "kind": "addNote", "state": "pending",
                "evidence": [], "ignored": []}])
    } else {
        json!([])
    };
    a.write_case(out, "same-id-two-bodies", "Two header bodies by one author with one operation ID and clock at one path, differing only in `level` (in the AAD, not in the ID). Fold order is (clock, author, id) with the body digest, lowest first, as the last tie-break: the lowest digest is admitted and the other is refused duplicateID, whichever arrives first. Both are admitted at step 8 and reserve one slot (one distinct (author, id)).", &["11.4", "11.5"], json!({"proposals": proposals, "heldResolutions": []}));

    let mut a = Ra::new("one-body-two-envelopes");
    a.rekey(10, 1, &[]);
    a.grant(20, &w, "device", w_terms(), &[1]);
    a.holder(&w);
    let x = a.op(Op {
        high_s: true,
        ..Op::new(&w, 1, 3, "x")
    });
    a.expect_digest(&x, "admitted");
    a.opened.push(x.path.clone());
    a.write_case(out, "one-body-two-envelopes", "One header body under two envelopes: the signature and its high-S twin, both valid (§4.3). Two envelopes over one body are the same object (§2.2): the record is admitted, reported under each envelope, and never refused as a duplicateID of itself.", &["2.2", "11.5"], json!({}));
}

/// A revoke while the vault is retiring carries empty `epochs` (§8.3): no epoch is introduced.
fn retiring(out: &mut Out) {
    let w = member("w");
    let k = derived("rec/second/signing");
    let a_key = A.clone();
    let mut a = Ra::build("retiring", Some(k.clone()));
    a.rekey(10, 1, &[]); // 2
    a.grant(20, &w, "device", w_terms(), &[1]); // 3
    a.holder(&w);
    let d1 = a.op(Op::new(&w, 1, 3, "d1"));
    // A full set (both control controllers sign, no home): due at its `issued`. It removes the
    // slotted controller A, so the vault is retiring when it is activated.
    let mut ids = vec![a_key.id.clone(), k.id.clone()];
    ids.sort();
    let tbody = json!({"protocol": "colophon/transition/5", "account": a.acct,
        "anchor": {"seq": 3, "digest": sha(&a.chain.last())}, "issued": ts(100), "by": a_key.id,
        "signers": ids, "change": {"keyring": {"remove": [a_key.id]}}});
    let tenv = seal(
        &tbody,
        &a_key,
        Opt {
            cos: sg![k],
            ..Opt::default()
        },
    );
    let abody = json!({"protocol": "colophon/authority/5", "seq": 4, "previous": sha(&a.chain.last()),
        "issued": ts(100), "by": a_key.id, "kind": "activate",
        "transition": b64(&env_bytes(&tenv)), "receipts": []});
    a.chain.envs.push(json!({"body": b64(&canonical(&abody))}));
    // seq 5: the second controller revokes the writer; the vault is retiring, so `epochs` is [].
    let second = k.clone();
    a.chain.add(
        "revoke",
        &second,
        &ts(200),
        &second,
        Opt::default(),
        json!({"member": w.sign.id, "kept": [d1.digest], "heads": [], "epochs": []}),
    );
    a.expect_opened(&d1);
    let _ = &a.second;
    a.write_case(out, "revoke-while-retiring", "The slotted controller is removed by a full-set transition (activated at seq 4): the vault is retiring (§8.3). The remaining controller then revokes the writer. §8.3: hosts MUST NOT introduce epochs while the vault is retiring and a `revoke` MAY carry empty `epochs`, so the revoke is ok with `epochs: []` and no epoch 2 exists; the removed key's retiring vault therefore opens nothing made after. The kept record is admitted.", &["8.3", "9.5", "7.1"], json!({"vaultRetiring": true, "latestEpoch": {"notes": 1}}));
}
