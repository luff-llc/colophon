//! Two devices of one person and a real home, through the typed exports only: the reference for
//! the SDKs (the Swift journey in `swift/Tests/ColophonSessionTests/RelayJourneyTests.swift` is the
//! same journey). The home is the real relay (`relay/server.js` on Bun with the Rust home module),
//! requiring a call for everything §13.4 and §14 say needs one; every call is built by
//! `exchange_begin_call` from the request the engine made, signed by the host, and judged by the
//! core with the home's own rule before it is sent.
//!
//! The journey: an owner creates an account (the creation's own engine, unlocked: no second
//! unlock), appoints the home and is approved as a device; it writes a note, a required and an
//! optional blob and syncs (the first upload). A second device holding the history from before
//! its approval (under `policy.history: members` a device with nothing can fetch only the head,
//! and cannot even name an `asOf`) asks, is approved by the first, learns its approval through
//! the home, reads, writes; the first reads that. A third device is approved, then revoked: the
//! home refuses its calls and it reads nothing new. A pending key change proposed on the first
//! device is shown on the second (which holds a control key) and vetoed there. Under `members`
//! and under `public`, and with two homes at `headQuorum` 2.
//!
//! Protocol time is only the test's clock (`World::now`, a second a pass). No home runs a
//! scheduler timer: the test runs each scheduler pass with `Relay::tick`, and waits (bounded) only
//! for forwarding between the two homes to arrive (`World::converge`).
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
mod v05_support;
mod v05_relay;
use serde_json::{json, Value};
use std::sync::Arc;
use v05_relay::*;
use v05_support::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "notes";

fn base(n: u8) -> String {
    format!("https://home-{n}.test/v1/accounts/journey")
}

/// The host: keys, and which relay serves which base.
struct World {
    host: Host,
    relays: Vec<Relay>,
    account: String,
    homes: Vec<String>,
    now: i64,
    /// Calls the engine's own check refused (the pass with that home was abandoned), by code.
    unbuilt: Vec<String>,
    /// The `result` of every 403 a home answered, in order.
    refused: Vec<String>,
    /// With two homes: both hold a head, and `sync` lets them converge before each pass.
    converging: bool,
}
impl World {
    fn tick(&mut self) -> i64 {
        self.now += 1_000;
        self.now
    }
    fn relay_for(&self, url: &str) -> &Relay {
        self.relays.iter().find(|r| url.starts_with(&format!("{}/", r.base))).expect("a request for a home of the account")
    }
    /// With more than one home: scheduler passes at every home until each serves a head over the
    /// same seq and holds every other home's head over it (a home judges a call by the heads it
    /// holds, and forwarding is how it gets the others', §13.1). A device fetches each home's head
    /// from that home, so without this it can hold a head its other home has not been given yet,
    /// and that home refuses the call it builds (`unavailable`, `refused:revoked`). The clock moves
    /// a second first: a home that signed a head at the last reading and has taken entries since
    /// can sign the head over them only at a later one (heads' `issued` strictly increase, §13.3).
    fn converge(&mut self, what: &str) {
        if self.relays.len() < 2 {
            return;
        }
        let now = self.tick();
        for r in &self.relays {
            r.set_clock(now);
        }
        forwarded(what, &self.relays, || {
            let own: Vec<Option<u64>> = self.relays.iter().map(|r| r.head_seq("/head")).collect();
            own[0].is_some()
                && own.iter().all(|s| *s == own[0])
                && self.relays.iter().enumerate().all(|(i, r)| {
                    self.homes.iter().enumerate().all(|(j, id)| i == j || r.head_seq(&format!("/records/heads/{id}.json")) == own[j])
                })
        });
    }
}

fn finish(engine: &AccountEngine, host: &Host, action: Arc<AccountAction>) -> Written {
    assert!(action.denial().unwrap().is_none(), "the action was denied");
    let prf = action.prf_requests().unwrap();
    if !prf.is_empty() {
        engine.provide_prf(action.clone(), host.answer_prf(&prf)).unwrap();
    }
    let sigs = host.sign(&action.steps().unwrap());
    engine.finish(action, sigs).unwrap()
}

/// A pass of `engine` with every home (`pass`). With two homes, once both hold a head (`World::
/// converging`), the homes first exchange what they forward (`World::converge`), so the device
/// fetches no head from one home that the other has not been given; and a pass the second home
/// sent to the primary (421: entries the device pushed before the primary's head over them reached
/// it, §13.1) is run again once that head has been forwarded. Its 421s are not returned.
fn sync(w: &mut World, engine: &AccountEngine, src: &MemSource, me: &str) -> Vec<ExchangeFault> {
    if !w.converging {
        return pass(w, engine, src, me);
    }
    w.converge("the homes hold each other's heads before a pass");
    let faults = pass(w, engine, src, me);
    if !faults.iter().any(|f| f.kind == ExchangeFaultKind::Redirect) {
        return faults;
    }
    assert!(
        faults.iter().all(|f| f.kind != ExchangeFaultKind::Redirect || f.home != w.homes[0]),
        "only the second home sends the device to the primary: {}",
        show(&faults)
    );
    let mut faults: Vec<ExchangeFault> = faults.into_iter().filter(|f| f.kind != ExchangeFaultKind::Redirect).collect();
    w.converge("the primary's head over the pushed entries reaches the second home");
    faults.extend(pass(w, engine, src, me));
    faults
}

/// One pass of `engine` with every home, as an app runs it: each request goes to the home its URL
/// names; each `NeedCall` gets a call built by the engine and signed by `me`.
fn pass(w: &mut World, engine: &AccountEngine, src: &MemSource, me: &str) -> Vec<ExchangeFault> {
    let now = w.tick();
    let mut faults = Vec::new();
    engine.advance(now).unwrap();
    engine.refresh(src.listing()).unwrap();
    for home in w.homes.clone() {
        for _ in 0..100_000 {
            let step = engine.exchange_next(home.clone()).unwrap();
            match step.kind {
                ExchangeStepKind::Done => break,
                ExchangeStepKind::Waiting => panic!("the loop answers every request"),
                ExchangeStepKind::NeedCall => {
                    let n = step.need.unwrap();
                    assert_eq!(n.url, format!("{}{}", n.audience, n.path), "the need names the request");
                    let key = w.host.keys[me].public().signing;
                    let action = engine.exchange_begin_call(home.clone(), n.ticket, key, w.host.fresh(32)).unwrap();
                    let sigs = w.host.sign(&action.steps().unwrap());
                    match engine.finish(action, sigs) {
                        Ok(written) => engine.exchange_provide_call(home.clone(), n.ticket, written.artifact.unwrap()).unwrap(),
                        Err(e) => {
                            // The device's own check refused the call: nothing is sent, the pass with
                            // this home is abandoned, the next home is tried.
                            w.unbuilt.push(e.code());
                            src.store(&engine.exchange_abort(home.clone()).unwrap().store);
                            break;
                        }
                    }
                }
                ExchangeStepKind::Request => {
                    let r = step.request.unwrap();
                    let method = match r.method {
                        HttpMethod::Get => "GET",
                        HttpMethod::Post => "POST",
                        HttpMethod::Put => "PUT",
                    };
                    let headers: Vec<(String, String)> = r.headers.iter().map(|h| (h.name.clone(), h.value.clone())).collect();
                    let (status, body) = w.relay_for(&r.url).send(method, &r.url, &headers, &r.body, now);
                    if status == 403 {
                        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        w.refused.push(v["result"].as_str().unwrap_or("-").to_string());
                    }
                    let report = engine
                        .exchange_answer(home.clone(), r.ticket, HttpAnswer { status: u32::from(status), headers: vec![], body })
                        .unwrap();
                    src.store(&report.store);
                    faults.extend(report.faults);
                }
            }
        }
    }
    faults
}

fn open(src: &MemSource, identity: &str, account: &str, now: i64) -> Arc<AccountEngine> {
    AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        ident(identity),
        account.into(),
        // The read scope an app gives (its namespaces): its change feed is scoped, and lists no
        // blob chunk (0.3 §8.4), so required chunks are asked for by the manifest's names.
        vec![NS.into()],
        0,
        SavedState { verifier: vec![], checkpoint: vec![], parts: vec![] },
        DEVICE_KEY.to_vec(),
        now,
    )
    .unwrap()
}
fn member_engine(w: &World, src: &MemSource, m: &str) -> Arc<AccountEngine> {
    let e = open(src, &format!("member:{m}"), &w.account, w.now);
    let agreements = e.begin_unlock_epochs().unwrap();
    if agreements.is_empty() {
        e.load().unwrap();
    } else {
        e.finish_unlock_epochs(w.host.answer_epochs(m, &agreements)).unwrap();
    }
    e
}
fn request(host: &Host, account: &str, key: &str, label: &str, kind: AccountMemberKind, terms: Value, endpoints: Vec<String>) -> RequestInfo {
    let p = host.keys[key].public();
    let req = AccountRequest::prepare(RequestSpec {
        account: account.into(),
        signing: p.signing,
        agreement: p.agreement,
        label: label.into(),
        kind,
        terms_json: terms.to_string(),
        created: account_format_date(NOW - 60_000).unwrap(),
        custody: None,
        operator: None,
        endpoints,
    })
    .unwrap();
    let step = req.step().unwrap();
    req.finish(host.sign_one(&step.body, key, false)).unwrap()
}
fn notes(e: &AccountEngine) -> usize {
    let v: Value = serde_json::from_str(&e.view_json(NS.into()).unwrap()).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v["value"]["admitted"].as_array().unwrap().len()
}
fn is_member(e: &AccountEngine) -> bool {
    e.me().unwrap().kind == StandingKind::Member
}
fn write_note(w: &mut World, e: &AccountEngine, src: &MemSource, id: &str) {
    let a = e.begin_write(NS.into(), "note.put".into(), json!({"id": id, "text": id}).to_string(), w.host.fresh(32)).unwrap();
    src.store(&finish(e, &w.host, a).stores);
}
/// A blob through the exports: chunks stored, then the manifest published.
fn put_blob(w: &mut World, e: &AccountEngine, src: &MemSource, bytes: &[u8], required: bool) -> String {
    let writer = e.begin_blob(NS.into(), "application/octet-stream".into(), w.host.fresh(32)).unwrap();
    for chunk in bytes.chunks(64 * 1024) {
        let c = writer.push(chunk.to_vec()).unwrap();
        src.put(&c.path, c.bytes);
    }
    let manifest: Value = serde_json::from_str(&writer.finish().unwrap()).unwrap();
    let digest = manifest["descriptor"]["digest"].as_str().unwrap().to_string();
    let mut payload = json!({"manifest": manifest, "reference": format!("ref-{required}")});
    if required {
        payload["required"] = json!(true);
    }
    let a = e.begin_write(NS.into(), "colophon.blobPublish".into(), payload.to_string(), w.host.fresh(32)).unwrap();
    src.store(&finish(e, &w.host, a).stores);
    digest
}

fn journey(history: &str, homes: u8) {
    let mut host = Host::new();
    let d = host.identity(10);
    let d2 = host.identity(12);
    let k = host.kit(20);
    let m1 = host.identity(31);
    let m2 = host.identity(32);
    let m3 = host.identity(33);
    let home_keys: Vec<HomeKey> = (0..homes)
        .map(|n| {
            let scalar = [0x50 + n; 32];
            let keys = colophon_core::crypto::SoftwareKeys::from_scalars(&scalar, &[0x60 + n; 32]).unwrap();
            let point = keys.public().signing;
            host.keys.insert(colophon_core::v05::ids::key_id(&point), keys);
            HomeKey { scalar, point }
        })
        .collect();

    // --- The owner creates the account: device key d, a second control key d2 (the second
    // device's), a recovery kit; one slot each.
    let mut policy: Value = serde_json::from_str(&account_default_policy().unwrap()).unwrap();
    policy["recoveryDelay"] = json!(3600);
    policy["history"] = json!(history);
    policy["headQuorum"] = json!(homes);
    let params = CreateParams {
        label: "Two devices".into(),
        namespaces: vec![NS.into()],
        controllers: vec![
            host.raw_controller(&d, "Mac", &["approve", "control", "recover"]),
            host.raw_controller(&d2, "Phone owner key", &["approve", "control"]),
            host.raw_controller(&k, "Kit", &["recover"]),
        ],
        slots: vec![
            SlotPlan { controllers: vec![d.clone()], label: "Mac".into() },
            SlotPlan { controllers: vec![d2.clone()], label: "Phone".into() },
            SlotPlan { controllers: vec![k.clone()], label: "Kit".into() },
        ],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy_json: policy.to_string(),
        signers: vec![d.clone()],
        rekey_signers: vec![d.clone()],
    };
    let creation = AccountCreation::begin(params, ident(&format!("controller:{d}")), NOW, host.fresh(96)).unwrap();
    let reqs = creation.prf_requests().unwrap();
    if !reqs.is_empty() {
        creation.provide_prf(host.answer_prf(&reqs)).unwrap();
    }
    while creation.provide_signatures(host.sign(&creation.steps().unwrap())).unwrap() != CreateStage::Done {}
    let created = creation.take_result().unwrap();
    let account = created.account.clone();
    let mac = MemSource::new();
    mac.store(&created.stores);
    // The creation's own engine: unlocked, no second unlock.
    let owner = creation.open_engine(Box::new(mac.clone()), mac.listing(), vec![], 0, DEVICE_KEY.to_vec(), NOW).unwrap();
    assert!(owner.is_unlocked().unwrap(), "the creation leaves its session unlocked");
    assert!(creation.open_engine(Box::new(mac.clone()), mac.listing(), vec![], 0, DEVICE_KEY.to_vec(), NOW).is_err(), "one shot");

    // --- The homes: started for this account, appointed in one transition recorded at once.
    // Each home knows where the others are (it forwards transitions, receipts and its heads).
    let mut relays = Vec::new();
    let bases: Vec<String> = (0..homes).map(base).collect();
    for (n, key) in home_keys.iter().enumerate() {
        relays.push(Relay::start(key, &account, &bases[n], NOW, &[], &format!("{history}-{homes}-{n}")));
    }
    for (n, relay) in relays.iter().enumerate() {
        let peers: Vec<(&str, u16)> = relays.iter().enumerate().filter(|(m, _)| *m != n)
            .map(|(m, peer)| (bases[m].as_str(), peer.port)).collect();
        relay.set_resolve(&peers);
    }
    let mut appoint = Vec::new();
    let mut home_ids = Vec::new();
    for (n, key) in home_keys.iter().enumerate() {
        let id = colophon_core::v05::ids::key_id(&key.point);
        let r = request(&host, &account, &id, "Home", AccountMemberKind::Server, json!({"serves": ["home"]}), vec![format!("{}/", base(n as u8))]);
        appoint.push(json!({"request": colophon_core::v05::encoding::encode_base64(&r.raw), "terms": {"serves": ["home"]}}));
        home_ids.push(id);
    }
    let change = json!({"homes": {"appoint": appoint}});
    let a = owner.begin_transition(change.to_string(), vec![d.clone(), k.clone()], RuleKind::Control, vec![]).unwrap();
    mac.store(&finish(&owner, &host, a).stores);
    for due in owner.record_due().unwrap() {
        mac.store(&due.stores);
    }
    assert_eq!(owner.homes().unwrap().len(), usize::from(homes));
    let terms = json!({"records": [{"namespace": NS, "access": "write"}]});
    let r1 = request(&host, &account, &m1, "Mac", AccountMemberKind::Device, terms.clone(), vec![]);
    let a = owner.begin_approve(r1.raw.clone(), terms.to_string(), vec![d.clone()], scanned(&owner, &r1.raw, NOW), host.fresh(32)).unwrap();
    mac.store(&finish(&owner, &host, a).stores);
    let mut w = World { host, relays, account: account.clone(), homes: home_ids, now: NOW, unbuilt: Vec::new(), refused: Vec::new(), converging: false };

    // --- Device one: its member writes a note, a required and an optional blob, and syncs.
    let dev1 = member_engine(&w, &mac, &m1);
    write_note(&mut w, &dev1, &mac, "n1");
    let required = put_blob(&mut w, &dev1, &mac, &vec![7u8; 100_000], true);
    let optional = put_blob(&mut w, &dev1, &mac, &vec![9u8; 5_000], false);
    // The first upload. At headQuorum 2 a call needs both homes' fresh heads covering the
    // member's grant; the second home stores entries only once a primary head covers them. Until
    // then the device's own check builds no call; then every call is built.
    let f = sync(&mut w, &dev1, &mac, &m1);
    assert!(homes > 1 || f.is_empty(), "the first upload and the records: {}", show(&f));
    if homes > 1 {
        // The second home has no primary head yet, so it answers 421 (§13.1); and with one home's
        // head at most, S (the seq covered by headQuorum heads) is before the grant: the device's
        // own check builds no call (`unavailable`, `refused:revoked`), as the homes would refuse it.
        assert!(!f.is_empty() && f.iter().all(|f| f.kind == ExchangeFaultKind::Redirect), "{}", show(&f));
        assert!(!w.unbuilt.is_empty(), "no call is built before both heads cover the grant");
        assert!(w.unbuilt.iter().all(|c| c == "unavailable" || c == "refused:revoked"), "{:?}", w.unbuilt);
        assert!(w.refused.is_empty(), "nothing was sent to be refused: {:?}", w.refused);
        w.unbuilt.clear();
        // The first home forwards the entries and its head; the second stores them, signs its own
        // head over them, and forwards that back.
        w.converge("each home holds the other's head over the first upload");
        w.converging = true;
    }
    clean(sync(&mut w, &dev1, &mac, &m1), "");
    assert_eq!(w.unbuilt, Vec::<String>::new(), "every call was built");

    // --- Device two holds the history from before its approval, asks, and is approved.
    let phone = MemSource::new();
    for l in mac.listing() {
        if l.path.starts_with("authority/") {
            phone.put(&l.path, mac.get(&l.path).unwrap());
        }
    }
    let dev2 = open(&phone, &format!("member:{m2}"), &account, w.now);
    dev2.load().unwrap();
    assert!(!is_member(&dev2));
    let r2 = request(&w.host, &account, &m2, "Phone", AccountMemberKind::Device, terms.clone(), vec![]);
    owner.refresh(mac.listing()).unwrap();
    let a = owner.begin_approve(r2.raw.clone(), terms.to_string(), vec![d.clone()], scanned(&owner, &r2.raw, NOW), w.host.fresh(32)).unwrap();
    mac.store(&finish(&owner, &w.host, a).stores);
    clean(sync(&mut w, &dev1, &mac, &m1), "the approval reaches the home");
    let f = sync(&mut w, &dev2, &phone, &m2);
    assert!(f.is_empty(), "{}", show(&f));
    assert!(is_member(&dev2), "the phone learnt its approval through the home");
    let agreements = dev2.begin_unlock_epochs().unwrap();
    dev2.finish_unlock_epochs(w.host.answer_epochs(&m2, &agreements)).unwrap();
    let f = sync(&mut w, &dev2, &phone, &m2);
    assert!(f.is_empty(), "{}", show(&f));
    assert_eq!(notes(&dev2), 3, "the note and the two blob publications");
    assert_eq!(dev2.blob_availability(NS.into(), required.clone()).unwrap().state, BlobState::Complete, "a required blob comes with the pass");
    assert_eq!(dev2.blob_availability(NS.into(), optional.clone()).unwrap().state, BlobState::Missing, "an optional one does not");
    dev2.exchange_want_blob(w.homes[0].clone(), NS.into(), optional.clone()).unwrap();
    clean(sync(&mut w, &dev2, &phone, &m2), "");
    assert_eq!(dev2.blob_availability(NS.into(), optional.clone()).unwrap().state, BlobState::Complete, "fetched when asked");
    write_note(&mut w, &dev2, &phone, "n2");
    clean(sync(&mut w, &dev2, &phone, &m2), "");
    clean(sync(&mut w, &dev1, &mac, &m1), "");
    assert_eq!(notes(&dev1), 4, "the Mac reads what the phone wrote");

    // --- A third device is approved, then revoked: the home refuses it and it reads nothing new.
    let tablet = phone.copy_of();
    let dev3 = open(&tablet, &format!("member:{m3}"), &account, w.now);
    dev3.load().unwrap();
    let r3 = request(&w.host, &account, &m3, "Tablet", AccountMemberKind::Device, terms.clone(), vec![]);
    owner.refresh(mac.listing()).unwrap();
    let a = owner.begin_approve(r3.raw.clone(), terms.to_string(), vec![d.clone()], scanned(&owner, &r3.raw, NOW), w.host.fresh(32)).unwrap();
    mac.store(&finish(&owner, &w.host, a).stores);
    clean(sync(&mut w, &dev1, &mac, &m1), "");
    clean(sync(&mut w, &dev3, &tablet, &m3), "");
    let agreements = dev3.begin_unlock_epochs().unwrap();
    dev3.finish_unlock_epochs(w.host.answer_epochs(&m3, &agreements)).unwrap();
    clean(sync(&mut w, &dev3, &tablet, &m3), "");
    assert_eq!(notes(&dev3), 4);
    owner.refresh(mac.listing()).unwrap();
    let keep = RevokeKeep { mode: KeepMode::Everything, kept: vec![], heads: vec![] };
    let a = owner.begin_revoke(m3.clone(), keep, vec![d.clone()], w.host.fresh(32)).unwrap();
    mac.store(&finish(&owner, &w.host, a).stores);
    dev1.refresh(mac.listing()).unwrap();
    // The revocation made new epochs: the Mac opens its shares of them.
    let agreements = dev1.begin_unlock_epochs().unwrap();
    assert!(!agreements.is_empty(), "the revocation sealed new epochs to the Mac");
    dev1.finish_unlock_epochs(w.host.answer_epochs(&m1, &agreements)).unwrap();
    write_note(&mut w, &dev1, &mac, "n3");
    clean(sync(&mut w, &dev1, &mac, &m1), "");
    w.refused.clear();
    w.unbuilt.clear();
    let f = sync(&mut w, &dev3, &tablet, &m3);
    // Under `members` the home refuses its call with `refused:revoked` (it holds the revocation;
    // the device cannot fetch it); under `public` it fetches the revocation without a call and
    // then builds none (its own check: `refused:revoked`). Any other refusal fails.
    let refused_by_home = f.iter().any(|f| f.kind == ExchangeFaultKind::Unauthorized);
    let refused_by_itself = w.unbuilt.iter().any(|c| c == "refused:revoked");
    assert!(refused_by_home || refused_by_itself, "the revoked device is refused: {} {:?} {:?}", show(&f), w.unbuilt, w.refused);
    if refused_by_home {
        assert!(
            !w.refused.is_empty() && w.refused.iter().all(|c| c == "refused:revoked"),
            "the home refuses it as revoked: {:?}",
            w.refused
        );
    }
    assert!(w.unbuilt.iter().all(|c| c == "refused:revoked"), "{:?}", w.unbuilt);
    if history == "members" {
        assert!(refused_by_home, "the home refuses the revoked device");
    }
    w.unbuilt.clear();
    w.refused.clear();
    let v: Value = serde_json::from_str(&dev3.view_json(NS.into()).unwrap()).unwrap();
    assert!(
        v["reason"] == "revoked" || v["value"]["admitted"].as_array().map(Vec::len) == Some(4),
        "the revoked device reads nothing new: {v}"
    );

    // --- A pending key change proposed on the Mac is shown on the phone and vetoed there.
    let tablet_owner = w.host.identity(41);
    let change = json!({"keyring": {"add": [raw_controller_json(&w.host, &tablet_owner)]}});
    owner.refresh(mac.listing()).unwrap();
    // The Mac's own control key alone proposes (the rule needs one unit here), so the phone's one
    // control key can veto it (a veto has at least the transition's units, §8.7).
    let a = owner.begin_transition(change.to_string(), vec![d.clone()], RuleKind::Control, vec![]).unwrap();
    let wt = finish(&owner, &w.host, a);
    mac.store(&wt.stores);
    clean(sync(&mut w, &dev1, &mac, &m1), "the transition is submitted and receipted");
    let digest = owner.pending().unwrap().first().unwrap().digest.clone();
    let phone_owner = open(&phone, &format!("controller:{d2}"), &account, w.now);
    let slot = phone_owner.slots().unwrap().into_iter().find(|s| s.controllers.len() == 1 && s.controllers[0].id == d2).unwrap();
    let inputs = phone_owner.begin_unlock_slot(slot.index).unwrap();
    phone_owner.finish_unlock_slot(slot.index, w.host.answer_slot(&inputs)).unwrap();
    clean(sync(&mut w, &phone_owner, &phone, &d2), "");
    let shown = phone_owner.pending().unwrap();
    let p = shown.iter().find(|p| p.digest == digest).expect("the phone shows the pending change");
    assert!(p.vetoable, "the phone's control key may veto it");
    let a = phone_owner.begin_veto(digest.clone(), vec![d2.clone()], vec![]).unwrap();
    phone.store(&finish(&phone_owner, &w.host, a).stores);
    let before_veto = w.relays[0].head_seq("/head");
    clean(sync(&mut w, &phone_owner, &phone, &d2), "the veto is submitted");
    // The home records `vetoed` in a scheduler pass (the test runs it); the Mac sees the change is
    // no longer pending.
    assert!(dev1.pending().unwrap().iter().any(|p| p.digest == digest), "pending before the home records the veto");
    let now = w.tick();
    for r in &w.relays {
        r.set_clock(now);
    }
    ticks_until("the veto is recorded at the home", 3, &w.relays, || w.relays[0].head_seq("/head") > before_veto);
    clean(sync(&mut w, &dev1, &mac, &m1), "the veto reaches the Mac");
    assert!(!dev1.pending().unwrap().iter().any(|p| p.digest == digest), "the veto is recorded at the home and reaches the Mac");
}

fn clean(f: Vec<ExchangeFault>, what: &str) {
    assert!(f.is_empty(), "{what}: {}", show(&f));
}

fn show(f: &[ExchangeFault]) -> String {
    f.iter()
        .map(|f| format!("{:?} {} {:?} {:?} {:?} {:?} {:?}", f.kind, f.home, f.status, f.code, f.what, f.why, f.path))
        .collect::<Vec<_>>()
        .join("; ")
}

fn raw_controller_json(host: &Host, id: &str) -> Value {
    let p = host.keys[id].public();
    json!({"key": {"form": "raw", "signing": colophon_core::v05::encoding::encode_base64(&p.signing),
           "agreement": colophon_core::v05::encoding::encode_base64(&p.agreement)},
           "label": "Tablet", "roles": ["approve"]})
}

#[test]
fn two_devices_and_a_home_with_the_history_for_members() {
    journey("members", 1);
}

#[test]
fn two_devices_and_a_home_with_a_public_history() {
    journey("public", 1);
}

#[test]
fn two_devices_and_two_homes_at_quorum_two() {
    journey("members", 2);
}
