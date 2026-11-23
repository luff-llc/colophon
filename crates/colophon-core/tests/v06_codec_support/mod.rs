//! Fixtures for the session codec tests: fixed member keys, an account view, epoch keys,
//! endpoints with host-signed delegations, and JSON surgery on sealed frames.
#![allow(clippy::unwrap_used, dead_code)]
use colophon_core::v05::encoding::{canonical, parse_date};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::terms::Access;
use colophon_core::v06::session::codec::{CellId, EpochTable, Sender};
use colophon_core::v06::session::endpoint::{Clock, Endpoint};
use colophon_core::v06::session::keys::{SessionAccount, SessionKey};
use colophon_core::v06::session::{Bytes, Claim, Id, Policy};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::Value;

pub const ACCOUNT: &str = "c143841cdecb774fa67497a18481d8d0ad76edc8e32490cf7d3377ad59ada5d5";
pub const OTHER_ACCOUNT: &str = "0000000000000000000000000000000000000000000000000000000000000001";
pub const NS: &str = "listening.podcasts";
pub const CELL: &str = "now-playing";
pub const EPOCH_KEY: [u8; 32] = [0x42; 32];

/// 2026-11-22T10:00:00Z.
pub fn t0() -> i64 {
    parse_date("2026-11-22T10:00:00Z").unwrap()
}
pub fn clock(mono_ms: u64) -> Clock {
    Clock {
        mono_ms,
        wall_ms: t0() + mono_ms as i64,
    }
}
pub fn cell() -> CellId {
    CellId::new(ACCOUNT, NS, CELL)
}
pub fn epochs() -> EpochTable {
    EpochTable::new().with(NS, 1, EPOCH_KEY)
}

/// A member: a software member key (the host's), its point and ID.
pub struct Member {
    pub key: SigningKey,
    pub point: Vec<u8>,
    pub id: String,
}
pub fn member(seed: u8) -> Member {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let id = key_id(&point);
    Member { key, point, id }
}
/// The host's raw ES256 signature with a member key.
pub fn host_sign(m: &Member, body: &[u8]) -> Vec<u8> {
    let s: Signature = m.key.sign(body);
    s.to_bytes().to_vec()
}

/// Members a, b, c write; r reads; x has another namespace only.
pub struct World {
    pub a: Member,
    pub b: Member,
    pub c: Member,
    pub r: Member,
    pub x: Member,
}
pub fn world() -> World {
    World {
        a: member(1),
        b: member(2),
        c: member(3),
        r: member(4),
        x: member(5),
    }
}
impl World {
    pub fn view(&self) -> SessionAccount {
        SessionAccount::new(ACCOUNT)
            .with_member(&self.a.point, 0, None, &[(NS, Access::Write)])
            .with_member(&self.b.point, 0, None, &[(NS, Access::Write)])
            .with_member(&self.c.point, 0, None, &[(NS, Access::Write)])
            .with_member(&self.r.point, 0, None, &[(NS, Access::Read)])
            .with_member(&self.x.point, 0, None, &[("notes", Access::Write)])
    }
}

/// A sender for `m` with a session key from `random` and a delegation valid from t0 for a day.
pub fn sender(m: &Member, view: &SessionAccount, random: u8, cell: CellId) -> Sender {
    let key = SessionKey::generate(&mut [random; 32]).unwrap();
    let mut s = Sender::new(cell, &m.id, key);
    let session = view.member(&m.id).map(|x| x.session).unwrap_or(0);
    let body = s.delegation_body(session, t0(), t0() + 86_400_000).unwrap();
    s.install(&body, &host_sign(m, &body), view, t0()).unwrap();
    s
}

/// An endpoint for `m` with its delegation installed.
pub fn endpoint(m: &Member, view: &SessionAccount, random: u8, policy: Policy) -> Endpoint {
    endpoint_window(m, view, random, policy, t0(), t0() + 86_400_000)
}
pub fn endpoint_window(
    m: &Member,
    view: &SessionAccount,
    random: u8,
    policy: Policy,
    not_before: i64,
    expires: i64,
) -> Endpoint {
    let mut e = Endpoint::new(
        cell(),
        &m.id,
        policy,
        None,
        view.clone(),
        &mut [random; 32],
        [random ^ 0x5a; 16],
        clock(0),
    )
    .unwrap();
    let body = e.begin_delegation(not_before, expires).unwrap();
    e.finish_delegation(&body, &host_sign(m, &body), clock(0)).unwrap();
    e
}

/// Parse sealed bytes as JSON.
pub fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
/// Re-encode JSON canonically.
pub fn enc(v: &Value) -> Vec<u8> {
    canonical(v).unwrap()
}
/// Modify a frame's JSON and re-encode it canonically.
pub fn edit(bytes: &[u8], f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Vec<u8> {
    let mut v = json(bytes);
    f(v.as_object_mut().unwrap());
    enc(&v)
}
/// Flip one bit of a base64 field.
pub fn flip_b64(v: &mut Value, at: usize) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut b = STANDARD.decode(v.as_str().unwrap()).unwrap();
    let i = at % b.len();
    b[i] ^= 1;
    *v = Value::String(STANDARD.encode(b));
}

pub fn claim(term: u64, holder: &Member) -> Claim {
    Claim::new(term, 0, &holder.id)
}
pub fn bytes(s: &str) -> Bytes {
    Bytes(s.as_bytes().to_vec())
}
pub fn id(label: &str) -> Id {
    Id::from_label(label)
}

/// A small deterministic PRNG (xorshift64*), so tests need no dependency.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}
