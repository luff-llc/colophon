//! The engine's side of live state (0.3 §5.1 with 0.5 §11.8's substitutions): reading
//! `state/` slots from the source, keeping the high-water witnesses, and writing a stamped
//! `/5` header to its slot with its evidence under `history/` and its predecessor retained
//! under `ops/`. The verdicts themselves are `v05::live`, run by the account over the set of
//! candidates it holds.
//!
//! The write is *prepare, then finish* like every other: [`PendingLive`] has private fields
//! and read-only accessors; [`Engine::finish_live_write`] verifies the exact bytes it returns
//! as a reader would (signature, binding, current authority, key, decrypted slot) before
//! anything is returned or held.
use super::{paths, Engine, Have, RecordSource, MAX_RECORD};
use crate::model::Denial;
use crate::v05::account::Changes;
use crate::v05::encoding::{canonical, encode_base64};
use crate::v05::live::{live_path, LiveVerdict};
use crate::v05::records::{operation_id, HeldRecord, OperationHeader};
use crate::v05::write::{format_date, SignatureResult, SigningStep};
use crate::v05::{malformed, require, Failure, Reason, Result};
use serde_json::{json, Value};

/// A live write prepared for the host to sign. Its fields are private.
#[derive(Debug)]
pub struct PendingLive {
    step: SigningStep,
    body: Vec<u8>,
    state_path: String,
    history_path: String,
    /// The predecessor's retained copy, `(ops path, exact bytes)`, when this write continues a
    /// slot whose head is not yet retained.
    retain: Option<(String, Vec<u8>)>,
    /// The exact bytes now at the state path, which the replacement must name (`If-Match`).
    replaces: Option<(String, [u8; 32])>,
    generation: u64,
}
impl PendingLive {
    /// The one step to sign: the header body, signed raw by the member key.
    pub fn step(&self) -> &SigningStep {
        &self.step
    }
    /// The slot's generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// The slot path.
    pub fn state_path(&self) -> &str {
        &self.state_path
    }
}

/// A finished live write: what to store, in this order.
#[derive(Clone, Debug)]
pub struct LiveWritten {
    /// `(path, bytes)`: the retained predecessor under `ops/` if any, then the evidence under
    /// `history/`, then the slot.
    pub stores: Vec<(String, Vec<u8>)>,
    /// The slot's previous bytes the replacement is conditional on: `(path, sha256 hex)`. The
    /// relay's `If-Match` names it (0.3 §8.2).
    pub replaces: Option<(String, String)>,
    /// What the write changed.
    pub changes: Changes,
}

fn unsigned_envelope(body: &[u8]) -> Result<Vec<u8>> {
    canonical(&json!({"body": encode_base64(body), "signature": encode_base64(&[0u8; 64])}))
}

impl<S: RecordSource> Engine<S> {
    /// Read live candidates, hold them with the account, and keep the witnesses. A candidate
    /// below its slot's witness is stale: it is not held and is reported
    /// ([`Engine::stale_live`]).
    pub(super) fn ingest_live(&mut self, wanted: Vec<String>) -> Result<Changes> {
        let mut cands: Vec<HeldRecord> = Vec::new();
        for p in wanted {
            let Ok(bytes) = super::read_source(&self.source, &mut self.stats, &p, MAX_RECORD)
            else {
                continue;
            };
            let version = self.source.content_version(&p).unwrap_or(None);
            self.ix.unread.remove(&p);
            if let Ok((h, _)) = OperationHeader::parse(&bytes) {
                if let Some((g, d)) = self.live_witness.get(&p) {
                    // Below the witness, or the same generation with another body (author
                    // equivocation, or a swap): fails closed.
                    if h.clock < *g || (h.clock == *g && h.digest() != *d) {
                        self.stale_live.push((p.clone(), h.clock));
                        continue;
                    }
                }
            }
            self.ix.live_have.insert(
                p.clone(),
                Have {
                    sha: super::sha(&bytes),
                    version,
                },
            );
            cands.push(HeldRecord { path: p, bytes });
        }
        if cands.is_empty() {
            return Ok(Changes::default());
        }
        let now = self.account.now_ms();
        let c = self.account.merge_live(cands, now)?;
        // The witnesses move only on what the verifier accepted as a current head.
        for h in self.account.live_heads() {
            let w = self.live_witness.entry(h.path.clone()).or_default();
            if h.generation > w.0 {
                *w = (h.generation, h.digest.clone());
            }
        }
        Ok(c)
    }

    /// Live candidates refused for being below their slot's witness, `(path, generation)`:
    /// the source served an older state than this device saw (a rollback or a stale copy).
    pub fn stale_live(&self) -> &[(String, u64)] {
        &self.stale_live
    }

    /// The verdict on each live candidate held.
    pub fn live_verdicts(&self) -> &[(String, LiveVerdict)] {
        self.account.live_verdicts()
    }

    /// Hold live candidates the host fetched itself (a relay answer), without the source.
    pub fn apply_live(&mut self, candidates: Vec<HeldRecord>) -> Result<Changes> {
        self.check_ready()?;
        let mut cands = Vec::new();
        for c in candidates {
            require(
                super::paths::classify(&c.path)
                    .is_some_and(|k| matches!(k, paths::Kind::Live { .. }))
                    && c.bytes.len() <= MAX_RECORD,
                "not a live slot path",
            )?;
            if let Ok((h, _)) = OperationHeader::parse(&c.bytes) {
                if self
                    .live_witness
                    .get(&c.path)
                    .is_some_and(|(g, d)| h.clock < *g || (h.clock == *g && h.digest() != *d))
                {
                    self.stale_live.push((c.path.clone(), h.clock));
                    continue;
                }
            }
            self.ix.live_have.insert(
                c.path.clone(),
                Have {
                    sha: super::sha(&c.bytes),
                    version: None,
                },
            );
            cands.push(c);
        }
        let now = self.account.now_ms();
        let ch = self.account.merge_live(cands, now)?;
        for h in self.account.live_heads() {
            let w = self.live_witness.entry(h.path.clone()).or_default();
            if h.generation > w.0 {
                *w = (h.generation, h.digest.clone());
            }
        }
        Ok(ch)
    }

    /// Prepare a live write: a passive `listening.podcasts` `position` sample from an
    /// uncaveated writer (0.3 §5.1). Anything else is refused here, before a host is asked to
    /// sign: a deliberate seek, completion, queue edit or recovery stays on the immutable path
    /// (`begin_write`), a caveated writer may not publish live state, and a sample that would
    /// pass the 1,024 bound must be an immutable anchor.
    pub fn begin_live_write(
        &self,
        namespace: &str,
        kind: &str,
        payload: Value,
        seed: [u8; 32],
    ) -> Result<std::result::Result<PendingLive, Denial>> {
        self.check_ready()?;
        let crate::v05::account::Standing::Member(me) = self.account.me() else {
            return Err(malformed("this session is not a member"));
        };
        if let Some(d) = self.account.write_denial(namespace) {
            return Ok(Err(d));
        }
        let slot = crate::protocol::live_slot(namespace, kind, &payload).ok_or_else(|| {
            malformed(
                "not live state: only a passive position sample without a seek may be replaceable",
            )
        })?;
        require(payload.is_object(), "operation payload must be an object")?;
        if let Some(module) = crate::domain::module(namespace) {
            if let Some(spec) = module.operations().iter().find(|s| s.name == kind) {
                require(
                    crate::domain::validate_input(&spec.input_schema, &payload),
                    "the payload does not match the operation schema",
                )?;
            }
        }
        let author = me.member.id.clone();
        let auth = self.account.record_authority();
        auth.require_clean()?;
        let account = auth.account().clone();
        let authority = auth.authority_seq();
        let epoch = auth
            .epoch_at(namespace, authority)
            .ok_or_else(|| malformed("the namespace has no epoch yet"))?;
        let Some(key) = self.account.epoch_keys().get(&account, namespace, epoch) else {
            return Ok(Err(Denial {
                reason: "unavailable".into(),
                detail: "Unlock the namespace epoch before writing".into(),
            }));
        };
        // The generation: one past the highest admitted durable clock and past this slot's
        // current head; live heads never advance the durable clock (0.3 §5.1).
        let durable = self.account.highest_admitted_clock(namespace);
        let prior = self
            .account
            .live_heads()
            .iter()
            .find(|h| h.author == author && h.namespace == namespace && h.slot == slot);
        let generation = durable
            .max(prior.map_or(0, |h| h.generation))
            .max(
                self.account
                    .live_generation_floor(&author, namespace, &slot),
            )
            .checked_add(1)
            .ok_or_else(|| malformed("clock overflow"))?;
        require(
            generation <= crate::v05::encoding::bounds::MAX_INTEGER
                && generation <= durable.saturating_add(1_024),
            "this sample passes the 1,024 clock bound: publish it as an immutable operation",
        )?;
        // The nonce must be new under this epoch key: against this member's own headers and
        // live heads (a host that reuses a seed would otherwise reuse a nonce).
        let nonce = crate::crypto::Entropy::new(seed)
            .take::<12>()
            .map_err(|e| malformed(e.to_string()))?;
        let own_prefix = format!("ops/{author}/{namespace}/");
        let reused = self
            .account
            .records()
            .iter()
            .filter(|r| r.path.starts_with(&own_prefix))
            .filter_map(|r| OperationHeader::parse(&r.bytes).ok())
            .map(|(h, _)| h)
            .chain(
                self.account
                    .live_heads()
                    .iter()
                    .filter_map(|h| OperationHeader::parse(&h.bytes).ok().map(|x| x.0)),
            )
            .any(|h| h.epoch == epoch && h.nonce == nonce);
        require(
            !reused,
            "that nonce is already used under this epoch key: pass a fresh seed",
        )?;
        let created = format_date(self.account.now_ms());
        let mut plain = json!({
            "id": "", "kind": kind, "v": 1, "clock": generation,
            "authority": authority, "created": created, "payload": payload,
        });
        let id = operation_id(namespace, &author, epoch, &nonce, &plain)?;
        plain["id"] = json!(id);
        let sketch = OperationHeader {
            body: Vec::new(),
            account: account.clone(),
            namespace: namespace.to_string(),
            author: author.clone(),
            epoch,
            id: id.clone(),
            clock: generation,
            authority,
            created: (created.clone(), self.account.now_ms()),
            level: crate::v05::records::Level::Write,
            previous: None,
            nonce: nonce.to_vec(),
            ciphertext: Vec::new(),
            live: None,
            unknown: Default::default(),
        };
        let ciphertext =
            crate::crypto::seal(key.expose(), &nonce, &canonical(&plain)?, &sketch.aad()?)
                .map_err(|e| malformed(e.to_string()))?;
        let body = canonical(&json!({
            "protocol": "colophon/operation/5",
            "account": account.as_str(),
            "namespace": namespace,
            "author": author,
            "epoch": epoch,
            "id": id,
            "clock": generation,
            "authority": authority,
            "created": created,
            "level": "write",
            "previous": Value::Null,
            "nonce": encode_base64(&nonce),
            "ciphertext": encode_base64(&ciphertext),
            "live": {"account": account.as_str(), "slot": slot, "generation": generation, "operationID": id},
        }))?;
        require(
            body.len() <= crate::v05::encoding::bounds::OPERATION_HEADER_BODY,
            "operation header exceeds its bound",
        )?;
        let state_path = live_path(&author, namespace, &slot);
        let member = auth
            .member(&author)
            .ok_or(Failure::Refused(Reason::NotGranted))?;
        // Judge the unsigned header exactly as a reader will judge the signed one.
        let verdict = self.account.preview_live(
            HeldRecord {
                path: state_path.clone(),
                bytes: unsigned_envelope(&body)?,
            },
            true,
        )?;
        match verdict {
            LiveVerdict::Current => {}
            LiveVerdict::Refused(r) => {
                return Ok(Err(Denial {
                    reason: r.into(),
                    detail: "a reader would refuse this live write".into(),
                }))
            }
            other => {
                return Err(malformed(format!(
                    "a reader would not take this live write: {other:?}"
                )))
            }
        }
        // Retain the exact signed predecessor at its immutable path first (0.3 §5.1): fetched
        // from the store and matched to the verified digest, never rebuilt.
        let mut retain = None;
        let mut replaces = None;
        // Only a sample that cites the previous revision (`expect`) relies on it, so only
        // that one retains it; a passive sample replaces it.
        let relies = payload.get("expect").is_some_and(|v| !v.is_null());
        if let Some(p) = prior {
            let (ph, _) = OperationHeader::parse(&p.bytes)?;
            let ops = crate::v05::records::operation_path(&p.author, &p.namespace, ph.clock, &p.id);
            if relies
                && !self.ix.have.contains_key(&ops)
                && !self.account.records().iter().any(|r| r.path == ops)
            {
                let fetched = self
                    .source
                    .read(&p.path)
                    .map_err(|e| Failure::Unavailable(format!("{}: {}", p.path, e.0)))?;
                require(
                    super::sha(&fetched) == super::sha(&p.bytes),
                    "the predecessor's stored bytes are not the verified head: fail the write",
                )?;
                retain = Some((ops, fetched));
            }
            replaces = Some((p.path.clone(), super::sha(&p.bytes)));
        }
        let step = SigningStep::for_call(
            state_path.clone(),
            body.clone(),
            author.clone(),
            member.request.signing.clone(),
            None,
        );
        Ok(Ok(PendingLive {
            step,
            body,
            history_path: format!("history/{author}/{namespace}/{generation:012}-{id}.json"),
            state_path,
            retain,
            replaces,
            generation,
        }))
    }

    /// Finish a live write: assemble the envelope, judge it as a reader would, and only then
    /// hold it and return the bytes.
    pub fn finish_live_write(
        &mut self,
        pending: PendingLive,
        signature: SignatureResult,
    ) -> Result<LiveWritten> {
        self.check_ready()?;
        require(
            signature.assertion.is_none() && signature.signature.len() == 64,
            "a live header is signed raw",
        )?;
        let envelope = canonical(
            &json!({"body": encode_base64(&pending.body), "signature": encode_base64(&signature.signature)}),
        )?;
        let cand = HeldRecord {
            path: pending.state_path.clone(),
            bytes: envelope.clone(),
        };
        match self.account.preview_live(cand.clone(), false)? {
            LiveVerdict::Current => {}
            other => {
                return Err(malformed(format!(
                    "the signed live header is not a current head: {other:?}"
                )))
            }
        }
        let mut total = Changes::default();
        let mut stores = Vec::new();
        let now = self.account.now_ms();
        if let Some((ops, bytes)) = pending.retain {
            let c = self.account.merge(
                crate::v05::account::Incoming {
                    objects: Default::default(),
                    records: vec![HeldRecord {
                        path: ops.clone(),
                        bytes: bytes.clone(),
                    }],
                },
                now,
            )?;
            super::absorb(&mut total, c);
            self.ix.have.insert(
                ops.clone(),
                Have {
                    sha: super::sha(&bytes),
                    version: None,
                },
            );
            stores.push((ops, bytes));
        }
        let c = self.account.merge_live(vec![cand], now)?;
        super::absorb(&mut total, c);
        for h in self.account.live_heads() {
            let w = self.live_witness.entry(h.path.clone()).or_default();
            if h.generation > w.0 {
                *w = (h.generation, h.digest.clone());
            }
        }
        self.ix.live_have.insert(
            pending.state_path.clone(),
            Have {
                sha: super::sha(&envelope),
                version: None,
            },
        );
        stores.push((pending.history_path, envelope.clone()));
        stores.push((pending.state_path, envelope));
        Ok(LiveWritten {
            stores,
            replaces: pending.replaces.map(|(p, d)| (p, super::hex(&d))),
            changes: total,
        })
    }
}
