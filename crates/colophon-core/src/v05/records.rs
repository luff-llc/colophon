//! `/5` operation headers (§11.2), operation IDs and opening (§11.3), and the admission steps
//! of §11.5 that are decidable from a given record view.
//!
//! Not here: epoch keys and their introduction (`rekey`, shares, vault rotation), the
//! revocation walk itself (§9.5; its outcome is an input), proposals (§11.6), folding and live
//! state (§11.8), and the upgraded-account `/3` fence (§11.5 last paragraph, needs §16.1).
use super::encoding::{bounds, canonical, is_lower_hex, Obj};
use super::ids::{is_key_id, AccountId};
use super::signature::RawEnvelope;
use super::terms::{valid_namespace, Access};
use super::{bad_signature, malformed, require, Reason, Result, Unknown};
use serde_json::{json, Value};

/// `level` of a header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// A write.
    Write,
    /// A proposal.
    Propose,
}
/// A live stamp (§11.2, §11.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveStamp {
    /// The account (64 hex).
    pub account: String,
    /// Slot name.
    pub slot: String,
    /// Generation (namespace clock).
    pub generation: u64,
    /// Operation ID.
    pub operation_id: String,
}
/// A parsed and signature-checked `/5` operation header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationHeader {
    /// Exact body bytes.
    pub body: Vec<u8>,
    /// Account.
    pub account: AccountId,
    /// Namespace.
    pub namespace: String,
    /// Author member ID.
    pub author: String,
    /// Epoch.
    pub epoch: u64,
    /// Operation ID (32 hex).
    pub id: String,
    /// Clock, 1 to 2^53 − 1.
    pub clock: u64,
    /// Cited authority seq.
    pub authority: u64,
    /// `created`, spelling and ms.
    pub created: (String, i64),
    /// Level.
    pub level: Level,
    /// Previous header digest in this author's chain.
    pub previous: Option<String>,
    /// 12-byte nonce.
    pub nonce: Vec<u8>,
    /// Ciphertext including the 16-byte tag.
    pub ciphertext: Vec<u8>,
    /// Live stamp.
    pub live: Option<LiveStamp>,
    /// Unknown content in the header.
    pub unknown: Unknown,
}

fn invalid_payload(_why: &str) -> super::Failure {
    super::Failure::Refused(Reason::InvalidPayload)
}

/// The storage path of a header (§11.2).
pub fn operation_path(author: &str, namespace: &str, clock: u64, id: &str) -> String {
    format!("ops/{author}/{namespace}/{clock:012}-{id}.json")
}

impl OperationHeader {
    /// Parse a header envelope and check its shape. The signature is checked by
    /// [`OperationHeader::verify`] once the author's key is known.
    pub fn parse(envelope: &[u8]) -> Result<(Self, RawEnvelope)> {
        let mut sink = Unknown::default();
        let unknown = &mut sink;
        let env = RawEnvelope::parse(envelope, bounds::OPERATION_HEADER_BODY, false)?;
        let mut o = Obj::new(env.value.clone(), "header")?;
        require(
            o.string("protocol")? == "colophon/operation/5",
            "not a colophon/operation/5 header",
        )?;
        let account = AccountId::parse(&o.string("account")?)?;
        let namespace = o.string("namespace")?;
        require(valid_namespace(&namespace), "invalid namespace")?;
        let author = o.key_id("author")?;
        let epoch = o.uint("epoch")?;
        require(epoch >= 1, "epoch starts at 1")?;
        let id = o.key_id("id")?;
        let clock = o.uint("clock")?;
        require(clock >= 1, "clock must be positive")?;
        let authority = o.uint("authority")?;
        require(authority >= 1, "authority must cite a seq")?;
        let created = o.date("created")?;
        let level = match o.string("level")?.as_str() {
            "write" => Level::Write,
            "propose" => Level::Propose,
            _ => return Err(malformed("level must be write or propose")),
        };
        let previous = match o.value("previous")? {
            Value::Null => None,
            Value::String(s) if super::encoding::is_digest(&s) => Some(s),
            _ => return Err(malformed("previous must be a digest or null")),
        };
        let nonce = o.bytes("nonce", 12)?;
        require(nonce.len() == 12, "nonce must be 12 bytes")?;
        let ciphertext = o.bytes("ciphertext", bounds::OPERATION_HEADER_BODY)?;
        require(ciphertext.len() >= 16, "ciphertext shorter than its tag")?;
        let live = match o.opt_obj("live")? {
            None => None,
            Some(mut l) => {
                let account = l.string("account")?;
                require(is_lower_hex(&account, 64), "live.account must be 64 hex")?;
                let slot = l.string("slot")?;
                require(!slot.is_empty(), "live.slot must not be empty")?;
                let generation = l.uint("generation")?;
                let operation_id = l.key_id("operationID")?;
                l.finish(unknown);
                Some(LiveStamp {
                    account,
                    slot,
                    generation,
                    operation_id,
                })
            }
        };
        if live.is_some() {
            require(
                level == Level::Write && previous.is_none(),
                "a live-stamped header has level write and previous null",
            )?;
        }
        o.finish(unknown);
        Ok((
            Self {
                body: env.body.clone(),
                account,
                namespace,
                author,
                epoch,
                id,
                clock,
                authority,
                created,
                level,
                previous,
                nonce,
                ciphertext,
                live,
                unknown: sink,
            },
            env,
        ))
    }
    /// Check that `author` and `namespace` match the storage path, and the clock and ID too.
    pub fn check_path(&self, path: &str) -> Result<()> {
        require(
            path == operation_path(&self.author, &self.namespace, self.clock, &self.id),
            "header does not match its path",
        )
    }
    /// The AES-GCM AAD (§11.2): canonical JSON of the eleven authenticated fields.
    pub fn aad(&self) -> Result<Vec<u8>> {
        canonical(&json!({
            "account": self.account.as_str(),
            "author": self.author,
            "authority": self.authority,
            "clock": self.clock,
            "created": self.created.0,
            "epoch": self.epoch,
            "id": self.id,
            "level": match self.level { Level::Write => "write", Level::Propose => "propose" },
            "namespace": self.namespace,
            "previous": self.previous,
            "protocol": "colophon/operation/5",
        }))
    }
    /// The header body digest (author chains and `kept` use it).
    pub fn digest(&self) -> String {
        super::encoding::digest(&self.body)
    }
    /// Open the ciphertext with the epoch key and check the plaintext against the header and
    /// its content-derived ID (§11.3). Returns the plaintext object.
    pub fn open(&self, epoch_key: &[u8; 32]) -> Result<Value> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let cipher =
            aes_gcm::Aes256Gcm::new_from_slice(epoch_key).map_err(|_| malformed("epoch key"))?;
        let aad = self.aad()?;
        let plain = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| invalid_payload("decryption failed"))?;
        let check = || -> Result<Value> {
            let value = super::encoding::strict_parse(&plain)
                .map_err(|_| invalid_payload("plaintext JSON"))?;
            let mut o = Obj::new(value.clone(), "plaintext")?;
            let id = o.string("id")?;
            let _kind = o.string("kind")?;
            let _v = o.uint("v")?;
            let clock = o.uint("clock")?;
            let authority = o.uint("authority")?;
            let created = o.string("created")?;
            let _payload = o.value("payload")?;
            o.finish_closed()?;
            require(
                id == self.id
                    && clock == self.clock
                    && authority == self.authority
                    && created == self.created.0,
                "plaintext does not match the header",
            )?;
            require(
                operation_id(
                    &self.namespace,
                    &self.author,
                    self.epoch,
                    &self.nonce,
                    &value,
                )? == self.id,
                "operation ID",
            )?;
            Ok(value)
        };
        // Every failure after decryption is `invalidPayload` (0.3 §5, §11.8).
        check().map_err(|_| invalid_payload("plaintext"))
    }
    /// Verify the header's `raw` signature under the author's member key.
    pub fn verify(env: &RawEnvelope, author_signing: &[u8]) -> Result<()> {
        env.verify(author_signing)
            .map_err(|e| bad_signature(e.to_string()))
    }
}

/// The operation ID (§11.3): first 32 hex of SHA-256 of canonical
/// `{"purpose":"colophon/operation-id/3","namespace","author","epoch","nonce","operation"}`,
/// `nonce` as twelve integer octets and `operation` the plaintext with `id` set to `""`.
pub fn operation_id(
    namespace: &str,
    author: &str,
    epoch: u64,
    nonce: &[u8],
    plaintext: &Value,
) -> Result<String> {
    let mut operation = plaintext.clone();
    let map = operation
        .as_object_mut()
        .ok_or_else(|| malformed("plaintext is not an object"))?;
    map.insert("id".into(), Value::String(String::new()));
    let preimage = json!({
        "purpose": "colophon/operation-id/3",
        "namespace": namespace,
        "author": author,
        "epoch": epoch,
        "nonce": nonce,
        "operation": operation,
    });
    Ok(super::encoding::digest(&canonical(&preimage)?)[..32].to_string())
}

/// What the record layer knows about the author when deciding admission (a given view).
#[derive(Clone, Debug)]
pub struct AuthorView {
    /// The member's records access in this namespace at the cited authority (`None`: none).
    pub access: Option<Access>,
    /// The member's latest verified expiry, ms.
    pub expires_ms: Option<i64>,
    /// The seq of the member's revocation, if revoked.
    pub revoked_seq: Option<u64>,
    /// The outcome of the §9.5 walk for this header (kept or not), computed by the caller.
    pub kept: Kept,
    /// The member's remaining `writes` budget (`None`: unbounded).
    pub writes_left: Option<u64>,
    /// The member was added by an activation that isn't final yet: its records are held
    /// `authorityBehind` (§8.7, revision 6).
    pub provisional: bool,
}
/// The revocation walk outcome for one header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    /// In `kept` or reached by the walk.
    Kept,
    /// Not kept.
    NotKept,
    /// The walk could not be completed: a missing intermediate header.
    Incomplete,
}
/// The namespace and replica state admission compares against.
#[derive(Clone, Debug)]
pub struct NamespaceView {
    /// The highest seq of this replica's verified authority.
    pub authority_seq: u64,
    /// The seq of an unresolved fork, if any.
    pub fork_seq: Option<u64>,
    /// The current epoch of the namespace at the cited seq.
    pub epoch_at_cited: u64,
    /// The highest earlier admitted clock in the namespace.
    pub highest_clock: u64,
}
/// An admission decision before opening (§11.5 steps 1–8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Admitted; reserves one budget slot.
    Admitted,
    /// Refused with a reason.
    Refused(Reason),
    /// Held with a reason (`revokedBackdated`, `authorityBehind`, `unavailable`).
    Held(&'static str),
    /// An unknown condition operator decided the after-opening check (§10.4).
    NewerFormat,
}

/// §11.5 after opening: a kind outside the member's `kinds`, or a `conditions` predicate that
/// is false on the payload, is refused `outOfScope` (and still reserves its slot); an unknown
/// operator that decides the result is `newerFormat`.
pub fn admit_opened(
    plaintext: &Value,
    entry: &super::terms::RecordsEntry,
    terms: &super::terms::Terms,
) -> Admission {
    let kind = plaintext
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if entry
        .kinds
        .as_ref()
        .is_some_and(|k| !k.iter().any(|x| x == kind))
    {
        return Admission::Refused(Reason::OutOfScope);
    }
    let payload = plaintext.get("payload").unwrap_or(&Value::Null);
    match terms.conditions_on(payload) {
        super::terms::Truth::True => Admission::Admitted,
        super::terms::Truth::False => Admission::Refused(Reason::OutOfScope),
        super::terms::Truth::Unknown => Admission::NewerFormat,
    }
}

/// §11.5 steps 1–8, in order, after the signature, binding, format and path checks.
pub fn admit(header: &OperationHeader, author: &AuthorView, ns: &NamespaceView) -> Admission {
    let needed = match header.level {
        Level::Write => Access::Write,
        Level::Propose => Access::Propose,
    };
    if author.access.is_none_or(|a| a < needed) {
        return Admission::Refused(Reason::NotGranted);
    }
    if author.expires_ms.is_some_and(|e| header.created.1 > e) {
        return Admission::Refused(Reason::Expired);
    }
    if let Some(revoked) = author.revoked_seq {
        // A record citing the revocation or later is refused whatever the walk says: a kept
        // record citing it is refused too (§9.5), so an incomplete walk can't change that.
        if header.authority >= revoked {
            return Admission::Refused(Reason::Revoked);
        }
        match author.kept {
            Kept::Kept => {}
            Kept::Incomplete => return Admission::Held("unavailable"),
            Kept::NotKept => return Admission::Held("revokedBackdated"),
        }
    }
    if author.provisional
        || header.authority > ns.authority_seq
        || ns.fork_seq.is_some_and(|f| header.authority >= f)
    {
        return Admission::Held("authorityBehind");
    }
    if header.epoch != ns.epoch_at_cited {
        return Admission::Refused(Reason::WrongEpoch);
    }
    if header.clock > ns.highest_clock.saturating_add(1_024) {
        return Admission::Refused(Reason::ClockJump);
    }
    if author.writes_left == Some(0) {
        return Admission::Refused(Reason::BudgetSpent);
    }
    Admission::Admitted
}

/// Helper for callers: true when `s` is a member ID.
pub fn is_member_id(s: &str) -> bool {
    is_key_id(s)
}
