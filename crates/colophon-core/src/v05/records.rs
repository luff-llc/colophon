//! `/5` operation headers (§11.2), operation IDs and opening (§11.3), and the admission steps
//! of §11.5, with the record-layer view of a verified authority history.
//!
//! **What is here.**
//!
//! * [`OperationHeader`], [`operation_id`] and [`admit`] / [`admit_opened`]: one header against
//!   a given author view and namespace view (the earlier, caller-fed form).
//! * [`RecordAuthority`]: the record-layer view **derived from the verifier's own verdict**
//!   (`verify_history`): members and their terms, expiry and revocation, the epoch current at
//!   each authority seq, the revocation `kept`/`heads` fields, the seals each epoch object
//!   carries, the upgrade fence. Nothing in it is caller-supplied.
//! * [`judge_records`]: end-to-end admission of a held set of headers, `/5` and the legacy `/3`
//!   headers of an in-place upgraded account (§11.5 last paragraph, §16.1), in fold order, with
//!   the §9.5 revocation walk, the §11.4 clock bound, the §11.5 budget, opening with the epoch
//!   keys held, and the §11.6 proposal fold.
//! * [`EpochKey`]: an opaque epoch key, bound to its account, namespace and epoch.
//!
//! **The epoch key guarantee, and the trust boundary, exactly.** An [`EpochKey`] has private
//! fields, no accessor visible outside this crate, no `Serialize`, a redacted `Debug` and no
//! `Display`; it erases its bytes on drop (best effort: ordinary writes, `black_box`). What the
//! core guarantees:
//!
//! * it never returns epoch key bytes through its interface;
//! * a new epoch is sealed only to the recipients the verified state names (§7.1);
//! * a handle opens only headers of its own account, namespace and epoch.
//!
//! What it does **not** guarantee, by design: a grant's `shares` are part of the body the
//! controller signs, so they must be sealed before signing and the core cannot hold them back
//! until after. **Holding [`EpochKeys`] handles is therefore as trusted as holding the keys:** a
//! host that holds them can have them sealed to a member it is preparing to admit (through
//! `prepare_grant`) and read the raw key from that seal with the member's own agreement key.
//! The host is likewise trusted with the seed it supplies for a new epoch (it can recompute the
//! key from it), and with the ECDH results and vault seed it passes in. Do not hand handles to
//! code the host does not trust as much as the keys.
//!
//! A member that was provisional (§8.7) or expired when an epoch was made is not sealed to it;
//! it gets its shares by a `renew` once it is current ([`RecordAuthority::owed_shares`] lists
//! who is owed what).
//!
//! Not here: folding and live state (§11.8, §6: the domain modules), and the
//! caveated-live-writer rule of 0.3 §5 (§11.8 incorporates it; the §19 results have no code for
//! it, see the E4 report).
use super::encoding::{bounds, canonical, is_lower_hex, Obj};
use super::history::envelope::AuthEnvelope;
use super::history::{verify_history, MemberRecord, Objects, Persisted, State, Stop};
use super::ids::{is_key_id, AccountId};
use super::signature::RawEnvelope;
use super::terms::{valid_namespace, Access};
use super::vault::{EcdhOutput, SealedBox, VaultPublic, VaultSeed};
use super::{bad_signature, malformed, require, Failure, Reason, Result, Unknown};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

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
        open_plaintext(
            epoch_key,
            &self.aad()?,
            &Sealed {
                namespace: &self.namespace,
                author: &self.author,
                epoch: self.epoch,
                id: &self.id,
                clock: self.clock,
                authority: self.authority,
                created: &self.created.0,
                nonce: &self.nonce,
                ciphertext: &self.ciphertext,
            },
        )
    }
    /// Verify the header's `raw` signature under the author's member key.
    pub fn verify(env: &RawEnvelope, author_signing: &[u8]) -> Result<()> {
        env.verify(author_signing)
            .map_err(|e| bad_signature(e.to_string()))
    }
}

/// The fields of a header that opening a ciphertext needs, `/5` or `/3` alike.
struct Sealed<'a> {
    namespace: &'a str,
    author: &'a str,
    epoch: u64,
    id: &'a str,
    clock: u64,
    authority: u64,
    created: &'a str,
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}
/// AES-256-GCM open with `aad`, then the §11.3 checks: the plaintext is canonical-parseable
/// JSON with exactly the seven fields, its ID, clock, authority and date match the header, and
/// its content-derived ID verifies. Every failure after decryption is `invalidPayload`.
fn open_plaintext(epoch_key: &[u8; 32], aad: &[u8], h: &Sealed<'_>) -> Result<Value> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let cipher =
        aes_gcm::Aes256Gcm::new_from_slice(epoch_key).map_err(|_| malformed("epoch key"))?;
    if h.nonce.len() != 12 {
        return Err(invalid_payload("nonce length"));
    }
    let plain = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(h.nonce),
            Payload {
                msg: h.ciphertext,
                aad,
            },
        )
        .map_err(|_| invalid_payload("decryption failed"))?;
    let check = || -> Result<Value> {
        let value =
            super::encoding::strict_parse(&plain).map_err(|_| invalid_payload("plaintext JSON"))?;
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
            id == h.id && clock == h.clock && authority == h.authority && created == h.created,
            "plaintext does not match the header",
        )?;
        require(
            operation_id(h.namespace, h.author, h.epoch, h.nonce, &value)? == h.id,
            "operation ID",
        )?;
        Ok(value)
    };
    check().map_err(|_| invalid_payload("plaintext"))
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

// ---------------------------------------------------------------------------------------------
// Epoch keys.

/// The HPKE `info` and AAD of an epoch seal (§11.1):
/// `colophon/epoch/3\n<libraryID>\n<namespace>\n<epoch>\n<recipientID>`, `<libraryID>` the
/// first 32 characters of the account ID.
pub fn epoch_info(account: &AccountId, namespace: &str, epoch: u64, recipient: &str) -> Vec<u8> {
    format!(
        "colophon/epoch/3\n{}\n{namespace}\n{epoch}\n{recipient}",
        account.legacy_library_id()
    )
    .into_bytes()
}

fn erase(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(&*bytes);
}

/// A namespace epoch key (§11.1) bound to the account, namespace and epoch it was made or
/// opened for. See the file header for exactly what is guaranteed.
///
/// ```compile_fail
/// fn read(k: &colophon_core::v05::records::EpochKey) -> [u8; 32] {
///     k.key // the field is private
/// }
/// ```
pub struct EpochKey {
    account: AccountId,
    namespace: String,
    epoch: u64,
    key: [u8; 32],
}
impl EpochKey {
    /// Wrap key bytes the core made or opened. Crate-internal.
    pub(crate) fn from_secret(
        account: &AccountId,
        namespace: &str,
        epoch: u64,
        key: [u8; 32],
    ) -> Self {
        Self {
            account: account.clone(),
            namespace: namespace.to_string(),
            epoch,
            key,
        }
    }
    /// The key bytes, for the functions of this crate that seal or encrypt with them. Not
    /// visible to a caller of the library.
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.key
    }
    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    /// The namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    /// The epoch number.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    fn binds(&self, account: &AccountId, namespace: &str, epoch: u64) -> bool {
        &self.account == account && self.namespace == namespace && self.epoch == epoch
    }
    /// Open a `/5` header with this key (§11.3). A header of another account, namespace or
    /// epoch is refused before any decryption.
    pub fn open(&self, header: &OperationHeader) -> Result<Value> {
        require(
            self.binds(&header.account, &header.namespace, header.epoch),
            "the key is for another account, namespace or epoch",
        )?;
        header.open(&self.key)
    }
}
impl Clone for EpochKey {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            namespace: self.namespace.clone(),
            epoch: self.epoch,
            key: self.key,
        }
    }
}
impl Drop for EpochKey {
    fn drop(&mut self) {
        erase(&mut self.key);
    }
}
impl std::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpochKey({}/{}, ..)", self.namespace, self.epoch)
    }
}

/// The epoch keys one holder has, by `(namespace, epoch)`, for one account. The first key
/// inserted fixes the account; a key bound to another account is refused, never substituted.
#[derive(Debug, Default)]
pub struct EpochKeys {
    account: Option<AccountId>,
    keys: BTreeMap<(String, u64), EpochKey>,
}
impl EpochKeys {
    /// No keys.
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a key (replacing an equal `(namespace, epoch)` of the same account). A key of
    /// another account than the keys already held is `malformed`.
    pub fn insert(&mut self, key: EpochKey) -> Result<()> {
        match &self.account {
            Some(a) => require(a == &key.account, "a key of another account")?,
            None => self.account = Some(key.account.clone()),
        }
        self.keys.insert((key.namespace.clone(), key.epoch), key);
        Ok(())
    }
    /// The key for `(namespace, epoch)` of `account`, if held.
    pub fn get(&self, account: &AccountId, namespace: &str, epoch: u64) -> Option<&EpochKey> {
        self.keys
            .get(&(namespace.to_string(), epoch))
            .filter(|k| k.binds(account, namespace, epoch))
    }
    /// How many keys are held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    /// True when none is held.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ---------------------------------------------------------------------------------------------
// The record-layer view of a verified authority history.

/// A recipient the verified state names for a new epoch (§7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// The recipient ID: a member ID, or the vault ID (the key ID of the vault's signing point).
    pub id: String,
    /// The agreement point sealed to.
    pub agreement: Vec<u8>,
    /// True for the vault.
    pub vault: bool,
}
/// One epoch a member is owed a share of (see [`RecordAuthority::owed_shares`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedShare {
    /// The member ID.
    pub member: String,
    /// The namespace.
    pub namespace: String,
    /// The epoch.
    pub epoch: u64,
    /// The member is provisional (its activation is not final yet).
    pub provisional: bool,
}
/// What an ECDH needs to open an epoch seal: the peer point to agree with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealRequest {
    /// The seal's ephemeral point: the peer for the host's ECDH with the recipient's key.
    pub enc: Vec<u8>,
    /// The recipient's agreement point.
    pub recipient: Vec<u8>,
}
#[derive(Clone, Debug)]
struct RevokeInfo {
    kept: BTreeSet<String>,
    heads: Vec<(String, String)>,
}

/// The record layer's view of an account, derived from the verifier's verdict over the held
/// authority objects. It holds the folded state, the verified branch's epoch introductions and
/// seals, and each revocation's `kept` and `heads`.
#[derive(Clone, Debug)]
pub struct RecordAuthority {
    state: State,
    authority_seq: u64,
    fork_seq: Option<u64>,
    stop: Option<Stop>,
    namespaces: Vec<String>,
    introductions: Vec<(u64, String, u64)>,
    sealed: BTreeMap<(String, u64), BTreeMap<String, SealedBox>>,
    revokes: BTreeMap<String, RevokeInfo>,
}

fn entry_value(bytes: &[u8]) -> Option<(String, Value)> {
    if let Ok(env) = AuthEnvelope::parse(
        bytes,
        bounds::AUTHORITY_BODY,
        bounds::AUTHORITY_BODY.saturating_mul(2),
        false,
    ) {
        return Some((env.digest.clone(), env.value));
    }
    // The 0.4 prefix of an upgraded account.
    let env = crate::keys::AuthorityEnvelope::from_json(bytes).ok()?;
    let value = env.body_value().ok()?;
    Some((super::encoding::digest(&env.body), value))
}

impl RecordAuthority {
    /// Run the history verifier over `objects` at `now_ms` and take the record-layer view of
    /// its verdict. A history that failed outright is refused with its failure. A held entry
    /// or an unresolved fork leaves the verified prefix (the fork seq is kept: §11.5 step 4).
    pub fn from_objects(objects: &Objects, now_ms: i64) -> Result<Self> {
        let verdict = verify_history(objects, &Persisted::default(), now_ms);
        if let Some(Stop::Failed { failure, .. }) = &verdict.stop {
            return Err(failure.clone());
        }
        Self::from_verdict(objects, verdict)
    }
    /// The record-layer view of a verdict the caller already holds, over the same `objects`
    /// the verdict was made from (the account layer's, which resumes from persisted state).
    /// A verdict that holds no genesis is refused. One that stopped with a failure after its
    /// genesis gives the view of the verified prefix, which reads but never writes:
    /// [`RecordAuthority::require_clean`] returns the failure.
    pub(crate) fn from_verdict(objects: &Objects, verdict: super::history::Verdict) -> Result<Self> {
        let state = verdict
            .state
            .clone()
            .ok_or_else(|| malformed("the held objects hold no genesis"))?;
        let fork_seq = match &verdict.stop {
            Some(Stop::Fork { seq }) => Some(*seq),
            _ => None,
        };
        let seq_of: BTreeMap<&str, u64> = verdict
            .branch
            .iter()
            .enumerate()
            .map(|(i, d)| (d.as_str(), i as u64 + 1))
            .collect();
        let mut by_seq: BTreeMap<u64, Value> = BTreeMap::new();
        for bytes in &objects.entries {
            if let Some((digest, value)) = entry_value(bytes) {
                if let Some(seq) = seq_of.get(digest.as_str()) {
                    by_seq.insert(*seq, value);
                }
            }
        }
        let mut namespaces = Vec::new();
        let mut introductions = Vec::new();
        let mut sealed: BTreeMap<(String, u64), BTreeMap<String, SealedBox>> = BTreeMap::new();
        let mut revokes = BTreeMap::new();
        for (seq, v) in &by_seq {
            if *seq == 1 {
                namespaces = v
                    .get("namespaces")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|n| n.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            for (field, introduces) in [("epochs", true), ("shares", false)] {
                let Some(items) = v.get(field).and_then(Value::as_array) else {
                    continue;
                };
                for item in items {
                    let (Some(ns), Some(epoch)) = (
                        item.get("namespace").and_then(Value::as_str),
                        item.get("epoch").and_then(Value::as_u64),
                    ) else {
                        continue;
                    };
                    if introduces {
                        introductions.push((*seq, ns.to_string(), epoch));
                    }
                    let Some(seals) = item.get("seals").and_then(Value::as_object) else {
                        continue;
                    };
                    for (rid, sb) in seals {
                        if let Ok(sb) = serde_json::from_value::<SealedBox>(sb.clone()) {
                            sealed
                                .entry((ns.to_string(), epoch))
                                .or_default()
                                .entry(rid.clone())
                                .or_insert(sb);
                        }
                    }
                }
            }
            if v.get("kind").and_then(Value::as_str) == Some("revoke") {
                let member = v
                    .get("member")
                    .or_else(|| v.get("memberID"))
                    .and_then(Value::as_str);
                if let Some(member) = member {
                    let kept = v
                        .get("kept")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|d| d.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let heads = v
                        .get("heads")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|h| {
                                    Some((
                                        h.get("namespace")?.as_str()?.to_string(),
                                        h.get("digest")?.as_str()?.to_string(),
                                    ))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    revokes.insert(member.to_string(), RevokeInfo { kept, heads });
                }
            }
        }
        Ok(Self {
            authority_seq: verdict.branch.len() as u64,
            state,
            fork_seq,
            stop: verdict.stop,
            namespaces,
            introductions,
            sealed,
            revokes,
        })
    }
    /// `Ok` only when the verifier said `ok` over the whole object set: no held entry and no
    /// fork. The write side requires it (a held result is `unavailable`, a fork `refused:fork`).
    pub fn require_clean(&self) -> Result<()> {
        match &self.stop {
            None => Ok(()),
            Some(Stop::Held { why, .. }) => Err(Failure::Unavailable(format!("held: {why}"))),
            Some(Stop::Fork { .. }) => Err(Failure::Refused(Reason::Fork)),
            Some(Stop::Failed { failure, .. }) => Err(failure.clone()),
        }
    }
    /// The account.
    pub fn account(&self) -> &AccountId {
        self.state.account()
    }
    /// The folded state at the last verified entry.
    pub fn state(&self) -> &State {
        &self.state
    }
    /// The highest verified seq.
    pub fn authority_seq(&self) -> u64 {
        self.authority_seq
    }
    /// The seq of an unresolved fork, if any.
    pub fn fork_seq(&self) -> Option<u64> {
        self.fork_seq
    }
    /// The `upgrade` seq of an in-place upgraded account (§16.1).
    pub fn upgrade_seq(&self) -> Option<u64> {
        self.state.upgrade_seq
    }
    /// Declared namespaces, from the genesis.
    pub fn namespaces(&self) -> &[String] {
        &self.namespaces
    }
    /// A member by ID (revoked members included).
    pub fn member(&self, id: &str) -> Option<&MemberRecord> {
        self.state
            .members()
            .iter()
            .find(|m| m.request.member_id() == id)
    }
    /// The epoch of `namespace` current at authority seq `seq` (§11.5 step 5): the highest
    /// epoch introduced at or before it. `None` before the first.
    pub fn epoch_at(&self, namespace: &str, seq: u64) -> Option<u64> {
        self.introductions
            .iter()
            .filter(|(s, n, _)| *s <= seq && n == namespace)
            .map(|(_, _, e)| *e)
            .max()
    }
    /// True while the vault is retiring (§8.3): hosts MUST NOT introduce epochs.
    pub fn vault_retiring(&self) -> bool {
        self.state.vault_retiring()
    }
    /// Members owed shares: each current (not revoked) member with a `records` entry for a
    /// namespace and an epoch of it that no epoch object of the verified history sealed to it,
    /// for example an epoch made while it was expired or provisional (§9.4: a `renew` carries
    /// the shares; a member that was provisional when an epoch was made gets its shares by a
    /// `renew` once its activation is final). Sorted by member, namespace, epoch.
    pub fn owed_shares(&self) -> Vec<OwedShare> {
        let mut out = Vec::new();
        for m in self.state.members() {
            if m.revoked_seq.is_some() {
                continue;
            }
            let id = m.request.member_id();
            for entry in m.terms.records().unwrap_or_default() {
                for e in 1..=self.latest_epoch(&entry.namespace) {
                    if !self.sealed_to(&entry.namespace, e).contains(&id) {
                        out.push(OwedShare {
                            member: id.clone(),
                            namespace: entry.namespace.clone(),
                            epoch: e,
                            provisional: m.provisional.is_some(),
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            (&a.member, &a.namespace, a.epoch).cmp(&(&b.member, &b.namespace, b.epoch))
        });
        out
    }
    /// The latest epoch of `namespace` in the verified history (0: none yet).
    pub fn latest_epoch(&self, namespace: &str) -> u64 {
        self.epoch_at(namespace, self.authority_seq).unwrap_or(0)
    }
    /// The vault's public identity from the folded keyring.
    pub fn vault(&self) -> VaultPublic {
        VaultPublic::from_pair(&self.state.keyring().vault)
    }
    /// Who a new epoch of `namespace` introduced by an entry issued at `at_ms` is sealed to
    /// (§7.1, §10.2): the current vault, and every member that is not revoked, not provisional,
    /// not expired at `at_ms` and has any `records` entry for the namespace, except `exclude`.
    /// Sorted by ID.
    pub fn recipients(&self, namespace: &str, at_ms: i64, exclude: Option<&str>) -> Vec<Recipient> {
        let vault = self.vault();
        let mut out = BTreeMap::new();
        out.insert(
            vault.id(),
            Recipient {
                id: vault.id(),
                agreement: vault.agreement.clone(),
                vault: true,
            },
        );
        for m in self.state.members() {
            let id = m.request.member_id();
            let reads = m
                .terms
                .records()
                .is_some_and(|r| r.iter().any(|e| e.namespace == namespace));
            if reads
                && m.revoked_seq.is_none()
                && m.provisional.is_none()
                && m.expires_ms.is_none_or(|e| at_ms <= e)
                && exclude != Some(id.as_str())
            {
                out.insert(
                    id.clone(),
                    Recipient {
                        id,
                        agreement: m.request.agreement.clone(),
                        vault: false,
                    },
                );
            }
        }
        out.into_values().collect()
    }
    /// The recipient IDs the verified history sealed `(namespace, epoch)` to, in any epoch
    /// object, `shares` included.
    pub fn sealed_to(&self, namespace: &str, epoch: u64) -> BTreeSet<String> {
        self.sealed
            .get(&(namespace.to_string(), epoch))
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
    fn recipient_point(&self, recipient_id: &str) -> Option<Vec<u8>> {
        let vault = self.vault();
        if vault.id() == recipient_id {
            return Some(vault.agreement);
        }
        self.member(recipient_id)
            .map(|m| m.request.agreement.clone())
    }
    /// Begin opening the seal of `(namespace, epoch)` addressed to `recipient_id`: the point
    /// the host agrees with its key for that recipient (§11.1: "decapsulation takes raw ECDH
    /// from the host"). `None` when the history holds no such seal.
    pub fn epoch_seal_request(
        &self,
        namespace: &str,
        epoch: u64,
        recipient_id: &str,
    ) -> Option<SealRequest> {
        let sb = self
            .sealed
            .get(&(namespace.to_string(), epoch))?
            .get(recipient_id)?;
        Some(SealRequest {
            enc: sb.enc.clone(),
            recipient: self.recipient_point(recipient_id)?,
        })
    }
    /// Finish opening an epoch seal with the host's raw ECDH result. The key is bound to this
    /// account, `namespace` and `epoch`. A wrong result, or a seal made for another context, is
    /// `refused:vaultLocked`.
    pub fn open_epoch(
        &self,
        namespace: &str,
        epoch: u64,
        recipient_id: &str,
        dh: &EcdhOutput,
    ) -> Result<EpochKey> {
        let sb = self
            .sealed
            .get(&(namespace.to_string(), epoch))
            .and_then(|m| m.get(recipient_id))
            .ok_or_else(|| Failure::Unavailable("no such seal in the verified history".into()))?;
        let recipient = self
            .recipient_point(recipient_id)
            .ok_or_else(|| malformed("the recipient is not in the verified history"))?;
        let info = epoch_info(self.account(), namespace, epoch, recipient_id);
        let mut plain = super::vault::open_core_seal_with_dh(sb, &recipient, dh, &info)?;
        let key = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| super::vault::locked());
        erase(&mut plain);
        Ok(EpochKey::from_secret(
            self.account(),
            namespace,
            epoch,
            key?,
        ))
    }
    /// Open the seal addressed to the vault with the vault seed. The seed must derive this
    /// account's keyring `vault`.
    pub fn open_epoch_with_vault(
        &self,
        seed: &VaultSeed,
        namespace: &str,
        epoch: u64,
    ) -> Result<EpochKey> {
        let vault = self.vault();
        if seed.public()? != vault {
            return Err(super::vault::locked());
        }
        let sb = self
            .sealed
            .get(&(namespace.to_string(), epoch))
            .and_then(|m| m.get(&vault.id()))
            .ok_or_else(|| Failure::Unavailable("no vault seal for this epoch".into()))?;
        let info = epoch_info(self.account(), namespace, epoch, &vault.id());
        let mut plain = seed.open_core_seal(sb, &info)?;
        let key = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| super::vault::locked());
        erase(&mut plain);
        Ok(EpochKey::from_secret(
            self.account(),
            namespace,
            epoch,
            key?,
        ))
    }
}

impl RecordAuthority {
    /// Open the seal of `(namespace, epoch)` addressed to the vault that `seed` derives, which
    /// may be an earlier vault of this account (§7.1, §8.3: epochs sealed to an earlier vault
    /// are reached through `previousVault`). The seal must be addressed to that vault's ID, and
    /// the ID must not be a member's. The key is bound to this account, namespace and epoch.
    pub(crate) fn open_epoch_with_seed(
        &self,
        seed: &VaultSeed,
        namespace: &str,
        epoch: u64,
    ) -> Result<EpochKey> {
        let public = seed.public()?;
        let id = public.id();
        require(
            self.member(&id).is_none(),
            "the seal is addressed to a member, not a vault",
        )?;
        let sb = self
            .sealed
            .get(&(namespace.to_string(), epoch))
            .and_then(|m| m.get(&id))
            .ok_or_else(|| Failure::Unavailable("no seal for this vault and epoch".into()))?;
        let info = epoch_info(self.account(), namespace, epoch, &id);
        let mut plain = seed.open_core_seal(sb, &info)?;
        let key = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| super::vault::locked());
        erase(&mut plain);
        Ok(EpochKey::from_secret(
            self.account(),
            namespace,
            epoch,
            key?,
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// Held headers, the `/3` and `/5` formats, and end-to-end admission.

/// A header the reader holds: its storage path and the exact envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRecord {
    /// `ops/<author>/<namespace>/<clock, 12 digits>-<id>.json`.
    pub path: String,
    /// The envelope bytes (`{"body","signature"}`).
    pub bytes: Vec<u8>,
}
/// Which header format a record had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderFormat {
    /// `colophon/operation/5`.
    V5,
    /// The legacy `colophon/operation/3` of an upgraded account (§11.5, §16.1).
    V3,
}
/// The admission result of one header (§11.5, §19).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Admitted (and, if its epoch key is held, authenticated and in scope).
    Admitted,
    /// Refused, by §19 reason or `duplicateID`.
    Refused(&'static str),
    /// Held: `revokedBackdated`, `authorityBehind`, `unavailable`.
    Held(&'static str),
    /// An unknown condition operator decided the scope check (§10.4).
    NewerFormat,
    /// Not a record: it failed before admission (`malformed`, `badSignature`). Reserves nothing.
    Invalid(String),
}
impl Outcome {
    /// The protocol spelling: `admitted`, `refused:<reason>`, `held:<why>`, `newerFormat`, or
    /// the failure code.
    pub fn code(&self) -> String {
        match self {
            Self::Admitted => "admitted".into(),
            Self::Refused(r) => format!("refused:{r}"),
            Self::Held(w) => format!("held:{w}"),
            Self::NewerFormat => "newerFormat".into(),
            Self::Invalid(c) => c.clone(),
        }
    }
}
/// One judged record.
#[derive(Clone, Debug)]
pub struct Judged {
    /// The storage path it was held at.
    pub path: String,
    /// The result.
    pub outcome: Outcome,
    /// The format, when it parsed.
    pub format: Option<HeaderFormat>,
    /// The header body digest, when it parsed.
    pub digest: Option<String>,
    /// Author.
    pub author: Option<String>,
    /// Namespace.
    pub namespace: Option<String>,
    /// Operation ID.
    pub id: Option<String>,
    /// Clock.
    pub clock: u64,
    /// Level (`/3` is always `Write`).
    pub level: Option<Level>,
    /// The opened plaintext, when it authenticated and was admitted.
    pub plaintext: Option<Value>,
    /// False for an unknown payload version (0.3 §5: admitted, not folded).
    pub folded: bool,
    /// The header passed §11.5 steps 1–8 and so reserved a budget slot and counted its clock,
    /// whatever opening then found.
    pub reserved: bool,
}
impl Judged {
    fn invalid(path: &str, why: Failure) -> Self {
        Self {
            path: path.to_string(),
            outcome: Outcome::Invalid(why.code()),
            format: None,
            digest: None,
            author: None,
            namespace: None,
            id: None,
            clock: 0,
            level: None,
            plaintext: None,
            folded: false,
            reserved: false,
        }
    }
}

struct Cand {
    idx: usize,
    path: String,
    digest: String,
    format: HeaderFormat,
    header: OperationHeader,
    aad: Vec<u8>,
    library: Option<String>,
}

fn legacy_aad(c: &Cand) -> Result<Vec<u8>> {
    let h = &c.header;
    canonical(&json!({
        "author": h.author,
        "authority": h.authority,
        "clock": h.clock,
        "created": h.created.0,
        "epoch": h.epoch,
        "id": h.id,
        "library": c.library.clone().unwrap_or_default(),
        "namespace": h.namespace,
        "protocol": "colophon/operation/3",
    }))
}

/// Parse a held record: `/5` through [`OperationHeader::parse`], `/3` as 0.3 §5 states the
/// header (`library` in place of `account`, no `level` and no `previous`).
fn parse_candidate(idx: usize, held: &HeldRecord) -> Result<Cand> {
    let raw = RawEnvelope::parse(&held.bytes, bounds::OPERATION_HEADER_BODY, false)?;
    let protocol = raw
        .value
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    match protocol.as_str() {
        "colophon/operation/5" => {
            let (header, _) = OperationHeader::parse(&held.bytes)?;
            let aad = header.aad()?;
            Ok(Cand {
                idx,
                path: held.path.clone(),
                digest: header.digest(),
                format: HeaderFormat::V5,
                header,
                aad,
                library: None,
            })
        }
        "colophon/operation/3" => {
            let mut o = Obj::new(raw.value.clone(), "header")?;
            let _ = o.string("protocol")?;
            let library = o.string("library")?;
            require(is_lower_hex(&library, 32), "library must be 32 hex")?;
            let namespace = o.string("namespace")?;
            require(valid_namespace(&namespace), "invalid namespace")?;
            let author = o.key_id("author")?;
            let epoch = o.uint("epoch")?;
            require(epoch >= 1, "epoch starts at 1")?;
            let id = o.key_id("id")?;
            let clock = o.uint("clock")?;
            require(
                (1..=bounds::MAX_INTEGER).contains(&clock),
                "clock out of range",
            )?;
            let authority = o.uint("authority")?;
            require(authority >= 1, "authority must cite a seq")?;
            let created = o.date("created")?;
            let nonce = o.bytes("nonce", 12)?;
            require(nonce.len() == 12, "nonce must be 12 bytes")?;
            let ciphertext = o.bytes("ciphertext", bounds::OPERATION_HEADER_BODY)?;
            require(ciphertext.len() >= 16, "ciphertext shorter than its tag")?;
            let live = match o.opt_obj("live")? {
                None => None,
                Some(mut l) => {
                    let account = l.string("libraryID")?;
                    let slot = l.string("slot")?;
                    let generation = l.uint("generation")?;
                    let operation_id = l.key_id("operationID")?;
                    l.finish_closed()?;
                    Some(LiveStamp {
                        account,
                        slot,
                        generation,
                        operation_id,
                    })
                }
            };
            o.finish_closed()?;
            let header = OperationHeader {
                body: raw.body.clone(),
                account: AccountId::parse(&"0".repeat(64))?,
                namespace,
                author,
                epoch,
                id,
                clock,
                authority,
                created,
                level: Level::Write,
                previous: None,
                nonce,
                ciphertext,
                live,
                unknown: Unknown::default(),
            };
            let mut cand = Cand {
                idx,
                path: held.path.clone(),
                digest: super::encoding::digest(&raw.body),
                format: HeaderFormat::V3,
                header,
                aad: Vec::new(),
                library: Some(library),
            };
            cand.aad = legacy_aad(&cand)?;
            Ok(cand)
        }
        _ => Err(malformed("not a colophon/operation header")),
    }
}

/// What the §9.5 walk needs of a held header.
#[derive(Clone, Debug)]
pub(crate) struct Walk {
    pub author: String,
    pub namespace: String,
    pub previous: Option<String>,
}
/// The §9.5 kept set of one revocation: the `kept` digests plus every header the walk reaches,
/// and whether some walk met a header it does not hold.
pub(crate) struct KeptSet {
    pub digests: BTreeSet<String>,
    pub incomplete: bool,
}
/// Compute the §9.5 kept set from `kept` and `heads` over the held headers by digest.
pub(crate) fn kept_set(
    kept: &BTreeSet<String>,
    heads: &[(String, String)],
    member: &str,
    held: &BTreeMap<String, Walk>,
) -> KeptSet {
    let mut digests = kept.clone();
    let mut incomplete = false;
    for (namespace, digest) in heads {
        let Some(start) = held.get(digest) else {
            incomplete = true;
            continue;
        };
        // An item names a header of this member in that namespace; anything else starts no
        // walk (the text does not say more; reported as a spec question).
        if start.author != member || &start.namespace != namespace {
            continue;
        }
        let mut cur_digest = digest.clone();
        let mut cur = start;
        for _ in 0..=held.len() {
            digests.insert(cur_digest.clone());
            match &cur.previous {
                None => break,
                Some(p) => match held.get(p) {
                    Some(next) => {
                        cur_digest = p.clone();
                        cur = next;
                    }
                    None => {
                        incomplete = true;
                        break;
                    }
                },
            }
        }
    }
    KeptSet {
        digests,
        incomplete,
    }
}

/// A proposal's standing after the §11.6 fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalState {
    /// No valid resolution yet.
    Pending,
    /// The first valid resolution in fold order is an `accept` (by this operation ID).
    Accepted {
        /// The accept record's operation ID.
        resolution: String,
        /// The accepter's member ID.
        by: String,
        /// The accept's fold position `(clock, author, id)`: where the proposal is folded.
        at: (u64, String, String),
    },
    /// The first valid resolution is a `decline`.
    Declined {
        /// The decline record's operation ID.
        resolution: String,
        /// The decliner's member ID.
        by: String,
    },
}
/// One proposal and what resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalStatus {
    /// Namespace.
    pub namespace: String,
    /// The proposal's operation ID.
    pub id: String,
    /// The proposer.
    pub proposer: String,
    /// The proposal's kind.
    pub kind: String,
    /// The proposal's clock.
    pub clock: u64,
    /// Standing.
    pub state: ProposalState,
    /// Operation IDs of later valid resolutions: evidence only.
    pub evidence: Vec<String>,
    /// Operation IDs of resolutions naming this proposal that are not valid (the resolver may
    /// not write the kind, or its clock does not exceed the proposal's).
    pub ignored: Vec<String>,
}
/// A resolution naming a proposal the reader lacks: held for it (§11.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldResolution {
    /// The resolution's operation ID.
    pub resolution: String,
    /// The proposal it waits for.
    pub proposal: String,
}
/// The result of [`judge_records`].
#[derive(Clone, Debug)]
pub struct Judgement {
    /// One entry per held record, in the order given.
    pub records: Vec<Judged>,
    /// Proposals and their standing, by `(namespace, id)`.
    pub proposals: Vec<ProposalStatus>,
    /// Resolutions held for a proposal the reader lacks.
    pub held_resolutions: Vec<HeldResolution>,
}

/// Parse a resolution payload (§11.6): `{"proposals": [<operation ID>, …]}`, 1–64.
fn resolution_targets(plaintext: &Value) -> Option<Vec<String>> {
    let kind = plaintext.get("kind")?.as_str()?;
    if kind != "colophon.accept" && kind != "colophon.decline" {
        return None;
    }
    let list = plaintext.get("payload")?.get("proposals")?.as_array()?;
    if list.is_empty() || list.len() > 64 {
        return None;
    }
    let mut out = Vec::new();
    for v in list {
        let id = v.as_str()?;
        if !is_key_id(id) {
            return None;
        }
        // A proposal named twice is named once (the text counts 1-64 IDs, not distinct ones).
        if !out.iter().any(|x| x == id) {
            out.push(id.to_string());
        }
    }
    Some(out)
}

/// Admit a held set of headers end to end (§11.5), `/5` and, for an upgraded account, `/3`.
///
/// Every record is checked in this order: parse, then signature under the author's member key
/// from the verified state, account (or `library`) binding and path (a failure is
/// `Outcome::Invalid` and reserves nothing); the upgrade fence (§11.5, last paragraph:
/// `wrongFormat`); then steps 1–8 in fold order `(clock, author, id)` through [`admit`] with the
/// author and namespace views derived from `auth`, including the walk of §9.5; then, for an
/// admitted header, opening with the key in `keys` (`held:unavailable` without one;
/// `invalidPayload`, `duplicateID`, `outOfScope` and `newerFormat` after it). Step 8 reserves a
/// budget slot per distinct `(author, id)` whatever opening finds.
///
/// An author that is not a member of the verified history has no key to check a signature
/// with: its header is `refused:notGranted` (§11.5 step 1; the order of this and the
/// signature check is a spec question).
pub fn judge_records(auth: &RecordAuthority, keys: &EpochKeys, held: &[HeldRecord]) -> Judgement {
    judge_core(auth, keys, held, None)
}

/// Stage one of admission for one held record.
enum Stage {
    /// Failed before admission.
    Bad(Box<Judged>),
    /// Parsed and bound, but the author is not a member: no key to check a signature with.
    Unknown(Box<Cand>),
    /// Parsed, bound, path-checked and signature-checked.
    Ready(Box<Cand>),
}
fn stage_one(auth: &RecordAuthority, idx: usize, h: &HeldRecord, skip_signature: bool) -> Stage {
    let account = auth.account();
    let c = match parse_candidate(idx, h) {
        Ok(c) => c,
        Err(f) => return Stage::Bad(Box::new(Judged::invalid(&h.path, f))),
    };
    let hd = &c.header;
    // A `/5` header of another account is not this account's record at all. A `/3` header
    // with another library is fenced out by format (§11.5), later.
    if c.format == HeaderFormat::V5 && &hd.account != account {
        return Stage::Bad(Box::new(Judged::invalid(
            &h.path,
            malformed("header names another account"),
        )));
    }
    if hd.check_path(&h.path).is_err() {
        return Stage::Bad(Box::new(Judged::invalid(
            &h.path,
            malformed("path mismatch"),
        )));
    }
    let Some(member) = auth.member(&hd.author) else {
        return Stage::Unknown(Box::new(c));
    };
    if !skip_signature {
        let sig = RawEnvelope::parse(&h.bytes, bounds::OPERATION_HEADER_BODY, false)
            .and_then(|env| OperationHeader::verify(&env, &member.request.signing));
        if let Err(f) = sig {
            return Stage::Bad(Box::new(Judged::invalid(&h.path, f)));
        }
    }
    Stage::Ready(Box::new(c))
}

/// [`judge_records`], optionally skipping the signature check of the one held record at index
/// `unsigned` (the write side judges its own header before the host has signed it).
///
/// The verdict is a function of the set of objects, not of the order of `held`: one body under
/// several envelopes is one object (§2.2) and is judged once, the result given to each of its
/// envelopes; fold order is `(clock, author, id)` with the body digest, lowest first, as the
/// last tie-break (the text has none past `id`; two bodies by one author with one ID and clock
/// differ only in AAD-only fields such as `level` or `previous`).
pub(crate) fn judge_core(
    auth: &RecordAuthority,
    keys: &EpochKeys,
    held: &[HeldRecord],
    unsigned: Option<usize>,
) -> Judgement {
    let account = auth.account().clone();
    let mut records: Vec<Option<Judged>> = vec![None; held.len()];
    let mut cands: Vec<Cand> = Vec::new();
    let mut early: BTreeMap<usize, Outcome> = BTreeMap::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut aliases: Vec<(usize, usize)> = Vec::new();
    for (idx, h) in held.iter().enumerate() {
        let c = match stage_one(auth, idx, h, unsigned == Some(idx)) {
            Stage::Bad(j) => {
                records[idx] = Some(*j);
                continue;
            }
            Stage::Unknown(c) => {
                early.insert(idx, Outcome::Refused("notGranted"));
                *c
            }
            Stage::Ready(c) => *c,
        };
        if let Some(first) = seen.get(&c.digest) {
            aliases.push((idx, *first));
            continue;
        }
        seen.insert(c.digest.clone(), cands.len());
        cands.push(c);
    }
    let upgrade = auth.upgrade_seq();
    let mut order: Vec<usize> = (0..cands.len()).collect();
    order.sort_by(|a, b| {
        let (x, y) = (&cands[*a].header, &cands[*b].header);
        (x.clock, &x.author, &x.id, &cands[*a].digest).cmp(&(
            y.clock,
            &y.author,
            &y.id,
            &cands[*b].digest,
        ))
    });
    let walkable: BTreeMap<String, Walk> = cands
        .iter()
        .map(|c| {
            (
                c.digest.clone(),
                Walk {
                    author: c.header.author.clone(),
                    namespace: c.header.namespace.clone(),
                    previous: c.header.previous.clone(),
                },
            )
        })
        .collect();
    let mut highest: BTreeMap<String, u64> = BTreeMap::new();
    let mut reserved: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut authentic: BTreeSet<(String, String)> = BTreeSet::new();
    let mut kept_cache: BTreeMap<String, KeptSet> = BTreeMap::new();
    let mut judged_by_cand: Vec<Option<Judged>> = vec![None; cands.len()];
    for &ci in &order {
        let c = &cands[ci];
        let hd = &c.header;
        let mut j = Judged {
            path: c.path.clone(),
            outcome: Outcome::Admitted,
            format: Some(c.format),
            digest: Some(c.digest.clone()),
            author: Some(hd.author.clone()),
            namespace: Some(hd.namespace.clone()),
            id: Some(hd.id.clone()),
            clock: hd.clock,
            level: Some(hd.level),
            plaintext: None,
            folded: false,
            reserved: false,
        };
        if let Some(o) = early.get(&c.idx) {
            j.outcome = o.clone();
            judged_by_cand[ci] = Some(j);
            continue;
        }
        // The upgrade fence (§11.5).
        let fenced = match (upgrade, c.format) {
            (Some(u), HeaderFormat::V3) => {
                hd.authority >= u
                    || !c
                        .library
                        .as_deref()
                        .is_some_and(|l| auth.account().has_legacy_id(l))
            }
            (Some(u), HeaderFormat::V5) => hd.authority < u,
            (None, HeaderFormat::V3) => true,
            (None, HeaderFormat::V5) => false,
        };
        if fenced {
            j.outcome = Outcome::Refused("wrongFormat");
            judged_by_cand[ci] = Some(j);
            continue;
        }
        let Some(member) = auth.member(&hd.author) else {
            j.outcome = Outcome::Refused("notGranted");
            judged_by_cand[ci] = Some(j);
            continue;
        };
        let entry = member
            .terms
            .records()
            .and_then(|r| r.iter().find(|e| e.namespace == hd.namespace));
        let kept = match member.revoked_seq {
            None => Kept::NotKept,
            Some(_) => {
                let set = kept_cache.entry(hd.author.clone()).or_insert_with(|| {
                    match auth.revokes.get(&hd.author) {
                        Some(info) => kept_set(&info.kept, &info.heads, &hd.author, &walkable),
                        None => KeptSet {
                            digests: BTreeSet::new(),
                            incomplete: false,
                        },
                    }
                });
                if set.digests.contains(&c.digest) {
                    Kept::Kept
                } else if set.incomplete {
                    Kept::Incomplete
                } else {
                    Kept::NotKept
                }
            }
        };
        let spent = reserved.get(&hd.author);
        let writes_left = match member.terms.writes() {
            None => None,
            Some(budget) => {
                if spent.is_some_and(|s| s.contains(&hd.id)) {
                    None
                } else {
                    Some(budget.saturating_sub(spent.map_or(0, |s| s.len() as u64)))
                }
            }
        };
        let author_view = AuthorView {
            access: if hd.authority >= member.granted_seq {
                entry.map(|e| e.access)
            } else {
                None
            },
            expires_ms: member.expires_ms,
            revoked_seq: member.revoked_seq,
            kept,
            writes_left,
            provisional: member.provisional.is_some(),
        };
        let cited = hd.authority.min(auth.authority_seq());
        let ns_view = NamespaceView {
            authority_seq: auth.authority_seq(),
            fork_seq: auth.fork_seq(),
            epoch_at_cited: auth.epoch_at(&hd.namespace, cited).unwrap_or(0),
            highest_clock: highest.get(&hd.namespace).copied().unwrap_or(0),
        };
        match admit(hd, &author_view, &ns_view) {
            Admission::Refused(r) => j.outcome = Outcome::Refused(r.as_str()),
            Admission::Held(w) => j.outcome = Outcome::Held(w),
            Admission::NewerFormat => j.outcome = Outcome::NewerFormat,
            Admission::Admitted => {
                // Step 8: reserve, and count the clock, whatever opening finds.
                j.reserved = true;
                reserved
                    .entry(hd.author.clone())
                    .or_default()
                    .insert(hd.id.clone());
                let h = highest.entry(hd.namespace.clone()).or_insert(0);
                *h = (*h).max(hd.clock);
                match keys.get(&account, &hd.namespace, hd.epoch) {
                    None => j.outcome = Outcome::Held("unavailable"),
                    Some(key) => {
                        let opened = open_plaintext(
                            key.expose(),
                            &c.aad,
                            &Sealed {
                                namespace: &hd.namespace,
                                author: &hd.author,
                                epoch: hd.epoch,
                                id: &hd.id,
                                clock: hd.clock,
                                authority: hd.authority,
                                created: &hd.created.0,
                                nonce: &hd.nonce,
                                ciphertext: &hd.ciphertext,
                            },
                        );
                        match opened {
                            Err(_) => j.outcome = Outcome::Refused("invalidPayload"),
                            Ok(pt) => {
                                let scope = match entry {
                                    Some(e) => admit_opened(&pt, e, &member.terms),
                                    None => Admission::Refused(Reason::NotGranted),
                                };
                                match scope {
                                    Admission::Refused(r) => {
                                        j.outcome = Outcome::Refused(r.as_str());
                                    }
                                    Admission::NewerFormat => j.outcome = Outcome::NewerFormat,
                                    _ => {
                                        if !authentic.insert((hd.author.clone(), hd.id.clone())) {
                                            j.outcome = Outcome::Refused("duplicateID");
                                        } else {
                                            j.folded =
                                                pt.get("v").and_then(Value::as_u64) == Some(1);
                                            j.plaintext = Some(pt);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        judged_by_cand[ci] = Some(j);
    }
    for (ci, j) in judged_by_cand.into_iter().enumerate() {
        if let Some(j) = j {
            records[cands[ci].idx] = Some(j);
        }
    }
    for (idx, ci) in aliases {
        let mut j = records[cands[ci].idx].clone();
        if let Some(j) = j.as_mut() {
            j.path = held[idx].path.clone();
        }
        records[idx] = j;
    }
    let records: Vec<Judged> = records
        .into_iter()
        .enumerate()
        .map(|(i, j)| j.unwrap_or_else(|| Judged::invalid(&held[i].path, malformed("not judged"))))
        .collect();
    let (proposals, held_resolutions) = fold_proposals(auth, &records);
    Judgement {
        records,
        proposals,
        held_resolutions,
    }
}

/// The §11.6 fold over the admitted, authenticated records.
fn fold_proposals(
    auth: &RecordAuthority,
    records: &[Judged],
) -> (Vec<ProposalStatus>, Vec<HeldResolution>) {
    let mut live: Vec<&Judged> = records
        .iter()
        .filter(|r| r.outcome == Outcome::Admitted && r.plaintext.is_some() && r.folded)
        .collect();
    live.sort_by(|a, b| {
        (a.clock, a.author.as_deref(), a.id.as_deref()).cmp(&(
            b.clock,
            b.author.as_deref(),
            b.id.as_deref(),
        ))
    });
    let mut proposals: Vec<ProposalStatus> = Vec::new();
    for r in &live {
        if r.level == Some(Level::Propose) {
            let (Some(ns), Some(id), Some(author), Some(pt)) = (
                r.namespace.clone(),
                r.id.clone(),
                r.author.clone(),
                r.plaintext.as_ref(),
            ) else {
                continue;
            };
            if proposals.iter().any(|p| p.namespace == ns && p.id == id) {
                continue;
            }
            proposals.push(ProposalStatus {
                namespace: ns,
                id,
                proposer: author,
                kind: pt
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                clock: r.clock,
                state: ProposalState::Pending,
                evidence: Vec::new(),
                ignored: Vec::new(),
            });
        }
    }
    let mut held_res = Vec::new();
    for r in &live {
        if r.level != Some(Level::Write) {
            continue;
        }
        let (Some(ns), Some(rid), Some(resolver), Some(pt)) = (
            r.namespace.as_ref(),
            r.id.as_ref(),
            r.author.as_ref(),
            r.plaintext.as_ref(),
        ) else {
            continue;
        };
        let Some(targets) = resolution_targets(pt) else {
            continue;
        };
        let accept = pt.get("kind").and_then(Value::as_str) == Some("colophon.accept");
        for target in targets {
            let Some(p) = proposals
                .iter_mut()
                .find(|p| &p.namespace == ns && p.id == target)
            else {
                held_res.push(HeldResolution {
                    resolution: rid.clone(),
                    proposal: target,
                });
                continue;
            };
            let may_write = auth.member(resolver).is_some_and(|m| {
                m.terms.records().is_some_and(|rs| {
                    rs.iter().any(|e| {
                        &e.namespace == ns
                            && e.access >= Access::Write
                            && e.kinds
                                .as_ref()
                                .is_none_or(|k| k.iter().any(|x| x == &p.kind))
                    })
                })
            });
            if !may_write || r.clock <= p.clock {
                p.ignored.push(rid.clone());
                continue;
            }
            if p.state == ProposalState::Pending {
                p.state = if accept {
                    ProposalState::Accepted {
                        resolution: rid.clone(),
                        by: resolver.clone(),
                        at: (r.clock, resolver.clone(), rid.clone()),
                    }
                } else {
                    ProposalState::Declined {
                        resolution: rid.clone(),
                        by: resolver.clone(),
                    }
                };
            } else {
                p.evidence.push(rid.clone());
            }
        }
    }
    (proposals, held_res)
}

/// Admit a held set against the account's authority objects: the verifier's verdict, then
/// [`judge_records`]. This is the end-to-end admission API for `/5` and legacy `/3` records.
pub fn admit_records(
    objects: &Objects,
    now_ms: i64,
    keys: &EpochKeys,
    held: &[HeldRecord],
) -> Result<Judgement> {
    let auth = RecordAuthority::from_objects(objects, now_ms)?;
    Ok(judge_records(&auth, keys, held))
}

/// A held header whose signature, account binding and path check out, as the write side needs
/// to know it (author chains, revocation heads).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderInfo {
    /// The header body digest.
    pub digest: String,
    /// Author.
    pub author: String,
    /// Namespace.
    pub namespace: String,
    /// Operation ID.
    pub id: String,
    /// Clock.
    pub clock: u64,
    /// Epoch.
    pub epoch: u64,
    /// `previous` (always `None` for a `/3` header).
    pub previous: Option<String>,
    /// Format.
    pub format: HeaderFormat,
    /// Nonce.
    pub nonce: Vec<u8>,
    /// The path it is held at.
    pub path: String,
}
/// The held headers that parse, bind to the account and path and carry a valid signature by a
/// member of the verified history. Anything else is left out.
pub fn verified_headers(auth: &RecordAuthority, held: &[HeldRecord]) -> Vec<HeaderInfo> {
    let mut out = Vec::new();
    for (idx, h) in held.iter().enumerate() {
        if let Stage::Ready(c) = stage_one(auth, idx, h, false) {
            out.push(HeaderInfo {
                digest: c.digest,
                author: c.header.author,
                namespace: c.header.namespace,
                id: c.header.id,
                clock: c.header.clock,
                epoch: c.header.epoch,
                previous: c.header.previous,
                format: c.format,
                nonce: c.header.nonce,
                path: c.path,
            });
        }
    }
    out
}
/// The maximal heads of `author`'s `/5` chain in `namespace` among `headers`: the digests no
/// other of its headers there names as `previous` (§11.2).
pub fn chain_heads(headers: &[HeaderInfo], author: &str, namespace: &str) -> Vec<String> {
    let mine: Vec<&HeaderInfo> = headers
        .iter()
        .filter(|h| h.author == author && h.namespace == namespace && h.format == HeaderFormat::V5)
        .collect();
    let named: BTreeSet<&str> = mine.iter().filter_map(|h| h.previous.as_deref()).collect();
    let mut heads: Vec<String> = mine
        .iter()
        .filter(|h| !named.contains(h.digest.as_str()))
        .map(|h| h.digest.clone())
        .collect();
    heads.sort();
    heads.dedup();
    heads
}
/// The §9.5 kept set a revocation of `member` with these `kept` digests and `heads` would
/// have over `headers`, and whether some walk is incomplete (a header of a chain is not held).
pub fn revocation_reach(
    headers: &[HeaderInfo],
    member: &str,
    kept: &[String],
    heads: &[(String, String)],
) -> (BTreeSet<String>, bool) {
    let held: BTreeMap<String, Walk> = headers
        .iter()
        .map(|h| {
            (
                h.digest.clone(),
                Walk {
                    author: h.author.clone(),
                    namespace: h.namespace.clone(),
                    previous: h.previous.clone(),
                },
            )
        })
        .collect();
    let set = kept_set(&kept.iter().cloned().collect(), heads, member, &held);
    (set.digests, set.incomplete)
}
impl Outcome {
    /// The refusal as a [`Failure`], or `None` for `Admitted`.
    pub fn failure(&self) -> Option<Failure> {
        const REASONS: [Reason; 11] = [
            Reason::NotGranted,
            Reason::Expired,
            Reason::Revoked,
            Reason::WrongEpoch,
            Reason::ClockJump,
            Reason::BudgetSpent,
            Reason::WrongFormat,
            Reason::InvalidPayload,
            Reason::OutOfScope,
            Reason::Fork,
            Reason::Rollback,
        ];
        match self {
            Self::Admitted => None,
            Self::Refused(r) => Some(
                REASONS
                    .iter()
                    .find(|x| x.as_str() == *r)
                    .map_or_else(|| malformed(*r), |x| Failure::Refused(*x)),
            ),
            Self::Held(w) => Some(Failure::Unavailable(format!("held: {w}"))),
            Self::NewerFormat => Some(Failure::NewerFormat("unknown condition operator".into())),
            Self::Invalid(c) => Some(malformed(c.clone())),
        }
    }
}
