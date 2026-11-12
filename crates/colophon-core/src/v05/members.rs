//! Members (§9): membership requests, and the `grant`, `renew`, `revoke` and `endSessions`
//! entry shapes with the §9 rules that don't depend on pending transitions; and the §3.3
//! one-key-one-principal invariant, including "a member is never a controller" (§9.7).
//!
//! Not here: who may sign these entries (§8.4 rules), sequencing and replay (§8.5), and whether
//! a grant containing `serves` or `import` is admissible as an immediate entry (§8.4 makes them
//! pending transitions; that classification is step 2). Callers pass the authority context a
//! rule needs (declared namespaces, current members, known principal keys).
use super::descriptor::valid_point;
use super::encoding::{bounds, byte_len_in, is_digest, Obj};
use super::ids::{key_id, AccountId};
use super::signature::RawEnvelope;
use super::terms::{valid_namespace, Terms, TermsKind};
use super::{bad_signature, malformed, require, Result, Unknown};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The generic header of an authority body (§8.1), split from the kind's fields. Shape only:
/// sequencing, `previous`, monotonic `issued` and signer binding are §8.5 (not here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityHeader {
    /// `colophon/authority/5` (or `/4` in an upgraded prefix).
    pub protocol: String,
    /// Sequence number from 1.
    pub seq: u64,
    /// SHA-256 hex of the preceding body; `None` only at seq 1.
    pub previous: Option<String>,
    /// `issued` in ms, and its spelling.
    pub issued: (String, i64),
    /// The primary signer's ID.
    pub by: String,
    /// The kind.
    pub kind: String,
}
impl AuthorityHeader {
    /// Split a parsed `/5` authority body into its header and the remaining kind fields.
    pub fn split(body: Value) -> Result<(Self, Obj)> {
        let mut o = Obj::new(body, "")?;
        let protocol = o.string("protocol")?;
        let seq = o.uint("seq")?;
        require(seq >= 1, "seq must be at least 1")?;
        let previous = match o.value("previous")? {
            Value::Null => None,
            Value::String(s) if is_digest(&s) => Some(s),
            _ => return Err(malformed("previous must be a digest or null")),
        };
        require(
            previous.is_none() == (seq == 1),
            "previous is null exactly at seq 1",
        )?;
        let issued = o.date("issued")?;
        let by = o.key_id("by")?;
        let kind = o.string("kind")?;
        Ok((
            Self {
                protocol,
                seq,
                previous,
                issued,
                by,
                kind,
            },
            o,
        ))
    }
}

/// A member's kind (§9.1).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemberKind {
    /// A device.
    Device,
    /// An app.
    App,
    /// An agent: its records are shown as written by AI.
    Agent,
    /// A server.
    Server,
    /// A kind this reader doesn't know (reported as unknown content).
    Unknown(String),
}
/// `custody` (§9.1), display only.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Custody {
    /// Hardware.
    Hardware,
    /// Platform.
    Platform,
    /// Software.
    Software,
    /// Custodial (needs `operator`).
    Custodial,
    /// Unknown (reported as unknown content).
    Unknown(String),
}

/// A verified membership request (§9.1).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Request {
    /// Exact request body bytes.
    pub body: Vec<u8>,
    /// The account it names.
    pub account: AccountId,
    /// Member signing point.
    pub signing: Vec<u8>,
    /// Member agreement point.
    pub agreement: Vec<u8>,
    /// Label.
    pub label: String,
    /// Kind.
    pub kind: MemberKind,
    /// Requested terms.
    pub terms: Terms,
    /// `created`, ms.
    pub created_ms: i64,
    /// Custody.
    pub custody: Option<Custody>,
    /// Operator.
    pub operator: Option<String>,
    /// Service endpoints (iff `terms.serves`).
    pub endpoints: Option<Vec<String>>,
    /// Unknown content in the request (fields, kind, custody, terms).
    pub unknown: Unknown,
}
impl Request {
    /// The member ID.
    pub fn member_id(&self) -> String {
        key_id(&self.signing)
    }
    /// Parse a request envelope (exactly `body` and `signature`), check its shape and verify
    /// its `raw` signature under `member.signing`. With `embedded` (inside a grant), the
    /// envelope bytes must be canonical too. Unknown content is kept in `unknown`.
    pub fn parse(envelope: &[u8], embedded: bool) -> Result<Self> {
        let mut sink = Unknown::default();
        let unknown = &mut sink;
        let env = RawEnvelope::parse(envelope, bounds::REQUEST_BODY, embedded)?;
        let mut o = Obj::new(env.value.clone(), "request")?;
        require(
            o.string("protocol")? == "colophon/request/5",
            "not a colophon/request/5 request",
        )?;
        let account = AccountId::parse(&o.string("account")?)?;
        let mut m = o.obj("member")?;
        let signing = m.bytes("signing", 65)?;
        let agreement = m.bytes("agreement", 65)?;
        m.finish(unknown);
        require(
            valid_point(&signing) && valid_point(&agreement),
            "member points must be valid",
        )?;
        require(signing != agreement, "member points must be distinct")?;
        let label = o.string("label")?;
        require(byte_len_in(&label, 1, 200), "label must be 1–200 bytes")?;
        let kind = match o.string("kind")?.as_str() {
            "device" => MemberKind::Device,
            "app" => MemberKind::App,
            "agent" => MemberKind::Agent,
            "server" => MemberKind::Server,
            other => {
                unknown.push(format!("request.kind={other}"));
                MemberKind::Unknown(other.into())
            }
        };
        let terms = Terms::parse(o.value("terms")?, TermsKind::Member)?;
        unknown.0.extend(terms.unknown().0.iter().cloned());
        require(!terms.import(), "requested terms contain import")?;
        let (_, created_ms) = o.date("created")?;
        let custody = o.opt_string("custody")?.map(|c| match c.as_str() {
            "hardware" => Custody::Hardware,
            "platform" => Custody::Platform,
            "software" => Custody::Software,
            "custodial" => Custody::Custodial,
            other => {
                unknown.push(format!("request.custody={other}"));
                Custody::Unknown(other.into())
            }
        });
        let operator = o.opt_string("operator")?;
        if let Some(op) = &operator {
            require(byte_len_in(op, 1, 200), "operator must be 1–200 bytes")?;
        }
        if custody == Some(Custody::Custodial) {
            require(operator.is_some(), "custodial custody needs an operator")?;
        }
        let endpoints = match o.opt_obj("service")? {
            None => None,
            Some(mut s) => {
                let items = s.array("endpoints")?;
                require(
                    (1..=8).contains(&items.len()),
                    "service.endpoints must have 1–8 entries",
                )?;
                let list = items
                    .into_iter()
                    .map(|v| match v {
                        Value::String(e) if e.starts_with("https://") && e.len() <= 512 => Ok(e),
                        _ => Err(malformed("invalid service endpoint")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                require(
                    list.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()),
                    "service.endpoints must be sorted and distinct",
                )?;
                s.finish(unknown);
                Some(list)
            }
        };
        require(
            endpoints.is_some() == terms.serves_present(),
            "service is present if and only if terms.serves is",
        )?;
        o.finish(unknown);
        env.verify(&signing)
            .map_err(|e| bad_signature(format!("request: {e}")))?;
        Ok(Self {
            body: env.body,
            account,
            signing,
            agreement,
            label,
            kind,
            terms,
            created_ms,
            custody,
            operator,
            endpoints,
            unknown: sink,
        })
    }
}

/// One epoch object, as used in `shares` and `epochs` (§11.1): `{namespace, epoch, seals}`
/// with seals `{recipientID: {enc (65 bytes), ciphertext (48 bytes)}}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochSeals {
    /// Namespace.
    pub namespace: String,
    /// Epoch number, from 1.
    pub epoch: u64,
    /// Recipient IDs sealed to.
    pub recipients: BTreeSet<String>,
}
fn parse_epochs(items: Vec<Value>, field: &str, unknown: &mut Unknown) -> Result<Vec<EpochSeals>> {
    items
        .into_iter()
        .map(|item| {
            let mut e = Obj::new(item, field)?;
            let namespace = e.string("namespace")?;
            require(valid_namespace(&namespace), "invalid namespace in epoch")?;
            let epoch = e.uint("epoch")?;
            require(epoch >= 1, "epochs start at 1")?;
            let mut recipients = BTreeSet::new();
            let Value::Object(map) = e.value("seals")? else {
                return Err(malformed("seals must be an object"));
            };
            for (id, sealed) in map {
                require(super::ids::is_key_id(&id), "seal recipient is not a key ID")?;
                let mut s = Obj::new(sealed, "seal")?;
                let enc = s.bytes("enc", 65)?;
                require(valid_point(&enc), "seal enc is not a valid point")?;
                require(
                    s.bytes("ciphertext", 48)?.len() == 48,
                    "seal ciphertext must be 48 bytes",
                )?;
                s.finish(unknown);
                recipients.insert(id);
            }
            e.finish(unknown);
            Ok(EpochSeals {
                namespace,
                epoch,
                recipients,
            })
        })
        .collect()
}
/// Context a grant is validated in (supplied by the authority replayer).
#[derive(Clone, Copy, Debug)]
pub struct GrantContext<'a> {
    /// This account.
    pub account: &'a AccountId,
    /// The entry's `issued`, ms.
    pub issued_ms: i64,
    /// Declared namespaces.
    pub namespaces: &'a [String],
    /// Every signing and agreement point and key ID used by any principal in the history so
    /// far (§3.3). A grant to any of them is `malformed`.
    pub known_keys: &'a BTreeSet<Vec<u8>>,
    /// Latest epoch per namespace, when the caller can check `shares` completeness.
    pub epochs: Option<&'a BTreeMap<String, u64>>,
}

/// A validated grant (§9.2).
#[derive(Clone, Debug, PartialEq)]
pub struct Grant {
    /// The embedded, verified request.
    pub request: Request,
    /// The granted terms.
    pub terms: Terms,
    /// The shares.
    pub shares: Vec<EpochSeals>,
    /// Unknown content (the request's, the terms', the fields').
    pub unknown: Unknown,
}
impl Grant {
    /// The member ID.
    pub fn member_id(&self) -> String {
        self.request.member_id()
    }
    /// Validate the fields of a `grant` entry (`request`, `terms`, `shares`) under §9.2–§9.3.
    pub fn parse(mut fields: Obj, ctx: GrantContext<'_>) -> Result<Self> {
        let mut sink = Unknown::default();
        let unknown = &mut sink;
        let request_bytes = fields.bytes("request", bounds::REQUEST_BODY * 2 + 4_096)?;
        let request = Request::parse(&request_bytes, true)?;
        unknown.0.extend(request.unknown.0.iter().cloned());
        require(
            &request.account == ctx.account,
            "request names another account",
        )?;
        let terms = Terms::parse(fields.value("terms")?, TermsKind::Member)?;
        unknown.0.extend(terms.unknown().0.iter().cloned());
        let shares = parse_epochs(fields.array("shares")?, "shares", unknown)?;
        fields.finish(unknown);
        require(
            terms.covered_by(&request.terms),
            "granted terms are not covered by the request",
        )?;
        let member = request.member_id();
        for k in [&request.signing, &request.agreement] {
            require(
                !ctx.known_keys.contains(k),
                "member key already used by a principal (§3.3)",
            )?;
            require(
                !ctx.known_keys.contains(key_id(k).as_bytes()),
                "member key ID already used by a principal (§3.3)",
            )?;
        }
        if let Some(records) = terms.records() {
            for r in records {
                require(
                    ctx.namespaces.contains(&r.namespace),
                    "granted namespace not declared",
                )?;
            }
        }
        if terms.records().is_none() {
            require(shares.is_empty(), "shares must be empty without records")?;
        }
        for s in &shares {
            require(
                terms
                    .records()
                    .is_some_and(|r| r.iter().any(|e| e.namespace == s.namespace)),
                "share for a namespace not granted",
            )?;
            require(
                s.recipients.contains(&member),
                "share not sealed to the member",
            )?;
        }
        if let (Some(epochs), Some(records)) = (ctx.epochs, terms.records()) {
            for r in records {
                let latest = epochs.get(&r.namespace).copied().unwrap_or(0);
                for e in 1..=latest {
                    require(
                        shares
                            .iter()
                            .any(|s| s.namespace == r.namespace && s.epoch == e),
                        "shares miss a historical epoch of a granted namespace",
                    )?;
                }
            }
        }
        if terms.serves_home() {
            require(
                request.kind != MemberKind::Agent,
                "serves is never granted to an agent",
            )?;
        }
        if terms.import() {
            require(
                matches!(request.kind, MemberKind::Device | MemberKind::App),
                "import is granted only to a device or app",
            )?;
            let records = terms
                .records()
                .ok_or_else(|| malformed("import needs records"))?;
            require(
                records
                    .iter()
                    .all(|r| r.access == super::terms::Access::Write),
                "import needs write in every records entry",
            )?;
            require(
                terms.expires_ms().is_some_and(|e| e > ctx.issued_ms),
                "import needs expires later than issued",
            )?;
        }
        Ok(Self {
            request,
            terms,
            shares,
            unknown: sink,
        })
    }
}

/// A validated `renew` (§9.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Renew {
    /// The member.
    pub member: String,
    /// The new expiry, ms.
    pub expires_ms: i64,
    /// Shares.
    pub shares: Vec<EpochSeals>,
    /// Unknown content.
    pub unknown: Unknown,
}
impl Renew {
    /// Validate `renew` fields. `current_expiry` is the member's expiry now (`None` for none);
    /// the member must be current (`is_current`). A member with no expiry can't be renewed:
    /// nothing is later than "never" (see the implementation notes).
    pub fn parse(
        mut fields: Obj,
        issued_ms: i64,
        is_current: bool,
        current_expiry: Option<i64>,
    ) -> Result<Self> {
        let mut sink = Unknown::default();
        let unknown = &mut sink;
        let member = fields.key_id("member")?;
        let (_, expires_ms) = fields.date("expires")?;
        let shares = parse_epochs(fields.array("shares")?, "shares", unknown)?;
        fields.finish(unknown);
        require(is_current, "renew of a member that isn't current")?;
        require(
            expires_ms > issued_ms,
            "renew expires must be later than issued",
        )?;
        let current =
            current_expiry.ok_or_else(|| malformed("renew of a member with no expiry"))?;
        require(expires_ms > current, "renew must extend the expiry")?;
        Ok(Self {
            member,
            expires_ms,
            shares,
            unknown: sink,
        })
    }
}

/// One `revoke.heads` item: a header of the member in a namespace (§9.5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RevokeHead {
    /// Namespace.
    pub namespace: String,
    /// Header body digest.
    pub digest: String,
}
/// A validated `revoke` (§9.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoke {
    /// The member.
    pub member: String,
    /// Kept header digests, sorted and distinct.
    pub kept: Vec<String>,
    /// Walk starting points, at most 16 per namespace.
    pub heads: Vec<RevokeHead>,
    /// New epochs.
    pub epochs: Vec<EpochSeals>,
    /// Unknown content.
    pub unknown: Unknown,
}
impl Revoke {
    /// Validate `revoke` fields (shapes only; the walk is the record layer's).
    pub fn parse(mut fields: Obj) -> Result<Self> {
        let mut sink = Unknown::default();
        let unknown = &mut sink;
        let member = fields.key_id("member")?;
        let kept = fields
            .array("kept")?
            .into_iter()
            .map(|v| match v {
                Value::String(s) if is_digest(&s) => Ok(s),
                _ => Err(malformed("kept entries must be digests")),
            })
            .collect::<Result<Vec<_>>>()?;
        require(
            kept.windows(2).all(|w| w[0] < w[1]),
            "kept must be sorted and distinct",
        )?;
        let mut heads = Vec::new();
        for item in fields.array("heads")? {
            let mut h = Obj::new(item, "heads[]")?;
            let namespace = h.string("namespace")?;
            require(valid_namespace(&namespace), "invalid namespace in heads")?;
            let digest = h.digest("digest")?;
            h.finish(unknown);
            heads.push(RevokeHead { namespace, digest });
        }
        require(
            heads.windows(2).all(|w| w[0] < w[1]),
            "heads must be sorted and distinct",
        )?;
        let mut per: BTreeMap<&str, usize> = BTreeMap::new();
        for h in &heads {
            *per.entry(&h.namespace).or_default() += 1;
        }
        require(
            per.values().all(|n| *n <= 16),
            "more than 16 heads in a namespace",
        )?;
        let epochs = parse_epochs(fields.array("epochs")?, "epochs", unknown)?;
        fields.finish(unknown);
        Ok(Self {
            member,
            kept,
            heads,
            epochs,
            unknown: sink,
        })
    }
}

/// Validate `endSessions` fields: exactly `member` (§9.6). Returns the member and any
/// unknown content.
pub fn parse_end_sessions(mut fields: Obj) -> Result<(String, Unknown)> {
    let mut unknown = Unknown::default();
    let member = fields.key_id("member")?;
    fields.finish(&mut unknown);
    Ok((member, unknown))
}

/// The kind of principal a key belongs to (§3.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Principal {
    /// A controller, by ID.
    Controller(String),
    /// A member, by ID.
    Member(String),
    /// A vault generation.
    Vault(u64),
}
/// How a point is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Usage {
    /// A signing point.
    Signing,
    /// An agreement point.
    Agreement,
}

/// Check §3.3 rule 2 over every key the history has used: each point and each key ID belongs
/// to exactly one principal and one usage, for ever. `uses` lists `(principal, usage, point)`
/// in history order; repeats by the same principal and usage are allowed (rule 3). In
/// particular no member key, of any kind (agents included), is ever a controller key (§9.7).
pub fn check_principals(uses: &[(Principal, Usage, Vec<u8>)]) -> Result<()> {
    let mut by_point: BTreeMap<&[u8], (&Principal, Usage)> = BTreeMap::new();
    let mut by_id: BTreeMap<String, (&Principal, Usage)> = BTreeMap::new();
    for (principal, usage, point) in uses {
        let owner = (principal, *usage);
        if let Some(prev) = by_point.insert(point, owner) {
            require(
                prev == owner,
                &format!("point reused across principals or usages: {prev:?} and {owner:?}"),
            )?;
        }
        if let Some(prev) = by_id.insert(key_id(point), owner) {
            require(prev == owner, "key ID reused across principals or usages")?;
        }
    }
    Ok(())
}

/// §9.7 as a checkable invariant over a keyring history and member set: no key that was ever
/// a member's (signing or agreement) is ever a controller's, and no controller key is ever
/// granted. `controllers` lists every controller descriptor ever present; `members` every
/// granted member's `(signing, agreement, kind)`.
pub fn check_members_never_controllers(
    controllers: &[super::descriptor::KeyDescriptor],
    members: &[(Vec<u8>, Vec<u8>, MemberKind)],
) -> Result<()> {
    let mut uses = Vec::new();
    for c in controllers {
        uses.push((
            Principal::Controller(c.id()),
            Usage::Signing,
            c.signing().to_vec(),
        ));
        if let Some(a) = c.agreement() {
            uses.push((Principal::Controller(c.id()), Usage::Agreement, a.to_vec()));
        }
    }
    for (signing, agreement, kind) in members {
        let id = key_id(signing);
        if controllers.iter().any(|c| {
            c.signing() == signing.as_slice()
                || c.agreement() == Some(signing.as_slice())
                || c.agreement() == Some(agreement.as_slice())
                || c.signing() == agreement.as_slice()
        }) {
            return Err(malformed(format!(
                "member {id} ({kind:?}) uses a controller key"
            )));
        }
        uses.push((
            Principal::Member(id.clone()),
            Usage::Signing,
            signing.clone(),
        ));
        uses.push((Principal::Member(id), Usage::Agreement, agreement.clone()));
    }
    check_principals(&uses)
}
