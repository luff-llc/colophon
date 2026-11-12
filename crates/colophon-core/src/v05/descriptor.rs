//! Key descriptors (§3.1), controllers (§6.1) and policy (§6.3).
//!
//! Every type here is sealed: fields are private, and values exist only through `parse` or a
//! validating constructor, so a value of these types always satisfies its section's rules.
//! Unknown content found while parsing is part of the value ([`KeyDescriptor::unknown`],
//! [`Controller::unknown`], [`Policy::unknown`]); it is never an out-parameter.
use super::encoding::{byte_len_in, Obj};
use super::ids::key_id;
use super::terms::valid_audience;
use super::{malformed, require, Result, Unknown};
use serde_json::Value;

/// A validated uncompressed P-256 point (65 bytes, `0x04 ‖ x ‖ y`, on the curve).
pub fn valid_point(bytes: &[u8]) -> bool {
    bytes.len() == 65 && bytes[0] == 4 && p256::PublicKey::from_sec1_bytes(bytes).is_ok()
}
fn point_field(obj: &mut Obj, field: &str) -> Result<Vec<u8>> {
    let path = obj.path_of(field);
    let bytes = obj.bytes(field, 65)?;
    require(valid_point(&bytes), &format!("invalid P-256 point: {path}"))?;
    Ok(bytes)
}

fn valid_label(label: &str) -> bool {
    byte_len_in(label, 1, 63)
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}
/// The `rp` grammar (§3.1): 1–253 bytes of dot-separated labels of 1–63 lowercase ASCII
/// letters, digits and `-`, no label starting or ending with `-`.
pub fn valid_rp(rp: &str) -> bool {
    byte_len_in(rp, 1, 253) && rp.split('.').all(valid_label)
}
/// A web origin (§3.1): `https://` followed by a host in the `rp` grammar and nothing else.
pub fn is_web_origin(origin: &str) -> bool {
    origin.strip_prefix("https://").is_some_and(valid_rp)
}
/// Printable ASCII (§2.2): bytes 0x21–0x7E; space is not printable.
pub fn is_printable(s: &str) -> bool {
    s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
/// A platform origin (§3.1): 1–512 printable ASCII bytes not starting with `http:` or `https:`.
pub fn is_platform_origin(origin: &str) -> bool {
    byte_len_in(origin, 1, 512)
        && is_printable(origin)
        && !origin.starts_with("http:")
        && !origin.starts_with("https:")
}

/// §4.3's general rule: `origin` is in `origins`, or is `https://` followed by a host with no
/// port, path, query, fragment or user information that equals `rp` or is a subdomain of it.
///
/// The text only forbids `/ : ? # @ \`, empty labels and leading or trailing dots in the
/// prefix. This implementation takes the safe reading the attack review asked for: the whole
/// host must follow the `rp` label grammar, so the prefix can't carry uppercase, `_`, `%`,
/// spaces or other bytes a browser would never report (see the implementation notes).
pub fn general_origin_allowed(origin: &str, rp: &str, origins: &[String]) -> bool {
    if origins.iter().any(|o| o == origin) {
        return true;
    }
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    if !valid_rp(host) {
        return false;
    }
    if host == rp {
        return true;
    }
    host.strip_suffix(rp)
        .and_then(|p| p.strip_suffix('.'))
        .is_some_and(|prefix| !prefix.is_empty() && prefix.split('.').all(valid_label))
}

/// WebAuthn descriptor fields (§3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnKey {
    rp: String,
    credential: Vec<u8>,
    origins: Option<Vec<String>>,
    authority_origins: Option<Vec<String>>,
}
impl WebAuthnKey {
    /// Validate and build the WebAuthn fields: the `rp` grammar, a 1–1,023-byte credential, and
    /// `origins` and `authorityOrigins` of 1–32 strictly ascending entries, each `origins`
    /// entry a web or platform origin and each `authorityOrigins` entry allowed by the general
    /// rule.
    pub fn new(
        rp: String,
        credential: Vec<u8>,
        origins: Option<Vec<String>>,
        authority_origins: Option<Vec<String>>,
    ) -> Result<Self> {
        require(valid_rp(&rp), "invalid rp")?;
        require(
            (1..=1023).contains(&credential.len()),
            "credential must be 1–1,023 bytes",
        )?;
        for (name, list) in [
            ("origins", &origins),
            ("authorityOrigins", &authority_origins),
        ] {
            if let Some(list) = list {
                require(
                    (1..=32).contains(&list.len()),
                    &format!("{name} must have 1–32 entries"),
                )?;
                require(
                    list.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()),
                    &format!("{name} must be distinct and strictly ascending"),
                )?;
            }
        }
        for o in origins.iter().flatten() {
            require(
                is_web_origin(o) || is_platform_origin(o),
                "invalid entry in origins",
            )?;
        }
        let extra = origins.as_deref().unwrap_or(&[]);
        for o in authority_origins.iter().flatten() {
            require(
                general_origin_allowed(o, &rp, extra),
                "authorityOrigins entry not allowed by the general rule",
            )?;
        }
        Ok(Self {
            rp,
            credential,
            origins,
            authority_origins,
        })
    }
    /// The relying-party ID.
    pub fn rp(&self) -> &str {
        &self.rp
    }
    /// The credential hint.
    pub fn credential(&self) -> &[u8] {
        &self.credential
    }
    /// `origins`, or empty.
    pub fn origins(&self) -> &[String] {
        self.origins.as_deref().unwrap_or(&[])
    }
    /// `authorityOrigins`, when present.
    pub fn authority_origins(&self) -> Option<&[String]> {
        self.authority_origins.as_deref()
    }
    /// §4.3 authority origins: in `authorityOrigins` when present, else exactly `https://<rp>`
    /// or a platform origin listed in `origins`.
    pub fn authority_origin_allowed(&self, origin: &str) -> bool {
        match &self.authority_origins {
            Some(list) => list.iter().any(|o| o == origin),
            None => {
                origin.strip_prefix("https://") == Some(self.rp.as_str())
                    || (is_platform_origin(origin) && self.origins().iter().any(|o| o == origin))
            }
        }
    }
}

/// The form-specific part of a descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyForm {
    /// `raw`: ES256 over the exact body, with an optional agreement point.
    Raw {
        /// A separate 65-byte agreement point.
        agreement: Option<Vec<u8>>,
    },
    /// `webauthn`: assertions under a relying-party ID.
    WebAuthn(WebAuthnKey),
    /// A form this reader doesn't know. A signature by such a key can't be decided: it is
    /// `newerFormat`, but only once every other check has passed (§1).
    Unknown(String),
}

/// A validated key descriptor (§3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDescriptor {
    signing: Vec<u8>,
    form: KeyForm,
    unknown: Unknown,
}
impl KeyDescriptor {
    /// A `raw` descriptor. `agreement`, when present, must be a valid point other than
    /// `signing` (§3.3 rule 1).
    pub fn new_raw(signing: Vec<u8>, agreement: Option<Vec<u8>>) -> Result<Self> {
        require(valid_point(&signing), "invalid signing point")?;
        if let Some(a) = &agreement {
            require(valid_point(a), "invalid agreement point")?;
            require(a != &signing, "signing equals agreement (§3.3 rule 1)")?;
        }
        Ok(Self {
            signing,
            form: KeyForm::Raw { agreement },
            unknown: Unknown::default(),
        })
    }
    /// A `webauthn` descriptor.
    pub fn new_webauthn(signing: Vec<u8>, key: WebAuthnKey) -> Result<Self> {
        require(valid_point(&signing), "invalid signing point")?;
        Ok(Self {
            signing,
            form: KeyForm::WebAuthn(key),
            unknown: Unknown::default(),
        })
    }
    /// The 65-byte signing point.
    pub fn signing(&self) -> &[u8] {
        &self.signing
    }
    /// The form.
    pub fn form(&self) -> &KeyForm {
        &self.form
    }
    /// The key ID (first 32 hex of SHA-256 of `signing`).
    pub fn id(&self) -> String {
        key_id(&self.signing)
    }
    /// The WebAuthn fields, when the form is `webauthn`.
    pub fn webauthn(&self) -> Option<&WebAuthnKey> {
        match &self.form {
            KeyForm::WebAuthn(w) => Some(w),
            _ => None,
        }
    }
    /// The agreement point of a `raw` key.
    pub fn agreement(&self) -> Option<&[u8]> {
        match &self.form {
            KeyForm::Raw { agreement } => agreement.as_deref(),
            _ => None,
        }
    }
    /// True when the form is unknown to this reader.
    pub fn is_unknown_form(&self) -> bool {
        matches!(self.form, KeyForm::Unknown(_))
    }
    /// Unknown content in the descriptor (unknown form or fields).
    pub fn unknown(&self) -> &Unknown {
        &self.unknown
    }
    /// Parse and validate a descriptor. Known fields are checked as they are read; unknown
    /// fields and an unknown `form` are kept as unknown content, never an early error (§1).
    pub fn parse(value: Value, path: &str) -> Result<Self> {
        let mut unknown = Unknown::default();
        let mut o = Obj::new(value, path)?;
        let form = o.string("form")?;
        let signing = point_field(&mut o, "signing")?;
        let form = match form.as_str() {
            "raw" => {
                for f in ["rp", "credential", "origins", "authorityOrigins"] {
                    require(!o.has(f), &format!("{f} on a raw key"))?;
                }
                let agreement = if o.has("agreement") {
                    let a = point_field(&mut o, "agreement")?;
                    require(a != signing, "signing equals agreement (§3.3 rule 1)")?;
                    Some(a)
                } else {
                    None
                };
                KeyForm::Raw { agreement }
            }
            "webauthn" => {
                require(!o.has("agreement"), "agreement on a webauthn key")?;
                let rp = o.string("rp")?;
                let credential = o.bytes("credential", 1023)?;
                let origins = origin_list(&mut o, "origins")?;
                let authority = origin_list(&mut o, "authorityOrigins")?;
                KeyForm::WebAuthn(WebAuthnKey::new(rp, credential, origins, authority)?)
            }
            other => {
                unknown.push(format!("{path}.form={other}"));
                KeyForm::Unknown(other.into())
            }
        };
        o.finish(&mut unknown);
        Ok(Self {
            signing,
            form,
            unknown,
        })
    }
}
fn origin_list(o: &mut Obj, field: &str) -> Result<Option<Vec<String>>> {
    let Some(items) = o.opt_value(field)? else {
        return Ok(None);
    };
    let Value::Array(items) = items else {
        return Err(malformed(format!("{field} must be an array")));
    };
    items
        .into_iter()
        .map(|v| match v {
            Value::String(s) => Ok(s),
            _ => Err(malformed(format!("{field} entries must be strings"))),
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// A controller role (§6.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Admit, renew and revoke members, end sessions, introduce epochs.
    Approve,
    /// Propose and veto transitions; immediate additive entries; suspend.
    Control,
    /// Propose recovery transitions; consent; veto; suspend; read the history.
    Recover,
    /// Sign calls at the listed audiences only.
    Sign,
    /// A role this reader doesn't know (unknown content).
    Unknown(String),
}
impl Role {
    fn parse(s: &str) -> Self {
        match s {
            "approve" => Self::Approve,
            "control" => Self::Control,
            "recover" => Self::Recover,
            "sign" => Self::Sign,
            other => Self::Unknown(other.into()),
        }
    }
}

/// A controller (§6.1). Its ID is its key ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Controller {
    key: KeyDescriptor,
    label: String,
    roles: Vec<Role>,
    verification: bool,
    holder: Option<String>,
    audiences: Option<Vec<String>>,
    unknown: Unknown,
}
impl Controller {
    /// The controller ID.
    pub fn id(&self) -> String {
        self.key.id()
    }
    /// The key descriptor.
    pub fn key(&self) -> &KeyDescriptor {
        &self.key
    }
    /// The display label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Sorted, distinct roles.
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }
    /// True when the controller holds `role`.
    pub fn has(&self, role: &Role) -> bool {
        self.roles.contains(role)
    }
    /// `true` when every signature needs UV.
    pub fn verification(&self) -> bool {
        self.verification
    }
    /// The holder label.
    pub fn holder(&self) -> Option<&str> {
        self.holder.as_deref()
    }
    /// Audiences of a `sign` controller.
    pub fn audiences(&self) -> Option<&[String]> {
        self.audiences.as_deref()
    }
    /// Unknown content: unknown fields, roles, and the descriptor's unknown content.
    pub fn unknown(&self) -> &Unknown {
        &self.unknown
    }
    /// Parse and validate a controller object (§6.1).
    pub fn parse(value: Value, path: &str) -> Result<Self> {
        let mut o = Obj::new(value, path)?;
        let key = KeyDescriptor::parse(o.value("key")?, &o.path_of("key"))?;
        let mut unknown = key.unknown().clone();
        let label = o.string("label")?;
        require(byte_len_in(&label, 1, 200), "label must be 1–200 bytes")?;
        let raw_roles = o.array("roles")?;
        require(!raw_roles.is_empty(), "roles must not be empty")?;
        let mut names = Vec::with_capacity(raw_roles.len());
        for r in raw_roles {
            match r {
                Value::String(s) => names.push(s),
                _ => return Err(malformed("roles must be strings")),
            }
        }
        require(
            names.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()),
            "roles must be sorted and distinct",
        )?;
        let roles: Vec<Role> = names.iter().map(|s| Role::parse(s)).collect();
        for r in &roles {
            if let Role::Unknown(name) = r {
                unknown.push(format!("{path}.roles:{name}"));
            }
        }
        if roles.contains(&Role::Sign) {
            require(roles.len() == 1, "sign must appear alone")?;
        }
        let verification = match o.opt_value("verification")? {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(malformed("verification is present only as true")),
        };
        if verification {
            require(
                !matches!(key.form(), KeyForm::Raw { .. }),
                "verification on a raw key",
            )?;
        }
        let holder = o.opt_string("holder")?;
        if let Some(h) = &holder {
            require(byte_len_in(h, 1, 64), "holder must be 1–64 bytes")?;
        }
        let audiences = match o.opt_value("audiences")? {
            None => None,
            Some(Value::Array(items)) => {
                require(
                    (1..=32).contains(&items.len()),
                    "audiences must have 1–32 entries",
                )?;
                let list = items
                    .into_iter()
                    .map(|v| match v {
                        Value::String(s) if valid_audience(&s) => Ok(s),
                        _ => Err(malformed("invalid audience")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                require(
                    list.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()),
                    "audiences must be sorted and distinct",
                )?;
                Some(list)
            }
            Some(_) => return Err(malformed("audiences must be an array")),
        };
        require(
            audiences.is_some() == (roles == [Role::Sign]),
            "audiences present if and only if roles are [\"sign\"]",
        )?;
        o.finish(&mut unknown);
        Ok(Self {
            key,
            label,
            roles,
            verification,
            holder,
            audiences,
            unknown,
        })
    }
}

/// `policy.history` (§6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryAccess {
    /// Served to members and authorized callers.
    Members,
    /// Served to anyone.
    Public,
}
/// `policy.memberRule` (§6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRule {
    /// One `approve` signer.
    Single,
    /// The control rule.
    Control,
}
/// One half of `policy.rate` (§6.3): immediate entries and bytes per 24 hours of `issued`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    entries: u64,
    bytes: u64,
}
impl RateLimit {
    /// Entries per 24 hours.
    pub fn entries(&self) -> u64 {
        self.entries
    }
    /// Envelope bytes per 24 hours.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}
const MIB: u64 = 1024 * 1024;

/// Account policy (§6.3). Every value satisfies the §6.3 ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    call_window: u64,
    head_max_age: u64,
    head_quorum: u64,
    history: HistoryAccess,
    link_max_age: u64,
    member_rule: MemberRule,
    primary_home: Option<String>,
    rate_signer: RateLimit,
    rate_account: RateLimit,
    recovery_delay: u64,
    unknown: Unknown,
}
impl Policy {
    /// The §18 person defaults with no primary home.
    pub fn default_person() -> Self {
        Self {
            call_window: 300,
            head_max_age: 300,
            head_quorum: 1,
            history: HistoryAccess::Members,
            link_max_age: 86_400,
            member_rule: MemberRule::Single,
            primary_home: None,
            rate_signer: RateLimit {
                entries: 64,
                bytes: 4 * MIB,
            },
            rate_account: RateLimit {
                entries: 256,
                bytes: 16 * MIB,
            },
            recovery_delay: 259_200,
            unknown: Unknown::default(),
        }
    }
    /// Seconds a call's `created` may differ from the clock (30–3,600).
    pub fn call_window(&self) -> u64 {
        self.call_window
    }
    /// Seconds a head stays fresh (30–86,400).
    pub fn head_max_age(&self) -> u64 {
        self.head_max_age
    }
    /// Distinct homes whose fresh heads are needed (1–8).
    pub fn head_quorum(&self) -> u64 {
        self.head_quorum
    }
    /// `history`.
    pub fn history(&self) -> HistoryAccess {
        self.history
    }
    /// Most seconds from a link's `notBefore` to `expires` (60–2,592,000).
    pub fn link_max_age(&self) -> u64 {
        self.link_max_age
    }
    /// `memberRule`.
    pub fn member_rule(&self) -> MemberRule {
        self.member_rule
    }
    /// The primary home's member ID.
    pub fn primary_home(&self) -> Option<&str> {
        self.primary_home.as_deref()
    }
    /// `rate.signer`.
    pub fn rate_signer(&self) -> RateLimit {
        self.rate_signer
    }
    /// `rate.account`.
    pub fn rate_account(&self) -> RateLimit {
        self.rate_account
    }
    /// Seconds a pending transition waits for a veto (0–2,592,000).
    pub fn recovery_delay(&self) -> u64 {
        self.recovery_delay
    }
    /// Unknown content (unknown fields or values).
    pub fn unknown(&self) -> &Unknown {
        &self.unknown
    }
    /// Parse a policy with its field ranges (§6.3). The cross-field rules that need the
    /// account's homes are [`Policy::check_homes`].
    pub fn parse(value: Value, path: &str) -> Result<Self> {
        let mut unknown = Unknown::default();
        let mut o = Obj::new(value, path)?;
        fn ranged(o: &mut Obj, f: &str, lo: u64, hi: u64) -> Result<u64> {
            let v = o.uint(f)?;
            require(
                (lo..=hi).contains(&v),
                &format!("{} out of range", o.path_of(f)),
            )?;
            Ok(v)
        }
        let call_window = ranged(&mut o, "callWindow", 30, 3_600)?;
        let head_max_age = ranged(&mut o, "headMaxAge", 30, 86_400)?;
        let head_quorum = ranged(&mut o, "headQuorum", 1, 8)?;
        let link_max_age = ranged(&mut o, "linkMaxAge", 60, 2_592_000)?;
        let recovery_delay = ranged(&mut o, "recoveryDelay", 0, 2_592_000)?;
        let history = match o.string("history")?.as_str() {
            "members" => HistoryAccess::Members,
            "public" => HistoryAccess::Public,
            other => {
                unknown.push(format!("{path}.history={other}"));
                HistoryAccess::Members
            }
        };
        let member_rule = match o.string("memberRule")?.as_str() {
            "single" => MemberRule::Single,
            "control" => MemberRule::Control,
            other => {
                unknown.push(format!("{path}.memberRule={other}"));
                MemberRule::Control
            }
        };
        let primary_home = o.opt_string("primaryHome")?;
        if let Some(h) = &primary_home {
            require(super::ids::is_key_id(h), "primaryHome is not a member ID")?;
        }
        let mut rate = o.obj("rate")?;
        let mut signer = rate.obj("signer")?;
        let rate_signer = RateLimit {
            entries: ranged(&mut signer, "entries", 16, 1_024)?,
            bytes: ranged(&mut signer, "bytes", MIB, 64 * MIB)?,
        };
        signer.finish(&mut unknown);
        let mut account = rate.obj("account")?;
        let rate_account = RateLimit {
            entries: ranged(&mut account, "entries", 64, 4_096)?,
            bytes: ranged(&mut account, "bytes", 4 * MIB, 256 * MIB)?,
        };
        account.finish(&mut unknown);
        rate.finish(&mut unknown);
        o.finish(&mut unknown);
        Ok(Self {
            call_window,
            head_max_age,
            head_quorum,
            history,
            link_max_age,
            member_rule,
            primary_home,
            rate_signer,
            rate_account,
            recovery_delay,
            unknown,
        })
    }
    /// The §6.3 rules that depend on the current homes.
    pub fn check_homes(&self, current_homes: &[String]) -> Result<()> {
        if !current_homes.is_empty() {
            require(
                self.recovery_delay >= 3_600,
                "recoveryDelay below 3,600 with a home",
            )?;
            require(
                current_homes.len() as u64 >= self.head_quorum,
                "fewer current homes than headQuorum",
            )?;
        }
        if let Some(h) = &self.primary_home {
            require(
                current_homes.contains(h),
                "primaryHome is not a current home",
            )?;
        }
        Ok(())
    }
    /// The field-wise stricter of two policies for calls (§12.3 step 5): `callWindow` and
    /// `linkMaxAge` at S made stricter by every later held policy.
    pub fn restrict_for_calls(&self, later: &Policy) -> Policy {
        Policy {
            call_window: self.call_window.min(later.call_window),
            link_max_age: self.link_max_age.min(later.link_max_age),
            ..self.clone()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn rp_and_origin_grammar() {
        assert!(valid_rp("id.luff.works"));
        assert!(valid_rp("a"));
        for bad in [
            "",
            "ID.luff",
            "-a.b",
            "a-.b",
            "a..b",
            ".a",
            "a.",
            "a_b",
            &"a".repeat(64),
        ] {
            assert!(!valid_rp(bad), "{bad}");
        }
        assert!(is_web_origin("https://keys.id.example"));
        assert!(!is_web_origin("https://keys.id.example/"));
        assert!(!is_web_origin("https://keys.id.example:443"));
        assert!(is_platform_origin("android:apk-key-hash:abc"));
        assert!(!is_platform_origin("http://x"));
        assert!(!is_platform_origin("https:x"));
        assert!(!is_platform_origin("a b"));
        let rp = "id.example";
        for ok in [
            "https://id.example",
            "https://a.id.example",
            "https://a.b.id.example",
        ] {
            assert!(general_origin_allowed(ok, rp, &[]), "{ok}");
        }
        for bad in [
            "https://xid.example",
            "https://.id.example",
            "https://a..id.example",
            "https://id.example:443",
            "https://id.example/",
            "https://u@id.example",
            "http://id.example",
            "https://id.example.evil",
            "https://a.id.example?x",
            "https://a.id.example#x",
            "https://a\\.id.example",
            "https://A.id.example",
            "https://a_b.id.example",
            "https://a%2e.id.example",
            "https://-a.id.example",
            "https://a b.id.example",
            "https://id.example.",
        ] {
            assert!(!general_origin_allowed(bad, rp, &[]), "{bad}");
        }
        assert!(general_origin_allowed(
            "ios:bundle",
            rp,
            &["ios:bundle".into()]
        ));
    }
    #[test]
    fn unknown_form_is_content_not_an_error() {
        let p = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let point = p
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        use base64::Engine;
        let s = base64::engine::general_purpose::STANDARD.encode(point);
        let d = KeyDescriptor::parse(
            serde_json::json!({"form":"future","signing":s,"x":1}),
            "key",
        )
        .unwrap();
        assert!(d.is_unknown_form());
        assert_eq!(d.unknown().0.len(), 2);
        assert!(
            KeyDescriptor::parse(serde_json::json!({"form":"future","signing":"AA=="}), "key")
                .is_err()
        );
    }
}
