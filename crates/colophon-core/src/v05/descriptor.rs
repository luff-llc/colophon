//! Key descriptors (§3.1), controllers (§6.1) and policy (§6.3).
use super::encoding::{byte_len_in, Obj};
use super::ids::key_id;
use super::terms::valid_audience;
use super::{malformed, require, Failure, Result, Unknown};
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

/// The `rp` grammar (§3.1): 1–253 bytes of dot-separated labels of 1–63 lowercase ASCII
/// letters, digits and `-`, no label starting or ending with `-`.
pub fn valid_rp(rp: &str) -> bool {
    byte_len_in(rp, 1, 253)
        && rp.split('.').all(|label| {
            byte_len_in(label, 1, 63)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}
/// A web origin (§3.1): `https://` followed by a host in the `rp` grammar and nothing else.
pub fn is_web_origin(origin: &str) -> bool {
    origin.strip_prefix("https://").is_some_and(valid_rp)
}
/// A platform origin (§3.1): 1–512 printable ASCII bytes not starting with `http:` or
/// `https:`. "Printable" is read as 0x21–0x7E (no space); see the implementation notes.
pub fn is_platform_origin(origin: &str) -> bool {
    byte_len_in(origin, 1, 512)
        && origin.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !origin.starts_with("http:")
        && !origin.starts_with("https:")
}

/// §4.3's general rule: `origin` is in `origins`, or is `https://` followed by a host with no
/// port, path, query, fragment or user information that equals `rp` or is a subdomain of it.
pub fn general_origin_allowed(origin: &str, rp: &str, origins: &[String]) -> bool {
    if origins.iter().any(|o| o == origin) {
        return true;
    }
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    if host.bytes().any(|b| b"/:?#@\\".contains(&b)) {
        return false;
    }
    if host == rp {
        return true;
    }
    match host.strip_suffix(rp).and_then(|p| p.strip_suffix('.')) {
        Some(prefix) => {
            !prefix.is_empty()
                && !prefix.starts_with('.')
                && !prefix.ends_with('.')
                && !prefix.contains("..")
        }
        None => false,
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
}
/// WebAuthn descriptor fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnKey {
    /// The relying-party ID.
    pub rp: String,
    /// A lookup hint; never affects verification.
    pub credential: Vec<u8>,
    /// Extra allowed origins (web or platform), strictly ascending.
    pub origins: Option<Vec<String>>,
    /// The only origins allowed for authority signatures, when present.
    pub authority_origins: Option<Vec<String>>,
}
impl WebAuthnKey {
    /// `origins`, or empty.
    pub fn origins(&self) -> &[String] {
        self.origins.as_deref().unwrap_or(&[])
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

/// A validated key descriptor (§3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDescriptor {
    /// The 65-byte signing point.
    pub signing: Vec<u8>,
    /// Form-specific fields.
    pub form: KeyForm,
}
impl KeyDescriptor {
    /// The key ID (first 32 hex of SHA-256 of `signing`).
    pub fn id(&self) -> String {
        key_id(&self.signing)
    }
    /// The WebAuthn fields, when the form is `webauthn`.
    pub fn webauthn(&self) -> Option<&WebAuthnKey> {
        match &self.form {
            KeyForm::WebAuthn(w) => Some(w),
            KeyForm::Raw { .. } => None,
        }
    }
    /// The agreement point of a `raw` key.
    pub fn agreement(&self) -> Option<&[u8]> {
        match &self.form {
            KeyForm::Raw { agreement } => agreement.as_deref(),
            KeyForm::WebAuthn(_) => None,
        }
    }
    /// Parse and validate a descriptor. Unknown fields go to `unknown`. An unknown `form` is
    /// `newerFormat` at once: there is no key to verify with (see the implementation notes).
    pub fn parse(value: Value, path: &str, unknown: &mut Unknown) -> Result<Self> {
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
                require(valid_rp(&rp), "invalid rp")?;
                let credential = o.bytes("credential", 1023)?;
                require(!credential.is_empty(), "empty credential")?;
                let origins = origin_list(&mut o, "origins")?;
                if let Some(list) = &origins {
                    for origin in list {
                        require(
                            is_web_origin(origin) || is_platform_origin(origin),
                            "invalid entry in origins",
                        )?;
                    }
                }
                let authority_origins = origin_list(&mut o, "authorityOrigins")?;
                if let Some(list) = &authority_origins {
                    let extra = origins.as_deref().unwrap_or(&[]);
                    for origin in list {
                        require(
                            general_origin_allowed(origin, &rp, extra),
                            "authorityOrigins entry not allowed by the general rule",
                        )?;
                    }
                }
                KeyForm::WebAuthn(WebAuthnKey {
                    rp,
                    credential,
                    origins,
                    authority_origins,
                })
            }
            other => return Err(Failure::NewerFormat(format!("unknown key form: {other}"))),
        };
        o.finish(unknown);
        Ok(Self { signing, form })
    }
}
fn origin_list(o: &mut Obj, field: &str) -> Result<Option<Vec<String>>> {
    let Some(items) = o.opt_value(field)? else {
        return Ok(None);
    };
    let Value::Array(items) = items else {
        return Err(malformed(format!("{field} must be an array")));
    };
    require(
        (1..=32).contains(&items.len()),
        &format!("{field} must have 1–32 entries"),
    )?;
    let list = items
        .into_iter()
        .map(|v| match v {
            Value::String(s) => Ok(s),
            _ => Err(malformed(format!("{field} entries must be strings"))),
        })
        .collect::<Result<Vec<_>>>()?;
    require(
        list.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()),
        &format!("{field} must be distinct and strictly ascending"),
    )?;
    Ok(Some(list))
}

/// A controller role (§6.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Admit, renew and revoke members, end sessions, introduce epochs.
    Approve,
    /// Propose transitions under the control rule; immediate additive changes; veto.
    Control,
    /// Propose recovery transitions; consent to recovery-set changes; veto.
    Recover,
    /// Sign calls at the listed audiences only.
    Sign,
    /// A role this reader doesn't know (reported as unknown content).
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
    /// The key descriptor.
    pub key: KeyDescriptor,
    /// Display label, 1–200 bytes.
    pub label: String,
    /// Sorted, distinct roles.
    pub roles: Vec<Role>,
    /// `true` when every signature needs UV (`webauthn` only).
    pub verification: bool,
    /// The holder label, 1–64 bytes.
    pub holder: Option<String>,
    /// Audiences of a `sign` controller.
    pub audiences: Option<Vec<String>>,
}
impl Controller {
    /// The controller ID.
    pub fn id(&self) -> String {
        self.key.id()
    }
    /// True when the controller holds `role`.
    pub fn has(&self, role: &Role) -> bool {
        self.roles.contains(role)
    }
    /// Parse and validate a controller object. Unknown fields and roles go to `unknown`.
    pub fn parse(value: Value, path: &str, unknown: &mut Unknown) -> Result<Self> {
        let mut o = Obj::new(value, path)?;
        let key = KeyDescriptor::parse(o.value("key")?, &o.path_of("key"), unknown)?;
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
            require(key.webauthn().is_some(), "verification on a raw key")?;
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
        o.finish(unknown);
        Ok(Self {
            key,
            label,
            roles,
            verification,
            holder,
            audiences,
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
/// Account policy (§6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Seconds a call's `created` may differ from the clock: 30–3,600.
    pub call_window: u64,
    /// Seconds a head stays fresh: 30–86,400.
    pub head_max_age: u64,
    /// Distinct homes whose fresh heads are needed: 1–8.
    pub head_quorum: u64,
    /// Who a home serves history to.
    pub history: HistoryAccess,
    /// Most seconds from a link's `notBefore` to `expires`: 60–2,592,000.
    pub link_max_age: u64,
    /// `single` or `control`.
    pub member_rule: MemberRule,
    /// The primary home's member ID.
    pub primary_home: Option<String>,
    /// Seconds a pending transition waits for a veto: 0–2,592,000.
    pub recovery_delay: u64,
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
            recovery_delay: 259_200,
        }
    }
    /// Parse a policy with its field ranges (§6.3). The cross-field rules that need the
    /// account's homes (`recoveryDelay` ≥ 3,600 with a home, `headQuorum` ≤ homes,
    /// `primaryHome` a current home) are checked by [`Policy::check_homes`].
    pub fn parse(value: Value, path: &str, unknown: &mut Unknown) -> Result<Self> {
        let mut o = Obj::new(value, path)?;
        let ranged = |o: &mut Obj, f: &str, lo: u64, hi: u64| -> Result<u64> {
            let v = o.uint(f)?;
            require((lo..=hi).contains(&v), &format!("policy.{f} out of range"))?;
            Ok(v)
        };
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
        o.finish(unknown);
        Ok(Self {
            call_window,
            head_max_age,
            head_quorum,
            history,
            link_max_age,
            member_rule,
            primary_home,
            recovery_delay,
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
    /// The field-wise more restrictive of two policies, for calls (§12.3 step 5: policy
    /// changes that shorten or restrict apply at once).
    pub fn restrict(&self, later: &Policy) -> Policy {
        Policy {
            call_window: self.call_window.min(later.call_window),
            head_max_age: self.head_max_age.min(later.head_max_age),
            head_quorum: self.head_quorum.max(later.head_quorum),
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
        ] {
            assert!(!general_origin_allowed(bad, rp, &[]), "{bad}");
        }
        assert!(general_origin_allowed(
            "ios:bundle",
            rp,
            &["ios:bundle".into()]
        ));
    }
}
