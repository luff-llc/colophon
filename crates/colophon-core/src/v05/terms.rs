//! Terms (§10): fields, conditions, narrowing and request coverage.
use super::encoding::{byte_len_in, canonical, compare_numbers, date, Obj};
use super::{malformed, require, Result, Unknown};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Namespace grammar (§8.2): 1–128 bytes of lowercase ASCII letters, digits, `.` and `_`.
pub fn valid_namespace(s: &str) -> bool {
    byte_len_in(s, 1, 128)
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
}
/// Record kind grammar (§10.1): 1–128 bytes of `A–Z a–z 0–9 . _ -`.
pub fn valid_kind(s: &str) -> bool {
    byte_len_in(s, 1, 128)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}
/// Purpose grammar (§10.1): 1–128 bytes of `A–Z a–z 0–9 . _ : / -`.
pub fn valid_purpose(s: &str) -> bool {
    byte_len_in(s, 1, 128)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:_/-".contains(&b))
}
/// Audience grammar (§10.1): 1–512 printable ASCII bytes, either an `https://` URL whose
/// host follows the `rp` grammar, with an optional path and no port, query, fragment or user
/// information, or a `urn:` URI.
pub fn valid_audience(s: &str) -> bool {
    if !byte_len_in(s, 1, 512) || !super::descriptor::is_printable(s) {
        return false;
    }
    if let Some(rest) = s.strip_prefix("https://") {
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        return super::descriptor::valid_rp(host) && !path.bytes().any(|b| b"?#@\\".contains(&b));
    }
    s.strip_prefix("urn:").is_some_and(|r| !r.is_empty())
}

/// Record access (`write` ⊃ `propose` ⊃ `read`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    /// Read.
    Read,
    /// Read and propose.
    Propose,
    /// Read, propose and write.
    Write,
}
/// One `records` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsEntry {
    /// Namespace.
    pub namespace: String,
    /// Access level.
    pub access: Access,
    /// Allowed record kinds, when restricted.
    pub kinds: Option<Vec<String>>,
}
/// One `services` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicesEntry {
    /// The audience.
    pub audience: String,
    /// `None` for `["*"]`; otherwise the distinct purposes.
    pub purposes: Option<Vec<String>>,
}
impl ServicesEntry {
    /// True when this entry allows `purpose`.
    pub fn allows(&self, purpose: &str) -> bool {
        self.purposes
            .as_ref()
            .is_none_or(|list| list.iter().any(|p| p == purpose))
    }
    /// True when this entry's purposes include all of `other`'s (`["*"]` needs `["*"]`).
    pub fn covers(&self, other: &ServicesEntry) -> bool {
        match (&self.purposes, &other.purposes) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(mine), Some(theirs)) => theirs.iter().all(|p| mine.contains(p)),
        }
    }
}

/// A condition path: 1–8 dotted member names of 1–64 bytes, a leading `args.` dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CondPath(pub Vec<String>);
impl CondPath {
    fn parse(value: &Value) -> Result<Self> {
        let Value::String(s) = value else {
            return Err(malformed("condition path must be a string"));
        };
        let segments: Vec<&str> = s.split('.').collect();
        require(
            (1..=8).contains(&segments.len()),
            "condition path must have 1–8 segments",
        )?;
        require(
            segments.iter().all(|seg| byte_len_in(seg, 1, 64)),
            "condition path segments must be 1–64 bytes",
        )?;
        let start = usize::from(segments.len() > 1 && segments[0] == "args");
        Ok(Self(
            segments[start..].iter().map(|s| (*s).to_string()).collect(),
        ))
    }
    fn lookup<'a>(&self, root: &'a Value) -> Option<&'a Value> {
        self.0
            .iter()
            .try_fold(root, |v, seg| v.as_object()?.get(seg))
    }
}

/// A three-valued condition result (§10.4, revision 6). `False` is `refused:outOfScope` at
/// §12.3 step 7; `Unknown` (an unknown operator decided the result) passes step 7 and is
/// `newerFormat` at step 8. It is the return value of evaluation, so no caller can drop it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Truth {
    /// Holds.
    True,
    /// Doesn't hold.
    False,
    /// Undecidable by this reader: an unknown operator.
    Unknown,
}
impl Truth {
    fn of(b: bool) -> Self {
        if b {
            Self::True
        } else {
            Self::False
        }
    }
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
    /// `all`: false if any is false, else unknown if any is, else true.
    pub fn all(items: impl IntoIterator<Item = Truth>) -> Self {
        let mut unknown = false;
        for t in items {
            match t {
                Self::False => return Self::False,
                Self::Unknown => unknown = true,
                Self::True => {}
            }
        }
        if unknown {
            Self::Unknown
        } else {
            Self::True
        }
    }
    /// `any`: true if any is true, else unknown if any is, else false.
    pub fn any(items: impl IntoIterator<Item = Truth>) -> Self {
        let mut unknown = false;
        for t in items {
            match t {
                Self::True => return Self::True,
                Self::Unknown => unknown = true,
                Self::False => {}
            }
        }
        if unknown {
            Self::Unknown
        } else {
            Self::False
        }
    }
}

/// A condition predicate (§10.4).
#[derive(Clone, Debug, PartialEq)]
pub enum Predicate {
    /// Equal by canonical bytes.
    Eq(CondPath, Vec<u8>),
    /// Equal to one of the values, by canonical bytes.
    In(CondPath, Vec<Vec<u8>>),
    /// Both strings and the value starts with the prefix.
    Prefix(CondPath, String),
    /// Both numbers and the value is ≤ the bound.
    Lte(CondPath, Number),
    /// Both numbers and the value is ≥ the bound.
    Gte(CondPath, Number),
    /// Every predicate holds (empty: true).
    All(Vec<Predicate>),
    /// Some predicate holds (empty: false).
    Any(Vec<Predicate>),
    /// The predicate does not hold.
    Not(Box<Predicate>),
    /// An operator this reader doesn't know (reported as unknown content; see notes).
    Unknown(String),
}
impl Predicate {
    fn parse(value: Value, depth: usize, count: &mut usize, unknown: &mut Unknown) -> Result<Self> {
        *count += 1;
        require(*count <= 32, "more than 32 predicates")?;
        require(depth <= 4, "predicates nested more than 4 deep")?;
        let Value::Object(map) = value else {
            return Err(malformed("predicate must be an object"));
        };
        require(map.len() == 1, "predicate must have exactly one operator")?;
        let Some((op, arg)) = map.into_iter().next() else {
            return Err(malformed("empty predicate"));
        };
        let pair = |arg: Value| -> Result<(Value, Value)> {
            match arg {
                Value::Array(mut v) if v.len() == 2 => {
                    let b = v.pop().unwrap_or(Value::Null);
                    let a = v.pop().unwrap_or(Value::Null);
                    Ok((a, b))
                }
                _ => Err(malformed("leaf predicate needs [path, value]")),
            }
        };
        Ok(match op.as_str() {
            "eq" => {
                let (p, v) = pair(arg)?;
                Self::Eq(CondPath::parse(&p)?, canonical(&v)?)
            }
            "in" => {
                let (p, v) = pair(arg)?;
                let Value::Array(values) = v else {
                    return Err(malformed("in needs an array of values"));
                };
                require((1..=64).contains(&values.len()), "in needs 1–64 values")?;
                Self::In(
                    CondPath::parse(&p)?,
                    values.iter().map(canonical).collect::<Result<_>>()?,
                )
            }
            "prefix" => {
                let (p, v) = pair(arg)?;
                let Value::String(s) = v else {
                    return Err(malformed("prefix needs a string"));
                };
                Self::Prefix(CondPath::parse(&p)?, s)
            }
            "lte" | "gte" => {
                let (p, v) = pair(arg)?;
                let Value::Number(n) = v else {
                    return Err(malformed("lte and gte need a number"));
                };
                let path = CondPath::parse(&p)?;
                if op == "lte" {
                    Self::Lte(path, n)
                } else {
                    Self::Gte(path, n)
                }
            }
            "all" | "any" => {
                let Value::Array(items) = arg else {
                    return Err(malformed("all and any need an array"));
                };
                let inner = items
                    .into_iter()
                    .map(|v| Self::parse(v, depth + 1, count, unknown))
                    .collect::<Result<Vec<_>>>()?;
                if op == "all" {
                    Self::All(inner)
                } else {
                    Self::Any(inner)
                }
            }
            "not" => Self::Not(Box::new(Self::parse(arg, depth + 1, count, unknown)?)),
            other => {
                unknown.push(format!("conditions: operator {other}"));
                Self::Unknown(other.into())
            }
        })
    }
    /// Evaluate on `args` (a call's) or a record's `payload`, in three-valued logic.
    pub fn eval(&self, root: &Value) -> Truth {
        match self {
            Self::Eq(p, v) => Truth::of(
                p.lookup(root)
                    .and_then(|x| canonical(x).ok())
                    .is_some_and(|x| &x == v),
            ),
            Self::In(p, vs) => Truth::of(
                p.lookup(root)
                    .and_then(|x| canonical(x).ok())
                    .is_some_and(|x| vs.contains(&x)),
            ),
            Self::Prefix(p, s) => Truth::of(
                matches!(p.lookup(root), Some(Value::String(x)) if x.starts_with(s.as_str())),
            ),
            Self::Lte(p, n) => Truth::of(matches!(p.lookup(root), Some(Value::Number(x))
                if matches!(compare_numbers(x, n), Some(Ordering::Less | Ordering::Equal)))),
            Self::Gte(p, n) => Truth::of(matches!(p.lookup(root), Some(Value::Number(x))
                if matches!(compare_numbers(x, n), Some(Ordering::Greater | Ordering::Equal)))),
            Self::All(items) => Truth::all(items.iter().map(|i| i.eval(root))),
            Self::Any(items) => Truth::any(items.iter().map(|i| i.eval(root))),
            Self::Not(inner) => inner.eval(root).not(),
            Self::Unknown(_) => Truth::Unknown,
        }
    }
}

/// A `conditions` array with each top-level predicate's canonical bytes (for narrowing).
#[derive(Clone, Debug, PartialEq)]
pub struct Conditions {
    /// Top-level predicates.
    pub predicates: Vec<Predicate>,
    /// Canonical bytes of each top-level predicate.
    pub canonical: Vec<Vec<u8>>,
}
impl Conditions {
    fn parse(value: Value, unknown: &mut Unknown) -> Result<Self> {
        require(
            canonical(&value)?.len() <= 4_096,
            "conditions exceed 4,096 bytes",
        )?;
        let Value::Array(items) = value else {
            return Err(malformed("conditions must be an array"));
        };
        require(
            (1..=32).contains(&items.len()),
            "conditions must have 1–32 predicates",
        )?;
        let canonical = items.iter().map(canonical).collect::<Result<Vec<_>>>()?;
        let mut count = 0;
        let predicates = items
            .into_iter()
            .map(|v| Predicate::parse(v, 1, &mut count, unknown))
            .collect::<Result<_>>()?;
        Ok(Self {
            predicates,
            canonical,
        })
    }
    /// Every predicate, as `all` (§10.4).
    pub fn eval(&self, root: &Value) -> Truth {
        Truth::all(self.predicates.iter().map(|p| p.eval(root)))
    }
}

/// Terms (§10.1).
#[derive(Clone, Debug, PartialEq)]
pub struct Terms {
    records: Option<Vec<RecordsEntry>>,
    services: Option<Vec<ServicesEntry>>,
    expires: Option<(String, i64)>,
    writes: Option<u64>,
    depth: u64,
    conditions: Option<Conditions>,
    serves_home: bool,
    serves_present: bool,
    import: bool,
    unknown: Unknown,
}

/// Where a terms object appears; link terms are restricted (§10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TermsKind {
    /// Member terms in a grant or request.
    Member,
    /// Terms in a link.
    Link,
}

impl Terms {
    /// Parse terms. Unknown terms, values and condition operators are kept in the value
    /// ([`Terms::unknown`]).
    pub fn parse(value: Value, kind: TermsKind) -> Result<Self> {
        let mut sink = Unknown::default();
        let unknown = &mut sink;
        let mut o = Obj::new(value, "terms")?;
        if kind == TermsKind::Link {
            for f in ["records", "expires", "writes", "serves", "import"] {
                require(!o.has(f), &format!("link terms contain {f}"))?;
            }
        }
        let mut t = Terms {
            records: None,
            services: None,
            expires: None,
            writes: None,
            depth: 0,
            conditions: None,
            serves_home: false,
            serves_present: false,
            import: false,
            unknown: Unknown::default(),
        };
        if let Some(items) = o.opt_value("records")? {
            let Value::Array(items) = items else {
                return Err(malformed("records must be an array"));
            };
            require(
                (1..=64).contains(&items.len()),
                "records must have 1–64 entries",
            )?;
            let mut list: Vec<RecordsEntry> = Vec::with_capacity(items.len());
            for item in items {
                let mut e = Obj::new(item, "terms.records[]")?;
                let namespace = e.string("namespace")?;
                require(valid_namespace(&namespace), "invalid namespace")?;
                require(
                    !list.iter().any(|x| x.namespace == namespace),
                    "records namespaces must be distinct",
                )?;
                let access = match e.string("access")?.as_str() {
                    "read" => Access::Read,
                    "propose" => Access::Propose,
                    "write" => Access::Write,
                    other => {
                        unknown.push(format!("terms.records.access={other}"));
                        Access::Read
                    }
                };
                let kinds = match e.opt_value("kinds")? {
                    None => None,
                    Some(Value::Array(ks)) => {
                        require((1..=64).contains(&ks.len()), "kinds must have 1–64 entries")?;
                        let mut out: Vec<String> = Vec::with_capacity(ks.len());
                        for k in ks {
                            let Value::String(k) = k else {
                                return Err(malformed("kinds must be strings"));
                            };
                            require(valid_kind(&k), "invalid kind")?;
                            require(!out.contains(&k), "kinds must be distinct")?;
                            out.push(k);
                        }
                        Some(out)
                    }
                    Some(_) => return Err(malformed("kinds must be an array")),
                };
                e.finish(unknown);
                list.push(RecordsEntry {
                    namespace,
                    access,
                    kinds,
                });
            }
            t.records = Some(list);
        }
        if let Some(items) = o.opt_value("services")? {
            let Value::Array(items) = items else {
                return Err(malformed("services must be an array"));
            };
            require(
                (1..=64).contains(&items.len()),
                "services must have 1–64 entries",
            )?;
            let mut list: Vec<ServicesEntry> = Vec::with_capacity(items.len());
            for item in items {
                let mut e = Obj::new(item, "terms.services[]")?;
                let audience = e.string("audience")?;
                require(valid_audience(&audience), "invalid audience")?;
                require(
                    !list.iter().any(|x| x.audience == audience),
                    "services audiences must be distinct",
                )?;
                let raw = e.array("purposes")?;
                let mut purposes = Vec::with_capacity(raw.len());
                for p in raw {
                    let Value::String(p) = p else {
                        return Err(malformed("purposes must be strings"));
                    };
                    purposes.push(p);
                }
                let purposes = if purposes == ["*"] {
                    None
                } else {
                    require(
                        (1..=64).contains(&purposes.len()),
                        "purposes must have 1–64 entries",
                    )?;
                    let mut seen: Vec<&String> = Vec::new();
                    for p in &purposes {
                        require(valid_purpose(p), "invalid purpose")?;
                        require(!seen.contains(&p), "purposes must be distinct")?;
                        seen.push(p);
                    }
                    Some(purposes)
                };
                e.finish(unknown);
                list.push(ServicesEntry { audience, purposes });
            }
            t.services = Some(list);
        }
        if o.has("expires") {
            let s = o.string("expires")?;
            let ms = date(&s, "terms.expires")?;
            t.expires = Some((s, ms));
        }
        t.writes = o.opt_uint("writes")?;
        if let Some(d) = o.opt_uint("depth")? {
            require(d <= 4, "depth must be 0–4")?;
            t.depth = d;
        }
        if let Some(c) = o.opt_value("conditions")? {
            t.conditions = Some(Conditions::parse(c, unknown)?);
        }
        if let Some(s) = o.opt_value("serves")? {
            let Value::Array(items) = s else {
                return Err(malformed("serves must be an array"));
            };
            require(!items.is_empty(), "serves must not be empty")?;
            for item in &items {
                match item {
                    Value::String(x) if x == "home" => {}
                    Value::String(x) => unknown.push(format!("terms.serves={x}")),
                    _ => return Err(malformed("serves entries must be strings")),
                }
            }
            let mut seen = BTreeSet::new();
            require(
                items.iter().all(|v| seen.insert(v.to_string())),
                "serves entries must be distinct",
            )?;
            t.serves_present = true;
            t.serves_home = items.contains(&Value::String("home".into()));
        }
        match o.opt_value("import")? {
            None => {}
            Some(Value::Bool(true)) => t.import = true,
            Some(_) => return Err(malformed("import is present only as true")),
        }
        o.finish(unknown);
        match kind {
            TermsKind::Member => require(
                t.records.is_some() || t.services.is_some() || t.serves_present,
                "terms need records, services or serves",
            )?,
            TermsKind::Link => require(t.services.is_some(), "link terms need services")?,
        }
        t.unknown = sink;
        Ok(t)
    }

    /// The services entry for `audience`.
    pub fn service(&self, audience: &str) -> Option<&ServicesEntry> {
        self.services
            .as_ref()?
            .iter()
            .find(|s| s.audience == audience)
    }
    /// True when these terms allow `purpose` at `audience` (§12.3 step 7).
    pub fn allows(&self, audience: &str, purpose: &str) -> bool {
        self.service(audience).is_some_and(|s| s.allows(purpose))
    }
    /// The conditions on `root` (absent: true), three-valued.
    pub fn conditions_on(&self, root: &Value) -> Truth {
        self.conditions
            .as_ref()
            .map_or(Truth::True, |c| c.eval(root))
    }
    /// `records` entries.
    pub fn records(&self) -> Option<&[RecordsEntry]> {
        self.records.as_deref()
    }
    /// `services` entries.
    pub fn services(&self) -> Option<&[ServicesEntry]> {
        self.services.as_deref()
    }
    /// `expires`, in ms.
    pub fn expires_ms(&self) -> Option<i64> {
        self.expires.as_ref().map(|(_, e)| *e)
    }
    /// `writes`.
    pub fn writes(&self) -> Option<u64> {
        self.writes
    }
    /// `depth` (absent: 0).
    pub fn depth(&self) -> u64 {
        self.depth
    }
    /// `conditions`.
    pub fn conditions(&self) -> Option<&Conditions> {
        self.conditions.as_ref()
    }
    /// `serves` contains `"home"`.
    pub fn serves_home(&self) -> bool {
        self.serves_home
    }
    /// `serves` is present.
    pub fn serves_present(&self) -> bool {
        self.serves_present
    }
    /// `import: true`.
    pub fn import(&self) -> bool {
        self.import
    }
    /// Unknown terms, values and condition operators in these terms.
    pub fn unknown(&self) -> &Unknown {
        &self.unknown
    }
    /// §10.3: these (link) terms narrow `parent`: every services entry has one in the parent
    /// for the same audience covering its purposes; `depth` is less than the parent's; and
    /// every parent predicate equals, by canonical JSON, some predicate here.
    pub fn narrows(&self, parent: &Terms) -> bool {
        let services_ok = self.services.as_ref().is_some_and(|mine| {
            mine.iter()
                .all(|s| parent.service(&s.audience).is_some_and(|p| p.covers(s)))
        });
        let conditions_ok = match &parent.conditions {
            None => true,
            Some(pc) => pc.canonical.iter().all(|p| {
                self.conditions
                    .as_ref()
                    .is_some_and(|c| c.canonical.contains(p))
            }),
        };
        services_ok && self.depth < parent.depth && conditions_ok
    }
    /// §9.2: these granted terms are covered by `requested`. `import`, `expires`, `writes`,
    /// `depth` and `conditions` are the approver's and never compared.
    pub fn covered_by(&self, requested: &Terms) -> bool {
        let records_ok = self.records.as_ref().is_none_or(|granted| {
            granted.iter().all(|g| {
                requested.records.as_ref().is_some_and(|req| {
                    req.iter().any(|r| {
                        r.namespace == g.namespace
                            && r.access >= g.access
                            && match (&r.kinds, &g.kinds) {
                                (None, _) => true,
                                (Some(_), None) => false,
                                (Some(rk), Some(gk)) => gk.iter().all(|k| rk.contains(k)),
                            }
                    })
                })
            })
        });
        let services_ok = self.services.as_ref().is_none_or(|granted| {
            granted
                .iter()
                .all(|g| requested.service(&g.audience).is_some_and(|r| r.covers(g)))
        });
        let serves_ok = !self.serves_home || requested.serves_home;
        records_ok && services_ok && serves_ok
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;
    fn member(v: Value) -> Terms {
        let t = Terms::parse(v, TermsKind::Member).unwrap();
        assert!(t.unknown().is_empty());
        t
    }
    fn link(v: Value) -> Result<Terms> {
        Terms::parse(v, TermsKind::Link)
    }
    const AUD: &str = "https://projects.example/scopes/7";
    fn with_conditions(c: Value) -> Result<Terms> {
        Terms::parse(
            json!({"services":[{"audience":AUD,"purposes":["x"]}],"conditions":c}),
            TermsKind::Member,
        )
    }

    #[test]
    fn grammar() {
        assert!(valid_audience(AUD));
        assert!(valid_audience("urn:example:x"));
        for bad in [
            "http://a",
            "https://a:1",
            "https://a/x?y",
            "https://a#x",
            "https://A",
            "urn:",
            "https://u@a",
            "urn:a b",
        ] {
            assert!(!valid_audience(bad), "{bad}");
        }
        assert!(
            valid_purpose("task.read")
                && valid_purpose("colophon.history.read")
                && !valid_purpose("a b")
        );
        assert!(
            valid_namespace("reading.books") && !valid_namespace("Notes") && !valid_namespace("")
        );
    }

    #[test]
    fn parse_rules() {
        for bad in [
            json!({}),
            json!({"records":[]}),
            json!({"records":[{"namespace":"a","access":"read"},{"namespace":"a","access":"write"}]}),
            json!({"services":[{"audience":AUD,"purposes":["*","x"]}]}),
            json!({"services":[{"audience":AUD,"purposes":["x","x"]}]}),
            json!({"services":[{"audience":AUD,"purposes":[]}]}),
            json!({"services":[{"audience":AUD,"purposes":["x"]}],"expires":"2026-02-30T00:00:00Z"}),
            json!({"services":[{"audience":AUD,"purposes":["x"]}],"depth":5}),
            json!({"services":[{"audience":AUD,"purposes":["x"]}],"import":false}),
            json!({"services":[{"audience":AUD,"purposes":["x"]}],"writes":1.0}),
            json!({"services":[{"audience":AUD,"purposes":["x"]}],"expires":null}),
            json!({"serves":["home","home"]}),
        ] {
            assert!(
                Terms::parse(bad.clone(), TermsKind::Member).is_err(),
                "{bad}"
            );
        }
        assert!(link(
            json!({"services":[{"audience":AUD,"purposes":["x"]}],"expires":"2026-01-01T00:00:00Z"})
        )
        .is_err());
        let t = link(json!({"services":[{"audience":AUD,"purposes":["x"]}],"future":1})).unwrap();
        assert_eq!(t.unknown().0, vec!["terms.future"]);
        let t = Terms::parse(json!({"serves":["relay"]}), TermsKind::Member).unwrap();
        assert!(!t.unknown().is_empty() && !t.serves_home());
    }

    #[test]
    fn condition_bounds_and_three_valued_evaluation() {
        let c = member(json!({"services":[{"audience":AUD,"purposes":["x"]}],
            "conditions":[{"lte":["args.amount",5000]},{"prefix":["task","T-"]},{"not":{"eq":["flag",true]}},{"all":[]},{"in":["k",[1,"a",null]]}]}));
        assert_eq!(
            c.conditions_on(&json!({"amount":5000,"task":"T-1","k":"a"})),
            Truth::True
        );
        assert_eq!(
            c.conditions_on(&json!({"amount":5000,"task":"T-1","k":null})),
            Truth::True
        );
        assert_eq!(
            c.conditions_on(&json!({"amount":5000.5,"task":"T-1","k":"a"})),
            Truth::False
        );
        assert_eq!(
            c.conditions_on(&json!({"task":"T-1","k":"a"})),
            Truth::False,
            "missing path: leaf false"
        );
        assert_eq!(
            c.conditions_on(&json!({"amount":"5","task":"T-1","k":"a"})),
            Truth::False
        );
        assert_eq!(
            c.conditions_on(&json!({"amount":1,"task":"T-1","k":"a","flag":true})),
            Truth::False
        );
        assert_eq!(
            member(
                json!({"services":[{"audience":AUD,"purposes":["x"]}],"conditions":[{"any":[]}]})
            )
            .conditions_on(&json!({})),
            Truth::False
        );
        // Unknown operators: not of unknown is unknown; all/any follow Kleene logic.
        let u = |c: Value| with_conditions(c).unwrap();
        let t = u(json!([{"future":["a",1]}]));
        assert!(!t.unknown().is_empty());
        assert_eq!(t.conditions_on(&json!({})), Truth::Unknown);
        assert_eq!(
            u(json!([{"not":{"future":1}}])).conditions_on(&json!({})),
            Truth::Unknown
        );
        assert_eq!(
            u(json!([{"all":[{"future":1},{"eq":["a",1]}]}])).conditions_on(&json!({"a":2})),
            Truth::False
        );
        assert_eq!(
            u(json!([{"all":[{"future":1},{"eq":["a",1]}]}])).conditions_on(&json!({"a":1})),
            Truth::Unknown
        );
        assert_eq!(
            u(json!([{"any":[{"future":1},{"eq":["a",1]}]}])).conditions_on(&json!({"a":1})),
            Truth::True
        );
        assert_eq!(
            u(json!([{"any":[{"future":1},{"eq":["a",1]}]}])).conditions_on(&json!({"a":2})),
            Truth::Unknown
        );
        assert_eq!(
            u(json!([{"future":1},{"eq":["a",1]}])).conditions_on(&json!({"a":2})),
            Truth::False
        );
        // Bounds: 32 predicates including logical ones, depth 4, 8 path segments with `args`.
        let leaf = json!({"eq":["a",1]});
        with_conditions(json!((0..32).map(|_| leaf.clone()).collect::<Vec<_>>())).unwrap();
        assert!(with_conditions(
            json!([{"all":(0..32).map(|_| leaf.clone()).collect::<Vec<_>>()}])
        )
        .is_err());
        with_conditions(json!([{"not":{"not":{"not":leaf.clone()}}}])).unwrap();
        assert!(with_conditions(json!([{"not":{"not":{"not":{"not":leaf.clone()}}}}])).is_err());
        assert!(with_conditions(json!([{"eq":["a.b.c.d.e.f.g.h.i",1]}])).is_err());
        assert!(
            with_conditions(json!([{"eq":["args.b.c.d.e.f.g.h.i",1]}])).is_err(),
            "args counts"
        );
        with_conditions(json!([{"eq":["args.b.c.d.e.f.g.h",1]}])).unwrap();
    }

    #[test]
    fn narrowing_and_coverage() {
        let parent = member(
            json!({"services":[{"audience":AUD,"purposes":["task.propose","task.read"]}],"depth":1,
            "conditions":[{"prefix":["args.task","T-"]}]}),
        );
        let narrow = link(json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"conditions":[{"prefix":["args.task","T-"]}]})).unwrap();
        assert!(narrow.narrows(&parent));
        assert!(
            !link(json!({"services":[{"audience":AUD,"purposes":["task.read"]}]}))
                .unwrap()
                .narrows(&parent)
        );
        assert!(!link(json!({"services":[{"audience":AUD,"purposes":["*"]}],"conditions":[{"prefix":["args.task","T-"]}]})).unwrap().narrows(&parent));
        assert!(!link(json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"depth":1,"conditions":[{"prefix":["args.task","T-"]}]})).unwrap().narrows(&parent));
        let requested = member(
            json!({"records":[{"namespace":"notes","access":"propose","kinds":["a","b"]}],"services":[{"audience":AUD,"purposes":["*"]}]}),
        );
        assert!(
            member(json!({"records":[{"namespace":"notes","access":"read","kinds":["a"]}]}))
                .covered_by(&requested)
        );
        assert!(
            !member(json!({"records":[{"namespace":"notes","access":"write"}]}))
                .covered_by(&requested)
        );
        assert!(
            !member(json!({"records":[{"namespace":"notes","access":"read"}]}))
                .covered_by(&requested)
        );
        assert!(member(
            json!({"services":[{"audience":AUD,"purposes":["*"]}],"import":true,"depth":4})
        )
        .covered_by(&requested));
        assert!(!member(json!({"serves":["home"]})).covered_by(&requested));
    }
}
