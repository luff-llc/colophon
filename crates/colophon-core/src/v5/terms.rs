//! Strict, bounded grant terms, conservative narrowing and deterministic predicates (§6).
use super::{timestamp, Verdict};
use crate::{keys::strict_json, records};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Access order in draft §6.2: read < propose < write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    /// Reading a namespace.
    Read,
    /// Proposing an operation (and reading).
    Propose,
    /// Writing an operation (and proposing and reading).
    Write,
}
impl Access {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "propose" => Some(Self::Propose),
            "write" => Some(Self::Write),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Propose => "propose",
            Self::Write => "write",
        }
    }
}

/// One namespace, access ceiling and optional allowed-kind subset.
#[derive(Clone, Debug, PartialEq)]
pub struct Scope {
    /// Namespace identifier.
    pub namespace: String,
    /// Highest access permitted.
    pub access: Access,
    /// Absent means any kind, present restricts to the listed kinds.
    pub kinds: Option<Vec<String>>,
}
impl Scope {
    fn from_value(v: &Value) -> Result<Self, Verdict> {
        let o = object(v)?;
        known(o, &["namespace", "access", "kinds"])?;
        let namespace = word(field(o, "namespace")?)?;
        let access = Access::parse(string(field(o, "access")?)?)
            .ok_or(Verdict::NewerFormat)?;
        let kinds = o.get("kinds").map(names).transpose()?;
        if kinds.as_ref().is_some_and(Vec::is_empty) {
            return Err(Verdict::Malformed);
        }
        Ok(Self { namespace, access, kinds })
    }
    fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("namespace".into(), json!(self.namespace));
        o.insert("access".into(), json!(self.access.name()));
        if let Some(k) = &self.kinds {
            o.insert("kinds".into(), json!(k));
        }
        Value::Object(o)
    }
    fn covers(&self, child: &Self) -> bool {
        self.namespace == child.namespace
            && self.access >= child.access
            && match (&self.kinds, &child.kinds) {
                (None, _) => true,
                (Some(parent), Some(child)) => child.iter().all(|k| parent.contains(k)),
                (Some(_), None) => false,
            }
    }
}

/// Every recognized field of a Colophon 0.5 grant. Missing depth is zero.
#[derive(Clone, Debug, PartialEq)]
pub struct Terms {
    /// Nonempty list of at most 64 namespace permissions.
    pub scope: Vec<Scope>,
    /// Optional inclusive UTC expiry.
    pub expires: Option<String>,
    /// Maximum number of links a holder may subsequently delegate.
    pub depth: u64,
    /// Optional cap on admitted records; counting is a later slice.
    pub writes: Option<u64>,
    /// Required acting-key capabilities. Only `uv` is currently defined.
    pub requires: Vec<String>,
    /// Bounded, printable JSON predicates over operation or transition arguments.
    pub conditions: Vec<Value>,
    /// Optional service capabilities `home` and/or `authority`.
    pub serves: Vec<String>,
}
impl Terms {
    /// Parse a whole JSON document with duplicate-key detection at every depth.
    pub fn parse(bytes: &[u8]) -> Result<Self, Verdict> {
        let value = strict_json::parse(bytes).map_err(|_| Verdict::Malformed)?;
        Self::from_value(&value)
    }
    /// Parse a previously duplicate-checked JSON value. Unknown fields are newerFormat.
    /// Call this only after the enclosing link's signature has verified.
    pub fn from_value(value: &Value) -> Result<Self, Verdict> {
        let o = object(value)?;
        known(o, &["scope", "expires", "depth", "writes", "requires", "conditions", "serves"])?;
        let scope = array(field(o, "scope")?)?;
        if scope.is_empty() || scope.len() > 64 {
            return Err(Verdict::Malformed);
        }
        let scope = scope.iter().map(Scope::from_value).collect::<Result<Vec<_>, _>>()?;
        let expires = o.get("expires").map(|v| date(v)).transpose()?;
        let depth = o.get("depth").map(unsigned).transpose()?.unwrap_or(0);
        let writes = o.get("writes").map(unsigned).transpose()?;
        let requires = o.get("requires").map(names).transpose()?.unwrap_or_default();
        if requires.iter().any(|v| v != "uv") {
            return Err(Verdict::NewerFormat);
        }
        let serves = o.get("serves").map(names).transpose()?.unwrap_or_default();
        if serves.iter().any(|v| v != "home" && v != "authority") {
            return Err(Verdict::NewerFormat);
        }
        let conditions = o.get("conditions").map(array).transpose()?.cloned().unwrap_or_default();
        let mut count = 0;
        for c in &conditions {
            validate_condition(c, 1, &mut count)?;
        }
        let bytes = records::canonical(&conditions).map_err(|_| Verdict::Malformed)?;
        if bytes.len() > 4096 {
            return Err(Verdict::Malformed);
        }
        Ok(Self { scope, expires, depth, writes, requires, conditions, serves })
    }
    /// Reconstruct canonical value; absent optional properties remain absent.
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("scope".into(), Value::Array(self.scope.iter().map(Scope::to_value).collect()));
        if let Some(v) = &self.expires {
            o.insert("expires".into(), json!(v));
        }
        if self.depth != 0 {
            o.insert("depth".into(), json!(self.depth));
        }
        if let Some(v) = self.writes {
            o.insert("writes".into(), json!(v));
        }
        if !self.requires.is_empty() {
            o.insert("requires".into(), json!(self.requires));
        }
        if !self.conditions.is_empty() {
            o.insert("conditions".into(), json!(self.conditions));
        }
        if !self.serves.is_empty() {
            o.insert("serves".into(), json!(self.serves));
        }
        Value::Object(o)
    }
    /// Canonical-JSON body for a terms object.
    pub fn canonical(&self) -> Result<Vec<u8>, Verdict> {
        records::canonical(&self.to_value()).map_err(|_| Verdict::Malformed)
    }
    /// B narrows A only if all seven constraints in §6.2 hold.
    pub fn narrows(&self, child: &Self) -> bool {
        child.scope.iter().all(|b| self.scope.iter().any(|a| a.covers(b)))
            && match (&self.expires, &child.expires) {
                (None, _) => true,
                (Some(a), Some(b)) => match (timestamp(a), timestamp(b)) {
                    (Some(a), Some(b)) => b <= a,
                    _ => false,
                },
                (Some(_), None) => false,
            }
            && child.depth < self.depth
            && match (self.writes, child.writes) {
                (None, _) => true,
                (Some(a), Some(b)) => b <= a,
                (Some(_), None) => false,
            }
            && self.requires.iter().all(|r| child.requires.contains(r))
            && self.conditions.iter().all(|a| child.conditions.contains(a))
            && child.serves.iter().all(|s| self.serves.contains(s))
    }
    /// Check the purpose's level, namespace and kind against the declared scopes.
    /// Unknown purpose grammars are denied rather than treated as wildcard access.
    pub fn allows(&self, purpose: &str) -> bool {
        if let Some(name) = purpose.strip_prefix("colophon.") {
            if name != "sign" && name != "publish" {
                return false;
            }
            return self.scope.iter().any(|s| {
                s.namespace == "colophon"
                    && s.kinds.as_ref().is_some_and(|k| k.iter().any(|v| v == name || v == purpose))
            });
        }
        if let Some(kind) = purpose.strip_prefix("guard:") {
            if kind.is_empty() {
                return false;
            }
            return self.scope.iter().any(|s| {
                s.namespace == "colophon"
                    && s.access == Access::Write
                    && s.kinds.as_ref().is_some_and(|k| k.contains(&format!("guard:{kind}")))
            });
        }
        let mut p = purpose.split(':');
        let (Some(level), Some(namespace), Some(kind), None) = (p.next(), p.next(), p.next(), p.next()) else {
            return false;
        };
        let Some(access) = Access::parse(level) else { return false; };
        if namespace.is_empty() || kind.is_empty() {
            return false;
        }
        self.scope.iter().any(|s| {
            s.namespace == namespace
                && s.access >= access
                && s.kinds.as_ref().is_none_or(|k| k.iter().any(|v| v == kind))
        })
    }
    /// Evaluate all predicates and `uv` against authenticated key context and the arguments value.
    /// An unknown capability is rejected during parsing, not silently ignored.
    pub fn conditions_hold(&self, arguments: &Value, uv: bool) -> bool {
        (!self.requires.iter().any(|r| r == "uv") || uv)
            && self.conditions.iter().all(|c| evaluate(c, arguments))
    }
}

fn object(v: &Value) -> Result<&Map<String, Value>, Verdict> {
    v.as_object().ok_or(Verdict::Malformed)
}
fn array(v: &Value) -> Result<&Vec<Value>, Verdict> {
    v.as_array().ok_or(Verdict::Malformed)
}
fn field<'a>(o: &'a Map<String, Value>, k: &str) -> Result<&'a Value, Verdict> {
    o.get(k).ok_or(Verdict::Malformed)
}
fn string(v: &Value) -> Result<&str, Verdict> {
    v.as_str().ok_or(Verdict::Malformed)
}
fn unsigned(v: &Value) -> Result<u64, Verdict> {
    v.as_u64().ok_or(Verdict::Malformed)
}
fn date(v: &Value) -> Result<String, Verdict> {
    let s = string(v)?;
    timestamp(s).ok_or(Verdict::Malformed)?;
    Ok(s.into())
}
fn known(o: &Map<String, Value>, fields: &[&str]) -> Result<(), Verdict> {
    if o.keys().any(|k| !fields.contains(&k.as_str())) {
        Err(Verdict::NewerFormat)
    } else {
        Ok(())
    }
}
fn word(v: &Value) -> Result<String, Verdict> {
    let s = string(v)?;
    if s.is_empty() || s.len() > 256 || s.chars().any(char::is_control) {
        return Err(Verdict::Malformed);
    }
    Ok(s.into())
}
fn names(v: &Value) -> Result<Vec<String>, Verdict> {
    let values = array(v)?;
    if values.len() > 64 {
        return Err(Verdict::Malformed);
    }
    let words = values.iter().map(word).collect::<Result<Vec<_>, _>>()?;
    let distinct = words.iter().collect::<BTreeSet<_>>();
    if distinct.len() != words.len() {
        return Err(Verdict::Malformed);
    }
    Ok(words)
}
fn path(v: &Value) -> Result<&str, Verdict> {
    let s = string(v)?;
    if s.len() > 256 || s.split('.').any(|p| p.is_empty()) || s.chars().any(char::is_control) {
        return Err(Verdict::Malformed);
    }
    Ok(s)
}
fn validate_condition(v: &Value, depth: usize, count: &mut usize) -> Result<(), Verdict> {
    *count += 1;
    if *count > 32 || depth > 4 {
        return Err(Verdict::Malformed);
    }
    let o = object(v)?;
    if o.len() != 1 {
        return Err(Verdict::Malformed);
    }
    let (op, operand) = o.iter().next().ok_or(Verdict::Malformed)?;
    match op.as_str() {
        "eq" | "in" | "prefix" | "lte" | "gte" => {
            let parts = array(operand)?;
            if parts.len() != 2 {
                return Err(Verdict::Malformed);
            }
            path(&parts[0])?;
            match op.as_str() {
                "in" => { array(&parts[1])?; }
                "prefix" => { string(&parts[1])?; }
                "lte" | "gte" => {
                    if !parts[1].is_number() { return Err(Verdict::Malformed); }
                }
                _ => {}
            }
        }
        "all" | "any" => {
            for c in array(operand)? {
                validate_condition(c, depth + 1, count)?;
            }
        }
        "not" => validate_condition(operand, depth + 1, count)?,
        _ => return Err(Verdict::NewerFormat),
    }
    Ok(())
}
fn at_path<'a>(arguments: &'a Value, p: &str) -> Option<&'a Value> {
    let p = p.strip_prefix("args.").unwrap_or(p);
    if p == "args" {
        return Some(arguments);
    }
    let mut value = arguments;
    for key in p.split('.') {
        value = value.as_object()?.get(key)?;
    }
    Some(value)
}
fn evaluate(v: &Value, arguments: &Value) -> bool {
    let Some((op, operand)) = v.as_object().and_then(|o| o.iter().next()) else { return false; };
    match op.as_str() {
        "all" => operand.as_array().is_some_and(|items| items.iter().all(|c| evaluate(c, arguments))),
        "any" => operand.as_array().is_some_and(|items| items.iter().any(|c| evaluate(c, arguments))),
        "not" => !evaluate(operand, arguments),
        _ => {
            let Some(parts) = operand.as_array() else { return false; };
            let Some(p) = parts.first().and_then(Value::as_str) else { return false; };
            let Some(actual) = at_path(arguments, p) else { return false; };
            let Some(expected) = parts.get(1) else { return false; };
            match op.as_str() {
                "eq" => actual == expected,
                "in" => expected.as_array().is_some_and(|vs| vs.contains(actual)),
                "prefix" => actual.as_str().zip(expected.as_str()).is_some_and(|(a,b)| a.starts_with(b)),
                "lte" => compare_json_numbers(actual, expected)
                    .is_some_and(|ordering| ordering != std::cmp::Ordering::Greater),
                "gte" => compare_json_numbers(actual, expected)
                    .is_some_and(|ordering| ordering != std::cmp::Ordering::Less),
                _ => false,
            }
        }
    }
}


/// Exact ordering of integer-token JSON numbers (including values above 2^53),
/// with IEEE-754 semantics for actual floating-point tokens. Casting large
/// integer tokens directly to f64 would silently authorize an over-limit spend.
fn compare_json_numbers(left: &Value, right: &Value) -> Option<std::cmp::Ordering> {
    let parse = |v: &Value| {
        let n = v.as_number()?;
        if n.is_i64() {
            Some((Some(i128::from(n.as_i64()?)), None))
        } else if n.is_u64() {
            Some((Some(i128::from(n.as_u64()?)), None))
        } else {
            Some((None, n.as_f64()))
        }
    };
    let (li, lf) = parse(left)?;
    let (ri, rf) = parse(right)?;
    match (li, ri) {
        (Some(a), Some(b)) => Some(a.cmp(&b)),
        (Some(a), None) => compare_int_float(a, rf?),
        (None, Some(b)) => compare_int_float(b, lf?).map(std::cmp::Ordering::reverse),
        (None, None) => lf?.partial_cmp(&rf?),
    }
}

/// Compare an exact signed/unsigned 64-bit JSON integer to finite binary64.
/// All integer inputs fit into i128; float magnitudes at least 2^64 dominate.
fn compare_int_float(integer: i128, float: f64) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    if !float.is_finite() {
        return None;
    }
    const TWO_TO_64: f64 = 18_446_744_073_709_551_616.0;
    if float >= TWO_TO_64 {
        return Some(Ordering::Less);
    }
    if float <= -TWO_TO_64 {
        return Some(Ordering::Greater);
    }
    let trunc = float.trunc() as i128;
    match integer.cmp(&trunc) {
        Ordering::Equal if float.fract() > 0.0 => Some(Ordering::Less),
        Ordering::Equal if float.fract() < 0.0 => Some(Ordering::Greater),
        other => Some(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_json_numeric_bounds() {
        let terms = |condition: Value| Terms::from_value(&json!({
            "scope":[{"namespace":"payments","access":"write"}],
            "conditions":[condition]
        })).unwrap();
        let limit = 9_007_199_254_740_992u64;
        let above = limit + 1;
        assert!(terms(json!({"lte":["args.amount",limit]}))
            .conditions_hold(&json!({"amount":limit}), false));
        assert!(!terms(json!({"lte":["args.amount",limit]}))
            .conditions_hold(&json!({"amount":above}), false));
        assert!(terms(json!({"gte":["args.amount",above]}))
            .conditions_hold(&json!({"amount":above}), false));
        assert!(!terms(json!({"gte":["args.amount",above]}))
            .conditions_hold(&json!({"amount":limit}), false));
        assert!(!terms(json!({"lte":["args.amount",1.5]}))
            .conditions_hold(&json!({"amount":2}), false));
        assert!(terms(json!({"gte":["args.amount",-1.5]}))
            .conditions_hold(&json!({"amount":-1}), false));
    }
    #[test]
    fn narrow_each_rule() {
        let p = Terms::from_value(&json!({"scope":[{"namespace":"notes","access":"write","kinds":["add","edit"]}],"expires":"2027-01-01T00:00:00Z","depth":3,"writes":5,"requires":["uv"],"conditions":[{"lte":["args.amount",10]}],"serves":["home","authority"]})).unwrap();
        let c = Terms::from_value(&json!({"scope":[{"namespace":"notes","access":"propose","kinds":["add"]}],"expires":"2026-12-01T00:00:00Z","depth":2,"writes":4,"requires":["uv"],"conditions":[{"lte":["args.amount",10]},{"gte":["args.amount",0]}],"serves":["home"]})).unwrap();
        assert!(p.narrows(&c));
        for (field,value) in [
            ("scope", json!([{"namespace":"notes","access":"write","kinds":["remove"]}])),
            ("expires", json!("2028-01-01T00:00:00Z")),
            ("depth", json!(3)),
            ("writes", json!(6)),
            ("requires", json!([])),
            ("conditions", json!([])),
            ("serves", json!(["home","authority","other"])),
        ] {
            let mut v = c.to_value();
            v[field] = value;
            if field == "serves" {
                assert_eq!(Terms::from_value(&v), Err(Verdict::NewerFormat));
            } else {
                assert!(!p.narrows(&Terms::from_value(&v).unwrap()), "{field}");
            }
        }
    }
    #[test]
    fn predicates_bounds_and_semantics() {
        let make = |conditions: Vec<Value>| {
            Terms::from_value(&json!({"scope":[{"namespace":"notes","access":"write"}],"conditions":conditions}))
        };
        assert!(make(vec![json!({"lte":["args.amount",5]})]).unwrap().conditions_hold(&json!({"amount":5}),false));
        assert!(!make(vec![json!({"lte":["args.amount",5]})]).unwrap().conditions_hold(&json!({"amount":6}),false));
        assert!(make((0..32).map(|_| json!({"eq":["args.amount",5]})).collect()).is_ok());
        assert_eq!(make((0..33).map(|_| json!({"eq":["args.amount",5]})).collect()), Err(Verdict::Malformed));
        assert!(make(vec![json!({"not":{"not":{"not":{"eq":["x",1]}}}})]).is_ok());
        assert_eq!(make(vec![json!({"not":{"not":{"not":{"not":{"eq":["x",1]}}}}})]), Err(Verdict::Malformed));
        let big = "x".repeat(4096);
        assert_eq!(make(vec![json!({"prefix":["args.x",big]})]), Err(Verdict::Malformed));
    }
}
