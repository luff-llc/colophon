//! Reading what a host passes and writing what it gets, with every bound checked first.
use super::fault::AccountError;
use colophon_core::v05::encoding::{decode_base64, encode_base64};
use serde_json::{json, Map, Value};

type R<T> = Result<T, AccountError>;

/// Most bytes of any JSON argument.
pub const MAX_JSON: usize = 64 << 20;
/// Most bytes of any single binary argument.
pub const MAX_BYTES: usize = 40 << 20;
/// Most items in any list argument.
pub const MAX_LIST: usize = 262_144;
/// Most signers, namespaces or controllers a call names.
pub const MAX_NAMES: usize = 256;

pub fn parse(text: &str, what: &str) -> R<Value> {
    if text.len() > MAX_JSON {
        return Err(AccountError::bound(&format!("{what} is too large")));
    }
    serde_json::from_str(text).map_err(|_| AccountError::bad(format!("{what} is not JSON")))
}
pub fn parse_or_null(text: &str, what: &str) -> R<Value> {
    if text.is_empty() {
        Ok(Value::Null)
    } else {
        parse(text, what)
    }
}
pub fn obj<'a>(v: &'a Value, what: &str) -> R<&'a Map<String, Value>> {
    v.as_object()
        .ok_or_else(|| AccountError::bad(format!("{what} must be an object")))
}
pub fn text<'a>(v: &'a Value, key: &str) -> R<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AccountError::bad(format!("`{key}` must be a string")))
}
pub fn opt_text<'a>(v: &'a Value, key: &str) -> R<Option<&'a str>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(AccountError::bad(format!("`{key}` must be a string"))),
    }
}
pub fn int(v: &Value, key: &str) -> R<i64> {
    v.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| AccountError::bad(format!("`{key}` must be an integer")))
}
pub fn uint(v: &Value, key: &str) -> R<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| AccountError::bad(format!("`{key}` must be a non-negative integer")))
}
pub fn boolean(v: &Value, key: &str, default: bool) -> R<bool> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(AccountError::bad(format!("`{key}` must be a boolean"))),
    }
}
pub fn list<'a>(v: &'a Value, key: &str) -> R<&'a [Value]> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) if a.len() <= MAX_LIST => Ok(a),
        Some(Value::Array(_)) => Err(AccountError::bound(&format!("`{key}` is too long"))),
        _ => Err(AccountError::bad(format!("`{key}` must be an array"))),
    }
}
pub fn strings(v: &Value, key: &str) -> R<Vec<String>> {
    list(v, key)?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_string)
                .ok_or_else(|| AccountError::bad(format!("`{key}` holds a non-string")))
        })
        .collect()
}
/// A names list (signers, namespaces, controller IDs): bounded.
pub fn names(v: &Value, key: &str) -> R<Vec<String>> {
    let s = strings(v, key)?;
    if s.len() > MAX_NAMES {
        return Err(AccountError::bound(&format!("`{key}` names too many")));
    }
    Ok(s)
}
pub fn names_of(v: &Value, what: &str) -> R<Vec<String>> {
    let a = v
        .as_array()
        .ok_or_else(|| AccountError::bad(format!("{what} must be an array")))?;
    if a.len() > MAX_LIST {
        return Err(AccountError::bound(&format!("{what} is too long")));
    }
    a.iter()
        .map(|s| {
            s.as_str()
                .map(str::to_string)
                .ok_or_else(|| AccountError::bad(format!("{what} holds a non-string")))
        })
        .collect()
}
pub fn b64(v: &Value, key: &str) -> R<Vec<u8>> {
    decode(text(v, key)?, key)
}
pub fn opt_b64(v: &Value, key: &str) -> R<Option<Vec<u8>>> {
    match opt_text(v, key)? {
        None => Ok(None),
        Some(s) => decode(s, key).map(Some),
    }
}
pub fn decode(s: &str, what: &str) -> R<Vec<u8>> {
    decode_base64(s, MAX_BYTES).map_err(|_| AccountError::bad(format!("`{what}` is not base64")))
}
pub fn b64_list(v: &Value, key: &str) -> R<Vec<Vec<u8>>> {
    list(v, key)?
        .iter()
        .map(|s| {
            let t = s
                .as_str()
                .ok_or_else(|| AccountError::bad(format!("`{key}` holds a non-string")))?;
            decode(t, key)
        })
        .collect()
}
pub fn b64_array(v: &Value, what: &str) -> R<Vec<Vec<u8>>> {
    let a = v
        .as_array()
        .ok_or_else(|| AccountError::bad(format!("{what} must be an array")))?;
    if a.len() > MAX_LIST {
        return Err(AccountError::bound(&format!("{what} is too long")));
    }
    a.iter()
        .map(|s| {
            let t = s
                .as_str()
                .ok_or_else(|| AccountError::bad(format!("{what} holds a non-string")))?;
            decode(t, what)
        })
        .collect()
}
pub fn enc(b: &[u8]) -> String {
    encode_base64(b)
}
pub fn bytes_list(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| json!(enc(b))).collect())
}
pub fn stores(items: &[(String, Vec<u8>)]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|(p, b)| json!({"path": p, "bytes": enc(b)}))
            .collect(),
    )
}

/// A fixed-length byte argument.
pub fn fixed<const N: usize>(b: &[u8], what: &str) -> R<[u8; N]> {
    b.try_into()
        .map_err(|_| AccountError::bound(&format!("{what} must be exactly {N} bytes")))
}
/// Check an argument's size before it is copied or parsed.
pub fn bounded(b: &[u8], max: usize, what: &str) -> R<()> {
    if b.len() > max {
        Err(AccountError::bound(&format!("{what} is too large")))
    } else {
        Ok(())
    }
}
pub fn to_string(v: &Value) -> R<String> {
    serde_json::to_string(v).map_err(|_| AccountError::internal("a result could not be written"))
}
