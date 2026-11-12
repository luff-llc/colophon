//! Canonical JSON, bytes, dates, digests, integers and bounds (§2).
//!
//! A `/5` body is accepted only if it is exactly the canonical encoding of the value it parses
//! to (§2.1). Readers never re-encode a body to "fix" it: [`canonical_body`] returns the parsed
//! value of the received bytes, and every signature is checked over those exact bytes.
use super::{malformed, require, Failure, Result, Unknown};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// §2.4 bounds on canonical bytes. Exceeding one is `malformed`.
pub mod bounds {
    /// Authority body (`/5`).
    pub const AUTHORITY_BODY: usize = 1_048_576;
    /// Receipt or veto body.
    pub const RECEIPT_BODY: usize = 1_024;
    /// Transition body.
    pub const TRANSITION_BODY: usize = 1_048_576;
    /// Membership request body.
    pub const REQUEST_BODY: usize = 16_384;
    /// Link body.
    pub const LINK_BODY: usize = 8_192;
    /// Call body, including embedded links.
    pub const CALL_BODY: usize = 65_536;
    /// `args` of a call.
    pub const CALL_ARGS: usize = 16_384;
    /// Head body.
    pub const HEAD_BODY: usize = 4_096;
    /// Equivocation evidence.
    pub const EQUIVOCATION: usize = 2_097_152;
    /// Operation header body, including `ciphertext`.
    pub const OPERATION_HEADER_BODY: usize = 16_777_216;
    /// WebAuthn `clientData`.
    pub const CLIENT_DATA: usize = 8_192;
    /// Largest integer in a field defined by the spec (§2.2): 2^53 − 1.
    pub const MAX_INTEGER: u64 = (1 << 53) - 1;
}

/// Encode a JSON value canonically (§2.1): object keys sorted recursively by their UTF-8 bytes,
/// no insignificant whitespace, strings and numbers exactly as the serde_json 1.0.145 writer
/// spells them (Ryū for binary64). Non-finite numbers are refused.
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}
fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if n.as_f64().is_some_and(|f| !f.is_finite()) {
                return Err(malformed("non-finite number"));
            }
            serde_json::to_writer(&mut *out, n).map_err(|_| malformed("number"))?;
        }
        Value::String(s) => serde_json::to_writer(&mut *out, s).map_err(|_| malformed("string"))?,
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sort explicitly, so the result never depends on the map's iteration order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).map_err(|_| malformed("key"))?;
                out.push(b':');
                write_canonical(&map[key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Parse with the strict pass: duplicate member names at any depth are `malformed` (§2.3).
pub fn strict_parse(bytes: &[u8]) -> Result<Value> {
    crate::keys::strict_json::parse(bytes).map_err(|e| malformed(format!("JSON: {}", e.0)))
}

/// Accept a `/5` body: within `bound`, one JSON object (first byte `{`), no duplicate names,
/// and byte-identical to its canonical re-encoding (§2.1, §2.4). Returns the parsed value.
pub fn canonical_body(bytes: &[u8], bound: usize) -> Result<Value> {
    require(bytes.len() <= bound, "body exceeds its bound")?;
    require(bytes.first() == Some(&b'{'), "body is not a JSON object")?;
    let value = strict_parse(bytes)?;
    require(value.is_object(), "body is not a JSON object")?;
    require(canonical(&value)? == bytes, "body is not canonical JSON")?;
    Ok(value)
}

/// Lowercase hex SHA-256 of exact bytes (§2.2).
pub fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}
/// True for exactly `len` lowercase hex characters.
pub fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// True for a 64-character lowercase hex digest.
pub fn is_digest(s: &str) -> bool {
    is_lower_hex(s, 64)
}

/// Decode standard padded base64, refusing every other spelling, including non-zero padding
/// bits, missing padding and whitespace (§2.2). `max` bounds the decoded length *before*
/// decoding, so no allocation is proportional to an unchecked claimed length.
pub fn decode_base64(text: &str, max: usize) -> Result<Vec<u8>> {
    require(
        text.len() <= max.div_ceil(3) * 4,
        "base64 value exceeds its bound",
    )?;
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| malformed("invalid base64"))?;
    // Independent of the engine's configuration: only the one canonical spelling round-trips.
    require(STANDARD.encode(&bytes) == text, "non-canonical base64")?;
    require(bytes.len() <= max, "base64 value exceeds its bound")?;
    Ok(bytes)
}
/// Standard padded base64.
pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
/// Decode a `requestId`: exactly 32 bytes as 43 characters of unpadded base64url (§12.2).
pub fn decode_request_id(text: &str) -> Result<[u8; 32]> {
    require(text.len() == 43, "requestId is not 43 characters")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| malformed("invalid requestId"))?;
    require(
        URL_SAFE_NO_PAD.encode(&bytes) == text,
        "non-canonical requestId",
    )?;
    bytes
        .try_into()
        .map_err(|_| malformed("requestId is not 32 bytes"))
}
/// Unpadded base64url.
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Parse a §2.2 date, `YYYY-MM-DDTHH:mm:ssZ` or `YYYY-MM-DDTHH:mm:ss.sssZ` (exactly three
/// fraction digits), to milliseconds since the Unix epoch. The calendar date and time must
/// exist; years 0001–9999 only (see the implementation notes on year 0000).
pub fn parse_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let short = b.len() == 20;
    if !short && b.len() != 24 {
        return None;
    }
    for (i, c) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
        if b[i] != c {
            return None;
        }
    }
    if short && b[19] != b'Z' || !short && (b[19] != b'.' || b[23] != b'Z') {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let digits = &b[from..to];
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            digits
                .iter()
                .fold(0i64, |n, d| n * 10 + i64::from(d - b'0')),
        )
    };
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let ms = if short { 0 } else { num(20, 23)? };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in_month = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if y < 1 || d < 1 || d > days_in_month || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    // Days from civil (Howard Hinnant); exact in i64 for years 1–9999.
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + hh * 3_600 + mm * 60 + ss) * 1_000) + ms)
}
/// Parse a §2.2 date or fail as `malformed` (never "no expiry").
pub fn date(s: &str, field: &str) -> Result<i64> {
    parse_date(s).ok_or_else(|| malformed(format!("invalid date: {field}")))
}

/// An integer token from 0 to 2^53 − 1 (§2.2). `1.0` is a float and is refused.
pub fn uint(value: &Value, field: &str) -> Result<u64> {
    match value {
        Value::Number(n) if !n.is_f64() => match n.as_u64() {
            Some(v) if v <= bounds::MAX_INTEGER => Ok(v),
            _ => Err(malformed(format!("integer out of range: {field}"))),
        },
        _ => Err(malformed(format!("expected integer: {field}"))),
    }
}

/// Bytes of a string, for the byte-length rules of the spec.
pub fn byte_len_in(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
}

/// A JSON object being read field by field. Known fields are taken; [`Obj::finish`] reports
/// every remaining member as unknown content (§2.3) instead of failing at once.
#[derive(Debug)]
pub struct Obj {
    map: Map<String, Value>,
    path: String,
}
impl Obj {
    /// Wrap an object value; anything else is `malformed`.
    pub fn new(value: Value, path: &str) -> Result<Self> {
        match value {
            Value::Object(map) => Ok(Self {
                map,
                path: path.into(),
            }),
            _ => Err(malformed(format!("expected object: {path}"))),
        }
    }
    fn at(&self, field: &str) -> String {
        if self.path.is_empty() {
            field.into()
        } else {
            format!("{}.{field}", self.path)
        }
    }
    /// The path of a field, for diagnostics.
    pub fn path_of(&self, field: &str) -> String {
        self.at(field)
    }
    /// True when the member is present (even as `null`).
    pub fn has(&self, field: &str) -> bool {
        self.map.contains_key(field)
    }
    /// Take a required member.
    pub fn value(&mut self, field: &str) -> Result<Value> {
        self.map
            .remove(field)
            .ok_or_else(|| malformed(format!("missing field: {}", self.at(field))))
    }
    /// Take an optional member. Optional fields are omitted when absent, so `null` is
    /// `malformed` unless `null_ok`.
    pub fn opt_value(&mut self, field: &str) -> Result<Option<Value>> {
        match self.map.remove(field) {
            Some(Value::Null) => Err(malformed(format!("null field: {}", self.at(field)))),
            other => Ok(other),
        }
    }
    /// Take a required string.
    pub fn string(&mut self, field: &str) -> Result<String> {
        match self.value(field)? {
            Value::String(s) => Ok(s),
            _ => Err(malformed(format!("expected string: {}", self.at(field)))),
        }
    }
    /// Take an optional string.
    pub fn opt_string(&mut self, field: &str) -> Result<Option<String>> {
        match self.opt_value(field)? {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(malformed(format!("expected string: {}", self.at(field)))),
        }
    }
    /// Take a required integer from 0 to 2^53 − 1.
    pub fn uint(&mut self, field: &str) -> Result<u64> {
        let path = self.at(field);
        uint(&self.value(field)?, &path)
    }
    /// Take an optional integer from 0 to 2^53 − 1.
    pub fn opt_uint(&mut self, field: &str) -> Result<Option<u64>> {
        let path = self.at(field);
        self.opt_value(field)?.map(|v| uint(&v, &path)).transpose()
    }
    /// Take a required array.
    pub fn array(&mut self, field: &str) -> Result<Vec<Value>> {
        match self.value(field)? {
            Value::Array(items) => Ok(items),
            _ => Err(malformed(format!("expected array: {}", self.at(field)))),
        }
    }
    /// Take an optional array; when present it MUST NOT be empty (absent or non-empty).
    pub fn opt_nonempty_array(&mut self, field: &str) -> Result<Option<Vec<Value>>> {
        match self.opt_value(field)? {
            None => Ok(None),
            Some(Value::Array(items)) if !items.is_empty() => Ok(Some(items)),
            Some(_) => Err(malformed(format!(
                "expected non-empty array: {}",
                self.at(field)
            ))),
        }
    }
    /// Take a required nested object.
    pub fn obj(&mut self, field: &str) -> Result<Obj> {
        let path = self.at(field);
        Obj::new(self.value(field)?, &path)
    }
    /// Take an optional nested object.
    pub fn opt_obj(&mut self, field: &str) -> Result<Option<Obj>> {
        let path = self.at(field);
        self.opt_value(field)?
            .map(|v| Obj::new(v, &path))
            .transpose()
    }
    /// Take a required standard base64 member of at most `max` decoded bytes.
    pub fn bytes(&mut self, field: &str, max: usize) -> Result<Vec<u8>> {
        let path = self.at(field);
        decode_base64(&self.string(field)?, max).map_err(|e| with_path(e, &path))
    }
    /// Take an optional standard base64 member.
    pub fn opt_bytes(&mut self, field: &str, max: usize) -> Result<Option<Vec<u8>>> {
        let path = self.at(field);
        self.opt_string(field)?
            .map(|s| decode_base64(&s, max).map_err(|e| with_path(e, &path)))
            .transpose()
    }
    /// Take a required §2.2 date, as milliseconds.
    pub fn date(&mut self, field: &str) -> Result<(String, i64)> {
        let path = self.at(field);
        let s = self.string(field)?;
        let ms = date(&s, &path)?;
        Ok((s, ms))
    }
    /// Take a required 64-hex digest.
    pub fn digest(&mut self, field: &str) -> Result<String> {
        let s = self.string(field)?;
        require(
            is_digest(&s),
            &format!("expected 64 lowercase hex: {}", self.at(field)),
        )?;
        Ok(s)
    }
    /// Take a required 32-hex key ID.
    pub fn key_id(&mut self, field: &str) -> Result<String> {
        let s = self.string(field)?;
        require(
            is_lower_hex(&s, 32),
            &format!("expected key ID: {}", self.at(field)),
        )?;
        Ok(s)
    }
    /// Report every member not taken as unknown content.
    pub fn finish(self, unknown: &mut Unknown) {
        for key in self.map.keys() {
            unknown.push(self.at(key));
        }
    }
    /// Require that no member is left (for objects whose extra fields are `malformed`).
    pub fn finish_closed(self) -> Result<()> {
        match self.map.keys().next() {
            None => Ok(()),
            Some(key) => Err(malformed(format!("unexpected field: {}", self.at(key)))),
        }
    }
}
fn with_path(e: Failure, path: &str) -> Failure {
    match e {
        Failure::Malformed(m) => malformed(format!("{m}: {path}")),
        other => other,
    }
}

/// Compare two JSON numbers exactly (§10.4): integers exactly, binary64 by IEEE-754, and an
/// integer against a binary64 without converting the integer.
pub fn compare_numbers(a: &Number, b: &Number) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    fn int(n: &Number) -> Option<i128> {
        if n.is_f64() {
            None
        } else {
            n.as_i64()
                .map(i128::from)
                .or_else(|| n.as_u64().map(i128::from))
        }
    }
    fn int_vs_float(i: i128, f: f64) -> Option<Ordering> {
        if !f.is_finite() {
            return None;
        }
        // |i| < 2^64 < 2^65 ≤ |f| decides at once; otherwise trunc(f) is exactly an integer
        // that fits i128, so both comparisons are exact.
        const BIG: f64 = 36_893_488_147_419_103_232.0; // 2^65
        if f >= BIG {
            return Some(Ordering::Less);
        }
        if f <= -BIG {
            return Some(Ordering::Greater);
        }
        let t = f.trunc();
        #[allow(clippy::cast_possible_truncation)]
        let ti = t as i128;
        match i.cmp(&ti) {
            Ordering::Equal => 0.0f64.partial_cmp(&(f - t)),
            other => Some(other),
        }
    }
    match (int(a), int(b)) {
        (Some(x), Some(y)) => Some(x.cmp(&y)),
        (Some(x), None) => int_vs_float(x, b.as_f64()?),
        (None, Some(y)) => int_vs_float(y, a.as_f64()?).map(Ordering::reverse),
        (None, None) => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn canonical_accepts_only_exact_bytes() {
        for ok in [
            br#"{}"#.as_slice(),
            br#"{"a":1,"b":[true,false,null],"c":{"d":"/"}}"#,
            br#"{"f":1.0,"g":-0.0,"h":1e21,"i":0.1,"j":-5,"k":18446744073709551615}"#,
            "{\"u\":\"é\\n\\u001f\\\"\\\\\"}".as_bytes(),
        ] {
            canonical_body(ok, 1000).unwrap();
        }
        for bad in [
            br#"{"b":1,"a":2}"#.as_slice(),
            br#"{ "a":1}"#,
            br#"{"a":1} "#,
            br#"{"a":1e2}"#,
            br#"{"a":1E21}"#,
            br#"{"a":01}"#,
            br#"{"a":-0}"#,
            br#"{"a":1.50}"#,
            br#"{"a":"\/"}"#,
            br#"{"a":"\u00e9"}"#,
            br#"{"a":"\u001F"}"#,
            br#"{"a":18446744073709551616}"#,
            br#"{"a":1,"a":1}"#,
            br#"[1]"#,
            b"\xef\xbb\xbf{}",
        ] {
            assert!(
                canonical_body(bad, 1000).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert!(canonical_body(br#"{"a":1}"#, 6).is_err());
    }

    #[test]
    fn base64_canonical_spelling() {
        assert_eq!(decode_base64("AAE=", 2).unwrap(), vec![0, 1]);
        for bad in ["AAF=", "AAE", "AA E=", "AAE==", "AA-=", "AAE=\n"] {
            assert!(decode_base64(bad, 10).is_err(), "{bad}");
        }
        assert!(decode_base64("AAEC", 2).is_err());
        let id = encode_base64url(&[7; 32]);
        assert_eq!(decode_request_id(&id).unwrap(), [7; 32]);
        assert!(decode_request_id(&format!("{id}=")).is_err());
    }

    #[test]
    fn dates_exist_and_have_three_fraction_digits() {
        assert_eq!(parse_date("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_date("1970-01-01T00:00:00.001Z"), Some(1));
        assert_eq!(
            parse_date("2024-02-29T23:59:59Z").unwrap() + 999,
            parse_date("2024-02-29T23:59:59.999Z").unwrap()
        );
        for bad in [
            "2026-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-11-11T24:00:00Z",
            "2026-11-11T23:60:00Z",
            "2026-11-11T23:59:60Z",
            "2026-11-11T09:00:00.00Z",
            "2026-11-11T09:00:00.0000Z",
            "2026-11-11T09:00:00",
            "2026-11-11 09:00:00Z",
            "2026-11-11T09:00:00+00:00",
            "0000-01-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-11-00T00:00:00Z",
            "+026-11-11T09:00:00Z",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
        assert!(parse_date("2000-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn numbers_compare_exactly() {
        use std::cmp::Ordering::*;
        let n = |s: &str| serde_json::from_str::<Number>(s).unwrap();
        assert_eq!(
            compare_numbers(&n("9007199254740993"), &n("9007199254740992.0")),
            Some(Greater)
        );
        assert_eq!(compare_numbers(&n("5000"), &n("5000.0")), Some(Equal));
        assert_eq!(compare_numbers(&n("5000"), &n("5000.5")), Some(Less));
        assert_eq!(compare_numbers(&n("-1"), &n("-0.5")), Some(Less));
        assert_eq!(
            compare_numbers(&n("18446744073709551615"), &n("1e30")),
            Some(Less)
        );
        assert_eq!(
            compare_numbers(&n("-9223372036854775808"), &n("-1e30")),
            Some(Greater)
        );
        assert_eq!(compare_numbers(&n("0.5"), &n("1")), Some(Less));
    }
}
