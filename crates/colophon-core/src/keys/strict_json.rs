//! Duplicate-rejecting JSON parsing for all protocol JSON (§2.1).
use super::malformed;
use crate::Result;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Parse exactly one JSON value, rejecting duplicate names at every depth.
/// Escaped and unescaped spellings of the same member name are duplicates.
/// Null values remain available for schemas that permit them.
pub fn parse(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer).map_err(malformed)?;
    deserializer.end().map_err(malformed)?;
    Ok(value.0)
}

pub(super) struct StrictValue(pub Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Self)
    }
}
struct StrictVisitor;
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with unique object member names")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON member"));
            }
            values.insert(key, map.next_value::<StrictValue>()?.0);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicates_at_any_depth_and_escaped_names() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":[{"b":1,"\u0062":2}]}"#,
            br#"[1,{"x":{"z":null,"z":3}}]"#,
        ] {
            assert!(parse(bytes).is_err());
        }
    }
    #[test]
    fn values_and_exactly_one_document() {
        let bytes = br#"{"payload":[null,true,false,-1,1,1.0,-0,"x"],"other":{"a":1}}"#;
        assert_eq!(parse(bytes).ok(), serde_json::from_slice(bytes).ok());
        for bytes in [b"{} {}".as_slice(), b"{", b"NaN", b"[1,]", b"\xff"] {
            assert!(parse(bytes).is_err());
        }
    }
}
