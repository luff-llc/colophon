//! Compact item projection encoding for device-local caches; no projected value is omitted.
use super::Item;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
type Items = BTreeMap<String, Item>;
type EncodedItem<'a> = (
    &'a str,
    Option<Vec<bool>>,
    Vec<&'a Value>,
    &'a Value,
    &'a Option<Value>,
    &'a Option<String>,
    &'a Option<String>,
    u64,
    &'a (u64, String, String),
);
type DecodedItem = (
    String,
    Option<Vec<bool>>,
    Vec<Value>,
    Value,
    Option<Value>,
    Option<String>,
    Option<String>,
    u64,
    (u64, String, String),
);

pub(super) fn serialize<S: serde::Serializer>(
    items: &Items,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let columns: BTreeSet<&str> = items
        .values()
        .filter_map(|item| item.value.as_object())
        .flat_map(|value| value.keys().map(String::as_str))
        .collect();
    let rows: Vec<EncodedItem<'_>> = items
        .iter()
        .map(|(id, item)| {
            let values: Vec<_> = columns.iter().map(|key| item.value.get(*key)).collect();
            let present = (!values.iter().all(Option::is_some))
                .then(|| values.iter().map(Option::is_some).collect());
            (
                id.as_str(),
                present,
                values.into_iter().flatten().collect(),
                &item.heads,
                &item.position,
                &item.selected,
                &item.checkpoint,
                item.added,
                &item.creation_order,
            )
        })
        .collect();
    (columns, rows).serialize(serializer)
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Items, D::Error> {
    let (columns, rows): (Vec<String>, Vec<DecodedItem>) = Deserialize::deserialize(deserializer)?;
    rows.into_iter()
        .map(
            |(
                id,
                present,
                values,
                heads,
                position,
                selected,
                checkpoint,
                added,
                creation_order,
            )| {
                let present = present.unwrap_or_else(|| vec![true; columns.len()]);
                if present.len() != columns.len()
                    || present.iter().filter(|p| **p).count() != values.len()
                {
                    return Err(serde::de::Error::custom("Invalid saved item columns"));
                }
                let names = columns
                    .iter()
                    .zip(present)
                    .filter(|(_, present)| *present)
                    .map(|(name, _)| name.clone());
                let value = Value::Object(names.zip(values).collect());
                Ok((
                    id,
                    Item {
                        value,
                        heads,
                        position,
                        selected,
                        checkpoint,
                        added,
                        creation_order,
                    },
                ))
            },
        )
        .collect()
}
