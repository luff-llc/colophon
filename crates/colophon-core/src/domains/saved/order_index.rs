//! Compact local-checkpoint encoding for repeated shelf ordering keys.
//! Every bucket remains a maintained ordered set; keys are shared, never historical payloads.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub(super) type Key = (String, String);
pub(super) type Index = BTreeMap<String, BTreeMap<String, BTreeSet<Arc<Key>>>>;

pub(super) fn serialize<S: serde::Serializer>(
    index: &Index,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let keys: BTreeSet<&Key> = index
        .values()
        .flat_map(BTreeMap::values)
        .flat_map(|set| set.iter().map(Arc::as_ref))
        .collect();
    let ids: BTreeMap<&Key, usize> = keys.iter().enumerate().map(|(i, key)| (*key, i)).collect();
    // Many filter buckets have identical membership. Encode each ordered set only once.
    let sets: BTreeSet<&BTreeSet<Arc<Key>>> = index.values().flat_map(BTreeMap::values).collect();
    let set_ids: BTreeMap<_, usize> = sets.iter().enumerate().map(|(i, set)| (*set, i)).collect();
    let members: Vec<Vec<usize>> = sets
        .iter()
        .map(|set| set.iter().map(|key| ids[key.as_ref()]).collect())
        .collect();
    let buckets: BTreeMap<&str, BTreeMap<&str, usize>> = index
        .iter()
        .map(|(bucket, sorts)| {
            (
                bucket.as_str(),
                sorts
                    .iter()
                    .map(|(sort, set)| (sort.as_str(), set_ids[set]))
                    .collect(),
            )
        })
        .collect();
    (keys, members, buckets).serialize(serializer)
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Index, D::Error> {
    type Encoded = (
        Vec<Key>,
        Vec<Vec<usize>>,
        BTreeMap<String, BTreeMap<String, usize>>,
    );
    let (keys, sets, buckets): Encoded = Deserialize::deserialize(deserializer)?;
    let keys: Vec<_> = keys.into_iter().map(Arc::new).collect();
    let sets: Vec<BTreeSet<Arc<Key>>> = sets
        .into_iter()
        .map(|ids| {
            ids.into_iter()
                .map(|id| {
                    keys.get(id)
                        .cloned()
                        .ok_or_else(|| serde::de::Error::custom("Invalid shelf ordering key"))
                })
                .collect::<Result<_, D::Error>>()
        })
        .collect::<Result<_, _>>()?;
    buckets
        .into_iter()
        .map(|(bucket, sorts)| {
            let sorts = sorts
                .into_iter()
                .map(|(sort, id)| {
                    // Independent tree nodes keep edits from copying a whole shared tree.
                    let set = sets
                        .get(id)
                        .cloned()
                        .ok_or_else(|| serde::de::Error::custom("Invalid shelf ordering set"))?;
                    Ok((sort, set))
                })
                .collect::<Result<_, D::Error>>()?;
            Ok((bucket, sorts))
        })
        .collect()
}
