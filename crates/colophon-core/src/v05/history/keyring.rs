//! The keyring (§6.2) as a validated value, with the raw JSON kept for deltas (§8.7).
use crate::v05::descriptor::{Controller, Policy, Role};
use crate::v05::encoding::{canonical, decode_base64, uint, Obj};
use crate::v05::{malformed, require, Result, Unknown};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// A validated keyring.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Keyring {
    /// Controllers by ID.
    pub controllers: BTreeMap<String, Controller>,
    /// `threshold`.
    pub threshold: u64,
    /// `recoverThreshold`.
    pub recover_threshold: u64,
    /// `addThreshold`.
    pub add_threshold: u64,
    /// `countBy: holders`.
    pub holders: bool,
    /// Policy.
    pub policy: Policy,
    /// Vault signing and agreement points.
    pub vault: (Vec<u8>, Vec<u8>),
    /// Slots as values.
    pub slots: Vec<Value>,
    /// The keyring as received or as rebuilt by a delta (canonical shape).
    pub raw: Value,
    /// Unknown content (fields, roles, forms, policy values, slot kinds).
    pub unknown: Unknown,
}

impl Keyring {
    /// The unit of a controller: its ID, or its holder under `countBy: holders` (§6.1).
    pub fn unit_of(&self, c: &Controller) -> String {
        if self.holders {
            format!("holder:{}", c.holder().unwrap_or_default())
        } else {
            c.id()
        }
    }
    /// Distinct units among controllers holding `role`.
    pub fn units_with(&self, role: &Role) -> BTreeSet<String> {
        self.controllers
            .values()
            .filter(|c| c.has(role))
            .map(|c| self.unit_of(c))
            .collect()
    }
    /// Parse and check a keyring under §6.2. `min_slots` is 1 at genesis, 0 after an
    /// activation drops slots.
    pub fn parse(value: Value, min_slots: usize) -> Result<Self> {
        let raw = value.clone();
        let mut unknown = Unknown::default();
        let mut o = Obj::new(value, "keyring")?;
        let list = o.array("controllers")?;
        require(
            (1..=64).contains(&list.len()),
            "keyring must have 1–64 controllers",
        )?;
        let mut controllers = BTreeMap::new();
        let mut last: Option<String> = None;
        for v in list {
            let c = Controller::parse(v, "keyring.controllers[]")?;
            unknown.0.extend(c.unknown().0.iter().cloned());
            let id = c.id();
            require(
                last.as_ref().is_none_or(|l| l < &id),
                "controllers must be sorted by ID and distinct",
            )?;
            last = Some(id.clone());
            controllers.insert(id, c);
        }
        let threshold = o.uint("threshold")?;
        let recover_threshold = o.uint("recoverThreshold")?;
        let add_threshold = o.uint("addThreshold")?;
        let holders = match o.string("countBy")?.as_str() {
            "keys" => false,
            "holders" => true,
            other => {
                unknown.push(format!("keyring.countBy={other}"));
                false
            }
        };
        let policy = Policy::parse(o.value("policy")?, "keyring.policy")?;
        unknown.0.extend(policy.unknown().0.iter().cloned());
        let mut vault = o.obj("vault")?;
        let vs = vault.bytes("signing", 65)?;
        let va = vault.bytes("agreement", 65)?;
        vault.finish_closed()?;
        require(
            crate::v05::descriptor::valid_point(&vs)
                && crate::v05::descriptor::valid_point(&va)
                && vs != va,
            "invalid vault points",
        )?;
        let slots = o.array("slots")?;
        o.finish(&mut unknown);
        let k = Self {
            controllers,
            threshold,
            recover_threshold,
            add_threshold,
            holders,
            policy,
            vault: (vs, va),
            slots,
            raw,
            unknown,
        };
        k.check(min_slots)?;
        Ok(k)
    }
    /// §6.2's rules over the parsed keyring.
    pub fn check(&self, min_slots: usize) -> Result<()> {
        require(
            self.controllers.values().any(|c| c.has(&Role::Control)),
            "no controller holds control",
        )?;
        if self.holders {
            require(
                self.controllers.values().all(|c| c.holder().is_some()),
                "countBy holders needs a holder on every controller",
            )?;
        }
        let control = self.units_with(&Role::Control).len() as u64;
        let recover = self.units_with(&Role::Recover).len() as u64;
        require(
            (1..=control).contains(&self.threshold),
            "threshold out of range",
        )?;
        if recover == 0 {
            require(
                self.recover_threshold == 0,
                "recoverThreshold must be 0 without recover controllers",
            )?;
        } else {
            require(
                (1..=recover).contains(&self.recover_threshold),
                "recoverThreshold out of range",
            )?;
        }
        require(
            (1..=self.threshold).contains(&self.add_threshold),
            "addThreshold out of range",
        )?;
        require(
            (min_slots..=256).contains(&self.slots.len()),
            "slot count out of range",
        )?;
        for s in &self.slots {
            self.check_slot(s)?;
        }
        Ok(())
    }
    fn check_slot(&self, s: &Value) -> Result<()> {
        let m = s
            .as_object()
            .ok_or_else(|| malformed("slot must be an object"))?;
        let kind = m
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("slot kind"))?;
        require(
            matches!(kind, "sealed" | "prf" | "combined"),
            "unknown slot kind",
        )?;
        let ids = m
            .get("controllers")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("slot controllers"))?;
        require(!ids.is_empty(), "slot names no controller")?;
        for id in ids {
            let id = id.as_str().ok_or_else(|| malformed("slot controller"))?;
            let c = self
                .controllers
                .get(id)
                .ok_or_else(|| malformed("slot names a key that is not a controller"))?;
            require(!c.has(&Role::Sign), "a slot names a sign controller")?;
        }
        if kind != "combined" {
            require(ids.len() == 1, "a sealed or prf slot names one controller")?;
        }
        let label = m.get("label").and_then(Value::as_str).unwrap_or_default();
        require(
            (1..=200).contains(&label.len()),
            "slot label must be 1–200 bytes",
        )?;
        Ok(())
    }
    /// Controller IDs a slot names.
    pub fn slot_ids(s: &Value) -> Vec<String> {
        s.get("controllers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// A slot's identity for "every existing slot stays": canonical JSON without `label`.
    pub fn slot_key(s: &Value) -> Vec<u8> {
        let mut s = s.clone();
        if let Some(m) = s.as_object_mut() {
            m.remove("label");
        }
        canonical(&s).unwrap_or_default()
    }
    /// The raw keyring with `controllers` replaced (sorted) and other fields set.
    pub fn rebuild(
        &self,
        controllers: &BTreeMap<String, Value>,
        overrides: &Map<String, Value>,
    ) -> Value {
        let mut raw = self.raw.clone();
        if let Some(m) = raw.as_object_mut() {
            m.insert(
                "controllers".into(),
                Value::Array(controllers.values().cloned().collect()),
            );
            for (k, v) in overrides {
                m.insert(k.clone(), v.clone());
            }
        }
        raw
    }
    /// Raw controller values by ID.
    pub fn raw_controllers(&self) -> BTreeMap<String, Value> {
        self.raw
            .get("controllers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|c| {
                        let s = c.get("key")?.get("signing")?.as_str()?;
                        let p = decode_base64(s, 65).ok()?;
                        Some((crate::v05::ids::key_id(&p), c.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// An integer field of a JSON object, or `None`.
pub fn int_field(v: &Value, f: &str) -> Option<u64> {
    v.get(f).and_then(|x| uint(x, f).ok())
}
