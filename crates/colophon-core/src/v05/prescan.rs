//! The unknown-content pre-scan that §1 and §8.5 need for authority entries.
//!
//! For an authority entry, kind-specific fields are step 5 of §1's verification order: unknown
//! content (`newerFormat`, step 4) is decided **before** the typed schema (`malformed`). The
//! typed parsers in this crate check known fields as they read them, so an authority replayer
//! calls these scans first: they never fail, never allocate in proportion to unchecked lengths
//! beyond the already-bounded body, and report unknown fields, kinds, forms, roles, terms,
//! values and condition operators. Malformed known fields are ignored here; the typed parse that
//! follows reports them.
use super::Unknown;
use serde_json::{Map, Value};

fn extra(map: &Map<String, Value>, known: &[&str], path: &str, out: &mut Unknown) {
    for k in map.keys() {
        if !known.contains(&k.as_str()) {
            out.push(format!("{path}.{k}"));
        }
    }
}
fn value_in(v: Option<&Value>, known: &[&str], path: &str, out: &mut Unknown) {
    if let Some(Value::String(s)) = v {
        if !known.contains(&s.as_str()) {
            out.push(format!("{path}={s}"));
        }
    }
}

/// Scan a key descriptor.
pub fn descriptor(v: &Value, path: &str, out: &mut Unknown) {
    let Some(m) = v.as_object() else { return };
    match m.get("form").and_then(Value::as_str) {
        Some("raw") => extra(m, &["form", "signing", "agreement"], path, out),
        Some("webauthn") => extra(
            m,
            &[
                "form",
                "signing",
                "rp",
                "credential",
                "origins",
                "authorityOrigins",
            ],
            path,
            out,
        ),
        Some(other) => out.push(format!("{path}.form={other}")),
        None => {}
    }
}

/// Scan a controller.
pub fn controller(v: &Value, path: &str, out: &mut Unknown) {
    let Some(m) = v.as_object() else { return };
    extra(
        m,
        &[
            "key",
            "label",
            "roles",
            "verification",
            "holder",
            "audiences",
        ],
        path,
        out,
    );
    if let Some(k) = m.get("key") {
        descriptor(k, &format!("{path}.key"), out);
    }
    for r in m
        .get("roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        value_in(
            Some(r),
            &["approve", "control", "recover", "sign"],
            &format!("{path}.roles"),
            out,
        );
    }
}

/// Scan a policy.
pub fn policy(v: &Value, path: &str, out: &mut Unknown) {
    let Some(m) = v.as_object() else { return };
    extra(
        m,
        &[
            "callWindow",
            "headMaxAge",
            "headQuorum",
            "history",
            "linkMaxAge",
            "memberRule",
            "primaryHome",
            "rate",
            "recoveryDelay",
        ],
        path,
        out,
    );
    value_in(
        m.get("history"),
        &["members", "public"],
        &format!("{path}.history"),
        out,
    );
    value_in(
        m.get("memberRule"),
        &["single", "control"],
        &format!("{path}.memberRule"),
        out,
    );
    if let Some(r) = m.get("rate").and_then(Value::as_object) {
        extra(r, &["signer", "account"], &format!("{path}.rate"), out);
        for side in ["signer", "account"] {
            if let Some(x) = r.get(side).and_then(Value::as_object) {
                extra(
                    x,
                    &["entries", "bytes"],
                    &format!("{path}.rate.{side}"),
                    out,
                );
            }
        }
    }
}

fn predicate(v: &Value, depth: usize, out: &mut Unknown) {
    if depth > 8 {
        return;
    }
    let Some(m) = v.as_object() else { return };
    for (op, arg) in m {
        match op.as_str() {
            "eq" | "in" | "prefix" | "lte" | "gte" => {}
            "all" | "any" => {
                for i in arg.as_array().into_iter().flatten() {
                    predicate(i, depth + 1, out);
                }
            }
            "not" => predicate(arg, depth + 1, out),
            other => out.push(format!("conditions: operator {other}")),
        }
    }
}

/// Scan terms.
pub fn terms(v: &Value, out: &mut Unknown) {
    let Some(m) = v.as_object() else { return };
    extra(
        m,
        &[
            "records",
            "services",
            "expires",
            "writes",
            "depth",
            "conditions",
            "serves",
            "import",
        ],
        "terms",
        out,
    );
    for r in m
        .get("records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(e) = r.as_object() {
            extra(e, &["namespace", "access", "kinds"], "terms.records[]", out);
            value_in(
                e.get("access"),
                &["read", "propose", "write"],
                "terms.records.access",
                out,
            );
        }
    }
    for s in m
        .get("services")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(e) = s.as_object() {
            extra(e, &["audience", "purposes"], "terms.services[]", out);
        }
    }
    for s in m
        .get("serves")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        value_in(Some(s), &["home"], "terms.serves", out);
    }
    for c in m
        .get("conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        predicate(c, 1, out);
    }
}

fn epochs(v: Option<&Value>, path: &str, out: &mut Unknown) {
    for e in v.and_then(Value::as_array).into_iter().flatten() {
        if let Some(m) = e.as_object() {
            extra(m, &["namespace", "epoch", "seals"], path, out);
            for s in m
                .get("seals")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|x| x.values())
            {
                if let Some(sm) = s.as_object() {
                    extra(sm, &["enc", "ciphertext"], &format!("{path}.seals"), out);
                }
            }
        }
    }
}

/// Scan the kind-specific fields of an authority body (everything but the §8.1 header) for
/// the kinds this crate parses. `None` for a kind it doesn't scan (the caller decides).
pub fn authority_fields(kind: &str, body: &Value) -> Option<Unknown> {
    let mut out = Unknown::default();
    let m = body.as_object()?;
    const HEADER: &[&str] = &["protocol", "seq", "previous", "issued", "by", "kind"];
    let known: &[&str] = match kind {
        "grant" => &["request", "terms", "shares"],
        "renew" => &["member", "expires", "shares"],
        "revoke" => &["member", "kept", "heads", "epochs"],
        "endSessions" => &["member"],
        "genesis" => &["label", "namespaces", "keyring", "predecessor"],
        _ => return None,
    };
    let all: Vec<&str> = HEADER.iter().chain(known.iter()).copied().collect();
    extra(m, &all, "", &mut out);
    match kind {
        "grant" => {
            if let Some(t) = m.get("terms") {
                terms(t, &mut out);
            }
            epochs(m.get("shares"), "shares", &mut out);
        }
        "renew" => epochs(m.get("shares"), "shares", &mut out),
        "revoke" => {
            for h in m
                .get("heads")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(hm) = h.as_object() {
                    extra(hm, &["namespace", "digest"], "heads[]", &mut out);
                }
            }
            epochs(m.get("epochs"), "epochs", &mut out);
        }
        "genesis" => {
            if let Some(k) = m.get("keyring").and_then(Value::as_object) {
                extra(
                    k,
                    &[
                        "controllers",
                        "threshold",
                        "recoverThreshold",
                        "addThreshold",
                        "countBy",
                        "policy",
                        "vault",
                        "slots",
                    ],
                    "keyring",
                    &mut out,
                );
                for (i, c) in k
                    .get("controllers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    controller(c, &format!("keyring.controllers[{i}]"), &mut out);
                }
                if let Some(p) = k.get("policy") {
                    policy(p, "keyring.policy", &mut out);
                }
                value_in(
                    k.get("countBy"),
                    &["keys", "holders"],
                    "keyring.countBy",
                    &mut out,
                );
            }
        }
        _ => {}
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn scans_without_failing_on_malformed_known_fields() {
        let u = authority_fields(
            "grant",
            &json!({"protocol":"colophon/authority/5","kind":"grant","request":1,"shares":"x",
                    "terms":{"records":[{"namespace":7,"access":"own"}],"conditions":[{"not":{"future":1}}],"serves":["relay"],"later":true},
                    "extra":0}),
        )
        .unwrap_or_default();
        let s = u.0.join(" ");
        for want in [
            ".extra",
            "terms.later",
            "terms.records.access=own",
            "operator future",
            "terms.serves=relay",
        ] {
            assert!(s.contains(want), "{want} in {s}");
        }
        assert!(authority_fields("upgrade", &json!({})).is_none());
    }
}
