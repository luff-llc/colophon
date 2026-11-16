//! Freeze package, stream W1-C Swift: the 0.5 candidate vectors this stream generates.
//! Only that stream edits this file (`docs/design-freeze-package.md`, §0 "Order of work").
use super::kit::*;
use super::swift::*;
use serde_json::{json, Value};

pub fn part(out: &mut Out) {
    swift_seq_zero(out);
}

/// §16.3 "Sequence zero" (item L3): the predecessor and successor of `succession/swift-keyring`,
/// byte for byte, plus a readable envelope at seq 0 (the Swift genesis body with `seq` 0, signed
/// by the root key as the genesis is). No candidate can stand at seq 0, so the predecessor is
/// `malformed` and the succession is not verified, whatever order the envelopes arrive in.
///
/// Built from the generator's own `swift-keyring` files, which `cases_v8` writes earlier in the
/// same build, so the two vectors cannot drift apart.
fn swift_seq_zero(out: &mut Out) {
    const FROM: &str = "succession/swift-keyring/";
    const TO: &str = "succession/swift-seq-zero/";
    let case = format!("{FROM}case.json");
    let copied: Vec<(String, Vec<u8>)> = out
        .range(FROM.to_string()..)
        .take_while(|(rel, _)| rel.starts_with(FROM))
        .filter(|(rel, _)| **rel != case)
        .map(|(rel, data)| (format!("{TO}{}", &rel[FROM.len()..]), data.clone()))
        .collect();
    assert!(
        copied.len() > 3,
        "swift-keyring must be built before swift-seq-zero"
    );
    for (rel, data) in copied {
        write_raw(out, &rel, data);
    }
    let genesis: Value =
        serde_json::from_slice(&out[&format!("{FROM}predecessor/authority/00000001.json")])
            .unwrap();
    let mut body = body_json(&genesis);
    body["seq"] = json!(0);
    write(
        out,
        &format!("{TO}predecessor/authority/00000000.json"),
        &swift_record(&body, &ROOT_S, &[]),
    );
    let why = "§16.3 \"Sequence zero\": the predecessor of `swift-keyring`, plus a readable envelope whose `seq` is 0 (the genesis body at seq 0, signed by the root key): the sequence is contiguous from entry 1 and no candidate can stand at seq 0, so the predecessor is malformed and the succession is not verified, in any order.";
    // `unreadable` names the predecessor envelope no builder writes, so a test that rebuilds the
    // predecessor from its inputs leaves the case out (as for `swift-unreadable-issued-*`).
    write(
        out,
        &format!("{TO}case.json"),
        &json!({"description": why, "sections": ["16.3"],
                "expected": {"succession": "unverified"},
                "unreadable": ["00000000.json"]}),
    );
}
