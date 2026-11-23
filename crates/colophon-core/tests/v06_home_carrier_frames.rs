//! The home carrier and the session codec agree on what a frame is (0.6 sessions §S3, §S9;
//! `docs/colophon-0.6-stream.md` §5.2). Frames sealed by a real [`Endpoint`] and [`Sender`],
//! and every frame of the wire conformance vectors, pass the home's check with the outer
//! fields the codec wrote, and the bytes the home forwards open at a receiver. The home refuses
//! what is not the codec's form, and judges nothing inside a frame.
#![allow(clippy::unwrap_used)]
mod v06_codec_support;

use colophon_core::v05::home_stream::{check_session_frame, FrameRefusal, SessionOuter};
use colophon_core::v06::session::codec::Receiver;
use colophon_core::v06::session::*;
use serde_json::Value;
use std::path::PathBuf;
use v06_codec_support::*;

const MAXP: u64 = 8_192;

fn entitled() -> Vec<String> {
    vec![NS.to_string()]
}

/// A sealed beat from a to b, retained, and the first frames a's endpoint sends when it joins.
fn sealed(w: &World) -> (Vec<u8>, Vec<Vec<u8>>) {
    let view = w.view();
    let mut tx = sender(&w.a, &view, 11, cell());
    let beat = Frame {
        from: w.a.id.clone(),
        to: Some(w.b.id.clone()),
        retain: true,
        body: Body::Beat {
            claim: claim(2, &w.a),
            seq: 4,
        },
    };
    let beat = tx.seal(&beat, &epochs(), t0()).unwrap();
    let mut ep = endpoint(&w.a, &view, 21, Policy::default());
    let up: Vec<Vec<u8>> = ep
        .command(Command::Join { state: None }, clock(0), &epochs())
        .frames()
        .map(<[u8]>::to_vec)
        .collect();
    assert!(!up.is_empty(), "joining sends a hello");
    (beat, up)
}

#[test]
fn a_sealed_frame_passes_the_home_with_its_outer_fields_and_opens_after_forwarding() {
    let w = world();
    let view = w.view();
    let (beat, up) = sealed(&w);
    let outer = check_session_frame(&beat, ACCOUNT, &w.a.id, &entitled()).unwrap();
    assert_eq!(
        outer,
        SessionOuter {
            namespace: NS.into(),
            cell: CELL.into(),
            from: w.a.id.clone(),
            to: Some(w.b.id.clone()),
            retain: true,
        }
    );
    // The home forwards the bytes it checked; a receiver opens them.
    let mut rx = Receiver::new(cell(), &w.b.id);
    rx.open(&beat, &view, t0(), &epochs(), MAXP).unwrap();
    // The endpoint's hello carries its delegation; the home passes it without reading it.
    for f in &up {
        assert!(json(f).get("delegation").is_some_and(Value::is_object));
        let o = check_session_frame(f, ACCOUNT, &w.a.id, &entitled()).unwrap();
        assert_eq!((o.from.as_str(), o.to.as_deref()), (w.a.id.as_str(), None));
    }
}

#[test]
fn the_home_refuses_a_sealed_frame_outside_its_rules() {
    let w = world();
    let (beat, up) = sealed(&w);
    let check = |bytes: &[u8], account: &str, member: &str, entitled: &[String]| {
        check_session_frame(bytes, account, member, entitled)
    };
    assert_eq!(
        check(&beat, OTHER_ACCOUNT, &w.a.id, &entitled()),
        Err(FrameRefusal::Account)
    );
    assert_eq!(
        check(&beat, ACCOUNT, &w.b.id, &entitled()),
        Err(FrameRefusal::Spoofed)
    );
    assert_eq!(
        check(&beat, ACCOUNT, &w.a.id, &["notes".to_string()]),
        Err(FrameRefusal::NotEntitled)
    );
    let malformed = |bytes: &[u8]| {
        matches!(
            check(bytes, ACCOUNT, &w.a.id, &entitled()),
            Err(FrameRefusal::Malformed(_))
        )
    };
    // The former raw envelope over the frame, an unknown field, `retain: false`.
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let envelope = serde_json::json!({"body": STANDARD.encode(&beat), "signature": "AAAA"});
    assert!(malformed(&enc(&envelope)));
    assert!(malformed(&edit(&beat, |m| {
        m.insert("nonce".into(), "AAAAAAAAAAAAAAAA".into());
    })));
    assert!(malformed(&edit(&beat, |m| {
        m.insert("retain".into(), false.into());
    })));
    // Opaque fields outside the codec's grammar: a key that is not a key ID, a short
    // signature, a ciphertext shorter than its tag.
    for (field, value) in [
        ("key", Value::from("k")),
        ("signature", Value::from("AAAA")),
        ("ciphertext", Value::from("AAAA")),
    ] {
        assert!(malformed(&edit(&beat, |m| {
            m.insert(field.into(), value);
        })), "{field}");
    }
    // A delegation for another session key, one that is not an envelope, and one over its bound.
    let other = json(&up[0])["delegation"].clone();
    assert!(malformed(&edit(&beat, |m| {
        m.insert("delegation".into(), other);
    })));
    assert!(malformed(&edit(&beat, |m| {
        m.insert("delegation".into(), serde_json::json!({"anything": [1, 2]}));
    })));
    let mut padded = json(&up[0])["delegation"].clone();
    padded["body"] = STANDARD.encode(vec![b' '; 1_600]).into();
    assert!(malformed(&edit(&beat, |m| {
        m.insert("delegation".into(), padded);
    })));
    // Not canonical: the same object with a space.
    let text = String::from_utf8(beat.clone()).unwrap();
    assert!(malformed(text.replacen(':', ": ", 1).as_bytes()));
    // Over the size limit, with a ciphertext padded past it.
    let big = edit(&beat, |m| {
        m.insert("ciphertext".into(), "A".repeat(16_384).into());
    });
    assert_eq!(
        check(&big, ACCOUNT, &w.a.id, &entitled()),
        Err(FrameRefusal::TooLarge)
    );
}

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.6-sessions/wire/vectors.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn every_wire_vector_frame_passes_the_home() {
    let v = vectors();
    let account = v["account"].as_str().unwrap();
    let ns = vec![v["namespace"].as_str().unwrap().to_string()];
    let frames = v["frames"].as_array().unwrap();
    assert!(!frames.is_empty());
    for f in frames {
        let name = f["name"].as_str().unwrap();
        let bytes = f["frame"].as_str().unwrap().as_bytes();
        let from = json(bytes)["from"].as_str().unwrap().to_string();
        let o = check_session_frame(bytes, account, &from, &ns)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(o.from, from, "{name}");
        assert_eq!(o.namespace, ns[0], "{name}");
        assert_eq!(o.cell, v["cell"].as_str().unwrap(), "{name}");
        assert_eq!(o.to.as_deref(), f["to"].as_str(), "{name}");
        assert_eq!(o.retain, f["retain"] == Value::Bool(true), "{name}");
    }
}

#[test]
fn the_home_refuses_exactly_the_negative_vectors_it_can_judge() {
    // The home applies the receiver's parser and nothing after it: it refuses frames a receiver
    // drops as malformed, oversize or of another account, and forwards the rest, which only a
    // receiver can judge.
    let v = vectors();
    let account = v["account"].as_str().unwrap();
    let ns = vec![v["namespace"].as_str().unwrap().to_string()];
    for n in v["negative"].as_array().unwrap() {
        let name = n["name"].as_str().unwrap();
        let bytes = n["frame"].as_str().unwrap().as_bytes();
        let from = serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|f| f["from"].as_str().map(str::to_string))
            .unwrap_or_default();
        let got = check_session_frame(bytes, account, &from, &ns);
        match n["drop"].as_str() {
            Some("malformed") => assert!(
                matches!(got, Err(FrameRefusal::Malformed(_))),
                "{name}: {got:?}"
            ),
            Some("oversize") => assert_eq!(got, Err(FrameRefusal::TooLarge), "{name}"),
            Some("account") => assert_eq!(got, Err(FrameRefusal::Account), "{name}"),
            // A delegation that is not a well-formed envelope naming (from, key) is refused; one
            // that is well formed but does not verify is a receiver's to drop.
            Some("delegation") => assert!(
                got.is_ok() || matches!(got, Err(FrameRefusal::Malformed(_))),
                "{name}: {got:?}"
            ),
            _ => assert!(got.is_ok(), "{name}: {got:?}"),
        }
    }
}
