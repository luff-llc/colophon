//! Colophon 0.6 draft: the decisions behind a home's two-way stream and its notice routes
//! (`docs/colophon-0.6-stream.md`, `spec/colophon-0.6-sessions.md` §S3 and §S9). Additive: no 0.5
//! object, verdict or path changes.
//!
//! The home is not a party to a session. What it decides here is only what the carrier rule
//! lets it decide: whether a sealed frame's outer fields are well formed, whether the
//! connection's authenticated member is the frame's `from`, and whether that member is entitled
//! to the namespace by a `records` entry of its terms. It never reads, keeps or judges anything
//! inside the frame. Notice routes are host configuration, not account objects: who may change
//! one, how many a principal may hold, and what an address may look like are decided here so
//! that every home applies one rule.
use super::encoding::{hex, strict_parse};
use super::terms::{valid_namespace, Access, Terms};
use crate::v06::session::keys::Delegation;
use crate::v06::session::wire::{DropReason, WireFrame};
use serde_json::Value;

/// The protocol of a session frame body (§S3).
pub const SESSION_PROTOCOL: &str = "colophon/session/6";
/// The largest encoded session frame, bytes (§S3).
pub const SESSION_FRAME_BYTES: usize = 16_384;
/// The longest a carrier keeps a retained frame when it does not know the cell (§S9).
pub const RETAIN_MAX_MS: i64 = 60_000;
/// Notice routes one slot holds.
pub const MAX_ROUTES: usize = 64;
/// Notice routes one principal (a controller, or a member with every link key under it) holds.
pub const MAX_ROUTES_PER_PRINCIPAL: usize = 8;

/// Cell grammar (§S1): 1–64 bytes of `a–z 0–9 . -`.
pub fn valid_cell(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// The namespaces a member is entitled to on a home stream, with its access: one per `records`
/// entry of its terms (§S1 "Who may join": the members a home would serve `/changes` to for the
/// namespace). Empty for terms with no `records` (a service-only member).
pub fn stream_namespaces(terms: &Terms) -> Vec<(String, Access)> {
    terms
        .records()
        .into_iter()
        .flatten()
        .map(|e| (e.namespace.clone(), e.access))
        .collect()
}

/// Why a home refuses a session frame. A member cannot tell a refusal from loss (§S9); the
/// code is a diagnostic for the sending connection only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameRefusal {
    /// Not the codec's frame: strict canonical JSON with exactly the §S3 fields, well formed.
    Malformed(&'static str),
    /// Larger than [`SESSION_FRAME_BYTES`].
    TooLarge,
    /// Another account than the stream's.
    Account,
    /// `from` is not the connection's authenticated member.
    Spoofed,
    /// The member holds no `records` entry for the namespace.
    NotEntitled,
}

impl FrameRefusal {
    /// The stream's error code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            FrameRefusal::Malformed(_) => "badFrame",
            FrameRefusal::TooLarge => "tooLarge",
            FrameRefusal::Account => "account",
            FrameRefusal::Spoofed => "from",
            FrameRefusal::NotEntitled => "notEntitled",
        }
    }
}

/// The outer fields a home routes a session frame by: everything it learns (§S9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOuter {
    /// The namespace.
    pub namespace: String,
    /// The cell.
    pub cell: String,
    /// The sending member.
    pub from: String,
    /// The member the frame is addressed to, when present. Advice to receivers, not a route:
    /// the carrier forwards the frame to every other subscribed, entitled member either way.
    pub to: Option<String>,
    /// Whether the carrier keeps it as the latest for `(namespace, cell, from)`.
    pub retain: bool,
}

/// Check a session frame a member sent on its stream (§S3 outer fields, §S9 home carrier).
///
/// `encoded` is the frame exactly as it will be forwarded: the session codec's frame, one
/// canonical JSON object with the §S3 fields and no others. The syntax check is the codec's
/// own, the one a receiver applies before anything cryptographic
/// ([`WireFrame::parse`](crate::v06::session::wire::WireFrame::parse), and for a carried
/// delegation [`Delegation::parse_carried`]): strict canonical JSON (no duplicate names, no
/// lone surrogates, nesting at most 64), exactly the §S3 fields, every outer field in its
/// grammar, `key` a key ID, `n` and `epoch` from 1 to 2^53 − 1, `ciphertext` canonical base64 of
/// at least the 16-byte tag, `signature` canonical base64 of 64 bytes, and `delegation`, when
/// present, a canonical raw envelope of at most 2,048 bytes whose body is a well-formed
/// `colophon/session-key/6` body naming `from` and `key`. So the home forwards and retains only
/// frames a receiver can get past parsing. Nothing is verified or decrypted: the frame and
/// delegation signatures, the delegation's standing and window, the replay window and the
/// plaintext are a receiver's to judge. `member` is the member the connection authenticated as,
/// `entitled` the namespaces it holds `records` entries for, as [`stream_namespaces`] gives
/// them at the home's committed history.
pub fn check_session_frame(
    encoded: &[u8],
    account: &str,
    member: &str,
    entitled: &[String],
) -> Result<SessionOuter, FrameRefusal> {
    if encoded.len() > SESSION_FRAME_BYTES {
        return Err(FrameRefusal::TooLarge);
    }
    let frame = WireFrame::parse(encoded).map_err(|e| match e {
        DropReason::Oversize => FrameRefusal::TooLarge,
        _ => FrameRefusal::Malformed("frame is not a well-formed session frame"),
    })?;
    let o = frame.outer;
    if let Some(d) = &frame.delegation {
        Delegation::parse_carried(d, &o.from, &o.key)
            .map_err(|_| FrameRefusal::Malformed("delegation is not a well-formed envelope"))?;
    }
    if o.account != account {
        return Err(FrameRefusal::Account);
    }
    if o.from != member {
        return Err(FrameRefusal::Spoofed);
    }
    if !entitled.contains(&o.namespace) {
        return Err(FrameRefusal::NotEntitled);
    }
    Ok(SessionOuter {
        namespace: o.namespace,
        cell: o.cell,
        from: o.from,
        to: o.to,
        retain: o.retain,
    })
}

/// Check a subscription request: the cell is well formed and the member is entitled to the
/// namespace. The same entitlement rule as [`check_session_frame`].
pub fn check_subscription(
    namespace: &str,
    cell: &str,
    entitled: &[String],
) -> Result<(), FrameRefusal> {
    if !valid_namespace(namespace) {
        return Err(FrameRefusal::Malformed("namespace"));
    }
    if !valid_cell(cell) {
        return Err(FrameRefusal::Malformed("cell"));
    }
    if !entitled.iter().any(|n| n == namespace) {
        return Err(FrameRefusal::NotEntitled);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Notice routes (0.5 §17.5 leaves delivery to the home; these are this home's rules).

/// A notice route as registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// `push`, `email`, `sms`, `webhook` or `other`.
    pub kind: String,
    /// The delivery destination. Never listed back.
    pub address: String,
    /// What the route reaches (a device or service label). Listed.
    pub reaches: String,
}

/// The length of a slot's route key, bytes.
pub const ROUTE_KEY_BYTES: usize = 32;

/// A route's ID: lowercase hex HMAC-SHA256 under the slot's secret route key (random, held by
/// the home and never served) of `principal`, a zero byte, `kind`, a zero byte and `address`.
/// The ID is listed and named in notice lines, so it must not reveal the address: without the
/// key, nobody can test a guessed phone number or email against it. The principal is part of
/// the input so that registering an address answers the same for every principal whoever else
/// registered it (no cross-principal oracle), and one principal re-registering an address
/// replaces its own route.
pub fn route_id(key: &[u8], principal: &str, kind: &str, address: &str) -> String {
    let mut bytes = Vec::with_capacity(principal.len() + kind.len() + address.len() + 2);
    bytes.extend_from_slice(principal.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(kind.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(address.as_bytes());
    // HKDF-Extract(salt = key, ikm) is HMAC-SHA256(key, ikm) (RFC 5869 §2.2).
    let (mac, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(key), &bytes);
    hex(&mac)
}

/// Whether `id` has the form of a route ID (64 lowercase hex).
pub fn is_route_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn no_controls(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn dns_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && host.len() <= 253
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        // An IP literal written as a name (`10.0.0.1`) is not a DNS name.
        && !labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `address` is well formed for `kind`. A webhook is an `https://` URL to a public DNS
/// name: no user information, port, fragment, IP literal or local-only name, so a home that
/// later delivers to it cannot be pointed at its own network.
pub fn valid_route_address(kind: &str, address: &str) -> bool {
    match kind {
        "push" => (1..=4096).contains(&address.len()) && printable_ascii(address),
        "email" => {
            let Some((local, domain)) = address.split_once('@') else {
                return false;
            };
            address.len() <= 254
                && (1..=64).contains(&local.len())
                && printable_ascii(local)
                && !domain.contains('@')
                && dns_name(&domain.to_ascii_lowercase())
        }
        "sms" => {
            let Some(digits) = address.strip_prefix('+') else {
                return false;
            };
            (7..=15).contains(&digits.len())
                && digits.bytes().all(|b| b.is_ascii_digit())
                && !digits.starts_with('0')
        }
        "webhook" => {
            let Some(rest) = address.strip_prefix("https://") else {
                return false;
            };
            if address.len() > 2048 || !printable_ascii(address) || address.contains('#') {
                return false;
            }
            let authority = rest.split(['/', '?']).next().unwrap_or_default();
            let host = authority.to_ascii_lowercase();
            if host.contains('@') || host.contains(':') || host.contains('[') {
                return false;
            }
            let local = host == "localhost"
                || [".localhost", ".local", ".internal", ".home.arpa", ".lan"]
                    .iter()
                    .any(|suffix| host.ends_with(suffix));
            dns_name(&host) && !local
        }
        "other" => (1..=1024).contains(&address.len()) && no_controls(address),
        _ => false,
    }
}

/// Parse and check a route body: exactly `{"kind","address","reaches"}`, a known kind, an
/// address well formed for it, and a `reaches` label of 1–128 bytes with no control characters
/// that does not repeat the address (the list shows `reaches` and must never leak an address).
pub fn parse_route(body: &[u8]) -> Result<Route, &'static str> {
    let v = strict_parse(body).map_err(|_| "Invalid JSON")?;
    let Value::Object(o) = &v else {
        return Err("Invalid notice route");
    };
    let text = |k: &str| o.get(k).and_then(Value::as_str);
    let (Some(kind), Some(address), Some(reaches)) =
        (text("kind"), text("address"), text("reaches"))
    else {
        return Err("Invalid notice route");
    };
    if o.len() != 3 || !valid_route_address(kind, address) {
        return Err("Invalid notice route");
    }
    let folded = |s: &str| s.trim().to_lowercase();
    if !(1..=128).contains(&reaches.len())
        || !no_controls(reaches)
        || reaches.trim().is_empty()
        || folded(reaches).contains(&folded(address))
    {
        return Err("Invalid notice route");
    }
    Ok(Route {
        kind: kind.to_string(),
        address: address.to_string(),
        reaches: reaches.to_string(),
    })
}

/// What a home answers a route change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteVerdict {
    /// Make the change; `created` when a new ID is added.
    Allow {
        /// A new route.
        created: bool,
    },
    /// The route is another principal's (403 `refused:notGranted`).
    NotOwner,
    /// No such route to delete (404).
    Absent,
    /// The principal holds [`MAX_ROUTES_PER_PRINCIPAL`] already (507 `refused:overQuota`).
    PrincipalFull,
    /// The slot holds [`MAX_ROUTES`] already (507 `refused:overQuota`).
    SlotFull,
}

/// Decide a route change by `principal` (`controller:<ID>` or `member:<ID>`): a principal
/// changes and deletes only routes it registered, so one stolen key cannot silence the routes of
/// another device; a new route counts against the principal's share and the slot's cap.
/// `owner` is the registering principal of the route at that ID, if any.
pub fn route_change(
    owner: Option<&str>,
    principal: &str,
    principal_routes: usize,
    total_routes: usize,
    deleting: bool,
) -> RouteVerdict {
    match owner {
        Some(o) if o != principal => RouteVerdict::NotOwner,
        Some(_) => RouteVerdict::Allow { created: false },
        None if deleting => RouteVerdict::Absent,
        None if principal_routes >= MAX_ROUTES_PER_PRINCIPAL => RouteVerdict::PrincipalFull,
        None if total_routes >= MAX_ROUTES => RouteVerdict::SlotFull,
        None => RouteVerdict::Allow { created: true },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::v05::encoding::canonical;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    const ACCOUNT: &str = "1b420a5e226586586d53eab23862f233e12dce1a5532f36e4b1d578fa0edfb6a";
    const A: &str = "7f5be46131fa76b0fb7050f5779a5a21";
    const B: &str = "3959fc4d14735eaf9b9751593d868541";

    /// The frame's canonical bytes, as the session codec emits them.
    fn frame(body: Value) -> Vec<u8> {
        canonical(&body).unwrap()
    }
    /// The base64 of `n` zero bytes.
    fn zeros(n: usize) -> String {
        B64.encode(vec![0u8; n])
    }
    /// A frame in the codec's form, without a delegation. The home never opens the ciphertext
    /// or checks the signature, so both are zero bytes of the right lengths. Frames with real
    /// delegations are in `tests/v06_home_carrier_frames.rs`.
    fn body() -> Value {
        serde_json::json!({"protocol": SESSION_PROTOCOL, "account": ACCOUNT, "namespace": "notes",
            "cell": "now-playing", "from": A, "key": "2bad0fd610d99eae443e932a26142bca", "n": 1,
            "epoch": 1, "ciphertext": zeros(16), "signature": zeros(64)})
    }
    fn notes() -> Vec<String> {
        vec!["notes".to_string()]
    }
    fn malformed(bytes: &[u8]) -> bool {
        matches!(
            check_session_frame(bytes, ACCOUNT, A, &notes()),
            Err(FrameRefusal::Malformed(_))
        )
    }

    #[test]
    fn a_well_formed_frame_yields_its_outer_fields() {
        let mut b = body();
        b["to"] = B.into();
        b["retain"] = true.into();
        b["n"] = ((1u64 << 53) - 1).into();
        let outer = check_session_frame(&frame(b), ACCOUNT, A, &notes()).unwrap();
        assert_eq!(
            outer,
            SessionOuter {
                namespace: "notes".into(),
                cell: "now-playing".into(),
                from: A.into(),
                to: Some(B.into()),
                retain: true
            }
        );
        let plain = check_session_frame(&frame(body()), ACCOUNT, A, &notes()).unwrap();
        assert_eq!((plain.to, plain.retain), (None, false));
    }

    #[test]
    fn opaque_fields_follow_the_codecs_grammar() {
        // Any ciphertext of at least the tag passes: the home does not open it.
        let mut b = body();
        b["ciphertext"] = zeros(4_000).into();
        assert!(check_session_frame(&frame(b), ACCOUNT, A, &notes()).is_ok());
        // Absent, wrongly typed or outside the grammar a receiver's parser applies: refused.
        for (field, value) in [
            ("key", None),
            ("key", Some(Value::from(7))),
            ("key", Some(Value::from("not a key id"))),
            ("key", Some(Value::from("2BAD0FD610D99EAE443E932A26142BCA"))),
            ("n", None),
            ("n", Some(Value::from("1"))),
            ("n", Some(Value::from(0))),
            ("n", Some(Value::from(1u64 << 53))),
            ("n", Some(Value::from(1.5))),
            ("n", Some(Value::from(-1))),
            ("epoch", None),
            ("epoch", Some(Value::from(0))),
            ("ciphertext", None),
            ("ciphertext", Some(serde_json::json!({"anything": [1, 2]}))),
            ("ciphertext", Some(Value::from(zeros(15)))),
            ("ciphertext", Some(Value::from("!!"))),
            ("ciphertext", Some(Value::from("AAAAAAAAAAAAAAAAAAAAAB=="))),
            ("signature", None),
            ("signature", Some(Value::Null)),
            ("signature", Some(Value::from(zeros(63)))),
            ("signature", Some(Value::from(zeros(65)))),
            ("signature", Some(Value::from(""))),
            ("delegation", Some(Value::from("e30="))),
            ("delegation", Some(Value::Null)),
            ("delegation", Some(serde_json::json!({}))),
            ("delegation", Some(serde_json::json!({"anything": [1, 2]}))),
            ("delegation", Some(serde_json::json!({"body": "e30=", "signature": zeros(64)}))),
            ("delegation", Some(serde_json::json!({"body": zeros(1_500), "signature": zeros(64)}))),
        ] {
            let mut b = body();
            match value {
                Some(v) => b[field] = v,
                None => {
                    b.as_object_mut().unwrap().remove(field);
                }
            }
            assert!(malformed(&frame(b)), "{field}");
        }
    }

    #[test]
    fn spoofed_unentitled_and_foreign_frames_are_refused() {
        assert_eq!(
            check_session_frame(&frame(body()), ACCOUNT, B, &notes()),
            Err(FrameRefusal::Spoofed)
        );
        assert_eq!(
            check_session_frame(&frame(body()), ACCOUNT, A, &["books".to_string()]),
            Err(FrameRefusal::NotEntitled)
        );
        assert_eq!(
            check_session_frame(&frame(body()), &"0".repeat(64), A, &notes()),
            Err(FrameRefusal::Account)
        );
    }

    #[test]
    fn malformed_outer_fields_are_refused() {
        for (field, value) in [
            ("protocol", Value::from("colophon/session/5")),
            ("cell", Value::from("Now Playing")),
            ("cell", Value::from("x".repeat(65))),
            ("namespace", Value::from("Notes")),
            ("from", Value::from("not-an-id")),
            ("to", Value::from(7)),
            ("to", Value::from("not-an-id")),
            ("retain", Value::from(false)),
            ("account", Value::from(1)),
        ] {
            let mut b = body();
            b[field] = value;
            assert!(malformed(&frame(b)), "{field}");
        }
        for field in ["protocol", "account", "namespace", "cell", "from"] {
            let mut b = body();
            b.as_object_mut().unwrap().remove(field);
            assert!(malformed(&frame(b)), "{field}");
        }
    }

    #[test]
    fn only_the_codec_form_is_accepted() {
        // Unknown top-level fields, as a receiver's codec refuses them.
        for extra in ["nonce", "future", "body"] {
            let mut b = body();
            b[extra] = "AAAA".into();
            assert!(malformed(&frame(b)), "{extra}");
        }
        // The former envelope over a base64 body is refused, whatever the body holds.
        let inner = String::from_utf8(frame(body())).unwrap();
        let envelope = serde_json::json!({"body": B64.encode(inner), "signature": "AAAA"});
        assert!(malformed(&frame(envelope)));
        // Not an object, not strict JSON, or not canonical.
        let canonical_text = String::from_utf8(frame(body())).unwrap();
        let spaced = canonical_text.replacen(':', ": ", 1);
        let reordered = serde_json::to_string(&body())
            .unwrap()
            .replacen("{\"account\"", "{\"zz\":0,\"account\"", 1);
        let duplicate = canonical_text.replacen("{", "{\"account\":\"x\",", 1);
        let escaped = canonical_text.replacen("now-playing", "now\\u002dplaying", 1);
        let float = canonical_text.replacen("\"n\":1", "\"n\":1.0", 1);
        for bad in [
            "[]".to_string(),
            "\"frame\"".to_string(),
            "{".to_string(),
            format!("{canonical_text} "),
            spaced,
            reordered,
            duplicate,
            escaped,
            float,
        ] {
            assert!(malformed(bad.as_bytes()), "{bad}");
        }
        // Keys out of byte order are not canonical either.
        let swapped = canonical_text.replacen(
            &format!("\"account\":\"{ACCOUNT}\",\"cell\":\"now-playing\""),
            &format!("\"cell\":\"now-playing\",\"account\":\"{ACCOUNT}\""),
            1,
        );
        assert_ne!(swapped, canonical_text);
        assert!(malformed(swapped.as_bytes()));
    }

    #[test]
    fn the_size_limit_is_on_the_encoded_frame() {
        let mut b = body();
        b["ciphertext"] = "A".repeat(SESSION_FRAME_BYTES).into();
        let big = frame(b);
        assert!(big.len() > SESSION_FRAME_BYTES);
        assert_eq!(
            check_session_frame(&big, ACCOUNT, A, &notes()),
            Err(FrameRefusal::TooLarge)
        );
        assert_eq!(FrameRefusal::TooLarge.code(), "tooLarge");
        // The largest ciphertext that fits is accepted; three more bytes are over the limit.
        let fit = |len: usize| {
            let mut b = body();
            b["ciphertext"] = zeros(len).into();
            frame(b)
        };
        let mut len = 16;
        while fit(len + 3).len() <= SESSION_FRAME_BYTES {
            len += 3;
        }
        let edge = fit(len);
        assert!(edge.len() > SESSION_FRAME_BYTES - 4);
        assert!(check_session_frame(&edge, ACCOUNT, A, &notes()).is_ok());
        assert_eq!(
            check_session_frame(&fit(len + 3), ACCOUNT, A, &notes()),
            Err(FrameRefusal::TooLarge)
        );
    }

    #[test]
    fn subscriptions_need_entitlement_and_a_cell() {
        assert!(check_subscription("notes", "now-playing", &notes()).is_ok());
        assert_eq!(
            check_subscription("books", "now-playing", &notes()),
            Err(FrameRefusal::NotEntitled)
        );
        assert!(matches!(
            check_subscription("notes", "", &notes()),
            Err(FrameRefusal::Malformed(_))
        ));
    }

    #[test]
    fn route_addresses_are_checked_per_kind() {
        assert!(valid_route_address("push", "token-123"));
        assert!(!valid_route_address("push", "has space"));
        assert!(valid_route_address("email", "me@example.com"));
        assert!(!valid_route_address("email", "me@localhost"));
        assert!(!valid_route_address("email", "a@b@example.com"));
        assert!(valid_route_address("sms", "+15551234567"));
        assert!(!valid_route_address("sms", "5551234567"));
        assert!(valid_route_address(
            "webhook",
            "https://hooks.example.com/notify?x=1"
        ));
        for bad in [
            "http://hooks.example.com/",
            "https://127.0.0.1/",
            "https://10.0.0.1/x",
            "https://[::1]/",
            "https://localhost/",
            "https://printer.local/",
            "https://user@hooks.example.com/",
            "https://hooks.example.com:8443/",
            "https://hooks.example.com/#frag",
            "https://metadata.internal/",
        ] {
            assert!(!valid_route_address("webhook", bad), "{bad}");
        }
        assert!(valid_route_address("other", "pager 7"));
        assert!(!valid_route_address("fax", "123"));
    }

    #[test]
    fn route_ids_are_keyed_and_per_principal() {
        let key = [7u8; ROUTE_KEY_BYTES];
        let id = route_id(&key, "member:a", "sms", "+15551234567");
        assert!(is_route_id(&id));
        assert_eq!(id, route_id(&key, "member:a", "sms", "+15551234567"));
        // Not the unkeyed digest a listing reader could compute from a guessed number.
        assert_ne!(id, crate::v05::encoding::digest(b"sms\0+15551234567"));
        assert_ne!(
            id,
            route_id(&[8u8; ROUTE_KEY_BYTES], "member:a", "sms", "+15551234567")
        );
        assert_ne!(id, route_id(&key, "member:b", "sms", "+15551234567"));
        assert_ne!(id, route_id(&key, "member:a", "sms", "+15551234568"));
        assert!(!is_route_id(&"A".repeat(64)));
    }

    #[test]
    fn route_bodies_never_repeat_the_address() {
        let ok = br#"{"address":"private-device-token","kind":"push","reaches":"Phone"}"#;
        assert_eq!(parse_route(ok).unwrap().reaches, "Phone");
        let reflecting =
            br#"{"address":"private-device-token","kind":"push","reaches":" my PRIVATE-DEVICE-TOKEN "}"#;
        assert_eq!(parse_route(reflecting), Err("Invalid notice route"));
        let extra = br#"{"address":"private-device-token","kind":"push","reaches":"Phone","x":1}"#;
        assert_eq!(parse_route(extra), Err("Invalid notice route"));
        assert_eq!(parse_route(b"nope"), Err("Invalid JSON"));
    }

    #[test]
    fn routes_belong_to_their_principal_within_caps() {
        let me = "member:a";
        assert_eq!(
            route_change(Some("controller:c"), me, 0, 1, false),
            RouteVerdict::NotOwner
        );
        assert_eq!(
            route_change(Some("controller:c"), me, 0, 1, true),
            RouteVerdict::NotOwner
        );
        assert_eq!(
            route_change(Some(me), me, 8, 64, false),
            RouteVerdict::Allow { created: false }
        );
        assert_eq!(
            route_change(Some(me), me, 1, 1, true),
            RouteVerdict::Allow { created: false }
        );
        assert_eq!(route_change(None, me, 0, 0, true), RouteVerdict::Absent);
        assert_eq!(
            route_change(None, me, MAX_ROUTES_PER_PRINCIPAL, 10, false),
            RouteVerdict::PrincipalFull
        );
        assert_eq!(
            route_change(None, me, 0, MAX_ROUTES, false),
            RouteVerdict::SlotFull
        );
        assert_eq!(
            route_change(None, me, 7, 63, false),
            RouteVerdict::Allow { created: true }
        );
    }

    #[test]
    fn cells_follow_the_grammar() {
        assert!(valid_cell("now-playing"));
        assert!(valid_cell("a.b-1"));
        assert!(!valid_cell(""));
        assert!(!valid_cell("Now"));
        assert!(!valid_cell("a_b"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod purpose_tests {
    use crate::v05::calls::{
        home_purposes, is_route_upkeep, HISTORY_READ, HOME_PURPOSES, HOME_READ, HOME_STREAM,
        HOME_WRITE,
    };

    #[test]
    fn the_stream_purpose_is_reserved_for_minting_tickets() {
        assert!(HOME_PURPOSES.contains(&HOME_STREAM));
        assert_eq!(home_purposes("POST", "/stream/ticket"), &[HOME_STREAM]);
        assert_eq!(home_purposes("GET", "/stream"), &[HOME_READ]);
        // The batch read keeps its own purpose; neither route shadows the other.
        assert_eq!(home_purposes("POST", "/records/batch"), &[HOME_READ]);
        assert_eq!(home_purposes("POST", "/stream/ticket?x=1"), &[HOME_WRITE]);
        for (method, path) in [
            ("GET", "/changes"),
            ("GET", "/authority"),
            ("PUT", "/records/x"),
        ] {
            assert!(!home_purposes(method, path).contains(&HOME_STREAM));
        }
        assert!(home_purposes("GET", "/authority").contains(&HISTORY_READ));
    }

    #[test]
    fn route_upkeep_is_listing_and_changing_routes() {
        let id = "a".repeat(64);
        assert!(is_route_upkeep("GET", "/routes"));
        assert!(is_route_upkeep("POST", "/routes"));
        assert!(is_route_upkeep("DELETE", &format!("/routes/{id}")));
        assert!(!is_route_upkeep("PUT", &format!("/routes/{id}")));
        assert!(!is_route_upkeep("GET", &format!("/routes/{id}")));
        assert!(!is_route_upkeep(
            "DELETE",
            &format!("/routes/{}", "A".repeat(64))
        ));
        assert!(!is_route_upkeep("POST", "/routes/x"));
        assert!(!is_route_upkeep("GET", "/routes?x"));
    }
}
