//! Sealing of the engine's device-local checkpoint: AES-256-GCM (`crypto::seal`, unchanged)
//! under a key derived by HKDF-SHA256 from the host's 32-byte device-held key, with a header
//! naming the account, the identity and the purpose as the authenticated data. The same
//! construction as the account's stored verifier state (`account/stored.rs`), with its own
//! purpose label so that one blob never opens as the other.
//!
//! Nothing here is trusted on bare bytes: a blob that fails any check is `None`.
use crate::crypto::{self, Entropy};
use crate::v05::account::Identity;
use crate::v05::encoding::canonical;
use crate::v05::{malformed, Result};
use serde_json::{json, Value};

const MAGIC: &[u8; 8] = b"COLOEN05";
const PURPOSE: &str = "colophon/engine-checkpoint/5";
const MAX_HEADER: usize = 2_048;
/// The most bytes of a checkpoint the engine reads.
pub const MAX_CHECKPOINT: usize = 256 * 1024 * 1024;

fn derive(key: &[u8; 32]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, key)
        .expand(PURPOSE.as_bytes(), &mut out)
        .map_err(|_| malformed("checkpoint key derivation"))?;
    Ok(out)
}

fn header(account: &str, me: &Identity, scope: &[String]) -> Result<Vec<u8>> {
    let (kind, id) = match me {
        Identity::Controller(i) => ("controller", i),
        Identity::Member(i) => ("member", i),
    };
    canonical(&json!({
        "account": account,
        "identity": {"id": id, "kind": kind},
        "purpose": PURPOSE,
        "scope": scope,
    }))
}

/// Seal `plain` for `account`, `me` and the namespace `scope`.
pub fn seal(
    plain: &[u8],
    account: &str,
    me: &Identity,
    scope: &[String],
    key: &[u8; 32],
    nonce_seed: [u8; 32],
) -> Result<Vec<u8>> {
    let head = header(account, me, scope)?;
    let nonce = Entropy::new(nonce_seed)
        .take::<12>()
        .map_err(|e| malformed(e.to_string()))?;
    let ct =
        crypto::seal(&derive(key)?, &nonce, plain, &head).map_err(|e| malformed(e.to_string()))?;
    let mut out = Vec::with_capacity(24 + head.len() + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(head.len() as u32).to_le_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The plaintext, when the tag verifies under `key` for exactly this `account`, `me` and
/// `scope`; `None` for everything else.
pub fn open(
    bytes: &[u8],
    account: &str,
    me: &Identity,
    scope: &[String],
    key: &[u8; 32],
) -> Option<Vec<u8>> {
    if bytes.len() < 24 + 16 || bytes.len() > MAX_CHECKPOINT || &bytes[..8] != MAGIC {
        return None;
    }
    let len = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
    if len > MAX_HEADER || bytes.len() < 12 + len + 12 + 16 {
        return None;
    }
    let head = &bytes[12..12 + len];
    if header(account, me, scope).ok()?.as_slice() != head {
        return None;
    }
    let claimed: Value = crate::v05::encoding::strict_parse(head).ok()?;
    if claimed.get("account")?.as_str()? != account {
        return None;
    }
    let nonce = &bytes[12 + len..24 + len];
    crypto::open(&derive(key).ok()?, nonce, &bytes[24 + len..], head).ok()
}
