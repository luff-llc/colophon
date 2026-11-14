//! The verifier's persisted state (§17.2) as a cache authenticated by a device-held key.
//!
//! The folded state a verifier saves is a function of the history and the objects held, but a
//! resume that takes it on its bare bytes lets anyone who can write the file change who is a
//! member or what is admitted. So the exported bytes are protected the way 0.4 protects its
//! checkpoints (`checkpoint.rs`): AES-256-GCM (`crypto::seal`, unchanged) under a key derived
//! by HKDF-SHA256 from a 32-byte key the host keeps in a device-held secret store (0.4's
//! `CheckpointKey::authentication_key`), with the header as the authenticated data. The header
//! names the account and the identity the state was exported for, so a blob moved to another
//! account or session fails its tag.
//!
//! Anything that does not verify (no key, a wrong key, a failed tag, an unknown format, a
//! blob for another identity or account, a shape failure) means the account replays from the
//! objects it is given. It is never an error that stops an account opening. The per-home head
//! marks are carried over only from a blob whose tag verified.
use super::Identity;
use crate::crypto::{self, Entropy};
use crate::v05::encoding::canonical;
use crate::v05::history::Persisted;
use crate::v05::{malformed, Result};
use serde_json::{json, Value};

const MAGIC: &[u8; 8] = b"COLOPS05";
const PURPOSE: &str = "colophon/persisted-verifier-state/5";
const MAX_HEADER: usize = 1_024;

fn derive(key: &[u8; 32]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, key)
        .expand(PURPOSE.as_bytes(), &mut out)
        .map_err(|_| malformed("persisted state key derivation"))?;
    Ok(out)
}

fn header(account: &str, me: &Identity) -> Result<Vec<u8>> {
    let (kind, id) = match me {
        Identity::Controller(i) => ("controller", i),
        Identity::Member(i) => ("member", i),
    };
    canonical(&json!({
        "account": account,
        "identity": {"id": id, "kind": kind},
        "purpose": PURPOSE,
    }))
}

/// Protect `persisted` for `account` and `me` under the host's `key`; `nonce_seed` is fresh
/// host entropy for this one export.
pub(super) fn protect(
    persisted: &Persisted,
    account: &str,
    me: &Identity,
    key: &[u8; 32],
    nonce_seed: [u8; 32],
) -> Result<Vec<u8>> {
    protect_plain(&persisted.to_bytes()?, account, me, key, nonce_seed)
}

/// Protect already-serialised state; the one place a blob is sealed.
fn protect_plain(
    plain: &[u8],
    account: &str,
    me: &Identity,
    key: &[u8; 32],
    nonce_seed: [u8; 32],
) -> Result<Vec<u8>> {
    let head = header(account, me)?;
    let nonce = Entropy::new(nonce_seed)
        .take::<12>()
        .map_err(|e| malformed(e.to_string()))?;
    let ciphertext =
        crypto::seal(&derive(key)?, &nonce, plain, &head).map_err(|e| malformed(e.to_string()))?;
    let mut out = Vec::with_capacity(24 + head.len() + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(head.len() as u32).to_le_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// What a blob whose tag verified held.
pub(super) enum Stored {
    /// The plaintext reads as persisted state of this format.
    Readable(Box<Persisted>),
    /// The tag verified but the plaintext is of another format or shape: the device's own old
    /// bytes, from which only the head marks and the succession flag can be carried over
    /// ([`Persisted::rebuild`], §17.2).
    Unreadable(Vec<u8>),
}

/// The state and the account it claims to be for, when the tag verifies under `key` for `me`;
/// `None` for everything else (no key, a wrong key, a failed tag, a blob for another identity).
pub(super) fn unprotect(bytes: &[u8], key: &[u8; 32], me: &Identity) -> Option<(Stored, String)> {
    if bytes.len() < 24 + 16 || &bytes[..8] != MAGIC {
        return None;
    }
    let len = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
    if len > MAX_HEADER || bytes.len() < 12 + len + 12 + 16 {
        return None;
    }
    let head = &bytes[12..12 + len];
    let nonce = &bytes[12 + len..24 + len];
    let ciphertext = &bytes[24 + len..];
    let claimed: Value = crate::v05::encoding::strict_parse(head).ok()?;
    let account = claimed.get("account")?.as_str()?.to_string();
    // The header must be exactly what this session would have written.
    if header(&account, me).ok()?.as_slice() != head {
        return None;
    }
    let plain = crypto::open(&derive(key).ok()?, nonce, ciphertext, head).ok()?;
    let stored = match Persisted::from_bytes(&plain) {
        Ok(p) => Stored::Readable(Box::new(p)),
        Err(_) => Stored::Unreadable(plain),
    };
    Some((stored, account))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "ab";

    /// A blob whose tag verifies but whose plaintext this build cannot read (a format change) is
    /// reported as unreadable, with its own bytes, so that `Persisted::rebuild` can carry the
    /// head marks over; a blob that fails its tag is nothing at all.
    #[test]
    fn a_verified_blob_of_another_format_is_unreadable_not_nothing() {
        let me = Identity::Member("0123456789abcdef0123456789abcdef".into());
        let key = [9u8; 32];
        let old = br#"{"format":1,"head_marks":{}}"#;
        let blob = protect_plain(old, ACCOUNT, &me, &key, [3; 32]).unwrap();
        match unprotect(&blob, &key, &me) {
            Some((Stored::Unreadable(b), a)) => {
                assert_eq!(b, old.to_vec());
                assert_eq!(a, ACCOUNT);
            }
            other => panic!("{:?}", other.map(|_| ())),
        }
        // A wrong key or another identity: nothing is carried over.
        assert!(unprotect(&blob, &[8u8; 32], &me).is_none());
        let other = Identity::Member("fedcba9876543210fedcba9876543210".into());
        assert!(unprotect(&blob, &key, &other).is_none());
    }
}
