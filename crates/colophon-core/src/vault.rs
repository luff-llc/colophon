//! Vault identity for Colophon 0.4 (§5.1): derivation from the seed and the seed-to-vault check.

use crate::{
    crypto::{PublicIdentity, SoftwareKeys},
    records, Error, Result,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF salt required for vault identities by §5.1.
pub const SALT: &[u8] = b"colophon/vault/4";

/// Return the vault ID: the first 32 lowercase hex digits of SHA-256(signing).
pub fn id(vault: &PublicIdentity) -> String {
    records::id(&vault.signing)
}

/// Derive the vault's software identity (§5.1): an intermediate seed from HKDF-SHA256 with
/// salt `colophon/vault/4` and info `identity`, then the 0.3 §2 software-identity procedure.
pub fn derive(seed: [u8; 32]) -> Result<SoftwareKeys> {
    let mut intermediate = [0; 32];
    Hkdf::<Sha256>::new(Some(SALT), &seed)
        .expand(b"identity", &mut intermediate)
        .map_err(|_| Error("Vault derivation".into()))?;
    SoftwareKeys::from_seed(intermediate)
}

/// Check an opened seed against both public keys of the expected vault with the §5.1
/// derivation. All failures are `vaultLocked`; replace a session seed only on success.
pub fn check_seed(plaintext: &[u8], expected: &PublicIdentity) -> Result<[u8; 32]> {
    check_seed_with(plaintext, expected, derive)
}

/// Check an opened seed against both expected vault public keys.
///
/// `derive` must be the core's §5.1 software-identity derivation, not a host key
/// operation. Its explicit parameter keeps the unresolved salt mapping out of
/// this implementation. All failures are `vaultLocked`. The returned seed is
/// suitable for replacing a session seed only after this call succeeds.
pub fn check_seed_with(
    plaintext: &[u8],
    expected: &PublicIdentity,
    derive: impl FnOnce([u8; 32]) -> Result<SoftwareKeys>,
) -> Result<[u8; 32]> {
    let seed = <[u8; 32]>::try_from(plaintext).map_err(|_| locked())?;
    let public = derive(seed).map_err(|_| locked())?.public();
    if public != *expected {
        return Err(locked());
    }
    Ok(seed)
}

pub(crate) fn locked() -> Error {
    Error("vaultLocked".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_matches_the_recovery_pattern_with_the_vault_salt() {
        let seed = [3; 32];
        let mut intermediate = [0; 32];
        Hkdf::<Sha256>::new(Some(b"colophon/vault/4".as_slice()), &seed)
            .expand(b"identity", &mut intermediate)
            .unwrap();
        let expected = SoftwareKeys::from_seed(intermediate).unwrap().public();
        let derived = derive(seed).unwrap().public();
        assert_eq!(derived, expected);
        assert_ne!(derived, SoftwareKeys::from_seed(seed).unwrap().public());
        assert_ne!(derived, SoftwareKeys::recovery(seed).unwrap().public());
        assert_eq!(check_seed(&seed, &derived).unwrap(), seed);
        assert_eq!(check_seed(&[4; 32], &derived), Err(locked()));
    }

    #[test]
    fn checks_length_and_both_points_without_replacing_session_seed() {
        // This fixture tests the check, not the unresolved §5.1 derivation.
        let seed = [7; 32];
        let vault = SoftwareKeys::from_seed(seed).unwrap().public();
        assert_eq!(id(&vault), vault.id());
        assert_eq!(
            check_seed_with(&seed, &vault, SoftwareKeys::from_seed).unwrap(),
            seed
        );
        for length in [0, 31, 33, 64] {
            assert_eq!(
                check_seed_with(&vec![7; length], &vault, SoftwareKeys::from_seed),
                Err(locked())
            );
        }
        assert_eq!(
            check_seed_with(&[8; 32], &vault, SoftwareKeys::from_seed),
            Err(locked())
        );
        let other = SoftwareKeys::from_seed([8; 32]).unwrap().public();
        for expected in [
            PublicIdentity {
                signing: other.signing,
                agreement: vault.agreement.clone(),
            },
            PublicIdentity {
                signing: vault.signing.clone(),
                agreement: other.agreement,
            },
        ] {
            assert_eq!(
                check_seed_with(&seed, &expected, SoftwareKeys::from_seed),
                Err(locked())
            );
        }
        let mut session = [1; 32];
        if let Ok(opened) = check_seed_with(&[8; 32], &vault, SoftwareKeys::from_seed) {
            session = opened;
        }
        assert_eq!(session, [1; 32]);
        assert_eq!(
            check_seed_with(&seed, &vault, |_| Err(Error("derivation failed".into()))),
            Err(locked())
        );
    }
}
