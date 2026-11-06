//! Exact-byte signature verification with an optional trusted host backend.
use crate::{
    authority::Authority, ensure, library::operation_path, model::*, records::SignedRecord, Error,
    Result,
};
use p256::{
    ecdsa::{Signature, VerifyingKey},
    elliptic_curve::{
        bigint::U256,
        group::Group,
        ops::{Invert, Reduce},
        point::AffineCoordinates,
    },
    ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::OnceLock};

/// One verification task. The host must check ECDSA P-256/SHA-256 over these exact bytes.
/// Signatures are raw 64-byte r||s; public keys are uncompressed SEC1 points.
pub struct VerificationTask<'a> {
    /// Exact signed body, never reserialized.
    pub body: &'a [u8],
    /// Raw signature (both low-S and high-S are valid).
    pub signature: &'a [u8],
    /// Authority-selected public signing key.
    pub public_key: &'a [u8],
}
/// Trusted cryptographic provider only: the core still checks headers, IDs, grants and admission.
/// Return exactly one boolean per input, in order. An error aborts the operation.
pub trait BatchVerifier: Send + Sync {
    /// Verify a batch without changing its order or interpreting record payloads.
    fn verify(&self, tasks: &[VerificationTask<'_>]) -> Result<Vec<bool>>;
}

// Fixed-base tables contain PUBLIC points only. Unlike signing, verification may index
// tables by public signature/message scalars. All field/point arithmetic remains in p256.
// p256 0.13.2/primeorder 0.13.6 have no precomputed-table feature; their default
// multiplication builds a table and performs 256 doublings for each scalar each time.
type Table = Vec<[ProjectivePoint; 16]>;
fn table(point: ProjectivePoint) -> Table {
    let mut base = point;
    (0..64)
        .map(|_| {
            let mut row = [ProjectivePoint::IDENTITY; 16];
            for i in 1..16 {
                row[i] = row[i - 1] + base;
            }
            base = base.double().double().double().double();
            row
        })
        .collect()
}
fn multiply(table: &Table, scalar: Scalar) -> ProjectivePoint {
    let bytes = scalar.to_bytes();
    let mut sum = ProjectivePoint::IDENTITY;
    for (i, byte) in bytes.iter().rev().enumerate() {
        sum += table[i * 2][(byte & 15) as usize];
        sum += table[i * 2 + 1][(byte >> 4) as usize];
    }
    sum
}
pub(crate) struct PreparedKey {
    key: VerifyingKey,
    table: OnceLock<Table>,
}
impl PreparedKey {
    pub(crate) fn new(public: &[u8]) -> Result<Self> {
        let key = VerifyingKey::from_sec1_bytes(public)
            .map_err(|_| Error("Invalid signing public key".into()))?;
        Ok(Self {
            key,
            table: OnceLock::new(),
        })
    }
    pub(crate) fn verify(&self, record: &SignedRecord) -> Result<()> {
        static GENERATOR: OnceLock<Table> = OnceLock::new();
        let sig = Signature::from_slice(&record.signature)
            .map_err(|_| Error("Invalid signature format".into()))?;
        let z = <Scalar as Reduce<U256>>::reduce_bytes(&Sha256::digest(&record.body));
        let (r, s) = sig.split_scalars();
        let inverse = *s.invert_vartime();
        let point = multiply(
            GENERATOR.get_or_init(|| table(ProjectivePoint::GENERATOR)),
            z * inverse,
        ) + multiply(
            self.table
                .get_or_init(|| table(ProjectivePoint::from(*self.key.as_affine()))),
            *r * inverse,
        );
        ensure(
            !bool::from(point.is_identity())
                && *r == <Scalar as Reduce<U256>>::reduce_bytes(&point.to_affine().x()),
            "Invalid signature",
        )
    }
}

pub(crate) struct Verifiers(BTreeMap<String, PreparedKey>);
impl Verifiers {
    pub(crate) fn new(authority: &Authority) -> Self {
        Self(
            authority
                .members
                .iter()
                .filter_map(|(id, m)| {
                    PreparedKey::new(&m.public.signing)
                        .ok()
                        .map(|k| (id.clone(), k))
                })
                .collect(),
        )
    }
    pub(crate) fn operations(
        &self,
        authority: &Authority,
        input: &[(&str, &[u8])],
        host: Option<&dyn BatchVerifier>,
    ) -> Result<Vec<Result<(OperationHeader, String)>>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let parse = |(_, raw): &(&str, &[u8])| -> Result<(SignedRecord, OperationHeader)> {
            let record: SignedRecord = serde_json::from_slice(raw)?;
            let header: OperationHeader = serde_json::from_slice(&record.body)?;
            ensure(self.0.contains_key(&header.meta.author), "Missing author")?;
            Ok((record, header))
        };
        let validate = |path: &str, header: &OperationHeader| -> Result<()> {
            let meta = &header.meta;
            ensure(
                meta.protocol == "colophon/operation/2" && meta.library == authority.id,
                "Wrong operation protocol or library",
            )?;
            ensure(
                meta.id.len() == 32
                    && meta
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "Invalid operation ID",
            )?;
            ensure(path == operation_path(meta), "Operation path mismatch")?;
            ensure(
                meta.clock > 0
                    && meta.clock <= 9_007_199_254_740_991
                    && meta.authority > 0
                    && header.nonce.len() == 12
                    && header.ciphertext.len() >= 16,
                "Invalid operation header",
            )?;
            time_key(&meta.created)?;
            Ok(())
        };
        if let Some(host) = host {
            let parsed: Vec<_> = input.iter().map(parse).collect();
            let tasks: Vec<_> = parsed
                .iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|(r, h)| VerificationTask {
                    body: &r.body,
                    signature: &r.signature,
                    public_key: &authority.members[&h.meta.author].public.signing,
                })
                .collect();
            let answers = host.verify(&tasks)?;
            ensure(
                answers.len() == tasks.len(),
                "Host verification result count mismatch",
            )?;
            let mut answers = answers.into_iter();
            Ok(parsed
                .into_iter()
                .enumerate()
                .map(|(i, r)| {
                    let (record, header) = r?;
                    ensure(answers.next() == Some(true), "Invalid signature")?;
                    validate(input[i].0, &header)?;
                    Ok((header, crate::records::digest(&record.body)))
                })
                .collect())
        } else {
            Ok(parallel_map(input, |input| {
                let (record, header) = parse(input)?;
                self.0[&header.meta.author].verify(&record)?;
                validate(input.0, &header)?;
                Ok((header, crate::records::digest(&record.body)))
            }))
        }
    }
}

pub(crate) fn parallel_map<T: Sync, R: Send>(input: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
    {
        let threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(16)
            .min(input.len().div_ceil(64))
            .max(1);
        if threads > 1 {
            return std::thread::scope(|scope| {
                let handles: Vec<_> = input
                    .chunks(input.len().div_ceil(threads))
                    .map(|chunk| {
                        let f = &f;
                        scope.spawn(move || chunk.iter().map(f).collect::<Vec<_>>())
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().expect("verification worker panicked"))
                    .collect()
            });
        }
    }
    input.iter().map(f).collect()
}

pub(crate) fn parallel_for_each<T: Send>(input: &mut [T], f: impl Fn(&mut T) + Sync) {
    #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
    {
        let threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(16)
            .min(input.len().div_ceil(64))
            .max(1);
        if threads > 1 {
            let size = input.len().div_ceil(threads);
            std::thread::scope(|scope| {
                for chunk in input.chunks_mut(size) {
                    let f = &f;
                    scope.spawn(move || chunk.iter_mut().for_each(f));
                }
            });
            return;
        }
    }
    input.iter_mut().for_each(f);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_matches_rustcrypto() {
        for seed in 0..4 {
            let keys = crate::crypto::SoftwareKeys::from_seed([seed; 32]).expect("keys");
            let verifier = PreparedKey::new(&keys.public().signing).expect("point");
            for i in 0..64 {
                let body = vec![i; i as usize];
                let mut record = SignedRecord {
                    signature: keys.sign(&body),
                    body,
                };
                assert!(record.verify(&keys.public().signing).is_ok());
                assert!(verifier.verify(&record).is_ok());
                let sig = Signature::from_slice(&record.signature).expect("sig");
                let (r, s) = sig.split_scalars();
                record.signature = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes())
                    .expect("high S")
                    .to_bytes()
                    .to_vec();
                assert_eq!(
                    verifier.verify(&record).is_ok(),
                    record.verify(&keys.public().signing).is_ok()
                );
                record.body.push(0);
                assert!(verifier.verify(&record).is_err());
                assert_eq!(
                    verifier.verify(&record).is_ok(),
                    record.verify(&keys.public().signing).is_ok()
                );
                record.signature[i as usize % 64] ^= 0xff;
                assert_eq!(
                    verifier.verify(&record).is_ok(),
                    record.verify(&keys.public().signing).is_ok()
                );
            }
            for signature in [vec![], vec![0; 64], vec![255; 64]] {
                let record = SignedRecord {
                    body: vec![0],
                    signature,
                };
                assert_eq!(
                    verifier.verify(&record).is_ok(),
                    record.verify(&keys.public().signing).is_ok()
                );
            }
        }
    }
}
