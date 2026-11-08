//! Private, member-bound protection for storage-engine checkpoints. Not shared library records.
//! Hosts retain the signed ticket and supply signing/ECDH results; private keys never enter here.
use crate::{
    crypto::{self, Entropy, PublicIdentity},
    ensure,
    hpke::SealedKey,
    records::{bytes, canonical, SignedRecord},
    Error, Result,
};
use serde::{Deserialize, Serialize};

const PURPOSE: &str = "colophon/verified-prefix/protection/3";
const MAX_BYTES: usize = 256 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Ticket {
    purpose: String,
    library: String,
    member: PublicIdentity,
    key: SealedKey,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(with = "bytes")]
    ticket: Vec<u8>,
    #[serde(with = "bytes")]
    nonce: Vec<u8>,
    #[serde(with = "bytes")]
    ciphertext: Vec<u8>,
}
fn info(library: &str, member: &PublicIdentity) -> Result<Vec<u8>> {
    canonical(&(PURPOSE, library, member))
}

/// A new random cache key sealed to the member, awaiting a signature from that same member.
pub struct PreparedCheckpointKey {
    key: [u8; 32],
    body: Vec<u8>,
    member: PublicIdentity,
}
impl PreparedCheckpointKey {
    /// Fresh unpredictable host entropy is required. Never replace an inaccessible existing key.
    pub fn new(library: &str, member: PublicIdentity, seed: [u8; 32]) -> Result<Self> {
        member.validate()?;
        let mut entropy = Entropy::new(seed);
        let key = entropy.take::<32>()?;
        let ticket = Ticket {
            purpose: PURPOSE.into(),
            library: library.into(),
            key: SealedKey::seal(
                &member.agreement,
                &key,
                &info(library, &member)?,
                &mut entropy,
            )?,
            member: member.clone(),
        };
        Ok(Self {
            key,
            body: canonical(&ticket)?,
            member,
        })
    }
    /// Exact bytes to pass to the host's member signing key.
    pub fn signing_body(&self) -> &[u8] {
        &self.body
    }
    /// Authenticate the ticket's creator: public-key encryption alone cannot do this.
    pub fn finish(self, signature: Vec<u8>) -> Result<CheckpointKey> {
        let ticket =
            SignedRecord::finish_sign(self.body, signature, &self.member.signing)?.encode()?;
        Ok(CheckpointKey {
            key: self.key,
            ticket,
        })
    }
}

/// A private cache key and authenticated key ticket. Never serialize the plaintext key.
pub struct CheckpointKey {
    key: [u8; 32],
    ticket: Vec<u8>,
}
impl CheckpointKey {
    /// Supply this secret to `EngineOptions.checkpoint_key`.
    pub fn authentication_key(&self) -> [u8; 32] {
        self.key
    }
    fn encryption_key(&self) -> Result<[u8; 32]> {
        let mut key = [0; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &self.key)
            .expand(PURPOSE.as_bytes(), &mut key)
            .map_err(|_| Error("Checkpoint key derivation".into()))?;
        Ok(key)
    }
    /// Binary private envelope for native caches, avoiding base64 copies of large indexes.
    /// The ticket purpose and AEAD binding are identical to the JSON envelope.
    pub fn protect_binary(&self, checkpoint: &[u8], seed: [u8; 32]) -> Result<Vec<u8>> {
        ensure(checkpoint.len() <= MAX_BYTES, "Checkpoint too large")?;
        let nonce = Entropy::new(seed).take::<12>()?;
        let ciphertext = crypto::seal(&self.encryption_key()?, &nonce, checkpoint, &self.ticket)?;
        let mut output = Vec::with_capacity(24 + self.ticket.len() + ciphertext.len());
        output.extend_from_slice(b"COLOPRV3");
        output.extend_from_slice(&(self.ticket.len() as u32).to_le_bytes());
        output.extend_from_slice(&self.ticket);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }
    /// Encrypt an engine checkpoint for private host persistence, using fresh host entropy.
    /// The signed ticket is AEAD additional data, binding the recipient, library and sealed key.
    pub fn protect(&self, checkpoint: &[u8], seed: [u8; 32]) -> Result<Vec<u8>> {
        ensure(checkpoint.len() <= MAX_BYTES, "Checkpoint too large")?;
        let nonce = Entropy::new(seed).take::<12>()?.to_vec();
        let ciphertext = crypto::seal(&self.encryption_key()?, &nonce, checkpoint, &self.ticket)?;
        canonical(&Envelope {
            ticket: self.ticket.clone(),
            nonce,
            ciphertext,
        })
    }
}

/// A validated cache ticket awaiting host ECDH. Failure is an error, never a new identity/key.
pub struct CheckpointOpening {
    envelope: Envelope,
    ticket: Ticket,
}
impl CheckpointOpening {
    /// Verify the member signature and exact expected library/recipient before requesting ECDH.
    pub fn begin(bytes: &[u8], library: &str, member: &PublicIdentity) -> Result<Self> {
        ensure(
            bytes.len() <= MAX_BYTES * 2,
            "Protected checkpoint too large",
        )?;
        member.validate()?;
        let envelope: Envelope = if bytes.starts_with(b"COLOPRV3") {
            ensure(bytes.len() >= 24, "Truncated protected checkpoint")?;
            let length = u32::from_le_bytes(
                bytes[8..12]
                    .try_into()
                    .map_err(|_| Error("Checkpoint ticket length".into()))?,
            ) as usize;
            ensure(
                length <= 16 * 1024 && bytes.len() >= 24 + length + 16,
                "Invalid checkpoint ticket length",
            )?;
            Envelope {
                ticket: bytes[12..12 + length].to_vec(),
                nonce: bytes[12 + length..24 + length].to_vec(),
                ciphertext: bytes[24 + length..].to_vec(),
            }
        } else {
            serde_json::from_slice(bytes)?
        };
        ensure(
            envelope.ticket.len() <= 16 * 1024,
            "Checkpoint ticket too large",
        )?;
        let signed = crate::authority::raw_record(&envelope.ticket)?;
        signed.verify(&member.signing)?;
        let ticket: Ticket = serde_json::from_slice(&signed.body)?;
        ensure(
            ticket.purpose == PURPOSE && ticket.library == library && ticket.member == *member,
            "Checkpoint ticket library/member mismatch",
        )?;
        Ok(Self { envelope, ticket })
    }
    /// Peer point for the host's member agreement key.
    pub fn agreement_peer(&self) -> &[u8] {
        self.ticket.key.begin_open()
    }
    /// Return the original protection key and authenticated plaintext for `Engine::open`.
    pub fn finish(self, shared: &[u8]) -> Result<(CheckpointKey, Vec<u8>)> {
        let raw = self.ticket.key.finish_open(
            &self.ticket.member.agreement,
            shared,
            &info(&self.ticket.library, &self.ticket.member)?,
        )?;
        let key: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error("Checkpoint key length".into()))?;
        let key = CheckpointKey {
            key,
            ticket: self.envelope.ticket,
        };
        let checkpoint = crypto::open(
            &key.encryption_key()?,
            &self.envelope.nonce,
            &self.envelope.ciphertext,
            &key.ticket,
        )?;
        ensure(checkpoint.len() <= MAX_BYTES, "Checkpoint too large")?;
        Ok((key, checkpoint))
    }
}
