//! Streaming encrypted content-addressed blobs. Hosts persist immutable chunks before publishing
//! their signed manifest. Descriptors name plaintext; storage paths name ciphertext.
use crate::{
    crypto, ensure,
    records::{canonical, digest},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

/// Maximum plaintext bytes in one authenticated read/write.
pub const CHUNK_BYTES: usize = 64 * 1024;
/// Plaintext content identity used by domains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobDescriptor {
    /// SHA-256 of complete plaintext bytes, lowercase hex.
    pub digest: String,
    /// Complete plaintext length.
    pub size: u64,
    /// Retained media type; no format/anchor validity is inferred from it.
    pub media_type: String,
}
/// One chunk bound by the signed encrypted manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobChunk {
    /// Content-addressed ciphertext storage path.
    pub path: String,
    /// Plaintext chunk SHA-256.
    pub digest: String,
    /// Plaintext chunk length.
    pub size: u64,
    /// AES-GCM nonce, unique within this upload.
    pub nonce: Vec<u8>,
}
/// Authenticated by an import publication; never accept an unsigned host manifest as authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobManifest {
    /// Whole plaintext descriptor.
    pub descriptor: BlobDescriptor,
    /// Namespace epoch used to seal the chunks.
    pub epoch: u64,
    /// Random upload identity binding chunk order and preventing substitution.
    pub upload: String,
    /// Ordered chunk descriptors. Empty blobs have no chunks.
    pub chunks: Vec<BlobChunk>,
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl BlobManifest {
    /// Validate bounded metadata, lengths and digest syntax, without claiming availability.
    pub fn validate(&self) -> Result<()> {
        ensure(
            valid_digest(&self.descriptor.digest) && valid_digest(&self.upload),
            "Invalid blob digest",
        )?;
        ensure(
            self.epoch > 0
                && !self.descriptor.media_type.is_empty()
                && self.descriptor.media_type.len() <= 255,
            "Invalid blob descriptor",
        )?;
        ensure(
            self.chunks.len() <= 8192,
            "Blob manifest exceeds 8192 chunks",
        )?;
        let mut total = 0u64;
        for chunk in &self.chunks {
            ensure(
                chunk.nonce.len() == 12
                    && chunk.size > 0
                    && chunk.size <= CHUNK_BYTES as u64
                    && valid_digest(&chunk.digest),
                "Invalid blob chunk",
            )?;
            ensure(
                chunk.path.strip_prefix("blobs/").is_some_and(valid_digest),
                "Invalid blob path",
            )?;
            total = total
                .checked_add(chunk.size)
                .ok_or_else(|| Error("Blob size overflow".into()))?;
        }
        ensure(total == self.descriptor.size, "Blob size mismatch")
    }
}
/// Streaming writer holding an unlocked namespace key; never serialize or synchronize it.
pub struct BlobWriter {
    key: Vec<u8>,
    library: String,
    namespace: String,
    manifest: BlobManifest,
    hash: Sha256,
}
impl BlobWriter {
    pub(crate) fn new(
        key: Vec<u8>,
        library: String,
        namespace: String,
        epoch: u64,
        media_type: String,
        seed: [u8; 32],
    ) -> Result<Self> {
        ensure(
            !media_type.is_empty() && media_type.len() <= 255,
            "Invalid media type",
        )?;
        Ok(Self {
            key,
            library,
            namespace,
            manifest: BlobManifest {
                descriptor: BlobDescriptor {
                    digest: String::new(),
                    size: 0,
                    media_type,
                },
                epoch,
                upload: digest(&seed),
                chunks: Vec::new(),
            },
            hash: Sha256::new(),
        })
    }
    /// Seal at most 64 KiB and return (immutable path, ciphertext). Persist before publication.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<(String, Vec<u8>)> {
        ensure(
            !plaintext.is_empty()
                && plaintext.len() <= CHUNK_BYTES
                && self.manifest.chunks.len() < 8192,
            "Invalid blob chunk size/count",
        )?;
        let index = self.manifest.chunks.len();
        let nonce =
            Sha256::digest(canonical(&json!([self.manifest.upload, index]))?)[..12].to_vec();
        let aad = aad(&self.library, &self.namespace, &self.manifest, index)?;
        let ciphertext = crypto::seal(&self.key, &nonce, plaintext, &aad)?;
        let path = format!("blobs/{}", digest(&ciphertext));
        self.hash.update(plaintext);
        self.manifest.descriptor.size += plaintext.len() as u64;
        self.manifest.chunks.push(BlobChunk {
            path: path.clone(),
            digest: digest(plaintext),
            size: plaintext.len() as u64,
            nonce,
        });
        Ok((path, ciphertext))
    }
    /// Finish hashing. The caller publishes this manifest with the durable source unit.
    pub fn finish(mut self) -> Result<BlobManifest> {
        self.manifest.descriptor.digest = self
            .hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.manifest.validate()?;
        Ok(self.manifest)
    }
}
fn aad(library: &str, namespace: &str, manifest: &BlobManifest, index: usize) -> Result<Vec<u8>> {
    canonical(&json!([
        "colophon/blob/1",
        library,
        namespace,
        manifest.epoch,
        manifest.upload,
        index
    ]))
}
pub(crate) fn open_chunk(
    key: &[u8],
    library: &str,
    namespace: &str,
    manifest: &BlobManifest,
    index: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    manifest.validate()?;
    let chunk = manifest
        .chunks
        .get(index)
        .ok_or_else(|| Error("Invalid blob chunk index".into()))?;
    ensure(
        ciphertext.len() <= CHUNK_BYTES + 16
            && chunk.path == format!("blobs/{}", digest(ciphertext)),
        "Invalid blob ciphertext digest",
    )?;
    let bytes = crypto::open(
        key,
        &chunk.nonce,
        ciphertext,
        &aad(library, namespace, manifest, index)?,
    )?;
    ensure(
        bytes.len() as u64 == chunk.size && digest(&bytes) == chunk.digest,
        "Invalid blob plaintext digest/size",
    )?;
    Ok(bytes)
}
/// Incremental full-content verifier for consumers streaming chunks. Do not mark the complete
/// original verified until finish succeeds; per-chunk authentication alone cannot prove the total.
#[derive(Default)]
pub struct BlobVerifier {
    hash: Sha256,
    size: u64,
}
impl BlobVerifier {
    /// Feed plaintext in manifest order.
    pub fn update(&mut self, bytes: &[u8]) {
        self.hash.update(bytes);
        self.size += bytes.len() as u64;
    }
    /// Check complete content identity and length.
    pub fn finish(self, descriptor: &BlobDescriptor) -> Result<()> {
        let hash: String = self
            .hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        ensure(
            self.size == descriptor.size && hash == descriptor.digest,
            "Invalid complete blob digest/size",
        )
    }
}

/// Host blob availability. Missing or inaccessible content is never an empty successful read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobRead {
    /// Authenticated plaintext on engine return; ciphertext when supplied by a host source.
    Available(Vec<u8>),
    /// No local chunk; the host may hydrate it later.
    Missing,
    /// Current permission/key or host storage prevents reading.
    Inaccessible(String),
    /// Stored bytes failed content-address or AEAD authentication.
    Invalid(String),
}
