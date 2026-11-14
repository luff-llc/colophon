//! Blobs (0.3 §7.2 with 0.5 §11.8's substitutions): signed encrypted manifests binding
//! content-addressed ciphertext chunks, written through the ordinary `colophon.blobPublish` and
//! `colophon.blobReference` operations, read through current grant checks and the account's
//! epoch keys. The chunk crypto is 0.4's `blobs` module, unchanged: AES-256-GCM under the
//! namespace epoch key, with the account (64 hex, 0.5's "library"), namespace, epoch, upload and
//! index as the authenticated data, so a chunk opens only under its own account, namespace and
//! epoch.
//!
//! Required versus optional retention is the manifest's `required` hint (a synchronized
//! eager-download hint): [`Engine::required_blob_fetches`] lists the chunks a device should
//! fetch. Blob garbage collection is **out of scope** and is not done: 0.3 §7.2 lets a client
//! remove a chunk only under confirmed custody or an explicit discard, and the relay has none.
use super::{Engine, RecordSource};
use crate::blobs::{BlobManifest, BlobRead, BlobVerifier, BlobWriter};
use crate::model::{Denial, Outcome};
use crate::v05::{malformed, require, Result};
use serde_json::json;

/// How much of a blob this device holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobAvailability {
    /// Every chunk is present locally (not yet authenticated: reading does that).
    Complete,
    /// Some chunks are present.
    Partial {
        /// Chunks present.
        present: usize,
        /// Chunks in the manifest.
        total: usize,
    },
    /// No chunk is present.
    Missing,
    /// The grant or the key does not allow reading it now; the detail.
    Inaccessible(String),
}

fn denial(reason: String, detail: String) -> Denial {
    Denial { reason, detail }
}

impl<S: RecordSource> Engine<S> {
    /// Start a streaming upload after the current namespace write check. The returned writer
    /// holds the epoch key it needs until it is dropped; never keep it.
    pub fn begin_blob(
        &self,
        namespace: &str,
        media_type: String,
        seed: [u8; 32],
    ) -> Result<Outcome<BlobWriter>> {
        self.check_ready()?;
        if let Some(d) = self.account.write_denial(namespace) {
            return Ok(Outcome::failure(d));
        }
        let auth = self.account.record_authority();
        let epoch = auth
            .epoch_at(namespace, auth.authority_seq())
            .ok_or_else(|| malformed("the namespace has no epoch yet"))?;
        let Some(key) = self
            .account
            .epoch_keys()
            .get(auth.account(), namespace, epoch)
        else {
            return Ok(Outcome::failure(denial(
                "notReadable".into(),
                "Namespace blob key is unavailable".into(),
            )));
        };
        Ok(Outcome::success(
            BlobWriter::new(
                key.expose().to_vec(),
                auth.account().as_str().chars().take(32).collect(),
                namespace.to_string(),
                epoch,
                media_type,
                seed,
            )
            .map_err(|e| malformed(e.to_string()))?,
        ))
    }

    /// The signed manifest, through the same current grant check as every namespace query.
    pub fn blob_manifest(&self, namespace: &str, digest: &str) -> Result<Outcome<BlobManifest>> {
        match self.query(namespace, "blob", json!({"digest": digest}))? {
            Outcome::Success { value, .. } => {
                // A domain query answers `{"value": …}`; the common ones may answer bare.
                let value = value.get("value").cloned().unwrap_or(value);
                if value["manifest"].is_null() {
                    return Ok(Outcome::failure(denial(
                        "unavailable".into(),
                        "Blob manifest is missing".into(),
                    )));
                }
                let m: BlobManifest = serde_json::from_value(value["manifest"].clone())
                    .map_err(|e| malformed(e.to_string()))?;
                m.validate().map_err(|e| malformed(e.to_string()))?;
                Ok(Outcome::success(m))
            }
            Outcome::Failure { reason, detail, .. } => Ok(Outcome::failure(denial(reason, detail))),
        }
    }

    /// Authenticate one chunk the host fetched, against the current grant and the epoch key of
    /// the manifest's epoch: the content address, the AEAD tag and the chunk's plaintext
    /// identity (0.3 §7.2).
    pub fn open_blob_chunk(
        &self,
        namespace: &str,
        digest: &str,
        index: usize,
        ciphertext: &[u8],
    ) -> Result<Outcome<Vec<u8>>> {
        let manifest = match self.blob_manifest(namespace, digest)? {
            Outcome::Success { value, .. } => value,
            Outcome::Failure { reason, detail, .. } => {
                return Ok(Outcome::failure(denial(reason, detail)))
            }
        };
        let account = self.account.id().clone();
        let Some(key) = self
            .account
            .epoch_keys()
            .get(&account, namespace, manifest.epoch)
        else {
            return Ok(Outcome::failure(denial(
                "notReadable".into(),
                "Historical blob key is unavailable".into(),
            )));
        };
        let bytes = crate::blobs::open_chunk(
            key.expose(),
            &account.as_str().chars().take(32).collect::<String>(),
            namespace,
            &manifest,
            index,
            ciphertext,
        )
        .map_err(|e| malformed(e.to_string()))?;
        Ok(Outcome::success(bytes))
    }

    /// Read and authenticate one chunk through the source: missing, inaccessible and invalid
    /// bytes stay distinct from available content, never an empty success.
    pub fn blob_chunk(&self, namespace: &str, digest: &str, index: usize) -> Result<BlobRead> {
        self.check_ready()?;
        let manifest = match self.blob_manifest(namespace, digest)? {
            Outcome::Success { value, .. } => value,
            Outcome::Failure { reason, detail, .. } => {
                return Ok(if reason == "unavailable" {
                    BlobRead::Missing
                } else {
                    BlobRead::Inaccessible(detail)
                })
            }
        };
        let chunk = manifest
            .chunks
            .get(index)
            .ok_or_else(|| malformed("invalid blob chunk index"))?;
        match self
            .source
            .read_blob(&chunk.path)
            .map_err(|e| crate::v05::Failure::Unavailable(e.0))?
        {
            BlobRead::Available(bytes) => {
                match self.open_blob_chunk(namespace, digest, index, &bytes) {
                    Ok(Outcome::Success { value, .. }) => Ok(BlobRead::Available(value)),
                    Ok(Outcome::Failure { detail, .. }) => Ok(BlobRead::Inaccessible(detail)),
                    Err(e) => Ok(BlobRead::Invalid(e.code())),
                }
            }
            other => Ok(other),
        }
    }

    /// Read the whole blob through the source, chunk by chunk, and mark it verified only when
    /// the complete descriptor (digest and size) matches. Returns the plaintext.
    pub fn read_blob(&self, namespace: &str, digest: &str) -> Result<BlobRead> {
        self.check_ready()?;
        let manifest = match self.blob_manifest(namespace, digest)? {
            Outcome::Success { value, .. } => value,
            Outcome::Failure { reason, detail, .. } => {
                return Ok(if reason == "unavailable" {
                    BlobRead::Missing
                } else {
                    BlobRead::Inaccessible(detail)
                })
            }
        };
        require(
            manifest.descriptor.size <= 1 << 30,
            "a blob read is bounded; stream it chunk by chunk",
        )?;
        let mut verifier = BlobVerifier::default();
        let mut out = Vec::new();
        for i in 0..manifest.chunks.len() {
            match self.blob_chunk(namespace, digest, i)? {
                BlobRead::Available(b) => {
                    verifier.update(&b);
                    out.extend_from_slice(&b);
                }
                other => return Ok(other),
            }
        }
        match verifier.finish(&manifest.descriptor) {
            Ok(()) => Ok(BlobRead::Available(out)),
            Err(e) => Ok(BlobRead::Invalid(e.to_string())),
        }
    }

    /// How much of the blob is held locally (chunk presence only).
    pub fn blob_availability(&self, namespace: &str, digest: &str) -> Result<BlobAvailability> {
        self.check_ready()?;
        let manifest = match self.blob_manifest(namespace, digest)? {
            Outcome::Success { value, .. } => value,
            Outcome::Failure { reason, detail, .. } => {
                return Ok(if reason == "unavailable" {
                    BlobAvailability::Missing
                } else {
                    BlobAvailability::Inaccessible(detail)
                })
            }
        };
        let mut present = 0;
        for c in &manifest.chunks {
            if matches!(
                self.source
                    .read_blob(&c.path)
                    .map_err(|e| crate::v05::Failure::Unavailable(e.0))?,
                BlobRead::Available(_)
            ) {
                present += 1;
            }
        }
        let total = manifest.chunks.len();
        Ok(match present {
            p if p == total => BlobAvailability::Complete,
            0 => BlobAvailability::Missing,
            p => BlobAvailability::Partial { present: p, total },
        })
    }

    /// The chunk paths of every blob marked `required` that this device does not hold: what a
    /// device should fetch from a home once the manifest is admitted (0.3 §7.2).
    pub fn required_blob_fetches(&self, namespace: &str) -> Result<Vec<String>> {
        self.check_ready()?;
        let mut missing = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let args = match &after {
                Some(a) => json!({"required": true, "limit": 1000, "after": a}),
                None => json!({"required": true, "limit": 1000}),
            };
            let page = match self.query(namespace, "blobs", args)? {
                Outcome::Success { value, .. } => value.get("value").cloned().unwrap_or(value),
                Outcome::Failure { .. } => return Ok(missing),
            };
            let items = page["blobs"].as_array().cloned().unwrap_or_default();
            for it in &items {
                let Some(d) = it["digest"].as_str() else {
                    continue;
                };
                if let Outcome::Success { value: m, .. } = self.blob_manifest(namespace, d)? {
                    for c in &m.chunks {
                        if !matches!(
                            self.source
                                .read_blob(&c.path)
                                .map_err(|e| crate::v05::Failure::Unavailable(e.0))?,
                            BlobRead::Available(_)
                        ) {
                            missing.push(c.path.clone());
                        }
                    }
                }
            }
            match page["next"].as_str() {
                Some(n) if !items.is_empty() => after = Some(n.to_string()),
                _ => break,
            }
        }
        missing.sort();
        missing.dedup();
        Ok(missing)
    }
}
