use super::*;
use crate::blobs::{BlobManifest, BlobWriter};
impl Library {
    /// Start a streaming upload after current namespace write/grant checks.
    pub fn begin_blob(
        &self,
        namespace: &str,
        media_type: String,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<BlobWriter>> {
        if let Some(denial) = self.authorize(namespace, Access::Write, now)? {
            return Ok(Outcome::failure(denial));
        }
        let epoch = self
            .authority
            .epoch_at(namespace, self.authority.latest)
            .ok_or_else(|| missing("epoch"))?;
        let Some(key) = self.keys.get(&(namespace.into(), epoch)) else {
            return Ok(Outcome::failure(Denial::new(
                "notReadable",
                "Namespace blob key is unavailable",
            )));
        };
        Ok(Outcome::success(BlobWriter::new(
            key.clone(),
            self.id().into(),
            namespace.into(),
            epoch,
            media_type,
            seed,
        )?))
    }
    /// Retrieve a signed manifest through the same current grant check as all namespace queries.
    pub fn blob_manifest(
        &self,
        namespace: &str,
        digest: &str,
        now: &str,
    ) -> Result<Outcome<BlobManifest>> {
        match self.query(namespace, "blob", json!({"digest":digest}), now)? {
            Outcome::Success { value, .. } => {
                if value["manifest"].is_null() {
                    return Ok(Outcome::failure(Denial::new(
                        "unavailable",
                        "Blob manifest is missing",
                    )));
                }
                Ok(Outcome::success(serde_json::from_value(
                    value["manifest"].clone(),
                )?))
            }
            Outcome::Failure { reason, detail, .. } => {
                Ok(Outcome::failure(Denial::new(&reason, &detail)))
            }
        }
    }
    /// Authenticate one host-fetched chunk. Rechecks grants, including revocation and expiry.
    pub fn open_blob_chunk(
        &self,
        namespace: &str,
        digest: &str,
        index: usize,
        ciphertext: &[u8],
        now: &str,
    ) -> Result<Outcome<Vec<u8>>> {
        match self.blob_manifest(namespace, digest, now)? {
            Outcome::Success {
                value: manifest, ..
            } => {
                let Some(key) = self.keys.get(&(namespace.into(), manifest.epoch)) else {
                    return Ok(Outcome::failure(Denial::new(
                        "notReadable",
                        "Historical blob key is unavailable",
                    )));
                };
                Ok(Outcome::success(crate::blobs::open_chunk(
                    key,
                    self.id(),
                    namespace,
                    &manifest,
                    index,
                    ciphertext,
                )?))
            }
            Outcome::Failure { reason, detail, .. } => {
                Ok(Outcome::failure(Denial::new(&reason, &detail)))
            }
        }
    }
}
