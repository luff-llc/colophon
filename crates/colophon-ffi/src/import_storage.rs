//! Native import and lazy blob host adapters. Host callbacks never run under the library mutex.
use super::*;
use colophon_core::{blobs::BlobWriter, imports};
use std::collections::BTreeMap;

#[uniffi::export]
pub fn import_output_id(
    library: String,
    namespace: String,
    batch: String,
    child: String,
) -> Result<String> {
    Ok(imports::output_id(&library, &namespace, &batch, &child)?)
}
#[uniffi::export]
pub fn import_occurrence_id(library: String, namespace: String, source: Vec<u8>) -> Result<String> {
    Ok(imports::occurrence_id(
        &library,
        &namespace,
        &serde_json::from_slice(&source)?,
    )?)
}
#[uniffi::export]
pub fn reconcile_import_prefix(
    previous: Vec<u8>,
    current: Vec<u8>,
    imported_heads: Vec<u8>,
) -> Result<Vec<u8>> {
    let previous: BTreeMap<String, serde_json::Value> = serde_json::from_slice(&previous)?;
    let current = serde_json::from_slice(&current)?;
    Ok(serde_json::to_vec(&imports::reconcile_prefix(
        &previous,
        &current,
        &serde_json::from_slice(&imported_heads)?,
    ))?)
}
#[derive(uniffi::Record)]
pub struct BlobChunkWrite {
    pub path: String,
    pub bytes: Vec<u8>,
}
#[derive(uniffi::Object)]
pub struct NativeBlobWriter {
    writer: Mutex<Option<BlobWriter>>,
}
#[uniffi::export]
impl NativeBlobWriter {
    pub fn push(&self, plaintext: Vec<u8>) -> Result<BlobChunkWrite> {
        let mut guard = self.writer.lock().map_err(|_| BindingError::Poisoned)?;
        let (path, bytes) = guard
            .as_mut()
            .ok_or_else(|| invalid("Blob writer already finished"))?
            .push(&plaintext)?;
        Ok(BlobChunkWrite { path, bytes })
    }
    pub fn finish(&self) -> Result<Vec<u8>> {
        let writer = self
            .writer
            .lock()
            .map_err(|_| BindingError::Poisoned)?
            .take()
            .ok_or_else(|| invalid("Blob writer already finished"))?;
        Ok(serde_json::to_vec(&writer.finish()?)?)
    }
}
#[derive(uniffi::Enum)]
pub enum BlobWriteOutcome {
    Ready { writer: Arc<NativeBlobWriter> },
    Failure { denial: Denial },
}
/// Return immutable ciphertext at the supplied content-addressed path; never plaintext.
#[uniffi::export(callback_interface)]
pub trait BlobSource: Send + Sync {
    fn read(&self, path: String) -> Result<BlobReadOutcome>;
}
#[uniffi::export]
impl NativeLibrary {
    pub fn begin_import(
        &self,
        namespace: String,
        batch: Vec<u8>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        self.prepared(
            &s,
            s.library.begin_write(
                &namespace,
                imports::BATCH_KIND,
                serde_json::from_slice(&batch)?,
                &now,
                seed(entropy)?,
            )?,
        )
    }
    pub fn begin_blob(
        &self,
        namespace: String,
        media_type: String,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<BlobWriteOutcome> {
        match self
            .lock()?
            .library
            .begin_blob(&namespace, media_type, &now, seed(entropy)?)?
        {
            Outcome::Success { value, .. } => Ok(BlobWriteOutcome::Ready {
                writer: Arc::new(NativeBlobWriter {
                    writer: Mutex::new(Some(value)),
                }),
            }),
            Outcome::Failure { reason, detail, .. } => Ok(BlobWriteOutcome::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    pub fn read_blob_chunk(
        &self,
        namespace: String,
        digest: String,
        index: u32,
        now: String,
        source: Box<dyn BlobSource>,
    ) -> Result<BlobReadOutcome> {
        let path = {
            let s = self.lock()?;
            match s.library.blob_manifest(&namespace, &digest, &now)? {
                Outcome::Success { value, .. } => value
                    .chunks
                    .get(index as usize)
                    .ok_or_else(|| invalid("Invalid blob chunk index"))?
                    .path
                    .clone(),
                Outcome::Failure { reason, detail, .. } => {
                    return Ok(if reason == "unavailable" {
                        BlobReadOutcome::Missing
                    } else {
                        BlobReadOutcome::Inaccessible { detail }
                    })
                }
            }
        };
        let bytes = match source.read(path)? {
            BlobReadOutcome::Available { bytes } => bytes,
            other => return Ok(other),
        };
        // A callback can reenter and change authority. Recheck permission after it returns.
        match self.lock()?.library.open_blob_chunk(
            &namespace,
            &digest,
            index as usize,
            &bytes,
            &now,
        ) {
            Ok(Outcome::Success { value, .. }) => Ok(BlobReadOutcome::Available { bytes: value }),
            Ok(Outcome::Failure { detail, .. }) => Ok(BlobReadOutcome::Inaccessible { detail }),
            Err(error) => Ok(BlobReadOutcome::Invalid {
                detail: error.to_string(),
            }),
        }
    }
}

#[uniffi::export]
pub fn import_identity_category(namespace: String, kind: String) -> String {
    imports::identity_category(&namespace, &kind).into()
}

/// Explicit availability for a bounded chunk. Host callbacks return ciphertext; library methods
/// return only authenticated plaintext. Host Invalid/Inaccessible messages must not contain keys.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum BlobReadOutcome {
    Available { bytes: Vec<u8> },
    Missing,
    Inaccessible { detail: String },
    Invalid { detail: String },
}
