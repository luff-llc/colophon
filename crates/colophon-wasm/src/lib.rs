//! WebAssembly transport for the pure core. Every private-key operation is a Uint8Array host step.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
use colophon_core::{
    crypto::PublicIdentity,
    library::{AgreementStep, Call, CreateOptions, Library, PendingBatch},
    model::{Grant, Outcome, Records, Request},
    Error,
};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
fn identity(signing: &[u8], agreement: &[u8]) -> PublicIdentity {
    PublicIdentity {
        signing: signing.to_vec(),
        agreement: agreement.to_vec(),
    }
}
fn seed(bytes: &[u8]) -> Result<[u8; 32], JsValue> {
    bytes
        .try_into()
        .map_err(|_| js_error("Expected a fresh 32-byte action seed"))
}

/// An action's exact signing tasks, held in WASM until every host signature is supplied.
#[wasm_bindgen]
pub struct HostAction {
    pending: Option<PendingBatch>,
    signatures: Vec<Vec<u8>>,
    settled: Option<Value>,
}
impl HostAction {
    fn pending(pending: PendingBatch) -> Self {
        let count = pending.steps.len();
        Self {
            pending: Some(pending),
            signatures: vec![vec![]; count],
            settled: None,
        }
    }
    fn outcome(outcome: Outcome<PendingBatch>) -> Self {
        match outcome {
            Outcome::Success { value, .. } => Self::pending(value),
            failure => Self {
                pending: None,
                signatures: vec![],
                settled: Some(json!(failure)),
            },
        }
    }
    fn finish(mut self) -> Result<Records, JsValue> {
        self.pending
            .take()
            .ok_or_else(|| js_error("Action has no signing steps"))?
            .finish(self.signatures)
            .map_err(js_error)
    }
}
#[wasm_bindgen]
impl HostAction {
    /// Number of exact signing bodies.
    pub fn count(&self) -> usize {
        self.signatures.len()
    }
    /// Body bytes at an action step.
    pub fn body(&self, index: usize) -> Result<Vec<u8>, JsValue> {
        self.pending
            .as_ref()
            .and_then(|p| p.steps.get(index))
            .map(|s| s.body.clone())
            .ok_or_else(|| js_error("Invalid signing step"))
    }
    /// Public key which must sign this action step.
    pub fn signing_key(&self, index: usize) -> Result<Vec<u8>, JsValue> {
        self.pending
            .as_ref()
            .and_then(|p| p.steps.get(index))
            .map(|s| s.signing.clone())
            .ok_or_else(|| js_error("Invalid signing step"))
    }
    /// Storage path for inspection and write-result lookup.
    pub fn path(&self, index: usize) -> Result<String, JsValue> {
        self.pending
            .as_ref()
            .and_then(|p| p.steps.get(index))
            .map(|s| s.path.clone())
            .ok_or_else(|| js_error("Invalid signing step"))
    }
    /// Supply one raw 64-byte host signature; full validation happens before commit.
    pub fn sign(&mut self, index: usize, signature: &[u8]) -> Result<(), JsValue> {
        let slot = self
            .signatures
            .get_mut(index)
            .ok_or_else(|| js_error("Invalid signing step"))?;
        *slot = signature.to_vec();
        Ok(())
    }
    /// Immediate read outcome or refusal, as JSON; null means signing is required.
    pub fn settled(&self) -> String {
        self.settled
            .as_ref()
            .map(Value::to_string)
            .unwrap_or_else(|| "null".into())
    }
    /// Complete a standalone access request and return its envelope bytes.
    pub fn finish_request(self) -> Result<Vec<u8>, JsValue> {
        self.finish()?
            .into_values()
            .next()
            .ok_or_else(|| js_error("Empty request"))
    }
}
/// Host agreement step. The peer bytes cross WASM as a Uint8Array.
#[wasm_bindgen]
pub struct HostAgreement {
    step: AgreementStep,
}
#[wasm_bindgen]
impl HostAgreement {
    /// Namespace whose key is being opened.
    pub fn namespace(&self) -> String {
        self.step.namespace.clone()
    }
    /// Epoch number.
    pub fn epoch(&self) -> u32 {
        self.step.epoch as u32
    }
    /// Public ECDH peer.
    pub fn peer(&self) -> Vec<u8> {
        self.step.peer.clone()
    }
}
/// Verified library session. Binary records enter and leave individually as Uint8Arrays.
#[wasm_bindgen]
pub struct WasmLibrary {
    me: PublicIdentity,
    inner: Option<Library>,
    staged: Records,
}
impl WasmLibrary {
    fn library(&self) -> Result<&Library, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_error("Library has not been opened"))
    }
    fn library_mut(&mut self) -> Result<&mut Library, JsValue> {
        self.inner
            .as_mut()
            .ok_or_else(|| js_error("Library has not been opened"))
    }
}
#[wasm_bindgen]
impl WasmLibrary {
    /// Create an empty session for a host-owned identity; import records or prepare creation next.
    #[wasm_bindgen(constructor)]
    pub fn new(signing: &[u8], agreement: &[u8]) -> Result<WasmLibrary, JsValue> {
        let me = identity(signing, agreement);
        me.validate().map_err(js_error)?;
        Ok(Self {
            me,
            inner: None,
            staged: Records::new(),
        })
    }
    /// Stage exact record bytes without mutating the verified session.
    pub fn import_record(&mut self, path: String, raw: &[u8]) -> Result<(), JsValue> {
        if self.staged.get(&path).is_some_and(|old| old != raw) {
            return Err(js_error("Staged record conflict"));
        }
        self.staged.insert(path, raw.to_vec());
        Ok(())
    }
    /// Atomically verify all staged records. Failure leaves the prior session untouched.
    pub fn merge(&mut self) -> Result<(), JsValue> {
        let incoming = std::mem::take(&mut self.staged);
        if let Some(lib) = &mut self.inner {
            lib.merge(incoming).map_err(js_error)
        } else {
            self.inner = Some(Library::open(incoming, self.me.clone()).map_err(js_error)?);
            Ok(())
        }
    }
    /// Complete a signed action and atomically apply it.
    pub fn commit(&mut self, action: HostAction) -> Result<(), JsValue> {
        let records = action.finish()?;
        if let Some(lib) = &mut self.inner {
            lib.merge(records).map_err(js_error)
        } else {
            self.inner = Some(Library::open(records, self.me.clone()).map_err(js_error)?);
            Ok(())
        }
    }
    /// Prepare genesis and epoch-key creation, using fresh host entropy.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_create(
        &self,
        label: String,
        owner_label: String,
        namespaces: &str,
        recovery_signing: &[u8],
        recovery_agreement: &[u8],
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        if self.inner.is_some() {
            return Err(js_error("Library already exists"));
        }
        let namespaces = serde_json::from_str(namespaces).map_err(js_error)?;
        Library::begin_create(
            CreateOptions {
                owner: self.me.clone(),
                recovery: identity(recovery_signing, recovery_agreement),
                label,
                owner_label,
                namespaces,
            },
            now,
            seed(entropy)?,
        )
        .map(HostAction::pending)
        .map_err(js_error)
    }
    /// Prepare a self-signed request. Metadata is JSON, public keys remain binary arguments.
    pub fn begin_request(
        signing: &[u8],
        agreement: &[u8],
        metadata: &str,
    ) -> Result<HostAction, JsValue> {
        let mut value: Value = serde_json::from_str(metadata).map_err(js_error)?;
        value["member"] = json!(identity(signing, agreement));
        value["protocol"] = json!(colophon_core::protocol::REQUEST);
        let request: Request = serde_json::from_value(value).map_err(js_error)?;
        Library::begin_request(request)
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Verify a signed request and return display metadata (record bytes remain with the host).
    pub fn request_info(raw: &[u8], library: &str) -> Result<String, JsValue> {
        let r = Library::finish_request(raw.to_vec(), library).map_err(js_error)?;
        Ok(json!({"id":r.id,"label":r.label,"kind":r.kind,"namespaces":r.namespaces,"access":r.access,"pairingCode":r.pairing_code}).to_string())
    }
    /// Prepare an approval. Partial grant merging is done by the TypeScript facade.
    pub fn begin_approve(
        &self,
        request: &[u8],
        grant: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        let grant: Option<Grant> = serde_json::from_str(grant).map_err(js_error)?;
        self.library()?
            .begin_approve(request.to_vec(), grant, now, seed(entropy)?)
            .map(HostAction::outcome)
            .map_err(js_error)
    }
    /// Prepare revoke plus every required namespace rekey.
    pub fn begin_revoke(
        &self,
        member: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_revoke(member, now, seed(entropy)?)
            .map(HostAction::outcome)
            .map_err(js_error)
    }
    /// Prepare a sealed operation with grant enforcement.
    pub fn begin_write(
        &self,
        namespace: &str,
        kind: &str,
        payload: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_write(
                namespace,
                kind,
                serde_json::from_str(payload).map_err(js_error)?,
                now,
                seed(entropy)?,
            )
            .map(HostAction::outcome)
            .map_err(js_error)
    }
    /// Prepare planned root handover, with key reshares before the transfer.
    pub fn begin_handover(
        &self,
        signing: &[u8],
        agreement: &[u8],
        label: String,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_handover(identity(signing, agreement), label, now, seed(entropy)?)
            .map(HostAction::outcome)
            .map_err(js_error)
    }
    /// Prepare recovery of both authority and every data-key epoch.
    pub fn begin_recover(
        &self,
        signing: &[u8],
        agreement: &[u8],
        label: String,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_recover(identity(signing, agreement), label, now, seed(entropy)?)
            .map(HostAction::outcome)
            .map_err(js_error)
    }
    /// Count pending host ECDH tasks.
    pub fn unlock_count(&self) -> Result<usize, JsValue> {
        Ok(self.library()?.begin_unlock().len())
    }
    /// Obtain one pending host ECDH task.
    pub fn begin_unlock(&self, index: usize) -> Result<HostAgreement, JsValue> {
        self.library()?
            .begin_unlock()
            .into_iter()
            .nth(index)
            .map(|step| HostAgreement { step })
            .ok_or_else(|| js_error("No agreement step"))
    }
    /// Supply the host's raw 32-byte shared secret.
    pub fn finish_unlock(
        &mut self,
        namespace: &str,
        epoch: u32,
        shared: &[u8],
    ) -> Result<(), JsValue> {
        self.library_mut()?
            .finish_unlock(namespace, u64::from(epoch), shared)
            .map_err(js_error)
    }
    /// Library ID.
    pub fn id(&self) -> Result<String, JsValue> {
        Ok(self.library()?.id().into())
    }
    /// Current member JSON.
    pub fn me(&self) -> Result<String, JsValue> {
        Ok(json!(self.library()?.me()).to_string())
    }
    /// Member list JSON.
    pub fn members(&self) -> Result<String, JsValue> {
        Ok(json!(self.library()?.members()).to_string())
    }
    /// Plain-language ledger JSON.
    pub fn ledger(&self) -> Result<String, JsValue> {
        Ok(json!(self.library()?.ledger()).to_string())
    }
    /// Namespace Outcome JSON.
    pub fn view(&self, namespace: &str, now: &str) -> Result<String, JsValue> {
        Ok(json!(self.library()?.view(namespace, now).map_err(js_error)?).to_string())
    }
    /// Generated tool specifications JSON.
    pub fn tools(&self, now: &str) -> Result<String, JsValue> {
        Ok(json!(self.library()?.tools(now).map_err(js_error)?).to_string())
    }
    /// Route a generated read or write tool through the same core authorization path.
    pub fn begin_call(
        &self,
        tool: &str,
        input: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        match self
            .library()?
            .begin_call(
                tool,
                serde_json::from_str(input).map_err(js_error)?,
                now,
                seed(entropy)?,
            )
            .map_err(js_error)?
        {
            Outcome::Success {
                value: Call::Write { pending },
                ..
            } => Ok(HostAction::pending(pending)),
            Outcome::Success {
                value: Call::Read { value },
                ..
            } => Ok(HostAction {
                pending: None,
                signatures: vec![],
                settled: Some(json!({"ok":true,"value":value})),
            }),
            Outcome::Failure { reason, detail, .. } => Ok(HostAction {
                pending: None,
                signatures: vec![],
                settled: Some(json!({"ok":false,"reason":reason,"detail":detail})),
            }),
        }
    }
    /// Number of immutable records.
    pub fn record_count(&self) -> Result<usize, JsValue> {
        Ok(self.library()?.records().len())
    }
    /// Storage path at a deterministic index.
    pub fn record_path(&self, index: usize) -> Result<String, JsValue> {
        self.library()?
            .records()
            .keys()
            .nth(index)
            .cloned()
            .ok_or_else(|| js_error("Record index"))
    }
    /// Exact stored bytes at a deterministic index.
    pub fn record(&self, index: usize) -> Result<Vec<u8>, JsValue> {
        self.library()?
            .records()
            .values()
            .nth(index)
            .cloned()
            .ok_or_else(|| js_error(Error("Record index".into())))
    }
}
