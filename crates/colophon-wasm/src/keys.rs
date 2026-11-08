//! Two-phase keyring and vault host work. JSON uses the protocol's base64 byte encoding.
use super::*;
use colophon_core::{
    authority::{Action, Controller, Keyring},
    keys::{strict_json, KeyDescriptor},
    library::PrfPreparation,
    slots::{OpeningInput, OpeningSecret, Slot},
};
macro_rules! parse {
    ($value:expr) => {
        serde_json::from_value(strict_json::parse($value.as_bytes()).map_err(js_error)?)
            .map_err(js_error)
    };
    ($value:expr, $ty:ty) => {
        serde_json::from_value::<$ty>(strict_json::parse($value.as_bytes()).map_err(js_error)?)
            .map_err(js_error)
    };
}
fn controller(value: &str) -> Result<Controller, JsValue> {
    parse!(value)
}
fn slot_inputs(library: &Library, index: usize) -> Result<Value, JsValue> {
    Ok(Value::Array(
        library
            .begin_unlock_slot(index)
            .map_err(js_error)?
            .into_iter()
            .map(|input| match input {
                OpeningInput::Ecdh { controller, enc } => {
                    json!({"kind":"ecdh","controller":controller,"enc":enc})
                }
                OpeningInput::Prf { controller, salt } => {
                    json!({"kind":"prf","controller":controller,"salt":salt})
                }
            })
            .collect(),
    ))
}
/// Single-use get ceremony for constructing a checked PRF slot.
#[wasm_bindgen]
pub struct HostPrf {
    pending: PrfPreparation,
}
#[wasm_bindgen]
impl HostPrf {
    /// Descriptor JSON. Restrict get to exactly this credential.
    pub fn descriptor(&self) -> String {
        json!(self.pending.key).to_string()
    }
    /// Exact prf.eval.first bytes.
    pub fn salt(&self) -> Vec<u8> {
        self.pending.salt.to_vec()
    }
    /// Fresh base64url get challenge.
    pub fn challenge(&self) -> String {
        self.pending.challenge.clone()
    }
}
#[wasm_bindgen]
impl HostAction {
    /// Signer's complete descriptor JSON.
    pub fn descriptor(&self, index: usize) -> Result<String, JsValue> {
        self.pending
            .as_ref()
            .and_then(|p| p.steps.get(index))
            .map(|s| json!(s.signer).to_string())
            .ok_or_else(|| js_error("Invalid signing step"))
    }
    /// WebAuthn base64url SHA-256 challenge; absent for raw signers.
    pub fn challenge(&self, index: usize) -> Result<Option<String>, JsValue> {
        self.pending
            .as_ref()
            .and_then(|p| p.steps.get(index))
            .map(|s| s.challenge.clone())
            .ok_or_else(|| js_error("Invalid signing step"))
    }
    /// Supply the exact WebAuthn DER signature and assertion bytes for one signer.
    pub fn assert(
        &mut self,
        index: usize,
        signature: &[u8],
        authenticator_data: &[u8],
        client_data: &[u8],
    ) -> Result<(), JsValue> {
        let result = self
            .signatures
            .get_mut(index)
            .ok_or_else(|| js_error("Invalid signing step"))?;
        *result = SignatureResult {
            signature: signature.to_vec(),
            assertion: Some(colophon_core::keys::Assertion::new(
                authenticator_data.to_vec(),
                client_data.to_vec(),
            )),
        };
        Ok(())
    }
}
#[wasm_bindgen]
impl WasmLibrary {
    /// Verify every prepared signature/assertion and atomically apply the authority batch.
    pub fn finish_authority(&mut self, action: HostAction) -> Result<(), JsValue> {
        self.commit(action)
    }
    /// Current keyring protocol JSON.
    pub fn keyring(&self) -> Result<String, JsValue> {
        Ok(json!(self.library()?.authority().keyring).to_string())
    }
    /// Select a controller for convenience authority actions.
    pub fn select_controller(&mut self, id: &str) -> Result<(), JsValue> {
        self.library_mut()?.select_controller(id).map_err(js_error)
    }
    /// All current slots with ordered enc points and PRF salts (byte arrays in this host JSON).
    pub fn begin_unlock_slots(&self) -> Result<String, JsValue> {
        let library = self.library()?;
        let options = library
            .authority()
            .keyring
            .slots
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                Ok(json!({"index":index,"label":slot.label(),"inputs":slot_inputs(library,index)?}))
            })
            .collect::<Result<Vec<_>, JsValue>>()?;
        Ok(json!(options).to_string())
    }
    /// Open a current vault slot. Secrets are ordered objects {kind:ecdh|prf,bytes:number[]}.
    pub fn finish_unlock_slot(&mut self, index: usize, secrets: &str) -> Result<(), JsValue> {
        let value = strict_json::parse(secrets.as_bytes()).map_err(js_error)?;
        let values = value
            .as_array()
            .ok_or_else(|| js_error("Expected secret array"))?;
        let mut bytes = Vec::<Vec<u8>>::new();
        for value in values {
            bytes.push(
                serde_json::from_value(
                    value
                        .get("bytes")
                        .cloned()
                        .ok_or_else(|| js_error("Missing secret bytes"))?,
                )
                .map_err(js_error)?,
            );
        }
        let result = (|| {
            let secrets = values
                .iter()
                .zip(&bytes)
                .map(
                    |(value, bytes)| match value.get("kind").and_then(Value::as_str) {
                        Some("ecdh") => Ok(OpeningSecret::Ecdh(bytes)),
                        Some("prf") => Ok(OpeningSecret::Prf(bytes)),
                        _ => Err(js_error("Unknown secret kind")),
                    },
                )
                .collect::<Result<Vec<_>, _>>()?;
            self.library_mut()?
                .finish_unlock_slot(index, &secrets)
                .map_err(js_error)
        })();
        for bytes in &mut bytes {
            bytes.fill(0);
        }
        result
    }
    /// Prepare action protocol JSON with explicit primary and cosigners.
    pub fn prepare_authority(
        &self,
        action: &str,
        by: &str,
        signers: &str,
        now: &str,
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .prepare_authority(
                parse!(action, Action)?,
                by,
                &parse!(signers, Vec<String>)?,
                now,
            )
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Build a sealed slot for the unlocked vault or a fresh rotation seed (empty means current).
    pub fn build_sealed_slot(
        &self,
        controller_json: &str,
        label: &str,
        new_seed: &[u8],
        entropy: &[u8],
    ) -> Result<String, JsValue> {
        Ok(json!(self
            .library()?
            .build_sealed_slot(
                &controller(controller_json)?,
                label,
                if new_seed.is_empty() {
                    None
                } else {
                    Some(seed(new_seed)?)
                },
                seed(entropy)?
            )
            .map_err(js_error)?)
        .to_string())
    }
    /// Begin a new-credential PRF get ceremony before the authority body is built.
    pub fn begin_prf_slot(&self, descriptor: &str, entropy: &[u8]) -> Result<HostPrf, JsValue> {
        Ok(HostPrf {
            pending: self
                .library()?
                .begin_prf_slot(
                    KeyDescriptor::from_json(descriptor.as_bytes()).map_err(js_error)?,
                    seed(entropy)?,
                )
                .map_err(js_error)?,
        })
    }
    /// Verify get, build a slot and reopen with the same output. Empty PRF explicitly fails.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_prf_slot(
        &mut self,
        action: HostPrf,
        signature: &[u8],
        authenticator_data: &[u8],
        client_data: &[u8],
        output: &[u8],
        label: &str,
        new_seed: &[u8],
        entropy: &[u8],
    ) -> Result<String, JsValue> {
        let result = SignatureResult {
            signature: signature.to_vec(),
            assertion: Some(colophon_core::keys::Assertion::new(
                authenticator_data.to_vec(),
                client_data.to_vec(),
            )),
        };
        let slot = if new_seed.is_empty() {
            self.library_mut()?.finish_prf_slot(
                action.pending,
                result,
                output,
                label,
                seed(entropy)?,
            )
        } else {
            self.library_mut()?.finish_prf_slot_for(
                action.pending,
                result,
                output,
                label,
                seed(new_seed)?,
                seed(entropy)?,
            )
        }
        .map_err(js_error)?;
        Ok(json!(slot).to_string())
    }
    /// Add a controller and optional checked slot (JSON null means no slot).
    pub fn begin_add_controller(
        &self,
        controller_json: &str,
        slot: &str,
        signers: &str,
        now: &str,
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_add_controller(
                controller(controller_json)?,
                parse!(slot, Option<Slot>)?,
                &parse!(signers, Vec<String>)?,
                now,
            )
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Prepare recovery only-adds; the core enforces the prior recovery rule.
    pub fn begin_recovery_add(
        &self,
        controller_json: &str,
        slot: &str,
        signers: &str,
        now: &str,
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_recovery_add(
                controller(controller_json)?,
                parse!(slot, Option<Slot>)?,
                &parse!(signers, Vec<String>)?,
                now,
            )
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Add a passkey with a checked PRF slot.
    pub fn begin_add_passkey(
        &self,
        controller_json: &str,
        slot: &str,
        signers: &str,
        now: &str,
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_add_passkey(
                controller(controller_json)?,
                parse!(slot)?,
                &parse!(signers, Vec<String>)?,
                now,
            )
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Remove a controller with vault rotation and replacement slots.
    pub fn begin_remove_controller(
        &self,
        id: &str,
        new_seed: &[u8],
        slots: &str,
        signers: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_remove_controller(
                id,
                seed(new_seed)?,
                parse!(slots)?,
                &parse!(signers, Vec<String>)?,
                now,
                seed(entropy)?,
            )
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Replace a keyring with optional vault rotation (empty seed means current vault).
    pub fn begin_keyring(
        &self,
        keyring: &str,
        new_seed: &[u8],
        signers: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_keyring(
                parse!(keyring, Keyring)?,
                if new_seed.is_empty() {
                    None
                } else {
                    Some(seed(new_seed)?)
                },
                &parse!(signers, Vec<String>)?,
                now,
                seed(entropy)?,
            )
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Grant scoped, expiring import permission with explicit control signers.
    pub fn begin_import_grant(
        &self,
        request: &[u8],
        grant: &str,
        signers: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_import_grant(
                request.to_vec(),
                parse!(grant)?,
                &parse!(signers, Vec<String>)?,
                now,
                seed(entropy)?,
            )
            .map(HostAction::pending)
            .map_err(js_error)
    }
    /// Introduce epochs using the selected controller.
    pub fn begin_rekey(
        &self,
        namespaces: &str,
        now: &str,
        entropy: &[u8],
    ) -> Result<HostAction, JsValue> {
        self.library()?
            .begin_rekey(&parse!(namespaces, Vec<String>)?, now, seed(entropy)?)
            .map(HostAction::outcome)
            .map_err(js_error)
    }
    /// Verify registration RP binding and extract descriptor JSON without attestation trust.
    pub fn parse_registration(attestation_object: &[u8], rp: &str) -> Result<String, JsValue> {
        Ok(json!(
            colophon_core::keys::registration::parse(attestation_object, rp).map_err(js_error)?
        )
        .to_string())
    }
}

/// Ordered new combined-route parts; each PRF part carries a single-use get ceremony.
#[wasm_bindgen]
pub struct HostCombinedParts {
    parts: Vec<CombinedInput>,
}
enum CombinedInput {
    Sealed(Controller),
    Prf(Controller, Box<PrfPreparation>, SignatureResult, Vec<u8>),
}
#[wasm_bindgen]
impl HostCombinedParts {
    /// Start a new combined route.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }
    /// Append a raw sealed part.
    pub fn sealed(&mut self, controller_json: &str) -> Result<(), JsValue> {
        self.parts
            .push(CombinedInput::Sealed(controller(controller_json)?));
        Ok(())
    }
    /// Append an assertion-bound PRF part. Verification happens before the route is built.
    pub fn prf(
        &mut self,
        controller_json: &str,
        action: HostPrf,
        signature: &[u8],
        authenticator_data: &[u8],
        client_data: &[u8],
        output: &[u8],
    ) -> Result<(), JsValue> {
        self.parts.push(CombinedInput::Prf(
            controller(controller_json)?,
            Box::new(action.pending),
            SignatureResult {
                signature: signature.to_vec(),
                assertion: Some(colophon_core::keys::Assertion::new(
                    authenticator_data.to_vec(),
                    client_data.to_vec(),
                )),
            },
            output.to_vec(),
        ));
        Ok(())
    }
}
impl Default for HostCombinedParts {
    fn default() -> Self {
        Self::new()
    }
}
/// A combined route awaiting the mandatory all-parts reopen check.
#[wasm_bindgen]
pub struct HostCombinedSlot {
    pending: colophon_core::library::PendingSlot,
}
#[wasm_bindgen]
impl HostCombinedSlot {
    /// Ordered ECDH enc points and PRF salts, with host byte arrays.
    pub fn inputs(&self) -> Result<String, JsValue> {
        let inputs = self
            .pending
            .begin_open()
            .map_err(js_error)?
            .into_iter()
            .map(|input| match input {
                OpeningInput::Ecdh { controller, enc } => {
                    json!({"kind":"ecdh","controller":controller,"enc":enc})
                }
                OpeningInput::Prf { controller, salt } => {
                    json!({"kind":"prf","controller":controller,"salt":salt})
                }
            })
            .collect::<Vec<_>>();
        Ok(json!(inputs).to_string())
    }
}
#[wasm_bindgen]
impl WasmLibrary {
    /// Verify every new PRF part and build fresh independent sealed part secrets.
    pub fn begin_combined_slot(
        &self,
        parts: HostCombinedParts,
        label: &str,
        new_seed: &[u8],
        entropy: &[u8],
    ) -> Result<HostCombinedSlot, JsValue> {
        let library = self.library()?;
        let parts = parts
            .parts
            .into_iter()
            .map(|part| match part {
                CombinedInput::Sealed(controller) => {
                    Ok(colophon_core::library::CombinedPart::Sealed { controller })
                }
                CombinedInput::Prf(controller, pending, result, mut output) => {
                    let verified = library.finish_prf_part(*pending, result, &output);
                    output.fill(0);
                    Ok(colophon_core::library::CombinedPart::Prf {
                        controller,
                        verified: verified.map_err(js_error)?,
                    })
                }
            })
            .collect::<Result<Vec<_>, JsValue>>()?;
        Ok(HostCombinedSlot {
            pending: library
                .begin_combined_slot(
                    parts,
                    label,
                    if new_seed.is_empty() {
                        None
                    } else {
                        Some(seed(new_seed)?)
                    },
                    seed(entropy)?,
                )
                .map_err(js_error)?,
        })
    }
    /// Reopen the built route with identical PRF outputs and host ECDH secrets before publication.
    pub fn finish_combined_slot(
        &mut self,
        action: HostCombinedSlot,
        secrets: &str,
    ) -> Result<String, JsValue> {
        let values: Vec<Value> = parse!(secrets, Vec<Value>)?;
        let mut bytes = values
            .iter()
            .map(|v| serde_json::from_value::<Vec<u8>>(v["bytes"].clone()).map_err(js_error))
            .collect::<Result<Vec<_>, _>>()?;
        let result = (|| {
            let secrets = values
                .iter()
                .zip(&bytes)
                .map(|(value, bytes)| match value["kind"].as_str() {
                    Some("ecdh") => Ok(OpeningSecret::Ecdh(bytes)),
                    Some("prf") => Ok(OpeningSecret::Prf(bytes)),
                    _ => Err(js_error("Unknown secret kind")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!(self
                .library_mut()?
                .finish_combined_slot(action.pending, &secrets)
                .map_err(js_error)?)
            .to_string())
        })();
        for bytes in &mut bytes {
            bytes.fill(0);
        }
        result
    }
    /// Candidate controllers, including forms, for choosing a complete signer quorum.
    pub fn eligible_signers(&self, action: &str) -> Result<String, JsValue> {
        use colophon_core::authority::Role;
        let action: Action = parse!(action, Action)?;
        let candidates = self
            .library()?
            .authority()
            .keyring
            .controllers
            .iter()
            .filter(|c| match &action {
                Action::Keyring { .. } => {
                    c.roles.contains(&Role::Control) || c.roles.contains(&Role::Recover)
                }
                Action::Layout { .. } | Action::Genesis { .. } => c.roles.contains(&Role::Control),
                Action::Grant { grant, .. } if grant.import == Some(true) => {
                    c.roles.contains(&Role::Control)
                }
                Action::Rekey { .. } => {
                    c.roles.contains(&Role::Control) || c.roles.contains(&Role::Approve)
                }
                _ => c.roles.contains(&Role::Approve),
            })
            .collect::<Vec<_>>();
        Ok(json!(candidates).to_string())
    }
    /// Derive the public vault identity for a fresh host seed.
    pub fn vault_public(seed_bytes: &[u8]) -> Result<String, JsValue> {
        Ok(json!(colophon_core::vault::derive(seed(seed_bytes)?)
            .map_err(js_error)?
            .public())
        .to_string())
    }
    /// CTAP hmac-secret transformation; use the UV-associated secret at the host.
    pub fn webauthn_prf_input(salt: &[u8]) -> Result<Vec<u8>, JsValue> {
        if salt.len() != 32 {
            return Err(js_error("Expected a 32-byte PRF salt"));
        }
        Ok(colophon_core::slots::webauthn_prf_input(salt).to_vec())
    }
}
