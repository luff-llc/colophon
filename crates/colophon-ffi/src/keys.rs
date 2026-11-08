//! Colophon 0.4 two-phase controller and vault transport.
use super::*;
use colophon_core::{
    authority::{Action, Controller, Keyring},
    keys::{strict_json, KeyDescriptor},
    library::PrfPreparation,
    slots::{OpeningInput, OpeningSecret, Slot},
};

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_json::from_value(strict_json::parse(bytes)?)?)
}
fn inputs(values: Vec<OpeningInput<'_>>) -> Vec<SlotInput> {
    values
        .into_iter()
        .map(|value| match value {
            OpeningInput::Ecdh { controller, enc } => SlotInput::Ecdh {
                controller: controller.into(),
                enc: enc.to_vec(),
            },
            OpeningInput::Prf { controller, salt } => SlotInput::Prf {
                controller: controller.into(),
                salt: salt.to_vec(),
            },
        })
        .collect()
}
fn signature_results(
    values: Vec<SignatureResult>,
) -> Result<Vec<colophon_core::library::SignatureResult>> {
    values.into_iter().map(TryInto::try_into).collect()
}

/// Synchronous controller provider; async hosts use the explicit begin/finish APIs.
/// No callback is invoked while a session mutex is held.
#[uniffi::export(callback_interface)]
pub trait ControllerProvider: Send + Sync {
    /// Complete validated key descriptor in protocol JSON.
    fn descriptor(&self) -> Result<Vec<u8>>;
    /// Report the signing form.
    fn form(&self) -> Result<KeyForm>;
    /// Sign exact raw body bytes.
    fn sign(&self, body: Vec<u8>) -> Result<Vec<u8>>;
    /// Return a raw ECDH secret.
    fn agree(&self, peer: Vec<u8>) -> Result<Vec<u8>>;
    /// Perform get restricted to this descriptor's credential; evaluate salt when supplied.
    fn assert(&self, challenge: String, prf_salt: Option<Vec<u8>>) -> Result<WebauthnResult>;
}

/// Single-use fresh get ceremony, bound to a session revision and a new credential.
#[derive(uniffi::Object)]
pub struct PrfAction {
    pending: Mutex<Option<PrfPreparation>>,
    session: u64,
    revision: u64,
    key: Vec<u8>,
    salt: Vec<u8>,
    challenge: String,
}
#[uniffi::export]
impl PrfAction {
    /// Complete new credential descriptor; restrict get to exactly this credential.
    pub fn descriptor(&self) -> Vec<u8> {
        self.key.clone()
    }
    /// Exact prf.eval.first input.
    pub fn salt(&self) -> Vec<u8> {
        self.salt.clone()
    }
    /// Fresh unpadded base64url get challenge.
    pub fn challenge(&self) -> String {
        self.challenge.clone()
    }
}
#[uniffi::export]
impl HostAction {
    /// Finish exact signatures and assertions with core verification before returning records.
    pub fn finish_authority(&self, results: Vec<SignatureResult>) -> Result<Records> {
        Ok(self
            .pending
            .clone()
            .finish_with_assertions(signature_results(results)?)?
            .into_iter()
            .collect())
    }
    /// Drive a single local controller without holding a session lock.
    pub fn sign_controller_with(
        &self,
        keys: Box<dyn ControllerProvider>,
    ) -> Result<Vec<SignatureResult>> {
        let descriptor = KeyDescriptor::from_json(&keys.descriptor()?)?;
        let form = keys.form()?;
        if descriptor.is_webauthn() != (form == KeyForm::Webauthn) {
            return Err(invalid("Provider form mismatch"));
        }
        self.pending
            .steps
            .iter()
            .map(|step| {
                if step.signer.signing() != descriptor.signing()
                    || step.signer.is_webauthn() != descriptor.is_webauthn()
                {
                    return Err(invalid("Unexpected controller"));
                }
                if let Some(challenge) = &step.challenge {
                    let assertion = keys.assert(challenge.clone(), None)?;
                    Ok(SignatureResult {
                        signature: assertion.signature.clone(),
                        assertion: Some(assertion),
                    })
                } else {
                    Ok(SignatureResult {
                        signature: keys.sign(step.body.clone())?,
                        assertion: None,
                    })
                }
            })
            .collect()
    }
}
impl NativeLibrary {
    fn action(&self, session: &Session, pending: PendingBatch) -> Arc<HostAction> {
        Arc::new(HostAction {
            pending,
            session: Some((self.id, session.revision)),
        })
    }
    fn check_revision(&self, s: &Session, session: u64, revision: u64) -> Result<()> {
        if session != self.id {
            return Err(BindingError::WrongSession);
        }
        if revision != s.revision {
            return Err(BindingError::StaleAction);
        }
        Ok(())
    }
}
#[uniffi::export]
impl NativeLibrary {
    /// Current keyring in exact protocol JSON schema.
    pub fn keyring(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &self.lock()?.library.authority().keyring,
        )?)
    }
    /// Select a controller for convenience grant, revoke, rekey and layout actions.
    pub fn select_controller(&self, id: String) -> Result<()> {
        let mut s = self.lock()?;
        s.library.select_controller(&id)?;
        s.revision += 1;
        Ok(())
    }
    /// All current vault slot options with ordered HPKE encapsulations and PRF salts.
    pub fn begin_unlock_slots(&self) -> Result<Vec<SlotOption>> {
        let s = self.lock()?;
        s.library
            .authority()
            .keyring
            .slots
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                Ok(SlotOption {
                    index: i as u64,
                    label: slot.label().into(),
                    session: self.id,
                    revision: s.revision,
                    inputs: inputs(s.library.begin_unlock_slot(i)?),
                })
            })
            .collect()
    }
    /// Atomically check the vault and open historical epochs; failure leaves the session untouched.
    pub fn finish_unlock_slot(
        &self,
        option: SlotOption,
        mut secrets: Vec<SlotSecret>,
    ) -> Result<ChangeSummary> {
        let result = (|| {
            let mut s = self.lock()?;
            self.check_revision(&s, option.session, option.revision)?;
            let index = usize::try_from(option.index).map_err(|_| invalid("Slot index"))?;
            if inputs(s.library.begin_unlock_slot(index)?) != option.inputs {
                return Err(BindingError::StaleAction);
            }
            let secrets = secrets
                .iter()
                .map(|secret| match secret {
                    SlotSecret::Ecdh { secret } => OpeningSecret::Ecdh(secret),
                    SlotSecret::Prf { output } => OpeningSecret::Prf(output),
                })
                .collect::<Vec<_>>();
            s.library.finish_unlock_slot(index, &secrets)?;
            s.revision += 1;
            Ok(Self::summary(&s, 0, true))
        })();
        for secret in &mut secrets {
            match secret {
                SlotSecret::Ecdh { secret } => secret.fill(0),
                SlotSecret::Prf { output } => output.fill(0),
            }
        }
        result
    }
    /// Prepare an authority/4 action (protocol JSON) with explicit primary and cosigners.
    pub fn prepare_authority(
        &self,
        action: Vec<u8>,
        by: String,
        signers: Vec<String>,
        now: String,
    ) -> Result<Arc<HostAction>> {
        let s = self.lock()?;
        Ok(self.action(
            &s,
            s.library
                .prepare_authority(parse::<Action>(&action)?, &by, &signers, &now)?,
        ))
    }
    /// Verify every signature and assertion before an optimistic atomic commit.
    pub fn finish_authority(
        &self,
        action: Arc<HostAction>,
        results: Vec<SignatureResult>,
    ) -> Result<ChangeSummary> {
        let records = action
            .pending
            .clone()
            .finish_with_assertions(signature_results(results)?)?;
        let mut s = self.lock()?;
        let (session, revision) = action.session.ok_or(BindingError::WrongSession)?;
        self.check_revision(&s, session, revision)?;
        let before = s.library.records().len();
        s.library.merge(records)?;
        let added = (s.library.records().len() - before) as u64;
        if added > 0 {
            s.revision += 1;
        }
        Ok(Self::summary(&s, added, added > 0))
    }
    /// Build an HPKE slot for the current vault or a fresh rotation seed; returns protocol JSON.
    pub fn build_sealed_slot(
        &self,
        controller: Vec<u8>,
        label: String,
        new_seed: Option<Vec<u8>>,
        entropy: Vec<u8>,
    ) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &self.lock()?.library.build_sealed_slot(
                &parse::<Controller>(&controller)?,
                &label,
                new_seed.map(seed).transpose()?,
                seed(entropy)?,
            )?,
        )?)
    }
    /// Begin a fresh get ceremony before building a PRF slot. Registration outputs cannot finish it.
    pub fn begin_prf_slot(&self, descriptor: Vec<u8>, entropy: Vec<u8>) -> Result<Arc<PrfAction>> {
        let s = self.lock()?;
        let pending = s
            .library
            .begin_prf_slot(KeyDescriptor::from_json(&descriptor)?, seed(entropy)?)?;
        Ok(Arc::new(PrfAction {
            key: serde_json::to_vec(&pending.key)?,
            salt: pending.salt.to_vec(),
            challenge: pending.challenge.clone(),
            pending: Mutex::new(Some(pending)),
            session: self.id,
            revision: s.revision,
        }))
    }
    /// Verify the new credential, build its slot and reopen with the same output before publication.
    pub fn finish_prf_slot(
        &self,
        action: Arc<PrfAction>,
        result: WebauthnResult,
        label: String,
        new_seed: Option<Vec<u8>>,
        entropy: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut s = self.lock()?;
        self.check_revision(&s, action.session, action.revision)?;
        let mut output = result
            .prf
            .clone()
            .ok_or_else(|| invalid("WebAuthn PRF unsupported or missing results.first"))?;
        let completed = (|| {
            let pending = action
                .pending
                .lock()
                .map_err(|_| BindingError::Poisoned)?
                .take()
                .ok_or_else(|| invalid("PRF ceremony already consumed"))?;
            let signature = SignatureResult {
                signature: result.signature.clone(),
                assertion: Some(result),
            }
            .try_into()?;
            let entropy = seed(entropy)?;
            let slot = match new_seed {
                Some(value) => s.library.finish_prf_slot_for(
                    pending,
                    signature,
                    &output,
                    &label,
                    seed(value)?,
                    entropy,
                )?,
                None => s
                    .library
                    .finish_prf_slot(pending, signature, &output, &label, entropy)?,
            };
            Ok(serde_json::to_vec(&slot)?)
        })();
        output.fill(0);
        completed
    }
    /// Add a controller with an optional checked slot under control or recovery authorization.
    pub fn begin_add_controller(
        &self,
        controller: Vec<u8>,
        slot: Option<Vec<u8>>,
        signers: Vec<String>,
        now: String,
    ) -> Result<Arc<HostAction>> {
        let s = self.lock()?;
        Ok(self.action(
            &s,
            s.library.begin_add_controller(
                parse(&controller)?,
                slot.map(|b| Slot::parse(&b)).transpose()?,
                &signers,
                &now,
            )?,
        ))
    }
    /// Recovery only-adds action; the core verifies the prior recovery quorum and role limits.
    pub fn begin_recovery_add(
        &self,
        controller: Vec<u8>,
        slot: Option<Vec<u8>>,
        signers: Vec<String>,
        now: String,
    ) -> Result<Arc<HostAction>> {
        let s = self.lock()?;
        Ok(self.action(
            &s,
            s.library.begin_recovery_add(
                parse(&controller)?,
                slot.map(|b| Slot::parse(&b)).transpose()?,
                &signers,
                &now,
            )?,
        ))
    }
    /// Add a passkey using the slot checked by finish_prf_slot.
    pub fn begin_add_passkey(
        &self,
        controller: Vec<u8>,
        slot: Vec<u8>,
        signers: Vec<String>,
        now: String,
    ) -> Result<Arc<HostAction>> {
        let s = self.lock()?;
        Ok(self.action(
            &s,
            s.library.begin_add_passkey(
                parse(&controller)?,
                Slot::parse(&slot)?,
                &signers,
                &now,
            )?,
        ))
    }
    /// Remove a controller, rotate the vault and reseal history to the replacement slots.
    pub fn begin_remove_controller(
        &self,
        id: String,
        new_seed: Vec<u8>,
        slots: Vec<Vec<u8>>,
        signers: Vec<String>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<Arc<HostAction>> {
        let s = self.lock()?;
        Ok(self.action(
            &s,
            s.library.begin_remove_controller(
                &id,
                seed(new_seed)?,
                slots
                    .iter()
                    .map(|b| Slot::parse(b))
                    .collect::<colophon_core::Result<_>>()?,
                &signers,
                &now,
                seed(entropy)?,
            )?,
        ))
    }
    /// Replace the keyring, including threshold, role, slot and vault changes.
    pub fn begin_keyring(
        &self,
        keyring: Vec<u8>,
        new_seed: Option<Vec<u8>>,
        signers: Vec<String>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<Arc<HostAction>> {
        let s = self.lock()?;
        Ok(self.action(
            &s,
            s.library.begin_keyring(
                parse::<Keyring>(&keyring)?,
                new_seed.map(seed).transpose()?,
                &signers,
                &now,
                seed(entropy)?,
            )?,
        ))
    }
    /// Grant explicit scoped, expiring import power under the control rule.
    pub fn begin_import_grant(
        &self,
        request: Vec<u8>,
        grant: Vec<u8>,
        signers: Vec<String>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<Arc<HostAction>> {
        let s = self.lock()?;
        Ok(self.action(
            &s,
            s.library.begin_import_grant(
                request,
                parse(&grant)?,
                &signers,
                &now,
                seed(entropy)?,
            )?,
        ))
    }
    /// Introduce namespace epochs using the selected controller.
    pub fn begin_rekey(
        &self,
        namespaces: Vec<String>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        self.prepared(
            &s,
            s.library.begin_rekey(&namespaces, &now, seed(entropy)?)?,
        )
    }
}

/// Parse registration without trusting or requiring attestation verification; returns descriptor JSON.
#[uniffi::export]
pub fn parse_registration(attestation_object: Vec<u8>, rp: String) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &colophon_core::keys::registration::parse(&attestation_object, &rp)?,
    )?)
}

/// One new combined-slot part; PRF parts require a fresh get ceremony and its result.
#[derive(uniffi::Enum)]
pub enum CombinedSlotPart {
    /// Raw controller encoded as protocol JSON.
    Sealed {
        /// Complete raw controller in protocol JSON.
        controller: Vec<u8>,
    },
    /// WebAuthn controller, fresh core ceremony and exact platform result.
    Prf {
        /// Complete WebAuthn controller in protocol JSON.
        controller: Vec<u8>,
        /// Fresh core get ceremony restricted to this credential.
        action: Arc<PrfAction>,
        /// Exact platform assertion and PRF output.
        result: WebauthnResult,
    },
}
/// A combined slot that cannot be published until all parts reopen the correct vault.
#[derive(uniffi::Object)]
pub struct CombinedSlotAction {
    pending: Mutex<Option<colophon_core::library::PendingSlot>>,
    inputs: Vec<SlotInput>,
    session: u64,
    revision: u64,
}
#[uniffi::export]
impl CombinedSlotAction {
    /// Ordered ECDH inputs and exact PRF salts for the mandatory reopen check.
    pub fn inputs(&self) -> Vec<SlotInput> {
        self.inputs.clone()
    }
}
#[uniffi::export]
impl NativeLibrary {
    /// Verify new PRF parts and construct a combined route with fresh sealed part secrets.
    pub fn begin_combined_slot(
        &self,
        parts: Vec<CombinedSlotPart>,
        label: String,
        new_seed: Option<Vec<u8>>,
        entropy: Vec<u8>,
    ) -> Result<Arc<CombinedSlotAction>> {
        let s = self.lock()?;
        let parts = parts
            .into_iter()
            .map(|part| match part {
                CombinedSlotPart::Sealed { controller } => {
                    Ok(colophon_core::library::CombinedPart::Sealed {
                        controller: parse(&controller)?,
                    })
                }
                CombinedSlotPart::Prf {
                    controller,
                    action,
                    result,
                } => {
                    self.check_revision(&s, action.session, action.revision)?;
                    let pending = action
                        .pending
                        .lock()
                        .map_err(|_| BindingError::Poisoned)?
                        .take()
                        .ok_or_else(|| invalid("PRF ceremony already consumed"))?;
                    let mut output = result.prf.clone().ok_or_else(|| {
                        invalid("WebAuthn PRF unsupported or missing results.first")
                    })?;
                    let signature = SignatureResult {
                        signature: result.signature.clone(),
                        assertion: Some(result),
                    }
                    .try_into()?;
                    let verified = s.library.finish_prf_part(pending, signature, &output);
                    output.fill(0);
                    Ok(colophon_core::library::CombinedPart::Prf {
                        controller: parse(&controller)?,
                        verified: verified?,
                    })
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let pending = s.library.begin_combined_slot(
            parts,
            &label,
            new_seed.map(seed).transpose()?,
            seed(entropy)?,
        )?;
        Ok(Arc::new(CombinedSlotAction {
            inputs: inputs(pending.begin_open()?),
            pending: Mutex::new(Some(pending)),
            session: self.id,
            revision: s.revision,
        }))
    }
    /// Reopen every combined part and check the vault before returning publishable slot JSON.
    pub fn finish_combined_slot(
        &self,
        action: Arc<CombinedSlotAction>,
        mut secrets: Vec<SlotSecret>,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            let mut s = self.lock()?;
            self.check_revision(&s, action.session, action.revision)?;
            let pending = action
                .pending
                .lock()
                .map_err(|_| BindingError::Poisoned)?
                .take()
                .ok_or_else(|| invalid("Combined route already consumed"))?;
            let secrets = secrets
                .iter()
                .map(|secret| match secret {
                    SlotSecret::Ecdh { secret } => OpeningSecret::Ecdh(secret),
                    SlotSecret::Prf { output } => OpeningSecret::Prf(output),
                })
                .collect::<Vec<_>>();
            Ok(serde_json::to_vec(
                &s.library.finish_combined_slot(pending, &secrets)?,
            )?)
        })();
        for secret in &mut secrets {
            match secret {
                SlotSecret::Ecdh { secret } => secret.fill(0),
                SlotSecret::Prf { output } => output.fill(0),
            }
        }
        result
    }
    /// Candidate controllers and forms for a rule, before choosing a complete signer quorum.
    /// `keyring` candidates include control and recovery; the core rejects mixed-role quorums.
    pub fn eligible_signers(&self, action: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        use colophon_core::authority::Role;
        let action: Action = parse(&action)?;
        let s = self.lock()?;
        let eligible = |c: &&Controller| match &action {
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
        };
        s.library
            .authority()
            .keyring
            .controllers
            .iter()
            .filter(eligible)
            .map(|c| Ok(serde_json::to_vec(c)?))
            .collect()
    }
}
/// Derive only the vault public identity for a host-supplied fresh seed.
#[uniffi::export]
pub fn vault_public(seed_bytes: Vec<u8>) -> Result<PublicKeys> {
    let public = colophon_core::vault::derive(seed(seed_bytes)?)?.public();
    Ok(PublicKeys {
        signing: public.signing,
        agreement: public.agreement,
    })
}
/// Transform a salt for hosts calling CTAP hmac-secret directly; use the UV-associated secret.
#[uniffi::export]
pub fn webauthn_prf_input(salt: Vec<u8>) -> Result<Vec<u8>> {
    if salt.len() != 32 {
        return Err(invalid("Expected a 32-byte PRF salt"));
    }
    Ok(colophon_core::slots::webauthn_prf_input(&salt).to_vec())
}
