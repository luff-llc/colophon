//! Vault slots under Colophon 0.5 (§7.2): the value type, structural validation, opening,
//! building, and rotation analysis (§8.3, §8.4).
//!
//! **No secret crosses this module.** Every secret it handles (the seed, a raw ECDH result, a
//! PRF output, a part secret, a box key) is an opaque type of [`super::vault`] with private
//! fields; this file never reads their bytes. Hosts hand secrets in as [`EcdhOutput`] and
//! [`PrfOutput`] (from the host's bytes) and get back only a [`VaultSeed`] handle, a [`Slot`]
//! (ciphertext) or a [`SlotBuild`] request. The slot labels `colophon/vault-slot/4` and
//! `colophon/vault-part/4` are kept on purpose (§7.1).
//!
//! The shape follows the 0.4 library: a *begin* that returns exactly what the host must do
//! (an ECDH against a point, a PRF evaluation of a salt, an assertion over a core challenge),
//! and a *finish* that takes the host's results and returns the opened vault handle or the new
//! slot.
use super::descriptor::{general_origin_allowed, Controller, KeyForm, Role};
use super::encoding::{bounds, encode_base64url, is_lower_hex, strict_parse};
use super::history::keyring::Keyring;
use super::history::State;
use super::signature::parse_der;
pub use super::vault::SealedBox;
use super::vault::{
    b64, bad_signature, locked, malformed, require, EcdhOutput, PartSecret, PrfOutput,
    SoftwareIdentity, VResult, VaultPublic, VaultSeed,
};
use crate::crypto::Entropy;
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The slot's `info` and AAD `I` (§7.2), with no trailing newline.
pub fn slot_info(vault_id: &str, kind: &str, controllers: &[String]) -> Vec<u8> {
    format!(
        "colophon/vault-slot/4\n{vault_id}\n{kind}\n{}",
        controllers.join(",")
    )
    .into_bytes()
}

/// A combined part's `info` `Ii` (§7.2): the zero-based index, the part kind and the
/// controller it belongs to.
pub fn part_info(vault_id: &str, index: usize, kind: &str, controller: &str) -> Vec<u8> {
    format!("colophon/vault-part/4\n{vault_id}\n{index}\n{kind}\n{controller}").into_bytes()
}

/// A combined-slot part: its position selects the controller at the same index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Part {
    /// An independent random secret sealed to a `raw` controller's agreement key.
    Sealed {
        /// The HPKE ciphertext of the 32-byte part secret.
        sealed: SealedBox,
    },
    /// A secret derived from the PRF output of a `webauthn` controller.
    Prf {
        /// The exact 32-byte `prf.eval.first` input.
        #[serde(with = "b64")]
        salt: Vec<u8>,
    },
}
impl Part {
    /// The protocol spelling of the part kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sealed { .. } => "sealed",
            Self::Prf { .. } => "prf",
        }
    }
}

/// A vault slot (§7.2) with exactly the fields of its kind. This is the serializable value the
/// authority builders embed in a keyring, a `vault` entry or a transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Slot {
    /// The seed sealed to one `raw` controller's agreement key.
    Sealed {
        /// Exactly one controller ID.
        controllers: Vec<String>,
        /// Display label, 1–200 bytes.
        label: String,
        /// The HPKE ciphertext of the seed.
        sealed: SealedBox,
    },
    /// The seed under one `webauthn` controller's PRF output.
    Prf {
        /// Exactly one controller ID.
        controllers: Vec<String>,
        /// Display label, 1–200 bytes.
        label: String,
        /// The exact 32-byte `prf.eval.first` input.
        #[serde(with = "b64")]
        salt: Vec<u8>,
        /// `nonce(12) ‖ ciphertext(32) ‖ tag(16)`.
        #[serde(rename = "box", with = "b64")]
        box_bytes: Vec<u8>,
    },
    /// The seed under the concatenated secrets of two or more parts.
    Combined {
        /// At least two distinct controller IDs, in part order.
        controllers: Vec<String>,
        /// Display label, 1–200 bytes.
        label: String,
        /// One part per controller, in the same order.
        parts: Vec<Part>,
        /// `nonce(12) ‖ ciphertext(32) ‖ tag(16)`.
        #[serde(rename = "box", with = "b64")]
        box_bytes: Vec<u8>,
    },
}

impl Slot {
    /// The protocol spelling of the kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sealed { .. } => "sealed",
            Self::Prf { .. } => "prf",
            Self::Combined { .. } => "combined",
        }
    }
    /// The controller IDs, in order (a combined slot's order is its part order).
    pub fn controllers(&self) -> &[String] {
        match self {
            Self::Sealed { controllers, .. }
            | Self::Prf { controllers, .. }
            | Self::Combined { controllers, .. } => controllers,
        }
    }
    /// The display label.
    pub fn label(&self) -> &str {
        match self {
            Self::Sealed { label, .. } | Self::Prf { label, .. } | Self::Combined { label, .. } => {
                label
            }
        }
    }
    /// The slot as a JSON value, ready to embed in a keyring.
    pub fn to_value(&self) -> VResult<Value> {
        serde_json::to_value(self).map_err(|e| malformed(format!("slot: {e}")))
    }
    /// Parse a slot from a JSON value: closed field sets, canonical base64, then
    /// [`Slot::validate_shape`]. Every failure is `malformed`.
    pub fn from_value(value: &Value) -> VResult<Self> {
        let slot: Self =
            serde_json::from_value(value.clone()).map_err(|e| malformed(format!("slot: {e}")))?;
        slot.validate_shape()?;
        Ok(slot)
    }
    /// The slot's identity for "every existing slot stays": its canonical JSON without `label`
    /// (§8.3).
    pub fn identity(&self) -> VResult<Vec<u8>> {
        Ok(Keyring::slot_key(&self.to_value()?))
    }

    /// Sizes, labels, counts, distinct IDs and part shapes, with no controller lookup.
    pub fn validate_shape(&self) -> VResult<()> {
        require(
            (1..=200).contains(&self.label().len()),
            "slot label must be 1–200 bytes",
        )?;
        let ids = self.controllers();
        require(
            ids.iter().all(|id| is_lower_hex(id, 32)),
            "slot controller is not a key ID",
        )?;
        require(
            ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
            "slot names a controller twice",
        )?;
        match self {
            Self::Sealed { sealed, .. } => {
                require(ids.len() == 1, "a sealed slot names one controller")?;
                sealed.validate_secret_box()
            }
            Self::Prf {
                salt, box_bytes, ..
            } => {
                require(ids.len() == 1, "a prf slot names one controller")?;
                require(salt.len() == 32, "prf salt is not 32 bytes")?;
                require(box_bytes.len() == 60, "prf box is not 60 bytes")
            }
            Self::Combined {
                parts, box_bytes, ..
            } => {
                require(
                    ids.len() >= 2,
                    "a combined slot names at least two controllers",
                )?;
                require(
                    parts.len() == ids.len(),
                    "combined parts and controllers differ",
                )?;
                require(box_bytes.len() == 60, "combined box is not 60 bytes")?;
                for part in parts {
                    match part {
                        Part::Sealed { sealed } => sealed.validate_secret_box()?,
                        Part::Prf { salt } => {
                            require(salt.len() == 32, "part salt is not 32 bytes")?
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// The structural validation of §7.2 against the keyring's current controllers: every
    /// named ID is a controller and none is `sign`; a `sealed` slot or part names a `raw`
    /// controller with `agreement`; a `prf` slot or part names a `webauthn` controller; plus
    /// [`Slot::validate_shape`]. Every failure is `malformed`. The authority builders call
    /// this on every slot they embed.
    pub fn validate(&self, controllers: &BTreeMap<String, Controller>) -> VResult<()> {
        self.validate_shape()?;
        for (index, id) in self.controllers().iter().enumerate() {
            let c = controllers
                .get(id)
                .ok_or_else(|| malformed("slot names a key that is not a controller"))?;
            require(!c.has(&Role::Sign), "a slot names a sign controller")?;
            let kind = match self {
                Self::Combined { parts, .. } => parts[index].kind(),
                other => other.kind(),
            };
            match (kind, c.key().form()) {
                ("sealed", KeyForm::Raw { agreement: Some(_) }) | ("prf", KeyForm::WebAuthn(_)) => {
                }
                _ => {
                    return Err(malformed(
                        "a slot or part does not fit its controller's key form",
                    ))
                }
            }
        }
        Ok(())
    }

    /// Begin opening: the exact host work, in controller order: an ECDH against each sealed
    /// point, a PRF evaluation of each salt.
    pub fn begin_open(
        &self,
        controllers: &BTreeMap<String, Controller>,
    ) -> VResult<Vec<OpeningInput>> {
        self.validate(controllers)?;
        Ok(match self {
            Self::Sealed {
                controllers: ids,
                sealed,
                ..
            } => vec![OpeningInput::Ecdh {
                controller: ids[0].clone(),
                enc: sealed.enc.clone(),
            }],
            Self::Prf {
                controllers: ids,
                salt,
                ..
            } => vec![OpeningInput::Prf {
                controller: ids[0].clone(),
                salt: salt.clone(),
            }],
            Self::Combined {
                controllers: ids,
                parts,
                ..
            } => parts
                .iter()
                .zip(ids)
                .map(|(part, id)| match part {
                    Part::Sealed { sealed } => OpeningInput::Ecdh {
                        controller: id.clone(),
                        enc: sealed.enc.clone(),
                    },
                    Part::Prf { salt } => OpeningInput::Prf {
                        controller: id.clone(),
                        salt: salt.clone(),
                    },
                })
                .collect(),
        })
    }

    /// Finish opening with the host's results in the same order, then check the plaintext
    /// against `vault` (§7.1). Wrong, missing or mismatched secrets are
    /// `refused:vaultLocked`; a malformed slot or controller set is `malformed`. A failure
    /// leaves the caller's session seed unchanged: replace it only on `Ok`.
    pub fn finish_open(
        &self,
        vault: &VaultPublic,
        controllers: &BTreeMap<String, Controller>,
        secrets: &[OpeningSecret],
    ) -> VResult<VaultSeed> {
        self.validate(controllers)?;
        vault.validate()?;
        if secrets.len() != self.controllers().len() {
            return Err(locked());
        }
        let vault_id = vault.id();
        let info = slot_info(&vault_id, self.kind(), self.controllers());
        match self {
            Self::Sealed {
                controllers: ids,
                sealed,
                ..
            } => {
                let agreement = agreement_of(controllers, &ids[0])?;
                let OpeningSecret::Ecdh(dh) = &secrets[0] else {
                    return Err(locked());
                };
                VaultSeed::open_sealed(sealed, agreement, dh, &info, vault)
            }
            Self::Prf {
                salt, box_bytes, ..
            } => {
                let OpeningSecret::Prf(p) = &secrets[0] else {
                    return Err(locked());
                };
                p.derive(salt, &info)?
                    .into_box_key()
                    .open_seed(box_bytes, &info, vault)
            }
            Self::Combined {
                controllers: ids,
                parts,
                box_bytes,
                ..
            } => {
                let mut secrets_of_parts = Vec::with_capacity(parts.len());
                for (index, part) in parts.iter().enumerate() {
                    let pinfo = part_info(&vault_id, index, part.kind(), &ids[index]);
                    secrets_of_parts.push(match (part, &secrets[index]) {
                        (Part::Sealed { sealed }, OpeningSecret::Ecdh(dh)) => {
                            let agreement = agreement_of(controllers, &ids[index])?;
                            PartSecret::open_sealed(sealed, agreement, dh, &pinfo)?
                        }
                        (Part::Prf { salt }, OpeningSecret::Prf(p)) => p.derive(salt, &pinfo)?,
                        _ => return Err(locked()),
                    });
                }
                PartSecret::combine(&secrets_of_parts, &info)?.open_seed(box_bytes, &info, vault)
            }
        }
    }
}

fn agreement_of<'a>(controllers: &'a BTreeMap<String, Controller>, id: &str) -> VResult<&'a [u8]> {
    controllers
        .get(id)
        .and_then(|c| c.key().agreement())
        .ok_or_else(|| malformed("sealed route needs a raw controller with agreement"))
}

/// Exact host work for one route of a slot, returned before any secret is supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpeningInput {
    /// Perform ECDH between the controller's agreement key and this point.
    Ecdh {
        /// The controller whose agreement key is needed.
        controller: String,
        /// The 65-byte HPKE ephemeral point.
        enc: Vec<u8>,
    },
    /// Evaluate the WebAuthn PRF extension for the controller's credential.
    Prf {
        /// The controller whose credential is needed.
        controller: String,
        /// The exact `prf.eval.first` input (a CTAP `hmac-secret` host applies
        /// [`webauthn_prf_input`]).
        salt: Vec<u8>,
    },
}

/// The host's raw result for one route. Opaque: see [`EcdhOutput`] and [`PrfOutput`].
#[derive(Debug)]
pub enum OpeningSecret {
    /// A raw P-256 ECDH x-coordinate.
    Ecdh(EcdhOutput),
    /// A WebAuthn PRF result.
    Prf(PrfOutput),
}

/// Answer an ECDH route with a software identity the core holds (a recovery kit or a device
/// software key): the raw ECDH result stays inside and goes straight into an opaque value. A
/// PRF route, or a controller that is not this identity, is `refused:vaultLocked`.
pub fn answer_with_identity(
    identity: &SoftwareIdentity,
    input: &OpeningInput,
) -> VResult<OpeningSecret> {
    match input {
        OpeningInput::Ecdh { controller, enc } if *controller == identity.id() => {
            identity.agree(enc).map(OpeningSecret::Ecdh)
        }
        _ => Err(locked()),
    }
}

/// The input transformation of a CTAP `hmac-secret` host: `SHA-256("WebAuthn PRF" ‖ 0x00 ‖
/// salt)` (§7.2). A WebAuthn host passes the salt unchanged to `prf.eval.first`.
pub fn webauthn_prf_input(salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF\0");
    h.update(salt);
    h.finalize().into()
}

// ---------------------------------------------------------------------------------------------
// Building.

/// What slot a host wants built: the controllers (one, or two or more for a `combined` slot)
/// and the label. The kind follows from the controllers: one `raw` controller is a `sealed`
/// slot, one `webauthn` controller a `prf` slot, two or more a `combined` slot whose parts
/// follow each controller's form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotPlan {
    /// Controller IDs, in part order for a combined slot.
    pub controllers: Vec<String>,
    /// Display label, 1–200 bytes.
    pub label: String,
}

/// The assertion the host must make for one new PRF route (§7.2): restricted to this
/// credential, evaluating this salt, over this fresh core challenge. Never a body digest, and
/// never registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfRequest {
    /// The controller whose credential must be used.
    pub controller: String,
    /// The relying-party ID.
    pub rp: String,
    /// The credential lookup hint (`allowCredentials`).
    pub credential: Vec<u8>,
    /// The exact `prf.eval.first` input.
    pub salt: [u8; 32],
    /// The exact 32-byte WebAuthn challenge.
    pub challenge: [u8; 32],
}

/// A host-supplied salt and challenge for one new PRF route ([`SlotBuild::begin_with`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrfInput {
    /// The exact `prf.eval.first` input: fresh random bytes.
    pub salt: [u8; 32],
    /// The exact WebAuthn challenge: fresh random bytes, never a body digest.
    pub challenge: [u8; 32],
}

/// The assertion bytes of a new PRF route.
#[derive(Clone, Debug)]
pub struct PrfAssertion {
    /// Exact `authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// Exact `clientData`.
    pub client_data: Vec<u8>,
    /// The DER ECDSA signature.
    pub signature: Vec<u8>,
}

/// The host's result for one [`PrfRequest`].
#[derive(Debug)]
pub struct PrfResult {
    /// The assertion over the core challenge.
    pub assertion: PrfAssertion,
    /// The `results.first` of that assertion.
    pub output: PrfOutput,
}

/// A slot being built: [`SlotBuild::begin`] returns the PRF requests the host must satisfy
/// (none for a `sealed` slot), and [`SlotBuild::finish`] takes the assertions and outputs,
/// builds the slot, opens it again with the same outputs and checks the vault before
/// returning it (§7.2). Nothing is returned on failure.
pub struct SlotBuild {
    vault: VaultPublic,
    controllers: BTreeMap<String, Controller>,
    needs_new_seed: bool,
    ids: Vec<String>,
    label: String,
    requests: Vec<PrfRequest>,
    entropy_seed: [u8; 32],
    draws: u64,
}
impl Drop for SlotBuild {
    fn drop(&mut self) {
        // Best effort (see the header of `vault.rs`).
        self.entropy_seed = [0; 32];
        std::hint::black_box(&self.entropy_seed);
    }
}

/// Where a built slot may seal the seed to: the controllers it may name and the vault it is
/// for, together with the kind of seed allowed. A seed that already protects an account is
/// only sealed to controllers taken from the **verifier's state** ([`SlotTarget::verified`]),
/// never to a list the caller made. The other constructors take a **new** seed, made from host
/// entropy in this session ([`VaultSeed::is_new`]), whose targets are the genesis being
/// prepared or the controllers of the verified state under a new vault.
#[derive(Clone, Debug)]
pub struct SlotTarget {
    vault: VaultPublic,
    controllers: BTreeMap<String, Controller>,
    needs_new_seed: bool,
}
impl SlotTarget {
    /// A slot of the account's current vault for a controller of its verified keyring
    /// (`v05::history::State`, from `verify_history`). Any seed that opens that vault may be
    /// sealed to it, opened or new.
    pub fn verified(state: &State) -> Self {
        Self {
            vault: VaultPublic::from_pair(&state.keyring().vault),
            controllers: state.keyring().controllers.clone(),
            needs_new_seed: false,
        }
    }
    /// The slots of a genesis being prepared: no verified state exists yet, so the controllers
    /// are those of the genesis. Only the **new** seed of that genesis can be sealed this way;
    /// [`SlotBuild::finish`] refuses an opened seed.
    pub fn genesis(
        new_seed: &VaultSeed,
        controllers: &BTreeMap<String, Controller>,
    ) -> VResult<Self> {
        require(new_seed.is_new(), "genesis slots need the new seed")?;
        Ok(Self {
            vault: new_seed.public()?,
            controllers: controllers.clone(),
            needs_new_seed: true,
        })
    }
    /// The slots of a rotation (a `vault` entry, or a vault change in a transition): the
    /// controllers of the verified state under the **new** seed's vault. Only that new seed can
    /// be sealed this way.
    pub fn rotation(state: &State, new_seed: &VaultSeed) -> VResult<Self> {
        require(new_seed.is_new(), "a rotation's slots need the new seed")?;
        Ok(Self {
            vault: new_seed.public()?,
            controllers: state.keyring().controllers.clone(),
            needs_new_seed: true,
        })
    }
    /// The current vault's slot for a controller that a transition or entry now being
    /// prepared adds (§17.3: the new device builds its slot before the controller is in the
    /// verified keyring). The account layer builds `added` from that body; hosts cannot call
    /// this.
    #[allow(dead_code)] // constructed by the account layer (E1, E5)
    pub(crate) fn with_additions(state: &State, added: &[Controller]) -> Self {
        let mut controllers = state.keyring().controllers.clone();
        for c in added {
            controllers.insert(c.id(), c.clone());
        }
        Self {
            vault: VaultPublic::from_pair(&state.keyring().vault),
            controllers,
            needs_new_seed: false,
        }
    }
}
impl std::fmt::Debug for SlotBuild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SlotBuild({:?})", self.ids)
    }
}

impl SlotBuild {
    /// Begin building the slot of `plan` for `vault`. `entropy_seed` is a fresh host-random
    /// 32-byte seed for this one action, expanded by §7.5: it supplies the salt and challenge
    /// of every new PRF route (in controller order), then the ephemeral keys, part secrets and
    /// nonces of [`SlotBuild::finish`].
    ///
    /// `target` says which controllers and vault the slot is for ([`SlotTarget`]).
    pub fn begin(plan: &SlotPlan, target: &SlotTarget, entropy_seed: [u8; 32]) -> VResult<Self> {
        Self::begin_inner(plan, target, entropy_seed, None)
    }

    /// [`SlotBuild::begin`] with the salt and challenge of each new PRF route supplied by the
    /// host, in controller order, instead of drawn from the entropy seed. Each must be fresh
    /// random bytes; the challenge is never a body digest. `entropy_seed` then supplies only
    /// the ephemeral keys, part secrets and nonces of [`SlotBuild::finish`].
    pub fn begin_with(
        plan: &SlotPlan,
        target: &SlotTarget,
        inputs: &[PrfInput],
        entropy_seed: [u8; 32],
    ) -> VResult<Self> {
        Self::begin_inner(plan, target, entropy_seed, Some(inputs))
    }

    fn begin_inner(
        plan: &SlotPlan,
        target: &SlotTarget,
        entropy_seed: [u8; 32],
        inputs: Option<&[PrfInput]>,
    ) -> VResult<Self> {
        let (vault, controllers) = (&target.vault, &target.controllers);
        vault.validate()?;
        require(
            (1..=200).contains(&plan.label.len()),
            "slot label must be 1–200 bytes",
        )?;
        require(!plan.controllers.is_empty(), "a slot names a controller")?;
        require(
            plan.controllers.iter().collect::<BTreeSet<_>>().len() == plan.controllers.len(),
            "slot names a controller twice",
        )?;
        let mut entropy = Entropy::new(entropy_seed);
        let mut draws = 0u64;
        let mut requests: Vec<PrfRequest> = Vec::new();
        for id in &plan.controllers {
            let c = controllers
                .get(id)
                .ok_or_else(|| malformed("slot names a key that is not a controller"))?;
            require(!c.has(&Role::Sign), "a slot names a sign controller")?;
            match c.key().form() {
                KeyForm::Raw { agreement: Some(_) } => {}
                KeyForm::WebAuthn(w) => {
                    let (salt, challenge) = match inputs {
                        Some(list) => {
                            let i = list
                                .get(requests.len())
                                .ok_or_else(|| malformed("a salt and challenge per PRF route"))?;
                            (i.salt, i.challenge)
                        }
                        None => {
                            draws += 2;
                            (
                                entropy
                                    .take::<32>()
                                    .map_err(|e| malformed(format!("entropy: {e}")))?,
                                entropy
                                    .take::<32>()
                                    .map_err(|e| malformed(format!("entropy: {e}")))?,
                            )
                        }
                    };
                    requests.push(PrfRequest {
                        controller: id.clone(),
                        rp: w.rp().to_string(),
                        credential: w.credential().to_vec(),
                        salt,
                        challenge,
                    });
                }
                _ => {
                    return Err(malformed(
                        "a slot needs a raw controller with agreement or a webauthn controller",
                    ))
                }
            }
        }
        if let Some(list) = inputs {
            require(
                list.len() == requests.len(),
                "a salt and challenge per PRF route",
            )?;
        }
        Ok(Self {
            vault: vault.clone(),
            controllers: controllers.clone(),
            needs_new_seed: target.needs_new_seed,
            ids: plan.controllers.clone(),
            label: plan.label.clone(),
            requests,
            entropy_seed,
            draws,
        })
    }

    /// The assertions the host must make, in controller order. Empty for a `sealed` slot.
    pub fn prf_requests(&self) -> &[PrfRequest] {
        &self.requests
    }

    /// Finish: verify each assertion against its controller's key, build the slot for `seed`,
    /// open it again with the same outputs and compare the plaintext with the vault, and
    /// return it. `seed` must be the unlocked seed of this build's vault (`refused:vaultLocked`
    /// otherwise).
    pub fn finish(self, seed: &VaultSeed, results: &[PrfResult]) -> VResult<Slot> {
        if seed.public()? != self.vault {
            return Err(locked());
        }
        require(
            seed.is_new() || !self.needs_new_seed,
            "an opened seed is sealed only to the controllers of the verified keyring",
        )?;
        // Resume the entropy after the draws `begin` made.
        let mut entropy = Entropy::new(self.entropy_seed);
        for _ in 0..self.draws {
            entropy
                .take::<1>()
                .map_err(|e| malformed(format!("entropy: {e}")))?;
        }
        require(
            results.len() == self.requests.len(),
            "one assertion and output per new PRF route",
        )?;
        for (request, result) in self.requests.iter().zip(results) {
            let c = self
                .controllers
                .get(&request.controller)
                .ok_or_else(|| malformed("request names an unknown controller"))?;
            verify_prf_assertion(c, &request.challenge, &result.assertion)?;
        }
        let vault_id = self.vault.id();
        let mut prf_index = 0usize;
        let slot = if self.ids.len() == 1 {
            let id = self.ids[0].clone();
            match self.controllers[&id].key().form() {
                KeyForm::Raw { agreement: Some(a) } => {
                    let info = slot_info(&vault_id, "sealed", &self.ids);
                    Slot::Sealed {
                        sealed: seed.seal_to(a, &info, &mut entropy)?,
                        controllers: self.ids.clone(),
                        label: self.label.clone(),
                    }
                }
                _ => {
                    let info = slot_info(&vault_id, "prf", &self.ids);
                    let req = &self.requests[0];
                    let out = &results[0].output;
                    let key = out.derive(&req.salt, &info)?.into_box_key();
                    let box_bytes = key.seal_seed(seed, &info, &mut entropy)?;
                    // Open it again with the same output and check the vault.
                    out.derive(&req.salt, &info)?.into_box_key().open_seed(
                        &box_bytes,
                        &info,
                        &self.vault,
                    )?;
                    Slot::Prf {
                        controllers: self.ids.clone(),
                        label: self.label.clone(),
                        salt: req.salt.to_vec(),
                        box_bytes,
                    }
                }
            }
        } else {
            let info = slot_info(&vault_id, "combined", &self.ids);
            let mut parts = Vec::new();
            let mut secrets = Vec::new();
            for (index, id) in self.ids.iter().enumerate() {
                match self.controllers[id].key().form() {
                    KeyForm::Raw { agreement: Some(a) } => {
                        let pinfo = part_info(&vault_id, index, "sealed", id);
                        let (secret, sealed) = PartSecret::fresh_sealed(a, &pinfo, &mut entropy)?;
                        secrets.push(secret);
                        parts.push(Part::Sealed { sealed });
                    }
                    _ => {
                        let pinfo = part_info(&vault_id, index, "prf", id);
                        let req = &self.requests[prf_index];
                        secrets.push(results[prf_index].output.derive(&req.salt, &pinfo)?);
                        parts.push(Part::Prf {
                            salt: req.salt.to_vec(),
                        });
                        prf_index += 1;
                    }
                }
            }
            let box_bytes =
                PartSecret::combine(&secrets, &info)?.seal_seed(seed, &info, &mut entropy)?;
            // Open it again from the same part secrets and check the vault.
            PartSecret::combine(&secrets, &info)?.open_seed(&box_bytes, &info, &self.vault)?;
            Slot::Combined {
                controllers: self.ids.clone(),
                label: self.label.clone(),
                parts,
                box_bytes,
            }
        };
        slot.validate(&self.controllers)?;
        Ok(slot)
    }
}

/// Verify the assertion of a new PRF route (§7.2) against the controller's key: `clientData`
/// type `webauthn.get`, `challenge` equal to the unpadded base64url of exactly the core's
/// 32-byte challenge, an origin allowed under the general rule of §4.3, `crossOrigin` absent
/// or false; `authenticatorData` at least 37 bytes with the SHA-256 of the `rp`, UP set, UV
/// set when the controller has `verification`; and an ES256 signature over
/// `authenticatorData ‖ SHA-256(clientData)`.
///
/// Spec question: §7.2 says "restricted to that slot's credential" and "verifies that
/// assertion against the new controller's key" but not which origin rule or whether UV is
/// required beyond the controller's `verification`. This uses the general origin rule and the
/// controller's own `verification` only.
pub fn verify_prf_assertion(
    controller: &Controller,
    challenge: &[u8; 32],
    a: &PrfAssertion,
) -> VResult<()> {
    let w = controller
        .key()
        .webauthn()
        .ok_or_else(|| bad_signature("PRF assertion for a controller that is not webauthn"))?;
    if a.client_data.len() > bounds::CLIENT_DATA {
        return Err(malformed("clientData exceeds 8,192 bytes"));
    }
    let value = strict_parse(&a.client_data).map_err(|_| bad_signature("clientData"))?;
    let map = value
        .as_object()
        .ok_or_else(|| bad_signature("clientData is not an object"))?;
    if map.get("type").and_then(Value::as_str) != Some("webauthn.get") {
        return Err(bad_signature("clientData type"));
    }
    if map.get("challenge").and_then(Value::as_str) != Some(encode_base64url(challenge).as_str()) {
        return Err(bad_signature(
            "clientData challenge is not the core challenge",
        ));
    }
    let Some(Value::String(origin)) = map.get("origin") else {
        return Err(bad_signature("clientData origin"));
    };
    if map
        .get("crossOrigin")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        return Err(bad_signature("crossOrigin"));
    }
    if !general_origin_allowed(origin, w.rp(), w.origins()) {
        return Err(bad_signature("origin not allowed for this credential"));
    }
    let data = &a.authenticator_data;
    if data.len() < 37 || data[..32] != Sha256::digest(w.rp().as_bytes())[..] {
        return Err(bad_signature("rpIdHash"));
    }
    if data[32] & 0x01 == 0 {
        return Err(bad_signature("user presence"));
    }
    if controller.verification() && data[32] & 0x04 == 0 {
        return Err(bad_signature("user verification"));
    }
    let sig = parse_der(&a.signature).map_err(|e| bad_signature(e.to_string()))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let key = VerifyingKey::from_sec1_bytes(controller.key().signing())
        .map_err(|_| bad_signature("signing point"))?;
    let mut message = data.clone();
    message.extend_from_slice(&Sha256::digest(&a.client_data));
    key.verify(&message, &sig)
        .map_err(|_| bad_signature("PRF assertion signature"))
}

// ---------------------------------------------------------------------------------------------
// Keyring-level validation for the authority builders.

/// Validate every slot of a keyring against its controllers (§7.2): the structural function
/// the authority builders call. Returns the parsed slots. `min` and the 256 maximum are §6.2's
/// bounds (1 at genesis, 0 after an activation drops slots).
pub fn validate_slots(
    controllers: &BTreeMap<String, Controller>,
    slots: &[Value],
    min: usize,
) -> VResult<Vec<Slot>> {
    require(
        (min..=256).contains(&slots.len()),
        "slot count out of range",
    )?;
    slots
        .iter()
        .map(|v| {
            let s = Slot::from_value(v)?;
            s.validate(controllers)?;
            Ok(s)
        })
        .collect()
}

/// The slots of a `vault` entry (§8.3, §8.4): valid against the controllers that remain, at
/// least one, and one of them names the signer.
pub fn validate_vault_entry_slots(
    controllers: &BTreeMap<String, Controller>,
    slots: &[Value],
    signer: &str,
) -> VResult<Vec<Slot>> {
    let parsed = validate_slots(controllers, slots, 1)?;
    require(
        parsed
            .iter()
            .any(|s| s.controllers().iter().any(|id| id == signer)),
        "vault: no slot names its signer",
    )?;
    Ok(parsed)
}

/// A self-slot `keyring` entry (§8.4): it adds slots to the current vault that name only its
/// signer, which is a non-`sign` current controller. `existing` are the keyring's slots before
/// and `after` the slots after: every existing slot stays and each new slot names only the
/// signer.
pub fn validate_self_slot(
    controllers: &BTreeMap<String, Controller>,
    existing: &[Value],
    after: &[Value],
    signer: &str,
) -> VResult<Vec<Slot>> {
    let c = controllers
        .get(signer)
        .ok_or_else(|| malformed("self-slot: the signer is not a controller"))?;
    require(
        !c.has(&Role::Sign),
        "self-slot: a sign controller has no slot",
    )?;
    let parsed = validate_slots(controllers, after, 0)?;
    let mut old: Vec<Vec<u8>> = existing.iter().map(Keyring::slot_key).collect();
    let mut added = 0;
    for slot in &parsed {
        let key = slot.identity()?;
        if let Some(i) = old.iter().position(|k| *k == key) {
            old.remove(i);
        } else {
            require(
                slot.controllers() == [signer.to_string()],
                "self-slot: a new slot names a controller other than the signer",
            )?;
            added += 1;
        }
    }
    require(
        old.is_empty(),
        "self-slot: an existing slot was deleted or changed",
    )?;
    require(added > 0, "self-slot: adds no slot")?;
    Ok(parsed)
}

// ---------------------------------------------------------------------------------------------
// Rotation.

/// What a keyring change does to the slots (§8.3), from the keyring before and after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationPlan {
    /// The vault's public identity differs: a rotation.
    pub vault_changed: bool,
    /// The vault is unchanged and an activation dropped slots: the removed key may still know
    /// the seed, and a `vault` entry must follow (§8.3).
    pub retiring: bool,
    /// Controllers some slot named that are removed, demoted (lost a role) or changed their
    /// `agreement`. Every slot naming one of them is dropped at activation.
    pub lost: Vec<String>,
    /// The slots of `before` the activation drops.
    pub dropped: Vec<Slot>,
    /// The slots the new vault needs to be built for (a `vault` entry or a rotation):
    /// every `before` slot whose controllers all remain, which has no slot over the same
    /// controllers in `after`, or all of them while the vault is retiring. A `sealed` plan can
    /// be built at once ([`SlotBuild`] with no PRF requests); `prf` and `combined` plans need
    /// their credentials present.
    pub rebuild: Vec<SlotPlan>,
    /// Remaining non-`sign` controllers that had a slot before and have none in `after`: hosts
    /// MUST warn while any exists (§6.4, §8.3) and get them the seed by §7.4.
    pub without_slot: Vec<String>,
    /// While retiring: controllers of `before` holding `control` or `recover` that had a slot
    /// (so hold the seed) and still hold one of those roles. Any one of them appends the
    /// `vault` entry (§8.4).
    pub vault_signers: Vec<String>,
}

/// Analyze the slot consequences of a change from `before` to `after` (both folded keyrings),
/// and refuse a result that breaks §8.3:
/// - with the vault unchanged, every slot of `before` that names only kept, unchanged
///   controllers stays (multiset by canonical JSON without `label`); one that is deleted or
///   changed is `malformed`;
/// - a slot naming a removed, demoted or re-keyed controller does not survive;
/// - every slot of `after` is valid against `after`'s controllers (§7.2).
///
/// `carried` is the `without_slot` of the previous plan the host kept: controllers that lost
/// their slot in an earlier step and still have none, so that after the `vault` entry (when
/// `before` no longer shows their old slot) they are still reported until they have one
/// (§8.3: the old seed retires only once every remaining controller that had an old slot has a
/// new one). Pass `&[]` for the first step.
///
/// A removed controller that no slot ever named leaves the vault as it is and the plan neither
/// retiring nor rebuilding anything.
pub fn plan_rotation(
    before: &Keyring,
    after: &Keyring,
    carried: &[String],
) -> VResult<RotationPlan> {
    let before_slots = before
        .slots
        .iter()
        .map(Slot::from_value)
        .collect::<VResult<Vec<_>>>()?;
    let after_slots = after
        .slots
        .iter()
        .map(Slot::from_value)
        .collect::<VResult<Vec<_>>>()?;
    for s in &after_slots {
        s.validate(&after.controllers)?;
    }
    let slotted: BTreeSet<&String> = before_slots.iter().flat_map(|s| s.controllers()).collect();
    let mut lost = Vec::new();
    for id in &slotted {
        let old = before
            .controllers
            .get(*id)
            .ok_or_else(|| malformed("a slot names a key that is not a controller"))?;
        let gone = match after.controllers.get(*id) {
            None => true,
            Some(new) => {
                old.roles().iter().any(|r| !new.has(r))
                    || old.key().agreement() != new.key().agreement()
            }
        };
        if gone {
            lost.push((*id).clone());
        }
    }
    let names_lost = |s: &Slot| s.controllers().iter().any(|id| lost.contains(id));
    let (dropped, surviving): (Vec<Slot>, Vec<Slot>) =
        before_slots.iter().cloned().partition(names_lost);
    let vault_changed = before.vault != after.vault;
    if !vault_changed {
        let mut want: Vec<Vec<u8>> = surviving
            .iter()
            .map(Slot::identity)
            .collect::<VResult<_>>()?;
        let dropped_keys: Vec<Vec<u8>> =
            dropped.iter().map(Slot::identity).collect::<VResult<_>>()?;
        for s in &after_slots {
            let key = s.identity()?;
            require(
                !dropped_keys.contains(&key),
                "a slot of a removed or demoted controller was kept (§8.3)",
            )?;
            if let Some(i) = want.iter().position(|k| *k == key) {
                want.remove(i);
            }
        }
        require(
            want.is_empty(),
            "an existing slot was deleted or changed without a vault change (§8.3)",
        )?;
    }
    let retiring = !vault_changed && !dropped.is_empty();
    let mut rebuild = Vec::new();
    if vault_changed || retiring {
        for s in &surviving {
            let covered = vault_changed
                && after_slots
                    .iter()
                    .any(|a| a.controllers() == s.controllers());
            if !covered {
                rebuild.push(SlotPlan {
                    controllers: s.controllers().to_vec(),
                    label: s.label().to_string(),
                });
            }
        }
    }
    let after_named: BTreeSet<&String> = after_slots.iter().flat_map(|s| s.controllers()).collect();
    // Remaining controllers that had a slot (this step, or carried from an earlier one) and
    // have none now: removed ones are gone, but demoted or re-keyed ones remain and need the
    // seed by §7.4 (§8.3, §6.4).
    let mut candidates: BTreeSet<String> = slotted.iter().map(|id| (*id).clone()).collect();
    candidates.extend(carried.iter().cloned());
    let without_slot: Vec<String> = candidates
        .into_iter()
        .filter(|id| {
            after
                .controllers
                .get(id)
                .is_some_and(|c| !c.has(&Role::Sign))
                && !after_named.contains(id)
        })
        .collect();
    // Only a controller named by a single-controller slot opens the seed alone; one that
    // appears only inside a combined slot cannot build a `vault` entry by itself.
    let alone: BTreeSet<&String> = before_slots
        .iter()
        .filter(|s| !matches!(s, Slot::Combined { .. }))
        .flat_map(|s| s.controllers())
        .collect();
    let vault_signers = if retiring {
        alone
            .iter()
            .filter(|id| {
                let holds = |k: &Keyring| {
                    k.controllers
                        .get(**id)
                        .is_some_and(|c| c.has(&Role::Control) || c.has(&Role::Recover))
                };
                holds(before) && holds(after)
            })
            .map(|id| (**id).clone())
            .collect()
    } else {
        Vec::new()
    };
    Ok(RotationPlan {
        vault_changed,
        retiring,
        lost,
        dropped,
        rebuild,
        without_slot,
        vault_signers,
    })
}
