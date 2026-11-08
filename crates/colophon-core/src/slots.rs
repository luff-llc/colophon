//! Closed slot schemas and raw-byte slot cryptography for Colophon 0.4 (§5.2).
//!
//! Authority replay must validate slots against the current controller descriptors.
//! PRF construction here is the cryptographic stage: the assertion ceremony and
//! verification required by §5.2 must precede it in the core's writer workflow.

use crate::{
    crypto::{self, Entropy, PublicIdentity, SoftwareKeys},
    hpke::SealedKey,
    records::{self, bytes},
    vault, Error, Result,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn malformed() -> Error {
    Error("malformed".into())
}
fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(malformed())
    }
}
fn point(point: &[u8]) -> Result<()> {
    require(point.len() == 65 && point.first() == Some(&4))?;
    p256::PublicKey::from_sec1_bytes(point).map_err(|_| malformed())?;
    Ok(())
}

/// A closed HPKE ciphertext object used in slots and parts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    /// Uncompressed 65-byte ephemeral P-256 point.
    #[serde(with = "bytes")]
    pub enc: Vec<u8>,
    /// The 32-byte plaintext encrypted with a 16-byte authentication tag.
    #[serde(with = "bytes")]
    pub ciphertext: Vec<u8>,
}
impl Sealed {
    fn validate(&self) -> Result<()> {
        point(&self.enc)?;
        require(self.ciphertext.len() == 48)
    }
    fn seal(recipient: &[u8], secret: &[u8], info: &[u8], entropy: &mut Entropy) -> Result<Self> {
        point(recipient)?;
        let sealed = SealedKey::seal(recipient, secret, info, entropy)?;
        Ok(Self {
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
        })
    }
    fn open(&self, recipient: &[u8], dh: &[u8], info: &[u8]) -> Result<Vec<u8>> {
        SealedKey {
            enc: self.enc.clone(),
            ciphertext: self.ciphertext.clone(),
        }
        .finish_open(recipient, dh, info)
        .map_err(|_| vault::locked())
    }
}

/// A combined-slot part; its position selects the corresponding controller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Part {
    /// An independent random secret sealed to a raw controller.
    Sealed {
        /// HPKE ciphertext of the part secret.
        sealed: Sealed,
    },
    /// A secret derived from a WebAuthn PRF output.
    Prf {
        /// Exact 32-byte WebAuthn `prf.eval.first` input.
        #[serde(with = "bytes")]
        salt: Vec<u8>,
    },
}
impl Part {
    /// The protocol spelling of this part kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sealed { .. } => "sealed",
            Self::Prf { .. } => "prf",
        }
    }
}

/// A vault slot, with exactly the fields allowed for its kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Slot {
    /// A seed sealed to one raw controller's agreement key.
    Sealed {
        /// Exactly one current controller ID.
        controllers: Vec<String>,
        /// Display label, 1–200 UTF-8 bytes.
        label: String,
        /// HPKE ciphertext of the vault seed.
        sealed: Sealed,
    },
    /// A seed encrypted under one WebAuthn controller's PRF output.
    Prf {
        /// Exactly one current controller ID.
        controllers: Vec<String>,
        /// Display label, 1–200 UTF-8 bytes.
        label: String,
        /// Exact 32-byte WebAuthn `prf.eval.first` input.
        #[serde(with = "bytes")]
        salt: Vec<u8>,
        /// Nonce, ciphertext and tag, totaling 60 bytes.
        #[serde(rename = "box", with = "bytes")]
        box_bytes: Vec<u8>,
    },
    /// A seed encrypted under all of the ordered part secrets.
    Combined {
        /// At least two distinct current controller IDs, in part order.
        controllers: Vec<String>,
        /// Display label, 1–200 UTF-8 bytes.
        label: String,
        /// One part for each controller, in the same order.
        parts: Vec<Part>,
        /// Nonce, ciphertext and tag, totaling 60 bytes.
        #[serde(rename = "box", with = "bytes")]
        box_bytes: Vec<u8>,
    },
}

/// A borrowed controller descriptor, independent of the W1 key types.
#[derive(Clone, Copy, Debug)]
pub enum ControllerKey<'a> {
    /// Raw controller; an agreement key is required by a sealed route.
    Raw {
        /// Uncompressed P-256 agreement point, when present.
        agreement: Option<&'a [u8]>,
    },
    /// A WebAuthn controller.
    Webauthn,
}

/// A raw host result for one route or combined-slot part.
pub enum OpeningSecret<'a> {
    /// Raw P-256 ECDH x-coordinate, exactly 32 bytes.
    Ecdh(&'a [u8]),
    /// WebAuthn `results.first`, exactly 32 bytes; absence is an explicit failure.
    Prf(&'a [u8]),
}

/// Exact host work for a controller, returned before any secret is supplied.
#[derive(Debug, PartialEq, Eq)]
pub enum OpeningInput<'a> {
    /// Perform ECDH with this encapsulated point.
    Ecdh {
        /// Controller whose agreement key is required.
        controller: &'a str,
        /// Uncompressed HPKE ephemeral point.
        enc: &'a [u8],
    },
    /// Evaluate the WebAuthn PRF extension.
    Prf {
        /// Controller whose credential is required.
        controller: &'a str,
        /// Exact `prf.eval.first` input, without a CTAP transformation.
        salt: &'a [u8],
    },
}

/// Inputs for the cryptographic stage of a new combined slot.
///
/// Each PRF output must already have passed the core's new-route assertion
/// workflow. Registration outputs are not valid inputs to that workflow.
pub enum NewPart<'a> {
    /// Generate and HPKE-seal a fresh independent part secret.
    Sealed {
        /// Controller's raw agreement point.
        agreement: &'a [u8],
    },
    /// Derive a part secret from a verified assertion's PRF output.
    Prf {
        /// Exact 32-byte WebAuthn extension input.
        salt: &'a [u8],
        /// Exact 32-byte WebAuthn extension result.
        output: &'a [u8],
    },
}

/// The exact slot info string `I`, with no trailing newline.
pub fn slot_info(vault_id: &str, kind: &str, controllers: &[String]) -> Vec<u8> {
    format!(
        "colophon/vault-slot/4\n{vault_id}\n{kind}\n{}",
        controllers.join(",")
    )
    .into_bytes()
}

/// The exact zero-based part info string `Ii`, with no trailing newline.
pub fn part_info(vault_id: &str, index: usize, kind: &str, controller: &str) -> Vec<u8> {
    format!("colophon/vault-part/4\n{vault_id}\n{index}\n{kind}\n{controller}").into_bytes()
}

/// WebAuthn's transformation of an extension salt for CTAP `hmac-secret` hosts.
///
/// CTAP hosts must also select the UV-associated secret. WebAuthn hosts pass the
/// original salt to `prf.eval.first` and do not call this function.
pub fn webauthn_prf_input(salt: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"WebAuthn PRF\0");
    hash.update(salt);
    hash.finalize().into()
}

/// Derive a slot or part key from exactly 32 PRF-result bytes and 32 salt bytes.
pub fn prf_key(output: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    require(salt.len() == 32)?;
    if output.len() != 32 {
        return Err(vault::locked());
    }
    hkdf_key(output, salt, info)
}

/// Derive a combined key from at least two ordered 32-byte part secrets.
pub fn combined_key(secrets: &[[u8; 32]], info: &[u8]) -> Result<[u8; 32]> {
    require(secrets.len() >= 2)?;
    let ikm: Vec<u8> = secrets.iter().flatten().copied().collect();
    hkdf_key(&ikm, &[], info)
}
fn hkdf_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut key)
        .map_err(|_| malformed())?;
    Ok(key)
}
fn seal_box(
    seed: &[u8; 32],
    key: &[u8; 32],
    info: &[u8],
    entropy: &mut Entropy,
) -> Result<Vec<u8>> {
    let nonce = entropy.take::<12>()?;
    let mut boxed = nonce.to_vec();
    boxed.extend(crypto::seal(key, &nonce, seed, info)?);
    Ok(boxed)
}
fn open_box(boxed: &[u8], key: &[u8; 32], info: &[u8]) -> Result<Vec<u8>> {
    require(boxed.len() == 60)?;
    crypto::open(key, &boxed[..12], &boxed[12..], info).map_err(|_| vault::locked())
}

impl Slot {
    /// The protocol spelling of this slot kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sealed { .. } => "sealed",
            Self::Prf { .. } => "prf",
            Self::Combined { .. } => "combined",
        }
    }
    /// Ordered controller IDs; combined slots do not sort this list.
    pub fn controllers(&self) -> &[String] {
        match self {
            Self::Sealed { controllers, .. }
            | Self::Prf { controllers, .. }
            | Self::Combined { controllers, .. } => controllers,
        }
    }
    /// Display-only UTF-8 label.
    pub fn label(&self) -> &str {
        match self {
            Self::Sealed { label, .. } | Self::Prf { label, .. } | Self::Combined { label, .. } => {
                label
            }
        }
    }
    /// Canonical protocol JSON, recursively sorted by object member name.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        records::canonical(self)
    }
    /// Parse closed typed JSON, rejecting duplicate and unknown fields at every depth.
    ///
    /// Authority verification must first scan generic JSON for authorized unknown
    /// content (§6.3). This typed stage reports all schema failures as `malformed`.
    pub fn parse(json: &[u8]) -> Result<Self> {
        let slot: Self = serde_json::from_slice(json).map_err(|_| malformed())?;
        slot.validate_shape()?;
        Ok(slot)
    }
    /// Validate sizes, labels, counts, distinct IDs and part shapes, without keys.
    pub fn validate_shape(&self) -> Result<()> {
        require((1..=200).contains(&self.label().len()))?;
        let controllers = self.controllers();
        require(controllers.iter().all(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }))?;
        require(controllers.iter().collect::<BTreeSet<_>>().len() == controllers.len())?;
        match self {
            Self::Sealed { sealed, .. } => {
                require(controllers.len() == 1)?;
                sealed.validate()
            }
            Self::Prf {
                salt, box_bytes, ..
            } => require(controllers.len() == 1 && salt.len() == 32 && box_bytes.len() == 60),
            Self::Combined {
                parts, box_bytes, ..
            } => {
                require(
                    controllers.len() >= 2
                        && parts.len() == controllers.len()
                        && box_bytes.len() == 60,
                )?;
                for part in parts {
                    match part {
                        Part::Sealed { sealed } => sealed.validate()?,
                        Part::Prf { salt } => require(salt.len() == 32)?,
                    }
                }
                Ok(())
            }
        }
    }
    /// Validate during replay against current controller IDs and key descriptors.
    ///
    /// The lookup must contain only current controllers. No private key or W1
    /// descriptor type is required.
    pub fn validate<'a>(
        &self,
        mut lookup: impl FnMut(&str) -> Option<ControllerKey<'a>>,
    ) -> Result<()> {
        self.validate_shape()?;
        for (index, controller) in self.controllers().iter().enumerate() {
            let kind = match self {
                Self::Combined { parts, .. } => parts[index].kind(),
                _ => self.kind(),
            };
            match (kind, lookup(controller)) {
                (
                    "sealed",
                    Some(ControllerKey::Raw {
                        agreement: Some(agreement),
                    }),
                ) => point(agreement)?,
                ("prf", Some(ControllerKey::Webauthn)) => {}
                _ => return Err(malformed()),
            }
        }
        Ok(())
    }
    /// Begin opening: return the exact ECDH peers and PRF salts in controller order.
    pub fn begin_open(&self) -> Result<Vec<OpeningInput<'_>>> {
        self.validate_shape()?;
        Ok(match self {
            Self::Sealed {
                controllers,
                sealed,
                ..
            } => vec![OpeningInput::Ecdh {
                controller: &controllers[0],
                enc: &sealed.enc,
            }],
            Self::Prf {
                controllers, salt, ..
            } => vec![OpeningInput::Prf {
                controller: &controllers[0],
                salt,
            }],
            Self::Combined {
                controllers, parts, ..
            } => parts
                .iter()
                .zip(controllers)
                .map(|(part, controller)| match part {
                    Part::Sealed { sealed } => OpeningInput::Ecdh {
                        controller,
                        enc: &sealed.enc,
                    },
                    Part::Prf { salt } => OpeningInput::Prf { controller, salt },
                })
                .collect(),
        })
    }
    /// Finish with ordered raw host results, then check the seed against both vault keys.
    ///
    /// `derive` is the core's §5.1 derivation (see `vault::check_seed_with`). A failed
    /// open never mutates session state. Wrong/missing host secrets are `vaultLocked`;
    /// malformed slot structure or controller descriptors are `malformed`.
    pub fn finish_open<'a>(
        &self,
        expected: &PublicIdentity,
        lookup: impl FnMut(&str) -> Option<ControllerKey<'a>>,
        secrets: &[OpeningSecret<'_>],
        derive: impl FnOnce([u8; 32]) -> Result<SoftwareKeys>,
    ) -> Result<[u8; 32]> {
        let mut lookup = lookup;
        self.validate(&mut lookup)?;
        if secrets.len() != self.controllers().len() {
            return Err(vault::locked());
        }
        let vault_id = vault::id(expected);
        let info = slot_info(&vault_id, self.kind(), self.controllers());
        let plaintext = match self {
            Self::Sealed {
                controllers,
                sealed,
                ..
            } => open_sealed(sealed, lookup(&controllers[0]), &secrets[0], &info)?,
            Self::Prf {
                salt, box_bytes, ..
            } => open_box(box_bytes, &open_prf(&secrets[0], salt, &info)?, &info)?,
            Self::Combined {
                controllers,
                parts,
                box_bytes,
                ..
            } => {
                let mut part_secrets = Vec::with_capacity(parts.len());
                for (index, part) in parts.iter().enumerate() {
                    let part_info = part_info(&vault_id, index, part.kind(), &controllers[index]);
                    part_secrets.push(match part {
                        Part::Sealed { sealed } => <[u8; 32]>::try_from(open_sealed(
                            sealed,
                            lookup(&controllers[index]),
                            &secrets[index],
                            &part_info,
                        )?)
                        .map_err(|_| vault::locked())?,
                        Part::Prf { salt } => open_prf(&secrets[index], salt, &part_info)?,
                    });
                }
                open_box(box_bytes, &combined_key(&part_secrets, &info)?, &info)?
            }
        };
        vault::check_seed_with(&plaintext, expected, derive)
    }

    /// Seal a seed to a raw controller using caller-owned entropy.
    ///
    /// The writer must supply the checked current vault seed. This cryptographic
    /// builder does not modify a keyring or publish a slot.
    pub fn seal(
        seed: &[u8; 32],
        vault_id: &str,
        controller: &str,
        label: &str,
        agreement: &[u8],
        entropy: &mut Entropy,
    ) -> Result<Self> {
        let controllers = vec![controller.to_owned()];
        let info = slot_info(vault_id, "sealed", &controllers);
        let slot = Self::Sealed {
            sealed: Sealed::seal(agreement, seed, &info, entropy)?,
            controllers,
            label: label.to_owned(),
        };
        slot.validate_shape()?;
        Ok(slot)
    }
    /// Encrypt a seed using an assertion's PRF output and caller-owned entropy.
    ///
    /// This is only the cryptographic stage. Before calling, the core writer must
    /// verify a fresh-challenge `get` assertion restricted to this credential and
    /// evaluating this salt. Registration-time outputs must never reach this call.
    /// After building, the writer must call `finish_open` with the same output and
    /// check the vault before publishing (§5.2).
    pub fn from_prf(
        seed: &[u8; 32],
        vault_id: &str,
        controller: &str,
        label: &str,
        salt: &[u8],
        output: &[u8],
        entropy: &mut Entropy,
    ) -> Result<Self> {
        let controllers = vec![controller.to_owned()];
        let info = slot_info(vault_id, "prf", &controllers);
        let key = prf_key(output, salt, &info)?;
        let box_bytes = seal_box(seed, &key, &info, entropy)?;
        // Authenticate the newly built cryptographic box with the same output.
        require(open_box(&box_bytes, &key, &info)? == seed)?;
        let slot = Self::Prf {
            controllers,
            label: label.to_owned(),
            salt: salt.to_vec(),
            box_bytes,
        };
        slot.validate_shape()?;
        Ok(slot)
    }
    /// Encrypt a seed under all ordered parts, generating each sealed part secret.
    ///
    /// Supply a fresh `Entropy` seed for each action, never recreate it between
    /// parts. The writer must perform §5.2's assertion checks for every PRF input,
    /// then open and check the complete slot before publishing it.
    pub fn combined(
        seed: &[u8; 32],
        vault_id: &str,
        controllers: &[String],
        label: &str,
        inputs: &[NewPart<'_>],
        entropy: &mut Entropy,
    ) -> Result<Self> {
        require(controllers.len() >= 2 && inputs.len() == controllers.len())?;
        let info = slot_info(vault_id, "combined", controllers);
        let mut parts = Vec::with_capacity(inputs.len());
        let mut secrets = Vec::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            match input {
                NewPart::Sealed { agreement } => {
                    let secret = entropy.take::<32>()?;
                    let info = part_info(vault_id, index, "sealed", &controllers[index]);
                    parts.push(Part::Sealed {
                        sealed: Sealed::seal(agreement, &secret, &info, entropy)?,
                    });
                    secrets.push(secret);
                }
                NewPart::Prf { salt, output } => {
                    let info = part_info(vault_id, index, "prf", &controllers[index]);
                    secrets.push(prf_key(output, salt, &info)?);
                    parts.push(Part::Prf {
                        salt: salt.to_vec(),
                    });
                }
            }
        }
        let key = combined_key(&secrets, &info)?;
        let boxed = seal_box(seed, &key, &info, entropy)?;
        require(open_box(&boxed, &key, &info)? == seed)?;
        let slot = Self::Combined {
            controllers: controllers.to_vec(),
            label: label.to_owned(),
            parts,
            box_bytes: boxed,
        };
        slot.validate_shape()?;
        Ok(slot)
    }
}

fn open_prf(secret: &OpeningSecret<'_>, salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    match secret {
        OpeningSecret::Prf(output) => prf_key(output, salt, info),
        _ => Err(vault::locked()),
    }
}
fn open_sealed(
    sealed: &Sealed,
    controller: Option<ControllerKey<'_>>,
    secret: &OpeningSecret<'_>,
    info: &[u8],
) -> Result<Vec<u8>> {
    match (controller, secret) {
        (
            Some(ControllerKey::Raw {
                agreement: Some(agreement),
            }),
            OpeningSecret::Ecdh(dh),
        ) => sealed.open(agreement, dh, info),
        _ => Err(vault::locked()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};

    const A: &str = "11111111111111111111111111111111";
    const B: &str = "22222222222222222222222222222222";
    const C: &str = "33333333333333333333333333333333";
    const V: &str = "0123456789abcdef0123456789abcdef";

    // Fixture-only derivation: §5.1's unresolved salt mapping is not selected here.
    fn fixture(seed: u8) -> PublicIdentity {
        SoftwareKeys::from_seed([seed; 32]).unwrap().public()
    }
    fn raw() -> SoftwareKeys {
        SoftwareKeys::from_seed([91; 32]).unwrap()
    }
    fn lookup<'a>(agreement: &'a [u8]) -> impl FnMut(&str) -> Option<ControllerKey<'a>> {
        move |id| match id {
            A | C => Some(ControllerKey::Raw {
                agreement: Some(agreement),
            }),
            B => Some(ControllerKey::Webauthn),
            _ => None,
        }
    }
    fn sealed_slot(seed: [u8; 32], expected: &PublicIdentity) -> Slot {
        Slot::seal(
            &seed,
            &vault::id(expected),
            A,
            "raw",
            &raw().public().agreement,
            &mut Entropy::new([21; 32]),
        )
        .unwrap()
    }
    fn prf_slot(seed: [u8; 32], expected: &PublicIdentity) -> Slot {
        Slot::from_prf(
            &seed,
            &vault::id(expected),
            B,
            "passkey",
            &[4; 32],
            &[3; 32],
            &mut Entropy::new([22; 32]),
        )
        .unwrap()
    }
    fn combined_slot(count: usize, seed: [u8; 32], expected: &PublicIdentity) -> Slot {
        let agreement = raw().public().agreement;
        let inputs = [
            NewPart::Sealed {
                agreement: &agreement,
            },
            NewPart::Prf {
                salt: &[4; 32],
                output: &[3; 32],
            },
            NewPart::Sealed {
                agreement: &agreement,
            },
        ];
        Slot::combined(
            &seed,
            &vault::id(expected),
            &[A.into(), B.into(), C.into()][..count],
            "combined",
            &inputs[..count],
            &mut Entropy::new([23; 32]),
        )
        .unwrap()
    }
    fn host_secrets(slot: &Slot) -> Vec<Vec<u8>> {
        slot.begin_open()
            .unwrap()
            .iter()
            .map(|input| match input {
                OpeningInput::Ecdh { enc, .. } => raw().agree(enc).unwrap(),
                OpeningInput::Prf { salt, .. } => {
                    assert_eq!(*salt, &[4; 32]);
                    vec![3; 32]
                }
            })
            .collect()
    }
    fn finish(slot: &Slot, expected: &PublicIdentity, secrets: &[Vec<u8>]) -> Result<[u8; 32]> {
        let kinds = slot.begin_open()?;
        let secrets: Vec<_> = kinds
            .iter()
            .zip(secrets)
            .map(|(input, secret)| match input {
                OpeningInput::Ecdh { .. } => OpeningSecret::Ecdh(secret),
                OpeningInput::Prf { .. } => OpeningSecret::Prf(secret),
            })
            .collect();
        slot.finish_open(
            expected,
            lookup(&raw().public().agreement),
            &secrets,
            SoftwareKeys::from_seed,
        )
    }

    #[test]
    fn exact_info_and_kdf_bytes() {
        assert_eq!(
            slot_info(V, "sealed", &[A.into()]),
            format!("colophon/vault-slot/4\n{V}\nsealed\n{A}").as_bytes()
        );
        assert_eq!(
            slot_info(V, "prf", &[B.into()]),
            format!("colophon/vault-slot/4\n{V}\nprf\n{B}").as_bytes()
        );
        assert_eq!(
            slot_info(V, "combined", &[B.into(), A.into(), C.into()]),
            format!("colophon/vault-slot/4\n{V}\ncombined\n{B},{A},{C}").as_bytes()
        );
        assert_eq!(
            part_info(V, 0, "sealed", A),
            format!("colophon/vault-part/4\n{V}\n0\nsealed\n{A}").as_bytes()
        );
        assert_eq!(
            part_info(V, 10, "prf", B),
            format!("colophon/vault-part/4\n{V}\n10\nprf\n{B}").as_bytes()
        );
        let info = slot_info(V, "prf", &[A.into()]);
        assert_eq!(
            records::hex(&prf_key(&[3; 32], &[4; 32], &info).unwrap()),
            "4c858fb5e8cfbc00f8916d3c53a0de9f735f8fd3bfb85e56a08df7213a5cc0e1"
        );
        assert_eq!(
            records::hex(&combined_key(&[[1; 32], [2; 32]], b"combined info").unwrap()),
            "dd801510def48706024c412418ffbf8cba6a9909841270ce42cbd65a6746731f"
        );
        assert_eq!(
            records::hex(&webauthn_prf_input(&[4; 32])),
            "9b6deb75ae008af5bda777176bff64050f1502e4da267f082aefd554252404aa"
        );
        assert_eq!(prf_key(&[3; 31], &[4; 32], &info), Err(vault::locked()));
        assert_eq!(prf_key(&[3; 32], &[4; 31], &info), Err(malformed()));
        assert_eq!(combined_key(&[[1; 32]], &info), Err(malformed()));
    }

    #[test]
    fn opens_each_kind_two_and_three_parts_and_rejects_wrong_secrets() {
        let expected = fixture(7);
        for slot in [
            sealed_slot([7; 32], &expected),
            prf_slot([7; 32], &expected),
            combined_slot(2, [7; 32], &expected),
            combined_slot(3, [7; 32], &expected),
        ] {
            slot.validate(lookup(&raw().public().agreement)).unwrap();
            let secrets = host_secrets(&slot);
            assert_eq!(finish(&slot, &expected, &secrets).unwrap(), [7; 32]);
            for index in 0..secrets.len() {
                let mut wrong = secrets.clone();
                wrong[index][0] ^= 1;
                assert_eq!(finish(&slot, &expected, &wrong), Err(vault::locked()));
                for length in [0, 31, 33] {
                    wrong[index] = vec![3; length];
                    assert_eq!(finish(&slot, &expected, &wrong), Err(vault::locked()));
                }
            }
            assert_eq!(finish(&slot, &expected, &[]), Err(vault::locked()));
            // Even an authenticated plaintext for another vault must be refused.
            let foreign = match &slot {
                Slot::Sealed { .. } => sealed_slot([8; 32], &expected),
                Slot::Prf { .. } => prf_slot([8; 32], &expected),
                Slot::Combined { parts, .. } => combined_slot(parts.len(), [8; 32], &expected),
            };
            assert_eq!(
                finish(&foreign, &expected, &host_secrets(&foreign)),
                Err(vault::locked())
            );
            // A different expected agreement key, even with the same ID, also fails.
            let mut wrong_vault = expected.clone();
            wrong_vault.agreement = fixture(8).agreement;
            assert_eq!(finish(&slot, &wrong_vault, &secrets), Err(vault::locked()));
            let mut wrong_vault = expected.clone();
            wrong_vault.signing = fixture(8).signing;
            assert_eq!(finish(&slot, &wrong_vault, &secrets), Err(vault::locked()));
        }
    }

    #[test]
    fn all_prf_combined_and_independent_sealed_parts() {
        let expected = fixture(7);
        let ids = [B.into(), C.into()];
        let prf = Slot::combined(
            &[7; 32],
            &vault::id(&expected),
            &ids,
            "two passkeys",
            &[
                NewPart::Prf {
                    salt: &[4; 32],
                    output: &[3; 32],
                },
                NewPart::Prf {
                    salt: &[5; 32],
                    output: &[6; 32],
                },
            ],
            &mut Entropy::new([30; 32]),
        )
        .unwrap();
        assert_eq!(
            prf.finish_open(
                &expected,
                |_| Some(ControllerKey::Webauthn),
                &[OpeningSecret::Prf(&[3; 32]), OpeningSecret::Prf(&[6; 32])],
                SoftwareKeys::from_seed
            )
            .unwrap(),
            [7; 32]
        );
        let agreement = raw().public().agreement;
        let ids = [A.into(), C.into()];
        let sealed = Slot::combined(
            &[7; 32],
            &vault::id(&expected),
            &ids,
            "two raw",
            &[
                NewPart::Sealed {
                    agreement: &agreement,
                },
                NewPart::Sealed {
                    agreement: &agreement,
                },
            ],
            &mut Entropy::new([31; 32]),
        )
        .unwrap();
        let Slot::Combined { parts, .. } = &sealed else {
            panic!("combined")
        };
        let mut plain = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let Part::Sealed { sealed } = part else {
                panic!("sealed part")
            };
            let dh = raw().agree(&sealed.enc).unwrap();
            plain.push(
                sealed
                    .open(
                        &agreement,
                        &dh,
                        &part_info(&vault::id(&expected), i, "sealed", &ids[i]),
                    )
                    .unwrap(),
            );
        }
        assert_ne!(plain[0], plain[1]);
        assert_ne!(plain[0], [7; 32]);
        assert_ne!(plain[1], [7; 32]);
        assert_ne!(parts[0], parts[1]);
        assert_eq!(
            finish(&sealed, &expected, &host_secrets(&sealed)).unwrap(),
            [7; 32]
        );
    }

    #[test]
    fn info_authenticates_order_kind_and_vault_but_not_label() {
        let expected = fixture(7);
        let original = combined_slot(3, [7; 32], &expected);
        let secrets = host_secrets(&original);
        let mut relabeled = original.clone();
        if let Slot::Combined { label, .. } = &mut relabeled {
            *label = "new label".into();
        }
        assert_eq!(finish(&relabeled, &expected, &secrets).unwrap(), [7; 32]);
        let mut reordered = original.clone();
        if let Slot::Combined {
            controllers, parts, ..
        } = &mut reordered
        {
            controllers.swap(0, 2);
            parts.swap(0, 2);
        }
        let mut reordered_secrets = secrets.clone();
        reordered_secrets.swap(0, 2);
        assert_eq!(
            finish(&reordered, &expected, &reordered_secrets),
            Err(vault::locked())
        );
        let mut corrupt = original.clone();
        if let Slot::Combined { box_bytes, .. } = &mut corrupt {
            box_bytes[0] ^= 1;
        }
        assert_eq!(finish(&corrupt, &expected, &secrets), Err(vault::locked()));
        let single = sealed_slot([7; 32], &expected);
        let Slot::Sealed { sealed, .. } = single else {
            panic!("sealed")
        };
        let dh = raw().agree(&sealed.enc).unwrap();
        assert_eq!(
            sealed.open(
                &raw().public().agreement,
                &dh,
                &part_info(&vault::id(&expected), 0, "sealed", A)
            ),
            Err(vault::locked())
        );
    }

    fn parse(value: &Value) -> Result<Slot> {
        Slot::parse(&serde_json::to_vec(value).unwrap())
    }
    fn refuses(value: Value) {
        assert_eq!(parse(&value), Err(malformed()), "{value}");
    }
    fn value(slot: Slot) -> Value {
        serde_json::to_value(slot).unwrap()
    }

    #[test]
    fn malformed_counts_controllers_labels_and_controller_kinds() {
        let expected = fixture(7);
        let agreement = raw().public().agreement;
        let values = [
            value(sealed_slot([7; 32], &expected)),
            value(prf_slot([7; 32], &expected)),
            value(combined_slot(2, [7; 32], &expected)),
        ];
        for valid in &values {
            for bad in [
                json!([]),
                json!([A, A]),
                json!([A, B, C]),
                json!(["not-an-id"]),
                json!(["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]),
                json!([4]),
                Value::Null,
            ] {
                let mut v = valid.clone();
                v["controllers"] = bad;
                refuses(v);
            }
            for bad in [json!(""), json!("é".repeat(101)), json!(4), Value::Null] {
                let mut v = valid.clone();
                v["label"] = bad;
                refuses(v);
            }
            let mut v = valid.clone();
            v["label"] = json!("é".repeat(100));
            parse(&v).unwrap();
            let slot = parse(valid).unwrap();
            assert_eq!(slot.validate(|_| None), Err(malformed()));
        }
        for (controllers, parts) in [
            (json!([]), json!([])),
            (json!([A]), json!([values[2]["parts"][0].clone()])),
            (json!([A, A]), values[2]["parts"].clone()),
            (json!([A, B, C]), values[2]["parts"].clone()),
        ] {
            let mut v = values[2].clone();
            v["controllers"] = controllers;
            v["parts"] = parts;
            refuses(v);
        }
        let mut v = values[2].clone();
        v["parts"].as_array_mut().unwrap().pop();
        refuses(v);
        let sealed = parse(&values[0]).unwrap();
        assert_eq!(
            sealed.validate(|_| Some(ControllerKey::Webauthn)),
            Err(malformed())
        );
        assert_eq!(
            sealed.validate(|_| Some(ControllerKey::Raw { agreement: None })),
            Err(malformed())
        );
        assert_eq!(
            sealed.validate(|_| Some(ControllerKey::Raw {
                agreement: Some(&[4; 65])
            })),
            Err(malformed())
        );
        assert_eq!(
            parse(&values[1])
                .unwrap()
                .validate(|_| Some(ControllerKey::Raw {
                    agreement: Some(&agreement)
                })),
            Err(malformed())
        );
        assert_eq!(
            parse(&values[2])
                .unwrap()
                .validate(|_| Some(ControllerKey::Webauthn)),
            Err(malformed())
        );
        let mut v = values[2].clone();
        v["parts"].as_array_mut().unwrap().swap(0, 1);
        assert_eq!(
            parse(&v).unwrap().validate(lookup(&agreement)),
            Err(malformed())
        );
        // Controller order is meaningful and need not be sorted.
        let mut v = values[2].clone();
        v["controllers"] = json!([B, A]);
        v["parts"].as_array_mut().unwrap().swap(0, 1);
        parse(&v).unwrap().validate(lookup(&agreement)).unwrap();
    }

    #[test]
    fn malformed_sizes_points_closed_fields_nulls_and_duplicates() {
        let expected = fixture(7);
        let valid = [
            value(sealed_slot([7; 32], &expected)),
            value(prf_slot([7; 32], &expected)),
            value(combined_slot(2, [7; 32], &expected)),
        ];
        let paths: [&[&str]; 8] = [
            &["sealed", "enc"],
            &["sealed", "ciphertext"],
            &["salt"],
            &["box"],
            &["parts", "0", "sealed", "enc"],
            &["parts", "0", "sealed", "ciphertext"],
            &["parts", "1", "salt"],
            &["box"],
        ];
        for (index, path) in paths.iter().enumerate() {
            let slot_index = if index < 2 {
                0
            } else if index < 4 {
                1
            } else {
                2
            };
            let pointer = format!("/{}", path.join("/"));
            let len = STANDARD
                .decode(
                    valid[slot_index]
                        .pointer(&pointer)
                        .unwrap()
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
                .len();
            for wrong in [
                Value::Null,
                json!([]),
                json!(32),
                json!("!!!"),
                json!(STANDARD.encode(vec![0; len - 1])),
                json!(STANDARD.encode(vec![0; len + 1])),
            ] {
                let mut v = valid[slot_index].clone();
                *v.pointer_mut(&pointer).unwrap() = wrong;
                refuses(v);
            }
            // Correct-sized encodings of invalid points are also structural failures.
            if path.last() == Some(&"enc") {
                for bytes in [vec![0; 65], vec![4; 65], vec![2; 65]] {
                    let mut v = valid[slot_index].clone();
                    *v.pointer_mut(&pointer).unwrap() = json!(STANDARD.encode(bytes));
                    refuses(v);
                }
            }
        }
        for original in &valid {
            for key in original.as_object().unwrap().keys() {
                let mut missing = original.clone();
                missing.as_object_mut().unwrap().remove(key);
                refuses(missing);
                let mut null = original.clone();
                null[key] = Value::Null;
                refuses(null);
            }
            for key in ["extra", "signing", "parts", "salt", "box", "sealed"] {
                if original.get(key).is_none() {
                    let mut v = original.clone();
                    v[key] = json!("unexpected");
                    refuses(v);
                }
            }
            for bad in [json!("unknown"), json!(null), json!(7), json!([])] {
                let mut v = original.clone();
                v["kind"] = bad;
                refuses(v);
            }
            // Typed deserialization must reject duplicates before any Value conversion.
            let encoded = serde_json::to_string(original).unwrap();
            for (key, val) in original.as_object().unwrap() {
                let duplicate = format!(
                    "{{{}:{},{}",
                    serde_json::to_string(key).unwrap(),
                    val,
                    &encoded[1..]
                );
                assert_eq!(
                    Slot::parse(duplicate.as_bytes()),
                    Err(malformed()),
                    "{duplicate}"
                );
            }
        }
        let nested = ["/sealed", "/parts/0", "/parts/0/sealed", "/parts/1"];
        for path in nested {
            let original = if path == "/sealed" {
                &valid[0]
            } else {
                &valid[2]
            };
            let object = original.pointer(path).unwrap().as_object().unwrap();
            for key in object.keys() {
                let mut v = original.clone();
                v.pointer_mut(path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                refuses(v);
                let mut v = original.clone();
                v.pointer_mut(path).unwrap()[key] = Value::Null;
                refuses(v);
                // Duplicate nested keys, including part-kind tags.
                let nested_json = serde_json::to_string(original.pointer(path).unwrap()).unwrap();
                let duplicate = format!(
                    "{{{}:{},{}",
                    serde_json::to_string(key).unwrap(),
                    object[key],
                    &nested_json[1..]
                );
                let encoded =
                    serde_json::to_string(original)
                        .unwrap()
                        .replacen(&nested_json, &duplicate, 1);
                assert_eq!(
                    Slot::parse(encoded.as_bytes()),
                    Err(malformed()),
                    "{encoded}"
                );
            }
            let mut v = original.clone();
            v.pointer_mut(path).unwrap()["extra"] = json!(true);
            refuses(v);
        }
        for wrong in [json!("combined"), json!("unknown"), json!(7)] {
            let mut v = valid[2].clone();
            v["parts"][0]["kind"] = wrong;
            refuses(v);
        }
        for wrong in [json!([]), json!({}), json!(4), Value::Null] {
            let mut v = valid[2].clone();
            v["parts"] = wrong;
            refuses(v);
        }
        assert_eq!(Slot::parse(b"null"), Err(malformed()));
        assert_eq!(Slot::parse(b"[]"), Err(malformed()));
        let encoded = serde_json::to_string(&valid[0]).unwrap() + " trailing";
        assert_eq!(Slot::parse(encoded.as_bytes()), Err(malformed()));
    }

    #[test]
    fn canonical_json_has_exact_field_names_and_omissions() {
        let expected = fixture(7);
        for slot in [
            sealed_slot([7; 32], &expected),
            prf_slot([7; 32], &expected),
            combined_slot(2, [7; 32], &expected),
        ] {
            let canonical = slot.canonical().unwrap();
            assert_eq!(Slot::parse(&canonical).unwrap(), slot);
            assert_eq!(canonical, records::canonical(&slot).unwrap());
            let value = serde_json::to_value(&slot).unwrap();
            assert!(!value.to_string().contains("box_bytes"));
            let names: Vec<_> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                names,
                match slot {
                    Slot::Sealed { .. } => vec!["controllers", "kind", "label", "sealed"],
                    Slot::Prf { .. } => vec!["box", "controllers", "kind", "label", "salt"],
                    Slot::Combined { .. } => vec!["box", "controllers", "kind", "label", "parts"],
                }
            );
        }
        let slot = Slot::Prf {
            controllers: vec![A.into()],
            label: "a/b".into(),
            salt: vec![0; 32],
            box_bytes: vec![0; 60],
        };
        assert_eq!(String::from_utf8(slot.canonical().unwrap()).unwrap(), format!("{{\"box\":\"{}\",\"controllers\":[\"{A}\"],\"kind\":\"prf\",\"label\":\"a/b\",\"salt\":\"{}\"}}", STANDARD.encode([0; 60]), STANDARD.encode([0; 32])));
    }
}
