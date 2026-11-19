//! The shipped Swift vault: opening a Swift keyring library's vault slots and namespace keys
//! (§15.3, §16.2, §16.3), so that its data can be moved into a 0.5 account.
//!
//! The formats are Marginalia `packages/Colophon/Sources` at `origin/main` `c8280332`:
//!
//! | Form | Swift source |
//! | --- | --- |
//! | `SealedKey` `{ephemeral, box}`: ECDH with the recipient's agreement key, HKDF-SHA256 (IKM the raw x-coordinate, **salt the recipient's 65-byte signing point**, info `colophon/sealed-key/1`), AES-256-GCM `nonce ‖ ciphertext ‖ tag`, no associated data | `ColophonCore/SealedKey.swift:11-30` |
//! | `sealed` slot: a `SealedKey` of the 32-byte seed to `recipient` | `ColophonAuthority/VaultSlot.swift:39-44`, open `:76-89` |
//! | `prf` slot: AES-GCM of the seed under HKDF-SHA256(IKM = PRF output, salt = `salt`, info `colophon/vault-prf/1`) | `VaultSlot.swift:47-57`, `:91-101`, `:121-123` |
//! | `combined` slot: AES-GCM of the seed under HKDF-SHA256(IKM = the part secrets in order, **empty salt**, info `colophon/vault-combined/1`) | `VaultSlot.swift:61-74`, `:104-119` |
//! | a `prf` part: its secret is HKDF-SHA256(IKM = PRF output, salt, info `colophon/vault-part/1`); a `sealed` part: a `SealedKey` of a random 32-byte secret | `ColophonAuthority/VaultSlotPart.swift:34-49`, `:51-75` |
//! | the vault identity of a seed: for each of `signing` and `agreement`, the first counter `c` from 0 for which HKDF-SHA256(IKM = seed, salt `colophon/vault/1`, info `<purpose>/<c>`) is a valid P-256 scalar | `ColophonCore/VaultKey.swift:6-40` |
//! | the recovery kit's identity: the same derivation with salt `colophon/recovery/1` over the 32 kit bytes | `ColophonCore/RecoveryKit.swift:55-59` |
//! | the check after opening: the seed's identity equals the keyring's `vault` (both points) | `KeyringHolder.swift:536-549` |
//! | an operation: AES-256-GCM `nonce ‖ ciphertext ‖ tag` of the canonical operation, no associated data, under the namespace key of the header's epoch | `ColophonReplica/Replica.swift:825`, `:996` |
//!
//! **The PRF input.** The Swift host passes the slot's `salt` unchanged as the platform's first
//! PRF input (`ColophonUI/SystemWebAuthnCeremonies.swift:33`, `:77`) and reads `prf.first`
//! (`:42`, `:88`); it applies no transform of its own. So the salt here is the exact
//! `prf.eval.first` of §7.2, and the standard WebAuthn hashing is the platform's.
//!
//! **What the core guarantees, exactly** (the words of `v05/vault.rs`). The core never returns
//! seed bytes, a raw ECDH output or a namespace key through its API. [`PredecessorVault`] and
//! [`SwiftEpochKey`] are opaque types with private fields, no accessor, no `Clone`, no
//! `Serialize`, a redacted `Debug` and erasure on drop (best effort: the crate forbids `unsafe`
//! and has no zeroizing dependency, so overwriting uses ordinary writes that
//! `std::hint::black_box` only discourages the optimizer from removing). Each records the
//! predecessor library it was opened under and refuses a library of any other ID. A
//! [`PredecessorVault`] can do exactly one thing: open the namespace keys the predecessor's
//! history sealed to its vault ([`PredecessorVault::open_epoch_key`]). A [`SwiftEpochKey`] can do
//! exactly one thing: open the operation headers of its own library, namespace and epoch
//! (`pub(super)`, so only `v05` modules reach it, and they receive plaintext operations, never
//! the key). **The host is trusted** with the ECDH results and PRF outputs it passes in, with the
//! kit bytes it hands to [`swift_kit_identity`], and with signing whatever it is asked to sign;
//! the core cannot stop a host that holds an old agreement key from opening what that key opens.
//! Nothing here seals anything: the successor's slots are built by `v05::slots` from a new seed
//! (§7.1), and the old seed is never written anywhere.
use super::descriptor::valid_point;
use super::encoding::decode_base64;
use super::history::swift;
use super::ids::key_id;
use super::slots::{OpeningInput, OpeningSecret, PrfRequest};
use super::vault::{
    erase, locked, malformed, require, EcdhOutput, PartSecret, SoftwareIdentity, VResult,
};
use hkdf::Hkdf;
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;

/// `info` of a Swift `SealedKey` (`SealedKey.swift:11`).
pub const SEALED_KEY_INFO: &[u8] = b"colophon/sealed-key/1";
/// `info` of a Swift `prf` slot (`VaultSlot.swift:9`).
pub const PRF_INFO: &[u8] = b"colophon/vault-prf/1";
/// `info` of a Swift `combined` slot (`VaultSlot.swift:10`).
pub const COMBINED_INFO: &[u8] = b"colophon/vault-combined/1";
/// `info` of a Swift PRF part (`VaultSlotPart.swift:8`).
pub const PART_INFO: &[u8] = b"colophon/vault-part/1";
/// HKDF salt of the Swift vault identity (`VaultKey.swift:29`).
pub const VAULT_SALT: &[u8] = b"colophon/vault/1";
/// HKDF salt of the Swift recovery kit's identity (`RecoveryKit.swift:12`).
pub const KIT_SALT: &[u8] = b"colophon/recovery/1";

/// The most parts a combined slot may have here (Swift sets none; shipped slots have two).
const MAX_PARTS: usize = 16;

/// `P256Derivation.scalar` (`VaultKey.swift:14-21`): the first counter from 0 up to 255 whose
/// HKDF output is a valid scalar.
fn derive_scalar(secret: &[u8; 32], salt: &[u8], purpose: &str) -> VResult<SecretKey> {
    for counter in 0..256u32 {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(salt), secret)
            .expand(format!("{purpose}/{counter}").as_bytes(), &mut out)
            .map_err(|_| malformed("HKDF output length"))?;
        let key = SecretKey::from_slice(&out);
        erase(&mut out);
        if let Ok(k) = key {
            return Ok(k);
        }
    }
    Err(malformed("Swift identity: no valid scalar in 256 counters"))
}

fn point_of(key: &SecretKey) -> Vec<u8> {
    key.public_key().to_encoded_point(false).as_bytes().to_vec()
}

/// The Swift recovery kit's identity (`RecoveryKit.identity()`): signing and agreement scalars
/// from the 32 kit bytes. A host answers an ECDH route of a kit's `sealed` slot with
/// [`super::slots::answer_with_identity`]. This is **not** the §7.5 / `kit_identity` derivation
/// (`colophon/recovery/3`): a Swift kit's keys are carried into the successor as public keys, and
/// only this derivation reproduces their private halves.
pub fn swift_kit_identity(kit: &[u8; 32]) -> VResult<SoftwareIdentity> {
    let signing = derive_scalar(kit, KIT_SALT, "signing")?;
    let agreement = derive_scalar(kit, KIT_SALT, "agreement")?;
    Ok(SoftwareIdentity::from_scalars(signing, agreement))
}

/// A Swift `PublicIdentity`: a signing and an agreement point (`PublicIdentity.swift`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwiftIdentity {
    /// The 65-byte signing point.
    pub signing: Vec<u8>,
    /// The 65-byte agreement point.
    pub agreement: Vec<u8>,
}
impl SwiftIdentity {
    /// The first 32 hex of SHA-256 of the signing point.
    pub fn id(&self) -> String {
        key_id(&self.signing)
    }
}

#[derive(Clone, Debug)]
struct SwiftSealed {
    ephemeral: Vec<u8>,
    boxed: Vec<u8>,
}

#[derive(Clone, Debug)]
enum Route {
    Sealed {
        recipient: SwiftIdentity,
        sealed: SwiftSealed,
    },
    Prf {
        credential: Vec<u8>,
        salt: Vec<u8>,
    },
}

/// One slot of a Swift keyring, parsed as `Keyring.swift:139-153` (`slotIncomplete`) reads it.
#[derive(Clone, Debug)]
pub struct SwiftSlot {
    kind: &'static str,
    label: String,
    controller: Option<String>,
    routes: Vec<Route>,
    boxed: Option<Vec<u8>>,
    /// Why this slot could not be parsed; such a slot opens nothing and fails only itself.
    invalid: Option<String>,
}
impl SwiftSlot {
    fn invalid(why: String) -> Self {
        Self {
            kind: "invalid",
            label: String::new(),
            controller: None,
            routes: Vec::new(),
            boxed: None,
            invalid: Some(why),
        }
    }
    /// Why the slot could not be read, when it could not.
    pub fn problem(&self) -> Option<&str> {
        self.invalid.as_deref()
    }
    /// `sealed`, `prf` or `combined`.
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    /// The display label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// The `controller` the slot names, when it names one.
    pub fn controller(&self) -> Option<&str> {
        self.controller.as_deref()
    }
}

fn text<'a>(v: &'a Value, f: &str) -> VResult<&'a str> {
    v.get(f)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("Swift slot: {f}")))
}
fn bytes(v: &Value, f: &str, max: usize) -> VResult<Vec<u8>> {
    decode_base64(text(v, f)?, max)
}
fn point(v: &Value, f: &str) -> VResult<Vec<u8>> {
    let p = bytes(v, f, 65)?;
    require(valid_point(&p), "Swift slot: not a P-256 point")?;
    Ok(p)
}
fn identity_of(v: &Value) -> VResult<SwiftIdentity> {
    Ok(SwiftIdentity {
        signing: point(v, "signing")?,
        agreement: point(v, "agreement")?,
    })
}
fn sealed_of(v: &Value) -> VResult<SwiftSealed> {
    let s = SwiftSealed {
        ephemeral: point(v, "ephemeral")?,
        boxed: bytes(v, "box", 60)?,
    };
    // 12-byte nonce, 32 bytes of secret, 16-byte tag (`SealedKey.swift:17`).
    require(s.boxed.len() == 60, "Swift sealed key: box is not 60 bytes")?;
    Ok(s)
}
fn route_of(v: &Value) -> VResult<Route> {
    match text(v, "kind")? {
        "sealed" => Ok(Route::Sealed {
            recipient: identity_of(
                v.get("recipient")
                    .ok_or_else(|| malformed("Swift slot: recipient"))?,
            )?,
            sealed: sealed_of(
                v.get("sealed")
                    .ok_or_else(|| malformed("Swift slot: sealed"))?,
            )?,
        }),
        "prf" => {
            let credential = bytes(v, "credential", 1_048_576)?;
            let salt = bytes(v, "salt", 32)?;
            require(
                !credential.is_empty() && salt.len() == 32,
                "Swift PRF route: credential and a 32-byte salt",
            )?;
            Ok(Route::Prf { credential, salt })
        }
        k => Err(crate::v05::Failure::NewerFormat(format!(
            "Swift slot kind {k}"
        ))),
    }
}
fn slot_of(v: &Value) -> VResult<SwiftSlot> {
    let kind = match text(v, "kind")? {
        "sealed" => "sealed",
        "prf" => "prf",
        "combined" => "combined",
        k => {
            return Err(crate::v05::Failure::NewerFormat(format!(
                "Swift slot kind {k}"
            )))
        }
    };
    let label = text(v, "label")?.to_string();
    let controller = v
        .get("controller")
        .and_then(Value::as_str)
        .map(str::to_string);
    let (routes, boxed) = match kind {
        "sealed" => (vec![route_of(v)?], None),
        "prf" => {
            let b = bytes(v, "box", 60)?;
            require(b.len() == 60, "Swift PRF slot: box is not 60 bytes")?;
            (vec![route_of(v)?], Some(b))
        }
        _ => {
            let parts = v
                .get("parts")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("Swift combined slot: parts"))?;
            require(
                (2..=MAX_PARTS).contains(&parts.len()),
                "Swift combined slot: 2 to 16 parts",
            )?;
            let b = bytes(v, "box", 60)?;
            require(b.len() == 60, "Swift combined slot: box is not 60 bytes")?;
            (
                parts.iter().map(route_of).collect::<VResult<Vec<_>>>()?,
                Some(b),
            )
        }
    };
    Ok(SwiftSlot {
        kind,
        label,
        controller,
        routes,
        boxed,
        invalid: None,
    })
}

/// A verified Swift keyring library (`history::swift::verify`) with what opening it needs: the
/// vault's public identity, its slots, and every sealed namespace key the history holds.
#[derive(Clone, Debug)]
pub struct SwiftLibrary {
    history: swift::History,
    library: String,
    vault: Option<SwiftIdentity>,
    slots: Vec<SwiftSlot>,
    /// `controller ID -> credential` of the WebAuthn controllers at the head.
    credentials: BTreeMap<String, Vec<u8>>,
    /// Every signing point the history names, by ID.
    signing: BTreeMap<String, Vec<u8>>,
    /// `(namespace, epoch) -> principal ID -> sealed key`, the last write winning
    /// (`AuthorityState.swift:307`).
    shares: BTreeMap<(String, u64), BTreeMap<String, SwiftSealed>>,
    /// `namespace -> [(epoch, seq of the introducing entry)]` (`AuthorityState.swift:308-310`).
    epochs: BTreeMap<String, Vec<(u64, u64)>>,
    /// Slots and shares that could not be read: each fails only itself.
    problems: Vec<String>,
}

fn collect_signing(v: &Value, out: &mut BTreeMap<String, Vec<u8>>) {
    if let Some(p) = v
        .get("signing")
        .and_then(Value::as_str)
        .and_then(|s| decode_base64(s, 65).ok())
        .filter(|p| valid_point(p))
    {
        out.insert(key_id(&p), p);
    }
}

impl SwiftLibrary {
    /// Verify `entries` (the predecessor's `authority/*.json`, in any order) with the Swift
    /// verifier and fold what opening needs. The last state is the one the slots are read from.
    pub fn read(entries: &[Vec<u8>]) -> VResult<Self> {
        let history = swift::verify(entries)?;
        let last = history
            .states
            .last()
            .ok_or_else(|| malformed("Swift empty predecessor"))?;
        let mut vault = None;
        let mut slots = Vec::new();
        let mut credentials = BTreeMap::new();
        if last.adopted {
            let ring = &last.raw_keyring;
            vault = Some(identity_of(
                ring.get("vault")
                    .ok_or_else(|| malformed("Swift keyring: vault"))?,
            )?);
            for s in ring
                .get("slots")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("Swift keyring: slots"))?
            {
                slots.push(
                    slot_of(s).unwrap_or_else(|e| SwiftSlot::invalid(e.detail().to_string())),
                );
            }
            for (id, c) in &last.controllers {
                if let Some(w) = c.key().webauthn() {
                    credentials.insert(id.clone(), w.credential().to_vec());
                }
            }
        }
        let mut signing = BTreeMap::new();
        let mut shares: BTreeMap<(String, u64), BTreeMap<String, SwiftSealed>> = BTreeMap::new();
        let mut epochs: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
        let mut problems: Vec<String> = slots
            .iter()
            .enumerate()
            .filter_map(|(i, s): (usize, &SwiftSlot)| s.problem().map(|p| format!("slot {i}: {p}")))
            .collect();
        for (i, e) in history.entries.iter().enumerate() {
            let v = &e.value;
            for f in ["root", "recovery", "member", "vault"] {
                if let Some(x) = v.get(f) {
                    collect_signing(x, &mut signing);
                }
            }
            for x in v
                .get("stewards")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                collect_signing(x, &mut signing);
            }
            for x in v
                .get("slots")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(r) = x.get("recipient") {
                    collect_signing(r, &mut signing);
                }
            }
            if v["kind"] != "shareKey" {
                continue;
            }
            let (Some(id), Some(ns), Some(epoch), Some(key)) = (
                v["memberID"].as_str(),
                v["namespace"].as_str(),
                v["epoch"].as_u64().filter(|n| *n < 1 << 53),
                v.get("key"),
            ) else {
                continue; // Swift's `apply` ignores a shareKey with a missing field (`:306`).
            };
            match sealed_of(key) {
                Ok(sealed) => {
                    shares
                        .entry((ns.to_string(), epoch))
                        .or_default()
                        .insert(id.to_string(), sealed);
                }
                Err(e) => problems.push(format!(
                    "share of {ns} epoch {epoch} to {id} (entry {}): {}",
                    i + 1,
                    e.detail()
                )),
            }
            let list = epochs.entry(ns.to_string()).or_default();
            if !list.iter().any(|(n, _)| *n == epoch) {
                list.push((epoch, i as u64 + 1));
            }
        }
        Ok(Self {
            library: history.account.clone(),
            history,
            vault,
            slots,
            credentials,
            signing,
            shares,
            epochs,
            problems,
        })
    }

    /// What could not be read, each item failing only itself: a slot that does not parse, a
    /// `shareKey` whose key is not a valid point and a 60-byte box.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
    /// The library ID: the first 32 hex of SHA-256 of entry 1's body.
    pub fn library(&self) -> &str {
        &self.library
    }
    /// The verified history.
    pub fn history(&self) -> &swift::History {
        &self.history
    }
    /// The vault's public identity, when the library has adopted a keyring.
    pub fn vault(&self) -> Option<&SwiftIdentity> {
        self.vault.as_ref()
    }
    /// The slots of the keyring at the head.
    pub fn slots(&self) -> &[SwiftSlot] {
        &self.slots
    }
    /// Every epoch of `namespace` with the seq of the entry that introduced it, oldest first.
    pub fn epochs(&self, namespace: &str) -> &[(u64, u64)] {
        self.epochs.get(namespace).map_or(&[], Vec::as_slice)
    }
    /// The namespaces that have an epoch (`AuthorityState.namespaces`).
    pub fn namespaces(&self) -> Vec<String> {
        self.epochs.keys().cloned().collect()
    }
    /// The principals (IDs) a `(namespace, epoch)` key was sealed to.
    pub fn sealed_to(&self, namespace: &str, epoch: u64) -> Vec<String> {
        self.shares
            .get(&(namespace.to_string(), epoch))
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn controller_of_credential(&self, credential: &[u8]) -> String {
        self.credentials
            .iter()
            .find(|(_, c)| c.as_slice() == credential)
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| format!("credential:{}", super::encoding::hex(credential)))
    }

    fn input_of(&self, route: &Route) -> OpeningInput {
        match route {
            Route::Sealed { recipient, sealed } => OpeningInput::Ecdh {
                controller: recipient.id(),
                enc: sealed.ephemeral.clone(),
            },
            Route::Prf { credential, salt } => OpeningInput::Prf {
                controller: self.controller_of_credential(credential),
                salt: salt.clone(),
            },
        }
    }

    /// Begin opening slot `index`: the exact host work, in order. An ECDH result for a route is
    /// the raw x-coordinate of the recipient's agreement key against the `enc` point; a PRF
    /// route is the PRF output of that credential for that salt, passed as `prf.eval.first`
    /// unchanged.
    pub fn begin_open(&self, index: usize) -> VResult<Vec<OpeningInput>> {
        let slot = self
            .slots
            .get(index)
            .ok_or_else(|| malformed("no such Swift slot"))?;
        require(slot.invalid.is_none(), "this Swift slot could not be read")?;
        Ok(slot.routes.iter().map(|r| self.input_of(r)).collect())
    }

    /// Finish opening slot `index` with the host's results, in the order [`Self::begin_open`]
    /// gave. The plaintext must be 32 bytes whose Swift vault identity is the keyring's `vault`
    /// (`KeyringHolder.swift:542`). A wrong, missing or mismatched result is
    /// `refused:vaultLocked`; the handle is returned only then.
    pub fn finish_open(
        &self,
        index: usize,
        secrets: &[OpeningSecret],
    ) -> VResult<PredecessorVault> {
        let slot = self
            .slots
            .get(index)
            .ok_or_else(|| malformed("no such Swift slot"))?;
        require(slot.invalid.is_none(), "this Swift slot could not be read")?;
        let vault = self.vault.as_ref().ok_or_else(locked)?;
        if secrets.len() != slot.routes.len() {
            return Err(locked());
        }
        let seed = match slot.kind {
            "sealed" => {
                let Route::Sealed { recipient, sealed } = &slot.routes[0] else {
                    return Err(malformed("Swift sealed slot route"));
                };
                let OpeningSecret::Ecdh(dh) = &secrets[0] else {
                    return Err(locked());
                };
                open_sealed(sealed, recipient, dh)?
            }
            "prf" => {
                let Route::Prf { salt, .. } = &slot.routes[0] else {
                    return Err(malformed("Swift PRF slot route"));
                };
                let OpeningSecret::Prf(p) = &secrets[0] else {
                    return Err(locked());
                };
                let boxed = slot
                    .boxed
                    .as_ref()
                    .ok_or_else(|| malformed("Swift PRF slot box"))?;
                // `VaultSlot.wrappingKey`: HKDF(IKM = PRF output, salt, info `vault-prf/1`).
                let key = p.derive(salt, PRF_INFO)?.into_box_key();
                key.open_swift(boxed).ok_or_else(locked)?
            }
            _ => {
                let boxed = slot
                    .boxed
                    .as_ref()
                    .ok_or_else(|| malformed("Swift combined slot box"))?;
                let mut parts = Vec::with_capacity(slot.routes.len());
                for (route, secret) in slot.routes.iter().zip(secrets) {
                    parts.push(match (route, secret) {
                        (Route::Sealed { recipient, sealed }, OpeningSecret::Ecdh(dh)) => {
                            PartSecret::from_swift_plain(open_sealed(sealed, recipient, dh)?)?
                        }
                        (Route::Prf { salt, .. }, OpeningSecret::Prf(p)) => {
                            p.derive(salt, PART_INFO)?
                        }
                        _ => return Err(locked()),
                    });
                }
                PartSecret::combine(&parts, COMBINED_INFO)?
                    .open_swift(boxed)
                    .ok_or_else(locked)?
            }
        };
        PredecessorVault::from_plain(&self.library, seed, vault)
    }

    /// Begin opening the key of `(namespace, epoch)` that the history sealed to the principal
    /// `principal` (a root, recovery or steward identity, a member, or the vault): the ECDH the
    /// host must do with that principal's agreement key. Nothing here needs the vault.
    pub fn begin_open_share(
        &self,
        namespace: &str,
        epoch: u64,
        principal: &str,
    ) -> VResult<OpeningInput> {
        let sealed = self.share(namespace, epoch, principal)?;
        Ok(OpeningInput::Ecdh {
            controller: principal.to_string(),
            enc: sealed.ephemeral.clone(),
        })
    }

    /// Finish [`Self::begin_open_share`] with the host's ECDH result.
    pub fn finish_open_share(
        &self,
        namespace: &str,
        epoch: u64,
        principal: &str,
        secret: &OpeningSecret,
    ) -> VResult<SwiftEpochKey> {
        let sealed = self.share(namespace, epoch, principal)?;
        let signing = self.signing.get(principal).ok_or_else(locked)?;
        let OpeningSecret::Ecdh(dh) = secret else {
            return Err(locked());
        };
        let plain = open_with_dh(sealed, signing, dh)?;
        SwiftEpochKey::from_plain(&self.library, namespace, epoch, plain)
    }

    fn share(&self, namespace: &str, epoch: u64, principal: &str) -> VResult<&SwiftSealed> {
        self.shares
            .get(&(namespace.to_string(), epoch))
            .and_then(|m| m.get(principal))
            .ok_or_else(|| {
                crate::v05::Failure::Unavailable(format!(
                    "no key of {namespace} epoch {epoch} was sealed to {principal}"
                ))
            })
    }
}

/// `SealedKey.open(with:)`: the wrapping key from the host's ECDH result, then AES-GCM.
fn open_with_dh(
    sealed: &SwiftSealed,
    recipient_signing: &[u8],
    dh: &EcdhOutput,
) -> VResult<Vec<u8>> {
    dh.derive_wrap(recipient_signing, SEALED_KEY_INFO)?
        .open_swift(&sealed.boxed)
        .ok_or_else(locked)
}
fn open_sealed(
    sealed: &SwiftSealed,
    recipient: &SwiftIdentity,
    dh: &EcdhOutput,
) -> VResult<Vec<u8>> {
    open_with_dh(sealed, &recipient.signing, dh)
}

/// The opened vault seed of a predecessor Swift library. Opaque: no accessor, no `Clone`, no
/// `Serialize`; see the module header.
///
/// ```compile_fail
/// fn read(v: &colophon_core::v05::swift_slots::PredecessorVault) {
///     let _ = &v.seed; // private: there is no accessor of any visibility for the seed
/// }
/// ```
pub struct PredecessorVault {
    library: String,
    seed: [u8; 32],
    vault: SwiftIdentity,
}
impl PredecessorVault {
    fn from_plain(library: &str, mut plain: Vec<u8>, expected: &SwiftIdentity) -> VResult<Self> {
        let seed = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| locked());
        erase(&mut plain);
        let mut seed = seed?;
        let derived = (|| -> VResult<SwiftIdentity> {
            Ok(SwiftIdentity {
                signing: point_of(&derive_scalar(&seed, VAULT_SALT, "signing")?),
                agreement: point_of(&derive_scalar(&seed, VAULT_SALT, "agreement")?),
            })
        })();
        match derived {
            Ok(d) if &d == expected => Ok(Self {
                library: library.to_string(),
                seed,
                vault: d,
            }),
            _ => {
                erase(&mut seed);
                Err(locked())
            }
        }
    }

    /// The library this seed was opened under.
    pub fn library(&self) -> &str {
        &self.library
    }
    /// The vault's public identity.
    pub fn vault(&self) -> &SwiftIdentity {
        &self.vault
    }

    /// Open the key of `(namespace, epoch)` that `library`'s history sealed to the vault. The
    /// handle opens only the library it was opened under; any other is `refused:vaultLocked`.
    pub fn open_epoch_key(
        &self,
        library: &SwiftLibrary,
        namespace: &str,
        epoch: u64,
    ) -> VResult<SwiftEpochKey> {
        require(
            library.library == self.library && library.vault.as_ref() == Some(&self.vault),
            "this vault was opened under another library",
        )
        .map_err(|_| locked())?;
        let sealed = library.share(namespace, epoch, &self.vault.id())?;
        let agreement = derive_scalar(&self.seed, VAULT_SALT, "agreement")?;
        let peer = p256::PublicKey::from_sec1_bytes(&sealed.ephemeral).map_err(|_| locked())?;
        let shared = p256::ecdh::diffie_hellman(agreement.to_nonzero_scalar(), peer.as_affine());
        let dh = EcdhOutput::from_host(shared.raw_secret_bytes().as_slice())?;
        let plain = open_with_dh(sealed, &self.vault.signing, &dh)?;
        SwiftEpochKey::from_plain(&self.library, namespace, epoch, plain)
    }
}
impl Drop for PredecessorVault {
    fn drop(&mut self) {
        erase(&mut self.seed);
    }
}
impl std::fmt::Debug for PredecessorVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PredecessorVault({}, ..)", self.library)
    }
}

/// A Swift namespace key (one epoch), bound to its library and namespace. It opens operation
/// headers of that library, namespace and epoch, and nothing else.
pub struct SwiftEpochKey {
    library: String,
    namespace: String,
    epoch: u64,
    key: [u8; 32],
}
impl SwiftEpochKey {
    fn from_plain(library: &str, namespace: &str, epoch: u64, mut plain: Vec<u8>) -> VResult<Self> {
        let key = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| locked());
        erase(&mut plain);
        Ok(Self {
            library: library.to_string(),
            namespace: namespace.to_string(),
            epoch,
            key: key?,
        })
    }
    /// The library this key belongs to.
    pub fn library(&self) -> &str {
        &self.library
    }
    /// The namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    /// The epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Open an operation's `sealed` bytes (`nonce ‖ ciphertext ‖ tag`, no associated data) and
    /// return the plaintext, or `None`. The caller names the library, namespace and epoch of
    /// the header the bytes came from; a key of any other is refused.
    pub(super) fn open_operation(
        &self,
        library: &str,
        namespace: &str,
        epoch: u64,
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        if library != self.library || namespace != self.namespace || epoch != self.epoch {
            return None;
        }
        super::vault::box_key_of(&self.key).open_swift(sealed)
    }
}
impl Drop for SwiftEpochKey {
    fn drop(&mut self) {
        erase(&mut self.key);
    }
}
impl std::fmt::Debug for SwiftEpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SwiftEpochKey({}/{}/{}, ..)",
            self.library, self.namespace, self.epoch
        )
    }
}

/// One assertion that rebuilds one passkey's slot: the old slot's PRF input and the new slot's
/// PRF request (§7.2), for the host to answer with a single WebAuthn assertion over the core's
/// challenge that evaluates both inputs, **with user verification** (the new route is verified
/// against the controller, and a carried passkey has `verification: true`).
///
/// The Swift host passes only one PRF input (`SystemWebAuthnCeremonies.swift:33`, `:77`), so a
/// host that rebuilds a slot with one assertion must pass the **new** salt as the first input
/// (§7.2: the slot's `salt` is `prf.eval.first`) and the **old** salt as the **second** input, and
/// read the outputs from `results.first` and `results.second`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoveCeremony {
    /// The controller whose credential is asserted.
    pub controller: String,
    /// The relying-party ID of the new slot's request.
    pub rp: String,
    /// The credential to assert.
    pub credential: Vec<u8>,
    /// The old slot's salt, to pass as the second PRF input: its output opens the Swift slot.
    pub old_salt: Vec<u8>,
    /// The new slot's request: its salt (the first PRF input) and the core's challenge.
    pub new_request: PrfRequest,
    /// The assertion must carry user verification.
    pub user_verification: bool,
}

impl SwiftLibrary {
    /// Pair the PRF route of slot `index` with the new PRF requests, by controller ID **and**
    /// credential, so that each passkey is asked once. A new request with no old route of the
    /// same controller and credential, and an old PRF route with no new request, are returned
    /// in `unpaired` (the controller's ID, or `credential:<hex>`).
    pub fn pair_ceremonies(
        &self,
        index: usize,
        new: &[PrfRequest],
    ) -> VResult<(Vec<MoveCeremony>, Vec<String>)> {
        let slot = self
            .slots
            .get(index)
            .ok_or_else(|| malformed("no such Swift slot"))?;
        let mut paired = Vec::new();
        let mut unpaired = Vec::new();
        let mut used = vec![false; slot.routes.len()];
        for r in new {
            let hit = slot.routes.iter().enumerate().find(|(i, route)| {
                !used[*i]
                    && matches!(route, Route::Prf { credential, .. }
                        if *credential == r.credential
                            && self.controller_of_credential(credential) == r.controller)
            });
            match hit {
                Some((i, Route::Prf { salt, .. })) => {
                    used[i] = true;
                    paired.push(MoveCeremony {
                        controller: r.controller.clone(),
                        rp: r.rp.clone(),
                        credential: r.credential.clone(),
                        old_salt: salt.clone(),
                        new_request: r.clone(),
                        user_verification: true,
                    });
                }
                _ => unpaired.push(r.controller.clone()),
            }
        }
        for (i, route) in slot.routes.iter().enumerate() {
            if let (false, Route::Prf { credential, .. }) = (used[i], route) {
                unpaired.push(self.controller_of_credential(credential));
            }
        }
        Ok((paired, unpaired))
    }
}
