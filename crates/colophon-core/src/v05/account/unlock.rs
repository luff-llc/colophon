//! Unlocking: slots to the vault seed, the seed (and `previousVault`) to epoch keys, a member's
//! agreement key to its shares, and a seed moved to a new device by pairing (§7.1–§7.4, §8.3,
//! §11.1).
//!
//! The seed and the epoch keys stay inside the account as the opaque types of `v05::vault` and
//! `v05::records`. There is no accessor for either, no `Serialize`, and `Debug` is redacted.
//! A seed is installed only when it was opened under this account (it records the account it
//! was opened under) or is new, and only after the core has checked that it derives a vault of
//! this account's verified history.
use super::{Account, Changes};
use crate::crypto::Entropy;
use crate::v05::descriptor::Controller;
use crate::v05::history::envelope::AuthEnvelope;
use crate::v05::ids::AccountId;
use crate::v05::pairing::{seal_seed_for_transfer, ConfirmedPairing, TransferKey};
use crate::v05::records::EpochKeys;
use crate::v05::slots::{OpeningInput, OpeningSecret, Slot};
use crate::v05::vault::{EcdhOutput, SealedBox, VaultPublic, VaultSeed};
use crate::v05::{malformed, require, Result};
use serde_json::Value;

/// The vault seeds this account holds in memory: the current one, earlier ones reached through
/// `previousVault`, and a new one staged by a rotation that has not activated yet.
#[derive(Default)]
pub(super) struct SeedRing {
    seeds: Vec<VaultSeed>,
}
impl SeedRing {
    pub(super) fn iter(&self) -> impl Iterator<Item = &VaultSeed> {
        self.seeds.iter()
    }
    pub(super) fn len(&self) -> usize {
        self.seeds.len()
    }
    /// Forget the seeds added after the first `n` (erased on drop).
    pub(super) fn truncate(&mut self, n: usize) {
        self.seeds.truncate(n);
    }
    pub(super) fn lock(&mut self) {
        self.seeds.clear();
    }
    /// The seed that derives `vault`, if held.
    pub(super) fn current(&self, vault: &VaultPublic) -> Option<&VaultSeed> {
        self.seeds
            .iter()
            .find(|s| s.public().is_ok_and(|p| p == *vault))
    }
    /// Add a seed: refused unless it is new or was opened under `account`. A seed that derives a
    /// vault already held is dropped (erased).
    pub(super) fn install(&mut self, seed: VaultSeed, account: &AccountId) -> Result<()> {
        require(
            seed.is_new() || seed.account() == Some(account),
            "the seed was opened under another account",
        )?;
        let public = seed.public()?;
        if self.current(&public).is_none() {
            self.seeds.push(seed);
        }
        Ok(())
    }
    /// Open every earlier seed reachable from a held one through the `previousVault` seals of
    /// the verified history, and so on back. `publics` are the vaults the history named;
    /// `boxes` the `previousVault` seals it carried.
    pub(super) fn close_chain(
        &mut self,
        account: &AccountId,
        publics: &[VaultPublic],
        boxes: &[SealedBox],
    ) {
        loop {
            let mut found = Vec::new();
            for seed in &self.seeds {
                let Ok(mine) = seed.public() else { continue };
                for b in boxes {
                    for old in publics {
                        if *old == mine || self.current(old).is_some() {
                            continue;
                        }
                        if let Ok(old_seed) = seed.open_previous(b, old, account) {
                            found.push(old_seed);
                        }
                    }
                }
            }
            if found.is_empty() {
                return;
            }
            let mut grew = false;
            for s in found {
                let before = self.seeds.len();
                if self.install(s, account).is_ok() && self.seeds.len() > before {
                    grew = true;
                }
            }
            if !grew {
                return;
            }
        }
    }
}

/// The vaults and `previousVault` seals the verified branch carries: a genesis keyring's vault,
/// each `vault` entry, and each activated transition with a `vault` component.
pub(super) fn vault_chain(
    entries: &[Vec<u8>],
    branch: &[String],
) -> (Vec<VaultPublic>, Vec<SealedBox>) {
    use crate::v05::encoding::{bounds, decode_base64};
    let on_branch: std::collections::BTreeSet<&String> = branch.iter().collect();
    let public_of = |v: &Value| -> Option<VaultPublic> {
        let s = decode_base64(v.get("signing")?.as_str()?, 128).ok()?;
        let a = decode_base64(v.get("agreement")?.as_str()?, 128).ok()?;
        Some(VaultPublic {
            signing: s,
            agreement: a,
        })
    };
    let mut publics: Vec<VaultPublic> = Vec::new();
    let mut boxes: Vec<SealedBox> = Vec::new();
    fn take(
        publics: &mut Vec<VaultPublic>,
        boxes: &mut Vec<SealedBox>,
        component: &Value,
        prev: Option<&Value>,
        public_of: &dyn Fn(&Value) -> Option<VaultPublic>,
    ) {
        if let Some(p) = component.get("vault").and_then(public_of) {
            if !publics.contains(&p) {
                publics.push(p);
            }
        }
        if let Some(b) = prev.and_then(|v| serde_json::from_value::<SealedBox>(v.clone()).ok()) {
            if !boxes.contains(&b) {
                boxes.push(b);
            }
        }
    }
    for bytes in entries {
        let Ok(env) = AuthEnvelope::parse(
            bytes,
            bounds::AUTHORITY_BODY,
            bounds::AUTHORITY_BODY.saturating_mul(2),
            false,
        ) else {
            continue;
        };
        if !on_branch.contains(&env.digest) {
            continue;
        }
        let v = &env.value;
        match v.get("kind").and_then(Value::as_str) {
            Some("genesis") => {
                if let Some(p) = v
                    .get("keyring")
                    .and_then(|k| k.get("vault"))
                    .and_then(public_of)
                {
                    if !publics.contains(&p) {
                        publics.push(p);
                    }
                }
            }
            Some("vault") => take(
                &mut publics,
                &mut boxes,
                v,
                v.get("previousVault"),
                &public_of,
            ),
            Some("activate") => {
                let Some(t) = v.get("transition").and_then(Value::as_str) else {
                    continue;
                };
                let Ok(raw) = decode_base64(t, bounds::TRANSITION_ENVELOPE * 2) else {
                    continue;
                };
                let Ok(te) = AuthEnvelope::parse(
                    &raw,
                    bounds::TRANSITION_ENVELOPE,
                    bounds::TRANSITION_ENVELOPE,
                    true,
                ) else {
                    continue;
                };
                if let Some(vc) = te.value.get("change").and_then(|c| c.get("vault")) {
                    take(
                        &mut publics,
                        &mut boxes,
                        vc,
                        vc.get("previousVault"),
                        &public_of,
                    );
                }
            }
            _ => {}
        }
    }
    (publics, boxes)
}

/// One slot of the current vault, as a host shows it in a chooser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotOption {
    /// Index in the verified keyring's `slots`, for [`Account::begin_unlock_slot`].
    pub index: usize,
    /// `sealed`, `prf` or `combined`.
    pub kind: String,
    /// The slot's display label.
    pub label: String,
    /// The controllers it names: `(ID, label)`, in order.
    pub controllers: Vec<(String, String)>,
}

/// One ECDH a member's host performs to open a share: its agreement key against `peer`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochAgreement {
    /// The namespace.
    pub namespace: String,
    /// The epoch.
    pub epoch: u64,
    /// The recipient the seal is addressed to: the member's ID.
    pub recipient: String,
    /// The recipient's agreement point, which names the private key to use.
    pub recipient_point: Vec<u8>,
    /// The seal's ephemeral point: the peer of the ECDH.
    pub peer: Vec<u8>,
}

/// A host's raw ECDH result for one [`EpochAgreement`]. Opaque: it cannot be read back.
#[derive(Debug)]
pub struct EpochSecret {
    /// The step this answers.
    pub step: EpochAgreement,
    /// The raw ECDH output.
    pub shared: EcdhOutput,
}

impl Account {
    /// The slots of the current vault.
    pub fn slots(&self) -> Result<Vec<SlotOption>> {
        let k = self.d.auth.state().keyring();
        let mut out = Vec::new();
        for (index, v) in k.slots.iter().enumerate() {
            let s = Slot::from_value(v)?;
            out.push(SlotOption {
                index,
                kind: s.kind().to_string(),
                label: s.label().to_string(),
                controllers: s
                    .controllers()
                    .iter()
                    .map(|id| {
                        (
                            id.clone(),
                            k.controllers
                                .get(id)
                                .map(|c: &Controller| c.label().to_string())
                                .unwrap_or_default(),
                        )
                    })
                    .collect(),
            });
        }
        Ok(out)
    }

    /// The host work to open slot `index`: an ECDH against each sealed point, a PRF evaluation
    /// of each salt, in controller order (§7.2).
    pub fn begin_unlock_slot(&self, index: usize) -> Result<Vec<OpeningInput>> {
        let k = self.d.auth.state().keyring();
        let v = k
            .slots
            .get(index)
            .ok_or_else(|| malformed("no such slot"))?;
        Slot::from_value(v)?.begin_open(&k.controllers)
    }

    /// Finish opening slot `index` with the host's results in the same order. A wrong or missing
    /// secret is `refused:vaultLocked` and changes nothing (§7.1). On success the seed is held,
    /// the earlier vaults it reaches are opened, and every epoch key it opens is held.
    pub fn finish_unlock_slot(
        &mut self,
        index: usize,
        secrets: &[OpeningSecret],
    ) -> Result<Changes> {
        let (opened, account) = {
            let k = self.d.auth.state().keyring();
            let v = k
                .slots
                .get(index)
                .ok_or_else(|| malformed("no such slot"))?;
            let account = self.d.auth.account().clone();
            let vault = VaultPublic::from_pair(&k.vault);
            (
                Slot::from_value(v)?.finish_open(&account, &vault, &k.controllers, secrets)?,
                account,
            )
        };
        self.adopt_seed(opened, &account)
    }

    /// Hold `seed` (new or opened under this account), close the `previousVault` chain from it
    /// and open the epoch keys it reaches. Candidate first, commit after.
    pub(super) fn adopt_seed(&mut self, seed: VaultSeed, account: &AccountId) -> Result<Changes> {
        // A seed is held only if the rebuild that depends on it succeeds: on any failure the
        // ring is put back as it was.
        let before = self.seeds.len();
        let result = (|| {
            self.seeds.install(seed, account)?;
            let (publics, boxes) = vault_chain(&self.objects.entries, &self.d.verdict.branch);
            self.seeds.close_chain(account, &publics, &boxes);
            self.rebuild_in_place()
        })();
        if result.is_err() {
            self.seeds.truncate(before);
        }
        result
    }

    /// True while the current vault's seed is held.
    pub fn is_unlocked(&self) -> bool {
        let k = self.d.auth.state().keyring();
        self.seeds
            .current(&VaultPublic::from_pair(&k.vault))
            .is_some()
    }

    /// Forget the seeds (erased on drop). Epoch keys already opened stay: they are what the
    /// session reads with, as in 0.4.
    pub fn lock(&mut self) {
        self.seeds.lock();
    }

    /// The agreements a member's host performs to open the shares it does not hold yet: one per
    /// `(namespace, epoch)` of its `records` scope that a seal in the verified history is
    /// addressed to this member for.
    pub fn begin_unlock_epochs(&self) -> Vec<EpochAgreement> {
        let super::Identity::Member(me) = &self.me else {
            return Vec::new();
        };
        let auth = &self.d.auth;
        let mut out = Vec::new();
        for ns in auth.namespaces() {
            if !super::derived::readable(auth, &self.me, ns)
                || self.scope.as_ref().is_some_and(|s| !s.contains(ns))
            {
                continue;
            }
            for epoch in 1..=auth.latest_epoch(ns) {
                if self.d.keys.get(auth.account(), ns, epoch).is_some() {
                    continue;
                }
                if let Some(req) = auth.epoch_seal_request(ns, epoch, me) {
                    out.push(EpochAgreement {
                        namespace: ns.clone(),
                        epoch,
                        recipient: me.clone(),
                        recipient_point: req.recipient,
                        peer: req.enc,
                    });
                }
            }
        }
        out
    }

    /// Open shares with the host's ECDH results. Each must answer a step
    /// [`Account::begin_unlock_epochs`] offers now; a wrong result is `refused:vaultLocked`.
    /// All or none: one failure leaves every key as it was.
    pub fn finish_unlock_epochs(&mut self, results: Vec<EpochSecret>) -> Result<Changes> {
        let want = self.begin_unlock_epochs();
        let mut opened = Vec::new();
        for r in &results {
            require(
                want.contains(&r.step),
                "an answer for a share this account did not ask for",
            )?;
            opened.push(self.d.auth.open_epoch(
                &r.step.namespace,
                r.step.epoch,
                &r.step.recipient,
                &r.shared,
            )?);
        }
        let mut keys = EpochKeys::new();
        for k in opened {
            keys.insert(k)?;
        }
        self.install_keys(keys)
    }

    /// Seal the current seed to a device the person confirmed by pairing (§7.4). The pairing
    /// must be for this account. The seed is never returned, only its HPKE ciphertext to the
    /// pairing's ephemeral key.
    pub fn transfer_seed(
        &self,
        pairing: &ConfirmedPairing,
        entropy_seed: [u8; 32],
    ) -> Result<SealedBox> {
        require(
            pairing.account() == self.d.auth.account(),
            "the pairing is for another account",
        )?;
        let k = self.d.auth.state().keyring();
        let seed = self
            .seeds
            .current(&VaultPublic::from_pair(&k.vault))
            .ok_or_else(crate::v05::vault::locked)?;
        seal_seed_for_transfer(seed, pairing, &mut Entropy::new(entropy_seed))
    }

    /// The new device opens the transferred seed (§7.4), checks it against the verified
    /// keyring's vault, and holds it bound to this account.
    pub fn accept_seed_transfer(
        &mut self,
        key: &TransferKey,
        sealed: &SealedBox,
        pairing: &ConfirmedPairing,
    ) -> Result<Changes> {
        require(
            pairing.account() == self.d.auth.account(),
            "the pairing is for another account",
        )?;
        let vault = VaultPublic::from_pair(&self.d.auth.state().keyring().vault);
        let seed = key.open_seed(sealed, pairing, &vault)?;
        let account = self.d.auth.account().clone();
        self.adopt_seed(seed, &account)
    }
}
