//! Joining at an invite's head: a history read signed by a member that holds no history yet, the
//! home's history pages, and the check that accepts the fetched history (core `v05::join`).
use super::convert as cv;
use super::fault::AccountError;
use super::guard;
use super::types::*;
use super::Cell;
use colophon_core::v05::encoding::{encode_base64url, is_digest};
use colophon_core::v05::ids::AccountId;
use colophon_core::v05::join::{
    check_history_size, current_webauthn_controller, history_page_path, parse_history_page,
    passkey_points, verify_at_head, verify_with_passkey, AtHead, PasskeyController,
    MAX_ENTRY_BYTES,
};
use colophon_core::v05::write::calls::{
    finish_history_read, prepare_history_read, prepare_passkey_history_read,
    HistoryReadSpec as CoreSpec, PreparedHistoryRead,
};

type R<T> = Result<T, AccountError>;

macro_rules! free_fn {
    ($($item:item)*) => {
        $(
            #[cfg_attr(feature = "native05", uniffi::export)]
            #[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
            $item
        )*
    };
}

free_fn! {
    /// The path, relative to a home's base, of the history page after `after` entries
    /// (`/authority?after=<after>&limit=64`).
    pub fn account_history_page_path(after: u64) -> String {
        history_page_path(after)
    }
}
free_fn! {
    /// One page of `GET {base}/authority`: its entries as canonical bytes (at most 64) and
    /// whether more follow. `malformed` for anything else.
    pub fn account_history_page(body: Vec<u8>) -> Result<HistoryPage, AccountError> {
        guard(|| {
            bytes_ok(&body, MAX_BYTES, "a history page")?;
            let page = parse_history_page(&body)?;
            Ok(HistoryPage {
                entries: page.entries.into_iter().map(|bytes| ByteString { bytes }).collect(),
                more: page.more,
            })
        })
    }
}
/// The entries, moved (never copied), after the joining device's bounds (core `v05::join`): each
/// at most the authority envelope bound, together at most 2^18 entries and 256 MiB.
fn entry_bytes(entries: Vec<ByteString>) -> R<Vec<Vec<u8>>> {
    let mut total = 0usize;
    for b in &entries {
        bytes_ok(&b.bytes, MAX_ENTRY_BYTES, "an entry")?;
        total = total.saturating_add(b.bytes.len());
    }
    check_history_size(entries.len(), total)?;
    Ok(entries.into_iter().map(|b| b.bytes).collect())
}

free_fn! {
    /// Accept a fetched history at an invite's head (core `v05::join::verify_at_head`): `ok`
    /// verdict, the history of `account`, every entry on the verified branch, the branch at least
    /// `seq` long with entry `seq` of body digest `head`, `member` (the key ID that signed the reads)
    /// the member `request` names, its tip exactly `signed_head` (the body
    /// of `GET {base}/head`, a fresh head of a current home serving at `base`), and the member of
    /// `request` (the joiner's own request envelope) current and granted from exactly that
    /// request. `admitted` false (and no stores) when the history names no member with that ID.
    /// Refused: another account, an entry off the branch, another digest at `seq`
    /// (`refused:fork`); a head beyond the history served (`refused:rollback`); a revoked or
    /// provisional member (`refused:revoked`), an expired one (`refused:expired`), a grant of
    /// another request (`refused:conflict`). `unavailable`: the branch is shorter than `seq`, or
    /// the head is behind or stale (fetch again).
    pub fn account_verify_at_head(account: String, seq: u64, head: String, member: String, request: Vec<u8>, base: String, signed_head: Vec<u8>, entries: Vec<ByteString>, now_ms: i64) -> Result<JoinedHistory, AccountError> {
        guard(|| {
            let account = AccountId::parse(&account)?;
            bytes_ok(&request, 1 << 22, "a request")?;
            bytes_ok(&signed_head, 1 << 16, "a head")?;
            let entries = entry_bytes(entries)?;
            Ok(match verify_at_head(&account, seq, &head, &member, &request, &base, &signed_head, entries, now_ms)? {
                AtHead::Admitted(files) => JoinedHistory {
                    admitted: true,
                    stores: files.into_iter().map(|(path, bytes)| Store { path, bytes }).collect(),
                },
                AtHead::NotAdmitted => JoinedHistory { admitted: false, stores: vec![] },
            })
        })
    }
}
free_fn! {
    /// The descriptor (`rp`, credential, origins) of controller `id` in a verified history, when
    /// it is a current WebAuthn controller; none for a removed, provisional, suspended or raw
    /// controller or an unknown ID. The history must verify (`ok`), else its failure.
    pub fn account_current_webauthn_controller(entries: Vec<ByteString>, id: String, now_ms: i64) -> Result<Option<KeyDescriptorView>, AccountError> {
        guard(|| {
            let entries = entry_bytes(entries)?;
            Ok(current_webauthn_controller(entries, &id, now_ms)?.as_ref().map(cv::descriptor_view))
        })
    }
}

free_fn! {
    /// The signing points a passkey assertion over `body` could have been made by, for `rp`
    /// (core `v05::join::passkey_points`): the assertion must pass §4.3 steps 1 to 3 for `rp`
    /// (`webauthn.get`, the challenge of `body`, the relying-party hash, UP) and step 5's DER
    /// grammar, else `badSignature`. With `key_id`, exactly the one point with that key ID (an
    /// invite names the owner's passkey by key ID), else `badSignature`. A discoverable get
    /// returns no public key: a device learns the passkey's point this way before it signs a call
    /// naming it. A point is only a candidate until a verified history names it.
    pub fn account_passkey_points(body: Vec<u8>, rp: String, authenticator_data: Vec<u8>, client_data: Vec<u8>, signature: Vec<u8>, key_id: Option<String>) -> Result<Vec<ByteString>, AccountError> {
        guard(|| {
            bytes_ok(&body, 4_096, "a challenge body")?;
            bytes_ok(rp.as_bytes(), 253, "an rp")?;
            bytes_ok(&authenticator_data, 1 << 16, "authenticator data")?;
            bytes_ok(&client_data, 1 << 16, "client data")?;
            bytes_ok(&signature, 80, "a DER signature")?;
            Ok(passkey_points(&body, &rp, &authenticator_data, &client_data, &signature, key_id.as_deref())?
                .into_iter()
                .map(|bytes| ByteString { bytes })
                .collect())
        })
    }
}
fn passkey_view(c: &PasskeyController) -> PasskeyControllerView {
    PasskeyControllerView {
        id: c.id.clone(),
        label: c.label.clone(),
        roles: c.roles.iter().map(|r| cv::controller_role(r)).collect(),
        roles_raw: c.roles.clone(),
        key: cv::descriptor_view(&c.key),
        verification: c.verification,
        own_slot: c.own_slot,
    }
}
free_fn! {
    /// Accept a history a device that is not a member yet read with a passkey's
    /// `colophon.history.read` calls (core `v05::join::verify_with_passkey`, 0.5.7): every check of
    /// `account_verify_at_head` up to the home's fresh signed head at `base`, at `(seq, head)`
    /// (an invite's head, or `(1, account)`: the genesis), then the signer, a current WebAuthn
    /// controller at the tip whose signing point is `signing` (else `refused:revoked`). Returns
    /// the entries to store, the signer and every current WebAuthn controller.
    pub fn account_verify_with_passkey(account: String, seq: u64, head: String, signing: Vec<u8>, base: String, signed_head: Vec<u8>, entries: Vec<ByteString>, now_ms: i64) -> Result<PasskeyHistoryView, AccountError> {
        guard(|| {
            let account = AccountId::parse(&account)?;
            bytes_ok(&signing, 65, "a point")?;
            bytes_ok(&signed_head, 1 << 16, "a head")?;
            let entries = entry_bytes(entries)?;
            let h = verify_with_passkey(&account, seq, &head, &signing, &base, &signed_head, entries, now_ms)?;
            Ok(PasskeyHistoryView {
                stores: h.files.into_iter().map(|(path, bytes)| Store { path, bytes }).collect(),
                signer: passkey_view(&h.signer),
                controllers: h.controllers.iter().map(passkey_view).collect(),
            })
        })
    }
}

/// A `colophon.history.read` call being prepared and signed by a member that holds no history:
/// one `GET` at a home path that serves the history, `asOf` the entry the device was given.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountHistoryRead {
    p: Cell<Option<PreparedHistoryRead>>,
}
impl AccountHistoryRead {
    fn prepare_inner(spec: HistoryReadSpec, passkey: bool) -> R<Self> {
        guard(|| {
            let account = AccountId::parse(&spec.account)?;
            bytes_ok(&spec.signing, 65, "a point")?;
            if !is_digest(&spec.as_of_digest) {
                return Err(AccountError::bad("asOf.digest must be 64 lowercase hex"));
            }
            bytes_ok(spec.audience.as_bytes(), 4_096, "the audience")?;
            let request_id = fixed::<32>(&spec.request_id, "a request ID")?;
            let core = CoreSpec {
                account: &account,
                as_of: (spec.as_of_seq, &spec.as_of_digest),
                signing: &spec.signing,
                audience: &spec.audience,
                path: &spec.path,
                request_id,
                created: &spec.created,
            };
            let prepared = if passkey {
                prepare_passkey_history_read(&core)?
            } else {
                prepare_history_read(&core)?
            };
            Ok(Self {
                p: Cell::new(Some(prepared)),
            })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountHistoryRead {
    /// The one step to sign: raw by the member key, or, for a passkey read, a WebAuthn get over
    /// its `challenge` by the passkey.
    pub fn step(&self) -> Result<AccountSigningStep, AccountError> {
        guard(|| {
            let g = self.p.lock()?;
            let p = g
                .as_ref()
                .ok_or_else(|| AccountError::consumed("this call is finished"))?;
            Ok(cv::step(p.step()))
        })
    }
    /// Finish with the signature (the member's raw signature, or the passkey's DER signature with
    /// its assertion): the envelope (parsed, possession checked), the URL it is bound to and the
    /// `Authorization` header value (`Colophon <base64url envelope>`).
    pub fn finish(&self, signature: Signature) -> Result<HistoryReadCall, AccountError> {
        guard(|| {
            let [sig] =
                <[colophon_core::v05::write::SignatureResult; 1]>::try_from(cv::signatures(vec![
                    signature,
                ])?)
                .map_err(|_| AccountError::bad("a call has exactly one signature"))?;
            let p = self
                .p
                .lock()?
                .take()
                .ok_or_else(|| AccountError::consumed("this call is finished"))?;
            let envelope = finish_history_read(&p, &sig)?;
            Ok(HistoryReadCall {
                url: p.url().to_string(),
                authorization: format!("Colophon {}", encode_base64url(&envelope)),
                envelope,
            })
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountHistoryRead {
    /// Prepare a history read.
    #[uniffi::constructor]
    pub fn prepare(spec: HistoryReadSpec) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::prepare_inner(spec, false).map(std::sync::Arc::new)
    }
    /// Prepare a history read signed by a WebAuthn controller (0.5.7): `spec.signing` is the
    /// passkey's point, the signer is that controller, and the step asks for an assertion. With
    /// no entry given, `asOf` is `(1, account)`.
    #[uniffi::constructor]
    pub fn prepare_passkey(spec: HistoryReadSpec) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::prepare_inner(spec, true).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountHistoryRead {
    /// Prepare a history read.
    pub fn prepare(spec: HistoryReadSpec) -> Result<AccountHistoryRead, AccountError> {
        Self::prepare_inner(spec, false)
    }
    /// Prepare a history read signed by a WebAuthn controller (0.5.7).
    pub fn prepare_passkey(spec: HistoryReadSpec) -> Result<AccountHistoryRead, AccountError> {
        Self::prepare_inner(spec, true)
    }
}
