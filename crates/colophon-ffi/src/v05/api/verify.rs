//! Standalone checks that need no account and no identity, and the member's side of a request.
use super::fault::AccountError;
use super::json::*;
use super::{guard, lock};
use colophon_core::v05::account::{finish_request, prepare_request, request_info};
use colophon_core::v05::descriptor::KeyDescriptor;
use colophon_core::v05::encoding::{encode_base64, strict_parse};
use colophon_core::v05::history::{swift, verify_history, Persisted};
use colophon_core::v05::ids::{key_id, AccountId};
use colophon_core::v05::signature::{
    webauthn_check, AssertionBytes, AuthorityRule, CheckMode,
};
use colophon_core::v05::slots::webauthn_prf_input;
use colophon_core::v05::vault::VaultSeed;
use colophon_core::v05::write::calls::{PreparedRequest, RequestSpec};
use colophon_core::v05::write::{format_date, SignatureResult};
use serde_json::{json, Value};
use std::sync::Mutex;

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
    /// The history verifier, with no identity: from the authority objects
    /// (`{"entries","pending","heads","predecessor"}`, base64 arrays) and the clock, the §1
    /// result code, the verified branch, why it stopped, the account ID and the conflicts it
    /// decided. It needs and keeps no state.
    pub fn account_verify_history(objects: String, now_ms: i64) -> Result<String, AccountError> {
        guard(|| {
            let o = super::account::objects(&objects)?;
            if o.entries.len() > super::json::MAX_LIST {
                return Err(AccountError::bound("too many entries"));
            }
            let v = verify_history(&o, &Persisted::default(), now_ms);
            let (stop_seq, detail) = {
                let s = colophon_core::v05::account::Status {
                    seq: v.branch.len() as u64,
                    code: v.code(),
                    stop_seq: None,
                    detail: None,
                    rollback: v.rollback,
                };
                let _ = s;
                (v.seq(), match &v.stop {
                    Some(colophon_core::v05::history::Stop::Failed { failure, .. }) => Some(failure.detail().to_string()),
                    Some(colophon_core::v05::history::Stop::Held { why, .. }) => Some(why.clone()),
                    _ => None,
                })
            };
            to_string(&json!({
                "code": v.code(),
                "seq": stop_seq,
                "detail": detail,
                "rollback": v.rollback,
                "account": v.state.as_ref().map(|s| s.account().as_str().to_string()),
                "branch": v.branch,
                "conflicts": v.conflicts.iter().map(|(s, d, l)| json!({"seq": s, "standing": d, "losing": l})).collect::<Vec<_>>(),
                "heldUntil": v.held_until,
            }))
        })
    }
}
free_fn! {
    /// The standalone WebAuthn check (§17.2): `{"ok":true,"uv","origin","counter"}`, or
    /// `BadSignature` whose detail names the failed check. `descriptor` is the protocol JSON of
    /// the key; `mode` is `{"mode":"authority","rule":"control"|"recovery"|"keyringEntry"|
    /// "transition"|"veto"|"handover"|"single"|"suspend"|"possession","verification":bool,
    /// "signController":bool}`, `{"mode":"call","origins":[..],"uvRequired":bool}` or
    /// `{"mode":"swiftPredecessor","uvRequired":bool}`.
    pub fn account_webauthn_check(
        descriptor: String,
        body: Vec<u8>,
        der_signature: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data: Vec<u8>,
        mode: String,
    ) -> Result<String, AccountError> {
        guard(|| {
            for (b, n) in [(&body, "body"), (&der_signature, "signature"), (&authenticator_data, "authenticatorData"), (&client_data, "clientData")] {
                bounded(b, MAX_BYTES, n)?;
            }
            let d = KeyDescriptor::parse(parse(&descriptor, "descriptor")?, "descriptor")?;
            let m = parse(&mode, "mode")?;
            let origins: Vec<String>;
            let cm = match text(&m, "mode")? {
                "authority" => CheckMode::Authority {
                    rule: match text(&m, "rule")? {
                        "control" => AuthorityRule::Control,
                        "recovery" => AuthorityRule::Recovery,
                        "keyringEntry" => AuthorityRule::KeyringEntry,
                        "transition" => AuthorityRule::Transition,
                        "veto" => AuthorityRule::Veto,
                        "handover" => AuthorityRule::Handover,
                        "single" => AuthorityRule::Single,
                        "suspend" => AuthorityRule::Suspend,
                        "possession" => AuthorityRule::Possession,
                        _ => return Err(AccountError::bad("unknown rule")),
                    },
                    verification: boolean(&m, "verification", false)?,
                    sign_controller: boolean(&m, "signController", false)?,
                },
                "call" => {
                    origins = names(&m, "origins")?;
                    CheckMode::Call { origins: &origins, uv_required: boolean(&m, "uvRequired", false)? }
                }
                "swiftPredecessor" => CheckMode::SwiftPredecessor { uv_required: boolean(&m, "uvRequired", false)? },
                _ => return Err(AccountError::bad("unknown mode")),
            };
            match webauthn_check(&d, &body, &der_signature,
                AssertionBytes { authenticator_data: &authenticator_data, client_data: &client_data }, cm) {
                Ok(ok) => to_string(&json!({"ok": true, "uv": ok.uv, "origin": ok.origin, "counter": ok.counter})),
                Err(f) => Err(AccountError::BadSignature { code: "badSignature".into(), detail: format!("{f:?}") }),
            }
        })
    }
}
free_fn! {
    /// The pure Swift predecessor verifier (§16.3): the account, and each verified entry's
    /// `seq`, body digest and `issued`. Entries are base64 envelopes, any order.
    pub fn account_verify_swift_predecessor(entries: String) -> Result<String, AccountError> {
        guard(|| {
            let e = b64_array(&parse(&entries, "entries")?, "entries")?;
            let h = swift::verify(&e)?;
            to_string(&json!({"account": h.account, "entries": h.entries.iter().map(|r| json!({
                "seq": r.value.get("seq"), "digest": r.digest, "issuedMs": r.issued_ms,
                "layout": r.value.get("layout")})).collect::<Vec<_>>()}))
        })
    }
}
free_fn! {
    /// A key ID from an uncompressed P-256 point (32 hex).
    pub fn account_key_id(signing: Vec<u8>) -> Result<String, AccountError> {
        guard(|| {
            bounded(&signing, 65, "a signing point")?;
            Ok(key_id(&signing))
        })
    }
}
free_fn! {
    /// `SHA-256("WebAuthn PRF" || 0 || salt)`: the input a CTAP hmac-secret host applies.
    pub fn account_webauthn_prf_input(salt: Vec<u8>) -> Result<Vec<u8>, AccountError> {
        guard(|| {
            bounded(&salt, 1024, "a salt")?;
            Ok(webauthn_prf_input(&salt).to_vec())
        })
    }
}
free_fn! {
    /// The public part of the vault a host-chosen seed names: `{"signing","agreement","id"}`.
    /// The seed is read and dropped; only public values return.
    pub fn account_vault_public(mut seed: Vec<u8>) -> Result<String, AccountError> {
        let r = guard(|| {
            let s = VaultSeed::from_host_random(fixed::<32>(&seed, "seed")?);
            let p = s.public()?;
            let v = p.to_value();
            to_string(&json!({"signing": v["signing"], "agreement": v["agreement"], "id": p.id()}))
        });
        seed.fill(0);
        r
    }
}
free_fn! {
    /// The §2.2 date text of a millisecond time.
    pub fn account_format_date(ms: i64) -> Result<String, AccountError> {
        guard(|| {
            colophon_core::v05::write::check_issued(ms)?;
            Ok(format_date(ms))
        })
    }
}
free_fn! {
    /// Parse a request envelope as an approver sees it: `{"raw","member","label","kind","terms"}`.
    pub fn account_request_info(raw: Vec<u8>) -> Result<String, AccountError> {
        guard(|| {
            bounded(&raw, 1 << 22, "a request")?;
            let r = request_info(&raw)?;
            to_string(&json!({"raw": encode_base64(&r.raw), "member": r.member, "label": r.label,
                "kind": r.kind, "terms": r.terms}))
        })
    }
}

/// A member's request being prepared and signed (§9.1): public values only, no account needed.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountRequest {
    p: Mutex<Option<PreparedRequest>>,
}
impl AccountRequest {
    fn prepare_inner(spec: String) -> R<Self> {
        guard(|| {
            let v = parse(&spec, "the request")?;
            let account = AccountId::parse(text(&v, "account")?)?;
            let signing = b64(&v, "signing")?;
            let agreement = b64(&v, "agreement")?;
            let custody = opt_text(&v, "custody")?;
            let operator = opt_text(&v, "operator")?;
            let endpoints = match v.get("endpoints") {
                None | Some(Value::Null) => None,
                Some(_) => Some(names(&v, "endpoints")?),
            };
            let prepared = prepare_request(&RequestSpec {
                account: &account,
                signing: &signing,
                agreement: &agreement,
                label: text(&v, "label")?,
                kind: text(&v, "kind")?,
                terms: v.get("terms").cloned().unwrap_or(Value::Null),
                created: text(&v, "created")?,
                custody,
                operator,
                endpoints,
            })?;
            Ok(Self {
                p: Mutex::new(Some(prepared)),
            })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountRequest {
    /// The one step the member signs (stored at `requests/<member>.json`).
    pub fn step(&self) -> Result<String, AccountError> {
        guard(|| {
            let g = lock(&self.p)?;
            let p = g
                .as_ref()
                .ok_or_else(|| AccountError::consumed("this request is finished"))?;
            to_string(&super::action::step_json(p.step()))
        })
    }
    /// Finish with the member's signature (`[{"signature"}]`): the verified request, as for
    /// `account_request_info`.
    pub fn finish(&self, signature: String) -> Result<String, AccountError> {
        guard(|| {
            let sigs = super::action::signatures(&signature)?;
            let [sig]: [SignatureResult; 1] = sigs
                .try_into()
                .map_err(|_| AccountError::bad("a request has exactly one signature"))?;
            let p = lock(&self.p)?
                .take()
                .ok_or_else(|| AccountError::consumed("this request is finished"))?;
            let r = finish_request(&p, &sig)?;
            let _ = strict_parse;
            to_string(&json!({"raw": encode_base64(&r.raw), "member": r.member, "label": r.label,
                "kind": r.kind, "terms": r.terms}))
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountRequest {
    /// Prepare a request. `spec` is JSON: `account`, `signing` and `agreement` (base64 points),
    /// `label`, `kind`, `terms`, `created` (a §2.2 date), optional `custody`, `operator`,
    /// `endpoints`.
    #[uniffi::constructor]
    pub fn prepare(spec: String) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::prepare_inner(spec).map(std::sync::Arc::new)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountRequest {
    pub fn prepare(spec: String) -> Result<AccountRequest, AccountError> {
        Self::prepare_inner(spec)
    }
}
