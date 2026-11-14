//! Standalone checks that need no account and no identity, and the member's side of a request.
use super::convert as cv;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::account::{finish_request, prepare_request, request_info};
use colophon_core::v05::history::{swift, verify_history, Persisted, Stop};
use colophon_core::v05::ids::{key_id, AccountId};
use colophon_core::v05::signature::{
    webauthn_check, AssertionBytes, AuthorityRule, CheckMode, SigFailure,
};
use colophon_core::v05::slots::webauthn_prf_input;
use colophon_core::v05::vault::VaultSeed;
use colophon_core::v05::write::calls::{PreparedRequest, RequestSpec as CoreRequest};
use colophon_core::v05::write::format_date;

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

fn blobs(v: Vec<ByteString>, what: &str) -> R<Vec<Vec<u8>>> {
    list_len(&v, what)?;
    v.into_iter()
        .map(|b| {
            bytes_ok(&b.bytes, MAX_BYTES, what)?;
            Ok(b.bytes)
        })
        .collect()
}
/// The stable name of the §4.3 check that failed (the order of the spec's steps).
fn check_name(f: SigFailure) -> &'static str {
    match f {
        SigFailure::Point => "point",
        SigFailure::RawLength => "rawLength",
        SigFailure::Scalar => "scalar",
        SigFailure::Der => "der",
        SigFailure::Verify => "verify",
        SigFailure::ClientData => "clientData",
        SigFailure::ClientDataBound => "clientDataBound",
        SigFailure::UnknownForm => "unknownForm",
        SigFailure::Type => "type",
        SigFailure::Challenge => "challenge",
        SigFailure::Origin => "origin",
        SigFailure::CrossOrigin => "crossOrigin",
        SigFailure::RelyingParty => "relyingParty",
        SigFailure::UserPresence => "userPresence",
        SigFailure::UserVerification => "userVerification",
        SigFailure::Form => "form",
        SigFailure::CallOrigin => "callOrigin",
    }
}
fn request_info_of(r: colophon_core::v05::account::AccessRequest) -> RequestInfo {
    RequestInfo {
        kind: cv::member_kind_from(&r.kind),
        raw: r.raw,
        member: r.member,
        label: r.label,
        terms_json: r.terms.to_string(),
    }
}

free_fn! {
    /// The history verifier, with no identity: from the authority objects and the clock, the §1
    /// result code, the verified branch, why it stopped, the account ID and the conflicts it
    /// decided. It needs and keeps no state.
    pub fn account_verify_history(objects: AuthorityObjects, now_ms: i64) -> Result<HistoryReport, AccountError> {
        guard(|| {
            let o = cv::authority_objects(objects)?;
            let v = verify_history(&o, &Persisted::default(), now_ms);
            let detail = match &v.stop {
                Some(Stop::Failed { failure, .. }) => Some(failure.detail().to_string()),
                Some(Stop::Held { why, .. }) => Some(why.clone()),
                _ => None,
            };
            let code = v.code();
            let (kind, reason) = cv::status_parts(&code);
            Ok(HistoryReport {
                code,
                kind,
                reason,
                seq: v.seq(),
                detail,
                rollback: v.rollback,
                account: v.state.as_ref().map(|s| s.account().as_str().to_string()),
                branch: v.branch.clone(),
                conflicts: v
                    .conflicts
                    .iter()
                    .map(|(seq, standing, losing)| Conflict {
                        seq: *seq,
                        standing: standing.clone(),
                        losing: losing.clone(),
                    })
                    .collect(),
                held_until_ms: v.held_until,
            })
        })
    }
}
free_fn! {
    /// The standalone WebAuthn check (§17.2): the verified assertion, or `BadSignature` whose
    /// `code` is `badSignature:<check>` with the failed check named in the order of §4.3
    /// (`point rawLength scalar der verify clientData clientDataBound unknownForm type challenge
    /// origin crossOrigin relyingParty userPresence userVerification form callOrigin`).
    pub fn account_webauthn_check(
        descriptor: KeyDescriptorView,
        body: Vec<u8>,
        der_signature: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data: Vec<u8>,
        mode: WebauthnMode,
    ) -> Result<WebauthnOk, AccountError> {
        guard(|| {
            for (b, n) in [(&body, "body"), (&der_signature, "signature"), (&authenticator_data, "authenticator data"), (&client_data, "client data")] {
                bytes_ok(b, MAX_BYTES, n)?;
            }
            names(mode.origins.clone(), "origins")?;
            let d = cv::descriptor_from_view(&descriptor)?;
            let cm = match mode.kind {
                CheckKind::Authority => CheckMode::Authority {
                    rule: match mode.rule {
                        AuthorityRuleKind::Control => AuthorityRule::Control,
                        AuthorityRuleKind::Recovery => AuthorityRule::Recovery,
                        AuthorityRuleKind::KeyringEntry => AuthorityRule::KeyringEntry,
                        AuthorityRuleKind::Transition => AuthorityRule::Transition,
                        AuthorityRuleKind::Veto => AuthorityRule::Veto,
                        AuthorityRuleKind::Handover => AuthorityRule::Handover,
                        AuthorityRuleKind::Single => AuthorityRule::Single,
                        AuthorityRuleKind::Suspend => AuthorityRule::Suspend,
                        AuthorityRuleKind::Possession => AuthorityRule::Possession,
                    },
                    verification: mode.verification,
                    sign_controller: mode.sign_controller,
                },
                CheckKind::Call => CheckMode::Call { origins: &mode.origins, uv_required: mode.uv_required },
                CheckKind::SwiftPredecessor => CheckMode::SwiftPredecessor { uv_required: mode.uv_required },
            };
            match webauthn_check(&d, &body, &der_signature,
                AssertionBytes { authenticator_data: &authenticator_data, client_data: &client_data }, cm) {
                Ok(ok) => Ok(WebauthnOk { uv: ok.uv, origin: ok.origin, counter: ok.counter }),
                Err(f) => Err(AccountError::BadSignature {
                    code: format!("badSignature:{}", check_name(f)),
                    detail: check_name(f).into(),
                }),
            }
        })
    }
}
free_fn! {
    /// The pure Swift predecessor verifier (§16.3): the account, and each verified entry.
    pub fn account_verify_swift_predecessor(entries: Vec<ByteString>) -> Result<SwiftPredecessor, AccountError> {
        guard(|| {
            let e = blobs(entries, "an entry")?;
            let h = swift::verify(&e)?;
            Ok(SwiftPredecessor {
                account: h.account.clone(),
                entries: h.entries.iter().map(|r| SwiftEntry {
                    seq: r.value.get("seq").and_then(serde_json::Value::as_u64),
                    digest: r.digest.clone(),
                    issued_ms: r.issued_ms,
                    layout: r.value.get("layout").and_then(serde_json::Value::as_u64),
                }).collect(),
            })
        })
    }
}
free_fn! {
    /// A key ID from an uncompressed P-256 point (32 hex).
    pub fn account_key_id(signing: Vec<u8>) -> Result<String, AccountError> {
        guard(|| {
            bytes_ok(&signing, 65, "a signing point")?;
            Ok(key_id(&signing))
        })
    }
}
free_fn! {
    /// `SHA-256("WebAuthn PRF" || 0 || salt)`: the input a CTAP hmac-secret host applies.
    pub fn account_webauthn_prf_input(salt: Vec<u8>) -> Result<Vec<u8>, AccountError> {
        guard(|| {
            bytes_ok(&salt, 1024, "a salt")?;
            Ok(webauthn_prf_input(&salt).to_vec())
        })
    }
}
free_fn! {
    /// The public points of the vault a host-chosen seed names (`signing`, `agreement`) as a
    /// descriptor view, and its ID in `account_vault_id`. The seed is read, wiped and dropped.
    pub fn account_vault_public(seed: Vec<u8>) -> Result<KeyDescriptorView, AccountError> {
        let mut seed = seed;
        let r = guard(|| {
            let s = VaultSeed::from_host_random(fixed::<32>(&seed, "seed")?);
            let p = s.public()?;
            let v = p.to_value();
            let dec = |k: &str| -> R<Vec<u8>> {
                Ok(colophon_core::v05::encoding::decode_base64(
                    v[k].as_str().unwrap_or_default(), 128)?)
            };
            Ok(KeyDescriptorView {
                form: SignForm::Raw,
                signing: dec("signing")?,
                agreement: Some(dec("agreement")?),
                rp: None,
                credential: None,
                origins: vec![],
                authority_origins: vec![],
            })
        });
        wipe(&mut seed);
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
    /// Parse a request envelope as an approver sees it.
    pub fn account_request_info(raw: Vec<u8>) -> Result<RequestInfo, AccountError> {
        guard(|| {
            bytes_ok(&raw, 1 << 22, "a request")?;
            Ok(request_info_of(request_info(&raw)?))
        })
    }
}

/// A member's request being prepared and signed (§9.1): public values only, no account needed.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountRequest {
    p: Cell<Option<PreparedRequest>>,
}
impl AccountRequest {
    fn prepare_inner(spec: RequestSpec) -> R<Self> {
        guard(|| {
            let account = AccountId::parse(&spec.account)?;
            bytes_ok(&spec.signing, 65, "a point")?;
            bytes_ok(&spec.agreement, 65, "a point")?;
            let terms = json(&spec.terms_json, "terms")?;
            let endpoints = (!spec.endpoints.is_empty()).then(|| spec.endpoints.clone());
            names(spec.endpoints.clone(), "endpoints")?;
            let prepared = prepare_request(&CoreRequest {
                account: &account,
                signing: &spec.signing,
                agreement: &spec.agreement,
                label: &spec.label,
                kind: cv::member_kind_of(spec.kind),
                terms,
                created: &spec.created,
                custody: (!spec.custody.is_empty()).then_some(spec.custody.as_str()),
                operator: (!spec.operator.is_empty()).then_some(spec.operator.as_str()),
                endpoints,
            })?;
            Ok(Self {
                p: Cell::new(Some(prepared)),
            })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountRequest {
    /// The one step the member signs (stored at `requests/<member>.json`).
    pub fn step(&self) -> Result<AccountSigningStep, AccountError> {
        guard(|| {
            let g = self.p.lock()?;
            let p = g
                .as_ref()
                .ok_or_else(|| AccountError::consumed("this request is finished"))?;
            Ok(cv::step(p.step()))
        })
    }
    /// Finish with the member's signature: the verified request.
    pub fn finish(&self, signature: Signature) -> Result<RequestInfo, AccountError> {
        guard(|| {
            let [sig] =
                <[colophon_core::v05::write::SignatureResult; 1]>::try_from(cv::signatures(vec![
                    signature,
                ])?)
                .map_err(|_| AccountError::bad("a request has exactly one signature"))?;
            let p = self
                .p
                .lock()?
                .take()
                .ok_or_else(|| AccountError::consumed("this request is finished"))?;
            Ok(request_info_of(finish_request(&p, &sig)?))
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountRequest {
    /// Prepare a request.
    #[uniffi::constructor]
    pub fn prepare(spec: RequestSpec) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::prepare_inner(spec).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountRequest {
    /// Prepare a request.
    pub fn prepare(spec: RequestSpec) -> Result<AccountRequest, AccountError> {
        Self::prepare_inner(spec)
    }
}
