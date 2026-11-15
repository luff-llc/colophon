//! `AccountEngine`: the session an app runs. It holds the core's engine (which holds the
//! account), reads the host's record source, and exposes reads, writes, live state, blobs,
//! imports, checkpoints and the exchange with a home as typed values the host performs.
//!
//! `record_due`, `set_read_scope`, `lock`, `accept_seed_transfer`, `accept_predecessor_entry`
//! and the artifact of a link or call are forwards of the core's engine (see `session.rs`); a
//! session is one object.
use super::action::{next_owner, AccountAction};
use super::convert as cv;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell, HostFault, HostSource, Source, Versions};
use colophon_core::blobs::{BlobRead, BlobWriter};
use colophon_core::model::Outcome;
use colophon_core::v05::account::RevokeKeep as CoreKeep;
use colophon_core::v05::account::{
    Account, AddController, AddMode as CoreAdd, Change, KeyringEdit,
};
use colophon_core::v05::engine::blobs::BlobAvailability as CoreAvail;
use colophon_core::v05::engine::exchange::{Fault, Method, Report as CoreReport, Response, Step};
use colophon_core::v05::engine::live::PendingLive;
use colophon_core::v05::engine::{Engine, EngineOptions, OpenMode as CoreOpen, Saved};
use colophon_core::v05::live::LiveVerdict as CoreLive;
use colophon_core::v05::records::{HeldRecord, Level};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type R<T> = Result<T, AccountError>;

const DEFAULT_BATCH: u64 = 16_384;

/// The account engine over a host record source.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountEngine {
    eng: Cell<Engine<Source>>,
    pub(crate) owner: u64,
    versions: Versions,
    fault: HostFault,
}

/// The 32-byte seeds cut from a call's entropy: held in one exact-size heap block that is
/// overwritten with zeros when this value drops, on every path (a refusal included).
pub(crate) struct Seeds(Vec<[u8; 32]>);
impl std::ops::Index<usize> for Seeds {
    type Output = [u8; 32];
    fn index(&self, i: usize) -> &[u8; 32] {
        &self.0[i]
    }
}
impl Drop for Seeds {
    fn drop(&mut self) {
        for s in &mut self.0 {
            wipe(s);
        }
    }
}
pub(crate) fn seeds32(entropy: &[u8], n: usize) -> R<Seeds> {
    if entropy.len() != 32 * n {
        return Err(AccountError::bound(&format!(
            "this call takes {} bytes of fresh entropy",
            32 * n
        )));
    }
    let mut out = Seeds(Vec::with_capacity(n));
    for c in entropy.chunks(32) {
        out.0.push(fixed::<32>(c, "entropy")?);
    }
    Ok(out)
}
/// A list of typed controllers as protocol JSON (at most 64: §6.2).
fn controller_values(v: &[ControllerSpec]) -> R<Vec<Value>> {
    if v.len() > 64 {
        return Err(AccountError::bound("a keyring has at most 64 controllers"));
    }
    v.iter().map(cv::controller_value).collect()
}
fn no_entropy(entropy: &[u8]) -> R<()> {
    if entropy.is_empty() {
        Ok(())
    } else {
        Err(AccountError::bound("this call takes no entropy"))
    }
}
fn method(m: Method) -> HttpMethod {
    match m {
        Method::Get => HttpMethod::Get,
        Method::Post => HttpMethod::Post,
        Method::Put => HttpMethod::Put,
    }
}
pub(crate) fn fault_of(f: &Fault) -> ExchangeFault {
    let mut o = ExchangeFault {
        kind: ExchangeFaultKind::Status,
        home: String::new(),
        path: None,
        feed: None,
        code: None,
        what: None,
        why: None,
        purpose: None,
        audience: None,
        endpoints: vec![],
        status: None,
    };
    match f {
        Fault::Rollback { home } => (o.kind, o.home) = (ExchangeFaultKind::Rollback, home.clone()),
        Fault::Fork { home } => (o.kind, o.home) = (ExchangeFaultKind::Fork, home.clone()),
        Fault::BadObject { home, code } => {
            (o.kind, o.home, o.code) = (
                ExchangeFaultKind::BadObject,
                home.clone(),
                Some(code.clone()),
            )
        }
        Fault::ForeignAccount { home } => {
            (o.kind, o.home) = (ExchangeFaultKind::ForeignAccount, home.clone())
        }
        Fault::NoProgress { home, feed } => {
            (o.kind, o.home, o.feed) = (
                ExchangeFaultKind::NoProgress,
                home.clone(),
                Some(feed.clone()),
            )
        }
        Fault::Mismatch { home, path } => {
            (o.kind, o.home, o.path) = (
                ExchangeFaultKind::Mismatch,
                home.clone(),
                Some(path.clone()),
            )
        }
        Fault::Refused { home, what, code } => {
            o.kind = ExchangeFaultKind::Refused;
            o.home = home.clone();
            o.what = Some(what.clone());
            o.code = Some(code.clone());
        }
        Fault::Conflict { home, path } => {
            (o.kind, o.home, o.path) = (
                ExchangeFaultKind::Conflict,
                home.clone(),
                Some(path.clone()),
            )
        }
        Fault::Race { home, path } => {
            (o.kind, o.home, o.path) = (ExchangeFaultKind::Race, home.clone(), Some(path.clone()))
        }
        Fault::Unauthorized {
            home,
            purpose,
            audience,
        } => {
            o.kind = ExchangeFaultKind::Unauthorized;
            o.home = home.clone();
            o.purpose = Some(purpose.clone());
            o.audience = Some(audience.clone());
        }
        Fault::Redirect { home, endpoints } => {
            o.kind = ExchangeFaultKind::Redirect;
            o.home = home.clone();
            o.endpoints = endpoints.clone();
        }
        Fault::Malformed { home, why } => {
            (o.kind, o.home, o.why) = (
                ExchangeFaultKind::Malformed,
                home.clone(),
                Some(why.clone()),
            )
        }
        Fault::CursorReset { home } => {
            (o.kind, o.home) = (ExchangeFaultKind::CursorReset, home.clone())
        }
        Fault::More { home, feed } => {
            (o.kind, o.home, o.feed) = (ExchangeFaultKind::More, home.clone(), Some(feed.clone()))
        }
        Fault::HeadAhead { home } => {
            (o.kind, o.home) = (ExchangeFaultKind::HeadAhead, home.clone())
        }
        Fault::Status { home, status } => {
            (o.kind, o.home, o.status) = (
                ExchangeFaultKind::Status,
                home.clone(),
                Some(u32::from(*status)),
            )
        }
    }
    o
}
fn report(r: &CoreReport) -> Report {
    Report {
        store: cv::store_list(&r.store),
        changes: cv::changes(&r.changes),
        faults: r.faults.iter().map(fault_of).collect(),
    }
}
fn headers(h: &[(String, String)]) -> Vec<Header> {
    h.iter()
        .map(|(n, v)| Header {
            name: n.clone(),
            value: v.clone(),
        })
        .collect()
}
fn blob_bytes(r: BlobRead) -> R<Vec<u8>> {
    match r {
        BlobRead::Available(b) => Ok(b),
        BlobRead::Missing => Err(AccountError::Unavailable {
            code: "unavailable".into(),
            detail: "the blob is not held here".into(),
        }),
        BlobRead::Inaccessible(d) => Err(AccountError::denied("notReadable", &d)),
        BlobRead::Invalid(d) => Err(AccountError::Malformed {
            code: "malformed".into(),
            detail: d,
        }),
    }
}
macro_rules! outcome_json {
    ($o:expr) => {
        serde_json::to_string(&$o)
            .map_err(|_| AccountError::internal("a result could not be written"))
    };
}
macro_rules! write_json {
    ($o:expr) => {
        serde_json::to_string(&$o)
            .map_err(|_| AccountError::internal("a result could not be written"))
    };
}

pub(crate) enum Prepared {
    Action(colophon_core::v05::account::PendingAction),
    Denied(colophon_core::model::Denial),
}
fn done(p: colophon_core::v05::Result<colophon_core::v05::account::PendingAction>) -> R<Prepared> {
    Ok(Prepared::Action(p?))
}
pub(crate) fn identity_of(i: &AccountIdentity) -> R<colophon_core::v05::account::Identity> {
    use colophon_core::v05::account::Identity;
    if i.id.len() != 32
        || !i
            .id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AccountError::bad("an identity names a 32-hex key ID"));
    }
    Ok(match i.kind {
        AccountIdentityKind::Controller => Identity::Controller(i.id.clone()),
        AccountIdentityKind::Member => Identity::Member(i.id.clone()),
    })
}
fn saved_in(s: SavedState) -> R<Option<Saved>> {
    if s.verifier.is_empty() && s.checkpoint.is_empty() {
        return Ok(None);
    }
    list_len(&s.parts, "saved parts")?;
    if s.parts.len() > MAX_NAMES {
        return Err(AccountError::bound("too many saved parts"));
    }
    Ok(Some(Saved {
        verifier: s.verifier,
        checkpoint: s.checkpoint,
        parts: s
            .parts
            .into_iter()
            .map(|p| (p.namespace, p.bytes))
            .collect(),
    }))
}

impl AccountEngine {
    /// Run a call over the locked engine. A host callback that failed during the call and left
    /// the call unable to finish is reported as `Host` with the host's message; an engine that
    /// has become unusable is reported as `Integrity`.
    pub(crate) fn run<T>(&self, f: impl FnOnce(&mut Engine<Source>) -> R<T>) -> R<T> {
        guard(|| {
            if let Ok(mut h) = self.fault.lock() {
                *h = None;
            }
            let mut g = self.eng.lock()?;
            // An engine that became unusable (its source or home was inconsistent) answers
            // nothing more, reads included.
            if let Err(poisoned) = g.advance(0) {
                return Err(AccountError::integrity(format!(
                    "{}: {}",
                    poisoned.code(),
                    poisoned.detail()
                )));
            }
            match f(&mut g) {
                Ok(v) => Ok(v),
                Err(e) => {
                    // The core says a locked engine refuses by a plain refusal: say it typed.
                    if g.is_locked()
                        && matches!(e, AccountError::Malformed { .. })
                        && e.detail_text().contains("the engine is locked")
                    {
                        return Err(AccountError::locked());
                    }
                    if let Err(poisoned) = g.advance(0) {
                        return Err(AccountError::integrity(format!(
                            "{}: {}",
                            poisoned.code(),
                            poisoned.detail()
                        )));
                    }
                    if matches!(e, AccountError::Unavailable { .. }) {
                        if let Some(h) = self.fault.lock().ok().and_then(|mut h| h.take()) {
                            return Err(AccountError::host(h));
                        }
                    }
                    Err(e)
                }
            }
        })
    }
    pub(crate) fn acct<T>(&self, f: impl FnOnce(&Account) -> R<T>) -> R<T> {
        self.run(|e| f(e.account()))
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_inner(
        host: Box<dyn HostSource>,
        listing: Vec<ListedPath>,
        identity: AccountIdentity,
        account: String,
        namespaces: Vec<String>,
        batch: u64,
        saved: SavedState,
        key: Vec<u8>,
        now_ms: i64,
    ) -> R<Self> {
        let saved = saved_in(saved);
        let identity = identity_of(&identity);
        Self::open_with(host, listing, account, namespaces, batch, key, |src, paths, options| {
            let saved = saved?;
            Ok(Engine::open(src, paths, identity?, options, saved.as_ref(), now_ms)?)
        })
    }
    /// An engine over the stores a creation returned, keeping the created account unlocked
    /// (`AccountCreation::open_engine`).
    pub(crate) fn open_created_inner(
        host: Box<dyn HostSource>,
        listing: Vec<ListedPath>,
        created: colophon_core::v05::account::Account,
        namespaces: Vec<String>,
        batch: u64,
        key: Vec<u8>,
        now_ms: i64,
    ) -> R<Self> {
        let account = created.id().as_str().to_string();
        Self::open_with(host, listing, account, namespaces, batch, key, |src, paths, options| {
            Ok(Engine::open_created(src, paths, created, options, now_ms)?)
        })
    }
    fn open_with(
        host: Box<dyn HostSource>,
        listing: Vec<ListedPath>,
        account: String,
        namespaces: Vec<String>,
        batch: u64,
        mut key: Vec<u8>,
        open: impl FnOnce(Source, Vec<String>, EngineOptions) -> R<Engine<Source>>,
    ) -> R<Self> {
        let r = guard(|| {
            let k = fixed::<32>(&key, "the sealed-state key")?;
            list_len(&listing, "the listing")?;
            let ns = names(namespaces, "namespaces")?;
            let versions: Versions = Arc::new(Mutex::new(HashMap::new()));
            let fault: HostFault = Arc::new(Mutex::new(None));
            let mut paths = Vec::with_capacity(listing.len());
            if let Ok(mut v) = versions.lock() {
                for l in listing {
                    if let Some(version) = l.version.filter(|v| !v.is_empty()) {
                        v.insert(l.path.clone(), version);
                    }
                    paths.push(l.path);
                }
            }
            let mut options = EngineOptions::new(&account, k);
            options.namespaces = ns;
            options.batch = usize::try_from(if batch == 0 { DEFAULT_BATCH } else { batch })
                .map_err(|_| AccountError::bound("batch"))?;
            let busy: super::InCallback = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let src = Source::new(host, versions.clone(), fault.clone(), busy.clone());
            let e = match open(src, paths, options) {
                Ok(e) => e,
                Err(e) => {
                    if matches!(e, AccountError::Unavailable { .. }) {
                        if let Some(h) = fault.lock().ok().and_then(|mut h| h.take()) {
                            return Err(AccountError::host(h));
                        }
                    }
                    return Err(e);
                }
            };
            Ok(Self {
                eng: Cell::watched(e, busy),
                owner: next_owner(),
                versions,
                fault,
            })
        });
        wipe(&mut key);
        r
    }
    /// Refuse (typed `Locked`) once `lock` was called. A prepared action, a new one and a
    /// finish all stop here; reads of the verified history keep answering.
    pub(crate) fn ensure_live(&self) -> R<()> {
        self.run(|e| {
            if e.is_locked() {
                Err(AccountError::locked())
            } else {
                Ok(())
            }
        })
    }
    pub(crate) fn prepare(
        &self,
        kind: ActionKind,
        mut entropy: Vec<u8>,
        f: impl FnOnce(&Engine<Source>, &[u8]) -> R<Prepared>,
    ) -> R<AccountAction> {
        if let Err(e) = self.ensure_live() {
            wipe(&mut entropy);
            return Err(e);
        }
        let r = self.run(|e| f(e, &entropy));
        wipe(&mut entropy);
        Ok(match r? {
            Prepared::Action(p) => AccountAction::ready(p, self.owner, kind),
            Prepared::Denied(d) => AccountAction::denied(&d, self.owner, kind),
        })
    }
    fn provide_prf_inner(&self, action: &AccountAction, results: Vec<PrfAnswer>) -> R<()> {
        guard(|| {
            let r = cv::prf_answers(results)?;
            self.ensure_live()?;
            let p = action.take(self.owner)?;
            let next = self.run(|e| Ok(e.account().provide_prf(p, r)?))?;
            action.put_back(next)
        })
    }
    fn finish_inner(&self, action: &AccountAction, sigs: Vec<Signature>) -> R<Written> {
        guard(|| {
            let sigs = cv::signatures(sigs)?;
            // Locked is judged, and the action taken, under one hold of the engine: a refusal
            // (locked, or a call that could not get the engine) never consumes the action.
            let w = self.run(|e| {
                if e.is_locked() {
                    return Err(AccountError::locked());
                }
                let p = action.take(self.owner)?;
                Ok(e.finish_write(p, sigs)?)
            })?;
            Ok(Written {
                stores: cv::store_list(&w.stores),
                changes: cv::changes(&w.changes),
                artifact: w.artifact,
            })
        })
    }
    fn begin_blob_inner(
        &self,
        namespace: String,
        media_type: String,
        entropy: Vec<u8>,
    ) -> R<AccountBlobWriter> {
        let mut entropy = entropy;
        let r = self.ensure_live().and_then(|()| {
            self.run(|e| {
                let seed = fixed::<32>(&entropy, "entropy")?;
                match e.begin_blob(&namespace, media_type, seed)? {
                    Outcome::Success { value, .. } => Ok(AccountBlobWriter {
                        w: Cell::new(Some(value)),
                    }),
                    Outcome::Failure { reason, detail, .. } => {
                        Err(AccountError::denied(&reason, &detail))
                    }
                }
            })
        });
        wipe(&mut entropy);
        r
    }
    fn begin_live_inner(
        &self,
        namespace: String,
        kind: String,
        payload_json: String,
        entropy: Vec<u8>,
    ) -> R<AccountLiveWrite> {
        let mut entropy = entropy;
        let r = self.ensure_live().and_then(|()| {
            self.run(|e| {
                let seed = fixed::<32>(&entropy, "entropy")?;
                let p = json(&payload_json, "payload")?;
                match e.begin_live_write(&namespace, &kind, p, seed)? {
                    Ok(pl) => Ok(AccountLiveWrite {
                        st: Cell::new(Some(pl)),
                        owner: self.owner,
                    }),
                    Err(d) => Err(AccountError::denied(&d.reason, &d.detail)),
                }
            })
        });
        wipe(&mut entropy);
        r
    }
    fn finish_live_inner(&self, live: &AccountLiveWrite, signature: Signature) -> R<LiveWritten> {
        guard(|| {
            let [sig]: [colophon_core::v05::write::SignatureResult; 1] =
                cv::signatures(vec![signature])?
                    .try_into()
                    .map_err(|_| AccountError::bad("a live write has exactly one signature"))?;
            self.ensure_live()?;
            let pl = {
                let mut s = live.st.lock()?;
                if live.owner != self.owner {
                    return Err(AccountError::wrong_object(
                        "this live write was prepared by another session",
                    ));
                }
                s.take()
                    .ok_or_else(|| AccountError::consumed("this live write is finished"))?
            };
            let w = self.run(|e| Ok(e.finish_live_write(pl, sig)?))?;
            Ok(LiveWritten {
                stores: cv::store_list(&w.stores),
                replaces: w.replaces.map(|(path, sha256)| Replaces { path, sha256 }),
                changes: cv::changes(&w.changes),
            })
        })
    }
}

/// The `begin_*` calls: one typed method per action, in both builds, returning a prepared
/// action. (A macro, because UniFFI returns the object as `Arc` and wasm-bindgen by value.)
macro_rules! begin_methods {
    ($(
        $(#[$m:meta])*
        fn $name:ident($($arg:ident : $t:ty),*) $kind:ident |$eng:ident, $ent:ident| $body:block
    )*) => {
        #[cfg(feature = "native05")]
        #[uniffi::export]
        impl AccountEngine {
            $(
                $(#[$m])*
                pub fn $name(&self $(, $arg: $t)*, entropy: Vec<u8>) -> Result<Arc<AccountAction>, AccountError> {
                    self.prepare(ActionKind::$kind, entropy, |$eng, $ent| $body).map(Arc::new)
                }
            )*
        }
        #[cfg(feature = "web05")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl AccountEngine {
            $(
                $(#[$m])*
                pub fn $name(&self $(, $arg: $t)*, entropy: Vec<u8>) -> Result<AccountAction, AccountError> {
                    self.prepare(ActionKind::$kind, entropy, |$eng, $ent| $body)
                }
            )*
        }
    };
}

begin_methods! {
    /// Approve a request (a `grant`; `terms_json` with `import` is an import grant). 32 bytes of entropy.
    fn begin_approve(request: Vec<u8>, terms_json: String, signers: Vec<String>) Approve |e, s| {
        let sd = seeds32(s, 1)?;
        let terms = auth_json(&terms_json, "terms")?;
        done(e.account().begin_approve(&request, terms, &names(signers, "signers")?, sd[0]))
    }
    /// Renew a member's expiry. 32 bytes of entropy.
    fn begin_renew(member: String, expires_ms: i64, signers: Vec<String>) Renew |e, s| {
        let sd = seeds32(s, 1)?;
        done(e.account().begin_renew(&member, expires_ms, &names(signers, "signers")?, sd[0]))
    }
    /// Seal the shares a member is owed (§9.4). 32 bytes of entropy.
    fn begin_renew_shares(member: String, signers: Vec<String>) RenewShares |e, s| {
        let sd = seeds32(s, 1)?;
        done(e.account().begin_renew_shares(&member, &names(signers, "signers")?, sd[0]))
    }
    /// Revoke a member, keeping what `keep` says (§9.5). 32 bytes of entropy.
    fn begin_revoke(member: String, keep: RevokeKeep, signers: Vec<String>) Revoke |e, s| {
        let sd = seeds32(s, 1)?;
        let k = match keep.mode {
            KeepMode::Everything => CoreKeep::Everything,
            KeepMode::Nothing => CoreKeep::Nothing,
            KeepMode::Explicit => CoreKeep::Explicit {
                kept: names(keep.kept, "kept")?,
                heads: keep.heads.into_iter().map(|h| (h.namespace, h.digest)).collect(),
            },
        };
        done(e.account().begin_revoke(&member, &k, &names(signers, "signers")?, sd[0]))
    }
    /// End a member's sessions. No entropy.
    fn begin_end_sessions(member: String, signers: Vec<String>) EndSessions |e, s| {
        no_entropy(s)?;
        done(e.account().begin_end_sessions(&member, &names(signers, "signers")?))
    }
    /// End this device's own sessions. No entropy.
    fn begin_end_my_sessions() EndMySessions |e, s| {
        no_entropy(s)?;
        done(e.account().begin_end_my_sessions())
    }
    /// A new epoch for the namespaces. 32 bytes of entropy.
    fn begin_rekey(namespaces: Vec<String>, signers: Vec<String>) Rekey |e, s| {
        let sd = seeds32(s, 1)?;
        done(e.account().begin_rekey(&names(namespaces, "namespaces")?, &names(signers, "signers")?, sd[0]))
    }
    /// An immediate additive `keyring` entry: controllers (typed), already-built slots (JSON
    /// each, at most 1 MiB in all) and policy fields (JSON, or empty). No entropy.
    fn begin_keyring(add_controllers: Vec<ControllerSpec>, add_slots_json: Vec<String>, policy_json: String, signers: Vec<String>) Keyring |e, s| {
        no_entropy(s)?;
        let edit = KeyringEdit {
            add_controllers: controller_values(&add_controllers)?,
            add_slots: json_list(&add_slots_json, MAX_AUTH_JSON, MAX_NAMES, "a slot")?,
            policy: if policy_json.is_empty() { None } else { Some(auth_json(&policy_json, "policy")?) },
        };
        done(e.account().begin_keyring(&edit, &names(signers, "signers")?))
    }
    /// Add a controller (typed): at once for `approve`/`sign` roles, or as a pending
    /// transition under `rule` for `control`/`recover`. No entropy.
    fn begin_add_controller(controller: ControllerSpec, mode: AddMode, signers: Vec<String>, rule: RuleKind) AddController |e, s| {
        no_entropy(s)?;
        let signers = names(signers, "signers")?;
        let m = match mode {
            AddMode::Immediate => CoreAdd::Immediate { signers },
            AddMode::Transition => CoreAdd::Transition { signers, rule: cv::rule(rule) },
        };
        done(e.account().begin_add_controller(&AddController {
            controller: cv::controller_value(&controller)?,
            mode: m,
        }))
    }
    /// A self-slot (§8.4). 32 bytes of entropy.
    fn begin_add_slot(signer: String, plan: SlotPlan) AddSlot |e, s| {
        let sd = seeds32(s, 1)?;
        done(e.account().begin_add_slot(&signer, cv::slot_plan(plan)?, sd[0]))
    }
    /// A `vault` entry from a new seed. 64 bytes: the new seed, then the entropy.
    fn begin_rotate_vault(signer: String, has_plans: bool, plans: Vec<SlotPlan>) RotateVault |e, s| {
        let sd = seeds32(s, 2)?;
        let plans = if has_plans {
            Some(plans.into_iter().map(cv::slot_plan).collect::<R<Vec<_>>>()?)
        } else { None };
        done(e.account().begin_rotate_vault(&signer, sd[0], plans, sd[1]))
    }
    /// Remove controllers, keeping some a removed key planted; with `rotate`, 64 bytes of
    /// entropy (new seed, seal entropy), else none.
    fn begin_remove_controller(remove: Vec<String>, keep: Vec<String>, signers: Vec<String>, rule: RuleKind, rotate: bool) RemoveController |e, s| {
        let rotation = if rotate {
            let sd = seeds32(s, 2)?;
            Some((sd[0], sd[1]))
        } else {
            no_entropy(s)?;
            None
        };
        done(e.account().begin_remove_controller(
            &names(remove, "remove")?, &names(keep, "keep")?, &names(signers, "signers")?, cv::rule(rule), rotation))
    }
    /// A pending transition; `change_json` is the §8.7 `change` object. No entropy.
    fn begin_transition(change_json: String, signers: Vec<String>, rule: RuleKind) Transition |e, s| {
        no_entropy(s)?;
        let c = auth_json(&change_json, "the change")?;
        let Value::Object(map) = c else { return Err(AccountError::bad("the change is an object")) };
        done(e.account().begin_transition(&Change(map), &names(signers, "signers")?, cv::rule(rule)))
    }
    /// A veto of a pending transition. No entropy.
    fn begin_veto(transition: String, signers: Vec<String>) Veto |e, s| {
        no_entropy(s)?;
        done(e.account().begin_veto(&transition, &names(signers, "signers")?))
    }
    /// Suspend a controller while a transition is pending. No entropy.
    fn begin_suspend(key: String, transition: String, signer: String) Suspend |e, s| {
        no_entropy(s)?;
        done(e.account().begin_suspend(&key, &transition, &signer))
    }
    /// Resolve a fork: the anchor and the kept candidate, each `(seq, digest)`. No entropy.
    fn begin_resolve(anchor_seq: u64, anchor_digest: String, kept_seq: u64, kept_digest: String, signers: Vec<String>, rule: RuleKind) Resolve |e, s| {
        no_entropy(s)?;
        done(e.account().begin_resolve((anchor_seq, anchor_digest), (kept_seq, kept_digest),
            &names(signers, "signers")?, cv::rule(rule)))
    }
    /// A record write; `payload_json` is the domain payload. The engine retains the live heads
    /// the write supersedes. 32 bytes of entropy. A write refused for access reasons returns an
    /// action whose `denial` is set.
    fn begin_write(namespace: String, kind: String, payload_json: String) Write |e, s| {
        let sd = seeds32(s, 1)?;
        let p = json(&payload_json, "payload")?;
        Ok(match e.begin_write(&namespace, &kind, p, Level::Write, sd[0])? {
            Ok(a) => Prepared::Action(a),
            Err(d) => Prepared::Denied(d),
        })
    }
    /// A proposal (§11.6). 32 bytes of entropy.
    fn begin_propose(namespace: String, kind: String, payload_json: String) Propose |e, s| {
        let sd = seeds32(s, 1)?;
        let p = json(&payload_json, "payload")?;
        Ok(match e.begin_write(&namespace, &kind, p, Level::Propose, sd[0])? {
            Ok(a) => Prepared::Action(a),
            Err(d) => Prepared::Denied(d),
        })
    }
    /// Accept or decline proposals. 32 bytes of entropy.
    fn begin_resolution(namespace: String, accept: bool, proposals: Vec<String>) Resolution |e, s| {
        let sd = seeds32(s, 1)?;
        done(e.account().begin_resolution(&namespace, accept, &names(proposals, "proposals")?, sd[0]))
    }
    /// An import batch (the 0.4 batch JSON) under a grant that carries `import`. 32 bytes.
    fn begin_import(namespace: String, batch_json: String) Import |e, s| {
        let sd = seeds32(s, 1)?;
        let v = json(&batch_json, "the import batch")?;
        let b: colophon_core::imports::ImportBatch = serde_json::from_value(v)
            .map_err(|_| AccountError::bad("not an import batch"))?;
        Ok(match e.begin_import(&namespace, &b, sd[0])? {
            Ok(a) => Prepared::Action(a),
            Err(d) => Prepared::Denied(d),
        })
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountEngine {
    /// The account ID (64 hex).
    pub fn id(&self) -> Result<String, AccountError> {
        self.acct(|a| Ok(a.id().as_str().to_string()))
    }
    /// This session's identity: a controller or a member, with its ID.
    pub fn identity(&self) -> Result<AccountIdentity, AccountError> {
        self.acct(|a| {
            Ok(match a.identity() {
                colophon_core::v05::account::Identity::Controller(i) => AccountIdentity {
                    kind: AccountIdentityKind::Controller,
                    id: i.clone(),
                },
                colophon_core::v05::account::Identity::Member(i) => AccountIdentity {
                    kind: AccountIdentityKind::Member,
                    id: i.clone(),
                },
            })
        })
    }
    /// The verifier's verdict on the history.
    pub fn status(&self) -> Result<Status, AccountError> {
        self.acct(|a| Ok(cv::status(&a.status())))
    }
    /// The seq of the head of the verified branch.
    pub fn head_seq(&self) -> Result<u64, AccountError> {
        self.acct(|a| Ok(a.head().0))
    }
    /// The digest of the head of the verified branch.
    pub fn head_digest(&self) -> Result<String, AccountError> {
        self.acct(|a| Ok(a.head().1))
    }
    /// The controllers of the verified keyring.
    pub fn controllers(&self) -> Result<Vec<Controller>, AccountError> {
        self.acct(|a| Ok(a.controllers().iter().map(cv::controller).collect()))
    }
    /// The homes the account names.
    pub fn homes(&self) -> Result<Vec<Home>, AccountError> {
        self.acct(|a| Ok(a.homes().iter().map(cv::home).collect()))
    }
    /// The effective policy.
    pub fn policy(&self) -> Result<Policy, AccountError> {
        self.acct(|a| Ok(cv::policy(&a.policy())))
    }
    /// Pending transitions.
    pub fn pending(&self) -> Result<Vec<Pending>, AccountError> {
        self.acct(|a| Ok(a.pending().iter().map(cv::pending).collect()))
    }
    /// Shares members are owed (§9.4).
    pub fn owed_shares(&self) -> Result<Vec<Owed>, AccountError> {
        self.acct(|a| Ok(a.owed_shares().iter().map(cv::owed).collect()))
    }
    /// What a person must be shown (§17.5). The host keeps `shown_seq` and the transitions it
    /// showed.
    pub fn notices(
        &self,
        shown_seq: u64,
        shown_transitions: Vec<String>,
        local_keys: Vec<String>,
    ) -> Result<Notices, AccountError> {
        list_len(&shown_transitions, "shown transitions")?;
        let shown: std::collections::BTreeSet<String> = shown_transitions.into_iter().collect();
        let keys = names(local_keys, "local keys")?;
        self.acct(|a| Ok(cv::notices(&a.notices(shown_seq, &shown, &keys))))
    }
    /// Open proposals of a namespace (JSON array).
    pub fn proposals_json(&self, namespace: String) -> Result<String, AccountError> {
        self.acct(|a| write_json!(a.proposals(&namespace)))
    }
    /// The tools this session can call (JSON array).
    pub fn tools_json(&self) -> Result<String, AccountError> {
        self.acct(|a| write_json!(a.tools()))
    }
    /// The slots of the current vault.
    pub fn slots(&self) -> Result<Vec<SlotInfo>, AccountError> {
        self.acct(cv::slots)
    }
    /// Whether the vault seed is held.
    pub fn is_unlocked(&self) -> Result<bool, AccountError> {
        self.acct(|a| Ok(a.is_unlocked()))
    }
    /// The work to open slot `index`: ECDH and PRF inputs, in answer order.
    pub fn begin_unlock_slot(&self, index: u64) -> Result<Vec<UnlockInput>, AccountError> {
        let i = usize::try_from(index).map_err(|_| AccountError::bound("slot index"))?;
        self.acct(|a| Ok(cv::unlock_inputs(&a.begin_unlock_slot(i)?)))
    }
    /// The ECDH work a member's host does to open its shares.
    pub fn begin_unlock_epochs(&self) -> Result<Vec<EpochAgreement>, AccountError> {
        self.acct(|a| Ok(cv::agreements(a.begin_unlock_epochs())))
    }
    /// Fork candidates a `resolve` may choose between.
    pub fn fork_candidates(&self) -> Result<Vec<ForkCandidate>, AccountError> {
        self.acct(|a| {
            Ok(a.fork_candidates()
                .into_iter()
                .map(|(seq, first, second)| ForkCandidate { seq, first, second })
                .collect())
        })
    }
    /// Controllers (IDs) that together meet the rule `need`, from those the host can sign with.
    pub fn suggest_signers(
        &self,
        available: Vec<String>,
        need: SignerNeed,
    ) -> Result<Vec<String>, AccountError> {
        let have = names(available, "available")?;
        self.acct(|a| Ok(a.suggest_signers(&have, cv::signer_need(need))?))
    }
    /// The latest epoch of a namespace.
    pub fn latest_epoch(&self, namespace: String) -> Result<u64, AccountError> {
        self.acct(|a| Ok(a.latest_epoch(&namespace)))
    }
    /// Why this session may not write `namespace` now, or none.
    pub fn write_denial(&self, namespace: String) -> Result<Option<AccountDenial>, AccountError> {
        self.acct(|a| Ok(a.write_denial(&namespace).as_ref().map(cv::denial)))
    }
    /// The verdict on a record the engine holds at `path`, or none.
    pub fn record_verdict(&self, path: String) -> Result<Option<RecordVerdict>, AccountError> {
        self.acct(|a| Ok(cv::record_verdict(a.record_verdict(&path))))
    }
    /// The verdict the engine would give `bytes` at `path`, without holding them.
    pub fn verdict_of(
        &self,
        path: String,
        bytes: Vec<u8>,
    ) -> Result<Option<RecordVerdict>, AccountError> {
        bytes_ok(&bytes, MAX_BYTES, "a record")?;
        self.acct(|a| Ok(cv::record_verdict(a.verdict_of(&path, &bytes))))
    }
    /// The live heads the verifier accepted.
    pub fn live_heads(&self) -> Result<Vec<LiveHead>, AccountError> {
        self.acct(|a| {
            Ok(a.live_heads()
                .iter()
                .map(|h| LiveHead {
                    path: h.path.clone(),
                    digest: h.digest.clone(),
                    author: h.author.clone(),
                    namespace: h.namespace.clone(),
                    slot: h.slot.clone(),
                    generation: h.generation,
                })
                .collect())
        })
    }
    /// How the open treated saved state.
    pub fn open_info(&self) -> Result<OpenInfo, AccountError> {
        self.run(|e| {
            Ok(match e.open_mode() {
                CoreOpen::Cold => OpenInfo {
                    mode: OpenMode::Cold,
                    reason: None,
                },
                CoreOpen::Resumed => OpenInfo {
                    mode: OpenMode::Resumed,
                    reason: None,
                },
                CoreOpen::Invalidated(w) => OpenInfo {
                    mode: OpenMode::Invalidated,
                    reason: Some(w.clone()),
                },
            })
        })
    }
    /// Work the engine did.
    pub fn stats(&self) -> Result<EngineStats, AccountError> {
        self.run(|e| {
            let s = e.stats();
            Ok(EngineStats {
                records_read: s.records_read,
                signatures_verified: s.signatures_verified,
                payloads_decrypted: s.payloads_decrypted,
                walked_last: s.walked_last,
                folds_applied_last: s.folds_applied_last,
                ignored_paths: s.ignored_paths,
                held_paths: s.held_paths as u64,
                unread_paths: s.unread_paths as u64,
            })
        })
    }
    /// Read every listed record not yet read and judge them (the unlock calls do this too).
    pub fn load(&self) -> Result<Changes, AccountError> {
        self.run(|e| Ok(cv::changes(&e.load()?)))
    }
    /// Take a fresh listing and read what is new.
    pub fn refresh(&self, listing: Vec<ListedPath>) -> Result<Changes, AccountError> {
        list_len(&listing, "the listing")?;
        let mut paths = Vec::with_capacity(listing.len());
        {
            let mut v = self
                .versions
                .lock()
                .map_err(|_| AccountError::internal("versions"))?;
            v.clear();
            for l in listing {
                if let Some(version) = l.version.filter(|v| !v.is_empty()) {
                    v.insert(l.path.clone(), version);
                }
                paths.push(l.path);
            }
        }
        let hint: std::collections::BTreeMap<String, Option<String>> = {
            let v = self
                .versions
                .lock()
                .map_err(|_| AccountError::internal("versions"))?;
            paths
                .iter()
                .map(|p| (p.clone(), v.get(p).cloned()))
                .collect()
        };
        self.run(|e| Ok(cv::changes(&e.refresh_batched(paths, hint)?)))
    }
    /// The host stored these paths itself: read and judge them (with their versions).
    pub fn apply_paths(&self, paths: Vec<ListedPath>) -> Result<Changes, AccountError> {
        list_len(&paths, "paths")?;
        let mut listed = Vec::with_capacity(paths.len());
        {
            let mut v = self
                .versions
                .lock()
                .map_err(|_| AccountError::internal("versions"))?;
            for l in paths {
                match l.version.filter(|v| !v.is_empty()) {
                    None => {
                        v.remove(&l.path);
                    }
                    Some(version) => {
                        v.insert(l.path.clone(), version);
                    }
                }
                listed.push(l.path);
            }
        }
        self.run(|e| Ok(cv::changes(&e.apply_paths(listed)?)))
    }
    /// Move the clock forward.
    pub fn advance(&self, now_ms: i64) -> Result<Changes, AccountError> {
        self.run(|e| Ok(cv::changes(&e.advance(now_ms)?)))
    }
    /// Open a slot with the host's answers (in input order), then read the records once. The
    /// secrets are consumed and wiped.
    pub fn finish_unlock_slot(
        &self,
        index: u64,
        secrets: Vec<UnlockSecret>,
    ) -> Result<Changes, AccountError> {
        let s = cv::unlock_secrets(secrets);
        let i = usize::try_from(index).map_err(|_| AccountError::bound("slot index"));
        let (i, s) = (i?, s?);
        self.run(|e| Ok(cv::changes(&e.finish_unlock_slot(i, &s)?)))
    }
    /// A member opens its shares with the host's answers, then the records are read once. The
    /// secrets are consumed and wiped.
    pub fn finish_unlock_epochs(&self, answers: Vec<EpochAnswer>) -> Result<Changes, AccountError> {
        // The shares are wiped after the call on every path: a failure before the engine is
        // reached (a call from inside a callback, a poisoned lock) included.
        let mut answers = answers;
        let r = self.run(|e| {
            let want = e.begin_unlock_epochs();
            let s = cv::epoch_secrets(want, &mut answers)?;
            Ok(cv::changes(&e.finish_unlock_epochs(s)?))
        });
        for a in &mut answers {
            wipe(&mut a.shared);
        }
        r
    }
    /// Paths a checkpoint covered that the listing no longer names.
    pub fn missing_covered(&self) -> Result<Vec<String>, AccountError> {
        self.run(|e| Ok(e.missing_covered()))
    }
    /// Namespaces whose budget cannot be judged until more is read.
    pub fn budget_scope_unavailable(&self) -> Result<Vec<String>, AccountError> {
        self.run(|e| Ok(e.budget_scope_unavailable()))
    }
    /// Covered paths judged again because their bytes changed.
    pub fn rejudged(&self) -> Result<Vec<String>, AccountError> {
        self.run(|e| Ok(e.rejudged().to_vec()))
    }
    /// Why `namespace` is not readable now, or none.
    pub fn access(&self, namespace: String) -> Result<Option<AccountDenial>, AccountError> {
        self.run(|e| Ok(e.access(&namespace)?.as_ref().map(cv::denial)))
    }
    /// The revision of a namespace's fold.
    pub fn revision(&self, namespace: String) -> Result<u64, AccountError> {
        self.run(|e| Ok(e.revision(&namespace)))
    }
    /// Every namespace's revision.
    pub fn revisions(&self) -> Result<Vec<NamespaceRevision>, AccountError> {
        self.run(|e| {
            Ok(e.revisions()
                .into_iter()
                .map(|(namespace, revision)| NamespaceRevision {
                    namespace,
                    revision,
                })
                .collect())
        })
    }
    /// What this session is in the verified history.
    pub fn me(&self) -> Result<Standing, AccountError> {
        self.run(|e| cv::standing(&e.me()))
    }
    /// Members with their terms and standing.
    pub fn members(&self) -> Result<Vec<AccountMember>, AccountError> {
        self.run(|e| e.members().iter().map(cv::member).collect())
    }
    /// The ledger (JSON array, the 0.4 ledger shape).
    pub fn ledger_json(&self) -> Result<String, AccountError> {
        self.run(|e| write_json!(e.ledger()))
    }
    /// A namespace's folded view: JSON `{"ok":true,"value":{..}}` or `{"ok":false,"reason",..}`.
    pub fn view_json(&self, namespace: String) -> Result<String, AccountError> {
        self.run(|e| outcome_json!(e.view(&namespace)?))
    }
    /// A named domain query; `args_json` is JSON (or empty). Result as `view_json`.
    pub fn query_json(
        &self,
        namespace: String,
        name: String,
        args_json: String,
    ) -> Result<String, AccountError> {
        let a = json_or_null(&args_json, "args")?;
        self.run(|e| outcome_json!(e.query(&namespace, &name, a)?))
    }
    /// One page (1 to 200) of admitted operations in fold order, as a JSON outcome whose value
    /// is `{"items":[..],"nextOffset":n|null}`.
    pub fn history_json(
        &self,
        namespace: String,
        offset: u64,
        limit: u64,
    ) -> Result<String, AccountError> {
        let o = usize::try_from(offset).map_err(|_| AccountError::bound("offset"))?;
        let l = usize::try_from(limit).map_err(|_| AccountError::bound("limit"))?;
        self.run(|e| outcome_json!(e.history(&namespace, o, l)?))
    }
    /// One admitted operation by the path it was stored at (JSON outcome).
    pub fn operation_at_json(
        &self,
        namespace: String,
        path: String,
    ) -> Result<String, AccountError> {
        self.run(|e| outcome_json!(e.operation_at(&namespace, &path)?))
    }
    /// Hold live candidates the host fetched (`path`, `bytes`).
    pub fn apply_live(&self, candidates: Vec<Store>) -> Result<Changes, AccountError> {
        list_len(&candidates, "candidates")?;
        let c: Vec<HeldRecord> = candidates
            .into_iter()
            .map(|s| HeldRecord {
                path: s.path,
                bytes: s.bytes,
            })
            .collect();
        self.run(|e| Ok(cv::changes(&e.apply_live(c)?)))
    }
    /// Live candidates refused for being below their witness.
    pub fn stale_live(&self) -> Result<Vec<StaleLive>, AccountError> {
        self.run(|e| {
            Ok(e.stale_live()
                .iter()
                .map(|(p, g)| StaleLive {
                    path: p.clone(),
                    generation: *g,
                })
                .collect())
        })
    }
    /// The verdict on each held live candidate.
    pub fn live_verdicts(&self) -> Result<Vec<LiveVerdict>, AccountError> {
        self.run(|e| {
            Ok(e.live_verdicts()
                .iter()
                .map(|(path, v)| {
                    let (kind, detail) = match v {
                        CoreLive::Current => (LiveVerdictKind::Current, None),
                        CoreLive::Superseded => (LiveVerdictKind::Superseded, None),
                        CoreLive::Retained => (LiveVerdictKind::Retained, None),
                        CoreLive::Equivocation => (LiveVerdictKind::Equivocation, None),
                        CoreLive::Quarantined(c) => {
                            (LiveVerdictKind::Quarantined, Some((*c).to_string()))
                        }
                        CoreLive::Refused(c) => (LiveVerdictKind::Refused, Some((*c).to_string())),
                        CoreLive::Invalid(w) => (LiveVerdictKind::Invalid, Some(w.clone())),
                    };
                    LiveVerdict {
                        path: path.clone(),
                        kind,
                        detail,
                    }
                })
                .collect())
        })
    }
    /// The sealed state to store atomically (caches sealed under the key given at open).
    /// `nonce_seed` is 32 fresh bytes, wiped.
    pub fn save(&self, nonce_seed: Vec<u8>) -> Result<SavedState, AccountError> {
        let mut nonce_seed = nonce_seed;
        let r = self.run(|e| {
            let n = fixed::<32>(&nonce_seed, "the nonce seed")?;
            let s = e.save(n)?;
            Ok(SavedState {
                verifier: s.verifier,
                checkpoint: s.checkpoint,
                parts: s
                    .parts
                    .into_iter()
                    .map(|(namespace, bytes)| SavedPart { namespace, bytes })
                    .collect(),
            })
        });
        wipe(&mut nonce_seed);
        r
    }
    /// Recheck up to `limit` held paths against the source; a change is a sticky integrity
    /// failure (`Integrity` from then on).
    pub fn verify_batch(&self, limit: u64) -> Result<VerifyProgress, AccountError> {
        let l = usize::try_from(limit).map_err(|_| AccountError::bound("limit"))?;
        self.run(|e| {
            let p = e.verify_batch(l)?;
            Ok(VerifyProgress {
                checked: p.checked as u64,
                remaining: p.remaining as u64,
            })
        })
    }
    /// The signed manifest of a blob (JSON outcome).
    pub fn blob_manifest_json(
        &self,
        namespace: String,
        digest: String,
    ) -> Result<String, AccountError> {
        self.run(|e| outcome_json!(e.blob_manifest(&namespace, &digest)?))
    }
    /// Authenticate one fetched chunk and return its plaintext. A refusal is `Denied`.
    pub fn open_blob_chunk(
        &self,
        namespace: String,
        digest: String,
        index: u64,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, AccountError> {
        bytes_ok(&ciphertext, 1 << 20, "a blob chunk")?;
        let i = usize::try_from(index).map_err(|_| AccountError::bound("index"))?;
        self.run(
            |e| match e.open_blob_chunk(&namespace, &digest, i, &ciphertext)? {
                Outcome::Success { value, .. } => Ok(value),
                Outcome::Failure { reason, detail, .. } => {
                    Err(AccountError::denied(&reason, &detail))
                }
            },
        )
    }
    /// The plaintext of one held chunk.
    pub fn blob_chunk(
        &self,
        namespace: String,
        digest: String,
        index: u64,
    ) -> Result<Vec<u8>, AccountError> {
        let i = usize::try_from(index).map_err(|_| AccountError::bound("index"))?;
        self.run(|e| blob_bytes(e.blob_chunk(&namespace, &digest, i)?))
    }
    /// The whole blob's authenticated plaintext.
    pub fn read_blob(&self, namespace: String, digest: String) -> Result<Vec<u8>, AccountError> {
        self.run(|e| blob_bytes(e.read_blob(&namespace, &digest)?))
    }
    /// How much of a blob is held.
    pub fn blob_availability(
        &self,
        namespace: String,
        digest: String,
    ) -> Result<BlobAvailability, AccountError> {
        self.run(|e| {
            Ok(match e.blob_availability(&namespace, &digest)? {
                CoreAvail::Complete => BlobAvailability {
                    state: BlobState::Complete,
                    present: 0,
                    total: 0,
                    detail: None,
                },
                CoreAvail::Partial { present, total } => BlobAvailability {
                    state: BlobState::Partial,
                    present: present as u64,
                    total: total as u64,
                    detail: None,
                },
                CoreAvail::Missing => BlobAvailability {
                    state: BlobState::Missing,
                    present: 0,
                    total: 0,
                    detail: None,
                },
                CoreAvail::Inaccessible(d) => BlobAvailability {
                    state: BlobState::Inaccessible,
                    present: 0,
                    total: 0,
                    detail: Some(d),
                },
            })
        })
    }
    /// Chunk paths of required blobs this device does not hold.
    pub fn required_blob_fetches(&self, namespace: String) -> Result<Vec<String>, AccountError> {
        self.run(|e| Ok(e.required_blob_fetches(&namespace)?))
    }
    /// The homes the account names, as the exchange sees them.
    pub fn exchange_homes(&self) -> Result<Vec<Home>, AccountError> {
        self.run(|e| Ok(e.exchange_homes().iter().map(cv::home).collect()))
    }
    /// Set (or clear, with an empty string) the storage bearer token for a home.
    pub fn exchange_set_bearer(&self, home: String, token: String) -> Result<(), AccountError> {
        if token.len() > 8192 {
            return Err(AccountError::bound("a bearer token is at most 8 KiB"));
        }
        self.run(|e| {
            e.exchange_set_bearer(&home, (!token.is_empty()).then_some(token));
            Ok(())
        })
    }
    /// The next step of a pass with `home`: a request to send, a request that needs a fresh
    /// call, a request to wait for, or done.
    pub fn exchange_next(&self, home: String) -> Result<ExchangeStep, AccountError> {
        self.run(|e| {
            Ok(match e.exchange_next(&home)? {
                Step::Request(r) => ExchangeStep {
                    kind: ExchangeStepKind::Request,
                    request: Some(HttpRequest {
                        ticket: r.ticket,
                        home: r.home,
                        method: method(r.method),
                        url: r.url,
                        headers: headers(&r.headers),
                        body: r.body,
                    }),
                    need: None,
                },
                Step::Waiting => ExchangeStep {
                    kind: ExchangeStepKind::Waiting,
                    request: None,
                    need: None,
                },
                Step::NeedCall(n) => ExchangeStep {
                    kind: ExchangeStepKind::NeedCall,
                    request: None,
                    need: Some(CallNeed {
                        ticket: n.ticket,
                        home: n.home,
                        audience: n.audience,
                        purpose: n.purpose,
                        method: method(n.method),
                        url: n.url,
                        path: n.path,
                        body_sha256: n.body_sha256,
                    }),
                },
                Step::Done => ExchangeStep {
                    kind: ExchangeStepKind::Done,
                    request: None,
                    need: None,
                },
            })
        })
    }
    /// Give the call the host built for a `NeedCall` step. It is bound to that ticket.
    pub fn exchange_provide_call(
        &self,
        home: String,
        ticket: u64,
        call: Vec<u8>,
    ) -> Result<(), AccountError> {
        bytes_ok(&call, 16_384, "a call")?;
        self.run(|e| Ok(e.exchange_provide_call(&home, ticket, &call)?))
    }
    /// Answer the request with `ticket`. Everything the home sent is verified before anything
    /// changes; the report holds what to store, what changed and the faults of the home.
    pub fn exchange_answer(
        &self,
        home: String,
        ticket: u64,
        answer: HttpAnswer,
    ) -> Result<Report, AccountError> {
        bytes_ok(&answer.body, 128 << 20, "a response body")?;
        let status = u16::try_from(answer.status).map_err(|_| AccountError::bound("status"))?;
        if answer.headers.len() > 256 {
            return Err(AccountError::bound("too many headers"));
        }
        let hs = answer
            .headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect();
        self.run(|e| {
            let r = e.exchange_answer(
                &home,
                ticket,
                Response {
                    status,
                    headers: hs,
                    body: answer.body,
                },
            )?;
            Ok(report(&r))
        })
    }
    /// Queue the pulls of the chunks of a blob this device lacks. Returns how many.
    pub fn exchange_want_blob(
        &self,
        home: String,
        namespace: String,
        digest: String,
    ) -> Result<u64, AccountError> {
        self.run(|e| Ok(e.exchange_want_blob(&home, &namespace, &digest)? as u64))
    }
    /// Homes whose verified receipt of `object` the account holds.
    pub fn receipted_by(&self, object: String) -> Result<Vec<String>, AccountError> {
        self.run(|e| Ok(e.receipted_by(&object)))
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// Open an engine over the host's source. `listing` is every path the source holds, with
    /// its content version (empty for none); `identity` is a controller or a member with its ID;
    /// `account` the 64-hex account ID; `namespaces` the read scope (empty: all); `batch` the
    /// records judged per step (0: the default); `saved` what `save` returned (an empty record
    /// for none); `key` the 32-byte device-held key (wiped from the argument; the core's
    /// engine keeps its own copy). Records are not read until a slot or shares are opened.
    #[uniffi::constructor]
    pub fn open(
        source: Box<dyn HostSource>,
        listing: Vec<ListedPath>,
        identity: AccountIdentity,
        account: String,
        namespaces: Vec<String>,
        batch: u64,
        saved: SavedState,
        key: Vec<u8>,
        now_ms: i64,
    ) -> Result<Arc<Self>, AccountError> {
        Self::open_inner(
            source, listing, identity, account, namespaces, batch, saved, key, now_ms,
        )
        .map(Arc::new)
    }
    /// Give the PRF answers an action asked for (consumed and wiped).
    pub fn provide_prf(
        &self,
        action: Arc<AccountAction>,
        results: Vec<PrfAnswer>,
    ) -> Result<(), AccountError> {
        self.provide_prf_inner(&action, results)
    }
    /// Finish a prepared action with the host's signatures, in step order. The core verifies
    /// the exact bytes it assembles before it changes anything; `stores` are to be stored as
    /// given. A failed finish consumes the action.
    pub fn finish(
        &self,
        action: Arc<AccountAction>,
        signatures: Vec<Signature>,
    ) -> Result<Written, AccountError> {
        self.finish_inner(&action, signatures)
    }
    /// Start a streaming blob upload (32 fresh bytes).
    pub fn begin_blob(
        &self,
        namespace: String,
        media_type: String,
        entropy: Vec<u8>,
    ) -> Result<Arc<AccountBlobWriter>, AccountError> {
        self.begin_blob_inner(namespace, media_type, entropy)
            .map(Arc::new)
    }
    /// Prepare a live write (a passive position sample). 32 fresh bytes.
    pub fn begin_live_write(
        &self,
        namespace: String,
        kind: String,
        payload_json: String,
        entropy: Vec<u8>,
    ) -> Result<Arc<AccountLiveWrite>, AccountError> {
        self.begin_live_inner(namespace, kind, payload_json, entropy)
            .map(Arc::new)
    }
    /// Finish a live write with its one raw signature.
    pub fn finish_live_write(
        &self,
        live: Arc<AccountLiveWrite>,
        signature: Signature,
    ) -> Result<LiveWritten, AccountError> {
        self.finish_live_inner(&live, signature)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    /// Give the PRF answers an action asked for (consumed and wiped).
    pub fn provide_prf(
        &self,
        action: &AccountAction,
        results: Vec<PrfAnswer>,
    ) -> Result<(), AccountError> {
        self.provide_prf_inner(action, results)
    }
    /// Finish a prepared action with the host's signatures, in step order.
    pub fn finish(
        &self,
        action: &AccountAction,
        signatures: Vec<Signature>,
    ) -> Result<Written, AccountError> {
        self.finish_inner(action, signatures)
    }
    /// Start a streaming blob upload (32 fresh bytes).
    pub fn begin_blob(
        &self,
        namespace: String,
        media_type: String,
        entropy: Vec<u8>,
    ) -> Result<AccountBlobWriter, AccountError> {
        self.begin_blob_inner(namespace, media_type, entropy)
    }
    /// Prepare a live write (a passive position sample). 32 fresh bytes.
    pub fn begin_live_write(
        &self,
        namespace: String,
        kind: String,
        payload_json: String,
        entropy: Vec<u8>,
    ) -> Result<AccountLiveWrite, AccountError> {
        self.begin_live_inner(namespace, kind, payload_json, entropy)
    }
    /// Finish a live write with its one raw signature.
    pub fn finish_live_write(
        &self,
        live: &AccountLiveWrite,
        signature: Signature,
    ) -> Result<LiveWritten, AccountError> {
        self.finish_live_inner(live, signature)
    }
}

/// A streaming blob upload. Holds an epoch key until finished or dropped; never keep it.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountBlobWriter {
    w: Cell<Option<BlobWriter>>,
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountBlobWriter {
    /// Seal at most 64 KiB; store the ciphertext at the path before the manifest is published.
    pub fn push(&self, plaintext: Vec<u8>) -> Result<BlobChunk, AccountError> {
        guard(|| {
            bytes_ok(&plaintext, 64 * 1024, "a blob chunk")?;
            let mut g = self.w.lock()?;
            let w = g
                .as_mut()
                .ok_or_else(|| AccountError::consumed("this blob writer is finished"))?;
            let (path, bytes) = w.push(&plaintext)?;
            Ok(BlobChunk { path, bytes })
        })
    }
    /// Finish: the manifest (JSON) to publish in the operation that names the blob. The writer
    /// and its key are gone afterwards.
    pub fn finish(&self) -> Result<String, AccountError> {
        guard(|| {
            let w = self
                .w
                .lock()?
                .take()
                .ok_or_else(|| AccountError::consumed("this blob writer is finished"))?;
            write_json!(w.finish()?)
        })
    }
}

/// A prepared live write: one raw signature over one header.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountLiveWrite {
    st: Cell<Option<PendingLive>>,
    owner: u64,
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountLiveWrite {
    /// The one step to sign.
    pub fn step(&self) -> Result<AccountSigningStep, AccountError> {
        guard(|| {
            let g = self.st.lock()?;
            let p = g
                .as_ref()
                .ok_or_else(|| AccountError::consumed("this live write is finished"))?;
            Ok(cv::step(p.step()))
        })
    }
    /// The slot's generation.
    pub fn generation(&self) -> Result<u64, AccountError> {
        guard(|| {
            let g = self.st.lock()?;
            Ok(g.as_ref()
                .ok_or_else(|| AccountError::consumed("this live write is finished"))?
                .generation())
        })
    }
    /// The slot path.
    pub fn state_path(&self) -> Result<String, AccountError> {
        guard(|| {
            let g = self.st.lock()?;
            Ok(g.as_ref()
                .ok_or_else(|| AccountError::consumed("this live write is finished"))?
                .state_path()
                .to_string())
        })
    }
}
