//! The rest of `AccountEngine`: what mutates the account the engine owns (due transitions, read
//! scope, lock, seed transfer, the predecessor's entry), links and calls with their artifact,
//! the exchange's abort, and moving a Swift library: the source with its vault and keys, the
//! copy plan with the host's translator, the copy write, the migration, `finish_move`.
use super::action::AccountAction;
use super::convert as cv;
use super::engine::{seeds32, AccountEngine, Prepared};
use super::fault::AccountError;
use super::moving::{stage, AccountMove};
use super::pairing::{AccountPairing, PairingTransferKey};
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::account::{CallTarget as CoreTarget, CopyWrite, Moved};
use colophon_core::v05::encoding::decode_base64;
use colophon_core::v05::records::OperationHeader;
use colophon_core::v05::slots::OpeningSecret;
use colophon_core::v05::swift_copy::{
    swift_members, Batch, Child, CopyItem as CoreItem, CopyPlan, CopyResult, Destination,
    SourceFile, SwiftOp,
};
use colophon_core::v05::swift_slots::{PredecessorVault, SwiftEpochKey, SwiftLibrary};
use colophon_core::v05::vault::{EcdhOutput, SealedBox};
use colophon_core::v05::write::succession::MigratedMember;
use colophon_core::v05::write::swift_veto::SwiftVetoParams;
use serde_json::Value;
use std::collections::BTreeMap;
#[cfg(feature = "native05")]
use std::sync::Arc;

type R<T> = Result<T, AccountError>;

/// The host's translator of Swift operations into destination batches (§16.2). Synchronous and
/// pure: it must not call into the plan or the engine.
#[cfg(feature = "native05")]
#[uniffi::export(callback_interface)]
pub trait SwiftTranslator: Send + Sync {
    /// Translate one admitted Swift operation. An error omits the record with its message.
    fn translate(&self, op: SwiftOpInfo) -> Result<SwiftBatch, AccountError>;
}
#[cfg(not(feature = "native05"))]
pub trait SwiftTranslator {
    fn translate(&self, op: SwiftOpInfo) -> Result<SwiftBatch, AccountError>;
}

fn json_of(text: &str, what: &str) -> R<Value> {
    json_or_null(text, what)
}
fn batch_of(b: SwiftBatch) -> R<Batch> {
    list_len(&b.children, "children")?;
    let mut identities = BTreeMap::new();
    for i in b.identities {
        identities.insert(i.source_key, (i.category, i.destination_id));
    }
    Ok(Batch {
        children: b
            .children
            .into_iter()
            .map(|c| {
                Ok(Child {
                    key: c.key,
                    kind: c.kind,
                    payload: json_of(&c.payload_json, "a child payload")?,
                    baseline: c.baseline,
                })
            })
            .collect::<R<Vec<_>>>()?,
        alternatives: b
            .alternatives_json
            .iter()
            .map(|a| json_of(a, "an alternative"))
            .collect::<R<Vec<_>>>()?,
        identities,
        blobs: b
            .blobs_json
            .iter()
            .map(|a| json_of(a, "a blob manifest"))
            .collect::<R<Vec<_>>>()?,
        outcome: b.outcome,
        evidence: json_of(&b.evidence_json, "evidence")?,
    })
}

/// A Swift predecessor library: read from its authority entries, its vault opened by the host's
/// answers, its namespace keys held inside. The keys never leave; a copy plan reads with them.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SwiftSource {
    st: Cell<SourceState>,
}
struct SourceState {
    lib: SwiftLibrary,
    vault: Option<PredecessorVault>,
    keys: Vec<SwiftEpochKey>,
}
impl SwiftSource {
    fn read_inner(entries: Vec<ByteString>) -> R<Self> {
        guard(|| {
            list_len(&entries, "entries")?;
            let mut raw = Vec::with_capacity(entries.len());
            for e in entries {
                bytes_ok(&e.bytes, 2_097_152, "an entry")?;
                raw.push(e.bytes);
            }
            Ok(Self {
                st: Cell::new(SourceState {
                    lib: SwiftLibrary::read(&raw)?,
                    vault: None,
                    keys: vec![],
                }),
            })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SwiftSource {
    /// The library's ID (32 hex).
    pub fn library(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.st.lock()?.lib.library().to_string()))
    }
    /// Problems the read found with parts of the library (each fails only itself).
    pub fn problems(&self) -> Result<Vec<String>, AccountError> {
        guard(|| Ok(self.st.lock()?.lib.problems().to_vec()))
    }
    /// The slots of the keyring.
    pub fn slots(&self) -> Result<Vec<SwiftSlotInfo>, AccountError> {
        guard(|| {
            Ok(self
                .st
                .lock()?
                .lib
                .slots()
                .iter()
                .enumerate()
                .map(|(i, s)| SwiftSlotInfo {
                    index: i as u64,
                    kind: s.kind().to_string(),
                    label: s.label().to_string(),
                    controller: s.controller().map(str::to_string),
                    problem: s.problem().map(str::to_string),
                })
                .collect())
        })
    }
    /// The host work to open slot `index`, in answer order.
    pub fn begin_open_slot(&self, index: u64) -> Result<Vec<UnlockInput>, AccountError> {
        guard(|| {
            let i = usize::try_from(index).map_err(|_| AccountError::bound("slot index"))?;
            Ok(cv::unlock_inputs(&self.st.lock()?.lib.begin_open(i)?))
        })
    }
    /// Open slot `index` with the host's answers (consumed and wiped); the vault is held inside.
    pub fn finish_open_slot(
        &self,
        index: u64,
        secrets: Vec<UnlockSecret>,
    ) -> Result<(), AccountError> {
        let s = cv::unlock_secrets(secrets);
        guard(|| {
            let i = usize::try_from(index).map_err(|_| AccountError::bound("slot index"))?;
            let s: Vec<OpeningSecret> = s?;
            let mut g = self.st.lock()?;
            let v = g.lib.finish_open(i, &s)?;
            g.vault = Some(v);
            Ok(())
        })
    }
    /// Every namespace and epoch of the keyring.
    pub fn epochs(&self) -> Result<Vec<SwiftEpoch>, AccountError> {
        guard(|| {
            let g = self.st.lock()?;
            let mut out = Vec::new();
            for ns in g.lib.namespaces() {
                for (epoch, seq) in g.lib.epochs(&ns) {
                    out.push(SwiftEpoch {
                        namespace: ns.clone(),
                        epoch: *epoch,
                        seq: *seq,
                    });
                }
            }
            Ok(out)
        })
    }
    /// Open every namespace key the opened vault reaches; they are held inside.
    pub fn open_namespace_keys(&self) -> Result<u64, AccountError> {
        guard(|| {
            let mut g = self.st.lock()?;
            let st = &mut *g;
            let v = st
                .vault
                .as_ref()
                .ok_or_else(|| AccountError::consumed("open a slot first"))?;
            let mut keys = Vec::new();
            for ns in st.lib.namespaces() {
                for (epoch, _) in st.lib.epochs(&ns) {
                    keys.push(v.open_epoch_key(&st.lib, &ns, *epoch)?);
                }
            }
            st.keys = keys;
            Ok(st.keys.len() as u64)
        })
    }
    /// The host work to open one share sealed to a principal other than the vault.
    pub fn begin_open_share(
        &self,
        namespace: String,
        epoch: u64,
        principal: String,
    ) -> Result<UnlockInput, AccountError> {
        guard(|| {
            let i = self
                .st
                .lock()?
                .lib
                .begin_open_share(&namespace, epoch, &principal)?;
            cv::unlock_inputs(&[i])
                .pop()
                .ok_or_else(|| AccountError::internal("no input"))
        })
    }
    /// Open that share with the host's answer (consumed and wiped); the key is held inside.
    pub fn finish_open_share(
        &self,
        namespace: String,
        epoch: u64,
        principal: String,
        secret: UnlockSecret,
    ) -> Result<(), AccountError> {
        let s = cv::unlock_secrets(vec![secret]);
        guard(|| {
            let mut s = s?;
            let o = s.pop().ok_or_else(|| AccountError::internal("no secret"))?;
            let mut g = self.st.lock()?;
            let k = g.lib.finish_open_share(&namespace, epoch, &principal, &o)?;
            g.keys.push(k);
            Ok(())
        })
    }
    /// The predecessor's members as the fold has them at the head.
    pub fn members(&self) -> Result<Vec<SwiftMemberInfo>, AccountError> {
        guard(|| {
            Ok(swift_members(&self.st.lock()?.lib)?
                .into_iter()
                .map(|m| SwiftMemberInfo {
                    id: m.id,
                    label: m.label,
                    role: m.role,
                    revoked: m.revoked,
                    budget: m.budget,
                })
                .collect())
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SwiftSource {
    /// Read a Swift library from its authority entries (any order).
    #[uniffi::constructor]
    pub fn read(entries: Vec<ByteString>) -> Result<Arc<Self>, AccountError> {
        Self::read_inner(entries).map(Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SwiftSource {
    /// Read a Swift library from its authority entries (any order).
    pub fn read(entries: Vec<ByteString>) -> Result<SwiftSource, AccountError> {
        Self::read_inner(entries)
    }
}

/// What the destination already holds of a copy, as the engine reports it (so an interrupted
/// copy continues without duplicating or losing a record).
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SwiftCopyDestination {
    d: Destination,
}
impl SwiftCopyDestination {
    fn empty_inner() -> Self {
        Self {
            d: Destination::empty(),
        }
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SwiftCopyDestination {
    /// A destination that holds nothing yet.
    #[uniffi::constructor]
    pub fn empty() -> Arc<Self> {
        Arc::new(Self::empty_inner())
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SwiftCopyDestination {
    /// A destination that holds nothing yet.
    pub fn empty() -> SwiftCopyDestination {
        Self::empty_inner()
    }
}

/// The plan of a copy: every source record planned once, in bounded batches, each carrying its
/// original author as evidence. The core validates every translated batch against the
/// destination's cumulative projection; a refused translation omits the record with its reason.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SwiftCopyPlan {
    p: Cell<Option<CopyPlan>>,
}
impl SwiftCopyPlan {
    pub(crate) fn read_inner(
        source: &SwiftSource,
        files: Vec<Store>,
        translator: Option<Box<dyn SwiftTranslator>>,
        destination: &SwiftCopyDestination,
    ) -> R<Self> {
        guard(|| {
            list_len(&files, "files")?;
            let mut src = Vec::with_capacity(files.len());
            for f in files {
                bytes_ok(&f.bytes, 4 << 20, "a source file")?;
                src.push(SourceFile {
                    path: f.path,
                    bytes: f.bytes,
                });
            }
            let g = source.st.lock()?;
            let tr = translator.map(|t| {
                move |op: &SwiftOp<'_>| -> colophon_core::v05::Result<Batch> {
                    let info = SwiftOpInfo {
                        source_library: op.source_library.to_string(),
                        author_id: op.author_id.to_string(),
                        author_label: op.author_label.to_string(),
                        operation_id: op.operation_id.to_string(),
                        signed_body_digest: op.signed_body_digest.to_string(),
                        kind: op.kind.to_string(),
                        version: op.version,
                        payload_json: op.payload.to_string(),
                        admitted_order: op.admitted_order,
                    };
                    let out = t
                        .translate(info)
                        .map_err(|e| colophon_core::v05::Failure::Unavailable(e.detail_text()))?;
                    batch_of(out)
                        .map_err(|e| colophon_core::v05::Failure::Malformed(e.detail_text()))
                }
            });
            let plan = CopyPlan::read(
                &g.lib,
                &src,
                &g.keys,
                tr.as_ref()
                    .map(|t| t as &colophon_core::v05::swift_copy::Translator<'_>),
                &destination.d,
            )?;
            Ok(Self {
                p: Cell::new(Some(plan)),
            })
        })
    }
    fn with<T>(&self, f: impl FnOnce(&CopyPlan) -> R<T>) -> R<T> {
        guard(|| {
            let g = self.p.lock()?;
            f(g.as_ref()
                .ok_or_else(|| AccountError::consumed("this plan is finished"))?)
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SwiftCopyPlan {
    /// The predecessor library this plan copies.
    pub fn library(&self) -> Result<String, AccountError> {
        self.with(|p| Ok(p.library().to_string()))
    }
    /// How many source records are still pending.
    pub fn pending(&self) -> Result<u64, AccountError> {
        self.with(|p| Ok(p.pending() as u64))
    }
    /// The source records omitted so far, each with its reason.
    pub fn omissions(&self) -> Result<Vec<SwiftOmission>, AccountError> {
        self.with(|p| {
            Ok(p.omissions()
                .into_iter()
                .map(|(namespace, source_digest, reason)| SwiftOmission {
                    namespace,
                    source_digest,
                    reason,
                })
                .collect())
        })
    }
    /// How many source records each namespace holds.
    pub fn source_counts(&self) -> Result<Vec<NamespaceCount>, AccountError> {
        self.with(|p| {
            Ok(p.source_counts()
                .into_iter()
                .map(|(namespace, count)| NamespaceCount { namespace, count })
                .collect())
        })
    }
    /// The next writes to make, at most `max` (and the core's bound).
    pub fn next_batch(&self, max: u64) -> Result<Vec<CopyItem>, AccountError> {
        let m = usize::try_from(max).map_err(|_| AccountError::bound("max"))?;
        self.with(|p| {
            Ok(p.next_batch(m)
                .into_iter()
                .map(|i| CopyItem {
                    namespace: i.namespace,
                    source_digest: i.source_digest,
                    key: i.key,
                    payload_json: i.payload.to_string(),
                })
                .collect())
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SwiftCopyPlan {
    /// Read the predecessor's files (`ops/...`, `state/...`, `history/...`, `blobs/...`) and plan
    /// the copy, translating each admitted Swift operation with the host's translator (none:
    /// the original kind and payload verbatim). `destination` is what the engine already holds.
    #[uniffi::constructor]
    pub fn read(
        source: Arc<SwiftSource>,
        files: Vec<Store>,
        translator: Option<Box<dyn SwiftTranslator>>,
        destination: Arc<SwiftCopyDestination>,
    ) -> Result<Arc<Self>, AccountError> {
        Self::read_inner(&source, files, translator, &destination).map(Arc::new)
    }
}

/// A finished copy, to give to `begin_swift_migration`.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SwiftCopyResult {
    r: CopyResult,
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SwiftCopyResult {
    /// What the copy holds.
    pub fn outcome(&self) -> CopyOutcome {
        CopyOutcome {
            namespaces: self
                .r
                .namespaces()
                .iter()
                .map(|n| MigratedNamespace {
                    namespace: n.namespace.clone(),
                    source: n.source,
                    copied: n.copied.clone(),
                    omitted: n.omitted,
                })
                .collect(),
            omitted: self
                .r
                .omitted()
                .iter()
                .map(|(d, r)| Omitted {
                    source_digest: d.clone(),
                    reason: r.clone(),
                })
                .collect(),
            blobs_not_copied: self.r.blobs_not_copied().to_vec(),
        }
    }
}

/// An import write begun for one item of a plan: it can be finished only as that item.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountCopyWrite {
    w: Cell<Option<CopyWrite>>,
    owner: u64,
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountCopyWrite {
    /// The header body the copying member signs raw.
    pub fn steps(&self) -> Result<Vec<AccountSigningStep>, AccountError> {
        guard(|| {
            let g = self.w.lock()?;
            Ok(cv::steps(
                g.as_ref()
                    .ok_or_else(|| AccountError::consumed("this write is finished"))?
                    .steps(),
            ))
        })
    }
}

fn target_of(t: CallTarget) -> R<CoreTarget> {
    let mut out = CoreTarget {
        audiences: names(t.audiences, "audiences")?,
        controller_purposes: names(t.controller_purposes, "controller purposes")?,
        home_endpoints: names(t.home_endpoints, "home endpoints")?,
        ..CoreTarget::default()
    };
    if t.call_origins.len() > MAX_NAMES {
        return Err(AccountError::bound("too many call origins"));
    }
    for o in t.call_origins {
        out.call_origins.insert(o.rp, names(o.origins, "origins")?);
    }
    Ok(out)
}
fn item_of(i: CopyItem) -> R<CoreItem> {
    Ok(CoreItem {
        namespace: i.namespace,
        source_digest: i.source_digest,
        key: i.key,
        payload: json(&i.payload_json, "the item payload")?,
    })
}
fn members_of(m: Vec<MigratedMemberInput>) -> R<Vec<MigratedMember>> {
    list_len(&m, "members")?;
    Ok(m.into_iter()
        .map(|x| MigratedMember {
            id: x.id,
            label: x.label,
            kind: cv::member_kind_of(x.kind).to_string(),
            dropped: x.dropped,
        })
        .collect())
}

impl AccountEngine {
    fn written(&self, w: colophon_core::v05::engine::Written) -> Written {
        Written {
            stores: cv::store_list(&w.stores),
            changes: cv::changes(&w.changes),
            artifact: w.artifact,
        }
    }
    fn move_result(m: Moved) -> MoveResult {
        let none = |changes: Option<Changes>| MoveResult {
            stores: vec![],
            veto: None,
            frozen_entry: None,
            frozen_seq: None,
            succession_verified: false,
            changes,
        };
        match m {
            Moved::Frozen(f) => MoveResult {
                frozen_entry: Some(f.entry),
                frozen_seq: Some(f.seq),
                succession_verified: f.succession_verified,
                ..none(None)
            },
            Moved::Migration(c) | Moved::Shares(c) => none(Some(cv::changes(&c))),
        }
    }
    fn move_step(&self, p: colophon_core::v05::account::PendingMove) -> AccountMove {
        AccountMove::of_move(p)
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountEngine {
    /// Record every transition that is due, in the account's order, all or none. Each recording
    /// is a write: its bytes and paths to store.
    pub fn record_due(&self) -> Result<Vec<Written>, AccountError> {
        self.run(|e| {
            Ok(e.record_due()?
                .into_iter()
                .map(|w| self.written(w))
                .collect())
        })
    }
    /// Restrict the namespaces this engine reads (empty: all); those newly in scope are read now.
    pub fn set_read_scope(&self, namespaces: Vec<String>) -> Result<Changes, AccountError> {
        let n = names(namespaces, "namespaces")?;
        self.run(|e| Ok(cv::changes(&e.set_read_scope(n)?)))
    }
    /// Forget the vault seed, every epoch key and the device key, and the opened plaintext the
    /// account keeps. The engine then refuses to unlock, load or save: open a new one.
    pub fn lock(&self) -> Result<Changes, AccountError> {
        self.run(|e| Ok(cv::changes(&e.lock()?)))
    }
    /// Whether `lock` was called.
    pub fn is_locked(&self) -> Result<bool, AccountError> {
        self.run(|e| Ok(e.is_locked()))
    }
    /// Take a predecessor entry the host holds (F, or any) into the account.
    pub fn accept_predecessor_entry(
        &self,
        entry: Vec<u8>,
        now_ms: i64,
    ) -> Result<Changes, AccountError> {
        bytes_ok(&entry, 3 << 20, "an entry")?;
        self.run(|e| Ok(cv::changes(&e.accept_predecessor_entry(entry, now_ms)?)))
    }
    /// Where the Swift succession this account claims stands (§15.1).
    pub fn swift_succession(&self) -> Result<SwiftSuccession, AccountError> {
        self.run(|e| {
            let s = e.swift_succession()?;
            let st = &s.status;
            Ok(SwiftSuccession {
                stage: stage(s.stage),
                format: st.format.clone(),
                predecessor: st.predecessor.clone(),
                head_seq: st.head_seq,
                head_digest: st.head_digest.clone(),
                genesis_digest: st.genesis_digest.clone(),
                handover_count: st.handover_count as u64,
                authorized: st.authorized,
                vetoed: st.vetoed,
                verified_seq: st.verified.as_ref().map(|(s, _)| *s),
                verified_digest: st.verified.as_ref().map(|(_, d)| d.clone()),
                timing: st.timing.as_ref().map(|t| SuccessionTiming {
                    window_start_ms: t.window_start_ms,
                    window_end_ms: t.window_end_ms,
                    recovery_delay_s: t.recovery_delay_s,
                    veto_deadline_ms: t.veto_deadline_ms,
                    due_ms: t.due_ms,
                    quorum: t.quorum as u64,
                    homes: t.homes.clone(),
                    vetoers: t.vetoers.iter().cloned().collect(),
                    keys_needed: t.keys_needed as u64,
                }),
            })
        })
    }
    /// The verified Swift predecessor history this account holds.
    pub fn swift_predecessor(&self) -> Result<SwiftPredecessor, AccountError> {
        self.acct(|a| {
            let h = a.swift_predecessor()?;
            Ok(SwiftPredecessor {
                account: h.account.clone(),
                entries: h
                    .entries
                    .iter()
                    .map(|r| SwiftEntry {
                        seq: r.value.get("seq").and_then(Value::as_u64),
                        digest: r.digest.clone(),
                        issued_ms: r.issued_ms,
                        layout: r.value.get("layout").and_then(Value::as_u64),
                    })
                    .collect(),
            })
        })
    }
    /// Abort a pass with `home`: the outstanding request is forgotten and a late answer refused.
    pub fn exchange_abort(&self, home: String) -> Result<Report, AccountError> {
        self.run(|e| {
            let r = e.exchange_abort(&home)?;
            Ok(Report {
                store: cv::store_list(&r.store),
                changes: cv::changes(&r.changes),
                faults: r.faults.iter().map(super::engine::fault_of).collect(),
            })
        })
    }
    /// Faults of the record source the host must show (it changed bytes it must never change).
    pub fn source_faults(&self) -> Result<Vec<SourceFault>, AccountError> {
        self.run(|e| {
            Ok(e.source_faults()
                .iter()
                .map(|f| SourceFault {
                    path: f.path.clone(),
                    what: f.what.clone(),
                })
                .collect())
        })
    }
    /// The paths whose provider versions the next `refresh` wants, for one batched provider call.
    pub fn version_paths(&self, listing: Vec<String>) -> Result<Vec<String>, AccountError> {
        list_len(&listing, "the listing")?;
        self.run(|e| Ok(e.version_paths(&listing)))
    }
}

/// Methods with object arguments or results: one body, two signatures (UniFFI passes and returns
/// `Arc`, wasm-bindgen a reference and a value).
macro_rules! object_methods {
    ($(
        $(#[$m:meta])*
        fn $name:ident($s:ident; objs [$($o:ident : $ot:ident),*]; args [$($a:ident : $t:ty),*]) -> $ret:ty $body:block
    )*) => {
        #[cfg(feature = "native05")]
        #[uniffi::export]
        impl AccountEngine {
            $(
                $(#[$m])*
                pub fn $name(&$s $(, $o: Arc<$ot>)* $(, $a: $t)*) -> Result<$ret, AccountError> {
                    $(let $o: &$ot = &$o;)*
                    $body
                }
            )*
        }
        #[cfg(feature = "web05")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl AccountEngine {
            $(
                $(#[$m])*
                pub fn $name(&$s $(, $o: &$ot)* $(, $a: $t)*) -> Result<$ret, AccountError> {
                    $body
                }
            )*
        }
    };
}
/// The same, for methods that return an object.
macro_rules! object_returning {
    ($(
        $(#[$m:meta])*
        fn $name:ident($s:ident; objs [$($o:ident : $ot:ident),*]; args [$($a:ident : $t:ty),*]) -> $ret:ident $body:block
    )*) => {
        #[cfg(feature = "native05")]
        #[uniffi::export]
        impl AccountEngine {
            $(
                $(#[$m])*
                pub fn $name(&$s $(, $o: Arc<$ot>)* $(, $a: $t)*) -> Result<Arc<$ret>, AccountError> {
                    $(let $o: &$ot = &$o;)*
                    let r: Result<$ret, AccountError> = $body;
                    r.map(Arc::new)
                }
            )*
        }
        #[cfg(feature = "web05")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl AccountEngine {
            $(
                $(#[$m])*
                pub fn $name(&$s $(, $o: &$ot)* $(, $a: $t)*) -> Result<$ret, AccountError> {
                    $body
                }
            )*
        }
    };
}

object_methods! {
    /// Seal the opened vault seed to the confirmed pairing's device.
    fn transfer_seed(self; objs [pairing: AccountPairing]; args [entropy: Vec<u8>]) -> SealedSeed {
        let mut entropy = entropy;
        let r = guard(|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            pairing.with_confirmed(|p| {
                let b = self.run(|e| Ok(e.transfer_seed(p, seed)?))?;
                Ok(SealedSeed { enc: b.enc, ciphertext: b.ciphertext })
            })
        });
        wipe(&mut entropy);
        r
    }
    /// Open a sealed seed on the new device with its transfer key and the confirmed pairing; the
    /// engine then holds the seed and reads the records it reaches.
    fn accept_seed_transfer(self; objs [key: PairingTransferKey, pairing: AccountPairing]; args [sealed: SealedSeed]) -> Changes {
        guard(|| {
            bytes_ok(&sealed.enc, 65, "a point")?;
            bytes_ok(&sealed.ciphertext, 64, "a ciphertext")?;
            let b = SealedBox { enc: sealed.enc, ciphertext: sealed.ciphertext };
            b.validate_secret_box()?;
            pairing.with_confirmed(|p| {
                self.run(|e| Ok(cv::changes(&e.accept_seed_transfer(&key.k, &b, p)?)))
            })
        })
    }
    /// Finish an import write of a copy plan as the item it was begun for; what it wrote is to be
    /// stored, and the plan records it.
    fn finish_swift_copy_write(self; objs [plan: SwiftCopyPlan, write: AccountCopyWrite]; args [signatures: Vec<Signature>]) -> Written {
        guard(|| {
            let sigs = cv::signatures(signatures)?;
            if write.owner != self.owner {
                return Err(AccountError::wrong_object("this write was begun on another session"));
            }
            let w = write.w.lock()?.take().ok_or_else(|| AccountError::consumed("this write is finished"))?;
            let mut p = plan.p.lock()?;
            let plan = p.as_mut().ok_or_else(|| AccountError::consumed("this plan is finished"))?;
            Ok(self.written(self.run(|e| Ok(e.finish_swift_copy_write(plan, w, sigs)?))?))
        })
    }
    /// Finish a step of the move on this engine (F, a copier's shares, a migration). F is
    /// returned as bytes for the host to append to the predecessor and is held as read.
    fn finish_move(self; objs [step: AccountMove]; args [signatures: Vec<Signature>]) -> MoveResult {
        guard(|| {
            let sigs = cv::signatures(signatures)?;
            let m = step.take_move()?;
            let moved = self.run(|e| Ok(e.finish_move(m, sigs)?))?;
            Ok(Self::move_result(moved))
        })
    }
}

object_returning! {
    /// The plan reconciled with what the account holds: the finished copy (`outcome` says what it
    /// holds). Consumes the plan.
    fn finish_swift_copy(self; objs [plan: SwiftCopyPlan]; args []) -> SwiftCopyResult {
        guard(|| {
            let p = plan.p.lock()?.take().ok_or_else(|| AccountError::consumed("this plan is finished"))?;
            let r = self.run(|e| Ok(e.finish_swift_copy(p)?))?;
            Ok(SwiftCopyResult { r })
        })
    }
    /// What the destination already holds of a copy of `library`.
    fn swift_copy_destination(self; objs []; args [library: String]) -> SwiftCopyDestination {
        guard(|| {
            let d = self.run(|e| Ok(e.swift_copy_destination(&library)?))?;
            Ok(SwiftCopyDestination { d })
        })
    }
    /// Prepare the owner's veto of this account's Swift succession (§15.1 step 3).
    fn begin_swift_veto(self; objs []; args [issued_ms: i64, signers: Vec<String>]) -> AccountMove {
        let s = names(signers, "signers")?;
        guard(|| self.run(|e| Ok(AccountMove::of_veto(e.begin_swift_veto(&SwiftVetoParams { issued_ms, signers: s })?))))
    }
    /// Prepare F (§15.1 step 5): the freezing `layout` entry of the Swift predecessor.
    fn begin_swift_freeze(self; objs []; args [signers: Vec<String>, issued_ms: i64]) -> AccountMove {
        let s = names(signers, "signers")?;
        guard(|| self.run(|e| Ok(self.move_step(e.begin_swift_freeze(Vec::new(), s, issued_ms)?))))
    }
    /// Seal the epochs a copying member is owed (§9.4). 32 fresh bytes (wiped).
    fn begin_swift_copier_shares(self; objs []; args [member: String, signers: Vec<String>, entropy: Vec<u8>]) -> AccountMove {
        let mut entropy = entropy;
        let r = guard(|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            let s = names(signers, "signers")?;
            self.run(|e| Ok(self.move_step(e.begin_swift_copier_shares(&member, &s, seed)?)))
        });
        wipe(&mut entropy);
        r
    }
    /// Prepare the `migration` transition from a finished copy (§15.4).
    fn begin_swift_migration(self; objs [copy: SwiftCopyResult]; args [members: Vec<MigratedMemberInput>, drain_from_ms: i64, drain_until_ms: i64, issued_ms: i64, signers: Vec<String>]) -> AccountMove {
        guard(|| {
            let m = members_of(members)?;
            let s = names(signers, "signers")?;
            self.run(|e| Ok(self.move_step(e.begin_swift_migration(&copy.r, m, drain_from_ms, drain_until_ms, issued_ms, s)?)))
        })
    }
    /// Begin the import write of one item of a plan, by this session's member (who holds the
    /// `import` term). 32 fresh bytes (wiped).
    fn begin_swift_copy_write(self; objs [plan: SwiftCopyPlan]; args [item: CopyItem, entropy: Vec<u8>]) -> AccountCopyWrite {
        let mut entropy = entropy;
        let r = guard(|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            let item = item_of(item)?;
            let p = plan.p.lock()?;
            let plan = p.as_ref().ok_or_else(|| AccountError::consumed("this plan is finished"))?;
            let w = self.run(|e| Ok(e.begin_swift_copy_write(plan, &item, seed)?))?;
            Ok(AccountCopyWrite { w: Cell::new(Some(w)), owner: self.owner })
        });
        wipe(&mut entropy);
        r
    }
}

// Links and calls: `begin_link` and `begin_call` prepare, `finish` returns the artifact.
impl AccountEngine {
    pub(crate) fn link_inner(
        &self,
        prior: Vec<ByteString>,
        to_signing: Vec<u8>,
        terms_json: String,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> R<AccountAction> {
        guard(|| {
            list_len(&prior, "prior links")?;
            let prior: Vec<Vec<u8>> = prior.into_iter().map(|b| b.bytes).collect();
            let terms = json(&terms_json, "terms")?;
            let p = self.run(|e| {
                Ok(e.account()
                    .begin_link(&prior, &to_signing, terms, not_before_ms, expires_ms)?)
            })?;
            Ok(AccountAction::ready(p, self.owner, "link"))
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn call_inner(
        &self,
        key: Vec<u8>,
        links: Vec<ByteString>,
        audience: String,
        purpose: String,
        args_json: String,
        target: CallTarget,
        entropy: Vec<u8>,
    ) -> R<AccountAction> {
        let mut entropy = entropy;
        let r = guard(|| {
            let sd = seeds32(&entropy, 1)?;
            list_len(&links, "links")?;
            let links: Vec<Vec<u8>> = links.into_iter().map(|b| b.bytes).collect();
            let args = json_or_null(&args_json, "args")?;
            let t = target_of(target)?;
            let p = self.run(|e| {
                Ok(e.account()
                    .begin_call(&key, &links, &audience, &purpose, args, sd[0], t)?)
            })?;
            Ok(AccountAction::ready(p, self.owner, "call"))
        });
        wipe(&mut entropy);
        r
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// Prepare a link (§12): `prior` the chain so far, `to_signing` the next key, `terms_json`
    /// the narrowed terms. No entropy. `finish` returns the link envelope as `artifact`.
    pub fn begin_link(
        &self,
        prior: Vec<ByteString>,
        to_signing: Vec<u8>,
        terms_json: String,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<Arc<AccountAction>, AccountError> {
        self.link_inner(prior, to_signing, terms_json, not_before_ms, expires_ms)
            .map(Arc::new)
    }
    /// Prepare a call (§12) with `key` over `links` for `audience` and `purpose`; the verifier's
    /// configuration is `target`. 32 bytes of entropy (the request ID). `finish` returns the call
    /// envelope as `artifact`.
    pub fn begin_call(
        &self,
        key: Vec<u8>,
        links: Vec<ByteString>,
        audience: String,
        purpose: String,
        args_json: String,
        target: CallTarget,
        entropy: Vec<u8>,
    ) -> Result<Arc<AccountAction>, AccountError> {
        self.call_inner(key, links, audience, purpose, args_json, target, entropy)
            .map(Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    /// Prepare a link (§12). No entropy. `finish` returns the link envelope as `artifact`.
    pub fn begin_link(
        &self,
        prior: Vec<ByteString>,
        to_signing: Vec<u8>,
        terms_json: String,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<AccountAction, AccountError> {
        self.link_inner(prior, to_signing, terms_json, not_before_ms, expires_ms)
    }
    /// Prepare a call (§12). 32 bytes of entropy. `finish` returns the call envelope as `artifact`.
    pub fn begin_call(
        &self,
        key: Vec<u8>,
        links: Vec<ByteString>,
        audience: String,
        purpose: String,
        args_json: String,
        target: CallTarget,
        entropy: Vec<u8>,
    ) -> Result<AccountAction, AccountError> {
        self.call_inner(key, links, audience, purpose, args_json, target, entropy)
    }
}

#[allow(dead_code)]
fn _unused(_: Prepared, _: &OperationHeader, _: &EcdhOutput) {
    let _ = decode_base64;
}
