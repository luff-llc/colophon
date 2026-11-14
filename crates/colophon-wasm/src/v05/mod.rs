//! The 0.5 wasm exports. The surface is the very source `colophon-ffi` compiles (`api/`),
//! included here, so the two cannot drift; this file adds only what a browser forces: the JS
//! record source, how an error is thrown, and the engine's constructor.
use wasm_bindgen::prelude::*;

#[path = "../../../colophon-ffi/src/v05/api/mod.rs"]
pub mod api;
pub use api::*;

/// The zero-on-free allocator, the very source `colophon-ffi` compiles.
#[path = "../../../colophon-ffi/src/v05/zero_alloc.rs"]
pub mod zero_alloc;
#[cfg(feature = "zero-on-free")]
#[global_allocator]
static ALLOCATOR: zero_alloc::ZeroOnFree = zero_alloc::ZeroOnFree::new(std::alloc::System);

#[wasm_bindgen]
extern "C" {
    /// A JavaScript object the host supplies: `read(path) -> Uint8Array` and
    /// `readBlob(path) -> Uint8Array` (empty: not held). Each throws to say it cannot answer;
    /// the message reaches the caller as a `Host` error. They are synchronous and must not
    /// call the engine, and must not wait on anything that does. A return that is not a
    /// `Uint8Array` (a `Promise`, `undefined`, an array, a string) is a `Host` error that names
    /// the callback: nothing is coerced.
    pub type JsSource;
}

#[wasm_bindgen(inline_js = r#"
export class AccountFault extends Error {
  constructor(kind, code, detail, reason) {
    super(detail);
    this.name = 'AccountFault';
    this.kind = kind;
    this.code = code;
    this.detail = detail;
    this.reason = reason;
  }
}
export function makeFault(kind, code, detail, reason) { return new AccountFault(kind, code, detail, reason); }
function describe(v) {
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  if (typeof v.then === 'function') return 'a Promise (the callback must be synchronous)';
  if (Array.isArray(v)) return 'an Array';
  return typeof v === 'object' ? (v.constructor && v.constructor.name) || 'an object' : typeof v;
}
function bytes(name, v) {
  if (!(v instanceof Uint8Array)) {
    throw new TypeError(`the host callback ${name} must return a Uint8Array synchronously, not ${describe(v)}`);
  }
  return v;
}
export function callRead(src, path) { return bytes('JsSource.read', src.read(path)); }
export function callReadBlob(src, path) { return bytes('JsSource.readBlob', src.readBlob(path)); }
export function callTranslate(tr, op) {
  const v = tr.translate(op);
  if (v === null || v === undefined || typeof v !== 'object' || typeof v.then === 'function'
      || typeof v.__wbg_ptr !== 'number' || v.__wbg_ptr === 0) {
    throw new TypeError(`the host callback JsTranslator.translate must return a SwiftBatch that was not used before, not ${describe(v)}`);
  }
  return v;
}
export function messageOf(e) {
  if (e instanceof Error) return e.message;
  if (typeof e === 'string') return e;
  return 'the host source threw';
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = makeFault)]
    fn make_fault(kind: &str, code: &str, detail: &str, reason: Option<String>) -> JsValue;
    #[wasm_bindgen(js_name = callRead, catch)]
    fn call_read(src: &JsSource, path: &str) -> Result<Vec<u8>, JsValue>;
    #[wasm_bindgen(js_name = callReadBlob, catch)]
    fn call_read_blob(src: &JsSource, path: &str) -> Result<Vec<u8>, JsValue>;
    #[wasm_bindgen(js_name = callTranslate, catch)]
    fn call_translate(tr: &JsTranslator, op: SwiftOpInfo) -> Result<SwiftBatch, JsValue>;
    #[wasm_bindgen(js_name = messageOf)]
    fn message_of(e: &JsValue) -> String;
}

#[wasm_bindgen]
extern "C" {
    /// A JavaScript object that translates one Swift operation: `translate(op: SwiftOpInfo) ->
    /// SwiftBatch` (a thrown error omits the record with its message). It is synchronous and
    /// returns a fresh `SwiftBatch` (a `Promise`, `undefined` or one already passed to a call is
    /// a `Host` error naming `JsTranslator.translate`).
    pub type JsTranslator;
}
struct JsTr(JsTranslator);
impl SwiftTranslator for JsTr {
    fn translate(&self, op: SwiftOpInfo) -> Result<SwiftBatch, AccountError> {
        call_translate(&self.0, op).map_err(thrown)
    }
}
#[wasm_bindgen]
impl SwiftCopyPlan {
    /// Read the predecessor's files and plan the copy, translating each admitted Swift operation
    /// with the host's translator (none: the original kind and payload verbatim).
    pub fn read(
        source: &SwiftSource,
        files: Vec<Store>,
        translator: Option<JsTranslator>,
        destination: &SwiftCopyDestination,
    ) -> Result<SwiftCopyPlan, AccountError> {
        let t = translator.map(|t| Box::new(JsTr(t)) as Box<dyn SwiftTranslator>);
        Self::read_inner(source, files, t, destination)
    }
}

struct JsHost(JsSource);
fn thrown(e: JsValue) -> AccountError {
    AccountError::host(message_of(&e))
}
impl HostSource for JsHost {
    fn read(&self, path: String) -> Result<Vec<u8>, AccountError> {
        call_read(&self.0, &path).map_err(thrown)
    }
    fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError> {
        call_read_blob(&self.0, &path).map_err(thrown)
    }
}

#[wasm_bindgen]
impl AccountEngine {
    /// Open an engine over the host's source (see `docs/bindings-05.md`).
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        source: JsSource,
        listing: Vec<ListedPath>,
        identity: AccountIdentity,
        account: String,
        namespaces: Vec<String>,
        batch: u64,
        saved: SavedState,
        key: Vec<u8>,
        now_ms: i64,
    ) -> Result<AccountEngine, AccountError> {
        Self::open_inner(
            Box::new(JsHost(source)),
            listing,
            identity,
            account,
            namespaces,
            batch,
            saved,
            key,
            now_ms,
        )
    }
}

/// What is thrown is a real JS `Error` subclass (`AccountFault`) with `kind`, `code`, `detail`
/// and `reason` (the §19 reason of a `Refused` or `Denied`, else `undefined`): a typed error with
/// its protocol code, never a message to parse.
impl From<AccountError> for JsValue {
    fn from(e: AccountError) -> JsValue {
        make_fault(&e.kind(), &e.code(), &e.detail(), e.reason())
    }
}
