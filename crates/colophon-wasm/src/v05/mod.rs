//! The 0.5 wasm exports. The surface is the very source `colophon-ffi` compiles (`api/`),
//! included here, so the two cannot drift; this file adds only what a browser forces: the JS
//! record source, how an error is thrown, and the engine's constructor.
use wasm_bindgen::prelude::*;

#[path = "../../../colophon-ffi/src/v05/api/mod.rs"]
pub mod api;
pub use api::*;

#[wasm_bindgen]
extern "C" {
    /// A JavaScript object the host supplies: `read(path) -> Uint8Array` and
    /// `readBlob(path) -> Uint8Array` (empty: not held). Each throws to say it cannot answer;
    /// the message reaches the caller as a `Host` error. They are synchronous and must not
    /// call the engine.
    pub type JsSource;
    #[wasm_bindgen(method, catch)]
    fn read(this: &JsSource, path: &str) -> Result<Vec<u8>, JsValue>;
    #[wasm_bindgen(method, catch, js_name = readBlob)]
    fn read_blob(this: &JsSource, path: &str) -> Result<Vec<u8>, JsValue>;
}

#[wasm_bindgen(inline_js = r#"
export class AccountFault extends Error {
  constructor(kind, code, detail) {
    super(detail);
    this.name = 'AccountFault';
    this.kind = kind;
    this.code = code;
    this.detail = detail;
  }
}
export function makeFault(kind, code, detail) { return new AccountFault(kind, code, detail); }
export function messageOf(e) {
  if (e instanceof Error) return e.message;
  if (typeof e === 'string') return e;
  return 'the host source threw';
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = makeFault)]
    fn make_fault(kind: &str, code: &str, detail: &str) -> JsValue;
    #[wasm_bindgen(js_name = messageOf)]
    fn message_of(e: &JsValue) -> String;
}

#[wasm_bindgen]
extern "C" {
    /// A JavaScript object that translates one Swift operation: `translate(op: SwiftOpInfo) ->
    /// SwiftBatch` (a thrown error omits the record with its message).
    pub type JsTranslator;
    #[wasm_bindgen(method, catch)]
    fn translate(this: &JsTranslator, op: SwiftOpInfo) -> Result<SwiftBatch, JsValue>;
}
struct JsTr(JsTranslator);
impl SwiftTranslator for JsTr {
    fn translate(&self, op: SwiftOpInfo) -> Result<SwiftBatch, AccountError> {
        self.0.translate(op).map_err(thrown)
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
        self.0.read(&path).map_err(thrown)
    }
    fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError> {
        self.0.read_blob(&path).map_err(thrown)
    }
}

#[wasm_bindgen]
impl AccountEngine {
    /// Open an engine over the host's source (see `docs/bindings-05.md`).
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        source: JsSource,
        listing: Vec<ListedPath>,
        identity: String,
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

/// What is thrown is a real JS `Error` subclass (`AccountFault`) with `kind`, `code` and
/// `detail`: a typed error with its protocol code, never a message to parse.
impl From<AccountError> for JsValue {
    fn from(e: AccountError) -> JsValue {
        make_fault(&e.kind(), &e.code(), &e.detail())
    }
}
