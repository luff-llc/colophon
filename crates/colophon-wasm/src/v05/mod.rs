//! The 0.5 wasm exports. The surface is the very source `colophon-ffi` compiles (`api/`),
//! included here, so the two cannot drift; this file adds only what a browser forces: the JS
//! record source, how an error is thrown, and the engine's constructor.
use wasm_bindgen::prelude::*;

#[path = "../../../colophon-ffi/src/v05/api/mod.rs"]
pub mod api;
pub use api::*;

#[wasm_bindgen]
extern "C" {
    /// A JavaScript object the host supplies: `read(path) -> Uint8Array`, `version(path) ->
    /// string` (empty for none) and `readBlob(path) -> Uint8Array` (empty: not held). Each
    /// throws to say it cannot answer. They are synchronous and must not call the engine.
    pub type JsSource;
    #[wasm_bindgen(method, catch)]
    fn read(this: &JsSource, path: &str) -> Result<Vec<u8>, JsValue>;
    #[wasm_bindgen(method, catch)]
    fn version(this: &JsSource, path: &str) -> Result<String, JsValue>;
    #[wasm_bindgen(method, catch, js_name = readBlob)]
    fn read_blob(this: &JsSource, path: &str) -> Result<Vec<u8>, JsValue>;
}

struct JsHost(JsSource);
fn thrown(e: JsValue) -> AccountError {
    AccountError::host(
        e.as_string()
            .unwrap_or_else(|| "the host source threw".into()),
    )
}
impl HostSource for JsHost {
    fn read(&self, path: String) -> Result<Vec<u8>, AccountError> {
        self.0.read(&path).map_err(thrown)
    }
    fn version(&self, path: String) -> Result<String, AccountError> {
        self.0.version(&path).map_err(thrown)
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
        listing: String,
        identity: String,
        account: String,
        namespaces: String,
        batch: u64,
        saved: String,
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

/// What is thrown: a typed error with its protocol code, never a message to parse.
#[wasm_bindgen]
pub struct AccountFault {
    kind: String,
    code: String,
    detail: String,
}
#[wasm_bindgen]
impl AccountFault {
    /// `Malformed`, `BadSignature`, `NewerFormat`, `Unavailable`, `Refused`, `Host`,
    /// `Reentered`, `Consumed`, `WrongObject`, `Bound`, `Internal` or `Denied`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }
    /// The protocol result code (`refused:audience`, `badSignature`, ...) or the binding's own.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }
    /// A diagnostic for logs; never key material, never to be parsed.
    #[wasm_bindgen(getter)]
    pub fn detail(&self) -> String {
        self.detail.clone()
    }
}
impl From<AccountError> for JsValue {
    fn from(e: AccountError) -> JsValue {
        JsValue::from(AccountFault {
            kind: e.kind(),
            code: e.code(),
            detail: e.detail(),
        })
    }
}
