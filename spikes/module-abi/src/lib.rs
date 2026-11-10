//! Disposable, import-free WASM adapter of the *existing* pure notes reducer.
//! Experimental ABI (not an amendment to the Colophon 0.5 specification):
//! alloc(n: i32)->i32, release(ptr:i32,len:i32)->(), initial()->i64,
//! apply(state_ptr:i32,state_len:i32,op_ptr:i32,op_len:i32)->i64,
//! query(state_ptr:i32,state_len:i32,name_ptr:i32,name_len:i32,
//!       args_ptr:i32,args_len:i32)->i64.
//! An i64 result packs length in its upper 32 bits and pointer in its lower
//! 32 bits. Zero means invalid input / no result. The caller owns EVERY
//! allocation and must release inputs and returned buffers, including initial.
//! The adapter does not bypass signature/admission validation: operations
//! supplied here are assumed already admitted (same as Reducer::apply).
use colophon_core::{
    domain::Reducer,
    domains::notes::{Notes, NotesState},
    model::OperationView,
    records::canonical,
};
use serde_json::Value;

const MAX_JSON: usize = 16 * 1024 * 1024;

/// A reference implementation of the pure reducer boundary, used by native
/// fixture generation as well as the WASM exports.
pub fn initial_bytes() -> Result<Vec<u8>, String> {
    canonical(&NotesState::default()).map_err(|e| e.to_string())
}
pub fn apply_bytes(state: &[u8], op: &[u8]) -> Result<Vec<u8>, String> {
    if state.len() > MAX_JSON || op.len() > MAX_JSON {
        return Err("input exceeds 16 MiB".into());
    }
    let mut state: NotesState = serde_json::from_slice(state).map_err(|e| e.to_string())?;
    let operation: OperationView = serde_json::from_slice(op).map_err(|e| e.to_string())?;
    Notes.apply(&mut state, &operation);
    let result = canonical(&state).map_err(|e| e.to_string())?;
    if result.len() > MAX_JSON {
        return Err("result exceeds 16 MiB".into());
    }
    Ok(result)
}
pub fn query_bytes(state: &[u8], name: &[u8], args: &[u8]) -> Result<Vec<u8>, String> {
    if [state.len(), name.len(), args.len()].iter().any(|&n| n > MAX_JSON) {
        return Err("input exceeds 16 MiB".into());
    }
    let state: NotesState = serde_json::from_slice(state).map_err(|e| e.to_string())?;
    let name = std::str::from_utf8(name).map_err(|e| e.to_string())?;
    let args: Value = serde_json::from_slice(args).map_err(|e| e.to_string())?;
    let result = Notes.query(&state, name, &args).map_err(|e| e.to_string())?;
    let bytes = canonical(&result).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_JSON {
        return Err("result exceeds 16 MiB".into());
    }
    Ok(bytes)
}

// A WebAssembly linear-memory pointer is a 32-bit integer. These raw pointers
// are intentionally isolated in the disposable adapter, not colophon-core.
fn write_buffer(bytes: Vec<u8>) -> u64 {
    if bytes.is_empty() || bytes.len() > MAX_JSON {
        return 0;
    }
    let n = bytes.len() as u32;
    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8 as u32;
    (u64::from(n) << 32) | u64::from(ptr)
}

#[no_mangle]
pub extern "C" fn alloc(len: u32) -> u32 {
    if len as usize > MAX_JSON {
        return 0;
    }
    // A zero-length logical slice still gets a real non-null allocation.
    let n = (len as usize).max(1);
    let bytes = vec![0u8; n].into_boxed_slice();
    Box::into_raw(bytes) as *mut u8 as u32
}

#[no_mangle]
pub unsafe extern "C" fn release(ptr: u32, len: u32) {
    if ptr == 0 || len as usize > MAX_JSON {
        return;
    }
    let n = (len as usize).max(1);
    let slice = std::ptr::slice_from_raw_parts_mut(ptr as *mut u8, n);
    drop(Box::from_raw(slice));
}

unsafe fn read<'a>(ptr: u32, len: u32) -> Option<&'a [u8]> {
    if ptr == 0 || len as usize > MAX_JSON {
        return None;
    }
    // SAFETY CONTRACT: the host must pass a live buffer allocated by alloc,
    // with EXACT length. No untrusted arbitrary pointers are permitted by this
    // scratch ABI. Production needs guest-side length/bounds validation.
    Some(std::slice::from_raw_parts(ptr as *const u8, len as usize))
}

#[no_mangle]
pub extern "C" fn initial() -> u64 {
    initial_bytes().map(write_buffer).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn apply(
    state_ptr: u32,
    state_len: u32,
    op_ptr: u32,
    op_len: u32,
) -> u64 {
    let (Some(state), Some(op)) = (read(state_ptr, state_len), read(op_ptr, op_len)) else {
        return 0;
    };
    apply_bytes(state, op).map(write_buffer).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn query(
    state_ptr: u32,
    state_len: u32,
    name_ptr: u32,
    name_len: u32,
    args_ptr: u32,
    args_len: u32,
) -> u64 {
    let (Some(state), Some(name), Some(args)) = (
        read(state_ptr, state_len),
        read(name_ptr, name_len),
        read(args_ptr, args_len),
    ) else {
        return 0;
    };
    query_bytes(state, name, args).map(write_buffer).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn native_adapter_matches_reducer_and_is_canonical() {
        let op = json!({"id":"r1","kind":"createNotebook","author":"writer","authorLabel":"Writer",
            "origin":"person","clock":1,"created":"2026-11-04T12:00:00Z",
            "payload":{"id":"b","title":"Book"}});
        let bytes = serde_json::to_vec(&op).expect("serialize");
        let output = apply_bytes(&initial_bytes().expect("initial"), &bytes).expect("apply");
        let mut native = NotesState::default();
        Notes.apply(&mut native, &serde_json::from_value(op).expect("operation"));
        assert_eq!(output, canonical(&native).expect("canonical"));
        assert_eq!(
            query_bytes(&output, b"noteCounts", b"{}").expect("query"),
            canonical(&Notes.query(&native, "noteCounts", &json!({})).expect("query")).expect("canonical")
        );
    }
}
