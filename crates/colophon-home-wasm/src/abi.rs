//! The plain C ABI: pointers and lengths only.
//!
//! The host allocates the request with [`colophon_alloc`], writes it, calls [`colophon_home`],
//! reads the 4-byte little-endian length at the returned pointer and that many bytes after it,
//! and frees both with [`colophon_free`] (the request with its length, the response with the
//! length plus four).
#![allow(unsafe_code)]

use crate::ops::handle;

/// Allocate `len` zeroed bytes in this module's memory. Free with [`colophon_free`], same `len`.
#[no_mangle]
pub extern "C" fn colophon_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len.max(1)].into_boxed_slice()) as *mut u8
}

/// Free memory from [`colophon_alloc`] or a [`colophon_home`] result.
///
/// # Safety
/// `ptr` must come from this module and `len` must be what it was allocated or returned with
/// (for a result, the length prefix plus four); it must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn colophon_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr,
            len.max(1),
        )));
    }
}

/// Run one request. Returns a pointer to `u32 length (LE)` followed by the response bytes.
///
/// # Safety
/// `ptr` must point to `len` readable bytes in this module's memory.
#[no_mangle]
pub unsafe extern "C" fn colophon_home(ptr: *const u8, len: usize) -> *mut u8 {
    let input = std::slice::from_raw_parts(ptr, len);
    let output = handle(input);
    let mut framed = Vec::with_capacity(output.len() + 4);
    framed.extend_from_slice(&(output.len() as u32).to_le_bytes());
    framed.extend_from_slice(&output);
    // A boxed slice has exactly its length as capacity, so `colophon_free(ptr, 4 + len)` is exact.
    Box::into_raw(framed.into_boxed_slice()) as *mut u8
}
