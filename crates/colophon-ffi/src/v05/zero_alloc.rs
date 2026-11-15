//! A global allocator that overwrites a block with zeros when it is freed.
//!
//! Why it exists. Every secret the host passes (an ECDH result, a share, a PRF output, a seed)
//! crosses the native boundary inside a transfer buffer that the UniFFI scaffolding allocates,
//! reads by copying, and frees without overwriting; the binding's own code cannot reach that
//! copy. Wiping at free time, for every block the process frees, closes the whole class: a freed
//! block no longer holds what it held. It is a thin wrapper over the system allocator, with no
//! dependency.
//!
//! What it guarantees: a block freed through `dealloc`, and the old block of a `realloc` that
//! moves, is zeroed before it returns to the system allocator. `realloc` is always
//! allocate, copy, zero the old block, free, so no grown buffer leaves its old contents behind.
//!
//! What it does not: memory that is still allocated (a live copy is the owner's to wipe), the
//! stack and registers, copies the host language makes in its own heap, pages the operating
//! system swaps out or includes in a core dump while a block is live, and a process that is
//! killed before the free.
//!
//! The cost is a `memset` per free and a copy per `realloc` (no in-place growth); it is measured
//! in `docs/bindings-05.md`.
//!
//! `set_observer` is test support: an observer sees every allocation and, for each free, the
//! block before and after the wipe. It must not allocate. Nothing is observed unless a test sets
//! one (a single relaxed load per call).
#![allow(unsafe_code)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// What an observer is told.
#[derive(Clone, Copy, Debug)]
pub enum Event {
    /// A block of this many bytes was allocated.
    Alloc(usize),
    /// A block of this many bytes is being freed.
    Free(usize),
    /// A block about to be freed, before the wipe: what a plain allocator would leave behind.
    /// Valid only during the call.
    BeforeWipe(*const u8, usize),
    /// The same block after the wipe.
    AfterWipe(*const u8, usize),
}

static OBSERVER: AtomicUsize = AtomicUsize::new(0);

/// Install (or clear) the observer. Test support: it must not allocate or call the engine.
pub fn set_observer(f: Option<fn(Event)>) {
    OBSERVER.store(f.map_or(0, |f| f as usize), Ordering::SeqCst);
}

#[inline]
fn observe(e: Event) {
    let o = OBSERVER.load(Ordering::Relaxed);
    if o != 0 {
        // SAFETY: only `set_observer` stores here, and it stores a `fn(Event)`.
        let f: fn(Event) = unsafe { std::mem::transmute::<usize, fn(Event)>(o) };
        f(e);
    }
}

/// Overwrite `len` bytes at `p` so the write is not removed as a dead store.
#[inline]
unsafe fn wipe(p: *mut u8, len: usize) {
    // SAFETY: the caller owns the block of `len` bytes at `p`.
    unsafe { std::ptr::write_bytes(p, 0, len) };
    std::hint::black_box(p);
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// An allocator that zeroes every block it frees, over `A`.
pub struct ZeroOnFree<A = System> {
    inner: A,
}
impl<A> ZeroOnFree<A> {
    /// Wrap `inner`.
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

// SAFETY: every method forwards to the inner allocator with the layouts it was given; the only
// addition is writing zeros to a block the caller has given back.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ZeroOnFree<A> {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        observe(Event::Alloc(l.size()));
        unsafe { self.inner.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        observe(Event::Alloc(l.size()));
        unsafe { self.inner.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        observe(Event::Free(l.size()));
        observe(Event::BeforeWipe(p, l.size()));
        unsafe { wipe(p, l.size()) };
        observe(Event::AfterWipe(p, l.size()));
        unsafe { self.inner.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        // Never in place: a moved block must not leave its old contents behind, and the inner
        // allocator does not say whether it moved.
        let Ok(nl) = Layout::from_size_align(new_size, l.align()) else {
            return std::ptr::null_mut();
        };
        let q = unsafe { self.alloc(nl) };
        if !q.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(p, q, l.size().min(new_size));
                self.dealloc(p, l);
            }
        }
        q
    }
}
