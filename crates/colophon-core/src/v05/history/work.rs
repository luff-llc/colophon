//! Counts of the expensive work done on the calling thread, for tests that bound it by counting
//! rather than timing: every [`verify_history`](super::verify_history) run, and every attempt to
//! build a recording entry (`prepare_activate`, `prepare_vetoed`, `prepare_final`, and their
//! [`VerifiedObjects`](crate::v05::write::authority::VerifiedObjects) forms). The counters exist
//! only with the `work-counters` feature; without it the hooks are empty and inlined away.

/// The work counted on this thread since the last [`reset`].
#[cfg(feature = "work-counters")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// `verify_history` runs.
    pub verifications: usize,
    /// Recording-entry build attempts.
    pub prepares: usize,
}

#[cfg(feature = "work-counters")]
thread_local! {
    static WORK: std::cell::Cell<Work> = const {
        std::cell::Cell::new(Work { verifications: 0, prepares: 0 })
    };
}

/// Zero this thread's counters.
#[cfg(feature = "work-counters")]
pub fn reset() {
    WORK.with(|w| w.set(Work::default()));
}

/// This thread's counters.
#[cfg(feature = "work-counters")]
pub fn get() -> Work {
    WORK.with(std::cell::Cell::get)
}

#[cfg(feature = "work-counters")]
pub(crate) fn verification() {
    WORK.with(|w| {
        let mut n = w.get();
        n.verifications += 1;
        w.set(n);
    });
}
#[cfg(feature = "work-counters")]
pub(crate) fn prepare() {
    WORK.with(|w| {
        let mut n = w.get();
        n.prepares += 1;
        w.set(n);
    });
}

#[cfg(not(feature = "work-counters"))]
#[inline(always)]
pub(crate) fn verification() {}
#[cfg(not(feature = "work-counters"))]
#[inline(always)]
pub(crate) fn prepare() {}

// Deterministic regression probes for effective pending-object selection.
#[cfg(test)]
thread_local! {
    pub(crate) static PENDING_CHECKS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}
