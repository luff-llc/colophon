//! Colophon 0.6, unfrozen draft (`spec/colophon-0.6-sessions.md`).
//!
//! `session` holds one member of one cell: the state machine (§S4–§S8), a pure, sans-IO model
//! over authenticated, opened plaintext frames; session keys and their delegations (§S2,
//! `session::keys`); the frame envelope, sealing, signatures and the receiver checks (§S3,
//! `session::wire`, `session::codec`); and the façade the bindings call
//! (`session::endpoint`). `bridge` is the carrier layer's bridging (§S9), which makes every
//! connected group of members fully reachable. Where the reference reading departs from the
//! draft text, see `docs/colophon-0.6-sessions-findings.md`; the wire is described in
//! `docs/colophon-0.6-sessions-wire.md`.

pub mod bridge;
pub mod session;
