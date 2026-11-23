//! Colophon 0.6, unfrozen draft (`spec/colophon-0.6-sessions.md`).
//!
//! The session state machine (§S4–§S8) is here: a pure, sans-IO model of one member of one
//! cell over already authenticated and opened plaintext frames, and the carrier layer's
//! bridging (§S9, `bridge`), which makes every connected group of members fully reachable. Session keys
//! (§S2), the frame envelope, sealing and signatures (§S3) and carriers (§S9) are later layers.
//! Where the reference reading departs from the draft text, see
//! `docs/colophon-0.6-sessions-findings.md`.

pub mod bridge;
pub mod session;
