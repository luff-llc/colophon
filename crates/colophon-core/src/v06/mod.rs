//! Colophon 0.6, unfrozen draft (`spec/colophon-0.6-sessions.md`).
//!
//! Only the session state machine (§S4–§S8) is here so far: a pure, sans-IO model of one
//! member of one cell over already authenticated and opened plaintext frames. Session keys
//! (§S2), the frame envelope, sealing and signatures (§S3) and carriers (§S9) are later layers.
//! Where the reference reading departs from the draft text, see
//! `docs/colophon-0.6-sessions-findings.md`.

pub mod session;
