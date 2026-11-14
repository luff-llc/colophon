//! Shared helpers for the ported attack tests: a PRNG with no dependency (splitmix64).
#![allow(dead_code)]
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Test-only adapter: the old raw `verify_webauthn(…, OriginRule, Strictness)` call shape,
/// mapped onto the public, rule-bound `webauthn_check`. `General` is the call mode with the
/// asserted origin as the only call origin, so it tests the general rule alone.
pub mod webauthn {
    use colophon_core::v05::descriptor::{KeyDescriptor, WebAuthnKey};
    use colophon_core::v05::signature::{
        webauthn_check, AssertionBytes, AuthorityRule, CheckMode, SigFailure, WebAuthnOk,
    };
    #[derive(Clone, Copy, Debug)]
    pub enum OriginRule<'a> {
        Authority,
        General,
        Call(&'a [String]),
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Strictness {
        Current,
        SwiftPredecessor,
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify_webauthn(
        signing: &[u8],
        key: &WebAuthnKey,
        body: &[u8],
        sig: &[u8],
        a: AssertionBytes<'_>,
        uv: bool,
        rule: OriginRule<'_>,
        strict: Strictness,
    ) -> Result<WebAuthnOk, SigFailure> {
        let d = KeyDescriptor::new_webauthn(signing.to_vec(), key.clone())
            .map_err(|_| SigFailure::Point)?;
        let asserted: Vec<String> = serde_json::from_slice::<serde_json::Value>(a.client_data)
            .ok()
            .and_then(|v| {
                v.get("origin")
                    .and_then(|o| o.as_str())
                    .map(|o| vec![o.to_string()])
            })
            .unwrap_or_default();
        let mode = match (strict, rule) {
            (Strictness::SwiftPredecessor, _) => CheckMode::SwiftPredecessor { uv_required: uv },
            (_, OriginRule::Authority) => CheckMode::Authority {
                rule: AuthorityRule::Single,
                verification: uv,
                sign_controller: false,
            },
            (_, OriginRule::General) => CheckMode::Call {
                origins: &asserted,
                uv_required: uv,
            },
            (_, OriginRule::Call(o)) => CheckMode::Call {
                origins: o,
                uv_required: uv,
            },
        };
        webauthn_check(&d, body, sig, a, mode)
    }
}
