# Draft-1 speaks-for vectors (not Colophon 0.5)

Each `*.json` file is a self-contained case with the verified-history snapshot, acting public key, proof envelopes, raw signed request body/signature, arguments and expected result. Signed body and envelope bytes are standard padded base64. The filenames are the case names. All keys are synthetic, derived from public fixture seeds `[21;32]` … `[39;32]`; **do not use them for real data**.

The generator is the test helper `crates/colophon-core/tests/legacy_draft1_conformance.rs`. To regenerate byte-for-byte:

```sh
COLOPHON_WRITE_V5_VECTORS=1 cargo test -p colophon-core --test legacy_draft1_conformance
```

Disk-only replay (with generator equivalence checks):

```sh
cargo test -p colophon-core --test legacy_draft1_conformance
```

The native suite checks both the exact result code and the unguarded bit for successful proofs. Existing 0.4 vectors are untouched.
