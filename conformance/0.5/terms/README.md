# Colophon 0.5 bounded terms conformance

Each `*.json` file contains a named `parse`, `narrow`, `purpose` or `condition` probe and an expected result. The committed cases exercise every field in §6.1, each narrowing constraint, predicate operators and both sides of predicate-count, nesting and canonical-size bounds.

Regenerate both vector groups with the opt-in fixture helper:

```sh
COLOPHON_WRITE_V5_VECTORS=1 cargo test -p colophon-core --test v5_conformance
```

Replay without writes: `cargo test -p colophon-core --test v5_conformance`.

The generator emits canonical JSON and compares the on-disk cases against freshly derived values on every replay. All inputs are synthetic.
