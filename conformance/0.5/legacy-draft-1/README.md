# Draft-1 vectors: not Colophon 0.5

These vectors were generated for Galley's draft 1 of a "Colophon 0.5" speaks-for layer
(2026-11-10) and published on `main` as `conformance/0.5/speaks-for` and
`conformance/0.5/terms`. **They are not 0.5 vectors.** The 0.5 candidate
([spec/colophon-0.5.md](../../../spec/colophon-0.5.md)) contradicts them in several places
(changes §D and finding L1): for example `refused:stale` and the `unguarded` success bit no
longer exist, terms use `records` and `services` rather than `scope`, and `requires` is gone.

They were moved here unchanged (byte for byte) by step 0 of the implementation plan, together
with the module that replays them (`colophon_core::legacy_draft1`, formerly
`colophon_core::v5`). They keep replaying so that nothing published silently stops working:

```sh
cargo test -p colophon-core --test legacy_draft1_conformance
```

The 0.5 candidate vectors are in [`../candidate/`](../candidate/); the 0.5 engine is
`colophon_core::v05`.
