# Engine performance — stage 2, November 6, 2026

The storage-backed `Engine` meets all three measured desktop timing targets: **78.2 ms**
for a fresh-process checkpoint open with 1% new records, **1.11 s** for a full
100k rebuild, and **0.746 ms** for a local write. These are medians of three runs, not tail-latency
guarantees. iPhone and Android hardware remain unmeasured. Existing `Library` methods stay source
compatible; applications must opt into `Engine<RecordSource>` for the fast cold-open path.

Record envelopes and full history views are no longer retained by the new engine. Its memory is
O(indexes + authority + reducer state + bounded content/batch buffers), **not strictly O(state)**.
The fresh cold process with 1% new records peaked at **98.2 MiB** with a disk-backed source.
The compatibility `Library::records() -> &Records` contract still retains complete history.

## Reproduction

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 cargo build --release -p colophon-core --examples
# Reuse the previous fixture, or generate it if absent (generation is not timed).
target/release/examples/bench 100000 /tmp/colophon-engine-100k.records --profile
# Full rebuild, unchanged cold open, real 1% suffix, local write and history/audit timings.
target/release/examples/storage_bench /tmp/colophon-engine-100k.records
# Independent process, disk source, including first-use verifier setup and new-record reads.
target/release/examples/storage_bench /tmp/colophon-engine-100k.records --cold-suffix
```

`storage_bench` writes three synthetic, device-local scratch artifacts for the independent run:
`/tmp/colophon-engine-v2.checkpoint`, `/tmp/colophon-engine-v2-suffix.records` (only 1,000 new
records), and `/tmp/colophon-engine-v2-suffix.expected.json`. Run the normal mode first with the
same fixture. The fresh process checks its resulting projection against that expected value and
asserts that fetched/decrypted record counts equal the suffix length. All keys and nonces in
these examples are deterministic **test material**, never suitable for production libraries.

Measure each memory case in a separate Python process on macOS:

```sh
python3 - <<'MEASURE'
import resource, subprocess
mode = '--cold-suffix' # also: --source-only, --cold-memory, --disk-memory
subprocess.run([
    'target/release/examples/storage_bench',
    '/tmp/colophon-engine-100k.records', mode
], check=True)
print('peak RSS bytes:', resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
MEASURE
```

Darwin reports `ru_maxrss` in bytes; it is the child's whole-process peak, not a live heap sample.
Process RSS inspection via `ps`, and `/usr/bin/time -l`'s clock query, are restricted in this
sandbox. The resource measurement above works. `--source-only` builds only the host file-offset
index/listing and initial authority setup. `--cold-memory` uses the same disk source with no
suffix. `--disk-memory` fully verifies/rebuilds through file reads without retaining source bytes.

For the portable serial diagnostic, build the `bench` example with `--no-default-features` and
run the same command. Rebuild with default features before comparing the native parallel timings.
No new benchmark framework, crypto dependency or platform provider is needed.

## Machine, fixture and timing boundary

- Apple M3 Max, 16 CPU cores (12 performance, 4 efficiency), 64 GB RAM; macOS 27.0.1, arm64.
  rustc 1.91.1 (`ed61e7d7e`), release/LTO and `CARGO_PROFILE_RELEASE_OPT_LEVEL=3`. No target-CPU
  override. The repository's default size-focused WASM release profile is unchanged.
- Same 100,000-operation fixture used at `302db73`: 89,999 podcast positions, 4,000 episode
  updates, 4,000 saved links, 1,999 note edits, one notebook and one initial note. Four writers,
  three grants and one revocation preserving 25,000 writes, with rotations of all namespaces.
- 100,009 total paths, 89,681,974 stored bytes. Projection: about 940 episodes, 4,000 saved
  links and one notebook/note. The new checkpoint is **17,126,601 bytes**, versus 1,539,944 bytes
  for the three old projection-only checkpoints: it additionally persists authenticated indexes
  and admission/authority evidence. It contains no epoch secret keys or historical payload cache.
- The suffix is 1,000 genuinely signed/encrypted new owner writes, bringing the total to 101,000
  operations. Authority is unchanged, all new operations append after the namespace tail, and
  all required epoch keys are supplied in one batch. No synthetic verification bypass is used.
- Timers cover `Engine::open`, host software ECDH and `finish_unlock_many`, including core
  listing comparison, cache authentication/deserialization, admission, signatures, decryption
  and reduction as needed. Hosts supply a listing and checkpoint bytes: directory enumeration,
  fixture loading/file-offset-index construction, reading the checkpoint file, and generation
  of the suffix are outside the timers. This is the engine contract, not total app-launch time.
- Normal benchmark reads come from an in-memory host source. Independent `--cold-suffix` runs
  use fresh processes and a disk-backed source, with no warmed optimized generator/key tables;
  their timers include fetching the 1,000 new envelopes. Filesystem caches are warm. These
  measurements do not claim cold physical-storage or iCloud enumeration latency.

## Before and after

Stage 1 is the committed `302db73` run recorded in the previous handoff. Stage 2 engine rows are
medians and observed ranges from three recorded runs. The old checkpoint baseline had **zero** new
records; the stricter new cold-open gate includes a 1% suffix.

| Measurement | Stage 1 | Stage 2 | Target |
| --- | ---: | ---: | --- |
| Full 100k rebuild, host source in memory | 17,798.004 ms | **1,111.243 ms** (1,061.620–1,344.308) | <1,500 ms, met |
| Checkpoint open + 1% new records, fresh process/disk source | 18,201.985 ms even with zero new | **78.245 ms** (76.984–78.718) | <100 ms, met |
| Checkpoint open, unchanged records | 18,201.985 ms | **60.098 ms** (58.744–62.150) | <100 ms, met |
| Local write including software sign, in-memory persist, verify and apply | 0.595 ms | **0.746 ms** (0.683–0.751) | <2 ms, met |
| Checkpoint open + 1%, in-memory source/fresh engine instance | Not measured | 76.547 ms (76.502–77.568) | <100 ms, met |
| Serialize the new authenticated index/state checkpoint | 6.153 ms for projection-only caches | 46.858 ms (45.144–48.030) | Host schedules persistence |
| First lazy 50-operation history page, including its ordering index | No bounded lazy history path | 4.123 ms (4.100–4.127) | No numeric gate |

An additional final confirmation run measured **1,169.611 ms** for full rebuild, **82.040 ms**
for fresh-process disk cold open with 1% new records, and **0.754 ms** for the local write. It
also met every timing gate and is reported separately from the three-run statistics above.

A separate disk-source full rebuild took **1,139.776 ms**, including record seeks and reads.
The first history query builds a compact ordering index; later pages reuse it. Numeric path clocks
are parsed once for sorting, and changed record sets explicitly invalidate that history index.
The sample 128-record background audit took **33.712 ms** (one final run), using the independent
standard verifier; this pass includes large authority records. A record-count limit is not a
hard latency limit.

Work counters establish that the checkpoint skips the intended work:

| Startup | Record fetches | Verified operation headers | Payload opens | Reducer applications |
| --- | ---: | ---: | ---: | ---: |
| Full rebuild | 100,015 (authority read twice for a coherent-read check) | 100,000 | 100,000 | 100,000 |
| Unchanged checkpoint | **0** | **0** | **0** | **0** |
| Checkpoint + 1% suffix | **1,000** | **1,000** | **1,000** | **1,000** |

The unchanged cold path JSON-parses checkpoint **state/metadata**, not historical operation
headers or plaintext. A later 50-operation history query fetches/decrypts only those 50 envelopes.
In the benchmark it retains 11,536 encoded plaintext bytes under its 64 KiB cache limit. Tests
also cover zero historical fetches, cache hits, byte-budget eviction and oversized-cache bypass
behavior through the bounded-cache contract.

## Memory

| Process/harness | Peak RSS bytes | Peak RSS |
| --- | ---: | ---: |
| Stage 1 compatibility benchmark (historical) | 653,508,608 | 623.2 MiB |
| Stage 2 compatibility benchmark, same harness | 691,503,104 | 659.5 MiB |
| Disk-source/listing/authority-setup baseline | 49,889,280 | 47.6 MiB |
| Storage-backed unchanged cold process | 95,977,472 | 91.5 MiB |
| Storage-backed full rebuild, disk source | 175,652,864 | 167.5 MiB |
| Storage-backed fresh cold process + 1% (largest of three) | 102,973,440 | 98.2 MiB |

These are whole-process peaks, including the host source/index, checkpoint input, allocator
retention and result comparisons. They are **not** directly comparable live engine heap sizes;
subtracting the baseline is not a reliable heap attribution. The legacy benchmark also creates
full history-bearing views for independent reducer comparison and retains all source bytes.
Its memory contract is deliberately unchanged, and parallel ingest temporarily adds buffers.

The new engine retains path/digest/namespace/admission indexes, authenticated duplicate IDs,
clocks and capped-author spend sets, parsed authority, reducer state and a bounded LRU history
cache. It drops raw authority bytes after their coherent-read check too. It processes at most
8,192 records at once and opens payload buffers in place. It does not retain original envelopes,
ciphertexts or full operation views between calls. `materialize_library()` is an explicit,
caller-owned O(history) escape hatch for the legacy ledger and administrative actions.

The raw-record/plaintext-retention blocker is removed for storage-backed hosts. Strictly
state-only memory remains impossible with these in-core exact membership/admission indexes;
those indexes still scale with record count. Reducer conflicts/invalid entries/tombstones and
authority keep sets can intrinsically grow with history. Individual record/object sizes are not
capped. Externalizing indexes is a separate future option, not a claimed result of this stage.

## Verification profiling and pinned-crate choices

The final standard-verifier sample of 2,000 records took **328.009 ms**, essentially unchanged
from stage 1's 327.546 ms. Envelope/header decode took 2.427 ms; AES-GCM opening 4.268 ms; plaintext
JSON 0.666 ms. Cryptography was the dominant original cost, not JSON.

The pinned sources were inspected directly: `p256` **0.13.2**, `primeorder` **0.13.6** and
`elliptic-curve` **0.13.8**. The `p256` feature list has no precomputed-table or alternative faster
field-arithmetic switch. Its field backend selects 32-bit or 64-bit Montgomery arithmetic by
pointer width. The pinned `primeorder` scalar multiplication constructs a 16-point table and
performs repeated doublings for each multiplication. No dependency version, field arithmetic,
secret signing/ECDH implementation or upstream feature selection changed.

The new public-input verifier caches 64 four-bit windows for the generator and each validated
public key, then evaluates the standard ECDSA `u1*G + u2*Q` equation using pinned RustCrypto
scalar/point operations. Inputs to indexed lookups are public signature/message scalars. Its
acceptance is differential-tested against the standard verifier for valid/high-S, altered-body,
altered-signature and malformed-scalar cases. Background audits use the standard implementation
independently. This is still a review-sensitive cryptographic composition change, not an upstream
acceleration feature or a claim of a new security audit.

Controlled configuration observations for the compatible `Library` path:

| Verification/header-admission configuration | 100k elapsed |
| --- | ---: |
| Stage 1 standard portable verifier, serial | 17,121.382 ms |
| Cached public-key tables, `--no-default-features` | 5,548.260 ms |
| Cached tables plus scoped native workers, final default run | 548.623 ms |

The serial diagnostic's full rebuild was 6,232.325 ms. The final parallel compatibility
`Library` rebuild was **1,279.026 ms**, with 730.384 ms spent unlocking/decrypting/reducing.
Its old `open_with_checkpoints` path still took **1,227.284 ms**: it does not adopt verified-prefix
trust implicitly. Local compatibility writes remained **0.551 ms** (podcast) and **0.406 ms**
(quiet notes namespace). A near-start insertion took 205.151 ms. Native apps need the new engine
API, not merely a new version-1 projection checkpoint.

Native independent record verification and payload opening use `std::thread::scope`, up to 16
workers, followed by ordered core admission/reduction. `wasm32` and builds without `parallel`
use the serial path. The duplicate-ID hash index uses fixed keys rather than `RandomState`, so
the core does not draw OS entropy. An optional trusted host batch verifier receives exact bytes
and public keys; the core still decides admission. No CryptoKit/Android provider is implemented
or included in these measurements.

## Validation and remaining integration gates

All 37 Rust tests pass with default features and with native parallelism disabled. The new tests
cover cache authentication/version/identity fallback, exact zero-read restoration, suffix-only
work, partial unlock, held/refused/invalid duplicate behavior, budgets, earlier arrivals,
revocation, authority changes, history parity/eviction, no-op merges, host callback failures,
background corruption, missing bytes, audit progress across appends, and preservation of
integrity evidence across invalidation.
Required clippy (`--workspace --all-targets -- -D warnings`), fmt, rebuilt JavaScript security/smoke
and exact Rust/WASM fixture parity pass. Existing wire/conformance fixture bytes are unchanged.

Remaining limits are explicit: the cache is a device-local trust optimization with delayed
shared-folder corruption detection until a fetch/audit; hosts must schedule audits and surface
sticky integrity errors. Authority changes, removed prefixes, earlier admissions and changed
key availability conservatively rebuild; the <100 ms gate applies to appendable suffixes with
unchanged authority. Administrative materialization can still allocate full history. Device-key
storage, production record sources, FFI/provider adapters, total app-launch I/O and mobile
hardware/power/tail latency remain host integration work. See [engine.md](engine.md) and
[the handoff](handoff-engine.md) for the contract and next-worker details.
