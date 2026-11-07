# Engine performance — Colophon 0.3

## Native session engine migration

November 7, 2026, this `engine-sessions` worktree. Actual `ColophonSession.restore()` and
`perform()` calls on the development arm64 Mac: Swift 6.4.2 in release configuration, Kotlin
on JDK 17 (2 GiB test heap), Rust 1.91.1 with release/LTO/opt-level 3. RustCrypto's accelerated
ARM AES/POLYVAL backends are enabled for both columns. These are single confirmation runs,
run sequentially after builds/tests. Process/JIT and filesystem caches are warm; **cold** means
new session/worker/engine objects, not a fresh OS process. No physical-device claim is made.

The before column uses test-only copies of the previous BindingSessionCore through the actual
session, holding the current worker/provider and current Rust build constant. It is a controlled
adapter comparison, not an untouched f5839c2 binary benchmark. That adapter has no persistent
engine checkpoint; the after column reopens a member-protected checkpoint written through the
session's `flushCheckpoint()`. The earlier Rust-only compatibility numbers below measure a
narrower boundary and must not be substituted for these end-to-end session measurements.

| Native session measurement | Swift before | Swift engine | Kotlin before | Kotlin engine |
| --- | ---: | ---: | ---: | ---: |
| 100k cold session reopen / checkpoint hit | 13,994.704 ms | 776.420 ms | 12,977.637 ms | 436.082 ms |
| 100k + 1,000 new immutable records | 17,433.904 ms | 841.964 ms | 22,875.502 ms | 429.806 ms |
| First passive podcast write after reopen | 31,243.455 ms | 5.911 ms | 30,283.626 ms | 14.966 ms |
| Notes write | 32,438.967 ms | 4.539 ms | 40,873.773 ms | 8.246 ms |
| Taupe-shaped open (no checkpoint) | 4.503 ms | 6.016 ms | 11.476 ms | 7.837 ms |

**The requested <150 ms checkpoint-open and <5 ms passive-write targets are missed on both
platforms.** Swift's checkpoint open is 18.0× faster than this session adapter baseline;
Kotlin's is 29.8× faster. Large compatibility views and ledger marshaling explain why the
before session numbers exceed the Rust-only adapter numbers. The small Swift Taupe case
regressed by 1.5 ms; engine/key-ticket setup has fixed cost. Do not infer mobile launch success
or steady-state/tail latency from one run. The oldest-supported-iPhone <500 ms target remains
unmeasured.

Both native harnesses assert **zero** covered operation reads, signature checks, decryptions
and reducer applications on checkpoint restoration. The independent 1% suffix run asserts
exactly **1,000** reads/verifications/decryptions/applications. Swift additionally asserts zero
immutable reducer applications for the passive write. Authority/ticket validation and current
key agreement still run. Passive preparation uses a single-episode projection; sessions no
longer build full namespace views or the complete ledger for launch/write receipts.

Fixture/store/key construction and content-version hashing are outside the timed region.
Inside are session journal/cache reads, path discovery and version inventory, FFI, checkpoint
opening/unlock, readiness publication, and (for writes) signing, private journal fsync, record
publication/readback and receipt checks. Records use built-in memory providers; private files
use the real filesystem. The 100k fixture has four domains; the 1,000-record suffix uses
explicit seeks. The Taupe shape follows one show, establishes one episode and publishes 10,000
passive samples: two immutable operations, one current live slot, and retained history evidence.
No first-screen rendering, secure hardware-key access or real folder-provider launch is timed.

Full path/version inventory, protected-cache decoding and known-path journal loading still
scale with record count. File providers still enumerate metadata during refresh/write; memory
providers implement complete change deltas. Explicit compatibility ledger/admin calls still
materialize history. Background checkpoint serialization is excluded from write latency;
records and pending-publication receipts are durable before `perform()` completes. See
[the handoff](handoff-engine-sessions.md) for API behavior and remaining work.

Reproduce after building the native artifacts (use the environment paths from the handoff/task):

```sh
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 SKIP_VISIONOS=1 bash scripts/build-apple.sh
bash scripts/bench-sessions.sh
```

The script generates signed fixtures when needed and runs both modes sequentially. Raw logs and
JVM XML reports are in `target/engine-sessions/{swift,kotlin}-{legacy,engine}.{log,xml}`;
[the checked-in result data](benchmarks/engine-sessions.json) records the measured boundary and
numbers. Full validation logs are retained in `target/engine-sessions/validation/`.

## Colophon 0.3 — November 7, 2026

Final measurements on the development arm64 Mac, Rust 1.91.1, release/LTO with
`CARGO_PROFILE_RELEASE_OPT_LEVEL=3`. These are single confirmation runs after the build/test jobs
completed, with uncontrolled/warm filesystem caching. They are not mobile launch timings, medians,
tail-latency guarantees or measurements of secure-key access. Logs: `target/v03-validation/`.

### 100k immutable operations

The four-domain fixture contains 100,000 immutable operations and 100,010 indexed records. The
1% suffix now explicitly uses deliberate seeks: passive positions would become live state in 0.3
and would no longer test 1,000 new immutable records. Fixture generation and listing construction
are excluded. Checkpoint timings measure the raw storage-engine checkpoint, including unlock;
the new optional encrypted private-envelope encoding/decoding and native session UI are excluded.

| Measurement | Colophon 0.3 | Earlier target |
| --- | ---: | ---: |
| Full rebuild including unlock | **1,335.215 ms** | <1,500 ms, met |
| Unchanged checkpoint open including unlock | **92.261 ms** | <100 ms, met |
| Local immutable write, software sign, memory persistence and apply | **0.899 ms** | <2 ms, met |
| In-memory checkpoint plus 1,000 new operations | 109.433 ms | <100 ms, missed |
| Fresh-process disk checkpoint plus 1,000 new operations | **116.858 ms** | <100 ms, missed |
| Checkpoint serialization | 102.995 ms | No gate |
| Lazy 50-operation history page | 6.271 ms | No gate |
| Independent 128-record audit | 33.991 ms | No gate |

The final checkpoint is **25,589,380 bytes**. It now includes namespaced paths, author/epoch and
provider-version bindings and playback ordering barriers. The previous engine3 checkpoint was
19,249,071 bytes; its fresh-process suffix measurement was 95.297 ms. The stronger 0.3 index does
not meet that earlier suffix-time target in this run. This is an explicit remaining performance
limit, not a failing correctness check or an assertion that the old gate remains satisfied.
A linear merge walk compares current and cached sorted listings; unchanged restoration reads,
verifies, decrypts and applies **zero** operation records. Both suffix runs read/verify/decrypt/apply
exactly **1,000** operations. Full rebuild verifies/decrypts/applies all **100,000** operations.
History fetches only the requested 50 payloads and retains 11,539 cache bytes. All projection and
work-counter assertions passed. RSS was not remeasured.

The separately rerun compatibility `Library` benchmark uses the same 100k fixture, but a different
API and checkpoint boundary. It reports **1,600.736 ms** for a full rebuild, **1,279.650 ms** for a
cold checkpoint open (which still verifies/decrypts records), and **96.452 ms** for a warm restore
after verification/decryption. A passive podcast write including signing and merge takes
**95.622 ms** with zero immutable reducer applications; a quieter notes write takes **0.542 ms**.
These adapter timings must not be substituted with the faster storage-engine results. At the 0.3 baseline, native
sessions used this adapter: removing unchanged body reads does not eliminate its projection
and merge CPU costs. Log: `target/v03-validation/bench-100k.log`.

### Taupe-shaped passive playback

Synthetic workload: follow one show, establish one episode, then publish **10,000 passive position
samples**. Before/after use the same commands and keys: implicit layout 1 stores samples as immutable
operations; layout 2 uses live state. Each cold open creates a new storage engine with no checkpoint,
authenticates authority, unlocks keys, verifies/decrypts opening records and prepares the current
state. Source maps/listings and fixture generation are outside timing; first UI/query rendering is
not timed. This is a shape comparison, not a production Taupe trace.

| Measurement | Immutable samples (layout 1) | Live samples (layout 2) |
| --- | ---: | ---: |
| Immutable `ops/` records | 10,002 | **2** |
| Current `state/` slots | 0 | **1** |
| Append-only `history/` evidence records | 0 | **10,000** |
| Opening operation/state paths | 10,002 | **3** |
| All stored records, including authority and evidence | 10,004 | 10,006 |
| Cold open | **143.115 ms** | **1.971 ms** |
| Total sample-write time | 4,142.103 ms | 5,909.767 ms |
| Opening operation signatures/decryptions | 10,002 | 3 |
| Immutable reducer applications | 10,002 | 2 |

Opening paths shrink **3,334×**, immutable operation count falls **99.98%**, and this cold-open run
is **72.6× faster**. Evidence is deliberately retained: total file count and signed publication work
do not disappear. Live publication is slower in this synthetic write loop because it preserves
history, verifies replacements and updates the slot. Deliberate actions or explicit references can
also retain live predecessors as immutable operations; this passive-only case does not exercise that
additional retention. Tests cover seeks, references, stale writers, revocation, expiry and rebuilding.

### Swift-side comparison supplied by Marginalia

Committed `apps/apple/docs/verification.md` at Marginalia HEAD
`6c29f3ea12ce4768c31dad39a8eeddd975e8dad0`, in the layout-2 acceptance record associated with the
`b93cc923` work, reports this separate **50,000-record** host benchmark:

| Swift Replica mode | Cold read | Persisted verified-cache read |
| --- | ---: | ---: |
| Legacy layout | 55,720 ms | 1,324 ms |
| Layout 2 | 13,799 ms | 710 ms |

Those persisted reads reopened/signature-checked zero old operation records; the layout-2 case
excluded 37,500 sibling-namespace records. They used fresh Replica objects on a Mac with uncontrolled
filesystem caching, not physical iPhone launches. The workload, cache representation and I/O boundary
differ from the Rust tests above; these are contextual comparisons, not a measured cross-language
speedup. At the 0.3 baseline, Rust native sessions used the compatible `Library` adapter, not persistent
storage-engine checkpoints. Their incremental-refresh tests asserted zero unchanged record-body reads.

Reproduce the 0.3 runs:

```sh
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 cargo build --release --offline -p colophon-core --examples
# Loads an existing fixture, or generates it when absent; generation is excluded.
target/release/examples/bench 100000 target/v03-validation/100k.records
target/release/examples/storage_bench target/v03-validation/100k.records
target/release/examples/storage_bench target/v03-validation/100k.records --cold-suffix
target/release/examples/taupe_bench 10000
```

The storage harness writes its temporary checkpoint/suffix files in `/tmp/colophon-engine-v2*`
(the historical harness filenames are local scratch paths, not the protocol version). The cold-suffix
command is a separate process. Historical measurements below are retained with their original scope.

## Engine3 final verification

Engine3 preserves all storage-backed desktop timing gates with reducer schema 4, authenticated
contexts, evidence/alternative projections, identity reservations and the lazy blob interface.
Final single-run measurements on the same synthetic four-domain 100k fixture, release opt-level 3:

| Measurement | Engine3 final | Target |
| --- | ---: | ---: |
| Full 100k rebuild including unlock | **1,391.915 ms** | <1,500 ms, met |
| Fresh-process disk checkpoint open plus 1,000 new operations | **95.297 ms** | <100 ms, met |
| Local write including software sign/persist(memory)/apply | **0.872 ms** | <2 ms, met |
| Unchanged checkpoint open including unlock | 73.696 ms | <100 ms, met |
| In-memory checkpoint plus 1% suffix | 90.937 ms | <100 ms, met |
| Checkpoint serialization | 90.190 ms | Host schedules persistence |
| First lazy 50-operation history page | 4.533 ms | No numeric gate |
| Independent 128-record audit | 34.142 ms | No numeric gate |

The checkpoint is 19,249,071 bytes. Work counters remain 100,000 verified/decrypted/applied for
full replay, zero fetches/verification/decryption/reduction for unchanged restoration, and exactly
1,000 for either suffix. The history page fetches only 50 payloads and retains 11,539 cache bytes.
The final cold disk process peaked at **128,581,632 bytes (122.6 MiB)**. The main harness peaked
at 358,203,392 bytes; unlike the independent cold run it also retains the fixture in memory.

The compatibility `Library` harness was separately rerun: 1,644.314 ms full rebuild,
1,245.521 ms checkpoint cold open (which still redoes historical cryptography), and 771,817,472
bytes peak process RSS. These are not the storage-backed engine's timing gates; apps must opt
into `Engine<RecordSource>` for the fast cold-open path. The native session remains the compatible
Library adapter. No 100k-import, large-blob throughput, mobile timing or production-library claim
is made by this existing workload.

Logs and the Python `os.wait4` RSS harness are in `.build/engine3-validation/`. `/usr/bin/time -l`
finished an earlier benchmark but then failed its sandbox-restricted `sysctl` query; it was replaced
by the documented child-resource method. These are single confirmation runs with warm filesystem
caches, not medians or tail-latency promises. Earlier measurements below are retained for history.

## Relay sync benchmark

November 7, 2026 (blobs branch). A local store of 100,003 records already in sync with a relay;
one new record is appended, then a pass runs. Release builds on the development Mac.

| Pass | Swift (`MemoryRecordStore`, in-process relay) | Kotlin JVM (`MemoryRecordStore`, reference Node relay) |
| --- | ---: | ---: |
| New process: load cursor + remote log, list, push 1 | 577 ms | 228 ms |
| Warm pass in the same process, push 1 | **26 ms** | **21 ms** |
| Local record bodies read | 1 (plus a one-time genesis check) | 1 (plus a one-time genesis check) |
| Whole-store reads (`read()`) | 0 | 0 |

Before this change every pass read every local record and rewrote the whole remote map. The new
process cost is dominated by loading 100k remembered remote paths; it is paid once per launch.
Reproduce with `COLOPHON_SYNC_BENCH=1 bash scripts/test-swift.sh -c release --filter
incrementalSyncPassIsProportionalToTheChange` and `COLOPHON_SYNC_BENCH=1 sdk/android/gradlew -p
sdk/android testDebugUnitTest --tests '*SessionBlobTest.incrementalSyncPass*'` (the Kotlin run
first pushes 100k records to the Node relay, about 30 minutes). Default runs use 5k/2k records and
assert the same work counters.

The storage-backed 100k gates were rerun after the schema-5 changes on a shared, loaded machine,
alternating with the previous commit's binary: rebuild 1,382–1,451 ms (previous 1,417–1,480),
local write 0.91–0.96 ms (previous 0.99–1.09), fresh-process disk checkpoint + 1% 99.5–107.2 ms
(previous 97.7–104.7 ms in the same session; 95.3 ms on the quieter November 6 run). No regression
was measured; the <100 ms cold gate is at the noise floor of the current machine load.

## Four-domain merge validation

The final merged engine meets all three desktop timing targets with `reading.books`,
`reading.saved`, `notes` and `listening.podcasts` registered **and exercised**. One final run
on the same host/release configuration, after builds and tests completed:

| Measurement | Final merged run | Target |
| --- | ---: | ---: |
| Full 100k rebuild, including unlock | **1,308.880 ms** | <1,500 ms, met |
| Fresh-process disk checkpoint open + 1,000 new operations | **92.215 ms** | <100 ms, met |
| Local write, software signing, in-memory host persistence and application | **0.809 ms** | <2 ms, met |
| Unchanged checkpoint open, including unlock | 71.251 ms | <100 ms, met |
| Checkpoint + 1% suffix, in-memory source | 88.424 ms | <100 ms, met |
| Checkpoint serialization | 87.874 ms | Host schedules persistence |
| First lazy 50-operation history page | 4.709 ms | No numeric gate |
| Independent background audit of 128 records | 34.170 ms | No numeric gate |

The new fixture keeps 100,000 operations, four writers, three grants, a revocation preserving
25,000 writes and namespace rotations. It adds books to genesis/grants and replaces part of the
old workload: 89,998 podcast positions, 4,000 episode updates, 4,000 saved captures, 1,000 note
edits, one notebook, one initial note, one book and 999 book positions. There are 100,009 paths
and 89,645,618 envelope bytes. This is a separate fixture from the historical three-domain run;
it is synthetic engine-load coverage, not a scale test of every domain command or blob workflow.

The final checkpoint is **19,116,119 bytes**. Full rebuild fetched 100,015 records (the authority
coherence reads are included), verified/decrypted/applied 100,000 operations, and retained zero
history-cache bytes. Unchanged restoration fetched/verified/decrypted/applied **zero** records.
Both suffix runs fetched/verified/decrypted/applied exactly **1,000** new operations. Lazy history
then opened only 50 requested payloads and retained 11,539 bytes under the 64 KiB cache budget.
Projection comparisons and all work-counter assertions passed. The memory contract remains
O(indexes + authority + projection + bounded content/batch buffers); historical RSS figures below
were not remeasured for this merged workload.

The first merged measurement failed the gates: 1,985.553 ms rebuild, 186.726 ms fresh-process
suffix open, and a 38,971,192-byte checkpoint. Saved shelf indexes duplicated ordering strings
across filter buckets; podcast reports repeatedly copied projections and rebuilt unchanged
indexes. The final implementation shares ordering keys, compacts item columns and identical
index memberships in local snapshots, and reconstructs derived shelf rows from retained state
in parallel during restore. Podcast updates reuse projection fields, retain exact canonical
prefix bytes and use a schema-equivalent typed playback validator. Ordered admission still
runs centrally; independent namespace reductions can run concurrently inside the same bounded
batch, preserving each namespace's order. No checks, conflicts, extensions or retained originals
were discarded to achieve these timings.

Intermediate measurements were used to diagnose the regression. Before the final parallel row
restoration change, a fixed three-process cold series was 102.537, 100.646 and 99.574 ms (median
100.646 ms), still over target; it is not included in the final result above. The final table is
one confirmation run, not a median or tail-latency guarantee. Existing timing exclusions and the
warm-filesystem-cache limitation below still apply. No conformance vectors were regenerated.

## Reproduction

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 cargo build --release -p colophon-core --examples
# Reuse the four-domain fixture, or generate it if absent (generation is not timed).
target/release/examples/bench 100000 /tmp/colophon-engine-four-domains-100k.records --profile
# Full rebuild, unchanged cold open, real 1% suffix, local write and history/audit timings.
target/release/examples/storage_bench /tmp/colophon-engine-four-domains-100k.records
# Independent process, disk source, including first-use verifier setup and new-record reads.
target/release/examples/storage_bench /tmp/colophon-engine-four-domains-100k.records --cold-suffix
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
    '/tmp/colophon-engine-four-domains-100k.records', mode
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

## Historical stage-2 baseline

The following stage-2 summary and before/after tables predate the four-domain integration.
Use the merged measurements above for the current code.

The storage-backed `Engine` meets all three measured desktop timing targets: **78.2 ms**
for a fresh-process checkpoint open with 1% new records, **1.11 s** for a full
100k rebuild, and **0.746 ms** for a local write. These are medians of three runs, not tail-latency
guarantees. iPhone and Android hardware remain unmeasured. Existing `Library` methods stay source
compatible; applications must opt into `Engine<RecordSource>` for the fast cold-open path.

Record envelopes and full history views are no longer retained by the new engine. Its memory is
O(indexes + authority + reducer state + bounded content/batch buffers), **not strictly O(state)**.
The fresh cold process with 1% new records peaked at **98.2 MiB** with a disk-backed source.
The compatibility `Library::records() -> &Records` contract still retains complete history.

## Historical machine, fixture and timing boundary

- Apple M3 Max, 16 CPU cores (12 performance, 4 efficiency), 64 GB RAM; macOS 27.0.1, arm64.
  rustc 1.91.1 (`ed61e7d7e`), release/LTO and `CARGO_PROFILE_RELEASE_OPT_LEVEL=3`. No target-CPU
  override. The repository's default size-focused WASM release profile is unchanged.
- Historical 100,000-operation fixture used at `302db73`: 89,999 podcast positions, 4,000 episode
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

## FFI

Measured November 6, 2026 on the arm64 macOS host in the `ffi` worktree. Rust stable 1.91.1,
Swift 6.4.2 / Xcode 27.2, JDK 17, Kotlin 2.2.21, JNA 5.18.1, UniFFI 0.32.2. CPU model access
is denied by this sandbox. Rust uses the workspace release profile (`opt-level = "s"`, LTO);
Swift uses `-c release`. These historical measurements used the pre-incremental public core of the
`ffi` worktree; they were not remeasured during the engine/domain merge.

| Path | Query median | Write median | Query difference vs Rust | Write difference vs Rust |
| --- | ---: | ---: | ---: | ---: |
| Native Rust + query JSON | 5.067 ms | 10.860 ms | +0.000 ms / +0.0% | +0.000 ms / +0.0% |
| Rust binding facade (no language ABI) | 5.073 ms | 10.920 ms | +0.006 ms / +0.1% | +0.061 ms / +0.6% |
| Swift generated ABI | 5.473 ms | 11.606 ms | +0.405 ms / +8.0% | +0.746 ms / +6.9% |
| Kotlin/JNA ABI | 5.525 ms | 11.755 ms | +0.457 ms / +9.0% | +0.895 ms / +8.2% |

Each cell is the median of three independent run medians. Each run uses 100 queries and 50
writes against the same fixed history: one notebook and 20 notes. Query is `notes__read`,
including JSON serialization on both native Rust and FFI paths. Write is prepare `addNote`,
verify/commit a precomputed valid signature, and retrieve the admitted operation. Every write
starts with a freshly restored, unlocked copy of the fixture; restoration is outside timing.
The seed and signature are deliberately reused only on those independent benchmark copies,
never on a continuing production library. Assertions and result inspection are outside timing.

Host ECDSA signing, ECDH, entropy generation, clocks, disk I/O, cold open, and UI work are
excluded. The same Rust signature verification, sealing, admission, and domain evaluation
remain inside the measured work. This isolates the transport path from differing Rust,
CryptoKit, Keystore, and JCA signing implementations. The Swift sample measures actual
UniFFI calls, not an in-Rust stand-in; the JVM sample crosses JNA after 200 query warmups and
10 discarded write warmups. It does not include an app coroutine dispatcher or Swift actor hop.

Observed per-run query medians ranged 5.061–5.326 ms in native Rust, 5.467–5.694 ms in Swift,
and 5.503–5.537 ms in Kotlin. Write medians ranged 10.847–11.044 ms, 11.586–11.886 ms, and
11.743–11.770 ms respectively. Treat the deltas as costs of the complete wrapper/ABI path,
including conversion and build/code-generation differences, rather than an isolated foreign
function call instruction. The host was shared with other work, so small differences are
noise-sensitive; these are not mobile-device latency claims.

At this history size the complete Swift/JVM paths add about 0.4–0.5 ms per query and
0.7–0.9 ms per write. The much smaller in-Rust facade delta separates adapter work from the
actual foreign-language transport. The current core's repeated full evaluation dominates;
these results neither establish the engine's future 100k-operation targets nor measure its
planned narrow query/checkpoint API. Small domain queries should replace whole namespace
reads when that public API is available.

Reproduce after `bash scripts/build-apple.sh`:

```sh
bash scripts/bench-ffi.sh
```

The harness is `crates/colophon-ffi/examples/ffi_bench.rs`, Swift's `PerformanceTests`, and
Kotlin's `PerformanceTest`. It writes only `target/ffi-bench/`. To repeat without recompiling,
run the Rust example binary, then `COLOPHON_FFI_BENCH=1 bash scripts/test-swift.sh --skip-build
-c release --filter PerformanceTests` and `COLOPHON_FFI_BENCH=1 bash scripts/test-kotlin.sh
--tests '*PerformanceTest' --rerun`. The three measured run medians are preserved in
`crates/colophon-ffi/benchmarks/2026-11-06.json`; build/test logs are local artifacts under
`target/ffi-validation/`.

<!-- End FFI measurements; keep engine sections separate when merging. -->
