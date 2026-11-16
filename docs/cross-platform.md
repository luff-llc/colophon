# Cross-platform account journey (0.5)

The journey found a defect in **both SDKs**: a revoked member cold-opens with no epoch shares to
unlock, but the host must still call the core's `load()` before notices or exchange. Both wrappers
skipped it and reported `malformed: the engine has not loaded its records` instead of `denied`.
They now load once when there is nothing to unlock. Before the fix, the cross matrix had 6 passes
and 4 failures (all `public` cold reopens). `RevokedReopenTests` and `RevokedReopenTest` cover each
SDK with and without a pre-revocation checkpoint, using a controlled real home and an explicit exchange.
Both tests fail when their SDK’s load fix is locally reverted; restoring it makes them pass. No Rust, exports, spec, vectors or relay changed.

Run `scripts/test-cross.sh` on macOS with Bun, Swift, JDK 17 and Rust/wasm installed. It builds the
native library, home module and test-only drivers; checks a content hash of the current crates, workspace manifest and Cargo.lock against the local Apple
XCFramework’s build stamp, rebuilding with `scripts/build-apple.sh` if missing or stale. It prints the
decision and counts actual test results; a Swift filter matching no tests fails. Missing prerequisites fail. Its private Cargo target is deleted on exit; every
relay is owned by a tracked child process. Cleanup closes drivers and relays on exit, SIGINT and SIGTERM;
keys live in a private per-run directory, with file mode 0600. SIGKILL cannot run cleanup. No dependency was added.

The eight real-home journeys cover both creation directions (Swift → Kotlin and Kotlin → Swift),
`members` and `public` history, and one home/quorum 1 or two homes/quorum 2. Each proves:

- Pairing transfers the HPKE-sealed seed across SDKs. The joiner builds its controller slot and learns
  its member approval through the home. Private device/controller keys stay on their own devices.
- Both SDKs read each other's saved links, preserving UTF-8, combining marks, escapes and NUL.
  Seven encrypted operation files match byte for byte. Each direction delivers a 90,000-byte required
  blob automatically and a 20,000-byte optional blob on demand: 220,000 plaintext bytes per journey.
- Today the journey approves imported requests **without pairing the request’s signing key**. This
  violates spec §9.1; confirmed-pairing approval is being fixed in another package (core, exports and
  sessions). The separate seed-transfer ceremony does not prove paired member approval. The second
  device approves a third device of the other SDK; the first revokes it. Refusal codes
  must be exactly `refused:revoked`, and the revoked device reads no new content.
- Swift proposes a pending policy change that Kotlin displays and vetoes, and vice versa. Each
  proposer’s verified ledger must record a new `vetoed` outcome.
- All three devices save, lock, exit and cold-reopen from their own files. Current members sync and
  read again, including the blobs. Under `members`, the third stays `ready`, surfaces a home’s
  unverified `remoteCallRefused("refused:revoked")` issue, and reads only its existing content. Under
  `public`, verified revocation records make it `denied` and local reads fail. Both outcomes are exact
  assertions on both SDKs, before and after reopen. Account/member IDs persist.

Homes are the real `bun relay/server.js` with the Rust home module. Anonymous feed reads must return
401, even with public history. Only transport destinations are mapped to loopback; signed-call
bytes, audiences and home decisions remain real. The test drivers hold each home’s private signing key
and sign the home’s account request on its behalf; this synthetic provisioning is not an independent
home-key custody test. The joiner receives pre-approval authority history
out of band, including the creator's sealed slot, as in the existing single-SDK journeys. Its own
slot, approval, content and private state are not copied. Its controller is declared at genesis and
signs possession in its own process. Its new slot reaches the home before the approver appends approval.

Two additional cross-runtime tests compare exact QR/commitment bytes for identical fixture inputs,
verify matching six-digit codes against §7.3's hash formula, and reject wrong codes/accounts,
noncanonical QR bytes, mismatched commitments and reused reveals. Actual ceremonies/retries use fresh
keys and nonces. The account journeys also prove wrong-code seed transfer fails without storing a slot.
Both SDKs exercise the persisted five-failures/hour limit; confirmed wrong-pairing seed acceptance
uses valid points and must fail without writing a slot.

Harness checks additionally cover missing/stale framework provenance, empty Swift filters, dynamic
result counts, ignored session errors, private key-file permissions and SIGINT/SIGTERM cleanup.

A home’s unsigned HTTP refusal cannot establish account revocation: the Rust exchange exposes it as
`Unauthorized`, without preserving its result code. The sessions additionally surface the exact
`refused:revoked` response only for this device’s authenticated request, end that home’s pass, and keep
local access governed by verified records. A lying home can stop its own sync, but cannot wipe keys or
turn the session `denied`; another home can still provide verified records.

This proves SDK interoperability on macOS (CryptoKit Swift and JCA/JVM Kotlin), not physical iPhone or
Android hardware. The drivers are test-only, outside shipped products. Software custody and file stores
are used; Swift uses the existing `FolderMedium(coordinated: false)` test seam, retaining its journal
and file lock. Secure Enclave, Keystore, passkeys, cameras/UI, iCloud/file coordination, background/mobile
lifecycle, seed/E memory erasure, adversarial networks, relay crash recovery and other domains remain unproven here. A saved
file and correct restart do not prove every cache avoided replay. All data is synthetic and temporary.
