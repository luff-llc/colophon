# Cross-platform account journey (0.5)

The journey found a defect in **both SDKs**: a revoked member cold-opens with no epoch shares to
unlock, but the host must still call the core's `load()` before notices or exchange. Both wrappers
skipped it and reported `malformed: the engine has not loaded its records` instead of `denied`.
They now load once when there is nothing to unlock. Before the fix, the cross matrix had 6 passes
and 4 failures (all `public` cold reopens). `RevokedReopenTests` and `RevokedReopenTest` cover each
SDK with and without a pre-revocation checkpoint. No Rust, exports, spec, vectors or relay changed.

Run `scripts/test-cross.sh` on macOS with Bun, Swift, JDK 17 and Rust/wasm installed. It builds the
native library, home module and test-only drivers; reuses a local Apple XCFramework or builds it
with `scripts/build-apple.sh`; and runs ten Bun tests, five Kotlin pairing tests and four reopen
regression cases. Missing prerequisites fail. Its private Cargo target is deleted on exit; every
relay PID is recorded, and any leftover is killed and makes the script fail. No dependency was added.

The eight real-home journeys cover both creation directions (Swift → Kotlin and Kotlin → Swift),
`members` and `public` history, and one home/quorum 1 or two homes/quorum 2. Each proves:

- Pairing transfers the HPKE-sealed seed across SDKs. The joiner builds its controller slot and learns
  its member approval through the home. Private device/controller keys stay on their own devices.
- Both SDKs read each other's saved links, preserving UTF-8, combining marks, escapes and NUL.
  Seven encrypted operation files match byte for byte. Each direction delivers a 90,000-byte required
  blob automatically and a 20,000-byte optional blob on demand: 220,000 plaintext bytes per journey.
- The second device approves a third device of the other SDK; the first revokes it. Refusal codes
  must be exactly `refused:revoked`, and the revoked device reads no new content.
- Swift proposes a pending policy change that Kotlin displays and vetoes, and vice versa.
- All three devices save, lock, exit and cold-reopen from their own files. Current members sync and
  read again, including the blobs; the third stays refused or denied. Account/member IDs persist.

Homes are the real `bun relay/server.js` with the Rust home module. Anonymous feed reads must return
401, even with public history. Only transport destinations are mapped to loopback; signed-call
bytes, audiences and home decisions remain real. The joiner receives pre-approval authority history
out of band, including the creator's sealed slot, as in the existing single-SDK journeys. Its own
slot, approval, content and private state are not copied. Its controller is declared at genesis and
signs possession in its own process. Its new slot reaches the home before the approver appends approval.

Two additional cross-runtime tests compare exact QR/commitment bytes for identical fixture inputs,
verify matching six-digit codes against §7.3's hash formula, and reject wrong codes/accounts,
noncanonical QR bytes, mismatched commitments and reused reveals. Actual ceremonies/retries use fresh
keys and nonces. The account journeys also prove wrong-code seed transfer fails without storing a slot.
Kotlin's five unit tests additionally exercise the persisted five-failures/hour limit and misbound seeds.

This proves SDK interoperability on macOS (CryptoKit Swift and JCA/JVM Kotlin), not physical iPhone or
Android hardware. The drivers are test-only, outside shipped products. Software custody and file stores
are used; Swift uses the existing `FolderMedium(coordinated: false)` test seam, retaining its journal
and file lock. Secure Enclave, Keystore, passkeys, cameras/UI, iCloud/file coordination, background/mobile
lifecycle, adversarial networks, relay crash recovery and other domains remain unproven here. A saved
file and correct restart do not prove every cache avoided replay. All data is synthetic and temporary.
