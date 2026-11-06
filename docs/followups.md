# Follow-ups found during verification

Each item has a source and a check that closes it.

1. **Fixed: explicit, retryable key-provider failure.** `SessionKeys` classifies provider
   errors at the public-key/sign/agreement boundary. Create, restore and signed enrollment
   request failures now produce `failed(.keysUnavailable(detail:))`; `retry()` retries the
   failed creation or refreshes restoration/enrollment with the same identity. The sample
   displays the reason and Retry. `KeyFailureTests` covers all three failure paths and recovery.
   Launch the sample with `--demo-key-failure`, choose Create library, then Retry to demonstrate
   this without Keychain entitlements or touching an existing sample library. Both sample
   platforms compile; interactive LaunchServices/device verification remains an unrestricted
   acceptance check (the restricted host refused to launch the built app).
2. **Implemented: authenticated author context.** Schema 3 already supplied member kinds;
   schema 4 supplies authority-derived kind, grant and root role on every engine path. Books
   loans and notes reviews have real-authority acceptance/rejection, replay and checkpoint tests;
   local signing/tool filtering also enforce their fences.
3. **Implemented: encrypted import evidence and historical alternatives.** Root-signed atomic
   source units synchronize namespace-encrypted evidence, output bindings and explicit alternatives.
   Bounded `importEvidence`/`historicalAlternatives` queries recheck grants. ColophonMigration uses
   the sidecar, publishes earlier-prefix outcome differences and retains native state. Exact-set
   historical acknowledgment is available; automatic correction and the app repair UI remain host
   work. See [engine contract](engine.md#engine3-authenticated-import-storage-and-blobs).
4. **Implemented: blob descriptors and storage seam.** Streaming 64 KiB encrypted chunks,
   content addresses, signed manifests, current grant checks, live reference counts and distinct
   availability outcomes are exposed through core/native host interfaces. Swift folder storage
   separates lazy blob bytes from record snapshots. Format/anchor validation and actual iCloud/
   mobile acceptance remain app/host gates; originals are never garbage-collected automatically.
5. **Android packaging.** No Android SDK/NDK on the build machine; `scripts/build-android.sh`
   is unrun. Check: AAR built and the Kotlin journey passes on an emulator.
