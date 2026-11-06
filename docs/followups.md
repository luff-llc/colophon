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
2. **Engine-supplied author kind and roles.** `reading.books` loans and `notes` proposal reviews
   fail closed until the engine passes the authenticated member kind and grant to reducers.
   Check: loan and review tests pass with real authority, refused for wrong roles.
3. **Historical conflict overlay and import evidence.** Domain importers emit import-evidence
   entries; the engine needs an encrypted evidence sidecar and an overlay for historical
   conflicts (docs/domains/README.md). Check: an importer round trip shows the evidence via a
   query.
4. **Blob descriptors.** Transcripts, retained originals and archives need the blob contract
   (encrypted, content-addressed, grant-checked) in the engine and storage layer.
5. **Android packaging.** No Android SDK/NDK on the build machine; `scripts/build-android.sh`
   is unrun. Check: AAR built and the Kotlin journey passes on an emulator.
