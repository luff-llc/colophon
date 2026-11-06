# Follow-ups found during verification

Each item has a source and a check that closes it.

1. **Silent create failure without Keychain access.** An unsigned simulator build of the sample
   left the session in `noLibrary` when key creation failed; nothing was shown. Fails closed but
   silently. Fix: key-provider failures in `create`, `restore` and `request` move the session to
   `failed(.keysUnavailable)` with a retry, and the sample shows it. Check: a unit test with a
   failing key provider, then the unsigned sample shows the error.
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
