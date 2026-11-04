# Lessons for the portable core

Read against the shipped Swift implementation and the earlier Android profile and JNI bridge.
No Android or Swift source was changed.

1. **Return host work instead of calling back into the platform.** The Android bridge carried a
   thread-local JNI environment through synchronous identity callbacks, with manual buffer and
   exception handling. Explicit prepare/finish signing and ECDH steps work with asynchronous
   hardware and WebCrypto without platform thread assumptions.
2. **Agree on one wire signature and public-key format.** Android needed DER-to-P1363 signature
   conversion and X.509 wrapping around raw EC points. Use uncompressed P-256 points and 64-byte
   raw signatures at every core boundary, and verify stored bytes without re-encoding.
3. **Separate protocol state from file and sync state.** Android's completion checks had to bind
   library identity, selected profile, inventory snapshots, and verified ciphertext. The core
   accepts immutable records; hosts remain responsible for files, atomic persistence and transport.
4. **Make failure categories portable.** Platform protection failures, missing downloads, pending
   grants and revoked access are different. Return explicit protocol outcomes and keep host key
   failures observable, rather than collapsing all errors into an empty bridge response.
5. **Use shared fixtures instead of porting app history.** Legacy imports and app-specific domain
   kinds multiplied the Android surface. Version 0.2 has one Rust evaluator, clean kinds, and
   deterministic cross-host fixtures; Swift and the 0.1 vectors remain historical references.
6. **Recover data, not just authority.** Preserve every epoch's recovery seal, keep known writes
   on revocation, and reshare keys before planned handover. These are tested protocol invariants,
   independent of any keystore or storage adapter.
