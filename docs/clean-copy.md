# Clean copy: an old library into a new 0.4 library

**Status:** plan, 2026-11-08. It implements spec §9 of [colophon-0.4-keys.md](../spec/colophon-0.4-keys.md).
The first library to copy is Mike's (the only one with a keyring set up). Backward
compatibility isn't required. What's required is a **clean, verified copy**, with the original
left untouched.

## Source

Mike's library is in iCloud Drive at
`~/Library/Mobile Documents/iCloud~org~luff~library/Documents/Library`. On 2026-11-08 it held
the following (file counts only; nothing was read):

| Folder | Files |
|---|---|
| `authority/` | 64 entries (keyring mode) |
| `requests/` | 8 |
| `ops/` | 1,562 operations from 6 authors |
| `blobs/` | 51 |

Every file was downloaded; there were no iCloud placeholders.

## Rules

1. **Never write to the source.** The tool first copies the folder to a private working
   directory (`ditto`, preserving bytes) and reads only that copy. It also records a digest
   manifest of the source before and after, and they must be equal.
2. **Read as a member, not as the root.** Proving possession of the old root isn't needed,
   because the copy doesn't claim to be the same library. That's the check that blocks restored
   phones (see the Galley spike).
3. **A dedicated, short-lived reader.** The tool creates a software member, "Clean copy (Mac)",
   and asks for read-only access to every namespace. Mike approves it once from his phone,
   and it's revoked after the copy. No app's keychain, Secure Enclave key or enrollment file is
   read or exported.
4. **Fail visibly.** Anything that can't be copied (unknown kinds, held or rejected records,
   unreadable blobs) is listed with its path and reason, never skipped silently.

## Steps

| Step | Work | Verified by |
|---|---|---|
| 1. Snapshot | `ditto` the source to `~/.local/share/colophon/clean-copy/<date>/source`, and write `source-manifest.json` (path → SHA-256) | Manifest of the iCloud folder before and after the run is identical |
| 2. Reader | Create the reader member and request read-only access to all namespaces. Mike approves on the phone. Wait for the grant and its key shares. | The reader opens every namespace with zero unreadable records |
| 3. Read | The 0.1 Swift verifier (`Replica.readComplete`, as in `SuiteLegacySource`, without the root check) produces `LegacyOperation`s for every namespace, in replica order, with exact signed-body digests | Counts per namespace and author match the replica's admitted plus held totals |
| 4. New library | Create a 0.4 library at a **new** location (`.../Documents/Library-0.4`, never inside the old folder). Genesis keyring: this Mac's owner key (`approve`, `control`), plus a passkey (`approve`, `recover`, PRF slot) registered fresh against `id.luff.works`, plus a new recovery kit (`recover`). | The genesis verifies; the vault opens from the passkey slot and from the kit |
| 5. Import | Give the copying member a short-lived `import` grant (control rule, spec §7). Publish `colophon.importBatch` units through `imports.rs` (0.3 §7.2), with source operation IDs and exact signed-body digests as encrypted evidence. Re-encrypt blobs under the new epochs, and keep their plaintext digests. | The folded views of every domain (reading.saved, reading.books, listening.podcasts, notes) are equal between the 0.1 fold and the 0.4 fold, compared as canonical JSON |
| 6. Report | Write `report.json` and `report.md`: counts, view digests, unresolved records with reasons, and the new library ID | Mike reviews the report |
| 7. Switch | Apps are pointed at the new library one at a time, by Mike. The old library stays readable and unchanged until he retires it. | Each app's acceptance journey passes on the new library |
| 8. Tidy | Revoke the reader member in the old library, and delete the private working directory | Revocation verified; directory gone |

Members, grants and agents aren't copied (§9). Each app and agent is approved again in the new
library with exactly the access it needs, which is also a chance to drop stale grants.

## What "views are equal" means

0.1 and 0.4 views can't be compared field by field: field names differ (books `author` versus
`creator`), revisions come from different operations, and destination authorship belongs to the
importer by design. A copy is verified by two checks.

1. **Accounting.** For every namespace, every source operation in replica order is either an
   admitted import child in the destination or listed as unresolved with its reason. Counts
   match per namespace and per source author. Nothing is silently dropped.
2. **Reference equality.** The tool runs the **same verified source snapshot** through the **same
   import transforms** into a fresh **in-memory** 0.4 library, with no folder storage, file
   publication, retries or blob re-encryption. It then compares that library's complete domain
   views with the persisted destination's, as canonical JSON per namespace (`viewDigest`).

   Before comparing, it removes **only** fields whose values come from destination operation
   identity, entropy or signer: revisions, operation and batch IDs, authorship and attribution
   of import children, and admission timestamps. That list is fixed in code per domain and
   printed in the report. Every other field must be byte-equal.

   This proves the persisted copy is exactly what the import transforms produce from the
   verified source. The transforms' own fidelity, 0.1 meaning to 0.4 meaning, is covered by the
   domain import tests in `crates/colophon-core`.

The report lists both checks per namespace, the normalized-field list, and every unresolved
record. `verified` is true only if both checks pass in every namespace.

## Where the code lives

- **Read side (0.1):** a small macOS command in the Colophon Swift reference package, beside
  `ColophonMigration`. It reuses `SuiteLegacySource`'s verified read with the root check
  removed. It's read-only by construction: it's handed a read-only `RecordStore` over the
  snapshot.
- **Write side (0.4):** Rust core, `imports.rs` plus the new keyring genesis, exposed through
  `colophon-ffi` so the same command can run.
- **Passkey registration** needs AuthenticationServices, so step 4 runs from the Mac app or a
  small signed helper that holds the `webcredentials:id.luff.works` association. The rest of
  the copy is headless.

## Order

The copy depends on the 0.4 keyring being implemented (Rust: verifier, writer, genesis) and on
the import contract accepting 0.4 destinations. It's the **first real consumer** of the 0.4
keyring, and its acceptance (step 5's view equality) is the keyring's integration test (S5).
