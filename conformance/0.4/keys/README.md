# Colophon 0.4 keys conformance vectors

All keys and seeds are public test secrets. `keys.json` publishes software seeds, private scalars, authenticator keys, kit and vault seeds. Byte strings in JSON use padded standard base64; record files preserve exact signed bytes.

Each case has `case.json` (description, normative sections, named outcome and an accept keyring summary), `records/`, `input.json` (host-only inputs), and `intermediates.json` (slot/part keys, PRF keys, ECDH and HPKE secrets, vault identity; epoch and share HPKE schedules for valid prefixes). COSE registration cases have an empty records directory and exact `input.cbor`: registration precedes authority. Empty directories may be absent in source distributions; the runner handles them. The registration PRF case attempts to publish a cryptographically valid slot without a verified get assertion.

`probe` selects authority replay, slot opening, history opening, registration, COSE parsing, or complete Library replay. A slot refuse case must replay authority successfully before attempting the failing opening. All other record cases replay the entire chain. Recovery rule failures are badSignature under §6.3. The newerFormat case appears in both §10 accept and refuse lists with the same mandated outcome.

Generate: `COLOPHON_WRITE_VECTORS=1 cargo test -p colophon-core --test keys_conformance`

Replay: `cargo test -p colophon-core --test keys_conformance`

Set PATH and CARGO_NET_OFFLINE as required by the handoff before cargo. Generation is opt-in; default tests only read published files. The runner checks all intermediates and final keyring summaries and checks completeness against the inventory below. `../library/` supplies the complete deterministic 0.4 library replacing the retired 0.3 library vector; the historical 0.3 tree is untouched.

## Case inventory

| Case | Spec sections | Outcome |
| --- | --- | --- |
| [genesis-one-raw](genesis-one-raw/case.json) | §4.2, §6.2, §6.3 | accept |
| [genesis-only](genesis-only/case.json) | §4.2, §6.2, §6.3 | accept |
| [genesis-threshold-two](genesis-threshold-two/case.json) | §3.3, §6.3 | accept |
| [seq-two-rekey](seq-two-rekey/case.json) | §5.1, §6.2 | accept |
| [passkey-grant](passkey-grant/case.json) | §3.3, §6.3, §7 | accept |
| [import-control-quorum](import-control-quorum/case.json) | §6.3, §7 | accept |
| [control-only-rekey](control-only-rekey/case.json) | §6.3 | accept |
| [recovery-add-approve-only](recovery-add-approve-only/case.json) | §6.3 | accept |
| [removal-with-rotation](removal-with-rotation/case.json) | §5.1, §6.2 | accept |
| [demotion-with-rotation](demotion-with-rotation/case.json) | §5.1, §6.2 | accept |
| [sealed-slot-open](sealed-slot-open/case.json) | §5.1, §5.2 | accept |
| [prf-slot-open](prf-slot-open/case.json) | §5.1, §5.2 | accept |
| [combined-slot-open](combined-slot-open/case.json) | §5.1, §5.2 | accept |
| [multi-label-origin](multi-label-origin/case.json) | §3.3 | accept |
| [android-origin](android-origin/case.json) | §3.3 | accept |
| [high-s-webauthn](high-s-webauthn/case.json) | §3.3 | accept |
| [low-s-webauthn](low-s-webauthn/case.json) | §3.3 | accept |
| [recovery-threshold-greater](recovery-threshold-greater/case.json) | §4.2 | accept |
| [slot-reorder-relabel](slot-reorder-relabel/case.json) | §6.2 | accept |
| [unknown-kind-control](unknown-kind-control/case.json) | §6.3 | newerFormat |
| [wrong-challenge](wrong-challenge/case.json) | §2.1, §3.3, §10 | badSignature |
| [wrong-rp-hash](wrong-rp-hash/case.json) | §2.1, §3.3, §10 | badSignature |
| [foreign-origin](foreign-origin/case.json) | §2.1, §3.3, §10 | badSignature |
| [origin-userinfo](origin-userinfo/case.json) | §2.1, §3.3, §10 | badSignature |
| [origin-port](origin-port/case.json) | §2.1, §3.3, §10 | badSignature |
| [cross-origin](cross-origin/case.json) | §2.1, §3.3, §10 | badSignature |
| [webauthn-create](webauthn-create/case.json) | §2.1, §3.3, §10 | badSignature |
| [up-missing](up-missing/case.json) | §2.1, §3.3, §10 | badSignature |
| [uv-missing](uv-missing/case.json) | §2.1, §3.3, §10 | badSignature |
| [duplicate-client-data](duplicate-client-data/case.json) | §2.1, §3.3, §10 | badSignature |
| [der-long-length](der-long-length/case.json) | §2.1, §3.3, §10 | badSignature |
| [der-extra-padding](der-extra-padding/case.json) | §2.1, §3.3, §10 | badSignature |
| [der-trailing](der-trailing/case.json) | §2.1, §3.3, §10 | badSignature |
| [der-non-minimal](der-non-minimal/case.json) | §2.1, §3.3, §10 | badSignature |
| [foreign-authenticator-key](foreign-authenticator-key/case.json) | §2.1, §3.3, §10 | badSignature |
| [threshold-unmet](threshold-unmet/case.json) | §6.3, §7 | badSignature |
| [mixed-role-signers](mixed-role-signers/case.json) | §6.3, §7 | badSignature |
| [single-rule-cosignatures](single-rule-cosignatures/case.json) | §6.3, §7 | badSignature |
| [layout-minority](layout-minority/case.json) | §6.3, §7 | badSignature |
| [unknown-kind-minority](unknown-kind-minority/case.json) | §6.3, §7 | badSignature |
| [unknown-kind-approve-only](unknown-kind-approve-only/case.json) | §6.3, §7 | badSignature |
| [import-single-rule](import-single-rule/case.json) | §6.3, §7 | badSignature |
| [invalid-extra-cosignature](invalid-extra-cosignature/case.json) | §3.1 | badSignature |
| [unknown-kind-unauthenticated](unknown-kind-unauthenticated/case.json) | §6.3 | badSignature |
| [controller-unknown-field-single-rule](controller-unknown-field-single-rule/case.json) | §6.3 | badSignature |
| [recovery-disabled](recovery-disabled/case.json) | §6.3 | badSignature |
| [recovery-add-control](recovery-add-control/case.json) | §6.3 | badSignature |
| [recovery-remove](recovery-remove/case.json) | §6.3 | badSignature |
| [recovery-demote](recovery-demote/case.json) | §6.3 | badSignature |
| [recovery-change-threshold](recovery-change-threshold/case.json) | §6.3 | badSignature |
| [recovery-change-recover-threshold](recovery-change-recover-threshold/case.json) | §6.3 | badSignature |
| [recovery-change-vault](recovery-change-vault/case.json) | §6.3 | badSignature |
| [removal-without-rotation](removal-without-rotation/case.json) | §6.2 | malformed |
| [demotion-without-rotation](demotion-without-rotation/case.json) | §6.2 | malformed |
| [agreement-change-without-rotation](agreement-change-without-rotation/case.json) | §6.2 | malformed |
| [slot-deletion-without-rotation](slot-deletion-without-rotation/case.json) | §6.2 | malformed |
| [vault-reuse-a-b-a](vault-reuse-a-b-a/case.json) | §2.3, §6.2 | malformed |
| [shares-without-vault-change](shares-without-vault-change/case.json) | §6.2 | malformed |
| [recovery-drops-duplicate-slot](recovery-drops-duplicate-slot/case.json) | §6.3 | badSignature |
| [controller-member-collision](controller-member-collision/case.json) | §2.3 | malformed |
| [member-vault-collision](member-vault-collision/case.json) | §2.3 | malformed |
| [shared-controller-agreement](shared-controller-agreement/case.json) | §2.3 | malformed |
| [signing-equals-agreement](signing-equals-agreement/case.json) | §2.3 | malformed |
| [combined-empty](combined-empty/case.json) | §2.2, §5.2 | malformed |
| [combined-one-part](combined-one-part/case.json) | §2.2, §5.2 | malformed |
| [combined-duplicate-controllers](combined-duplicate-controllers/case.json) | §2.2, §5.2 | malformed |
| [prf-raw-controller](prf-raw-controller/case.json) | §2.2, §5.2 | malformed |
| [sealed-ciphertext-size](sealed-ciphertext-size/case.json) | §2.2, §5.2 | malformed |
| [sealed-enc-size](sealed-enc-size/case.json) | §2.2, §5.2 | malformed |
| [prf-salt-size](prf-salt-size/case.json) | §2.2, §5.2 | malformed |
| [prf-box-size](prf-box-size/case.json) | §2.2, §5.2 | malformed |
| [combined-box-size](combined-box-size/case.json) | §2.2, §5.2 | malformed |
| [part-ciphertext-size](part-ciphertext-size/case.json) | §2.2, §5.2 | malformed |
| [part-salt-size](part-salt-size/case.json) | §2.2, §5.2 | malformed |
| [origins-https-prefix](origins-https-prefix/case.json) | §2.2, §5.2 | malformed |
| [rp-leading-hyphen](rp-leading-hyphen/case.json) | §2.2, §5.2 | malformed |
| [slot-foreign-vault-seed](slot-foreign-vault-seed/case.json) | §5.1 | vaultLocked |
| [wrong-prf-output](wrong-prf-output/case.json) | §5.2 | vaultLocked |
| [duplicate-body-name](duplicate-body-name/case.json) | §2.1 | malformed |
| [empty-cosignatures](empty-cosignatures/case.json) | §3.1 | malformed |
| [seq-two-not-rekey](seq-two-not-rekey/case.json) | §6.2 | malformed |
| [seq-two-incomplete-rekey](seq-two-incomplete-rekey/case.json) | §6.2 | malformed |
| [seq-two-wrong-epoch](seq-two-wrong-epoch/case.json) | §6.2 | malformed |
| [seq-two-missing-namespace](seq-two-missing-namespace/case.json) | §6.2 | malformed |
| [authority-three](authority-three/case.json) | §6.1, §9 | malformed |
| [import-agent](import-agent/case.json) | §7 | malformed |
| [import-server](import-server/case.json) | §7 | malformed |
| [import-read-only](import-read-only/case.json) | §7 | malformed |
| [import-expiry-equal](import-expiry-equal/case.json) | §7 | malformed |
| [import-expiry-before](import-expiry-before/case.json) | §7 | malformed |
| [imported-from-uppercase](imported-from-uppercase/case.json) | §6.2, §9 | malformed |
| [imported-from-short](imported-from-short/case.json) | §6.2, §9 | malformed |
| [imported-from-nonhex](imported-from-nonhex/case.json) | §6.2, §9 | malformed |
| [cose-extra-key](cose-extra-key/case.json) | §2.5 | malformed |
| [cose-duplicate-key](cose-duplicate-key/case.json) | §2.5 | malformed |
| [cose-trailing-bytes](cose-trailing-bytes/case.json) | §2.5 | malformed |
| [registration-prf-output](registration-prf-output/case.json) | §5.2, §8 | malformed |
| [operation-payload-null](operation-payload-null/case.json) | §2.1, §7 | accept |

## Coverage of every §10 bullet

| §10 accept bullet | Cases |
| --- | --- |
| Genesis with one raw controller | genesis-one-raw |
| Genesis with threshold 2 (raw plus WebAuthn) | genesis-threshold-two |
| Seq-2 rekey | seq-two-rekey |
| A passkey-signed grant | passkey-grant |
| An import grant under the control rule | import-control-quorum |
| Rekey signed by a control-only controller | control-only-rekey |
| Recovery only adds; approve-only addition below control quorum | recovery-add-approve-only |
| Removal with rotation; new vault reads history | removal-with-rotation |
| Demotion with rotation; demoted controller keeps a new slot | demotion-with-rotation |
| PRF, sealed and two-part combined slots opened | prf-slot-open, sealed-slot-open, combined-slot-open |
| Multi-label subdomain origin | multi-label-origin |
| Allowlisted Android origin | android-origin |
| High-S WebAuthn signature | high-s-webauthn (also low-s-webauthn) |
| Genesis-only library | genesis-only |
| recoverThreshold greater than threshold | recovery-threshold-greater |
| Slot reordering and relabeling without rotation | slot-reorder-relabel |
| Unknown kind signed under control rule (newerFormat) | unknown-kind-control |
| Null inside an operation payload | operation-payload-null (complete library in ../library/) |

| §10 refuse bullet | Cases |
| --- | --- |
| Wrong challenge | wrong-challenge |
| Wrong RP hash | wrong-rp-hash |
| Foreign origin | foreign-origin |
| Origin with user information or port | origin-userinfo, origin-port |
| crossOrigin true | cross-origin |
| webauthn.create | webauthn-create |
| UP missing | up-missing |
| UV missing where required | uv-missing |
| Non-minimal DER | der-non-minimal |
| Another controller's key | foreign-authenticator-key |
| Threshold unmet | threshold-unmet |
| Mixed-role signers | mixed-role-signers |
| Invalid extra cosignature | invalid-extra-cosignature |
| Cosignatures on a single-rule kind | single-rule-cosignatures |
| recoverThreshold 0 used for recovery | recovery-disabled |
| Recovery adding control below control quorum | recovery-add-control |
| Recovery removes, demotes, changes threshold or vault | recovery-remove, recovery-demote, recovery-change-threshold, recovery-change-recover-threshold, recovery-change-vault |
| Removal or demotion without rotation | removal-without-rotation, demotion-without-rotation |
| Vault reuse A→B→A | vault-reuse-a-b-a |
| Shares without vault change | shares-without-vault-change |
| Layout with one of two signatures | layout-minority |
| Import grant under single rule or to agent | import-single-rule, import-agent |
| Key in two principals: controller/member, member/vault | controller-member-collision, member-vault-collision |
| Empty or one-part combined slot | combined-empty, combined-one-part |
| Duplicate controllers in combined slot | combined-duplicate-controllers |
| PRF slot naming raw controller | prf-raw-controller |
| Wrong sizes | sealed-ciphertext-size, sealed-enc-size, prf-salt-size, prf-box-size, combined-box-size, part-ciphertext-size, part-salt-size |
| Slot opens seed for another vault | slot-foreign-vault-seed |
| Wrong PRF output | wrong-prf-output |
| Duplicate JSON names in body and clientData | duplicate-body-name, duplicate-client-data |
| COSE extra/duplicate keys or trailing bytes | cose-extra-key, cose-duplicate-key, cose-trailing-bytes |
| Empty cosignatures array | empty-cosignatures |
| Unauthenticated unknown kind gives badSignature | unknown-kind-unauthenticated |
| Authenticated unknown kind gives newerFormat | unknown-kind-control |
| Seq 2 not full rekey | seq-two-not-rekey, seq-two-incomplete-rekey, seq-two-wrong-epoch, seq-two-missing-namespace |
| 0.3 authority body | authority-three |
| Unknown kind signed by one approve controller | unknown-kind-approve-only |
| Unknown controller field under single rule | controller-unknown-field-single-rule |
| DER long-form length, trailing bytes, extra padding | der-long-length, der-trailing, der-extra-padding |
| Two controllers sharing agreement point | shared-controller-agreement |
| Signing equals agreement | signing-equals-agreement |
| Slot deletion without rotation | slot-deletion-without-rotation |
| Agreement change without rotation | agreement-change-without-rotation |
| Recovery drops duplicate slot | recovery-drops-duplicate-slot |
| PRF slot built from registration output (host check) | registration-prf-output |
| Origins entry starts with https: | origins-https-prefix |
| RP label starts with hyphen | rp-leading-hyphen |
| Import grant read-only, expires not after issued, server | import-read-only, import-expiry-equal, import-expiry-before, import-server |
| importedFrom not 32 lowercase hex | imported-from-uppercase, imported-from-short, imported-from-nonhex |
