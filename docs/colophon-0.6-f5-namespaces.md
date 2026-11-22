# Colophon 0.6 post-genesis namespaces

`namespace.add` is an immediate signed authority entry. It uses the
`colophon/authority/5` envelope, the usual `seq`, `previous`, `issued` and `by`
fields, and one kind-specific field, `epochs`. Each element has the §11.1 shape
`{"namespace":"game.foundry","epoch":1,"seals":{"<vault ID>":{"enc":"…","ciphertext":"…"}}}`.

- The entry starts at seq 3 or later. It carries a nonempty list sorted by
  namespace, with one epoch 1 per newly declared name. The account may hold up
  to 256 namespaces in total. Names use the §8.2 grammar (1–128 bytes, lowercase
  ASCII letters, digits, dots and underscores). The `colophon.` prefix is
  reserved and yields `newerFormat`.
- The current control threshold and its user-verification rules apply under
  either `memberRule`. The entry uses the signer rate limit and requires a
  non-retiring vault. Each epoch is sealed exclusively to that vault with
  §11.1 HPKE. Current controllers open it through their existing vault slots.
- The declaration and its first epoch take effect together on the verified
  branch. Later grants may name the namespace and share its keys. Each member
  continues to use the record scopes in its grant. Standard `rekey` and
  `revoke` rules apply to the declared namespace from then on.

The entry kind is the wire-level extension. A 0.5 verifier encountering it
stops at the unknown kind. The genesis and seq-2 rules, account ID, record paths
and record format carry forward. A Home must support the entry to accept it.

In Rust, prepare the entry with `Account::begin_add_namespaces` and finish it
through the usual Account or Engine signing flow. Replicate it through the
normal Home authority exchange before sending records that rely on a new grant.
