# Branches, tags and releases

This is how Colophon's history is organised, for the people and agents who work on it.
Releases are driven by [Edition](https://github.com/luff-llc/edition) from
[`edition.toml`](../edition.toml). Every command below is a dry run that prints its plan.
Local steps run with `--apply`; a plan that pushes or deploys also needs
`--confirm <receipt>`, using the receipt its dry run printed (valid once, for 30 minutes,
and only while the refs and configuration are unchanged).

## The model

- **`main`** carries the next version. It always builds as `X.Y.0-dev`, where `X.Y` is the
  line that has not been cut yet (today `0.6.0-dev`).
- **`release/X.Y`** carries a shipped line. It takes fixes only, and its version files say
  the release it will tag next (`0.5.2`, then `0.5.3`).
- **Tags** are made on a release line only:
  - `vX.Y.Z` is a release. Production homes and app pins use these and nothing else.
  - `vX.Y.Z-rc.N` is a release candidate, for builds that need outside review before the
    final tag. The version files still say `X.Y.Z`.
- **Release lines merge forward into `main`**, never the other way. `main` is never merged
  into a release branch, and fixes are not cherry-picked backwards.

CI runs on pushes and pull requests to `main` and to every `release/**` branch.

## Where builds go

| Tier | Takes | Approval | Recorded |
| --- | --- | --- | --- |
| dev | any ref, on one machine | no | no |
| staging | the tip of `main`, nothing else | no | yes |
| prod | a final `vX.Y.Z` tag, named explicitly, on `release/X.Y` and present on the remote | yes | yes |

The staging home (`colophon.toolsperson.com`) follows `main`: every merge to `main` can be
deployed there without further approval. The production home (`colophon.luff.works`) only
ever runs a final tag. Apps that embed the SDK pin the commit of a final tag, so anyone
can rebuild what shipped from the public repository.

Every staging and prod deploy is appended to `releases/ledger.toml` with the commit, the
tag, who ran it and the checks that passed. `edition status` reads it to answer "what is
deployed where".

## Common tasks

```sh
edition status                      # lines, tags, what each channel holds
edition verify --online             # invariants: versions, forward merges, tags, ledger
```

**Ship main to staging**

```sh
edition deploy staging-home main                       # prints the plan and a receipt
edition deploy staging-home main --apply --confirm <receipt>
```

**Cut a line at feature freeze**

```sh
edition cut 0.6                           # creates and pushes release/0.6 from main
# on release/0.6: edition bump 0.6.0 --apply, commit, merge
# on main:        edition bump 0.7.0-dev --apply, commit, merge
```

**Release candidates and the release**

```sh
edition rc 0.6.0                          # v0.6.0-rc.1, then rc.2, ...
edition tag 0.6.0                         # v0.6.0 on release/0.6
edition deploy production-home v0.6.0 --approved-by <name>
```

Each pushing command prints a receipt; run it again with `--apply --confirm <receipt>`.

**Hotfix a shipped line**

```sh
edition hotfix start 0.5 --apply          # hotfix/0.5.3 from release/0.5
# fix, edition bump 0.5.3 --apply, open a pull request into release/0.5, merge it
edition hotfix finish 0.5.3               # one plan: tag v0.5.3, publish it, open the
                                          # pull request release/0.5 -> main
```

`edition verify` fails while any release line has commits that are not in `main`, so a
forgotten forward merge is visible on the next check.

## What belongs in this repository

This repository is public. Specifications, design rationale, roadmaps and code belong
here. Working notes, questions addressed to a person, local machine paths and transcripts
do not. Edition scans what its own plans would publish here, and
`edition hooks install --apply` adds a pre-push hook that blocks other pushes carrying
such text.
