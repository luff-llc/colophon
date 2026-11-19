#!/usr/bin/env bash
# Hash source bytes, including dirty/untracked crate sources; never writes Git's index or objects.
set -euo pipefail
cd "${1:?repository root required}"
hash() {
  {
    rg --files --hidden crates | LC_ALL=C sort | while IFS= read -r file; do shasum -a 256 "$file"; done
    shasum -a 256 Cargo.lock Cargo.toml
  } | shasum -a 256 | awk '{print $1}'
}
case "${2:-hash}" in
  hash) hash ;;
  check)
    [[ -d sdk/apple/ColophonFFI.xcframework && -f sdk/apple/ColophonFFI.source-hash ]] &&
      [[ "$(cat sdk/apple/ColophonFFI.source-hash)" == "$(hash)" ]]
    ;;
  *) echo 'usage: apple-provenance.sh ROOT [hash|check]' >&2; exit 2 ;;
esac
