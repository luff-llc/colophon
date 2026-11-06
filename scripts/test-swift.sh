#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Cache paths stay inside this worktree. --disable-sandbox avoids nested sandbox-exec on
# restricted builders; it does not grant access to filecoordinationd or backup services.
mkdir -p .build/module-cache
export CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"
export COLOPHON_SOFTWARE_KEYS=1
swift test --disable-sandbox "$@"
