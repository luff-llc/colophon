#!/usr/bin/env bash
# Packages what an app consumes, from one commit, into dist/release/<version>/ with SHA256SUMS
# and manifest.json. It builds; it never signs and never publishes. See docs/release-packaging.md.
#
#   scripts/package-release.sh [--only apple|android|js|home]... [--verify] [--allow-dirty] [--force]
#
#   apple    ColophonFFI-<version>.xcframework.zip   (scripts/build-apple.sh)
#   android  colophon-android-<version>.aar           (scripts/build-android.sh)
#   js       colophon-core-<package version>.tgz      (npm ci, js/scripts/build.sh, npm pack)
#   home     colophon-home-<version>.tar.gz           (relay/*.js, relay/package.json and the
#                                                      colophon-home-wasm module)
#
#   --only X       build only X (repeatable, or comma-separated). Default: all four. The
#                  directory then holds only what this run built.
#   --verify       build twice, each pass from its own clean export with its own target, Cargo,
#                  Gradle and npm directories (the second pass offline for Cargo), and fail with
#                  a per-file summary when a checksum differs.
#   --allow-dirty  build the working tree with its changes (development only). The version gets
#                  -dirty-<input digest> and the manifest says "dirty": true.
#   --force        replace an existing dist/release/<version>/ (it is never merged).
#
#   RELEASE_TOOLCHAIN   the pinned Rust toolchain (default 1.99.1).
#   VISIONOS_TOOLCHAIN  dated nightly for the visionOS slices (default nightly-2026-11-05).
#   SKIP_VISIONOS=1     leave out the visionOS slices; the manifest says so.
#   WASM_BINDGEN        the wasm-bindgen 0.2.130 CLI (default ~/.cargo/tools/wasm-bindgen-0.2.130/bin/wasm-bindgen).
#   NODE, CARGO_NDK     the node and cargo-ndk to use (default: found on PATH).
#   ANDROID_HOME, ANDROID_NDK_HOME, JAVA_HOME are passed to scripts/build-android.sh when set.
set -euo pipefail

say() { echo "package-release: $*"; }
die() { echo "package-release: $*" >&2; exit 1; }
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; s="${s//$'\t'/ }"; s="${s//$'\r'/}"
  printf '"%s"' "$s"
}
sha_of() { shasum -a 256 "$1" | awk '{print $1}'; }
size_of() { wc -c <"$1" | tr -d ' '; }
first_line() { "$@" 2>&1 | head -n 1; }

# --- One build pass: runs under env -i (see run_pass), in a clean export. ---

# Fixed mode and mtime on a staging tree. Owner is set when archiving.
normalize_tree() {
  local dir="$1" stamp
  stamp="$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)"
  find "$dir" -type d -exec chmod 0755 {} +
  find "$dir" -type f -perm -u+x -exec chmod 0755 {} +
  find "$dir" -type f ! -perm -u+x -exec chmod 0644 {} +
  find "$dir" -exec touch -h -t "$stamp" {} +
}

# Deterministic zip of DIR's contents (sorted, no extra attributes, no directory entries).
zip_tree() {
  local dir="$1" dest="$2" links
  links="$(cd "$dir" && find . -type l)"
  [[ -z "$links" ]] || die "refusing to zip symlinks (they would be dropped): $links"
  normalize_tree "$dir"
  rm -f "$dest"
  (cd "$dir" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | zip -X -D -q "$dest" -@)
}

# Deterministic tar.gz of DIR (DIR's basename is the top directory).
tar_tree() {
  local dir="$1" dest="$2" parent base
  parent="$(dirname "$dir")"; base="$(basename "$dir")"
  normalize_tree "$dir"
  rm -f "$dest"
  (cd "$parent" && find "$base" | LC_ALL=C sort | \
    tar --format ustar --uid 0 --gid 0 --uname root --gname root --no-xattrs --no-acls \
        --no-mac-metadata -n -c -f - -T - | gzip -n -9 >"$dest")
}

# Per-target rustflags remapping every absolute build path. Cargo joins these with the
# target.'cfg(target_arch = "aarch64")' flags in .cargo/config.toml (RUSTFLAGS would replace them).
# The last matching prefix wins.
set_rustflags() {
  local t var flags
  flags="--remap-path-prefix=$CARGO_HOME=/cargo"
  flags+=" --remap-path-prefix=$RUSTUP_HOME=/rustup --remap-path-prefix=$PWD=/colophon"
  flags+=" --remap-path-prefix=$CARGO_TARGET_DIR=/target"
  for t in aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-visionos \
           aarch64-apple-visionos-sim aarch64-linux-android x86_64-linux-android wasm32-unknown-unknown; do
    var="CARGO_TARGET_$(echo "$t" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"
    export "$var=$flags"
  done
}

# The committed generated bindings must come out of the build unchanged.
generated_digest() {
  find swift/Sources/ColophonKit/Generated sdk/kotlin/src/main/kotlin -type f 2>/dev/null | LC_ALL=C sort | \
    while IFS= read -r f; do shasum -a 256 "$f"; done | shasum -a 256 | awk '{print $1}'
}
check_generated() {
  [[ "$(generated_digest)" == "$1" ]] && return 0
  if [[ "$RELEASE_DIRTY" == true ]]; then
    echo "package-release: warning: the build rewrote the generated bindings" >&2
    return 0
  fi
  die "the build rewrote the committed generated bindings; the artefact would not match the commit"
}

# Toolchain JSON lines (the body of an object) for the Rust toolchain in use.
rust_tools() {
  local sysroot
  sysroot="$(rustc --print sysroot)"
  printf '%s: %s,\n%s: %s,\n%s: %s,\n%s: %s' \
    "$(json_str rustc)" "$(json_str "$(first_line rustc --version)")" \
    "$(json_str rustc_sha256)" "$(json_str "$(sha_of "$sysroot/bin/rustc")")" \
    "$(json_str cargo)" "$(json_str "$(first_line cargo --version)")" \
    "$(json_str cargo_sha256)" "$(json_str "$(sha_of "$sysroot/bin/cargo")")"
}

# xcodebuild -create-xcframework writes AvailableLibraries in a different order on each run
# (the same entries). Sort them by LibraryIdentifier; nothing else in the plist changes.
sort_xcframework_plist() {
  local plist="$1" tmp="$1.sorted" n i id frag entries=()
  n="$(plutil -extract AvailableLibraries raw -o - "$plist")"
  for ((i = 0; i < n; i++)); do
    id="$(plutil -extract "AvailableLibraries.$i.LibraryIdentifier" raw -o - "$plist")"
    entries+=("$id $i")
  done
  cp "$plist" "$tmp"
  plutil -replace AvailableLibraries -array "$tmp"
  while read -r id i; do
    frag="$(plutil -extract "AvailableLibraries.$i" xml1 -o - "$plist" | sed -e '1,/<plist/d' -e '/<\/plist>/d')"
    plutil -insert AvailableLibraries -xml "$frag" -append "$tmp"
  done < <(printf '%s\n' "${entries[@]}" | LC_ALL=C sort)
  plutil -convert xml1 "$tmp"
  mv "$tmp" "$plist"
}

build_apple() {
  local out="$1" stage file visionos=true tc gen nsys
  [[ "${SKIP_VISIONOS:-0}" == 1 ]] && visionos=false
  gen="$(generated_digest)"
  APPLE_TARGET_ROOT="$CARGO_TARGET_DIR/apple" bash scripts/build-apple.sh
  check_generated "$gen"
  stage="$TMPDIR/apple-stage"
  rm -rf "$stage"; mkdir -p "$stage"
  cp -R sdk/apple/ColophonFFI.xcframework "$stage/ColophonFFI.xcframework"
  sort_xcframework_plist "$stage/ColophonFFI.xcframework/Info.plist"
  file="ColophonFFI-$RELEASE_VERSION.xcframework.zip"
  # SwiftPM binary targets expect the .xcframework directory at the top of the zip.
  zip_tree "$stage" "$out/$file"
  rm -rf "$stage"
  tc="$(rust_tools),
$(json_str rustup): $(json_str "$(first_line rustup --version)"),
$(json_str xcode): $(json_str "$(xcodebuild -version 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"),
$(json_str sdks): $(json_str "macosx $(xcrun --sdk macosx --show-sdk-version) iphoneos $(xcrun --sdk iphoneos --show-sdk-version) iphonesimulator $(xcrun --sdk iphonesimulator --show-sdk-version)$( [[ $visionos == true ]] && echo " xros $(xcrun --sdk xros --show-sdk-version) xrsimulator $(xcrun --sdk xrsimulator --show-sdk-version)")"),
$(json_str visionos_slices): $visionos"
  if [[ "$visionos" == true ]]; then
    nsys="$(rustup run "$VISIONOS_TOOLCHAIN" rustc --print sysroot)"
    tc+=",
$(json_str visionos_toolchain): $(json_str "$VISIONOS_TOOLCHAIN"),
$(json_str visionos_rustc): $(json_str "$(first_line rustup run "$VISIONOS_TOOLCHAIN" rustc --version)"),
$(json_str visionos_rustc_sha256): $(json_str "$(sha_of "$nsys/bin/rustc")")"
  fi
  printf '%s' "$tc" >"$out/.parts/apple.toolchain"
  echo "$file" >"$out/.parts/apple.file"
}

build_android() {
  local out="$1" file info ndk java_home tc gen props=sdk/android/gradle/wrapper/gradle-wrapper.properties
  gen="$(generated_digest)"
  info="$TMPDIR/android-info"
  BUILD_INFO_FILE="$info" bash scripts/build-android.sh
  check_generated "$gen"
  file="colophon-android-$RELEASE_VERSION.aar"
  cp sdk/android/build/outputs/aar/colophon-android-release.aar "$out/$file"
  chmod 0644 "$out/$file"
  ndk="$(grep '^ndk=' "$info" | cut -d= -f2-)"
  java_home="$(grep '^java_home=' "$info" | cut -d= -f2-)"
  tc="$(rust_tools),
$(json_str cargo_ndk): $(json_str "$(first_line cargo ndk --version)"),
$(json_str cargo_ndk_sha256): $(json_str "$(sha_of "$(command -v cargo-ndk)")"),
$(json_str ndk): $(json_str "$(grep '^Pkg.Revision' "$ndk/source.properties" | cut -d= -f2- | tr -d ' ')"),
$(json_str jdk): $(json_str "$(grep '^JAVA_RUNTIME_VERSION=' "$java_home/release" | cut -d= -f2- | tr -d '"')"),
$(json_str gradle): $(json_str "$(grep '^distributionUrl=' "$props" | sed 's|.*/gradle-\(.*\)-bin.zip|\1|')"),
$(json_str gradle_distribution_sha256): $(json_str "$(grep '^distributionSha256Sum=' "$props" | cut -d= -f2-)"),
$(json_str android_gradle_plugin): $(json_str "$(sed -n 's/.*id("com.android.library") version "\(.*\)".*/\1/p' sdk/android/build.gradle.kts)"),
$(json_str kotlin): $(json_str "$(sed -n 's/.*kotlin("android") version "\(.*\)".*/\1/p' sdk/android/build.gradle.kts)")"
  printf '%s' "$tc" >"$out/.parts/android.toolchain"
  echo "$file" >"$out/.parts/android.file"
}

build_js() {
  local out="$1" file tc packed
  # node_modules always comes from the lock (integrity hashes), never from an earlier install.
  (cd js && npm ci --ignore-scripts --no-audit --no-fund)
  bash js/scripts/build.sh
  packed="$(cd js && npm pack --silent --pack-destination "$out")"
  file="$(echo "$packed" | tail -n 1)"
  chmod 0644 "$out/$file"
  tc="$(rust_tools),
$(json_str wasm_bindgen): $(json_str "$(first_line wasm-bindgen --version)"),
$(json_str wasm_bindgen_sha256): $(json_str "$(sha_of "$(command -v wasm-bindgen)")"),
$(json_str node): $(json_str "$(first_line node --version)"),
$(json_str node_sha256): $(json_str "$(sha_of "$(command -v node)")"),
$(json_str npm): $(json_str "$(first_line npm --version)"),
$(json_str typescript): $(json_str "$(first_line js/node_modules/.bin/tsc --version)")"
  printf '%s' "$tc" >"$out/.parts/js.toolchain"
  echo "$file" >"$out/.parts/js.file"
}

build_home() {
  local out="$1" file dir f
  cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm
  dir="$TMPDIR/home-stage/colophon-home-$RELEASE_VERSION"
  rm -rf "$TMPDIR/home-stage"; mkdir -p "$dir"
  for f in relay/*.js relay/package.json; do cp "$f" "$dir/"; done
  cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/colophon_home_wasm.wasm" "$dir/"
  chmod 0644 "$dir"/*  # none of these is executable in git; cargo marks the .wasm 0755
  file="colophon-home-$RELEASE_VERSION.tar.gz"
  tar_tree "$dir" "$out/$file"
  rm -rf "$TMPDIR/home-stage"
  printf '%s' "$(rust_tools)" >"$out/.parts/home.toolchain"
  echo "$file" >"$out/.parts/home.file"
}

if [[ "${1:-}" == --pass ]]; then
  # env -i already cleared these; unset again so a change to run_pass cannot let them in.
  unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER \
        CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER GRADLE_OPTS JAVA_TOOL_OPTIONS _JAVA_OPTIONS
  pass_arts="$2" pass_dir="$3"
  cd "$pass_dir/src"
  set_rustflags
  # Pass a fetches every crate Cargo.lock names (all targets); pass b is offline on a copy.
  if [[ "$RELEASE_PASS" == a ]]; then cargo fetch --locked; fi
  IFS=, read -r -a pass_list <<<"$pass_arts"
  for art in "${pass_list[@]}"; do
    say "pass $RELEASE_PASS: building $art"
    "build_$art" "$pass_dir/out"
  done
  exit 0
fi

# --- The driver. ---

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
all=(apple android js home)
only=()
verify=0
allow_dirty=0
force=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) [[ $# -ge 2 ]] || die "--only needs a value"
            IFS=, read -r -a parts <<<"$2"; only+=("${parts[@]}"); shift 2 ;;
    --only=*) IFS=, read -r -a parts <<<"${1#--only=}"; only+=("${parts[@]}"); shift ;;
    --verify) verify=1; shift ;;
    --allow-dirty) allow_dirty=1; shift ;;
    --force) force=1; shift ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ ${#only[@]} -gt 0 ]] || only=("${all[@]}")
for o in "${only[@]}"; do
  case "$o" in apple|android|js|home) ;; *) echo "unknown artefact: $o" >&2; exit 2 ;; esac
done
selected=()
for a in "${all[@]}"; do
  for o in "${only[@]}"; do if [[ "$o" == "$a" ]]; then selected+=("$a"); break; fi; done
done
selected_csv="$(IFS=,; echo "${selected[*]}")"
want() { [[ ",$selected_csv," == *",$1,"* ]]; }

# Rustflags are split on whitespace, so a path containing whitespace cannot be remapped.
for p in "$root" "$HOME" "${TMPDIR:-/tmp}"; do
  [[ "$p" != *[[:space:]]* ]] || die "refusing to run from a path with whitespace ($p): --remap-path-prefix cannot carry it"
done

changes="$(git status --porcelain --untracked-files=all)"
dirty=false
if [[ -n "$changes" ]]; then
  if [[ "$allow_dirty" != 1 ]]; then
    echo "package-release: the tree has changes or untracked files (use --allow-dirty to build them):" >&2
    echo "$changes" >&2
    exit 1
  fi
  dirty=true
fi
commit="$(git rev-parse HEAD)"
describe="$(git describe --tags --match 'v[0-9]*' --always)"
describe="${describe#v}"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"

# Pinned and resolved tools. Nothing is installed by a release run: a missing tool fails.
toolchain="${RELEASE_TOOLCHAIN:-1.99.1}"
visionos_tc="${VISIONOS_TOOLCHAIN:-nightly-2026-11-05}"
rustup_bin="$(command -v rustup || true)"
if [[ -z "$rustup_bin" && -x "$HOME/.cargo/bin/rustup" ]]; then rustup_bin="$HOME/.cargo/bin/rustup"; fi
[[ -n "$rustup_bin" ]] || die "rustup not found"
tc_rustc="$("$rustup_bin" which --toolchain "$toolchain" rustc 2>/dev/null)" ||
  die "Rust toolchain $toolchain is not installed (rustup toolchain install $toolchain)"
tc_bin="$(dirname "$tc_rustc")"
real_rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
real_cargo_home="${CARGO_HOME:-$HOME/.cargo}"
wasm_bindgen="${WASM_BINDGEN:-$HOME/.cargo/tools/wasm-bindgen-0.2.130/bin/wasm-bindgen}"
node_bin="${NODE:-$(command -v node || true)}"
npm_bin=""
if [[ -n "$node_bin" ]]; then
  npm_bin="$(dirname "$node_bin")/npm"
  [[ -x "$npm_bin" ]] || npm_bin="$(command -v npm || true)"
fi
cargo_ndk="${CARGO_NDK:-$(command -v cargo-ndk || echo "$real_cargo_home/bin/cargo-ndk")}"
rg_bin="$(command -v rg || true)"
if want js; then
  [[ -x "$wasm_bindgen" && "$("$wasm_bindgen" --version)" == "wasm-bindgen 0.2.130" ]] ||
    die "wasm-bindgen 0.2.130 not found at $wasm_bindgen (set WASM_BINDGEN)"
  [[ -x "$node_bin" && -n "$npm_bin" ]] || die "node and npm are required for js (set NODE)"
fi
if want android; then [[ -x "$cargo_ndk" ]] || die "cargo-ndk not found (set CARGO_NDK)"; fi
if want apple; then
  [[ -n "$rg_bin" ]] || die "rg is required by scripts/apple-provenance.sh"
  command -v xcodebuild >/dev/null || die "xcodebuild is required for apple"
fi

mkdir -p "$root/dist/release"
run="$(mktemp -d "$root/dist/release/.run.XXXXXX")"
version="" dest="" marker=""
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ $rc -ne 0 && -n "$marker" ]]; then
    printf 'package-release failed (exit %s) at %s for %s; see the run output\n' "$rc" "$commit" "$selected_csv" >"$marker"
  fi
  # Gradle and Go-style caches leave read-only files; make everything removable first.
  chmod -R u+w "$run" 2>/dev/null || true
  rm -rf "$run"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A clean export of the commit, or of the working tree with its changes (--allow-dirty).
# Ignored files never enter: node_modules, target, build output, local properties.
export_source() {
  local dir="$1"
  mkdir -p "$dir"
  if [[ "$dirty" == true ]]; then
    git ls-files -z --cached --others --exclude-standard | \
      while IFS= read -r -d '' f; do if [[ -e "$f" || -L "$f" ]]; then printf '%s\0' "$f"; fi; done | \
      tar --null -T - -cf - | tar -xf - -C "$dir"
  else
    git archive --format=tar "$commit" | tar -xf - -C "$dir"
  fi
}

# sha256 over the sorted list of "sha256  path" for every exported file (and link target).
input_digest() {
  (cd "$1" && find . \( -type f -o -type l \) | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do
    if [[ -L "$f" ]]; then printf 'link  %s -> %s\n' "$f" "$(readlink "$f")"
    else printf '%s  %s\n' "$(sha_of "$f")" "$f"; fi
  done) | shasum -a 256 | awk '{print $1}'
}

say "exporting $commit$( [[ $dirty == true ]] && echo ' with working-tree changes')"
export_source "$run/a/src"
inputs_sha="$(input_digest "$run/a/src")"
if [[ "$dirty" == true ]]; then version="$describe-dirty-${inputs_sha:0:12}"; else version="$describe"; fi
dest="$root/dist/release/$version"
if [[ -e "$dest" && "$force" != 1 ]]; then die "dist/release/$version exists; pass --force to replace it"; fi
marker="$root/dist/release/$version.FAILED"
rm -f "$marker"

# One pass in a sanitized environment with its own HOME, Cargo home, Gradle home, npm cache,
# target directory and TMPDIR. Nothing is shared with the machine's Cargo home, so its
# config.toml never applies. Pass a fills its own registry with `cargo fetch --locked` (Cargo.lock
# pins every crate by checksum); pass b starts from a copy of pass a's registry and runs offline.
# The registry must be a real directory: a symlink in a crate's source path breaks proc macros
# that resolve files relative to it (askama in uniffi_bindgen).
run_pass() {
  local p="$1" dir="$run/$1" v envs
  mkdir -p "$dir/out/.parts" "$dir/home" "$dir/tmp" "$dir/bin" "$dir/cargo-home" "$dir/gradle-home" \
           "$dir/npm-cache" "$dir/target"
  : >"$dir/npmrc-user"
  : >"$dir/npmrc-global"
  if [[ "$p" == b ]]; then
    # A clone where the filesystem can (APFS, reflink), a plain copy otherwise.
    if [[ "$(uname -s)" == Darwin ]]; then cp -Rc "$run/a/cargo-home/registry" "$dir/cargo-home/registry"
    else cp -a --reflink=auto "$run/a/cargo-home/registry" "$dir/cargo-home/registry"; fi
  fi
  ln -s "$rustup_bin" "$dir/bin/rustup"
  if want js; then ln -s "$wasm_bindgen" "$dir/bin/wasm-bindgen"; ln -s "$node_bin" "$dir/bin/node"; ln -s "$npm_bin" "$dir/bin/npm"; fi
  if want android; then ln -s "$cargo_ndk" "$dir/bin/cargo-ndk"; fi
  if want apple; then ln -s "$rg_bin" "$dir/bin/rg"; fi
  envs=(
    HOME="$dir/home" PATH="$dir/bin:$tc_bin:/usr/bin:/bin:/usr/sbin:/sbin" TMPDIR="$dir/tmp"
    LANG=C LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" ZERO_AR_DATE=1 COPYFILE_DISABLE=1
    CARGO_INCREMENTAL=0 CARGO_HOME="$dir/cargo-home"
    RUSTUP_HOME="$real_rustup_home" RUSTUP_TOOLCHAIN="$toolchain" APPLE_TOOLCHAIN="$toolchain"
    VISIONOS_TOOLCHAIN="$visionos_tc" SKIP_VISIONOS="${SKIP_VISIONOS:-0}" RELEASE_NO_INSTALL=1
    CARGO_TARGET_DIR="$dir/target" GRADLE_USER_HOME="$dir/gradle-home"
    npm_config_cache="$dir/npm-cache" npm_config_userconfig="$dir/npmrc-user" npm_config_globalconfig="$dir/npmrc-global"
    npm_config_update_notifier=false RELEASE_VERSION="$version" RELEASE_PASS="$p" RELEASE_DIRTY="$dirty"
  )
  if [[ "$p" == b ]]; then envs+=(CARGO_NET_OFFLINE=true); fi
  for v in ANDROID_HOME ANDROID_NDK_HOME JAVA_HOME DEVELOPER_DIR CARGO_BUILD_JOBS PRESSROOM_THREADS \
           PRESSROOM_MEMORY_GB PRESSROOM_JOB PRESSROOM_HOLDER; do
    if [[ -n "${!v:-}" ]]; then envs+=("$v=${!v}"); fi
  done
  env -i "${envs[@]}" "$BASH" "$dir/src/scripts/package-release.sh" --pass "$selected_csv" "$dir"
}

# The payload: sha256 of every file in an archive, sorted by path; a .jar inside is listed
# entry by entry as name.jar!/entry as well.
list_contents() {
  local archive="$1" dest="$2" tmp
  tmp="$(mktemp -d "$run/contents.XXXXXX")"
  case "$archive" in
    *.zip|*.aar) unzip -q "$archive" -d "$tmp/x" ;;
    *.tgz|*.tar.gz) mkdir -p "$tmp/x"; tar -xzf "$archive" -C "$tmp/x" ;;
  esac
  (cd "$tmp/x" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do
    printf '%s  %s\n' "$(sha_of "$f")" "$f"
    if [[ "$f" == *.jar ]]; then
      rm -rf "$tmp/j"; unzip -q "$f" -d "$tmp/j"
      (cd "$tmp/j" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r g; do
        printf '%s  %s!/%s\n' "$(sha_of "$g")" "$f" "$g"
      done)
    fi
  done) >"$dest"
  rm -rf "$tmp"
}

# Payload files that still carry this machine's home, the source root or the run directory.
path_leaks() {
  local archive="$1" tmp n=0 f c
  tmp="$(mktemp -d "$run/leaks.XXXXXX")"
  case "$archive" in
    *.zip|*.aar) unzip -q "$archive" -d "$tmp" ;;
    *.tgz|*.tar.gz) tar -xzf "$archive" -C "$tmp" ;;
  esac
  while IFS= read -r f; do
    # grep -c reads the whole stream, so unzip never writes into a closed pipe.
    if [[ "$f" == *.jar ]]; then
      c="$(unzip -p "$f" | LC_ALL=C grep -a -c -F -e "$HOME" -e "$root" -e "$run" || true)"
    else
      c="$(LC_ALL=C grep -a -c -F -e "$HOME" -e "$root" -e "$run" "$f" || true)"
    fi
    if [[ "${c:-0}" -gt 0 ]]; then n=$((n + 1)); fi
  done < <(find "$tmp" -type f)
  rm -rf "$tmp"
  echo "$n"
}

say "pass a: $selected_csv as $version"
run_pass a
if [[ "$verify" == 1 ]]; then
  export_source "$run/b/src"
  [[ "$(input_digest "$run/b/src")" == "$inputs_sha" ]] || die "the second export differs from the first; the tree changed during the run"
  say "pass b: $selected_csv (Cargo offline)"
  run_pass b
fi

failed=0
for art in "${selected[@]}"; do
  f="$(cat "$run/a/out/.parts/$art.file")"
  list_contents "$run/a/out/$f" "$run/a/out/$f.contents.sha256"
  path_leaks "$run/a/out/$f" >"$run/a/out/.parts/$art.leaks"
  say "$art: $f $(sha_of "$run/a/out/$f")"
  if [[ "$verify" == 1 ]]; then
    list_contents "$run/b/out/$f" "$run/b/out/$f.contents.sha256"
    if [[ "$(sha_of "$run/a/out/$f")" == "$(sha_of "$run/b/out/$f")" ]]; then
      say "$art reproduces: $f"
    else
      failed=1
      echo "package-release: $art does NOT reproduce: $f" >&2
      echo "  pass a $(sha_of "$run/a/out/$f")" >&2
      echo "  pass b $(sha_of "$run/b/out/$f")" >&2
      d="$(awk 'NR == FNR { h[$2] = $1; next }
                { if (!($2 in h)) print "    only in pass b: " $2; else if (h[$2] != $1) print "    differs: " $2; seen[$2] = 1 }
                END { for (p in h) if (!(p in seen)) print "    only in pass a: " p }' \
              "$run/a/out/$f.contents.sha256" "$run/b/out/$f.contents.sha256" | LC_ALL=C sort)"
      if [[ -n "$d" ]]; then echo "$d" >&2; else echo "    every payload file is identical; only the archive differs" >&2; fi
    fi
  fi
done
[[ "$failed" == 0 ]] || die "verify FAILED; nothing was written to dist/release/$version"

# Only now: SHA256SUMS and manifest.json for exactly what this run built, then one move.
out="$run/a/out"
reproduced=null
if [[ "$verify" == 1 ]]; then reproduced=true; fi
entries=()
: >"$out/SHA256SUMS"
for art in "${selected[@]}"; do
  f="$(cat "$out/.parts/$art.file")"
  (cd "$out" && shasum -a 256 "$f") >>"$out/SHA256SUMS"
  entries+=("    {
      $(json_str artefact): $(json_str "$art"),
      $(json_str name): $(json_str "$f"),
      $(json_str size): $(size_of "$out/$f"),
      $(json_str sha256): $(json_str "$(sha_of "$out/$f")"),
      $(json_str contents): $(json_str "$f.contents.sha256"),
      $(json_str contents_sha256): $(json_str "$(sha_of "$out/$f.contents.sha256")"),
      $(json_str reproduced): $reproduced,
      $(json_str files_with_build_paths): $(cat "$out/.parts/$art.leaks"),
      $(json_str toolchain): {
$(sed "s/^/        /" "$out/.parts/$art.toolchain")
      }
    }")
done
{
  echo "{"
  echo "  $(json_str name): $(json_str colophon),"
  echo "  $(json_str version): $(json_str "$version"),"
  echo "  $(json_str commit): $(json_str "$commit"),"
  echo "  $(json_str dirty): $dirty,"
  echo "  $(json_str inputs_sha256): $(json_str "$inputs_sha"),"
  echo "  $(json_str source_date_epoch): $SOURCE_DATE_EPOCH,"
  echo "  $(json_str host): $(json_str "$(uname -sm) $(sw_vers -productVersion 2>/dev/null || true)"),"
  echo "  $(json_str passes): $([[ $verify == 1 ]] && echo 2 || echo 1),"
  echo "  $(json_str signed): false,"
  echo "  $(json_str published): false,"
  echo "  $(json_str artefacts): ["
  for i in "${!entries[@]}"; do
    if [[ $i -lt $((${#entries[@]} - 1)) ]]; then echo "${entries[$i]},"; else echo "${entries[$i]}"; fi
  done
  echo "  ]"
  echo "}"
} >"$out/manifest.json"
rm -rf "$out/.parts"
if [[ -e "$dest" ]]; then mv "$dest" "$run/replaced"; fi
mv "$out" "$dest"
say "wrote dist/release/$version"
cat "$dest/SHA256SUMS"
if [[ "$verify" == 1 ]]; then say "verify: every selected artefact reproduced bit for bit"; fi
