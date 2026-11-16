#!/usr/bin/env bash
# Packages what an app consumes, from one commit, into dist/release/<version>/ with SHA256SUMS
# and manifest.json. It builds; it never signs and never publishes. See docs/release-packaging.md.
#
#   scripts/package-release.sh [--only apple|android|js|home]... [--verify] [--allow-dirty]
#
#   apple    ColophonFFI-<version>.xcframework.zip   (scripts/build-apple.sh)
#   android  colophon-android-<version>.aar           (scripts/build-android.sh)
#   js       colophon-core-<package version>.tgz      (js/scripts/build.sh, then npm pack)
#   home     colophon-home-<version>.tar.gz           (relay/*.js, relay/package.json and the
#                                                      colophon-home-wasm module)
#
#   --only X       build only X (repeatable, or comma-separated). Default: all four. Artefacts
#                  built earlier for the same version stay; manifest.json and SHA256SUMS list
#                  everything in the directory.
#   --verify       build every selected artefact twice, from empty target directories, into
#                  dist/release/<version>/ and dist/release/<version>.verify/, and fail with a
#                  per-file summary when a checksum differs.
#   --allow-dirty  build from a tree with changes in the inputs (development only). The version
#                  gets a -dirty suffix and the manifest says "dirty": true.
#
#   RELEASE_TOOLCHAIN   the pinned Rust toolchain (default 1.99.1).
#   SKIP_VISIONOS=1     leave out the visionOS slices (they need nightly Rust); the manifest says so.
#   VISIONOS_TOOLCHAIN  nightly toolchain for the visionOS slices (default: nightly).
#   CARGO_TARGET_DIR    target directories go under $CARGO_TARGET_DIR/package-release (default:
#                       ./target/package-release).
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
# The pinned wasm-bindgen CLI lives where scripts/test-js.sh expects it.
export PATH="$HOME/.cargo/tools/wasm-bindgen-0.2.130/bin:/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

all=(apple android js home)
only=()
verify=0
allow_dirty=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) [[ $# -ge 2 ]] || { echo "--only needs a value" >&2; exit 2; }
            IFS=, read -r -a parts <<<"$2"; only+=("${parts[@]}"); shift 2 ;;
    --only=*) IFS=, read -r -a parts <<<"${1#--only=}"; only+=("${parts[@]}"); shift ;;
    --verify) verify=1; shift ;;
    --allow-dirty) allow_dirty=1; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ ${#only[@]} -gt 0 ]] || only=("${all[@]}")
selected=()
for a in "${all[@]}"; do
  for o in "${only[@]}"; do
    case "$o" in apple|android|js|home) ;; *) echo "unknown artefact: $o" >&2; exit 2 ;; esac
    if [[ "$o" == "$a" ]]; then selected+=("$a"); break; fi
  done
done

# Everything a build reads. Git-ignored build output is not an input and is cleared before use.
inputs=(.cargo Cargo.toml Cargo.lock crates js relay sdk swift scripts Package.swift)
changes="$(git status --porcelain --untracked-files=all -- "${inputs[@]}")"
dirty=false
if [[ -n "$changes" ]]; then
  if [[ "$allow_dirty" != 1 ]]; then
    echo "package-release: the inputs have changes or untracked files (use --allow-dirty to build anyway):" >&2
    echo "$changes" >&2
    exit 1
  fi
  dirty=true
fi

commit="$(git rev-parse HEAD)"
version="$(git describe --tags --match 'v[0-9]*' --always)"
version="${version#v}"
[[ "$dirty" == true ]] && version="$version-dirty"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"
export SOURCE_DATE_EPOCH
# Fixed environment for everything below: no locale or timezone in archives, no ar dates.
export TZ=UTC LC_ALL=C ZERO_AR_DATE=1 COPYFILE_DISABLE=1
toolchain="${RELEASE_TOOLCHAIN:-1.99.1}"
export RUSTUP_TOOLCHAIN="$toolchain" APPLE_TOOLCHAIN="$toolchain"
visionos_tc="${VISIONOS_TOOLCHAIN:-nightly}"
export VISIONOS_TOOLCHAIN="$visionos_tc"
stamp="$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)"

out="$root/dist/release/$version"
outb="$root/dist/release/$version.verify"
tbase="${CARGO_TARGET_DIR:-$root/target}/package-release"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"

say() { echo "package-release: $*"; }

json_str() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; s="${s//$'\t'/ }"; s="${s//$'\r'/}"
  printf '"%s"' "$s"
}

sha_of() { shasum -a 256 "$1" | awk '{print $1}'; }
size_of() { wc -c <"$1" | tr -d ' '; }

# Per-target rustflags: remap every absolute build path. Cargo joins these with the
# target.'cfg(target_arch = "aarch64")' flags in .cargo/config.toml (RUSTFLAGS would replace them).
# The last matching prefix wins, so the target root comes after the source root.
set_rustflags() {
  local troot="$1" t var
  local flags="--remap-path-prefix=$root=/colophon --remap-path-prefix=$cargo_home=/cargo"
  flags+=" --remap-path-prefix=$rustup_home=/rustup --remap-path-prefix=$troot=/target"
  for t in aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-visionos \
           aarch64-apple-visionos-sim aarch64-linux-android x86_64-linux-android wasm32-unknown-unknown; do
    var="CARGO_TARGET_$(echo "$t" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"
    export "$var=$flags"
  done
}

# Fixed mode and mtime on a staging tree. Owner is set when archiving.
normalize_tree() {
  local dir="$1"
  find "$dir" -type d -exec chmod 0755 {} +
  find "$dir" -type f -perm -u+x -exec chmod 0755 {} +
  find "$dir" -type f ! -perm -u+x -exec chmod 0644 {} +
  find "$dir" -exec touch -h -t "$stamp" {} +
}

# Deterministic zip of DIR's contents (sorted, no extra attributes, no directory entries).
zip_tree() {
  local dir="$1" dest="$2"
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

# The payload: sha256 of every file in an archive, sorted by path; a .jar inside is listed
# entry by entry as name.jar!/entry as well.
list_contents() {
  local archive="$1" dest="$2" tmp f
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/colophon-contents.XXXXXX")"
  case "$archive" in
    *.zip|*.aar) unzip -q "$archive" -d "$tmp/x" ;;
    *.tgz|*.tar.gz) mkdir -p "$tmp/x"; tar -xzf "$archive" -C "$tmp/x" ;;
  esac
  {
    (cd "$tmp/x" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do
      printf '%s  %s\n' "$(sha_of "$f")" "$f"
      if [[ "$f" == *.jar ]]; then
        rm -rf "$tmp/j"; unzip -q "$f" -d "$tmp/j"
        (cd "$tmp/j" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r g; do
          printf '%s  %s!/%s\n' "$(sha_of "$g")" "$f" "$g"
        done)
      fi
    done)
  } >"$dest"
  rm -rf "$tmp"
}

# Count payload files that still carry this machine's home directory or the source root.
path_leaks() {
  local archive="$1" tmp n=0 f
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/colophon-leaks.XXXXXX")"
  case "$archive" in
    *.zip|*.aar) unzip -q "$archive" -d "$tmp" ;;
    *.tgz|*.tar.gz) tar -xzf "$archive" -C "$tmp" ;;
  esac
  while IFS= read -r f; do
    if [[ "$f" == *.jar ]]; then
      if unzip -p "$f" | LC_ALL=C grep -a -q -F -e "$HOME" -e "$root"; then n=$((n + 1)); fi
    elif LC_ALL=C grep -a -q -F -e "$HOME" -e "$root" "$f"; then n=$((n + 1)); fi
  done < <(find "$tmp" -type f)
  rm -rf "$tmp"
  echo "$n"
}

tool_line() { "$@" 2>&1 | head -n 1; }

# The committed generated sources must come out of the build unchanged.
check_generated() {
  local changed
  changed="$(git status --porcelain --untracked-files=all -- swift/Sources/ColophonKit/Generated sdk/kotlin/src)"
  if [[ -n "$changed" && "$dirty" != true ]]; then
    echo "package-release: the build changed committed generated sources; the artefact would not match $commit:" >&2
    echo "$changed" >&2
    exit 1
  fi
}

# Each build_<artefact> DEST TROOT writes DEST/<file>, DEST/<file>.contents.sha256 and
# DEST/.parts/<artefact>.{file,toolchain}. The toolchain file is the body of a JSON object.

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
  local dest="$1" troot="$2" stage file visionos=true tc
  [[ "${SKIP_VISIONOS:-0}" == 1 ]] && visionos=false
  APPLE_TARGET_ROOT="$troot/apple" CARGO_TARGET_DIR="$troot/host" bash scripts/build-apple.sh
  check_generated
  stage="$(mktemp -d "${TMPDIR:-/tmp}/colophon-apple.XXXXXX")"
  cp -R sdk/apple/ColophonFFI.xcframework "$stage/ColophonFFI.xcframework"
  sort_xcframework_plist "$stage/ColophonFFI.xcframework/Info.plist"
  file="ColophonFFI-$version.xcframework.zip"
  # SwiftPM binary targets expect the .xcframework directory at the top of the zip.
  zip_tree "$stage" "$dest/$file"
  rm -rf "$stage"
  tc="$(json_str rustc): $(json_str "$(tool_line rustc --version)"),
$(json_str cargo): $(json_str "$(tool_line cargo --version)"),
$(json_str xcode): $(json_str "$(xcodebuild -version 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"),
$(json_str sdks): $(json_str "macosx $(xcrun --sdk macosx --show-sdk-version) iphoneos $(xcrun --sdk iphoneos --show-sdk-version) iphonesimulator $(xcrun --sdk iphonesimulator --show-sdk-version)$( [[ $visionos == true ]] && echo " xros $(xcrun --sdk xros --show-sdk-version) xrsimulator $(xcrun --sdk xrsimulator --show-sdk-version)")"),
$(json_str visionos_slices): $visionos"
  if [[ "$visionos" == true ]]; then
    tc+=",
$(json_str visionos_rustc): $(json_str "$(tool_line rustc +"$visionos_tc" --version)")"
  fi
  printf '%s' "$tc" >"$dest/.parts/apple.toolchain"
  echo "$file" >"$dest/.parts/apple.file"
}

build_android() {
  local dest="$1" troot="$2" file info ndk java_home tc
  # Clear Gradle's and cargo-ndk's outputs so nothing from an earlier build is packaged.
  rm -rf sdk/android/build sdk/android/native
  info="$(mktemp "${TMPDIR:-/tmp}/colophon-android-info.XXXXXX")"
  BUILD_INFO_FILE="$info" CARGO_TARGET_DIR="$troot/host" bash scripts/build-android.sh
  check_generated
  file="colophon-android-$version.aar"
  cp sdk/android/build/outputs/aar/colophon-android-release.aar "$dest/$file"
  chmod 0644 "$dest/$file"
  ndk="$(grep '^ndk=' "$info" | cut -d= -f2-)"
  java_home="$(grep '^java_home=' "$info" | cut -d= -f2-)"
  rm -f "$info"
  tc="$(json_str rustc): $(json_str "$(tool_line rustc --version)"),
$(json_str cargo): $(json_str "$(tool_line cargo --version)"),
$(json_str cargo_ndk): $(json_str "$(tool_line cargo ndk --version)"),
$(json_str ndk): $(json_str "$(grep '^Pkg.Revision' "$ndk/source.properties" | cut -d= -f2- | tr -d ' ')"),
$(json_str jdk): $(json_str "$(grep '^JAVA_RUNTIME_VERSION=' "$java_home/release" | cut -d= -f2- | tr -d '"')"),
$(json_str gradle): $(json_str "$(grep '^distributionUrl=' sdk/android/gradle/wrapper/gradle-wrapper.properties | sed 's|.*/gradle-\(.*\)-bin.zip|\1|')"),
$(json_str android_gradle_plugin): $(json_str "$(sed -n 's/.*id("com.android.library") version "\(.*\)".*/\1/p' sdk/android/build.gradle.kts)"),
$(json_str kotlin): $(json_str "$(sed -n 's/.*kotlin("android") version "\(.*\)".*/\1/p' sdk/android/build.gradle.kts)")"
  printf '%s' "$tc" >"$dest/.parts/android.toolchain"
  echo "$file" >"$dest/.parts/android.file"
}

build_js() {
  local dest="$1" troot="$2" file tc packed
  if [[ ! -x js/node_modules/.bin/tsc ]]; then
    (cd js && npm ci --ignore-scripts --no-audit --no-fund)
  fi
  rm -rf js/dist
  CARGO_TARGET_DIR="$troot/host" bash js/scripts/build.sh
  packed="$(cd js && npm pack --silent --pack-destination "$dest")"
  file="$(echo "$packed" | tail -n 1)"
  chmod 0644 "$dest/$file"
  tc="$(json_str rustc): $(json_str "$(tool_line rustc --version)"),
$(json_str cargo): $(json_str "$(tool_line cargo --version)"),
$(json_str wasm_bindgen): $(json_str "$(tool_line wasm-bindgen --version)"),
$(json_str node): $(json_str "$(tool_line node --version)"),
$(json_str npm): $(json_str "$(tool_line npm --version)"),
$(json_str typescript): $(json_str "$(tool_line js/node_modules/.bin/tsc --version)")"
  printf '%s' "$tc" >"$dest/.parts/js.toolchain"
  echo "$file" >"$dest/.parts/js.file"
}

build_home() {
  local dest="$1" troot="$2" file stage dir tc f
  CARGO_TARGET_DIR="$troot/host" cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm
  stage="$(mktemp -d "${TMPDIR:-/tmp}/colophon-home.XXXXXX")"
  dir="$stage/colophon-home-$version"
  mkdir -p "$dir"
  for f in relay/*.js relay/package.json; do
    git ls-files --error-unmatch "$f" >/dev/null 2>&1 || { echo "package-release: $f is not tracked" >&2; exit 1; }
    cp "$f" "$dir/"
  done
  cp "$troot/host/wasm32-unknown-unknown/release/colophon_home_wasm.wasm" "$dir/"
  chmod 0644 "$dir"/*  # none of these is executable in git; cargo marks the .wasm 0755
  file="colophon-home-$version.tar.gz"
  tar_tree "$dir" "$dest/$file"
  rm -rf "$stage"
  tc="$(json_str rustc): $(json_str "$(tool_line rustc --version)"),
$(json_str cargo): $(json_str "$(tool_line cargo --version)")"
  printf '%s' "$tc" >"$dest/.parts/home.toolchain"
  echo "$file" >"$dest/.parts/home.file"
}

build_one() {
  local art="$1" dest="$2" troot="$3" file
  mkdir -p "$dest/.parts"
  if [[ -f "$dest/.parts/$art.file" ]]; then
    rm -f "$dest/$(cat "$dest/.parts/$art.file")" "$dest/$(cat "$dest/.parts/$art.file").contents.sha256"
  fi
  rm -f "$dest/.parts/$art".*
  set_rustflags "$troot"
  say "building $art into ${dest#"$root"/}"
  "build_$art" "$dest" "$troot"
  file="$(cat "$dest/.parts/$art.file")"
  list_contents "$dest/$file" "$dest/$file.contents.sha256"
  path_leaks "$dest/$file" >"$dest/.parts/$art.leaks"
  say "$art: $file $(sha_of "$dest/$file")"
}

# Per-file differences between two contents lists.
diff_contents() {
  local a="$1" b="$2"
  awk 'NR == FNR { h[$2] = $1; next }
       { if (!($2 in h)) print "    only in second build: " $2;
         else if (h[$2] != $1) print "    differs: " $2;
         seen[$2] = 1 }
       END { for (p in h) if (!(p in seen)) print "    only in first build: " p }' "$a" "$b" | LC_ALL=C sort
}

failed=0
if [[ "$verify" == 1 ]]; then
  rm -rf "$tbase/a" "$tbase/b" "$outb"
fi
mkdir -p "$out"
for art in "${selected[@]}"; do
  if [[ "$verify" == 1 ]]; then
    build_one "$art" "$out" "$tbase/a"
    build_one "$art" "$outb" "$tbase/b"
    fa="$(cat "$out/.parts/$art.file")"
    if [[ "$(sha_of "$out/$fa")" == "$(sha_of "$outb/$fa")" ]]; then
      say "$art reproduces: $fa"
      echo true >"$out/.parts/$art.reproduced"
    else
      echo false >"$out/.parts/$art.reproduced"
      failed=1
      echo "package-release: $art does NOT reproduce: $fa" >&2
      echo "  first  $(sha_of "$out/$fa")" >&2
      echo "  second $(sha_of "$outb/$fa")" >&2
      d="$(diff_contents "$out/$fa.contents.sha256" "$outb/$fa.contents.sha256")"
      if [[ -n "$d" ]]; then echo "$d" >&2; else echo "    every payload file is identical; only the archive differs" >&2; fi
    fi
  else
    build_one "$art" "$out" "$tbase/main"
    rm -f "$out/.parts/$art.reproduced"
  fi
done

# SHA256SUMS and manifest.json list every artefact in the directory, in a fixed order.
host="$(uname -sm) $(sw_vers -productVersion 2>/dev/null || true)"
entries=()
: >"$out/SHA256SUMS.next"
for art in "${all[@]}"; do
  [[ -f "$out/.parts/$art.file" ]] || continue
  f="$(cat "$out/.parts/$art.file")"
  (cd "$out" && shasum -a 256 "$f") >>"$out/SHA256SUMS.next"
  reproduced=null
  [[ -f "$out/.parts/$art.reproduced" ]] && reproduced="$(cat "$out/.parts/$art.reproduced")"
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
mv "$out/SHA256SUMS.next" "$out/SHA256SUMS"
{
  echo "{"
  echo "  $(json_str name): $(json_str colophon),"
  echo "  $(json_str version): $(json_str "$version"),"
  echo "  $(json_str commit): $(json_str "$commit"),"
  echo "  $(json_str dirty): $dirty,"
  echo "  $(json_str source_date_epoch): $SOURCE_DATE_EPOCH,"
  echo "  $(json_str host): $(json_str "$host"),"
  echo "  $(json_str signed): false,"
  echo "  $(json_str published): false,"
  echo "  $(json_str artefacts): ["
  for i in "${!entries[@]}"; do
    if [[ $i -lt $((${#entries[@]} - 1)) ]]; then echo "${entries[$i]},"; else echo "${entries[$i]}"; fi
  done
  echo "  ]"
  echo "}"
} >"$out/manifest.json"
say "wrote ${out#"$root"/}/SHA256SUMS and manifest.json"
cat "$out/SHA256SUMS"
if [[ "$verify" == 1 ]]; then
  if [[ "$failed" == 0 ]]; then
    say "verify: every selected artefact reproduced bit for bit"
    rm -rf "$tbase/a" "$tbase/b"
  else
    echo "package-release: verify FAILED; the second build is in ${outb#"$root"/}, target directories in $tbase/a and $tbase/b" >&2
    exit 1
  fi
fi
