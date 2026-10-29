#!/usr/bin/env bash
# vcpkg-triplet-sentinel.sh — invalidate vcpkg_installed/<triplet>/ ONLY when
# its inputs actually changed. Universal cache-key contract from the CI
# overhaul plan (PR-2):
#
#   key = sha256(
#       vcpkg.json
#     | vcpkg-configuration.json
#     | triplets/<triplet>.cmake     (when an overlay exists; otherwise empty)
#     | $VCPKG_COMMIT                (vcpkg baseline pinned in CI env)
#   )
#
# Scope of action on key drift:
#   - rm -rf vcpkg_installed/<triplet>/         (the per-triplet install root)
#   - rm -rf vcpkg_installed/vcpkg/             (per-workspace registry —
#     info/, status, updates/. Leaving this in place after wiping the
#     triplet tree leaves orphaned `info/<port>_<triplet>.list` entries
#     that make the next `vcpkg install` short-circuit to "already
#     installed" and then fail post-install pkgconfig validation. #741.)
#   - write the new key to vcpkg_installed/.<triplet>-cachekey.sha256
#
# Scope NEVER touched:
#   - $WS/vcpkg/                   (vcpkg tool root, owned by lukka/run-vcpkg
#                                    — distinct from $WS/vcpkg_installed/vcpkg/)
#   - runner.tool_cache/...        (binary cache zips — that's the warm tier)
#   - ccache (~/.cache/ccache, %LOCALAPPDATA%\ccache)
#   - any other vcpkg_installed/<other-triplet>/ tree
#
# Cross-platform: bash only, sha256sum (Linux + MSYS2 bash on Windows + macOS).
# Idempotent. Exit 0 unconditionally — a sentinel mismatch is a normal state,
# not a failure. Hard errors (no manifest, missing workspace) exit non-zero.

set -uo pipefail
# NOTE: `set -e` deliberately omitted. Under MSYS2 bash on the Windows
# self-hosted runner, the `[[ test ]] && cmd` short-circuit pattern
# silently exits the script before any echo runs (run #25051196135 hit
# this — the script produced zero log output and exited non-zero,
# making diagnosis impossible). Explicit if/fi blocks plus per-command
# error checks instead.

# Self-identify so the next failure isn't a 0-byte log line.
echo "vcpkg-triplet-sentinel.sh: starting (triplet=${1:-?}, GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-<unset>})"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <triplet>" >&2
  exit 2
fi
TRIPLET="$1"

WS="${GITHUB_WORKSPACE:-$(pwd)}"
# On MSYS2 Windows GITHUB_WORKSPACE arrives as 'C:\actions-runner\...'
# with backslashes. Translate to POSIX form when cygpath is available so
# `cd` and downstream relative-path operations behave consistently across
# Linux / MSYS2 / macOS.
if command -v cygpath >/dev/null 2>&1; then
  WS=$(cygpath -u "$WS")
fi
if ! cd "$WS"; then
  echo "::error::cd to '$WS' failed" >&2
  exit 2
fi
echo "vcpkg-triplet-sentinel.sh: cwd=$(pwd)"

if [[ ! -f vcpkg.json ]]; then
  echo "::error::$(pwd) has no vcpkg.json — cannot compute sentinel" >&2
  exit 2
fi

# --- compute the cache key ------------------------------------------------
#
# sha256sum reads every input that exists; missing inputs are skipped (they
# contribute nothing to the digest). The vcpkg-configuration.json is a hard
# requirement of the manifest layout for our pinned-baseline mode but the
# overlay triplet is conditional — x64-linux-asan / x64-linux-tsan /
# x64-linux-static / x64-windows and the macOS target arm64-osx each have one.
# Stock triplets such as x64-linux do not.
inputs=(vcpkg.json)
if [[ -f vcpkg-configuration.json ]]; then
  inputs+=(vcpkg-configuration.json)
fi
overlay="triplets/${TRIPLET}.cmake"
if [[ -f "$overlay" ]]; then
  inputs+=("$overlay")
fi
echo "vcpkg-triplet-sentinel.sh: inputs=${inputs[*]}"

# Include the vcpkg baseline commit so a baseline bump invalidates every
# cache (correct: ports may have changed even if our manifest didn't).
baseline="${VCPKG_COMMIT:-unset}"

if ! want=$( { sha256sum "${inputs[@]}" && printf '%s\n' "$baseline"; } | sha256sum | awk '{print $1}'); then
  echo "::error::sha256sum pipeline failed" >&2
  exit 2
fi
if [[ -z "$want" ]]; then
  echo "::error::sha256sum produced empty output" >&2
  exit 2
fi

# --- compare against stored sentinel --------------------------------------
sentinel_dir="$WS/vcpkg_installed"
sentinel_file="$sentinel_dir/.${TRIPLET}-cachekey.sha256"
installed_dir="$sentinel_dir/${TRIPLET}"

mkdir -p "$sentinel_dir"
have=$(cat "$sentinel_file" 2>/dev/null || echo "")

registry_dir="$sentinel_dir/vcpkg"

if [[ "$want" != "$have" ]]; then
  echo "vcpkg sentinel drift for triplet=${TRIPLET}"
  echo "  inputs:   ${inputs[*]}"
  echo "  baseline: ${baseline}"
  echo "  have=${have:-<none>}"
  echo "  want=${want}"
  if [[ -d "$installed_dir" ]]; then
    echo "  wiping ${installed_dir}"
    rm -rf "$installed_dir"
  else
    echo "  no existing tree to wipe"
  fi
  # Wipe the per-workspace registry alongside the triplet tree so vcpkg
  # cannot short-circuit to "already installed" against a phantom entry
  # in `vcpkg/info/<port>_<triplet>.list`. #741.
  if [[ -d "$registry_dir" ]]; then
    echo "  wiping ${registry_dir} (workspace registry)"
    rm -rf "$registry_dir"
  else
    echo "  no existing registry to wipe"
  fi
  echo "$want" > "$sentinel_file"
else
  echo "vcpkg sentinel unchanged for triplet=${TRIPLET} — keeping vcpkg_installed/${TRIPLET}"
fi

# --- defensive invariant: registry-without-tree is always orphaned --------
#
# Runs whether or not the cache key drifted. The "wipe both halves on
# drift" rule above plugs the path where a NEW commit lands on a corrupt
# workspace; this rule plugs the path where the SAME commit re-runs on a
# workspace that an earlier crash, abort, or pre-#741 sentinel run left
# in the orphaned-registry state. Without it, every sentinel-passes
# branch would happily preserve `vcpkg/info/<port>_<triplet>.list`
# entries pointing at files in a `<triplet>/` tree that doesn't exist —
# vcpkg short-circuits to "already installed" and then fails post-install
# pkgconfig validation. Self-healing on the very first run after the
# orphan appears, regardless of when the sentinel was last bumped.
if [[ -d "$registry_dir" && ! -d "$installed_dir" ]]; then
  echo "vcpkg sentinel: orphaned registry detected for triplet=${TRIPLET}"
  echo "  ${registry_dir} exists but ${installed_dir} does not"
  echo "  wiping ${registry_dir} (workspace registry) to recover"
  rm -rf "$registry_dir"
fi

exit 0
