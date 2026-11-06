#!/usr/bin/env bash
# link-tests.sh — create /tests-build-<component>-<triplet>/ symlinks.
#
# Meson places test binaries inside the per-OS build dir at
# <builddir>/tests/yuzu_<component>_tests (with .exe on Windows). That path
# is awkward to remember — CLAUDE.md used to need a "magic string" section
# just to find them. This script exposes the binaries at a stable,
# discoverable top-level path that names the component and triplet
# explicitly:
#
#   tests-build-agent-linux_x64/yuzu_agent_tests
#   tests-build-server-linux_x64/yuzu_server_tests
#   tests-build-echo-linux_x64/yuzu_echo_tests
#
# Each entry is a symlink to the live build output, so it stays current
# across rebuilds without the script having to run again. Invoked
# automatically at the end of scripts/setup.sh, but safe to run standalone
# after any build.
#
# Usage:
#   bash scripts/link-tests.sh [--builddir DIR]
#
# If --builddir is not given, defaults to build-linux / build-macos /
# build-windows based on the host OS — matching the convention in
# scripts/setup.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Detect host OS, triplet, default build dir ────────────────────────────
HOST_OS=""
TRIPLET=""
BIN_SUFFIX=""
if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
  HOST_OS="windows"
  TRIPLET="windows_x64"
  BIN_SUFFIX=".exe"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  HOST_OS="macos"
  if [[ "$(uname -m)" == "arm64" ]]; then
    TRIPLET="macos_arm64"
  else
    TRIPLET="macos_x64"
  fi
else
  HOST_OS="linux"
  case "$(uname -m)" in
    x86_64)  TRIPLET="linux_x64" ;;
    aarch64) TRIPLET="linux_arm64" ;;
    armv7l)  TRIPLET="linux_arm" ;;
    *)       TRIPLET="linux_$(uname -m)" ;;
  esac
fi

BUILDDIR="build-${HOST_OS}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --builddir) BUILDDIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,25p' "$0"
      exit 0
      ;;
    *)
      echo "link-tests.sh: unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

BUILD_TESTS_DIR="$PROJECT_ROOT/$BUILDDIR/tests"
if [[ ! -d "$BUILD_TESTS_DIR" ]]; then
  echo "link-tests.sh: no test binaries yet at $BUILD_TESTS_DIR — skipping" >&2
  exit 0
fi

# ── Link each component's test binary ─────────────────────────────────────
# Add a new component by appending its short name here. The binary is
# expected at <BUILD_TESTS_DIR>/yuzu_<component>_tests[.exe].
COMPONENTS=(agent server echo)

linked=0
skipped=0
for comp in "${COMPONENTS[@]}"; do
  src="$BUILD_TESTS_DIR/yuzu_${comp}_tests${BIN_SUFFIX}"
  if [[ ! -f "$src" ]]; then
    skipped=$((skipped + 1))
    continue
  fi

  dst_dir="$PROJECT_ROOT/tests-build-${comp}-${TRIPLET}"
  dst="$dst_dir/yuzu_${comp}_tests${BIN_SUFFIX}"

  mkdir -p "$dst_dir"

  # Remove any stale entry (file, symlink, or broken symlink) before relinking.
  if [[ -L "$dst" ]] || [[ -e "$dst" ]]; then
    rm -f "$dst"
  fi

  # Prefer a relative symlink so the link continues to resolve if the repo
  # is moved. Fall back to copy on systems where symlink creation fails
  # (Windows without developer-mode, some restricted filesystems).
  rel_src="$(python3 -c "import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))" \
    "$src" "$dst_dir" 2>/dev/null || echo "")"
  if [[ -n "$rel_src" ]] && ln -s "$rel_src" "$dst" 2>/dev/null; then
    :
  elif ln -s "$src" "$dst" 2>/dev/null; then
    :
  else
    cp -f "$src" "$dst"
    echo "link-tests.sh: symlink not supported, copied ${comp} binary instead" >&2
  fi

  linked=$((linked + 1))
done

echo "link-tests.sh: linked ${linked} test binaries into tests-build-*-${TRIPLET}/ (skipped ${skipped} not-yet-built)"
