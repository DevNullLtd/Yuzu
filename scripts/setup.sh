#!/bin/bash
# setup.sh — Configure and prepare a Yuzu build directory using Meson.
#
# Wraps vcpkg install + meson setup into a single command.
# On Windows, source setup_msvc_env.sh first.
#
# This script picks a per-OS default build directory (build-linux,
# build-windows, build-macos) so the same source tree can be configured
# concurrently from WSL2 and a native Windows shell — and from a separate
# macOS host — without the build dirs trampling each other.
#
# Usage:
#   ./scripts/setup.sh [--buildtype debug|release] [--tests] [--lto]
#                       [--native-file FILE] [--cross-file FILE]
#                       [--builddir DIR] [--wipe] [-- extra meson args...]
#
# Examples:
#   ./scripts/setup.sh                              # debug build, default compiler
#   ./scripts/setup.sh --buildtype release --lto    # release + LTO
#   ./scripts/setup.sh --tests                      # enable tests
#   ./scripts/setup.sh --native-file meson/native/linux-gcc13.ini
#   ./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini
#   ./scripts/setup.sh -- -Dbuild_agent=false       # pass extra args to meson

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Detect platform and vcpkg triplet ────────────────────────────────────────
# (Detected before BUILDDIR default so the per-OS name is correct.)
HOST_OS=""
if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
  HOST_OS="windows"
  TRIPLET="x64-windows"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  HOST_OS="macos"
  if [[ "$(uname -m)" == "arm64" ]]; then
    TRIPLET="arm64-osx"
  else
    TRIPLET="x64-osx"
  fi
else
  HOST_OS="linux"
  TRIPLET="x64-linux"
fi

# ── Defaults ──────────────────────────────────────────────────────────────────
BUILDDIR="build-${HOST_OS}"
BUILDTYPE="debug"
TESTS=false
LTO=false
WIPE=false
NATIVE_FILE=""
CROSS_FILE=""
EXTRA_ARGS=()

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --builddir)    BUILDDIR="$2"; shift 2 ;;
    --buildtype)   BUILDTYPE="$2"; shift 2 ;;
    --tests)       TESTS=true; shift ;;
    --lto)         LTO=true; shift ;;
    --wipe)        WIPE=true; shift ;;
    --native-file) NATIVE_FILE="$2"; shift 2 ;;
    --cross-file)  CROSS_FILE="$2"; shift 2 ;;
    --)            shift; EXTRA_ARGS+=("$@"); break ;;
    *)             echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Cross-compile overrides the host triplet (but keeps the host-named builddir
# unless the caller passed --builddir explicitly).
if [[ -n "$CROSS_FILE" ]]; then
  case "$CROSS_FILE" in
    *aarch64*) TRIPLET="arm64-linux" ;;
    *armv7*)   TRIPLET="arm-linux" ;;
    *)         echo "Warning: could not infer vcpkg triplet from cross file." >&2 ;;
  esac
fi

# ── Reject reusing a build dir from a different host OS ──────────────────────
# meson-info.json records the absolute source path of the configuring host.
# Windows builds record "C:\...", POSIX builds record "/mnt/c/..." or "/Users/...".
# Mixing them produces opaque ninja errors deep into the build, so detect early.
MESON_INFO="$PROJECT_ROOT/$BUILDDIR/meson-info/meson-info.json"
if [[ -f "$MESON_INFO" ]] && ! $WIPE; then
  RECORDED_SRC="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('directories',{}).get('source',''))" "$MESON_INFO" 2>/dev/null || true)"
  if [[ -n "$RECORDED_SRC" ]]; then
    case "$HOST_OS" in
      windows) EXPECTED_PREFIX_RE='^[A-Za-z]:[\\/]' ;;
      *)       EXPECTED_PREFIX_RE='^/' ;;
    esac
    if ! [[ "$RECORDED_SRC" =~ $EXPECTED_PREFIX_RE ]]; then
      echo "Error: $BUILDDIR was configured from a different host (source=$RECORDED_SRC)." >&2
      echo "       This script is running on $HOST_OS. Either:" >&2
      echo "         - re-run with --wipe to start fresh, or" >&2
      echo "         - re-run with --builddir build-${HOST_OS}-alt to keep both." >&2
      exit 1
    fi
  fi
fi

# ── vcpkg install ─────────────────────────────────────────────────────────────
if [[ -z "${VCPKG_ROOT:-}" ]]; then
  echo "Error: VCPKG_ROOT is not set. Set it to your vcpkg installation directory." >&2
  exit 1
fi

# Normalize to Unix-style path for MSYS2 compatibility
VCPKG_EXE="$VCPKG_ROOT/vcpkg"
if [[ ! -x "$VCPKG_EXE" ]] && [[ -f "$VCPKG_ROOT/vcpkg.exe" ]]; then
  VCPKG_EXE="$VCPKG_ROOT/vcpkg.exe"
fi

echo "── Installing vcpkg packages (triplet: ${TRIPLET}) ──"
VCPKG_INSTALL_ARGS=(
  install
  --x-manifest-root="$PROJECT_ROOT"
)
if [[ -n "$TRIPLET" ]]; then
  VCPKG_INSTALL_ARGS+=(--triplet="$TRIPLET")
fi
"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"

# ── Determine cmake_prefix_path for Meson ────────────────────────────────────
# vcpkg manifest mode installs to <manifest-root>/vcpkg_installed/ (not
# $VCPKG_ROOT/installed/).  Prefer the manifest-local directory when it exists.
VCPKG_INSTALLED_ROOT="$PROJECT_ROOT/vcpkg_installed"
if [[ ! -d "$VCPKG_INSTALLED_ROOT" ]]; then
  VCPKG_INSTALLED_ROOT="$VCPKG_ROOT/installed"
fi
if [[ -n "$TRIPLET" ]]; then
  VCPKG_INSTALLED="$VCPKG_INSTALLED_ROOT/$TRIPLET"
else
  VCPKG_INSTALLED="$VCPKG_INSTALLED_ROOT"
fi

# ── Build meson setup command ─────────────────────────────────────────────────
MESON_ARGS=(
  setup "$BUILDDIR"
  --buildtype="$BUILDTYPE"
)

# Native / cross files
if [[ -n "$NATIVE_FILE" ]]; then
  MESON_ARGS+=(--native-file "$NATIVE_FILE")
fi
if [[ -n "$CROSS_FILE" ]]; then
  MESON_ARGS+=(--cross-file "$CROSS_FILE")
fi

# vcpkg integration: pass cmake_prefix_path so Meson's cmake dependency method
# can find packages installed by vcpkg.
MESON_ARGS+=(-Dcmake_prefix_path="$VCPKG_INSTALLED")

# Also pass pkg_config_path: spdlog/fmt resolve via pkg-config first, and with
# the cmake prefix alone a system spdlog in pkg-config's default search path
# shadows the vcpkg one — configure succeeds, the link then dies on
# `undefined reference to fmt::v12::...` (#3725; CLAUDE.md "Manual configure").
# The vcpkg dir goes first so it wins; the platform's system dir is appended so
# distro deps keep resolving, and any caller-exported PKG_CONFIG_PATH is folded
# in after that (the Meson option REPLACES the env var, it does not extend it).
# Linux/macOS only: the Windows MSVC build hand-wires its deps (#375) and
# pkg-config behaviour under MSYS2+MSVC is unverified — do not guess there.
# Precedence: skipped entirely when the native/cross file sets pkg_config_path
# (a command-line -D would silently override the file); an explicit
# -Dpkg_config_path after `--` still wins because a later -D beats an earlier
# one on the meson command line.
MACHINE_FILE_SETS_PKGCONF=false
for MF in "$NATIVE_FILE" "$CROSS_FILE"; do
  [[ -z "$MF" ]] && continue
  [[ ! -f "$MF" ]] && MF="$PROJECT_ROOT/$MF"
  # Section-aware: only a pkg_config_path key inside [built-in options] (or
  # [project options]) sets the meson option - the same identifier inside,
  # say, [constants] must not suppress our flag.
  if [[ -f "$MF" ]] && awk -F= '
      /^[[:space:]]*\[/ { insec = ($0 ~ /\[(built-in|project) options\]/) }
      insec && $1 ~ /^[[:space:]]*pkg_config_path[[:space:]]*$/ { found=1 }
      END { exit !found }' "$MF"; then
    MACHINE_FILE_SETS_PKGCONF=true
  fi
done
if [[ "$HOST_OS" != "windows" ]] && ! $MACHINE_FILE_SETS_PKGCONF; then
  PKG_CONFIG_DIRS="$VCPKG_INSTALLED/lib/pkgconfig"
  if [[ "$HOST_OS" == "linux" && -z "$CROSS_FILE" ]]; then
    # Debian-family multiarch layout first (gcc is a build prerequisite),
    # then the RHEL-family lib64 layout. Host dirs are wrong for a cross
    # target, so cross builds get the vcpkg dir only.
    MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
    if [[ -z "$MULTIARCH" ]] && command -v dpkg-architecture >/dev/null 2>&1; then
      MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
    fi
    if [[ -n "$MULTIARCH" && -d "/usr/lib/$MULTIARCH/pkgconfig" ]]; then
      PKG_CONFIG_DIRS+=",/usr/lib/$MULTIARCH/pkgconfig"
    elif [[ -d /usr/lib64/pkgconfig ]]; then
      PKG_CONFIG_DIRS+=",/usr/lib64/pkgconfig"
    fi
  fi
  # macOS needs no system dir: Homebrew's pkgconfig dir is on pkg-config's
  # built-in path, which is always searched after PKG_CONFIG_PATH.
  if [[ -n "${PKG_CONFIG_PATH:-}" ]]; then
    PKG_CONFIG_DIRS+=",${PKG_CONFIG_PATH//:/,}"
  fi
  MESON_ARGS+=(-Dpkg_config_path="$PKG_CONFIG_DIRS")
fi

# Options
if $TESTS; then
  MESON_ARGS+=(-Dbuild_tests=true)
fi
if $LTO; then
  MESON_ARGS+=(-Db_lto=true)
fi

# Extra args from user
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  MESON_ARGS+=("${EXTRA_ARGS[@]}")
fi

# Reuse the existing build dir if present and same-host: meson reconfigures
# in place. Only wipe if --wipe was passed (no silent destruction of work).
if [[ -d "$PROJECT_ROOT/$BUILDDIR" ]]; then
  if $WIPE; then
    echo "── Wiping existing build directory: $BUILDDIR ──"
    MESON_ARGS+=(--wipe)
  else
    echo "── Reconfiguring existing build directory: $BUILDDIR ──"
    echo "   note: dependency-resolution options (e.g. -Dpkg_config_path) may not affect"
    echo "   deps this build dir already resolved - meson can serve them from its"
    echo "   dependency cache. Re-run with --wipe (or run:"
    echo "   meson configure \"$BUILDDIR\" --clearcache) to re-resolve."
    MESON_ARGS+=(--reconfigure)
  fi
fi

echo "── Running: meson ${MESON_ARGS[*]} ──"
cd "$PROJECT_ROOT"
meson "${MESON_ARGS[@]}"

# Refresh the /tests-build-<component>-<triplet>/ convenience symlinks so
# the test binaries are discoverable at the top level. On fresh setups
# the script is a no-op (no binaries yet) — re-run after `meson compile`
# to materialize the links.
if [[ -x "$SCRIPT_DIR/link-tests.sh" ]]; then
  "$SCRIPT_DIR/link-tests.sh" --builddir "$BUILDDIR" || true
fi

echo ""
echo "Build configured. Next steps:"
echo "  meson compile -C $BUILDDIR"
if $TESTS; then
  echo "  meson test -C $BUILDDIR --suite server --print-errorlogs"
  echo "  bash scripts/link-tests.sh        # refresh tests-build-* symlinks"
fi
