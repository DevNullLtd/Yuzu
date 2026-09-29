#!/usr/bin/env bash
# Build Yuzu Windows installers (agent, server, or both).
#
# Usage:
#   bash deploy/packaging/windows/build-installer.sh [--builddir DIR] [--version VER] [--target agent|server|all]
#
# Defaults:
#   --builddir  builddir       (relative to repo root)
#   --version   extracted from meson.build
#   --target    all
#
# Requires: InnoSetup 6 (ISCC.exe on PATH, or installed via Chocolatey)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Defaults
BUILD_DIR="$REPO_ROOT/builddir"
VERSION=""
TARGET="all"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --builddir) BUILD_DIR="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --target)   TARGET="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--builddir DIR] [--version VER] [--target agent|server|all]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Extract version from meson.build if not provided
if [[ -z "$VERSION" ]]; then
    VERSION=$(grep -oP "version:\s*'\K[^']+" "$REPO_ROOT/meson.build" | head -1)
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: Could not extract version from meson.build" >&2
        exit 1
    fi
fi

echo "=== Yuzu Windows Installer Builder ==="
echo "Version:   $VERSION"
echo "Build dir: $BUILD_DIR"
echo "Target:    $TARGET"
echo ""

# Find ISCC.exe
ISCC=""
if command -v ISCC &>/dev/null; then
    ISCC="ISCC"
elif [[ -f "/c/ProgramData/chocolatey/bin/ISCC.exe" ]]; then
    ISCC="/c/ProgramData/chocolatey/bin/ISCC.exe"
elif [[ -f "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" ]]; then
    ISCC="/c/Program Files (x86)/Inno Setup 6/ISCC.exe"
elif [[ -f "/c/Program Files/Inno Setup 6/ISCC.exe" ]]; then
    ISCC="/c/Program Files/Inno Setup 6/ISCC.exe"
else
    echo "ERROR: ISCC.exe not found. Install InnoSetup: choco install innosetup" >&2
    exit 1
fi

echo "ISCC: $ISCC"

# Create output directory
mkdir -p "$SCRIPT_DIR/output"

# Convert paths to Windows format for ISCC
WIN_BUILD_DIR=$(cygpath -w "$BUILD_DIR" 2>/dev/null || echo "$BUILD_DIR")

# ── Build agent installer ──
if [[ "$TARGET" == "agent" || "$TARGET" == "all" ]]; then
    echo ""
    echo "=== Building Agent Installer ==="

    if [[ ! -f "$BUILD_DIR/agents/core/yuzu-agent.exe" ]]; then
        echo "ERROR: yuzu-agent.exe not found in $BUILD_DIR/agents/core/" >&2
        echo "Run 'meson compile -C builddir' first." >&2
        exit 1
    fi

    AGENT_DLL_COUNT=$(ls "$BUILD_DIR/agents/core/"*.dll 2>/dev/null | wc -l)
    echo "Agent exe:    found"
    echo "Runtime DLLs: $AGENT_DLL_COUNT"

    WIN_ISS=$(cygpath -w "$SCRIPT_DIR/yuzu-agent.iss" 2>/dev/null || echo "$SCRIPT_DIR/yuzu-agent.iss")

    MSYS_NO_PATHCONV=1 "$ISCC" \
        "/DAppVersion=$VERSION" \
        "/DBuildDir=$WIN_BUILD_DIR" \
        "$WIN_ISS"

    echo "Built: $SCRIPT_DIR/output/YuzuAgentSetup-$VERSION.exe"
fi

# ── Build server installer ──
if [[ "$TARGET" == "server" || "$TARGET" == "all" ]]; then
    echo ""
    echo "=== Building Server Installer ==="

    if [[ ! -f "$BUILD_DIR/server/core/yuzu-server.exe" ]]; then
        echo "ERROR: yuzu-server.exe not found in $BUILD_DIR/server/core/" >&2
        echo "Run 'meson compile -C builddir' first." >&2
        exit 1
    fi

    echo "Server exe:   found"

    WIN_ISS=$(cygpath -w "$SCRIPT_DIR/yuzu-server.iss" 2>/dev/null || echo "$SCRIPT_DIR/yuzu-server.iss")

    MSYS_NO_PATHCONV=1 "$ISCC" \
        "/DAppVersion=$VERSION" \
        "/DBuildDir=$WIN_BUILD_DIR" \
        "$WIN_ISS"

    echo "Built: $SCRIPT_DIR/output/YuzuServerSetup-$VERSION.exe"
fi

echo ""
echo "=== Build complete ==="
ls -lh "$SCRIPT_DIR/output/"*.exe 2>/dev/null || true
