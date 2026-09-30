#!/usr/bin/env bash
# Build the Yuzu Agent macOS installer package (.pkg).
#
# Usage:
#   bash deploy/packaging/macos/build-pkg.sh \
#     --bin-dir builddir --version 0.7.0 [--output dist/]
#
# Requires: macOS with pkgbuild and productbuild (Xcode CLI tools).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR=""
VERSION=""
OUTPUT_DIR="."
IDENTIFIER="com.yuzu.agent"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir)  BIN_DIR="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --output)   OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --bin-dir DIR --version VER [--output DIR]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$BIN_DIR" || -z "$VERSION" ]]; then
    echo "ERROR: --bin-dir and --version are required" >&2
    exit 1
fi

echo "=== Yuzu Agent macOS Package Builder ==="
echo "Version:   $VERSION"
echo "Bin dir:   $BIN_DIR"
echo "Output:    $OUTPUT_DIR"
echo ""

# Verify binaries exist
AGENT_BIN="$BIN_DIR/yuzu-agent"
if [[ ! -f "$AGENT_BIN" ]]; then
    # Try subdirectory layout
    AGENT_BIN="$BIN_DIR/agents/core/yuzu-agent"
fi
if [[ ! -f "$AGENT_BIN" ]]; then
    echo "ERROR: yuzu-agent not found in $BIN_DIR" >&2
    exit 1
fi

# ── Create staging layout ──────────────────────────────────────────
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

SCRIPTS="$(mktemp -d)"
trap 'rm -rf "$STAGING" "$SCRIPTS"' EXIT

echo "Staging files..."

# Binary
install -d "${STAGING}/usr/local/bin"
install -m 755 "$AGENT_BIN" "${STAGING}/usr/local/bin/yuzu-agent"

# Agent core dylib
CORE_DYLIB=""
for candidate in \
    "$BIN_DIR/libyuzu_agent_core.dylib" \
    "$BIN_DIR/agents/core/libyuzu_agent_core.dylib"; do
    if [[ -f "$candidate" ]]; then
        CORE_DYLIB="$candidate"
        break
    fi
done
if [[ -n "$CORE_DYLIB" ]]; then
    # Next to the binary, not in /usr/local/lib (#5144): yuzu-agent loads
    # @rpath/libyuzu_agent_core.dylib and its only LC_RPATH is @loader_path/
    # (the build-tree rpath; release.yml ships build-dir binaries without
    # `meson install`), so dyld looks only in /usr/local/bin. This matches the
    # tarball, which also ships the dylib beside the binary, and leaves the
    # signed/notarized binary untouched (adding an rpath would invalidate it).
    install -m 755 "$CORE_DYLIB" "${STAGING}/usr/local/bin/"
fi

# Plugins
install -d "${STAGING}/usr/local/lib/yuzu/plugins"
PLUGIN_COUNT=0

# Try builddir/plugins/ first (deploy_build_dlls layout)
if [[ -d "$BIN_DIR/plugins" ]]; then
    for p in "$BIN_DIR/plugins/"*.dylib; do
        [[ -f "$p" ]] || continue
        install -m 755 "$p" "${STAGING}/usr/local/lib/yuzu/plugins/"
        PLUGIN_COUNT=$((PLUGIN_COUNT + 1))
    done
fi

# Try agents/plugins/ subdirectories
if [[ $PLUGIN_COUNT -eq 0 && -d "$BIN_DIR/agents/plugins" ]]; then
    find "$BIN_DIR/agents/plugins" -name '*.dylib' -print0 | while IFS= read -r -d '' p; do
        install -m 755 "$p" "${STAGING}/usr/local/lib/yuzu/plugins/"
        PLUGIN_COUNT=$((PLUGIN_COUNT + 1))
    done
fi

echo "  Binary:  yuzu-agent"
echo "  Dylib:   $(basename "${CORE_DYLIB:-none}")"
echo "  Plugins: $PLUGIN_COUNT"

# LaunchDaemon plist
install -d "${STAGING}/Library/LaunchDaemons"
install -m 644 "${SCRIPT_DIR}/com.yuzu.agent.plist" \
    "${STAGING}/Library/LaunchDaemons/com.yuzu.agent.plist"

# Data and log directories (created by postinstall, but set ownership here)
install -d -m 750 "${STAGING}/Library/Application Support/Yuzu"
install -d -m 755 "${STAGING}/Library/Logs/Yuzu"

# ── Install scripts ─────────────────────────────────────────────────
install -m 755 "${SCRIPT_DIR}/preinstall" "${SCRIPTS}/preinstall"
install -m 755 "${SCRIPT_DIR}/postinstall" "${SCRIPTS}/postinstall"

# ── Build component package ─────────────────────────────────────────
COMPONENT_PKG="$(mktemp -d)/yuzu-agent-component.pkg"

echo ""
echo "Building component package..."
pkgbuild \
    --root "$STAGING" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --scripts "$SCRIPTS" \
    --install-location "/" \
    "$COMPONENT_PKG"

# ── Build product archive (adds license, welcome, customization) ────
mkdir -p "$OUTPUT_DIR"
PRODUCT_PKG="$OUTPUT_DIR/YuzuAgent-${VERSION}-macos-arm64.pkg"

# Create a distribution XML for productbuild
DIST_XML="$(mktemp).xml"
cat > "$DIST_XML" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Yuzu Agent ${VERSION}</title>
    <organization>${IDENTIFIER}</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="12.0"/>
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default">
            <line choice="${IDENTIFIER}"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="${IDENTIFIER}" visible="false">
        <pkg-ref id="${IDENTIFIER}"/>
    </choice>
    <pkg-ref id="${IDENTIFIER}" version="${VERSION}" onConclusion="none">yuzu-agent-component.pkg</pkg-ref>
</installer-gui-script>
XML

echo "Building product archive..."
productbuild \
    --distribution "$DIST_XML" \
    --package-path "$(dirname "$COMPONENT_PKG")" \
    "$PRODUCT_PKG"

rm -f "$DIST_XML" "$COMPONENT_PKG"

SIZE=$(du -h "$PRODUCT_PKG" | cut -f1)
echo ""
echo "=== Build complete ==="
echo "Output: $PRODUCT_PKG ($SIZE)"
