#!/usr/bin/env bash
set -euo pipefail

# Build Yuzu .deb packages from pre-compiled binaries.
# Usage: build-deb.sh --bin-dir DIR --version VERSION [--output DIR]
#
# Expects bin-dir to contain: yuzu-server, yuzu-agent, plugins/

BIN_DIR=""
VERSION=""
OUTPUT="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir)  BIN_DIR="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --output)   OUTPUT="$2"; shift 2 ;;
        --help)     echo "Usage: $0 --bin-dir DIR --version VERSION [--output DIR]"; exit 0 ;;
        *)          echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$BIN_DIR" || -z "$VERSION" ]] && { echo "Error: --bin-dir and --version required"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")

# --- yuzu-server .deb ---
echo "=== Building yuzu-server_${VERSION}_${ARCH}.deb ==="
PKG="$OUTPUT/yuzu-server_${VERSION}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/local/bin"
mkdir -p "$PKG/usr/lib/systemd/system"
mkdir -p "$PKG/etc/yuzu"
mkdir -p "$PKG/var/lib/yuzu"
mkdir -p "$PKG/var/log/yuzu"
# InstructionDefinitions are embedded into the server binary at build
# time (server/core/scripts/embed_content.py); the runtime never reads
# them from disk. Don't ship the YAMLs alongside the binary — operators
# would edit them expecting changes to take effect.

# Handle both flat layout (staging) and meson build layout (server/core/)
if [[ -f "$BIN_DIR/yuzu-server" ]]; then
    cp "$BIN_DIR/yuzu-server" "$PKG/usr/local/bin/"
elif [[ -f "$BIN_DIR/server/core/yuzu-server" ]]; then
    cp "$BIN_DIR/server/core/yuzu-server" "$PKG/usr/local/bin/"
else
    echo "ERROR: yuzu-server not found in $BIN_DIR" >&2; exit 1
fi
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-server.service" "$PKG/usr/lib/systemd/system/"

# Postgres provisioning helper (ADR-0006, #1320). Shipped in the package and
# invoked non-fatally from postinst so a native install is Postgres-ready
# before the server starts requiring a DSN (#1320 PR 3 fail-closed flip).
mkdir -p "$PKG/usr/share/yuzu/scripts"
cp "$SCRIPT_DIR/../../../scripts/install-server-postgres.sh" "$PKG/usr/share/yuzu/scripts/"
chmod 0755 "$PKG/usr/share/yuzu/scripts/install-server-postgres.sh"

cat > "$PKG/DEBIAN/control" <<EOF
Package: yuzu-server
Version: $VERSION
Architecture: $ARCH
Maintainer: Yuzu Team <noreply@yuzu.io>
Depends: adduser
Section: admin
Priority: optional
Homepage: https://github.com/DevNullLtd/Yuzu
Description: Yuzu endpoint management server
 Enterprise endpoint management platform — server component.
EOF

cp "$SCRIPT_DIR/postinst" "$PKG/DEBIAN/"
cp "$SCRIPT_DIR/prerm" "$PKG/DEBIAN/"
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$PKG"
echo "Built: ${PKG}.deb"

# --- yuzu-agent .deb ---
echo "=== Building yuzu-agent_${VERSION}_${ARCH}.deb ==="
PKG="$OUTPUT/yuzu-agent_${VERSION}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/local/bin"
mkdir -p "$PKG/usr/lib/yuzu/plugins"
mkdir -p "$PKG/usr/lib/systemd/system"
mkdir -p "$PKG/var/lib/yuzu-agent"

if [[ -f "$BIN_DIR/yuzu-agent" ]]; then
    cp "$BIN_DIR/yuzu-agent" "$PKG/usr/local/bin/"
elif [[ -f "$BIN_DIR/agents/core/yuzu-agent" ]]; then
    cp "$BIN_DIR/agents/core/yuzu-agent" "$PKG/usr/local/bin/"
else
    echo "ERROR: yuzu-agent not found in $BIN_DIR" >&2; exit 1
fi
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-agent.service" "$PKG/usr/lib/systemd/system/"

# Agent core shared library (plugins link against it)
AGENT_CORE_FOUND=0
find "$BIN_DIR" -name 'libyuzu_agent_core.so*' -exec cp {} "$PKG/usr/lib/yuzu/" \; 2>/dev/null && AGENT_CORE_FOUND=1
if [[ "$AGENT_CORE_FOUND" -eq 0 ]] || ! ls "$PKG/usr/lib/yuzu/libyuzu_agent_core.so"* >/dev/null 2>&1; then
    echo "WARNING: libyuzu_agent_core.so not found in $BIN_DIR — agent may fail to start" >&2
fi

# Plugin shared libraries
if [[ -d "$BIN_DIR/plugins" ]]; then
    cp "$BIN_DIR/plugins/"*.so "$PKG/usr/lib/yuzu/plugins/" 2>/dev/null || true
fi
find "$BIN_DIR/agents/plugins" -name '*.so' -exec cp {} "$PKG/usr/lib/yuzu/plugins/" \; 2>/dev/null || true

# ldconfig configuration so the linker can find libyuzu_agent_core.so
mkdir -p "$PKG/etc/ld.so.conf.d"
echo "/usr/lib/yuzu" > "$PKG/etc/ld.so.conf.d/yuzu.conf"

cat > "$PKG/DEBIAN/control" <<EOF
Package: yuzu-agent
Version: $VERSION
Architecture: $ARCH
Maintainer: Yuzu Team <noreply@yuzu.io>
Depends: adduser
Section: admin
Priority: optional
Homepage: https://github.com/DevNullLtd/Yuzu
Description: Yuzu endpoint management agent
 Enterprise endpoint management platform — agent component.
EOF

cp "$SCRIPT_DIR/postinst" "$PKG/DEBIAN/"
cp "$SCRIPT_DIR/prerm" "$PKG/DEBIAN/"
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$PKG"
echo "Built: ${PKG}.deb"

echo "=== Done ==="
