#!/usr/bin/env bash
set -euo pipefail

# Build Yuzu RPMs from pre-compiled binaries.
# Usage: build-rpm.sh --bin-dir DIR --version VERSION [--output DIR]

BIN_DIR=""
VERSION=""
PRERELEASE=""
OUTPUT="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir)     BIN_DIR="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        --prerelease)  PRERELEASE="$2"; shift 2 ;;
        --output)      OUTPUT="$2"; shift 2 ;;
        --help)        echo "Usage: $0 --bin-dir DIR --version VERSION [--prerelease rc1] [--output DIR]"; exit 0 ;;
        *)             echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$BIN_DIR" || -z "$VERSION" ]] && { echo "Error: --bin-dir and --version required"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOPDIR="$(mktemp -d)"
trap "rm -rf $TOPDIR" EXIT

mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy sources — handle both flat layout and meson build layout
for bin in yuzu-server yuzu-agent; do
    if [[ -f "$BIN_DIR/$bin" ]]; then
        cp "$BIN_DIR/$bin" "$TOPDIR/SOURCES/"
    else
        # Meson layout: server/core/yuzu-server, agents/core/yuzu-agent
        found=$(find "$BIN_DIR" -name "$bin" -type f | head -1)
        [[ -n "$found" ]] && cp "$found" "$TOPDIR/SOURCES/" || { echo "ERROR: $bin not found in $BIN_DIR" >&2; exit 1; }
    fi
done
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-server.service" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-agent.service" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-agent-dmi-snapshot.sh" "$TOPDIR/SOURCES/"
# Postgres provisioning helper, shipped in the server RPM (ADR-0006, #1320)
cp "$SCRIPT_DIR/../../../scripts/install-server-postgres.sh" "$TOPDIR/SOURCES/"

# Agent core shared library (plugins link against it)
find "$BIN_DIR" -name 'libyuzu_agent_core.so*' -exec cp {} "$TOPDIR/SOURCES/" \; 2>/dev/null || true

# Plugins — check both builddir/plugins/ (deploy_dlls layout) and agents/plugins/ (meson layout)
mkdir -p "$TOPDIR/SOURCES/plugins"
if [[ -d "$BIN_DIR/plugins" ]]; then
    cp "$BIN_DIR/plugins/"*.so "$TOPDIR/SOURCES/plugins/" 2>/dev/null || true
fi
find "$BIN_DIR/agents/plugins" -name '*.so' -exec cp {} "$TOPDIR/SOURCES/plugins/" \; 2>/dev/null || true

# Determine Release field
if [[ -n "$PRERELEASE" ]]; then
    RPM_RELEASE="0.1.${PRERELEASE}%{?dist}"
else
    RPM_RELEASE="1%{?dist}"
fi

# Define systemd macros if not available (e.g., building on Ubuntu/Debian)
SYSTEMD_DEFINES=()
if ! rpm --showrc 2>/dev/null | grep -q systemd_post; then
    SYSTEMD_DEFINES=(
        --define "systemd_post() systemctl preset %{?*} >/dev/null 2>&1 || :"
        --define "systemd_preun() if [ \$1 -eq 0 ]; then systemctl --no-reload disable --now %{?*} >/dev/null 2>&1 || :; fi"
        --define "systemd_postun_with_restart() if [ \$1 -ge 1 ]; then systemctl try-restart %{?*} >/dev/null 2>&1 || :; fi"
        --define "_unitdir /usr/lib/systemd/system"
    )
fi

# Build server RPM
echo "=== Building yuzu-server-${VERSION} RPM ==="
sed -e "s/^Version:.*/Version:        $VERSION/" \
    -e "s/^Release:.*/Release:        $RPM_RELEASE/" \
    "$SCRIPT_DIR/yuzu-server.spec" > "$TOPDIR/SPECS/yuzu-server.spec"
rpmbuild --define "_topdir $TOPDIR" "${SYSTEMD_DEFINES[@]}" -bb "$TOPDIR/SPECS/yuzu-server.spec"

# Build agent RPM
echo "=== Building yuzu-agent-${VERSION} RPM ==="
sed -e "s/^Version:.*/Version:        $VERSION/" \
    -e "s/^Release:.*/Release:        $RPM_RELEASE/" \
    "$SCRIPT_DIR/yuzu-agent.spec" > "$TOPDIR/SPECS/yuzu-agent.spec"
rpmbuild --define "_topdir $TOPDIR" "${SYSTEMD_DEFINES[@]}" -bb "$TOPDIR/SPECS/yuzu-agent.spec"

# Copy output
mkdir -p "$OUTPUT"
find "$TOPDIR/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT/" \;

echo "=== Done ==="
ls -la "$OUTPUT"/*.rpm 2>/dev/null
