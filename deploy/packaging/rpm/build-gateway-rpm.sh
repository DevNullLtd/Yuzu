#!/usr/bin/env bash
set -euo pipefail

# Build yuzu-gateway RPM from a rebar3 release.
# Usage: build-gateway-rpm.sh --rel-dir DIR --version VERSION [--output DIR]

REL_DIR=""
VERSION=""
PRERELEASE=""
OUTPUT="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rel-dir)     REL_DIR="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        --prerelease)  PRERELEASE="$2"; shift 2 ;;
        --output)      OUTPUT="$2"; shift 2 ;;
        --help)        echo "Usage: $0 --rel-dir DIR --version VERSION [--prerelease rc1] [--output DIR]"; exit 0 ;;
        *)             echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$REL_DIR" || -z "$VERSION" ]] && { echo "Error: --rel-dir and --version required"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOPDIR="$(mktemp -d)"
trap "rm -rf $TOPDIR" EXIT

mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy the Erlang release as source
mkdir -p "$TOPDIR/SOURCES/yuzu_gw"
cp -a "$REL_DIR"/* "$TOPDIR/SOURCES/yuzu_gw/"

# Systemd service
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-gateway.service" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/../../../deploy/docker/gateway-cookie-policy.sh" "$TOPDIR/SOURCES/"

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

# Build RPM
echo "=== Building yuzu-gateway-${VERSION} RPM ==="
sed -e "s/^Version:.*/Version:        $VERSION/" \
    -e "s/^Release:.*/Release:        $RPM_RELEASE/" \
    "$SCRIPT_DIR/yuzu-gateway.spec" > "$TOPDIR/SPECS/yuzu-gateway.spec"
rpmbuild --define "_topdir $TOPDIR" "${SYSTEMD_DEFINES[@]}" -bb "$TOPDIR/SPECS/yuzu-gateway.spec"

# Copy output
mkdir -p "$OUTPUT"
find "$TOPDIR/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT/" \;

echo "=== Done ==="
ls -la "$OUTPUT"/yuzu-gateway*.rpm 2>/dev/null
