#!/usr/bin/env bash
set -euo pipefail

# Build yuzu-gateway .deb from a rebar3 release tarball.
# Usage: build-gateway-deb.sh --rel-dir DIR --version VERSION [--output DIR]
#
# Expects rel-dir to point to _build/prod/rel/yuzu_gw/

REL_DIR=""
VERSION=""
OUTPUT="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rel-dir)  REL_DIR="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --output)   OUTPUT="$2"; shift 2 ;;
        --help)     echo "Usage: $0 --rel-dir DIR --version VERSION [--output DIR]"; exit 0 ;;
        *)          echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$REL_DIR" || -z "$VERSION" ]] && { echo "Error: --rel-dir and --version required"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$SCRIPT_DIR/../../.."
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")

echo "=== Building yuzu-gateway_${VERSION}_${ARCH}.deb ==="

PKG="$OUTPUT/yuzu-gateway_${VERSION}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/opt/yuzu_gw"
mkdir -p "$PKG/usr/lib/systemd/system"
mkdir -p "$PKG/var/log/yuzu"

# Copy the entire Erlang release (self-contained with embedded ERTS)
cp -a "$REL_DIR"/* "$PKG/opt/yuzu_gw/"

# Systemd service
cp "$DEPLOY_DIR/deploy/systemd/yuzu-gateway.service" "$PKG/usr/lib/systemd/system/"

# Control file
cat > "$PKG/DEBIAN/control" <<EOF
Package: yuzu-gateway
Version: $VERSION
Architecture: $ARCH
Maintainer: Yuzu Team <noreply@yuzu.io>
Depends: adduser
Section: admin
Priority: optional
Homepage: https://github.com/DevNullLtd/Yuzu
Description: Yuzu endpoint management gateway
 Erlang/OTP gateway node for scaling Yuzu agent connections.
 Routes commands from the server to agents and aggregates responses.
 Self-contained — includes embedded Erlang runtime.
EOF

# postinst
cat > "$PKG/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e
case "$1" in
    configure)
        # Create system user
        if ! getent passwd yuzu-gw >/dev/null 2>&1; then
            adduser --system --group --home /opt/yuzu_gw --no-create-home --shell /usr/sbin/nologin yuzu-gw
        fi

        # Set ownership
        chown -R yuzu-gw:yuzu-gw /opt/yuzu_gw
        install -d -m 0755 -o yuzu-gw -g yuzu-gw /var/log/yuzu

        # #659: generate a unique Erlang distribution cookie once. The gateway
        # refuses to boot with the historical default (a publicly known cookie =
        # unauthenticated inter-node RPC over EPMD). Never clobber on upgrade so
        # the cookie stays stable. For a multi-node cluster, set the SAME value
        # on every node (overwrite /etc/yuzu/gateway.env identically).
        install -d -m 0755 /etc/yuzu
        if [ ! -f /etc/yuzu/gateway.env ]; then
            COOKIE=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
            ( umask 027; printf 'YUZU_GW_COOKIE=%s\n' "$COOKIE" > /etc/yuzu/gateway.env )
            chown root:yuzu-gw /etc/yuzu/gateway.env
            chmod 0640 /etc/yuzu/gateway.env
            echo "yuzu-gateway: generated /etc/yuzu/gateway.env with a unique distribution cookie"
        fi

        # Enable systemd service
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
            systemctl enable yuzu-gateway.service || true
            echo "yuzu-gateway installed. Start with: systemctl start yuzu-gateway"
        fi
        ;;
esac
exit 0
POSTINST
chmod 0755 "$PKG/DEBIAN/postinst"

# prerm
cat > "$PKG/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e
case "$1" in
    remove|purge)
        if [ -d /run/systemd/system ]; then
            systemctl stop yuzu-gateway.service || true
            systemctl disable yuzu-gateway.service || true
        fi
        ;;
esac
exit 0
PRERM
chmod 0755 "$PKG/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$PKG"
echo "Built: ${PKG}.deb"
