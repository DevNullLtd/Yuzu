#!/usr/bin/env bash
# Build either the legacy loose-binary package or an opt-in signed app bundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR=""
BUNDLE_DIR=""
VERSION=""
OUTPUT_DIR="."
IDENTIFIER="com.yuzu.agent"
PLUGIN_TRUST_BUNDLE=""

usage() { echo "Usage: $0 (--bin-dir DIR | --bundle-dir DIR) --version VER [--output DIR] [--plugin-trust-bundle PEM]" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --bundle-dir) BUNDLE_DIR="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --plugin-trust-bundle) PLUGIN_TRUST_BUNDLE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage; exit 1 ;;
    esac
done
if [[ -z "$VERSION" || ( -z "$BIN_DIR" && -z "$BUNDLE_DIR" ) || ( -n "$BIN_DIR" && -n "$BUNDLE_DIR" ) ]]; then
    echo "ERROR: exactly one of --bin-dir or --bundle-dir and --version are required" >&2
    usage; exit 1
fi

STAGING="$(mktemp -d)"
SCRIPTS="$(mktemp -d)"
COMPONENT_DIR="$(mktemp -d)"
VALIDATION_DIR="$(mktemp -d)"
# Success is decided by reaching the end, never by $? in this trap: stock macOS
# /bin/bash 3.2 reports $?=0 to an EXIT trap after a `set -u` abort, so a
# status-preserving trap would still turn that abort into a successful exit.
BUILD_COMPLETED=0
cleanup() {
    local rc=$?
    rm -rf "$STAGING" "$SCRIPTS" "$COMPONENT_DIR" "$VALIDATION_DIR"
    # Keep a real failure's own status; only a "0" from an unfinished run is false.
    if [[ "$BUILD_COMPLETED" != 1 && "$rc" == 0 ]]; then rc=1; fi
    exit "$rc"
}
trap cleanup EXIT
install -m 755 "$SCRIPT_DIR/preinstall" "$SCRIPTS/preinstall"
install -m 755 "$SCRIPT_DIR/postinstall" "$SCRIPTS/postinstall"
install -d "${STAGING}/usr/local/lib/yuzu/.plugins.incoming"
: > "${STAGING}/usr/local/lib/yuzu/.package-files.incoming"
install -m 644 "$SCRIPT_DIR/merge-launchd-plist.js" "$STAGING/usr/local/lib/yuzu/merge-launchd-plist.js"

PACKAGE_MODE="loose"
AGENT_BIN=""
PLUGIN_COUNT=0
stage_loose_plugin() {
    local plugin="$1" name destination
    name="$(basename "$plugin")"
    destination="${STAGING}/usr/local/lib/yuzu/.plugins.incoming/$name"
    [[ "$name" != .* && ! -e "$destination" ]] || {
        echo "ERROR: duplicate or hidden plugin basename: $name" >&2; return 1; }
    install -m 755 "$plugin" "$destination"
    printf 'plugins/%s\n' "$name" >> "${STAGING}/usr/local/lib/yuzu/.package-files.incoming"
    PLUGIN_COUNT=$((PLUGIN_COUNT + 1))
}
if [[ -n "$BUNDLE_DIR" ]]; then
    PACKAGE_MODE="bundle"
    APP="$BUNDLE_DIR/YuzuAgent.app"
    PLUGINS="$BUNDLE_DIR/plugins"
    AGENT_BIN="$APP/Contents/MacOS/yuzu-agent"
    [[ -d "$APP" && -x "$AGENT_BIN" && -d "$PLUGINS" ]] || {
        echo "ERROR: --bundle-dir must contain YuzuAgent.app and plugins/" >&2; exit 1; }
    install -d "${STAGING}/Library/Application Support/YuzuAgent"
    install -d "${STAGING}/Library/LaunchDaemons" "${STAGING}/usr/local/lib/yuzu/.plugins.incoming"
    # pkgbuild recognizes a signed .app by its bundle identifier and relocates it
    # before postinstall, even when its payload name is hidden. Deliver a ZIP of
    # Contents instead; postinstall reconstructs and verifies the sealed app.
    STAGED_BUNDLE_ARCHIVE="${STAGING}/usr/local/lib/yuzu/.bundle-contents.incoming.zip"
    ditto -c -k --keepParent "$APP/Contents" "$STAGED_BUNDLE_ARCHIVE"
    STAGED_APP="${VALIDATION_DIR}/YuzuAgent.app"
    ditto -x -k "$STAGED_BUNDLE_ARCHIVE" "$STAGED_APP"
    STAGED_PLUGINS="${STAGING}/usr/local/lib/yuzu/.plugins.incoming"
    STAGED_POLICY="${STAGING}/usr/local/lib/yuzu/plugin-signing-policy.json"
    AGENT_BIN="$STAGED_APP/Contents/MacOS/yuzu-agent"
    [[ -x "$AGENT_BIN" ]] || { echo "ERROR: staged bundle executable is missing" >&2; exit 1; }
    ACTUAL_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$STAGED_APP/Contents/Info.plist")"
    [[ "$ACTUAL_VERSION" == "$VERSION" ]] || { echo "ERROR: staged bundle version does not match --version" >&2; exit 1; }
    POLICY_ARGS=()
    if [[ -f "$PLUGINS/plugin-signing-policy.json" ]]; then
        install -m 644 "$PLUGINS/plugin-signing-policy.json" \
            "$STAGED_POLICY"
    fi
    for plugin in "$PLUGINS"/*.dylib; do
        [[ -f "$plugin" ]] || continue
        install -m 755 "$plugin" "$STAGED_PLUGINS/$(basename "$plugin")"
        [[ ! -f "$plugin.sig" ]] || install -m 644 "$plugin.sig" "$STAGED_PLUGINS/$(basename "$plugin").sig"
    done
    # Validate only this private archive snapshot. Source bundle paths are
    # intentionally never read again, closing validation-to-publication races.
    codesign --verify --deep --strict --verbose=2 "$STAGED_APP"
    [[ ! -f "$STAGED_POLICY" ]] || POLICY_ARGS=(--plugin-signing-policy "$STAGED_POLICY")
    CMS_ENFORCEMENT=0
    if [[ -f "$STAGED_POLICY" ]] || compgen -G "$STAGED_PLUGINS/*.dylib.sig" >/dev/null; then
        CMS_ENFORCEMENT=1
        [[ -f "$STAGED_POLICY" ]] || {
            echo "ERROR: plugin CMS sidecars require a verified signing policy" >&2; exit 1; }
        [[ -n "$PLUGIN_TRUST_BUNDLE" && -f "$PLUGIN_TRUST_BUNDLE" ]] || {
            echo "ERROR: plugin CMS sidecars require --plugin-trust-bundle for final-byte verification" >&2; exit 1; }
        for plugin in "$STAGED_PLUGINS"/*.dylib; do
            [[ -f "$plugin" ]] || continue
            [[ -f "$plugin.sig" ]] || {
                echo "ERROR: all external plugins must have CMS sidecars when signing policy is present" >&2; exit 1; }
        done
    fi
    python3 "$SCRIPT_DIR/generate-launchd-plist.py" --source "$SCRIPT_DIR/com.yuzu.agent.plist" \
        --output "${STAGING}/Library/LaunchDaemons/.com.yuzu.agent.incoming.plist" \
        --bundle-executable "/Library/Application Support/YuzuAgent/YuzuAgent.app/Contents/MacOS/yuzu-agent" \
        ${POLICY_ARGS[@]+"${POLICY_ARGS[@]}"}  # bash 3.2: a bare empty "${a[@]}" trips set -u
    for plugin in "$STAGED_PLUGINS"/*.dylib; do
        [[ -f "$plugin" ]] || continue
        codesign --verify --strict --verbose=2 "$plugin"
        if [[ "$CMS_ENFORCEMENT" == 1 ]]; then
            "$STAGED_APP/Contents/MacOS/yuzu-agent" --verify-plugin-signature "$plugin" \
                --plugin-trust-bundle "$PLUGIN_TRUST_BUNDLE"
        fi
        printf 'plugins/%s\n' "$(basename "$plugin")" >> "${STAGING}/usr/local/lib/yuzu/.package-files.incoming"
        PLUGIN_COUNT=$((PLUGIN_COUNT + 1))
    done
    [[ "$PLUGIN_COUNT" -gt 0 ]] || { echo "ERROR: bundle has no external plugins" >&2; exit 1; }
else
    AGENT_BIN="$BIN_DIR/yuzu-agent"
    [[ -f "$AGENT_BIN" ]] || AGENT_BIN="$BIN_DIR/agents/core/yuzu-agent"
    [[ -f "$AGENT_BIN" ]] || { echo "ERROR: yuzu-agent not found in $BIN_DIR" >&2; exit 1; }
    install -d "${STAGING}/usr/local/bin"
    install -m 755 "$AGENT_BIN" "${STAGING}/usr/local/bin/.yuzu-agent.incoming"
    for candidate in "$BIN_DIR/libyuzu_agent_core.dylib" "$BIN_DIR/agents/core/libyuzu_agent_core.dylib"; do
        [[ -f "$candidate" ]] || continue
        # Beside the binary, not in /usr/local/lib (#5144): yuzu-agent loads
        # @rpath/libyuzu_agent_core.dylib and its only LC_RPATH is @loader_path/.
        install -m 755 "$candidate" "${STAGING}/usr/local/bin/.libyuzu_agent_core.incoming.dylib"
        break
    done
    if [[ -d "$BIN_DIR/plugins" ]]; then
        for plugin in "$BIN_DIR/plugins"/*.dylib; do
            [[ -f "$plugin" ]] || continue
            stage_loose_plugin "$plugin"
        done
    fi
    if [[ "$PLUGIN_COUNT" -eq 0 && -d "$BIN_DIR/agents/plugins" ]]; then
        while IFS= read -r -d '' plugin; do
            stage_loose_plugin "$plugin"
        done < <(find "$BIN_DIR/agents/plugins" -type f -name '*.dylib' -print0)
    fi
    install -d "${STAGING}/Library/LaunchDaemons"
    install -m 644 "$SCRIPT_DIR/com.yuzu.agent.plist" "${STAGING}/Library/LaunchDaemons/.com.yuzu.agent.incoming.plist"
fi

install -d "${STAGING}/Library/LaunchDaemons" "${STAGING}/Library/Application Support/YuzuAgent" "${STAGING}/Library/Logs/Yuzu"
install -m 755 "$SCRIPT_DIR/uninstall.sh" "${STAGING}/usr/local/lib/yuzu/uninstall.sh"
printf '%s\n' "$PACKAGE_MODE" > "${STAGING}/usr/local/lib/yuzu/.package-mode.incoming"

ARCHES="$(lipo -archs "$AGENT_BIN")"
case "$ARCHES" in
    arm64) ARCH="arm64" ;;
    x86_64) ARCH="x86_64" ;;
    *) echo "ERROR: package must contain one supported architecture, got: $ARCHES" >&2; exit 1 ;;
esac
COMPONENT_PKG="$COMPONENT_DIR/yuzu-agent-component.pkg"
pkgbuild --root "$STAGING" --identifier "$IDENTIFIER" --version "$VERSION" --scripts "$SCRIPTS" --install-location / "$COMPONENT_PKG"
mkdir -p "$OUTPUT_DIR"
PRODUCT_PKG="$OUTPUT_DIR/YuzuAgent-${VERSION}-macos-${ARCH}.pkg"
DIST_XML="$COMPONENT_DIR/distribution.xml"
cat > "$DIST_XML" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2"><title>Yuzu Agent ${VERSION}</title><organization>${IDENTIFIER}</organization><domains enable_localSystem="true"/><options customize="never" require-scripts="true" rootVolumeOnly="true"/><volume-check><allowed-os-versions><os-version min="13.3"/></allowed-os-versions></volume-check><choices-outline><line choice="default"><line choice="${IDENTIFIER}"/></line></choices-outline><choice id="default"/><choice id="${IDENTIFIER}" visible="false"><pkg-ref id="${IDENTIFIER}"/></choice><pkg-ref id="${IDENTIFIER}" version="${VERSION}" onConclusion="none">yuzu-agent-component.pkg</pkg-ref></installer-gui-script>
XML
# Remove any earlier artifact first, so the existence check below proves THIS run wrote it.
rm -f "$PRODUCT_PKG"
productbuild --distribution "$DIST_XML" --package-path "$COMPONENT_DIR" "$PRODUCT_PKG"
[[ -f "$PRODUCT_PKG" ]] || {
    echo "ERROR: productbuild reported success but did not write $PRODUCT_PKG" >&2; exit 1; }
BUILD_COMPLETED=1
echo "Built $PACKAGE_MODE package: $PRODUCT_PKG"
