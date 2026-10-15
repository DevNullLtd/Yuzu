#!/bin/bash
# Remove only Yuzu package-owned code and service files; retain operational data.
set -euo pipefail

# One package transition at a time: an uninstall never interleaves with an
# install's promotion (PR #4482 governance ch-3). See postinstall.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
TRANSITION_LOCK=/var/db/.yuzu-agent-transition.lock
if [[ "${YUZU_PKG_TRANSITION_LOCKED:-}" != 1 ]]; then
    # Owner-only: a lock file any account can open is one it can hold,
    # blocking every install and uninstall (PR #4482 governance G8-S2). /var/db
    # is root-only, so nothing else can place this path.
    [[ ! -L "$TRANSITION_LOCK" ]] || { echo "ERROR: refusing a symlinked transition lock" >&2; exit 1; }
    (umask 077; : >> "$TRANSITION_LOCK")
    chmod 600 "$TRANSITION_LOCK"
    exec /usr/bin/lockf -k -t 600 "$TRANSITION_LOCK" \
        /usr/bin/env YUZU_PKG_TRANSITION_LOCKED=1 /bin/bash "$0" "$@"
fi

PLIST="/Library/LaunchDaemons/com.yuzu.agent.plist"
YUZU_LIB="/usr/local/lib/yuzu"
PLUGIN_DIR="$YUZU_LIB/plugins"
MODE_FILE="$YUZU_LIB/package-mode"
MANIFEST="$YUZU_LIB/package-files.list"
HASHES="$YUZU_LIB/package-files.sha256"
LOOSE_BIN="/usr/local/bin"
LEGACY_APP="/Library/Application Support/Yuzu/YuzuAgent.app"
LEGACY_TEAM_ID="7RLSYL2JM7"
LEGACY_APP_ID="7RLSYL2JM7.co.uk.devnullsecurity.yuzu-agent"
LEGACY_SIGNING_AUTHORITY="Mac Developer: Nathan Dornbrook (YA95685L8R)"
LEGACY_PROFILE_SHA256="3e764aafaa5cd29398ef6646b98c7b00332404c5ea57f79b92663695acdd70e1"
STATE_DIR="/var/db/yuzu-agent"
RECOVERY_FILE="$STATE_DIR/current-recovery"

ensure_state_dir() {
    local parent owner group mode
    parent="$(dirname "$STATE_DIR")"
    [[ -d "$parent" && ! -L "$parent" ]] || {
        echo "ERROR: refusing untrusted recovery state parent" >&2; exit 1; }
    owner="$(stat -f '%u' "$parent")"
    mode="$(stat -f '%Lp' "$parent")"
    [[ "$owner" == 0 && $((8#$mode & 8#022)) == 0 ]] || {
        echo "ERROR: recovery state parent must be root-owned and not group/world writable" >&2; exit 1; }
    if [[ -e "$STATE_DIR" || -L "$STATE_DIR" ]]; then
        [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || {
            echo "ERROR: refusing symlinked or non-directory recovery state root" >&2; exit 1; }
        owner="$(stat -f '%u' "$STATE_DIR")"
        group="$(stat -f '%g' "$STATE_DIR")"
        mode="$(stat -f '%Lp' "$STATE_DIR")"
        [[ "$owner" == 0 && "$group" == 0 && "$mode" == 700 ]] || {
            echo "ERROR: recovery state root must be root:wheel mode 700" >&2; exit 1; }
    else
        mkdir -m 700 "$STATE_DIR"
        chown root:wheel "$STATE_DIR"
    fi
}

legacy_app_is_managed() {
    local candidate="$1"
    [[ -d "$candidate" && ! -L "$candidate" ]] || return 1
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$candidate/Contents/Info.plist" 2>/dev/null || true)" \
        == "${LEGACY_APP_ID#*.}" ]] || return 1
    codesign --verify --deep --strict --verbose=2 "$candidate" >/dev/null 2>&1 || return 1
    [[ "$(codesign -dvv "$candidate" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2; exit}')" \
        == "$LEGACY_TEAM_ID" ]] || return 1
    [[ "$(codesign -dvv "$candidate" 2>&1 | awk -F= '/^Authority=/{print $2; exit}')" \
        == "$LEGACY_SIGNING_AUTHORITY" ]] || return 1
    [[ -f "$candidate/Contents/embedded.provisionprofile" ]] || return 1
    [[ "$(shasum -a 256 "$candidate/Contents/embedded.provisionprofile" | awk '{print $1}')" \
        == "$LEGACY_PROFILE_SHA256" ]]
}

# As in the installer: an app that is not provably the package's is moved to a
# root-only quarantine, never run, restored or deleted, and never blocks.
quarantine_legacy_app() {
    local source="$1" quarantine destination
    [[ -e "$source" || -L "$source" ]] || return 0
    quarantine="$STATE_DIR/quarantine"
    if [[ ! -d "$quarantine" ]]; then
        mkdir -m 700 "$quarantine"
        chown root:wheel "$quarantine"
    fi
    destination="$(mktemp -d "$quarantine/legacy-YuzuAgent.XXXXXX")"
    mv "$source" "$destination/YuzuAgent.app"
    echo "WARNING: quarantined an unrecognized legacy YuzuAgent.app at $destination; it was not run, restored or deleted" >&2
}

retire_legacy_app() {
    [[ ! -e "$LEGACY_APP" && ! -L "$LEGACY_APP" ]] && return 0
    if legacy_app_is_managed "$LEGACY_APP"; then
        rm -rf "$LEGACY_APP"
    else
        quarantine_legacy_app "$LEGACY_APP"
    fi
}

# Exit 0: the file's SHA-256 equals the hash recorded at build time.
plugin_hash_matches() {
    local plugin="$1" hashes="$2" recorded actual
    recorded="$(awk -v n="plugins/$plugin" '$2 == n {print $1; exit}' "$hashes")"
    [[ -n "$recorded" && -f "$PLUGIN_DIR/$plugin" ]] || return 1
    actual="$(shasum -a 256 "$PLUGIN_DIR/$plugin")" || return 1
    [[ "${actual%% *}" == "$recorded" ]]
}

# A listed plugin whose bytes no longer match the recorded hash belongs to the
# operator and is kept (PR #4482 governance sec-3).
remove_managed_plugins() {
    local manifest="$1" hashes="${2:-}" relative plugin
    [[ -f "$manifest" ]] || return 0
    while IFS= read -r relative; do
        [[ "$relative" == plugins/* ]] || continue
        plugin="${relative#plugins/}"
        [[ -n "$plugin" && "$plugin" != */* && "$plugin" != .* ]] || {
            echo "ERROR: invalid package plugin manifest entry" >&2; return 1; }
        if [[ -n "$hashes" && -f "$hashes" && -e "$PLUGIN_DIR/$plugin" ]] && \
           ! plugin_hash_matches "$plugin" "$hashes"; then
            echo "WARNING: kept $PLUGIN_DIR/$plugin: its bytes differ from the package's, so it is not package-owned" >&2
            continue
        fi
        rm -f "$PLUGIN_DIR/$plugin" "$PLUGIN_DIR/$plugin.sig"
    done < "$manifest"
}

# Interrupted-install state is cleared FIRST, pointer before snapshots: with no
# pointer, no later recovery can restore (and restart) the agent this script
# removes (PR #4482 governance ch-3). The quarantine is kept for inspection.
clear_recovery_state() {
    local snapshot
    rm -f "$RECOVERY_FILE" "$RECOVERY_FILE.new"
    sync
    for snapshot in "$STATE_DIR"/install-recovery.* "$STATE_DIR"/uninstall-legacy.*; do
        [[ -e "$snapshot" || -L "$snapshot" ]] || continue
        rm -rf "$snapshot"
    done
}

ensure_state_dir
clear_recovery_state
launchctl bootout "system/com.yuzu.agent" >/dev/null 2>&1 || true
retire_legacy_app
remove_managed_plugins "$MANIFEST" "$HASHES"
# Both lanes are package-owned. Remove both so a loose-to-bundle (or reverse)
# transition cannot leave executable code behind, including an updater rollback
# file that would otherwise be promoted on a later install (ch-4).
rm -rf "/Library/Application Support/YuzuAgent/YuzuAgent.app" \
       "/Library/Application Support/YuzuAgent/.YuzuAgent.incoming.app" \
       "$YUZU_LIB/.plugins.incoming"
rm -f "$LOOSE_BIN/yuzu-agent" "$LOOSE_BIN/.yuzu-agent.incoming" \
      "$LOOSE_BIN/yuzu-agent.old" "$LOOSE_BIN/.yuzu-update-verified" \
      "$LOOSE_BIN/libyuzu_agent_core.dylib" "$LOOSE_BIN/.libyuzu_agent_core.incoming.dylib" \
      /usr/local/lib/libyuzu_agent_core.dylib /usr/local/lib/.libyuzu_agent_core.incoming.dylib \
      "$YUZU_LIB/.bundle-contents.incoming.zip" \
      "$PLIST" /Library/LaunchDaemons/.com.yuzu.agent.incoming.plist \
      "$MODE_FILE" "$YUZU_LIB/.package-mode.incoming" \
      "$MANIFEST" "$YUZU_LIB/.package-files.incoming" \
      "$HASHES" "$YUZU_LIB/.package-files.sha256.incoming" \
      "$YUZU_LIB/merge-launchd-plist.py" \
      "$YUZU_LIB/merge-launchd-plist.js" \
      "$YUZU_LIB/plugin-signing-policy.json" "$YUZU_LIB/uninstall.sh"
pkgutil --forget com.yuzu.agent >/dev/null 2>&1 || true
# The state root holds only recovery state and the quarantine. Remove it when
# nothing was quarantined; otherwise keep it and say where (co-5).
if [[ -d "$STATE_DIR/quarantine" ]] && [[ -n "$(ls -A "$STATE_DIR/quarantine")" ]]; then
    echo "Quarantined items were kept for inspection in $STATE_DIR/quarantine; remove that directory when done."
else
    rm -rf "$STATE_DIR"
fi
echo "Yuzu Agent code removed. Data, logs, configuration, and trust anchors were preserved."
