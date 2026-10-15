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
    # Lock this shell's own descriptor, so the lock lasts exactly as long as
    # this script: with a separate lockf wrapper process, killing the wrapper
    # released the lock while the script ran on (governance uh8-6). macOS 13
    # and 14 ship no /usr/bin/lockf at all (measured, #5903), so there perl's
    # flock on the same descriptor takes the lock; the wrapper form is only the
    # last resort, and with neither tool the install refuses rather than run
    # unlocked. 75 is lockf's timeout, kept short so this
    # message appears well within the time Installer allows a script (sre8-2).
    exec 9>>"$TRANSITION_LOCK"
    lock_status=0
    /usr/bin/lockf -s -t 120 9 2>/dev/null || lock_status=$?
    if [[ "$lock_status" == 75 ]]; then
        echo "ERROR: another Yuzu Agent package transition did not finish within 2 minutes; retry" >&2
        exit 1
    fi
    if [[ "$lock_status" != 0 && "$lock_status" != 75 && -x /usr/bin/perl ]]; then
        # The same descriptor lock through perl's flock, for a lockf without the
        # descriptor form (governance uh8-6): the wrapper form below can be
        # released by killing the wrapper while this script runs on.
        lock_status=0
        /usr/bin/perl -MFcntl=:flock -e \
            'open(my $f, ">>&=", 9) or exit 2; for (1 .. 120) { exit 0 if flock($f, LOCK_EX | LOCK_NB); sleep 1 } exit 75' \
            || lock_status=$?
        if [[ "$lock_status" == 75 ]]; then
            echo "ERROR: another Yuzu Agent package transition did not finish within 2 minutes; retry" >&2
            exit 1
        fi
    fi
    if [[ "$lock_status" != 0 ]]; then
        [[ -x /usr/bin/lockf ]] || {
            echo "ERROR: neither /usr/bin/lockf nor /usr/bin/perl can take the install lock on this Mac; nothing was changed" >&2
            exit 1; }
        exec 9>&-
        exec /usr/bin/lockf -k -t 120 "$TRANSITION_LOCK" \
            /usr/bin/env YUZU_PKG_TRANSITION_LOCKED=1 /bin/bash "$0" "$@"
    fi
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
        rm -rf "${LEGACY_APP:?}"
        echo "Removed the retired development YuzuAgent.app (its identity was verified)" >&2
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

# Every hash file given is a package's record (the old one, the new one, their
# snapshot copies): a listed plugin is package-owned if its bytes match ANY of
# them. Recovery after an interruption between moving the new manifest and the
# new hashes would otherwise keep the new package's plugin (governance uh8-1).
remove_managed_plugins() {
    local manifest="$1" relative plugin hashes recorded owned
    shift
    [[ -f "$manifest" ]] || return 0
    while IFS= read -r relative; do
        [[ "$relative" == plugins/* ]] || continue
        plugin="${relative#plugins/}"
        [[ -n "$plugin" && "$plugin" != */* && "$plugin" != .* ]] || {
            echo "ERROR: invalid package plugin manifest entry" >&2; return 1; }
        if [[ -e "$PLUGIN_DIR/$plugin" ]]; then
            recorded=0 owned=0
            for hashes in "$@"; do
                [[ -n "$hashes" && -f "$hashes" ]] || continue
                recorded=1
                if plugin_hash_matches "$plugin" "$hashes"; then owned=1; break; fi
            done
            if [[ "$recorded" == 1 && "$owned" != 1 ]]; then
                echo "WARNING: kept $PLUGIN_DIR/$plugin: its bytes differ from the package's, so it is not package-owned" >&2
                continue
            fi
        fi
        rm -f "${PLUGIN_DIR:?}/${plugin:?}" "${PLUGIN_DIR:?}/${plugin:?}.sig"
    done < "$manifest"
}

# launchctl bootout returns before the job is gone: measured on macOS 15, the
# agent leaves ~1.3 s after SIGTERM. Wait for it, bounded at 30 s (PR #4482
# governance g8ch-B1). Returns 1 if it is still loaded.
stop_service() {
    local waited=0
    launchctl print "system/com.yuzu.agent" >/dev/null 2>&1 || return 0
    launchctl bootout "system/com.yuzu.agent" >/dev/null 2>&1 || true
    while launchctl print "system/com.yuzu.agent" >/dev/null 2>&1; do
        [[ "$waited" -lt 60 ]] || return 1
        sleep 0.5
        waited=$((waited + 1))
    done
}

# After a fleet rollback to a package without a manifest (governance rd-2),
# this package's manifest and hashes are stale and would disown the older
# package's plugins; with no manifest at all only the receipt names them.
# Either way they are removed by name, from the manifest and from the
# Installer receipt (con8-4).
manifest_is_stale() {
    local recorded
    [[ -f "$MANIFEST" ]] || return 1
    recorded="$(awk 'NR == 1 && $1 == "#" && $2 == "package-version" {print $3}' "$MANIFEST")"
    [[ -n "$recorded" ]] || return 1
    # The version read once at the start, never a second pkgutil call (uh8r4-3).
    [[ -n "$RECEIPT_VERSION" && "$RECEIPT_VERSION" != "$recorded" ]]
}

remove_receipted_plugins() {
    local receipt relative name
    [[ "$RECEIPT_PRESENT" == 1 ]] || return 0
    # A receipt that exists but cannot be listed must stop the uninstall before
    # `pkgutil --forget`, or its plugins are orphaned (governance uh8r3-3).
    receipt="$(/usr/sbin/pkgutil --files com.yuzu.agent 2>/dev/null)" || {
        echo "ERROR: cannot list the Installer receipt's files; nothing was forgotten, retry" >&2
        return 1; }
    while IFS= read -r relative; do
        case "$relative" in
            usr/local/lib/yuzu/plugins/._*) ;;
            usr/local/lib/yuzu/plugins/*.dylib)
                name="${relative#usr/local/lib/yuzu/plugins/}"
                [[ "$name" != .* && "$name" != */* && "$name" != *[!a-zA-Z0-9_.-]* ]] || continue
                rm -f "${PLUGIN_DIR:?}/${name:?}" "${PLUGIN_DIR:?}/${name:?}.sig"
                ;;
        esac
    done <<< "$receipt"
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

# Whether the Installer receipt exists, read once: `pkgutil --forget` below runs
# only for a receipt confirmed here, so a transient failure can never forget
# a receipt whose plugins were not removed (governance U-1).
# A missing receipt and an unreadable one are told apart, and an unreadable one
# stops the uninstall before anything is removed (governance uh8r4-3).
RECEIPT_PRESENT=0
RECEIPT_VERSION=""
receipt_ids="$(/usr/sbin/pkgutil --pkgs 2>/dev/null)" || {
    echo "ERROR: cannot read the Installer receipt database; nothing was removed, retry" >&2
    exit 1; }
if grep -Fqx com.yuzu.agent <<<"$receipt_ids"; then
    RECEIPT_PRESENT=1
    receipt_info="$(/usr/sbin/pkgutil --pkg-info com.yuzu.agent 2>/dev/null)" || {
        echo "ERROR: cannot read the Yuzu Agent Installer receipt; nothing was removed, retry" >&2
        exit 1; }
    RECEIPT_VERSION="$(awk '/^version: / {print $2; exit}' <<<"$receipt_info")"
fi
ensure_state_dir
clear_recovery_state
stop_service || echo "WARNING: Yuzu Agent is still unloading; its code is removed anyway" >&2
retire_legacy_app
if [[ ! -f "$MANIFEST" ]]; then
    remove_receipted_plugins
elif manifest_is_stale; then
    echo "WARNING: the package manifest predates the installed package (a rollback); removing its plugins by name" >&2
    remove_managed_plugins "$MANIFEST"
    remove_receipted_plugins
else
    remove_managed_plugins "$MANIFEST" "$HASHES"
fi
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
[[ "$RECEIPT_PRESENT" != 1 ]] || pkgutil --forget com.yuzu.agent >/dev/null 2>&1 || true
# The state root holds only recovery state and the quarantine. Remove it when
# nothing was quarantined; otherwise keep it and say where (co-5).
if [[ -d "$STATE_DIR/quarantine" ]] && [[ -n "$(ls -A "$STATE_DIR/quarantine")" ]]; then
    echo "Quarantined items were kept for inspection in $STATE_DIR/quarantine; remove that directory when done."
else
    rm -rf "$STATE_DIR"
fi
echo "Yuzu Agent code and its service definition were removed. Data, logs, /etc/yuzu-agent and trust anchors were preserved;"
echo "the server address and other settings in the removed definition were not, so re-apply them after a reinstall."
