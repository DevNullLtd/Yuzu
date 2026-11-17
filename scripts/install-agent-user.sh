#!/usr/bin/env bash
###############################################################################
# install-agent-user.sh — provision the unprivileged account the Yuzu agent
#                        runs under, plus the narrow privilege grants it
#                        needs to operate plugins like the firewall plugin's
#                        containment actions, services.set_start_mode, and
#                        network_actions.flush_dns.
#
# AUTHORITY
# ─────────
# This script is the implementation of the privilege model defined in
# docs/agent-privilege-model.md. If the doc and the script disagree,
# the doc wins — fix the script, then re-run.
#
# WHAT THIS SCRIPT DOES
# ─────────────────────
# 1.  Creates a dedicated system user the agent runs under:
#       macOS:  _yuzu      (UID/GID auto-assigned in the 200-400 system range,
#                          following the Apple convention of leading-underscore
#                          names for system daemons — _postgres, _www, etc.)
#       Linux:  yuzu       (UID/GID auto-assigned by `useradd --system` in
#                          the distro's system-user range, typically <1000)
# 2.  Creates the agent's filesystem hierarchy with correct ownership:
#       /var/lib/yuzu-agent/    or  /Library/Application Support/Yuzu/   (state)
#       /var/cache/yuzu-agent/  or  /Library/Caches/Yuzu/                (staging)
#       /var/log/yuzu-agent/    or  /Library/Logs/Yuzu/                  (logs)
# 3.  Adds the user to the platform-specific groups it needs:
#       Linux:  systemd-journal (read journal), adm (read /var/log/*)
#       macOS:  (no extra group memberships needed beyond the user record)
# 4.  Installs /etc/sudoers.d/yuzu-agent with NOPASSWD entries for the
#       narrow set of privileged commands plugins shell out to.
#       The file is validated with `visudo -cf` before being moved into
#       place — a syntactically broken sudoers file would brick the
#       entire sudo subsystem on this host, so we never write to
#       /etc/sudoers.d/ directly.
# 5.  (Linux only) Installs the root-owned systemctl wrapper
#       /usr/libexec/yuzu/yuzu-systemctl (the ONLY systemctl sudo grant; it
#       validates verb and unit name, so no sudoers argument glob is relied
#       on), and REMOVES any file capabilities from the agent binary.
#       The installer NEVER sets file capabilities (WP13/F21): a file
#       capability on a binary any local user can execute is a local
#       privilege escalation (the invoker chooses --plugin-dir, which the
#       agent dlopens). Capabilities are granted to the SERVICE only, as
#       the packaged unit does (deploy/systemd/yuzu-agent.service:
#       AmbientCapabilities=CAP_DAC_READ_SEARCH), or, for the dev/UAT
#       launcher, by `setpriv --ambient-caps` in scripts/start-UAT.sh.
# 6.  (Optional) On both platforms, prints a verifying summary that the
#       operator can spot-check.
#
# WHAT THIS SCRIPT DOES NOT DO
# ─────────────────────────────
# - Install the agent binary itself. Use `meson install` or the platform
#   installer (`.pkg` on macOS, `.deb`/`.rpm` on Linux) for that.
# - Register the agent with launchd / systemd. Those plists/units belong
#   alongside the binary install, not the user provisioning.
# - Touch the `interaction` plugin's per-session helper. Popups need a
#   logged-in user's GUI session, which a daemon running as _yuzu cannot
#   reach. The interaction helper is a separate (future) per-user agent
#   process loaded by launchd at login / systemd --user. Out of scope here.
# - Generate the agent's mTLS cert/key. That comes from the server
#   enrollment flow, not the install step.
#
# IDEMPOTENCY
# ───────────
# Every step probes for the existing target state and skips if already
# present. Running this script twice is safe and changes nothing on the
# second pass. The sudoers file is overwritten each run (so you can
# update the privilege list and re-run), but only after passing
# `visudo -cf`.
#
# UNINSTALL
# ─────────
# Pass --uninstall to reverse:
#   - removes /etc/sudoers.d/yuzu-agent
#   - removes the agent's filesystem hierarchy (logs are preserved
#     under /var/log/yuzu-agent.removed-<timestamp>/ for forensics)
#   - deletes the user account
# Also removes /usr/libexec/yuzu/yuzu-systemctl (Linux). File capabilities
# are never set by this script and any found on the binary are stripped on
# install, so there is nothing to undo on uninstall.
#
# ARGUMENTS
# ─────────
#   --dry-run        Print every command the script would run, without
#                    executing any of them. Use this first.
#   --check          Verify the install is correct (user exists with
#                    expected attributes, sudoers file present + valid,
#                    state dirs exist with correct ownership). Exits
#                    non-zero on any drift.
#   --uninstall      Remove the user, sudoers file, and state dirs.
#   --account-name N Override the default account name (_yuzu / yuzu).
#                    Useful for parallel test environments.
#   --binary-path P  Override the path to the agent binary whose file
#                    capabilities are stripped.
#                    Default: /usr/local/bin/yuzu-agent (Linux) or
#                    /Library/Application\ Support/Yuzu/yuzu-agent (macOS).
#                    On macOS this is a no-op (no file capabilities).
#   --no-sudoers     Skip the sudoers file install. Useful in test
#                    environments where you don't want any privilege
#                    grants; the agent will still run but the firewall
#                    containment actions and other privileged plugins will fail at dispatch
#                    time (which the test ladder catches).
#   --no-cap-cleanup Skip stripping file capabilities from the binary
#                    (Linux). The script never GRANTS file capabilities;
#                    this only skips stripping file capabilities from the binary.
#
# EXIT CODES
# ──────────
#   0  - install/check/uninstall succeeded (check: everything verified)
#   1  - failed: not run as root (install/uninstall), a precondition fail(), or --check
#        found drift; details on stderr
#   2  - argument error or unsupported OS
#   3  - sudoers file failed visudo validation; any existing sudoers file was REMOVED
#        (fail closed: no grants) and nothing new was installed
#   4  - the systemctl wrapper could not be installed (no systemctl grant was written)
#   5  - file capabilities may still be live: `setcap` is missing while the binary
#        carries them (or getcap is also missing, so that cannot be ruled out), `setcap -r`
#        failed, or getcap still shows them afterwards. A missing getcap ALONE (setcap
#        present) does not exit 5: the strip runs unverified and --check reports the drift.
#   6  - --check only: no drift found but part of the install could not be VERIFIED
#        (the sudoers file is present but unreadable to this user): re-run as root
#   When several install steps fail the exit status is the first in the order 3, 4, 5.
#
# THIS SCRIPT MUST BE RUN AS ROOT.
# We don't try to be cute about that — every action below requires root.
###############################################################################

set -uo pipefail

# ── argument defaults ────────────────────────────────────────────────────────

ACTION="install"           # install | check | uninstall
DRY_RUN=0
ACCOUNT_NAME=""            # filled in based on platform if not specified
BINARY_PATH=""             # filled in based on platform if not specified
SKIP_SUDOERS=0
SKIP_SETCAP=0
# Root-owned systemctl validator (Linux, WP13/F48). The ONLY systemctl sudo grant; the
# services plugin probes this exact path (agents/plugins/services/src/services_parsers.hpp
# kYuzuSystemctlWrapper) - keep the two in sync.
SYSTEMCTL_WRAPPER_DIR="/usr/libexec/yuzu"
SYSTEMCTL_WRAPPER_PATH="$SYSTEMCTL_WRAPPER_DIR/yuzu-systemctl"
SYSTEMCTL_WRAPPER_OK=1     # set to 0 when the wrapper could not be installed (no grant written)
SUDOERS_TARGET="/etc/sudoers.d/yuzu-agent"   # a variable so the execution tests can redirect it

# ── platform detection ───────────────────────────────────────────────────────
# We support exactly two platforms in this script: macOS and Linux. The
# Windows path is install-agent-user.ps1; this script's --help refuses to
# proceed on anything else so a misuse on FreeBSD / OpenBSD / etc. fails
# fast with a clear message rather than silently corrupting state.

OS="$(uname -s)"
case "$OS" in
    Darwin)
        PLATFORM="macos"
        DEFAULT_ACCOUNT="_yuzu"
        # macOS canonical paths for system daemons follow the Apple File
        # System Programming Guide. /Library/* is system-wide; ~/Library/*
        # is per-user. Daemon state, caches, and logs all under /Library/.
        STATE_DIR="/Library/Application Support/Yuzu"
        CACHE_DIR="/Library/Caches/Yuzu"
        LOG_DIR="/Library/Logs/Yuzu"
        DEFAULT_BINARY_PATH="/Library/Application Support/Yuzu/yuzu-agent"
        ;;
    Linux)
        PLATFORM="linux"
        DEFAULT_ACCOUNT="yuzu"
        # Linux canonical paths follow the Filesystem Hierarchy Standard.
        # /var/lib/<pkg>/   - persistent state
        # /var/cache/<pkg>/ - regenerable cache (staging area for content_dist)
        # /var/log/<pkg>/   - log files (managed by logrotate in production)
        STATE_DIR="/var/lib/yuzu-agent"
        CACHE_DIR="/var/cache/yuzu-agent"
        LOG_DIR="/var/log/yuzu-agent"
        DEFAULT_BINARY_PATH="/usr/local/bin/yuzu-agent"
        ;;
    *)
        echo "error: unsupported platform: $OS" >&2
        echo "       this script supports macOS (Darwin) and Linux only." >&2
        echo "       for Windows, use scripts/install-agent-user.ps1." >&2
        exit 2
        ;;
esac

# ── argument parsing ─────────────────────────────────────────────────────────

usage() {
    sed -n '/^# install-agent-user.sh/,/^# THIS SCRIPT MUST BE RUN AS ROOT/p' "$0" \
        | sed 's/^# \?//' | sed '$d'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)        DRY_RUN=1; shift ;;
        --check)          ACTION="check"; shift ;;
        --uninstall)      ACTION="uninstall"; shift ;;
        --account-name)   ACCOUNT_NAME="$2"; shift 2 ;;
        --binary-path)    BINARY_PATH="$2"; shift 2 ;;
        --no-sudoers)     SKIP_SUDOERS=1; shift ;;
        --no-cap-cleanup) SKIP_SETCAP=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                echo "unknown arg: $1" >&2; echo "use --help for usage." >&2; exit 2 ;;
    esac
done

ACCOUNT_NAME="${ACCOUNT_NAME:-$DEFAULT_ACCOUNT}"
BINARY_PATH="${BINARY_PATH:-$DEFAULT_BINARY_PATH}"

TEST_ROOT="${YUZU_INSTALLER_TEST_ROOT:-}"

# ── helpers ──────────────────────────────────────────────────────────────────

# run() executes a command (or just prints it under --dry-run). Shell
# quoting matters here: the array form preserves argument boundaries so
# paths with spaces (macOS "/Library/Application Support/Yuzu") survive
# unmangled.
run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] '
        printf '%q ' "$@"
        printf '\n'
    else
        "$@"
    fi
}

# log() — info messages on stdout, distinct from command output.
log() { printf '[install-agent-user] %s\n' "$*"; }
warn() { printf '[install-agent-user] WARN: %s\n' "$*" >&2; }
fail() { printf '[install-agent-user] ERROR: %s\n' "$*" >&2; exit 1; }

# TEST-ONLY escape hatch (tests/test_agent_installer_exec.py): YUZU_INSTALLER_TEST_ROOT redirects
# every root-owned path under a prefix directory and skips the root check, so the real, NON-sourced
# script (dispatch and exit status included) can run in a temp dir with stub tools.
#
# It is NOT safe to honour in general: an environment variable can be inherited (sudo -E,
# env_keep, CI, systemd Environment=), and a root run that honoured it would run the real
# useradd/dscl while the sudoers file and wrapper stayed untouched, exit 0, and leave the old
# grants in place (WP13 governance R4-TESTROOT). So: it is REFUSED for root, and when honoured it
# must be an absolute, existing, non-symlink directory owned by the caller, and never `/`.
# `id -u` (not $EUID, which bash makes read-only) so the root refusal can be tested with a stub.
if [[ -n "$TEST_ROOT" ]]; then
    [[ "$(id -u)" -ne 0 ]] || fail "YUZU_INSTALLER_TEST_ROOT is set but this is a root run: refusing (it is a test-only redirect; unset it)"
    [[ "$TEST_ROOT" == /* && -n "${TEST_ROOT//\//}" ]] || fail "YUZU_INSTALLER_TEST_ROOT must be an absolute path other than /"
    [[ ! -L "$TEST_ROOT" ]] || fail "YUZU_INSTALLER_TEST_ROOT must not be a symlink"
    [[ -d "$TEST_ROOT" ]] || fail "YUZU_INSTALLER_TEST_ROOT must be an existing directory"
    [[ -O "$TEST_ROOT" ]] || fail "YUZU_INSTALLER_TEST_ROOT must be owned by the caller"
    printf '[install-agent-user] *** TEST-ONLY MODE: every path is redirected under %s and the root check is skipped; this run changes NOTHING on the real host ***\n' "$TEST_ROOT" >&2
    STATE_DIR="$TEST_ROOT$STATE_DIR"; CACHE_DIR="$TEST_ROOT$CACHE_DIR"; LOG_DIR="$TEST_ROOT$LOG_DIR"
    SUDOERS_TARGET="$TEST_ROOT$SUDOERS_TARGET"
    SYSTEMCTL_WRAPPER_DIR="$TEST_ROOT$SYSTEMCTL_WRAPPER_DIR"
    SYSTEMCTL_WRAPPER_PATH="$TEST_ROOT$SYSTEMCTL_WRAPPER_PATH"
fi

# require_root — most actions need root; we fail early rather than
# half-running and leaving a partially-installed state. --dry-run and
# --check are exempt: dry-run only prints what would happen, and check
# only reads state.
require_root() {
    if [[ "$DRY_RUN" -eq 1 || -n "$TEST_ROOT" ]]; then
        return 0
    fi
    if [[ "$EUID" -ne 0 ]]; then
        fail "must be run as root (use sudo). EUID=$EUID"
    fi
}

# ── platform-specific user management ────────────────────────────────────────
#
# macOS uses Directory Services (`dscl`) to manage local accounts, not
# /etc/passwd. The local DS database lives under /var/db/dslocal/ and
# is what `dscl . -list /Users` queries.
#
# Linux uses /etc/passwd + /etc/group via useradd/groupadd. Service-mode
# users are created with `--system` to get a UID/GID below SYS_UID_MAX
# (usually 999) and with --no-create-home + --shell /usr/sbin/nologin so
# the account can't be used for login.

macos_user_exists() {
    dscl . -read "/Users/$ACCOUNT_NAME" >/dev/null 2>&1
}

macos_group_exists() {
    dscl . -read "/Groups/$ACCOUNT_NAME" >/dev/null 2>&1
}

# Pick an ID >= 200 that is free in BOTH the user and group namespaces.
# macOS user UIDs and group GIDs are independent number spaces — Apple
# ships `_guest` at GID 201 and `_yuzu` at no UID, so naively assuming
# UID==GID lands on a collision. We scan both lists and find the first
# integer that's used by neither, so the resulting account has matching
# UID and GID for ergonomic consistency with the Linux convention.
macos_pick_free_id() {
    {
        dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}'
        dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}'
    } \
        | sort -un \
        | awk 'BEGIN{u=200} $1==u{u++} END{print u}'
}

macos_create_user() {
    local user_exists group_exists
    macos_user_exists && user_exists=1 || user_exists=0
    macos_group_exists && group_exists=1 || group_exists=0

    # If both records are present AND the user's PrimaryGroupID actually
    # resolves to the `_yuzu` group (not, say, `_guest` because a prior
    # collision left the user's PGID pointing somewhere else), skip the
    # whole sequence. Otherwise fall through to the repair path below.
    if [[ "$user_exists" -eq 1 && "$group_exists" -eq 1 ]]; then
        local user_pgid group_pgid
        user_pgid=$(dscl . -read "/Users/$ACCOUNT_NAME" PrimaryGroupID 2>/dev/null \
                        | awk '/PrimaryGroupID:/ {print $2}')
        group_pgid=$(dscl . -read "/Groups/$ACCOUNT_NAME" PrimaryGroupID 2>/dev/null \
                         | awk '/PrimaryGroupID:/ {print $2}')
        if [[ -n "$user_pgid" && -n "$group_pgid" && "$user_pgid" == "$group_pgid" ]]; then
            log "user and group $ACCOUNT_NAME already consistent (gid=$user_pgid) — skipping"
            return 0
        fi
        log "user and group $ACCOUNT_NAME exist but inconsistent " \
            "(user pgid='${user_pgid:-<missing>}', group pgid='${group_pgid:-<missing>}') — repairing"
    fi

    local next_id
    next_id=$(macos_pick_free_id)
    log "selected ID $next_id (free in both /Users UniqueID and /Groups PrimaryGroupID)"

    if [[ "$user_exists" -eq 0 ]]; then
        log "creating macOS user $ACCOUNT_NAME (UID=$next_id, hidden, no shell)"
        run dscl . -create "/Users/$ACCOUNT_NAME"
        run dscl . -create "/Users/$ACCOUNT_NAME" UserShell /usr/bin/false
        run dscl . -create "/Users/$ACCOUNT_NAME" RealName "Yuzu Agent Daemon"
        run dscl . -create "/Users/$ACCOUNT_NAME" UniqueID "$next_id"
        run dscl . -create "/Users/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
        run dscl . -create "/Users/$ACCOUNT_NAME" NFSHomeDirectory /var/empty
        run dscl . -create "/Users/$ACCOUNT_NAME" Password "*"
        # Hide from the login window's user picker (cosmetic but expected).
        run dscl . -create "/Users/$ACCOUNT_NAME" IsHidden 1
    else
        log "user $ACCOUNT_NAME exists — repointing PrimaryGroupID to $next_id"
        # Self-heal a partial install where the user record exists but
        # its PrimaryGroupID points at someone else's GID (commonly
        # `_guest` if a prior run grabbed UID 201 without checking the
        # group namespace).
        run dscl . -create "/Users/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
    fi

    # Matching group entry. Without it, anything that maps gid → name
    # (ls -l, `ps`, install -g) prints the bare GID instead of `_yuzu` —
    # or, worse, fails outright with "unknown group".
    if [[ "$group_exists" -eq 0 ]]; then
        log "creating macOS group $ACCOUNT_NAME (GID=$next_id)"
        run dscl . -create "/Groups/$ACCOUNT_NAME"
        run dscl . -create "/Groups/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
        run dscl . -create "/Groups/$ACCOUNT_NAME" Password "*"
        run dscl . -create "/Groups/$ACCOUNT_NAME" RealName "Yuzu Agent Daemon"
    else
        log "group $ACCOUNT_NAME exists — repairing PrimaryGroupID to $next_id"
        # Self-heal a partial install where the group record was created
        # but its PrimaryGroupID couldn't be set (e.g., earlier dscl
        # collision on the chosen GID). Without a PrimaryGroupID, the
        # group is invisible to getgrnam() and `install -g` fails.
        run dscl . -create "/Groups/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
    fi

    # Flush the Directory Services cache so getpwnam() / getgrnam() see
    # the new records immediately. Without this, the very next `install
    # -o _yuzu -g _yuzu` call after group creation fails with
    # "install: unknown group _yuzu" because the cache hasn't picked
    # up the new dscl record yet. dscacheutil is idempotent and harmless.
    run dscacheutil -flushcache
}

macos_delete_user() {
    if macos_user_exists; then
        log "deleting macOS user $ACCOUNT_NAME"
        run dscl . -delete "/Users/$ACCOUNT_NAME" || true
        run dscl . -delete "/Groups/$ACCOUNT_NAME" || true
    fi
}

linux_user_exists() {
    getent passwd "$ACCOUNT_NAME" >/dev/null 2>&1
}

linux_create_user() {
    log "creating Linux system user $ACCOUNT_NAME"
    # --system  : pick UID/GID from the system range
    # --no-create-home : don't auto-create a home dir; we manage state
    #                    dirs explicitly below.
    # --shell /usr/sbin/nologin : refuse interactive logins.
    # --home <dir> : the home dir we create separately as the state dir.
    run useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --home "$STATE_DIR" \
        --comment "Yuzu Agent Daemon" \
        "$ACCOUNT_NAME"

    # Group memberships — the install adds these unconditionally because
    # the cost of being-in-a-group-you-don't-need is zero, but the cost
    # of being-NOT-in-a-group-you-do-need is a runtime failure that
    # operators have to debug. We only add to groups that exist on this
    # host (some distros don't ship `adm`, for example).
    for group in systemd-journal adm; do
        if getent group "$group" >/dev/null 2>&1; then
            log "  adding $ACCOUNT_NAME to group $group"
            run usermod -aG "$group" "$ACCOUNT_NAME"
        else
            warn "  group $group not present on this host — skipping"
        fi
    done
}

linux_delete_user() {
    if linux_user_exists; then
        log "deleting Linux system user $ACCOUNT_NAME"
        # --remove deletes the home dir; we created the home dir ourselves,
        # but we'll deliberately handle that under remove_state_dirs() so
        # we get the audit-preserve behavior.
        run userdel "$ACCOUNT_NAME" || true
    fi
}

# ── state-dir management ─────────────────────────────────────────────────────

create_state_dirs() {
    for dir in "$STATE_DIR" "$CACHE_DIR" "$LOG_DIR"; do
        if [[ ! -d "$dir" ]]; then
            log "creating $dir"
            run install -d -m 0750 -o "$ACCOUNT_NAME" -g "$ACCOUNT_NAME" "$dir"
        else
            # Already exists — re-set ownership in case a previous run
            # left it root-owned, but leave the mode bits alone (operator
            # might have tightened them).
            log "ensuring ownership of $dir"
            run chown -R "$ACCOUNT_NAME:$ACCOUNT_NAME" "$dir"
        fi
    done
}

remove_state_dirs() {
    for dir in "$STATE_DIR" "$CACHE_DIR"; do
        if [[ -d "$dir" ]]; then
            log "removing $dir"
            run rm -rf "$dir"
        fi
    done
    # Logs are preserved on uninstall — we rename rather than delete so
    # forensic / post-mortem investigation can still reach them. Operator
    # decides when to delete them.
    if [[ -d "$LOG_DIR" ]]; then
        local archive="${LOG_DIR}.removed-$(date -u +%Y%m%dT%H%M%SZ)"
        log "preserving $LOG_DIR -> $archive"
        run mv "$LOG_DIR" "$archive"
    fi
}

# ── sudoers management ───────────────────────────────────────────────────────
#
# /etc/sudoers.d/ files are sourced by sudo on every invocation. A
# syntactically broken file in this directory will cause EVERY sudo call
# on the system to fail — including the one you'd use to fix the broken
# file. So:
#
#  1. We always write to a temp file under /tmp first.
#  2. We validate with `visudo -cf <tempfile>` and refuse to install if
#     it doesn't pass.
#  3. We use `install` with mode 0440 owner root:root. Any other ownership
#     or any group/other write bit causes sudo to refuse to load the file
#     (visible in `journalctl -u sudo` / Console.app).
#  4. We never echo the sudoers contents into the live file directly —
#     a pipe failure mid-write would leave half a file in place.

generate_sudoers_content() {
    cat <<EOF
# Yuzu agent — privileged commands the agent shells out to from plugin code.
#
# This file is owned by scripts/install-agent-user.sh — DO NOT edit by hand.
# Re-run the installer with an updated privilege list to change it; the
# installer validates with visudo -cf before atomic replace.
#
# Audit trail for this file is the install script's git history.
#
# All commands are NOPASSWD because the agent runs non-interactively as
# a daemon. Each entry uses an absolute binary path to prevent
# PATH-injection sudo bypass.
#
# DELIBERATELY NOT GRANTED:
#   - generic ALL=(ALL) sudo (would make the audit surface infinite)
#   - script_exec.exec / script_exec.bash / script_exec.powershell
#     (these run in the agent's own context; if an operator wants to
#     run a privileged script they should approve a quarantine-class
#     instruction that wraps the specific command)
#   - SeLoadDriverPrivilege equivalent (kernel driver loading)
#   - chown / chmod (agent should never rewrite ACLs)

EOF

    if [[ "$PLATFORM" == "macos" ]]; then
        cat <<EOF
# firewall plugin — pf anchor containment (the narrowed argv the firewall containment actions
# run). These lines NARROW the argv shape; they do not confine pfctl: sudo globs match
# concatenated args, and the anchor file named by -f is agent-generated. The confinement is the
# firewall plugin's token validation (agents/plugins/firewall/src/firewall_quarantine_parsers.hpp).
# There is no bare /sbin/pfctl grant. The anchor name sorts first among Apple's com.apple/*
# sub-anchors, and the release flush is -F rules / -F nat on that anchor only (never -F all:
# that is global).
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -E
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -X *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple/000.yuzu_quarantine -f *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple/000.yuzu_quarantine -F rules
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple/000.yuzu_quarantine -F nat
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple/000.yuzu_quarantine -s rules
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple -s Anchors
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -F states
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -s info
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -s rules
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -s References

# services.set_start_mode — launchd system domain. No bootstrap/bootout grant (WP13/F48): no
# plugin calls them, and \`launchctl bootstrap system <plist>\` loads an arbitrary plist as a
# root daemon.
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl enable system/*
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl disable system/*

# network_actions.flush_dns
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/dscacheutil -flushcache
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder

# certificates.delete (system keychain only — user keychain is non-privileged)
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/security delete-certificate -t /Library/Keychains/System.keychain *

EOF
    else  # linux
        cat <<EOF
# firewall plugin — iptables / ip6tables, the containment fallback when nft is absent. Their
# rule text rides argv, so sudoers cannot pin them the way it pins nft and pfctl below.
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/iptables
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/ip6tables

# firewall plugin — nftables containment (own table inet yuzu_quarantine). These lines NARROW
# the argv shape; they do not confine nft: sudo globs match concatenated args, and the file
# named by -f is agent-generated. The confinement is the firewall plugin's token validation
# (agents/plugins/firewall/src/firewall_quarantine_parsers.hpp). The bare /usr/sbin/nft grant
# that used to sit here was never called by any plugin and is replaced by these three.
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft -f *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft delete table inet yuzu_quarantine
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft list table inet yuzu_quarantine

# services.set_start_mode — systemd unit lifecycle, through the root-owned wrapper ONLY
# (WP13/F48). A \`systemctl enable *\` glob matches \`enable --now /path/unit.service\`, which links
# and starts an agent-authored unit as root. The wrapper takes exactly <verb> <unit>, checks the
# verb (enable|disable|mask|unmask) and the unit name against the services plugin's charset, and
# execs \`systemctl <verb> -- <unit>\`; there is no sudoers regex, so no sudo-version floor.
EOF
    if [[ "${SYSTEMCTL_WRAPPER_OK:-1}" -eq 1 ]]; then
        cat <<EOF
$ACCOUNT_NAME ALL=(root) NOPASSWD: $SYSTEMCTL_WRAPPER_PATH
EOF
    else
        cat <<EOF
# NO systemctl grant: the wrapper could not be installed, and the wildcard grant is never
# written as a fallback. services.set_start_mode reports privilege_unavailable until the
# installer is re-run successfully.
EOF
    fi
    cat <<EOF

# network_actions.flush_dns
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemd-resolve --flush-caches
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/resolvectl flush-caches

EOF
    fi

    cat <<EOF
# Pre-requisites for daemon-style invocation. (No \`Defaults !requiretty\`: requiretty is OFF by
# default in every supported sudo, and sudo-rs rejects the flag outright, which made visudo -cf
# refuse the WHOLE file.)
Defaults:$ACCOUNT_NAME    env_keep += "YUZU_*"
EOF
}

install_sudoers() {
    if [[ "$SKIP_SUDOERS" -eq 1 ]]; then
        log "skipping sudoers install (--no-sudoers)"
        return 0
    fi

    local target="$SUDOERS_TARGET"
    local tmp
    tmp=$(mktemp -t yuzu-sudoers.XXXXXX)
    # Cleanup on any exit path: the temp file should never linger.
    # `${tmp:-}` and the self-removal matter: a RETURN trap outlives this function, and under
    # `set -u` it fired on the NEXT function's return with `tmp` out of scope ("unbound variable"),
    # aborting the installer before it reached the capability strip (WP13 governance N1).
    trap 'rm -f "${tmp:-}"; trap - RETURN' RETURN

    log "generating sudoers file at $tmp"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would write the following to $target:"
        generate_sudoers_content | sed 's/^/[dry-run]   /'
    else
        generate_sudoers_content > "$tmp"
    fi

    log "validating with visudo -cf"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if ! visudo -cf "$tmp" >/dev/null; then
            warn "sudoers file failed visudo validation — NOT installing"
            visudo -cf "$tmp" >&2 || true
            # Fail CLOSED (WP13 governance R1): on validation failure the existing $target is
            # removed rather than left in place, so a grant-carrying file never outlives a failed
            # update; the agent then has NO privileged grants (actions report
            # privilege_unavailable) until a successful run.
            if [[ -f "$target" ]]; then
                warn "removing the existing $target so its grants do not outlive a failed update"
                run rm -f "$target"
            fi
            return 3
        fi
    fi

    # macOS uses `wheel` (GID 0) as root's primary group; there is no
    # group named `root` on Darwin. Linux uses `root:root`. The sudoers
    # file must end up owner=root:wheel on macOS, owner=root:root on
    # Linux — without the right ownership sudo refuses to load it.
    local root_group
    if [[ "$PLATFORM" == "macos" ]]; then
        root_group="wheel"
    else
        root_group="root"
    fi

    log "installing $tmp -> $target (mode 0440, root:$root_group)"
    run install -m 0440 -o root -g "$root_group" "$tmp" "$target"
}

remove_sudoers() {
    local target="$SUDOERS_TARGET"
    if [[ -f "$target" ]]; then
        log "removing $target"
        run rm -f "$target"
    fi
}

# ── systemctl wrapper (Linux, WP13/F48) ─────────────────────────────────────
# The agent account may change a unit's start mode, but only through this root-owned
# validator: exactly <verb> <unit>, verb in enable|disable|mask|unmask, unit name in the
# services plugin's charset (is_safe_service_name: [A-Za-z0-9._@-], 1..256). Anything else is
# refused with exit 2. `--` always precedes the unit, so a leading '-' is a name, never a flag,
# and no option (--now, --root, a unit-file path) can ride in. Plain POSIX sh: no regex, no
# sudo-version dependence.

generate_systemctl_wrapper_content() {
    cat <<'WRAPPER_EOF'
#!/bin/sh
# yuzu-systemctl - installed by scripts/install-agent-user.sh (WP13/F48). Root-owned; do not edit.
# Usage: yuzu-systemctl <enable|disable|mask|unmask> <unit>
SYSTEMCTL=/usr/bin/systemctl
[ -x "$SYSTEMCTL" ] || SYSTEMCTL=/bin/systemctl
if [ "$#" -ne 2 ]; then
    echo "yuzu-systemctl: usage: yuzu-systemctl enable|disable|mask|unmask UNIT" >&2
    exit 2
fi
verb=$1
unit=$2
case "$verb" in
    enable|disable|mask|unmask) ;;
    *) echo "yuzu-systemctl: refused verb" >&2; exit 2 ;;
esac
case "$unit" in
    ""|*[!A-Za-z0-9@_.-]*) echo "yuzu-systemctl: refused unit name" >&2; exit 2 ;;
esac
if [ "${#unit}" -gt 256 ]; then
    echo "yuzu-systemctl: refused unit name (too long)" >&2
    exit 2
fi
exec "$SYSTEMCTL" "$verb" -- "$unit"
WRAPPER_EOF
}

install_systemctl_wrapper() {
    if [[ "$PLATFORM" != "linux" ]]; then return 0; fi
    if [[ "$SKIP_SUDOERS" -eq 1 ]]; then return 0; fi

    log "installing systemctl wrapper $SYSTEMCTL_WRAPPER_PATH (root:root 0755)"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would write the following to $SYSTEMCTL_WRAPPER_PATH:"
        generate_systemctl_wrapper_content | sed 's/^/[dry-run]   /'
        run install -d -m 0755 -o root -g root "$SYSTEMCTL_WRAPPER_DIR"
        run install -m 0755 -o root -g root /dev/null "$SYSTEMCTL_WRAPPER_PATH"
        return 0
    fi

    local tmp
    tmp=$(mktemp -t yuzu-systemctl.XXXXXX) || { SYSTEMCTL_WRAPPER_OK=0; return 4; }
    generate_systemctl_wrapper_content > "$tmp"
    if install -d -m 0755 -o root -g root "$SYSTEMCTL_WRAPPER_DIR" \
        && install -m 0755 -o root -g root "$tmp" "$SYSTEMCTL_WRAPPER_PATH"; then
        :
    else
        warn "could not install $SYSTEMCTL_WRAPPER_PATH - NO systemctl sudo grant will be written"
        SYSTEMCTL_WRAPPER_OK=0
        rm -f "$tmp"
        return 4
    fi
    rm -f "$tmp"
    return 0
}

remove_systemctl_wrapper() {
    if [[ "$PLATFORM" != "linux" ]]; then return 0; fi
    if [[ -e "$SYSTEMCTL_WRAPPER_PATH" ]]; then
        log "removing $SYSTEMCTL_WRAPPER_PATH"
        run rm -f "$SYSTEMCTL_WRAPPER_PATH"
        run rmdir "$SYSTEMCTL_WRAPPER_DIR" 2>/dev/null || true
    fi
}

# ── linux file capabilities: REMOVE, never grant (WP13/F21) ─────────────────
# A file capability such as `cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace+eip`
# on the agent binary is a hazard. The binary is 0755, so ANY local user who executes it would receive those
# capabilities, and that user chooses --plugin-dir / YUZU_PLUGIN_DIR, which the agent dlopens:
# local root. Capabilities belong to the SERVICE only (systemd AmbientCapabilities in the
# packaged unit; \`setpriv --ambient-caps\` in scripts/start-UAT.sh --as-user).
#
# Removing the grant from this script is not enough: This script never grants file capabilities. Each run removes any file capability found on the
# binary at `--binary-path` (idempotent).

strip_file_capabilities() {
    if [[ "$PLATFORM" != "linux" ]]; then return 0; fi
    if [[ "$SKIP_SETCAP" -eq 1 ]]; then
        log "skipping file-capability cleanup (--no-cap-cleanup)"
        # Loud, on stderr: this flag can leave an exploitable file capability on a binary that
        # any local user can execute, and the install still exits 0 (WP13 governance R3-NOCAP).
        if [[ -f "$BINARY_PATH" ]] && command -v getcap >/dev/null 2>&1; then
            local live
            live=$(getcap "$BINARY_PATH" 2>/dev/null || true)
            if [[ -n "$live" ]]; then
                warn "--no-cap-cleanup: file capabilities are STILL LIVE on $BINARY_PATH: $live"
                warn "  any local user can run that binary with them; remove with: setcap -r $BINARY_PATH"
            fi
        fi
        return 0
    fi
    if [[ ! -f "$BINARY_PATH" ]]; then
        log "agent binary not found at $BINARY_PATH - no file capabilities to strip"
        return 0
    fi
    local have_getcap=0 caps=""
    if command -v getcap >/dev/null 2>&1; then
        have_getcap=1
        caps=$(getcap "$BINARY_PATH" 2>/dev/null || true)
        if [[ -z "$caps" ]]; then
            log "no file capabilities on $BINARY_PATH (good)"
            return 0
        fi
        log "stripping file capabilities from $BINARY_PATH: $caps"
    fi
    if ! command -v setcap >/dev/null 2>&1; then
        # FAIL (exit 5), never "skip": with the capability possibly still live the install is NOT
        # safe, and the caller must not report success (WP13 governance N1).
        warn "setcap not installed - cannot strip file capabilities from $BINARY_PATH"
        warn "  remove them by hand: setcap -r $BINARY_PATH   (apt: libcap2-bin, dnf: libcap)"
        return 5
    fi
    run setcap -r "$BINARY_PATH" || { warn "setcap -r $BINARY_PATH failed"; return 5; }
    if [[ "$DRY_RUN" -eq 0 && "$have_getcap" -eq 1 ]]; then
        caps=$(getcap "$BINARY_PATH" 2>/dev/null || true)
        if [[ -n "$caps" ]]; then
            warn "file capabilities STILL present on $BINARY_PATH after setcap -r: $caps"
            return 5
        fi
    fi
    return 0
}

# ── verification ────────────────────────────────────────────────────────────
# --check exits non-zero on ANY drift so the caller can rely on it as a
# pre-flight gate (e.g., scripts/start-UAT.sh checks before launching
# the agent).

check_install() {
    local errs=0 unverified=0

    # 1. user exists
    if [[ "$PLATFORM" == "macos" ]]; then
        macos_user_exists || { warn "user $ACCOUNT_NAME does not exist (macOS)"; ((errs++)); }
    else
        linux_user_exists || { warn "user $ACCOUNT_NAME does not exist (Linux)"; ((errs++)); }
    fi

    # 2. state dirs exist with correct ownership
    for dir in "$STATE_DIR" "$CACHE_DIR" "$LOG_DIR"; do
        if [[ ! -d "$dir" ]]; then
            warn "missing dir: $dir"; ((errs++)); continue
        fi
        local owner
        # Branch on the platform: GNU `stat -f` means "filesystem status" (it prints a report and
        # exits 1 for a path), so a `stat -f ... || stat -c ...` chain never reaches `-c` and --check
        # would fail on every healthy Linux host. BSD/macOS `stat` has no `-c`.
        if [[ "$PLATFORM" == "macos" ]]; then
            owner=$(stat -f '%Su' "$dir" 2>/dev/null || echo "")
        else
            owner=$(stat -c '%U' "$dir" 2>/dev/null || echo "")
        fi
        if [[ "$owner" != "$ACCOUNT_NAME" ]]; then
            warn "wrong owner on $dir: got $owner, expected $ACCOUNT_NAME"
            ((errs++))
        fi
    done

    # 3. sudoers file is present and valid
    #
    # The file is installed mode 0440 root:<wheel|root>, so a non-root
    # user can't read it (correct — sudoers files MUST refuse access
    # below their group, sudo refuses to load them otherwise). When we
    # invoke visudo -cf without read access, it returns non-zero with
    # EACCES — that's NOT a validation failure, it's a permissions
    # condition this user can't resolve here. Detect explicitly and
    # report a SKIP-with-instructions instead of a misleading FAIL.
    if [[ "$SKIP_SUDOERS" -eq 0 ]]; then
        if [[ ! -f "$SUDOERS_TARGET" ]]; then
            warn "$SUDOERS_TARGET is missing"; ((errs++))
        elif [[ ! -r "$SUDOERS_TARGET" ]]; then
            # Cannot read it = cannot verify the grants (the glob-grant and wrapper-grant checks below
            # would be skipped), so a green result would be false (WP13 governance R4-CHECKGREEN).
            warn "$SUDOERS_TARGET is present but not readable by $(id -un): its grants are UNVERIFIED"
            warn "  (mode 0440 root-owned is correct; re-run --check as root)"
            unverified=1
        else
            if ! visudo -cf "$SUDOERS_TARGET" >/dev/null 2>&1; then
                warn "$SUDOERS_TARGET fails visudo validation"; ((errs++))
            else
                log "$SUDOERS_TARGET present and visudo-valid"
            fi
            # WP13 governance R1: the CONTENT must be the narrowed one. A file can be
            # present and valid while still carrying wildcard grants.
            if [[ "$PLATFORM" == "linux" ]]; then
                if grep -Eq '^[^#]*systemctl[[:space:]]+(enable|disable|mask|unmask)[[:space:]]' "$SUDOERS_TARGET"; then
                    warn "$SUDOERS_TARGET carries the systemctl enable|disable|mask|unmask glob grants - re-run the installer"
                    ((errs++))
                fi
                if ! grep -Eq "^[^#]*NOPASSWD:[[:space:]]*$SYSTEMCTL_WRAPPER_PATH[[:space:]]*\$" "$SUDOERS_TARGET"; then
                    warn "$SUDOERS_TARGET lacks the $SYSTEMCTL_WRAPPER_PATH grant"
                    ((errs++))
                fi
            else
                if grep -Eq '^[^#]*launchctl[[:space:]]+(bootstrap|bootout)' "$SUDOERS_TARGET"; then
                    warn "$SUDOERS_TARGET carries the launchctl bootstrap|bootout grants - re-run the installer"
                    ((errs++))
                fi
            fi
        fi
    fi

    if [[ "$PLATFORM" == "linux" && "$SKIP_SETCAP" -eq 1 ]]; then
        warn "--no-cap-cleanup given: the file-capability check is SKIPPED, so a green --check does not prove the binary is capability-free"
    fi
    # 4. file capabilities (Linux only): their PRESENCE is the drift. A file capability on a
    #    binary other users can execute is a local privilege escalation (WP13/F21).
    if [[ "$PLATFORM" == "linux" && "$SKIP_SETCAP" -eq 0 && -f "$BINARY_PATH" ]]; then
        if command -v getcap >/dev/null 2>&1; then
            local caps
            caps=$(getcap "$BINARY_PATH" 2>/dev/null || true)
            if [[ -n "$caps" ]]; then
                warn "file capabilities present on $BINARY_PATH: $caps"
                warn "  re-run this installer (it strips them) or: setcap -r $BINARY_PATH"
                ((errs++))
            else
                log "no file capabilities on $BINARY_PATH (correct)"
            fi
        else
            # Cannot verify = drift (WP13 governance R2): a green --check must mean the binary
            # was inspected, not that the inspector was missing.
            warn "getcap is not installed - cannot verify $BINARY_PATH carries no file capabilities"
            warn "  (apt: libcap2-bin, dnf: libcap)"
            ((errs++))
        fi
    fi

    # 5. systemctl wrapper (Linux, when sudoers is installed)
    if [[ "$PLATFORM" == "linux" && "$SKIP_SUDOERS" -eq 0 ]]; then
        if [[ ! -x "$SYSTEMCTL_WRAPPER_PATH" ]]; then
            warn "$SYSTEMCTL_WRAPPER_PATH is missing - services.set_start_mode has no privilege"
            ((errs++))
        else
            local wowner wmode
            wowner=$(stat -c '%u' "$SYSTEMCTL_WRAPPER_PATH" 2>/dev/null || echo "")
            wmode=$(stat -c '%a' "$SYSTEMCTL_WRAPPER_PATH" 2>/dev/null || echo "")
            local want_uid=0
            [[ -n "$TEST_ROOT" ]] && want_uid="$(id -u)" # test layout: the temp dir's owner stands in for root
            if [[ "$wowner" != "$want_uid" || "$wmode" != "755" ]]; then
                warn "$SYSTEMCTL_WRAPPER_PATH must be root-owned 0755 (found uid=$wowner mode=$wmode)"
                ((errs++))
            fi
        fi
    fi

    if [[ "$errs" -ne 0 ]]; then
        warn "check failed — $errs issue(s) found"
        return 1
    fi
    if [[ "$unverified" -ne 0 ]]; then
        warn "check INCOMPLETE — part of the install could not be verified by this user (exit 6)"
        return 6
    fi
    log "check passed — install looks correct"
    return 0
}

# ── action dispatch ─────────────────────────────────────────────────────────

# The install sequence is a function so the execution tests can source this file
# (YUZU_INSTALLER_SOURCE_ONLY=1) and drive it with stub tools. Returns the FIRST failure in the
# order sudoers (3), wrapper (4), file capabilities (5); success only if every step succeeded.
do_install() {
    require_root
    log "installing Yuzu agent user on $PLATFORM (account: $ACCOUNT_NAME)"
    # macos_create_user / linux_create_user are themselves idempotent —
    # they probe existing state, create what's missing, repair what's
    # broken. Don't short-circuit here (short-circuiting would mean a
    # half-installed account couldn't be self-healed by re-running).
    if [[ "$PLATFORM" == "macos" ]]; then
        macos_create_user
    else
        if linux_user_exists; then
            log "user $ACCOUNT_NAME already exists — skipping create"
        else
            linux_create_user
        fi
    fi
    create_state_dirs
    # The wrapper goes in BEFORE the sudoers file that grants it (and a failed install
    # clears SYSTEMCTL_WRAPPER_OK so no systemctl grant is written at all).
    local wrapper_rc=0 sudoers_rc=0 strip_rc=0
    install_systemctl_wrapper || wrapper_rc=$?
    install_sudoers || sudoers_rc=$?
    # Always attempt the capability strip (safe either way), but no failed step may be reported
    # as a complete install.
    strip_file_capabilities || strip_rc=$?
    if [[ "$sudoers_rc" -ne 0 ]]; then
        warn "install INCOMPLETE: the sudoers file was not installed (exit $sudoers_rc)"
        return "$sudoers_rc"
    fi
    if [[ "$wrapper_rc" -ne 0 ]]; then
        warn "install INCOMPLETE: the systemctl wrapper was not installed (exit $wrapper_rc)"
        return "$wrapper_rc"
    fi
    if [[ "$strip_rc" -ne 0 ]]; then
        warn "install INCOMPLETE: file capabilities may still be present on $BINARY_PATH (exit $strip_rc)"
        return "$strip_rc"
    fi
    log "install complete. Verify with: $0 --check"
    return 0
}

if [[ "${YUZU_INSTALLER_SOURCE_ONLY:-0}" == "1" ]]; then
    if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
        return 0 # sourced by the execution tests: define the functions, run nothing
    fi
    # Executed (not sourced) with the test variable set: do NOT silently do nothing and exit 0.
    warn "YUZU_INSTALLER_SOURCE_ONLY is only for sourcing; ignoring it and running normally"
fi

case "$ACTION" in
    install)
        do_install
        exit $?
        ;;

    check)
        # The exit status IS the contract ("exits non-zero on any drift"): the case must not fall
        # through to the trailing `exit 0`, or --check could never fail (WP13 governance N1).
        check_install
        exit $?
        ;;

    uninstall)
        require_root
        log "uninstalling Yuzu agent user on $PLATFORM (account: $ACCOUNT_NAME)"
        remove_sudoers
        remove_systemctl_wrapper
        remove_state_dirs
        if [[ "$PLATFORM" == "macos" ]]; then
            macos_delete_user
        else
            linux_delete_user
        fi
        log "uninstall complete."
        ;;
esac

exit 0
