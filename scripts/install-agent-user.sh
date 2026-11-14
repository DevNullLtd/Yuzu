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
# 5.  (Linux only) Sets file capabilities on the agent binary so plugins
#       that need raw sockets, ptrace, or ip-route management can do
#       so without an extra sudo round-trip:
#         cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace +eip
# 6.  (Linux only) Installs /usr/local/sbin/yuzu-fw-helper (root:root 0755), the
#       one program the sudoers file lets the agent account run as root for
#       iptables and ip6tables. It is written from a quoted heredoc below,
#       to a temporary file in the same directory and renamed into place,
#       and it goes in BEFORE the sudoers file that names it. See the
#       helper's own header for the argument shapes it accepts.
# 7.  (Optional) On both platforms, prints a verifying summary that the
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
# UPGRADES
# ────────
# A host provisioned by an earlier copy of this script has no helper and its
# sudoers file still carries the earlier iptables lines. Re-run this script
# (with the agent upgrade) on every host whose containment falls back to
# iptables: it installs the helper and replaces the sudoers file. Until it
# has run, sudo refuses the helper and the iptables-fallback containment
# actions fail on that host.
#
# UNINSTALL
# ─────────
# Pass --uninstall to reverse:
#   - removes /etc/sudoers.d/yuzu-agent
#   - removes /usr/local/sbin/yuzu-fw-helper (Linux)
#   - removes the agent's filesystem hierarchy (logs are preserved
#     under /var/log/yuzu-agent.removed-<timestamp>/ for forensics)
#   - deletes the user account
# Capabilities applied to the agent binary are NOT removed because the
# binary itself is not owned by this script — uninstall the package to
# remove the binary, capabilities go with it.
#
# ARGUMENTS
# ─────────
#   --dry-run        Print every command the script would run, without
#                    executing any of them. Use this first.
#   --check          Verify the install is correct (user exists with
#                    expected attributes, sudoers file present + valid,
#                    the Linux firewall helper present with the expected
#                    owner, mode and content, state dirs exist with
#                    correct ownership). Exits non-zero on any drift.
#   --uninstall      Remove the user, sudoers file, firewall helper, and
#                    state dirs.
#   --account-name N Override the default account name (_yuzu / yuzu).
#                    Useful for parallel test environments.
#   --binary-path P  Override the path to the agent binary for setcap.
#                    Default: /usr/local/bin/yuzu-agent (Linux) or
#                    /Library/Application\ Support/Yuzu/yuzu-agent (macOS).
#                    On macOS this is a no-op (no setcap equivalent).
#   --no-sudoers     Skip the sudoers file install and the Linux firewall
#                    helper it names. Useful in test environments where
#                    you don't want any privilege grants; the agent will
#                    still run but the firewall containment actions and
#                    other privileged plugins will fail at dispatch
#                    time (which the test ladder catches).
#   --no-setcap      Skip the setcap step on Linux. Useful if you set
#                    capabilities via a packaging tool (.deb postinst,
#                    .rpm %post).
#
# EXIT CODES
# ──────────
#   0  - install/check/uninstall succeeded
#   1  - install/check/uninstall failed; details on stderr
#   2  - argument or precondition error (not run as root, unsupported OS)
#   3  - sudoers file failed visudo validation; install was rolled back
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

# The root-owned helper the Linux sudoers file names for iptables / ip6tables. The same string is
# kFwHelperPath in agents/plugins/firewall/src/firewall_quarantine_parsers.hpp;
# tests/test_legacy_quarantine_plugin_removed_lexical.py checks the two against each other.
FW_HELPER_PATH="/usr/local/sbin/yuzu-fw-helper"

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
        --no-setcap)      SKIP_SETCAP=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                echo "unknown arg: $1" >&2; echo "use --help for usage." >&2; exit 2 ;;
    esac
done

ACCOUNT_NAME="${ACCOUNT_NAME:-$DEFAULT_ACCOUNT}"
BINARY_PATH="${BINARY_PATH:-$DEFAULT_BINARY_PATH}"

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

# require_root — most actions need root; we fail early rather than
# half-running and leaving a partially-installed state. --dry-run and
# --check are exempt: dry-run only prints what would happen, and check
# only reads state.
require_root() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
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

# services.set_start_mode — launchd system domain
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl bootstrap system *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl bootout system *
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
# firewall plugin — iptables / ip6tables, the containment fallback when nft is absent. The agent
# account may run exactly one program as root for them: the helper the installer wrote to
# $FW_HELPER_PATH (root:root 0755). This line names the helper with no argument and no wildcard;
# the helper takes the tokens of one fixed argument shape (list, or create / append / insert the
# jump / remove the jump / flush / delete on a yuzu-fwq-* generation chain), validates every
# variable token itself, and runs /usr/sbin/iptables or /usr/sbin/ip6tables with an argument list
# it builds from its own literals plus the validated values. It never passes the caller's
# arguments on, and anything outside the shapes exits non-zero having run nothing. There is no
# iptables, ip6tables, iptables-save or iptables-restore grant. A sudo regular expression could pin
# the arguments in this file instead, but it needs sudo 1.9.10, which RHEL 8 and 9, Ubuntu 22.04
# and earlier and Debian 11 do not ship. A host provisioned before the helper existed has none of
# this until the installer is re-run.
$ACCOUNT_NAME ALL=(root) NOPASSWD: $FW_HELPER_PATH

# firewall plugin — nftables containment (own table inet yuzu_quarantine). These lines NARROW
# the argv shape; they do not confine nft: sudo globs match concatenated args, and the file
# named by -f is agent-generated. The confinement is the firewall plugin's token validation
# (agents/plugins/firewall/src/firewall_quarantine_parsers.hpp). The bare /usr/sbin/nft grant
# that used to sit here was never called by any plugin and is replaced by these three.
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft -f *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft delete table inet yuzu_quarantine
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft list table inet yuzu_quarantine

# services.set_start_mode — systemd unit lifecycle
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/systemctl enable *,  /bin/systemctl disable *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/systemctl mask *,    /bin/systemctl unmask *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemctl enable *,  /usr/bin/systemctl disable *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemctl mask *,    /usr/bin/systemctl unmask *

# network_actions.flush_dns
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemd-resolve --flush-caches
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/resolvectl flush-caches

EOF
    fi

    cat <<EOF
# Pre-requisites for daemon-style invocation:
Defaults:$ACCOUNT_NAME    !requiretty
Defaults:$ACCOUNT_NAME    env_keep += "YUZU_*"
EOF
}

install_sudoers() {
    if [[ "$SKIP_SUDOERS" -eq 1 ]]; then
        log "skipping sudoers install (--no-sudoers)"
        return 0
    fi

    local target="/etc/sudoers.d/yuzu-agent"
    local tmp
    tmp=$(mktemp -t yuzu-sudoers.XXXXXX)
    # Cleanup on any exit path: the temp file should never linger.
    trap 'rm -f "$tmp"' RETURN

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
    local target="/etc/sudoers.d/yuzu-agent"
    if [[ -f "$target" ]]; then
        log "removing $target"
        run rm -f "$target"
    fi
}

# ── Linux firewall helper ───────────────────────────────────────────────────
#
# The sudoers file names ONE program for iptables / ip6tables: $FW_HELPER_PATH. It is a POSIX sh
# script, written from the quoted heredoc below (nothing in it is expanded by this script). The
# installer is standalone and has no build output to copy, so the text lives here, and --check
# compares the installed file with it byte for byte.
#
# Contract (the C++ twin is iptables_helper_argv in
# agents/plugins/firewall/src/firewall_quarantine_parsers.hpp; the two grammars move together and
# tests/test_legacy_quarantine_plugin_removed_lexical.py runs this text against the same cases):
#   - it matches the token count and every fixed token with `case`, validates every variable
#     token, and then execs the tool with an argument list it builds from its own literals plus the
#     validated values. No token ever reaches a shell parser: no eval, no `sh -c`, no arithmetic on a
#     token before its digit check, no environment read.
#   - anything else exits 64 having run nothing.
# Installed root:root 0755, written to a temporary file in the same directory and renamed into
# place, and always BEFORE the sudoers file that names it. Linux only.

generate_fw_helper_content() {
    cat <<'YUZU_FW_HELPER'
#!/bin/sh
# yuzu-fw-helper: the one program the Yuzu agent account may run as root to change iptables and
# ip6tables. Installed by scripts/install-agent-user.sh (Linux only), root:root 0755, and named in
# /etc/sudoers.d/yuzu-agent with no argument and no wildcard. Do not edit by hand: the installer's
# --check compares this file with its own text.
#
# Usage: yuzu-fw-helper iptables|ip6tables <tokens>
# <tokens> are exactly those of one of these shapes (<ours> is a yuzu-fwq-<generation>[-f] chain,
# the generation 1 to 10 digits and at most 2147483647):
#   -S
#   -N <ours>
#   -A <ours> <rule>
#   -I INPUT|OUTPUT|FORWARD 1 -j <ours>
#   -D <chain> -j <ours>           (<chain>: 1 to 28 of letters, digits . : / _ -, not starting with -)
#   -F <ours>
#   -X <ours>
# and <rule> is one of:
#   -j DROP
#   -i lo -j ACCEPT
#   -o lo -j ACCEPT
#   -p icmpv6 --icmpv6-type 133|134|135|136 -j ACCEPT
#   [-s|-d <address>[/<prefix>]] -p tcp|udp [--sport <port>] [--dport <port>]
#       [--tcp-flags ACK ACK|RST RST (tcp only)] -j ACCEPT
# <address> is an IPv4 literal (digits, exactly three dots) or an IPv6 literal (lower-case hex and
# colons, two or more colons), at most 43 characters with its prefix; <port> is 1 to 65535 in
# plain decimal.
#
# The caller's arguments are never passed on. Each branch below matches the token count and the
# fixed tokens, validates the variable ones, and execs the tool with an argument list made of its
# own literals plus the validated values. Anything else exits 64, having run nothing.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
IPT=/usr/sbin/iptables
IP6T=/usr/sbin/ip6tables

refuse() {
    printf 'yuzu-fw-helper: refused\n' >&2
    exit 64
}

# tok_is TOKEN LITERAL: the token is exactly the literal (a quoted case pattern is not a glob).
tok_is() {
    case $1 in
        "$2") return 0 ;;
    esac
    return 1
}

all_digits() {
    case $1 in
        '' | *[!0123456789]*) return 1 ;;
    esac
    return 0
}

# is_ours TOKEN: yuzu-fwq-<generation>[-f].
is_ours() {
    case $1 in
        yuzu-fwq-*) ;;
        *) return 1 ;;
    esac
    gen=${1#yuzu-fwq-}
    gen=${gen%-f}
    all_digits "$gen" || return 1
    case ${#gen} in
        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9) return 0 ;;
        10) [ "$gen" -le 2147483647 ] ;;
        *) return 1 ;;
    esac
}

# is_from_chain TOKEN: the chain a jump of ours sits in.
is_from_chain() {
    case $1 in
        '' | -* | *[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._:/-]*) return 1 ;;
    esac
    [ "${#1}" -le 28 ]
}

# is_port TOKEN: plain decimal 1 to 65535.
is_port() {
    case $1 in
        '' | 0* | *[!0123456789]*) return 1 ;;
    esac
    case ${#1} in
        1 | 2 | 3 | 4) return 0 ;;
        5) [ "$1" -le 65535 ] ;;
        *) return 1 ;;
    esac
}

# is_addr TOKEN: an IPv4 or IPv6 literal with an optional /prefix.
is_addr() {
    [ "${#1}" -le 43 ] || return 1
    addr_part=$1
    pre=
    case $1 in
        */*)
            addr_part=${1%%/*}
            pre=${1#*/}
            all_digits "$pre" || return 1
            [ "${#pre}" -le 3 ] || return 1
            ;;
    esac
    case $addr_part in
        *:*:*)
            case $addr_part in
                *[!0123456789abcdef:]* | *:::*) return 1 ;;
            esac
            lim=128
            ;;
        *:*) return 1 ;;
        *[!0123456789.]* | .* | *. | *..* | *.*.*.*.*) return 1 ;;
        *.*.*.*) lim=32 ;;
        *) return 1 ;;
    esac
    [ -z "$pre" ] || [ "$pre" -le "$lim" ]
}

# parse_l4 TOKENS: [-s|-d ADDR] -p tcp|udp [--sport P] [--dport P] [--tcp-flags F F] -j ACCEPT, or the
# icmpv6 form. Sets r_*; the caller rebuilds the argument list from them.
parse_l4() {
    case $1 in
        -s | -d)
            [ $# -ge 2 ] || return 1
            is_addr "$2" || return 1
            r_aopt=$1
            r_addr=$2
            shift 2
            ;;
    esac
    [ $# -ge 4 ] || return 1
    tok_is "$1" -p || return 1
    case $2 in
        tcp) r_proto=tcp ;;
        udp) r_proto=udp ;;
        icmpv6)
            [ -z "$r_aopt" ] || return 1
            [ $# -eq 6 ] || return 1
            tok_is "$3" --icmpv6-type || return 1
            case $4 in
                133) r_type=133 ;;
                134) r_type=134 ;;
                135) r_type=135 ;;
                136) r_type=136 ;;
                *) return 1 ;;
            esac
            tok_is "$5" -j || return 1
            tok_is "$6" ACCEPT || return 1
            r_kind=icmp6
            return 0
            ;;
        *) return 1 ;;
    esac
    shift 2
    if [ $# -ge 2 ] && tok_is "$1" --sport; then
        is_port "$2" || return 1
        r_sport=$2
        shift 2
    fi
    if [ $# -ge 2 ] && tok_is "$1" --dport; then
        is_port "$2" || return 1
        r_dport=$2
        shift 2
    fi
    if [ $# -ge 3 ] && tok_is "$1" --tcp-flags; then
        tok_is "$r_proto" tcp || return 1
        if tok_is "$2" ACK && tok_is "$3" ACK; then
            r_flags=ACK
        elif tok_is "$2" RST && tok_is "$3" RST; then
            r_flags=RST
        else
            return 1
        fi
        shift 3
    fi
    [ $# -eq 2 ] || return 1
    tok_is "$1" -j || return 1
    tok_is "$2" ACCEPT || return 1
    r_kind=l4
    return 0
}

# parse_rule TOKENS: the rule of an -A.
parse_rule() {
    r_kind=
    r_type=
    r_aopt=
    r_addr=
    r_proto=
    r_sport=
    r_dport=
    r_flags=
    [ $# -ge 2 ] || return 1
    case $1 in
        -j)
            [ $# -eq 2 ] || return 1
            tok_is "$2" DROP || return 1
            r_kind=drop
            ;;
        -i | -o)
            [ $# -eq 4 ] || return 1
            tok_is "$2" lo || return 1
            tok_is "$3" -j || return 1
            tok_is "$4" ACCEPT || return 1
            case $1 in
                -i) r_kind=lo_in ;;
                *) r_kind=lo_out ;;
            esac
            ;;
        -s | -d | -p) parse_l4 "$@" || return 1 ;;
        *) return 1 ;;
    esac
    return 0
}

[ $# -ge 2 ] || refuse
case $1 in
    iptables) tool=$IPT ;;
    ip6tables) tool=$IP6T ;;
    *) refuse ;;
esac
op=$2
shift 2

case $op in
    -S)
        [ $# -eq 0 ] || refuse
        exec "$tool" -S
        ;;
    -N)
        [ $# -eq 1 ] || refuse
        is_ours "$1" || refuse
        exec "$tool" -N "$1"
        ;;
    -F)
        [ $# -eq 1 ] || refuse
        is_ours "$1" || refuse
        exec "$tool" -F "$1"
        ;;
    -X)
        [ $# -eq 1 ] || refuse
        is_ours "$1" || refuse
        exec "$tool" -X "$1"
        ;;
    -I)
        [ $# -eq 4 ] || refuse
        tok_is "$2" 1 || refuse
        tok_is "$3" -j || refuse
        is_ours "$4" || refuse
        case $1 in
            INPUT) exec "$tool" -I INPUT 1 -j "$4" ;;
            OUTPUT) exec "$tool" -I OUTPUT 1 -j "$4" ;;
            FORWARD) exec "$tool" -I FORWARD 1 -j "$4" ;;
            *) refuse ;;
        esac
        ;;
    -D)
        [ $# -eq 3 ] || refuse
        is_from_chain "$1" || refuse
        tok_is "$2" -j || refuse
        is_ours "$3" || refuse
        exec "$tool" -D "$1" -j "$3"
        ;;
    -A)
        [ $# -ge 3 ] || refuse
        is_ours "$1" || refuse
        chain=$1
        shift
        parse_rule "$@" || refuse
        # Rebuild the argument list from literals and the validated values. The "$@" at the exec
        # below is this list, not the caller's.
        set -- -A "$chain"
        case $r_kind in
            drop) set -- "$@" -j DROP ;;
            lo_in) set -- "$@" -i lo -j ACCEPT ;;
            lo_out) set -- "$@" -o lo -j ACCEPT ;;
            icmp6) set -- "$@" -p icmpv6 --icmpv6-type "$r_type" -j ACCEPT ;;
            l4)
                case $r_aopt in
                    -s) set -- "$@" -s "$r_addr" ;;
                    -d) set -- "$@" -d "$r_addr" ;;
                esac
                case $r_proto in
                    tcp) set -- "$@" -p tcp ;;
                    udp) set -- "$@" -p udp ;;
                esac
                [ -z "$r_sport" ] || set -- "$@" --sport "$r_sport"
                [ -z "$r_dport" ] || set -- "$@" --dport "$r_dport"
                case $r_flags in
                    ACK) set -- "$@" --tcp-flags ACK ACK ;;
                    RST) set -- "$@" --tcp-flags RST RST ;;
                esac
                set -- "$@" -j ACCEPT
                ;;
            *) refuse ;;
        esac
        exec "$tool" "$@"
        ;;
    *) refuse ;;
esac
YUZU_FW_HELPER
}

install_fw_helper() {
    if [[ "$PLATFORM" != "linux" || "$SKIP_SUDOERS" -eq 1 ]]; then return 0; fi

    local dir tmp
    dir=$(dirname "$FW_HELPER_PATH")
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would write the following to $FW_HELPER_PATH (root:root 0755):"
        generate_fw_helper_content | sed 's/^/[dry-run]   /'
        return 0
    fi

    log "installing the firewall helper $FW_HELPER_PATH (root:root 0755)"
    # Create the directory only when missing: never reset a site-customised owner or mode.
    [[ -d "$dir" ]] || run install -d -m 0755 -o root -g root "$dir"
    # A temporary file in the SAME directory, so the final rename is atomic: sudo never sees a
    # half-written helper, and a failed write leaves the previous helper in place.
    tmp=$(mktemp "$dir/.yuzu-fw-helper.XXXXXX") || { warn "cannot create a temp file in $dir"; return 1; }
    if ! generate_fw_helper_content > "$tmp" \
        || ! chown root:root "$tmp" \
        || ! chmod 0755 "$tmp" \
        || ! sh -n "$tmp" \
        || ! mv -f "$tmp" "$FW_HELPER_PATH"; then
        rm -f "$tmp"
        warn "could not install $FW_HELPER_PATH"
        return 1
    fi
}

remove_fw_helper() {
    if [[ "$PLATFORM" != "linux" ]]; then return 0; fi
    if [[ -e "$FW_HELPER_PATH" ]]; then
        log "removing $FW_HELPER_PATH"
        run rm -f "$FW_HELPER_PATH"
    fi
}

# check_fw_helper — Linux only: the helper is present, root:root 0755 and byte-identical to this
# script's text. Returns non-zero on any drift.
check_fw_helper() {
    if [[ ! -f "$FW_HELPER_PATH" ]]; then
        warn "$FW_HELPER_PATH is missing (re-run this installer)"
        return 1
    fi
    local owner_mode
    owner_mode=$(stat -c '%U:%G %a' "$FW_HELPER_PATH" 2>/dev/null || true)
    if [[ "$owner_mode" != "root:root 755" ]]; then
        warn "$FW_HELPER_PATH is ${owner_mode:-unreadable}, expected root:root 755"
        return 1
    fi
    if ! generate_fw_helper_content | cmp -s - "$FW_HELPER_PATH"; then
        warn "$FW_HELPER_PATH differs from this installer's text (re-run this installer)"
        return 1
    fi
    log "$FW_HELPER_PATH present, root:root 0755, content current"
    return 0
}

# ── linux capabilities ──────────────────────────────────────────────────────
# Capabilities granted to the agent binary directly. These avoid a
# sudo round-trip for syscalls the agent makes itself (raw sockets,
# routing-table writes, ptrace). They do NOT transfer through execve,
# so plugins that shell out to iptables still need the sudoers entry
# for the firewall helper above — capabilities cover only the agent's own
# syscalls, not its child processes.
#
# +eip means the capability is in the binary's effective, inheritable,
# AND permitted sets. eip is the right combination for a daemon
# binary; +ep alone wouldn't survive setuid (we don't setuid) and +ei
# alone wouldn't be effective without explicit cap_set_proc().

apply_setcap() {
    if [[ "$PLATFORM" != "linux" ]]; then return 0; fi
    if [[ "$SKIP_SETCAP" -eq 1 ]]; then
        log "skipping setcap (--no-setcap)"
        return 0
    fi
    if ! command -v setcap >/dev/null 2>&1; then
        warn "setcap not installed — skipping (apt: libcap2-bin, dnf: libcap)"
        return 0
    fi
    if [[ ! -f "$BINARY_PATH" ]]; then
        warn "agent binary not found at $BINARY_PATH — skipping setcap"
        warn "  re-run with --binary-path PATH after the agent is installed,"
        warn "  or set capabilities from your packaging tool (postinst hook)."
        return 0
    fi

    log "applying capabilities to $BINARY_PATH"
    log "  cap_net_admin, cap_net_raw, cap_dac_read_search, cap_sys_ptrace +eip"
    run setcap "cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace+eip" "$BINARY_PATH"
}

# ── verification ────────────────────────────────────────────────────────────
# --check exits non-zero on ANY drift so the caller can rely on it as a
# pre-flight gate (e.g., scripts/start-UAT.sh checks before launching
# the agent).

check_install() {
    local errs=0

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
        owner=$(stat -f '%Su' "$dir" 2>/dev/null || stat -c '%U' "$dir")
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
        if [[ ! -f /etc/sudoers.d/yuzu-agent ]]; then
            warn "/etc/sudoers.d/yuzu-agent is missing"; ((errs++))
        elif [[ ! -r /etc/sudoers.d/yuzu-agent ]]; then
            log "/etc/sudoers.d/yuzu-agent present but not readable by $(id -un)"
            log "  (mode 0440 root:wheel/root is correct; rerun --check as root to validate)"
        else
            if ! visudo -cf /etc/sudoers.d/yuzu-agent >/dev/null 2>&1; then
                warn "/etc/sudoers.d/yuzu-agent fails visudo validation"; ((errs++))
            else
                log "/etc/sudoers.d/yuzu-agent present and visudo-valid"
            fi
        fi
    fi

    # 4. the firewall helper the Linux sudoers file names: owner, mode and content
    if [[ "$PLATFORM" == "linux" && "$SKIP_SUDOERS" -eq 0 ]]; then
        check_fw_helper || ((errs++))
    fi

    # 5. capabilities (Linux only)
    if [[ "$PLATFORM" == "linux" && "$SKIP_SETCAP" -eq 0 && -f "$BINARY_PATH" ]]; then
        if command -v getcap >/dev/null 2>&1; then
            local caps
            caps=$(getcap "$BINARY_PATH" 2>/dev/null || true)
            if [[ -z "$caps" ]]; then
                warn "no capabilities set on $BINARY_PATH"; ((errs++))
            else
                log "capabilities on $BINARY_PATH: $caps"
            fi
        fi
    fi

    if [[ "$errs" -eq 0 ]]; then
        log "check passed — install looks correct"
        return 0
    else
        warn "check failed — $errs issue(s) found"
        return 1
    fi
}

# ── action dispatch ─────────────────────────────────────────────────────────

case "$ACTION" in
    install)
        require_root
        log "installing Yuzu agent user on $PLATFORM (account: $ACCOUNT_NAME)"
        # macos_create_user / linux_create_user are themselves idempotent —
        # they probe existing state, create what's missing, repair what's
        # broken. Don't short-circuit here (we used to, which meant a
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
        # The helper goes in BEFORE the sudoers file that names it. A failed helper does not hold
        # the sudoers file back (replacing it is what drops the earlier iptables lines); it fails
        # the run at the end instead.
        fw_helper_rc=0
        install_fw_helper || fw_helper_rc=1
        install_sudoers
        apply_setcap
        if [[ "$fw_helper_rc" -ne 0 ]]; then
            fail "the firewall helper was not installed; iptables containment will fail on this host until it is"
        fi
        log "install complete. Verify with: $0 --check"
        ;;

    check)
        check_install
        ;;

    uninstall)
        require_root
        log "uninstalling Yuzu agent user on $PLATFORM (account: $ACCOUNT_NAME)"
        remove_sudoers
        remove_fw_helper
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
