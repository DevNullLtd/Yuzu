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
# 6.  Installs two root-owned helper programs (root:root 0755 on Linux, root:wheel 0755 on
#       macOS), the only programs the sudoers file lets the agent account run as root for
#       the work that needs more than a fixed command:
#         yuzu-fw-helper   firewall containment: iptables / ip6tables and the nftables
#                          ruleset load on Linux, the pf anchor load on macOS
#         yuzu-svc-helper  services.set_start_mode: systemctl enable|disable|mask|unmask on
#                          Linux, launchctl enable|disable on macOS
#       Linux: /usr/local/sbin.  macOS: /Library/PrivilegedHelperTools.
#       Each is written from a quoted heredoc below, to a temporary file in the same
#       directory and renamed into place, and each goes in BEFORE the sudoers file that
#       names it. The sudoers file is written only when BOTH helpers were installed in
#       that run; otherwise the installer removes it and exits 1. See the helper's own
#       header for the argument shapes it accepts.
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
# `visudo -cf`, and only when both helpers were installed in that run. When a helper
# cannot be installed (its directory is not owned by root, or is writable by all users;
# a group-writable one is accepted with a warning) the installer removes the sudoers file and exits 1, so no grant names a helper
# that is not there. Correct the directory and re-run to get the file back.
#
# HOSTS WITHOUT THE HELPERS
# ─────────────────────────
# The two helpers and the sudoers lines that name them are written by this script. A
# host without them has none of these grants: the containment actions (the nftables
# load and the iptables fallback on Linux, the pf anchor load on macOS) and
# services.set_start_mode fail there with sudo's own message, unless the agent runs as
# root. Provision every Linux and macOS host with this build's copy of this script. An
# agent or host from an earlier build is unsupported and is reprovisioned into a fresh
# deployment of this build (docs/user-manual/upgrading.md, "Deployment contract (hard
# cutover)"); running this script again on the same build is safe (see above).
#
# UNINSTALL
# ─────────
# Pass --uninstall to reverse:
#   - removes /etc/sudoers.d/yuzu-agent
#   - removes the two helpers (yuzu-fw-helper, yuzu-svc-helper)
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
#                    both helpers present with the expected owner, mode
#                    and content, state dirs exist with correct
#                    ownership). Exits non-zero on any drift.
#   --uninstall      Remove the user, sudoers file, both helpers, and
#                    state dirs.
#   --account-name N Override the default account name (_yuzu / yuzu).
#                    Useful for parallel test environments.
#   --binary-path P  Override the path to the agent binary for setcap.
#                    Default: /usr/local/bin/yuzu-agent (Linux) or
#                    /Library/Application\ Support/Yuzu/yuzu-agent (macOS).
#                    On macOS this is a no-op (no setcap equivalent).
#   --no-sudoers     Skip the sudoers file install and the two helpers it
#                    names. Useful in test environments where you don't
#                    want any privilege grants; the agent will still run
#                    but the firewall containment actions and other
#                    privileged plugins will fail at dispatch time (which
#                    the test ladder catches).
#   --no-setcap      Skip the setcap step on Linux. Useful if you set
#                    capabilities via a packaging tool (.deb postinst,
#                    .rpm %post).
#
# EXIT CODES
# ──────────
#   0  - install/check/uninstall succeeded
#   1  - install/check/uninstall failed; details on stderr (an install that could not
#        install a helper also exits 1, after removing the sudoers file)
#   2  - argument or precondition error (not run as root, unsupported OS)
#   3  - sudoers file failed visudo validation; it was not installed and the
#        installer removed any earlier file, so no old grant stays (another
#        install failure of that file exits with that command's own status)
#
# THIS SCRIPT MUST BE RUN AS ROOT.
# We don't try to be cute about that — every action below requires root.
###############################################################################

set -uo pipefail

# ── argument defaults ────────────────────────────────────────────────────────

ACTION="install"           # install | check | uninstall
SUDOERS_FILE="/etc/sudoers.d/yuzu-agent"   # fixed: never read from the environment
DRY_RUN=0
ACCOUNT_NAME=""            # filled in based on platform if not specified
BINARY_PATH=""             # filled in based on platform if not specified
SKIP_SUDOERS=0
SKIP_SETCAP=0

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
        # The two root-owned helpers the sudoers file names, and the group root's files carry
        # (macOS has no group named root). These strings are kFwHelperPathMacos in
        # agents/plugins/firewall/src/firewall_quarantine_parsers.hpp and kSvcHelperPathMacos in
        # agents/plugins/services/src/services_parsers.hpp; tests/test_legacy_quarantine_plugin_removed_lexical.py
        # checks each against its header. /Library/PrivilegedHelperTools is root:wheel 0755 on a stock
        # macOS and is where Apple keeps helpers a daemon runs as root.
        ROOT_GROUP="wheel"
        FW_HELPER_PATH="/Library/PrivilegedHelperTools/yuzu-fw-helper"
        SVC_HELPER_PATH="/Library/PrivilegedHelperTools/yuzu-svc-helper"
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
        # The two root-owned helpers the sudoers file names, and root's group. These strings are
        # kFwHelperPath in agents/plugins/firewall/src/firewall_quarantine_parsers.hpp and
        # kSvcHelperPathLinux in agents/plugins/services/src/services_parsers.hpp;
        # tests/test_legacy_quarantine_plugin_removed_lexical.py checks each against its header.
        ROOT_GROUP="root"
        FW_HELPER_PATH="/usr/local/sbin/yuzu-fw-helper"
        SVC_HELPER_PATH="/usr/local/sbin/yuzu-svc-helper"
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
# firewall plugin — pf anchor containment. The agent account may run one program as root to load
# the anchor: the helper the installer wrote to $FW_HELPER_PATH (root:wheel 0755). This line names
# the helper with no argument and no wildcard. For the anchor it takes "pf load <staged file>",
# checks every line of the file against the ruleset the plugin generates (the fixed lines, then
# rule lines of the plugin's own forms with each address and port validated, then the closing
# block line), and gives pfctl a ruleset it builds from its own literals plus the checked values on
# standard input; the file is never handed to pfctl. It never passes the caller's arguments on, and
# anything outside that shape exits non-zero having run nothing. There is no pfctl grant that takes
# a file name. The enable reference is given back with "pfctl -X <token>": the token is 1 to 24
# digits, and sudoers pins that with one bracket class per digit (24 lines, the n-th with n
# classes), because a sudoers argument pattern cannot otherwise fix a length without a wildcard and
# sudo regular expressions need sudo 1.9.10, which an older sudo does not read. There is no bare
# pfctl grant. The anchor name sorts first among Apple's com.apple/* sub-anchors, and the release
# flush is -F rules / -F nat on that anchor only (never -F all: that is global). The installer
# writes the helper before this file; a host without it is provisioned with this build's installer.
$ACCOUNT_NAME ALL=(root) NOPASSWD: $FW_HELPER_PATH
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -E
EOF
        local pf_digits="" pf_n
        for ((pf_n = 1; pf_n <= 24; pf_n++)); do
            pf_digits+="[0123456789]"
            printf '%s ALL=(root) NOPASSWD: /sbin/pfctl -X %s\n' "$ACCOUNT_NAME" "$pf_digits"
        done
        cat <<EOF
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple/000.yuzu_quarantine -F rules
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple/000.yuzu_quarantine -F nat
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple/000.yuzu_quarantine -s rules
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -a com.apple -s Anchors
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -F states
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -s info
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -s rules
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl -s References

# services.set_start_mode — launchd system domain. The agent account may run one program as root
# for it: the helper the installer wrote to $SVC_HELPER_PATH (root:wheel 0755). This line names the
# helper with no argument and no wildcard. The helper takes "launchctl enable|disable <label>",
# checks the label against the characters a launchd label may have here (letters, digits, - _ . @,
# 1 to 256 of them), and runs /bin/launchctl enable|disable system/<label> with an argument list
# it builds from its own literals plus that label. It never passes the caller's arguments on, and
# any other subcommand or shape exits non-zero having run nothing. The plugin runs no launchctl
# bootstrap or bootout, so there is no line for them. The installer writes the helper before this
# file; a host without it is provisioned with this build's installer.
$ACCOUNT_NAME ALL=(root) NOPASSWD: $SVC_HELPER_PATH

# network_actions.flush_dns
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/dscacheutil -flushcache
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder

EOF
    else  # linux
        cat <<EOF
# firewall plugin — Linux containment (nftables, or iptables / ip6tables when nft is absent). The
# agent account may run exactly one program as root to change them: the helper the installer wrote
# to $FW_HELPER_PATH (root:root 0755). This line names the helper with no argument and no
# wildcard. For iptables and ip6tables the helper takes the tokens of one fixed argument shape
# (list, or create / append / insert the jump / remove the jump / flush / delete on a yuzu-fwq-*
# generation chain), validates every variable token itself, and runs /usr/sbin/iptables or
# /usr/sbin/ip6tables with an argument list it builds from its own literals plus the validated
# values. For nftables it takes the ruleset file the plugin staged (nft load <file>), checks every
# line of it against the ruleset the plugin generates, and gives nft a ruleset it builds from its
# own literals plus the checked values on standard input; the file is never handed to nft. It
# never passes the caller's arguments on, and anything outside these shapes exits non-zero having
# run nothing. There is no iptables, ip6tables, iptables-save, iptables-restore or nft grant that
# takes a file name or an argument pattern. A sudo regular expression could pin the arguments in
# this file instead, but it needs sudo 1.9.10, which RHEL 8 and 9, Ubuntu 22.04 and earlier and
# Debian 11 do not ship. The installer writes the helper before this file; a host without it is
# provisioned with this build's installer.
$ACCOUNT_NAME ALL=(root) NOPASSWD: $FW_HELPER_PATH

# firewall plugin — nftables containment (own table inet yuzu_quarantine). The ruleset is loaded
# through the helper above, so no line here takes a file name. Removing the table and listing it
# are the two fixed commands below, with no argument pattern.
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft delete table inet yuzu_quarantine
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft list table inet yuzu_quarantine

# services.set_start_mode — systemd unit lifecycle. The agent account may run one program as root
# for it: the helper the installer wrote to $SVC_HELPER_PATH (root:root 0755). This line names the
# helper with no argument and no wildcard. The helper takes "systemctl enable|disable|mask|unmask
# <unit>", checks the unit name against the characters a unit name may have here (letters, digits,
# - _ . @, 1 to 256 of them), and runs systemctl <verb> -- <unit> with an argument list it builds
# from its own literals plus that name. It never passes the caller's arguments on, and any other
# subcommand or shape exits non-zero having run nothing. A sudo regular expression could pin the
# name in this file instead, but it needs sudo 1.9.10 (see the firewall note above). The installer
# writes the helper before this file; a host without it is provisioned with this build's installer.
$ACCOUNT_NAME ALL=(root) NOPASSWD: $SVC_HELPER_PATH

# network_actions.flush_dns
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemd-resolve --flush-caches
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/resolvectl flush-caches

EOF
    fi

    echo "# Pre-requisites for daemon-style invocation:"
    if sudo_knows_requiretty; then
        echo "Defaults:$ACCOUNT_NAME    !requiretty"
    fi
    echo "Defaults:$ACCOUNT_NAME    env_keep += \"YUZU_*\""
}

# sudo_knows_requiretty: sudo-rs (the default sudo on newer Ubuntu) has no `requiretty` setting and
# its visudo rejects the whole file over that one line, so the line is written only when this host's
# visudo accepts it. No visudo, or no temporary file, keeps the line (install_sudoers needs visudo
# and refuses the file without it).
sudo_knows_requiretty() {
    command -v visudo >/dev/null 2>&1 || return 0
    local probe rc
    probe=$(mktemp -t yuzu-requiretty.XXXXXX) || return 0
    echo "Defaults !requiretty" >"$probe"
    visudo -cf "$probe" >/dev/null 2>&1
    rc=$?
    rm -f "$probe"
    return "$rc"
}

install_sudoers() {
    if [[ "$SKIP_SUDOERS" -eq 1 ]]; then
        log "skipping sudoers install (--no-sudoers)"
        return 0
    fi

    local target="$SUDOERS_FILE"
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
    # ROOT_GROUP is set once, in the platform block.
    log "installing $tmp -> $target (mode 0440, root:$ROOT_GROUP)"
    run install -m 0440 -o root -g "$ROOT_GROUP" "$tmp" "$target"
}

remove_sudoers() {
    local target="$SUDOERS_FILE"
    if [[ -f "$target" ]]; then
        log "removing $target"
        run rm -f "$target"
    fi
}

# ── Root-owned helpers ──────────────────────────────────────────────────────
#
# Two helpers, each a POSIX sh script written from a quoted heredoc below (nothing in it is
# expanded by this script), on both platforms (the paths are set in the platform block). The
# installer is standalone and has no build output to copy, so the text lives here, and --check
# compares each installed file with it byte for byte. The sudoers file names each helper with no
# argument and no wildcard:
#   - $FW_HELPER_PATH, firewall containment: iptables, ip6tables and the nftables ruleset load on
#     Linux, the pf anchor load on macOS.
#   - $SVC_HELPER_PATH, services.set_start_mode: systemctl on Linux, launchctl on macOS.
#
# The firewall helper's contract (the C++ twins are iptables_helper_argv, nft_ruleset_text and
# pf_anchor_ruleset in agents/plugins/firewall/src/firewall_quarantine_parsers.hpp; the grammars
# move together and tests/test_legacy_quarantine_plugin_removed_lexical.py runs this text against
# the same cases):
#   - iptables / ip6tables: it matches the token count and every fixed token with `case`,
#     validates every variable token, and then execs the tool with an argument list it builds from
#     its own literals plus the validated values. No token ever reaches a shell parser: no eval,
#     no `sh -c`, no arithmetic on a token before its digit check, no environment read.
#   - nft load: it reads the staged file ONCE, checks every line against the ruleset the plugin
#     generates, and gives nft a ruleset it builds from its own literals plus the checked tokens on
#     standard input. The file's bytes never reach nft: a shell `read` and nft do not split the same
#     bytes the same way (NUL, CR, backslash-newline), so a copy that passed a shell check would not
#     be proven to be what nft parses. There is no temporary file to leave behind or cut short.
#   - pf load: the same, for the macOS anchor: the staged file is read ONCE, every line is checked
#     against the ruleset the plugin generates, and pfctl is given a ruleset the helper builds from
#     its own literals plus the checked tokens on standard input.
#   - anything else exits 64 having run nothing.
# The helper is ONE text on both platforms. An action whose tool is not on the host (iptables or
# nft on a Mac, pfctl on Linux) fails at exec, after the same validation, having changed nothing.
# The services helper's contract is in its own header (the C++ twin is the builders in
# agents/plugins/services/src/services_parsers.hpp). Each is installed root:<root group> 0755,
# written to a temporary file in the same directory and renamed into place, and always BEFORE the
# sudoers file that names it. The sudoers file is written only when both are installed; a failed
# helper removes it instead.

generate_fw_helper_content() {
    cat <<'YUZU_FW_HELPER'
#!/bin/sh
# yuzu-fw-helper: the one program the Yuzu agent account may run as root for firewall containment:
# iptables and ip6tables and the nftables ruleset load on Linux, the pf anchor load on macOS.
# Installed by scripts/install-agent-user.sh on both platforms, root-owned 0755 (root:root on
# Linux, root:wheel on macOS), and named in /etc/sudoers.d/yuzu-agent with no argument and no
# wildcard. Do not edit by hand: the installer's --check compares this file with its own text. An
# action whose tool is not on the host fails at exec, having changed nothing.
#
# Usage: yuzu-fw-helper iptables|ip6tables <tokens>
#        yuzu-fw-helper nft load <path>
#        yuzu-fw-helper pf load <path>
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
# <address> is an IPv4 literal (four decimal parts of 0 to 255, no leading zero, exactly three
# dots) or an IPv6 literal (lower-case hex and colons, two or more colons), at most 43 characters
# with its prefix, which is 1 to 3 digits with no leading zero (0 alone is allowed) and at most 32
# or 128; <port> is 1 to 65535 in plain decimal.
#
# The caller's arguments are never passed on. Each branch below matches the token count and the
# fixed tokens, validates the variable ones, and execs the tool with an argument list made of its
# own literals plus the validated values. Anything else exits 64, having run nothing.
#
# nft load <path> and pf load <path>: <path> is absolute, at most 512 characters with no control
# character, in a directory named firewall-staging, and its file name is yuzu-fwq-<letters, digits,
# . _ ->.nft for nft and yuzu-fwq-<...>.pf for pf (the other suffix is refused). The file must be
# neither a link nor a file that is not a regular one. It is read ONCE, at most 262145 bytes of it,
# at most 512 lines of at most 512 characters, and the whole input is checked before anything runs.
# A last line with no newline is refused. A NUL byte is dropped, or cuts its line short, as the
# shell reads it and never reaches the tool; bytes past the cap are not read. Nothing read from the
# file is printed. The link, file-type and path checks are not atomic with the open, so they are not
# the boundary: the line grammar is. Then the tool is given a ruleset this script builds from its
# own literals plus the checked tokens, on standard input, never the file.
#
# nft: the file must hold exactly the ruleset the plugin generates (nft_ruleset_text): thirteen
# fixed lines in order, rule lines only in the input and output chains, nothing after the closing
# brace. A rule line is `iif lo accept` (input), `oif lo accept` (output), the neighbour-discovery
# line, or
#   [ip|ip6 saddr|daddr <address>] (meta l4proto tcp|udp | [P sport <port>] [P dport <port>])
#       [tcp flags & (syn|ack) != syn] accept
# with one protocol P per line, the flags only with tcp, `ip` only with an IPv4 address and `ip6`
# only with an IPv6 one. nft is run as `nft -f /dev/stdin`.
#
# pf: the file must hold exactly the anchor ruleset the plugin generates (pf_anchor_ruleset). Lines
# 1 to 3 are `no nat all`, `no rdr all` and `pass quick on lo0 all no state`; then rule lines; the
# last line is `block drop quick all`, with nothing after it. A rule line is one of
#   pass quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } no state
#   pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 keep state
#   pass in quick inet proto udp from any port 67 to any port 68 keep state
#   pass out quick <fam> proto tcp from any to <address> port <port> no state
#   pass in quick <fam> proto tcp from <address> port <port> to any no state
#   pass out quick <fam> proto tcp|udp from any to <address> [port <port>] keep state
#   pass in quick <fam> proto tcp|udp from <address> to any [port <port>] keep state
# where <fam> is `inet` only with an IPv4 address and `inet6` only with an IPv6 one, and <address>
# and <port> are as above. Every line is rebuilt from the literals plus the checked tokens and must
# equal the input line character for character. pfctl is run as
# `pfctl -a com.apple/000.yuzu_quarantine -f /dev/stdin`; the anchor name is this script's literal.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
IPT=/usr/sbin/iptables
IP6T=/usr/sbin/ip6tables
NFT=/usr/sbin/nft
PFCTL=/sbin/pfctl
PF_ANCHOR=com.apple/000.yuzu_quarantine
# No pathname expansion and a single-space field separator before any word split below.
set -f
IFS=' '
nl='
'
ND_RULE='icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept'
PF_ND='pass quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } no state'
PF_DHCP_OUT='pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 keep state'
PF_DHCP_IN='pass in quick inet proto udp from any port 67 to any port 68 keep state'

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

# is_octet TOKEN: one IPv4 part: 1 to 3 digits, no leading zero unless the token is 0, at most 255.
is_octet() {
    case $1 in
        0) return 0 ;;
        '' | 0* | *[!0123456789]*) return 1 ;;
    esac
    case ${#1} in
        1 | 2) return 0 ;;
        3) [ "$1" -le 255 ] ;;
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
            case $pre in 0?*) return 1 ;; esac
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
        *.*.*.*)
            o1=${addr_part%%.*}
            rest=${addr_part#*.}
            o2=${rest%%.*}
            rest=${rest#*.}
            o3=${rest%%.*}
            o4=${rest#*.}
            is_octet "$o1" && is_octet "$o2" && is_octet "$o3" && is_octet "$o4" || return 1
            lim=32
            ;;
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

# want LITERAL: the current input line ($line) is exactly LITERAL. The literal, never the input's
# own bytes, is the next line of the text the tool is given.
want() {
    tok_is "$line" "$1" || refuse
    out_text=$out_text$1$nl
}

# nft_rule CHAIN RULE: RULE (a line without its four-space indent) is a rule the plugin emits into
# CHAIN, input or output. Sets rule_out to the rule rebuilt from literals plus the validated
# address and ports, and succeeds only when that is RULE character for character.
nft_rule() {
    rule=$2
    case $rule in
        'iif lo accept')
            [ "$1" = input ] || return 1
            rule_out='iif lo accept'
            return 0
            ;;
        'oif lo accept')
            [ "$1" = output ] || return 1
            rule_out='oif lo accept'
            return 0
            ;;
        "$ND_RULE")
            rule_out=$ND_RULE
            return 0
            ;;
    esac
    r_fam=
    r_dir=
    r_addr=
    r_proto=
    r_sport=
    r_dport=
    r_flags=
    set -- $rule
    [ $# -ge 1 ] || return 1
    case $1 in
        ip | ip6)
            [ $# -ge 3 ] || return 1
            case $1 in
                ip) r_fam=ip ;;
                *) r_fam=ip6 ;;
            esac
            case $2 in
                saddr) r_dir=saddr ;;
                daddr) r_dir=daddr ;;
                *) return 1 ;;
            esac
            is_addr "$3" || return 1
            case $r_fam in
                ip)
                    case $3 in
                        *:*) return 1 ;;
                    esac
                    ;;
                *)
                    case $3 in
                        *:*) ;;
                        *) return 1 ;;
                    esac
                    ;;
            esac
            r_addr=$3
            shift 3
            ;;
    esac
    [ $# -ge 3 ] || return 1
    case $1 in
        meta)
            tok_is "$2" l4proto || return 1
            case $3 in
                tcp) r_proto=tcp ;;
                udp) r_proto=udp ;;
                *) return 1 ;;
            esac
            shift 3
            ;;
        tcp | udp)
            case $1 in
                tcp) r_proto=tcp ;;
                *) r_proto=udp ;;
            esac
            if tok_is "$2" sport; then
                is_port "$3" || return 1
                r_sport=$3
                shift 3
                if [ $# -ge 3 ] && tok_is "$1" "$r_proto" && tok_is "$2" dport; then
                    is_port "$3" || return 1
                    r_dport=$3
                    shift 3
                fi
            elif tok_is "$2" dport; then
                is_port "$3" || return 1
                r_dport=$3
                shift 3
            else
                return 1
            fi
            ;;
        *) return 1 ;;
    esac
    if [ $# -eq 7 ]; then
        tok_is "$r_proto" tcp || return 1
        tok_is "$1 $2 $3 $4 $5 $6" 'tcp flags & (syn|ack) != syn' || return 1
        r_flags=1
        shift 6
    fi
    [ $# -eq 1 ] || return 1
    tok_is "$1" accept || return 1
    rule_out=
    [ -z "$r_fam" ] || rule_out="$r_fam $r_dir $r_addr "
    if [ -n "$r_sport$r_dport" ]; then
        [ -z "$r_sport" ] || rule_out="$rule_out$r_proto sport $r_sport "
        [ -z "$r_dport" ] || rule_out="$rule_out$r_proto dport $r_dport "
    else
        rule_out="${rule_out}meta l4proto $r_proto "
    fi
    [ -z "$r_flags" ] || rule_out="${rule_out}tcp flags & (syn|ack) != syn "
    rule_out="${rule_out}accept"
    [ "$rule_out" = "$rule" ]
}

# nft_rule_line CHAIN: the current input line ($line) is an indented rule of CHAIN.
nft_rule_line() {
    case $line in
        '    '*) ;;
        *) refuse ;;
    esac
    nft_rule "$1" "${line#    }" || refuse
    out_text=$out_text'    '$rule_out$nl
}

# nft_apply: reads ALL of standard input (the staged file, already capped by the caller) and checks
# it line by line against the ruleset the plugin generates. Only when the whole input passed does
# it give nft the text built by want / nft_rule_line, on standard input: never a stream of the
# file. It always ends in exit, with nft's status or 64.
nft_apply() {
    out_text=
    nft_n=
    st=1
    line=
    while IFS= read -r line; do
        nft_n=${nft_n}x
        [ "${#nft_n}" -le 512 ] || refuse
        [ "${#line}" -le 512 ] || refuse
        case $st in
            1) want 'table inet yuzu_quarantine {}'; st=2 ;;
            2) want 'flush table inet yuzu_quarantine'; st=3 ;;
            3) want 'table inet yuzu_quarantine {'; st=4 ;;
            4) want '  chain input {'; st=5 ;;
            5) want '    type filter hook input priority -100; policy drop;'; st=6 ;;
            6)
                if tok_is "$line" '  }'; then
                    want '  }'
                    st=7
                else
                    nft_rule_line input
                fi
                ;;
            7) want '  chain output {'; st=8 ;;
            8) want '    type filter hook output priority -100; policy drop;'; st=9 ;;
            9)
                if tok_is "$line" '  }'; then
                    want '  }'
                    st=10
                else
                    nft_rule_line output
                fi
                ;;
            10) want '  chain forward {'; st=11 ;;
            11) want '    type filter hook forward priority -100; policy drop;'; st=12 ;;
            12) want '  }'; st=13 ;;
            13) want '}'; st=14 ;;
            *) refuse ;;
        esac
    done
    # The loop body does not run for a last line with no newline, but read leaves its text in $line.
    [ -z "$line" ] || refuse
    [ "$st" = 14 ] || refuse
    printf '%s' "$out_text" | "$NFT" -f /dev/stdin
    exit $?
}

# pf_rule: the current input line ($line) is a rule line the plugin emits into the pf anchor. Sets
# rule_out to the line rebuilt from the script's literals plus the validated address and port, and
# succeeds only when that is $line character for character. The parse below is permissive on
# purpose (it only has to find the tokens); the comparison at the end is the check.
pf_rule() {
    case $line in
        "$PF_ND" | "$PF_DHCP_OUT" | "$PF_DHCP_IN")
            rule_out=$line
            return 0
            ;;
    esac
    set -- $line
    [ $# -ge 12 ] || return 1
    tok_is "$1" pass || return 1
    case $2 in
        out) p_dir=out ;;
        in) p_dir=in ;;
        *) return 1 ;;
    esac
    tok_is "$3" quick || return 1
    case $4 in
        inet) p_fam=inet ;;
        inet6) p_fam=inet6 ;;
        *) return 1 ;;
    esac
    tok_is "$5" proto || return 1
    case $6 in
        tcp) p_proto=tcp ;;
        udp) p_proto=udp ;;
        *) return 1 ;;
    esac
    tok_is "$7" from || return 1
    shift 7
    [ $# -ge 5 ] || return 1
    p_port=
    case $p_dir in
        out)
            tok_is "$1" any || return 1
            tok_is "$2" to || return 1
            is_addr "$3" || return 1
            p_addr=$3
            shift 3
            ;;
        *)
            is_addr "$1" || return 1
            p_addr=$1
            shift 1
            if tok_is "$1" port; then
                is_port "$2" || return 1
                p_port=$2
                shift 2
            fi
            [ $# -ge 2 ] || return 1
            tok_is "$1" to || return 1
            tok_is "$2" any || return 1
            shift 2
            ;;
    esac
    # An optional port here: after the destination (out) or after `to any` (in, no port before it).
    if [ -z "$p_port" ] && [ $# -ge 2 ] && tok_is "$1" port; then
        is_port "$2" || return 1
        p_port=$2
        shift 2
    fi
    [ $# -eq 2 ] || return 1
    tok_is "$2" state || return 1
    case $1 in
        keep) p_mode=keep ;;
        no) p_mode=no ;;
        *) return 1 ;;
    esac
    # `inet` goes with an IPv4 literal and `inet6` with an IPv6 one (is_addr admitted only those).
    case $p_addr in
        *:*)
            tok_is "$p_fam" inet6 || return 1
            ;;
        *)
            tok_is "$p_fam" inet || return 1
            ;;
    esac
    # The stateless control-channel form is TCP with a port; nothing else is `no state`.
    if tok_is "$p_mode" no; then
        tok_is "$p_proto" tcp || return 1
        [ -n "$p_port" ] || return 1
    fi
    rule_out="pass $p_dir quick $p_fam proto $p_proto from "
    case $p_dir in
        out)
            rule_out="${rule_out}any to $p_addr"
            [ -z "$p_port" ] || rule_out="$rule_out port $p_port"
            ;;
        *)
            rule_out="${rule_out}$p_addr"
            if tok_is "$p_mode" no; then
                rule_out="$rule_out port $p_port to any"
            else
                rule_out="$rule_out to any"
                [ -z "$p_port" ] || rule_out="$rule_out port $p_port"
            fi
            ;;
    esac
    case $p_mode in
        no) rule_out="$rule_out no state" ;;
        *) rule_out="$rule_out keep state" ;;
    esac
    tok_is "$rule_out" "$line"
}

# pf_apply: reads ALL of standard input (the staged file, already capped by the caller) and checks
# it line by line against the anchor ruleset the plugin generates. Only when the whole input passed
# does it give pfctl the text built by want / pf_rule, on standard input: never a stream of the
# file. It always ends in exit, with pfctl's status or 64.
pf_apply() {
    out_text=
    pf_n=
    st=1
    line=
    while IFS= read -r line; do
        pf_n=${pf_n}x
        [ "${#pf_n}" -le 512 ] || refuse
        [ "${#line}" -le 512 ] || refuse
        case $st in
            1) want 'no nat all'; st=2 ;;
            2) want 'no rdr all'; st=3 ;;
            3) want 'pass quick on lo0 all no state'; st=4 ;;
            4)
                if tok_is "$line" 'block drop quick all'; then
                    want 'block drop quick all'
                    st=5
                else
                    pf_rule || refuse
                    out_text=$out_text$rule_out$nl
                fi
                ;;
            *) refuse ;;
        esac
    done
    # The loop body does not run for a last line with no newline, but read leaves its text in $line.
    [ -z "$line" ] || refuse
    [ "$st" = 5 ] || refuse
    printf '%s' "$out_text" | "$PFCTL" -a "$PF_ANCHOR" -f /dev/stdin
    exit $?
}

# staged_file PATH SUFFIX: PATH is the shape of a file the plugin staged (SUFFIX is `.nft` or
# `.pf`) and is neither a link nor a file that is not a regular one; sets `path`. Refuses
# otherwise. Never the boundary: a link or a non-regular file is refused here, but the file can
# change between these tests and the open the caller makes. The boundary is the caller's apply
# function, which reads the one opened file and gives the tool only text it built itself. A FIFO
# present at the tests is refused; a FIFO or device node put there after them is opened with
# whatever side effects opening it has, and a FIFO blocks the open until a writer appears.
staged_file() {
    path=$1
    sfx=$2
    case $path in
        /*) ;;
        *) refuse ;;
    esac
    [ "${#path}" -le 512 ] || refuse
    case $path in
        *[[:cntrl:]]*) refuse ;;
    esac
    dir=${path%/*}
    leaf=${path##*/}
    case $dir in
        */firewall-staging) ;;
        *) refuse ;;
    esac
    case $leaf in
        yuzu-fwq-*"$sfx") ;;
        *) refuse ;;
    esac
    mid=${leaf#yuzu-fwq-}
    mid=${mid%"$sfx"}
    case $mid in
        '' | *[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-]*) refuse ;;
    esac
    if [ -L "$path" ] || [ ! -f "$path" ]; then
        refuse
    fi
}

# nft_load PATH: yuzu-fw-helper nft load PATH. Never returns.
nft_load() {
    staged_file "$1" .nft
    # The cap, 512 x 512 + 1, bounds the read and is not a check: 512 full-length lines exceed it and
    # nft_apply refuses them. The largest ruleset the grammar accepts is 64512 bytes.
    head -c 262145 < "$path" | nft_apply
    exit $?
}

# pf_load PATH: yuzu-fw-helper pf load PATH. Never returns. The same cap and the same single open.
pf_load() {
    staged_file "$1" .pf
    head -c 262145 < "$path" | pf_apply
    exit $?
}

[ $# -ge 2 ] || refuse
case $1 in
    iptables) tool=$IPT ;;
    ip6tables) tool=$IP6T ;;
    nft)
        [ $# -eq 3 ] || refuse
        tok_is "$2" load || refuse
        nft_load "$3"
        refuse
        ;;
    pf)
        [ $# -eq 3 ] || refuse
        tok_is "$2" load || refuse
        pf_load "$3"
        refuse
        ;;
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

# ── The services helper ─────────────────────────────────────────────────────
#
# $SVC_HELPER_PATH, the one program the sudoers file lets the agent account run as root for
# services.set_start_mode. A POSIX sh script (valid under bash 3.2 as /bin/sh, dash and ash), the
# same prelude as the firewall helper, no eval and no shell on a token. Contract (the C++ twin is
# the builders in agents/plugins/services/src/services_parsers.hpp, and is_safe_service_name there
# is the character class below; tests/test_legacy_quarantine_plugin_removed_lexical.py runs this
# text against the same cases):
#   - exactly three arguments: a tool, a verb and a name. The name is 1 to 256 characters of
#     letters, digits and - _ . @, checked FIRST, with an enumerated `case` class, so nothing else
#     reaches an argument list.
#   - systemctl enable|disable|mask|unmask <unit>: the tool is /usr/bin/systemctl when it is
#     executable, else /bin/systemctl (the plugin's own order); each verb arm execs the tool with
#     its own literal verb, then `--`, then the name.
#   - launchctl enable|disable <label>: each arm execs /bin/launchctl with its own literal verb and
#     system/<label>.
#   - anything else exits 64 having run nothing. The caller's arguments are never passed on as a
#     list.

generate_svc_helper_content() {
    cat <<'YUZU_SVC_HELPER'
#!/bin/sh
# yuzu-svc-helper: the one program the Yuzu agent account may run as root for
# services.set_start_mode: systemctl enable|disable|mask|unmask on Linux, launchctl enable|disable
# on macOS. Installed by scripts/install-agent-user.sh on both platforms, root-owned 0755 (root:root
# on Linux, root:wheel on macOS), and named in /etc/sudoers.d/yuzu-agent with no argument and no
# wildcard. Do not edit by hand: the installer's --check compares this file with its own text. An
# action whose tool is not on the host fails at exec, having changed nothing.
#
# Usage: yuzu-svc-helper systemctl enable|disable|mask|unmask <unit>
#        yuzu-svc-helper launchctl enable|disable <label>
# Exactly three arguments. The third is 1 to 256 characters of letters, digits and - _ . @ (a
# leading - is allowed, which is why systemctl is given -- before it), checked before anything
# else. The caller's arguments are never passed on: each arm below execs the tool with an argument
# list made of its own literals plus that name. Anything else exits 64, having run nothing.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
# No pathname expansion and a single-space field separator before any word split below.
set -f
IFS=' '

refuse() {
    printf 'yuzu-svc-helper: refused\n' >&2
    exit 64
}

[ $# -eq 3 ] || refuse
case $3 in
    '' | *[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._@-]*) refuse ;;
esac
[ "${#3}" -le 256 ] || refuse

case $1 in
    systemctl)
        if [ -x /usr/bin/systemctl ]; then
            tool=/usr/bin/systemctl
        else
            tool=/bin/systemctl
        fi
        case $2 in
            enable) exec "$tool" enable -- "$3" ;;
            disable) exec "$tool" disable -- "$3" ;;
            mask) exec "$tool" mask -- "$3" ;;
            unmask) exec "$tool" unmask -- "$3" ;;
            *) refuse ;;
        esac
        ;;
    launchctl)
        case $2 in
            enable) exec /bin/launchctl enable "system/$3" ;;
            disable) exec /bin/launchctl disable "system/$3" ;;
            *) refuse ;;
        esac
        ;;
    *) refuse ;;
esac
refuse
YUZU_SVC_HELPER
}

# dir_info DIR: `<uid> <octal mode> <group>` of the directory itself (links followed). The stat form
# is chosen by platform, never by trying one and falling back to the other: on GNU stat, `-f` means
# file-system status and would answer, wrongly, with text.
dir_info() {
    if [[ "$PLATFORM" == "macos" ]]; then
        stat -L -f '%u %Lp %Sg' "$1"
    else
        stat -L -c '%u %a %G' "$1"
    fi
}

# file_owner_mode FILE: `<owner>:<group> <octal mode>` of the file itself, by the same rule.
file_owner_mode() {
    if [[ "$PLATFORM" == "macos" ]]; then
        stat -f '%Su:%Sg %Lp' "$1"
    else
        stat -c '%U:%G %a' "$1"
    fi
}

# fw_dir_verdict UID OCTAL_MODE: pure, no I/O. For the directory that holds a helper, with the
# owner uid and octal mode dir_info reports, prints ok, warn or refuse. refuse: the
# owner is not uid 0 or the mode has the other-write bit (anyone could replace the helper). warn: the
# mode has the group-write bit (Debian policy ships /usr/local directories root:staff 2775, so a
# flat refusal would stop the installer there). Anything that is not a uid and an octal mode refuses.
fw_dir_verdict() {
    case $2 in '' | *[!01234567]*) echo refuse; return ;; esac
    [ "$1" = 0 ] || { echo refuse; return; }
    if (( 8#$2 & 0002 )); then echo refuse; elif (( 8#$2 & 0020 )); then echo warn; else echo ok; fi
}

# check_helper_dir DIR: applies fw_dir_verdict to DIR as it is now. Prints the warning on warn and
# carries on (returns 0); returns non-zero on refuse or when the owner and mode cannot be read.
check_helper_dir() {
    local dir="$1" info uid mode grp
    info=$(dir_info "$dir" 2>/dev/null) || {
        warn "cannot read the owner and mode of $dir"
        return 1
    }
    read -r uid mode grp <<<"$info"
    case "$(fw_dir_verdict "$uid" "$mode")" in
        ok) return 0 ;;
        warn)
            warn "$dir is writable by group $grp (mode $mode): its members can replace the files in it, including the root-owned helpers"
            return 0
            ;;
        *)
            warn "$dir is owned by uid $uid with mode $mode: the root-owned helpers must live in a directory owned by root that other users cannot write to"
            return 1
            ;;
    esac
}

# install_helper PATH GENERATOR: writes the helper GENERATOR prints to PATH, root:$ROOT_GROUP 0755.
install_helper() {
    local path="$1" generator="$2"
    if [[ "$SKIP_SUDOERS" -eq 1 ]]; then return 0; fi

    local dir tmp
    dir=$(dirname "$path")
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would write the following to $path (root:$ROOT_GROUP 0755):"
        "$generator" | sed 's/^/[dry-run]   /'
        return 0
    fi

    log "installing the helper $path (root:$ROOT_GROUP 0755)"
    # Create the directory only when missing: never reset a site-customised owner or mode.
    [[ -d "$dir" ]] || run install -d -m 0755 -o root -g "$ROOT_GROUP" "$dir"
    # Stop before writing when anyone but root could replace the helper.
    check_helper_dir "$dir" || return 1
    # No sweep of earlier temp files: a killed run can leave one, a root-owned dotfile that nothing
    # runs (sudoers names only the exact helper path), and a concurrent run's live file has the same
    # name shape.
    # A temporary file in the SAME directory, so the final rename is atomic: sudo never sees a
    # half-written helper, and a failed write leaves the previous helper in place.
    tmp=$(mktemp "$dir/.$(basename "$path").XXXXXX") || { warn "cannot create a temp file in $dir"; return 1; }
    if ! "$generator" > "$tmp" \
        || ! chown "root:$ROOT_GROUP" "$tmp" \
        || ! chmod 0755 "$tmp" \
        || ! sh -n "$tmp" \
        || ! mv -f "$tmp" "$path"; then
        rm -f "$tmp"
        warn "could not install $path"
        return 1
    fi
}

# install_helpers: both helpers, before the sudoers file that names them. A failure of one does not
# stop the other; the return is non-zero when either failed, and the install then removes the
# sudoers file instead of writing it (the dispatch below).
install_helpers() {
    local rc=0
    install_helper "$FW_HELPER_PATH" generate_fw_helper_content || rc=1
    install_helper "$SVC_HELPER_PATH" generate_svc_helper_content || rc=1
    return "$rc"
}

remove_helpers() {
    local path
    for path in "$FW_HELPER_PATH" "$SVC_HELPER_PATH"; do
        if [[ -e "$path" ]]; then
            log "removing $path"
            run rm -f "$path"
        fi
    done
}

# check_helper PATH GENERATOR: the helper is present, root:$ROOT_GROUP 0755 and byte-identical to
# the text GENERATOR prints. Returns non-zero on any drift.
check_helper() {
    local path="$1" generator="$2"
    if [[ ! -f "$path" ]]; then
        warn "$path is missing (re-run this installer)"
        return 1
    fi
    check_helper_dir "$(dirname "$path")" || return 1
    local owner_mode
    owner_mode=$(file_owner_mode "$path" 2>/dev/null || true)
    if [[ "$owner_mode" != "root:$ROOT_GROUP 755" ]]; then
        warn "$path is ${owner_mode:-unreadable}, expected root:$ROOT_GROUP 755"
        return 1
    fi
    if ! "$generator" | cmp -s - "$path"; then
        warn "$path differs from this installer's text (re-run this installer)"
        return 1
    fi
    log "$path present, root:$ROOT_GROUP 0755, content current"
    return 0
}

check_helpers() {
    local rc=0
    check_helper "$FW_HELPER_PATH" generate_fw_helper_content || rc=1
    check_helper "$SVC_HELPER_PATH" generate_svc_helper_content || rc=1
    return "$rc"
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
        owner=$(file_owner_mode "$dir" 2>/dev/null || true)
        owner=${owner%%:*}
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
        if [[ ! -f "$SUDOERS_FILE" ]]; then
            warn "$SUDOERS_FILE is missing"; ((errs++))
        elif [[ ! -r "$SUDOERS_FILE" ]]; then
            log "$SUDOERS_FILE present but not readable by $(id -un)"
            log "  (mode 0440 root:wheel/root is correct; rerun --check as root to validate; the content check was skipped)"
        else
            if ! visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1; then
                warn "$SUDOERS_FILE fails visudo validation"; ((errs++))
            else
                log "$SUDOERS_FILE present and visudo-valid"
                # A valid file is not the file this installer writes: a hand edit that still
                # validates (an added grant) must not pass --check, as a changed helper does not.
                if generate_sudoers_content | cmp -s - "$SUDOERS_FILE"; then
                    log "$SUDOERS_FILE content current"
                else
                    warn "$SUDOERS_FILE differs from this installer's text (re-run this installer)"
                    ((errs++))
                fi
            fi
        fi
    fi

    # 4. the two helpers the sudoers file names: owner, mode and content
    if [[ "$SKIP_SUDOERS" -eq 0 ]]; then
        check_helpers || ((errs++))
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
        # The helpers go in BEFORE the sudoers file that names them, and the file is written only
        # when both are in: a grant that names a path with nothing root-owned behind it is worse
        # than no grant. When a helper fails (install_helpers has said why) the file is removed,
        # earlier lines included, and the run fails at the end. Both helpers share one directory
        # per platform, so a refused directory fails both.
        helper_rc=0
        sudoers_rc=0
        if install_helpers; then
            install_sudoers || sudoers_rc=$?
        else
            helper_rc=1
            remove_sudoers
        fi
        apply_setcap
        if [[ "$helper_rc" -ne 0 ]]; then
            if [[ -e "$SUDOERS_FILE" ]]; then
                fail "a root-owned helper was not installed and $SUDOERS_FILE could not be removed: remove it by hand, correct the helper directory and re-run this installer"
            fi
            fail "a root-owned helper was not installed, so $SUDOERS_FILE was removed: until the helper directory is corrected (owned by root, not writable by all users) and this installer is re-run, every sudo-backed action fails on a non-root agent, firewall containment and services.set_start_mode included"
        fi
        if [[ "$sudoers_rc" -ne 0 ]]; then
            warn "$SUDOERS_FILE was not installed (status $sudoers_rc); removing any earlier file so no old grant stays"
            remove_sudoers
            if [[ -e "$SUDOERS_FILE" ]]; then
                warn "$SUDOERS_FILE could not be removed: remove it by hand"
            fi
            exit "$sudoers_rc"
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
        remove_helpers
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
