#!/bin/sh
# yuzu-fw-snapshot.sh: the read-only host firewall snapshot behind yuzu-fw-snapshot.socket.
#
# systemd starts it as root for each connection to the socket (yuzu-fw-snapshot@.service), with
# standard input /dev/null and standard output the connection; the Yuzu agent connects, sends
# nothing and reads to end of stream. The contract is docs/adr/3007-os-activated-read-helpers.md:
#   - It takes no input. Nothing is read from the connection, the environment or any argument: it
#     is a fixed list of three commands, each with its literal absolute path and literal arguments,
#     under a reset PATH and locale. Any argument at all is refused (nothing printed, exit 64).
#   - It changes nothing. It only runs `nft -a list ruleset`, `iptables -S` and `ip6tables -S` and
#     prints each under a `== <label>` heading: `[absent]` for a tool that is not installed, a
#     `[failed]` line of its own after the output of one that exits non-zero, and `[unloaded]`
#     (the tool is not run) for a legacy iptables or ip6tables whose kernel module is not loaded,
#     so the family holds no rule (snap_ipt below says how that is known). The whole reply is
#     cut at 1 MiB and ends with `== end`, so a reply that was cut has no end line and the reader
#     treats it as unknown.
#   - The agent unit (NoNewPrivileges, one capability) never changes: this program returns data,
#     it is not a way for the agent to gain anything.
# The assignments and the three functions below are the root helper's `snapshot` word
# (scripts/install-agent-user.sh), byte for byte; tests/test_legacy_quarantine_plugin_removed_lexical.py
# pins that, and runs this file under every shell with stub tools.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
IPT=/usr/sbin/iptables
IP6T=/usr/sbin/ip6tables
NFT=/usr/sbin/nft

# snap_one LABEL TOOL ARGS: one section of the snapshot. Reads only: the tool is run with the
# fixed arguments the caller of this function names, and its standard error is dropped. A failed
# tool's marker is written after a newline, so it is a line of its own even when the tool died in
# the middle of one (a reader that matches the whole line `[failed]` then always sees it).
snap_one() {
    printf '== %s\n' "$1"
    snap_tool=$2
    shift 2
    if [ ! -x "$snap_tool" ]; then
        printf '[absent]\n'
        return 0
    fi
    "$snap_tool" "$@" 2>/dev/null || printf '\n[failed]\n'
}

# snap_ipt LABEL TOOL NAMES: the iptables and ip6tables sections, `-S` being the tool's only
# argument. A legacy xtables tool whose core kernel module is not loaded runs modprobe itself, which
# this service may not do (no CAP_SYS_MODULE, ProtectKernelModules): it exits non-zero having
# printed nothing, while the same word run by an unconfined root would load the module. That is
# decided here, before the tool runs and not from how it fails, so no module is loaded and no tool
# output has to be trusted as empty. The section is the header and `[unloaded]`, and the tool is not
# run, only when all four hold: the tool is installed; it is the legacy multi-call binary (the same
# file, so the nft shim, an older or a moved binary never qualifies); the process can see /proc/net
# (its device list is there); and NAMES, the family's table list under /proc/net, is not. That file
# exists exactly while the family's core module is loaded, so without it the family holds no rule.
# Anything else is snap_one, which is unchanged: a tool that runs and fails is still `[failed]`.
snap_ipt() {
    if [ -x "$2" ] && [ "$2" -ef /usr/sbin/xtables-legacy-multi ] && [ -e /proc/net/dev ] && [ ! -e "$3" ]; then
        printf '== %s\n[unloaded]\n' "$1"
        return 0
    fi
    snap_one "$1" "$2" -S
}

# host_snapshot: yuzu-fw-helper snapshot. Never returns. The group is cut at 1 MiB, so a listing
# that was cut has no end line.
host_snapshot() {
    {
        snap_one 'nft -a list ruleset' "$NFT" -a list ruleset
        snap_ipt 'iptables -S' "$IPT" /proc/net/ip_tables_names
        snap_ipt 'ip6tables -S' "$IP6T" /proc/net/ip6_tables_names
        printf '== end\n'
    } | head -c 1048576
    exit 0
}

# No argument is accepted: a bare call is the only call.
[ $# -eq 0 ] || exit 64
host_snapshot
