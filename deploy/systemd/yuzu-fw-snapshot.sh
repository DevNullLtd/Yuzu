#!/bin/sh
# yuzu-fw-snapshot.sh: the read-only host firewall snapshot behind yuzu-fw-snapshot.socket.
#
# systemd starts it as root for each connection to the socket (yuzu-fw-snapshot@.service), with
# standard input /dev/null and standard output the connection; the Yuzu agent connects, sends
# nothing and reads to end of stream. The contract is docs/adr/3007-os-activated-read-helpers.md:
#   - It takes no input. Nothing is read from the connection, the environment or any argument: it
#     is a fixed list of three commands, each with its literal absolute path and literal arguments,
#     under a reset PATH and locale. Any argument at all is refused (nothing printed, exit 64).
#   - It changes no ruleset and writes no file. It reads two kernel rulesets, one reader each: the
#     nf_tables ruleset with `nft -a list ruleset`, and the legacy xtables tables of each family with
#     that family's legacy save tool under its own name (`iptables-legacy-save`,
#     `ip6tables-legacy-save`), which lists every instantiated table, loads no module and takes no
#     lock. It prints each under a `== <label>` heading. `[absent]` is the nft tool not installed,
#     so that section was not read. `[failed]` is a line of its own after the output of a tool that
#     exits non-zero, and the whole section of one that could not be tried. A legacy family with no
#     save tool prints `[tables]` and then the kernel's own list of its instantiated tables (see
#     snap_xt). The whole reply is cut at 1 MiB and ends with `== end`, so a reply that was cut has
#     no end line and the reader treats it as unknown. One side effect is measured and stays: an nft
#     read on a host where nf_tables is not loaded makes the kernel load it.
#   - The agent unit (NoNewPrivileges, one capability) never changes: this program returns data,
#     it is not a way for the agent to gain anything.
# The assignments and the three functions below are the root helper's `snapshot` word
# (scripts/install-agent-user.sh), byte for byte; tests/test_legacy_quarantine_plugin_removed_lexical.py
# pins that, and runs this file under every shell with stub tools.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
NFT=/usr/sbin/nft
XT4=/usr/sbin/iptables-legacy-save
XT6=/usr/sbin/ip6tables-legacy-save

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

# snap_xt LABEL TOOL NAMES: a legacy xtables section, read by the family's legacy save tool under
# its own name, with no argument. That tool lists every instantiated table, loads no kernel module,
# runs no modprobe and takes no lock; empty output with exit 0 is a family that holds no table, and
# a non-zero exit is a failure (`[failed]` through snap_one). Two decisions are made here, before
# any tool runs, from host state and never from input. If /proc/net cannot be stat'ed the process
# cannot see the kernel's tables at all, and a save tool reads a missing table list as no table, so
# the section is `[failed]` and no tool is run. If the family has no save tool, nothing here can
# list its tables; the kernel's own list of them is printed under `[tables]`, which is the names
# file NAMES, present exactly while the family's core module is loaded. `[tables]` alone says the
# family holds no table; `[tables]` and a name say tables exist that nothing listed, and the reader
# treats them as unread. NAMES that cannot be stat'ed is read as no table (behind the /proc/net
# check above, which rules out every cause at directory level); a name list that cannot be read is
# `[failed]`. No file is created.
snap_xt() {
    if [ ! -e /proc/net/dev ]; then
        printf '== %s\n\n[failed]\n' "$1"
        return 0
    fi
    if [ -x "$2" ]; then
        snap_one "$1" "$2"
        return 0
    fi
    printf '== %s\n[tables]\n' "$1"
    [ ! -e "$3" ] || head -c 4096 "$3" 2>/dev/null || printf '\n[failed]\n'
}

# host_snapshot: yuzu-fw-helper snapshot. Never returns. The group is cut at 1 MiB, so a listing
# that was cut has no end line.
host_snapshot() {
    {
        snap_one 'nft -a list ruleset' "$NFT" -a list ruleset
        snap_xt 'iptables-legacy-save' "$XT4" /proc/net/ip_tables_names
        snap_xt 'ip6tables-legacy-save' "$XT6" /proc/net/ip6_tables_names
        printf '== end\n'
    } | head -c 1048576
    exit 0
}

# No argument is accepted: a bare call is the only call.
[ $# -eq 0 ] || exit 64
host_snapshot
