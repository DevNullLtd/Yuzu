#!/bin/bash
# Copy the firmware DMI table and SMBIOS entry point into <state-dir>/dmi so the
# unprivileged agent can read them. Run as root by an ExecStartPre line in
# yuzu-agent.service (the sources under /sys/firmware are root-only).
#
# Usage: yuzu-agent-dmi-snapshot.sh STATE_DIR USER [SRC]
#   STATE_DIR  agent-writable state directory (the snapshot goes in STATE_DIR/dmi)
#   USER       the agent service account
#   SRC        optional source directory, default /sys/firmware/dmi/tables
#              (exists so tests can point at fixture files; only root edits the unit)
#
# Security model: root only READS. Every create, write, rename and remove inside
# STATE_DIR is done as USER via runuser, because that directory is writable by the
# agent: a root write there could be redirected through a planted symlink. This
# script never chowns, chmods or writes a STATE_DIR path as root.
#
# All-or-none: both files are written into a fresh STATE_DIR/dmi.tmp (directory 0700,
# files 0600) and published with one atomic directory rename, so a reader sees the
# whole pair or nothing. An interruption leaves at most dmi.tmp, which the unit's
# pre-clean and the next run remove. On any failure there is no snapshot.
#
# Always exits 0 so a missing snapshot never blocks the agent from starting. Output
# is one stderr line per failure and never contains table bytes or serial numbers.

set -u -o pipefail

state=${1:-}
user=${2:-}
src=${3:-/sys/firmware/dmi/tables}

if [ -z "$state" ] || [ -z "$user" ]; then
    echo "yuzu-agent-dmi-snapshot: usage: STATE_DIR USER [SRC]" >&2
    exit 0
fi

dest="$state/dmi"
tmp="$state/dmi.tmp"

if ! command -v runuser >/dev/null 2>&1; then
    echo "yuzu-agent-dmi-snapshot: runuser not found; no hardware table snapshot" >&2
    exit 0
fi

as_user() { runuser -u "$user" -- "$@"; }

# Positional paths are passed as arguments to sh -c, never interpolated.
# shellcheck disable=SC2016 # the single-quoted script is meant for the inner shell
remove() { as_user /bin/sh -c 'rm -rf "$@"' sh "$@" >/dev/null 2>&1 || true; }

# shellcheck disable=SC2016 # the single-quoted script is meant for the inner shell
if ! as_user /bin/sh -c 'umask 077 && rm -rf "$1" "$2" && mkdir "$2"' sh "$dest" "$tmp"; then
    echo "yuzu-agent-dmi-snapshot: cannot create $tmp as $user; no hardware table snapshot" >&2
    remove "$tmp"
    exit 0
fi

for name in smbios_entry_point DMI; do
    # -f/-r first: cat on a FIFO or other non-regular source would block.
    if [ ! -f "$src/$name" ] || [ ! -r "$src/$name" ]; then
        echo "yuzu-agent-dmi-snapshot: $src/$name is not a readable file; no hardware table snapshot" >&2
        remove "$tmp" "$dest"
        exit 0
    fi
    # cat to EOF: sysfs binary files report size 0, so a size-based copy would be empty.
    # shellcheck disable=SC2016 # the single-quoted script is meant for the inner shell
    if ! cat "$src/$name" | as_user /bin/sh -c 'umask 077 && cat > "$1"' sh "$tmp/$name"; then
        echo "yuzu-agent-dmi-snapshot: copying $name failed; no hardware table snapshot" >&2
        remove "$tmp" "$dest"
        exit 0
    fi
done

if ! as_user mv -T "$tmp" "$dest"; then
    echo "yuzu-agent-dmi-snapshot: publishing the snapshot failed; no hardware table snapshot" >&2
    remove "$tmp" "$dest"
    exit 0
fi

exit 0
