#!/usr/bin/env bash
# ensure-gcovr.sh -- make `gcovr` available for the /test coverage gate, installing it if missing.
#
# Called by /test Phase 0b (default and --full modes), and again right before the coverage gate in
# Phase 7b, next to ensure-puppeteer.sh. Before this existed a missing gcovr made
# scripts/test/coverage-gate.sh record WARN ("gcovr missing"), and its former hint
# (`pip3 install --user gcovr`) fails on a distro Python marked externally managed (PEP 668).
#
# READY means: the `gcovr` that the CALLER's PATH resolves to -- the same lookup
# scripts/test/coverage-gate.sh does, with no PATH fix-up here -- reports the version pinned in
# requirements-ci.in. A gcovr you already have at that version (a distro package, your own install)
# is accepted and left alone, provided it can actually produce the reports the gate asks for (a
# probe run in an empty temp directory: --json-summary, --xml, --html --html-details); this script
# only installs when there is none, or when it is a different version or cannot do that. If the gcovr
# in use is the one THIS script manages, it must also be healthy (its dependencies import) and built
# from the current requirements-ci.txt.
#
# INTEGRITY of what this script installs: gcovr is installed with the same hash-pinned file CI uses
# -- `pip install --require-hashes -r requirements-ci.txt` (CI installs it with --user; here it goes
# into a private virtualenv) -- so gcovr AND every transitive dependency is verified against the
# committed hashes, not just the top-level version. The venv also receives the other packages in
# requirements-ci.txt (meson, ...); they stay inside the venv and only the single `gcovr` symlink
# below is put on PATH. A gcovr you installed yourself is, by definition, not verified by this script.
#
# Where it writes (the only changes this script makes):
#   $YUZU_GCOVR_VENV   default ~/.local/share/yuzu/gcovr-venv   the virtualenv (an ABSOLUTE path with no
#                      `.` or `..` segment), plus beside it <venv>.lock and, transiently, a fresh
#                      <venv>.yuzu-gcovr-old.XXXXXX directory made by mktemp; ~/.local/share/yuzu is created
#   ~/.local/bin/gcovr a symlink to the venv's gcovr. An existing link there is replaced ONLY when it
#                      already points into this venv (compared after resolving `.` and `..` and a
#                      relative target against the link's directory); a link to anything else (a pipx
#                      shim, another install, a sibling venv) and a regular file are refused, with the
#                      command to run yourself
# pip may also write its own cache under ~/.cache/pip.
#
# OWNERSHIP: the script deletes or moves a directory only when it can show the directory is its own.
# That takes a marker or a stamp it wrote, WITH its exact content, and a layout a venv has: the marker file
# `.yuzu-gcovr-venv` holds exactly the line `yuzu-gcovr-venv v1` and nothing else (byte for byte: a trailing
# space, a second newline or NUL padding fails), the stamp `.requirements-ci.sha256` holds exactly one
# SHA-256 and a newline, and every top-level entry is one a venv of this script has (bin, lib, lib64,
# include, share, pyvenv.cfg, .gitignore -- Python 3.13+ writes one -- and the two ownership files). A file
# named like a marker in a directory of yours does not make it ours, and neither does a copied marker next
# to your own files: a directory with any other top-level entry is refused and named. There is no weaker
# tier: a marker without the token (an empty file, as an earlier build of this branch wrote) is NOT accepted,
# so the one thing a user-planted file could satisfy is gone; such a directory is refused and the message
# gives the command to remove it by hand. The entries are read with ONE helper (list_entries: a bash glob
# with dotglob and nullglob, no `find -printf`, no process substitution), and any failure to read a directory
# means "not ours", never "no entries". The same rule decides every question below: replacing $VENV,
# sweeping leftovers, removing a half-built venv.
#
# RECOVERY / SAFETY: a rebuild MOVES the old venv aside (one atomic rename) before building, then removes
# the moved copy, so an interrupt can never leave a half-deleted directory at $VENV. The aside name comes
# from `mktemp -d` (a NEW empty directory beside the venv, so a foreign directory or a symlink can never
# be at that name) and the venv is renamed over it with `mv -T` (GNU mv; never INTO it); the inode of the
# old venv is noted first. If the rebuild FAILS (pip, a timeout, Ctrl-C, a signal), the half-built venv
# this run created (owned by the rule above, or empty) is removed and the previous venv is moved BACK, but
# only after checking that what stands at the aside name still has that inode, i.e. is the very directory
# this run moved; a second Ctrl-C or TERM during the restore is ignored so it cannot abort it. A transient
# PyPI failure therefore does not cost you a working gcovr. A kill -9 or a power cut cannot run that code,
# and the next run then rebuilds. A half-BUILT venv carries the marker written before venv creation, so the
# next run recognises and replaces it. A leftover <venv>.yuzu-gcovr-old.* is removed only when it is owned
# by the rule above (the contents go first and the ownership files last, so a kill part-way still leaves it
# recognisable) or is empty; any other directory of that name is left alone and named once. A box with no
# `flock` gives two runs no mutual exclusion, so one can sweep the other's leftovers; that is accepted
# (flock exists on every Linux this runs on). The delete guard refuses to touch a $VENV that is not owned
# unless it is empty: a plain Python venv of yours, such as a project .venv, is never taken for ours. A
# managed venv that is fresh and healthy is not rebuilt just because something else shadows it on PATH. The
# install holds an exclusive lock (when `flock` exists; the lock file is opened for append, never through a
# symlink, and only in a directory you own) so two worktrees cannot rebuild the same venv under each other;
# pip runs under a timeout (when `timeout` or `gtimeout` exists; YUZU_ENSURE_PIP_TIMEOUT /
# YUZU_ENSURE_LOCK_TIMEOUT override, in seconds). The lock descriptor is closed for every PROBE child
# (version checks, the capability probe), so a leaked probe cannot keep it; the install steps (python3 -m
# venv, pip) keep it on purpose, so an orphaned install makes the next run wait for it instead of racing it.
#
# Linux only: coverage-gate.sh refuses to measure anywhere else (the baseline is Linux/gcc data,
# #6187), so on another OS this exits 0 with a note rather than installing something unused.
#
# Exit 0 = ready (or not applicable). Exit 1 = could not make it ready; the LAST line printed says why,
# even when a failed rebuild put the previous venv back (that notice comes first, then the cause again).
set -euo pipefail

say() { printf 'ensure-gcovr: %s\n' "$*"; }
# The cause is kept so the restore trap can print it AGAIN after its own notices: the last line of the log
# is what /test records as the gate's note.
DIE_MSG=""
die() { DIE_MSG="ensure-gcovr: NOT READY: $*"; printf '%s\n' "$DIE_MSG" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PIP_TIMEOUT="${YUZU_ENSURE_PIP_TIMEOUT:-600}"
LOCK_TIMEOUT="${YUZU_ENSURE_LOCK_TIMEOUT:-1200}"
MARKER=".yuzu-gcovr-venv"
OWN_TOKEN="yuzu-gcovr-venv v1"   # the whole content of the marker file
STAMPNAME=".requirements-ci.sha256"

if [[ "$(uname -s)" != "Linux" ]]; then
    say "not Linux; the coverage gate does not measure here, nothing to install"
    exit 0
fi

[[ -n "${HOME:-}" ]] || die "HOME is not set"
[[ "$HOME" == /* ]] || die "HOME must be an absolute path (it is '$HOME'); a relative one would make the gcovr link dangle"
case "/$HOME/" in
    */./*|*/../*) die "HOME ($HOME) must not contain a '.' or '..' path segment; the gcovr virtualenv and link are placed under it" ;;
esac
VENV="${YUZU_GCOVR_VENV:-${HOME%/}/.local/share/yuzu/gcovr-venv}"
while [[ "$VENV" == */ && "$VENV" != "/" ]]; do VENV="${VENV%/}"; done
[[ -n "$VENV" && "$VENV" != "/" ]] || die "YUZU_GCOVR_VENV must not be empty or /"
[[ "$VENV" == /* ]] || die "YUZU_GCOVR_VENV must be an absolute path (it is '$VENV'); a relative one is resolved against whatever directory this runs in and would leave the gcovr link dangling"
case "/$VENV/" in
    */./*|*/../*) die "YUZU_GCOVR_VENV ($VENV) must not contain a '.' or '..' path segment; give the real directory" ;;
esac
[[ ! -L "$VENV" ]] || die "YUZU_GCOVR_VENV ($VENV) is a symlink; point it at the real directory"
LINK="${HOME%/}/.local/bin/gcovr"

# _timed KEEP_LOCK SECONDS CMD...: run CMD under a timeout when one exists (macOS has `gtimeout` only
# with coreutils installed). The timeout kills the whole process group, so no orphan outlives it; the
# price is that a Ctrl-C typed in a terminal waits for the current step to finish or time out (use
# `kill -TERM -<pgid>` to stop sooner). KEEP_LOCK=1 lets the child inherit the lock descriptor (an
# orphaned INSTALL then keeps other runs waiting for it, which is right); 0 closes it (probes must
# never hold the lock).
_timed() {
    local keep="$1" secs="$2" t=""
    shift 2
    if command -v timeout >/dev/null 2>&1; then
        t=timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        t=gtimeout
    fi
    if [[ -n "$t" ]]; then
        if [[ "$keep" == 1 ]]; then
            $t -k 10 "$secs" "$@" || { local rc=$?; [[ $rc -eq 124 ]] && say "timed out after ${secs}s: ${1:-} ${2:-}" >&2; return $rc; }
        else
            $t -k 10 "$secs" "$@" 9>&- || { local rc=$?; [[ $rc -eq 124 ]] && say "timed out after ${secs}s: ${1:-} ${2:-}" >&2; return $rc; }
        fi
    elif [[ "$keep" == 1 ]]; then
        "$@"
    else
        "$@" 9>&-
    fi
}
tmo()       { _timed 1 "$@"; }   # install steps
tmo_probe() { _timed 0 "$@"; }   # probes

pin="$(sed -n 's/^gcovr==\([0-9][0-9.]*\).*/\1/p' "$ROOT/requirements-ci.in" | head -n1)"
[[ -n "$pin" ]] || die "no gcovr== pin found in requirements-ci.in"
[[ -f "$ROOT/requirements-ci.txt" ]] || die "requirements-ci.txt is missing; this checkout is incomplete"
grep -q -E "^gcovr==${pin}( |\\\\|$)" "$ROOT/requirements-ci.txt" \
    || die "requirements-ci.txt does not pin gcovr==${pin} (it must agree with requirements-ci.in)"
req_sha="$(sha256sum "$ROOT/requirements-ci.txt" | cut -d' ' -f1)" || die "cannot hash requirements-ci.txt"
[[ -n "$req_sha" ]] || die "cannot hash requirements-ci.txt"

# What the caller's PATH resolves gcovr to, and its version. Both empty when it is not found.
resolved_real() { local p; p="$(command -v gcovr 2>/dev/null)" || return 1; readlink -f "$p"; }
resolved_version() { tmo_probe 20 gcovr --version 2>/dev/null | sed -n 's/^gcovr \([0-9][0-9.]*\).*/\1/p' | head -n1 || true; }
ours() { [[ "$(resolved_real || true)" == "$(readlink -f "$VENV/bin/gcovr" 2>/dev/null || true)" ]]; }

STAMP="$VENV/.requirements-ci.sha256"
venv_fresh() { [[ "$(cat "$STAMP" 2>/dev/null || true)" == "$req_sha" ]]; }
# gcovr's own import can succeed with a dependency missing; --html (which the coverage gate uses)
# then fails late. Import what the gate needs.
venv_healthy() { tmo_probe 30 "$VENV/bin/python" -c 'import gcovr, jinja2, lxml, pygments, yaml' >/dev/null 2>&1; }
venv_version() { tmo_probe 20 "$VENV/bin/gcovr" --version 2>/dev/null | sed -n 's/^gcovr \([0-9][0-9.]*\).*/\1/p' | head -n1 || true; }
# The managed venv is complete: right version, built from the current requirements, imports work.
managed_ok() { [[ "$(venv_version)" == "$pin" ]] && venv_fresh && venv_healthy; }

# Can the gcovr on PATH produce the reports coverage-gate.sh asks for? Run it on an empty tree in a
# scratch directory. A gcovr with its dependencies missing passes --version and fails here.
gcovr_works() {
    local d rc=0
    d="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_gcovr_probe.XXXXXX")" || return 1
    ( cd "$d" && tmo_probe 60 gcovr --root . --json-summary j.json --xml x.xml --html --html-details -o i.html . ) >/dev/null 2>&1 || rc=$?
    rm -rf "$d"
    return $rc
}

# Returns 0 when nothing needs doing; prints why.
already_ready() {
    [[ "$(resolved_version)" == "$pin" ]] || return 1
    if ours; then
        managed_ok || return 1
        say "gcovr ${pin} already installed (${VENV})"
    else
        gcovr_works || return 1
        say "using gcovr ${pin} found at $(command -v gcovr); it is not managed by this script, so its integrity is yours"
    fi
    return 0
}

if already_ready; then
    exit 0
fi

# What the ownership and move-aside logic below leans on; without one of them it could not tell what is its own.
for _tool in cmp find mktemp stat; do
    command -v "$_tool" >/dev/null 2>&1 || die "'$_tool' is not on PATH; this script needs cmp (diffutils), find (findutils), mktemp and stat (coreutils)"
done

if [[ -e "$LINK" && ! -L "$LINK" ]]; then
    die "$LINK exists and is not a symlink; move it aside so the pinned gcovr can be linked there"
fi
# A link there is replaced only when it already points into THIS venv. Compare where it points after
# resolving `.`/`..` and, for a relative target, against the link's own directory: a plain prefix test is
# bypassed by $VENV/../pipx/bin/gcovr, and a sibling venv2 must not pass for venv. Dangling is judged on the
# path alone (a dangling link into our own venv is replaced; one elsewhere is not). Anything else is
# somebody's: a pipx shim, a link to another install.
if [[ -L "$LINK" ]]; then
    link_target="$(readlink "$LINK" 2>/dev/null || true)"
    link_abs="$link_target"
    [[ "$link_abs" == /* ]] || link_abs="$(dirname "$LINK")/$link_abs"
    link_canon="$(readlink -m -- "$link_abs" 2>/dev/null || true)"
    venv_canon="$(readlink -m -- "$VENV" 2>/dev/null || true)"
    if [[ -z "$link_canon" || -z "$venv_canon" || "$link_canon" != "$venv_canon"/* ]]; then
        die "$LINK is a symlink to '${link_target}', not into this script's virtualenv ($VENV), so it was NOT replaced; if you want the pinned gcovr there, remove it yourself (rm '$LINK') and re-run, or put $VENV/bin ahead of it on PATH"
    fi
fi

# requirements-ci.txt pins gcovr 8.7, meson 1.12 and jsonschema 4.26, which all need Python 3.10+.
# Say so up front: otherwise an older interpreter (RHEL9's 3.9, Ubuntu 20.04's 3.8) reaches pip, which
# reports "no matching distribution", and the cause reads like a network problem.
if ! managed_ok; then
    command -v python3 >/dev/null 2>&1 || die "python3 is not on PATH"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
        || die "python3 $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])') is older than 3.10, which the pinned gcovr and meson require; run this with a python3 3.10 or newer first on PATH (for example a python3 symlink to python3.12 in a directory ahead of /usr/bin; docs/rhel9-build-setup.md covers RHEL9)"
    # `python3 -m venv --help` succeeds on Debian/Ubuntu even without python3-venv; ensurepip is what is missing.
    python3 -c 'import ensurepip' >/dev/null 2>&1 \
        || die "python3 cannot create virtualenvs (the ensurepip module is missing); install it (Debian/Ubuntu: apt install python3-venv)"
fi

mkdir -p "$(dirname "$VENV")" "$(dirname "$LINK")" || die "cannot create $(dirname "$VENV") or $(dirname "$LINK")"

# One build at a time per venv path; the venv is shared by every worktree. After taking the lock,
# look again: another run may just have finished the same job. The lock file is opened for APPEND
# (never truncated), only in a directory you own, and never through a symlink.
if command -v flock >/dev/null 2>&1; then
    [[ -O "$(dirname "$VENV")" ]] || die "$(dirname "$VENV") is not owned by you; refusing to put a lock file there"
    [[ ! -L "$VENV.lock" ]] || die "$VENV.lock is a symlink; refusing to use it as a lock file"
    [[ ! -e "$VENV.lock" || -f "$VENV.lock" ]] || die "$VENV.lock is not a regular file; refusing to use it as a lock file"
    exec 9>>"$VENV.lock" || die "cannot open $VENV.lock"
    flock -w "$LOCK_TIMEOUT" 9 || die "timed out waiting for another ensure-gcovr run (lock: $VENV.lock)"
    if already_ready; then
        exit 0
    fi
fi

# list_entries DIR: fill the array ENTRIES with the NAMES in DIR (dotfiles included, never . or ..). It is the
# ONE place a directory's contents are read for a decision (empty? a venv's layout?). Status 0 only when the
# directory could be read; anything else (not a directory, a link, no read or search permission) returns 1 with
# ENTRIES empty, and every caller reads that as "not ours" / "not empty", never as "no entries". A bash glob, on
# purpose: `find -printf` does not exist in BusyBox find, and a process substitution swallows the failure of the
# command inside it, which once made a failed enumeration look like an empty (so acceptable) directory. The
# shell options it sets are put back.
ENTRIES=()
list_entries() {
    local d="$1" i had_dot=0 had_null=0
    ENTRIES=()
    [[ -d "$d" && ! -L "$d" && -r "$d" && -x "$d" ]] || return 1
    shopt -q dotglob && had_dot=1
    shopt -q nullglob && had_null=1
    shopt -s dotglob nullglob
    ENTRIES=("$d"/*)
    (( had_dot )) || shopt -u dotglob
    (( had_null )) || shopt -u nullglob
    for ((i = 0; i < ${#ENTRIES[@]}; i++)); do ENTRIES[i]="${ENTRIES[i]##*/}"; done
    return 0
}
# Empty means a directory we could READ that has no entries.
empty_dir() { list_entries "$1" && (( ${#ENTRIES[@]} == 0 )); }

# The top-level entries a venv of this script has (see OWNERSHIP in the header). An exact comparison, not a
# substring test: a directory entry called "bin lib" must not pass. A directory that cannot be read has no
# known layout.
layout_ok() {
    local name allowed ok
    list_entries "$1" || return 1
    for name in ${ENTRIES[@]+"${ENTRIES[@]}"}; do
        ok=0
        for allowed in bin lib lib64 include share pyvenv.cfg .gitignore "$MARKER" "$STAMPNAME"; do
            [[ "$name" == "$allowed" ]] && { ok=1; break; }
        done
        [[ "$ok" == 1 ]] || return 1
    done
    return 0
}
# A regular file (never a link) whose bytes are EXACTLY "$2" followed by one newline: a trailing space, a
# second newline, NUL padding or more content all fail, and cmp stops at the first difference, so a user's huge
# file of that name is never read in full.
file_is() {
    [[ -f "$1" && ! -L "$1" ]] && cmp -s "$1" - <<< "$2" 2>/dev/null
}
# A stamp is exactly one lowercase SHA-256 and a newline, byte for byte.
stamp_ok() {
    local f="$1" h
    [[ -f "$f" && ! -L "$f" ]] || return 1
    h="$(head -c 64 "$f" 2>/dev/null)"
    [[ "$h" =~ ^[0-9a-f]{64}$ ]] && file_is "$f" "$h"
}
# owned DIR: DIR is a real directory (never a link), every top-level entry is one a venv has, and it carries this
# script's marker with its exact token and/or a stamp that is exactly a SHA-256. A marker or a stamp with any
# other content makes it not ours; so does a marker with no token at all (an empty file included).
owned() {
    local d="$1" token=0 stamp=0
    [[ -d "$d" && ! -L "$d" ]] || return 1
    layout_ok "$d" || return 1
    if [[ -e "$d/$MARKER" || -L "$d/$MARKER" ]]; then
        file_is "$d/$MARKER" "$OWN_TOKEN" || return 1
        token=1
    fi
    if [[ -e "$d/$STAMPNAME" || -L "$d/$STAMPNAME" ]]; then
        stamp_ok "$d/$STAMPNAME" || return 1
        stamp=1
    fi
    (( token || stamp ))
}
# remove_owned_tree DIR: delete a directory that is owned (checked again here). The contents go first and
# the two ownership files LAST, so a kill part-way leaves a tree that is still recognisably ours (rm -rf in
# one go could delete the marker first and strand an unidentifiable half-tree).
remove_owned_tree() {
    local d="$1"
    [[ -d "$d" && ! -L "$d" ]] || return 1
    owned "$d" || return 1
    find "$d" -mindepth 1 -maxdepth 1 ! -name "$MARKER" ! -name "$STAMPNAME" -exec rm -rf {} + || return 1
    rm -f "$d/$MARKER" "$d/$STAMPNAME" || return 1
    rmdir "$d"
}
# Leftovers live beside the venv as <venv>.yuzu-gcovr-old.<suffix>, but a name is not ownership: with
# YUZU_GCOVR_VENV pointing at a path of yours, an unrelated directory could be called that. So a leftover is
# removed only when it is owned (or empty); any other is left in place and named once. Never a symlink.
remove_leftovers() {
    local old loud="${1:-}"
    for old in "$VENV".yuzu-gcovr-old.*; do
        [[ -d "$old" && ! -L "$old" ]] || continue
        if owned "$old"; then
            remove_owned_tree "$old" || say "could not remove the leftover $old; remove it by hand (rm -rf) once you have checked it" >&2
        elif empty_dir "$old"; then
            rmdir "$old" 2>/dev/null || true
        elif [[ -n "$loud" ]]; then
            say "leaving $old alone: it is not known to be ours (no marker with this script's token, no SHA-256 stamp, or it holds entries a virtualenv does not); if it is a leftover of an interrupted run of this script, remove it by hand (rm -rf)" >&2
        fi
    done
}
remove_leftovers loud

# A failed rebuild gives the previous venv back. OLD_ASIDE is the directory mktemp made for it and ASIDE_INODE
# its inode as made; OLD_INODE is the venv's inode before it was renamed over OLD_ASIDE. Whether the venv WAS
# moved is decided from the disk, never from a flag set after the rename (a signal between the rename and such a
# flag would leave the old venv stranded): OLD_ASIDE is the old venv exactly when it is a real directory whose
# inode is OLD_INODE. The EXIT trap acts only on a non-zero exit, so a successful run, a refusal that happens
# before any rebuild, and the failures that come after the new venv is complete (OLD_ASIDE is cleared then)
# never restore. Positive evidence only: what stands at $VENV must be what THIS run started (owned, or empty) --
# never a symlink, never anything else; a directory mktemp made and nothing moved into is removed only while it
# is still empty and still has the inode it was made with. Every notice it prints goes before the cause, which is
# then printed again as the LAST line.
OLD_ASIDE=""
OLD_INODE=""
ASIDE_INODE=""
RESTORE_SAID=0
rsay() { RESTORE_SAID=1; say "$*" >&2; }
_restore_body() {
    local rc="$1" aside_now=""
    [[ -n "$OLD_ASIDE" && "$rc" -ne 0 ]] || return 0
    if [[ -d "$OLD_ASIDE" && ! -L "$OLD_ASIDE" ]]; then
        aside_now="$(stat -c %i "$OLD_ASIDE" 2>/dev/null || true)"
    fi
    if [[ -z "$OLD_INODE" || -z "$aside_now" || "$aside_now" != "$OLD_INODE" ]]; then
        # the old venv is not here: either it was never moved (the empty directory mktemp made, if it is still
        # that directory and still empty, is dropped; nothing else is touched), or what is here is no longer it
        if [[ -n "$aside_now" && "$aside_now" == "$ASIDE_INODE" ]] && empty_dir "$OLD_ASIDE"; then
            rmdir "$OLD_ASIDE" 2>/dev/null || true
        elif [[ -n "$OLD_INODE" ]]; then
            rsay "NOT restoring the previous virtualenv: $OLD_ASIDE is not the directory this run moved aside (it was replaced or changed); leaving it, and whatever is at $VENV, as they are"
        fi
        return 0
    fi
    if [[ -L "$VENV" ]]; then
        rsay "NOT restoring the previous virtualenv: $VENV is a symlink; it is at $OLD_ASIDE"
        return 0
    elif [[ -e "$VENV" ]]; then
        if owned "$VENV"; then
            remove_owned_tree "$VENV" || { rsay "could not remove the half-built virtualenv at $VENV; the previous one is left at $OLD_ASIDE"; return 0; }
        elif empty_dir "$VENV"; then
            rmdir "$VENV" || { rsay "could not remove the empty $VENV; the previous virtualenv is left at $OLD_ASIDE"; return 0; }
        else
            rsay "NOT restoring the previous virtualenv: $VENV is not what this run created; it is at $OLD_ASIDE"
            return 0
        fi
    fi
    if [[ -e "$VENV" || -L "$VENV" ]]; then
        rsay "NOT restoring the previous virtualenv: $VENV is still there; it is at $OLD_ASIDE"
    elif mv -T "$OLD_ASIDE" "$VENV"; then
        rsay "the rebuild failed; restored the previous virtualenv at $VENV"
    else
        rsay "the rebuild failed and the previous virtualenv could not be moved back; it is at $OLD_ASIDE"
    fi
}
restore_old_venv() {
    # The first thing it does, so a second Ctrl-C or TERM cannot abort the restore. (The exit status arrives as
    # $1, from the EXIT trap string, so nothing has to run before this line. The one residual: a signal that is
    # delivered before this single builtin executes still takes the default action.)
    trap '' INT TERM
    local rc="${1:-1}"
    trap - EXIT
    set +e
    _restore_body "$rc"
    # the cause last, after any notice of ours (the gate note is the last line of the log)
    if [[ "$RESTORE_SAID" == 1 && -n "$DIE_MSG" ]]; then
        printf '%s\n' "$DIE_MSG" >&2
    fi
    return 0
}

if managed_ok; then
    # Only the PATH order (or the link) is wrong; rebuilding would change nothing.
    say "the managed venv at ${VENV} is complete; (re)linking it"
else
    if [[ -e "$VENV" ]]; then
        if ! owned "$VENV" && ! empty_dir "$VENV"; then
            hint=""
            if [[ -e "$VENV/$MARKER" || -L "$VENV/$MARKER" ]] && ! file_is "$VENV/$MARKER" "$OWN_TOKEN"; then
                hint="; it has a '${MARKER}' file WITHOUT this script's token (an earlier build of this branch wrote it empty, and a file planted by somebody else looks the same), which is not accepted. If the directory is yours to delete, run: rm -rf '$VENV'  and re-run"
            fi
            die "refusing to replace $VENV: it is not known to be a virtualenv of this script (no marker with this script's exact token or SHA-256 stamp, or it holds entries a virtualenv does not, or it could not be read); point YUZU_GCOVR_VENV at an unused path, or if it is the leftover of an interrupted run of this script, remove it by hand (rm -rf) and re-run${hint}"
        fi
        # The EXIT/INT/TERM traps go in first, so a failure or a signal anywhere below puts it back. The
        # signal traps record the cause too, so the last line of the log names it.
        trap 'restore_old_venv $?' EXIT
        trap 'DIE_MSG="ensure-gcovr: NOT READY: interrupted (SIGINT)"; exit 130' INT
        trap 'DIE_MSG="ensure-gcovr: NOT READY: interrupted (SIGTERM)"; exit 143' TERM
        # A name that is certainly free and certainly ours: mktemp -d makes a NEW empty directory beside the
        # venv, so a foreign directory or a symlink can never be at that name. If something is anyway,
        # refuse before the old venv is touched. The venv is then renamed OVER that empty directory
        # (mv -T: never INTO it), after noting its inode so the restore can prove it is the same one.
        # Atomic: after the rename $VENV does not exist, and the old tree is deleted afterwards; a kill
        # during the delete leaves only a <venv>.yuzu-gcovr-old.* directory, never a half-deleted $VENV.
        aside="$(mktemp -d "$VENV.yuzu-gcovr-old.XXXXXX")" || die "cannot create a directory beside $VENV to move the old virtualenv into"
        # Recorded at once, so that ANY refusal below lets the restore drop the directory mktemp made (it does
        # so only while it still has this inode and is still empty; a foreign directory, a link or a file that
        # is somehow at this name is never touched).
        OLD_ASIDE="$aside"
        ASIDE_INODE="$(stat -c %i "$aside" 2>/dev/null || true)"
        if [[ -L "$aside" || ! -d "$aside" ]] || ! empty_dir "$aside"; then
            die "refusing to move $VENV aside: '$aside' is not a fresh empty directory, and the old virtualenv was left untouched"
        fi
        OLD_INODE="$(stat -c %i "$VENV" 2>/dev/null || true)"
        [[ -n "$OLD_INODE" ]] || die "cannot read the inode of $VENV"
        mv -T "$VENV" "$OLD_ASIDE" || die "cannot move $VENV aside"
    fi

    say "installing gcovr==${pin} with hashes from requirements-ci.txt into ${VENV}"
    mkdir -p "$VENV" || die "cannot create $VENV"
    # The marker goes in BEFORE venv creation, so a build killed at any later point is recognisably ours.
    printf '%s\n' "$OWN_TOKEN" > "$VENV/$MARKER" || die "cannot write to $VENV"
    tmo 300 python3 -m venv "$VENV" || die "could not create the virtualenv at $VENV"
    tmo "$PIP_TIMEOUT" "$VENV/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
        -r "$ROOT/requirements-ci.txt" \
        || die "pip could not install requirements-ci.txt with hashes (see the pip error above); the usual causes are no network access to PyPI, or a hash-pinned wheel that is not available for this platform"
    # The stamp is written only after pip succeeded, so a half-built venv never reads as fresh.
    printf '%s\n' "$req_sha" > "$STAMP" || die "cannot write $STAMP"
    # The new venv is complete: from here a failure (the link, PATH) must NOT give the old one back.
    OLD_ASIDE=""
    remove_leftovers
fi
ln -sfn "$VENV/bin/gcovr" "$LINK" || die "cannot link $LINK"

# Verify with the caller's PATH, exactly as coverage-gate.sh will look it up. No PATH fix-up here.
if ! command -v gcovr >/dev/null 2>&1; then
    die "gcovr ${pin} is installed and linked at $LINK, but $(dirname "$LINK") is not on PATH; add it (export PATH=\"\$HOME/.local/bin:\$PATH\"; a fresh login shell picks it up if the directory existed at login)"
fi
got="$(resolved_version)"
[[ "$got" == "$pin" ]] \
    || die "gcovr ${pin} is installed, but PATH resolves 'gcovr' to $(command -v gcovr), which reports '${got:-nothing}'; remove or reorder that entry"
# A same-version gcovr that shadows ours must still be able to produce the reports.
if ! ours && ! gcovr_works; then
    die "gcovr ${pin} is installed, but PATH resolves 'gcovr' to $(command -v gcovr), which reports ${pin} yet cannot produce the coverage reports; remove or reorder that entry"
fi
say "ready (gcovr ${pin})"
