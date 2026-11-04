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
#   $YUZU_GCOVR_VENV   default ~/.local/share/yuzu/gcovr-venv   the virtualenv, plus beside it
#                      <venv>.lock and, transiently, <venv>.old.<pid>; ~/.local/share/yuzu is created
#   ~/.local/bin/gcovr a symlink to the venv's gcovr (replaces an existing symlink there, e.g. a
#                      pipx shim; refuses to replace a regular file)
# pip may also write its own cache under ~/.cache/pip.
#
# RECOVERY / SAFETY: a rebuild MOVES the old venv aside (one atomic rename) before building, then
# removes the moved copy, so an interrupt can never leave a half-deleted directory at $VENV; a
# half-BUILT venv carries a marker written before venv creation, so the next run recognises and
# replaces it, and a leftover <venv>.old.<pid> is removed by name. The delete guard refuses to touch a
# $VENV that is not this script's own (it must carry the marker file or the requirements stamp this
# script writes) unless it is empty: a plain Python venv of yours, such as a project .venv, is never
# taken for ours. A managed venv that is fresh and healthy is not rebuilt just because something else
# shadows it on PATH. The install holds an exclusive lock (when `flock` exists; the lock file is opened
# for append, never through a symlink, and only in a directory you own) so two worktrees cannot
# rebuild the same venv under each other; pip runs under a timeout (when `timeout` or `gtimeout`
# exists; YUZU_ENSURE_PIP_TIMEOUT / YUZU_ENSURE_LOCK_TIMEOUT override, in seconds), and the lock
# descriptor is closed for every child process.
#
# Linux only: coverage-gate.sh refuses to measure anywhere else (the baseline is Linux/gcc data,
# #6187), so on another OS this exits 0 with a note rather than installing something unused.
#
# Exit 0 = ready (or not applicable). Exit 1 = could not make it ready; the last line says why.
set -euo pipefail

say() { printf 'ensure-gcovr: %s\n' "$*"; }
die() { printf 'ensure-gcovr: NOT READY: %s\n' "$*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PIP_TIMEOUT="${YUZU_ENSURE_PIP_TIMEOUT:-600}"
LOCK_TIMEOUT="${YUZU_ENSURE_LOCK_TIMEOUT:-1200}"
MARKER=".yuzu-gcovr-venv"

if [[ "$(uname -s)" != "Linux" ]]; then
    say "not Linux; the coverage gate does not measure here, nothing to install"
    exit 0
fi

[[ -n "${HOME:-}" ]] || die "HOME is not set"
VENV="${YUZU_GCOVR_VENV:-$HOME/.local/share/yuzu/gcovr-venv}"
LINK="$HOME/.local/bin/gcovr"

# tmo SECONDS CMD...: run CMD under a timeout when one exists, with the lock descriptor (9) closed
# for the child.
tmo() {
    local secs="$1" t=""
    shift
    if command -v timeout >/dev/null 2>&1; then
        t=timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        t=gtimeout
    fi
    if [[ -n "$t" ]]; then
        "$t" -k 10 "$secs" "$@" 9>&- || { local rc=$?; [[ $rc -eq 124 ]] && say "timed out after ${secs}s: ${1:-} ${2:-}"; return $rc; }
    else
        "$@" 9>&-
    fi
}

pin="$(sed -n 's/^gcovr==\([0-9][0-9.]*\).*/\1/p' "$ROOT/requirements-ci.in" | head -n1)"
[[ -n "$pin" ]] || die "no gcovr== pin found in requirements-ci.in"
[[ -f "$ROOT/requirements-ci.txt" ]] || die "requirements-ci.txt is missing; this checkout is incomplete"
grep -q -E "^gcovr==${pin}( |\\\\|$)" "$ROOT/requirements-ci.txt" \
    || die "requirements-ci.txt does not pin gcovr==${pin} (it must agree with requirements-ci.in)"
req_sha="$(sha256sum "$ROOT/requirements-ci.txt" | cut -d' ' -f1)" || die "cannot hash requirements-ci.txt"
[[ -n "$req_sha" ]] || die "cannot hash requirements-ci.txt"

# What the caller's PATH resolves gcovr to, and its version. Both empty when it is not found.
resolved_real() { local p; p="$(command -v gcovr 2>/dev/null)" || return 1; readlink -f "$p"; }
resolved_version() { gcovr --version 2>/dev/null | sed -n 's/^gcovr \([0-9][0-9.]*\).*/\1/p' | head -n1 || true; }
ours() { [[ "$(resolved_real || true)" == "$(readlink -f "$VENV/bin/gcovr" 2>/dev/null || true)" ]]; }

STAMP="$VENV/.requirements-ci.sha256"
venv_fresh() { [[ "$(cat "$STAMP" 2>/dev/null || true)" == "$req_sha" ]]; }
# gcovr's own import can succeed with a dependency missing; --html (which the coverage gate uses)
# then fails late. Import what the gate needs.
venv_healthy() { "$VENV/bin/python" -c 'import gcovr, jinja2, lxml, pygments, yaml' >/dev/null 2>&1; }
venv_version() { "$VENV/bin/gcovr" --version 2>/dev/null | sed -n 's/^gcovr \([0-9][0-9.]*\).*/\1/p' | head -n1 || true; }
# The managed venv is complete: right version, built from the current requirements, imports work.
managed_ok() { [[ "$(venv_version)" == "$pin" ]] && venv_fresh && venv_healthy; }

# Can the gcovr on PATH produce the reports coverage-gate.sh asks for? Run it on an empty tree in a
# scratch directory. A gcovr with its dependencies missing passes --version and fails here.
gcovr_works() {
    local d rc=0
    d="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_gcovr_probe.XXXXXX")" || return 1
    ( cd "$d" && tmo 60 gcovr --root . --json-summary j.json --xml x.xml --html --html-details -o i.html . ) >/dev/null 2>&1 || rc=$?
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

if [[ -e "$LINK" && ! -L "$LINK" ]]; then
    die "$LINK exists and is not a symlink; move it aside so the pinned gcovr can be linked there"
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
    exec 9>>"$VENV.lock" || die "cannot open $VENV.lock"
    flock -w "$LOCK_TIMEOUT" 9 || die "timed out waiting for another ensure-gcovr run (lock: $VENV.lock)"
    if already_ready; then
        exit 0
    fi
fi

# A directory is ours only if it carries what THIS script writes: the marker (written before venv
# creation) or the requirements stamp (written after a successful install). A bare pyvenv.cfg is NOT
# enough -- any Python virtualenv, including a project's own .venv, has one.
owned() { [[ -f "$1/$MARKER" || -f "$1/.requirements-ci.sha256" ]]; }
empty_dir() { [[ -d "$1" && -z "$(ls -A "$1" 2>/dev/null)" ]]; }
# Moved-aside leftovers are ours by NAME: <venv>.old.<digits>, never a symlink.
remove_leftovers() {
    local old
    for old in "$VENV".old.*; do
        [[ -d "$old" && ! -L "$old" && "$old" =~ \.old\.[0-9]+$ ]] || continue
        rm -rf "$old"
    done
}
remove_leftovers

if managed_ok; then
    # Only the PATH order (or the link) is wrong; rebuilding would change nothing.
    say "the managed venv at ${VENV} is complete; (re)linking it"
else
    if [[ -e "$VENV" ]]; then
        if ! owned "$VENV" && ! empty_dir "$VENV"; then
            die "refusing to replace $VENV: it is not a virtualenv of this script (no ${MARKER} or requirements stamp); point YUZU_GCOVR_VENV at an unused path"
        fi
        # Atomic: after this rename $VENV does not exist, and the old tree is deleted afterwards. A kill
        # during the delete leaves only a <venv>.old.<pid> directory, never a half-deleted $VENV.
        mv "$VENV" "$VENV.old.$$" || die "cannot move $VENV aside"
    fi

    say "installing gcovr==${pin} with hashes from requirements-ci.txt into ${VENV}"
    mkdir -p "$VENV" || die "cannot create $VENV"
    # The marker goes in BEFORE venv creation, so a build killed at any later point is recognisably ours.
    : > "$VENV/$MARKER" || die "cannot write to $VENV"
    python3 -m venv "$VENV" || die "could not create the virtualenv at $VENV"
    tmo "$PIP_TIMEOUT" "$VENV/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
        -r "$ROOT/requirements-ci.txt" \
        || die "pip could not install requirements-ci.txt with hashes (see the pip error above); the usual causes are no network access to PyPI, or a hash-pinned wheel that is not available for this platform"
    # The stamp is written only after pip succeeded, so a half-built venv never reads as fresh.
    printf '%s\n' "$req_sha" > "$STAMP" || die "cannot write $STAMP"
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
