#!/usr/bin/env bash
# ensure-gcovr.sh -- make `gcovr` available for the /test coverage gate, installing it if missing.
#
# Called by /test Phase 0b (default and --full modes) next to ensure-puppeteer.sh. Before this
# existed a missing gcovr made scripts/test/coverage-gate.sh record WARN ("gcovr missing"), and its
# own hint (`pip3 install --user gcovr`) fails on a distro Python marked externally managed
# (PEP 668).
#
# READY means: the `gcovr` that the CALLER's PATH resolves to -- the same lookup
# scripts/test/coverage-gate.sh does, with no PATH fix-up here -- reports the version pinned in
# requirements-ci.in. A gcovr you already have at that version (a distro package, your own install)
# is accepted and left alone: this script only installs when there is none, or when it is a
# different version. If the gcovr in use is the one THIS script manages, it must also be healthy
# (its dependencies import) and built from the current requirements-ci.txt.
#
# INTEGRITY of what this script installs: gcovr is installed the way CI installs it --
# `pip install --require-hashes` from the hash-pinned requirements-ci.txt -- into a private
# virtualenv, so gcovr AND every transitive dependency is verified against the committed hashes, not
# just the top-level version. The venv also receives the other packages in requirements-ci.txt
# (meson, ...); they stay inside the venv and only the single `gcovr` symlink below is put on PATH.
# (A gcovr you installed yourself is, by definition, not verified by this script.)
#
# Where it writes (the only changes this script makes):
#   $YUZU_GCOVR_VENV   default ~/.local/share/yuzu/gcovr-venv   the virtualenv (+ a .lock beside it)
#   ~/.local/bin/gcovr a symlink to the venv's gcovr (replaces an existing symlink there, e.g. a
#                      pipx shim; refuses to replace a regular file)
# pip may also write its own cache under ~/.cache/pip.
#
# RECOVERY / SAFETY: a rebuild MOVES the old venv aside (one atomic rename) before building, then
# removes the moved copy, so an interrupt can never leave a half-deleted directory at $VENV that
# the delete guard would then refuse; a half-BUILT venv carries a marker written before venv creation,
# so the next run recognises and replaces it. The guard refuses to touch a $VENV that is neither
# ours nor empty. The install takes an exclusive lock (when `flock` exists) so two worktrees cannot
# rebuild the same venv under each other, and pip runs under a timeout (when `timeout` exists).
#
# Linux only: coverage-gate.sh refuses to measure anywhere else (the baseline is Linux/gcc data,
# #6187), so on another OS this exits 0 with a note rather than installing something unused.
#
# Exit 0 = ready (or not applicable). Exit 1 = could not make it ready; the last line says why.
set -euo pipefail

say() { printf 'ensure-gcovr: %s\n' "$*"; }
die() { printf 'ensure-gcovr: NOT READY: %s\n' "$*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PIP_TIMEOUT=600
MARKER=".yuzu-gcovr-venv"

if [[ "$(uname -s)" != "Linux" ]]; then
    say "not Linux; the coverage gate does not measure here, nothing to install"
    exit 0
fi

[[ -n "${HOME:-}" ]] || die "HOME is not set"
VENV="${YUZU_GCOVR_VENV:-$HOME/.local/share/yuzu/gcovr-venv}"
LINK="$HOME/.local/bin/gcovr"

# tmo SECONDS CMD...: run CMD under `timeout` when it exists.
tmo() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@" || { local rc=$?; [[ $rc -eq 124 ]] && say "timed out after ${secs}s: $1 $2"; return $rc; }
    else
        "$@"
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

# Returns 0 when nothing needs doing; prints why.
already_ready() {
    [[ "$(resolved_version)" == "$pin" ]] || return 1
    if ours; then
        venv_fresh && venv_healthy || return 1
        say "gcovr ${pin} already installed (${VENV})"
    else
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
command -v python3 >/dev/null 2>&1 || die "python3 is not on PATH"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "python3 $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])') is older than 3.10, which the pinned gcovr and meson require; run this with a python3 3.10 or newer first on PATH (docs/rhel9-build-setup.md covers RHEL9)"
# `python3 -m venv --help` succeeds on Debian/Ubuntu even without python3-venv; ensurepip is what is missing.
python3 -c 'import ensurepip' >/dev/null 2>&1 \
    || die "python3 cannot create virtualenvs (the ensurepip module is missing); install it (Debian/Ubuntu: apt install python3-venv)"

mkdir -p "$(dirname "$VENV")" "$(dirname "$LINK")" || die "cannot create $(dirname "$VENV") or $(dirname "$LINK")"

# One build at a time per venv path; the venv is shared by every worktree. After taking the lock,
# look again: another run may just have finished the same job.
if command -v flock >/dev/null 2>&1; then
    exec 9>"$VENV.lock" || die "cannot open $VENV.lock"
    flock -w "$PIP_TIMEOUT" 9 || die "timed out waiting for another ensure-gcovr run (lock: $VENV.lock)"
    if already_ready; then
        exit 0
    fi
fi

owned() { [[ -f "$1/pyvenv.cfg" || -f "$1/$MARKER" ]]; }
empty_dir() { [[ -d "$1" && -z "$(ls -A "$1" 2>/dev/null)" ]]; }

# Leftovers of an interrupted rebuild (the moved-aside copy): ours by name, and removed only if they
# are recognisably a venv of ours.
for old in "$VENV".old.*; do
    if [[ -d "$old" ]] && owned "$old"; then rm -rf "$old"; fi
done

if [[ -e "$VENV" ]]; then
    if ! owned "$VENV" && ! empty_dir "$VENV"; then
        die "refusing to replace $VENV: it is not a virtualenv of this script (no pyvenv.cfg or ${MARKER}); point YUZU_GCOVR_VENV at an unused path"
    fi
    # Atomic: after this rename $VENV does not exist, and the old tree is deleted afterwards. A kill
    # during the delete leaves only a recognisable $VENV.old.* directory, never a half-deleted $VENV.
    mv "$VENV" "$VENV.old.$$" || die "cannot move $VENV aside"
fi

say "installing gcovr==${pin} with hashes from requirements-ci.txt into ${VENV}"
mkdir -p "$VENV" || die "cannot create $VENV"
# The marker goes in BEFORE venv creation, so a build killed at any later point is recognisably ours.
: > "$VENV/$MARKER" || die "cannot write to $VENV"
python3 -m venv "$VENV" || die "could not create the virtualenv at $VENV"
tmo "$PIP_TIMEOUT" "$VENV/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
    -r "$ROOT/requirements-ci.txt" \
    || die "pip could not install requirements-ci.txt with hashes (see the pip error above); the usual causes are no network access to PyPI or a python3 older than the pinned packages support"
# The stamp is written only after pip succeeded, so a half-built venv never reads as fresh.
printf '%s\n' "$req_sha" > "$STAMP" || die "cannot write $STAMP"
for old in "$VENV".old.*; do
    if [[ -d "$old" ]] && owned "$old"; then rm -rf "$old"; fi
done
ln -sfn "$VENV/bin/gcovr" "$LINK" || die "cannot link $LINK"

# Verify with the caller's PATH, exactly as coverage-gate.sh will look it up. No PATH fix-up here.
if ! command -v gcovr >/dev/null 2>&1; then
    die "gcovr ${pin} is installed and linked at $LINK, but $(dirname "$LINK") is not on PATH; add it to PATH (a fresh login shell picks it up if the directory existed at login)"
fi
got="$(resolved_version)"
[[ "$got" == "$pin" ]] \
    || die "gcovr ${pin} is installed, but PATH resolves 'gcovr' to $(command -v gcovr), which reports '${got:-nothing}'; remove or reorder that entry"
say "ready (gcovr ${pin})"
