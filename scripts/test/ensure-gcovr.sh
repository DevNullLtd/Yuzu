#!/usr/bin/env bash
# ensure-gcovr.sh -- make `gcovr` available for the /test coverage gate, installing it if missing.
#
# Called by /test Phase 0b (default and --full modes) next to ensure-puppeteer.sh. Before this
# existed a missing gcovr made scripts/test/coverage-gate.sh record WARN ("gcovr missing"), and its
# own hint (`pip3 install --user gcovr`) fails on a distro Python marked externally managed
# (PEP 668).
#
# INTEGRITY: gcovr is installed the way CI installs it -- `pip install --require-hashes` from the
# hash-pinned requirements-ci.txt -- into a private virtualenv, so gcovr AND every transitive
# dependency is verified against the committed hashes, not just the top-level version. (A bare
# `pipx install gcovr==X` pins only X; its dependencies float and are unhashed.) The venv also
# receives the other packages in requirements-ci.txt (meson, ...); they are installed into the venv
# only and nothing outside it is put on PATH except the single `gcovr` symlink below.
#
# Where things go (the only changes this script makes):
#   $YUZU_GCOVR_VENV   default ~/.local/share/yuzu/gcovr-venv   the virtualenv
#   ~/.local/bin/gcovr a symlink to the venv's gcovr (replaces an existing symlink there, e.g. a
#                      pipx shim; refuses to replace a regular file)
# pip may also write its own cache under ~/.cache/pip.
#
# "Ready" means the `gcovr` that the CALLER's PATH resolves to IS the venv's gcovr at the pinned
# version -- the same lookup scripts/test/coverage-gate.sh does -- so a recorded PASS cannot coexist
# with the gate warning "gcovr missing", or with an older gcovr earlier on PATH doing the measuring.
# The version pin is read from requirements-ci.in. Idempotent: a ready install only verifies.
#
# Linux only: coverage-gate.sh refuses to measure anywhere else (the baseline is Linux/gcc data,
# #6187), so on another OS this exits 0 with a note rather than installing something unused.
#
# Exit 0 = ready (or not applicable). Exit 1 = could not make it ready; the last line says why.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV="${YUZU_GCOVR_VENV:-$HOME/.local/share/yuzu/gcovr-venv}"
LINK="$HOME/.local/bin/gcovr"
say() { printf 'ensure-gcovr: %s\n' "$*"; }
die() { printf 'ensure-gcovr: NOT READY: %s\n' "$*" >&2; exit 1; }

if [[ "$(uname -s)" != "Linux" ]]; then
    say "not Linux; the coverage gate does not measure here, nothing to install"
    exit 0
fi

pin="$(sed -n 's/^gcovr==\([0-9][0-9.]*\).*/\1/p' "$ROOT/requirements-ci.in" | head -n1)"
[[ -n "$pin" ]] || die "no gcovr== pin found in requirements-ci.in"
[[ -f "$ROOT/requirements-ci.txt" ]] || die "requirements-ci.txt is missing; this checkout is incomplete"
grep -q -E "^gcovr==${pin}( |\\\\|$)" "$ROOT/requirements-ci.txt" \
    || die "requirements-ci.txt does not pin gcovr==${pin} (it must agree with requirements-ci.in)"

# What the caller's PATH resolves gcovr to, and its version. Both empty when it is not found.
resolved_real() { local p; p="$(command -v gcovr 2>/dev/null)" || return 1; readlink -f "$p"; }
resolved_version() { gcovr --version 2>/dev/null | sed -n 's/^gcovr \([0-9][0-9.]*\).*/\1/p' | head -n1; }

ours() { [[ "$(resolved_real || true)" == "$(readlink -f "$VENV/bin/gcovr" 2>/dev/null || true)" ]]; }

if ours && [[ "$(resolved_version)" == "$pin" ]]; then
    say "gcovr ${pin} already installed (${VENV})"
    exit 0
fi

if [[ -e "$LINK" && ! -L "$LINK" ]]; then
    die "$LINK exists and is not a symlink; move it aside so the pinned gcovr can be linked there"
fi

python3 -m venv --help >/dev/null 2>&1 \
    || die "python3 cannot create virtualenvs; install the venv module (apt install python3-venv)"

mkdir -p "$(dirname "$VENV")" "$(dirname "$LINK")"
venv_version="$("$VENV/bin/gcovr" --version 2>/dev/null | sed -n 's/^gcovr \([0-9][0-9.]*\).*/\1/p' | head -n1 || true)"
if [[ "$venv_version" == "$pin" ]]; then
    say "the venv at ${VENV} already has gcovr ${pin}; linking it"
else
    say "installing gcovr==${pin} with hashes from requirements-ci.txt into ${VENV}"
    rm -rf "$VENV"
    python3 -m venv "$VENV" || die "could not create the virtualenv at $VENV"
    "$VENV/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
        -r "$ROOT/requirements-ci.txt" \
        || die "pip could not install requirements-ci.txt with hashes; check network access to PyPI"
fi
ln -sfn "$VENV/bin/gcovr" "$LINK"

# Verify with the caller's PATH, exactly as coverage-gate.sh will look it up. No PATH fix-up here.
if ! command -v gcovr >/dev/null 2>&1; then
    die "gcovr ${pin} is installed and linked at $LINK, but $(dirname "$LINK") is not on PATH; add it to PATH"
fi
ours || die "gcovr ${pin} is installed, but PATH resolves 'gcovr' to $(command -v gcovr), not $LINK; remove or reorder that entry"
[[ "$(resolved_version)" == "$pin" ]] || die "installed gcovr reports '$(resolved_version)', expected ${pin}"
say "ready (gcovr ${pin})"
