#!/usr/bin/env bash
# ensure-gcovr.sh -- make `gcovr` available for the /test coverage gate, installing it if missing.
#
# Called by /test Phase 0b (default and --full modes) next to ensure-puppeteer.sh. Before this
# existed a missing gcovr made scripts/test/coverage-gate.sh record WARN ("gcovr missing"), and its
# own hint (`pip3 install --user gcovr`) fails on a distro Python marked externally managed
# (PEP 668). pipx is the install route that works there.
#
# The version is read from requirements-ci.in so a local run measures with the gcovr that CI
# uses; a different major/minor can change the reported percentages. Idempotent: a matching
# install only verifies.
#
# Linux only: coverage-gate.sh refuses to measure anywhere else (the baseline is Linux/gcc data,
# #6187), so on another OS this exits 0 with a note rather than installing something unused.
#
# Exit 0 = ready (or not applicable). Exit 1 = could not make it ready; the last line says why.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
say() { printf 'ensure-gcovr: %s\n' "$*"; }
die() { printf 'ensure-gcovr: NOT READY: %s\n' "$*" >&2; exit 1; }

if [[ "$(uname -s)" != "Linux" ]]; then
    say "not Linux; the coverage gate does not measure here, nothing to install"
    exit 0
fi

pin="$(sed -n 's/^gcovr==\([0-9][0-9.]*\).*/\1/p' "$ROOT/requirements-ci.in" | head -n1)"
[[ -n "$pin" ]] || die "no gcovr== pin found in requirements-ci.in"

installed_version() {
    command -v gcovr >/dev/null 2>&1 || return 1
    gcovr --version 2>/dev/null | sed -n 's/^gcovr \([0-9][0-9.]*\).*/\1/p' | head -n1
}

have="$(installed_version || true)"
if [[ "$have" == "$pin" ]]; then
    say "gcovr ${pin} already installed"
    exit 0
fi
[[ -n "$have" ]] && say "gcovr ${have} is installed but CI pins ${pin}; installing ${pin}"

if command -v pipx >/dev/null 2>&1; then
    say "installing gcovr==${pin} with pipx"
    pipx install --force "gcovr==${pin}" \
        || die "pipx could not install gcovr==${pin}; check network access to PyPI"
else
    die "pipx is not on PATH; install it (apt install pipx) and re-run, or install gcovr==${pin} yourself"
fi

# pipx puts the shim in ~/.local/bin, which a non-login shell may not have on PATH.
export PATH="$HOME/.local/bin:$PATH"
have="$(installed_version || true)"
[[ "$have" == "$pin" ]] || die "gcovr ${pin} installed but 'gcovr --version' reports '${have:-nothing}'; is ~/.local/bin on PATH?"
say "ready (gcovr ${pin})"
