#!/usr/bin/env bash
# ensure-puppeteer.sh -- make tests/puppeteer runnable, installing what is missing.
#
# Called by /test Phase 0 (default and --full modes) so the two headless-browser gates
# ("Puppeteer", "Browser smoke") always have something to run. Before this existed a missing
# `npm ci` recorded SKIP, and a gate that skips for want of a one-line install is a gate that
# silently stops protecting the dashboard. Idempotent: a second run on a ready box only
# verifies and exits 0.
#
# What "ready" means, each step proven rather than assumed:
#   1. node >= 22.12 and npm on PATH (the pinned puppeteer's floor).
#   2. tests/puppeteer/node_modules matches package-lock.json (`npm ci` otherwise).
#   3. A Chrome for Testing binary exists (`puppeteer browsers install chrome` otherwise).
#      PUPPETEER_EXECUTABLE_PATH, when set, is honoured and nothing is downloaded.
#   4. That browser actually LAUNCHES headless. A binary that is present but cannot start
#      (a missing shared library on a minimal Linux image is the usual cause) would otherwise
#      surface as a confusing failure deep inside the crawl.
#
# Exit 0 = ready. Exit 1 = not ready; the last line printed says what to do. Never prints
# credentials; makes no change outside tests/puppeteer/node_modules and the puppeteer cache.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PP="$ROOT/tests/puppeteer"
NODE_MIN_MAJOR=22
NODE_MIN_MINOR=12

say()  { printf 'ensure-puppeteer: %s\n' "$*"; }
die()  { printf 'ensure-puppeteer: NOT READY: %s\n' "$*" >&2; exit 1; }

command -v node >/dev/null 2>&1 || die "node is not on PATH; install Node ${NODE_MIN_MAJOR}.${NODE_MIN_MINOR} or newer"
command -v npm  >/dev/null 2>&1 || die "npm is not on PATH; it ships with Node"

node_ver="$(node --version)"
node_ver="${node_ver#v}"
node_major="${node_ver%%.*}"
rest="${node_ver#*.}"
node_minor="${rest%%.*}"
if (( node_major < NODE_MIN_MAJOR )) || { (( node_major == NODE_MIN_MAJOR )) && (( node_minor < NODE_MIN_MINOR )); }; then
    die "node ${node_ver} is older than ${NODE_MIN_MAJOR}.${NODE_MIN_MINOR}, which the pinned puppeteer requires"
fi
say "node ${node_ver}"

[[ -f "$PP/package-lock.json" ]] || die "$PP/package-lock.json is missing; this checkout is incomplete"

# --- 2. dependencies ----------------------------------------------------------------------
# npm ci writes node_modules/.package-lock.json; a lockfile newer than it means the install
# predates the pinned versions (a rebase moved the lock), so reinstall rather than trust it.
stale=0
if [[ ! -d "$PP/node_modules/puppeteer" ]]; then
    stale=1
elif [[ "$PP/package-lock.json" -nt "$PP/node_modules/.package-lock.json" ]]; then
    stale=1
fi
if (( stale )); then
    say "installing dependencies (npm ci) in tests/puppeteer"
    # Defer the browser download to step 3 so a failure there names itself. A caller who set
    # PUPPETEER_EXECUTABLE_PATH wants no download at all, which this also satisfies.
    ( cd "$PP" && PUPPETEER_SKIP_DOWNLOAD=1 npm ci --no-audit --no-fund ) \
        || die "npm ci failed in tests/puppeteer; check network access to the npm registry"
else
    say "dependencies already match package-lock.json"
fi

# --- 3. browser ---------------------------------------------------------------------------
# puppeteer resolves the path itself (cache dir, PUPPETEER_EXECUTABLE_PATH), so ask it rather
# than guessing where Chrome for Testing lives on this OS.
browser_present() {
    ( cd "$PP" && node --input-type=module -e "
        import puppeteer from 'puppeteer';
        import { existsSync } from 'node:fs';
        process.exit(existsSync(await puppeteer.executablePath()) ? 0 : 1);
    " ) >/dev/null 2>&1
}

if browser_present; then
    say "browser already present"
else
    if [[ -n "${PUPPETEER_EXECUTABLE_PATH:-}" ]]; then
        die "PUPPETEER_EXECUTABLE_PATH is set to '${PUPPETEER_EXECUTABLE_PATH}' but nothing is there"
    fi
    say "installing Chrome for Testing (npx puppeteer browsers install chrome)"
    ( cd "$PP" && npx --no-install puppeteer browsers install chrome ) \
        || die "browser download failed; check network access, or set PUPPETEER_EXECUTABLE_PATH to an existing Chrome for Testing binary"
    browser_present || die "the browser install reported success but the binary is not where puppeteer looks"
fi

# --- 4. it launches ------------------------------------------------------------------------
# Same flags as tests/puppeteer/lib/harness.mjs launch(), so this proves what the gates need.
if ! ( cd "$PP" && node --input-type=module -e "
        import puppeteer from 'puppeteer';
        const b = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
        const v = await b.version();
        await b.close();
        console.log('launched ' + v);
    " ) 2>&1; then
    die "the browser is installed but will not start headless; on a minimal Linux image a shared library is usually missing (run: ldd \"\$(cd tests/puppeteer && node --input-type=module -e \"import p from 'puppeteer'; console.log(await p.executablePath())\")\" | grep 'not found')"
fi

say "ready"
