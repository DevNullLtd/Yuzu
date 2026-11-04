#!/usr/bin/env bash
# ensure-puppeteer.sh -- make tests/puppeteer runnable, installing what is missing.
#
# Called by /test Phase 0b (default and --full modes) so the two headless-browser gates
# ("Puppeteer", "Browser smoke") always have something to run. Before this existed a missing
# `npm ci` recorded SKIP, and a gate that skips for want of a one-line install is a gate that
# silently stops protecting the dashboard. Idempotent: a second run on a ready box only
# verifies and exits 0.
#
# What "ready" means, each step checked rather than assumed:
#   1. node >= 22.12 and npm on PATH (the pinned puppeteer's floor).
#   2. tests/puppeteer/node_modules matches package-lock.json (`npm ci` otherwise).
#   3. A Chrome for Testing binary exists (`puppeteer browsers install chrome` otherwise).
#      PUPPETEER_EXECUTABLE_PATH, when set, is honoured and nothing is downloaded.
#   4. That browser actually LAUNCHES headless. A binary that is present but cannot start
#      (a missing shared library on a minimal Linux image is the usual cause) would otherwise
#      surface as a confusing failure deep inside the crawl.
#
# What it changes: tests/puppeteer/node_modules, the puppeteer browser cache (~/.cache/puppeteer)
# and npm's own cache (~/.npm). It reads no credentials and prints none of its own; the output of
# npm and the browser installer is passed through as they print it.
#
# INTEGRITY: `npm ci` installs exactly the committed package-lock.json (every entry carries a
# sha512), with lifecycle scripts disabled (--ignore-scripts) and the browser download deferred to
# step 3. The Chrome for Testing archive itself is fetched over TLS from Google's CDN at the build
# puppeteer pins; neither Google nor @puppeteer/browsers publishes a checksum for it, so its bytes
# are not hash-verified -- an accepted residual for a developer test tool.
#
# RECOVERY: an interrupted Chrome download or extract leaves a partial archive and a build directory
# with no usable binary; puppeteer then fails the same way on every run. This script deletes that one
# build directory (and the stale *.zip beside it) ONCE and reinstalls, but only when the browser
# lives in puppeteer's own cache (a directory named `chrome`), and never when PUPPETEER_EXECUTABLE_PATH
# names a binary the caller supplied. A browser that fails to start because of a missing shared
# library is NOT reinstalled (a download cannot fix it); the missing libraries are listed instead.
#
# Every network step has a timeout (when `timeout` exists) and the install section takes an exclusive
# lock (when `flock` exists), so a stalled connection ends and two worktrees cannot race on the shared
# ~/.cache/puppeteer.
#
# Exit 0 = ready. Exit 1 = not ready; the last line printed says what to do.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PP="$ROOT/tests/puppeteer"
NODE_MIN_MAJOR=22
NODE_MIN_MINOR=12
NPM_CI_TIMEOUT=600
BROWSER_TIMEOUT=900
LAUNCH_TIMEOUT=60

say()  { printf 'ensure-puppeteer: %s\n' "$*"; }
die()  { printf 'ensure-puppeteer: NOT READY: %s\n' "$*" >&2; exit 1; }

[[ -n "${HOME:-}" ]] || die "HOME is not set"

# tmo SECONDS CMD...: run CMD under `timeout` when it exists (macOS has none by default).
tmo() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@" || { local rc=$?; [[ $rc -eq 124 ]] && say "timed out after ${secs}s: $1 $2"; return $rc; }
    else
        "$@"
    fi
}

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

# One install at a time per user: the browser cache is shared by every worktree.
if command -v flock >/dev/null 2>&1; then
    LOCKFILE="${XDG_CACHE_HOME:-$HOME/.cache}/yuzu-ensure-puppeteer.lock"
    mkdir -p "$(dirname "$LOCKFILE")" || die "cannot create $(dirname "$LOCKFILE")"
    exec 9>"$LOCKFILE" || die "cannot open $LOCKFILE"
    flock -w "$BROWSER_TIMEOUT" 9 || die "timed out waiting for another ensure-puppeteer run (lock: $LOCKFILE)"
fi

# --- 2. dependencies ----------------------------------------------------------------------
# npm ci writes node_modules/.package-lock.json; a lockfile newer than it means the install
# predates the pinned versions (a rebase moved the lock), so reinstall rather than trust it. This is
# an mtime heuristic: a lock whose mtime was preserved by cp -p or rsync can be trusted wrongly.
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
    ( cd "$PP" && PUPPETEER_SKIP_DOWNLOAD=1 tmo "$NPM_CI_TIMEOUT" npm ci --ignore-scripts --no-audit --no-fund ) \
        || die "npm ci failed in tests/puppeteer; check network access to the npm registry"
else
    say "dependencies already match package-lock.json"
fi

# --- 3. browser ---------------------------------------------------------------------------
# puppeteer resolves the path itself (cache dir, PUPPETEER_EXECUTABLE_PATH), so ask it rather
# than guessing where Chrome for Testing lives on this OS. Node's own errors are NOT swallowed: a
# broken import must read as a broken import, not as "browser absent".
exe_path() {
    ( cd "$PP" && node --input-type=module -e "
        import puppeteer from 'puppeteer';
        console.log(await puppeteer.executablePath());
    " )
}
browser_present() {
    local exe
    exe="$(exe_path)" || return 1
    [[ -n "$exe" && -e "$exe" ]]
}
install_browser() {
    ( cd "$PP" && tmo "$BROWSER_TIMEOUT" npx --no-install puppeteer browsers install chrome )
}
# Delete the ONE build directory that holds a partial or corrupt browser, plus the stale archives
# beside it. Refuses (returns 1) unless the browser is inside a puppeteer cache `chrome` directory
# and the caller did not supply their own binary.
heal_browser() {
    [[ -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]] || return 1
    local exe dir parent
    exe="$(exe_path)" || return 1
    [[ -n "$exe" ]] || return 1
    dir="$(dirname "$(dirname "$exe")")"
    parent="$(dirname "$dir")"
    [[ "$(basename "$parent")" == "chrome" && "$dir" != "$parent" ]] || return 1
    say "removing the partial browser install at $dir"
    rm -rf "$dir" || return 1
    rm -f "$parent"/*.zip 2>/dev/null || true
}

RECOVERY="to reset the browser cache run: cd tests/puppeteer && npx puppeteer browsers clear (then re-run); or set PUPPETEER_EXECUTABLE_PATH to an existing Chrome for Testing binary"

# If node cannot even load puppeteer, say that now: treating it as "browser absent" would download
# a browser and then fail with a message that points at the wrong thing.
exe_now="$(exe_path)" \
    || die "node could not load puppeteer (its error is above); remove tests/puppeteer/node_modules and re-run"
if [[ -n "$exe_now" && -e "$exe_now" ]]; then
    say "browser already present"
else
    if [[ -n "${PUPPETEER_EXECUTABLE_PATH:-}" ]]; then
        die "PUPPETEER_EXECUTABLE_PATH is set to '${PUPPETEER_EXECUTABLE_PATH}' but nothing is there"
    fi
    say "installing Chrome for Testing (npx puppeteer browsers install chrome)"
    if ! install_browser; then
        say "the browser install failed; clearing any partial download and retrying once"
        heal_browser || true
        install_browser || die "browser download failed twice; check network access (${RECOVERY})"
    fi
    browser_present || die "the browser install reported success but the binary is not where puppeteer looks (${RECOVERY})"
fi

# --- 4. it launches ------------------------------------------------------------------------
# Same flags as tests/puppeteer/lib/harness.mjs launch(), so this proves what the gates need. A
# present-but-truncated binary passes the existence check above and fails here.
launch_check() {
    ( cd "$PP" && tmo "$LAUNCH_TIMEOUT" node --input-type=module -e "
        import puppeteer from 'puppeteer';
        const b = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
        const v = await b.version();
        await b.close();
        console.log('launched ' + v);
    " ) 2>&1
}

if ! launch_out="$(launch_check)"; then
    exe="$(exe_path || true)"
    missing=""
    if [[ -n "$exe" ]] && command -v ldd >/dev/null 2>&1; then
        missing="$(ldd "$exe" 2>/dev/null | grep 'not found' | sed 's/^[[:space:]]*//' | tr '\n' ';' || true)"
    fi
    if [[ -n "$missing" ]]; then
        die "the browser will not start: shared libraries are missing (${missing}) - install them (Debian/Ubuntu: apt install the matching packages); a reinstall will not help"
    fi
    if heal_browser; then
        say "the browser is present but will not start; reinstalling it once"
        install_browser || die "browser reinstall failed (${RECOVERY})"
        launch_out="$(launch_check)" || die "the browser still will not start headless after a reinstall (${RECOVERY}); see the output above: ${launch_out##*$'\n'}"
    else
        die "the browser will not start headless and is not in puppeteer's cache, so it was left alone (${RECOVERY}): ${launch_out##*$'\n'}"
    fi
fi
printf '%s\n' "$launch_out"

say "ready"
