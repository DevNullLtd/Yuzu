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
# What it changes: tests/puppeteer/node_modules, the puppeteer browser cache (PUPPETEER_CACHE_DIR,
# default ~/.cache/puppeteer), npm's own cache (~/.npm) and one lock file,
# ${XDG_CACHE_HOME:-~/.cache}/yuzu-ensure-puppeteer.lock. It reads no credentials and prints none of
# its own; the output of npm and the browser installer is passed through as they print it.
#
# INTEGRITY: `npm ci` installs exactly the committed package-lock.json (every entry carries a
# sha512), with lifecycle scripts disabled (--ignore-scripts) and the browser download deferred to
# step 3. The Chrome for Testing archive itself is fetched over TLS from Google's CDN at the build
# puppeteer pins; neither Google nor @puppeteer/browsers publishes a checksum for it, so its bytes
# are not hash-verified -- an accepted residual for a developer test tool.
#
# RECOVERY: an interrupted Chrome download or extract leaves a partial archive and a build directory
# with no usable binary; puppeteer then fails the same way on every run. This script removes that one
# build directory (and the stale *chrome*.zip archives beside it) ONCE and reinstalls. It does so only
# when (a) the browser lives inside puppeteer's own cache directory, at <cache>/chrome/<build>/..., so
# a path set by a config file or a lookalike directory is never touched, (b) the caller did not supply
# PUPPETEER_EXECUTABLE_PATH, and (c) for a browser that is present but will not start, the file is
# demonstrably INCOMPLETE (shorter than an ELF header, or its section-header table runs past the end
# of the file) or is not a recognisable binary at all. A browser that cannot print its version but is
# structurally complete, one that runs but fails to start headless for another reason (an unwritable
# TMPDIR, memory limits), and one that is missing shared libraries are all LEFT IN PLACE: a download
# cannot fix them, and a healthy shared build must never be deleted on weak evidence. Missing
# libraries are listed by name.
#
# Every network step has a timeout (when `timeout` or `gtimeout` exists; override with
# YUZU_ENSURE_NPM_TIMEOUT / _BROWSER_TIMEOUT / _LAUNCH_TIMEOUT, seconds) and the whole run holds an
# exclusive lock (when `flock` exists; YUZU_ENSURE_LOCK_TIMEOUT bounds the wait), so a stalled
# connection ends and two worktrees cannot race on the shared browser cache. The lock descriptor is
# closed for every PROBE child (version checks, ldd, the launch check), so a leaked probe cannot keep
# it; the install steps (npm, npx) keep it on purpose, so an orphaned download makes the next run wait
# for it instead of racing it.
#
# Exit 0 = ready. Exit 1 = not ready; the last line printed says what to do.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PP="$ROOT/tests/puppeteer"
NODE_MIN_MAJOR=22
NODE_MIN_MINOR=12
NPM_CI_TIMEOUT="${YUZU_ENSURE_NPM_TIMEOUT:-600}"
BROWSER_TIMEOUT="${YUZU_ENSURE_BROWSER_TIMEOUT:-900}"
LAUNCH_TIMEOUT="${YUZU_ENSURE_LAUNCH_TIMEOUT:-60}"
LOCK_TIMEOUT="${YUZU_ENSURE_LOCK_TIMEOUT:-2400}"

say()  { printf 'ensure-puppeteer: %s\n' "$*"; }
die()  { printf 'ensure-puppeteer: NOT READY: %s\n' "$*" >&2; exit 1; }

[[ -n "${HOME:-}" ]] || die "HOME is not set"

# _timed KEEP_LOCK SECONDS CMD...: run CMD under a timeout when one exists (macOS has `gtimeout` only
# with coreutils installed). With a terminal on stdin, --foreground keeps Ctrl-C working. KEEP_LOCK=1
# lets the child inherit the lock descriptor (an orphaned INSTALL then keeps other runs waiting for
# it, which is right); 0 closes it (probes must never hold the lock).
_timed() {
    local keep="$1" secs="$2" t="" fg=""
    shift 2
    if command -v timeout >/dev/null 2>&1; then
        t=timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        t=gtimeout
    fi
    if [[ -n "$t" ]]; then
        [[ -t 0 ]] && fg="--foreground"
        if [[ "$keep" == 1 ]]; then
            $t $fg -k 10 "$secs" "$@" || { local rc=$?; [[ $rc -eq 124 ]] && say "timed out after ${secs}s: ${1:-} ${2:-}"; return $rc; }
        else
            $t $fg -k 10 "$secs" "$@" 9>&- || { local rc=$?; [[ $rc -eq 124 ]] && say "timed out after ${secs}s: ${1:-} ${2:-}"; return $rc; }
        fi
    elif [[ "$keep" == 1 ]]; then
        "$@"
    else
        "$@" 9>&-
    fi
}
tmo()       { _timed 1 "$@"; }   # install steps
tmo_probe() { _timed 0 "$@"; }   # probes

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

# One install at a time per user: the browser cache is shared by every worktree. The lock file is
# opened for APPEND (never truncated) and only in a directory you own and not through a symlink,
# so a planted link cannot be used to clobber another file.
if command -v flock >/dev/null 2>&1; then
    LOCKFILE="${XDG_CACHE_HOME:-${HOME%/}/.cache}/yuzu-ensure-puppeteer.lock"
    lockdir="$(dirname "$LOCKFILE")"
    mkdir -p "$lockdir" || die "cannot create $lockdir"
    [[ -O "$lockdir" ]] || die "$lockdir is not owned by you; refusing to put a lock file there"
    [[ ! -L "$LOCKFILE" ]] || die "$LOCKFILE is a symlink; refusing to use it as a lock file"
    [[ ! -e "$LOCKFILE" || -f "$LOCKFILE" ]] || die "$LOCKFILE is not a regular file; refusing to use it as a lock file"
    exec 9>>"$LOCKFILE" || die "cannot open $LOCKFILE"
    flock -w "$LOCK_TIMEOUT" 9 || die "timed out waiting for another ensure-puppeteer run (lock: $LOCKFILE)"
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
    ( cd "$PP" && tmo_probe 60 node --input-type=module -e "
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
# Remove the partial or corrupt browser install and its stale archives. Refuses (returns 1) unless
# the browser path is <puppeteer cache>/chrome/<build>/... inside the cache directory this script
# knows about, and the caller did not supply their own binary. The build directory is the first path
# component under <cache>/chrome/ -- the same on Linux (chrome-linux64/chrome) and macOS (an .app
# bundle several levels deep).
heal_browser() {
    [[ -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]] || return 1
    local exe cache base rel first build
    exe="$(exe_path)" || return 1
    cache="${PUPPETEER_CACHE_DIR:-${HOME%/}/.cache/puppeteer}"
    [[ "$cache" == /* ]] || return 1       # puppeteer resolves a relative cache against its own cwd, not ours
    base="${cache%/}/chrome/"
    [[ "$exe" == "$base"* ]] || return 1
    rel="${exe#"$base"}"
    first="${rel%%/*}"
    [[ -n "$first" && "$first" != "." && "$first" != ".." ]] || return 1
    build="$base$first"
    if [[ -d "$build" && ! -L "$build" ]]; then
        say "removing the partial browser install at $build"
        rm -rf "$build" || return 1
    fi
    rm -f "$base"*chrome*.zip 2>/dev/null || true
}

RECOVERY="to reset the browser cache run: cd tests/puppeteer && npx puppeteer browsers clear (this removes ALL cached browsers, shared by every project; then re-run); or set PUPPETEER_EXECUTABLE_PATH to an existing Chrome for Testing binary"

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
    ( cd "$PP" && tmo_probe "$LAUNCH_TIMEOUT" node --input-type=module -e "
        import puppeteer from 'puppeteer';
        const b = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
        const v = await b.version();
        await b.close();
        console.log('launched ' + v);
    " ) 2>&1
}
# True when the binary itself runs. A truncated or half-extracted browser cannot even print its
# version; an intact one can, whatever else stopped it launching.
browser_runs() {
    [[ -n "$1" && -x "$1" ]] && tmo_probe 20 "$1" --version >/dev/null 2>&1
}
# Positive evidence that an ELF binary is INCOMPLETE (an interrupted extract). 0 = certainly incomplete
# (shorter than an ELF header, or its section-header table runs past the end of the file); 1 = the
# file is structurally complete; 2 = not an ELF64 little-endian file, so no conclusion (macOS, garbage).
binary_incomplete() {
    local f="$1" size hex shoff=0 i b shentsize shnum
    size="$(wc -c < "$f" 2>/dev/null | tr -d ' ')" || return 2
    [[ -n "$size" ]] || return 2
    (( size >= 64 )) || return 0
    hex="$(od -An -v -tx1 -N64 "$f" 2>/dev/null | tr -d ' \n')" || return 2
    [[ "${hex:0:8}" == "7f454c46" && "${hex:8:2}" == "02" && "${hex:10:2}" == "01" ]] || return 2
    for ((i = 7; i >= 0; i--)); do b="${hex:$((80 + i * 2)):2}"; shoff=$(( (shoff << 8) | 0x$b )); done
    shentsize=$(( 0x${hex:118:2}${hex:116:2} ))   # e_shentsize: 2 bytes at ELF offset 0x3a
    shnum=$(( 0x${hex:122:2}${hex:120:2} ))       # e_shnum: 2 bytes at ELF offset 0x3c
    (( shoff >= 0 && size >= shoff + shnum * shentsize )) && return 1
    return 0
}
last_line() { printf '%s\n' "$1" | tail -n 1; }

if ! launch_out="$(launch_check)"; then
    exe="$(exe_path || true)"
    missing=""
    if [[ -n "$exe" ]] && command -v ldd >/dev/null 2>&1; then
        missing="$(tmo_probe 20 ldd "$exe" 2>/dev/null | grep 'not found' | sed 's/^[[:space:]]*//' | tr '\n' ';' || true)"
    fi
    printf '%s\n' "$launch_out" >&2
    if [[ -n "$missing" ]]; then
        die "the browser will not start: shared libraries are missing (${missing}) - install the packages that provide them (Debian/Ubuntu: apt-file search <library> names the package); a reinstall will not help"
    fi
    if browser_runs "$exe"; then
        die "the browser runs (it prints its version) but will not start headless, so it was NOT reinstalled; the output above says why - often an unwritable TMPDIR, a memory limit or a sandbox restriction. Last line: $(last_line "$launch_out")"
    fi
    # `--version` failing is weak evidence on its own (an address-space limit, a cold disk, a seccomp
    # profile all do it to a healthy browser). Reinstall only when the file is demonstrably incomplete
    # or is not a recognisable binary; a structurally complete one is left for the operator.
    inc=0
    binary_incomplete "$exe" || inc=$?
    if [[ "$inc" -eq 1 ]]; then
        die "the browser binary is complete but cannot run (it fails even to print its version) and was NOT reinstalled; the output above says why. Last line: $(last_line "$launch_out")"
    fi
    if heal_browser; then
        say "the browser binary is incomplete or corrupt; reinstalling it once"
        install_browser || die "browser reinstall failed (${RECOVERY})"
        launch_out="$(launch_check)" || { printf '%s\n' "$launch_out" >&2; die "the browser still will not start headless after a reinstall (${RECOVERY}). Last line: $(last_line "$launch_out")"; }
    else
        die "the browser is broken but is not inside puppeteer's own cache directory (or PUPPETEER_EXECUTABLE_PATH is set), so it was left alone (${RECOVERY}). Last line: $(last_line "$launch_out")"
    fi
fi
printf '%s\n' "$launch_out"

say "ready"
