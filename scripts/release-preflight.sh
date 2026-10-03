#!/usr/bin/env bash
# release-preflight.sh — validate that the repo is ready to tag a release.
# Usage: bash scripts/release-preflight.sh v0.9.0 [--full]
#   --full  also compiles C++ and Erlang (adds ~2 min)
set -euo pipefail

TAG="${1:?Usage: release-preflight.sh <tag> [--full]}"
FULL="${2:-}"
VERSION="${TAG#v}"
BASE_VERSION="${VERSION%%-*}"

echo "=== Release Preflight for $TAG (base: $BASE_VERSION) ==="
echo ""

FAILURES=0
pass() { printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAILURES=$((FAILURES + 1)); }

# ── 1. CRLF in scripts / Erlang ──────────────────────────────────────────
if grep -rPl '\r$' scripts/*.sh gateway/rebar.config 2>/dev/null; then
    fail "CRLF line endings found (see files above)"
else
    pass "No CRLF in scripts or gateway config"
fi

# ── 2. meson.build version matches tag ────────────────────────────────────
MESON_VER=$(sed -n "s/.*version: '\([^']*\)'.*/\1/p" meson.build | head -1)
if [ "$MESON_VER" = "$BASE_VERSION" ]; then
    pass "meson.build version is $MESON_VER"
else
    fail "meson.build version is '$MESON_VER', expected '$BASE_VERSION'"
fi

# ── 3. CHANGELOG has matching section ─────────────────────────────────────
if grep -q "## \[${BASE_VERSION}\]" CHANGELOG.md; then
    pass "CHANGELOG.md has ## [$BASE_VERSION] section"
else
    fail "CHANGELOG.md missing ## [$BASE_VERSION] section"
fi

# ── 4. Changelog extraction produces content (same AWK as release.yml) ────
EXTRACTED=$(awk "/^## \[${BASE_VERSION}\]/{found=1;next} /^## \[/{if(found) exit} found{print}" CHANGELOG.md)
LINE_COUNT=$(echo "$EXTRACTED" | grep -c '.' || true)
if [ "$LINE_COUNT" -gt 0 ]; then
    pass "Changelog extraction produced $LINE_COUNT lines"
else
    fail "Changelog extraction produced empty output"
fi

# ── 4b. No unpromoted changelog fragments ─────────────────────────────────
# PRs land changelog entries as changelog.d/ fragment files; the promote step
# (scripts/assemble-changelog.py promote X.Y.Z) must have folded them all into
# the ## [X.Y.Z] section before tagging. See changelog.d/README.md.
FRAG_COUNT=$(find changelog.d -maxdepth 1 -name '*.md' ! -name 'README.md' 2>/dev/null | wc -l | tr -d ' ')
if [ "$FRAG_COUNT" -eq 0 ]; then
    pass "changelog.d/ has no unpromoted fragments"
else
    if grep -q "^## \[${BASE_VERSION//./\\.}\]" CHANGELOG.md 2>/dev/null; then
        if [ "$VERSION" = "$BASE_VERSION" ]; then
            APPEND_DATE=" --date YYYY-MM-DD  (the final release date)"
        else
            APPEND_DATE="  (omit --date for an RC; pass it only at the final release)"
        fi
        fail "changelog.d/ has $FRAG_COUNT unpromoted fragment(s) and ## [$BASE_VERSION] already exists — run: python3 scripts/assemble-changelog.py promote $BASE_VERSION --append$APPEND_DATE"
    else
        fail "changelog.d/ has $FRAG_COUNT unpromoted fragment(s) — run: python3 scripts/assemble-changelog.py promote $BASE_VERSION"
    fi
fi

# ── 5. Clean working tree ─────────────────────────────────────────────────
if git diff --quiet HEAD && git diff --cached --quiet; then
    pass "Working tree clean (no uncommitted changes)"
else
    fail "Uncommitted changes present — commit or stash first"
fi

# ── 6. Dockerfile.server has --data-dir ───────────────────────────────────
if grep -q 'data-dir' deploy/docker/Dockerfile.server; then
    pass "Dockerfile.server CMD includes --data-dir"
else
    fail "Dockerfile.server CMD missing --data-dir"
fi

# ── 7. release.yml uses cache/restore only, never cache (save) ────────────
# Release builds consume cache, never produce — each tag is a unique
# commit so the file-hash key never matches anything a future release
# could benefit from. Paying the cache writeback cost on every release
# blew the Linux 45-min job budget during v0.11.0 retags (Post Cache
# ccache spent 28.5 min uploading data nobody would re-read). Enforce
# that only `actions/cache/restore@` references appear in release.yml
# — bare `actions/cache@` would re-introduce the save phase and the
# timeout regression. The previous check enforced `save-always: true`,
# but the action authors deprecated that input as "does not work as
# intended", so the invariant flipped: now we enforce its absence.
BARE_CACHE_COUNT=$(grep -cE 'actions/cache@([0-9a-f]{40}|v[0-9]+)' .github/workflows/release.yml || true)
RESTORE_CACHE_COUNT=$(grep -cE 'actions/cache/restore@([0-9a-f]{40}|v[0-9]+)' .github/workflows/release.yml || true)
# Match YAML input only (whitespace-then-key), not comments mentioning the
# string. Without the `^\s*` anchor the regex caught the inline comment
# block in release.yml that explains why save-always was removed.
SAVE_ALWAYS_COUNT=$(grep -cE '^\s*save-always:' .github/workflows/release.yml || true)
if [ "$BARE_CACHE_COUNT" -gt 0 ]; then
    fail "$BARE_CACHE_COUNT bare actions/cache@ references in release.yml — must be actions/cache/restore@ (release builds consume cache, never produce)"
elif [ "$SAVE_ALWAYS_COUNT" -gt 0 ]; then
    fail "$SAVE_ALWAYS_COUNT save-always: references in release.yml — input is deprecated and the cache surgery removed the save phase"
else
    pass "All $RESTORE_CACHE_COUNT cache steps in release.yml are restore-only (no save phase, no save-always)"
fi

# ── 8. docker-compose.full-uat.yml has --data-dir ─────────────────────────
if grep -q 'data-dir' deploy/docker/docker-compose.full-uat.yml; then
    pass "docker-compose.full-uat.yml includes --data-dir"
else
    fail "docker-compose.full-uat.yml missing --data-dir"
fi

# ── 9. dev / main reconciliation ──────────────────────────────────────────
# Releases tag from main. If main is missing commits that are on dev, the
# tag will not include them — and worse, if main has commits not on dev
# (typical leftover release-prep commits from prior releases), continued
# work on dev keeps diverging silently. This check is hard FAIL per the
# /release skill's "this catches us every time" lesson — surface the
# divergence at preflight rather than at tag-time-or-later.
if git ls-remote --exit-code --heads origin main >/dev/null 2>&1 \
   && git ls-remote --exit-code --heads origin dev >/dev/null 2>&1; then
    git fetch --quiet origin main dev 2>/dev/null || true
    DEV_AHEAD=$(git rev-list --count origin/main..origin/dev 2>/dev/null || echo 0)
    MAIN_AHEAD=$(git rev-list --count origin/dev..origin/main 2>/dev/null || echo 0)
    if [ "$DEV_AHEAD" = "0" ] && [ "$MAIN_AHEAD" = "0" ]; then
        pass "origin/dev and origin/main reconciled (no divergence)"
    else
        fail "origin/dev and origin/main diverged: dev is $DEV_AHEAD ahead, main is $MAIN_AHEAD ahead — reconcile before tagging (see /release skill 'Phase 0.5 — Branch reconciliation')"
    fi
else
    pass "skipping dev/main reconciliation check (one or both branches missing on origin)"
fi

# ── 10. Full build validation (optional) ─────────────────────────────────
if [ "$FULL" = "--full" ]; then
    echo ""
    echo "  --- Full build validation ---"

    # Per-OS canonical build directory (mirrors scripts/setup.sh).
    if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
        BUILDDIR="build-windows"
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        BUILDDIR="build-macos"
    else
        BUILDDIR="build-linux"
    fi

    # Erlang toolchain — required by both the standalone rebar3 step and the
    # gateway custom_target inside meson, so it must be on PATH before the C++
    # compile too. ensure-erlang.sh probes kerl, asdf, Homebrew, and the MSYS2
    # installer paths in turn; it always returns 0, so we verify with command -v.
    # The explicit "28" arg is load-bearing: a sourced script inherits the
    # caller's positional args, so without it the helper would receive "$1"
    # from THIS script (e.g. "v0.10.0") and search for a kerl install with
    # that name. Pass the major version explicitly to track release.yml's
    # erlef/setup-beam otp-version.
    # shellcheck source=ensure-erlang.sh
    source "$(dirname "$0")/ensure-erlang.sh" 28
    HAVE_ERL=0
    if command -v erl > /dev/null 2>&1; then
        HAVE_ERL=1
        pass "Erlang on PATH ($(erl -version 2>&1 | tr -d '\n'))"
    else
        fail "Erlang not on PATH after ensure-erlang.sh — install via kerl/asdf/brew or activate manually"
    fi

    # C++ compile
    if [ -d "$BUILDDIR" ]; then
        echo "  Compiling C++ (meson compile -C $BUILDDIR)..."
        if meson compile -C "$BUILDDIR" > /dev/null 2>&1; then
            pass "C++ compiles"
        else
            fail "C++ compilation failed"
        fi
    else
        fail "No $BUILDDIR found — run scripts/setup.sh first"
    fi

    # Erlang compile + dialyzer (skipped if erl missing — already failed above)
    if [ "$HAVE_ERL" -eq 1 ] && [ -d "gateway" ]; then
        echo "  Compiling Erlang (rebar3 compile + dialyzer)..."
        if (cd gateway && rebar3 compile > /dev/null 2>&1); then
            pass "Erlang compiles"
        else
            fail "Erlang compilation failed"
        fi
        if (cd gateway && rebar3 dialyzer > /dev/null 2>&1); then
            pass "Dialyzer passes"
        else
            fail "Dialyzer failed"
        fi
    elif [ ! -d "gateway" ]; then
        fail "No gateway directory found"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "=== \033[32mPREFLIGHT PASSED\033[0m for %s ===\n" "$TAG"
    exit 0
else
    printf "=== \033[31mPREFLIGHT FAILED: %d issue(s)\033[0m ===\n" "$FAILURES"
    exit 1
fi
