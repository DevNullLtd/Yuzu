#!/usr/bin/env bash
# test_release_guard.sh — contract net for release.yml's `release-guard` job
# (#5282), which refuses a release run when the tag already has a published
# GitHub release, so a mistaken or superseded run cannot push new image digests
# over :X.Y.Z (and :X.Y/:latest) that no longer match the release's signed
# SHA256SUMS and SBOMs.
#
# WHAT IT PINS.
#
#   Step body (executed verbatim out of release.yml, `gh` stubbed):
#     release found                 -> exit 1, names the release, no "proceed"
#     gh prints "release not found" -> exit 0 (the ONLY proceeding outcome)
#     "release not found" + CRLF    -> exit 0 (Windows-style line ending tolerated)
#     auth error (401)              -> exit 1, fail-closed
#     network / 5xx / rate limit    -> exit 1, fail-closed
#     not-found wording embedded in a longer error -> exit 1 (exact match only)
#     empty GITHUB_REF_NAME         -> exit 1 before calling gh
#   The stub's canned outputs are the real gh 2.46.0 outputs, recorded against
#   DevNullLtd/Yuzu for an existing tag (v0.14.0), a missing tag, and a bad token.
#
#   Wiring (static, over release.yml): every job holding `packages: write`
#   (i.e. every image-publishing job, including any added later) and the
#   `release` job list `release-guard` in `needs`, as do the three build jobs.
#
# Run:  bash tests/shell/test_release_guard.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WF="$ROOT/.github/workflows/release.yml"
[ -f "$WF" ] || { echo "missing $WF" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-release-guard.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}
check_grep() { # check_grep <desc> <pattern> <file>
  if grep -q -- "$2" "$3"; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s (pattern %s not in output)\n' "$1" "$2"; sed 's/^/         | /' "$3"; fail=$((fail+1)); fi
}

python3 "$ROOT/tests/shell/extract_run_block.py" "$WF" "$TMP/guard.sh" \
  --id refuse-published-release || exit 2
grep -q 'gh release view' "$TMP/guard.sh" || { echo "extracted body does not look like the guard step" >&2; exit 2; }

# ── Hermetic gh ──────────────────────────────────────────────────────────────
# Records its argv, then answers per GH_STUB_MODE with the recorded real outputs.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$GH_STUB_ARGS"
case "$GH_STUB_MODE" in
  found)
    printf '%s\n' '{"isDraft":false,"publishedAt":"2026-10-03T22:54:21Z","tagName":"v0.14.0","url":"https://github.com/DevNullLtd/Yuzu/releases/tag/v0.14.0"}'
    exit 0 ;;
  notfound)      printf 'release not found\n' >&2; exit 1 ;;
  notfound_crlf) printf 'release not found\r\n' >&2; exit 1 ;;
  auth)
    printf '%s\n' 'non-200 OK status code: 401 Unauthorized body: "{\r\n  \"message\": \"Bad credentials\",\r\n  \"documentation_url\": \"https://docs.github.com/rest\",\r\n  \"status\": \"401\"\r\n}"' >&2
    exit 1 ;;
  network)
    printf 'error connecting to api.github.com\ncheck your internet connection or https://githubstatus.com\n' >&2
    exit 1 ;;
  server)        printf 'HTTP 502: Bad Gateway (https://api.github.com/repos/o/r/releases/tags/v1.2.3)\n' >&2; exit 1 ;;
  embedded)      printf 'unexpected: release not found in cache; HTTP 500\n' >&2; exit 1 ;;
  *)             echo "stub: unexpected mode '$GH_STUB_MODE'" >&2; exit 99 ;;
esac
EOF
chmod +x "$TMP/bin/gh"

# Invoked exactly as GitHub runs a `run:` block (`bash --noprofile --norc -eo
# pipefail {0}`), so an -e trap in the body is exercised here too.
run_guard() { # run_guard <mode> <tag> -> sets rc, writes $TMP/out
  : > "$TMP/args"
  rc=0
  env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP" \
    GH_STUB_MODE="$1" GH_STUB_ARGS="$TMP/args" GH_TOKEN="stub" \
    GITHUB_REF_NAME="$2" GITHUB_REPOSITORY="DevNullLtd/Yuzu" \
    bash --noprofile --norc -eo pipefail "$TMP/guard.sh" > "$TMP/out" 2>&1 || rc=$?
}

echo "release-guard step:"
run_guard found v0.14.0
check "published release -> run refused (exit 1)" 1 "$rc"
check_grep "refusal names the existing release" 'Release v0.14.0 already exists' "$TMP/out"
check "gh asked about the run's own tag in the run's repo" \
  "release view v0.14.0 --repo DevNullLtd/Yuzu --json tagName,isDraft,publishedAt,url" "$(cat "$TMP/args")"

run_guard notfound v0.14.1
check "no release (gh: 'release not found') -> proceed (exit 0)" 0 "$rc"
check_grep "proceed message printed" 'No release exists for v0.14.1' "$TMP/out"

run_guard notfound_crlf v0.14.1
check "'release not found' with CRLF -> proceed (exit 0)" 0 "$rc"

run_guard auth v0.14.1
check "401 bad credentials -> fail closed (exit 1)" 1 "$rc"
check_grep "auth failure reported as undeterminable" 'Could not determine whether release v0.14.1 exists' "$TMP/out"

run_guard network v0.14.1
check "network error -> fail closed (exit 1)" 1 "$rc"

run_guard server v0.14.1
check "HTTP 502 -> fail closed (exit 1)" 1 "$rc"

run_guard embedded v0.14.1
check "'release not found' inside a longer error -> fail closed (exit 1)" 1 "$rc"

run_guard found ""
check "empty GITHUB_REF_NAME -> refused (exit 1)" 1 "$rc"
check "empty GITHUB_REF_NAME -> gh never called" "" "$(cat "$TMP/args")"

# ── Wiring ───────────────────────────────────────────────────────────────────
# One line per job: "<job> <needs-line> <has-packages-write>".
echo "release-guard wiring:"
awk '
  /^jobs:/ { j = 1; next }
  j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    if (name != "") print name "|" needs "|" pkg
    name = $1; sub(":", "", name); needs = ""; pkg = "no"
    next
  }
  j && /^    needs:/ { needs = $0 }
  j && /^      packages:[[:space:]]*write/ { pkg = "yes" }
  END { if (name != "") print name "|" needs "|" pkg }
' "$WF" > "$TMP/jobs"

grep -q '^release-guard|' "$TMP/jobs"; check "release-guard job exists" 0 "$?"
publishers=0
while IFS='|' read -r job needs pkg; do
  [ "$job" = "release-guard" ] && continue
  must=no
  case "$job" in release|build-linux|build-windows|build-macos) must=yes ;; esac
  [ "$pkg" = "yes" ] && { must=yes; publishers=$((publishers+1)); }
  [ "$must" = "yes" ] || continue
  case "$needs" in
    *release-guard*) check "$job needs release-guard" yes yes ;;
    *)               check "$job needs release-guard" yes "no (needs: '${needs# *}')" ;;
  esac
done < "$TMP/jobs"
# Guard against the scan going vacuous (e.g. a reindent that hides every job).
if [ "$publishers" -ge 4 ]; then check "found the image-publishing jobs (>=4)" yes yes
else check "found the image-publishing jobs (>=4)" ">=4" "$publishers"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
