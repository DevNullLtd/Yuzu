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
#     GITHUB_REF_TYPE != tag (a branch dispatch)       -> exit 1, gh never called
#     tag not vX.Y.Z[-{alpha,beta,rc}N]                -> exit 1, gh never called
#     `gh api -i` status line HTTP/x 200               -> exit 1, names the release
#     status line HTTP/x 404 (HTTP/2.0 or HTTP/1.1)    -> exit 0 (the ONLY proceed)
#     401 / 502 / 500-with-"Not Found"-in-body         -> exit 1, fail-closed
#     no status line (network error; a 404 that appears
#       only in gh's stderr prose; or not on line 1)   -> exit 1, fail-closed
#     empty GITHUB_REF_NAME                            -> exit 1 before calling gh
#   The stub's canned outputs follow real gh 2.46.0 `gh api -i` output, recorded
#   against DevNullLtd/Yuzu for an existing tag (v0.14.0) and a missing tag: the
#   status line and headers then the body on stdout, and on a 404 the
#   "gh: Not Found (HTTP 404)" line on stderr.
#
#   Wiring (static, over release.yml): every job holding `packages: write`
#   (i.e. every image-publishing job, including any added later) and the
#   `release` job list `release-guard` in `needs`, as do the three build jobs.
#   Each of those publishing jobs and `release` runs
#   scripts/ci/check-release-tag-sha.sh exactly once, before its first push /
#   `gh release create` line (the script itself: test_release_tag_sha.sh).
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
grep -q 'gh api -i' "$TMP/guard.sh" || { echo "extracted body does not look like the guard step" >&2; exit 2; }

# ── Hermetic gh ──────────────────────────────────────────────────────────────
# Records its argv, then answers per GH_STUB_MODE with the recorded real outputs.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$GH_STUB_ARGS"
hdr() { printf '%s\r\nContent-Type: application/json; charset=utf-8\r\nX-Github-Api-Version-Selected: 2022-11-28\r\n\r\n' "$1"; }
case "$GH_STUB_MODE" in
  found)
    hdr 'HTTP/2.0 200 OK'
    printf '%s' '{"tag_name":"v0.14.0","draft":false,"published_at":"2026-10-03T22:54:21Z","html_url":"https://github.com/DevNullLtd/Yuzu/releases/tag/v0.14.0"}'
    exit 0 ;;
  notfound)
    hdr 'HTTP/2.0 404 Not Found'
    printf '%s' '{"message":"Not Found","documentation_url":"https://docs.github.com/rest/releases/releases#get-a-release-by-tag-name","status":"404"}'
    printf 'gh: Not Found (HTTP 404)\n' >&2
    exit 1 ;;
  http11)
    hdr 'HTTP/1.1 404 Not Found'
    printf '%s' '{"message":"Not Found","status":"404"}'
    printf 'gh: Not Found (HTTP 404)\n' >&2
    exit 1 ;;
  auth)
    hdr 'HTTP/2.0 401 Unauthorized'
    printf '%s' '{"message":"Bad credentials","documentation_url":"https://docs.github.com/rest","status":"401"}'
    printf 'gh: Bad credentials (HTTP 401)\n' >&2
    exit 1 ;;
  server)
    hdr 'HTTP/2.0 502 Bad Gateway'
    printf '%s' '{"message":"Server Error"}'
    printf 'gh: HTTP 502: Bad Gateway (https://api.github.com/repos/o/r/releases/tags/v1.2.3)\n' >&2
    exit 1 ;;
  network)
    printf 'error connecting to api.github.com\ncheck your internet connection or https://githubstatus.com\n' >&2
    exit 1 ;;
  embedded)
    hdr 'HTTP/2.0 500 Internal Server Error'
    printf '%s' '{"message":"release Not Found in cache","status":"500"}'
    printf 'gh: release Not Found in cache (HTTP 500)\n' >&2
    exit 1 ;;
  found_lf|notfound_lf)
    # gh 2.46.0 as actually observed: LF-only status line and headers.
    if [ "$GH_STUB_MODE" = found_lf ]; then
      printf 'HTTP/2.0 200 OK\nContent-Type: application/json; charset=utf-8\n\n%s' '{"tag_name":"v0.14.0","draft":false,"published_at":"2026-10-03T22:54:21Z","html_url":"https://github.com/DevNullLtd/Yuzu/releases/tag/v0.14.0"}'
      exit 0
    fi
    printf 'HTTP/2.0 404 Not Found\nContent-Type: application/json; charset=utf-8\n\n%s' '{"message":"Not Found","status":"404"}'
    printf 'gh: Not Found (HTTP 404)\n' >&2
    exit 1 ;;
  late_status)
    # A status-shaped line that is NOT the first line (e.g. inside a body):
    # only the first line counts, so this has no status and fails closed.
    printf '%s\nHTTP/2.0 404 Not Found\n' '{"note":"proxy page"}'
    exit 1 ;;
  stderr_only_404)
    printf 'gh: Not Found (HTTP 404)\n' >&2
    exit 1 ;;
  *)             echo "stub: unexpected mode '$GH_STUB_MODE'" >&2; exit 99 ;;
esac
EOF
chmod +x "$TMP/bin/gh"

# Invoked exactly as GitHub runs a `run:` block (`bash --noprofile --norc -eo
# pipefail {0}`), so an -e trap in the body is exercised here too.
run_guard() { # run_guard <mode> <tag> [ref_type=tag] -> sets rc, writes $TMP/out
  : > "$TMP/args"
  rc=0
  env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP" \
    GH_STUB_MODE="$1" GH_STUB_ARGS="$TMP/args" GH_TOKEN="stub" \
    GITHUB_REF_NAME="$2" GITHUB_REF_TYPE="${3-tag}" GITHUB_REPOSITORY="DevNullLtd/Yuzu" \
    bash --noprofile --norc -eo pipefail "$TMP/guard.sh" > "$TMP/out" 2>&1 || rc=$?
}

echo "release-guard step:"
run_guard found v0.14.0
check "published release (HTTP 200) -> run refused (exit 1)" 1 "$rc"
check_grep "refusal names the existing release" 'Release v0.14.0 already exists' "$TMP/out"
check_grep "refusal quotes the release's published_at" '2026-10-03T22:54:21Z' "$TMP/out"
check "gh asked about the run's own tag in the run's repo" \
  "api -i repos/DevNullLtd/Yuzu/releases/tags/v0.14.0" "$(cat "$TMP/args")"

for t in v0.14.1 v0.14.1-rc1 v0.14.1-beta2 v1.0.0-alpha3; do
  run_guard notfound "$t"
  check "no release for $t (HTTP 404) -> proceed (exit 0)" 0 "$rc"
done
check_grep "proceed message printed" 'No published release for v1.0.0-alpha3 (HTTP 404)' "$TMP/out"

run_guard http11 v0.14.1
check "HTTP/1.1 404 status line -> proceed (exit 0)" 0 "$rc"
run_guard notfound_lf v0.14.1
check "LF-only 404 status line (gh 2.46.0 as observed) -> proceed (exit 0)" 0 "$rc"
run_guard found_lf v0.14.0
check "LF-only 200 status line -> refused (exit 1)" 1 "$rc"
check_grep "LF-only refusal still parses the body" 'releases/tag/v0.14.0' "$TMP/out"

run_guard auth v0.14.1
check "401 bad credentials -> fail closed (exit 1)" 1 "$rc"
check_grep "auth failure reported as undeterminable" "Could not determine whether release v0.14.1 exists (gh exit 1, HTTP status '401')" "$TMP/out"

run_guard network v0.14.1
check "network error (no status line) -> fail closed (exit 1)" 1 "$rc"
check_grep "network failure names the missing status" "HTTP status 'none'" "$TMP/out"

run_guard server v0.14.1
check "HTTP 502 -> fail closed (exit 1)" 1 "$rc"

run_guard embedded v0.14.1
check "HTTP 500 with 'Not Found' in the body -> fail closed (exit 1)" 1 "$rc"

run_guard late_status v0.14.1
check "a 404 status line that is not the FIRST line -> fail closed (exit 1)" 1 "$rc"

run_guard stderr_only_404 v0.14.1
check "404 only in gh's stderr prose, no status line -> fail closed (exit 1)" 1 "$rc"

run_guard notfound main branch
check "branch ref (dispatch without --ref vX.Y.Z) -> refused (exit 1)" 1 "$rc"
check "branch ref -> gh never called" "" "$(cat "$TMP/args")"
check_grep "branch refusal names the ref type" "not branch 'main'" "$TMP/out"

run_guard notfound v0.14.1 ""
check "unset ref type -> refused (exit 1)" 1 "$rc"
check "unset ref type -> gh never called" "" "$(cat "$TMP/args")"

for t in main v1.2.3-foo v1.2 1.2.3 v1.2.3-rc v1.2.3-rc1-extra; do
  run_guard notfound "$t"
  check "tag '$t' is not a release tag -> refused (exit 1)" 1 "$rc"
  check "tag '$t' -> gh never called" "" "$(cat "$TMP/args")"
done

run_guard found ""
check "empty GITHUB_REF_NAME -> refused (exit 1)" 1 "$rc"
check "empty GITHUB_REF_NAME -> gh never called" "" "$(cat "$TMP/args")"

# ── Wiring ───────────────────────────────────────────────────────────────────
# One line per job:
#   "<job>|<needs-line>|<has-packages-write>|<#tag-recheck lines>|<first recheck line>|<first act line>"
# An "act" line is a `push: true`, `--push` or `gh release create` outside a comment.
echo "release-guard wiring:"
awk '
  function flush() {
    if (name != "") print name "|" needs "|" pkg "|" nchk "|" firstchk "|" firstact
  }
  /^jobs:/ { j = 1; next }
  j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    flush()
    name = $1; sub(":", "", name); needs = ""; pkg = "no"; nchk = 0; firstchk = 0; firstact = 0
    next
  }
  j && /^    needs:/ { needs = $0 }
  j && /^      packages:[[:space:]]*write/ { pkg = "yes" }
  j && /^[[:space:]]*#/ { next }
  j {
    line = $0; sub(/[[:space:]]+#.*/, "", line)   # drop a trailing YAML comment
    if (line ~ /check-release-tag-sha\.sh/) { nchk++; if (!firstchk) firstchk = NR }
    if (line ~ /push:[[:space:]]*true/ || line ~ /--push/ || line ~ /gh release create/) { if (!firstact) firstact = NR }
  }
  END { flush() }
' "$WF" > "$TMP/jobs"

grep -q '^release-guard|' "$TMP/jobs"; check "release-guard job exists" 0 "$?"
publishers=0
while IFS='|' read -r job needs pkg nchk firstchk firstact; do
  [ "$job" = "release-guard" ] && continue
  must=no publishes=no
  case "$job" in release|build-linux|build-windows|build-macos) must=yes ;; esac
  [ "$job" = "release" ] && publishes=yes
  [ "$pkg" = "yes" ] && { must=yes publishes=yes; publishers=$((publishers+1)); }
  [ "$must" = "yes" ] || continue
  case "$needs" in
    *release-guard*) check "$job needs release-guard" yes yes ;;
    *)               check "$job needs release-guard" yes "no (needs: '${needs# *}')" ;;
  esac
  [ "$publishes" = "yes" ] || continue
  check "$job runs check-release-tag-sha.sh exactly once" 1 "$nchk"
  if [ "$firstact" -gt 0 ] && [ "$firstchk" -gt 0 ] && [ "$firstchk" -lt "$firstact" ]; then
    check "$job re-checks the tag before its first push/release line" yes yes
  else
    check "$job re-checks the tag before its first push/release line" yes \
      "no (recheck line $firstchk, first act line $firstact)"
  fi
done < "$TMP/jobs"
# Each recheck step must be the plain, unconditional form: a step-level `if:`,
# `continue-on-error`, or a `run:` that is not exactly the script call would
# leave the check present in the file but unable to stop a push (G8-QE-1).
python3 - "$WF" > "$TMP/stepshape" <<'PYEOF'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
for job, spec in (wf.get("jobs") or {}).items():
    for st in spec.get("steps") or []:
        run = st.get("run") or ""
        if "check-release-tag-sha.sh" not in run:
            continue
        bad = []
        if "if" in st: bad.append("if")
        if st.get("continue-on-error") not in (None, False): bad.append("continue-on-error")
        if run.strip() != "bash scripts/ci/check-release-tag-sha.sh": bad.append("run")
        if "continue-on-error" in spec and spec["continue-on-error"] not in (False,): bad.append("job-continue-on-error")
        print(f"{job}|{','.join(bad) or 'ok'}")
    # The push itself must not run after a failed recheck (if: always() etc.).
    for st in spec.get("steps") or []:
        txt = (st.get("run") or "") + str(st.get("with") or "")
        acts = "gh release create" in txt or "--push" in txt or "'push': True" in txt
        cond = str(st.get("if", ""))
        if acts and any(k in cond for k in ("always()", "failure()", "cancelled()")):
            print(f"{job} push step|runs-after-failure")
PYEOF
nshape=0
while IFS='|' read -r job verdict; do
  nshape=$((nshape+1))
  check "$job tag-recheck step is unconditional and exact" ok "$verdict"
done < "$TMP/stepshape"
check "found the five tag-recheck steps" 5 "$(grep -cv ' push step|' "$TMP/stepshape")"
# Guard against the scan going vacuous (e.g. a reindent that hides every job).
if [ "$publishers" -ge 4 ]; then check "found the image-publishing jobs (>=4)" yes yes
else check "found the image-publishing jobs (>=4)" ">=4" "$publishers"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
