#!/usr/bin/env bash
# test_fork_dynamic_review_validate.sh — contract net for fork-dynamic-review.yml's
# `Validate immutable inputs` step, the hosted fork review's ONLY guard between a
# dispatch and the checkout of UNREVIEWED fork code.
#
# WHY THIS EXISTS (#4471). The step refuses any dispatch ref other than the PR's
# own throwaway `trusted-fork/pr-<N>[-<sha>]` branch, because the dispatch ref is
# the run's GitHub Actions cache scope. Review of the change that added it found
# the guard pinned only as a STRING in scripts/ci/test_runner_health_check.py — a
# `true || [[ ... ]]` bypass would keep that pin green while fork code ran in the
# main/dev cache scope again. This test executes the real step body.
#
# WHAT IT PINS: five refused shapes (main, dev, another PR's branch, a malformed
# suffix, an extra path segment) each exit non-zero with the runbook diagnostic;
# the bare branch, a short-sha suffix and a full-sha suffix are accepted.
#
# Run:  bash tests/shell/test_fork_dynamic_review_validate.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WF="$ROOT/.github/workflows/fork-dynamic-review.yml"
[ -f "$WF" ] || { echo "missing $WF" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-fork-review.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
python3 "$ROOT/tests/shell/extract_run_block.py" "$WF" "$TMP/validate.sh" \
  --name 'Validate immutable inputs' || exit 2
grep -q 'trusted-fork/pr-' "$TMP/validate.sh" || { echo "extracted body has no quarantine guard" >&2; exit 2; }

SHA=3333333333333333333333333333333333333333
run_validate() { # run_validate <github_ref>  -> rc, stdout in $TMP/stdout
  ( set +e
    export PR_NUMBER=2832 HEAD_SHA="$SHA" GITHUB_REF="$1"
    # The step body relies on GitHub's default `bash -e` for its bare `[[ ]]` lines.
    bash -e "$TMP/validate.sh" >"$TMP/stdout" 2>"$TMP/stderr"
    echo $? > "$TMP/rc" )
  rc=$(cat "$TMP/rc")
}

echo "-- wrong cache scope: refused with the runbook diagnostic --"
for ref in refs/heads/main refs/heads/dev refs/heads/trusted-fork/pr-999 \
           refs/heads/trusted-fork/pr-28320 refs/heads/trusted-fork/pr-2832-notasha \
           refs/heads/trusted-fork/pr-2832/extra; do
  run_validate "$ref"
  if [ "$rc" != 0 ] && grep -qF 'trusted-fork/pr-2832' "$TMP/stdout"; then
    printf '  [pass] %s refused (rc=%s)\n' "$ref" "$rc"; pass=$((pass+1))
  else
    printf '  [FAIL] %s: rc=%s stdout=%s\n' "$ref" "$rc" "$(tr '\n' ' ' < "$TMP/stdout")"; fail=$((fail+1))
  fi
done

echo "-- own quarantine scope: accepted --"
for ref in refs/heads/trusted-fork/pr-2832 refs/heads/trusted-fork/pr-2832-3333333 \
           "refs/heads/trusted-fork/pr-2832-$SHA"; do
  run_validate "$ref"
  if [ "$rc" = 0 ]; then printf '  [pass] %s accepted\n' "$ref"; pass=$((pass+1))
  else printf '  [FAIL] %s: rc=%s stdout=%s\n' "$ref" "$rc" "$(tr '\n' ' ' < "$TMP/stdout")"; fail=$((fail+1)); fi
done

echo "-- malformed inputs still refused --"
( set +e; export PR_NUMBER=abc HEAD_SHA="$SHA" GITHUB_REF=refs/heads/trusted-fork/pr-abc; bash -e "$TMP/validate.sh" >/dev/null 2>&1; echo $? > "$TMP/rc" )
[ "$(cat "$TMP/rc")" != 0 ] && { printf '  [pass] non-numeric PR number refused\n'; pass=$((pass+1)); } || { printf '  [FAIL] non-numeric PR number accepted\n'; fail=$((fail+1)); }
( set +e; export PR_NUMBER=2832 HEAD_SHA=not-a-sha GITHUB_REF=refs/heads/trusted-fork/pr-2832; bash -e "$TMP/validate.sh" >/dev/null 2>&1; echo $? > "$TMP/rc" )
[ "$(cat "$TMP/rc")" != 0 ] && { printf '  [pass] malformed head sha refused\n'; pass=$((pass+1)); } || { printf '  [FAIL] malformed head sha accepted\n'; fail=$((fail+1)); }

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
