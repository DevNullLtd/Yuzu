#!/usr/bin/env bash
# test_trusted_fork_validate_approval.sh — contract net for trusted-fork-ci.yml's
# `validate-approval` job body (#4471 round-2 review, fjarvis), the SOLE gate
# deciding whether a workflow_dispatch of the trusted CI gate is authorized to
# execute a fork's revision at all.
#
# WHY THIS EXISTS. The job's title-binding check ties a cited review run to
# (PR#, SHA) only -- never to which quarantine BRANCH it ran on. Branch
# reuse-or-fresh across approval rounds is sanctioned, documented behavior
# (docs/ci-troubleshooting.md 1.2), as is a failed purge needing a re-dispatch.
# Put those together: a review run from quarantine branch A, successfully
# reviewed, can be cited to authorize a trusted-gate dispatch on a DIFFERENT
# branch B for the same PR/SHA -- pulling branch A's (possibly
# fork-poisoned, pre-purge) cache scope into the full trusted gate. This test
# pins the fix: the cited review run's own branch must match the branch this
# job is actually dispatched on.
#
# Run:  bash tests/shell/test_trusted_fork_validate_approval.sh

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v jq >/dev/null 2>&1 || { echo "  [skip] jq not installed (the step itself uses it)"; exit 0; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-fork-validate.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
pass=0 fail=0
check() { if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1)); else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi; }

WF="$ROOT/.github/workflows/trusted-fork-ci.yml"
[ -f "$WF" ] || { echo "missing $WF" >&2; exit 2; }
python3 "$ROOT/tests/shell/extract_run_block.py" "$WF" "$TMP/validate.sh" --id validate || exit 2
grep -q 'gh run view' "$TMP/validate.sh" || { echo "extracted body does not look like validate-approval" >&2; exit 2; }

# Stateful stub covering the two `gh` calls this step makes: the PR lookup and
# the review-run lookup. PR_STATE/PR_SHA/PR_HEAD_REPO drive the first; the
# REVIEW_* vars drive the second, keyed so a test can mismatch any one field
# independently (title, workflow name, status, conclusion, or -- the finding
# under test -- headBranch) without touching the others.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$LOG"
if [ "$1" = api ]; then
  python3 - "$PR_STATE" "$PR_SHA" "$PR_HEAD_REPO" "$REPOSITORY" <<'PY'
import json, sys
state, sha, head_repo, repo = sys.argv[1:5]
print(json.dumps({
    "state": state,
    "head": {"sha": sha, "repo": ({"full_name": head_repo} if head_repo else None)},
}))
PY
  exit 0
fi
if [ "$1" = run ] && [ "$2" = view ]; then
  python3 - "$REVIEW_WORKFLOW" "$REVIEW_TITLE" "$REVIEW_STATUS" "$REVIEW_CONCLUSION" "$REVIEW_BRANCH" <<'PY'
import json, sys
wf, title, status, conclusion, branch = sys.argv[1:6]
print(json.dumps({
    "workflowName": wf, "displayTitle": title,
    "status": status, "conclusion": conclusion, "headBranch": branch,
}))
PY
  exit 0
fi
echo "stub gh: unexpected invocation: $*" >&2; exit 99
STUB
chmod +x "$TMP/bin/gh"

# run_validate [env overrides via VAR=value ...] -- always starts from a
# baseline that would PASS every check, so each test overrides exactly the
# one field it wants to probe.
run_validate() {
  : > "$TMP/log" > "$TMP/out.env"
  ( set +e
    export PATH="$TMP/bin:$PATH" GH_TOKEN=""
    export REPOSITORY=DevNullLtd/Yuzu PR_NUMBER=42 APPROVED_SHA="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" REVIEW_RUN_ID=999
    export GITHUB_REF="refs/heads/trusted-fork/pr-42"
    export PR_STATE=open PR_SHA="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" PR_HEAD_REPO="someone/Yuzu"
    export REVIEW_WORKFLOW="Fork dynamic review" \
           REVIEW_TITLE="Fork review PR #42 @ a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" \
           REVIEW_STATUS=completed REVIEW_CONCLUSION=success \
           REVIEW_BRANCH="trusted-fork/pr-42"
    for kv in "$@"; do export "${kv?}"; done
    GITHUB_OUTPUT="$TMP/out.env" bash "$TMP/validate.sh" >"$TMP/out" 2>"$TMP/err"; echo $? > "$TMP/rc" )
  rc=$(cat "$TMP/rc")
}

echo "=== trusted-fork-ci.yml: validate-approval ==="

echo "-- happy path: everything matches, including the branch --"
run_validate
check "exits 0"                 "0" "$rc"
check "emits pr_number output"  "1" "$(grep -c '^pr_number=42$' "$TMP/out.env" || true)"
check "emits head_sha output"   "1" "$(grep -c '^head_sha=a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1$' "$TMP/out.env" || true)"

echo "-- the regression this test exists for: review run's branch != dispatch branch --"
run_validate REVIEW_BRANCH="trusted-fork/pr-42-2222222"
check "exits non-zero"          "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
check "names both branches"     "1" "$(grep -c 'trusted-fork/pr-42-2222222' "$TMP/out" || true)"
check "cites the runbook"       "1" "$(grep -c 'ci-troubleshooting.md 1.2' "$TMP/out" || true)"

echo "-- same PR/SHA/title, cited from a SHA-suffixed branch while dispatched on the bare one --"
run_validate GITHUB_REF="refs/heads/trusted-fork/pr-42" REVIEW_BRANCH="trusted-fork/pr-42-3333333"
check "exits non-zero"          "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"

echo "-- existing checks still hold (byproduct of the harness, not new coverage) --"
run_validate PR_STATE=closed
check "PR not open: exits non-zero"      "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
run_validate PR_SHA="b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
check "PR moved: exits non-zero"         "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
run_validate PR_HEAD_REPO="DevNullLtd/Yuzu"
check "not a fork PR: exits non-zero"    "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
run_validate REVIEW_WORKFLOW="Some other workflow"
check "wrong review workflow: exits non-zero" "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
run_validate REVIEW_TITLE="Fork review PR #42 @ deadbeef"
check "title doesn't bind PR/SHA: exits non-zero" "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
run_validate REVIEW_CONCLUSION=failure
check "review run failed: exits non-zero" "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"

echo
echo "trusted-fork-ci.yml validate-approval: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
