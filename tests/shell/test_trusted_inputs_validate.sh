#!/usr/bin/env bash
# test_trusted_inputs_validate.sh — contract net for ci.yml's `trusted_inputs`
# validate step, the SOLE chokepoint deciding which commit every downstream CI
# job builds.
#
# WHY THIS EXISTS. Two independent reviewers of #2832 flagged the same gap: the
# adjacent shell gates run in that very job have dedicated tests
# (test_check_compose_versions.sh, test_detect_code_change.sh) while the step
# that picks the BUILD COMMIT had none, so nothing short of a live Actions run
# could catch a regression in it. #2832 itself is the proof: its first version
# pinned `checkout_ref` to a bare SHA for EVERY non-workflow_call trigger,
# including `push`, which leaves a self-hosted workspace in detached HEAD and
# permanently disarms the branch-switch build-dir wipe (that sentinel's guard is
# `current != "HEAD"`, and `git rev-parse --abbrev-ref HEAD` prints exactly
# "HEAD" when detached). No test saw it; a reviewer did.
#
# WHAT IT PINS. The branches of the step and the properties each must hold:
#
#   push               -> checkout_ref is a BRANCH REF (attached HEAD, so the
#                         branch-switch wipe still works), checkout_sha is the
#                         event commit, base_sha falls back to the event commit
#   pull_request       -> checkout_ref is the event SHA (immune to GitHub
#                         re-minting refs/pull/N/merge), and equals checkout_sha
#                         so `Verify resolved checkout` compares like with like;
#                         base_sha is the PR base
#   workflow_call, incomplete (no PR number / gate sentinel) -> rejected before
#                         any API call, never falling through to the untrusted
#                         branch
#   workflow_call, wrong cache scope (#4471) -> rejected before any API call:
#                         the dispatch ref is the run's GitHub Actions cache
#                         scope, so only a throwaway trusted-fork/pr-<N>[-<sha>]
#                         branch for THAT PR is accepted — never main, dev, or
#                         another PR's quarantine branch
#   workflow_call, approved in its quarantine scope -> both outputs pinned to
#                         the APPROVED head sha (never anything the fork
#                         controls at run time), trusted_execution=true,
#                         base_sha from the PR, checkout_repository the base
#                         repo
#   workflow_call, PR head moved between approval and dispatch -> rejected
#                         AFTER the API call (this is the one case that must
#                         call gh to detect), nothing pinned
#   workflow_call, malformed approved sha -> rejected outright
#
# The step's own body is extracted from ci.yml rather than duplicated here, so
# this test cannot drift into asserting a copy of the logic instead of the logic.
# `gh` is a hermetic stub (below): the approved path is exercised end to end
# without network, and a PATH slip is detected rather than silently hitting the
# real API.
#
# Run:  bash tests/shell/test_trusted_inputs_validate.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="$ROOT/.github/workflows/ci.yml"
[ -f "$CI_YML" ] || { echo "missing $CI_YML" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-trusted-inputs.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}

# ── Extract the step body from ci.yml ────────────────────────────────────────
# Take the `run: |` block of the `- id: validate` step, de-indent it, and
# substitute the two `${{ github.* }}` expressions the shell cannot evaluate with
# harness-controlled variables. Everything else runs verbatim.
python3 "$ROOT/tests/shell/extract_run_block.py" "$CI_YML" "$TMP/validate.sh" --id validate \
  --subst 'github.event_name=GH_EVENT_NAME' \
  --subst 'github.event.pull_request.base.sha=GH_BASE_SHA' || exit 2
grep -q 'checkout_ref=' "$TMP/validate.sh" || { echo "extracted body does not look like the validate step" >&2; exit 2; }

# ── Hermetic `gh` ────────────────────────────────────────────────────────────
# Answers ONLY the one PR read the trusted path makes, records that it was
# called, and refuses anything else. The harness exports GH_TOKEN EMPTY, which
# the real gh treats as unset and falls back to keyring auth — so a PATH slip
# would make a live network call that could masquerade as a refusal. The marker
# file is how the approved case proves the stub, not the network, answered.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
if [ "$#" -eq 2 ] && [ "$1" = "api" ] && [[ "$2" =~ ^repos/DevNullLtd/Yuzu/pulls/[1-9][0-9]*$ ]]; then
  : > "$STUB_MARKER"
  # STUB_ACTUAL_HEAD_SHA overrides what the "live" PR head is, independent of
  # STUB_HEAD_SHA (the approved SHA passed in) -- unset, it defaults to the
  # approved SHA, so every existing case is unaffected; set, it simulates a
  # PR that moved between approval and dispatch (test_trusted_inputs_validate.sh
  # "PR head moved" case).
  printf '{"state":"open","head":{"sha":"%s","repo":{"full_name":"someone/Yuzu"}},"base":{"sha":"%s"}}\n' \
    "${STUB_ACTUAL_HEAD_SHA:-$STUB_HEAD_SHA}" "$STUB_BASE_SHA"
  exit 0
fi
echo "stub gh: unexpected invocation: $*" >&2
exit 99
STUB
chmod +x "$TMP/bin/gh"

run_validate() { # run_validate <event> <github_ref> <github_sha> <approved_sha> <base_sha>
  # The trusted path additionally reads RV_PR_NUMBER / RV_TRUSTED_GATE from the
  # caller's environment (default empty, which the step refuses before any API
  # call). The stub `gh` answers with <approved_sha> as the PR head.
  : > "$TMP/out"; rm -f "$TMP/gh-called"
  ( set +e
    export PATH="$TMP/bin:$PATH" \
           GITHUB_OUTPUT="$TMP/out" GH_EVENT_NAME="$1" GITHUB_REF="$2" GITHUB_SHA="$3" \
           APPROVED_SHA="$4" GH_BASE_SHA="$5" \
           REPOSITORY="DevNullLtd/Yuzu" PR_NUMBER="${RV_PR_NUMBER:-}" TRUSTED_GATE="${RV_TRUSTED_GATE:-}" \
           GH_TOKEN="" STUB_MARKER="$TMP/gh-called" STUB_HEAD_SHA="$4" STUB_BASE_SHA="$5" \
           STUB_ACTUAL_HEAD_SHA="${RV_STUB_ACTUAL_HEAD_SHA:-}"
    bash "$TMP/validate.sh" >"$TMP/stdout" 2>"$TMP/stderr"
    echo $? > "$TMP/rc" )
  rc=$(cat "$TMP/rc")
}
out_of() { grep -E "^$1=" "$TMP/out" | tail -1 | cut -d= -f2-; }
gh_called() { [ -e "$TMP/gh-called" ] && echo yes || echo no; }
# A refusal on the trusted path must be total: non-zero, nothing pinned, no API
# call made, and (when given) the named diagnostic on stdout — the step reports
# with `::error::` on stdout, which is what a run log shows.
assert_refused() { # assert_refused <desc> <stdout-substring>
  if [ "$rc" != 0 ] && [ ! -s "$TMP/out" ] && [ "$(gh_called)" = no ] \
     && { [ -z "$2" ] || grep -qF -- "$2" "$TMP/stdout"; }; then
    printf '  [pass] %s (rc=%s)\n' "$1" "$rc"; pass=$((pass+1))
  else
    printf '  [FAIL] %s\n         rc=%s pinned=[%s] gh_called=%s\n         stdout: %s\n' \
      "$1" "$rc" "$(tr '\n' ' ' < "$TMP/out")" "$(gh_called)" "$(tr '\n' ' ' < "$TMP/stdout")"
    fail=$((fail+1))
  fi
}

SHA_EVENT=1111111111111111111111111111111111111111
SHA_BASE=2222222222222222222222222222222222222222

echo "-- push: must stay on a BRANCH ref, or the self-hosted branch-switch wipe dies --"
run_validate push "refs/heads/dev" "$SHA_EVENT" "" ""
check "exits 0"                          "0"                 "$rc"
check "checkout_ref is the branch ref"   "refs/heads/dev"    "$(out_of checkout_ref)"
check "checkout_sha is the event commit" "$SHA_EVENT"        "$(out_of checkout_sha)"
check "base_sha falls back to the event" "$SHA_EVENT"        "$(out_of base_sha)"
check "trusted_execution is false"       "false"             "$(out_of trusted_execution)"
# The property, stated as such: a bare 40-hex checkout_ref detaches HEAD.
if [[ "$(out_of checkout_ref)" =~ ^[0-9a-fA-F]{40}$ ]]; then
  printf '  [FAIL] push checkout_ref must NOT be a bare SHA (detaches HEAD, disarms the wipe)\n'; fail=$((fail+1))
else
  printf '  [pass] push checkout_ref is not a bare SHA\n'; pass=$((pass+1))
fi

echo "-- pull_request: must pin to the event SHA, immune to refs/pull/N/merge re-minting --"
run_validate pull_request "refs/pull/2832/merge" "$SHA_EVENT" "" "$SHA_BASE"
check "exits 0"                            "0"          "$rc"
check "checkout_ref is the event SHA"      "$SHA_EVENT" "$(out_of checkout_ref)"
check "checkout_sha is the event SHA"      "$SHA_EVENT" "$(out_of checkout_sha)"
check "ref == sha, so Verify is meaningful" "$(out_of checkout_sha)" "$(out_of checkout_ref)"
check "base_sha is the PR base"            "$SHA_BASE"  "$(out_of base_sha)"

APPROVED=3333333333333333333333333333333333333333
QUARANTINE="refs/heads/trusted-fork/pr-2832"

echo "-- workflow_call, approved sha but no PR number / gate sentinel: refuse, never fall through --"
run_validate pull_request "$QUARANTINE" "$SHA_EVENT" "$APPROVED" "$SHA_BASE"
assert_refused "incomplete trusted call refuses and pins nothing" ""

echo "-- workflow_call in the wrong cache scope (#4471): refuse before any API call --"
for ref in refs/heads/main refs/heads/dev refs/pull/2832/merge \
           refs/heads/trusted-fork/pr-999 refs/heads/trusted-fork/pr-28320 \
           refs/heads/trusted-fork/pr-2832-notasha refs/heads/trusted-fork/pr-2832/extra; do
  RV_PR_NUMBER=2832 RV_TRUSTED_GATE=sentinel \
    run_validate pull_request "$ref" "$SHA_EVENT" "$APPROVED" "$SHA_BASE"
  assert_refused "dispatch on $ref refused" "trusted-fork/pr-2832"
done

echo "-- workflow_call in its own quarantine scope: pinned to the approved commit --"
if command -v jq >/dev/null 2>&1; then
  for ref in "$QUARANTINE" "$QUARANTINE-3333333" "$QUARANTINE-$APPROVED"; do
    RV_PR_NUMBER=2832 RV_TRUSTED_GATE=sentinel \
      run_validate pull_request "$ref" "$SHA_EVENT" "$APPROVED" "$SHA_BASE"
    check "$ref: exits 0"                          "0"           "$rc"
    check "$ref: the stub gh answered (no network)" "yes"         "$(gh_called)"
    check "$ref: checkout_ref is the approved sha"  "$APPROVED"   "$(out_of checkout_ref)"
    check "$ref: checkout_sha is the approved sha"  "$APPROVED"   "$(out_of checkout_sha)"
    check "$ref: trusted_execution is true"         "true"        "$(out_of trusted_execution)"
    check "$ref: base_sha is the PR base"           "$SHA_BASE"   "$(out_of base_sha)"
    check "$ref: checkout_repository is the base repo" "DevNullLtd/Yuzu" "$(out_of checkout_repository)"
  done

  echo "-- workflow_call, PR head moved between approval and dispatch: refused, nothing pinned --"
  MOVED=4444444444444444444444444444444444444444
  RV_PR_NUMBER=2832 RV_TRUSTED_GATE=sentinel RV_STUB_ACTUAL_HEAD_SHA="$MOVED" \
    run_validate pull_request "$QUARANTINE" "$SHA_EVENT" "$APPROVED" "$SHA_BASE"
  check "exits non-zero"                 "1"   "$([ "$rc" != 0 ] && echo 1 || echo 0)"
  check "nothing pinned"                 ""    "$(cat "$TMP/out")"
  check "stub gh WAS called (post-check, not pre-check)" "yes" "$(gh_called)"
  check "names the mismatch"             "1"   "$(grep -c 'head moved' "$TMP/stdout" || true)"
else
  printf '  [skip] approved-path cases need jq (the step itself uses it); not installed here\n'
fi

echo "-- workflow_call, malformed approved sha: must never build it --"
RV_PR_NUMBER=2832 RV_TRUSTED_GATE=sentinel \
  run_validate pull_request "$QUARANTINE" "$SHA_EVENT" "not-a-sha" "$SHA_BASE"
assert_refused "malformed approved sha refused" ""

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
