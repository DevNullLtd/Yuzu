#!/usr/bin/env bash
# release-legs-issue.sh — open, update or close the `release-legs-broken` issue
# from the outcome of ONE completed CI dispatch run on dev (docs/ci-architecture.md,
# Tier 2b). The single copy of this logic, called by:
#   - release-legs-alert.yml (workflow_run listener; fast path, mode `event`)
#   - release-legs-daily.yml (daily reconcile before dispatching; backstop,
#     mode `reconcile`), so a missed or failed listener run, or a run that
#     never started, is still reported within a day, and an issue opened by a
#     dispatcher failure is closed once dev's tip is known green.
#
# Usage: release-legs-issue.sh <event|reconcile> <run-id>
# Env:   GH_TOKEN, REPO (owner/name). Needs `gh` and `jq`.
#
# Decision, from the run's conclusion and its job list:
#   success + every OS (Linux, Windows MSVC, macOS) has >=1 `... [dispatch]`
#     build leg and every such leg succeeded        -> close every open issue
#   success otherwise (a leg skipped/missing)       -> leave issues as they are
#   cancelled / skipped                             -> nothing (an operator
#     cancel, or a pending dispatch replaced by a newer one; the daily check
#     re-dispatches an uncovered tip)
#   anything else (failure, timed_out, startup_failure, ...) -> report:
#     event mode comments on the open issue or opens one; reconcile mode opens
#     one only if none is open (the listener already commented on this run).
# Only OPEN ISSUES authored by github-actions[bot] carrying the label are ever
# touched (gh issue list never returns PRs), so a hand-labelled issue is safe.
set -euo pipefail

mode=${1:?usage: release-legs-issue.sh <event|reconcile> <run-id>}
run_id=${2:?usage: release-legs-issue.sh <event|reconcile> <run-id>}
: "${REPO:?REPO (owner/name) is required}"
[[ "$mode" == event || "$mode" == reconcile ]] || { echo "::error::bad mode '$mode'"; exit 2; }
[[ "$run_id" =~ ^[0-9]+$ ]] || { echo "::error::bad run id '$run_id'"; exit 2; }

label=release-legs-broken
run_json=$(gh run view "$run_id" -R "$REPO" --json conclusion,headSha,headBranch,event,url,jobs)
conclusion=$(jq -r '.conclusion // ""' <<<"$run_json")
head_sha=$(jq -r '.headSha // ""' <<<"$run_json")
url=$(jq -r '.url // ""' <<<"$run_json")
# Defence in depth: the callers already filter to dev + workflow_dispatch.
if [[ "$(jq -r '.event' <<<"$run_json")" != workflow_dispatch || "$(jq -r '.headBranch' <<<"$run_json")" != dev ]]; then
  echo "run $run_id is not a workflow_dispatch run on dev — nothing to do"; exit 0
fi
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::bad head sha '$head_sha'"; exit 1; }

open=$(gh issue list -R "$REPO" --label "$label" --state open \
         --author "app/github-actions" --json number --jq '.[].number' 2>/dev/null || true)

case "$conclusion" in
  cancelled|skipped|"")
    echo "run $run_id conclusion '${conclusion:-none}' — nothing to report"; exit 0 ;;
  success)
    legs_ok=$(jq '[.jobs[] | select(.name | test("^(Linux|Windows MSVC|macOS) .*\\[dispatch\\]$"))] as $l
                  | ($l | length > 0) and ($l | all(.conclusion == "success"))
                    and ([ "Linux", "Windows MSVC", "macOS" ]
                         | all(. as $os | $l | any(.name | startswith($os + " "))))' <<<"$run_json")
    if [[ "$legs_ok" != true ]]; then
      echo "run $run_id succeeded but not every OS had a passing dispatch build leg — leaving issues as they are"; exit 0
    fi
    body=$(printf '%s\n\n%s\n' \
      "Release-legs dispatch on \`dev\` @ \`$head_sha\` is **green** (every OS leg passed): $url" \
      "(auto-closed by scripts/ci/release-legs-issue.sh; a later failing dispatch opens a new issue.)")
    for n in $open; do
      gh issue comment "$n" -R "$REPO" --body "$body"
      gh issue close "$n" -R "$REPO" --reason completed
      echo "closed #$n"
    done
    exit 0 ;;
esac

# Failure of some kind.
failed=$(jq -r '[.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "cancelled") | .name] | join(", ")' <<<"$run_json")
njobs=$(jq '.jobs | length' <<<"$run_json")
infra_only=$(jq '[.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "cancelled") | .name]
                | (length > 0) and all(test("^(Validate trusted CI inputs|Preflight \\(gate\\)|Preflight \\(runner health\\)( \\[dispatch\\])?)$"))' <<<"$run_json")
if [[ "$njobs" == 0 ]]; then
  cause="The CI run never started any job (conclusion \`$conclusion\`): most likely a workflow-load or permission error in dev's ci.yml. Every dev push is probably failing the same way."
elif [[ "$infra_only" == true ]]; then
  cause="Only the preflight jobs failed, so this is most likely **infrastructure** (an unhealthy runner pool, a runner-health or source gate, or dev moving during the checkout check), not a code regression. Check the Preflight (gate) log first."
else
  cause="A build or test leg failed. If it is a real failure rather than a flake or an infrastructure timeout, a release-only regression landed on dev since the last green dispatch."
fi
body=$(printf '%s\n\n%s\n\n%s\n\n%s\n\n%s\n\n%s\n' \
  "Release-legs dispatch failed on \`dev\` (dispatched at \`$head_sha\`, conclusion \`$conclusion\`)." \
  "**Failed jobs:** ${failed:-none reported}" \
  "$cause" \
  "**Run:** $url" \
  "Each build leg checks out the dev BRANCH when it starts, so it may have built a later commit than the dispatched one; its \"Record built commit (dispatch)\" step names the exact commit. Triage and bisect recipe: docs/ci-architecture.md, Tier 2b." \
  "(auto-posted by scripts/ci/release-legs-issue.sh in $mode mode; closed automatically by the next fully green dispatch.)")

first=$(head -n1 <<<"$open")
if [[ -n "$first" ]]; then
  if [[ "$mode" == event ]]; then
    gh issue comment "$first" -R "$REPO" --body "$body"
    echo "commented on #$first"
  else
    echo "issue #$first already open — reconcile adds nothing"
  fi
  exit 0
fi
# gh resolves --label by name and refuses an absent one; create it (idempotent).
gh label create "$label" -R "$REPO" --color ededed --force \
  --description "Daily release/LTO legs on dev failed (docs/ci-architecture.md Tier 2b)"
gh issue create -R "$REPO" --title "Release legs broken on dev: ${failed:-run did not start}" \
  --label "$label" --body "$body"
