#!/usr/bin/env bash
# release-legs-issue.sh — open, update or close the `release-legs-broken` issue
# from the outcome of ONE completed CI dispatch run on dev (docs/ci-architecture.md,
# Tier 2b). The single copy of this logic, called by:
#   - release-legs-alert.yml (workflow_run listener; fast path, mode `event`)
#   - release-legs-daily.yml (daily reconcile before dispatching; backstop,
#     mode `reconcile`), so a missed or failed listener run, or a run that
#     never started, is still reported within a day.
#
# Usage: release-legs-issue.sh <event|reconcile> <run-id>
# Env:   GH_TOKEN, REPO (owner/name). Needs `gh` and `jq`.
#
# Decision, from the run's conclusion and its job list:
#   success + every OS (Linux, Windows MSVC, macOS) has >=1 `... [dispatch]`
#     build leg and every such leg succeeded + this is the newest completed
#     non-cancelled dispatch run on dev                            -> close every open issue
#     opened before this run finished (a later report is not answered by it)
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
run_json=$(gh run view "$run_id" -R "$REPO" --json conclusion,headSha,headBranch,event,url,updatedAt,jobs)
conclusion=$(jq -r '.conclusion // ""' <<<"$run_json")
head_sha=$(jq -r '.headSha // ""' <<<"$run_json")
url=$(jq -r '.url // ""' <<<"$run_json")
# Defence in depth: the callers already filter to dev + workflow_dispatch.
if [[ "$(jq -r '.event' <<<"$run_json")" != workflow_dispatch || "$(jq -r '.headBranch' <<<"$run_json")" != dev ]]; then
  echo "run $run_id is not a workflow_dispatch run on dev — nothing to do"; exit 0
fi
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::bad head sha '$head_sha'"; exit 1; }

# No `|| true`: an API error must fail this job (red), never read as "no open
# issue" (which would open a duplicate, or silently skip a close).
open_json=$(gh issue list -R "$REPO" --label "$label" --state open \
              --author "app/github-actions" --json number,createdAt)
open=$(jq -r '.[].number' <<<"$open_json")

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
    # Only the NEWEST completed (non-cancelled) dispatch run on dev may close:
    # re-running an older run's failed jobs to green must not close an issue
    # while a newer run is still red.
    latest=$(gh run list -R "$REPO" --workflow ci.yml --event workflow_dispatch --branch dev \
               --status completed --limit 20 --json databaseId,conclusion \
               --jq '[.[] | select(.conclusion != "cancelled" and .conclusion != "skipped")][0].databaseId // empty')
    if [[ "$latest" != "$run_id" ]]; then
      echo "run $run_id is green but not the newest completed dispatch run (${latest:-none}) — leaving issues as they are"; exit 0
    fi
    # Close only issues opened BEFORE this run finished: a green run says
    # nothing about a failure reported after it (e.g. a dispatcher failure the
    # next day, judged by reconcile against this older green run).
    finished=$(jq -r '.updatedAt // ""' <<<"$run_json")
    closable=$(jq -r --arg t "$finished" '.[] | select(.createdAt < $t) | .number' <<<"$open_json")
    for n in $closable; do
      gh issue comment "$n" -R "$REPO" --body "$body"
      gh issue close "$n" -R "$REPO" --reason completed
      echo "closed #$n"
    done
    exit 0 ;;
esac

# Failure of some kind. In event mode, a report for a run that a newer
# completed (non-cancelled) dispatch run has already superseded is dropped:
# workflow_run events arrive in no fixed order, and the newer run's own
# event or the daily reconcile speaks for dev's current state.
if [[ "$mode" == event ]]; then
  latest=$(gh run list -R "$REPO" --workflow ci.yml --event workflow_dispatch --branch dev \
             --status completed --limit 20 --json databaseId,conclusion \
             --jq '[.[] | select(.conclusion != "cancelled" and .conclusion != "skipped")][0].databaseId // empty')
  if [[ -n "$latest" && "$latest" != "$run_id" ]]; then
    echo "run $run_id failed but newer dispatch run $latest has completed — not reporting a superseded run"; exit 0
  fi
fi
failed=$(jq -r '[.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "cancelled") | .name] | join(", ")' <<<"$run_json")
njobs=$(jq '.jobs | length' <<<"$run_json")
# Infrastructure: the trusted-inputs or preflight GATE failed (every job after
# it is then skipped or fails closed, proto-compat included, so ignore those),
# or only preflight-class jobs failed.
infra_only=$(jq '[.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "cancelled") | .name] as $f
                | ($f | length > 0)
                  and (($f | any(test("^(Validate trusted CI inputs|Preflight \\(gate\\))$")))
                       or ($f | all(test("^(Validate trusted CI inputs|Preflight \\(gate\\)|Preflight \\(runner health\\)( \\[dispatch\\])?)$"))))' <<<"$run_json")
if [[ "$njobs" == 0 ]]; then
  cause="The CI run never started any job (conclusion \`$conclusion\`): most likely a workflow-load or permission error in dev's ci.yml. Every dev push is probably failing the same way."
elif [[ "$infra_only" == true ]]; then
  cause="The preflight gate (or only preflight jobs) failed, so this is most likely **infrastructure** (an unhealthy runner pool, a runner-health or source gate, or dev advancing while the preflight checked out its tip), not a code regression; jobs after the gate were skipped or failed closed. Check the Preflight (gate) log first."
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
title="Release legs broken on dev: ${failed:-run did not start}"
(( ${#title} <= 200 )) || title="${title:0:197}..."   # GitHub caps titles at 256
gh issue create -R "$REPO" --title "$title" \
  --label "$label" --body "$body"
