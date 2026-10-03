#!/usr/bin/env bash
# dispatch-runner-job.sh — shared helper for dispatching a workflow on a
# self-hosted runner, polling until the run completes, and downloading its
# artifacts into a cache directory. Consumed by:
#
#   - scripts/test/sanitizer-gate.sh   (PR2) → sanitizer-tests.yml on the Big Tam pool
#   - scripts/test/test-ota-fetch-windows-binary.sh (PR3) → build-windows-agent.yml
#
# The gates treat runner unavailability as WARN (not FAIL) so the rest of
# the /test run can proceed. This script exits:
#
#   0  success (workflow completed successfully, artifacts downloaded)
#   1  hard error (malformed args, gh missing, workflow doesn't exist)
#   2  workflow ran but failed (caller should mark FAIL)
#   3  runner unavailable / dispatch timed out (caller should mark WARN)
#
# Usage:
#   bash scripts/test/dispatch-runner-job.sh \
#       --workflow sanitizer-tests.yml \
#       --ref "$(git rev-parse HEAD)" \
#       --out-dir "$ART_DIR" \
#       [--inputs '{"suite":"asan"}'] \
#       [--timeout-minutes 60] \
#       [--poll-seconds 30] \
#       [--expect-runner yuzu-bigtam-linux]
#
# Behaviour notes:
#
# 1. The workflow must exist in the current branch's .github/workflows/.
#    We don't upload-the-workflow-first; the operator is expected to have
#    pushed the workflow file ahead of time. For dev iterations,
#    `--ref $(git rev-parse HEAD)` targets the commit under test.
#
# 2. `gh run list` + `gh run view` is the polling mechanism. We match the
#    run by its created_at timestamp crossing the dispatch threshold AND
#    the workflow name, so concurrent dispatches of the same workflow
#    don't confuse each other. The matched run ID is then cached in
#    $OUT_DIR/.run-id for idempotent re-polling.
#
# 3. Timeouts: default 60 minutes total (--timeout-minutes) with 30s
#    polls (--poll-seconds). The "queued" state counts against the
#    timeout — if the runner is offline, the dispatch sits queued and
#    eventually times out, which surfaces as exit 3 (WARN).
#
# 4. Artifacts: every artifact on the completed run is downloaded via
#    `gh run download` into --out-dir. The caller is responsible for
#    parsing the layout (they know what their workflow uploaded).

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

WORKFLOW=""
REF=""
OUT_DIR=""
INPUTS=""
TIMEOUT_MINUTES=60
POLL_SECONDS=30
EXPECT_RUNNER=""
REPO_OVERRIDE=""

usage() {
    cat <<EOF
usage: $0 --workflow FILE --ref SHA --out-dir DIR [options]

Required:
  --workflow FILE        workflow filename (e.g. sanitizer-tests.yml)
  --ref SHA              git ref or SHA to dispatch against
  --out-dir DIR          directory for downloaded artifacts (created if missing)

Optional:
  --inputs JSON          workflow_dispatch inputs as a JSON object string
  --timeout-minutes N    total wall-clock budget (default: 60)
  --poll-seconds N       polling interval while waiting (default: 30)
  --expect-runner NAME   warn-only: label a completed run WARN if it didn't
                         run on a runner named NAME or NAME-<digits>, so a
                         pool name such as yuzu-bigtam-linux matches
                         yuzu-bigtam-linux-0..3 (helps catch "ran on GH-hosted
                         fallback" drift when the self-hosted runner was down)
  --repo OWNER/NAME      override the repo (default: from gh repo view)

Exit codes:
  0 success, artifacts downloaded
  1 hard error (bad args, gh missing, workflow missing)
  2 workflow ran but failed
  3 runner unavailable / dispatch timed out (caller should WARN, not FAIL)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workflow)         WORKFLOW="$2"; shift 2 ;;
        --ref)              REF="$2"; shift 2 ;;
        --out-dir)          OUT_DIR="$2"; shift 2 ;;
        --inputs)           INPUTS="$2"; shift 2 ;;
        --timeout-minutes)  TIMEOUT_MINUTES="$2"; shift 2 ;;
        --poll-seconds)     POLL_SECONDS="$2"; shift 2 ;;
        --expect-runner)    EXPECT_RUNNER="$2"; shift 2 ;;
        --repo)             REPO_OVERRIDE="$2"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        *)                  echo "dispatch-runner-job: unknown arg: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$WORKFLOW" || -z "$REF" || -z "$OUT_DIR" ]]; then
    echo "dispatch-runner-job: missing required argument" >&2
    usage >&2
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "dispatch-runner-job: gh CLI not on PATH (install 'gh' or exit 3 for WARN)" >&2
    exit 3
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "dispatch-runner-job: jq not on PATH (required for polling logic)" >&2
    exit 1
fi

REPO="${REPO_OVERRIDE}"
if [[ -z "$REPO" ]]; then
    REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
fi
if [[ -z "$REPO" ]]; then
    echo "dispatch-runner-job: could not determine repo (pass --repo OWNER/NAME)" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

echo "dispatch-runner-job: workflow=$WORKFLOW ref=$REF repo=$REPO out=$OUT_DIR"

# ── Step 1: dispatch the workflow ────────────────────────────────────────
#
# `gh workflow run` is fire-and-forget — it does not return a run ID.
# Capture the pre-dispatch wall-clock timestamp (UTC ISO-8601) so we can
# scan forward for a NEW run whose createdAt is strictly greater than the
# dispatch moment AND whose headSha matches our target ref. Using both
# filters (timestamp + headSha) makes the discovery robust against
# concurrent dispatches of the same workflow by other operators/CI
# (UP-14 / hp-B2 / qa-N3 race fix).

DISPATCH_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Resolve the target ref to a concrete SHA so we can filter on headSha.
# --ref accepts branch names and tags as well as SHAs; gh resolves
# internally, but the run list JSON reports the SHA, so we need ours too.
#
# sec-h-2: strictly resolve via git rev-parse. If resolution fails we
# do NOT fall back to echoing $REF verbatim — an unresolvable ref
# could contain arbitrary characters that would get smuggled into the
# jq filter below. Require a clean hex SHA or a ref that git knows.
if ! TARGET_SHA=$(git rev-parse --verify "$REF^{commit}" 2>/dev/null); then
    echo "dispatch-runner-job: --ref '$REF' did not resolve to a commit via 'git rev-parse --verify'; refusing to dispatch" >&2
    exit 1
fi
# Extra defense-in-depth: TARGET_SHA should be hex[40] (or hex[64] for
# SHA-256 repos). Anything else means git rev-parse returned unexpected
# output (newlines, multi-line). Reject it.
if [[ ! "$TARGET_SHA" =~ ^[0-9a-f]{40,64}$ ]]; then
    echo "dispatch-runner-job: git rev-parse produced non-hex SHA '$TARGET_SHA'; refusing to dispatch" >&2
    exit 1
fi
echo "dispatch-runner-job: dispatch-ts=$DISPATCH_TS target-sha=$TARGET_SHA"

DISPATCH_ARGS=(--repo "$REPO" --ref "$REF")
if [[ -n "$INPUTS" ]]; then
    # Inputs come in via --raw-field KEY=VALUE pairs. Parse the JSON once
    # with jq and fan out. Keep values unquoted — gh quotes for us.
    # Reject values containing newlines to prevent split-injection into
    # --raw-field (UP-4). jq's @sh would over-escape; we filter explicitly.
    while IFS= read -r kv; do
        if [[ "$kv" == *$'\n'* ]]; then
            echo "dispatch-runner-job: --inputs value contains newline, rejecting" >&2
            exit 1
        fi
        DISPATCH_ARGS+=(--raw-field "$kv")
    done < <(echo "$INPUTS" | jq -r 'to_entries[] | "\(.key)=\(.value)"')
fi

if ! gh workflow run "$WORKFLOW" "${DISPATCH_ARGS[@]}" 2>&1; then
    echo "dispatch-runner-job: gh workflow run failed (workflow missing on $REF?)" >&2
    exit 1
fi

echo "dispatch-runner-job: dispatched; waiting for new run since $DISPATCH_TS"

# ── Step 2: find the new run ID ─────────────────────────────────────────
#
# Poll `gh run list` until we see a run that:
#   - matches this workflow
#   - has createdAt > DISPATCH_TS (strictly after our dispatch moment)
#   - has headSha == TARGET_SHA when we have a concrete SHA
#
# Both filters are applied in a jq expression so concurrent dispatches by
# another caller (same workflow, different SHA) don't collide with us.
#
# Short 3 s ticks for the discovery phase so we don't miss a fast-start
# run. Cap discovery at 3 minutes; after that assume the dispatch never
# produced a run (exit 3 WARN).

NEW_RUN_ID=""
DISCOVERY_DEADLINE=$(( $(date +%s) + 180 ))
while [[ $(date +%s) -lt $DISCOVERY_DEADLINE ]]; do
    # sec-h-2: The jq filter is a static string (no shell-interpolated
    # variables). Operator-controlled values flow through JSON decoder
    # via jq's `--slurpfile` / positional args. Since gh's `--jq` does
    # not support `--arg`, we use a jq function with environment
    # variables via the `env` object, which jq exposes for every process
    # env var. DISPATCH_TS and TARGET_SHA are already validated
    # (TARGET_SHA is hex-only; DISPATCH_TS is a date format), but we
    # treat them as untrusted by piping through env to avoid ever
    # splicing them as jq syntax.
    CANDIDATE=$(DISPATCH_TS="$DISPATCH_TS" TARGET_SHA="$TARGET_SHA" \
        gh run list \
            --repo "$REPO" \
            --workflow "$WORKFLOW" \
            --limit 20 \
            --json databaseId,createdAt,headSha \
            --jq '[.[] | select(.createdAt > env.DISPATCH_TS) | select(.headSha == env.TARGET_SHA)] | sort_by(.createdAt) | .[0].databaseId' \
            2>/dev/null || echo "")
    if [[ -n "$CANDIDATE" && "$CANDIDATE" != "null" ]]; then
        NEW_RUN_ID="$CANDIDATE"
        break
    fi
    sleep 3
done

if [[ -z "$NEW_RUN_ID" ]]; then
    echo "dispatch-runner-job: no new run matching ts>$DISPATCH_TS headSha=$TARGET_SHA within 180s — runner likely offline or workflow missing" >&2
    exit 3
fi

echo "dispatch-runner-job: tracking run $NEW_RUN_ID"
# Cache for idempotent re-polling if the operator re-runs this helper.
echo "$NEW_RUN_ID" > "$OUT_DIR/.run-id"

# ── Step 3: wait for completion ─────────────────────────────────────────
#
# `gh run view <id> --json status,conclusion` is the source of truth.
# States: queued, in_progress, completed. Conclusions on completed:
# success, failure, cancelled, skipped, timed_out, action_required,
# neutral, stale.

DEADLINE=$(( $(date +%s) + TIMEOUT_MINUTES * 60 ))
LAST_STATUS=""
while :; do
    NOW=$(date +%s)
    if [[ $NOW -ge $DEADLINE ]]; then
        echo "dispatch-runner-job: run $NEW_RUN_ID did not complete in ${TIMEOUT_MINUTES}m — giving up" >&2
        exit 3
    fi
    INFO=$(gh run view "$NEW_RUN_ID" \
        --repo "$REPO" \
        --json status,conclusion,createdAt 2>/dev/null || echo "")
    if [[ -z "$INFO" ]]; then
        echo "dispatch-runner-job: gh run view failed, retrying"
        sleep "$POLL_SECONDS"
        continue
    fi
    STATUS=$(echo "$INFO" | jq -r .status)
    CONCLUSION=$(echo "$INFO" | jq -r .conclusion)
    if [[ "$STATUS" != "$LAST_STATUS" ]]; then
        echo "dispatch-runner-job: run $NEW_RUN_ID status=$STATUS conclusion=${CONCLUSION:-null}"
        LAST_STATUS="$STATUS"
    fi
    if [[ "$STATUS" == "completed" ]]; then
        break
    fi
    sleep "$POLL_SECONDS"
done

# ── Step 4: sanity check the runner if requested ────────────────────────
#
# When --expect-runner is set, query the job labels on the run and look
# for the expected runner label. The runner_name field in the jobs API
# is authoritative but only populated post-completion.

if [[ -n "$EXPECT_RUNNER" ]]; then
    RUNNER_USED=$(gh api "/repos/$REPO/actions/runs/$NEW_RUN_ID/jobs" \
        -q '.jobs[0].runner_name' 2>/dev/null || echo "")
    if [[ -z "$RUNNER_USED" ]]; then
        echo "dispatch-runner-job: warn — could not determine runner_name for run $NEW_RUN_ID"
    elif [[ "$RUNNER_USED" != "$EXPECT_RUNNER" && "$RUNNER_USED" != "$EXPECT_RUNNER"-[0-9]* ]]; then
        echo "dispatch-runner-job: warn — ran on '$RUNNER_USED', expected '$EXPECT_RUNNER'"
    else
        echo "dispatch-runner-job: ran on expected runner $RUNNER_USED"
    fi
fi

# ── Step 5: download artifacts ──────────────────────────────────────────
#
# gh run download puts each artifact in its own subdirectory under
# --dir. If the run produced no artifacts, the command succeeds silently.

if ! gh run download "$NEW_RUN_ID" --repo "$REPO" --dir "$OUT_DIR" 2>/dev/null; then
    # "no artifacts found" also returns non-zero; distinguish by checking
    # whether OUT_DIR has any non-dotfile content.
    shopt -s nullglob
    content=("$OUT_DIR"/*)
    if [[ ${#content[@]} -eq 0 ]]; then
        echo "dispatch-runner-job: no artifacts on run $NEW_RUN_ID"
    fi
    shopt -u nullglob
fi

# ── Step 6: report success/failure ─────────────────────────────────────

echo "dispatch-runner-job: run $NEW_RUN_ID conclusion=$CONCLUSION"
case "$CONCLUSION" in
    success)
        exit 0
        ;;
    failure|timed_out|cancelled|action_required|stale)
        exit 2
        ;;
    skipped|neutral)
        # Skipped/neutral means the workflow had nothing to do — treat
        # as WARN rather than FAIL because it's ambiguous.
        echo "dispatch-runner-job: run $NEW_RUN_ID completed with ambiguous conclusion '$CONCLUSION'" >&2
        exit 3
        ;;
    *)
        echo "dispatch-runner-job: unknown conclusion '$CONCLUSION' — treating as FAIL" >&2
        exit 2
        ;;
esac
