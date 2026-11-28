#!/usr/bin/env bash
# test-db-write.sh — Helper for /test gates to record results to the DB.
#
# Thin wrapper around scripts/test/test_db.py. Subcommands:
#
#   run-start  --run-id ID --commit SHA --branch B --mode MODE [--notes N]
#       Open a new test_runs row in RUNNING state and create the per-run
#       log directory under ~/.local/share/yuzu/test-runs/${RUN_ID}/.
#
#   run-finish --run-id ID [--status PASS|FAIL|WARN|ABORTED|SKIP]
#       Aggregate gate counts, set finished_at/total_duration_seconds, and
#       compute overall_status: any recorded FAIL→FAIL; unfinished/empty→ABORTED;
#       any recorded WARN→WARN; at least one PASS→PASS; otherwise all-SKIP→SKIP.
#       --status can worsen this verdict, never improve it. Its strongest value
#       persists through repeated finalization and subsequent gate writes.
#       Gates never recorded cannot be detected without a declared run plan.
#
#   gate    --run-id ID --phase N --gate NAME --status PASS|FAIL|WARN|SKIP|RUNNING|ABORTED \
#           --duration SECONDS [--log REL_PATH] [--notes "..."]
#       Append one immutable observation and update the latest gate result.
#       Repeating the write appends another observation; it is NOT idempotent.
#       A write after finalization reopens the run until run-finish is called.
#
#   timing  --run-id ID --gate NAME --step NAME --ms N
#       Record a sub-step duration in milliseconds. Idempotent.
#
#   metric  --run-id ID --name NAME --value FLOAT [--unit UNIT]
#       Record a quantitative measurement (coverage %, perf ops/sec, etc.).
#
# Honors YUZU_TEST_DB=path to override the default DB location.
# Writes without run-start create a manual capture. Its original commit, branch
# and start time stay fixed; reuse at another/unknown revision is refused.
# Choose a new --run-id for a capture at a new commit.
#
# Examples:
#   bash scripts/test/test-db-write.sh run-start \
#       --run-id "$RUN_ID" --commit "$(git rev-parse HEAD)" \
#       --branch dev --mode default
#   bash scripts/test/test-db-write.sh gate \
#       --run-id "$RUN_ID" --phase 2 --gate "Upgrade v0.10.0->HEAD" \
#       --status PASS --duration 192 --notes "8/8 fixtures preserved"
#   bash scripts/test/test-db-write.sh timing \
#       --run-id "$RUN_ID" --gate phase2 --step image-swap --ms 1240
#   bash scripts/test/test-db-write.sh metric \
#       --run-id "$RUN_ID" --name branch_coverage_overall --value 71.3 --unit %

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 {run-start|run-finish|gate|timing|metric} [args...]" >&2
    exit 2
fi

exec python3 "$HERE/test_db.py" "$@"
