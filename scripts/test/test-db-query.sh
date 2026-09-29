#!/usr/bin/env bash
# test-db-query.sh — Operator-facing query wrapper for the test-runs DB.
#
# Thin wrapper around `python3 scripts/test/test_db.py`. Power users can
# run that directly or `python3 -c "import sqlite3; ..."` against
# ~/.local/share/yuzu/test-runs.db for ad-hoc analysis.
#
# Test-runs queries (default subcommand if first arg is unrecognised):
#   bash scripts/test/test-db-query.sh                           # last 10 runs
#   bash scripts/test/test-db-query.sh --latest                  # most recent + gate detail
#   bash scripts/test/test-db-query.sh --last 20
#   bash scripts/test/test-db-query.sh --diff RUN_A RUN_B
#   bash scripts/test/test-db-query.sh --trend metric=branch_coverage_overall
#   bash scripts/test/test-db-query.sh --flaky --days 30
#   bash scripts/test/test-db-query.sh --export RUN_ID
#   bash scripts/test/test-db-query.sh --prune 100
#
# CI-runs queries (PR-9 of CI overhaul plan):
#   bash scripts/test/test-db-query.sh ci-stats                  # 7d aggregate
#   bash scripts/test/test-db-query.sh ci-stats --since 14d
#   bash scripts/test/test-db-query.sh ci-suite-stats --since 14d
#   bash scripts/test/test-db-query.sh ci-flakes --since 30d
#   bash scripts/test/test-db-query.sh ci-ingest                 # backfill from gh
#   bash scripts/test/test-db-query.sh ci-ingest --branch dev --limit 100

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# First positional arg routes to a ci-* subcommand if it matches; otherwise
# falls through to the legacy `query` surface.
case "${1:-}" in
  ci-stats|ci-suite-stats|ci-flakes|ci-ingest|ci-record|ci-import-junit)
    exec python3 "$HERE/test_db.py" "$@"
    ;;
esac

exec python3 "$HERE/test_db.py" query "$@"
