#!/usr/bin/env bash
# bootstrap-labels.sh -- create the ADR-3001 (A1 par.7) automation labels. Idempotent:
# `gh label create --force` upserts, so re-running is always safe (same idiom as
# scripts/create_issues.sh). Run once from any authenticated checkout AT PR-1 MERGE,
# before the first agent filing: `task`/`decision` become filing-valid types the moment
# the issue standard lands, and a filing that names a nonexistent label fails at create.
# Verify afterwards:
#   gh label list --repo DevNullLtd/Yuzu --limit 100 | grep -E 'task|decision|do-not-close|fixed-on-dev|automation-broken|triage-sweep'
#
# Deliberately NOT a migration: the parallel priority-p* scheme was deleted in the
# 2026-07-14 consolidation, so there is nothing to migrate -- only these six labels
# are genuinely missing. See docs/adr/3001-issue-lifecycle-guardrails.md, Amendment A1.
set -euo pipefail

repo="DevNullLtd/Yuzu"

gh label create "task" --repo "$repo" --force \
    --description "Concrete engineering chore (type label)" --color "1d76db"
gh label create "decision" --repo "$repo" --force \
    --description "A choice to be made; the outcome is a recorded decision, not code (type label)" --color "c5def5"
gh label create "do-not-close" --repo "$repo" --force \
    --description "Automation must never close this issue (docs/agents/issue-standard.md 5.1)" --color "b60205"
gh label create "fixed-on-dev" --repo "$repo" --force \
    --description "Closed by dev-merge automation; fix not yet in a main release" --color "0e8a16"
gh label create "automation-broken" --repo "$repo" --force \
    --description "Tracker automation failure -- opened by the close-linked-issues alert job" --color "d93f0b"
gh label create "triage-sweep" --repo "$repo" --force \
    --description "Rolling tracking issue for the tracker report / triage sweep" --color "fbca04"

echo "bootstrap-labels: 6 labels ensured on $repo"
