#!/usr/bin/env bash
# pr-merge-parent.sh — print the diff base for a pull_request job: the FIRST
# PARENT of the checked-out refs/pull/<N>/merge commit, i.e. the target-branch
# tip GitHub merged the PR onto. Diffing that base against the merge commit is
# exactly the PR's own change, however far the target branch has moved.
#
#   pr-merge-parent.sh <MERGE_SHA> <PR_HEAD_SHA>    # prints the base SHA
#   pr-merge-parent.sh --selftest
#
# Why not github.event.pull_request.base.sha: it can lag the tip the merge
# commit was built on (on #8235 it was the tip from when the PR was opened), and
# a diff against it then reports every change the target branch gained in
# between as the PR's — a false red in a "did you touch X" rule, and a false
# GREEN in a grandfathering rule that treats base content as already accepted.
# doc-coupling.yml reached the same base inline (HEAD^1); this is the shared
# form, with the check below.
#
# FAILS CLOSED (exit 1, nothing on stdout) unless MERGE_SHA has exactly two
# parents and its second parent is PR_HEAD_SHA. The checkout must hold both
# parents (actions/checkout `fetch-depth: 2` or more).
set -euo pipefail

resolve() {
  local MERGE="$1" PRHEAD="$2" parents
  if ! parents="$(git rev-list --parents -n1 "$MERGE" 2>/dev/null)"; then
    echo "pr-merge-parent: cannot read $MERGE; check out at fetch-depth 2 or more — failing closed" >&2
    return 1
  fi
  # shellcheck disable=SC2086 # deliberate word split: "<sha> <parent>..."
  set -- $parents
  if [ "$#" -ne 3 ]; then
    echo "pr-merge-parent: $MERGE is not a two-parent merge commit — failing closed" >&2
    return 1
  fi
  if [ "$3" != "$PRHEAD" ]; then
    echo "pr-merge-parent: $MERGE does not merge the PR head $PRHEAD (second parent is $3)." >&2
    echo "  The merge ref is out of date for this event; push to the PR to get a fresh run (a re-run reuses the same event) — failing closed" >&2
    return 1
  fi
  printf '%s\n' "$2"
}

selftest() {
  local tmp rc fails=0 out
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  (
    cd "$tmp"
    git init -q -b main .
    git config user.name t; git config user.email t@example.invalid; git config commit.gpgsign false
    echo a > a; git add a; git commit -qm base0
    git checkout -qb pr; echo p > p; git add p; git commit -qm pr1
    git checkout -q main; echo b > b; git add b; git commit -qm base1
    git merge -q --no-ff --no-edit pr
  ) >/dev/null
  local M PR B0 B1
  M="$(git -C "$tmp" rev-parse HEAD)"; PR="$(git -C "$tmp" rev-parse pr)"
  B1="$(git -C "$tmp" rev-parse HEAD^1)"; B0="$(git -C "$tmp" rev-parse main~2)"

  check() { # name expected_rc expected_stdout merge prhead
    rc=0; out="$(cd "$tmp" && resolve "$4" "$5" 2>/dev/null)" || rc=$?
    if [ "$rc" -ne "$2" ] || [ "$out" != "$3" ]; then
      echo "FAIL: $1 (rc=$rc want $2, out='$out' want '$3')" >&2; fails=$((fails + 1))
    fi
  }
  check "merge commit gives its first parent, not the stale fork base" 0 "$B1" "$M" "$PR"
  [ "$B1" != "$B0" ] || { echo "FAIL: fixture has no stale base" >&2; fails=$((fails + 1)); }
  # The base must make the diff exactly the PR's change: p, and not b.
  [ "$(git -C "$tmp" diff --name-only "$B1" "$M")" = "p" ] \
    || { echo "FAIL: first-parent diff is not the PR's own change" >&2; fails=$((fails + 1)); }
  check "one-parent HEAD fails closed" 1 "" "$PR" "$PR"
  check "second parent that is not the PR head fails closed" 1 "" "$M" "$B0"
  check "unknown commit fails closed" 1 "" "0123456789abcdef0123456789abcdef01234567" "$PR"

  # The pull_request jobs that need this base must take it from here, never
  # from the event's base.sha (a revert to base.sha passes every fixture above).
  local root wf
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  for wf in docs-lint.yml plugin-spawn-gate.yml; do
    if ! grep -q 'scripts/ci/pr-merge-parent.sh' "$root/.github/workflows/$wf"; then
      echo "FAIL: .github/workflows/$wf no longer takes its PR base from pr-merge-parent.sh" >&2
      fails=$((fails + 1))
    fi
  done
  if [ "$fails" -ne 0 ]; then
    echo "pr-merge-parent --selftest: $fails check(s) failed" >&2
    return 1
  fi
  echo "pr-merge-parent --selftest: all checks passed."
}

case "${1:-}" in
  --selftest) selftest ;;
  *)
    [ "$#" -eq 2 ] || { echo "usage: pr-merge-parent.sh <MERGE_SHA> <PR_HEAD_SHA> | --selftest" >&2; exit 2; }
    resolve "$1" "$2"
    ;;
esac
