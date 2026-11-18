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
    # At fetch-depth 1 the merge commit is a shallow boundary and lists no
    # parents, which reads exactly like a non-merge: name both causes.
    echo "pr-merge-parent: $MERGE shows $(($# - 1)) parent(s), not two: either it is not a merge commit or the checkout is too shallow (use fetch-depth 2 or more) — failing closed" >&2
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
  # Hermetic git: no inherited GIT_* (a hook context sets GIT_DIR and the
  # fixture commits would land in THAT repo), and no global/system config.
  local v
  for v in $(env | sed -n 's/^\(GIT_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_pr_merge_parent.XXXXXX")"
  # EXIT, not RETURN: a failed fixture setup exits the script under set -e.
  trap "rm -rf '$tmp'" EXIT
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
  # The pins match the EXECUTED lines (comments stripped), not a mention.
  local root wf code want n
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  pin() { # workflow, fixed-string executed line, description
    code="$(sed -E 's/^[[:space:]]*#.*$//' "$root/.github/workflows/$1")"
    if ! grep -qF -- "$2" <<<"$code"; then
      echo "FAIL: .github/workflows/$1 no longer $3" >&2
      fails=$((fails + 1))
    fi
  }
  pin docs-lint.yml 'BASE="$(bash scripts/ci/pr-merge-parent.sh "$HEAD_SHA" "$PR_HEAD_SHA")"' \
    "sets the README touch rule's BASE from pr-merge-parent.sh"
  pin docs-lint.yml 'scripts/ci/check-plugin-readme-touch.sh "$BASE" "$HEAD_SHA"' \
    "passes that BASE to check-plugin-readme-touch.sh"
  pin plugin-spawn-gate.yml 'PR_BASE="$(bash scripts/ci/pr-merge-parent.sh "$HEAD_SHA" "$PR_HEAD_SHA")"' \
    "sets the spawn scan's PR base from pr-merge-parent.sh"
  pin plugin-spawn-gate.yml 'echo "ref=$PR_BASE" >> "$GITHUB_OUTPUT"' \
    "hands that base to the scan step"
  pin plugin-spawn-gate.yml 'BASE_REF: ${{ steps.base.outputs.ref }}' \
    "feeds the scan step's BASE_REF from that output"
  pin plugin-spawn-gate.yml 'check-plugin-spawn-lexical.sh --base "$BASE_REF"' \
    "passes BASE_REF to the scan"
  # The spawn gate must not read the event's base.sha at all; docs-lint keeps
  # exactly one use, in the changelog-fragments job (see the touch-rule step).
  for wf in plugin-spawn-gate.yml docs-lint.yml; do
    code="$(sed -E 's/^[[:space:]]*#.*$//' "$root/.github/workflows/$wf")"
    want=0; [ "$wf" = docs-lint.yml ] && want=1
    n="$(grep -cF 'pull_request.base.sha' <<<"$code" || true)"
    if [ "$n" -ne "$want" ]; then
      echo "FAIL: .github/workflows/$wf uses pull_request.base.sha $n time(s), expected $want" >&2
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
