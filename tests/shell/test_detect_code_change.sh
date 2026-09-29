#!/usr/bin/env bash
# test_detect_code_change.sh — fixture tests for scripts/ci/detect-code-change.sh
#
# The classifier is the docs-only gate for ci.yml (issue #1978): it decides
# whether a PR skips the self-hosted build matrix. A silent regression (an
# ignore arm dropped, `*.md` accidentally matching nested paths, the truncation
# guard removed) would either block every docs PR again or, worse, let real
# code merge without the required build. This exercises the code/docs/mixed,
# root-vs-nested pattern semantics, the ignore set, and the 3000-file
# truncation guard hermetically — no network, no GitHub. It also exercises the
# named CI-infrastructure class against a temporary git repository, including
# the former false-green: an unresolvable diff base must select the canary.
#
# Run:  bash tests/shell/test_detect_code_change.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SCRIPT="$ROOT/scripts/ci/detect-code-change.sh"
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

pass=0 fail=0
# expect <want true|false> <desc> <authoritative-total> <newline-separated files>
expect() {
  local want="$1" desc="$2" total="$3" files="$4"
  local got
  got=$(printf '%s' "$files" | bash "$SCRIPT" "$total")
  if [ "$got" = "$want" ]; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s (want %s, got %s)\n' "$desc" "$want" "$got"; fail=$((fail + 1))
  fi
}

# --- docs-only: skip the build ---
expect false "adr + nested docs (docs/**)"        2 $'docs/adr/1005-headless.md\ndocs/adr-1005-execution-plan.md'
expect false "root markdown README.md"            1 $'README.md'
expect false "root LICENSE"                        1 $'LICENSE'
expect false "root .gitignore"                     1 $'.gitignore'
expect false "runner-inventory ignore files"      2 $'.github/runner-inventory.json\n.github/workflows/runner-inventory-sentinel.yml'

# --- code-side: run the full matrix ---
expect true  "single C++ source"                  1 $'server/core/src/server.cpp'
expect true  "mixed docs + code"                  2 $'docs/x.md\nserver/a.cpp'
expect true  "workflow change (ci.yml itself)"    1 $'.github/workflows/ci.yml'

# --- root-anchored semantics (C3 / K1): nested != root ---
expect true  "nested markdown is code-side"       1 $'sdk/README.md'
expect true  "changelog fragment (nested .md)"    1 $'changelog.d/1978-fix.fixed.md'
expect true  "nested LICENSE is code-side"        1 $'gateway/_checkouts/grpcbox/LICENSE'

# --- more root-anchored / boundary cases (K3) ---
expect false "root LICENSE.md (root *.md, not README)" 1 $'LICENSE.md'
expect true  "docs + nested markdown mixed"       2 $'docs/guide.md\nsdk/README.md'

# --- #2204 PR1.1: docs/os-capability-matrix.md is carved OUT of docs/** ---
# It carries a machine-generated block (tools/capmatrix-gen +
# scripts/ci/check-capability-matrix.sh); a hand-edit there must still run
# the build/gate matrix, unlike an ordinary docs/** change.
expect true  "os-capability-matrix.md is carved out of docs-only" 1 $'docs/os-capability-matrix.md'
expect false "ordinary docs/** still docs-only"   1 $'docs/some-other-doc.md'
expect true  "capability-matrix + ordinary docs mixed" 2 $'docs/os-capability-matrix.md\ndocs/guide.md'

# --- fail-closed guards ---
expect true  "truncation guard: 3 seen of 4"      4 $'docs/a.md\ndocs/b.md\ndocs/c.md'
expect false "3000 docs files at cap boundary"    3000 "$(printf 'docs/f%d.md\n' $(seq 1 3000))"
expect true  "empty file list"                     0 ''
expect true  "invalid authoritative total"       nope $'docs/a.md'

# --- named CI-infrastructure class ---
# --- hermetic git-diff acquisition: match, proven empty, and failure ---
tmp_repo=$(mktemp -d "${TMPDIR:-/tmp}/yuzu-change-classifier.XXXXXX")
trap 'rm -rf "$tmp_repo"' EXIT
git_fixture() {
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    git -C "$tmp_repo" "$@"
}
git_fixture init -q
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null \
  commit --allow-empty -qm base
base=$(git_fixture rev-parse HEAD)
mkdir -p "$tmp_repo/.github/workflows"
printf '%s\n' 'name: fixture' > "$tmp_repo/.github/workflows/fixture.yml"
git_fixture add .github/workflows/fixture.yml
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm infra-change
infra_commit=$(git_fixture rev-parse HEAD)

mkdir -p "$tmp_repo/server"
printf '%s\n' '// fixture' > "$tmp_repo/server/fixture.cpp"
git_fixture add server/fixture.cpp
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm non-ci-change
non_ci_commit=$(git_fixture rev-parse HEAD)

# Git's default rename display reports only the destination for a detected
# rename. Moving a workflow out of the owned tree must still expose its source
# path and select the canary.
mkdir -p "$tmp_repo/docs"
git_fixture mv .github/workflows/fixture.yml docs/fixture.yml
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm rename-out
rename_commit=$(git_fixture rev-parse HEAD)

# A line-oriented classifier cannot prove the prefix of Git's C-quoted output
# for a control-character filename. It must run the canary fail-closed.
odd_path=$'docs/line\nbreak.md'
printf '%s\n' 'fixture' > "$tmp_repo/$odd_path"
git_fixture add -- "$odd_path"
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm quoted-path
quoted_commit=$(git_fixture rev-parse HEAD)

expect_diff() {
  local want="$1" desc="$2" base_ref="$3" head_ref="$4"
  local got
  got=$(cd "$tmp_repo" && GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    bash "$SCRIPT" --class ci-infrastructure --git-diff "$base_ref" "$head_ref")
  if [ "$got" = "$want" ]; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s (want %s, got %s)\n' "$desc" "$want" "$got"; fail=$((fail + 1))
  fi
}

expect_diff true  "git diff success: CI change selects canary" "$base" "$infra_commit"
expect_diff false "non-empty non-CI diff may skip canary"       "$infra_commit" "$non_ci_commit"
expect_diff true  "rename out of CI tree selects canary"        "$non_ci_commit" "$rename_commit"
expect_diff true  "quoted path runs canary fail-closed"          "$rename_commit" "$quoted_commit"
expect_diff false "git diff no-change: canary may skip"          HEAD HEAD
expect_diff true  "git diff failure: canary runs fail-closed"    missing-base HEAD

# --- merge-base mode: the PULL REQUEST diff ---------------------------------
# Two-dot against a LIVE base tip reports the base branch's own commits as if
# the PR contained them, so a PR that has merely fallen behind a base which
# touched CI infra is misclassified. These cases pin the fix AND the trap that
# makes the obvious version of the fix an inert no-op.
commit_fixture() {
  git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
    -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm "$1"
}

# A PR branched off the quoted-path commit, touching nothing CI-owned.
git_fixture checkout -q -b pr-head "$quoted_commit"
mkdir -p "$tmp_repo/agents"
printf '%s\n' '// pr change' > "$tmp_repo/agents/pr_only.cpp"
git_fixture add agents/pr_only.cpp
commit_fixture pr-work
pr_head=$(git_fixture rev-parse HEAD)

# Meanwhile the base branch advances OVER an owned path.
git_fixture checkout -q -b base-advanced "$quoted_commit"
mkdir -p "$tmp_repo/scripts/ci"
printf '%s\n' '# advanced' > "$tmp_repo/scripts/ci/advanced.sh"
git_fixture add scripts/ci/advanced.sh
commit_fixture base-infra-advance
base_advanced=$(git_fixture rev-parse HEAD)

# The synthetic merge commit GitHub checks out for `refs/pull/<N>/merge`.
git_fixture checkout -q -b merge-ref "$base_advanced"
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null \
  merge -q --no-ff -m "Merge pr-head into base-advanced" "$pr_head"
merge_commit=$(git_fixture rev-parse HEAD)

expect_diff_mb() {
  local want="$1" desc="$2" base_ref="$3" head_ref="$4"
  local got
  got=$(cd "$tmp_repo" && GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    bash "$SCRIPT" --class ci-infrastructure --git-diff-merge-base "$base_ref" "$head_ref")
  if [ "$got" = "$want" ]; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s (want %s, got %s)\n' "$desc" "$want" "$got"; fail=$((fail + 1))
  fi
}

# The defect: two-dot sees the base branch's own CI commit.
expect_diff    true  "two-dot against an advanced base misclassifies a non-CI PR" \
  "$base_advanced" "$pr_head"
# The fix: three-dot from the fork point sees only the PR's own work.
expect_diff_mb false "merge-base against the PR HEAD classifies a non-CI PR correctly" \
  "$base_advanced" "$pr_head"
# THE TRAP, modelled as GitHub actually presents it: `base.sha` comes from the
# event payload and is a STALE ancestor of the synthetic merge commit, which
# already contains the base branch's later commits. Because the base is an
# ancestor, merge-base(base, MERGE) == base and three-dot collapses straight
# back to two-dot — both spellings below report the base branch's CI commit and
# return `true`. That is why the workflow passes the PR HEAD explicitly rather
# than the checked-out merge ref; if someone "simplifies" the caller to use
# HEAD, these two cases are what catch it.
expect_diff    true  "two-dot: stale base vs merge commit sees the base's CI commit" \
  "$quoted_commit" "$merge_commit"
expect_diff_mb true  "merge-base against the MERGE COMMIT is a no-op (head object matters)" \
  "$quoted_commit" "$merge_commit"
expect_diff_mb false "...while the same stale base vs the PR HEAD is classified correctly" \
  "$quoted_commit" "$pr_head"
# A PR that genuinely touches an owned path is still selected.
expect_diff_mb true  "merge-base still selects a PR that really touches CI infra" \
  "$non_ci_commit" "$base_advanced"
# Unrelated histories have no merge base: git exits non-zero -> fail-closed.
git_fixture checkout -q --orphan orphan-branch
git_fixture rm -rq --cached . 2>/dev/null || true
printf '%s\n' 'unrelated' > "$tmp_repo/unrelated.txt"
git_fixture add unrelated.txt
commit_fixture unrelated-root
orphan_commit=$(git_fixture rev-parse HEAD)
expect_diff_mb true  "merge-base with no common ancestor runs canary fail-closed" \
  "$orphan_commit" "$pr_head"

# --- caller contract: ci.yml must pass a PR HEAD, never the merge ref -------
# The cases above prove the SCRIPT is correct in both modes. They cannot see
# which head the WORKFLOW passes, and passing the checked-out `refs/pull/N/merge`
# commit makes merge-base mode an inert no-op while every case here stays green.
# That exact false-green is the reason this block exists.
workflow="$ROOT/.github/workflows/ci.yml"
# Match against a whitespace-normalised copy: these pins assert the caller's
# ARGUMENT CHOICE, not its formatting, and a line-rewrap of the invocation must
# not red a required check. (This is the weaker of two in-repo idioms — see
# tests/shell/test_trusted_inputs_validate.sh, which extracts the step body and
# EXECUTES it. Upgrading to that is tracked separately.)
workflow_flat=""
expect_caller() {
  local want="$1" desc="$2" pattern="$3"
  local got=false
  # Flatten newlines AND drop shell line-continuations, so a rewrapped
  # invocation reads identically to a single-line one.
  [ -n "$workflow_flat" ] || \
    workflow_flat="$(tr '\n' ' ' < "$workflow" | sed 's/\\ / /g' | tr -s ' ')"
  printf '%s' "$workflow_flat" | grep -Eq -- "$pattern" && got=true
  if [ "$got" = "$want" ]; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s (want %s, got %s)\n' "$desc" "$want" "$got"; fail=$((fail + 1))
  fi
}

if [ -f "$workflow" ]; then
  expect_caller true  "ci.yml passes a resolved head, not the checked-out ref" \
    '--class ci-infrastructure "\$diff_mode" "\$base_sha" "\$diff_head"'
  expect_caller false "ci.yml does not pass a literal HEAD to the classifier" \
    '--class ci-infrastructure "\$diff_mode" "\$base_sha" HEAD'
  expect_caller true  "ci.yml resolves the PR head from the event payload" \
    'PR_HEAD_SHA:[[:space:]]*\$\{\{[[:space:]]*github\.event\.pull_request\.head\.sha'
  # Declaring PR_HEAD_SHA is not the same as USING it: `diff_head="$GITHUB_SHA"`
  # leaves the env line intact and the call site untouched, and puts the merge
  # commit back — the no-op, fully restored, with every case above still green.
  expect_caller true  "ci.yml assigns the PR head to diff_head" \
    'diff_head="\$PR_HEAD_SHA"'
  # Likewise the mode: flipping the initialiser reverts both PR arms to two-dot
  # while `--git-diff` still appears (twice) and nothing else notices.
  expect_caller true  "ci.yml selects merge-base mode for the PR arms" \
    'diff_mode=--git-diff-merge-base '
  expect_caller true  "ci.yml still uses two-dot for the push arm" \
    'diff_mode=--git-diff '
  # The canary ccache key is a TIME BUCKET, not a source hash (#3270's
  # successor design): any hashFiles() in this key is a regression to a
  # source identity — the workspace-wide form splits the namespace against
  # the vcpkg restore's unpacked headers (#3270), and even the scoped-roots
  # form never exact-hits at this repo's commit rate, so every run saves a
  # fresh multi-GB entry and the pool evicts (measured 2026-09-01, 7x over
  # the 10 GB quota). The bucket value comes from the runner clock via
  # CCACHE_BUCKET, unreachable by any restore step by construction.
  expect_caller false "canary ccache key does not hash sources at all" \
    "key: ccache-canary-x64-linux-.*hashFiles"
  expect_caller true  "canary ccache key is the time bucket" \
    'key: ccache-canary-x64-linux-\$\{\{ env\.CCACHE_BUCKET \}\}'
  # CCACHE_BUCKET and CCACHE_PREV_BUCKET must come from ONE runner-clock
  # read: two independent `date` calls can straddle the 259200s boundary
  # (self-healing next run, but pointless to risk when one read serves
  # both — see the "Compute ccache time bucket" step's own comment).
  expect_caller true  "canary reads the runner clock exactly once for both buckets" \
    'now="\$\(date -u \+%s\)"'
  expect_caller true  "canary derives CCACHE_BUCKET from that single clock read" \
    'CCACHE_BUCKET=\$\(\( now / 259200 \)\)'
  # The restore-keys fallback must name the SPECIFIC previous bucket, never
  # a bare open-ended prefix — a prefix matches every entry this cache name
  # has ever produced, including one left by a since-changed key format,
  # and GitHub's restore-keys fallback hits refresh the last-accessed clock
  # that would otherwise age a dead entry out. That dead entry (~2.4 GB,
  # pre-dating this design) sat immortal in the pool for a day, pinning it
  # near the 10 GB quota #3797 had just cleared (measured 2026-09-02).
  expect_caller true  "canary derives CCACHE_PREV_BUCKET from the same single clock read" \
    'CCACHE_PREV_BUCKET=\$\(\( now / 259200 - 1 \)\)'
  # A pair of assertions checking only "the right value appears somewhere"
  # and "a bare prefix isn't the first line" both pass even if a bare
  # `ccache-canary-x64-linux-` fallback is ADDED as a trailing second
  # restore-keys line — the exact hazard this test exists to catch,
  # reintroduced further down instead of in place. Anchor the WHOLE
  # restore-keys block instead: nothing may appear between the correct
  # value and the next step, EXCEPT an inline `#` comment on the fallback
  # line itself (`( #[^-]*)?` below) — a maintainer annotating this exact
  # line is the single most likely harmless edit here, and this test
  # exists to catch a real regression, not to red on a comment.
  expect_caller true  "canary ccache restore-key fallback is the previous bucket and nothing else" \
    'restore-keys: \| *ccache-canary-x64-linux-\$\{\{ env\.CCACHE_PREV_BUCKET \}\}( #[^-]*)? *- name'
  # #3269: a cancelled run must not write a thin ccache entry that later
  # same-source runs exact-hit and then decline to replace.
  expect_caller true  "canary ccache save is gated on the Build step outcome" \
    'steps\.build-canary\.outcome'
  # Assert the DECLARATION too, not just the use: delete the id and both
  # outcome comparisons silently evaluate empty, the `if:` is false forever,
  # and the ccache save stops happening at all with nothing to show for it.
  expect_caller true  "canary Build step still declares the id the gate reads" \
    'id: build-canary'
else
  printf '  [skip] ci.yml not found (running outside the repo)\n'
fi

# merge-base mode requires an explicit HEAD: defaulting to `HEAD` would be the
# checked-out merge ref, i.e. the no-op. Two args must be a usage error, not a
# silent substitution.
mb_arity_rc=0
(cd "$tmp_repo" && bash "$SCRIPT" --class ci-infrastructure --git-diff-merge-base "$base_advanced") \
  >/dev/null 2>&1 || mb_arity_rc=$?
if [ "$mb_arity_rc" -eq 2 ]; then
  printf '  [pass] merge-base mode rejects a missing HEAD (usage, rc=2)\n'; pass=$((pass + 1))
else
  printf '  [FAIL] merge-base mode rejects a missing HEAD (want rc=2, got %s)\n' "$mb_arity_rc"
  fail=$((fail + 1))
fi

mb_empty_rc=0
(cd "$tmp_repo" && bash "$SCRIPT" --class ci-infrastructure --git-diff-merge-base "$base_advanced" "") \
  >/dev/null 2>&1 || mb_empty_rc=$?
if [ "$mb_empty_rc" -eq 2 ]; then
  printf '  [pass] merge-base mode rejects an EMPTY head (usage, rc=2)\n'; pass=$((pass + 1))
else
  printf '  [FAIL] merge-base mode rejects an EMPTY head (want rc=2, got %s)\n' "$mb_empty_rc"
  fail=$((fail + 1))
fi

echo "----"
echo "detect-code-change: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
