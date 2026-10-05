#!/usr/bin/env bash
# test_codegate_push.sh — contract net for the PUSH arm of ci.yml's docs-only
# gate (preflight's `codegate` step, #5320).
#
# WHY THIS EXISTS. Since #5320 a push to main/dev is no longer path-filtered:
# every push runs, and this step decides whether the heavy build jobs are
# skipped. A wrong `false` here skips the whole Tier-2 build matrix on a code
# push while the required contexts still go green (the docs-required-checks
# stub emits them), so the failure mode is a silent false-green on main — the
# exact commit a release tags. The step's body is extracted from ci.yml and
# executed, with `gh` stubbed, rather than copied here.
#
# WHAT IT PINS. code_changed=false ONLY when all of these hold:
#   - the previous tip's NEWEST ci.yml push run on this branch concluded
#     success (failure / cancelled / none / an API error all build: a docs
#     push must never stand in for an unbuilt or red code commit — a newer
#     pending run cancels an older pending one in ci.yml's concurrency group);
#   - the compare API says the push is a fast-forward (status "ahead");
#   - it lists 1..299 files (0 is missing evidence, 300 may be truncated);
#   - every listed path, and every rename's previous path, is docs-only per
#     scripts/ci/detect-code-change.sh (BR-010: docs/os-capability-matrix.md
#     is NOT docs-only).
# Plus: an all-zero / malformed `before` builds, and a non-push non-PR event
# builds. The runs query must ask about the previous tip, event=push and this
# branch.
#
# Run:  bash tests/shell/test_codegate_push.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="$ROOT/.github/workflows/ci.yml"
[ -f "$CI_YML" ] || { echo "missing $CI_YML" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-codegate-push.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"
    sed 's/^/         | /' "$TMP/log"; fail=$((fail+1)); fi
}

python3 "$ROOT/tests/shell/extract_run_block.py" "$CI_YML" "$TMP/codegate.sh" \
  --name "Determine code-vs-docs change set (docs-only gate)" \
  --subst 'github.event_name=GH_EVENT_NAME' \
  --subst 'github.repository=GITHUB_REPOSITORY' \
  --subst 'github.event.pull_request.number=PR_NUMBER' \
  --subst 'github.event.pull_request.changed_files=PR_CHANGED_FILES' || exit 2
grep -q 'PUSH_BEFORE_SHA' "$TMP/codegate.sh" || { echo "extracted body has no push arm" >&2; exit 2; }

# ── Hermetic gh ──────────────────────────────────────────────────────────────
# Serves two endpoints from fixture files: the workflow-runs list (applying the
# caller's --jq filter with jq, as gh does with gojq) and the compare. Records
# every argv. A missing fixture, or the literal "ERROR", makes that call fail.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_STUB_LOG"
jqf=""; endpoint=""
while [ $# -gt 0 ]; do
  case "$1" in
    --jq) jqf="$2"; shift 2 ;;
    -X|-f) shift 2 ;;
    api) shift ;;
    *) endpoint="$1"; shift ;;
  esac
done
case "$endpoint" in
  */actions/workflows/ci.yml/runs) fx="$GH_STUB_RUNS" ;;
  */compare/*) fx="$GH_STUB_COMPARE" ;;
  *) echo "stub: unexpected endpoint '$endpoint'" >&2; exit 99 ;;
esac
if [ ! -f "$fx" ] || [ "$(cat "$fx")" = "ERROR" ]; then
  echo "HTTP 502: Bad Gateway" >&2; exit 1
fi
if [ -n "$jqf" ]; then jq -r "$jqf" < "$fx"; else cat "$fx"; fi
EOF
chmod +x "$TMP/bin/gh"

BEFORE=1111111111111111111111111111111111111111
HEAD_SHA=2222222222222222222222222222222222222222

runs_json() { # runs_json "<run_number>:<conclusion>" ...  (conclusion "null" = in progress)
  local items=() n c
  for spec in "$@"; do
    n="${spec%%:*}"; c="${spec#*:}"
    [ "$c" = "null" ] && c=null || c="\"$c\""
    items+=("{\"run_number\":$n,\"conclusion\":$c,\"head_sha\":\"$BEFORE\"}")
  done
  local IFS=,
  printf '{"total_count":%d,"workflow_runs":[%s]}\n' "${#items[@]}" "${items[*]}"
}
compare_json() { # compare_json <status> <path>...  ("old=>new" = a rename)
  local items=() p
  for p in "${@:2}"; do
    if [[ "$p" == *"=>"* ]]; then
      items+=("{\"filename\":\"${p#*=>}\",\"previous_filename\":\"${p%%=>*}\",\"status\":\"renamed\"}")
    else
      items+=("{\"filename\":\"$p\",\"status\":\"modified\"}")
    fi
  done
  local IFS=,
  printf '{"status":"%s","files":[%s]}\n' "$1" "${items[*]}"
}

# run_gate <event> <before> -> prints the code_changed value written to GITHUB_OUTPUT
# Invoked as GitHub runs a `run:` block (`bash --noprofile --norc -eo pipefail`),
# from the repo root (the step calls scripts/ci/detect-code-change.sh relatively).
run_gate() {
  : > "$TMP/out"; : > "$TMP/gh.log"
  (cd "$ROOT" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP" \
      GH_STUB_LOG="$TMP/gh.log" GH_STUB_RUNS="$TMP/runs.json" GH_STUB_COMPARE="$TMP/compare.json" \
      GH_TOKEN=stub GITHUB_OUTPUT="$TMP/out" RUNNER_TEMP="$TMP" \
      GITHUB_EVENT_NAME="$1" GH_EVENT_NAME="$1" PUSH_BEFORE_SHA="$2" \
      GITHUB_REPOSITORY=DevNullLtd/Yuzu GITHUB_REF_NAME=main GITHUB_SHA="$HEAD_SHA" \
      PR_NUMBER="" PR_CHANGED_FILES="" \
      bash --noprofile --norc -eo pipefail "$TMP/codegate.sh") > "$TMP/log" 2>&1
  local rc=$?
  if [ "$rc" -ne 0 ]; then echo "step-exit-$rc"; return; fi
  local lines; lines=$(grep -c '^code_changed=' "$TMP/out")
  if [ "$lines" -ne 1 ]; then echo "outputs:$lines"; return; fi
  sed -n 's/^code_changed=//p' "$TMP/out"
}

echo "codegate push arm:"
runs_json "41:success" > "$TMP/runs.json"
compare_json ahead CHANGELOG.md > "$TMP/compare.json"
check "changelog-only push after a green tip -> skip build" false "$(run_gate push "$BEFORE")"
check "runs query asks about the previous tip, event=push, this branch" yes \
  "$(grep -q "actions/workflows/ci.yml/runs -f head_sha=$BEFORE -f event=push -f branch=main" "$TMP/gh.log" && echo yes || echo no)"
check "compare spans previous tip...this commit" yes \
  "$(grep -q "compare/$BEFORE...$HEAD_SHA" "$TMP/gh.log" && echo yes || echo no)"

compare_json ahead README.md docs/user-manual/rest-api.md CHANGELOG.md > "$TMP/compare.json"
check "root *.md + docs/** push after a green tip -> skip build" false "$(run_gate push "$BEFORE")"

compare_json ahead CHANGELOG.md > "$TMP/compare.json"
for c in failure cancelled timed_out action_required startup_failure skipped; do
  runs_json "41:$c" > "$TMP/runs.json"
  check "previous tip's run concluded '$c' -> build" true "$(run_gate push "$BEFORE")"
done
runs_json "41:null" > "$TMP/runs.json"
check "previous tip's run still in progress -> build" true "$(run_gate push "$BEFORE")"
runs_json > "$TMP/runs.json"
check "previous tip has no ci.yml push run -> build" true "$(run_gate push "$BEFORE")"
runs_json "40:success" "41:failure" > "$TMP/runs.json"
check "newest of several runs failed (older green) -> build" true "$(run_gate push "$BEFORE")"
runs_json "41:success" "40:failure" > "$TMP/runs.json"
check "newest of several runs green (older red) -> skip build" false "$(run_gate push "$BEFORE")"
echo ERROR > "$TMP/runs.json"
check "workflow-runs API error -> build" true "$(run_gate push "$BEFORE")"
check "workflow-runs API error -> compare never consulted" no \
  "$(grep -q compare "$TMP/gh.log" && echo yes || echo no)"

runs_json "41:success" > "$TMP/runs.json"
echo ERROR > "$TMP/compare.json"
check "compare API error -> build" true "$(run_gate push "$BEFORE")"
compare_json diverged CHANGELOG.md > "$TMP/compare.json"
check "non-fast-forward (force) push -> build" true "$(run_gate push "$BEFORE")"
compare_json identical > "$TMP/compare.json"
check "compare status 'identical' -> build" true "$(run_gate push "$BEFORE")"
compare_json ahead > "$TMP/compare.json"
check "zero changed files (empty commit) -> build" true "$(run_gate push "$BEFORE")"
printf '{"status":"ahead"}\n' > "$TMP/compare.json"
check "compare without a files array -> build" true "$(run_gate push "$BEFORE")"
many=(); for i in $(seq 1 300); do many+=("docs/f$i.md"); done
compare_json ahead "${many[@]}" > "$TMP/compare.json"
check "300 files (API cap, maybe truncated) -> build" true "$(run_gate push "$BEFORE")"
compare_json ahead "${many[@]:0:299}" > "$TMP/compare.json"
check "299 docs files -> skip build" false "$(run_gate push "$BEFORE")"

compare_json ahead CHANGELOG.md server/core/src/server.cpp > "$TMP/compare.json"
check "code file in the push -> build" true "$(run_gate push "$BEFORE")"
compare_json ahead docs/os-capability-matrix.md > "$TMP/compare.json"
check "docs/os-capability-matrix.md only (BR-010 drift gate) -> build" true "$(run_gate push "$BEFORE")"
compare_json ahead sdk/README.md > "$TMP/compare.json"
check "nested markdown is code-side -> build" true "$(run_gate push "$BEFORE")"
compare_json ahead "server/core/src/old.cpp=>docs/old.md" > "$TMP/compare.json"
check "rename from code into docs/ -> build (previous path counts)" true "$(run_gate push "$BEFORE")"
compare_json ahead "docs/a.md=>docs/b.md" > "$TMP/compare.json"
check "rename within docs/ -> skip build" false "$(run_gate push "$BEFORE")"
compare_json ahead .github/workflows/ci.yml > "$TMP/compare.json"
check "workflow change -> build" true "$(run_gate push "$BEFORE")"

compare_json ahead CHANGELOG.md > "$TMP/compare.json"
check "all-zero previous tip (new branch) -> build" true \
  "$(run_gate push 0000000000000000000000000000000000000000)"
check "empty previous tip -> build" true "$(run_gate push "")"
check "malformed previous tip -> build" true "$(run_gate push 'abc; rm -rf /')"
check "malformed previous tip -> no API call" "" "$(cat "$TMP/gh.log")"

check "other non-PR event (workflow_dispatch) -> build unconditionally" true \
  "$(run_gate workflow_dispatch "$BEFORE")"
check "other non-PR event -> no API call" "" "$(cat "$TMP/gh.log")"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
