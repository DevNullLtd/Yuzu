#!/usr/bin/env bash
# test_vcpkg_baseline_bump.sh — contract net for the automated vcpkg baseline PR
# and the ci.yml gate that keeps it off the self-hosted runners until a
# maintainer opts in.
#
# WHY THIS EXISTS. vcpkg-baseline-update.yml opens a monthly PR with a token
# that starts CI, at a public time, building an unreviewed microsoft/vcpkg
# HEAD. The self-hosted runners are persistent and write the caches release
# builds read (docs/ci-architecture.md "Release build environment and
# provenance"), so ci.yml's preflight-gate refuses such a PR (step id
# vcpkg_bump_optin) until it carries the `vcpkg-bump-reviewed` label at its
# current head, and the bump workflow removes that label before each new push.
# A silent regression in either half runs upstream code on the release hosts
# unattended, so both are executed here (step bodies extracted from the
# workflows, `gh` stubbed) and their wiring is pinned lexically.
#
# WHAT IT PINS.
#   Gate step (ci.yml): not a pull_request, or a branch outside
#   deps/vcpkg-baseline*, passes untouched; a deps/vcpkg-baseline* PR passes
#   ONLY when the PR's live head equals the run's head AND its live labels
#   include the exact opt-in label. API failure, a moved head, a malformed
#   PR number or head SHA, an unreadable label list, a near-miss label: fail.
#   Wiring (ci.yml): the gate step sits in preflight-gate with no `if:` and no
#   continue-on-error; every self-hosted job needs preflight-gate and has no
#   status function outside the direct-dispatch arm (so a failed gate skips
#   it); `preflight` fails unless preflight-gate succeeded.
#   Bump workflow: the PR branch is the fixed BUMP_BRANCH of the label-removal
#   step and falls inside the gate's deps/vcpkg-baseline* pattern; both use
#   the same label; the removal runs before "Create pull request" under the
#   same `if:`; the PR is based on dev from a dev checkout and opened with
#   secrets.VCPKG_BASELINE_PR_TOKEN; the PR body lists exactly the files the
#   sed rewrites; and every tracked file carrying the current baseline SHA is
#   in that list (docs/reviews/, governance.d/, changelog.d/ and CHANGELOG.md
#   are history and exempt).
#   Label-removal step: removes the label from exactly the open bump PRs that
#   carry it, and fails (pushing nothing) when the lookup or removal fails.
#
# Run:  bash tests/shell/test_vcpkg_baseline_bump.sh
set -uo pipefail

ROOT="${YUZU_VCPKG_BUMP_TEST_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CI_YML="$ROOT/.github/workflows/ci.yml"
BUMP_YML="$ROOT/.github/workflows/vcpkg-baseline-update.yml"
EXTRACT="$ROOT/tests/shell/extract_run_block.py"
for f in "$CI_YML" "$BUMP_YML" "$EXTRACT"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_vcpkg_bump.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"
    [ -f "$TMP/log" ] && sed 's/^/         | /' "$TMP/log"; fail=$((fail+1)); fi
}

python3 "$EXTRACT" "$CI_YML" "$TMP/gate.sh" --id vcpkg_bump_optin || exit 2
python3 "$EXTRACT" "$BUMP_YML" "$TMP/strip.sh" \
  --name "Withdraw the self-hosted opt-in from the open bump PR" || exit 2

# ── Hermetic gh ──────────────────────────────────────────────────────────────
# GET repos/<r>/pulls/<n>  -> $GH_STUB_PR (the gate's live PR read)
# GET repos/<r>/pulls      -> $GH_STUB_LIST, filtered by the caller's --jq
# DELETE .../labels/<l>    -> recorded in $GH_STUB_LOG; fails if $GH_STUB_DELETE_FAIL
# A missing fixture, or one reading "ERROR", fails the call like an HTTP 502.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_STUB_LOG"
jqf=""; endpoint=""; method=GET
while [ $# -gt 0 ]; do
  case "$1" in
    --jq) jqf="$2"; shift 2 ;;
    -X) method="$2"; shift 2 ;;
    -f) shift 2 ;;
    api) shift ;;
    *) endpoint="$1"; shift ;;
  esac
done
case "$method $endpoint" in
  "GET "*/pulls/*) fx="${GH_STUB_PR:-}" ;;
  "GET "*/pulls) fx="${GH_STUB_LIST:-}" ;;
  "DELETE "*/issues/*/labels/*)
    [ -n "${GH_STUB_DELETE_FAIL:-}" ] && { echo "HTTP 403" >&2; exit 1; }
    echo "DELETED $endpoint" >> "$GH_STUB_LOG"; echo '[]'; exit 0 ;;
  *) echo "stub: unexpected call '$method $endpoint'" >&2; exit 99 ;;
esac
if [ -z "$fx" ] || [ ! -f "$fx" ] || [ "$(cat "$fx")" = "ERROR" ]; then
  echo "HTTP 502: Bad Gateway" >&2; exit 1
fi
if [ -n "$jqf" ]; then jq -r "$jqf" < "$fx"; else cat "$fx"; fi
EOF
chmod +x "$TMP/bin/gh"

HEAD_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
HEAD_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
LABEL=vcpkg-bump-reviewed

pr_json() { # pr_json <head_sha> <label>...
  local head="$1"; shift
  local labels=() l
  for l in "$@"; do labels+=("{\"name\":\"$l\"}"); done
  local IFS=,
  printf '{"number":42,"head":{"sha":"%s","ref":"deps/vcpkg-baseline-update"},"labels":[%s]}\n' "$head" "${labels[*]}"
}

# run_gate <event> <head_ref> <pr_number> <run_head> [pr fixture] -> exit code
# Invoked as GitHub runs a `run:` block (bash --noprofile --norc -eo pipefail).
run_gate() {
  : > "$TMP/gh.log"
  ( cd "$TMP" && PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_PR="${5:-}" \
      GITHUB_REPOSITORY=o/r GITHUB_STEP_SUMMARY="$TMP/summary" GH_TOKEN=x \
      EVENT_NAME="$1" HEAD_REF="$2" PR_NUMBER="$3" RUN_HEAD_SHA="$4" OPT_IN_LABEL="$LABEL" \
      bash --noprofile --norc -eo pipefail "$TMP/gate.sh" ) > "$TMP/log" 2>&1
  echo $?
}

echo "== ci.yml gate step (vcpkg_bump_optin)"
check "push event passes without an API call" 0 "$(run_gate push '' '' '')"
check "  ... and makes no gh call" 0 "$(wc -l < "$TMP/gh.log" | tr -d ' ')"
check "workflow_dispatch passes" 0 "$(run_gate workflow_dispatch '' '' '')"
check "PR from another branch passes" 0 "$(run_gate pull_request feat/x 7 "$HEAD_A")"
check "PR from a branch merely containing the prefix passes" 0 \
  "$(run_gate pull_request feat/deps/vcpkg-baseline-update 7 "$HEAD_A")"
pr_json "$HEAD_A" dependencies ci > "$TMP/pr-nolabel.json"
check "bump PR without the label FAILS" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 "$HEAD_A" "$TMP/pr-nolabel.json")"
check "  ... and says so in the step summary" 1 "$(grep -c 'Self-hosted legs not run' "$TMP/summary" 2>/dev/null || echo 0)"
rm -f "$TMP/summary"
pr_json "$HEAD_A" dependencies "$LABEL" ci > "$TMP/pr-label.json"
check "bump PR with the label at the run's head passes" 0 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 "$HEAD_A" "$TMP/pr-label.json")"
check "old SHA-named bump branch is gated too (no label)" 1 \
  "$(run_gate pull_request "deps/vcpkg-baseline-$HEAD_B" 42 "$HEAD_A" "$TMP/pr-nolabel.json")"
check "label present but the PR moved since this run FAILS" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 "$HEAD_B" "$TMP/pr-label.json")"
pr_json "$HEAD_A" "$LABEL-not" "not-$LABEL" "${LABEL^^}" > "$TMP/pr-nearmiss.json"
check "near-miss labels FAIL" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 "$HEAD_A" "$TMP/pr-nearmiss.json")"
echo ERROR > "$TMP/pr-error.json"
check "PR API failure FAILS" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 "$HEAD_A" "$TMP/pr-error.json")"
echo '{"labels":[{"name":"vcpkg-bump-reviewed"}]}' > "$TMP/pr-nohead.json"
check "PR JSON without a head FAILS" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 "$HEAD_A" "$TMP/pr-nohead.json")"
printf '{"number":42,"head":{"sha":"%s"}}\n' "$HEAD_A" > "$TMP/pr-nolabels-key.json"
check "PR JSON without a labels list FAILS" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 "$HEAD_A" "$TMP/pr-nolabels-key.json")"
check "malformed PR number FAILS" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update '42; x' "$HEAD_A" "$TMP/pr-label.json")"
check "malformed run head FAILS" 1 \
  "$(run_gate pull_request deps/vcpkg-baseline-update 42 nothex "$TMP/pr-label.json")"

# run_strip [list fixture] -> exit code; deletions recorded in gh.log
run_strip() {
  : > "$TMP/gh.log"
  ( cd "$TMP" && PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_LIST="${1:-}" \
      GITHUB_REPOSITORY=o/r GITHUB_REPOSITORY_OWNER=o GH_TOKEN=x \
      BUMP_BRANCH=deps/vcpkg-baseline-update OPT_IN_LABEL="$LABEL" \
      bash --noprofile --norc -eo pipefail "$TMP/strip.sh" ) > "$TMP/log" 2>&1
  echo $?
}
deleted() { grep '^DELETED ' "$TMP/gh.log" | sed 's/^DELETED //' | sort | tr '\n' ' ' | sed 's/ $//'; }

echo "== vcpkg-baseline-update.yml label removal"
echo '[]' > "$TMP/list-empty.json"
check "no open bump PR: passes" 0 "$(run_strip "$TMP/list-empty.json")"
check "  ... and removes nothing" "" "$(deleted)"
printf '[{"number":42,"labels":[{"name":"ci"},{"name":"%s"}]},{"number":43,"labels":[{"name":"ci"}]}]\n' \
  "$LABEL" > "$TMP/list-mixed.json"
check "open bump PR with the label: passes" 0 "$(run_strip "$TMP/list-mixed.json")"
check "  ... removes the label from exactly that PR" "repos/o/r/issues/42/labels/$LABEL" "$(deleted)"
check "  ... asks for open PRs on the bump branch" 1 \
  "$(grep -c -- '-f state=open -f head=o:deps/vcpkg-baseline-update' "$TMP/gh.log")"
echo ERROR > "$TMP/list-error.json"
check "PR lookup failure FAILS (nothing pushed)" 1 "$(run_strip "$TMP/list-error.json")"
check "removal failure FAILS (nothing pushed)" 1 \
  "$(GH_STUB_DELETE_FAIL=1 run_strip "$TMP/list-mixed.json")"

echo "== wiring (lexical)"
python3 - "$ROOT" > "$TMP/lex.out" 2>&1 <<'PY'
import fnmatch, os, re, subprocess, sys
from pathlib import Path
import yaml

root = Path(sys.argv[1])
fails = []
def need(cond, msg):
    print(("  [pass] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)

ci = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
bump = yaml.safe_load((root / ".github/workflows/vcpkg-baseline-update.yml").read_text(encoding="utf-8"))
jobs = ci["jobs"]

gate_steps = [s for s in jobs["preflight-gate"]["steps"] if s.get("id") == "vcpkg_bump_optin"]
need(len(gate_steps) == 1, "preflight-gate has exactly one vcpkg_bump_optin step")
gate = gate_steps[0] if gate_steps else {}
need("if" not in gate, "the gate step has no if: (it must always run)")
need(not gate.get("continue-on-error"), "the gate step is not continue-on-error")
gate_label = (gate.get("env") or {}).get("OPT_IN_LABEL")

def needs_of(job):
    n = job.get("needs", [])
    return [n] if isinstance(n, str) else list(n)

DISPATCH_ARM = "((github.event_name == 'workflow_dispatch' && !inputs.head_sha) && always())"
self_hosted = [name for name, job in jobs.items() if "self-hosted" in str(job.get("runs-on", ""))]
need(len(self_hosted) >= 4, f"ci.yml has its self-hosted jobs ({', '.join(self_hosted)})")
for name in self_hosted:
    job = jobs[name]
    need("preflight-gate" in needs_of(job), f"self-hosted job {name} needs preflight-gate")
    cond = str(job.get("if", "")).replace(DISPATCH_ARM, "")
    need(not re.search(r"always\(\)|cancelled\(\)|failure\(\)", cond),
         f"self-hosted job {name} has no status function outside the dispatch arm")

pre = jobs["preflight"]
first = pre["steps"][0].get("run", "")
need("needs.preflight-gate.result" in first and "'success'" in first and "exit 1" in first,
     "preflight's first step fails unless preflight-gate succeeded")

steps = bump["jobs"]["propose-bump"]["steps"]
def find(pred):
    for i, s in enumerate(steps):
        if pred(s):
            return i, s
    return None, {}
si, strip = find(lambda s: s.get("name") == "Withdraw the self-hosted opt-in from the open bump PR")
ci_, create = find(lambda s: str(s.get("uses", "")).startswith("peter-evans/create-pull-request@"))
_, checkout = find(lambda s: str(s.get("uses", "")).startswith("actions/checkout@"))
_, apply_ = find(lambda s: s.get("name") == "Apply bump")
need(si is not None and ci_ is not None and si < ci_, "label removal runs before Create pull request")
need(strip.get("if") == create.get("if"), "label removal has the same if: as Create pull request")
w = create.get("with") or {}
senv = strip.get("env") or {}
need(senv.get("OPT_IN_LABEL") == gate_label and bool(gate_label),
     f"gate and removal use the same label ({gate_label!r})")
need(w.get("branch") == senv.get("BUMP_BRANCH") and bool(w.get("branch")),
     "PR branch is the fixed branch the removal step looks up")
need("${{" not in str(w.get("branch", "")), "PR branch is a fixed name (no expression)")
need(fnmatch.fnmatchcase(str(w.get("branch", "")), "deps/vcpkg-baseline*"),
     "PR branch falls inside the gate's deps/vcpkg-baseline* pattern")
need("deps/vcpkg-baseline*" in gate.get("run", ""), "the gate step matches deps/vcpkg-baseline*")
need(w.get("base") == "dev", "PR base is dev")
need((checkout.get("with") or {}).get("ref") == "dev", "bump checks out dev")
need(w.get("token") == "${{ secrets.VCPKG_BASELINE_PR_TOKEN }}",
     "PR is opened with secrets.VCPKG_BASELINE_PR_TOKEN")

m = re.search(r"files=\(\n(.*?)\n\s*\)", apply_.get("run", ""), re.S)
listed = set(m.group(1).split()) if m else set()
need(len(listed) > 0, f"Apply bump lists its files ({len(listed)})")
body = w.get("body", "")
body_files = set(re.findall(r"^- `([^`]+)`", body, re.M))
need(body_files == listed,
     "PR body lists exactly the sed list" +
     ("" if body_files == listed else f" (body-only {sorted(body_files - listed)}, list-only {sorted(listed - body_files)})"))

import json
baseline = json.loads((root / "vcpkg.json").read_text(encoding="utf-8"))["builtin-baseline"]
EXEMPT = ("docs/reviews/", "governance.d/", "changelog.d/", "CHANGELOG.md")
try:
    tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True,
                             capture_output=True).stdout.decode().split("\0")
    if not (root / ".git").exists():
        raise RuntimeError("not a checkout root")
except Exception:
    tracked = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]
carriers = set()
for rel in filter(None, tracked):
    if rel.startswith(EXEMPT):
        continue
    try:
        if baseline in (root / rel).read_text(encoding="utf-8", errors="ignore"):
            carriers.add(rel)
    except OSError:
        pass
need(carriers <= listed,
     "every tracked file carrying the baseline SHA is in the sed list" +
     ("" if carriers <= listed else f" (missing {sorted(carriers - listed)})"))
sys.exit(1 if fails else 0)
PY
lex=$?
cat "$TMP/lex.out"
pass=$((pass + $(grep -c '^  \[pass\]' "$TMP/lex.out")))
fail=$((fail + $(grep -c '^  \[FAIL\]' "$TMP/lex.out")))
[ "$lex" -eq 0 ] || [ "$(grep -c '^  \[FAIL\]' "$TMP/lex.out")" -gt 0 ] || { echo "  [FAIL] lexical checker crashed"; fail=$((fail+1)); }

echo "test_vcpkg_baseline_bump: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
