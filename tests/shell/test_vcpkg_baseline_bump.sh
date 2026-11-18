#!/usr/bin/env bash
# test_vcpkg_baseline_bump.sh — contract net for the automated vcpkg baseline PR
# and the ci.yml gate that keeps it off the self-hosted runners until a
# maintainer approves it at the head being built.
#
# WHY THIS EXISTS. vcpkg-baseline-update.yml opens a monthly PR with a token
# that starts CI, at a public time, building an unreviewed microsoft/vcpkg
# HEAD. The self-hosted runners are persistent and write the caches release
# builds read (docs/ci-architecture.md "Release build environment and
# provenance"), so ci.yml's preflight-gate refuses such a PR (step id
# vcpkg_bump_approval) until a reviewer other than the PR's author, with write
# access and not a bot, has APPROVED it at exactly the run's head SHA. A silent
# regression runs upstream code on the release hosts unattended, so the step
# body is executed here (extracted from the workflow, `gh` stubbed) and its
# wiring is pinned lexically.
#
# WHAT IT PINS.
#   Gate step (ci.yml): not a pull_request, or a branch outside
#   deps/vcpkg-baseline*, passes untouched and calls no API. A
#   deps/vcpkg-baseline* PR passes ONLY when some reviewer's latest decisive
#   review (APPROVED / CHANGES_REQUESTED / DISMISSED, by review id; COMMENTED
#   is ignored) is APPROVED with commit_id == the run's head, from a User
#   account that is not the PR author, whose login is a plain GitHub login (so
#   never an app's name[bot]), and whose
#   repository permission reads write or admin. Everything else fails: no
#   review, an approval at an older commit, the author's own approval, a bot
#   approval, an approval superseded by CHANGES_REQUESTED or dismissed, an
#   outsider's approval, an API failure (reviews or permission), malformed
#   JSON, a malformed PR number, head SHA or author id. Reviews are read with
#   --paginate --slurp, and an approval on a later page counts.
#   Token step (vcpkg-baseline-update.yml): an unset token, or one GitHub
#   rejects on an authenticated read, fails the run before anything changes.
#   Apply bump (vcpkg-baseline-update.yml), run on copies of the listed files:
#   both the full SHA and its 12-character form move, and none of either
#   old form is left.
#   Wiring (ci.yml): the gate step sits in preflight-gate with no `if:` and no
#   continue-on-error, takes its author id and head SHA from the event
#   payload, and preflight-gate can read pull requests; every self-hosted job
#   needs preflight-gate and has no status function outside the
#   direct-dispatch arm (so a failed gate skips it); `preflight` fails unless
#   preflight-gate succeeded.
#   Bump workflow: no label machinery and no pull-requests grant are left; the
#   PR branch is fixed and falls inside the gate's deps/vcpkg-baseline*
#   pattern; the PR is based on dev from a dev checkout and opened with
#   secrets.VCPKG_BASELINE_PR_TOKEN; close-on-green runs only for main's copy
#   on a run that created or updated the PR; the PR body lists exactly the
#   files the sed rewrites; and every tracked file carrying the current
#   baseline SHA, in full or as a short prefix, is in that list, with every
#   short form exactly the 12 characters the sed rewrites (docs/reviews/,
#   governance.d/, changelog.d/, CHANGELOG.md and a "moved from `x` to `y`"
#   bump record are history and exempt).
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

python3 "$EXTRACT" "$CI_YML" "$TMP/gate.sh" --id vcpkg_bump_approval || exit 2
python3 "$EXTRACT" "$BUMP_YML" "$TMP/token.sh" --name "Require the PR token" || exit 2
python3 "$EXTRACT" "$BUMP_YML" "$TMP/apply.sh" --name "Apply bump" || exit 2

# ── Hermetic gh ──────────────────────────────────────────────────────────────
# GET .../pulls/<n>/reviews (--paginate --slurp) -> $GH_STUB_REVIEWS, verbatim
# GET .../collaborators/<login>/permission       -> line "<login> <perm>" of
#     $GH_STUB_PERMS; a login not listed is a 404 (exit 1), "<login> ERROR" a 502
# GET repos/<r> (the token step)                 -> fails if $GH_STUB_AUTH_FAIL
# A missing fixture, or one reading "ERROR", fails the call like an HTTP 502.
# The reviews call must carry --paginate and --slurp: without them it fails.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_STUB_LOG"
jqf=""; endpoint=""; paginate=0; slurp=0
while [ $# -gt 0 ]; do
  case "$1" in
    --jq) jqf="$2"; shift 2 ;;
    --paginate) paginate=1; shift ;;
    --slurp) slurp=1; shift ;;
    -X|--method) shift 2 ;;
    api) shift ;;
    *) endpoint="$1"; shift ;;
  esac
done
emit() { if [ -n "$jqf" ]; then jq -r "$jqf"; else cat; fi; }
case "$endpoint" in
  */pulls/*/reviews*)
    [ "$paginate$slurp" = 11 ] || { echo "stub: reviews read without --paginate --slurp" >&2; exit 98; }
    fx="${GH_STUB_REVIEWS:-}"
    if [ -z "$fx" ] || [ ! -f "$fx" ] || [ "$(cat "$fx")" = "ERROR" ]; then
      echo "HTTP 502: Bad Gateway" >&2; exit 1
    fi
    emit < "$fx" ;;
  */collaborators/*/permission)
    login="${endpoint#*/collaborators/}"; login="${login%/permission}"
    perm="$(awk -v l="$login" '$1 == l { print $2 }' "${GH_STUB_PERMS:-/dev/null}")"
    [ -n "$perm" ] || { echo "HTTP 404: Not Found" >&2; exit 1; }
    [ "$perm" != ERROR ] || { echo "HTTP 502: Bad Gateway" >&2; exit 1; }
    printf '{"permission":"%s","user":{"login":"%s"}}\n' "$perm" "$login" | emit ;;
  repos/*/*)
    [ -z "${GH_STUB_AUTH_FAIL:-}" ] || { echo "HTTP 401: Bad credentials" >&2; exit 1; }
    echo '{"full_name":"o/r"}' | emit ;;
  *) echo "stub: unexpected call '$endpoint'" >&2; exit 99 ;;
esac
EOF
chmod +x "$TMP/bin/gh"

HEAD_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
HEAD_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
AUTHOR_ID=100          # the PR author (the bump token's owner), login "tokenowner"

# rv <review id> <state> <commit> <user id> <login> [type] -> one review object
rv() {
  printf '{"id":%s,"state":"%s","commit_id":"%s","user":{"id":%s,"login":"%s","type":"%s"}}' \
    "$1" "$2" "$3" "$4" "$5" "${6:-User}"
}
# pages <file> <page>... : each page a comma-joined list of rv objects
pages() {
  local out="$1"; shift
  local p first=1
  { printf '['
    for p in "$@"; do [ $first = 1 ] || printf ','; first=0; printf '[%s]' "$p"; done
    printf ']\n'; } > "$out"
}
cat > "$TMP/perms" <<'EOF'
maint write
admin1 admin
tokenowner admin
reader read
flaky ERROR
renovate-app write
maint[bot] write
../x write
EOF

# run_gate <event> <head_ref> <pr_number> <run_head> [reviews fixture] [author id] -> exit code
# Invoked as GitHub runs a `run:` block (bash --noprofile --norc -eo pipefail).
run_gate() {
  : > "$TMP/gh.log"
  ( cd "$TMP" && PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_REVIEWS="${5:-}" \
      GH_STUB_PERMS="$TMP/perms" GITHUB_REPOSITORY=o/r GITHUB_STEP_SUMMARY="$TMP/summary" GH_TOKEN=x \
      EVENT_NAME="$1" HEAD_REF="$2" PR_NUMBER="$3" RUN_HEAD_SHA="$4" PR_AUTHOR_ID="${6-$AUTHOR_ID}" \
      bash --noprofile --norc -eo pipefail "$TMP/gate.sh" ) > "$TMP/log" 2>&1
  echo $?
}
BR=deps/vcpkg-baseline-update
gate_with() { # gate_with <name> <page>... -> exit code of the gate on a bump PR at HEAD_A
  local f="$TMP/rv-$1.json"; shift
  pages "$f" "$@"
  run_gate pull_request "$BR" 42 "$HEAD_A" "$f"
}

echo "== ci.yml gate step (vcpkg_bump_approval): passes only these"
check "push event passes without an API call" 0 "$(run_gate push '' '' '')"
check "  ... and makes no gh call" 0 "$(wc -l < "$TMP/gh.log" | tr -d ' ')"
check "workflow_dispatch passes" 0 "$(run_gate workflow_dispatch '' '' '' '' '')"
check "PR from another branch passes (ordinary dev/main PR)" 0 "$(run_gate pull_request feat/x 7 "$HEAD_A")"
check "  ... and makes no gh call" 0 "$(wc -l < "$TMP/gh.log" | tr -d ' ')"
check "PR from a branch merely containing the prefix passes" 0 \
  "$(run_gate pull_request feat/deps/vcpkg-baseline-update 7 "$HEAD_A")"
check "approval at the run's head by a write maintainer passes" 0 \
  "$(gate_with ok "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... reads reviews of this PR with --paginate --slurp" 1 \
  "$(grep -c -- '--paginate --slurp repos/o/r/pulls/42/reviews' "$TMP/gh.log")"
check "approval by an admin passes" 0 "$(gate_with admin "$(rv 1 APPROVED "$HEAD_A" 201 admin1)")"
check "approval on the second page passes" 0 \
  "$(gate_with page2 "$(rv 1 COMMENTED "$HEAD_A" 300 someone)" "$(rv 2 APPROVED "$HEAD_A" 200 maint)")"
check "a later COMMENTED review keeps the approval" 0 \
  "$(gate_with commented "$(rv 1 APPROVED "$HEAD_A" 200 maint),$(rv 2 COMMENTED "$HEAD_A" 200 maint)")"
check "re-approval after CHANGES_REQUESTED passes" 0 \
  "$(gate_with reapprove "$(rv 1 CHANGES_REQUESTED "$HEAD_A" 200 maint),$(rv 2 APPROVED "$HEAD_A" 200 maint)")"
check "author approval does not mask another maintainer's" 0 \
  "$(gate_with mixed "$(rv 1 APPROVED "$HEAD_A" "$AUTHOR_ID" tokenowner),$(rv 2 APPROVED "$HEAD_A" 200 maint)")"
check "one approver's permission API failure, another's success: passes" 0 \
  "$(gate_with flaky-other "$(rv 1 APPROVED "$HEAD_A" 400 flaky),$(rv 2 APPROVED "$HEAD_A" 200 maint)")"

echo "== ci.yml gate step: everything else FAILS"
check "bump PR with no reviews FAILS" 1 "$(gate_with none '')"
check "  ... and says so in the step summary" 1 "$(grep -c 'Self-hosted legs not run' "$TMP/summary" 2>/dev/null || echo 0)"
check "  ... and gives the procedure: approve at this head, then re-run" 1 \
  "$(grep -c "approves the PR at that head, then chooses \"Re-run failed jobs\"" "$TMP/log")"
rm -f "$TMP/summary"
check "approval at an older commit FAILS" 1 "$(gate_with older "$(rv 1 APPROVED "$HEAD_B" 200 maint)")"
check "approval by the PR author FAILS" 1 \
  "$(gate_with author "$(rv 1 APPROVED "$HEAD_A" "$AUTHOR_ID" tokenowner)")"
check "approval superseded by CHANGES_REQUESTED FAILS" 1 \
  "$(gate_with superseded "$(rv 1 APPROVED "$HEAD_A" 200 maint),$(rv 2 CHANGES_REQUESTED "$HEAD_A" 200 maint)")"
check "approval superseded on a later page FAILS" 1 \
  "$(gate_with superseded-p2 "$(rv 1 APPROVED "$HEAD_A" 200 maint)" "$(rv 2 CHANGES_REQUESTED "$HEAD_B" 200 maint)")"
check "dismissed approval FAILS" 1 "$(gate_with dismissed "$(rv 1 DISMISSED "$HEAD_A" 200 maint)")"
check "later approval at an older head does not count for this head" 1 \
  "$(gate_with later-old "$(rv 1 APPROVED "$HEAD_A" 200 maint),$(rv 2 APPROVED "$HEAD_B" 200 maint)")"
check "bot approval (type Bot, write access) FAILS" 1 \
  "$(gate_with bot "$(rv 1 APPROVED "$HEAD_A" 500 renovate-app Bot)")"
check "bot-named login typed User (write access) FAILS" 1 \
  "$(gate_with botname "$(rv 1 APPROVED "$HEAD_A" 501 'maint[bot]')")"
check "approval by a non-collaborator FAILS" 1 "$(gate_with outsider "$(rv 1 APPROVED "$HEAD_A" 600 drive-by)")"
check "approval by a read-only collaborator FAILS" 1 "$(gate_with reader "$(rv 1 APPROVED "$HEAD_A" 601 reader)")"
check "permission API failure FAILS" 1 "$(gate_with flaky "$(rv 1 APPROVED "$HEAD_A" 400 flaky)")"
check "  ... and says it failed closed" 1 "$(grep -c 'failing closed' "$TMP/log")"
check "malformed login FAILS" 1 "$(gate_with badlogin "$(rv 1 APPROVED "$HEAD_A" 602 '../x')")"
echo ERROR > "$TMP/rv-error.json"
check "reviews API failure FAILS" 1 "$(run_gate pull_request "$BR" 42 "$HEAD_A" "$TMP/rv-error.json")"
echo '{"message":"x"}' > "$TMP/rv-object.json"
check "reviews that are not a list of pages FAIL" 1 "$(run_gate pull_request "$BR" 42 "$HEAD_A" "$TMP/rv-object.json")"
echo 'not json' > "$TMP/rv-garbage.json"
check "unparseable reviews FAIL" 1 "$(run_gate pull_request "$BR" 42 "$HEAD_A" "$TMP/rv-garbage.json")"
pages "$TMP/rv-ok.json" "$(rv 1 APPROVED "$HEAD_A" 200 maint)"
check "old SHA-named bump branch is gated too" 1 \
  "$(run_gate pull_request "deps/vcpkg-baseline-$HEAD_B" 42 "$HEAD_A" "$TMP/rv-none.json")"
check "malformed PR number FAILS" 1 "$(run_gate pull_request "$BR" '42; x' "$HEAD_A" "$TMP/rv-ok.json")"
check "malformed run head FAILS" 1 "$(run_gate pull_request "$BR" 42 nothex "$TMP/rv-ok.json")"
check "missing author id FAILS" 1 "$(run_gate pull_request "$BR" 42 "$HEAD_A" "$TMP/rv-ok.json" '')"
check "malformed author id FAILS" 1 "$(run_gate pull_request "$BR" 42 "$HEAD_A" "$TMP/rv-ok.json" '1 or 1')"
pages "$TMP/rv-author.json" "$(rv 1 APPROVED "$HEAD_A" "$AUTHOR_ID" tokenowner)"
check "author id 'null' (valid JSON, matches nobody) FAILS with only the author's approval" 1 \
  "$(run_gate pull_request "$BR" 42 "$HEAD_A" "$TMP/rv-author.json" null)"
HEAD_UP=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
pages "$TMP/rv-upper.json" "$(rv 1 APPROVED "$HEAD_UP" 200 maint)"
check "head SHA in the wrong form FAILS even when a review names it" 1 \
  "$(run_gate pull_request "$BR" 42 "$HEAD_UP" "$TMP/rv-upper.json")"

# run_token [HAS] [auth-fail] -> exit code of the bump workflow's token step
run_token() {
  : > "$TMP/gh.log"
  ( cd "$TMP" && PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_AUTH_FAIL="${2:-}" \
      GITHUB_REPOSITORY=o/r HAS_PR_TOKEN="$1" PR_TOKEN=tok \
      bash --noprofile --norc -eo pipefail "$TMP/token.sh" ) > "$TMP/log" 2>&1
  echo $?
}
echo "== vcpkg-baseline-update.yml token step"
check "token set and accepted passes" 0 "$(run_token true)"
check "  ... after an authenticated read of the repository" 1 "$(grep -cx 'api repos/o/r --jq .full_name' "$TMP/gh.log")"
check "token unset FAILS before any API call" 1 "$(run_token false)"
check "  ... and makes no gh call" 0 "$(wc -l < "$TMP/gh.log" | tr -d ' ')"
check "token rejected by GitHub FAILS" 1 "$(run_token true 1)"

# The real sed over copies of the listed files: full and 12-character forms
# both move, and nothing of the old SHA is left.
echo "== vcpkg-baseline-update.yml Apply bump (on copies of the listed files)"
OLD_SHA="$(jq -r '."builtin-baseline"' "$ROOT/vcpkg.json")"
NEW_SHA=0123456789abcdef0123456789abcdef01234567
mkdir -p "$TMP/apply"
for f in $(sed -n '/files=(/,/)/p' "$TMP/apply.sh" | sed '1d;$d'); do
  mkdir -p "$TMP/apply/$(dirname "$f")"; cp "$ROOT/$f" "$TMP/apply/$f"
done
( cd "$TMP/apply" && CURRENT_SHA="$OLD_SHA" LATEST_SHA="$NEW_SHA"     bash --noprofile --norc -eo pipefail "$TMP/apply.sh" ) > "$TMP/log" 2>&1
check "Apply bump succeeds" 0 "$?"
check "  ... leaves no full or 12-character old SHA" 0 "$(grep -rl "${OLD_SHA:0:12}" "$TMP/apply" | wc -l | tr -d ' ')"
check "  ... writes the new short form into deploy/windows/README.md" 1 \
  "$(grep -c "\"vcpkg_baseline\": \"${NEW_SHA:0:12}\"" "$TMP/apply/deploy/windows/README.md")"
check "  ... writes the new full SHA into vcpkg.json" "$NEW_SHA" "$(jq -r '."builtin-baseline"' "$TMP/apply/vcpkg.json")"

echo "== wiring (lexical)"
python3 - "$ROOT" > "$TMP/lex.out" 2>&1 <<'PY'
import fnmatch, json, os, re, subprocess, sys
from pathlib import Path
import yaml

root = Path(sys.argv[1])
fails = []
def need(cond, msg):
    print(("  [pass] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)

ci_text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
bump_text = (root / ".github/workflows/vcpkg-baseline-update.yml").read_text(encoding="utf-8")
ci = yaml.safe_load(ci_text)
bump = yaml.safe_load(bump_text)
jobs = ci["jobs"]

gate_steps = [s for s in jobs["preflight-gate"]["steps"] if s.get("id") == "vcpkg_bump_approval"]
need(len(gate_steps) == 1, "preflight-gate has exactly one vcpkg_bump_approval step")
gate = gate_steps[0] if gate_steps else {}
need("if" not in gate, "the gate step has no if: (it must always run)")
need(not gate.get("continue-on-error"), "the gate step is not continue-on-error")
genv = gate.get("env") or {}
need(genv.get("PR_AUTHOR_ID") == "${{ github.event.pull_request.user.id }}",
     "the gate takes the PR author id from the event payload")
need(genv.get("RUN_HEAD_SHA") == "${{ github.event.pull_request.head.sha }}",
     "the gate takes the head SHA from the event payload")
need((jobs["preflight-gate"].get("permissions") or {}).get("pull-requests") == "read",
     "preflight-gate can read pull requests (reviews)")
need("deps/vcpkg-baseline*" in gate.get("run", ""), "the gate step matches deps/vcpkg-baseline*")
for name, text in (("ci.yml", ci_text), ("vcpkg-baseline-update.yml", bump_text)):
    need("vcpkg-bump-reviewed" not in text and "OPT_IN_LABEL" not in text,
         f"{name} carries no opt-in label machinery")

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

pb = bump["jobs"]["propose-bump"]
steps = pb["steps"]
def find(pred):
    for i, s in enumerate(steps):
        if pred(s):
            return i, s
    return None, {}
ti, token = find(lambda s: s.get("name") == "Require the PR token")
_, create = find(lambda s: str(s.get("uses", "")).startswith("peter-evans/create-pull-request@"))
_, checkout = find(lambda s: str(s.get("uses", "")).startswith("actions/checkout@"))
_, apply_ = find(lambda s: s.get("name") == "Apply bump")
need(ti == 0 and "if" not in token, "the token step is the first step and always runs")
need("pull-requests" not in (pb.get("permissions") or {}),
     "propose-bump holds no pull-requests grant (no label to strip)")
w = create.get("with") or {}
need(bool(w.get("branch")) and "${{" not in str(w.get("branch", "")),
     "PR branch is a fixed name (no expression)")
need(fnmatch.fnmatchcase(str(w.get("branch", "")), "deps/vcpkg-baseline*"),
     "PR branch falls inside the gate's deps/vcpkg-baseline* pattern")
need(w.get("base") == "dev", "PR base is dev")
need((checkout.get("with") or {}).get("ref") == "dev", "bump checks out dev")
need(w.get("token") == "${{ secrets.VCPKG_BASELINE_PR_TOKEN }}",
     "PR is opened with secrets.VCPKG_BASELINE_PR_TOKEN")
need(create.get("id") == "cpr" and
     (pb.get("outputs") or {}).get("pr_operation") == "${{ steps.cpr.outputs.pull-request-operation }}",
     "propose-bump exports the PR operation of Create pull request")
cog = " ".join(str(bump["jobs"]["close-on-green"].get("if", "")).split())
need(cog == "${{ success() && github.ref == 'refs/heads/main' && "
            "(needs.propose-bump.outputs.pr_operation == 'created' || "
            "needs.propose-bump.outputs.pr_operation == 'updated') }}",
     "close-on-green closes only on main's copy after a run that created or updated the PR")

run = apply_.get("run", "")
m = re.search(r"files=\(\n(.*?)\n\s*\)", run, re.S)
listed = set(m.group(1).split()) if m else set()
need(len(listed) > 0, f"Apply bump lists its files ({len(listed)})")
need('-e "s/${old:0:12}/${new:0:12}/g"' in run and 'grep -l "${old:0:12}"' in run,
     "Apply bump rewrites and re-checks the 12-character short form")
body = w.get("body", "")
body_files = set(re.findall(r"^- `([^`]+)`", body, re.M))
need(body_files == listed,
     "PR body lists exactly the sed list" +
     ("" if body_files == listed else f" (body-only {sorted(body_files - listed)}, list-only {sorted(listed - body_files)})"))

baseline = json.loads((root / "vcpkg.json").read_text(encoding="utf-8"))["builtin-baseline"]
EXEMPT = ("docs/reviews/", "governance.d/", "changelog.d/", "CHANGELOG.md")
# A bump record ("moved from `<old>` to `<new>`") is history, like docs/reviews/.
BUMP_RECORD = re.compile(r"moved from `[0-9a-f]{7,40}` to `[0-9a-f]{7,40}`")
SHORT = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{7,39}(?![0-9A-Za-z])")
try:
    tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True,
                             capture_output=True).stdout.decode().split("\0")
    if not (root / ".git").exists():
        raise RuntimeError("not a checkout root")
except Exception:
    tracked = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]
carriers, bad_len = set(), set()
for rel in filter(None, tracked):
    if rel.startswith(EXEMPT):
        continue
    try:
        text = (root / rel).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        continue
    if baseline[:7] not in text:
        continue
    if baseline in text:
        carriers.add(rel)
    for line in text.splitlines():
        if BUMP_RECORD.search(line):
            continue
        for tok in SHORT.findall(line):
            if baseline.startswith(tok):
                carriers.add(rel)
                if len(tok) != 12:
                    bad_len.add(f"{rel}:{tok}")
need(carriers <= listed,
     "every tracked file carrying the baseline SHA (full or short) is in the sed list" +
     ("" if carriers <= listed else f" (missing {sorted(carriers - listed)})"))
need(not bad_len, "every short form of the baseline is the 12 characters the sed rewrites" +
     ("" if not bad_len else f" (other lengths: {sorted(bad_len)})"))
sys.exit(1 if fails else 0)
PY
lex=$?
cat "$TMP/lex.out"
pass=$((pass + $(grep -c '^  \[pass\]' "$TMP/lex.out")))
fail=$((fail + $(grep -c '^  \[FAIL\]' "$TMP/lex.out")))
[ "$lex" -eq 0 ] || [ "$(grep -c '^  \[FAIL\]' "$TMP/lex.out")" -gt 0 ] || { echo "  [FAIL] lexical checker crashed"; fail=$((fail+1)); }

echo "test_vcpkg_baseline_bump: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
