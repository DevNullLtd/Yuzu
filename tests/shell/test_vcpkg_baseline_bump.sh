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
# vcpkg_bump_approval) until a reviewer with write access, not a bot, and
# independent of the head (not the PR's author, not the pusher of the head,
# not on any of its commits) has APPROVED it at exactly the run's head SHA. A
# silent regression runs upstream code on the release hosts unattended, so the
# step body is executed here (extracted from the workflow, `gh` stubbed) and
# its wiring is pinned lexically.
#
# WHAT IT PINS.
#   Gate step (ci.yml): not a pull_request, or a branch outside
#   deps/vcpkg-baseline*, passes untouched and calls no API. A
#   deps/vcpkg-baseline* PR passes ONLY when some reviewer's latest decisive
#   review (APPROVED / CHANGES_REQUESTED / DISMISSED, by review id; COMMENTED
#   is ignored) is APPROVED with commit_id == the run's head, from a User
#   account that is not the PR author, not (on a synchronize run) the event's
#   sender, and not the GitHub-linked author or committer of any commit of the
#   PR, whose login is a plain GitHub login (so never an app's name[bot]), and
#   whose repository permission reads write or admin. Everything else fails: no
#   review, an approval at an older commit, the author's own approval, the
#   pusher's, a commit author's or committer's, a bot approval, an approval
#   superseded by CHANGES_REQUESTED or dismissed, an outsider's approval, a
#   commit whose author or committer links to no account, a commit list without
#   the run's head or of 250 or more commits, an API failure (commits, reviews
#   or permission), malformed JSON, a malformed PR number, head SHA, author id
#   or (on synchronize) sender id. Commits and reviews are read with
#   --paginate --slurp, and an entry on a later page counts. The chaos-injector
#   scenarios S0-S5 (token rotation, re-run, reopen, Update branch, hand-push)
#   each have a row below.
#   Token step (vcpkg-baseline-update.yml): an unset token, or one GitHub
#   rejects on an authenticated read made WITH the PR token, fails the run
#   before anything changes.
#   Rotation guard (vcpkg-baseline-update.yml): pushing proceeds only when every
#   open bump PR was opened by the token's owner (GET /user with the PR token);
#   another owner, an unreadable owner or login, or an API or parse failure
#   refuses. On success it outputs the owner's id and the commit identity
#   "<login> <id+login@users.noreply.github.com>", which Create pull request
#   uses as author and committer; the gate then excludes the token owner as
#   PR author and commit author alike.
#   Attribution check: fails the run when the PR's author is not the token's
#   owner, when any commit of the PR has an author or committer linked to no
#   account (a deleted account), or when this run pushed a head not linked to
#   the token's owner; re-reads a commit list that lags the push, at most six
#   times; fails closed on any read, parse or input defect.
#   Secret scoping: propose-bump runs in the vcpkg-baseline environment; no
#   other job or workflow declares it or reads VCPKG_BASELINE_PR_TOKEN.
#   Alert body names every refusing token/rotation/attribution step and the
#   environment; every "see X in the header" pointer names a header section.
#   Push record: `pushed` is true only when the branch head moved.
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
#   secrets.VCPKG_BASELINE_PR_TOKEN; the rotation guard and the head record run
#   before Create pull request, on the same branch name; close-on-green runs
#   only for main's copy on a run that moved the branch head and created or
#   updated the PR; the PR body lists exactly the
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
python3 "$EXTRACT" "$BUMP_YML" "$TMP/owner.sh" --name "Refuse to push onto a bump PR another account opened" || exit 2
python3 "$EXTRACT" "$BUMP_YML" "$TMP/pushed.sh" --name "Record whether this run pushed the bump branch" || exit 2
python3 "$EXTRACT" "$BUMP_YML" "$TMP/attr.sh" --name "Check the bump PR can be approved" || exit 2

# ── Hermetic gh ──────────────────────────────────────────────────────────────
# GET .../pulls/<n>/reviews (--paginate --slurp) -> $GH_STUB_REVIEWS, verbatim
# GET .../pulls/<n>/commits (--paginate --slurp) -> $GH_STUB_COMMITS, verbatim;
#     the first $GH_STUB_COMMITS_LAG reads (default 0) return
#     $GH_STUB_COMMITS_EARLY instead (a commit list lagging a fresh push)
# GET repos/<r>/pulls/<n>                        -> $GH_STUB_PR, verbatim
# GET .../collaborators/<login>/permission       -> line "<login> <perm>" of
#     $GH_STUB_PERMS; a login not listed is a 404 (exit 1), "<login> ERROR" a 502
# GET repos/<r>/pulls?... (--paginate --slurp)   -> $GH_STUB_OPEN_PRS, verbatim
# GET user                                       -> {"id": $GH_STUB_TOKEN_OWNER,
#     "login": $GH_STUB_TOKEN_LOGIN (a JSON value, default "tokenowner")};
#     an owner unset or "ERROR" is a 502
# GET repos/<r> (the token step)                 -> fails if $GH_STUB_AUTH_FAIL
# A missing fixture, or one reading "ERROR", fails the call like an HTTP 502.
# The list calls must carry --paginate and --slurp: without them they fail.
# Every call fails with a 401 unless GH_TOKEN equals $GH_STUB_EXPECT_TOKEN, so a
# step that stops sending the token it is meant to use is caught.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_STUB_LOG"
if [ "${GH_TOKEN:-}" != "${GH_STUB_EXPECT_TOKEN:-unset}" ]; then
  echo "HTTP 401: Bad credentials (token '${GH_TOKEN:-}')" >&2; exit 1
fi
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
listed() { # listed <fixture>: a --paginate --slurp list read
  [ "$paginate$slurp" = 11 ] || { echo "stub: $endpoint read without --paginate --slurp" >&2; exit 98; }
  if [ -z "$1" ] || [ ! -f "$1" ] || [ "$(cat "$1")" = "ERROR" ]; then
    echo "HTTP 502: Bad Gateway" >&2; exit 1
  fi
  emit < "$1"
}
case "$endpoint" in
  */pulls/*/reviews*) listed "${GH_STUB_REVIEWS:-}" ;;
  */pulls/*/commits*)
    reads=$(( $(grep -c '/commits' "$GH_STUB_LOG") ))
    if [ "$reads" -le "${GH_STUB_COMMITS_LAG:-0}" ]; then listed "${GH_STUB_COMMITS_EARLY:-}"
    else listed "${GH_STUB_COMMITS:-}"; fi ;;
  repos/*/pulls\?*) listed "${GH_STUB_OPEN_PRS:-}" ;;
  repos/*/pulls/[0-9]*)
    f="${GH_STUB_PR:-}"
    if [ -z "$f" ] || [ ! -f "$f" ] || [ "$(cat "$f")" = "ERROR" ]; then
      echo "HTTP 502: Bad Gateway" >&2; exit 1
    fi
    emit < "$f" ;;
  user)
    case "${GH_STUB_TOKEN_OWNER:-ERROR}" in
      ERROR) echo "HTTP 502: Bad Gateway" >&2; exit 1 ;;
      *) printf '{"id":%s,"login":%s}\n' "$GH_STUB_TOKEN_OWNER" "${GH_STUB_TOKEN_LOGIN-\"tokenowner\"}" | emit ;;
    esac ;;
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
# sleep: logged, never waits (the attribution check re-reads a lagging list).
printf '#!/usr/bin/env bash\nprintf "sleep %%s\\n" "$*" >> "$GH_STUB_LOG"\n' > "$TMP/bin/sleep"
chmod +x "$TMP/bin/sleep"

HEAD_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
HEAD_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
HEAD_C=cccccccccccccccccccccccccccccccccccccccc
AUTHOR_ID=100          # the PR author (the bump token's owner), login "tokenowner"
# Other accounts: 200 maint, 201 admin1 (write maintainers who review);
# 202 newowner (the token's owner after a rotation); 203 handpush (a
# maintainer who pushes to the bump branch by hand); 700 dispatcher (started
# the bump run, so create-pull-request names it the bump commit's author);
# 41898282 github-actions[bot] (the bump commit's committer); 19864447
# web-flow (committer of an "Update branch" merge).
BOT=41898282 WEB=19864447 DISPATCHER=700

# rv <review id> <state> <commit> <user id> <login> [type] -> one review object
rv() {
  printf '{"id":%s,"state":"%s","commit_id":"%s","user":{"id":%s,"login":"%s","type":"%s"}}' \
    "$1" "$2" "$3" "$4" "$5" "${6:-User}"
}
# cm <sha> <author id|null> <committer id|null> -> one PR-commit object
cm() {
  local a=null c=null
  [ "$2" = null ] || a="{\"id\":$2,\"login\":\"u$2\",\"type\":\"User\"}"
  [ "$3" = null ] || c="{\"id\":$3,\"login\":\"u$3\",\"type\":\"User\"}"
  printf '{"sha":"%s","author":%s,"committer":%s}' "$1" "$a" "$c"
}
# pages <file> <page>... : each page a comma-joined list of rv (or cm) objects
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
newowner write
handpush write
dispatcher write
EOF
# The default commit list: the bump commit at HEAD_A, as create-pull-request
# makes it with the workflow's explicit identity (author and committer: the
# token's owner, who is the PR's author).
pages "$TMP/commits-default.json" "$(cm "$HEAD_A" "$AUTHOR_ID" "$AUTHOR_ID")"
# A bump commit from a copy of the workflow that predates the explicit
# identity (create-pull-request's default: author whoever started the run,
# committer github-actions[bot]).
pages "$TMP/commits-legacy.json" "$(cm "$HEAD_A" "$DISPATCHER" "$BOT")"

# run_gate <event> <head_ref> <pr_number> <run_head> [reviews fixture] [author id] -> exit code
# Invoked as GitHub runs a `run:` block (bash --noprofile --norc -eo pipefail).
# The event's action and sender, and the commit list, come from G_ACTION
# (default opened), G_SENDER (default the PR author) and G_COMMITS (default
# the bump commit above); set them as prefix assignments on one call.
run_gate() {
  : > "$TMP/gh.log"
  ( cd "$TMP" && PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_REVIEWS="${5:-}" \
      GH_STUB_COMMITS="${G_COMMITS:-$TMP/commits-default.json}" GH_STUB_EXPECT_TOKEN=x \
      GH_STUB_PERMS="$TMP/perms" GITHUB_REPOSITORY=o/r GITHUB_STEP_SUMMARY="$TMP/summary" GH_TOKEN=x \
      EVENT_NAME="$1" HEAD_REF="$2" PR_NUMBER="$3" RUN_HEAD_SHA="$4" PR_AUTHOR_ID="${6-$AUTHOR_ID}" \
      EVENT_ACTION="${G_ACTION-opened}" SENDER_ID="${G_SENDER-$AUTHOR_ID}" \
      bash --noprofile --norc -eo pipefail "$TMP/gate.sh" ) > "$TMP/log" 2>&1
  echo $?
}
BR=deps/vcpkg-baseline-update
gate_with() { # gate_with <name> <page>... -> exit code of the gate on a bump PR at HEAD_A
  local f="$TMP/rv-$1.json"; shift
  pages "$f" "$@"
  run_gate pull_request "$BR" 42 "$HEAD_A" "$f"
}
commits() { # commits <name> <page>... -> path of a commit-list fixture
  local f="$TMP/cm-$1.json"; shift
  pages "$f" "$@"
  echo "$f"
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

echo "== ci.yml gate step: the approver must be independent of the head (G8P3-SG-N1)"
check "the commit list is read with --paginate --slurp" 1 \
  "$(gate_with ind-read "$(rv 1 APPROVED "$HEAD_A" 200 maint)" >/dev/null; grep -c -- '--paginate --slurp repos/o/r/pulls/42/commits' "$TMP/gh.log")"
check "the token owner (PR author, bump commit author and committer) cannot approve" 1 \
  "$(gate_with owner-self "$(rv 1 APPROVED "$HEAD_A" "$AUTHOR_ID" tokenowner)")"
check "the PR author cannot approve even when on no commit (older workflow copy)" 1 \
  "$(G_COMMITS="$TMP/commits-legacy.json" gate_with owner-legacy "$(rv 1 APPROVED "$HEAD_A" "$AUTHOR_ID" tokenowner)")"
check "  ... while a maintainer on none of it may approve the same head" 0 \
  "$(gate_with owner-other "$(rv 1 APPROVED "$HEAD_A" "$AUTHOR_ID" tokenowner),$(rv 2 APPROVED "$HEAD_A" 200 maint)")"
check "older workflow copy: the run's dispatcher (bump commit author) cannot approve" 1 \
  "$(G_COMMITS="$TMP/commits-legacy.json" gate_with dispatcher "$(rv 1 APPROVED "$HEAD_A" "$DISPATCHER" dispatcher)")"
check "a bump commit by a deleted account (author unlinked) FAILS every approval (G8P4-SRE-N2)" 1 \
  "$(G_COMMITS="$(commits deleted "$(cm "$HEAD_A" null "$BOT")")" gate_with deleted "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... and its recovery names a run from main, whose commit names the token's owner" 1 \
  "$(grep -c "close the PR and run vcpkg-baseline-update.yml from main: its new PR's commit names the token's owner" "$TMP/log")"
# A maintainer who pushed by hand: a first commit by the automation, then
# handpush's commit at the head.
HANDPUSH="$(commits handpush "$(cm "$HEAD_B" "$DISPATCHER" "$BOT"),$(cm "$HEAD_A" 203 203)")"
check "hand-push then self-approve, on the push run, FAILS" 1 \
  "$(G_ACTION=synchronize G_SENDER=203 G_COMMITS="$HANDPUSH" gate_with hp-self "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
check "  ... and says why" 1 "$(grep -c 'no approval at head .* from a maintainer independent of it' "$TMP/log")"
check "hand-push then self-approve, on a run the PR's reopening started, FAILS (commit identity)" 1 \
  "$(G_ACTION=reopened G_SENDER=200 G_COMMITS="$HANDPUSH" gate_with hp-reopen "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
check "hand-pushed commit as committer only: the committer cannot approve" 1 \
  "$(G_ACTION=reopened G_SENDER=200 G_COMMITS="$(commits hp-comm "$(cm "$HEAD_A" 200 203)")" \
     gate_with hp-comm "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
check "hand-pushed commit with forged identities, self-approved on its push run, FAILS (sender)" 1 \
  "$(G_ACTION=synchronize G_SENDER=203 G_COMMITS="$(commits forged "$(cm "$HEAD_A" 201 201)")" \
     gate_with forged "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
check "a hand-pusher's approval does not mask an independent maintainer's" 0 \
  "$(G_ACTION=synchronize G_SENDER=203 G_COMMITS="$HANDPUSH" gate_with hp-other \
     "$(rv 1 APPROVED "$HEAD_A" 203 handpush),$(rv 2 APPROVED "$HEAD_A" 200 maint)")"
check "a commit on the second page of the list counts" 1 \
  "$(G_ACTION=reopened G_SENDER=200 G_COMMITS="$(commits p2 "$(cm "$HEAD_B" "$DISPATCHER" "$BOT")" "$(cm "$HEAD_A" 203 203)")" \
     gate_with hp-p2 "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
check "the sender is not excluded on a reopened run (the reopener may approve)" 0 \
  "$(G_ACTION=reopened G_SENDER=200 gate_with reopener "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "a push run with a malformed sender id FAILS" 1 \
  "$(G_ACTION=synchronize G_SENDER='' gate_with badsender "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... and says the sender id is malformed" 1 "$(grep -c "malformed sender id ''" "$TMP/log")"
check "a push run whose sender id is null (would exclude nobody) FAILS" 1 \
  "$(G_ACTION=synchronize G_SENDER=null gate_with nullsender "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"

echo "== chaos-injector scenarios S0-S5 (A=tokenowner 100, B=newowner 202, C=maint 200, M=handpush 203)"
check "S0 A's bump, C approves: passes" 0 \
  "$(gate_with s0 "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "S1 rotation: B's token pushed, B approves on that push run: FAILS (sender)" 1 \
  "$(G_ACTION=synchronize G_SENDER=202 gate_with s1 "$(rv 1 APPROVED "$HEAD_A" 202 newowner)")"
check "S1r the same run re-run after B's approval (payload kept): FAILS" 1 \
  "$(G_ACTION=synchronize G_SENDER=202 gate_with s1r "$(rv 1 COMMENTED "$HEAD_A" 202 newowner),$(rv 2 APPROVED "$HEAD_A" 202 newowner)")"
check "S2 rotation, B dispatched the bump, PR reopened by C, B approves: FAILS (commit author)" 1 \
  "$(G_ACTION=reopened G_SENDER=200 G_COMMITS="$(commits s2 "$(cm "$HEAD_A" 202 "$BOT")")" \
     gate_with s2 "$(rv 1 APPROVED "$HEAD_A" 202 newowner)")"
S3="$(commits s3 "$(cm "$HEAD_B" 202 "$BOT"),$(cm "$HEAD_A" 200 "$WEB")")"
check "S3 rotation, B dispatched the bump, Update branch by C, B approves: FAILS" 1 \
  "$(G_ACTION=synchronize G_SENDER=200 G_COMMITS="$S3" gate_with s3 "$(rv 1 APPROVED "$HEAD_A" 202 newowner)")"
check "S3 C, who pressed Update branch, cannot approve either" 1 \
  "$(G_ACTION=synchronize G_SENDER=200 G_COMMITS="$S3" gate_with s3c "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "S3 a maintainer on none of it may approve" 0 \
  "$(G_ACTION=synchronize G_SENDER=200 G_COMMITS="$S3" gate_with s3ok "$(rv 1 APPROVED "$HEAD_A" 201 admin1)")"
check "S4 hand-push by M, M approves on the push run: FAILS" 1 \
  "$(G_ACTION=synchronize G_SENDER=203 G_COMMITS="$HANDPUSH" gate_with s4 "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
check "S5 hand-push by M, reopened by C, M approves: FAILS" 1 \
  "$(G_ACTION=reopened G_SENDER=200 G_COMMITS="$HANDPUSH" gate_with s5 "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
check "S5 hand-push by M, Update branch by C, M approves: FAILS" 1 \
  "$(G_ACTION=synchronize G_SENDER=200 G_COMMITS="$(commits s5u "$(cm "$HEAD_C" 203 203),$(cm "$HEAD_A" 200 "$WEB")")" \
     gate_with s5u "$(rv 1 APPROVED "$HEAD_A" 203 handpush)")"
# S1-S3 with the bump run started by someone other than B leave B on no
# commit and not the sender: the bump workflow's rotation guard (below)
# refuses B's push onto A's PR, so that head never exists.

echo "== ci.yml gate step: the commit list must be complete, current and linked"
check "a commit whose author links to no account FAILS" 1 \
  "$(G_COMMITS="$(commits unl-a "$(cm "$HEAD_A" null "$BOT")")" gate_with unl-a "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... naming the commit" 1 "$(grep -c "commit(s) ${HEAD_A:0:12} of PR #42 have an author or committer that GitHub links to no account" "$TMP/log")"
check "a commit whose committer links to no account FAILS" 1 \
  "$(G_COMMITS="$(commits unl-c "$(cm "$HEAD_B" "$DISPATCHER" "$BOT"),$(cm "$HEAD_A" 203 null)")" gate_with unl-c "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "a commit list without the run's head (PR moved on) FAILS" 1 \
  "$(G_COMMITS="$(commits moved "$(cm "$HEAD_B" "$DISPATCHER" "$BOT")")" gate_with moved "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... and says the PR moved on" 1 "$(grep -c "is no longer at head $HEAD_A" "$TMP/log")"
many=""; for i in $(seq 1 249); do many="$many$(cm "$(printf '%040x' "$i")" "$DISPATCHER" "$BOT"),"; done
check "249 commits plus the head (250, may be truncated) FAILS" 1 \
  "$(G_COMMITS="$(commits many "$many$(cm "$HEAD_A" "$DISPATCHER" "$BOT")")" gate_with many "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... and says why" 1 "$(grep -c '250 or more commits' "$TMP/log")"
echo ERROR > "$TMP/cm-error.json"
check "commits API failure FAILS" 1 "$(G_COMMITS="$TMP/cm-error.json" gate_with cm-err "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... saying it could not read them" 1 "$(grep -c "could not read PR #42's commits (failing closed)" "$TMP/log")"
echo '{"message":"x"}' > "$TMP/cm-object.json"
check "commits that are not a list of pages FAIL" 1 "$(G_COMMITS="$TMP/cm-object.json" gate_with cm-obj "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
check "  ... saying it could not parse them" 1 "$(grep -c "could not parse PR #42's commits (failing closed)" "$TMP/log")"
echo '[[]]' > "$TMP/cm-empty.json"
check "an empty commit list FAILS" 1 "$(G_COMMITS="$TMP/cm-empty.json" gate_with cm-empty "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"
echo '[["x"]]' > "$TMP/cm-str.json"
check "a commit that is not an object FAILS" 1 "$(G_COMMITS="$TMP/cm-str.json" gate_with cm-str "$(rv 1 APPROVED "$HEAD_A" 200 maint)")"

# The step sets no GH_TOKEN of its own in the environment: the stub accepts
# only the PR token's value ("tok"), so the read must be made with it.
run_token() {
  : > "$TMP/gh.log"
  ( cd "$TMP" && env -u GH_TOKEN PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_AUTH_FAIL="${2:-}" \
      GH_STUB_EXPECT_TOKEN=tok GITHUB_REPOSITORY=o/r HAS_PR_TOKEN="$1" PR_TOKEN=tok \
      bash --noprofile --norc -eo pipefail "$TMP/token.sh" ) > "$TMP/log" 2>&1
  echo $?
}
echo "== vcpkg-baseline-update.yml token step"
check "token set and accepted passes" 0 "$(run_token true)"
check "  ... after an authenticated read of the repository" 1 "$(grep -cx 'api repos/o/r --jq .full_name' "$TMP/gh.log")"
check "token unset FAILS before any API call" 1 "$(run_token false)"
check "  ... and makes no gh call" 0 "$(wc -l < "$TMP/gh.log" | tr -d ' ')"
check "token rejected by GitHub FAILS" 1 "$(run_token true 1)"
check "  ... without claiming to detect a token awaiting organization approval" 0 \
  "$(grep -c 'expired, revoked, not yet approved' "$TMP/log")"

# run_owner <token owner id|ERROR> <open-PR fixture> -> exit code of the rotation guard
# The owner's login is $O_LOGIN (a JSON value) when set, else "tokenowner";
# the step's outputs land in $TMP/owner.out.
run_owner() {
  : > "$TMP/gh.log"; : > "$TMP/owner.out"
  ( cd "$TMP" && env -u GH_TOKEN PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_EXPECT_TOKEN=tok \
      GH_STUB_TOKEN_OWNER="$1" GH_STUB_TOKEN_LOGIN="${O_LOGIN-\"tokenowner\"}" GH_STUB_OPEN_PRS="$2" \
      GITHUB_REPOSITORY=o/r PR_TOKEN=tok GITHUB_OUTPUT="$TMP/owner.out" \
      BUMP_BRANCH=deps/vcpkg-baseline-update \
      bash --noprofile --norc -eo pipefail "$TMP/owner.sh" ) > "$TMP/log" 2>&1
  echo $?
}
pr() { printf '{"number":%s,"user":{"id":%s,"login":"%s"}}' "$1" "$2" "$3"; }
pages "$TMP/pr-a.json" "$(pr 42 "$AUTHOR_ID" tokenowner)"
pages "$TMP/pr-none.json" ''
echo "== vcpkg-baseline-update.yml rotation guard (refuse to push onto another account's bump PR)"
check "token owner opened the open bump PR: may push" 0 "$(run_owner "$AUTHOR_ID" "$TMP/pr-a.json")"
check "  ... reads the owner with the PR token (GET user)" 1 "$(grep -c '^api user --jq ' "$TMP/gh.log")"
check "  ... and outputs the owner's id" "id=$AUTHOR_ID" "$(grep '^id=' "$TMP/owner.out")"
check "  ... and the commit identity: login and linked no-reply address" \
  "identity=tokenowner <$AUTHOR_ID+tokenowner@users.noreply.github.com>" "$(grep '^identity=' "$TMP/owner.out")"
check "  ... and lists this branch's open PRs with --paginate --slurp" 1 \
  "$(grep -cF -- '--paginate --slurp repos/o/r/pulls?state=open&head=o:deps/vcpkg-baseline-update&per_page=100' "$TMP/gh.log")"
check "no open bump PR: may push (the next PR is the new owner's)" 0 "$(run_owner 202 "$TMP/pr-none.json")"
check "rotation: token now owned by B, open PR opened by A: REFUSED" 1 "$(run_owner 202 "$TMP/pr-a.json")"
check "  ... naming the PR and telling the operator to close it" 1 \
  "$(grep -c '#42 (opened by tokenowner).*Close that PR' "$TMP/log")"
check "  ... having made only reads" 0 "$(grep -vc '^api user --jq \|^api --paginate --slurp repos/o/r/pulls?' "$TMP/gh.log")"
check "  ... and output no commit identity" 0 "$(grep -c '^identity=' "$TMP/owner.out")"
pages "$TMP/pr-p2.json" "$(pr 41 "$AUTHOR_ID" tokenowner)" "$(pr 43 202 newowner)"
check "another account's PR on a later page: REFUSED" 1 "$(run_owner "$AUTHOR_ID" "$TMP/pr-p2.json")"
pages "$TMP/pr-nouser.json" '{"number":42,"user":null}'
check "an open PR with no readable author: REFUSED" 1 "$(run_owner 202 "$TMP/pr-nouser.json")"
check "token owner unreadable (GET user fails, or an App token): REFUSED" 1 "$(run_owner ERROR "$TMP/pr-a.json")"
check "token owner id malformed: REFUSED" 1 "$(run_owner '"x"' "$TMP/pr-a.json")"
check "  ... as an unreadable owner, not as a mismatch" 1 "$(grep -c 'Could not read which account owns' "$TMP/log")"
check "token owner login missing: REFUSED" 1 "$(O_LOGIN=null run_owner "$AUTHOR_ID" "$TMP/pr-a.json")"
check "  ... with no commit identity output" 0 "$(grep -c '^identity=' "$TMP/owner.out")"
check "token owner login that would break the identity string: REFUSED" 1 \
  "$(O_LOGIN='"x> <evil@example.com"' run_owner "$AUTHOR_ID" "$TMP/pr-a.json")"
check "token owner login with a leading hyphen: REFUSED" 1 "$(O_LOGIN='"-x"' run_owner "$AUTHOR_ID" "$TMP/pr-a.json")"
check "token owner login of 40 characters: REFUSED" 1 \
  "$(O_LOGIN="\"$(printf 'a%.0s' $(seq 1 40))\"" run_owner "$AUTHOR_ID" "$TMP/pr-a.json")"
check "token owner login of 39 characters with inner hyphens: may push" 0 \
  "$(O_LOGIN="\"a-b$(printf 'c%.0s' $(seq 1 36))\"" run_owner "$AUTHOR_ID" "$TMP/pr-a.json")"
echo ERROR > "$TMP/pr-error.json"
check "open-PR listing fails: REFUSED" 1 "$(run_owner "$AUTHOR_ID" "$TMP/pr-error.json")"
echo '{"message":"x"}' > "$TMP/pr-object.json"
check "open-PR listing not a list of pages: REFUSED" 1 "$(run_owner "$AUTHOR_ID" "$TMP/pr-object.json")"

# run_attr <PR fixture> <commits fixture> [pushed] -> exit code of "Check the bump
# PR can be approved" for PR 42 at HEAD_A, token owner $AUTHOR_ID. A_LAG and
# A_EARLY make the first reads of the commit list return another fixture;
# A_OWNER, A_PR and A_HEAD override the step's inputs.
run_attr() {
  : > "$TMP/gh.log"
  ( cd "$TMP" && env -u GH_TOKEN PATH="$TMP/bin:$PATH" GH_STUB_LOG="$TMP/gh.log" GH_STUB_EXPECT_TOKEN=tok \
      GH_STUB_PR="$1" GH_STUB_COMMITS="$2" GH_STUB_COMMITS_LAG="${A_LAG:-0}" GH_STUB_COMMITS_EARLY="${A_EARLY:-}" \
      GITHUB_REPOSITORY=o/r PR_TOKEN=tok OWNER_ID="${A_OWNER-$AUTHOR_ID}" PR_NUMBER="${A_PR-42}" \
      HEAD_SHA="${A_HEAD-$HEAD_A}" PUSHED="${3:-true}" \
      bash --noprofile --norc -eo pipefail "$TMP/attr.sh" ) > "$TMP/log" 2>&1
  echo $?
}
printf '{"number":42,"user":{"id":%s,"login":"tokenowner"}}\n' "$AUTHOR_ID" > "$TMP/pr42-owner.json"
printf '{"number":42,"user":{"id":202,"login":"newowner"}}\n' > "$TMP/pr42-other.json"
printf '{"number":42,"user":null}\n' > "$TMP/pr42-nouser.json"
echo ERROR > "$TMP/pr42-error.json"
OWNED="$TMP/commits-default.json"
echo "== vcpkg-baseline-update.yml attribution check (G8P4-SRE-N2 / G8P4-UP-N1 detection)"
check "the token owner's PR, commit linked to the owner as author and committer: passes" 0 \
  "$(run_attr "$TMP/pr42-owner.json" "$OWNED")"
check "  ... reading the PR and its commits with the PR token" 2 \
  "$(grep -c '^api repos/o/r/pulls/42 --jq \|^api --paginate --slurp repos/o/r/pulls/42/commits' "$TMP/gh.log")"
check "  ... and making only those reads" 0 \
  "$(grep -vc '^api repos/o/r/pulls/42 --jq \|^api --paginate --slurp repos/o/r/pulls/42/commits' "$TMP/gh.log")"
check "a PR opened by another account than the token's owner FAILS" 1 \
  "$(run_attr "$TMP/pr42-other.json" "$OWNED")"
check "  ... naming the PR's author and the remedy" 1 \
  "$(grep -c "opened by 'newowner' (id '202'), not by the token's owner (id $AUTHOR_ID).*Close the PR" "$TMP/log")"
check "a PR with no readable author FAILS" 1 "$(run_attr "$TMP/pr42-nouser.json" "$OWNED")"
check "PR read failure FAILS" 1 "$(run_attr "$TMP/pr42-error.json" "$OWNED")"
check "  ... saying it could not read the PR" 1 "$(grep -c '::error::Could not read bump PR #42 (failing closed)' "$TMP/log")"
check "the deleted-account case: a bump commit whose author links to no account FAILS" 1 \
  "$(run_attr "$TMP/pr42-owner.json" "$(commits a-unl "$(cm "$HEAD_A" null "$BOT")")" false)"
check "  ... naming the commit, the gate's refusal and the run-from-main recovery" 1 \
  "$(grep -c "Commit(s) ${HEAD_A:0:12} of bump PR #42 have an author or committer that GitHub links to no account.*run this workflow from main" "$TMP/log")"
check "  ... and pointing at the docs' recovery section" 1 "$(grep -c "'If the bump PR cannot be approved'" "$TMP/log")"
check "an unlinked committer FAILS (earlier run's head, nothing pushed)" 1 \
  "$(run_attr "$TMP/pr42-owner.json" "$(commits a-unlc "$(cm "$HEAD_A" "$AUTHOR_ID" null)")" false)"
check "  ... as an unlinked identity" 1 "$(grep -c 'links to no account' "$TMP/log")"
check "an unlinked earlier commit FAILS" 1 \
  "$(run_attr "$TMP/pr42-owner.json" "$(commits a-unle "$(cm "$HEAD_B" null null),$(cm "$HEAD_A" "$AUTHOR_ID" "$AUTHOR_ID")")")"
check "  ... naming that commit" 1 "$(grep -c "Commit(s) ${HEAD_B:0:12} of bump PR #42" "$TMP/log")"
check "this run pushed a head authored by another account FAILS" 1 \
  "$(run_attr "$TMP/pr42-owner.json" "$TMP/commits-legacy.json" true)"
check "  ... saying the pushed commit is not linked to the token's owner" 1 \
  "$(grep -c "The bump commit this run pushed at $HEAD_A is not linked to the token's owner" "$TMP/log")"
check "this run pushed a head committed by another account FAILS" 1 \
  "$(run_attr "$TMP/pr42-owner.json" "$(commits a-com "$(cm "$HEAD_A" "$AUTHOR_ID" "$BOT")")" true)"
check "an earlier run's head by another linked account, nothing pushed: passes" 0 \
  "$(run_attr "$TMP/pr42-owner.json" "$TMP/commits-legacy.json" false)"
check "the commit list lags the push twice, then holds the head: passes" 0 \
  "$(A_LAG=2 A_EARLY="$(commits a-early "$(cm "$HEAD_B" "$AUTHOR_ID" "$AUTHOR_ID")")" run_attr "$TMP/pr42-owner.json" "$OWNED")"
check "  ... after three reads and two waits" "3 2" \
  "$(echo "$(grep -c '/commits' "$TMP/gh.log") $(grep -c '^sleep ' "$TMP/gh.log")")"
check "a commit list that never holds the head FAILS after six reads" 1 \
  "$(run_attr "$TMP/pr42-owner.json" "$(commits a-never "$(cm "$HEAD_B" "$AUTHOR_ID" "$AUTHOR_ID")")")"
check "  ... six reads, five waits" "6 5" \
  "$(echo "$(grep -c '/commits' "$TMP/gh.log") $(grep -c '^sleep ' "$TMP/gh.log")")"
check "commits read failure FAILS" 1 "$(run_attr "$TMP/pr42-owner.json" "$TMP/cm-error.json")"
check "commits not a list of pages FAIL" 1 "$(run_attr "$TMP/pr42-owner.json" "$TMP/cm-object.json")"
check "a commit that is not an object FAILS" 1 "$(run_attr "$TMP/pr42-owner.json" "$TMP/cm-str.json")"
check "no PR number from Create pull request FAILS" 1 "$(A_PR='' run_attr "$TMP/pr42-owner.json" "$OWNED")"
check "  ... before any API call" "1 0" "$(echo "$(grep -c 'no usable PR number' "$TMP/log") $(wc -l < "$TMP/gh.log" | tr -d ' ')")"
check "malformed head SHA FAILS" 1 "$(A_HEAD=zz run_attr "$TMP/pr42-owner.json" "$OWNED")"
check "  ... before any API call" "1 0" "$(echo "$(grep -c 'no usable head SHA' "$TMP/log") $(wc -l < "$TMP/gh.log" | tr -d ' ')")"
check "malformed token owner id FAILS" 1 "$(A_OWNER='' run_attr "$TMP/pr42-owner.json" "$OWNED")"
check "  ... before any API call" "1 0" "$(echo "$(grep -c "token owner's id '' is malformed" "$TMP/log") $(wc -l < "$TMP/gh.log" | tr -d ' ')")"

# run_pushed <before> <after> -> the step's `pushed` output
run_pushed() {
  : > "$TMP/out"
  ( cd "$TMP" && GITHUB_OUTPUT="$TMP/out" BEFORE_SHA="$1" AFTER_SHA="$2" \
      bash --noprofile --norc -eo pipefail "$TMP/pushed.sh" ) > "$TMP/log" 2>&1
  sed -n 's/^pushed=//p' "$TMP/out"
}
echo "== vcpkg-baseline-update.yml push record (close-on-green needs a real push, G8P3-BC-N1)"
check "branch created (no head before): pushed" true "$(run_pushed '' "$HEAD_A")"
check "branch moved to a new head: pushed" true "$(run_pushed "$HEAD_B" "$HEAD_A")"
check "branch already at this head (PR created, nothing pushed): not pushed" false "$(run_pushed "$HEAD_A" "$HEAD_A")"
check "no head reported: not pushed" false "$(run_pushed "$HEAD_B" '')"
check "malformed head reported: not pushed" false "$(run_pushed "$HEAD_B" 'zz')"

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
need(genv.get("EVENT_ACTION") == "${{ github.event.action }}" and
     genv.get("SENDER_ID") == "${{ github.event.sender.id }}",
     "the gate takes the event's action and sender id from the payload")
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
need((pb.get("outputs") or {}).get("pushed") == "${{ steps.pushed.outputs.pushed }}",
     "propose-bump exports whether the run pushed the bump branch")
cog = " ".join(str(bump["jobs"]["close-on-green"].get("if", "")).split())
need(cog == "${{ success() && github.ref == 'refs/heads/main' && "
            "needs.propose-bump.outputs.pushed == 'true' && "
            "(needs.propose-bump.outputs.pr_operation == 'created' || "
            "needs.propose-bump.outputs.pr_operation == 'updated') }}",
     "close-on-green closes only on main's copy after a run that pushed and created or updated the PR")
ci_idx, _ = find(lambda s: s.get("id") == "cpr")
oi, owner = find(lambda s: s.get("name") == "Refuse to push onto a bump PR another account opened")
bi, before = find(lambda s: s.get("id") == "before")
pi, pushed = find(lambda s: s.get("id") == "pushed")
CHANGED = "steps.check.outputs.changed == 'true'"
need(None not in (oi, ci_idx) and oi < ci_idx and owner.get("if") == CHANGED
     and not owner.get("continue-on-error"),
     "the rotation guard runs before Create pull request whenever there is a bump to push")
oenv = owner.get("env") or {}
need(oenv.get("PR_TOKEN") == "${{ secrets.VCPKG_BASELINE_PR_TOKEN }}"
     and oenv.get("BUMP_BRANCH") == w.get("branch"),
     "the rotation guard reads with the PR token, for the branch Create pull request pushes")
need(None not in (bi, ci_idx) and bi < ci_idx and before.get("if") == CHANGED
     and f"refs/heads/{w.get('branch')}" in before.get("run", ""),
     "the bump branch's head is recorded before Create pull request, for that branch")
penv = pushed.get("env") or {}
need(None not in (pi, ci_idx) and pi > ci_idx
     and penv.get("BEFORE_SHA") == "${{ steps.before.outputs.sha }}"
     and penv.get("AFTER_SHA") == "${{ steps.cpr.outputs.pull-request-head-sha }}",
     "the push record compares the head before with Create pull request's head SHA")

# Commit identity (G8P4-SRE-N2): the bump commit names the token's owner as
# both author and committer, resolved by the rotation guard; never the
# create-pull-request default (github.actor, whoever last edited the cron).
need(owner.get("id") == "owner", "the rotation guard has id owner (its outputs name the commit identity)")
need(w.get("author") == "${{ steps.owner.outputs.identity }}" and
     w.get("committer") == "${{ steps.owner.outputs.identity }}",
     "Create pull request sets author and committer to the token owner's identity")
ai, attr = find(lambda s: s.get("name") == "Check the bump PR can be approved")
aenv = attr.get("env") or {}
need(None not in (ai, pi) and ai > pi and attr.get("if") == CHANGED
     and not attr.get("continue-on-error"),
     "the attribution check runs after the push record whenever there is a bump")
need(aenv.get("PR_TOKEN") == "${{ secrets.VCPKG_BASELINE_PR_TOKEN }}"
     and aenv.get("OWNER_ID") == "${{ steps.owner.outputs.id }}"
     and aenv.get("PR_NUMBER") == "${{ steps.cpr.outputs.pull-request-number }}"
     and aenv.get("HEAD_SHA") == "${{ steps.cpr.outputs.pull-request-head-sha }}"
     and aenv.get("PUSHED") == "${{ steps.pushed.outputs.pushed }}",
     "the attribution check reads the owner id, PR number, head and push record from their steps")

# Secret scoping (G8P4-SG-N2): the PR token lives in the vcpkg-baseline
# environment, which only propose-bump declares; no other job or workflow
# names the environment or the secret.
ENV = "vcpkg-baseline"
SECRET = "VCPKG_BASELINE_PR_TOKEN"
# A read of the secret: secrets.NAME or secrets['NAME'] / secrets["NAME"].
# Prose naming it (a comment, the alert text) reads nothing.
SECRET_READ = re.compile(r"secrets\s*(?:\.\s*" + SECRET + r"\b|\[\s*['\"]" + SECRET + r"['\"])")
def env_name(job):
    e = job.get("environment")
    return e.get("name") if isinstance(e, dict) else e
need(env_name(pb) == ENV, f"propose-bump runs in the {ENV} environment")
for jname, job in bump["jobs"].items():
    if jname == "propose-bump":
        continue
    need(env_name(job) != ENV, f"bump job {jname} does not declare the {ENV} environment")
    need(not SECRET_READ.search(yaml.safe_dump(job, width=10**6)),
         f"bump job {jname} does not read {SECRET}")
others = sorted(p for p in (root / ".github").rglob("*")
                if p.is_file() and p.suffix in (".yml", ".yaml")
                and p.name != "vcpkg-baseline-update.yml")
need(len(others) >= 20, f"the scan sees the other workflow and action files ({len(others)})")
for p in others:
    text = p.read_text(encoding="utf-8", errors="ignore")
    rel = p.relative_to(root)
    need(not SECRET_READ.search(text), f"{rel} does not read {SECRET}")
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        doc = {}
    for jname, job in ((doc.get("jobs") or {}) if isinstance(doc, dict) else {}).items():
        if isinstance(job, dict) and env_name(job) == ENV:
            need(False, f"{rel} job {jname} must not declare the {ENV} environment")

# The alert names every step that refuses on a token, rotation or
# attribution problem, and the environment (G8P4-SRE-N1).
alert_script = (bump["jobs"]["alert"]["steps"][0].get("with") or {}).get("script", "")
for named in ("Require the PR token", "Create pull request",
              "Refuse to push onto a bump PR another account opened",
              "Check the bump PR can be approved", f"\\`{ENV}\\` environment: the run was"):
    need(named in alert_script, f"the alert body names {named!r}")
    if not named.startswith("\\"):
        need(find(lambda s: s.get("name") == named)[0] is not None,
             f"{named!r} is a step of propose-bump")

# Every "(see X in the header)" pointer names a section of the header
# (G8P3-DW-N1).
header_labels = set(re.findall(r"^# ([A-Z][A-Z' -]+)\.", bump_text, re.M))
pointers = re.findall(r"see ([A-Z][A-Z' -]+) in the header", bump_text)
need(len(pointers) > 0 and all(x in header_labels for x in pointers),
     f"every 'see X in the header' pointer names a header section ({sorted(set(pointers))})")

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
