#!/usr/bin/env bash
# test_release_legs_issue.sh — contract net for scripts/ci/release-legs-issue.sh,
# the single copy of the open / comment / close decision for the
# `release-legs-broken` issue (docs/ci-architecture.md, Tier 2b). It is called by
# the workflow_run listener (mode `event`) and by the daily reconcile (mode
# `reconcile`); a wrong decision either hides a release-only regression or
# closes an alert while an OS leg never ran.
#
# `gh` is a hermetic stub: `run view` answers from a fixture, `issue list`
# answers from $OPEN, and every mutating call is recorded, so each case asserts
# exactly which issue actions were taken.
#
# Run:  bash tests/shell/test_release_legs_issue.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/release-legs-issue.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-release-legs-issue.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
command -v jq >/dev/null || { echo "  [skip] needs jq"; exit 0; }

mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "run view")   cat "$RUN_FIXTURE" ;;
  "run list")   printf '%s\n' "${LATEST_RUN-5}" ;;
  "issue list") [ -n "${LIST_FAILS:-}" ] && { echo "HTTP 502" >&2; exit 1; }; printf '%s' "${OPEN:-[]}" ;;
  "issue comment"|"issue close"|"issue create"|"label create") echo "$1 $2 $3" >> "$ACTIONS" ;;
  *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
STUB
chmod +x "$TMP/bin/gh"

pass=0 fail=0
check() { if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1));
          else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi; }

SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
fixture() { # fixture <conclusion> <jobs-json-array> [event] [branch]
  printf '{"conclusion":"%s","headSha":"%s","headBranch":"%s","event":"%s","url":"https://x/run/5","updatedAt":"2026-06-01T00:00:00Z","jobs":%s}' \
    "$1" "$SHA" "${4:-dev}" "${3:-workflow_dispatch}" "$2" > "$TMP/run.json"; }
# Open issues as gh returns them; created BEFORE the fixture run finished unless
# a later timestamp is given.
iss() { local out='[' sep='' n; for n in "$@"; do out+="$sep{\"number\":${n%%@*},\"createdAt\":\"${n#*@}\"}"; sep=','; done; printf '%s]' "$out"; }
EARLY=2026-05-01T00:00:00Z LATE=2026-07-01T00:00:00Z
run() { # run <mode> <open-issues-json>
  : > "$TMP/actions"
  ( export PATH="$TMP/bin:$PATH" RUN_FIXTURE="$TMP/run.json" OPEN="$2" ACTIONS="$TMP/actions" \
           REPO=o/r GH_TOKEN=x
    bash "$SCRIPT" "$1" 5 > "$TMP/out" 2>&1; echo $? > "$TMP/rc" )
  rc=$(cat "$TMP/rc"); acts=$(tr '\n' ';' < "$TMP/actions")
  [ "${EXPECT_RC:-0}" = "$rc" ] || { printf '  [FAIL] exit code %s, expected %s\n' "$rc" "${EXPECT_RC:-0}"; fail=$((fail+1)); }; }

ALL_GREEN='[{"name":"Preflight (gate)","conclusion":"success"},{"name":"Linux gcc-15 release [dispatch]","conclusion":"success"},{"name":"Linux clang-21 release [dispatch]","conclusion":"success"},{"name":"Windows MSVC release [dispatch]","conclusion":"success"},{"name":"macOS release [dispatch]","conclusion":"success"}]'
NO_MAC='[{"name":"Linux gcc-15 release [dispatch]","conclusion":"success"},{"name":"Windows MSVC release [dispatch]","conclusion":"success"},{"name":"macOS ${{ matrix.build_type }}${{ x }}","conclusion":"skipped"}]'
LEG_RED='[{"name":"Preflight (gate)","conclusion":"success"},{"name":"Linux gcc-15 release [dispatch]","conclusion":"failure"}]'
# Realistic gate failure: proto-compat fails closed on a dispatch whose gate failed.
INFRA='[{"name":"Preflight (gate)","conclusion":"failure"},{"name":"Preflight (runner health) [dispatch]","conclusion":"failure"},{"name":"Proto backward-compat","conclusion":"failure"},{"name":"Linux gcc-15 release [dispatch]","conclusion":"skipped"}]'

echo "-- success --"
fixture success "$ALL_GREEN"; run event "$(iss 7@$EARLY 9@$EARLY)"
check "all OS legs green closes every open issue" "issue comment 7;issue close 7;issue comment 9;issue close 9;" "$acts"
fixture success "$ALL_GREEN"; run reconcile "$(iss 7@$EARLY)"
check "reconcile closes too" "issue comment 7;issue close 7;" "$acts"
fixture success "$ALL_GREEN"; run reconcile "$(iss 7@$EARLY 8@$LATE)"
check "a green run never closes an issue opened after it finished" "issue comment 7;issue close 7;" "$acts"
fixture success "$ALL_GREEN"; LATEST_RUN=6 run event "$(iss 7@$EARLY)"
check "a green re-run of an OLDER run never closes (a newer run exists)" "" "$acts"
fixture success "$NO_MAC"; run event "$(iss 7@$EARLY)"
check "an OS leg skipped/missing never closes" "" "$acts"
ONE_RED='[{"name":"Linux gcc-15 release [dispatch]","conclusion":"success"},{"name":"Linux clang-21 release [dispatch]","conclusion":"failure"},{"name":"Windows MSVC release [dispatch]","conclusion":"success"},{"name":"macOS release [dispatch]","conclusion":"success"}]'
fixture success "$ONE_RED"; run event "$(iss 7@$EARLY)"
check "every OS present but one leg not green never closes" "" "$acts"

echo "-- failure --"
fixture failure "$LEG_RED"; run event "[]"
check "event, none open: creates (label ensured first)" "label create release-legs-broken;issue create -R;" "$acts"
fixture failure "$LEG_RED"; run event "$(iss 7@$EARLY)"
check "event, one open: comments on it" "issue comment 7;" "$acts"
fixture failure "$LEG_RED"; run reconcile "$(iss 7@$EARLY)"
check "reconcile, one open: adds nothing" "" "$acts"
fixture failure "$LEG_RED"; run reconcile "[]"
check "reconcile, none open: creates (listener missed it)" "label create release-legs-broken;issue create -R;" "$acts"
fixture timed_out "$LEG_RED"; run event "[]"
check "timed_out reports" "label create release-legs-broken;issue create -R;" "$acts"
fixture startup_failure "[]"; run event "[]"
check "startup_failure (no jobs) reports" "label create release-legs-broken;issue create -R;" "$acts"

echo "-- nothing to do --"
fixture cancelled "$LEG_RED"; run event "$(iss 7@$EARLY)"
check "cancelled: nothing" "" "$acts"
fixture failure "$LEG_RED" push; run event "[]"
check "not a dispatch run: nothing" "" "$acts"
fixture failure "$LEG_RED" workflow_dispatch main; run event "[]"
check "not on dev: nothing" "" "$acts"

echo "-- wording (the body is passed to gh as an argument; check via a body-capturing stub) --"
sed -i 's|"issue comment"\|"issue close"\|"issue create"\|"label create") echo "$1 $2 $3" >> "$ACTIONS" ;;|"issue comment"\|"issue close"\|"issue create"\|"label create") echo "$1 $2 $3" >> "$ACTIONS"; printf "%s\\n" "$@" >> "$ACTIONS.args" ;;|' "$TMP/bin/gh"
body_has() { grep -c "$1" "$TMP/actions.args" 2>/dev/null || true; }
fixture failure "$INFRA"; rm -f "$TMP/actions.args"; run event "[]"
check "preflight-only failure worded as infrastructure" "1" "$(body_has 'most likely \*\*infrastructure')"
fixture startup_failure "[]"; rm -f "$TMP/actions.args"; run event "[]"
check "no-jobs run worded as never started" "1" "$(body_has 'never started any job')"
fixture failure "$LEG_RED"; rm -f "$TMP/actions.args"; run event "[]"
check "leg failure worded as a build/test failure" "1" "$(body_has 'A build or test leg failed')"
check "body names the failed job" "1" "$(body_has 'Failed jobs:\*\* Linux gcc-15 release \[dispatch\]')"

echo "-- API failure --"
fixture failure "$LEG_RED"; LIST_FAILS=1 EXPECT_RC=1 run event "[]"
check "issue-list API error fails red, never reads as none-open" "" "$acts"

echo "-- input validation --"
( PATH="$TMP/bin:$PATH" REPO=o/r bash "$SCRIPT" event 'x;y' >/dev/null 2>&1 ); check "non-numeric run id refused" "2" "$?"
( PATH="$TMP/bin:$PATH" REPO=o/r bash "$SCRIPT" bogus 5 >/dev/null 2>&1 ); check "unknown mode refused" "2" "$?"

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
