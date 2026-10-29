#!/usr/bin/env bash
# test-vcpkg-sentinel.sh — unit tests for vcpkg-triplet-sentinel.sh.
#
# Pins the behaviours the sentinel must preserve:
#   1. registry-desync recovery (#741): on key drift, BOTH
#      vcpkg_installed/<triplet>/ and vcpkg_installed/vcpkg/ are wiped.
#   2. no-op on matching key: neither directory is touched.
#   3. first-run with no sentinel: exit 0, "no existing tree to wipe".
#   4. error on missing manifest: exit non-zero.
#   5. the optional install profile is part of the key: an agent-only and a
#      full install of the SAME triplet share one tree path, so flipping the
#      profile must wipe it, and omitting the profile must hash exactly as it
#      did before profiles existed.
#
# Runs locally (./scripts/ci/test-vcpkg-sentinel.sh) and from the
# canary job in ci.yml. No external test framework — plain bash.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SENTINEL="$REPO_ROOT/scripts/ci/vcpkg-triplet-sentinel.sh"
TRIPLET="x64-linux"

if [[ ! -x "$SENTINEL" ]] && [[ ! -f "$SENTINEL" ]]; then
  echo "FAIL: sentinel not found at $SENTINEL" >&2
  exit 2
fi

PASS=0
FAIL=0
TMPROOT=""

cleanup() {
  if [[ -n "${TMPROOT:-}" && -d "$TMPROOT" ]]; then
    rm -rf "$TMPROOT"
  fi
}
trap cleanup EXIT

# Run the sentinel with $1 as $GITHUB_WORKSPACE and $2 as $VCPKG_COMMIT.
# Captures stdout+stderr to $3, exit code to $4 (passed by name). Optional $5
# is the install profile, passed as the sentinel's second argument.
run_sentinel() {
  local ws="$1" commit="$2" out_var="$3" rc_var="$4" profile="${5:-}"
  local tmp_out
  tmp_out="$(mktemp)"
  local rc=0
  GITHUB_WORKSPACE="$ws" VCPKG_COMMIT="$commit" \
    bash "$SENTINEL" "$TRIPLET" ${profile:+"$profile"} >"$tmp_out" 2>&1 || rc=$?
  printf -v "$out_var" '%s' "$(cat "$tmp_out")"
  printf -v "$rc_var" '%s' "$rc"
  rm -f "$tmp_out"
}

mk_workspace() {
  local ws="$1"
  mkdir -p "$ws"
  printf '{"name":"yuzu-test","version":"0.0.0","dependencies":["abseil"]}\n' \
    > "$ws/vcpkg.json"
}

# Mimic the desync state from issue #741: triplet tree present, plus the
# per-workspace registry that lists files under it. With a wrong sentinel
# hash this is what the sentinel must recover from.
seed_desync_state() {
  local ws="$1"
  mkdir -p "$ws/vcpkg_installed/$TRIPLET/lib/pkgconfig"
  echo "fake .pc" > "$ws/vcpkg_installed/$TRIPLET/lib/pkgconfig/foo.pc"

  mkdir -p "$ws/vcpkg_installed/vcpkg/info"
  cat > "$ws/vcpkg_installed/vcpkg/info/abseil_20260107.1_${TRIPLET}.list" <<EOF
${TRIPLET}/
${TRIPLET}/lib/
${TRIPLET}/lib/pkgconfig/
${TRIPLET}/lib/pkgconfig/absl_absl_check.pc
EOF
  printf 'Package: abseil\nVersion: 20260107.1\nArchitecture: %s\n' "$TRIPLET" \
    > "$ws/vcpkg_installed/vcpkg/status"
  mkdir -p "$ws/vcpkg_installed/vcpkg/updates"
}

assert_msg() {
  local cond="$1" msg="$2"
  if eval "$cond"; then
    PASS=$((PASS + 1))
    echo "  PASS: $msg"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $msg" >&2
  fi
}

# -----------------------------------------------------------------------
# Test 1 — registry-desync recovery (the #741 case)
# -----------------------------------------------------------------------
echo "Test 1: registry-desync recovery (#741)"
TMPROOT="$(mktemp -d)"
WS1="$TMPROOT/t1"
mk_workspace "$WS1"
seed_desync_state "$WS1"
# Plant a stale sentinel so any non-matching VCPKG_COMMIT triggers drift.
echo "stale-hash" > "$WS1/vcpkg_installed/.${TRIPLET}-cachekey.sha256"

OUT1=""; RC1=0
run_sentinel "$WS1" "deliberately-different-commit-hash" OUT1 RC1

assert_msg "[[ $RC1 -eq 0 ]]" "exit code is 0 (got $RC1)"
assert_msg "[[ ! -d '$WS1/vcpkg_installed/$TRIPLET' ]]" \
  "triplet tree is wiped"
assert_msg "[[ ! -d '$WS1/vcpkg_installed/vcpkg' ]]" \
  "workspace registry is wiped (the #741 fix)"
assert_msg "[[ -f '$WS1/vcpkg_installed/.${TRIPLET}-cachekey.sha256' ]]" \
  "new sentinel hash file is present"
have_hash="$(cat "$WS1/vcpkg_installed/.${TRIPLET}-cachekey.sha256")"
assert_msg "[[ '$have_hash' != 'stale-hash' ]]" \
  "sentinel hash was rewritten"
assert_msg "echo \"\$OUT1\" | grep -q 'wiping .*workspace registry'" \
  "log line names the registry wipe"

rm -rf "$TMPROOT"

# -----------------------------------------------------------------------
# Test 2 — no-op on matching key
# -----------------------------------------------------------------------
echo "Test 2: no-op on matching sentinel"
TMPROOT="$(mktemp -d)"
WS2="$TMPROOT/t2"
mk_workspace "$WS2"
seed_desync_state "$WS2"

# Run once to establish the canonical sentinel hash for this manifest.
OUT_BOOT=""; RC_BOOT=0
run_sentinel "$WS2" "fixed-test-baseline" OUT_BOOT RC_BOOT
# Re-seed since the first run wiped both directories (drift from <none>).
seed_desync_state "$WS2"

# Second run with the same VCPKG_COMMIT should be a no-op.
OUT2=""; RC2=0
run_sentinel "$WS2" "fixed-test-baseline" OUT2 RC2

assert_msg "[[ $RC2 -eq 0 ]]" "exit code is 0 (got $RC2)"
assert_msg "[[ -d '$WS2/vcpkg_installed/$TRIPLET' ]]" \
  "triplet tree preserved on matching key"
assert_msg "[[ -d '$WS2/vcpkg_installed/vcpkg' ]]" \
  "registry preserved on matching key"
assert_msg "! echo \"\$OUT2\" | grep -q 'wiping'" \
  "no 'wiping' log line on matching key"
assert_msg "echo \"\$OUT2\" | grep -q 'sentinel unchanged'" \
  "log line says sentinel unchanged"

rm -rf "$TMPROOT"

# -----------------------------------------------------------------------
# Test 3 — first-run with no sentinel and no existing trees
# -----------------------------------------------------------------------
echo "Test 3: first-run with empty workspace"
TMPROOT="$(mktemp -d)"
WS3="$TMPROOT/t3"
mk_workspace "$WS3"

OUT3=""; RC3=0
run_sentinel "$WS3" "first-run-baseline" OUT3 RC3

assert_msg "[[ $RC3 -eq 0 ]]" "exit code is 0 (got $RC3)"
assert_msg "echo \"\$OUT3\" | grep -q 'no existing tree to wipe'" \
  "log line says no existing tree"
assert_msg "echo \"\$OUT3\" | grep -q 'no existing registry to wipe'" \
  "log line says no existing registry"
assert_msg "[[ -f '$WS3/vcpkg_installed/.${TRIPLET}-cachekey.sha256' ]]" \
  "sentinel hash file is created"

rm -rf "$TMPROOT"

# -----------------------------------------------------------------------
# Test 4 — orphaned-registry recovery on no-drift run (#741 follow-up)
# -----------------------------------------------------------------------
# Reproduces the PR #742 CI failure: the same commit re-runs against a
# workspace that an earlier crash, abort, or pre-#741 sentinel left in
# the orphaned-registry state. The cache key has not drifted (it's the
# same commit) so the "wipe both halves on drift" rule doesn't fire.
# The defensive invariant must detect that the registry exists but the
# triplet tree does not, and wipe the registry to recover.
echo "Test 4: orphaned-registry recovery on no-drift run"
TMPROOT="$(mktemp -d)"
WS4="$TMPROOT/t4"
mk_workspace "$WS4"

# Establish the canonical sentinel hash for this manifest+baseline.
OUT_BOOT4=""; RC_BOOT4=0
run_sentinel "$WS4" "orphan-test-baseline" OUT_BOOT4 RC_BOOT4

# Now plant the bad state: registry present with phantom info entry,
# triplet tree absent. This is exactly what was on yuzu-local-windows
# when PR #742 CI ran.
mkdir -p "$WS4/vcpkg_installed/vcpkg/info"
cat > "$WS4/vcpkg_installed/vcpkg/info/abseil_20260107.1_${TRIPLET}.list" <<EOF
${TRIPLET}/lib/pkgconfig/absl_absl_check.pc
EOF
echo "Package: abseil" > "$WS4/vcpkg_installed/vcpkg/status"
# Triplet tree intentionally missing.

# Re-run with the same VCPKG_COMMIT — sentinel should NOT drift but
# should detect the orphan and wipe.
OUT4=""; RC4=0
run_sentinel "$WS4" "orphan-test-baseline" OUT4 RC4

assert_msg "[[ $RC4 -eq 0 ]]" "exit code is 0 (got $RC4)"
assert_msg "echo \"\$OUT4\" | grep -q 'sentinel unchanged'" \
  "sentinel reports unchanged (key did not drift)"
assert_msg "echo \"\$OUT4\" | grep -q 'orphaned registry detected'" \
  "orphan detection log line fires"
assert_msg "[[ ! -d '$WS4/vcpkg_installed/vcpkg' ]]" \
  "orphaned registry is wiped"

# Verify the orphan check is a no-op on a healthy workspace.
mkdir -p "$WS4/vcpkg_installed/vcpkg/info" \
         "$WS4/vcpkg_installed/$TRIPLET/lib/pkgconfig"
echo "fake .pc" > "$WS4/vcpkg_installed/$TRIPLET/lib/pkgconfig/foo.pc"
OUT4b=""; RC4b=0
run_sentinel "$WS4" "orphan-test-baseline" OUT4b RC4b

assert_msg "[[ $RC4b -eq 0 ]]" "exit code is 0 on healthy workspace (got $RC4b)"
assert_msg "! echo \"\$OUT4b\" | grep -q 'orphaned registry detected'" \
  "orphan detection does NOT fire when triplet tree is present"
assert_msg "[[ -d '$WS4/vcpkg_installed/vcpkg' ]]" \
  "registry preserved on healthy workspace"

rm -rf "$TMPROOT"

# -----------------------------------------------------------------------
# Test 5 — error on missing manifest
# -----------------------------------------------------------------------
echo "Test 5: missing vcpkg.json must fail"
TMPROOT="$(mktemp -d)"
WS5="$TMPROOT/t5"
mkdir -p "$WS5"
# Deliberately do NOT create vcpkg.json.

OUT5=""; RC5=0
run_sentinel "$WS5" "any-baseline" OUT5 RC5

assert_msg "[[ $RC5 -ne 0 ]]" "exit code is non-zero (got $RC5)"
assert_msg "echo \"\$OUT5\" | grep -q 'no vcpkg.json'" \
  "error message names the missing manifest"

rm -rf "$TMPROOT"

# -----------------------------------------------------------------------
# Test 6 — the install profile is part of the key
# -----------------------------------------------------------------------
# vcpkg.json defaults to the `server` + `tests` features; an agent-only
# install (--x-no-default-features) of the same triplet fills the SAME
# vcpkg_installed/<triplet>/ path with fewer ports. The two must not share a
# key, in either direction, or one shape silently stands in for the other.
echo "Test 6: install profile flips the key; same profile is a no-op"
TMPROOT="$(mktemp -d)"
WS6="$TMPROOT/t6"
mk_workspace "$WS6"

# Establish the default (no-profile) key and a populated tree.
OUT6a=""; RC6a=0
run_sentinel "$WS6" "profile-baseline" OUT6a RC6a
seed_desync_state "$WS6"

# Same manifest, same baseline, but an agent-only profile: must drift + wipe.
OUT6b=""; RC6b=0
run_sentinel "$WS6" "profile-baseline" OUT6b RC6b "agent-only"
assert_msg "[[ $RC6b -eq 0 ]]" "exit code is 0 (got $RC6b)"
assert_msg "echo \"\$OUT6b\" | grep -q 'sentinel drift'" \
  "default -> agent-only is reported as drift"
assert_msg "[[ ! -d '$WS6/vcpkg_installed/$TRIPLET' ]]" \
  "default-profile tree wiped when the profile changes"
assert_msg "[[ ! -d '$WS6/vcpkg_installed/vcpkg' ]]" \
  "default-profile registry wiped when the profile changes"

# Same profile again: no-op.
seed_desync_state "$WS6"
OUT6c=""; RC6c=0
run_sentinel "$WS6" "profile-baseline" OUT6c RC6c "agent-only"
assert_msg "echo \"\$OUT6c\" | grep -q 'sentinel unchanged'" \
  "agent-only -> agent-only is a no-op"
assert_msg "[[ -d '$WS6/vcpkg_installed/$TRIPLET' ]]" \
  "agent-only tree preserved on matching profile"

# And back: agent-only -> default must also drift (the other direction).
OUT6d=""; RC6d=0
run_sentinel "$WS6" "profile-baseline" OUT6d RC6d
assert_msg "echo \"\$OUT6d\" | grep -q 'sentinel drift'" \
  "agent-only -> default is reported as drift"
assert_msg "[[ ! -d '$WS6/vcpkg_installed/$TRIPLET' ]]" \
  "agent-only tree wiped when returning to the default profile"

rm -rf "$TMPROOT"

# -----------------------------------------------------------------------
# Test 7 — omitting the profile hashes exactly the pre-profile inputs
# -----------------------------------------------------------------------
# Every existing caller passes no profile. Their key must stay the digest of
# (manifest [+ configuration + overlay], baseline) and nothing else, so adding
# the argument cannot by itself invalidate or alias an unrelated cache.
echo "Test 7: no-profile key equals the pre-profile digest"
TMPROOT="$(mktemp -d)"
WS7="$TMPROOT/t7"
mk_workspace "$WS7"
expected="$( { (cd "$WS7" && sha256sum vcpkg.json) && printf '%s\n' "legacy-baseline"; } | sha256sum | awk '{print $1}')"
OUT7=""; RC7=0
run_sentinel "$WS7" "legacy-baseline" OUT7 RC7
got7="$(cat "$WS7/vcpkg_installed/.${TRIPLET}-cachekey.sha256")"
assert_msg "[[ '$got7' == '$expected' ]]" \
  "no-profile key is byte-identical to the pre-profile formula"

rm -rf "$TMPROOT"
TMPROOT=""

# -----------------------------------------------------------------------
echo
echo "Results: $PASS passed, $FAIL failed"
if [[ $FAIL -ne 0 ]]; then
  exit 1
fi
exit 0
