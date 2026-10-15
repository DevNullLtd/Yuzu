#!/usr/bin/env bash
# test_release_tag_sha.sh — contract net for scripts/ci/check-release-tag-sha.sh
# (#5282, SEC-F2), which every image push and the release creation in
# release.yml run immediately before acting, so only the run whose commit the
# tag names right now may publish. Two runs for one tag at different commits
# both pass release-guard (no release exists yet); without this re-check the
# last one to push owns :X.Y.Z while the other's release signs SHA256SUMS for
# different images.
#
# WHAT IT PINS (`git` stubbed on PATH, canned `git ls-remote` output):
#   annotated tag, peeled commit == GITHUB_SHA       -> exit 0
#   annotated tag, tag OBJECT == GITHUB_SHA          -> exit 0 (either is accepted)
#   lightweight tag (plain line only) == GITHUB_SHA  -> exit 0
#   annotated tag, peeled commit != GITHUB_SHA       -> exit 1, "now points at"
#   lightweight tag != GITHUB_SHA                    -> exit 1
#   no matching line (tag deleted)                   -> exit 1
#   git exits 128 (network / auth)                   -> exit 1, fail-closed
#   GH_TOKEN set or unset -> argv never carries a credential: no `-c`, no
#                     extraheader, neither the raw nor the base64 token (SEC-G8-1)
#   git runs under `timeout` (a hung connection cannot hold a runner slot)
#   argv asks origin for exactly refs/tags/<tag> and refs/tags/<tag>^{}
# The wiring (each publishing job runs it once, before its push) is pinned by
# tests/shell/test_release_guard.sh.
#
# Run:  bash tests/shell/test_release_tag_sha.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/check-release-tag-sha.sh"
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-release-tag-sha.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"
    sed 's/^/         | /' "$TMP/out"; fail=$((fail+1)); fi
}
has() { grep -qF -- "$1" "$2" && echo yes || echo no; }

TAG=v0.14.1
RUN_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa   # this run's commit (GITHUB_SHA)
TAG_OBJ=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb   # an annotated tag object
OTHER=cccccccccccccccccccccccccccccccccccccccc     # a different commit
TOKEN=ghs_stubtoken_DO_NOT_LEAK_0123456789

# ── Hermetic git ─────────────────────────────────────────────────────────────
# Records each argv element on its own line, then prints GIT_STUB_REFS (already
# in ls-remote's "<sha>\t<ref>" form) or fails with GIT_STUB_RC.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/git" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$GIT_STUB_ARGS"
if [ "${GIT_STUB_RC:-0}" -ne 0 ]; then
  echo "fatal: unable to access 'https://github.com/DevNullLtd/Yuzu/': Could not resolve host: github.com" >&2
  exit "$GIT_STUB_RC"
fi
printf '%b' "$GIT_STUB_REFS"
EOF
chmod +x "$TMP/bin/git"

# run_check <refs> [git_rc] [token] -> sets rc, writes $TMP/out, argv in $TMP/args
run_check() {
  : > "$TMP/args"
  rc=0
  local tokvar=()
  [ -n "${3:-}" ] && tokvar=(GH_TOKEN="$3")
  env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP" \
    GIT_STUB_ARGS="$TMP/args" GIT_STUB_REFS="$1" GIT_STUB_RC="${2:-0}" "${tokvar[@]}" \
    GITHUB_REF_NAME="$TAG" GITHUB_SHA="$RUN_SHA" \
    bash --noprofile --norc -eo pipefail "$SCRIPT" > "$TMP/out" 2>&1 || rc=$?
}

annotated() { printf '%s\\trefs/tags/%s\\n%s\\trefs/tags/%s^{}\\n' "$1" "$TAG" "$2" "$TAG"; }
lightweight() { printf '%s\\trefs/tags/%s\\n' "$1" "$TAG"; }

echo "check-release-tag-sha.sh:"
run_check "$(annotated "$TAG_OBJ" "$RUN_SHA")" 0 "$TOKEN"
check "annotated tag, peeled commit is this run's -> proceed (exit 0)" 0 "$rc"
check "proceed message names the commit" yes "$(has "still points at $RUN_SHA" "$TMP/out")"
check "asks origin for the tag and its peeled ref" \
  "ls-remote|origin|refs/tags/$TAG|refs/tags/$TAG^{}" "$(tail -n 4 "$TMP/args" | paste -sd'|')"
check "GH_TOKEN set -> no -c argument (no credential in argv)" no "$(grep -qx -- '-c' "$TMP/args" && echo yes || echo no)"
check "GH_TOKEN set -> no extraheader in argv" no "$(has 'extraheader' "$TMP/args")"
check "GH_TOKEN set -> the base64 credential never appears in argv" no \
  "$(has "$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)" "$TMP/args")"
check "git ls-remote is bounded by timeout" yes "$(grep -q 'timeout [0-9][0-9]* git ls-remote' "$SCRIPT" && echo yes || echo no)"
check "GH_TOKEN set -> the raw token never appears in git's argv" no "$(has "$TOKEN" "$TMP/args")"
check "GH_TOKEN set -> the raw token never appears in the output" no "$(has "$TOKEN" "$TMP/out")"

run_check "$(annotated "$RUN_SHA" "$OTHER")"
check "annotated tag whose tag object is this run's SHA -> proceed (exit 0)" 0 "$rc"

run_check "$(lightweight "$RUN_SHA")"
check "lightweight tag at this run's commit -> proceed (exit 0)" 0 "$rc"
check "GH_TOKEN unset -> no -c argument" no "$(grep -qx -- '-c' "$TMP/args" && echo yes || echo no)"
check "GH_TOKEN unset -> argv is exactly ls-remote origin <tag> <tag>^{}" \
  "ls-remote|origin|refs/tags/$TAG|refs/tags/$TAG^{}" "$(paste -sd'|' "$TMP/args")"

run_check "$(annotated "$TAG_OBJ" "$OTHER")" 0 "$TOKEN"
check "annotated tag moved to another commit -> refused (exit 1)" 1 "$rc"
check "refusal says where the tag points now" yes "$(has "now points at $OTHER" "$TMP/out")"

run_check "$(lightweight "$OTHER")"
check "lightweight tag moved to another commit -> refused (exit 1)" 1 "$rc"

run_check ""
check "tag no longer on origin (no lines) -> refused (exit 1)" 1 "$rc"
check "deleted-tag refusal says so" yes "$(has "no longer exists on origin" "$TMP/out")"

run_check "$(printf '%s\\trefs/tags/%s-rc1\\n' "$RUN_SHA" "$TAG")"
check "only a DIFFERENT tag's line (prefix match) -> refused (exit 1)" 1 "$rc"

run_check "$(annotated "$TAG_OBJ" "$RUN_SHA")" 128 "$TOKEN"
check "git ls-remote fails (exit 128) -> fail closed (exit 1)" 1 "$rc"
check "git failure reported as fail-closed" yes "$(has "fail-closed" "$TMP/out")"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
