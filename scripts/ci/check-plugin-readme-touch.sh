#!/usr/bin/env bash
# check-plugin-readme-touch.sh — the plugin README touch rule
# (docs/plugin-readme-standard.md rule 7).
#
# A change under agents/plugins/<x>/src/** must be accompanied by a change to
# agents/plugins/<x>/README.md, or the pull-request body must state
#
#     docs-unchanged: <section it would have touched> — <reason>
#
# so the reviewer sees the claim rather than a silent omission. A plugin that
# has no README at HEAD yet is exempt (the README-existence ratchet in
# tests/test_plugin_readmes.py governs that count); the exemption is printed,
# never silent.
#
# Usage:
#   check-plugin-readme-touch.sh <BASE> <HEAD> [PR_BODY_FILE]
#   check-plugin-readme-touch.sh --selftest        # fixture run, no repository
#
# BASE/HEAD are commit-ish. The body file is read verbatim (never interpolated
# into this script); when absent, no override is possible.
#
# Exit status: 0 = rule satisfied (or nothing to enforce, or selftest passed),
# 1 = a plugin's src/ changed without its README or an override (or a commit
# is unavailable — fail closed; or selftest failed), 2 = usage error.
set -euo pipefail

usage() {
  echo "usage: check-plugin-readme-touch.sh <BASE> <HEAD> [PR_BODY_FILE] | --selftest" >&2
  exit 2
}

# ── the rule ─────────────────────────────────────────────────────────────────

check() {
  local BASE="$1" HEAD="$2" BODY="${3:-}"

  if ! git cat-file -e "${BASE}^{commit}" 2>/dev/null || ! git cat-file -e "${HEAD}^{commit}" 2>/dev/null; then
    echo "check-plugin-readme-touch: base or head commit unavailable (${BASE}..${HEAD}) — cannot evaluate, failing closed" >&2
    return 1
  fi

  local CHANGED
  CHANGED="$(git diff --name-only "$BASE" "$HEAD" --)"

  local override=""
  if [ -n "$BODY" ] && [ -f "$BODY" ]; then
    # First matching line wins; the text after the colon must be non-empty. A
    # leading list marker ("- " / "* ") is allowed so the line can sit in a
    # bullet. Fenced code blocks and HTML comments are skipped: the override
    # must be visible to the reviewer on the rendered page.
    # A GFM fence closes only on a run of the SAME character at least as
    # long as the one that opened it (a 4-backtick fence is not closed by a
    # nested 3-backtick line) — matching that asymmetrically is what let a
    # decoy inner fence re-expose text that still renders hidden on GitHub.
    override="$(tr -d '\r' < "$BODY" | awk '
      function run_len(s, ch,    n) { n = 0; while (substr(s, n + 1, 1) == ch) n++; return n }
      {
        raw = $0; t = raw; sub(/^[ \t]{0,3}/, "", t); ch = substr(t, 1, 1)
        is_fence = 0; len = 0
        if (ch == "\140" || ch == "~") {
          len = run_len(t, ch)
          if (len >= 3 && (ch == "~" || index(substr(t, len + 1), "\140") == 0)) is_fence = 1
        }
        if (fence) {
          if (is_fence && ch == fchar && len >= flen) fence = 0
          next
        } else if (is_fence) { fence = 1; fchar = ch; flen = len; next }
        line = raw
        while (1) {
          if (comment) { i = index(line, "-->"); if (!i) next; line = substr(line, i + 3); comment = 0 }
          i = index(line, "<!--"); if (!i) break
          rest = substr(line, i + 4); j = index(rest, "-->")
          if (j) { line = substr(line, 1, i - 1) substr(rest, j + 3) } else { line = substr(line, 1, i - 1); comment = 1; break }
        }
        print line
      }' | grep -m1 -E '^[[:space:]]*([-*][[:space:]]+)?docs-unchanged:[[:space:]]*[^[:space:]].*[[:space:]](—|-)[[:space:]]+[^[:space:]]' || true)"
  fi

  # Plugins whose src/ changed, deduplicated.
  local plugins
  plugins="$(printf '%s\n' "$CHANGED" | sed -n -E 's#^agents/plugins/([^/]+)/src/.*$#\1#p' | sort -u)"
  if [ -z "$plugins" ]; then
    echo "check-plugin-readme-touch: no plugin src/ changes between ${BASE} and ${HEAD} — nothing to enforce"
    return 0
  fi

  local failed=0 p readme
  for p in $plugins; do
    readme="agents/plugins/${p}/README.md"
    if ! git cat-file -e "${HEAD}:${readme}" 2>/dev/null; then
      echo "check-plugin-readme-touch: ${p}: src/ changed and no README exists at HEAD — exempt (README-existence ratchet governs; tests/test_plugin_readmes.py)"
      continue
    fi
    # A here-string, not a pipe: `grep -q` exits on the first match and, under
    # pipefail, a printf still writing a change list larger than the pipe
    # buffer would take SIGPIPE and turn a satisfied rule into a false red.
    if grep -qxF -- "$readme" <<<"$CHANGED"; then
      echo "check-plugin-readme-touch: ${p}: src/ and README.md both changed — ok"
      continue
    fi
    if [ -n "$override" ]; then
      echo "check-plugin-readme-touch: ${p}: src/ changed, README.md unchanged, override stated in the PR body: ${override}"
      continue
    fi
    echo "check-plugin-readme-touch: ${p}: agents/plugins/${p}/src/** changed but ${readme} did not." >&2
    echo "  Either update the README (docs/plugin-readme-standard.md), or add to the PR body a line:" >&2
    echo "    docs-unchanged: <section it would have touched> — <reason>" >&2
    failed=1
  done
  return $failed
}

# ── selftest ─────────────────────────────────────────────────────────────────
# A fake `git` on PATH answers the two calls the rule makes from FILE-based
# fixtures: FAKE_CHANGED_FILE (newline-separated changed paths) and
# FAKE_EXISTS_FILE (newline-separated objects that exist: commits, or
# "<rev>:<path>"). Files, not environment variables: a fixture the size of a
# real large-PR change list, passed as an exported env var to a re-exec'd
# subprocess, can exceed the kernel's execve() argv+envp limit (ARG_MAX) —
# observed on a CI container where the effective limit is far below what a
# developer workstation allows, even though the *script's own* internal
# here-string handling (the fix this exact fixture exists to verify) has no
# such limit. A file has none either way.

selftest() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_readme_touch.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  mkdir "$tmp/bin"
  cat > "$tmp/bin/git" <<'FAKE'
#!/usr/bin/env bash
case "$1" in
  cat-file) obj="${3%^\{commit\}}"; grep -qxF -- "$obj" <"${FAKE_EXISTS_FILE:?}" ;;
  diff)     cat "${FAKE_CHANGED_FILE:?}" ;;
  *)        exit 1 ;;
esac
FAKE
  chmod +x "$tmp/bin/git"
  export PATH="$tmp/bin:$PATH"

  local failures=0 n=0
  # run <name> <expected rc> <changed> <exists> [body text]
  run() {
    local name="$1" want="$2" body="" rc=0
    n=$((n + 1))
    local changed_file="$tmp/changed.$n" exists_file="$tmp/exists.$n"
    printf '%s' "$3" > "$changed_file"
    printf '%s' "$4" > "$exists_file"
    if [ $# -ge 5 ]; then
      body="$tmp/body.$n"
      printf '%s' "$5" > "$body"
    fi
    FAKE_CHANGED_FILE="$changed_file" FAKE_EXISTS_FILE="$exists_file" \
      "$0" base1 head1 "$body" > "$tmp/out.$n" 2>&1 || rc=$?
    if [ "$rc" != "$want" ]; then
      echo "selftest FAIL: $name — expected rc $want, got $rc:" >&2
      sed 's/^/    /' "$tmp/out.$n" >&2
      failures=$((failures + 1))
    fi
  }
  local commits=$'base1\nhead1'
  local with_readme="$commits"$'\nhead1:agents/plugins/alpha/README.md'

  run "no plugin src change" 0 $'docs/x.md\nserver/core/src/a.cpp' "$with_readme"
  run "src and README both changed" 0 $'agents/plugins/alpha/src/a.cpp\nagents/plugins/alpha/README.md' "$with_readme"
  run "src changed, README present, no override" 1 $'agents/plugins/alpha/src/a.cpp' "$with_readme"
  run "src changed, override in body" 0 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'Summary\n\ndocs-unchanged: Caveats — comment-only change\n'
  run "src changed, override in a bullet" 0 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'- docs-unchanged: Caveats — comment-only change\n'
  run "src changed, empty override is no override" 1 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'docs-unchanged:\n'
  # PR #4112 review, minor: content-free text (no <section> — <reason> shape)
  # is not a real override, even though it is non-empty.
  run "src changed, content-free override text is no override" 1 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'docs-unchanged: x\n'
  run "src changed, plain-hyphen separator is accepted" 0 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'docs-unchanged: Caveats - comment-only change\n'
  run "override inside a code fence is invisible" 1 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'```\ndocs-unchanged: Caveats — hidden\n```\n'
  run "override inside an HTML comment is invisible" 1 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'<!--\ndocs-unchanged: Caveats — hidden\n-->\n'
  run "override on a CRLF body" 0 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'Summary\r\ndocs-unchanged: Caveats — comment-only\r\n'
  run "override after a closed fence" 0 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'```\nx\n```\ndocs-unchanged: Caveats — comment-only\n'
  run "decoy 3-backtick line inside a 4-backtick fence stays hidden" 1 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'````\n```\ndocs-unchanged: Caveats — hidden\n```\n````\n'
  run "override after the real close of a 4-backtick fence" 0 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'````\nx\n````\ndocs-unchanged: Caveats — comment-only\n'
  run "tilde fence does not close on a backtick decoy" 1 $'agents/plugins/alpha/src/a.cpp' "$with_readme" $'~~~\n```\ndocs-unchanged: Caveats — hidden\n```\n~~~\n'
  run "src changed, no README at HEAD (exempt)" 0 $'agents/plugins/beta/src/b.cpp' "$commits"
  run "two plugins, one satisfied one not" 1 $'agents/plugins/alpha/src/a.cpp\nagents/plugins/gamma/src/g.cpp\nagents/plugins/gamma/README.md' "$with_readme"$'\nhead1:agents/plugins/gamma/README.md'
  run "base commit unavailable fails closed" 1 $'agents/plugins/alpha/src/a.cpp' $'head1\nhead1:agents/plugins/alpha/README.md'
  # A change list far larger than a pipe buffer (64 KiB): the satisfied rule
  # must not turn into a false red through SIGPIPE.
  local big i
  big="agents/plugins/alpha/src/a.cpp"
  for i in $(seq 1 3000); do big="$big"$'\n'"docs/generated/file-$i-with-a-long-enough-name-to-fill-the-pipe.md"; done
  big="$big"$'\nagents/plugins/alpha/README.md'
  run "huge change list, README present" 0 "$big" "$with_readme"

  if [ "$failures" -ne 0 ]; then
    echo "check-plugin-readme-touch --selftest: $failures of $n fixtures failed." >&2
    return 1
  fi
  echo "check-plugin-readme-touch --selftest: all $n fixtures behaved as expected."
}

case "${1:-}" in
  --selftest) selftest; exit $? ;;
  --help|-h|"") usage ;;
esac
[ $# -ge 2 ] || usage
check "$@"
