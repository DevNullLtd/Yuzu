#!/usr/bin/env bash
# test_review_driver_substitution.sh — regression net for the adversarial-review
# driver prompt substitution, over BOTH drivers (Codex and Kimi).
#
# Bash >= 5.2 turns `patsub_replacement` ON by default, which makes an unescaped
# `&` in a ${var//pat/repl} REPLACEMENT expand to the text that was MATCHED. The
# drivers render their prompt template with exactly that construct, so without an
# explicit `shopt -u patsub_replacement` every `&` in an injected value silently
# becomes the token being substituted:
#
#     --anchors "failure() && cancelled()"   ->   "failure() {{ANCHORS}}{{ANCHORS}} cancelled()"
#     a C++ snippet "bool& ref"              ->   "bool{{ANCHORS}} ref"
#     a URL "?a=1&b=2"                       ->   "?a=1{{ANCHORS}}b=2"
#
# That corrupts the anchors a reviewer grades against, and mangles any C++
# reference type or query string in the code under review — silently, in a file
# nobody reads, on every run. Observed live on the #2622 review (recorded in
# .claude/skills/governance/SKILL.md and docs/governance-skill-tuning-2026-07.md).
#
# This drives the REAL drivers with stub `codex`/`kimi` binaries on PATH, captures
# the prompt each would have sent, and asserts the ampersands survive.
#
# Known limitation (pre-existing, not what this net guards): render() substitutes
# the seven tokens in sequential passes, so a token literal INSIDE an injected
# value (e.g. --target 'touches {{REPO}}') is expanded by a later pass. This net
# covers ampersand corruption only.
#
# Run:  bash tests/shell/test_review_driver_substitution.sh
set -euo pipefail

# The defect mechanism (`patsub_replacement`) only exists on bash >= 5.2. On older
# bash the guard-under-test is inert AND the corruption cannot manifest, so every
# assertion would pass vacuously with or without the guard. Skip LOUDLY rather
# than print a green that verified nothing (CI runs Ubuntu bash >= 5.2; this
# branch is for stock macOS /bin/bash 3.2).
if (( BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 2) )); then
  echo "  [SKIP] bash ${BASH_VERSION} < 5.2 — patsub_replacement does not exist here;"
  echo "         this net cannot arm. Re-run under bash >= 5.2 (CI does)."
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # script-relative, never the caller's CWD
SKILL_DIR="$ROOT/.claude/skills/adversarial-review"
CODEX_DRIVER="$SKILL_DIR/run-codex-reviewer.sh"
KIMI_DRIVER="$SKILL_DIR/run-kimi-reviewer.sh"
[ -f "$CODEX_DRIVER" ] || { echo "missing $CODEX_DRIVER" >&2; exit 2; }
[ -f "$KIMI_DRIVER" ]  || { echo "missing $KIMI_DRIVER" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-revsub-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin"

# Stub `codex`: the Codex driver pipes the rendered prompt to it on stdin.
cat > "$TMP/bin/codex" <<EOF
#!/usr/bin/env bash
cat > "$TMP/captured-codex.txt"
EOF
chmod +x "$TMP/bin/codex"

# Stub `kimi`: the Kimi driver passes the rendered prompt as the argument after
# `-p` (plus other flags), and probes `kimi --version` first.
cat > "$TMP/bin/kimi" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then echo "0.16.0"; exit 0; fi
while [ \$# -gt 0 ]; do
  if [ "\$1" = "-p" ]; then printf '%s' "\$2" > "$TMP/captured-kimi.txt"; shift 2; else shift; fi
done
EOF
chmod +x "$TMP/bin/kimi"

# The Kimi driver's restricted (default/static) mode requires --review-dir inside
# --repo, refuses a project-local .kimi-code, and clones KIMI_CODE_HOME's
# config.toml — give it a scratch repo and a minimal clean config.
mkdir -p "$TMP/repo/rev" "$TMP/kimi-home"
printf 'model = "stub"\n' > "$TMP/kimi-home/config.toml"

ANCHORS='- failure() && cancelled() guards
- C++ `bool& ref` params
- url?a=1&b=2'

pass=0 fail=0
# expect_literal <capture> <desc> <string that must appear verbatim>
expect_literal() {
  local cap="$1" desc="$2" needle="$3"
  if grep -qF -- "$needle" "$cap"; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s — %q not found in rendered prompt\n' "$desc" "$needle"; fail=$((fail + 1))
  fi
}
# expect_absent <capture> <desc> <string that must NOT appear>
expect_absent() {
  local cap="$1" desc="$2" needle="$3"
  if grep -qF -- "$needle" "$cap"; then
    printf '  [FAIL] %s — %q leaked into rendered prompt\n' "$desc" "$needle"; fail=$((fail + 1))
  else
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  fi
}

# run_driver <name> <capture-file> <driver> [extra args...]
run_driver() {
  local name="$1" cap="$2" driver="$3"; shift 3
  : > "$TMP/driver-$name.stderr"
  PATH="$TMP/bin:$PATH" KIMI_CODE_HOME="$TMP/kimi-home" bash "$driver" \
    --phase 1 --target 'smoke && test' --anchors "$ANCHORS" "$@" \
    >/dev/null 2>"$TMP/driver-$name.stderr" || true
  if [ ! -s "$cap" ]; then
    echo "  [FAIL] $name driver produced no prompt — driver stderr:" >&2
    sed 's/^/    | /' "$TMP/driver-$name.stderr" >&2
    exit 1
  fi
  echo "  -- $name driver --"
  expect_literal "$cap" "&& survives in anchors"        'failure() && cancelled() guards'
  expect_literal "$cap" "C++ reference type survives"   'bool& ref'
  expect_literal "$cap" "URL query separator survives"  'url?a=1&b=2'
  expect_literal "$cap" "&& survives in target"         'smoke && test'
  # The tell-tale of the patsub bug: the token being replaced appears in its own output.
  expect_absent  "$cap" "no {{ANCHORS}} echoed back"    '{{ANCHORS}}'
  expect_absent  "$cap" "no {{TARGET}} echoed back"     '{{TARGET}}'
}

run_driver codex "$TMP/captured-codex.txt" "$CODEX_DRIVER" \
  --review-dir "$TMP/repo/rev" --repo "$ROOT" --self codex --peer kimi
run_driver kimi  "$TMP/captured-kimi.txt"  "$KIMI_DRIVER" \
  --review-dir "$TMP/repo/rev" --repo "$TMP/repo" --self kimi --peer codex

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
