#!/usr/bin/env bash
# run-codex-reviewer.sh — drive the Codex side of an adversarial two-phase review.
#
# Renders review-prompt.md with the CONFIG block injected, then runs `codex exec`
# non-interactively. Codex writes its own review to $REVIEW_DIR/codex.phaseN.md
# (per the prompt); we also capture its final summary message via `-o`.
#
# The orchestrator (Claude) calls this once for Phase 1 and again for Phase 2.
# Each call is a fresh, ephemeral Codex session — all cross-phase state lives on
# disk in REVIEW_DIR, exactly as the protocol requires.
#
# Usage:
#   run-codex-reviewer.sh --phase 1 --review-dir DIR --target "PR #1220, head abc, diff X..Y" \
#       [--repo .] [--anchors "- CLAUDE.md\n- docs/foo.md §3"] \
#       [--self codex] [--peer claude] [--sandbox workspace-write] [--model NAME] [--static-only]
#
# Notes:
#   * --sandbox workspace-write (default) lets Codex compile/run tests inside the repo
#     and write to REVIEW_DIR (passed via --add-dir). Use danger-full-access only if a
#     build genuinely needs network/system access the workspace sandbox denies.
#   * Exit code is Codex's; the phase file's existence is the real success signal —
#     the orchestrator checks for $REVIEW_DIR/$SELF.phaseN.md before proceeding.

set -euo pipefail

# LOAD-BEARING — do not remove. Bash >= 5.2 defaults `patsub_replacement` ON, which
# makes an unescaped `&` in a ${var//pat/repl} replacement expand to the MATCH. Every
# `&` in an injected value then becomes the literal token being replaced, silently
# corrupting `&&` in anchors, C++ reference types (`bool& x`) and URL query strings
# in the text under review. run-kimi-reviewer.sh carries the same guard (added in the
# same change — neither driver had it before) — keep the two in sync; the regression
# test drives BOTH drivers.
shopt -u patsub_replacement 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_TEMPLATE="$SCRIPT_DIR/review-prompt.md"

PHASE=""
REVIEW_DIR=""
TARGET=""
REPO="$(pwd)"
ANCHORS="(none specified — fall back to CLAUDE.md routing table + the docs it points changed files at)"
SELF="codex"
PEER="claude"
SANDBOX="workspace-write"
MODEL=""
STATIC_ONLY="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)       PHASE="$2"; shift 2 ;;
    --review-dir)  REVIEW_DIR="$2"; shift 2 ;;
    --target)      TARGET="$2"; shift 2 ;;
    --repo)        REPO="$2"; shift 2 ;;
    --anchors)     ANCHORS="$2"; shift 2 ;;
    --self)        SELF="$2"; shift 2 ;;
    --peer)        PEER="$2"; shift 2 ;;
    --sandbox)     SANDBOX="$2"; shift 2 ;;
    --model)       MODEL="$2"; shift 2 ;;
    --static-only) STATIC_ONLY="true"; shift ;;
    --prompt-template) PROMPT_TEMPLATE="$2"; shift 2 ;;
    -h|--help)     awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$PHASE" && -n "$REVIEW_DIR" && -n "$TARGET" ]] || {
  echo "error: --phase, --review-dir, and --target are required" >&2; exit 2; }
[[ "$PHASE" == "1" || "$PHASE" == "2" ]] || { echo "error: --phase must be 1 or 2" >&2; exit 2; }
[[ -f "$PROMPT_TEMPLATE" ]] || { echo "error: prompt template not found: $PROMPT_TEMPLATE" >&2; exit 2; }

mkdir -p "$REVIEW_DIR"
REPO="$(cd "$REPO" && pwd)"
REVIEW_DIR="$(cd "$REVIEW_DIR" && pwd)"

# Render the prompt: substitute the {{TOKENS}} in the template.
render() {
  local body
  body="$(cat "$PROMPT_TEMPLATE")"
  body="${body//\{\{SELF\}\}/$SELF}"
  body="${body//\{\{PEER\}\}/$PEER}"
  body="${body//\{\{TARGET\}\}/$TARGET}"
  body="${body//\{\{REPO\}\}/$REPO}"
  body="${body//\{\{REVIEW_DIR\}\}/$REVIEW_DIR}"
  body="${body//\{\{PHASE\}\}/$PHASE}"
  body="${body//\{\{ANCHORS\}\}/$ANCHORS}"
  printf '%s\n' "$body"
}

PROMPT="$(render)"
if [[ "$STATIC_ONLY" == "true" ]]; then
  read -r -d '' STATIC_NOTE <<'EOF' || true

---
## STATIC SAFETY PASS
This phase runs before any PR-controlled configure, build, test, generator, hook, or dependency
command. Do not execute project code or invoke build-system commands. Inspect the diff, source, and
anchors only; tag findings `static-read`. The orchestrator will record dynamic evidence separately
after the trust gate.
EOF
  PROMPT="$PROMPT$STATIC_NOTE"
fi
SUMMARY_FILE="$REVIEW_DIR/$SELF.phase$PHASE.summary.md"

echo ">> Codex reviewer: SELF=$SELF PEER=$PEER PHASE=$PHASE sandbox=$SANDBOX" >&2
echo ">> repo=$REPO  review_dir=$REVIEW_DIR" >&2
echo ">> expecting Codex to write: $REVIEW_DIR/$SELF.phase$PHASE.md" >&2

CODEX_ARGS=(
  exec
  --cd "$REPO"
  --sandbox "$SANDBOX"
  --add-dir "$REVIEW_DIR"
  --skip-git-repo-check
  --ephemeral
  -o "$SUMMARY_FILE"
)
[[ -n "$MODEL" ]] && CODEX_ARGS+=(--model "$MODEL")

printf '%s' "$PROMPT" | codex "${CODEX_ARGS[@]}" -

PHASE_FILE="$REVIEW_DIR/$SELF.phase$PHASE.md"
if [[ -s "$PHASE_FILE" ]]; then
  echo ">> OK: $PHASE_FILE ($(wc -l < "$PHASE_FILE") lines)" >&2
else
  echo ">> WARNING: $PHASE_FILE missing or empty — Codex may not have written it." >&2
  echo ">> Check its summary at: $SUMMARY_FILE" >&2
  exit 1
fi
