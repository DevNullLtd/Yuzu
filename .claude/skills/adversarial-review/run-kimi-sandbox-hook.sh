#!/usr/bin/env bash
# Intercept Kimi's one permitted empirical request. The native Bash deny rule
# remains in force after this hook, so hook failure cannot grant shell access.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECTED="$SCRIPT_DIR/run-kimi-sandboxed-shell.sh"
INPUT="$(head -c 65536)"
COMMAND="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))' <<<"$INPUT")"

if [[ "$COMMAND" != "$EXPECTED" ]]; then
  exit 0
fi

if "$EXPECTED"; then
  OUTPUT_FILE="${YUZU_KIMI_SANDBOX_REVIEW_DIR:?}/KIMI_SANDBOX_OUTPUT.md"
  OUTPUT="$(head -c 32768 "$OUTPUT_FILE" 2>/dev/null || true)"
  python3 -c 'import json,sys; print(json.dumps({"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Sandbox collector completed; direct Bash remains denied. Collector output:\n" + sys.stdin.read()}}))' <<<"$OUTPUT"
else
  printf '%s\n' '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Sandbox collector failed; direct Bash remains denied."}}'
fi
