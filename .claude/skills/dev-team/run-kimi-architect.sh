#!/usr/bin/env bash
# run-kimi-architect.sh — one-shot Kimi architectural consultation for /dev-team.
#
# Simpler than the adversarial-review Kimi driver: no phase protocol, no peer files.
# The senior injects the full architect prompt (plan + code context + output contract)
# via --question; the model's answer is written to --output-file.
#
# Usage:
#   run-kimi-architect.sh \
#     --question "$ARCHITECT_PROMPT" \
#     --output-file /tmp/dev-team-architect-verdict.md \
#     [--model kimi-k2.7-code] [--max-tokens 32000]
#
# Auth: OLLAMA_API_KEY from env or ~/.hermes/.env (never printed).
# Note: Kimi is static-only — it cannot read files. The senior must inject all
#       relevant source code into --question. Label findings `static-read`.

set -euo pipefail

QUESTION=""
OUTPUT_FILE=""
MODEL="kimi-k2.7-code"
MAX_TOKENS="32000"
BASE_URL="${OLLAMA_BASE_URL:-https://ollama.com/v1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --question)    QUESTION="$2";    shift 2 ;;
    --output-file) OUTPUT_FILE="$2"; shift 2 ;;
    --model)       MODEL="$2";       shift 2 ;;
    --max-tokens)  MAX_TOKENS="$2";  shift 2 ;;
    -h|--help) grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$QUESTION" && -n "$OUTPUT_FILE" ]] || {
  echo "error: --question and --output-file are required" >&2; exit 2; }
command -v jq   >/dev/null || { echo "error: jq required"   >&2; exit 2; }
command -v curl >/dev/null || { echo "error: curl required"  >&2; exit 2; }

# Auth
if [[ -z "${OLLAMA_API_KEY:-}" ]]; then
  if [[ -f "$HOME/.hermes/.env" ]]; then
    OLLAMA_API_KEY="$(grep -E '^OLLAMA_API_KEY=' "$HOME/.hermes/.env" | head -1 | cut -d= -f2-)"
  fi
fi
[[ -n "${OLLAMA_API_KEY:-}" ]] || {
  echo "error: OLLAMA_API_KEY not set and not in ~/.hermes/.env" >&2; exit 2; }

PROMPT_FILE="$(mktemp)"
BODY_FILE="$(mktemp)"
RESP_FILE="$(mktemp)"
trap 'rm -f "$PROMPT_FILE" "$BODY_FILE" "$RESP_FILE"' EXIT

printf '%s' "$QUESTION" > "$PROMPT_FILE"

jq -n \
  --rawfile p "$PROMPT_FILE" \
  --arg model "$MODEL" \
  --argjson max "$MAX_TOKENS" \
  '{model:$model, think:true, messages:[{role:"user",content:$p}], stream:false, temperature:0.2, max_tokens:$max}' \
  > "$BODY_FILE"

echo ">> Kimi architect: model=$MODEL max_tokens=$MAX_TOKENS" >&2
echo ">> prompt $(wc -c < "$PROMPT_FILE") bytes → $OUTPUT_FILE" >&2

HTTP=$(curl -sS -w '%{http_code}' -o "$RESP_FILE" \
  "$BASE_URL/chat/completions" \
  -H "Authorization: Bearer $OLLAMA_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @"$BODY_FILE" \
  --max-time 600) || { echo ">> curl failed" >&2; exit 1; }

if [[ "$HTTP" != "200" ]]; then
  echo ">> HTTP $HTTP from Ollama Cloud:" >&2
  jq -r '.error // .' "$RESP_FILE" 2>/dev/null | head -5 >&2
  exit 1
fi

RAW_JSON="${OUTPUT_FILE%.md}.raw.json"
cp "$RESP_FILE" "$RAW_JSON"

jq -r '.choices[0].message.content // ""' "$RESP_FILE" > "$OUTPUT_FILE"

FINISH=$(jq -r '.choices[0].finish_reason // "?"'           "$RESP_FILE")
USED=$(jq   -r '.usage.completion_tokens // 0'              "$RESP_FILE")
REASON_LEN=$(jq -r '(.choices[0].message.reasoning // "") | length' "$RESP_FILE")

BUDGET_EXHAUSTED=0
[[ "$USED" -ge $((MAX_TOKENS - 8)) ]] && BUDGET_EXHAUSTED=1

if [[ -s "$OUTPUT_FILE" && "$BUDGET_EXHAUSTED" -eq 0 ]]; then
  echo ">> OK: $OUTPUT_FILE ($(wc -l < "$OUTPUT_FILE") lines, finish=$FINISH, completion_tokens=$USED, reasoning_chars=$REASON_LEN)" >&2
else
  echo ">> FAIL: no usable content (finish=$FINISH, completion_tokens=$USED/$MAX_TOKENS, reasoning_chars=$REASON_LEN)" >&2
  [[ "$BUDGET_EXHAUSTED" -eq 1 ]] && echo ">>   → budget exhausted in reasoning; raise --max-tokens or shrink prompt." >&2
  echo ">>   Raw response: $RAW_JSON" >&2
  exit 1
fi
