#!/usr/bin/env bash
# visualization-demo.sh — End-to-end demo of issue #253 chart rendering.
#
# Prereq: a running UAT stack (server + gateway + at least one agent).
#   bash scripts/start-UAT.sh
#
# What it does:
#   1. Imports an InstructionDefinition with `spec.visualization` set.
#   2. Dispatches it to all connected agents.
#   3. Polls until responses come in.
#   4. GETs /api/v1/executions/<cmd_id>/visualization and pretty-prints the
#      chart-ready JSON.
#   5. Renders the HTMX fragment that embeds the chart card.
#   6. Probes the static SVG-renderer asset.
#
# When you log in to the dashboard at http://localhost:8080/ (admin /
# YuzuUatAdmin1!) and dispatch the same instruction via the Send button,
# the chart deck auto-renders above the results table — no browser
# console paste required (#589 closed). The flow below is the headless /
# external-tool path, suitable for Grafana scripted-panel datasources or
# any custom dashboard that consumes JSON over HTTP.

set -euo pipefail

UAT="${YUZU_UAT_DIR:-/tmp/yuzu-uat}"
BASE="${YUZU_BASE_URL:-http://localhost:8080}"

if [[ ! -f "$UAT/cookies.txt" ]]; then
    echo "✗ No session cookies at $UAT/cookies.txt" >&2
    echo "  Run: bash scripts/start-UAT.sh" >&2
    exit 1
fi

DEF_ID="demo.viz.os_distribution"

echo "──────────────────────────────────────────────────────────────"
echo "Step 1/4 — Import InstructionDefinition with spec.visualization"
echo "──────────────────────────────────────────────────────────────"

DEF_BODY=$(python3 -c "
import json
print(json.dumps({
  'id': '$DEF_ID',
  'name': 'OS Distribution (demo)',
  'type': 'question',
  'plugin': 'os_info',
  'action': 'os_name',
  'version': '1.0',
  'description': 'Pie chart of OS distribution across the fleet (issue #253 demo).',
  'platforms': 'windows,linux,darwin',
  'visualization_spec': {
    'type': 'pie',
    'processor': 'single_series',
    'title': 'OS Distribution',
    'labelField': 1,
    'maxCategories': 8,
  }
}))")

IMPORT=$(curl -s -b "$UAT/cookies.txt" \
    -X POST "$BASE/api/instructions/import" \
    -H "Content-Type: application/json" \
    -d "$DEF_BODY")

if echo "$IMPORT" | grep -q '"id"'; then
    echo "  ✓ Created definition: $DEF_ID"
elif echo "$IMPORT" | grep -qi 'already exists\|conflict'; then
    echo "  ↻ Definition already exists — re-using."
else
    echo "  ✗ Import failed: $IMPORT"
    exit 1
fi

echo ""
echo "──────────────────────────────────────────────────────────────"
echo "Step 2/4 — Dispatch the definition"
echo "──────────────────────────────────────────────────────────────"

DISPATCH=$(curl -s -b "$UAT/cookies.txt" \
    -X POST "$BASE/api/instructions/$DEF_ID/execute" \
    -H "Content-Type: application/json" \
    -d '{"scope":"__all__"}')

CMD_ID=$(echo "$DISPATCH" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('command_id',''))")
AGENTS=$(echo "$DISPATCH" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('agents_reached',0))")

if [[ -z "$CMD_ID" ]]; then
    echo "  ✗ Dispatch failed: $DISPATCH"
    exit 1
fi

echo "  ✓ Dispatched to $AGENTS agent(s); command_id=$CMD_ID"

echo ""
echo "──────────────────────────────────────────────────────────────"
echo "Step 3/4 — Poll for responses"
echo "──────────────────────────────────────────────────────────────"

waited=0
while [[ $waited -lt 15 ]]; do
    sleep 1
    waited=$((waited + 1))
    COUNT=$(curl -s -b "$UAT/cookies.txt" "$BASE/api/responses/$CMD_ID" \
        | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('responses',[])))" 2>/dev/null \
        || echo 0)
    if [[ "$COUNT" -ge 1 ]]; then
        echo "  ✓ $COUNT response(s) recorded after ${waited}s"
        break
    fi
done

if [[ "${COUNT:-0}" -lt 1 ]]; then
    echo "  ✗ No responses after 15s — check $UAT/agent.log"
    exit 1
fi

echo ""
echo "──────────────────────────────────────────────────────────────"
echo "Step 4/4 — Render visualization"
echo "──────────────────────────────────────────────────────────────"
echo ""
echo "  REST: GET /api/v1/executions/$CMD_ID/visualization?definition_id=$DEF_ID"
echo ""

curl -s -b "$UAT/cookies.txt" \
    "$BASE/api/v1/executions/$CMD_ID/visualization?definition_id=$DEF_ID" \
    | python3 -m json.tool

echo ""
echo "  Fragment: GET /fragments/executions/$CMD_ID/visualization?definition_id=$DEF_ID"
echo ""
FRAGMENT=$(curl -s -b "$UAT/cookies.txt" \
    "$BASE/fragments/executions/$CMD_ID/visualization?definition_id=$DEF_ID")
echo "    $FRAGMENT"

echo ""
echo "  Static asset: HEAD /static/yuzu-charts.js"
JS_SIZE=$(curl -s -o /dev/null -w "%{size_download}" "$BASE/static/yuzu-charts.js")
echo "    Body size: $JS_SIZE bytes"

echo ""
echo "──────────────────────────────────────────────────────────────"
echo "  See the chart inline in the dashboard:"
echo ""
echo "    1. Visit $BASE/ and log in (admin / YuzuUatAdmin1!)"
echo "    2. In the instruction box, type: os_info os_name"
echo "    3. Click Send"
echo ""
echo "  After ~2s the chart deck appears above the results table."
echo "  The dashboard reverse-looks-up '$DEF_ID' from (plugin, action)"
echo "  and threads definition_id through the OOB swaps so the chart"
echo "  card renders without a browser-console paste."
echo "──────────────────────────────────────────────────────────────"
echo ""
echo "  (Power-user / external-tool path: the REST endpoint above"
echo "  returns the same JSON for Grafana scripted-panel datasources"
echo "  or any custom dashboard.)"
echo "──────────────────────────────────────────────────────────────"
