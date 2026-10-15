#!/usr/bin/env bash
# test_check_compose_versions.sh — fixture tests for scripts/check-compose-versions.sh
#
# The compose-version gate is the FIRST step of the release job; a silent regex
# regression (e.g. the BASH_REMATCH capture-group index shift when the optional
# `(-chisel)?` group was added) would let a mismatched image pin ship a whole
# release. This exercises the parameterized / hardcoded / -chisel / floating /
# ${YUZU_REGISTRY} cases hermetically against synthetic compose fixtures — the
# gate accepts an explicit file list after the version for exactly this purpose.
#
# Run:  bash tests/shell/test_check_compose_versions.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
GATE="$ROOT/scripts/check-compose-versions.sh"
[ -f "$GATE" ] || { echo "missing $GATE" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-ccv-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
# expect <wanted-exit> <desc> <version> <file...>
expect() {
  local want="$1" desc="$2" ver="$3"; shift 3
  local got=0
  bash "$GATE" "$ver" "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" = "$want" ]; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s (want exit %s, got %s)\n' "$desc" "$want" "$got"; fail=$((fail + 1))
  fi
}

mkf() { printf '%s\n' "$2" > "$TMP/$1"; printf '%s' "$TMP/$1"; }

f_ok_plain="$(mkf ok_plain.yml      '    image: ghcr.io/devnullltd/yuzu-server:${YUZU_VERSION:-0.12.0}')"
f_ok_chisel="$(mkf ok_chisel.yml    '    image: ghcr.io/devnullltd/yuzu-gateway-chisel:${YUZU_VERSION:-0.12.0}')"
f_ok_regvar="$(mkf ok_regvar.yml    '    image: ${YUZU_REGISTRY:-ghcr.io/devnullltd}/yuzu-agent-chisel:${YUZU_VERSION:-0.12.0}')"
f_drift_chisel="$(mkf drift.yml     '    image: ghcr.io/devnullltd/yuzu-server-chisel:${YUZU_VERSION:-0.11.0}')"
f_hardcoded="$(mkf hardcoded.yml    '    image: ghcr.io/devnullltd/yuzu-server:0.12.0')"
f_floating="$(mkf floating.yml      '    image: ghcr.io/devnullltd/yuzu-server:latest')"
# yuzu-postgres joined the pin discipline in #1318 (F4/F5 of the Postgres
# substrate program) — exercise all three behaviours for the new repo name.
f_ok_pg="$(mkf ok_pg.yml            '    image: ghcr.io/devnullltd/yuzu-postgres:${YUZU_VERSION:-0.12.0}')"
f_drift_pg="$(mkf drift_pg.yml      '    image: ghcr.io/devnullltd/yuzu-postgres:${YUZU_VERSION:-0.11.0}')"
f_hard_pg="$(mkf hard_pg.yml        '    image: ghcr.io/devnullltd/yuzu-postgres:0.12.0')"
f_floating_pg="$(mkf float_pg.yml   '    image: yuzu-postgres:local')"

echo "check-compose-versions.sh fixture tests:"
expect 0 "parameterized non-chisel pin matches"          0.12.0 "$f_ok_plain"
expect 0 "parameterized -chisel pin matches"             0.12.0 "$f_ok_chisel"
expect 0 "parameterized pin under \${YUZU_REGISTRY}"     0.12.0 "$f_ok_regvar"
expect 1 "-chisel pin drift is caught"                   0.12.0 "$f_drift_chisel"
expect 1 "hardcoded numeric tag is rejected"             0.12.0 "$f_hardcoded"
expect 0 "floating tag (latest) is ignored"              0.12.0 "$f_floating"
expect 0 "parameterized yuzu-postgres pin matches"       0.12.0 "$f_ok_pg"
expect 1 "yuzu-postgres pin drift is caught"             0.12.0 "$f_drift_pg"
expect 1 "hardcoded yuzu-postgres tag is rejected"       0.12.0 "$f_hard_pg"
expect 0 "non-ghcr local yuzu-postgres tag is ignored"   0.12.0 "$f_floating_pg"

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
