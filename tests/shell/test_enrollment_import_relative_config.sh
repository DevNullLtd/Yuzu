#!/usr/bin/env bash
# test_enrollment_import_relative_config.sh — regression test for PR #5107's
# review BLOCKER (WS-6 6.2, adversarial review by FortitudeEtc/Codex-Sol/Kimi-K3).
#
# A bare relative `--config yuzu-server.cfg` (no `--data-dir`) left
# `cfg_.auth_config_path.parent_path()` empty. `Locations{data_dir,
# auth_config_path.parent_path()}` (server.cpp) then skipped the config-dir
# probe for the one-time legacy enrollment import (enrollment_cfg_import.cpp)
# entirely, because `locate()` only probes a directory when its string is
# non-empty. The pre-6.2 code implicitly resolved that same empty parent
# against the process's CWD via plain path concatenation
# (`std::filesystem::path("") / "enrollment-tokens.cfg"` is just the bare
# relative filename, which `std::ifstream` opens against the CWD) — so this
# was a silent REGRESSION, not a pre-existing gap: an operator's outstanding
# enrollment tokens and approve/deny decisions could be dropped on the 6.2
# upgrade with zero `[enrollment-import]` log lines, zero error, and the
# outcome reads as the documented-benign "no legacy file present" steady
# state (Outcome::absent), which alerts on nothing.
#
# The fix (main.cpp) canonicalizes `--config` to an absolute path immediately
# after resolving it, before anything derives a directory from it. This test
# reproduces the reviewer's exact live A/B: boot the server from a CWD that
# holds both legacy files, with a bare relative `--config` and no `--data-dir`,
# and assert the import actually ran — both the token (partially consumed,
# max_uses=3 use_count=1) and the pending-agent (status=denied) rows must
# land in Postgres with their exact prior state preserved, and both legacy
# files must be renamed aside (`*.imported`), matching the successful-import
# behavior `tests/unit/server/test_enrollment_cfg_import.cpp` already proves
# for an ABSOLUTE config/data dir — this is the ONE shape that suite cannot
# exercise (Catch2 never drives main()).
#
# Requires: a built yuzu-server, YUZU_TEST_POSTGRES_DSN, psql, python3.
# Run:  bash tests/shell/test_enrollment_import_relative_config.sh

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
BIN=""
if [ -n "${YUZU_SERVER_BIN:-}" ] && [ -x "${YUZU_SERVER_BIN}" ]; then
  BIN="${YUZU_SERVER_BIN}"
else
  for d in build-linux build-macos build-windows; do
    for p in "$ROOT/$d/server/core/yuzu-server" "$ROOT/$d/server/core/yuzu-server.exe"; do
      [ -x "$p" ] && BIN="$p" && break
    done
    [ -n "$BIN" ] && break
  done
fi
if [ -z "$BIN" ]; then
  echo "SKIP: no built yuzu-server binary found (build with -Dbuild_server=true first)" >&2
  exit 0
fi

PG_DSN="${YUZU_TEST_POSTGRES_DSN:-}"
if [ -z "$PG_DSN" ]; then
  echo "SKIP: YUZU_TEST_POSTGRES_DSN unset — this test boots a real server against Postgres. Set it to run this test." >&2
  exit 0
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "SKIP: psql not on PATH — cannot provision the ephemeral database or verify persisted rows." >&2
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 not on PATH — needed to seed the admin credential and the legacy .cfg files." >&2
  exit 0
fi

pass=0 fail=0
report() { # <desc> <ok:0|1>
  if [ "$2" = "0" ]; then echo "ok   - $1"; pass=$((pass+1))
  else echo "FAIL - $1"; fail=$((fail+1)); fi
}

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

# ── Ephemeral database (never mutates the shared base DB; safe on a shared runner) ──
SALT="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
DB="yuzu_relcfg_$$_${SALT}"
dsn_base="${PG_DSN%%\?*}"
dsn_query=""
[ "$dsn_base" != "$PG_DSN" ] && dsn_query="?${PG_DSN#*\?}"
dsn_prefix="${dsn_base%/*}"
CHILD_DSN="${dsn_prefix}/${DB}${dsn_query}"

if ! psql "$PG_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"${DB}\";" >/dev/null 2>&1; then
  echo "FAIL: could not CREATE DATABASE ${DB} on YUZU_TEST_POSTGRES_DSN — Postgres is set but unusable." >&2
  exit 1
fi

RIG="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-relcfg-test.XXXXXX")"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill -KILL "$SERVER_PID" 2>/dev/null
  psql "$PG_DSN" -qtAc "DROP DATABASE IF EXISTS \"${DB}\" WITH (FORCE);" >/dev/null 2>&1 || true
  rm -rf "$RIG"
}
trap cleanup EXIT

psql_db() { PGPASSWORD="" psql "$CHILD_DSN" -v ON_ERROR_STOP=1 -qtAc "$1"; }

# Seed an admin config so the server never falls into interactive first-run
# setup (would hang this test waiting on stdin) — same seed shape as
# test_generate_tokens.sh / test_mfa_reset.sh.
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'testpass123', salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > "$RIG/yuzu-server.cfg"
chmod 600 "$RIG/yuzu-server.cfg"

# The legacy .cfg files this test's bug drops: one enrollment token
# (partially consumed: max_uses=3, use_count=1 — the shape the successful-path
# unit tests also assert, so a false pass here can't be mistaken for the
# import running with a trivially-empty file) and one DENIED pending agent
# (the exact "approve/deny decisions must survive the upgrade" anchor
# enrollment_cfg_import.hpp cites) — both written directly in the OLD file
# format (colon-delimited, header comment), matching what a real pre-6.2
# server would have on disk.
TOKEN_RAW="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
TOKEN_HASH="$(python3 -c "import hashlib,sys; print(hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest())" "$TOKEN_RAW")"
NOW_EPOCH="$(date +%s)"
cat > "$RIG/enrollment-tokens.cfg" <<EOF
# Version: 1
# Format: token_id:token_hash:label:max_uses:use_count:created_epoch:expires_epoch:revoked
${TOKEN_HASH:0:8}:${TOKEN_HASH}:relcfg-test:3:1:${NOW_EPOCH}:0:0
EOF
cat > "$RIG/pending-agents.cfg" <<EOF
# Version: 1
# Format: agent_id:hostname:os:arch:version:requested_epoch:status
relcfg-denied-agent:relcfg-host:linux:x86_64:1.0.0:${NOW_EPOCH}:denied
EOF
chmod 600 "$RIG/enrollment-tokens.cfg" "$RIG/pending-agents.cfg"

WEB_PORT="$(free_port)"
GRPC_PORT="$(free_port)"
MGMT_PORT="$(free_port)"

wait_ready() { # <web-port> <timeout-s>
  local port="$1" limit="$2" start now
  start=$(date +%s)
  while :; do
    if curl -sf --max-time 2 "http://127.0.0.1:${port}/readyz" 2>/dev/null | grep -q '"ready"'; then
      return 0
    fi
    now=$(date +%s)
    (( now - start >= limit )) && return 1
    sleep 0.5
  done
}

echo "== booting yuzu-server from CWD=$RIG with a BARE RELATIVE --config (the reviewer's exact repro), no --data-dir"
# The whole point: --config is a bare filename, not an absolute path or a
# ./-prefixed one, and no --data-dir is given — both must be true for
# `auth_config_path.parent_path()` to be empty. Started in a subshell so this
# script's own CWD is untouched.
(
  cd "$RIG" || exit 1
  exec "$BIN" --listen "127.0.0.1:${GRPC_PORT}" --no-tls --no-https --no-default-certs \
    --web-address 127.0.0.1 --web-port "$WEB_PORT" --management "127.0.0.1:${MGMT_PORT}" \
    --postgres-dsn "$CHILD_DSN" --config yuzu-server.cfg \
    --ca-dir "$RIG/certs" >> "$RIG/server.log" 2>&1
) &
SERVER_PID=$!

if ! wait_ready "$WEB_PORT" 60; then
  echo "server never became ready" >&2
  tail -50 "$RIG/server.log" >&2
  exit 1
fi
report "server booted and became ready with a bare relative --config" 0

# ── The regression check: did the import actually run? ──
IMPORTED_TOKENS="$(psql_db "SELECT count(*) FROM auth.import_meta WHERE key='enrollment-tokens.cfg'" 2>/dev/null || echo 0)"
IMPORTED_PENDING="$(psql_db "SELECT count(*) FROM auth.import_meta WHERE key='pending-agents.cfg'" 2>/dev/null || echo 0)"
if [ "$IMPORTED_TOKENS" = "1" ] && [ "$IMPORTED_PENDING" = "1" ]; then
  report "import ran for both legacy file kinds despite the bare relative --config (auth.import_meta stamped)" 0
else
  report "import ran for both legacy file kinds (tokens=$IMPORTED_TOKENS pending=$IMPORTED_PENDING, want 1/1) — THIS IS THE PR #5107 BLOCKER IF IT FAILS" 1
fi

ROW_SHAPE="$(psql_db "SELECT max_uses||','||use_count||','||revoked::int FROM auth.enrollment_tokens WHERE token_hash='${TOKEN_HASH}'" 2>/dev/null || echo "")"
if [ "$ROW_SHAPE" = "3,1,0" ]; then
  report "imported token row preserved its exact prior state (max_uses=3, use_count=1, not revoked)" 0
else
  report "imported token row shape (got '$ROW_SHAPE', want '3,1,0')" 1
fi

AGENT_STATUS="$(psql_db "SELECT status FROM auth.pending_agents WHERE agent_id='relcfg-denied-agent'" 2>/dev/null || echo "")"
if [ "$AGENT_STATUS" = "denied" ]; then
  report "imported pending-agent row preserved its DENIED status (the exact WS-6 6.2 governance-1 concern)" 0
else
  report "imported pending-agent status (got '$AGENT_STATUS', want 'denied')" 1
fi

if [ -f "$RIG/enrollment-tokens.cfg.imported" ] && [ -f "$RIG/pending-agents.cfg.imported" ]; then
  report "both legacy files renamed aside after import (never re-read)" 0
else
  report "legacy files renamed aside (enrollment-tokens.cfg.imported exists: $([ -f "$RIG/enrollment-tokens.cfg.imported" ] && echo yes || echo no), pending-agents.cfg.imported exists: $([ -f "$RIG/pending-agents.cfg.imported" ] && echo yes || echo no))" 1
fi

kill -KILL "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""

echo ""
echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
