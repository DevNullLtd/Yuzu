#!/usr/bin/env bash
# test_gateway_peer_boot_refusal.sh -- contract test for the gateway-upstream peer
# authorization BOOT decision, driven through the real yuzu-server binary.
#
# Refusal rows: with --gateway-upstream enabled, each configuration below must exit non-zero
# BEFORE any listener is bound, with the actionable message the resolver prints:
#   A  --no-tls, no acknowledgement          (--no-tls is not an acknowledgement)
#   B  acknowledgement + a pin               (contradictory)
#   C  operator certificates, no pin         (a pin is required)
#   D  TLS without a client CA, no ack       (no pin could ever match)
#   E  default certs, explicit pin file missing  (no fallback to the automatic pin)
#   F  default certs, malformed hex pin      (rejected at boot)
#   I  HTTPS on generated defaults while gRPC uses operator certs (the mixed-mode trap):
#      NO automatic pin, a pin is required
# Control rows (prove the refusals are specific, not a general boot failure):
#   G  default certs, no flags: boots, the default gateway certificate is pinned automatically
#   H  --no-tls + --insecure-gateway-peer: boots, loudly says peer authorization is DISABLED once,
#      mode insecure_ack, and writes one server.gateway_peer_authz_disabled boot audit row
#   J  default certs (TLS on, client CA present) + --insecure-gateway-peer: boots, mode
#      insecure_ack_tls (a production-shaped configuration with the control switched off), the
#      "pinning is available" warning, and the boot audit row with mode=insecure_ack_tls tls=true
#   K  default certs + an explicit --gateway-peer-pin: boots, enforces exactly that pin set (the
#      automatic pin is not added), mode enforce
#   L  default certs + YUZU_INSECURE_GATEWAY_PEER=0 in the environment: the boolean environment
#      value stays FALSE, so it boots enforcing with the automatic pin and no boot audit row
#   M  --no-tls + YUZU_INSECURE_GATEWAY_PEER=1 in the environment (the release-pinned compose
#      form): boots, mode insecure_ack, one boot audit row
#
# Pins are read once at boot: there is no reload and no pin gauge, so no row looks for one.
#
# "Before any listener is bound" is asserted by the absence of the log lines the server prints
# only after BuildAndStart ("Yuzu Server listening", "Gateway upstream listening"). Every port
# the rows pass is a free port picked by the OS; no row uses a default or shared port.
#
# Postgres: the server fails closed without it, so this needs YUZU_TEST_POSTGRES_DSN (each row
# gets its own uniquely named database, dropped on exit). Skip-vs-fail: on a developer box a
# missing prerequisite (binary, DSN, psql, openssl, python3) is a SKIP; when GITHUB_ACTIONS=true
# or YUZU_SERVER_BIN is set (an explicit request to run it) the same condition is a FAIL, so a CI
# step can never go green without having run. A DSN that is set but unusable is always a FAIL.
# One deliberate exception: under GITHUB_ACTIONS=true a missing `psql` is a SKIP with a
# `::warning::` annotation (exit 0), because the sibling shell tests that need a Postgres client
# skip the same way on runners that do not carry one; provisioning psql on those runners is a
# separate change. A missing server binary, openssl, python3 or DSN stays a FAIL.
# Rows run concurrently (the server's shutdown drain is a fixed few seconds).
#
# Run:  bash tests/shell/test_gateway_peer_boot_refusal.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
# skip_or_fail MSG : SKIP (exit 0) on a developer box, FAIL (exit 1) when CI or an explicit
# YUZU_SERVER_BIN says this test is required to run.
skip_or_fail() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ -n "${YUZU_SERVER_BIN:-}" ]; then
    echo "FAIL: $1 (required: GITHUB_ACTIONS=true or YUZU_SERVER_BIN is set)" >&2
    exit 1
  fi
  echo "SKIP: $1" >&2
  exit 0
}

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
[ -n "$BIN" ] || skip_or_fail "no built yuzu-server binary found"
PG_DSN="${YUZU_TEST_POSTGRES_DSN:-}"
[ -n "$PG_DSN" ] || skip_or_fail "YUZU_TEST_POSTGRES_DSN unset (the server needs Postgres)"
if ! command -v psql >/dev/null 2>&1; then
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    # Policy: a CI skip must be visible. Annotate, then skip (see the header comment).
    echo "::warning::gateway peer boot-refusal test skipped: psql not available on this runner"
    echo "SKIP: psql not on PATH (GITHUB_ACTIONS=true: warning annotation emitted)" >&2
    exit 0
  fi
  skip_or_fail "psql not on PATH"
fi
command -v openssl >/dev/null 2>&1 || skip_or_fail "openssl not on PATH"
command -v python3 >/dev/null 2>&1 || skip_or_fail "python3 not on PATH"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_gwpeer_boot.XXXXXX")"
SALT="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
# Database names are `yuzu_test_<epoch>_gwpeer_<salt>_<row, lowercase>`: lowercase [a-z0-9_] only,
# and an epoch right after the prefix, so BOTH the in-process sweeper (parse_test_db_epoch in
# tests/unit/test_helpers.hpp) and scripts/ci/sweep-test-databases.sh pass A (age by the
# name-embedded epoch) can reclaim a database this script leaked (SIGKILL, runner loss).
EPOCH="$(date +%s)"
row_db() { # ROW : prints the database name for a row
  printf 'yuzu_test_%s_gwpeer_%s_%s' "$EPOCH" "$SALT" "$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
}
dsn_base="${PG_DSN%%\?*}"
dsn_query=""
[ "$dsn_base" != "$PG_DSN" ] && dsn_query="?${PG_DSN#*\?}"
dsn_prefix="${dsn_base%/*}"
DBS=()
PIDS=()
cleanup() {
  local p d f
  # The row subshells' pids (PIDS) are not the servers: the server pid of each row is the one
  # recorded in its .pid file. Kill those (the `timeout` wrapper forwards the signal), then the
  # subshells.
  for f in "$TMP"/*.pid; do
    [ -f "$f" ] && kill "$(cat "$f")" >/dev/null 2>&1 || true
  done
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" >/dev/null 2>&1 || true; done
  for d in ${DBS[@]+"${DBS[@]}"}; do
    psql "$PG_DSN" -qtAc "DROP DATABASE IF EXISTS \"$d\" WITH (FORCE);" >/dev/null 2>&1 || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

# One admin-role config shared by every row (fresh-install bootstrap needs an admin).
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'pw'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')
" > "$TMP/boot.cfg"
chmod 600 "$TMP/boot.cfg"

# Operator-style certificates: a throwaway CA and one server leaf (key 0600).
( cd "$TMP"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=GwPeerTestCA" -keyout opca.key -out opca.pem >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
    -keyout opsrv.key -out opsrv.csr >/dev/null 2>&1
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > ext.cnf
  openssl x509 -req -in opsrv.csr -CA opca.pem -CAkey opca.key -CAcreateserial -days 2 \
    -extfile ext.cnf -out opsrv.pem >/dev/null 2>&1
  chmod 600 opsrv.key opca.key )

free_ports() { # N : prints N free ports
  python3 -c "
import socket, sys
s = [socket.socket() for _ in range(int(sys.argv[1]))]
[x.bind(('127.0.0.1', 0)) for x in s]
print(*[x.getsockname()[1] for x in s])" "$1"
}

# Defense in depth: if a refusal row regresses into a full boot, `timeout` turns the
# resulting hang into a clean non-zero exit. macOS ships no `timeout`, so there the
# binary runs directly (same guard as test_first_admin_bootstrap_refusal.sh).
TIMEOUT_PFX=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_PFX="timeout 240"; fi

# start_row NAME ENVSPEC -- ARGS... : launches the server in the background for one row.
# Output in $TMP/NAME.log, exit status in $TMP/NAME.rc once it exits.
start_row() {
  local name="$1" envspec="$2"; shift 3
  local db
  db="$(row_db "$name")"
  psql "$PG_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"$db\";" >/dev/null 2>&1 || {
    echo "FAIL: could not CREATE DATABASE $db on YUZU_TEST_POSTGRES_DSN" >&2; exit 1; }
  DBS+=("$db")
  local p1 p2 p3 p4 p5 https_flags
  read -r p1 p2 p3 p4 p5 < <(free_ports 5)
  https_flags="--no-https"
  case "$envspec" in
    *WITH_HTTPS=1*) https_flags="--https-port $p5 --no-https-redirect" ;;
  esac
  mkdir -p "$TMP/$name"
  echo "$p3" > "$TMP/$name.web"
  (
    set +e
    # shellcheck disable=SC2086
    env $envspec $TIMEOUT_PFX "$BIN" --config "$TMP/boot.cfg" --data-dir "$TMP/$name/data" \
      --ca-dir "$TMP/$name/ca" --postgres-dsn "${dsn_prefix}/${db}${dsn_query}" \
      --listen "127.0.0.1:$p1" --management "127.0.0.1:$p2" --web-address 127.0.0.1 \
      --web-port "$p3" --metrics-no-auth $https_flags --gateway-upstream "127.0.0.1:$p4" "$@" \
      </dev/null >"$TMP/$name.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$TMP/$name.pid"
    wait "$pid"
    echo "$?" > "$TMP/$name.rc"
  ) &
  PIDS+=("$!")
}

HEX="$(printf 'a%.0s' $(seq 1 64))"
start_row A "X=1" -- --no-tls
start_row B "X=1" -- --no-tls --insecure-gateway-peer --gateway-peer-pin "$HEX"
start_row C "X=1" -- --cert "$TMP/opsrv.pem" --key "$TMP/opsrv.key" --ca-cert "$TMP/opca.pem"
start_row D "YUZU_ALLOW_INSECURE_TLS=1" -- --cert "$TMP/opsrv.pem" --key "$TMP/opsrv.key" \
  --insecure-skip-client-verify
start_row E "X=1" -- --gateway-peer-pin-file "$TMP/absent.pem"
start_row F "X=1" -- --gateway-peer-pin zzzzzzzz
start_row I "WITH_HTTPS=1" -- --cert "$TMP/opsrv.pem" --key "$TMP/opsrv.key" --ca-cert "$TMP/opca.pem"
# Controls: these boot, so they must be stopped; wait for their marker first.
start_row G "X=1" --
start_row H "X=1" -- --no-tls --insecure-gateway-peer
start_row J "X=1" -- --insecure-gateway-peer
start_row K "X=1" -- --gateway-peer-pin "$HEX"
start_row L "YUZU_INSECURE_GATEWAY_PEER=0" --
start_row M "YUZU_INSECURE_GATEWAY_PEER=1" -- --no-tls

pass=0 fail=0
ok()   { echo "ok   - $1"; pass=$((pass+1)); }
bad()  { echo "FAIL - $1"; fail=$((fail+1)); }

# Controls: wait (bounded, event-driven poll) for the post-bind marker or an early exit.
wait_marker() { # NAME MARKER
  local i=0
  while [ $i -lt 1800 ]; do    # 180 s: twelve concurrent boots on a shared runner
    grep -qF "$2" "$TMP/$1.log" 2>/dev/null && return 0
    [ -f "$TMP/$1.rc" ] && return 1
    i=$((i+1)); sleep 0.1
  done
  return 1
}
# Scrape /metrics once the web listener is up (bounded poll, no fixed sleep).
scrape() { # NAME : prints /metrics or nothing
  local i=0 port out
  port="$(cat "$TMP/$1.web")"
  while [ $i -lt 300 ]; do
    out="$(curl -fsS --max-time 2 "http://127.0.0.1:$port/metrics" 2>/dev/null || true)"
    if [ -n "$out" ]; then printf '%s\n' "$out"; return 0; fi
    [ -f "$TMP/$1.rc" ] && return 1
    i=$((i+1)); sleep 0.1
  done
  return 1
}
for c in G H J K L M; do
  if wait_marker "$c" "Gateway upstream listening"; then
    scrape "$c" > "$TMP/$c.metrics" || true
    kill -TERM "$(cat "$TMP/$c.pid")" >/dev/null 2>&1 || true
  fi
done

# Wait for every row to finish.
for p in "${PIDS[@]}"; do wait "$p" || true; done

refusal_row() { # NAME DESCRIPTION MESSAGE-FRAGMENT
  local name="$1" desc="$2" frag="$3" rc log
  rc="$(cat "$TMP/$name.rc" 2>/dev/null || echo missing)"
  log="$TMP/$name.log"
  if [ "$rc" = "0" ] || [ "$rc" = "missing" ] || [ "$rc" = "124" ]; then
    bad "$desc: expected a non-zero exit (rc=$rc)"; tail -5 "$log" >&2; return
  fi
  if ! grep -qF "$frag" "$log"; then
    bad "$desc: refusal message missing '$frag'"; tail -5 "$log" >&2; return
  fi
  if grep -qF "Gateway upstream listening" "$log" || grep -qF "Yuzu Server listening" "$log"; then
    bad "$desc: a listener was bound before the refusal"; return
  fi
  ok "$desc (exit=$rc, nothing bound)"
}
refusal_row A "--no-tls without an acknowledgement refuses" "is not an acknowledgement"
refusal_row B "acknowledgement plus a pin refuses" "contradict"
refusal_row C "operator certificates without a pin refuse" "operator-supplied certificates and no gateway peer pin"
refusal_row D "TLS without a client CA refuses" "no client CA"
refusal_row E "default certs with a missing explicit pin file refuse (no auto-pin fallback)" "does not exist"
refusal_row I "HTTPS on defaults with operator gRPC certs does not auto-pin" "operator-supplied certificates and no gateway peer pin"
refusal_row F "a malformed hex pin refuses at boot" "is not 64 hexadecimal characters"

control_row() { # NAME DESCRIPTION MARKER...
  local name="$1" desc="$2"; shift 2
  local m
  for m in "$@"; do
    if ! grep -qF "$m" "$TMP/$name.log"; then
      bad "$desc: log lacks '$m'"; tail -5 "$TMP/$name.log" >&2; return
    fi
  done
  ok "$desc"
}
control_row G "default certs, no flags: boots and auto-pins the default gateway certificate" \
  "pinned automatically" "Gateway upstream listening"
control_row K "default certs plus an explicit pin: boots and enforces that pin set only" \
  "enforcing 1 pin(s)" "pins are fixed until restart" "Gateway upstream listening"
control_row L "YUZU_INSECURE_GATEWAY_PEER=0: the environment boolean stays false, auto-pin enforced" \
  "pinned automatically" "Gateway upstream listening"
control_row M "YUZU_INSECURE_GATEWAY_PEER=1 with --no-tls: boots acknowledged" \
  "GATEWAY PEER AUTHORIZATION IS DISABLED" "Gateway upstream listening"
control_row H "--no-tls plus --insecure-gateway-peer: boots and says peer authorization is DISABLED" \
  "GATEWAY PEER AUTHORIZATION IS DISABLED" "Gateway upstream listening"
control_row J "TLS defaults plus --insecure-gateway-peer: boots, disabled-with-TLS warning" \
  "GATEWAY PEER AUTHORIZATION IS DISABLED" "gateway peer pinning is available" \
  "Gateway upstream listening"
# The disabled-authorization alarm is logged exactly once per boot.
for c in H J M; do
  n="$(grep -cF "PEER AUTHORIZATION IS DISABLED" "$TMP/$c.log" 2>/dev/null || true)"
  if [ "$n" = "1" ]; then
    ok "row $c logs the disabled-authorization alarm exactly once"
  else
    bad "row $c logs the disabled-authorization alarm exactly once (found ${n:-0})"
  fi
done

metric_row() { # NAME DESCRIPTION LINE-FRAGMENT...
  local name="$1" desc="$2"; shift 2
  local m
  for m in "$@"; do
    if ! grep -qF "$m" "$TMP/$name.metrics" 2>/dev/null; then
      bad "$desc: /metrics lacks '$m'"; return
    fi
  done
  ok "$desc"
}
metric_row G "enforce mode publishes the mode gauge" \
  'yuzu_server_gateway_peer_authz_mode{mode="enforce"} 1' \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack"} 0' \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack_tls"} 0' \
  'yuzu_server_gateway_peer_authz_mode{mode="disabled"} 0'
# The pre-seeded denial series, whatever order the exposition prints its labels in.
if grep 'yuzu_server_gateway_peer_denied_total' "$TMP/G.metrics" 2>/dev/null | grep 'rpc="proxy_register"' \
     | grep 'reason="not_authenticated"' | grep 'event="security"' | grep -q ' 0$'; then
  ok "enforce mode pre-seeds the denial counter at 0"
else
  bad "enforce mode pre-seeds the denial counter at 0"
fi
metric_row H "acknowledged mode publishes insecure_ack" \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack"} 1' \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack_tls"} 0' \
  'yuzu_server_gateway_peer_authz_mode{mode="enforce"} 0'
metric_row J "acknowledged mode on a TLS server with a client CA publishes insecure_ack_tls" \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack_tls"} 1' \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack"} 0' \
  'yuzu_server_gateway_peer_authz_mode{mode="enforce"} 0'
metric_row K "an explicit pin on default certs publishes enforce" \
  'yuzu_server_gateway_peer_authz_mode{mode="enforce"} 1' \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack"} 0'
metric_row L "a false environment acknowledgement publishes enforce" \
  'yuzu_server_gateway_peer_authz_mode{mode="enforce"} 1' \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack"} 0' \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack_tls"} 0'
metric_row M "a true environment acknowledgement publishes insecure_ack" \
  'yuzu_server_gateway_peer_authz_mode{mode="insecure_ack"} 1' \
  'yuzu_server_gateway_peer_authz_mode{mode="enforce"} 0'

# The boot audit row (audit_store.audit_events, written synchronously at boot when the
# acknowledgement is in force) and its absence in enforce mode. Queried after the rows exit.
audit_row() { # NAME DESCRIPTION EXPECTED-COUNT EXPECTED-DETAIL(optional)
  local name="$1" desc="$2" want="$3" detail="${4:-}" db dsn n d
  db="$(row_db "$name")"
  dsn="${dsn_prefix}/${db}${dsn_query}"
  n="$(psql "$dsn" -qtAc "SELECT count(*) FROM audit_store.audit_events WHERE action = 'server.gateway_peer_authz_disabled';" 2>/dev/null || echo err)"
  if [ "$n" != "$want" ]; then
    bad "$desc: expected $want server.gateway_peer_authz_disabled row(s), found '$n'"; return
  fi
  if [ -n "$detail" ]; then
    d="$(psql "$dsn" -qtAc "SELECT principal || '|' || target_type || '|' || target_id || '|' || result || '|' || detail FROM audit_store.audit_events WHERE action = 'server.gateway_peer_authz_disabled';" 2>/dev/null || echo err)"
    if [ "$d" != "system|GatewayUpstream|peer_authorization|success|$detail" ]; then
      bad "$desc: row is '$d', want 'system|GatewayUpstream|peer_authorization|success|$detail'"; return
    fi
  fi
  ok "$desc"
}
audit_row H "acknowledged plaintext boot writes one boot audit row (mode=insecure_ack tls=false)" 1 "mode=insecure_ack tls=false"
audit_row J "acknowledged TLS boot writes one boot audit row (mode=insecure_ack_tls tls=true)" 1 "mode=insecure_ack_tls tls=true"
audit_row M "an environment acknowledgement writes one boot audit row (mode=insecure_ack tls=false)" 1 "mode=insecure_ack tls=false"
audit_row G "enforce mode writes no boot audit row" 0
audit_row K "an explicit pin writes no boot audit row" 0
audit_row L "a false environment acknowledgement writes no boot audit row" 0

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
