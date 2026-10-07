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
#   N  default certs + `--gateway-peer-pin ''` (a supplied but blank pin): refused, never read as
#      "not supplied" (which would silently select the auto-pin)
#   O  acknowledgement + a blank pin (`--no-tls --insecure-gateway-peer --gateway-peer-pin ' '`)
#   Q  default certs + YUZU_GATEWAY_PEER_PINS=,, (blank list in the environment)
#   U  default certs + a pin file whose only certificate lacks serverAuth: refused (every call
#      would be denied)
#   P  control: default certs + a pin file holding a serverAuth leaf: boots, and the enforce boot
#      line lists the pin's first 16 hex characters, equal to the SPKI hash openssl computes
# Bounded rows (phase 2, started once phase 1 has finished so the machine is quiet; each must print
# its refusal within REFUSE_BOUND_S seconds of starting, else the row is terminated and fails as a hang.
# The bound is on the refusal line, not on process exit: the server's fixed shutdown drain adds
# about five seconds after it. Measured on a quiet box: refusal about 2 s after start):
#   R  default certs + a pin file holding a passphrase-protected PEM block, stdin /dev/null
#   S  the same with stdin an open pipe nothing ever writes to (OpenSSL's passphrase prompt would
#      block on it: the refusing password callback must make the refusal immediate)
#   T  default certs + a FIFO as the pin file (no writer): refused without blocking
#   W  default certs + a symlink to /dev/zero as the pin file: refused without reading forever
#
# Anonymous gateway-upstream calls (the only rows that exercise the REAL guard wiring in the real
# binary; nothing else constructs ServerImpl): curl speaks h2 to a controls row's listener with NO
# client certificate and calls /yuzu.gateway.v1.GatewayUpstream/BatchHeartbeat with an empty gRPC
# frame.
#   G  enforce on default certs: TLS, request-not-require client auth on the agent port; expect
#      grpc-status 16 and yuzu_server_gateway_peer_denied_total{rpc="batch_heartbeat",
#      reason="not_authenticated"} >= 1 on /metrics
#   H  acknowledged plaintext (h2c prior knowledge): grpc-status other than 16 (the real handler
#      answers; an empty BatchHeartbeat is OK) and no denial series incremented
#   J  acknowledged on TLS defaults: the same, over TLS
#
# Pins are read once at boot: there is no reload and no pin gauge, so no row looks for one.
#
# "Before any listener is bound" is asserted by the absence of the log lines the server prints
# only after BuildAndStart ("Yuzu Server listening", "Gateway upstream listening"). Every port
# the rows pass is a free port picked by the OS in ONE allocation call (distinct by construction);
# no row uses a default or shared port.
#
# Postgres: the server fails closed without it, so this needs YUZU_TEST_POSTGRES_DSN (each row
# gets its own uniquely named database, dropped on exit). Skip-vs-fail: on a developer box a
# missing prerequisite (binary, DSN, psql, openssl, python3, curl) is a SKIP; when
# GITHUB_ACTIONS=true or YUZU_SERVER_BIN is set (an explicit request to run it) the same
# condition is a FAIL, so a CI step can never go green without having run. A missing `psql` is
# ALSO a FAIL whenever YUZU_REQUIRE_PSQL=1 (the ci.yml step sets it), and under GITHUB_ACTIONS=true
# regardless. A DSN that is set but unusable is always a FAIL. A curl without HTTP/2 skips only
# the anonymous-call rows on a developer box and is a FAIL under the same CI/explicit conditions.
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
  # A CI skip would let the step go green without having run: psql is required there.
  if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${YUZU_REQUIRE_PSQL:-}" = "1" ]; then
    echo "FAIL: psql not on PATH (required: GITHUB_ACTIONS=true or YUZU_REQUIRE_PSQL=1); this test creates one database per row" >&2
    exit 1
  fi
  skip_or_fail "psql not on PATH"
fi
command -v openssl >/dev/null 2>&1 || skip_or_fail "openssl not on PATH"
command -v python3 >/dev/null 2>&1 || skip_or_fail "python3 not on PATH"
command -v curl >/dev/null 2>&1 || skip_or_fail "curl not on PATH"
# The anonymous-call rows need curl with HTTP/2 (TLS ALPN h2, and h2c prior knowledge).
ANON_OK=1
CURL_VERSION="$(curl --version 2>/dev/null || true)"
case "$CURL_VERSION" in *HTTP2*|*http2*) ;; *)
  if [ "${GITHUB_ACTIONS:-}" = "true" ] || [ -n "${YUZU_SERVER_BIN:-}" ]; then
    echo "FAIL: this curl has no HTTP/2 support (required for the anonymous gateway-upstream call rows)" >&2
    exit 1
  fi
  echo "SKIP: this curl has no HTTP/2 support: the anonymous gateway-upstream call rows are skipped" >&2
  ANON_OK=0 ;;
esac

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
  # A row whose .rc exists has exited: its pid may since have been reused by an unrelated
  # process, so it is never signalled.
  for f in "$TMP"/*.pid; do
    [ -f "$f" ] || continue
    [ -f "${f%.pid}.rc" ] && continue
    kill "$(cat "$f")" >/dev/null 2>&1 || true
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

# A leaf whose only extended key usage is clientAuth (no serverAuth): pinning it can never admit a
# gateway, so a pin set made only of it must be refused at boot.
( cd "$TMP"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=GwPeerClientOnly" \
    -keyout clientonly.key -out clientonly.csr >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' > ext_client.cnf
  openssl x509 -req -in clientonly.csr -CA opca.pem -CAkey opca.key -CAcreateserial -days 2 \
    -extfile ext_client.cnf -out clientonly.pem >/dev/null 2>&1 )
# A CERTIFICATE block whose PEM header says the body is passphrase-encrypted (the same shape the
# unit test uses): OpenSSL asks for a passphrase when it reads one; the body is never decrypted.
{ printf -- '-----BEGIN CERTIFICATE-----\n'
  printf 'Proc-Type: 4,ENCRYPTED\n'
  printf 'DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n'
  printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n'
  printf -- '-----END CERTIFICATE-----\n'; } > "$TMP/encrypted.pem"
# The SPKI SHA-256 openssl computes for a certificate: the 64 hex a pin is.
spki_hex() { # PEM-FILE
  openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 2>/dev/null | awk '{print $NF}' | tr 'A-F' 'a-f'
}
# An empty gRPC message frame (flag 0, length 0): a valid request body for BatchHeartbeat.
printf '\000\000\000\000\000' > "$TMP/empty.frame"

# Every row's ports come from ONE allocation call: the sockets are all held open until the list
# is printed, so no two rows can be handed the same port (separate per-row calls release their
# sockets at once and the OS may hand the same number to the next call).
MAX_ROWS=40
PORT_POOL=($(python3 -c "
import socket, sys
s = [socket.socket() for _ in range(int(sys.argv[1]))]
[x.bind(('127.0.0.1', 0)) for x in s]
print(*[x.getsockname()[1] for x in s])" $((MAX_ROWS * 5))))
PORT_NEXT=0
# next_ports sets p1..p5 in THE CALLER'S shell (a command substitution would advance a copy of
# the counter and hand every row the same ports).
next_ports() {
  if [ $((PORT_NEXT + 5)) -gt "${#PORT_POOL[@]}" ]; then
    echo "FAIL: more rows than the port pool allocated ($MAX_ROWS)" >&2; exit 1
  fi
  p1="${PORT_POOL[$PORT_NEXT]}"; p2="${PORT_POOL[$((PORT_NEXT + 1))]}"; p3="${PORT_POOL[$((PORT_NEXT + 2))]}"
  p4="${PORT_POOL[$((PORT_NEXT + 3))]}"; p5="${PORT_POOL[$((PORT_NEXT + 4))]}"
  PORT_NEXT=$((PORT_NEXT + 5))
}

# Defense in depth: if a refusal row regresses into a full boot, `timeout` turns the
# resulting hang into a clean non-zero exit. macOS ships no `timeout`, so there the
# binary runs directly (same guard as test_first_admin_bootstrap_refusal.sh).
TIMEOUT_PFX=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_PFX="timeout 240"; fi

# start_row NAME ENVSPEC -- ARGS... : launches the server in the background for one row.
# Output in $TMP/NAME.log, exit status in $TMP/NAME.rc once it exits. One optional global the
# caller sets for one call: ROW_STDIN=<fifo path> gives the server an open pipe nothing ever
# writes to instead of /dev/null (opened read-write, so the open never blocks and the read never
# sees EOF).
ROW_STDIN=""
start_row() {
  local name="$1" envspec="$2"; shift 3
  local db
  db="$(row_db "$name")"
  psql "$PG_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"$db\";" >/dev/null 2>&1 || {
    echo "FAIL: could not CREATE DATABASE $db on YUZU_TEST_POSTGRES_DSN" >&2; exit 1; }
  DBS+=("$db")
  local p1 p2 p3 p4 p5 https_flags
  next_ports
  https_flags="--no-https"
  case "$envspec" in
    *WITH_HTTPS=1*) https_flags="--https-port $p5 --no-https-redirect" ;;
  esac
  mkdir -p "$TMP/$name"
  echo "$p3" > "$TMP/$name.web"
  echo "$p1" > "$TMP/$name.agent"
  local tpfx="$TIMEOUT_PFX" stdin_src="/dev/null"
  [ -n "$ROW_STDIN" ] && stdin_src="$ROW_STDIN"
  (
    set +e
    # shellcheck disable=SC2086
    # `<>` (read-write) so a FIFO opens without waiting for a writer; for /dev/null it is
    # equivalent to `<`.
    env $envspec $tpfx "$BIN" --config "$TMP/boot.cfg" --data-dir "$TMP/$name/data" \
      --ca-dir "$TMP/$name/ca" --postgres-dsn "${dsn_prefix}/${db}${dsn_query}" \
      --listen "127.0.0.1:$p1" --management "127.0.0.1:$p2" --web-address 127.0.0.1 \
      --web-port "$p3" --metrics-no-auth $https_flags --gateway-upstream "127.0.0.1:$p4" "$@" \
      <>"$stdin_src" >"$TMP/$name.log" 2>&1 &
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
# Blank-pin, no-serverAuth and serverAuth pin-file rows (the pin file lives in $TMP, never in the repo).
start_row N "X=1" -- --gateway-peer-pin ''
start_row O "X=1" -- --no-tls --insecure-gateway-peer --gateway-peer-pin ' '
start_row Q "YUZU_GATEWAY_PEER_PINS=,," --
start_row U "X=1" -- --gateway-peer-pin-file "$TMP/clientonly.pem"
start_row P "X=1" -- --gateway-peer-pin-file "$TMP/opsrv.pem"

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
# anon_call NAME SCHEME PORT : BatchHeartbeat with an empty frame and NO client certificate.
# Headers and trailers land in $TMP/NAME.anon (curl -D includes the HTTP/2 trailers; a
# Trailers-Only response, the shape a guard denial takes, carries grpc-status in the headers).
anon_call() {
  local mode="--http2"
  [ "$2" = "http" ] && mode="--http2-prior-knowledge"
  curl $mode -k -sS -D "$TMP/$1.anon" -o /dev/null --max-time 15 \
    -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @"$TMP/empty.frame" \
    "$2://127.0.0.1:$3/yuzu.gateway.v1.GatewayUpstream/BatchHeartbeat" 2>"$TMP/$1.anon.err" || true
}
grpc_status_of() { # NAME : the grpc-status the anonymous call received (empty when none)
  grep -i '^grpc-status:' "$TMP/$1.anon" 2>/dev/null | tail -1 | tr -d '\r' | awk '{print $2}' || true
}
for c in G H J K L M P; do
  if wait_marker "$c" "Gateway upstream listening"; then
    if [ "$ANON_OK" = "1" ]; then
      case "$c" in
        G|J) anon_call "$c" https "$(cat "$TMP/$c.agent")" ;;
        H)   anon_call "$c" http  "$(cat "$TMP/$c.agent")" ;;
      esac
    fi
    scrape "$c" > "$TMP/$c.metrics" || true
    kill -TERM "$(cat "$TMP/$c.pid")" >/dev/null 2>&1 || true
  fi
done

# Phase 1 is over: wait for every row to finish.
for p in ${PIDS[@]+"${PIDS[@]}"}; do wait "$p" || true; done
PIDS=()

# Phase 2: rows whose failure mode is a HANG (a passphrase prompt on stdin, a blocking open of a
# FIFO, an endless read of a device). Each must print its refusal within REFUSE_BOUND_S seconds;
# one that does not is terminated and reported as a hang.
REFUSE_BOUND_S=20
wait_refusal() { # NAME : 0 once the row refused or exited, 1 (and killed) if it did not within the bound
  local i=0
  while [ $i -lt $((REFUSE_BOUND_S * 10)) ]; do
    grep -qF "Refusing to start" "$TMP/$1.log" 2>/dev/null && return 0
    [ -f "$TMP/$1.rc" ] && return 0
    i=$((i+1)); sleep 0.1
  done
  echo 1 > "$TMP/$1.hung"
  # TERM first: the `timeout` wrapper forwards it to the server; a KILL of the wrapper alone
  # would orphan the server. KILL only if it is still there a second later.
  kill -TERM "$(cat "$TMP/$1.pid")" >/dev/null 2>&1 || true
  sleep 1
  [ -f "$TMP/$1.rc" ] || kill -KILL "$(cat "$TMP/$1.pid")" >/dev/null 2>&1 || true
  return 1
}
PHASE2_ROWS="R W"
start_row R "X=1" -- --gateway-peer-pin-file "$TMP/encrypted.pem"
if command -v mkfifo >/dev/null 2>&1; then
  mkfifo "$TMP/stdin.fifo" "$TMP/pin.fifo"
  ROW_STDIN="$TMP/stdin.fifo"
  start_row S "X=1" -- --gateway-peer-pin-file "$TMP/encrypted.pem"
  ROW_STDIN=""
  start_row T "X=1" -- --gateway-peer-pin-file "$TMP/pin.fifo"
  PHASE2_ROWS="R S T W"
else
  echo "SKIP: rows S and T need mkfifo" >&2
fi
ln -s /dev/zero "$TMP/pin.zero"
start_row W "X=1" -- --gateway-peer-pin-file "$TMP/pin.zero"
for c in $PHASE2_ROWS; do wait_refusal "$c" || true; done
for p in ${PIDS[@]+"${PIDS[@]}"}; do wait "$p" || true; done
PIDS=()

refusal_row() { # NAME DESCRIPTION MESSAGE-FRAGMENT
  local name="$1" desc="$2" frag="$3" rc log
  rc="$(cat "$TMP/$name.rc" 2>/dev/null || echo missing)"
  log="$TMP/$name.log"
  if [ -f "$TMP/$name.hung" ]; then
    bad "$desc: no refusal within ${REFUSE_BOUND_S:-?} s (a hang)"; tail -5 "$log" >&2; return
  fi
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
refusal_row N "a blank --gateway-peer-pin on default certs refuses (never read as not supplied)" \
  "gateway peer pin option supplied but contains no pin"
refusal_row O "acknowledgement plus a blank pin refuses" "contradict"
refusal_row Q "a blank YUZU_GATEWAY_PEER_PINS list on default certs refuses" \
  "gateway peer pin option supplied but contains no pin"
refusal_row U "a pin file whose only certificate lacks serverAuth refuses" \
  "every configured gateway peer pin lacks the serverAuth extended key usage"
refusal_row R "a passphrase-protected PEM pin file refuses promptly (stdin /dev/null)" "is malformed"
refusal_row W "a symlink to /dev/zero as the pin file refuses promptly" "could not be read"
case " $PHASE2_ROWS " in *" S "*)
  refusal_row S "a passphrase-protected PEM pin file refuses promptly (stdin an unwritten pipe)" "is malformed"
  refusal_row T "a FIFO pin file refuses promptly without blocking" "could not be read" ;;
esac
for c in $PHASE2_ROWS; do
  case "$c" in R|S)
    if grep -qi "pass phrase" "$TMP/$c.log" 2>/dev/null; then
      bad "row $c: the log shows a passphrase prompt"
    else
      ok "row $c: no passphrase prompt was printed"
    fi ;;
  esac
done

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
# The enforce boot line lists the pins' first 16 hex characters: the operator's lockout diagnostic
# (compare it with the `spki=` of a denial and with the gateway certificate's own hash).
PIN_P="$(spki_hex "$TMP/opsrv.pem")"
control_row P "default certs plus a serverAuth pin file: boots, enforces 1 pin from 1 pin file" \
  "enforcing 1 pin(s) from 0 --gateway-peer-pin value(s) and 1 pin file(s)" "Gateway upstream listening"
if [ -n "$PIN_P" ] && grep -qF "pin prefixes (first 16 hex): ${PIN_P:0:16}" "$TMP/P.log"; then
  ok "row P: the boot line lists the pin prefix equal to the certificate's SPKI hash (${PIN_P:0:16})"
else
  bad "row P: the boot line does not list 'pin prefixes (first 16 hex): ${PIN_P:0:16}'"; grep -F "gateway peer authorization" "$TMP/P.log" >&2 || true
fi
if grep -qF "pin prefixes (first 16 hex): aaaaaaaaaaaaaaaa" "$TMP/K.log"; then
  ok "row K: the boot line lists the explicit hex pin's first 16 characters"
else
  bad "row K: the boot line does not list 'pin prefixes (first 16 hex): aaaaaaaaaaaaaaaa'"
fi
PIN_G="$(spki_hex "$TMP/G/ca/default-gateway.pem")"
if [ -n "$PIN_G" ] && grep -qF "pin prefixes (first 16 hex): ${PIN_G:0:16}" "$TMP/G.log"; then
  ok "row G: the auto-pin boot line lists the default gateway certificate's SPKI prefix (${PIN_G:0:16})"
else
  bad "row G: the auto-pin boot line does not list the default gateway certificate's SPKI prefix '${PIN_G:0:16}'"
  grep -F "gateway peer authorization" "$TMP/G.log" >&2 || true
fi
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

# Anonymous gateway-upstream calls against the real binary (no client certificate).
denied_series() { # NAME : the denial counter lines with a non-zero value
  grep 'yuzu_server_gateway_peer_denied_total' "$TMP/$1.metrics" 2>/dev/null | grep -v '^#' | grep -v ' 0$' || true
}
anon_row() { # NAME DESCRIPTION WANT(16|not16)
  local name="$1" desc="$2" want="$3" st
  if [ "$ANON_OK" != "1" ]; then echo "skip - $desc (curl without HTTP/2)"; return; fi
  st="$(grpc_status_of "$name")"
  if [ -z "$st" ]; then
    bad "$desc: no grpc-status was received ($(tr '\n' ' ' < "$TMP/$name.anon.err" 2>/dev/null))"; return
  fi
  if [ "$want" = "16" ] && [ "$st" != "16" ]; then
    bad "$desc: expected grpc-status 16 (UNAUTHENTICATED), got $st"; return
  fi
  if [ "$want" = "not16" ] && [ "$st" = "16" ]; then
    bad "$desc: the anonymous call was refused (grpc-status 16) although authorization is acknowledged-off"; return
  fi
  ok "$desc (grpc-status $st)"
}
anon_row G "enforce: an anonymous gateway-upstream call (no client certificate, agent port) is refused" 16
if [ "$ANON_OK" = "1" ]; then
  denied_n="$(grep 'yuzu_server_gateway_peer_denied_total' "$TMP/G.metrics" 2>/dev/null | grep 'rpc="batch_heartbeat"' \
    | grep 'reason="not_authenticated"' | awk '{print $NF}' | head -1 || true)"
  case "$denied_n" in
    ''|*[!0-9]*) bad "enforce: the not_authenticated denial counter for batch_heartbeat is missing from /metrics ('$denied_n')" ;;
    *) if [ "$denied_n" -ge 1 ]; then
         ok "enforce: yuzu_server_gateway_peer_denied_total{rpc=\"batch_heartbeat\",reason=\"not_authenticated\"} = $denied_n"
       else
         bad "enforce: the not_authenticated denial counter did not increment (= $denied_n)"
       fi ;;
  esac
fi
anon_row H "acknowledged plaintext: the same anonymous call is NOT refused (the real handler answers)" not16
anon_row J "acknowledged on TLS defaults: the same anonymous call is NOT refused" not16
if [ "$ANON_OK" = "1" ]; then
  for c in H J; do
    d="$(denied_series "$c")"
    if [ -z "$d" ]; then ok "row $c: no denial counter incremented"; else bad "row $c: a denial counter incremented: $d"; fi
  done
fi

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
