#!/usr/bin/env bash
# test_mfa_reset.sh — contract test for the `--mfa-reset` break-glass CLI (#1226).
#
# The break-glass path is the documented recovery from MFA-enforcement lockout
# (lost device, IdP not asserting amr, sole admin who could not enroll). It runs
# `yuzu-server --mfa-reset <user>`, clears the user's MFA, writes an audit row,
# and exits without starting the server. This verifies the CLI contract:
# existing user -> ok + exit 0; missing user -> error + exit 1; runs without
# requiring the TLS/HTTPS flags (it never serves).
#
# Postgres (ADR-0006 auth migration): the auth store is now Postgres-only, so
# the one-shot needs `--postgres-dsn`. This test provisions a uniquely-named
# ephemeral database on YUZU_TEST_POSTGRES_DSN (the CI server-test DSN exported
# by scripts/ci/ensure-postgres.sh) and drops it on exit, so it never mutates
# the shared base DB and is safe under the shared self-hosted runner pools.
# Skip-vs-fail mirrors the Catch2 PG fixtures: DSN unset -> SKIP (local dev
# without Postgres); DSN set but unusable -> FAIL.
#
# Run:  bash tests/shell/test_mfa_reset.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
# Locate a built server binary. An explicit YUZU_SERVER_BIN wins (CI sets it to
# the matrix build dir, e.g. build-linux-gcc-13-debug); otherwise scan the
# conventional per-OS dirs.
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

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-mfareset-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# The auth store is Postgres-only (ADR-0006). The --mfa-reset one-shot opens a
# Postgres AuthDB, so this contract test needs a reachable Postgres. Mirror the
# server-suite skip-vs-fail rule: unset -> skip (local dev), set -> must work.
PG_DSN="${YUZU_TEST_POSTGRES_DSN:-}"
if [ -z "$PG_DSN" ]; then
  echo "SKIP: YUZU_TEST_POSTGRES_DSN unset — the break-glass/--mfa-reset one-shot needs the Postgres auth store (ADR-0006). Set it to run this test." >&2
  exit 0
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "SKIP: psql not on PATH — cannot provision the ephemeral break-glass test database." >&2
  exit 0
fi

# Provision a uniquely-named ephemeral database (per-process + urandom salt) so
# concurrent CI jobs on a shared runner never collide and the shared base DB is
# never mutated. Derive a child DSN by swapping the database name in the URI.
SALT="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
BG_DB="yuzu_bgtest_$$_${SALT}"
dsn_base="${PG_DSN%%\?*}"                       # strip any ?query
dsn_query=""
[ "$dsn_base" != "$PG_DSN" ] && dsn_query="?${PG_DSN#*\?}"
dsn_prefix="${dsn_base%/*}"                     # everything up to the last '/'
CHILD_DSN="${dsn_prefix}/${BG_DB}${dsn_query}"

if ! psql "$PG_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"${BG_DB}\";" >/dev/null 2>&1; then
  echo "FAIL: could not CREATE DATABASE ${BG_DB} on YUZU_TEST_POSTGRES_DSN — Postgres is set but unusable." >&2
  exit 1
fi
# Extend the cleanup trap to drop the ephemeral DB (FORCE closes any lingering
# backend) in addition to removing the temp dir.
trap 'psql "$PG_DSN" -qtAc "DROP DATABASE IF EXISTS \"${BG_DB}\" WITH (FORCE);" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

# Seed a config with one admin (PBKDF2-SHA256 100k/32B, the server's scheme).
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'pw'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')
" > "$TMP/yuzu-server.cfg"
chmod 600 "$TMP/yuzu-server.cfg"

pass=0 fail=0
check() { # <desc> <expected-exit> <expected-substr>
  local desc="$1" want_exit="$2" want_sub="$3"; shift 3
  local out got
  set +e
  # --ca-dir points the SecretCodec KEK provider at a writable temp dir; the
  # Postgres auth bootstrap runs SecretCodec::init() before --mfa-reset, and the
  # default /etc/yuzu/certs is not writable in CI (or unprivileged dev).
  out="$("$BIN" --config "$TMP/yuzu-server.cfg" --data-dir "$TMP" --ca-dir "$TMP" --postgres-dsn "$CHILD_DSN" --mfa-reset "$@" 2>/dev/null)"
  got=$?
  set -e
  if [ "$got" = "$want_exit" ] && printf '%s' "$out" | grep -qF "$want_sub"; then
    echo "ok   - $desc"; pass=$((pass+1))
  else
    echo "FAIL - $desc (exit=$got want=$want_exit; out=$out)"; fail=$((fail+1))
  fi
}

# Existing user: cleared, JSON ok, exit 0. (Idempotent on a not-enrolled row.)
check "reset existing user -> ok/exit 0" 0 '"status":"ok"' admin
# Missing user: error, exit 1.
check "reset missing user -> error/exit 1" 1 'not found' ghost

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
