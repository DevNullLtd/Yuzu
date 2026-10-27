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
BG_DB="yuzu_test_$(date +%s)_bgtest_$$_${SALT}"
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

# The reset also ends the account's durable sessions (#6079). The first run above
# created the session_store schema; seed one row each for the reset user and an
# unrelated user, reset again, and require only the reset user's row to be gone
# and the audit row to say how many were ended.
sess_sql() { psql "$CHILD_DSN" -v ON_ERROR_STOP=1 -qtAc "$1"; }
sess_sql "INSERT INTO session_store.sessions (token_hash, username, role, created_at_ms, expires_at_ms, last_activity_ms, mfa_verified_ms) VALUES ('yuzu_test_h_admin', 'admin', 'admin', 1, 9999999999999, 1, 1), ('yuzu_test_h_other', 'other', 'user', 1, 9999999999999, 1, 0);"
check "reset ends the account's sessions -> ok/exit 0" 0 '"status":"ok"' admin
left_admin="$(sess_sql "SELECT count(*) FROM session_store.sessions WHERE username='admin';")"
left_other="$(sess_sql "SELECT count(*) FROM session_store.sessions WHERE username='other';")"
if [ "$left_admin" = "0" ] && [ "$left_other" = "1" ]; then
  echo "ok   - reset removed only the reset user's session"; pass=$((pass+1))
else
  echo "FAIL - session rows after reset (admin=$left_admin want 0, other=$left_other want 1)"; fail=$((fail+1))
fi
detail="$(sess_sql "SELECT detail FROM audit_store.audit_events WHERE action='mfa.reset.breakglass' ORDER BY id DESC LIMIT 1;" 2>&1 || true)"
if printf '%s' "$detail" | grep -qF 'sessions_ended=1'; then
  echo "ok   - audit row records sessions_ended=1"; pass=$((pass+1))
else
  echo "FAIL - audit detail lacks sessions_ended=1 (detail=$detail)"; fail=$((fail+1))
fi

# Two audit rows per reset (#6079 au-F1): an INTENT row ("attempted") written BEFORE the factor
# is cleared and an OUTCOME row after, ordered by the `id` identity column (`timestamp` is whole
# seconds). The last two rows are this run's pair.
last_two="$(sess_sql "SELECT result FROM (SELECT id, result FROM audit_store.audit_events WHERE action='mfa.reset.breakglass' ORDER BY id DESC LIMIT 2) t ORDER BY id;" 2>&1 | tr '\n' ',' || true)"
if [ "$last_two" = "attempted,success," ]; then
  echo "ok   - intent row (attempted) precedes the outcome row (success)"; pass=$((pass+1))
else
  echo "FAIL - audit row order/results (got '$last_two', want 'attempted,success,')"; fail=$((fail+1))
fi
intent_detail="$(sess_sql "SELECT detail FROM audit_store.audit_events WHERE action='mfa.reset.breakglass' AND result='attempted' ORDER BY id DESC LIMIT 1;" 2>&1 || true)"
if printf '%s' "$intent_detail" | grep -qF 'MFA clear requested via --mfa-reset CLI (os_identity='; then
  echo "ok   - intent row detail names the CLI and the OS identity"; pass=$((pass+1))
else
  echo "FAIL - intent row detail (detail=$intent_detail)"; fail=$((fail+1))
fi

# Fail closed on the intent row: when the audit store refuses it, NOTHING is cleared. A BEFORE
# INSERT trigger rejects only the intent row. The user is given a (marker-only) enrolment and a
# session, and both must survive the refused run, which exits 1 and says nothing was changed.
sess_sql "UPDATE auth.users SET mfa_enrolled_at = now() WHERE username='admin';"
sess_sql "INSERT INTO session_store.sessions (token_hash, username, role, created_at_ms, expires_at_ms, last_activity_ms, mfa_verified_ms) VALUES ('yuzu_test_h_admin2', 'admin', 'admin', 1, 9999999999999, 1, 1);"
sess_sql "CREATE FUNCTION public.yuzu_test_block_intent() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF NEW.action = 'mfa.reset.breakglass' AND NEW.result = 'attempted' THEN RAISE EXCEPTION 'yuzu_test: intent row refused'; END IF; RETURN NEW; END \$\$; CREATE TRIGGER yuzu_test_block_intent BEFORE INSERT ON audit_store.audit_events FOR EACH ROW EXECUTE FUNCTION public.yuzu_test_block_intent();"
rows_before="$(sess_sql "SELECT count(*) FROM audit_store.audit_events WHERE action='mfa.reset.breakglass';")"
set +e
err="$("$BIN" --config "$TMP/yuzu-server.cfg" --data-dir "$TMP" --ca-dir "$TMP" --postgres-dsn "$CHILD_DSN" --mfa-reset admin 2>&1 >/dev/null)"
got=$?
set -e
still_enrolled="$(sess_sql "SELECT count(*) FROM auth.users WHERE username='admin' AND mfa_enrolled_at IS NOT NULL;")"
sess_left="$(sess_sql "SELECT count(*) FROM session_store.sessions WHERE username='admin';")"
rows_after="$(sess_sql "SELECT count(*) FROM audit_store.audit_events WHERE action='mfa.reset.breakglass';")"
sess_sql "DROP TRIGGER yuzu_test_block_intent ON audit_store.audit_events; DROP FUNCTION public.yuzu_test_block_intent();"
if [ "$got" = "1" ] && printf '%s' "$err" | grep -qF 'nothing was changed' \
   && [ "$still_enrolled" = "1" ] && [ "$sess_left" = "1" ] && [ "$rows_after" = "$rows_before" ]; then
  echo "ok   - a refused intent row clears nothing (exit 1, factor and session intact, no row)"; pass=$((pass+1))
else
  echo "FAIL - refused intent row (exit=$got want=1; enrolled=$still_enrolled want 1; sessions=$sess_left want 1; rows $rows_before->$rows_after; err=$err)"; fail=$((fail+1))
fi
sess_sql "DELETE FROM session_store.sessions WHERE token_hash='yuzu_test_h_admin2';"

# A failed session delete is loud and non-zero, but the outcome audit row is still written.
sess_sql "ALTER TABLE session_store.sessions RENAME TO sessions_yuzu_test_hidden;"
set +e
"$BIN" --config "$TMP/yuzu-server.cfg" --data-dir "$TMP" --ca-dir "$TMP" --postgres-dsn "$CHILD_DSN" --mfa-reset admin >/dev/null 2>&1
got=$?
set -e
detail="$(sess_sql "SELECT detail FROM audit_store.audit_events WHERE action='mfa.reset.breakglass' ORDER BY id DESC LIMIT 1;" 2>&1 || true)"
if [ "$got" = "1" ] && printf '%s' "$detail" | grep -qF 'sessions_ended=failed'; then
  echo "ok   - failed session delete exits 1 and still audits sessions_ended=failed"; pass=$((pass+1))
else
  echo "FAIL - failed session delete (exit=$got want=1; detail=$detail)"; fail=$((fail+1))
fi
# The outcome row's result is "partial" (the vocabulary the Settings route uses), not "success",
# because the sessions were not ended; the intent row still precedes it (#6079 sec-F3, qe-N2).
last_two="$(sess_sql "SELECT result FROM (SELECT id, result FROM audit_store.audit_events WHERE action='mfa.reset.breakglass' ORDER BY id DESC LIMIT 2) t ORDER BY id;" 2>&1 | tr '\n' ',' || true)"
if [ "$last_two" = "attempted,partial," ]; then
  echo "ok   - failed session delete records result=partial after the intent row"; pass=$((pass+1))
else
  echo "FAIL - failed session delete result column (got '$last_two', want 'attempted,partial,')"; fail=$((fail+1))
fi

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
