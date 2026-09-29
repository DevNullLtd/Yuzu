#!/usr/bin/env bash
# test_first_admin_bootstrap_refusal.sh — contract test for the fresh-install
# Administrator bootstrap's fatal refusal path (main.cpp, "Fatal: the loaded
# config lists ... but none has role=admin") and the durable audit row a
# SUCCESSFUL fresh-install bootstrap writes (`rbac.bootstrap.first_admin`).
#
# IMPORTANT: despite the log message's wording, the `cfg_users` this check
# reads is `AuthManager::list_users()` BEFORE `auth_mgr.set_auth_db()` is
# ever called in main.cpp (that call happens later, inside
# `Server::create()` in server.cpp) — so `auth_db_` is null and
# `AuthManager::list_users()` (auth.cpp) falls through to the in-memory
# `users_` map populated by `load_config()` from the yuzu-server.cfg FILE,
# never a live `auth.users` Postgres read. The log message's "the loaded
# config lists..." wording is accurate, not stale. Case 1 below therefore
# drives this via the CONFIG FILE (one non-admin-role local user), not a
# `psql` INSERT into `auth.users`.
#
# Case 1 (the refusal): a config file with exactly one local user whose role
# is NOT admin, against a fresh (schema-migrated-but-empty) Postgres
# database. `yuzu-server` must exit 1 before ever binding a port, must never
# provision that account, and must never write the fresh-install bootstrap
# audit row (its AuditStore is only constructed inside the branch this
# refusal never reaches).
#
# Case 2 (the audit row on success): a config file with exactly one
# admin-role local user, against a SEPARATE fresh empty Postgres database.
# `RbacStore::provision_first_admin` fires for real and a durable
# `rbac.bootstrap.first_admin` audit row lands in `audit_store.audit_events`.
# Driven via the `--mfa-reset` one-shot (same as test_mfa_reset.sh) — it runs
# every line of the fresh-install bootstrap block (main.cpp, well before its
# own `--mfa-reset` handling) and then exits without starting the server, so
# no port-binding/full-boot harness is needed.
#
# Postgres (ADR-0006 auth migration): the auth store is Postgres-only, so
# this test provisions two uniquely-named ephemeral databases on
# YUZU_TEST_POSTGRES_DSN (the CI server-test DSN exported by
# scripts/ci/ensure-postgres.sh) and drops both on exit, so it never mutates
# the shared base DB and is safe under the shared self-hosted runner pools
# (#1871). Skip-vs-fail mirrors the Catch2 PG fixtures and test_mfa_reset.sh:
# DSN unset -> SKIP (local dev without Postgres); DSN set but unusable ->
# FAIL.
#
# Run:  bash tests/shell/test_first_admin_bootstrap_refusal.sh
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

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-fabtest.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# The auth store is Postgres-only (ADR-0006). Mirror the server-suite
# skip-vs-fail rule: unset -> skip (local dev), set -> must work.
PG_DSN="${YUZU_TEST_POSTGRES_DSN:-}"
if [ -z "$PG_DSN" ]; then
  echo "SKIP: YUZU_TEST_POSTGRES_DSN unset — the fresh-install Administrator bootstrap needs the Postgres auth store (ADR-0006). Set it to run this test." >&2
  exit 0
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "SKIP: psql not on PATH — cannot provision the ephemeral bootstrap test databases." >&2
  exit 0
fi

# Provision two uniquely-named ephemeral databases (per-process + urandom
# salt) so concurrent CI jobs on a shared runner never collide and the
# shared base DB is never mutated. Derive child DSNs by swapping the
# database name in the URI. Two databases (not one, and not a reuse of
# Case 1's) keep Case 2's assertions independent of any Case 1 regression.
SALT="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
DB_REFUSE="yuzu_fabtest_$$_${SALT}_refuse"
DB_BOOT="yuzu_fabtest_$$_${SALT}_boot"
dsn_base="${PG_DSN%%\?*}"                       # strip any ?query
dsn_query=""
[ "$dsn_base" != "$PG_DSN" ] && dsn_query="?${PG_DSN#*\?}"
dsn_prefix="${dsn_base%/*}"                     # everything up to the last '/'
CHILD_DSN_REFUSE="${dsn_prefix}/${DB_REFUSE}${dsn_query}"
CHILD_DSN_BOOT="${dsn_prefix}/${DB_BOOT}${dsn_query}"

if ! psql "$PG_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"${DB_REFUSE}\";" >/dev/null 2>&1; then
  echo "FAIL: could not CREATE DATABASE ${DB_REFUSE} on YUZU_TEST_POSTGRES_DSN — Postgres is set but unusable." >&2
  exit 1
fi
if ! psql "$PG_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"${DB_BOOT}\";" >/dev/null 2>&1; then
  echo "FAIL: could not CREATE DATABASE ${DB_BOOT} on YUZU_TEST_POSTGRES_DSN — Postgres is set but unusable." >&2
  psql "$PG_DSN" -qtAc "DROP DATABASE IF EXISTS \"${DB_REFUSE}\" WITH (FORCE);" >/dev/null 2>&1 || true
  exit 1
fi
# Extend the cleanup trap to drop both ephemeral DBs (FORCE closes any
# lingering backend) in addition to removing the temp dir.
trap 'psql "$PG_DSN" -qtAc "DROP DATABASE IF EXISTS \"${DB_REFUSE}\" WITH (FORCE);" >/dev/null 2>&1 || true; psql "$PG_DSN" -qtAc "DROP DATABASE IF EXISTS \"${DB_BOOT}\" WITH (FORCE);" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

# Both cases exit before Server::create() ever binds a port (the fatal
# refusal returns before it; the --mfa-reset one-shot exits before it by
# design). `timeout` is defense-in-depth only: if either code path
# regresses to fall through into a full boot, it turns a CI hang into a
# clean non-zero exit instead.
run_bin() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 60 "$BIN" "$@"
  else
    "$BIN" "$@"
  fi
}

pass=0 fail=0

# ── Case 1: fatal refusal — config lists a local user, none has role=admin ──
mkdir -p "$TMP/refuse-data" "$TMP/refuse-ca"
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'pw'.encode(), salt, 100000, dklen=32)
print(f'bob:user:{salt.hex()}:{dk.hex()}')
" > "$TMP/refuse.cfg"
chmod 600 "$TMP/refuse.cfg"

# spdlog's default logger (no --log-file passed) is spdlog's built-in
# stdout sink, not stderr — main.cpp only rebinds to a stderr+file logger
# when --log-file is given. Capture stdout+stderr combined rather than
# asserting a specific stream.
set +e
out="$(run_bin --config "$TMP/refuse.cfg" --data-dir "$TMP/refuse-data" \
       --ca-dir "$TMP/refuse-ca" --postgres-dsn "$CHILD_DSN_REFUSE" \
       </dev/null 2>&1)"
got=$?
set -e

if [ "$got" = "1" ] && printf '%s' "$out" | grep -qF "but none has role=admin"; then
  echo "ok   - fatal refusal: exit=1, fatal message present"; pass=$((pass+1))
else
  echo "FAIL - fatal refusal (exit=$got want=1; out=$out)"; fail=$((fail+1))
fi

# The refusal must be a genuine no-op: no account was provisioned into
# auth.users, and no bootstrap audit event exists — the AuditStore
# (audit_store.audit_events) is only ever constructed inside the branch
# this refusal returns before reaching, so on a clean refusal the schema
# may not exist at all.
users_count="$(psql "$CHILD_DSN_REFUSE" -qtAc "SELECT count(*) FROM auth.users;" 2>/dev/null || echo -1)"
audit_table_exists="$(psql "$CHILD_DSN_REFUSE" -qtAc \
  "SELECT to_regclass('audit_store.audit_events') IS NOT NULL;" 2>/dev/null || echo f)"
if [ "$audit_table_exists" = "t" ]; then
  audit_count="$(psql "$CHILD_DSN_REFUSE" -qtAc \
    "SELECT count(*) FROM audit_store.audit_events WHERE action = 'rbac.bootstrap.first_admin';")"
else
  audit_count=0
fi
if [ "$users_count" = "0" ] && [ "$audit_count" = "0" ]; then
  echo "ok   - fatal refusal: no account provisioned, no bootstrap audit row"; pass=$((pass+1))
else
  echo "FAIL - fatal refusal side effects (auth.users count=$users_count; bootstrap audit count=$audit_count)"
  fail=$((fail+1))
fi

# ── Case 2: successful fresh-install bootstrap writes the durable audit row ──
mkdir -p "$TMP/boot-data" "$TMP/boot-ca"
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'pw'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')
" > "$TMP/boot.cfg"
chmod 600 "$TMP/boot.cfg"

# --mfa-reset runs every line of the fresh-install bootstrap block before
# its own one-shot handling and then exits without starting the server
# (same shape as test_mfa_reset.sh's own admin-cfg case) — the cheapest way
# to reach a completed provision_first_admin() without a full server boot.
set +e
out="$(run_bin --config "$TMP/boot.cfg" --data-dir "$TMP/boot-data" \
       --ca-dir "$TMP/boot-ca" --postgres-dsn "$CHILD_DSN_BOOT" \
       --mfa-reset admin </dev/null 2>&1)"
got=$?
set -e

if [ "$got" != "0" ]; then
  echo "FAIL - fresh-install bootstrap did not complete (--mfa-reset exit=$got want=0; out=$out)"
  fail=$((fail+1))
else
  row="$(psql "$CHILD_DSN_BOOT" -qtAc \
    "SELECT principal || '|' || principal_role || '|' || target_type || '|' || target_id || '|' || result FROM audit_store.audit_events WHERE action = 'rbac.bootstrap.first_admin';")"
  role="$(psql "$CHILD_DSN_BOOT" -qtAc "SELECT role FROM auth.users WHERE username = 'admin';")"
  # The legacy auth.users.role column alone doesn't prove the RBAC grant
  # landed -- provision_first_admin exists specifically to guarantee BOTH
  # the account AND the durable Administrator principal_roles row in one
  # transaction (unlike the older seed_admin_if_empty, which only ever
  # touched the account). Check the grant row directly so a regression that
  # drops/swallows the principal_roles INSERT still fails this test.
  grant_count="$(psql "$CHILD_DSN_BOOT" -qtAc \
    "SELECT count(*) FROM rbac_store.principal_roles WHERE principal_type = 'user' AND principal_id = 'admin' AND role_name = 'Administrator';")"
  if [ "$row" = "system|system|User|admin|success" ] && [ "$role" = "admin" ] && [ "$grant_count" = "1" ]; then
    echo "ok   - fresh-install bootstrap: durable rbac.bootstrap.first_admin audit row + admin grant"
    pass=$((pass+1))
  else
    echo "FAIL - fresh-install bootstrap audit/role/grant (row='$row' want='system|system|User|admin|success'; role='$role' want='admin'; grant_count='$grant_count' want=1)"
    fail=$((fail+1))
  fi
fi

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
