#!/bin/bash
# 10-create-yuzu-role-db.sh — first-boot init for the yuzu-postgres image.
#
# Creates the Yuzu application role and database, and installs the pgvector
# extension into the app database (extension creation needs superuser; doing
# it here means the app role never needs elevated rights).
#
# Per-store SCHEMAs and all tables are created at runtime by the server's
# migration runner (ADR-0008) — deliberately NOT here.
#
# Runs under the upstream postgres entrypoint (docker-entrypoint-initdb.d),
# i.e. only when the data directory is empty. Guarded with WHERE NOT EXISTS
# so a custom POSTGRES_USER/POSTGRES_DB that collides with the Yuzu defaults
# cannot abort initdb — but a pre-existing role/db is then VALIDATED
# (non-superuser, login-capable, correct db owner) so the collision cannot
# silently hand the app DSN superuser rights (PR #1334 review, S4).
#
# Env contract (see Dockerfile.postgres header):
#   YUZU_DB_USER      app role      (default: yuzu)
#   YUZU_DB_NAME      app database  (default: yuzu)
#   YUZU_DB_PASSWORD  app password  REQUIRED — must differ from
#                     POSTGRES_PASSWORD. There is deliberately no fallback
#                     to the superuser password: a leaked app DSN must never
#                     disclose superuser credentials (PR #1334 review, S1).
#   YUZU_PG_RESERVED_CONNECTIONS
#                     Connection slots reserved for the app role, ahead of
#                     every other client (HA WS-8, #4943; default: 40, 0 =
#                     none). The app role is granted
#                     pg_use_reserved_connections (PG 16+) so its pool AND
#                     its /readyz probe draw from that reserve — a backup
#                     job or an ad-hoc psql session can then never take the
#                     slot the probe needs to reconnect, which would red a
#                     replica on a database that still serves. On the
#                     single-node image the number is applied with ALTER
#                     SYSTEM (takes effect when the entrypoint restarts the
#                     server after initdb); under Patroni (PATRONI_SCOPE
#                     set) the entrypoint renders it into the bootstrap
#                     parameters instead, because Patroni owns
#                     postgresql.conf and warns on ALTER SYSTEM overrides.
#                     Size it at N_servers x (--postgres-pool-size + 2).
set -euo pipefail

YUZU_DB_USER="${YUZU_DB_USER:-yuzu}"
YUZU_DB_NAME="${YUZU_DB_NAME:-yuzu}"
YUZU_PG_RESERVED_CONNECTIONS="${YUZU_PG_RESERVED_CONNECTIONS:-40}"
if ! [[ "${YUZU_PG_RESERVED_CONNECTIONS}" =~ ^[0-9]{1,6}$ ]]; then
    echo "yuzu-postgres init: ERROR — YUZU_PG_RESERVED_CONNECTIONS must be a non-negative integer" >&2
    echo "  (got '${YUZU_PG_RESERVED_CONNECTIONS}')." >&2
    exit 1
fi

# ── Credential / identity guards (S1 + S4) ───────────────────────────────
if [[ -z "${YUZU_DB_PASSWORD:-}" ]]; then
    echo "yuzu-postgres init: ERROR — YUZU_DB_PASSWORD is not set." >&2
    echo "  The app role password must be provided explicitly and must" >&2
    echo "  differ from POSTGRES_PASSWORD (the superuser password)." >&2
    echo "  Generate one:  openssl rand -hex 24" >&2
    exit 1
fi
if [[ "${YUZU_DB_PASSWORD}" == "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set (upstream image contract)}" ]]; then
    echo "yuzu-postgres init: ERROR — YUZU_DB_PASSWORD equals POSTGRES_PASSWORD." >&2
    echo "  The app role and the superuser must not share a password: a" >&2
    echo "  leaked app DSN would disclose superuser credentials." >&2
    exit 1
fi
if [[ "${YUZU_DB_USER}" == "${POSTGRES_USER}" ]]; then
    echo "yuzu-postgres init: ERROR — YUZU_DB_USER ('${YUZU_DB_USER}') equals POSTGRES_USER." >&2
    echo "  The app role must not be the bootstrap superuser. Pick a" >&2
    echo "  different YUZU_DB_USER (or POSTGRES_USER)." >&2
    exit 1
fi

# psql variable substitution (:'var' literal / :"var" identifier) + format()
# with %I/%L handles quoting safely — role/db names and the password are
# never spliced into SQL by the shell. The password is read by psql from its
# own environment (\getenv, psql 15+; this image ships 18) rather than -v,
# so it is never in argv, which the HOST process table exposes even for
# container processes (F7/#3859) — environ is owner-only, argv is not.
# -X/--no-psqlrc: \getenv keeps the password out of the ECHOED INPUT LINE,
# but \gexec separately echoes the fully-substituted query text under an
# active ECHO setting — so a .psqlrc under the postgres OS user's $HOME
# (the same /var/lib/postgresql this image tells operators to mount a
# volume at) setting `\set ECHO all` would still print the password via
# \gexec's echo, same disclosure class as the native script's -X fix
# (gov Gate 4, #3859). Any FUTURE psql call in this file that ever
# handles a secret needs -X too — it is per-invocation, not file-wide.
psql -X -v ON_ERROR_STOP=1 \
     -v yuzu_user="${YUZU_DB_USER}" \
     -v yuzu_db="${YUZU_DB_NAME}" \
     --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
\getenv yuzu_pass YUZU_DB_PASSWORD
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'yuzu_user', :'yuzu_pass')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'yuzu_user')
\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'yuzu_db', :'yuzu_user')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'yuzu_db')
\gexec
EOSQL

# ── Post-create validation (S4) ──────────────────────────────────────────
# Whether we just created them or a custom POSTGRES_USER/POSTGRES_DB
# collided with the Yuzu names, the end state must be: non-superuser
# login-capable app role, app database owned by it. Fail the boot loudly
# otherwise — a silently-superuser app role is worse than no database.
role_attrs=$(psql -At -v ON_ERROR_STOP=1 -v yuzu_user="${YUZU_DB_USER}" \
    --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
SELECT CASE
         WHEN NOT rolsuper AND rolcanlogin THEN 'ok'
         ELSE 'rolsuper=' || rolsuper::text || ',rolcanlogin=' || rolcanlogin::text
       END
  FROM pg_roles WHERE rolname = :'yuzu_user'
EOSQL
)
if [[ "${role_attrs}" != "ok" ]]; then
    echo "yuzu-postgres init: ERROR — role '${YUZU_DB_USER}' exists but is not a plain login role" >&2
    echo "  (${role_attrs:-role missing}; expected rolsuper=false, rolcanlogin=true)." >&2
    echo "  Refusing to hand the app DSN to this role. Drop/fix it or choose" >&2
    echo "  a different YUZU_DB_USER." >&2
    exit 1
fi

db_owner=$(psql -At -v ON_ERROR_STOP=1 -v yuzu_db="${YUZU_DB_NAME}" \
    --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :'yuzu_db'
EOSQL
)
if [[ "${db_owner}" != "${YUZU_DB_USER}" ]]; then
    echo "yuzu-postgres init: ERROR — database '${YUZU_DB_NAME}' is owned by '${db_owner:-<missing>}'," >&2
    echo "  expected '${YUZU_DB_USER}'. Refusing to continue with wrong ownership." >&2
    exit 1
fi

# ── Extension + schema hardening inside the app database ─────────────────
# REVOKE CREATE: PG15+ already restricts the public schema, but be explicit
# — non-owner roles must not be able to create objects in public. The app
# role keeps create rights via database/schema ownership.
psql -v ON_ERROR_STOP=1 \
     --username "${POSTGRES_USER}" --dbname "${YUZU_DB_NAME}" <<'EOSQL'
CREATE EXTENSION IF NOT EXISTS vector;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
EOSQL

# ── Reserved connection slots for the app role (HA WS-8, #4943) ──────────
# pg_use_reserved_connections + reserved_connections exist from PG 16. The
# GRANT is what makes the reserve reach the app: it applies to every session
# the role opens — the server's pool and its /readyz probe alike — so the
# probe's reconnect is never refused ahead of a pool connect (the probe must
# see exactly what a fresh pool connection sees; a probe-only privilege
# would report ready while pool connects fail). On an older server the grant
# would fail, so it is skipped with a notice rather than aborting initdb.
# The setting itself is postmaster-context (server start): ALTER SYSTEM here
# lands in postgresql.auto.conf and takes effect when the upstream entrypoint
# restarts the server after initdb. Under Patroni the entrypoint owns the
# parameter (see the header), so only the GRANT runs here.
server_version_num=$(psql -At -v ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" --dbname postgres -c "SHOW server_version_num")
if (( server_version_num >= 160000 )); then
    psql -v ON_ERROR_STOP=1 -v yuzu_user="${YUZU_DB_USER}" \
         --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
SELECT format('GRANT pg_use_reserved_connections TO %I', :'yuzu_user')
\gexec
EOSQL
    if [[ -z "${PATRONI_SCOPE:-}" ]]; then
        # Bound the reserve against the LIVE cluster (an operator may have passed
        # their own -c max_connections=... to `docker run`, so the check reads it
        # back rather than assuming the image default). reserved_connections is a
        # hard carve-out on Postgres: set it at or past max_connections minus
        # superuser_reserved_connections and NO ordinary (non-privileged) client —
        # a backup job, Grafana's DSN, an operator's own psql — can ever connect
        # again, not merely under load (security-guardian, Gate 2 finding #1).
        max_conn=$(psql -At -v ON_ERROR_STOP=1             --username "${POSTGRES_USER}" --dbname postgres -c "SHOW max_connections")
        su_reserved=$(psql -At -v ON_ERROR_STOP=1             --username "${POSTGRES_USER}" --dbname postgres -c "SHOW superuser_reserved_connections")
        ordinary_floor=$(( max_conn - su_reserved ))
        if (( YUZU_PG_RESERVED_CONNECTIONS >= ordinary_floor )); then
            echo "yuzu-postgres init: ERROR — YUZU_PG_RESERVED_CONNECTIONS=${YUZU_PG_RESERVED_CONNECTIONS}" >&2
            echo "  is >= max_connections(${max_conn}) - superuser_reserved_connections(${su_reserved}) = ${ordinary_floor}." >&2
            echo "  That leaves ZERO connection slots any ordinary (non-privileged) client can ever use —" >&2
            echo "  not merely under load. Lower YUZU_PG_RESERVED_CONNECTIONS or raise max_connections." >&2
            echo "  NOTE: the role/database above already exist on this data directory now — restarting" >&2
            echo "  this same container with a corrected value will NOT re-run this script (initdb-once)" >&2
            echo "  and will silently start WITHOUT the fix applied. Either wipe this data volume and" >&2
            echo "  start fresh, or apply reserved_connections/the GRANT by hand per the 'Existing" >&2
            echo "  databases' steps in docs/user-manual/server-admin.md." >&2
            exit 1
        fi
        psql -v ON_ERROR_STOP=1 -v n="${YUZU_PG_RESERVED_CONNECTIONS}" \
             --username "${POSTGRES_USER}" --dbname postgres <<'EOSQL'
SELECT format('ALTER SYSTEM SET reserved_connections = %s', :'n'::int)
\gexec
EOSQL
        reserved_note="reserved_connections=${YUZU_PG_RESERVED_CONNECTIONS} (applied at server start)"
    else
        reserved_note="reserved_connections rendered by the Patroni entrypoint"
    fi
    reserved_note="${reserved_note}; ${YUZU_DB_USER} granted pg_use_reserved_connections"
else
    reserved_note="server_version_num=${server_version_num} < 160000: no reserved_connections support, skipped"
fi

echo "yuzu-postgres init: role '${YUZU_DB_USER}' + database '${YUZU_DB_NAME}' ready (pgvector installed; ${reserved_note})"
