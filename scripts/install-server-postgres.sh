#!/usr/bin/env bash
# install-server-postgres.sh — optional Postgres provisioning for a native
# (non-container) yuzu-server install (ADR-0006/0007, #1318).
#
# Two modes:
#
#   1. External / managed Postgres (first-class):
#        sudo bash scripts/install-server-postgres.sh --dsn 'postgresql://yuzu:...@db.example.com:5432/yuzu'
#      Writes the DSN to /etc/yuzu/yuzu-server.env (mode 0600, yuzu:yuzu),
#      which the systemd unit loads via EnvironmentFile=. No local Postgres
#      is touched.
#
#   2. Local Postgres (default): provisions the app role + database on an
#      already-installed, running local PostgreSQL (16+ recommended) and
#      writes the DSN env file. Idempotent — re-running never clobbers an
#      existing role, database, or env file.
#
# NON-FATAL where Postgres is absent: until #1320 lands the server-side DSN
# consumer, yuzu-server boots happily without Postgres, so a missing local
# cluster prints install hints and exits 0. Flip SOFT_EXIT to 1 when #1320
# makes the DSN mandatory (ADR-0007 fail-closed startup).
#
# Schemas are NOT created here — the server's migration runner owns those
# at startup (ADR-0008), exactly like the container init script
# (deploy/docker/postgres-init/10-create-yuzu-role-db.sh) which is this
# script's compose-side twin.
set -euo pipefail

ENV_FILE="/etc/yuzu/yuzu-server.env"
DEFER_SENTINEL="/etc/yuzu/postgres-provisioning-deferred"
DB_USER="${YUZU_DB_USER:-yuzu}"
DB_NAME="${YUZU_DB_NAME:-yuzu}"
SVC_USER="yuzu"
SOFT_EXIT=0   # see header — becomes a hard failure once #1320 lands
EXTERNAL_DSN=""

# Root-baseline privilege drop to the postgres OS user. We already run as
# root (enforced below; postinst/%post call us as root), so do NOT depend on
# sudo — minimal hosts may not ship it (PR #1381 review, item 3). Prefer
# util-linux runuser, fall back to su; sudo is the last resort (macOS has no
# runuser, and Homebrew clusters usually run under the operator's own user —
# those fail soft at the detection step regardless).
run_as_postgres() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u postgres -- "$@"
  elif command -v su >/dev/null 2>&1; then
    su -s /bin/sh postgres -c "$(printf '%q ' "$@")"
  else
    sudo -u postgres "$@"
  fi
}

usage() {
  echo "usage: $0 [--dsn <postgresql://...>]" >&2
  echo "  --dsn   use an external/managed Postgres; only writes ${ENV_FILE}" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dsn) EXTERNAL_DSN="${2:?--dsn needs a value}"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: must run as root (writes ${ENV_FILE}; provisions the DB role)" >&2
  exit 1
fi

write_env_file() {
  local dsn="$1"
  install -d -m 0750 /etc/yuzu
  if [[ -f "$ENV_FILE" ]] && grep -q '^YUZU_POSTGRES_DSN=' "$ENV_FILE"; then
    echo "ok: ${ENV_FILE} already carries YUZU_POSTGRES_DSN — leaving it untouched"
    return 0
  fi
  # Pre-create at 0600 so the file NEVER exists world-readable, even for a
  # sub-second window between write and chmod (PR #1334 review, S3).
  if [[ ! -f "$ENV_FILE" ]]; then
    install -m 0600 /dev/null "$ENV_FILE"
  fi
  chmod 0600 "$ENV_FILE"
  # Append-or-create so other variables in the file survive.
  printf 'YUZU_POSTGRES_DSN=%s\n' "$dsn" >> "$ENV_FILE"
  # The yuzu service user may not exist yet on a bare provisioning run.
  chown "${SVC_USER}:${SVC_USER}" "$ENV_FILE" 2>/dev/null || true
  echo "ok: wrote YUZU_POSTGRES_DSN to ${ENV_FILE} (0600)"
}

# ── Mode 1: external DSN — write and done ────────────────────────────────
if [[ -n "$EXTERNAL_DSN" ]]; then
  write_env_file "$EXTERNAL_DSN"
  rm -f "$DEFER_SENTINEL"
  exit 0
fi

# ── Mode 2: local provisioning ───────────────────────────────────────────
# Soft-detect a running local cluster: psql present + the postgres
# superuser can connect over the local socket.
if ! command -v psql >/dev/null 2>&1 \
   || ! run_as_postgres psql -At -c 'SELECT 1' >/dev/null 2>&1; then
  echo "warn: no running local PostgreSQL found — skipping provisioning (non-fatal until #1320)." >&2
  echo "      Install one first, e.g.:" >&2
  echo "        Debian/Ubuntu:  apt-get install postgresql-18   (or distro default)" >&2
  echo "        RHEL/Fedora:    dnf install postgresql-server && postgresql-setup --initdb" >&2
  echo "        macOS:          brew install postgresql@18 && brew services start postgresql@18" >&2
  echo "      then re-run this script, or point at a managed database with:" >&2
  echo "        $0 --dsn 'postgresql://...'" >&2
  # Durable breadcrumb: the soft-skip is silent in package-install logs, and
  # the server starts REQUIRING a DSN at the #1320 fail-closed flip. The
  # sentinel gives that failure a findable cause (PR #1381 review, item 3).
  install -d -m 0750 /etc/yuzu
  printf 'deferred at %s: no running local PostgreSQL found.\nRe-run install-server-postgres.sh (or --dsn for a managed database); this file is removed on success.\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DEFER_SENTINEL"
  echo "      (recorded in ${DEFER_SENTINEL})" >&2
  exit "$SOFT_EXIT"
fi

# Generate a credential only if the role doesn't exist yet; never reset an
# existing role's password (idempotency). The credential is freshly random
# (openssl rand) — the app role NEVER shares a password with any superuser
# (the local postgres superuser authenticates via peer auth, passwordless).
#
# Existence checks use psql -v / :'var' interpolation like the CREATEs —
# never shell interpolation into SQL (PR #1334 review, S2). No `|| true`:
# under `set -e` a failed query (cluster down, bad identifier) aborts the
# script instead of masquerading as "role does not exist". psql variables
# do not interpolate in -c strings, so the query comes via stdin.
role_exists=$(run_as_postgres psql -At -v ON_ERROR_STOP=1 \
  -v yuzu_user="$DB_USER" <<'EOSQL'
SELECT 1 FROM pg_roles WHERE rolname = :'yuzu_user'
EOSQL
)

DB_PASSWORD=""
if [[ "$role_exists" != "1" ]]; then
  DB_PASSWORD="$(openssl rand -hex 24)"
  # 48 lowercase hex chars by construction (openssl rand -hex 24). This
  # assertion is what makes the \set line below hazard-free: psql applies
  # C-style backslash escapes inside single-quoted meta-command args, and
  # hex contains none of the characters that could break out of the quote.
  # Fail hard rather than provision if that ever isn't true.
  if [[ ! "$DB_PASSWORD" =~ ^[0-9a-f]{48}$ ]]; then
    echo "error: openssl rand produced an unexpected credential shape; refusing to provision" >&2
    exit 1
  fi
  # The password rides stdin as a psql \set meta-command (builtin printf —
  # no process, no argv) rather than -v: -v puts it in argv, which is
  # world-readable via /proc/<pid>/cmdline and ps for the psql child's
  # lifetime (F7/#3859). It never touches raw SQL — :'yuzu_pass' still goes
  # through psql's own SQL-literal quoting, same S2 property as above.
  # \set rather than \getenv (the container init script's twin, gov Gate 4,
  # #3859): \getenv is psql 15+ only, and this script's target is whatever
  # psql ships with the host's local cluster — including distro-default
  # psql 13/14 (RHEL9, older Ubuntu). Don't "simplify" this to \getenv.
  # -X/--no-psqlrc: the postgres OS user's ~/.psqlrc is untrusted input to
  # this script — an `ECHO all` setting there would otherwise echo the raw
  # \set line (password included) to stdout (gov Gate 2, #3859).
  printf '%s\n' \
    "\\set yuzu_pass '${DB_PASSWORD}'" \
    "SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'yuzu_user', :'yuzu_pass')" \
    '\gexec' \
    | run_as_postgres psql -X -v ON_ERROR_STOP=1 -v yuzu_user="$DB_USER"
  echo "ok: created role '${DB_USER}'"
else
  echo "ok: role '${DB_USER}' already exists — password left unchanged"
fi

db_exists=$(run_as_postgres psql -At -v ON_ERROR_STOP=1 \
  -v yuzu_db="$DB_NAME" <<'EOSQL'
SELECT 1 FROM pg_database WHERE datname = :'yuzu_db'
EOSQL
)
if [[ "$db_exists" != "1" ]]; then
  run_as_postgres psql -v ON_ERROR_STOP=1 \
    -v yuzu_db="$DB_NAME" -v yuzu_user="$DB_USER" <<'EOSQL'
SELECT format('CREATE DATABASE %I OWNER %I', :'yuzu_db', :'yuzu_user')
\gexec
EOSQL
  echo "ok: created database '${DB_NAME}' owned by '${DB_USER}'"
else
  echo "ok: database '${DB_NAME}' already exists"
fi

# pgvector if available (the yuzu-postgres image always has it; a distro
# cluster needs the postgresql-18-pgvector package). Non-fatal — only the
# vuln-graph store (ADR-0004) needs it, and that lands later.
if ! run_as_postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" \
     -c 'CREATE EXTENSION IF NOT EXISTS vector' >/dev/null 2>&1; then
  echo "warn: pgvector extension unavailable — install postgresql-18-pgvector (or distro equivalent) before the vuln-graph store migrates" >&2
fi

if [[ -n "$DB_PASSWORD" ]]; then
  write_env_file "postgresql://${DB_USER}:${DB_PASSWORD}@127.0.0.1:5432/${DB_NAME}"
else
  # Role pre-existed so we don't know its password; only write a DSN if the
  # env file doesn't already have one (write_env_file no-ops in that case),
  # using a placeholder the operator must fill in.
  if [[ -f "$ENV_FILE" ]] && grep -q '^YUZU_POSTGRES_DSN=' "$ENV_FILE"; then
    echo "ok: existing DSN in ${ENV_FILE} retained"
  else
    echo "warn: role existed before this run, so its password is unknown here." >&2
    echo "      Write the DSN yourself:  $0 --dsn 'postgresql://${DB_USER}:<password>@127.0.0.1:5432/${DB_NAME}'" >&2
  fi
fi

rm -f "$DEFER_SENTINEL"
echo "done. The systemd unit picks the DSN up via EnvironmentFile=${ENV_FILE} (server-side consumer: #1320)."
