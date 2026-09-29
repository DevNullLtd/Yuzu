#!/usr/bin/env bash
# ha-pg-smoke.sh — bring up the HA-Postgres cluster, prove automatic failover
# with zero acknowledged-write loss (WS-7 / WS-9 seed, ADR-2002 §11/§13/§14).
#
# What it proves:
#   1. A 3-node Patroni cluster forms and elects a primary.
#   2. The server-facing endpoint (HAProxy `postgres:5432` alias) accepts writes
#      with NO server-side config beyond the unchanged DSN.
#   3. Killing the primary triggers automatic failover; HAProxy re-points to the
#      newly promoted primary within the measured RTO.
#   4. Every write acknowledged BEFORE the kill survives it (RPO=0 under the
#      default quorum profile), and writes resume afterwards.
#
# Usage:
#   bash scripts/ha/ha-pg-smoke.sh            # full run, tears down at the end
#   bash scripts/ha/ha-pg-smoke.sh --keep     # leave the cluster up for poking
#   ROWS=500 bash scripts/ha/ha-pg-smoke.sh   # more pre-kill writes
#
# Requires: docker + compose. Builds yuzu-postgres:local (base) if absent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker/docker-compose.ha-postgres.yml"
NETWORK="yuzu-ha-pg"
# Base substrate image as the psql client — its `psql` runs directly. (The HA
# image can't be used here: its ENTRYPOINT is patroni-entrypoint.sh, which would
# intercept the psql command.)
CLIENT_IMAGE="yuzu-postgres:local"
NODES=(yuzu-ha-pg1 yuzu-ha-pg2 yuzu-ha-pg3)
ROWS="${ROWS:-200}"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

# App credentials. The compose REQUIRES all three passwords (no insecure
# defaults); export dev values here for the harness (overridable from the env).
APP_USER="${YUZU_DB_USER:-yuzu}"
APP_DB="${YUZU_DB_NAME:-yuzu}"
APP_PASS="${YUZU_DB_PASSWORD:-yuzu-app-dev}"
export YUZU_SUPERUSER_PASSWORD="${YUZU_SUPERUSER_PASSWORD:-yuzu-super-dev}"
export YUZU_PG_REPLICATION_PASSWORD="${YUZU_PG_REPLICATION_PASSWORD:-yuzu-repl-dev}"
export YUZU_DB_PASSWORD="${APP_PASS}"

[[ "${ROWS}" =~ ^[0-9]+$ && "${ROWS}" -gt 0 ]] \
  || { echo "ROWS must be a positive integer (got '${ROWS}')" >&2; exit 1; }

# The HA image builds `FROM yuzu-postgres:local` (a local-only tag). That
# resolves only on a buildx builder that shares the local image store — the
# `docker` driver — NOT a `docker-container` builder (which would try to pull
# the tag from a registry and fail). Pin the build steps to the default builder.
export BUILDX_BUILDER="${YUZU_HA_BUILDER:-default}"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ "${KEEP}" -eq 1 ]]; then
    printf '\n(--keep) cluster left running. Tear down with:\n  docker compose -f %s down -v\n' "${COMPOSE_FILE}"
  else
    say "Tearing down"
    docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Run psql against the HAProxy endpoint (the `postgres` alias) from an ephemeral
# client on the cluster network — independent of which node is primary/alive.
appsql() {
  # Hard backstops: a connection opened during the brief "HAProxy has no
  # backend" failover window can stall on a backend that accepted TCP then died
  # mid-handshake. PGCONNECT_TIMEOUT bounds libpq; `timeout` bounds the whole
  # docker run regardless — so a probe never blocks the loop indefinitely.
  timeout 20 docker run --rm --network "${NETWORK}" \
    -e PGPASSWORD="${APP_PASS}" -e PGCONNECT_TIMEOUT=5 \
    --entrypoint psql "${CLIENT_IMAGE}" \
    -h postgres -U "${APP_USER}" -d "${APP_DB}" \
    -v ON_ERROR_STOP=1 -tAc "$1"
}

# Which container is the current Patroni primary? (REST /primary → 200 on leader)
find_primary() {
  local n code
  for n in "${NODES[@]}"; do
    code="$(timeout 10 docker exec "${n}" curl -s -m 5 -o /dev/null -w '%{http_code}' \
             http://localhost:8008/primary 2>/dev/null || echo 000)"
    if [[ "${code}" == "200" ]]; then echo "${n}"; return 0; fi
  done
  return 1
}

# ── 0. base image ─────────────────────────────────────────────────────────
if ! docker image inspect yuzu-postgres:local >/dev/null 2>&1; then
  say "Building base image yuzu-postgres:local (pgvector from source — slow, one-time)"
  docker build -t yuzu-postgres:local -f "${REPO_ROOT}/deploy/docker/Dockerfile.postgres" "${REPO_ROOT}"
fi

# ── 1. bring up ───────────────────────────────────────────────────────────
say "Bringing up the HA-Postgres cluster (etcd + 3×Patroni + HAProxy)"
docker compose -f "${COMPOSE_FILE}" up -d --build

say "Waiting for a primary to be elected and accept writes via HAProxy"
primary=""
for i in $(seq 1 60); do
  if primary="$(find_primary)"; then
    # confirm the HAProxy path is write-capable (not in recovery)
    if [[ "$(appsql 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)" == "t" ]]; then
      ok "primary elected: ${primary} (writes flow through HAProxy)"
      break
    fi
  fi
  sleep 2
  [[ "${i}" -eq 60 ]] && die "cluster did not become write-ready within 120s"
done

# ── 1b. wait for a synchronous standby to catch up ───────────────────────
# CRITICAL failover-safety gate: a primary elected seconds ago still has its
# standbys running their initial pg_basebackup (role "creating replica").
# Killing it then leaves NO caught-up node to promote — Patroni correctly
# refuses ("not healthy enough for leader race") and the cluster stalls. Only
# once a standby is STREAMING in the sync/quorum set is a failover survivable
# with RPO=0. (This is a real property any failover test must assert.)
# Require BOTH standbys caught up, not just one. Under synchronous_mode_strict,
# the node that gets promoted must have a caught-up sync standby before it will
# accept writes; if we kill while a standby is still cloning, the survivor that
# promotes is left waiting on the behind standby and writes stall far longer than
# a real failover. Waiting for all N-1 standbys guarantees the survivor is synced.
NEED_SYNC=$(( ${#NODES[@]} - 1 ))
say "Waiting for both synchronous standbys to catch up (failover-safety gate)"
for i in $(seq 1 90); do
  synced="$(timeout 15 docker exec "${primary}" psql -U "${YUZU_SUPERUSER_NAME:-postgres}" -d postgres -tAc \
    "SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND sync_state IN ('sync','quorum')" 2>/dev/null || echo 0)"
  if [[ "${synced:-0}" -ge "${NEED_SYNC}" ]]; then ok "both synchronous standbys streaming and caught up (${synced})"; break; fi
  sleep 2
  [[ "${i}" -eq 90 ]] && die "both synchronous standbys not caught up within 180s (strict mode needs the survivor already synced for a fast failover)"
done

# ── 2. pre-kill writes (each its own committed txn) ───────────────────────
say "Writing ${ROWS} committed rows through the server-facing endpoint"
# DROP first so the run is deterministic even if a prior cluster left the volume
# behind. Static rows take ids 1..ROWS via the sequence, so the concurrent
# DEFAULT VALUES writes below (nextval) start at ROWS+1 — no PK collision.
appsql "DROP TABLE IF EXISTS ha_smoke" >/dev/null
appsql "CREATE TABLE ha_smoke(id bigserial primary key, ts timestamptz default now())" >/dev/null
appsql "INSERT INTO ha_smoke SELECT nextval('ha_smoke_id_seq') FROM generate_series(1, ${ROWS})" >/dev/null
before="$(appsql 'SELECT count(*) FROM ha_smoke')"
[[ "${before}" == "${ROWS}" ]] || die "expected ${ROWS} rows pre-kill, got ${before}"
ok "${before} rows committed and acknowledged"

# ── 3. kill the primary, measure failover ─────────────────────────────────
say "Killing the primary (${primary}) — simulating a host/node loss"
# Disable restart first so the SIGKILL sticks (else restart:unless-stopped revives it).
docker update --restart=no "${primary}" >/dev/null 2>&1 || true
kill_ts="$(date +%s.%N)"
docker kill "${primary}" >/dev/null

# Wait until writes flow again through the unchanged HAProxy endpoint. Wall-clock
# deadline; RTO is the operator-visible time to write-resumption.
say "Waiting for automatic failover (writes resume via HAProxy)"
deadline=$(( $(date +%s) + 180 ))
new_primary=""
while [[ "$(date +%s)" -lt "${deadline}" ]]; do
  if [[ "$(appsql 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)" == "t" ]]; then
    new_primary="$(find_primary || echo '?')"
    break
  fi
  sleep 2
done
[[ -n "${new_primary}" && "${new_primary}" != "${primary}" ]] || die "no write-capable new primary via HAProxy within 180s"
rto="$(awk "BEGIN{printf \"%.1f\", $(date +%s.%N) - ${kill_ts}}")"
ok "failover complete: new primary ${new_primary}, writes resumed, RTO ≈ ${rto}s"

# ── 4. RPO=0 — every acknowledged pre-kill row survives ────────────────────
say "Verifying zero acknowledged-write loss (RPO=0) and resumed writes"
after="$(appsql 'SELECT count(*) FROM ha_smoke')"
[[ "${after}" == "${ROWS}" ]] || die "RPO VIOLATION: ${ROWS} acknowledged rows before, ${after} after failover"
ok "all ${after} acknowledged pre-kill rows survived the failover (RPO=0)"

# one more committed write proves the new primary accepts application writes end-to-end
appsql "INSERT INTO ha_smoke DEFAULT VALUES" >/dev/null
resumed="$(appsql 'SELECT count(*) FROM ha_smoke')"
[[ "${resumed}" -gt "${after}" ]] || die "application writes did not resume on the new primary"
ok "application writes resumed on the new primary (${resumed} rows total)"

say "SMOKE PASSED — automatic failover, RTO ≈ ${rto}s, RPO=0 (${ROWS} acknowledged rows preserved)"
