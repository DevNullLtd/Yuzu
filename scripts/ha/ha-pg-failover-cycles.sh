#!/usr/bin/env bash
# ha-pg-failover-cycles.sh — repeated automatic-failover soak (WS-7 / WS-9).
#
# Where ha-pg-smoke.sh proves ONE failover, this proves the cluster fails over
# RELIABLY and repeatedly: it kills the current primary, verifies promotion +
# RPO=0 through the unchanged HAProxy endpoint, restarts the killed node, waits
# for full 3-node health, and repeats — so successive cycles kill different
# nodes and exercise node rejoin (via pg_rewind or a reclone; the harness asserts
# the node re-streams, not which path Patroni took). Reports per-cycle RTO.
#
# Usage:
#   bash scripts/ha/ha-pg-failover-cycles.sh            # 3 cycles, tears down
#   CYCLES=5 bash scripts/ha/ha-pg-failover-cycles.sh   # more cycles
#   bash scripts/ha/ha-pg-failover-cycles.sh --keep
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker/docker-compose.ha-postgres.yml"
NETWORK="yuzu-ha-pg"
CLIENT_IMAGE="yuzu-postgres:local"
NODES=(yuzu-ha-pg1 yuzu-ha-pg2 yuzu-ha-pg3)
CYCLES="${CYCLES:-3}"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1
export BUILDX_BUILDER="${YUZU_HA_BUILDER:-default}"

APP_USER="${YUZU_DB_USER:-yuzu}"; APP_DB="${YUZU_DB_NAME:-yuzu}"; APP_PASS="${YUZU_DB_PASSWORD:-yuzu-app-dev}"
SUPER="${YUZU_SUPERUSER_NAME:-postgres}"
# The compose REQUIRES all three passwords (no insecure defaults) — export dev
# values for the harness (overridable from the env).
export YUZU_SUPERUSER_PASSWORD="${YUZU_SUPERUSER_PASSWORD:-yuzu-super-dev}"
export YUZU_PG_REPLICATION_PASSWORD="${YUZU_PG_REPLICATION_PASSWORD:-yuzu-repl-dev}"
export YUZU_DB_PASSWORD="${APP_PASS}"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }
cleanup() {
  if [[ "${KEEP}" -eq 1 ]]; then printf '\n(--keep) left running: docker compose -f %s down -v\n' "${COMPOSE_FILE}"
  else say "Tearing down"; docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# timeout backstops everywhere: no probe may block a loop indefinitely if a
# backend accepts TCP then dies mid-handshake during a failover window.
appsql() {
  timeout 20 docker run --rm --network "${NETWORK}" \
    -e PGPASSWORD="${APP_PASS}" -e PGCONNECT_TIMEOUT=5 --entrypoint psql \
    "${CLIENT_IMAGE}" -h postgres -U "${APP_USER}" -d "${APP_DB}" -v ON_ERROR_STOP=1 -tAc "$1"
}
find_primary() {
  local n code
  for n in "${NODES[@]}"; do
    code="$(timeout 10 docker exec "$n" curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:8008/primary 2>/dev/null || echo 000)"
    [[ "${code}" == "200" ]] && { echo "$n"; return 0; }
  done
  return 1
}
# Wait until the primary reports it has >=1 streaming sync/quorum standby.
wait_sync_standby() {
  local p="$1" i s
  for i in $(seq 1 90); do
    s="$(timeout 15 docker exec "$p" psql -U "${SUPER}" -d postgres -tAc \
      "SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND sync_state IN ('sync','quorum')" 2>/dev/null || echo 0)"
    [[ "${s:-0}" -ge 1 ]] && { echo "$s"; return 0; }
    sleep 2
  done
  return 1
}
# Wait until the primary sees the full standby fleet streaming again (all N-1).
wait_full_health() {
  local p="$1" want="$2" i s
  for i in $(seq 1 90); do
    s="$(timeout 15 docker exec "$p" psql -U "${SUPER}" -d postgres -tAc \
      "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'" 2>/dev/null || echo 0)"
    [[ "${s:-0}" -ge "${want}" ]] && { echo "$s"; return 0; }
    sleep 2
  done
  return 1
}

# ── base image ────────────────────────────────────────────────────────────
if ! docker image inspect yuzu-postgres:local >/dev/null 2>&1; then
  say "Building base image yuzu-postgres:local (one-time)"
  docker build -t yuzu-postgres:local -f "${REPO_ROOT}/deploy/docker/Dockerfile.postgres" "${REPO_ROOT}"
fi

say "Bringing up the HA-Postgres cluster"
docker compose -f "${COMPOSE_FILE}" up -d --build

say "Waiting for a primary + a caught-up sync standby"
primary=""
for i in $(seq 1 60); do
  if primary="$(find_primary)"; then
    [[ "$(appsql 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)" == "t" ]] && break
  fi
  sleep 2; [[ "${i}" -eq 60 ]] && die "cluster not write-ready within 120s"
done
# Require BOTH standbys caught up before the first kill — under
# synchronous_mode_strict the promoted survivor must already have a synced sync
# standby or it blocks writes far longer than a real failover (the per-cycle
# rejoin below waits for the same full health).
wait_full_health "${primary}" "$(( ${#NODES[@]} - 1 ))" >/dev/null || die "not all standbys caught up"
wait_sync_standby "${primary}" >/dev/null || die "no sync standby caught up"
ok "cluster healthy (all standbys synced), primary=${primary}"

appsql "CREATE TABLE IF NOT EXISTS ha_cycles(id bigserial primary key, cycle int, note text, ts timestamptz default now())" >/dev/null
appsql "INSERT INTO ha_cycles(cycle,note) SELECT 0,'baseline' FROM generate_series(1,100)" >/dev/null

declare -a RTOS=()
for c in $(seq 1 "${CYCLES}"); do
  say "── Cycle ${c}/${CYCLES}: kill primary ${primary} ──"
  pre="$(appsql 'SELECT count(*) FROM ha_cycles')"
  docker update --restart=no "${primary}" >/dev/null 2>&1 || true
  kill_ts="$(date +%s.%N)"
  docker kill "${primary}" >/dev/null
  killed="${primary}"

  deadline=$(( $(date +%s) + 120 )); new=""
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    if [[ "$(appsql 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)" == "t" ]]; then new="$(find_primary || echo '?')"; break; fi
    sleep 2
  done
  [[ -n "${new}" && "${new}" != "${killed}" ]] || die "cycle ${c}: no failover from ${killed} within 120s"
  rto="$(awk "BEGIN{printf \"%.1f\", $(date +%s.%N) - ${kill_ts}}")"; RTOS+=("${rto}")

  post="$(appsql 'SELECT count(*) FROM ha_cycles')"
  [[ "${post}" == "${pre}" ]] || die "cycle ${c}: RPO VIOLATION (${pre} before, ${post} after)"
  appsql "INSERT INTO ha_cycles(cycle,note) VALUES (${c}, 'after-failover-${killed}')" >/dev/null
  ok "cycle ${c}: ${killed} → ${new}, RTO ≈ ${rto}s, RPO=0 (${post} rows intact)"

  # bring the killed node back and wait for full 3-node health before next kill
  say "Cycle ${c}: restarting ${killed}, waiting for full health"
  docker update --restart=unless-stopped "${killed}" >/dev/null 2>&1 || true
  docker start "${killed}" >/dev/null
  primary="${new}"
  wait_full_health "${primary}" 2 >/dev/null || die "cycle ${c}: ${killed} did not rejoin as streaming standby"
  wait_sync_standby "${primary}" >/dev/null || die "cycle ${c}: sync standby not re-established"
  ok "cycle ${c}: ${killed} rejoined; cluster back to full 3-node health"
done

say "Final consistency check"
markers="$(appsql "SELECT count(*) FROM ha_cycles WHERE cycle > 0")"
[[ "${markers}" == "${CYCLES}" ]] || die "expected ${CYCLES} post-failover marker rows, found ${markers}"
base="$(appsql "SELECT count(*) FROM ha_cycles WHERE cycle = 0")"
[[ "${base}" == "100" ]] || die "baseline rows lost: expected 100, found ${base}"
ok "all ${CYCLES} failover markers + 100 baseline rows present across every failover"

printf '\n\033[1;32mSOAK PASSED — %s consecutive failovers, RTOs: %ss, RPO=0 throughout\033[0m\n' "${CYCLES}" "${RTOS[*]}"
