#!/usr/bin/env bash
# ensure-postgres.sh — idempotent "a PostgreSQL is reachable for server
# tests" step for every CI tier (ADR-0006 decision 8, #1318). The shipped
# substrate is PostgreSQL 18 (deploy/docker/Dockerfile.postgres); the server
# SQL is version-agnostic (13+), so a runner-native cluster on an older major
# still exercises the suites correctly.
#
# Exports YUZU_TEST_POSTGRES_DSN via $GITHUB_ENV (or prints it when run
# outside Actions, e.g. by the /test skill or a dev shell). Resolution
# order:
#
#   1. Pre-set YUZU_TEST_POSTGRES_DSN — runner-level/env override (the
#      documented hook for a self-hosted box with a bespoke native install;
#      see docs/ci-architecture.md "Postgres for server tests"). On a
#      multi-agent box (runner name ending "-<n>", e.g. the 4-runner
#      yuzu-weetam-windows pool) the pre-set DSN names the agent-0 cluster
#      and agent <n> uses port+<n> when that per-agent cluster answers —
#      one instance per agent, no cross-job contention (#2094). Falls back
#      to the shared pre-set DSN (with a ::warning) until the box is
#      provisioned with the extra clusters.
#   2. Docker available -> idempotent `yuzu-ci-postgres` container on
#      127.0.0.1:15432 (self-hosted Linux — the same boxes run the
#      docker-publish jobs, so docker is a given). Port 15432 deliberately
#      avoids colliding with any native cluster or UAT rig on 5432.
#      `--restart unless-stopped` + `docker start` makes this a one-time
#      cost per runner. Multi-agent boxes (yuzu-bigtam-linux pool) get a
#      container PER AGENT — `yuzu-ci-postgres-<n>` on 127.0.0.1:15440+<n>,
#      self-created on the agent's first job (#2094).
#   3. macOS (GHA-hosted, no docker): brew postgresql@18, throwaway
#      trust-auth cluster under $RUNNER_TEMP on port 15432.
#   4. Native cluster on 127.0.0.1:5432 (self-hosted Windows precondition —
#      PostgreSQL 16+ installed as a service with role yuzu / password yuzu
#      / database yuzu_test; bootstrap once per runner, see
#      docs/ci-architecture.md).
#   5. Nothing found -> ::error + exit 1.
#
# FATAL since #1320 PR 1: the pg substrate test suites ([pg] tags in the
# server suite) consume YUZU_TEST_POSTGRES_DSN and skip when it is unset —
# so a runner without a database would silently skip that coverage. A
# missing/unready Postgres now fails the job instead.
set -euo pipefail

SOFT_EXIT=1   # flipped 0->1 when #1320 PR 1 shipped the [pg] test suites

# Same pinned multi-arch image as deploy/docker/Dockerfile.postgres's base.
PG_IMAGE="postgres:18.4-bookworm@sha256:efef99e1558f86089bc84bece29208c0777a185ff717ec7fa288a652ce2d0adf"
CONTAINER="yuzu-ci-postgres"
DOCKER_PORT=15432
# Bump when the durability/-c tuning below changes: the docker container is
# persistent (--restart unless-stopped), so a container born before a tuning
# change keeps the OLD flags until recreated. The image-drift guard already
# recreates on a PG_IMAGE bump; this label makes a tuning bump recreate too,
# so fsync=off actually reaches runners that already have a container.
PG_TUNE_LABEL="v1-durability-off"

# ── Per-agent instance selection (#2094) ─────────────────────────────────
# Both self-hosted pools run 4 runner agents on ONE box (CLAUDE.md standing
# invariant), and a single shared Postgres is a cross-job contention
# multiplier: the WAL/fsync-heavy [pg] fixture traffic of concurrent jobs
# mutually DoSes their server suites (the 2026-07-12 Wee Tam 900 s
# server-suite timeouts). Pool runner names carry the agent index as a
# trailing "-<n>" (yuzu-weetam-windows-2, yuzu-bigtam-linux-0); derive it
# and give every agent its OWN instance — the database-shaped case of the
# fixed-port/named-object cross-JOB collision pattern (#1871). Single-agent
# boxes (yuzu-wsl2-linux) and GHA-hosted runners have no such suffix and
# keep the shared-instance behaviour.
AGENT_IDX=""
if [[ "${RUNNER_NAME:-}" =~ -([0-9]+)$ ]]; then
  AGENT_IDX=$((10#${BASH_REMATCH[1]}))
  if (( AGENT_IDX > 9 )); then
    # Pool agent indexes are single-digit; a larger trailing number (some
    # hosted-runner naming schemes) is not an agent index.
    AGENT_IDX=""
  fi
fi
# Disposable CI cluster -> durability OFF (fsync/synchronous_commit/
# full_page_writes). Every [pg] test does CREATE DATABASE ... TEMPLATE + DROP
# DATABASE WITH (FORCE) per case (~72 cases) — both fsync-heavy — so full
# durability makes the [pg] shard the slowest-scaling part of the suite,
# ~20x worse on Windows where fsync is dominant (the 2026-07-14 600s Windows
# TIMEOUTs). The DBs are throwaway; a crash just re-runs the job. fsync and
# full_page_writes are POSTMASTER params, so they must be set at the server
# (the -c flags here / postgresql.conf), not per-connection.
DOCKER_PG_ARGS=(-c fsync=off -c synchronous_commit=off -c full_page_writes=off)
if [[ -n "$AGENT_IDX" ]]; then
  # Container-per-agent on 15440+<n>: base deliberately OFF 15432/15433 so
  # agent 0 collides with neither a legacy shared container (15432) nor the
  # UAT postgres sidecar (15433) — port map in scripts/start-UAT.sh.
  CONTAINER="yuzu-ci-postgres-${AGENT_IDX}"
  DOCKER_PORT=$((15440 + AGENT_IDX))
  # Wee-Tam-parity connection headroom (#2096): the server suite's PgPool
  # fan-out can exhaust the postgres default of 100 (the CH-9 flake).
  DOCKER_PG_ARGS+=(-c max_connections=400)
fi

# NOTE: durability-off is applied SERVER-SIDE only (docker/brew `-c` flags
# below; the native Windows service via deploy/windows/Provision-Windows-Runner
# .ps1 or a one-off `ALTER SYSTEM SET fsync/synchronous_commit/full_page_writes
# = off` + reload). Do NOT inject it into the emitted DSN via the libpq
# `options` keyword: PgPool only injects its statement_timeout/lock_timeout
# GUCs "unless the conninfo sets its own `options`" (pg_pool.hpp), so a DSN-level
# `options=` silently disables those safety bounds — the [pg][hardening] test
# "PgPool injects statement_timeout and lock_timeout GUCs" catches it.
emit_dsn() {
  local dsn="$1" how="$2"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "YUZU_TEST_POSTGRES_DSN=${dsn}" >> "$GITHUB_ENV"
  fi
  # Always echo too — local invocations eval/grep this.
  echo "YUZU_TEST_POSTGRES_DSN=${dsn}"
  echo "ensure-postgres: ready (${how})" >&2
}

tcp_probe() { # host port — pure-bash, works in MSYS2 too
  local host="$1" port="$2"
  (exec 3<>"/dev/tcp/${host}/${port}") >/dev/null 2>&1
}

# PGOPTIONS is process-environment-level, not DSN content: pg_pool.cpp's
# conninfo_has_options_ gate checks getenv("PGOPTIONS") unconditionally,
# regardless of which of the 4 paths below built the connection string.
# A set PGOPTIONS would silently disable PgPool's statement_timeout/
# lock_timeout safety bounds even on the docker/brew/native paths, which
# never see a caller-supplied DSN - so this runs unconditionally, before
# path selection, not only inside the pre-set-DSN branch (path 1 below).
if [[ -n "${PGOPTIONS:-}" ]]; then
  echo "::error::ensure-postgres: PGOPTIONS must not be set in the job or runner machine environment (disables PgPool statement_timeout/lock_timeout safety bounds) - put durability settings in postgresql.conf via ALTER SYSTEM instead. See docs/ci-architecture.md 'Postgres for server tests'." >&2
  exit "$SOFT_EXIT"
fi

# ── 1. Pre-set DSN wins ──────────────────────────────────────────────────
if [[ -n "${YUZU_TEST_POSTGRES_DSN:-}" ]]; then
  # PgPool (pg_pool.cpp) only injects its statement_timeout/lock_timeout
  # safety-bound GUCs when PQconninfoParse finds no `options` keyword (the
  # PGOPTIONS half of that same gate is checked unconditionally above). An
  # `options=` in a pre-set DSN (URI query form OR keyword form) silently
  # disables those bounds (the [pg][hardening] test "PgPool injects
  # statement_timeout and lock_timeout GUCs"). This is the one path that
  # takes a caller-supplied DSN (paths 2-4 build DSNs from constants), so
  # gate it before the per-agent derivation below, which would otherwise
  # carry an unsafe `options=` straight into PA_DSN. DSN-literal match
  # only - an indirect `service=` naming a pg_service.conf section that
  # itself sets `options=` is out of scope for this string check. Case-
  # sensitive is intentional: libpq's conninfo_storeval (fe-connect.c)
  # matches keywords via a case-sensitive strcmp, so an "OPTIONS=" variant
  # isn't honored as the `options` keyword by libpq either. Keyword-form
  # conninfo allows whitespace around `=` (`options = -c ...` is valid
  # per libpq's conninfo_parse), so the `=` is matched with `[[:space:]]*`
  # in front, not a bare `=` - adversarial review v2 F1', reproduced
  # empirically against `options = '-c statement_timeout=0'`.
  if [[ "${YUZU_TEST_POSTGRES_DSN}" =~ (^|[?&[:space:]])options[[:space:]]*= ]]; then
    echo "::error::ensure-postgres: pre-set YUZU_TEST_POSTGRES_DSN must not set options= (disables PgPool statement_timeout/lock_timeout safety bounds) - put durability settings in postgresql.conf via ALTER SYSTEM instead. See docs/ci-architecture.md 'Postgres for server tests'." >&2
    exit "$SOFT_EXIT"
  fi
  # Per-agent derivation (#2094): on a multi-agent box the pre-set DSN
  # (machine env on Wee Tam) names the agent-0 cluster; agent <n> shifts
  # the port by <n> (Wee Tam: 5433 -> 5434..5436, provisioned by
  # deploy/windows/Provision-Windows-Runner.ps1). Probe before switching
  # and fall back LOUDLY to the shared DSN while a box has not been
  # provisioned with per-agent clusters yet — the cutover needs no flag
  # day, and the warning is the provisioning reminder.
  if [[ -n "$AGENT_IDX" && "$AGENT_IDX" != "0" \
        && "$YUZU_TEST_POSTGRES_DSN" =~ ^(.*@([^:/@]+)):([0-9]+)(/.*)$ ]]; then
    PA_HOST="${BASH_REMATCH[2]}"
    PA_PORT=$((BASH_REMATCH[3] + AGENT_IDX))
    PA_DSN="${BASH_REMATCH[1]}:${PA_PORT}${BASH_REMATCH[4]}"
    PA_HOW=""
    if command -v psql >/dev/null 2>&1; then
      # Authenticate the exact DSN we are about to export (same rationale
      # as path 4's SELECT 1 gate, PR #1334 S5).
      if psql "$PA_DSN" -tA -c 'SELECT 1' >/dev/null 2>&1; then
        PA_HOW="psql SELECT 1 verified"
      fi
    elif tcp_probe "$PA_HOST" "$PA_PORT"; then
      PA_HOW="TCP probe only — psql unavailable, credential unverified"
    fi
    if [[ -n "$PA_HOW" ]]; then
      emit_dsn "$PA_DSN" "pre-set runner env, per-agent port ${PA_PORT} for ${RUNNER_NAME} (${PA_HOW}; #2094)"
      exit 0
    fi
    echo "::warning::ensure-postgres: no per-agent Postgres on ${PA_HOST}:${PA_PORT} for ${RUNNER_NAME} — falling back to the SHARED pre-set DSN (cross-job contention multiplier, #2094). Provision the per-agent clusters (deploy/windows/Provision-Windows-Runner.ps1) to remove it." >&2
  fi
  emit_dsn "$YUZU_TEST_POSTGRES_DSN" "pre-set runner env"
  exit 0
fi

# ── 2. Docker (self-hosted Linux) ────────────────────────────────────────
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if command -v flock >/dev/null 2>&1; then
    # Lock name embeds the (possibly per-agent) container name, so agents
    # managing their own containers never serialize on each other (#2094).
    exec 9>"/tmp/${CONTAINER}.lock"
    if ! flock -w 120 9; then
      echo "::error::ensure-postgres: timed out waiting for /tmp/${CONTAINER}.lock — another runner may be stuck managing ${CONTAINER}" >&2
      exit "$SOFT_EXIT"
    fi
  else
    echo "::warning::ensure-postgres: flock not available; shared docker container lifecycle is not serialized" >&2
  fi
  # Digest-drift guard: the container is persistent (--restart
  # unless-stopped), so a PG_IMAGE pin bump would otherwise never reach
  # runners that already have one — tests would silently keep running the
  # old Postgres. Recreate when the recorded image differs.
  EXISTING_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null || true)"
  EXISTING_TUNE="$(docker inspect -f '{{index .Config.Labels "yuzu-pgtune"}}' "$CONTAINER" 2>/dev/null || true)"
  if [[ -n "$EXISTING_IMAGE" && ( "$EXISTING_IMAGE" != "$PG_IMAGE" || "$EXISTING_TUNE" != "$PG_TUNE_LABEL" ) ]]; then
    echo "ensure-postgres: ${CONTAINER} drift (image ${EXISTING_IMAGE} vs ${PG_IMAGE}, tune ${EXISTING_TUNE:-none} vs ${PG_TUNE_LABEL}) — recreating" >&2
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
      echo "::error::ensure-postgres: failed to remove stale ${CONTAINER} - old tuning still active. See docs/ci-architecture.md 'Postgres for server tests'." >&2
      exit "$SOFT_EXIT"
    fi
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != "true" ]]; then
    # ${arr[@]+...} guarded expansion: empty-array-safe under `set -u` on
    # bash 3.2 (macOS /bin/bash) too.
    docker start "$CONTAINER" >/dev/null 2>&1 || docker run -d \
      --name "$CONTAINER" \
      --label "yuzu-pgtune=${PG_TUNE_LABEL}" \
      --restart unless-stopped \
      -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e POSTGRES_DB=yuzu_test \
      -p "127.0.0.1:${DOCKER_PORT}:5432" \
      "$PG_IMAGE" ${DOCKER_PG_ARGS[@]+"${DOCKER_PG_ARGS[@]}"} >/dev/null
  fi
  # 120 s budget (60 × 2 s): a cold PG18 first boot runs the init scripts +
  # pgvector extension install, which on a loaded self-hosted runner can take
  # longer than the old 60 s (gov fjarvis).
  for _ in $(seq 1 60); do
    # -h 127.0.0.1: the init-phase temporary server is unix-socket-only,
    # so a TCP probe can't false-positive mid-init.
    if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U yuzu -d yuzu_test >/dev/null 2>&1; then
      emit_dsn "postgresql://yuzu:yuzu@127.0.0.1:${DOCKER_PORT}/yuzu_test" "docker container ${CONTAINER}"
      exit 0
    fi
    sleep 2
  done
  echo "::error::ensure-postgres: ${CONTAINER} container did not become ready in 120s — failing the job (SOFT_EXIT=1 since #1320 PR 1)" >&2
  exit "$SOFT_EXIT"
fi

# ── 3. GHA-hosted macOS — brew + throwaway cluster ───────────────────────
if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
  # Without a valid locale the macOS postmaster aborts with "postmaster
  # became multithreaded during startup" (CoreFoundation locale lookup
  # spawns a thread). Pin LC_ALL/LANG defensively — minimal shells (and
  # this script's own CI smoke test under `env -i`) hit it.
  export LC_ALL="${LC_ALL:-C}" LANG="${LANG:-C}"
  brew list postgresql@18 >/dev/null 2>&1 || brew install --quiet postgresql@18
  PGBIN="$(brew --prefix postgresql@18)/bin"
  PGDATA="${RUNNER_TEMP:-/tmp}/yuzu-ci-pgdata"
  PGLOG="${PGDATA}.log"
  if [[ ! -s "${PGDATA}/PG_VERSION" ]]; then
    # trust auth: throwaway per-job cluster on an ephemeral runner, bound
    # to loopback only.
    "$PGBIN/initdb" --username=yuzu --auth=trust --no-instructions -D "$PGDATA" >/dev/null
  fi
  if ! "$PGBIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; then
    # Durability off — throwaway per-job cluster (see DOCKER_PG_ARGS rationale).
    "$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGLOG" \
      -o "-p ${DOCKER_PORT} -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off -c full_page_writes=off" start >/dev/null
  fi
  for _ in $(seq 1 15); do
    if "$PGBIN/pg_isready" -h 127.0.0.1 -p "$DOCKER_PORT" -U yuzu >/dev/null 2>&1; then
      "$PGBIN/createdb" -h 127.0.0.1 -p "$DOCKER_PORT" -U yuzu yuzu_test 2>/dev/null || true
      emit_dsn "postgresql://yuzu@127.0.0.1:${DOCKER_PORT}/yuzu_test" "brew postgresql@18 cluster"
      exit 0
    fi
    sleep 2
  done
  echo "::error::ensure-postgres: brew postgresql@18 cluster did not become ready (log: ${PGLOG}) — failing the job (SOFT_EXIT=1 since #1320 PR 1)" >&2
  exit "$SOFT_EXIT"
fi

# ── 4. Native cluster on the conventional port (self-hosted Windows) ─────
if tcp_probe 127.0.0.1 5432; then
  # Convention documented in docs/ci-architecture.md: role yuzu / password
  # yuzu / db yuzu_test, created once at runner bootstrap. A bespoke setup
  # overrides via the pre-set-DSN path (1).
  NATIVE_DSN="postgresql://yuzu:yuzu@127.0.0.1:5432/yuzu_test"
  # A TCP listener alone proves nothing about the app credential — when
  # psql is on PATH, authenticate the exact DSN we are about to export
  # (PR #1334 review, S5). Fall back to the bare TCP probe + warning when
  # psql is unavailable.
  if command -v psql >/dev/null 2>&1; then
    if psql "$NATIVE_DSN" -tA -c 'SELECT 1' >/dev/null 2>&1; then
      emit_dsn "$NATIVE_DSN" "native cluster on 5432 (psql SELECT 1 verified)"
      exit 0
    fi
    echo "::error::ensure-postgres: something listens on 127.0.0.1:5432 but the conventional DSN failed 'psql SELECT 1' — failing the job. Fix the runner bootstrap (role yuzu / password yuzu / db yuzu_test) or pre-set YUZU_TEST_POSTGRES_DSN." >&2
    exit "$SOFT_EXIT"
  fi
  echo "::warning::ensure-postgres: psql not on PATH — exporting the conventional DSN on a TCP probe only (credential UNVERIFIED). Install psql on the runner for an authenticated readiness check." >&2
  emit_dsn "$NATIVE_DSN" "native cluster on 5432 (TCP probe only — psql unavailable)"
  exit 0
fi

# ── 5. Nothing available ─────────────────────────────────────────────────
echo "::error::ensure-postgres: no Postgres available (no docker, no brew, nothing on 127.0.0.1:5432) — failing the job: the [pg] server tests require a database (SOFT_EXIT=1 since #1320 PR 1). See docs/ci-architecture.md 'Postgres for server tests'." >&2
exit "$SOFT_EXIT"
