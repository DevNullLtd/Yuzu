#!/bin/bash
# patroni-entrypoint.sh — render Patroni config from the container environment
# and launch Patroni as the `postgres` OS user (WS-7, ADR-2002 §11).
#
# Generates the config here (rather than shipping a static file) so the
# durability profile and per-node identity are driven entirely by env vars —
# the same image is every node in the cluster.
#
# Env contract (compose supplies these):
#   PATRONI_SCOPE            cluster name (all nodes share it)          [required]
#   PATRONI_NAME             this node's unique name (e.g. pg1)         [required]
#   PATRONI_CONNECT_HOST     hostname other nodes/HAProxy reach us on   [default: $PATRONI_NAME]
#   ETCD_HOSTS               comma-list host:port of the etcd cluster   [required]
#   POSTGRES_USER            bootstrap superuser name                   [default: postgres]
#   POSTGRES_PASSWORD        bootstrap superuser password               [required]
#   YUZU_PG_REPLICATION_PASSWORD  replication-role password             [required]
#   YUZU_DB_USER/NAME/PASSWORD    app role/db/password — consumed by the
#                            inherited post_init init script, NOT here  [required]
#   YUZU_PG_RESERVED_CONNECTIONS  slots reserved for the app role ahead of every
#                            other client (HA WS-8, #4943); rendered into the
#                            bootstrap parameters here (Patroni owns
#                            postgresql.conf) while the inherited init script
#                            does the GRANT. Size: N_servers x (pool + 2)
#                                                                    [default: 40]
#   YUZU_PG_DURABILITY       quorum3 (default) | sync2 | async          [default: quorum3]
#   YUZU_PG_SYNC_STRICT      fail-closed on total standby loss          [default: false]
#   YUZU_PG_TRUST_CIDR       CIDR allowed host (TCP) connections        [default: 0.0.0.0/0]
set -euo pipefail

: "${PATRONI_SCOPE:?PATRONI_SCOPE is required}"
: "${PATRONI_NAME:?PATRONI_NAME is required}"
: "${ETCD_HOSTS:?ETCD_HOSTS is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${YUZU_PG_REPLICATION_PASSWORD:?YUZU_PG_REPLICATION_PASSWORD is required}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
PATRONI_CONNECT_HOST="${PATRONI_CONNECT_HOST:-$PATRONI_NAME}"
YUZU_PG_RESERVED_CONNECTIONS="${YUZU_PG_RESERVED_CONNECTIONS:-40}"
if ! [[ "${YUZU_PG_RESERVED_CONNECTIONS}" =~ ^[0-9]{1,6}$ ]]; then
    echo "patroni-entrypoint: YUZU_PG_RESERVED_CONNECTIONS must be a non-negative integer (got '${YUZU_PG_RESERVED_CONNECTIONS}')" >&2
    exit 1
fi
# The bootstrap max_connections this cluster renders with, and Postgres's
# superuser_reserved_connections default (not overridden below) — ONE shell
# variable each, substituted into the YAML template further down AND used in
# the bound check here, so the two can never drift apart (Gate 8 re-review,
# #4943: two independent literals 86 lines apart was the exact drift the
# clock-guarded-retention/dispatch-confined-arms rows warn about elsewhere —
# a future edit to one without the other would silently reopen the gap).
readonly PATRONI_MAX_CONNECTIONS=200
readonly PATRONI_SUPERUSER_RESERVED_CONNECTIONS=3
# A value at or past (max_connections - superuser_reserved_connections) leaves
# ZERO slots any ordinary (non-privileged) client can ever use, not merely
# under load (security-guardian, Gate 2 finding #1). No server is running yet
# at render time, so this is a static check against the two constants above,
# not a live query (contrast the single-node script's SHOW-based check).
if (( YUZU_PG_RESERVED_CONNECTIONS >= PATRONI_MAX_CONNECTIONS - PATRONI_SUPERUSER_RESERVED_CONNECTIONS )); then
    echo "patroni-entrypoint: YUZU_PG_RESERVED_CONNECTIONS=${YUZU_PG_RESERVED_CONNECTIONS} is >= max_connections(${PATRONI_MAX_CONNECTIONS}) - superuser_reserved_connections(${PATRONI_SUPERUSER_RESERVED_CONNECTIONS}) = $(( PATRONI_MAX_CONNECTIONS - PATRONI_SUPERUSER_RESERVED_CONNECTIONS ))" >&2
    exit 1
fi
YUZU_PG_DURABILITY="${YUZU_PG_DURABILITY:-quorum3}"
# CIDR permitted to open host (TCP) connections — replication + app. Defaults
# OPEN so a bring-your-own network works out of the box; the shipped compose
# pins it to the cluster subnet (defence in depth behind scram + the container
# network boundary — the compose publishes no host ports).
YUZU_PG_TRUST_CIDR="${YUZU_PG_TRUST_CIDR:-0.0.0.0/0}"
[[ "${YUZU_PG_TRUST_CIDR}" == "0.0.0.0/0" ]] && \
  echo "patroni-entrypoint: WARNING — YUZU_PG_TRUST_CIDR is open (0.0.0.0/0); host connections are scram-authed but NOT network-scoped. The shipped compose pins the cluster subnet; set YUZU_PG_TRUST_CIDR for a bring-your-own network." >&2

# YAML-quote a scalar so a password containing YAML-significant characters
# (: # newline etc.) cannot break the generated config or inject keys. A single-
# quoted YAML scalar escapes an embedded quote by doubling it.
yq_scalar() { printf "'%s'" "${1//\'/\'\'}"; }
POSTGRES_PASSWORD_Y="$(yq_scalar "${POSTGRES_PASSWORD}")"
REPL_PASSWORD_Y="$(yq_scalar "${YUZU_PG_REPLICATION_PASSWORD}")"

# PGDATA at the base image's version-pinned subdir; the PARENT is the mounted
# volume (never mount .../data — PG18 reads it as an un-migrated upgrade).
PGDATA_DIR="/var/lib/postgresql/18/docker"
PG_BIN_DIR="/usr/lib/postgresql/18/bin"

# ── Durability profile → Patroni synchronous settings (ADR-2002 §11) ──────
# quorum3 (default): ANY 1 of the standbys must confirm → RPO=0 while ≥1 sync
#   standby is available (the normal case, incl. after a single failover).
# sync2: FIRST 1 — one designated sync standby; single-standby loss stalls
#   writes (the §11 footgun; offered, not default).
# async: no synchronous standby — max availability, bounded data loss.
#
# synchronous_mode_strict (YUZU_PG_SYNC_STRICT, default FALSE): what happens when
# NO eligible sync standby remains (total standby loss — a double failure on a
# 3-node cluster). OFF (default): Patroni clears synchronous_standby_names and
# the lone primary continues in DEGRADED async mode — availability over
# durability, a bounded-loss window until a standby returns. ON: the primary
# BLOCKS writes (fail-closed on quorum loss, ADR-2002 §11 / ADR-0007 intent) —
# but this can also EXTEND post-failover write-unavailability while the surviving
# standby re-establishes sync, so VALIDATE failover timing in your environment
# before enabling (kickoff testing measured a materially longer write-resume with
# it on; see docs/ha-postgres-ws7-plan.md). Off by default so single-failover
# recovery stays fast and reliable. async is never strict.
YUZU_PG_SYNC_STRICT="${YUZU_PG_SYNC_STRICT:-false}"
case "${YUZU_PG_DURABILITY}" in
  quorum3) SYNC_MODE="quorum"; SYNC_COUNT=1; SYNC_STRICT="${YUZU_PG_SYNC_STRICT}" ;;
  sync2)   SYNC_MODE="true";   SYNC_COUNT=1; SYNC_STRICT="${YUZU_PG_SYNC_STRICT}" ;;
  async)   SYNC_MODE="false";  SYNC_COUNT=0; SYNC_STRICT="false" ;;
  *) echo "patroni-entrypoint: unknown YUZU_PG_DURABILITY='${YUZU_PG_DURABILITY}' (want quorum3|sync2|async)" >&2; exit 1 ;;
esac

# Build the etcd3 hosts YAML list from the comma-separated env.
ETCD_HOSTS_YAML=""
IFS=',' read -ra _hosts <<< "${ETCD_HOSTS}"
for h in "${_hosts[@]}"; do
  ETCD_HOSTS_YAML+="    - ${h}"$'\n'
done

CONFIG=/run/patroni/patroni.yml
mkdir -p /run/patroni

cat > "${CONFIG}" <<EOF
scope: ${PATRONI_SCOPE}
name: ${PATRONI_NAME}

restapi:
  listen: 0.0.0.0:8008
  connect_address: ${PATRONI_CONNECT_HOST}:8008

etcd3:
  hosts:
$(printf '%s' "${ETCD_HOSTS_YAML}")

bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 10
    maximum_lag_on_failover: 1048576
    synchronous_mode: ${SYNC_MODE}
    synchronous_mode_strict: ${SYNC_STRICT}
    synchronous_node_count: ${SYNC_COUNT}
    postgresql:
      use_pg_rewind: true
      parameters:
        # Keep aligned with the single-node substrate's operational envelope.
        max_connections: ${PATRONI_MAX_CONNECTIONS}
        # Slots only pg_use_reserved_connections members (the app role, granted
        # by post_init) may take once the free count drops this low — so a
        # foreign client can never hold the slot a server's /readyz probe needs
        # to reconnect (HA WS-8, #4943). N_servers x (pool 16 + 2), two servers.
        reserved_connections: ${YUZU_PG_RESERVED_CONNECTIONS}
        wal_level: replica
        hot_standby: "on"
        max_wal_senders: 10
        max_replication_slots: 10
        wal_keep_size: 512MB
        password_encryption: scram-sha-256
  # initdb options — data checksums are non-negotiable for an HA store (torn-page
  # / corruption detection across replicas).
  initdb:
    - encoding: UTF8
    - data-checksums
  # pg_hba the cluster bootstraps with. Local trust is scoped to the SUPERUSER
  # only (the post_init hook runs the inherited app-init over the unix socket);
  # every other principal — local or TCP — needs scram. Host connections are
  # scoped to YUZU_PG_TRUST_CIDR, with an explicit reject fallthrough.
  pg_hba:
    - local all ${POSTGRES_USER} trust
    - local all all scram-sha-256
    - host replication replicator ${YUZU_PG_TRUST_CIDR} scram-sha-256
    - host all all ${YUZU_PG_TRUST_CIDR} scram-sha-256
    - host all all 0.0.0.0/0 reject
    - host all all ::/0 reject
  # Re-invoke the SHIPPED first-boot init (same script as the single-node
  # image) on the bootstrap primary — creates the app role/db + pgvector with
  # the byte-identical two-password contract. Runs once, cluster-wide.
  post_init: /docker-entrypoint-initdb.d/10-create-yuzu-role-db.sh

postgresql:
  listen: 0.0.0.0:5432
  connect_address: ${PATRONI_CONNECT_HOST}:5432
  data_dir: ${PGDATA_DIR}
  bin_dir: ${PG_BIN_DIR}
  pgpass: /tmp/pgpass
  authentication:
    superuser:
      username: ${POSTGRES_USER}
      password: ${POSTGRES_PASSWORD_Y}
    replication:
      username: replicator
      password: ${REPL_PASSWORD_Y}
    rewind:
      username: ${POSTGRES_USER}
      password: ${POSTGRES_PASSWORD_Y}
  parameters:
    unix_socket_directories: /var/run/postgresql

tags:
  nofailover: false
  noloadbalance: false
  clonefrom: false
  nosync: false
EOF

# The generated config holds three plaintext passwords — keep it owner-only, and
# fail fast if it is not valid YAML (e.g. a password the quoting above somehow
# did not tame) rather than launching Patroni against a broken file. The venv's
# python has PyYAML (a Patroni dependency).
chmod 600 "${CONFIG}"
python -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' "${CONFIG}" \
  || { echo "patroni-entrypoint: generated ${CONFIG} is not valid YAML — refusing to start" >&2; exit 1; }

# Ownership: the mounted volume parent + runtime dirs must be writable by the
# postgres OS user that Patroni (and PG) run as.
mkdir -p "$(dirname "${PGDATA_DIR}")" /var/run/postgresql
chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql /run/patroni
chmod 700 "$(dirname "${PGDATA_DIR}")" || true

echo "patroni-entrypoint: node '${PATRONI_NAME}' scope '${PATRONI_SCOPE}' durability '${YUZU_PG_DURABILITY}' (sync_mode=${SYNC_MODE}, count=${SYNC_COUNT})"
exec gosu postgres patroni "${CONFIG}"
