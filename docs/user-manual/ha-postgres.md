# High-Availability PostgreSQL

Yuzu stores all server state in PostgreSQL (ADR-0006/0007) and **fails closed** if it cannot reach
it. A single Postgres is a fully supported deployment, but it is a single point of failure: if that
one database is lost, the server stops. This page describes Yuzu's **opt-in High-Availability
Postgres** profile, which removes that single point of failure with automatic failover.

> HA-Postgres is the **storage** availability axis. It is independent of server-tier HA (running
> multiple server replicas). You can run either without the other. See ADR-2002 for the whole
> picture.

> ⚠️ **Before any customer-facing use, read [Production requirements](#production-requirements-read-before-deploying).**
> The shipped Compose profile runs a **single etcd** and a **single HAProxy** — both single points of
> failure on their own — and is host-HA only when its three Postgres nodes sit on distinct hosts. On
> one Docker host it is for **development and testing**. Migrating an existing single-Postgres
> deployment onto this profile (data cutover) is **not yet documented** — it is delivered separately
> (WS-12); until then, stand this up on a fresh deployment or contact support.

## What you get

- **Automatic failover.** Three PostgreSQL nodes are managed by [Patroni](https://patroni.readthedocs.io/),
  which elects a primary and promotes a standby automatically if the primary is lost. End-to-end
  recovery time (RTO) — from the primary dying to writes flowing again through the endpoint — is
  **~30–40 seconds** with the shipped defaults (Patroni's 30 s leader-lock TTL plus HAProxy
  re-routing). This is measured by the failover smoke test, not just claimed. It is tunable lower by
  reducing Patroni's `ttl`/`loop_wait`, at the cost of sensitivity to transient network blips.
- **No acknowledged-write loss (RPO = 0) while a synchronous quorum holds.** The default profile
  keeps two synchronous standbys and requires at least one to confirm every commit, so a primary
  loss cannot lose an acknowledged write.
- **No server change.** The server connects to the cluster through the same DSN it always used — the
  HA layer is transparent to it.

## Two ways to run it

### 1. Shipped profile (Patroni + etcd + HAProxy)

Yuzu ships a containerised cluster you can select at deploy time:
`deploy/docker/docker-compose.ha-postgres.yml`. It runs:

- **3 × PostgreSQL** nodes (the `yuzu-postgres` substrate + Patroni), replicating synchronously.
- **etcd**, the distributed configuration store Patroni uses for leader election.
- **HAProxy**, which routes the server's connections to whichever node is currently the primary. It
  presents the network alias **`postgres:5432`**, so the server's existing
  `YUZU_POSTGRES_DSN: postgresql://…@postgres:5432/yuzu` is **unchanged**.

Bring it up and prove failover end-to-end:

```bash
bash scripts/ha/ha-pg-smoke.sh
```

The smoke test forms the cluster, writes committed rows through the server-facing endpoint, kills the
primary, and verifies every acknowledged write survives the failover.

### 2. Bring your own (managed service or existing Patroni)

If you run PostgreSQL HA already — a managed service (RDS/Cloud SQL/Azure), your own Patroni, or any
primary-following router — point Yuzu at it with **no shipped cluster**. Two DSN shapes work, both
transparent to the server:

- **A single VIP / endpoint** that always resolves to the current primary (a managed endpoint, or
  your own HAProxy): `YUZU_POSTGRES_DSN=postgresql://user:pw@your-endpoint:5432/yuzu`.
- **A libpq multi-host DSN** with client-side primary discovery:
  `YUZU_POSTGRES_DSN="postgresql://user:pw@n1:5432,n2:5432,n3:5432/yuzu?target_session_attrs=read-write"`.
  libpq tries each host and selects the read-write one; on failover it re-resolves on reconnect.

## Durability profiles

Selected with `YUZU_PG_DURABILITY` on the Postgres nodes:

| Profile | Meaning | Write availability | Data loss on primary failure |
|---|---|---|---|
| **`quorum3`** *(default)* | 1 primary + 2 sync standbys; **any 1** standby must confirm each commit | Writes continue while **at least one** standby is up | **None** (RPO = 0) while a standby is up |
| `sync2` | 1 primary + 1 designated sync standby | Writes **stall** if that one standby is lost | None while the standby is up |
| `async` | No synchronous standby | Maximum — writes never wait on a standby | Up to the replication lag at the moment of failure |

**Why `quorum3` is the default:** it gives RPO = 0 without the `sync2` footgun (losing the single
standby stalls *all* writes). With `quorum3`, **RPO = 0 holds while at least one synchronous standby
is available** — including after an ordinary single-node failover.

**Behaviour on total standby loss** (both standbys gone — a double failure on a 3-node cluster) is
**selectable** via `YUZU_PG_SYNC_STRICT`:

- **`false` (default)** — the lone primary continues in **degraded async mode**: it keeps accepting
  writes (availability over durability), opening a data-loss window (bounded by the write rate over the
  degraded interval, until a standby returns). Single-node failover recovers quickly and reliably.
  **This degrade is currently unsignalled** — Prometheus HA-state metrics land in WS-11, so until then
  poll Patroni's REST (`/cluster`, `synchronous_standby_names`) to detect it, or run `strict` if a
  silent async window is unacceptable.
- **`true`** — the primary **blocks writes** when no synchronous standby is available (fail-closed on
  quorum loss — the ADR-2002 §11 / ADR-0007 intent; it never acknowledges a write it cannot protect).
  **Validate failover timing before enabling:** kickoff testing measured a materially longer time for
  writes to resume after even a *single* failover with strict mode on (the promoted primary blocks
  until its surviving standby re-establishes synchronous replication). It is off by default so that
  ordinary failover stays fast; enable it where a bounded-loss window is unacceptable and the extra
  failover latency is acceptable.

> **Set the profile before first boot.** `YUZU_PG_DURABILITY` is applied at cluster
> **initialization** (it seeds Patroni's DCS `bootstrap.dcs`). Changing it on an already-initialized
> cluster has no effect through this variable — adjust a running cluster through Patroni's config API
> (`patronictl edit-config`), or re-initialize.

## Production requirements (read before deploying)

The shipped Compose profile is convenient but Compose alone cannot make a deployment
production-grade. You **must**:

1. **Run a 3-node etcd cluster**, not the single etcd node the dev profile starts. A single etcd is
   itself a single point of failure for leader election.
2. **Place the three Postgres nodes on distinct hosts / failure domains.** Compose pins containers,
   not hosts — co-locating all three on one machine voids the whole guarantee. On a single Docker
   host the profile is for testing only.
3. **Supply real, distinct secrets** for all three roles: the superuser password
   (`YUZU_SUPERUSER_PASSWORD`), the application role password (`YUZU_DB_PASSWORD`), and the
   replication password (`YUZU_PG_REPLICATION_PASSWORD`). These are **required** — the profile ships
   with no default passwords — and the application-role init **refuses to run** if the app password
   equals the superuser password. Prefer Docker secrets or an `.env` file over inline values.
4. **Run HAProxy redundantly.** The shipped profile runs a single HAProxy — itself a single point of
   failure in front of the cluster. Run it behind a VIP (e.g. keepalived), or use the libpq multi-host
   DSN (the "Bring your own" option above) so a lost HAProxy does not take the database offline.
5. **Harden the control plane before any untrusted network.** As shipped, the coordination services
   are **unauthenticated** and reachable only from within the cluster's Docker network (the compose
   publishes **no host ports**): **etcd** (`:2379`, no auth/TLS) and each node's **Patroni REST API**
   (`:8008`, no auth) — and Patroni REST exposes *mutating* endpoints (`/switchover`, `/failover`,
   `/restart`, config changes), so a compromised peer container on that network can drive the cluster.
   Postgres and replication traffic are likewise plaintext, and `pg_hba` host rules are scoped to the
   cluster subnet (`YUZU_PG_TRUST_CIDR`). Before running across hosts or on a shared network, enable
   etcd client/peer TLS + auth, Patroni REST auth/TLS, and `hostssl` for Postgres, and segment etcd +
   the PG nodes onto an `internal` network behind HAProxy.

## What the server experiences during a failover

- **Bounded, not instant.** In-flight queries against the lost primary fail; the server's connection
  pool bounds this (10 s connect / 30 s statement timeouts, TCP keepalives) and does not hang. Once
  HAProxy re-points at the new primary — within one health-check interval — new connections succeed.
- **A brief burst of errors.** Until the connection-pool failover-hardening (WS-7 slice 2) lands, the
  first request on each stale-cached connection after a failover returns an error before the pool
  reconnects. These are transient — a retry succeeds — and are bounded by the RTO above. Operators
  running behind the agentic/REST API should expect a short window of 5xx responses during the
  ~30–40 s failover, not a sustained outage.
- **`/readyz` goes red on every server replica for the failover, then green.** Each replica's
  reachability probe (HA WS-8) sees the old primary go away — or, briefly, reaches a node that is
  still a standby — and reports not ready until it reaches the new primary; recovery is one
  successful probe (about 2 s). A load balancer health-checking `/readyz` stops routing during
  that window; one that fails open when all backends are down keeps forwarding and gets `503`s.
  The probe drops its connection whenever it lands on a server that refuses writes, so a proxy,
  DNS name or read-any port that sends a *new* connection to a standby cannot pin it there. With a
  multi-host DSN (`host=n1,n2,n3`; the server requires `target_session_attrs=read-write` there and
  adds it when absent) libpq walks the hosts for the probe exactly as for the pool, and the probe gives
  each host its own deadline (the pool's `connect_timeout`, 10 s unless you set one), so a frozen
  first host costs one timeout instead of holding the probe; with `connect_timeout=0` it does not move
  on, because the pool would not either. `load_balance_hosts` is refused at startup — in the DSN, the environment or a service file.
  List the Postgres servers themselves, not a pooler per node: a pooler (pgbouncer) can keep reporting
  a demoted node as writable to libpq and keeps its server connections open across the demotion.
  One host name that resolves to several addresses: a silent address makes the probe give up that
  name's other addresses (the pool would try them), so list the addresses as hosts instead.

## Backup and disaster recovery

Point-in-time recovery (PITR) and WAL archiving under HA-Postgres are delivered separately (WS-12).
This profile provides **availability** (automatic failover), which is not a substitute for backups —
a logical error (a bad migration, an accidental delete) replicates to every node. Until the WS-12
runbook lands, continue to take backups per your existing disaster-recovery process.

## Monitoring

- **HAProxy stats** are bound to `127.0.0.1:7000` inside the haproxy container (which node is primary,
  backend up/down) — reach them with `docker exec yuzu-ha-haproxy wget -qO- http://127.0.0.1:7000/`.
  They are container-local so peer containers cannot read the backend topology.
- **Patroni REST API** on each node's port `8008`: `GET /primary` (200 on the leader), `GET /replica`
  (200 on a running replica), `GET /health`, `GET /cluster` (full topology).
- Prometheus metrics for leader identity, replica lag, and quorum state are delivered separately
  (WS-11).
