# UAT Environment (Server ↔ Gateway ↔ Agent)

Reference for the dev-facing rigs that stand up the full Yuzu stack, the port
map, and gateway command forwarding.

> Routed out of `CLAUDE.md`. The `release-deploy` agent loads this doc on any
> compose / UAT-script change. The Cedar & Vale sales demo has its own full
> runbook at `docs/demo-environment.md`.

A cross-platform UAT script at `scripts/start-UAT.sh` (Linux + macOS) stands up the full stack, verifies connectivity, and runs command round-trip tests. The historical `scripts/linux-start-UAT.sh` name is kept as a thin shim that execs the canonical script. Usage:

```bash
bash scripts/start-UAT.sh          # start + verify (6 automated tests)
bash scripts/start-UAT.sh stop     # kill all
bash scripts/start-UAT.sh status   # show running processes
```

**Server tier = (server + postgres) pair.** Under the Postgres substrate (ADR-0006, #1320) the deployable stack is `(Server + Postgres) → Gateway → Agent` — every rig that boots the server tier also carries a PostgreSQL instance. The native rig runs a **postgres sidecar container** (`yuzu-native-uat-postgres` — distinct from the full-uat compose's `yuzu-uat-postgres`, since the native teardown force-removes it; image `yuzu-postgres:local` built from `deploy/docker/Dockerfile.postgres` on first use) on loopback `:15433` with per-run random credentials (superuser ≠ app role, per the #1334 init contract); the DSN is exported to the server as `YUZU_POSTGRES_DSN` and saved to `/tmp/yuzu-uat/postgres-dsn` (0600). The viz-UAT and demo rigs get their postgres as a compose service. Until #1320 PR 3 lands the fail-closed boot, a missing docker/sidecar is a **warning, not a failure** (`PG_SOFT_FAIL=1` in the script — flip with that PR). Host port 15433 deliberately avoids `5432` (local clusters), `5433` (dev pg-canary convention), `15432` (yuzu-ci-postgres), and `15440`–`15449` (per-agent `yuzu-ci-postgres-<n>` CI containers, #2094).

## viz-UAT (container-based, feat/viz-engine ladder)

`scripts/start-viz-uat.sh` stands up a three-container Docker stack (server + gateway + agent) for the visualization feature ladder. **Cannot run alongside `start-UAT.sh`** — both bind host ports 8080 *and* 50051. Auto-detects arm64 vs amd64 and sets `--build-arg TRIPLET` accordingly; default `x64-linux` preserves the `release.yml` path. The launcher exports `VIZ_UAT_CONFIG` (absolute path to a generated `yuzu-server.cfg`); do not invoke `docker compose -f docker-compose.viz-uat.yml up` directly. State dir `/tmp/yuzu-viz-uat/`; scale agents with `VIZ_UAT_AGENTS=N`. Set `VIZ_UAT_AGENT_MODE=vm` to skip the in-container agent and print the enrollment token + host-exposed gateway address for running a native `yuzu-agent` on an OrbStack VM / bare-metal host — needed for PR 8+ visuals that depend on real loopback workloads. `VIZ_UAT_AGENT_MODE=none` skips agent startup entirely. **Note:** `scripts/start-UAT.sh` (the native, non-container UAT) force-wipes `/tmp/yuzu-uat/` on each start to work around a stale-DB session-auth bug (#947); do not remove that wipe without first closing the issue. See `bash scripts/start-viz-uat.sh --help` for full usage.

## Cedar & Vale demo environment (release-pinned, sales)

`scripts/start-demo.sh` stands up a three-tier **chiselled** Docker stack (server + gateway + N agent replicas) from release-pinned GHCR images. **Cannot run alongside `start-viz-uat.sh` or `start-UAT.sh`** — all three bind host ports 8080 and 50051 (the launcher pre-checks and refuses to start if they are busy). Clean-start by default (wipes `/tmp/yuzu-demo/` + compose volumes); `--keep` preserves state. Distinct from the viz-UAT rig. The **agent-bundle** delivery image (`docs/agent-bundle.md`, `scripts/build-agent-bundle.sh`) ships the agent for `linux-x64` / `windows-x64` / `macos-arm64` to design partners who can only `docker pull` — published + cosign-signed + SBOM'd by the `docker-publish-agent-bundle` release job. Full runbook: `docs/demo-environment.md`.

## Port assignments

Server and gateway defaults do not conflict — all three components can run on the same box without overrides:

| Port | Component | Purpose |
|------|-----------|---------|
| 8080 | Server | Web dashboard + REST API |
| 50051 | Server | Agent gRPC (direct connections) |
| 50052 | Server | Management gRPC |
| 50055 | Server | Gateway upstream (registration, heartbeats) |
| 50051 | Gateway | Agent-facing gRPC (agents connect here) |
| 50063 | Gateway | Management/command forwarding (server sends commands here) |
| 8081 | Gateway | Health/readiness (`/healthz`, `/readyz`) |
| 9568 | Gateway | Prometheus metrics |
| 15433 | Postgres sidecar | Native-rig `yuzu-native-uat-postgres` container, loopback-published → container 5432 (server tier's substrate pair; ADR-0006/#1320) |

## Gateway command forwarding

The gateway's primary function is **command fanout** — relaying commands from the server to potentially millions of agents and aggregating responses. This requires three server flags:

1. **`--gateway-upstream 0.0.0.0:50055`** — Enables the `GatewayUpstream` gRPC service so the gateway can proxy agent registrations and batch heartbeats to the server.
2. **`--gateway-mode`** — Subscribe stream peer-mismatch validation accepts the agent's Register peer IP (default rule) **OR** an IP previously recorded in the trusted-gateway peer set via `GatewayUpstreamServiceImpl::ProxyRegister` (W1.3 / #826). Entries are noted only on a successful enrollment branch and expire after 1h (LRU-capped at 1024 entries). Without `--gateway-mode` the trusted-set lookup is skipped — direct-connect agents only ever match their Register peer. Layered defence note: this rule scopes Subscribe to known gateway IPs but does NOT defend against a sniffed `session_id` presented from inside the gateway's IP space; the agent_id↔session binding from W1.4 (#827) is the layer that closes that.
3. **`--gateway-command-addr localhost:50063`** — Points the server at the gateway's `ManagementService` for command forwarding. Without this, commands to gateway-connected agents are queued in `gw_pending_` but never forwarded. The server calls `SendCommand` (server-streaming RPC) on this address; the gateway fans out to agents and streams responses back.

`--trusted-nat-cidr <cidr>[,…]` (`Config::trusted_nat_cidrs`, #1128) is the direct-connect analogue of `--gateway-mode`'s trusted-IP relaxation: when a direct agent's Register and Subscribe source IPs both fall inside one declared CIDR (multi-egress NAT / proxy pool / CG-NAT / SD-WAN), the per-session peer-IP mismatch is downgraded to *advisory* (audit `result="ok" outcome=advisory` + `yuzu_grpc_subscribe_peer_advisory_total`) instead of rejected. mTLS-identity match does the same downgrade but is **opt-in** via `--nat-trust-mtls-identity` (`Config::nat_trust_mtls_identity`, default off) — it is a session-replay bypass under a shared fleet-wide client cert, so it requires the operator to affirm per-agent certs (gov UP-2). Strict exact-match stays the default; mismatches outside both accommodations still reject; an empty extracted IP always rejects (#826). The pure decision is `AgentServiceImpl::evaluate_peer_binding`; gateway origin-IP attribution rides `RegisterRequest.gateway_observed_peer` (#1064, server-side consumed; gateway population is a follow-up — grpcbox can't see the direct transport peer, QUIC #376 will). See `docs/auth-architecture.md` "Per-session peer binding and NAT-aware relaxation".

The dispatch flow in `agent_registry.cpp` `send_to()`:
- Agent has a local Subscribe stream → write directly (direct-connect agents)
- Agent has a `gateway_node` but no local stream → queue to `gw_pending_` for gateway forwarding
- `forward_gateway_pending()` drains the queue via `gw_mgmt_stub_->SendCommand()`

The gateway uses port range 5006x (vs server's 5005x); `gateway/config/sys.config` and `grpcbox` `listen_opts` are configured independently and must match. UAT credentials: fresh `yuzu-server.cfg` with PBKDF2-SHA256 hashed `admin` / `adminpassword1` per run; state lives under `/tmp/yuzu-uat/` and is wiped on each start.
