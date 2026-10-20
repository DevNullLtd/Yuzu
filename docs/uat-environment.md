# UAT Environment (Server ↔ Gateway ↔ Agent)

For an already installed signed macOS agent, use the non-restarting, single-target
check in [macOS development foundation](macos-development-foundation.md). Do not
restart a retained UAT stack merely to inspect it.

Reference for the dev-facing rigs that stand up the full Yuzu stack, the port
map, and gateway command forwarding.

> Routed out of `CLAUDE.md`. The `release-deploy` agent loads this doc on any
> compose / UAT-script change. The Cedar & Vale sales demo has its own full
> runbook at `docs/demo-environment.md`.

A cross-platform UAT script at `scripts/start-UAT.sh` (Linux + macOS) stands up the full stack, verifies connectivity, and runs command round-trip tests. The historical `scripts/linux-start-UAT.sh` name is kept as a thin shim that execs the canonical script. Usage:

```bash
bash scripts/start-UAT.sh          # start + verify (6 automated tests)
bash scripts/start-UAT.sh stop     # stop the processes this script started
bash scripts/start-UAT.sh status   # show running processes
```

`start` and `stop` signal only PIDs recorded in `/tmp/yuzu-uat/pids/` at spawn (the PID, the launched binary path and the process start time). Each is checked against that recorded path and start time before it is signalled, so a stack this script started from any worktree is replaced, while a recycled PID is never touched. Records that are not owned by you, or that sit in a directory writable by others, are ignored (never signalled, never deleted). A UAT port held by anything else (another rig, a stray process) is named via `lsof` where available and `start` and `stop` refuse (exit 1) without touching the Postgres sidecar (in sidecar mode the same refusal applies when host port 15433 stays held after the sidecar is removed; with `YUZU_UAT_PG_DSN` set there is no sidecar and :15433 is not checked); it never kills by command-line match (#5333). Stop the owning stack from the session that owns it. A recorded process that survives SIGKILL (for example `--as-user`'s root-owned sudo parent without a warm `sudo -v`) keeps its record, and `start`/`stop` exit 1 until it is stopped by hand. If the records are lost (for example `/tmp` was wiped), including a stack started by a pre-#5333 version of this script, which has no records, stop the stack by hand: `kill` the PIDs `lsof` shows on the UAT ports and the agent, which has no port (list it read-only with `ps -wwaxo pid=,command= | grep -F -- "--data-dir /tmp/yuzu-uat/agent-data"`, confirm the full command line is this stack's `yuzu-agent`, then kill that PID), and run `docker rm -f yuzu-native-uat-postgres`.

**Server tier = (server + postgres) pair.** Under the Postgres substrate (ADR-0006, #1320) the deployable stack is `(Server + Postgres) → Gateway → Agent` — every rig that boots the server tier also carries a PostgreSQL instance. The native rig runs a **postgres sidecar container** (`yuzu-native-uat-postgres` — distinct from the full-uat compose's `yuzu-uat-postgres`, since the native teardown force-removes it; image `yuzu-postgres:local` built from `deploy/docker/Dockerfile.postgres` on first use) on loopback `:15433` with per-run random credentials (superuser ≠ app role, per the #1334 init contract); the DSN is exported to the server as `YUZU_POSTGRES_DSN` and saved to `/tmp/yuzu-uat/postgres-dsn` (0600). The viz-UAT and demo rigs get their postgres as a compose service. Until #1320 PR 3 lands the fail-closed boot, a missing docker/sidecar is a **warning, not a failure** (`PG_SOFT_FAIL=1` in the script — flip with that PR). Host port 15433 deliberately avoids `5432` (local clusters), `5433` (dev pg-canary convention), `15432` (yuzu-ci-postgres), and `15440`–`15449` (per-agent `yuzu-ci-postgres-<n>` CI containers, #2094).

## viz-UAT (container-based, feat/viz-engine ladder)

`scripts/start-viz-uat.sh` stands up a three-container Docker stack (server + gateway + agent) for the visualization feature ladder. **Cannot run alongside a host-namespace `start-UAT.sh`** (a `uat-netns.sh` rig does not conflict — see *Concurrent rigs*) — both bind host ports 8080 *and* 50051. Auto-detects arm64 vs amd64 and sets `--build-arg TRIPLET` accordingly; default `x64-linux` preserves the `release.yml` path. The launcher exports `VIZ_UAT_CONFIG` (absolute path to a generated `yuzu-server.cfg`); do not invoke `docker compose -f docker-compose.viz-uat.yml up` directly. State dir `/tmp/yuzu-viz-uat/`; scale agents with `VIZ_UAT_AGENTS=N`. Set `VIZ_UAT_AGENT_MODE=vm` to skip the in-container agent and print the enrollment token + host-exposed gateway address for running a native `yuzu-agent` on an OrbStack VM / bare-metal host — needed for PR 8+ visuals that depend on real loopback workloads. `VIZ_UAT_AGENT_MODE=none` skips agent startup entirely. **Note:** `scripts/start-UAT.sh` (the native, non-container UAT) force-wipes `/tmp/yuzu-uat/` on each start to work around a stale-DB session-auth bug (#947); do not remove that wipe without first closing the issue. See `bash scripts/start-viz-uat.sh --help` for full usage.

## Cedar & Vale demo environment (release-pinned, sales)

`scripts/start-demo.sh` stands up a three-tier **chiselled** Docker stack (server + gateway + N agent replicas) from release-pinned GHCR images. **Cannot run alongside `start-viz-uat.sh` or a host-namespace `start-UAT.sh`** — all three bind host ports 8080 and 50051 (the launcher pre-checks and refuses to start if they are busy). Clean-start by default (wipes `/tmp/yuzu-demo/` + compose volumes); `--keep` preserves state. Distinct from the viz-UAT rig. The **agent-bundle** delivery image (`docs/agent-bundle.md`, `scripts/build-agent-bundle.sh`) ships the agent for `linux-x64` / `windows-x64` / `macos-arm64` to design partners who can only `docker pull` — published + cosign-signed + SBOM'd by the `docker-publish-agent-bundle` release job. Full runbook: `docs/demo-environment.md`.

## Concurrent rigs (`scripts/uat-netns.sh`)

The native rig, `/test`'s port phases and the scripts that default to `localhost:8080` all want the same host ports, so ordinarily only one runs at a time. `scripts/uat-netns.sh run <rig> -- <command>` runs a command inside a private network **and** PID namespace (bubblewrap, `--unshare-net --unshare-pid`): inside it `127.0.0.1:8080`, `:50051`, `:50063` and even `epmd` on `:4369` belong to that rig alone, so several rigs — a dev worktree and a PR review, say — run side by side and none of them touches the host's ports. Inside the namespace only that rig's processes are visible, so `start-UAT.sh stop` and its port-free checks cannot see, let alone signal, another rig. A second `run` of a rig name that is already running is refused (the wrapper holds a per-rig lock for the rig's whole life), since it would drop the first one's database.

Save the whole rig as one script — start, drive, copy the logs out, stop — and run it from the repo root:

```bash
# my-rig.sh   (KEEP = where to leave the logs; /tmp/yuzu-uat vanishes with the rig)
trap 'mkdir -p "$KEEP" && cp -a /tmp/yuzu-uat/*.log "$KEEP"/ 2>/dev/null' EXIT
bash scripts/start-UAT.sh && bash scripts/e2e-api-test.sh; rc=$?; bash scripts/start-UAT.sh stop; exit $rc
```

```bash
KEEP=$HOME/rig-a-logs scripts/uat-netns.sh run a -- bash my-rig.sh      # terminal 1
KEEP=$HOME/rig-b-logs scripts/uat-netns.sh run b -- bash my-rig.sh      # terminal 2, same ports, at the same time
scripts/uat-netns.sh status                       # shared Postgres, rig databases, which rigs are running
scripts/uat-netns.sh pg-down                      # remove the shared Postgres when done (refuses while a rig runs; --force overrides)
```

Prerequisites: Linux with `bubblewrap` (`apt install bubblewrap` / `dnf install bubblewrap`), `flock` (util-linux), a reachable Docker daemon, and the `yuzu-postgres:local` image (built once: `docker build -t yuzu-postgres:local -f deploy/docker/Dockerfile.postgres .`; outside a rig `start-UAT.sh` builds it on first use, but inside a rig it never does — the wrapper stops and prints that command).

**This is not a sandbox.** Only the network, the PID table and `/tmp/yuzu-uat` are private. A rig can read and write the host filesystem (`--dev-bind / /`), reach the Docker socket (root-equivalent), and connect to the shared Postgres as its superuser, so any rig can read or drop any other rig's database. Do not run code you do not trust in a rig.

How it works: published Docker ports live in the host namespace and are not reachable from a private one, but unix sockets are files and cross it. One container (`yuzu-netns-pg-<hash of the state dir>`) runs with `--network none` — no published port and no bridge address — so its **only** way in is a unix socket, in a `0700` directory under `/tmp` that keeps other local users out (the image's `local` auth is `trust`, and that directory is the access control). Each rig gets its own freshly created database `yuzu_<rig>`. The wrapper hands the rig `YUZU_UAT_PG_DSN`, which `start-UAT.sh` uses **instead of** starting its `:15433` sidecar (it neither starts nor removes one, and does not look at `:15433`); `YUZU_NETNS_RIG` carries the rig's name. The wrapper passes its Postgres credentials in the environment, never on a command line, because argv is world-readable through `/proc`; `start-UAT.sh`'s own sidecar path predates this and still does not make that promise. `/tmp/yuzu-uat` is a private tmpfs per rig, so the start-time wipe (#947) never touches another rig.

You can also export `YUZU_UAT_PG_DSN=postgresql://…` yourself to point `start-UAT.sh` at any Postgres. It is validated as a `postgresql://` or `postgres://` URI and is never printed (it is written `0600` to `/tmp/yuzu-uat/postgres-dsn`). It is not preflighted: a dead DSN shows up as the server failing to start.

Lifetime: every process in a rig, and its `/tmp/yuzu-uat`, is gone when the command exits, so the command must run its own tests and copy out any logs it wants — there is no attaching afterwards. (Processes a rig starts *through the Docker daemon*, such as compose services, are outside the namespace and are not killed.) Run the stack's clients (`scripts/e2e-*.sh`, `scripts/test/instructions-tests.sh`, `scripts/test/synthetic-uat-tests.sh`) **inside** the same `run`: the host cannot reach a namespace's loopback, so a client run from outside gets connection refused. The shared Postgres container and each rig's database outlive the command, until the next `run` of that rig or `pg-down`; a rig's database holds whatever it ingested, including device data from the machine it ran on, so `pg-down` after a UAT on a real machine's inventory.

Capacity: Postgres is started with `max_connections=300` and each server's pool is 16 (`YUZU_POSTGRES_POOL_SIZE` lowers it), so connections allow roughly a dozen rigs; RAM is the real limit (a server, an Erlang gateway and an agent per rig — a rough estimate of a few GB each; measure on your hardware).

Limits: Linux only; native rigs only (`start-viz-uat.sh`, `start-demo.sh`, `sanitizer-uat.sh` and the compose rigs publish ports in the host namespace and stay mutually exclusive); no `sudo` inside, so `start-UAT.sh --as-user` is unsupported there; needs unprivileged user namespaces (on Ubuntu 24.04+ an AppArmor profile for `bwrap`, see `kernel.apparmor_restrict_unprivileged_userns`). It removes **port** clashes only: rigs still share the build tree (do not run two builds in one worktree), `~/.local/share/yuzu`, and CPU/RAM/tmpfs — so do not run `scripts/test/perf-gate.sh` (or take timings) while a rig is up: its quiet-port check cannot see a rig, but the rig's load will skew the measurement.

Troubleshooting: *"not a private directory"* — remove `/tmp/yuzu-netns-<uid>` or point `YUZU_NETNS_STATE` elsewhere; *"already running"* — that rig name is live (see `status`); *stale socket files* — re-run `pg-up`; *"credentials … are gone"* — the state directory was deleted under a running container: stop the rigs and `pg-down --force`.

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
| 15433 | Postgres sidecar | Native-rig `yuzu-native-uat-postgres` container, loopback-published → container 5432 (server tier's substrate pair; ADR-0006/#1320). Not used when `YUZU_UAT_PG_DSN` is set (see *Concurrent rigs*) |

## Gateway command forwarding

The gateway's primary function is **command fanout** — relaying commands from the server to potentially millions of agents and aggregating responses. This requires three server flags:

1. **`--gateway-upstream 0.0.0.0:50055`**: Enables the `GatewayUpstream` gRPC service so the gateway can proxy agent registrations and batch heartbeats to the server. The server refuses to start with this flag unless gateway peer authorization is configured or acknowledged as disabled, and `--no-tls` alone is not an acknowledgement. The plaintext UAT rigs (`start-UAT.sh`, `win-start-UAT.sh`, `start-stack.sh` and the full, sanitizer and viz Docker UAT composes) therefore also pass **`--insecure-gateway-peer`**, which disables peer authorization on this service (development rigs only; `YUZU_INSECURE_GATEWAY_PEER=1` is the equivalent environment form).
2. **`--gateway-mode`** — Subscribe stream peer-mismatch validation accepts the agent's Register peer IP (default rule) **OR** an IP previously recorded in the trusted-gateway peer set via `GatewayUpstreamServiceImpl::ProxyRegister` (W1.3 / #826). Entries are noted only on a successful enrollment branch and expire after 1h (LRU-capped at 1024 entries). Without `--gateway-mode` the trusted-set lookup is skipped — direct-connect agents only ever match their Register peer. Layered defence note: this rule scopes Subscribe to known gateway IPs but does NOT defend against a sniffed `session_id` presented from inside the gateway's IP space; the agent_id↔session binding from W1.4 (#827) is the layer that closes that.
3. **`--gateway-command-addr localhost:50063`** — Points the server at the gateway's `ManagementService` for command forwarding. Without this, commands to gateway-connected agents are queued in `gw_pending_` but never forwarded. The server calls `SendCommand` (server-streaming RPC) on this address; the gateway fans out to agents and streams responses back.

`--trusted-nat-cidr <cidr>[,…]` (`Config::trusted_nat_cidrs`, #1128) is the direct-connect analogue of `--gateway-mode`'s trusted-IP relaxation: when a direct agent's Register and Subscribe source IPs both fall inside one declared CIDR (multi-egress NAT / proxy pool / CG-NAT / SD-WAN), the per-session peer-IP mismatch is downgraded to *advisory* (audit `result="ok" outcome=advisory` + `yuzu_grpc_subscribe_peer_advisory_total`) instead of rejected. mTLS-identity match does the same downgrade but is **opt-in** via `--nat-trust-mtls-identity` (`Config::nat_trust_mtls_identity`, default off) — it is a session-replay bypass under a shared fleet-wide client cert, so it requires the operator to affirm per-agent certs (gov UP-2). Strict exact-match stays the default; mismatches outside both accommodations still reject; an empty extracted IP always rejects (#826). The pure decision is `AgentServiceImpl::evaluate_peer_binding`; gateway origin-IP attribution rides `RegisterRequest.gateway_observed_peer` (#1064, server-side consumed; gateway population is a follow-up — grpcbox doesn't yet expose the direct transport peer to handlers — #1172). See `docs/auth-architecture.md` "Per-session peer binding and NAT-aware relaxation".

The dispatch flow in `agent_registry.cpp` `send_to()`:
- Agent has a local Subscribe stream → write directly (direct-connect agents)
- Agent has a `gateway_node` but no local stream → queue to `gw_pending_` for gateway forwarding
- `forward_gateway_pending()` drains the queue via `gw_mgmt_stub_->SendCommand()`

The gateway uses port range 5006x (vs server's 5005x); `gateway/config/sys.config` and `grpcbox` `listen_opts` are configured independently and must match. UAT credentials: fresh `yuzu-server.cfg` with PBKDF2-SHA256 hashed `admin` / `adminpassword1` per run; state lives under `/tmp/yuzu-uat/` and is wiped on each start.
