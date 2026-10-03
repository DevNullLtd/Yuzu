# Yuzu Gateway

The Yuzu gateway is an Erlang/OTP application that sits between agents and the
C++ server, enabling the platform to scale beyond the connection limits of a
single server process.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture) -- PARTIALLY IMPLEMENTED
- [Core Proxy Functions](#core-proxy-functions) -- PARTIALLY IMPLEMENTED
- [GatewayUpstream Service](#gatewayupstream-service) -- PARTIALLY IMPLEMENTED
- [Configuration](#configuration)
- [Building and Testing](#building-and-testing)
- [Gateway Clustering](#gateway-clustering) -- PARTIALLY IMPLEMENTED
- [Prometheus Metrics](#prometheus-metrics) -- PARTIALLY IMPLEMENTED
- [Reference](#reference)

---

## Overview

**Status: PARTIALLY IMPLEMENTED**

At scale, the C++ server's single-process gRPC architecture hits limits:
each Subscribe bidi stream holds a per-agent mutex, and broadcast operations
iterate all agents serially. At millions of agents this creates lock convoys,
thread exhaustion, and single-box ceilings.

The gateway solves this by owning the **command fanout plane** (Subscribe
bidi streams to agents, command dispatch, response aggregation) while the
C++ server retains the **control plane** (enrollment, auth, inventory,
dashboard, REST API).

The key scaling insight is that Erlang can sustain millions of lightweight
processes, each holding the state for one agent's bidi stream, with no
mutexes -- message passing provides serialization.

---

## Architecture

**Status: PARTIALLY IMPLEMENTED**

```
Operators (browser, REST API, CLI)
    |
    v
+-----------------------------------------------+
|           yuzu-gateway (Erlang/OTP)            |
|                                                |
|   +----------+  +----------+  +----------+    |
|   | gw_node1 |  | gw_node2 |  | gw_nodeN |    |
|   +----------+  +----------+  +----------+    |
|        |              |             |          |
|    agent_proc     agent_proc   agent_proc      |
|    agent_proc     agent_proc   agent_proc      |
+--------+--------------+------------+----------+
         |              |            |
         v              v            v
    +---------+    +---------+  +---------+
    | Agent 1 |    | Agent 2 |  | Agent M |
    +---------+    +---------+  +---------+
         |              |            |
         +--------------+------------+
                        |
                        | Register, Heartbeat, Inventory
                        v
               +------------------+
               |  yuzu-server     |
               |  (C++ control    |
               |   plane)         |
               +------------------+
```

**Plane separation:**

| Plane | Owner | Responsibilities |
|---|---|---|
| Control | yuzu-server (C++) | Register, Heartbeat, enrollment, auth, inventory, dashboard, REST API, mTLS termination |
| Command | yuzu-gateway (Erlang) | Subscribe bidi streams, SendCommand fanout, response aggregation, streaming relay |

### OTP Process Model

Each connected agent is represented by a single Erlang process (`yuzu_gw_agent`,
a `gen_statem` state machine). The process owns the gRPC stream writer handle;
all writes to that agent go through its mailbox with no mutex contention.

**Agent process states:**

| State | Description |
|---|---|
| `connecting` | Agent called Register; forwarded to upstream server; awaiting session_id |
| `streaming` | Bidi stream active; agent process owns the stream writer |
| `disconnected` | Stream broken or heartbeat timeout; cleanup and termination |

Memory per agent process is approximately 2 KB base plus the pending command
map. At 1 million agents this is 2--4 GB, trivially shardable across a cluster.

### Module Inventory

The gateway source lives in `gateway/apps/yuzu_gw/src/`:

| Module | Role |
|---|---|
| `yuzu_gw_app` | OTP application behaviour |
| `yuzu_gw_sup` | Top-level supervisor |
| `yuzu_gw_agent_sup` | `simple_one_for_one` supervisor for agent processes |
| `yuzu_gw_agent` | `gen_statem`: one process per agent bidi stream |
| `yuzu_gw_registry` | Process groups + ETS routing table, plus the node-local session index used by heartbeat admission |
| `yuzu_gw_router` | Command fanout coordinator |
| `yuzu_gw_upstream` | gRPC client pool to the C++ server |
| `yuzu_gw_agent_service` | Agent-facing gRPC server (AgentService proxy) |
| `yuzu_gw_conn` | Connection key (the HTTP/2 connection pid) of an agent-facing gRPC call, read through the vendored grpcbox accessors |
| `yuzu_gw_heartbeat_admission` | Admission decision for agent `Heartbeat` calls (session held by this node and call on the connection that opened it), rejection counters and the rate-limited summary log line |
| `yuzu_gw_mgmt_service` | Operator-facing gRPC server (ManagementService proxy) |
| `yuzu_gw_telemetry` | Telemetry event definitions and handlers |
| `yuzu_gw_gauge` | Periodic gauge emission for Prometheus |
| `yuzu_gw_proto` | Protobuf encode/decode wrappers |

---

## Core Proxy Functions

**Status: PARTIALLY IMPLEMENTED**

### Register Proxy

When an agent calls `Register`, the gateway's `yuzu_gw_agent_service` forwards
the request to the C++ server via `yuzu_gw_upstream:proxy_register/1`. The
server handles enrollment logic (token validation, pending approval queue)
and returns a `RegisterResponse` with a session ID. The gateway relays the
response to the agent and starts an agent process.

When the server's built-in CA is active, that `RegisterResponse` now also carries
a signed **per-agent client certificate** — the same certificate an agent would
receive on the direct-connect path (PKI PR5d). The gateway relays the full
response verbatim, so the certificate reaches the agent with no gateway
configuration change. **Revocation note:** revoking a certificate invalidates the
presented leaf but does **not** prevent re-enrollment; to stop an agent from
re-enrolling and re-obtaining a certificate, **deny** the agent (dashboard
Devices → deny). Both the direct and gateway paths reject a denied agent before
signing. (In M1 the agent↔gateway hop is one-way TLS, so the agent's client cert
is not yet verified at the gateway transport — through-gateway identity remains
the app-layer `gateway_observed_peer`; the issued cert is for inventory,
revocation, and the future gateway-mTLS cutover.)

### Heartbeat Batching

Individual agent heartbeats are not forwarded one-by-one. Instead,
`yuzu_gw_upstream` buffers heartbeats and sends them in a single
`BatchHeartbeat` RPC at a configurable interval (`heartbeat_batch_interval_ms`,
default 1000 ms; env override `YUZU_GW_HEARTBEAT_INTERVAL_MS`).

This reduces upstream load from O(agents/interval) to O(nodes/interval).

On RPC failure, heartbeat buffers are retained (capped at 10,000) for retry
on the next flush cycle rather than being silently discarded.

#### Heartbeat admission

Before a heartbeat is buffered, the gateway checks that it belongs to a session
this gateway node holds **and** that it arrived on the HTTP/2 connection that opened
that session's `Subscribe` stream. A session that has registered but not yet
subscribed is held to the connection that sent its `Register`. The check reads
node-local state only: a session held by another gateway node is not admitted here,
and the decision does not depend on what the server currently knows about the
session.

A heartbeat that does not meet both conditions is answered with gRPC `NOT_FOUND`
(`unknown session`), counted, and not buffered or forwarded. The answer is the same
whatever the reason (no session, wrong connection, no usable binding), so the
response does not reveal which condition failed; the reason appears only in the
counters below. A heartbeat that is admitted is acknowledged and buffered exactly as
before.

A rejected agent re-registers through its `NOT_FOUND` handling where that handling
works; see below. Where it works, the agent waits an escalating cooldown (2 s on the first
rejection, doubling to a 300 s cap), drops its `Subscribe` stream and registers
again. There is no wire or server change, and no agent change for the supported
topologies. The recovery logic exists from v0.13.0 (checked in the agent source at
the v0.12.0 and v0.13.0 tags), but the released v0.13.0 and v0.14.0-rc6 agents wedge in
their reconnect path with default settings (bug #2182, fixed by PR #5183, in no release
yet): after the rejection they log `(#1894)` and `Heartbeat thread stopped` and never
re-register (observed, 19 minutes, reproduced on a second agent; the cause is inferred
from the fix). They recover only with `--no-auto-update` (observed with v0.13.0 and
v0.14.0-rc6, re-registering 20 to 21 s after a registry restart; a command-line flag
with no environment variable) or on a build that includes the fix. Agent v0.12.0 and
older never re-register by themselves: they only log `Heartbeat failed` (observed with
v0.12.0 and default settings, 29 failures in 14.5 minutes; a `--no-auto-update` run was
watched for only about 2 minutes and behaved the same, with no re-registration; older than
v0.12.0 is inferred from the agent source, not run) and, for
persistent missing state, stay rejected until restarted or upgraded (a heartbeat that
falls in the short gap between the session leaving the pending table and its agent
process registering can succeed later without re-registration). Upgrade the agents
first, then the gateway, with a build that includes the #2182 fix once released; until
then, restart an agent that stays rejected (restarting the agent service re-registers
it). Agents that do not connect through the gateway are not affected. Recovery matters
only when heartbeats are rejected, which happens in four cases: a topology that breaks
the one-connection assumption, a gateway running without the session index, a
gateway registry process restart or crash while agent connections stay up (the registry
recreates its tables empty, so every heartbeat for the agents it held is rejected until
they re-register), and, for released agents, a gateway process restart (observed in a graceful SIGTERM run with rc6, v0.13.0 and v0.12.0 together: the released agents did not
notice the lost `Subscribe` stream and got `NOT_FOUND` on the new gateway, rc6 and v0.13.0 then wedged;
in the earlier run v0.12.0 was rejected and v0.13.0 was already wedged from the registry kills; the
branch agent re-registered in 11 to 12 s with no rejections both times; see Connection drain). A
node failover that leaves the session not held by the surviving node is expected to
behave the same way (inferred, not tested).

**Supported topologies.** Agents connect to the gateway agent listener (`:50051`)
directly, or through an L4 / TLS-passthrough path that keeps one TCP connection per
agent end to end (a plain TCP load balancer, an L4 virtual IP, a TLS-passthrough
proxy). An HTTP/2-terminating or HTTP/2-multiplexing proxy between agents and the
gateway (including a service-mesh sidecar that terminates HTTP/2) is **not
supported** for this check: it may cause repeated heartbeat rejection or share
gateway-side connections across agents, removing the per-agent connection separation
this check requires. It can spread one agent's calls over several
connections, which shows up as connection mismatches (the `connection_mismatch=`
count in the gateway summary log line; the counter is
`yuzu_gw_heartbeat_session_mismatch_total`) and repeated re-registration, and it
removes the per-agent separation the check relies on. See
[Security Hardening](security-hardening.md#gateway-tls-if-you-deploy-the-erlang-gateway).

**Multi-node gateways.** The check reads node-local state, so for the life of a session
the `Register`, `Subscribe` and `Heartbeat` calls of one agent must reach the same
gateway node on one connection: use per-connection sticky L4 and do not balance
per RPC. An agent that re-registers on a new connection (for example after a failover
to another node) mints a new session, which is compatible with this rule. Multi-node
behaviour is not tested with a real agent (a two-node registry unit test exists).

*Observed in testing* (a real C++ agent, a plaintext gateway listener, two agents per
run):

- Behind an HTTP/2-terminating proxy (nginx `grpc_pass`, two agents), every heartbeat was
  rejected as a connection mismatch: the mismatch counter rose and nothing reached
  the server. The agents still enrolled and still received commands over their
  `Subscribe` streams, and they re-registered on their back-off ladder (2 s doubling
  to a 300 s cap). The server's online count for the two agents flickered between 2,
  1 and 0. In this observed nginx case the topology therefore fails loudly in the
  counters and the gateway summary log, not silently; that is one two-agent test, not
  a guarantee for every HTTP/2-terminating proxy.
- Behind an L4 TCP forwarder (nginx `stream`), there were zero rejections.
- A multiplexing HTTP/2 proxy with upstream keepalive was **not tested**.

The agent-facing message is the same `unknown session` for every reason (this is
deliberate, see above), so the agent log cannot tell the reasons apart. Diagnose from
the counters and the gateway summary log line, not from the agent log.

**Connection drain.** The gateway's HTTP/2 server closes a connection as soon as it
sends `GOAWAY`, so a `Subscribe` stream and its binding end with the connection;
there is no drain period. A heartbeat that reaches the gateway on a different
connection while the old `Subscribe` is still bound is rejected (`NOT_FOUND`,
connection mismatch), and an agent with the reconnect fix recovers by re-registering. This is what the
gateway's own tests observed with a test HTTP/2 client. With the real C++ agent (a build
from the branch tree) a graceful `GOAWAY` injected by the tester on the gateway-side
connection (the gateway itself did not send one) moved the agent's next heartbeat to a
new connection: the mismatch counter rose by one, the agent logged `(#1894)` and
re-registered 16 s after the `GOAWAY`, and acked heartbeats resumed about 30 s later. An
abrupt close of just that agent's connection made it re-register in 9 s with the
counters unchanged. A graceful gateway SIGTERM and restart (observed twice) showed the
branch agent reconnecting in about 11 to 12 s with no rejections; in the second run the released agents
tested (v0.14.0-rc6, v0.13.0, v0.12.0, default settings) did not notice the lost
`Subscribe` stream across that restart, their heartbeats got `NOT_FOUND`, and rc6 and
v0.13.0 then wedged as described above (restart them). A `GOAWAY` originating from the
gateway on its own was not observed.

**Observability.** Rejections are counted by two families (see
[Available Metrics](#available-metrics)): `yuzu_gw_heartbeat_rejected_total{reason}`
for a heartbeat with no usable binding, and
`yuzu_gw_heartbeat_session_mismatch_total{event="security"}` for a held session whose
heartbeat arrived on a different connection. Every series is created at 0 at gateway
start, and the counters reset when the gateway restarts (use `increase()` in
queries). There is no per-heartbeat log line. Rejections are folded into one summary
line at `info` level, written for the first rejection and then at most once per
`telemetry_gauge_interval_ms` (10 s by default), for example
`Heartbeat admission rejected heartbeats since the last summary: unknown_session=3, connection_mismatch=1`.
It carries reason names and counts only, never a session id. The line is written only
when a rejection arrives, so counts that trail the last line wait for the next
rejection and the line can lag the counters; the counters are authoritative. The rate
limit is one state shared by all concurrent rejections (it is created at gateway
start, after telemetry setup and before the gateway supervision tree starts; the agent
listener belongs to the grpcbox dependency application, which can start first, so a
heartbeat in that window is rejected and the state is then created lazily), so in initialized operation a burst of simultaneous first rejections produces one line; a heartbeat before the state exists can race with other lazy initializations and may produce an extra line. At startup the
gateway logs `Heartbeat admission is connection-bound: a heartbeat is admitted only on the connection that opened its session`. No alert rule ships for these series. The
rejected heartbeat has no resolved principal, so there is no audit row, only the
counters and the summary line.

**Reading the counters.**

- Symptom first: agents re-register every few minutes, or the server's online count
  flickers. Check `yuzu_gw_heartbeat_session_mismatch_total` and the
  `connection_mismatch=` count in the summary log line, then check the proxy topology
  between the agents and `:50051`; use L4 or TLS passthrough. Do not rely on the online
  count alone: in rig run 4, rejected or orphaned agents (observed with v0.12.0) were still
  counted online by the server's `/health` `agents.online`, so diagnose that case from the
  rejection counters, the gateway summary log, the agent log and heartbeat freshness. The
  online count flickering was observed only in the run behind an HTTP/2-terminating proxy.
- `yuzu_gw_heartbeat_session_mismatch_total` that keeps rising for more than about
  15 minutes (a rule of thumb, not a measured value) points to a topology that breaks
  one connection per agent (an HTTP/2-terminating proxy, or similar). A rise of
  one per affected agent is expected when an agent's connection is replaced while its
  session is still held (observed with an injected GOAWAY, a test-only trigger; not
  observed with an abrupt close or a gateway restart, where the counter stayed
  unchanged).
- `yuzu_gw_heartbeat_rejected_total{reason="unknown_session"}` rises by about one per
  agent after a gateway registry restart. Observed: after killing the registry process
  with 4 agents attached the counter rose by 4, and all 4 agents were admitted again
  within about 25 s (a four-agent run; observed with agents built from the branch tree,
  which includes the #2182 fix). Over four later registry kills with one branch agent,
  that agent was admitted again 17 to 37 s after each kill. The released v0.13.0
  and v0.14.0-rc6 agents wedge with default settings and v0.12.0 only logs the
  rejection (see Heartbeat admission above); restart such an agent. It is also expected
  to rise around a node failover, but that was not observed in testing (multi-node was
  not tested).
- `yuzu_gw_heartbeat_rejected_total{reason="no_connection"}` rises when the call, or
  the session it names, has no connection key to compare. Not observed in testing. Its
  possible causes are a registration path that carries no connection key, or a
  regression in the connection accessor (`yuzu_gw_conn` returns `undefined` when the
  vendored grpcbox accessor fails, see `gateway/_checkouts/grpcbox/YUZU_PATCH.md`). The
  decision is in `gateway/apps/yuzu_gw/src/yuzu_gw_heartbeat_admission.erl`.
- `yuzu_gw_heartbeat_rejected_total{reason="registry_unavailable"}` stays at 0 on a
  gateway that was restarted to deploy this change. A non-zero value means the session
  index table was missing when a heartbeat arrived (new code loaded into a running
  node, or the registry process was down); `/readyz` reports it (see Upgrading
  below).

Agents behind a topology that breaks the one-connection-per-agent assumption back off
from 2 s up to 300 s between re-registrations, but this does not bound the load in
every case. An admitted heartbeat resets the agent's back-off streak (observed), so a
topology with only partial affinity, where an occasional heartbeat does land on the
right connection, would be expected to keep retries frequent (inferred, not tested);
and each retry is a registration through the gateway to the server. The back-off was
observed with two agents only, and no storm test was run at fleet scale.

**Health probes.** The shipped container healthchecks use `/healthz` (liveness).
`/readyz` also reports `sessions_index` and answers 503 while the table is missing, so
a load balancer that should drain such a node must probe `:8081/readyz`.

**Rolling upgrades.** Restart one gateway node at a time behind an L4 balancer. Agents
on a restarted node reconnect and re-register on their back-off (agents with the reconnect
fix; released agents may need a restart, see [Heartbeat admission](#heartbeat-admission)).
Multi-node behaviour
is not tested.

**Upgrading.** A rejected agent re-registers on its own only in a build that includes
the #2182 fix, or with `--no-auto-update` on v0.13.0 and v0.14.0-rc6 (see Heartbeat
admission): upgrade the agents first, then the gateway, with a build that includes the fix
once released. Until then, restart an agent that stays rejected (restarting the agent service
re-registers it). Agents that do not connect through the gateway are not affected. Deploy this
change with a **gateway restart**. The session index is a
new in-memory table created when the gateway registry starts, and hot code upgrade
is not supported for this change. New code loaded into a running node has no index
table (a unit test exercises this by deleting the table inside the registry; a real
hot code load was not run): the registry process survives and keeps its routing rows
and process groups, logs one warning, and every heartbeat on that node is rejected as
`registry_unavailable` until the node is restarted. `/readyz` reports the table as
`sessions_index` and answers 503 `not_ready` while it is missing. The table is
protected: only the registry process writes it. After a restart agents with the
reconnect fix reconnect, register and subscribe again, and their sessions are bound to the new
connections (released agents may need a restart, see [Heartbeat admission](#heartbeat-admission)).

**Rollback.** Redeploy the previous gateway release. The only new state is the in-memory
session index, and there is no wire, agent or server change, so nothing needs migrating;
agents re-register on their own (released agents may need a restart, see
[Heartbeat admission](#heartbeat-admission)), and a rollback removes the connection
check. This is derived from the change and was not run.

**Tested configurations** (observed, with the rejection counters at 0): a real C++ agent over one-way TLS (it enrolled one-way, received a per-agent
certificate and then presented its client certificate; the listener does not require one; a second agent ran steady one-way TLS;
the counters stayed at 0 through gateway, agent and server restarts; the listener
advertises `h2` through NPN only and the agent connects without an ALPN error), a
Windows agent (about 25 minutes, plaintext), the released agents v0.13.0 and
v0.14.0-rc6 (plaintext), a 31-minute soak with 4 agents plus a run with 25 extra
agents, and non-default agent heartbeat intervals. A later plaintext run on the final
gateway code covered a clean boot (`/readyz` 200 with `sessions_index`, both counter
families at 0), a 6 minute 23 s steady run of a branch agent at the default heartbeat interval, a heartbeat
for a held session sent from a second connection (`NOT_FOUND`, mismatch counter 0 to 1,
nothing buffered), registry kills, graceful gateway restarts, an injected `GOAWAY` and an
abrupt connection close, with the released agents v0.14.0-rc6, v0.13.0 and v0.12.0 (see
Heartbeat admission and Connection drain for the results).

**Not tested with a real agent:** a multi-node gateway (a two-node registry unit test,
`yuzu_gw_registry_multinode_tests`, exists), and a listener that requires client
certificates (a test-client mutual TLS leg exists in
`yuzu_gw_heartbeat_conn_rpc_tests`; the shipped listener does not require client
certificates). **Not tested at all:** a multiplexing HTTP/2 proxy with upstream
keepalive, Windows service mode, a macOS agent, fleet-scale storms, a real hot code
load, TLS in the final-code rig run, and a real C++ agent across a `GOAWAY` that the
gateway itself originates (only an injected one was run).

The first rig runs used gateway commit `1c145d78a` (the first run, plaintext, ran on
`2e884bb9b`, which differs from it only in tests and docs). Later fix
commits were covered by the eunit suite only until a plaintext rig run (rig run 4) at `1e9c9784d`
exercised the final gateway source, the boot path included: `605f117d2`
(index guard), `3431d20ea` (`/readyz` `sessions_index`) and `026830cd9` (summary log
state created at boot), the round-2 code commits `e139c5e86` (boot test and two
source comments), `9ad473534` (counter HELP wording), `942fe5770` and `c2d040a66`
(test changes) and `ab3986ec1` (comments), and the round-3 code commit `21125cc3b` (a source
comment, the `yuzu_gw_heartbeat_rejected_total` HELP text and tests). The commits after
`1e9c9784d` (`050703fcc`, `e3c9989b4`, `b19e4d818`, `b497ead98` and later documentation, test and CI
commits) change tests, documentation, HELP text and the `ci.yml` environment only, and were not run on a rig. At `ab3986ec1` the fix agents ran eunit (401 of 401,
three times from a fresh build) and dialyzer (clean); these were not rig runs. The per-run record is in
[the evidence record](../security-reviews/gateway-heartbeat-connection-binding-2026-10-03.md).

### Subscribe Stream Proxy

The gateway owns the agent's Subscribe bidi stream. When an operator sends a
command via `SendCommand`, the `yuzu_gw_router` fans it out to the target
agent processes, which write to their respective streams. Responses flow back
through the agent process mailbox to the router and are aggregated for the
operator.

### Inventory Proxy

Full inventory reports from agents are forwarded to the C++ server via
`ProxyInventory` for storage and querying.

### Stream Status Notification

When an agent's Subscribe stream connects or disconnects at the gateway, a
`NotifyStreamStatus` RPC informs the C++ server so it can update its
connectivity records.

---

## GatewayUpstream Service

**Status: PARTIALLY IMPLEMENTED**

The `GatewayUpstream` service is a gRPC service exposed by the C++ server
specifically for gateway communication. It is defined in
`proto/yuzu/gateway/v1/gateway.proto`. Each core replica answers from its own
in-memory view of the gateway sessions it holds; see the `BatchHeartbeat`
message below for the per-replica unknown-session list the server now returns.

### RPCs

| RPC | Request | Response | Purpose |
|---|---|---|---|
| `ProxyRegister` | `RegisterRequest` | `RegisterResponse` | Forward agent registration to control plane |
| `BatchHeartbeat` | `BatchHeartbeatRequest` | `BatchHeartbeatResponse` | Aggregated heartbeats from all agents on one gateway node |
| `ProxyInventory` | `InventoryReport` | `InventoryAck` | Forward inventory reports to storage layer |
| `NotifyStreamStatus` | `StreamStatusNotification` | `StreamStatusAck` | Inform server of agent connect/disconnect events |

### BatchHeartbeat Message

```protobuf
message BatchHeartbeatRequest {
  repeated HeartbeatRequest heartbeats = 1;
  string gateway_node = 2;
}

message BatchHeartbeatResponse {
  int32 acknowledged_count = 1;
  repeated string unknown_session_ids = 2;
  bool unknown_session_ids_truncated = 3;
}
```

`unknown_session_ids` lists the distinct session ids in the batch that the
answering server replica does not hold in memory (at most 4096; empty and
over-length ids are never listed), and `unknown_session_ids_truncated` is set
when more than that were unknown. A server that predates these fields and a
server with nothing unknown look the same on the wire, by design. **The gateway
does not read either field yet** (only the server side exists today), so
today they have no effect on gateway behaviour; the gateway-side replay that
will consume them is tracked in #1197.

### StreamStatusNotification Message

```protobuf
message StreamStatusNotification {
  string agent_id   = 1;
  string session_id = 2;
  enum Event {
    CONNECTED    = 0;
    DISCONNECTED = 1;
  }
  Event event       = 3;
  string peer_addr  = 4;
  string gateway_node = 5;
}
```

---

## Configuration

The gateway is configured via `gateway/config/sys.config`. Key settings:

```erlang
{yuzu_gw, [
    %% Agent-facing gRPC (agents connect here)
    {agent_listen_addr, "0.0.0.0"},
    {agent_listen_port, 50051},

    %% Operator-facing gRPC (dashboard/CLI)
    {mgmt_listen_addr, "0.0.0.0"},
    {mgmt_listen_port, 50052},

    %% Upstream C++ server (GatewayUpstream service)
    {upstream_addr, "127.0.0.1"},
    {upstream_port, 50055},

    %% Upstream connection pool size
    {upstream_pool_size, 16},

    %% Heartbeat batching interval (ms)
    {heartbeat_batch_interval_ms, 1000},

    %% Default command timeout (seconds)
    {default_command_timeout_s, 300},

    %% Prometheus metrics HTTP port
    {prometheus_port, 9568},

    %% Agent telemetry gauge emission interval (ms); also the cadence of the
    %% heartbeat-rejection summary log line
    {telemetry_gauge_interval_ms, 10000},

    %% Consistent hash ring: virtual nodes per physical node
    {hash_ring_vnodes, 256},

    %% HA WS-4 4.1 -- the trust-zone/region cluster id this gateway belongs
    %% to; agents are pinned to one cluster (ADR-2002 §7). Stamped onto
    %% every StreamStatusNotification sent upstream so the server's
    %% routing directory can record which cluster owns an agent's live
    %% stream. Override: YUZU_GW_CLUSTER_ID
    {cluster_id, <<"default">>},

    %% HA WS-4 #4555 -- gateway multi-node cluster FORMATION (ADR-2002 §7b),
    %% distinct from cluster_id above: what to RESOLVE to find peer
    %% addresses, not the logical cluster identifier. Override:
    %% YUZU_GW_SEED_DNS_NAME
    {cluster_seed_dns_name, <<"gateway">>},

    %% Explicit peer address list; when non-empty REPLACES DNS resolution
    %% outright (never merged). Override: YUZU_GW_SEED_NODES
    %% (e.g. "10.0.0.1,10.0.0.2")
    {cluster_seed_nodes, []},

    %% Always-on redial loop interval (ms), fixed, no backoff. Override:
    %% YUZU_GW_CLUSTER_REDIAL_INTERVAL_MS
    {cluster_redial_interval_ms, 5000},

    %% Lifetime cap on distinct peer addresses ever turned into an Erlang
    %% atom (atoms are never garbage-collected) — defends against a
    %% hostile/misconfigured seed DNS name rotating through fresh
    %% addresses forever. No env override; edit sys.config directly if a
    %% real deployment's lifetime address churn needs a higher ceiling.
    {cluster_max_lifetime_addrs, 1024}
]}
```

**`YUZU_GW_ADVERTISE_ADDR`** (env var only, no `sys.config` key — consumed by
`deploy/docker/gateway-entrypoint.sh` before the BEAM starts, not by
application code): overrides auto-detection of this node's own advertised
distribution address. Needed on a bare-VM/multi-NIC host or a container
behind NAT where auto-detection is ambiguous or wrong; every gateway node
otherwise auto-detects it with zero configuration under Docker Compose.

Auto-detection order (first success wins — useful when debugging why a
container picked a surprising address):
1. `YUZU_GW_ADVERTISE_ADDR` itself, if already set — wins outright.
2. Resolve `YUZU_GW_SEED_DNS_NAME` (default `gateway`) to A records and
   intersect them with this container's own local interface addresses —
   "which of the addresses my peers would also see is mine."
3. Resolve this container's own hostname to an address.
4. Default `127.0.0.1` (matches the pre-`#4555` single-node behavior).

See `deploy/docker/gateway-entrypoint.sh` for the exact logic.

### TLS posture (M1)

> **⚠ SECURITY — do not expose the agent listener (`:50051`) to an untrusted
> network.** The gateway is the command fan-out plane. A plaintext,
> internet-reachable agent listener has **no confidentiality, no integrity, and no
> gateway authentication** — an on-path attacker can inject commands → **remote
> code execution across the fleet**. **One-way (server-authenticated) TLS now
> exists for the agent listener (PKI PR5c)** — enable it (see below) and distribute
> the CA to agents. **Until your deployment turns it on (only the reference gateway compose
> ships it; the cluster, demo and UAT composes are plaintext, see the table
> below), a gateway exposed to an untrusted network MUST**
> either (a) front the gateway at L4 or with TLS passthrough only (one TCP
> connection per agent end to end, with the gateway's own agent-listener TLS
> enabled; an HTTP/2-terminating reverse proxy, including a service-mesh sidecar
> that terminates HTTP/2, is not supported for heartbeat admission, see
> [Heartbeat admission](#heartbeat-admission)), or (b) keep
> `:50051` on a trusted network (VPN / private subnet / a mesh policy that does not
> terminate HTTP/2; see [Heartbeat admission](#heartbeat-admission)). Direct
> agent→server connections use TLS; this gap is specific to the gateway edge.

| Hop | State | Notes |
|---|---|---|
| gateway → server upstream (`:50055`) | **mutual TLS** | `gateway/config/sys.config.prod` `{https,...}` `default_channel`; CA-issued `default-gateway` leaf, TLS 1.2 floor + AEAD/PFS cipher whitelist. |
| agent → gateway (`:50051`) | **one-way TLS (PR5c)** | Server-authenticated TLS, no client cert required (bootstrap-safe). Enabled on the agent listener in `sys.config.prod` via `transport_opts => #{ssl => true, certfile, keyfile, cacertfile, verify => verify_none, fail_if_no_peer_cert => false}` (needs the vendored `_checkouts/grpcbox`). Of the shipped composes, only `docker-compose.reference-gateway.yml` enables it (#1314, mounting `reference-gateway-sys.config`). The cluster, demo, full-UAT, viz-UAT and sanitizer-UAT composes, and the repo-root `docker-compose.uat.yml`, run plaintext on the shipped default or an inline UAT/demo `sys.config`; the remaining composes do not run the gateway. Heartbeats are bound to the connection that opened the session's `Subscribe` stream (see [Heartbeat admission](#heartbeat-admission)); the agent listener itself still does not authenticate agents. |
| server → gateway mgmt (`:50063`) | **strict mTLS + SPKI peer pin (#1422)** | The privileged command-fan-out plane. Do NOT one-way-TLS it (would be unauthenticated). The secure shape (in `sys.config.prod` / `reference-gateway-sys.config`) is strict mTLS (omit `verify`/`fail_if_no_peer_cert`) **plus** `auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1` with `{yuzu_gw, mgmt_peer_pins}` pinning the server's cert — a CA-issued cert alone (an agent's leaf, the gateway's own leaf) is NOT authorization to command the fleet. The gateway **refuses to boot** with a network-reachable mgmt listener lacking this posture; `{allow_insecure_mgmt, true}` is a lab-rig-only acknowledgement (pair it with an unpublished `:50063`). BYO certs: point `mgmt_peer_pins` at your server cert (`{cert_file, ...}`) or paste its SPKI SHA-256 (`{spki_sha256, "..."}`) — the cert **must carry the `serverAuth` EKU** or the pin rejects it (`missing_server_auth_eku` in the gateway log); list old+new pins to overlap a rotation. Pin-list edits (adding/removing an entry) require a gateway restart; only a `{cert_file, Path}` target's file **content** re-reads live without one. |

TLS is configured **entirely in the `grpcbox` block** (grpcbox reads its own
config at boot — the old `{tls, [...]}` advisory key under `yuzu_gw` was removed
in PKI PR5 and does **nothing**). To enable upstream mutual TLS, copy the
`{grpcbox, [{client, ...}]}` `{https,...}` channel from
`gateway/config/sys.config.prod`.

To enable mTLS on the agent listener for a deployment where **every agent already
holds a CA-issued client cert** (not the normal enrollment path), add a
`transport_opts` map to each server entry — see the commented block in
`sys.config.prod`. **`ssl => true` is mandatory**; omit it and grpcbox silently
runs plaintext regardless of the other options. Full detail:
`docs/pki-architecture.md` "Gateway TLS".

#### Enabling agent-listener TLS — order of operations + caveats (#1244)

One-way TLS on the agent listener only helps if the **agent dials TLS and
verifies the CA**. A listener doing TLS while agents still dial plaintext (or dial
TLS without pinning the CA) is either inert or **MITM-able** — if the gateway leaf
chains to a *public* CA and the agent falls back to the system trust store, any
publicly-trusted impostor cert for the dial host is accepted. The agent half (CA
distribution + TLS-dial wiring + a fail-closed guard for `tls_enabled` with an
empty CA path) shipped as #1314 (the reference gateway compose is the worked example); the flag-day order below still applies when you enable the listener on an existing fleet.

**Flag-day upgrade order (enabling the listener disconnects every plaintext agent
at once — there is no dual-listen transition):**

1. **Distribute the CA** (`default-gateway`'s issuing CA, i.e. the install root)
   to every agent's `--ca-cert` / cert dir.
2. **Reconfigure agents** to dial the gateway over TLS and verify that CA.
3. **Only then flip the listener** to `ssl => true` in `sys.config.prod`.

Reversing the order strands the fleet until every agent is re-pointed.

**Compromised-gateway caveat:** one-way TLS authenticates the **gateway to the
agent**, not the agent to the gateway. It closes the on-path eavesdrop/inject of
the plaintext edge, but a *compromised gateway itself* can still inject commands
to the fleet — the compensating controls are app-layer: the server's
gateway-authoritative `gateway_observed_peer` attribution and the enrollment
approval workflow. Full cryptographic agent-to-gateway identity (so the gateway
can't forge an agent) arrives with the through-gateway attestation work gated on
PR5d / the QUIC migration (#376).

#### End-to-end enablement runbook (manual / interim)

Of the shipped composes, `docker-compose.reference-gateway.yml` already ships
one-way TLS on the agent listener (#1314). The cluster
(`docker-compose.reference-gateway-cluster.yml`), demo, full-UAT, viz-UAT and
sanitizer-UAT composes, and the repo-root `docker-compose.uat.yml`, use the shipped default or a UAT/demo `sys.config` and
are plaintext (the automated flip for those is tracked in issue **#1289**). To
stand up an **encrypted** agent↔gateway↔server stack from the
current artifacts today, wire it by hand in this order:

```bash
# 0. Server first boot generates the install CA + default-gateway leaf under the
#    cert dir. If agents reach the gateway by a name/VIP, mint the leaf with that
#    SAN so SNI verification passes:
yuzu-server --cert-san dns:gateway --cert-san dns:gw.corp.example
#    (repeatable; dns:/ip: prefixes, or a bare value auto-classified. Copy the
#    issuing CA out for step 2:)
cp /etc/yuzu/certs/default-ca.pem ./install-ca.pem   # or GET /api/v1/ca/root

# 1. Point the gateway's upstream at the server over mutual TLS (PR5) and turn on
#    the agent-listener one-way TLS (PR5c) — both live in sys.config.prod:
#      {grpcbox,[{client,...,{https,...,[{ssl_options,...}]}}]}   % upstream mTLS
#      listener transport_opts => #{ssl=>true, certfile, keyfile, cacertfile,
#                                   verify=>verify_none, fail_if_no_peer_cert=>false}
#    (needs the vendored _checkouts/grpcbox — the image build asserts it.)

# 2. Distribute install-ca.pem to every agent and have them dial the gateway over
#    TLS, verifying that CA:
yuzu-agent --server gateway:50051 --ca-cert /etc/yuzu/install-ca.pem \
           --enrollment-token "$TOKEN"

# 3. ONLY after every agent has the CA + dials TLS, flip the listener live
#    (restart the gateway). Enabling it ahead of step 2 disconnects the fleet.
```

Verify: the gateway boot log shows `tls` posture (not `plaintext`); an agent
connects and enrolls; `openssl s_client -connect gateway:50051` presents the
`default-gateway` leaf. Direct agent→server connections (no gateway) use TLS and
need none of this.

### Distribution Cookie (Required in Production)

The gateway enables Erlang distribution (`-name` in `config/vm.args.src`) for
clustering and remote-shell/`recon` access. The distribution **cookie is the
sole authentication for inter-node RPC** — any host that can reach EPMD
(TCP 4369) with the cookie can execute arbitrary code on the gateway node.

Supply it at boot from the `YUZU_GW_COOKIE` environment variable:

```bash
export YUZU_GW_COOKIE="$(openssl rand -hex 32)"   # strong, unique per cluster
```

If `YUZU_GW_COOKIE` is unset, `vm.args.src` falls back to the historical
default and the boot guard (`yuzu_gw_app:check_distribution_cookie/0`)
**refuses to start** — it fails closed, because a known cookie is
unauthenticated RCE (#659). For local dev/CI where distribution is not
exposed, override the guard with `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`. All nodes
in a cluster must share the same cookie.

The same guard also **refuses a cookie shorter than 32 characters** (HA WS-4
`#4555`): DNS-based cluster discovery means a node dials addresses it did not
choose by hand, and the distribution handshake's initiator sends the cookie
hash first — a short cookie is brute-forceable offline from a
legitimately-dialing node, a materially different exposure than a hand-typed
static seed list carried. `openssl rand -hex 32` above already clears this
floor with room to spare; the same `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` override
bypasses the length check too.

**Firewall ports for multi-node clustering (HA WS-4 `#4555`).** Alongside
EPMD (TCP 4369, above), a clustered gateway also needs the Erlang
distribution listener range **TCP 9100-9105** (`inet_dist_listen_min`/`_max`
in `config/sys.config`) reachable between every node. This range is
per-HOST, not per-cluster: one container is one network namespace, so every
containerized node binds the same first port (9100) with no collision — the
6-port range only matters for a dev/test rig running multiple gateway nodes
on ONE host, where each needs its own port from the range. Both EPMD and the
distribution range should be firewalled to ONLY the other gateway nodes,
never exposed publicly — the cookie is the authentication, but a closed
network is still the first line of defense.

> **IPv4-only.** Cluster discovery (DNS seed-name resolution, the
> entrypoint's local-interface intersection, and the static
> `YUZU_GW_SEED_NODES` override) is IPv4-only in this release. An
> IPv6-only Docker network degrades to N isolated single-node gateways —
> each resolves zero peers and boots standalone (fail-open, per design),
> rather than failing to start. `yuzu_gw_cluster_peers_resolved` staying
> at 0 is the signal to check for this. AAAA support is tracked as a
> follow-up.

> **Never set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production.** It disables the
> boot guard and restores the unauthenticated inter-node RPC surface (#659); it
> exists only for ephemeral dev/CI stacks (where it appears in the UAT compose
> files). On `.deb`/`.rpm` installs the cookie is auto-generated into
> `/etc/yuzu/gateway.env`. **Rotate** it by writing a new value there — and to
> every cluster node identically — then restarting the gateway.

### Server-Side Setup

The C++ server must be started with the `--gateway-upstream` flag specifying
the address and port for the GatewayUpstream service. This port must match
`upstream_port` in `sys.config`:

```bash
yuzu-server --gateway-upstream "0.0.0.0:50055"
```

> **Known limitation — gateway origin-IP attribution (#1064).** On the gateway
> `ProxyRegister` path, audit rows currently record the **gateway node's** IP as
> `source_ip`, not the originating agent's IP. The server already consumes the
> `RegisterRequest.gateway_observed_peer` field that carries the agent origin
> (recording `source_ip`=agent origin and `gateway_ip`=transport peer when
> present), but the gateway does not yet populate it — today's grpcbox transport
> cannot observe the direct agent peer, and the durable source arrives with the
> QUIC transport migration (#376). Until then, SIEM/audit consumers correlating
> `source_ip` with network logs on this path will see the gateway's address.

> **Known limitation - server-only restart (#1197).** After the server restarts
> while a gateway stays connected, `/health` `agents.online` can stay 0. The
> server keeps its gateway sessions in memory, and no registration replay was
> observed in this scenario (the replay drip documented under
> [Prometheus Metrics](#prometheus-metrics) runs after an upstream reconnect,
> which a server-only restart did not trigger in the observed runs). Signals at
> the default log level: the server WARN `GatewayRouteStore renew_leases guard
> rejected the write (outcome=unknown_session ...)`, logged for each heartbeat
> batch that carries such a session (about every 30 s per agent on the rig;
> expect more log volume on a larger fleet), the WARN `ProxyInventory: unknown
> session` when an inventory report arrives, and
> `yuzu_server_gateway_route_desync_total{op="renew_leases",outcome="unknown_session"}`
> rising while `/health` `agents.online` stays at 0. With `--log-level debug`
> the server also logs `BatchHeartbeat: unknown session` and `0/1 acked`.
> Observed on one local development rig after a SIGKILL of the server with an
> immediate restart (about 5 to 13 s of downtime across the four samples), with
> one agent; graceful shutdown, longer downtime and multiple agents or replicas
> were not tested. A command to the agent was still delivered while its route
> lease was unexpired (the lease runs 90 s from the last heartbeat the previous
> server ingested, so the window after the restart is 90 s minus that
> heartbeat's age at the kill minus the downtime) and was refused (503)
> afterwards; if the previous server had ingested no heartbeat there was no
> such window; the server did not relearn the session in the observed windows
> (to about 125 s). A full restart of the server, the gateway and the agent
> restored it (the one agent tested; for a fleet this would mean every agent
> behind that gateway, which was not tested); that is the only recovery
> observed and is NOT a recommended procedure (restarting only the gateway, or
> only the agent, was not tested). The gateway-side fix is tracked in #1197;
> this note will be revised when it ships.

---

## Building and Testing

### Prerequisites

- Erlang/OTP 26 or later
- rebar3

### Build

```bash
cd gateway
rebar3 compile
```

### Run Tests

```bash
cd gateway
rebar3 ct --dir apps/yuzu_gw/test
```

To run a specific test suite:

```bash
rebar3 ct --dir apps/yuzu_gw/test --suite yuzu_gw_agent_SUITE
```

### Create a Release

```bash
cd gateway
rebar3 release
```

The release is written to `_build/default/rel/yuzu_gw/`.

### Production Release

```bash
cd gateway
rebar3 as prod release
```

Production releases include the Erlang runtime (`include_erts: true`) for
self-contained deployment.

### Run the Release

```bash
_build/default/rel/yuzu_gw/bin/yuzu_gw foreground
```

### Interactive Shell (Development)

```bash
cd gateway
rebar3 shell
```

This starts the gateway with all applications loaded, useful for debugging.

### Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| grpcbox | 0.17.1 | gRPC server and client (HTTP/2, protobuf) |
| gpb | 4.21.7 | Protobuf compiler and runtime |
| telemetry | 1.3.0 | Metrics event API |
| prometheus | 4.11.0 | Prometheus exposition |
| prometheus_httpd | 2.1.2 | HTTP endpoint for Prometheus scraping |
| recon | 2.5.5 | Production introspection |
| gproc | 1.0.0 | Extended process registry |

Test-only dependencies (loaded in the `test` profile):

| Dependency | Version | Purpose |
|---|---|---|
| meck | 0.9.2 | Mocking framework |
| proper | 1.4.0 | Property-based testing |

---

## Gateway Clustering

> **Status: cluster FORMATION implemented (HA WS-4 `#4555`, ADR-2002 §7b);
> adjacency/load-shedding/latency-redistribution below remain PLANNED
> (Issue 7.1.1 / WS-4 4.4).**

Multiple gateway nodes now form a real distributed-Erlang mesh: each node
runs an always-on redial loop (`yuzu_gw_cluster_discovery`) that resolves
peer addresses — by default a DNS lookup on a configurable seed name
(`YUZU_GW_SEED_DNS_NAME`, default `gateway`, matching the reference Compose
service name — a scaled `docker compose up --scale gateway=N` needs zero
extra config), or an explicit `YUZU_GW_SEED_NODES` address list for a no-DNS
deployment — and connects to each via `net_kernel:connect_node/1`, forever,
on a fixed interval (no backoff). Every gateway replica shares one fixed
short name and is distinguished only by an address resolved at boot
(`YUZU_GW_ADVERTISE_ADDR`, auto-detected by default); nodes are otherwise
interchangeable. A node that finds no peers boots standalone anyway and
keeps retrying — cluster formation is fail-open, never a new way for a
discovery hiccup to become an agent-facing outage. See ADR-2002 §7b for the
full mechanism-choice record and `docker-compose.reference-gateway-cluster.yml`
for a runnable demo.

**Retry has no backoff, by design** (self-healing must stay prompt), which
also means a persistently misconfigured `YUZU_GW_SEED_DNS_NAME` causes every
node to re-query the seed name every 5s indefinitely — DNS query volume
scales linearly with cluster size. Bounded/negligible at the reference rig's
scale; if you operate a cluster large enough for this to matter against
shared DNS infrastructure, treat the redial interval
(`YUZU_GW_CLUSTER_REDIAL_INTERVAL_MS`) as a tuning knob.

Forming the mesh is what makes HA WS-4 4.3a's per-agent cross-node `pg`
routing (agents connecting to a *different* node than the one dispatching a
command) actually take effect — before `#4555`, that routing code was
component-complete but inert, since `pg` group membership only replicates
across *connected* nodes.

**Not yet implemented** — the adjacency table, load-shedding, and
latency-based redistribution features below, which build ON TOP OF the mesh
`#4555` forms, remain the rest of WS-4 4.3 and 4.4:

> **Note:** the `cluster_id` config key (see [Configuration](#configuration))
> is a separate, logical trust-zone/region identifier — a database key for
> the routing directory (HA WS-4 4.1, ADR-2002 §7) — distinct from
> `YUZU_GW_SEED_DNS_NAME` above, which is what to *resolve* to find peers.
> Two gateway nodes can share a `cluster_id` without being meshed, or (in a
> misconfiguration) be meshed without sharing one — the mesh and the logical
> cluster identity are independently configured.

### Planned Features

**Adjacency table:** Each gateway node maintains a routing table mapping agent
IDs to the owning node. When a command targets an agent on a different node,
the router forwards it via Erlang distribution.

**Load shedding via GOAWAY:** When a gateway node is overloaded, it sends
HTTP/2 GOAWAY frames to agents, causing them to reconnect. A load balancer
directs them to less-loaded nodes.

**Agent absorption:** When a gateway node shuts down (planned or crash), its
agents reconnect and are absorbed by the remaining nodes. The adjacency table
is updated via Erlang's node monitoring (`net_kernel:monitor_nodes/1`).

**Latency-based redistribution:** Agents periodically report their round-trip
latency to the gateway. If a closer node is available, the agent is migrated
via a controlled GOAWAY + reconnect cycle.

**Stability mechanisms:**
- Cooldown period after redistribution to prevent oscillation.
- Hysteresis thresholds -- an agent is only migrated if the latency improvement
  exceeds a configurable minimum.
- Rate limiting on GOAWAY frames to prevent thundering herd.

---

## Prometheus Metrics

**Status: PARTIALLY IMPLEMENTED**

The gateway exposes Prometheus metrics on a configurable HTTP port (default:
9568). The `yuzu_gw_telemetry` module defines telemetry events, and
`yuzu_gw_gauge` periodically emits gauge values.

### Available Metrics

Names, types, and labels below are taken from the emitting source
(`gateway/apps/yuzu_gw/src/yuzu_gw_telemetry.erl`) and match the canonical
gateway list in [`docs/grafana/README.md`](../grafana/README.md). Only metrics
that are actually emitted are listed.

| Metric | Type | Description |
|---|---|---|
| `yuzu_gw_agents_current` | gauge | Agents currently connected to this gateway node (label `node`) |
| `yuzu_gw_agents_connected_total` | counter | Total agent connections since startup (label `node`) |
| `yuzu_gw_agents_disconnected_total` | counter | Total agent disconnections (label `node`) |
| `yuzu_gw_commands_dispatched_total` | counter | Commands dispatched to agents (label `plugin`) |
| `yuzu_gw_commands_timed_out_total` | counter | Commands that timed out before a response |
| `yuzu_gw_commands_dropped_backpressure_total` | counter | Commands dropped because an agent's send buffer was full |
| `yuzu_gw_stream_write_errors_total` | counter | Agent stream write errors |
| `yuzu_gw_command_duration_ms` | histogram | Command dispatch duration in ms (labels `plugin`, `status`) |
| `yuzu_gw_agent_session_duration_ms` | histogram | Agent session duration in ms (label `node`) |
| `yuzu_gw_upstream_rpc_duration_ms` | histogram | Upstream (gateway→server) RPC latency in ms (label `rpc_name`) |
| `yuzu_gw_upstream_rpc_errors_total` | counter | Upstream RPC errors (labels `rpc_name`, `code`) |
| `yuzu_gw_registration_replay_total` | counter | Agents re-proxied upstream by the registration-replay drip after an upstream reconnect |
| `yuzu_gw_registration_replay_queue_depth` | gauge | Agents still queued for registration replay (0 = idle, label `node`). A persistently non-zero value indicates a replay that never drains — alert on it. |
| `yuzu_gw_cluster_peers_resolved` | gauge | Peer addresses found by the cluster-formation redial loop's most recent tick (label `node`; HA WS-4 `#4555`). 0 is expected for a genuinely single-node deployment. |
| `yuzu_gw_cluster_peers_connected` | gauge | Distribution-connected peer nodes as of the most recent redial tick (label `node`; `#4555`). Compare against `peers_resolved` — a sustained gap most often means a distribution-cookie mismatch across replicas. |
| `yuzu_gw_cluster_connect_failures_total` | counter | Total `net_kernel:connect_node/1` failures from the redial loop (`#4555`). |
| `yuzu_gw_cluster_address_cap_exceeded_total` | counter | Total times the lifetime distinct-address cap (`cluster_max_lifetime_addrs`) refused a never-before-seen address (`#4555` review round 2). Any non-zero value should be investigated immediately — it means the seed DNS name is returning an unexpectedly large or rotating/hostile answer set. |
| `yuzu_gw_heartbeat_rejected_total` | counter | Agent `Heartbeat` calls rejected before buffering because no usable session binding exists (label `reason`, closed set: `unknown_session` = the session is not held by this node, `no_connection` = no connection key to compare, `registry_unavailable` = the session index does not exist). Every reason is created at 0 at start. The agent re-registers on the `NOT_FOUND` answer when its build includes the reconnect fix (see the gateway manual); older agents only log it. A held session whose heartbeat arrived on a different connection is counted in the next row instead. See [Heartbeat admission](#heartbeat-admission). |
| `yuzu_gw_heartbeat_session_mismatch_total` | counter | Agent `Heartbeat` calls rejected because the session is held by this node but the call arrived on a different connection than the one that opened it (label `event`, always `security`, for SIEM routing; created at 0 at start). Also rises when an HTTP/2 proxy between agents and the gateway spreads one agent's calls over several connections. A rise of one per affected agent is expected when an agent's connection is replaced while its session is still held (observed with an injected GOAWAY, a test-only trigger; not observed with an abrupt close or a gateway restart). There is no audit row (the sender of a rejected heartbeat is not a resolved principal): the counter and a rate-limited summary log line are the signal. |

The full set of gateway metrics (BEAM scheduler/memory gauges, fan-out and
queue-length histograms, circuit-breaker and cluster counters) is registered in
`yuzu_gw_telemetry.erl`; see [`docs/grafana/README.md`](../grafana/README.md)
for the canonical catalogue.

### Planned Metrics (Not Yet Implemented)

| Metric | Type | Description |
|---|---|---|
| `yuzu_gw_agent_migrations_total` | counter | Agents migrated between nodes |
| `yuzu_gw_goaway_sent_total` | counter | GOAWAY frames sent for load shedding |

(`yuzu_gw_cluster_nodes` — cluster size — is superseded by
`yuzu_gw_cluster_peers_connected` above, shipped with `#4555`; this node's
total cluster size is `peers_connected + 1`.)

### Scrape Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'yuzu-gateway'
    static_configs:
      - targets: ['gateway-host:9568']
    scrape_interval: 15s
```

---

## Reference

- `docs/erlang-gateway-blueprint.md` -- Full architecture blueprint with
  detailed process model, message flow diagrams, and design rationale.
- `proto/yuzu/gateway/v1/gateway.proto` -- GatewayUpstream protobuf definition.
- `gateway/config/sys.config` -- Default configuration.
- `gateway/config/vm.args.src` -- Erlang VM arguments (`.src` = env-substituted
  at boot; supplies the distribution cookie from `YUZU_GW_COOKIE`).
- `gateway/rebar.config` -- Build configuration and dependencies.
