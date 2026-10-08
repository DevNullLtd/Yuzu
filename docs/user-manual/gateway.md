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
| `yuzu_gw_upstream` | gRPC client to the C++ server: one channel, one HTTP/2 connection, one call at a time (see "Registration rate per gateway" under [What happens when the server restarts](#what-happens-when-the-server-restarts)) |
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
default 1000 ms, valid 100 to 60000; env override `YUZU_GW_HEARTBEAT_INTERVAL_MS`).

This reduces upstream load from O(agents/interval) to O(nodes/interval).

On RPC failure, the buffered heartbeats are retained for retry on the next
flush cycle rather than being silently discarded. The retained buffer is bounded
in sessions and in bytes (see below).

**One entry per session.** The buffer holds at most one entry per session. A
newer heartbeat for a session that already has an entry replaces the fields of
the older one (the newest status tags and sent time win), except that the newest
non-empty `fleet_snapshot_json` is kept: an agent attaches a snapshot only when
it has a new one and does not resend it, so a replacement that carried no
snapshot must not erase the last one. `yuzu_gw_heartbeat_coalesced_total` counts
each replacement.

**Chunked flush.** A flush is split into chunks of at most about 3 MiB
(estimated), oldest first, so that a `BatchHeartbeat` request the gateway builds
stays under the server's gRPC receive limit of 4194304 bytes (4 MiB). The verdict
of each chunk that succeeds is consumed as usual (see
[What happens when the server restarts](#what-happens-when-the-server-restarts)).
A flush sends at most 8 chunks (about 24 MiB) per cycle (one cycle is
`heartbeat_batch_interval_ms`, 1 s by default); what is left stays buffered for
the next cycle, so a long backlog drains over several cycles. A chunk that fails
for a transient reason (the server is unreachable, a timeout), and the chunks not
yet sent, stay buffered for the next flush; transient server trouble does not lose
heartbeats. A chunk the server rejects with a non-transient status (for example
`RESOURCE_EXHAUSTED`) is split in halves and retried when it holds more than one
heartbeat (a few extra RPCs per bad heartbeat), and a single heartbeat that is still rejected is dropped and counted
(`yuzu_gw_heartbeat_buffer_dropped_total{reason="chunk_rejected"}`), so that it
cannot block the newer heartbeats behind it. A single heartbeat that is by itself
larger than 3 MiB is sent without its snapshot
(`yuzu_gw_heartbeat_buffer_dropped_total{reason="snapshot_oversize"}`, counted
only when a snapshot was present). A heartbeat that is still larger than 3 MiB
after its snapshot is removed (for example from very large status tags), or that
carries more than 512 status tags, or whose status tags are large by themselves (one
tag key or value over about 64 KiB, or more than about 256 KiB of tag bytes in
total), is kept but loses all of its status tags, and is counted
(`reason="heartbeat_oversize"`). The tag size check runs before the UTF-8 repair
described next, so a heartbeat of that size is never repaired: repairing several MiB
of invalid bytes was measured by a security reviewer (a scratch probe, not a rig run)
at 24 ms of the single heartbeat buffer process for 3 MiB, which a misbehaving agent
could repeat on every heartbeat. A heartbeat with a status tag that is
not valid UTF-8 (and within those bounds) is kept with the invalid bytes replaced by replacement
characters, and is counted (`reason="heartbeat_invalid"`). Neither case is
retried or dropped whole, so a session that sends oversized or invalid tags on
every heartbeat still renews its lease and keeps its other telemetry; only the
tags are lost or repaired. A heartbeat whose session id is empty or not valid
UTF-8 is still dropped and counted as `heartbeat_invalid`; heartbeat admission
already rejects such ids, so this is a safety net. The reason is wider than
the metric's HELP text, which is kept short and says only "repaired":
`heartbeat_invalid` counts (a) a status tag with invalid UTF-8 that was repaired
(heartbeat kept), (b) the status tags removed because they were not a map or a
tag was not a binary (heartbeat kept), (c) a heartbeat dropped for an empty or invalid session id, and
(d) a heartbeat the request encoder raised on in a failed chunk, which is dropped.
Before these drop reasons existed, one heartbeat
over the server's 4 MiB limit (5 to 8 MiB of status tags; the gateway had no
inbound size cap) blocked every newer heartbeat until its own session heartbeated
again (verified by two reviewers with a fake server and a real registered agent;
not run on a rig), and an invalid UTF-8 heartbeat made the buffer process crash
and lose every buffered heartbeat (found by a review probe, not on a rig; the
crash was there before this work). On a rig the largest chunk observed was
3,142,583 bytes, under the 3 MiB packing
limit of 3,145,728 bytes; chunk sizes are in no log or metric. The line
`Flushed N heartbeats in M chunk(s)` is logged at INFO only when a flush needed
more than one chunk (M greater than 1) and at DEBUG otherwise.

**Server status codes the gateway reads as "drop this heartbeat".** The gateway
reads `RESOURCE_EXHAUSTED` and `INVALID_ARGUMENT` on `BatchHeartbeat` as a verdict
on the request itself, not on the server's health: the chunk is split and, for a
single heartbeat, dropped and counted as `chunk_rejected`, as described above.
Any other failing status is treated as transient and keeps the data buffered. The
server does not use either of those two codes on this call today (OBSERVED by
reading the handler: it answers only OK or CANCELLED; the one source of
`RESOURCE_EXHAUSTED` on this call is the gRPC receive size limit). A proxy between
the gateway and the server, or a future server change, that returned
`RESOURCE_EXHAUSTED` to ask for a slower rate would therefore make the gateway
drop heartbeats instead of retrying them; use a different status for that case.

**Bounds on the retained buffer.** `max_heartbeat_buffer` (default 10000) is a
number of sessions. When the buffer holds that many sessions, a heartbeat of a
new session is dropped and counted
(`yuzu_gw_heartbeat_buffer_dropped_total{reason="buffer_full"}`); a heartbeat of a
session that already has an entry is still accepted, because it replaces that
entry. `max_heartbeat_buffer_bytes` (default 64 MiB; see "Heartbeat buffer
bounds" under Configuration) caps the bytes the buffer retains. When the buffer is over that cap, snapshots are dropped
oldest first
(`yuzu_gw_heartbeat_buffer_dropped_total{reason="snapshot_evicted"}`), and only when
no entry holds a snapshot any more is the oldest whole session dropped (counted as
`reason="buffer_full"`). What is lost is only older heartbeat state: the agent
sends its next heartbeat on its own interval. The same holds for a dropped
`chunk_rejected` heartbeat: one heartbeat is lost, and the agent sends the next on
its own interval. A `heartbeat_oversize` or `heartbeat_invalid` heartbeat is not
lost: it is forwarded, so liveness is unaffected, and only its status tags are
dropped or repaired.

**Consequences.**

- `yuzu_heartbeats_received_total{via="gateway"}` on the server under-counts while
  a backlog is coalesced. It counts the heartbeats the server received, and fewer
  arrive when several heartbeats of one session are merged into one. It is not a
  count of the heartbeats the agents sent, so do not read a fall in it during or
  just after a server outage as agents going quiet; read
  `yuzu_gw_heartbeat_coalesced_total` and `yuzu_gw_agents_current` beside it.
- After a snapshot is evicted, the topology snapshot the server holds for that
  agent can be older by one agent snapshot cycle (INFERRED from the agent proto
  comment: the agent produces a new snapshot about once a minute and does not
  resend one it already sent).
- The server's gRPC receive limit of 4 MiB is unchanged and is not raised. The
  gateway keeps each request under it instead.

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
removes the per-agent separation the check relies on. The gateway also caps the
agent sessions one connection may hold (`max_sessions_per_connection`, default 8;
see "Per-connection session cap" under Configuration). See
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
  count alone: in rig run 4, agents that stayed rejected (observed with v0.12.0) and agents that had been killed were still
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

The router clamps the `timeout_seconds` of a `SendCommand` request to 1 to 3600
seconds. A missing, non-positive or non-integer value uses the application env key
`default_command_timeout_s` (valid 1 to 3600), and 300 seconds when that key is
unset or invalid. The key is read by the router each time a command arrives with no
timeout of its own, and an invalid value logs at most one warning per minute per
router process (a restarted router can warn again at once). A `SendCommand` that arrives on the management API while the
router process is unavailable (for example during its restart) is answered with
gRPC `UNAVAILABLE` (14); it used to be answered `INTERNAL`. The warning in the
gateway log is the existing safe-call limiter's warning, at most one per second per
called process, and names only the class of the failure (`noproc`, `timeout` or
`other`); it is not a new warning. A registry that is unavailable during a
`Register` is still answered `INTERNAL` (13). A negative timeout used to crash the router, and the crash report
printed the command request including its parameters (OBSERVED by a security
review probe with the real application and a marker value, not on a rig); see the
crash report entry under "Known limits".

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
server with nothing unknown look the same on the wire, by design. The gateway
reads both fields on every successful `BatchHeartbeat` response: it keeps the
ids that are non-empty binaries of at most 64 bytes, de-duplicates them, passes
at most 4096 of them to the upstream client, and replays exactly the sessions it
still holds through the registration-replay drip (see
[What happens when the server restarts](#what-happens-when-the-server-restarts)).
A truncated list is counted and logged, and the omitted sessions may be reported
again by later heartbeats. An empty list, or a response without the fields (an
older server), changes nothing.

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

    %% No effect: no gateway code reads this key. The upstream channel is one
    %% connection whatever the value (see "Registration rate per gateway")
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

**Registration replay tuning** (application env keys read by the upstream
client at start, except `upstream_call_timeout_ms`, which is read on every call; set them in the `yuzu_gw` section of `sys.config`. No
`YUZU_GW_*` environment variable maps to any of them):

| Key | Default | Valid range | Meaning |
|---|---|---|---|
| `registration_replay_spacing_ms` | 20 | 0 to 60000 | Gap between two replay `ProxyRegister` calls in the replay drip |
| `registration_replay_session_guard_ms` | 10000 | 0 to 3600000 | A session that was just replayed is not queued again by a heartbeat verdict until this many ms have passed. The stamp is taken when the replay is sent, so a stale verdict can arrive up to the 5 s flush deadline (the vendored grpcbox client default) plus the replay RPC time later (INFERRED from the code): do not set it below 5000 plus the expected replay RPC time, because a smaller guard lets such a stale verdict replay a session the server already knows; the default 10000 is safe (see "Replaying a session the server already knows is not free" under [What happens when the server restarts](#what-happens-when-the-server-restarts)) |
| `registration_replay_queue_max` | 10000 | 1 to 1000000 | Most agents the replay queue holds when a heartbeat verdict appends to it; there is one pending entry per agent, and an id past the cap is counted in `yuzu_gw_heartbeat_verdict_dropped_total{reason="queue_full"}` (so is an id in a verdict that the heartbeat buffer did not cast because the upstream client's mailbox held more than 100 messages, see "Heartbeat batching interval" below). The cap bounds only verdict appends: the snapshot a breaker recovery seeds is not capped (it is bounded by the number of agents the node holds, as before), and while a snapshot of this size or larger drains, every verdict id for an agent not already queued counts as `queue_full` |
| `upstream_call_timeout_ms` | 30000 | 100 to 300000 | How long `yuzu_gw_upstream:proxy_register/1` and `proxy_inventory/1` wait for the upstream client before the call gives up with `{error, upstream_unavailable}` and one caller-side warning that names the class `timeout`. Read on every call, not at start. It exists so a test can exercise the timeout without waiting 30 s, and it also works as a setting. A value outside the range, or one that is not an integer, falls back to the default with a WARN that names the key |

An invalid value for any of these keys falls back to the default and logs a
warning that names the key. See
[What happens when the server restarts](#what-happens-when-the-server-restarts).

**Upstream channel tuning** (read once, by `yuzu_gw_app` before the supervision
tree starts; set it in the `yuzu_gw` section of `sys.config`. No `YUZU_GW_*`
environment variable maps to it, so a compose deployment cannot switch it off
through the environment; it takes a `sys.config` edit):

| Key | Default | Valid values | Meaning |
|---|---|---|---|
| `upstream_tcp_nodelay` | `true` | `true` or `false` | Sets TCP_NODELAY on the gateway-to-server (upstream) gRPC channel. Without it, every upstream call with a request under about 64 KiB waited about 41 to 43 ms for Nagle's algorithm and the server's delayed ACK, which capped registration at about 24 agents per gateway per second (see "Registration rate per gateway"). At start the gateway restarts grpcbox's `default_channel` with `{nodelay, true}` added to the `socket_options` of each endpoint; the channel connects on its first call, so the restart drops no connection and existing `sys.config` files need no edit. Other `socket_options` of an endpoint are kept, and a `nodelay` entry you set there yourself wins (a hand-set `{nodelay, false}` keeps Nagle on that endpoint). It applies only to the upstream channel, not to the agent listener or the management channel. A value that is not a boolean logs a warning that names the key and uses the default `true`. `false` logs one INFO line and leaves the channel as configured. If the restart fails, one WARN `could not restart it with TCP_NODELAY` is logged and the channel is restored with the endpoints as configured; if that restore fails as well, one further WARN `could not restore it with the endpoints as configured either` is logged, and the node then has no upstream channel (the restart itself was observed on a rig in pass 6, run K0; the restore paths are read from the code and its eunit tests, not run on a rig). |

**Heartbeat batching interval** (read by the heartbeat buffer at start; unlike
the replay keys above, it also has an environment override):

| Key | Environment override | Default | Valid range | Meaning |
|---|---|---|---|---|
| `heartbeat_batch_interval_ms` | `YUZU_GW_HEARTBEAT_INTERVAL_MS` | 1000 | 100 to 60000 | How often the buffered heartbeats are flushed in one `BatchHeartbeat` RPC. A value outside the range logs one warning that names the key and falls back to the default (INFERRED: the range check also applies to a value set through the environment override, because the override writes the same application key at start) |

The buffer also skips casting a verdict to the upstream client when the upstream
client's mailbox holds more than 100 messages. Those session ids are counted in
`yuzu_gw_heartbeat_verdict_dropped_total{reason="queue_full"}` and one DEBUG line
is logged; the sessions are listed again by later heartbeats (INFERRED). So
`queue_full` means either that the replay queue is at its cap or that the upstream
client has a message backlog.

**Heartbeat buffer bounds**

Application env keys read by the heartbeat buffer at start (set them in the
`yuzu_gw` section of `sys.config`):

| Key | Default | Valid range | Meaning |
|---|---|---|---|
| `max_heartbeat_buffer` | 10000 | not range-checked (use a positive integer) | Most sessions the buffer holds. The buffer keeps one entry per session, so this counts sessions, not heartbeats. When it is full, a heartbeat of a new session is dropped and counted in `yuzu_gw_heartbeat_buffer_dropped_total{reason="buffer_full"}`. |
| `max_heartbeat_buffer_bytes` | 67108864 (64 MiB) | 1048576 to 1073741824 | Most bytes (estimated) the buffer retains across a failed flush. When the buffer is over this cap, snapshots are dropped oldest first (`reason="snapshot_evicted"`); only when none is left is the oldest whole session dropped (`reason="buffer_full"`). A value outside the range logs one warning that names the key and falls back to the default. Do not set it below a few MiB: on a rig with the 1048576 minimum and 5 agents, `snapshot_evicted` kept rising after the server was back, because two snapshot-bearing heartbeats (about 0.8 MB each) landing in one 1 s flush window exceed that cap. The default 64 MiB was not observed to evict in the rig runs (see "Observed on a rig"). |

A flush is split into chunks of at most about 3 MiB (estimated), a fixed value
that is not configurable, and sends at most 8 chunks (about 24 MiB) per flush
cycle, also fixed; the rest stays buffered for the next cycle. A heartbeat larger
than the chunk limit after its snapshot is removed, or whose status tags exceed the
tag bounds (about 64 KiB for one key or value, about 256 KiB in total), is kept
without its status tags and counted (`reason="heartbeat_oversize"`, see "Heartbeat
Batching"). The bound is checked before the UTF-8 repair walk runs. What a stock
agent sends is far below it: at most 8 tags per plugin with a key suffix of at most
32 characters and a value of at most 64 bytes (read from
`agents/core/src/plugin_heartbeat_tags.hpp`), so about 70 KiB for 50 plugins
(arithmetic), plus about 25 `yuzu.*` tags and one list-valued tag of a few KiB. Size the byte cap for the largest backlog you want to
survive: each session's entry can carry a snapshot of several hundred KB (observed
on one rig, see "Known limits" below), so 64 MiB holds roughly 80 to 330 such
snapshots at once (arithmetic on the default and the observed 200 to 800 KB range,
not measured). See
[Heartbeat Batching](#heartbeat-batching).

**Per-connection session cap** (application env keys; set them in the `yuzu_gw`
section of `sys.config`; both are read once, when the registry process starts, so
a change needs a gateway restart):

| Key | Default | Valid range | Meaning |
|---|---|---|---|
| `max_sessions_per_connection` | 8 | 1 to 1000 | Most session slots one gRPC connection may hold. Each unexpired reservation row (a `Register` that was admitted and is not yet answered by the server, see below) is one slot, including the registering agent's own in-flight reservations. Another agent's live row counts one; another agent's committed pending row (registered and not yet subscribed) counts one only if that agent has no reservation in flight. The registering agent's own live row and committed pending row never count, because a commit supersedes them, and the `Subscribe` path leaves out all of that agent's own rows. A `Register` is admitted while fewer than the cap of those slots are held, so a connection holds at most the cap of counted slots plus the registering agent's own live row and committed pending row; the stored rows can briefly exceed that by the committed pending row of an agent that has a retry in flight, which its commit removes. A slot is reserved inside the registry process, which handles one call at a time, when a `Register` is admitted and before it is proxied to the server, so N concurrent `Register` calls on one connection, whether they carry one agent id or several, admit at most the cap and nothing beyond it is proxied (a retry made while an earlier `Register` of the same id is in flight uses one more slot until that one is released or committed). The reservation row is turned into the pending row by a commit step once the server accepted the registration; it is released if the proxied `Register` fails or is not accepted, and a handler that is killed while its `Register` is proxied leaves a reservation that the pending time to live (120 s, swept every 60 s) removes. Over the cap, a `Register` is answered `UNAVAILABLE` (14) and a `Subscribe` ends its stream (status 2 today, see Known limits); both are counted in `yuzu_gw_session_limit_rejected_total` and logged as a warning at most once per second that names only the cap. A value outside the range falls back to the default and logs one warning that names the key. |
| `dead_connection_grace_ms` | 15000 | 0 to 120000 | How long the reserved and pending rows of a connection that went down stay takeable. The registry monitors each connection once; when it goes down its rows are not dropped at once, so that a `Subscribe` on a reconnected channel can still take a pending session after the connection was closed with a GOAWAY. Without the grace, a released agent v0.13.0 or v0.14.0-rc6 would be answered `NOT_FOUND` and wedge (INFERRED from bug #2182, see "Agent dependency"; not run for this key). When the grace has passed, the reserved and committed pending rows that the connection's index names are deleted, each by its key (the cost is that connection's rows, never a scan of the pending table), so a client that reconnects over and over neither starts again below the cap nor leaves its stored registration requests to wait for the time to live. A row that a handler stored and has not committed yet is in no index and survives the removal: it is removed when its own commit finds the connection down and monitors it again, or by the pending time to live sweep (120 s time to live, swept every 60 s) if its handler died (read from the code and its eunit tests, not rig-run). `0` drops them at once. A value outside the range falls back to the default and logs one warning that names the key. |

The cap exists so that one connection cannot hold many pending sessions with large
snapshots and, while the upstream is not draining the heartbeat buffer, push other
agents' snapshots out of a full buffer first. OBSERVED by a security review probe
against the real application with a fake upstream that was not draining: all the
other agents' snapshots were evicted; the same probe did not reproduce it with a
healthy upstream. A stock agent holds one session per connection (INFERRED from the
one-connection-per-agent rule under [Heartbeat admission](#heartbeat-admission)), so
deployments sit at 1 of 8 and the default is not expected to matter for the
supported topologies. An L4 balancer or proxy that multiplexes several agents onto
one HTTP/2 connection to the gateway would reach the cap, and the `Register` calls of
those agents would be answered `UNAVAILABLE` (a refused `Subscribe` ends its stream);
the operator raises the key (an HTTP/2-terminating proxy is
already unsupported, see "Supported topologies").

Both counts come from per-connection indexes that only the registry process writes,
so a count costs the rows of that connection, never a scan of the pending table.
The count is released on every path that ends a session: deregister, supersede, a
session process that died, a pending session taken by `Subscribe`, the pending time
to live (120 s), and a connection that went down (after the grace above).

A repeated `Register` of the same agent id on the same connection leaves exactly
one committed pending row: the one with the newest stamp (of equal stamps, the last
commit handled). A `Register` whose commit finds its own row already gone, or a
newer committed row of the same agent (it was superseded), is answered
`UNAVAILABLE` (14, "Registration superseded by a newer registration") and logged at
INFO as `Register superseded by a newer registration` (the line carries no request
and no agent id), and leaves no row of its own. That answer used to be `INTERNAL`
(13, `registry_unavailable`, a WARN line); `registry_unavailable` now stays for a
registry that cannot be reached (a missing table, a timeout) and for a row lost
with a registry restart. The agent registers again: the agent retries any
non-OK `Register` status with its reconnect backoff (read from
`agents/core/src/agent.cpp`; the delay itself is not stated here). The server may
hold a session for that refused `Register` that nobody subscribes to (INFERRED
from the code).

Review history. Two independent security reviews found two gaps in an earlier form
of the cap, both with probes against the real application and a fake upstream, not
on a rig. First, the same agent id repeating `Register` without `Subscribe` stored
unlimited pending sessions (OBSERVED: 40 accepted with a cap of 8; 150 `Register`
calls with 3.5 MB payloads held 510 MiB until the 120 s pending time to live).
Second, the early check was not atomic with the step that stores the pending
session (OBSERVED: with 200 concurrent `Register` calls, about 121 passed the check
and were proxied to the server while 8 pending rows were stored, so about 113
server sessions per burst never subscribed). The later review rounds found three
more, all fixed in this change: two `Register` calls of one agent id that committed
together could leave no pending row (fixed by the commit rule above); the pending
rows of a closed connection stayed until the time to live (fixed by the grace);
and counting pending rows scanned the whole pending table (fixed by the
per-connection index). An adversarial review by two external models then found
that the atomic reservation did not bound concurrent `Register` calls that carry
one agent id: the registering agent's own reservations were left out of the count,
so all of them were admitted and proxied to the server (both reviewers reproduced
it with probes against the real application and a fake upstream, not on a rig: 20
of 20 and 300 of 300 admissions at cap 8). It is fixed in this change: each
in-flight reservation counts, the handler-level test makes 20 concurrent same-id
calls at cap 8 and sees exactly 8 reach the upstream call and 12 answered
`UNAVAILABLE`, and the rig passes below ran earlier code and did not exercise it
(the 200 concurrent calls of pass 5 used distinct ids).

OBSERVED on a rig (pass 5, build `e3cf6b38a`, default cap 8, one probe connection,
20 real agents live): 9 distinct agent ids registered one after the other, the
first 8 accepted and the 9th refused `UNAVAILABLE`, and after the 8 sessions were
closed the cap was reached again exactly (no leaked slot); the same agent id
registering 40 and then 120 times with a 1 MiB payload each left one pending row
at every sample; 200 concurrent `Register` calls with distinct ids on one
connection admitted 8, refused 192, and 8 of them reached the server (the same
probe on the previous code, `ab01f4f2f`, admitted 8 but let 153, 157 and 153
through to the server in three runs). The pending index, the same-agent commit
rule and the grace (commits after `e3cf6b38a`) were checked by eunit, dialyzer,
Common Test and scratch probes against a fake upstream, NOT run on a rig.

Residuals, stated as they are: (1) a handler that dies between inserting its
pending row and committing it leaves one row with no index entry; it is not
counted by itself (its reservation is), and the pending time to live sweep removes
it. The same holds for a row of a connection that went down before that row was
committed: the removal after the grace follows the connection's index, so that
row stays until its own commit finds the connection down or the sweep removes it. (2) A reserve call that times out at 5 s can leave a reservation until the time
to live. (3) The live insert can be refused in the brief gap between `Subscribe`
taking the pending row and the live insert, because a slot is free for a moment and
another `Register` can take it; the agent retries (INFERRED: about 2 s later) and no
proxied `Register` is left without a pending row. (4) Behaviour with real agents
near the cap and with an L4 forwarder multiplexing agents was not run, and the
default of 8 is a chosen value, not one derived from fleet data.

**Circuit breaker tuning** (the breaker the replay and the other upstream calls
share; read once when the upstream client starts, not range-checked, and each key
has an environment override, unlike the replay keys above):

| Key | Environment override | Default | Meaning |
|---|---|---|---|
| `circuit_breaker_failure_threshold` | `YUZU_GW_CB_FAILURE_THRESHOLD` | 5 | Consecutive failed upstream calls that open the breaker |
| `circuit_breaker_reset_timeout_ms` | `YUZU_GW_CB_RESET_TIMEOUT_MS` | 10000 | How long the breaker stays open the first time before it goes half open and allows one probe RPC |
| `circuit_breaker_max_reset_timeout_ms` | `YUZU_GW_CB_MAX_RESET_TIMEOUT_MS` | 300000 | Cap on the open duration, which doubles each time a trip or a failed probe reopens the breaker (10 s, 20 s, 40 s, 80 s and so on) and returns to the first value when a probe succeeds. This is the 300 s the recovery bounds in "What happens when the server restarts" cite |


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
| agent → gateway (`:50051`) | **one-way TLS (PR5c)** | Server-authenticated TLS, no client cert required (bootstrap-safe). Enabled on the agent listener in `sys.config.prod` via `transport_opts => #{ssl => true, certfile, keyfile, cacertfile, verify => verify_none, fail_if_no_peer_cert => false}` (needs the vendored `_checkouts/grpcbox`). Of the shipped composes, only `docker-compose.reference-gateway.yml` enables it (#1314, mounting `reference-gateway-sys.config`). The cluster, demo, full-UAT, viz-UAT and sanitizer-UAT composes, and the repo-root `docker-compose.uat.yml`, run plaintext on the shipped default or a UAT/demo `sys.config` (inline in `docker-compose.uat.yml`, mounted as a file by the others); the remaining composes do not run the gateway. Heartbeats are bound to the connection that opened the session's `Subscribe` stream (see [Heartbeat admission](#heartbeat-admission)); the agent listener itself still does not authenticate agents. |
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
distribution + TLS-dial wiring + a fail-closed guard when no CA can be pinned,
#1303) is shipped, and the reference gateway compose (#1314) is the worked example. The
flag-day order below still applies when you enable the listener on an existing fleet.

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
can't forge an agent) arrives with the through-gateway attestation work (#1292, under #4722).

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
> cannot observe the direct agent peer; the grpcbox peer-address fix is tracked
> in #1172. Until then, SIEM/audit consumers correlating
> `source_ip` with network logs on this path will see the gateway's address.

### What happens when the server restarts

This section covers a server process restart while a gateway stays up and its
agents stay connected to it. The agents do not notice. The server keeps its
gateway sessions in memory, so a restarted server does not know them, and it
says so in every `BatchHeartbeatResponse` (see
[BatchHeartbeat Message](#batchheartbeat-message)). A gateway that reads that
answer re-registers the listed agents upstream without operator action. If the
gateway's circuit breaker opened during the outage, the verdict is dropped while
it is open and the breaker's own recovery replay re-registers the agents instead
(see "Several agents and a long outage" below).
Restart the gateway to deploy this behaviour; the wire format is unchanged, so
an old gateway with a new server, or a new gateway with an old server, still
works (the old pairing simply keeps the behaviour described under "Without the
reconcile" below).

**Upgrade day.** The server is upgraded first, so the server restart that ships
this fix meets the old gateway, and agents behind it can read offline after that
restart (the behaviour under "Without the reconcile" below; observed on one rig
after a SIGKILL restart, a graceful upgrade restart was not tested). Upgrade the
gateway and restart it: from then on a server restart recovers without operator
action. A gateway restart disconnects every agent that node holds, so it is a
fleet-wide reconnect for the node, and what the agents do next depends on their
build. OBSERVED (a graceful gateway restart, see "Connection drain" under
[Heartbeat admission](#heartbeat-admission) and "Agent dependency" below): released v0.13.0 and v0.14.0-rc6 agents with
default settings did not re-register and stayed wedged, and v0.12.0 never
re-registered; an agent build with the #5183 fix (bug #2182, in no release tag
yet) re-registered in 11 to 12 s. So before you restart the gateway, upgrade the
agents behind it to a build that includes #5183 where you have one, or expect to
restart the agent service on every released agent behind that gateway. Whether
restarting only the gateway recovers agents stranded by an earlier server restart
was NOT tested. INFERRED from the code: a reconnecting agent registers again
through the gateway and the running server accepts it, which holds only for an
agent build that re-registers by itself; released agents do not (see
"Agent dependency" below).

**What you should see** (new gateway and new server, one core replica):

| Where | Level | Line | Meaning |
|---|---|---|---|
| gateway | INFO | `Registration replay: heartbeat verdict named N session(s); queued Q, not local L, already queued A, within guard G, queue full F` | One verdict was handled. Logged at INFO when Q is at least 1, at DEBUG otherwise. It carries counts only, no session ids. |
| gateway | DEBUG | `Registration replay: re-proxied <agent> (adopted session <id>)` | One agent was re-proxied by the replay drip, one line per agent. |
| gateway | INFO | `Flushed N heartbeats in M chunk(s)` | A flush needed more than one chunk (about 3 MiB each), which is expected after a long server outage. It is logged at INFO only when M is greater than 1; a flush of one chunk is logged at DEBUG. The line carries counts only: no log line or metric shows the size of a chunk. |
| server | INFO | `[gateway] ProxyRegister succeeded: agent=..., session=<the pre-restart session id>` | The server accepted the replay and relearned the session under the id the agent already holds. |
| server | DEBUG | `[gateway] ProxyRegister: adopted presented session ... (store-confirmed=true)` | The presented session was adopted; `store-confirmed=true` when the routing directory confirmed it. |
| gateway | WARN | `Circuit breaker: OPEN (will probe in <ms>ms)` | The upstream circuit breaker opened. A verdict that arrives while it is open is dropped and counted in `yuzu_gw_heartbeat_verdict_dropped_total{reason="circuit_open"}`; the matching line `heartbeat verdict named N session(s) while the circuit is open; dropped` is DEBUG, so at the default log level you see the counter and this warning, not that line. While the breaker is open, the whole `/readyz` answer is 503 `not_ready` (`circuit_breaker` is false in its checks), and the shipped guidance is that a load balancer probes `:8081/readyz`, so an open breaker can take this node out of rotation (INFERRED from `yuzu_gw_health.erl`; not run). Wait: do not restart the gateway. The replay runs after the breaker goes half open (INFO `Circuit breaker: open -> half_open (allowing probe RPC)`; `/readyz` reads ready again from that point), and the probe closing it logs INFO `Circuit breaker: half_open -> closed (probe succeeded)`. |
| gateway | WARN | `Circuit breaker: half_open -> open (probe failed, increasing backoff)` | The probe RPC failed, so the server is still failing the gateway's calls and the breaker is open again for a longer time. Escalate to the server: check that it is healthy and reachable from the gateway. Restarting the gateway does not help and reconnects every agent it holds. |
| gateway | WARN | `Registration replay aborted: circuit open (N agent(s) not yet re-proxied)` | The breaker opened while the drip was running. The queue is dropped; the agents come back on a later verdict or on the next breaker recovery. |
| gateway | WARN | `Registration replay aborted: registry unavailable (N queued entries dropped)` | The gateway's registry process was down when the drip popped an entry, so nothing queued could be re-verified and the queue was dropped. This abort disconnects no agent. INFERRED from the code (not tested): a registry that died has lost its tables (see [Heartbeat admission](#heartbeat-admission)), so a later verdict finds no local session for these agents and counts them `not_local`; they are not listed again into the replay. They come back only through their own `NOT_FOUND` re-register path, which released v0.13.0 and v0.14.0-rc6 agents do not complete (see "Agent dependency" below). |
| gateway | WARN | `Registration replay: <agent> failed: <reason>` | A replay `ProxyRegister` failed. It counts as a failure for the shared circuit breaker (see "Replay failures feed the shared circuit breaker" below). |
| gateway | metric | `yuzu_gw_registration_replay_triggered_total{trigger="breaker"}` rising | The circuit breaker closed after an outage and the gateway replayed every agent this node holds. Expected after a long outage when the breaker opened (see "Several agents and a long outage" below). No action. |
| gateway | metric | `yuzu_gw_heartbeat_coalesced_total` rising | Newer heartbeats of a session are replacing older buffered ones, one at a time. Expected during a server outage: heartbeats pile up between failed flushes and are merged, so the buffer stays at one entry per session. No action. The server's `yuzu_heartbeats_received_total{via="gateway"}` falls short of the number of heartbeats the agents sent for the same reason; that is not a loss of agents. |
| gateway | metric | `yuzu_gw_heartbeat_buffer_dropped_total{reason}` rising | The buffer is under pressure, typically after a long server outage. `snapshot_evicted`: older snapshots were dropped to stay under `max_heartbeat_buffer_bytes`, oldest first. `buffer_full`: the buffer held `max_heartbeat_buffer` sessions and a heartbeat of a new session was dropped, or it was still over `max_heartbeat_buffer_bytes` with no snapshot left and its oldest whole session was dropped. `snapshot_oversize`: one heartbeat larger than about 3 MiB was sent without its snapshot (see "Known limits" below for the agent side). `heartbeat_oversize`: a heartbeat still larger than about 3 MiB after its snapshot was removed, or with more than 512 status tags, or with a status tag key or value over about 64 KiB or more than about 256 KiB of tag bytes in total (checked before the UTF-8 repair, so such a heartbeat costs no repair work), lost all of its status tags and was forwarded without them. `heartbeat_invalid`: a heartbeat with a status tag that was not valid UTF-8 was forwarded with the invalid bytes replaced by replacement characters. The reason also counts tags removed because a tag was not a binary and a heartbeat dropped for a bad or empty session id (see "Heartbeat Batching"). `chunk_rejected`: one heartbeat that the server rejected with a non-transient status (for example `RESOURCE_EXHAUSTED`) was dropped so that it does not block newer heartbeats. `heartbeat_oversize` and `heartbeat_invalid` mean an agent, or a plugin on it, sent oversized or invalid status tags: only the tags of those heartbeats are lost or repaired, and liveness is unaffected because the heartbeat itself is forwarded and the session keeps renewing its lease. `chunk_rejected` means the server refused one heartbeat, which is lost; the agent sends the next on its own interval. The metric has no agent label, so identify the agent from the gateway log or debug log if one names it, and upgrade or fix that agent or the plugin that produces the tags; no other action is needed. Transient server trouble (server unreachable, timeouts) does not lose heartbeats: they stay buffered. The data lost for the first three reasons is only older heartbeat state, which the agents refresh on their own interval. No action unless `buffer_full`, `snapshot_oversize` or `snapshot_evicted` keeps rising after the server is back; if it does, check that the server is reachable and answering `BatchHeartbeat` (`yuzu_gw_upstream_rpc_errors_total{rpc_name}`), and consider raising `max_heartbeat_buffer_bytes` or `max_heartbeat_buffer` if your fleet is larger than the defaults assume. Do not restart the gateway for this: a restart disconnects every agent the node holds. |
| gateway | metric | `yuzu_gw_session_limit_rejected_total` rising | A `Register` or `Subscribe` was refused because one gRPC connection already holds `max_sessions_per_connection` agent sessions (default 8; see "Per-connection session cap" for what counts). A stock agent holds one session per connection (INFERRED), so a rise means an L4 balancer, forwarder or client is carrying several agents on one connection (see "Per-connection session cap" under Configuration). A refused `Register` is answered `UNAVAILABLE` (14); a refused `Subscribe` ends the stream (status 2 today, see Known limits) and is counted the same. The agent retries either way. If the topology is legitimate, raise the key in `sys.config`; the key is read once when the registry starts, so the change needs a gateway restart, which disconnects every agent the node holds, so plan it. The metric has no agent label. A refused `Register` leaves nothing on the server and no row on the gateway. Rows of a connection that closed stay counted for the dead connection key only, which no new connection uses, until `dead_connection_grace_ms` (default 15 s) has passed, so a reconnecting client is not refused because of them. |
| gateway | WARN | `Register failed: registry_unavailable` | The agent was answered `INTERNAL` (13) "Registration failed: registry unavailable". The gateway's registry process could not be reached for this `Register`: its table is missing, a call timed out, or the registry restarted and lost the row (see the `Registration replay aborted: registry unavailable` row). This line no longer covers a superseded `Register` (see the next row). The agent registers again with its reconnect backoff (read from the agent code). A sustained run of lines is not expected: check `/readyz` and the registry process. |
| gateway | INFO | `Register superseded by a newer registration` | Two `Register` calls of one agent id overlapped on one connection and the newer one committed first. The older one was answered `UNAVAILABLE` (14) and left no row; the registry is healthy. No action: the agent retries a non-OK `Register` with its reconnect backoff (read from the agent code). An occasional line is expected; a sustained run would mean an agent or forwarder keeps repeating `Register` for one agent id on one connection (INFERRED from the code, not observed). |
| gateway | WARN | `Upstream channel default_channel: could not restart it with TCP_NODELAY` | At start the gateway could not restart its upstream channel with `upstream_tcp_nodelay` applied. It restored the channel with the endpoints as configured, so registration runs at the stock rate (see "Registration rate per gateway"). If a second WARN `could not restore it with the endpoints as configured either` follows, the node has no upstream channel (read from the code, not run). |

The server's `renew_leases ... unknown_session` warnings stop once the agent
is known again. How long that takes depends on the gateway's upstream circuit
breaker (derived from the code; the rig runs under "Observed on a rig" below
are the measured evidence).

- **Breaker closed.** The verdict arrives with the first agent heartbeat after
  the server is back, so the bound is up to one agent heartbeat interval (30 s
  by default), plus one gateway flush (1 s by default,
  `heartbeat_batch_interval_ms`), plus the agent's position in the replay drip
  (see the table below). OBSERVED with 1 agent: after outages of 302 s to 402 s
  the verdict arrived 0.33 s to 0.67 s after the server was healthy, because the
  first flush carried the heartbeats buffered during the outage (rig runs E2b,
  E2c and F1); after a 12 s outage it arrived with the first agent heartbeat
  after T0, at T0 + 17.6 s (run E1).
- **Breaker open.** A verdict that arrives while the breaker is open is
  dropped and counted in `yuzu_gw_heartbeat_verdict_dropped_total{reason="circuit_open"}`.
  The replay then waits for the breaker to go half open, so recovery is bounded
  by the breaker's remaining backoff (capped at 300 s,
  `circuit_breaker_max_reset_timeout_ms`, see "Circuit breaker tuning" under
  Configuration), plus up to one heartbeat interval, plus one flush, plus the drip position. A
  long outage can open the breaker because other upstream calls the agent keeps
  retrying feed it. Wait: do not restart anything for this (the 58 s recovery
  in R2d and the recoveries in runs F3a (all agents online at T0 + 85.2 s) and
  F3b (T0 + 50.4 s) under "Observed on a rig" are this case; in F3a and F3b the agents came back through
  the breaker's own replay right after the probe closed the breaker, with no wait
  for a heartbeat). This applies to one agent too: in rig pass 4 (run H3, 1 agent,
  302 s outage) the breaker was open at the restart, the verdicts at T0 and the
  next two (30 s heartbeat cadence) were dropped, the breaker went half open and
  the next verdict closed it as the probe, and the agent was online at T0 + 86.7 s;
  in rig pass 5 (run J3, 1 agent, 300 s outage, breaker closed at the restart) it was
  online at T0 + 0.98 s. Wait for the breaker, do not restart. While the breaker is open the whole
  `/readyz` answer is 503, not only its `circuit_breaker` check (INFERRED from
  `yuzu_gw_health.erl`), so a load balancer that probes `/readyz` can take the
  node out of rotation for the open period; `/healthz` (liveness) is not
  affected.

**Several agents and a long outage: the breaker opened (OBSERVED, a normal
path).** On a rig with 10 or 30 agents behind one gateway, the circuit breaker
opened 72 s (10 agents, run F3a, 302 s outage) and 40 s (30 agents, run F3b, 152 s
outage) into a server outage, because the agents' own upstream calls (an
inventory report, for example) kept failing and each failure counts toward the
breaker. Every verdict that arrived after the server was back was dropped as
`circuit_open` (30 in F3a, 75 in F3b) until the breaker's half open probe
succeeded. In F3a the probes at the 10, 20, 40 and 80 s backoff steps failed
while the server was down and the 160 s probe succeeded, at T0 + 84.5 s; all 10
agents were online at T0 + 85.2 s. In F3b the probe succeeded at T0 + 49.1 s and
all 30 agents were online at T0 + 50.4 s. Recovery came from the breaker's own
replay (`trigger="breaker"` 1 in both runs; `trigger="heartbeat"` 0 in F3a), not
from the heartbeat verdict. With 1 agent the breaker stayed closed and the verdict
replay (`trigger="heartbeat"`) ran at T0 + 0.67 s (run F1). Whether the breaker is
open at the restart decides the wait, not the number of agents: rig pass 4 (build
`ab01f4f2f`) recovered 30 agents after a 12 s outage at T0 + 21.2 s and 45 agents
after a 150 s outage at T0 + 23.8 s with the breaker open, and the single agent
above at T0 + 86.7 s; rig pass 5 (build `e3cf6b38a`) recovered 45 agents after a
150 s outage at T0 + 29.5 s with the breaker open and 1 agent at T0 + 0.98 s with it
closed. The heartbeat flush
itself was accepted on the first flush after the server returned in these runs
(no `larger than max` line), so the buffer was not the cause of the wait.

- What you see: `yuzu_gw_heartbeat_verdict_dropped_total{reason="circuit_open"}`
  rising, WARN `Circuit breaker: OPEN (will probe in <ms>ms)` lines, and the
  `half_open -> closed (probe succeeded)` INFO line when it ends.
- Action: wait. Do not restart the gateway: a restart disconnects every agent the
  node holds.
- How long: the wait after the server is back is the remaining breaker backoff.
  The backoff doubles from 10 s up to `circuit_breaker_max_reset_timeout_ms`
  (300 s by default). The steps up to 160 s were observed (F3a); a wait on the
  300 s step was not observed and a longer outage with several agents was not
  run, so the worst case is bounded by the configured maximum but not measured
  beyond 160 s. The rig used a failure threshold of 5, a reset timeout of 10 s
  and a maximum of 300 s, the defaults.

The gateway-side counters move as follows: `yuzu_gw_registration_replay_triggered_total{trigger="heartbeat"}`
rises by one each time a verdict queued at least one agent,
`yuzu_gw_registration_replay_total` rises by one for every drip attempt, any
outcome (its HELP text reads `Total registration replay attempts by the drip, any outcome`),
and `yuzu_gw_registration_replay_queue_depth` rises, then returns to 0.

**A sustained `unknown_session` rate means the reconcile is not converging.**
If `yuzu_server_gateway_route_desync_total{op="renew_leases",outcome="unknown_session"}`
keeps rising well after the restart, with both the gateway and the server
upgraded, read the new gateway counters:

- `yuzu_gw_heartbeat_verdict_dropped_total{reason}`. Operator action per reason
  (derived from the code; on a rig `circuit_open` was observed in R2d, F3a and
  F3b, and the other reasons by injected verdicts in run E6):
  - `not_local`: the server named sessions this node does not hold (they are
    never replayed). INFERRED: this happens when an agent left this node, or
    changed session, after its heartbeat was buffered and before the verdict was
    handled. No action; informational, with one exception: if it rises after a
    `Registration replay aborted: registry unavailable` WARN, those agents are
    not coming back through the replay (see that row above), and released agents
    need an agent service restart (see "Agent dependency" below). If it stays
    high while agents stay offline, look at agent reconnect churn
    (`yuzu_gw_heartbeat_rejected_total`, the agent log) rather than at the replay.
  - `circuit_open`: the upstream circuit breaker was open when the verdict
    arrived; the sessions are listed again by later heartbeats. Wait for the
    breaker (see the breaker rows above); do not restart.
  - `queue_full`: the replay queue is at `registration_replay_queue_max`, or the
    upstream client's mailbox held more than 100 messages when the heartbeat
    buffer would have cast the verdict to it (the buffer then skips the cast and
    logs one DEBUG line). The
    sessions are listed again by later heartbeats (INFERRED), so first wait and
    watch `yuzu_gw_registration_replay_queue_depth` fall. If it recurs at your
    normal fleet size, raise the key in the `yuzu_gw` section of `sys.config`
    and restart the gateway (the key is read at start). A gateway restart
    disconnects every agent it holds, so read "Upgrade day" above first.
  - `malformed`: an id the gateway could not use as a session id (not a binary
    of 1 to 64 bytes). Expected to stay at 0, because the server does not list
    over-length ids. Only the length is checked: ids that are not valid UTF-8 and
    are within 64 bytes were accepted as ordinary ids and counted `not_local`,
    not `malformed`, in the injected-verdict run E6, which also counted ids of 65
    and 100 bytes as `malformed`. No gateway-side action; a sustained non-zero count means the
    server and gateway disagree about the field, so collect the gateway debug
    line `Heartbeat verdict: N unknown session(s) listed, M malformed` and report
    it.
- `yuzu_gw_heartbeat_unknown_truncated_total`: the server listed more than
  4096 unknown sessions in one response. Sessions beyond the cap may be
  reported again by later heartbeats. No action; informational. It marks a
  recovery that needs more than one round (more than 4096 unknown sessions from
  one gateway in one batch), and the gateway logs a WARN
  `Heartbeat verdict truncated by the server`. The counter counts every
  occurrence, but the WARN is logged at most once per 60 s per heartbeat buffer
  process, and its text ends with `suppressed N`, the number of occurrences since
  the last WARN. The limit resets when the buffer process restarts, so the first
  WARN after a restart says `suppressed 0`. A recovery of several rounds
  therefore does not repeat the line every flush.
- `yuzu_gw_registration_replay_triggered_total{trigger="heartbeat"}`: rises by
  one each time a verdict queued at least one agent.
- `yuzu_gw_registration_replay_total`: rises for every replay attempt the drip
  makes, whatever started it and whatever the outcome. This is the evidence
  that replays are being sent. The three counters above staying at 0 while
  `unknown_session` rises does not prove that no verdict reaches the replay: ids
  already queued, or replayed inside the guard window, are counted nowhere, so
  a verdict can arrive and move none of them. If `registration_replay_total`
  is also flat while `unknown_session` rises, no replay is being sent (an older
  gateway, a response without the fields, or a breaker that stays open).

No shipped alert rule watches an `unknown_session` rate, on purpose.
`yuzu_server_gateway_route_desync_total{op="renew_leases",outcome="unknown_session"}`
has a low background rate and a post-restart baseline rise that must not page,
and a threshold that avoids that needs real fleet data (the comment above
`YuzuGatewayRouteUnreadable` in `docs/prometheus/yuzu-alerts.yml` gives this
reason). The gateway's `yuzu_gw_heartbeat_rejected_total{reason="unknown_session"}`
has no rule either; the same file states the reason only for the server counter.
Watch both on a dashboard after a server restart instead.

A replay the server answers with `accepted=false` is handled separately. The
server answers `accepted=false` for an enrollment outcome, for example an
admin-denied or not yet approved enrollment (also a rejected, expired or already
consumed token, an invalid token length, and an auto-approve failure). A replay
reaches that answer only when the agent is not already approved in the
enrollment store (for example after an enrollment-store reset or restore); INFERRED
from `gateway_service_impl.cpp`, which skips the enrollment checks for an agent
the store lists as approved. The gateway logs
`Registration replay: <agent> was not accepted by the server (<reason>); disconnecting so the agent follows its own registration path`
(the reason is the server's text, cut to 128 bytes, and no session id is
logged), disconnects that agent's process, and does not re-announce the
session. The agent then registers again by itself through the gateway and
follows its own outcome. The server counts an enrollment denial in
`yuzu_register_denied_total{source="gateway_proxy"}` and logs the refusal in its
own log. Operator action: check the enrollment queue, then restart a released
v0.13.0 or v0.14.0-rc6 agent that stays disconnected. Those builds were observed
to wedge only after a `NOT_FOUND` heartbeat rejection; the `accepted=false`
disconnect itself was not run, and the same wedge there is INFERRED (see "Agent
dependency" below). This disconnect has the shape tracked in #4629: nothing
checks that the process being disconnected still holds the replayed session.

The `accepted=false` disconnect is a new branch of this change. Before it, an
`accepted=false` answer to a replay took the same arm as an accepted one: the
gateway re-announced the session, and the server then refused that announcement
as an unknown session, so the agent stayed stranded without any signal
(INFERRED from `yuzu_gw_upstream.erl` on `dev`, where the replay's `{ok, Response}`
arm has no `accepted` check and the only disconnect is the superseded
`FAILED_PRECONDITION` arm, and from the server's unknown-session handling of a
`CONNECTED` in `gateway_service_impl.cpp`; neither was run). The disconnect makes
the strand visible and lets the agent follow its own registration path. Released
agents that wedge after any disconnect still need the agent service restarted
until a release containing #5183 ships.

**Replay failures feed the shared circuit breaker.** A failed `ProxyRegister`
during a verdict-driven drip calls the breaker's failure path like any other
`ProxyRegister`; a server answer of superseded or `accepted=false` counts as a
success. The breaker policy is unchanged, but verdict replays are a new source of
failures that count. With the default threshold of 5 consecutive failures and
20 ms spacing, a failing server can open the breaker within about 100 ms plus
the RPC time of five calls (INFERRED: arithmetic on the code and the defaults,
not measured). An open breaker gates `ProxyRegister` and `ProxyInventory`, drops
stream-status notifications (`yuzu_gw_upstream_notify_dropped_total`, reason
`circuit_open`) and makes the whole `/readyz` answer 503 `not_ready`, with
`circuit_breaker` false in its checks (`yuzu_gw_health.erl`, INFERRED; the
shipped guidance is that a load balancer probes `/readyz`, so an open breaker can
take the node out of rotation until it goes half open). A heartbeat flush never
feeds the breaker. If the breaker keeps reopening, look at the server: a
`half_open -> open (probe failed ...)` WARN means the server is still failing,
and restarting the gateway does not help.

**Replaying a session the server already knows is not free.** The server's adopt
decision calls `register_agent` for every replayed session, including one it
already holds in memory. That installs a fresh `AgentSession`, so the agent loses
its dispatch placement until its re-sent CONNECTED notification lands (the
`BatchHeartbeatResponse` comment in `gateway.proto` says the same), and it
revokes the agent's device tokens when a prior session exists and a device-token
store is wired (`agent_registry.cpp`, `register_agent`). INFERRED from the
code: no device-token store is wired in the production server today
(`set_device_token_store` has no production caller, so the pointer stays null
and the revoke is dormant), but the revoke becomes live the moment one is
wired. Two cases replay a session the server already knows:

- A verdict computed before a replay landed arrives after it. The guard stamp is
  taken when the replay is sent, and a stale verdict can arrive up to the 5 s
  flush deadline (INFERRED: the vendored grpcbox client default) plus the replay
  RPC time later. Do not set `registration_replay_session_guard_ms` below 5000
  plus the expected replay RPC time; the default 10000 is safe (INFERRED).
- A double replay. A verdict replay runs first (the server has no prior session,
  so nothing is revoked), and a later full breaker-recovery replay re-proxies
  the same sessions (a prior session now exists). INFERRED from
  `yuzu_gw_upstream.erl`: the breaker-seeded snapshot is not filtered by the guard.

Neither case was observed on the rig. An idempotent adopt (a re-adopt of a
session the server already holds would no longer wipe placement) is tracked in
#5244.

**Breaker recovery and the verdict drip interact.** While a verdict-seeded
(targeted) drip is queued, a breaker-recovery full replay trigger is dropped (the
existing in-flight rule), so an agent that is not in the targeted queue is not
replayed by that recovery. A targeted replay that is the half open probe closes
the breaker without seeding a full replay. Unit test:
`breaker_replay_during_targeted_drip_is_dropped`. The consequence is under "Known
limits" below.

**What the reconcile promises, on one core replica.** Every session the server
reports unknown, and that the gateway still holds live, is queued for
the existing replay drip, and a heartbeat verdict does not queue it again within
the guard window (`registration_replay_session_guard_ms`, 10 s by default), with
no operator action. A listed agent is known to the server again (heartbeats acknowledged,
lease renewed, counted in `agents.online`) within the bound above: with the
breaker closed, one heartbeat interval plus one flush plus its drip position
times (ProxyRegister RPC time plus the spacing); with the breaker open, the
breaker's remaining backoff is added first. The change adds no new unbounded state: one pending entry per agent,
at most 4096 session ids of at most 64 bytes per flush, and a cap on verdict
appends (`registration_replay_queue_max`, 10000 by default). The cap bounds only
verdict appends: the snapshot a breaker recovery seeds is not capped (it is
bounded by the number of agents the node holds, as before), and while a snapshot
of 10000 or more agents drains, every verdict id for an agent not already queued
counts as `queue_full`. The circuit breaker policy is unchanged, but replay
failures now count toward the shared breaker (see below).

**What it does not promise.**

- Completion inside a route lease. The route lease runs 90 s from the last
  heartbeat the previous server ingested. Agents whose turn in the drip comes
  after the remaining lease has run out get `503 no agent connected` for
  commands until their turn.
- Dispatch reachability after the session is adopted. Adopting restores the
  server's knowledge of the session (heartbeats acknowledged, lease renewed,
  `agents.online`). Dispatch placement converges when the agent's re-sent
  CONNECTED notification is delivered. A rise in
  `yuzu_gw_upstream_notify_dropped_total` during recovery means some agents
  stay acknowledged but unreachable for commands until their next reconnect.
  The series has no sample until a notification is first dropped, so an
  absent series means no drops. The series has no agent label, so the affected
  agents cannot be identified from the metric. They recover at their next
  reconnect; to force it, restart the agent service (OBSERVED: a restart
  recovers any agent). The in-flight notification limit that causes the drop is
  tracked in #4632; it is not fixed here.
- Correctness on several core replicas (see below).
- Any order beyond first-in, first-out in sorted session-id order. The gateway
  sorts the ids it keeps from one response, so each verdict's agents are queued
  in sorted session-id order (not the order the server listed them) and a later
  verdict is appended after the earlier ones. The gateway has no lease data to
  prioritise by.
- Recovery of a route row that the server's lease reaper tombstoned while the
  server stayed up (see "Known limits" at the end of this section).

**Observed on a rig.** Everything in this list was observed on a local rig and
is not reproducible from the repository (the raw logs are not published): runs
R1 to R6 used one real agent with the default auto-update setting; the later
runs in the table after this list used up to 30 agents behind one gateway. All
runs used one core replica, debug builds, gateway log level debug, one box, and
(except R6) plaintext on loopback. T0 is the moment the restarted server's
`/health` first returned 200. A statement marked INFERRED was read from the
code and was not seen in a run. The run labels (R, E and F) follow the local rig
notes. The run table, the test results and the not-tested list are in the
[evidence record](../security-reviews/gateway-heartbeat-verdict-replay-2026-10-04.md);
the raw rig logs are local only.

- **R1: server killed for about 10 s, then restarted (plaintext rig).** OBSERVED:
  the gateway logged the INFO line `Registration replay: heartbeat verdict named 1 session(s); queued 1, not local 0, already queued 0, within guard 0, queue full 0`
  (no session id), then at DEBUG `re-proxied <agent> (adopted session ...)`.
  The server logged `adopted presented session ... (store-confirmed=true)` and
  INFO `ProxyRegister succeeded` with the session id from before the restart.
  The replay came at T0 + 17.5 s, on the first agent heartbeat after T0.
  `/health` `agents.online` returned to 1, and a read-only single-target
  command returned a result within 1 s of that. The session id and the
  gateway-side agent process were the same as before; the agent did not
  reconnect. Over the next 71 s (two heartbeat cycles) every counter stayed
  unchanged (the `renew_leases` `unknown_session` count, the `heartbeat`
  replay trigger, the verdict-dropped counter and the connection-binding
  counters). The server's `renew_leases guard rejected` warning fired once, for
  the triggering heartbeat, and stopped. A baseline run of the same scenario on
  dev without this change, as a separate rig run: `agents.online` stayed 0 for
  about 280 s and the gateway never replayed.
- **R2: server down for 300 s, with the route row expired before the restart.**
  OBSERVED: the row had `cluster_id` and `gateway_node` set and `lease_until`
  in the past. The agent recovered with the same session id and the same
  process, and the lease advanced. The `renew_leases` `unknown_session` count
  stopped rising at 3. `yuzu_server_gateway_route_reap_total{outcome="ok"}`
  went from 0 to 1 at T0 + 300 s, with no reap INFO line (that line is printed
  only when something was reaped). INFERRED from the row state: the server path
  was the renew adopt, since the renew and the reclaim paths log the same
  `adopted presented session ... (store-confirmed=true)` line.
- **R2d: recovery after that outage took 58 s, not seconds.** OBSERVED: the gateway
  circuit breaker was open at T0 (the agent's inventory report retries every
  30 s had fed it during the outage, and its backoff had grown to 80 s), so the
  first two verdicts were dropped (`heartbeat verdict named 1 session(s) while the circuit is open; dropped`,
  `verdict_dropped{reason="circuit_open"}` at 2). The breaker went half open at
  T0 + 54 s, the next verdict queued the agent, and the replay RPC was the half
  open probe that closed the breaker. A repeat run in which the breaker never
  opened replayed at T0 + 4.2 s. INFERRED from the existing replay-on-recovery
  code: a breaker-opening outage was also recovered by the gateway before this
  change, through the same half open transition; this change adds the closed
  breaker case.
- **R2c: route row tombstoned, then the server killed for 10 s.** OBSERVED: replay
  at T0 + 17.5 s with the same signals, and the row repopulated with the same
  session. INFERRED: the reclaim path (a renew would match zero rows).
- **R5: Guaranteed State push.** OBSERVED: before the restart, a `full_sync` push
  returned 202 and the agent logged `Guardian: apply_rules ok (applied=1, failed=0, pending=0, full_sync=true, generation=2, total=1)`.
  After the recovery the same push produced the identical line 13 ms later
  (only baseline members are pushed, so a one-rule Baseline was deployed
  first). The earlier symptom of a push never delivered after a bounce was not
  reproduced.
- **R6: TLS.** OBSERVED on a separate rig: the first scenario above repeated with
  the server's default certificates and CA, gateway-to-server mutual TLS, the
  management listener on mutual TLS with the server certificate pin, and
  agent-to-gateway one-way TLS (with `--ca-cert`, then mutual TLS after CSR
  enrollment). The web UI was served over plain HTTP. Result: replay at
  T0 + 17.1 s, same session, same process, no reconnect, counters unchanged
  after convergence. The web UI over HTTPS was not tested.
- **E2a and an unplanned long outage: a stuck heartbeat batch (before the
  buffer change).** OBSERVED on a rig with an agent that had the TAR plugin
  (default plugin set), one core replica, before the heartbeat buffer change
  described under "Heartbeat Batching". Such an agent's heartbeats can carry a
  `fleet_snapshot_json` of 200 to 800 KB (this rig host, busy). At that time the
  buffer retained heartbeats on a failed flush capped by count only (10000), so a
  long server outage (about 150 s or more, INFERRED from the snapshot sizes; the
  runs below were 300 s and 15.6 minutes) left a retained batch larger than the
  server's gRPC receive limit of 4194304 bytes. In an unplanned outage of 15.6 minutes the retained batch reached
  24805137 bytes. After the server was back, every `BatchHeartbeat` failed with
  `Received message larger than max (... vs. 4194304)` and never drained: no
  verdict, no replay and no recovery until the gateway was restarted. In run E2a
  (a planned 300 s outage) the same thing happened: `agents.online` stayed 0 for
  the whole 420 s deadline plus 91 s of further observation, a command returned
  `503 no agent connected`, the route row was tombstoned, the replay counters did
  not move and the agent never reconnected. A 10 s outage with 30 agents behind
  one gateway (run E3c) failed the same way: the first flush after T0 was 28
  heartbeats, 20,035,889 bytes, and was rejected. This is existing buffer
  behaviour, not introduced by the verdict replay, but it disabled the recovery
  this section describes. The R runs above used an agent without the TAR plugin,
  so their heartbeats were small and did not meet it. After the buffer change
  (one entry per session, chunked flush, byte cap) the same scenarios recovered
  (runs F1 to F6 in the table below, at `990e57e48`), and the same sequence on a
  gateway built before the change failed again (control run F5). The runs are
  recorded in the
  [evidence record](../security-reviews/gateway-heartbeat-verdict-replay-2026-10-04.md)
  on its `Post-fix rig run:` line.
- **`yuzu_gw_upstream_notify_dropped_total`.** OBSERVED: the metric has HELP
  and TYPE lines but no sample until a notification is first dropped, so an
  absent series means no drops.
- **Not tested:** 100 or more real agents (rig pass 6 ran 1000 to 5000 simulated agents, a load generator that answers no commands and sends no inventory, see the K rows of the table below), HA or several replicas, notify
  pressure, agents started with `--no-auto-update`, the `queue_full` and
  `malformed` verdict reasons produced by a real server (only injected verdicts
  were run, E6), a double replay, a verdict that arrives after a replay it
  predates, the registry-unavailable abort, a crash of the registry process, an
  `accepted=false` answer, a failing server feeding the breaker during a drip,
  TLS with the final code (R6 ran earlier), a gateway log level other than debug,
  a wait for the circuit breaker longer than the 160 s backoff step, a 300 s or
  longer outage with a closed breaker and several agents (the breaker opened in
  F3a, 10 agents and 302 s, and in F3b, 30 agents and 152 s), the commits after
  `e3cf6b38a` (the pending row cleanup on connection down with its grace, the
  per-connection pending index, the same-agent commit rule, the `UNAVAILABLE`
  answer for a superseded `Register` and the removal of a dead connection's rows
  by its index: eunit, dialyzer, Common Test and scratch probes only; rig pass 6 on `c518edd93`, which predates the removal by index and the superseded answer, observed the grace itself and the removal of a dead connection's rows after it, run K5), and hot loading the
  code into a running node (not a supported deployment path).

**Later runs: several agents and the buffer change.** OBSERVED on the same kind
of local rig (one box, plaintext, loopback, debug builds, one core replica, agent
build containing #5183). Runs E1 to E6 ran on gateway commit `848709698` (before
the heartbeat buffer change); runs F1 to F6 ran on `990e57e48` (with it); runs H1
to H7 (rig pass 4) ran on `ab01f4f2f` and runs J1 to J7 (rig pass 5) on
`e3cf6b38a`, both with the later review rounds' code up to those commits (rig pass
3, runs G1 to G5, is in the evidence record). The code after `e3cf6b38a` ran in a
recovery pass only in rig pass 6 on `c518edd93` (runs K0 to K7 of pass 6 in the
table, which include the nodelay commits); the other rig run on it is the
registration-rate investigation on `71ee2b02f` (runs K1 and K2 in the table, not a
recovery pass). The four review fix commits after `c518edd93` are not in any rig
build. T0 is the first `/health` 200 of the restarted server. "Default agents" means the
default plugin set with the TAR plugin loaded; "no TAR" means the TAR plugin was
removed so the heartbeat carried no snapshot.

| Run | Commit | Scenario | Observed |
|---|---|---|---|
| E1 | `848709698` | 1 default agent, server killed for a nominal 10 s | verdict at T0 + 17.6 s, same session, no reconnect (R1: T0 + 17.5 s) |
| E2a | `848709698` | 1 default agent, 300 s outage | FAIL, the stuck batch: 10 buffered heartbeats, 7,067,350 bytes, `larger than max`, never recovered in 420 s plus 91 s |
| E2b, E2c | `848709698` | 1 agent (E2b with no plugins loaded, E2c no TAR), 302 s and 402 s outages | recovered at T0 + 0.38 s and T0 + 0.33 s, same session and process, breaker closed |
| E2x | `848709698` | 1 default agent, unplanned 15.6 minute outage | breaker opened, breaker replay at T0 + 36 s, then the stuck batch (31 buffered, 24,805,137 bytes) until the gateway was restarted |
| E3a | `848709698` | 10 agents, no TAR, 10 s outage | last agent online at T0 + 17.9 s, one replay per agent, drip gap median 44 ms |
| E3b | `848709698` | 30 agents, no TAR, 10 s outage | last agent online at T0 + 17.6 s, drip gap median 43 ms, queue depth peak 15, gateway CPU peak 35% of one core, RSS 243 to 256 MB |
| E3c | `848709698` | 30 default agents, 10 s outage | FAIL, the stuck batch: first flush 28 heartbeats, 20,035,889 bytes, no recovery in 200 s plus 61 s |
| E4 | `848709698` | R2b state reproduced twice (partitions of 431 s and 411 s), then a recovery action | restarting only the agent re-armed the route row at +10.5 s with a new session; restarting only the gateway re-armed it at +14.2 s with a new session; commands worked throughout |
| E5 | `848709698` | crash and timeout variants with the crash report filter, 30 agents, release build | all seven markers counted 0 in three variants; the control with the filter removed had hits |
| E6 | `848709698` | injected verdicts, 30 agents | counters and log lines matched the documented reasons (details below) |
| F1 | `990e57e48` | 1 default agent, 402.5 s outage | verdict at T0 + 0.67 s, same session and process, no `larger than max` |
| F2 | `990e57e48` | 30 default agents, 12 s outage | first flush 20 heartbeats in 5 chunks, last agent online at T0 + 17.7 s, same sessions |
| F3a | `990e57e48` | 10 default agents, 302 s outage | breaker opened 72 s into the outage, verdicts dropped as `circuit_open`, recovery by the breaker replay at T0 + 84.5 s |
| F3b | `990e57e48` | 30 default agents, 152 s outage | breaker opened 40 s into the outage, 30 heartbeats flushed in 9 chunks, recovery by the breaker replay, all online at T0 + 50.4 s |
| F4 | `990e57e48` | `max_heartbeat_buffer_bytes` at the 1048576 minimum, 5 default agents, 121.5 s outage | `snapshot_evicted` 23 at T0, agents recovered at T0 + 1.1 s |
| F5 | `848709698` gateway, `990e57e48` server and agent builds | control: 1 default agent, 302 s outage | FAIL as before: 504 `larger than max` lines, 21,629,287 bytes buffered, no recovery |
| F6 | `990e57e48` | 10 minute steady state after F1 | no WARN or ERROR, counters flat, gateway mean 2.5% of one core |
| H1 | `ab01f4f2f` | 30 default agents, 12 s outage | breaker open at the restart, verdicts dropped as `circuit_open`, all 30 online at T0 + 21.2 s, same sessions and processes, cap counter 0 |
| H2 | `ab01f4f2f` | 45 default agents, 150 s outage | first drain 35 heartbeats in 8 chunks, then 10 in 3, 0 drops, all 45 online at T0 + 23.8 s (breaker open, 45 re-proxied in 1.87 s) |
| H3 | `ab01f4f2f` | 1 default agent, 302 s outage | breaker open at the restart, verdicts dropped three times, the next verdict closed it as the probe, online at T0 + 86.7 s, same session, no reconnect |
| H4 | `ab01f4f2f` | bad heartbeats from a probe agent (5 MiB tag, 600 tags, invalid UTF-8, 10 in a row) | all 29 acknowledged, `heartbeat_oversize` 8, `heartbeat_invalid` 5, buffer process not restarted, route row kept renewing |
| H5 | `ab01f4f2f` | session cap, default 8 and a cap of 2 | 9th distinct agent refused `UNAVAILABLE`, the same id accepted, no leaked slot, 3 refusals counted for each cap value |
| H6 | `ab01f4f2f` | router timeout clamp and crash redaction | 99999 clamped to 3600 s, non-positive took the 300 s default, forced router and buffer crashes left 0 marker hits |
| H7 | `ab01f4f2f` | 5 minute steady state after H3 | WARN 0, ERROR 0, only the upstream RPC counts changed |
| J1 | `e3cf6b38a` | 30 default agents: cold start through the reservation path, then a 12 s outage | cold start: all 30 registered in 7.5 s, 0 refused; outage (breaker closed): all online at T0 + 16.1 s, same sessions and processes |
| J2 | `e3cf6b38a` | 45 default agents, 150 s outage | 3 chunks then 2, 0 drops, breaker open, all 45 online at T0 + 29.5 s |
| J3 | `e3cf6b38a` | 1 default agent, 300 s outage | breaker closed at the restart, online at T0 + 0.98 s, same session and process |
| J4 | `e3cf6b38a` | gateway kill -9 three times with 20 agents | every agent re-registered in every gateway life in the second variant (20 of 20, 60 registrations), 0 refused, 0 stale rows |
| J5 | `e3cf6b38a` (control: `ab01f4f2f` gateway) | session cap, same-id supersede, 200 concurrent Registers with distinct ids on one connection | 8 admitted, 192 refused, 8 reached the server; control on the previous code let 153 to 157 through per run |
| J6 | `e3cf6b38a` | tag bound probe (5 MiB invalid value, 6 x 50 KiB, one 40 KiB tag) | `heartbeat_oversize` +2, `heartbeat_invalid` +0, the 40 KiB tag kept, buffer not restarted |
| J7 | `e3cf6b38a` | 5 minute steady state after J3 | gateway WARN 0, ERROR 0, 0 flush errors |
| K1 | `71ee2b02f` | registration rate, C++ clients with the agents' 30 s deadline, real-size `Register` (9,054 bytes), stock gateway and gateway with nodelay set kernel-wide, real server, loopback | stock: each upstream call 41 to 43 ms, about 24 per second per gateway; 1000 agents 703 registered and 297 hit the deadline; 2000 agents all registered after 776 s (85 s ideal), 5.9 attempts per agent. With nodelay: 2000 agents in 3.8 s and 5000 in 10.2 s, 0 retries. Stock 5000 not run. Not a recovery pass |
| K2 | `71ee2b02f` | probe client: 40 concurrent `Register` calls of 256 KiB on one connection (the earlier J5 b2 case), Erlang HTTP/2 client and a C++ client | the 2 per second of J5 b2 came from the Erlang client's flow-control window update coalescing (500 ms by default), a measurement artefact; the C++ client sent the same 40 x 256 KiB in 91 ms through the same gateway |
| K0 (pass 6) | `c518edd93` | nodelay on the stock configuration (no nodelay setting in `sys.config`) | start log `Upstream channel default_channel: TCP_NODELAY on`; the upstream client socket reported `{nodelay,true}` after the first agent registered |
| K1 to K3 (pass 6) | `c518edd93` | cold-start bursts of 1000, 2000 and 5000 simulated agents (a load generator: one connection per agent, the real 9,054 byte `Register`, the 30 s deadline; it answers no commands and sends no inventory), stock gateway, shipped nodelay | 1000 agents: all registered in 1.89, 2.11 and 2.09 s (three runs), 0 deadline failures, 1.0 `ProxyRegister` per agent; 2000 agents 4.16 s; 5000 agents 12.08 s; 0 failures, WARN 0, ERROR 0 in every run |
| K1-control (pass 6) | `c518edd93` | the 1000 agent load with `upstream_tcp_nodelay` set to `false` | 703 registered inside the deadline and 297 hit it (the same count as the stock run on `71ee2b02f`), 1297 attempts, last agent at 55.5 s |
| K4a to K4d (pass 6) | `c518edd93` | real agents (TAR plugin loaded): 30 agents and a 12 s outage; 45 agents and 150 s; 1 agent and 300 s (plus an open-breaker variant); 20 agents and three gateway kill -9 | K4a all 30 online at T0 + 15.5 s, same sessions; K4b breaker open, all 45 online at T0 + 17.3 s, 0 buffer drops; K4c online at T0 + 0.98 s (breaker closed), K4c2 at T0 + 52.9 s (breaker open); K4d 20 of 20 re-registered in every gateway life (12 to 13 s), 0 refused, 0 stale pending rows |
| K5 (pass 6) | `c518edd93` | grace of a closed connection's pending rows, probe client | default grace: a `Subscribe` on a new connection accepted, rows 2 at +10 s and 0 at +17 s, a late `Subscribe` refused; with `dead_connection_grace_ms` 2000 the rows were gone by +3.7 s. The refusal reached the probe as status 2, see Known limits |
| K6 (pass 6) | `c518edd93` | server-only restart with 1000 and 2000 simulated agents that heartbeat and hold a `Subscribe` (the load generator) | 1000 agents all back at T0 + 22.7 to 23.3 s (10 s and 60 s outages), 2000 agents at T0 + 46.1 s; breaker closed throughout (the generator sends no inventory), 0 drops, original session ids kept |
| K7 (pass 6) | `c518edd93` | 5 minute steady state after K4c, 1 real agent | WARN 0, ERROR 0, 0 flush errors |

The K0 to K7 rows marked pass 6 are one run set (the evidence record's "Rig pass 6" has the full figures and caveats); the unmarked K1 and K2 above are the earlier investigation on a different commit. All pass 6 runs were loopback, plaintext, one core replica, a debug-built C++ server and PostgreSQL with fsync off, on a shared box.

Details of what these runs showed:

- **Chunk sizes.** The largest chunk observed was 3,142,583 bytes (F3b, 4
  heartbeats; F3a: 3,139,857 bytes), against the packing limit of 3 MiB
  (3,145,728 bytes) and the server's receive limit of 4,194,304 bytes. These
  figures come from a local trace inside the gateway node that recorded the exact
  encoded size of every chunk; chunk bytes are in no log line and no metric.
- **Log level.** `Flushed N heartbeats in M chunk(s)` is INFO only when M is
  greater than 1 (F2: 20 heartbeats in 5 chunks; F3b: 30 in 9). A one chunk flush
  is DEBUG, so at the default log level a normal flush leaves no line.
- **Byte cap at the minimum (F4).** With `max_heartbeat_buffer_bytes` at 1048576
  and 5 agents, `snapshot_evicted` rose to 23 during the outage and kept rising
  after the server was back (23 to 29 over 90 s, at the agents' 30 s heartbeat
  instants), because two snapshot-bearing heartbeats of about 0.8 MB landing in
  the same 1 s flush window exceed that cap. Do not set the cap below a few MiB.
  At the default 64 MiB `buffer_dropped` stayed 0 in F1, F2, F3a, F3b and F6; a
  backlog that reaches the default cap was not run (the largest estimated buffer
  was 24.2 MB).
- **Steady state (F6).** After recovery, over 10 minutes with one agent: gateway
  log WARN 0 and ERROR 0, 21 flushes of one heartbeat, every counter unchanged
  (`coalesced_total` 12, `buffer_dropped` 0, `replay_total` 1), gateway CPU mean
  2.5% of one core (maximum 15%) and RSS 235 to 248 MB, server CPU mean 0.4%.
- **Recovery cost (E3b, F2, F3b).** With 30 agents, the drip re-proxied one agent
  about every 42 to 43 ms (median); gateway CPU peaked at 35% to 42% of one core
  and RSS reached 243 to 325 MB across these runs (the chunk tracer adds some CPU
  in F3b). The last agents came back at about T0 + 17.6 s to 17.7 s in the 12 s
  outage runs because an agent is named only when its own 30 s heartbeat arrives.
- **Crash redaction (E5).** In a release build with 30 agents, a crash of the
  upstream client with a call queued, a crash of three per-agent processes and a
  35 s suspension of the upstream client each left 0 occurrences of the real
  enrollment token, `BEGIN CERTIFICATE`, `BEGIN CERTIFICATE REQUEST`,
  `enrollment_token`, `csr_pem`, `machine_certificate` and a synthetic canary in
  the gateway log; with the filter removed at run time the upstream crash
  produced 3 of each. The plaintext rig's registrations had empty certificate and
  CSR fields, so synthetic canary values stood in for them, and the per-agent
  crash variant gave 0 hits also without the filter, so it does not test the
  filter. A crash of the registry process was not tested.
- **Injected verdicts (E6).** A forwarder on the server to gateway leg replaced
  one empty `BatchHeartbeatResponse` per stage. 4100 listed ids produced
  `named 4096 session(s)` (the 4 beyond the cap are neither queued nor counted)
  and, with the truncated flag set, one WARN `Heartbeat verdict truncated by the
  server` and `unknown_truncated_total` +1. Ids over 64 bytes (65 and 100) were
  counted `malformed` (+2). Ids that were not valid UTF-8 but within 64 bytes
  were counted `not_local`, not `malformed`. With
  `registration_replay_queue_max` 5 and one verdict naming 30 real sessions: 5
  queued, `queue_full` +25. All 30 agents stayed online in every stage. The
  forwarder only touched responses without unknown ids, so the injections landed
  on an otherwise healthy upstream.

**Load and convergence bounds.** The drip sends one ProxyRegister at a time.
The period per agent is the ProxyRegister RPC time plus the spacing
(`registration_replay_spacing_ms`, 20 ms by default) plus scheduling. The
figures below are arithmetic on those constants, not measurements: the
largest real-agent runs of the replay drip were 30 agents (runs E3b, F2 and F3b
under "Observed on a rig", drip gap median 42 to 43 ms per agent with the default
20 ms spacing; rig pass 6 later ran the drip at 1000 and 2000 simulated agents
from a load generator, run K6, see "Replay recovery at fleet scale" below; the
heartbeat connection-binding soak with 27 agents, recorded in
[its evidence record](../security-reviews/gateway-heartbeat-connection-binding-2026-10-03.md),
did not exercise the replay drip), and the fleet-scale measurement is
tracked in #5313.

| ProxyRegister RPC time | Drip rate | 1,000 agents | 10,000 agents |
|---|---|---|---|
| 5 ms | 40 per second | 25 s | 250 s |
| 20 ms | 25 per second | 40 s | 400 s |
| 100 ms | 8.3 per second | 120 s | 1200 s |

The drip also waits while 10 stream-status notifications are in flight, so
these rates are ceilings. The first verdict lists the agents that heartbeated
in the first flush window, so synchronized heartbeats list more agents at
once. Spacing is the gateway's only lever; the RPC time is the server's. A
drain that runs past 270 s after the last heartbeat the previous server ingested (the
route lease of 90 s plus the reaper's 180 s grace) makes their route rows
eligible for the server's lease reaper, which runs about every 5 minutes
(#4627; read from the server code and the ADR).

**Registration rate per gateway.** Every `ProxyRegister` goes through the one
`yuzu_gw_upstream` process, over one channel and one HTTP/2 connection, one call
at a time, so the time of one upstream call sets how many agents a gateway can
register per second. OBSERVED on a rig, on gateway commit `71ee2b02f` (which does
not have the `upstream_tcp_nodelay` change; loopback, one box, debug-built
server, plaintext, a C++ client with the agents' 30 s `Register` deadline and
retry backoff; the request was a real `RegisterRequest` of 9,054 bytes, captured
from a running agent through the gateway): each upstream call took about 41 to
43 ms for any request under about 64 KiB, which caps a stock gateway at about 24
registrations per second whatever the concurrency. The cause is INFERRED from
switching nodelay on and off at three places (no packet capture was taken):
Nagle's algorithm on the gateway-to-server socket meets the server's delayed
ACK, because the HTTP/2 client library the gateway uses does not set TCP_NODELAY.
The server's own handler time for a real-size `Register` was 1 to 2 ms, new
enrollment included (derived from client-side latency, the server has no such
metric). Bursts of simultaneous registrations, one connection per agent:

| Agents | Stock gateway (before the change) | With nodelay (kernel-wide setting, earlier measurement) | Shipped setting, no override (rig pass 6, `c518edd93`) |
|---|---|---|---|
| 1000, one burst | 703 registered inside the 30 s deadline, 297 hit it | not run | all registered, last at 1.89 s (three runs: 1.89, 2.11 and 2.09 s), 0 deadline failures; the same load with `upstream_tcp_nodelay` set to `false`: 703 registered, 297 hit the deadline, last agent at 55.5 s |
| 2000, one burst, agents retry | all registered after 776 s (85 s ideal), 5.9 attempts per agent | 3.8 s, 0 retries | 4.16 s, 0 failures, 2000 attempts |
| 5000, one burst, agents retry | not run | 10.2 s, 0 retries | 12.08 s, 0 failures, 5000 attempts |

The "With nodelay" column was measured with the equivalent kernel-wide setting
(`inet_default_connect_options` with `{nodelay, true}`) in the gateway's
`sys.config`, not with `upstream_tcp_nodelay`, on the earlier commit; it is kept
as it was recorded. The last column is the shipped mechanism: OBSERVED in rig pass
6 on `c518edd93`, with no nodelay setting in `sys.config` (the default `true`; the
start log and the socket confirmed it, run K0), and the clients were simulated
agents from a load generator (one connection per agent, the real 9,054 byte
`Register`, the 30 s deadline and the agents' retry backoff), not real agents. It
was loopback, a debug-built server, PostgreSQL with fsync off, on a box shared
with other sessions (the 5000 agent run peaked at 597% gateway CPU). A stock
5000-agent burst (with the key off) was not run. The per-endpoint `socket_options`
setting that the key applies was also measured earlier by writing it into the
channel declaration by hand, on `71ee2b02f` and against an in-VM fake upstream
only: 40 concurrent real-size registrations took 1,665 ms stock and 43 ms with it,
and a serial call 42 ms and 1 ms.

Three consequences. First, the agents give up on a `Register` after 30 s, and 24
per second times 30 s is about 700, so a simultaneous burst of more than about
700 agents on a stock gateway could not complete in one attempt (OBSERVED on the
1000-agent run). Second, a call the agent has abandoned stays queued in the
upstream process and is still executed: in the 2000-agent stock run the server
executed every one of the 11,712 attempts, and the queue filled with abandoned
work (the process mailbox held 988 messages one second into the 1000-agent burst
and drained at 24 per second). Third, the replay drip's spacing
(`registration_replay_spacing_ms`, 20 ms by default) was never the limit on a
stock gateway: each call took about 43 ms, so the call time set the pace. With
nodelay a call takes 1 to 2 ms, so the spacing becomes the pace of the drip
(INFERRED from the code and the figures above; the next paragraph has the
measured replay at 1000 and 2000 simulated agents, and the 5 ms row of the table
under "Load and convergence bounds" is the arithmetic). Not measured: a replay of
5000 sessions through the drip, TLS (the certificate request adds about 1
KiB to each `Register`), a non-loopback network (its round trip adds to each
call), a stock 5000-agent burst, and the effect of a registration storm on
inventory traffic (it runs through the same process) and on heartbeat batches
(INFERRED from the code: they call the channel directly, not through the process).

**Replay recovery at fleet scale.** OBSERVED in rig pass 6 on `c518edd93`
(loopback, one box shared with other sessions, a debug-built server,
PostgreSQL with fsync off, plaintext; the agents were simulated by a load
generator that heartbeats and holds a `Subscribe` open but answers no commands and
sends no inventory): after a server-only restart (kill -9 of the server, outages of
10 s and 60 s), 1000 simulated agents were all back 22.7 to 23.3 s after the
restarted server's first `/health` 200, and 2000 agents 46.1 s. Recovery was
linear in the agent count at about 22.5 ms per agent, which is the replay
spacing (20 ms by default) plus about 2 ms per upstream call: with the Nagle delay
gone, the drip sets the pace, not the upstream call. All sessions were re-adopted
under their original session ids, with 0 `circuit_open` or `queue_full` verdict
drops and 0 buffer drops. For 5000 agents the same rate gives about 115 s;
that is arithmetic on the observed rate, not a measurement (K6 at 5000 agents was
not run). The breaker stayed closed in these runs because the generator sends no
inventory, so nothing fed it; the open-breaker recovery was measured only with
real agents, at 45 agents or fewer (45 agents back at T0 + 17.3 s with the
breaker open, run K4b). A real fleet adds inventory, snapshots and a non-loopback
round trip to each call, none of which was measured at this scale. Spacing is the
operator's lever (`registration_replay_spacing_ms`); each agent costs the spacing
plus the call.

| Symptom | What you see | Cause | Action |
|---|---|---|---|
| Agents slow to come back after a server restart on a large fleet | The server log shows more than one `[gateway] ProxyRegister succeeded` line per agent (5.9 attempts per agent in the 2000-agent stock run); agents give up on a `Register` after 30 s; `yuzu_gw_upstream_rpc_duration_ms` for the `register` rpc name has a mean near 40 ms | Before the `upstream_tcp_nodelay` change, the 43 ms per-`Register` Nagle delay (OBSERVED on a rig, see above); also a slow server, because the upstream process runs one call at a time | Confirm `upstream_tcp_nodelay` is not `false` in the `yuzu_gw` section of `sys.config` (and that no endpoint has a hand-set `{nodelay, false}`); check the server's `ProxyRegister` latency. There is no queue metric for the upstream process: the mailbox depth was read on a rig with `process_info`, and no metric or log line shows it |

**Several core replicas.** The verdict and replay reconcile is correct and
bounded on one core replica. On several replicas it converges in one round only
if a gateway's `BatchHeartbeat`, replay `ProxyRegister` and re-announced
`NotifyStreamStatus` reach the same replica during the reconcile. The shipped
gateway does this per connection (one grpcbox channel, one endpoint, one
HTTP/2 connection) through a layer-4 VIP. A multi-endpoint node list (grpcbox
round-robins per RPC) or a layer-7 per-RPC balancer breaks it. Convergence is
then probabilistic, not bounded, and the per-session guard bounds the replay
rate but not the number of rounds. No multi-replica run exists; this is
inferred from the code. The durable cross-replica session lookup (WS-5,
#4246 item 3) is the fix, and until it lands the safe-to-scale gate forbids a
second replica (see [ADR-2002](../adr/2002-high-availability-architecture.md),
section 7c, update 2026-10-04).

**Agent dependency.** The ordinary restart path above does not need the agent
to do anything. When the gateway does disconnect an agent process (an
`accepted=false` replay answer, or a session the server reports as superseded),
the agent has to register again by itself. In the
[connection-binding test record](../security-reviews/gateway-heartbeat-connection-binding-2026-10-03.md),
released agents v0.13.0 and v0.14.0-rc6 with default settings did not
re-register after a `NOT_FOUND` heartbeat rejection, while the same agents run
with `--no-auto-update` did; the cause is inferred to be bug #2182, fixed by
#5183, which is in no release yet. Agent v0.12.0 never recovered by itself in
that test. Restarting the agent is the interim action for an agent that stays
disconnected. Running an agent with `--no-auto-update` avoids the wedge but also
disables the OTA update channel for that agent.

**Without the reconcile** (a gateway that does not yet read the verdict, or a
verdict that never reaches the replay) the symptom was the following. Observed
on one local development rig with one agent, plaintext, one core replica, after
a server-only restart (about 12.5 s and 300 s of downtime): `/health`
`agents.online` stayed 0 for about 280 s and about 270 s, and the gateway
never replayed (no log line, `yuzu_gw_registration_replay_total` 0). The
server logged `BatchHeartbeat: unknown session` (at debug level) and the WARN
`GatewayRouteStore renew_leases guard rejected the write (outcome=unknown_session ...)`
every 30 s, and `ProxyInventory: unknown session` when an inventory report
arrived. A command to the agent was delivered only while its route lease was
unexpired and was refused with `503 no agent connected` afterwards. After a
300 s outage there was no delivery window at all. TLS, several agents, several
replicas and graceful shutdown were not tested.

**Rollback.** A plain revert of the gateway. There is no schema, no migration
and no new required configuration; the two tunables are optional application
env keys with defaults, which a reverted build ignores.

#### Known limits

- **Heartbeat buffer: agent snapshot size, server limit, shutdown flush.**
  (1) The agent's snapshot size is not bounded by this change. The agent proto
  comment says a snapshot is typically 5 to 20 KB, while 200 to 800 KB was
  observed on one busy rig host with the TAR plugin, and the server accepts a
  snapshot of up to 2 MiB (`kPushedSnapshotMaxBytes` in `fleet_topology_store.hpp`,
  read from the code). The gateway keeps each request under the server's limit by
  chunking and by eviction, but a smaller snapshot from the agent side is the
  real fix; it is tracked as a follow-up for the agent side (no issue number
  yet). (2) The server's gRPC receive limit of 4194304 bytes is the library
  default and is not configured explicitly by the server (INFERRED from reading
  the server code; not run), so the gateway's chunk size of about 3 MiB depends on
  that default staying as it is. It is not raised by this change. (3) The
  gateway's shutdown flush waits at most 5 s and sends at most 8 chunks; it is
  best effort. A shutdown with a backlog that needs more chunks, or that does not
  finish inside that time, loses what is still buffered with the process (INFERRED
  from the code; not run). Losing buffered heartbeats at shutdown costs only older
  heartbeat state. (4) One heartbeat larger than the chunk limit (after its snapshot
  is removed), or with more than 512 status tags, or with a status tag key or value
  over about 64 KiB or more than about 256 KiB of tag bytes in total (checked before
  the UTF-8 repair, which is then not run), loses all of its status tags and
  is counted as `heartbeat_oversize`; the heartbeat itself is kept, so an agent that
  keeps sending such heartbeats still renews its lease but has no status tags until
  it is fixed. (5) An exit that escapes the flush RPC no longer ends the
  buffer process (it used to be able to, losing every buffered heartbeat), and
  the buffer's crash-report status shows counts only, not heartbeat contents.
- **Registration is still serialised through one process.** The proxy RPC of a
  `Register` runs inside the `yuzu_gw_upstream` process, so calls queue behind
  each other even with nodelay on, and a slow server still limits how fast a
  gateway registers agents (a call is as slow as the server's answer). The call
  carries no deadline of its own (only the vendored grpcbox client's default 5 s
  receive timeout applies; read from the code, not run); the caller waits `upstream_call_timeout_ms`
  (30 s by default, the same as the agents' `Register` deadline), and a call whose
  caller or agent has gone is still executed when its turn comes (OBSERVED, see
  "Registration rate per gateway"). Planned follow-ups, with no issue numbers yet:
  run the proxy RPC outside the gen_server, shed requests whose caller is gone,
  and give the upstream call a deadline shorter than the agent's 30 s. The
  `upstream_pool_size` key in the shipped `sys.config` files does nothing; there
  is no connection pool to size.
- **R2b: a route row tombstoned while the server stayed up is not repaired by this
  reconcile.** OBSERVED: during a 6.9 minute network partition between the
  gateway and the server, with the server staying up (the traffic went through a
  TCP proxy), the server's lease reaper tombstoned the agent's route row.
  `/health` stayed at `agents.online` 1 and commands kept working, because the
  server's in-memory session was intact. After the partition healed there was
  no verdict, no replay and no `ProxyRegister`, the `renew_leases` shortfall
  warning repeated every 30 s, and the route row was still tombstoned 4 minutes
  later (commands still returned a result within 1 s). INFERRED from
  `gateway_service_impl.cpp`: the verdict is computed from the server's
  in-memory session map only, so a tombstoned row with a live in-memory session
  never produces one. INFERRED impact: harmless with one replica, because
  dispatch uses the in-memory map and does not consult the durable directory; a
  gap for HA and multi-replica routing. This is not fixed by this change. The state was
  reproduced twice in a later rig run (partitions of 431 s and 411 s; E4), with the same
  outcome for 120 s after the partition healed. The observed run had no breaker
  transition and no replay (no replay and no `ProxyRegister` followed the
  partition), so an earlier breaker-recovery full replay could not have repaired
  that run, and R2b itself is not caused by this change. The next entry narrows
  an incidental repair path that exists only when a breaker transition happens to
  coincide with a tombstoned row. It is
  related to #4627 (the reap-versus-replay race after a drain that runs past the
  270 s reap eligibility horizon, 90 s lease plus 180 s grace). Signal: a repeating `renew_leases` shortfall
  warning on the server with no `Registration replay` line on the gateway after
  a partition heals. Recovery action, OBSERVED in the later rig run (E4, 1 agent,
  agent build containing #5183, plaintext): restarting only the agent re-armed
  the route row at +10.5 s with a new session id, with `agents.online` 1
  throughout; restarting only the gateway re-armed it at +14.2 s, the agent
  re-registering by itself, also with a new session id. Commands kept working
  throughout and returned in 1 s afterwards. Both actions give the agent a new
  session (the old one is not preserved), and a gateway restart disconnects every
  agent that node holds (see "Upgrade day" above). Not tested: other partition
  lengths, several agents, and released agent builds without #5183, which did not
  re-register by themselves after a rejection in the earlier tests (see "Agent dependency"). Without
  an action the row stayed tombstoned for the 4 minutes observed in R2b and the
  120 s observed in E4.
- **A tombstoned route row is no longer repaired by a breaker-recovery full
  replay while a verdict drip is queued or probing.** The server lists only the
  sessions missing from its in-memory map, so a session it still knows whose
  durable route row was tombstoned (the entry above) is never named by a
  verdict. A breaker-recovery full replay was an incidental repair path for such a
  row: it exists only when a breaker transition happens to coincide with a
  tombstoned row, and this change narrows it. It was not observed to repair R2b
  (that run had no breaker transition), and R2b itself is not caused by this
  change. The limit stands: that trigger is now dropped while a targeted drip is
  queued, and a targeted replay that is the half open probe closes the breaker
  without seeding a full replay, so the row waits for the agent's own reconnect
  (INFERRED from the code: the in-flight rule drops the second trigger and
  `record_result_no_replay` discards the replay trigger; unit test
  `breaker_replay_during_targeted_drip_is_dropped`). Not observed on a rig.
  Tracked as a follow-up (no issue yet), together with the entry above.
- **A crash report can still contain the enrollment token, certificate or CSR of
  a registration in four cases: use of the modules outside the application, a
  report shape the redaction filter does not recognise, new code hot-loaded into a
  running node, and any other process that holds a registration request and is not
  named here.** Three gateway processes hold or are sent a registration request:
  the upstream client `yuzu_gw_upstream` (every agent waiting in the replay queue,
  and a request in flight), the per-agent process `yuzu_gw_agent` (the stored
  request of its own agent) and the routing registry `yuzu_gw_registry` (it
  receives the request in the message of its `register` call and keeps it in an
  ETS table). Three layers now cover those three processes. First, `format_status`
  exists for all three and redacts the stored request: for the upstream client the
  replay queue and the recent-replay stamps (shown as sizes), the last message, the
  reason and the debug log; for the per-agent process the stored registration
  request; for the registry the request inside the `register` message. Second, a
  request can no longer leave through an exit reason: an exception raised inside
  the upstream client's own RPC calls is caught and counted as a failed RPC (code
  `exception`), and the three caller side call sites that carry a registration
  request go through one wrapper, `yuzu_gw_safe_call`, which catches an exit of the
  call (the called process crashing, the call timeout, or the process not running
  during a restart). The sites are `yuzu_gw_upstream:proxy_register/1`,
  `yuzu_gw_upstream:proxy_inventory/1` and `yuzu_gw_registry:register_agent/7`. The
  callers get `{error, upstream_unavailable}` from the first two and
  `{error, registry_unavailable}` from the third. The exit reason carries the
  request and is never logged or returned. The wrapper logs at most one warning per
  second for each called process on a node, and the warning names only the class of
  the exit (`noproc`, `timeout` or `other`). The Register handler answers a gRPC
  `INTERNAL` status for any `{error, _}` from `proxy_register/1` (the same status it
  gives for `circuit_open`), and the agent retries registration on any non-OK
  status (read in `yuzu_gw_agent_service.erl` and `agents/core/src/agent.cpp`; not
  run). The third site matters because a failed registry call in the per-agent
  process's init used to exit that init with a reason that embedded the
  `RegisterRequest`, which the Subscribe handler then logged (INFERRED from the
  code; not run). The agent init now stops with the fixed reason
  `registry_unavailable`. Before this, the gRPC server library logged the exit of
  the calling handler process at INFO together with the whole request (OBSERVED by a
  security reviewer running the real application with a real gRPC client, for three
  triggers on the upstream client: a crash with a call queued, a 30 s stall with no
  crash, and the restart gap). A later security review, running the real application,
  found two more call sites that put the request into a crash report (OBSERVED):
  a Register while the registry process was down (the ETS insert error carried the
  request in its stacktrace) and a Subscribe while the agent supervisor was down
  (the `start_child` exit carried the request in its arguments). The exit wrap now
  covers both, and each returns a fixed error that carries no request. Third, a logger primary filter,
  `yuzu_gw_crash_redact`, installed when the application starts, now covers five
  processes: `yuzu_gw_upstream`, `yuzu_gw_agent`, `yuzu_gw_registry`,
  `yuzu_gw_router` and `yuzu_gw_heartbeat_buffer`. The router and the heartbeat
  buffer hold command requests and heartbeat status tags, not registration
  requests; they were added after a security review found that a crash of the
  router printed the command request with its parameters (OBSERVED, see "Subscribe
  Stream Proxy") and reported that a crash of the buffer would print fleet tags
  (not reproduced here). The router now also has a counts-only crash status, like
  the buffer's. A process
  is covered when it is registered under one of those module names or was started
  by that module's `init/1` (a crash report still names it after its name is gone,
  and the per-agent processes never had one). The filter rewrites four report
  shapes. In the `proc_lib` crash report of a covered process the mailbox becomes
  a count, the process dictionary becomes a count, and the exception keeps its class
  with the reason and stacktrace reduced so that no argument list remains (only the
  first process of a crash report is rewritten, not the neighbours listed after
  it). In the `gen_server` terminate report of the upstream client or the registry,
  and the `gen_statem` terminate report of a per-agent process (matched by the
  callback module in its `modules` list), the reason is reduced the same way; the
  terminate report of `yuzu_gw_agent` also redacts its queue and last event, where
  present. In a
  supervisor report whose offender is a covered process, the reason is reduced
  likewise (the offender is matched by its child id for the upstream client and the
  registry, and by the module in its start spec for the per-agent processes,
  because their child id is the shared word `agent`). Reports of every other
  process pass through unchanged. A crash of a per-agent process printed its stored
  request before this change (OBSERVED by the same reviewer with a forced crash). A
  crash from any other source (for example a function clause in a helper that was
  handed a request) would otherwise print that function's argument list, because
  OTP appends the stacktrace after `format_status` runs; with the application
  running, the filter removes the argument lists from that report as well. If the
  filter itself raises, the event is kept with a fixed message that names no data.
  The filter reduces reasons and stacktraces with the functions the upstream
  client's `format_status` uses (`redact_why` and `redact_stack`), so those two
  share one implementation. They are verified by unit tests on the real processes
  (the final test count is on the PR). A later rig run (E5, release build, plaintext, 30 agents) crashed the upstream client with a call queued, crashed three per-agent processes and suspended the upstream client for 35 s, and found none of the seven markers (the real enrollment token, the two certificate markers, the three field names and a synthetic canary) in the gateway log in any variant; with the filter removed the upstream crash printed all of them. That rig's certificate and CSR fields were empty, so synthetic values stood in, and a crash of the registry process was not run. The residual
  is therefore: (i) use of the modules outside the application (the filter is
  installed at application start, so a bare `yuzu_gw_upstream`, `yuzu_gw_agent`,
  `yuzu_gw_registry`, `yuzu_gw_router` or `yuzu_gw_heartbeat_buffer` started in a
  shell has no filter); (ii) a report shape the
  filter does not recognise (an OTP release that formats the report differently);
  (iii) hot-loading the code into a running node, because the filter is
  installed at application start and a hot-loaded node would not have it (hot code
  upgrade is not a supported deployment path for the gateway: the appup in the
  repository is an old skeleton from 0.1.0 to 0.2.0, no relup is built, and the
  runbook above says to restart; INFERRED from a search of the gateway sources,
  the CI workflows and the docs); and (iv) any other process that holds a
  registration request and is not named here. Only the five processes above were
  checked, and a crash of the registry, the router or the buffer was not run on a
  rig. The gRPC handler processes for
  Register and Subscribe hold the request while they run; their two call sites
  named above (a Register while the registry is down, a Subscribe while the agent
  supervisor is down, and the command request that the management handler hands
  to the router) are now covered, and other handler-process call sites were
  searched by grep, not exhaustively audited, so what a crash report of one of
  them would print is not established (INFERRED, not measured). Operator guidance:
  treat any gateway crash report as sensitive.
  As defence in depth, if your log pipeline is shared, you can also bound how much
  of a term the logger prints with the `chars_limit` and `depth` options of the
  `logger_formatter` (set in the handler's `formatter` config; a size bound, not a
  redaction, and not tested here); it is not the main remedy. The shipped
  `gateway/config/sys.config` and `sys.config.prod` set neither: their default
  handler sets only a level and a formatter template (read at this commit).
- The several-replica and agent-dependency limits are described above.
- **Per-connection session cap residuals.** A handler that dies between storing
  its pending row and committing it leaves one row with no index entry, which the
  pending time to live sweep removes (a row stored and not yet committed when its
  connection went down is likewise outside the removal after the grace, which
  follows the connection's index: its own commit or the sweep removes it); a reserve call that times out at 5 s can
  leave a reservation until the time to live; and the live insert can be refused in
  the brief gap between `Subscribe` taking the pending row and the live insert
  (the agent retries, INFERRED about 2 s later). Details under "Per-connection
  session cap" in Configuration.
- **Cold-start notifications are shed at the in-flight limit, so most route rows
  stay tombstoned until the replay runs.** OBSERVED in rig pass 6 (runs K1 and K6
  of that pass) and, per the local rig notes, in the cold start of pass 5 run J1;
  pre-existing, not introduced by this change. After a cold `Subscribe` wave of
  1000 simulated agents `yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}`
  was 987 (989 and 988 in two repeats, and 1953 after 2000 agents).
  `MAX_NOTIFY_INFLIGHT` is 10 in `yuzu_gw_upstream.erl`, so `CONNECTED`
  notifications beyond 10 in flight are shed best effort. The server's route table
  before the restart showed `live=13 tomb=987` for the 1000 agent run; the rows are
  only filled when the replay (or a re-announce) runs, after which it showed
  `live=1000 tomb=0`. With 30 real agents cold started the same effect gave 13
  drops. The counter did not move during the restart itself. The consequence is
  that the server's `online` count and its route rows disagree after a large cold
  start. It is covered by the planned follow-up (i) below, a bounded pending queue
  for dropped notifications, and by #4632 (the in-flight notification limit).
- **A refused `Subscribe` reaches the client as status 2 (`process exited without
  reason`), not as `NOT_FOUND`, and logs an error report.** OBSERVED in rig pass 6
  (run K5) with an Erlang probe client, not with a real agent: for a `Subscribe`
  with no pending registration the gateway logged the WARN `Subscribe: no pending
  registration for session` and then an `[error] crasher` report from
  `grpcbox_stream:handle_streams/2` carrying `throw: {grpc_error, {<<"5">>,
  <<"No pending registration for session">>}}`, and the probe's stream ended with
  status 2 instead of 5. INFERRED from the code: `yuzu_gw_agent_service:subscribe/2`
  signals its refusals with `throw({grpc_error, ...})`, which crashes the stream
  process of a bidirectional streaming call. The same throw pattern exists on
  `origin/dev` (`subscribe/2` there throws at its argument, pending-registration
  and internal-error refusals; checked with `git show` and `grep -n throw`), so
  this is not introduced by this change. No functional effect was seen in pass 6,
  but no real agent was refused: from `agents/core/src/agent.cpp` (not run) a
  non-OK `Register` goes back to the retry loop and an ended `Subscribe` stream
  goes through the reconnect loop, whichever status the stream ended with, so the
  agent re-registers either way. Expect one error report per refused `Subscribe`
  (for example after the dead connection grace has passed). A `Subscribe` refused
  by the per-connection session cap is raised by the same throw pattern
  (`session_limit_error()` in `subscribe/2`), so it is expected to end the same
  way (INFERRED from the code, not run); a refused `Register` is returned and
  reaches the client as `UNAVAILABLE` (14). Follow-up, no issue
  number yet: answer these refusals with a status returned from the handler rather
  than a throw.
- Related tracked items: #5244 (an idempotent adopt: a re-adopt of a session the
  server already holds wipes placement), #4632 (the in-flight notification limit
  on the convergence path), #5278 (verdict follow-ups: the desync log seam and a
  concurrent-handler test) and #5313 (re-registration load measurement).
- Planned follow-ups, tracked as follow-ups (no issue numbers yet), in this
  order: (i) a bounded pending queue for dropped notifications, a gateway-only
  change; (ii) a server-side re-arm of a tombstoned route row when a lease renewal
  comes up short, with a new advisory list that the gateway answers by
  re-announcing, which needs a protocol change and is planned to land before the
  safe-to-scale gate; (iii) a session-match guard and a refusal counter for the
  `accepted=false` disconnect.

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
rebar3 ct --dir apps/yuzu_gw/test/ct
```

To run a specific test suite:

```bash
rebar3 ct --dir apps/yuzu_gw/test/ct --suite yuzu_gw_integration_SUITE
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
| `yuzu_gw_registration_replay_total` | counter | Total registration replay attempts by the drip, any outcome. The drip runs after the upstream circuit breaker recovers, and when a heartbeat verdict lists sessions the gateway still holds |
| `yuzu_gw_registration_replay_queue_depth` | gauge | Agents still queued for registration replay, whether queued by an upstream recovery or by a heartbeat verdict (0 = idle, label `node`). A non-zero value is normal while a drip runs: each entry takes the `ProxyRegister` RPC time plus the spacing (20 ms by default), so a full 10000-entry verdict queue takes at least 200 s to drain (250 s at 5 ms RPC time, see the table under "Load and convergence bounds"), and a breaker-seeded snapshot can be larger. A value that does not fall over longer than that points to a replay that is not draining (INFERRED). No alert rule ships for it. |
| `yuzu_gw_registration_replay_triggered_total` | counter | Registration replays started, by `trigger` (`breaker` = the upstream recovered and every agent this node holds is queued for replay, unless a verdict-seeded drip is already queued, in which case the trigger is dropped, `heartbeat` = a heartbeat verdict listed sessions the server does not know and only those are replayed). Both series are created at 0 at start. |
| `yuzu_gw_heartbeat_unknown_truncated_total` | counter | `BatchHeartbeat` responses whose list of unknown sessions the server truncated at 4096. Sessions beyond the cap may be reported again by later heartbeats. Every occurrence is counted; the matching WARN is logged at most once per 60 s per heartbeat buffer process (the limit resets when that process restarts). |
| `yuzu_gw_heartbeat_verdict_dropped_total` | counter | Session ids named by a heartbeat verdict that were not queued for replay (label `reason`, closed set: `malformed` = not a usable session id, `not_local` = this node does not hold the session, `circuit_open` = the upstream circuit breaker is open, `queue_full` = the replay queue is at its cap, or the upstream process already holds more than 100 unhandled messages so the ids were not handed to it; the cap bounds only verdict appends, so while a breaker-seeded snapshot of that size or larger drains, every verdict id for an agent not already queued counts here). Every reason is created at 0 at start. Ids already queued, or replayed within the session guard window, are not counted. |
| `yuzu_gw_heartbeat_buffer_dropped_total` | counter | Heartbeat state the gateway's heartbeat buffer dropped instead of sending (label `reason`, closed set of six, all created at 0 at start: `buffer_full` = a heartbeat of a new session was dropped because the buffer held `max_heartbeat_buffer` sessions, or the oldest whole session was dropped because the buffer was still over `max_heartbeat_buffer_bytes` with no snapshot left to drop; `snapshot_oversize` = a single heartbeat larger than about 3 MiB was sent without its snapshot; `snapshot_evicted` = a retained snapshot was dropped, oldest first, because the buffer was over `max_heartbeat_buffer_bytes`; `heartbeat_oversize` = a heartbeat still larger than about 3 MiB after its snapshot was removed, or with more than 512 status tags, or with a status tag key or value over about 64 KiB or more than about 256 KiB of tag bytes in total (checked before the UTF-8 repair), was forwarded without its status tags; `heartbeat_invalid` = a heartbeat with a status tag that is not valid UTF-8 was forwarded with the invalid bytes replaced by replacement characters (the reason also counts tags removed because a tag was not a binary, and a heartbeat dropped for a bad or empty session id; see Heartbeat Batching); `chunk_rejected` = a single heartbeat the server rejected with a non-transient status was dropped). What is lost is older heartbeat state; for `heartbeat_oversize` the status tags of one heartbeat, for `heartbeat_invalid` only the invalid bytes, and for `chunk_rejected` one whole heartbeat. See [Heartbeat Batching](#heartbeat-batching). |
| `yuzu_gw_heartbeat_coalesced_total` | counter | Buffered heartbeats replaced by a newer heartbeat of the same session (unlabelled). Expected to rise while the server is unreachable. While a backlog is coalesced, the server's `yuzu_heartbeats_received_total{via="gateway"}` under-counts, because it counts the heartbeats the server received. |
| `yuzu_gw_cluster_peers_resolved` | gauge | Peer addresses found by the cluster-formation redial loop's most recent tick (label `node`; HA WS-4 `#4555`). 0 is expected for a genuinely single-node deployment. |
| `yuzu_gw_cluster_peers_connected` | gauge | Distribution-connected peer nodes as of the most recent redial tick (label `node`; `#4555`). Compare against `peers_resolved` — a sustained gap most often means a distribution-cookie mismatch across replicas. |
| `yuzu_gw_cluster_connect_failures_total` | counter | Total `net_kernel:connect_node/1` failures from the redial loop (`#4555`). |
| `yuzu_gw_cluster_address_cap_exceeded_total` | counter | Total times the lifetime distinct-address cap (`cluster_max_lifetime_addrs`) refused a never-before-seen address (`#4555` review round 2). Any non-zero value should be investigated immediately — it means the seed DNS name is returning an unexpectedly large or rotating/hostile answer set. |
| `yuzu_gw_heartbeat_rejected_total` | counter | Agent `Heartbeat` calls rejected before buffering because no usable session binding exists (label `reason`, closed set: `unknown_session` = the session is not held by this node, `no_connection` = no connection key to compare, `registry_unavailable` = the session index does not exist). Every reason is created at 0 at start. The agent re-registers on the `NOT_FOUND` answer when its build includes the reconnect fix (see the gateway manual); older agents only log it. A held session whose heartbeat arrived on a different connection is counted in the next row instead. See [Heartbeat admission](#heartbeat-admission). |
| `yuzu_gw_heartbeat_session_mismatch_total` | counter | Agent `Heartbeat` calls rejected because the session is held by this node but the call arrived on a different connection than the one that opened it (label `event`, always `security`, for SIEM routing; created at 0 at start). Also rises when an HTTP/2 proxy between agents and the gateway spreads one agent's calls over several connections. A rise of one per affected agent is expected when an agent's connection is replaced while its session is still held (observed with an injected GOAWAY, a test-only trigger; not observed with an abrupt close or a gateway restart). There is no audit row (the sender of a rejected heartbeat is not a resolved principal): the counter and a rate-limited summary log line are the signal. |
| `yuzu_gw_session_limit_rejected_total` | counter | Registrations refused because one connection already holds the configured number of agent sessions, pending plus live (`max_sessions_per_connection`, default 8). Unlabelled, created at 0 at start. A `Register` over the cap is answered `UNAVAILABLE` (14); a `Subscribe` over the cap ends its stream (status 2 today, see Known limits) and is counted the same. A stock agent holds one session per connection (INFERRED), so a rise points to an L4 balancer, forwarder or client that carries several agents on one connection; see "Per-connection session cap" under Configuration. |

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
