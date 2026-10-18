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
| `registering` | The first event after the process starts: it enters the routing table (the session was already registered with the server by `Register`) |
| `recovering` | The first event of an agent process restarted after a crash: see [When an agent's owner process crashes](#when-an-agents-owner-process-crashes) |
| `connecting` | Registered, waiting for the Subscribe stream (only for a process started without one) |
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
| `yuzu_gw_registry` | ETS routing table, plus the node-local session index used by heartbeat admission. It makes no `pg` call: each agent process joins its own `{agent, Id}` group, which a node reads to find an agent held by another node |
| `yuzu_gw_router` | Command fanout coordinator |
| `yuzu_gw_upstream` | Owner of the circuit breaker, the held stream-status notifications and the registration replay; makes no RPC itself (proxied calls run in the caller, notifications and replays in workers; #5695) |
| `yuzu_gw_upstream_regulator` | Permits for proxied `Register` and inventory calls and for replays, with a bounded wait queue whose entries carry the caller's deadline (see "Upstream call permits") |
| `yuzu_grpc_client`, `yuzu_grpc_client_channel`, `yuzu_grpc_client_config` | The upstream gRPC client, unary calls only (see [The upstream client](#the-upstream-client)): `yuzu_grpc_client` makes one call over a connection the channel hands it, `yuzu_grpc_client_channel` keeps a pool of HTTP/2 connections (gun) per endpoint open and reopens them, `yuzu_grpc_client_config` reads `{yuzu_gw, upstream_client}` |
| `yuzu_gw_agent_service` | Agent-facing gRPC server (AgentService proxy) |
| `yuzu_gw_conn` | Connection key (the HTTP/2 connection pid) of an agent-facing gRPC call, read from the call's context or stream |
| `yuzu_gw_heartbeat_admission` | Admission decision for agent `Heartbeat` calls (session held by this node and call on the connection that opened it), rejection counters and the rate-limited summary log line |
| `yuzu_gw_mgmt_service` | Operator-facing gRPC server (ManagementService proxy) |
| `yuzu_grpc_listener` | One gRPC listener per `grpc_listeners` entry: a Ranch listener running Cowboy's HTTP/2 connection with `yuzu_grpc_stream_h` as its only stream handler; a `gen_server` the supervisor starts as one of its last children |
| `yuzu_grpc_stream_h` | Cowboy stream handler: runs the listener's `auth_fun` on the peer certificate, resolves the caller's address (`yuzu_grpc_origin`), routes the call and spawns the handler |
| `yuzu_grpc_origin` | Which address a call is attributed to (transport peer, PROXY protocol header, `x-forwarded-for`); pure |
| `yuzu_grpc`, `yuzu_grpc_stream`, `yuzu_grpc_route`, `yuzu_grpc_runner`, `yuzu_grpc_frame` | The rest of the gRPC layer: context accessors (`peer/1`, `origin/1`, `peer_cert/1`), the stream API handlers use (`send/2`), route table built from the proto modules, handler runner (unary, server-streaming, bidi), and gRPC message framing |
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

The `ProxyRegister` (and `ProxyInventory`) call runs in the process of the agent's
own gRPC request, not inside the `yuzu_gw_upstream` process (#5695), so registrations
go to the server in parallel. Each needs a permit first ("Upstream call permits"
below): 48 at a time for `Register` by default, 8 for inventory. A request that finds
every permit taken waits in a bounded queue with its own deadline, the agent's
`grpc-timeout` less the stream handler's margin; it is refused `UNAVAILABLE` (the agent
retries) when the queue is full or its deadline passes first, and a request that ran
out of time while it waited is never sent, so the server never registers an agent
nobody is waiting for. The call to the server gets what is left of that deadline, at
most `upstream_rpc_timeout_ms` (5 s), and sends it as `grpc-timeout`. If the agent's
call is cancelled (the stream is reset, the deadline passes or the connection closes),
the request's process is stopped: its permit or its place in the queue is freed by its
exit, and its reservation is released at once. A call already in flight to the server
is not cancelled. An open breaker, a full queue, a passed deadline and a planned stop
are all answered `UNAVAILABLE`. Stream status, Guardian forwards and registration
replays are not affected.

When the server's built-in CA is active, that `RegisterResponse` now also carries
a signed **per-agent client certificate** — the same certificate an agent would
receive on the direct-connect path (PKI PR5d). The gateway relays the full
response verbatim, so the certificate reaches the agent with no gateway
configuration change. **Revocation note:** revoking a certificate invalidates the
presented leaf but does **not** prevent re-enrollment; to stop an agent from
re-enrolling and re-obtaining a certificate, **deny** the agent (dashboard
Devices → deny). Both the direct and gateway paths reject a denied agent before
signing. (In M1 the agent↔gateway hop is one-way TLS, so the agent's client cert
is not yet verified at the gateway transport — the agent's address reaches the
server as the app-layer `gateway_observed_peer`, which is attribution, not
authentication; the issued cert is for inventory, revocation, and the future
gateway-mTLS cutover.)

The gateway checks the agent id first, before it handles the peer address,
reserves a session or sends anything upstream: an empty, missing or non-binary id,
or one longer than 256 bytes, is answered `INVALID_ARGUMENT` locally (the server's
own bound), and a request the server would answer with a status that only means
"the request was wrong" does not count against the circuit breaker. See "Known
limits" for the exact rules.

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
session. A session whose agent process died and is being restarted to recover it
stays held, on the same connection, until the restarted process registers it again
or ends it (see [When an agent's owner process crashes](#when-an-agents-owner-process-crashes)):
a rejection there would make the agent drop the stream being recovered, and the
released agents listed below can wedge on it.

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
directly, or through a path that keeps **one gateway-side connection per agent for the
whole life of its session**: an L4 / TLS-passthrough path (a plain TCP load balancer, an L4
virtual IP, a TLS-passthrough proxy), or a proxy that terminates HTTP/2 **and is
configured for connection affinity**, meaning each client connection gets its own
backend connection, kept for as long as the client connection lives (see
[Keeping each agent on one backend connection](#keeping-each-agent-on-one-backend-connection)).
An HTTP/2-terminating proxy that pools backend connections across clients, or that
sends one agent's calls over several of them (a service-mesh sidecar that terminates
HTTP/2, nginx `grpc_pass` as observed below), is
**not supported**: it
may cause repeated heartbeat rejection or share
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

*Observed in testing.* The first two results are from a real C++ agent against a
plaintext gateway listener, two agents per run; the last two are 50 agents against a TLS
agent listener (OKD 4.21 and HAProxy 3.2.25, details below):

- Behind an HTTP/2-terminating proxy (nginx `grpc_pass`, two agents), every heartbeat was
  rejected as a connection mismatch: the mismatch counter rose and nothing reached
  the server. The agents still enrolled and still received commands over their
  `Subscribe` streams, and they re-registered on their back-off ladder (2 s doubling
  to a 300 s cap). The server's online count for the two agents flickered between 2,
  1 and 0. In this observed nginx case the topology therefore fails loudly in the
  counters and the gateway summary log, not silently; that is one two-agent test, not
  a guarantee for every HTTP/2-terminating proxy.
- Behind an L4 TCP forwarder (nginx `stream`), there were zero rejections.
- Behind HAProxy 3.2.25 (default settings, and with `http-reuse never`) and behind the
  OKD 4.21 router (HAProxy 2.8), 50 agents for ten minutes or more each, the mismatch
  counter stayed at 0 and every agent attributed its real address. HAProxy documents
  `safe` as reserving a backend connection to the session once it has carried a
  stream, which matches what was measured. See
  [Keeping each agent on one backend connection](#keeping-each-agent-on-one-backend-connection).
- Behind HAProxy 3.2.25 in `mode tcp` with `send-proxy-v2` to a `proxy_protocol` listener,
  50 agents for ten minutes, the mismatch counter stayed at 0, the zero-valued `no_claim`
  and `bad_claim` counters stayed at 0, and every agent attributed its real address. A
  forged PROXY header sent by a client that reached the listener directly (not a listed
  `source`) was ignored and counted as `untrusted_source`; a client that sent no header was
  closed after about a second. This is the measured stand-in for an F5 iRule, which was not
  tested.
- A multiplexing HTTP/2 proxy with upstream keepalive other than those was **not tested**.

The agent-facing message is the same `unknown session` for every reason (this is
deliberate, see above), so the agent log cannot tell the reasons apart. Diagnose from
the counters and the gateway summary log line, not from the agent log.

**Connection drain.** Two different things are described here, and only the first was
measured on the previous stack.

*Measured on the previous (grpcbox) stack, before the Cowboy listeners.* That server
closed a connection as soon as it sent `GOAWAY`, so a `Subscribe` stream and its binding
ended with the connection and there was no drain period. A heartbeat that reached the
gateway on a different connection while the old `Subscribe` was still bound was rejected
(`NOT_FOUND`, connection mismatch), and an agent with the reconnect fix recovered by
re-registering. With the real C++ agent (a build from the branch tree) a graceful `GOAWAY`
injected by the tester on the gateway-side connection (the gateway itself did not send one)
moved the agent's next heartbeat to a new connection: the mismatch counter rose by one, the
agent logged `(#1894)` and re-registered 16 s after the `GOAWAY`, and acked heartbeats
resumed about 30 s later. An abrupt close of just that agent's connection made it
re-register in 9 s with the counters unchanged. A graceful gateway SIGTERM and restart
(observed twice) showed the branch agent reconnecting in about 11 to 12 s with no
rejections; in the second run the released agents tested (v0.14.0-rc6, v0.13.0, v0.12.0,
default settings) did not notice the lost `Subscribe` stream across that restart, their
heartbeats got `NOT_FOUND`, and rc6 and v0.13.0 then wedged as described above (restart
them). A `GOAWAY` originating from the gateway on its own was not observed.

*On the Cowboy listeners.* Read from the Cowboy 2.19.0 source (`cowboy_http2`), not
measured: when the listener's supervisor stops its connection processes (a gateway stop,
or a listener restart), each HTTP/2 connection sends a first `GOAWAY` with last stream id
2^31-1 and `NO_ERROR`, waits `goaway_initial_timeout` (1 s), sends a second `GOAWAY` with
the real last stream id, and, if streams are still open (a `Subscribe` stream always is),
waits up to `goaway_complete_timeout` (3 s) before closing. The two options are not set by
the gateway, so these are Cowboy's defaults. The listeners are the last children of the
supervision tree, so they stop first. The gateway's own 10 s wait for in-flight commands
(`drain_pending`, in `yuzu_gw_app:stop/1`) runs after the tree is down (INFERRED from OTP,
which calls `stop/1` after the application's processes have stopped), so it does not hold
the listeners open. What an agent does with that `GOAWAY` was not measured on this stack.
The only restart measured on it is one gateway pod rollout on OKD with 50 agents (the
`yuzu-agent-chisel:0.14.1` image, default settings, agents connected directly): the agent
count fell as the old pod terminated and all 50 were back on the new gateway 58 s after the
rollout began, pod start included. The same rollout on the previous stack, with the same
agents, was still at 0 agents after 405 s. One run each; the difference is not explained.

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
start, after telemetry setup and before the gateway supervision tree starts; the
listeners are that tree's last children, so they start after it), so in initialized operation a burst of simultaneous first rejections produces one line; a heartbeat before the state exists can race with other lazy initializations and may produce an extra line. At startup the
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
  regression in the connection accessor (`yuzu_gw_conn:key_from_ctx/1` and
  `key_from_stream/1` return `undefined` when the call carries no connection). The
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

A notification is held, not dropped, when it cannot be sent at once (#4632).
Each one goes into a bounded pending store in the upstream client, and a drain
step sends the held entries first in first out, at most 10 at a time, each on
its own worker so the upstream client never waits on one. A notification is held
while 10 are already in flight and while the upstream circuit breaker is open or
half open. (Read from the code: INFERRED, not measured on a rig; the measured
runs are marked below.)

- **Keys.** The store is keyed by agent id, session id and stream home id. A
  newer notification for a key that is already held replaces the held one and
  keeps its place in the queue, so a `CONNECTED` followed by a `DISCONNECTED` for
  one session sends only the `DISCONNECTED`, and an identical repeated
  `CONNECTED` is sent once. The exception is the key of a half open probe that is
  out: that key is no longer held, so a newer notification for it is held in the
  probe's reserved slot and supersedes the probe's older notification if the probe
  fails (see Probe and Cap). Two sessions of one agent are two keys and both are
  kept. Replacements are counted in `yuzu_gw_upstream_notify_coalesced_total`.
- **Probe.** While the breaker is half open exactly one held notification is
  sent, as the probe, and nothing else is sent from the store while it is out.
  That rule holds in the half open state only: if a call-path RPC closes the
  breaker while the probe is still out, the drain resumes at once (INFERRED from
  the code). If the probe succeeds the breaker closes, the registration replay of
  every agent the node holds starts (OBSERVED on a rig), and the rest drain first
  in first out; if it fails the breaker opens again with a doubled backoff and the
  probe's notification goes back to the head of the queue, unless a newer
  notification for the same key is held by then: the newer one supersedes it
  (counted in `yuzu_gw_upstream_notify_coalesced_total`). The one exception is
  a probe whose request cannot be encoded inside the gateway: that does not
  move the breaker, and the notification is evicted instead of requeued (see
  Known limits). A successful probe proves only the notification path, which on
  the server is an in-memory session lookup: a server whose registration path is
  failing can still accept the probe (INFERRED from the code, not run). A probe
  result that arrives after the breaker has moved on to a later half-open period
  does not change the breaker. The probe has a deadline of its own, owned by the
  gateway: `notify_probe_timeout_ms` (default 15000 ms, see "Upstream client
  tuning"). A probe worker that has not reported by then is killed and the probe
  fails like any failed probe: its notification goes back to the head of the
  queue (a newer notification for the same key still supersedes it), the breaker
  opens again with the doubled backoff, and the next half-open cycle sends a new
  probe. One WARN is logged per timeout (see the log table). Behind it sit the
  upstream client's own bounds (`yuzu_grpc_client`: a connect timeout, TCP and TLS each,
  5000 ms by default, and a per-call timeout of 5000 ms that includes the connection wait),
  which usually end an unresponsive probe first. The 5 to 10 seconds per half-open cycle
  that was observed against an unresponsive upstream, and the 20 to 25 second serial
  sum, were measured on the previous client (grpcbox) and have not been re-measured
  on this one. Those bounds can be removed (an endpoint `connect_timeout` set to
  `infinity`, which no shipped configuration does, or a connection process blocked in
  initialisation); the gateway's deadline does not depend on them. The default sits above the client's default bounds; a `did not answer` WARN that repeats while the server is healthy points at raising `notify_probe_timeout_ms`, and a value below about 5000 kills probes that would have answered (a killed probe is requeued, so delivery stays at least once). The deadline was exercised in
  unit tests with a mocked client, not against a real unresponsive upstream on a
  rig. It covers the notification probe only: a proxied `ProxyRegister` or
  `ProxyInventory` is bounded by its caller's deadline and a replay by
  `upstream_rpc_timeout_ms`. Without the probe, held notifications could sit
  indefinitely after the server recovers, because a disconnected session produces
  no heartbeat to trigger a replay. A probe that timed out may still have reached
  the server, and its notification is sent again after the requeue, so delivery of
  a probe notification is at least once. OBSERVED on a rig: when the frozen server
  was resumed after two timed-out probes, the same `DISCONNECTED` reached it three
  times and the server counted one `deregister` `session_mismatch` and one
  `unknown_session` for the extra copies, with no error and no change to the
  final state. With five failed probes in a row the same `DISCONNECTED` reached
  the server six times. A held `CONNECTED` used as the probe was also delivered
  twice (the timed-out copy executed when the frozen server resumed, then the
  resend) and changed no server desync counter; all 300 agents ended routable.
- **Cap.** `notify_pending_max` bounds the number of held keys, not agents (#5695).
  Its default is three per connection the agent listeners admit (the sum of their
  `limits.max_connections`), and at least 15,000; the shipped `sys.config.prod`
  sets 180,000 for its 60,000 connections. Why three: a server that is down lets
  no agent get a new session, so an outage holds at most one `DISCONNECTED` per
  agent; a server that is up but slow lets an agent that flaps register again,
  which holds its old session's `DISCONNECTED` and its new session's `CONNECTED`,
  two per agent for one flap of the whole fleet; the third leaves room for a
  second flap. Each send in flight (the half open probe included) still counts
  toward the cap, because its notification comes back if the send fails: a new
  key is admitted only while the held keys plus the sends in flight stay below
  the cap. A newer notification for a key that is in flight is never refused at
  the cap: it replaces what would come back. Memory: about 0.9 KB per held key
  (855 bytes measured with 100,000 synthetic notifications), so 180,000 is a
  ceiling of about 160 MB, reached only with that many keys held.
- **When the store is full** (#5695). A `DISCONNECTED` evicts the oldest held
  `CONNECTED` and is held in its place (counted in
  `yuzu_gw_upstream_notify_lost_total{event="connected",reason="evicted"}`). A
  `CONNECTED`, or a `DISCONNECTED` when no `CONNECTED` is held, is refused
  (`yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}` and
  `yuzu_gw_upstream_notify_lost_total{reason="at_capacity"}` by event). The two
  losses are not alike, and neither is put right by the heartbeat verdict: the
  server already knows the session, so it never lists it as unknown. A lost
  `CONNECTED` leaves a live agent that the server cannot dispatch to; the gateway
  puts it right itself: the loss arms a full registration replay, run once the
  breaker is closed and the store has drained below half, and every agent
  re-sends its `CONNECTED` after its adopted replay (counted in
  `yuzu_gw_registration_replay_triggered_total{trigger="notify_loss"}`). A lost
  `DISCONNECTED` leaves the server listing a session as online until that agent
  registers again, which nothing on the gateway can repair; that is why it is
  the one kept.
- **Failed sends are retried** (#5695). A send that fails is held again at the
  head of the store and retried (`yuzu_gw_upstream_notify_requeued_total`), in any
  breaker state. While the breaker is closed each failure counts against it, so a
  server that keeps failing gets at most the failure threshold (5) of retries
  before the breaker opens and the half open probe takes over. A notification the
  server answers as a bad request, or one that cannot be encoded, is not retried
  (`notify_lost_total{reason="rejected"}`), nor is one whose worker died without a
  result (`reason="crashed"`).
- **Order.** A notification whose key has a send in flight waits until that send
  has finished, so a `CONNECTED` and the `DISCONNECTED` after it for one session
  cannot reach the server the other way round.
- **High-water mark.** `yuzu_gw_upstream_notify_pending_hwm` is the most keys held
  at once over the last one to two minutes, so a spike between two scrapes is
  seen; `yuzu_gw_upstream_notify_pending_max` is the cap in force.
- **Peer address.** The peer address of a notification is the agent's
  `:authority` header (or `x-forwarded-for`), so the agent controls every byte of
  it. The gateway sanitises it where the `Register` call reads it and again where
  the notification is admitted to the store: a value that is not valid UTF-8
  becomes `invalid`, and a longer one is cut to 255 bytes at a character
  boundary. The sanitised value is the one kept in the pending registration, in
  the per-agent process, in the `Agent <id> connected from <address>` log line and in the
  `peer_addr` of the notification, which is how the gateway sends it to the server.
  The sanitised value is not sent in the registration request to the server
  (`ProxyRegister` forwards the agent's `RegisterRequest` as received). A legitimate DNS name with a port can reach about 259
  bytes in the pathological maximum and would be cut: cosmetic, because the field
  is informational (an audit trail value) (INFERRED from the code). The
  `Agent <id> connected from <address>` line is a log copy only: it cuts the agent
  id and the address to 128 bytes each and replaces control characters with `?`
  (`log_text`), whereas the value that is kept and sent is the sanitised one of up
  to 255 bytes.
- **Volatile.** The pending store is memory only. It is lost when the upstream
  client process restarts, and when the gateway stops except for what a planned
  stop sends before it goes (see Planned stop); a crash or a kill sends nothing.
  Failed sends are retried while the process runs, as described above: a
  returned RPC error puts the notification back at the head of the store, a
  notification the server rejects as a bad request or that cannot be encoded is
  counted lost (`reason="rejected"`; a probe that cannot be encoded is evicted,
  see Known limits), and one whose worker died without a result is counted lost
  (`reason="crashed"`). The gauges `yuzu_gw_upstream_notify_pending` and
  `yuzu_gw_upstream_notify_inflight` report the held keys and the tracked workers
  of the current upstream client process only.

#### When the server does not record a notification

The server answers `NotifyStreamStatus` with gRPC OK and a `StreamStatusAck`
whose `acknowledged` field says whether it recorded the notification. Before
NOTIFY-ACK (#5695) the gateway took every OK as delivered. An independent test
with a stub that answered every `CONNECTED` with `acknowledged=false` for 60 s,
then `true`, left 500 of 500 agents unknown to the server for the 5 minutes it
watched after the switch: one `CONNECTED` per agent, never sent again, and the
heartbeat verdict does not repair it because the server knows those sessions. The
gateway now reads the field: `acknowledged=false` means **not delivered**.

What the server means by `false` (read from `NotifyStreamStatus` in
`server/core/src/gateway_service_impl.cpp`; each case logs a WARN on the server
and counts in `yuzu_server_gateway_route_desync_total{op="notify_stream_status"}`
under the outcome named):

| Server WARN line (start) | Outcome | Event | Kind |
|---|---|---|---|
| `NotifyStreamStatus: CONNECTED for session ... refused — the directory read degraded and this replica holds no matching local session` | `connected_unverified` | CONNECTED | Transient: the route store could not be read; the same notification is accepted once it reads again |
| `NotifyStreamStatus: unknown session ... for agent ...` | `unknown_session` | both | Definitive for that session: the server lost its state or never saw the registration. For a live session the heartbeat verdict names it and the replay re-registers it |
| `NotifyStreamStatus: CONNECTED for session ... but the directory names a different session — rejecting`, or `NotifyStreamStatus: CONNECTED for session ... is no longer the currently-installed session` | `stale_connected_session` | CONNECTED | Definitive: a newer registration owns the agent |
| `NotifyStreamStatus: CONNECTED for agent ... claims cluster_id ..., which differs from this agent's already-bound cluster affinity` | `cluster_affinity_violation` (op `announce_connected`) | CONNECTED | Definitive until the cluster configuration is fixed |

A failed directory write is answered `true` by this server (the write is
fail-open); a server change in review (#5961) answers it `UNAVAILABLE` instead,
which the gateway already retries as a failed send. The answer carries no reason,
so the gateway treats every `false` the same way:

- **Held and sent again.** The notification goes to a retry set beside the
  pending store, one entry per session, and is sent again after a backoff with
  decorrelated jitter: the next delay is a random value between
  `notify_unacked_retry_base_ms` (1 s) and three times the previous delay, at
  most `notify_unacked_retry_max_ms` (60 s). The first resend comes 1 to 3 s
  after the refusal; once refusals go on, the delay averages about 34 s
  (simulated), so 5,000 refused sessions cost about 150 resends a second. A
  server that starts accepting again has every refused notification within about
  a minute.
- **The circuit breaker is not touched.** A refusal is an answer, so it is not a
  failure, and the server recorded nothing, so it is not a recovery either: it
  neither opens the breaker nor clears real failures. A refused half-open probe
  leaves the breaker half open, and the next notification is probed.
- **A newer notification wins.** A `DISCONNECTED` for the session cancels a
  pending `CONNECTED` resend and is sent; the `CONNECTED` is not sent again. A
  resend already on its way is waited for, so the two still reach the server in
  order.
- **A `CONNECTED` is resent only while the gateway holds the session**, checked
  when each backoff ends. It has no time limit: a live session the server does not
  record is the failure this exists to repair.
- **A `DISCONNECTED` is resent for at most
  `notify_unacked_disconnected_window_ms` (120 s)**, then counted lost
  (`yuzu_gw_upstream_notify_lost_total{event="disconnected",reason="unacknowledged"}`).
  The server answers a `DISCONNECTED` `false` only for an unknown session:
  harmless when it never knew the session or already removed it, and otherwise
  the route row it would have removed stops being routable when its 90 s lease
  runs out.
- **Bounded.** Resends use at most 5 of the 10 notification slots, and new
  notifications are sent first, so a large refused population cannot hold up a
  fresh `CONNECTED` or `DISCONNECTED` (a unit test with 5,000 refused sessions,
  each refusal answered after 5 ms, saw a fresh `CONNECTED` and a fresh
  `DISCONNECTED` each delivered within 12 ms, measured with a 10 ms poll, and
  never more than 5 resends in flight). The retry set holds at most `notify_pending_max`
  sessions; a refusal past that is counted lost (`reason="unacknowledged"`).
- **Planned stop.** When the last gasp begins, a refused `CONNECTED` still
  waiting is dropped (counted `reason="shutdown"`; the session ends with the
  stop), and a refused `DISCONNECTED` still waiting is sent with the other held
  notifications. A refusal during the last gasp is not resent.
- **Volatile**, like the pending store: lost when the upstream client restarts.

Signals: `yuzu_gw_upstream_notify_unacknowledged_total{event}` counts every
`false`; `yuzu_gw_upstream_notify_unacked_keys` is the number of sessions waiting
for a resend; `yuzu_gw_upstream_notify_unacked_ended_total{outcome}` says how each
wait ended. The gateway logs a WARN, at most one a second, `Server did not record
the <event> stream status notice for <agent> (acknowledged=false); sending it again
in <ms> ms`. `YuzuGatewayNotifyUnacknowledged` fires when sessions have been
waiting for 10 minutes: the server is refusing to record sessions. Read the
server log for the lines in the table above and
`yuzu_server_gateway_route_desync_total{op="notify_stream_status"}` by outcome. For
`connected_unverified`, the route store cannot be read: check PostgreSQL and the
server's pool (`yuzu_server_gateway_route_write_failed_total{op="session_lookup"}`,
`YuzuGatewayRouteWriteFailed`); the resends succeed once it reads again. For the
definitive outcomes, find the agents in the gateway WARN and look at their
registrations on the server (a newer session elsewhere, a cluster id mismatch).

Measured evidence for this behaviour (OBSERVED on a loopback rig with a
debug-built server, PostgreSQL with fsync off, on a shared host): a cold wave of
1000 simulated agents dropped 0 notifications and had 1000 routable rows
(confirmed placement and a valid lease) by the first poll after registration
ended, at most 1.2 s later; 30 real agents dropped 0, all 30 were routable and
answered a real command; in an outage with the breaker open, 10 held
`DISCONNECTED` notifications waited 55 to 59 s, then exactly one was sent as the
probe when the breaker went half open, it closed the breaker, and the other 9
followed in order, with the pending gauge back at 0 within 2 ms of the half open
transition (five runs: three with simulated agents and two with real agents). With the server kept frozen through the first two half open periods the
probe failed twice by timeout (the breaker reopened with 120 s and then 240 s
backoff, and the pending gauge dipped to 9 while the probe was out and returned
to 10), the third probe closed the breaker, and all 10 held notifications were
delivered in their original order. For contrast, the previous build dropped all 10
(`reason="circuit_open"`) in three runs of the same outage, and the server still
listed the 10 stopped agents as online about 2.6 minutes after the server resumed
(10 route rows without a lease); the fixed build left none of them online and
tombstoned their route rows. The previous build's stale
registry entries were still online 20 minutes after the server resumed; only the
route directory cleared (leases expired by 2 minutes, rows tombstoned at about 5
minutes and deleted at about 10). Other probe paths observed: the open duration
doubled and then held at the configured cap (5, 10, 20, 20 s with a 20 s cap, six
half open periods, one probe each); a probe refused by a stopped server failed in
under a millisecond and doubled the backoff; killing the probe worker produced
one reopen and the event went back to the head; and a `ProxyRegister` retry that
arrived while the probe was out drove the breaker transition, the late probe
result left the breaker alone, and the event was still requeued. The runs, their
instruments and what they did not cover are in the
[evidence record](../security-reviews/gateway-notify-pending-store-2026-10-05.md).
The statements that exactly one probe was sent, that the held entries were delivered in order
and how often each key was sent come from a temporary telemetry tracer loaded into
the gateway, which has an observer effect; the 100 ms sampler cannot resolve a 2 ms
event, and the gateway debug log has no line for a successful notification.

The same behaviour was also measured with TLS on every hop that the notification
path uses (OBSERVED on the same rig: the agent edge is one way TLS, the upstream
channel and the management channel are mutual TLS, all from the server's default
certificates, with a private certificate directory). A cold wave of 1000
simulated agents over TLS dropped 0 notifications. With the handshakes done
before the burst, 1000 rows were routable at the first poll, 0.4 to 0.5 s after the
last registration (all registered in 2.11 to 2.15 s against 1.88 to 1.93 s without
TLS; 100 ms sample peaks of 574 to 904 held keys). With the handshakes overlapping
the burst (the agents not preconnected), all 1000 registered on the first attempt
in 2.45 and 2.52 s, 1000 rows were routable 0.6 to 0.7 s after the last
registration, the sample peaks were 749 and 901, and there was no handshake error
and no acceptor crash line. 30 real agents over
TLS dropped 0, all enrolled (two `ProxyRegister` calls each, 60 in total, 30
certificates issued) and answered commands, and a 5 minute steady state logged no
warnings or errors. The breaker hold, single probe and FIFO flush, the failing
probe by timeout and the probe refused by a restarted server behaved as without
TLS; the probe that was the first caller back after a server restart paid a fresh
TLS handshake (about 5.1 ms against 1.8 ms without TLS). With an untrusted
upstream certificate authority every probe failed in about 2 ms with an
`unknown_ca` handshake error, the 10 held notifications stayed held and the
backoff doubled. A TLS handshake failure on the upstream channel is counted by
`yuzu_gw_upstream_tls_handshake_failures_total` and feeds the breaker like any
other transport error. 1000 simulated agents over TLS that each sent a
certificate signing request in the first `Register` and registered again on a new
connection with the issued certificate dropped 0 notifications, left 1000
routable rows, made 2000 `ProxyRegister` calls and got 1000 certificates, with
notifications in flight never above 10 (OBSERVED). All were registered in 4.6 to
5.8 s against 1.95 s without a signing request: a signing-request `Register` took
about 3.3 ms against 2.0 ms, and every `Register` ran one at a time in the
gateway's upstream process (before #5695; they now run in parallel under permits). The 1000 first-`Register` entries stay in the
gateway's pending registry until the bootstrap connection's dead-connection grace
clears them (about 19 s after connect, with gateway memory about 75 MB higher
meanwhile; the cause is INFERRED from the registry code and the 15 s default
grace, since the simulated agents close that connection at once). The end state
was clean: 1000 routable rows and no never-announced row left. Without a packet
capture, TLS on each hop was shown with `openssl` client probes (OBSERVED): the
agent edge is one way TLS 1.2 (a plaintext HTTP/2 preface got a TLS alert and no
HTTP/2 settings); the server's upstream port rejected a missing client
certificate and a certificate from another CA and accepted the gateway's, and it
also accepted the server's own certificate: at the TLS layer that port admits any
certificate that chains to the run's CA, so the gateway's identity is not pinned
there (the gRPC layer of that port was not probed). The management port rejected a missing or other-CA certificate, and a valid
certificate with the wrong pinned key got `UNAUTHENTICATED` with `pin_mismatch`
counted. Under sustained command load over management mutual TLS, 179,081
commands to 30 real agents all reached every targeted agent with results, with 0
authentication errors and 0 handshake failures, and latency within noise of
plaintext (p50 about 29 ms at concurrency 4; at 16 the debug-build server was
the bound). Not covered: client certificates on the agent edge (the shipped edge
does not verify them), certificate rotation or expiry, multiple replicas, a
release-build server, and packet-level capture. TLS 1.3 is not offered on the agent
edge (a TLS 1.3 client was refused with a protocol-version alert, OBSERVED) and was
not tested on the management listener.

---

## GatewayUpstream Service

**Status: PARTIALLY IMPLEMENTED**

The `GatewayUpstream` service is a gRPC service exposed by the C++ server
specifically for gateway communication. It is defined in
`proto/yuzu/gateway/v1/gateway.proto`. A gateway `session_id` is resolved to
an agent against the durable route directory in Postgres (batched reads of up to
1,024 ids each on one database connection per RPC), so any core replica can
answer for it; a session the replica holds no local entry for is still ingested
and is also reported in the `BatchHeartbeat` unknown-session list below. Run
exactly one server replica until the HA safe-to-scale gate lifts
([ADR-2002](../adr/2002-high-availability-architecture.md) section 7c).

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
answering server replica does not hold: ids the durable directory does not
know, and ids the directory knows but this replica holds no local session for
(for example right after a server-only restart; these are still ingested and
their leases renewed, and listing them makes the gateway replay
`ProxyRegister` so the replica rebuilds its local session). At most 4096 are
listed; empty and over-length ids are never listed. A session whose directory
read failed and that this replica holds no local session for, and a session id
that matches more than one directory row (refused as ambiguous), is neither
acknowledged nor listed.
`unknown_session_ids_truncated` is set when more than 4096 ids would be listed
(directory-unknown ids plus directory-known ids awaiting replay). A server that predates these fields and a
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

`peer_addr` is the address the gateway attributed the agent to when it registered: a bare
IP address (see [Client addresses behind a proxy](#client-addresses-behind-a-proxy)), or
`unknown` when the listener had no observation for the registration. It used to be the
`:authority`, `x-forwarded-for` or `unknown`. The server does not read the field.

---

## Configuration

The gateway is configured via `gateway/config/sys.config`. Key settings:

```erlang
{yuzu_gw, [
    %% The agent-facing (:50051) and operator-facing (:50063) gRPC listeners
    %% are the {grpc_listeners, [...]} entries described under "gRPC listeners"
    %% below. The agent_listen_* / mgmt_listen_* keys that older configs carry
    %% are read by nothing and have no effect.

    %% No effect: no gateway code reads upstream_addr or upstream_port (the
    %% environment variables YUZU_GW_UPSTREAM_ADDR / YUZU_GW_UPSTREAM_PORT only
    %% set these two keys). The address the gateway dials is the endpoint of
    %% the default_channel in {upstream_client, ...} (see "The upstream client")
    {upstream_addr, "127.0.0.1"},
    {upstream_port, 50055},

    %% No effect either: no gateway code reads this key. The connections per
    %% endpoint are the `pool_size` option of the channel (default 1)
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
    %% ... plus {grpc_listeners, [...]}, below
]}
```

### gRPC listeners

The gateway's two listeners are served by its own gRPC layer over Cowboy/Ranch
(`yuzu_grpc_listener`). They are configured as a list of maps under
`{yuzu_gw, grpc_listeners}`, one map per listener, and are the last children of the
supervision tree. Every entry is validated before anything is bound, and the validation
is **closed**: an entry and each of its `tls`, `listen`, `http2`, `limits` and `origin`
maps may carry only the keys listed below, and any other key refuses boot. An entry
that cannot start (an unknown or legacy key, an incomplete `tls` map, an `origin` mode
with no `sources`, an `auth_fun` on a listener that serves the agent service, a service module
that lacks what its proto declares, a name or a fixed port used twice) refuses boot with
a critical log line that names the defect by a term (`legacy_keys`, `unknown_keys`,
`tls_incomplete`, `auth_fun_on_agent_listener`, `duplicate_name`, ...; the terms and what to
change for each are in the
[table in Upgrading the Gateway](upgrading.md#gateway-listeners-move-to-grpc_listeners-the-cowboy-edge--breaking)).
A config with no listeners at all (the key
unset, empty or `[]`) refuses boot too, because the gateway would otherwise start,
report healthy and accept no connection, and so does a config whose entries are all valid
but none of which **routes the AgentService** (an entry counts only if its `services` map has
the key `'yuzu.agent.v1.AgentService'`; `service_protos => [agent_pb]` with an empty
`services` does not, because nothing would answer an agent; no agent could connect and
`/readyz` would never answer ready); the lab-rig acknowledgement for both is
`{yuzu_gw, [{allow_no_listeners, true}]}` (only the literal `true`), which unit tests use and
a deployment does not. A `services` entry whose module exports none of that service's methods
is refused too (`{bad_routes, {service_without_routes, Name}}`, a mistyped module); one that
exports only some is accepted and answers the rest `UNIMPLEMENTED`. Moving from the old `{grpcbox, [{servers, ...}]}` shape: see the key mapping
below and [Upgrading the Gateway](upgrading.md#gateway-listeners-move-to-grpc_listeners-the-cowboy-edge--breaking).
This is the production shape, from `gateway/config/sys.config.prod` (comments shortened):

```erlang
{yuzu_gw, [
    {grpc_listeners, [
        %% Agent listener: one-way (server-authenticated) TLS. NEVER give this
        %% listener an auth_fun (see "Moving the agent edge to mutual TLS").
        #{name => agent,
          service_protos => [agent_pb],
          services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service},
          listen => #{port => 50051, ip => {0,0,0,0}},
          tls => #{certfile   => "/etc/yuzu/certs/default-gateway.pem",
                   keyfile    => "/etc/yuzu/certs/default-gateway.key",
                   cacertfile => "/etc/yuzu/certs/default-ca.pem",
                   verify => verify_none,
                   fail_if_no_peer_cert => false},
          acceptors => 32,
          http2 => #{idle_timeout => 180000, max_concurrent_streams => 32}},

        %% Mgmt listener: strict mTLS (the defaults) + the SPKI peer pin.
        #{name => mgmt,
          service_protos => [management_pb],
          services => #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service},
          listen => #{port => 50063, ip => {0,0,0,0}},
          tls => #{certfile   => "/etc/yuzu/certs/default-gateway.pem",
                   keyfile    => "/etc/yuzu/certs/default-gateway.key",
                   cacertfile => "/etc/yuzu/certs/default-ca.pem"},
          auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1,
          acceptors => 4,
          http2 => #{idle_timeout => 600000, max_concurrent_streams => 4096}}
    ]}
]}
```

| Key | Meaning |
|---|---|
| `name` | Any term; names the listener. Mandatory and unique (the old `{grpcbox, [{servers, ...}]}` shape had no names). |
| `service_protos` | The proto modules (`agent_pb`, `management_pb`) that describe the services the listener serves. |
| `services` | `#{ServiceName => Module}`: the module that serves each service. |
| `listen` | `#{port, ip, socket_opts}`. `ip` defaults to `0.0.0.0`. `port => 0` binds any free port (tests). An optional `socket_opts` list is appended to the socket options; it may not carry `ip`, `ifaddr`, `fd`, `port` or `{local, _}`, which would move the bind away from `listen` (boot refuses them on every listener, because an `ifaddr` of `0.0.0.0` on a listener whose `ip` says loopback would publish the plaintext management plane to the network). |
| `tls` | Keys: `certfile`, `keyfile`, `cacertfile`, `verify`, `fail_if_no_peer_cert`, `ciphers`. Omit the map for plaintext HTTP/2 (an explicit choice: a listener with no `tls` map is plaintext whatever certificates are mounted next to it). When present, `certfile`, `keyfile` **and** `cacertfile` are all required and an incomplete map refuses boot. A listener that still carries certificate settings under a legacy key (`transport_opts`, `ssl`) refuses boot rather than running plaintext, so "certificates configured but plaintext" cannot come from a half-converted entry. `verify` defaults to `verify_peer` and `fail_if_no_peer_cert` to `true` (mutual TLS); `verify => verify_none` is one-way TLS and then `fail_if_no_peer_cert` defaults to `false`. TLS 1.2 only. Cipher suites follow the certificate's key type when `ciphers` is unset: ECDHE-ECDSA AEAD suites for an EC key (the generated default certificates), ECDHE-RSA AES-GCM suites for an RSA key (a bring-your-own certificate); an explicit `ciphers` list always wins. FIPS mode is not claimed. The listener also sets `reuse_sessions => false` (every reconnect is a full TLS handshake, so a reconnect herd costs more CPU than with session resumption) and `honor_cipher_order => true` (the gateway's list decides the suite, not the client's); listeners built from the old `{grpcbox, [{servers, ...}]}` shape took OTP's defaults for both. **Not supported:** the `tls` map is closed, so an encrypted private key (`password`) and the ssl options `depth`, `crl_check`, `partial_chain` and `versions` that a `transport_opts` map could carry refuse boot. Decrypt the key first (`openssl pkey -in encrypted.key -out gateway.key`, with the file readable by the gateway user only) and use the defaults; supporting them is a follow-up, not something to work around. **Decrypting removes the passphrase protection the key had at rest**: if you answer "are private keys encrypted at rest?" for this key, the answer is now "protected by file permissions and the secret store that mounts it". |
| `auth_fun` | Management listener only: `fun(Der) -> {true, Id} \| true \| false`, run by the stream handler on the peer certificate before a handler exists. Needs `tls`. **Boot refuses an `auth_fun` on any listener that serves the agent service** (`auth_fun_on_agent_listener`), that is, whose `service_protos` include `agent_pb` **or** whose `services` map has `'yuzu.agent.v1.AgentService'` as a key (the management proto embeds the AgentService definition, so `service_protos` alone would miss it), including a combined agent-and-management listener that has one; a combined listener without an `auth_fun` is valid (the integration test uses one). That refusal and the boot and `/readyz` rule are two different tests: the refusal asks whether the entry *serves* the agent service by either route, while boot and `/readyz` require at least one entry that *routes* it (the `services` key). |
| `origin` | Keys: `mode`, `sources`, `trusted_hops`. How the caller's address is decided; default `#{mode => transport}`. See [Client addresses behind a proxy](#client-addresses-behind-a-proxy). |
| `acceptors` | Acceptor processes, a positive integer (default 4). `sys.config.prod` and the reference configs give the agent listener 32 for reconnect storms; the plaintext default, demo and UAT configs set nothing and so run 4. |
| `http2` | Overrides of the Cowboy HTTP/2 options, by Cowboy's own option names; the options the layer owns and any unknown name are refused. Defaults: `idle_timeout` 600000 ms, `max_concurrent_streams` 1024, `max_frame_size_received` 16384, `linger_timeout` 1000, and, on a listener whose `services` map has `'yuzu.server.v1.ManagementService'` as a key (a combined agent-and-management listener included), `max_received_frame_rate` `{100000, 10000}`: 100000 received frames per 10 s. A listener that routes only the AgentService leaves `max_received_frame_rate` unset and so keeps Cowboy's own `{10000, 10000}`, the flood guard for the agents' unauthenticated connections. The management value is ten times Cowboy's because the server sends every command of a fan-out over its one connection to the management listener, at about 2 received frames per call: Cowboy's ceiling is about 5000 calls per 10 s, and past it Cowboy closes the whole connection with GOAWAY `enhance_your_calm` and every call in flight on it fails (`stream_error`). `{100000, 10000}` is about 5000 calls per second, far above the ~205 responses per second measured per server channel even with 8 channels to one gateway, and it is still finite. Raising `max_concurrent_streams` does not help: the ceiling counts frames, not streams. A listener that routes the `ManagementService` also defaults `max_concurrent_streams` to 4096 instead of 1024. The server sends each forwarded command as its own call over its one connection and queues the calls past the cap, so a fan-out takes about the agents' answer time or (agents x mean answer time / cap), whichever is longer. Measured over one loopback connection with 5,000 agents answering uniformly in 0 to 10 s: 30.7 s at 1024, 18.8 s at 2048, 11.9 s at 4096 and 10.1 s at 8192 (25,000 agents: 37.1 s at 4096, 21.7 s at 8192). 4096 brings 5,000 agents to within about 2 s of the answer time. It is not higher because the cap also bounds the memory the management connection can hold: each call in flight can have one response waiting to be written when agents answer faster than the server reads, and 5,000 answers of 256 KiB inside 1 s peaked at about 1 GB in the connection at 4096 and 1.2 GB at 8192. Past 5,000 agents per gateway, more server connections or one message per fan-out (#5956) is the way forward, not a larger cap. The measurement used a gun client that keeps at most the cap in flight, as the server's gRPC C++ client does; it was not repeated with the server itself. `sys.config.prod` and `deploy/docker/reference-gateway-sys.config` set `max_received_frame_rate => {100000, 10000}` and `max_concurrent_streams => 4096` on the management listener explicitly; every other shipped config gets them from the default. `sys.config.prod` and the reference configs set the agent listener's `idle_timeout` to 180000 because agents ping every 60 s (the 60 s default would race the ping) and `max_concurrent_streams` to 32. The shipped plaintext default, demo and UAT configs set neither and so inherit 600000 ms and 1024 streams. The management client does not ping, so it keeps ten minutes. |
| `limits` | Keys: `max_connections` (a positive integer or `infinity`, the default; the most simultaneous connections the listener holds, over which Ranch stops accepting until one closes), `max_message_bytes` (a positive integer, default 4194304), `send_timeout_ms` (a positive integer or `infinity`, default 30000), `max_connection_memory_bytes` (a positive integer at least 1048576, or `infinity`; default eight times `max_message_bytes`, i.e. 32 MiB for the 4 MiB default, except on a listener that routes the `ManagementService` and does not serve the agent service, where the default is no ceiling) and `request_timeout_ms` (a positive integer or `infinity`, default 30000). A request message larger than `max_message_bytes` is refused before it is buffered, but a message that fits is decoded in full, so a smaller `max_message_bytes` also bounds the memory one stream can make the gateway decode. `max_connection_memory_bytes` caps a single connection's memory (a `max_heap_size` on the Cowboy connection process that counts the refc buffers its streams hold); a connection that buffers more than this of half-finished requests is killed by the VM and the kill is counted in `yuzu_gw_grpc_connection_killed_total`. The VM checks the ceiling when the connection collects its garbage and counts the binaries that are already dead, so the default is sized from what one well-behaved connection was measured to reach, not from the bytes in flight alone: one message of `max_message_bytes` costs the connection three times its size at its peak (the received chunks, the joined message and the decoded request) plus under 1 MiB, so the 32 MiB default lets two full-size messages complete at once with room to spare and kills a peer holding half-sent full-size streams at about the eighth. Do not set it below about four times `max_message_bytes`: an agent sending one full-size message can then be killed. The ceiling also counts the responses waiting to be written, which is why the management listener has none by default: its one peer is the pinned server sending a whole fan-out over one connection, and when the agents answered together with large responses the ceiling (then 16 MiB, equal to Cowboy's own 16 MB output-buffer alarm) killed that connection, and every call on it, before Cowboy's backpressure could act. Without it, Cowboy's buffer alarm paces the senders and the connection holds about 16 MB plus one response per stream in flight; set `max_connection_memory_bytes` on the management listener to keep a hard cap anyway. A combined agent-and-management listener serves anonymous agents and keeps the ceiling. `request_timeout_ms` is how long a unary or server-streaming stream may buffer its one request before it is aborted `DEADLINE_EXCEEDED` (counted in `yuzu_gw_grpc_recv_timeout_total`) and its buffer dropped; it never cuts a bidirectional or client-streaming handler (an agent's long-lived `Subscribe`), which runs before any message, and a `grpc-timeout` the client sent runs alongside it with the earlier of the two winning. The gateway ends a call that carries a `grpc-timeout` with `DEADLINE_EXCEEDED` a tenth of that timeout early, at most 1 s early (299 s for the server's 300 s calls), so the client receives the status before its own deadline instead of resetting the stream: when thousands of the server's calls expire together, their resets exceed Cowboy's `max_cancel_stream_rate` (500 per 10 s) and Cowboy closes the whole management connection. Tested with a gun client; that the server's gRPC C++ client then sends no reset is standard gRPC behaviour but was not observed against the server. Together these two bound an unauthenticated peer that opens streams and stalls them half-sent (see "Connection ceilings and the unauthenticated ports" below). `max_connections` bounds the file descriptors a listener's connections can take. It is **not protection against a hostile peer**: see that same section for what it does and does not do on each listener. `sys.config.prod`, the reference configs and the packaged release config (`gateway/config/sys.config`, the one the release packages and the systemd unit run) set `max_connections => 60000` on the agent listener (the systemd unit's `LimitNOFILE` of 65536 less about 5500 of headroom for the upstream channel, the health and metrics ports, the management listener, Erlang distribution and files, so it holds to a fleet of about 30000 agents; raise it together with `LimitNOFILE` and keep about 5500 below it, lower it if the limit is lower) and `max_connections => 256` on the management listener. Both set `max_message_bytes => 4194304` explicitly, which is the default and gRPC's default receive limit: it is not lowered on the agent listener because an agent's installed-software inventory blob may be 3 MiB by design. The agent listener also sets `max_connection_memory_bytes => 33554432` and `request_timeout_ms => 30000` explicitly (both the defaults). The demo and UAT configs set no `limits`, so `max_connections` is `infinity` there, but the memory ceiling and request deadline still apply at their defaults. Size the file-descriptor limit for the listener's `max_connections` plus the other sockets (about 1.5 to 2 times the agent count plus 200 in use). |

**Connection ceilings and the unauthenticated ports (known residual risk).**
`limits.max_connections` bounds file descriptors. It does not protect either port from a
peer that wants to hold connections, and this is what it does on each listener:

- *Before it existed* both listeners had no ceiling (`infinity`), so a flood of connections
  exhausted the gateway process's file-descriptor limit and took down everything in the
  process: the upstream channel, the health and metrics ports and Erlang distribution as
  well as the listeners. A ceiling keeps the process alive. It does not keep the port
  serving.
- *Agent listener (`:50051`), 60000.* The port is unauthenticated by design: an agent that
  has not enrolled has no certificate. A connection that has not finished the PROXY header
  (about 1 s) or the TLS handshake (10 s) is closed on those timers, and one that then sends
  nothing is closed by the listener's `idle_timeout`. A connection that keeps sending is
  **not**: any received data, a `PING` included, resets Cowboy's idle counter
  (`cowboy_http2.erl` in Cowboy 2.19.0, read from the source, not measured), so a peer that
  has completed the handshake can hold the connection open for as long as it likes. A peer that holds
  60000 of them fills the ceiling; new connections then wait in the kernel's listen
  backlog while the agents already connected are unaffected until they reconnect, and
  a gateway restart frees the slots only until the peer reconnects. This predates the
  ceiling, which only changed what the same flood exhausts, and it is an accepted residual
  risk of the unauthenticated agent port with follow-up work, not a fixed defect. Mitigate
  it by limiting connections per source address at the L4 balancer or firewall. Behind a
  proxy the gateway sees only the proxy's address, so the limit has to be on the proxy.
  What the ceiling does **not** bound — the *memory* a held connection can consume — is
  bounded separately: `limits.max_connection_memory_bytes` kills a connection that buffers
  more than its ceiling of half-finished requests, `limits.request_timeout_ms` aborts a
  single stalled request, and node-wide memory shedding (below) suspends the whole listener
  before the node runs out. A held but quiet connection still occupies a slot; those three
  stop a held connection from being turned into a memory-exhaustion attack.
- *Management listener (`:50063`), 256.* The only peers that need it are the server's
  replicas, one connection each. Who can hold the other slots depends on how far the
  connection gets. **Before the TLS handshake**, anyone with layer-4 reach to the port can
  hold a slot, for up to the 10 s handshake timeout. **After the handshake**, any holder of
  a certificate issued by the install CA can hold it for as long as `PING`s keep the
  connection busy; every enrolled agent has such a certificate, and the SPKI pin
  (`mgmt_peer_pins`) is checked later, per stream (against the key the pin watcher last
  published, with no file I/O on the connection), so it does not turn the connection
  away. About 256 held connections stop the server making **new** connections to the
  gateway; connections already established are unaffected. This is a **known, accepted
  limitation that will not be fixed in the gateway** (owner decision, 2026-10-10): you must
  firewall the management port so that only the server replicas can reach it, and the
  preferred deployment multi-homes the server so that its management- and gateway-facing
  interface is on a different network interface from the agent- and database-facing
  ones. The shipped composes do not publish `:50063`. The practical lever is `listen.ip`:
  set the management listener's `ip` to the address of the management interface (for
  example `listen => #{port => 50063, ip => {10,0,5,12}}`), so the port is not bound on
  the agent-facing interface at all. The shipped configs bind `{0,0,0,0}`, so this is a
  change you make. The gateway cannot check that the firewall rule exists or that the
  interfaces are separate, and a host that the firewall allows can still hold slots.
  *Detection* (there is no gateway metric at the ceiling): on the gateway host,
  `ss -Htn state established '( sport = :50063 )' | wc -l` against the number of server
  replicas (each holds one), `ss -Htn state syn-recv '( sport = :50063 )' | wc -l`, and the
  Recv-Q of `ss -ltn '( sport = :50063 )'` (connections the kernel accepted that the
  listener has not); on the server, `yuzu_server_gateway_forward_total{status="unavailable"}`
  rising, which counts commands to gateway-connected agents dropped after three
  attempts, whatever the cause, so it says the forward path is failing, not why. An alert on `increase(yuzu_server_gateway_forward_total{status="unavailable"}[5m]) > 0`
  is recommended; none ships. *Recovery*: find the source address in the `ss` output and
  block it at the firewall. A process restart does not clear it (the peer reconnects), and
  the server's established connection is unaffected throughout.

**Node-wide memory load shedding.** The per-connection bounds above cap one
connection; a large enough fleet of well-behaved connections, or a flood that each
stay just under their own ceiling, can still drive the node's total memory up. The
memory shedder (`yuzu_gw_memory_shedder`) is the backstop: it samples
`erlang:memory(total)` every `interval_ms` and, above a **high-water mark**, calls
`ranch:suspend_listener/1` on the **agent** listener(s), and below a **low-water mark**
it resumes them. The two marks give hysteresis so a node hovering at the line does not
flap. The **management listener is never suspended**: the operator and command plane
stays reachable so you can drain the fleet and act on the pressure.

*What a new agent connection sees while shedding.* Suspending a listener closes its
listen socket, so a new connection to the agent port is **refused** at once
(`ECONNREFUSED`); connections the kernel had queued but the gateway had not yet
accepted are reset. Every connection already established is untouched and keeps
working. This is deliberate, rather than leaving new connections waiting in the kernel's
listen backlog: a refused agent goes straight into its reconnect backoff (2, 4, 8 ...
seconds, at most 256 s) and a load balancer retries a refused connect on another node,
while a connection parked in the backlog completes the TCP handshake, makes the agent
wait for a TLS handshake nobody answers until gRPC gives up (about 18 s, measured
against a server that accepts TCP and never answers), is not
retried elsewhere by the balancer, holds kernel socket memory that counts against a
container's memory limit, and is accepted in one burst with all the others when the
shedder resumes. Agents reconnect without jitter today (#5990), so a refused fleet
retries in step; the backoff still spreads it over minutes. While shedding, `/readyz`
reports not-ready (the agent listener reads as not running, `"listeners":false`), so a
load balancer drains this node automatically.

*When a suspend or resume fails.* Resuming opens the listen socket again, which can fail:
`eaddrinuse` if another process took the port while it was closed, `emfile`/`enfile` if
the gateway is out of file descriptors. The shedder then leaves that listener as it is
and tries again on every tick. It logs the first failure (`could not resume agent
listener(s) ... retrying every N ms`), then at most once a minute while it lasts, and
the success; it counts each failed attempt in
`yuzu_gw_memory_shedding_transition_failures_total{action}` and shows the listeners still
not moved in `yuzu_gw_memory_shedding_transition_failing{action}`. `/readyz` stays 503
until the listener is actually running again. The alert
`YuzuGatewayMemorySheddingTransitionFailing` fires only when a failure has lasted 5
minutes, and says what to do. The same applies the other way round to a suspend that
fails (the listener keeps accepting and the shedder keeps trying). If the shedder process
itself restarts while it has a listener suspended, the new process finds the listener
suspended, treats it as shed and resumes it once memory is at or below the low-water mark.

Configure it under `{yuzu_gw, [{memory_shedding, #{...}}]}`:

| Key | Meaning | Default |
|---|---|---|
| `high_water_fraction` / `high_water_bytes` | The mark above which the agent listener(s) are suspended, as a fraction of the memory limit (below) or absolute bytes (bytes win if both are set). | `0.75` of the memory limit |
| `low_water_fraction` / `low_water_bytes` | The mark below which they resume. Must be below the high-water mark. | `0.65` of the memory limit |
| `interval_ms` | How often `erlang:memory(total)` is sampled, and how often a failed suspend or resume is retried. | `1000` |
| `enabled` | `false` turns the shedder off. | `true` |

*The memory limit* a fraction applies to is the smaller of the host's memory and the
cgroup memory limit the gateway runs under, read once at start without adding `os_mon`:

- host memory: `MemTotal` in `/proc/meminfo` on Linux, the `hw.memsize` sysctl on macOS;
- cgroup v2: `memory.max` (`max` means no limit); cgroup v1:
  `memory/memory.limit_in_bytes` (a value of 2^62 or more means no limit). Both are read
  in the gateway's own cgroup (from `/proc/self/cgroup`) and in each parent up to the root
  of `/sys/fs/cgroup`, and the smallest limit wins, so a container's memory limit
  (`docker run --memory`, a Kubernetes `resources.limits.memory`) and a systemd
  `MemoryMax=` on the unit or its slice are all seen.

Before this, the fraction was of the host's memory only, so a gateway in a container with
a memory limit below the host's memory never shed before the kernel's OOM killer stopped
it. The gauges `yuzu_gw_memory_shedding_high_water_bytes` and
`yuzu_gw_memory_shedding_low_water_bytes` show the marks the shedder resolved, and its
start-up log line names the limit and where it came from (`cgroup_v2`, `cgroup_v1` or
`host`): check them against the container's limit after a deployment. A cgroup file that
exists but cannot be read or parsed is logged as a warning and skipped; the shedder then
uses the host's memory, which may be too high, so set `high_water_bytes` and
`low_water_bytes` below the limit in that case. A configured `high_water_bytes` at or
above the cgroup limit is also logged, since it can never trip first. `memory.high` (a
throttling threshold, not a kill) is not read. A limit changed while the gateway runs
(`docker update --memory`) takes effect at the next restart.

*What is sampled* stays `erlang:memory(total)`, the memory the VM has allocated, not the
cgroup's `memory.current`. It is what the agent connections cost and what shedding them
relieves, it needs no file read per sample, and it does not move with the page cache
(`memory.current` counts file cache that the kernel reclaims before it kills anything, so
log writes alone could trip the shedder). The cost is that it leaves out what the cgroup
also counts: allocator overhead (memory the VM holds from the OS but has not handed out),
memory outside the VM's allocators and kernel socket buffers. The default high-water mark
of 0.75 of the limit leaves that quarter for them. Compare
`yuzu_gw_beam_memory_bytes{type="total"}` with the container's working set (cAdvisor's
`container_memory_working_set_bytes`) under load; if the gap is more than about a quarter
of the limit, lower the fractions.

Where no limit can be read at all (no cgroup, no `/proc/meminfo`, not macOS) and no
absolute bytes are configured, the shedder runs **inactive** and logs it, rather than
failing boot: it is a backstop, and the per-connection and per-stream bounds still hold.
The config shape is validated at boot; a malformed `memory_shedding` map refuses to start.

Metrics: `yuzu_gw_memory_shedding_active` is a gauge, `1` while the gateway is shedding
(memory passed the high-water mark and has not yet fallen to the low-water mark) and `0`
otherwise; `yuzu_gw_memory_shedding_suspensions_total` counts each time shedding began.
The failure metrics and mark gauges are described above. The shipped alert
`YuzuGatewayMemorySheddingActive` fires while the gauge is `1` for 3 minutes
(`docs/prometheus/yuzu-alerts.yml`). **Tuning:** if the node sheds under normal load, the
node is undersized for the fleet (lower the fleet per node or raise the memory); if it
never sheds under a flood that is hurting it, lower the high-water mark. Leave at least a
few points between the two marks so it does not flap. The kill and receive-timeout
counters above (`yuzu_gw_grpc_connection_killed_total`,
`yuzu_gw_grpc_recv_timeout_total`) tell you whether the pressure is a flood of
half-finished requests rather than genuine fleet growth.

A leftover `{grpcbox, [{servers, ...}]}` block **refuses boot**: nothing reads it, so
it would configure no listener while the file reads as if it did. The same goes for a
leftover `{grpcbox, [{client, ...}]}` block (the upstream channel to the C++ server, now
`{yuzu_gw, [{upstream_client, ...}]}`; see [The upstream client](#the-upstream-client)).
The gateway contains no `grpcbox` application, so no `{grpcbox, ...}` block of any kind
belongs in a `sys.config` any more. Both refusals are checked before any listener is
bound.

**Moving an old config.** The key mapping from the grpcbox shape, one listener at a time
(a worked before and after, the refusal text and the roll-out order are in
[Upgrading the Gateway](upgrading.md#gateway-listeners-move-to-grpc_listeners-the-cowboy-edge--breaking)):

| Old key (inside `{grpcbox, [{servers, [...]}]}`) | New key (inside `{yuzu_gw, [{grpc_listeners, [...]}]}`) |
|---|---|
| `grpc_opts => #{service_protos, services, auth_fun}` | Dissolved: `service_protos`, `services` and `auth_fun` are keys of the listener entry itself. |
| `listen_opts => #{port, ip}` | `listen => #{port, ip}` |
| `transport_opts => #{ssl => true, certfile, keyfile, cacertfile, verify, fail_if_no_peer_cert}` | `tls => #{certfile, keyfile, cacertfile, verify, fail_if_no_peer_cert}`. `ssl => true` is gone: the presence of the `tls` map turns TLS on. A legacy `transport_opts` key refuses boot. |
| `pool_opts => #{size => N}` | `acceptors => N` |
| (none) | `name`: mandatory and unique. |
| (none) | `origin`, `http2`, `limits`: new, all optional. |
| `{yuzu_gw, [{agent_listen_addr, ...}, {agent_listen_port, ...}, {mgmt_listen_addr, ...}, {mgmt_listen_port, ...}]}` | Dead. No code reads them, and a config can keep them harmlessly; the bind address and port are `listen`. |

The block `grpc_listeners` belongs in is the `yuzu_gw` application block, not `grpcbox`:
a `grpc_listeners` key placed under `grpcbox` is ignored, and the gateway then refuses
to boot for lack of listeners.

**Environment overrides for the listeners.** `YUZU_GW_AGENT_PORT` rewrites
`listen.port` of the entry whose `service_protos` contains `agent_pb`, and
`YUZU_GW_MGMT_PORT` that of the entry serving `management_pb` (applied at start by
`yuzu_gw_app:apply_listener_port_overrides/0`). An override applies only when
**exactly one** entry serves the proto: with none, or with several (two agent listeners,
one for an F5 path and one for a router path, say), the variable is logged as a warning
that names it and is ignored, because one port cannot be applied to several listeners
without creating a duplicate. A value that is not an integer from 0 to 65535 is logged
and ignored. On a single combined agent-and-management listener only `YUZU_GW_AGENT_PORT`
can apply. The `agent_listen_port` / `mgmt_listen_port` keys that older configs still
carry are dead and are left alone. **Check `YUZU_GW_MGMT_PORT` before you upgrade:** the server's
Settings page lists it with the default 50052, but the management listener is on 50063 and the
variable is now live, so a gateway whose environment carries `YUZU_GW_MGMT_PORT=50052` moves its
management listener to 50052 on first start (and the server's command connections then fail).
Leave the variable unset, or set it to the port in `listen`. The `YUZU_GW_TLS_*` variables still do not drive the
listeners' certificates (#1291): certificate paths are in the `tls` map.

**Readiness.** `/healthz` answers 200 whenever the health endpoint itself responds; it checks
no other process. The endpoint serves each connection in its own process and waits at most
2 s for the request, so a client that connects and sends nothing does not hold up the probes
behind it; at most 64 connections are served at once, and past that new ones wait in the
listen backlog until one finishes. `/readyz` answers 200 only when every check in its body passes, and 503
`not_ready` otherwise: the registry, upstream, agent supervisor and router processes are alive
(`registry`, `upstream`, `agent_sup`, `router`); the registry's session index table exists
(`sessions_index`); no upstream channel's latest connection attempt failed on unusable TLS
files (`upstream_tls_files`); the upstream circuit breaker is not open (`circuit_breaker`, read
from the state the upstream process publishes rather than by a call into it, so it answers at
once while that process is inside a slow RPC); and
every configured listener is running (its Ranch listener `{yuzu_grpc, Name}` reports `running`,
shown as `listeners`) with at least one of them routing the AgentService (the same rule as boot: the entry's `services` map has the key `'yuzu.agent.v1.AgentService'`); an empty list, or a list with no entry that routes it, is ready only with `allow_no_listeners` set to `true`. The `listeners` check asks
Ranch and does not connect to the ports, and the `upstream` check tests only that the process is
alive, so a 200 does not show that a running listener accepts connections or that the server is
reachable. A listener whose Ranch status is not `running` turns `/readyz` red (503)
instead of leaving a "ready" gateway that accepts nothing.

**`cluster_id`** (the `cluster_id` key above, or the `YUZU_GW_CLUSTER_ID` environment
variable, which replaces it when set): the name is stamped on every notification as
UTF-8, and the two sources are read by different rules (INFERRED from the code and unit
tests; the `sys.config` forms were also checked with `file:consult` and `erl -config`
under a C locale and a UTF-8 locale, with identical results; none of it was run on a rig):

- **Environment variable.** The VM hands the text over in its native name encoding:
  latin1 in the shipped images (no `LANG`, `LC_ALL` or `+fnu`), UTF-8 under a UTF-8
  locale. The gateway recovers the original bytes and requires them to be valid UTF-8,
  so a name typed in a shell gives the same bytes on both. Bytes that are not UTF-8, a
  surrogate or a code point above 16#10FFFF are refused. Limit: on a UTF-8 native node
  a byte sequence that is not valid UTF-8 is read as latin1 characters, which cannot be
  told from valid text, so only a latin1 node (the shipped images) can refuse it.
- **`sys.config`.** Independent of the node's locale. A binary must already be valid
  UTF-8; a string is read as Unicode code points. The working forms for a name with a
  non-ASCII character are the string `"Z\x{FC}rich"` (or the name typed as UTF-8 text
  inside the quotes) and the binary `<<"Z\x{FC}rich"/utf8>>`. A plain binary
  `<<"Z\x{FC}rich">>` is the single byte 16#FC, which is not valid UTF-8, and is
  refused at boot. A plain `<<"...">>` binary that holds code points above 255 is
  truncated to bytes when the file is read, and is accepted only if the surviving
  bytes happen to be valid UTF-8 (`<<"\x{140}\x{141}">>` reads as the two bytes of
  `@A`, a different name from the one written), so always use the `/utf8` form.
  (INFERRED, and checked with `file:consult` on OTP 28.4.2 for these forms.)
- **Refusal.** A name that cannot be represented makes the gateway refuse to start:
  `yuzu_gw_app:start/2` returns `{error, {invalid_cluster_id, env}}` (the variable) or
  `{error, {invalid_cluster_id, app_env}}` (the `cluster_id` setting) and logs a
  critical line that names the source and never prints the value (the runbook row has
  the line). Most refusals come from `sys.config`; the variable is refused only for
  bytes that are not UTF-8 on a latin1 node. When the variable is set it replaces the
  setting, so only it is checked. The environment override also logs
  `ENV override: YUZU_GW_CLUSTER_ID cannot be represented as UTF-8; ignoring it (the
  value is not logged)`: it never echoes the value.

It refuses rather than warns and falls back because the cluster id pins agents to a
trust zone, so starting under a different id is wrong, and starting with an id that
makes every notification fail to encode would silently lose all stream status. An
empty name is still accepted, and the default is `default`. What a cluster id means
for routing is in [ADR-2002](../adr/2002-high-availability-architecture.md) section 7.

**Upstream client tuning** (proxied calls, registration replay and pending notifications; application env keys read by the upstream
client at start, except `upstream_call_timeout_ms` and `upstream_rpc_timeout_ms`, which are read on every call; set them in the `yuzu_gw` section of `sys.config`. No
`YUZU_GW_*` environment variable maps to any of them):

| Key | Default | Valid range | Meaning |
|---|---|---|---|
| `registration_replay_start_jitter_ms` | 1000 | 0 to 60000 | A full replay (when a heartbeat verdict shows the server lost its state, see "What starts a full replay") starts after a random delay of 0 to this many ms, so gateways that saw the same server come back do not all start at once. `registration_replay_spacing_ms`, which paced the old one-at-a-time drip, is no longer read (#5695) |
| `upstream_register_concurrency` | 48 | 1 to 1024 | Permits for `ProxyRegister` calls in flight at once (live registrations and replays together). See "Upstream call permits" |
| `upstream_replay_concurrency` | half of the above (24) | 1 to `upstream_register_concurrency` | Most of those permits a registration replay may hold, so live registrations always have the rest |
| `upstream_inventory_concurrency` | 8 | 1 to 1024 | Permits for `ProxyInventory` calls in flight at once |
| `upstream_register_queue_max` | 10000 | 0 to 1000000 | Most `Register` requests that wait for a permit; one more is refused `UNAVAILABLE` at once |
| `upstream_inventory_queue_max` | 1000 | 0 to 1000000 | The same for inventory reports |
| `upstream_rpc_timeout_ms` | 5000 | 100 to 60000 | The longest one proxied call or replay may take; a caller with less time left gets what it has left |
| `registration_replay_session_guard_ms` | 10000 | 0 to 3600000 | A session that was just replayed is not queued again by a heartbeat verdict until this many ms have passed. The stamp is taken when the replay is sent, so a stale verdict can arrive up to the 5 s flush deadline (the upstream client's default per-call timeout, 5000 ms in `yuzu_grpc_client`) plus the replay RPC time later (INFERRED from the code): do not set it below 5000 plus the expected replay RPC time, because a smaller guard lets such a stale verdict replay a session the server already knows; the default 10000 is safe (see "Replaying a session the server already knows is not free" under [What happens when the server restarts](#what-happens-when-the-server-restarts)) |
| `registration_replay_queue_max` | 10000 | 1 to 1000000 | Most agents the replay queue holds when a heartbeat verdict appends to it; there is one pending entry per agent, and an id past the cap is counted in `yuzu_gw_heartbeat_verdict_dropped_total{reason="queue_full"}` (so is an id in a verdict that the heartbeat buffer did not cast because the upstream client's mailbox held more than 100 messages, see "Heartbeat batching interval" below). The cap bounds only verdict appends: a full replay walks the registry in chunks of 500 and is not capped (it is bounded by the number of agents the node holds) |
| `notify_pending_max` | three per agent-listener connection (sum of `limits.max_connections`), at least 15000 | 1 to 1000000 | Most stream-status notification keys (agent id, session id and stream home id) the upstream client holds while they cannot be sent, counting the sends in flight. The cap counts keys, not agents. When full, a `DISCONNECTED` evicts the oldest held `CONNECTED`; anything else past the cap is refused and counted. The derivation, the drop policy and the memory per key are under "Stream Status Notification" above. `sys.config.prod` and the reference compose config ship 180000 for their 60,000 connections; change it with `max_connections`. Read once at start and logged in the start line of the upstream client |
| `notify_probe_timeout_ms` | 15000 | 100 to 300000 | The gateway's own deadline for the half-open notification probe. A probe worker that has not reported after this many ms is killed, and the probe fails like any failed probe: its notification goes back to the head of the held queue, the breaker opens again with the doubled backoff, and the next half-open cycle sends a new probe. One WARN `Notify probe worker for <agent> did not answer within <ms>ms and was killed; the notification is held again` is logged per timeout. It bounds the notification probe only, not the call-path RPCs (`ProxyRegister`, `ProxyInventory`, replay), and it does not depend on the upstream client's connect and call bounds. Tuning: 15000 sits above the upstream client's default bounds (a 5000 ms connect and a 5000 ms call), so a healthy upstream answers in milliseconds and a silent one is cut off after one deadline. A `did not answer` WARN that repeats while the server is healthy points at RAISING the value, not lowering it. A value below about 5000 kills probes that would have answered. A killed probe is requeued, so delivery stays at least once. Read once at start (a change needs a gateway restart). Not present in any shipped `sys.config`. A value outside the range, or one that is not an integer, falls back to the default with a WARN that names the key |
| `notify_unacked_retry_base_ms` | 1000 | 10 to 60000 | The first backoff before a notification the server refused (`acknowledged=false`) is sent again; each later delay is a random value between this and three times the previous delay. See "When the server does not record a notification". Read once at start |
| `notify_unacked_retry_max_ms` | 60000 | 100 to 3600000 (raised to the base when below it) | The longest backoff between resends of a refused notification: once the server accepts again, every refused notification is sent within about this long. Read once at start |
| `notify_unacked_disconnected_window_ms` | 120000 | 0 to 3600000 | How long after its first refusal a refused `DISCONNECTED` is still sent again (0: never), then counted lost (`reason="unacknowledged"`). The default is past the server's 90 s route lease, after which the row the `DISCONNECTED` would remove is no longer routable. A refused `CONNECTED` has no window. Read once at start |
| `upstream_call_timeout_ms` | 30000 | 100 to 300000 | The budget of a proxied `Register` or inventory report whose agent sent no `grpc-timeout`, from the call's arrival: the wait for a permit and the call itself must fit in it. Read on every call. A value outside the range, or one that is not an integer, falls back to the default with a WARN that names the key |
| `shutdown_flush_budget_ms` | 20000 | 0 to 600000 | How long a planned stop may spend ending the agent sessions and sending their `DISCONNECTED` notices before the processes stop. See "Planned stop". The container's or unit's stop timeout must be larger (40 s is shipped) |
| `agent_restart_intensity` | 2000 | 1 to 1000000 | How many agent owner processes may be restarted within `agent_restart_period_s` before the agent supervisor itself stops and is restarted (shared by all owners). See "When an agent's owner process crashes". Read when the agent supervisor starts |
| `agent_restart_period_s` | 10 | 1 to 3600 | The window of `agent_restart_intensity`, in seconds |

An invalid value for any of these keys falls back to the default and logs a
warning that names the key. See
[What happens when the server restarts](#what-happens-when-the-server-restarts).

**Upstream call permits** (#5695). `ProxyRegister` and `ProxyInventory` run in the
process of the agent's own request, under a permit from
`yuzu_gw_upstream_regulator`, not inside one upstream process. The pools:

| Class | Permits | Wait queue | Notes |
|---|---|---|---|
| `register` | 48 (`upstream_register_concurrency`) | 10000 | live `Register`, served before replays |
| `replay` | at most 24 of the register pool | not counted | registration replays; live registrations always keep the other 24 |
| `inventory` | 8 (`upstream_inventory_concurrency`) | 1000 | `ProxyInventory`; large payloads, not on the connect path |

These are the configured sizes. The permits in force can be lower when the server
allows fewer streams: see "How the gateway sizes its upstream calls" below.

Why these numbers. The register pool, by Little's law: a restarted gateway can
see its whole fleet register at once; 5,000 agents inside the agent's 30 s `Register`
deadline (25 s with margin) is 200 per second, and at 50 to 200 ms per server call
that is 10 to 40 calls in flight, so 48 serves the storm with margin even at 200 ms
(240 per second, 5,000 in about 21 s). Measured with a mocked server at 50 ms per
call: a burst of 600 `Register` calls was served with 0 refused and 48 in flight at
most, in 0.67 s; the previous serial path refused 503 of the 600 within a 5 s budget.

A request that finds every permit of its pool taken waits in the queue, each with
its own deadline (the agent's `grpc-timeout` less the stream handler's margin, or
`upstream_call_timeout_ms` when it sent none). It is refused `UNAVAILABLE` when the
queue is full (`yuzu_gw_upstream_permit_refused_total{reason="queue_full"}`) or when
its deadline passes first (`reason="deadline"`, and the request is not sent:
`yuzu_gw_upstream_calls_dropped_total`); the agent retries. A request whose process
is stopped (a reset stream, a closed connection) frees its permit or its place by
its exit. The wait is in `yuzu_gw_upstream_permit_wait_seconds`; held and waiting
permits are `yuzu_gw_upstream_permits_held` and `yuzu_gw_upstream_permits_waiting`
by class.

**How the gateway sizes its upstream calls.** Every upstream call is one HTTP/2
stream on a connection of the upstream channel. The server says how many streams it
accepts at once on a connection (`SETTINGS_MAX_CONCURRENT_STREAMS`, sent when the
connection starts and possibly changed later, RFC 9113 sections 6.5 and 6.5.2), and
the gateway must not open more (section 5.1.2): its HTTP/2 client refuses a call past
the limit itself (`too_many_streams`). For the C++ server the value is its
`--grpc-max-concurrent-streams` (128 by default), because the gateway-upstream
service shares the gRPC builder of the agent service.

The gateway reads the value from the server instead of assuming it. The channel
records what each of its connections declared, adds them up (one connection by
default, `pool_size`), and updates the total whenever the server sends new settings
or a connection goes down. The total is `yuzu_gw_upstream_server_max_streams` (0 when
nothing is known, or when the server declared no limit). From it the gateway works
out the permits in force (`yuzu_gw_upstream_permit_limit`):

- First it sets aside 61 streams for the lanes that take no permit: up to 10
  stream-status notifications, up to 50 Guardian forwards, and one heartbeat flush.
- If what is left covers the configured `register` and `inventory` pools together,
  they apply unchanged. At the C++ default of 128 and `pool_size` 1, 67 streams are
  left for 48 + 8, so nothing changes.
- Otherwise what is left is split between the two pools in proportion to their
  configured sizes: `register` gets (left x 48 / 56) rounded down and `inventory`
  the rest. Neither gets less than one permit or more than its configured size.
  The replay cap shrinks with `register` (half of it, by default). For example, a
  server that allows 100 streams gives `register` 33, `replay` 16 and `inventory` 6.
- A server that allows fewer streams than the 61 the other lanes need leaves one
  permit each, and the gateway logs a WARN (`The server allows <N> concurrent
  streams on the gateway's connections; ...`). The other lanes can then hit the
  server's limit too, and a failed stream-status notification counts against the
  circuit breaker as before. Raise the server's `--grpc-max-concurrent-streams`, or
  the channel's `pool_size`.
- Each change is logged (`Upstream permits in force: ...` or `Upstream permits
  lowered to the server's stream limit: ...`).

A lower limit takes nothing away: calls already holding a permit finish, and no new
permit is granted until fewer are held than the new limit. If the server lowers its
limit just as a call is granted, and the call is then refused with
`too_many_streams`, the call is not counted against the circuit breaker: nothing was
sent. The call hands its permit back, waits 10 ms (doubling up to 100 ms), and asks
for a permit again, so it waits in the queue like any other call until its deadline
(then the agent is told `UNAVAILABLE` and retries). Registration replays do the
same. Each refusal is counted in `yuzu_gw_upstream_rpc_errors_total` under
`code="too_many_streams"`.

There is nothing to configure for this. To give the gateway more upstream capacity,
raise the server's stream limit or the channel's `pool_size`; raising
`upstream_register_concurrency` above what the server allows has no effect.

**Upstream channel tuning** (read when the upstream channel configuration is parsed,
at start-up; set it in the `yuzu_gw` section of `sys.config`. No `YUZU_GW_*`
environment variable maps to it, so a compose deployment cannot switch it off
through the environment; it takes a `sys.config` edit):

| Key | Default | Valid values | Meaning |
|---|---|---|---|
| `upstream_tcp_nodelay` | `true` | `true` or `false` | Sets TCP_NODELAY on the gateway-to-server (upstream) gRPC channel. Without it, every upstream call with a request under about 64 KiB waited about 41 to 43 ms for Nagle's algorithm and the server's delayed ACK, which capped registration at about 24 agents per gateway per second (see "Registration rate per gateway"). Each upstream connection is opened with `{nodelay, true}` among its TCP socket options, for `http` and `https` endpoints alike (the options go to the TCP socket that TLS is then started on). An endpoint whose own `socket_options` (the optional fifth element of the endpoint tuple, see [The upstream client](#the-upstream-client)) already hold a `nodelay` entry keeps it, in either direction: a hand-set `{nodelay, false}` keeps Nagle on that endpoint. Other `socket_options` are kept. Existing `sys.config` files need no edit. It applies only to the upstream channel, not to the agent listener or the management channel. A value that is not a boolean logs a warning that names the key and uses the default `true` (the warning can appear more than once, because the configuration is parsed more than once at start). `false` leaves the endpoints as configured and logs nothing. Since 2026-10-11 nothing restarts the channel and the gateway logs no line about nodelay (an earlier release restarted grpcbox's `default_channel` at start and logged `Upstream channel default_channel: TCP_NODELAY on`; the `could not restart it with TCP_NODELAY` warning no longer exists). The option placement was checked in `yuzu_grpc_client_channel:gun_opts/2` and the default in `yuzu_grpc_client_config`; the effect on a live stack was one measurement, see the update under "Registration rate per gateway". |

**gRPC handler failure log** (read on every failure; set it in the `yuzu_gw` section of
`sys.config`. No `YUZU_GW_*` environment variable maps to it):

| Key | Default | Valid values | Meaning |
|---|---|---|---|
| `grpc_runner_warn_interval_ms` | 1000 | `0` to 3600000 | The shortest gap between two `gateway grpc handler <Method> failed` WARN lines on this node. `0` logs every failure. A value that is not a non-negative integer is read as 1000 **without a warning**, and a larger integer is read as 3600000 (an hour), so a typo cannot silence the log. A line that follows suppressed ones ends `(N similar failures not logged since the last line)`. |

**Management-pin refresh** (#5696; read once when the pin watcher starts; set it in the
`yuzu_gw` section of `sys.config`. No `YUZU_GW_*` environment variable maps to it):

| Key | Default | Valid values | Meaning |
|---|---|---|---|
| `mgmt_pin_refresh_ms` | 5000 | 100 to 3600000 | How often the `yuzu_gw_mgmt_pins` process re-reads every `{cert_file, Path}` entry of `mgmt_peer_pins`. It parses the PEM again only when the file's bytes changed (it compares a SHA-256 of the contents, not the modification time or size, so a new key of the same size copied with `cp -p` is still picked up), and publishes the pinned key for the management `auth_fun` to read. The `auth_fun` runs once per management stream and does no file I/O itself, so a stalled certificate volume stalls only the watcher, never a connection. The interval bounds how long a rotated server leaf is refused: until the next refresh the gateway still pins the old key, so a stream the server opens with its new leaf in that window gets `UNAUTHENTICATED` (`pin_mismatch`, fail closed). The server does not retry it: the commands it forwards in that window fail as `gateway_unauthenticated`, and commands after the refresh go through. The same tick refreshes the certificate expiry gauges (see [Certificate rotation and expiry](#certificate-rotation-and-expiry)). The pins are resolved once at start, before the listeners, so the first stream never waits for a refresh. A value outside the range, or one that is not an integer, **refuses boot** (`Refusing to start: invalid {yuzu_gw, mgmt_pin_refresh_ms}`). Not present in any shipped `sys.config`. |

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
| `max_sessions_per_connection` | 8 | 1 to 1000 | Most session slots one gRPC connection may hold. Each unexpired reservation row (a `Register` that was admitted and is not yet answered by the server, see below) is one slot, including the registering agent's own in-flight reservations. Another agent's live row counts one; another agent's committed pending row (registered and not yet subscribed) counts one only if that agent has no reservation in flight. The registering agent's own live row and committed pending row never count, because a commit supersedes them, and the `Subscribe` path leaves out all of that agent's own rows. A `Register` is admitted while fewer than the cap of those slots are held, so a connection holds at most the cap of counted slots plus the registering agent's own live row and committed pending row; the stored rows can briefly exceed that by the committed pending row of an agent that has a retry in flight, which its commit removes. A slot is reserved inside the registry process, which handles one call at a time, when a `Register` is admitted and before it is proxied to the server, so N concurrent `Register` calls on one connection, whether they carry one agent id or several, admit at most the cap and nothing beyond it is proxied (a retry made while an earlier `Register` of the same id is in flight uses one more slot until that one is released or committed). The reservation row is turned into the pending row by a commit step once the server accepted the registration; it is released if the proxied `Register` fails or is not accepted, and a handler that is killed while its `Register` is proxied (the client reset the stream, the call's deadline passed, the connection closed) has its reservation released promptly by a guard process that watches the handler. The pending time to live (120 s, swept every 60 s) is the backstop for a kill in the short windows before the guard exists and between the release and the commit. Over the cap, a `Register` is answered `UNAVAILABLE` (14) and a `Subscribe` is refused with `UNAVAILABLE` (14); both are counted in `yuzu_gw_session_limit_rejected_total` and logged as a warning at most once per second that names only the cap. A value outside the range falls back to the default and logs one warning that names the key. |
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
those agents would be answered `UNAVAILABLE` (so would a refused `Subscribe`).
Putting several agents on one backend connection is not a supported topology (see
"Supported topologies"); raising the key does not make it one, because the agent
listener's 32 concurrent streams per connection also apply, and heartbeat admission can
no longer tell the agents apart.

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

**What counts as a failure.** The breaker counts calls that failed because of the
server or the path to it: no connection, a timeout, and every gRPC status except the
five that say the request itself was wrong. `INVALID_ARGUMENT`, `NOT_FOUND`,
`ALREADY_EXISTS`, `FAILED_PRECONDITION` and `OUT_OF_RANGE` are the server answering
correctly, so they leave the breaker as it is: not a failure, and not a success either
(they do not reset the run of consecutive failures or close a half-open breaker).
`PERMISSION_DENIED`, `UNAUTHENTICATED` and `RESOURCE_EXHAUSTED` are counted;
`RESOURCE_EXHAUSTED` because it is the only brake the gateway has until the server sends
explicit backpressure.

**Circuit breaker tuning** (the breaker the replay and the other upstream calls
share; read once when the upstream client starts, and each key has an environment
override, unlike the replay keys above. All three are range-checked: the failure
threshold (1 to 1000) and the two reset timeouts (100 to 3600000 ms). A bad value
logs a WARN that names the key and takes the default; the effective maximum is
never below the base, see the max row):

| Key | Environment override | Default | Meaning |
|---|---|---|---|
| `circuit_breaker_failure_threshold` | `YUZU_GW_CB_FAILURE_THRESHOLD` | 5 (valid range 1 to 1000) | Consecutive failed upstream calls that open the breaker. A value that is not an integer in 1 to 1000 logs `Invalid circuit_breaker_failure_threshold value <V> (expected an integer in 1..1000); using 5` and takes the default; before this check a threshold of 0 opened the breaker on the first failure. An environment override that is not an integer is ignored with the `ENV override` line, as for the timeouts (INFERRED from the code and unit tests, not run on a rig). A failed stream-status notification (CONNECTED or DISCONNECTED) sent while the breaker is closed counts by the same rule as a failed `ProxyRegister` or `ProxyInventory` (see "What counts as a failure" above), and so does a success after failures: it clears the failure count (since #5695 it starts no registration replay; before #5695 it replayed the registrations). A Guardian forward and a heartbeat batch do not count. While the breaker is not closed the notifications are held, not sent (the head held one is the half-open probe), and an answer to a notification sent before the breaker last opened does not count against the breaker, although its notification is still retried or retired as usual (INFERRED from the code and unit tests, not run on a rig) |
| `circuit_breaker_reset_timeout_ms` | `YUZU_GW_CB_RESET_TIMEOUT_MS` | 10000 (valid range 100 to 3600000) | How long the breaker stays open the first time before it goes half open and allows one probe: a call-path RPC or, when stream-status notifications are held, the head held notification. A successful probe closes the breaker. Since #5695 that starts no registration replay; before #5695 it started the registration replay of every agent the node holds (OBSERVED on a rig). A value that is not an integer in 100 to 3600000 (0, a negative number, a float, a string, more than an hour) logs a WARN that names the key (`Invalid circuit_breaker_reset_timeout_ms value <V> (expected an integer in 100..3600000); using 10000`) and takes the default. The floor is 100 because the probe is timer driven: 0 would stay 0 and make the half open probe a hot loop forever, and a base or cap of 1 ms would still give a probe loop of about 1000 attempts a second. An environment override that is not an integer never reaches that check: `yuzu_gw_app` logs `ENV override: <VAR> has invalid value '<value>', ignoring` and the `sys.config` value (or the default) applies. An environment override that is an integer is stored and checked against the same range when the upstream client starts, so only an out-of-range integer produces the WARN above. A value above 3600000 does not clamp to one hour: it takes the default 10000, with the WARN (INFERRED from the code and unit tests, not run on a rig) |
| `circuit_breaker_max_reset_timeout_ms` | `YUZU_GW_CB_MAX_RESET_TIMEOUT_MS` | 30000 (valid range 100 to 3600000; 300000 before #5695) | Cap on the open duration, which doubles each time a trip or a failed probe reopens the breaker (10 s, 20 s, then 30 s with the defaults) and returns to the first value when a probe succeeds. 30 s means a server that comes back is used again within about 30 s, while a server that stays down gets one probe (a held notification or a proxied call) twice a minute; the `YuzuGatewayUpstreamCircuitOpened` alert relies on reopens at least every few minutes (its 5-minute window), so an operator who raises the cap above about 4 minutes must widen that rule with it. An invalid value takes the default 30000 with a WARN that names the key (`Invalid circuit_breaker_max_reset_timeout_ms value <V> (expected an integer in 100..3600000); using 30000`), and an environment override that is not an integer is ignored with the `ENV override` line, both as for the reset timeout; a value above 3600000 takes the default, not the limit. When the base is above the cap the effective cap is the base and one WARN is logged, with a different text for each case. An operator-set valid cap below the base logs `circuit_breaker_max_reset_timeout_ms (<Max>) is below circuit_breaker_reset_timeout_ms (<Base>); using <Base> for both`. A cap that is not set, or was rejected as invalid (the default applies), logs `circuit_breaker_reset_timeout_ms (<Base>) is above the default circuit_breaker_max_reset_timeout_ms (<Max>, not set or rejected); the maximum backoff is raised to <Base>. Set circuit_breaker_max_reset_timeout_ms to choose it.` |


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

### The upstream client

The gateway calls the server's `GatewayUpstream` service (registration, inventory, heartbeat
batches, stream-status notices, Guardian forwarding) with its own unary gRPC client,
`yuzu_grpc_client`, over a **channel** of HTTP/2 connections opened by gun
(`yuzu_grpc_client_channel`). Before 2026-10-11 this hop was grpcbox, configured in
`{grpcbox, [{client, ...}]}`; the wire protocol, the protobuf contracts and the server are
unchanged, and the value moved without changing shape (see *Upgrade notes by release* in
[Upgrading](upgrading.md#the-upstream-channel-moves-to-upstream_client--breaking)).

The channels are the `upstream_client` entry of the `yuzu_gw` application:

```erlang
{yuzu_gw, [
    {upstream_client, #{channels => [
        {default_channel,
         [{https, "yuzu-server.example.com", 50055, [
              {cacertfile, "/etc/yuzu/certs/default-ca.pem"},
              {certfile,   "/etc/yuzu/certs/default-gateway.pem"},
              {keyfile,    "/etc/yuzu/certs/default-gateway.key"},
              {verify, verify_peer}]}],
         #{pool_size => 1}}
    ]}}
]}
```

A channel is `{Name, Endpoints, Options}`. The registration, inventory and heartbeat code
calls the channel named **`default_channel`**, so that name is required. An endpoint is
`{http | https, Host, Port, SslOptions}`, or the same with a fifth element, a map whose
`socket_options` (a list) go to the TCP socket. `SslOptions` are Erlang `ssl` client options,
handed on unchanged; `http` is plaintext HTTP/2 (the lab and UAT posture), `https` is TLS
with ALPN `h2`. The shipped `sys.config.prod` is the mutual-TLS reference.

**What is acceptable for production:** `https`, `{verify, verify_peer}`, a CA-pinned
`cacertfile` (or `cacerts`) of the endpoint's own, and a client certificate and key
(`certfile` and `keyfile`): mutual TLS. Everything else (plaintext `http`, `https` without
those) is a dev or UAT posture, and the gateway refuses the unsafe half of it at boot (see
"What the gateway refuses at boot" below). A channel is one scheme: it may not list both
`http` and `https` endpoints.

| Channel option | Default | Meaning |
|---|---|---|
| `pool_size` | 1 | HTTP/2 connections **per endpoint**, 1 to 64 (a value outside that range is replaced by the default and the gateway logs a warning at boot, see [Bad values replaced by defaults](#bad-values-replaced-by-defaults)). One connection is what the grpcbox client held. **Raising it has consequences:** calls go round-robin over the live connections, so behind a layer-4 VIP in front of several server replicas the connections can land on different replicas (see "Several core replicas" under [What happens when the server restarts](#what-happens-when-the-server-restarts)), and after a certificate change the connections redial independently. Registration and inventory calls run one at a time, so a larger pool does not speed them up |
| `connect_timeout` | 5000 | Milliseconds allowed for the TCP connect and, separately, for the TLS handshake, 1 to 600000 |
| `max_receive_message_bytes` | 16777216 (16 MiB) | The largest response message accepted, up to 1 GiB; a larger one fails the call as soon as the limit is passed |

The grpcbox-era options `balancer`, `encoding` and `sync_start` are accepted and ignored.
Messages are never compressed (a compressed response message fails the call).

**How calls use the channel.** The channel process only owns the connections: it opens
`pool_size` of them per endpoint when it starts, notices when one comes up or goes down, and
reopens a lost one after a delay of 100 ms doubling to 5 s, with up to 20% jitter added on
top (so the longest delay is about 5.8 s, and the delay returns to 100 ms only once a
connection has stayed up for 5 s), so a restarted server is not met by every gateway at the
same instant. A call does not pass
through that process: it takes the next **live** connection, round-robin, and sends its
request there. A call that finds no live connection waits, at most for its own timeout, for
one that is already connecting; if none is connecting it fails **at once** with the last
connection error (`econnrefused`, `closed`, a TLS alert name), so a dead server is answered
in microseconds and the circuit breaker sees it. The per-call timeout is 5000 ms and covers
the connection wait; the callers do not change it. Nothing recycles a connection that is up:
there is no connection-age cap.

**TCP_NODELAY** is on for every connection by default (`upstream_tcp_nodelay`, see the table
under *Upstream channel tuning*).

**Certificates.** The gateway reads no certificate file itself: `SslOptions` reach Erlang's
`ssl` application, which reads `certfile`, `keyfile` and `cacertfile` when a connection's TLS
handshake runs. A connection that is up keeps presenting the certificate it opened with; a
reconnect presents the files as they are then, except that `ssl` caches file contents and
cleans that cache about every 120 s. MEASURED with this channel on OTP 28 against a local TLS
listener that requires a client certificate: after the files were replaced, the open connection
kept presenting the old certificate; a reconnect inside the cache window presented the old
one again; a reconnect after the `ssl` cache was cleared presented the new one. Replacing
the files therefore takes effect on the next reconnect, which happens when the connection
drops (a server restart does it) and can still present the previous certificate for up to
about 2 minutes. With the default of one connection per endpoint this is all or nothing, as it was with grpcbox. If you raise `pool_size` above 1, each connection redials on its own when it drops, so after a certificate change (or while an expired certificate is still in use) some calls can be refused by the server's peer check while others succeed, until every connection has redialed (INFERRED from the channel code, not run); see [Gateway upstream peer authorization](server-admin.md#gateway-upstream-peer-authorization)
for the procedure around pins and expiry.

**Log volume while TLS keeps failing.** Every failed TLS handshake writes the channel's own
`down` line plus Erlang `ssl` progress reports, about 5.8 KB per attempt in a probe. A
connection that fails persistently (a wrong CA, an expired certificate) redials about every
5.8 s once the delay has reached its cap, which at `pool_size` 1 comes to roughly 100 MB a day
(DERIVED from that figure, not measured over a day); a larger pool multiplies it, and a probe
at `pool_size` 8 wrote 369 KB in 12 s. Bound container logs (`logging: {driver: json-file,
options: {max-size: "50m", max-file: "5"}}` in Compose) and alert on the failure rather than
reading the log. The `ssl` progress reports list the option sets of each TLS connection,
including the **file paths** of the key and certificate (never the key's passphrase, probed
on OTP 28.4.2); treat the gateway log as sensitive to the same degree as the paths are.

**What the gateway refuses at boot.** Before any listener is bound it exits, with a critical
log line, when:

- a `{grpcbox, [{client, _}]}` or `{grpcbox, [{servers, _}]}` entry exists, in the application
  environment or in any config file the VM was started with (nothing reads them; see the
  upgrade notes);
- `upstream_client` is present but unusable: the log line gives the shape of the first defect
  (`bad_client_config`, `bad_channel`, `bad_endpoint`, `bad_host`, `bad_socket_options`),
  never the value, because SSL options name key files;
- no channel is named `default_channel`. A gateway with none would register no agent and
  forward no heartbeat while `/readyz` answered ready (its `upstream` check only tests that
  the `yuzu_gw_upstream` process is alive, not that the server is reachable). Only the literal
  `{yuzu_gw, [{allow_no_upstream, true}]}` excuses it, for a gateway under test;
- **any** `https` upstream endpoint lacks `{verify, verify_peer}`, or lacks a `cacertfile` /
  `cacerts` of its own (`Refusing to start: the upstream channel uses TLS (https) WITHOUT
  {verify,verify_peer} and a {cacertfile,...} of its own`). Without a CA of its own the TLS
  stack trusts the operating system's CA store, so any publicly trusted certificate for the
  server's name would be accepted. One verified endpoint does not excuse an unverified one:
  calls go round-robin over all of them. Only the dev/CI override
  `YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1` excuses it (the gateway then logs a warning);
- a TLS file named by an `https` endpoint (`cacertfile`, `certfile`, `keyfile`) is a directory or
  another non-file (`Refusing to start: a TLS file of an upstream endpoint is a directory or not
  a regular file`; reason `unusable_upstream_tls_file`). It cannot become a file by waiting, and a
  container runtime creates exactly this in place of a bind-mounted file that does not exist on
  the host. A file that is merely **missing**, empty or without a certificate is not refused;
  see [A CA, certificate or key file that is wrong](#a-ca-certificate-or-key-file-that-is-wrong);
- one channel lists both `http` and `https` endpoints (`Refusing to start: the upstream
  channel <name> lists both plaintext (http) and TLS (https) endpoints`; reason
  `mixed_upstream_endpoints`). Calls go round-robin over every live connection, so some would
  travel unencrypted whatever the `https` endpoint is verified against. There is no override:
  give the channel one scheme.

The boot log then names the posture: `mutual-TLS` only when every endpoint also carries a
`certfile` and `keyfile`, otherwise `server-authenticated TLS (no client certificate)`. The
gateway does not require the client certificate; the server enforces it (mutual TLS plus
the gateway's SPKI pin, see [Gateway upstream peer
authorization](server-admin.md#gateway-upstream-peer-authorization)), so a gateway without one
boots and is then refused by the server.

**Keys that look related and do nothing.** `upstream_addr`, `upstream_port` and
`upstream_pool_size` are read by nothing: the endpoints of the channel are what is dialled,
and the pool size is the channel's `pool_size`. This was already so before the client was
replaced. The environment variables `YUZU_GW_UPSTREAM_ADDR` and `YUZU_GW_UPSTREAM_PORT` are
now **ignored with a boot warning** (`YUZU_GW_UPSTREAM_ADDR is set but has no effect`); they
no longer log an `ENV override` line as if they had applied. Change the endpoint in the channel
to repoint a gateway, not these variables.

**Two limits of the endpoint.** An IPv6 literal host (`"::1"`) fails name resolution in a
retry loop unless the endpoint's `socket_options` include `inet6`, and `"[::1]"` fails too;
the dial is IPv4 only, with no fallback, so `localhost` against an IPv6-only listener reads as
`econnrefused`. Both look like a server that is down. A `pool_size`,
`connect_timeout` or `max_receive_message_bytes` that is out of range or not an integer is
replaced by its default; see [Bad values replaced by defaults](#bad-values-replaced-by-defaults).

#### A CA, certificate or key file that is wrong

When the CA, certificate or key file an `https` endpoint names is missing, unreadable, empty
or holds no PEM certificate (or no PEM key, for `keyfile`), Erlang's `ssl` rejects the whole
option set. Every connection attempt then fails in about 2 ms with the one word
`bad_tls_options`, which says nothing about which file. The gateway therefore looks at the
files itself and says it in three places:

1. **At boot**, one WARNING per file: `Upstream channel default_channel endpoint
   gw.example:50055: cacertfile /etc/yuzu/ca.pem does not exist (yet). Every connection to it
   fails until this is fixed. The gateway starts anyway ...`. The gateway starts on purpose: the
   server generates its certificates on its first start, which can be after the gateway's, and
   the channel keeps retrying. A **directory** where a file belongs is the one case it refuses
   (see above).
2. **While it keeps failing**, an ERROR line from the channel, the first at once and then at
   most once a minute: `Upstream channel default_channel: the TLS client options cannot be used,
   so every connection fails: cacertfile /etc/yuzu/ca.pem does not exist (yet). The gateway
   keeps retrying and /readyz stays 503 until this is fixed`. If none of the files is at fault,
   it says so, and the cause is one of the other `ssl` options.
3. **In `/readyz`**: the check `upstream_tls_files` is `false` and the whole answer is 503
   `not_ready` while the most recent connection attempt of any channel failed because its TLS
   options are unusable. It is a table read, so a slow upstream cannot hold it. The circuit
   breaker alone would have stayed closed until five calls had failed.

The reasons are `does not exist (yet)`, `cannot be read (permission denied)`, `is a directory,
not a file`, `is not a regular file`, `is empty`, `contains no PEM certificate` and `contains no
PEM private key`; any other file error is shown as its POSIX name (`eio`). The path of a
`cacertfile` or `certfile` is printed, the path of a `keyfile` is **never** printed (the line
says `keyfile`, and you know which key your configuration names).

Limits, so the signal is not read as more than it is:

- It reports the **most recent attempt**. If the server is also down, the TCP connect fails
  before TLS is tried, the report clears, and it returns once the server is reachable. A gateway
  with both problems is not ready for the first reason either way.
- The file check reads each file once per failed attempt and parses it only up to 4 MiB. A file that is
  a valid PEM certificate but the wrong one (another CA) is not a file problem: it fails the
  handshake with a TLS alert such as `unknown_ca` instead, which the `down (<alert>)` lines
  and `yuzu_gw_upstream_tls_handshake_failures_total` carry.
- A key that does not match its certificate is not detected here.
- The OTP `ssl` progress reports that also appear on each attempt still print the option set,
  key file paths included (tracked separately); this line adds none.

#### Bad values replaced by defaults

A channel option that is present but is not an integer inside its range does not stop the
gateway. It is replaced by the option's default, and the gateway logs one warning per option at
boot, before it binds any listener:

```
Upstream channel default_channel: pool_size is 100, not an integer from 1 to 64; the default 1
is used instead (docs/user-manual/gateway.md 'Bad values replaced by defaults').
```

The gateway starts anyway on purpose: a typo in a tuning option would otherwise turn into a
refusal to boot on the next restart, on every gateway that shares the file. The cost is that the
gateway that runs is not the one the file describes, so look for this warning after any change to
`upstream_client`.

| Option | Accepted | Default used instead |
|---|---|---|
| `pool_size` | integer, 1 to 64 | 1 |
| `connect_timeout` (ms) | integer, 1 to 600000 | 5000 |
| `max_receive_message_bytes` | integer, 1 to 1073741824 | 16777216 (16 MiB) |

What the warning says about the value: an integer is printed as it is, an atom by name
(`infinity`), and anything else only by its type (`a list`, `a binary`, `a float`, `a map`). So
`"4"` (a string) and `2.0` (a float) are both replaced, and the warning reads `a list` and `a
float`. The contents are not printed, because these options sit beside the channel's SSL options
in the same file.

To clear the warning, correct the value in `sys.config`. It takes effect the next time the
gateway starts, and a restart disconnects every agent the node holds (see [What happens when the
server restarts](#what-happens-when-the-server-restarts)), so schedule it like any other restart.

What this warning does **not** cover:

- A value that is valid but unwise. A `max_receive_message_bytes` of a few hundred bytes is in
  range, so it is used as written, and every response larger than that then fails the call
  after the server has already acted on the request (a `ProxyRegister` is committed on the
  server and the gateway sees an error).
- An option that is misspelled or unknown, such as `poolsize`. It is not a bad value, it is
  simply not read, and nothing is logged.
- Other gateway settings. Each is described where it is introduced; this warning concerns the
  channel options above only. `upstream_tcp_nodelay` and the other boolean environment
  settings log a warning of their own when their value is invalid.

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
> either (a) front the gateway at L4 or with TLS passthrough (one TCP
> connection per agent end to end, with the gateway's own agent-listener TLS
> enabled), or with an HTTP/2-terminating proxy configured for connection affinity
> (re-encrypting to the gateway; see
> [Keeping each agent on one backend connection](#keeping-each-agent-on-one-backend-connection)),
> never one that pools backend connections across clients, or (b) keep
> `:50051` on a trusted network (VPN / private subnet / a mesh policy that does not
> terminate HTTP/2; see [Heartbeat admission](#heartbeat-admission)). Direct
> agent→server connections use TLS; this gap is specific to the gateway edge.

| Hop | State | Notes |
|---|---|---|
| gateway → server upstream (`:50055`) | **mutual TLS in `sys.config.prod`; the gateway itself enforces only server verification** | `gateway/config/sys.config.prod` `{https,...}` `default_channel`; CA-issued `default-gateway` leaf, TLS 1.2 floor + AEAD/PFS cipher whitelist. The gateway refuses to boot on `https` without `verify_peer` and a CA of its own, and on a channel mixing `http` and `https`; it does **not** require a client certificate, so mutual TLS holds only where the endpoint carries `certfile` and `keyfile` and the server demands them (SPKI pin, see [Gateway upstream peer authorization](server-admin.md#gateway-upstream-peer-authorization)). Plaintext `http` boots as the lab/UAT posture. |
| agent → gateway (`:50051`) | **one-way TLS (PR5c)** | Server-authenticated TLS, no client cert required (bootstrap-safe). Enabled on the agent listener in `sys.config.prod` via `tls => #{certfile, keyfile, cacertfile, verify => verify_none, fail_if_no_peer_cert => false}` in its `grpc_listeners` entry. Of the shipped composes, only `docker-compose.reference-gateway.yml` enables it (#1314, mounting `reference-gateway-sys.config`). The cluster, demo, full-UAT, viz-UAT and sanitizer-UAT composes, and the repo-root `docker-compose.uat.yml`, run plaintext on the shipped default or a UAT/demo `sys.config` (inline in `docker-compose.uat.yml`, mounted as a file by the others); the remaining composes do not run the gateway. Heartbeats are bound to the connection that opened the session's `Subscribe` stream (see [Heartbeat admission](#heartbeat-admission)); the agent listener itself still does not authenticate agents. |
| server → gateway mgmt (`:50063`) | **strict mTLS + SPKI peer pin (#1422)** | The privileged command-fan-out plane. Do NOT one-way-TLS it (would be unauthenticated). The secure shape (in `sys.config.prod` / `reference-gateway-sys.config`) is strict mTLS (omit `verify`/`fail_if_no_peer_cert` from the `tls` map) **plus** `auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1` with `{yuzu_gw, mgmt_peer_pins}` pinning the server's cert — a CA-issued cert alone (an agent's leaf, the gateway's own leaf) is NOT authorization to command the fleet. The gateway **refuses to boot** with a network-reachable mgmt listener lacking this posture; `{allow_insecure_mgmt, true}` is a lab-rig-only acknowledgement (pair it with an unpublished `:50063`). BYO certs: point `mgmt_peer_pins` at your server cert (`{cert_file, ...}`) or paste its SPKI SHA-256 (`{spki_sha256, "..."}`) — the cert **must carry the `serverAuth` EKU** or the pin rejects it (`missing_server_auth_eku` in the gateway log); list old+new pins to overlap a rotation. Pin-list edits (adding/removing an entry) require a gateway restart; only a `{cert_file, Path}` target's file **content** re-reads live without one — within `mgmt_pin_refresh_ms` (default 5 s, see "Management-pin refresh"): the `yuzu_gw_mgmt_pins` watcher re-reads the file on its own timer (comparing a SHA-256 of its contents, so a new key of the same size with a preserved mtime is still picked up) and the per-stream check reads its published key, never the file, so a rotated server leaf can be refused for up to one interval (fail closed). The server does not retry a refused command: it fails terminally as `gateway_unauthenticated` and must be submitted again (#5988 tracks a server-side retry). |

TLS is configured in two places: the `tls` map of each `grpc_listeners` entry (the
two listeners) and the `{yuzu_gw, [{upstream_client, ...}]}` entry (the upstream channel;
it was `{grpcbox, [{client, ...}]}` before 2026-10-11, and a leftover block under that
name refuses boot). The
old `{tls, [...]}` advisory key under `yuzu_gw` was removed in PKI PR5 and does
**nothing**. To enable upstream mutual TLS, copy the `{https,...}` channel of
`upstream_client` from `gateway/config/sys.config.prod`. A listener without a `tls`
map is plaintext, and a `tls` map must carry all three of `certfile`, `keyfile` and
`cacertfile` or the gateway refuses to boot.

Do not turn on client-certificate enforcement on the agent listener by adding an
`auth_fun`: see [Moving the agent edge to mutual TLS](#moving-the-agent-edge-to-mutual-tls)
for what exists and what does not. Full detail: `docs/pki-architecture.md` "Gateway TLS".

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
3. **Only then flip the listener** to TLS by adding the `tls` map to its entry (as in `sys.config.prod`).

Reversing the order strands the fleet until every agent is re-pointed.

**Compromised-gateway caveat:** one-way TLS authenticates the **gateway to the
agent**, not the agent to the gateway. It closes the on-path eavesdrop/inject of
the plaintext edge, but a *compromised gateway itself* can still inject commands
to the fleet — the compensating control is app-layer: the enrollment approval
workflow. (The server also accepts gateway-authoritative `gateway_observed_peer`
attribution, which the gateway now sets itself for every registration; see
[Client addresses behind a proxy](#client-addresses-behind-a-proxy). It is
attribution, not authentication: a compromised gateway, and a host listed in a
listener's `origin.sources`, can assert any source address.)
Full cryptographic agent-to-gateway identity (so the gateway can't forge an
agent) is tracked in the through-gateway attestation work (#1292, design in
#5578); no release is committed.

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
#      {yuzu_gw,[{upstream_client,#{channels=>[{default_channel,[{https,...,[{certfile,...},...]}],#{}}]}}]}   % upstream mTLS
#      grpc_listeners agent entry: tls => #{certfile, keyfile, cacertfile,
#                                   verify=>verify_none, fail_if_no_peer_cert=>false}

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

### Certificate rotation and expiry

**What the gateway watches.** The management-pin watcher (`yuzu_gw_mgmt_pins`)
checks every certificate file the gateway is configured with every
`mgmt_pin_refresh_ms` (default 5 s). It reads every file on every check and
parses it again only when its bytes changed (a SHA-256 of the contents is
compared). The modification time and size are not enough: a new certificate
with a key of the same type usually has exactly the same size, and `cp -p`,
`rsync -a` or `tar -p` keep the old modification time, so a check on those
alone would keep the old key. Certificate files are a few kilobytes, so this
costs one small read per file per interval, on the watcher's own timer; no
management call ever touches the file system. The files,
and the `role` and `name` labels they are reported under:

| `role` | File | `name` |
|---|---|---|
| `listener` | `tls.certfile` of a `grpc_listeners` entry | the listener's `name` |
| `listener_ca` | `tls.cacertfile` of the same entry | the listener's `name` |
| `upstream_client` | `certfile` of an `upstream_client` channel endpoint | the channel name |
| `upstream_ca` | `cacertfile` of the same endpoint | the channel name |
| `mgmt_peer_pin` | the `Path` of a `{cert_file, Path}` entry of `mgmt_peer_pins` (the **server's** certificate) | the file name |

Inline certificates (`cert`, `cacerts`) are not files and are not reported.

**Metrics.** `yuzu_gw_cert_expiry_timestamp_seconds{role,name}` is the
certificate's `notAfter` in Unix seconds (for a file holding several
certificates, the earliest). `yuzu_gw_cert_file_readable{role,name}` is 1 while
the latest read of the file parsed as PEM certificates and 0 when the stat, the
read or the parse failed. When a file becomes unreadable the expiry gauge keeps
the last value read from it, so an expiring certificate keeps alerting; a file
that was never readable has no expiry series. Two certificates under one
`role` and `name` (two endpoints of one channel with different files) are
reported as one series: the earliest `notAfter`, and readable only if both are.
`yuzu_gw_mgmt_pin_rotated_timestamp_seconds` is the Unix time at which the
watcher last published a **different** key for a `{cert_file, Path}` pin. It is
0 until the first such change in the gateway process; reading the file at start,
or a rewrite of the same key, does not set it.

**A management pin file that cannot be read.** Once a `{cert_file, Path}` pin has
been read, the gateway keeps the key it read if a later read fails (the file is
missing, unreadable, not a PEM certificate, or caught half-written). Commands
keep flowing, `yuzu_gw_cert_file_readable{role="mgmt_peer_pin"}` reads 0, the
log says `the key last read from it stays pinned until the file is readable
again`, and `YuzuGatewayMgmtPinUnresolved` fires after 2 minutes. Fix the file:
until it is readable again the gateway cannot pick up the server's next
rotation, which it would then refuse. Deleting the file does **not** withdraw
the pin. To change the pinned key, replace the file with the new certificate
(picked up within one interval). Removing the entry from `mgmt_peer_pins` also
withdraws it, but only at the next gateway restart, which disconnects every
agent on the node; agents without the #5183 fix stay wedged after it, so
prefer replacing the file unless the entry itself must go. A pin file that is unreadable when the gateway starts pins
nothing, as before (fail closed): every management stream is refused
`no_pins_resolved` unless another pin admits the server.

**A routine rotation of the server's certificate.** When the server replaces its
leaf at the pinned path, the gateway pins the new key at its next refresh. In
the window between the two (at most one `mgmt_pin_refresh_ms`, 5 s by default)
the server's management streams carry the new key while the gateway still pins
the old one, and they are refused `pin_mismatch`. **The server does not retry
these**: each command it forwards to this gateway in that window fails
terminally as `gateway_unauthenticated`, is counted in the server's
`yuzu_server_gateway_forward_total{status="unauthenticated"}` and shows as a
failed command. Commands sent after the refresh go through, and nothing needs to
be done about the gateway. If a failed command matters, run it again. To make
the window empty, pre-stage the new key as a second pin (`{spki_sha256, Hex}` of
the new certificate) before the server rotates, and remove it after. Each change
to `mgmt_peer_pins` applies only at a gateway restart, which disconnects every
agent on the node (agents without the #5183 fix stay wedged after it), so weigh
that against re-running the few commands a rotation drops.

**Alerts** (group `yuzu-gateway` and `yuzu-tls` of
`docs/prometheus/yuzu-alerts.yml`; scrape the gateway). Each fires only when
someone has something to do:

| Alert | Fires when | What to do |
|---|---|---|
| `YuzuGatewayMgmtAuthRejected` (warning) | a management peer was refused for any reason **other than** `pin_mismatch`, in the last hour | `missing_server_auth_eku`, `bad_peer_cert`: a holder of an install-CA certificate that is not the server reached `:50063`, or the server's leaf lacks the serverAuth usage; investigate the source, fix the server certificate. `no_pins_resolved`, `no_pins_configured`, `bad_pin_config`: the pins admit nobody and every forwarded command fails; restore the pinned file or correct `mgmt_peer_pins`. `internal_error`: collect the log, report it. A rotation never produces these. |
| `YuzuGatewayMgmtPinMismatch` (critical) | `pin_mismatch` rejections that no pin rotation on this gateway explains: rejections are read one minute late and ignored for 4 minutes after `yuzu_gw_mgmt_pin_rotated_timestamp_seconds` moves | Commands to this gateway's agents are failing. If the server's certificate changed, update the pinned file (picked up within one interval). If it did not change, someone is presenting another serverAuth certificate (for example the gateway's own key) to the command plane: treat it as a security incident. |
| `YuzuGatewayMgmtPinUnresolved` (warning, 2 m) | a configured pin has never resolved, or a pin file's latest read failed (`yuzu_gw_cert_file_readable{role="mgmt_peer_pin"} == 0`) | Correct the fingerprint, or restore the pinned file (owner, mode, contents). The fix is picked up within one interval. |
| `YuzuGatewayCertificateFileUnreadable` (warning, 10 m) | a listener or upstream certificate file cannot be read or parsed | Restore it before the gateway restarts or redials: until then it keeps the certificate it loaded, but anything that reads the file again fails. |
| `YuzuGatewayCertificateExpiringSoon` (warning, 1 h) | a configured certificate expires in 7 to 30 days | Schedule the renewal. |
| `YuzuGatewayCertificateExpiryImminent` (critical, 10 m) | it expires in 1 to 7 days | Renew it today. |
| `YuzuGatewayCertificateExpiryCritical` (critical, 5 m) | it expires in under 24 hours, or has expired | Renew it now. |

The three expiry bands do not overlap, so one renewal pages once at a time. For
`mgmt_peer_pin` the certificate is the server's: renew it on the server, and the
gateway pins the new key on its own. Renewing the gateway's own leaf
(`listener`, `upstream_client`) over a **new key** needs the server's gateway
peer pin updated first: see "Rotation" in [Gateway upstream peer
authorization](server-admin.md#gateway-upstream-peer-authorization).

**Limits.** The rotation suppression assumes the scrape interval plus
`mgmt_pin_refresh_ms` is at most one minute; with a longer refresh interval the
refused window is longer and a rotation can fire `YuzuGatewayMgmtPinMismatch`.
The rotation timestamp lives in the gateway process and starts at 0: a gateway
that starts after the server rotated reads the new key at start and records no
rotation, which is correct because it never refuses the new key. The `notAfter` comes from the
file, not from the certificate a listener or connection loaded: after replacing a
file, the new date is reported within one interval even if a long-lived
connection still presents the old certificate.

### Client addresses behind a proxy

The server records the address of the agent that registered (`source_ip` in audit rows,
`gateway_observed_peer` on the wire). The gateway decides that address itself, per call,
from the listener's `origin` option. Whatever an agent puts in
`RegisterRequest.gateway_observed_peer` is discarded and replaced by the gateway's value:
a bare IP address (no port, no brackets), or empty, which means "no observation".

A gateway behind a load balancer or a router sees the balancer as its TCP peer. The
address of the agent behind it arrives as a claim: a PROXY protocol header, or an
`x-forwarded-for` header. A claim is believable only when the proxy made it, so the
decision is made by **who connected, never by whether the claim matches** the connection:

| `origin` | The address is | Use when |
|---|---|---|
| `#{mode => transport}` (default) | The TCP peer. A PROXY header or `x-forwarded-for` a client sends is ignored. | Agents connect to the gateway directly. |
| `#{mode => proxy_protocol, sources => [...]}` | The address in the PROXY protocol header, if the TCP peer is one of `sources`. | An F5 (iRule) or HAProxy (`send-proxy-v2`) passes the TCP stream through. |
| `#{mode => forwarded_for, sources => [...], trusted_hops => N}` | The `x-forwarded-for` entry `trusted_hops` places from the right (0 = the last entry, the one the nearest proxy appended), if the TCP peer is one of `sources`. Entries further left are never examined. `trusted_hops` is an integer from 0 to 31. | A router terminates TLS and forwards HTTP/2 to the gateway. |

What the server is told, by who connected:

| The call came from | `gateway_observed_peer` | Counter | Server audit |
|---|---|---|---|
| A listener in `transport` mode | The TCP peer | none | `source_ip` = the TCP peer, no flag. **Behind a proxy you have not configured this is the proxy's address, and nothing flags it.** |
| A configured proxy, usable claim | The claimed address | none | `source_ip` = the claimed address |
| A configured proxy, claim missing or unusable (`no_claim`, `bad_claim`) | **Empty: no observation** | `origin_ignored{reason="no_claim"\|"bad_claim"}` | `source_ip` = the gateway node's address, `origin_observed=false` |
| A peer that is not one of the `sources` (`untrusted_source`) | The TCP peer (what that client really is) | `origin_ignored{reason="untrusted_source"}` | `source_ip` = the TCP peer |

An unusable claim from a proxy you trust is therefore never turned into the proxy's own
address: the gateway says "not observed" and the server's audit row carries
`origin_observed=false` beside the fallback `source_ip`, so a rise of `no_claim` /
`bad_claim` is both a counter you can alert on and a visible flag in the audit trail. A
claim from a TCP peer that is **not** a source is **ignored, not refused**: the call is
served and attributed to that peer. Behind NAT, an F5 or a router the claim and the
connection legitimately differ, so refusing a mismatch would turn a configuration slip
into an outage; the TCP peer is what a client that reached the listener directly, and sent
the claim itself, really is. Addresses are attributed without a port, and IPv4-mapped IPv6
addresses are folded to IPv4 (including a source network written that way, such as
`{{0,0,0,0,0,16#ffff,16#0a00,0}, 104}` for `10.0.0.0/8`; a mapped network with a prefix
of 96 or less is refused at boot).

The server's audit row records the address (or `origin_observed=false`), not how it was
obtained: it does not distinguish the TCP peer, a proxy-vouched address and a listener left in
`transport` mode behind an unconfigured proxy. A separate, later change will add that.

Version skew: the server cannot tell a gateway that overwrites the field from one that does
not. An older gateway forwards the value the agent sent, so **upgrade every gateway before
you rely on `source_ip`**; until then a forged value passes through that gateway.

```erlang
%% F5 iRule or HAProxy `send-proxy-v2`; v1 and v2 headers are both read.
origin => #{mode => proxy_protocol, sources => [{10,0,0,5}, {{10,1,0,0}, 24}]}

%% A router that terminates TLS and appends the client it saw to x-forwarded-for.
origin => #{mode => forwarded_for, sources => [{10,0,0,5}], trusted_hops => 0}
```

`sources` are the proxies as the gateway's socket sees them: an IP tuple such as
`{10,0,0,5}`, or `{Ip, PrefixLen}` for a network such as `{{10,1,0,0}, 24}`. A proxy mode
with no sources refuses boot, as does an unknown mode or option. Keep `sources` narrow: a
wide network (a `/8`, say) trusts every host in it to vouch for any address.

**`proxy_protocol`.** The header precedes the TLS handshake, so a TLS-passthrough
balancer keeps the TLS session end to end and the **client certificate still reaches the
gateway**. Every connection on the listener must carry the header or it is closed (after a
second), so such a listener serves only the proxy. An F5 health monitor aimed at that port
will fail unless it sends the header: monitor another port (for example the gateway's
health port). A PROXY `LOCAL` command (a health check by the proxy itself) carries no
client: if the connection goes on to make a call, that call counts as `no_claim` and is not
attributed to anyone; a check that only connects opens no stream and is not counted. A PROXY header
with an address family that has no address (`UNSPEC`, a unix socket) counts as
`bad_claim`.

**`forwarded_for`.** The router terminates TLS, so the certificate the gateway sees is the
router's, not the agent's, and the option **cannot be combined with an `auth_fun`**
(boot refuses it: the check would pass on the router's certificate and say nothing about the
agent). Cowboy joins repeated `x-forwarded-for` lines with `, ` in order, so the entry the
nearest proxy added is the last one, whether it sent a new line or extended the client's.
The gateway examines only the entry `trusted_hops` places from the right and ignores
everything to its left, whatever its length, count or bytes: a client cannot spoil the
claim by sending a long or malformed header. The entry is trimmed of spaces and tabs and
must be a bare IP address of at most 64 bytes (no port, no brackets, no leading zeros, no
`1.2.3`). A scoped IPv6 entry such as `fe80::1%eth0` is accepted with the zone dropped (the
Erlang address parser reads it that way), so it is attributed as `fe80::1`; an entry over 64
bytes is `bad_claim` however valid it is. A header with fewer than `trusted_hops + 1` entries, or whose selected entry is
not an IP, is `bad_claim`; no header at all is `no_claim`. In both cases the call has no
observed address (see the table above). With an OpenShift/OKD router, leave the
IngressController's `spec.httpHeaders.forwardedHeaderPolicy` at `Append` (the default) or
`Replace`: either puts the address the router saw last in `x-forwarded-for`, which
`trusted_hops => 0` reads. `IfNone` and `Never` can leave a client-supplied header as the
only entry; do not use them with this option. On OKD 4.21 with the default `Append`, the
real client address was attributed for every agent and a forged `x-forwarded-for` was
ignored. A router that terminates HTTP/2 must also keep each agent on one backend
connection, because [Heartbeat admission](#heartbeat-admission) binds heartbeats to the
connection that opened the session: see the next section.

**Count your proxies.** `trusted_hops` is the number of trusted proxies between the client
and the gateway, minus one: 0 when one proxy appends the client's address, 1 when two do.
A value **larger** than the real number lets a client choose the entry: behind one proxy,
`trusted_hops => 1` selects the entry to the left of the proxy's, which is whatever the
client put in its own `x-forwarded-for`, so the audit `source_ip` is a forged address. A
value that is **smaller** attributes the call to an address the proxy chain owns (the
outer proxy, say), which is wrong but not forged. Check it with the real path: send a
`Register` that presents an enrollment token from a test host through the proxy with a
client-supplied `x-forwarded-for` header (a made-up address) and confirm that the
`source_ip` of the `enrollment.token_consumed` audit row is the test host's own address and
not the header's. The check needs the enrollment token because the server writes the gateway
origin to the audit log only on that action (an unknown or already-used token writes the same row
with `result=failure`); a `Register` without one leaves nothing to read.

#### Keeping each agent on one backend connection

Behind a router that terminates TLS the gateway's "connection" is the router's
connection to the gateway, not the agent's to the router. Heartbeat admission compares the
connection of an agent's `Heartbeat` calls with the one that opened its `Subscribe`
stream, so the router must give **each client connection its own backend connection and
keep it for as long as the client connection lives**. Then all of an agent's calls arrive
on one backend connection (and, with several gateway replicas, on the one replica that
backend connection is to, which the node-local admission state also needs). A router that
pools backend connections across clients breaks this in both directions: one agent's
calls spread over several connections are rejected as `connection_mismatch`, and calls of
different agents share one, which weakens the separation the check provides.

HAProxy's default `http-reuse safe` did **not** do this in testing (HAProxy 3.2.25 and
the OKD 4.21 router's 2.8, 50 agents, ten minutes or more, zero mismatches): its
documentation says that once a stream has been processed the connection is reserved for
the streams of the same session. `http-reuse never` is the setting that states the
requirement outright, costs nothing for this workload, and is what to use if you want the
configuration to say what it needs. Even `http-reuse always` gave zero mismatches in a
six-minute run, but it exists to share connections between clients and nothing in its
documentation promises otherwise, so do not rely on it. A mismatch counter that stays at 0 only means
something if it can move: a Register on one connection followed by a Heartbeat on another
raised it to 1 in the same rig.

HAProxy as the terminating proxy, re-encrypting to the gateway over HTTP/2. This is the
configuration that was tested; the `defaults` section is part of it, because without
`mode http` HAProxy ignores `option forwardfor` and the `http-request` rule, adds no
`X-Forwarded-For`, and every agent is then attributed to the proxy (`no_claim`):

```
defaults
    mode http
    timeout connect 5s
    timeout client 300s
    timeout server 300s

frontend yuzu_agents
    bind :443 ssl crt /etc/haproxy/agents.pem alpn h2
    http-request del-header X-Forwarded-For   # drop anything the client sent
    option forwardfor                         # add the address HAProxy saw
    default_backend yuzu_gateway

backend yuzu_gateway
    http-reuse never                          # a backend connection belongs to ONE client connection
    balance leastconn                         # chooses the replica when the client connects
    timeout server 300s                       # longer than the agent's 60 s keepalive
    server gw1 10.0.1.11:50051 ssl verify required ca-file /etc/haproxy/yuzu-ca.pem alpn h2
```

`http-reuse never` is HAProxy's setting for connection-bound protocols: the server
connection a session opened stays attached to that session instead of returning to a
pool other sessions draw from. `option forwardfor` adds the client address as its own
`X-Forwarded-For` line after any the client sent; the gateway joins the lines in order and
reads the one `trusted_hops` places from the right, so the client's own claim is never the
one used (deleting it first keeps the header short). `timeout client` belongs in the
`defaults` or `frontend` section and `timeout server` in the backend or `defaults`; the
snippet sets both in `defaults` and repeats `timeout server` in the backend.

What was run. The snippet is the file the acceptance run checked with `haproxy -c` on
HAProxy 3.2.25 (the official container image; rc 0), and 50 agents then ran for ten
minutes or more through a configuration that differs from it only in the listening port
(`:8443`, because the container did not run as root), the backend address (the test
gateway) and a `global` section that sets `maxconn 4096` and logging. `haproxy -c` on
2.8.14 also accepts it without a warning (paths changed for a scratch directory). Without
the `defaults` section HAProxy still accepts the file (`haproxy -c` returns 0) but warns
that the `http-request` rule and `option forwardfor` are ignored because the proxy is not
in HTTP mode, and it adds no header: a `-c` that returns 0 proves the syntax, not that the
configuration does its job, so read its warnings. Not tested: timeouts of 1 hour in `mode
http`, `bind :443` itself, more than one `server` line, and any HAProxy older than 2.8.

*Idle timeouts.* An agent's `Subscribe` stream is long-lived and carries no traffic while
idle, and a router cuts it once its timeout passes. Measured with 50 agents behind
`forwarded_for` (the gateway's connected and disconnected counters, sampled every 10 to
30 s, so each time is good to one sample interval; "t0" is the sample at which all 50 had
registered):

| Run | Idle timeout | Sampled cut |
|---|---|---|
| OKD router, stock timeouts | 30 s | 3 disconnects 33 s after the first connect sample, all 50 by 74 s |
| OKD router, route `timeout` annotation only (the server side) | 30 s client side | 2 disconnects 32 s after the first connect sample, all 50 by 63 s |
| HAProxy 3.2.25, the snippet above | 300 s | none at t0 + 332 s, all 50 at t0 + 362 s |
| HAProxy 3.2.25, the snippet without `http-reuse never` | 300 s | none at t0 + 332 s, all 50 at t0 + 363 s |
| OKD router, `clientTimeout` and `serverTimeout` 10 m | 600 s | disconnect counter 4 at t0 + 634 s and 51 at t0 + 664 s (it stood at 1 from t0 + 30 s: the mismatch check made then) |
| HAProxy 3.2.25, `mode tcp` with `send-proxy-v2` | 3600 s | none in the 10 minutes watched |

Read against the timeout: in the two 300 s runs the sample 32 s after it showed no
disconnect and the sample 62 s (63 s in the second run) after it showed all 50 gone; in the
10 m run the sample 34 s after it showed 3 of the 50 gone and the sample 64 s after it
showed all 50. So the first disconnect was seen 34 s after the timeout in the 10 m run and
between 32 and 62 s after it in the 300 s runs, and the cut was complete 62 to 64 s after
the timeout in all three. The two 30 s runs began to disconnect 32 and 33 s after the first
connect sample, when 47 and 50 agents had connected, and had cut all 50 by 74 and 63 s
after it. The sample interval (10 to 30 s) does not allow more precision, and why the cut
lands after the timeout rather than at it is not established. In every run the agents re-registered each
time with no mismatches, but each cut is a reconnect and a fresh session, so a short
timeout turns into constant churn, and every agent behind the proxy reconnects in the same
few seconds (see "Sizing the proxy and the gateway for a fleet" below). Raise **both** the
client and the server timeout; on OpenShift a route's
`haproxy.router.openshift.io/timeout` annotation changes only the server side (the second
row). The agent listener itself closes a connection that has carried no bytes for 180 s
on `sys.config.prod` and the reference configs (the plaintext default, demo and UAT
configs inherit 600 s), so behind a router the gateway is not what ends a quiet
connection.

**OpenShift / OKD router.** Measured on OKD 4.21.0-okd-scos.8 (single node, router
HAProxy 2.8.10), 50 agents, no route or router setting for connection reuse was needed.
What was needed:

- **Enable HTTP/2 on the router.** A stock router ships with HTTP/2 off, so no ALPN is
  negotiated and a gRPC client refuses the connection. Annotate the IngressController
  with `ingress.operator.openshift.io/default-enable-http2=true`. Red Hat's guidance for
  gRPC through the router is that HTTP/2 on the front end needs a custom certificate on
  the route and that HTTP/2 end to end works with a **re-encrypt** or **passthrough**
  route, not **edge**.
- **Use a re-encrypt route** with the gateway's certificate as the route's custom
  certificate (or a passthrough route, which keeps the agent's own TCP connection and
  needs no `forwarded_for`).
- **Raise the idle timeouts** as above: `spec.tuningOptions.clientTimeout` and
  `serverTimeout` on the IngressController.
- **Set the listener to `forwarded_for`** with `trusted_hops => 0`. With `hostNetwork`
  the gateway sees the router as the node's OVN management address (10.217.0.2 on the
  test cluster), not the router pod's. If `yuzu_gw_grpc_origin_ignored_total{reason="untrusted_source"}`
  rises for traffic that came through the router, `sources` does not name the address the
  gateway actually sees.

A second, sharded `IngressController` behaves the same and is a supported way to keep
agent traffic off the default router. A router run from a custom HAProxy template (the
`TEMPLATE_FILE` mechanism of the router image) also passed, but Red Hat does not support
custom templates or an unmanaged router on OpenShift 4.x (knowledge-base solution
5381141): treat it as your own proxy, not as the platform's. The ingress operator offers
no setting for `http-reuse`; an HAProxy of your own, configured as above, is the way to
control it. Repeat the check below after any change of OKD or router version: this was one
single-node cluster and one router pod, and several router replicas were not tried.

**Check it.** Run agents through the proxy for at least ten minutes, then check three
things in the gateway's `/metrics` and the server's audit log:

1. Connection pinning. `yuzu_gw_heartbeat_session_mismatch_total` and
   `yuzu_gw_heartbeat_rejected_total{reason="no_connection"}` must not rise, and the summary
   log line must not report `connection_mismatch=`. A router that is not pinning shows as a
   steady rise of the first, and as agents that re-register every few minutes.
2. Attribution. `yuzu_gw_grpc_origin_ignored_total{reason=~"no_claim|bad_claim"}` must not
   rise on a proxied listener, and the `source_ip` of the server's gateway-path registration audit rows
   (`enrollment.token_consumed`) must equal each agent's own address, with no
   `origin_observed=false` on them. The server writes the gateway origin to the audit log
   only on that action, so this check needs agents that enroll with an enrollment token
   (new agents, or a test agent registered with a fresh token); a `Register` without a
   token leaves no row to read. A rise of `untrusted_source` means `sources` does not name
   the address the gateway sees (see [Origin counters](#origin-counters) below).
3. Churn. `increase(yuzu_gw_agents_connected_total[10m])` should be close to the number of
   agents that came up in that window, and `yuzu_gw_agents_current` should be steady. An agent
   count that sawtooths with a period equal to a proxy idle timeout is a proxy cutting idle
   connections (see "Idle timeouts" above and "Sizing the proxy and the gateway for a fleet"
   below); a count that falls once and stays down is a proxy or network fault, not churn.

Repeat after any change to the router's configuration or version.

#### Which topologies were tested

| Topology | Gateway listener `origin` | Status | Evidence |
|---|---|---|---|
| Agents reach the gateway directly | `transport` (default) | MEASURED | OKD acceptance run A (agents direct to the gateway), and the eunit wire tests |
| Router or HAProxy only, terminating TLS | `forwarded_for`, `trusted_hops => 0`, `sources` = the proxy | MEASURED for HAProxy 3.2.25 (run C, 50 agents, 10 minutes) and the stock OKD 4.21 router (run B; router HAProxy 2.8.10; HTTP/2 enabled, re-encrypt route, `Append` policy) | Real client address attributed for all 50 agents in both; a forged `x-forwarded-for` ignored |
| Router run from a custom HAProxy template | `forwarded_for` | MEASURED, not supported by Red Hat (knowledge-base solution 5381141) | Run F; treat as your own proxy |
| HAProxy `send-proxy-v2` in `mode tcp` | `proxy_protocol`, `sources` = HAProxy | MEASURED (run D, 50 agents, 10 minutes) | Real address attributed for all 50; a forged PROXY header from a non-listed peer ignored; a client with no header is closed after about 1 s |
| PROXY protocol from a generic sender | `proxy_protocol` | MEASURED against a synthetic relay only | `yuzu_grpc_origin_wire_tests` (eunit) |
| F5 only, TLS passthrough, PROXY protocol by iRule | `proxy_protocol`, `sources` = the F5's self IPs | UNTESTED: no F5 was available. See "F5" below | none |
| F5 in front of a router (the gateway sits behind the router) | `forwarded_for`, `sources` = the router; `trusted_hops => 0` if the F5 hands the client address to the router by PROXY protocol, `1` if the F5 inserts `X-Forwarded-For` itself and the router appends the F5's address | UNTESTED, INFERRED from the header rules | none |
| Both an F5 path and a router path reach the gateway | Two listeners on two ports, one entry per path, each with its own mode and `sources` | UNTESTED with a real F5; the port-override rule for two agent listeners is covered by eunit | `yuzu_gw_app_tests` |
| 2000 or more agents behind a router or HAProxy | as above | UNMEASURED. The largest run is 50 agents. | none |
| Several router replicas | as above | UNMEASURED. One single-node cluster and one router pod were tried. | none |

The runs above were one OKD 4.21.0-okd-scos.8 single-node cluster and one HAProxy 3.2.25
container, on 2026-10-09 and 10; the raw logs are with the pull request record, not in the
repository. Only the INFERRED and UNTESTED rows are claims about code paths, not about a
product. Do not treat a MEASURED row as a statement about another version of the same
product.

**F5 (UNVERIFIED).** The `proxy_protocol` mode expects the F5 to prepend a PROXY protocol
header (v1 or v2) carrying the real client address to every TCP connection it opens to the
gateway, before any TLS bytes, with the virtual server in TLS passthrough (no TLS
termination). This is done in an iRule on the F5; no iRule is given here because none has
been run against the gateway and a plausible-looking one that has not would be worse than
none. What the iRule must achieve is the contract above: one header per backend connection,
first on the wire, carrying the client's address and not the F5's own. Test it with a lab F5
before relying on it: register an agent that presents an enrollment token through the virtual server and check
that the `enrollment.token_consumed` audit row's `source_ip` is the agent's address and that
`yuzu_gw_grpc_origin_ignored_total{reason=~"no_claim|bad_claim"}` stays flat. Two F5 behaviours
to plan for: a health monitor that connects to the PROXY-protocol port without sending the
header is closed by the gateway after about a second and the pool member then reads down, so
monitor another port; and the self IPs the F5 connects from are what `sources` must list.

**The listener must also be reachable only from the proxy** (a firewall rule, a Kubernetes
NetworkPolicy). `sources` is defence in depth, not a substitute: the trust decision is
made on the TCP peer, so the strength of the attribution is the strength of who can reach
that port. The management listener is never proxied: the boot guard refuses a
network-reachable management listener whose `origin` is not `transport`.

#### Sizing the proxy and the gateway for a fleet

Only 50 agents behind a proxy were measured. Everything below for larger fleets is
arithmetic or the proxy vendors' guidance, not a measurement; test your own proxy at your
own scale before relying on it.

- **One backend connection per agent connection.** The supported proxy topology needs the
  proxy to open one connection to the gateway for each agent connection and keep it for the
  life of the agent's connection. Pooling many agents onto one backend connection is
  **unsupported**: the per-connection cap of 8 sessions (`max_sessions_per_connection`) and
  of 32 concurrent streams on the agent listener (`max_concurrent_streams`) would apply to all
  of them together, the ninth `Register` on that connection is answered `UNAVAILABLE`, and
  heartbeat admission cannot tell the agents apart.
- **Gateway file descriptors.** Plan for about 1.5 to 2 times the agent count plus 200:
  old and new connections overlap for a moment after a proxy idle cut. 2000 agents need
  about 4000 or more; 10000 agents about 20000 or more. A systemd unit with
  `LimitNOFILE=65536` holds to about 30000 agents; the gateway services in the shipped
  compose files set no `ulimits`, so add `ulimits: nofile: 131072` to the gateway service and check
  the **hard** limit in `/proc/1/limits` inside the container (the BEAM raises its soft limit
  to the hard one). The agent listener's `limits.max_connections => 60000` assumes about 65536
  descriptors, so raising the descriptor limit alone changes nothing at the ceiling: raise
  `max_connections` with it (keep about 5500 descriptors below the limit) or the listener
  still stops accepting at 60000.
- **HAProxy.** Each agent costs two sockets (client side and server side). Set the global
  `maxconn` to about 1.5 times the agent count, `ulimit-n` to at least `2 * maxconn + 100`,
  and do not set a `maxconn` on the `server` line below that; check `show info` on the
  stats socket for `Maxconn` and `Maxsock`.
- **OKD / OpenShift router.** `spec.tuningOptions.maxConnections` on the IngressController
  is shared by every route the router serves.
- **Idle timeouts above 180 s** on both sides (three times the agent's 60 s ping), and expect
  a herd: when the proxy cuts every idle connection at once, every agent reconnects within
  seconds (50 agents did in the runs above; thousands is unmeasured). The gateway asks for a listen
  backlog of 4096; raise `net.core.somaxconn` on the gateway host for fleets of 10000 or
  more, or the kernel caps it lower.

#### Origin counters

`yuzu_gw_grpc_origin_ignored_total{mode,reason}` counts calls on a proxied listener whose
claim was not used. The origin is resolved **per RPC stream**, so only a connection that
opens a stream is counted: an L4, TCP, TLS or PROXY-`LOCAL` health check opens none and is
never counted, and only an HTTP/2 health check that makes a call would be. Both labels
come from closed sets, and an address is never a label or a log field. The counters carry
no listener label.

| Reason | Meaning | What the call is attributed to |
|---|---|---|
| `untrusted_source` | The TCP peer is not one of the `sources`, so any claim was ignored. | The TCP peer. |
| `no_claim` | A trusted proxy sent nothing to read on a connection that went on to make a call: a PROXY `LOCAL` command, or no `x-forwarded-for` header. | No observation (empty; the server records `origin_observed=false`). |
| `bad_claim` | A trusted proxy sent something that is not usable: a PROXY header whose address family has no address (`UNSPEC`, unix), an `x-forwarded-for` with fewer than `trusted_hops + 1` entries, or a selected entry that is empty, longer than 64 bytes, or not a bare IP address (a port, brackets, a leading zero, `1.2.3`). | No observation. |

A steady `untrusted_source` rate means something other than the proxy is reaching the
listener (or `sources` is wrong): fix the network rule, not the counter. A steady
`no_claim` or `bad_claim` rate on a proxied listener means the proxy is not giving the
gateway an address it can use (HAProxy without `mode http`, a missing `option forwardfor`,
a PROXY `LOCAL` connection that goes on to make a call): the shipped alert rules
`YuzuGatewayOriginUnusable` and `YuzuGatewayOriginSourcesMismatch` fire on these two
conditions. `yuzu_gw_grpc_dropped_data_bytes_total{reason}` is the request bytes the layer
discarded in a state that must not run a handler (`extra_request_data`, `stream_ended`).

### Moving the agent edge to mutual TLS

Agent identity at the gateway is application-layer: the agent listener is **one-way
TLS**, encrypting the hop and authenticating the gateway to the agent, and a client
certificate is neither requested nor checked. The move to client certificates has three
stages. Only the first two exist in code today, and the second enforces nothing.

1. **One-way TLS (today, shipped).** `tls => #{..., verify => verify_none,
   fail_if_no_peer_cert => false}`. This is the shape in `sys.config.prod`.
2. **Request a certificate, enforce nothing (available now, configuration only).**
   `tls => #{..., verify => verify_peer, fail_if_no_peer_cert => false}` asks every client
   for a certificate and still serves agents that have none (an agent that has not
   enrolled yet has none). A handler can see the certificate the client presented
   (`yuzu_grpc:peer_cert/1` returns its DER, or `undefined`); no shipped handler reads it
   and nothing refuses a call because of it. A certificate that is presented but invalid
   (expired, wrong CA) still aborts the handshake under `verify_peer`, whatever
   `fail_if_no_peer_cert` says, so an agent with a stale leaf would be locked out: check
   that before using this stage on a fleet.
3. **Enforcement (not built; needs a design and its own ADR).** An `auth_fun` refuses
   every peer without a certificate, and the agents that have not enrolled have none, so
   enforcing certificates needs more than configuration: enrollment has to be separated
   from the enforced surface (a listener that serves only `Register`, and a per-listener
   method allow-list, which the layer does not have yet). The cryptographic agent
   identity work is tracked in #1292 and the design in #5578.

**Never put an `auth_fun` on the agent listener as it stands today.** It would refuse
every agent without a certificate and cut agent bootstrap fleet-wide, so boot refuses an
`auth_fun` on any listener that serves the agent service (`agent_pb` in `service_protos`, or the
AgentService as a key of `services`); a combined agent-and-management listener is covered.

How this interacts with a proxy: behind `proxy_protocol` the certificate still reaches
the gateway (TLS passes through the balancer), so stages 2 and 3 are possible. Behind
`forwarded_for` the router terminates TLS, so the certificate the gateway sees is the
router's and cannot identify an agent; the layer refuses `forwarded_for` together with
an `auth_fun` for that reason.

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
the address and port for the GatewayUpstream service. This port must match the
port of the `default_channel` endpoint in `{yuzu_gw, [{upstream_client, ...}]}` (see
[The upstream client](#the-upstream-client); `upstream_port` is read by nothing):

```bash
yuzu-server --gateway-upstream "0.0.0.0:50055"
```

> **Gateway origin-IP attribution (#1064, #1172).** On the gateway `ProxyRegister`
> path the server's transport peer is the gateway. The gateway therefore sets
> `RegisterRequest.gateway_observed_peer` itself on every registration, to the
> address it decided for the caller (the TCP peer, or the address a trusted proxy
> vouched for, see [Client addresses behind a proxy](#client-addresses-behind-a-proxy)),
> and discards whatever the agent put in that field; on a proxied listener whose proxy
> gave no usable address it sends the field empty, and the server then records
> `source_ip`=the gateway node and `origin_observed=false`. Otherwise the server records
> `source_ip`=that address and `gateway_ip`=transport peer. Behind a load
> balancer or router with no `origin` configured, the address is the balancer's and
> nothing flags it: configure `origin` to get the agent's. Upgrade every gateway: an
> older one still forwards the value the agent sent.

### What happens when the server restarts

This section covers a server process restart while a gateway stays up and its
agents stay connected to it. The agents do not notice. The route directory in
Postgres survives the restart, so the restarted server still resolves every
session and keeps acknowledging heartbeats and renewing leases; but its
in-memory registry is empty, so it lists those sessions in every
`BatchHeartbeatResponse` until it has rebuilt them (see
[BatchHeartbeat Message](#batchheartbeat-message)). A gateway that reads that
answer re-registers the listed agents upstream without operator action.
This needs a gateway that carries the reconcile (#1197); with an older gateway
the listing is ignored and the registry stays empty until the agents
re-register (the behaviour under "Without the reconcile" below). If the
gateway's circuit breaker opened during the outage, the verdict is dropped while
it is open; once the breaker has closed, the next verdict lists the agents again,
and because the server does not know most of that batch the gateway replays every
agent it holds (see "Several agents and a long outage" and "What starts a full
replay" below).
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

**Convergence window after a server-only restart.** Until the replay has
re-proxied an agent, the restarted server has no local session for it:
`yuzu_agents_connected` reads 0 and then ramps, the device list in
`/api/agents` and the dashboard fills in as agents are replayed, and
`YuzuAgentFleetDrop` can fire if the ramp outlasts its 2 minute window (expected
for a fleet of 10,000 or more; correlate it with the gateway
`Registration replay` INFO lines). Heartbeats are acknowledged and leases
renewed throughout, so nothing is reaped meanwhile and you must not restart the
gateway. The replay is paced by permits (#5695): the per-session guard is
`registration_replay_session_guard_ms` (default 10 s), and up to 24 `ProxyRegister`
replays run at once (`upstream_replay_concurrency`), so the rate is 24 divided by the
round trip: at 100 ms per call that is about 240 agents per second, and 10,000
agents take about 42 s (arithmetic; measured with a mocked server: 5,000 agents in
10.7 s at 50 ms per call; before #5695 the drip sent one at a time with a 20 ms gap:
about 8.3 agents per second and 1,200 s; the table under "Several agents and a long
outage" gives the older figures),
and the queue holds `registration_replay_queue_max` (10,000) entries. Each
response lists at most 4,096 ids, so a larger fleet converges over several
rounds. Scope targeting and command dispatch reach agents through the directory
fallback during the window; the fleet views that read only the local registry
do not.

**What you should see** (new gateway and new server, one core replica):

| Where | Level | Line | Meaning |
|---|---|---|---|
| gateway | INFO | `Registration replay: heartbeat verdict named N session(s); queued Q, not local L, already queued A, within guard G, queue full F` | One verdict was handled. Logged at INFO when Q is at least 1, at DEBUG otherwise. It carries counts only, no session ids. |
| gateway | DEBUG | `Registration replay: re-proxied <agent> (adopted session <id>)` | One agent was re-proxied by the replay drip, one line per agent. |
| gateway | INFO | `Flushed N heartbeats in M chunk(s)` | A flush needed more than one chunk (about 3 MiB each), which is expected after a long server outage. It is logged at INFO only when M is greater than 1; a flush of one chunk is logged at DEBUG. The line carries counts only: no log line or metric shows the size of a chunk. |
| server | INFO | `[gateway] ProxyRegister succeeded: agent=..., session=<the pre-restart session id>` | The server accepted the replay and relearned the session under the id the agent already holds. |
| server | DEBUG | `[gateway] ProxyRegister: adopted presented session ... (store-confirmed=true)` | The presented session was adopted; `store-confirmed=true` when the routing directory confirmed it. |
| gateway | WARN | `Circuit breaker: OPEN (will probe in <ms>ms)` | The upstream circuit breaker opened. A verdict that arrives while it is open is dropped and counted in `yuzu_gw_heartbeat_verdict_dropped_total{reason="circuit_open"}`; the matching line `heartbeat verdict named N session(s) while the circuit is open; dropped` is DEBUG, so at the default log level you see the counter and this warning, not that line. While the breaker is open, the whole `/readyz` answer is 503 `not_ready` (`circuit_breaker` is false in its checks), and the shipped guidance is that a load balancer probes `:8081/readyz`, so an open breaker can take this node out of rotation (INFERRED from `yuzu_gw_health.erl`; not run). Wait: do not restart the gateway, unless the repeating-failure signature in the next two rows applies. The replay runs after the breaker goes half open (INFO `Circuit breaker: open -> half_open (allowing probe RPC)`; `/readyz` reads ready again from that point), and the probe closing it logs INFO `Circuit breaker: half_open -> closed (probe succeeded)`. |
| gateway | WARN | `Circuit breaker: half_open -> open (probe failed, increasing backoff)` | The probe failed, so the breaker is open again for a longer time (the backoff doubles up to the cap). The probe is either a call-path RPC or, when notifications are held, the head held notification (see "Stream Status Notification"); a notification probe that fails as a breaker failure also logs a `Failed to notify stream status for <agent>` WARN (see that row), and a probe worker that is killed without a result logs a different WARN instead (described in the same row). Read the reason in that line and the `code` label of `yuzu_gw_upstream_rpc_errors_total{rpc_name="notify_stream"}` first (a probe killed at its deadline has neither: it logs the `did not answer within` line (later in this table) instead, and does not move that counter). A transport reason (`timeout`, `econnrefused`, a TLS handshake error) means the server is down, frozen or unreachable from the gateway: escalate to the server and check that it is healthy and reachable. Restarting the gateway does not help and reconnects every agent it holds. The SAME agent id in that line at every cycle is expected in this case too, because a failed probe goes back to the head of the queue (OBSERVED on a rig: the same head was probed again at every half open period while the server stayed down), so a repeating id alone does not identify the cause. A probe whose outcome is neutral (a local encode failure, or a server status that means the request itself was wrong) does not produce this line: see the next row and the `Failed to notify` row. |
| gateway | WARN | `Evicted held stream status notification for <agent>: it cannot be encoded (<Class>:<Why>); the circuit breaker is not affected` | A held notification that cannot be encoded inside the gateway is not a probe failure, because the request never left it: a local encode exception does not move the breaker at all (see "Known limits"), so it does not produce the `half_open -> open` line. The signature is `Upstream RPC NotifyStreamStatus raised <Class>:<Why>` (for example `error:badarg`) with `yuzu_gw_upstream_rpc_errors_total{rpc_name="notify_stream",code="encode"}` rising, followed, when it was the probe, by this eviction line. The breaker state does not change, the entry is evicted from the store, and the next held notification is probed at once. Nothing blocks behind it and `ProxyRegister` and `ProxyInventory` are not refused because of it (INFERRED from the code and unit tests, not run on a rig). |
| gateway | WARN | Reading an eviction or a `raised` line | What an eviction means for the agent: an evicted `CONNECTED` leaves the agent acknowledged by the server but not dispatchable until it reconnects, and an evicted `DISCONNECTED` leaves it looking online in the server's registry until its route lease expires. Every field of a notification is bounded, sanitised or minted by the gateway or the server before it is held, so a repeating eviction points at the gateway or its encoder, not at that agent. The agent id appears only in the eviction line: the `raised` and `Register refused` lines carry none, so for those discriminate by the `code` label of `yuzu_gw_upstream_rpc_errors_total`, by the `<Class>:<Why>` reason in the line, and by the ` (N similar line(s) suppressed since the last)` suffix, and treat `code="encode"` as a local encoder fault (see "Known limits"). A gateway restart is not the remedy, because it removes only the held entries and reconnects every agent the node holds. An `Upstream RPC ... raised` line with no eviction line comes from a call-path RPC or from an ordinary notification worker. For a call-path RPC (and for a probe) an exception raised by the request encoder does not move the breaker, whereas any other exception out of the call, every transport error and timeout, and every server status outside the request-fault set (3, 5, 6, 9, 11) is a breaker failure. An ordinary notification worker feeds the breaker by the same rule, but only while the breaker is closed and still in the generation the worker started in. Whatever the breaker state, an encoder exception or a request-fault status retires its entry as lost (`yuzu_gw_upstream_notify_lost_total{reason="rejected"}`), and any other failure puts the entry back at the head of the store to be retried (`yuzu_gw_upstream_notify_requeued_total`); either way it logs `Failed to notify stream status` (next row) (INFERRED from the code and unit tests, not run on a rig). |
| gateway | WARN | `Failed to notify stream status for <agent>: <reason>` | One `NotifyStreamStatus` call failed. It is logged for an ordinary notification worker and once for every failed (not killed) breaker probe that is a notification. A probe worker that is killed without a result does not log this line: it logs `Notify probe worker for <agent> exited without a result: <reason>` instead (see the next row), and a probe killed at its own deadline logs the `did not answer within` line instead of either (the row after next) and does not increment `rpc_errors_total`. For an ordinary worker it means that one agent's `CONNECTED` or `DISCONNECTED` did not reach the server on that attempt. It is held again at the head of the store and retried, whatever the breaker state (`yuzu_gw_upstream_notify_requeued_total`; if a newer notification for the same session was held meanwhile, that one is sent instead and the old one is counted in `notify_coalesced`). While the breaker is closed, and the worker was started in the breaker's current generation, the failure counts against the breaker like a failed call, so a server that keeps failing gets at most about the failure threshold (5) of retries, plus the sends already in flight, before the breaker opens and the half open probe takes over. Two outcomes are not retried and do not move the breaker: a server status that blames the request (3, 5, 6, 9, 11) and a request that failed to encode in the gateway; both are counted in `yuzu_gw_upstream_notify_lost_total{reason="rejected"}` (see the `at_capacity` row for the effects on the server). During a planned stop's last gasp a failed send is not retried (`reason="shutdown"`). None of these is counted in `notify_dropped` (INFERRED from the code and unit tests, not run on a rig). For a probe that failed as a breaker failure (a transport error, a timeout, a server status that counts, or an exception out of the client) it is followed by the `half_open -> open` WARN above and the notification stays held. A probe with a neutral outcome has no `half_open -> open` transition: the breaker stays half open until a real RPC or probe decides. A probe whose request cannot be encoded in the gateway logs the eviction WARN described two rows up instead of this line, and the entry is evicted; a probe answered with a request-fault status (3, 5, 6, 9, 11; the server cannot return one for `NotifyStreamStatus` today) logs this line and the notification is retired, not requeued. The reason is the call's error: an `internal` error with the message `timeout` (the server did not answer within 5 s: frozen or overloaded), `econnrefused` (nothing is listening), a TLS handshake error (see `yuzu_gw_upstream_tls_handshake_failures_total`), or an `rpc exception <Class>:<Why>` (an exception inside the call; a request that failed to encode in the gateway is one of these and is counted as `code="encode"`, and for it the breaker is not touched, an ordinary worker loses the entry and a probe evicts it, see the previous row). The line names the agent id only, never a session id or a peer address. OBSERVED on a rig: 10 lines, one per stopped agent, when 10 agents were stopped while the server was frozen for more than 5 s with the breaker closed, and one line per failed probe in the failing-probe runs. |
| gateway | WARN | `Notify probe worker for <agent> exited without a result: <reason>` | This WARN is logged when the probe worker is killed and so returns nothing; it carries the agent id and a redacted reason only (never the notification), and is followed by the `half_open -> open` WARN and a requeue of the notification. On the rig run that killed a probe worker no such line existed, because the WARN was added afterwards; it is covered by unit tests and was not re-run on a rig (INFERRED from the code). |
| gateway | WARN | `Notify probe worker for <agent> did not answer within <ms>ms and was killed; the notification is held again` | The half-open probe did not report within `notify_probe_timeout_ms` (default 15000 ms), so the gateway killed the worker and failed the probe: the notification goes back to the head of the queue and, while the breaker is still half open under the same generation, the `half_open -> open` WARN follows with the doubled backoff. One line per timeout. A second line can follow in the same half-open cycle when an earlier generation's probe times out after the breaker has re-entered half open (a call-path RPC failure reopened the breaker while that probe was out, and the deadline is longer than the breaker's open interval): that late timeout leaves the breaker as it is and the next probe is sent in the same cycle. The line carries the agent id (control characters replaced) and the configured milliseconds, never the notification. It means the upstream did not answer in time, or the connection attempt did not complete in time: check that the server is healthy and reachable, as for the `half_open -> open` row. A probe killed at its deadline increments neither `yuzu_gw_upstream_rpc_errors_total{rpc_name="notify_stream"}` nor logs `Failed to notify stream status` (the worker is killed before it reports), so do not look for either. The signals are this WARN, the `half_open -> open` WARN with its `Circuit breaker: OPEN (will probe in <ms>ms)` line, `yuzu_gw_upstream_circuit_transitions_total` cycling through open, half open and open, and a high `yuzu_gw_upstream_notify_pending`. A WARN that repeats while the server is healthy points at RAISING `notify_probe_timeout_ms` (see "Upstream client tuning") The notification may have reached the server before the kill, so it can be sent again (at least once). Covered by unit tests with a mocked client; not run on a rig. |
| gateway | WARN | `Server did not record the <event> stream status notice for <agent> (acknowledged=false); sending it again in <ms> ms` (also `...; giving up after <ms> ms (<why>)` and `... during the planned-stop flush; not sent again`) | The server answered a `NotifyStreamStatus` with `acknowledged=false`: it did not record the notification, so the gateway holds it and sends it again (see "When the server does not record a notification"). At most one line a second; the next line says how many were suppressed. A line now and then is a session the server no longer knows or that a newer registration replaced; a steady stream, with `yuzu_gw_upstream_notify_unacked_keys` above 0, means the server is refusing to record sessions (`YuzuGatewayNotifyUnacknowledged`). `giving up` names a `DISCONNECTED` past `notify_unacked_disconnected_window_ms` or a full retry set. Covered by unit tests with a mocked client and the scale suite's `unacknowledged` case; not run against a real server. |
| gateway | WARN | `Register refused: the agent id is empty or longer than 256 bytes (size <N> bytes)` | A `Register` carried an agent id that the server would refuse (empty, missing, not a binary, or over 256 bytes) and was answered `INVALID_ARGUMENT` at the gateway edge with no upstream call; the circuit breaker is untouched. The line carries the byte size (0 for a value that is not a binary) and no agent id, so it cannot name the sender. At most one line per second, with a ` (N similar line(s) suppressed since the last)` suffix, so the number of lines is not the number of refusals: the counter `yuzu_gw_register_refused_total{reason="agent_id_length"}` counts every one, and it and the suffix are the two edge-refusal signals. A few refusals point at one broken or misconfigured client; a steady rate means clients are sending agent ids outside the bound. No gateway action is needed, because these cannot move the breaker (INFERRED from the code and unit tests, not run on a rig). |
| gateway | WARN | `Upstream Register failed: <reason>` (also `Upstream ReportInventory failed: <reason>` and `Upstream RPC <Method> failed: <Status> <message>`) | An upstream `ProxyRegister` or inventory call failed and the agent's request failed with it; the agent retries with its own backoff. The reason is `circuit_open` (the breaker is open), a server status, a transport reason, or `rpc exception <Class>:<Why>`. These lines are rate limited to one per second per kind, and the next line ends with ` (N similar line(s) suppressed since the last)`, so the number of lines is not the number of failed requests: during a genuine outage the per-event signal is the unlimited `Circuit breaker:` lines and the suppressed-count suffix, not a line per `Register` (a `circuit_open` rejection never reaches the call, so `yuzu_gw_upstream_rpc_errors_total` does not count it). `Upstream RPC <Method> failed: <Status> <message>` is limited only for the five request-fault statuses (3, 5, 6, 9, 11); the same line for any other status is not limited (INFERRED from the code and unit tests, not run on a rig). |
| gateway | WARN | `Upstream RPC <Method> raised <Class>:<Why>` with `yuzu_gw_upstream_rpc_errors_total{code="encode"}` rising | The gateway's own request encoder failed, so the request was never sent and the breaker is untouched (`error:badarg` is a field that is not valid UTF-8; `error:request_too_large` is a request over 4194304 bytes). A few lines are expected now and then, one per request the encoder rejected. A STEADY rise with every `Register` answered `INTERNAL` (`Upstream registration failed: {internal,<<"rpc exception <Class>:<Why>">>}`), the breaker CLOSED and `/readyz` ready is a systematic local encoder fault: nothing in the breaker or in readiness shows it, so this row is the discriminator. Read `<Class>:<Why>` first; if every agent is affected, escalate and fix the sender or the build; rolling back to the previous gateway build is possible but re-exposes the defect this change fixed (a request the gateway rejected locally counting as an upstream failure that can open the circuit breaker; see the security note in the release changelog), so prefer fixing the sender. A gateway restart does not help and reconnects every agent the node holds. The shipped `YuzuGatewayUpstreamErrors` alert fires only above 0.1 errors per second and has no `code` filter, so a slow stream of encode failures does not reach it; `YuzuGatewayUpstreamEncodeErrors` (about ten increases of `code="encode"` in 10 minutes, `increase()` being extrapolated, so a lone rejected request stays quiet; read the rate, not the firing alone) is the alert for this row. The line carries no agent id, so identify the cause by the `<Class>:<Why>` text and the `rpc_name` and `code` labels. With `code="exception"` instead, an exception out of the client or transport counts against the breaker on the `Register` and `ProxyInventory` call paths, on a stream-status notification (the half-open probe, and an ordinary notification worker while the breaker is closed and in the worker's generation; either way the notification is held again and retried) and on a registration replay; a guardian forward and the heartbeat buffer's own flush do not feed the breaker (INFERRED from the code and unit tests, not run on a rig). |
| gateway | CRITICAL | `Refusing to start: the cluster id (<source>) cannot be represented as UTF-8 (a code point above 16#10FFFF, a surrogate, or bytes that are not UTF-8). Set YUZU_GW_CLUSTER_ID, or cluster_id in sys.config, to a name made of valid Unicode characters.` | The gateway did not start: `<source>` is `YUZU_GW_CLUSTER_ID` or `the cluster_id application setting`, and the application start returned `{error, {invalid_cluster_id, env}}` or `{error, {invalid_cluster_id, app_env}}`. The value is never logged. Check the named source: for `sys.config`, a plain binary `<<"...">>` that holds a non-ASCII character is the usual cause (one holding code points above 255 is truncated to bytes and passes only if those bytes happen to be valid UTF-8), so write the name as a string (`"Z\x{FC}rich"`) or as `<<"Z\x{FC}rich"/utf8>>`; for the variable, check that the value is valid UTF-8 text. Correct it and start the gateway again; a restart without the fix will refuse again (see the `cluster_id` paragraph under "Configuration"; INFERRED from the code and unit tests, not run on a rig). |
| gateway | metric | `up == 0` for the gateway job, `YuzuGatewayDown`, or a unit that stays `failed` after a `cluster_id` refusal | The refusal is a boot failure, so the supervisor decides what you see. Under systemd, `deploy/systemd/yuzu-gateway.service` sets `Restart=on-failure`, `RestartSec=5`, `StartLimitIntervalSec=60` and `StartLimitBurst=3`: the unit is started at most three times in 60 s (the initial start plus two restarts) and is then left `failed`, which is reached within roughly 15 to 20 s of the first start (derived from those values, not measured). The unit's journal tag is `yuzu-gateway`, so `journalctl -t yuzu-gateway` shows the `Refusing to start` line (it names the source and never the value). Under the reference compose files the gateway has `restart: unless-stopped`, so it loops without ever being marked failed; read `docker logs` for the same line. In both cases the metrics endpoint is down, so Prometheus sees `up == 0` and `YuzuGatewayDown` fires after its 2 minute `for` (shipped in `docs/prometheus/yuzu-alerts.yml`). Fix the named source and start the unit again (`systemctl reset-failed yuzu-gateway` first if the start limit was hit). Whether the process exits with a non-zero status on this refusal, so that systemd counts it under `Restart=on-failure`, was not run; check `systemctl status yuzu-gateway` on your first rollout (INFERRED from the unit file, not run on a rig). |
| gateway | WARN | `ENV override: YUZU_GW_CLUSTER_ID cannot be represented as UTF-8; ignoring it (the value is not logged)` | The variable could not be converted. It is not applied, and because the variable is still set the gateway then refuses to start with the critical line above. |
| gateway | WARN | `Registration replay aborted: circuit open (N agent(s) not yet re-proxied)` | The breaker opened while the drip was running. The queue is dropped; the agents come back on a later verdict once the breaker has closed (a breaker recovery replays nothing by itself since #5695). |
| gateway | WARN | `Registration replay aborted: registry unavailable (N agent(s) not yet re-proxied)` | The gateway's registry process was down when the drip popped an entry, so nothing queued could be re-verified and the queue was dropped. This abort disconnects no agent. INFERRED from the code (not tested): a registry that died has lost its tables (see [Heartbeat admission](#heartbeat-admission)), so a later verdict finds no local session for these agents and counts them `not_local`; they are not listed again into the replay. They come back only through their own `NOT_FOUND` re-register path, which released v0.13.0 and v0.14.0-rc6 agents do not complete (see "Agent dependency" below). |
| gateway | WARN | `Registration replay: <agent> failed: <reason>` | A replay `ProxyRegister` failed. It counts as a failure for the shared circuit breaker (see "Replay failures feed the shared circuit breaker" below). |
| gateway | metric | `yuzu_gw_registration_replay_triggered_total{trigger="server_lost_state"}` rising | A heartbeat verdict showed that the server does not know most of the sessions of a batch, and the gateway replayed every agent this node holds (see "What starts a full replay" below). Expected once after a server restart. Rising again and again with the server up means the server keeps forgetting or refusing the replayed sessions: read the server's `ProxyRegister` lines. The `breaker` value of this label is no longer emitted (#5695): a breaker recovery replays nothing by itself. |
| gateway | metric | `yuzu_gw_heartbeat_coalesced_total` rising | Newer heartbeats of a session are replacing older buffered ones, one at a time. Expected during a server outage: heartbeats pile up between failed flushes and are merged, so the buffer stays at one entry per session. No action. The server's `yuzu_heartbeats_received_total{via="gateway"}` falls short of the number of heartbeats the agents sent for the same reason; that is not a loss of agents. |
| gateway | metric | `yuzu_gw_upstream_notify_pending` non-zero | Stream-status notifications are held (#4632). Check the breaker first: while it is open the entries are held by design and this is the common case (the `Circuit breaker:` lines above, `yuzu_gw_upstream_circuit_transitions_total`, and `/readyz`). One entry is sent as the probe when it goes half open and the rest drain in first in first out order once the probe succeeds (OBSERVED on a rig: 10 held entries waited 55 to 59 s, the probe closed the breaker, and the pending gauge was back at 0 about 2 ms after the half open transition). If the breaker is closed and the gauge stays above 0 for longer than a connect burst, read `yuzu_gw_upstream_notify_inflight` (at most 10; a value stuck at 10 means the workers are slow or stuck) and `yuzu_gw_upstream_rpc_errors_total{rpc_name="notify_stream"}`, whose `code` label separates a timeout (the server is slow or frozen) from `encode` (a request that failed to encode in the gateway: local, no breaker effect), from `exception` (an exception out of the client or transport) and from a transport error. A short rise is normal during a cold `Subscribe` wave: the gauge counts held keys and falls as the 10 workers drain them first in first out (INFERRED from the code; OBSERVED on a rig: 100 ms samples peaked at 660 to 762 held keys for 1000 agents (the one event-level trace of a run measured a maximum of 989) and at 1850 and 1906 for 2000 agents, and the gauge was back at 0 within about 0.3 s of the last `Register`, so a one second scrape does not see such a burst and a faster sampler is needed). The 3 a.m. diagnostic with no other tooling is `sys:get_status(yuzu_gw_upstream)` from a remote shell on the node: the state is shown redacted, with `cb_state`, `notify_pending_len` (a count) and `notify_probe_held` (whether a probe is out), and no session ids or addresses (INFERRED from `format_status`, not run on a rig). An agent reconnect recovers one agent whose notification was lost; a held notification that can never be encoded does not hold the queue: as the half open probe it is evicted with a WARN, and with the breaker closed an ordinary worker loses it and logs `Failed to notify stream status` (see the `half_open -> open` row). Both gauges describe the current upstream client process only: after it restarts they start at 0, held entries are gone, and workers of the old process are not counted. |
| gateway | metric | `yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}` rising | The pending store was at its cap and a notification for a new key was lost at admission (#4632): a new key is admitted only while the held keys plus the key of a half open probe in flight stay below `notify_pending_max`. Each lost notification can leave one agent acknowledged by the server but not dispatchable until it registers again. Find out why so many distinct keys are held (a connect storm with the breaker open, or a server that answers too slowly for the 10 workers), or raise `notify_pending_max` in the `yuzu_gw` section of `sys.config` (read at start; a gateway restart disconnects every agent it holds, see "Upgrade day" above). The series has no agent label, so the affected agents cannot be listed from the metric. The counter does not include a notification lost after admission (a failed or killed worker, or a gateway stop with entries held). A lost `DISCONNECTED` has a different effect from a lost `CONNECTED`: the agent is not undispatchable, it looks online. When the server was only paused, its registry kept listing the stopped agent as online (OBSERVED on the previous build: all 10 stopped agents were still online 20 minutes after the server resumed; a server restart rebuilds the registry and does not list them). Its route row stays routable until the 90 s lease expires (OBSERVED after a server kill and restart with the `DISCONNECTED` requests lost: 30 routable rows for 20 live agents 51 s after the restart, 20 routable and 10 without a lease at 141 s), and the server's route reaper tombstones it at about 5 minutes and deletes it at about 10 minutes (OBSERVED at 282 s and 582 s after the server resumed, on the previous build). A command sent to such an agent in the meantime goes to a stream that no longer exists (INFERRED). |
| server | metric | An agent is acknowledged by the server (heartbeats accepted, `agents.online`) but commands to it fail with `503 no agent connected` | The second branch of #4632: the server knows the session but its dispatch placement was not published, because the `CONNECTED` notification was lost or refused. Read the server counters `yuzu_server_gateway_route_desync_total{op="notify_stream_status",outcome="unknown_session"}` (the notification named a session the answering replica does not hold), `{op="notify_stream_status",outcome="stale_connected_session"}` (a `CONNECTED` for a session that was no longer the current one) and `{op="deregister",outcome="session_mismatch"}` (a `DISCONNECTED` for a session that was already superseded; expected to rise a little when held `DISCONNECTED` notifications flush after an outage). After a server restart, `{op="notify_stream_status",outcome="unknown_session"}` also rises by about the number of notifications that were held: the held entries flush when the breaker closes, before the registration replay has re-registered the sessions on the new server, so the server answers each with `unknown_session` (OBSERVED on a rig: +10 for 10 held, with and without TLS). That rise is expected, not a fault; agents with a live stream converge through the replay's re-announce (INFERRED from the code). Restarting the agent service recovers an agent (OBSERVED earlier for any agent). The 90 s route lease is how long the durable row stays valid after the last renewing heartbeat; it is not an expiry guarantee for the server's in-memory belief about a session, which can last until that agent registers again on that replica (INFERRED from the code, not run). Limit, stated plainly: with several core replicas, if replica A still holds an old session of an agent while replica B registered a newer one, A can accept a late `CONNECTED` for the old session into its own in-memory registry; the durable route update refuses it, but the in-memory publication is not undone. No gateway-side change closes that case (INFERRED from the code, not run). |
| gateway | metric | `yuzu_gw_heartbeat_buffer_dropped_total{reason}` rising | The buffer is under pressure, typically after a long server outage. `snapshot_evicted`: older snapshots were dropped to stay under `max_heartbeat_buffer_bytes`, oldest first. `buffer_full`: the buffer held `max_heartbeat_buffer` sessions and a heartbeat of a new session was dropped, or it was still over `max_heartbeat_buffer_bytes` with no snapshot left and its oldest whole session was dropped. `snapshot_oversize`: one heartbeat larger than about 3 MiB was sent without its snapshot (see "Known limits" below for the agent side). `heartbeat_oversize`: a heartbeat still larger than about 3 MiB after its snapshot was removed, or with more than 512 status tags, or with a status tag key or value over about 64 KiB or more than about 256 KiB of tag bytes in total (checked before the UTF-8 repair, so such a heartbeat costs no repair work), lost all of its status tags and was forwarded without them. `heartbeat_invalid`: a heartbeat with a status tag that was not valid UTF-8 was forwarded with the invalid bytes replaced by replacement characters. The reason also counts tags removed because a tag was not a binary and a heartbeat dropped for a bad or empty session id (see "Heartbeat Batching"). `chunk_rejected`: one heartbeat that the server rejected with a non-transient status (for example `RESOURCE_EXHAUSTED`) was dropped so that it does not block newer heartbeats. `heartbeat_oversize` and `heartbeat_invalid` mean an agent, or a plugin on it, sent oversized or invalid status tags: only the tags of those heartbeats are lost or repaired, and liveness is unaffected because the heartbeat itself is forwarded and the session keeps renewing its lease. `chunk_rejected` means the server refused one heartbeat, which is lost; the agent sends the next on its own interval. The metric has no agent label, so identify the agent from the gateway log or debug log if one names it, and upgrade or fix that agent or the plugin that produces the tags; no other action is needed. Transient server trouble (server unreachable, timeouts) does not lose heartbeats: they stay buffered. The data lost for the first three reasons is only older heartbeat state, which the agents refresh on their own interval. No action unless `buffer_full`, `snapshot_oversize` or `snapshot_evicted` keeps rising after the server is back; if it does, check that the server is reachable and answering `BatchHeartbeat` (`yuzu_gw_upstream_rpc_errors_total{rpc_name}`), and consider raising `max_heartbeat_buffer_bytes` or `max_heartbeat_buffer` if your fleet is larger than the defaults assume. Do not restart the gateway for this: a restart disconnects every agent the node holds. |
| gateway | metric | `yuzu_gw_session_limit_rejected_total` rising | A `Register` or `Subscribe` was refused because one gRPC connection already holds `max_sessions_per_connection` agent sessions (default 8; see "Per-connection session cap" for what counts). A stock agent holds one session per connection (INFERRED), so a rise means an L4 balancer, forwarder or client is carrying several agents on one connection (see "Per-connection session cap" under Configuration). A refused `Register` is answered `UNAVAILABLE` (14); a refused `Subscribe` is also answered `UNAVAILABLE` (14) and is counted the same. The agent retries either way. If the topology is legitimate, raise the key in `sys.config`; the key is read once when the registry starts, so the change needs a gateway restart, which disconnects every agent the node holds, so plan it. The metric has no agent label. A refused `Register` leaves nothing on the server and no row on the gateway. Rows of a connection that closed stay counted for the dead connection key only, which no new connection uses, until `dead_connection_grace_ms` (default 15 s) has passed, so a reconnecting client is not refused because of them. |
| gateway | WARN | `Register failed: registry_unavailable` | The agent was answered `INTERNAL` (13) "Registration failed: registry unavailable". The gateway's registry process could not be reached for this `Register`: its table is missing, a call timed out, or the registry restarted and lost the row (see the `Registration replay aborted: registry unavailable` row). This line no longer covers a superseded `Register` (see the next row). The agent registers again with its reconnect backoff (read from the agent code). A sustained run of lines is not expected: check `/readyz` and the registry process. |
| gateway | INFO | `Register superseded by a newer registration` | Two `Register` calls of one agent id overlapped on one connection and the newer one committed first. The older one was answered `UNAVAILABLE` (14) and left no row; the registry is healthy. No action: the agent retries a non-OK `Register` with its reconnect backoff (read from the agent code). An occasional line is expected; a sustained run would mean an agent or forwarder keeps repeating `Register` for one agent id on one connection (INFERRED from the code, not observed). |
| gateway | WARN | `mgmt-plane peer rejected: <reason> (CA-issued cert is not authorization to command the fleet — see mgmt_peer_pins)` | A management-listener (`:50063`) stream was refused `UNAUTHENTICATED` by the SPKI pin (#1422). `<reason>` is one of the closed set counted on `yuzu_gw_mgmt_auth_rejected_total{reason}` (`pin_mismatch`, `missing_server_auth_eku`, `no_pins_resolved`, `no_pins_configured`, `bad_peer_cert`, `bad_pin_config`, `internal_error`); no certificate contents are logged. At most one line per reason per second (any holder of an install-CA certificate that reaches the port can provoke one per stream, N4); a line that follows suppressed ones ends `(N similar line(s) suppressed since the last)`. The counter counts every rejection; read it, not the log, for how many there were. A `pin_mismatch` burst right after the server rotated its leaf that stops within `mgmt_pin_refresh_ms` is the rotation window, not an attack; the server does not retry those streams, so the commands it forwarded in that window failed as `gateway_unauthenticated` (see [Certificate rotation and expiry](#certificate-rotation-and-expiry)). |
| gateway | WARN | `mgmt_peer_pins: the certificate at <path> cannot be read or is not a PEM certificate; it pins nothing until it is fixed (fail closed)` | The pin watcher (`yuzu_gw_mgmt_pins`) could not stat, read or parse a `{cert_file, Path}` pin that has never been read since the gateway started. That entry admits nothing until the file is readable and holds a certificate (picked up within `mgmt_pin_refresh_ms`); with no other pin resolved every management stream is refused `no_pins_resolved`. One line per change of state, not per stream. |
| gateway | WARN | `mgmt_peer_pins: the certificate at <path> cannot be read or is not a PEM certificate; the key last read from it stays pinned until the file is readable again (fix the file; replace it with a different certificate to change the pin)` | The same failure on a pin file that was read before. The key last read stays pinned, so commands still flow; `yuzu_gw_cert_file_readable{role="mgmt_peer_pin"}` reads 0 and `YuzuGatewayMgmtPinUnresolved` fires after 2 minutes. Fix the file before the server's next rotation, which would otherwise be refused. Deleting the file does not withdraw the pin. |
| gateway | INFO | `mgmt_peer_pins: the certificate at <path> is readable again; the pinned key is unchanged` | A pin file that had failed is readable again with the key already pinned. No action. |
| gateway | NOTICE | `mgmt_peer_pins: the certificate at <path> changed; the new key is pinned` | The pin watcher picked up a rotated server leaf and set `yuzu_gw_mgmt_pin_rotated_timestamp_seconds`. Management streams made with the old leaf are refused from now on (`pin_mismatch`). |
| gateway | WARN | `certificate expiry refresh failed: <class>:<reason>; the expiry gauges keep their last values` | The expiry refresh on the pin watcher's tick raised. The pins are unaffected; the expiry and readable gauges stop updating until it succeeds. Not expected: collect the log line and report it. |
| gateway | WARN | `gateway grpc handler <Method> failed: class=<class> at <frame>` | A service handler raised, and the call was answered `INTERNAL` (13). The line names only the method, the exception class and the top stack frame, never a request, headers or the exception term. At most one line is written per second per node (`{yuzu_gw, grpc_runner_warn_interval_ms}`, default 1000, `0` logs every failure, an invalid value reads as 1000 silently and one above 3600000 as 3600000); a line that follows suppressed ones ends `(N similar failures not logged since the last line)`. The number of failed calls is not in the log: it is in the status the calls were answered with. |
| gateway | WARN | `gateway grpc: a <tag> message arrived for stream <id>, which had already ended; dropped` (or `gateway grpc: a process whose stream had already ended exited (<tag>)`) | A message for a stream that had already ended reached its connection: a handler's response frame or status, or the stream's deadline timer, that lost a race with the client resetting the stream. Expected now and then; harmless (the message is dropped). Cowboy used to write one such warning per stream, with the whole message (a response body); the gateway now writes at most one of each kind per second for the whole node (not per connection: a registration storm against a slow server ends one timed-out `Register` per agent connection, each with a late status, and wrote about 15,000 such lines at 25,000 agents when the limit was per connection), with the message's tag only, and a line that follows suppressed ones ends `(N similar line(s) not logged since the last)`, which counts every connection's. A steady stream of them on the management listener means the server is resetting many calls: check for a server restart or a mass cancel, and see the `max_cancel_stream_rate` note under "gRPC listeners"; on the agent listener during a reconnect storm it means agents are giving up on `Register` (see `yuzu_gw_upstream_permit_wait_seconds`). |
| gateway | INFO | `Upstream channel <name> connection <n> down (<word>); retrying in <ms> ms` | One of the channel's connections to the server went down or could not be opened; the channel reopens it after the delay (100 ms doubling to 5 s, with up to 20% jitter). `<word>` is a socket error such as `econnrefused` or `closed`, a TLS alert name, or `bad_tls_options`. A call made while no connection is up and none is connecting fails at once with the last such word (see [The upstream client](#the-upstream-client)); the circuit breaker counts it. One line per failed attempt, so a server that is down for a minute writes a line per connection every 5 to 6 s once the delay has reached its cap. Expected while the server restarts; a persistent TLS alert word means the certificate, the CA or the hostname is wrong (see the runbooks in [Gateway upstream peer authorization](server-admin.md#gateway-upstream-peer-authorization)). Read from the code, not run. |
| gateway | CRITICAL | `Refusing to start: the upstream channel configuration {yuzu_gw, upstream_client} is unusable (<Why>)` | `<Why>` names the shape of the first defect (`bad_client_config`, `bad_channel`, `bad_endpoint`, `bad_host`, `bad_socket_options`), never a value. Fix that entry; the pre-flight in [Upgrading](upgrading.md#the-upstream-channel-moves-to-upstream_client--breaking) finds it offline. |
| gateway | CRITICAL | `Refusing to start: the upstream channel uses TLS (https) WITHOUT {verify,verify_peer} and a {cacertfile,...} of its own` | At least one `https` endpoint has no `verify_peer`, or no `cacertfile` / `cacerts` of its own (a missing CA means the operating system's CA store would be trusted). Add both to every `https` endpoint; `YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1` is dev/CI only and makes the gateway log a warning at every boot. |
| gateway | CRITICAL | `Refusing to start: the upstream channel <name> lists both plaintext (http) and TLS (https) endpoints` | One channel mixes schemes, so some calls would travel unencrypted. Give the channel one scheme (two channels cannot help: only `default_channel` is called). No override. |
| gateway | crash report | `yuzu_gw_sup` fails to start with a child specification error | Two channels share a name, or a channel is named after a registered process (`yuzu_gw_registry`, say). Loud and fail-closed, but the text does not name the duplicate. Give every channel a unique name (seen in a probe; the boot guard does not check it). |
| gateway | ERROR | `Upstream channel <name>: the TLS client options cannot be used, so every connection fails: <file> ...`, `/readyz` 503 with `upstream_tls_files` false | A CA, certificate or key file named by an `https` endpoint is missing, unreadable, empty or holds no certificate or key. The line names the option and, except for a `keyfile`, the path. Create or fix the file; the channel finds it on its next attempt (within about 5 s, or up to about 2 minutes if `ssl` had cached an earlier version of the same file; see Certificates above) with no restart, and `/readyz` returns to 200 once a connection attempt fails for any other reason or succeeds. If the line says none of the files is at fault, check the other `ssl` options. A file that is a directory refuses boot instead. See [A CA, certificate or key file that is wrong](#a-ca-certificate-or-key-file-that-is-wrong). Covered by tests; not run against a live server. |
| gateway | INFO/metric | `Upstream channel <name> connection <n> down (<TLS alert word>)` repeating, and `yuzu_gw_upstream_tls_handshake_failures_total` rising | Certificates or the CA were replaced or expired after the connection opened: an open connection keeps the old material until it drops, then the reconnect presents the new files (after Erlang's `ssl` cache clears, about 2 minutes). Recovery takes the cache window plus up to 5.8 s of delay, plus the circuit breaker's open time if it tripped (up to 300 s, doubling). While the breaker is open the counter moves only at its probes. INFERRED from the code and the certificate probe, not run end to end. |
| gateway | metric | `yuzu_gw_upstream_rpc_errors_total{code="timeout"}` rising on every call, no channel log line, and `/readyz` 200 until the breaker opens | A blackhole peer: the server host or a VIP failed over without a FIN or RST. The gateway sends an HTTP/2 PING on each upstream connection every 45 s and closes the connection when two go unanswered, so a peer that stopped answering is noticed after about 90 s, after which the slot redials; it also sets `SO_KEEPALIVE` on the socket, with the operating system's default timers (the kernel alone would take about 15 minutes with default TCP retries). Until the PINGs give up, every call times out. INFERRED from the gun options in `yuzu_grpc_client_channel.erl`; not run against a true blackhole (an earlier observation of a peer that stopped answering saw the connection counted as up for the whole 35 s watched, inside the 90 s window). Restart the gateway early only if the server is confirmed healthy and reachable by another route; it redials at once (INFERRED), but agents behind it reconnect as described for #5183 above. The 45 s interval is not configurable and must stay above the server's 30 s floor for pings without data: a faster client keepalive is refused with GOAWAY `too_many_pings`. |
| gateway | metric | `yuzu_gw_upstream_rpc_errors_total{code="connection_lost"}` rising by a few, then recovery | An upstream connection closed (reset, or the server's end went away) or the server sent HTTP/2 GOAWAY (a server draining or restarting) with calls on it: those calls fail as `connection_lost` and the agents whose `Register` was among them retry. Since #5695 the breaker counts one lost connection once, however many calls it ended, so one dropped connection no longer opens it; and a connection that is going away is retired at the first call it refuses, its slot redialled at once (before, it kept being handed out for its 3 s closing window and every call on it failed and counted). Expected around a server restart. A count that keeps rising with the server up means connections keep dropping: look at the network path and the server's connection limits. |

Progress shows as `yuzu_agents_connected` (and `/health` `agents.online`)
ramping back, together with the gateway `Registration replay` INFO lines and
replay counters above. After a server-only restart shorter than 270 s (the 90 s
route lease plus the 180 s reaper grace) the directory rows are still live, so
the server lists the sessions for replay but does not count them under
`yuzu_server_gateway_route_desync_total{op="renew_leases",outcome="unknown_session"}`
and logs no `renew_leases ... unknown_session` warning for them: that counter
stays flat. It and its warning move only for ids the directory itself does not
know (rows tombstoned after a longer outage, or an old replica answering during
a rolling deploy), and stop once the agent is known again. How long the replay
takes depends on the gateway's upstream circuit breaker (derived from the code;
the rig runs under "Observed on a rig" below are the measured evidence).

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
  by the breaker's remaining backoff (capped at 30 s by default since #5695, 300 s on
  the builds the runs below used; `circuit_breaker_max_reset_timeout_ms`, see
  "Circuit breaker tuning" under Configuration), plus up to one heartbeat interval,
  plus one flush, plus the agent's turn in the replay. A
  long outage can open the breaker because other upstream calls the agent keeps
  retrying feed it. Wait: do not restart anything for this (the 58 s recovery
  in R2d and the recoveries in runs F3a (all agents online at T0 + 85.2 s) and
  F3b (T0 + 50.4 s) under "Observed on a rig" are this case; in F3a and F3b the agents came back through
  the breaker's own replay right after the probe closed the breaker, with no wait
  for a heartbeat. Since #5695 a breaker recovery replays nothing by itself: the
  first verdict after the probe closed the breaker starts the replay, one flush
  interval later when agents heartbeat every second or more often across the node,
  see "What starts a full replay" below). This applies to one agent too: in rig pass 4 (run H3, 1 agent,
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
  The backoff doubles from 10 s up to `circuit_breaker_max_reset_timeout_ms`,
  30 s by default since #5695 (it was 300 s), so the wait is at most about 30 s plus
  one probe, plus the first heartbeat flush after it (the verdict that starts the
  replay, see below). The runs above used the old 300 s cap: the steps up to 160 s were
  observed (F3a). The rig used a failure threshold of 5 and a reset timeout of 10 s,
  the defaults.

**What starts a full replay (since #5695).** The runs above predate this: the
gateway then replayed every agent whenever the breaker closed, and whenever any
call succeeded after a failed one. That replayed the whole node to a server that
had lost nothing each time one upstream connection dropped (measured with the
scale suite's `upstream_conn_loss` case: 5,500 replayed registrations and 5,500
repeated `CONNECTED` notices for one reset connection at 5,500 agents). Now a
recovery replays nothing, and the server's heartbeat verdict decides:

- a verdict replays the sessions it names (`trigger="heartbeat"`);
- a verdict that names at least half of the heartbeats of its batch, and at least
  one session per 64 agents this node holds (at least 1, at most 16), or that the
  server marked truncated (more than 4096 unknown), is evidence that the server
  lost its state: the gateway then replays every agent it holds
  (`trigger="server_lost_state"`, INFO line `Registration replay: the server does
  not know N of the M session(s) of a heartbeat batch; replaying every agent`);
- no second full replay starts within 60 s of the end of the previous one (the
  named sessions are still replayed), so a server that keeps answering "unknown"
  costs at most one full replay a minute.

After a server restart that lost its in-memory registry, every agent is unknown,
so the first verdict that reaches the new server starts the full replay. At 5,000
agents in the scale suite's `server_crash` case the replay of 4,500 sessions
finished 13.2 s after the new server started (13.3 s before this change), with
the breaker open during the outage.

The gateway-side counters move as follows: `yuzu_gw_registration_replay_triggered_total{trigger="heartbeat"}`
rises by one each time a verdict queued at least one agent,
`yuzu_gw_registration_replay_total` rises by one for every drip attempt, any
outcome (its HELP text reads `Total registration replay attempts by the drip, any outcome`),
and `yuzu_gw_registration_replay_queue_depth` rises, then returns to 0.

**Telling that the reconcile is not converging.** After a short server-only
restart (under 270 s) the server-side `unknown_session` counter stays flat even
when nothing is being replayed, so do not wait for it. The signal is
`yuzu_agents_connected` (or `agents.online`) not ramping back; the gateway
counters below say why. After a longer outage, a
`yuzu_server_gateway_route_desync_total{op="renew_leases",outcome="unknown_session"}`
that keeps rising well after the restart is a second sign. In either case, with
both the gateway and the server upgraded, read the new gateway counters:

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
  agents stay offline does not prove that no verdict reaches the replay: ids
  already queued, or replayed inside the guard window, are counted nowhere, so
  a verdict can arrive and move none of them. If `registration_replay_total`
  is also flat while agents stay offline, no replay is being sent (an older
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
not measured). An open breaker gates `ProxyRegister` and `ProxyInventory`, holds
stream-status notifications in the pending store (see "Stream Status
Notification"; they used to be dropped) and makes the whole `/readyz` answer 503 `not_ready`, with
`circuit_breaker` false in its checks (`yuzu_gw_health.erl`, INFERRED; the
shipped guidance is that a load balancer probes `/readyz`, so an open breaker can
take the node out of rotation until it goes half open). A heartbeat flush never
feeds the breaker. If the breaker keeps reopening, look at the server: a
`half_open -> open (probe failed ...)` WARN with a transport reason in the accompanying
`Failed to notify stream status` line means the server is still failing, and
restarting the gateway does not help. A repeating `Upstream RPC NotifyStreamStatus
raised` line against a healthy server points at the gateway's own encoder, not
at the server: a restart does not help, and the runbook row says to fix the sender or the build first, because a rollback is itself a gateway restart and brings back the earlier behaviours.

One server-side cause of a reopening breaker applies right after a server-only
restart: when Postgres writes fail while directory reads
still succeed, the server refuses each replay `ProxyRegister` with
`UNAVAILABLE` (its adopt decision fails closed and is counted under
`yuzu_server_gateway_route_write_failed_total{op="renew_leases"}` or
`{op="reclaim_tombstoned_session"}`), so the replays open the breaker and other
upstream calls fail fast until writes recover (INFERRED from the code, not run).
Fix the Postgres write path; the replay resumes when the breaker closes.

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
  flush deadline (read from the code: neither the flush nor the replay call passes a
  timeout, so the upstream client's default of 5000 ms applies) plus the replay
  RPC time later. Do not set `registration_replay_session_guard_ms` below 5000
  plus the expected replay RPC time; the default 10000 is safe (INFERRED).
- A double replay. A verdict replay runs first (the server has no prior session,
  so nothing is revoked), and a later full replay re-proxies the same sessions
  (a prior session now exists) once their guard window has passed (the walk of a
  full replay skips a session replayed within the window).

Neither case was observed on the rig. An idempotent adopt (a re-adopt of a
session the server already holds would no longer wipe placement) is tracked in
#5244.

**A full replay and the verdict drip.** A full replay started while a
verdict-seeded (targeted) drip runs is not dropped: it walks the registry after
the queued entries and skips the sessions inside the guard window, so each agent
is replayed once (unit test `breaker_replay_during_targeted_drip_walks_the_rest`).
A breaker recovery starts no replay at all since #5695, including when a targeted
replay is the half open probe that closes it. The consequence is under "Known
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
verdict appends: a full replay walks the registry in chunks of 500 and is not
capped (it is bounded by the number of agents the node holds), and while a chunk
of the walk drains, every verdict id for an agent not already queued may count
as `queue_full` once the queue is at its cap. The circuit breaker policy is unchanged, but replay
failures now count toward the shared breaker (see below).

**What it does not promise.**

- Completion inside a route lease. The route lease runs 90 s from the last
  heartbeat the previous server ingested. Agents whose turn in the drip comes
  after the remaining lease has run out get `503 no agent connected` for
  commands until their turn.
- Dispatch reachability after the session is adopted. Adopting restores the
  server's knowledge of the session (heartbeats acknowledged, lease renewed,
  `agents.online`). Dispatch placement converges when the agent's re-sent
  CONNECTED notification is delivered. That notification is held, not dropped,
  while 10 are in flight or the breaker is not closed, and is sent first in
  first out (#4632; INFERRED from the code, OBSERVED on a rig: 0 notifications dropped across five 1000-agent and two 2000-agent cold waves). It is still
  lost when the pending store is at its cap, that is, the held keys plus the key of a half open probe in flight have reached `notify_pending_max` (counted in
  `yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}`), when the
  server answers it with a request-fault status or it cannot be encoded
  (`yuzu_gw_upstream_notify_lost_total{reason="rejected"}`), when its worker
  dies without a result (`reason="crashed"`), and when the upstream client
  process or the gateway stops while it is held (`reason="shutdown"`; nothing is
  counted if the process is killed). A worker that fails with any other error
  no longer loses it: since #5695 the notification is held again at the head of
  the store and retried (before #5695 that failure lost it, uncounted). An agent
  affected that way stays acknowledged but unreachable for commands until its
  next reconnect. The dropped series is created at 0 at start, so a rise is
  visible. It has no agent label, so the affected agents cannot be identified
  from the metric. They recover at their next reconnect; to force it, restart
  the agent service (OBSERVED: a restart recovers any agent). A CONNECTED the server receives but
  refuses (`acknowledged=false`) does NOT move that gateway metric either. Since
  #5695 the gateway holds it and sends it again after a backoff while it still
  holds the session (counted in
  `yuzu_gw_upstream_notify_unacknowledged_total`; see "When the server does not
  record a notification"); an older gateway ignores `acknowledged=false` and does
  not retry. The server counts it under
  `yuzu_server_gateway_route_desync_total{op="notify_stream_status"}` with
  outcome `connected_unverified` (the directory read failed and this replica
  holds no matching local session) or `stale_connected_session` (the directory
  row or the local registry names a different session). On an older gateway
  recovery is the same: the agent's next reconnect. On a gateway with #5695 the
  resend is delivered once the server records it (a `connected_unverified`
  refusal clears when the directory reads again; a `stale_connected_session`
  refusal is definitive and is resent until the session ends).
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
- **`yuzu_gw_upstream_notify_dropped_total`.** OBSERVED on gateways built
  before #4632: the metric has HELP and TYPE lines but no sample until a
  notification is first dropped, so an absent series meant no drops. A gateway
  with #4632 creates `reason="at_capacity"` and `reason="unknown"` at 0 at
  start (INFERRED from the code; `unknown` is the overflow bucket for an
  unexpected value and is not emitted today), so there an absent series means an older gateway, and 0 means nothing
  was lost at admission. Samples with `reason="circuit_open"` come only from an
  older gateway: the new one holds a notification that arrives while the
  breaker is not closed and no longer emits that reason.
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
| K5 (pass 6) | `c518edd93` | grace of a closed connection's pending rows, probe client | default grace: a `Subscribe` on a new connection accepted, rows 2 at +10 s and 0 at +17 s, a late `Subscribe` refused; with `dead_connection_grace_ms` 2000 the rows were gone by +3.7 s. The refusal reached the probe as status 2 (the previous transport; the current layer answers `UNAVAILABLE`, 14) |
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

**Load and convergence bounds.** This paragraph and the next two describe the
replay drip as it was before #5695 and the runs made on it. Since #5695 a full
replay walks the agents table in chunks of 500 and replays up to 24 agents at once
under permits, so the period per agent is the call time divided by 24. Measured
with a mocked server (no network, no notifications, one laptop): 5,000 agents
replayed in 4.5 s at 20 ms per call and 10.7 s at 50 ms, against 217 s and 365 s
for the drip on the same harness with its default 20 ms spacing (OBSERVED, #5695).
The drip sent one ProxyRegister at a time.
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

The drip can also wait for a free stream-status notification slot, but now only
when 10 notifications were already in flight before the replay armed, or when a
half open probe took the tenth slot (the notification drain keeps one slot free
while a replay is active), so these rates remain ceilings. The first verdict lists the agents that heartbeated
in the first flush window, so synchronized heartbeats list more agents at
once. Spacing is the gateway's only lever; the RPC time is the server's. A
drain that runs past 270 s after the last heartbeat the previous server ingested (the
route lease of 90 s plus the reaper's 180 s grace) makes their route rows
eligible for the server's lease reaper, which runs about every 5 minutes
(#4627; read from the server code and the ADR). The same 90 s lease plus
180 s grace (270 s) is the horizon for a Postgres outage: heartbeats cannot
renew leases while the directory is unreadable or unwritable, and the
`YuzuGatewayRouteWriteFailed` alert pages 5 to 10 minutes after onset, so the
rows can already be tombstoned when you are paged. Recovery is automatic: the
renewal shortfall shows up as `renew_leases` `unknown_session`, which lists the
sessions and triggers the gateway replay; expect a spike of that counter and do
not restart anything.

**Registration rate per gateway.** Every `ProxyRegister` goes through the one
`yuzu_gw_upstream` process, one call at a time (the measurements below were taken
when the channel was one HTTP/2 connection; see the update after the table), so the time of one upstream call sets how many agents a gateway can
register per second. OBSERVED on a rig, on gateway commit `71ee2b02f` (which does
not have the `upstream_tcp_nodelay` change; loopback, one box, debug-built
server, plaintext, a C++ client with the agents' 30 s `Register` deadline and
retry backoff; the request was a real `RegisterRequest` of 9,054 bytes, captured
from a running agent through the gateway): each upstream call took about 41 to
43 ms for any request under about 64 KiB, which caps a stock gateway at about 24
registrations per second whatever the concurrency. The cause is INFERRED from
switching nodelay on and off at three places (no packet capture was taken):
Nagle's algorithm on the gateway-to-server socket meets the server's delayed
ACK, because the HTTP/2 client library the gateway then used did not set TCP_NODELAY.
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

**Update (2026-10-11): the upstream client was replaced.** The runs above used grpcbox
as the upstream client, which held one HTTP/2 connection (the new client's default too), and the K0 start log line
`Upstream channel default_channel: TCP_NODELAY on` came from the code that restarted that
channel. Neither exists now: the client is `yuzu_grpc_client` over gun with a channel of
`pool_size` connections per endpoint (default 1, as before; see [The upstream client](#the-upstream-client)),
TCP_NODELAY is set when each connection is opened, and the gateway logs no line about it.
Since #5695 the calls of registration run in parallel under permits (48, of which
replays at most 24), so the rate is the permits divided by the call time; a larger
pool raises the stream ceiling the permits must stay under, not the rate itself. The rate figures above were not
re-measured with the new client. A single measurement on a live stack with TLS, reported by
the author of the change and not repeated on the rig, put the `ProxyRegister` mean at
about 3 ms with nodelay on and about 45 ms with it off.

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
| Agents slow to come back after a server restart on a large fleet | The server log shows more than one `[gateway] ProxyRegister succeeded` line per agent; agents give up on a `Register` after 30 s; `yuzu_gw_upstream_rpc_duration_ms` for the `register` rpc name has a high mean | Before the `upstream_tcp_nodelay` change, the 43 ms per-`Register` Nagle delay (OBSERVED on a rig, see above); otherwise a slow server: the register pool (48) drains at 48 divided by the server's answer time | Confirm `upstream_tcp_nodelay` is not `false` in the `yuzu_gw` section of `sys.config` (and that no endpoint has a hand-set `{nodelay, false}`); check the server's `ProxyRegister` latency and `yuzu_gw_upstream_permits_waiting{class="register"}`. A slow server shows as `yuzu_gw_upstream_slow` 1 and a duty cycle near 1; see "Slow server" below |
| Registrations are being refused or abandoned while the gateway is busy | `yuzu_gw_upstream_permit_refused_total{class="register"}` rises (`queue_full` or `deadline`), with `yuzu_gw_upstream_calls_dropped_total{rpc_name="register"}` for the deadline case; agents log `UNAVAILABLE` and retry | Every register permit is held and the wait queue is full, or a request's deadline passed while it waited; nothing is sent for it, so no server session is created for a request nobody waits for | Look at the cause (a slow server `ProxyRegister`, a restart herd; see the table above). The refused agents retry; a sustained `queue_full` with a healthy server points at raising `upstream_register_concurrency` together with the channel's `pool_size` (see "Upstream call permits") |

**Slow server.** A gateway reaches the server through lanes of bounded capacity, and
"slow" is defined from how often those lanes are full, not from a latency figure.

- A lane is *saturated* at an instant when work is waiting on it or would be refused. There are
  three. `permits` (`serial` before #5695): a live `Register` or inventory report waits for a
  permit, because every permit of its pool is held (a replay waiting for one does not count; it
  waits behind live registrations by design). `notify`: every
  stream-status notification slot is held (10), so the next notification waits in the held store
  until a slot frees (it is dropped, `yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}`,
  only when the held store itself is full). `guardian`: all 50 Guardian
  forward slots are held.
- *Backpressure* is present at an instant when at least one lane is saturated. The *duty cycle* is
  the share of a window during which it was present, 0 to 1.
- A *slow server*, as one gateway sees it, is a duty cycle of **0.5 or more over the last 60 s**
  (`yuzu_gw_upstream_slow` is 1): for at least half of the last minute, work waited on the server
  or was refused because it answered slower than work arrived. Exactly 0.5 counts. The window is 60
  one-second buckets, and until the gateway has run for a minute the missing seconds count as not
  saturated, so after a start the figure can only read low.

| To see | Query |
|---|---|
| This gateway's duty cycle over any window | `rate(yuzu_gw_upstream_backpressure_seconds_total[5m])` |
| The same over the last 60 s, and the flag | `yuzu_gw_upstream_backpressure_duty_cycle`, `yuzu_gw_upstream_slow` |
| Which lane | `rate(yuzu_gw_upstream_lane_saturated_seconds_total[5m])` by `lane`. The lanes overlap: never add them |
| The server or its database, not one gateway | `avg(yuzu_gw_upstream_slow)` across the gateways. Near 1 means every gateway sees it; one gateway at 1 among many at 0 points at that gateway or its path |
| Slow, or just a lot of work | `histogram_quantile(0.5, sum by (le) (rate(yuzu_gw_upstream_rpc_duration_ms_bucket{rpc_name="register"}[5m])))` beside the duty cycle |

How it is measured: a process in the gateway samples the lanes every 100 ms. It reads the
published counts of the upstream process and of the permit regulator without calling them, credits each sample with the time until the next, and credits one step at most 1 s, so a
stalled VM does not credit a minute. It is a sampled estimate with a resolution of 100 ms: a state
that begins and ends between two samples is missed.

What it does not tell apart, and does not do:

- A server that answers slowly, and more work than the permits drain at a healthy server's pace
  (every agent of a restarted fleet registering at once), both read as a slow server: the server's
  service rate is below the rate work arrives, which is the thing measured. The latency histogram in
  the table says which it was.
- It is one figure for the gateway, not one per upstream endpoint. With several servers behind a
  channel it does not say which server is slow; per-endpoint state is not exported yet (#5648,
  #5655).
- It does not change what the gateway does. The breaker still counts only failed calls, so a
  server that answers every call in 3 to 5 s never opens it; this is how that case is seen. What
  the gateway should do about it is open (#5681).
- A slow server is not a readiness input. The `/readyz` `circuit_breaker` check reads the breaker
  state the `yuzu_gw_upstream` process publishes at each breaker transition, without a call into
  that process, so it answers at once while the process is inside a slow RPC: a closed breaker
  reads `true`, and a slow server alone does not turn `/readyz` 503 (#5680). Before this, the
  check called the process, waited out its 5 s timeout behind the RPC in progress and reported
  `circuit_breaker` false with the breaker closed. Covered by a unit test against a mocked server
  whose RPC does not return (`circuit_breaker` true within the test's 2 s bound; the old check
  answered false after 5 s), not run against a live server.
- One alert ships: `YuzuGatewayUpstreamSlow` (warning) fires when `yuzu_gw_upstream_slow` has been 1
  for 5 minutes, per gateway, so with many gateways behind one slow server they fire together and
  its alert name should be grouped in Alertmanager. The threshold and window are initial values,
  to be tuned on a real deployment.
- Covered by unit tests against a mocked server whose RPC does not return and against synthetic
  samples; not run against a live server.

**Several core replicas.** The verdict and replay reconcile is correct and
bounded on one core replica. On several replicas it converges in one round only
if a gateway's `BatchHeartbeat`, replay `ProxyRegister` and re-announced
`NotifyStreamStatus` reach the same replica during the reconcile. The shipped
gateway sends all of these calls through one channel and one endpoint, through a
layer-4 VIP, and with the default `pool_size` of 1 that is one HTTP/2 connection, as it was
with grpcbox: unchanged. **Warning:** a channel opens `pool_size` connections per endpoint
and sends each call on the next live connection, round-robin, so with `pool_size` above 1
each connection can land on a different replica and two consecutive calls of the
reconcile can reach different replicas (read from `yuzu_grpc_client_channel`, not run on
several replicas); keep `pool_size` at 1 where this matters. A multi-endpoint node list (the channel
round-robins per call) or a layer-7 per-RPC balancer breaks it too. Convergence is
then probabilistic, not bounded, and the per-session guard bounds the replay
rate but not the number of rounds. No multi-replica run exists; this is
inferred from the code. The durable cross-replica session lookup (WS-5,
#4246 item 3, ADR-2002 section 7f) is the fix for the session-resolution part:
`BatchHeartbeat`, `ProxyInventory` and `NotifyStreamStatus` now resolve a session
against the durable directory on any replica. It does not lift the safe-to-scale
gate: the gate still forbids a second replica, so run exactly one server
replica (see [ADR-2002](../adr/2002-high-availability-architecture.md),
section 7c, update 2026-10-04, and section 7f). Deferred:
the surfaces that read only the local registry (`/api/agents`, the dashboard
device list, `yuzu_agents_connected`, the guardian heartbeat reconcile) on a
replica that has not been hydrated by the replay, a unique index on the
directory's `session_id` column (#5683), and the failover and restart validation
scenarios (WS-9).

**Degraded directory reads.** The posture differs per RPC on purpose.
`BatchHeartbeat` is fail-soft: sessions the replica holds locally are still
acknowledged, ingested and lease-renewed, and a session whose read failed and
that the replica does not hold is neither acknowledged nor listed (so the
gateway does not re-register in a storm). `ProxyInventory` for a session id the
directory does not know keeps `received=false` (the agent retries); a local
hint helps only on a degraded read or for a session that lost a race.
`NotifyStreamStatus` CONNECTED, when the directory read fails, is accepted only
if this replica holds the matching local session (the session it registered
for that agent, which the directory confirmed at `ProxyRegister`), and is
otherwise rejected (`acknowledged=false`) and counted under
`yuzu_server_gateway_route_desync_total{op="notify_stream_status",outcome="connected_unverified"}`.
A delayed CONNECTED for a session this replica has since superseded is counted
the same way (a successful read counts it as `stale_connected_session`).
`yuzu_gw_upstream_notify_dropped_total` does not count a rejected CONNECTED.
A gateway that includes #5695 counts it in
`yuzu_gw_upstream_notify_unacknowledged_total{event="connected"}` and sends it
again after a backoff while it holds the session, so a `connected_unverified`
rejection is put right once the directory reads again (see "When the server
does not record a notification"). An older gateway does not retry it: that
server counter is then the only signal, and an agent whose current session was
rejected keeps heartbeating but cannot receive commands until it reconnects. When the read succeeds, the local fallback applies only if
the directory row is absent or tombstoned, or the session is one this replica
recorded as having lost a race; a row with a different session id rejects the
CONNECTED (`stale_connected_session`). A DISCONNECTED proceeds on the local
check. Every degraded read counts under
`yuzu_server_gateway_route_write_failed_total{op="session_lookup"}` (despite
the metric name, that op is a read).
`yuzu_server_gateway_route_degraded_renewal_total{op="batch_heartbeat"}` counts
batches, not sessions: it rises once per `BatchHeartbeat` whose read degraded
and that still renewed at least one locally held session.

**Read bound (capacity).** The 500 ms hot-path timeout bounds only the wait for
a database connection. A batch of n distinct session ids then runs
ceil(n/1024) statements on that one connection, each bounded by the server's
Postgres `statement_timeout` (30 s by default), with no overall deadline. The
server does not cap the number of ids in a batch; the gateway sends one batch
per buffer chunk (about 3 MiB) and buffers at most `max_heartbeat_buffer`
sessions (default 10,000), so a default gateway's batch needs at most 10
statements. A slow but reachable Postgres therefore lengthens a large batch
roughly in proportion to its size.

**Rolling upgrade.** An old replica answering a batch reports directory-known
sessions as unknown, so the gateway re-registers those agents. Drain the old
replica first and run one replica.

#### Forged or colliding session ids

The session id on the gateway-to-server hop is asserted by the gateway.

- The agent identity of a heartbeat, inventory report or stream notification is
  taken from the durable directory row for that session id, never from a field on
  the wire.
- A session id that matches more than one directory row is refused: it is
  neither acknowledged nor listed, and counts under
  `yuzu_server_gateway_route_desync_total{op="session_lookup",outcome="ambiguous_session"}`
  (alert `YuzuGatewaySessionAmbiguous`). It means duplicate placement, two
  concurrent adopts of one id (below), or a forged presented id.
- An unreadable directory is never treated as "unknown" (which would trigger a
  re-register). A session this replica itself registered (a local hint) is
  still acknowledged, lease-renewed and ingested during the degrade, which
  suspends the ambiguity refusal for that window.
- The gateway reaches the server over mTLS with the gateway peer SPKI pin, and
  `ProxyRegister` rejects a presented session id that is not `gw-session-`
  followed by 32 lowercase hex characters
  (`yuzu_server_gateway_route_desync_total{op="proxy_register",outcome="malformed_session_id"}`).
- `ProxyRegister` refuses to adopt a presented session id that a different
  agent's committed directory row already holds, counted under
  `yuzu_server_gateway_route_desync_total{op="proxy_register",outcome="session_held_by_other_agent"}`
  (alert `YuzuGatewaySessionHeldByOtherAgent`; expected rate zero, so any
  increase means a forged or colliding id from a pinned gateway). The check is
  not a lock: two concurrent adopts of one id for different agents can both
  land (measured against live Postgres), and the ambiguity refusal above then
  catches the duplicate until a unique index on `session_id` ships (deferred,
  #5683). Nor can it see another agent's row that was already tombstoned
  (after a Postgres outage longer than 270 s): the presented id is then
  reclaimed and resolves to the presenting agent until the original agent's
  stream reconnects. If the original agent was already listed for replay, its
  replay is refused and forces that reconnect; otherwise the window lasts until
  the original agent next reconnects for any other reason.
- The gateway logs every `FAILED_PRECONDITION` replay answer (a malformed id,
  an id held by another agent, or a superseded session) as
  `Registration replay: <agent>'s presented session was superseded`; the
  server's WARN line and the `outcome` label on
  `yuzu_server_gateway_route_desync_total{op="proxy_register"}` tell the three
  refusals apart.

The evidence for these decisions is the metrics above and the server log (ids
are sanitized and truncated to 64 bytes); there is no per-event audit row.

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
- **Registration runs in parallel, bounded by permits** (#5695; it was serialised
  through one process). See "Upstream call permits". A request that waits for a permit
  and runs out of time is refused and never sent; a call already in flight to the server
  is not cancelled when the agent gives up, but the server is told the deadline
  (`grpc-timeout`) and may stop it. The `upstream_pool_size` key in the shipped
  `sys.config` files does nothing (nothing reads it); the connections per endpoint are the
  channel's `pool_size` option (default 1, see [The upstream client](#the-upstream-client)),
  and a larger pool raises the stream ceiling the permits must stay under.
- **Queued upstream calls are not bounded per connection (accepted residual risk, part of
  the unauthenticated-port family).** The agent listener is unauthenticated by design, and
  a request is decoded in full before any handler sees it. A client that repeatedly sends
  a large `Register` and resets the stream can keep decoded requests waiting for a
  permit (each in its own request process, freed when the stream is reset); they are
  bounded by the register wait queue (10000), Cowboy's cancel-stream rate limit
  (`max_cancel_stream_rate`, an `http2` option) and memory, not by a per-connection
  quota. The same family covers the decode amplification of a message that fits
  `max_message_bytes` and the half-open connection flood described under "Connection ceilings and the
  unauthenticated ports". The decode-side bound is the first follow-up; until it lands,
  limit connections and request rate per source at the L4 balancer or firewall.
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
- **A tombstoned route row is not repaired by a breaker recovery.** The server
  lists only the sessions missing from its in-memory map, so a session it still
  knows whose durable route row was tombstoned (the entry above) is never named by
  a verdict. A breaker-recovery full replay used to be an incidental repair path
  for such a row, when a breaker transition happened to coincide with it; it was
  not observed to repair R2b (that run had no breaker transition), and R2b itself
  is not caused by this change. Since #5695 a breaker recovery replays nothing, so
  the row waits for the agent's own reconnect. Not observed on a rig. Tracked as a
  follow-up (no issue yet), together with the entry above.
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
  replay queue and the recent-replay stamps (shown as sizes), the held
  stream-status store and the probe record (shown only as `notify_pending_len`, a
  count, and `notify_probe_held`, true or false, so `sys:get_status(yuzu_gw_upstream)`
  shows no session id or peer address), the last message (the
  `notify_stream_status` cast is redacted too: the agent id and the event are
  kept, the session id, peer address and stream home are replaced), the
  reason and the debug log (INFERRED from `format_status` and unit tests, not run on a rig); for the per-agent process the stored registration
  request; for the registry the request inside the `register` message. Second, a
  request can no longer leave through an exit reason: an exception raised inside
  the upstream client's own RPC calls is caught and counted as an RPC error (code
  `exception`; a local request encoding failure is not a breaker failure, see Known
  limits), and the three caller side call sites that carry a registration
  request go through one wrapper, `yuzu_gw_safe_call`, which catches an exit of the
  call (the called process crashing, the call timeout, or the process not running
  during a restart). The sites are `yuzu_gw_upstream:proxy_register/1`,
  `yuzu_gw_upstream:proxy_inventory/1` and `yuzu_gw_registry:register_agent/7`. The
  callers get `{error, upstream_unavailable}` from the first two and
  `{error, registry_unavailable}` from the third. The exit reason carries the
  request and is never logged or returned. The wrapper logs at most one warning per
  second for each called process on a node, and the warning names only the class of
  the exit (`noproc`, `timeout` or `other`). The Register handler answers a gRPC
  `UNAVAILABLE` status for `upstream_unavailable`, as for `circuit_open` and the
  other refusals the gateway makes itself (#5695; it answered `INTERNAL` before),
  and `INTERNAL` for any other `{error, _}`, and the agent retries registration on any non-OK
  status (read in `yuzu_gw_agent_service.erl` and `agents/core/src/agent.cpp`; not
  run). The third site matters because a failed registry call in the per-agent
  process's init used to exit that init with a reason that embedded the
  `RegisterRequest`, which the Subscribe handler then logged (INFERRED from the
  code; not run). The agent process now answers a failed registry call with the
  fixed reason `registry_unavailable` to the Subscribe handler that waits for it,
  and stops with reason `normal`, which writes no crash report (since PR #5695 the
  registration runs after the agent's `init/1` has returned, so the agent
  supervisor never waits for the registry). Before this, the gRPC server library logged the exit of
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
- **Cold-start notifications were shed at the in-flight limit, so most route rows
  had a session but no placement (never announced) until the replay ran. Fixed by
  #4632 (hold instead of drop).** Before the fix, OBSERVED in rig pass 6 (runs K1 and K6 of that pass)
  and in the cold start of pass 5 run J1 (recorded in the
  [verdict replay evidence record](../security-reviews/gateway-heartbeat-verdict-replay-2026-10-04.md)),
  and it was measured again on the previous build for #4632 (see the
  [evidence record](../security-reviews/gateway-notify-pending-store-2026-10-05.md)): after a cold
  `Subscribe` wave of 1000 simulated agents
  `yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}` was 987 (989 and
  988 in two repeats, and 1953 after 2000 agents), the server's route table
  before the restart showed `live=13 tomb=987` (the `tomb` label was wrong: a
  later measurement of the previous build found 0 tombstones and 989 rows with a
  session and no placement, never announced), and with 30 real agents cold
  started the same effect gave 13 drops (not reproduced in the later control runs,
  which dropped nothing at 30 real agents, where each notification took 1 to 2 ms
  and the in-flight count never reached 10; a control run that started 30
  simulated agents at the same instant did drop 20, so the earlier drops came
  from simultaneous starts, INFERRED). `MAX_NOTIFY_INFLIGHT` is 10 in
  `yuzu_gw_upstream.erl` and a `CONNECTED` beyond 10 in flight was shed. Now a
  notification beyond 10 in flight is held and sent first in first out (see
  "Stream Status Notification"). Measured after the fix (OBSERVED on a loopback rig with a debug-built server,
  PostgreSQL with fsync off, on a shared host): the previous build dropped 989
  notifications in each of two 1000-agent waves (11 routable rows, 989 rows with a
  session id but no placement, unchanged over 76 s) and 1935 in a 2000-agent wave
  (65 routable rows). The fixed build dropped 0 in five 1000-agent waves (1000
  routable rows, all registered in about 1.9 s, 100 ms samples of held keys peaked
  at 660 to 762 (the one run traced event by event had a maximum of 989) and the
  gauge was back to 0 within about 0.3 s, in-flight workers peaked at 10) and 0 in
  two 2000-agent waves (2000 routable rows, 100 ms sample peaks of 1850 and 1906;
  the event-level maximum was not measured at 2000). With 30 real
  agents neither build dropped anything (in-flight workers peaked at 4 and 2, below
  the limit of 10), so that scale does not separate them. A 5 minute steady state
  with 30 real agents logged no warnings or errors and both gauges stayed at 0.
  The statements below are INFERRED from the code. Residuals:
  - The cap. A notification for a new key is still lost, and counted, when the
    store is at its cap: a new key is admitted only while the held keys plus the
    key of a half open probe in flight stay below `notify_pending_max`.
  - A worker that dies after taking a notification (killed or crashed, so it
    returns no result) loses it, counted in
    `yuzu_gw_upstream_notify_lost_total{reason="crashed"}`. Since #5695 a worker
    that returns an RPC error no longer loses it: the notification is held again
    at the head of the store and retried, and while the breaker is closed the
    failure counts against it (see "Failed sends are retried" above; INFERRED
    from the code and unit tests). On the #4632 build the runs below used, a
    returned error lost the notification, uncounted, and ordinary notification
    results did not drive the breaker. Measured on that build (OBSERVED): with the server stopped by SIGSTOP and resumed 12 s later,
    10 of 10 notification workers timed out (the 5 s call timeout; the 6.05 s in
    the rig notes is measured from the SIGSTOP, and the requests were dispatched
    about 1 s later) and logged `Failed to
    notify stream status`, yet all 10 events still took effect at the server,
    because the requests were already in the frozen server's socket buffer. When
    the frozen server was killed and restarted instead, 0 of 10 stop notifications
    reached it: 51 s later the route directory showed 30 routable rows for 20 live
    agents, and at 141 s 20 routable rows and 10 placed rows without a lease. On a
    gateway that includes #5695 those timed-out notifications are held and sent
    again, so in the first case the server can receive the same notification
    twice and in the second the stop notifications are sent again once the server
    answers (INFERRED from the code, not re-run on a rig).
  - Shutdown loses the volatile store. Held entries are not flushed when the
    upstream client process or the gateway stops.
  - Workers orphaned by an upstream client restart are not counted by
    `yuzu_gw_upstream_notify_inflight` or the pending gauge, which describe the
    current process only.
  - The cap bounds retained keys, not memory or mailbox size. `ProxyRegister`,
    `ProxyInventory` and the replay still run synchronous RPCs inside the
    upstream client process, so casts accumulate in its mailbox while one runs,
    and a long mailbox makes the heartbeat buffer skip verdict casts (counted as
    `yuzu_gw_heartbeat_verdict_dropped_total{reason="queue_full"}`). OBSERVED during cold waves (a slow-RPC burst was not
    measured): the upstream process mailbox peaked at about the number of agents
    on both builds (999 to 1001 on the fixed build and 1001 to 1003 on the previous
    build, at 1000 agents); at 2000 agents the upstream process memory peaked at
    64.6 and 95.5 MB on the fixed build and 94.2 MB on the previous build.
  - With several core replicas, a late `CONNECTED` for an old session can still
    be accepted into the in-memory registry of a replica that holds that old
    session, while another replica registered a newer one (see the runbook row
    for an agent that is acknowledged but not dispatchable). The gateway cannot
    close that case.
- **A local encode failure never moves the circuit breaker, and a probe
  notification that cannot be encoded is evicted, not retried (standing
  invariant).** INFERRED from the code and unit tests, not run on a rig. The head
  held notification is the breaker probe. A request that fails inside the
  gateway's own request encoder (a text field that is not valid UTF-8, or an
  encoded size over 4194304 bytes, the server's receive limit) never left the
  gateway, so it says nothing about the server: that outcome is recorded as a
  local error, counted once in
  `yuzu_gw_upstream_rpc_errors_total{code="encode"}` (the value `exception` is
  kept for an exception out of the client or transport, which does count against
  the breaker) and logged as `Upstream RPC <Method> raised <Class>:<Why>` (for the
  size limit `error:request_too_large`), and it feeds the breaker neither as a
  success nor as a failure. When the probe's result is a local error, the
  entry is evicted (not requeued, not counted as coalesced), the breaker is left
  exactly as it was (no backoff doubling), one WARN names the agent and the short
  reason (`Evicted held stream status notification for <agent>: it cannot be
  encoded (<Class>:<Why>); the circuit breaker is not affected`; no payload is in
  the line), and the next held notification is probed at once. A store that holds
  only such entries drains to empty with the breaker still half open, and the next
  encodable notification closes it. Eviction happens only to the half open probe:
  with the breaker closed there is no probe, and an ordinary worker that meets
  the same encoder failure loses that one notification, logs `Failed to notify
  stream status` and does not touch the breaker (not retried; counted in
  `yuzu_gw_upstream_notify_lost_total{reason="rejected"}`, not in
  `notify_dropped`). An evicted `CONNECTED` leaves the agent acknowledged by the
  server but undispatchable until it reconnects; an evicted `DISCONNECTED` leaves
  it looking online in the server's registry until its route lease expires. A
  registration replay whose stored request cannot be encoded is skipped with a
  WARN and the drip continues. Everything else is unchanged and still counts as a
  breaker failure: a transport error, a timeout, a TLS error, an HTTP-level error,
  a server status that is not in the request-fault set described in the next item,
  any other exception out of the call, and a killed probe worker (which also
  requeues its entry at the head). A `Register` whose request carries text that
  is not valid UTF-8 is answered `INTERNAL` and logged as `Upstream Register
  failed`, and it does not count against the breaker, however many arrive. A
  request over 4194304 bytes is refused the same way (`error:request_too_large`):
  the server's stock receive limit would otherwise answer `RESOURCE_EXHAUSTED`,
  which is deliberately NOT a request fault because a server short of memory or
  threads answers it too. A daily-sync inventory batch can legitimately exceed
  4 MiB (the per-source caps sum to about 5.6 MiB; real captures are about
  50 KB), and through the gateway the agent then sees `INTERNAL` instead of
  `RESOURCE_EXHAUSTED` (8) and retries at its 30 s floor (INFERRED). The peer
  address (the agent's `:authority` header) is still sanitised where it is read
  and where the notification is admitted, so the notification is sent and the
  agent stays dispatchable instead of being evicted: a value that is not valid
  UTF-8 becomes `invalid`, and a longer one is cut to 255 bytes at a character
  boundary, with one rate-limited WARN per `Register` (`Register from agent
  <agent>: the peer address was replaced or cut to fit (original size <N>
  bytes)`; the size only, never the bytes). Where each value stamped on a
  notification comes from: `agent_id` is bounded at the gateway edge (1 to 256
  bytes, see the next item), `session_id` is minted by the server,
  `stream_home_id` is minted by the gateway, the peer address is sanitised, and
  `cluster_id` is converted at boot, with a refusal to start when it cannot be
  represented (see the `cluster_id` paragraph under "Configuration"; the
  fallback sentence under "Upstream client tuning" does not apply to it). A request
  that the gateway rejects locally (the edge bound, the local encode refusal)
  is neutral for the breaker, so it cannot trip it; load-driven store faults on
  the server still count. A new
  payload field that an agent controls must still be made safe or bounded where
  it is admitted, and a new field needs a deliberate decision (the key set of
  the notification is asserted in a test so that it cannot be added silently). A
  repeating eviction points at the gateway or its encoder, not at that agent.
  The agent id is in the eviction line only; the `raised` and `Register refused`
  lines carry none (see the "Reading an eviction or a `raised` line" runbook row).
- **A server status that means the request was wrong never moves the breaker,
  and the agent id is bounded at the edge (standing invariant).** INFERRED from
  the code and unit tests, not run on a rig. `Register` checks the agent id
  first, before the peer address is handled, a session is reserved or anything
  is sent upstream: an id that is empty, missing, not a binary or longer than 256
  bytes (bytes, not characters; exactly 256 is accepted) is refused locally with
  `INVALID_ARGUMENT` and the message `agent_id length exceeds 256 bytes or is
  empty` (the id is not in it), with one rate-limited WARN `Register refused: the
  agent id is empty or longer than 256 bytes (size <N> bytes)` (the size only;
  0 for a value that is not a binary). That is the server's own bound
  (`server/core/src/gateway_service_impl.cpp`, `kMaxAgentIdLength` in
  `auth.hpp`), so an agent sees the same status class as before, only earlier and
  without an upstream call. Before this change the gateway counted a request the
  server refused as wrong as an upstream failure, which could open the breaker;
  the problem pre-dates this change. As defence in depth the server
  statuses `INVALID_ARGUMENT` (3), `NOT_FOUND` (5), `ALREADY_EXISTS` (6),
  `FAILED_PRECONDITION` (9) and `OUT_OF_RANGE` (11) are a request-fault set that
  leaves the breaker unchanged on the call path and on the replay path: not a
  failure, and not a success either (the failure count is not reset and no
  registration replay starts), the same treatment as a local error. The server
  returns only 3 and 9 on these RPCs today (read from the server code); 5, 6 and
  11 are the same gRPC class and each has a test. This deliberately does not
  copy the replay path's own handling of status 9 (`do_replay_one` still counts
  it as a success, because there the answer is authoritative about the session).
  A half open probe notification answered with a request-fault status is retired
  (not requeued, because requeueing could loop for ever when the answer does not
  move the breaker), the breaker is untouched, and the next held notification is
  probed at once; the server cannot return such a status for
  `NotifyStreamStatus` today, so this is defence in depth. A half open breaker
  that receives only request-fault answers or local failures stays half open
  until a real RPC or probe decides. Every other status still counts as a failure
  (1, 2, 4, 7, 8, 10, 12, 13, 14, 15, 16), as does every transport error, HTTP
  level error and exception out of the client. Not mirrored at the edge: an agent
  id of 1 to 256 bytes that holds a control character, a comma, or (for an id the server
  has not seen before) any character outside letters, digits, `.`, `_`, `:` and `-`, is refused by the
  server (`INVALID_ARGUMENT`, before enrolment; the agent sees it wrapped in `INTERNAL`) and reaches it, one upstream
  call per request; the classification means it cannot open the breaker, and its
  gateway log lines are rate limited. The two signals for an edge refusal are the
  counter `yuzu_gw_register_refused_total{reason="agent_id_length"}` (every
  refusal) and the ` (N similar line(s) suppressed since the last)` suffix on the
  `Register refused` line.
- **A systematic local encoder failure is invisible to the breaker and to
  `/readyz`.** INFERRED from the code and unit tests, not run on a rig. Because a
  local encode failure never moves the breaker, a gateway whose own encoder fails
  for every request (a broken build, say) keeps the breaker CLOSED and `/readyz`
  ready. Its signature is that every `Register` is answered `INTERNAL`
  (`Upstream registration failed: {internal,<<"rpc exception <Class>:<Why>">>}`),
  `Upstream RPC <Method> raised <Class>:<Why>` lines appear (one per second at
  most, with a suppressed count, see the next item) and
  `yuzu_gw_upstream_rpc_errors_total{code="encode"}` rises. The shipped
  `YuzuGatewayUpstreamErrors` alert (rate above 0.1 errors per second, no `code`
  filter) covers it only above that rate, so `YuzuGatewayUpstreamEncodeErrors`
  (about ten increases of `code="encode"` in 10 minutes, `increase()` being
  extrapolated, so one rejected request stays quiet) is the alert for this case. It is per `rpc_name` with no sum and needs about one encode a minute, which a Register fault reaches on a gateway fronting about five or more agents; a small gateway, or an encode fault only on `inventory`, `notify_stream` or `guardian`, can stay under it, and for those the `Upstream RPC ... raised` log line and `yuzu_gw_agents_current` are the signals. The `encode` series is pre-seeded to 0
  for `register`, `inventory`, `notify_stream` and `guardian`, and `exception` for
  those four plus `batch_heartbeat`; a marshal failure on the heartbeat buffer's
  flush is counted as `code="exception"` and is not covered by the encode alert.
  See the runbook row for that signature.
- **Warnings that a refused registration can trigger are rate
  limited.** INFERRED from the code and unit tests, not run on a rig. One
  limiter, `yuzu_gw_safe_call:warn_limited`, allows one line per second per kind,
  and the next line logged after the interval ends with ` (N similar line(s)
  suppressed since the last)`; the first line of a kind is never suppressed.
  Kinds (all warning level): `Register refused: ...` (the agent id bound), `Register
  from agent <agent>: the peer address was replaced or cut to fit ...`,
  `Upstream Register failed: <reason>` (also `answer is not a response
  message`), `Upstream ReportInventory failed: <reason>`, `Upstream RPC <Method>
  raised <Class>:<Why>` (local and remote exceptions) and `Upstream RPC <Method>
  failed: <Status> <message>` for the five request-fault statuses only (the same
  line for any other status is not limited). Consequence for an outage: during a
  genuine upstream outage the per-Register line `Upstream Register failed:
  circuit_open` is now one line per second with a suppressed count, where the
  earlier gateway logged one line per refused `Register`. The per-event signal in
  an outage is the lines that are not limited (the `Circuit breaker:` transitions)
  and the ` (N similar line(s) suppressed since the last)` suffix; a `circuit_open`
  rejection never reaches the call, so `yuzu_gw_upstream_rpc_errors_total` does not
  count it. Not limited and unchanged: breaker
  transition lines, replay lines (including the superseded-session line),
  `Failed to notify stream status`, the eviction warning, the killed-probe
  warning and the probe-deadline warning.
- **A successful probe does not prove registration works.** INFERRED from the
  code, not run. The probe is a `NotifyStreamStatus` call, an in-memory session
  lookup on the server. A server whose `Register` path is failing (for example a
  degraded database) can still answer it, so the breaker closes, the next verdict
  starts the replay, the call-path failures of the replay reopen the breaker after
  the threshold, and the cycle repeats at the base interval (10 s by default) with
  no exponential growth, because a success resets the backoff; a full replay runs
  at most once a minute in that cycle. Judge such a server by
  the `Upstream Register failed` and `Registration replay` lines, not by the
  breaker state alone.
- **The server's upstream port does not pin the gateway's identity, and TLS 1.3
  is not offered on the agent edge.** OBSERVED on a loopback rig with `openssl`
  and gRPC client probes (not a packet capture): at the TLS layer the server's
  upstream port admitted a client certificate that chains to the run's CA,
  including the server's own certificate, so a certificate is checked for its
  chain and not for being the gateway's (the management listener is the one that
  pins a key; the gRPC layer of the upstream port was not probed). The agent edge
  speaks one way TLS 1.2 only: a TLS 1.3 client was refused with a
  protocol-version alert. This manual does not claim that the gateway identity is
  pinned on the upstream port or that the agent edge negotiates TLS 1.3; neither
  is true of the shipped build.
- **A refused `Subscribe` ends with its own status.** The handler returns or throws
  `{grpc_error, {Status, Message}}` and the gRPC layer sends that status as the stream's
  trailers: `INVALID_ARGUMENT` (3) when `x-yuzu-session-id` is missing, `NOT_FOUND` (5)
  for a session with no pending registration, `UNAVAILABLE` (14) when the
  per-connection session cap refuses it. Any other return, throw or crash of a
  handler is `INTERNAL` (13) with one log line naming only the method, the exception
  class and the top frame; the request, the context and the exit term are never
  logged. (Rig pass 6 observed the previous transport ending such a stream with
  status 2 and an error report; that no longer applies.) From `agents/core/src/agent.cpp` (read, not run) the
  agent re-registers on any non-OK status either way.
- Related tracked items: #5244 (an idempotent adopt: a re-adopt of a session the
  server already holds wipes placement), #4632 (stream-status notifications held
  instead of dropped, the change described under "Stream Status Notification";
  its residuals are listed under the cold-start item above), #5278 (verdict
  follow-ups: the desync log seam and a concurrent-handler test) and #5313
  (re-registration load measurement).
- Planned follow-ups, tracked as follow-ups (no issue numbers yet), in this
  order: (i) a server-side re-arm of a tombstoned route row when a lease renewal
  comes up short, with a new advisory list that the gateway answers by
  re-announcing, which needs a protocol change and is planned to land before the
  safe-to-scale gate; (ii) a session-match guard and a refusal counter for the
  `accepted=false` disconnect; (iii) a server test that runs two overlapping
  `NotifyStreamStatus` handlers for one session (none was found in
  `tests/unit/server`; the gateway's per-key replacement relies on the server
  converging when a `CONNECTED` and a `DISCONNECTED` for one session overlap,
  INFERRED from the code, not run); (iv) alerts for pending
  stuck, in-flight saturated and the `at_capacity` loss (the `code="encode"`
  alert and the pre-seeding of the `encode` and `exception` values have shipped);
  (v) refusing at the edge an agent id with a control character or a comma,
  which the server already refuses.

---

### Planned stop

A planned stop (`application:stop/1`, which the release runs on SIGTERM: `docker
stop`, `systemctl stop`) tells the server about every session the gateway gives up
(#5695). Before the processes stop (`yuzu_gw_app:prep_stop/1`), within one budget,
`shutdown_flush_budget_ms` (20 s by default):

1. Proxied `Register` and inventory calls are refused `UNAVAILABLE`, so agents
   register through another gateway; no registration replay runs; the
   held-notification cap is raised by twice the sessions held.
2. The agent listeners are suspended (Ranch keeps the established connections;
   new ones are refused) after the memory shedder is stopped, so nothing resumes
   them. The router stops taking commands, and in-flight commands get up to 3 s
   (or 30% of the budget) to finish.
3. Every session is ended through its own agent process, which closes its stream
   and sends the `DISCONNECTED` notice with the session's stream home id (the
   server matches a `DISCONNECTED` to the placement by it; it is kept by the
   agent process and its row in the owner table, not by the routing table). Up
   to 5 s (or 40% of the budget) for them to finish. An agent process that is
   restarted after a crash during the stop sends its session's `DISCONNECTED`
   and stops: its re-registration is refused (`stopping`), so no session comes
   back, and no session gets a second `DISCONNECTED`.
4. The heartbeat buffer is flushed.
5. Every held notification is sent, whatever the breaker state, 64 at a time,
   until none is left or the budget ends. What is left is counted in
   `yuzu_gw_upstream_notify_lost_total{reason="shutdown"}` and named in one WARN
   (`Planned stop: <n> stream-status notification(s) sent, <m> not sent by the
   flush deadline`); a failed send is not retried. A notification the server
   refused (`acknowledged=false`) and that waits for a resend is sent here if it
   is a `DISCONNECTED`, and dropped if it is a `CONNECTED` (counted
   `reason="shutdown"`); a refusal during the flush is not resent
   (`reason="unacknowledged"`). Later notifications are counted, not sent.

The `/metrics` endpoint keeps answering through the drain and the shutdown of
the processes, and is stopped last (`yuzu_gw_app:stop/1`). Before #5695 it was
left to the application master's final clean-up, which killed the process that
owns its listening socket under it, and every stop logged about 20 crash
reports and as many supervisor reports from the inets `httpd_acceptor`
(`noproc` on `link`); the scale suite's `planned_stop` case counted 67 at 500
agents, and counts 0 now (it fails on any).

Measured with a mocked server: 100 sessions, 100 `DISCONNECTED` notices delivered
before `application:stop/1` returned (0 before #5695: the drain ran after the
processes were gone); with a server that never answers, the stop returned 1.5 s
after a 1.5 s budget and counted all 100 as lost.

**Stop timeout coupling.** The budget must fit inside the container's or unit's
stop timeout, with room for the processes to stop after it. Docker's default is
10 s before SIGKILL, so every shipped compose file sets `stop_grace_period: 40s` on
the gateway service, and `deploy/systemd/yuzu-gateway.service` sets
`TimeoutStopSec=40`. Raise them together with `shutdown_flush_budget_ms`. A SIGKILL,
a crash or a stop that outlasts the timeout sends nothing: the server keeps those
sessions listed as online until the agents register again. At 5,000 sessions and
50 ms per server call the flush takes about 4 s (64 at a time); a server at 200 ms
per call needs about 16 s, close to the default budget (arithmetic, not measured at
that scale). A server batch call ("this
gateway is going away; these sessions are gone") would make it one call; it is not
implemented.

### When an agent's owner process crashes

Each agent session is held by one Erlang process on the gateway, its owner
(`yuzu_gw_agent`). Owners do not crash in normal operation; when one does (a
gateway defect, or an operator killing it), the gateway does what the agent's
own reconnect would do, faster, and without dropping the agent where it can
avoid it (#5695):

1. **The supervisor restarts the owner.** `yuzu_gw_agent_sup` restarts an owner
   that ended abnormally (its children are `transient`); an owner that ends
   normally (the agent disconnected, a refused registration) or is shut down (a
   planned stop) is not restarted.
2. **The restarted owner sends the `DISCONNECTED`** for the session its
   predecessor held, with the predecessor's stream home id, so the server stops
   showing the agent as connected through a process that no longer exists.
   Before #5695 nothing told the server: it kept the agent listed as connected
   until the agent itself reconnected, which took about 54 s in an independent
   tester's runs (the agent's next heartbeat was refused, then it registered
   again). The session's details survive the crash in the owner table (an ETS
   table owned by `yuzu_gw_sup`, one row per owner, written when the session is
   set up and removed when the owner ends for good). Exactly one process sends
   a session's `DISCONNECTED`: the owner itself when it ends the session, or
   its successor after a crash.
3. **It tries to recover the agent.** The agent's Subscribe stream is a separate
   process that watches its owner; after an abnormal owner exit it waits up to
   5 s for the restarted owner to re-attach, and ends the stream otherwise. If
   the stream is still open, the restarted owner re-attaches, waits until the
   `DISCONNECTED` has reached the server (or been refused, or counted lost; a
   refused one is not sent again: its resend, and any resend of the
   predecessor's refused notices, is cancelled and counted
   `yuzu_gw_upstream_notify_unacked_ended_total{outcome="superseded"}`, so none
   reaches the server after the next step), registers the
   session again in the routing table, presents the same session to the server
   again (a `ProxyRegister` carrying the session id, as a registration replay
   does), and announces `CONNECTED` for it with the same stream home id. The
   agent keeps its connection and its session; commands reach it again at once.
   If the stream is gone, or any of these steps fails (the agent registered a
   newer session meanwhile, the server is unreachable, the server answers that
   another session holds the agent), the owner closes the stream and ends after
   the `DISCONNECTED`: the agent reconnects by itself.

   The agent's heartbeats stay admitted, on the connection the session is bound
   to, from the owner's death until the restarted owner has registered the
   session again or ended it. The registry drops a dead owner's session at
   once, and the restarted owner registers it again only after the
   `DISCONNECTED` has settled, which with hundreds of owners killed at once
   waits behind the other notices (up to about 0.4 s for 500 on a 16-core
   host). Heartbeat admission therefore also accepts a session whose owner, in
   the owner table, is dead or is a restarted owner recovering it (not one
   being ended, and not one superseded by a newer session of the agent). A live
   owner missing from the registry because the registry itself restarted is not
   covered: those heartbeats still fail closed, so the agent registers again. Before this, a heartbeat that fell in the gap was
   answered `NOT_FOUND`, and the agent dropped the stream the owner was
   recovering and registered a new session: 1 to 3 of 500 killed owners per run
   at 5,000 agents.
4. **A crash loop gives up.** One owner may be restarted at most 3 times within
   60 s. The next restart sends the `DISCONNECTED` if it was not already sent,
   closes the stream and ends, logging one WARN (`owner process restarted more
   than 3 times in 60 s; giving up`) with the agent id.
5. **A crash of most of the fleet's owners escalates.** The supervisor's restart
   intensity is shared by every owner: `agent_restart_intensity` restarts
   (default 2000) within `agent_restart_period_s` (default 10). An induced loss
   of 10% of a 5,000-agent gateway's owners stays below it; a fault that crashes
   more than 2000 owners within 10 s is a fault of the gateway, and the agent
   supervisor stops. Every owner still running sends its session's
   `DISCONNECTED` on the way down and its stream closes, so those agents
   reconnect. The gateway supervisor starts a new agent supervisor, which
   restarts an owner for every session left without one (it sends that
   `DISCONNECTED` and recovers the session if its stream is still open). If the
   fault persists, the gateway supervisor's own limit (10 restarts in 60 s)
   stops the application and the container or systemd unit restarts the
   gateway. Raise `agent_restart_intensity` for a gateway that holds far more
   than 5,000 agents (about 40% of its agents keeps the same margins).

What is lost: commands that were in flight at the crash. After an exception
the dying owner answers their callers `agent_disconnected`; after a kill
nothing can, and the router ends them at their timeout (300 s by default). The
agent's replies to them arrive at the restarted owner and are dropped.

Each restart writes the usual crash or supervisor report (one per crash,
redacted) and one line naming the outcome. The outcomes are counted in
`yuzu_gw_agent_owner_restarts_total{outcome}`: `recovered`,
`disconnected_only`, `gave_up`. `YuzuGatewayAgentOwnerCrashLoop` fires for 30
minutes after a give-up; a recovered restart raises no alert.

Measured (EUnit, mocked server): a killed owner's `DISCONNECTED` reached the
server 0.1 ms after the kill and the session was `CONNECTED` again 0.06 ms
later, with a command reaching the agent on the same stream. Scale suite
(`owner_kill`, 500 agents, 50 owners killed at once): 50 `DISCONNECTED`
received, all 50 sessions recovered within 22 ms, no agent reconnected, every
command to them answered, no supervisor restart; at 5,000 agents with 500
owners killed at once, all 500 recovered within 147 ms, the same way. On the
code before #5695 the 500-agent run received 0 `DISCONNECTED` and every one of
the 50 agents had to reconnect.

## Building and Testing

### Prerequisites

- Erlang/OTP 28.4 or any later 28.x (OTP 29 is not yet supported; `meson setup` skips the gateway with a warning on any other release)
- rebar3

The `rebar3` commands below run on whichever `erl` is first on PATH and do not check its
version. Run `source scripts/ensure-erlang.sh` from the repository root first to put the
pinned release on PATH.

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
| cowboy / ranch | 2.19.0 / 2.3.0 | HTTP/2 server and listener behind the gateway's own gRPC layer (`yuzu_grpc*`) |
| gun | 2.5.0 | HTTP/2 client behind the upstream gRPC client (`yuzu_grpc_client`); needs cowlib, which cowboy brings too |
| ctx | 0.6.0 | The request-context type of the gRPC layer |
| gpb | 4.21.7 | Protobuf compiler and runtime |
| telemetry | 1.3.0 | Metrics event API |
| prometheus | 4.11.0 | Prometheus exposition |
| prometheus_httpd | 2.1.2 | HTTP endpoint for Prometheus scraping |
| recon | 2.5.5 | Production introspection |

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
| `yuzu_gw_upstream_rpc_errors_total` | counter | Upstream RPC errors (labels `rpc_name`, `code`). `code` is the gRPC status number the server answered (`"16"` and so on) or, for a failure before any status, one of these words: `closed`, `econnrefused`, `timeout`, `connection_lost` (the call's connection closed or went away, since #5695), `stream_error` (the server reset that one call), `too_many_streams` (the gateway's own HTTP/2 client did not open the stream, because the connection was at the server's concurrent-stream limit; nothing was sent. Counted as `stream_error` before this was told apart), `protocol`, `response_too_large`, `invalid_metadata`, `no_channel`, `exception`, `encode`, `other`, or `{tls_alert,<Alert>}` for a TLS alert (for example `{tls_alert,certificate_required}`). Alerts keyed on `code="16"` or on `yuzu_gw_upstream_tls_handshake_failures_total` are unchanged |
| `yuzu_gw_upstream_rpc_errors_total{code="exception"}` | counter series | An exception out of the client or transport. It counts against the circuit breaker on the `Register` and `ProxyInventory` call paths, a stream-status notification worker (while the breaker is closed), the half-open notification probe and a registration replay; a guardian forward and the heartbeat buffer's own flush do not feed the breaker. Pre-seeded to 0 for `register`, `inventory`, `notify_stream`, `guardian` and `batch_heartbeat`. |
| `yuzu_gw_upstream_rpc_errors_total{code="encode"}` | counter series | A request that failed in the gateway's own encoder, including one over 4194304 bytes: local, never sent, no breaker effect. Pre-seeded to 0 for `register`, `inventory`, `notify_stream` and `guardian`; `batch_heartbeat` has no `encode` series, because a marshal failure on the heartbeat buffer's flush is counted as `code="exception"` and is not covered by the `YuzuGatewayUpstreamEncodeErrors` alert. That alert fires at about ten increases in 10 minutes (`increase()` is extrapolated). Other `code` values appear at their first occurrence. A `circuit_open` rejection never reaches the call and is not counted here. |
| `yuzu_gw_register_refused_total` | counter | `Register` calls the gateway edge refused before any upstream call because the agent id was empty or longer than 256 bytes (label `reason`, closed set `agent_id_length` and `unknown`; both created at 0 at start). No label is derived from agent data. |
| `yuzu_gw_registration_replay_total` | counter | Total registration replay attempts by the drip, any outcome. The drip runs after the upstream circuit breaker recovers, and when a heartbeat verdict lists sessions the gateway still holds |
| `yuzu_gw_registration_replay_queue_depth` | gauge | Agents still queued for registration replay, whether queued by a full replay or by a heartbeat verdict (0 = idle, label `node`). A non-zero value is normal while a replay runs: up to `upstream_replay_concurrency` (24) entries are replayed at once, each taking the `ProxyRegister` RPC time, so 5,000 agents at 50 ms per call take about 10 s, and a full replay counts every agent the node holds. A value that does not fall over longer than that points to a replay that is not draining (INFERRED). No alert rule ships for it. |
| `yuzu_gw_registration_replay_triggered_total` | counter | Registration replays started, by `trigger` (`breaker` = the upstream recovered and every agent this node holds is queued for replay, unless a verdict-seeded drip is already queued, in which case the trigger is dropped, `heartbeat` = a heartbeat verdict listed sessions the server does not know and only those are replayed). Both series are created at 0 at start. |
| `yuzu_gw_heartbeat_unknown_truncated_total` | counter | `BatchHeartbeat` responses whose list of unknown sessions the server truncated at 4096. Sessions beyond the cap may be reported again by later heartbeats. Every occurrence is counted; the matching WARN is logged at most once per 60 s per heartbeat buffer process (the limit resets when that process restarts). |
| `yuzu_gw_heartbeat_verdict_dropped_total` | counter | Session ids named by a heartbeat verdict that were not queued for replay (label `reason`, closed set: `malformed` = not a usable session id, `not_local` = this node does not hold the session, `circuit_open` = the upstream circuit breaker is open, `queue_full` = the replay queue is at its cap, or the upstream process already holds more than 100 unhandled messages so the ids were not handed to it; the cap bounds only verdict appends, not the walk of a full replay). Every reason is created at 0 at start. Ids already queued, or replayed within the session guard window, are not counted. |
| `yuzu_gw_heartbeat_buffer_dropped_total` | counter | Heartbeat state the gateway's heartbeat buffer dropped instead of sending (label `reason`, closed set of six, all created at 0 at start: `buffer_full` = a heartbeat of a new session was dropped because the buffer held `max_heartbeat_buffer` sessions, or the oldest whole session was dropped because the buffer was still over `max_heartbeat_buffer_bytes` with no snapshot left to drop; `snapshot_oversize` = a single heartbeat larger than about 3 MiB was sent without its snapshot; `snapshot_evicted` = a retained snapshot was dropped, oldest first, because the buffer was over `max_heartbeat_buffer_bytes`; `heartbeat_oversize` = a heartbeat still larger than about 3 MiB after its snapshot was removed, or with more than 512 status tags, or with a status tag key or value over about 64 KiB or more than about 256 KiB of tag bytes in total (checked before the UTF-8 repair), was forwarded without its status tags; `heartbeat_invalid` = a heartbeat with a status tag that is not valid UTF-8 was forwarded with the invalid bytes replaced by replacement characters (the reason also counts tags removed because a tag was not a binary, and a heartbeat dropped for a bad or empty session id; see Heartbeat Batching); `chunk_rejected` = a single heartbeat the server rejected with a non-transient status was dropped). What is lost is older heartbeat state; for `heartbeat_oversize` the status tags of one heartbeat, for `heartbeat_invalid` only the invalid bytes, and for `chunk_rejected` one whole heartbeat. See [Heartbeat Batching](#heartbeat-batching). |
| `yuzu_gw_heartbeat_coalesced_total` | counter | Buffered heartbeats replaced by a newer heartbeat of the same session (unlabelled). Expected to rise while the server is unreachable. While a backlog is coalesced, the server's `yuzu_heartbeats_received_total{via="gateway"}` under-counts, because it counts the heartbeats the server received. |
| `yuzu_gw_upstream_notify_pending` | gauge | Stream-status notifications held because the in-flight limit is reached or the upstream circuit breaker is not closed; drained first in first out (0 = nothing held). The key of a half open probe in flight is not counted here (it is counted by `yuzu_gw_upstream_notify_inflight`), unless a newer notification for the same key has since been held, and the key still counts toward the `notify_pending_max` cap. The gauge can equal `notify_pending_max` without any loss, so do not alert on that; alert on `increase(yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}[5m]) > 0`. Label `node`, created at 0 at start. Counts the current upstream client process only |
| `yuzu_gw_upstream_notify_inflight` | gauge | NotifyStreamStatus workers tracked by this gateway process (at most 10). Label `node`, created at 0 at start. Counts the current upstream client process only: workers of a previous process after an upstream client restart are not counted |
| `yuzu_gw_upstream_notify_coalesced_total` | counter | Held stream-status notifications replaced by a newer event for the same agent session and stream home, or a failed probe notification superseded by one. Unlabelled, created at 0 at start. It measures suppression, not delivery: an identical repeated `CONNECTED` also counts |
| `yuzu_gw_upstream_notify_dropped_total` | counter | Stream-status notifications lost at admission because the pending store was at its cap: a new key is admitted only while the held keys plus the key of a half open probe in flight stay below `notify_pending_max` (label `reason`, closed set `at_capacity` and `unknown`, both created at 0 at start; `unknown` catches an unexpected value and is not emitted today). The value `circuit_open` is retired: a notification that arrives while the breaker is not closed is held, and only an older gateway still exports it. It does not count delivery loss after admission (a failed or killed worker, a gateway stop) |
| `yuzu_gw_cluster_peers_resolved` | gauge | Peer addresses found by the cluster-formation redial loop's most recent tick (label `node`; HA WS-4 `#4555`). 0 is expected for a genuinely single-node deployment. |
| `yuzu_gw_cluster_peers_connected` | gauge | Distribution-connected peer nodes as of the most recent redial tick (label `node`; `#4555`). Compare against `peers_resolved` — a sustained gap most often means a distribution-cookie mismatch across replicas. |
| `yuzu_gw_cluster_connect_failures_total` | counter | Total `net_kernel:connect_node/1` failures from the redial loop (`#4555`). |
| `yuzu_gw_cluster_address_cap_exceeded_total` | counter | Total times the lifetime distinct-address cap (`cluster_max_lifetime_addrs`) refused a never-before-seen address (`#4555` review round 2). Any non-zero value should be investigated immediately — it means the seed DNS name is returning an unexpectedly large or rotating/hostile answer set. |
| `yuzu_gw_heartbeat_rejected_total` | counter | Agent `Heartbeat` calls rejected before buffering because no usable session binding exists (label `reason`, closed set: `unknown_session` = the session is not held by this node, `no_connection` = no connection key to compare, `registry_unavailable` = the session index does not exist). Every reason is created at 0 at start. The agent re-registers on the `NOT_FOUND` answer when its build includes the reconnect fix (see the gateway manual); older agents only log it. A held session whose heartbeat arrived on a different connection is counted in the next row instead. See [Heartbeat admission](#heartbeat-admission). |
| `yuzu_gw_heartbeat_session_mismatch_total` | counter | Agent `Heartbeat` calls rejected because the session is held by this node but the call arrived on a different connection than the one that opened it (label `event`, always `security`, for SIEM routing; created at 0 at start). Also rises when an HTTP/2 proxy between agents and the gateway spreads one agent's calls over several connections. A rise of one per affected agent is expected when an agent's connection is replaced while its session is still held (observed with an injected GOAWAY, a test-only trigger; not observed with an abrupt close or a gateway restart). There is no audit row (the sender of a rejected heartbeat is not a resolved principal): the counter and a rate-limited summary log line are the signal. |
| `yuzu_gw_grpc_origin_ignored_total` | counter | gRPC calls on a listener configured as behind a proxy whose claimed client address was not used (labels `mode` = `proxy_protocol` or `forwarded_for`, `reason` = `untrusted_source`, `no_claim` or `bad_claim`). The call is served either way: for `untrusted_source` it is attributed to the TCP peer, for `no_claim` and `bad_claim` it is sent upstream with no observed address (empty `gateway_observed_peer`; the server records `origin_observed=false`). Created at 0 for every pair at start; no listener label. See [Client addresses behind a proxy](#client-addresses-behind-a-proxy) and [Origin counters](#origin-counters). |
| `yuzu_gw_grpc_dropped_data_bytes_total` | counter | Request bytes the gRPC layer discarded in a state that must not run a handler (label `reason`, closed set: `extra_request_data` = a second message on a unary call, `stream_ended` = data after the stream's status). |
| `yuzu_gw_upstream_calls_dropped_total` | counter | Proxied `Register` or inventory calls not sent because the caller's deadline passed while it waited for a permit, or left too little time (250 ms) to make the call (label `rpc_name`, closed set `register` and `inventory`, both created at 0 at start). Nothing is sent for them, so no server session is created. Before #5695 it counted queued calls of callers that had exited. |
| `yuzu_gw_upstream_permits_held` | gauge | Upstream call permits held now, by `class` (`register`, `replay`, `inventory`; created at 0). `register` and `replay` share one pool (see "Upstream call permits") |
| `yuzu_gw_upstream_permits_waiting` | gauge | Callers waiting for a permit now, by `class`. Non-zero for `register` or `inventory` means every permit of the pool is held |
| `yuzu_gw_upstream_permit_limit` | gauge | Permits in force, by `class` (`replay` is the most of the register pool a replay may hold): the configured size, or less when the server's stream limit leaves less room (see "How the gateway sizes its upstream calls") |
| `yuzu_gw_upstream_server_max_streams` | gauge | Concurrent streams the server allows on the gateway's upstream connections together, as it declared them (`SETTINGS_MAX_CONCURRENT_STREAMS`, summed over the connections). Created at 0; 0 also means nothing is known (no connection up) or the server declared no limit, and then the configured permit sizes apply. No label: the gateway makes its upstream calls on one channel |
| `yuzu_gw_upstream_permit_refused_total` | counter | Permits refused, by `class` and `reason` (`queue_full`, `deadline`, `stopping`; every pair created at 0). The agent is told `UNAVAILABLE` and retries |
| `yuzu_gw_upstream_permit_wait_seconds` | histogram | Seconds a granted permit was waited for, by `class` |
| `yuzu_gw_registration_replay_outcomes_total` | counter | Registration replay entries by `outcome` (`adopted`, `superseded`, `rejected`, `failed`, `skipped`, `aborted`; created at 0) |
| `yuzu_gw_registration_replay_last_duration_seconds` | gauge | Seconds the last finished registration replay took (0 until one finished). Measured with a mocked server: 2,000 agents at 10 ms per call in 0.94 s, 24 in flight |
| `yuzu_gw_upstream_notify_lost_total` | counter | Stream-status notifications lost, by `event` (`connected`, `disconnected`) and `reason`: `at_capacity` (refused at a full store), `evicted` (a held `CONNECTED` evicted for a `DISCONNECTED`; a full replay re-sends it), `rejected` (a bad-request answer or an encode failure), `crashed` (the send's worker died without a result), `shutdown` (left by a planned stop's flush). Every pair created at 0 |
| `yuzu_gw_upstream_notify_requeued_total` | counter | Stream-status notifications whose send failed and that were held again to be retried |
| `yuzu_gw_upstream_notify_pending_hwm` | gauge | Most stream-status notifications held at once over the last one to two minutes |
| `yuzu_gw_upstream_notify_pending_max` | gauge | The held-notification cap in force (`notify_pending_max`) |
| `yuzu_gw_upstream_backpressure_seconds_total` | counter | Seconds during which the path to the server was backed up: at least one lane saturated (a live `Register` or inventory report waiting for a permit, all 10 stream-status notification slots held, or all 50 Guardian forward slots held). `rate()` of it is the backpressure duty cycle, 0 to 1. Sampled every 100 ms. See "Slow server" |
| `yuzu_gw_upstream_lane_saturated_seconds_total` | counter | The same, per lane (label `lane`: `permits` (`serial` before #5695), `notify`, `guardian`; all three created at 0 at start). The lanes overlap, so never add them: the figure for the gateway as a whole is the counter above |
| `yuzu_gw_upstream_backpressure_duty_cycle` | gauge | The backpressure duty cycle over the last 60 s, 0 to 1. Reads low for the first minute after a start (the missing seconds count as not saturated) |
| `yuzu_gw_upstream_slow` | gauge | 1 when the duty cycle above is 0.5 or more (a slow server, as this gateway sees it), else 0. Not a readiness input |
| `yuzu_gw_session_limit_rejected_total` | counter | Registrations refused because one connection already holds the configured number of agent sessions, pending plus live (`max_sessions_per_connection`, default 8). Unlabelled, created at 0 at start. A `Register` over the cap is answered `UNAVAILABLE` (14); a `Subscribe` over the cap is also answered `UNAVAILABLE` (14) and is counted the same. A stock agent holds one session per connection (INFERRED), so a rise points to an L4 balancer, forwarder or client that carries several agents on one connection; see "Per-connection session cap" under Configuration. |
| `yuzu_gw_mgmt_auth_rejected_total` | counter | Management-listener (`:50063`) streams refused by the SPKI peer pin, by `reason` (closed set: `pin_mismatch`, `missing_server_auth_eku`, `no_pins_resolved`, `no_pins_configured`, `bad_peer_cert`, `bad_pin_config`, `internal_error`; all created at 0 at start). Alerts: `YuzuGatewayMgmtAuthRejected` (every reason but `pin_mismatch`), `YuzuGatewayMgmtPinMismatch` |
| `yuzu_gw_mgmt_auth_pin_unresolved_total` | counter | Management auth attempts during which at least one configured `mgmt_peer_pins` entry did not resolve (a typo'd fingerprint, or a pin file never readable since start) |
| `yuzu_gw_mgmt_pin_rotated_timestamp_seconds` | gauge | Unix time at which the pin watcher last published a different key for a `{cert_file, Path}` pin; 0 until the first such change in the process (created at 0 at start). Used by `YuzuGatewayMgmtPinMismatch` to stay quiet through a rotation |
| `yuzu_gw_cert_expiry_timestamp_seconds` | gauge | `notAfter` in Unix seconds of each configured certificate file, the earliest for a file with several certificates (labels `role` = `listener`, `listener_ca`, `upstream_client`, `upstream_ca`, `mgmt_peer_pin`; `name` = listener or channel name, or the pin file's name). Keeps the last value read if the file becomes unreadable; absent for a file never read. Alerts: the `YuzuGatewayCertificateExpir*` ladder |
| `yuzu_gw_cert_file_readable` | gauge | 1 when the latest read of every certificate file under that `role` and `name` parsed, 0 when a stat, read or parse failed. Alerts: `YuzuGatewayMgmtPinUnresolved` (`mgmt_peer_pin`), `YuzuGatewayCertificateFileUnreadable` (the other roles) |
| `yuzu_gw_process_mailbox_len` | gauge | Messages waiting in the mailbox of a named gateway process, labeled by `process` (closed set: `upstream`, `upstream_regulator`, `registry`, `router`, `heartbeat_buffer`, `agent_sup`, `pg`, `upstream_channel`, `logger`; all created at 0). Sampled every `telemetry_gauge_interval_ms`. Alert: `YuzuGatewayProcessBacklogged` (over 10,000 for 10 minutes) |
| `yuzu_gw_process_queue_wait_seconds` | gauge | How long a message sent to that process waited before it was handled (a probe's round trip each sample; while a probe is unanswered, the time since it was sent), labeled by `process` |
| `yuzu_gw_listener_connections` | gauge | Connections a gRPC listener holds (Ranch active connections), labeled by `listener` role (`agent`, `management`, `other`; all created at 0) |
| `yuzu_gw_listener_max_connections` | gauge | That role's `limits.max_connections`; no series without a ceiling (the default). Alert: `YuzuGatewayListenerNearConnectionCeiling` (over 90% for 10 minutes) |
| `yuzu_gw_mgmt_streams_inflight` | gauge | Calls the management listener is running a handler for |
| `yuzu_gw_router_fanouts_inflight` | gauge | Command fan-outs the router is tracking, set by the router whenever the number changes |
| `yuzu_gw_beam_ports` | gauge | Ports open in the gateway VM (each TCP connection is one). Alert: `YuzuGatewayFileDescriptorsNearLimit` (over 90% of either limit below for 10 minutes) |
| `yuzu_gw_beam_port_limit` | gauge | The most ports the VM can open (`+Q`) |
| `yuzu_gw_beam_fd_limit` | gauge | The open-files limit the VM found at start; no series where the VM does not report one |
| `yuzu_gw_beam_run_queue` | gauge | Processes waiting for a scheduler (`total_run_queue_lengths`) |
| `yuzu_gw_grpc_connections_closed_total` | counter | Connections the gateway's HTTP/2 server closed itself, labeled by `listener` role and `reason` (`idle_timeout`, `enhance_your_calm`, `protocol_error`; every pair created at 0); counted once per connection that had a call open. A memory-ceiling kill is counted in `yuzu_gw_grpc_connection_killed_total` |

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
