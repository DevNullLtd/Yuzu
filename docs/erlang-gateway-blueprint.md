# Erlang Gateway Blueprint for Yuzu

## Problem Statement

The current `yuzu-server` runs command dispatch and response aggregation in a
single C++ process. Every `Subscribe()` bidi stream holds a per-agent
`stream_mu` mutex; `send_to_all()` iterates all agents serially, acquiring each
lock in turn. At millions of agents this creates:

1. **Lock convoy** — a single slow agent write stalls the broadcast loop.
2. **Thread exhaustion** — each incoming command thread contends on a shared
   mutex (`mu_`) protecting `std::unordered_map<agent_id, AgentSession>`.
3. **Single-box ceiling** — one gRPC server process cannot hold millions of
   persistent bidi streams.

The Erlang gateway ("yuzu-gateway") sits between operators/dashboards and the
C++ server, owning the *command fanout plane* and *response aggregation plane*
while the C++ server retains the *control plane* (enrollment, auth, inventory,
dashboard).

---

## Architecture Overview

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                   Operator / Dashboard                  │
                  │           (ManagementService.SendCommand)               │
                  └────────────────────────┬────────────────────────────────┘
                                           │ gRPC (or HTTP/2)
                                           ▼
                ┌──────────────────────────────────────────────────────────┐
                │              yuzu-gateway  (Erlang/OTP cluster)          │
                │                                                          │
                │   ┌──────────┐  ┌──────────┐       ┌──────────┐        │
                │   │ gw_node1 │  │ gw_node2 │  ...  │ gw_nodeN │        │
                │   └──────────┘  └──────────┘       └──────────┘        │
                │        │              │                   │              │
                │    agent_proc     agent_proc         agent_proc          │
                │    agent_proc     agent_proc         agent_proc          │
                │    agent_proc     agent_proc         agent_proc          │
                └──────┬───────────────┬───────────────────┬──────────────┘
                       │               │                   │
                       ▼               ▼                   ▼
                  ┌─────────┐    ┌─────────┐         ┌─────────┐
                  │ Agent 1 │    │ Agent 2 │   ...   │ Agent M │
                  └─────────┘    └─────────┘         └─────────┘
                       │               │                   │
                       └───────────────┼───────────────────┘
                                       │ Register, Heartbeat,
                                       │ Inventory, Enrollment
                                       ▼
                              ┌──────────────────┐
                              │  yuzu-server     │
                              │  (C++ control    │
                              │   plane)         │
                              └──────────────────┘
```

**Key split:**

| Plane | Owner | Responsibilities |
|-------|-------|-----------------|
| Control | `yuzu-server` (C++) | Register, Heartbeat, enrollment tiers, auth, inventory, dashboard, mTLS termination |
| Command | `yuzu-gateway` (Erlang) | Subscribe bidi streams to agents, SendCommand fanout, response aggregation, streaming relay |

---

## OTP Application Structure

```
yuzu_gateway/
├── rebar.config
├── config/
│   └── sys.config              % Node name, gRPC listen port, C++ upstream,
│                               % Erlang distribution cookie, telemetry sinks
├── apps/
│   └── yuzu_gw/
│       ├── src/
│       │   ├── yuzu_gw_app.erl            % application behaviour
│       │   ├── yuzu_gw_sup.erl            % top-level supervisor
│       │   │
│       │   ├── %% ── Agent Connection Layer ──
│       │   ├── yuzu_gw_agent_sup.erl      % simple_one_for_one for agent procs
│       │   ├── yuzu_gw_agent.erl          % gen_statem: one per agent bidi stream
│       │   │
│       │   ├── %% ── Routing / Registry ──
│       │   ├── yuzu_gw_registry.erl       % pg (process groups) + ETS routing table
│       │   ├── yuzu_gw_router.erl         % gen_server: command fanout coordinator
│       │   │
│       │   ├── %% ── Upstream (C++ server) ──
│       │   ├── yuzu_gw_upstream.erl       % gen_server: gRPC client pool to yuzu-server
│       │   │
│       │   ├── %% ── Operator-facing gRPC ──
│       │   ├── yuzu_gw_mgmt_service.erl   % grpc server: ManagementService.SendCommand
│       │   ├── yuzu_gw_agent_service.erl  % grpc server: AgentService proxy (Register→upstream)
│       │   │
│       │   ├── %% ── Telemetry ──
│       │   ├── yuzu_gw_telemetry.erl      % telemetry event definitions + handlers
│       │   │
│       │   └── %% ── Proto helpers ──
│       │       └── yuzu_gw_proto.erl      % encode/decode wrappers (gpb or grpc_client)
│       │
│       └── priv/
│           └── proto/                     % Symlink or copy of proto/ from repo root
│               ├── yuzu/agent/v1/agent.proto
│               ├── yuzu/common/v1/common.proto
│               └── yuzu/server/v1/management.proto
```

### Dependencies

```erlang
%% rebar.config
{deps, [
    {grpcbox,   "0.17.1"},     % gRPC server + client (HTTP/2, protobuf)
    {gpb,       "4.21.7"},     % Protobuf compiler/runtime (grpcbox dep)
    {telemetry,  "1.3.0"},     % Metrics event API
    {prometheus, "4.11.0"},    % Prometheus exposition (telemetry handler)
    {recon,      "2.5.5"}      % Production introspection
]}.
```

---

## Process Model

### 1. `yuzu_gw_agent` — One Erlang Process per Agent (gen_statem)

This is the core scaling insight: Erlang can sustain **millions of lightweight
processes**, each holding the state for one agent's bidi stream. No mutexes —
message passing provides serialization.

```
States:
  ┌──────────────┐
  │  connecting   │  Agent called Register → upstream forwarded → got session_id
  └──────┬───────┘
         │ Subscribe stream established
         ▼
  ┌──────────────┐
  │   streaming   │  Bidi stream active; agent_proc owns the stream writer
  └──────┬───────┘
         │ stream broken / heartbeat timeout
         ▼
  ┌──────────────┐
  │ disconnected  │  Cleanup, deregister from routing table, terminate
  └──────────────┘
```

**Key properties:**

- The process **owns** the gRPC stream writer handle. All writes to this agent
  go through its mailbox — no mutex needed.
- Incoming `CommandRequest` messages are delivered via `gen_statem:cast/2`.
  The process writes to the stream immediately; backpressure is handled by
  the HTTP/2 flow control window.
- Incoming `CommandResponse` frames from the agent are read in the process's
  receive loop and forwarded to the originating `yuzu_gw_router` request.

```erlang
%% Simplified state machine sketch
-module(yuzu_gw_agent).
-behaviour(gen_statem).

-record(data, {
    agent_id    :: binary(),
    session_id  :: binary(),
    stream_ref  :: grpcbox:stream_ref(),
    plugins     :: [binary()],
    pending     :: #{command_id() => from()}   % who to send responses to
}).

%% In 'streaming' state, handle command dispatch:
streaming(cast, {dispatch, CommandReq, ReplyTo}, Data) ->
    CmdId = maps:get(command_id, CommandReq),
    ok = grpcbox_client:send(Data#data.stream_ref, CommandReq),
    telemetry:execute([yuzu, gw, command, dispatched],
                      #{count => 1},
                      #{agent_id => Data#data.agent_id, plugin => maps:get(plugin, CommandReq)}),
    {keep_state, Data#data{pending = maps:put(CmdId, ReplyTo, Data#data.pending)}};

%% Incoming response from agent stream:
streaming(info, {grpc_data, _StreamRef, ResponseFrame}, Data) ->
    CmdId  = maps:get(command_id, ResponseFrame),
    Status = maps:get(status, ResponseFrame),
    case maps:find(CmdId, Data#data.pending) of
        {ok, ReplyTo} ->
            ReplyTo ! {command_response, Data#data.agent_id, ResponseFrame},
            Pending2 = case Status of
                'RUNNING' -> Data#data.pending;          % keep tracking
                _Final    -> maps:remove(CmdId, Data#data.pending)
            end,
            {keep_state, Data#data{pending = Pending2}};
        error ->
            %% Orphaned response — log and drop
            {keep_state, Data}
    end;

streaming(info, {grpc_closed, _StreamRef}, Data) ->
    {next_state, disconnected, Data}.
```

**Memory per process:** ~2 KB base + pending command map. At 1M agents ≈ 2–4 GB
(trivially shardable across a cluster).

### 2. `yuzu_gw_agent_sup` — simple_one_for_one

```erlang
%% Child spec
#{id       => agent,
  start    => {yuzu_gw_agent, start_link, []},
  restart  => temporary,       % agent procs are ephemeral
  shutdown => 5000,
  type     => worker}.
```

`temporary` restart: if an agent process crashes, the agent will reconnect
naturally via a new Register → Subscribe cycle. No point restarting a process
whose stream is already broken.

### 3. `yuzu_gw_router` — Command Fanout Coordinator

```erlang
-module(yuzu_gw_router).
-behaviour(gen_server).

%% Called by yuzu_gw_mgmt_service when operator sends SendCommand
handle_call({send_command, AgentIds, CommandReq, Timeout}, From, State) ->
    Targets = case AgentIds of
        [] -> yuzu_gw_registry:all_agents();   % broadcast
        _  -> AgentIds
    end,
    %% Fan out: cast to each agent process in parallel
    FanoutRef = make_ref(),
    lists:foreach(fun(AgentId) ->
        case yuzu_gw_registry:lookup(AgentId) of
            {ok, Pid} ->
                gen_statem:cast(Pid, {dispatch, CommandReq, {self(), FanoutRef, AgentId}});
            error ->
                self() ! {command_response_skip, FanoutRef, AgentId}
        end
    end, Targets),
    %% Aggregation happens async — responses stream back via the mgmt gRPC stream
    {noreply, State#{FanoutRef => #{from => From,
                                     targets => length(Targets),
                                     received => 0,
                                     timeout_ref => erlang:send_after(Timeout * 1000, self(),
                                                                       {fanout_timeout, FanoutRef})}}}.
```

The router does **not** wait for all responses synchronously. It tracks a
`FanoutRef`, counts terminal responses, and streams each
`SendCommandResponse` back to the operator's gRPC stream as they arrive. This
means the operator sees progressive results — identical to the current
server-streaming `SendCommand` contract.

### 4. Supervision Tree

```
yuzu_gw_sup (one_for_one)
  ├── yuzu_gw_registry          (gen_server — ETS owner, pg coordinator)
  ├── yuzu_gw_upstream          (gen_server — gRPC client pool to C++ server)
  ├── yuzu_gw_router            (gen_server — fanout coordinator)
  ├── yuzu_gw_agent_sup         (simple_one_for_one — agent processes)
  ├── yuzu_gw_mgmt_service      (grpcbox service — operator-facing)
  └── yuzu_gw_agent_service     (grpcbox service — agent-facing proxy)
```

---

## Routing Table

### Design: ETS + pg (Process Groups)

Two complementary mechanisms:

**ETS table (`yuzu_gw_agents`)** — fast single-agent lookup:

```erlang
%% Table: set, {agent_id, pid, node, session_id, plugins, connected_at}
ets:new(yuzu_gw_agents, [named_table, set, public, {read_concurrency, true}]).

%% Register
ets:insert(yuzu_gw_agents, {AgentId, self(), node(), SessionId, Plugins, os:timestamp()}).

%% Lookup
[{_, Pid, _, _, _, _}] = ets:lookup(yuzu_gw_agents, AgentId).

%% Remove (on agent disconnect)
ets:delete(yuzu_gw_agents, AgentId).
```

**pg (process groups)** — efficient broadcast/multicast:

```erlang
%% Every agent process joins the 'all_agents' group
pg:join(yuzu_gw, all_agents, self()).

%% Plugin-specific groups for targeted fanout
pg:join(yuzu_gw, {plugin, <<"inventory">>}, self()).
pg:join(yuzu_gw, {plugin, <<"patch">>}, self()).

%% Broadcast to all agents (returns list of pids across the cluster)
Pids = pg:get_members(yuzu_gw, all_agents).

%% Plugin-targeted command
Pids = pg:get_members(yuzu_gw, {plugin, Plugin}).
```

**Why both?**

| Operation | Mechanism | Time complexity |
|-----------|-----------|-----------------|
| Send to one agent by ID | ETS lookup | O(1) |
| Broadcast to all agents | pg group | O(1) to get member list |
| Send to agents with plugin X | pg group | O(1) to get member list |
| List all agents (dashboard) | ETS `select` | O(n) but paginated via cursor |
| Cross-node fanout | pg (cluster-aware) | Automatic via Erlang distribution |

### Cross-Node Routing (Clustering)

pg is cluster-aware once nodes are actually connected — but nothing in this
document connected them, and until HA WS-4 `#4555` shipped, nothing in
`gateway/` did either (verified: zero `net_kernel`/`net_adm`/discovery code
existed anywhere in the tree). "No external service discovery needed" below
was aspirational, not built — cluster FORMATION (getting nodes connected in
the first place) is net-new work, not a `pg` side-effect.

```erlang
%% In sys.config — Erlang distribution
[{kernel, [
    {connect_all, false},          % Don't auto-mesh; use explicit connections
    {net_ticktime, 30}             % Failure detection: 30s × 4 = 120s
]}].
```

**Node discovery — IMPLEMENTED (HA WS-4 `#4555`, ADR-2002 §7b):** of the three
options originally sketched here, only **Option A (static/DNS-based)**
shipped — this repo has zero Kubernetes deployment artifacts, so Options B
(Kubernetes headless service) and C (AWS Cloud Map/Consul) remain a
documented, explicitly deferred, pluggable seam rather than v1 scope.
`yuzu_gw_cluster_discovery` resolves a configurable DNS seed name
(`YUZU_GW_SEED_DNS_NAME`, default `gateway`) to A records — which, via Docker
Compose's own embedded DNS for a scaled service, turns out to be the SAME
underlying mechanism Option B's "headless service via `inet_res`" describes,
achieved with zero Kubernetes-specific code. An explicit `YUZU_GW_SEED_NODES`
address list REPLACES DNS resolution outright when set (never merged), for a
no-DNS/air-gapped deployment. Because `{connect_all, false}` above means
nothing else in the VM ever self-heals a partial mesh, the redial loop runs
ALWAYS-ON (fixed interval, forever — not a one-time boot-time attempt),
subtracting already-connected nodes each tick so the steady-state cost is one
DNS query plus cheap no-ops. See ADR-2002 §7b for the full mechanism-choice
record, including the node-identity change this required (every replica
shares one fixed short name, distinguished only by a boot-time-resolved IP
literal — never a hostname, and never the pre-`#4555` hardcoded
per-node `vm.args` name) and the distribution-cookie hardening it added
(DNS-sourced dial targets otherwise let a compromised DNS answer mount an
offline cookie brute-force from a legitimately dialing node).

### Routing Table for Partitioned Agents

For millions of agents across N gateway nodes, agents are distributed by
consistent hashing on `agent_id`. This determines which gateway node an agent
*should* connect to (for rebalancing), but any node *can* accept any agent.

```erlang
%% Ring: 256 virtual nodes per physical node
%% Agent assignment: hash(agent_id) mod ring → owning node
%% Used only for:
%%   1. DNS-based connection routing (return preferred node IP)
%%   2. Rebalancing after node add/remove
%% NOT used for command routing — pg handles that transparently.
```

### Gateway Adjacency and Latency-Based Agent Redistribution

Each gateway node must maintain an awareness of its **peers** (adjacent gateway
nodes in the cluster) and be able to dynamically redistribute agents across the
cluster based on measured latency and load. The consistent hash ring determines
an agent's *preferred* node, but the actual placement must adapt at runtime.

#### Adjacency Table

Every gateway node maintains a live adjacency table of all peer nodes:

| Field | Source | Update frequency |
|-------|--------|-----------------|
| Node name | Erlang distribution (`net_kernel`) | On connect/disconnect |
| Agent count | Periodic exchange (or pg group size) | Every 10s |
| CPU / scheduler utilisation | `scheduler:utilization/1` shared via `gen_server:call` or gossip | Every 10s |
| Memory pressure | `erlang:memory/0` | Every 10s |
| RTT to this node | `net_adm:ping` latency or distribution heartbeat | Every 30s |
| Agent→node latency histogram | Aggregated from heartbeat RTTs per agent | Rolling 5 min window |
| Drain state | Explicit flag (set via admin API or SIGTERM handler) | Event-driven |

The adjacency table is held in an ETS table owned by a new `yuzu_gw_cluster`
gen_server, which publishes changes as telemetry events.

#### Load Shedding (Outbound)

A gateway node sheds agents when it is overloaded or draining. Shedding is
cooperative — the node sends a gRPC `GOAWAY` frame to selected agents, which
triggers agent reconnection. The reconnecting agent is steered to a less-loaded
peer via one of:

1. **DNS steering** — the gateway updates a DNS record (or health-check weight)
   so the agent's next resolution returns a different node.
2. **Redirect hint** — a new field in the `RegisterResponse` or a custom gRPC
   trailing metadata entry tells the agent which address to connect to next.

Shedding triggers:

| Trigger | Threshold (configurable) | Action |
|---------|-------------------------|--------|
| Scheduler utilisation | > 85% sustained 60s | Shed 10% of agents to least-loaded peer |
| Memory | > 80% of configured ceiling | Shed agents with largest pending maps first |
| Admin drain | Explicit API call or SIGTERM | Shed all agents over a configurable ramp-down window (default 5 min) |
| Node joining | New node enters cluster with 0 agents | Existing nodes shed proportionally to rebalance |

Shedding must be **rate-limited** (e.g., max 1000 GOAWAYs/sec) to prevent a
reconnection storm that overwhelms the receiving nodes.

#### Agent Absorption (Inbound)

When a gateway node has capacity and peers are shedding, it absorbs agents by
accepting their reconnections. Absorption is passive — the node simply accepts
`Register` + `Subscribe` calls as normal — but the node advertises its
willingness to absorb by broadcasting its load state via the adjacency table.

A node may also **proactively pull** agents by requesting a peer to shed specific
agents toward it. This is useful when a new node joins and wants to ramp up
quickly rather than waiting for organic reconnections.

#### Latency-Based Redistribution

Static hash-based placement ignores network topology. An agent in a Sydney
branch office routed by hash to a Frankfurt gateway incurs unnecessary latency.
Latency-aware redistribution addresses this:

1. **Measurement:** Each gateway node measures RTT to its connected agents via
   heartbeat round-trip times (already available — heartbeat response latency).
   These are bucketed per agent into a rolling P50/P99 window.

2. **Peer latency:** Gateways exchange inter-node RTT measurements via the
   adjacency table, so each node knows latency to every other node.

3. **Affinity score:** For each agent, the system computes an affinity score
   combining:
   - Agent→current node RTT (measured)
   - Agent→alternative node RTT (estimated: agent→current + current→peer,
     refined by actual measurement after migration)
   - Current node load (from adjacency table)
   - Peer node load (from adjacency table)

4. **Migration decision:** If an agent's estimated RTT to a peer is
   significantly lower (configurable threshold, e.g., > 30% improvement) *and*
   the peer has capacity, the current node sheds that agent toward the peer.
   The agent reconnects and the peer measures actual RTT to confirm improvement.

5. **Stability:** To prevent oscillation, an agent that was recently migrated
   (configurable cooldown, e.g., 10 min) is exempt from further redistribution.
   Decisions use hysteresis — migrate only when the improvement exceeds a
   threshold, not on marginal differences.

#### Telemetry Events

```erlang
%% ── Adjacency / redistribution ──
[yuzu, gw, cluster, adjacency_update]   % meta: #{peer, agent_count, cpu, memory, rtt_ms}
[yuzu, gw, cluster, shed_started]       % #{count, reason} meta: #{target_peer}
[yuzu, gw, cluster, shed_completed]     % #{count, duration_ms}
[yuzu, gw, cluster, absorbed]           % #{count} meta: #{from_peer}
[yuzu, gw, cluster, latency_migration]  % #{agent_id, old_rtt_ms, estimated_new_rtt_ms, target_peer}
```

#### Prometheus Metrics

```
yuzu_gw_cluster_peer_rtt_ms{peer="gw2@10.0.1.2"}              12
yuzu_gw_cluster_peer_agent_count{peer="gw2@10.0.1.2"}         342819
yuzu_gw_cluster_shed_total{reason="overload"}                  1500
yuzu_gw_cluster_absorbed_total{from_peer="gw3@10.0.1.3"}      1200
yuzu_gw_agent_rtt_ms{quantile="0.99"}                          45
yuzu_gw_redistribution_decisions_total{action="migrate"}       320
yuzu_gw_redistribution_decisions_total{action="keep"}          980000
```

---

## Wire Protocol Integration

### Agent-Facing: Proxy the Existing Protobuf Contract

The gateway speaks the **exact same** `AgentService` proto that agents already
use. Zero agent-side changes required.

```
Agent                          Gateway                        C++ Server
  │                              │                              │
  │── Register(RegisterReq) ────▶│── Register(RegisterReq) ────▶│
  │◀── RegisterResponse ────────│◀── RegisterResponse ─────────│
  │                              │                              │
  │  (gateway records session_id, spawns yuzu_gw_agent proc)   │
  │                              │                              │
  │── Subscribe(bidi stream) ──▶│  (stream terminates at       │
  │                              │   gateway; NOT proxied to    │
  │                              │   C++ server)                │
  │◀── CommandRequest ──────────│                              │
  │── CommandResponse ─────────▶│                              │
  │                              │                              │
  │── Heartbeat ────────────────▶│── Heartbeat (batched) ──────▶│
  │◀── HeartbeatResponse ───────│◀── HeartbeatResponse ────────│
  │                              │                              │
  │── ReportInventory ─────────▶│── ReportInventory (proxy) ──▶│
  │◀── InventoryAck ────────────│◀── InventoryAck ─────────────│
```

**Key insight:** The Subscribe bidi stream terminates at the gateway. The C++
server never holds agent streams at scale — the gateway owns them. Register,
Heartbeat, and ReportInventory are proxied upstream to the C++ server so it
retains enrollment authority and inventory storage.

### Operator-Facing: Gateway Implements SendCommand Directly

```
Dashboard                      Gateway                        C++ Server
  │                              │                              │
  │── SendCommand(req) ────────▶│  (fan out to agent procs     │
  │                              │   via pg/ETS)                │
  │◀── stream SendCommandResp ──│◀── responses from agents ───│
  │                              │                              │
  │── ListAgents ──────────────▶│  (answered from ETS table)   │
  │◀── ListAgentsResponse ──────│                              │
  │                              │                              │
  │── WatchEvents ─────────────▶│  (gateway-native; monitors   │
  │◀── stream AgentEvent ───────│   agent process lifecycle)   │
```

`ListAgents`, `GetAgent`, and `WatchEvents` can be served entirely by the
gateway (it knows which agents are connected). `QueryInventory` is proxied
to the C++ server (which owns the SQLite store).

### Heartbeat Batching

Instead of proxying every individual heartbeat to the C++ server, the gateway
batches them:

```erlang
%% yuzu_gw_upstream batches heartbeats every 10 seconds
%% Sends a single BatchHeartbeat (new internal-only RPC) to C++ server
%% containing [{session_id, timestamp, status_tags}] for all agents on this node.
%%
%% The C++ server updates last_seen timestamps in bulk.
%% This reduces upstream RPC volume from O(agents/interval) to O(nodes/interval).
```

This requires a small addition to the C++ server — a `BatchHeartbeat` RPC on an
internal service. Alternatively, the gateway can simply call `Heartbeat` in a
pooled fashion with a configurable concurrency limit.

---

## Telemetry

### Event Definitions

All events use the standard Erlang `telemetry` library (compatible with
Prometheus, StatsD, OpenTelemetry exporters).

```erlang
%% ── Connection lifecycle ──
[yuzu, gw, agent, connected]        % #{agent_id, node, session_id}
[yuzu, gw, agent, disconnected]     % #{agent_id, reason, duration_ms}
[yuzu, gw, agent, count]            % #{count}  (gauge, emitted every 10s)

%% ── Command plane ──
[yuzu, gw, command, dispatched]     % #{count => 1}  meta: #{agent_id, plugin, command_id}
[yuzu, gw, command, completed]      % #{duration_ms} meta: #{agent_id, plugin, status}
[yuzu, gw, command, timeout]        % #{count => 1}  meta: #{agent_id, command_id}
[yuzu, gw, command, fanout]         % #{target_count, duration_ms} meta: #{command_id}

%% ── Stream health ──
[yuzu, gw, stream, backpressure]    % #{queue_len} meta: #{agent_id}
[yuzu, gw, stream, write_error]     % #{count => 1} meta: #{agent_id, error}

%% ── Upstream (C++ server) ──
[yuzu, gw, upstream, rpc_latency]   % #{duration_ms} meta: #{rpc_name}
[yuzu, gw, upstream, rpc_error]     % #{count => 1}  meta: #{rpc_name, code}

%% ── Cluster ──
[yuzu, gw, cluster, node_up]        % meta: #{node}
[yuzu, gw, cluster, node_down]      % meta: #{node}
[yuzu, gw, cluster, rebalance]      % #{moved_agents} meta: #{from, to}

%% ── BEAM VM ──
[yuzu, gw, vm, process_count]       % #{count}
[yuzu, gw, vm, memory]              % #{total, processes, ets, binary}
[yuzu, gw, vm, scheduler_util]      % #{weighted_avg}
```

### Prometheus Exposition

```erlang
%% Attach handler in yuzu_gw_app:start/2
telemetry:attach_many(prometheus_handler, [
    [yuzu, gw, agent, connected],
    [yuzu, gw, agent, disconnected],
    [yuzu, gw, command, dispatched],
    [yuzu, gw, command, completed],
    [yuzu, gw, command, fanout],
    [yuzu, gw, upstream, rpc_latency]
], fun yuzu_gw_telemetry:handle_event/4, #{}).

%% Metrics exposed on :9568/metrics (prometheus_httpd)
%% Example output:
%%   yuzu_gw_agents_connected_total{node="gw1@10.0.1.1"} 342819
%%   yuzu_gw_command_dispatch_duration_ms{plugin="inventory",quantile="0.99"} 12
%%   yuzu_gw_fanout_target_count{quantile="0.5"} 50000
%%   yuzu_gw_upstream_rpc_duration_ms{rpc="Register",quantile="0.99"} 45
%%   yuzu_gw_beam_process_count{node="gw1@10.0.1.1"} 1048832
```

### Dashboard Integration

The existing SSE `EventBus` in the C++ server can subscribe to a
`WatchEvents` stream from the gateway to continue powering the web dashboard
without changes. The gateway emits `AgentConnected`/`AgentDisconnected`
events natively from process lifecycle monitoring.

---

## Capacity Planning

| Resource | Per Agent | At 1M Agents | At 5M Agents (clustered) |
|----------|-----------|--------------|--------------------------|
| Erlang process | ~2 KB | 2 GB | 10 GB (across 5 nodes) |
| ETS row | ~200 B | 200 MB | 1 GB |
| pg membership | ~64 B | 64 MB | 320 MB |
| File descriptors | 1 | 1M (set `ulimit -n 2000000`) | 1M per node |
| TCP buffers (kernel) | ~8 KB | 8 GB | 8 GB per node |

**Recommended node sizing:** 1M agents per gateway node on a 16-core / 32 GB
machine. The BEAM scheduler pins one scheduler thread per core; all agent
processes are multiplexed across them without thread-per-connection overhead.

**Cluster topology for 5M agents:**

```
               ┌─── gw1 (1M agents) ───┐
               ├─── gw2 (1M agents) ───┤
LB/DNS ────────├─── gw3 (1M agents) ───├──── yuzu-server (C++)
               ├─── gw4 (1M agents) ───┤
               └─── gw5 (1M agents) ───┘
```

---

## Migration Steps

### Phase 0: Proto Preparation (no runtime changes)

1. **Add a `gateway` package** to the proto directory:

   ```
   proto/yuzu/gateway/v1/gateway.proto
   ```

   Define an internal-only service for gateway ↔ C++ server communication:

   ```protobuf
   syntax = "proto3";
   package yuzu.gateway.v1;

   import "yuzu/agent/v1/agent.proto";

   // Internal service: gateway → C++ server (not exposed to agents)
   service GatewayUpstream {
     // Proxy registration to the control plane
     rpc ProxyRegister(yuzu.agent.v1.RegisterRequest)
         returns (yuzu.agent.v1.RegisterResponse);

     // Batch heartbeat (reduces per-agent RPC overhead)
     rpc BatchHeartbeat(BatchHeartbeatRequest)
         returns (BatchHeartbeatResponse);

     // Proxy inventory reports
     rpc ProxyInventory(yuzu.agent.v1.InventoryReport)
         returns (yuzu.agent.v1.InventoryAck);
   }

   message BatchHeartbeatRequest {
     repeated yuzu.agent.v1.HeartbeatRequest heartbeats = 1;
   }

   message BatchHeartbeatResponse {
     int32 acknowledged_count = 1;
   }
   ```

2. **Implement `GatewayUpstream` in the C++ server** — thin wrappers around
   existing `AgentServiceImpl` logic. `BatchHeartbeat` iterates the heartbeat
   list and updates `last_seen` in bulk.

3. **Add the Erlang OTP project** under `gateway/` (or a separate repo).
   Wire up `grpcbox` with the proto files using `gpb` for code generation.

### Phase 1: Shadow Mode (read-only gateway, agents still connect to C++)

1. Deploy the gateway alongside the C++ server.
2. Gateway connects to `GatewayUpstream` and calls `ListAgents` periodically to
   build its routing table from the C++ server's ground truth.
3. Operators can issue `SendCommand` to **either** the gateway or the C++ server.
   The gateway proxies to the C++ server's `Subscribe` streams (no direct agent
   connections yet).
4. Validate telemetry, latency, and correctness by comparing results.

### Phase 2: Agent Cutover (gateway owns Subscribe streams)

1. **DNS / load balancer change**: point agents' gRPC target to the gateway
   cluster instead of the C++ server directly.
2. Agents call `Register` → gateway proxies to C++ server via `ProxyRegister`.
3. Agents call `Subscribe` → gateway **terminates** the bidi stream locally,
   spawning a `yuzu_gw_agent` process. Stream is NOT forwarded to C++.
4. Agents call `Heartbeat` → gateway batches and sends via `BatchHeartbeat`.
5. `SendCommand` from operators hits the gateway's `ManagementService`, which
   fans out via the local agent processes.
6. The C++ server's `AgentRegistry` is no longer populated (no direct Subscribe
   streams). Its `send_to`/`send_to_all` become dead code for command dispatch.

### Phase 3: Cleanup & Optimization

1. **Remove stream_mu and send_to/send_to_all from C++ server** — no longer
   needed. The C++ server becomes a pure control-plane + dashboard server.
2. **Implement cross-node fanout** — scale the gateway cluster horizontally.
   pg handles routing transparently; add consistent hashing for connection
   balancing.
3. **Add circuit breakers** in `yuzu_gw_upstream` for C++ server calls.
4. **Implement graceful agent migration** — when a gateway node is drained,
   its agent processes send a `GOAWAY` frame, causing agents to reconnect
   (likely to a different node).

### Phase 4: Advanced Features

1. **Command deduplication** — the gateway can deduplicate identical broadcast
   commands (same plugin + action + parameters) within a time window.
2. **Priority queues** — high-priority commands skip the agent process mailbox
   queue (Erlang process priorities or a two-mailbox pattern).
3. **Response caching** — cache inventory-like responses at the gateway to
   reduce agent round-trips.
4. **OIDC token validation at the gateway** — offload auth for operator-facing
   RPCs from the C++ server.

---

## Agent-Side Changes

**None required for Phase 1–2.** The gateway speaks the identical `AgentService`
proto. The agent's `--server` flag simply points to the gateway's address
instead of the C++ server's.

The only agent-visible difference: the TLS certificate presented by the gateway
must be trusted. If using mTLS, the gateway's server certificate must be signed
by the same CA, and the gateway must validate agent client certificates the same
way (or proxy the raw TLS peer identity to the C++ server in `ProxyRegister`).

---

## C++ Server Changes Summary

| Change | Scope | Effort |
|--------|-------|--------|
| Implement `GatewayUpstream` service | New gRPC service in `server/core/` | Medium |
| `BatchHeartbeat` handler | Iterate + update `last_seen` | Small |
| `ProxyRegister` handler | Delegate to existing enrollment logic | Small |
| `ProxyInventory` handler | Delegate to existing inventory store | Small |
| Expose `GatewayUpstream` on a separate port or with interceptor auth | Config | Small |
| Remove `stream_mu`, `send_to`, `send_to_all` (Phase 3) | Delete code | Small |
| Update dashboard SSE to source events from gateway `WatchEvents` | `server.cpp` EventBus | Medium |

---

## Why Erlang (vs. alternatives)

| Concern | Erlang/OTP | Alternatives considered |
|---------|-----------|----------------------|
| Millions of concurrent connections | BEAM VM: 1M+ processes per node, each ~2 KB. Purpose-built for telecom switches. | Go goroutines (similar scale, but no supervision trees, no hot code reload). Rust async (similar scale, harder to express the actor model). |
| Fault isolation | Process crash kills only that agent's session. Supervisor restarts are automatic. | Go/Rust: a panic or deadlock in one connection handler can cascade without careful engineering. |
| Hot code upgrade | OTP release upgrades allow deploying new routing logic without dropping agent connections. | Go/Rust: rolling restart required, causing mass agent reconnection storms. |
| Cluster-native | Erlang distribution + pg gives transparent cross-node process groups. | Go/Rust: requires external service mesh (Consul, etcd) for cluster membership. |
| Backpressure | Mailbox-per-process provides natural backpressure; slow agents don't block fast ones. | Go channels (similar). C++ shared mutex (current problem). |
| Operational maturity for this workload | 30+ years in telecom; WhatsApp ran 2M connections/server on BEAM. | Proven but less specifically optimized for this pattern. |

---

## File Placement in Yuzu Repo

```
Yuzu/
├── gateway/
│   └── erlang/                    % New: Erlang OTP application
│       ├── rebar.config
│       ├── rebar.lock
│       ├── config/
│       │   ├── sys.config
│       │   └── vm.args.src   # env-substituted at boot (supplies YUZU_GW_COOKIE)
│       └── apps/
│           └── yuzu_gw/
│               └── src/
│                   └── (modules listed above)
├── proto/
│   └── yuzu/
│       ├── gateway/
│       │   └── v1/
│       │       └── gateway.proto  % New: internal gateway↔server proto
│       ├── agent/v1/agent.proto   % Unchanged
│       ├── common/v1/common.proto % Unchanged
│       └── server/v1/management.proto % Unchanged
└── server/
    └── core/
        └── src/
            └── server.cpp         % Add GatewayUpstream service impl
```
