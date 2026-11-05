# WS-13 slice 13.6: the two-replica dispatch probe (#7082)

Measurement record. **No product code changed. The HA safe-to-scale gate is NOT lifted, and a second server
replica is NOT a supported deployment.** The rig runs two replicas so that one question can be measured; a
result here is evidence for this rig only.

## The question

Decision #6920 (2026-11-04) keeps slice 13.6 (a gateway node that is up but cut off from its servers) outside
the safe-to-scale gate because its harm on two replicas was untested, and moves it inside if a two-replica
dispatch probe finds an attached agent undispatchable. The 13.0 spike measured one replica only
([ws13-0-gateway-failover.md](ws13-0-gateway-failover.md), finding 4): dispatch kept working, because one
replica uses its own session and never consults the route directory. This probe measures the case it could
not.

## Method

- **Rig.** The 13.0 spike rig plus the overlay `deploy/docker/docker-compose.ha-gateway-two-replica.yml`: two
  server replicas on one Postgres and one CA/KEK volume, three clustered gateways, HAProxy, CoreDNS, and N
  real agents, over real TLS. Every gateway dials ONE upstream endpoint, an L4 VIP over both replicas, with the
  shipped `pool_size` 1, so each gateway holds one upstream connection and therefore has one **holder** replica
  (the replica that adopted its agents' sessions). The management plane (`--gateway-command-addr`) is the
  gateway VIP on both replicas, never one node (that is #7062). Two upstream endpoints on the gateway channel
  were rejected before the first run: the channel round-robins every call over both replicas
  (`yuzu_grpc_client_channel.erl`, and `gateway.md` warns against it), so an agent would have no stable holder.
- **Fault (F3-2r).** In the victim gateway's network namespace, DROP tcp to the upstream VIP on :50055 only.
  The agent edge (:50051) and the management plane (:50063) stay up, so a command can still reach the agent
  through the gateway and its response can come back on the same SendCommand stream. A packet capture taken in
  the victim's namespace on :50055 saw no outbound packet and no FIN or RST during the fault (the egress drop
  sits before the capture point) and only 7 inbound packets in about 450 s; the first RST came 7-117 s after
  the fault was undone. It was a silent partition, not a reset, and the gateway's upstream connection stayed
  established for the whole window.
- **Probe.** `os_info.os_name` (read-only) to each sampled agent, through BOTH replicas, on both REST surfaces
  (`POST /api/v1/commands` and the legacy `POST /api/command`), plus one scope-arm probe per replica
  (`hostname == '<name>'`). Rounds: a control 20 s before the fault, then +60, +120, +300 and +420 s, then
  every 10 s after the fault was undone. "Delivered" = a terminal response produced by the agent (SUCCESS with
  output, or an agent-reported failure) inside a polled 30 s deadline; every send was re-read at the end of the
  run for late terminals. A refusal, a server-synthesised `[gateway_*]` failure and "accepted, no result" are
  each recorded as such. Every "delivered" row's command id was also found in an agent container log (0 rows
  without one in any run).
- **Holder and cohort.** The holder of an agent = the replica whose own log holds the agent's CURRENT session id
  in a `ProxyRegister succeeded` line (the agent id alone is not enough, see finding 2). The sample is the
  agents attached to the victim gateway, in two cohorts: **clean** (the other replica has no local session for
  the agent, so a dispatch through it goes through the route directory), and **stale-session** (the other
  replica also lists the agent; finding 2). Only the clean cohort enters the trigger tally.
- **Controls.** The control round is sent through both replicas before the fault; a failed control makes that
  agent inconclusive, not a pass. A full-length no-fault run with the same schedule validates the rig.
- **Setting.** Image commit `7cc3dd2ff` (server `52104c72bd82`, gateway `432fcabd6cc9`, agent `9fb9dbf8b8c8`),
  one 32-core host with 122 GB RAM (Docker 29.1.3), cpuset-pinned (infrastructure on the lower half, agents on
  the upper). **Every number is single host. The fleet was 60 agents (20 per gateway); the first, provisional
  run used 20.** Raw data (route samples at 1 Hz, agent, gateway and server logs, captures) is kept outside the
  repository; the committed summaries are in `docs/ha-spikes/ws13-6/` (`probe-summary.csv`, `run-timeline.csv`).

## Predictions, written before any run, against what was measured

The predictions came from reading `origin/dev` and were not run before the rig existed.

| Prediction | Measured |
|---|---|
| The replica that holds the session delivers at every lease state (`send_to` queues to the gateway and ignores the lease, #5960) | **Held**: 20 of 20 delivered at every round in all three fault runs, including +420 s, and after the route row was tombstoned (run gateway-2: tombstoned at +331 s) |
| The non-holder delivers while the route lease is valid | **Held**: 20 of 20 at the control and at +60 s |
| The non-holder refuses once the lease has expired (+120, +300, +420 s), as `no_agents_reached` | **Held**: 0 of 20 at +120, +300 and +420 s in all three runs; the v1 route answers HTTP 503 `no_agents_reached`, the legacy route a bare 503 |
| A second refusal class, "no agent connected" before the arm walk, on a replica with no local sessions | **Not observed**: every refusal was `no_agents_reached` or the legacy bare 503, because each replica held other agents' sessions |
| Scope/group arms drop the agent from the candidate set once presence lapses | **Not as predicted**: the scope-arm probe was delivered through both replicas up to +60 s and refused with `no_agents_reached` on the non-holder from +120 s, the same as the id arm (after the path returned the scope arm recovered one probe interval, about 5 s, later than the id arm in one run) |
| After the path returns, the one-replica spike's 2-6 s re-arm (or, on two replicas, #5380's never-re-armed case) | **Re-armed in 1-4 s** in all three runs, including the two where the row had been tombstoned; #5380 was not reproduced on this rig |

## Results

Clean cohort, 10 agents per run, both surfaces (20 probes per cell). Delivered / probes.

| Run (victim gateway, holder) | Probed replica | control | +60 s | +120 s | +300 s | +420 s | Recovery |
|---|---|---|---|---|---|---|---|
| gateway-1, holder 1 | 1 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |
| gateway-1, holder 1 | 2 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | dispatchable again 3 s after the undo |
| gateway-2, holder 2 | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |
| gateway-2, holder 2 | 1 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | 4 s |
| gateway-3, holder 2 | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |
| gateway-3, holder 2 | 1 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | 1 s |
| no fault (gateway-3) | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |
| no fault (gateway-3) | 1 (non-holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |

Route directory, same clean-cohort agents (seconds after the fault): first non-routable (lease expired) 63-87 s
in every fault run; the route row was tombstoned (session cleared) at +331 s in one run, at +471 s in one and
not within the 480 s window in one (the sweep is phase dependent); every agent was routable again 1-4 s after
the fault was undone. No agent moved off the victim gateway at any point.

### Findings

1. **The 13.6 trigger condition of #6920 is met on this rig.** An agent attached to a gateway node that is up
   but cut off from its servers is undispatchable through the replica that does not hold its session, from the
   moment its route lease expires (about 63-87 s after the fault) until the path returns, in 3 of 3 fault runs
   and for both holder directions; it stays dispatchable through the replica that holds the session. A
   load balancer in front of two replicas would send some operator requests to each, so the same agent is
   reachable or not by chance. The refusal does not say why: a v1/MCP caller gets `no_agents_reached` (with
   `retry_after_ms`), the same answer as an offline device, and a legacy caller a bare 503. The fault is
   recoverable on this rig (1-4 s after the path returns).
2. **A stale local session on a replica hides a live route, with no fault at all.** In every run, agents that
   enrolled through the harness were registered through two gateways within milliseconds of each other (the
   per-agent certificate is issued, the agent reconnects), leaving a local session on the replica of the
   first gateway. A dispatch through that replica is refused (`no_agents_reached`, 4 of 4 in every run, before
   and during the fault and in the no-fault run) although the route directory has a live route and the other
   replica delivers. The agents were restarted before each run and still carry it, because the server never
   evicts a gateway-proxied local session (`reap_stale_sessions` only cancels a stream context, and a proxied
   session has none). This is consistent with the dispatch wiring consulting the route directory only for ids
   the replica holds no local session for (`dispatch_route_fallback.hpp` header); it is not separately proven
   that the stale session carries no `gateway_node`. It is reported as a separate cohort and never counted in
   finding 1. It bears on #5380 and #5960 and is a candidate issue.
3. **Two upstream endpoints on a gateway cannot be measured, and the shipped doc already warns against them**
   (see Method). The rig therefore uses one VIP endpoint; holders mix per gateway, not per agent.
4. **Recovery was fast and the tombstone did not make it permanent here.** The one-replica spike's 2-6 s
   re-arm held on two replicas, including after the row was tombstoned. This does not close #5380, whose
   trigger is a cut longer than the ones sampled and a different re-arm path.

### Limits

Single host, one hardware shape, 60 agents (20 per gateway), 10 clean agents sampled per run, one probe per
agent per surface per round. Three fault runs (one with holder 1, two with holder 2), one full-length no-fault
run, and a provisional 20-agent run taken before probes carried a cohort tag (its raw data is kept; it is not
summarised). `os_info.os_name` only: nothing here says whether a quarantine or another protective command
reaches the endpoint in this state (unmeasured, and #7062 owns the management-address half). The fault is F3
only (the path to the servers dropped, both directions, no reset); a node with a failing `/readyz`, a server
restart and a longer cut are other cases. The holder is fixed per gateway by HAProxy's placement of one
connection; behaviour when a gateway reconnects to the other replica was not probed. No claim is made about
how an operator's own load balancer would distribute requests.

### What this does not change

The safe-to-scale gate is not lifted and one server replica remains the only supported shape. The edit that
moves 13.6 inside the gate (every hand-stated copy of the gate: the delivery matrix, ADR-2002, the `/ha` skill,
roadmap 14.2) is a separate change, owned by #7082. The gateway-side fix (end agent streams after an outage
longer than the lease) is not designed here.

## Reproducing

`scripts/ha/ha-gateway-two-replica-probe.sh up --tag <image-tag> --agents N`, then `scenario NOFAULT` or
`scenario F3-2r --victim gateway-N`, then `down`. Build the three `yuzu-spike-{server,gateway,agent}` images
from the commit under test with `Dockerfile.server`, `Dockerfile.gateway` and `Dockerfile.agent`. Run it on a
host with nothing else on 10.77.12.0/22; it refuses otherwise. The overlay is a lab measurement rig and not a
deployment pattern.
