# WS-13 slice 13.6: the two-replica dispatch probe (#7082)

Measurement record. **No product code changed. The HA safe-to-scale gate is NOT lifted, and a second server
replica is NOT a supported deployment.** The rig runs two replicas so that one question can be measured; a
result here is evidence for this rig only.

Statements below are tagged **[measured]** (read from the run data), **[code]** (read from `origin/dev`, not
run) or **[inferred]** (reasoned from the two, not tested).

## The question

Decision #6920 (2026-11-04) keeps slice 13.6 (a gateway node that is up but cut off from its servers) outside
the safe-to-scale gate because its harm on two replicas was untested, and moves it inside if a two-replica
dispatch probe finds an attached agent undispatchable. The 13.0 spike measured one replica only
([ws13-0-gateway-failover.md](ws13-0-gateway-failover.md), finding 4): dispatch kept working, because one
replica uses its own session and never consults the route directory [code]. This probe measures the case it
could not.

## Method

- **Rig.** The 13.0 spike rig plus the overlay `deploy/docker/docker-compose.ha-gateway-two-replica.yml`: two
  server replicas on one Postgres and one CA/KEK volume, three clustered gateways, HAProxy, CoreDNS, and N
  real agents, over real TLS. Every gateway dials ONE upstream endpoint, an L4 VIP over both replicas, with the
  shipped `pool_size` 1, so each gateway holds one upstream connection and therefore has one **holder** replica
  (the replica that adopted its agents' sessions). The management plane (`--gateway-command-addr`) is the
  gateway VIP on both replicas, never one node (that is #7062). Two upstream endpoints on the gateway channel
  were rejected before the first run: the channel round-robins every call over both replicas
  (`yuzu_grpc_client_channel.erl`; `gateway.md` warns against it), so an agent would have no stable holder
  [code].
- **Fault (F3-2r).** In the victim gateway's network namespace, DROP tcp to the upstream VIP on :50055 only.
  The agent edge (:50051) and the management plane (:50063) stay up, so a command can still reach the agent
  through the gateway and its response can come back on the same SendCommand stream [code]. A capture taken in
  the victim's namespace on :50055 [measured] saw no outbound packet and no FIN or RST during the fault (the
  egress drop sits before the capture point), 11-27 inbound packets per run between the fault and the undo
  (10 s buckets: 27, 14, 11), and the first FIN/RST 7-117 s after the fault was undone. It was a silent
  partition, not a reset. The victim gateway's own log [measured] shows its upstream channel going down
  (`connection 1 down (timeout); reconnecting`) from +64 s, +71 s and +89 s in the three runs and retrying until
  the undo; the agents stayed attached to it throughout (none of the 30 clean sampled agents changed gateway
  node in the route samples), and the victim's `/readyz` answered 200 in every sample between the fault and the
  undo (339 of 339 in each run), so a load balancer that health-checks `/readyz` would not have ejected the
  node.
- **Probe.** `os_info.os_name` (read-only) to each sampled agent, through BOTH replicas, on both REST surfaces
  (`POST /api/v1/commands` and the legacy `POST /api/command`), plus one scope-arm probe per replica
  (`hostname == '<name>'`, v1 only). Rounds: a control that immediately precedes the fault (its last send is
  0.14-0.19 s before the fault is injected), then +60, +120, +300 and +420 s, then recovery rounds from the undo
  (+0.4 s and +5.6 s in all three runs; the loop stops once every clean agent was delivered through both
  replicas, so two rounds were needed). "Delivered" = a terminal response produced by the agent (SUCCESS with
  output, or an agent-reported failure) inside a polled 30 s deadline; a send that was still "accepted, no
  result" at its deadline was re-read at the end of the run for late terminals. A dispatch refusal (HTTP 503 or
  zero agents reached), a server-synthesised `[gateway_*]` failure and "accepted, no result" are each recorded
  as such; anything else that is not a 2xx is a rig error and is never counted as a refusal (none occurred).
  Every "delivered" row's command id was also found in an agent container log (0 rows without one).
- **Holder and cohort.** The holder of an agent = the replica whose own log holds the agent's CURRENT session id
  in a `ProxyRegister succeeded` line (the agent id alone is not enough, see finding 2). The sample is the
  agents attached to the victim gateway, in two cohorts: **clean** (the other replica does not list the agent,
  so a dispatch through it goes through the route directory) and **stale-session** (the other replica also lists
  it; finding 2). Only the clean cohort enters the trigger tally. The 10 clean agents behind one gateway share
  one holder, one upstream connection and one lease timeline, so each fault run is ONE observation of the
  fault, not ten.
- **Controls.** The control round goes through both replicas before the fault. An agent whose control did not
  deliver through both replicas on both surfaces is reported in its own `inconclusive` cohort for the whole
  run, never as a pass and never as a refusal (none were: every clean agent's control delivered). A
  full-length no-fault run with the same schedule validates the rig.
- **Setting.** Image commit `7cc3dd2ff` (server `52104c72bd82`, gateway `432fcabd6cc9`, agent `9fb9dbf8b8c8`),
  one 32-core host with 122 GB RAM (Docker 29.1.3), cpuset-pinned (infrastructure on the lower half, agents on
  the upper). **Every number is single host. The fleet was 60 agents (20 per gateway); an earlier provisional
  20-agent run is described but not summarised** (it predates the cohort tag). Route samples were taken about
  every 1.4 s (median gap 1.42 s, not 1 Hz).

## Evidence and its provenance

The raw data (route samples, per-run `probes.jsonl`, `holders.csv`, `sample.txt`, agent, gateway and server logs,
captures, `meta.txt`) is **a single copy on the host that ran it**, under `~/.local/share/yuzu/ws13-7082/`. It
is not committed and has no off-host copy. The committed summaries (`docs/ha-spikes/ws13-6/probe-summary.csv`,
`run-timeline.csv`) are regenerated from it by `ha-two-replica-probe-client.py export` and carry the SHA-256 of
each run's `probes.jsonl`, so a re-analysis can be checked against them. The runner and client were edited
after the runs (the `export` subcommand, then the scoring, cohort and control rules after review); the current
client re-derives every cell of the committed tables from the raw `probes.jsonl` (0 cells differ from the
tables first produced live). Each run's `meta.txt` records the runner's SHA-1; the runs predate recording the
client's and the overlay's.

## Predictions, written before any run, against what was measured

The predictions came from reading `origin/dev` and were not run before the rig existed.

| Prediction | Measured |
|---|---|
| The replica that holds the session delivers at every lease state (`send_to` queues to the gateway and ignores the lease, #5960) | **Held**: 20 of 20 delivered at every round in all three fault runs, including +420 s, and after the route row was tombstoned (gateway-2 run, tombstoned at +331 s) |
| The non-holder delivers while the route lease is valid | **Held**: 20 of 20 at the control and at +60 s |
| The non-holder refuses once the lease has expired (+120, +300, +420 s), as `no_agents_reached` | **Held**: 0 of 20 at +120, +300 and +420 s in all three runs; the v1 route answers HTTP 503 `no_agents_reached`, the legacy route a bare 503 |
| A second refusal class, "no agent connected" before the arm walk (a legacy-route check [code]), on a replica with no local sessions | **Not observed**: every refusal was `no_agents_reached` or the legacy bare 503, because each replica held other agents' sessions |
| Scope/group arms may drop the agent from the candidate set once presence lapses | **Consistent, not separated from the id arm**: the scope-arm probe (one agent per replica per round) delivered through both replicas up to +60 s and was refused with `no_agents_reached` on the non-holder from +120 s; whether the agent was dropped before or after the route lookup was not distinguished, and scope-arm recovery after the undo was not characterised |
| After the path returns: the one-replica spike's 2-6 s re-arm, or on two replicas #5380's never-re-armed case | **Re-armed, see finding 4**: the route row was routable again 1-4 s after the undo in all three runs, including the two where it had been tombstoned |

## Results

Clean cohort, 10 agents per run, both surfaces (20 probes per cell). Delivered / probes.

| Run (victim gateway, holder) | Probed replica | control | +60 s | +120 s | +300 s | +420 s | After the undo |
|---|---|---|---|---|---|---|---|
| gateway-1, holder 1 | 1 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | delivered |
| gateway-1, holder 1 | 2 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | refused at +0.4 s, delivered at +5.7 s |
| gateway-2, holder 2 | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | delivered |
| gateway-2, holder 2 | 1 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | refused at +0.4 s, delivered at +5.7 s |
| gateway-3, holder 2 | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | delivered |
| gateway-3, holder 2 | 1 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | refused at +0.4 s, delivered at +5.6 s |
| no fault (gateway-3) | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |
| no fault (gateway-3) | 1 (non-holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |

Route directory, same clean-cohort agents, seconds after the fault (first non-routable: median 81.1, 75.3 and
79.0 s, range 63-87 s; route row tombstoned, meaning its session cleared: +331 s in the gateway-2 run, +471 s in
the gateway-3 run and not within the window in the gateway-1 run, the sweep being phase dependent; the fault
was undone at +481 s in each run; route row routable again after the undo: 2.9, 3.6 and 1.3 s median).

### Findings

1. **The condition of #6920 item (1) is met on this rig [measured].** An agent attached to a gateway node that
   is up but cut off from its servers is undispatchable through the replica that does not hold its session, from
   the moment its route lease expires (63-87 s after the fault) until the path returns, in 3 of 3 fault runs
   and for both holder directions; it stays dispatchable through the replica that holds the session. A load
   balancer in front of two replicas would send some requests to each, so the same agent is reachable or not by
   chance [inferred]. The refusal does not say why: a v1 caller gets `no_agents_reached` with
   `retry_after_ms`, the same answer as an offline device, and a legacy caller a bare 503 [measured]; the MCP
   twin shares the dispatch path [code] but was not probed. So `no_agents_reached` is not proof that a device is
   offline: check the other replica and the agent's gateway before concluding that. Qualifiers: REST only; a quiet fleet with no load; the holder replica
   stays dispatchable; one gateway per run (the 10 agents are one observation of the fault); a `os_info` read.
   The decision text (#6920 item (1)) makes the move inside the gate follow from this; that edit is not made
   here and the project lead is the owner of that call.
2. **Some agents hold a registration on both replicas, and the replica without the stream refuses them, with or
   without a fault.** [measured] In each run 2 of the 12 sampled agents were in a `stale-session` cohort (the
   other replica also lists them): through the replica that does not hold their stream, 4 of 4 probes were
   refused at the control, at every round of the fault runs and in the no-fault run, while the route directory
   held a live route and the holder delivered. In the server logs these agents show `ProxyRegister succeeded`
   on BOTH replicas 10-14 ms apart in the same restart, with a `CONNECTED` notice on only one (for example one
   agent: replica 1 at 16:58:55.114 with no CONNECTED, replica 2 at 16:58:55.124 with CONNECTED at gateway node
   10.77.12.13). The cohort is different agents in each run (no agent id appears in two runs), and the agents
   had been restarted just before each run, so the doubled registration arises at the restart. What was NOT
   established: why an agent registers twice (the agents dial the gateway VIP, which spreads connections over
   gateways, and each gateway has its own holder), whether it happens in a deployment with different fronting,
   or that the refused replica's local session carries no `gateway_node`. [code] The dispatch wiring consults
   the route directory only for ids the replica holds no local session for (`dispatch_route_fallback.hpp`
   header), which would produce this refusal; that is a hypothesis, not a result. It needs two replicas (on
   one, a second registration overwrites the first). Its relation to #5380 and #5960 is not established. It is reported as a separate cohort and never counted in finding 1.
3. **Two upstream endpoints on a gateway cannot be measured, and the shipped doc already warns against them**
   [code]. The rig therefore uses one VIP endpoint; holders mix per gateway, not per agent.
4. **The route row re-armed after the undo in all three runs, with and without a replay, and the holder can
   change.** [measured] The route row was routable again 1-4 s after the undo (rows sampled every 1.4 s). The
   first dispatch probe after the undo (+0.4 s) was refused through the non-holder in all three runs and the
   next (+5.6 s) delivered, so dispatch through the non-holder recovered within about 5.6 s. In the gateway-1
   run no `ProxyRegister` reached either replica after the undo for the sampled agents; in the other two the 10
   sampled agents re-registered 0.7-2.5 s after the undo: on the same replica in the gateway-3 run, and on the
   OTHER replica in the gateway-2 run (the holder flipped from 2 to 1). Two runs saw a tombstoned row (at +331
   s and +471 s; the second only 10 s before the undo) and both re-armed with a replay. Two observations are not
   a characterisation of #5380, which concerns a row that is tombstoned and never re-armed under multi-replica
   routing; this does not close or narrow it.

### Limits

Single host, one hardware shape, 60 agents (20 per gateway), 10 clean agents sampled per run behind one
gateway (so the effective sample is three fault events and one no-fault run, not 60 agents), one probe per agent
per surface per round. Three fault runs (one with holder 1, two with holder 2) and one full-length no-fault run;
a provisional 20-agent run taken before probes carried a cohort tag is kept as raw data and not summarised.
`os_info.os_name` only. **A quarantine or another protective command goes through the same dispatch refusal
[code]; whether one reaches the endpoint in this state was not probed** (and #7062 owns the management-address
half). The fault is F3 only (egress to the upstream VIP dropped, no reset); a node with a failing
`/readyz`, a server restart and a longer cut are other cases. The holder is fixed per gateway by HAProxy's
placement of one connection; it changed once, at recovery (finding 4). No claim is made about how an
operator's own load balancer would distribute requests. The rig is not the ADR-2002 §7g topology (holder mixing
per agent, and the WS-5 session-lookup path under it, are unmeasured here).

### What this does not change

The safe-to-scale gate is not lifted and one server replica remains the only supported shape. The edit that
moves 13.6 inside the gate (every hand-stated copy of the gate: the delivery matrix, ADR-2002, the `/ha` skill,
roadmap 14.2, and the operator manuals that describe this state as unmeasured) is a separate change owned by
#7082; **until it lands those copies say 13.6 is outside the gate while this record reports the condition for
moving it inside as met.** The gateway-side fix (end agent streams after an outage longer than the lease) is not
designed here.

## Reproducing

`scripts/ha/ha-gateway-two-replica-probe.sh up --tag <image-tag> --agents N`, then `scenario NOFAULT` or
`scenario F3-2r --victim gateway-N`, then `down`. Build the three `yuzu-spike-{server,gateway,agent}` images
from the commit under test with `Dockerfile.server`, `Dockerfile.gateway` and `Dockerfile.agent`. Run it on a
host with nothing else on 10.77.12.0/22; it refuses otherwise, and it takes a lock so two commands cannot run
against one rig. The overlay is a lab measurement rig and not a deployment pattern.
