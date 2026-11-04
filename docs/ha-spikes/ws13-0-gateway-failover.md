# HA WS-13 slice 13.0 - gateway failover with real agents and real TLS

Measured 2026-11-03/04 on one shared 32-core host. This is the record for slice 13.0 of WS-13
(#291, ADR-2002 "gateway-fronting"). It is **input** to the open decisions (#6920 and the slices
13.2, 13.4, 13.6), not a decision. **The safe-to-scale gate is not lifted by this record, and a second
server replica is still not safe.** Nothing in `docs/user-manual/`, ADR-2002 or the delivery matrix
has been edited to reflect these numbers; those edits belong to the slice that acts on them.

## What was measured, and why

D1 (2026-11-02) chose "a VIP or a multi-address DNS name, with no agent code" as the first
failover design. The only evidence was a one-off at the gRPC layer (gRPC 1.76, two test servers,
`pick_first` moved to the surviving address in about 1 s). It used no real agent, no TLS, and no
silent partition, and it kept no artefact. This slice repeats the question with the real agent
daemon, real TLS, three clustered gateways, a real server and Postgres, and 20 / 100 / 300 agents.

## Method

- **Build under test:** `origin/dev` at `416cf12d2` (includes 13.1, decorrelated reconnect
  jitter). Server, gateway and agent images were built from that commit with the repository's
  `Dockerfile.server`, `Dockerfile.gateway` and `Dockerfile.agent`.
- **Rig:** `deploy/docker/docker-compose.ha-gateway-failover.yml` plus
  `deploy/docker/ha-gateway-failover/`, driven by `scripts/ha/ha-gateway-failover-spike.sh`.
  Server + Postgres + three gateways (clustered, one shared gateway leaf certificate) + HAProxy
  + CoreDNS + N real agents, one container each, with its own tmpfs data directory (so its own
  agent identity) and its own hostname. A fresh certificate volume per rig, with the SANs for every
  name the agents dial.
- **Two ways to address the gateways**, switched by the agents' `--server`:
  - **DNS:** `gw-dns.ha.test`, three A records in a CoreDNS **static** zone. A dead gateway's record is
    **not** withdrawn (Docker's embedded DNS withdraws it instantly, which would flatter DNS), and the
    zone is served in shuffled order.
  - **VIP:** `gw-vip.ha.test`, HAProxy in `mode tcp`, health-checking each gateway's `/readyz` every
    3 s (down after 3 failures, `on-marked-down shutdown-sessions`). A variant adds
    `retries 3` and `option redispatch`.
- **Server to gateway management plane:** behind a second HAProxy frontend (`gw-mgmt.ha.test`) by
  default, or pointed at `gateway-1:50063` alone for the H7 runs.
- **Faults**, injected from a sidecar in the node's own network namespace (no host root):
  - **F1** `docker kill` of the node holding the most agents.
  - **F1g** `docker stop` (the gateway ends its sessions first).
  - **F2** silent drop of the agent port (50051) only. **F2p** silent drop of everything on the node
    except loopback (a full partition; this is the faithful "silent partition").
  - **F3** the node stays reachable but its path to the server (port 50055) is dropped. The
    management plane (port 50063) is untouched. **F3x** the node is fully isolated from the server.
  - Each fault is classified with a packet capture on three agents attached to the victim (FIN/RST
    seen, or silence).
- **Observation:** re-attach times come from the agents' own container logs (millisecond
  timestamps) joined to the harness's fault timestamp; route state from `agent_routes` in Postgres
  once a second; `/readyz` and `yuzu_gw_agents_current` per gateway once a second. After each
  fault, one `os_info.os_name` command is sent to one agent on the victim and one on another node at
  +10 s, +120 s and +300 s (where the window allows).
- **Between runs** every fleet was restarted and given time to settle (and to let the 1-minute load
  average fall) so each run starts from the same shape. Agents do not rebalance by themselves.

## Caveats (read before quoting any number)

- **One host, shared with other jobs.** Absolute times are indicative; the comparison between modes is
  what the data supports. The 1-minute load average at the moment of each fault is in
  `ws13-0/results.csv`. Nearly all runs started below 5 on 32 cores; the exceptions are noted in the
  CSV (one 100-agent kill at 52 from the harness's own restart burst; one at 11). Repeat runs agree
  closely, which argues against contention swinging the results, but cannot rule out a constant offset.
- **Docker is not a real network.** `docker kill` produced a clean FIN/RST within 40-70 ms every time.
  Real node loss can be silent; that is what F2p covers.
- **DNS here is a static zone served by CoreDNS in the same host.** Real resolver behaviour (TTL,
  caching, negative caching) was not modelled. Fixed-order (non-shuffled) A records were **not**
  measured: a fixed order might concentrate all agents on one node. H6 (a replaced node on a new
  IP) was **not** run.
- **One server replica.** Dispatch results (F3, H7) say nothing about a second replica, where the
  route directory is used instead of the server's own session.
- Runs per cell are small (1-4). Ranges below are the min-max over the runs, not confidence intervals.
- Per-agent footprint: about 20 MiB resident and 61 threads, flat from 20 to 300 agents.

## Results

"Noticed" is when the agent logged the loss of its stream; "re-registered" is the first successful
Register after the fault. Times in seconds, from the fault. All agents on the victim re-registered on a
surviving node in every run listed.

| Fault | Addressing | Agents | Runs | On victim | Noticed p50 | Re-registered p50 | p99 / worst |
|---|---|---|---|---|---|---|---|
| F1 kill | DNS | 100 | 3 | 34-38 | 6.9-8.0 | 9.4-9.9 | 12.8-13.2 |
| F1 kill | DNS | 300 | 4* | 107-114 | 7.2-8.0 | 9.4-9.9 | 12.7-13.2 |
| F1 kill | VIP, default | 100 | 3 | 34 | 7.0-7.9 | 18.4-20.2 | 24.4-25.2 |
| F1 kill | VIP, redispatch | 100 | 3 | 34 | 6.3-7.1 | 12.2-13.4 | 15.1-16.3 |
| F1 kill | VIP, default / redispatch | 300 | 1 / 1 | 100 | 7.9 / 8.0 | 18.6 / 14.0 | 24.6 / 16.2 |
| F1g graceful stop | DNS | 100 | 1 | 44 | 7.9 | 10.8 | 16.0 |
| F2p full partition | DNS | 100 | 1 | 35 | 44.7 | 47.5 | 61.7 |
| F2 (silent) | DNS | 100 | 3 | 35-44 | 43.9-47.5 | 46.2-50.1 | 61.1-62.7 |
| F2p full partition | VIP, default | 100 | 3 | 34 | 22.6-25.6 | 24.2-27.4 | 28.0-30.4 |
| F2p full partition | VIP, redispatch | 100 | 2 | 34 | 22.8-23.2 | 24.5-26.0 | 28.4-29.1 |
| F2p full partition | VIP, default | 300 | 1 | 100 | 22.9 | 24.5 | 28.5 |
| F2 agent port only (health check stays green) | VIP | 100 | 3 | 24 | 114.8-116.5 | 117.6-121.9 | 131.2-135.8 |

\* Two of the four 300-agent DNS kill runs are the H7 runs below (the management address does not change
agent failover).

Registration peaked at 8-10 per second at 100 agents and 22-28 per second at 300 agents (agents on the
victim re-register spread over about 8 s). **No "overloaded" or refusal message appeared in any gateway
or server log in any run.**

### Node up, path to the server dropped (F3, F3x)

| Run | Agents | On victim | Agents that moved | `/readyz` flipped | Routes non-routable | Routes tombstoned | Undo to ready / all routable |
|---|---|---|---|---|---|---|---|
| F3 DNS | 20 | 18 | 0 | never | 68-80 s | 275 s | (n/a) / ~7 s |
| F3 DNS | 100 | 35 | 0 | never | 61-90 s | 381 s | not timed |
| F3 DNS | 300 | 111 | 0 | never | 60-89 s | not within 400 s | 1 s / 2 s |
| F3 VIP | 100 | 34 | 0 | never | 60-91 s | 269 s | not timed |
| F3 VIP | 300 | 100 | 0 | never | 60-89 s | 244 s | 1 s / 6 s |
| F3x DNS (full isolation) | 100 | not recorded | 0 | never | not computed | not computed | not timed |

Every dispatch probe that was sent in an F3/F3x run was **delivered** (5-6 probes per run). The probes
include agents on the victim at +120 s, after their routes were no longer routable, and at +300 s where
the victim's rows had not yet been tombstoned. (Once a row is tombstoned the harness cannot pick a
victim agent from the route table, so later victim-side probes were not sent.) This is the single-replica case (the server uses its own
session for the agent). In F3x the victim's own link to the server was down, and commands still arrived
because the management plane was fronted by the VIP and a different node relayed to the victim across
the gateway cluster.

### Management plane addressed at one node (H7)

With `--gateway-command-addr` set to `gateway-1:50063` only and gateway-1 killed (2 runs, 300 agents):
107-108 agents re-registered on survivors (median 9.4-9.7 s), **but dispatch to agents on the healthy
nodes failed** ("Gateway unreachable", or no result inside the wait) at +10 s and at +120 s. Every probe
in the VIP-fronted runs was delivered.

## Findings

1. **A VIP or a multi-A DNS name, with no agent code, fails agents over in every kill and partition
   scenario measured**, with real TLS (the SANs on one shared gateway certificate were enough), at 20,
   100 and 300 agents, with no refusals. This supports D1. It does not show that agent code is never
   needed (fixed-order DNS, a real resolver, and a static node list with no DNS were not measured).
2. **DNS is faster for a clean kill (about 9.5 s median); a VIP is faster for a silent partition
   (about 25 s against about 46 s).** A VIP's health-check window (about 9 s) costs a kill about 10 s over
   DNS, because HAProxy keeps sending new connections to the dead node until its check fails. With
   `option redispatch` the VIP kill penalty falls to about 3 s over DNS. **If a VIP is used, redispatch
   belongs in the reference configuration.**
3. **A VIP does not protect against a half-working node.** If only the agent port is blackholed and the
   health port still answers, HAProxy does not eject the node and agents wait out their own timeouts
   (median about 118 s, worst about 136 s), the worst case measured. Choose health checks that exercise
   the agent port.
4. **Neither a VIP nor DNS can see a gateway that is up but cut off from the server (the "node up,
   upstream dead" gap).** `/readyz` never changed in six runs; agents never moved. The effect was mild
   and self-healing in this single-replica rig: dispatch kept working, routes became non-routable at
   about 60-90 s, were tombstoned at about 244-381 s (or not within 400 s), and all agents were
   routable again 2-6 s after the path returned (300 agents). The multi-replica case, where dispatch
   depends on the route directory, was not tested. The reading of the code is that the gateway's
   circuit breaker is fed only by Register and inventory calls, not by heartbeat flushes, so `/readyz`
   stays green under heartbeat-only traffic.
5. **Agent failover and command dispatch are separate things.** With the server's management address on
   one gateway, killing that gateway made the whole fleet undispatchable although every agent had
   re-attached (H7). Fronting the management plane with the same kind of VIP avoids this. This is not
   something the agent-side design of 13.2 can address.
6. **A restored gateway comes back empty.** In the minutes after a node returned it held no agents.
   Agents do not rebalance (observed directly at 20 agents; every later settle restarted the fleet, so
   longer-term behaviour was not observed). This is evidence for the failback work (WS-15, #5759).
7. **About 7 s of the agents' recovery after a clean FIN/RST is agent-side teardown, before the
   reconnect starts.** The packet capture sees the reset within 40-70 ms of the kill, but "Subscribe
   stream ended" is logged about 6-8 s later (heartbeat thread stop, then the concurrency-claim keepalive
   thread stop), followed by the 13.1 jitter delay (1-3 s for the first retry) and the Register. This is
   the largest single contributor to kill recovery time. Its cause was not investigated.
8. **No flap-back was observed** (no agent returned to its first node during any run's window, 45 runs,
   sampled once a second). The period after a partition heals was not observed for stale sessions,
   because the next settle restarted the fleet.

## Hypothesis scorecard

| # | Claim | Outcome |
|---|---|---|
| H1 | Clean kill: agents re-attach to survivors, TLS passes | Confirmed (about 9.5 s DNS) |
| H2 | Silent partition: detection bounded by keepalive; a VIP with a health check is faster | Confirmed (about 46 s DNS, about 25 s VIP); not for a green health check (about 118 s) |
| H3 | Node up, server path dropped: agents stay; routes expire; self-heals | Confirmed (single replica) |
| H3b | `/readyz` stays 200, a VIP will not eject the node | Confirmed (6 runs, both modes) |
| H4 | Reconnect of a third of the fleet with 13.1 jitter does not overload Register | Confirmed up to 114 agents at once (peak 28 registers/s, no refusals) |
| H5 | A restored node stays empty | Observed, short horizon |
| H6 | DNS: a replaced node on a new IP is found only after the resolver cooldown | **Not run** |
| H7 | Single management address: killing that node breaks dispatch fleet-wide | Confirmed (2 runs) |
| H8 | Stale session re-announce after a partition heals | No reversion seen during the windows; post-heal period not observed |
| H9 | In-flight command at fault time: lost / duplicated / delivered once | **Not run** (no suitable long-running action was identified) |

## Not measured, voided, or limited

- **Not run:** H6, H9, fixed-order DNS, a static endpoint list with no DNS (13.2's case), a real
  resolver with TTLs, a multi-replica server, PROXY-protocol / client-address attribution behind a VIP,
  and TLS session resumption across nodes.
- **Voided runs** (kept in `ws13-0/results.csv` with a note): the first H7 kill (dispatch probes got HTTP
  401 after a server recreate), and a gateway-1 partition run whose victim held no agents. The early
  VIP F2 runs are retained but are labelled "agent port only", not a full partition.
- **Packet capture** was missing for the first 20-agent kill (a container name clash, fixed).
- Raw logs and secrets are not committed. The summary CSV is the artefact.

## What this means for the open decisions (inputs, not decisions)

- **13.2 (agent endpoint list):** nothing here shows it is needed for the VIP/multi-A shapes. Whether a
  deployment with a static node list and no DNS needs it was not tested.
- **13.6 (gateway closes agent streams after a long upstream outage):** the failure it addresses is mild
  and self-healing in a single-replica rig. Its urgency depends on the multi-replica case, which this
  slice could not test.
- **#6920 (what belongs in the gate):** finding 5 (management-plane addressing) is a failover property
  that no agent-side slice covers. It is a candidate gate item in its own right.
- **13.4 (rollout runbook):** the agent-to-gateway edge is one-way TLS (the gateway does not verify
  agent client certificates; mutual TLS applies only between server and gateways). Behind a VIP in
  `mode tcp` every agent's peer address is the proxy.
- **WS-15:** finding 6.
- **A new candidate issue:** finding 7 (agent teardown latency after a clean reset).

## Reproduce

```
# images (once), from the commit under test
docker build -t yuzu-spike-server:<sha>  -f deploy/docker/Dockerfile.server  .
docker build -t yuzu-spike-gateway:<sha> -f deploy/docker/Dockerfile.gateway .
docker build -t yuzu-spike-agent:<sha>   -f deploy/docker/Dockerfile.agent   .

scripts/ha/ha-gateway-failover-spike.sh up --tag <sha> --agents 100 --dns-order shuffled
scripts/ha/ha-gateway-failover-spike.sh scenario F1  --mode dns --window 120
scripts/ha/ha-gateway-failover-spike.sh scenario F2p --mode vip --window 150
scripts/ha/ha-gateway-failover-spike.sh haproxy redispatch
scripts/ha/ha-gateway-failover-spike.sh mgmt node1          # H7
scripts/ha/ha-gateway-failover-spike.sh report | export <dir> | down
```

State and raw logs go under `~/.local/share/yuzu/ws13-spike/` (never the repository). The rig binds
no fixed host port except one random loopback port for the REST login, so it can run beside the
UAT and demo stacks.
