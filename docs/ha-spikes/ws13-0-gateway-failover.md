# HA WS-13 slice 13.0 - gateway failover with real agents and real TLS

Measured 2026-11-03/04 on one shared host. This is the record for slice 13.0 of WS-13 (#291,
ADR-2002 "gateway-fronting"). It is **input** to the open decisions (#6920 and slices 13.2, 13.4,
13.6), not a decision. **The safe-to-scale gate is not lifted by this record, and a second server
replica is still not safe.** Nothing in `docs/user-manual/`, ADR-2002 or the delivery matrix has been
edited to reflect these numbers; those edits belong to the slice that acts on them.

> **How to read every number below.** They come from one host that other jobs also used, in small
> numbers of runs (1-4 per cell), with the runs of one configuration taken back to back rather than
> interleaved. They are good for comparing addressing shapes and faults against each other. They are
> **not** production latencies and should not be quoted as such. Five results are lower bounds or rest
> on a rig that cannot exercise the production path; each is marked "lower bound" or "not measured"
> where it appears, and the follow-up measurements that would settle them are listed under "Not
> measured".

## What was measured, and why

D1 (2026-11-02) chose "a VIP or a multi-address DNS name, with no agent code" as the first failover
design. The only evidence was a one-off at the gRPC layer (gRPC 1.76, two test servers, `pick_first`
moved to the surviving address in about 1 s). It used no real agent, no TLS, and no silent partition,
and it kept no artefact. This slice repeats the question with the real agent daemon, real TLS, three
clustered gateways, a real server and Postgres, and 20 / 100 / 300 agents.

## Method

- **Build under test:** `origin/dev` at `416cf12d2` (includes 13.1, decorrelated reconnect jitter).
  Server, gateway and agent images were built from that commit with the repository's `Dockerfile.server`,
  `Dockerfile.gateway` and `Dockerfile.agent` (image ids: server `2497dbd7d0db`, gateway `50feb79eeac8`,
  agent `926eec7ec5bc`). The Postgres image was the repository's `yuzu-postgres:local`.
- **Rig:** `deploy/docker/docker-compose.ha-gateway-failover.yml` plus `deploy/docker/ha-gateway-failover/`,
  driven by `scripts/ha/ha-gateway-failover-spike.sh`. Server + Postgres + three gateways (clustered, one
  shared gateway leaf certificate) + HAProxy + CoreDNS + N real agents, one container each, with its own
  tmpfs data directory (so its own agent identity) and its own hostname. A fresh certificate volume per
  rig, with the SANs for every name the agents dial. The agents run with `--no-auto-update`,
  `--dex-disable`, `--inventory-disable` and `--spark-disable`, so on a steady fleet the only
  agent-to-server traffic is heartbeats, plus registrations after a fault.
- **Two ways to address the gateways**, switched by the agents' `--server`:
  - **DNS:** `gw-dns.ha.test`, three A records in a CoreDNS **static** zone. A dead gateway's record is
    **not** withdrawn (Docker's embedded DNS withdraws it instantly, which would flatter DNS), and the
    zone is served in shuffled order.
  - **VIP:** `gw-vip.ha.test`, HAProxy in `mode tcp`, health-checking each gateway's `/readyz` every
    3 s (down after 3 failures, `on-marked-down shutdown-sessions`). A variant adds
    `retries 3` and `option redispatch`.
- **Server to gateway management plane:** behind a second HAProxy frontend (`gw-mgmt.ha.test`) in all
  runs except the "H7" runs, where `--gateway-command-addr` pointed at `gateway-1:50063` alone.
- **Faults**, injected from a sidecar in the node's own network namespace (no host root):
  - **F1** `docker kill` of the node holding the most agents. **F1g** `docker stop` (the gateway ends
    its sessions first).
  - **F2** silent drop of the agent port (50051) only. **F2p** silent drop of everything on the node
    except loopback (a full partition; this is the faithful "silent partition"). With DNS the agents
    connect straight to the node, so F2 and F2p are the same fault for them; with a VIP they are not,
    because the VIP's health check uses a different port (see finding 3).
  - **F3** the node stays reachable but its path to the server (port 50055) is dropped. The management
    plane (port 50063) is untouched. **F3x** the node is fully isolated from the server.
  - Each fault is classified with a packet capture on three agents attached to the victim. Only packets
    whose source is the gateway side (the node, or the VIP) count as a peer FIN/RST; an agent's own FIN
    after it gives up is not a signal.
- **Observation:** re-attach times come from the agents' own container logs (millisecond timestamps)
  joined to the harness's fault timestamp; route state from `agent_routes` in Postgres once a second;
  `/readyz` and `yuzu_gw_agents_current` per gateway once a second. After each fault, one
  `os_info.os_name` command is sent to one agent on the victim and one on another node at +10 s, +120 s
  and +300 s (where the window allows). A probe is classed Y (delivered), U (the server reported
  "gateway unavailable"), T (accepted by the server, no result within 6 s), or H4xx (HTTP error).
- **Between runs** every fleet was restarted and given time to settle so each run starts from the same
  shape. Agents do not rebalance by themselves.

## Provenance and limits of this record

- **Host:** Ubuntu 26.04, Linux 7.0, Docker 29.1.3 (cgroup v2), 16 physical cores / 32 hardware threads,
  122 GB. The infrastructure containers were pinned to CPUs 0-15 and the agents to CPUs 16-31; those are
  the SMT siblings of one another (CPU n and n+16 share a core), so the pinning separates logical CPUs
  but not physical cores. Other jobs also ran on the host; only the load average was recorded.
- **Host load at the fault** is in `ws13-0/results.csv` for every run. Four runs started at a 1-minute
  load of 5 or more: a 100-agent kill at 52.5 (the harness's own restart burst; its re-registration
  median, 9.9 s, matches its quiet siblings at 9.4 and 9.9 s, though agent-side detection was slower at
  8.0 s against 6.9 and 7.7 s), a no-fault control at 19.2, a port-only partition at 11.2, and a 300-agent
  full partition at 7.7. All others were below 5.
- **The harness changed during the campaign.** The settle step gained a wait for load to fall after the
  first 100-agent runs; the full-partition scenario (F2p) and the HAProxy redispatch variant were added
  after the first VIP runs; recovery timing was added after the first two F2p runs; and several rig
  defects were fixed along the way (file permissions on the server config, a name the server could not
  resolve, a REST port that changes on a server restart, a stale login). The committed script is the
  final version (`git hash-object` `019240c77943` before this record's last edits). Derived columns in
  the CSV (peer FIN/RST timing, "gateway is busy" counts, route and `/readyz` timelines) were recomputed
  from the raw run data with the final analysis code, so they are consistent across the early and late runs.
- **Raw data is not committed.** The per-run logs, route samples and packet captures (about 1.1 GB) exist on
  the measuring host only. The CSV is the only retained record, so the numbers are not independently
  reproducible from this repository; the rig is, which reproduces the measurements, not the figures.
- **Docker is not a real network.** The kill produced a peer FIN/RST within 41-95 ms in the 9 DNS-mode kill
  runs that had a capture (the tenth had none). In the VIP kill runs 6 of 7 captured runs saw it within
  39-72 ms and one saw it at 16.2 s (the VIP closing the sessions after marking the node down); one run
  had no capture. Real node loss can be silent; that is what F2p covers.
- **DNS here is a static zone served by CoreDNS on the same host.** Resolver behaviour (TTL, caching,
  negative caching) was not modelled. Fixed-order A records were **not** measured: a fixed order might
  concentrate all agents on one node.
- **One server replica.** Dispatch results (F3, H7) say nothing about a second replica, where the route
  directory is used instead of the server's own session.
- **Run order.** The runs of one configuration were taken consecutively. HAProxy's 3 s health-check phase
  relative to each fault was not controlled, so a difference of about one check cycle (3 s) between
  configurations, such as the redispatch variant's, is indicative only.
- Per-agent footprint: about 20 MiB resident and 61 threads, flat from 20 to 300 agents.

## Results

"Noticed" is when the agent logged the loss of its stream; "re-registered" is the first successful
Register after the fault. Times in seconds, from the fault, over the victim's agents that re-registered
inside the window. Each cell is the min-max over the runs. "k / N" is how many of the agents that were on
the victim re-registered by the end of the window.

| Fault | Addressing | Agents | Runs | On victim | Re-registered | Noticed p50 | Re-registered p50 | p99 / worst |
|---|---|---|---|---|---|---|---|---|
| F1 kill | DNS | 20 | 2 | 9-13 | all | 6.1 | 8.2-8.8 | 10.3-12.7 |
| F1 kill | DNS | 100 | 3 | 34-38 | all | 6.9-8.0 | 9.4-9.9 | 12.8-13.2 |
| F1 kill | DNS | 300 | 2 | 110-114 | all | 7.2-7.8 | 9.6-9.9 | 12.7-13.1 |
| F1 kill | VIP, default | 100 | 3 | 34 | all | 7.0-7.9 | 18.4-20.2 | 24.4-25.2 |
| F1 kill | VIP, default | 300 | 1 | 100 | all | 7.9 | 18.6 | 24.6 |
| F1 kill | VIP, redispatch | 100 | 3 | 34 | all | 6.3-7.1 | 12.2-13.4 | 15.1-16.3 |
| F1 kill | VIP, redispatch | 300 | 1 | 100 | all | 8.0 | 14.0 | 16.2 |
| F1g graceful stop | DNS | 100 | 1 | 44 | all | 7.9 | 10.8 | 16.0 |
| F2 agent port only | DNS | 20 | 1 | 11 | all | 39.0 | 41.5 | 50.5 |
| F2 agent port only | DNS | 100 | 3 | 35-44 | all | 43.9-47.5 | 46.2-50.1 | 61.1-62.7 |
| F2p full partition | DNS | 100 | 1 | 35 | all | 44.7 | 47.5 | 61.7 |
| F2p full partition | VIP, default | 100 | 3 | 34 | all | 22.6-25.6 | 24.2-27.4 | 28.0-30.4 |
| F2p full partition | VIP, default | 300 | 1 | 100 | all | 22.9 | 24.5 | 28.5 |
| F2p full partition | VIP, redispatch | 100 | 2 | 34 | all | 22.8-23.2 | 24.5-26.0 | 28.4-29.1 |
| F2 agent port only, VIP health check green | VIP, default | 100 | 3 | 34 | **24 / 34** | 114.8-116.5 | 117.6-121.9 | 131.2-135.8 (**lower bounds**) |

**The last row is right-censored.** In each of those three runs, 10 of the 34 victims had **not**
re-registered 150 s after the fault, when the window ended. The medians and worst values are over the 24
that had; the true median and worst case are higher than shown and were not measured.

Registration peaked at 8-10 per second at 100 agents; at 300 agents it peaked at 23-25 per second in the
two plain DNS kills (110-114 agents), 22-27 in the VIP kills (100 agents), and 28 in the two H7 runs
(107-108 agents), spread over about 8 s. **No agent log in any of the 45 runs contains the gateway's
"the gateway is busy" refusal** (the text the gateway returns when its upstream permits are all held),
and none contains an upstream-permit message. (An earlier version of the exporter searched the gateway
and server logs for the word "overloaded", which the gateway does not log per request; that column was
a false zero and has been replaced.)

Timing of the peer-originated FIN/RST, where captured, helps explain the VIP rows: in the full-partition
VIP runs the VIP closed the sessions 15.4-17.7 s after the fault (its health check marking the node
down), and agents noticed about 7 s later (22.6-25.6 s). With a clean kill the reset arrives in tens of
milliseconds and agents still notice only 6-8 s later (finding 7).

### Node up, path to the server dropped (F3, F3x)

| Run | Agents | On victim | Agents that moved | Victim `/readyz` non-200 | Routes non-routable (k / N, when) | Routes tombstoned (k / N, when) | Undo: ready / all routable |
|---|---|---|---|---|---|---|---|
| F3 DNS | 20 | 18 | 0 | never | 18 / 18, 68-80 s | 18 / 18, 275 s | not timed by the harness (about 7 s by hand) |
| F3 DNS | 100 | 35 | 0 | never | 35 / 35, 61-90 s | 35 / 35, 381 s | not timed |
| F3 DNS | 300 | 111 | 0 | never | 111 / 111, 60-89 s | **0 / 111 within 400 s** | 1 s / 2 s |
| F3 VIP | 100 | 34 | 0 | never | 34 / 34, 60-91 s | 32 / 34, 269 s | not timed |
| F3 VIP | 300 | 100 | 0 | never | 100 / 100, 60-89 s | **12 / 100 within 400 s**, 244 s | 1 s / 6 s |
| F3x DNS (full isolation) | 100 | 43 | 0 | never | 43 / 43, 62-91 s | 0 / 43 within 400 s | not timed |

Every dispatch probe sent in an F3/F3x run was delivered (5-6 probes per run). The probes include agents
on the victim at +120 s, after their routes were no longer routable. This is the single-replica case: the
server uses its own session for the agent. (Once a row is tombstoned the harness cannot pick a victim
agent from the route table, so later victim-side probes were not sent.) In F3x the victim's own link to
the server was down, and commands still arrived because the management plane was fronted by the VIP and a
different node relayed to the victim across the gateway cluster.

### Other dispatch outcomes

| Fault and management address | Probe target | Delivered |
|---|---|---|
| F1, management plane behind the VIP | agent on a node that stayed up | 19 / 19 |
| F1, management plane behind the VIP | agent on the dead node | 14 / 15 (the miss was an agent still re-registering) |
| **F1, management address on `gateway-1` only; `gateway-1` killed (H7, 2 runs, 300 agents)** | agent on a node that stayed up | **0 / 4** (3 "gateway unavailable", 1 accepted with no result) |
| same | agent on the dead node | 0 / 2 (1 "gateway unavailable", 1 accepted with no result) |
| F2 agent port only, VIP-fronted management plane | agent on the victim | 0 / 10 (accepted, no result) |
| F2p full partition, VIP-fronted management plane | agent on a node that stayed up / on the victim | 14 / 14 and 0 / 7 |

### Controls

Five no-fault runs (20, 20, 20, 100 and 100 agents; DNS and VIP): zero agents changed node in any of them.
The first two had harness defects at the time (a readyz-parsing glitch and a management name the server
could not resolve, so both of its probes failed); they were not used for any claim beyond "no movement".

## Findings

1. **A VIP or a multi-A DNS name, with no agent code, re-registered every agent on a failed node in every
   kill and full-partition run measured**, with real TLS (one shared gateway certificate with the right
   SANs was enough), at 20, 100 and 300 agents. This is consistent with D1 for these topologies; it does
   not test the cases 13.2 exists for (a static node list with no DNS, fixed-order or real-resolver DNS),
   and it excludes the half-working-node case in finding 3.
2. **DNS was faster for a clean kill (re-registered median about 9.5 s); the VIP was faster for a full
   silent partition (about 25 s against about 47 s).** A VIP's health-check window (about 9 s) costs a
   kill about 10 s over DNS in these runs, because HAProxy keeps sending new connections to the dead node
   until its check fails. In the runs with `retries 3` and `option redispatch` that penalty fell to about
   3 s (3-4 runs per cell, uncontrolled health-check phase: indicative). `option redispatch` is a
   candidate setting for any reference VIP configuration, to be confirmed.
3. **A VIP does not help against a half-working node.** When only the agent port was blackholed and the
   health port still answered, HAProxy did not eject the node. Of 34 agents on it, 24 re-registered by
   +150 s, after a median of about 118 s; **10 had not re-registered when the window ended**, so the
   numbers in the table are lower bounds. A health check that exercises the agent port would catch this
   fault; that was not measured.
4. **In this rig, neither a VIP nor DNS could see a gateway that is up but cut off from the server, and
   what it means for a production fleet is not measured.** In six F3/F3x runs the victim's `/readyz` never
   changed and no agent moved, and the effect on the server side was mild and self-healing: dispatch kept
   working, routes became non-routable at about 60-90 s, were tombstoned (in 0-100 % of cases) between
   244 and 381 s, and every agent was routable again 2-6 s after the path returned (300 agents). But this
   fleet had inventory, DEX and Spark collection disabled and no churn, so nothing but heartbeats crossed
   the gateway-to-server link; the reading of the code is that the gateway's circuit breaker is fed by
   Register and inventory calls, not by heartbeat flushes. When something else fed it the breaker did
   open: in the one full-partition run long enough (200 s, 300 agents), the victim's `/readyz` went 503
   at +157 s. Whether a production fleet's registration and sync traffic would open the breaker, and so let
   a VIP eject such a node, was **not measured**, and the multi-replica case was not tested.
5. **Agent failover and command dispatch are separate things.** With the server's management address on
   one gateway, killing that gateway left every probe undelivered (6 probes in 2 runs: 4 to agents on surviving
   nodes, 2 to agents on the dead node) although all 107-108 agents on it had re-attached (H7). In the runs with the
   management plane behind a VIP, probes to agents on surviving nodes were delivered in 19 of 19 kill runs.
   This is not something the agent-side design of 13.2 can address.
6. **A restored gateway came back empty.** In the minutes after a node returned it held no agents; agents
   do not rebalance (observed directly at 20 agents; every later settle restarted the fleet, so longer-term
   behaviour was not observed). This is evidence for the failback work (WS-15, #5759).
7. **About 7 s of the agents' recovery after a clean FIN/RST is agent-side teardown, before the reconnect
   starts.** The reset is seen within tens of milliseconds, but "Subscribe stream ended" is logged about
   6-8 s later (heartbeat thread stop, then the concurrency-claim keepalive thread stop), followed by the
   13.1 jitter delay (1-3 s for the first retry) and the Register. This is the largest single contributor
   to kill recovery time in these runs. Its cause was not investigated.
8. **No flap-back was observed** (no agent returned to its first node during any run's window, 45 runs,
   sampled once a second). The period after a partition heals was not observed for stale sessions, because
   the next settle restarted the fleet.

## Hypothesis scorecard

| # | Claim | Outcome |
|---|---|---|
| H1 | Clean kill: agents re-attach to survivors, TLS passes | Observed (about 9.5 s DNS) |
| H2 | Silent partition: detection bounded by keepalive; a VIP with a health check is faster | Observed for a full partition (about 47 s DNS, about 25 s VIP); the green-health-check case is a lower bound (over 118 s) |
| H3 | Node up, server path dropped: agents stay; routes expire; self-heals | Observed (single replica, 6 runs) |
| H3b | `/readyz` stays 200, a VIP will not eject the node | Observed in this rig (static fleet, nothing feeding the breaker); **not established for a production fleet** |
| H4 | Reconnect of a third of the fleet with 13.1 jitter does not overload Register | Observed up to 114 agents at once (peak 23-25 registers/s; 28 in the H7 runs at 107-108 agents; no "gateway is busy" in any agent log) |
| H5 | A restored node stays empty | Observed, short horizon |
| H6 | DNS: a replaced node on a new IP is found only after the resolver cooldown | **Not run** |
| H7 | Single management address: killing that node breaks dispatch fleet-wide | Observed (2 runs) |
| H8 | Stale session re-announce after a partition heals | No reversion seen during the windows; post-heal period not observed |
| H9 | In-flight command at fault time: lost / duplicated / delivered once | **Not run** (no suitable long-running action was identified) |

## Not measured, voided, or limited

- **Follow-up measurements needed before any figure here is quoted in a #6920 decision:**
  1. the port-only VIP fault (finding 3) with a window long enough that every victim has re-registered;
  2. an F3 run with inventory, DEX and Spark enabled and some registration churn, to see whether the
     breaker opens and a VIP ejects the node (finding 4);
  3. a positive control for the "gateway is busy" check (an induced permit exhaustion), since "no refusal
     seen" is only informative if the detector can see one;
  4. an H7 control that proves the management address was the only difference.
- **Not run:** H6, H9, fixed-order DNS, a static endpoint list with no DNS (13.2's case), a real
  resolver with TTLs, a multi-replica server, PROXY-protocol / client-address attribution behind a VIP, and
  TLS session resumption across nodes.
- **Voided or qualified runs** (kept in `ws13-0/results.csv` with a note): two runs (one kill, one
  agent-port partition) taken with the management address on `gateway-1` only; the kill's dispatch probes
  are void (HTTP 401 after a server recreate) but its failover timings are valid, and the partition's
  probes are valid because the login was restored by hand mid-run. The early VIP F2 runs are labelled
  "agent port only", not a full partition, and as right-censored.
- **Packet capture** was missing for the first 20-agent kill (a container name clash, fixed) and for one
  VIP kill.
- The run configuration (DNS order, management address, HAProxy variant) was typed by hand when the CSV
  was exported for the runs taken before the harness began recording it in each run's metadata; the
  "haproxy" column for those runs reflects the operator's list.
- Raw logs and secrets are not committed. The summary CSV is the artefact.

## What this means for the open decisions (inputs, not decisions)

- **13.2 (agent endpoint list):** nothing here shows it is needed for the VIP and multi-A shapes tested.
  Whether a deployment with a static node list and no DNS needs it was not tested.
- **13.6 (gateway closes agent streams after a long upstream outage):** the failure it addresses was mild
  and self-healing in this single-replica, quiet-fleet rig. Its urgency depends on the multi-replica case
  and on whether production traffic feeds the breaker (follow-ups 2 and the multi-replica gap).
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
# the repository's Postgres image (the rig uses the tag yuzu-postgres:local)
docker build -t yuzu-postgres:local      -f deploy/docker/Dockerfile.postgres .

scripts/ha/ha-gateway-failover-spike.sh up --tag <sha> --agents 100 --dns-order shuffled
scripts/ha/ha-gateway-failover-spike.sh scenario F1  --mode dns --window 120
scripts/ha/ha-gateway-failover-spike.sh scenario F2p --mode vip --window 150
scripts/ha/ha-gateway-failover-spike.sh haproxy redispatch
scripts/ha/ha-gateway-failover-spike.sh mgmt node1          # H7
scripts/ha/ha-gateway-failover-spike.sh report | export <dir> | down
```

The rig is Linux and Docker only (it uses GNU `date`, `/proc/loadavg`, network namespaces and cgroup
cpusets); it was not run on macOS or Windows. State and raw logs go under `~/.local/share/yuzu/ws13-spike/`
(never the repository). The rig binds no fixed host port except one random loopback port for the REST
login, so it can run beside the UAT and demo stacks.
