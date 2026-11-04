# HA WS-13 slice 13.0 - gateway failover with real agents and real TLS

Measured 2026-11-03/04 on one shared host. This is the record for slice 13.0 of WS-13 (#291,
ADR-2002 "gateway-fronting"). It is **input** to the open decisions (#6920 and slices 13.2, 13.4,
13.6), not a decision. **The safe-to-scale gate is not lifted by this record, and a second server
replica is still not safe.** Nothing in `docs/user-manual/`, ADR-2002 or the delivery matrix has been
edited to reflect these numbers; those edits belong to the slice that acts on them. This record makes no
availability or recovery-time commitment and is not an SLO statement.

> **How to read every number below.** They come from one host that other jobs also used, in small numbers
> of runs (1-4 per cell), with the runs of one configuration taken back to back rather than interleaved.
> They are good for comparing addressing shapes and faults against each other. They are **not** production
> latencies and should not be quoted as such. Some results are lower bounds or rest on a rig that cannot
> exercise the production path: the VIP "health check stays green" row is right-censored (a lower bound);
> the conclusions about a gateway cut off from the server hold for a quiet fleet only; and the reconnect-load
> result (finding 9) shows recovery times, not capacity. Each is marked where it appears, and the follow-up
> measurements that would settle them are listed under "Not measured".

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
- **This harness is advisory.** It is a manual measurement tool: not wired into CI, it gates no merge, and
  its output is evidence for a human decision, not an automated check.
- **Two ways to address the gateways**, switched by the agents' `--server`:
  - **DNS:** `gw-dns.ha.test`, three A records in a CoreDNS **static** zone. A dead gateway's record is
    **not** withdrawn (Docker's embedded DNS withdraws it instantly, which would flatter DNS), and the
    zone is served in shuffled order.
  - **VIP:** `gw-vip.ha.test`, HAProxy in `mode tcp`, health-checking each gateway's `/readyz` every
    3 s (down after 3 failures, `on-marked-down shutdown-sessions`). A variant adds
    `retries 3` and `option redispatch`.
- **Server to gateway management plane ("Mgmt addr" in the tables):** behind a second HAProxy frontend
  (`gw-mgmt.ha.test`, "VIP") in all runs except the "H7" runs, where `--gateway-command-addr` pointed at
  `gateway-1:50063` alone ("single node").
- **Faults**, injected from a sidecar in the node's own network namespace (no host root):
  - **F1** `docker kill` of the node holding the most agents. **F1g** `docker stop` (the gateway ends
    its sessions first).
  - **F2** silent drop of the agent port (50051) only. **F2p** silent drop of everything on the node
    except loopback (a full partition; this is the faithful "silent partition"). With DNS the agents
    connect straight to the node, so F2 and F2p are the same fault for them; with a VIP they are not,
    because the VIP's health check uses a different port (finding 3).
  - **F3** the node stays reachable but its path to the server (port 50055) is dropped. The management
    plane (port 50063) is untouched. **F3x** the node is fully isolated from the server.
  - Each fault is classified with a packet capture on three agents attached to the victim. Only packets
    whose source is the gateway side (the node, or the VIP) count as a peer FIN/RST; an agent's own FIN
    after it gives up is not a signal.
- **Observation:** re-attach times come from the agents' own container logs (millisecond timestamps)
  joined to the harness's fault timestamp; route state from `agent_routes` in Postgres about once a second;
  `/readyz` and `yuzu_gw_agents_current` per gateway about once a second; the circuit-breaker state from
  the victim gateway's log. After each fault, one `os_info.os_name` command is sent to one agent on the
  victim and one on another node at +10 s, +120 s and +300 s (where the window allows). A probe is
  classed Y (a response with status SUCCESS and output), U (the server reported "gateway unavailable"),
  F (an answer with status FAILURE, TIMEOUT or REJECTED), T (accepted by the server, no result within 6 s),
  or H4xx (HTTP error). F can only occur in runs taken with the final harness, which records the response
  status; none of the 45 committed runs has it, so the F column of the Probes table is zero by construction. **S** marks a probe an earlier
  version of the harness scored as delivered although the server had synthesised a failure
  (`status=2`): the command id appears in no agent log of that run.
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
- **The harness clock ran ahead in the runs taken before the final script.** The fault timestamps came from
  `date +%s%3N` on a host whose `date` is uutils coreutils 0.10, and about one call in ten (143 of 1500
  tested) returned a stamp up to 0.9 s ahead of real time. A fault stamped late makes every duration measured
  from it too short. Where a gateway-originated reset was captured before the stamped fault, the fault was
  re-placed from the capture (41 ms before the first reset; the median delay in the runs with no stamp problem is about 44 ms): 2 runs, shifted
  by 0.6 s and 0.9 s (column `t0_shift_ms`). Runs without such evidence are **not** corrected and may be
  optimistic by up to about a second; the route and `/readyz` samples carry the same skew, and the sampler
  achieved about 0.77 Hz, not 1 Hz. The final script reads the clock from the shell's own built-in.
- **Commit messages on this branch overstate in places** (the first commit's headline result before the
  round-1 corrections; "tables are generated" while the management-address and HAProxy columns are
  operator-supplied; "reads the HAProxy variant from run metadata" for runs that recorded none). The commits
  were not rewritten because the governance ledger cites them by hash; this record is the statement of
  what was measured.
- **Percentiles** are the sorted value at index `round(p/100 x (n-1))` over the victim's agents, using
  Python's round-half-to-even, so for an even count the "median" is the upper or lower middle value
  depending on n. They are not interpolated.
- **The harness changed during the campaign.** The settle step gained a wait for load to fall after the
  first 100-agent runs; the full-partition scenario (F2p) and the HAProxy redispatch variant were added
  after the first VIP runs; recovery timing was added after the first two F2p runs; and several rig
  defects were fixed along the way (file permissions on the server config, a name the server could not
  resolve, a REST port that changes on a server restart, a stale login). **None of the 45 committed runs has
  its configuration in its `meta.txt`** (the DNS order, the management address, the HAProxy variant and the
  script hash were added to the metadata afterwards). The "Mgmt addr" and HAProxy columns, and which runs are
  the H7 and redispatch runs, therefore come from the operator's own notes, listed under "Run configurations"
  below. The addressing label (DNS or VIP) of those runs is likewise the mode that was requested, not one
  read back from the fleet (the harness now records the observed mode and marks a mismatch INVALID). Derived columns in the CSV (peer FIN/RST timing, route and `/readyz` timelines, breaker timing,
  probe classes) were recomputed from the raw run data with the final code, so they are consistent across
  the early and late runs.
- **Raw data is not committed (two series excepted), and no copy exists outside the measuring host.** The
  per-run logs, route samples and packet captures (about 1.1 GB, almost all of it the route samples) are on
  that host only. The exception is the two per-second gateway series under `ws13-0/raw/`, committed because
  the alerting paragraph cites them: columns are epoch milliseconds, gateway, the `/readyz` HTTP status (or
  `down`), and `yuzu_gw_agents_current`; there is no header line, and the fault is at epoch millisecond
  1793751229989 in the 300-agent run (`run-F2p-vip-001328`) and 1793743803557 in the 100-agent DNS run
  (`run-F2p-dns-220945`).
  The CSVs are the only retained record, so the numbers are not independently reproducible from this
  repository; the rig is, which reproduces the measurements, not the figures. Archiving the subset needed to
  recompute the CSVs is left to the maintainers.
- **This rig and this record are not a deployment pattern.** The rig relaxes what a deployment must not:
  fixed addresses on one bridge network; throwaway credentials that appear in this host's process list and
  `docker inspect` while it runs; one gateway certificate and key shared by three nodes (the reference rig's
  layout); an agent-to-gateway edge with one-way TLS, where the gateway does not verify agent client
  certificates; a `mode tcp` VIP without PROXY protocol, so the gateways see the proxy as every agent's
  address; a REST login over `curl -k` to the rig's own CA; no monitoring, persistence or hardening; and a
  management plane open on the bridge and protected only by the unchanged reference peer authorization. Do
  not copy its configuration, or a figure from this record, into a deployment or a runbook. Deployment
  guidance stays in `docs/user-manual/gateway.md` and, when it exists, the 13.4 rollout runbook.
- **Docker is not a real network.** A kill produced a gateway-side FIN/RST within tens of milliseconds
  (the Peer FIN/RST column). Real node loss can be silent; that is what F2p covers.
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
Register after the fault. Times are in seconds from the fault, over the victim's agents that re-registered
inside the window; each cell is the min-max over the runs of that row. "Re-registered" is how many of the
agents that were on the victim re-registered by the end of the window. The tables below are generated from
`ws13-0/results.csv` and `ws13-0/probes.csv` by `ha-gateway-failover-spike.sh export`, not typed by hand.

### Failover

<!-- BEGIN GENERATED: failover -->
| Fault | Addressing | Mgmt addr | Agents | Runs | On victim | Re-registered | Noticed p50 (s) | Re-registered p50 (s) | p99 (s) | Worst (s) | Peak regs/s | Peer FIN/RST (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F1 kill | DNS | VIP | 20 | 2 | 9-13 | all | 6.1 | 8.2-8.8 | 10.3-12.7 | 10.3-12.7 | - | 41 |
| F1 kill | DNS | VIP | 100 | 3 | 34-38 | all | 6.9-8.0 | 9.4-9.9 | 12.8-13.2 | 12.8-13.2 | 8-10 | 41-63 |
| F1 kill | DNS | single node | 100 | 1 | 33 | all | 7.4 | 9.0 | 12.6 | 12.6 | 10 | 61 |
| F1 kill | DNS | VIP | 300 | 2 | 110-114 | all | 7.2-7.8 | 9.6-9.9 | 12.7-13.0 | 12.9-13.1 | 23-25 | 45-47 |
| F1 kill | DNS | single node | 300 | 2 | 107-108 | all | 7.4-8.0 | 9.4-9.7 | 13.1 | 13.2 | 28 | 44-95 |
| F1 kill | VIP, default | VIP | 100 | 3 | 34 | all | 7.8-7.9 | 18.4-21.1 | 24.4-26.1 | 24.4-26.1 | 7-10 | 40-72 |
| F1 kill | VIP, redispatch | VIP | 100 | 3 | 34 | all | 6.9-7.1 | 12.8-13.4 | 15.7-16.3 | 15.7-16.3 | 8-9 | 39-68 |
| F1 kill | VIP, default | VIP | 300 | 1 | 100 | all | 7.9 | 18.6 | 24.6 | 24.6 | 22 | 43 |
| F1 kill | VIP, redispatch | VIP | 300 | 1 | 100 | all | 8.0 | 14.0 | 15.9 | 16.2 | 27 | 42 |
| F1g graceful stop | DNS | VIP | 100 | 1 | 44 | all | 7.9 | 10.8 | 16.0 | 16.0 | 15 | 9275 |
| F2p full partition | DNS | VIP | 100 | 1 | 35 | all | 44.7 | 47.5 | 61.7 | 61.7 | 3 | - |
| F2p full partition | VIP, default | VIP | 100 | 3 | 34 | all | 22.6-25.6 | 24.2-27.4 | 28.0-30.4 | 28.0-30.4 | 8-11 | 15441-17717 |
| F2p full partition | VIP, redispatch | VIP | 100 | 2 | 34 | all | 22.8-23.2 | 24.5-26.0 | 28.4-29.1 | 28.4-29.1 | 8 | 15702-16300 |
| F2p full partition | VIP, default | VIP | 300 | 1 | 100 | all | 22.9 | 24.5 | 28.5 | 28.5 | 24 | 15708 |
| F2 agent port only | DNS | VIP | 20 | 1 | 11 | all | 39.0 | 41.5 | 50.5 | 50.5 | - | - |
| F2 agent port only | DNS | VIP | 100 | 3 | 35-44 | all | 43.9-47.5 | 46.2-50.1 | 61.1-62.7 | 61.1-62.7 | 3-4 | - |
| F2 agent port only | DNS | single node | 100 | 1 | 34 | all | 48.2 | 50.7 | 63.3 | 63.3 | 3 | - |
| F2 agent port only (VIP health check stays green) | VIP, default | VIP | 100 | 3 | 34 | **24 of 34** | 114.8-116.5 | 117.6-121.9 | 131.2-135.8 | 131.2-135.8 | 2 | 137812-147455 |
<!-- END GENERATED: failover -->

The **bold** "24 of 34" row is **right-censored**: in each of those three runs 10 of the 34 victims had not
re-registered when the window ended, 150 s after the fault. The **re-registered** median and worst values
are over the 24 that had, so they are lower bounds; the true values are higher and were not measured. The
"noticed" median is over all 34 victims, every one of which had noticed the loss by 130 s. The "single node"
rows were taken with the management address on one gateway and do not differ from their VIP-managed
siblings in failover time (that address affects dispatch, not agents).

### Full partitions and a gateway cut off from the server

<!-- BEGIN GENERATED: faults-f3-f2p -->
| Run | Fault | Addressing | Agents | On victim | Moved | Victim /readyz non-200 | Breaker opened (s) | Non-routable (k / N, when s) | Tombstoned (k / N, when s) | Undo: ready / all routable (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| F2p-dns-220945 | F2p | DNS | 100 | 35 | 35 | none to +149s | 162 | - | - | 5 / 5 |
| F2p-vip-001328 | F2p | VIP | 300 | 100 | 100 | 157 | 157 | - | - | 30 / 30 |
| F2p-vip-214249 | F2p | VIP | 100 | 34 | 34 | none to +150s | 156 | - | - | - / - |
| F2p-vip-215144 | F2p | VIP | 100 | 34 | 34 | none to +150s | 158 | - | - | - / - |
| F2p-vip-220044 | F2p | VIP | 100 | 34 | 34 | none to +149s | 162 | - | - | 6 / 6 |
| F2p-vip-224347 | F2p | VIP | 100 | 34 | 34 | none to +150s | 161 | - | - | 23 / 23 |
| F2p-vip-225245 | F2p | VIP | 100 | 34 | 34 | none to +150s | 159 | - | - | 21 / 22 |
| F3-dns-013638 | F3 | DNS | 300 | 111 | 0 | none to +399s | never | 111 / 111, 60-89 | 0 / 111 | 1 / 2 |
| F3-dns-174502 | F3 | DNS | 20 | 18 | 0 | none to +400s | n/a | 18 / 18, 68-80 | 18 / 18, 275 | - / - |
| F3-dns-193321 | F3 | DNS | 100 | 35 | 0 | none to +400s | never | 35 / 35, 61-90 | 35 / 35, 381 | - / - |
| F3-vip-020123 | F3 | VIP | 300 | 100 | 0 | none to +399s | never | 100 / 100, 60-89 | 12 / 100, 244 | 1 / 6 |
| F3-vip-210017 | F3 | VIP | 100 | 34 | 0 | none to +399s | never | 34 / 34, 60-91 | 32 / 34, 269 | - / - |
| F3x-dns-194637 | F3x | DNS | 100 | 43 | 0 | none to +400s | never | 43 / 43, 62-91 | 0 / 43 | - / - |
<!-- END GENERATED: faults-f3-f2p -->

In `results.csv` the `victim_readyz_non200_s` column is blank for every run in which `/readyz` never went
non-200 within the sampled window, so a blank is only as strong as the `readyz_sampled_to_s` column beside it
(the series ends at +149 or +150 s for the six 100-agent F2p runs, before the breaker opened, and at +399 or
+400 s for the F3/F3x runs). The `breaker_open_s` column, from the gateway log, shows 156-162 s in all seven
F2p runs: for those six, blank means "not sampled long enough", not "never".
For F3/F3x "Moved" is 0 by construction (the agents never left). In the F2p rows the victim's circuit
breaker opened at 156-162 s in every run; the 100-agent runs' windows (150 s) ended before `/readyz`
followed, and the one run whose window outlasted it (300 agents, 200 s) shows `/readyz` at 157 s. In the F3
and F3x runs for which a gateway log was kept the breaker never opened in 400 s ("n/a" marks a run with no
gateway log: the 20-agent F3 run; for it only `/readyz`, which includes the breaker, stayed 200). Routes are tombstoned by the server's periodic reap sweep, so
the tombstone times (244-381 s, and none within 400 s in two runs) reflect the sweep's phase rather than
anything about the fault.

### Dispatch probes

<!-- BEGIN GENERATED: probes -->
| Fault | Mgmt addr | Probe target | Probes | Delivered (Y) | Server-synthesised failure scored as delivered by the old harness (S) | Gateway unavailable (U) | Failure status (F) | Accepted, no result (T) | Other |
|---|---|---|---|---|---|---|---|---|---|
| F1 | VIP | on the victim | 15 | 0 | 14 | 0 | 0 | 1 | 0 |
| F1 | VIP | other node, had been on the victim | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| F1 | VIP | unaffected node | 14 | 14 | 0 | 0 | 0 | 0 | 0 |
| F1 | single node | on the victim | 2 | 0 | 0 | 1 | 0 | 1 | 0 |
| F1 | single node | other node, had been on the victim | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| F1 | single node | unaffected node | 3 | 0 | 0 | 3 | 0 | 0 | 0 |
| F1g | VIP | unaffected node | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| F2p | VIP | on the victim | 7 | 0 | 0 | 0 | 0 | 7 | 0 |
| F2p | VIP | other node, had been on the victim | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| F2p | VIP | unaffected node | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| F2 | VIP | on the victim | 10 | 0 | 0 | 0 | 0 | 10 | 0 |
| F2 | VIP | other node, had been on the victim | 4 | 2 | 0 | 0 | 0 | 2 | 0 |
| F2 | VIP | unaffected node | 10 | 10 | 0 | 0 | 0 | 0 | 0 |
| F2 | single node | on the victim | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| F2 | single node | other node, had been on the victim | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| F2 | single node | unaffected node | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| F3 | VIP | on the victim | 14 | 14 | 0 | 0 | 0 | 0 | 0 |
| F3 | VIP | unaffected node | 15 | 15 | 0 | 0 | 0 | 0 | 0 |
| F3x | VIP | on the victim | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| F3x | VIP | unaffected node | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
<!-- END GENERATED: probes -->

"Other node, had been on the victim" are agents that had already re-attached elsewhere when probed;
"unaffected node" are agents that never moved. Runs whose probe results are void (HTTP 401 after a server
recreate) are left out. In F3x the victim's own link to the server was down and commands still arrived; the
likely route is that a different node relayed to the victim across the gateway cluster, but that is an
inference: a direct path from the VIP to the victim was open and the relay was not observed.

Registration peaked at about 7-15 per second at 100 agents (15 for the graceful stop) and 22-28 per second
at 300 agents, spread over about 8 s (see the Failover table).

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
2. **DNS was faster for a clean kill (re-registered median about 9-10 s); the VIP was faster for a full
   silent partition (about 24-27 s against about 47 s).** A VIP's health-check window (about 9 s) costs a
   kill about 9-11 s over DNS in these runs, because HAProxy keeps sending new connections to the dead node
   until its check fails. In the runs with `retries 3` and `option redispatch` the penalty was about 3-4 s
   (3-4 runs per cell, uncontrolled health-check phase: indicative). `option redispatch` is a candidate
   setting for any reference VIP configuration, to be confirmed.
3. **A VIP does not help against a half-working node.** When only the agent port was blackholed and the
   health port still answered, HAProxy did not eject the node. Of 34 agents on it, 24 re-registered by
   +150 s, after a median of about 118 s; **10 had not re-registered when the window ended**, so the
   figures are lower bounds, and no probe to an agent on the victim was delivered. A health check that
   exercises the agent port would catch this fault; that was not measured. The DNS median for the same
   fault (about 46-50 s, worst about 61-63 s) sits inside the roughly 80 s keepalive bound ADR-2002 quotes;
   the VIP case exceeds it, and why was not investigated.
4. **A gateway that is up but cut off from the server was invisible to `/readyz` in a quiet fleet, and
   what it means for a production fleet is not measured.** In six F3/F3x runs the victim's `/readyz` never
   changed and its breaker never opened in 400 s; no agent moved. The ADR's "known gap, unconfirmed"
   precondition is therefore confirmed for this rig. Its consequence is not: on this single-replica server
   dispatch kept working, routes became non-routable at about 60-90 s, and every agent was routable again
   2-6 s after the path returned (300 agents), but the harmful case, route-directory dispatch on two or more
   replicas, could not be tested here. The fleet also had
   inventory, DEX and Spark collection disabled and no churn, so almost nothing but heartbeats crossed the
   link; the reading of the code is that Register, inventory and stream-status calls feed the breaker and
   heartbeat flushes do not. That matches the full-partition runs: when the node was cut off completely the
   agents left, and the breaker opened at +156 to +162 s in all seven F2p runs. A node with a dead
   upstream path and live agents is therefore invisible to a VIP's `/readyz` check only while nothing feeds
   the breaker. Whether a production fleet's registration and sync traffic would open it, and so let a VIP
   eject such a node, was **not measured**, and the multi-replica case was not tested.
5. **Agent failover and command dispatch are separate things.** With the server's management address on
   one gateway, killing that gateway left every probe undelivered (0 of 4 to agents on surviving nodes and 0 of 2 to agents on the dead
   node, in the table) although every agent on the dead node had re-attached (H7). In the runs with the management
   plane behind a VIP, every probe to an agent that had never moved was delivered, and so was every probe to
   an agent that had re-attached after a kill or a full partition (the Probes table). **Not so after the
   agent-port-only fault:** 2 of 4 probes to agents that had re-attached elsewhere were accepted by the server
   and never reached an agent (finding 10). This is not something the agent-side design of 13.2 can address.
6. **A restored gateway came back empty.** In the minutes after a node returned it held no agents; agents
   do not rebalance. This was seen by eye during the early 20-agent runs and no run artefact retains it
   (every later run began with a settle step that restarted the fleet), so it is **unverified here**; it is
   consistent with the design (nothing in the agent or the gateway moves a connected agent) and is the
   question the failback work (WS-15, #5759) exists for.
7. **About 7 s of the agents' recovery after a clean FIN/RST is agent-side teardown, before the reconnect
   starts.** The reset is seen within tens of milliseconds, but "Subscribe stream ended" is logged about
   6-8 s later (heartbeat thread stop, then the concurrency-claim keepalive thread stop), followed by the
   13.1 jitter delay (1-3 s for the first retry) and the Register. This is the largest single contributor
   to kill recovery time in these runs. Its cause was not investigated.
8. **No flap-back was observed** (no agent returned to its first node during any run's window, 45 runs,
   sampled about once a second). The period after a partition heals was not observed for stale sessions,
   because the next settle restarted the fleet.
9. **A DNS-addressed kill of up to 114 agents re-registered within about 13 s, and that is all this shows.**
   With a VIP the same kill took up to about 26 s (about 16 s with redispatch), a full partition about 28-30 s
   and a graceful stop of a DNS-addressed gateway about 16 s (the Failover table; no graceful stop was run behind a VIP).
   No agent log in any of the 45 runs contains the gateway's "the gateway is busy" refusal. But the gateway
   returns that only when its register wait queue is full (10,000 entries by default), which a fleet of 300
   agents cannot fill, so its absence says nothing about capacity. What the data show is the time to recover,
   with registration peaks up to 28 per second at 300 agents.

10. **After the agent-port-only fault, commands to agents that had re-attached elsewhere were sometimes lost
    (observed, unexplained).** Across the agent-port-only runs, 5 probes went to agents that had already
    re-attached to another node (4 with the management plane behind the VIP, 1 with it on a single node). 3 of
    the 5 were accepted by the server and are in no agent, gateway or server log. One candidate explanation,
    not verified: the victim node keeps a local session for the agent while it is partitioned (its
    `yuzu_gw_agents_current` gauge stayed at its pre-fault value until about +160 s of a full partition and
    only then fell) and the gateway looks at its local table before the cluster, so a command routed through
    the victim goes nowhere. If that is right it is a product defect, not a rig artefact. A confirming
    experiment would point the management address at a node other than the victim and expect every probe to be
    delivered; because loss is intermittent it needs several repetitions.

## Hypothesis scorecard

| # | Claim | Outcome |
|---|---|---|
| H1 | Clean kill: agents re-attach to survivors, TLS passes | Observed (about 9-10 s DNS) |
| H2 | Silent partition: detection bounded by keepalive; a VIP with a health check is faster | Observed for a full partition (about 47 s DNS, about 24-27 s VIP); the green-health-check case is a lower bound (over 118 s) |
| H3 | Node up, server path dropped: agents stay; routes expire; routable again after the path returns | Observed (single replica, 6 runs; the return was timed in 2 of them, 300 agents, and seen by hand in a third) |
| H3b | `/readyz` stays 200, a VIP will not eject the node | Observed in this rig for the dropped-upstream fault with a quiet fleet; in the full partitions the breaker did open (+156-162 s); **not established for a production fleet** |
| H4 | Reconnect of a third of the fleet with 13.1 jitter does not overload Register | Recovery times observed up to 114 agents at once; capacity was **not** tested (finding 9) |
| H5 | A restored node stays empty | Seen informally in early runs; no retained artefact; unverified here |
| H6 | DNS: a replaced node on a new IP is found only after the resolver cooldown | **Not run** |
| H7 | Single management address: killing that node breaks dispatch fleet-wide | Observed (2 runs) |
| H8 | Stale session re-announce after a partition heals | No reversion seen during the windows; post-heal period not observed |
| H9 | In-flight command at fault time: lost / duplicated / delivered once | **Not run** (no suitable long-running action was identified) |

## Not measured, voided, or limited

- **Follow-up measurements needed before any figure here is quoted in a #6920 decision:**
  1. the port-only VIP fault (finding 3) with a window long enough that every victim has re-registered;
  2. an F3 run with inventory, DEX and Spark enabled and some registration churn, recording the gateway's
     `yuzu_gw_upstream_circuit_transitions_total` and the victim's `/readyz` once a second, to see whether
     the breaker opens and a VIP ejects the node (finding 4);
  3. a positive control for refusals: lower the gateway's register queue limit (`upstream_register_queue_max`)
     until "the gateway is busy" is produced and appears in an agent log, then repeat a kill (finding 9);
  4. an H7 control that proves the management address was the only difference;
  5. a re-run of the early-harness runs on the corrected clock, to replace the corrections described above;
  6. the finding 10 experiment, with the management address on a node other than the victim, repeated
     several times (a verification, since the loss is intermittent).
- **Not run:** H6, H9, fixed-order DNS, a static endpoint list with no DNS (13.2's case), a real
  resolver with TTLs, a multi-replica server, PROXY-protocol / client-address attribution behind a VIP, and
  TLS session resumption across nodes.
- **Voided or qualified runs** (kept in `ws13-0/results.csv` with a note): two runs (one kill, one
  agent-port partition) taken with the management address on `gateway-1` only; the kill's dispatch probes
  are void (HTTP 401 after a server recreate) and are left out of the Probes table, but its failover timings
  are valid; the partition's probes are valid because the login was restored by hand mid-run. The early VIP
  F2 runs are labelled "agent port only", not a full partition, and as right-censored.
- **Packet capture** was missing for the first 20-agent kill (a container name clash, fixed).
- The HAProxy variant, the management address and the DNS order are operator-supplied for every run (see
  "Run configurations"); the run metadata did not record them.
- Raw logs and secrets are not committed (the two gateway series under `ws13-0/raw/` excepted). The summary
  CSVs are the artefact.

## What this means for the open decisions (inputs, not decisions)

- **13.2 (agent endpoint list):** nothing here shows it is needed for the VIP and multi-A shapes tested.
  Whether a deployment with a static node list and no DNS needs it was not tested.
- **13.6 (gateway closes agent streams after a long upstream outage):** the precondition it addresses
  (a node with live agents and a dead upstream path) is confirmed and was invisible to `/readyz` in this
  single-replica, quiet-fleet rig; the harm it would prevent was not testable here, and the breaker opened,
  after about 160 s, only when the node was fully cut off. How much it matters depends on the multi-replica
  case and on whether production traffic feeds the breaker (follow-up 2).
- **#6920 (what belongs in the gate):** finding 5 (management-plane addressing) is a failover property
  that no agent-side slice covers. It is a candidate gate item in its own right.
- **13.4 (rollout runbook):** the agent-to-gateway edge is one-way TLS (the gateway does not verify
  agent client certificates; mutual TLS applies only between server and gateways). Behind a VIP in
  `mode tcp` every agent's peer address is the proxy.
- **WS-15:** finding 6.
- **Candidate issues (not filed):** finding 7 (agent teardown latency after a clean reset), and finding 10
  (commands lost after the agent-port-only fault: a verification first, then a defect if confirmed).

## Run configurations (operator-supplied)

- **HAProxy `option redispatch` variant:** `run-F1-vip-221906`, `run-F1-vip-222734`, `run-F1-vip-223600`,
  `run-F1-vip-003436`, `run-F2p-vip-224347`, `run-F2p-vip-225245`. Every other VIP run used the default
  configuration.
- **Management address on `gateway-1` only (the H7 runs):** `run-F1-dns-005812`, `run-F1-dns-011727`,
  `run-F1-dns-212006`, `run-F2-dns-212901`. Every other run had the management plane behind the VIP.
- **DNS zone order:** shuffled in every DNS run (the fixed-order zone was built but not used for any run in
  this record).

## Operator documentation this record contradicts or extends

- `docs/user-manual/gateway.md` (the section on a node that is up but has lost its server) says the agent
  "stops being dispatchable" after the route lease expires and that the case "has not been observed end to
  end". In this rig dispatch to such an agent kept working on the single-replica server; the multi-replica
  case, where the route directory is used, was not tested.
- The same page quotes a worst case of about 80 s to detect a lost node (60 s keepalive plus 20 s timeout).
  The DNS measurements sit inside that; the VIP "health check stays green" case did not (finding 3).
- `docs/user-manual/server-admin.md` documents `--gateway-command-addr` as one address without warning that
  killing that node loses command dispatch to the whole fleet (finding 5).
- **Alerting:** during a full partition the victim gateway's `yuzu_gw_agents_current` held its pre-fault
  value until about +160 s and then fell (in the 300-agent, 200 s run: 100 until +159.8 s, 96 at +160 s,
  71 at +171 s, 41 at +182 s, 13 at +190 s; the series is `ws13-0/raw/run-F2p-vip-001328-gw.csv`; this is
  one run, and the 100-agent runs' 150 s windows ended before the fall). The `/readyz` flip in the same run
  was at +157 s, which is a different quantity. The shipped `YuzuGatewayConnectionDrops` alert needs that
  gauge to fall below 70 % of its value five minutes earlier for two minutes, and needs a positive connection
  rate in the last five minutes. By derivation, not measurement, the rate term is necessary but not
  sufficient: by +300 s the five-minute window holds no pre-fault connection, and the victim takes none after
  the fault, so the alert needs an agent to have connected to the victim after the fault, and cannot
  otherwise fire; if it can, the earliest is about +300 s. `YuzuGatewayUpstreamCircuitOpened` (a breaker that
  opened and has not closed, held three minutes) would fire at about +340 s, since the breaker opened at
  +157 s. Qualifiers: this harness read the gauge over the node's loopback, whereas a networked Prometheus
  would see the node unreachable in a full partition, which `YuzuGatewayDown` covers; in the agent-port-only
  shape (the one with the lost commands, finding 10) only the drop alert could act; and the server-side fleet
  alerts (`YuzuAgentFleetDrop`, `YuzuAgentDisconnected`) exist and were not evaluated. None of the alert
  rules was exercised.

None of these pages was edited by this slice.

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

The rig is Linux and Docker only (it uses bash's `EPOCHREALTIME`, `/proc/loadavg`, `flock`,
network namespaces and cgroup cpusets); it was not run on macOS or Windows. State and raw logs go under
`~/.local/share/yuzu/ws13-spike/` (never the repository). The rig binds no fixed host port except one
random loopback port for the REST login, so it can run beside the UAT and demo stacks.
