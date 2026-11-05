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
  egress drop sits before the capture point), 13, 13 and 11 inbound packets in total across the 7 to 8 ten-second buckets that fall wholly between the fault
  and the undo (at most 6, 6 and 4 in any one bucket, all in the first; the bucket that contains the undo also
  holds the recovery burst and is excluded), and the first FIN/RST 7-117 s after the fault was undone. It was a silent
  partition, not a reset. The victim gateway's own log [measured] shows its upstream channel going down
  (`connection 1 down (timeout); reconnecting`, `connection_error` in the gateway-2 and gateway-3 runs) from +64 s, +71 s and +89 s in the three runs and retrying until
  the undo; the agents stayed attached to it throughout (none of the 30 clean sampled agents changed gateway
  node in the route samples), and the victim's `/readyz` answered 200 in every sample between the fault and the
  undo (339 of 339 in each run), so a load balancer that health-checks `/readyz` would not have ejected the
  node; the gateways' `yuzu_gw_upstream_circuit_transitions_total` (open and half_open) read 0 on all three
  after the runs, so the circuit breaker did not open either on this quiet fleet [measured: open and half_open
  read 0 on all three gateways, read live after all runs; the counters die with `down`]. The victim's heartbeat
  lane failed throughout (213-224 `BatchHeartbeat failed ... timeout` lines in its log per fault run, about 0.45
  per second [measured]) and does not feed the breaker (`yuzu_gw_heartbeat_buffer.erl` [code]). The one shipped
  rule that would see it is `YuzuGatewayUpstreamErrors` (`deploy/grafana/yuzu-alerts.yml:87-88`,
  `rate(yuzu_gw_upstream_rpc_errors_total[5m]) > 0.1` for 5 m) [code, not run against these runs].
- **Probe.** `os_info.os_name` (read-only) to each sampled agent, through BOTH replicas, on both REST surfaces
  (`POST /api/v1/commands` and the legacy `POST /api/command`), plus one scope-arm probe per replica
  (`hostname == '<name>'`, v1 only). Rounds: a control that immediately precedes the fault (its sends are 0.14-0.19 s
  before the fault is injected; the last one 0.14-0.15 s), then +60, +120, +300 and +420 s, then recovery rounds from the undo
  (+0.4 s and +5.6-5.7 s in all three runs; the loop stops once every clean agent was delivered through both
  replicas, so two rounds were needed). "Delivered" = a terminal response produced by the agent (SUCCESS with
  output, or an agent-reported failure) inside a polled deadline (30 s; 10 s in the recovery rounds); a send that was still "accepted, no
  result" at its deadline was re-read at the end of the run for late terminals. A dispatch refusal (HTTP 503 or
  zero agents reached), a server-synthesised `[gateway_*]` failure and "accepted, no result" are each recorded
  as such; anything else that is not a 2xx is a rig error and is never counted as a refusal (none occurred). A
  503 is scored as a refusal whatever produced it, so a 503 from a replica that was not serving would read as one;
  the first 400 characters of the body are kept, and every replica was serving throughout.
  Every "delivered" row's command id was also found in an agent container log (0 rows without one).
- **Holder and cohort.** The holder of an agent = the replica whose own log holds the agent's CURRENT session id
  in a `ProxyRegister succeeded` line (the agent id alone is not enough, see finding 2). The sample is the
  agents attached to the victim gateway, in two cohorts: **clean** (the other replica does not list the agent,
  so a dispatch through it goes through the route directory) and **`stale_other`** (the other replica also lists
  it; finding 2). Only the clean cohort enters the trigger tally. The 10 clean agents behind one gateway share
  one holder, one upstream connection and one lease timeline, so each fault run is ONE observation of the
  fault, not ten.
- **Controls.** The control round goes through both replicas before the fault. An agent whose control did not
  deliver through both replicas on both surfaces is reported in its own `inconclusive` cohort for the whole
  run, never as a pass and never as a refusal (none were: every clean agent's control delivered). A
  full-length no-fault run with the same schedule validates the rig.
- **Setting.** Image commit `7cc3dd2ff` (server `52104c72bd82`, gateway `432fcabd6cc9`, agent `9fb9dbf8b8c8`),
  one 32-core host with 122 GiB RAM (Docker 29.1.3), cpuset-pinned (containers other than CoreDNS on cores 0-15, agents on
  cores 16-31). **Every number is single host. The fleet was 60 agents (20 per gateway); two earlier provisional
  runs (a 20-agent fault run and a 100 s no-fault run) are kept as raw data and not summarised** (they predate
  the cohort tag). Route samples were taken about
  every 1.4 s (median gap 1.42 s, not 1 Hz).

## Evidence and its provenance

The raw data (route samples, per-run `probes.jsonl`, `holders.csv`, `sample.txt`, agent, gateway and server logs,
captures, `meta.txt`) is **a single copy on the host that ran it**, under `~/.local/share/yuzu/ws13-7082/`. It
is not committed and has no off-host copy. The committed summaries (`docs/ha-spikes/ws13-6/probe-summary.csv`,
`run-timeline.csv`) are regenerated from it by `ha-two-replica-probe-client.py export` and carry the SHA-256 of
each run's `probes.jsonl`, so a re-analysis can be checked against them.

**Which code took the data.** The four data runs were taken with the runner as committed at `4bfa0565a`
(`script_sha` 9b0c86c8099b in each run's `meta.txt`), before any governance fix to the runner or client; their
`meta.txt` records no client or overlay sha. The runner, client and overlay were then changed in three rounds of
review fixes. After the last of them one 100 s, 6-agent no-fault smoke run (`run-NOFAULT-211915`) was taken with
the files exactly as committed (`script_sha` ca221d6e97af, `client_sha` bca5fa548225, `overlay_sha`
412931b7c0da, equal to the blobs at that commit); it has a `COMPLETE` marker and a 54-line `registrations.txt`
and is valid by the rule below. **No full fault run was taken on the hardened rig.** The hardening was checked by
that smoke run, by refusals of bad arguments and of a concurrent command (including one with another state
directory), by an offline contract test of the client (`tests/test_ha_two_replica_probe_contract.py`: synthetic
runs with no rows, no control rows, a missing round, all HTTP 500, no window, duplicate rows, a missing capture
or an outbound packet in a fault window are each not valid), and by an export that refuses to replace the
committed CSVs when nothing matches.

**What the committed tables are.** The current client re-derives them from the raw `probes.jsonl`: `export --runs`
of the four runs with `--legacy-unmarked` reproduces both committed CSVs byte for byte. Against the first CSVs
committed in `4bfa0565a` the probe-summary cells are unchanged; 8 `run-timeline.csv` median cells differ (upper
median became true median, rounding); `probe-summary.csv` gained `rig_error`, and `run-timeline.csv` replaced
`invalid` with `inconclusive_agents`, `complete_marker`, `valid`, `invalid_reason` and `probes_sha256`. The four
runs predate the `COMPLETE` marker; their completeness is attested by the author, resting on their summary
existing and no failure line in the run logs. The first-registration lines behind finding 2 are in
`docs/ha-spikes/ws13-6/stale-cohort-registrations.txt`, a hand-selected subset of container logs that the rig's
`down` removes (its header says what is missing).

## Predictions, written before any run, against what was measured

The predictions came from reading `origin/dev` and were not run before the rig existed.

| Prediction | Measured |
|---|---|
| The replica that holds the session delivers at every lease state (`send_to` queues to the gateway and ignores the lease, #5960) | **Held**: 20 of 20 delivered at every round in all three fault runs, including +420 s, and after the route row was tombstoned (gateway-2 run, tombstoned at +331 s) |
| The non-holder delivers while the route lease is valid | **Held**: 20 of 20 at the control and at +60 s |
| The non-holder refuses once the lease has expired (+120, +300, +420 s), as `no_agents_reached` | **Held**: 0 of 20 at +120, +300 and +420 s in all three runs; the v1 route answers HTTP 503 `no_agents_reached`, the legacy route a bare 503 |
| A second refusal class, "no agent connected" before the arm walk (a legacy-route check [code]), on a replica with no local sessions | **Not observed**: every refusal was `no_agents_reached` or the legacy bare 503, because each replica held other agents' sessions |
| Scope/group arms may drop the agent from the candidate set once presence lapses | **Consistent, not separated from the id arm**: the scope-arm probe (one agent per replica per round) delivered through both replicas up to +60 s and was refused with `no_agents_reached` on the non-holder from +120 s; whether the agent was dropped before or after the route lookup was not distinguished; after the undo the scope-arm probe through the non-holder was refused at +0.4 s in all three runs, delivered at +5.7 s in the gateway-1 and gateway-2 runs and still refused at +5.6 s in the gateway-3 run |
| After the path returns: the one-replica spike's 2-6 s re-arm, or on two replicas #5380's never-re-armed case | **Re-armed, see finding 4**: the route row was routable again 1-4 s after the undo in all three runs, including the two where it had been tombstoned |

## Results

Clean cohort, 10 agents per run, both surfaces (20 probes per cell). Delivered / probes.

| Run (victim gateway, holder) | Probed replica | control | +60 s | +120 s | +300 s | +420 s | After the undo (id arm) |
|---|---|---|---|---|---|---|---|
| gateway-1, holder 1 | 1 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | delivered |
| gateway-1, holder 1 | 2 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | refused at +0.4 s, delivered at +5.7 s |
| gateway-2, holder 2 | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | delivered |
| gateway-2, holder 2 | 1 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | refused at +0.4 s, delivered at +5.7 s (a replay at +2.5 s made replica 1 the holder) |
| gateway-3, holder 2 | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | delivered |
| gateway-3, holder 2 | 1 (non-holder) | 20/20 | 20/20 | **0/20** | **0/20** | **0/20** | refused at +0.4 s, delivered at +5.6 s |
| no fault (gateway-3) | 2 (holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |
| no fault (gateway-3) | 1 (non-holder) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | n/a |

Route directory, same clean-cohort agents, seconds after the fault (first non-routable: median 81.1, 75.3 and
79.0 s, range 63-87 s; route row tombstoned, meaning its session cleared: +331 s in the gateway-2 run, +471 s in
the gateway-3 run and not within the window in the gateway-1 run, the sweep being phase dependent; the fault
was undone at +481 s in each run; route row routable again after the undo: 2.9, 3.6 and 1.3 s median).

### Findings

1. **The condition of #6920 item (a) (item (1) of the delivery matrix's decision note) is met on this rig [measured].** An agent attached to a gateway node that
   is up but cut off from its servers is undispatchable through the replica that does not hold its session, from
   the first probe round after its route lease expired (the lease was non-routable 63-87 s after the fault, and
   the first refusal was at the +120 s round; +60 s delivered, so the moment between is not resolved) until the
   path returns, in 3 of 3 fault runs
   and for both holder directions; it stays dispatchable through the replica that holds the session. A load
   balancer in front of two replicas would send some requests to each, so the same agent is reachable or not by
   chance [inferred]. The refusal does not say why: a v1 caller gets HTTP 503 `no_agents_reached` and a legacy caller a bare 503
   [measured]; that the v1 body carries `retry_after_ms` and is the same answer as for an offline device is
   [code]; the MCP
   twin shares the dispatch path [code] but was not probed. So `no_agents_reached` is not proof that a device is
   offline: check the other replica and the agent's gateway before concluding that. Qualifiers: REST only; a quiet fleet: the agents ran with `--dex-disable --inventory-disable --spark-disable`
   (`docker-compose.ha-gateway-failover.yml:203-205`), so almost only heartbeats crossed the gateway-server link
   and the registration and sync traffic that does feed the breaker [code] was absent; the holder replica
   stays dispatchable; one gateway per run (the 10 agents are one observation of the fault); an `os_info` read;
   the recovery figures are at 20 agents per gateway.
   The decision (#6920 item (a)) makes the move inside the gate follow from this; that edit is not made here
   (see below).
2. **Some agents hold a registration on both replicas, and the replica without the stream refuses them
   before any fault.** [measured] In each run 2 agents were sampled into the `stale_other` cohort (the sampler caps it at 2; the other replica
   also lists them). On the victim gateway 10, 6, 7 and 3 of its 20 agents were in that state in the four runs
   (26 of 80), so the cap understates how common it is on this rig. Through the replica that does not hold their stream, 4 of 4 probes were
   refused at the control and at +60 s in every run, and at every round of the no-fault run, while the route
   directory held a live route and the holder delivered. (During a fault run the refusal after the lease expired
   cannot be told from finding 1, and in the gateway-2 run the same 4 were refused at the first post-undo round (+0.4 s) and delivered at the
   second (+5.7 s), after the replay at +2.45 s moved the holder to replica 1; in the other two runs they were
   refused at both post-undo rounds. So "refused at every round" does not hold there.) In the server
   logs all 8 such agents show, 9-11 ms apart (first `ProxyRegister` on each replica) at their enrolment, one replica logging `auto-enrolled via
   enrollment token`, `Issued per-agent client cert` and `ProxyRegister succeeded` with no `CONNECTED`, and the
   other logging `re-registering (already enrolled)`, `ProxyRegister succeeded` and `CONNECTED` (`stale-cohort-registrations.txt`)
   [measured; the gateway logs, not committed, show all 8 pairs arriving 10 ms apart through two different
   gateways]. In this rig every agent re-enrols whenever its container
   restarts (its data dir is a tmpfs), so the enrolment path ran again at each settle, and the cohort is
   different agents in each run (8 distinct agents over 4 runs). [code] The agent registers a second time over mutual TLS on a rebuilt channel right after its certificate is
   issued (`agents/core/src/agent.cpp:2063-2093`), so the two registrations can reach two replicas through two
   gateways [measured above]; that this leaves a session on the replica that never sees the stream is [inferred,
   not isolated]. Not established: how often it happens outside this rig, or that the refused replica's local
   session carries no `gateway_node`. [code] The dispatch wiring consults the route directory only for ids the
   replica holds no local session for (`dispatch_route_fallback.hpp` header), which would produce this refusal;
   that is a hypothesis, not a result. It needs two replicas (on one, a second registration overwrites the
   first). Its relation to #5380 and #5960 is not established. An agent registered through two gateways whose upstream holders differ bears on ADR-2002 §7g item 3 (#5649);
   this is evidence for that clause's premise on this rig, not a result for it. It is reported as a separate
   cohort and never counted in finding 1.
3. **Two upstream endpoints on a gateway cannot be measured on this rig, and the shipped guidance still warns
   against them** [code] (`gateway.md`, `yuzu_grpc_client_channel.erl`). ADR-2002 §7g records several upstream
   servers as the stated production topology and says the one-connection premise 'no longer holds as a default'
   (#5648, #5649), but the shipped default and guidance are unchanged, so this rig measures the shipped
   one-endpoint shape. Holders mix per gateway, not per agent, which is not the §7g topology.
4. **The route row re-armed after the undo in all three runs, and the holder can change.** [measured] The route row was routable again 1-4 s after the undo (rows sampled every 1.4 s). The
   first id-arm dispatch probe after the undo (+0.4 s) was refused through the non-holder in all three runs and
   the next (+5.6-5.7 s) delivered, so id-arm dispatch through the non-holder was back within about 5.6 s at 20
   agents per gateway. The scope-arm probe through the non-holder was refused at both rounds in the gateway-3 run.
   Only the gateway-1 run healed without a replay; in the other two a replay landed first (+0.7 s, +2.5 s), so
   they are not a lease heal alone. Recovery at hundreds of gateways is unmeasured. In the gateway-1
   run no `ProxyRegister` reached either replica after the undo for the sampled agents; in the other two the 10
   sampled agents re-registered 0.7-2.5 s after the undo: on the same replica in the gateway-3 run, and on the
   OTHER replica in the gateway-2 run (the holder flipped from 2 to 1). The gateway-1 run was never tombstoned and
   healed without a replay; the other two saw a tombstoned row (at +331 s and +471 s; the second only 10 s
   before the undo, the closest case to #5380's state) and both re-armed after a replay. Two observations are not
   a characterisation of #5380, which concerns a row that is tombstoned and never re-armed under multi-replica
   routing; this does not close or narrow it.

### Limits

Single host, one hardware shape, 60 agents (20 per gateway), 10 clean agents sampled per run behind one
gateway (so the effective sample is three fault events and one no-fault run, not 60 agents), one probe per agent
per surface per round. Three fault runs (one with holder 1, two with holder 2) and one full-length no-fault run;
two provisional runs (`run-F3-2r-153150`, 20 agents, and a 100 s `run-NOFAULT-152124`), taken before probes carried a cohort tag, are kept as raw data and not summarised.
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
moving it inside as met, and #7082 stays open for that edit.** This record is the first recorded outcome of
the #7082 probe. The project lead's risk acceptance (`docs/ha-delivery-matrix.md:76`, ADR-2002 line 503) names
that outcome as its review trigger and is due its review now. Its premise for slice 13.6, 'unmeasured', no
longer holds on this rig; its quarantine clause is still unmeasured (Limits). The review is not made here.
Roadmap 14.2 says nothing of 13.6 yet. The gateway-side fix (end agent streams after an outage longer than the lease) is not
designed here.

## Reproducing

`scripts/ha/ha-gateway-two-replica-probe.sh up --tag <image-tag> --agents N`, then `scenario NOFAULT` or
`scenario F3-2r --victim gateway-N`, then `down`. Build the three `yuzu-spike-{server,gateway,agent}` images
from the commit under test with `Dockerfile.server`, `Dockerfile.gateway` and `Dockerfile.agent`. Also needed:
the `yuzu-postgres:local` image (`Dockerfile.postgres`), Docker Compose new enough for `!override` (the runs used
5.1.4), `flock`, bash 5, and a host with nothing else on 10.77.12.0/22 (the runner refuses otherwise). The runner
takes a lock at `/tmp/yuzu-ws13-7082-yuzu-ha-gw-2r.lock` (a fixed path, refused if it is a symlink), so two
commands cannot run against one rig whatever their `TMPDIR` or state directory. The runs used `up --agents 20` and
then `scale 60`, `scenario NOFAULT --window 480 --sample 10` and `scenario F3-2r --victim gateway-N --sample 10
--window 480 --recovery 300`; the `scenario` defaults are `--window 480 --sample 10 --recovery 600`. The
summaries are produced by `python3 -I scripts/ha/ha-two-replica-probe-client.py export --state
~/.local/share/yuzu/ws13-7082/<salt> --out <dir> --runs <run,run> [--legacy-unmarked <run,run>]`, which refuses
(and replaces nothing) when no run matches. An offline test of the client's rules is
`python3 -I tests/test_ha_two_replica_probe_contract.py` (not wired into CI).

`probe-summary.csv` has one row per run, round, cohort (`clean`, `stale_other`, or `inconclusive` for an agent
whose control failed), probed replica and arm, with the outcome counts (`rig_error` = a non-2xx that is not a
503 or a malformed probe). `role` is the holder or non-holder at sample time and is not updated when the holder
flips (the gateway-2 recovery rounds). `run-timeline.csv` has one row per run: `holder_replica`,
`agents_total`, `clean_sampled` and `stale_sampled` are as sampled; `nonroutable_*` = seconds after the fault until
a route sample first showed the lease expired or the session cleared, over the clean cohort; `unarmed_*` = until
the route row's session was cleared (tombstoned); `routable_after_undo_*` = seconds after the undo until the route
row was routable again; `inconclusive_agents` = clean agents whose control failed; `complete_marker` = the
runner's end-of-run marker (`attested by the author` for the four runs, which predate it); `valid` = every
expected control and fault round (control, then +60/+120/+300/+420 s inside the window stated in `meta.txt`, which
must exceed 60 s) has an id-arm row through both replicas on both surfaces for every clean agent, no duplicate
row, no rig-error row, no `INVALID` marker, not every control failed, the `COMPLETE` marker (or the attestation),
and for an F3-2r run a capture showing no outbound packet on :50055 in the fault window. It means usable for the
finding-1 tally; it does not require the recovery rounds. `invalid_reason` says why not.

A run killed with SIGKILL leaves its sampler, its fault rule and its capture container `spike-2r-cap-<pid>`
behind, and the rig lock is held until every foreground child the runner had started exits (a schedule `sleep`, a
probe, or the `docker wait` on the capture), so `restore`, `down` and `scale` are refused meanwhile. Recover in
this order: `docker rm -f spike-2r-cap-*` (ends the `docker wait`), kill the sampler (`kill $(cat <run
dir>/sampler.pid)`) and any surviving child, then `restore`. Such a run has no `COMPLETE` marker: do not export
it. The overlay is a lab measurement rig and not a deployment pattern.
