# Gateway scale tests

`yuzu_gw_scale_SUITE` measures the Erlang gateway with many agents at once. It
drives the real gateway listeners over real HTTP/2, and replaces the C++ server
with a fake that speaks the `GatewayUpstream` service on a real listener, so the
gateway's own upstream client, circuit breaker and registration replay are
exercised rather than mocked. It is the before-and-after measurement for the
5,000-agent work on PR #5695.

Files:

| File | What it is |
|---|---|
| `gateway/apps/yuzu_gw/test/ct/yuzu_gw_scale_SUITE.erl` | The scenarios, the invariants and the reports |
| `gateway/apps/yuzu_gw/test/yuzu_gw_scale_fleet.erl` | The load generator: simulated agents and the management client |
| `gateway/apps/yuzu_gw/test/yuzu_gw_scale_upstream.erl` | The fake server |
| `gateway/apps/yuzu_gw/test/yuzu_gw_scale_probe.erl` | The sampler that runs inside the gateway node |
| `gateway/apps/yuzu_gw/test/yuzu_gw_scale_peer.erl` | Starts, kills and stops the nodes |
| `gateway/apps/yuzu_gw/test/ct/yuzu_gw_scale_SUITE_data/register_plugins.eterm` | The 69 plugins each agent registers with |
| `scripts/test/gen-gateway-scale-register-fixture.py` | Regenerates that file from `agents/plugins/*/src` |
| `scripts/test/gateway-scale-report.py` | Prints a summary of a run's JSON file |

## How it is built

Each scenario starts three operating-system processes besides the Common Test
node, so the load generator does not share schedulers with the gateway it
measures:

- **gateway**: the `yuzu_gw` application with the listener settings of
  `config/sys.config.prod` (acceptors, HTTP/2 limits, connection limits), the
  production VM flags of `config/vm.args.src`, and the production circuit
  breaker settings. Two things differ from production: the listeners and the
  upstream hop are plaintext (TLS cost is not measured), and every port is
  chosen by the operating system.
- **upstream**: the fake server. It answers `ProxyRegister` after a configurable
  delay (20 to 50 ms by default in the measured phases), records every call, and
  answers `BatchHeartbeat` with the sessions it does not know, as the real server
  does. Its listener allows 128 concurrent streams per connection, the C++
  server's `--grpc-max-concurrent-streams` default, and has no received-frame
  budget (Cowboy's default of 10,000 frames per 10 s closed the gateway's
  connection with `ENHANCE_YOUR_CALM` during a 5,000-agent storm; gRPC C++ has
  no such limit). A "server crash" is a `kill -9` of this node; the restart is a
  fresh node with an empty state, on the same port.
- **loadgen**: the simulated agents and the management client.

The nodes are started with the `peer` module's `standard_io` connection and no
node name. They are not distributed, use no epmd and no cookie file, and talk to
each other only over TCP, as the real components do. Every port and name is
picked per run, so two runs on one host do not collide (#1871).

A simulated agent is one process and one HTTP/2 connection. It speaks the real
`AgentService` protocol: `Register` with a 30 s deadline and a request shaped
like a real agent's (hostname, platform, version, three scopable tags and one
`PluginInfo` per plugin under `agents/plugins`, with each plugin's name,
version, description and actions, about 9 KB encoded), then a `Subscribe`
stream held open, and a `Heartbeat` every 30 s. It answers every command with
`SUCCESS`. After a failed `Register`, a lost connection or an ended stream it
waits 2, 4, 8 ... seconds (capped at 300 s, no jitter) before trying again, as
`agents/core/src/agent.cpp` does.

The management client is shaped like the server's: one connection, one
`SendCommand` call per target agent, at most 4096 calls open at once (the
management listener's `max_concurrent_streams` in `sys.config.prod`; gun refuses
a stream over the limit where gRPC C++ queues it, so the client queues).

## Scenarios

| Case | What happens |
|---|---|
| `ramp` | N agents connect and register at a fixed rate (100 per second) |
| `storm` | N agents connect and register at once |
| `server_crash` | N agents registered; the server is killed and restarted after 5 s. 10% of the agents drop their connection 0.5 s into the outage. Measures the time to replay every session to the new server, and the notices lost |
| `gateway_crash` | N agents registered; the gateway node is killed and a new one started on the same ports. Every agent comes back by its own retry rule |
| `planned_stop` | N agents registered; `application:stop(yuzu_gw)`. Counts the `DISCONNECTED` notices the server received |
| `fanout` | N agents registered; one command to each agent over one management connection; agents answer after a random 0 to 10 s |
| `upstream_conn_loss` | N agents registered; a wave of N/10 more (at least 100) registers at once, and once at least 8 `ProxyRegister` calls are open at the server it closes the gateway's upstream connection (kills its connection process) and keeps running with everything it knows. Counts breaker openings, replayed registrations and repeated `CONNECTED` notices |

The crash, stop and fan-out cases first register the N agents with the server
answering at once, then switch to the measured behaviour.

## What it reports

Every case writes a JSON file to the Common Test log directory (the case's
`log_private` folder) or to `YUZU_GW_SCALE_RESULTS_DIR`, and the run writes one
more file holding every case: `yuzu_gw_scale-<run>.json`. Each number is also
written as a `SCALE_METRIC <name>=<value>` line: the headline ones on the
console, every one in the case's HTML log. The main numbers:

- `Register` attempts: first-attempt successes and failures (with the reasons),
  agents not registered within the budget, latency percentiles;
- the server's view: the peak number of `ProxyRegister` calls in flight at once;
  the calls that created a session the agent never got because its attempt
  failed ("wasted"), and of those the ones that arrived after the agent had
  already given up ("stale") (each agent puts its attempt number in one extra
  scopable tag, which the gateway forwards unchanged, so each call is matched to
  its attempt); `CONNECTED` and `DISCONNECTED` counts; live sessions the server
  has no `CONNECTED` for; and sessions it still thinks are connected that no
  agent holds; and the `ProxyRegister` handlers that were stopped before they
  answered (`register_rpcs_cut`, with the exit reasons: the listener stops a
  handler whose stream was reset, whose deadline passed or whose connection
  closed);
- replay: sessions replayed, time to full replay, peak replays in flight;
- notices lost on an outage and on a planned stop;
- fan-out: answers, failures, completion time, per-command latency, management
  connection drops;
- the gateway: memory per connection (memory now less memory at boot, divided by
  the registered agents, in total and per type), the memory of the three
  processes one agent costs (its `yuzu_gw_agent` process, its `Subscribe`
  handler and its Cowboy connection process, averaged over 20 agents, before and
  after a garbage collection of each), the mailbox high-water mark of
  each named singleton (`yuzu_gw_upstream`, `yuzu_gw_registry`, `yuzu_gw_router`,
  the agent supervisor, the top supervisor, the heartbeat buffer, the `pg` scope,
  the upstream channel and a few more), sampled every 50 ms inside the gateway
  node, and scheduler utilisation (`scheduler:utilization/2`) over the measured
  phase.

`python3 scripts/test/gateway-scale-report.py <file.json>` prints a summary.
`scripts/test/perf-gate.sh --run-id ID --scale-agents N` runs the suite after the
perf suite and records the headline numbers as `perf_scale_*` metrics.

The numbers come from four nodes on one host, so they are noisy; they are
reported, never compared with a fixed limit.

## Invariants and the gate

Each case also checks invariants that involve no timing:

| Case | Invariant |
|---|---|
| `ramp`, `storm` | every first `Register` succeeds; every agent registers within the budget; more than one `ProxyRegister` is in flight at the server at some point; no `ProxyRegister` creates a session at the server for an attempt that failed ("wasted" above); the server holds a `CONNECTED` for every live session; every singleton mailbox is back to 0 |
| `server_crash` | every held session is replayed; more than one replay is in flight at some point; every `DISCONNECTED` raised during the outage reaches the server; the new server holds a `CONNECTED` for every live session |
| `gateway_crash` | every agent registers again; no `Register` to the new gateway fails; the server holds a `CONNECTED` for every live session |
| `planned_stop` | the server receives a `DISCONNECTED` for every session |
| `fanout` | every command is answered; the management connection is never closed; no agent loses its session |
| `upstream_conn_loss` | the server closed at least one connection; the circuit breaker never opened; no registration was replayed; at most 10 sessions got a second `CONNECTED` (the notifications in flight when the connection went are sent again, their answers were lost with it); every agent registers within the budget; the server holds a `CONNECTED` for every live session |

Several of these fail on the gateway as of commit 29a8e655b (see the numbers
below). The suite therefore has two groups with the same cases:

- `report` (the default): a failed invariant is recorded in the JSON, printed as
  a `SCALE_INVARIANT_VIOLATED` line and set as the case comment, and the case
  passes;
- `gate`: a failed invariant fails the case. `YUZU_GW_SCALE_GATE=1` selects it.
  The Meson `gateway ct` test (`scripts/test_gateway.py`, which CI's `--suite
  gateway` runs) sets it, so CI fails on a broken invariant at 500 agents. It
  was switched on after every case passed in `gate` on six consecutive runs
  with the PR #5695 fixes.

The cases are independent (each starts its own nodes), so a failed case in
`gate` does not skip the others.

The suite is in `apps/yuzu_gw/test/ct`, so the Meson `gateway ct` test (in the
`gate` group) and every `rebar3 ct --dir apps/yuzu_gw/test/ct` run (in the
`report` group unless `YUZU_GW_SCALE_GATE=1`) include it, at the CI size. A case still fails if the harness itself breaks (a node that
does not start, a call that times out). It has not been run on Windows yet (the
peer nodes, the kill path and the port ranges are unverified there), so on
Windows it skips itself unless `YUZU_GW_SCALE_WINDOWS=1` is set.

## Running it

From `gateway/`, with the pinned Erlang/OTP active (see
`docs/erlang-gateway-build.md`):

```bash
# CI size: 500 agents (about 55 s with the fixes, 2 min 40 s before them)
rebar3 ct --dir apps/yuzu_gw/test/ct --suite yuzu_gw_scale_SUITE

# 5,000 agents, one case
YUZU_GW_SCALE_AGENTS=5000 rebar3 ct --dir apps/yuzu_gw/test/ct --suite yuzu_gw_scale_SUITE --case storm

# 5,000 agents, every case, results kept outside _build
YUZU_GW_SCALE_AGENTS=5000 YUZU_GW_SCALE_RESULTS_DIR=$HOME/scale-runs \
  rebar3 ct --dir apps/yuzu_gw/test/ct --suite yuzu_gw_scale_SUITE

# fail on a broken invariant
YUZU_GW_SCALE_GATE=1 rebar3 ct --dir apps/yuzu_gw/test/ct --suite yuzu_gw_scale_SUITE
```

Other settings, all optional:

| Variable | Default | Meaning |
|---|---|---|
| `YUZU_GW_SCALE_AGENTS` | 500 | agents per case |
| `YUZU_GW_SCALE_RAMP_RATE` | 100 | agents per second in `ramp` |
| `YUZU_GW_SCALE_LATENCY_MS` | `20-50` | the server's `Register` latency in the measured phases |
| `YUZU_GW_SCALE_OUTAGE_MS` | 5000 | how long the server is down in `server_crash` |
| `YUZU_GW_SCALE_FLAP_PCT` | 10 | percent of agents that drop their connection during that outage |
| `YUZU_GW_SCALE_FANOUT_DELAY_MS` | `0-10000` | agents' answer delay in `fanout` |
| `YUZU_GW_SCALE_FANOUT_WINDOW` | 4096 | management calls open at once |
| `YUZU_GW_SCALE_OUTPUT_BYTES` | 2048 | size of each command answer |
| `YUZU_GW_SCALE_HB_MS` | 30000 | agent heartbeat interval (0 = none) |
| `YUZU_GW_SCALE_BUDGET_MS` | 60000 + 10 per agent | the registration budget the invariants use; the suite waits up to three times this before it gives up |
| `YUZU_GW_SCALE_RESULTS_DIR` | the CT log dir | where the JSON files go |
| `YUZU_GW_SCALE_GATE` | unset | `1` selects the `gate` group |
| `YUZU_GW_SCALE_WINDOWS` | unset | `1` runs the suite on Windows |
| `YUZU_GW_SCALE_DUAL_STACK_ABOVE` | 14000 | above this many agents half of them use a second agent listener on `::1` |
| `YUZU_GW_SCALE_UPSTREAM_STREAMS` | 128 | the fake server's concurrent streams per connection |
| `YUZU_GW_SCALE_TRACE_UPSTREAM` | unset | `1` counts why the fake server's streams end abnormally (`upstream.stream_ends` in the JSON); a diagnostic, it traces every stream end |

### Large sizes: file descriptors, ports and time

- **File descriptors.** An agent costs one socket in the load generator and one
  in the gateway. On Unix each node starts through `ulimit -n <2N + 4096>`,
  which raises its soft limit up to the hard limit of the shell that runs the
  suite; it cannot raise the hard limit and changes nothing outside the node.
  The case's first log line prints the limit each node got. If it is below
  `2N + 4096`, raise the hard limit first (`ulimit -Hn`; on macOS the ceiling is
  `kern.maxfilesperproc`).
- **Ephemeral ports (macOS).** macOS gives about 16,000 ephemeral ports per
  local address (`net.inet.ip.portrange.first`/`last`, 49152 to 65535) and has a
  single IPv4 loopback address. Above 14,000 agents the gateway gets a second
  agent listener on `::1` and half the agents use it, which allows about 32,000.
  The agents close with a reset (linger 0), and the gateway node is stopped
  before the load generator, so no `TIME_WAIT` is left on the load generator's
  ports between cases. Linux has a larger range by default.
- **Time.** With the fixes a full run at 5,000 agents took 2 minutes on the
  host in the results below (27 minutes before them, when the cases waited on
  the serial upstream lane). At 25,000 run the cases one or a few at a time
  with `--case`.
- **One host.** All four nodes share the machine, so the load generator's own
  work can show in the gateway's numbers at large sizes; the published practice
  (Tsung, amoc) is to run the generators on separate hosts. Treat the 25,000
  size as a check that the gateway survives, not as a performance figure.

## Results on 29a8e655b (before the fixes)

Measured on an Apple M5 Max Mac (18 cores, 128 GB), Erlang/OTP 28.4, with the
defaults above.

A full run took 2 min 40 s at 500 agents and 27 min at 5,000. "Peak in
flight" is the most `ProxyRegister` calls the server had open at once; the
mailbox figures are the peak queue length of `yuzu_gw_upstream`. Times are
milliseconds unless marked.

| Case | 500 agents | 5,000 agents |
|---|---|---|
| `ramp` (100/s) | all 500 first attempts succeed; all registered 18.6 s after the start; first-attempt latency p50 6.7 s, p99 13.2 s; peak in flight 1; mailbox 484 | 1,087 first attempts succeed, 3,911 end `DEADLINE_EXCEEDED`; 3,369 registered when the wait ended at 330 s; the server got 9,252 `ProxyRegister` calls, 5,883 of them for attempts that failed; 1,055 live sessions have no `CONNECTED` at the server and the upstream mailbox still held 1,120 messages 50 s later; mailbox 4,285 |
| `storm` | all 500 first attempts succeed; all registered in 18.6 s; p50 9.3 s, p99 18.3 s; peak in flight 1; mailbox 499 | 803 first attempts succeed (3,905 `DEADLINE_EXCEEDED`, 292 `INTERNAL`); 2,421 not registered within the 110 s budget; all registered after 312 s; 5,028 calls, 28 wasted; mailbox 5,001 |
| `server_crash` | 450 sessions replayed one at a time, the last 33.6 s after the restart; of the 50 `DISCONNECTED` raised during the outage, 6 to 14 were lost (three runs) | 4,500 replayed one at a time in 286 s; 13 of 500 `DISCONNECTED` lost; registry mailbox peak 1,997, `pg` scope 496 |
| `gateway_crash` | the new gateway is up 0.6 s after the kill; all 500 back after 20.7 s; no failed attempt; the server still holds 500 old sessions (no last gasp on a kill) | 4,892 of 5,000 back when the wait ended at 330 s; 12,937 failed attempts after the restart (11,458 `DEADLINE_EXCEEDED`, 1,479 `INTERNAL`); mailbox 5,002 |
| `planned_stop` | `application:stop` takes 15.5 s; the server receives 46 of 500 `DISCONNECTED` (454 lost) | 15.6 s; 473 of 5,000 received (4,527 lost); during the stop the `pg` scope's mailbox peaked at 4,029, the registry's at 3,133, the agent supervisor's at 352 |
| `fanout` (0-10 s answers) | 500 of 500 answered in 10.0 s; per-command p50 4.8 s, p99 9.8 s; no connection drop | 5,000 of 5,000 in 31.3 s; p50 5.1 s, p99 9.9 s; no connection drop; router mailbox peak 213 |

Invariants that failed: at 500 agents, `ramp` and `storm`
(`upstream_register_in_parallel`), `server_crash` (`replay_in_parallel`,
`no_lost_disconnected`) and `planned_stop` (`no_lost_disconnected`); in the
`gate` group those four cases fail and `gateway_crash` and `fanout` pass. At
5,000 the same four, and more: `ramp` also fails `no_first_attempt_failures`,
`all_registered_within_budget`, `no_wasted_upstream_registers`,
`every_live_session_connected` and `singleton_mailboxes_drain`; `storm` also
fails `no_first_attempt_failures`, `all_registered_within_budget` and
`no_wasted_upstream_registers`; `gateway_crash` fails `all_reregistered` and
`no_register_failures_after_restart`. `fanout` passes at both sizes.

Across every case and both sizes:

- The gateway's schedulers were almost idle (weighted utilisation under 1%)
  while registrations took minutes: the limit is one process doing one
  `ProxyRegister` at a time, not CPU.
- Memory per connection was 360 to 620 KB, most of it process heap. One agent
  costs three processes: its `yuzu_gw_agent` process held 143 KB (89 KB after a
  garbage collection, the decoded `RegisterRequest` it keeps), its `Subscribe`
  handler 89 KB (4 KB after a collection) and its Cowboy connection 88 to
  160 KB (14 KB after a collection). The rest is heap the processes no longer
  use and have not collected.
- On the macOS host the gateway logged `gateway memory shedding is inactive:
  system_memory_unknown`, so the shedder took no part.

At 25,000 agents only the `fanout` case was run (18 min, half the agents on the
`::1` listener). Its setup phase, which registers every agent with the server
answering at once, did not finish: 12,028 agents were live when the wait ended
at 930 s, and agents kept losing their sessions and registering again. The
agent supervisor's mailbox peaked at 342,953 messages and the upstream's at
13,788; the gateway node held 28 GB (25 GB of it process heap) in 67,438
processes, with weighted scheduler utilisation 0.145. Of the 11,800 commands
sent to the agents live at that point, 6,150 were answered; 5,650 ended with
no answer, and 13,942 agent sessions ended during the fan-out. The management
connection stayed up.

## Results after the PR #5695 fixes

The same host and parameters, on the merged branch (`feat/gateway-grpc-client`
at c5c037e9b: EDGE, REGISTRY, SCALE and UPSTREAM workstreams), with two
harness changes that follow the shipped configuration: the fan-out client opens
up to 4096 calls (the management listener's new `max_concurrent_streams`), and
the gateway runs with `circuit_breaker_max_reset_timeout_ms` 30000 and
`notify_pending_max` 180000 as `sys.config.prod` now sets them. The fake
server's listener allows 128 streams per connection and has no frame budget
(see "How it is built"; the frame budget was found while measuring these
results). A full run took 55 s at 500 agents and 2 min at 5,000.

| Case | 500 before | 500 after | 5,000 before | 5,000 after |
|---|---|---|---|---|
| `ramp` (100/s) | all ok; p99 13.2 s; peak in flight 1 | all ok; p50 37 ms, p99 52 ms; peak in flight 7 | 1,087 of 5,000 first attempts ok; 5,883 wasted calls; not all registered at 330 s | all 5,000 first attempts ok; p99 52 ms; no wasted call |
| `storm` | all registered in 18.6 s; p99 18.3 s | in 0.5 s; p99 0.44 s; peak in flight 48 | 803 first attempts ok; all registered after 312 s | all 5,000 first attempts ok; all registered in 4.0 s; p99 3.6 s; peak in flight 48 |
| `server_crash` | serial replay, 33.6 s; 6 to 14 of 50 `DISCONNECTED` lost | replay 6.2 s, 24 in flight; none lost | 286 s serial; 13 of 500 lost | 13.3 s, 24 in flight; none lost |
| `gateway_crash` | all back in 20.7 s | all back in 2.6 s | 4,892 of 5,000 back at 330 s; 12,937 failed attempts | all back in 6.2 s; no failed attempt |
| `planned_stop` | stop 15.5 s; 454 of 500 lost | stop 0.06 s; none lost | 15.6 s; 4,527 lost | 0.47 s; none lost |
| `fanout` | 500 of 500 in 10.0 s | 500 of 500 in 10.0 s | 5,000 of 5,000 in 31.3 s (1024 calls open) | 5,000 of 5,000 in 12.1 s (4096 open) |

Memory per connection, after: 320 to 410 KB (360 to 620 KB before). One agent's
`yuzu_gw_agent` process now holds 89 KB (143 KB before; it registers after
`init/1` and keeps only the decoded `RegisterRequest`), its `Subscribe` handler
89 KB (4 KB after a collection) and its Cowboy connection 66 to 146 KB (14 KB
after a collection), as before: about 200 KB per agent is heap no process
uses, and about 90 KB is the request the agent process keeps.

Every invariant passed at 500 agents in the `gate` group on seven consecutive
runs (three before the fake server's frame budget was removed, three after,
one through `scripts/test_gateway.py`); the Meson `gateway ct` test now runs the
`gate` group. At 5,000 every invariant passed in a full run.

At 25,000 agents (`storm`, `planned_stop`, `fanout`, about 9 GB in the gateway
node, 340 to 350 KB per agent):

- `storm`: all 25,000 registered in 22 s; 11,206 to 11,585 first attempts were
  answered `UNAVAILABLE` (the permit pool full, the designed refusal) and
  succeeded on the agents' retry 2 s later. The invariant
  `no_first_attempt_failures` therefore fails at this size, by design.
- `planned_stop`: the stop took 5.0 s and the server received all 25,000
  `DISCONNECTED` notices; the registry's mailbox peaked at 42,861 during it.
- `fanout`: 25,000 of 25,000 answered in 37.4 s with no connection drop (second
  run). In the first run the setup never finished: ProxyRegister and
  NotifyStreamStatus calls were answered `DEADLINE_EXCEEDED` by the fake
  server (their grpc-timeout is at most `upstream_rpc_timeout_ms`, 5 s), the
  breaker opened 19 times and failed 18 half-open probes, and only 7,552
  agents were live after 930 s (the agents' backoff had reached minutes). The
  run followed the 25,000-agent `storm` case on a host using swap; the fake
  server's own counters, added since, were not captured in it, so the cause of
  the first stall is not isolated.

## One lost upstream connection

The `upstream_conn_loss` case was added after a 5,000-agent `storm` against a
healthy server whose single upstream connection had been closed showed the
gateway replaying its whole fleet: every call on the connection failed and each
counted against the circuit breaker, the breaker opened, its recovery started a
full replay, and a later failure aborted it and started over. The server got up
to 7,303 replayed registrations and 12,276 `CONNECTED` notices for 5,000 agents
it already knew. Same host as above.

| | 500 before | 500 after | 5,000 before | 5,000 after |
|---|---|---|---|---|
| wave, `ProxyRegister` open at the server when it closed the connection | 100, 21 | 100, 14 | 500, 10 | 500, 11 |
| breaker openings | 1 | 0 | 1 | 0 |
| registrations replayed | 600 (every agent) | 0 | 5,500 (every agent) | 0 |
| sessions with a second `CONNECTED` | 600 | 0 | 5,500 | 0 |
| wave agents whose first `Register` failed | 100 (74 `INTERNAL`, 26 `UNAVAILABLE` from the open breaker) | 50 (`INTERNAL`, their calls were on the connection) | 500 (38 `INTERNAL`, 462 `UNAVAILABLE`) | 37 (`INTERNAL`) |
| all registered after the wave started | 14.3 s | 2.3 s | 14.7 s | 2.3 s |

"Before" is c318b1e5a; "after" is the change that counts a lost connection once
and replays only what the server's heartbeat verdict says it does not know (see
"What starts a full replay" in `docs/user-manual/gateway.md`). The agents whose
calls were on the closed connection retry by their own rule (2 s), which is the
2.3 s. A real server restart still replays everyone: `server_crash` after the
change replayed all 450 held sessions in 6.8 s at 500 agents and all 4,500 in
13.2 s at 5,000 (13.3 s before it), 24 in flight, no `DISCONNECTED` lost.
