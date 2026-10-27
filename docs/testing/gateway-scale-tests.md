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
| `owner_kill` | N agents registered; the owner process (`yuzu_gw_agent`) of 10% of them is killed at once with `exit(Pid, kill)` (no clean-up runs; modelled on an independent tester's cell ch_x10a). Each restarted owner must send its session's `DISCONNECTED` and recover the session on the agent's open stream; then one command is sent to every killed agent. Measures the time until every killed session is `CONNECTED` again |
| `upstream_conn_loss` | N agents registered; a wave of N/10 more (at least 100) registers at once, and once at least 8 `ProxyRegister` calls are open at the server it closes the gateway's upstream connection (kills its connection process) and keeps running with everything it knows. Counts breaker openings, replayed registrations and repeated `CONNECTED` notices |
| `unacknowledged` | N agents register at once while the server answers every `CONNECTED` with `acknowledged=false` (it does not record it) for the first `YUZU_GW_SCALE_UNACK_MS` (10 s) of the case, then records them: the independent tester's ch_xa stub, which held 60 s. Measures how long after the switch the last live session is recorded |

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
  failed ("wasted"), and of those the ones that provably arrived after the
  agent had already given up ("stale": the server had already received a call
  for a later attempt of the same agent, a lower bound) (each agent puts its
  attempt number in one extra scopable tag, which the gateway forwards
  unchanged, so each call is matched to its attempt); `CONNECTED` and
  `DISCONNECTED` counts; live sessions the server
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

No result compares a time taken on one node with a time taken on another. Each
node's `erlang:system_time` follows the OS clock through that node's own time
correction, so the four nodes disagree by tens of microseconds while the OS
clock is steady and by milliseconds while it is being slewed (an `owner_kill`
`DISCONNECTED` once read 6 ms before the suite's kill marker, and the case
reported 34 of them missing from a run that had every one). Before a case acts,
the suite asks the fake server and the load generator for a marker (a sequence
number each, `mark/0`); "since the kill" or "since the wave" means "started
there with a larger number". A number is taken when the thing STARTS, never
when it ends: a load-generator `Register` when it is sent, a failed connection
when it was opened (so a connection opened before a marker and failing after it
is not counted after it), and a fake-server call when it arrives. A duration is
a difference of two times taken on the same node.

## Invariants and the gate

Each case also checks invariants that involve no timing:

| Case | Invariant |
|---|---|
| `ramp`, `storm` | no registration is replayed (the server lost nothing); every first `Register` succeeds; every agent registers within the budget; more than one `ProxyRegister` is in flight at the server at some point; no `ProxyRegister` creates a session at the server for an attempt that failed ("wasted" above); the server holds a `CONNECTED` for every live session; every singleton mailbox is back to 0 |
| `server_crash` | both waits finish before they stall or reach their cap (every held session replayed and every agent live again; then every flapped agent's `DISCONNECTED` received as well); every held session is replayed; more than one replay is in flight at some point; every `DISCONNECTED` raised during the outage reaches the server; the new server holds a `CONNECTED` for every live session |
| `gateway_crash` | every agent registers again; no `Register` to the new gateway fails; the server holds a `CONNECTED` for every live session |
| `planned_stop` | the server receives a `DISCONNECTED` for every session; the gateway node logs no crash or supervisor report during the stop |
| `fanout` | every command is answered; the management connection is never closed; no agent loses its session |
| `upstream_conn_loss` | at least 8 `ProxyRegister` calls were in flight at the server when the connection was closed (without that, the next invariant proves nothing); the server closed at least one connection; the circuit breaker never opened; no registration was replayed; at most 10 sessions got a second `CONNECTED` (the notifications in flight when the connection went are sent again, their answers were lost with it); every agent registers within the budget; the server holds a `CONNECTED` for every live session |
| `owner_kill` | at least one owner was killed; every killed owner's session had its `DISCONNECTED` reach the server; every one was `CONNECTED` again after that `DISCONNECTED` within the budget; no agent lost its stream or registered again (every killed owner's agent kept its session, and the fleet saw no disconnect); a command to every killed agent afterwards was answered; the agent supervisor was not restarted; the server holds a `CONNECTED` for every live session; every singleton mailbox is back to 0 |
| `unacknowledged` | the server refused at least one `CONNECTED` (without that, the case proves nothing); every live session's `CONNECTED` is recorded within `YUZU_GW_SCALE_UNACK_BOUND_MS` (90 s: the gateway's 60 s longest normal-phase resend backoff plus 30 s) after the server starts accepting them; the circuit breaker never opened; and the `ramp`/`storm` invariants |
| every case that registers its agents first | no registration is replayed during that setup (the server lost nothing) |

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
| `YUZU_GW_SCALE_KILL_PCT` | 10 | percent of agents whose owner process `owner_kill` kills |
| `YUZU_GW_SCALE_UNACK_MS` | 10000 | `unacknowledged`: ms from the start of the case during which the server refuses every `CONNECTED` (60000 reproduces ch_xa). A window shorter than 15 minutes slows no one: the gateway's slow phase (a `CONNECTED` resent only every 8 to 10 minutes; #6059 stopgap) starts only once a `CONNECTED` has been refused continuously for `notify_unacked_slow_after_ms` (900000, 15 minutes; #6077). A window longer than that engages it, so raise `YUZU_GW_SCALE_UNACK_BOUND_MS` above the gateway's `notify_unacked_slow_max_ms` (600000) with it, or `every_live_session_recorded` fails by design |
| `YUZU_GW_SCALE_UNACK_BOUND_MS` | 90000 | `unacknowledged`: ms after the switch by which every live session must be recorded |
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
  system_memory_unknown`, so the shedder took no part. (The shedder now reads
  the host's memory on macOS from `hw.memsize`, so a rerun there would have it
  active, at 0.75 of the host's memory by default.)

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
  server's own counters, added since, were not captured in it. See "The
  25,000-agent stall" below for the loop that most likely drove it and the
  change that removes it.

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

## Crash reports on a planned stop

A planned stop logged about 20 crash reports from the inets `httpd_acceptor`
behind the Prometheus endpoint (`noproc` on `link`), each with a supervisor
report. It predates PR #5695 (`yuzu_gw_app` starts the endpoint the same way on
`dev`): the application master killed the endpoint's listen-socket owner, which
carries the gateway application's group leader, and the acceptor's restarts
could not link to it. The `planned_stop` case now counts crash and supervisor
reports logged in the gateway node during the stop and fails on any: 67 at 500
agents before the fix (the endpoint is now stopped in `yuzu_gw_app:stop/1`), 0
after.

## The 25,000-agent stall

One earlier 25,000-agent `fanout` run never finished its setup (see "Results
after the PR #5695 fixes": the breaker opened 19 times and only 7,552 agents
were live after 930 s). It followed a 25,000-agent `storm` on a host that was
swapping, and a rerun did not reproduce it. After the change under "One lost
upstream connection", the 25,000-agent `storm` and `fanout` cases were run back
to back twice with `YUZU_GW_SCALE_TRACE_UPSTREAM=1` on a quiet host (no other
Erlang node or test running; 3.1 GB of the 4 GB swap file still held stale pages
from earlier work, but the swap-out counter did not move during any of the runs
and memory was 92 to 94% free), then twice more with the gateway source of
c318b1e5a (before that change) for comparison. The harness now also records the
gateway's own view of the upstream (breaker transitions, `BatchHeartbeat` flush
times, RPC errors by code, replays by trigger) and the live-agent count every
5 s.

| | after, run 1 | after, run 2 | before, run 1 | before, run 2 |
|---|---|---|---|---|
| `storm`: all registered | 22.2 s | 21.7 s | 22.8 s | 23.3 s |
| `storm`: breaker transitions, upstream RPC errors | none | none | none | none |
| `fanout` setup: all 25,000 live | 19.2 s | 8.6 s | 14.3 s | 9.3 s |
| setup: `ProxyRegister` / `NotifyStreamStatus` answered `DEADLINE_EXCEEDED` | 16 / 2 | 0 / 0 | 19 / 3 | 9 / 1 |
| setup: replays started | none | none | 1 (`breaker`) | 1 (`breaker`) |
| setup: replayed registrations | 0 | 0 | 16,214 | 24,677 |
| setup: `CONNECTED` notices for 25,000 agents | 25,000 | 25,000 | 30,740 | 40,901 |
| setup: slowest `BatchHeartbeat` flush | 0.9 s | 3 ms | 1.4 s | 2.7 s |
| setup: smallest `grpc-timeout` a `ProxyRegister` arrived with | 3.9 s | 5.0 s | 5.0 s | 5.0 s |
| setup: fake server's connection mailbox, longest | 25 | 32 | 29 | 31 |
| `fanout`: answered, connection drops, agent disconnects | 25,000, 0, 0 | 25,000, 0, 0 | 25,000, 0, 0 | 25,000, 0, 0 |
| breaker transitions in any phase | none | none | none | none |

The stall did not reproduce in the four quiet runs, but the runs show the loop
that can turn a few slow answers into one. During the setup, with the fake
server answering at once, a few calls were answered `DEADLINE_EXCEEDED` before
their handler started (in the first run after the change the fake handled
exactly 25,000 `ProxyRegister` calls for 25,000 agents, 16 attempts having
failed that way, and stopped no handler at a deadline, so each of those calls spent most of
its 5 s between its headers reaching the fake and the rest of it arriving on the
one connection all upstream calls share). Before the change, the next success
after one such failure started a full replay of every agent registered so far,
in the middle of the registration storm: 16,214 and 24,677 extra
`ProxyRegister` calls and 5,740 and 15,901 repeated `CONNECTED` notices on that
same connection. On the quiet host the extra load was absorbed; on a host that
was swapping, more calls would time out, five in a row open the breaker, and
every close of the breaker started the full replay again, which matches the
19 openings and the timed-out heartbeat flushes of the stalled run. After the
change the same failures replay nothing (the server lost nothing, so no
heartbeat verdict lists a session). The setup of every case now fails on any
replay (`no_replay_in_setup`), as do `ramp` and `storm`
(`no_replay_during_registration`). What delays a call's body on the shared
connection at this load is not isolated: the fake's connection process was not
backlogged (at most 32 messages when a call started), so the gateway side of
the connection (gun's single connection process, or HTTP/2 flow control) is the
remaining suspect, and the C++ server's own connection handling is not the
same as the fake's.

## Owner processes killed (`owner_kill`)

Added with the OWNER-RESTART change (#5695): before it, a killed agent owner
process (`yuzu_gw_agent`, the one process that holds an agent's session) was
not restarted and sent nothing to the server. Same host as above.

| | 500 agents, 50 owners killed, before | 500 agents, 50 killed, after | 5,000 agents, 500 killed, after |
|---|---|---|---|
| `DISCONNECTED` received for the killed sessions | 0 | 50 | 500 |
| Sessions `CONNECTED` again after their `DISCONNECTED` | 0 (the agents registered new sessions after their heartbeat was refused, about 65 s) | 50, the last 22 ms after the kill | 500, the last 147 ms after the kill |
| Agents that lost their stream or registered again | 50 | 0 | 0 |
| Commands to the killed agents answered afterwards | 50 (on their new sessions) | 50 | 500 |
| Agent supervisor restarted | no | no | no |
| Invariants violated | `no_lost_disconnected`, `all_recovered`, `no_agent_reconnect` | none | none |

500 restarts within a second is a quarter of the agent supervisor's default
restart intensity (2000 in 10 s), so it does not escalate.

