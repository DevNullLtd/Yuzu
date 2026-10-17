- **Gateway scale tests now drive real connections.** A new Common Test suite,
  `yuzu_gw_scale_SUITE`, starts the gateway, a fake server and a load generator
  as separate nodes and runs 500 simulated agents (5,000 or 25,000 on demand)
  over real HTTP/2 through six scenarios: a registration ramp, a registration
  storm, a server crash, a gateway crash, a planned stop and a management
  fan-out. Each agent registers with a real agent's plugin list (69 plugins).
  It reports registration latency, replay time, notices lost, memory per
  connection, singleton mailbox peaks and scheduler utilisation as JSON, and
  checks timing-free invariants (Register parallelism, no wasted server work,
  full parallel replay, no notice lost on an outage or a planned stop, every
  fan-out command answered). The Meson `gateway ct` test runs them as a gate
  (`YUZU_GW_SCALE_GATE=1`); a plain `rebar3 ct` run records violations without
  failing. `scripts/test/perf-gate.sh
  --scale-agents N` records its headline numbers, and now points the perf suite
  at `apps/yuzu_gw/test/ct`, where it lives. See
  `docs/testing/gateway-scale-tests.md`.
