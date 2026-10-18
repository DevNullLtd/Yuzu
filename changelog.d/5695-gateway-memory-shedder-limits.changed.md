- **The gateway's memory shedder uses the container's memory limit, recovers
  from a failed resume, and documents that it refuses new agents.** The
  high-water and low-water fractions are now of the smaller of host memory and
  the cgroup memory limit (cgroup v2 `memory.max` or v1
  `memory.limit_in_bytes`, in the gateway's own cgroup and every parent, read
  at start), so a gateway in a container or under a systemd `MemoryMax=` sheds
  before the OOM killer stops it; before, the fraction was of the host's
  memory and a limited container never shed. The marks in force are on
  `/metrics` (`yuzu_gw_memory_shedding_high_water_bytes`,
  `yuzu_gw_memory_shedding_low_water_bytes`). A resume or suspend of the agent
  listener that fails (for example `eaddrinuse` or `emfile` when reopening the
  socket) is now retried every `interval_ms`, logged, counted
  (`yuzu_gw_memory_shedding_transition_failures_total`) and shown
  (`yuzu_gw_memory_shedding_transition_failing`); before, one failed resume
  left the gateway refusing new agents for good. The new critical alert
  `YuzuGatewayMemorySheddingTransitionFailing` fires when that lasts 5
  minutes. A shedder that restarts while shed now resumes the listener its
  predecessor suspended. While shedding, a new agent connection is refused
  (`ECONNREFUSED`), as it always was; the manual and code comments wrongly
  said it waited in the kernel backlog, and now explain why refusing is the
  intended behaviour. On macOS the fractions now work from `hw.memsize`
  instead of leaving the shedder inactive.
- **Gateway: one absolute memory-shedding mark no longer turns shedding off,
  marks that cannot work refuse to start, and an inactive shedder alerts
  (#5695).** Setting only `memory_shedding` `high_water_bytes` (for example
  1 GiB) left the low mark at its default of 0.65 of the memory limit, above
  the high mark, so the shedder ran inactive with only a warning line and
  zeroed gauges. Now, when exactly one of `high_water_bytes` /
  `low_water_bytes` is set and the other mark is not set at all, the other is
  derived from it with the ratio of the defaults (low = high x 0.65 / 0.75,
  high = low x 0.75 / 0.65, a derived high mark clamped below the memory
  limit). **A config that used to boot can now refuse to start:** with
  shedding enabled, a low mark not below the high mark, a mark at or above the
  memory limit (the smaller of host memory and the cgroup limit, read at boot)
  or a mark that is not positive refuses boot with `Refusing to start:
  {yuzu_gw, memory_shedding}: ...`, naming the settings. Where no memory limit
  is readable for a fractional mark the shedder still runs inactive without
  failing boot, but the new gauge `yuzu_gw_memory_shedding_inactive` reads 1
  and the new warning `YuzuGatewayMemorySheddingInactive` fires after 10
  minutes. Found by the independent review of 2026-10-18.
