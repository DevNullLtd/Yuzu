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
