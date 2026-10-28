- **Gateway: registrations no longer queue behind one process; planned stops tell the server; the breaker recovers within 30 s (#5695).**
  `ProxyRegister` and `ProxyInventory` run in the agent's own request process under
  bounded permits (48 for registrations, of which replays at most 24, and 8 for
  inventory; sized to stay under the server's 128 HTTP/2 streams per connection),
  with a bounded wait queue whose entries carry the agent's deadline: a burst far
  above the permit count is absorbed instead of refused, a request that runs out of
  time while it waits is never sent, and the upstream call carries a `grpc-timeout`.
  A refusal that means "retry" (breaker open, queue full, deadline, stopping) is
  answered `UNAVAILABLE`. A registration replay after a server restart walks the
  agents table in chunks and replays 24 agents at once (5,000 agents in seconds,
  not minutes), after a start jitter (`registration_replay_start_jitter_ms`, 1000 ms);
  `registration_replay_spacing_ms` is no longer read. The held stream-status
  notification cap defaults to three per agent-listener connection (at least
  15,000; 180,000 in the shipped production config); when full, a `DISCONNECTED`
  evicts the oldest held `CONNECTED`, and a lost `CONNECTED` triggers a full replay
  so every agent re-sends it; a failed send is retried; two events of one session
  are never in flight together. A planned stop (SIGTERM) now ends every agent
  session and sends its `DISCONNECTED` notice to the server before the processes
  stop, within `shutdown_flush_budget_ms` (20 s); the compose files set
  `stop_grace_period: 40s` and the systemd unit `TimeoutStopSec=40` to fit it.
  `circuit_breaker_max_reset_timeout_ms` defaults to 30000 (was 300000), and
  `YuzuGatewayUpstreamCircuitOpened` fires only when the breaker opened and has not
  closed for 3 minutes, or keeps flapping. New metrics:
  `yuzu_gw_upstream_permits_{held,waiting}`, `yuzu_gw_upstream_permit_{limit,refused_total,wait_seconds}`,
  `yuzu_gw_registration_replay_outcomes_total`,
  `yuzu_gw_registration_replay_last_duration_seconds`,
  `yuzu_gw_upstream_notify_lost_total{event,reason}`,
  `yuzu_gw_upstream_notify_requeued_total`, `yuzu_gw_upstream_notify_pending_{hwm,max}`;
  the pressure lane `serial` is now `permits`.
