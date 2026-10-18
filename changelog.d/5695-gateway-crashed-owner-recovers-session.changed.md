- **A crashed agent owner process on the gateway is restarted, tells the server
  the session ended, and recovers the agent.** Each agent session is held by one
  owner process on the gateway. When one died abnormally nothing told the
  server, which kept the agent listed as connected until the agent itself
  reconnected (about 54 s in an independent tester's runs). The agent supervisor
  now restarts it (`transient` children): the restarted owner sends the
  `DISCONNECTED` notice for its predecessor's session (with the same stream home
  id), and if the agent's Subscribe stream is still open it re-attaches to it,
  waits for that notice to reach the server, registers the same session again
  and announces `CONNECTED`, so commands reach the agent again without a
  reconnect; the agent's heartbeats stay admitted on its connection while that
  happens. If the stream is gone it stops after the `DISCONNECTED` and the
  agent reconnects by itself. One owner may be restarted 3 times in 60 s; then
  it gives up (one WARN, the session ends). A crash of most owners at once
  (more than `agent_restart_intensity`, default 2000, within
  `agent_restart_period_s`, default 10) restarts the agent supervisor, and every
  session ended that way gets its `DISCONNECTED`. New metric
  `yuzu_gw_agent_owner_restarts_total{outcome}` (`recovered`,
  `disconnected_only`, `gave_up`) and alert `YuzuGatewayAgentOwnerCrashLoop`
  (fires after a give-up). Measured with 5,000 agents and 500 owners killed at
  once: 500 `DISCONNECTED` received and all 500 sessions recovered within
  147 ms, with no agent reconnecting. The scale suite has a new `owner_kill`
  case.
