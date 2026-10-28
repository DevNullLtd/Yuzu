- **One dropped upstream connection no longer replays the whole fleet.** The
  gateway counted every call a lost upstream connection took with it as a
  separate circuit-breaker failure, so one reset connection could open the
  breaker, and every breaker recovery (and any success after a single failed
  call) re-registered every agent with a server that had lost nothing. A lost
  connection now counts once, a connection the server is closing (GOAWAY) is
  replaced at the first call it refuses, and a recovery replays nothing by
  itself: the gateway replays the sessions the server's heartbeat answer says it
  does not know, and every agent only when that answer shows the server lost its
  state (at least half of a batch unknown; at most once a minute). New label
  values: `yuzu_gw_registration_replay_triggered_total{trigger="server_lost_state"|"manual"}`
  (`breaker` stays at 0) and `yuzu_gw_upstream_rpc_errors_total{code="connection_lost"}`.
  The scale suite gains an `upstream_conn_loss` case: at 5,000 agents the server
  got 5,500 replayed registrations and 5,500 repeated `CONNECTED` notices before,
  none after.
- **A planned gateway stop no longer logs crash reports.** The Prometheus
  endpoint is stopped at the end of the stop instead of being killed by the
  application master's clean-up, which made its inets acceptor fail to restart
  about 20 times (67 crash and supervisor reports at 500 agents, now none).
