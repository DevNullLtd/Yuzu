- **Leader-election metrics and alerts (HA WS-11, #4014).** Every server with a Postgres-backed leader
  elector now exports `yuzu_server_leader_is_leader`, `yuzu_server_leader_epoch`,
  `yuzu_server_leader_acquired_total`, `yuzu_server_leader_acquire_failures_total{cause}`,
  `yuzu_server_leader_lost_total{cause}`, `yuzu_server_leader_last_ok_age_seconds` and
  `yuzu_server_leader_loop_errors_total` on `/metrics`, published at scrape time so a stalled coordination
  connection cannot stall a scrape. `docs/prometheus/yuzu-alerts.yml` gains the `yuzu-ha-leader` group:
  `YuzuLeaderSplitBrain`, `YuzuLeaderNoLeader` and `YuzuLeaderCoordinationStale` (critical) and
  `YuzuLeaderFlapping` (warning); reload your rule file, and scrape each replica individually. Leadership is
  deliberately not part of `/readyz`, so these alerts are the only signal that the leader-only background
  passes are paused. The `leader_elector: acquired leadership` log line now carries the `holder_id`. This does
  not lift the second-replica safe-to-scale gate; remediation-claim counters (#6526), a CRL freshness gauge
  (#6527) and a durable cluster-capability admission gate (#6528) are tracked separately.
