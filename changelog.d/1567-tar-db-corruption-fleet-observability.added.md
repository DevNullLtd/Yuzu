- **tar.db corruption is now newly detected fleet-wide** (#1567; see
  `docs/user-manual/tar.md` "Fleet visibility" for known limitations —
  audit-row latency during a mass event, and no backfill for a device
  quarantined before this shipped). `tar.status` gains a
  `db_health|<ok|quarantined>|<epoch>` row; the tar plugin publishes
  `heartbeat.db_corruption_total` / `heartbeat.db_quarantine_last`, which a new
  generic plugin heartbeat-tag bridge forwards as `yuzu.plugin.tar.*` tags. The
  server exposes `yuzu_fleet_tar_db_corruption_agents` and
  `yuzu_fleet_plugin_init_failed{plugin}`, writes a `tar.db.corruption_quarantined`
  audit row per (agent, quarantine identity), deduplicated against the audit store
  and rate-limited per agent per server process, and a new `yuzu.plugins_failed`
  heartbeat tag distinguishes a plugin that failed init from one that is not
  installed.
