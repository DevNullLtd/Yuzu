- **tar.db corruption is now fleet-observable** (#1567). `tar.status` gains a
  `db_health|<ok|quarantined>|<epoch>` row; the tar plugin publishes
  `heartbeat.db_corruption_total` / `heartbeat.db_quarantine_last`, which a new
  generic plugin heartbeat-tag bridge forwards as `yuzu.plugin.tar.*` tags. The
  server exposes `yuzu_fleet_tar_db_corruption_agents` and
  `yuzu_fleet_plugin_init_failed{plugin}`, writes one `tar.db.corruption_quarantined`
  audit row per quarantine (deduplicated against the audit store), and a new
  `yuzu.plugins_failed` heartbeat tag distinguishes a plugin that failed init from
  one that is not installed.
