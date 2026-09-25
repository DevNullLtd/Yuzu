- **Breaking — `installed_apps` `list` rows grow from five to seven `|`-separated fields (definition `crossplatform.software.inventory` 1.1.0, plugin 1.2.0).**
  Each `app|` row now ends `…|install_date|install_location|bundle_id`. A script, SIEM parser or export job that
  unpacks or anchors exactly five fields fails or drops every row from an upgraded agent, and one that reads the
  last field as `install_date` now reads `bundle_id`. The first five fields keep their position; every field is
  now escape-aware (`\` folds to `/`, `|` to `\|`, CR/LF to a space, a field over 4 KiB is cut) — a no-op for
  every value in the three reference captures. Policies or scripts that substring-match the raw `output` now
  also see install paths and bundle identifiers; both are untrusted, as reported by the local registry/bundle. On macOS, applications sharing a name now sort by (name,
  install_location) — the previous relative order was arbitrary — in the collector shared by `list`, `query` and
  `list_per_user`, so all three re-sort; row shape and the daily-sync inventory are otherwise unchanged. Agents
  not yet on plugin 1.2.0 keep emitting five fields and do not escape `|`, so
  both shapes coexist during a rollout: accept a row only when it has exactly 5 or exactly 7 escape-aware
  tokens, reject any other count, and read the sixth/seventh columns only for agents known to be on plugin
  1.2.0 or later. See the `installed_apps list` note in `docs/user-manual/server-admin.md` (Upgrade Notes).
