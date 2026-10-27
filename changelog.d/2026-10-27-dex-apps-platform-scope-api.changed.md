- **`GET /api/v1/dex/apps` takes a `platform` query parameter (`all`, `windows`, `macos`,
  `linux`), and its default is now `all`, which is a breaking change.** A caller that sends
  no `platform` now gets applications, counts, population and scores for every platform;
  add `platform=windows` to keep the former Windows-only figures. Under `all` an
  application is one row across operating systems. The response also carries a new
  `crash_source_coverage` object saying whether each platform's crash sources are complete
  (Windows) or partial (Linux, macOS). An unknown `platform` is a 400. The `list_dex_apps`
  MCP tool is unchanged apart from the additive field.
