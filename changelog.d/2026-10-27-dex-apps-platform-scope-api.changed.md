- **Breaking — `GET /api/v1/dex/apps` now covers every platform by default; it takes a
  `platform` query parameter (`all`, `windows`, `macos`, `linux`).** A caller that sends
  no `platform` now gets applications, counts, population and scores for every platform;
  add `platform=windows` to keep the former Windows-only figures. Under `all` an
  application is one row across operating systems. The response also carries a new
  `crash_source_coverage` object saying whether each platform's crash sources are complete
  (Windows) or partial (Linux, macOS). An unknown `platform` is a 400. The `list_dex_apps`
  MCP tool is unchanged apart from the additive field. Operating system spellings that
  start with `darwin` or `macos` (for example `darwin24.1`) now count as macOS in the
  fleet label and the Overview segments.
