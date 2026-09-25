- **`installed_apps` `list` now reports each application's install location and macOS bundle identifier** (`install_location`: the Windows Uninstall-key `InstallLocation`, unexpanded, or the location macOS reports; `bundle_id`: the macOS `CFBundleIdentifier`; `-` where the OS has none, which is every Linux row by design).
  It partially satisfies ADR-0028's `installed_apps`/`InstallLocation` sequencing dependency for the operator `list` action only; the hashed daily-sync blob addition remains open, and the ADR-0016 daily-sync row is unchanged.
  In the dashboard results table these rows still render as `app` plus one merged cell (a pre-existing server limit
  shared by the four original columns): the new fields appear in that cell and the search box matches them, but
  they are not separate, sortable or filterable columns; read them from `GET /api/v1/responses/{id}`, its
  `/export`, or MCP `query_responses`. An existing server keeps its seeded definition (four declared columns)
  until you edit it; row content is unaffected. The columns anchor a future installed-component inventory
  (ADR-0028, not yet implemented); no bundled-library or file-system scanning ships in this release.
