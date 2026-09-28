- **`/dex` Catalogue family cards get a public REST + MCP resource.** `GET
  /api/v1/dex/catalogue` and the MCP twin `get_dex_catalogue` now serve the
  per-family monitored/total type count, health-score slice, window event
  count, and busiest member type the `/dex` Catalogue grid has always
  computed, plus an `uncatalogued[]` list of signal types seen on the wire but
  not yet in a curated family — the first public resource for this data (no
  per-agent identity; not audited). A degraded fleet signal-summary read now
  answers `503` (retryable) rather than a fabricated healthy, zero-event
  catalogue. `GET /api/v1/dex/overview` and its MCP twin `get_dex_overview`
  additionally carry `connected_platforms`, `busiest_family`, and
  `busiest_family_events`, mirroring the fields the Overview hub's own
  coverage tile and Explore card already show.
