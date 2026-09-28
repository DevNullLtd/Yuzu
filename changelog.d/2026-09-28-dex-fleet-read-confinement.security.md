- **`GET /api/v1/dex/signals/{obs_type}`, `GET /api/v1/dex/app`, and `GET
  /api/v1/dex/overview` (REST + MCP) now gate on the ADR-0017 admit-then-filter
  fleet-read chokepoint (`AuthRoutes::require_fleet_read`) instead of a bare
  permission check paired with a per-file confinement resolver.** Under the
  previous shape, the bare permission check resolved global roles only, so a
  management-group-confined operator with no global grant was denied outright
  (`403`) before the confinement resolver behind it ever ran — that resolver's
  own confinement was therefore dormant, not disclosive. Migrating onto
  `require_fleet_read` fixes this the other way: a management-group-confined
  operator now gets their own visible devices instead of a `403`, and an
  elevated administrator correctly sees the unfiltered fleet (previously
  narrowed to the base identity's own, usually empty, grant). The visibility
  filter is applied POST-`limit` on the signal drill-down (the store's
  top-`limit` most-affected devices are fetched first, then filtered), so a
  confined caller may see fewer than `limit` devices; `subjects[]`/`by_os[]`/
  `by_day[]` remain fleet-wide aggregates. A genuinely **unwired** fleet-read
  gate — a server misconfiguration, distinct from a wired gate legitimately
  answering "unfiltered" under RBAC-off or a global grant — now refuses the
  request (REST `503`, MCP internal error) rather than silently serving the
  whole fleet.
