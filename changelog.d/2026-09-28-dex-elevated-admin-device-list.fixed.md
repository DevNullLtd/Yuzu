- **`GET /api/v1/dex/signals/{obs_type}`, `GET /api/v1/dex/app`, and `GET
  /api/v1/dex/overview` (REST + MCP) now gate exclusively on the ADR-0017
  admit-then-filter fleet-read chokepoint (`AuthRoutes::require_fleet_read`),
  and these three fleet-wide-aggregate reads are pinned to a GLOBAL grant
  only.** Under the previous shape, a bare permission check resolved global
  roles only, so a management-group-confined operator with no global grant
  was denied outright (`403`) before the confinement resolver behind it ever
  ran — that resolver's own confinement was therefore dormant, never
  disclosive. Migrating onto `require_fleet_read` does not change that a
  confined operator (management-group-scoped, or a service-scoped API token
  under RBAC enabled) is refused (`403`) — it stays refused, now with its own
  `<verb>|denied` audit row — because `subjects[]`/`by_os[]`/`devices[]`/
  `by_day[]`/`top_devices[]`/`top_apps[]` and every other field these three
  routes return are fleet-wide aggregates with no per-caller SQL slice
  (ADR-0017 INV-3); a per-row device-list filter cannot confine an aggregate,
  so serving a narrowed answer would have been silently incomplete or
  outright leaked the underlying rollup. What DOES change: an **elevated**
  administrator with zero underlying RBAC grants now correctly sees the
  unfiltered fleet (previously narrowed to the base identity's own, usually
  empty, grant), and a genuinely **unwired** fleet-read gate — a server
  misconfiguration, distinct from a wired gate legitimately refusing a
  confined caller — now fails closed (REST `503`, MCP internal error) rather
  than silently serving the whole fleet.
