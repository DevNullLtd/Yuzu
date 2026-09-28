- **`GET /api/v1/dex/signals/{obs_type}`, `GET /api/v1/dex/app`, and `GET
  /api/v1/dex/overview` (REST + MCP) no longer narrow a JIT-elevated
  administrator's device list.** These three routes carried a per-caller
  `visible`-set resolver whose confinement was already dormant for the
  operator class it was meant to protect — a management-group-confined-only
  operator has no global grant, so the routes' bare permission gate denied
  them (`403`) before that resolver ever ran — but the SAME resolver ran for
  an elevated administrator and wrongly narrowed their device list to the
  base identity's own (usually empty) management-group grant instead of the
  unfiltered view elevation earns. The dormant, never-narrowing-anyone-real
  resolver has been retired outright; every admitted caller (a global grant,
  RBAC disabled, or an elevated administrator) now sees the same unfiltered
  device list. No other caller class's behaviour changes: a management-group
  -confined operator is still denied by the unchanged permission gate, and a
  service-scoped API token is still denied outright.
