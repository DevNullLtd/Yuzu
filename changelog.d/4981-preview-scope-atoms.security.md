- **Fixed — `preview_scope_targets` (MCP) / `POST /api/v1/scope/preview` (REST) now resolve
  `from_result_set:<id>` and `props.<key>` atoms identically to a real dispatch** (#4981). The
  prior implementation evaluated a scope expression against a bespoke per-agent attribute
  resolver that only ever populated `ostype`/`arch`/`hostname`/`agent_version`/`tag:<key>` — a
  `from_result_set:`/`props.` atom silently resolved to "" (unset), so the atom's comparison was
  always false, and `NOT from_result_set:<id>` inverted that to match every agent the caller
  could see, regardless of the referenced set's real membership: a fleet-wide over-disclosure
  bug, not merely an undercount. Both surfaces now route through the same evaluation ladder a
  real dispatch uses (alias resolution, the owner-check gate, parse, then registry evaluation,
  each step fail-closed), so a `from_result_set:<id>` referencing a set that is absent, expired,
  or not owned by the caller now aborts (`RESULT_SET_NOT_FOUND` — REST 404, MCP `kInvalidParams`)
  rather than silently matching nothing or, negated, everything; a degraded store or presence
  read aborts (REST 503, MCP `kInternalError`, both with a retry hint) rather than under- or
  over-reporting the match set. Confinement (a management-group-confined caller's own visible
  devices) is now applied AFTER the ladder's fleet-wide evaluation, matching how a real dispatch
  intersects against the operator's execute-visible set before sending. Additionally, a
  service-scoped API token is now denied outright (403) on both surfaces (closing the same
  cross-service-reach gap #4980 closed on `create_result_set_from_inventory_query`), and a
  preview no longer touches a referenced result set's TTL (`last_used_at`) as a side effect — it
  is now a genuine read-only dry run.
