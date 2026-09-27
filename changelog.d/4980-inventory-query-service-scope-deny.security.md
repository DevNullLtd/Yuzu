- **Security — `POST /api/v1/result-sets/from-inventory-query` now hard-denies a
  service-scoped API token outright, matching its 8 non-dispatch sibling
  result-set routes (#4980).** Previously this route gated purely through the
  admit-then-filter `fleet_read_fn` chokepoint (ADR-0017), whose service-scope
  branch admits-and-confines a service-scoped caller under RBAC-on rather than
  denying it (RBAC-off, the default, was unaffected — `fleet_read_fn` still
  hard-denied a service-scoped caller there) — but the result set this call
  materializes is owner-scoped to
  `session->username` (the token-minting **principal's** identity, not the
  token's own service tag), so a service-scoped token holding `Inventory:Read`
  could mint a result set the minting principal's other tokens/session could
  then read: a cross-service-reach gap, originally tracked as #4307. The MCP
  twin, `create_result_set_from_inventory_query`, was verified during this fix
  to already be safe — its `kToolSecurity` classification defaults to
  `ServiceScopeClass::denied`, and MCP's generic C8 gate structurally denies a
  service-scoped caller before the tool's handler (and its `fleet_read_fn_`
  call) ever runs, so only the REST route needed the fix. No `.permission` is
  named on the new deny's error body — a service-scoped caller holding
  `Inventory:Read` is still denied outright, so naming that permission as "the
  fix" would be a false self-remediation claim.
