- **Fleet-wide RBAC role assignment for human users (A2).** An Administrator can now
  grant or revoke one of 6 built-in roles (`Administrator`, `PlatformEngineer`,
  `Operator`, `ApiTokenManager`, `Viewer`, `Reviewer`) to a human user, fleet-wide, via
  `POST/DELETE /api/v1/rbac/roles/{name}/assignments` and MCP twins `assign_rbac_role`/
  `unassign_rbac_role`. Gated on a dedicated durable-Administrator check (re-read fresh
  from the store, never a cached session role or JIT elevation) instead of an ordinary
  permission check. Guards: a caller may not revoke their own `Administrator` grant,
  and the fleet's last remaining (authenticatable) `Administrator` grant is refused for
  anyone — enforced inside the same transaction as the removal, and scoped to accounts
  that are actually active in `auth.users` so a grant naming a nonexistent,
  deactivated, or deleted username is never counted as a survivor. The guard also
  holds against a concurrent reactivation of the removed principal's existing
  account. Two races remain outside it: an account created concurrently for a
  pre-provisioned grant, and a surviving Administrator's account deactivated
  concurrently (the account-deactivation path has no last-Administrator guard);
  both are tracked at #4966.
  `ITServiceOwner` and any custom/unknown role are rejected uniformly (no role-catalog
  oracle); pre-provisioning a role ahead of a user's first login is allowed. Both routes
  ALSO re-verify, with a fresh, uncached read, that the caller holds authority under the
  regime that is durably true right now, closing a cross-replica cache-staleness gap in
  the durable-Administrator check itself — a grant minted through a stale-regime read
  would otherwise persist indefinitely once written. A bearer token minted with a
  restrictive `mcp_tier` (e.g. `readonly`) whose principal happens to be a durable
  administrator can no longer reach either route via REST with no MFA/approval gate.
