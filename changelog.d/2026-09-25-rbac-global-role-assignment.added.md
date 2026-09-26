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
  counts the removed principal's existing account when it is reactivated
  concurrently; a concurrently created account, or a concurrently deactivated
  surviving Administrator, remain outside it (tracked at #4966).
  `ITServiceOwner` and any custom/unknown role are rejected uniformly (no role-catalog
  oracle); pre-provisioning a role ahead of a user's first login is allowed.
