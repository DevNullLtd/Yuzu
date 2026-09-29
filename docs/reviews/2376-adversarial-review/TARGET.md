# Adversarial review target

**Change:** #2376 — an authorization-topology floor that holds regardless of the RBAC toggle, plus a
new `EnginePrincipal` RBAC securable cut away from the over-broad `Security:Read`.

**Repo:** /home/fraser/Yuzu/.claude/worktrees/authz-topology-floor (a git worktree; branch
`feat/authz-topology-floor`). **Range:** `origin/dev..HEAD` = c686f31a..33b4153a, 7 commits.

**The defect being closed.** `RbacStore::rbac_enabled_` defaults false, so a fresh install runs RBAC
OFF — the default posture. With RBAC off, `require_permission`/`require_scoped_permission` fall
through to a legacy branch that allowed EVERY `Read` to any authenticated non-engine session. On a
default install a plain `user` could read the authorization topology: the fleet-wide access-review
export (SOC 2 CC6.2 evidence), `GET /api/v1/rbac/roles`, and the engine-principal grant graph.

**The fix, three parts.** (1) A new `EnginePrincipal:Read` securable carrying the engine-principal
inventory/grant-graph reads (3 REST routes + 3 MCP tools), seeded to Administrator + Viewer — exactly
the roles that reached them via `Security:Read`. (2) `{AccessReview:Read, UserManagement:Read,
EnginePrincipal:Read}` require an admin effective role regardless of the RBAC toggle, via one
chokepoint (`authz_topology_floor.hpp`) applied at BOTH legacy branches. (3) A distinct audit reason
plus `yuzu_auth_topology_floor_denied_total{permission}`.

**Prior review.** `/governance` ran 14 agents over 4 rounds: 18 findings, 7 blocking (2 policy floors
+ 5 derived HIGH), all fixed. You are NOT being asked to re-run governance. You are the independent
panel — look for what 14 same-family reviewers missed.

**The claims most worth attacking:**
1. The floor is applied ONLY in the legacy branch and can never shadow a live RBAC grant.
2. `perm_fn` is a genuine single chokepoint — no surface reaches the floored data around it.
3. No schema migration is needed because `seed_defaults()` re-seeds unconditionally.
4. Viewer keeping `EnginePrincipal:Read` preserves prior access exactly and widens nothing.
5. The MCP tier gate and the RBAC gate agree for all three moved tools.
