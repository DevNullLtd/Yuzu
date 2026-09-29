Warning: Unknown toolsets: messaging

session_id: 20260806_104745_0a12c0
## Security Pass 2 — Findings

### 1. FIX VERIFICATION: ITServiceOwner Regression (MEDIUM)

**The fix is correct as a leak-fix but introduces a false denial.**

`GET /api/v1/management-groups/{id}/roles` now requires both `ManagementGroup:Read` AND `UserManagement:Read` (`rest_api_v1.cpp:1963-1983`). The seeded `ITServiceOwner` role holds `ManagementGroup:Read` (`rbac_store.cpp:668`) but holds **no** `UserManagement` grants at all (`rbac_store.cpp:657-698` — ITServiceOwner's loop explicitly excludes `UserManagement`).

**Concrete trigger:**
- Seed a user as ITServiceOwner on group G.
- Call `GET /api/v1/management-groups/{G}/roles` → **403 after the fix**, 200 before.

**Why this is a regression:** `ITServiceOwner` is the group-scoped admin role. The `POST` and `DELETE` handlers for the same path (`rest_api_v1.cpp:2042-2118`) include an `ITServiceOwner` self-check fallback — if the caller lacks `ManagementGroup:Write`, the handler looks up whether the caller is ITServiceOwner on that group and allows the mutation. So `ITServiceOwner` can **write** role assignments but, after this fix, cannot **read** them. That breaks a legitimate group-admin workflow and creates an asymmetric posture.

**JIT elevation / break-glass / service-scoped tokens:** unaffected. JIT elevation grants `effective_role = admin` (`auth_routes.cpp:548-759`), which holds both permissions. Break-glass does not currently elevate RBAC permissions. Service-scoped tokens are capped at ITServiceOwner permissions, so consistent.

### 2. THE SAME SHAPE, A FOURTH TIME: Clean

Swept dashboard/HTMX fragments (`*_ui.cpp`, `settings_routes.cpp`), MCP tools (`mcp_server.cpp`), gRPC agent surface (`agent_service_impl.cpp`), SSE/event streams, metrics labels (`yuzu_scim_role_changes_total` — counts, not grants), audit log detail fields, error messages, and file/report exports.

- **No additional surface** exposes the full authorization-topology graph (principal→role→permission grid) outside the floored routes.
- `/api/v1/access-reviews/export` (`rest_api_v1.cpp:4832`) returns topology (roles, `effective_permission_count`), but it is **deliberately gated on `AccessReview:Read`** — a dedicated narrow securable seeded only to `Administrator` and `Reviewer` (`rbac_store.cpp:420+`). This is by-design SOC 2 evidence surface, not a floor bypass.
- **Axis is clean.**

### 3. THE INVERSE RISK: ITServiceOwner False Denial (MEDIUM)

Same finding as Axis 1, elevated to a distinct axis per your instructions.

- **ITServiceOwner within its own group:** Denied. An ITServiceOwner managing a group can no longer see who has what role in that group.
- **JIT-elevated operator:** No issue — elevation → admin → both permissions satisfied.
- **Break-glass account mid-incident:** No issue — break-glass does not currently grant extra RBAC permissions in the `perm_fn` path.
- **Legitimately scoped MCP token:** No issue — `discover_permissions` uses the probe-and-withhold pattern; the tool still returns the taxonomy half.

### 4. THE CACHE FIX: Missing `X-Yuzu-Token` in `Vary` (LOW)

`discover_routes.cpp:69` sets:
```cpp
res.set_header("Vary", "Authorization, Cookie");
```

The server authenticates via three mechanisms (`auth_routes.cpp:337-363`):
1. Session cookie → `Cookie` header
2. Bearer token → `Authorization` header
3. API token → `X-Yuzu-Token` header

`Vary` omits `X-Yuzu-Token`. `Cache-Control: private` prevents **shared** cache leaks, but a **caller-local** cache (browser, agentic worker HTTP client with a cache layer) keys only on `Authorization` and `Cookie`. Two different requests both using `X-Yuzu-Token` (with no `Authorization` and no `Cookie`) would have identical cache keys and could cross-pollute.

**Concrete trigger:**
- Request `/api/v1/discover/permissions` with `X-Yuzu-Token: token-A` → cached.
- Same client requests same route with `X-Yuzu-Token: token-B` → may receive token-A's cached permission grid (different caller, different grants).

**File:** `server/core/src/discover_routes.cpp:69`
**Tests to update:** `tests/unit/server/test_discovery_routes.cpp:272` and `:295` (assert `Vary` value).

---

### Recommendations

1. **ITServiceOwner GET parity:** Consider adding the same ITServiceOwner self-check fallback to the GET handler that POST/DELETE already use, OR document the intentional asymmetry. If deliberate, a code comment explaining why ITServiceOwner is excluded from reads would help future reviewers.

2. **Vary header:** Expand to `Vary: Authorization, Cookie, X-Yuzu-Token` on the two `DocAudience::PerCaller` discovery routes. Update the two `test_discovery_routes.cpp` assertions.
