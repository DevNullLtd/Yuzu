Warning: Unknown toolsets: messaging
I've read the full diff and traced every call site. Here are my findings, axis by axis.

---

### Axis 1 — Other topology-emitting surfaces outside the floor set

**Finding: `GET /api/v1/management-groups/{id}/roles` emits principal→role mappings under `ManagementGroup:Read`, which is outside the floor.**

**Severity:** MEDIUM  
**File:** `server/core/src/rest_api_v1.cpp:1961`

This route returns an array of `{group_id, principal_type, principal_id, role_name}` — the scoped role-assignment graph for a management group. That is authorization topology (who holds what role). It is gated on `perm_fn(req, res, "ManagementGroup", "Read")` which, with RBAC off, falls through to the legacy branch. `ManagementGroup:Read` is explicitly excluded from `kTopologyFloor` (`authz_topology_floor.hpp:30-34`). On a default install a plain `user` can enumerate every scoped role assignment in every group.

The exclusion rationale in the header — "`ManagementGroup:Read` was considered and excluded ... it is too coarse" — refers to the securable gating operational reads (group metadata, member lists), not to this specific sub-route that emits pure topology. This is exactly the same shape as the adversarial panel's `/discover/permissions` miss: the floor set was derived from securables, not from "which routes emit authorization topology."

**Concrete trigger:**
```bash
curl -H 'Cookie: yuzu_session=<plain_user_session>' \
     'http://server/api/v1/management-groups/any-group-id/roles'
```

**Verify:** On an RBAC-off install, compare:
- Admin session → 200 with role-assignment array
- Plain `user` session → also 200 with the same array (should be 403 if the floor covered it)

No other route, MCP tool, gRPC path, dashboard fragment, or background task that I could find emits topology under a securable outside the floor. The access-review surfaces are on `AccessReview:Read` (in floor). `/rbac/roles` and `/rbac/roles/{role}/permissions` are on `UserManagement:Read` (in floor). Engine-principal list/get/roles are on `EnginePrincipal:Read` (in floor). `discover_permissions` is split and probed correctly. The `audit/no-admin` evidentiary query is on `AuditLog:Read` — deliberately excluded by design, gated as read-only auditor surface.

---

### Axis 2 — Session/principal manipulation defeating the floor

**Clean axis.** No synthesis or credential-class trick bypasses the floor.

**Token synthesis:** `synthesize_token_session` (auth_routes.cpp:230) resolves human tokens via `get_user_role` (live, not cached at mint time). Engine tokens are rejected before the legacy branch: with RBAC off, `!rbac_store_->is_rbac_enabled()` → 403 (auth_routes.cpp:600). Engine sessions have no legacy authority.

**MCP tier:** Tier checks (`mcp::tier_allows`) run before the RBAC/legacy branch. A readonly tier can only reach Read operations, and the floor still intercepts floored Reads. Operator/supervised tiers can reach Writes, but Writes are already blocked by the legacy branch for non-admins. No tier provides a bypass around the floor string match.

**Service-scoped tokens:** Explicitly blocked when RBAC is disabled (`rbac_store_->is_rbac_enabled()` must be true, auth_routes.cpp:665-675). When RBAC is enabled, the floor is irrelevant.

**JIT elevation:** `is_elevated` short-circuits before the floor (auth_routes.cpp:580). An elevated session is treated as admin by design; this is the intended bypass path for a human operator who has already authenticated and stepped up. Not a defect.

**Break-glass:** The break-glass account gets whatever legacy role is stored in AuthDB for its username. If configured as `user`, the floor applies. If configured as `admin`, it bypasses by design.

**SSO/SCIM:** SCIM can change a user's persisted role (`recompute_scum_user_role`), but cookie sessions carry `session->role` fixed at login time. API tokens resolve fresh on every request, but `get_user_role` reflects the current DB state. A demoted admin's token would reflect `user` on the next request. No window where a live session has stale admin rights.

---

### Axis 3 — Timing/TOCTOU around `seed_defaults()`

**Clean axis.** No exploitable window.

The constructor sequence is:
1. `sqlite3_open_v2` → `db_` set
2. `create_tables()` → migrations
3. `seed_defaults()` → `INSERT OR IGNORE` for `EnginePrincipal` + grants
4. `load_enabled_flag()` → reads `enabled` into `rbac_enabled_`

`seed_defaults()` runs before `load_enabled_flag()`, so by the time the store reports RBAC off, the new securable is already seeded. Even if `seed_defaults()` silently fails (it does not check `sqlite3_prepare_v2`/`bind`/`step` return values), the floor is unaffected: `topology_floor_applies` matches by string literal, not by store lookup. With RBAC off, the legacy branch denies based on the string. With RBAC on, `check_permission` queries `role_permissions` directly; a missing `securable_types` row does not create false allows — it is fail-closed.

There is a non-security code-quality issue: `seed_defaults()` ignores SQLite errors, so a corrupt DB could leave `EnginePrincipal` unseeded. But this does not open an authorization window; it just means the RBAC-on path also denies `EnginePrincipal:Read` to everyone (no grants for a non-existent securable type), which is closed.

---

### Axis 4 — 403 denial path, audit row, information disclosure

**Clean axis.** No injection, oracle, or meaningful leak.

The `reason` string built at auth_routes.cpp:728-732:
```cpp
const std::string reason =
    (floored ? std::string("topology floor: non-admin role denied ")
             : std::string("non-admin role denied ")) +
    securable_type + ":" + operation +
    (session->mcp_tier.empty() ? "" : " (mcp_tier=" + session->mcp_tier + ")");
```

- `securable_type` and `operation` are **hardcoded by the route handler**, not user-controlled.
- `session->mcp_tier` is validated at token-creation time against the closed set `{readonly, operator, supervised}` (`mcp_policy.hpp:88`). An out-of-allowlist tier causes `validate_token` to reject the token before session synthesis.
- The `a4_denial` response body emits `permission = securable_type + ":" + operation` — also server-controlled.

An attacker can distinguish a floored Read (403 "admin role required") from a non-floored Read (200) on an RBAC-off install, but the floor set is public (documented in `authz_topology_floor.hpp`). No useful oracle is created. The audit `detail` field does not contain attacker-supplied strings.

One observation (not a finding): the `a4_denial` response for a floored denial says `"admin role required"` rather than `"permission denied: X:Y"`. A caller could notice that floored securables get a different message body than non-floored Writes. But the status code is the same (403), and the message shape is still A4-compliant. This is a minor UX consistency issue, not a security issue.

---

### Axis 5 — Cache-fix sufficiency

**Clean axis.** The fix is sufficient for the reported shared-cache leak.

The current headers for `discover_permissions` are:
```cpp
res.set_header("Cache-Control", "private, max-age=300");
res.set_header("Vary", "Authorization, Cookie");
```

- `private` prevents shared/intermediary caches from storing the response.
- `Vary: Authorization, Cookie` ensures per-credential cache keying for browser/private caches.
- The handler **re-runs the permission probe on every request** before the ETag check. If a user's grants change, `build_permissions_catalog` produces a different body and a different ETag. The `If-None-Match` comparison fails, and the server returns 200 with the updated body. There is no path where a shared cache serves a privileged representation to an unprivileged caller.

**Residual (not a finding, just context):** A standard HTTP `max-age=300` freshness window means a browser may serve its private cached copy for up to 5 minutes without revalidating. If an admin is demoted to `user` but keeps the same session cookie, their browser could show the full role grid for up to 5 minutes. This is generic HTTP cache semantics — the same staleness window affects every cached endpoint in the product — and it is bounded, private, and not cross-user. The adversarial panel's concern was cross-user shared-cache leakage, which is closed.

---

### Summary

| Axis | Finding | Severity |
|---|---|---|
| 1 | `GET /api/v1/management-groups/{id}/roles` emits topology under `ManagementGroup:Read` (outside floor) | **MEDIUM** |
| 2 | Clean — no session-synthesis bypass | — |
| 3 | Clean — no TOCTOU window | — |
| 4 | Clean — no log-injection or oracle | — |
| 5 | Clean — cache fix addresses the reported leak | — |

The one actionable finding is the management-group role-assignment GET. It is the same class of miss as the adversarial panel's two BLOCKs: a route that emits authorization topology gated on a securable that was excluded from the floor because the exclusion was based on the securable's other operational uses, not on the data shape of this specific sub-resource.
session_id: 20260806_102222_b37335

