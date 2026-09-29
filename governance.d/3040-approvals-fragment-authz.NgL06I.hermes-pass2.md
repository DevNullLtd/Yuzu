Warning: Unknown toolsets: messaging

session_id: 20260815_095147_32c790
## Adversarial Review — #3040 Approvals Fragment AuthZ

**Verdict: No exploitable findings.** The fix achieves true sibling parity and closes the disclosure gap without introducing new bypasses, oracles, or fail-open degrade paths.

Checked surfaces (all gated on `Approval:Read` unless noted):
- `GET /fragments/approvals` — fixed, now gates `Approval:Read` (server.cpp:14041)
- `GET /api/approvals` — pre-existing gate `Approval:Read` (server.cpp:13480)
- `GET /api/approvals/pending/count` — pre-existing gate `Approval:Read` (server.cpp:13514)
- `GET /api/v1/approvals/{id}` — pre-existing gate `Approval:Read` (rest_api_v1.cpp:6232)
- MCP `list_pending_approvals` — pre-existing gate `Approval:Read` via `perm_fn` (mcp_server.cpp:5407)
- MCP `approve_request`/`reject_request` — gate `Approval:Approve` (mcp_server.cpp:7682)
- SSE `/events`, `/api/v1/events` — generic bus, no approval-data broadcast
- Dashboard `instruction_ui.cpp` tab markup — lazy-loads via `hx-get="/fragments/approvals"`, no inline data

### Detailed Pass-2 Analysis

#### (a) 403-vs-200/302 response oracle
The fragment now returns:
- **401** — unauthenticated (set by `require_auth`)
- **403** — authenticated but lacks `Approval:Read` (set by `require_permission`)
- **200 + "Not available"** — authenticated, holds `Approval:Read`, but `approval_manager_` is null
- **200 + table/empty-state** — authenticated, holds `Approval:Read`, manager live

This creates a 200-vs-403 oracle for "caller holds Approval:Read", but this oracle is **identical on every permission-gated route in the system** (e.g. `/api/agents`, `/api/inventory/tables`, `/fragments/results`). No differential timing: both `require_auth` and `require_permission` resolve the session from cookie/token without DB round-trips for the auth path; the RBAC `check_permission` may query the store, but that query is shared by the REST twin and every other gated endpoint. The fix does not introduce a new enumeration surface.

#### (b) API token / MCP principal / engine principal reachability
- **Browser cookie session**: standard path. Gated by `require_auth` → `require_permission("Approval","Read")`.
- **API token (Bearer / X-Yuzu-Token)**: resolved by the same `require_auth` path. `require_permission` checks RBAC/legacy identically. No weaker gate.
- **MCP principal**: `require_permission` enforces the MCP tier policy first (`mcp::tier_allows`), then falls through to the creator's RBAC role. The tier check for Approval:Read is enforced on ALL transports. An MCP token cannot reach the fragment with a weaker gate than the REST/MCP tool surfaces.
- **Engine principal**: `require_permission` has a dedicated engine branch (auth_routes.cpp:593). Engine principals have **zero legacy authority**; they are denied outright if RBAC is off or the store is unavailable (503). When RBAC is on, they need an explicit grant. This is **stricter** than browser sessions under RBAC-off.

#### (c) Does `require_permission` fail OPEN on degrade?
Tracing the degrade paths:
1. **`rbac_store_` is nullptr (fresh install)**: `rbac_enforcement_in_effect` is never called; falls through to legacy fallback where Read is allowed for non-floored securables. **This is pre-existing/system-wide/by-design**, not introduced by #3040. The REST twin behaves identically.
2. **`rbac_store_` truthy but `!is_open()` (corrupted/load-failed)**: `rbac_enforcement_in_effect` returns `true` → enters RBAC block → `check_permission` returns `false` → **403, fail CLOSED**.
3. **Store open but stale/degraded view**: `rbac_enforcement_in_effect` returns `store->rbac_enabled_view_degraded()` which returns `true` on degrade → **fail CLOSED**.
4. **Engine principal + unavailable store**: explicit 503 → **fail CLOSED**.
5. **Service-scoped token + RBAC off**: explicit 403 → **fail CLOSED**.

The only "open" path is the null-store fresh-install legacy fallback, which is universal and accepted per ADR-0017 / #1717.

### Button Render Case
The Approve/Reject buttons are rendered inside the fragment **after** the `Approval:Read` gate. A caller lacking `Approval:Read` never reaches the HTML generation. A caller with `Approval:Read` (e.g. Viewer role) sees the buttons for all non-self pending approvals, but clicking them POSTs to `/api/approvals/{id}/approve|reject`, which gates on `Approval:Approve`. This is **disclosure-of-existence only**, not a bypass. The server-side `ApprovalManager::approve` additionally enforces reviewer≠submitter.

### Governance Misses
I find nothing the 7 governance agents + architect missed on the security question. The one pre-existing annotation drift they caught (MCP metadata table labels approve/reject as `Approval:Write` while enforcement uses `Approval:Approve`) is correctly filed as non-exploitable.
