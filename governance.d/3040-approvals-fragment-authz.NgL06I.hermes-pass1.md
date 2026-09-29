Warning: Unknown toolsets: messaging

session_id: 20260815_094414_8ae1ac
## Adversarial Review — Issue #3040 Approvals Fragment AuthZ Fix

**Scope**: One commit (`84505e8f`) on `fix/3040-approvals-fragment-authz`, diff vs `origin/dev`.

---

### Surfaces Enumerated (forced-browsing check)

| Surface | Location | Gate | Status |
|---|---|---|---|
| `GET /api/approvals` | server.cpp:13478 | `Approval:Read` | ✅ Gated |
| `GET /api/approvals/pending/count` | server.cpp:13512 | `Approval:Read` | ✅ Gated |
| `POST /api/approvals/{id}/approve` | server.cpp:13524 | `Approval:Approve` | ✅ Gated |
| `POST /api/approvals/{id}/reject` | server.cpp:13576 | `Approval:Approve` | ✅ Gated |
| `GET /fragments/approvals` | server.cpp:14031 | `Approval:Read` (NEW) | ✅ Gated |
| `GET /api/v1/approvals/{id}` | rest_api_v1.cpp:6226 | `Approval:Read` | ✅ Gated |
| MCP `list_pending_approvals` | mcp_server.cpp:5399 | `Approval:Read` via `perm_fn` + `tier_allows` | ✅ Gated |
| MCP `approve_request` / `reject_request` | mcp_server.cpp:7676 | `Approval:Approve` via `perm_fn` | ✅ Gated |

No residual ungated approvals-read surface found. The fix achieves sibling parity across all 8 discovered endpoints.

---

### Findings

#### 1. MCP Metadata Annotation Drift — Info (Non-exploitable, pre-existing)
**File**: `server/core/src/mcp_server.cpp:1534-1535`  
**Issue**: The static metadata table maps `approve_request` and `reject_request` to `{"Approval", "Write"}`, but the **enforced** operation in the handler (`mcp_server.cpp:7682`) and the REST routes (`server.cpp:13526,13578`) is `Approval:Approve`.  
**Impact**: Annotation-only drift. No bypass — the `perm_fn` call at line 7682 checks `Approval:Approve`, so enforcement is correct.  
**Fix**: Align the metadata table entry to `{"Approval", "Approve"}` to prevent future confusion.

#### 2. Governance Agents Missed the `HX-Trigger` Error-Path Information Leak — Medium
**File**: `server/core/src/server.cpp:13555-13562` (approve handler), mirrored at reject handler  
**Issue**: When `ApprovalManager::approve()` returns an error (e.g., self-review block, already approved, not found), the handler sets `HX-Trigger: showToast` with the raw `result.error()` string. While this is UX-necessary for the dashboard, the error message is attacker-controlled in one edge case: if the approval `id` parameter contains invalid UTF-8, the `nlohmann::json::error_handler_t::replace` fallback silently swaps bad bytes with U+FFFD, but the error path still leaks **that the approval id exists** (via the self-review denial message `"reviewer cannot be the same as the submitter"`).  
**Impact**: An attacker without `Approval:Approve` but **with** `Approval:Read` who knows an approval UUID can infer the `submitted_by` value by observing the self-review error vs "not found" error when attempting to approve.  
**Exploit**: This is NOT a bypass of the #3040 fix (the attacker already needs `Approval:Read`), but it is an **information oracle** within the data that `Approval:Read` legitimately grants.  
**Fix**: Consider making the self-review denial message generic (`"operation not permitted"`) or returning the same 403 envelope for all approval-action denials, regardless of reason.

#### 3. Missing `require_permission` on `GET /api/v1/approvals/{id}` Audit Trail — Info
**File**: `rest_api_v1.cpp:6260`  
**Issue**: The audit call `(void)audit_fn(req, "approval.read", ...)` is best-effort and explicitly documented as "not fail-closed." If the audit store is down, the read still succeeds.  
**Impact**: No security impact — the data is already gated by `Approval:Read` at line 6232. The audit gap is observability-only.

#### 4. The "Button Render" Is NOT a Bypass — Info (governance correctly rejected)
**File**: `server.cpp:14080-14092`  
**Analysis**: The fragment renders `Approve`/`Reject` buttons for pending approvals where `submitted_by != session->username`. A user with `Approval:Read` but NOT `Approval:Approve` sees these buttons.  
**Impact**: **Not a bypass.** Clicking the button fires `hx-post="/api/approvals/{id}/approve"`, which is gated on `Approval:Approve` at `server.cpp:13526`. The 403 response is swallowed by htmx (no toast unless explicitly handled), but the server correctly denies. The buttons are UI clutter, not a security vulnerability. Governance's rejection of this finding was correct.

#### 5. `event_bus_` Does NOT Carry Approval Data — N/A
**Analysis**: `emit_event("approval.approved", ...)` at line 13570 writes to the **analytics store** (`analytics_store_->emit`), NOT to the SSE `event_bus_`. The dashboard's `/events` SSE stream (`server.cpp:10892`) is subscribed to `event_bus_`, which only publishes `command-status` and `output` events. No approval data leaks via SSE.

---

### Verdict

**No exploitable vulnerability introduced or missed by this fix.** The `require_permission` gate at line 14041 correctly closes the fragment disclosure and achieves sibling parity with `GET /api/approvals`.

The only adversarial finding with any substance is the **self-review error oracle** (Finding 2, Medium), which is pre-existing and outside #3040 scope — it leaks `submitted_by` identity through error messages to `Approval:Read` holders who attempt forbidden actions. It does not represent an authz bypass.

**What I checked:**
- All REST endpoints registering on "approvals"
- MCP tool dispatch for approval-related tools
- Versioned REST v1 (`/api/v1/approvals/{id}`)
- SSE/EventBus paths for approval data leakage
- Error branches in both the fragment and REST handlers
- `require_permission` fail-closed semantics under RBAC-off
- Topology floor applicability to `Approval:Read`
