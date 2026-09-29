# PHASE 1 — independent static review (`kimi`)

Scope: `rest_api_v1.cpp` diff + `rest_audit.hpp` kernel + the three full handler bodies shown. Tests were omitted from CONTEXT; anything depending on them or on code outside the shown hunks is marked `not-verified`.

---

[K1] MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read)
REST JSON reads and the engine-session denial proceed on audit-persist failure with only the `Sec-Audit-Failed` header
- Location: rest_api_v1.cpp:2543 (`engine_principal.role.listed`), :3555 (`engine_principal.list`), :3623 (`engine_principal.get`), :4319 (`engine_principal.audit.no_admin` success), :251 (`deny_engine_session`)
- Claim: These REST JSON handlers discard the `emit_behavioral_audit` bool and serve 200/403 on a known audit-persist failure, so a header-blind downstream consumer records evidence-less data as audited.
- Evidence: `(void)detail::emit_behavioral_audit(audit_fn, req, res, "engine_principal.role.listed", "success", ...)` followed by `res.set_content(ok_json(arr.str()), ...)` with no status change; same shape at list/get/no_admin; denial path sets header then `res.status = 403`.
- Scenario: A CMDB/ServiceNow-style integration polls `GET /engine-principals` or the role-list read; the audit DB is locked; the read returns 200 + header; the integration (which does not parse `Sec-Audit-Failed`) treats the privilege-enumeration data as audited evidence — the same threat shape the helper's own doc cites as the originating #1623 HIGH.
- Inference: The orchestrator's anchor summary states the `emit_behavioral_audit` contract as "REST JSON fail closed (503) on audit-persist failure". The full header text scopes the fail-closed posture to behavioural-data PII routes and ADR-1005 scopes fail-closed to *mutations* ("a denial commits no mutation, so it does not fail closed" — the diff's own reasoning). Engine-principal list/get are RBAC/identity data, not per-person behavioural PII, so this is a posture choice, not a clear contract breach — but it is in tension with the compressed anchor and is undocumented as an exception.
- Anchor: judgment (ADR-1005 covers mutations only; rest_audit.hpp full text makes posture caller-selected, its summary line reads broader)
- Fix: Either fail closed (503) on the four REST JSON reads, or add an explicit note in `rest_audit.hpp` / `docs/auth-architecture.md` that engine-principal reads and denials are deliberately header-only, so the exception is contractual rather than accidental.

[K2] LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
Confirm fail-closed 503 message ("treat as unconfirmed and reconcile") is not actionable — the confirm cannot be re-driven
- Location: rest_api_v1.cpp:4093–4101
- Claim: The recovery guidance implies the operator can still confirm, but `confirm_rotation` consumed the pending successor (predecessor retired) and requires the raw secret + pending state, so a retry necessarily fails.
- Evidence: `token_store->confirm_rotation(...)` succeeded (we are past `if (!confirmed)`), then on audit failure the body says `"the rotation was confirmed but its audit record could not be persisted; treat as unconfirmed and reconcile"`.
- Scenario: Operator gets 503, follows the message, re-POSTs confirm with the same token_id+secret → store rejects (no pending rotation) → a second, confusing failure; the actual state is fully consistent (confirmed), only the audit row is missing.
- Inference: "Reconcile" is only achievable via GET/audit-log inspection, not via re-confirm; the mint/rotate messages by contrast name a working recovery (re-rotate re-serves the same successor).
- Anchor: judgment
- Fix: Reword to e.g. "the rotation was confirmed but its audit record could not be persisted; verify state via GET and reconcile the audit gap — do not re-confirm."

[K3] LOW · CONFIDENCE(lo) · PROVENANCE(static-read) · not-verified
`detail::a4_error(res, ...)` runs after `Sec-Audit-Failed` is set and takes `res` by non-const reference — header survival unverifiable
- Location: rest_api_v1.cpp:252–254 (deny), and every fail-closed 503 path (e.g., :3848–3856, :3937–3945)
- Claim: If `a4_error` mutates or clears response headers, the audit-failed signal set by `emit_behavioral_audit` would be dropped from exactly the responses that must carry it.
- Evidence: Call order is `(void)detail::emit_behavioral_audit(...)` (sets header) then `res.set_content(detail::a4_error(res, ...), ...)`; `a4_error` takes `res` as a parameter, implying it touches the response.
- Scenario: a4_error internally does `res.headers.clear()` or re-`set_header`s in a way that emplaces over the multimap → 503 body says "audit record could not be persisted" but the machine-readable header is gone.
- Inference: Unlikely (all pre-existing call sites use the same ordering and the helper is already relied on by PII routes), but `a4_error`'s source is not in CONTEXT.
- Anchor: judgment
- Fix: None if a4_error only builds the body; worth a one-line assertion in the [audit_failclose] tests that the header survives on the 503 body path (tests are described as asserting 503+header, which would catch this — not-verified).
- Falsifier: `a4_error` source shows no header mutation, or the described tests assert the header on these exact responses.

[K4] LOW · CONFIDENCE(med) · PROVENANCE(static-read) · not-verified
Mint 503 recovery text "revoke+re-mint" may be impossible: the only revoke route shown is principal-level, after which mint 409s
- Location: rest_api_v1.cpp:3848–3856 (mint fail-closed body); mint 409 guard at "engine principal is not active"
- Claim: The message advises "revoke+re-mint", but `engine_principal.revoke` revokes the principal, and the mint handler rejects non-active principals with 409 — so that recovery path requires a credential-level revoke that is not shown to exist.
- Evidence: Mint guard: `if ((*row_res)->lifecycle_state != "active") { res.status = 409; ... }`; the diff's only revoke route audits `engine_principal.revoke` ("the engine principal was revoked").
- Scenario: Audit failure persists; operator mints → 503 (orphan active credential, secret withheld); re-mint → 409 "already has an active credential"; follows the message's "revoke+re-mint" → principal revoked → mint now 409 "not active". Only "rotate" (the message's first option) actually recovers.
- Inference: If a credential-level revoke route exists elsewhere in the file the advice is fine; it is not in CONTEXT. The rotate-first ordering makes this a messaging inaccuracy, not a trap.
- Anchor: judgment
- Fix: Drop "revoke+re-mint" from the mint 503 body (rotate alone suffices), or point at the credential-level revoke route if one exists.

[K5] LOW · CONFIDENCE(med) · PROVENANCE(static-read)
`confirm_metric("success")` is incremented before the fail-closed audit check, so the counter records success alongside an HTTP 503
- Location: rest_api_v1.cpp:4088–4101
- Claim: `yuzu_engine_principal_confirm_total{surface="rest",result="success"}` fires even when the client receives 503 (audit not persisted), so metric-based success rates and HTTP-status-based alerting diverge.
- Evidence: `confirm_metric("success");` immediately precedes `if (!detail::emit_behavioral_audit(...)) { res.status = 503; ... }`.
- Scenario: Audit DB down → every confirm 503s while the success counter climbs; an operator alerting on 503 rate sees failures, one watching the metric sees 100% success.
- Inference: This matches the route's stated #2404 policy ("Increment BEFORE the audit emission so an audit-store failure cannot suppress the operational counter") written on the failure path — the metric deliberately counts store outcomes, not HTTP outcomes. Consistent design, but worth a doc line.
- Anchor: judgment
- Fix: None required; optionally document that `result="success"` means "store confirmed", independent of audit persist.

[K6] LOW · CONFIDENCE(med) · PROVENANCE(static-read)
`Sec-Audit-Failed: true` on the 403 engine-session denial discloses audit-subsystem health to a denied, least-trust caller
- Location: rest_api_v1.cpp:248–256 (`deny_engine_session`)
- Claim: An authenticated engine principal — by definition a caller this endpoint refuses to serve — now learns from every 403 whether the audit store is healthy.
- Evidence: `(void)detail::emit_behavioral_audit(...)` sets the header on failure, then `res.status = 403`; engine principals are default-deny/RBAC-only per ADR-1005, i.e., the most adversarial authenticated class on these routes.
- Scenario: A compromised engine token probes an admin endpoint; a `Sec-Audit-Failed` presence/absence oracle tells the attacker when audit persistence is down — i.e., when unaudited-activity windows exist on other surfaces that still proceed (HTML fragments, these reads).
- Inference: The same disclosure exists on 503s to Security:Write admins (acceptable) and is the deliberate header-signaling design; the marginal leak is extending it to the denied class. Low because the caller is authenticated and the information is coarse.
- Anchor: judgment
- Fix: Acceptable as-is; if unwanted, suppress the header on the denial path and rely on the server-side warn log/metric (`yuzu_server_audit_emit_failed_total`) for the denial case.

---

Notes on completeness (not findings):
- Every engine-principal *mutation success* path in the diff (role.assigned, role.unassigned, create, revoke, credential.mint, credential.reveal/rotate, credential.confirm, transfer_owner) is fail-closed 503 with the mutation-committed-but-unaudited message; argument order (action, result, target_type, target_id, detail) is preserved at every converted call site; the two secret-bearing routes withhold the secret on the 503 path and never place it in the body. I found no mechanical defect in the hunk rewrites (all added `return;`/`}` pairs balance against the removed trailing audit calls).
- Whether any *other* engine-principal mutation route exists in `rest_api_v1.cpp` outside the shown hunks (e.g., lifecycle activate/deactivate, update) and remains fail-open: `not-verified` — the CONTEXT contains only the changed hunks.
- Audit-off deployment (null `audit_fn`) still serves success on all these mutations per the `rest_audit.hpp` contract ("NOT a persistence failure"); that is anchor-blessed, not a finding.

VERDICT: PASS — the fail-closed conversion is mechanically correct, secret-withholding is sound, and all residual issues are MEDIUM/LOW judgment items around read/denial posture and recovery-message accuracy, none rising to an anchor-backed block.
COVERAGE: Deep — correctness/control-flow of every hunk (incl. `return`/`}` balancing), security (secret withholding, anti-oracle uniformity, info disclosure on 403/503), contract consistency vs ADR-1005 and the rest_audit.hpp kernel (null-audit, try/catch, header idempotence), cross-component claims (MCP-twin comments — consistent but `not-verified`). Skimmed — concurrency (no new shared state; audit_fn call pattern unchanged), portability (no platform-specific code), resource/lifetime (no ownership changes), test adequacy (test diff omitted from CONTEXT — flagged, not silently skipped).
FILES: Leaned on the full production diff (all hunks), the complete `rest_audit.hpp` kernel, and the full mint/rotate/confirm + `deny_engine_session` bodies; did NOT have `a4_error` source, any route outside the shown hunks, the MCP twin, or the [audit_failclose] tests — findings K3/K4 and the completeness note are gated on those.
