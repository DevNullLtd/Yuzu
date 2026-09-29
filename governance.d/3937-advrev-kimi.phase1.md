## PHASE 1 — independent static review (`kimi`)

I read all 8 diff hunks against the `a4_error`/`mcp_audit` helper source provided. The transformation is mechanically uniform: domain `audit_fn` result checked immediately after the committed mutation; on failure, best-effort `mcp_audit("error", "audit_persist_failed")`, then a 503 `a4_error` with `audit_ok=false` (which appends `"audit_persisted":false` to the error data), then early `return` before any success payload is built. For mint and rotate I verified from the diff that the early return precedes `JObj payload` construction, so the comments' claim "the one-time secret is WITHHELD (never built into the response below)" is textually accurate. Argument order at every call site matches the `a4_error(code, message, remediation, retry_after_ms, cid_override, audit_ok)` signature. All messages/remediations are server literals; remediation is routed through `json_quoted_string`. No injection, no double-response, no fall-through.

---

[K1] MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read) · **not-verified**
Fail-closed coverage completeness across the MCP engine-principal mutation surface cannot be confirmed from the shown diff
- Location: server/core/src/mcp_server.cpp — 8 hunks shown (≈12099, 12167, 12350, 12597, 12709, 12841, 12957, 13415)
- Claim: If the MCP engine-principal surface has any other mutation handler (e.g., a principal update/metadata mutation or a single-credential revoke) that still does set-and-proceed, this PR leaves an ADR-1005 violation in place; the diff alone cannot prove the set is complete.
- Evidence: The provided CONTEXT contains only these 8 hunks of `mcp_server.cpp`; the rest of the file (the full tool registry) was not shown. The revoke hunk's `credentials_revoked` count implies credentials are individually enumerable, which *suggests* per-credential operations may exist elsewhere — observation of the diff text only.
- Scenario: A `engine_principal.credential.revoke` (or similar) MCP tool exists outside the shown hunks, still returns success with `audit_persisted:false` on audit failure → an unaudited revocation reports success → same gap ADR-1005 closed on REST #2466.
- Inference: I have no positive evidence such a handler exists; this is absence-of-evidence, not evidence-of-absence. `codex` can grep the full file and settle it empirically.
- Anchor: ADR-1005 'mutations fail closed on audit failure' (MCP engine surface) — blocking only *if* a missed mutation twin exists.
- Fix: Enumerate every MCP tool whose handler mutates engine-principal state and confirm each checks its domain `audit_fn` return; convert any straggler.
- Falsifier: A full-file listing showing the 8 converted handlers are the complete engine-principal mutation set.

[K2] MEDIUM · CONFIDENCE(lo) · PROVENANCE(static-read) · **not-verified**
Mint/rotate remediation text and comments assert rotation-lifecycle behaviors not shown in CONTEXT
- Location: server/core/src/mcp_server.cpp:12709–12724 (mint), 12841–12860 (rotate)
- Claim: The 503 guidance — mint: "list it and rotate it to obtain an audited secret"; rotate: "re-rotate re-serves the same successor once the audit persists" — is only correct if (a) rotate does not require possession of the orphaned credential's withheld raw secret, (b) re-rotate within overlap is idempotent (re-serves the same successor), and (c) overlap expiry without confirm cannot strand the principal with only a secret-less successor. None of these semantics are in the CONTEXT.
- Evidence: The comments themselves state the dependency: "the credential exists but is unusable: list it and rotate it" and "within the overlap window a re-rotate re-serves the same successor" — claims about code not included in the diff.
- Scenario: If rotate requires presenting the current raw token, the orphaned mint can never be rotated (nobody holds its secret) → remediation is impossible and the credential is permanently stranded; if re-rotate mints a *new* successor rather than re-serving, the rotate message misleads callers during an audit outage.
- Inference: The rotate audit detail (`"principal=" + principal_id + " action=rotate"`) hints rotation is principal-scoped rather than secret-possession-scoped, which would make the remediation viable — but that is inference from one string, not proof.
- Anchor: judgment (message accuracy), though a wrong "do this to recover" instruction on a security surface is operationally significant.
- Fix: Verify rotate's auth requirement and overlap re-serve semantics; if rotate needs the secret, change mint's remediation to "revoke the orphaned credential and mint a new one."
- Falsifier: The rotate handler source showing it authorizes by principal identity and re-serves the same successor within the overlap window.

[K3] LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
Fail-closed 503 envelopes omit the committed mutation's identifiers, forcing list-and-guess reconciliation
- Location: server/core/src/mcp_server.cpp:12350 (create — `principal_id` withheld), 12709 (mint — `token_id` withheld)
- Claim: On the create and mint failure paths the caller learns *that* something committed but not *which* record: the error data carries only `correlation_id`, `retry_after_ms`, `remediation`, `audit_persisted` — no `principal_id` / `token_id` — while the success payloads would have included exactly those fields.
- Evidence: Diff at create: success payload does `payload.add("principal_id", created->principal_id)`; the 503 `a4_error` data (per the helper source) contains only the four fields above. Same shape at mint (`token_id` only in the success payload).
- Scenario: Audit store drops the create row → caller gets 503 "reconcile via a read" → caller must list *all* engine principals and guess which one it created (by display_name/owner/timestamp); with `principal_id` in the error data the read would be deterministic. These identifiers are non-secret (they appear in success responses), so including them costs nothing in confidentiality.
- Inference: For an agentic-first API, machine-readable reconciliation identifiers matter more than prose; the correlation_id helps ops, not the caller.
- Anchor: judgment.
- Fix: Add `principal_id` (create) and `token_id` (mint) to the 503 error data on those two paths.

[K4] LOW · CONFIDENCE(med) · PROVENANCE(static-read)
Success path still silently ignores `mcp_audit("success")` failure
- Location: all 8 hunks (e.g., server/core/src/mcp_server.cpp:12372 `mcp_audit("success", principal_id);` — return discarded)
- Claim: After the domain audit persists, the MCP-invocation audit row (`"mcp." + tool_name`) is written best-effort; if that single row fails transiently, the mutation returns success with no invocation-level audit record and no signal to the caller.
- Evidence: `mcp_audit` returns `bool` (per the helper source) and every success-path call site discards it; only the domain `audit_fn` result gates the 503.
- Scenario: Transient single-row failure between the two writes → mutation committed, domain row exists, invocation row absent → an auditor correlating by tool name sees a gap with no `audit_persisted:false` marker anywhere.
- Inference: The domain mutation row — the record ADR-1005 is about — *does* exist in this scenario, and the same-store failure mode makes this window narrow; the plugin-config precedent likely shares this shape. Hence LOW, and whether ADR-1005's "audit" covers the invocation row is a judgment call.
- Anchor: judgment (ADR-1005 scope ambiguous re: invocation audit).
- Fix: Either document that fail-closed applies to the domain mutation audit only, or also surface a dropped `mcp_audit("success")` via `audit_persisted:false` on the success payload (the field the PR just removed — so documentation is the cheaper fix).

[K5] LOW · CONFIDENCE(med) · PROVENANCE(static-read) · **not-verified**
Contract/documentation drift: the `audit_persisted:false`-on-success signal is gone; docs and existing clients/tests are not in this diff
- Location: all 8 hunks (removed `payload["audit_persisted"] = false` / `payload.add("audit_persisted", false)` lines); production diff is `mcp_server.cpp` only
- Claim: Any client automation or test that handled the old success-with-`audit_persisted:false` contract now receives a 503 error envelope instead, and `docs/mcp-server.md`'s audit posture section (cited as an anchor) may still describe set-and-proceed for these tools — neither is updated or verifiable here.
- Evidence: The diff deletes the success-payload signal at 8 sites and the PR contains no docs or test changes ("PRODUCTION DIFF (server/core/src/mcp_server.cpp only)").
- Scenario: An agent that previously proceeded-with-warning on `audit_persisted:false` now sees an unexpected 503 error code path it never handled; or the docs still promise a success payload with a flag that can no longer appear.
- Inference: The breaking change itself is the anchored, intended behavior — this finding is only about the surrounding contract surface (docs, tests, client guidance) keeping pace.
- Anchor: judgment (the behavior change is anchored; the documentation drift is not).
- Fix: Update `docs/mcp-server.md` audit posture to state these 8 tools fail closed with 503 + `audit_persisted:false` in error data; confirm tests asserting the old flag were converted (not shown).

---

**Axes with no findings (stated, not silent):**
- **Security/injection:** clean. All 16 message/remediation strings are server literals; remediation goes through `json_quoted_string`; `cid` is server-minted; no caller-derived text reaches the envelope. Secret withholding verified textually (early return precedes payload construction at mint and rotate).
- **Concurrency/resource/lifetime:** no new shared state, captures, threads, or handles; the added blocks reuse the existing `[&]` lambdas. The doubled audit-write attempt on the failure path (`audit_fn` + `mcp_audit("error",…)`) is best-effort and bounded.
- **Cross-platform:** pure string/JSON assembly; nothing platform-specific.
- **Test adequacy:** not assessable — no tests were included in CONTEXT. I flag this explicitly rather than guess; `codex`'s empirical pass owns this axis.

```
VERDICT:  PASS — all 8 shown sites implement the anchored fail-closed semantics correctly (domain-audit gate, withheld secrets, audit_persisted:false on the 503 envelope); my findings are one not-verified completeness question (K1) and non-blocking MEDIUM/LOW observations.
COVERAGE: deep on correctness/logic, security (secret-withholding, injection, info disclosure), cross-component contract consistency (a4_error signature, envelope shape, REST-parity claims); skimmed concurrency/lifetime (no new state) and portability (nothing platform-specific); test adequacy and full-surface completeness (K1) explicitly deferred — they need the full file and test suite I was not given.
FILES:    leaned on all 8 diff hunks of server/core/src/mcp_server.cpp plus the post-change a4_error and mcp_audit helper source; nothing else was provided, which is exactly why K1/K2/K5 are not-verified.
```
