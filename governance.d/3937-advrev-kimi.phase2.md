## PHASE 2 — cross-examination (`kimi` static reviewer)

### 1. Cross-examination of codex's findings

| PEER-ID | Label | Evidence I checked (within my CONTEXT) | My severity |
|---|---|---|---|
| CDX-P1-001 (throwing audit_fn bypasses A4 envelope) | **confirmed-independently** (asymmetry) / **not-verified** (throw-ability premise) | Diff shows all 8 sites call `audit_fn(req, ...)` directly with no try/catch (e.g., :12100, :12350, :12709); the `mcp_audit` helper source I was given routes through `detail::try_persist_audit(audit_fn, ...)` — proving the kernel exists and that the codebase protects only the `mcp.*` rows, not the domain rows. What I cannot see: `rest_audit.hpp:61-89` and `audit_fn`'s definition, so "audit_fn can throw" rests on codex's read. | MEDIUM (agree) |
| CDX-P1-002 (kTools[] descriptions omit new behavior) | **not-verified** — severity adjudicated down | `kTools[]` registry (:976-1183, :1308-1359) is not in my bundle; I cannot check a single quoted description. Plausibility is high: my diff touches only handler bodies, and the orchestrator NOTE lists docs updated but not tool descriptions. | **LOW** (codex: MEDIUM) — adjudication below |
| CDX-P1-003 (stale set-and-proceed docs/comments) | **confirmed-independently** (sub-c, mechanism) / **not-verified** (sub-a, sub-b texts) | Sub-(c) mechanism is verifiable from my CONTEXT: `mcp_audit` calls `try_persist_audit(audit_fn, ...)` on the *same* `audit_fn`, so during an audit-store outage the `mcp.*\|error` row is exactly as unpersistable as the domain row — any doc claiming it "records the outcome server-side" overstates durability. Sub-(a): corroborated indirectly — the orchestrator NOTE lists docs/mcp-server.md, docs/user-manual/mcp.md, docs/auth-architecture.md as updated; `audit-log.md` is conspicuously absent. Sub-(b): comment block :11324-11339 not in my bundle. | MEDIUM (agree) |

**Adjudication of CDX-P1-001 (one refinement, not a rebuttal):** Codex correctly does *not* overclaim a security break, and I confirm why from the diff: at every site the `audit_fn` call precedes payload construction, so a throw still withholds the secret (mint/rotate) and never reports success — the ADR-1005 fail-closed *security* invariant survives a throw. What dies is the A4 envelope *shape* (503 + correlation_id + remediation + `audit_persisted:false`). So this is an A4-contract gap, not an ADR-1005 silent-success gap — MEDIUM is the right ceiling, and I note one falsifier codex didn't state: if `audit_fn`'s definition internally catches all exceptions (making it non-throwing), the finding collapses to a no-op; the proposed fix (route domain audits through the existing kernel) is harmless either way.

**Adjudication of CDX-P1-002 (severity disagreement):** The A4 503 envelope already carries the per-tool recovery instruction at the moment of failure — "do not retry the mint," "rotate again within the overlap window," "do not re-confirm" are all in the diff I can see. The agent is therefore not flying blind when it matters; what missing description text costs is *anticipatory* context, not recovery guidance. A5 item 2 makes codex's MEDIUM anchor-defensible, but the in-envelope remediation mitigates the actual harm to LOW in my grading.

### 2. Coverage adopt/rebut (no silence on codex's axes)

- **Test adequacy — adopted with a material caveat.** Codex's own RAN line undercuts its "reviewed deeply" claim empirically: `[audit_failclose]` ran **11/11 SKIPPED** (no `YUZU_TEST_POSTGRES_DSN`, Postgres unprovisionable). The new fail-closed tests are compiled but **unexecuted**; the empirical weight is "compiles + skips," not "passes." CI status is also UNKNOWN (no api.github.com). This keeps my K2 alive (below).
- **A1-A5 metadata / tool descriptions** — covered via CDX-P1-002; not-verified for me, adopted at reduced severity (K8).
- **Docs contracts** — adopt CDX-P1-003 (K7), mechanism verified, doc texts not-verified.
- **Resource/concurrency** — codex says net-neutral; **agrees-with-mine** (diff adds no shared state, threads, handles, or ownership transfers).
- **Cross-platform** — adopt codex's stronger grounding (ADR-0035, server Linux-only); consistent with my "pure string/JSON assembly" read.
- **Security/privilege, correctness** — both went deep; convergent, no conflict.

### 3. Defense of my own findings

- **K1 (completeness of the 8) — WITHDRAWN.** My stated falsifier is met: the orchestrator NOTE + codex's full-file pass confirm the 8 are the complete engine-principal mutation set.
- **K2 (mint/rotate remediation semantics) — STANDS, unchanged.** Codex neither confirms nor refutes it: the `[audit_failclose]` PG tests skipped, so rotate's auth requirement, overlap re-serve idempotency, and orphan-credential recovery were *not exercised empirically by either reviewer*. Codex read `docs/auth-engine-principals-design.md` and raised no contradiction — weak negative evidence only. This remains the one open correctness question on the security surface.
- **K3 (503 omits principal_id/token_id) — STANDS, unchanged.** Codex silent. Re-verified from the diff: create's success payload carries `created->principal_id`, mint's carries `token_id`; the `a4_error` data shape (helper source) carries only correlation_id/retry_after_ms/remediation/audit_persisted. Non-secret identifiers; their absence forces list-and-guess reconciliation.
- **K4 (mcp_audit("success") return discarded) — STANDS, unchanged.** Codex silent. Re-verified: helper returns `bool`, all 8 success-path call sites discard it. Cross-link: this is the success-path face of the same best-effort `mcp.*` invocation-row issue whose failure-path face codex documented in CDX-P1-003(c).
- **K5 (docs/tests drift) — WITHDRAWN as stated.** The orchestrator NOTE establishes the PR *did* update the three docs and add tests; my claim was an artifact of my cpp-only bundle. Its residual — the docs/comments that were *not* updated — survives via my adoption of CDX-P1-003 (K7).

### 4. Revised finding list

- **K1** — `withdrawn` (falsifier met).
- **K2** — `unchanged` — MEDIUM · lo · static-read · not-verified. Mint/rotate 503 remediation asserts rotate-by-principal and overlap re-serve semantics not shown in CONTEXT and not exercised by codex's skipped PG tests. Falsifier stands: rotate handler source showing principal-scoped auth + same-successor re-serve.
- **K3** — `unchanged` — LOW · hi · static-read. Create/mint 503 envelopes omit the committed record's non-secret identifiers (`principal_id`/`token_id`), forcing list-and-guess reconciliation. Fix: add the id to the error data on those two paths.
- **K4** — `unchanged` — LOW · med · static-read. `mcp_audit("success")` failure is silently swallowed on all 8 success paths; document fail-closed scope as domain-audit-only. Cross-linked with K7.
- **K5** — `withdrawn` (bundle artifact; residual adopted as K7).

**[K6] `new-from-cross-exam` (adopts CDX-P1-001)** MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read)
Throwing audit sink bypasses the promised A4 503 envelope on all 8 domain-audit calls
- Location: server/core/src/mcp_server.cpp:12100, 12168, 12350, 12598, 12708, 12839, 12958, 13416
- Claim: The domain `audit_fn(...)` calls are unprotected; only the `mcp.*` rows go through `try_persist_audit`, so a throwing sink escapes before the 503/A4 envelope is built.
- Evidence: Diff shows direct `audit_fn(req, ...)` calls at all 8 sites; the `mcp_audit` helper source wraps the same `audit_fn` in `detail::try_persist_audit` — the asymmetry is in my CONTEXT.
- Scenario: Mutation commits → audit sink throws (alloc failure, etc.) → caller gets whatever the dispatch layer does with exceptions, not the documented 503 + correlation_id + remediation + `audit_persisted:false`.
- Inference: The ADR-1005 security invariant survives (throw precedes payload construction — no success, no secret); this is an A4-envelope-contract violation. The premise "audit_fn can throw" is not-verified from my bundle; corroborated by the kernel's existence and purpose.
- Anchor: docs/agentic-first-principle.md A4/A5 (every failure response self-describing); docs/mcp-server.md fail-closed posture.
- Fix: Route the 8 domain audits through `detail::try_persist_audit` (one shared local helper), plus a throwing-AuditFn regression test — codex's fix is minimal and correct.

**[K7] `new-from-cross-exam` (adopts CDX-P1-003)** MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read)
Stale set-and-proceed authorities survive the contract flip; `mcp_audit("error")` durability overstated
- Location: docs/user-manual/audit-log.md:184 (not-verified); server/core/src/mcp_server.cpp:11324-11339 (not-verified); docs/mcp-server.md:163 (mechanism verified)
- Claim: Retained docs/comments still describe non-fatal `audit_persisted:false`-on-success and cite a now-converted handler as precedent, and the new posture text implies the `mcp.*|error` row is durably recorded when it cannot be during the outage.
- Evidence (verified portion): `mcp_audit` = `try_persist_audit(audit_fn, ...)` on the same sink → same failure domain as the row that just failed; best-effort only. Corroboration: orchestrator NOTE's updated-docs list omits audit-log.md.
- Scenario: A maintainer implements a sibling mutation from the stale comment's precedent → reintroduces set-and-proceed; an operator alerts on an `mcp.*|error` row that never persists.
- Anchor: ADR-1005 standing question (truthful audit behavior at the API); judgment for the doc-completeness portion.
- Fix: Update audit-log.md, rewrite the stale plugin-config comment, describe `mcp_audit("error")` as best-effort + out-of-band log/metric.

**[K8] `new-from-cross-exam` (adopts CDX-P1-002 at reduced severity)** LOW · CONFIDENCE(lo) · PROVENANCE(static-read) · **not-verified**
Served `kTools[]` descriptions reportedly omit the committed-but-unconfirmed / secret-withheld semantics
- Location: server/core/src/mcp_server.cpp:976-1183, 1308-1359 (not in my CONTEXT)
- Claim: If codex's quotes are accurate, agents cannot anticipate the audit-failure mode from `tools/list`; mitigated because the 503 envelope itself carries the exact per-tool recovery instruction (verified in the diff).
- Anchor: docs/agentic-first-principle.md A5 item 2 (codex reads it as MEDIUM; I grade LOW given the A4 in-envelope remediation).
- Fix: One clause per affected description naming the audit-failure outcome and safe recovery.

```
VERDICT:  PASS — no CRITICAL/HIGH from my side: the 8 converted sites correctly gate on the domain audit, withhold secrets, and emit the A4 503 with audit_persisted:false; all standing findings are MEDIUM/LOW, and the one empirical gap (unexecuted [audit_failclose] tests) is a confidence caveat, not a defect.
COVERAGE: deep on correctness/logic, security (secret-withholding, injection, envelope shape), cross-component contract consistency, and — via cross-exam — exception-safety of the audit path and docs/comment truthfulness; adopted codex's test-adequacy axis with the caveat that the new fail-closed tests skipped (no Postgres) and CI is unknown; concurrency/resource and portability remain net-neutral skims both reviewers agree on.
FILES:    the 8 diff hunks of server/core/src/mcp_server.cpp and the post-change a4_error/mcp_audit helper source (all I was given); for codex's claims I leaned on the helper source (K6/K7 mechanism verification) and the orchestrator NOTE (K1 falsifier, K5 withdrawal, audit-log.md corroboration) — kTools[], rest_audit.hpp, audit-log.md, and the :11324 comment block remain unseen by me.
```

**Delta since Phase 1 (4 lines):**
1. K1 withdrawn — falsifier met (orchestrator NOTE + codex full-file pass: the 8 are the complete mutation set).
2. K5 withdrawn as a bundle artifact (docs/tests *were* updated); its residual survives as adopted K7 (audit-log.md + stale source comment + `mcp_audit("error")` durability overstatement — mechanism verified from the helper source).
3. Adopted codex's throwing-audit gap (K6, MEDIUM, with the refinement that the security invariant survives a throw — it's an A4-shape gap) and the tool-description gap at reduced severity (K8, LOW — the 503 envelope already carries per-tool remediation).
4. K2 stands unopposed and unresolvable by either reviewer: codex's `[audit_failclose]` tests went 11/11 SKIPPED, so mint/rotate lifecycle semantics behind the new remediation text remain empirically unexercised; K3/K4 stand unmentioned by codex.
