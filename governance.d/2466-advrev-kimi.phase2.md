# PHASE 2 — cross-examination (`kimi`)

## 1. Cross-examination of codex's findings

| PEER-ID | Label | Evidence I checked (file:line) | My severity |
|---|---|---|---|
| C1-LOW-1 | **not-verified** (changelog half) / code-side **confirmed-independently** | rest_api_v1.cpp rotate comment: "a re-rotate re-serves the SAME successor (an audited re-serve, not a new credential)" and 503 body: "re-serve the same audited successor secret" — both in my CONTEXT, both confirm the *implemented* behavior half of the claim. `changelog.d/2466-...security.md:7` and `rest-api.md:1134` are **not in my CONTEXT**, so the existence of the drift rests entirely on codex's quote of "rotate again for a fresh, audited credential" | LOW (agree, conditional on the quote being exact) |

Adversarial notes on C1:
- The scenario is mildly overstated: the re-served rotate response carries the **same successor `token_id`** (the handler looks it up structurally via `supersedes_token_id`), so an operator correlating `token_id` can detect that no new credential was issued. The drift is real if quoted accurately, but its blast radius is smaller than "operator records a new credential identity" implies. Severity unaffected — LOW is right.
- Codex's own standard here (recovery wording must match implemented behavior) is exactly the standard my K2 and K4 apply to the 503 bodies — which codex did not surface. More below.

Nothing else to cross-examine: codex produced one finding. Its empirical claims (compile+link PASS; `[rest][audit][helper]` 5 cases/12 assertions PASS; `[audit_failclose]` 6/6 SKIPPED on missing `YUZU_TEST_POSTGRES_DSN`) are outside my static reach but internally consistent, and I adopt them where noted.

## 2. Coverage — adopt or rebut

- **Security/privilege** — codex deep, I deep. No contradiction. But codex's deep pass did not surface my K6 (audit-health oracle on the 403 denial path). I maintain it; silence is not a falsifier.
- **Correctness/logic** — **adopt**. Codex's compile+link PASS empirically confirms my Phase-1 static completeness note (all added `return;`/`}` pairs balance; argument order preserved). My static read and its build agree.
- **Cross-component/schema/contract** — **adopt with caveat**. Codex read the MCP twin, `auth-architecture.md`, `rest-api.md`, and the changelog; I could not (not in CONTEXT). I adopt its testimony that the docs now carry the read-vs-mutation posture rationale — this is the basis for my K1 downgrade — flagged as codex-testimony, not my own read.
- **Test adequacy** — **partial rebut**. Codex went deep in *execution* but under-weighed its own result: the `[audit_failclose]` cases — the only tests asserting the anchored route-level behavior (503+header, secret-withheld, committed-state) — **skipped 6/6** in its run. The suite that actually ran (`[rest][audit][helper]`) covers the kernel, not the route fail-closed paths. Codex reported the skip in COVERAGE but let it inform neither a finding nor the verdict. I raise it as K7.
- **Resource/concurrency** — agree; the diff adds no shared state, ownership transfer, or threading primitive.
- **Portability** — agree with the skim; nothing platform-specific in the diff.

## 3. Defense of my Phase-1 findings

- **K1 (reads/denials header-only)** — *attacked by implication* (codex's PASS + its read of the new docs). The orchestrator's note confirms the diff added a read-vs-mutation rationale to `auth-architecture.md` + `rest-api.md`, which resolves my "undocumented exception" prong. **Severity-changed MEDIUM→LOW**, reframed to what survives: the four read sites still `(void)` the bool with no site-level comment, and `rest_audit.hpp`'s summary line ("REST JSON integrations FAIL CLOSED (503)") still reads broader than the actual posture. Not withdrawn — the in-code visibility gap is real and verifiable from my CONTEXT alone.
- **K2 (confirm 503 message not actionable)** — unaddressed by codex. Re-verified against the confirm handler: we are past `if (!confirmed)`, so `confirm_rotation` consumed the pending successor; a re-confirm with the same `token_id`+secret must fail (no pending rotation). "Treat as unconfirmed and reconcile" invites exactly that dead retry. Codex's C1 establishes wording accuracy as in-scope; K2 meets that standard. **Stands, LOW.**
- **K3 (`a4_error` header survival)** — codex read the full file and did not flag `a4_error` (weak exculpatory evidence), but the integration tests that would assert the header on these exact 503 responses **skipped** in codex's run, so my falsifier remains unmet on both prongs. **Stands, LOW/lo.**
- **K4 (mint "revoke+re-mint" dead advice)** — unaddressed. Codex read the whole file and did not surface a credential-level revoke route, but absence-of-finding ≠ falsifier. From my CONTEXT: mint 409s on any active credential and 409s on non-active principals; the only revoke shown is principal-level. **Stands, LOW, not-verified.**
- **K5 (`confirm_metric("success")` before the 503)** — unaddressed. Consistent with the route's stated #2404 increment-before-audit policy (metric counts store outcomes, not HTTP outcomes). **Stands, LOW.**
- **K6 (`Sec-Audit-Failed` on the 403)** — unaddressed. Sharpened on re-read: on this path the failed audit *is the denial record itself*, so the header tells the denied, least-trust caller two things — the audit store is down, **and this very probe left no audit row** (server-side warn log + `yuzu_server_audit_emit_failed_total` still fire, so defenders aren't blind). **Stands, LOW.**

## 4. Revised finding list

**[K1] LOW (severity-changed from MEDIUM) · CONFIDENCE(med) · PROVENANCE(static-read)**
Read/denial sites discard the emit bool with no site-level note; the helper's summary line reads broader than the actual posture
- Location: rest_api_v1.cpp:2543, :3555, :3623, :4319 (reads); :251 (denial)
- Claim: Four REST JSON reads and the 403 denial serve header-only on audit-persist failure; that posture is now documented in manuals (per orchestrator note + codex testimony), but the code sites carry no rationale comment and `rest_audit.hpp`'s summary ("REST JSON integrations FAIL CLOSED (503)") reads as if all REST JSON fails closed.
- Evidence: `(void)detail::emit_behavioral_audit(audit_fn, req, res, "engine_principal.role.listed", ...)` with no comment (contrast `deny_engine_session`, which gained an explicit posture comment in this diff); helper doc: "The caller then picks its posture … REST JSON integrations FAIL CLOSED (503)".
- Scenario: A future route author copies the `(void)emit_behavioral_audit(...)` pattern onto a route where fail-closed is required (or needlessly 503s a read), because the exception lives in manuals, not at the pattern's point of use.
- Inference: ADR-1005 anchors mutations-only; the helper scopes fail-closed to behavioural PII; engine-principal reads are identity/RBAC data — the posture itself is anchor-consistent; only its in-code visibility is thin.
- Anchor: judgment
- Fix: One-line comment at each read site ("read posture: header-only per the read-vs-mutation rationale") or a clarifying sentence in `rest_audit.hpp` that fail-closed applies to behavioural-data REST routes and committed mutations, not all REST JSON.

**[K2] LOW (unchanged) · CONFIDENCE(hi) · PROVENANCE(static-read)**
Confirm fail-closed 503 message is not actionable — the confirm cannot be re-driven
- Location: rest_api_v1.cpp:4093–4101
- Claim: "Treat as unconfirmed and reconcile" implies a re-confirm is possible, but `confirm_rotation` already consumed the pending successor; a retry necessarily fails.
- Evidence: The 503 fires only after `if (!confirmed)` passed; body text: "the rotation was confirmed but its audit record could not be persisted; treat as unconfirmed and reconcile".
- Scenario: Operator re-POSTs confirm with the same token_id+secret → store rejects (no pending rotation) → confusing second failure; actual state is fully consistent, only the audit row is missing.
- Inference: Unlike the mint/rotate messages, which name working recoveries, this one names none; reconciliation is only via GET/audit-log inspection.
- Anchor: judgment
- Fix: Reword to "…verify state via GET and reconcile the audit gap out-of-band — do not re-confirm."

**[K3] LOW (unchanged) · CONFIDENCE(lo) · PROVENANCE(static-read) · not-verified**
`detail::a4_error(res, ...)` runs after `Sec-Audit-Failed` is set and takes `res` by non-const reference — header survival unverifiable
- Location: rest_api_v1.cpp:252–254 and every fail-closed 503 path (e.g., :3848–3856, :3937–3945)
- Claim: If `a4_error` mutates response headers, the audit-failed signal is dropped from exactly the responses that must carry it.
- Evidence: Call order is `emit_behavioral_audit(...)` (sets header) then `res.set_content(detail::a4_error(res, ...), ...)`; `a4_error` takes `res`.
- Scenario: `a4_error` clears/rebuilds headers → 503 body says "audit record could not be persisted" but the machine-readable header is gone.
- Inference: Codex's full-file read without flagging `a4_error` is weak exculpatory evidence; however the `[audit_failclose]` tests that would assert the header on these responses skipped in codex's run, so neither prong of my falsifier has fired.
- Anchor: judgment
- Fix: None if `a4_error` only builds the body; ensure a header assertion on the 503 path executes in a DSN-backed CI job.
- Falsifier: `a4_error` source shows no header mutation, or an executed test asserts the header on these exact responses.

**[K4] LOW (unchanged) · CONFIDENCE(med) · PROVENANCE(static-read) · not-verified**
Mint 503 recovery text "revoke+re-mint" may be impossible: the only revoke route shown is principal-level, after which mint 409s
- Location: rest_api_v1.cpp:3848–3856; mint guards ("already has an active credential" 409; "engine principal is not active" 409)
- Claim: After a withheld-secret mint, the orphan credential is active (re-mint 409s) and principal-level revoke makes the principal non-active (mint 409s) — so "revoke+re-mint" is dead advice unless a credential-level revoke route exists.
- Evidence: Mint 503 body: "list it and rotate or revoke+re-mint to obtain an audited secret"; the diff's only revoke audits `engine_principal.revoke` ("the engine principal was revoked").
- Scenario: Persistent audit failure → mint 503 → operator follows "revoke+re-mint" → principal revoked → mint 409 "not active". Only rotate (the first option) actually recovers.
- Inference: Codex read the whole file and did not surface a credential-level revoke route, but that silence is not a falsifier.
- Anchor: judgment
- Fix: Drop "revoke+re-mint" from the mint 503 body, or point at the credential-level revoke route if one exists.
- Falsifier: a credential-level revoke route exists in `rest_api_v1.cpp`.

**[K5] LOW (unchanged) · CONFIDENCE(med) · PROVENANCE(static-read)**
`confirm_metric("success")` increments before the fail-closed audit check — counter records success alongside an HTTP 503
- Location: rest_api_v1.cpp:4088–4101
- Claim: `yuzu_engine_principal_confirm_total{result="success"}` fires even when the client receives 503, so metric-based and status-based views of the same operation diverge.
- Evidence: `confirm_metric("success");` immediately precedes `if (!detail::emit_behavioral_audit(...)) { res.status = 503; ... }`.
- Scenario: Audit DB down → every confirm 503s while the success counter climbs; one operator sees 100% failure, another 100% success.
- Inference: Matches the route's stated #2404 policy (metric counts store outcomes, not HTTP outcomes) — deliberate, but undocumented as such.
- Anchor: judgment
- Fix: None required; optionally document that `result="success"` means "store confirmed", independent of audit persist.

**[K6] LOW (unchanged) · CONFIDENCE(med) · PROVENANCE(static-read)**
`Sec-Audit-Failed: true` on the 403 engine-session denial discloses audit-subsystem health — and the probe's own unaudited status — to a denied caller
- Location: rest_api_v1.cpp:248–256 (`deny_engine_session`)
- Claim: An authenticated engine principal — the default-deny, least-trust class on these routes — learns from every 403 whether the audit store is healthy.
- Evidence: `(void)detail::emit_behavioral_audit(...)` sets the header on failure, then `res.status = 403`; on this path the failed audit *is* the denial record.
- Scenario: A compromised engine token probes an admin endpoint; header presence tells the attacker both that audit persistence is down (unaudited windows exist on surfaces that proceed — HTML fragments, these reads) and that this specific probe left no audit row.
- Inference: Server-side warn log + `yuzu_server_audit_emit_failed_total` still fire, so defenders aren't blind; the marginal leak is extending the signal to the denied class. Coarse, authenticated-only — LOW.
- Anchor: judgment
- Fix: Acceptable as-is; if unwanted, suppress the header on the denial path and rely on the server-side log/metric.

**[K7] LOW (new-from-cross-exam) · CONFIDENCE(med) · PROVENANCE(static-read — adopting codex's empirical run)**
The route-level `[audit_failclose]` tests skip without a live Postgres DSN — the anchored fail-closed contract may have zero executed coverage
- Location: test suite (not in my CONTEXT); codex run: `yuzu_server_tests '[audit_failclose]'` → 6/6 SKIPPED, exit 4, `YUZU_TEST_POSTGRES_DSN` unset
- Claim: The only tests asserting the new route-level behavior (503+header, secret-withheld, committed-state) are Postgres-gated; in any DSN-less environment they skip silently, leaving the ADR-1005 contract enforced only by static review and kernel-level helper tests.
- Evidence: Codex's reported 6/6 skip; the suite that did run (`[rest][audit][helper]`, 5 cases/12 assertions PASS) covers `try_persist_audit`/`emit_behavioral_audit`, not the route fail-closed paths.
- Scenario: CI lacks the DSN → a future regression dropping the 503/`return` on the mint path compiles, helper tests pass, integration tests skip → a fail-open mutation ships undetected.
- Inference: Whether CI sets the DSN is unknown (codex: "CI status … not checked"); if a Postgres-backed job runs these, the concern evaporates.
- Anchor: judgment (test adequacy for ADR-1005's fail-closed contract)
- Fix: Confirm a CI job exports `YUZU_TEST_POSTGRES_DSN` and runs `[audit_failclose]`; if none exists, add a DSN-free route-level test with a false-returning fake `AuditFn` (the helper tests demonstrate the pattern) — not-verified whether the route harness can run without Postgres.

**[K8] LOW (new-from-cross-exam — adopted from codex C1) · CONFIDENCE(med) · PROVENANCE(static-read; changelog half not-verified)**
Changelog promises a "fresh" credential where rotate recovery re-serves the same successor secret
- Location: `changelog.d/2466-engine-principal-rest-audit-failclose.security.md:7` (not in my CONTEXT); rest_api_v1.cpp rotate comment + 503 body (verified)
- Claim: If the changelog reads "rotate again for a fresh, audited credential", it contradicts the implemented and manual-documented recovery, which re-serves the SAME successor secret.
- Evidence (verified half): route comment "a re-rotate re-serves the SAME successor (an audited re-serve, not a new credential)"; 503 body "re-serve the same audited successor secret".
- Scenario: Operator treats the first successor as rotated-away and mis-records the returned bytes as a newly issued credential — mitigated by the re-served response carrying the same successor `token_id`.
- Inference: Documentation drift only; no control bypass.
- Anchor: judgment
- Fix: Reword the changelog to "re-serve the same successor under a successfully persisted reveal audit."

---

VERDICT: **PASS** — the fail-closed conversion is mechanically correct (now also empirically: compiles, links, kernel tests pass), secret-withholding is sound, and every residual finding is LOW judgment around recovery-message accuracy, in-code posture visibility, a denied-caller information leak, and executed-test coverage.

COVERAGE: Deep — cross-exam of codex's single finding (code half verified, changelog half not-verified), defense of all six Phase-1 findings against codex's PASS, adoption of codex's compile/test evidence, and a partial rebuttal of its test-adequacy axis (the 6/6 skip it reported but didn't weigh → K7). Skimmed — portability and concurrency (nothing platform- or thread-specific in the diff; codex's GCC-only build noted). Not possible — independent verification of the changelog, manuals, MCP twin, `a4_error`, and any route outside the shown hunks; all findings gated on those are marked not-verified.

FILES: Leaned on the full production diff, the complete `rest_audit.hpp` kernel, and the full mint/rotate/confirm + `deny_engine_session` bodies (all in my CONTEXT); for codex's claims I could only check the rest_api_v1.cpp halves — `changelog.d/...`, `rest-api.md`, `auth-architecture.md`, `mcp_server.cpp`, and both test files were never in my bundle.

DELTA-SINCE-PHASE-1: K1 downgraded MEDIUM→LOW — the read-vs-mutation rationale added to `auth-architecture.md`/`rest-api.md` (orchestrator note + codex testimony) resolves the "undocumented exception" prong; the residue is site-comment absence plus the helper's over-broad summary line. K2–K6 unchanged; codex confirmed none and refuted none, and K3's falsifier stays unmet because the header-asserting integration tests skipped. New from cross-exam: K7 (codex's own 6/6 `[audit_failclose]` skip means the anchored route-level behavior had zero executed test coverage in its run — reported by codex, weighed by me) and K8 (codex's C1 changelog wording drift, adopted; code side verified, changelog not in my CONTEXT). Codex's compile+link PASS empirically closes my Phase-1 mechanical-correctness note. Verdict unchanged: PASS.
