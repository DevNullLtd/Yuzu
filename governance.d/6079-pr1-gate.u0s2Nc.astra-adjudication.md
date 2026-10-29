# Astra (gpt-6-astra) adjudication of five open BLOCKING-band rows, PR 1 of #6079

Run 2026-10-28, codex skill opine mode (read-only), reasoning high, tree HEAD bf246be94 vs origin/dev 73369c123. Opinion text verbatim below; the brief it answered is appended after it.

---

Reviewed HEAD `bf246be9475186c15e816ee3e865014a2a66ed39` against `origin/dev` at `73369c123406775714cb04cf82d186cb4fd3fd64`. The merge-base is `fde3564da412401b2585f3750ff11e49f3e6f378`. All conclusions below are from code inspection, not runtime reproduction.

## UP-2

**Verdict: ACCEPT-AS-RESIDUAL. HIGH, but not a regression or a reason to block PR 1.**

The attack works under the stated conditions. Settings init requires the administrator session and the same-site write check, but no password or existing MFA proof. Verify accepts the newly enrolled factor and stamps that cookie session. A client possessing the cookie can supply the required Origin header.

Deciding HEAD locations:

- [settings_routes.cpp:6755](/home/dgr/yuzu-6079-pr1/server/core/src/settings_routes.cpp:6755): init authenticates the administrator and passes `std::nullopt` for the proven password hash.
- [settings_routes.cpp:6840](/home/dgr/yuzu-6079-pr1/server/core/src/settings_routes.cpp:6840): enrollment verification likewise requires no password re-proof.
- [settings_routes.cpp:6946](/home/dgr/yuzu-6079-pr1/server/core/src/settings_routes.cpp:6946): successful verification stamps the matching local cookie session.
- [mfa_step_up.cpp:241](/home/dgr/yuzu-6079-pr1/server/core/src/mfa_step_up.cpp:241): enrolled, fresh, non-predating proof passes.

**Provenance: pre-existing, with exposure narrowed by PR 1.** Those enrollment and stamping paths already exist at `origin/dev:server/core/src/settings_routes.cpp:6755`, `:6840` and `:6946`. More decisively, baseline approvals call only the generic gate at `origin/dev:server/core/src/approval_routes.cpp:118`; that gate passes an unenrolled local account at `origin/dev:server/core/src/step_up_gate.cpp:325`, and passes when the window is disabled at `:289`.

Previously, the stolen unenrolled administrator cookie could approve directly. PR 1 makes it enroll and prove a factor first. This adds friction and evidence, but does not establish that the legitimate account owner enrolled the factor. An already-enrolled victim presents a different obstacle: init refuses replacement of an enrolled factor.

**Derivation:** trigger = stolen cookie for an unenrolled administrator, optional enforcement, attacker completes enrollment; impact = **I1**, failure of independence from session possession; exposure = **E3**, starting with administrator session authority, not a lower-privilege escalation; epistemic status = **likely**; band = **HIGH**.

**Before push:** no code change required for this row. Password re-proof for enrollment is a separate hardening task. Keep the disclosed limitation at `docs/enterprise-readiness-soc2-first-customer.md:509`.

## UP-4-enforced

**Verdict: ACCEPT-AS-RESIDUAL. The enforced-mode loop is real and pre-existing; the current documentation is sufficient for this PR’s scope.**

At [auth.cpp:558](/home/dgr/yuzu-6079-pr1/server/core/src/auth.cpp:558), a proof later than DB now produces an empty monotonic anchor. Under protected OIDC enforcement, [step_up_gate.cpp:341](/home/dgr/yuzu-6079-pr1/server/core/src/step_up_gate.cpp:341) does not take the no-proof exemption and reaches the challenge at `:363`.

The generic check precedes the new check. The handler also preserves that ordering at [approval_routes.cpp:191](/home/dgr/yuzu-6079-pr1/server/core/src/approval_routes.cpp:191). Consequently, the new skew branch at `mfa_step_up.cpp:176` and its response at `approval_routes.cpp:225` are unreachable for this request.

“Cannot clear” needs qualification: repeating sign-in while the clock condition persists does not cure it. Correcting the clocks and obtaining/re-deriving a usable proof can restore access. It is not an irreversible ticket state.

**Provenance: pre-existing.** The same proof-dropping code is at `origin/dev:server/core/src/auth.cpp:558`; the same enforced OIDC decision is at `origin/dev:server/core/src/step_up_gate.cpp:340`, ending in the challenge at `:362`. Baseline approval handling already calls that gate first at `origin/dev:server/core/src/approval_routes.cpp:118`. PR 1 changes audit-detail sanitization in `step_up_gate.cpp`, not this decision logic.

The runbook explicitly distinguishes the enforced-mode repeating `401`, absence of approval skew rows, the generic refusal metric, and clock synchronization at [auth-db-recovery.md:1197](/home/dgr/yuzu-6079-pr1/docs/ops-runbooks/auth-db-recovery.md:1197). The architecture description does the same at `docs/auth-architecture.md:963`. These are diagnostic instructions, not evidence that a skewed deployment was tested.

**Derivation:** trigger = protected OIDC role, positive window, future-dated stored proof and continuing skew during reauthentication; impact = **I5**, with **HIGH** under the rubric’s looping/wedged state-machine clause; exposure = **E4 + E5**; epistemic status = **likely**. I do **not** retain I4 against the corrected documentation.

**Before push:** no generic-gate redesign required for this row. Carrying the skew reason through the generic gate would improve recovery, but PR 1 neither creates nor broadens this enforced-mode failure.

## UP-5bc

**Verdict: ACCEPT-AS-RESIDUAL. Both mechanisms have identifiable paths and triggers; replace “speculative” with “likely.”**

**(b) Lossy standby promotion.** A concrete trigger is promotion of a standby whose replay position includes the original enrolled factor and session proof, but excludes the later factor clear and session deletion. A restarted server can load that restored session through `SessionStore::find` and `validate_session_durable`. If its proof remains within the effective window, the restored factor and proof satisfy the new gate.

Deciding HEAD locations are [session_store.cpp:416](/home/dgr/yuzu-6079-pr1/server/core/src/session_store.cpp:416), `auth.cpp:1738`, and `mfa_step_up.cpp:220`. There is no independent record outside that restored database which tells this gate that the factor or session was revoked.

**(c) Clock rollback with a surviving session.** A concrete sequence is:

1. Session S earns an old-factor proof at DB time P.
2. The factor clear commits, but session deletion fails or the process dies before it.
3. DB time moves below P. Another session completes enrollment of a replacement factor at E, where E < P.
4. After DB time reaches P again, S is loaded or its cached proof is re-derived. Both proof-age checks can pass, while `P < E` is false.

The separate clear/delete operations are at [settings_routes.cpp:7119](/home/dgr/yuzu-6079-pr1/server/core/src/settings_routes.cpp:7119) and `:7154`; failed deletion leaves durable rows intact through `auth.cpp:1903`. Enrollment uses DB `now()` at `auth_db.cpp:1836`. The deciding comparison is [mfa_step_up.cpp:238](/home/dgr/yuzu-6079-pr1/server/core/src/mfa_step_up.cpp:238).

Two qualifications matter: the surviving session must retain its old proof rather than receive the new enrollment stamp, and an anchor dropped while P was future-dated needs re-derivation. The sequence above supplies both. Acceptance lasts only while both freshness checks pass.

**Provenance: pre-existing security exposure, narrowed by PR 1.** Baseline Settings disable cleared the factor without ending sessions at `origin/dev:server/core/src/settings_routes.cpp:7068`. Baseline enrollment already used `now()` at `origin/dev:server/core/src/auth_db.cpp:1834`; durable session loading already existed at `origin/dev:server/core/src/session_store.cpp:416`. Baseline approvals had neither current-factor enforcement nor the enrollment-order comparison.

PR 1 introduces the timestamp comparison as an additional defense, but does not introduce the ability to reuse surviving session authority. Successful session deletion now removes that route entirely.

The residual is disclosed: SOC 2 residual (b) names restore/lagging-standby limits at `docs/enterprise-readiness-soc2-first-customer.md:485`, and the backward-clock assumption at `:489`. `docs/auth-architecture.md:1059` states the same assumption. These disclosures do not prevent either outcome.

**Derivation:** trigger = the sequences above; impact = **I1**, plus **I2** for lost committed state in (b); exposure = **E4 + E5** for asynchronous promotion, **E5** for the partial-failure/clock-rollback sequence; epistemic status = **likely**; band = **HIGH** for both.

**Before push:** no PR 2 implementation required. Record these concrete investigations and correct the speculative status. Factor-generation binding addresses a different guarantee; a generation restored along with the entire database would not itself solve lossy promotion.

## UP-9

**Verdict: RESTATE. The technical exposure is a pre-existing HIGH residual; the unsupported acceptance claim needs resolution before push.**

An old replica applies its old rules. It has no new enrolled-factor gate, its Settings disable does not revoke sessions, and its approval audit detail lacks the new marker.

**Provenance:** the weaker behavior is proven by `origin/dev:server/core/src/approval_routes.cpp:118` and `:164`, and `origin/dev:server/core/src/settings_routes.cpp:7068`. PR 1 introduces enforcement differences during coexistence and introduces the specific acceptance claims; it does not weaken the old binary.

At HEAD, [approval_routes.cpp:200](/home/dgr/yuzu-6079-pr1/server/core/src/approval_routes.cpp:200) applies the new gate, and `:309` and `:323` write its assurance marker. [upgrading.md:942](/home/dgr/yuzu-6079-pr1/docs/user-manual/upgrading.md:942) accurately warns about weaker old replicas and recommends stop-all/upgrade/start-all or exclusive routing to upgraded replicas.

The unsupported-operation claim is substantiated by [ha-delivery-matrix.md:44](/home/dgr/yuzu-6079-pr1/docs/ha-delivery-matrix.md:44), including the explicit statement that the gate is not lifted. The same restriction exists at `origin/dev:docs/ha-delivery-matrix.md:44`.

I found assertions of acceptance at `docs/user-manual/upgrading.md:1002` and `docs/enterprise-readiness-soc2-first-customer.md:515`, but no independently attributable acceptance artifact in the searched repository material. **ADR-1005’s 2026-10-19 addendum concerns distinct human identities, not mixed-version admission** (`docs/adr/1005-headless-platform-use-case-engines.md:760`). I did not inspect external issue comments.

**Derivation:** trigger = approval traffic reaches an old replica during mixed-version operation; impact = **I1**; exposure = **E4**, with unsupported operation not qualifying for E6; epistemic status = **likely**; band = **HIGH**. The missing acceptance evidence is separate from that technical severity.

**Before push:** no minimum-version protocol is required merely to support a deployment mode the project already forbids. However, the maintainer must either substantiate the acceptance claim or remove it.

Any of these would be adequate:

- A maintainer-approved ADR-1005 exception block.
- A maintainer-approved SOC 2 risk-register entry.
- An explicit maintainer-authored #6079 comment, linked from the repository.

The record should identify the acceptor, actual decision date, exact risk and scope, rollout conditions, residual exposure, and revisit condition. Replica timestamps and load-balancer logs are operational evidence, not acceptance. I cannot supply the maintainer’s decision or validate the claimed historical date.

## UP-14

**Verdict: RESTATE to MEDIUM, I5, E5, likely. The structure is pre-existing; the claimed I3 is not established.**

The production binding is `server.cpp:16041` through `server.cpp:14127` to `AuthRoutes::audit_log`. Ordinary store failures do **not** throw: [audit_store.cpp:418](/home/dgr/yuzu-6079-pr1/server/core/src/audit_store.cpp:418) returns `false` for closed/unavailable storage, and `:477` returns `false` for INSERT failure.

Nevertheless, **the complete production callback can throw beyond allocation failure**. Audit attribution calls `make_audit_event`, which re-resolves the session at `auth_routes.cpp:1604`. That reaches token hashing through `auth.cpp:1721` and `:459`. [auth.cpp:2677](/home/dgr/yuzu-6079-pr1/server/core/src/auth.cpp:2677) explicitly throws when an EVP digest operation fails; Windows has analogous BCrypt failure branches.

The candidate trigger must be a failure on the post-commit resolution after earlier resolutions and the attempted audit succeeded. A persistently throwing callback would instead be caught by the guarded attempted audit and prevent mutation. I identified the exception path; I did not reproduce a non-allocation crypto failure occurring at that precise point.

At [approval_routes.cpp:323](/home/dgr/yuzu-6079-pr1/server/core/src/approval_routes.cpp:323), the success audit has no local guard. A throw skips event emission and normal success rendering. `write_denied` at `:270` is also unguarded, but it runs when the manager returns an error, not after a successful manager result. The guarded helper at `:309` protects only that earlier audit call.

A subsequent retry, assuming authentication and audit recover, encounters `approval already reviewed` at `approval_manager.cpp:1765`.

**Provenance: pre-existing.** Baseline has the same raw denied audit at `origin/dev:server/core/src/approval_routes.cpp:147`, raw success audit at `:164`, and event emission afterward at `:166`. The attribution path exists at `origin/dev:server/core/src/auth_routes.cpp:1604`; the EVP throw exists at `origin/dev:server/core/src/auth.cpp:2651`.

**Derivation:** trigger = transient post-commit callback exception; impact = **I5**, request failure and missed completion notification; exposure = **E5**; epistemic status = **likely**; band = **MEDIUM**. A failed response with ambiguous completion is not a result presented as successful and correct, so I3 is inappropriate. The durable attempted audit and committed ticket also mean this is not a wholly unaudited approval.

**Before push:** no mandatory change for this row. Guarding completion-side audit calls is sensible follow-up hardening.

## Also

**Additional CRITICAL or HIGH defects: none found in the inspected PR 1 changes.** This is not a governance result or a claim of merge readiness.

I ran only read-only Git, search, numbered-source reads, and a Python text search. No builds, tests, fault injection, database queries, network calls, or file modifications were performed.

Files inspected, as relevant excerpts or diff hunks:

- Core implementation: `approval_routes.{cpp,hpp}`, `approver_assurance.hpp`, `mfa_step_up.{cpp,hpp}`, `mfa_factor_state.hpp`, `step_up_gate.cpp`, `step_up_policy.hpp`, `auth.cpp`, `auth_db.cpp`, `auth_routes.cpp`, `session_store.cpp`, `settings_routes.{cpp,hpp}`, `server.cpp`, `main.cpp`, `approval_manager.cpp`, `audit_store.cpp`, `rest_audit.hpp`, `pg/pg_pool.cpp`, `pg/pg_exec.hpp`, `mcp_server.cpp`, `mcp_orientation.cpp`, `rest_api_v1.cpp`, `settings_security_ui.cpp`; public `auth.hpp`, `auth_db.hpp`, and SDK `metrics.hpp`.
- Browser changes: `yuzu-operate.js`, `yuzu-operate-extras.js`.
- Test-source search excerpts: `test_mfa_step_up.cpp`, `test_approval_routes.cpp`, `test_settings_routes_mfa.cpp`. These were not executed.
- Reference/evidence excerpts: the auth skill, governance severity rubric, routed-concern tables, `auth-architecture.md`, the SOC 2 readiness document, `ha-delivery-matrix.md`, `upgrading.md`, `auth-db-recovery.md`, ADR-1005, ADR-0033, and the PR 1 ledger. Additional tracked documentation, changelog and ledger searches checked for mixed-version acceptance records. Baseline locations cited above were read with `git show origin/dev:<path>`.

| Row | Verdict | Band | Gates push |
|---|---|---|---|
| UP-2 | ACCEPT-AS-RESIDUAL | HIGH | No |
| UP-4-enforced | ACCEPT-AS-RESIDUAL | HIGH | No |
| UP-5bc | ACCEPT-AS-RESIDUAL | HIGH | No |
| UP-9 | RESTATE | HIGH | Yes, acceptance claim/record only |
| UP-14 | RESTATE | MEDIUM | No |
---

## Brief

# Codex (Astra) task brief: independent adjudication of five open BLOCKING ledger rows, PR 1 of Yuzu #6079

## Task (opine, read-only)
You are the INDEPENDENT adjudicator. The pipeline agents that wrote these rows belong to the authoring session, so their rulings are not independent. Rule on each row yourself, from the code, not from the rows' summaries. Do not assume any claim below is true; verify it.

Tree to read: /home/dgr/yuzu-6079-pr1 (branch fix/6079-pr1-gate, HEAD bf246be94). Dev baseline: use `git show origin/dev:<path>` (merge-base fde3564da; origin/dev has since moved). The PR diff is `git diff origin/dev...HEAD`. Do NOT read /home/dgr/yuzu-6079-gate or branches fix/6079-approver-gate / fix/6079-approver-mfa-enrolled.

What PR 1 does: approving or rejecting an approval ticket now requires an enrolled MFA factor plus a fresh proof (<= min(--mfa-step-up-window-secs, 300) s, 300 when that setting is 0 or negative) regardless of --mfa-enforcement. Gate: `require_enrolled_fresh_mfa` in server/core/src/mfa_step_up.cpp, wired as `approval::Deps::approver_mfa_fn` in approval_routes.cpp (handle_review). The generic central step-up check (`decide_step_up`, step_up_gate.cpp) still answers FIRST and is unchanged by this PR. Proof age is judged on the DB clock. Severity rubric: .claude/skills/governance/SKILL.md (derive from TRIGGER, IMPACT I1..I9, EXPOSURE E0..E7, EPISTEMIC STATUS; BLOCKING = derived CRITICAL or HIGH; `speculative` means a mandatory investigation is owed).

For EACH row below give: (1) verdict: CONFIRMED / RESTATE (new impact, exposure, band) / REFUTED / ACCEPT-AS-RESIDUAL (true, but should not gate this PR, with reasoning); (2) provenance: introduced by this diff, aggravated by it, or pre-existing (prove it with the origin/dev file:line); (3) the deciding file:line at HEAD; (4) derived band with the four facts; (5) what, if anything, must change before this PR is pushed.

### Row UP-2 (reporter: HIGH, I1, E3, likely)
Stolen admin cookie, victim unenrolled (default), --mfa-enforcement=optional. Settings MFA enrol init/verify (settings_routes.cpp, routes `/api/settings/mfa/init` and `/verify`) need only the admin session (no password, no proof); verify stamps a fresh proof on that session; attacker enrols their own TOTP and approves immediately. An earlier pipeline agent (chaos-injector, not independent) said this is NOT a regression because on origin/dev the same stolen cookie approves with no factor at all (approval_routes.cpp ~109-120 calls only step_up_fn; step_up_gate.cpp passes at window<=0 and passes an unenrolled local user). Verify that, and decide whether PR 1 changes or narrows the exposure. Proposed follow-up (not in PR): password re-prove on enrol init.

### Row UP-4-enforced (reporter: HIGH if counted against this PR, I4+I5, E4+E5, likely)
--mfa-enforcement=required (or admin-only with an administrator approver), window > 0, OIDC session whose cached MFA proof was dropped by DB-clock skew (derive_session_deadlines in auth.cpp drops a proof dated after DB now). The generic gate (decide_step_up, step_up_gate.cpp ~300-361) answers first with a repeating 401 "step-up required" challenge the approver cannot clear; PR 1's new 503 skew arm (kProofClockSkew in approval_routes.cpp / mfa_step_up.cpp) and clock hint are never reached. The generic gate is unchanged by this PR. Docs now name the repeating 401, the metric yuzu_auth_mfa_step_up_gate_total{outcome="refused"} and clock synchronisation (runbook docs/ops-runbooks/auth-db-recovery.md, authentication.md, upgrading.md, auth-architecture.md, rest-api.md). Never reproduced on a skewed rig, code read only. Decide provenance, band, and whether the documentation mitigation is sufficient for this PR or the generic gate must carry the skew signal now.

### Row UP-5bc (reporter: MEDIUM label, I1, E5, speculative; derives HIGH; mandatory investigation NOT performed)
(b) asynchronous Postgres standby promotion loses the last commits, resurrecting a cleared factor and ended sessions. (c) a surviving session (partial session-end after a factor clear) plus a DB clock step back below its proof: a re-enrol gets enrolled_at below the old proof_ms so the `predates` check (proof_ms < enrolled_at_ms, strict <) is false, and when the clock passes that instant the pre-clear proof is accepted under the NEW factor for up to the window. Do the investigation: name the code path and a concrete trigger, or say it cannot be named. Is the residual already stated in the docs (SOC 2 doc residual (b), auth-architecture DB-clock-backward assumption)? PR 2 (binding proof to a factor generation) is a separate later PR and is out of scope here.

### Row UP-9 (reporter: HIGH derived, I1, E4, likely)
Mixed-version rolling upgrade: an old replica without the gate serves approvals (skips the gate), its Settings disable ends no sessions, its rows lack the enrolled_fresh_mfa marker; the load balancer decides. Docs (upgrading.md ~883-940, SOC 2 doc residual (d)) disclose it and say the maintainer accepted it on 2026-10-19; there is NO in-repo acceptance record. Multi-replica operation is documented as unsupported today (safe-to-scale gate, docs/ha-delivery-matrix.md). Verify those two claims against the repo. Rule on whether this should gate PR 1, and say precisely what kind of record (ADR-1005 exception block, SOC 2 risk-register row, a #6079 comment) would be adequate. You cannot create the maintainer's acceptance; say what the maintainer must do.

### Row UP-14 (reporter: label NICE/LOW, I3, E5, speculative; derives HIGH; mandatory investigation NOT performed)
In approval_routes.cpp handle_review, `deps.audit_fn(... "success")` and `write_denied` are raw unguarded calls after `approve()` commits. A throw would give a 500, skip the `approval.approved` event, and a retry returns 400 already-reviewed. Do the investigation: can the production audit_fn (find what server.cpp binds, `AuditStore::log` etc.) actually throw (allocation failure aside)? Does anything else in the handler already guard it? Is this pre-existing structure or introduced? Compare with origin/dev.

## Also
List any additional defect you notice in the PR 1 diff that you would derive CRITICAL or HIGH. Keep to defects you can prove with a file:line; say "none found" otherwise. Say which files you actually read and whether you ran anything (you are read-only; you may run read-only commands, not builds).

## Constraints
- Read-only. No em or en dashes in your answer. No competitor names.
- Output: one section per row in the order above, then the "Also" section, then a 5-line summary table (row, verdict, band, gates push yes/no).
