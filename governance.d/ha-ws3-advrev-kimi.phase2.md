# Phase 2 — cross-examination (reviewer: `kimi`)

## 1. Cross-examination of codex's findings

| PEER-ID | label | evidence I checked (file:line) | my severity |
|---|---|---|---|
| CDX-P1-01 | `not-verified` (facts) + `disagrees` (severity → LOW) | The claimed startup call site (server.cpp:7181) and `publish_crl()` internals (:10397–10442, `crl_publish_mu_`, `next_crl_number()`) are **not in my CONTEXT** — I cannot verify existence, ungatedness, or the read-then-write race. What I *can* verify corroborates only the ordering: my diff's hunk offsets place elector construction at new-lines ~7333–7400 (`@@ -7226,6 +7333,68 @@`) and the gated freshness republish at ~7831–7845 (`@@ -7660,11 +7829,22 @@`), so an unchanged call at :7181 would indeed precede elector construction. | LOW (judgment) |

**Adjudication of CDX-P1-01.** Even taking codex's file-read facts on faith, I grade this LOW, not MEDIUM, for four reasons:

1. **Unsupported topology precondition.** The scenario requires two replicas booting against the same DB. The target statement and the `DisabledUntilFixed` deployment gate make single-replica the only supported topology; the race cannot manifest in any supported deployment today. This is forward-looking multi-replica hygiene, not a defect in this change.
2. **Explicit scope deferral.** The diff's own CRL gate comment states "Numbering correctness itself is WS-6." The slice's contract (target statement) is "gates the 4 FencedLeaderOnly background passes" — the startup one-shot is not one of the four classified passes; it is pre-existing, unchanged boot code. Grading it as a gap *of this slice* stretches the anchor; codex themselves marked the anchor `judgment`.
3. **Codex's fix would regress the supported topology as literally proposed.** "Guard it through `leader_gate_permits`" at the startup site would evaluate `is_leader()` at a point where the election thread has not yet acquired (acquisition is async in `leader_thread_`; my K6). On the single supported topology that *skips* the boot-time CRL publish — a behavior change introduced by the fix, not the change. The only safe version ("block boot until acquired") contradicts the slice's deliberate do-NOT-fail-boot posture (server.cpp:7349–7358).
4. **Residual value is real but is a tracking note.** If the startup site carries `YUZU_ASSERT_BACKGROUND_JOB("ca.publish_crl")` (not-verified — codex didn't say, I don't have the line), it is a *live instance of my K5* (classification pinned, gate presence manual). That is the useful form of this observation: a WS-6 checklist item, not a MEDIUM against 3.2.

## 2. Adopt / rebut codex's coverage

- **ca_routes.cpp operator path (codex read it; I had only comments):** ADOPT. Codex's full-file read empirically confirms the operator revoke/publish path is ungated, upgrading my phase-1 "verified-clean: two-dispatch-planes" from comment-trust to peer-empirical corroboration.
- **CLAUDE.md / agentic-first-principle (not inlined for me):** ADOPT. Codex read both and surfaced no contract violation; consistent with my judgment-tagged (not contract-tagged) K1/K5.
- **Compile + unit tests:** ADOPT as corroboration. GCC 15.2/C++23 compiling `test_leader_gate.cpp`'s `static_assert`s empirically confirms the `kBackgroundJobs` classifications I had to trust (exactly the 4 FencedLeaderOnly passes, event-poll ReplicaSafe, nvd_sync DisabledUntilFixed) and that the consteval/template gate machinery is sound.
- **REBUT one implication:** codex's test runs do **not** exercise any PG-backed path (`YUZU_TEST_POSTGRES_DSN` unset → 14 `[leader-elector]` cases skipped, including the backend-kill test and the TSan-labelled concurrency test; no sanitizer build run). So my K4 (flake) and the lock-free publish protocol remain empirically unexercised — codex's green run must not be read as covering them.

## 3. Defense of my own findings

None were contradicted. Re-verified against codex's review:

- **K1** — unaddressed by codex despite their full server.cpp read; nothing in their review establishes whether no-Postgres boot is supported. Stands, still `lo`/`not-verified`.
- **K2** — codex loaded cpp-safety and did not flag the unguarded election-thread lambda; their silence doesn't refute a code-read fact visible in my diff (no try/catch in the lambda vs. try/catch at all three sibling tick sites). Stands.
- **K3** — codex's green compile/tests added zero coverage of `build_coord_dsn` (anonymous namespace, no test references it). Stands.
- **K4** — strengthened, not weakened: codex's environment *skipped* the PG-backed test, so the race I flagged has never executed anywhere in this review. Stands.
- **K5** — strengthened conditionally: CDX-P1-01 is a possible live instance (an ungated dispatch site for a classified pass). Stands.
- **K6** — unaddressed; codex's own finding inadvertently confirms the fact underneath it (leadership is not acquired synchronously at construction). Stands.

## 4. Revised finding list

**[K1] MEDIUM · lo · static-read — `unchanged`.** Null-`pg_pool_` boot silently disables all four FencedLeaderOnly loops with no log (server.cpp:7343 guard has no `else`; leader_gate.hpp:55 denies on null; the elector-open-failure branch logs `[HA]` but this branch logs nothing). Falsifier: evidence boot fails without Postgres or the four workers are only spawned when `pg_pool_` exists. Anchor: judgment.

**[K2] LOW · med · static-read — `unchanged`.** Election-loop thread body has no exception guard; an escaping throw is `std::terminate`, inconsistent with the try/catch idiom at every sibling loop in the same diff (server.cpp:7367–7400). Anchor: judgment.

**[K3] LOW · med · static-read — `unchanged`.** `build_coord_dsn` (server.cpp:375–421) is pure string logic — six keys, keyword-vs-URI branch, operator-wins suppression — untestable in an anonymous namespace and entirely untested; codex's run confirms zero coverage. Anchor: judgment.

**[K4] LOW · med · static-read — `unchanged`.** The #4013 backend-kill test asserts `CHECK_FALSE(a.heartbeat())` immediately after `pg_terminate_backend` with no wait, racing async backend death (test_leader_elector.cpp:252–280); the same file's re-acquire loop shows the authors knew termination is async. Never executed in codex's env (PG skipped). Anchor: judgment.

**[K5] LOW · lo · static-read — `unchanged` (cross-link CDX-P1-01).** Anti-drift enforces classification, not gate *presence*: a future (or existing, cf. the startup CRL site) dispatch site can carry `YUZU_ASSERT_BACKGROUND_JOB` without `leader_gate_permits` and compile fine. Anchor: judgment.

**[K6] LOW · lo · static-read — `unchanged`.** run() comment overclaims "`is_leader()` already has a value by the time … first tick"; acquisition is async in the election thread, so a first tick can legitimately skip. Comment accuracy only. Anchor: judgment.

**[K7] LOW · lo · static-read — `new-from-cross-exam` (adopted from CDX-P1-01 at reduced severity).** Startup CRL pre-publication (claimed server.cpp:7181) runs before elector construction and ungated; in a future multi-replica deployment two concurrent boots could double-publish/race crlNumber. Facts `not-verified` from my CONTEXT (site and `publish_crl()` internals not shown; ordering corroborated by hunk offsets). Non-blocking because: unsupported topology today, numbering explicitly deferred to WS-6, and a bare gate check at that site would skip the publish on the supported single-replica topology. Fix: WS-6 tracking note (make `next_crl_number()` cross-replica atomic; then decide whether the boot one-shot needs a gate at all) — not codex's literal fix. Falsifier: n/a (LOW).

**VERDICT:** PASS — unchanged; codex's sole finding survives cross-examination only as a LOW tracking note, and nothing in codex's empirical results contradicts any of my six findings.

**COVERAGE:** Deep (unchanged from phase 1): correctness/logic, concurrency/resource, security/injection, test adequacy, cross-component/contract anti-drift. Adopted from codex: ca_routes.cpp operator-plane read, CLAUDE.md/agentic-first-principle read, compile/unit-test corroboration of the classification table. Rebutted: any reading of codex's green tests as covering PG-backed or TSan paths (all skipped). Skimmed (both of us): cross-platform.

**FILES:** Same as phase 1, plus codex's RAN/FILES list used only as evidence of what was empirically exercised (compile, non-PG unit tests) vs. skipped (all PG-backed cases).

**Delta since phase 1:** (1) Adopted codex's startup-CRL observation as K7 at LOW (down from MEDIUM) — facts not-verified from my CONTEXT, severity adjudicated down on topology-support, explicit WS-6 deferral, and a fix that would regress single-replica boot as proposed. (2) K4 and the TSan path confirmed *unexercised* — codex's PG tests all skipped. (3) Classification-table contents upgraded from trusted to peer-confirmed via codex's compiling static_asserts. (4) Two-dispatch-planes verified-clean upgraded via codex's ca_routes.cpp read. (5) No finding withdrawn; verdict unchanged.
