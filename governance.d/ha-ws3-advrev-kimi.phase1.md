# Phase 1 — independent static review (reviewer: `kimi`)

Scope honored: attempt-gate only. The momentarily-stale-leader dispatch window is the documented 3.3/3.4 residual and is **not** treated as a defect below. All findings are `static-read`; I could not compile, run, or open files beyond the CONTEXT.

---

[K1] MEDIUM · CONFIDENCE(lo) · PROVENANCE(static-read)
Null-`pg_pool_` boot silently disables all four FencedLeaderOnly loops, with no log
- Location: server.cpp:7343 (`if (pg_pool_ && !startup_failed_)` guard on elector construction) + leader_gate.hpp:55 (`elector != nullptr && elector->is_leader()`)
- Claim: when `pg_pool_` is null, no elector is ever constructed, every `leader_gate_permits<FencedLeaderOnly>(nullptr)` denies, and schedule/policy/quarantine/CRL never run again — and unlike the elector-failed-to-open case (which logs a loud `[HA]` error), this branch logs nothing.
- Evidence: `if (pg_pool_ && !startup_failed_) { leader_elector_ = std::make_unique<LeaderElector>(...); ... }` — the `else` is absent; leader_gate.hpp: "A null `elector` (never wired) denies a `FencedLeaderOnly` pass — fail-closed"; the deny-on-null behavior is pinned as intended by `test_leader_gate.cpp` ("fails closed with no elector").
- Scenario: server runs in a configuration where `pg_pool_` is null but boot proceeds (the guard's existence implies the author considered it a runnable state) → all four background passes silently stop; schedules never fire, CRL goes stale.
- Inference: whether any *supported* topology runs with null `pg_pool_` is not determinable from the CONTEXT; the born-on-Postgres direction of the codebase suggests Postgres may be mandatory, in which case this is moot. If the gated worker threads are themselves conditional on `pg_pool_`, also moot. `not-verified` on both.
- Anchor: judgment (no anchor covers the no-Postgres topology; ADR-2002 assumes the Postgres coordination substrate).
- Fix: if no-Postgres boot is supported, either fail boot when FencedLeaderOnly passes exist without coordination, or log the same `[HA]` pause warning when `pg_pool_` is null.
- Falsifier: evidence that boot fails without Postgres, or that the four worker threads are only spawned when `pg_pool_` exists.

[K2] LOW · CONFIDENCE(med) · PROVENANCE(static-read)
Election-loop thread body has no exception guard — an escaping throw is `std::terminate`
- Location: server.cpp:7367–7400 (`leader_thread_ = std::thread([this]() { ... })`)
- Claim: the lambda calls `try_acquire()`/`heartbeat()` unguarded; any exception escaping the thread function terminates the process, unlike every sibling background loop in this same diff.
- Evidence: the policy/quarantine/schedule sites each wrap the tick in `try { ... } catch (const std::exception& e) { ... } catch (...) { ... }` with the comment "Catch, log, and keep ticking"; the election-loop lambda has no try/catch anywhere around `leader_elector_->heartbeat()` / `try_acquire()`.
- Scenario: `std::bad_alloc` from string/vector ops in `try_acquire`, or a throwing spdlog sink, inside the election thread → exception escapes the thread → `std::terminate` → whole server down (ironically triggering failover).
- Inference: realistically only bad_alloc-grade throws are plausible (libpq doesn't throw; `pg::exec_params` behavior not visible — `not-verified`), and terminate-on-bad_alloc is arguably acceptable; the finding is the inconsistency with the established local idiom, which the diff itself invokes for thread-join safety ("cpp-safety BLOCKING").
- Anchor: judgment (codebase pattern consistency; no anchor mandates catch-and-continue for this loop).
- Fix: wrap the loop body in `try { ... } catch (...) { spdlog::error(...); }` mirroring the other three loops.

[K3] LOW · CONFIDENCE(med) · PROVENANCE(static-read)
`build_coord_dsn` is untestable where it lives and entirely untested
- Location: server.cpp:375–421 (anonymous namespace inside server.cpp)
- Claim: six appended parameters, the keyword-vs-URI branch, and the operator-value-wins suppression are pure string logic with zero test coverage, and placement in server.cpp's anonymous namespace makes them unreachable from unit tests; a malformed append surfaces only at runtime as a coordination-connect failure (fail-closed, but a silent pause of all four loops).
- Evidence: `namespace { ... std::string build_coord_dsn(const std::string& base) { ... } }` in server.cpp; no test referencing it in either test file; the comment itself acknowledges one false-suppression class ("A DSN whose VALUE literally contains `<key>=`").
- Scenario 1: a DSN with leading whitespace (`" postgresql://..."`) defeats `base.rfind("postgresql://", 0) == 0` → treated as keyword form → appends `" connect_timeout=5"` onto a URI → malformed DSN → elector never opens → loops paused. Scenario 2: a separator/typo bug in the append loop → same outcome, caught only in production.
- Inference: scenario 1 is contrived but is exactly the class of bug a 20-line pure-function test file would pin; the acknowledged value-contains-`key=` case shows the authors know this function has edge semantics worth pinning.
- Anchor: judgment (test adequacy).
- Fix: move `build_coord_dsn` into a small header (the `leader_gate.hpp` pattern) and add unit tests: keyword append, URI append with/without existing query, operator-set-wins for each of the six keys, empty base.

[K4] LOW · CONFIDENCE(med) · PROVENANCE(static-read)
The #4013 backend-kill test races asynchronous backend termination
- Location: tests/unit/server/test_leader_elector.cpp:252–280
- Claim: `pg_terminate_backend` signals but does not synchronously kill; the immediate `CHECK_FALSE(a.heartbeat())` can observe a not-yet-dead backend whose `SELECT 1` still succeeds, making the test intermittently fail.
- Evidence: `PgResult k{PQexec(killer.get(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity ...")}; REQUIRE(k.status() == PGRES_TUPLES_OK);` is immediately followed by `CHECK_FALSE(a.heartbeat());` with no wait — while the *later* re-acquire assertion in the same test does tolerate async death (`for (int i = 0; i < 40 && !led; ++i) { ... sleep 50ms }`), showing the authors knew termination is asynchronous.
- Scenario: loaded CI runner → SIGTERM delivered but `a`'s backend hasn't exited when heartbeat's `SELECT 1` round-trips → heartbeat returns true → `CHECK_FALSE` fails → flaky test.
- Inference: the window is small (an idle backend in `recv()` dies promptly on SIGTERM, and the socket close itself errors the next query), so flake probability is low but nonzero.
- Anchor: judgment (test robustness).
- Fix: poll `pg_stat_activity` until the victim pid is gone (or loop heartbeat with a deadline) before the `CHECK_FALSE(a.heartbeat())`.

[K5] LOW · CONFIDENCE(lo) · PROVENANCE(static-read)
Anti-drift covers reclassification but not gate *presence* for a future FencedLeaderOnly pass
- Location: leader_gate.hpp (mechanism) + the four manual call sites in server.cpp
- Claim: the consteval `background_job_class()` makes applying the gate to an *unclassified* pass a build failure, but nothing forces a *newly added* FencedLeaderOnly row in `kBackgroundJobs` to acquire a `leader_gate_permits` call at its dispatch site — it compiles and runs ungated on every replica.
- Evidence: the gate is opt-in per site (`if (leader_gate_permits<background_job_class("...")>(...))` written by hand at four sites); `YUZU_ASSERT_BACKGROUND_JOB` asserts only classification, not gating; the static_asserts in test_leader_gate.cpp pin classifications of existing passes, not gate presence.
- Scenario: a future slice adds a 5th FencedLeaderOnly pass to the table; author adds the site assert (compiles) but forgets the gate → double-dispatch once a second replica exists, exactly the drift the seam exists to prevent.
- Inference: today the table has exactly the four gated passes (per the target statement), so this is future-safety only; the header's anti-drift claim ("no second list") is true for reclassification, not for new-pass adoption.
- Anchor: judgment.
- Fix: a comment/checklist note in background_jobs.hpp at the `FencedLeaderOnly` enumerator ("adding one REQUIRES a `leader_gate_permits` site"), or a test enumerating all FencedLeaderOnly rows against a site registry.

[K6] LOW · CONFIDENCE(lo) · PROVENANCE(static-read)
run() comment overclaims leadership readiness before workers' first tick
- Location: server.cpp:7336–7342 (comment above elector construction)
- Claim: the comment says the elector is started before the worker loops "so `is_leader()` already has a value by the time schedule/policy/quarantine/CRL first tick," but the first `try_acquire` runs asynchronously in the election thread; a worker ticking immediately after spawn can observe not-leader and skip one tick.
- Evidence: `leader_thread_ = std::thread(...)` only *starts* the loop; acquisition happens inside it (`: leader_elector_->try_acquire()`), racing the subsequent synchronous boot work and worker spawns.
- Scenario: fast worker first tick before the election thread's first acquire round-trip completes → one skipped tick. Harmless: ticks are periodic and single-replica acquisition is milliseconds.
- Inference: impact negligible; this is comment accuracy only (the causal claim is wrong even though the practical outcome is fine).
- Anchor: judgment.
- Fix: reword the comment ("leadership is typically acquired within one round-trip of thread start; a first tick may legitimately observe not-leader and skip").

---

**Verified-clean axes (no findings):** SQL injection surface (lock_name validated `[a-z][a-z0-9_]{0,47}` and fail-closed `(1=0)`; `holder_id`/`lock_name` bound as `$1`/`$2` in the epoch INSERT; advisory key SQL embeds only the validated identifier); DSN password never logged (only `PQhost`/`PQport`/`PQdb`); `live_epoch_` release/acquire publish is correct, single-writer-under-`mu_` including the cross-thread `resign()`; stop() ordering is deadlock-free and no post-`resign()` re-acquire is possible (`stop_requested_` set before `resign()`, loop re-checks it; `resign()` blocks on `mu_` until any in-flight acquire completes and then drops it); connection/guard lifetime (`connect_locked` drops the guard before reassigning `conn_`; member declaration order + explicit drop in `~LeaderElector`); election-loop state machine (all six leading/open/backoff combinations traced correct); two-dispatch-planes respected (only the four background ticks gated; operator CRL/revoke and `remediate`/`evaluate_now` explicitly ungated per comments); WS-2a event poll pinned ReplicaSafe and never gated; `DisabledUntilFixed`→run mapping deliberate and tested; lock-leak-on-mint-failure path both correct in code and covered by a real test.

**VERDICT:** PASS — no CRITICAL/HIGH within the attempt-gate-only scope; the strongest finding (K1) is a low-confidence judgment call about a possibly-unsupported no-Postgres topology, and everything else is LOW test-robustness/robustness polish against an otherwise faithful implementation of the §3/§6/§10 invariants.

**COVERAGE:** Deep — correctness/logic (election loop, backoff, gate truth table, fail-closed paths), concurrency/resource (atomic publish protocol, thread lifecycle, join/resign interleavings, guard/connection lifetime), security (injection validation, bound params, secret-in-log check, fail-closed), test adequacy (flake K4, untested K3, fixture assumptions), cross-component/contract (consteval anti-drift incl. its K5 gap, two-dispatch-planes, WS-10 pins). Skimmed — cross-platform (Linux-server product; `tcp_user_timeout`/keepalive params are ignored where unsupported, not a defect) and CLAUDE.md / agentic-first-principle (not inlined in CONTEXT; where a finding would need them — K1 — it is marked `judgment`).

**FILES:** Leaned on the full leader_elector.hpp/.cpp and leader_gate.hpp, all server.cpp diff regions (DSN builder, elector construction + election loop, the four gate sites, stop() block, member declarations), and both test files in full. Not available and relied on comments/target-statement for: `kBackgroundJobs` table contents (trusted that exactly 4 FencedLeaderOnly rows exist), full stop() body (worker join ordering — verified the safety property holds regardless because the elector outlives stop()), `pg_pool_` nullability semantics (K1, `not-verified`), `PgMigrationRunner` version-tracking internals (the lock-leak test's dropped sequence stays dropped only if v1 is recorded as applied — plausible, `not-verified`), ca_routes.cpp operator path.
