# GOVERNANCE PASS 2 (independent gate fan-out) — SHARED CONTEXT FOR EVERY GATE AGENT

SENTINEL (echo this exact line back at the top of your report to prove you read this file):
`SENTINEL-9c-PR1-PASS2: alive is not quota; a claim is retained, never dropped`

## A. Run rules — binding on you

1. Worktree under review: `/home/dgr/yuzu-spark-9c-pr1` (branch `feat/spark-9c-pr1-executor-submit`, HEAD `706f11003`). Range: `df93548e9..706f11003` (`df93548e9` = `origin/dev` = merge-base).
2. The worktree is **READ-ONLY** for you: never `git checkout` / `stash` / `reset` / `commit` / `add`, never edit any file there, never build (`meson`/`ninja` compile), never run `meson test`. You MAY: `git show`, `git diff`, `git log`, `grep`, `Read`, and RUN the existing warm test binaries with a Catch2 tag or name filter (read-only inspection), e.g. `/home/dgr/yuzu-spark-9c-pr1/build-linux/tests/yuzu_agent_tests "[spark][ioexecutor]"` or `.../build-linux-tsan/tests/yuzu_agent_tests "[spark][runtime]"`. Those binaries were built at 07:53 / 07:59 (2026-09-09 +0100); the fold commit `ddab120f6` and HEAD were COMMITTED at 08:01, so the binaries may or may not include the fold's code. `ninja -C /home/dgr/yuzu-spark-9c-pr1/build-linux -n yuzu_agent_tests` (dry run, `-n`, writes nothing) tells you whether they are stale; report which you observed. Never rebuild.
3. **Do NOT read pipeline rules from `/home/dgr/Yuzu`** (its pipeline files are stale). The authoritative rules are in the worktree: `/home/dgr/yuzu-spark-9c-pr1/.claude/skills/governance/SKILL.md`, `/home/dgr/yuzu-spark-9c-pr1/.claude/routed-concerns.md`, `/home/dgr/yuzu-spark-9c-pr1/.claude/routed-concerns-access-control.md`, `/home/dgr/yuzu-spark-9c-pr1/CLAUDE.md`. Pass this instruction verbatim to any sub-agent you spawn (you should not need to).
4. **Your own brief may be stale in the copy preloaded into you.** FIRST read `/home/dgr/yuzu-spark-9c-pr1/.claude/agents/<your-agent-name>.md` (byte-identical to `origin/dev`) and treat it as your authoritative brief where the two differ.
5. Use absolute paths only. Do not write report files; return your findings as your final message.
6. This is pass 2. Pass 1 on this range was SELF-RUN by one model acting as every gate persona; you are the independent re-run. You have NOT been shown the code-level reasoning of pass 1, only its finding one-liners (section F). Re-derive from the code; do not defer to pass 1.

## B. Gate 1 — Change Summary: rung 9c PR-1, `GuardianIoExecutor::submit()` + per-key claim/queue

**Commits in scope (19; author Dave Rae on all; none pushed; no PR yet):**

| sha | subject | kind |
|---|---|---|
| 613cb427c | docs(guardian): fold ruling 14, #4147 and #4148 into R5 (rung 9c PR-1 doc pass) | design doc |
| fedbc1e99 | feat(guardian): GuardianDetachedWorkerRole marker + WorkerHostileMutex second role | C++ |
| 8b9e0bb15 | feat(guardian): GuardianIoExecutor::submit() with a two-count quota/physical split | C++ |
| b77ace735 | feat(guardian): per-key claim/queue in GuardianSparkRuntime (rung 9c R5.2, happy path) | C++ |
| e65e5820a | test(guardian): submit() worker mtx_ death test (WorkerHostileMutex second role) | tests |
| 440ba9b98 | fix(guardian): publish claim verdicts only after the compensating disarm has run | C++ (adv-review r0) |
| 5d9c97e82 | fix(guardian): publish and pop adopted claims inside the drain's commit step | C++ (adv r1 C1/K1') |
| 6c49ef8e4 | fix(guardian): own the arm subscription before any fallible work in the drain | C++ (adv r1 C2/K5) |
| 85102826f | docs(guardian): correct D10, R5.1 nested-disarm and alive-count release wording | docs |
| d1d911b70 | fix(guardian): build the disarm claim before the durable detach mutation | C++ (adv r2 C1) |
| fb760ec09 | fix(guardian): clear index ownership only after the index removal succeeds | C++ (adv r2 C2) |
| e8a0b4a9d | fix(guardian): run the firewall's last-resort disarm off registry_mu_ | C++ (adv r2 C3) |
| 360819482 | docs(guardian): residual alive-count wording, ClaimEnd plug-point note, comment truth | docs |
| e232676b2 | fix(guardian): contain claim-index release failures on the noexcept drain and stop paths | C++ (adv r3 C2/C3) |
| 3e15d25b9 | fix(guardian): prebuild post-erase allocations in detach_rule_locked | C++ (adv r3 C4) |
| 07658e0df | docs(guardian): alive-count tail wording, registry D10 per-instance ceiling and verification stamp | docs (adv r3 C1/C5) |
| 1ff175470 | Merge remote-tracking branch 'origin/dev' | merge |
| ddab120f6 | fix(guardian): fold governance findings hp-1, c-1, doc-1 (rung 9c PR-1) | C++ + changelog (pass-1 Gate 7) |
| 706f11003 | docs(governance): ledger for the rung 9c PR-1 governance run | governance.d |

**Files touched (21):**

| path | delta |
|---|---|
| `agents/core/src/guardian_io_executor.hpp` | +571/- : NEW `submit()` non-waiting form; two-count split (quota-held vs physical alive); `admit_locked()` shared admission (order stopping → key → quota → ceiling); `IoFailure::CeilingExhausted`; `kAliveCeilingFactor=2`, `kMaxAliveIoWorkers=20`; `TicketCore::release_quota_locked()` + `quota_released` handshake; `Stats`/`Counters` extended; `GuardianDetachedWorkerRole` as first statement of BOTH worker bodies, callables held in `std::optional` and reset inside the marked scope; `active_worker_count()` now = PHYSICAL alive count |
| `agents/core/src/guardian_spark_runtime.hpp` | +457/- : `arming_keys_`/`InFlightArm`/`DisarmWork` REPLACED by `claims_` (`unordered_map<string, KeyClaimQueue>`), `KeyClaim`, `ClaimKind`/`ClaimDispatch`/`ClaimEnd`, one runtime-wide `claim_cv_`; new private helpers; `backend_op_busy()` REMOVED → `backend_op_queued()`; 6 new counter accessors; 6 test seams; `set_agent_id_provider` contract strengthened (any-thread, never `mtx_`); `pending_journal_` doc: now also written from a detached worker |
| `agents/core/src/guardian_spark_runtime.cpp` | +1476/- : `attach_rule` claim path + bounded `wait_for_claim`; `detach_rule_locked` returns `shared_ptr<KeyClaim>`, builds the Disarm claim BEFORE the durable erase, Case-0 claim withdrawal; `submit_disarm_off_lock(claim)` retains a refused disarm; `dispatch_arm_off_lock`; `on_arm_complete` noexcept commit-in-callback drain (steps 1/1b/2/2b/3/4); `fail_all_claims_locked`; `release_claim_index_locked` noexcept; `abandon_claim_locked`; `begin_stop` drops Queued claims; `arm_failure_reason` helper; ~18 new try/catch sites |
| `agents/core/src/guardian_detached_worker_role.{hpp,cpp}` | NEW: single-TU `thread_local bool`, exported `set_/on_guardian_detached_worker_thread()`, RAII `GuardianDetachedWorkerRole` |
| `agents/core/include/yuzu/agent/guardian_engine.hpp` / `src/guardian_engine.cpp` | `WorkerHostileMutex::abort_if_worker_thread()` consults both role predicates, role-specific critical log; joined-thread text verbatim |
| `agents/core/src/spark_key_rule_index.hpp` | NEW `erase_rule(string_view) noexcept` (= `remove_rule` minus its key-copy allocation) |
| `agents/core/src/guardian_state_reader.cpp` | `io_failure_detail()` gains the `CeilingExhausted` string (reaches `guard.unhealthy` detail) |
| `agents/core/meson.build` | adds `src/guardian_detached_worker_role.cpp` to both `files()` lists |
| `tests/unit/test_guardian_io_executor.cpp` | +414: 12 new `[spark][ioexecutor]` cases |
| `tests/unit/test_guardian_spark_runtime.cpp` | +1384: 28 new cases (`[spark][runtime][liveness]`, one `[source_tripwire]`, one `[death]`); POSIX-only `fork()` death test under `#ifndef _WIN32` (:39-43, :5330+) |
| `tests/unit/test_guardian_engine_spark_reconcile.cpp` | +88: 1 new `[spark][guardian][reconcile][death]` case (submit() worker taking `mtx_` aborts) |
| `docs/spark-stage2-guardian-consumer-design.md` | +239: R5.1 two counts/F3 binding/#4147; R5.2 `ClaimEnd` plug point, three named non-success outcomes, ruling 14 (a)(b)(c); R5.3 K scope; R5.4 three timings; R5.5 physical count; R5.6 |
| `docs/spark-legacy-delta-registry.md` | rows A3, D10 (per-instance ceiling, restamped), E2 (physical count), two verify-at notes resolved |
| `changelog.d/20260909-spark-9c-pr1-executor-submit.changed.md` | NEW fragment (date-named; README permits rename at PR time) |
| `governance.d/spark-9c-pr1-adversarial-review-r{1,2,3}.md`, `-mutation-table.md`, `-executor-submit.jRNg61.jsonl` | committed evidence: 3 adversarial rounds, red/green mutation table (47 valid rows), pass-1 ledger |

**Interfaces affected:** agent-internal C++ only. `GuardianIoExecutor` public API extended (`submit()`, `alive_ceiling()`, `Stats`/`Counters`/`IoFailure` grown; `active_worker_count()` semantics change from single inflight count to PHYSICAL alive count). `GuardianSparkRuntime` public surface: accessor rename (`backend_op_busy` → `backend_op_queued`), new accessors and test seams, stronger `set_agent_id_provider` contract. `SparkKeyRuleIndex::erase_rule` added. **UNCHANGED:** proto/wire, REST, MCP, dashboard, plugin ABI, store schemas, CLI flags, env vars, `spark_engine.cpp`, `GuardianEngine::apply_rules` behaviour, `prefer_spark_` (false).

**Security surface:** no authn/authz/crypto/network/ingress change. What DOES change in a security-adjacent way: (1) F3 orphan-exit accounting — `active_worker_count()` (summed by `GuardianEngine::active_io_workers()` for the `hard_exit` grace) is now the PHYSICAL alive count; a `submit()` worker still inside `on_complete` holds the process open; a regression here is the use-after-free-at-DSO-teardown class F3 exists to prevent. (2) A new debug/sanitizer-only abort tripwire for `GuardianEngine::mtx_` on detached workers (compiles out of release). (3) Executor header code is SHARED with the live state-reader executor: `admit_locked`, the two-count split, `~TicketCore`, `stop()` snapshot and `active_worker_count()` all changed on that LIVE path.

**User-facing impact:** dormant for the arm/disarm path (`prefer_spark_=false`: no production arm/disarm reaches `submit()` or `claims_`). NOT dormant: the executor refactor on the live state-reader path; the `WorkerHostileMutex` tripwire in debug/sanitizer builds; the new `guard.unhealthy` detail string for `CeilingExhausted` (header claims it is provably inert for run()-only workloads). No operator workflow, flag, env var or schema change. Changelog fragment present.

**Resource Ledger (C++):**
- THREAD T1 — `submit()` detached worker. Created by `io_detail::spawn_detached` (`pthread_create` PTHREAD_CREATE_DETACHED / `_beginthreadex`+`CloseHandle`) in `GuardianIoExecutor::submit()` (`guardian_io_executor.hpp`, the `submit` template). Owner: none (detached by design, never joined). Liveness accounting: `State::alive_total`/`alive_by_class` ++ in `admit_locked`, -- in `~TicketCore` when the trampoline destroys the payload (last holder). Quota slot + single-flight key: released by `TicketCore::release_quota_locked()` at `fn()` return, BEFORE `on_complete`. Payload ownership: worker owns `fn`/`on_complete` in `std::optional`, reset inside the `GuardianDetachedWorkerRole` scope. Failure cleanup: spawn/alloc failure → `LaunchFailed`, armed ticket dtor rolls back key+quota+alive; `on_complete` never fires on admission failure. Caller's ticket copy dropped UNLOCKED after launch (dtor may run on the caller thread, late). Process-exit: F3 `hard_exit` grace on `active_worker_count()`.
- THREAD T2 — `run()` detached worker (pre-existing). Changed: role marker first statement; callables in `std::optional` reset inside marked scope; quota+alive both released in `~TicketCore` (release point unchanged vs base 74090cf4a); key at publish (`release_key_locked`).
- THREAD-LOCAL — `tl_guardian_detached_worker` (single TU `guardian_detached_worker_role.cpp`, exported accessors; set true in `GuardianDetachedWorkerRole` ctor, false in dtor on every exit path).
- CALLBACK C1 — arm `on_complete` closure (`guardian_spark_runtime.cpp:393`): captures `self = shared_from_this()` (keeps the runtime alive across the callback), `key` (string copy), `claim` (`shared_ptr<KeyClaim>`). No raw `this`, no weak_ptr. Fires exactly once on T1 after `fn()` returns; MAY fire before `submit()` returns to the caller; DOES fire after `begin_stop()`/executor `stop()` (`completed_after_stop`). Body = `on_arm_complete` (noexcept, firewalled).
- CALLBACK C2 — arm `fn` (`.cpp:390`): captures `backend` (`shared_ptr<ISparkBackend>`) + `spec` by value; calls `backend->arm(spec)` on T1.
- CALLBACK C3 — disarm `fn` closures for `io_executor_.run` in `submit_disarm_off_lock` (`.cpp:302-306`, caller thread blocks, `cfg_.backend_op_deadline`) and in `run_compensating_disarm` (`.cpp:519-523`, on T1, nested run from inside on_complete): capture `backend` + `sub` by value.
- CALLBACK C4 — `waker`/`outbox_waker`/`drain_gap_hook_for_test_`: copied under `registry_mu_`, fired OFF-lock on T1 (`.cpp:832-838`, `:751`).
- CALLBACK C5 — `agent_id_fn_`: now invoked on T1 under `registry_mu_` from `enqueue_lifecycle_locked` (the "armed" staging in the drain). Contract: any-thread-safe, never takes `GuardianEngine::mtx_`.
- SHARED STATE — `claims_`, `claim_cv_` (paired with `registry_mu_`), `KeyClaim` objects (shared_ptr held by waiter + fifo + C1; rollback/erase by POINTER identity); `pending_journal_`/`lifecycle_log_` under `outbox_mu_` now written from T1; `SparkKeyRuleIndex` mapping ownership tracked per claim by `index_held`.
- LOCK DISCIPLINE — no executor call under `registry_mu_` (sites `.cpp:302`, `:388`, `:519`, `:2371`); `on_arm_complete` steps (1)/(1b) under one `registry_mu_` acquisition (`:603`), (2)/(2b) off-lock, (3) fresh `lock_guard` (`:804`) with a nested re-acquisition in the double-fault catch (`:820`), (4) off-lock. Backend calls UNDER `registry_mu_`: pre-existing inline-type sites `:1070`/`:1076`/`:1379`, plus ONE NEW counted last-resort `backend_->disarm(kit->second->subscription)` at `:1385` (`detach_rule_locked`, remove_rule-throw rollback path).
- NOEXCEPT BOUNDARIES — `on_arm_complete` (`:439`), `release_claim_index_locked` (`:126`), `run_compensating_disarm` (lambda `:513`), both executor worker lambdas; `SparkKeyRuleIndex::erase_rule`. ~18 new try/catch sites in the .cpp (`:148`, `:194`, `:301`, `:386`, `:422`, `:518`, `:530`, `:601`, `:685`, `:735`, `:804`, `:832`, `:1317`, `:1334`, `:1364`, `:1384`, `:2326`, `:2370`).
- NONE introduced/modified: fds, HANDLEs, SOCKETs, `FILE*`, SQLite, OpenSSL, BCrypt, C strings, subprocesses, temp paths, mapped libraries. Tests: `fork()` without exec (POSIX-only death tests).

**Prior validation performed (author-reported in the committed evidence; NOT re-run by the orchestrator):** mutation table 47 valid red→green rows; `[spark][ioexecutor]` 35/248, `[spark][runtime]` 137 cases, `[spark][guardian][reconcile]` 49/684; `meson test --suite agent` Ok 2/Fail 0 (debug); TSan spark tags 35/137/49, 0 reports; `scripts/assemble-changelog.py --check` OK; 3 adversarial rounds (Kimi K3 + Codex Sol; r3 Codex-only). No CI (unpushed).

**Governance domains triggered — routed-concern walk at 706f11003 (Step 0: `SKILL.md`, both routed tables, `CLAUDE.md`, `.claude/agents/*` all byte-identical to `origin/dev` df93548e9):**
- `.claude/routed-concerns.md` MATCHED rows → agents: C++23 conventions → **cpp-expert**; C++ resource ownership/lifetime → **cpp-safety** (+ security-guardian enforces the ownership proof at Gate 2); docs-writer on every change → **docs-writer**; Guardian/Guaranteed State (`guardian_*`; registry F12 staleness) → **security-guardian + docs-writer**; Spark detection layer ADR-0021 (`guardian_spark_*`, `spark_key_rule_index.hpp`, F3/`hard_exit`) → **security-guardian + cpp-safety** [catastrophic clauses: `reconcile_rule_locked` sole arm/disarm chokepoint + mutual exclusion (armed in at most one of `guards_`/`spark_runtime_`); arm failure is ERRORED never a silent fallback; `prefer_spark_` defaults false; `stop()` sticky; F3 orphan grace/hard_exit]; Unit-test conventions (`tests/unit/`) → **quality-engineer**; Agentic-first (consistency-auditor every PR) → **consistency-auditor**; Prometheus/audit/event (the "armed" lifecycle audit staging moved onto a worker thread, R5.4) → **sre + architect**; System architecture (design doc = normative text; spans >2 dirs) → **architect**; macOS/Darwin (`thread_local`, detached pthread, `fork()` death tests) → **cross-platform**; Enterprise parity → **enterprise-readiness**.
- `.claude/routed-concerns-access-control.md`: all 18 rows walked — NO match (no auth/RBAC/token/PKI/MCP/dispatch/ingress/leader-election/split-interlock path; the ADR-1005 "engine-path marker" clause does not reach agent-side Guardian code).
- Gate 3 decision matrix: any C++ → cpp-expert + cpp-safety; `tests/` → quality-engineer; `meson.build` → **build-ci**; background thread/callback storing pointer → cpp-safety + sre; `#ifndef _WIN32` + `thread_local` + `pthread_create`/`_beginthreadex` → cross-platform. NOT triggered: performance, plugin-developer, gateway-erlang, dsl-engineer, release-deploy, authdb.

## C. Design authority and binding scope rules

- Design: `/home/dgr/yuzu-spark-9c-pr1/docs/spark-stage2-guardian-consumer-design.md` §R5 (section "Async-arm acknowledgment (rung 9c)" from line 271; R5.1 ~330-395, R5.2 ~397-480, R5.3 ~482-550, R5.4/R5.5/R5.6 to ~620) AS AMENDED in this range; `/home/dgr/yuzu-spark-9c-pr1/docs/yuzu-guardian-design-v1.1.md` §24 (line 2457ff), first bullet incl. the ORPHAN-EXIT CONTRACT paragraph (the "F3" label is the routed-concerns Spark row's + `agents/core/src/hard_exit.hpp`'s name for it); `docs/adr/0021-spark-reflex-architecture.md`; `docs/spark-legacy-delta-registry.md` rows A3/D10/E2; `docs/cpp-conventions.md`.
- BINDING SCOPE RULES (a violation is a finding): NO claim deadline, NO quarantine, NO K-bound, NO `arm_failed` classification (`ClaimEnd` is a FACTS-ONLY plug point the kickoff explicitly permitted; PR-1 reads it only as bookkeeping guards at `.cpp:566` and `:1253`); NO `apply_rules` wiring; NO telemetry/heartbeat egress; `spark_engine.cpp` UNTOUCHED; lands DORMANT behind `prefer_spark_=false` — but it IS a live-path change to tested code (executor header shared with the live state reader).
- STANDING ADJUDICATION (pass 1, `adjudicated_by: kimi-code/k3`): Codex's "physical alive count released in `~TicketCore` at payload destruction, before OS-thread exit" (adv-r1-C3 / adv-r3-C1) is PRE-EXISTING since rung 7 — release point byte-identical at base `74090cf4a` (`git show 74090cf4a:agents/core/src/guardian_io_executor.hpp`, lines 36-37 and 586-597) — and is CLOSED by doc wording (07658e0df). You may re-open it ONLY with NEW evidence that THIS RANGE changed the release point or added non-runtime code to the post-decrement tail. Re-stating the mechanism is not new evidence.

## D. Severity — DERIVE it, do not choose it (verbatim from the worktree skill; binding)

## Severity — DERIVE it, do not choose it

Report in the severity vocabulary your own brief specifies. Do NOT switch
vocabularies — a renamed band loses information. But do NOT pick a band by feel
either. State the facts below; the band follows from them. Where your brief's own
severity criteria disagree with the derived band, **the derived band governs the
GATE**; record your brief's label as `severity_native` and say they disagreed.

Every finding MUST carry, as separate fields — they are independent, and collapsing
them into one choice is what let severity be chosen:

1. TRIGGER — the concrete input, state, or configuration that produces it. Name
   it. "Under load" and "in some cases" are not triggers. If you cannot isolate
   one, write `unresolved` — do NOT downgrade IMPACT to compensate.
2. IMPACT — what goes wrong if this ships. Closed list. **List EVERY value that
   applies**; the strongest gives the base band. A crash that also corrupts is
   `I2` AND `I5`, and it derives from `I2`. Recording only the weaker one is how
   severity gets chosen.
3. EXPOSURE — what is required for it to happen. Closed list. **List EVERY value
   that applies**; the strongest modifier is the one that counts.
4. EPISTEMIC STATUS — `verified` (you ran something and observed the outcome),
   `likely` (reasoned from code you actually read), or `speculative` (you can
   name neither the code path nor a candidate trigger — a hypothesis about code
   you have not read). `likely` is the normal case and gates normally. Only
   `speculative` is exempt, and it is the narrow case, not the humble one.

### IMPACT — gives the base band

  I1  security-control failure — an authn, authz, confinement, crypto, or
      audit control does not hold                                     base HIGH
  I2  data loss or corruption — data destroyed or wrong. A surfaced
      error does not lower this; silence is not a precondition                   base HIGH
  I3  wrong result presented as correct — the caller cannot tell      base HIGH
  I4  harmful operator guidance — a doc, runbook, or error message
      directs an operator to a NAMED action that causes damage, or
      that fails in a way which conceals the real state. Guidance
      that merely fails visibly and diagnosably is I7 or I8, not I4  base HIGH
                                                                      (caps at HIGH)
  I5  unavailability — crash, hang, deadlock, wedge, unbounded growth base MEDIUM
  I6  capability absent or unreachable — a deliverable the change
      presents is not actually reachable in production (shipped-
      incomplete), or a required call site is missing                 base MEDIUM
  I7  required documentation absent for a shipped behaviour change    base MEDIUM
                                                                      (caps at HIGH)
  I8  degraded but correct — slow, wasteful, noisy; output still right base LOW
  I9  no operational impact — latent, stylistic, defence-in-depth only base INFO

I6 raises to HIGH in exactly two cases:
  (a) FALSE ASSURANCE — the change advertises a security or data-integrity
      control as in force which is not in fact enforced; or
  (b) DORMANT AUTHORISATION CODE — a new authz or enforcement branch ships with
      no production caller or author, so it goes live later without re-review.
      #2202 Blocker 4 is the reference case for (b): an RBAC resolver consuming
      a grant no production route could author. It is (b), NOT (a) — that
      resolver fails CLOSED, so nothing was under-enforced.

I5 raises to HIGH in any of three cases:
  (a) it is REPRODUCIBLE unavailability of the server or agent process reached on
      an ordinary request path — a triggerable control-plane crash gates, and
      does not need an unauthenticated reporter to do so;
  (b) it is unbounded or persistent AND falls on a serialised path shared with a
      security or data-integrity operation (revocation, enforcement, audit,
      retention);
  (c) it wedges a state machine. Delaying a
security operation at scale is a security outcome, not a performance one. #2580's
15s unbatched sampler on the agent-revocation thread is the reference case, and
the class also covers #2284's state-machine wedges.

I7 raises to HIGH when the omission conceals a breaking change, a security-
relevant behaviour, a data-loss risk, a migration step, or an irreversible
operation. Otherwise it stays MEDIUM. I4 and I7 never exceed HIGH: a document
is not reached by an attacker, so EXPOSURE cannot promote it to CRITICAL.

### EXPOSURE — list all that apply; strongest modifier wins

  E1  unauthenticated, in the DEFAULT configuration                   raise one band
  E2  an actor operating BEYOND the privilege it starts with
      (escalation, confinement escape). Judge by the privilege
      REQUIRED to begin, never the privilege gained                   raise one band
  E0  no actor required — it fires unconditionally in production: a timer, a
      background thread, a boot path, a scheduled sweep                no change
  E3  any authenticated actor within its own privilege, default
      configuration — including the ordinary operator                 no change
  E4  requires a non-default configuration                            no change
  E5  requires a race or a rare environmental condition (clock skew,
      disk full, concurrent writer, partial failure)                  no change
  E6  the WRONG OUTCOME — not merely the code branch — is proven
      unable to occur in production                                   cap at LOW

Bands, ordered:  INFO < LOW < MEDIUM < HIGH < CRITICAL
Order of operations: apply the strongest RAISE first, then any CAP. `E6` is
applied LAST and dominates every raise — the same recorded facts must not derive
CRITICAL or LOW depending on the order they are read in.

E4 is deliberately NOT a downgrade. In Yuzu the default is frequently the LESS
hardened setting — RBAC off is the default, `--auth-mode=sso-only` is opt-in — so
"only with the flag on" often means "only for the customers who care most".

E6 is about the OUTCOME, not the branch. A branch with no production caller is
usually I6 (shipped-incomplete), not E6 — E6 requires proving the wrong outcome
cannot occur, which a missing caller does not establish. If both a security
control failed AND the actor ends up beyond its privilege, that is I1 with E2;
do not report the escalation as though it were the only fact.

### The gate

BLOCKING = the derived band is CRITICAL or HIGH.

Vocabulary map, derived from the bands above, not asserted alongside them:
  BLOCKING / SHOULD / NICE     → BLOCKING = CRITICAL|HIGH, SHOULD = MEDIUM,
                                  NICE = LOW|INFO
  BLOCKING / SHOULD-FIX / NICE-TO-HAVE  → the same three
  low / medium / high / critical        → already bands; INFO absent, use LOW

### Policy floors — gate regardless of the derived band

These are contract violations, not operational severity. They do not run through
IMPACT/EXPOSURE and they always gate:

  - a Resource Ledger omission on a C++ diff
  - a direct edit to `CHANGELOG.md`, or a missing mandated `changelog.d/` fragment
  - a broken build or test leg on any supported platform that this change
    INTRODUCED or newly exposed — not a pre-existing or environmental failure
  - manual resource cleanup in NEW C++ that is not RAII-wrapped. The
    "documented impossibility" exception is NOT self-granted: it must be
    adjudicated by an agent other than the one proposing it and recorded in the
    ledger with `adjudicated_by`. Pre-existing cleanup in a file this change
    merely touches is SHOULD, not a floor — a deliberate narrowing, see the
    tuning doc
  - a violation of an explicit MUST / never / catastrophic-if-violated invariant.
    CLOSED to three sources, so floor membership is not a judgement call: a
    catastrophic-if-violated clause in a `.claude/routed-concerns.md` row; a
    CLAUDE.md sentence inside a standing-rule or invariant block; an accepted
    ADR's normative requirements. NARRATIVE prose does not qualify — an ADR
    saying a thing "never landed" is history, not a contract. If you cannot
    point at one of those three, it is not a floor — a
    second copy of a single-chokepoint rule, a forked dangerous-op gate, an
    approval gate outside the core primitive, a new server SQLite store with no
    exception ADR. These have no wrong outcome TODAY, which is exactly why the
    derivation cannot see them
  - an ownership or lifetime defect of the kind `cpp-safety`'s blocking contract
    enumerates: a leak, a double-close/double-free, a use-after-free or
    borrowed-data escape, an unjoined or ambiguously-owned thread, unsafe shell
    string construction, or a cast resting on undocumented aliasing/lifetime.
    These derive `I5`/MEDIUM on an ordinary path and would otherwise stop gating
  - a FALSE-GREEN test offered as closure evidence for a blocking finding — a
    test that cannot observe what it asserts. Ordinary missing coverage stays
    SHOULD; this is a floor because it is evidence of resolution that is not
    evidence of anything (#2580 parity test)

A missing test for a behaviour that has a bounded blast radius is SHOULD, not a
floor.

### Absences — and which way each one points

- TRIGGER unresolved → keep IMPACT honest. It is `speculative` ONLY if you also
  have no code path — that is the definition above. If you READ the code and
  named the path but cannot yet isolate the input, it stays `likely` (so it
  gates) and is flagged for adjudication. Never record a lower IMPACT than you
  observed in order to express low confidence.

  EPISTEMIC STATUS is an operation on the GATE, not on the band. Derive and
  report the band normally; `speculative` then converts the finding into a
  MANDATORY INVESTIGATION rather than a merge blocker: it is recorded at its
  derived band, it must be resolved to `verified`, `likely`, or `refuted` before
  the gate passes, and resolving it may confirm the band and block. `refuted` is
  a resolution, not an escape: it is the disposition, it carries its evidence and
  an independent refuter, and it is how a speculative claim that turns out FALSE
  leaves the gate — without it, a correctly-killed finding either wedges the gate
  or gets relabelled `likely`, which falsifies the record. It is a deferral of
  the decision, never a dismissal of it. `verified` and `likely` gate normally.
  If a finding is BOTH speculative AND has unresolved EXPOSURE, it GATES
  outright: a schema failure outranks weak evidence, because the unknown may
  be `E1`.
- EXPOSURE undeterminable → record `unresolved`. It does NOT default to E3, and
  it GATES pending adjudication. Defaulting an unknown to "no change" is a silent
  downgrade of a possible E1. Narrow exception, stated under the prose rule: `I4`
  and `I7` take `E3` — a document is read by an ordinary operator, is not reached
  by an attacker, and both cap at HIGH, so there is no `E1` to conceal. That is a
  determination for a named IMPACT class, not a licence to default an unknown.
- Your vocabulary does not map → gate it, and say so.

Your evidence being weak points DOWN, via EPISTEMIC STATUS. The schema failing
points UP. Those are different things and they are deliberately not symmetric.

## Prose: docs-writer owns WORDING, the domain agent owns TRUTH

Two different questions, two different owners:

- Is this text WELL WRITTEN (clear, accurate to convention, not stale)? ->
  `docs-writer`, including in-code comments and log/error-message text.
- Is this text TRUE? -> the domain agent. Ordinary C++ comments: `cpp-expert`.
  Lifetime / ownership / thread / callback / syscall claims: `cpp-safety`.
  Auth, authz, crypto, control claims: `security-guardian`. Erlang:
  `gateway-erlang`. CI / build / release: `build-ci` or `release-deploy`.
  Normative architecture text — ADRs, invariants documents, routed-concern rows:
  `architect`, plus `security-guardian` where the text states a security posture.

So: report a comment or doc when it CONTRADICTS the code — that is a truth finding,
at your own native severity, and it is yours to raise whatever agent you are. A
WORDING-ONLY observation belongs to `docs-writer`: if you are any other agent, do
not file it at all. That is the half that makes this a consolidation rather than a
sixth opinion — routing prose to one reviewer only works if the other five stop.
`docs-writer` files wording at NICE, capped.

Exception, and it is load-bearing: a factually false comment adjacent to a security
or control-flow branch IS a contradiction, not wording. #2202 shipped a comment
asserting the opposite of what its function did, next to an authz branch.

**Absence is a third category, and it is NOT wording.** A behaviour change with no
doc at all contradicts nothing, so the cap does not reach it: a missing required doc
is a TRUTH finding, derived per standing rule 2 as `I7` (SHOULD by default, BLOCKING
where the omission conceals a breaking change, security-relevant behaviour, a
data-loss risk, a migration step, or an irreversible operation). Never file a
missing-doc finding as NICE on the grounds that it is "documentation".

**"Required" is defined, not judged.** A doc is required when it is one of these,
and nothing else:

  1. the REST API reference, for a changed endpoint signature, body, error path or
     permission
  2. a `docs/user-manual/` section, for a changed operator workflow, CLI flag, env
     var or upgrade step
  3. a `changelog.d/` fragment, for an operator-visible change
  4. `CLAUDE.md` or a routed-concern row, for a new architectural invariant, store,
     ABI pattern or release gate
  5. an audit-action, permission or error-code table the change's contract touches
  6. a doc a `.claude/routed-concerns.md` row names as an **update obligation for
     the changed surface** — whether operator-facing (a user-manual page for a
     changed feature) or author-facing (a migration ladder, a capability registry,
     a per-surface invariants doc that records each change as it lands). What it is
     NOT is the row's **reading list**: `docs/cpp-conventions.md` is named for *any*
     C++ change so the reviewing agent LOADS it, and reading "names the doc"
     literally would make every C++ PR that does not edit it a missing-doc finding.
     The test is whether the doc accrues an entry per change, not who reads it.

**In-code prose never qualifies.** An uncommented function is not a missing required
doc. Without that boundary the rule becomes a laundering route: any wording nit
restates as "the doc does not state X" and walks from NICE to SHOULD, re-creating
the noise this whole line of work exists to reduce.

An absence finding must cite which of the six it rests on. If you cannot, it is a
wording finding or nothing.

For `I4` and `I7` findings, EXPOSURE is `E3` unless you can name a specific reason
otherwise. A document that isn't there is read by an ordinary operator; it is not a
timer and not an escalation. Recording `unresolved` here instead would gate every
missing doc, contradicting the `I7`-is-SHOULD-by-default rule two paragraphs up.

(Capping wording rather than banning it is deliberate: deciding whether prose is
descriptive or normative is exactly the disputed question, so a mis-classification
should cost a line of noise, not a lost finding.)

## Verify what you can, read-only

Verify the reviewer read what you think it read. A finding derived from corrupted
input is confident and wrong, and reads exactly like a finding derived from clean
input — a shell `patsub_replacement` setting silently rewrote every `&` in a review
payload on #2622, and the corruption was invisible in the output. Echo back a
distinctive line of the source before trusting a review of it.

Where a claim can be tested cheaply — a query, a compile, a one-case test — TEST IT
and report the output. An empirically verified finding outranks a reasoned one, and
a reasoned finding about observable behaviour should say it was not verified. The
highest-value finding of the #2580 run came from an agent running a real query
against a live Postgres rather than reasoning about the SQL.

READ-ONLY, against disposable state only. Never mutate a live store, and never run a
destructive statement to raise a finding's standing.
```

## E. Output contract (every agent)

Start with the SENTINEL line, then `Brief read: /home/dgr/yuzu-spark-9c-pr1/.claude/agents/<name>.md` and one distinctive line you quote from the source you reviewed (proves you read the right tree). Then findings, each with ALL of:
- `id`: `<prefix>-N` (prefix = your agent name abbreviation, e.g. `sg-1`, `dw-1`, `cx-1`, `cs-1`, `qe-1`, `ar-1`, `bc-1`, `xp-1`, `hp-1`, `up-1`, `ca-1`, `co-1`, `sre-1`, `er-1`)
- `severity_native` (YOUR brief's vocabulary), `file:line` at HEAD 706f11003 (or `unresolved`)
- TRIGGER; IMPACT (every `I` that applies); EXPOSURE (every `E` that applies, or `unresolved`); EPISTEMIC STATUS (`verified`/`likely`/`speculative`); the DERIVED band and whether it GATES; `policy_floor` if any (name which of the enumerated floors)
- `provenance`: `introduced` (in this range's diff) / `newly-reachable` / `pre-existing` (with the `git show <base>:<path>` evidence)
- `classification`: `truth-contradiction` / `wording` / `absence` + one-line rationale
- `falsifier`: the concrete test, command, or observation that would prove the finding wrong (or the red test that would show it)
- one-line `summary`; recommended fix (do NOT implement anything)
If you have NO findings, say so and list what you verified (files read top-to-bottom, tests run with their output line). Also state for each pass-1 finding in section F whether you INDEPENDENTLY re-derived it (yes/no) — that is the convergence signal, never an echo. An agent saying "this is safe" is not evidence: where a claim is cheaply testable (run a tag-filtered test, `git show` a base file, grep a sibling), test it and report the output. READ-ONLY, disposable state only.

## F. Pass-1 findings already recorded (do not re-raise WITHOUT new evidence; confirming/refuting closure IS welcome)

- hp-1 (happy-path, NICE, fixed ddab120f6): `attach_rule` key-move onto a key holding a RETAINED disarm left that disarm undriven (else-if); test `[spark][runtime]` "governance Gate 4 hp-1", RED at test:4657 pre-fix.
- c-1 (consistency, NICE, fixed): duplicate arm-side IoFailure→reason map → `arm_failure_reason()` helper.
- doc-1 (docs-writer, policy floor missing fragment, fixed): `changelog.d/20260909-spark-9c-pr1-executor-submit.changed.md`.
- sre-1 (sre, NICE, linked #4130): no heartbeat/metrics egress for the 9 new counters (PR-3 by design).
- up-1 (unhappy-path, NICE, pre-existing, linked #3813): disarm `run()` Timeout then refill → the rearm's `submit()` is refused AlreadyRunning for that push (retried next re-apply).
- adv-r1-C1 (commit-to-publish window leak/misroute) fixed 5d9c97e82; adv-r1-C2 (ownership guard after fallible allocs) fixed 6c49ef8e4; adv-r2-C1 (disarm claim allocated after durable detach) fixed d1d911b70; adv-r2-C2 (`index_held` cleared before remove_rule) fixed fb760ec09; adv-r2-C3 (last-resort disarm under registry_mu_ in the drain firewall) fixed e8a0b4a9d; adv-r3-C2 (throwing index release on noexcept drain) + adv-r3-C3 (`begin_stop` throw) fixed e232676b2; adv-r3-C4 (post-erase allocations in detach) fixed 3e15d25b9; adv-r3-C5 (registry D10 stamp) fixed 07658e0df.
- adv-r1-C3 / adv-r3-C1 (alive count released at payload destruction, not OS-thread exit): REJECTED as pre-existing (see section C standing adjudication); doc-truth half fixed.

## B-addendum (after Gate 3): Resource Ledger completion — the arm SUBSCRIPTION ID owner chain (cpp-safety, independently proven; security-guardian reached the same conclusion in Gate 2)

| Point (guardian_spark_runtime.cpp @706f11003) | Owner of the `uint64_t` subscription | Release |
|---|---|---|
| `backend->arm` returns on T1 (:391) | worker-stack `r` (:676) -> moved into C1 (:700) | - |
| `on_arm_complete` entry :473-474 | `compensating` (nothrow assignment, first statement) | - |
| throw at `fault_here(1)` :625 / fifo snapshot :626-634 / `!is_head` :609 | `compensating` | catch :785 -> step (2b) :795 |
| stopping / withdrawn / waiter-abandoned :636-649 | `compensating` | step (2) :782 |
| `!r` / `!armed_live` :650-669 | none (no live subscription) | - |
| first-claim commit throw :685-711 (make_shared, `keys_.emplace` hard error :696, `commit_new_generation_locked` allocations incl. `enqueue_lifecycle_locked`) | `compensating` (rollback :705-707 erases rules_/keys_) | step (2) :782 |
| adoption :727 | `keys_[K]->subscription` (PerKey) | via a later Disarm claim |
| post-adoption throw (`fault_here(2)` :729; :754/:755 SSO strings) | PerKey | step (3) fill-in :568-573 reports Committed, no disarm (correct) |
| sibling commit throw :742-747 | PerKey | - |
| step (2) `run_compensating_disarm` :516-536 | nested `run()` worker `[backend, sub]`; Timeout -> that worker still executes the disarm; Stopped / refusal / argument-throw -> direct `backend_->disarm` :531 | released |
| step (3) / double-fault :804-827 | already released or adopted | - |
| `detach_rule_locked` :1308-1325 | `KeyClaim::subscription` (Disarm claim pushed BEFORE `remove_rule`; a `remove_rule` throw rolls back :1340-1350 restoring `active`, `keys_` still owns) | `submit_disarm_off_lock` :302-306; the :1385 last-resort branch is unreachable (`claim_pushed <=> last_on_key && keys_ && io_class`, `disarm_key <=> last_on_key` asserted :1374); `kit` valid under the lock |
| `submit_disarm_off_lock` Timeout :332-339 | the run() worker completes the void disarm on its own (4-arg `run()` discards) - benign, not a leak; the executor key stays held until it finishes (pass-1 up-1) | - |
| `begin_stop` :2313-2334 | a Queued Disarm dropped -> owner remains `SparkEngine::armed_` | `SparkEngine::stop()` -> `m->stop()` (:1532-1533), ordered after `guardian_->stop()` in `agent.cpp` :1086->:1099 and :3341->:3358 |

Two NEW non-RAII release shapes, ADJUDICATED not a policy floor (documented impossibility) by cpp-safety (Gate 3, pass 3) - security-guardian independently concluded "no manual non-RAII cleanup introduced" in Gate 2: (a) `compensating` + the explicit `run_compensating_disarm` placement is load-bearing (a scope-end guard would fire AFTER step (3) publish - exactly 440ba9b98's defect); (b) `index_held` release must run under `registry_mu_` and the last `KeyClaim` holder can die off-lock, so a destructor-RAII release is impossible. `on_complete.reset(); fn.reset();` in the worker bodies is ordering-only (the payload destructor is the fallback); `ticket.reset()` is a shared_ptr transfer.
Lock order verified: `registry_mu_` -> `outbox_mu_` at :1366/:1492/:1666/:1819/:1865, never reversed; executor `State::mu` never nested with either (:302/:388/:519/:782/:795/:2371 all off-lock). Sanitizer evidence: TSan at HEAD green on `[spark][ioexecutor]` 35/248, `[spark][runtime]` 137/2711, `[spark][guardian][reconcile]` 49/582, `[spark][runtime][liveness] --order rand --rng-seed 2` 39/1037.
