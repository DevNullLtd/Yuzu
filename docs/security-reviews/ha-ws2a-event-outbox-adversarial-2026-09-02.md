# Synthesis — HA WS-2a slice 1 self-adversarial (Codex empirical + Kimi static)

**VERDICT: BLOCK → fix 2 substantive + 2 minor, then re-green.** Both reviewers independently
reached the same headline; cross-exam adopted one new finding each way. Empiricism note: Codex
compiled clean but its PG fixture was unreachable from the codex sandbox (network isolation to the
:5433 container) — so the behavioural [outbox] tests ran only in MY environment (9 cases/110
assertions green). C1's falsifier is therefore mine to execute.

## Consolidated findings

| ID | Sev (adjudicated) | Found by | Verdict |
|----|----|----|----|
| **C1/K6** | **HIGH — gates (policy floor: §5 normative violation)** | both, independent | **FIX** |
| **C2/K1** | **MEDIUM — gates as a frozen-contract defect** | both (cross-exam) | **FIX** |
| C3/K2 | LOW | both | FIX (trivial) |
| C4c/K4c | LOW | both | FIX (cheap test) |
| K3 | conditional, not-verified | Kimi | **REFUTED** (Codex repo-wide publisher search + my own audit: the 4 publish sites are the only ExecutionEventBus::publish sites; create_execution/set_agents_targeted don't publish) |
| K5 | LOW, not-verified | Kimi | **REFUTED** (migration v3 runs green in my test env every run; the runner's simple-query executor + SET LOCAL search_path handles multi-statement unqualified DDL — Codex read it) |

### C1/K6 — mark_cancelled commits a durable event-without-state (HIGH, gates)
`mark_cancelled`'s `UPDATE ... WHERE id=$2` (no RETURNING) returns `PGRES_COMMAND_OK` for a
zero-row match, then appends `execution-completed` unconditionally → a durable terminal event with
no paired state mutation. Violates ADR-2002 §5 ("never state-without-event NOR event-without-state")
and routed-concern (c). Kimi's fairness note: the unchecked-UPDATE + ephemeral phantom is
PRE-EXISTING; the **new** blocking delta is making the phantom **durable + cross-instance**. I had
deferred this (UP-7) as E6-capped; wrong call — it's a normative-invariant violation (policy floor),
gates regardless of "no consumer yet". **Fix:** `UPDATE ... RETURNING id`; append + publish + report
success only if one row matched; a zero-row cancel is a no-op. + regression test.

### C2/K1 — the frozen id-ordering contract prescribes an UNSAFE cursor (MEDIUM, gates)
My governance-round "fix" (watermark = trailing lookback ≥ max appending-txn duration) is itself
insufficient: `created_at = now()` is transaction-START time, so NO finite time-lookback linearizes
commit order — Kimi constructs a permanent-skip straddle even at L=2D. The whole point of freezing
this contract in 2a-1 is to give 2a-2 a CORRECT spec; a misleading one is worse than none. **Fix:**
rewrite the note — a `created_at` time-lookback is NOT sufficient on its own; the safe approaches are
an id-gap-pending advance (track missing ids, advance past one only once it is proven committed or
rolled back) or a txid/snapshot-horizon cursor (poll below the all-committed xmin). Leave the exact
algorithm to 2a-2 but stop prescribing the unsafe one.

### C3/K2 — stale "~30s" comment (LOW). The constants comment says the reap runs "~30s" but the
implementation is 30 ticks = ~60s. Fix: s/~30s/~60s/.

### C4c/K4c — refresh_counts_once's two-append terminal rollback is untested (LOW). Cheap + material.
Add a refresh-path append-failure rollback test.

## What each reviewer ran
- Codex: `meson compile -C build-linux tests/yuzu_server_tests` PASS; `[outbox]`/`[execution_tracker]`
  attempted but PG fixture unreachable (exit 42, no product assertion reached); `git diff --check` PASS.
- Kimi: static-only over the injected CONTEXT bundle (diff + run_in_txn + sibling reap + ADR §5).
- Me (adjudicator): the behavioural tests pass in my env; I execute C1's falsifier as the new regression test.
