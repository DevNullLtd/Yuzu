# Kimi (K3) opine brief

## Task

ONE adjudication question, answered against the code with file:line citations, for a governance
ledger row that needs an external attestation (rung 9c PR-1, branch
`feat/spark-9c-pr1-executor-submit`, this checkout). Answer with a clear one-line VERDICT first
(one of: "INTRODUCED BY THIS RANGE" / "PRE-EXISTING, RANGE DID NOT MOVE IT" / "CANNOT DETERMINE"),
then the evidence, then a second one-line verdict on the doc wording ("TRUTHFUL" / "OVERCLAIMS" /
"UNDERCLAIMS") with the exact sentences you checked.

Question: Does the commit range `74090cf4a..HEAD` change the point at which `GuardianIoExecutor`'s
PHYSICAL alive-worker count (`alive_total` / `alive_by_class`, what `active_worker_count()`
reports and what `GuardianEngine::active_io_workers()` sums for the F3 orphan-exit contract) is
released, relative to the detached worker's OS-thread exit?

Compare the BASE header `git show 74090cf4a:agents/core/src/guardian_io_executor.hpp` (its
`TicketCore` destructor, the worker lambda's captured `ticket` copy, and `io_detail::detached_trampoline`)
with the same three things at HEAD (`agents/core/src/guardian_io_executor.hpp`). State, for base
and for HEAD separately, exactly WHEN the decrement runs (which destructor, on which thread,
before or after the trampoline returns, before or after the OS thread exits). Then state whether
a reviewer's finding "the alive count reaches zero before the OS thread exits, opening the F3
teardown race" describes a defect INTRODUCED by this range or a property that already held at
the base. Finally check whether the HEAD wording is truthful: the header's own TicketCore doc
block ("the latest SELF-observable point before the OS thread exits ... process-lifetime runtime
code ... No grace covers that tail ... identical for every run() worker since rung 7"),
`docs/spark-stage2-guardian-consumer-design.md` R5.1/R5.5 sentences on the release point, and
`docs/spark-legacy-delta-registry.md` row E2's alive-count clause. Cite `hard_exit.hpp`'s
`wait_for_workers_to_drain` and `main.cpp`'s F3 block when judging the "no grace covers that
tail" claim.

Do NOT propose a redesign (join handles, reapers) - the detached-at-creation design is a settled
decision (rung 5/7, no std::terminate path); the question is only whether this RANGE moved the
release point and whether the words at HEAD are true.

## In scope
- Files: `agents/core/src/guardian_io_executor.hpp` (base via `git show 74090cf4a:...`, and HEAD),
  `agents/core/src/hard_exit.hpp`, `agents/core/src/main.cpp` (the F3 block near
  `guardian_active_io_workers`), `docs/spark-stage2-guardian-consumer-design.md` (R5.1 / R5.5),
  `docs/spark-legacy-delta-registry.md` (row E2).
- Out of scope: the runtime's claim/queue machinery, the docs' other sections, any redesign.

## Yuzu context specific to this task
- Relevant docs: `docs/yuzu-guardian-design-v1.1.md` §24, the F3 orphan-exit invariant
  (catastrophic-if-violated): no C++ teardown while any detached worker is alive; the hazard it
  names is worker code running libc/OpenSSL/libsystemd/Win32-RPC through DSO teardown.
- Key invariant: `active_worker_count()` must be bound to the PHYSICAL count (issue #4147), never
  the early quota release `submit()` performs when `fn()` returns.
