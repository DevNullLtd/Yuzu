# Final corrections review: feat/instructions-membership-cache (2026-11-22)

- **Reviewed SHA (final HEAD):** `96940e85c0968e1e4ace24726505a78c6454a5dd`. Every reviewer in the last round confirmed it with `git rev-parse HEAD`.
- **Last tested source:** `47dd31527d`. At that commit the Linux suite passed 97/97 focused PostgreSQL cases and 31/31 Meson server-suite entries (`linux-test-evidence.md`).
- **Since the last tested source:** one commit, `eb583eef1b`, which changes only `//` comment text in `result_set_store.cpp`, plus docs and governance files. No build was re-run for it. Three reviewers independently confirmed that no token outside a comment changed.
- **Production behaviour:** unchanged in this pass.
- **Not touched:** `tests/unit/server/test_result_set_store.cpp`. Its fix, `1f0c89b02e`, was committed by the separate session.
- **External actions:** none. Nothing was pushed, published or merged, and no issue was filed.

## Commits in this pass

| sha | content |
|---|---|
| 47dd31527d | con-r3-1: the phantom `result_set.gc_sweep` audit row is marked "Not written". The comment bound is restored to `5000 x kMaxMembersPerSet` (cs11-01; perf-14 refuted). ADR-0036 now has a per-server ceiling, measured WAL and no dangling perf-12 pointer. server-admin.md gains a GC pass-size paragraph (er11-1) and "every server stopped" (er11-2). |
| cf497f7691 | The run ledger and resource ledger are committed under `governance.d/`. The first 131 rows are byte-identical to the scratch ledger; the addendum findings and the fixes are appended as superseding rows. |
| 2233c3739a | The ADR regression is stated by rows per pass (arch-c1). The scope-walking lead-in contradiction is fixed (SEC-1, also consistency-1). The resource ledger is completed with the fix-4 rows, the tests' PgPool/PgConn objects and 1f0c89b02e (cpps-1, policy floor). |
| 8891179889 | Ledger rows for the above. |
| eb583eef1b | The ADR, the comment and the manual cite only reviewed Gate 8 measurements (con-f1, A4-4). The regression condition is stated exactly: both the summed `device_count` above 5M and an uncapped pass that would have fitted the timeout (A4-1, A4-2). The unmeasured example is removed (A4-3). The resource-ledger later-commits list is completed (I-1). |
| 96940e85c0 | Ledger rows for the above. |

## Numbers now in the docs and comment (all reviewed Gate 8 evidence, 2026-11-21)

- **5M-row pass time, with the v7 trigger:** 3.13–3.35 s (`gate8-performance-r3.md`), and 3.65 s in a second reviewer's run (addendum perf-r4).
- **Uncapped pre-budget query:** a 20M-row pass took 13.35 s (`gate8-performance-r3.md`).
- **WAL:** 939 MB per full 5M-row pass with 36-character device IDs, on PostgreSQL 16.16 (perf-r4-3). The figure depends on ID length and full-page writes.
- **Drain ceiling:** at most 5,000,000 server-counted member rows per pass, one pass per server per 5-minute tick, so 60M an hour per server. Passes never overlap (advisory try-lock), but each server takes its own. These come from the code (`server.cpp` `kGcEveryNTicks`, `background_jobs.hpp` ReplicaSafe).
- **Withdrawn:** my own unreviewed 2026-11-22 runs. They were 4.1 s for 1,000×5,000, 824 MB with 12-character IDs, and 87 s / 7.5 GB for an uncapped 40M-row pass. They also carried a checkpoint condition. All are withdrawn as unreviewed. They survive only as history in ledger rows, where the superseding row withdraws them. The onset point where the uncapped query exceeded the timeout is stated as "not independently measured".

## Independent reviews

| round, HEAD | reviewer | verdict | findings, disposition |
|---|---|---|---|
| 1, cf497f7691 | enterprise-readiness | PASS | none |
| | compliance-officer | PASS | none |
| | sre | PASS | none |
| | docs-writer | PASS | none |
| | security-guardian | PASS | SEC-1 LOW, fixed in 2233c3739a |
| | consistency-auditor | PASS (1 LOW) | consistency-1 = SEC-1, fixed |
| | architect | PASS (1 LOW) | arch-1, recorded as arch-c1 (id collision), fixed |
| | cpp-safety (+cpp-expert) | FAIL (floor) | cpps-1, Resource Ledger omission (policy floor; INFO by derivation), fixed in 2233c3739a |
| | performance | did not finish | Its session ended before it reported. Disputed figures were then reduced to reviewed evidence. |
| 2, 8891179889 (evidence only) | compliance-officer | PASS | none |
| | consistency-auditor | PASS (1 LOW) | con-f1, fixed in eb583eef1b |
| | cpp-safety | PASS | I-1 INFO, fixed; I-2 INFO (shared_ptr in agent_registry, not a ledger resource), no change |
| | architect (+performance) | PASS (4 LOW) | A4-1..A4-4, fixed in eb583eef1b |
| 3, 96940e85c0 (evidence only, Gate 8 rule 4 on the final fix diff) | architect (+performance) | PASS | none |
| | cpp-safety (+cpp-expert) | PASS | none; the C++ change is comment-only, and the Resource Ledger is complete |
| | compliance-officer | PASS | One NICE note: `orch-process-r3` stays `open`. That is deliberate; see below. |

The reviewers were subagents of this session. Their independence is asserted, not enforced.

## Ledger

- **File:** `governance.d/d3e45ade99-result-set-membership-cache.8zrqzB.jsonl`, 182 rows.
  - The filename matches `run_id`, and rows 1–131 are the scratch ledger byte for byte.
  - Every later write is an append. One uncommitted draft was regenerated twice before any commit: once for a reporter value that failed lint, once for an id collision. Nothing committed was rewritten.
- **Checks:** `scripts/ci/check-governance-ledger.py --files`: OK, lint clean. Step-4 park check: exit 4 (clean).
- **Resource ledger:** `governance.d/d3e45ade99-result-set-membership-cache.8zrqzB.resource-ledger.md`. Final cpp-safety verdict: complete.
- **con-r3-1** (HIGH, BLOCKING): raised open at d3e45ade99, fixed at 47dd31527d. The fix was re-reviewed by consistency-auditor, docs-writer, compliance-officer and security-guardian.
- **perf-14:** superseded as `refuted`, with file:line evidence in `refuted_by`.

## Open and untracked: no issue authorized, not valid deferrals

These are recorded `open` with no issue number. Before merge each needs an owner-authorized issue (`deferred-to-issue #N` / `roadmap-#N` / `linked-to-#N`) or an owner ruling.

- **SHOULD F3** (I7, E5): no test separates the replica clock from the database clock for expiry; this needs a clock seam. Genuine, unchanged by this pass.
- **SHOULD perf-12** (I5+I8, E3): the drain ceiling is 5M server-counted member rows per pass, 60M an hour per server.
  - It drains less than the pre-budget query whenever the oldest 5,000 expired sets' summed `device_count` exceeds 5M and that query's pass would have fitted the 30 s timeout. Sustained creation above the ceiling grows the backlog.
  - Genuine. Its summary has been corrected (the earlier "5k–40k members" was wrong).
- **NICE, recorded open:**
  - corr-2: the test-only `std::vector<std::thread>` emplace-throw case, in the test file this pass may not edit.
  - sre8-1, cs10-2 and the other open NICE rows listed in run-report.md.
  - orch-process-r3: the process record, deliberately left open as a status row.

## Remaining before merge

1. Owner decision or issues for F3 and perf-12 (and the open NICE rows).
2. Optional: a Linux rebuild at 96940e85c0. Only comment text and docs changed since the tested 47dd31527d.
