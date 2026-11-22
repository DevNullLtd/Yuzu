# Gate 8 addendum: independent coverage of the final head (2026-11-21)

- **Branch:** feat/instructions-membership-cache.
- **Head reviewed:** `d3e45ade99cf43b586508d8582eceff529fd603e`. Every reviewer confirmed it with `git rev-parse HEAD` before starting.
- **Scope:** the four final commits that run-report.md (deviation 4) lists as checked by the author only:
  - `07eb23ab56`;
  - `0980d0e513`;
  - `e084d7b0cf`;
  - `d3e45ade99`.

  The earlier Gate 8 rounds covered `0bfddb1e17` and everything before it.
- **Mode:** every review was read-only. Nobody edited a source file, committed, filed an issue or ran a custom-linked test. The parent session is running the normal Meson tests. One exception: the performance reviewer measured SQL on a throwaway local PostgreSQL 16.16, reached over a socket only, and deleted it afterwards.
- **Who wrote this:** the governance orchestrator session (Claude Opus 5.5). The orchestrator is the same party that authored these commits. Each reviewer below ran as a separate subagent with no conclusions handed to it. It is a separate run, but that independence is asserted, not enforced (the same caveat as deviation 5 in the report).

## Routed-concern walk for the final four commits

| Changed path | Rows matched | Agents dispatched |
|---|---|---|
| `server/core/src/result_set_store.cpp` (comments only, including inside `migrations()`) | C++ conventions; C++ ownership; Server storage substrate (PostgreSQL); Clock-guarded retention | cpp-expert, cpp-safety, architect, sre |
| `tests/unit/server/test_result_set_store.cpp` | Unit-test conventions | quality-engineer |
| `docs/adr/0036-*.md` | PostgreSQL substrate; docs-writer row | architect, docs-writer, performance (to check the truth of the numbers) |
| `docs/scope-walking-design.md` | Scope walking (audit chain, cross-operator authorization) | architect, consistency-auditor, security-guardian |
| `docs/clock-guarded-retention.md` | Clock-guarded retention | cpp-safety, sre, compliance-officer |
| `docs/user-manual/server-admin.md` (runbook) | docs-writer row; Gate 6 operator-visible change | docs-writer, sre, enterprise-readiness |
| Every change | Gate 2 | security-guardian, docs-writer |

- **Not dispatched:** happy-path and unhappy-path, because no logic or error path changed: the C++ edits are comments and test data. Chaos was not re-run either, because no behaviour changed.
- **Tables walked:** all four routed-concern tables. No access-control, security-posture or software-estate row matched.

## Independent outcomes

| Agent | Verdict | Findings |
|---|---|---|
| security-guardian | PASS | sg11-1 INFO (pre-existing roadmap wording); sg11-2 INFO (long line) |
| docs-writer | PASS | doc-g11-1..4 NICE |
| cpp-safety | PASS | cs11-01 INFO (false comment); cs11-02 INFO (long line) |
| cpp-expert | PASS | cx11-1 INFO (long line); cx11-2 INFO (false comment) |
| quality-engineer | PASS | qe11-1 INFO (= cs10-2, still open) |
| architect | PASS | arch-r7-1 INFO (false comment; refutes perf-14's "fixed" disposition); arch-r7-2 INFO (untracked `perf-12` pointer in the ADR) |
| consistency-auditor | **FAIL** | **con-r3-1 HIGH (BLOCKING)**; con-r3-2 INFO; con-r3-3 INFO |
| performance | PASS | perf-r4-1 LOW; perf-r4-2 INFO; perf-r4-3 INFO; perf-r4-4 INFO |
| sre | PASS | sre11-1 LOW (= sre8-1, still open); sre11-2 MEDIUM, non-blocking |
| compliance-officer | PASS | comp11-1 INFO |
| enterprise-readiness | PASS | er11-1 MEDIUM, non-blocking; er11-2 LOW |

### Confirmed independently (what the author checks claimed)

- **`07eb23ab56` is comment-only.**
  - The edit to `migrations()` is a `//` comment block at lines 300–327. It sits before the v7 raw string, which opens at line 328, so no SQL text or function body changed. The boot-time trigger check is unaffected.
  - Confirmed by security-guardian, cpp-safety and architect.
- **`e084d7b0cf` test assertions are sound** (quality-engineer, cpp-safety and cpp-expert, by reading the code).
  - `ResultSetStore::get` (`result_set_store.cpp:649`) has no TTL filter. The expired survivors are therefore visible, so the `CHECK` and `CHECK_FALSE` survivor assertions are meaningful and not false-green.
  - The pass sequence 1, 2, 1, 1, 0 follows from `n = 1 OR rows_through <= $3`.
  - An exclusive `<` fails pass 2, and so does the pre-fix query, so the test pins both.
  - `would_wipe` never trips.
  - **qe10-1 and qe10-2 are independently confirmed closed.**
- **`e084d7b0cf` removal of the phantom GC audit row at `scope-walking-design.md:158` is correct.**
  - `server.cpp:20384-20390` only increments `yuzu_result_set_gc_total` and logs at info. Confirmed by security-guardian, compliance-officer, architect and sre.
  - The false claim already existed on origin/dev (compliance-officer). **comp8-1 is confirmed fixed at line 158, but not tree-wide; see con-r3-1 below.**
- **arch-r6-1 (best-effort wording) is confirmed fixed** (architect, consistency-auditor). Every statement of the budget now scopes it as best-effort.
- **`0980d0e513` deadlock runbook text is accurate and is not I4.**
  - The lock order checks out: the member row is locked first, then the header; the sweep takes the header first, then the cascade.
  - Confirmed by consistency-auditor, security-guardian and sre.
- **The owner/superuser narrowing in `07eb23ab56` is correct PostgreSQL behaviour** (enterprise-readiness, sre).
- **`d3e45ade99`, the 3.1 s and 60M/h figures:**
  - The 5M-row timing reproduced at 3.65 s on other hardware.
  - The 5-minute cadence and one pass per tick are confirmed (`server.cpp:20105-20106`, `:20384`). The 60M/h figure is per replica (perf-r4-4).

### New findings on the final head

**BLOCKING — con-r3-1 (HIGH).**
- **Defect:** `docs/scope-walking-design.md:415`, the §9 audit-action table, still lists `result_set.gc_sweep | success | Aggregate row, written once per sweep with the count`.
  - No emitter exists anywhere in the tree. I re-checked by grepping for `result_set\.gc_sweep`: the only hit is this doc line.
  - Line 158 of the same doc now says "no audit row is written".
- **Derivation:**
  - TRIGGER: every accepted GC pass.
  - IMPACT: I6, raised under clause (a), false assurance: an audit control is advertised as in force and is not.
  - EXPOSURE: E0.
  - EPISTEMIC STATUS: verified.
  - Derived band: HIGH.
- **Provenance:** pre-existing (origin/dev line 380). Provenance is band-neutral under the skill. The fix commit whose stated purpose was to "drop the phantom GC audit row" left this copy in place, and it lies inside Gate 8's domain for that commit.
- **Fix:** a one-line doc edit. Delete the row, or mark it "Not written: counted in `yuzu_result_set_gc_total` only".
- **Not yet done:** this review made no edits. The fix must be made and then re-reviewed by consistency-auditor and docs-writer. Changing this band would need a non-author adjudicator in `adjudicated_by`; none was sought.

**False comment introduced by `d3e45ade99`** (cs11-01 = cx11-2 = arch-r7-1 = con-r3-2 = perf-r4-2; INFO/NICE, five independent reporters).
- `result_set_store.cpp:1577` says "5000 sets of any size (a background fill is bounded only by the fleet)". That is false.
  - The only production caller of `materialize()` reads at most `kMaxMembersPerSet` rows (`result_set_members.hpp:79,93`).
  - On truncation it calls `mark_failed` (`server.cpp:20330-20346`).
  - `insert_row_impl` caps at line 547.
- The removed wording, "up to 5000 x kMaxMembersPerSet", was correct, and the new comment contradicts `clock-guarded-retention.md:53`.
- **Consequence for the ledger:** **perf-14 should not stand as `fixed`.** Its premise is refuted by evidence from a reviewer who is not its author, so its supersession should be `refuted`, with these file:line references as `refuted_by`. The comment also needs reverting to the earlier wording.
- One security-guardian note (sg11-2) called the new claim consistent with the code. It is outweighed by the five traced refutations above.

**ADR range wrong** (perf-r4-1 LOW, verified; con-r3-3 INFO, which independently reached about 1k–9.7k).
- `ADR-0036:427` says "for sets of 5,000 to 40,000 members". That turns the earlier "5M to ~40M rows per pass" into members per set.
- The true regression range is about 1,000 to 8,000 members per set. Above roughly 8k the uncapped pass timed out and drained nothing, so the cap there is a pure gain.
- perf-12's stated scope inherits the same error.

**Other non-blocking findings:**
- **WAL figure under-reads** (perf-r4-3, INFO): the reviewer measured 939 MB per 5M-row pass with 36-character device ids. The figure depends on id length and on full-page writes.
- **Drain ceiling and WAL cost are only in the ADR**, not in the operator manual (er11-1 and sre11-2, MEDIUM, I7, non-blocking; doc-g11-4 NICE).
- **"Servers stopped" advice versus HA** (er11-2, LOW).
- **No signal for a budget-limited pass** (sre11-1, LOW; = sre8-1, still open).
- **Untracked `perf-12` pointer in the ADR** (arch-r7-2 and doc-g11-3, INFO). No issue exists, and the run ledger is not committed under `governance.d/`.
- **Line-length and wrap nits:** cx11-1, cs11-02, sg11-2, doc-g11-1 and doc-g11-2. The clang-format CI job is commented out (`ci.yml:895`), so nothing gates on them.
- **Measurements undated** (comp11-1, INFO).
- **Roadmap "audit polish on every state transition" wording** (sg11-1, INFO, pre-existing).
- **`id` tie-break still untested** (qe11-1 = cs10-2).

## The two open SHOULD items (F3, perf-12) do NOT meet the deferral requirements

This addendum does not treat them as validly deferred.
- **What Gate 7 requires:** every valid non-blocking finding must end recorded. That means fixed, filed (`deferred-to-issue #N`), linked to an existing issue (`linked-to-#N`), or parked (`roadmap-#N`, under the two parking constraints).
- **Where they stand:** both rows are `disposition: "open"` with no issue number. "Untracked deferral" is not a disposition in the schema. Both remain **open findings, not deferrals**.
- **F3** (I7, E5, SHOULD). It carries no I1/I2/I3, so parking is permitted in principle. It still needs an issue (`roadmap-#N` or `deferred-to-issue #N`) filed, or an existing one identified, plus the dedupe probe and a superseding row before merge. Constraint 2 (escalate on second sighting) cannot be checked until the dedupe probe runs.
- **perf-12** (I5, I8, E3, SHOULD). The same requirements apply. In addition:
  - its scope statement and the ADR sentence citing it are numerically wrong (perf-r4-1) and should be corrected first;
  - performance attached conditions to the recommended fix: loop only while the previous pass hit its budget; a wall budget of at most about 10 s, or a dedicated thread; a WAL or pass cap;
  - the ADR's "an open follow-up" points at nothing a reader can follow (arch-r7-2).
- **Who must act:** both require filing authority, which this run was not given. The owner must authorize the issues, or rule otherwise, before merge.

## Remaining conditions before merge

1. **Fix con-r3-1** (`scope-walking-design.md:415`) and re-run consistency-auditor and docs-writer on the fix diff, per Gate 8 rule 4. **This blocks merge.**
2. **Revert the false comment** at `result_set_store.cpp:1577` to the `kMaxMembersPerSet` bound, wrapped at 100 columns. Supersede perf-14 as `refuted`. Re-run cpp-safety and cpp-expert on that diff (it is comment-only, but rule 4 is about domain, not size).
3. **Correct ADR-0036:427** to about 1,000–8,000 members per set, along with perf-12's summary. Optionally:
   - state the WAL figure as a range;
   - say the 60M/h ceiling is per replica;
   - replace the dangling "perf-12" pointer.
4. **F3 and perf-12** each need a terminal Gate 7 disposition (file, link or park, with an issue number) and a superseding ledger row. Until then they are open SHOULD findings.
5. **Ledger:** append superseding rows for con-r3-1 (open, BLOCKING), perf-14 (`refuted`) and the new findings above, then re-run `check-governance-ledger.py` and the park check.
   - The skill's default is a fragment committed under `governance.d/`. This run's ledger lives only in `/private/tmp`, and that should be decided explicitly. This addendum did not modify the existing ledger file.
6. **Tests:** the Linux Meson server suite at `d3e45ade99` (`[result_set]` including `[gc]`, and `test_echo_rename_migration_pg`) is still outstanding.
   - linux-test-evidence.md covers only `a20119b06c` and `9e98085a7e`.
   - The new GC row-budget test and the v7 trigger SQL have still not run through the C++ code paths.

## Verdict

**Gate 8 on the final head: FAIL.** One blocking finding is open: con-r3-1, HIGH, verified. Once it is fixed and re-reviewed, every other independent review returned PASS. The final four commits are otherwise confirmed, with the corrections listed above.

The run is not merge-ready until conditions 1–6 are met.
