# Governance run report — feat/instructions-membership-cache (Gate 7 fixes + re-review)

- Range: merge-base `ddb5649aba` .. `d3e45ade99` (use `git diff $(git merge-base origin/dev HEAD)..HEAD`;
  two-dot `origin/dev..HEAD` also shows unrelated dev commits).
- Prior run: `/private/tmp/yuzu-governance-a20119b06c` (ledger `a20119b06c-result-set-membership-cache.ZoKGgV`).
- Ledger: `/private/tmp/yuzu-gov-fix-cache12/d3e45ade99-result-set-membership-cache.8zrqzB.jsonl`
  (131 rows, self-contained: every prior finding carried forward with its final disposition).
  `scripts/ci/check-governance-ledger.py --files <ledger>`: OK, lint clean. Park check (`jq -e`): exit 4 (clean).
- Nothing pushed, published, filed or merged. All commits local on the branch.

## Verdict

**Governance review: no open BLOCKING finding, no policy floor open. Merge readiness is CONDITIONAL on
the Linux Meson server suite**, which this session could not run and whose results were not received.
Until those results arrive the run cannot be called a full PASS. In particular, the following SQL
has run only on scratch PostgreSQL, never through the C++ code paths:
- the migration v7 triggers;
- the boot check;
- the race test;
- the new GC row-budget test.

The adjudicator made every closure of the UP-1 class explicitly conditional on that run.

| mapped | fixed | re-cut | refuted | rejected | open |
|---|---|---|---|---|---|
| BLOCKING | 10 | 2 | – | – | 0 |
| SHOULD | 11 | – | – | – | 2 (F3, perf-12; untracked) |
| NICE | 58 | – | 1 | 13 | 34 (untracked) |

## Fix commits this pass (after 2742185310)

| sha | addresses |
|---|---|
| c1f1428e2a | arch-r5-1/2/3 |
| 3b19d0fbe3 | con-r2-1, con-r2-2, con-r2-4 (doc line) |
| 578c4514d3 | uh-1 (temp-space cost documented) |
| cc986cba7d | comp-1, er-1/2/3, doc-g8-1/2 |
| 07eb23ab56 | doc-g8-3/4 |
| 0980d0e513 | chaos-1 |
| 0bfddb1e17 | **perf-8R** (gc_sweep member-row budget, test, docs) |
| e084d7b0cf | arch-r6-1, comp8-1, sre8-2/3, qe10-1/2, cs10-1, doc-g8-5/6 |
| d3e45ade99 | perf-13, perf-14 (perf-12 stated in ADR) |

Earlier fix commits in this run: 9e98085a7e, be31e6fbda, 0530c2b018, 8766b4a7d9, 3725960929,
d4906a972d, 2742185310.

## Gates

- **Gates 1–3 and the earlier Gate 8 rounds:** see gate1-change-summary.md, gate2-*.md, gate3-*.md and gate8-*.md.
- **Gate 4:**
  - happy-path: PASS, no findings.
  - unhappy-path: PASS; uh-1 MEDIUM, verified and fixed by documentation.
  - consistency-auditor: PASS; one MEDIUM, fixed.
- **Gate 5:** chaos-injector PASS. R-1..R-8 hold; chaos-1 fixed.
- **Gate 6:** compliance, sre and enterprise-readiness all PASS; only LOW findings.
- **Gate 6b:** the orchestrator did the synthesis inline (a deviation).
- **Independent adjudication** (enterprise-architect): see adjudication-enterprise-architect.md.
  - sec-1: the floor applied to the original text and is now closed.
  - UP-1: HIGH stands; closed, with a documented owner-level residual.
  - sre6-1: closed.
  - uh-1: rejecting the design alternative was sound.
  - perf-8R: **gating**. It was then fixed in 0bfddb1e17.
- **Gate 8 on the perf-8R fix:** performance, cpp-safety (with cpp-expert), sre plus compliance, and
  architect plus QE plus docs all returned PASS, and all confirmed perf-8R closed.

### Routed-concern walk for the final fix diff

| row | matched by | agents run |
|---|---|---|
| Clock-guarded retention | `gc_sweep` changed | cpp-safety, sre, compliance-officer |
| PostgreSQL substrate | — | architect, sre |
| C++ conventions and ownership | — | cpp-safety, plus the cpp-expert brief |
| Unit-test conventions | — | quality-engineer brief |
| docs-writer row | — | docs-writer brief |
| Scope walking | design-doc GC row | architect |

No access-control, security-posture or software-estate row matched: no such file was touched.

## Behaviour now in the branch

The member cache is enforced by four ENABLE ALWAYS triggers on `result_set_store.result_set_members`:
- **INSERT and UPDATE:** statement-level, with transition tables. A bulk load costs one header write
  per set, never per row.
- **DELETE:** a BEFORE row trigger with a single-slot marker. A cascade writes nothing.
- **TRUNCATE:** re-stamps every set's generation.

Every INSERT, UPDATE and DELETE re-stamp locks the header row, pending sets included; TRUNCATE is
ordered by its own exclusive table lock instead. A boot check must find all four triggers in force,
or the server serves membership uncached and logs an error.

The restore and repair runbook covers:
- the writes that bypass the triggers, and restarting every replica after them;
- the repair SQL, which must run as the owning role, plus a query to confirm the trigger state;
- the deadlock between an out-of-band member DELETE and the sweep;
- a `temp_file_limit` of at least 12 MB.

gc_sweep now also bounds each pass at 5,000,000 summed `device_count`, always taking at least one set.
Callers see the same semantics as before, except for one documented behaviour change: an unpinned set
is refused as a scope from the moment it expires.

## Open, untracked deferrals (no issue authorized; recorded openly)

- **SHOULD:**
  - **F3:** no test can tell the replica clock from the database clock for expiry. It needs a clock seam.
  - **perf-12:** the GC drain ceiling is about 60M member rows an hour. For sets of 5k–40k members the
    old query drained up to 8× faster per pass when it fit. Recommended fix: run further passes in
    the same tick.
- **NICE/LOW, expiry siblings:** sec-3, dsl-1, dsl-2 and arch-r2-5 (sibling readers still serve
  expired sets); arch-r2-3 and con-r2-4 (two clocks).
- **NICE/LOW, logging and observability:** con-r2-3 (= UP-3, uh-3, sre7-1, comp-2: expiry is logged
  at ERROR in pre-existing code); uh-2 and sre7-2 (cache-off state shows only in a log line); sre-1
  (no cache metrics); sre8-1 (a budget-limited pass is not distinguishable in the log).
- **NICE/LOW, test gaps:** QE9-2 and chaos-2 (untested boot-check arms); QE9-3 (the temp test skips
  for a non-superuser DSN); cs10-2 (the `id` tie-break is not pinned).
- **NICE/LOW, other:** cs10-3 (a negative `device_count`); cs10-4; UP-2, UP-4, UP-5, UP-6 and UP-8;
  perf-3; sec-5; SG9-2; SG10-1; arch-r3-5; con-4; perf-7 (no description available).
- **Rejected:** sre-2 (configurable cache), per the owner instruction.

## Deviations (also recorded as `orch-process-r2`)

1. Agents were given the shared preamble as a file to read, not pasted inline.
2. The orchestrator did the Gate 6b synthesis inline.
3. This session built and tested nothing. It is a macOS host, and the server builds only on Linux
   (ADR-0035). Only `-fsyntax-only` against the worktree headers was run, plus SQL checks on scratch
   PostgreSQL 16 (and 17.10 and 18.4 for the boot check).
4. Four final commits were checked by the orchestrator only, with no fresh Gate 8 agent pass:
   - 07eb23ab56 (wording);
   - 0980d0e513 (one runbook sentence);
   - e084d7b0cf (the Gate 8 r4 reviewers' own suggested edits: docs, one comment, a test seed value
     and five survivor assertions; `-fsyntax-only` clean);
   - d3e45ade99 (one comment, one ADR sentence).
5. The adjudicator's independence is asserted, not enforced.
6. The first ledger file created this pass failed the per-fragment lint: its supersession rows were
   not self-contained. It was deleted before use and regenerated; the regenerated file is the only
   ledger.

## Test status

- The parent's Linux Meson server suite (`meson test -C build-linux --suite server`) has **not
  reported**. Required before merge:
  - `[result_set]`, including `[gc]` and the member-cache tests;
  - `test_echo_rename_migration_pg`.
- Scratch PostgreSQL 16 verification this pass:
  - the fill fails at an 8 MB `temp_file_limit` and passes at 12 MB;
  - the owner-role error text, and the trigger-state query output;
  - row-budget SQL semantics: a 1/2/1/1/0 pattern on a model of the test's data;
  - a 5M-row cascade takes 3.1 s;
  - reviewers' runs: chaos R-1..R-8, a 40/40 deadlock reproduction, and `pg_restore -j 4` round trips.
