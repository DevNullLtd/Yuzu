# PR #2697 (AuditStore -> PostgreSQL) — governance handoff

**State as of 2026-08-06 (round 3 complete):** branch `pg/audit-store`, head `2adfda9e`,
worktree `/home/dgr/yuzu-audit-pg`. **Nothing pushed.** 31 commits authored on this branch
(first-parent, no-merges) past the pushed head `31452b85`. Working tree clean.

**Round 3 (this session) is DONE — Phase 1 (code) and Phase 2 (docs) of the governing plan
(`/home/dgr/.claude/plans/how-do-we-get-ethereal-sunbeam.md`) are both complete:**
- **1a** Marker authority — holder-side fingerprint verification (`a1dc268c`), implementing
  Sol's diagnosed fix shape. Fable-reviewed afterward (independent, adversarial): confirmed
  sound, confirmed the deviation from Sol's literal "fail every sourceless boot" rule is
  deliberate and defensible (a never-booted-on-new-binary holder is a known, deferred,
  fleet-level detection gap, not a hole in this fix).
- **1b** Reconciliation integrity — `PQcmdTuples` + fingerprint completion check (folded into 1a).
- **1c** Corrupt legacy file typed tri-state (folded into 1a).
- **1d** Retention clock authority — PG's own clock inside the advisory-lock txn, not the
  caller's (`e3f77a18`); self-caught a false precedent claim in its own comment next commit
  (`4586964b` — result_set_store.cpp does NOT already do this, verified by reading it).
- **1e** Five round-2 fix-round defects: MCP `query_audit_log` limit clamp (`ce8962ba`),
  "nothing was deleted" universal qualified (`30ea8b3d`), `YuzuAuditRetentionCapBinding`
  threshold re-derived for the 5s re-arm (`79733544`), NUL-truncation in the meta-copy path
  (`243a6d02`), one-shot lockout docs (`c7695a7c`).
- **1f** Performance — `ORDER BY/LIMIT` rewrite of the survivor probe (`0dd16d3b`); measured
  locally (5M-row scratch table) rather than re-citing the prior agent's unverified figures.
- **Fable follow-up** (`fb121eff`): a real code fix Fable's review caught — marker-present path
  failed OPEN on a filesystem stat error where the marker-absent path fails closed; fixed +
  tested (symlink-loop repro).
- **Phase 2 docs consolidation**, six commits (`8dd12ddb`, `fe33b219`, `c17d0d63`, `c4168f6a`,
  `6c721bed` + the ADR/upgrading fixes folded into 1a/1e): biggest finding was the drain-rate
  "sustained ceiling" quoted in FIVE docs (including the SOC2 customer-facing sizing doc) was
  ~700x too conservative — every doc quoted only the quiet-operation cadence (6.9 events/s) as
  if it were the hard ceiling, ignoring the 5s backlog-recovery re-arm (measured ceiling: up to
  ~5,000/s). New runbook `docs/ops-runbooks/audit-store-backfill-recovery.md`. Playbook +
  ADR-0040 gained the ladder-wide normative rules.
- **CI fix** (`2adfda9e`): found running `meson test --suite docs` as a final check —
  `flake-retry.py`'s shard-filter selftest pin had gone stale relative to `66a55fcc` (earlier
  in this same branch), a real policy-floor test breakage. Fixed.

Every code fix has red-green mutation-test proof in its own commit message. Full server suite
(4 shards, live PG 18) and `docs` suite (8/8) both green at current head.

**STILL OWED before this can merge** — Phase 3/4/5 of the governing plan, not started this
session: Gates 4/5/6/6b/8 have never run on ANY of round 3's diff (round 2's Gate 3 blockers
are what round 3 fixed; round 3 itself is ungoverned). `quality-engineer` (mutation-sweep,
must run alone/isolated). `build-ci` (meson.build/tests/meson.build changes never reviewed).
Windows re-verify on DGRHP — has NEVER run on this branch since `c10fcc68`, before every
round-2 AND round-3 fix. Deferred issues not yet filed (sibling-store marker-authority gap for
ManagementGroupStore/ResultSetStore — now ALSO includes ResultSetStore's clock-divergence gap,
found while fixing 1d; Sol's conflict-equality reconciliation; the still-open cpp-safety trio;
etc. — see ROUND 3 section below for the fuller list, re-triage before filing since some may be
fixed now). **Ask Dave before running governance** (standing rule — checkpoint before the
spend) and **before pushing** (separate standing rule, always).

Do NOT work in `/home/dgr/Yuzu` — that is Dave's dirty tree on another branch.

## Commits on top of the pushed PR

| sha | what |
|---|---|
| `e586a2a8` | Windows CI fix: finalize the streaming `SqliteStmt` before `sqlite3_close_v2` so the legacy `audit.db` move-aside can rename |
| `7432b4d1` | 4 fixes from a Kimi+Codex adversarial review (prefix proof, sample-pool cap, WAL sidecars, length-aware legacy read) |
| `d928d8ec` | merge `origin/dev` (218 commits) + carry two controls the port had dropped |
| `c10fcc68` | arm the advisory-lease test so it can actually fail (Gate 3 QE blocker) |
| `2e5b1625` | A-1 + A-2: no native audit row before the backfill marker; sourceless exits stamp only over an empty table |
| `65d98216` | PERF-1: retention probe back to an EXISTS pair (was a full scan) |
| `71ee717d` | A-3: alert on an observable symptom; `metrics.md`/`upgrading.md` corrected + abandon procedure |
| `ead4f84c` | non-blocking truth fixes this diff caused (cpp-expert F2/F3, A-5, QE-2, QE-3) |
| `3631f04e` | adversarial review: pre-seed the metric families the A-3 alert keys on, + 2 LOWs |

## Verification already done (re-derive before trusting)

- Linux full server suite at head `3631f04e`: **87352 assertions / 4588 cases**, all four
  shards OK, live PG 18. (87169 / 4584 at `c10fcc68`; the delta is the four new tests.)
- Windows MSVC (DGRHP): `[audit_store]` **3419 assertions / 43 cases**, exit 0 — but that
  was at `c10fcc68`, BEFORE the four blocker fixes. It does NOT cover this head.
- Red-green: reverting the three code fixes with tests kept produced exactly 5 red cases,
  one per fix. The 4th #2579 test correctly stayed green (it asserts the trigger does NOT
  fire), so the set discriminates rather than merely tracking.
- The ORIGINAL Windows CI failure (`test_audit_store.cpp:440`, exit 42) was measured
  red -> green on native MSVC.

- **Independently re-derived by Gate 3 `quality-engineer`**, which reverted each of the
  three fixes itself, rebuilt, confirmed red, and restored: sec-F1 -> 3 of the 4 #2579 cases
  fail; sec-F2 -> the contiguous-id case fails with 50 rows of evidence destroyed; F4 ->
  plaintext `hunter2` leaks. It cleared them as genuinely coupled, not false greens. It also
  cleared `anchor_guard()` as honest (the `!has_expired -> None` short-circuit means the
  empty-table pass reaches a real verdict) and confirmed PG advisory locks are per-database,
  so the fixed lock-key string is not a cross-job hazard.

### Verification NOT completed — redo this

- **Windows CI shard-B filter** (`[pg]~[routes]~[store]~[token]`) on the merged head. It was
  still running at handover and I stopped it to restore Dave's rig. `[audit_store]` passing
  is the narrower result; shard B is what the CI leg actually runs.

## Governance run: where it stopped

Gate 1 written; **Gate 2 done** (both findings fixed); **Gate 3 done** (5 agents:
security-guardian and docs-writer at Gate 2; cpp-safety, cpp-expert, quality-engineer,
architect, performance at Gate 3). **Gates 4, 5, 6, 6b, 7, 8 NOT RUN.** Gate 3 produced 4
blockers, so Gates 4/6 were deliberately not launched — they would review a diff that was
about to change. All five Gate 3 blockers (QE's plus the four) are now fixed; the fix diff
itself has had NO gate run over it, which is what item 2 below is for.

Rule-file currency: re-checked 2026-08-05 — `CLAUDE.md`, `.claude/routed-concerns.md` and
`.claude/skills/governance/SKILL.md` all match `origin/dev` in the WORKING TREE. Re-check
before the next wave (`git diff --quiet origin/dev -- <path>` per file, working tree not
commit).

## Blockers: CLOSED (2026-08-05)

All four are fixed and committed. What follows REPLACES the original finding text
(this file is untracked, so that text is not recoverable from git); it states
what was done and how it was proven. The ledger fragment owed at Gate 8 still
needs one row per finding — write it from the commit messages, which carry the
reproductions.

### PERF-1 (performance) — retention probe was a full table scan — `65d98216`
`audit_store.cpp` now runs an EXISTS pair instead of `count(*) FILTER (...)`, and
`expiring == 0` became `!has_expired`. Re-measured independently on PG 18, a
5,000,000-row `audit_events` with 5,000 rows carrying `ttl_expires_at > 0`, after
`VACUUM ANALYZE`. The scratch table was hand-mirrored from `kMigrations` (same column set
and the same partial index), NOT created by the store itself: old shape `Parallel Seq Scan`, 61,729 buffers, 196.966 ms; new
shape two `Index Only Scan`s, 6 buffers, 0.034 ms. (The Gate 3 numbers were
253.9 ms / 0.084 ms on their own data — same conclusion, different cache state.)
The dev citation checks out: `origin/dev:server/core/src/audit_store.cpp:728`.
**Deliberately NOT done:** the finding's second half, moving the anchor stamp out
of the transaction. Doing so would let one transient probe failure advance the
stored reading without the pass reaching a verdict — the erosion #2579 exists to
prevent (`bootstrap_settled` is settled separately for exactly that reason).
Rolling the whole pass back is the fail-safe; the fix for "the probe keeps
failing" is the probe that no longer scans. Argued in the commit message — a
re-reviewer who disagrees should read that before re-raising.

### A-2 (architect) — one-shots wrote native rows before the marker — `2e5b1625`
Both call sites go through `open_one_shot_audit` (`main.cpp`), which runs the
idempotent backfill before the store can log. Verified end to end on live PG 18
with a 5-row legacy `audit.db`: pre-fix binary left native row id=1, zero marker
rows and `audit.db` in place; the next run refused with the prefix-proof
diagnostic (whose remediation offers to clear `audit_events` — the break-glass
row). Post-fix: 5 rows streamed, marker stamped, file moved aside, break-glass
row written as id 6, exit 0; on the already-poisoned database it refuses and
exits 1. ADR-0040 now states the rule (`ead4f84c`).

### A-1 (architect) — sourceless exits stamped over a non-empty table — `2e5b1625`
Both "nothing to migrate" exits (no legacy file; legacy file with no
`audit_events` table) now go through `complete_without_source`, which stamps only
over an empty table and otherwise fails closed. The crash-resume path is
untouched — it has a source, so it never reaches the guard; the comment that
previously argued no such guard could exist was corrected in place. Red-green:
neutering `pg_rows_before > 0` fails exactly the two new cases (4 assertions) and
nothing else **within `[audit_store]`** — that mutation was never run against the full
server suite, so "nothing else" is scoped to that tag, not to the suite (rule-5 correction,
2026-08-05; the earlier unscoped wording is in `2e5b1625`'s message and is over-broad). Operator-facing half is in `upgrading.md`, including the abandon
procedure for an unrecoverable trail (which carries BOTH statements
`stamp_complete` runs — a hand-stamped marker without the `setval` wedges the first live
write; MEASURED 2026-08-05 on a scratch PG 18 database, not inferred from the code comment:
backfilled ids 1..5 via `OVERRIDING SYSTEM VALUE`, then a plain INSERT ->
`duplicate key value violates unique constraint "audit_events_pkey", Key (id)=(1)`).

### A-3 (architect) — the fail-closed boot condition was unobservable — `71ee717d`
Premise re-derived: `run()` returns at its first `startup_failed_` check, before
`bootstrap_default_certs()` and long before the web listener, so `/metrics` is
never served on that path. The rule now keys on
`absent_over_time(yuzu_server_audit_backfill_total{result=~"completed|fresh"}[15m])`
and both its comment and description state what it cannot see (one wedged replica
among healthy ones is a down instance, not this alert; the boot log is primary).
`metrics.md` and `upgrading.md` corrected to match. Nothing in CI lints the rules file
— all 23 files in `.github/workflows/` were enumerated, none references
`promtool`/`yamllint`/`prometheus`, and the only plausible candidate (`docs-lint.yml`) runs
CHANGELOG-order, issue-doc and changelog-fragment checks. No promtool in this environment
either; it parses as YAML (62 rules), no more.

## CLOSED after the handover was first written

- **QE Finding 1 — BLOCKING, fixed in `c10fcc68`.** The advisory-lease test
  (`test_audit_store.cpp`, "a sibling holding the advisory lease skips the pass quietly")
  never called `anchor_guard()`, so it declined for the missing anchor rather than the lock:
  every assertion passed for the wrong reason and the test stayed green through a lock that
  did nothing. Proven both ways — replacing `pg_try_advisory_xact_lock(...)` with `true` left
  it PASSING before the fix and FAILS it after. This was self-inflicted: an `anchor_guard`
  had landed there via a scripted edit matching the wrong construction and I removed it as
  misplaced without checking whether the test needed one.

- **QE Finding 2 MEDIUM / QE Finding 3 LOW / A-5 MEDIUM / cpp-expert F2+F3 INFO — fixed in
  `ead4f84c`.** `docs/test-coverage.md`'s AuditStore row rewritten to what the file now
  covers; the four #2579 tests moved to `YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl)` (46
  cases / 3583 assertions still green, 10.1s); ADR-0040 now names all five prefix-proof
  aggregates AND states the two rules A-1/A-2 turn on; `audit_retention_rules.hpp` no longer
  cites the deleted `bootstrap_pending_` (and its "sole producer" clause is gone —
  `result_set_store.cpp` builds the same Facts with `no_anchor` pinned false);
  `audit_store.cpp` says five guard facts, matching `serialize_facts`.

## OPEN NON-BLOCKING (verified by their reporters)

- **QE Finding 4 INFO** — no test drives `migrate_from_sqlite` against a legacy `audit.db`
  whose `audit_events` exists but is EMPTY (only "no file" / "no table" are covered); and
  nothing bounds `SUM(timestamp)` in the prefix fingerprint on a pathologically large table.

- **A-4 MEDIUM** `server.cpp:10002-10005` — degraded `total_count()` laundered into
  `arr.size()`, so a degraded total silently reports the page size. Contradicts the
  never-a-false-empty contract. Also `"data":null` where siblings use `"meta"`.
- **cpp-expert F1 LOW** `rest_api_v1.cpp:4574-4582`, `mcp_server.cpp:307,3488` — negative
  `limit` reaches PG as `LIMIT -1`, failing the query and letting a client drive
  `yuzu_server_audit_read_degrade_total{reason="query_error"}`. Sibling route clamps; this
  one does not.
- **cpp-safety LOW** — `start_cleanup()` is not idempotent in the non-jthread arm
  (`std::thread` move-assign over a joinable thread is `std::terminate`); the comment at
  `audit_store.cpp:1098` claiming no spdlog formatting runs under the lock is untrue (nine
  sites format inside the advisory-lock txn); the batch bound is per-row not per-byte.
- **cpp-safety SHOULD** — no test calls `start_cleanup()`/`stop_cleanup()`; join-on-destroy,
  double-stop, stop-during-pass and the non-jthread arm are all unexercised.
- **cpp-safety INFO** — `legacy_has_table` binds `SQLITE_STATIC`; fine today, UAF for a
  future `std::string(...).c_str()` caller.
- **perf INFO** — backfill call site `audit_store.cpp:613` passes `r.detail` from a
  `const auto&`, forcing one copy per row; `std::move` it.
- **Resource Ledger correction** — actual counts are 10 lease sites, 19 `PgResult`,
  6 `SqliteStmt` (Gate 1 said 9/18/5). Two borrowed boundaries were omitted: the
  `MetricsRegistry*` from `set_metrics`, and the `AuditStore*` borrowed into
  `agent_service_`/`gateway_service_`/`fleet_topology_store_`.
- **Not this PR's regression** — reaper ceiling is 25000/pass x 1 pass/hour ~= 6.9 events/s
  sustained; constants unchanged from the SQLite predecessor, but PERF-1 makes it likelier
  to bite. Worth its own issue.

## Adversarial review of the FIX commits (2026-08-05, after the blockers closed)

Kimi (dynamic, live PG) + Codex (gpt-5.5 high, PG-blocked by its sandbox) reviewed
`c10fcc68..ead4f84c`. Synthesis: `/tmp/advrev-2697-fix/SYNTHESIS.md` (tmp — copy it if
it matters). Both found ONE defect, and it was mine, introduced by the A-3 fix:

**The re-keyed alert pages on every routine restart.** Nothing described or pre-seeded
`yuzu_server_audit_backfill_total`, and an already-migrated server returns at the marker
check without reaching an outcome — so a HEALTHY restarted server exports no
`completed`/`fresh` series and the critical absence rule fires. Kimi graded HIGH and
BLOCKED; Codex MEDIUM and PASSed. Fixed in `3631f04e` (pre-seed both closed label sets in
`AuditStore::set_metrics`, + a test; red-green: disabling the seed fails that one case, 8
assertions, **within `[audit_store]`** — same scope caveat as the A-1 mutation above). Two LOWs fixed with it: the one-shot retention default (365 vs
`cfg.audit_retention_days`) and the `sqlite3_step` HELP text.

Both reviewers confirmed all six author claims, including the anchor-stamp judgement call
and the single-construction-site universal. Neither could build Windows.

## Governance run 2 (2026-08-05) — Gates 1/2/3 + Gate 7 DONE, ledger written

Ledger: `governance.d/2697-audit-store-postgres.jpGglq.jsonl`, 33 findings — 6 BLOCKING,
9 SHOULD, 17 NICE, 1 REJECTED. 21 fixed, 11 deferred to issues, 1 rejected.

Agents run: Gate 2 `security-guardian` + `docs-writer`; Gate 3 `architect`, `cpp-expert`,
`cpp-safety`, `quality-engineer`, `performance`, `cross-platform`. **Gate 3 was launched
before Gate 2's security agent returned**, so Gate 3 saw only the docs findings — that makes
them independent reporters rather than downstream echoes, which is why the total-laundering
defect carries `independent_reporters: 3`.

### Fix commits (Gate 7)

| sha | what |
|---|---|
| `39a36740` | write gate on an incomplete backfill (cs-1); sourceless stamp policy + in-txn emptiness re-check (A-4); retention re-arms on a binding cap (PERF-2) |
| `4920db87` | negative limit is a 400, not a degrade (sec-F1); degraded `total` is null (sec-F3/ce-F1) |
| `66a55fcc` | `[audit_store]` moved to the lighter Windows PG shard (CP-1) |
| `003578ac` | ADR's invented ADR-0038/0039 precedent, four false comments, live-path sanitisation, meta integer detector |
| `6bdd1bc7` | probe-shape guard (the PERF-1 fix had NO test), empty-legacy-table path |
| `cc303f9f` | the run ledger |

### The shape that cost this round

Three blockers were the SAME defect class as fixes I had already made, one door along:
A-4 is the empty-table twin of A-1 (I closed stamping over ROWS); cs-1 is the boot-path twin
of A-2 (I closed the CLI path); sec-F3 was filed LOW in the previous round and came back as a
3-reporter BLOCKING. `[[feedback-fix-commit-ships-next-defect]]` — fix the SINK.

### Process defect this run produced (`proc-1`)

Three Gate 3 agents were given write access to ONE worktree. cpp-safety built from
quality-engineer's in-flight mutation and drew a false conclusion from it; a phantom
`TEST_CASE` from a stale object file appeared in a full-suite run. QE discarded and redid all
four mutations under a clean-tree discipline after I warned it. **Next run: give every
mutating agent its own worktree.** I then made a worse version of the same mistake myself —
`git checkout -- <file>` to revert a mutation, which wiped ~120 lines of uncommitted
implementation in that file. Commit before mutating; revert the mutation, not the file.

### STILL OWED before this PR can pass

1. **Gate 8 re-review** — the fix diff touches `audit_store.{cpp,hpp}`, `main.cpp`,
   `server.cpp`, `rest_api_v1.cpp`, `mcp_server.cpp`, `tests/meson.build` and six docs, so
   the re-trigger set is essentially the whole Gate 2+3 roster plus `build-ci` (meson) and
   `sre` (retention cadence + alert text).
2. **Gates 4, 5, 6, 6b have NEVER run on this PR.**
3. **Windows**: shard B has never run on this branch, and the only Windows run at all was at
   `c10fcc68`, before every fix. The shard rebalance does not discharge this.
4. **11 deferred findings to file as issues** — PERF-3/4/5/6, A-7, A-10, docs-3, ce-F6,
   qe-A2gap, CP-2, CP-3, plus the still-open cpp-safety items (non-idempotent
   `start_cleanup`, the false no-spdlog-under-lock comment, per-row batch bound,
   `SQLITE_STATIC`).

## ROUND 3 — Gates 4/6/8 findings + Sol's verdict (2026-08-05, session end)

Head is still `cc303f9f`; NOTHING from this round is fixed. Sol's full opinion is saved beside this
file at `.claude/plans/pr2697-sol-opinion.md`.

### Sol's verdict, which I agree with

**Stop polishing `Sourceless`.** The rule that matters:

> No process may declare "no legacy audit trail exists" based only on its local filesystem.

A host-local absence of `audit.db` cannot prove deployment-wide absence, and a server boot has no more
authority to claim it than a CLI one-shot does. That declaration needs either positive proof from a
valid source, or an explicit durable deployment-level attestation. Documentation + a WARN cannot repair
an information deficit — and in Kubernetes nobody controls which replica starts first.

Sol's model: a real migration state (`awaiting_source` / `copying` / `verified` / `no_legacy_attested`
/ `needs_repair`), where only `verified` and `no_legacy_attested` permit serving and native writes, and
only an explicit operator/install-time authority can create `no_legacy_attested`.

**THIS IS LADDER-WIDE, not an audit defect.** I checked after reading Sol:
`ManagementGroupStore::migrate_from_sqlite:995` has the identical `if (!legacy_exists)` -> "marking
complete (fresh install)" shape, and that store is the AUTHORITATIVE confinement substrate.
`ResultSetStore:349-367` too. The fix belongs in ADR-0012 / `docs/postgres-store-playbook.md` as the
recipe, not only here. **Check this before doing anything else in round 3.**

### Round-3 blockers (none fixed)

Marker authority (Sol + architect F1 + UP-5 + enterprise-readiness), and note the detection gap
enterprise-readiness found: the replica that SKIPS its migration takes `spdlog::debug` at
`audit_store.cpp:410-413` with NO `backfill_metric()` call, so the loss is invisible on the host where
it happens — wrong host, wrong log level, and masked fleet-wide in the alert. A cheap detector exists
regardless of the redesign: at the marker-present return, if a legacy file IS present, that is
"I hold a trail and I am not migrating it" -> WARN + a distinct metric label.

Reconciliation (architect F2, sharpened by Sol): the completion check is a bare `COUNT(*)`
(`:846`/`:869`), and `inserted += batch.size()` at `:768` is unconditional after
`ON CONFLICT (id) DO NOTHING` — so the count of rows OFFERED is reported as rows inserted and nothing
observes the discard. Sol's stronger point: five aggregates check id/timestamp SHAPE, not event
identity; two rows can share id+timestamp and differ in principal/action/detail. For mandatory
evidence, conflicts need exact equality on the canonical row.

Corrupt/zero-length legacy file treated as a fresh install (UP-1, measured; Sol concurs — needs a typed
`Present`/`Absent`/`Error`, because a parse error is never an absence).

Cross-replica clock divergence (UP-2, sec-F4). Sol's class-level fix is better than anything proposed:
take retention decisions and `last_pass_now` from POSTGRES's clock inside the advisory-lock
transaction, so every sweeper compares one authority. He grades it HIGH/SHOULD, below silent loss.

Marker loss locking out boot AND break-glass (UP-6). Sol's correction: the "clear
audit_store.audit_events" advice is at `:610`, the source-present prefix-mismatch path, not the
sourceless one; and "permanent" means no product-path recovery, not irrecoverable.

MY OWN fix-round defects: MCP `query_audit_log` now returns a silent empty page (the `"minimum":1` I
added is never validated — `compiled_input_schemas().at().validate()` has ONE call site, `:3203`,
inside `if (requires_approval(...))`, and `AuditLog:Read` never requires approval); the replacement
"every site means NOTHING WAS DELETED" universal is false for the thread-boundary catch; the 5s re-arm
mis-arms `YuzuAuditRetentionCapBinding` (6 increments in ~30s trips a 6h rule); the meta branch
NUL-truncates via `reinterpret_cast` + implicit `strlen` (the correct idiom with
`sqlite3_column_bytes` is 40 lines above at `:663`); one-shots now refuse on a never-booted host.

Docs: the drain-rate ceiling is falsified in FIVE shipped docs, each line read rather than
pattern-matched: `audit-log.md:630`, `upgrading.md:1183`,
`enterprise-readiness-soc2-first-customer.md:260`, `yuzu-alerts.yml:905`,
`audit-store-clock-guard.md:127`. (docs-writer said nine; its count included `server-admin.md:2180`,
which is about pacing and remains true. `audit-log.md:547` likewise.) The runbook is the worst of
them: `:133` tells an operator to compute a backlog drain estimate from the stale figure and open an
engineering ticket with that number.
`audit-store-clock-guard.md` is cited by three shipped alerts and diagnoses SQLite throughout.
`auth-db-recovery.md:318-326` tells an operator the break-glass row lands in `<data-dir>/audit.db` and
describes SQLite auto-creating a fresh one — false, on a recovery path. `rest-api.md` documents neither
breaking change. The changelog omits the live-write sanitisation fix.

PERFORMANCE MEASURED my re-arm justification and it is wrong. THESE ARE THE AGENT'S MEASUREMENTS,
not re-derived by me — re-run them before treating any figure as load-bearing. A capped pass with a
real backlog is **169 ms mean / 465 ms max**, not the 41-49 ms I cited (that figure was measured with no backlog — the
only state the re-arm never runs in). It also measured **9.3 MB WAL per pass = 1.80 MB/s = 6.5 GB/h**
at the 5s cadence, which my comment does not mention. The PERF-3 `LIMIT 1` rewrite I deferred as LOW
takes the pass to **59.5 ms** and removes a 57-465 ms non-determinism (`synchronize_seqscans`) — it is
now the fix that makes my own justification true.

### Gate status
Gate 8 re-review: security-guardian, architect, cpp-safety, docs-writer, performance DONE.
Gate 4: all three DONE. Gate 6: sre, compliance-officer, enterprise-readiness DONE.
NOT run: `build-ci` (tests/meson.build), `quality-engineer` (must run ALONE — it mutates),
Gate 5 chaos (warranted: 15 UP entries + 7 consistency findings), Gate 6b synthesis.

cpp-safety Gate 8 also flagged the round-2 Resource Ledger correction (line 217 above) as
now further stale: 1a's holder-verification branch (`audit_store.cpp`, marker-present +
legacy-file-still-here path) added a fourth `SqliteDb` — `verify_db` — never counted
anywhere. It is RAII (opens `SQLITE_OPEN_READONLY`, closes at scope exit, no manual
cleanup), so this is a ledger-completeness gap, not an ownership defect — recorded here
rather than in `audit_store.cpp` itself, since the Resource Ledger lives in the Gate 1
summary/handoff doc, not in code comments.

## Still to do

1. ~~Fix the four blockers~~ — DONE (`2e5b1625`, `65d98216`, `71ee717d`), plus the
   non-blocking truth defects this diff caused (`ead4f84c`) and the adversarial-review
   findings (`3631f04e`).
2. Re-run Gate 2 (`security-guardian` always, `docs-writer` — four docs changed) + every
   Gate 3 agent whose domain the fix diff touches: `architect` (A-1/A-2/A-5 are its
   findings), `performance` + `cpp-safety` + `sre` + `compliance-officer` (PERF-1 is a
   retention-behaviour change → the clock-guard routed row), `cpp-expert` (main.cpp +
   audit_store.cpp), `quality-engineer` (three new tests + a fixture swap).
3. Run Gates 4 (happy/unhappy/consistency), 5 if warranted, 6 (compliance-officer, sre,
   enterprise-readiness), 6b synthesis.
4. Gate 8 + write the ledger fragment `governance.d/2697-<slug>.<random>.jsonl` (one row per
   finding; `mktemp -u` + `noclobber`, NOT `mv`).
5. Windows re-verify after the fixes (the store changed again) — `[audit_store]` AND the
   shard-B filter `[pg]~[routes]~[store]~[token]`, which has never been run on this head.
6. Still OPEN and untouched: QE Finding 4, A-4, cpp-expert F1, the three cpp-safety items,
   the perf INFO copy, the Resource Ledger correction, and the reaper-ceiling issue.
7. THEN ask Dave before pushing. He has approved: adversarial review, the dev merge,
   filing #2798, and this governance run. He has NOT approved a push.

## Environment

- Live PG for tests: `export YUZU_TEST_ENABLE_PG=1
  YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu` (container
  `yuzu-advrev-2362-pg`, already up on BigColin, not mine).
- Adversarial-review synthesis: `/tmp/advrev-pr2697/SYNTHESIS.md` (survives until reboot;
  copy it if you want it durable).
- Filed this session: **#2798** (ADR-0009 rollback-window re-entry gap — the refuted
  "failed rename causes a rollback split" finding, re-scoped to the real ADR-level gap).

### Windows rig — already cleaned up, here is how to redo it

DGRHP is restored: `yuzu-pr3a` detached at `feffdbfa`, clean, scratch removed, and the
scratch Postgres container deleted. To verify again:

1. `docker run -d --name yuzu-pr2697-pg -p 100.74.176.116:5445:5432 -e POSTGRES_USER=yuzu
   -e POSTGRES_PASSWORD=yuzu -e POSTGRES_DB=yuzu postgres:18` (bind to the TAILSCALE ip —
   DGRHP has no local Postgres).
2. `git bundle create pr2697.bundle pg/audit-store ^origin/dev`, scp to
   `C:/Users/daver/`, then on DGRHP: `git fetch <bundle> 'pg/audit-store:pr2697-verify'`,
   `git checkout --detach pr2697-verify` inside `C:/Users/daver/yuzu-pr3a`.
3. `source ./setup_msvc_env.sh > log 2>&1` (REDIRECT, never a pipe — a pipe runs it in a
   subshell and the PATH exports are lost), prepend the MSVC `Hostx64/x64` dir to PATH,
   `vcpkg install --x-install-root=<wt>/vcpkg_installed`, `meson setup build-windows
   --reconfigure -Dcmake_prefix_path=<wt>/vcpkg_installed/x64-windows -Dbuild_tests=true`,
   `meson compile -C build-windows yuzu_server_tests`.
4. Run the exe with `build-windows/tests` + the vcpkg `debug/bin` and `bin` dirs on PATH.
5. **RESTORE `yuzu-pr3a` to `feffdbfa` and delete the container when done.**

Gotchas that cost time this session: non-login MSYS bash has no coreutils on PATH (export
`/usr/bin:/bin:/c/Program Files/Git/cmd` at the top of every script you send over); piping
a long remote build through `tail` locally buffers until it ends, so you see nothing; and
`LNK1318: Unexpected PDB error; LIMIT (12)` means the DISK IS FULL, not a PDB size limit —
C: runs at 95-100%.

## ROUND 3 — CLOSED (2026-08-06)

All gates now green at HEAD `de7b8325` (52 commits ahead of `origin/dev`). Sequence this
session: fixed the 10 Gate 3/4/6/8 findings from the fix-diff re-review (`70ecfd3f`,
`67110894`, `b8bb6c57`, `7568318d`, `9531d4c3`) → ledger pass_ordinal 2+3 (`57f98bb6`) →
`quality-engineer` mutation pass ALONE (clean, 5/5 closures solid red-green, 0 false-green,
worktree confirmed restored) → Gate 5 `chaos-injector` (`780fdcc1`, one genuine P0 — F1,
below) → Gate 8 re-review of the F1 fix, 6 mandatory agents in parallel (routed-concern:
PostgreSQL server-store change unconditionally requires `architect`+`sre`) → three
independent reporters (`architect`, `cpp-expert`, `cpp-safety`) converged on a second
BLOCKING finding inside the F1 fix itself → fixed → ledger pass_ordinal 4+5 (`780fdcc1`,
`de7b8325`).

**F1 (Gate 5 chaos-injector, fixed `11936b34`+`3609a2f8`):** the whole-file reconciliation
scan (an unqualified full-table aggregate over `audit_events`) silently inherited the
connection pool's fixed 30s `statement_timeout` — `kBackfillTxnTimeout`'s name and comment
claimed a wider deadline, but that parameter only ever bounded the pool-ACQUIRE wait, never
statement execution. At the documented target scale (tens of millions of rows, #2661) this
was a wall the mandatory, boot-blocking backfill would hit identically on every retry, and
`startup_failed_` blocks the whole server, not just audit. Independently re-derived
HIGH/BLOCKING (I5 raised via reproducible-unavailability-on-an-ordinary-path, E0). First fix
cut hand-rolled `BEGIN`/`SET LOCAL`/`COMMIT`/`ROLLBACK` via bare `pg::exec_params` — three
Gate 8 reporters independently caught that this violates the "non-RAII manual cleanup in new
C++" policy floor (this codebase already ships `pg::PgTxn` + `pool_.with_txn` for exactly
this shape, used 3x elsewhere in the same function; architect traced a cleaner precedent,
`SoftwareLicensingStore::count_stale_agents`, than the one the first cut cited). Rewritten to
use `pool_.with_txn` + `PgTxn`.

**Incident, not a finding:** during the Gate 8 parallel review, one of the six agents'
tool use (Bash or Edit — not conclusively identified, but only `cpp-expert` of the six had
write access) deleted 101 lines from `server/core/src/pg/pg_raii.hpp` (all of `PgConn`'s
move-assignment/`get`/`release`/`reset` plus the entire `PgTxn` class), an UNRELATED file no
agent was asked to touch. Caught by `security-guardian`'s out-of-scope flag, confirmed via
`git diff`, and restored via `git show HEAD:<path>` + `Edit` (NOT `git checkout --`, which
the permission classifier correctly blocked as a destructive op) — reconstructed
byte-for-byte, verified identical to HEAD, full build (143/143) + `[audit_store]` suite
re-confirmed green before continuing. No code from this incident shipped; nothing to revert
in the commit history since it was never staged. Lesson for next time a mutating agent runs
alongside review-only ones: even a single mutating agent among several sharing one worktree
carries the same risk `proc-1` (round 1) already flagged — give it an isolated worktree.

**Deferred (recorded in the ledger, not blocking):** chaos-injector's B1 (no fault-injected
severed-connection test), A3 (no test forces an exception through `run_cleanup`'s
try/catch), C1 (benign concurrent-reaper-vs-backfill race worth naming in the runbook), C2
(orphan-fingerprint provenance-label gap in the abandon procedure); Gate 8's test-coverage
gap for the new transaction's failure branches; sre's open question on whether 60s remains
sufficient at the extreme end of documented scale. Plus everything already carried from
round 2/3's "OPEN NON-BLOCKING" list above (QE Finding 4, A-4, cpp-expert F1, the cpp-safety
trio, PERF INFO, the reaper-ceiling issue) and the ladder-wide sibling-store deferral
(ManagementGroupStore/ResultSetStore holder-verification porting, Sol's conflict-equality
reconciliation).

**Full Linux verification at HEAD `de7b8325`:** `[audit_store]` suite 66 cases / 4004
assertions green; full server suite 4608 cases / 87765 assertions green.

**Still owed:** Windows verification on DGRHP (never run since `c10fcc68`, before every
round-2/3 fix), file the deferred issues above, then ask Dave before pushing (NOT yet
authorized — governance was, push was not).

## ROUND 3 — fully closed (2026-08-06)

Windows verification done (DGRHP, MSVC 19.44): clean build, `[audit_store]` matches Linux
exactly (66/4004), PG shard B fully green (614 cases, first time it's ever run on this
branch), PG shard A green except 2 pre-existing SCIM-route flakes confirmed unrelated
(network-PG-latency artifact of the verification setup, not this PR's code — investigated,
traced to a 5s client timeout on a 5000-member seeded test, matches an established flake
class in `feedback-green-on-bigcolin-isnt-green-on-ci.md`).

Asked directly whether all governance had run — built the actual gate matrix instead of
answering from memory and found a real gap: the first fix batch (`70ecfd3f`/`67110894`/
`b8bb6c57`, including the HIGH-severity fingerprint-race fix) never got its own Gate 8
domain re-review. Closed it with the full 6-agent set: no BLOCKING findings (architect gave
a formal proof the fix is correct), 4 SHOULD-tier gaps, all fixed (`6e7f384c`). Ledger now
80 rows across 7 passes.

**Deferred issues filed** (dedupe-probed, all clean; `governance-deferred` label on all six):
- #2820 — AuditStore read-path performance (`total_count()`, unsargable `action LIKE`, O(n²) OFFSET pagination). P2.
- #2821 — Port holder-verification + retention-probe fixes to ManagementGroupStore/ResultSetStore (Sol's ladder-wide diagnosis + A-7). P1.
- #2822 — 4 test-coverage gaps (fault injection, exception path, A-2 order contract, txn-failure paths). P2.
- #2823 — CI: macOS has zero PG test coverage; one test mistagged out of shard B. P2.
- #2824 — Audit-degrade error envelope inconsistent (REST sites + REST-vs-MCP). P2.
- #2825 — 3 operational-hardening follow-ups (concurrent-reaper race, orphan provenance label, reconciliation-timeout margin). P2.

Two originally-ledgered items were re-verified and NOT filed: `PERF-3` is already fixed
(the LIMIT-1 rewrite landed via `0dd16d3b`/1f, after that ledger row was written); `ce-F6`
(claimed 10 duplicate `PgTestTemplate` definitions) appears stale — the class is a single
shared, build-once, keyed definition in `test_helpers.hpp`, not duplicated. Recorded as
corrections rather than silently dropped (ledger pass_ordinal 7).

**Final state:** 57 commits ahead of `origin/dev` (55 as of the last governance ledger
commit, +1 for that commit, +1 for this one), full Linux suite green (4608 cases / 87768
assertions), Windows-verified, nothing outstanding known to be blocking. Not yet pushed —
awaiting Dave's go-ahead.
