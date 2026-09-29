# Governance ledger - Guardian C0 journal relocation (PR #2345, issue #2298)

This file exists because it did not. Two earlier governance rounds on this branch ("Gate 8",
"Gate 8b") are cited by name in commit messages with no verdict recorded anywhere in the tree, so
a reader could confirm only that the author said they ran. Gate 6 compliance called that a CC7.2
traceability failure and it was the blocking finding of this run.

**Standing rule adopted here, PROSPECTIVELY: from this run onward, no commit may cite a gate
number that is not independently recorded in this file.** The existing citations of "Gate 8" and
"Gate 8b" - in five commit messages and around twenty in-tree comments - are grandfathered and
remain unrecorded, because their verdicts are not recoverable. Reading the rule as already
satisfied by this tree would be exactly the kind of false claim it exists to stop.

## Run

| | |
|---|---|
| Range | `85711833..c869ee72` (37 commits) at review time; fixes landed on top |
| Reviewed HEAD | `c869ee72` |
| Date | 2026-07-22 |
| Gates | 2, 3, 4, 5, 6 (13 agents) + two external reviewers |
| Verification | build exit 0; 13/13 meson targets; `[guardian]` 274 cases; TSan `[guardian]` 0 warnings |

Authorship note, because it bears on how much weight the earlier rounds carry: this range was
written across seven rounds by **multiple separate agent sessions in the same worktree**, one of
which reverted another's mechanism wholesale (`a42eddcf`). Round N+1 silently contradicting round
N is the characteristic failure of that arrangement, and this run found several instances.

## Verdicts

| Gate | Reviewer | Verdict |
|---|---|---|
| 2 | security-guardian | PASS with findings; no CRITICAL/HIGH |
| 2 | docs-writer | PASS; 1 SHOULD |
| 3 | cpp-expert | PASS; no BLOCKING |
| 3 | cpp-safety | No BLOCKING; 3 SHOULD |
| 3 | quality-engineer | 1 BLOCKING (coverage) |
| 3 | performance | Nothing merge-blocking; 3 HIGH at flip |
| 4 | happy-path | 1 finding (downgraded, see below) |
| 4 | unhappy-path | 15-entry risk register |
| 4 | consistency-auditor | 1 BLOCKING (hollow test) |
| 5 | chaos-injector | Triage: 11 NOW / 3 FLIP / 3 DROP |
| 6 | compliance-officer | 1 BLOCKING (this file) |
| 6 | sre | PASS; 4 flip-blockers |
| 6 | enterprise-readiness | PASS conditioned on the changelog correction |

**Every code-level finding is capped by dormancy.** `prefer_spark_` is hardcoded false at a single
call site (`agent.cpp`), independently verified by three agents. Nothing found here can affect a
shipped agent.

## Fixed in this run

| Finding | Source | Commit |
|---|---|---|
| Steady-state re-send of already-delivered batches | happy-path (+ operator report) | `0fff861d` |
| Hollow head-of-line guard (window floor made it vacuous) | consistency-auditor | `0889bf0e` |
| `erase_persisted_prefix` wrap destroying the staging buffer | quality-engineer | `0889bf0e` |
| False restart-survival claim (customer-facing) | enterprise-readiness | `1106fe1c` |
| False first-cycle-death claim in `metrics.md` | docs-writer | `1106fe1c` |

Earlier in the same session, before the gates ran: backward-clock replay freeze and the
cutoff-published-before-delete stranding (`c21aa154`, from external review), and the pre-join
persist test plus two contradictory comments (`97da3f12`, `5791aa0b`).

## Findings raised and NOT fixed

Tracked, not forgotten. All are unreachable while dormant.

- **sec-M1** the clock guard does not carry its anomaly state across a restart. Precisely: the
  latch re-arms (it defaults to declined-nothing), but an agent that re-arms Guardian rules at
  startup persists fresh in-retention records before the first retention pass, and one of those
  makes the would-this-wipe-everything test false, while the large-step-since-last-pass test has
  no previous pass at boot. So on a restored VM with rules deployed nothing declines. An earlier
  wording of this finding - including mine, twice - said a restart alone disarms it; that is
  wrong, and the distinction is the whole mechanism.
- **sec-M2** stale replay cutoff surviving prune's early returns.
- **sec-M3** prune and page order future-dated rows oppositely.
- **sec-M4** shutdown classification under-reports the loss indicator. Gate 5 DROPped a test for
  it: in-memory counter only, needs a new mid-loop seam.
- **sec-M5** read boundary caps entry count, not row byte size.
- **UP-1/2/3/5/6/9/11/12** un-quarantinable rows; quarantine off-gauge; no integrity binding on
  rows; per-key `exists()` on the delivery thread; reconnect backlog vs replay rate; false
  `evicted_no_send_evidence`; persist wedged by a key collision; disk-full triple bind.
- **UP-4** `send_exception_count()` and `lifecycle_backpressure_drops()` reach no heartbeat tag.
  Confirmed by me: referenced only in tests. Highest-value cheap fix outstanding.
  **DELIVERED** on branch `feat/guardian-journal-observability` (alongside flip-checklist item 5):
  wired both into the journal family as `yuzu.guardian_send_exceptions` and
  `yuzu.guardian_journal_backpressure_drops`, with fleet rollups and metrics.md rows.
- **compliance** provenance-backfill throw can OVER-report the audit-gap counter.
- **performance** P1 RSS ratchet (5 -> 206 MiB, permanent); P2 per-batch tokens vs per-record
  cost; P3 re-arm floor below pass cost.
- **sre** rollout control is a compile-time bool with no kill switch; liveness needs two gauges.

### Reconciled against origin after the review (merge `93367961`)

The gates above reviewed `85711833..c869ee72` while this branch was 29 commits behind origin.
Merging revealed that some of what they recorded as open had already shipped:

- **Flip item 4, the `yuzu_fleet_guardian_*` rollup, is DONE** (PR #2334), with 18 Guardian
  journal rules in `docs/prometheus/yuzu-alerts.yml`. Gate 6 sre called this BLOCKING-for-flip
  on the grounds that nothing aggregated the per-agent tags; that objection is answered. Its
  alerting recommendations should be read against the rules that actually landed, not against
  a blank page.
- The rollup ships a static assertion binding the journal stats field count to the gauge table.
  It caught four fields this branch added that origin had never seen - the two counters from
  this run plus the drain/sweep exception split. The merge auto-resolved with ZERO textual
  conflicts and still broke the build, which is the most useful thing in this section: on this
  subsystem a clean merge is not evidence of a correct one.
- Findings from the gates that touch fleet-visibility (security F5 and consistency #7 on
  `skipped_already_sent`, sre's alerting set) predate the rollup and should be re-read against
  it before anyone acts on them.

Gate 5's triage is the spec for these: each NOW item names its seam, its vacuity-proof
precondition, its observable, and the production line whose removal must turn it red.

## Rejected, with reasons

Recorded because a rejected finding that leaves no trace gets re-raised every round.

- **K3 and security-guardian: "the post-join persist comment is false, nothing stages during
  `stop()`."** Accepted after initially rejecting it. I argued staging happens from `on_event` on
  the scheduler lanes; that call path does not exist. `enqueue_lifecycle_locked` has exactly two
  callers, `attach_rule` and `detach_rule_locked`, both under `mtx_`, which `stop()` holds
  throughout.
- **unhappy-path UP-10: "`stop_all_guards_locked()` mints disarm records after the join."**
  Rejected. It stops legacy `IGuard` objects only; `detach_all()`, which does stage, is called
  from the `apply_rules` full-sync path, not from `stop()`.
- **happy-path's BLOCKING severity on re-send-all.** Downgraded on the arithmetic - the token
  bucket bounds it to ~1 batch/10s, not once per 30s cadence - then fixed anyway on operator
  direction, because bounded and documented is not the same as justified at fleet scale.
- **K3's token-overdraft fix.** Implemented, then reverted: charging after the break hands out a
  free batch per pass and roughly doubles the replay rate. The negative balance is correct
  accounting. The rationale is now a comment so it is not "fixed" again.

Three reviewers, including me, reasoned from a plausible call path around `enqueue_lifecycle_locked`
that does not exist. That function deserves a comment naming its two and only two callers.

## Open

`docs/guardian-c0-thread-reloc-design.md` carries the flip checklist (14 items). This run adds
candidates not yet folded in: completeness reconciliation, retention-period governance sign-off,
tamper-evidence risk acceptance, customer-assurance-package update, per-cohort rollout with a
kill switch, and headroom-blocked telemetry. Issues #2360, #2361, #2364 track the retention and
size-biased-loss work.
