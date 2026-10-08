# #5459 option D implementation brief (2026-10-06)

Worktree: /home/dgr/yuzu-5459d, branch fix/5459-optionD-retry-suppression, off origin/dev 56ea4db8a
(+ cherry-picked repro commit 88dc5f14f: tests [5459a]/[5459b]/[5459control]/[5459probe]; the
`set_drain_to_persist_hook_for_test` commit e6e230813 is DELIBERATELY NOT carried: dead under D, drop [5459c]).
`vcpkg_installed` is a symlink to /home/dgr/Yuzu/vcpkg_installed: never `git add -A`; stage explicit paths.

READ FIRST (in full): ~/.claude/plans/spark-5459-optionD-retry-suppression-KICKOFF.md (design, delete/adapt
list, test dispositions, docs list, known limits) and ~/.claude/plans/spark-5459-astra-d-suppress-opinion.md
(Astra's source-read of the suppress condition). This file only records Step 0 CORRECTIONS and stage plan.

## Step 0 result (verified vs origin/dev 56ea4db8a; spark code + tests byte-identical to kickoff base c9ffc9087)
75/85 confirmed. Design is sound; no dangling production caller after the delete
(`reapply_count`/`kReapplyWaiverThreshold`/`reapply_count_for_test` live only in guardian_arm_ack.{hpp,cpp};
`can_advance` callers engine.cpp:1081,1700; `decide_retry` engine.cpp:1378 only; `begin_application` engine.cpp:696,1397).

### Corrections to the kickoff
1. Test cite: the K-funding characterization to DELETE is test_guardian_spark_runtime.cpp:14850
   (`#4472 characterization (ACCEPTED COST): reapply_count saturated ...`). :14890 is the #4472 tripwire
   `compensation_finished is written with the pop, never alone` = KEEP.
2. #5403/#5404 age/deadline gauges are claim/runtime-scoped (compensation_deadline set once, runtime.cpp
   ~1453) and do NOT dip on a forced Reapply. Only yuzu.guardian_arm_pending/failed (ledger arm_stats) are
   Application-scoped. Do not repeat the kickoff's claim in docs.
3. #4045: persisted baselines are re-seeded on every arm (engine.cpp ~2450-2462). Only Spark-first-captured,
   unpersisted FileHashEquals baselines are exposed to a forced Reapply. Word the known-limit that narrowly.
4. Moved lines: can_advance cpp:369-387 (conservative branch 370-375, K branch 376-386); decide_retry cpp:429-486;
   server.cpp agent_gen>=current at 5806; PostK4472Rig K counter at test_guardian_spark_runtime.cpp:14264/14277
   (rig 14195-14309; helpers reapply_twice_while_wedged / third_reapply_with_compensation_outstanding) - every rig
   test (14312,14360,14850,...) depends on it; registry K prose at docs/spark-legacy-delta-registry.md :143/:145/:146.
5. Valve cadence: decide_retry has ONE production caller (apply_rules), so wedge_suppress_count counts pushes.
   Real spacing = 30 s heartbeat => max 10 suppressions ~330 s (275 s only at <=25 s heartbeat). Use 330 s in docs.
6. Default-path pin required: with prefer_spark_=false / nothing Accepted, decide_retry must still return
   Reapply on every path (spark_runtime_ is wired unconditionally; decide_retry is live regardless).
7. Repro-branch hook `set_drain_to_persist_hook_for_test` is not carried. [5459a]/[5459b]/[5459control]/[5459probe]
   use `require_k_established()` / `establish_k()` (policy_generation()==5 + persisted 5): that precondition is
   FALSE by design under D. Replace with "generation held" (policy_generation stays at the old value, no ack),
   then assert: repeated identical pushes are Suppressed (watch count unchanged, Application survives), and the
   rule ends ARMED after the late failure via recovery drain / safety-valve Reapply, then ack happens.
   [5459b] CHECKs gen==5 at ~4461/4472/4478 and [5459control] gen==5 + persisted 5 (~4549-4550) must be restated
   against the held-generation model. `reapply_before_k(n)` now exercises Suppress: add positive assertions.
8. Test list additions beyond the kickoff (K/waiver mentions to re-word or fix):
   test_guardian_arm_ack.cpp: 184, 255-300, 323, 419-451, 642-693, 733, 807, 853-861, 937-956, ~1589 stale comment.
   test_guardian_engine_spark_reconcile.cpp: 3317-3318, 3378, 3393, 3725, 3770, 3896-3943, 4087-4091, 4354-4356, 4381;
   helper run_post_k_4472_scenario 3329-3418 (pushes identical gen-7 four times, asserts !acknowledged).
   test_guardian_spark_runtime.cpp: 10073-10126 (keeps receipt_wedge_k_eligible: keep accessor), 14178-14239,
   14408-14467, 14509-14518 (needs compensation_pending false), 14591, 14604, 14669.
   test_guardian_arm_ack.cpp :742 uses content "content" (non-sha256): the new "ack after suppressed pushes"
   assertion needs a 64-hex content_id. :1324 add decide_retry==Reapply right after ~1370 (popped, sticky Wedged).
   :459 retitle but KEEP the persist-retry assertion (~480).
9. Unlisted doc/comment sites to update: docs/metrics.md :1591 :2187 :2190 (the "generation lag unreliable once
   K-waiver fires" caveat INVERTS), docs/user-manual/upgrading.md :3465, server/core/src/guardian_arm_fleet_tags.hpp:101
   (check tests pinning the text), agents/core/include/yuzu/agent/guardian_engine.hpp:359, guardian_arm_heartbeat.hpp
   :12 :49-57, guardian_arm_ack.hpp :30-41 :85-92 :195-208 :243-246 :364-389, guardian_arm_ack.cpp :114 :131-157 :204-255
   :263-331 :376-386, guardian_spark_runtime.hpp ~722 ~1261 ~1415-1530 ~1755 ~1824-1849, runtime.cpp ~841 ~1437 ~1870
   ~2307-2331, engine.cpp comments ~1358-1369 and ~1678-1699 (describe empty-pending as the only Reapply reason).
   Design doc: prose at :678-682 :707-716 :900-1056 :1008-1012 :1052-1056 :1096-1102 plus :474 :494-500 :554 :586
   :654 :668 :1065 :1118 :1323. Flip gate: :855-860 :882-910 :911-927 (#5459 precondition) :928-947 (reapply_count
   funding) :952-983 AC-1 :984-992 AC-2 :997-1000 AC-4; follow-ups line :1013 (from #5509, merged) stays.
   Registry rows :143 :145 :146. guaranteed-state.md :462 (+:464 cross-ref).
10. Changelog: NEW fragment changelog.d/<PR#>-<slug>.<section>.md (do not reuse 5497-4472-...). Governance record:
   NEW governance.d file, not an append to the 4472 one. PR number unknown until opened: do not invent one.
11. No open PR conflicts with this work.

## Stages
- Stage 1 (production + arm_ack unit tests; ONE agent, serial): guardian_arm_ack.{hpp,cpp} (delete waiver,
  conservative can_advance, restructured non-const decide_retry, wedge_suppress_count + safety valve max 10,
  compensation-aware retention in BOTH drain loops), guardian_spark_runtime.{hpp,cpp} (WedgeAwareStatus.
  compensation_pending, RecoveryStatus::CompensationPending via one private helper under registry_mu_),
  engine.cpp comments. test_guardian_arm_ack.cpp dispositions per kickoff + corrections above.
- Stage 2 (parallel after stage 1 builds green): (2a) test_guardian_spark_runtime.cpp PostK4472Rig + tests;
  (2b) test_guardian_engine_spark_reconcile.cpp + repro [5459*] restated; (2c) docs/comments sweep (item 9).
- Checkpoint to SPARK CHAOS peer BEFORE governance: restructured decide_retry + compensation-aware status +
  repro tests adapted. Then full /governance (user's go required before any push).

## Rules
- Build: cap -j8; wrap in `systemd-run --user --scope -p MemoryMax=24G`; scratch on NVMe (~/yuzu-scratch), TMPDIR
  =~/yuzu-scratch/tmp for tests; never bare /tmp. Run `meson test -C build-linux --suite agent` targeted first.
- Tests: event-driven waits, tight bounds, no unnecessary long waits (shard F margin ~10%).
- No em-dashes in authored text; no competitor names; no "verified" claims without a run; no push/PR/commit
  attribution beyond the repo convention. Do NOT push. Commit locally only when told.
- Any deviation from the kickoff design: STOP and report; do not consult Astra/Fable without Dave's permission.
