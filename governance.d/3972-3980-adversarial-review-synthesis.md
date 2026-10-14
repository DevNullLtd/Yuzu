## Review - approving (no CRITICAL/HIGH); one Should-fix before the F14 flip

Range 0a4b60ac5..bab909086 (6 local commits, #3972 + #3980). Both reviewers (Kimi K3 dynamic, Codex Sol high) built the tree, ran the targeted agent and server suites, and reached the same verdict independently. No CRITICAL/HIGH finding. One MEDIUM contract defect found by both; three LOWs.

### Should fix
**S1. Leftover release allowance survives a lane-emptying transition** (found by both; adjudicated against source). `agents/core/src/guardian_outbox_drain_worker.cpp:351` checks `empty_epoch` only inside `else if (h.allowance == 0)`. Release sets `allowance = N` (:365-367) and resets `held_since`; the `blocked && allowance > 0` path never re-samples the epoch (epoch_at_hold is set only at the first denial, :395-399). So release -> one launch empties the compliance lane -> refill behind a still-older blocker spends the stale allowance with no fresh H. Contradicts the published GUARANTEE (`guardian_spark_runtime.cpp:4915-4919`: episode "ends when the lane ... empties", "a further overtake needs a further H") and design v3 2.7. Bounded: aggregate overtakes per release stay <= N, release is counted, `prefer_spark_` is false. Fix: when `blocked && h.allowance > 0` compare the lane's current empty_epoch with `epoch_at_hold`; on mismatch clear allowance and take the fresh-denial path. Add regression: release -> launch -> empty -> refill behind the same blocker -> a second H is required. (T4/T4b/T5 cover carry-over, no-blocker clearing, and empty-before-release, not this combination.)

### Minor
- **M1** `guardian_spark_runtime.hpp:1055` says "Nothing in production consumes these yet", but `wrapped_send()` consumes all four accessors (`guardian_outbox_drain_worker.cpp:329,357,398`). Truth drift; fix the sentence. (found by both after cross-exam)
- **M2** `changelog.d/0000-guardian-outbox-send-order-hold.fixed.md`: placeholder name; convention (`changelog.d/README.md:17-21`) and design v3 say `3972-...` until a PR exists. Rename now. (found by both after cross-exam)
- **M3** (Kimi only; Codex rebutted, adjudicated NOT a defect) no engine-level test for the `journal_stats().send_order_hold_releases` forward; design v3 5.4 explicitly sanctions review-only verification, same as `send_stalls`. State it in the PR body.

### Adjudication
S1: verified at the cited lines. Codex's "re-derives HIGH at the flip" is the flip-time derivation, not a present grade; kept MEDIUM. M3: Codex's rebuttal stands (design-sanctioned gap).

**Empiricism:** Kimi K3 `--dynamic --i-trust-this-input` (no static-fallback warning in either phase log); Codex Sol `--reasoning high`, workspace-write. Both: meson compile of yuzu_agent_tests + yuzu_server_tests, `[send_executor],[drain],[outbox]` (148 cases) PASS, `[spark],[guardian]` (1324) PASS, server `[guardian][journal][fleet]` (7 cases) PASS, plus lints. No ASan/TSan/MSVC/Apple-Clang tree available to either. Reviewed SHA bab909086 (local, no PR, nothing posted).

---
Dispositions recorded at commit time (the review above read bab909086): S1, M1, M2 fixed in e2f78656b; M3 closed by the engine-level journal_stats() forward test added in f62732bcd. This file is a derived synthesis of the Kimi K3 and Codex Sol reports, not their raw transcripts; the reviewers' phase files were in /tmp/advrev-3972-3980/ and are not committed. Ledger rows: governance.d/3972-3980-outbox-send-lanes.hGwmA3.jsonl (finding ids adv-s1-*, adv-m1-*, adv-m2-*, adv-m3-*).
