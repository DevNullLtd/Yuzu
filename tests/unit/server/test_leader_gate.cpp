// test_leader_gate.cpp — WS-3 slice 3.2 (ADR-2002 §3/§6): the runtime leader
// gate over WS-10's background-job classification. These cases need no Postgres:
// they bind the PURE decision (background_pass_may_run), the COMPILE-TIME
// classification lookup the gate dispatches on (background_job_class), and the
// null-elector fail-closed path. The gate over a REAL acquired elector
// (leader_gate_permits<FencedLeaderOnly>(&e) flipping false→true→false across
// acquire/resign) is bound in test_leader_elector.cpp's [pg][leader-gate] case,
// which takes a real backend.

#include "leader_gate.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::BackgroundJobClass;
using yuzu::server::background_job_class;
using yuzu::server::background_pass_may_run;
using yuzu::server::leader_gate_permits;

TEST_CASE("background_pass_may_run: only FencedLeaderOnly requires leadership",
          "[leader-gate][unit]") {
    // FencedLeaderOnly runs only on the leader.
    CHECK(background_pass_may_run(BackgroundJobClass::FencedLeaderOnly, /*is_leader=*/true));
    CHECK_FALSE(background_pass_may_run(BackgroundJobClass::FencedLeaderOnly, /*is_leader=*/false));
    // ReplicaSafe runs on every replica, leader or not.
    CHECK(background_pass_may_run(BackgroundJobClass::ReplicaSafe, false));
    CHECK(background_pass_may_run(BackgroundJobClass::ReplicaSafe, true));
    // DisabledUntilFixed runs REGARDLESS of leadership on purpose: it must keep
    // running on today's single replica (gated by the deployment safe-to-scale
    // gate, not this runtime gate) — a leader-gate that denied it would be a
    // silent regression on the single replica.
    CHECK(background_pass_may_run(BackgroundJobClass::DisabledUntilFixed, false));
    CHECK(background_pass_may_run(BackgroundJobClass::DisabledUntilFixed, true));
}

// The gate dispatches on the SAME kBackgroundJobs classification the site
// assertion pins, so these compile-time checks are the anti-drift binding: if a
// pass is re-classified in background_jobs.hpp, these static_asserts move with it
// and the gate follows. A mis-typed pass name would fail to compile
// (background_job_class throws in constant evaluation) — that is the point.
static_assert(background_job_class("schedule_runner.tick") == BackgroundJobClass::FencedLeaderOnly);
// PR #4134: tick() split — only the leader-owned scheduling half is fenced; the
// operator-plane completion half (collect_ready) MUST run per-replica.
static_assert(background_job_class("policy_evaluator.dispatch_due") ==
              BackgroundJobClass::FencedLeaderOnly);
static_assert(background_job_class("policy_evaluator.collect_ready") ==
              BackgroundJobClass::ReplicaSafe);
static_assert(background_job_class("quarantine_reconciler.tick") ==
              BackgroundJobClass::FencedLeaderOnly);
static_assert(background_job_class("ca.publish_crl") == BackgroundJobClass::FencedLeaderOnly);
// The load-bearing exception: the WS-2a cross-replica event poll (ADR-2002 §5)
// MUST run on every replica or SSE subscribers on a non-leader go dark. It is
// ReplicaSafe, so the gate never leader-restricts it.
static_assert(background_job_class("execution_tracker.poll_event_outbox_once") ==
              BackgroundJobClass::ReplicaSafe);
// A DisabledUntilFixed pass classifies as such (it runs today, gated by the
// deployment gate — see the truth-table case above).
static_assert(background_job_class("nvd_sync.do_sync") == BackgroundJobClass::DisabledUntilFixed);

TEST_CASE("leader_gate_permits: WS-2a event poll is NEVER leader-gated",
          "[leader-gate][unit]") {
    // The explicit per-plan test: the must-run-per-replica poll runs even with no
    // elector / not leader.
    CHECK(leader_gate_permits<background_job_class("execution_tracker.poll_event_outbox_once")>(
        nullptr));
}

TEST_CASE("leader_gate_permits: a FencedLeaderOnly pass fails closed with no elector",
          "[leader-gate][unit]") {
    // A null elector (never wired) denies a FencedLeaderOnly pass — fail-closed,
    // never a silent permit.
    CHECK_FALSE(
        leader_gate_permits<background_job_class("schedule_runner.tick")>(nullptr));
    // ...but a ReplicaSafe pass still runs with a null elector (it never consults it).
    CHECK(leader_gate_permits<background_job_class("app_perf_rollup.roll_window")>(nullptr));
}
