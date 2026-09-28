// test_background_jobs.cpp — WS-10 slice 10.1: the background-job classification
// table (server/core/src/background_jobs.hpp) is the checked-in, CI-auditable
// guarantee that every background pass is classified for replica-safety. This
// test binds the table's internal consistency and completeness; the per-site
// YUZU_ASSERT_BACKGROUND_JOB consteval gate binds that no GATED pass's table entry
// is removed or renamed (it fires only where the macro is written — proving
// pass⇒named for every dispatch site is the tracked CI-sweep follow-up #4094).

#include "background_jobs.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string_view>

using yuzu::server::BackgroundJobClass;
using yuzu::server::kBackgroundJobs;

namespace {
const yuzu::server::BackgroundJobDecl* find(std::string_view pass) {
    for (const auto& j : kBackgroundJobs)
        if (j.pass == pass)
            return &j;
    return nullptr;
}
} // namespace

TEST_CASE("background-job table is internally consistent", "[server][background-jobs]") {
    std::set<std::string_view> seen;
    for (const auto& j : kBackgroundJobs) {
        // Every field populated.
        CHECK_FALSE(j.pass.empty());
        CHECK_FALSE(j.owning_thread.empty());
        CHECK_FALSE(j.mechanism.empty());
        // Valid class.
        const bool valid_class = j.cls == BackgroundJobClass::ReplicaSafe ||
                                 j.cls == BackgroundJobClass::FencedLeaderOnly ||
                                 j.cls == BackgroundJobClass::DisabledUntilFixed;
        CHECK(valid_class);
        // Pass symbol is unique — the key the site-assert and the audit join on.
        INFO("duplicate pass symbol: " << j.pass);
        CHECK(seen.insert(j.pass).second);
    }
}

TEST_CASE("background-job table classifies every audited pass correctly",
          "[server][background-jobs]") {
    // Count tripwire — forces a conscious table update when a pass is added or
    // removed (a silent count change is exactly what WS-10 exists to prevent).
    // Update this number ONLY alongside a real classification change.
    CHECK(kBackgroundJobs.size() == 44);

    // The load-bearing per-pass calls — a regression here is the WS-10 hazard.
    SECTION("MUST-run-per-replica passes are ReplicaSafe, never leader-gated") {
        // ADR-2002 §5: leader-gating the event-outbox poll starves non-leader SSE.
        auto* poll = find("execution_tracker.poll_event_outbox_once");
        REQUIRE(poll != nullptr);
        CHECK(poll->cls == BackgroundJobClass::ReplicaSafe);
        // PR #4134: collect_ready() is the operator-plane completion path — gating it
        // strands an evaluate_now()/remediate() accepted on a non-leader forever.
        auto* collect = find("policy_evaluator.collect_ready");
        REQUIRE(collect != nullptr);
        CHECK(collect->cls == BackgroundJobClass::ReplicaSafe);
        // HA WS-8: each replica's /readyz must measure its OWN path to Postgres —
        // leader-gating the probe would leave every follower stale/unready.
        auto* probe = find("pg_reachability_probe.tick");
        REQUIRE(probe != nullptr);
        CHECK(probe->cls == BackgroundJobClass::ReplicaSafe);
    }
    SECTION("the three #2508 clock-guard prune targets are ReplicaSafe (single-writer via guard)") {
        for (std::string_view p : {"app_perf_fleet_store.run_retention_prune",
                                   "preflight_run_store.run_retention_prune",
                                   "deployment_run_store.run_retention_prune"}) {
            auto* j = find(p);
            INFO("missing/misclassified: " << p);
            REQUIRE(j != nullptr);
            CHECK(j->cls == BackgroundJobClass::ReplicaSafe);
        }
    }
    SECTION("WS-4 4.2a: the gateway route directory reaper is ReplicaSafe, on result_set_maint_thread_") {
        auto* j = find("gateway_route_store.reap_stale_routes");
        REQUIRE(j != nullptr);
        CHECK(j->cls == BackgroundJobClass::ReplicaSafe);
        CHECK(j->owning_thread == "result_set_maint_thread_");
    }
    SECTION("the sweep-added MUST-run-per-replica / idempotent passes are ReplicaSafe") {
        for (std::string_view p : {"cert_reloader.run_loop",
                                   "software_catalog_rollup.refresh_catalog_rollup",
                                   "auth_db.cleanup_provisional_mfa",
                                   "ota_transfer_watchdog.sweep_once",
                                   "mcp_stream_bridge.run_projector",
                                   "mcp_stream_bridge.sweep",
                                   "mcp_session_registry.gc",
                                   "store_worker_pool.worker_loop"}) {
            auto* j = find(p);
            INFO("missing/misclassified: " << p);
            REQUIRE(j != nullptr);
            CHECK(j->cls == BackgroundJobClass::ReplicaSafe);
        }
    }
    SECTION("side-effecting singletons are FencedLeaderOnly") {
        for (std::string_view p : {"schedule_runner.tick", "policy_evaluator.dispatch_due",
                                   "quarantine_reconciler.tick", "ca.publish_crl",
                                   "command_outbox.deliver"}) {
            auto* j = find(p);
            INFO("missing/misclassified: " << p);
            REQUIRE(j != nullptr);
            CHECK(j->cls == BackgroundJobClass::FencedLeaderOnly);
        }
    }
    SECTION("passes with a pending pre-2nd-replica migration are DisabledUntilFixed") {
        // nvd_sync: engine-tier migration pending. The concurrency reconciler: its
        // clock authority is still replica-local (#4093) — the advisory lock made it
        // single-writer but not clock-consistent, so it is NOT ReplicaSafe until the
        // DB-clock migration lands (same posture as nvd_sync, not the prunes).
        for (std::string_view p : {"nvd_sync.do_sync",
                                   "execution_tracker.reconcile_stale_concurrency_claims"}) {
            auto* j = find(p);
            INFO("missing/misclassified: " << p);
            REQUIRE(j != nullptr);
            CHECK(j->cls == BackgroundJobClass::DisabledUntilFixed);
        }
    }
}

TEST_CASE("background_job_index resolves membership at compile time",
          "[server][background-jobs]") {
    static_assert(yuzu::server::background_job_index("schedule_runner.tick") >= 0);
    static_assert(yuzu::server::background_job_index("no.such.pass") == -1);
    CHECK(yuzu::server::background_job_index("ca.publish_crl") >= 0);
    CHECK(yuzu::server::background_job_index("nope") == -1);
}
