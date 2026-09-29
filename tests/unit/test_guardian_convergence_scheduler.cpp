// test_guardian_convergence_scheduler.cpp - the convergence backstop (ADR-0021
// rung 4). Deterministic sweep seams verify type-lane separation and pending-
// initial servicing; a live-thread case verifies the CV-woken priority lane and
// clean CV-interruptible stop (also the TSan checkpoint for the scheduler).

#include "guardian_convergence_scheduler.hpp"
#include "guardian_spark_runtime.hpp"

#include <yuzu/agent/spark.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <memory>
#include <chrono>
#include <random>
#include <string>
#include <thread>

using namespace yuzu::agent;

namespace {
struct FakeReader : IStateReader {
    std::atomic<int> file_reads{0};
    std::atomic<int> reg_reads{0};
    std::atomic<int> svc_reads{0};
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan&) override {
        file_reads.fetch_add(1);
        return read_known(FileSnapshot{.exists = true});
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan& plan) override {
        reg_reads.fetch_add(1);
        RegistryRead out;
        for (const auto& vn : plan.value_names)
            out.values.emplace(vn, read_known(RegistrySnapshot{.present = true, .value = "v"}));
        return out;
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        svc_reads.fetch_add(1);
        return read_known(ServiceRunState::Running);
    }
    void request_stop() noexcept override {}
};
struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::expected<std::uint64_t, std::string> arm(const SparkSpec&) override {
        return next.fetch_add(1);
    }
    void disarm(std::uint64_t) override {}
};
RuleAssertion file_rule(const std::string& id) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = id;
    a.expect_present = true;
    return a;
}
RuleAssertion svc_rule(const std::string& id) {
    RuleAssertion a;
    a.kind = AssertionKind::ServiceRunning;
    a.rule_id = id;
    return a;
}
SparkSpec file_spec(const std::string& p) { return SparkSpec{SparkType::File, FileSparkParams{p}}; }
SparkSpec svc_spec(const std::string& n) {
    return SparkSpec{SparkType::Service, ServiceSparkParams{n}};
}
// Spin until `pred()` or the deadline; returns pred()'s final value.
template <typename Pred>
bool wait_until(Pred pred, std::chrono::milliseconds budget = std::chrono::milliseconds{3000}) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    return pred();
}
} // namespace

TEST_CASE("sweep_lane drives only its own type's armed keys", "[spark][convergence]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    ConvergenceScheduler sched{*rt};
    rt->attach_rule("f1", file_spec("/a"), file_rule("f1"), true);
    rt->attach_rule("s1", svc_spec("nginx"), svc_rule("s1"), true);

    sched.sweep_lane(SparkType::File);
    REQUIRE(r->file_reads.load() == 1);
    REQUIRE(r->svc_reads.load() == 0); // the file lane never touches a service key

    sched.sweep_lane(SparkType::Service);
    REQUIRE(r->svc_reads.load() == 1);
    REQUIRE(r->file_reads.load() == 1);
}

TEST_CASE("sweep_pending_initial services every key that still owes a first eval",
          "[spark][convergence]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    ConvergenceScheduler sched{*rt};
    rt->attach_rule("f1", file_spec("/a"), file_rule("f1"), true);
    rt->attach_rule("s1", svc_spec("nginx"), svc_rule("s1"), true);
    REQUIRE_FALSE(rt->pending_initial(spark_key(file_spec("/a"))).empty());

    sched.sweep_pending_initial();
    REQUIRE(rt->pending_initial(spark_key(file_spec("/a"))).empty());
    REQUIRE(rt->pending_initial(spark_key(svc_spec("nginx"))).empty());
}

TEST_CASE("running scheduler converges armed keys and stops cleanly", "[spark][convergence][tsan]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    ConvergenceScheduler::Config cfg;
    cfg.service_cadence_ms = 5;
    cfg.registry_cadence_ms = 5;
    cfg.file_cadence_ms = 5;
    cfg.priority_poll_ms = 5;
    cfg.jitter_pct = 0;
    ConvergenceScheduler sched{*rt, cfg};
    rt->attach_rule("f1", file_spec("/a"), file_rule("f1"), true);

    sched.start();
    // The file lane re-evaluates /a on its cadence, independent of any event.
    REQUIRE(wait_until([&] { return r->file_reads.load() >= 3; }));
    sched.stop();
    const int after_stop = r->file_reads.load();
    std::this_thread::sleep_for(std::chrono::milliseconds{30});
    REQUIRE(r->file_reads.load() == after_stop); // stop actually stops the lanes
}

TEST_CASE("attaching a rule while running wakes the priority lane promptly",
          "[spark][convergence][tsan]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    ConvergenceScheduler::Config cfg;
    // Long cadences so ONLY the CV wake (not a cadence tick) can service the new rule quickly.
    cfg.service_cadence_ms = 1'000'000;
    cfg.registry_cadence_ms = 1'000'000;
    cfg.file_cadence_ms = 1'000'000;
    cfg.priority_poll_ms = 1'000'000;
    cfg.jitter_pct = 0;
    ConvergenceScheduler sched{*rt, cfg};
    sched.start();

    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("f1", file_spec("/a"), file_rule("f1"), true); // fires the waker
    // Despite the ~1000s cadences, the priority lane wakes and clears pending-initial.
    REQUIRE(wait_until([&] { return rt->pending_initial(key).empty(); }));
    sched.stop();
}

TEST_CASE("a waker copied before stop is safe to invoke after the scheduler is destroyed",
          "[spark][convergence]") {
    // Models an attach_rule that copied the waker just before stop(), then invoked its
    // copy after the scheduler was gone. The waker captures the shared Signal, not the
    // scheduler, so this is a harmless no-op - under the old raw-`this` capture it was a
    // use-after-free on the destroyed mutex/CV.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    std::function<void()> copied;
    {
        ConvergenceScheduler sched{*rt};
        sched.start();
        copied = rt->pending_initial_waker_for_test(); // the installed waker
        REQUIRE(copied);
        sched.stop();
    } // scheduler destroyed; only `copied` (holding the Signal) remains
    copied(); // must not crash / UAF
    SUCCEED();
}

TEST_CASE("stop is idempotent and safe before start", "[spark][convergence]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    ConvergenceScheduler sched{*rt};
    sched.stop(); // never started
    sched.start();
    sched.stop();
    sched.stop(); // idempotent
    SUCCEED();
}

TEST_CASE("jittered stays within the shared jitter-span bound at nonzero jitter_pct",
          "[spark][convergence]") {
    // Every OTHER test in this file runs jitter_pct = 0, so nothing else exercises
    // this arithmetic. #3531: a future edit that re-inlines or subtly changes
    // jittered()'s formula must not be able to pass every test in the suite.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    ConvergenceScheduler::Config cfg;
    cfg.jitter_pct = kGuardianLaneJitterPct;
    ConvergenceScheduler sched{*rt, cfg};

    const std::uint64_t base_ms = kGuardianServiceLaneCadenceMs;
    // Independently computed via the SAME shared formula jittered() itself calls -
    // not re-derived inline, which is the whole point of the extraction (#3388).
    const std::uint64_t span = guardian_jitter_span_ms(base_ms, cfg.jitter_pct);
    // Pins guardian_jitter_span_ms's OWN output for these constants, so a future
    // change to the formula (or the constants) that silently shifts this test's
    // bound fails loudly here. This does NOT close the separate boundary-value gap
    // in jittered()'s own dist(-span, span) construction (a different translation
    // unit) - a +/-1 there would still pass every REQUIRE below undetected; that
    // residual gap needs a directly-testable {lo, hi} seam to close, not this
    // assert (#3531, quality-engineer Gate 8).
    static_assert(guardian_jitter_span_ms(kGuardianServiceLaneCadenceMs, kGuardianLaneJitterPct) ==
                      12'000,
                  "this test's bound depends on this exact span - re-derive both if "
                  "the lane cadence or jitter percentage constants ever change");
    REQUIRE(span > 0);

    std::mt19937 rng{0x5eed};
    std::int64_t min_ms = static_cast<std::int64_t>(base_ms + span);
    std::int64_t max_ms = static_cast<std::int64_t>(base_ms - span);
    for (int i = 0; i < 1000; ++i) {
        const auto ms = sched.jittered(base_ms, rng).count();
        REQUIRE(ms >= static_cast<std::int64_t>(base_ms - span));
        REQUIRE(ms <= static_cast<std::int64_t>(base_ms + span));
        min_ms = std::min(min_ms, ms);
        max_ms = std::max(max_ms, ms);
    }
    // Demonstrates jitter is actually applied, not silently collapsed to a constant.
    REQUIRE(min_ms < static_cast<std::int64_t>(base_ms));
    REQUIRE(max_ms > static_cast<std::int64_t>(base_ms));
}

TEST_CASE("jittered returns base_ms unchanged when jitter_pct is zero",
          "[spark][convergence]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    ConvergenceScheduler::Config cfg;
    cfg.jitter_pct = 0;
    ConvergenceScheduler sched{*rt, cfg};

    std::mt19937 rng{0x5eed};
    REQUIRE(sched.jittered(kGuardianServiceLaneCadenceMs, rng).count() ==
            static_cast<std::int64_t>(kGuardianServiceLaneCadenceMs));
}
