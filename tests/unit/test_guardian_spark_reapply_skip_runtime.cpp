// #4415 PR-A (+ the complete #5512 transition) RED-FIRST tests: SPARK RUNTIME level.
//
// Scope: GuardianSparkRuntime::attach_core's reuse decisions (the "Reuse has THREE cases"
// of the #4415 kickoff), the same-rule follower behind its own retained wedge, the
// one-desired-incarnation-per-rule_id rule, and the detach shapes the scoped full_sync
// detach depends on. The engine-level effect-set tests (identical re-push touching no
// healthy rule, scoped detach_all, baseline-on-arm, faulted bit) live in
// test_guardian_spark_reapply_skip_engine.cpp and are not duplicated here.
//
// Every case is tagged [4415prA] and sits in the `[runtime]` tag family, which partitions
// into agent shard A with the neighbouring cases in test_guardian_spark_runtime.cpp.
//
// STATUS ON THE BASELINE (origin/dev 45f727420), recorded in each case's own header:
//   RED  : reuse-1, reuse-3a, reuse-3b, #5512 (both variants), one-incarnation
//   GREEN: reuse-2, reuse-3c, scoped-detach 6a/6b, 7 (regression guards)
// Later additions with no baseline status of their own: reuse-3d (blocking identical attach),
// scoped-detach 7b (detach_rules_except), and the health-authority cases (F1: a lost Faulted
// event must not turn a deaf rule into a skipped one; a Dead key shared by kept rules is rebuilt;
// a throwing, re-entered or raced health query), the in_unknown skip term at the runtime level,
// and the content-id field table.
//
// Every wait is event-driven (gate entry, spin_until on an observable effect); there is
// no sleep. A wedge is created by parking the key's first arm() and abandoning the
// dispatched claim through expire_overdue_claims_at_for_test with a future-dated `now`
// (that overload abandons EVERY in-flight arm claim whose deadline precedes `now`, so
// each case creates a wedge BEFORE it queues anything it needs to stay live).
//
// The fakes below are a deliberately small subset of the ones in
// test_guardian_spark_runtime.cpp (those live in that TU's anonymous namespace and cannot
// be shared); the keyed arm gate has the same semantics.

#include "guardian_rule_eval.hpp" // read_unknown
#include "guardian_spark_runtime.hpp"

#include <yuzu/agent/spark.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::agent;

namespace {
using clk = std::chrono::steady_clock;
using RT = GuardianSparkRuntime;
using namespace std::chrono_literals;

struct FakeReader : IStateReader {
    ReadResult<FileSnapshot> file{read_known(FileSnapshot{.exists = true, .size = 4, .hash = "h"})};
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan&) override {
        return file;
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan&) override {
        return {};
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        return read_known(ServiceRunState::Running);
    }
    void request_stop() noexcept override {}
};

/// Counts effects at the mechanism boundary (arm/disarm ENTRIES, ids) and can park the
/// first arm() for a given key until the test releases it.
struct FakeBackend : ISparkBackend {
    struct ArmGate {
        std::mutex mu;
        std::condition_variable cv;
        bool entered{false};
        bool released{false};
        void wait() {
            std::unique_lock<std::mutex> lk{mu};
            entered = true;
            cv.notify_all();
            cv.wait(lk, [this] { return released; });
        }
        bool wait_entered(std::chrono::seconds timeout) {
            std::unique_lock<std::mutex> lk{mu};
            return cv.wait_for(lk, timeout, [this] { return entered; });
        }
        void release() {
            std::lock_guard<std::mutex> lk{mu};
            released = true;
            cv.notify_all();
        }
    };

    std::atomic<std::uint64_t> next{1};
    std::atomic<int> arm_entries{0};    ///< counted at entry, before any gate
    std::atomic<int> arms{0};           ///< arms that returned a subscription
    std::atomic<int> disarm_entries{0};

    std::shared_ptr<ArmGate> park_next_arm_for_key(const std::string& key) {
        auto gate = std::make_shared<ArmGate>();
        std::lock_guard<std::mutex> lk{gates_mu_};
        all_gates_.push_back(gate);
        gates_.insert_or_assign(key, gate);
        return gate;
    }
    void release_all_gates() {
        std::lock_guard<std::mutex> lk{gates_mu_};
        for (const auto& g : all_gates_)
            g->release();
    }

    std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) override {
        arm_entries.fetch_add(1);
        std::shared_ptr<ArmGate> gate;
        {
            std::lock_guard<std::mutex> lk{gates_mu_};
            if (const auto it = gates_.find(spark_key(spec)); it != gates_.end()) {
                gate = std::move(it->second);
                gates_.erase(it);
            }
        }
        if (gate)
            gate->wait();
        arms.fetch_add(1);
        const std::uint64_t id = next.fetch_add(1);
        std::lock_guard<std::mutex> lk{ids_mu_};
        armed_ids_.push_back(id);
        return id;
    }
    void disarm(std::uint64_t sub) override {
        disarm_entries.fetch_add(1);
        std::lock_guard<std::mutex> lk{ids_mu_};
        disarmed_ids_.push_back(sub);
    }
    /// What subscription_health() reports for `id` (Healthy when never set), standing in for the
    /// engine's own state independent of whether any Faulted event was ever delivered.
    void set_health(std::uint64_t id, SubscriptionHealth h) {
        std::lock_guard<std::mutex> lk{ids_mu_};
        health_[id] = h;
    }
    /// Runs at the START of every subscription_health() call, before any FakeBackend lock is
    /// taken, so it may block (a gate), throw, or call back into the runtime.
    void set_health_hook(std::function<void(std::uint64_t)> hook) {
        std::lock_guard<std::mutex> lk{hook_mu_};
        health_hook_ = std::move(hook);
    }
    SubscriptionHealth subscription_health(std::uint64_t id) override {
        std::function<void(std::uint64_t)> hook;
        {
            std::lock_guard<std::mutex> lk{hook_mu_};
            hook = health_hook_;
        }
        if (hook)
            hook(id);
        std::lock_guard<std::mutex> lk{ids_mu_};
        const auto it = health_.find(id);
        return it != health_.end() ? it->second : SubscriptionHealth::Healthy;
    }
    std::vector<std::uint64_t> armed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return armed_ids_;
    }
    std::vector<std::uint64_t> disarmed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return disarmed_ids_;
    }

private:
    std::mutex hook_mu_;
    std::function<void(std::uint64_t)> health_hook_;
    std::mutex gates_mu_;
    std::unordered_map<std::string, std::shared_ptr<ArmGate>> gates_;
    std::vector<std::shared_ptr<ArmGate>> all_gates_;
    mutable std::mutex ids_mu_;
    std::vector<std::uint64_t> armed_ids_;
    std::vector<std::uint64_t> disarmed_ids_;
    std::unordered_map<std::uint64_t, SubscriptionHealth> health_;
};

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}
RuleAssertion file_exists_rule(const std::string& rule_id, bool present = true) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = rule_id;
    a.expect_present = present;
    return a;
}
RuleAssertion file_hash_rule(const std::string& rule_id, const std::string& expected_hash) {
    RuleAssertion a;
    a.kind = AssertionKind::FileHashEquals;
    a.rule_id = rule_id;
    a.expected_hash = expected_hash;
    return a;
}

SparkSpec svc_spec_for_identity() {
    return SparkSpec{SparkType::Service, ServiceSparkParams{"svc"}};
}
RuleAssertion svc_rule_for_identity(const std::string& rule_id, AssertionKind kind) {
    RuleAssertion a;
    a.kind = kind;
    a.rule_id = rule_id;
    return a;
}

std::size_t drain_lifecycle_count(RT& rt) {
    std::size_t n = 0;
    rt.drain([&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle)
            ++n;
        return SendResult::Sent;
    });
    return n;
}

/// Owns a runtime over fakes and, on EVERY exit path (a failed REQUIRE included), releases
/// every parked arm before the runtime is destroyed so no executor worker is left blocked.
struct Rig {
    std::shared_ptr<FakeReader> reader = std::make_shared<FakeReader>();
    std::shared_ptr<FakeBackend> backend = std::make_shared<FakeBackend>();
    std::shared_ptr<RT> rt;
    Rig() {
        static std::atomic<std::int64_t> tick{0};
        RT::Config cfg;
        cfg.backend_op_deadline = 60s; // no claim ever expires on its own: only the explicit
                                       // future-dated expire below abandons anything
        rt = std::make_shared<RT>(reader, backend, cfg, [] {
            return clk::time_point{} + std::chrono::milliseconds(tick.fetch_add(1000));
        });
    }
    /// Releases every parked arm, then waits (bounded, event-driven) for every detached executor
    /// worker to finish: a worker released here still runs on_arm_complete (which logs) after the
    /// case returns, and one still running at process exit logs through a destroyed spdlog
    /// registry (TSan heap-use-after-free). active_total is the PHYSICAL alive count, freed only
    /// after the worker's completion callback has returned; a worker that dispatches a queued
    /// claim does so before it exits, so the count cannot dip to zero with work still pending.
    ~Rig() {
        backend->release_all_gates();
        if (!yuzu::test::spin_until([&] { return rt->io_executor_stats_for_test().active_total == 0; },
                                    10s))
            std::fputs("reapply_skip Rig: io_executor workers still alive after 10 s\n", stderr);
    }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;
};

/// Abandons every in-flight arm claim now (see the file header for the blast radius).
std::size_t expire_in_flight(RT& rt) {
    return rt.expire_overdue_claims_at_for_test(clk::now() + 1h);
}

/// Readable receipt status for failure messages (a bare enum prints as an integer).
std::string status_name(RT& rt, const RT::ArmReceipt& receipt) {
    switch (rt.receipt_status(receipt)) {
    case RT::ReceiptStatus::Pending: return "Pending";
    case RT::ReceiptStatus::Committed: return "Committed";
    case RT::ReceiptStatus::Failed: return "Failed";
    case RT::ReceiptStatus::CongestionExpired: return "CongestionExpired";
    case RT::ReceiptStatus::Wedged: return "Wedged";
    case RT::ReceiptStatus::Withdrawn: return "Withdrawn";
    case RT::ReceiptStatus::Stopped: return "Stopped";
    }
    return "?";
}

struct Parked {
    std::shared_ptr<FakeBackend::ArmGate> gate;
    RT::ArmReceipt receipt;
};

/// Attaches `a` with its key's first arm() parked, waits until the worker is inside the
/// mechanism, and returns the (still Pending, Dispatched, NOT abandoned) claim.
Parked attach_parked(Rig& rig, const std::string& rid, const SparkSpec& spec, RuleAssertion a) {
    auto gate = rig.backend->park_next_arm_for_key(spark_key(spec));
    auto out = rig.rt->attach_rule(RT::NonWaiting{}, rid, spec, std::move(a), true);
    REQUIRE(out.has_value());
    REQUIRE(out->kind == RT::ArmOutcomeKind::Accepted);
    REQUIRE(gate->wait_entered(10s));
    REQUIRE(status_name(*rig.rt, out->receipt) == "Pending");
    return Parked{std::move(gate), out->receipt};
}

/// attach_parked + abandon it into a retained wedge head (candidate for `rid`).
Parked attach_wedged(Rig& rig, const std::string& rid, const SparkSpec& spec, RuleAssertion a) {
    auto p = attach_parked(rig, rid, spec, std::move(a));
    REQUIRE(expire_in_flight(*rig.rt) == 1);
    REQUIRE(status_name(*rig.rt, p.receipt) == "Wedged");
    REQUIRE(rig.rt->wedge_candidate_count_for_test(rid) == 1);
    return p;
}

} // namespace

// ---------------------------------------------------------------------------------------
// 1. Reuse case 1: committed-live identical attach.
// BASELINE: RED. attach_core unconditionally detaches the live generation (a Disarm claim)
// and queues a fresh arm behind it: Accepted + a new incarnation + a real disarm/arm pair.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A reuse 1: an identical attach on a committed-live rule returns Armed "
          "with the existing generation and touches nothing",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);

    const auto gen1 = rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true); // blocking
    REQUIRE(gen1.has_value());
    REQUIRE(rig.rt->rule_count() == 1);
    REQUIRE(rig.rt->claim_queue_depth_for_test(key) == 0);
    REQUIRE(rig.backend->arm_entries.load() == 1);
    REQUIRE(drain_lifecycle_count(*rig.rt) == 1); // the one "armed" record; consumed here
    const auto fence_before = rig.rt->application_fence_for_test();
    REQUIRE(fence_before.second == *gen1);

    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    INFO("second attach: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    // Settle whatever the (baseline) teardown + re-arm needs, so the counters below are final.
    REQUIRE(yuzu::test::spin_until([&] { return rig.rt->claim_queue_depth_for_test(key) == 0; }, 10s));

    CHECK(again->kind == RT::ArmOutcomeKind::Armed);          // baseline: Accepted
    CHECK(again->generation == *gen1);                        // baseline: a new incarnation
    CHECK(again->receipt.claim == nullptr);                   // no claim: nothing it could acknowledge
    CHECK(rig.rt->application_fence_for_test().second == fence_before.second); // no incarnation minted
    CHECK(rig.backend->arm_entries.load() == 1);              // no mechanism call: no re-arm ...
    CHECK(rig.backend->disarm_entries.load() == 0);           // ... and no teardown
    CHECK(drain_lifecycle_count(*rig.rt) == 0);               // no armed/disarmed audit record
    CHECK(rig.rt->rule_count() == 1);
    CHECK(rig.rt->armed_key_count() == 1);
}

// ---------------------------------------------------------------------------------------
// 2. Reuse case 2: retained-wedge identical -> Reobserved (today's behaviour, pinned).
// BASELINE: GREEN (regression guard).
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A reuse 2: an identical attach on a retained wedge re-observes it",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto wedge = attach_wedged(rig, "r1", spec, file_exists_rule("r1"));
    const auto reobs_before = rig.rt->wedged_reobservations();

    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    INFO("second attach: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    CHECK(again->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(again->receipt.claim == wedge.receipt.claim);        // the EXISTING claim, nothing new
    CHECK(rig.rt->wedged_reobservations() == reobs_before + 1);
    CHECK(rig.rt->wedged_refusals() == 0);
    CHECK(rig.rt->claim_queue_depth_for_test(key) == 1);
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 1);  // still the single desired candidate
    CHECK(rig.backend->arm_entries.load() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);

    // The late success adopts it: re-observation restarted nothing.
    wedge.gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 1 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    CHECK(status_name(*rig.rt, wedge.receipt) == "Wedged"); // sticky
    CHECK(rig.backend->arms.load() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);
}

// ---------------------------------------------------------------------------------------
// 3a. Reuse case 3, DISPATCHED same-rule identical claim.
// BASELINE: RED. A repeat attach withdraws the in-flight claim (Case 0) and queues a new one
// behind it: the receipt names a different claim, the first reads Withdrawn, depth is 2.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A reuse 3a: an identical attach while the same rule's arm is in flight "
          "re-observes that claim and neither withdraws nor requeues it",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto inflight = attach_parked(rig, "r1", spec, file_exists_rule("r1"));
    REQUIRE(rig.rt->claim_queue_depth_for_test(key) == 1);

    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    INFO("second attach: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    CHECK(again->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(again->receipt.claim == inflight.receipt.claim);     // the exact claim object
    CHECK(status_name(*rig.rt, inflight.receipt) == "Pending"); // not Withdrawn
    CHECK(rig.rt->claim_queue_depth_for_test(key) == 1);       // not requeued behind a tombstone
    CHECK(rig.backend->arm_entries.load() == 1);

    inflight.gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 1 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    CHECK(status_name(*rig.rt, inflight.receipt) == "Committed");
    CHECK(rig.backend->arms.load() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);
}

// ---------------------------------------------------------------------------------------
// 3b. Reuse case 3, QUEUED same-rule identical claim (behind another rule's in-flight arm
// on the SAME key). BASELINE: RED, same reason as 3a (the queued claim is erased outright
// and replaced by a fresh one).
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A reuse 3b: an identical attach while the same rule's claim is QUEUED "
          "re-observes it and does not requeue it",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto head = attach_parked(rig, "r2", spec, file_exists_rule("r2")); // in flight, other rule
    auto queued = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    REQUIRE(queued.has_value());
    REQUIRE(queued->kind == RT::ArmOutcomeKind::Accepted);
    REQUIRE(queued->receipt.claim != head.receipt.claim);
    REQUIRE(rig.rt->claim_queue_depth_for_test(key) == 2);
    REQUIRE(status_name(*rig.rt, queued->receipt) == "Pending");

    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    INFO("second attach: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    CHECK(again->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(again->receipt.claim == queued->receipt.claim);      // baseline: a different object
    CHECK(status_name(*rig.rt, queued->receipt) == "Pending"); // baseline: Withdrawn
    CHECK(rig.rt->claim_queue_depth_for_test(key) == 2);
    CHECK(status_name(*rig.rt, head.receipt) == "Pending"); // head untouched

    head.gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 2 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    CHECK(status_name(*rig.rt, queued->receipt) == "Committed");
    CHECK(rig.backend->arms.load() == 1);                      // both rules share one watcher
    CHECK(rig.backend->disarm_entries.load() == 0);
}

// ---------------------------------------------------------------------------------------
// 3c. The "not withdrawn" limb of case 3: a claim the rule's own detach withdrew is NOT
// re-observed; the next attach is a fresh claim. BASELINE: GREEN (guard against an
// over-eager reuse that would resurrect a withdrawn claim).
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A reuse 3c: an attach after the rule was detached is a fresh claim, "
          "never a re-observation of the withdrawn one",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto inflight = attach_parked(rig, "r1", spec, file_exists_rule("r1"));

    rig.rt->detach_rule("r1");
    REQUIRE(status_name(*rig.rt, inflight.receipt) == "Withdrawn");

    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    INFO("second attach: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    REQUIRE(again->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(again->receipt.claim != inflight.receipt.claim);
    CHECK(status_name(*rig.rt, again->receipt) == "Pending");
    CHECK(status_name(*rig.rt, inflight.receipt) == "Withdrawn");
    CHECK(rig.rt->claim_queue_depth_for_test(key) == 2);       // withdrawn marker + the fresh claim

    inflight.gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 1 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    CHECK(status_name(*rig.rt, again->receipt) == "Committed");
    CHECK(rig.backend->arms.load() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);
}

// ---------------------------------------------------------------------------------------
// 3d. The BLOCKING overload re-observing the same rule's live claim. The re-observation branch
// there used to assume a retained wedge (an outcome already set); a live claim has none, so the
// call must wait for that claim and must not abandon it (this call owns nothing).
// BASELINE: a Case 0 withdraw + requeue; the first claim ends Withdrawn.
// NON-DETERMINISTIC BRANCH: the waiter thread may call attach_rule before the test releases the
// gate (it parks on the live claim: the re-observation branch) or, if the thread is slow, after
// the commit (the committed-live skip). Both end in the same observable state and both are
// asserted below; only one of them is exercised per run, so the re-observation branch is
// covered probabilistically here and deterministically by 3a (NonWaiting) instead.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A reuse 3d: a BLOCKING identical attach on a rule whose arm is in flight "
          "waits for that claim and returns its generation, abandoning nothing",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto inflight = attach_parked(rig, "r1", spec, file_exists_rule("r1"));

    std::optional<std::expected<std::uint64_t, std::string>> got;
    std::thread waiter{[&] { got = rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true); }};
    // Declared after `waiter`, so it runs first on EVERY exit path (a failed REQUIRE included):
    // the parked arm is released and the waiter joined before anything it uses goes away.
    struct ReleaseAndJoin {
        Parked& arm;
        std::thread& t;
        ~ReleaseAndJoin() {
            arm.gate->release();
            if (t.joinable())
                t.join();
        }
    } release_and_join{inflight, waiter};

    // The late success is the only thing that resolves the call, whether it parked on the claim
    // or arrived after the commit (then it is the committed-live skip and returns the same value).
    inflight.gate->release();
    waiter.join();
    REQUIRE(got.has_value());
    INFO("blocking attach: " << (got->has_value() ? "ok" : got->error()));
    REQUIRE(got->has_value());
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 1 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    CHECK(**got == rig.rt->application_fence_for_test().second); // the ONE incarnation
    CHECK(status_name(*rig.rt, inflight.receipt) == "Committed"); // never withdrawn or abandoned
    CHECK(rig.backend->arm_entries.load() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);
}

// ---------------------------------------------------------------------------------------
// 4. #5512 transition: same rule_id, same key, DIFFERENT content, head is a retained wedge.
// Expected: the old candidacy is deactivated and a live FOLLOWER is queued behind the head;
// on the head's late success the follower commits its OWN content and the wedge is not
// adopted.
// BASELINE: RED. The hoisted re-observation test compares only (rule_id, spec), so the
// attach returns Reobserved of the OLD claim: the new content is discarded and the late
// success adopts the stale one. (Not the kSparkKeyWedged refusal: that is what a content
// term added WITHOUT a new branch would produce, see the kickoff.)
// ---------------------------------------------------------------------------------------
namespace {
void run_content_change_over_wedge(RuleAssertion old_content, RuleAssertion new_content,
                                   bool old_compliant, bool new_compliant) {
    REQUIRE(old_compliant != new_compliant); // the verdict is how committed content is observed
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto wedge = attach_wedged(rig, "r1", spec, std::move(old_content));
    const auto refusals_before = rig.rt->wedged_refusals();
    const auto reobs_before = rig.rt->wedged_reobservations();

    auto changed = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, std::move(new_content), true);
    INFO("changed-content attach: " << (changed ? "ok" : changed.error().message));
    REQUIRE(changed.has_value()); // a Failed (kSparkKeyWedged) here is the "different claimant" refusal
    CHECK(changed->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(changed->receipt.claim != wedge.receipt.claim);       // a NEW follower, not the wedge
    CHECK(rig.rt->wedged_refusals() == refusals_before);        // not the kSparkKeyWedged refusal
    CHECK(rig.rt->wedged_reobservations() == reobs_before);     // not a re-observation either
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 0);   // old candidacy deactivated
    CHECK(rig.rt->claim_queue_depth_for_test(key) == 2);        // wedge head + live follower
    CHECK(status_name(*rig.rt, changed->receipt) == "Pending");

    wedge.gate->release(); // late success of the wedged head
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 1 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    CHECK(status_name(*rig.rt, changed->receipt) == "Committed"); // follower won
    CHECK(status_name(*rig.rt, wedge.receipt) == "Wedged");       // sticky, first verdict wins
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 0);   // the wedge was NOT adopted
    CHECK(rig.rt->wedge_adopt_stale_refused() == 0);
    CHECK(rig.backend->arms.load() == 1);                       // the follower shared the head's subscription
    CHECK(rig.backend->disarm_entries.load() == 0);             // nothing compensated
    CHECK(rig.rt->invariant_violations_for_test().empty());

    // The committed rule enforces the NEW content (assertion content, not just rule/key).
    rig.rt->evaluate_key(key, EvalReason::Initial);
    const auto st = rig.rt->status_for_rule("r1");
    REQUIRE(st.has_value());
    REQUIRE(st->last_compliant.has_value());
    CHECK(*st->last_compliant == new_compliant); // baseline: the OLD content's verdict (old_compliant)
}
} // namespace

TEST_CASE("#5512 (#4415 PR-A): a changed expect_present over a retained wedge queues a "
          "follower; the late success commits the new content",
          "[spark][runtime][4415prA]") {
    run_content_change_over_wedge(file_exists_rule("r1", /*present=*/true),
                                  file_exists_rule("r1", /*present=*/false),
                                  /*old_compliant=*/true, /*new_compliant=*/false);
}

TEST_CASE("#5512 (#4415 PR-A): a changed expected_hash over a retained wedge queues a "
          "follower; the late success commits the new content",
          "[spark][runtime][4415prA]") {
    // FakeReader's file hashes to "h": the old rule is compliant, the new one drifts.
    run_content_change_over_wedge(file_hash_rule("r1", "h"), file_hash_rule("r1", "other"),
                                  /*old_compliant=*/true, /*new_compliant=*/false);
}

// ---------------------------------------------------------------------------------------
// 5. One desired incarnation per rule_id on a key. After the new-content follower is queued
// behind the wedge, a push of the OLD content again must re-observe the head AND withdraw the
// follower (Case 0), so the late success arms the OLD content, not the new.
// BASELINE: RED, but ONLY through the case-4 step: today the first changed-content attach is
// itself a re-observation, so no follower ever exists and the final adoption happens to
// carry the old content. The END-STATE assertion alone is GREEN on the baseline; the
// follower-existence / follower-withdrawn assertions are what fail. Post-fix, the end-state
// assertion is the one that catches a missing follower withdrawal.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A one incarnation: a revert-to-old push while a new-content follower is "
          "queued behind the wedge arms the OLD content",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto wedge = attach_wedged(rig, "r1", spec, file_exists_rule("r1", /*present=*/true)); // A

    auto b = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec,
                                 file_exists_rule("r1", /*present=*/false), true); // B
    INFO("B attach: " << (b ? "ok" : b.error().message));
    REQUIRE(b.has_value());
    REQUIRE(b->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(b->receipt.claim != wedge.receipt.claim);             // baseline: the wedge itself
    CHECK(rig.rt->claim_queue_depth_for_test(key) == 2);

    auto revert = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec,
                                      file_exists_rule("r1", /*present=*/true), true); // A again
    INFO("revert attach: " << (revert ? "ok" : revert.error().message));
    REQUIRE(revert.has_value());
    CHECK(revert->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(revert->receipt.claim == wedge.receipt.claim);        // the head is re-observed
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 1);   // candidacy restored, W1 holds
    CHECK(status_name(*rig.rt, b->receipt) == "Withdrawn"); // follower withdrawn
    CHECK(rig.rt->claim_queue_depth_for_test(key) == 1);        // only the head remains

    wedge.gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 1 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    CHECK(rig.rt->wedge_adopt_stale_refused() == 0);
    CHECK(rig.backend->arms.load() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);
    CHECK(rig.rt->invariant_violations_for_test().empty());

    rig.rt->evaluate_key(key, EvalReason::Initial);
    const auto st = rig.rt->status_for_rule("r1");
    REQUIRE(st.has_value());
    REQUIRE(st->last_compliant.has_value());
    CHECK(*st->last_compliant); // content A (expect present): the LAST push wins, not the follower
}

// ---------------------------------------------------------------------------------------
// 6a. Scoped full_sync detach, an ABSENT rule's pending (in-flight, non-wedge) arm: it is
// withdrawn, its late success is compensated, and a healthy sibling is untouched.
// Expressed through detach_rule (the per-rule primitive the scoped bulk detach is built
// from; the bulk entry point, detach_rules_except, is covered by 7b).
// BASELINE: GREEN (regression guard).
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A scoped detach 6a: an absent rule's pending arm is withdrawn and its "
          "late success compensated; a healthy sibling is untouched",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto keep_spec = file_spec("/y");
    const auto abs_spec = file_spec("/x");
    const auto abs_key = spark_key(abs_spec);
    REQUIRE(rig.rt->attach_rule("keep", keep_spec, file_exists_rule("keep"), true).has_value());
    REQUIRE(rig.backend->armed_ids().size() == 1);
    const auto keep_id = rig.backend->armed_ids().front();
    auto pending = attach_parked(rig, "absent", abs_spec, file_exists_rule("absent"));

    rig.rt->detach_rule("absent");
    CHECK(status_name(*rig.rt, pending.receipt) == "Withdrawn");
    CHECK(rig.rt->rule_count() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);             // the sibling's watcher is not torn down

    pending.gate->release(); // late success of a withdrawn arm: nobody wants it
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.backend->disarmed_ids().size() == 1 && rig.rt->claim_queue_depth_for_test(abs_key) == 0;
    }, 10s));
    const auto ids = rig.backend->armed_ids();
    REQUIRE(ids.size() == 2);
    CHECK(rig.backend->disarmed_ids() == std::vector<std::uint64_t>{ids[1]}); // exactly the late arm
    CHECK(rig.backend->disarmed_ids().front() != keep_id);
    CHECK(rig.rt->rule_count() == 1);
    CHECK(rig.rt->armed_key_count() == 1);
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

// ---------------------------------------------------------------------------------------
// 6b. Scoped full_sync detach, an ABSENT rule's retained wedge head keeps today's behaviour:
// candidacy cleared, never re-observed, late success compensated (not adopted).
// BASELINE: GREEN (regression guard).
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A scoped detach 6b: an absent rule's retained wedge loses its candidacy "
          "and its late success is compensated, never adopted",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto keep_spec = file_spec("/y");
    const auto wedge_spec = file_spec("/w");
    const auto wedge_key = spark_key(wedge_spec);
    REQUIRE(rig.rt->attach_rule("keep", keep_spec, file_exists_rule("keep"), true).has_value());
    auto wedge = attach_wedged(rig, "absent", wedge_spec, file_exists_rule("absent"));
    const auto reobs_before = rig.rt->wedged_reobservations();

    rig.rt->detach_rule("absent");
    CHECK(rig.rt->wedge_candidate_count_for_test("absent") == 0);
    CHECK(status_name(*rig.rt, wedge.receipt) == "Wedged");
    CHECK(rig.rt->wedged_reobservations() == reobs_before);     // nothing re-observed it
    CHECK(rig.backend->disarm_entries.load() == 0);

    wedge.gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.backend->disarmed_ids().size() == 1 && rig.rt->claim_queue_depth_for_test(wedge_key) == 0;
    }, 10s));
    const auto ids = rig.backend->armed_ids();
    REQUIRE(ids.size() == 2);
    CHECK(rig.backend->disarmed_ids() == std::vector<std::uint64_t>{ids[1]}); // compensated
    CHECK(rig.rt->rule_count() == 1);                           // only "keep"; the wedge was not adopted
    CHECK(rig.rt->wedge_candidate_count_for_test("absent") == 0);
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

// ---------------------------------------------------------------------------------------
// 7. WedgeWithdrawalPostcondition{nullopt}: the GLOBAL wedge-candidate sweep leaves no
// candidate behind, for every rule; identical re-observation afterwards restores exactly the
// re-observed rule's candidacy (W1) and no other.
// BASELINE: GREEN (regression guard on the existing detach_all()).
//
// The SCOPED form of this invariant (detach_rules_except) is case 7b below; this case keeps the
// unscoped detach_all(), which is detach_rules_except with an empty keep set.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A scoped detach 7: the global wedge sweep leaves no candidate for any rule",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec_a = file_spec("/a");
    const auto spec_b = file_spec("/b");
    auto w1 = attach_wedged(rig, "r1", spec_a, file_exists_rule("r1"));
    auto w2 = attach_wedged(rig, "r2", spec_b, file_exists_rule("r2"));
    REQUIRE(rig.rt->wedge_candidate_count_for_test("r1") == 1);
    REQUIRE(rig.rt->wedge_candidate_count_for_test("r2") == 1);
    const auto epoch_before = rig.rt->application_fence_for_test().first;

    rig.rt->detach_all();
    CHECK(rig.rt->application_fence_for_test().first == epoch_before + 1);
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 0);
    CHECK(rig.rt->wedge_candidate_count_for_test("r2") == 0);
    CHECK(status_name(*rig.rt, w1.receipt) == "Wedged");
    CHECK(status_name(*rig.rt, w2.receipt) == "Wedged");

    // Only the rule that is pushed again comes back, and it comes back as the SAME claim.
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec_a, file_exists_rule("r1"), true);
    INFO("re-push of r1: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    CHECK(again->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(again->receipt.claim == w1.receipt.claim);
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 1);
    CHECK(rig.rt->wedge_candidate_count_for_test("r2") == 0);   // r2 was not pushed again
    CHECK(rig.backend->arm_entries.load() == 2);                // one arm per key, no re-arm
}

// ---------------------------------------------------------------------------------------
// 7b. detach_rules_except(keep): the same global wedge sweep, but only rules NOT in `keep` are
// detached. Absent r1 (wedged) and r2 (a healthy committed rule) go; kept r3 (wedged) loses its
// candidacy to the global sweep and regains it only by being re-observed; kept r4 (a healthy
// committed rule) is not touched at all. The epoch moves by exactly one.
// BASELINE: no such entry point (does not compile against it); written to the seam.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A scoped detach 7b: detach_rules_except detaches only the omitted rules and "
          "still clears every wedge candidacy",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec_healthy_absent = file_spec("/h_absent");
    const auto spec_healthy_kept = file_spec("/h_kept");
    REQUIRE(rig.rt->attach_rule("r2", spec_healthy_absent, file_exists_rule("r2"), true).has_value());
    REQUIRE(rig.rt->attach_rule("r4", spec_healthy_kept, file_exists_rule("r4"), true).has_value());
    const auto kept_key = spark_key(spec_healthy_kept);
    const auto absent_key = spark_key(spec_healthy_absent);
    const auto spec_w1 = file_spec("/w1");
    const auto spec_w3 = file_spec("/w3");
    auto w1 = attach_wedged(rig, "r1", spec_w1, file_exists_rule("r1"));
    auto w3 = attach_wedged(rig, "r3", spec_w3, file_exists_rule("r3"));
    REQUIRE(rig.rt->rule_count() == 2);
    const auto epoch_before = rig.rt->application_fence_for_test().first;

    rig.rt->detach_rules_except({"r3", "r4"});
    CHECK(rig.rt->application_fence_for_test().first == epoch_before + 1);
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 0);   // absent: gone for good
    CHECK(rig.rt->wedge_candidate_count_for_test("r3") == 0);   // kept, but the global sweep clears it
    CHECK(rig.rt->rule_count() == 1);                            // r2 detached, r4 kept
    CHECK_FALSE(rig.rt->status_for_rule("r2").has_value());
    CHECK(rig.rt->status_for_rule("r4").has_value());
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.backend->disarm_entries.load() == 1 && rig.rt->claim_queue_depth_for_test(absent_key) == 0;
    }, 10s));
    CHECK(rig.rt->claim_queue_depth_for_test(kept_key) == 0);
    CHECK(rig.backend->disarm_entries.load() == 1);              // only r2's watcher; r4's is untouched
    CHECK(rig.rt->armed_key_count() == 1);

    // The kept wedged rule is re-pushed (the engine's per-rule reconcile): same claim, candidacy
    // restored. The absent one is not, and stays gone.
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r3", spec_w3, file_exists_rule("r3"), true);
    INFO("re-push of r3: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    CHECK(again->receipt.claim == w3.receipt.claim);
    CHECK(rig.rt->wedge_candidate_count_for_test("r3") == 1);
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 0);
    CHECK(status_name(*rig.rt, w1.receipt) == "Wedged");
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

// ---------------------------------------------------------------------------------------
// 8. The skip never depends on a Faulted EVENT having been delivered (governance F1). The
// backend's own health is the authority; the event only maintains a recorded bit. Each case
// makes the backend report Faulted for the key's subscription WITHOUT the runtime hearing it
// (the three ways an event is lost), then pushes the identical rule again: it must be rebuilt
// (a real disarm + arm), never skipped and reported Armed.
// Mutation: make probe_key_health report Healthy whatever the backend says and F1a, F1b, F1c and
// F1d go red (F1e drives the sweep, not the probe).
// ---------------------------------------------------------------------------------------
namespace {
/// Pushes the identical rule again and returns true iff it was REBUILT (an Accepted claim, a
/// second disarm and a second arm entered the mechanism) rather than skipped.
bool identical_push_rebuilds(Rig& rig, const SparkSpec& spec, const std::string& rid) {
    const auto key = spark_key(spec);
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, rid, spec, file_exists_rule(rid), true);
    INFO("identical re-push: " << (again ? "ok" : again.error().message));
    REQUIRE(again.has_value());
    REQUIRE(yuzu::test::spin_until([&] { return rig.rt->claim_queue_depth_for_test(key) == 0; }, 10s));
    return !again->skipped && rig.backend->arm_entries.load() == 2 &&
           rig.backend->disarm_entries.load() == 1;
}
} // namespace

TEST_CASE("#4415 PR-A F1a: a dropped Faulted event does not make a deaf rule skippable",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.backend->armed_ids().size() == 1);
    // The engine marks the subscription faulted; the event is dropped (full queued channel), so
    // on_event is never called.
    rig.backend->set_health(rig.backend->armed_ids().front(), SubscriptionHealth::Faulted);
    CHECK(identical_push_rebuilds(rig, spec, "r1"));
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

TEST_CASE("#4415 PR-A F1b: a Faulted that arrived before keys_ held the key is not lost to the "
          "skip decision",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto parked = attach_parked(rig, "r1", spec, file_exists_rule("r1"));
    // keys_ has no entry yet: the staleness guard discards this event (the id is the one the
    // parked arm will return, FakeBackend::next starts at 1).
    rig.rt->on_event(SparkEvent{.key = key, .kind = SparkEventKind::Faulted,
                                .subscription_id = 1, .detail = "early"});
    rig.backend->set_health(1, SubscriptionHealth::Faulted);
    parked.gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->rule_count() == 1 && rig.rt->claim_queue_depth_for_test(key) == 0;
    }, 10s));
    REQUIRE(rig.backend->armed_ids() == std::vector<std::uint64_t>{1});
    CHECK(identical_push_rebuilds(rig, spec, "r1"));
}

TEST_CASE("#4415 PR-A F1c: a fresh watcher that joins an engine key which is still faulted is "
          "not skippable",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    rig.rt->detach_rule("r1");
    REQUIRE(yuzu::test::spin_until([&] { return rig.rt->armed_key_count() == 0; }, 10s));
    // The mechanism's key is shared with another consumer and still faulted: the next arm gets a
    // NEW subscription id on it (a dedup join, no fault edge, so no Faulted event), and the
    // runtime's PerKey for it starts with faulted == false.
    rig.backend->set_health(2, SubscriptionHealth::Faulted);
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.backend->armed_ids().size() == 2);
    const auto disarms_before = rig.backend->disarm_entries.load();
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    REQUIRE(again.has_value());
    CHECK(!again->skipped);
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->claim_queue_depth_for_test(spark_key(spec)) == 0;
    }, 10s));
    CHECK(rig.backend->disarm_entries.load() == disarms_before + 1);
}

TEST_CASE("#4415 PR-A F1d: a healthy key is still skipped, and a Dead one is rebuilt",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    rig.backend->set_health(rig.backend->armed_ids().front(), SubscriptionHealth::Healthy);
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    REQUIRE(again.has_value());
    CHECK(again->kind == RT::ArmOutcomeKind::Armed);
    CHECK(rig.backend->arm_entries.load() == 1);
    CHECK(rig.backend->disarm_entries.load() == 0);
    // Dead is not healthy either (its Lost handling is separate; the push must not skip it).
    rig.backend->set_health(rig.backend->armed_ids().front(), SubscriptionHealth::Dead);
    auto dead = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    REQUIRE(dead.has_value());
    CHECK(!dead->skipped);
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->claim_queue_depth_for_test(spark_key(spec)) == 0;
    }, 10s));
}

TEST_CASE("#4415 PR-A F1e: the health sweep sets the faulted bit and never clears it, so the "
          "scoped detach tears down a kept rule on a deaf key",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    const auto sub = rig.backend->armed_ids().front();
    // Faulted, no event: the scoped detach consults the backend before deciding, so the kept
    // rule goes with its key and the next per-rule reconcile re-arms a fresh watcher.
    rig.backend->set_health(sub, SubscriptionHealth::Faulted);
    rig.rt->detach_rules_except({"r1"});
    CHECK(rig.rt->rule_count() == 0);
    REQUIRE(yuzu::test::spin_until([&] { return rig.backend->disarm_entries.load() == 1; }, 10s));

    // Recovered, event lost: a Faulted event set the bit and the backend now says Healthy. The
    // sweep is set-only (an older answer must never overwrite a newer event), so the stale bit
    // costs the next identical push exactly one rebuild, whose fresh PerKey starts clear.
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    const auto sub2 = rig.backend->armed_ids().back();
    rig.rt->on_event(SparkEvent{.key = spark_key(spec), .kind = SparkEventKind::Faulted,
                                .subscription_id = sub2, .detail = "deaf"});
    rig.backend->set_health(sub2, SubscriptionHealth::Healthy);
    rig.rt->revalidate_subscriptions();
    auto stale = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    REQUIRE(stale.has_value());
    CHECK(!stale->skipped);
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->claim_queue_depth_for_test(spark_key(spec)) == 0;
    }, 10s));
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    REQUIRE(again.has_value());
    CHECK(again->skipped); // a wrongly rebuilt arm that commits fast is also Armed: skipped is the proof
}

// ---------------------------------------------------------------------------------------
// 9. The withdrawal of a same-rule follower with MORE than one claim behind the wedge head. The
// head is r1's retained wedge (content A); r1 then pushes B and C (each replaces the previous
// follower through detach_rule_locked, which leaves a withdrawn entry in the fifo until it is
// swept); an identical push of A re-observes the head and withdraws the live follower. The
// helper that expires claims also drops another rule's QUEUED claim, so a foreign claim behind
// a wedge cannot be built through the public seam: the reachable three-plus-element fifo is the
// same-rule shape below, and the foreign claim is covered by the engine-level cases instead.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A re-observation withdraws the live follower when several claims sit "
          "behind the wedge head",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    auto wedge = attach_wedged(rig, "r1", spec, file_exists_rule("r1", /*present=*/true)); // A
    auto b = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec,
                                 file_exists_rule("r1", /*present=*/false), true); // B
    REQUIRE(b.has_value());
    RuleAssertion c_rule = file_exists_rule("r1", /*present=*/false);
    c_rule.rule_name = "third";
    auto c = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, c_rule, true); // C replaces B
    REQUIRE(c.has_value());
    REQUIRE(c->receipt.claim != wedge.receipt.claim);
    REQUIRE(rig.rt->claim_queue_depth_for_test(key) >= 2);

    auto revert = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec,
                                      file_exists_rule("r1", /*present=*/true), true); // A again
    REQUIRE(revert.has_value());
    CHECK(revert->receipt.claim == wedge.receipt.claim); // the head is re-observed
    CHECK(status_name(*rig.rt, c->receipt) == "Withdrawn");
    CHECK(status_name(*rig.rt, wedge.receipt) == "Wedged");
    CHECK(rig.rt->wedge_candidate_count_for_test("r1") == 1);
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

// ---------------------------------------------------------------------------------------
// 10. The content identity covers every RuleAssertion field that changes what a rule enforces
// or reports. Each case pushes a mutated copy of a healthy committed rule with exactly ONE field
// (or the compliant-edge flag) changed and requires a rebuild, never a skip. Two fields are
// deliberately outside the identity and are covered elsewhere: rule_id is the lookup key, and
// expected_hash is compared against the live effective baseline (engine case 3b, and the
// FileHashEquals block of reuse_existing_locked). A new RuleAssertion field must be added to
// assertion_content_id AND to this table (a field added to neither is the gap this guards).
// Mutation: delete any one `put(...)` line of assertion_content_id and its row goes red.
// ---------------------------------------------------------------------------------------
namespace {
bool field_change_rebuilds(const SparkSpec& spec, const RuleAssertion& base,
                           const RuleAssertion& changed, bool base_emit, bool changed_emit) {
    Rig rig;
    REQUIRE(rig.rt->attach_rule("r1", spec, base, base_emit).has_value());
    // Control: the unchanged push IS a skip, so a "rebuild" below is caused by the change.
    auto same = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, base, base_emit);
    REQUIRE(same.has_value());
    REQUIRE(same->skipped);
    auto out = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, changed, changed_emit);
    REQUIRE(out.has_value());
    const bool rebuilt = !out->skipped;
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->claim_queue_depth_for_test(spark_key(spec)) == 0;
    }, 10s));
    return rebuilt;
}
} // namespace

TEST_CASE("#4415 PR-A content identity: a change to any single RuleAssertion field rebuilds",
          "[spark][runtime][4415prA]") {
    const auto fspec = file_spec("/a");
    const RuleAssertion fbase = file_exists_rule("r1");
    {
        auto m = fbase; m.rule_name = "renamed";
        CHECK(field_change_rebuilds(fspec, fbase, m, true, true));
    }
    {
        auto m = fbase; m.debounce_ms = fbase.debounce_ms + 1;
        CHECK(field_change_rebuilds(fspec, fbase, m, true, true));
    }
    {
        auto m = fbase; m.expect_present = !fbase.expect_present;
        CHECK(field_change_rebuilds(fspec, fbase, m, true, true));
    }
    {
        auto m = fbase; m.max_bytes = fbase.max_bytes + 1;
        CHECK(field_change_rebuilds(fspec, fbase, m, true, true));
    }
    {
        auto m = fbase; m.expected_value = "v";
        CHECK(field_change_rebuilds(fspec, fbase, m, true, true));
    }
    {
        auto m = fbase; m.value_name = "n";
        CHECK(field_change_rebuilds(fspec, fbase, m, true, true));
    }
    CHECK(field_change_rebuilds(fspec, fbase, fbase, /*base_emit=*/true, /*changed_emit=*/false));
    // Split collisions: the same concatenation of ADJACENT fields (the order in
    // assertion_content_id is rule_name, debounce_ms, ..., expected_value, value_name) split at a
    // different point must still differ. Mutation: drop the length prefix AND the ':' separator
    // from assertion_content_id's put() and both of these report "not rebuilt" (the first
    // concatenates to "a10" either way; verified on a scratch copy of the id function).
    {
        auto b = fbase; b.rule_name = "a1"; b.debounce_ms = 0;
        auto m = fbase; m.rule_name = "a"; m.debounce_ms = 10;
        CHECK(field_change_rebuilds(fspec, b, m, true, true));
    }
    {
        auto b = fbase; b.expected_value = "x"; b.value_name = "";
        auto m = fbase; m.expected_value = ""; m.value_name = "x";
        CHECK(field_change_rebuilds(fspec, b, m, true, true));
    }
    // kind: ServiceRunning -> ServiceStopped on the same service key.
    const auto sspec = svc_spec_for_identity();
    const RuleAssertion sbase = svc_rule_for_identity("r1", AssertionKind::ServiceRunning);
    CHECK(field_change_rebuilds(sspec, sbase,
                                svc_rule_for_identity("r1", AssertionKind::ServiceStopped), true, true));
}

// ---------------------------------------------------------------------------------------
// 11. ADR-0021 clause 3: stop() is sticky. A skip is a claim the rule is live, so an identical
// push after begin_stop() must be REFUSED like any attach, never answered Armed.
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A an identical attach after begin_stop() is refused, not skipped",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    rig.rt->begin_stop();
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    CHECK_FALSE(again.has_value());
    auto blocking = rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true);
    CHECK_FALSE(blocking.has_value());
}

// ---------------------------------------------------------------------------------------
// 12. An in-flight arm whose push differs ONLY in the authored expected_hash is not re-observed:
// content_id leaves expected_hash out, so the claim's pushed_hash term is what separates the two.
// Mutation: delete `c->pushed_hash == pushed.assertion.expected_hash` in reuse_existing_locked
// (the second push then returns the first push's claim and the new hash is dropped).
// ---------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A an in-flight arm is not re-observed by a push with a different expected_hash",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    auto parked = attach_parked(rig, "r1", spec, file_hash_rule("r1", "h"));
    auto changed = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_hash_rule("r1", "other"), true);
    INFO("changed-hash attach: " << (changed ? "ok" : changed.error().message));
    REQUIRE(changed.has_value());
    CHECK(changed->receipt.claim != parked.receipt.claim);
    CHECK(status_name(*rig.rt, parked.receipt) == "Withdrawn"); // replaced, not kept alongside
}

// ---------------------------------------------------------------------------------------
// 13. Backend health authority, the cases a lost event or a misbehaving backend reach.
// ---------------------------------------------------------------------------------------
namespace {
/// Joins every thread on EVERY exit path, after the gates guarding them were released.
struct Joiner {
    std::mutex mu;
    std::vector<std::thread> threads;
    void add(std::thread t) {
        std::lock_guard<std::mutex> lk{mu};
        threads.push_back(std::move(t));
    }
    ~Joiner() {
        for (auto& t : threads)
            if (t.joinable())
                t.join();
    }
};

/// Clears the backend's health hook on scope exit. Declare it AFTER the stack locals the hook
/// captures by reference, so it runs BEFORE they die and the hook never outlives them.
struct HookReset {
    Rig& rig;
    ~HookReset() { rig.backend->set_health_hook({}); }
};
} // namespace

// Two rules share ONE key whose subscription the backend reports Dead while its Lost event has
// not been delivered (CH-1 / UP-1). The scoped detach of an identical full_sync must tear the
// key down so both kept rules re-arm on a NEW subscription; left kept, each rule's attach would
// rebuild but rejoin the dead PerKey, report Armed, and be errored by the next revalidate.
// Mutation: in sweep_key_health, stop treating Dead as unhealthy when !report_dead (armed_ids
// stays at one subscription and rule_count drops to 0 after the revalidate).
TEST_CASE("#4415 PR-A F1f: a Dead key shared by two kept rules is rebuilt by the scoped detach, "
          "and both rules end armed on a new subscription",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.rt->attach_rule("r2", spec, file_exists_rule("r2"), true).has_value());
    REQUIRE(rig.backend->armed_ids() == std::vector<std::uint64_t>{1}); // one shared watcher
    rig.backend->set_health(1, SubscriptionHealth::Dead); // no Lost event is delivered

    rig.rt->detach_rules_except({"r1", "r2"});
    CHECK(rig.rt->rule_count() == 0); // both went with their key
    REQUIRE(yuzu::test::spin_until([&] { return rig.backend->disarm_entries.load() == 1; }, 10s));

    // The per-rule reconcile of the same push.
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.rt->attach_rule("r2", spec, file_exists_rule("r2"), true).has_value());
    CHECK(rig.backend->armed_ids() == std::vector<std::uint64_t>{1, 2});
    rig.rt->revalidate_subscriptions(); // the backstop finds nothing dead on the new subscription
    CHECK(rig.rt->rule_count() == 2);
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

// A backend whose health query throws: the probe treats it as unhealthy (rebuild).
// Mutation: remove the catch in probe_key_health (the exception escapes attach_rule).
TEST_CASE("#4415 PR-A F1g: a health query that throws makes an identical push rebuild",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    rig.backend->set_health_hook([](std::uint64_t) { throw std::runtime_error("health"); });
    CHECK(identical_push_rebuilds(rig, spec, "r1"));
}

// The same throwing backend during the scoped detach: the sweep never aborts the teardown of the
// omitted rule (CH-4 / UP-3). The kept rule's health is unknown, which is not healthy, so its key
// is rebuilt too (what the full teardown did before #4415).
// Mutation: remove the try/catch around the backend call in sweep_key_health (the throw escapes
// detach_rules_except before r2 is detached).
TEST_CASE("#4415 PR-A F1h: a throwing health query does not stop the scoped detach from "
          "detaching the omitted rules",
          "[spark][runtime][4415prA]") {
    Rig rig;
    REQUIRE(rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true).has_value());
    rig.backend->set_health_hook([](std::uint64_t) { throw std::runtime_error("health"); });
    rig.rt->detach_rules_except({"r1"});
    CHECK_FALSE(rig.rt->status_for_rule("r2").has_value());
    CHECK_FALSE(rig.rt->status_for_rule("r1").has_value()); // unknown health: rebuilt
    REQUIRE(yuzu::test::spin_until([&] { return rig.backend->disarm_entries.load() == 2; }, 10s));
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

// The poll backstop (report_dead=true) with a backend whose health query throws for one key: the
// exception does not escape, the unknown-health key is NOT reported lost (unknown is not dead),
// and the sweep still reaches the next key, whose Dead answer is reported as before.
// Mutation: remove the try/catch around the backend call in sweep_key_health (the throw escapes).
TEST_CASE("#4415 PR-A F1k: a throwing health query does not stop the poll backstop",
          "[spark][runtime][4415prA]") {
    Rig rig;
    REQUIRE(rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true).has_value());
    REQUIRE(rig.rt->attach_rule("r3", file_spec("/c"), file_exists_rule("r3"), true).has_value());
    const auto ids = rig.backend->armed_ids();
    REQUIRE(ids.size() == 3);
    // The sweep visits keys in unordered_map order, so the test must not depend on which key is
    // visited first: every subscription is Dead and the hook throws on whichever is asked FIRST,
    // so the other two are always visited after the throw.
    for (const auto id : ids)
        rig.backend->set_health(id, SubscriptionHealth::Dead);
    std::atomic<bool> first{true};
    std::atomic<int> thrown{0};
    HookReset hook_reset{rig}; // after the captured locals: resets the hook before they die
    rig.backend->set_health_hook([&first, &thrown](std::uint64_t) {
        if (first.exchange(false)) {
            thrown.fetch_add(1);
            throw std::runtime_error("health");
        }
    });
    CHECK_NOTHROW(rig.rt->revalidate_subscriptions());
    CHECK(thrown.load() == 1); // the hook really threw (else this proves nothing)
    // The unknown-health key is left attached, the two Dead keys visited after it are reported
    // lost and detached.
    CHECK(rig.rt->rule_count() == 1);
    CHECK(rig.rt->invariant_violations_for_test().empty());
}

// registry_mu_ is not held while the backend answers (probe and sweep): from INSIDE the backend's
// health call another thread reads the registry. If the lock were held across the call that
// thread could not finish while the call is still running.
// Mutation: take registry_mu_ around the backend call in probe_key_health or sweep_key_health.
TEST_CASE("#4415 PR-A F1i: the registry lock is not held across the backend health query",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec_a = file_spec("/a");
    const auto spec_b = file_spec("/b");
    REQUIRE(rig.rt->attach_rule("r1", spec_a, file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.rt->attach_rule("r2", spec_b, file_exists_rule("r2"), true).has_value());
    const auto key = spark_key(spec_a);
    Joiner joiner; // joins the hook's helper threads (each already finished: the hook awaits it)
    std::atomic<int> reentered{0}, blocked{0};
    HookReset hook_reset{rig}; // after the captured locals: resets the hook before they die
    rig.backend->set_health_hook([&](std::uint64_t) {
        auto done = std::make_shared<std::atomic<bool>>(false);
        joiner.add(std::thread([&rig, key, done] {
            (void)rig.rt->rule_count();
            (void)rig.rt->claim_queue_depth_for_test(key);
            done->store(true);
        }));
        if (yuzu::test::spin_until([&] { return done->load(); }, 5s))
            ++reentered;
        else
            ++blocked;
    });
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec_a, file_exists_rule("r1"), true);
    REQUIRE(again.has_value());
    CHECK(again->skipped);                // the probe ran (and the rule is skipped)
    const int after_probe = reentered.load();
    CHECK(after_probe >= 1);              // the probe call site re-entered the registry
    rig.rt->detach_rules_except({"r1", "r2"});       // the sweep asks for each armed key
    CHECK(reentered.load() - after_probe >= 1);      // the sweep call site did too (not an exact
                                                     // count: that is an implementation detail)
    CHECK(blocked.load() == 0);
}

// The subscription is replaced while the probe is parked in the backend: the answer was about the
// OLD subscription, so the locked decision must rebuild rather than skip (the relock revalidation).
// Mutation: drop `probe->subscription != kit->second->subscription` in reuse_existing_locked.
TEST_CASE("#4415 PR-A F1j: a subscription replaced between the probe and the relock is rebuilt, "
          "not skipped",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    std::mutex mu;
    std::condition_variable cv;
    bool entered = false, released = false;
    std::atomic<bool> first{true};
    rig.backend->set_health_hook([&](std::uint64_t) {
        if (!first.exchange(false))
            return;
        std::unique_lock<std::mutex> lk{mu};
        entered = true;
        cv.notify_all();
        cv.wait(lk, [&] { return released; });
    });
    const auto release = [&] {
        std::lock_guard<std::mutex> lk{mu};
        released = true;
        cv.notify_all();
    };
    std::optional<bool> skipped;
    Joiner joiner;
    struct Releaser {
        std::function<void()> fn;
        ~Releaser() { fn(); }
    } releaser{release}; // runs before the joiner on every exit path
    HookReset hook_reset{rig}; // declared last: resets the hook before the captured locals die
    joiner.add(std::thread([&] {
        auto out = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
        if (out.has_value())
            skipped = out->skipped;
    }));
    {
        std::unique_lock<std::mutex> lk{mu};
        REQUIRE(cv.wait_for(lk, 10s, [&] { return entered; }));
    }
    rig.rt->detach_rule("r1");
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    REQUIRE(rig.backend->armed_ids().size() == 2); // the replacement subscription
    release();
    joiner.threads.front().join();
    REQUIRE(skipped.has_value());
    CHECK(!*skipped);
    REQUIRE(yuzu::test::spin_until([&] {
        return rig.rt->claim_queue_depth_for_test(spark_key(spec)) == 0;
    }, 10s));
    CHECK(rig.backend->arm_entries.load() == 3);
}

// The in_unknown skip term at the runtime level: a rule whose last evaluation was Unknown is not
// healthy, so an identical push rebuilds it. Mutation: delete `live.eval.in_unknown` from
// reuse_existing_locked.
TEST_CASE("#4415 PR-A a rule in an Unknown evaluation episode is rebuilt by an identical push",
          "[spark][runtime][4415prA]") {
    Rig rig;
    const auto spec = file_spec("/a");
    const auto key = spark_key(spec);
    REQUIRE(rig.rt->attach_rule("r1", spec, file_exists_rule("r1"), true).has_value());
    rig.reader->file = read_unknown<FileSnapshot>("io");
    rig.rt->evaluate_key(key, EvalReason::Initial);
    const auto st = rig.rt->status_for_rule("r1");
    REQUIRE(st.has_value());
    REQUIRE(st->in_unknown);
    auto again = rig.rt->attach_rule(RT::NonWaiting{}, "r1", spec, file_exists_rule("r1"), true);
    REQUIRE(again.has_value());
    CHECK(!again->skipped);
    REQUIRE(yuzu::test::spin_until([&] { return rig.rt->claim_queue_depth_for_test(key) == 0; }, 10s));
}
