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

#include "guardian_spark_runtime.hpp"

#include <yuzu/agent/spark.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
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
    std::vector<std::uint64_t> armed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return armed_ids_;
    }
    std::vector<std::uint64_t> disarmed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return disarmed_ids_;
    }

private:
    std::mutex gates_mu_;
    std::unordered_map<std::string, std::shared_ptr<ArmGate>> gates_;
    std::vector<std::shared_ptr<ArmGate>> all_gates_;
    mutable std::mutex ids_mu_;
    std::vector<std::uint64_t> armed_ids_;
    std::vector<std::uint64_t> disarmed_ids_;
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
    ~Rig() { backend->release_all_gates(); }
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
// from; the bulk entry point itself does not exist yet - see 7).
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
