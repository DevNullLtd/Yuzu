// test_guardian_arm_ack.cpp - rung 9c PR-2 Unit 5 (ack bookkeeping preparation,
// docs/spark-stage2-guardian-consumer-design.md §R5.3). GuardianArmAckLedger and
// guardian_push_content_id() are exercised directly here, against a real
// GuardianSparkRuntime + a minimal fake backend (genuine ArmReceipts via
// attach_rule(NonWaiting, ...), not faked statuses) - PREPARATION ONLY: nothing
// here wires the ledger into GuardianEngine::apply_rules() (that is Unit 6).

#include "guardian_arm_ack.hpp"

#include "guaranteed_state.pb.h"

#include <yuzu/agent/spark.hpp>

#include "test_helpers.hpp" // yuzu::test::spin_until

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <variant>

using namespace yuzu::agent;
namespace gpb = ::yuzu::guardian::v1;

namespace {

struct FakeReader : IStateReader {
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan&) override {
        return read_known(FileSnapshot{.exists = true});
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan& plan) override {
        RegistryRead out;
        for (const auto& vn : plan.value_names)
            out.values.emplace(vn, read_known(RegistrySnapshot{.present = true, .value = "v"}));
        return out;
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        return read_known(ServiceRunState::Running);
    }
    void request_stop() noexcept override {}
};

// Minimal fake, sized for this file only (test_guardian_convergence_scheduler.cpp's own
// precedent: each consumer of GuardianSparkRuntime writes its own lean fake rather than
// sharing test_guardian_spark_runtime.cpp's full-featured one). A single hang gate is
// enough - Unit 5's ledger tests need "accepted, still pending" and "later resolves",
// not the soak/lane machinery the runtime's own test suite exercises.
struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::atomic<bool> fail_arm{false};
    std::atomic<bool> hang_next_arm{false};
    /// Unlike hang_next_arm (single-shot, consumed by the first caller), this parks
    /// EVERY arm() call - needed for the bounded-drain test below, which needs several
    /// independent keys simultaneously Pending, not just one.
    std::atomic<bool> hang_every_arm{false};
    std::atomic<int> parked{0};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool entered_hang_{false};
    bool released_{false};
    // Per-path single-shot gates (all guarded by gate_mu_), independent of the global
    // gate above: lets a test park a SECOND arm and release it alone while an earlier
    // arm stays parked on the global gate (e.g. a still-wedged r1). Checked BEFORE the
    // global gate, so a path-gated arm never consumes hang_next_arm.
    std::set<std::string> hang_paths_;
    std::set<std::string> entered_paths_;
    std::set<std::string> released_paths_;

    /// accept()'s precondition: an arm that could resolve (success OR fail_arm) on
    /// the worker before attach_rule(NonWaiting) re-checks the claim may legitimately
    /// return Armed or a failure instead of Accepted. So every fresh (non-Reobserved)
    /// accept() must be preceded by arming a gate whose release it controls.
    std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) override {
        const auto* file = std::get_if<FileSparkParams>(&spec.params);
        bool path_gated = false;
        if (file) {
            std::unique_lock<std::mutex> lk{gate_mu_};
            if (hang_paths_.erase(file->path) > 0) {
                path_gated = true;
                entered_paths_.insert(file->path);
                gate_cv_.notify_all();
                gate_cv_.wait(lk, [this, file] { return released_paths_.contains(file->path); });
            }
        }
        if (!path_gated && (hang_next_arm.exchange(false) || hang_every_arm.load())) {
            std::unique_lock<std::mutex> lk{gate_mu_};
            entered_hang_ = true;
            ++parked;
            gate_cv_.notify_all();
            gate_cv_.wait(lk, [this] { return released_; });
        }
        if (fail_arm.load())
            return std::unexpected(std::string{"no mechanism"});
        return next.fetch_add(1);
    }
    /// #5459: parks the NEXT disarm() call (single-shot) until release_disarm(), so a
    /// test can hold a wedge's compensating teardown outstanding (the claim stays the
    /// Dispatched FIFO front with compensation_finished false). Guarded by gate_mu_.
    std::atomic<bool> hang_next_disarm{false};
    bool disarm_entered_{false};
    bool disarm_released_{false};
    void disarm(std::uint64_t) override {
        if (!hang_next_disarm.exchange(false))
            return;
        std::unique_lock<std::mutex> lk{gate_mu_};
        disarm_entered_ = true;
        gate_cv_.notify_all();
        gate_cv_.wait(lk, [this] { return disarm_released_; });
    }
    bool wait_entered_disarm(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this] { return disarm_entered_; });
    }
    void release_disarm() {
        {
            std::lock_guard<std::mutex> lk{gate_mu_};
            disarm_released_ = true;
        }
        gate_cv_.notify_all();
    }

    bool wait_entered_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this] { return entered_hang_; });
    }
    bool wait_parked(int n, std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this, n] { return parked.load() >= n; });
    }
    /// Releases the global gate AND every armed or parked per-path gate - the
    /// teardown-safe "let every worker go" call every Cleanup guard relies on.
    void release_hang() {
        {
            std::lock_guard<std::mutex> lk{gate_mu_};
            released_ = true;
            released_paths_.insert(entered_paths_.begin(), entered_paths_.end());
            released_paths_.insert(hang_paths_.begin(), hang_paths_.end());
        }
        gate_cv_.notify_all();
    }
    /// Re-arms the global gate after a previous release_hang(): without this, a
    /// second wait_entered_hang()/release_hang() pair passes trivially (both flags
    /// are still true) and hang_next_arm, being single-shot, no longer parks
    /// anything. Only valid while nothing is parked on the global gate.
    void reset_hang() {
        std::lock_guard<std::mutex> lk{gate_mu_};
        entered_hang_ = false;
        released_ = false;
    }

    /// Per-path gate: the NEXT arm() of `path` parks until release_path(path) (or
    /// release_hang()). Re-armable - clears any earlier entered/released state.
    void hang_next_arm_on(const std::string& path) {
        std::lock_guard<std::mutex> lk{gate_mu_};
        hang_paths_.insert(path);
        entered_paths_.erase(path);
        released_paths_.erase(path);
    }
    bool wait_entered_path(const std::string& path, std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this, &path] { return entered_paths_.contains(path); });
    }
    void release_path(const std::string& path) {
        {
            std::lock_guard<std::mutex> lk{gate_mu_};
            released_paths_.insert(path);
        }
        gate_cv_.notify_all();
    }
};

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}
RuleAssertion file_exists_rule(const std::string& rule_id) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = rule_id;
    a.expect_present = true;
    return a;
}

std::shared_ptr<GuardianSparkRuntime> make_rt(std::shared_ptr<FakeReader> r,
                                              std::shared_ptr<FakeBackend> b,
                                              GuardianSparkRuntime::Config cfg = {}) {
    return std::make_shared<GuardianSparkRuntime>(std::move(r), std::move(b), cfg);
}

/// Accept rule_id via attach_rule(NonWaiting, ...) and REQUIRE it came back Accepted
/// (a parked FakeBackend arm never resolves synchronously). Returns the receipt.
GuardianSparkRuntime::ArmReceipt accept(GuardianSparkRuntime& rt, const std::string& rule_id,
                                        const std::string& path = "/a") {
    auto res = rt.attach_rule(GuardianSparkRuntime::NonWaiting{}, rule_id, file_spec(path),
                              file_exists_rule(rule_id), true);
    REQUIRE(res.has_value());
    REQUIRE(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    return res->receipt;
}

/// A minimal single-rule push, for guardian_push_content_id() and decide_retry() tests.
gpb::GuaranteedStatePush one_rule_push(const std::string& rule_id, const std::string& param_value,
                                       bool full_sync = false) {
    gpb::GuaranteedStatePush push;
    push.set_full_sync(full_sync);
    auto* rule = push.add_rules();
    rule->set_rule_id(rule_id);
    rule->set_enabled(true);
    rule->set_enforcement_mode("enforce");
    rule->set_version(1);
    rule->mutable_spark()->set_type("file-change");
    rule->mutable_spark()->mutable_params()->insert({"path", param_value});
    rule->mutable_assertion()->set_type("file-exists");
    return push;
}

using RD = GuardianArmAckLedger::RetryDecision;
using RT = GuardianSparkRuntime;

/// #5459 (option D) rig: a real GuardianSparkRuntime + real GuardianArmAckLedger over the
/// file's FakeBackend, with deterministic, sleep-free wedge creation. The runtime's
/// backend_op_deadline is 120 s, so no claim can age out on the real clock inside a test
/// (drain_locked()'s own expire_overdue_claims() sweep therefore never touches a Pending
/// sibling); claims are aged on demand with age_out(), which advances the sweep's clock
/// instead of sleeping. Every claim parks on its OWN per-path gate, so wedges, Pending
/// siblings and refusals can be created independently and settled one at a time.
struct Rig5459 {
    std::shared_ptr<FakeReader> r = std::make_shared<FakeReader>();
    std::shared_ptr<FakeBackend> b = std::make_shared<FakeBackend>();
    std::shared_ptr<RT> rt = make_rt(r, b, RT::Config{.backend_op_deadline = std::chrono::seconds(120)});
    const std::string digest = std::string(64, 'a'); // real-shaped SHA-256 hex: identity is exact
    GuardianArmAckLedger ledger;

    Rig5459() = default;
    // Releases every park before the runtime stops, so a failing REQUIRE cannot leave a
    // detached worker parked.
    ~Rig5459() {
        b->release_disarm();
        b->release_hang();
        rt->begin_stop();
        (void)yuzu::test::spin_until([&] { return rt->active_backend_op_workers() == 0; },
                                     std::chrono::seconds(10));
    }

    [[nodiscard]] static std::string key_of(const std::string& path) { return spark_key(file_spec(path)); }

    /// Accepts `rule_id` and parks its arm inside the backend (Pending).
    RT::ArmReceipt hang(const std::string& rule_id, const std::string& path) {
        b->hang_next_arm_on(path);
        auto receipt = accept(*rt, rule_id, path);
        REQUIRE(b->wait_entered_path(path, std::chrono::seconds(30)));
        return receipt;
    }
    /// Ages every currently-Pending claim past its 120 s deadline (no sleep).
    void age_out() {
        REQUIRE(rt->expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() +
                                                      std::chrono::seconds(121)) >= 1);
    }
    /// A genuinely hung, dispatched arm aged past its deadline: a retained Wedged claim that
    /// is the key's Dispatched FIFO front, with no compensation outstanding.
    RT::ArmReceipt wedge(const std::string& rule_id, const std::string& path) {
        auto receipt = hang(rule_id, path);
        age_out();
        REQUIRE(rt->receipt_status(receipt) == RT::ReceiptStatus::Wedged);
        REQUIRE(rt->receipt_wedge_k_eligible(receipt));
        return receipt;
    }
    /// Must be created AFTER every age_out() of the test: stays Pending.
    RT::ArmReceipt pending_sibling(const std::string& rule_id, const std::string& path) {
        return hang(rule_id, path);
    }
    RT::ArmReceipt committed_sibling(const std::string& rule_id, const std::string& path) {
        auto receipt = hang(rule_id, path);
        b->release_path(path);
        REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
        REQUIRE(rt->receipt_status(receipt) == RT::ReceiptStatus::Committed);
        return receipt;
    }
    /// An ORDINARY (non-wedge) failure: a real backend refusal, resolved before any expiry.
    RT::ArmReceipt failed_sibling(const std::string& rule_id, const std::string& path) {
        auto receipt = hang(rule_id, path);
        b->fail_arm.store(true);
        b->release_path(path);
        REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
        b->fail_arm.store(false);
        REQUIRE(rt->receipt_status(receipt) == RT::ReceiptStatus::Failed);
        return receipt;
    }
    /// The wedged arm finally refuses: the claim is popped and nothing adopts it.
    void late_failure(const std::string& path) {
        b->fail_arm.store(true);
        b->release_path(path);
        REQUIRE(yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key_of(path)) == 0; },
                                       std::chrono::seconds(10)));
        b->fail_arm.store(false);
    }
    /// The wedged rule is withdrawn (so its late success is NOT adopted) and the hung arm
    /// returns: the compensating disarm parks inside the backend, the claim stays the
    /// Dispatched FIFO front with compensation_finished false.
    void start_compensation(const std::string& path) {
        b->hang_next_disarm.store(true);
        rt->detach_all();
        b->release_path(path);
        REQUIRE(b->wait_entered_disarm(std::chrono::seconds(10)));
        REQUIRE(rt->claim_queue_depth_for_test(key_of(path)) == 1);
    }
    void finish_compensation(const std::string& path) {
        b->release_disarm();
        REQUIRE(yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key_of(path)) == 0; },
                                       std::chrono::seconds(10)));
    }
    void open_app(std::size_t applied = 1) { ledger.begin_application(1, digest, false, applied); }
    [[nodiscard]] RD retry() { return ledger.decide_retry(1, digest, false, *rt); }
};

} // namespace

TEST_CASE("guardian_push_content_id(): identical content hashes identically "
          "regardless of param insertion order",
          "[spark][ack]") {
    gpb::GuaranteedStatePush a;
    a.set_full_sync(false);
    auto* ra = a.add_rules();
    ra->set_rule_id("r1");
    ra->set_enabled(true);
    ra->set_enforcement_mode("enforce");
    ra->set_version(1);
    ra->mutable_spark()->set_type("file-change");
    ra->mutable_spark()->mutable_params()->insert({"path", "/a"});
    ra->mutable_spark()->mutable_params()->insert({"recursive", "true"});

    gpb::GuaranteedStatePush b;
    b.set_full_sync(false);
    auto* rb = b.add_rules();
    rb->set_rule_id("r1");
    rb->set_enabled(true);
    rb->set_enforcement_mode("enforce");
    rb->set_version(1);
    rb->mutable_spark()->set_type("file-change");
    rb->mutable_spark()->mutable_params()->insert({"recursive", "true"}); // reversed insertion order
    rb->mutable_spark()->mutable_params()->insert({"path", "/a"});

    CHECK(guardian_push_content_id(a) == guardian_push_content_id(b));
}

TEST_CASE("guardian_push_content_id(): a changed param value changes the id; "
          "full_sync alone also changes it",
          "[spark][ack]") {
    const auto base = one_rule_push("r1", "/a");
    const auto changed_param = one_rule_push("r1", "/b");
    const auto changed_full_sync = one_rule_push("r1", "/a", /*full_sync=*/true);

    const auto id_base = guardian_push_content_id(base);
    CHECK(id_base == guardian_push_content_id(one_rule_push("r1", "/a"))); // stable, reproducible
    CHECK(id_base != guardian_push_content_id(changed_param));
    CHECK(id_base != guardian_push_content_id(changed_full_sync));
}

TEST_CASE("GuardianArmAckLedger: a superseded application's stale receipt cannot "
          "satisfy the NEW application, even once it commits",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_every_arm.store(true); // r1 (gen 1) and r2 (gen 2) both need to park independently
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(/*generation=*/1, "content-a", /*full_sync=*/false, /*applied=*/1);
    auto r1 = accept(*rt, "r1", "/a");
    ledger.add_pending("r1", r1);
    CHECK_FALSE(ledger.can_advance()); // r1 still pending

    // A higher-generation application supersedes it before r1 ever resolves - r1's own
    // claim is NOT re-added to generation 2; generation 2 gets its own, different rule.
    ledger.begin_application(/*generation=*/2, "content-b", /*full_sync=*/false, /*applied=*/1);
    auto r2 = accept(*rt, "r2", "/b");
    ledger.add_pending("r2", r2);
    CHECK_FALSE(ledger.can_advance()); // r2 still pending - not vacuously true
    REQUIRE(b->wait_parked(2, std::chrono::seconds(30)));

    // Release both - r1 (generation 1's own claim, no longer watched by any ledger) and
    // r2 (generation 2's own claim) resolve independently.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(r1) && rt->is_terminal(r2); },
                                   std::chrono::seconds(10)));

    // Draining generation 2's ledger must resolve EXACTLY r2 - r1's commit was never
    // added to this application's pending map, so it is neither seen nor counted here.
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10) == 1);
    CHECK(ledger.can_advance());
    CHECK(ledger.applied_count() == 1); // generation 2's own stashed count, unaffected by r1
}

TEST_CASE("GuardianArmAckLedger: can_advance() is false with zero pending, zero "
          "armed, and one resolved failure - never vacuously true",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    // Hang first so attach_core's own completion-before-return race always resolves
    // to Accepted (the worker cannot possibly finish before it's released), THEN flip
    // fail_arm before releasing - a genuinely asynchronous Failed resolution.
    b->hang_next_arm.store(true);
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Failed);

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 0);
    ledger.add_pending("r1", receipt);
    ledger.drain_locked(*rt, 10);
    CHECK(ledger.can_advance() == false);
}

TEST_CASE("GuardianArmAckLedger: a latched teardown failure holds the generation "
          "even once every receipt commits",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 0);
    ledger.latch_failure(); // e.g. this generation's full_sync kv sweep failed
    auto receipt = accept(*rt, "r1");
    ledger.add_pending("r1", receipt);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Committed);

    ledger.drain_locked(*rt, 10);
    CHECK_FALSE(ledger.can_advance()); // r1 committed cleanly, but the latch still holds it
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): identical (generation, content, "
          "full_sync) while every receipt is still pending is Suppressed",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    // Governance finding UP-2/SHOULD-2 (Gate 4): decide_retry() now requires BOTH
    // sides of a content_id comparison to look like a real SHA-256 digest (64 hex
    // chars) before trusting the comparison at all - a human-readable placeholder
    // like the old "content-x" would now unconditionally Reapply regardless of what
    // this test is trying to pin, since it isn't a valid hash. Use real-shaped hex
    // stand-ins so the SUPPRESS/REAPPLY assertions below still exercise the
    // content-comparison branch they were written to test, not the sentinel guard.
    const std::string content_x(64, 'a');
    const std::string content_y(64, 'b');

    GuardianArmAckLedger ledger;
    ledger.begin_application(5, content_x, false, 3);
    ledger.add_pending("r1", accept(*rt, "r1"));
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    ledger.drain_locked(*rt, 10); // r1 still parked - stays Pending
    CHECK(ledger.decide_retry(5, content_x, false, *rt) == GuardianArmAckLedger::RetryDecision::Suppress);
    CHECK(ledger.applied_count() == 3);

    // A different generation is never a retry - always Reapply.
    CHECK(ledger.decide_retry(6, content_x, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
    // Changed content under the SAME generation number is Reapply too.
    CHECK(ledger.decide_retry(5, content_y, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
    // Changed full_sync flag alone is Reapply.
    CHECK(ledger.decide_retry(5, content_x, true, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
    // A non-hash sentinel content_id (the boot placeholder, or a hash-throw
    // fallback) is NEVER trusted to mean "same content", even if it happens to
    // match byte-for-byte - it degrades to Reapply instead.
    CHECK(ledger.decide_retry(5, "", false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; }, std::chrono::seconds(10)));
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): once a pending receipt resolves "
          "to an ORDINARY (non-wedge) failure, the same (generation, content) is "
          "Reapply, not Suppress",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    const std::string content_x(64, 'a'); // see the sibling Suppress test above for why

    GuardianArmAckLedger ledger;
    ledger.begin_application(5, content_x, false, 1);
    auto receipt = accept(*rt, "r1");
    ledger.add_pending("r1", receipt);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));

    ledger.drain_locked(*rt, 10);
    CHECK(ledger.decide_retry(5, content_x, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): bounded per call - 3 pending "
          "receipts resolve over two ticks, at most 2 per call",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_every_arm.store(true); // every one of the 3 keys below parks independently
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 3);
    // 3 DISTINCT keys (paths) - same-key siblings would queue behind one shared
    // arm instead of each dispatching (and parking) their own, per R5.2.
    auto r1 = accept(*rt, "r1", "/a");
    auto r2 = accept(*rt, "r2", "/b");
    auto r3 = accept(*rt, "r3", "/c");
    ledger.add_pending("r1", r1);
    ledger.add_pending("r2", r2);
    ledger.add_pending("r3", r3);
    REQUIRE(b->wait_parked(3, std::chrono::seconds(30)));

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(r1) && rt->is_terminal(r2) &&
                                                rt->is_terminal(r3); },
                                   std::chrono::seconds(10)));

    const auto first = ledger.drain_locked(*rt, /*max_per_tick=*/2);
    CHECK(first == 2);
    CHECK_FALSE(ledger.can_advance()); // one still un-drained

    const auto second = ledger.drain_locked(*rt, /*max_per_tick=*/2);
    CHECK(second == 1);
    CHECK(ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::retire(): drops the current application without "
          "resolving it further, and can_advance() reports false afterward",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 1);
    ledger.add_pending("r1", accept(*rt, "r1"));
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    ledger.retire();
    CHECK_FALSE(ledger.can_advance()); // no current application at all
    CHECK(ledger.decide_retry(1, "content", false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);

    b->release_hang(); // the runtime's own claim still resolves on its own schedule (§R5.5)
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; }, std::chrono::seconds(10)));
}

// ---------------------------------------------------------------------------
// Governance hardening round (Gates 2-6, rung 9c PR-2): sec-1/arch-1 and cae-1
// regression tests. sec-1/arch-1 was the production-live wedge (confirmed
// reachable today via spark_runtime_, independent of prefer_spark_ - see
// sre's and enterprise-readiness's Gate 6 findings): decide_retry() used to
// vacuously Suppress whenever `pending` was empty, which is the case on
// EVERY push at prefer_spark_=false (Accepted is unreachable there) - so a
// failed generation-advance persist was never retried by any repeat push.
// cae-1 was guardian_push_content_id()'s canonicalization not being
// block-boundary-injective (cpp-expert, hand-verified collision).
// ---------------------------------------------------------------------------

TEST_CASE("GuardianArmAckLedger::decide_retry(): no pending receipts and no retained "
          "outstanding work is Reapply, never a vacuous Suppress",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    const std::string content(64, 'c');

    GuardianArmAckLedger ledger;
    // Nothing was ever Accepted this application (the ordinary case at
    // prefer_spark_=false) - pending stays empty for its whole lifetime.
    ledger.begin_application(5, content, false, 3);
    CHECK(ledger.can_advance()); // trivially true - nothing to hold the generation

    // TARGET (sec-1/arch-1): before the fix, an identical (generation, content,
    // full_sync) retry against an application with nothing pending fell through
    // to a vacuous Suppress - exactly the shape of a server retry arriving after
    // a transient persist_generation_locked() failure, which this decision
    // alone is what silently and permanently wedged the reported generation.
    // Reapply here is what lets the caller's own tail gate retry that persist.
    CHECK(ledger.decide_retry(5, content, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);

    // #5459: an empty `pending` is no longer the ONLY thing that decides this (an
    // outstanding wedge in a pending-empty application Suppresses - see the wedge tests
    // below); what stays true is that NOTHING in flight at all is Reapply, and that a drain
    // of the empty application does not change that.
    CHECK(ledger.drain_locked(*rt, 10) == 0);
    CHECK(ledger.decide_retry(5, content, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): default-path pin - with nothing Accepted "
          "(prefer_spark_=false) EVERY decision is Reapply (#5459)",
          "[spark][ack][5459]") {
    // GuardianEngine wires spark_runtime_ (and so this ledger's decide_retry()) at boot
    // regardless of prefer_spark_, so this is live in production at the default. The
    // restructured decision must not Suppress a push that has nothing in flight, on ANY
    // path: matching identity, mismatching identity, sentinel, latched, no application.
    Rig5459 f;
    CHECK(f.retry() == RD::Reapply); // no current application at all

    f.ledger.begin_application(5, f.digest, false, 3); // nothing is ever add_pending()ed
    CHECK(f.ledger.decide_retry(5, f.digest, false, *f.rt) == RD::Reapply); // identical retry
    CHECK(f.ledger.decide_retry(6, f.digest, false, *f.rt) == RD::Reapply);
    CHECK(f.ledger.decide_retry(5, std::string(64, 'b'), false, *f.rt) == RD::Reapply);
    CHECK(f.ledger.decide_retry(5, f.digest, true, *f.rt) == RD::Reapply);
    CHECK(f.ledger.decide_retry(5, "", false, *f.rt) == RD::Reapply);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.decide_retry(5, f.digest, false, *f.rt) == RD::Reapply);

    f.ledger.latch_failure();
    CHECK(f.ledger.decide_retry(5, f.digest, false, *f.rt) == RD::Reapply);

    // A sentinel content_id on the OPEN application never matches either, even against
    // itself, and even with an outstanding wedge in it.
    auto w = f.wedge("r1", "/a");
    f.ledger.begin_application(5, "", false, 1);
    f.ledger.add_pending("r1", w);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
    CHECK(f.ledger.decide_retry(5, "", false, *f.rt) == RD::Reapply);

    // An EMPTY application (nothing add_pending()ed) is Reapply even while the runtime
    // itself holds a live outstanding wedge: the ledger only reasons about receipts ITS
    // application accepted, so a wedge it never saw can never turn a decision into Suppress.
    f.ledger.begin_application(7, f.digest, false, 1);
    CHECK(f.rt->receipt_recovery_status(w) == RT::RecoveryStatus::WedgeEligible);
    CHECK(f.ledger.decide_retry(7, f.digest, false, *f.rt) == RD::Reapply);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.decide_retry(7, f.digest, false, *f.rt) == RD::Reapply);

    // And after retire() there is no application at all.
    f.ledger.retire();
    CHECK(f.ledger.decide_retry(7, f.digest, false, *f.rt) == RD::Reapply);
    CHECK(f.ledger.decide_retry(5, "", false, *f.rt) == RD::Reapply);
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): failed_out feeds an async arm "
          "failure back to the caller (UP-3 regression, Gate 8 quality-engineer gap)",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, std::string(64, 'd'), false, 1);
    auto receipt = accept(*rt, "r1");
    ledger.add_pending("r1", receipt);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));

    // TARGET: drain_locked()'s optional out-param must be INCREMENTED (never reset)
    // by exactly the number of receipts THIS call resolved to non-Committed, so
    // GuardianEngine::journal_maintenance_tick() can fold it into the durable
    // fleet-visible arm_failures_ counter (previously only this ledger's own
    // internal resolved_failed and a local log line saw an async-resolved failure).
    std::size_t failed = 0;
    const auto resolved = ledger.drain_locked(*rt, 10, &failed);
    CHECK(resolved == 1);
    CHECK(failed == 1);

    // A second call with nothing left pending must not double-count.
    std::size_t failed_again = 0;
    ledger.drain_locked(*rt, 10, &failed_again);
    CHECK(failed_again == 0);

    // Omitting the out-param entirely (every pre-existing call site) must remain
    // valid and behave exactly as before - the default is nullptr, checked before
    // every increment.
    //
    // Re-arm the backend exactly like r1's half: hang_next_arm was consumed by r1,
    // fail_arm is still set, and the global gate's entered/released flags are still
    // true - without this reset r2's arm fails on the worker straight away, racing
    // accept()'s Accepted expectation (the flake seen on macOS CI), and the
    // wait_entered_hang()/release_hang() pair below passes trivially.
    b->fail_arm.store(false);
    b->reset_hang();
    b->hang_next_arm.store(true);
    yuzu::test::ScopeExit release_guard{[&] { b->release_hang(); }};
    GuardianArmAckLedger ledger2;
    ledger2.begin_application(2, std::string(64, 'e'), false, 1);
    auto receipt2 = accept(*rt, "r2");
    ledger2.add_pending("r2", receipt2);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt2); }, std::chrono::seconds(10)));
    REQUIRE(rt->receipt_status(receipt2) == GuardianSparkRuntime::ReceiptStatus::Failed);
    CHECK(ledger2.drain_locked(*rt, 10) == 1); // no third argument - must not crash
}

TEST_CASE("guardian_push_content_id(): different (spark, assertion) block splits "
          "of the SAME flat field sequence must NOT hash identically",
          "[spark][ack]") {
    // TARGET (cae-1, cpp-expert's hand-constructed collision, independently
    // re-derived by the orchestrator and confirmed with a standalone Python
    // trace before this fix landed): concatenating canonicalize_spec_block()'s
    // own already-field-injective output directly (no length prefix on the
    // BLOCK as a whole) let two rules with different spark/assertion splits of
    // an identical flat field sequence canonicalize - and therefore hash - to
    // the same content_id. Rule X: spark={type:"T", params:{k1:v1,k2:v2}},
    // assertion={type:"A", params:{}}. Rule Y: spark={type:"T",
    // params:{k1:v1}}, assertion={type:"k2", params:{v2:"A"}}. Both produced
    // the flat field sequence [T,k1,v1,k2,v2,A] before the fix.
    gpb::GuaranteedStatePush x;
    x.set_full_sync(false);
    auto* rx = x.add_rules();
    rx->set_rule_id("r1");
    rx->set_enabled(true);
    rx->set_enforcement_mode("enforce");
    rx->set_version(1);
    rx->mutable_spark()->set_type("T");
    rx->mutable_spark()->mutable_params()->insert({"k1", "v1"});
    rx->mutable_spark()->mutable_params()->insert({"k2", "v2"});
    rx->mutable_assertion()->set_type("A");

    gpb::GuaranteedStatePush y;
    y.set_full_sync(false);
    auto* ry = y.add_rules();
    ry->set_rule_id("r1");
    ry->set_enabled(true);
    ry->set_enforcement_mode("enforce");
    ry->set_version(1);
    ry->mutable_spark()->set_type("T");
    ry->mutable_spark()->mutable_params()->insert({"k1", "v1"});
    ry->mutable_assertion()->set_type("k2");
    ry->mutable_assertion()->mutable_params()->insert({"v2", "A"});

    CHECK(guardian_push_content_id(x) != guardian_push_content_id(y));
}

// ---------------------------------------------------------------------------
// rung 9c PR-3: GuardianArmAckLedger::arm_stats() - the re-statable snapshot
// GuardianEngine::arm_stats() forwards (behind its own prefer_spark_ dormancy
// gate, tested at the GuardianEngine level in test_guardian_engine.cpp - this
// file tests the LEDGER's own contract only, which has no notion of
// prefer_spark_ and must not gain one).
// ---------------------------------------------------------------------------

TEST_CASE("GuardianArmAckLedger::arm_stats(): no current application returns "
          "nullopt - governance fix, adversarial review CODEX-1/K1: the settled "
          "KICKOFF-v2 interface is std::optional, absent on no-application, not a "
          "present {0, 0}",
          "[spark][ack][arm_stats]") {
    GuardianArmAckLedger ledger;
    CHECK_FALSE(ledger.arm_stats().has_value());
}

TEST_CASE("GuardianArmAckLedger::arm_stats(): a live empty application reads a "
          "PRESENT {0, 0} - the common case, not the same as no application at all",
          "[spark][ack][arm_stats]") {
    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 0);
    const auto s = ledger.arm_stats();
    REQUIRE(s.has_value());
    CHECK(s->pending == 0);
    CHECK(s->failed == 0);
}

TEST_CASE("GuardianArmAckLedger::arm_stats(): an accepted receipt increases pending; "
          "a Committed drain reduces it back to 0",
          "[spark][ack][arm_stats]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    b->hang_next_arm.store(true);
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 1);
    ledger.add_pending("r1", receipt);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 1);
        CHECK(s->failed == 0);
    }

    b->release_hang(); // resolves Committed (fail_arm was never set)
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
    ledger.drain_locked(*rt, 10);

    const auto s = ledger.arm_stats();
    REQUIRE(s.has_value());
    CHECK(s->pending == 0);
    CHECK(s->failed == 0);
}

TEST_CASE("GuardianArmAckLedger::arm_stats(): a Failed drain increases failed; "
          "RED-FIRST - replacing the application via begin_application() (the "
          "same path decide_retry()'s Reapply takes on an ordinary retry) "
          "brings a PRESENT failed back to 0",
          "[spark][ack][arm_stats]") {
    // This proves the production snapshot CAN decrease via APPLICATION
    // REPLACEMENT - the mechanism already live today through decide_retry()'s
    // Reapply-on-resolved_failed>0 path (see decide_retry()'s own test above).
    // It does NOT prove same-application late-success recovery (a still-
    // pending receipt flipping from Failed to Committed without a new
    // application) - that is rung 9c PR-5's job, not built here. See
    // GuardianArmStats::failed's own doc comment (guardian_arm_heartbeat.hpp)
    // for why "monotonic until PR-5" is the wrong way to describe this field.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    b->hang_next_arm.store(true);
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Failed);

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 1);
    ledger.add_pending("r1", receipt);
    ledger.drain_locked(*rt, 10);

    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0);
        CHECK(s->failed == 1); // present, nonzero - not absent
    }

    // A fresh application replaces the failed one - exactly what happens on the
    // NEXT push for a generation decide_retry() sent to Reapply because
    // resolved_failed > 0 (see the "identical (generation, content, full_sync) is
    // Suppress" test above, which pins that Reapply trigger).
    ledger.begin_application(2, "content-2", false, 0);
    const auto s = ledger.arm_stats();
    REQUIRE(s.has_value()); // PRESENT zero, not merely "no longer 1", and not absent
    CHECK(s->pending == 0);
    CHECK(s->failed == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// rung 9c PR-5c (#4221): the ReceiptStatus enum split - Expired became
// CongestionExpired (timed out merely queued) / Wedged (timed out while
// dispatching/dispatched). Both new variants fold into drain_locked()'s
// resolved_failed exactly like the pre-split Expired did - this PR adds
// classification only (the K-bound acknowledgement policy 5e once added was deleted
// by #5459 option D: a counted wedge now holds the generation).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("GuardianArmAckLedger::drain_locked(): a Wedged receipt (timed out while "
          "dispatching) resolves as an ordinary failure, exactly once",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    b->hang_next_arm.store(true);
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 1);
    ledger.add_pending("r1", receipt);

    std::size_t failed_out = 0;
    const std::size_t drained = ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out);
    const auto statuses = ledger.resolved_statuses_for_test();
    CHECK(std::find(statuses.begin(), statuses.end(),
                    GuardianSparkRuntime::ReceiptStatus::Wedged) != statuses.end());
    CHECK(drained == 1);
    CHECK(failed_out == 1);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0);
        CHECK(s->failed == 1);
    }
    CHECK_FALSE(ledger.can_advance());

    // Already resolved and erased from pending - a second drain on the same
    // application finds nothing left to resolve, never double-counts this claim.
    std::size_t failed_out2 = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out2) == 0);
    CHECK(failed_out2 == 0);
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): concern 2 (rung 9c PR-5d) - a Wedged "
          "receipt's arm-failed contribution clears once the runtime ADOPTS its late "
          "success, without touching the cumulative fleet-visible failed_out counter",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); } // idempotent - the explicit release below still fires
    } cleanup{b.get()};

    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // #5459: a real SHA-256-shaped content_id (decide_retry() never trusts a sentinel).
    const std::string digest(64, 'a');
    GuardianArmAckLedger ledger;
    ledger.begin_application(1, digest, false, 1);
    ledger.add_pending("r1", receipt);

    // First drain: resolves Wedged as an ordinary failure, exactly like the sibling
    // test above - AND retains the receipt in failed_receipts (concern 2's own new
    // bookkeeping), since Wedged is the one status a later runtime adoption can
    // retroactively recover.
    std::size_t failed_out = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out) == 1);
    CHECK(failed_out == 1);
    CHECK(ledger.failed_receipt_count_for_test() == 1);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
    }
    CHECK_FALSE(ledger.can_advance());

    // #5459 (option D): the generation is HELD, not acknowledged, while the wedge is
    // outstanding - and every identical server re-push in that window is Suppressed
    // (no teardown, no re-arm), never an acknowledgement. This is what keeps the server's
    // re-push alive until the late result lands.
    for (int i = 0; i < 3; ++i) {
        CHECK(ledger.decide_retry(1, digest, false, *rt) == GuardianArmAckLedger::RetryDecision::Suppress);
        CHECK_FALSE(ledger.can_advance());
    }
    CHECK(ledger.failed_receipt_count_for_test() == 1);

    // Nobody withdrew "r1" - releasing the parked backend call now delivers a late
    // success the runtime ADOPTS (rung 9c PR-5d concern 1), not disarms.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged); // sticky

    // Second drain: the recovery scan notices the adoption via
    // receipt_recovery_status() and clears this rule's own resolved_failed
    // contribution - failed_out (the
    // cumulative fleet-visible counter) does NOT move, since this is a recovery,
    // not a new failure.
    std::size_t failed_out2 = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out2) == 0); // nothing NEW resolved
    CHECK(failed_out2 == 0);
    CHECK(ledger.failed_receipt_count_for_test() == 0);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0);
    }
    CHECK(ledger.can_advance()); // recovered - nothing left blocking this application
    // ... and with nothing outstanding any more an identical retry is a Reapply again, which
    // is also what lets a failed generation-persist be retried.
    CHECK(ledger.decide_retry(1, digest, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): concern 2 - a Wedged receipt that is "
          "later WITHDRAWN (never adopted) never recovers via receipt_recovered(), and "
          "resolved_failed never clears, but the entry leaves the outstanding-wedge set "
          "(rung 9c PR-5e, #4221) since it is no longer still-claimed, and the next "
          "identical retry is a Reapply (#5459)",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); } // idempotent - the explicit release below still fires
    } cleanup{b.get()};

    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    const std::string digest(64, 'a');
    GuardianArmAckLedger ledger;
    ledger.begin_application(1, digest, false, 1);
    ledger.add_pending("r1", receipt);
    std::size_t failed_out = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out) == 1);
    CHECK(ledger.failed_receipt_count_for_test() == 1);
    CHECK(ledger.decide_retry(1, digest, false, *rt) == GuardianArmAckLedger::RetryDecision::Suppress);

    // The operator withdraws "r1" while it is still wedged.
    rt->detach_rule("r1");

    // Late success for a no-longer-desired rule -> disarmed, not adopted. This
    // file's own minimal FakeBackend does not count disarms (its disarm() is a
    // plain no-op override) - the claim actually leaving the runtime's own queue
    // is the observable signal here.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until(
        [&] { return rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0; },
        std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);

    // #5459: BEFORE any further drain the entry is still in failed_receipts, but the live
    // re-read finds its claim popped - an identical retry is a Reapply, never a Suppress
    // on the stale map.
    CHECK(ledger.decide_retry(1, digest, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);

    std::size_t failed_out2 = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out2) == 0);
    CHECK(failed_out2 == 0);
    // Never recovered: receipt_recovered() requires rules_ to carry this exact
    // (rule_id, generation), which withdrawal never installs - resolved_failed stays
    // exactly as it was, still 1 (checked via arm_stats() below).
    //
    // The entry itself DOES leave failed_receipts, via the "still-claimed" (FIFO-front)
    // check, not receipt_recovered()'s adoption check - the claim was popped from its
    // key's FIFO the instant the late, disarmed success was published
    // (claim_queue_depth_for_test() == 0 above), so it is no longer an outstanding wedge.
    // resolved_failed itself never moves, so `resolved_failed != failed_receipts.size()`
    // holds permanently for this application: decide_retry() answers Reapply and
    // can_advance() stays false - see below.
    CHECK(ledger.failed_receipt_count_for_test() == 0);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1); // resolved_failed itself is untouched by the pruning
    }
    CHECK_FALSE(ledger.can_advance());
    CHECK(ledger.decide_retry(1, digest, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
}

TEST_CASE("receipt_status_name(): every ReceiptStatus renders a distinct, correct "
          "name - the mapping drain_locked()'s async-failure warn line depends on",
          "[spark][ack]") {
    // Governance follow-up (Gate 4, happy-path + unhappy-path, 2026-09-16): the
    // LogCapture-based assertions removed from the two tests below (cross-image
    // hazard) incidentally covered this mapping too - direct, LogCapture-free
    // coverage restored here instead, now that receipt_status_name() is exported
    // for exactly this purpose (see its own declaration comment).
    using S = GuardianSparkRuntime::ReceiptStatus;
    CHECK(std::string_view(receipt_status_name(S::Pending)) == "Pending");
    CHECK(std::string_view(receipt_status_name(S::Committed)) == "Committed");
    CHECK(std::string_view(receipt_status_name(S::Failed)) == "Failed");
    CHECK(std::string_view(receipt_status_name(S::CongestionExpired)) == "CongestionExpired");
    CHECK(std::string_view(receipt_status_name(S::Wedged)) == "Wedged");
    CHECK(std::string_view(receipt_status_name(S::Withdrawn)) == "Withdrawn");
    CHECK(std::string_view(receipt_status_name(S::Stopped)) == "Stopped");
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): a CongestionExpired receipt (timed "
          "out merely queued, never reached dispatch) resolves as an ordinary "
          "failure too",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_every_arm.store(true); // r1 (the head) parks; r2 queues behind it
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    // Same key: r1 occupies the head (Dispatching, parked); r2 queues behind it
    // and never reaches dispatch at all before its own deadline elapses.
    auto r1_receipt = accept(*rt, "r1", "/a");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    auto r2_receipt = accept(*rt, "r2", "/a");
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    // Both r1 (Dispatching) and r2 (Queued) are overdue by now.
    REQUIRE(rt->expire_overdue_claims() == 2);
    REQUIRE(rt->receipt_status(r1_receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    REQUIRE(rt->receipt_status(r2_receipt) == GuardianSparkRuntime::ReceiptStatus::CongestionExpired);

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 2);
    ledger.add_pending("r1", r1_receipt);
    ledger.add_pending("r2", r2_receipt);

    std::size_t failed_out = 0;
    const std::size_t drained = ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out);
    const auto statuses = ledger.resolved_statuses_for_test();
    CHECK(std::find(statuses.begin(), statuses.end(),
                    GuardianSparkRuntime::ReceiptStatus::Wedged) != statuses.end());
    CHECK(std::find(statuses.begin(), statuses.end(),
                    GuardianSparkRuntime::ReceiptStatus::CongestionExpired) != statuses.end());
    CHECK(drained == 2);
    CHECK(failed_out == 2);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0);
        CHECK(s->failed == 2);
    }
    CHECK_FALSE(ledger.can_advance());

    // Adversarial-review finding (2026-09-15): the Wedged test above already covers
    // this half (":660-664") - CongestionExpired needs the identical proof. Both
    // receipts are already resolved and erased from pending; a second drain finds
    // nothing left for either and must not double-count.
    std::size_t failed_out2 = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out2) == 0);
    CHECK(failed_out2 == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// #5459 (option D): the rung 9c PR-5e K-bound waiver is DELETED. can_advance()
// never acknowledges an outstanding wedge (however many identical re-applies it
// has survived); the waiver's predicate moved to decide_retry(), which Suppresses
// an identical retry whose only unresolved items are live outstanding wedges
// (hung, or with a compensating teardown outstanding) so a held generation does
// not cost a full teardown + re-arm per server re-push. The tests below pin both
// halves: no acknowledgement, and exactly-when-suppress.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("GuardianArmAckLedger::can_advance(): never acknowledges an outstanding wedge, "
          "including beyond the old K-bound (#5459 option D)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");

    f.open_app();
    f.ledger.add_pending("r1", w);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
    CHECK(f.ledger.failed_receipt_count_for_test() == 1);
    CHECK_FALSE(f.ledger.can_advance());

    // The old waiver acknowledged after 3 identical re-applies. There is none now: six
    // identical re-applications, each re-observing the same retained claim, never
    // acknowledge. (Each begin_application() replaces the application wholesale, so each
    // starts with fresh accounting and a fresh suppression budget.)
    for (int i = 1; i <= 6; ++i) {
        f.open_app();
        f.ledger.add_pending("r1", accept(*f.rt, "r1", "/a")); // Reobserved: same underlying claim
        CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
        CHECK(f.ledger.failed_receipt_count_for_test() == 1);
        CHECK_FALSE(f.ledger.can_advance());
        CHECK(f.retry() == RD::Suppress); // held, not acknowledged, and not re-armed
    }
    {
        const auto s = f.ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1); // the failure stays visible: suppression never erases evidence
        CHECK(s->pending == 0);
    }

    // A DISTINCT push (different content) is a fresh application with clean accounting.
    f.ledger.begin_application(1, std::string(64, 'b'), false, 1);
    CHECK(f.ledger.failed_receipt_count_for_test() == 0); // no leak
    CHECK(f.ledger.can_advance()); // trivially true - nothing pending or failed YET
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): an outstanding wedge in a pending-EMPTY "
          "application is Suppressed, and the generation stays held (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app(3);
    f.ledger.add_pending("r1", w);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
    REQUIRE(f.ledger.pending_count_for_test() == 0);
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);

    for (int i = 0; i < 5; ++i)
        CHECK(f.retry() == RD::Suppress);
    CHECK(f.ledger.applied_count() == 3); // the stashed count handed back by a Suppress
    CHECK_FALSE(f.ledger.can_advance());
    CHECK(f.ledger.failed_receipt_count_for_test() == 1);
    {
        const auto s = f.ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
        CHECK(s->pending == 0);
    }
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): a live-eligible Wedged receipt the bounded "
          "drain has NOT reached yet (still in `pending`) is Suppressed, not a spurious "
          "Reapply (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w); // deliberately NOT drained
    REQUIRE(f.ledger.pending_count_for_test() == 1);
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 0);
    CHECK(f.retry() == RD::Suppress);
    CHECK_FALSE(f.ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): wedges alongside Pending and Committed "
          "siblings, and several wedges at once, are Suppressed; the first wedge to pop "
          "makes the next retry a Reapply even while the others stay wedged (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w1 = f.wedge("r1", "/a");
    auto w2 = f.wedge("r2", "/b");
    auto pend = f.pending_sibling("r3", "/c"); // created after the last age_out(): stays Pending
    auto done = f.committed_sibling("r4", "/d");

    f.open_app(4);
    f.ledger.add_pending("r1", w1);
    f.ledger.add_pending("r2", w2);
    f.ledger.add_pending("r3", pend);
    f.ledger.add_pending("r4", done);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 3); // r1, r2 wedged + r4 committed; r3 still Pending
    CHECK(f.ledger.pending_count_for_test() == 1);
    CHECK(f.ledger.failed_receipt_count_for_test() == 2);
    CHECK(f.retry() == RD::Suppress);
    CHECK(f.retry() == RD::Suppress);
    CHECK_FALSE(f.ledger.can_advance());

    // r2's hung arm finally refuses - its claim pops. r1 is still wedged and r3 still
    // Pending, but one counted failure is no longer an outstanding wedge: a real re-arm is
    // owed, even BEFORE the next drain has pruned the entry.
    f.late_failure("/b");
    CHECK(f.retry() == RD::Reapply);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.failed_receipt_count_for_test() == 1); // r1 only
    CHECK(f.retry() == RD::Reapply);                       // resolved_failed(2) != size(1)
    CHECK_FALSE(f.ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): an outstanding wedge never overrides an "
          "identity change or a latched failure (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);

    // Many identity mismatches never consume the suppression budget (only the wedge
    // Suppress branch counts), so the matching retry afterwards is still a Suppress.
    for (int i = 0; i < 3 * static_cast<int>(kWedgeSuppressMaxDecisions); ++i) {
        CHECK(f.ledger.decide_retry(2, f.digest, false, *f.rt) == RD::Reapply);
        CHECK(f.ledger.decide_retry(1, std::string(64, 'b'), false, *f.rt) == RD::Reapply);
        CHECK(f.ledger.decide_retry(1, f.digest, true, *f.rt) == RD::Reapply);
        CHECK(f.ledger.decide_retry(1, "", false, *f.rt) == RD::Reapply);
    }
    CHECK(f.retry() == RD::Suppress);

    // A latched apply_rules() generation-hold failure forces a real re-apply.
    f.ledger.latch_failure();
    CHECK(f.retry() == RD::Reapply);
    CHECK_FALSE(f.ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::can_advance(): a wedge plus an ORDINARY failure in the same "
          "application forces Reapply and never acknowledges, however many re-applies "
          "(#5459; was the K-waiver non-Wedged-blocks case)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    auto bad = f.failed_sibling("r2", "/b");

    f.open_app(2);
    f.ledger.add_pending("r1", w);
    f.ledger.add_pending("r2", bad);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 2);
    CHECK(f.ledger.failed_receipt_count_for_test() == 1); // only r1 - r2 was never Wedged at all
    CHECK_FALSE(f.ledger.can_advance()); // resolved_failed(2) != failed_receipts.size()(1)
    CHECK(f.retry() == RD::Reapply);     // mixed set: the ordinary failure needs a real re-arm

    // Beyond the old K: r1 is re-observed each time (same retained head); r2 gets a brand
    // new claim that refuses again - "the same rule keeps failing every push".
    for (int i = 0; i < 4; ++i) {
        f.open_app(2);
        f.ledger.add_pending("r1", accept(*f.rt, "r1", "/a")); // Reobserved
        f.ledger.add_pending("r2", f.failed_sibling("r2", "/b"));
        CHECK(f.ledger.drain_locked(*f.rt, 10) == 2);
        CHECK(f.ledger.failed_receipt_count_for_test() == 1);
        CHECK_FALSE(f.ledger.can_advance());
        CHECK(f.retry() == RD::Reapply);
    }
    {
        const auto s = f.ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 2);
    }
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): a wedge plus an UNDRAINED ordinary failure "
          "(past the bounded drain's cap) is Reapply, read live from the runtime (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    auto bad = f.failed_sibling("r2", "/b");

    f.open_app(2);
    f.ledger.add_pending("r1", w);
    f.ledger.add_pending("r2", bad);
    // max_per_tick = 1 resolves r1 (map order) and leaves r2 - already Failed in the runtime -
    // sitting un-drained in `pending`, uncounted in resolved_failed.
    CHECK(f.ledger.drain_locked(*f.rt, 1) == 1);
    REQUIRE(f.ledger.pending_count_for_test() == 1);
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);
    CHECK(f.retry() == RD::Reapply);
    CHECK_FALSE(f.ledger.can_advance());

    // Fully drained: still Reapply (the counted failure has no retained wedge candidate).
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
    CHECK(f.retry() == RD::Reapply);
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): safety valve - kWedgeSuppressMaxDecisions "
          "wedge Suppresses, then Reapply; Pending-only suppression never spends the "
          "budget; only begin_application()/retire() reset it (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");

    // The budget is exhausted and then stays exhausted - a drain, an identity mismatch, or
    // a further call never replenishes it.
    auto exhaust = [&] {
        for (std::size_t i = 0; i < kWedgeSuppressMaxDecisions; ++i) {
            REQUIRE(f.retry() == RD::Suppress);
            if (i % 3 == 0)
                f.ledger.drain_locked(*f.rt, 10); // heartbeat drains must not reset the count
        }
        for (int i = 0; i < 3; ++i) {
            CHECK(f.retry() == RD::Reapply);
            CHECK(f.ledger.decide_retry(2, f.digest, false, *f.rt) == RD::Reapply);
            f.ledger.drain_locked(*f.rt, 10);
        }
        CHECK_FALSE(f.ledger.can_advance()); // the valve forces a re-apply, never an ack
    };

    f.open_app();
    f.ledger.add_pending("r1", w);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
    exhaust();

    // A new application (what the forced Reapply produces) starts a fresh budget. The same
    // wedge is re-observed: forcing a Reapply never unsticks the claim itself.
    f.open_app();
    f.ledger.add_pending("r1", accept(*f.rt, "r1", "/a"));
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
    exhaust();

    // Pending-only suppression is the pre-existing behaviour and is NOT valve-bounded.
    Rig5459 g;
    auto p = g.pending_sibling("r1", "/a");
    g.open_app();
    g.ledger.add_pending("r1", p);
    for (std::size_t i = 0; i < 3 * kWedgeSuppressMaxDecisions; ++i)
        CHECK(g.retry() == RD::Suppress);
}

// ---------------------------------------------------------------------------
// #5459 (option D), compensation-aware suppression: #4472 made a wedge whose late
// result has RETURNED, with a compensating teardown outstanding, not K-eligible. The
// ledger must still hold a handle on it (BOTH drain loops retain it) so held pushes
// during the compensation do not pay a full teardown - while NEVER acknowledging it.
// ---------------------------------------------------------------------------

TEST_CASE("GuardianSparkRuntime: a wedge whose compensating teardown is outstanding reports "
          "compensation_pending / CompensationPending, never wedge_eligible (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    CHECK(f.rt->receipt_recovery_status(w) == RT::RecoveryStatus::WedgeEligible);
    {
        const auto wa = f.rt->receipt_status_wedge_aware(w);
        CHECK(wa.status == RT::ReceiptStatus::Wedged);
        CHECK(wa.wedge_eligible);
        CHECK_FALSE(wa.compensation_pending);
    }

    f.start_compensation("/a");
    CHECK(f.rt->receipt_status(w) == RT::ReceiptStatus::Wedged); // sticky
    CHECK_FALSE(f.rt->receipt_wedge_k_eligible(w)); // the accessor keeps its narrow meaning
    CHECK(f.rt->receipt_recovery_status(w) == RT::RecoveryStatus::CompensationPending);
    {
        const auto wa = f.rt->receipt_status_wedge_aware(w);
        CHECK(wa.status == RT::ReceiptStatus::Wedged);
        CHECK_FALSE(wa.wedge_eligible);
        CHECK(wa.compensation_pending);
    }

    f.finish_compensation("/a"); // the teardown pops the claim
    CHECK(f.rt->receipt_recovery_status(w) == RT::RecoveryStatus::Blocking);
    {
        const auto wa = f.rt->receipt_status_wedge_aware(w);
        CHECK(wa.status == RT::ReceiptStatus::Wedged); // still sticky
        CHECK_FALSE(wa.wedge_eligible);
        CHECK_FALSE(wa.compensation_pending);
    }
}

TEST_CASE("GuardianSparkRuntime: Recovered keeps first priority - an adopted wedge reports "
          "Recovered, with neither wedge flag set (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);

    f.b->release_path("/a"); // nobody withdrew r1: the late success is ADOPTED
    REQUIRE(yuzu::test::spin_until([&] { return f.rt->rule_count() == 1; }, std::chrono::seconds(10)));
    CHECK(f.rt->receipt_recovery_status(w) == RT::RecoveryStatus::Recovered);
    const auto wa = f.rt->receipt_status_wedge_aware(w);
    CHECK(wa.status == RT::ReceiptStatus::Wedged);
    CHECK_FALSE(wa.wedge_eligible);
    CHECK_FALSE(wa.compensation_pending);

    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0); // the recovery scan records the recovery
    CHECK(f.ledger.failed_receipt_count_for_test() == 0);
    CHECK(f.ledger.can_advance()); // the ONLY way a wedge's generation is ever acknowledged
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): a compensating wedge is retained in "
          "failed_receipts by the PRIMARY drain loop, suppressed until the teardown pops it, "
          "then Reapply BEFORE the next drain (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.start_compensation("/a"); // compensation is already outstanding at the FIRST drain

    f.open_app();
    f.ledger.add_pending("r1", w);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
    CHECK(f.ledger.failed_receipt_count_for_test() == 1); // retained, though not wedge_eligible
    CHECK(f.retry() == RD::Suppress);
    CHECK(f.retry() == RD::Suppress);
    CHECK_FALSE(f.ledger.can_advance()); // suppression only - never an acknowledgement

    // A second drain (the recovery loop) keeps it too.
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.failed_receipt_count_for_test() == 1);
    CHECK(f.retry() == RD::Suppress);

    f.finish_compensation("/a");
    // The claim popped with no replacement arm: the rule is unarmed and needs the server's
    // re-push to be a REAL re-apply - before any drain has pruned the stale entry.
    CHECK(f.retry() == RD::Reapply);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.failed_receipt_count_for_test() == 0);
    CHECK(f.retry() == RD::Reapply);
    CHECK_FALSE(f.ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): a wedge retained while hung and compensating "
          "LATER is kept by the RECOVERY drain loop, suppressed until the pop (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);
    CHECK(f.retry() == RD::Suppress);

    f.start_compensation("/a"); // WITHOUT a new application, after the receipt was retained
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.failed_receipt_count_for_test() == 1); // was erased as Blocking before #5459
    CHECK(f.retry() == RD::Suppress);
    CHECK_FALSE(f.ledger.can_advance());

    f.finish_compensation("/a");
    CHECK(f.retry() == RD::Reapply);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.failed_receipt_count_for_test() == 0);
    CHECK(f.retry() == RD::Reapply);
    CHECK_FALSE(f.ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): identity is checked BEFORE any wedge "
          "reasoning - with an outstanding eligible wedge in either bookkeeping shape, any "
          "identity mismatch or sentinel is Reapply and only the exact identity Suppresses "
          "(#5459)",
          "[spark][ack][5459]") {
    const std::string other(64, 'b');
    const std::string not_hex(64, 'g'); // 64 chars, but not a SHA-256 digest
    const std::string short_hex(63, 'a');

    auto check_identity = [&](Rig5459& f) {
        // A decision for a DIFFERENT push is never a retry of this one, wedge or not.
        CHECK(f.ledger.decide_retry(2, f.digest, false, *f.rt) == RD::Reapply);  // generation
        CHECK(f.ledger.decide_retry(1, other, false, *f.rt) == RD::Reapply);     // content_id
        CHECK(f.ledger.decide_retry(1, f.digest, true, *f.rt) == RD::Reapply);   // full_sync
        CHECK(f.ledger.decide_retry(1, "", false, *f.rt) == RD::Reapply);        // sentinel
        CHECK(f.ledger.decide_retry(1, not_hex, false, *f.rt) == RD::Reapply);   // sentinel
        CHECK(f.ledger.decide_retry(1, short_hex, false, *f.rt) == RD::Reapply); // sentinel
        // None of those spent the suppression budget: the whole budget is still there.
        for (std::size_t i = 0; i < kWedgeSuppressMaxDecisions; ++i)
            CHECK(f.retry() == RD::Suppress);
        CHECK(f.retry() == RD::Reapply);
    };

    SECTION("wedge retained by a drain (pending empty)") {
        Rig5459 f;
        auto w = f.wedge("r1", "/a");
        f.open_app();
        f.ledger.add_pending("r1", w);
        REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
        REQUIRE(f.ledger.pending_count_for_test() == 0);
        REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);
        check_identity(f);
    }
    SECTION("wedge still undrained in `pending`") {
        Rig5459 f;
        auto w = f.wedge("r1", "/a");
        f.open_app();
        f.ledger.add_pending("r1", w);
        REQUIRE(f.ledger.pending_count_for_test() == 1);
        check_identity(f);
    }
    SECTION("a sentinel on the OPEN application never matches, even a sentinel") {
        Rig5459 f;
        auto w = f.wedge("r1", "/a");
        f.ledger.begin_application(1, not_hex, false, 1);
        f.ledger.add_pending("r1", w);
        REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
        CHECK(f.ledger.decide_retry(1, not_hex, false, *f.rt) == RD::Reapply);
        CHECK(f.ledger.decide_retry(1, f.digest, false, *f.rt) == RD::Reapply);
    }
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): a compensating wedge still in `pending` "
          "(compensation started before the FIRST drain) is Suppressed, never Reapply; "
          "once the teardown pops it the next push is Reapply even before a drain (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.start_compensation("/a"); // outstanding BEFORE the ledger has ever drained the receipt

    f.open_app();
    f.ledger.add_pending("r1", w); // deliberately NOT drained: only the PENDING loop sees it
    REQUIRE(f.ledger.pending_count_for_test() == 1);
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 0);
    CHECK(f.retry() == RD::Suppress);
    CHECK(f.retry() == RD::Suppress);
    CHECK_FALSE(f.ledger.can_advance());

    f.finish_compensation("/a"); // popped, nothing adopted it
    CHECK(f.retry() == RD::Reapply); // before any drain
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
    CHECK(f.ledger.failed_receipt_count_for_test() == 0); // a popped claim is Blocking: not retained
    CHECK(f.retry() == RD::Reapply);
    CHECK_FALSE(f.ledger.can_advance());
}

// Recovered > CompensationPending (the priority receipt_recovery_status() states) is NOT
// constructible against the real runtime: Recovered is keyed on the claim's own
// (rule_id, generation), adoption pops the claim in the SAME registry_mu_ critical
// section, and a re-attach of the same rule onto a compensating head returns Reobserved
// (the same claim), never a newer queued incarnation (AC-5). So a claim that is still the
// Dispatched FIFO front can never also be adopted. The priority is therefore pinned only
// where it is observable, by the "Recovered keeps first priority" test above (adoption
// reads Recovered with both wedge flags false) and the CompensationPending test above.

TEST_CASE("GuardianArmAckLedger::decide_retry(): a retained wedge whose late success was "
          "ADOPTED since the last drain is Suppressed (the rule just armed - no teardown), "
          "then the next drain clears it and the generation acknowledges (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1); // retained: still hung
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);
    CHECK(f.retry() == RD::Suppress);

    // The hung arm finally succeeds and nobody withdrew the rule: the late success is
    // ADOPTED. NO tick (drain) runs between the adoption and the next push.
    f.b->release_path("/a");
    REQUIRE(yuzu::test::spin_until([&] { return f.rt->rule_count() == 1; }, std::chrono::seconds(10)));
    REQUIRE(f.rt->receipt_recovery_status(w) == RT::RecoveryStatus::Recovered);
    // Sticky Wedged but no longer the FIFO front: exactly what the old eligible-only live
    // check misread as a settled failure.
    REQUIRE(f.rt->receipt_status(w) == RT::ReceiptStatus::Wedged);
    REQUIRE_FALSE(f.rt->receipt_wedge_k_eligible(w));

    CHECK(f.retry() == RD::Suppress); // NOT Reapply: tearing down would undo the recovery
    CHECK(f.rt->rule_count() == 1);   // the rule keeps the subscription it just armed
    CHECK(f.rt->rule_active_for_test("r1") == std::optional<bool>{true});
    CHECK_FALSE(f.ledger.can_advance()); // suppression never acknowledges
    CHECK(f.retry() == RD::Suppress);

    // The next tick's recovery scan records the recovery; only now does the generation ack.
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0);
    CHECK(f.ledger.failed_receipt_count_for_test() == 0);
    CHECK(f.ledger.can_advance());
    {
        const auto s = f.ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0);
        CHECK(s->pending == 0);
    }
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): a Recovered entry spends the safety-valve "
          "budget like any other Suppress (#5459)",
          "[spark][ack][5459]") {
    // Deliberate: the Recovered window is one heartbeat tick long so the valve is never the
    // binding bound for it in production, but an uncounted Suppress would be a second
    // unbounded suppression path. Pinned so a change is a decision, not an accident.
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
    f.b->release_path("/a");
    REQUIRE(yuzu::test::spin_until([&] { return f.rt->rule_count() == 1; }, std::chrono::seconds(10)));
    REQUIRE(f.rt->receipt_recovery_status(w) == RT::RecoveryStatus::Recovered);

    for (std::size_t i = 0; i < kWedgeSuppressMaxDecisions; ++i)
        CHECK(f.retry() == RD::Suppress);
    CHECK(f.retry() == RD::Reapply);
    CHECK_FALSE(f.ledger.can_advance()); // still held until a drain records the recovery
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): a Blocking failed_receipts entry is Reapply "
          "even when a sibling entry is Recovered (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w1 = f.wedge("r1", "/a");
    auto w2 = f.wedge("r2", "/b");
    f.open_app(2);
    f.ledger.add_pending("r1", w1);
    f.ledger.add_pending("r2", w2);
    REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 2);
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 2);
    CHECK(f.retry() == RD::Suppress);

    f.b->release_path("/a"); // r1: late success adopted
    REQUIRE(yuzu::test::spin_until([&] { return f.rt->rule_count() == 1; }, std::chrono::seconds(10)));
    CHECK(f.retry() == RD::Suppress); // Recovered + still-hung wedge

    f.late_failure("/b"); // r2: late failure, popped without adoption
    CHECK(f.retry() == RD::Reapply);
}

TEST_CASE("GuardianArmAckLedger::begin_application(): a fresh application starts with clean "
          "failure accounting and a fresh suppression budget; retire() likewise (#5459)",
          "[spark][ack][5459]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");

    auto establish = [&](bool reobserve) {
        f.open_app();
        f.ledger.add_pending("r1", reobserve ? accept(*f.rt, "r1", "/a") : w);
        REQUIRE(f.ledger.drain_locked(*f.rt, 10) == 1);
        REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);
    };
    auto exhaust_budget = [&] {
        for (std::size_t i = 0; i < kWedgeSuppressMaxDecisions; ++i)
            REQUIRE(f.retry() == RD::Suppress);
        REQUIRE(f.retry() == RD::Reapply);
    };

    establish(false);
    exhaust_budget();

    // An identical begin_application() (what the forced Reapply does): no stale failure
    // state leaks, and an application with nothing outstanding is a Reapply.
    f.open_app();
    CHECK(f.ledger.failed_receipt_count_for_test() == 0);
    {
        const auto s = f.ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0);
        CHECK(s->pending == 0);
    }
    CHECK(f.ledger.can_advance()); // vacuously true - a fresh, empty application
    CHECK(f.retry() == RD::Reapply);

    // The budget came back with it.
    establish(true);
    exhaust_budget();

    // retire() drops the application: nothing to suppress against, and the next one starts fresh.
    f.ledger.retire();
    CHECK_FALSE(f.ledger.can_advance());
    CHECK(f.retry() == RD::Reapply);
    establish(true);
    exhaust_budget();
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): a genuinely dispatched claim that "
          "later resolves to a real backend refusal leaves the outstanding-wedge set - the "
          "\"still-claimed\" requirement (rung 9c PR-5e, #4221) - and the next retry is a "
          "Reapply even BEFORE the next drain (#5459)",
          "[spark][ack]") {
    // Scope note (PR #4529 review finding): this test drives the refusal to
    // completion, THEN reads - a settled-ordering check, not a concurrent one.
    // It proves the eligibility transition happens correctly once observed, but
    // a `drain_locked()` call issued WHILE the transition is still in flight is
    // never raced here. See the genuinely concurrent test below
    // ("receipt_status_wedge_aware(): a real concurrent poller...") for that
    // property - a real background reader racing the actual production
    // completion path, not this test's own sequential ordering.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    // The backend call is genuinely running (dispatch reached Dispatched well before
    // the deadline - hang_next_arm blocks INSIDE arm(), which only runs after
    // io_executor_.submit() already succeeded) - this is the SETTLED case, not the
    // Dispatching-window race.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    REQUIRE(rt->receipt_wedge_k_eligible(receipt)); // genuinely outstanding right now

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, std::string(64, '2'), false, 1);
    ledger.add_pending("r1", receipt);
    CHECK(ledger.drain_locked(*rt, 10) == 1);
    CHECK(ledger.failed_receipt_count_for_test() == 1); // retained - genuinely eligible right now

    // The backend call NOW resolves for real, as a genuine refusal (not a success,
    // not a hang) - on_arm_complete()'s !armed_live branch stages BackendRefused,
    // but publish_arm_verdicts_locked() skips overwriting an already-resolved
    // claim's outcome/end (the sticky-Wedged contract) - `end` stays
    // WaiterTimedOutDispatched forever, but the claim is POPPED from its key's FIFO.
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until(
        [&] { return rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0; },
        std::chrono::seconds(10)));
    CHECK(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged); // still sticky
    CHECK_FALSE(rt->receipt_wedge_k_eligible(receipt)); // no longer still-claimed

    // #5459: the ledger still holds the entry (no drain has run since the pop), but
    // decide_retry() re-reads the runtime LIVE - the exact-FIFO-front check fails for the
    // popped claim, so the retry is a Reapply (the rule must be re-armed) rather than a
    // Suppress on the stale map. No drain has run in between.
    REQUIRE(ledger.failed_receipt_count_for_test() == 1);
    CHECK(ledger.decide_retry(1, std::string(64, '2'), false, *rt) ==
          GuardianArmAckLedger::RetryDecision::Reapply);

    std::size_t failed_out2 = 0;
    CHECK(ledger.drain_locked(*rt, 10, &failed_out2) == 0); // nothing new in `pending`
    CHECK(failed_out2 == 0);
    // Pruned from the outstanding-wedge set, but resolved_failed itself is untouched
    // (still a genuine, counted failure): the retry stays a Reapply and nothing
    // acknowledges.
    CHECK(ledger.failed_receipt_count_for_test() == 0);
    CHECK(ledger.decide_retry(1, std::string(64, '2'), false, *rt) ==
          GuardianArmAckLedger::RetryDecision::Reapply);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
    }
    CHECK_FALSE(ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::can_advance(): latch_failure() blocks unconditionally, and "
          "forces decide_retry() to Reapply even with an otherwise outstanding wedge "
          "(governance Gate 3 quality-engineer finding; #5459 removed the K setup)",
          "[spark][ack]") {
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
    CHECK_FALSE(f.ledger.can_advance());
    CHECK(f.retry() == RD::Suppress); // the otherwise fully-suppressible failure set

    // Latch an unrelated application-level failure (e.g. a full_sync KV sweep failure
    // apply_rules() itself would have hit) on this SAME application. It blocks
    // acknowledgement (as everything here does) and it overrides suppression: the latched
    // failure is a real re-apply owed, not an arm that is merely still in flight.
    f.ledger.latch_failure();
    CHECK_FALSE(f.ledger.can_advance());
    CHECK(f.retry() == RD::Reapply);

    // Draining again (still genuinely wedged) must not clear the latch or change the verdict.
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0); // nothing new in `pending`
    CHECK_FALSE(f.ledger.can_advance());
    CHECK(f.retry() == RD::Reapply);
}

TEST_CASE("GuardianArmAckLedger::can_advance(): a wedge that settles to a real refusal "
          "AFTER the drain is never acknowledged, and its next retry is a Reapply - there "
          "is no drain-time acknowledgement to linearize on (#5459 option D)",
          "[spark][ack][5459]") {
    // Before #5459 the K-waiver acknowledged on the drain-time read: a completion landing
    // after the drain but before can_advance() could not revoke that tick's decision, so a
    // generation could be persisted over a rule that then failed (the drain-to-persist gap).
    // With the waiver deleted nothing is acknowledged off a wedge at all, so this ordering
    // can no longer publish a false advancement.
    Rig5459 f;
    auto w = f.wedge("r1", "/a");
    f.open_app();
    f.ledger.add_pending("r1", w);
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
    for (int i = 0; i < 3; ++i) {
        f.open_app();
        f.ledger.add_pending("r1", accept(*f.rt, "r1", "/a")); // Reobserved: same underlying claim
        CHECK(f.ledger.drain_locked(*f.rt, 10) == 1);
        CHECK_FALSE(f.ledger.can_advance());
    }
    REQUIRE(f.ledger.failed_receipt_count_for_test() == 1);
    CHECK(f.retry() == RD::Suppress);

    // The claim settles to a real refusal - AFTER the drain read it as outstanding.
    f.late_failure("/a");
    CHECK(f.rt->receipt_status(w) == RT::ReceiptStatus::Wedged); // sticky
    CHECK_FALSE(f.ledger.can_advance());                         // no acknowledgement, at any point
    CHECK(f.retry() == RD::Reapply); // the exact-FIFO-front check fails: re-arm, before any drain

    // A SUBSEQUENT drain (the next heartbeat tick) prunes the settled entry; still held, still Reapply.
    CHECK(f.ledger.drain_locked(*f.rt, 10) == 0); // nothing new in `pending`
    CHECK(f.ledger.failed_receipt_count_for_test() == 0);
    CHECK_FALSE(f.ledger.can_advance());
    CHECK(f.retry() == RD::Reapply);
}

TEST_CASE("GuardianSparkRuntime::receipt_status_wedge_aware(): a real concurrent "
          "poller racing the actual production completion path never observes an "
          "inconsistent (status, wedge_eligible) pair (rung 9c PR-5e, #4221, PR "
          "#4529 review finding, round 3 - fixed per happy-path/unhappy-path/"
          "consistency-auditor convergent Gate 4 findings)",
          "[spark][ack]") {
    // Unlike the sequential test above, this races a REAL background reader
    // against the REAL production completion path (a genuine backend refusal
    // resolving on its own detached worker) - no test hook stands in for the
    // race, so this exercises actual concurrency, not settled-then-read
    // ordering. The poller starts BEFORE expire_overdue_claims(): `end` is
    // sticky and unique - once Wedged, `status` never changes again for this
    // receipt, so a poller started AFTER the Pending->Wedged transition can
    // only ever race `wedge_eligible`'s own later true->false narrowing,
    // never the transition a split two-call accessor would actually
    // mishandle. Starting earlier makes BOTH sub-fields of the pair
    // genuinely in flight together at least once: (1) `status` observed
    // Pending, then later Wedged, NEVER the reverse for the same receipt;
    // (2) once a poll observes `status == Wedged && !wedge_eligible`
    // (settled to a genuine refusal, no longer still-claimed) HAVING
    // PREVIOUSLY observed it eligible, no LATER poll ever observes
    // `wedge_eligible == true` again for the same receipt - eligibility only
    // ever narrows for one episode, it cannot un-settle.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::atomic<bool> stop{false};
    std::atomic<int> poll_count{0};
    std::atomic<bool> saw_pending_after_wedged{false};
    std::atomic<bool> saw_eligible_after_settled_ineligible{false};
    // #5459: this scenario (a hung arm that later REFUSES) never owes a compensating
    // teardown, and eligible/compensation_pending are mutually exclusive in any single read.
    std::atomic<bool> saw_compensation_pending{false};
    std::atomic<bool> saw_both_wedge_flags{false};
    // consistency-auditor/happy-path/unhappy-path (round 3, converging): the
    // round-2 versions of these two flags proved only "Wedged was sampled at
    // least once" / "settled-ineligible was sampled at least once" - true even
    // for a poller starting AFTER the transition it claims to have raced. Each
    // now requires having observed the PRE-transition state first, so the flag
    // is genuine proof the straddle itself was sampled, not just the after-state.
    std::atomic<bool> observed_pending_then_wedged{false};
    std::atomic<bool> observed_eligible_then_settled_ineligible{false};
    // Barrier flag for the release below (see its comment): set once the poller has
    // sampled the Wedged-and-still-eligible state at least once.
    std::atomic<bool> poller_saw_eligible_wedged{false};
    std::thread poller{[&] {
        bool ever_pending = false;
        bool ever_wedged = false;
        bool ever_eligible_wedged = false;
        bool ever_settled_ineligible = false;
        while (!stop.load(std::memory_order_relaxed)) {
            const auto wa = rt->receipt_status_wedge_aware(receipt);
            poll_count.fetch_add(1, std::memory_order_relaxed);
            if (wa.status == GuardianSparkRuntime::ReceiptStatus::Pending)
                ever_pending = true;
            if (ever_wedged && wa.status == GuardianSparkRuntime::ReceiptStatus::Pending)
                saw_pending_after_wedged.store(true, std::memory_order_relaxed);
            if (wa.status == GuardianSparkRuntime::ReceiptStatus::Wedged) {
                if (!ever_wedged && ever_pending)
                    observed_pending_then_wedged.store(true, std::memory_order_relaxed);
                ever_wedged = true;
            }
            if (wa.status == GuardianSparkRuntime::ReceiptStatus::Wedged && wa.wedge_eligible) {
                ever_eligible_wedged = true;
                poller_saw_eligible_wedged.store(true, std::memory_order_relaxed);
            }
            if (wa.compensation_pending)
                saw_compensation_pending.store(true, std::memory_order_relaxed);
            if (wa.compensation_pending && wa.wedge_eligible)
                saw_both_wedge_flags.store(true, std::memory_order_relaxed);
            if (ever_settled_ineligible && wa.wedge_eligible)
                saw_eligible_after_settled_ineligible.store(true, std::memory_order_relaxed);
            if (wa.status == GuardianSparkRuntime::ReceiptStatus::Wedged && !wa.wedge_eligible) {
                if (!ever_settled_ineligible && ever_eligible_wedged)
                    observed_eligible_then_settled_ineligible.store(true, std::memory_order_relaxed);
                ever_settled_ineligible = true;
            }
        }
    }};
    // cpp-safety/security-guardian/cpp-expert (round 2, all three independently):
    // a REQUIRE between `poller`'s construction and its join can throw and unwind
    // past a still-joinable std::thread, which calls std::terminate() rather than
    // failing this one test - the exact hazard class this file's sibling
    // (test_guardian_engine_spark_reconcile.cpp) already guards against via a
    // local RAII type, and the shared, promoted fix for it here:
    // yuzu::test::ScopeExit (test_helpers.hpp, already included transitively).
    // Declared immediately after `poller` so it destructs FIRST on any unwind
    // path (reverse declaration order) - sets `stop` before joining, since the
    // poll loop only exits on that flag (joining first would deadlock the
    // unwind). consistency-auditor (round 3): also releases the backend's own
    // hung arm-worker BEFORE stopping/joining the poller - every other
    // hang-then-check test in this file does this via a local Cleanup guard
    // (e.g. this file's own wedge tests above); the round-2 version of
    // this guard omitted it, so a REQUIRE failure between wait_entered_hang()
    // and the explicit release_hang() below would leak FakeBackend's own
    // parked arm-worker thread for the process lifetime - exactly the defect
    // class this file's G2R2-linearization-test-no-cleanup finding already
    // fixed once elsewhere. release_hang() is idempotent (a plain bool flag),
    // so calling it again on the normal path below is safe.
    yuzu::test::ScopeExit poller_guard{[&] {
        b->release_hang();
        stop.store(true, std::memory_order_relaxed);
        if (poller.joinable())
            poller.join();
    }};
    // Barrier: block until the poller has genuinely started and sampled the
    // still-Pending state at least once before advancing the claim to Wedged -
    // without this, thread-creation scheduling latency alone can let
    // expire_overdue_claims() below run before the poller's very first
    // iteration, silently skipping the Pending->Wedged straddle entirely
    // (reproduced empirically: observed_pending_then_wedged read false on a
    // lightly-loaded run with no code defect involved).
    REQUIRE(yuzu::test::spin_until([&] { return poll_count.load(std::memory_order_relaxed) > 0; },
                                   std::chrono::seconds(10)));

    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    REQUIRE(rt->receipt_wedge_k_eligible(receipt));

    // Second barrier (#4661): the eligible->settled-ineligible straddle can only be
    // sampled if the poller observes the Wedged-and-eligible state BEFORE the release
    // below settles it. Under CPU contention the poller can go unscheduled for the
    // whole expire -> release window, so the settled-ineligible state is the only one
    // it ever sees and the straddle flag stays false with no code defect involved
    // (the final spin_until then times out: it waits on a flag that can no longer be
    // set). Waiting on this latched flag instead of sampling the transient state is
    // the same idiom as the poll_count barrier above. Eligibility cannot narrow before
    // the release (the claim stays parked and FIFO-front), so this waits for a state
    // the test already asserts above; it does not weaken any check.
    REQUIRE(yuzu::test::spin_until(
        [&] { return poller_saw_eligible_wedged.load(std::memory_order_relaxed); },
        std::chrono::seconds(10)));

    // The real completion, racing the poller above on its own detached worker -
    // not test-hook-gated.
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return !rt->receipt_wedge_k_eligible(receipt); },
                                   std::chrono::seconds(10)));
    // unhappy-path (round 3): a fixed sleep is not a liveness wait and can
    // starve on a loaded shared CI runner, producing a false BLOCKING red with
    // no production defect behind it - spin on the flag actually needed
    // instead, matching this file's own established idiom.
    REQUIRE(yuzu::test::spin_until(
        [&] { return observed_eligible_then_settled_ineligible.load(std::memory_order_relaxed); },
        std::chrono::seconds(10)));
    stop.store(true, std::memory_order_relaxed);
    poller.join();

    CHECK(poll_count.load(std::memory_order_relaxed) > 0);
    CHECK(observed_pending_then_wedged.load(std::memory_order_relaxed)); // the straddle
        // was genuinely sampled, not just "Wedged was seen at some point"
    CHECK(observed_eligible_then_settled_ineligible.load(std::memory_order_relaxed)); // ditto
    CHECK_FALSE(saw_pending_after_wedged.load(std::memory_order_relaxed));
    CHECK_FALSE(saw_eligible_after_settled_ineligible.load(std::memory_order_relaxed));
    CHECK_FALSE(saw_compensation_pending.load(std::memory_order_relaxed));
    CHECK_FALSE(saw_both_wedge_flags.load(std::memory_order_relaxed));
    CHECK(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged); // still sticky
    CHECK_FALSE(rt->receipt_wedge_k_eligible(receipt));
}
