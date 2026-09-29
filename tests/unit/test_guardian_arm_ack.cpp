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
#include <string>
#include <string_view>
#include <thread>

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

    std::expected<std::uint64_t, std::string> arm(const SparkSpec&) override {
        if (hang_next_arm.exchange(false) || hang_every_arm.load()) {
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
    void disarm(std::uint64_t) override {}

    bool wait_entered_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this] { return entered_hang_; });
    }
    bool wait_parked(int n, std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this, n] { return parked.load() >= n; });
    }
    void release_hang() {
        {
            std::lock_guard<std::mutex> lk{gate_mu_};
            released_ = true;
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
          "to a failure, the same (generation, content) is Reapply, not Suppress",
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

TEST_CASE("GuardianArmAckLedger::decide_retry(): an EMPTY pending map is always "
          "Reapply, never a vacuous Suppress",
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
    GuardianArmAckLedger ledger2;
    ledger2.begin_application(2, std::string(64, 'e'), false, 1);
    auto receipt2 = accept(*rt, "r2");
    ledger2.add_pending("r2", receipt2);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt2); }, std::chrono::seconds(10)));
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
// classification only, not the later K-bound acknowledgement policy (5e).
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

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 1);
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
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): concern 2 - a Wedged receipt that is "
          "later WITHDRAWN (never adopted) never recovers via receipt_recovered(), and "
          "resolved_failed never clears, but the entry leaves the K-eligible set (rung "
          "9c PR-5e, #4221) since it is no longer still-claimed",
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

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 1);
    ledger.add_pending("r1", receipt);
    std::size_t failed_out = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out) == 1);
    CHECK(ledger.failed_receipt_count_for_test() == 1);

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

    std::size_t failed_out2 = 0;
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10, &failed_out2) == 0);
    CHECK(failed_out2 == 0);
    // Never recovered: receipt_recovered() requires rules_ to carry this exact
    // (rule_id, generation), which withdrawal never installs - resolved_failed stays
    // exactly as it was, still 1 (checked via arm_stats() below).
    //
    // rung 9c PR-5e (#4221, K-bound closeout): the entry itself DOES leave
    // failed_receipts now, via receipt_wedge_k_eligible()'s "still-claimed" (FIFO-
    // front) check, not receipt_recovered()'s adoption check - the claim was popped
    // from its key's FIFO the instant the late, disarmed success was published
    // (claim_queue_depth_for_test() == 0 above), so it is no longer the still-
    // outstanding episode K-eligibility requires. This is deliberately SAFER than the
    // pre-5e behavior, not weaker: dropping the entry only ever shrinks the
    // K-waiver-eligible set (resolved_failed itself never moves), so
    // can_advance()'s `resolved_failed == failed_receipts.size()` check correctly
    // stays permanently unsatisfiable for this application - see CHECK_FALSE below,
    // unchanged from before this PR.
    CHECK(ledger.failed_receipt_count_for_test() == 0);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1); // resolved_failed itself is untouched by the pruning
    }
    CHECK_FALSE(ledger.can_advance());
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
// rung 9c PR-5e (#4221, K-bound closeout, decision 1): after
// kReapplyWaiverThreshold identical (generation, content_id, full_sync)
// re-applies, can_advance() waives a Wedged-only failure set - but ONLY once
// receipt_wedge_k_eligible() confirms every remaining failure is still a
// genuinely-outstanding, settled Wedged episode, never a stale or since-
// corrected classification (the Dispatching-window-race / "still-claimed"
// gaps a naive resolved_failed == failed_receipts.size() predicate alone
// would miss - see can_advance()'s and receipt_wedge_k_eligible()'s own doc
// comments).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("GuardianArmAckLedger::can_advance(): K-bound waives a persistently "
          "Wedged-only failure after exactly kReapplyWaiverThreshold identical "
          "reapplies, never before",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    const std::string digest(64, 'a');

    // Establish the wedge once: r1 hangs past its deadline, genuinely dispatched
    // (dispatch reaches Dispatched well before the deadline - the backend call
    // itself is what's hanging), so this is the SETTLED case
    // receipt_wedge_k_eligible() must accept.
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    REQUIRE(rt->receipt_wedge_k_eligible(receipt));

    GuardianArmAckLedger ledger;

    // Application 1 (the original push, reapply_count starts at 0): drains as an
    // ordinary Wedged failure. resolved_failed(1) == failed_receipts(1), but
    // reapply_count(0) < K(3) - held.
    ledger.begin_application(1, digest, false, 1);
    CHECK(ledger.reapply_count_for_test() == 0);
    ledger.add_pending("r1", receipt);
    CHECK(ledger.drain_locked(*rt, 10) == 1);
    CHECK(ledger.failed_receipt_count_for_test() == 1);
    CHECK_FALSE(ledger.can_advance());

    // Reapplies 1-3 (identity-identical, 3 MORE begin_application() calls - the
    // DELIVERY-PLAN's own recorded semantics: "K requires four established
    // applications in total, not three pushes including the original"): up-2's
    // Reobserved path hands back the SAME claim - re-observe it via accept() again
    // each time, matching what a real repeated identical push does
    // (reconcile_rule_locked() re-attaches and add_pending()s fresh for THIS
    // application, per decide_retry()'s own Reapply trigger once resolved_failed >
    // 0).
    for (int i = 1; i <= 3; ++i) {
        ledger.begin_application(1, digest, false, 1);
        CHECK(ledger.reapply_count_for_test() == static_cast<std::size_t>(i));
        auto re_receipt = accept(*rt, "r1"); // Reobserved: same underlying claim
        ledger.add_pending("r1", re_receipt);
        CHECK(ledger.drain_locked(*rt, 10) == 1);
        CHECK(ledger.failed_receipt_count_for_test() == 1);
        if (i < 3)
            CHECK_FALSE(ledger.can_advance()); // reapply_count < K still
    }
    // The 3rd reapply (4th established application overall) installed
    // reapply_count == 3 == K, and the single remaining failure is still genuinely,
    // settledly Wedged - waived.
    CHECK(ledger.reapply_count_for_test() == 3);
    CHECK(ledger.can_advance());

    // A K-waived generation still reports the failure via telemetry (R5.3's own
    // "leaves arm_failed>0" requirement) - K-waiver never erases the receipt or
    // decrements resolved_failed.
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
    }

    // A 4th, DISTINCT push (different content) does not inherit the saturated
    // count - starts a fresh sequence at 0.
    ledger.begin_application(1, std::string(64, 'b'), false, 1);
    CHECK(ledger.reapply_count_for_test() == 0);
    CHECK(ledger.failed_receipt_count_for_test() == 0); // fresh application, no leak
    CHECK(ledger.can_advance()); // trivially true - nothing pending or failed yet
}

TEST_CASE("GuardianArmAckLedger::can_advance(): a non-Wedged failure blocks K-waiver "
          "even at reapply_count >= K - the equality check actually discriminates, "
          "not just the count",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); } // idempotent - releases r1's own park, if still parked
    } cleanup{b.get()};

    const std::string digest(64, 'c');

    // r1: hangs past its deadline - genuinely, settledly Wedged (dispatch reaches
    // Dispatched well before the deadline; the backend call itself is what hangs).
    // Never released until Cleanup - stays wedged for this whole test.
    b->hang_next_arm.store(true);
    auto r1 = accept(*rt, "r1", "/a");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // r2: a DIFFERENT, distinct-key rule whose backend call refuses IMMEDIATELY (no
    // hang at all - hang_next_arm was already consumed by r1's own call above, so
    // this one proceeds straight to the fail_arm check) - a genuine, ordinary
    // (non-Wedged) BackendRefused failure. R5.3's "K is not a generation-wide
    // liveness bound": a sibling's ordinary refusal must hold the generation
    // regardless of r1's own reapply count.
    b->fail_arm.store(true);
    auto r2 = accept(*rt, "r2", "/b");
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(r2); }, std::chrono::seconds(10)));
    CHECK(rt->receipt_status(r2) == GuardianSparkRuntime::ReceiptStatus::Failed);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1); // only r1 - r2 already resolved, never queued
    REQUIRE(rt->receipt_status(r1) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    REQUIRE(rt->receipt_wedge_k_eligible(r1));

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, digest, false, 2);
    ledger.add_pending("r1", r1);
    ledger.add_pending("r2", r2);
    CHECK(ledger.drain_locked(*rt, 10) == 2);
    CHECK(ledger.failed_receipt_count_for_test() == 1); // only r1 - r2 was never Wedged at all
    CHECK_FALSE(ledger.can_advance()); // resolved_failed(2) != failed_receipts.size()(1)

    // Drive reapply_count to K: r1's claim is Reobserved each time (still the same
    // retained-wedge head); r2's rule_id gets a brand-new claim each time (its prior
    // one already resolved and popped) - fail_arm is still set, so each fresh r2
    // attach refuses again immediately, matching "the same rule keeps failing every
    // push" exactly.
    for (int i = 0; i < 3; ++i) {
        ledger.begin_application(1, digest, false, 2);
        auto re_r1 = accept(*rt, "r1", "/a"); // Reobserved
        auto re_r2 = accept(*rt, "r2", "/b"); // fresh claim, refuses again
        REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(re_r2); },
                                       std::chrono::seconds(10)));
        ledger.add_pending("r1", re_r1);
        ledger.add_pending("r2", re_r2);
        CHECK(ledger.drain_locked(*rt, 10) == 2);
        CHECK(ledger.failed_receipt_count_for_test() == 1); // still only r1
    }
    CHECK(ledger.reapply_count_for_test() == 3); // K reached

    // Even at K, the equality check correctly discriminates: resolved_failed(2) !=
    // failed_receipts.size()(1) - r2's non-Wedged failure alone holds the generation,
    // no matter how high reapply_count climbs.
    CHECK_FALSE(ledger.can_advance());
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 2);
    }
}

TEST_CASE("GuardianArmAckLedger::can_advance(): reapply_count funded by an unrelated, "
          "now-cleared sibling failure legitimately K-waives a wedge this ledger has "
          "only ever observed once (governance Gate 4, unhappy-path finding - confirmed "
          "against decision 1's own framing as deliberate, not a defect; see "
          "docs/spark-stage2-guardian-consumer-design.md's R5.3 Mechanism section)",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    const std::string digest(64, 'f');
    GuardianArmAckLedger ledger;

    // Application 1 (the original push, reapply_count starts at 0): r2 fails
    // ordinarily (BackendRefused - never Wedged, never enters failed_receipts).
    // r1 is not part of the push at all yet - standing in for "this rule was
    // fine (or simply not yet in the policy) through the last 3 pushes," so it
    // has not wedged, or even been observed, even once.
    ledger.begin_application(1, digest, false, 1);
    CHECK(ledger.reapply_count_for_test() == 0);
    b->fail_arm.store(true);
    {
        auto r2 = accept(*rt, "r2", "/b");
        REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(r2); },
                                       std::chrono::seconds(10)));
        ledger.add_pending("r2", r2);
    }
    CHECK(ledger.drain_locked(*rt, 10) == 1);
    CHECK(ledger.failed_receipt_count_for_test() == 0); // r2 never Wedged
    CHECK_FALSE(ledger.can_advance()); // r2's ordinary failure alone holds it

    // Reapplies 1-3 (3 MORE identical begin_application() calls - matching the
    // DELIVERY-PLAN's own recorded semantics: K requires four established
    // applications in total, not three pushes including the original): r2 keeps
    // failing ordinarily every time, funding reapply_count purely off its own
    // now-repeated (but never Wedged) refusal.
    for (int i = 1; i <= 3; ++i) {
        ledger.begin_application(1, digest, false, 1);
        CHECK(ledger.reapply_count_for_test() == static_cast<std::size_t>(i));
        auto re_r2 = accept(*rt, "r2", "/b");
        REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(re_r2); },
                                       std::chrono::seconds(10)));
        ledger.add_pending("r2", re_r2);
        CHECK(ledger.drain_locked(*rt, 10) == 1);
        CHECK(ledger.failed_receipt_count_for_test() == 0); // r2 never Wedged
        CHECK_FALSE(ledger.can_advance()); // r2's ordinary failure alone holds it
    }
    REQUIRE(ledger.reapply_count_for_test() == 3); // funded purely by r2's own reapplies

    // Reapply 3 (the funded application): r2's own failure finally clears, and
    // r1 - a DIFFERENT rule, wedging for the very first time this ledger has
    // ever observed it - hangs past its deadline.
    ledger.begin_application(1, digest, false, 2);
    b->fail_arm.store(false);
    b->hang_next_arm.store(true);
    auto r1 = accept(*rt, "r1", "/a");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    auto r2 = accept(*rt, "r2", "/b");
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(r2); }, std::chrono::seconds(10)));
    CHECK(rt->receipt_status(r2) == GuardianSparkRuntime::ReceiptStatus::Committed);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1); // only r1 - r2 already resolved
    REQUIRE(rt->receipt_status(r1) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    REQUIRE(rt->receipt_wedge_k_eligible(r1));

    ledger.add_pending("r1", r1);
    ledger.add_pending("r2", r2);
    CHECK(ledger.drain_locked(*rt, 10) == 2);
    CHECK(ledger.failed_receipt_count_for_test() == 1); // only r1's first-ever Wedged observation

    // The consequence this test pins: r1's wedge is waived despite being observed
    // as Wedged only this once, because reapply_count already reached K purely
    // from r2's earlier, unrelated, now-cleared ordinary failures - matching the
    // design doc's "a specific rule's own wedge can therefore be waived on its
    // very first observation" paragraph. This is decision 1's own reviewed
    // tradeoff (a per-content-sequence counter, not a per-rule/per-episode
    // credit ledger) - not a TOCTOU, not a stale classification, and it does not
    // violate the one invariant K-waiver must never violate: r1 IS, at this exact
    // moment, still genuinely Wedged and still its key's FIFO-front claim.
    CHECK(ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::begin_application(): reapply_count resets to 0 on "
          "any distinct identity, an invalid digest never inherits it, and no stale "
          "failure state leaks into a fresh identical application",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    // Short deadline: the pure begin_application() identity/reset checks below don't
    // touch the runtime at all, but the "no stale failure state leaks" section
    // further down needs a genuine, quickly-triggerable wedge.
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    const std::string digest_x(64, 'e'); // 0-9/a-f only - is_sha256_hex() rejects anything else
    const std::string digest_y(64, 'f');

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, digest_x, false, 0);
    CHECK(ledger.reapply_count_for_test() == 0);
    ledger.begin_application(1, digest_x, false, 0); // identical identity
    CHECK(ledger.reapply_count_for_test() == 1);
    ledger.begin_application(1, digest_x, false, 0); // identical again
    CHECK(ledger.reapply_count_for_test() == 2);

    // A distinct generation resets it.
    ledger.begin_application(2, digest_x, false, 0);
    CHECK(ledger.reapply_count_for_test() == 0);
    ledger.begin_application(2, digest_x, false, 0);
    CHECK(ledger.reapply_count_for_test() == 1);

    // A distinct content_id under the SAME generation resets it too.
    ledger.begin_application(2, digest_y, false, 0);
    CHECK(ledger.reapply_count_for_test() == 0);
    ledger.begin_application(2, digest_y, false, 0);
    CHECK(ledger.reapply_count_for_test() == 1);

    // A distinct full_sync flag alone resets it.
    ledger.begin_application(2, digest_y, true, 0);
    CHECK(ledger.reapply_count_for_test() == 0);

    // An invalid (non-SHA-256-shaped) digest never inherits credit, even against an
    // identical sentinel from a "different" push - matches decide_retry()'s own
    // is_sha256_hex guard exactly.
    ledger.begin_application(3, "not-a-real-digest", false, 0);
    CHECK(ledger.reapply_count_for_test() == 0);
    ledger.begin_application(3, "not-a-real-digest", false, 0); // identical sentinel
    CHECK(ledger.reapply_count_for_test() == 0); // still 0 - sentinels never match

    // Returning to an earlier, previously-established identity does not recover its
    // old (now-superseded) count.
    ledger.begin_application(1, digest_x, false, 0);
    CHECK(ledger.reapply_count_for_test() == 0);

    // Retirement drops the sequence entirely - a subsequent begin has no inherited
    // count regardless of identity. Current state going in: (1, digest_x, false,
    // count=0), from the "returning to an earlier identity" check just above - one
    // more identical call establishes a nonzero count to retire.
    ledger.begin_application(1, digest_x, false, 0);
    REQUIRE(ledger.reapply_count_for_test() == 1);
    ledger.retire();
    ledger.begin_application(1, digest_x, false, 0);
    CHECK(ledger.reapply_count_for_test() == 0);

    // No stale failure state leaks: begin a fresh identical application with a
    // genuine outstanding wedge, K-waive it, then confirm the NEXT identical
    // application starts with clean resolved_failed/failed_receipts (only
    // reapply_count itself carries forward).
    b->hang_next_arm.store(true);
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const std::string digest_z(64, '1');
    ledger.begin_application(9, digest_z, false, 1);
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    ledger.add_pending("r1", receipt);
    ledger.drain_locked(*rt, 10);
    // 3 MORE identical reapplies (4 established applications in total - see the
    // sibling K-bound test's own comment on this exact arithmetic).
    for (int i = 0; i < 3; ++i) {
        ledger.begin_application(9, digest_z, false, 1);
        auto re = accept(*rt, "r1");
        ledger.add_pending("r1", re);
        ledger.drain_locked(*rt, 10);
    }
    REQUIRE(ledger.reapply_count_for_test() == 3);
    REQUIRE(ledger.can_advance()); // K-waived

    // Next identical application: reapply_count carries forward (saturated), but
    // resolved_failed/failed_receipts start fresh - can_advance() is trivially true
    // again (nothing pending/failed YET in this brand-new application), not because
    // K-waiver leaked a "permanently advance-able" state forward.
    ledger.begin_application(9, digest_z, false, 1);
    CHECK(ledger.reapply_count_for_test() == 3); // saturated, carried forward
    CHECK(ledger.failed_receipt_count_for_test() == 0); // no leak
    CHECK(ledger.can_advance()); // vacuously true - a fresh, empty application
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): a genuinely dispatched claim that "
          "later resolves to a real backend refusal leaves the K-eligible set - the "
          "\"still-claimed\" requirement (rung 9c PR-5e, #4221)",
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

    std::size_t failed_out2 = 0;
    CHECK(ledger.drain_locked(*rt, 10, &failed_out2) == 0); // nothing new in `pending`
    CHECK(failed_out2 == 0);
    // Pruned from the K-eligible set - never K-waivable now, even at reapply_count
    // >= K - but resolved_failed itself is untouched (still a genuine, counted
    // failure).
    CHECK(ledger.failed_receipt_count_for_test() == 0);
    {
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
    }
    CHECK_FALSE(ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::can_advance(): latch_failure() blocks "
          "unconditionally even at reapply_count >= K with an otherwise fully "
          "K-eligible failure set (governance Gate 3 quality-engineer finding)",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    const std::string digest(64, 'd');
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, digest, false, 1);
    ledger.add_pending("r1", receipt);
    CHECK(ledger.drain_locked(*rt, 10) == 1);
    CHECK_FALSE(ledger.can_advance()); // reapply_count 0 < K

    for (int i = 0; i < 3; ++i) {
        ledger.begin_application(1, digest, false, 1);
        auto re = accept(*rt, "r1"); // Reobserved: same underlying claim
        ledger.add_pending("r1", re);
        CHECK(ledger.drain_locked(*rt, 10) == 1);
    }
    REQUIRE(ledger.reapply_count_for_test() == 3);
    REQUIRE(ledger.failed_receipt_count_for_test() == 1); // still genuinely eligible
    REQUIRE(ledger.can_advance()); // K-waived, absent any latch - confirms the setup

    // Now latch an unrelated application-level failure (e.g. a full_sync KV sweep
    // failure apply_rules() itself would have hit) on this SAME, otherwise fully
    // K-eligible application. latch_failure() must block unconditionally - it is
    // checked BEFORE the K-arithmetic in can_advance(), and this must never
    // silently reorder to let K-waiver bypass a latched failure.
    ledger.latch_failure();
    CHECK_FALSE(ledger.can_advance());

    // Draining again (still genuinely wedged, still K-eligible) must not clear the
    // latch or change the verdict.
    CHECK(ledger.drain_locked(*rt, 10) == 0); // nothing new in `pending`
    CHECK_FALSE(ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::can_advance(): K-eligibility linearizes at the "
          "drain-time read - a completion landing after drain but before "
          "can_advance() does not retroactively revoke that tick's decision "
          "(docs/spark-stage2-guardian-consumer-design.md's own drain-time-"
          "linearization claim, governance Gate 3 quality-engineer finding)",
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

    const std::string digest(64, '9');
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, digest, false, 1);
    ledger.add_pending("r1", receipt);
    CHECK(ledger.drain_locked(*rt, 10) == 1);
    for (int i = 0; i < 2; ++i) {
        ledger.begin_application(1, digest, false, 1);
        auto re = accept(*rt, "r1");
        ledger.add_pending("r1", re);
        CHECK(ledger.drain_locked(*rt, 10) == 1);
    }
    ledger.begin_application(1, digest, false, 1);
    auto final_receipt = accept(*rt, "r1"); // Reobserved: same underlying claim
    ledger.add_pending("r1", final_receipt);
    CHECK(ledger.drain_locked(*rt, 10) == 1); // this tick's drain-time read: eligible
    REQUIRE(ledger.reapply_count_for_test() == 3);
    REQUIRE(ledger.failed_receipt_count_for_test() == 1);

    // Now let the claim genuinely settle to a real refusal - AFTER this tick's
    // drain already read it as eligible, but BEFORE can_advance() is called. Per
    // the design doc's own "K-eligibility linearizes at the drain-time read"
    // stamp, this tick's decision must stand: can_advance() reads the ledger
    // membership drain_locked() already computed, not the runtime's current
    // (now-stale-relative-to-this-tick) state.
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until(
        [&] { return rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0; },
        std::chrono::seconds(10)));
    CHECK(rt->receipt_status(final_receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged); // sticky
    CHECK(ledger.can_advance()); // this tick's already-drained decision stands

    // A SUBSEQUENT drain (the next heartbeat tick) re-validates and correctly
    // prunes the now-settled entry - can_advance() then correctly flips to false
    // for any FUTURE tick's own decision (this one's already happened).
    CHECK(ledger.drain_locked(*rt, 10) == 0); // nothing new in `pending`
    CHECK(ledger.failed_receipt_count_for_test() == 0);
    CHECK_FALSE(ledger.can_advance());
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
    // consistency-auditor/happy-path/unhappy-path (round 3, converging): the
    // round-2 versions of these two flags proved only "Wedged was sampled at
    // least once" / "settled-ineligible was sampled at least once" - true even
    // for a poller starting AFTER the transition it claims to have raced. Each
    // now requires having observed the PRE-transition state first, so the flag
    // is genuine proof the straddle itself was sampled, not just the after-state.
    std::atomic<bool> observed_pending_then_wedged{false};
    std::atomic<bool> observed_eligible_then_settled_ineligible{false};
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
            if (wa.status == GuardianSparkRuntime::ReceiptStatus::Wedged && wa.wedge_eligible)
                ever_eligible_wedged = true;
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
    // (e.g. this file's own K-bound-waiver test above); the round-2 version of
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
    CHECK(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged); // still sticky
    CHECK_FALSE(rt->receipt_wedge_k_eligible(receipt));
}
