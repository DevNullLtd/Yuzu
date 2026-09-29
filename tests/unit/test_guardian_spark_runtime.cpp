// test_guardian_spark_runtime.cpp - the GuardianSparkRuntime core (ADR-0021 rung
// 3, hardened rung 4.5). Drives the runtime against fake IStateReader /
// ISparkBackend seams (owned via shared_ptr): arm/disarm edges, shared-watcher
// fan-out, evaluate_key verdict -> outbox -> drain, pending-initial, tri-state
// Unknown -> health, generation purge, cap/backpressure leaving an eval pending,
// detach-safety of a late handler EVEN when the reader ref is dropped, and a
// multi-threaded stress case that is the TSan checkpoint.

#include "guardian_spark_runtime.hpp"

#include "guardian_arm_ack.hpp" // rung 9c PR-5e (#4221): ledger-level insertion-gate regression
#include "guardian_convergence_scheduler.hpp" // up-5 (#4221): scheduler integration test
#include "guardian_lifecycle_journal.hpp"

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/spark.hpp>
#include <yuzu/log_token.hpp>

#include "fake_journal_store.hpp" // FakeJournalStore (#4153)
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp> // #4665: shared golden fixture (tests/unit/fixtures/spark/arm_committed_line.json)

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <functional>
#include <latch>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef _WIN32
#  include <csignal>   // SIGABRT (fork-based containment test, rung 9c r3 C2)
#  include <sys/wait.h> // waitpid
#  include <unistd.h>   // fork, _exit
#endif

using namespace yuzu::agent;

namespace {
using clk = std::chrono::steady_clock;

// A reader whose single-key responses tests set directly. Thread-safe for the
// blocking gate tests (one in-flight read; the response fields aren't rewritten
// during it).
struct FakeReader : IStateReader {
    ReadResult<FileSnapshot> file{read_known(FileSnapshot{.exists = true, .size = 4, .hash = "h"})};
    ReadResult<RegistrySnapshot> reg_snap{read_known(RegistrySnapshot{.present = true, .value = "v"})};
    std::unordered_map<std::string, ReadResult<RegistrySnapshot>> reg_values; ///< per value_name override
    ReadResult<ServiceRunState> svc{read_known(ServiceRunState::Running)};
    std::function<void()> on_read; // optional gate
    std::atomic<int> reads{0};
    std::atomic<std::uint64_t> last_hash_cap{0};
    std::atomic<std::size_t> last_reg_plan_size{0};
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan& plan) override {
        reads.fetch_add(1);
        last_hash_cap.store(plan.hash_cap);
        if (on_read) on_read();
        return file;
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan& plan) override {
        reads.fetch_add(1);
        last_reg_plan_size.store(plan.value_names.size());
        RegistryRead out;
        out.latency_us = 7;
        for (const auto& vn : plan.value_names) {
            const auto it = reg_values.find(vn);
            out.values.emplace(vn, it != reg_values.end() ? it->second : reg_snap);
        }
        return out;
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        reads.fetch_add(1);
        return svc;
    }
    std::atomic<int> stops{0};
    void request_stop() noexcept override { stops.fetch_add(1); }
};

/// An EPOCH/PULSE extension of FakeBackend's hang_next_arm / hang_next_disarm idiom
/// below, for the #3848 blocking-backend checkpoint.
///
/// WHY AN EXTENSION AND NOT A SECOND MECHANISM. hang_next_* is a single-waiter,
/// single-shot park: a test arms it, one call enters, the test releases it. Exactly right
/// for pinning one race, useless for a sustained soak where EVERY backend call must be
/// able to block, repeatedly, on several threads at once, with nobody holding a per-call
/// handle. So this adds the two things that turn that idiom into a soak gate - a
/// repeating admission rule (`park_every`) and a broadcast release (`pulse()`) - and
/// keeps everything else, naming included, the same. Two park styles in one file read as
/// one family; two unrelated mechanisms would not.
///
/// NEVER HANGS THE SUITE. Every wait is a `wait_for` with a generous deadline, and a
/// deadline hit is COUNTED (`watchdog_trips`) rather than silently absorbed - the test
/// asserts that count is zero, so a gate that stopped being released fails loudly
/// instead of wedging the binary the way a bare `wait()` would.
struct BlockingGate {
    // ── configuration: set before any thread starts in the COMMON case; a caller
    // that must mutate it once threads are already live (see the REFILLED-claim
    // Dispatching-window test, governance follow-up 2026-09-16) MUST take `mu`
    // first, matching maybe_park()'s own locked read below ──
    int park_every{0};              ///< 0 disables the gate entirely, so the existing
                                    ///< hang_next_* tests are completely unaffected
    int long_every{0};              ///< every Nth park is a LONG hold; 0 = none
    std::uint64_t long_hold_pulses{200}; ///< a long hold lasts this many releaser pulses

    mutable std::mutex mu;
    std::condition_variable cv;
    bool open_{false};              ///< latched open at shutdown: every park returns at once
    std::uint64_t epoch{0};         ///< ++ per pulse(); a short park waits for the next one
    int calls{0};
    int parks{0};
    int parked{0};
    int peak_parked{0};
    std::uint64_t total_parked{0};
    std::uint64_t long_holds{0};
    std::uint64_t watchdog_trips{0};
    /// At most ONE long hold per lane in flight. Each churner owns one IoClass lane and
    /// submits one op at a time, so this only stops a second long hold being selected for
    /// a lane whose previous one has not finished unwinding.
    std::array<bool, 3> long_in_flight{};

    /// Called from inside a backend call, on whatever thread the executor ran it on.
    /// `lane` is the IoClass index, or -1 for a call with no lane (the send fn).
    void maybe_park(int lane) {
        std::unique_lock lk(mu);
        if (park_every <= 0)
            return;
        if (++calls % park_every != 0)
            return;
        const bool want_long = long_every > 0 && (++parks % long_every == 0) && lane >= 0 &&
                               !long_in_flight[static_cast<std::size_t>(lane)];
        ++total_parked;
        ++parked;
        peak_parked = std::max(peak_parked, parked);
        bool released = false;
        if (want_long) {
            ++long_holds;
            long_in_flight[static_cast<std::size_t>(lane)] = true;
            // A LONG hold deliberately outlives the caller's backend_op_deadline, so the
            // submitter observes IoFailure::Timeout and the late-success path runs. Its
            // length is counted in RELEASER PULSES, not wall-clock, so it scales with how
            // slowly a sanitizer build is actually running rather than racing a fixed clock.
            const auto target = epoch + long_hold_pulses;
            released = cv.wait_for(lk, std::chrono::seconds{30},
                                   [&] { return open_ || epoch >= target; });
            long_in_flight[static_cast<std::size_t>(lane)] = false;
        } else {
            const auto target = epoch + 1;
            released = cv.wait_for(lk, std::chrono::seconds{30},
                                   [&] { return open_ || epoch >= target; });
        }
        if (!released)
            ++watchdog_trips;
        --parked;
    }

    void pulse() {
        {
            std::lock_guard lk(mu);
            ++epoch;
        }
        cv.notify_all();
    }
    /// Latch every current and future park open. Idempotent; REQUIRED before any join.
    void open() {
        {
            std::lock_guard lk(mu);
            open_ = true;
        }
        cv.notify_all();
    }
};

struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::atomic<int> arms{0};
    std::atomic<int> disarms{0};
    /// rung 9c R5.2: counted at ENTRY to arm()/disarm(), before any gate or injection
    /// (`arms`/`disarms` count after the gates, so "arms == 0 while parked" cannot prove
    /// that only one backend call ENTERED - a queued sibling that wrongly dispatched
    /// its own arm would be parked too, invisible to `arms`).
    std::atomic<int> arm_entries{0};
    std::atomic<int> disarm_entries{0};
    std::atomic<bool> fail_arm{false};
    std::atomic<bool> throw_arm{false}; ///< arm() throws (a backend that throws, not just fails)
    // #2233 item 3: park the NEXT arm() call (on whichever thread calls it - the
    // GuardianIoExecutor detached worker in production/these tests) until
    // release_hang() is called. Mirrors FakeServiceMechanism's hang idiom in
    // test_guardian_engine_spark_reconcile.cpp: the gate is a SEPARATE lock from
    // nothing here (FakeBackend has no other lock), so release_hang() never blocks.
    std::atomic<bool> hang_next_arm{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool entered_hang_{false};
    bool released_{false};
    /// #3848: the soak gates. Disabled (park_every == 0) unless a test configures them,
    /// so every pre-existing case behaves exactly as before.
    BlockingGate arm_park;
    BlockingGate disarm_park;
    // #3848 census: every subscription id this backend HANDED OUT and every id it was
    // asked to release - written from executor worker threads AND (for the abandonment
    // self-disarm) from inside the arm worker's own lambda. Storage (ids_mu_/armed_ids_/
    // disarmed_ids_) and the exact-id accessors live below, after disarm() - #3816's
    // shape, adopted as-is on merge rather than forking a parallel raw-member convention.
    /// The IoClass lane a spec belongs to, as the runtime derives it — the gates key
    /// their per-lane long-hold state on this. -1 for an inline (non-executor) type.
    static int lane_of(SparkType t) {
        switch (t) {
        case SparkType::File: return 0;
        case SparkType::Registry: return 1;
        case SparkType::Service: return 2;
        default: return -1;
        }
    }
    /// The lane of the id we most recently handed out, so disarm() — which receives only
    /// an id — can park on the right lane. Written under ids_mu_ by arm().
    std::unordered_map<std::uint64_t, int> id_lane_;

    std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) override {
        arm_entries.fetch_add(1);
        if (hang_next_arm.exchange(false)) {
            std::unique_lock<std::mutex> lk{gate_mu_};
            entered_hang_ = true;
            gate_cv_.notify_all();
            gate_cv_.wait(lk, [this] { return released_; });
        }
        std::shared_ptr<ArmGate> keyed_gate;
        {
            std::lock_guard<std::mutex> lk{key_gates_mu_};
            if (const auto it = key_gates_.find(spark_key(spec)); it != key_gates_.end()) {
                keyed_gate = std::move(it->second);
                key_gates_.erase(it);
            }
        }
        if (keyed_gate)
            keyed_gate->wait();
        // #3848: the soak park sits AFTER the single-shot hang (so the two idioms never
        // interleave) and BEFORE the failure injections (so a parked arm still resolves
        // the way an unparked one would).
        const int lane = lane_of(spec.type);
        arm_park.maybe_park(lane);
        if (throw_arm.load()) throw std::runtime_error("arm boom");
        if (fail_arm.load()) return std::unexpected(std::string{"no mechanism"});
        arms.fetch_add(1);
        const std::uint64_t id = next.fetch_add(1);
        {
            std::lock_guard<std::mutex> lk{ids_mu_};
            armed_ids_.push_back(id);
            id_lane_[id] = lane;
        }
        return id;
    }
    void disarm(std::uint64_t sub) override {
        disarm_entries.fetch_add(1);
        if (hang_next_disarm.exchange(false)) {
            std::unique_lock<std::mutex> lk{disarm_gate_mu_};
            disarm_entered_hang_ = true;
            disarm_gate_cv_.notify_all();
            disarm_gate_cv_.wait(lk, [this] { return disarm_released_; });
        }
        int lane = -1;
        {
            std::lock_guard<std::mutex> lk{ids_mu_};
            disarmed_ids_.push_back(sub);
            if (const auto it = id_lane_.find(sub); it != id_lane_.end())
                lane = it->second;
        }
        // #3848: recorded BEFORE the park, so a disarm the test then has to wait out is
        // still counted; the census reconciles ids, never call ordering.
        disarm_park.maybe_park(lane);
        disarms.fetch_add(1);
    }
    /// #3816: exact-id recording, not just balanced counts - a wrong-handle disarm
    /// (the right COUNT, the wrong SUBSCRIPTION) would pass a count-only check.
    std::vector<std::uint64_t> armed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return armed_ids_;
    }
    std::vector<std::uint64_t> disarmed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return disarmed_ids_;
    }
    mutable std::mutex ids_mu_;
    std::vector<std::uint64_t> armed_ids_;
    std::vector<std::uint64_t> disarmed_ids_;

    /// #2818 poll backstop test seam: report a specific health for a specific id,
    /// simulating "the engine says this subscription is dead/faulted" independent of
    /// whether any push notification was ever delivered for it - exactly the fact
    /// revalidate_subscriptions() queries. Unset ids report Healthy (the base class
    /// default), matching every pre-existing test that never calls this.
    void set_health_for_test(std::uint64_t id, SubscriptionHealth h) {
        std::lock_guard<std::mutex> lk{ids_mu_};
        health_[id] = h;
    }
    SubscriptionHealth subscription_health(std::uint64_t id) override {
        std::lock_guard<std::mutex> lk{ids_mu_};
        const auto it = health_.find(id);
        return it != health_.end() ? it->second : SubscriptionHealth::Healthy;
    }
    std::unordered_map<std::uint64_t, SubscriptionHealth> health_;

    /// Blocks until a hung arm() has actually entered its wait (avoids a racy
    /// sleep-based poll for "is the worker parked yet").
    bool wait_entered_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this] { return entered_hang_; });
    }
    void release_hang() {
        {
            std::lock_guard<std::mutex> lk{gate_mu_};
            released_ = true;
        }
        gate_cv_.notify_all();
    }
    /// Quality-engineer Gate 3 finding: entered_hang_/released_ latch permanently
    /// true after one release_hang() and were never resettable, a silent-no-op trap
    /// for any test needing a SECOND hang on the same FakeBackend (e.g. a
    /// timeout-then-retry sequence). Call between uses, only once release_hang()'s
    /// waiter has actually woken (the caller's own synchronization - typically
    /// after observing the effect of the first hang, e.g. a timeout return).
    void reset_hang() {
        std::lock_guard<std::mutex> lk{gate_mu_};
        entered_hang_ = false;
        released_ = false;
    }

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
    std::mutex key_gates_mu_;
    std::unordered_map<std::string, std::shared_ptr<ArmGate>> key_gates_;
    std::vector<std::shared_ptr<ArmGate>> all_key_gates_;
    std::shared_ptr<ArmGate> park_next_arm_for_key(const std::string& key) {
        auto gate = std::make_shared<ArmGate>();
        std::lock_guard<std::mutex> lk{key_gates_mu_};
        all_key_gates_.push_back(gate);
        key_gates_.insert_or_assign(key, gate);
        return gate;
    }
    void release_all_key_gates() {
        std::lock_guard<std::mutex> lk{key_gates_mu_};
        for (const auto& gate : all_key_gates_)
            gate->release(); // includes gates already consumed by arm()
    }

    /// Adversarial-review C2/c2 regression coverage: park the NEXT disarm() call
    /// (a SEPARATE gate from arm()'s, so a test can hang a rollback's disarm
    /// specifically without also hanging any arm).
    std::atomic<bool> hang_next_disarm{false};
    std::mutex disarm_gate_mu_;
    std::condition_variable disarm_gate_cv_;
    bool disarm_entered_hang_{false};
    bool disarm_released_{false};
    bool wait_entered_disarm_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{disarm_gate_mu_};
        return disarm_gate_cv_.wait_for(lk, timeout, [this] { return disarm_entered_hang_; });
    }
    void release_disarm_hang() {
        {
            std::lock_guard<std::mutex> lk{disarm_gate_mu_};
            disarm_released_ = true;
        }
        disarm_gate_cv_.notify_all();
    }
    /// See reset_hang()'s doc - same single-shot-latch fix, disarm side.
    void reset_disarm_hang() {
        std::lock_guard<std::mutex> lk{disarm_gate_mu_};
        disarm_entered_hang_ = false;
        disarm_released_ = false;
    }
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
SparkSpec svc_spec(const std::string& name) {
    return SparkSpec{SparkType::Service, ServiceSparkParams{name}};
}
RuleAssertion svc_running_rule(const std::string& rule_id) {
    RuleAssertion a;
    a.kind = AssertionKind::ServiceRunning;
    a.rule_id = rule_id;
    return a;
}
SparkSpec reg_spec(const std::string& hive, const std::string& key) {
    return SparkSpec{SparkType::Registry, RegistrySparkParams{hive, key}};
}
RuleAssertion registry_rule(const std::string& rule_id, const std::string& value_name,
                            const std::string& expected) {
    RuleAssertion a;
    a.kind = AssertionKind::RegistryEquals;
    a.rule_id = rule_id;
    a.value_name = value_name;
    a.expected_value = expected;
    return a;
}
// Drains the compliance/health verdicts these tests were written against.
// Filters out Lifecycle (rung 7 audit-on-arm: attach_rule/detach_rule now
// enqueue an armed/disarmed entry on every call) - a SEPARATE helper below
// (drain_lifecycle) is for the tests that specifically exercise that.
std::vector<OutboxEntry> drain_all(GuardianSparkRuntime& rt) {
    std::vector<OutboxEntry> got;
    rt.drain([&](const OutboxEntry& e) {
        if (e.domain != OutboxDomain::Lifecycle)
            got.push_back(e);
        return SendResult::Sent;
    });
    return got;
}
std::vector<OutboxEntry> drain_lifecycle(GuardianSparkRuntime& rt) {
    std::vector<OutboxEntry> got;
    rt.drain([&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle)
            got.push_back(e);
        return SendResult::Sent;
    });
    return got;
}
std::shared_ptr<GuardianSparkRuntime> make_rt(std::shared_ptr<FakeReader> r,
                                              std::shared_ptr<FakeBackend> b,
                                              GuardianSparkRuntime::Config cfg = {}) {
    // Deterministic clock so debounce is controllable. The lambda captures nothing
    // borrowed (the static satisfies the self-contained-clock contract).
    static std::atomic<std::int64_t> tick{0};
    return std::make_shared<GuardianSparkRuntime>(
        std::move(r), std::move(b), cfg,
        [] { return clk::time_point{} + std::chrono::milliseconds(tick.fetch_add(1000)); });
}

// F5 (6b/6c): a PER-TEST clock the test explicitly advances, unlike make_rt's TU-global
// clock above which auto-advances +1s on every call regardless of which test invoked it.
// The M1 refresh/demotion intervals are minutes-scale - driving them off an uncontrolled
// shared auto-tick would make elapsed-time assertions racy against test execution order.
// Holds its counter in a shared_ptr (not a raw capture) so the runtime's clock stays
// self-contained per its own lifetime contract (guardian_spark_runtime.hpp:186-193,
// the constructor doc block).
struct SettableClock {
    std::shared_ptr<std::atomic<std::int64_t>> ms{std::make_shared<std::atomic<std::int64_t>>(0)};
    void advance(std::int64_t delta_ms) { ms->fetch_add(delta_ms); }
    [[nodiscard]] RuntimeClock as_runtime_clock() const {
        auto m = ms;
        return [m] { return clk::time_point{} + std::chrono::milliseconds(m->load()); };
    }
};
std::shared_ptr<GuardianSparkRuntime> make_rt_with_clock(std::shared_ptr<FakeReader> r,
                                                         std::shared_ptr<FakeBackend> b,
                                                         const SettableClock& sc,
                                                         GuardianSparkRuntime::Config cfg = {}) {
    return std::make_shared<GuardianSparkRuntime>(std::move(r), std::move(b), cfg,
                                                  sc.as_runtime_clock());
}

// A replayable lifecycle entry for try_page_batch tests.
OutboxEntry lc_entry(const std::string& rule, const std::string& eid, const std::string& kind = "armed") {
    return OutboxEntry::lifecycle(rule, 1, eid, 1'700'000'000'000'000'000, kind, "file", "n");
}

// A component + runtime + KvStore rig for page_into_window integration (item 7 PR-Ag C5).
struct PageRig {
    yuzu::test::TempDbFile db{"yuzu_test_page-"};
    std::unique_ptr<KvStore> kv;
    std::shared_ptr<GuardianSparkRuntime> rt;
    std::unique_ptr<GuardianLifecycleJournal> journal;
    PageRig() {
        auto r = KvStore::open(db.path);
        REQUIRE(r.has_value());
        kv = std::make_unique<KvStore>(std::move(*r));
        rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
        journal = std::make_unique<GuardianLifecycleJournal>(kv.get());
    }
    // Persist one record as its own batch (a distinct persist call → a distinct batch key).
    void persist(const std::string& rule, const std::string& kind = "armed") {
        std::vector<std::shared_ptr<const JournalRecord>> pending{
            std::make_shared<const JournalRecord>(
                JournalRecord{.rule_id = rule, .generation = 1, .event_id = "e-" + rule,
                              .enqueued_ns = 1'700'000'000'000'000'000, .kind = kind,
                              .guard_type = "file", .rule_name = "n"})};
        REQUIRE(journal->persist(pending, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 1);
    }
};

// A component + runtime + FakeJournalStore rig (#4153) for the two concurrency
// checkpoints that used to run against a real on-disk KvStore. `store` is declared
// FIRST so it is fully constructed before `journal` captures `store.get()`, and it
// outlives `journal` on teardown too (member destruction is reverse-declaration-order,
// so `journal`, a non-owning raw pointer holder, is destroyed before the store it
// points at - though it does nothing in its destructor that would matter either way).
struct FakeStoreRig {
    std::unique_ptr<yuzu::test::FakeJournalStore> store =
        std::make_unique<yuzu::test::FakeJournalStore>();
    std::shared_ptr<GuardianSparkRuntime> rt =
        make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    std::unique_ptr<GuardianLifecycleJournal> journal =
        std::make_unique<GuardianLifecycleJournal>(store.get());

    // Seed one batch DIRECTLY into the store with an EXPLICIT timestamp, bypassing
    // persist() entirely - persist() stamps real wall-clock system_clock::now(), which
    // would make a pruner clock walking a controlled historical range never actually
    // reach the batch's age (the pre-#4153 pagers test's "walks forward to drive the
    // age-cutoff logic" claim was hollow for exactly this reason: it seeded via
    // PageRig::persist() while pruning against a fixed 2023 clock). `ts_ms` doubling
    // as the only source of key uniqueness across a rig's seed calls is deliberate -
    // every caller in this file seeds a distinct ts_ms per batch, so the default
    // nonce/seq never collide.
    void seed_batch(std::int64_t ts_ms, const std::string& rule, std::uint64_t seq = 0,
                    const std::string& nonce = "seed") {
        const std::vector<JournalRecord> entries{
            JournalRecord{.rule_id = rule, .generation = 1, .event_id = "e-" + rule,
                          .enqueued_ns = ts_ms * 1'000'000, .kind = "armed",
                          .guard_type = "file", .rule_name = "n"}};
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(store->insert_if_absent(kJournalNamespace, key,
                                        serialize_journal_batch(ts_ms, entries)) ==
               KvInsert::Inserted);
    }
};

// Portable std::jthread/std::stop_token replacement (adversarial-review finding,
// #4153): Apple Clang's libc++, at Yuzu's declared Apple Clang 15+ floor
// (docs/cpp-conventions.md), does not provide std::jthread or std::stop_token -
// this exact break already took down the macOS leg once (#2530/#2580,
// test_secret_codec.cpp:1103-1121), and every OTHER std::jthread use in the tree
// feature-gates it (`#ifdef __cpp_lib_jthread`, e.g. auth_db.cpp:440-445). Rather
// than duplicate every worker body below behind that macro, this hand-rolled RAII
// thread + shared atomic-flag pair sidesteps the feature-detection question
// entirely: it is unconditionally portable across every supported compiler and
// reproduces exactly the two properties the two checkpoints below actually need -
// stop_requested() as a poll predicate, and an implicit request-then-join on
// destruction so a REQUIRE-throw unwind can never leave a worker joinable (the
// same std::terminate hazard test_secret_codec.cpp's JoinGuard exists for).
class PortableStopToken {
public:
    explicit PortableStopToken(std::shared_ptr<std::atomic<bool>> flag) : flag_(std::move(flag)) {}
    bool stop_requested() const { return flag_->load(std::memory_order_acquire); }

private:
    std::shared_ptr<std::atomic<bool>> flag_;
};

class PortableJThread {
public:
    // Mirrors std::jthread's own overload selection: a callable taking one
    // PortableStopToken gets one constructed from this instance's shared flag;
    // anything else (a plain `[&]{...}` capture) is invoked with no arguments.
    template <typename F>
    explicit PortableJThread(F&& f) : flag_(std::make_shared<std::atomic<bool>>(false)) {
        if constexpr (std::is_invocable_v<std::decay_t<F>, PortableStopToken>) {
            thread_ = std::thread(
                [f = std::forward<F>(f), tok = PortableStopToken(flag_)]() mutable { f(tok); });
        } else {
            thread_ = std::thread(std::forward<F>(f));
        }
    }
    PortableJThread(PortableJThread&&) = default;
    PortableJThread& operator=(PortableJThread&&) = default;
    // Matches std::jthread::join(): joins only, does NOT request_stop() first (that
    // combination is exclusive to the destructor, both here and on the real type).
    void join() { thread_.join(); }
    ~PortableJThread() {
        if (thread_.joinable()) {
            flag_->store(true, std::memory_order_release);
            thread_.join();
        }
    }

private:
    std::shared_ptr<std::atomic<bool>> flag_;
    std::thread thread_;
};
} // namespace

TEST_CASE("attach arms the watcher on the 0->1 edge; a sibling rule shares it", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->arms.load() == 1);
    REQUIRE(rt->armed_key_count() == 1);

    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    REQUIRE(b->arms.load() == 1); // shared watcher, no second arm
    REQUIRE(rt->rule_count() == 2);
    REQUIRE(rt->armed_key_count() == 1);

    // One event fans out to both rules.
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 2); // both compliant edges
}

TEST_CASE("detach disarms on the ->0 edge; a sibling detach keeps the watcher", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);

    rt->detach_rule("r1"); // sibling remains -> no disarm
    REQUIRE(b->disarms.load() == 0);
    REQUIRE(rt->armed_key_count() == 1);
    REQUIRE(rt->rule_count() == 1);

    rt->detach_rule("r2"); // ->0 -> disarm
    // rung 9c PR-2 Unit 3: submit_disarm_off_lock() is non-blocking now (submit(), not
    // run()) - detach_rule() returns once the disarm is admitted, not once the backend
    // call physically finishes, so the actual disarm count is observed asynchronously.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    REQUIRE(rt->armed_key_count() == 0);
}

TEST_CASE("#2818 poll backstop: revalidate_subscriptions detects and reports a dead "
          "subscription no push notification ever announced",
          "[spark][runtime]") {
    // The delivery-guarantee backstop for the case where a genuine Lost notification
    // was silently dropped by a full Queued consumer channel: this test never triggers
    // (or relies on) a Lost push at all — b->set_health_for_test reports the exact fact
    // subscription_health() would, independent of how the subscription actually died.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(rt->armed_key_count() == 1);
    REQUIRE(rt->rule_count() == 1);
    REQUIRE(b->armed_ids().size() == 1);

    b->set_health_for_test(b->armed_ids().front(), SubscriptionHealth::Dead);
    rt->revalidate_subscriptions();

    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->rule_count() == 0);
    const auto lc = drain_lifecycle(*rt);
    REQUIRE(!lc.empty());
    CHECK(std::any_of(lc.begin(), lc.end(), [](const OutboxEntry& e) {
        return e.rule_id == "r1" && e.lifecycle_kind == "errored";
    }));
}

TEST_CASE("#2818 poll backstop: a Healthy/Faulted subscription is left alone",
          "[spark][runtime]") {
    // Scoped to Dead only (Dave's call, 2026-09-06): a Faulted key is still armed at
    // the engine level and may self-heal, so the backstop must not detach it.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->armed_ids().size() == 1);
    b->set_health_for_test(b->armed_ids().front(), SubscriptionHealth::Faulted);

    rt->revalidate_subscriptions();

    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);
    CHECK(b->disarms.load() == 0);
}

TEST_CASE("#2818: a stale Lost/Faulted notification (superseded by a fresh re-arm) is a "
          "safe no-op (quality-engineer Gate 3 finding - the staleness guard was untested)",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->armed_ids().size() == 1);
    const auto stale_id = b->armed_ids().front();

    // Detach then re-attach: the key gets a FRESH subscription id, distinct from the
    // one the (now-stale) notification below still names.
    rt->detach_rule("r1");
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->armed_ids().size() == 2);
    REQUIRE(b->armed_ids().back() != stale_id); // ids are monotonic, never reused

    // A Lost naming the STALE id must be a no-op: r1 stays armed under its fresh id.
    rt->on_event(SparkEvent{.key = key, .kind = SparkEventKind::Lost, .subscription_id = stale_id});
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);

    // A Faulted naming the STALE id must also be a no-op: no health entry produced.
    rt->on_event(SparkEvent{.key = key,
                             .kind = SparkEventKind::Faulted,
                             .subscription_id = stale_id,
                             .detail = "stale"});
    const auto got = drain_all(*rt);
    CHECK(got.empty());
    CHECK(rt->armed_key_count() == 1); // still armed - the guard held both times
}

TEST_CASE("evaluate_key re-reads live state each pass (event is a hint)", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_known(FileSnapshot{.exists = true}); // compliant
    rt->evaluate_key(key, EvalReason::Initial);
    auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].drift.compliant);

    r->file = read_known(FileSnapshot{.exists = false}); // now absent
    rt->evaluate_key(key, EvalReason::Event);            // re-reads -> drift
    got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE_FALSE(got[0].drift.compliant);
    REQUIRE(got[0].drift.detected_value == "<absent>");
}

TEST_CASE("#4606 criterion-10: on_event(Fired) stages a timing record with trigger present "
          "(mechanism/handler/seq); a Convergence pass with no event stages trigger absent",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_known(FileSnapshot{.exists = true}); // compliant
    auto steady_ns = [] {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    };
    const auto mono_before_ns = steady_ns();
    const auto before = std::chrono::system_clock::now();
    const SparkEvent ev{.key = key, .seq = 42, .at = std::chrono::system_clock::now(),
                        .kind = SparkEventKind::Fired};
    rt->on_event(ev);
    const auto after = std::chrono::system_clock::now();
    const auto mono_after_ns = steady_ns();
    drain_all(*rt); // clears the buffered edge; not what this test asserts on

    auto timings = rt->last_eval_timings_for_test();
    REQUIRE(timings.size() == 1);
    REQUIRE(timings[0].trigger.has_value());
    CHECK(timings[0].trigger->seq == 42);
    // The three *_mono_ns stamps must be REAL steady_clock reads: the runtime's injected clock
    // (make_rt) is a small synthetic time_point, so a stamp taken from it would fall outside this
    // bracket and fail, and the chain must be non-decreasing in program order.
    REQUIRE(timings[0].accepted);
    CHECK(timings[0].trigger->handler_mono_ns >= mono_before_ns);
    CHECK(timings[0].trigger->handler_mono_ns <= timings[0].detect_mono_ns);
    CHECK(timings[0].detect_mono_ns <= timings[0].fire_mono_ns);
    CHECK(timings[0].fire_mono_ns <= mono_after_ns);
    CHECK(timings[0].trigger->mechanism_wall_ns ==
          std::chrono::duration_cast<std::chrono::nanoseconds>(ev.at.time_since_epoch()).count());
    const auto before_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(before.time_since_epoch()).count();
    const auto after_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(after.time_since_epoch()).count();
    CHECK(timings[0].trigger->handler_wall_ns >= before_ns);
    CHECK(timings[0].trigger->handler_wall_ns <= after_ns);

    // Convergence-reason pass, no event context. Flip the read so it actually produces a
    // record (a no-op Convergence over unchanged compliant state stages nothing).
    r->file = read_known(FileSnapshot{.exists = false}); // now drifted
    rt->evaluate_key(key, EvalReason::Convergence);
    timings = rt->last_eval_timings_for_test();
    REQUIRE(timings.size() == 1);
    CHECK_FALSE(timings[0].trigger.has_value());
}

TEST_CASE("pending-initial holds until a Known verdict, kept on Unknown", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(rt->pending_initial(key) == std::vector<std::string>{"r1"});

    // Unknown read -> health event, pending-initial RETAINED.
    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(rt->pending_initial(key) == std::vector<std::string>{"r1"});
    auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].domain == OutboxDomain::Health);
    REQUIRE_FALSE(got[0].healthy);

    // Known read -> compliance verdict, pending-initial cleared.
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->pending_initial(key).empty());
}

TEST_CASE("a backend arm failure errors the rule, never a silent legacy fallback",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->fail_arm = true;
    auto rt = make_rt(r, b);
    const auto res = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(res.has_value()); // errored
    REQUIRE(rt->armed_key_count() == 0);
    REQUIRE(rt->rule_count() == 0); // not left half-attached
}

TEST_CASE("drain sends Lifecycle (armed) before Compliance (item 4 / Fable M6)",
          "[spark][runtime]") {
    // The "armed" audit entry must reach the server before the rule's first compliance
    // event, or the trail shows detection preceding arm.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // Lifecycle "armed"
    rt->evaluate_key(key, EvalReason::Initial);                           // Compliance edge
    REQUIRE(rt->outbox_size() == 1);

    // Capture EVERY domain in send order (drain_all/drain_lifecycle filter by domain).
    std::vector<OutboxEntry> got;
    rt->drain([&](const OutboxEntry& e) {
        got.push_back(e);
        return SendResult::Sent;
    });
    REQUIRE(got.size() == 2);
    CHECK(got[0].domain == OutboxDomain::Lifecycle); // armed first
    CHECK(got[0].lifecycle_kind == "armed");
    CHECK(got[1].domain == OutboxDomain::Compliance); // then the edge
}

TEST_CASE("drain does NOT let a stuck lifecycle head block compliance (Gate 4 UP-3)",
          "[spark][runtime]") {
    // Regression for the M6-gate blackout: an earlier version gated compliance on the
    // lifecycle log being empty, so a lifecycle head that could not send blocked ALL
    // compliance/health indefinitely. Both logs must drain every pass (lifecycle first
    // for best-effort ordering, but NO hard gate) so failure isolation holds.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // Lifecycle "armed"
    rt->evaluate_key(key, EvalReason::Initial);                           // Compliance edge
    REQUIRE(rt->outbox_size() == 1);

    // Retain the lifecycle head (as if its send keeps failing); compliance must STILL drain.
    std::vector<OutboxDomain> got;
    rt->drain([&](const OutboxEntry& e) {
        got.push_back(e.domain);
        return e.domain == OutboxDomain::Lifecycle ? SendResult::Retain : SendResult::Sent;
    });
    CHECK(rt->outbox_size() == 0); // compliance drained despite the stuck lifecycle head
    REQUIRE(got.size() == 2);
    CHECK(got[0] == OutboxDomain::Lifecycle);  // attempted first (best-effort ordering)
    CHECK(got[1] == OutboxDomain::Compliance); // then compliance, NOT blocked
}

TEST_CASE("drain counts a send that throws and retains the head (item 4 hardening)",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // Lifecycle "armed"
    REQUIRE(rt->send_exception_count() == 0);

    // A throwing send must not escape drain (that would eventually reach the worker's
    // firewall), must be counted (not silent), and must retain the head.
    rt->drain([](const OutboxEntry&) -> SendResult { throw std::runtime_error("send boom"); });
    CHECK(rt->send_exception_count() == 1);

    const auto lc = drain_lifecycle(*rt); // clean drain: the retained head still sends
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].lifecycle_kind == "armed");
}

TEST_CASE("drain releases outbox_mu_ during send - no head-of-line block (item 4)",
          "[spark][runtime]") {
    // Proof the send (a gRPC Write in production) no longer runs UNDER outbox_mu_: the
    // callback itself takes outbox_mu_ via outbox_size(). Under the old lock-across-send
    // drain this self-deadlocks the drain thread; with item 4 it completes.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // enqueues an "armed"

    // Run the drain on a separate thread with a timeout so a REGRESSION (self-deadlock
    // when the send runs under outbox_mu_) fails FAST here instead of burning the 240s
    // binary-level CI timeout and killing every other test in the run (quality Gate 3).
    // The blocked thread would hold only locks local to this test's rt - safe to abandon.
    std::atomic<bool> callback_ran{false};
    std::atomic<std::size_t> sent{0};
    auto fut = std::async(std::launch::async, [&] {
        sent = rt->drain([&](const OutboxEntry&) {
            (void)rt->outbox_size(); // takes outbox_mu_ - would DEADLOCK if held across send
            callback_ran = true;
            return SendResult::Sent;
        });
    });
    REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready); // no deadlock
    fut.get();
    CHECK(callback_ran.load());
    CHECK(sent.load() == 1);
}

TEST_CASE("detach purges a rule's buffered (undrained) outbox entries", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->evaluate_key(key, EvalReason::Initial); // buffers a compliant edge (not drained)
    REQUIRE(rt->outbox_size() == 1);

    rt->detach_rule("r1");
    REQUIRE(rt->outbox_size() == 0); // purged, never sent for a withdrawn rule
}

TEST_CASE("re-attach supersedes the old generation and purges its stale entry", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    const auto gen1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 1);

    // Re-attach (same rule) -> a new generation; the stale gen-1 entry is purged.
    const auto gen2 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(gen2.value() > gen1.value());
    REQUIRE(rt->outbox_size() == 0);

    rt->evaluate_key(key, EvalReason::Initial);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].generation == gen2.value());
}

TEST_CASE("at outbox cap the eval stays pending and is delivered after a drain", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor; three drifting keys exceed it
    auto rt = make_rt(r, b, cfg);
    const auto k3 = spark_key(file_spec("/c"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/false), true); // drifts
    rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2", /*present=*/false), true); // drifts
    rt->attach_rule("r3", file_spec("/c"), file_exists_rule("r3", /*present=*/false), true); // drifts
    r->file = read_known(FileSnapshot{.exists = true}); // present -> all rules drift (expect absent)

    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial); // slot 1
    rt->evaluate_key(spark_key(file_spec("/b")), EvalReason::Initial); // slot 2 (full)
    REQUIRE(rt->outbox_size() == 2);
    rt->evaluate_key(k3, EvalReason::Initial); // rejected at cap -> r3 left pending
    REQUIRE(rt->outbox_size() == 2);
    REQUIRE(rt->outbox_backpressure_drops() == 1);
    REQUIRE(rt->pending_initial(k3) == std::vector<std::string>{"r3"}); // still owes a verdict

    drain_all(*rt);                                // frees the slots
    rt->evaluate_key(k3, EvalReason::Convergence); // now r3's drift lands
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].rule_id == "r3");
    REQUIRE(rt->pending_initial(k3).empty());
}

TEST_CASE("#4606 criterion-10: a rejected enqueue at outbox cap stages accepted=false with "
          "fire_wall_ns/fire_mono_ns at the -1 sentinel while detect_wall_ns is still captured",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor; three drifting keys exceed it
    auto rt = make_rt(r, b, cfg);
    const auto k3 = spark_key(file_spec("/c"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/false), true);
    rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2", /*present=*/false), true);
    rt->attach_rule("r3", file_spec("/c"), file_exists_rule("r3", /*present=*/false), true);
    r->file = read_known(FileSnapshot{.exists = true}); // present -> all rules drift (expect absent)

    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial); // slot 1
    rt->evaluate_key(spark_key(file_spec("/b")), EvalReason::Initial); // slot 2 (full)
    REQUIRE(rt->outbox_size() == 2);

    rt->evaluate_key(k3, EvalReason::Initial); // rejected at cap
    REQUIRE(rt->outbox_size() == 2);

    const auto timings = rt->last_eval_timings_for_test();
    REQUIRE(timings.size() == 1); // r3's one drift entry, rejected
    CHECK_FALSE(timings[0].accepted);
    // -1 "never fired" sentinel, never a fabricated 0 a parser could read as "fired at the epoch".
    CHECK(timings[0].fire_wall_ns == -1);
    CHECK(timings[0].fire_mono_ns == -1);
    CHECK(timings[0].detect_wall_ns != 0); // still captured even though the enqueue was rejected
    CHECK(timings[0].detect_mono_ns != 0);
}

TEST_CASE("a configured capacity below two is floored so a recovery pair can never be lost",
          "[spark][runtime]") {
    // A recovery emits TWO entries (guard.healthy + verdict). A cap of 1 would reject
    // the pair on every retry forever. The runtime floors the capacity at 2.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // deliberately below the floor
    auto rt = make_rt(r, b, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io"); // errored -> health(false)
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1);

    r->file = read_known(FileSnapshot{.exists = false}); // recovery to a DRIFT -> health(true)+drift
    rt->evaluate_key(key, EvalReason::Event);
    const auto g = drain_all(*rt);
    REQUIRE(g.size() == 2); // the pair landed - not permanently rejected
    REQUIRE(rt->pending_initial(key).empty());
}

TEST_CASE("Unknown flood guard: repeat errored evals emit one health(false), count the rest (M1)",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io");
    // First errored eval -> exactly one guard.unhealthy on the wire; nothing suppressed yet.
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 0);

    // The convergence priority lane re-visits a rule still owing a verdict every tick. Three
    // more errored re-evals must produce NO new wire entries - each is counted instead, so a
    // rule stuck errored can't flood the fleet's health-event ingest.
    for (int i = 0; i < 3; ++i)
        rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 3);
    REQUIRE_FALSE(rt->pending_initial(key).empty()); // still Unknown -> still owes a verdict

    // Recovery emits guard.healthy (+ the compliant edge) and re-arms the edge: the NEXT
    // Unknown emits a fresh health(false), and the suppression counter is untouched by it.
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Event);
    const auto recovered = drain_all(*rt);
    // Precisely: recovery MUST emit a guard.healthy (Health domain, healthy=true), not merely
    // "some entry" - a regression that dropped health(true) on recovery would leave the health
    // stream stuck errored forever (qa Gate-3 SHOULD).
    REQUIRE(std::any_of(recovered.begin(), recovered.end(), [](const OutboxEntry& e) {
        return e.domain == OutboxDomain::Health && e.healthy;
    }));
    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 3);
}

TEST_CASE("Unknown edge rejected at outbox cap is retried, never counted as suppressed (M1)",
          "[spark][runtime]") {
    // Metrics-honesty invariant: unhealthy_suppressed_ counts only COMMITTED repeat-Unknowns,
    // never an edge the outbox rejected (that edge is re-attempted, not suppressed). Guards the
    // counter's placement AFTER the accept-check + COMMIT against a future refactor that hoists it.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor
    auto rt = make_rt(r, b, cfg);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/false), true); // drifts
    rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2", /*present=*/false), true); // drifts
    const auto kc = spark_key(file_spec("/c"));
    rt->attach_rule("rc", file_spec("/c"), file_exists_rule("rc", /*present=*/true), true);

    // Fill the outbox with two drifts (no slot left).
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial);
    rt->evaluate_key(spark_key(file_spec("/b")), EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);

    // Edge Unknown for rc while the outbox is full: its single health(false) entry is rejected
    // (both-or-neither), so nothing commits, rc stays pending, and NOTHING is counted suppressed -
    // the edge was not delivered and will be retried, so counting it would over-report.
    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(kc, EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);
    REQUIRE(rt->pending_initial(kc) == std::vector<std::string>{"rc"});
    REQUIRE(rt->unhealthy_suppressed() == 0);

    // Drain frees a slot; the STILL-first Unknown re-attempts as a fresh edge and lands.
    drain_all(*rt);
    rt->evaluate_key(kc, EvalReason::Convergence);
    REQUIRE(drain_all(*rt).size() == 1);      // the edge health(false) finally delivered, not lost
    REQUIRE(rt->unhealthy_suppressed() == 0); // still an edge, never a suppression
}

TEST_CASE("Unknown flood guard: two rules on one key each count suppression independently (M1)",
          "[spark][runtime]") {
    // The counter increments PER RULE inside the per-key eval loop, not once per key. A refactor
    // that hoisted the increment outside the loop would silently under-count a multi-rule key
    // (qa Gate-3 SHOULD). Two rules share one spark_key; both go Unknown together.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io");
    // First pass: both rules edge -> two health(false) on the wire, nothing suppressed.
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 2);
    REQUIRE(rt->unhealthy_suppressed() == 0);

    // Second pass: both rules repeat -> no wire entries, +2 suppressed (one per rule, not one
    // per key).
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 2);
}

// --- F5 6b: errored-refresh backstop -----------------------------------------------

TEST_CASE("M1 refresh: a repeat Unknown before errored_refresh_ms elapses stays suppressed (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc); // default errored_refresh_ms = 300'000
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(1'000); // well short of the 300s default
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);
}

TEST_CASE("M1 refresh: a repeat Unknown past errored_refresh_ms re-emits with the CURRENT "
          "detail (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("eacces");
    rt->evaluate_key(key, EvalReason::Initial); // edge, detail="eacces"
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(300'000); // exactly errored_refresh_ms - the ">=" boundary
    r->file = read_unknown<FileSnapshot>("enodev"); // the reason CHANGED mid-episode
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].domain == OutboxDomain::Health);
    REQUIRE_FALSE(got[0].healthy);
    // The refresh re-surfaces the CURRENT reason - unlike a merely-suppressed tick, this is
    // the retired staleness trade (build_entries doc): a changed error is not silently held
    // back until recovery.
    REQUIRE(got[0].health_detail == "enodev");
    REQUIRE(rt->unhealthy_refreshed() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 0);
}

TEST_CASE("M1 refresh: errored_refresh_ms=0 disables refresh - stays edge-only (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.errored_refresh_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(10'000'000); // arbitrarily far past any real cadence
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty()); // still nothing - refresh is OFF
    REQUIRE(rt->unhealthy_suppressed() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);
}

TEST_CASE("M1 refresh: suppressed and refreshed partition every committed repeat-Unknown, "
          "keyed off the LAST emission not the original edge (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(100'000); // t=100s: < 300s since the edge
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 1);

    sc.advance(100'000); // t=200s: still < 300s since the edge
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 2);

    sc.advance(150'000); // t=350s: >= 300s since the edge -> refresh
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 2); // unchanged by the refresh

    sc.advance(50'000); // t=400s: only 50s since the REFRESH (not 400s since the edge)
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty()); // too soon since the LAST emission -> suppressed again
    REQUIRE(rt->unhealthy_suppressed() == 3);
    REQUIRE(rt->unhealthy_refreshed() == 1);
}

TEST_CASE("M1 refresh: two rules sharing one key each refresh independently, per-rule not "
          "per-key (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // both edge
    REQUIRE(drain_all(*rt).size() == 2);

    sc.advance(300'000);
    r->file = read_unknown<FileSnapshot>("io2");
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 2); // BOTH refresh, not one per key
    for (const auto& e : got) {
        REQUIRE(e.domain == OutboxDomain::Health);
        REQUIRE(e.health_detail == "io2");
    }
    REQUIRE(rt->unhealthy_refreshed() == 2);
}

TEST_CASE("M1 refresh: rejected at outbox cap is retried, never counted (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto kc = spark_key(file_spec("/c"));
    rt->attach_rule("rc", file_spec("/c"), file_exists_rule("rc"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(kc, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(300'000); // rc's next Unknown is refresh-due

    // Fill the outbox with two unrelated drifts (r->file must read KNOWN for these).
    r->file = read_known(FileSnapshot{.exists = true});
    rt->attach_rule("r1", file_spec("/x"), file_exists_rule("r1", /*present=*/false), true);
    rt->attach_rule("r2", file_spec("/y"), file_exists_rule("r2", /*present=*/false), true);
    rt->evaluate_key(spark_key(file_spec("/x")), EvalReason::Initial);
    rt->evaluate_key(spark_key(file_spec("/y")), EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);

    // rc's refresh is due but the outbox is full: rejected, nothing commits, not counted.
    r->file = read_unknown<FileSnapshot>("io2");
    rt->evaluate_key(kc, EvalReason::Convergence);
    REQUIRE(rt->outbox_size() == 2);
    REQUIRE(rt->unhealthy_refreshed() == 0);
    REQUIRE(rt->unhealthy_suppressed() == 0); // not suppressed either - it will retry, not lose

    // Free a slot; the STILL-due refresh re-attempts and lands (last_unhealthy_emit was never
    // advanced by the rejected attempt, so it is STILL past the interval).
    drain_all(*rt);
    rt->evaluate_key(kc, EvalReason::Convergence);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].health_detail == "io2");
    REQUIRE(rt->unhealthy_refreshed() == 1);
}

TEST_CASE("M1 refresh: recovery after a refresh still emits guard.healthy and re-arms the "
          "edge (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(300'000);
    rt->evaluate_key(key, EvalReason::Event); // refresh
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 1);

    r->file = read_known(FileSnapshot{.exists = true}); // recovers
    rt->evaluate_key(key, EvalReason::Event);
    const auto recovered = drain_all(*rt);
    REQUIRE(std::any_of(recovered.begin(), recovered.end(), [](const OutboxEntry& e) {
        return e.domain == OutboxDomain::Health && e.healthy;
    }));

    // A FRESH errored episode re-arms the edge immediately (not gated on errored_refresh_ms -
    // the edge is the primary emission and always fires on the false->true transition).
    r->file = read_unknown<FileSnapshot>("io3");
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].health_detail == "io3");
    REQUIRE(rt->unhealthy_refreshed() == 1); // unchanged - that was an edge, not a refresh
    REQUIRE(rt->unhealthy_suppressed() == 0);
}

// --- F5 6c: priority-lane demotion -------------------------------------------------

TEST_CASE("M1 demotion: K consecutive committed Convergence-reason Unknown sweeps demote a "
          "still-pending rule off the priority lane (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 3;
    cfg.pending_demote_ms = 0; // isolate the sweep-count arm
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 2; ++i)
        rt->evaluate_key(key, EvalReason::Convergence); // sweeps 1 (edge) + 2
    REQUIRE(rt->pending_demoted_for_test(key).empty());
    REQUIRE(rt->priority_demoted() == 0);
    const auto before = rt->keys_with_pending_initial();
    REQUIRE(std::find(before.begin(), before.end(), key) != before.end());

    rt->evaluate_key(key, EvalReason::Convergence); // sweep 3 -> demote
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"});
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->keys_with_pending_initial().empty()); // off the priority worklist
    REQUIRE_FALSE(rt->pending_initial(key).empty());  // still "never Known" - membership unchanged
}

TEST_CASE("M1 demotion: elapsed time demotes even with sparse sweeps (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 0; // isolate the elapsed-time arm
    cfg.pending_demote_ms = 120'000;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // first_seen @ t=0
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence); // t=0: not yet
    REQUIRE(rt->priority_demoted() == 0);

    sc.advance(120'000); // t=120s
    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"});
}

TEST_CASE("M1 demotion: Event-reason evals never advance the sweep counter (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 1; // would demote on the very first COUNTED sweep
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 5; ++i)
        rt->evaluate_key(key, EvalReason::Event); // never Convergence
    REQUIRE(rt->priority_demoted() == 0);
    REQUIRE(rt->pending_demoted_for_test(key).empty());

    rt->evaluate_key(key, EvalReason::Convergence); // the FIRST counted sweep
    REQUIRE(rt->priority_demoted() == 1);
}

TEST_CASE("M1 demotion: a Known verdict before K sweeps clears pending_initial normally, "
          "without demoting (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 5;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 2; ++i)
        rt->evaluate_key(key, EvalReason::Convergence); // sweeps 1+2, well below K=5

    r->file = read_known(FileSnapshot{.exists = true}); // recovers to compliant -> Known
    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->pending_initial(key).empty()); // ordinary erase-on-Known
    REQUIRE(rt->priority_demoted() == 0);
}

TEST_CASE("M1 demotion: a demoted key still converges via its type lane and a later Known "
          "eval erases + emits recovery (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 1;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence); // K=1: demotes on the very first sweep
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->keys_with_pending_initial().empty()); // off the priority lane

    // The scheduler's type lane (keys_for_type()) is unfiltered by demotion - drive that
    // same call directly, as guardian_convergence_scheduler.cpp's sweep_lane() would.
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Convergence);
    const auto got = drain_all(*rt);
    REQUIRE(std::any_of(got.begin(), got.end(), [](const OutboxEntry& e) {
        return e.domain == OutboxDomain::Health && e.healthy;
    }));
    REQUIRE(rt->pending_initial(key).empty()); // Known -> erased; demotion is moot now
}

TEST_CASE("M1 demotion: re-attaching a rule resets its demotion state (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 1;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->keys_with_pending_initial().empty());

    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // fresh generation
    const auto after = rt->keys_with_pending_initial();
    REQUIRE(std::find(after.begin(), after.end(), key) != after.end()); // back on the priority lane
    REQUIRE(rt->pending_demoted_for_test(key).empty());
}

TEST_CASE("M1 demotion: pending_demote_sweeps=0 and pending_demote_ms=0 each disable their "
          "arm - never demote-on-first-Unknown (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 0;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 20; ++i) {
        rt->evaluate_key(key, EvalReason::Convergence);
        sc.advance(1'000'000); // also exercises the elapsed-time arm being off
    }
    REQUIRE(rt->priority_demoted() == 0);
    REQUIRE(rt->pending_demoted_for_test(key).empty());
    const auto still = rt->keys_with_pending_initial();
    REQUIRE(std::find(still.begin(), still.end(), key) != still.end());
}

TEST_CASE("M1 demotion: a mixed demoted/non-demoted pending set on one key keeps the key on "
          "the priority worklist (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 2;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence); // r1 sweep 1
    rt->evaluate_key(key, EvalReason::Convergence); // r1 sweep 2 -> demote
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"});
    REQUIRE(rt->keys_with_pending_initial().empty()); // sole pending rule demoted -> key off

    // A fresh sibling on the SAME key (the watcher already exists - shared-watcher branch).
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    const auto mixed = rt->keys_with_pending_initial();
    REQUIRE(std::find(mixed.begin(), mixed.end(), key) != mixed.end()); // back on the worklist
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"}); // r2 not demoted
    const auto pend = rt->pending_initial(key);
    REQUIRE(std::find(pend.begin(), pend.end(), "r1") != pend.end()); // still a member
    REQUIRE(std::find(pend.begin(), pend.end(), "r2") != pend.end());

    // Sweeping again advances ONLY r2's counter - r1 is frozen once demoted (guarded by
    // !pit->second.demoted before incrementing).
    rt->evaluate_key(key, EvalReason::Convergence); // r2 sweep 1
    REQUIRE(rt->priority_demoted() == 1);           // still just r1
    rt->evaluate_key(key, EvalReason::Convergence); // r2 sweep 2 -> demote
    REQUIRE(rt->priority_demoted() == 2);
    REQUIRE(rt->keys_with_pending_initial().empty()); // both demoted now -> key fully off
}

// --- #2992: M1 backstops can be permanently starved for the rules they protect ---
//
// Before the fix below, both M1 mitigations (errored-refresh 6b, priority-lane
// demotion 6c) made their commit decisions inside evaluate_key's commit section,
// gated behind the pre-existing `!accepted -> continue` (outbox full) and, for 6c,
// behind `reason == EvalReason::Convergence`. These four cases pin two distinct ways
// that previously left 6c unreachable for exactly the rules it exists to protect:
// (1) a rule whose every pass was rejected at the outbox cap never reached the
// demotion block at all (it sat above the `continue`), so it retried the identical
// read at priority-lane cadence forever; (2) the elapsed-time arm was evaluated only
// inside the Convergence-reason branch, so a key driven by Event-reason evals alone
// never demoted no matter how much time passed. At HEAD, demotion runs on the read
// outcome ahead of the enqueue accept/reject decision (#2992's fix), so both are
// reachable. Each case asserts the STUCK state first (true both before and after the
// fix, proving the scenario is real and that nothing was lost) and the PROGRESS state
// second (red on origin/dev, green after the fix hoists the demotion bookkeeping above
// the accept check and decouples time_due from the Convergence-reason gate).

TEST_CASE("M1 demotion: chronically-full outbox, sweep arm still demotes (#2992 CH-1a)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor
    cfg.pending_demote_sweeps = 3;
    cfg.pending_demote_ms = 0; // isolate the sweep arm under rejection
    auto rt = make_rt_with_clock(r, b, sc, cfg);

    // Fill the outbox with two unrelated drifts so rc's own entries are never NEW keys
    // the cap has room for.
    rt->attach_rule("r1", file_spec("/x"), file_exists_rule("r1", /*present=*/false), true);
    rt->attach_rule("r2", file_spec("/y"), file_exists_rule("r2", /*present=*/false), true);
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(spark_key(file_spec("/x")), EvalReason::Initial);
    rt->evaluate_key(spark_key(file_spec("/y")), EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);

    const auto kc = spark_key(file_spec("/c"));
    rt->attach_rule("rc", file_spec("/c"), file_exists_rule("rc", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io");

    const int reads_before = r->reads.load();
    const auto drops_before = rt->outbox_backpressure_drops();

    // Sweeps 1-2: below the sweep_due threshold, still fully stuck.
    for (int i = 0; i < 2; ++i) {
        sc.advance(5'000);
        rt->evaluate_key(kc, EvalReason::Convergence);
    }
    CHECK(rt->outbox_size() == 2);
    CHECK(rt->status_for_rule("rc")->in_unknown == false); // edge still owed - nothing committed
    CHECK(rt->pending_initial(kc) == std::vector<std::string>{"rc"});
    CHECK(rt->unhealthy_suppressed() == 0);
    CHECK(rt->unhealthy_refreshed() == 0);
    CHECK(rt->priority_demoted() == 0); // 2 sweeps < 3, arm not due yet

    // Sweep 3: RED on origin/dev - the rejected-enqueue `continue` sits above the
    // demotion block, so the counter never even advances, let alone crosses 3.
    sc.advance(5'000);
    rt->evaluate_key(kc, EvalReason::Convergence);
    CHECK(rt->priority_demoted() == 1);
    CHECK(rt->pending_demoted_for_test(kc) == std::vector<std::string>{"rc"});
    const auto worklist = rt->keys_with_pending_initial();
    CHECK(std::find(worklist.begin(), worklist.end(), kc) == worklist.end());

    // Sweeps 4-20: no double count, and the outbox/edge state is still untouched.
    for (int i = 0; i < 17; ++i) {
        sc.advance(5'000);
        rt->evaluate_key(kc, EvalReason::Convergence);
    }
    CHECK(rt->priority_demoted() == 1);
    CHECK(rt->outbox_size() == 2);
    CHECK(rt->outbox_backpressure_drops() - drops_before == 20);
    CHECK(r->reads.load() - reads_before == 20);
    CHECK(rt->status_for_rule("rc")->in_unknown == false);
    CHECK(rt->unhealthy_suppressed() == 0);
    CHECK(rt->unhealthy_refreshed() == 0);

    // The edge is not lost: draining frees a slot and the still-first edge lands.
    drain_all(*rt);
    rt->evaluate_key(kc, EvalReason::Convergence);
    const auto edge = drain_all(*rt);
    REQUIRE(edge.size() == 1);
    CHECK(edge[0].domain == OutboxDomain::Health);
    CHECK(edge[0].healthy == false);
    CHECK(edge[0].health_detail == "io");
    CHECK(rt->status_for_rule("rc")->in_unknown == true);
    CHECK(rt->unhealthy_suppressed() == 0);

    // 6b starts post-drain, exactly as it does today.
    sc.advance(300'000);
    rt->evaluate_key(kc, EvalReason::Convergence);
    CHECK(rt->unhealthy_refreshed() == 1);
}

TEST_CASE("M1 demotion: chronically-full outbox, elapsed-time arm still demotes "
          "(#2992 CH-1a-time)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2;       // the floor
    cfg.pending_demote_sweeps = 0; // isolate the elapsed-time arm
    cfg.pending_demote_ms = 120'000;
    auto rt = make_rt_with_clock(r, b, sc, cfg);

    rt->attach_rule("r1", file_spec("/x"), file_exists_rule("r1", /*present=*/false), true);
    rt->attach_rule("r2", file_spec("/y"), file_exists_rule("r2", /*present=*/false), true);
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(spark_key(file_spec("/x")), EvalReason::Initial);
    rt->evaluate_key(spark_key(file_spec("/y")), EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);

    const auto kc = spark_key(file_spec("/c"));
    rt->attach_rule("rc", file_spec("/c"), file_exists_rule("rc", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io");

    sc.advance(119'999);
    rt->evaluate_key(kc, EvalReason::Convergence);
    CHECK(rt->outbox_size() == 2);
    CHECK(rt->status_for_rule("rc")->in_unknown == false);
    CHECK(rt->priority_demoted() == 0); // not yet 120s since first_seen

    // now - first_seen == 120'000: RED on origin/dev, same shape as CH-1a - the
    // rejected-enqueue `continue` sits above the demotion block regardless of what
    // gates time_due inside it.
    sc.advance(1);
    rt->evaluate_key(kc, EvalReason::Convergence);
    CHECK(rt->priority_demoted() == 1);
    CHECK(rt->pending_demoted_for_test(kc) == std::vector<std::string>{"rc"});
    const auto worklist = rt->keys_with_pending_initial();
    CHECK(std::find(worklist.begin(), worklist.end(), kc) == worklist.end());

    CHECK(rt->outbox_size() == 2); // still nothing landed on the wire
    CHECK(rt->unhealthy_suppressed() == 0);
    CHECK(rt->unhealthy_refreshed() == 0);
}

TEST_CASE("M1 demotion: Event-only passes still demote on elapsed time (#2992 CH-2)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 0; // isolate the elapsed-time arm
    cfg.pending_demote_ms = 120'000;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Event); // edge @ t=0, commits normally
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(60'000);
    rt->evaluate_key(key, EvalReason::Event); // repeat Unknown, suppressed, commits
    CHECK(rt->unhealthy_suppressed() == 1);
    CHECK(rt->priority_demoted() == 0); // not yet 120s

    // now - first_seen == 120'000: RED on origin/dev - time_due is only ever evaluated
    // inside the `reason == EvalReason::Convergence` branch, so an Event-reason pass
    // never reaches it no matter how much time has elapsed.
    sc.advance(60'000);
    rt->evaluate_key(key, EvalReason::Event);
    CHECK(rt->unhealthy_suppressed() == 2); // Event path's commit semantics unchanged
    CHECK(rt->priority_demoted() == 1);
    CHECK(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"});
    CHECK(rt->keys_with_pending_initial().empty());

    // A later Convergence pass does not double-count.
    rt->evaluate_key(key, EvalReason::Convergence);
    CHECK(rt->priority_demoted() == 1);
}

TEST_CASE("M1 demotion: chronically-full outbox + Event-only passes, elapsed-time arm "
          "(#2992 combined)",
          "[spark][runtime]") {
    // Discriminates "moved above the accept check" from "moved out of the Convergence
    // gate": fixing only one half leaves this stuck (the rejected pass never reaches the
    // demotion block at all, so an Event-only reason never even gets a chance to matter).
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2;       // the floor
    cfg.pending_demote_sweeps = 0; // isolate the elapsed-time arm
    cfg.pending_demote_ms = 120'000;
    auto rt = make_rt_with_clock(r, b, sc, cfg);

    rt->attach_rule("r1", file_spec("/x"), file_exists_rule("r1", /*present=*/false), true);
    rt->attach_rule("r2", file_spec("/y"), file_exists_rule("r2", /*present=*/false), true);
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(spark_key(file_spec("/x")), EvalReason::Initial);
    rt->evaluate_key(spark_key(file_spec("/y")), EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);

    const auto kc = spark_key(file_spec("/c"));
    rt->attach_rule("rc", file_spec("/c"), file_exists_rule("rc", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(kc, EvalReason::Event); // t=0, rejected
    CHECK(rt->outbox_size() == 2);
    CHECK(rt->status_for_rule("rc")->in_unknown == false);
    CHECK(rt->priority_demoted() == 0);

    sc.advance(60'000);
    rt->evaluate_key(kc, EvalReason::Event); // t=60s, rejected
    CHECK(rt->outbox_size() == 2);
    CHECK(rt->status_for_rule("rc")->in_unknown == false);
    CHECK(rt->priority_demoted() == 0);

    // t=120s, rejected: RED on origin/dev under either half of the fix alone.
    sc.advance(60'000);
    rt->evaluate_key(kc, EvalReason::Event);
    CHECK(rt->priority_demoted() == 1);
    CHECK(rt->pending_demoted_for_test(kc) == std::vector<std::string>{"rc"});
    const auto worklist = rt->keys_with_pending_initial();
    CHECK(std::find(worklist.begin(), worklist.end(), kc) == worklist.end());

    CHECK(rt->outbox_size() == 2); // still nothing landed on the wire
    CHECK(rt->status_for_rule("rc")->in_unknown == false);
    CHECK(rt->unhealthy_suppressed() == 0);
    CHECK(rt->unhealthy_refreshed() == 0);
}

// --- F11: flood measurement, production defaults (#2298) --------------------------
//
// These three cases drive the F5 6b/6c mechanisms end-to-end at PRODUCTION DEFAULT
// Config (unlike the 6b/6c tests above, which mostly override pending_demote_sweeps/ms
// to isolate one arm) to establish the wire-flood ceiling the F11 run doc
// (docs/spark-rebuild-baselines/f11-flood-measurement-run.md) reports, replacing the
// stale pre-F5 ~17k/day extrapolation in docs/spark-stage2-guardian-consumer-design.md.
// A test drives cadence by an explicit clock advance per simulated scheduler tick
// (5s priority lane, 60s/600s type lanes) since GuardianConvergenceScheduler itself
// received zero code change from F5 (docs/spark-stage2-guardian-consumer-design.md:283)
// - the real per-lane tick spacing is the scheduler's job, reproduced here by hand.

TEST_CASE("F11 flood: production-default demotion completes in 12 sweeps @ 5s (60s) - "
          "before any refresh could fire (#2298)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc); // production defaults: 12 sweeps, 120s, 300s refresh
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge - never-Known, priority lane
    REQUIRE(drain_all(*rt).size() == 1);

    int sweeps = 0;
    while (rt->priority_demoted() == 0) {
        sc.advance(5'000); // the 5s priority-lane cadence (guardian_convergence_scheduler.hpp:72)
        rt->evaluate_key(key, EvalReason::Convergence);
        REQUIRE(drain_all(*rt).empty()); // pre-demotion: every sweep suppressed, none refresh
        ++sweeps;
    }
    CHECK(sweeps == 12); // pending_demote_sweeps default (guardian_spark_runtime.hpp:178)
    CHECK(rt->unhealthy_suppressed() == 12);
    CHECK(rt->unhealthy_refreshed() == 0); // demotion (60s) completes well inside the 300s floor
}

TEST_CASE("F11 flood: post-demotion 60s-cadence lane (service/registry) refreshes exactly "
          "every errored_refresh_ms, first landing at t=300s (#2298)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    while (rt->priority_demoted() == 0) { // demote at t=60s, as the prior case establishes
        sc.advance(5'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    REQUIRE(rt->priority_demoted() == 1);

    // Now on the 60s type-lane cadence. 14 ticks reaches t=60s+14*60s=900s, spanning
    // three 300s refresh boundaries (t=300s, 600s, 900s) - refreshed is keyed off the
    // LAST emission (the edge at t=0 initially), not re-armed by demotion.
    for (int i = 1; i <= 3; ++i) {
        sc.advance(60'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    CHECK(rt->unhealthy_refreshed() == 0); // t=240s: still short of the 300s floor
    sc.advance(60'000); // t=300s: exactly the boundary
    rt->evaluate_key(key, EvalReason::Convergence);
    drain_all(*rt);
    CHECK(rt->unhealthy_refreshed() == 1);
    for (int i = 1; i <= 10; ++i) { // t=360s..900s: two more 300s boundaries at 600s, 900s
        sc.advance(60'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    CHECK(rt->unhealthy_refreshed() == 3);
    // Steady-state projection (arithmetic on the measured 300s period, not a fresh
    // 24h loop - 300s divides 86400s evenly): 288 refreshes/day + 1 edge = 289 total
    // guard.unhealthy wire messages/rule/agent/day on this lane - see the F11 run doc.
}

TEST_CASE("F11 flood: post-demotion 600s-cadence lane (file) refreshes on EVERY sweep, "
          "since its cadence already exceeds errored_refresh_ms (#2298)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    while (rt->priority_demoted() == 0) { // demote at t=60s
        sc.advance(5'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);

    // First post-demotion file-lane sweep: t=60s+600s=660s, already >=300s since the
    // t=0 edge - refreshes immediately, no suppression window at all on this lane.
    sc.advance(600'000);
    rt->evaluate_key(key, EvalReason::Convergence);
    CHECK(drain_all(*rt).size() == 1);
    CHECK(rt->unhealthy_refreshed() == 1);
    CHECK(rt->unhealthy_suppressed() == 12); // unchanged since demotion - never suppressed here

    sc.advance(600'000); // t=1260s
    rt->evaluate_key(key, EvalReason::Convergence);
    CHECK(drain_all(*rt).size() == 1);
    CHECK(rt->unhealthy_refreshed() == 2);
    // At EXACT 600s cadence (no scheduler jitter): 144 refreshes/day + 1 edge = 145
    // total wire messages/rule/agent/day on this lane (86400s/600s = 144 sweeps/day,
    // every one refreshes). This is the NOMINAL figure, not the production ceiling -
    // see the next case for the jittered worst-case, and the F11 run doc for both.
}

TEST_CASE("F11 flood: file lane at the scheduler-jitter floor (480s) still refreshes "
          "every sweep - the TRUE production worst-case ceiling is 180/day, not the "
          "144/day no-jitter figure (#2298, adversarial-review finding)",
          "[spark][runtime]") {
    // ConvergenceScheduler::Config defaults file_cadence_ms=600'000, jitter_pct=20
    // (guardian_convergence_scheduler.hpp:69-73); jittered() draws base_ms +
    // uniform(-span, +span) with span = base_ms*jitter_pct/100 = 120'000
    // (guardian_convergence_scheduler.cpp:59-69) - a SYMMETRIC perturbation, not the
    // later-only skew the run doc originally (incorrectly) claimed. The minimum
    // possible single-draw interval is therefore 600'000-120'000=480'000ms: still
    // above the 300s errored_refresh_ms floor, so every such sweep still refreshes,
    // same as the exact-600s case - but at up to 86400/480=180 refreshes/day, not 144.
    // This case proves that boundary empirically rather than asserting the arithmetic.
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    while (rt->priority_demoted() == 0) { // demote at t=60s
        sc.advance(5'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);

    // Three consecutive sweeps at the jitter-floor 480s interval: every one refreshes
    // (480s > 300s), proving jitter cannot suppress a file-lane refresh - it can only
    // make them MORE frequent than the no-jitter 144/day figure, up to 180/day.
    for (std::uint64_t i = 1; i <= 3; ++i) {
        sc.advance(480'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        CHECK(drain_all(*rt).size() == 1);
        CHECK(rt->unhealthy_refreshed() == i);
    }
    CHECK(rt->unhealthy_suppressed() == 12); // unchanged - still never suppressed on this lane
    // Ceiling: 86'400s / 480s = 180 refreshes/day + 1 edge = 181 total wire
    // messages/rule/agent/day - the honest production worst-case, not 144. See the
    // F11 run doc's corrected Claims section.
}

TEST_CASE("on_event after begin_stop commits nothing", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(r->stops.load() == 0);
    rt->begin_stop();
    REQUIRE(rt->stopping());
    CHECK(r->stops.load() == 1); // begin_stop() -> reader_->request_stop(), exactly once
    rt->on_event(SparkEvent{.key = key, .type = SparkType::File});
    REQUIRE(rt->outbox_size() == 0); // stopping -> no commit
}

TEST_CASE("a detached in-flight handler is memory-safe even after the reader ref is dropped",
          "[spark][runtime]") {
    // The runtime OWNS the reader, so keeping the runtime alive (via the handler's
    // captured shared_ptr) keeps the reader alive too. We drop BOTH the test's reader
    // ref and the runtime ref while a handler is mid-read; the detached thread must
    // still finish safely. Under the old borrowed-reference design this destroyed the
    // reader out from under the in-flight read (ASan use-after-free).
    auto reader = std::make_shared<FakeReader>();
    auto backend = std::make_shared<FakeBackend>();
    std::latch reading{1};
    std::latch release{1};
    reader->on_read = [&] {
        reading.count_down();
        release.wait();
    };
    auto rt = std::make_shared<GuardianSparkRuntime>(reader, backend);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    auto handler = GuardianSparkRuntime::make_handler(rt);
    std::thread t([handler, key] { handler(SparkEvent{.key = key, .type = SparkType::File}); });

    reading.wait();  // the pass is inside read(); the runtime (owning the reader) is alive via `handler`
    reader.reset();  // drop the test's reader ref: only the runtime co-owns it now
    rt.reset();      // drop the test's runtime ref: only the detached handler owns it
    release.count_down();
    t.join(); // read finished, verdict committed, reader still alive: no UAF
    SUCCEED();
}

TEST_CASE("two registry rules under one key each read their OWN value_name", "[spark][runtime]") {
    // Rules watching different values under one (hive,key) share ONE spark_key/watcher.
    // The read plan requests both value_names; each rule evaluates against ITS value -
    // reading one snapshot and fanning it to both would give a wrong verdict.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    r->reg_values["A"] = read_known(RegistrySnapshot{.present = true, .value = "1"}); // r1 compliant
    r->reg_values["B"] = read_known(RegistrySnapshot{.present = true, .value = "9"}); // r2 drifts vs "2"
    auto rt = make_rt(r, b);
    const auto key = spark_key(reg_spec("HKLM", "Software\\X"));
    rt->attach_rule("r1", reg_spec("HKLM", "Software\\X"), registry_rule("r1", "A", "1"), true);
    rt->attach_rule("r2", reg_spec("HKLM", "Software\\X"), registry_rule("r2", "B", "2"), true);
    REQUIRE(rt->armed_key_count() == 1); // one shared watcher
    REQUIRE(b->arms.load() == 1);

    rt->evaluate_key(key, EvalReason::Initial);
    auto g = drain_all(*rt);
    REQUIRE(g.size() == 2);
    std::sort(g.begin(), g.end(),
              [](const OutboxEntry& a, const OutboxEntry& c) { return a.rule_id < c.rule_id; });
    REQUIRE(g[0].rule_id == "r1");
    REQUIRE(g[0].drift.compliant); // A == "1"
    REQUIRE(g[1].rule_id == "r2");
    REQUIRE_FALSE(g[1].drift.compliant); // B == "9" != "2"
    REQUIRE(g[1].drift.detected_value == "9");
}

TEST_CASE("two rules watching the SAME registry value dedup the read plan", "[spark][runtime]") {
    // The read plan promises DISTINCT value_names; a rung-5 reader relies on that to
    // avoid redundant OS reads. Two rules on the same value must produce one entry.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    r->reg_values["A"] = read_known(RegistrySnapshot{.present = true, .value = "1"});
    auto rt = make_rt(r, b);
    const auto key = spark_key(reg_spec("HKLM", "Software\\X"));
    rt->attach_rule("r1", reg_spec("HKLM", "Software\\X"), registry_rule("r1", "A", "1"), true);
    rt->attach_rule("r2", reg_spec("HKLM", "Software\\X"), registry_rule("r2", "A", "1"), true);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(r->last_reg_plan_size.load() == 1); // deduped: value A read once, not twice
    REQUIRE(drain_all(*rt).size() == 2);        // both rules still evaluated
}

TEST_CASE("the file read plan uses the largest hash cap among the key's rules", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    RuleAssertion small = file_exists_rule("r1"); // file-exists: no hash
    small.kind = AssertionKind::FileHashEquals;
    small.expected_hash = "h";
    small.max_bytes = 100;
    RuleAssertion big = small;
    big.rule_id = "r2";
    big.max_bytes = 5000;
    rt->attach_rule("r1", file_spec("/a"), small, true);
    rt->attach_rule("r2", file_spec("/a"), big, true);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(r->last_hash_cap.load() == 5000); // hashed once at the largest admitting cap
}

TEST_CASE("a rule that joins mid-read is NOT committed against the stale snapshot",
          "[spark][runtime]") {
    // F2+F4: the pass snapshots its plan+gens before I/O and commits only those. A
    // sibling rule that attaches while the read is in flight is not in the plan, so it
    // is not evaluated against a snapshot that predates it - it stays dirty and the
    // priority lane will run it next. (The old post-read fan-out evaluated it here.)
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    std::latch reading{1};
    std::latch release{1};
    r->on_read = [&] {
        reading.count_down();
        release.wait();
    };
    std::thread t([&] { rt->evaluate_key(key, EvalReason::Initial); });
    reading.wait(); // r1's read is in flight; the plan was snapshotted with only r1

    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); // joins mid-read
    release.count_down();
    t.join();

    // r1 was in the plan -> committed + cleared; r2 joined after -> still pending.
    REQUIRE(rt->pending_initial(key) == std::vector<std::string>{"r2"});
    const auto g = drain_all(*rt);
    REQUIRE(g.size() == 1); // only r1's verdict, not r2's
    REQUIRE(g[0].rule_id == "r1");
}

TEST_CASE("Unknown->Known recovery emits guard.healthy even when the verdict is Silent",
          "[spark][runtime]") {
    // The systemd worst case: emit_compliant_edge=false, so a recovery to steady
    // compliant is a Silent verdict. Without a health-recovery emit the health stream
    // would stay unhealthy forever. Assert guard.healthy IS emitted on recovery.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(svc_spec("nginx"));
    rt->attach_rule("s1", svc_spec("nginx"), svc_running_rule("s1"), /*emit_compliant_edge=*/false);

    r->svc = read_known(ServiceRunState::Running);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 0); // systemd compliant edge is Silent

    r->svc = read_unknown<ServiceRunState>("scm timeout");
    rt->evaluate_key(key, EvalReason::Event);
    auto g = drain_all(*rt);
    REQUIRE(g.size() == 1);
    REQUIRE(g[0].domain == OutboxDomain::Health);
    REQUIRE_FALSE(g[0].healthy);

    r->svc = read_known(ServiceRunState::Running); // recovery to steady compliant
    rt->evaluate_key(key, EvalReason::Convergence);
    g = drain_all(*rt);
    REQUIRE(g.size() == 1);
    REQUIRE(g[0].domain == OutboxDomain::Health);
    REQUIRE(g[0].healthy); // the recovery signal that was previously never sent
}

TEST_CASE("recovery to a drifted state emits BOTH guard.healthy and the drift verdict",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("f1", file_spec("/a"), file_exists_rule("f1", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io"); // errored
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1); // health(false)

    r->file = read_known(FileSnapshot{.exists = false}); // recovery, but now drifted
    rt->evaluate_key(key, EvalReason::Event);
    const auto g = drain_all(*rt);
    REQUIRE(g.size() == 2); // health(true) + the drift, landed atomically
    REQUIRE(g[0].domain == OutboxDomain::Health);
    REQUIRE(g[0].healthy);
    REQUIRE(g[1].domain == OutboxDomain::Compliance);
    REQUIRE_FALSE(g[1].drift.compliant);
}

TEST_CASE("#4606 criterion-10: a two-entry build_entries pass stages two timing records "
          "sharing one detect timestamp with distinct event_ids",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("f1", file_spec("/a"), file_exists_rule("f1", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io"); // errored
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1); // health(false)

    r->file = read_known(FileSnapshot{.exists = false}); // recovery, but now drifted
    const auto mono_before_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch())
                                    .count();
    rt->evaluate_key(key, EvalReason::Event);
    const auto mono_after_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count();
    REQUIRE(drain_all(*rt).size() == 2); // health(true) + the drift, landed atomically

    const auto timings = rt->last_eval_timings_for_test();
    REQUIRE(timings.size() == 2);
    // Both stamps are REAL steady_clock reads (the injected make_rt clock is a small synthetic
    // time_point that would fall outside this bracket), taken inside the evaluate_key call.
    for (const auto& t : timings) {
        CHECK(t.detect_mono_ns >= mono_before_ns);
        CHECK(t.detect_mono_ns <= t.fire_mono_ns);
        CHECK(t.fire_mono_ns <= mono_after_ns);
    }
    CHECK(timings[0].detect_wall_ns == timings[1].detect_wall_ns);
    CHECK(timings[0].detect_mono_ns == timings[1].detect_mono_ns);
    CHECK(timings[0].detect_wall_ns != 0);
    CHECK(timings[0].event_id != timings[1].event_id);
    CHECK(timings[0].accepted);
    CHECK(timings[1].accepted);
    CHECK(timings[0].fire_wall_ns == timings[1].fire_wall_ns); // one backfill pass, same instant
    // T_fire is the measurement itself: an ACCEPTED record's fire_* must actually be populated
    // (not left at the -1 "never fired" sentinel) and must not precede its own detect stamp.
    // The mono pair uses steady_clock so the ordering check is immune to a wall-clock step.
    CHECK(timings[0].fire_wall_ns != -1);
    CHECK(timings[0].fire_mono_ns != -1);
    CHECK(timings[1].fire_mono_ns != -1);
    CHECK(timings[0].fire_mono_ns >= timings[0].detect_mono_ns);
    CHECK(timings[1].fire_mono_ns >= timings[1].detect_mono_ns);
    CHECK_FALSE(timings[0].trigger.has_value()); // evaluate_key called directly, no trigger arg
    CHECK_FALSE(timings[1].trigger.has_value());
}

TEST_CASE("#4606 criterion-10: a failure while staging timing records never drops the event",
          "[spark][runtime]") {
    // The timing bookkeeping runs BEFORE the real enqueue inside evaluate_key. It must be
    // best-effort: if it cannot allocate, the pass loses its timing lines, never its outbox entry
    // (and never throws out of evaluate_key, which would also skip the drain-worker wake).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("f1", file_spec("/a"), file_exists_rule("f1", /*present=*/true), true);

    rt->fail_timing_stage_at_for_test(0); // fail on the very first record
    r->file = read_unknown<FileSnapshot>("io"); // errored -> one health entry
    REQUIRE_NOTHROW(rt->evaluate_key(key, EvalReason::Initial));
    CHECK(drain_all(*rt).size() == 1);                // the event was still enqueued
    CHECK(rt->last_eval_timings_for_test().empty());  // only the timing was dropped

    // With the seam off the same pass shape stages its timing again, so the empty result above
    // was the seam, not a broken accessor.
    rt->fail_timing_stage_at_for_test(-1);
    r->file = read_known(FileSnapshot{.exists = false}); // recovery, but now drifted
    rt->evaluate_key(key, EvalReason::Event);
    CHECK(drain_all(*rt).size() == 2);
    CHECK(rt->last_eval_timings_for_test().size() == 2);
}

TEST_CASE("#4606 criterion-10: a failure part-way through a rule's batch drops that whole batch's "
          "timing but never an event",
          "[spark][runtime]") {
    // One rule, two entries in one pass (recovery + drift). Failing on the SECOND record means the
    // first was already staged when the handler runs, so this is the case where the handler's
    // tail erase has something to erase: leaving the half-staged record would report a batch whose
    // second entry has no timing.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("f1", file_spec("/a"), file_exists_rule("f1", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io"); // errored
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1);

    rt->fail_timing_stage_at_for_test(1);
    r->file = read_known(FileSnapshot{.exists = false}); // recovery, but now drifted -> 2 entries
    REQUIRE_NOTHROW(rt->evaluate_key(key, EvalReason::Event));
    CHECK(drain_all(*rt).size() == 2);                // both events enqueued
    CHECK(rt->last_eval_timings_for_test().empty());  // the half-staged record was erased too
}

TEST_CASE("#4606 criterion-10: a staging failure for one rule keeps the timing of the rules before "
          "AND after it in the same pass",
          "[spark][runtime]") {
    // Three rules on one key each emit one entry in one pass. The seam is one-shot and fails the
    // second record: that rule's timing is dropped, the earlier rule's already-staged record
    // survives, and the LATER rule stages normally (a seam that re-fired after the erase would leave
    // only one record). All three events are still enqueued.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2", /*present=*/true), true);
    rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3", /*present=*/true), true);

    rt->fail_timing_stage_at_for_test(1);
    r->file = read_unknown<FileSnapshot>("io"); // all rules edge -> three health entries
    REQUIRE_NOTHROW(rt->evaluate_key(key, EvalReason::Initial));
    CHECK(drain_all(*rt).size() == 3);                   // every event enqueued
    CHECK(rt->last_eval_timings_for_test().size() == 2); // exactly the failing rule's timing dropped
}

TEST_CASE("#4606 criterion-10: a failure in the timing reserve() never drops the event",
          "[spark][runtime]") {
    // The reserve() runs before the registry commit. Its guard is a swallowed catch, so a failure
    // there must leave the pass enqueuing and still staging timing (the loop re-allocates on its
    // own); without the guard the exception would escape evaluate_key before any of that.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("f1", file_spec("/a"), file_exists_rule("f1", /*present=*/true), true);

    rt->fail_next_timing_reserve_for_test();
    r->file = read_unknown<FileSnapshot>("io"); // errored -> one health entry
    REQUIRE_NOTHROW(rt->evaluate_key(key, EvalReason::Initial));
    CHECK(drain_all(*rt).size() == 1);                   // the event was enqueued
    CHECK(rt->last_eval_timings_for_test().size() == 1); // and timing still staged (reserve is a hint)
}

TEST_CASE("#4606 criterion-10: format_eval_timing_line field order + absent-trigger sentinel "
          "contract (pure formatter, no runtime)",
          "[spark][runtime]") {
    EvalTimingRecord r;
    r.event_id = "evt-1";
    r.domain = OutboxDomain::Compliance;
    r.detect_wall_ns = 100;
    r.detect_mono_ns = 200;
    r.accepted = true;
    r.fire_wall_ns = 300;
    r.fire_mono_ns = 400;
    // trigger left absent (std::nullopt by default)

    const auto line_absent = format_eval_timing_line(r);
    // The exact line pins FIELD ORDER, which the substring checks below cannot: the header calls
    // it the parseable-log-line contract the benchmark tooling regexes against.
    CHECK(line_absent ==
          "Guardian T_detect event_id=evt-1 domain=compliance detect_wall_ns=100 "
          "detect_mono_ns=200 accepted=1 fire_wall_ns=300 fire_mono_ns=400 trigger_present=0 "
          "mechanism_wall_ns=-1 handler_wall_ns=-1 handler_mono_ns=-1 seq=-1");
    CHECK(line_absent.find("event_id=evt-1") != std::string::npos);
    CHECK(line_absent.find("domain=compliance") != std::string::npos);
    CHECK(line_absent.find("detect_wall_ns=100") != std::string::npos);
    CHECK(line_absent.find("detect_mono_ns=200") != std::string::npos);
    CHECK(line_absent.find("accepted=1") != std::string::npos);
    CHECK(line_absent.find("fire_wall_ns=300") != std::string::npos);
    CHECK(line_absent.find("fire_mono_ns=400") != std::string::npos);
    CHECK(line_absent.find("trigger_present=0") != std::string::npos);
    CHECK(line_absent.find("mechanism_wall_ns=-1") != std::string::npos);
    CHECK(line_absent.find("handler_wall_ns=-1") != std::string::npos);
    CHECK(line_absent.find("handler_mono_ns=-1") != std::string::npos);
    CHECK(line_absent.find("seq=-1") != std::string::npos);
    // "absent" must never render as a fabricated zero a benchmark parser could mistake
    // for "observed, zero-latency".
    CHECK(line_absent.find("mechanism_wall_ns=0") == std::string::npos);
    CHECK(line_absent.find("handler_wall_ns=0") == std::string::npos);
    CHECK(line_absent.find("handler_mono_ns=0") == std::string::npos);
    CHECK(line_absent.find("seq=0") == std::string::npos);

    EvalTrigger trig;
    trig.mechanism_wall_ns = 10;
    trig.handler_wall_ns = 20;
    trig.handler_mono_ns = 30;
    trig.seq = 7;
    r.trigger = trig;
    r.accepted = false;
    r.fire_wall_ns = -1;
    r.fire_mono_ns = -1;

    const auto line_present = format_eval_timing_line(r);
    CHECK(line_present ==
          "Guardian T_detect event_id=evt-1 domain=compliance detect_wall_ns=100 "
          "detect_mono_ns=200 accepted=0 fire_wall_ns=-1 fire_mono_ns=-1 trigger_present=1 "
          "mechanism_wall_ns=10 handler_wall_ns=20 handler_mono_ns=30 seq=7");
    CHECK(line_present.find("accepted=0") != std::string::npos);
    CHECK(line_present.find("fire_wall_ns=-1") != std::string::npos);
    CHECK(line_present.find("fire_mono_ns=-1") != std::string::npos);
    // A record never touched by the backfill (rejected enqueue) must default to the
    // sentinel, not to a fabricated 0.
    CHECK(EvalTimingRecord{}.fire_wall_ns == -1);
    CHECK(EvalTimingRecord{}.fire_mono_ns == -1);
    CHECK(line_present.find("trigger_present=1") != std::string::npos);
    CHECK(line_present.find("mechanism_wall_ns=10") != std::string::npos);
    CHECK(line_present.find("handler_wall_ns=20") != std::string::npos);
    CHECK(line_present.find("handler_mono_ns=30") != std::string::npos);
    CHECK(line_present.find("seq=7") != std::string::npos);
}

TEST_CASE("#4606 criterion-10: format_send_timing_line field order (pure formatter)",
          "[spark][runtime]") {
    SendTimingRecord r;
    r.event_id = "evt-9";
    r.sent = true;
    r.wire_wall_ns = 555;
    // domain left absent: the legacy drift-sink path has no outbox and so no OutboxDomain.
    const auto line = format_send_timing_line(r);
    CHECK(line.find("event_id=evt-9") != std::string::npos);
    CHECK(line.find("domain=legacy") != std::string::npos);
    CHECK(line.find("sent=1") != std::string::npos);
    CHECK(line.find("wire_wall_ns=555") != std::string::npos);
    // event_id stays the first field after the line-name token (correlator parse invariant),
    // and the exact line pins the full field order.
    CHECK(line.find("Guardian T_wire event_id=evt-9") == 0);
    CHECK(line == "Guardian T_wire event_id=evt-9 domain=legacy sent=1 wire_wall_ns=555");

    r.sent = false;
    const auto line2 = format_send_timing_line(r);
    CHECK(line2.find("sent=0") != std::string::npos);

    // Every Spark-outbox domain renders by name, so a Lifecycle journal replay (server answers
    // Redelivered, legitimately no T_server) is distinguishable from a lost Compliance/Health
    // event in the log alone.
    r.domain = OutboxDomain::Lifecycle;
    CHECK(format_send_timing_line(r).find("domain=lifecycle") != std::string::npos);
    r.domain = OutboxDomain::Compliance;
    CHECK(format_send_timing_line(r).find("domain=compliance") != std::string::npos);
    r.domain = OutboxDomain::Health;
    CHECK(format_send_timing_line(r).find("domain=health") != std::string::npos);
    CHECK(format_send_timing_line(r).find("domain=legacy") == std::string::npos);
}

TEST_CASE("#4606 criterion-10: make_outbox_send_timing carries the entry's event_id and domain",
          "[spark][runtime]") {
    // send_guardian_outbox_entry (agent.cpp) builds its T_wire record through this function.
    // AgentImpl is unreachable from a unit test, so this proves the HELPER carries event_id and
    // domain (a hard-coded or dropped domain fails here); that agent.cpp calls it, with the right
    // entry and outcome, is a single call site checked by reading it, not by a test.
    OutboxEntry lifecycle;
    lifecycle.domain = OutboxDomain::Lifecycle;
    lifecycle.event_id = "evt-life";
    const auto rec = make_outbox_send_timing(lifecycle, /*sent=*/true, 777);
    CHECK(rec.event_id == "evt-life");
    REQUIRE(rec.domain.has_value());
    CHECK(*rec.domain == OutboxDomain::Lifecycle);
    CHECK(rec.sent);
    CHECK(rec.wire_wall_ns == 777);
    CHECK(format_send_timing_line(rec) ==
          "Guardian T_wire event_id=evt-life domain=lifecycle sent=1 wire_wall_ns=777");

    OutboxEntry health;
    health.domain = OutboxDomain::Health;
    health.event_id = "evt-health";
    const auto rec2 = make_outbox_send_timing(health, /*sent=*/false, 5);
    REQUIRE(rec2.domain.has_value());
    CHECK(*rec2.domain == OutboxDomain::Health);
    CHECK_FALSE(rec2.sent);
    // A Spark-path record never renders as the legacy marker.
    CHECK(format_send_timing_line(rec2).find("domain=legacy") == std::string::npos);
}

TEST_CASE("#4606 criterion-10: an untrusted event id cannot forge a token or a line in the "
          "agent T_detect/T_wire output",
          "[spark][runtime]") {
    // The event id embeds the operator-authored rule id (any non-empty string is accepted at rule
    // creation), so it reaches these lines unvalidated. A newline would forge a whole physical
    // line and a space or '=' would forge extra key=value tokens that a first-match parser reads.
    const std::string hostile =
        "agent-1-r x=9\nGuardian T_wire event_id=victim domain=health sent=1 wire_wall_ns=1";
    const std::string neutral =
        "agent-1-r_x_9_Guardian_T_wire_event_id_victim_domain_health_sent_1_wire_wall_ns_1";
    auto count = [](const std::string& hay, const std::string& needle) {
        std::size_t n = 0;
        for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
            ++n;
        return n;
    };

    EvalTimingRecord e;
    e.event_id = hostile;
    e.domain = OutboxDomain::Compliance;
    const auto detect = format_eval_timing_line(e);
    CHECK(detect.find('\n') == std::string::npos);
    CHECK(detect.rfind("Guardian T_detect event_id=" + neutral + " domain=compliance ", 0) == 0);
    CHECK(count(detect, "event_id=") == 1);
    CHECK(count(detect, " domain=") == 1);
    CHECK(count(detect, "Guardian T_") == 1);

    SendTimingRecord w;
    w.event_id = hostile;
    w.domain = OutboxDomain::Health;
    w.sent = true;
    w.wire_wall_ns = 9;
    const auto wire = format_send_timing_line(w);
    CHECK(wire == "Guardian T_wire event_id=" + neutral + " domain=health sent=1 wire_wall_ns=9");
    CHECK(wire.find('\n') == std::string::npos);
    CHECK(count(wire, "event_id=") == 1);
    CHECK(count(wire, "Guardian T_") == 1);

    // Both lines shorten an over-long id with the SAME function the server's T_server line uses
    // (head, '~', last 24 bytes), so it still joins.
    const std::string longid(yuzu::kGuardianLogIdMaxBytes + 40, 'a');
    e.event_id = longid;
    w.event_id = longid;
    const std::string shortened =
        std::string(yuzu::kGuardianLogIdMaxBytes - yuzu::kGuardianLogIdTailBytes - 1, 'a') + "~" +
        std::string(yuzu::kGuardianLogIdTailBytes, 'a');
    CHECK(shortened.size() == yuzu::kGuardianLogIdMaxBytes);
    CHECK(format_eval_timing_line(e).rfind("Guardian T_detect event_id=" + shortened + " ", 0) == 0);
    CHECK(format_send_timing_line(w).rfind("Guardian T_wire event_id=" + shortened + " ", 0) == 0);

    // The tail (`<wall_ms>-<seq>`) survives, so two events of one very long rule id stay distinct.
    const std::string rule(300, 'r');
    e.event_id = rule + "-1789930557755-101";
    const auto first = format_eval_timing_line(e);
    e.event_id = rule + "-1789930557755-102";
    CHECK(format_eval_timing_line(e) != first);

    // A multi-byte character (here U+2028 LINE SEPARATOR, and a run of lone lead bytes) never
    // reaches the line: every byte outside printable ASCII becomes '_', so the output is ASCII
    // and cannot be split by a Unicode-aware consumer or made invalid UTF-8 by a cut (the exact
    // straddle of the head boundary is pinned in test_log_token.cpp).
    e.event_id = "a\xE2\x80\xA8" "b" + std::string(300, '\xC3');
    for (const char c : format_eval_timing_line(e))
        CHECK(static_cast<unsigned char>(c) < 0x80);
    w.event_id = "a\xE2\x80\xA8" "b";
    CHECK(format_send_timing_line(w) == "Guardian T_wire event_id=a___b domain=health sent=1 wire_wall_ns=9");
}

TEST_CASE("#4606 criterion-10: format_arm_committed_line keeps the #3990 driver's pinned shape and "
          "cannot be forged through the rule id",
          "[spark][runtime]") {
    // Formatter-only: the runtime's own spdlog output is not reliably capturable from a test (it
    // lives in libyuzu_agent_core, see test_log_capture.hpp), so nothing HERE pins that the call
    // sites in guardian_spark_runtime.cpp actually go through log_id_token/log_key_token. That gap
    // is now closed by a real, position-aware lexical scanner instead of "checked by reading" --
    // tests/test_guardian_spark_log_injection_tripwire.py (suite 'docs') fails the moment a NEW
    // spdlog:: call across the Guardian/Spark subsystem prints a rule-id/Spark-key-shaped argument
    // unwrapped, and it also recognises a direct call to format_arm_committed_line() itself as a
    // safe formatter (the wrap happens inside it, confirmed by reading the implementation).
    // A plain id renders byte-for-byte as it did before the id was neutralised: the #3990 driver's
    // T2_RE (docs/spark-rebuild-baselines/fullsync_blackout_diag.py) parses exactly this shape.
    // #4665: fixture-driven (tests/unit/fixtures/spark/arm_committed_line.json) so this assertion
    // and the driver-side lockstep test (tests/test_spark_evidence_format_lockstep.py) share one
    // golden shape instead of two independently hand-spelled literals.
    {
        const std::filesystem::path fixture_path =
            std::filesystem::path{YUZU_TEST_FIXTURE_DIR} / "spark" / "arm_committed_line.json";
        REQUIRE(std::filesystem::exists(fixture_path));
        std::ifstream fixture_file(fixture_path, std::ios::binary);
        const auto fixture = nlohmann::json::parse(fixture_file);
        const auto& in = fixture.at("input");
        const std::string rule_id = in.at("rule_id").get<std::string>();
        const std::string type = in.at("type").get<std::string>();
        const std::string via = in.at("via").get<std::string>();
        CHECK(format_arm_committed_line(rule_id, in.at("epoch").get<std::uint64_t>(),
                                         in.at("incarnation").get<std::uint64_t>(), type.c_str(),
                                         via.c_str(),
                                         in.at("attach_to_commit_ms").get<std::int64_t>()) ==
              fixture.at("expected_line").get<std::string>());
    }

    // The rule id is operator-authored and unvalidated. A newline would forge a whole physical
    // line (here a fake benchmark T_detect line) and a space, '=' or ',' would forge tokens.
    const auto hostile = format_arm_committed_line(
        "x a=b,c\nGuardian T_detect event_id=victim domain=health detect_wall_ns=1", 1, 2, "file",
        "callback-arm", 0);
    CHECK(hostile.find('\n') == std::string::npos);
    CHECK(hostile ==
          "Guardian spark: arm committed for rule "
          "'x_a_b_c_Guardian_T_detect_event_id_victim_domain_health_detect_wall_ns_1' (epoch=1, "
          "incarnation=2, type=file, via=callback-arm, attach_to_commit_ms=0)");

    // Non-ASCII bytes (U+2028, a lone lead byte) never reach the line, and an over-long id is
    // shortened with the same head + '~' + last-24-bytes rule as the T_* lines.
    for (const char c : format_arm_committed_line("a\xE2\x80\xA8" "b\xC3", 1, 2, "file", "x", 0))
        CHECK(static_cast<unsigned char>(c) < 0x80);
    const std::string longid(yuzu::kGuardianLogIdMaxBytes + 40, 'a');
    const std::string shortened =
        std::string(yuzu::kGuardianLogIdMaxBytes - yuzu::kGuardianLogIdTailBytes - 1, 'a') + "~" +
        std::string(yuzu::kGuardianLogIdTailBytes, 'a');
    CHECK(format_arm_committed_line(longid, 1, 2, "file", "x", 0)
              .rfind("Guardian spark: arm committed for rule '" + shortened + "' (epoch=1,",
                     0) == 0);

    // std::format on a null const char* is undefined; a null type or via prints as "unknown",
    // which still fits the driver's T2_RE token class ([\w-]+).
    CHECK(format_arm_committed_line("r1", 1, 2, nullptr, nullptr, 3) ==
          "Guardian spark: arm committed for rule 'r1' (epoch=1, incarnation=2, type=unknown, "
          "via=unknown, attach_to_commit_ms=3)");
}

TEST_CASE("event ids fold in the agent id + are distinct per observation", "[spark][runtime]") {
    // Within one runtime, two observations of the same rule get distinct ids (seq);
    // two agents get distinct id prefixes - so the server's event_id PK never drops a
    // legitimate observation as a duplicate.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->set_agent_id_provider([] { return std::string{"agentA"}; });
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Initial); // compliant edge
    const auto e1 = drain_all(*rt);
    r->file = read_known(FileSnapshot{.exists = false});
    rt->evaluate_key(key, EvalReason::Event); // drift
    const auto e2 = drain_all(*rt);
    REQUIRE(e1.size() == 1);
    REQUIRE(e2.size() == 1);
    REQUIRE(e1[0].event_id != e2[0].event_id);        // distinct observations
    REQUIRE(e1[0].event_id.rfind("agentA-", 0) == 0); // agent-id folded in
    REQUIRE(e1[0].enqueued_ns > 0);                   // wall-clock timestamp, not steady epoch

    // A second agent with a different id yields a different prefix for the same rule.
    auto rt2 = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    rt2->set_agent_id_provider([] { return std::string{"agentB"}; });
    rt2->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt2->evaluate_key(key, EvalReason::Initial);
    const auto eB = drain_all(*rt2);
    REQUIRE(eB.size() == 1);
    REQUIRE(eB[0].event_id.rfind("agentB-", 0) == 0);
    REQUIRE(eB[0].event_id != e1[0].event_id); // cross-agent distinct
}

TEST_CASE("the agent-id provider is invoked before the read, not on the detached path",
          "[spark][runtime]") {
    // F3b: clock + agent-id provider are snapshotted at pass start, so neither is
    // called after the (possibly blocking) read - a provider borrowing agent state
    // would UAF if shutdown destroyed it mid-read. Gate the read and assert the
    // provider has already run by the time the read is in flight.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    std::atomic<int> provider_calls{0};
    rt->set_agent_id_provider([&] {
        provider_calls.fetch_add(1);
        return std::string{"a"};
    });
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    // attach_rule itself calls the provider once too (its Lifecycle "armed"
    // audit entry, rung 7 - synchronous on the caller's thread, never on the
    // detached-post-read path, so this call is fine). Check the DELTA from here
    // rather than an absolute count, so this stays robust to other legitimate
    // synchronous provider calls: the invariant under test is specifically that
    // evaluate_key's read-thread calls it once, before the blocking read.
    const int before_read = provider_calls.load();

    std::latch reading{1};
    std::latch release{1};
    r->on_read = [&] {
        reading.count_down();
        release.wait();
    };
    std::thread t([&] { rt->evaluate_key(key, EvalReason::Initial); });
    reading.wait();
    REQUIRE(provider_calls.load() == before_read + 1); // snapshotted BEFORE the read
    release.count_down();
    t.join();
}

TEST_CASE("a per-boot nonce disambiguates event ids across runtime instances", "[spark][runtime]") {
    // Two runtimes with the SAME agent id (i.e. a restart) still mint different ids
    // for the same rule + observation, because each has its own random boot nonce -
    // so a restart cannot reproduce a prior id and have the server's PK drop it.
    const auto make_id = [] {
        auto r = std::make_shared<FakeReader>();
        auto b = std::make_shared<FakeBackend>();
        auto rt = make_rt(r, b);
        rt->set_agent_id_provider([] { return std::string{"agentA"}; });
        const auto key = spark_key(file_spec("/a"));
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        rt->evaluate_key(key, EvalReason::Initial);
        return drain_all(*rt).at(0).event_id;
    };
    REQUIRE(make_id() != make_id());
}

TEST_CASE("concurrent attach/detach/evaluate/drain do not race (TSan checkpoint)",
          "[spark][runtime][tsan]") {
    auto r = std::make_shared<FakeReader>(); // `file` is not rewritten during this test
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const std::vector<std::string> paths{"/a", "/b", "/c", "/d"};
    std::vector<std::string> keys;
    for (const auto& p : paths) keys.push_back(spark_key(file_spec(p)));

    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    constexpr int kIters = 400;

    // Churners: attach/detach many rules across the shared keys.
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&, t] {
            while (!go.load()) {}
            for (int i = 0; i < kIters; ++i) {
                const std::string rid = "r" + std::to_string(t) + "_" + std::to_string(i % 8);
                const auto& p = paths[(t + i) % paths.size()];
                if (i % 3 == 0)
                    rt->detach_rule(rid);
                else
                    (void)rt->attach_rule(rid, file_spec(p), file_exists_rule(rid), true);
            }
        });
    }
    // Evaluators: hammer evaluate_key on every key.
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&, t] {
            while (!go.load()) {}
            for (int i = 0; i < kIters; ++i)
                rt->evaluate_key(keys[(t + i) % keys.size()],
                                 i % 2 ? EvalReason::Event : EvalReason::Convergence);
        });
    }
    // Drainer: continuously drains.
    threads.emplace_back([&] {
        while (!go.load()) {}
        for (int i = 0; i < kIters; ++i) drain_all(*rt);
    });
    // Reader: the #4606 test accessor copies the last staged batch under its leaf mutex while the
    // evaluators move-assign into it. It keeps reading until every writer has finished, so it
    // overlaps the writers (a fixed iteration count can finish before the first writer takes the
    // lock); writer-vs-writer is exercised by the evaluators themselves.
    std::atomic<bool> writers_done{false};
    std::thread reader([&] {
        while (!go.load()) {}
        std::size_t seen = 0;
        while (!writers_done.load()) seen += rt->last_eval_timings_for_test().size();
        (void)seen;
    });

    go.store(true);
    for (auto& th : threads) th.join();
    writers_done.store(true);
    reader.join();
    rt->begin_stop();
    SUCCEED(); // no crash / no TSan report is the assertion
}

TEST_CASE("concurrent attach/detach/evaluate/drain do not race when the backend and the "
          "send callback BLOCK (TSan checkpoint, #3848)",
          "[spark][runtime][liveness][tsan][tsan-heavy]") {
    // WHY THIS EXISTS. The three committed TSan checkpoints - including the one directly
    // above - all run against an INSTANTANEOUS FakeBackend: nothing blocks in arm, in
    // disarm, or in the send callback. Race-freedom is therefore proven only for a
    // backend that never blocks, which is the one backend production does not have
    // (a real arm is an OS watch registration behind a mechanism's own lock). This case
    // re-runs the same churn shape with every one of those three call sites able to park.
    //
    // WHAT A FAILURE MEANS, stated precisely because it changed during design. On this
    // tree the census below is a NO-REGRESSION check, not a leak detector: attach_rule's
    // worker already self-disarms a late arm success via its `still_wanted` re-check
    // (guardian_spark_runtime.cpp), so a leaked subscription is not reachable today
    // whatever this test does. What a surplus WOULD mean is that the self-disarm contract
    // has been broken - which is exactly the regression a rewrite of that worker lambda
    // could introduce. Recorded as a finding, never dismissed as a test bug.
    //
    // NOT RUN BY ANY PR OR PUSH CI LEG. `[tsan-heavy]` is filtered out whenever
    // b_sanitize == none (tests/meson.build), and the nightly TSan job runs against main,
    // not dev. Its evidence is a LOCAL TSan build - docs/spark-flip-gate.md says so.
    using yuzu::test::spin_until;

    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();

    GuardianSparkRuntime::Config cfg;
    // Short enough that a long backend hold reliably overruns it (the late-success path
    // is the point), long enough that an ORDINARY one-pulse park never does. The gap
    // between the two is what keeps the rejection assertion below meaningful: a short
    // park that spuriously timed out would leave its executor ticket held and make the
    // NEXT op on that key an AlreadyRunning rejection, which is indistinguishable from a
    // real dropped disarm.
    cfg.backend_op_deadline = std::chrono::milliseconds{60};
    auto rt = make_rt(r, b, cfg);

    // ── the three gates ──
    // Arms park on every call, and every 8th park is a LONG hold (300 releaser pulses,
    // ~300 ms against a 60 ms deadline) so the submitter genuinely observes
    // IoFailure::Timeout and the late-arm-success path runs for real.
    b->arm_park.park_every = 1;
    b->arm_park.long_every = 8;
    b->arm_park.long_hold_pulses = 300;
    // Disarms park SHORT ONLY. A long-held disarm would still hold its (class, key)
    // executor ticket when attach_rule's prior-generation disarm timed out, and the arm
    // that immediately follows it inside the same attach_rule call would be refused
    // AlreadyRunning - a self-inflicted rejection the census cannot tell from a real one.
    b->disarm_park.park_every = 1;
    b->disarm_park.long_every = 0;
    // The send callback runs with outbox_mu_ RELEASED but drain_mu_ HELD, and
    // evaluate_key never takes drain_mu_, so a parked send stalls only the drainer.
    BlockingGate send_park;
    send_park.park_every = 4;

    // ── per-lane fixtures: one IoClass per churner, disjoint keys and rule ids ──
    constexpr int kLanes = 3;
    constexpr int kKeysPerLane = 3;
    constexpr int kRidsPerLane = 8;
    constexpr int kIters = 400;
    const auto spec_for = [](int lane, int k) -> SparkSpec {
        switch (lane) {
        case 0: return file_spec("/p3848_" + std::to_string(k));
        case 1: return reg_spec("HKLM", "K3848_" + std::to_string(k));
        default: return svc_spec("svc3848_" + std::to_string(k));
        }
    };
    const auto rule_for = [](int lane, const std::string& rid) -> RuleAssertion {
        switch (lane) {
        case 0: return file_exists_rule(rid);
        case 1: return registry_rule(rid, "V", "v");
        default: return svc_running_rule(rid);
        }
    };
    std::vector<std::string> all_keys;
    for (int lane = 0; lane < kLanes; ++lane)
        for (int k = 0; k < kKeysPerLane; ++k)
            all_keys.push_back(spark_key(spec_for(lane, k)));

    // ── shared state ──
    std::atomic<bool> go{false};
    std::atomic<bool> churn_done{false};
    std::atomic<bool> releaser_stop{false};
    std::atomic<std::uint64_t> evals{0};
    std::atomic<std::uint64_t> drains{0};
    std::atomic<std::uint64_t> sends{0};
    std::atomic<std::uint64_t> attach_ok{0};
    std::atomic<std::uint64_t> attach_err{0};
    std::atomic<std::uint64_t> lane_spin_trips{0}; ///< harness bug detector, asserted zero
    // Each churner's EXCLUSIVE view of what it left attached. Written only by its owner,
    // read by the main thread after every churner has joined.
    std::array<std::map<std::string, std::string>, kLanes> live; // rid -> key

    std::vector<std::thread> workers;
    std::thread releaser;

    // ONE idempotent shutdown sequence, used by BOTH the normal path and the RAII guard
    // below - a Catch2 REQUIRE failure mid-test still has to unwind through live, parked
    // threads safely, and two similar-but-drifting sequences is how that stops working.
    std::once_flag stopped_once;
    const auto stop_everything = [&] {
        std::call_once(stopped_once, [&] {
            churn_done.store(true);
            go.store(true); // never leave a worker spinning on a start flag that never sets
            // GATES OPEN BEFORE ANY JOIN. A worker parked in a gate cannot be joined, and
            // the releaser is about to stop pulsing.
            b->arm_park.open();
            b->disarm_park.open();
            send_park.open();
            releaser_stop.store(true);
            if (releaser.joinable())
                releaser.join();
            for (auto& w : workers)
                if (w.joinable())
                    w.join();
            // Executor workers are DETACHED, so joining our own threads says nothing
            // about them. Wait for the last one to exit before anything they touch dies.
            (void)spin_until([&] { return rt->active_backend_op_workers() == 0; },
                             std::chrono::seconds{30});
        });
    };
    struct Cleanup {
        const std::function<void()>& fn;
        ~Cleanup() { fn(); }
    };
    const std::function<void()> cleanup_fn = stop_everything;
    Cleanup cleanup{cleanup_fn}; // declared AFTER workers/releaser/gates -> runs BEFORE them

    // ── releaser: the only thing that ever un-parks a gate during the soak ──
    releaser = std::thread([&] {
        while (!releaser_stop.load()) {
            b->arm_park.pulse();
            b->disarm_park.pulse();
            send_park.pulse();
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    });

    // ── churners: one IoClass lane each ──
    for (int lane = 0; lane < kLanes; ++lane) {
        workers.emplace_back([&, lane] {
            while (!go.load()) {
            }
            for (int i = 0; i < kIters; ++i) {
                const int j = i % kRidsPerLane;
                const std::string rid =
                    "r" + std::to_string(lane) + "_" + std::to_string(j);
                // A rid MIGRATES across keys over time, so a re-attach hits attach_rule's
                // prior-generation teardown (detach_rule_locked + an off-lock disarm)
                // before its own arm - the path a same-rid re-attach actually takes.
                const int k = ((i / kRidsPerLane) + j) % kKeysPerLane;
                if (i % 3 == 0) {
                    rt->detach_rule(rid);
                    live[static_cast<std::size_t>(lane)].erase(rid);
                } else {
                    const auto spec = spec_for(lane, k);
                    auto res = rt->attach_rule(rid, spec, rule_for(lane, rid), true);
                    if (res) {
                        attach_ok.fetch_add(1);
                        live[static_cast<std::size_t>(lane)][rid] = spark_key(spec);
                    } else {
                        attach_err.fetch_add(1);
                        // attach_rule ALWAYS tears the prior generation down first
                        // (detach_rule_locked runs in its phase 1, before the arm), so a
                        // failed attach leaves this rid NOT attached - never still
                        // attached to whatever it had before.
                        live[static_cast<std::size_t>(lane)].erase(rid);
                    }
                }
                // THE INVARIANT THAT MAKES THE REJECTION ASSERTION REAL: never submit a
                // second op for this lane while the previous one's (class, key) executor
                // ticket is still held. One submitter per lane, so this serializes
                // nothing across churners - it only waits for this churner's own work.
                if (!spin_until(
                        [&] {
                            const auto st = rt->io_executor_stats_for_test();
                            return st.active_by_class[static_cast<std::size_t>(lane)] == 0;
                        },
                        std::chrono::seconds{30}))
                    lane_spin_trips.fetch_add(1);
            }
        });
    }

    // ── evaluators: hammer evaluate_key across every lane's keys ──
    for (int t = 0; t < 3; ++t) {
        workers.emplace_back([&, t] {
            while (!go.load()) {
            }
            for (int i = 0; i < kIters; ++i) {
                rt->evaluate_key(all_keys[static_cast<std::size_t>((t + i) % all_keys.size())],
                                 i % 2 ? EvalReason::Event : EvalReason::Convergence);
                evals.fetch_add(1);
            }
        });
    }

    // ── drainer: loops on churn_done, not a fixed count. A fixed-count drainer finishes
    //    before the first arm has even landed once the backend can block. ──
    workers.emplace_back([&] {
        while (!go.load()) {
        }
        while (!churn_done.load()) {
            rt->drain([&](const OutboxEntry&) {
                send_park.maybe_park(-1);
                sends.fetch_add(1);
                return SendResult::Sent;
            });
            drains.fetch_add(1);
        }
    });

    go.store(true);
    // Join the churners specifically, then stop everything through the SAME function the
    // RAII guard uses.
    for (int lane = 0; lane < kLanes; ++lane)
        workers[static_cast<std::size_t>(lane)].join();
    churn_done.store(true);
    stop_everything();

    // One final drain with the gates already open, so nothing is left buffered.
    rt->drain([&](const OutboxEntry&) {
        sends.fetch_add(1);
        return SendResult::Sent;
    });

    // ── (a) harness health: if any of these fires, nothing below means anything ──
    CHECK(b->arm_park.watchdog_trips == 0);
    CHECK(b->disarm_park.watchdog_trips == 0);
    CHECK(send_park.watchdog_trips == 0);
    CHECK(lane_spin_trips.load() == 0);
    CHECK(rt->active_backend_op_workers() == 0);

    // ── (b) the blocking paths were actually exercised ──
    CHECK(attach_ok.load() > 0);
    CHECK(b->arm_park.long_holds > 0);
    CHECK(rt->backend_op_timeouts() > 0); // HARD: a long hold must reach the deadline
    CHECK(b->disarm_park.total_parked > 0);
    CHECK(send_park.total_parked > 0);
    CHECK(evals.load() > 0);
    CHECK(drains.load() > 0);
    CHECK(sends.load() > 0);
    CHECK(rt->outbox_size() == 0);

    // ── (c) census + rejection check, BEFORE begin_stop() ──
    // Taken before begin_stop() deliberately: once the executor is stopping, a disarm
    // routed through it is dropped as Stopped, which would present here as a surplus.
    const auto io = rt->io_executor_stats_for_test();
    // These two are what make the reconciliation a proof rather than a likelihood. An
    // AlreadyRunning or CapacityExhausted refusal is counted nowhere at the runtime's own
    // surface and submit_disarm_off_lock drops it silently, so a non-zero here means a
    // surplus below could be a declined disarm rather than a leak - the assertion could
    // no longer distinguish them.
    for (std::size_t c = 0; c < io.counters.size(); ++c) {
        CHECK(io.counters[c].rejected_key == 0);
        CHECK(io.counters[c].rejected_capacity == 0);
    }
    std::multiset<std::uint64_t> armed;
    std::multiset<std::uint64_t> disarmed;
    {
        const auto armed_snapshot = b->armed_ids();
        const auto disarmed_snapshot = b->disarmed_ids();
        armed.insert(armed_snapshot.begin(), armed_snapshot.end());
        disarmed.insert(disarmed_snapshot.begin(), disarmed_snapshot.end());
    }
    for (const auto id : disarmed) {
        // A disarm for an id that was never armed (or armed fewer times than it is
        // disarmed) is a DOUBLE-DISARM, a different defect from a leak and one that must
        // stop the reconciliation rather than quietly cancel a real surplus out of it.
        REQUIRE(armed.count(id) >= disarmed.count(id));
    }
    std::multiset<std::uint64_t> still_armed;
    for (const auto id : armed)
        if (disarmed.count(id) == 0)
            still_armed.insert(id);
    // Live subscriptions must equal live armed keys: the runtime holds exactly one
    // subscription per key, however many rules share it.
    CHECK(still_armed.size() == rt->armed_key_count());

    // ── (d) the churners' exclusive view ──
    std::size_t expected_rules = 0;
    std::set<std::string> expected_keys;
    for (const auto& m : live) {
        expected_rules += m.size();
        for (const auto& [rid, key] : m)
            expected_keys.insert(key);
    }
    CHECK(rt->rule_count() == expected_rules);
    CHECK(rt->armed_key_count() == expected_keys.size());

    rt->begin_stop();
}

// ── rung 7.4: detach_all, status_for_rule, Lifecycle audit, live-drain waker ─

TEST_CASE("attach_rule enqueues a Lifecycle 'armed' entry; detach_rule enqueues 'disarmed'",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    auto rule = file_exists_rule("r1");
    rule.rule_name = "Hosts integrity";
    rt->attach_rule("r1", file_spec("/a"), rule, true);

    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].rule_id == "r1");
    CHECK(lc[0].lifecycle_kind == "armed");
    // The entry carries the guard identity so the wire event is not blank (#2237 item 4).
    CHECK(lc[0].guard_type == "file");
    CHECK(lc[0].rule_name == "Hosts integrity");

    rt->detach_rule("r1");
    lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].rule_id == "r1");
    CHECK(lc[0].lifecycle_kind == "disarmed");
    CHECK(lc[0].guard_type == "file"); // disarmed carries the identity too (captured pre-erase)
    CHECK(lc[0].rule_name == "Hosts integrity");
}

TEST_CASE("attach_rule: a THROWING backend arm() rolls back with no ghost index entry / no leak",
          "[spark][runtime]") {
    // Fable rung-7.7b M3: the pre-fix code installed attach_rule's rollback only AFTER
    // arm(), so a THROWING arm() left the rule in the index with no subscription. That
    // ghost then corrupted a LATER successful attach of a sibling rule on the same key
    // (a false 0->1 edge -> double-arm / untracked subscription).
    //
    // #2233 item 3: File/Registry/Service now run backend_->arm() on a detached
    // GuardianIoExecutor worker, off registry_mu_ - a throw there can no longer
    // propagate as a C++ exception across the thread boundary (GuardianIoExecutor
    // contains it by design, converting it to IoFailure::WorkerThrew). attach_rule
    // returns an error instead of throwing; the rollback guarantee below (no ghost
    // index entry, a sibling arms cleanly after) is otherwise unchanged.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    b->throw_arm = true;
    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm worker threw");
    b->throw_arm = false;

    // Rolled back clean: no armed watcher, the throwing arm did not count, nothing to
    // disarm (arm threw before returning a subscription).
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->arms.load() == 0);
    CHECK(b->disarms.load() == 0);

    // The decisive check: a fresh attach of a SIBLING on the SAME key sees a real 0->1
    // edge and arms EXACTLY once. A lingering ghost from r1 would make this take the
    // existing-key branch and never arm (armed_key_count would stay 0, or double-count).
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1);
}

TEST_CASE("attach_rule: a throw AFTER arm() (waker copy) disarms and leaves no phantom audit",
          "[spark][runtime]") {
    // The throwing-arm test above only covers a throw BEFORE arm has any side effect.
    // This exercises the armed_here=true rollback path: arm() genuinely succeeds, then a
    // later step throws. A callable whose COPY throws, installed as the pending-initial
    // waker, makes the std::function copy inside attach_rule (after arm() returned a
    // subscription) throw. (Fable rung-7.7b: the seam the shipped test lacked.)
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    rt->set_pending_initial_waker(ThrowOnCopy{}); // moved in (noexcept); the COPY inside attach throws
    CHECK_THROWS_AS(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true),
                    std::runtime_error);
    rt->set_pending_initial_waker({}); // clear so the sibling attach below is clean

    // arm() succeeded, then the waker copy threw: the rollback disarmed the just-armed
    // subscription and removed the rule, and (the waker copy now precedes the lifecycle
    // enqueue) NO "armed" audit entry was written for the rolled-back attach.
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->arms.load() == 1);    // the arm did happen
    CHECK(b->disarms.load() == 1); // ...and the rollback disarmed it (the armed_here path)
    CHECK(drain_lifecycle(*rt).empty()); // no phantom "armed"

    // Key is clean afterward: a fresh attach arms exactly once.
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 2);
}

TEST_CASE("attach_rule: a throw AFTER joining an ALREADY-armed key leaves no ghost rule",
          "[spark][runtime]") {
    // #2233 item 3: distinct from the "throw AFTER arm()" test above, which only
    // covers the arm_edge==true (this call is the key's pioneer) rollback path.
    // This exercises the arm_edge==false (an existing shared watcher) path's OWN
    // rollback, which the #2233 item 3 restructure initially dropped (no backend
    // call happens here, so it is easy to assume nothing needs undoing - but
    // rules_/pending_initial were still mutated before the throw).
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true)); // pioneer, clean
    CHECK(rt->rule_count() == 1);

    rt->set_pending_initial_waker(ThrowOnCopy{});
    CHECK_THROWS_AS(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true),
                    std::runtime_error);
    rt->set_pending_initial_waker({});

    // r2 never committed: no ghost rule, no phantom "armed" audit, and the SHARED
    // watcher (which this call never touched - arm_edge was false) is untouched -
    // still exactly one armed key, one arm() call total, no disarm.
    CHECK(rt->rule_count() == 1); // r1 only
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);
    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1); // r1's own "armed" only - no r2 entry
    CHECK(lc[0].rule_id == "r1");

    // r1 is still healthy: a fresh detach/attach cycle on it works cleanly.
    rt->detach_rule("r1");
    CHECK(rt->armed_key_count() == 0);
}

TEST_CASE("source tripwire: claim_rollback's .fn is assigned before the arm claim is "
          "enqueued, not after (#3831, rung 9c R5.2 shape)",
          "[spark][runtime][liveness][source_tripwire]") {
    // #3831: a bad_alloc during claim_rollback's OWN .fn= assignment (a multi-capture
    // closure exceeding libstdc++'s std::function SBO) is not injectable from this
    // ordinary test binary - it would need allocator fault-injection at a specific
    // call site, which this repo's only such mechanism (test_spark_alloc_budget.cpp)
    // is a SEPARATE executable for precisely because global operator new replacement
    // cannot coexist with normal test infrastructure (see that file's own "WHY THIS IS
    // A SEPARATE EXECUTABLE" doc comment). Absent that, this pins the textual property
    // the fix actually depends on: .fn is assigned before the mutation it protects, so
    // a throw during the assignment has nothing left to roll back.
    //
    // RE-ANCHORED (rung 9c PR-2, Unit 1, Astra opine review 2026-09-12): attach_rule()'s
    // body that does the actual claim enqueue was extracted into a shared
    // attach_core() (attach_rule() alone still owns claim_rollback's declaration and
    // commit point - see attach_core()'s own doc comment for why). The property is
    // now a stronger, two-part one, WITHIN attach_rule(): (a) claim_rollback.fn is
    // assigned in attach_rule() BEFORE it calls attach_core() at all - a hard
    // function-call boundary, not merely an in-function line order, so reordering just
    // those two lines can't reintroduce the defect the way it did pre-extraction; (b)
    // attach_core()'s own locked block still takes registry_mu_ before the enqueue,
    // preserving the original ordering WITHIN the function that now does the mutation.
    //
    // RE-ANCHORED AGAIN (rung 9c PR-2, Unit 2): Unit 2 added exactly the second
    // occurrence this comment previously warned about - attach_rule(NonWaiting, ...)
    // has its own, textually-identical "claim_rollback.fn = [this, key, &arm_claim]"
    // and its own "attach_core(key, std::move(rule_id)" call, sharing attach_core()
    // with the blocking overload by design. An unscoped source.find() would now
    // silently grab whichever copy sorts first in the file - which happens to still
    // be the blocking overload's own (it is declared first), so this test was
    // passing for the right reason purely by file-layout accident. Fixed by bounding
    // the search to the blocking attach_rule(std::string rule_id, ...)'s own
    // definition range: from its own signature up to (but not including) the next
    // attach_rule(...) overload's definition. If a THIRD attach_rule overload or a
    // reordering of these two ever changes that range's content, re-anchor again
    // rather than relaxing this bound.
    std::ifstream input(std::filesystem::path(YUZU_AGENT_SRC_DIR) / "guardian_spark_runtime.cpp");
    REQUIRE(input.is_open());
    const std::string source((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());

    const auto attach_rule_def_pos =
        source.find("GuardianSparkRuntime::attach_rule(std::string rule_id");
    REQUIRE(attach_rule_def_pos != std::string::npos);
    const auto next_overload_pos =
        source.find("GuardianSparkRuntime::attach_rule(NonWaiting", attach_rule_def_pos);
    REQUIRE(next_overload_pos != std::string::npos);
    REQUIRE(attach_rule_def_pos < next_overload_pos);

    const auto fn_assign_pos = source.find("claim_rollback.fn =", attach_rule_def_pos);
    REQUIRE(fn_assign_pos != std::string::npos);
    REQUIRE(fn_assign_pos < next_overload_pos); // still inside the blocking overload
    const auto core_call_pos = source.find("attach_core(key, std::move(rule_id)", fn_assign_pos);
    REQUIRE(core_call_pos != std::string::npos);
    REQUIRE(core_call_pos < next_overload_pos); // ditto
    CHECK(fn_assign_pos < core_call_pos);

    // Within attach_core() (defined after this call site): the lock still precedes the
    // real enqueue, not a mention in prose - the push of the freshly built claim into
    // its key entry is the mutation the guard (now armed before attach_core() is even
    // entered) protects. "entry.fifo.push_back(c);" is the call's own text and appears
    // in no comment.
    const auto lock_pos =
        source.find("std::unique_lock<std::mutex> lk{registry_mu_}", core_call_pos);
    REQUIRE(lock_pos != std::string::npos);
    const auto enqueue_pos = source.find("entry.fifo.push_back(c);", core_call_pos);
    REQUIRE(enqueue_pos != std::string::npos);
    CHECK(lock_pos < enqueue_pos);
}

// ── PR #3821 review (fjarvis): prior_disarm dropped on an early exit ───────────
// attach_rule captures prior_disarm (the OWED backend disarm for whatever
// generation this call supersedes) BEFORE deciding which of three branches this
// push takes, but the ONLY submission site was the function's normal fall-through
// exit. Any earlier return or throw dropped it silently: a permanent, untracked
// live watcher - a real regression vs. pre-#2233's inline disarm, which no later
// step in this same function could skip. Three tests below, one per exit shape
// the review named.

TEST_CASE("attach_rule: a same-key re-push that QUEUES behind an in-flight arm still "
          "disarms the re-pushed rule's OWN prior generation first (rung 9c R5.2)",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    // r2 starts on its own key, fully armed.
    REQUIRE(rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true));
    CHECK(b->arms.load() == 1);

    // r1 parks a hung arm on "/a".
    b->hang_next_arm.store(true);
    std::thread a_thread{[&] { rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // r2 is re-pushed pointing at the SAME key r1 is currently arming ("/a") - a
    // legitimate spec change. detach_rule_locked("r2") queues its old "/b" watcher's
    // disarm claim, attach_rule drives that disarm to completion BEFORE it waits on
    // its own new claim, and the new claim QUEUES behind r1's in-flight arm on "/a"
    // (the old fail-fast "busy" rejection is gone). It runs on its own thread because
    // the wait is bounded by the 30 s deadline, not fail-fast.
    // Mutation: drop the prior_disarm submission before the wait -> disarms stays 0.
    std::expected<std::uint64_t, std::string> gen_r2;
    std::thread r2_thread{[&] {
        gen_r2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));
    // r2's OLD "/b" watcher is disarmed by r2's own attach_rule BEFORE it waits on its
    // new claim (the claim is queued under the lock first, then the prior disarm is
    // driven off-lock, then the wait) - unreachable from any Guardian state after
    // detach_rule_locked erased it, so it must go regardless of how the new arm ends.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; }, std::chrono::seconds(10)));
    CHECK(b->arm_entries.load() == 2); // r2's original "/b" arm + r1's parked "/a" arm; r2's re-push entered nothing

    b->release_hang();
    a_thread.join();
    r2_thread.join();
    REQUIRE(gen_r2.has_value());
    CHECK(b->arms.load() == 2);    // r2's original "/b" arm + r1's "/a" arm; r2 joined "/a"
    CHECK(b->disarms.load() == 1);
    CHECK(rt->rule_count() == 2);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("attach_rule: an inline-type arm() failure still disarms the re-pushed "
          "rule's prior bounded-key generation",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);

    // Re-push r1 as an inline type (Startup - never routes through io_class_
    // for_spark_type's bounded set) whose arm() then fails.
    b->fail_arm = true;
    auto gen2 = rt->attach_rule("r1", SparkSpec{SparkType::Startup, StartupSparkParams{}},
                                file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen2);
    b->fail_arm = false;

    // r1's OLD file-backed watcher must be disarmed even though the re-push
    // itself failed - it is no longer referenced anywhere in Guardian's state.
    // rung 9c PR-2 Unit 3: the prior-generation disarm is dispatched off-lock
    // through the same non-blocking submit_disarm_off_lock() (attach_core's own
    // off-lock section), so it is observed asynchronously here too.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0); // the failed re-push left nothing behind either
}

TEST_CASE("attach_rule: a commit throw still disarms the re-pushed rule's prior "
          "bounded-key generation",
          "[spark][runtime]") {
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);

    // Re-push r1 as another inline type; commit_new_generation_locked's own waker
    // copy throws AFTER the new arm() succeeds, unwinding out of attach_rule.
    rt->set_pending_initial_waker(ThrowOnCopy{});
    CHECK_THROWS_AS(rt->attach_rule("r1", SparkSpec{SparkType::Startup, StartupSparkParams{}},
                                     file_exists_rule("r1"), true),
                    std::runtime_error);
    rt->set_pending_initial_waker({});

    // Both watchers must be disarmed: the NEW one via the inline branch's own
    // pre-existing rollback (armed_here==true), and r1's OLD file-backed one via
    // the #3821 review fix - the two rollbacks nest (LIFO) and neither replaces
    // the other.
    CHECK(b->arms.load() == 2);    // old File arm + new Startup arm
    // rung 9c PR-2 Unit 3: both rollback disarms dispatch off-lock through the
    // non-blocking submit_disarm_off_lock() - observed asynchronously.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 2; },
                                   std::chrono::seconds(10))); // both rolled back
    CHECK(rt->rule_count() == 0);
}

// ── #2233 item 3: arm/disarm liveness (bounded, off-registry_mu_ backend calls) ──

TEST_CASE("#2233 item 3: a bounded arm that never returns times out, leaves no state, "
          "and is counted",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    // Release the still-parked detached worker on EVERY exit path, so a failing
    // REQUIRE below can never leave a real OS thread parked for the rest of the
    // binary (io_executor_'s shared_ptr<State> keeps it memory-safe regardless, but
    // a parked worker trips every later fork gate and the quiescence self-test;
    // governance cs-202). Declared after `rt` -> runs before it is destroyed.
    const std::function<void()> release_parked_fn = [&] {
        b->wait_entered_hang(std::chrono::seconds(30));
        b->release_hang();
    };
    struct Cleanup {
        const std::function<void()>& fn;
        ~Cleanup() { fn(); }
    };
    Cleanup release_parked{release_parked_fn};

    const auto t0 = clk::now();
    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    const auto elapsed = clk::now() - t0;

    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm timed out");
    // Bounded, not the old unbounded wedge: returns close to the configured
    // deadline, not never and not near-instantly (which would mean the deadline
    // was not actually applied).
    CHECK(elapsed >= std::chrono::milliseconds(50));
    CHECK(elapsed < std::chrono::seconds(10));
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->backend_op_timeouts() == 1);
    CHECK(drain_lifecycle(*rt).empty()); // no phantom "armed" for a rule that never armed
    // (the parked worker is released by `release_parked` above on every exit path)
}

TEST_CASE("rung 9c PR-2 Unit 3: a hung disarm no longer blocks detach_rule() or times "
          "out - it returns promptly and the claim resolves for real once released",
          "[spark][runtime][liveness]") {
    // Supersedes "#2233 item 3: a bounded disarm that never returns is counted too"
    // (pre-Unit-3: detach_rule() blocked up to cfg_.backend_op_deadline via run(),
    // and a disarm timeout was counted in backend_op_timeouts()). Unit 3 converted
    // submit_disarm_off_lock() to submit(), which has NO deadline concept at all
    // (guardian_io_executor.hpp: "there is no waiter to time out") - so detach_rule()
    // returns as soon as the disarm is ADMITTED, regardless of how long the backend
    // call takes, and no disarm can ever be counted as a timeout any more. This is a
    // real behavior improvement, not merely a relocation: the pre-Unit-3 code's own
    // timeout branch popped the claim (and let a rearm proceed) WHILE the backend
    // call was still physically running (Astra opine review Blocker 4) - that hazard
    // is gone by construction now, not worked around.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(rt->backend_op_timeouts() == 0);

    b->hang_next_disarm.store(true);
    // Release the parked disarm worker on every exit path (governance cs-202; same
    // shape as the arm-side liveness tests above).
    const std::function<void()> release_parked_fn = [&] {
        b->wait_entered_disarm_hang(std::chrono::seconds(30));
        b->release_disarm_hang();
    };
    struct Cleanup {
        const std::function<void()>& fn;
        ~Cleanup() { fn(); }
    };
    Cleanup release_parked{release_parked_fn};

    const auto t0 = clk::now();
    rt->detach_rule("r1"); // returns once the disarm is admitted, not once it completes
    const auto elapsed = clk::now() - t0;

    // Well under the 50ms deadline that used to bound this call - proof it did not
    // wait for anything, not just that it happened to be fast.
    CHECK(elapsed < std::chrono::milliseconds(50));
    CHECK(rt->rule_count() == 0);      // the confirmed-state mutation is synchronous, unchanged
    CHECK(rt->armed_key_count() == 0); // ditto
    CHECK(rt->backend_op_timeouts() == 0); // no timeout concept for disarm any more
    CHECK(b->disarms.load() == 0);     // the backend call itself is still parked

    b->release_disarm_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->backend_op_timeouts() == 0); // still never counted, even after the late completion
    // (release_parked's own release_disarm_hang() call above is now a harmless no-op
    // repeat - BlockingGate/the hang flag idiom this mirrors elsewhere in this file
    // tolerates a second release)
}

TEST_CASE("#2233 item 3: a parked arm on one key does not block a DIFFERENT key's attach",
          "[spark][runtime][liveness]") {
    // The actual defect this PR fixes: pre-fix, backend_->arm() ran INSIDE
    // registry_mu_, so a parked arm on key A blocked every other registry_mu_
    // operation - including an attach on an entirely unrelated key B - until it
    // returned. Proving key B's attach completes promptly WHILE key A's arm is
    // still parked is the direct proof registry_mu_ is genuinely released during
    // the bounded wait, not just released sooner.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<bool> a_done{false};
    std::thread a_thread{[&] {
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        a_done.store(true, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    CHECK_FALSE(a_done.load(std::memory_order_acquire)); // still parked

    // key B is a DIFFERENT spark_key (different path) - must complete promptly,
    // well under key A's 30s deadline, while A is still parked.
    const auto t0 = clk::now();
    auto gen_b = rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true);
    const auto elapsed_b = clk::now() - t0;
    REQUIRE(gen_b);
    CHECK(elapsed_b < std::chrono::seconds(5));
    CHECK(rt->armed_key_count() == 1); // only B so far - A is still parked

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return a_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(rt->armed_key_count() == 2);
}

TEST_CASE("rung 9c R5.2: a same-key attach while another is in flight QUEUES behind it, "
          "joins the one subscription, and never double-arms",
          "[spark][runtime][liveness]") {
    // Replaces #2233 item 3's fail-fast "busy" shape. Mutations: restore the busy
    // rejection (gen_r2 false); dispatch a backend arm per claim (arm_entries == 2).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::expected<std::uint64_t, std::string> gen_r1;
    std::expected<std::uint64_t, std::string> gen_r2;
    std::thread a_thread{[&] { gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    std::thread r2_thread;
    struct Cleanup {
        FakeBackend* backend;
        std::thread* a;
        std::thread* r2;
        ~Cleanup() {
            backend->release_hang();
            if (a->joinable())
                a->join();
            if (r2->joinable())
                r2->join();
        }
    } cleanup{b.get(), &a_thread, &r2_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // r2 targets the SAME key ("/a") while r1's arm is still parked: it queues behind
    // r1's claim (bounded wait, on its own thread) and issues NO backend arm of its own.
    r2_thread = std::thread{[&] {
        gen_r2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 2);
    CHECK(rt->rule_count() == 0);       // neither installed yet - the commit is the callback's
    CHECK(b->arm_entries.load() == 1);  // exactly ONE backend arm() ever entered (r1's, parked)
    CHECK(b->arms.load() == 0);

    b->release_hang();
    a_thread.join();
    r2_thread.join();
    REQUIRE(gen_r1.has_value());
    REQUIRE(gen_r2.has_value());
    CHECK(*gen_r1 != *gen_r2);
    CHECK(b->arms.load() == 1);         // r1's single arm(), once it finally resolved
    CHECK(b->arm_entries.load() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 2);       // r2 joined r1's subscription
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
    const auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 2); // one "armed" audit entry per committed claim
    CHECK(lc[0].lifecycle_kind == "armed");
    CHECK(lc[1].lifecycle_kind == "armed");
}

TEST_CASE("#2233 item 3: begin_stop() wakes a parked arm before its deadline elapses",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    // A long deadline - begin_stop() must wake the wait well before this, not by
    // riding it out.
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<int> outcome_ok{-1};
    const auto t0 = clk::now();
    std::thread a_thread{[&] {
        auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        outcome_ok.store(gen.has_value() ? 1 : 0, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->begin_stop(); // must wake the parked wait promptly, not after 30s

    a_thread.join(); // Cleanup's dtor no-ops afterward (t->joinable() is false post-join)
    const auto elapsed = clk::now() - t0;
    CHECK(elapsed < std::chrono::seconds(5)); // woken, not ridden out to the 30s deadline
    CHECK(outcome_ok.load(std::memory_order_acquire) == 0); // rejected (stopping)

    b->release_hang(); // the still-parked backend worker itself (io_executor_.stop()
                       // wakes the WAITER, not the underlying OS call - see begin_stop's doc)
}

TEST_CASE("#3816: begin_stop() followed by a late successful arm disarms the exact "
          "subscription id, once",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<int> outcome_ok{-1};
    std::thread a_thread{[&] {
        auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        outcome_ok.store(gen.has_value() ? 1 : 0, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->begin_stop(); // wakes the parked caller with Stopped, well before the arm resolves
    a_thread.join();
    CHECK(outcome_ok.load(std::memory_order_acquire) == 0); // rejected (stopping)

    b->release_hang(); // let the parked arm() finally succeed, well after the stop
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 1);
    CHECK(b->armed_ids() == b->disarmed_ids()); // the exact id, not merely a count
    CHECK(rt->backend_op_late_arms() == 1);
}

// ── Adversarial-review fix round: C1/c1 (late-success subscription leak) and
// C2/c2 (rollback disarm still under registry_mu_), both reviewers independently
// HIGH, plus C5/k3 (untested detach-during-in-flight-arm withdrawal path). ──

TEST_CASE("#3816 (was C1/c1): a timeout followed by a LATE successful arm "
          "is ADOPTED (rung 9c PR-5d: nobody withdrew \"r1\" - #3816's own exactly-"
          "once/never-leaked invariant is preserved by adoption, not only by disarm)",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    // cpp-safety Gate 3 finding: without this, a REQUIRE failure below (exactly the
    // regression this test exists to catch) throws past every plain statement,
    // including the release_hang() near the end - leaking the parked detached
    // worker for the rest of the binary's run. release_hang() is idempotent
    // (harmless if it also runs again, non-exceptionally, further down).
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm timed out");
    // The worker is STILL parked at this point (only release_hang() unblocks it) -
    // attach_rule has already returned Timeout to its own caller.
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->arms.load() == 0);
    CHECK(b->disarms.load() == 0);
    CHECK(rt->backend_op_late_arms() == 0);

    b->release_hang(); // let the parked arm() finally return - successfully, LATE
    // rung 9c PR-5d: nobody withdrew "r1" while it was wedged - #3816's exactly-
    // once/never-leaked contract is satisfied by ADOPTION here, not disarm: the
    // subscription is real, tracked, and enforcing, not torn down and reminted on
    // a future retry.
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);
    CHECK(rt->backend_op_late_arms() == 0); // this counter is the disarm-path's own signal
    CHECK(rt->armed_key_count() == 1);
    CHECK(drain_lifecycle(*rt).size() == 1); // exactly one "armed" audit entry, not zero

    // Runtime is still healthy: a fresh attach for a DIFFERENT rule on the SAME
    // key joins the already-adopted watcher (no new backend arm needed).
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 2);
    CHECK(b->arms.load() == 1); // r2 joined the existing watcher - no second arm() call
}

TEST_CASE("#3816: a timeout followed by a LATE FAILED arm is not counted as a late "
          "success and attempts no disarm",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm timed out");

    b->fail_arm.store(true); // the parked call, once released, fails rather than succeeds
    b->release_hang();
    // No RUNTIME-level counter this failure path touches increments
    // (backend_op_late_arms/arms/disarms all stay put), so there is nothing to
    // spin_until on to prove the worker resumed - give it ample bounded time (same
    // idiom test_guardian_io_executor.cpp uses to prove an erroneous action never
    // happened) before asserting the negative. The EXECUTOR's own T-agnostic
    // Counters::abandoned DOES increment for this case (a late failure is still a
    // normal, non-throwing fn() return, routed to on_abandoned same as a late
    // success) - not testable from this file, since GuardianSparkRuntime exposes
    // no executor-stats accessor; see test_guardian_io_executor.cpp's own coverage.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(b->arms.load() == 0);      // arm() itself failed - no subscription ever minted
    CHECK(b->disarms.load() == 0);   // nothing to disarm
    CHECK(rt->backend_op_late_arms() == 0); // a late FAILURE is not a late SUCCESS
}

TEST_CASE("#2233 item 3 (security-guardian F2 / cpp-safety HIGH): a same-rule_id "
          "RETRY after a timeout arms cleanly, exercising the generation token",
          "[spark][runtime][liveness]") {
    // Matches production's actual retry shape more precisely than the C1 test above
    // (which retries as a DIFFERENT rule_id, "r2"): apply_rules' policy_generation
    // hold-on-failure means a timed-out rule is retried under the SAME rule_id on
    // the next push. This is the scenario InFlightArm::generation exists for - a
    // stale worker's self-disarm check must not match a LATER episode's marker just
    // because it shares the same rule_id. This test proves the END-TO-END outcome
    // (subscription census stays consistent: every arm() is eventually matched by
    // exactly one disarm() or one live tracked watcher) across a full
    // timeout-then-retry-then-late-resolution cycle; it does not pin the exact
    // microsecond interleaving cpp-safety traced (that window is genuinely narrow -
    // both the stale worker's check and a rejected retry's own cleanup race through
    // only a couple of registry_mu_ acquisitions - forcing it deterministically
    // would need a new production-code test hook, out of proportion here; the fix
    // itself (compare generation, not just rule_id) is correct by construction
    // regardless of how precisely this test can pin the race).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    // Episode 1: the WAITER times out (waiter abandonment). rung 9c R5.2: the claim
    // itself stays at the head of its key entry as the dispatched marker until the
    // backend call returns - it is the RETAINED CLAIM, not the executor's single-flight
    // key (released at fn() return under submit()), that now protects this key.
    auto gen1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen1);
    CHECK(gen1.error() == "arm timed out");
    CHECK(rt->rule_count() == 0);
    CHECK(rt->backend_op_timeouts() == 1);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1); // the abandoned head

    // Episode 2: SAME rule_id, SAME spec, retried immediately while episode 1's
    // worker is still parked. rung 9c PR-5c (#4221 up-2): the head is now
    // genuinely Wedged (abandoned while Dispatching) - this identical retry
    // RE-OBSERVES it directly rather than queuing a new claim behind it (the whole
    // point of up-2: a routine same-rule retry onto an already-wedged key must not
    // pile up a fresh, doomed-to-timeout-again claim on every re-apply). It
    // returns the SAME "arm timed out" outcome episode 1's own claim already
    // carries - never a second backend arm, never a second independent timeout.
    // (Pre-up-2 behavior, superseded: it used to queue behind the abandoned head,
    // wait out its own 50ms deadline, and get erased as a second, separate
    // timeout - #2233 item 3's own generation-token fix still matters for THAT
    // shape when the retry is a genuinely different rule_id/spec, exercised by
    // the C1 sibling test above this one.)
    auto gen2 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen2);
    CHECK(gen2.error() == "arm timed out");
    CHECK(rt->wedged_reobservations() == 1);
    CHECK(rt->backend_op_queued() == 0);
    CHECK(rt->backend_op_timeouts() == 1); // episode 2 never independently times out
    CHECK(b->arm_entries.load() == 1); // still only episode 1's parked backend call
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);

    // Release the original hang - whichever episode's worker was actually parked
    // resolves now. rung 9c PR-5d: neither episode ever withdrew "r1" - the real
    // backend subscription that arm() mints is ADOPTED (still desired), never
    // disarmed, and the runtime's own bookkeeping ends up consistent with exactly
    // one live rule, one arm, zero disarms.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->arms.load() >= 1; }, std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until(
        [&] { return rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0; },
        std::chrono::seconds(10)));
    CHECK(b->arms.load() == 1);              // exactly one backend arm across both episodes
    CHECK(b->disarms.load() == 0);           // adopted, not disarmed
    CHECK(rt->backend_op_late_arms() == 0);
    CHECK(rt->armed_key_count() == 1);
    CHECK(drain_lifecycle(*rt).size() == 1); // one "armed" audit entry for the adopted rule

    // Runtime is still healthy: a fresh, DIFFERENT rule_id attaching onto the SAME
    // now-adopted key joins the existing watcher rather than minting a second arm.
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 2);
    CHECK(b->arms.load() == 1);
}

TEST_CASE("#2233 item 3 (C2/c2): the post-arm commit rollback's disarm runs "
          "off registry_mu_ - a parked disarm does not block a different key",
          "[spark][runtime][liveness]") {
    // Reproduces C2/c2's exact scenario: arm succeeds, then a later commit step
    // throws (a throwing waker copy, same seam as the existing "throw AFTER arm()"
    // test), triggering the rollback's compensating disarm. Proves that disarm now
    // runs OFF registry_mu_: while it is parked, a DIFFERENT key's attach proceeds.
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_disarm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    rt->set_pending_initial_waker(ThrowOnCopy{});
    std::atomic<bool> a_threw{false};
    std::thread a_thread{[&] {
        try {
            rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        } catch (const std::runtime_error&) {
            a_threw.store(true, std::memory_order_release);
        }
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_disarm_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    // The rollback's disarm is now parked - PROOF it is not holding registry_mu_:
    // a different key's attach completes promptly while it is still hung. r1's own
    // throw has already happened by this point (synchronously, before its rollback
    // even reaches the disarm call) - safe to clear the waker now so r2's own
    // commit does not ALSO throw on the same still-installed ThrowOnCopy.
    REQUIRE(b->wait_entered_disarm_hang(std::chrono::seconds(30)));
    rt->set_pending_initial_waker({});
    const auto t0 = clk::now();
    auto gen_b = rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true);
    const auto elapsed_b = clk::now() - t0;
    REQUIRE(gen_b);
    CHECK(elapsed_b < std::chrono::seconds(5));

    b->release_disarm_hang();
    REQUIRE(yuzu::test::spin_until([&] { return a_threw.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));

    CHECK(b->arms.load() == 2);    // r1's arm (rolled back) + r2's arm
    CHECK(b->disarms.load() == 1); // r1's rollback disarm only
    CHECK(rt->armed_key_count() == 1); // r2 only - r1 never committed
    CHECK(rt->rule_count() == 1);
    CHECK(drain_lifecycle(*rt).size() == 1); // r2's "armed" only, no phantom for r1
}

TEST_CASE("#2233 item 3 (C5/k3): detaching a rule while its own arm is still "
          "parked withdraws it cleanly, with an eventual compensating disarm",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<bool> a_done{false};
    std::thread a_thread{[&] {
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        a_done.store(true, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // Detach the SAME rule whose arm is still parked - the withdrawn branch
    // (detach_rule_locked's Case 0, guardian_spark_runtime.cpp) must handle this
    // without touching keys_/rules_ (neither exists yet) and without waiting.
    const auto t0 = clk::now();
    rt->detach_rule("r1");
    const auto elapsed = clk::now() - t0;
    CHECK(elapsed < std::chrono::seconds(1)); // withdrawal itself does not wait
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(drain_lifecycle(*rt).empty()); // never armed - no "armed" or "disarmed" entry

    b->release_hang(); // let the parked (now-withdrawn) arm finally resolve
    REQUIRE(yuzu::test::spin_until([&] { return b->arms.load() == 1; }, std::chrono::seconds(10)));
    // Withdrawn-path completion (attach_rule's stopping_||withdrawn branch) disarms
    // whatever the late arm produced - same self-cleanup shape as C1/c1 above.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; }, std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until([&] { return a_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(drain_lifecycle(*rt).empty());

    // Runtime is still healthy: a fresh attach on the same key/rule arms cleanly.
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 2);
}

TEST_CASE("Lifecycle audit entries are NOT coalesced or purged like compliance/health",
          "[spark][runtime]") {
    // The bug Sol's review caught: GuardianOutbox coalesces by (domain,rule_id)
    // - latest wins - and detach_rule's drop_rule(rule_id) purges every domain
    // for that rule, including (before this fix) Lifecycle. Attach-then-
    // immediately-disable must not lose the "armed" audit evidence.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->detach_rule("r1"); // same-tick disable, before anything ever drained

    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 2); // BOTH survive: armed, then disarmed
    CHECK(lc[0].lifecycle_kind == "armed");
    CHECK(lc[1].lifecycle_kind == "disarmed");
}

TEST_CASE("a same-id re-attach enqueues disarmed-then-armed, both surviving",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", false), true); // replace

    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 3); // armed, disarmed (internal replace), armed (new generation)
    CHECK(lc[0].lifecycle_kind == "armed");
    CHECK(lc[1].lifecycle_kind == "disarmed");
    CHECK(lc[2].lifecycle_kind == "armed");
}

TEST_CASE("detach_all withdraws every attached rule and disarms every backend subscription",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r2", svc_spec("sshd"), svc_running_rule("r2"), true);
    REQUIRE(rt->rule_count() == 2);
    REQUIRE(rt->armed_key_count() == 2);
    REQUIRE(b->arms.load() == 2);

    rt->detach_all();

    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    // rung 9c PR-2 Unit 3: the confirmed-state mutation (and its "disarmed" audit
    // entry, checked below) is synchronous and unchanged; only the actual backend
    // disarm call is now dispatched off-lock through non-blocking submit().
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 2; },
                                   std::chrono::seconds(10)));
    const auto lc = drain_lifecycle(*rt);
    CHECK(lc.size() == 4); // armed x2, disarmed x2
}

TEST_CASE("detach_all also clears pending-initial bookkeeping (no stale scheduler reference)",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(rt->keys_with_pending_initial().size() == 1);

    rt->detach_all();

    CHECK(rt->keys_with_pending_initial().empty());
    // A convergence sweep over a now-nonexistent key must be a safe no-op, not
    // a dangling reference into freed PerKey state.
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Convergence);
    SUCCEED("sweeping a detached key after detach_all did not crash");
}

TEST_CASE("R5.7: application_fence_for_test() - epoch starts at 0, detach_all() bumps it by "
          "exactly 1, and incarnations straddle the reported floor correctly",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    auto [epoch0, floor0] = rt->application_fence_for_test();
    CHECK(epoch0 == 0);

    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    auto [epoch_before, floor_before] = rt->application_fence_for_test();
    CHECK(epoch_before == 0); // no detach_all() yet
    CHECK(floor_before > 0); // r1's own attach already minted an incarnation

    rt->detach_all();
    auto [epoch1, floor1] = rt->application_fence_for_test();
    CHECK(epoch1 == epoch0 + 1);
    CHECK(floor1 == floor_before); // detach_all() reports gen_counter_ as-is, never bumps it

    rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true);
    auto [epoch_after, floor_after] = rt->application_fence_for_test();
    CHECK(epoch_after == epoch1); // only detach_all() bumps the epoch, not an attach
    CHECK(floor_after > floor1); // r2's own attach minted an incarnation strictly above the floor

    rt->detach_all();
    auto [epoch2, floor2] = rt->application_fence_for_test();
    CHECK(epoch2 == epoch1 + 1);
    CHECK(floor2 == floor_after);
}

TEST_CASE("R5.7: commit_path_name() renders every CommitPath value distinctly",
          "[spark][runtime]") {
    using P = GuardianSparkRuntime::CommitPath;
    const std::string inline_arm = commit_path_name(P::InlineArm);
    const std::string inline_shared = commit_path_name(P::InlineShared);
    const std::string callback_arm = commit_path_name(P::CallbackArm);
    const std::string callback_shared = commit_path_name(P::CallbackShared);
    const std::string callback_adopt = commit_path_name(P::CallbackAdopt);

    CHECK(inline_arm == "inline-arm");
    CHECK(inline_shared == "inline-shared");
    CHECK(callback_arm == "callback-arm");
    CHECK(callback_shared == "callback-shared");
    CHECK(callback_adopt == "callback-adopt");

    // Honest scope (werror=false repo-wide): this pins the five known names, it does
    // not make a sixth CommitPath value fail to compile - that is a -Wswitch warning
    // only, per commit_path_name()'s own header comment.
    const std::set<std::string> names = {inline_arm, inline_shared, callback_arm,
                                         callback_shared, callback_adopt};
    CHECK(names.size() == 5);
}

TEST_CASE("R5.7: a redeploy's in-flight arm callback racing detach_all() for registry_mu_ "
          "never leaves a stale live rule or a double epoch bump (TSan checkpoint)",
          "[spark][runtime][tsan]") {
    // Doomgoose review (PR #4614), corrected in a follow-up round after cpp-safety
    // AND quality-engineer independently found the same false-assurance gap: this
    // test's own comment used to claim protection against a regression that moved
    // the epoch bump "to the wrong place inside detach_all()'s locked block". Two
    // separate proofs showed that claim cannot hold. (1) detach_all()'s entire body
    // (guardian_spark_runtime.cpp) runs under ONE unbroken registry_mu_ acquisition
    // - a pure reordering WITHIN that single critical section is unobservable to
    // any other thread by construction, so no concurrency test can ever detect it.
    // (2) Even the more realistic regression - SPLITTING that one lock scope into
    // two separately-locked sections - was reproduced directly (a temporary mutant
    // built and run 3000 iterations, plain AND under a real -Db_sanitize=thread
    // build, both 100% green): the callback landing in the gap still gets cleaned
    // up by the second lock scope's own rules_ walk, so rule_count()/
    // armed_key_count()/the epoch counter all still converge correctly, and TSan
    // does not flag a compositional atomicity violation across two individually
    // well-locked sections the way it flags a raw unsynchronized access. Neither
    // this test nor any runtime test can enforce that invariant - it is enforced by
    // detach_all()'s own single lock_guard scope today, and by code review on any
    // future change to it, not by this file.
    //
    // What THIS test does verify, and does so via a genuine two-OS-thread race for
    // registry_mu_ (not the fully-sequenced "detach_all withdraws a rule that is
    // still only CLAIMED" test below, which always calls detach_all() only after
    // confirming the arm is parked, so detach_all() deterministically wins): that
    // BOTH legal resolutions of that race - the claim being withdrawn before its
    // callback can commit, or the callback committing before detach_all() begins
    // its walk - leave the runtime in a fully-converged, self-consistent state
    // (no double-commit, no stale live rule, exactly one epoch bump). As originally
    // written the timing meant detach_all() won every single time (150/150 and
    // 3000/3000 runs respectively, per cpp-safety's and quality-engineer's own
    // independent sampling) - the "commit wins" branch and its cleanup path were
    // never actually exercised despite the loop. A small deliberate stagger on
    // alternating iterations now biases the race the other way often enough that
    // this test asserts BOTH outcomes were actually observed, not merely legal in
    // theory.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    bool saw_withdrawn = false;
    bool saw_committed = false;
    constexpr int kIters = 30;
    for (int i = 0; i < kIters; ++i) {
        REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
        const auto epoch_before = rt->application_fence_for_test().first;

        // A same-key re-attach disarms the live subscription and queues a fresh arm
        // behind it (confirmed by the "same-id re-attach" test above: armed,
        // disarmed, armed) - park THAT fresh arm, not the initial one. reset_hang()
        // is required before each REUSE of the hang gate on the same FakeBackend
        // (its own doc comment: entered_hang_/released_ latch permanently true
        // after one release_hang() cycle) - without it, wait_entered_hang() below
        // returns immediately-true on iteration 1+ from the STALE prior cycle's
        // flag, before the redeploy's own claim even exists yet, which raced
        // detach_all() against nothing and produced a false failure here.
        b->reset_hang();
        b->hang_next_arm.store(true);
        auto fut = std::async(std::launch::async, [&] {
            return rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", false), true);
        });
        // cpp-safety Gate-3 finding (this review round): a Cleanup guard between
        // `fut`'s declaration and the throwing REQUIRE below, matching the
        // established idiom elsewhere in this file (see the "detach_all withdraws
        // a rule that is still only CLAIMED" test below) - without it, a REQUIRE
        // failure here would unwind straight into fut's destructor, which blocks
        // until the parked worker resolves; nothing on that path ever calls
        // release_hang(), so the worker - and the whole runtime/backend graph its
        // completion closure keeps alive - would leak for the rest of the process.
        // cpp-expert Gate-3 finding (this review round): `releaser` is declared
        // default-constructed HERE, alongside `cleanup`, rather than at its
        // construction point below - `detach_all()` is not noexcept, and a
        // joinable `std::thread` destroyed mid-unwind is std::terminate(), not a
        // catchable exception. `cleanup`'s destructor now joins it too (harmless
        // no-op if never started, or already joined on the normal path), matching
        // this file's own "stop_everything" precedent (declare the thread first,
        // the guard after, so the guard's destructor - which runs first - can
        // safely join a still-live thread before that thread's own destructor
        // would otherwise abort the process).
        std::thread releaser;
        struct Cleanup {
            FakeBackend* backend;
            std::thread* releaser_thread;
            ~Cleanup() {
                backend->release_hang();
                if (releaser_thread->joinable())
                    releaser_thread->join();
            }
        } cleanup{b.get(), &releaser};
        REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

        // Race: release the parked arm (letting its completion callback try to
        // commit) on one thread while detach_all() runs on this one. On odd
        // iterations, give the callback thread a small head start so it sometimes
        // wins registry_mu_ instead of detach_all() always winning by default
        // timing - both orderings are legal (a clean withdraw-then-disarm, or a
        // legitimate commit-then-detach); what must never happen is either thread
        // observing torn/partial state.
        releaser = std::thread([&] { b->release_hang(); });
        if (i % 2 == 1)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        rt->detach_all();
        releaser.join();
        const auto fut_result = fut.get(); // either a real generation or "withdrawn" is valid here
        if (fut_result.has_value()) {
            saw_committed = true;
        } else {
            // cpp-expert Gate-3 finding (this review round): check the SPECIFIC
            // error, matching the precedent this comment cites (the "detach_all
            // withdraws a rule that is still only CLAIMED" test's own
            // CHECK(gen.error() == "withdrawn")) - a bare has_value()==false would
            // silently misclassify a future, different error class (e.g. a
            // deadline timeout, unreachable today per Config::backend_op_deadline's
            // 5s default and this race resolving in milliseconds) as the expected
            // "withdrawn" outcome instead of catching the drift.
            CHECK(fut_result.error() == "withdrawn");
            saw_withdrawn = true;
        }

        const auto epoch_after = rt->application_fence_for_test().first;
        INFO("iteration " << i << " epoch_before=" << epoch_before << " epoch_after=" << epoch_after
                          << " rule_count=" << rt->rule_count()
                          << " armed_key_count=" << rt->armed_key_count());
        CHECK(epoch_after == epoch_before + 1); // detach_all() ran exactly once, bumped exactly once
        // Both race outcomes settle asynchronously off-lock (submit_disarm_off_lock /
        // the executor's own completion dispatch) - spin rather than a bare CHECK
        // immediately after detach_all() returns.
        REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 0 && rt->armed_key_count() == 0; },
                                       std::chrono::seconds(10)));
        REQUIRE(yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key) == 0; },
                                       std::chrono::seconds(10)));
    }
    // The claim this test actually makes - both orderings converge safely - is
    // only checked if both orderings actually happened at least once.
    CHECK(saw_withdrawn);
    CHECK(saw_committed);
}

TEST_CASE("status_for_rule reflects the last committed verdict; nullopt for an unattached rule",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    CHECK_FALSE(rt->status_for_rule("ghost").has_value());

    r->file = read_known(FileSnapshot{.exists = true});
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial);

    const auto st = rt->status_for_rule("r1");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->in_unknown);
    REQUIRE(st->last_compliant.has_value());
    CHECK(*st->last_compliant); // file exists, expect_present=true -> compliant

    r->file = read_unknown<FileSnapshot>("transient");
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Convergence);
    const auto st2 = rt->status_for_rule("r1");
    REQUIRE(st2.has_value());
    CHECK(st2->in_unknown);
}

TEST_CASE("the outbox-enqueue waker fires on a compliance commit and on attach/detach lifecycle "
          "entries",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    std::atomic<int> wakes{0};
    rt->set_outbox_enqueue_waker([&] { wakes.fetch_add(1); });

    r->file = read_known(FileSnapshot{.exists = true});
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    // The "armed" lifecycle enqueue. Since rung 9c R5.2 the commit (and this waker)
    // runs on the executor worker, whose drain notifies the attach waiter BEFORE it
    // fires the wakers (a pinned ordering: "a parked completion callback keeps ...
    // the waiter returns before the waker parks", below), so attach_rule() can
    // return a scheduler tick ahead of the wake. Liveness, not a synchronous count
    // (governance qe-201 - reproduced under CPU starvation as `0 >= 1`).
    CHECK(yuzu::test::spin_until([&] { return wakes.load() >= 1; }));

    const int before_eval = wakes.load();
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial);
    CHECK(wakes.load() > before_eval); // the compliant-edge commit

    const int before_detach = wakes.load();
    rt->detach_rule("r1");
    CHECK(wakes.load() > before_detach); // the "disarmed" lifecycle enqueue
}

TEST_CASE("a copied outbox-enqueue waker outliving its installer is a harmless no-op",
          "[spark][runtime]") {
    // Mirrors the already-shipped pending_initial_waker_ lifetime test: a
    // waker capturing only shared, still-alive state must be safe to invoke
    // after whatever installed it is gone.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    auto flag = std::make_shared<std::atomic<bool>>(false);
    rt->set_outbox_enqueue_waker([flag] { flag->store(true); });
    auto copied = rt->outbox_enqueue_waker_for_test();
    rt->set_outbox_enqueue_waker({}); // clear the installed one
    REQUIRE(copied);
    copied(); // the copy still runs fine
    CHECK(flag->load());
}

TEST_CASE("lifecycle_backpressure_drops counts a full audit log without blocking the arm",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // clamped up to the one-max-batch floor
    auto rt = make_rt(r, b, cfg);

    // Fill the lifecycle log to capacity, then churn one rule's arm/disarm on top. Paged in
    // directly because the window is floored at a whole maximum-size batch, so filling it via
    // rule churn alone would take hundreds of attaches to say the same thing.
    const std::size_t cap = rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rt->try_page_batch(std::move(fill)).added == cap);
    REQUIRE(rt->lifecycle_headroom() == 0);
    for (int i = 0; i < 5; ++i)
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    CHECK(rt->lifecycle_backpressure_drops() > 0);
    // #2233 item 7: 5 attaches each drop at capacity (5 rejected "armed" entries), but
    // the log-once branch (enqueue_lifecycle_locked's own == 1 gate) must fire exactly
    // ONCE - proving the log-once logic actually gates repeats, not just that it
    // doesn't crash under repetition. Direct proof via the _for_test observable
    // (LogCapture cannot see this: guardian_spark_runtime.cpp is compiled into
    // libyuzu_agent_core.so, and its own doc comment documents the logger-swap not
    // reliably crossing that shared-library boundary).
    CHECK(rt->lifecycle_backpressure_log_fires_for_test() == 1);
    // The arm itself still succeeded throughout - the audit trail never blocks
    // the real detection-capability change. rung 9c R5.2 (governance qe-304): the 5
    // attach_rule() calls above are unchecked and same-key ("r1"), each one
    // superseding the prior generation's claim; under CPU contention a caller can
    // hit its own waiter deadline (waiter_abandoned) and return before the
    // completion callback commits the LAST generation into rules_/keys_ - a
    // transient race between this synchronous check and the async commit, not a
    // permanent retention (unlike qe-303's detach_all - a further same-key event
    // isn't needed here, the in-flight claim's own completion lands on its own).
    // A bounded wait is valid and sufficient.
    CHECK(yuzu::test::spin_until([&] { return rt->rule_count() == 1; }));
    CHECK(b->arms.load() >= 1);
}

// ── Durable-journal staging (item 7 PR-Ag C2) ────────────────────────────────

TEST_CASE("attach_rule stages a durable record; its event_id matches the wire event",
          "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    auto staged = rt->snapshot_pending().records;
    REQUIRE(staged.size() == 1);
    CHECK(staged[0]->rule_id == "r1");
    CHECK(staged[0]->kind == "armed");
    CHECK(staged[0]->enqueued_ns > 0);
    CHECK_FALSE(staged[0]->event_id.empty());

    // Mint-once: the durable record and the live wire event carry ONE id (rev-4.1 #4)
    // - a replay must reproduce it byte-for-byte or the server sees a false Conflict.
    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].event_id == staged[0]->event_id);
    CHECK(lc[0].lifecycle_kind == staged[0]->kind);
    CHECK(lc[0].guard_type == staged[0]->guard_type);
    // The drain pops the send window, NOT the staging vector.
    CHECK(rt->pending_journal_depth() == 1);
}

TEST_CASE("detach_rule stages a disarmed record after the armed one", "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true)); // stages "armed"
    rt->detach_rule("r1");                                                         // ->0 edge, stages "disarmed"

    auto staged = rt->snapshot_pending().records;
    REQUIRE(staged.size() == 2);
    CHECK(staged[0]->kind == "armed");
    CHECK(staged[1]->kind == "disarmed");
    CHECK(staged[1]->rule_id == "r1");
}

TEST_CASE("a refused arm stages no durable record (no phantom)", "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->fail_arm.store(true);
    auto rt = make_rt(r, b);
    CHECK_FALSE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true).has_value());
    CHECK(rt->snapshot_pending().records.empty()); // arm refused before enqueue → nothing staged
}

TEST_CASE("a throwing arm stages no durable record (no phantom)", "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->throw_arm.store(true);
    auto rt = make_rt(r, b);
    // #2233 item 3: File runs off registry_mu_ via GuardianIoExecutor, which contains
    // a worker throw and returns it as an error rather than propagating it - see the
    // "a THROWING backend arm() rolls back..." test above for the full rationale.
    CHECK_FALSE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true).has_value());
    CHECK(rt->snapshot_pending().records.empty()); // rollback undid the arm; nothing staged
}

TEST_CASE("snapshot_pending is FIFO; erase_persisted_prefix drops the oldest N",
          "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true));
    REQUIRE(rt->attach_rule("r3", file_spec("/c"), file_exists_rule("r3"), true));
    REQUIRE(rt->pending_journal_depth() == 3);

    auto staged = rt->snapshot_pending().records;
    REQUIRE(staged.size() == 3);
    CHECK(staged[0]->rule_id == "r1");
    CHECK(staged[2]->rule_id == "r3");

    rt->erase_persisted_prefix(2, rt->snapshot_pending().drops_at_snapshot); // drop the two oldest (r1, r2)
    REQUIRE(rt->pending_journal_depth() == 1);
    CHECK(rt->snapshot_pending().records[0]->rule_id == "r3");

    rt->erase_persisted_prefix(99, rt->snapshot_pending().drops_at_snapshot); // clamps to size
    CHECK(rt->pending_journal_depth() == 0);
}

// ── Replay: try_page_batch + page_into_window (item 7 PR-Ag C5) ───────────────

TEST_CASE("try_page_batch pages new entries into the send window", "[spark][runtime][journal]") {
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    CHECK(rt->try_page_batch({lc_entry("r1", "e1"), lc_entry("r2", "e2")}).added == 2);
    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 2);
    CHECK(lc[0].event_id == "e1");
    CHECK(lc[1].event_id == "e2");
}

TEST_CASE("try_page_batch skips entries already in the window (membership scan)",
          "[spark][runtime][journal]") {
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    CHECK(rt->try_page_batch({lc_entry("r1", "e1")}).added == 1);
    // e1 already present; only e2 is net-new.
    CHECK(rt->try_page_batch({lc_entry("r1", "e1"), lc_entry("r2", "e2")}).added == 1);
}

TEST_CASE("try_page_batch defers a batch that does not fit the headroom", "[spark][runtime][journal]") {
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // clamped up to the one-max-batch floor
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);
    const std::size_t cap = rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill; // fill to exactly ONE free slot
    for (std::size_t i = 0; i + 1 < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rt->try_page_batch(std::move(fill)).added == cap - 1);
    // headroom is 1; a 2-entry batch is deferred WHOLE (never split).
    {   // A 0 return now carries WHY: blocked for headroom, not "already a member". That
        // distinction is what lets the journal tell a waiting backlog from an idle steady
        // state (#2345 Gate 3).
        const auto blocked = rt->try_page_batch({lc_entry("r2", "e2"), lc_entry("r3", "e3")});
        CHECK(blocked.added == 0);
        CHECK(blocked.blocked_for_headroom);
        CHECK(blocked.required == 2);
    }
    CHECK(rt->try_page_batch({lc_entry("r2", "e2")}).added == 1); // a 1-entry batch fits
}

TEST_CASE("page_into_window replays a persisted batch with provenance", "[spark][runtime][journal]") {
    PageRig rig;
    rig.persist("r1");
    auto stats = rig.journal->page_into_window(*rig.rt, /*now_ms=*/1'700'000'100'000);
    CHECK(stats.records_paged == 1);

    auto lc = drain_lifecycle(*rig.rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].event_id == "e-r1");
    CHECK(lc[0].journal_last_in_batch);         // provenance attached for the sent-label
    CHECK_FALSE(lc[0].journal_batch_key.empty());
}

TEST_CASE("page_into_window replays an \"errored\" record without quarantining it (#2818, "
          "enterprise-readiness Gate 6)",
          "[spark][runtime][journal]") {
    // Before this fix, guardian_lifecycle_journal.cpp's replay allowlist only recognized
    // "armed"/"disarmed" - an "errored" record (GuardianSparkRuntime::on_subscription_lost,
    // #2818) surviving a crash/restart before it drained live would have been silently
    // QUARANTINED here as tampered, destroying the exact audit record #2818 exists to
    // produce, in the exact scenario (durability across a restart) it's meant to survive.
    PageRig rig;
    rig.persist("r1", "errored");
    auto stats = rig.journal->page_into_window(*rig.rt, /*now_ms=*/1'700'000'100'000);
    CHECK(stats.records_paged == 1); // replayed, not quarantined
    CHECK(rig.journal->quarantined() == 0);

    auto lc = drain_lifecycle(*rig.rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].lifecycle_kind == "errored");
    CHECK(lc[0].event_id == "e-r1");
}

TEST_CASE("page_into_window does not re-page a windowed entry (skips entries already windowed)",
          "[spark][runtime][journal]") {
    PageRig rig;
    rig.persist("r1");
    const std::int64_t now = 1'700'000'100'000;
    CHECK(rig.journal->page_into_window(*rig.rt, now).records_paged == 1);
    // The window still holds e-r1 (not drained): a second pass re-considers it but membership
    // skips it - 0 net-new.
    CHECK(rig.journal->page_into_window(*rig.rt, now + 60'000).records_paged == 0);
}

TEST_CASE("page_into_window reaches the never-sent tail on a stable connection (fair rotation)",
          "[spark][runtime][journal]") {
    PageRig rig;
    const int N = 12; // > burst; the head keeps re-arriving as it is sent + popped
    for (int i = 0; i < N; ++i)
        rig.persist("r" + std::to_string(i));

    // Model a healthy connected agent: page, then drain (send + pop), each tick; the bucket
    // refills as the clock advances. Oldest-first (the old code) would re-send the head forever
    // and starve the tail; fair rotation must reach EVERY batch. (Design §10 mandated test.)
    std::set<std::string> ever_sent;
    std::int64_t t = 1'700'000'000'000;
    for (int tick = 0; tick < 80 && ever_sent.size() < static_cast<std::size_t>(N); ++tick) {
        rig.journal->page_into_window(*rig.rt, t);
        rig.rt->drain([&](const OutboxEntry& e) {
            if (e.domain == OutboxDomain::Lifecycle)
                ever_sent.insert(e.event_id);
            return SendResult::Sent;
        });
        t += 30'000; // 30 s / tick
    }
    CHECK(ever_sent.size() == static_cast<std::size_t>(N)); // no tail starvation
}

TEST_CASE("page_into_window bounds net-new work per pass (rate limit)", "[spark][runtime][journal]") {
    PageRig rig;
    for (int i = 0; i < 20; ++i)
        rig.persist("r" + std::to_string(i));
    // One pass with a fresh bucket pages at most burst + the single-batch overshoot; the rest
    // are DELAYED (still journaled), never dropped.
    const auto s = rig.journal->page_into_window(*rig.rt, 1'700'000'000'000);
    CHECK(s.batches_paged >= 1);
    CHECK(s.batches_paged <= 6); // burst (5) + 1 overshoot
    CHECK(drain_lifecycle(*rig.rt).size() == s.batches_paged);
}

// ── #2364 headroom-blocked EPISODE state ──────────────────────────────────────
// The regime test: the episode clock must SURVIVE a pass that places small batches
// while the big one stays blocked - that is the exact starvation channel #2364
// documents, and the design this replaced (clear-on-placement) zeroed the clock on
// every such pass, measuring nothing (Sol + Kimi opine, 2026-07-23).

TEST_CASE("#2364 episode: survives small-batch placement while the big batch is blocked",
          "[spark][runtime][journal]") {
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // clamped up to the one-max-batch floor (256)
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    // Fill the window to headroom 3.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i + 3 < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap - 3);

    // ONE 4-record batch (blocked: needs 4 > 3) + one 1-record batch (fits).
    std::vector<std::shared_ptr<const JournalRecord>> big;
    for (int i = 0; i < 4; ++i)
        big.push_back(std::make_shared<const JournalRecord>(
            JournalRecord{.rule_id = "big", .generation = 1, .event_id = "e-big-" + std::to_string(i),
                          .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                          .guard_type = "file", .rule_name = "n"}));
    REQUIRE(rig.journal->persist(big, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 4);
    rig.persist("small");

    CHECK(rig.journal->headroom_blocked_since_for_test() == -1); // no episode yet

    const std::int64_t t0 = 1'700'000'000'000;
    const auto s1 = rig.journal->page_into_window(*rig.rt, t0);
    CHECK(s1.headroom_blocked);
    CHECK(s1.records_paged == 1); // the small batch placed IN THE SAME PASS
    const auto since1 = rig.journal->headroom_blocked_since_for_test();
    CHECK(since1 >= 0); // episode started

    // Second blocked pass: set-if-unset must HOLD the original stamp, not re-stamp -
    // re-stamping is the sawtooth that pins the age at ~0 under sustained starvation.
    const auto s2 = rig.journal->page_into_window(*rig.rt, t0 + 60'000);
    CHECK(s2.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since1);

    // The age accessor takes the caller's steady now: exact age, and saturating (a now
    // at-or-before the stamp reads 0, never an unsigned wrap).
    CHECK(rig.journal->headroom_blocked_age_ms(since1 + 5'000) == 5'000);
    CHECK(rig.journal->headroom_blocked_age_ms(since1) == 0);
    CHECK(rig.journal->headroom_blocked_age_ms(since1 - 1) == 0);

    // Recovery: drain the window, then a pass that classifies EVERY candidate with no
    // block observed (a full clean sweep) clears the episode.
    drain_lifecycle(*rig.rt);
    const auto s3 = rig.journal->page_into_window(*rig.rt, t0 + 120'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
    CHECK(rig.journal->headroom_blocked_age_ms(t0) == 0); // no episode -> age 0
}

TEST_CASE("#2364 episode: a clean SLICE of a >128-candidate journal must not clear it",
          "[spark][runtime][journal]") {
    // A pass scans at most kJournalPageMaxBatchesPerPass (128) candidates, so with more
    // candidates than that a clean pass proves nothing about the unscanned tail -
    // clearing on it would sawtooth the gauge in the big-journal regime (both external
    // reviewers, independently). Clearing waits for accumulated block-free coverage of
    // the full candidate set.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    // 130 journal batches whose records are ALREADY in the window (need==0 candidates:
    // cleanly classified, never a blockage, and - crucially - no token spend), plus one
    // OLDEST 1-record batch that cannot fit (headroom 0) and starts the episode.
    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        // Mint the key through the production helper: the timestamp is IN the key, and the
        // maintenance passes order and expire by it, so a hand-written key would be corruption.
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string blocked_key = write_batch("aaa", 0, base_ts - 1'000, "e-blk"); // oldest
    std::vector<OutboxEntry> windowed;
    for (int i = 0; i < 130; ++i) {
        const auto id = std::to_string(i);
        write_batch("bbb", static_cast<std::uint64_t>(i), base_ts + i, "e-r" + id);
        windowed.push_back(lc_entry("r" + id, "e-r" + id));
    }
    // Fill the window COMPLETELY: the 130 candidate ids + filler to capacity.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    for (std::size_t i = 130; i < cap; ++i)
        windowed.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(windowed)).added == cap);

    // Pass 1: headroom 0, the oldest candidate needs a slot -> blocked, episode starts.
    const auto s1 = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    CHECK(s1.headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // The blocked batch gets a durable sent-label (as if delivered), so ordinary passes
    // now SKIP it - every remaining candidate classifies cleanly (already windowed).
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(blocked_key), ""));

    // Pass 2: 131 candidates, slice cap 128 -> a CLEAN pass that covered only a slice.
    // The old clear-on-clean-pass rule would clear here; the episode must survive.
    const auto s2 = rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    CHECK_FALSE(s2.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);

    // Pass 3: accumulated block-free coverage (128 + 128) now spans all 131 candidates
    // -> the episode clears.
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}

TEST_CASE("#2364 episode: shrink-churn cannot clear it early (distinct coverage, not a count)",
          "[spark][runtime][journal]") {
    // THE Fable-review regression (2026-07-23). A coverage COUNT compared against the
    // current candidate-set size clears early when prune eviction removes
    // already-counted candidates between passes: the count survives, the bar drops, and
    // the episode clears before the rotation ever re-reaches the still-blocked batch -
    // re-opening the sawtooth in exactly the #2364 shrink-churn regime. Distinct-key
    // coverage must keep the episode alive until every SURVIVING candidate has itself
    // been observed block-free.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    // Oldest: the blocked batch (1 net-new record, and the window will be full).
    write_batch("aaa", 0, base_ts - 1'000, "e-blk");
    // 260 newer batches, all sent-labelled: they classify cleanly (skip-sent) without
    // needing window room, and 260 > 2x the 128-per-pass slice so full coverage takes
    // more than two passes.
    std::vector<std::string> clean_keys;
    for (int i = 0; i < 260; ++i) {
        const auto id = std::to_string(i);
        const std::string key =
            write_batch("bbb", static_cast<std::uint64_t>(i), base_ts + i, "e-r" + id);
        REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(key), ""));
        clean_keys.push_back(key);
    }
    // Window completely full -> the blk batch can never place.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);

    // Pass 1: the oldest candidate blocks at headroom 0 -> episode starts.
    const auto s1 = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    REQUIRE(s1.headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // Pass 2: a clean 128-candidate slice (cursor sits after blk), coverage 128 of 261.
    const auto s2 = rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    CHECK_FALSE(s2.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);

    // Prune-eviction stand-in: delete the 128 candidates pass 2 just classified. A
    // count-based rule now holds 128 counted classifications against a 133-candidate
    // set - pass 3's clean slice would push it to 256 >= 133 and clear spuriously.
    for (int i = 0; i < 128; ++i)
        REQUIRE(rig.kv->del(kJournalNamespace, clean_keys[static_cast<std::size_t>(i)]));

    // Pass 3: another clean slice (128 of the 132 remaining cleans; blk still not
    // reached). The still-blocked batch has NOT been observed block-free, so the
    // episode MUST survive - this is the assertion the count rule fails.
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);

    // Pass 4: the rotation finishes the cleans and wraps back to blk - still blocked,
    // and set-if-unset holds the ORIGINAL stamp (the episode was continuous).
    const auto s4 = rig.journal->page_into_window(*rig.rt, base_ts + 230'000);
    CHECK(s4.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);
}

TEST_CASE("#2364 episode: a stop-truncated pass with FULL coverage still does not clear",
          "[spark][runtime][journal]") {
    // Drives the in-loop stopping_ break (the only writer of stop_truncated) via the
    // test-only per-candidate hook - no external sequence can land a stop between
    // candidates deterministically. DISCRIMINATING setup (governance Gate 3 QE): the
    // truncated pass completes the coverage of EVERY candidate before the stop lands,
    // so if the stop_truncated guard were deleted the footer's covered-check would
    // evaluate TRUE and clear - this test flips on exactly that mutation, unlike a
    // partial-coverage truncation where the missing keys also block the clear.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    // Same 131-candidate scaffold as the clean-slice test: blk oldest, 130 batches
    // whose records are pre-windowed (need==0 -> clean, token-free classifications).
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string blocked_key = write_batch("aaa", 0, base_ts - 1'000, "e-blk");
    std::vector<OutboxEntry> windowed;
    for (int i = 0; i < 130; ++i) {
        const auto id = std::to_string(i);
        write_batch("bbb", static_cast<std::uint64_t>(i), base_ts + i, "e-r" + id);
        windowed.push_back(lc_entry("r" + id, "e-r" + id));
    }
    const std::size_t cap = rig.rt->lifecycle_headroom();
    for (std::size_t i = 130; i < cap; ++i)
        windowed.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(windowed)).added == cap);

    // Pass 1: blocked at blk -> episode starts. Then label blk as delivered so every
    // candidate classifies cleanly from here on.
    REQUIRE(rig.journal->page_into_window(*rig.rt, base_ts + 50'000).headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(blocked_key), ""));

    // Pass 2: ordinary clean 128-slice (covers bbb0..bbb127). Survives - partial.
    (void)rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() == since);

    // Pass 3: the rotation continues at bbb128, bbb129, then blk - after those THREE
    // classifications coverage of all 131 candidates is complete. Stop on the 4th
    // examined candidate: the pass is truncated AFTER coverage completed, so ONLY the
    // stop_truncated guard stands between this pass and a (wrong) clear.
    int classify_calls = 0;
    rig.journal->set_post_classify_hook_for_test([&] {
        if (++classify_calls == 4)
            rig.journal->request_stop();
    });
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(classify_calls == 4); // truncated mid-loop, after the coverage-completing 3rd
    CHECK(rig.journal->headroom_blocked_since_for_test() == since); // NOT cleared
    // #2452 Gate 7: a stop-truncated pass placed nothing and did not verify a clean idle backlog,
    // so it is not "verified idle". This pins the `stop_truncated` tail term - the one governance
    // Gate 8 found unpinned: with records_paged==0 and every other term false, deleting
    // `!stop_truncated` from the tail conjunction would flip this to true.
    CHECK(s3.records_paged == 0);
    CHECK_FALSE(s3.progress_or_verified_idle);
}

TEST_CASE("#2364 episode: restart after clear - a fresh episode stamps and clears cleanly",
          "[spark][runtime][journal]") {
    // Guards the epoch-reset path (governance Gate 3 QE): after block -> clear, a
    // SECOND blocking episode must get its own fresh stamp and must itself be
    // clearable - i.e. the clear really reset the coverage set, and no stale coverage
    // from epoch 1 lets epoch 2 clear early (or blocks it from clearing at all).
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1;
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i + 3 < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap - 3);

    // Episode 1: a 4-record batch blocks against headroom 3.
    std::vector<std::shared_ptr<const JournalRecord>> big;
    for (int i = 0; i < 4; ++i)
        big.push_back(std::make_shared<const JournalRecord>(
            JournalRecord{.rule_id = "big", .generation = 1, .event_id = "e-big-" + std::to_string(i),
                          .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                          .guard_type = "file", .rule_name = "n"}));
    REQUIRE(rig.journal->persist(big, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 4);
    const std::int64_t t0 = 1'700'000'000'000;
    REQUIRE(rig.journal->page_into_window(*rig.rt, t0).headroom_blocked);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() >= 0);

    // Clear episode 1: drain frees the window; the next pass places big (full clean
    // coverage of the single candidate).
    drain_lifecycle(*rig.rt);
    (void)rig.journal->page_into_window(*rig.rt, t0 + 60'000);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() == -1);

    // Episode 2: a fresh 2-record batch against a re-filled window (headroom 1).
    const std::size_t headroom_now = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> refill;
    for (std::size_t i = 0; i + 1 < headroom_now; ++i)
        refill.push_back(lc_entry("fill2", "g" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(refill)).added == headroom_now - 1);
    std::vector<std::shared_ptr<const JournalRecord>> big2;
    for (int i = 0; i < 2; ++i)
        big2.push_back(std::make_shared<const JournalRecord>(
            JournalRecord{.rule_id = "big2", .generation = 1, .event_id = "e-b2-" + std::to_string(i),
                          .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                          .guard_type = "file", .rule_name = "n"}));
    REQUIRE(rig.journal->persist(big2, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 2);
    const auto s3 = rig.journal->page_into_window(*rig.rt, t0 + 120'000);
    CHECK(s3.headroom_blocked);
    const auto since2 = rig.journal->headroom_blocked_since_for_test();
    CHECK(since2 >= 0); // fresh episode stamped after a genuine -1

    // And episode 2 clears on recovery exactly like episode 1 did.
    drain_lifecycle(*rig.rt);
    (void)rig.journal->page_into_window(*rig.rt, t0 + 180'000);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}

TEST_CASE("#2364 episode: early returns leave the state untouched",
          "[spark][runtime][journal]") {
    // Every return before the end-of-pass update - stop, no token, scan failure - must
    // neither start nor clear an episode: an examination that never ran refutes nothing.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1;
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);
    rig.persist("blk"); // 1 net-new record, headroom 0 -> blocks when a pass runs

    const std::int64_t t0 = 1'700'000'000'000;
    // A failed journal scan returns before the update: no episode may start.
    rig.journal->inject_page_read_failures_for_test(1);
    (void)rig.journal->page_into_window(*rig.rt, t0);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);

    // A real pass starts it.
    (void)rig.journal->page_into_window(*rig.rt, t0 + 30'000);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // After request_stop() the pass returns at the entry gate: state untouched.
    rig.journal->request_stop();
    (void)rig.journal->page_into_window(*rig.rt, t0 + 60'000);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);
}

TEST_CASE("page_into_window prunes an expired batch before replaying (boot barrier)",
          "[spark][runtime][journal]") {
    PageRig rig;
    // Both batches written directly with CONTROLLED ts_ms (persist would stamp real-now).
    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    write_batch("old", 0, 1000, "e-old");             // ancient → older than 7 days
    write_batch("new", 0, 1'700'000'000'000, "e-new"); // recent

    // The barrier prunes before paging: the ts_ms=1000 batch ages out and is never replayed.
    auto stats = rig.journal->page_into_window(*rig.rt, 1'700'000'050'000LL);
    CHECK(stats.records_paged == 1);
    CHECK(rig.journal->batches_pruned() == 1); // the expired batch pruned by the barrier
    auto lc = drain_lifecycle(*rig.rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].event_id == "e-new");
}

TEST_CASE("page_into_window pages NOTHING when the boot prune's scan fails (#2303 C4)",
          "[spark][runtime][journal]") {
    PageRig rig;
    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    // Both recent (neither ages out), so ONLY the count cap can evict - and only a prune whose
    // scan succeeds can apply it.
    write_batch("aaa", 0, 1'700'000'000'000, "e-older");
    write_batch("bbb", 0, 1'700'000'001'000, "e-newer");
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/1,
                                               /*max_bytes=*/std::size_t(-1), 100);

    // The boot barrier's scan fails. Latching only on read_ok (M5) already kept the barrier
    // un-latched, but the pass used to FALL THROUGH and replay anyway - handing the runtime
    // exactly the over-cap candidates a good prune would have evicted, on the one pass the
    // barrier exists to protect.
    rig.journal->inject_read_failures_for_test(1);
    const auto blocked = rig.journal->page_into_window(*rig.rt, 1'700'000'050'000LL);
    CHECK(blocked.records_paged == 0);
    CHECK(blocked.batches_paged == 0);
    CHECK(drain_lifecycle(*rig.rt).empty());
    CHECK(rig.journal->prune_failures() == 1); // counted, not silent

    // Self-correcting: the failure latched nothing. The next pass prunes cleanly, applies the
    // count cap, and replays only the survivor.
    const auto ok = rig.journal->page_into_window(*rig.rt, 1'700'000'110'000LL);
    CHECK(rig.journal->batches_pruned() == 1);
    CHECK(ok.records_paged == 1);
    auto lc2 = drain_lifecycle(*rig.rt);
    REQUIRE(lc2.size() == 1);
    CHECK(lc2[0].event_id == "e-newer"); // the oldest was evicted by the cap, never replayed
}

TEST_CASE("page_into_window stops enqueuing once request_stop is signalled (stop-race gate)",
          "[spark][runtime][journal]") {
    PageRig rig;
    for (int i = 0; i < 4; ++i)
        rig.persist("r" + std::to_string(i));
    rig.journal->request_stop();
    // A page pass after stop began must not mutate the window.
    CHECK(rig.journal->page_into_window(*rig.rt, 1'700'000'100'000).records_paged == 0);
    CHECK(drain_lifecycle(*rig.rt).empty());
}

TEST_CASE("a paged batch's last entry, when sent, gets a sent-label (send-wrap logic)",
          "[spark][runtime][journal]") {
    PageRig rig;
    rig.persist("r1");
    REQUIRE(rig.journal->page_into_window(*rig.rt, 1'700'000'100'000).records_paged == 1);

    // Drain with the same wrap wire_spark_engine installs: on a Sent last-in-batch paged
    // entry, write the sent-label.
    rig.rt->drain([&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle && e.journal_last_in_batch &&
            !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        return SendResult::Sent;
    });
    CHECK(rig.journal->sent_labels_written() == 1);
    auto sent = rig.kv->list_entries(kJournalNamespace, kSentKeyPrefix);
    REQUIRE(sent.has_value());
    CHECK(sent->size() == 1);
}

TEST_CASE("concurrent pagers + a drainer do not race (TSan checkpoint)",
          "[spark][runtime][journal][tsan]") {
    // #4153: redesigned off a real on-disk KvStore + unbounded `while(!stop)` worker
    // loops, whose termination depended on the MAIN thread winning lock races against
    // spinning workers - that starved under contention and caused real CI stalls
    // (#2373, #2345, #4018). Every worker below instead runs a FIXED, bounded number
    // of iterations against an in-memory FakeJournalStore, so termination depends on
    // nothing but each worker's own loop counter, never on main's progress. Dependency
    // graph (acyclic, every wait is on finite work, nothing ever waits on main): the 3
    // pagers each count down `first_pass` once, after their OWN first completed
    // page_into_window call; main blocks on `first_pass` before doing its own passes;
    // the drainer polls `pagers_done` (a non-blocking try_wait, real work every
    // iteration) between drain_bounded calls and issues one final drain once it fires.
    // `workers` is declared LAST (after the rig and every latch) so it destructs FIRST
    // on any REQUIRE unwind, joining every thread - each bounded by its own fixed loop,
    // none blocked on anything main provides - before the latches they might still be
    // touching are destroyed.
    FakeStoreRig rig;

    // Seed 20 batches with EXPLICIT 2023 timestamps, never via persist() (which stamps
    // real wall-clock NOW and made the pre-#4153 test's "walks forward to drive the
    // age-cutoff logic" claim hollow: a fixed-2023 prune clock can never age-evict a
    // real-2026-stamped persist() batch).
    constexpr std::int64_t kBaseTs = 1'672'531'200'000; // 2023-01-01T00:00:00Z
    for (int i = 0; i < 20; ++i)
        rig.seed_batch(kBaseTs + i, "r" + std::to_string(i));

    // Retention small enough that the pruner's own forward-walking clock (below)
    // genuinely crosses the age boundary within this test's bounded iteration count -
    // real age eviction, not merely the count/byte caps QE-1 (below) already exercises.
    rig.journal->set_retention_limits_for_test(/*days=*/1, /*max_batches=*/1000,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);

    constexpr int kIters = 300;
    constexpr int kMain = 200;
    std::latch first_pass{3};
    std::latch pagers_done{3};
    std::atomic<bool> prune_evicted{false}; // set once the pruner's age eviction has landed
    std::atomic<std::size_t> sends{0};
    // The production journaled_send wrap (guardian_engine.cpp): a paged batch's LAST
    // entry, once sent, gets a durable sent-label - the journal's THIRD store caller,
    // exercised here (not just claimed) alongside the pagers and the pruner.
    const auto send = [&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle && e.journal_last_in_batch &&
            !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        sends.fetch_add(1, std::memory_order_relaxed);
        return SendResult::Sent;
    };

    // Governance Gate 8 finding (#4153 round 3, four independent reviewers, one
    // empirically reproduced with a live 285s hang): if `first_pass` never releases
    // because of a counting/latch regression - NOT a genuine deadlock inside
    // page_into_window itself, which no test-side mechanism can un-stick - the pruner
    // below used to sit in an unbounded `first_pass.wait()` even after main's own
    // bounded_wait (further below) already FAILed and started tearing down; `workers`'
    // destructor then hung forever trying to join it. `stoppable_wait` gives the pruner
    // a PortableStopToken (this file's own portable std::jthread/std::stop_token
    // replacement, defined above FakeStoreRig - Apple Clang's libc++ lacks the real
    // ones, see that definition's comment) supplied automatically to a callable that
    // accepts it, so ~PortableJThread's implicit request-then-join actually releases
    // it - false only for a real production hang inside page_into_window, which stays
    // fundamentally untestable this way.
    const auto stoppable_wait = [](auto&& ready, PortableStopToken stoken) {
        while (!ready()) {
            if (stoken.stop_requested())
                return false;
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        return true;
    };

    std::vector<PortableJThread> workers;
    for (int p = 0; p < 3; ++p)
        workers.emplace_back([&, p] {
            std::int64_t t = kBaseTs + p * 1000;
            for (int i = 0; i < kIters; ++i) {
                rig.journal->page_into_window(*rig.rt, t);
                if (i == 0)
                    first_pass.count_down();
                t += 10'000; // advance the clock so the paging bucket keeps refilling
            }
            pagers_done.count_down();
        });
    // A RETENTION thread, not only pagers (#2345 Gate 8 cpp-safety): prune_locked_ and
    // page_into_window hand three non-atomic members between them - last_prune_now_ms_,
    // last_age_cutoff_, pruned_cutoff_valid_ - a handoff pagers alone never exercise
    // concurrently. The ~8.3-hour step stays well under the 1-day retention window, so
    // no single pass ever trips the forward-clock-jump guard on step size alone - but by
    // the 4th call the CUMULATIVE walk has already crossed 1 day, ageing all 20 seeded
    // batches out at once: that pass is declined once (the guard's own
    // would-wipe-everything protection - #2360/#2361's "clock-guarded retention"
    // family), and the very next call, seeing the identical fact set, proceeds and
    // evicts. TRIPWIRE (governance Gate 4 finding, #4153 round 3): this decline-then-
    // proceed sequence depends on `already_reported`'s dedup key NOT including now_ms
    // (common/include/yuzu/audit_retention_rules.hpp's Facts, compared in
    // guardian_lifecycle_journal.cpp) - if a future change adds a
    // clock reading to that key, every pass here reads as a NEW anomaly, eviction never
    // proceeds, and `prune_evicted` never fires; the `bounded_wait` below will FAIL this
    // test with an attributed message rather than hang, but a red run on exactly this
    // assertion after such a change should look here first, not assume a fresh
    // concurrency regression. Waits on `first_pass` FIRST - the same gate main waits on - so the pagers
    // get at least one crack at the seeded batches (the paging bucket starts pre-filled
    // to its burst size, so even an unadvanced first pass can place several) before
    // ageing can start; without that gate, a pruner that happened to run ahead of every
    // pager under contention could evict all 20 seeded batches before any of them were
    // ever paged, leaving records_paged()/sends/sent_labels_written() at zero (#4153
    // round 2, measured under load). Once unblocked, the eviction itself must still
    // land within the first handful of iterations, not near the end of this loop's
    // budget: request_stop() (below, from main) makes every subsequent prune() call a
    // no-op. That is not by itself a GUARANTEE the pruner beats main to it either - main
    // additionally blocks on `prune_evicted` before calling request_stop() (also #4153
    // round 2), which is what actually makes this deterministic; the step size here
    // only keeps that wait short.
    workers.emplace_back([&](PortableStopToken stoken) {
        if (!stoppable_wait([&] { return first_pass.try_wait(); }, stoken))
            return; // request_stop() fired before first_pass ever released - nothing to prune
        std::int64_t t = kBaseTs;
        for (int i = 0; i < kIters; ++i) {
            rig.journal->prune(t);
            if (rig.journal->batches_pruned() > 0) {
                prune_evicted.store(true, std::memory_order_release);
                prune_evicted.notify_all();
            }
            t += 30'000'000;
        }
    });
    // Governance follow-up (#4153 round 4, redesigned per external review after an
    // earlier attempt here was found unsafe and reverted): stop_token-aware, but ONLY
    // ever meaningfully cancelled on the FAILURE path below (main's own bounded_wait on
    // pagers_done times out and throws, unwinding through `workers`' destructor, which
    // calls request_stop() on every element). On the SUCCESS path this stop_token is
    // never requested before the join loop, so this loop's own try_wait() condition is
    // what ends it - exactly as before - and it is never cut off while pagers may still
    // have unpaged work in flight.
    workers.emplace_back([&](PortableStopToken stoken) {
        while (!pagers_done.try_wait() && !stoken.stop_requested())
            rig.rt->drain_bounded(send, {.max_entries = 64});
        rig.rt->drain_bounded(send, {}); // final drain: whatever the last pass paged
    });

    // Main interleaves once every pager has completed at least one pass, then blocks
    // until the pruner has ACTUALLY evicted for age at least once - request_stop()
    // (next) turns every subsequent prune() call into a no-op, so calling it before the
    // pruner's own eviction pass would race that pass rather than deterministically
    // letting it land first. Only once both are satisfied does main signal stop (also
    // exercising the stop-race gate) while the fixed-iteration workers above may still
    // be mid-loop - exactly the shape of the production drain-worker/reconnect race
    // this checkpoint exists to prove race-free.
    //
    // All three of main's waits below (two here, plus `pagers_done` further down after
    // request_stop()) are bounded (governance Gate 4/5/6/8 finding, folded #4153
    // round 3): every worker's own loop is fixed-iteration, so under normal operation
    // these release in well under a second - the 30s ceiling only ever fires on a
    // genuine stuck-thread regression, converting what would otherwise be a silent,
    // unattributed ride to Meson's external 240s entry timeout into a named FAIL()
    // pointing at which rendezvous never happened. latch/atomic have no timed wait, so
    // this polls try_wait()/load() against a steady_clock deadline rather than blocking
    // outright - deliberately NOT a wall-clock cap on the test's PASS/FAIL logic itself
    // (that failure mode is what tests/meson.build's own history warns against): a fast
    // run and a run that takes 29s both still pass identically, only a run stuck past
    // 30s fails, and only with an explicit reason. The pruner's own `first_pass` wait
    // above uses `stoppable_wait`, not this, so a FAIL() here also unblocks it during
    // teardown (see that lambda's comment) rather than leaving it to hang - the one
    // exception being a genuine deadlock inside page_into_window itself, which no
    // wait-side mechanism on either thread can un-stick.
    const auto bounded_wait = [](auto&& ready, const char* what) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
        while (!ready()) {
            if (std::chrono::steady_clock::now() >= deadline)
                FAIL("timed out after 30s waiting for " << what);
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
    };
    bounded_wait([&] { return first_pass.try_wait(); },
                 "first_pass (no pager completed its first page_into_window call)");
    for (int i = 0; i < kMain; ++i)
        rig.journal->page_into_window(*rig.rt, kBaseTs + 500'000 + i * 1000);
    bounded_wait([&] { return prune_evicted.load(std::memory_order_acquire); },
                 "prune_evicted (the pruner never evicted a batch for age)");

    rig.journal->request_stop();
    // Placed AFTER request_stop(), not before: this still exercises journal shutdown
    // while pagers may be mid-loop (the property the comment above names), and only
    // adds a bound on how long main then waits for them to genuinely finish - it does
    // NOT gate their own completion on anything main does. If this never releases (a
    // future regression dropping a pagers_done.count_down() call), the FAIL() below
    // unwinds through `workers`' destructor, which cancels the drainer before joining
    // (see its own comment) - the pruner's stop_token has nothing left to interrupt by
    // this point, since a pagers_done-stuck scenario implies first_pass/prune_evicted
    // already succeeded, meaning the pruner is long past its own only interruptible
    // point and just finishing its fixed, non-stop-checking loop. On the success path
    // nothing here requests any worker's stop_token.
    bounded_wait([&] { return pagers_done.try_wait(); },
                 "pagers_done (a pager never finished all its iterations)");
    for (auto& w : workers)
        w.join();

    INFO("fake store ops=" << rig.store->ops() << " contended=" << rig.store->contended());
    CHECK(rig.journal->records_paged() > 0);
    CHECK(sends.load(std::memory_order_relaxed) > 0);
    CHECK(rig.journal->batches_pruned() > 0);
    CHECK(rig.journal->sent_labels_written() > 0);

    // Functional stop-gate check, sequential on main: a pass AFTER request_stop() must
    // not enqueue anything - proving the gate actually holds, not merely that nothing
    // raced while it was up. Seeds a BRAND-NEW batch first, far ahead of any timestamp
    // this run's pruner or pagers ever used (#4153 mutation-testing round, second fix:
    // the FIRST fix - seeding near kBaseTs - was still not a clean test, because the
    // concurrent pruner's own clock (now far advanced, ~kBaseTs + 300 * 30'000'000ms)
    // had already pushed page_into_window's replay-skip cutoff (last_age_cutoff_) well
    // past kBaseTs; a batch seeded there reads as "retention will delete this anyway"
    // and is skipped by THAT heuristic, not by the stop gate - so the check passed even
    // with every one of page_into_window's SIX stopping_ gates deleted outright, for the
    // wrong reason (deleting only the two early-return gates leaves the check green too,
    // via the surviving mid-scan gate - "every gate" is the reproduction that actually
    // exercises this fix, not just the first two). A timestamp this far beyond anything
    // the run's clocks ever reached cannot be mistaken for already-expired by any cutoff
    // this run could have computed).
    constexpr std::int64_t kPostStopTs = 9'000'000'000'000;
    rig.seed_batch(kPostStopTs, "poststop", 0, "poststop");
    const auto post_stop = rig.journal->page_into_window(*rig.rt, kPostStopTs + 500'000);
    CHECK(post_stop.records_paged == 0);
}

TEST_CASE("page_into_window quarantines a corrupt batch instead of replaying it (M6)",
          "[spark][runtime][journal]") {
    PageRig rig;
    auto write = [&](const std::string& nonce, std::int64_t ts, const std::string& eid,
                     std::int64_t ns, const std::string& kind) {
        REQUIRE(rig.kv->set(kJournalNamespace, journal_batch_key(ts, nonce, 0),
                            R"({"v":4,"ts_ms":)" + std::to_string(ts) +
                                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                                R"(","enqueued_ns":)" + std::to_string(ns) + R"(,"kind":")" + kind +
                                R"(","guard_type":"file","rule_name":"n"}]})"));
    };
    // enqueued_ns=0 floors to epoch second 0, so the server would stamp receipt-now -> a false
    // Conflict every replay. A kind outside {armed,disarmed} is likewise corrupt/tampered.
    // The KEYS here are well-formed: this is VALUE corruption, which since #2299 is discovered
    // by the replay pass when it reads a candidate it is about to place, not by prune.
    write("bad", 1'700'000'000'000, "e-bad", 0, "armed");
    write("badkind", 1'700'000'000'000, "e-bk", 1'700'000'000'000'000'000, "banana");
    write("good", 1'700'000'000'000, "e-good", 1'700'000'000'000'000'000, "armed");

    auto stats = rig.journal->page_into_window(*rig.rt, 1'700'000'050'000);
    CHECK(stats.records_paged == 1);        // only the good batch replayed
    CHECK(rig.journal->quarantined() >= 2); // both corrupt batches moved aside
    CHECK(rig.kv->list_entries(kJournalNamespace, kQuarantineKeyPrefix)->size() >= 2);

    auto sent = drain_lifecycle(*rig.rt);
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].event_id == "e-good"); // the poison batches never reach the wire
}

TEST_CASE("page_into_window reads NO candidate values when every candidate is skipped (#2299)",
          "[spark][runtime][journal]") {
    // THE O(work) assertion. Selection - expiry, ordering, the sent-label skip, rotation - is
    // now a function of the KEY, so a pass that places nothing must read nothing. Before
    // #2299 perf-P-1 the same pass materialized and parsed every row in the namespace before
    // the 128-candidate cap was applied at all (~670 ms and +162 MiB at the byte ceiling).
    PageRig rig;
    const std::int64_t base_ts = 1'700'000'000'000;
    for (int i = 0; i < 40; ++i) {
        const std::string key =
            journal_batch_key(base_ts + i, "aaa", static_cast<std::uint64_t>(i));
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(base_ts + i) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":"e)" + std::to_string(i) +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        // Durable sent-label: an ordinary pass skips a delivered batch.
        REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(key), ""));
    }

    const auto stats = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    CHECK(stats.skipped_already_sent == 40);
    CHECK(stats.records_paged == 0);
    CHECK(rig.journal->candidate_value_fetches_for_test() == 0); // not one value read

    // A FORCED pass re-offers the labelled batches, so now the values ARE read - at most one
    // read per candidate considered, and only for candidates considered.
    //
    // Stated honestly, because the bound looks stronger than it is: with the loop as written
    // no candidate is visited twice in a pass anyway (the headroom==0 inner scan is followed
    // by `break`), so this assertion does NOT discriminate the memoization in ensure_batch -
    // that memo is defence-in-depth for a future loop shape that does revisit, not something
    // this test can catch regressing. The `== 0` assertion above is the real pin, and it is
    // the one that fails the moment selection stops being key-only.
    const auto before = rig.journal->candidate_value_fetches_for_test();
    const auto forced = rig.journal->page_into_window(*rig.rt, base_ts + 60'000, true);
    const auto fetched = rig.journal->candidate_value_fetches_for_test() - before;
    CHECK(forced.records_paged >= 1);
    CHECK(forced.batches_paged >= 1); // it really did read and place, not skip cheaply
    CHECK(fetched >= 1);
    CHECK(fetched <= 40); // never more than one read per candidate
}

TEST_CASE("#2364 episode: a failed candidate VALUE read never counts as block-free coverage",
          "[spark][runtime][journal]") {
    // A candidate whose value cannot be READ has an UNKNOWN headroom disposition. Recording it
    // as clean would let a chronically unreadable row complete the coverage set and clear a
    // live episode while the batch that is actually blocking went unread - the same shape as
    // the three clear rules already rejected in review (clear-on-place, clear-on-clean-PASS,
    // count-vs-set-size), reached through the point read #2299 introduced.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string blocked_key = write_batch("aaa", 0, base_ts - 1'000, "e-blk");
    const std::string other_key = write_batch("bbb", 0, base_ts, "e-oth");

    // Fill the window so the oldest candidate cannot place.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);

    // Pass 1: blocked -> the episode starts.
    REQUIRE(rig.journal->page_into_window(*rig.rt, base_ts + 50'000).headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // Label the blocking batch delivered, so from here it is skipped and classified clean.
    // The OTHER candidate is the only one left to prove block-free - and its value read fails.
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(blocked_key), ""));
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(other_key), ""));
    // Drain the window so nothing is blocked any more: only the unknown disposition remains.
    (void)drain_lifecycle(*rig.rt);

    // Exactly the two candidates this pass considers, so the NEXT pass reads cleanly.
    rig.journal->inject_value_read_failures_for_test(2);
    const auto s2 = rig.journal->page_into_window(*rig.rt, base_ts + 110'000, /*replay_sent=*/true);
    CHECK_FALSE(s2.headroom_blocked);
    // The episode MUST survive: coverage was never proven for the unreadable candidate.
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);
    CHECK(rig.journal->page_read_failures() >= 1); // counted, not silent

    // With the reads working again, the same candidates classify cleanly and the episode ends.
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000, /*replay_sent=*/true);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}

TEST_CASE("persist back-fills provenance onto the live window entry (M3)",
          "[spark][runtime][journal]") {
    PageRig rig;
    // A live entry enters BOTH the send window and staging; persist it, then back-fill.
    REQUIRE(rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    auto pending = rig.rt->snapshot_pending().records;
    REQUIRE(pending.size() == 1);

    std::vector<PersistedBatch> batches;
    CHECK(rig.journal->persist(pending, &batches, kJournalPersistUnbounded, kJournalPersistUnbounded) == 1);
    REQUIRE(batches.size() == 1);
    for (const auto& b : batches)
        rig.rt->backfill_batch_provenance(b.key, b.event_ids, b.event_ids.back());

    // The live entry now carries the batch key + last-in-batch, so its LIVE send writes a
    // sent-label (before this fix a live-sent entry had no key and later false-alerted).
    rig.rt->drain([&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle && e.journal_last_in_batch &&
            !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        return SendResult::Sent;
    });
    CHECK(rig.journal->sent_labels_written() == 1);
    auto sent_m3 = rig.kv->list_entries(kJournalNamespace, kSentKeyPrefix);
    REQUIRE(sent_m3.has_value());
    CHECK(sent_m3->size() == 1);
}

TEST_CASE("a hostile rule_name is rejected from the journal but never crashes the arm (QE-2)",
          "[spark][runtime][journal]") {
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());

    // Feed embedded-NUL / invalid-UTF-8 / oversized rule_names through the REAL wired staging
    // path (attach_rule -> enqueue_lifecycle_locked -> build_journal_record -> validate_record),
    // not validate_record in isolation. This is the governance blind-spot #1593 lesson: a
    // "rejected, not thrown" claim for the wired path needs a reproduction. Each must be kept out
    // of the durable journal (journal_field_rejected++) while the arm itself still succeeds.
    const auto arm_with_name = [&](const std::string& rid, const std::string& name) {
        auto rule = file_exists_rule(rid);
        rule.rule_name = name;
        return rt->attach_rule(rid, file_spec("/" + rid), rule, true);
    };

    std::string nul = "bad";
    nul.push_back('\0');
    nul += "name";
    REQUIRE(arm_with_name("r1", nul).has_value());                           // embedded NUL
    REQUIRE(arm_with_name("r2", std::string("bad\xff\xfetail")).has_value()); // invalid UTF-8
    REQUIRE(arm_with_name("r3", std::string(5000, 'x')).has_value());        // > kMaxJournalFieldBytes

    CHECK(rt->journal_field_rejected() == 3); // all three kept OUT of the durable journal
    CHECK(rt->journal_clock_rejected() == 0);
    CHECK(rt->pending_journal_depth() == 0);  // nothing staged (the live audit entry still sent)
}

TEST_CASE("concurrent persist + page + prune + drain do not race (TSan checkpoint, QE-1)",
          "[spark][runtime][journal][tsan]") {
    // #4153: same redesign as the pagers+drainer checkpoint above - see its header
    // comment for the full rationale (real KvStore -> FakeJournalStore, unbounded
    // stop-flag loops -> fixed per-thread iteration counts, PortableJThread (this
    // file's portable std::jthread replacement, defined above FakeStoreRig) for RAII
    // join safety, `workers` declared after the rig/latches/atomics for unwind
    // safety). This test additionally exercises persist() - a REAL write path serialised only by the
    // store's own lock, no paging_mutex_ - racing page/prune's paging_mutex_-guarded
    // path: the FR5 prune-vs-paging serialization under genuinely concurrent I/O.
    FakeStoreRig rig;
    // A small retention cap keeps the pruner trimming the journal so page-passes stay
    // O(small): TSan finds a race from the INTERLEAVING, not from volume, so a short
    // bounded run suffices. `days` is deliberately huge (never age-evicts) - this test
    // exercises COUNT eviction only; the pagers+drainer checkpoint above is the one
    // that exercises AGE eviction.
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/16,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    constexpr std::int64_t kBaseTs = 1'700'000'000'000;
    for (int i = 0; i < 16; ++i)
        rig.seed_batch(kBaseTs + i, "seed" + std::to_string(i));

    constexpr int kIters = 300;
    constexpr int kPersistTotal = 40;
    std::atomic<int> pruner_passes{0};
    std::atomic<int> persist_successes{0};
    std::latch producers_done{4}; // 2 pagers + pruner + persister (not the drainer)
    std::atomic<std::size_t> sends{0};
    const auto send = [&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle && e.journal_last_in_batch &&
            !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        sends.fetch_add(1, std::memory_order_relaxed);
        return SendResult::Sent;
    };

    // Governance follow-up (#4153 round 4, same shape as the pagers+drainer test above -
    // see its comments for the full rationale and the empirical two-sided proof this
    // design is safe: a suppressed producers_done count-down fails fast and attributed
    // instead of hanging, and a genuinely slow-but-healthy producer still completes
    // normally instead of being cut off early). `bounded_wait` gates only MAIN's own
    // wait for producers_done before the join below; `stoppable_wait` lets the persister
    // and drainer be cancelled, but ONLY via the failure path (bounded_wait's FAIL()
    // unwinding through `workers`' destructor) - never on the success path, since
    // nothing here requests any worker's stop_token before producers_done is confirmed.
    const auto bounded_wait = [](auto&& ready, const char* what) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
        while (!ready()) {
            if (std::chrono::steady_clock::now() >= deadline)
                FAIL("timed out after 30s waiting for " << what);
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
    };
    // Governance follow-up (#4153 round 4 continued): unlike the pagers test's use of
    // this same helper (a one-shot latch check, coarse interval is fine), the persister
    // below uses this repeatedly as an interleaving GATE - a std::stop_callback bridging
    // request_stop() to pruner_passes.notify_all() was tried and reverted here: it does
    // NOT work, because std::atomic<T>::wait(old) is specified to re-compare against
    // `old` on every wakeup and re-block if the value hasn't actually changed - a notify
    // with no value change is silently absorbed and never returns control to the caller
    // (empirically confirmed: the persister hung past its own bounded_wait's 30s FAIL,
    // needing the external kill). A poll is therefore the only viable stoppable
    // mechanism here; this overload takes an explicit interval so the persister can use
    // one far finer than the pagers test's one-shot 5ms default, since a coarse interval
    // here would blur the persist/prune interleaving this test exists to exercise.
    const auto stoppable_wait = [](auto&& ready, PortableStopToken stoken,
                                   std::chrono::microseconds poll = std::chrono::milliseconds{5}) {
        while (!ready()) {
            if (stoken.stop_requested())
                return false;
            std::this_thread::sleep_for(poll);
        }
        return true;
    };

    std::vector<PortableJThread> workers;
    // Pagers: page_into_window (paging_mutex_ -> the fake store's own mutex).
    for (int p = 0; p < 2; ++p)
        workers.emplace_back([&, p] {
            std::int64_t t = kBaseTs + p * 1000;
            for (int i = 0; i < kIters; ++i) {
                rig.journal->page_into_window(*rig.rt, t);
                t += 10'000;
            }
            producers_done.count_down();
        });
    // Pruner: prune() (paging_mutex_ -> the store) - the FR5 prune-vs-paging
    // serialization this test exists to exercise under TSan. Publishes its own pass
    // count so the persister below can genuinely interleave with it, instead of racing
    // to finish first. NOT a blocking wait/notify pair as of #4153 round 4 - see the
    // persister's own comment for why - so this fetch_add is the only reader that
    // matters; the notify has no waiter to wake and is deliberately not sent.
    workers.emplace_back([&] {
        std::int64_t t = kBaseTs;
        for (int i = 0; i < kIters; ++i) {
            rig.journal->prune(t);
            t += 5'000;
            pruner_passes.fetch_add(1, std::memory_order_release);
        }
        producers_done.count_down();
    });
    // Persister: persist() (the store only, no paging_mutex_) - a single writer, as in
    // production (always under the engine mtx_); it races page/prune only on the
    // shared store + atomics. Three tranches gated on the pruner's OWN pass count via a
    // fine-grained stoppable_wait poll (50us, not this file's usual 5ms), so count-
    // eviction interleaves with writes closely enough to still exercise the property
    // under test, rather than one finishing before the other starts. NOT a blocking
    // atomic::wait()/notify_all() pair: that shape was tried in this exact spot and
    // empirically reverted - std::atomic<T>::wait(old) re-compares against `old` on
    // every wakeup and re-blocks if the value hasn't actually changed, so a stop_token-
    // triggered notify_all() with no real value change is silently absorbed and never
    // returns control to the caller (confirmed: the persister hung past its own 30s
    // bounded_wait FAIL(), needing an external kill). A poll is the only mechanism here
    // that is both genuinely stoppable and doesn't require mutating pruner_passes with
    // an artificial sentinel value.
    workers.emplace_back([&](PortableStopToken stoken) {
        int n = 0;
        const auto persist_one = [&] {
            std::vector<std::shared_ptr<const JournalRecord>> pending{
                std::make_shared<const JournalRecord>(JournalRecord{
                    .rule_id = "w" + std::to_string(n), .generation = 1,
                    .event_id = "we-" + std::to_string(n),
                    .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                    .guard_type = "file", .rule_name = "n"})};
            if (rig.journal->persist(pending, nullptr, kJournalPersistUnbounded,
                                     kJournalPersistUnbounded) == 1)
                persist_successes.fetch_add(1, std::memory_order_relaxed);
            ++n;
        };
        const auto wait_for_pass = [&](int target) {
            return stoppable_wait(
                [&] { return pruner_passes.load(std::memory_order_acquire) >= target; },
                stoken, std::chrono::microseconds{50});
        };
        for (int i = 0; i < kPersistTotal / 3; ++i)
            persist_one();
        if (!wait_for_pass(1))
            return; // request_stop() fired before the pruner reached pass 1
        for (int i = 0; i < kPersistTotal / 3; ++i)
            persist_one();
        if (!wait_for_pass(2))
            return;
        while (n < kPersistTotal)
            persist_one();
        producers_done.count_down();
    });
    // Drainer. Stoppable for the same reason and under the same success-path guarantee
    // as the pagers test's drainer above.
    workers.emplace_back([&](PortableStopToken stoken) {
        while (!producers_done.try_wait() && !stoken.stop_requested())
            rig.rt->drain(send);
        rig.rt->drain(send); // final drain
    });

    for (int i = 0; i < 60; ++i)
        rig.journal->page_into_window(*rig.rt, kBaseTs + 500'000 + i * 1000);

    // Bounds how long main then waits for all four producers to genuinely finish - it
    // does NOT gate their own completion on anything main does, and nothing here
    // requests any worker's stop_token on this (the success) path. If it never
    // releases (a future regression dropping a producers_done.count_down() call), the
    // FAIL() below unwinds through `workers`' destructor, which cancels the stoppable
    // persister and drainer before joining.
    bounded_wait([&] { return producers_done.try_wait(); },
                 "producers_done (a pager, the pruner, or the persister never completed)");
    for (auto& w : workers)
        w.join();

    INFO("fake store ops=" << rig.store->ops() << " contended=" << rig.store->contended());
    CHECK(persist_successes.load(std::memory_order_relaxed) == kPersistTotal);
    CHECK(rig.journal->batches_pruned() > 0); // BEFORE the settle prune below
    CHECK(rig.journal->records_paged() > 0);
    CHECK(sends.load(std::memory_order_relaxed) > 0);
    CHECK(rig.journal->sent_labels_written() > 0);

    // request_stop() comes AFTER the settle prune below, not before it. Calling it first made
    // that prune return at its shutdown gate without doing anything, so the rebase the
    // assertions depend on never happened and they were checking gauges that had merely
    // survived the concurrent run - passing or flaking on the documented transient
    // double-count interleaving rather than on the property this test is named for
    // (#2345 round 7, Sol). The workers are already joined, so nothing races this.
    //
    // Beyond race-freedom (TSan): the running-counter gauges (#2303) must stay ACCOUNTING-correct
    // under the real concurrent persist/prune interleaving, not just data-race-free. A final
    // settle prune rebases to on-disk truth; the
    // gauges must then exactly equal what namespace_size sees on disk - proving no lost update
    // and no drift accumulated across the concurrent run (deterministic single-threaded pin:
    // test_guardian_lifecycle_journal.cpp's "rebase-as-delta preserves a concurrent persist's
    // increment" case).
    rig.journal->prune(kBaseTs + 900'000);
    rig.journal->request_stop();
    auto sz = rig.store->namespace_size(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(sz.has_value());
    CHECK(rig.journal->journal_batch_count() == sz->count);
    CHECK(rig.journal->journal_bytes() == sz->bytes);
    CHECK(rig.journal->gauge_underflow() == 0); // never fell into the fail-open underflow window
}

TEST_CASE("erase_persisted_prefix identifies the prefix it wrote, not an index",
          "[spark][runtime][journal][chaos]") {
    // snapshot_pending() releases outbox_mu_, persist() does its KvStore I/O unlocked, and the
    // erase re-takes the lock. If staging overflows in that window it drops from the FRONT, so
    // position 0 is no longer the record it was - and erasing by index deletes records that
    // were never written. Silent, uncounted destruction of audit evidence, worst exactly when
    // staging is full, i.e. when persist is already failing. RED before the fix: r4 and r5,
    // which were never persisted, are erased and lost.
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    for (int i = 0; i < 6; ++i)
        REQUIRE(rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                                file_exists_rule("r" + std::to_string(i)), true));
    REQUIRE(rt->pending_journal_depth() == 6);

    const auto snap = rt->snapshot_pending();
    const auto drops = snap.drops_at_snapshot;
    REQUIRE(snap.records.size() == 6);

    // ...persist commits the first 4. Meanwhile two overflow drops take r0 and r1 off the front.
    rt->drop_oldest_pending_for_test(2);
    REQUIRE(rt->pending_journal_depth() == 4); // r2..r5

    rt->erase_persisted_prefix(4, drops);
    // r0 and r1 are already gone and r2, r3 were the rest of the persisted prefix, so exactly
    // r4 and r5 - never written - must SURVIVE to be retried.
    REQUIRE(rt->pending_journal_depth() == 2);
    const auto left = rt->snapshot_pending().records;
    CHECK(left[0]->rule_id == "r4");
    CHECK(left[1]->rule_id == "r5");
}

TEST_CASE("erase_persisted_prefix erases nothing when drops already exceeded the prefix",
          "[spark][runtime][journal][chaos]") {
    // The far end of the same seam, and the dangerous one. If MORE records were dropped from
    // the front than persist durably wrote, the whole persisted prefix is already gone and
    // there is nothing left to erase. Without the early return, `n -= dropped_since` wraps a
    // size_t to an enormous value, std::min clamps it to the buffer size, and the erase takes
    // the ENTIRE remaining staging buffer - every record staged but never written. That is
    // silent audit-record destruction, and it is worst exactly when it is most likely: staging
    // only overflows when persist is already failing.
    // RED before the fix: pending_journal_depth() == 0 - everything still waiting is destroyed.
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    for (int i = 0; i < 6; ++i)
        REQUIRE(rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                                file_exists_rule("r" + std::to_string(i)), true));

    const auto snap = rt->snapshot_pending();
    const auto drops = snap.drops_at_snapshot;
    REQUIRE(snap.records.size() == 6);

    // persist committed 3 (r0..r2). Meanwhile FIVE overflow drops took r0..r4 off the front -
    // strictly more than the prefix that was written.
    rt->drop_oldest_pending_for_test(5);
    REQUIRE(rt->pending_journal_depth() == 1); // only r5 is left, and it was never persisted

    rt->erase_persisted_prefix(3, drops);
    REQUIRE(rt->pending_journal_depth() == 1); // untouched: nothing of the prefix remained
    const auto left = rt->snapshot_pending().records;
    REQUIRE(left.size() == 1);
    CHECK(left[0]->rule_id == "r5"); // the never-persisted record survives to be retried
}

TEST_CASE("#2298: the smallest-blocked scan stops issuing KvStore reads once stop is requested",
          "[spark][runtime][journal]") {
    // The min-blocked-headroom inner scan used to be pure in-memory arithmetic over
    // already-parsed batches. Once the value read became lazy it issues a KvStore point read
    // per remaining candidate - and can issue a quarantine rename - so at the 128-candidate
    // cap it is up to ~127 round trips, each able to block on the 5 s busy timeout, on the
    // very thread GuardianEngine::stop() joins while holding mtx_. That is the bounded-
    // shutdown invariant every other KvStore loop in this file already respects.
    //
    // RED without the gate: the scan reads every remaining candidate after the stop.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    const std::int64_t base_ts = 1'700'000'000'000;
    for (int i = 0; i < 10; ++i) {
        const std::string key =
            journal_batch_key(base_ts + i, "aaa", static_cast<std::uint64_t>(i));
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(base_ts + i) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":"e)" + std::to_string(i) +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
    }
    // Fill the window completely so the FIRST candidate blocks at headroom 0 and the inner
    // smallest-blocked scan is entered.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);

    // Land the stop while the pass is between candidates: the outer loop has already passed
    // its own gate for candidate 0, so candidate 0 is processed and the inner scan IS
    // entered - which is exactly the window this gate has to cover.
    rig.journal->set_post_classify_hook_for_test([&] { rig.journal->request_stop(); });

    const auto before = rig.journal->candidate_value_fetches_for_test();
    const auto stats = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    const auto fetched = rig.journal->candidate_value_fetches_for_test() - before;

    CHECK(stats.headroom_blocked);   // it did reach the blocked branch...
    CHECK(fetched == 1);             // ...and read ONLY the candidate it was already holding
    // The reported requirement stays conservative (seeded from the blocked candidate's own
    // need), so an early break costs a later re-arm, never a wrong-sized one.
    CHECK(stats.min_blocked_headroom >= 1);
}

TEST_CASE("#2364 episode: a STALE clean-key cannot complete coverage on a failed-read pass",
          "[spark][runtime][journal]") {
    // The DISCRIMINATING form of the read-failure guard (governance Gate 3 QE showed the
    // first attempt was not one). The per-candidate rule - a failed-read candidate is never
    // note_clean'd - is not enough on its own, because the coverage set is CROSS-PASS: a key
    // banked by an earlier pass is still in it. So the shape that matters is a pass where
    // every CURRENT candidate is already covered from before, and the only thing this pass
    // learned is that it could not read one of them. Without the footer's pass-level
    // `!value_read_failed` term that pass clears a live episode on stale evidence.
    //
    // Verified by mutation: deleting `!value_read_failed` from the footer turns this red.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string kept = write_batch("aaa", 0, base_ts - 1'000, "e-kept");
    const std::string doomed = write_batch("bbb", 0, base_ts, "e-doomed");

    // Start an episode: fill the window so the oldest candidate cannot place.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);
    REQUIRE(rig.journal->page_into_window(*rig.rt, base_ts + 50'000).headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);
    (void)drain_lifecycle(*rig.rt); // room again, so nothing blocks from here

    // PASS A - bank a clean key for `kept` while leaving `doomed` uncovered, so the episode
    // survives with a non-empty coverage set. `kept` is sent-labelled, so it is skipped (and
    // banked) without any value read; `doomed` is not, so it IS read - and that read fails.
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(kept), ""));
    rig.journal->inject_value_read_failures_for_test(1);
    const auto a = rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    CHECK_FALSE(a.headroom_blocked);
    CHECK(a.skipped_already_sent == 1);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() == since); // still live

    // Retention removes `doomed`. The coverage set now holds a key for every remaining
    // candidate - but it was banked two passes ago, not by the pass that is about to run.
    REQUIRE(rig.kv->del(kJournalNamespace, doomed));

    // PASS B - forced, so the sent-label is ignored and `kept` is actually READ. That read
    // fails. The pass therefore learned nothing about whether `kept` waits on headroom, and
    // must not clear the episode on the strength of pass A's stale entry.
    rig.journal->inject_value_read_failures_for_test(1);
    const auto b = rig.journal->page_into_window(*rig.rt, base_ts + 170'000, /*replay_sent=*/true);
    CHECK_FALSE(b.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since); // NOT cleared
    CHECK(rig.journal->page_read_failures() >= 2);

    // With the read working again the same pass shape does clear it, so the guard is
    // withholding the clear rather than breaking it.
    const auto c = rig.journal->page_into_window(*rig.rt, base_ts + 230'000, /*replay_sent=*/true);
    CHECK_FALSE(c.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}

// ── rung 9c R5.2: per-key claim/queue (happy path) ─────────────────────────────
// Each case names the mutation that makes it RED (recorded in the PR's mutation table).

namespace {
/// Park a thread's attach_rule on `key` behind a parked head and prove it queued.
struct QueuedAttach {
    std::thread t;
    std::expected<std::uint64_t, std::string> gen;
    ~QueuedAttach() {
        if (t.joinable())
            t.join();
    }
};
} // namespace

TEST_CASE("rung 9c R5.2: three concurrent same-key attaches produce ONE backend arm and "
          "three distinct generations sharing it",
          "[spark][runtime][liveness]") {
    // Mutation: dispatch a backend arm per claim -> arm_entries == 3.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1, a2, a3;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    a3.t = std::thread{[&] { a3.gen = rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 2; },
                                   std::chrono::seconds(10)));
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 3);
    CHECK(b->arm_entries.load() == 1);

    b->release_hang();
    a1.t.join();
    a2.t.join();
    a3.t.join();
    REQUIRE(a1.gen.has_value());
    REQUIRE(a2.gen.has_value());
    REQUIRE(a3.gen.has_value());
    CHECK(*a1.gen != *a2.gen);
    CHECK(*a2.gen != *a3.gen);
    CHECK(b->arm_entries.load() == 1);
    CHECK(b->arms.load() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 3);
    CHECK(drain_lifecycle(*rt).size() == 3);
}

TEST_CASE("rung 9c R5.2: the head's backend REFUSAL fails every queued sibling with it and "
          "leaves the key clean",
          "[spark][runtime][liveness]") {
    // Mutation: forget the siblings' index release on failure -> the fresh attach
    // below never sees the 0->1 edge (arm_entries stays 1).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1, a2;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));

    b->fail_arm = true; // the parked arm returns unexpected("no mechanism") once released
    b->release_hang();
    a1.t.join();
    a2.t.join();
    b->fail_arm = false;
    REQUIRE_FALSE(a1.gen.has_value());
    REQUIRE_FALSE(a2.gen.has_value());
    CHECK(a1.gen.error() == "no mechanism");
    CHECK(a2.gen.error() == "no mechanism");
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
    CHECK(drain_lifecycle(*rt).empty());

    // The key is genuinely clean: a fresh attach under a NEW rule id sees the 0->1
    // edge and arms (a re-push of r1/r2 would clean its own stale mapping through its
    // prior-generation detach and mask a leaked sibling entry).
    REQUIRE(rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true));
    CHECK(b->arm_entries.load() == 2);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("rung 9c R5.2: the head's backend THROW fails every queued sibling with "
          "\"arm worker threw\"",
          "[spark][runtime][liveness]") {
    // Mutation: deliver only the head's failure and leave the sibling queued -> a2 rides
    // out its deadline ("arm timed out") instead.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1, a2;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));

    b->throw_arm = true;
    b->release_hang();
    a1.t.join();
    a2.t.join();
    b->throw_arm = false;
    REQUIRE_FALSE(a1.gen.has_value());
    REQUIRE_FALSE(a2.gen.has_value());
    CHECK(a1.gen.error() == "arm worker threw");
    CHECK(a2.gen.error() == "arm worker threw");
    CHECK(rt->rule_count() == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
}

TEST_CASE("rung 9c R5.2: detaching a QUEUED sibling before the head completes withdraws "
          "it promptly; the others commit",
          "[spark][runtime][liveness]") {
    // Mutation: skip erasing a withdrawn Queued claim -> r2's attach rides out its
    // deadline instead of returning "withdrawn" at once.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1, a2, a3;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    a3.t = std::thread{[&] { a3.gen = rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 2; },
                                   std::chrono::seconds(10)));

    const auto t0 = clk::now();
    rt->detach_rule("r2"); // queued, never dispatched: erased outright, waiter woken
    a2.t.join();
    CHECK(clk::now() - t0 < std::chrono::seconds(5));
    REQUIRE_FALSE(a2.gen.has_value());
    CHECK(a2.gen.error() == "withdrawn");
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 2);

    b->release_hang();
    a1.t.join();
    a3.t.join();
    REQUIRE(a1.gen.has_value());
    REQUIRE(a3.gen.has_value());
    CHECK(rt->rule_count() == 2);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);
    CHECK(drain_lifecycle(*rt).size() == 2); // r1 + r3 armed; r2 never armed, no entry
}

TEST_CASE("rung 9c R5.2: a withdrawn HEAD with a live sibling: the sibling adopts the "
          "subscription, nothing is disarmed",
          "[spark][runtime][liveness]") {
    // Mutation: always disarm when the head is withdrawn -> disarms == 1 and r2 fails.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1, a2;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));

    rt->detach_rule("r1"); // the dispatched head: withdrawn in place, stays as the marker
    a1.t.join();
    REQUIRE_FALSE(a1.gen.has_value());
    CHECK(a1.gen.error() == "withdrawn");
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 2); // marker + r2

    b->release_hang();
    a2.t.join();
    REQUIRE(a2.gen.has_value());
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);   // adopted, not disarmed
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->backend_op_late_arms() == 0);
    const auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].rule_id == "r2");
}

TEST_CASE("rung 9c R5.2: an arm that arrives while the key's DISARM is in flight queues "
          "behind it - the disarm completes before the rearm dispatches",
          "[spark][runtime][liveness]") {
    // Mutation: dispatch the arm without checking the claim entry -> arm_entries == 2
    // while the disarm is still parked.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(b->arm_entries.load() == 1);

    b->hang_next_disarm.store(true);
    std::thread d_thread{[&] { rt->detach_rule("r1"); }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_disarm_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &d_thread};
    REQUIRE(b->wait_entered_disarm_hang(std::chrono::seconds(30)));

    QueuedAttach a2;
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // before asserting a negative
    CHECK(b->arm_entries.load() == 1); // the rearm has NOT entered the backend

    b->release_disarm_hang();
    d_thread.join();
    a2.t.join();
    REQUIRE(a2.gen.has_value());
    CHECK(b->arm_entries.load() == 2);
    CHECK(b->disarms.load() == 1);
    REQUIRE(b->disarmed_ids().size() == 1);
    REQUIRE(b->armed_ids().size() == 2);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]); // r1's watcher went before r2's came
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("rung 9c R5.2: a same-key REDEPLOY queues its own rearm behind its own disarm, "
          "and a third rule racing that gap queues behind both",
          "[spark][runtime][liveness]") {
    // Astra 7a: the disarm claim is reserved in the SAME critical section that erases
    // keys_[key], so nothing can slip an arm in ahead of the teardown. Mutation: create
    // the disarm claim off-lock (after detach_rule_locked returns) -> r2 can take the
    // 0->1 edge first and arm_entries reaches 2 while the disarm is still parked.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));

    b->hang_next_disarm.store(true);
    QueuedAttach re1; // r1 re-pushed onto the SAME key
    re1.t = std::thread{[&] { re1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_disarm_hang(); }
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_disarm_hang(std::chrono::seconds(30)));

    QueuedAttach a2;
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 2; },
                                   std::chrono::seconds(10))); // r1's rearm + r2
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 3); // disarm, r1, r2
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(b->arm_entries.load() == 1);

    b->release_disarm_hang();
    re1.t.join();
    a2.t.join();
    REQUIRE(re1.gen.has_value());
    REQUIRE(a2.gen.has_value());
    CHECK(b->arm_entries.load() == 2);  // the original + ONE rearm shared by r1 and r2
    CHECK(b->disarms.load() == 1);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->rule_count() == 2);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("rung 9c R5.2: a disarm the executor refuses at admission is RETAINED at the "
          "head and re-driven by the next same-key attach, before that attach's own arm",
          "[spark][runtime][liveness]") {
    // Closes the #3415 silent-drop gap. Mutation: drop the claim on a non-Timeout,
    // non-Stopped refusal -> disarms stays 0 forever and the rearm goes first.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));

    rt->set_io_executor_fail_launch_for_test(true); // LaunchFailed at admission
    rt->detach_rule("r1");
    rt->set_io_executor_fail_launch_for_test(false);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->disarm_entries.load() == 0);
    CHECK(rt->disarm_retained() == 1);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1); // retained head
    CHECK(rt->io_executor_stats_for_test().counters[0].launch_failures == 1);

    // The next same-key event re-drives it: the retained disarm executes FIRST, then
    // the new arm dispatches.
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(b->disarms.load() == 1);
    CHECK(b->arms.load() == 2);
    REQUIRE(b->disarmed_ids().size() == 1);
    REQUIRE(b->armed_ids().size() == 2);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);
}

TEST_CASE("rung 9c R5.2 (governance Gate 4 hp-1): a rule re-pushed from one key onto ANOTHER "
          "key that holds a RETAINED disarm drives BOTH its prior-key disarm and the target "
          "key's retained disarm before its own arm",
          "[spark][runtime][liveness]") {
    // Mutation: attach_rule drives prior_disarm OR head_to_drive (an else-if) -> the
    // target key's retained disarm is never re-driven by this call, the new arm claim
    // waits behind it until the deadline and the push fails "arm timed out".
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::milliseconds(300)});
    // Key /b: r1 armed, then its disarm refused at admission -> a RETAINED disarm head.
    REQUIRE(rt->attach_rule("r1", file_spec("/b"), file_exists_rule("r1"), true));
    rt->set_io_executor_fail_launch_for_test(true); // LaunchFailed at admission
    rt->detach_rule("r1");
    rt->set_io_executor_fail_launch_for_test(false);
    REQUIRE(rt->disarm_retained() == 1);
    REQUIRE(rt->claim_queue_depth_for_test(spark_key(file_spec("/b"))) == 1);
    // Key /a: r2 armed.
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    REQUIRE(b->arms.load() == 2);
    // r2 re-pushed onto /b: its prior generation on /a owes a disarm (prior_disarm)
    // AND /b's head is the retained disarm (head_to_drive). Both must run before
    // r2's arm on /b dispatches.
    const auto gen = rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true);
    REQUIRE(gen);
    CHECK(b->disarms.load() == 2);
    CHECK(b->arms.load() == 3);
    REQUIRE(b->armed_ids().size() == 3);
    REQUIRE(b->disarmed_ids().size() == 2);
    const auto disarmed = b->disarmed_ids();
    const auto armed = b->armed_ids();
    // Both stale watchers are gone (r1's on /b, r2's on /a); the new /b watcher is live.
    CHECK(std::find(disarmed.begin(), disarmed.end(), armed[0]) != disarmed.end());
    CHECK(std::find(disarmed.begin(), disarmed.end(), armed[1]) != disarmed.end());
    CHECK(std::find(disarmed.begin(), disarmed.end(), armed[2]) == disarmed.end());
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/b"))) == 0);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);
}

TEST_CASE("rung 9c R5.2: begin_stop() wakes queued siblings promptly with \"stopping\" and "
          "counts them; the dispatched head is left to its callback",
          "[spark][runtime][liveness]") {
    // Mutation: forget claim_cv_.notify_all() in begin_stop -> the siblings ride out
    // their 30 s deadline.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1, a2, a3;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    a3.t = std::thread{[&] { a3.gen = rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 2; },
                                   std::chrono::seconds(10)));

    const auto t0 = clk::now();
    rt->begin_stop();
    a1.t.join();
    a2.t.join();
    a3.t.join();
    CHECK(clk::now() - t0 < std::chrono::seconds(5));
    REQUIRE_FALSE(a1.gen.has_value());
    REQUIRE_FALSE(a2.gen.has_value());
    REQUIRE_FALSE(a3.gen.has_value());
    CHECK(a1.gen.error() == "stopping");
    CHECK(a2.gen.error() == "stopping");
    CHECK(a3.gen.error() == "stopping");
    CHECK(rt->claims_dropped_at_stop() == 2); // the two QUEUED ones; the head is dispatched
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1);

    // The head's late success is disarmed by its callback (R5.5), never left live.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; }, std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until(
        [&] { return rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0; },
        std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
}

TEST_CASE("rung 9c R5.2: a commit throw in the drain surfaces on the head's waiter, fails "
          "the sibling, disarms the subscription once, and leaves the key clean",
          "[spark][runtime][liveness]") {
    // The moved C2/c2 shape. Mutation: omit the catch-block publish/erase in
    // on_arm_complete -> the fresh attach below queues behind a dead head and times out.
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    std::exception_ptr thrown;
    std::thread a1{[&] {
        try {
            (void)rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        } catch (...) {
            thrown = std::current_exception();
        }
    }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    QueuedAttach a2;
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));

    rt->set_pending_initial_waker(ThrowOnCopy{}); // the FIRST commit's waker copy throws
    b->release_hang();
    a1.join();
    a2.t.join();
    rt->set_pending_initial_waker({});
    REQUIRE(thrown);
    CHECK_THROWS_AS(std::rethrow_exception(thrown), std::runtime_error);
    REQUIRE_FALSE(a2.gen.has_value());
    CHECK(a2.gen.error() == "arm commit failed");
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 1); // the compensating disarm ran BEFORE the waiter woke
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
    CHECK(drain_lifecycle(*rt).empty()); // no phantom "armed"

    // Runtime is still healthy: a fresh attach arms cleanly.
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("rung 9c R5.2: a rule re-pushed onto ANOTHER key while its old-key claim is in "
          "flight keeps its new mapping when the old claim finishes (index ownership)",
          "[spark][runtime][liveness]") {
    // Astra 7d: index_->remove_rule() removes the CURRENT mapping with no generation
    // check, so a stale claim must never release a replacement's mapping. Mutation:
    // remove the index_held guard (call index_->remove_rule unconditionally in the
    // drain) -> the final detach_rule("r1") finds no key and disarms nothing.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // r1 moves to "/b" (its "/a" claim is withdrawn in place; "/b" arms instantly).
    REQUIRE(rt->attach_rule("r1", file_spec("/b"), file_exists_rule("r1"), true));
    a1.t.join();
    REQUIRE_FALSE(a1.gen.has_value());
    CHECK(a1.gen.error() == "withdrawn");
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);

    b->release_hang(); // the old "/a" arm lands: nobody wants it -> disarmed
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; }, std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until(
        [&] { return rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0; },
        std::chrono::seconds(10)));
    CHECK(b->arms.load() == 2);
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);

    // r1's LIVE mapping ("/b") survived the old claim's cleanup: detaching it disarms
    // the "/b" watcher. rung 9c PR-2 Unit 3: observed asynchronously (non-blocking
    // submit_disarm_off_lock()).
    rt->detach_rule("r1");
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 2; },
                                   std::chrono::seconds(10)));
    CHECK(rt->armed_key_count() == 0);
}

TEST_CASE("rung 9c R5.2 / #4147: a parked completion callback keeps the F3 count "
          "(active_backend_op_workers) nonzero after the quota slot has released",
          "[spark][runtime][liveness]") {
    // GuardianEngine::active_io_workers() sums active_backend_op_workers()
    // (guardian_engine.cpp) - this pins the input to that sum across the post-fn()
    // window: the drain fires the wakers with the callback thread still alive and no
    // quota held. Mutation: report quota_held_total from active_worker_count() -> 0.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    std::mutex gate_mu;
    std::condition_variable gate_cv;
    bool release = false;
    std::atomic<bool> parked{false};
    rt->set_pending_initial_waker([&] {
        parked.store(true);
        std::unique_lock<std::mutex> lk{gate_mu};
        gate_cv.wait(lk, [&] { return release; });
    });
    // The waiter returns once the outcome publishes (step 3 of the drain), BEFORE the
    // waker parks (step 4), so this returns while the callback thread is still alive.
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(yuzu::test::spin_until([&] { return parked.load(); }, std::chrono::seconds(10)));
    CHECK(rt->active_backend_op_workers() == 1);
    const auto io = rt->io_executor_stats_for_test();
    CHECK(io.active_total == 1);
    CHECK(io.quota_held_total == 0);
    {
        std::lock_guard<std::mutex> lk{gate_mu};
        release = true;
    }
    gate_cv.notify_all();
    REQUIRE(yuzu::test::spin_until([&] { return rt->active_backend_op_workers() == 0; },
                                   std::chrono::seconds(10)));
    rt->set_pending_initial_waker({});
}

TEST_CASE("rung 9c R5.2: rapid attaches on distinct keys all commit (the callback may run "
          "before submit() returns)",
          "[spark][runtime][liveness]") {
    // Coverage for the dispatcher's "mark Dispatched only if still the Dispatching head"
    // guard under an instant backend, where the completion routinely lands before
    // dispatch_arm_off_lock re-locks. No single mutation isolates the guard (its
    // failure mode is a stale write onto a successor claim); kept as a churn check.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    for (int i = 0; i < 200; ++i) {
        const auto rid = "r" + std::to_string(i);
        REQUIRE(rt->attach_rule(rid, file_spec("/k" + std::to_string(i)), file_exists_rule(rid), true));
    }
    CHECK(rt->rule_count() == 200);
    CHECK(rt->armed_key_count() == 200);
    CHECK(b->arms.load() == 200);
    for (int i = 0; i < 200; ++i)
        CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/k" + std::to_string(i)))) == 0);
    rt->detach_all();
    // rung 9c R5.2 (governance qe-303): detach_all() submits each key's disarm
    // sequentially and does NOT redrive an admission-refused claim - there is no
    // redrive timer in PR-1, and nothing else touches these 200 distinct keys again
    // after this call, so a claim refused at admission (CapacityExhausted etc, the
    // class quota exhausted by workers still draining under contention) stays
    // retained forever rather than eventually landing in disarms. The two counters
    // are a strict partition of the 200 claims: every claim's disarm either actually
    // ran (disarms) or was refused-and-retained with nothing to re-drive it
    // (disarm_retained()) - CHECK(disarms == 200) is a guarantee this design never
    // made and is a proven false invariant under CPU contention (observed under
    // TSan+starvation: as few as 4/200 actually dispatched). Asserting the sum
    // pins the real contract instead of masking ch-202's retention mechanism.
    //
    // rung 9c PR-2 Unit 3: detach_all() dispatches every disarm off-lock
    // (submit_disarm_off_lock) and returns once each is ADMITTED, not once its
    // backend call physically finishes - a disarm that was admitted but has not
    // yet completed is in NEITHER bucket for a brief window (not in `disarms`
    // until its own completion callback runs, not in disarm_retained() since it
    // was never refused). The partition above is still exactly right; it just
    // is not necessarily true the INSTANT detach_all() returns any more. Settle
    // on it rather than asserting immediately - once true it stays true (the
    // comment above already establishes neither bucket ever un-counts a claim).
    REQUIRE(yuzu::test::spin_until(
        [&] { return b->disarms.load() + rt->disarm_retained() == 200; },
        std::chrono::seconds(10)));
    CHECK(b->disarms.load() + rt->disarm_retained() == 200);
    CHECK(rt->armed_key_count() == 0);
}

// ---------------------------------------------------------------------------
// rung 9c R5.2 - adversarial-review fix round (C1/K1'): the commit-to-publish gap.
// Both tests install the drain's gap hook and park in it. With the fix an ADOPTED
// commit publishes and pops inside its own critical section and never reaches the
// gap (CHECK_FALSE(park->entered)); the RED mutation (skip the in-step-(1) publish,
// i.e. comment out `if (!compensating) publish_locked(false);`) reopens the window,
// the drain parks, and the racing attach / detach lands inside it.
namespace {
struct DrainPark {
    std::mutex m;
    std::condition_variable cv;
    bool released{false};
    std::atomic<bool> entered{false};
    void wait() {
        entered.store(true);
        std::unique_lock<std::mutex> l{m};
        cv.wait(l, [&] { return released; });
    }
    void release() {
        {
            std::lock_guard<std::mutex> l{m};
            released = true;
        }
        cv.notify_all();
    }
};
} // namespace

TEST_CASE("rung 9c R5.2 (adversarial review C1/K1'): an adopted commit is published inside "
          "its own critical section - a same-key attach arriving right after it JOINS the "
          "watcher instead of queuing behind a committed head and re-arming",
          "[spark][runtime][liveness]") {
    // Mutation: skip the in-step-(1) publish -> the drain parks in the gap with keys_[K]
    // written and the head still claimed; r2 queues, the refill re-arms: arm_entries == 2
    // and a second subscription id that no detach can ever reach.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    auto park = std::make_shared<DrainPark>();
    struct Cleanup {
        FakeBackend* backend;
        DrainPark* park;
        ~Cleanup() {
            backend->release_hang();
            park->release();
        }
    } cleanup{b.get(), park.get()};
    rt->set_drain_gap_hook_for_test([park] { park->wait(); });
    const auto key = spark_key(file_spec("/a"));

    std::atomic<bool> a1_done{false}, a2_done{false};
    std::exception_ptr a2_threw; // RED: r2's redundant re-arm hits the keys_.emplace hard error
    QueuedAttach a1, a2;
    a1.t = std::thread{[&] {
        a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        a1_done.store(true);
    }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    b->release_hang(); // the drain runs: fixed -> publishes in (1b) and a1 returns; RED -> parks
    REQUIRE(yuzu::test::spin_until([&] { return park->entered.load() || a1_done.load(); },
                                   std::chrono::seconds(10)));

    a2.t = std::thread{[&] {
        try {
            a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
        } catch (...) {
            a2_threw = std::current_exception();
        }
        a2_done.store(true);
    }};
    // Fixed: r2 joins the committed watcher at once. RED: r2 queues behind the head.
    REQUIRE(yuzu::test::spin_until(
        [&] { return a2_done.load() || rt->claim_queue_depth_for_test(key) >= 2; },
        std::chrono::seconds(10)));
    park->release();
    a1.t.join();
    a2.t.join();
    rt->set_drain_gap_hook_for_test({});

    CHECK_FALSE(park->entered.load()); // an adopted commit never reaches the gap
    CHECK(b->arm_entries.load() == 1);  // RED: 2 - the refill re-armed the committed key
    CHECK_FALSE(a2_threw);              // RED: keys_.emplace hard error surfaced on r2
    REQUIRE(a1.gen.has_value());
    REQUIRE(a2.gen.has_value());
    REQUIRE(b->armed_ids().size() == 1);
    CHECK(rt->rule_count() == 2);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    // Both rules share the ONE subscription: the ->0 edge disarms exactly that id, once.
    rt->detach_rule("r1");
    CHECK(b->disarm_entries.load() == 0); // sibling remains -> no disarm at all; race-free
    rt->detach_rule("r2");
    // rung 9c PR-2 Unit 3: the ->0 edge's disarm dispatches off-lock through
    // non-blocking submit_disarm_off_lock() - observed asynchronously.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarm_entries.load() == 1; },
                                   std::chrono::seconds(10)));
    REQUIRE(b->disarmed_ids().size() == 1);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->armed_key_count() == 0);
}

TEST_CASE("rung 9c R5.2 (adversarial review C1/K1'): a detach arriving right after the commit "
          "disarms the LIVE rule - a committed claim can never be matched as a pending arm",
          "[spark][runtime][liveness]") {
    // Mutation: skip the in-step-(1) publish -> detach_rule_locked's Case-0 matches the
    // still-present committed head, publishes "withdrawn" for a rule that is live in
    // rules_/keys_, and disarms nothing: a1 returns "withdrawn" and disarm_entries == 0.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    auto park = std::make_shared<DrainPark>();
    struct Cleanup {
        FakeBackend* backend;
        DrainPark* park;
        ~Cleanup() {
            backend->release_hang();
            park->release();
        }
    } cleanup{b.get(), park.get()};
    rt->set_drain_gap_hook_for_test([park] { park->wait(); });
    const auto key = spark_key(file_spec("/a"));

    std::atomic<bool> a1_done{false}, d_done{false};
    QueuedAttach a1;
    a1.t = std::thread{[&] {
        a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        a1_done.store(true);
    }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return park->entered.load() || a1_done.load(); },
                                   std::chrono::seconds(10)));

    std::thread dt{[&] {
        rt->detach_rule("r1");
        d_done.store(true);
    }};
    REQUIRE(yuzu::test::spin_until([&] { return d_done.load(); }, std::chrono::seconds(10)));
    park->release();
    a1.t.join();
    dt.join();
    rt->set_drain_gap_hook_for_test({});

    CHECK_FALSE(park->entered.load());
    REQUIRE(a1.gen.has_value()); // RED: "withdrawn" for a rule that was actually armed
    REQUIRE(b->armed_ids().size() == 1);
    // rung 9c PR-2 Unit 3: detach_rule() (dt, above) returns once its disarm is
    // ADMITTED (submit_disarm_off_lock), not once the backend call physically
    // finishes - settle on the disarm's own observable effect before asserting it,
    // rather than assuming d_done implies completion.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarmed_ids().size() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarm_entries.load() == 1);
    REQUIRE(b->disarmed_ids().size() == 1);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
}

// rung 9c R5.2 - adversarial-review fix round (C2/K5): the drain's subscription
// ownership guard must exist before any fallible work, and a throw after the commit
// adopted the subscription must still publish a TRUTHFUL verdict.
TEST_CASE("rung 9c R5.2 (adversarial review C2/K5): a bad_alloc in the drain before the fifo "
          "snapshot never leaks the successful arm - the firewall disarms it and the key stays "
          "usable",
          "[spark][runtime][liveness]") {
    // Mutation: take ownership only inside the success branch (the pre-fix order, after
    // the vectors are built) -> the firewall finds `compensating` empty: disarms == 0 and
    // the subscription is live with no owner.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const auto key = spark_key(file_spec("/a"));

    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->set_drain_fault_point_for_test(1); // bad_alloc before finished/live are built
    b->release_hang();
    a1.t.join();

    REQUIRE_FALSE(a1.gen.has_value());
    CHECK(a1.gen.error() == "arm drain failed");
    CHECK(rt->claim_drain_failures() == 1);
    CHECK(b->arms.load() == 1);
    REQUIRE(b->armed_ids().size() == 1);
    CHECK(b->disarms.load() == 1); // the firewall's last-resort disarm reclaimed it
    REQUIRE(b->disarmed_ids().size() == 1);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    CHECK(drain_lifecycle(*rt).empty()); // nothing committed, no phantom "armed"

    // Runtime is still healthy: a fresh attach arms cleanly (index_ was released).
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 2);
}

TEST_CASE("rung 9c R5.2 (adversarial review C2/K5): a throw after the first commit adopted the "
          "subscription publishes the TRUE verdict - the rule is live and its waiter gets its "
          "generation, not a failure",
          "[spark][runtime][liveness]") {
    // Mutation: drop the rules_-carries-this-generation check in the drain's publish
    // (always "arm drain failed") -> the waiter is told the arm failed while the rule
    // sits committed in rules_/keys_, and the engine's defensive detach would tear it
    // down: a1.gen is an error.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const auto key = spark_key(file_spec("/a"));

    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->set_drain_fault_point_for_test(2); // throw right after the commit adopted `sub`
    b->release_hang();
    a1.t.join();

    REQUIRE(a1.gen.has_value()); // truthful: the rule IS armed
    CHECK(rt->claim_drain_failures() == 1);
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0); // nothing to compensate: the subscription is owned by keys_
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    CHECK(drain_lifecycle(*rt).size() == 1); // the "armed" record the commit staged

    // The live rule is a normal rule: detaching it disarms exactly that subscription.
    // rung 9c PR-2 Unit 3: observed asynchronously (non-blocking submit_disarm_off_lock()).
    rt->detach_rule("r1");
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    REQUIRE(b->disarmed_ids().size() == 1);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->armed_key_count() == 0);
}

// rung 9c R5.2 - adversarial re-review r2 (C1, found by both reviewers): the DISARM
// claim is built and queued BEFORE the durable detach mutation (index_/rules_/keys_),
// so an allocation failure leaves the rule fully consistent and the subscription still
// owned by keys_ - never stranded with no rule, no index entry and no claim.
TEST_CASE("rung 9c R5.2 (adversarial re-review r2 C1): a bad_alloc building the disarm claim "
          "leaves the rule consistent - a retried detach disarms once and a fresh attach arms "
          "cleanly",
          "[spark][runtime][liveness]") {
    // Mutation (the pre-fix order): build the claim AFTER index_->remove_rule /
    // rules_.erase -> the throw strands the subscription in keys_: rule_count() reads 0
    // right after the throw, the retry finds nothing to disarm (disarms stays 0), and
    // the fresh attach fails on the keys_.emplace hard error.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->armed_ids().size() == 1);
    const auto key = spark_key(file_spec("/a"));

    rt->set_detach_fault_for_test(true);
    REQUIRE_THROWS_AS(rt->detach_rule("r1"), std::bad_alloc);

    // Nothing durable moved: the rule is still confirmed, the key still armed, no
    // half-built claim left behind, and no rollback was needed (the seam fires before
    // the erase).
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    CHECK(b->disarms.load() == 0);
    CHECK(rt->detach_claim_failures() == 0);

    // The retry succeeds and disarms exactly the armed subscription, once. rung 9c
    // PR-2 Unit 3: the disarm claim is dispatched off-lock through non-blocking
    // submit_disarm_off_lock(), and popped from the fifo by its own completion
    // callback - both disarmed_ids() and the queue depth are observed asynchronously,
    // so both are folded into one predicate to avoid a window where the backend call
    // has completed but the callback has not yet popped the claim.
    rt->detach_rule("r1");
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    REQUIRE(yuzu::test::spin_until(
        [&] { return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key) == 0; },
        std::chrono::seconds(10)));
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);

    // A fresh attach on the same key arms cleanly (no keys_.emplace hard error).
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(b->arms.load() == 2);
    CHECK(rt->armed_key_count() == 1);
}

// rung 9c R5.2 - adversarial re-review r2 (C2, found by both reviewers): a claim's
// index ownership flag is cleared only AFTER index_->remove_rule succeeded, so a throw
// from the removal leaves both the mapping and the flag for the next release to retry.
TEST_CASE("rung 9c R5.2 (adversarial re-review r2 C2): a throw inside the index removal keeps "
          "the claim's index ownership - the drain's retry cleans the mapping and the real "
          "owner's detach is still the ->0 edge",
          "[spark][runtime][liveness]") {
    // Mutation (the pre-fix order): clear index_held BEFORE remove_rule -> the throw
    // leaves a stale (key, r2) mapping nothing retries; the key's refcount never
    // reaches zero again, so detaching r1 (the real owner) is NOT the ->0 edge:
    // disarms stays 0, armed_key_count() stays 1 - a leaked subscription.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    std::expected<std::uint64_t, std::string> gen_r1;
    std::thread a_thread{[&] {
        gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // r2 queues behind r1's parked arm on the same key (a queued sibling with its own
    // index mapping), then is detached while remove_rule "fails to allocate".
    std::expected<std::uint64_t, std::string> gen_r2;
    std::thread r2_thread{[&] {
        gen_r2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));
    rt->set_index_remove_fault_for_test(true);
    // Adversarial re-review r3 C2/C3: the release is CONTAINED now (it never propagates,
    // since it also runs on noexcept and destructor paths), so the detach returns
    // normally with the failure counted; the ownership flag is still kept for the retry.
    REQUIRE_NOTHROW(rt->detach_rule("r2"));
    CHECK(rt->claim_index_release_failures() == 1);

    // r1's arm lands: the drain commits r1 and, sweeping the withdrawn sibling, RETRIES
    // r2's index release - which now succeeds because the flag was never cleared.
    b->release_hang();
    a_thread.join();
    r2_thread.join();
    REQUIRE(gen_r1.has_value());
    REQUIRE_FALSE(gen_r2.has_value());
    CHECK(gen_r2.error() == "withdrawn");
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1);

    // The real owner's detach is the ->0 edge ONLY if r2's stale mapping is gone.
    // rung 9c PR-2 Unit 3: observed asynchronously, folded into one predicate (see
    // the bad_alloc-building-the-disarm-claim test above for why).
    rt->detach_rule("r1");
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    const auto key_a = spark_key(file_spec("/a"));
    REQUIRE(yuzu::test::spin_until(
        [&] { return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key_a) == 0; },
        std::chrono::seconds(10)));
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
}

// rung 9c R5.2 - adversarial re-review r2 (C3 / Kimi K5): the drain's firewall
// compensation runs OFF registry_mu_, so a wedged backend unwatch on that path can
// never block the runtime's other operations (or begin_stop) behind the lock.
TEST_CASE("rung 9c R5.2 (adversarial re-review r2 C3): the firewall's last-resort disarm runs "
          "off registry_mu_ - a parked unwatch on that path does not block other rule operations",
          "[spark][runtime][liveness]") {
    // Mutation (the pre-fix shape): call backend_->disarm(*compensating) inside step
    // (3)'s lock_guard{registry_mu_} -> the probe below cannot take the lock while the
    // disarm is parked and times out.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() {
            backend->release_hang();
            backend->release_disarm_hang();
        }
    } cleanup{b.get()};
    const auto key = spark_key(file_spec("/a"));

    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    // Firewall path: bad_alloc before the fifo snapshot with a SUCCESSFUL arm, and the
    // compensating disarm it owes parks inside the backend.
    rt->set_drain_fault_point_for_test(1);
    b->hang_next_disarm.store(true);
    b->release_hang();
    REQUIRE(b->wait_entered_disarm_hang(std::chrono::seconds(30)));

    // While the unwatch is parked, an unrelated registry_mu_ acquisition must go through.
    auto probe = std::async(std::launch::async, [&] { return rt->claim_queue_depth_for_test(key); });
    const bool lock_free = probe.wait_for(std::chrono::seconds(3)) == std::future_status::ready;
    CHECK(lock_free);
    b->release_disarm_hang();
    (void)probe.get();
    a1.t.join();

    REQUIRE_FALSE(a1.gen.has_value());
    CHECK(a1.gen.error() == "arm drain failed");
    CHECK(rt->claim_drain_failures() == 1);
    REQUIRE(b->armed_ids().size() == 1);
    REQUIRE(b->disarmed_ids().size() == 1); // compensated exactly once, before the verdict
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
}

// rung 9c R5.2 - adversarial re-review r3 (C3): begin_stop() runs from the destructor
// (implicitly noexcept) and from GuardianEngine::stop() ahead of the executor/scheduler/
// worker shutdown, so its queued-claim walk must never propagate a throw from the index
// release. The release is noexcept by construction now (SparkKeyRuleIndex::erase_rule
// has no allocation); the seam throws to prove the containment shape.
TEST_CASE("rung 9c R5.2 (adversarial re-review r3 C3): begin_stop() survives a throwing index "
          "release on a queued claim - counted, the claim dropped, the executor still stopped",
          "[spark][runtime][liveness]") {
    // Mutation (the pre-fix shape): release_claim_index_locked propagates the throw ->
    // begin_stop() throws out of its walk before io_executor_.stop() runs
    // (REQUIRE_NOTHROW fails); from ~GuardianSparkRuntime that is std::terminate.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    QueuedAttach a2; // queues behind r1's parked arm: a Queued claim holding an index mapping
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));

    rt->set_index_remove_fault_for_test(true); // r2's release in the stop walk "throws"
    REQUIRE_NOTHROW(rt->begin_stop());
    CHECK(rt->claim_index_release_failures() == 1);
    CHECK(rt->claims_dropped_at_stop() == 1);
    CHECK(rt->io_executor_stats_for_test().stopping); // the walk continued to the executor stop

    b->release_hang(); // r1's late success is disarmed by the drain (R5.5)
    a1.t.join();
    a2.t.join();
    REQUIRE_FALSE(a2.gen.has_value());
    CHECK(a2.gen.error() == "stopping");
    REQUIRE_FALSE(a1.gen.has_value());
    CHECK(a1.gen.error() == "stopping");
    REQUIRE(yuzu::test::spin_until([&] { return b->disarmed_ids().size() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
}

#ifndef _WIN32
// rung 9c R5.2 - adversarial re-review r3 (C2, the real half): a refill whose admission is
// refused is cleaned up INSIDE on_arm_complete() (noexcept). Before this round a throw
// from the index release in that cleanup crossed the noexcept boundary: std::terminate,
// the agent gone. Inverted death test: the child must exit 0, never die by SIGABRT.
// fork() WITHOUT exec, as the reconcile death tests do; Catch2 runs cases sequentially
// and this case starts no threads before forking (every thread below is created in the
// child). A detached executor worker from an EARLIER case may still be alive at fork
// time; the child's only libc-lock-sensitive work is allocation, and the existing death
// tests carry the same exposure - noted, not new.
TEST_CASE("rung 9c R5.2 (adversarial re-review r3 C2): a throwing index release inside the "
          "refill's admission-failure cleanup is contained on the noexcept drain (inverted "
          "death test: the child must not abort)",
          "[spark][runtime][liveness][death]") {
    // Mutation (the pre-fix shape): release_claim_index_locked propagates -> the throw
    // leaves fail_all_claims_locked -> dispatch_arm_off_lock -> on_arm_complete()
    // noexcept -> std::terminate: the child dies by SIGABRT (WIFSIGNALED), exit code
    // never reached.
    REQUIRE(yuzu::test::wait_until_quiescent()); // no stray worker at fork (pass-3 qe-2/cp-1/cs-4)
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        // ---- child ----
        ::signal(SIGABRT, SIG_DFL); // die silently on a regression; the parent reads the signal
        auto r = std::make_shared<FakeReader>();
        auto b = std::make_shared<FakeBackend>();
        b->hang_next_arm.store(true);
        auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
        const auto key = spark_key(file_spec("/a"));

        std::expected<std::uint64_t, std::string> gen_r1;
        std::thread t1{[&] { gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
        if (!b->wait_entered_hang(std::chrono::seconds(30)))
            ::_exit(90);
        rt->detach_rule("r1"); // Case-0 withdraw: the dispatched head stays as the key's marker
        t1.join();
        if (gen_r1.has_value() || gen_r1.error() != "withdrawn")
            ::_exit(91);

        // In the drain's compensating gap (nobody adopts the withdrawn head's result):
        // queue r2 behind the head, then make the REFILL's admission fail and r2's
        // index release throw inside that failure's cleanup.
        std::expected<std::uint64_t, std::string> gen_r2;
        std::thread t2;
        std::atomic<bool> r2_done{false};
        rt->set_drain_gap_hook_for_test([&] {
            t2 = std::thread{[&] {
                gen_r2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
                r2_done.store(true);
            }};
            (void)yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                         std::chrono::seconds(10));
            rt->set_io_executor_fail_launch_for_test(true); // the refill's submit() is refused
            rt->set_index_remove_fault_for_test(true);      // ...and its cleanup's release throws
        });
        b->release_hang(); // r1's arm lands: drain -> gap hook -> compensation -> pop -> refill r2
        if (!yuzu::test::spin_until([&] { return r2_done.load(); }, std::chrono::seconds(30)))
            ::_exit(92);
        t2.join();
        rt->set_io_executor_fail_launch_for_test(false);
        if (gen_r2.has_value())
            ::_exit(93);
        if (gen_r2.error() != "arm worker launch failed")
            ::_exit(94); // the cleanup published its verdict despite the contained throw
        if (rt->claim_index_release_failures() != 1)
            ::_exit(95);
        if (rt->claim_queue_depth_for_test(key) != 1)
            ::_exit(96); // r2 stays as a withdrawn TOMBSTONE: its index mapping is still
                         // held (the release "failed"), parked for the next drain to retry
        // Recovery on the SAME key (the state a later same-key event must be able to
        // recover from): r4 queues behind the tombstone, its dispatch drives the head,
        // the drain adopts the arm for r4 and sweeps the tombstone - retrying and now
        // completing r2's index release. Then r4 is the sole owner: its detach is the
        // ->0 edge and disarms exactly the subscription r4 adopted.
        const auto gen_r4 = rt->attach_rule("r4", file_spec("/a"), file_exists_rule("r4"), true);
        if (!gen_r4.has_value())
            ::_exit(97);
        if (rt->claim_queue_depth_for_test(key) != 0 || rt->rule_count() != 1)
            ::_exit(98); // the tombstone was swept, the mapping cleaned
        rt->detach_rule("r4");
        if (rt->rule_count() != 0 || rt->armed_key_count() != 0)
            ::_exit(99);
        // Two disarms overall: r1's compensation (its withdrawn head) and r4's own -
        // both dispatched off-lock through non-blocking submit_disarm_off_lock()
        // (rung 9c PR-2 Unit 3), so detach_rule("r4") returning is not proof either
        // disarm has physically completed yet.
        if (!yuzu::test::spin_until([&] { return b->disarmed_ids().size() == 2; },
                                    std::chrono::seconds(10)))
            ::_exit(101);
        if (b->armed_ids().size() != 2 || b->disarmed_ids()[1] != b->armed_ids()[1])
            ::_exit(100);
        rt->begin_stop();
        ::_exit(0);
    }

    // ---- parent ---- poll, never block: a regression that hangs must fail, not stall the suite.
    int status = 0;
    bool reaped = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            reaped = true;
            break;
        }
        REQUIRE(w == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!reaped) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        FAIL("child never exited within 60 s");
    }
    INFO("child status: exited=" << WIFEXITED(status) << " code=" << (WIFEXITED(status) ? WEXITSTATUS(status) : -1)
                                 << " signaled=" << WIFSIGNALED(status)
                                 << " sig=" << (WIFSIGNALED(status) ? WTERMSIG(status) : 0));
    CHECK_FALSE(WIFSIGNALED(status)); // the pre-fix shape: SIGABRT from std::terminate
    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

// rung 9c PR-5a (#4221 ch-102): governance correction (2026-09-14, F3) - the comment
// this test replaces claimed the death test above and the up-101 test below already
// cover ch-102's "refill-inside-catch admission-refusal arm", and this test's own
// first-draft comment then mis-described WHY they don't: both cited tests DO take the
// `compensating` branch (r1 withdrawn while parked, nobody adopts it) same as this
// test, so "on_arm_complete's not-compensating inline path" was wrong. The real
// distinction is which of TWO textually-similar `refill = try_dispatch_head_locked(...)`
// call sites fires: both cited tests arm only set_io_executor_fail_launch_for_test +
// set_index_remove_fault_for_test (no drain fault point), so their compensating
// disarm's own admission is refused, finalize_arm_compensation()'s OUTER try
// SUCCEEDS calling publish_arm_verdicts_locked(), and the refill comes from THAT
// function's own ordinary-completion tail (`else refill = try_dispatch_head_locked(
// key);` near its end - the same tail on_arm_complete's inline, non-compensating path
// also reaches on success). ch-102's actual target is the OTHER site: the
// `else refill = try_dispatch_head_locked(cont->key);` inside finalize_arm_
// compensation()'s own DOUBLE-FAULT catch handler (this file, the
// `if (cont->claim->outcome || cont->claim->commit_exception) { ...; else refill = ...}`
// block) - reached only when publish_arm_verdicts_locked() ITSELF throws
// (set_drain_fault_point_for_test(3), which fires inside that function) WHILE a
// second claim is already queued behind the compensating head. That branch had zero
// coverage; this test targets it directly.
//
// Mutation-verify: change the catch handler's `else refill = try_dispatch_head_locked(
// cont->key);` to a no-op (drop the refill) and this goes RED - r2 is left Queued
// forever behind the popped r1, never dispatched, and its attach_rule() call hangs
// past its own deadline instead of resolving "arm worker launch failed".
TEST_CASE("rung 9c PR-5a (#4221 ch-102): finalize_arm_compensation's double-fault catch "
          "handler refills the next queued claim, and that refill's OWN admission "
          "refusal is handled cleanly",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    const auto key = spark_key(file_spec("/a"));

    // r1 hangs as the dispatched head, then is withdrawn while still parked - the
    // same "nobody wants the late result" setup the compensating-disarm death test
    // above uses, so on_arm_complete takes the `compensating` branch rather than
    // committing the result. Its own claim stays at the fifo's head throughout: the
    // compensating disarm is a separate io_executor_ submission (ArmCompensation),
    // never a queued Disarm claim, until finalize_arm_compensation() actually pops it.
    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->detach_rule("r1");
    a1.t.join();
    REQUIRE_FALSE(a1.gen.has_value());
    CHECK(a1.gen.error() == "withdrawn");

    // In the drain's compensating gap (r1's own on_arm_complete pass has already
    // collected ITS finished/verdicts sets - queuing r2 here does not join them, it
    // queues fresh behind r1's still-present head, exactly matching the "second
    // queued claim" ch-102 needs): queue r2, then arm BOTH seams together. Governance
    // B2: this hook runs on on_arm_complete's own noexcept, detached-worker call
    // stack - no REQUIRE/CHECK in here, only recording/signalling; every assertion
    // below runs on the main thread after a2.t.join().
    QueuedAttach a2;
    std::atomic<bool> r2_queued{false};
    // Governance F1: spin_until's own result must be RECORDED and asserted on the main
    // thread, not discarded - under a loaded/slow runner the inner wait could time out
    // while the test still happens to pass for an unrelated reason (r2 hitting the same
    // error string via ordinary admission refusal instead of exercising the target
    // catch-handler branch at all). Same pattern as governance B2's own fix: an atomic
    // recorded here, checked after a2.t.join() below.
    std::atomic<bool> r2_queue_wait_ok{false};
    rt->set_drain_gap_hook_for_test([&] {
        a2.t = std::thread{[&] {
            a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
        }};
        r2_queue_wait_ok.store(
            yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key) == 2; },
                                   std::chrono::seconds(10)));
        r2_queued.store(true);
        // Fires inside finalize_arm_compensation's deferred publish_arm_verdicts_locked()
        // call (NOT here, and NOT during this on_arm_complete pass, which never calls
        // it while `compensating` is set) - the double fault ch-102 needs.
        rt->set_drain_fault_point_for_test(3);
        // Persistent (not consumed-once): also refuses the compensating disarm's own
        // submission below, which falls back to direct_disarm_fallback() - a
        // different, already-covered recovery path (up-3/#4221 territory), harmless
        // to this test. Left armed through finalize_arm_compensation's own refill
        // dispatch, which is the actual refusal this test targets.
        rt->set_io_executor_fail_launch_for_test(true);
    });
    b->release_hang(); // r1's arm lands late: drain -> gap hook -> compensation ->
                       // (direct-disarm fallback) -> finalize_arm_compensation ->
                       // fault 3 -> catch -> pop r1 -> refill r2 -> r2's own admission refused
    REQUIRE(yuzu::test::spin_until([&] { return r2_queued.load(); }, std::chrono::seconds(30)));
    a2.t.join();
    rt->set_io_executor_fail_launch_for_test(false);

    REQUIRE(r2_queue_wait_ok.load()); // r2 genuinely reached claim_queue_depth==2 before
                                      // fault 3 armed - not a coincidental pass via a
                                      // timed-out wait plus an unrelated admission refusal
    REQUIRE_FALSE(a2.gen.has_value()); // the refill's OWN admission was refused
    CHECK(a2.gen.error() == "arm worker launch failed");
    CHECK(rt->claim_drain_failures() >= 1); // fault 3's throw was contained and counted
    CHECK(rt->claim_queue_depth_for_test(key) == 0); // r1 popped, r2 failed-and-cleaned -
                                                     // no leftover tombstone from either
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->arms.load() == 1); // only r1's real (late) arm - r2 never reached the
                                // backend at all (refused at admission)

    // The key is not wedged: a fresh attach still succeeds cleanly.
    auto gen_r3 = rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true);
    REQUIRE(gen_r3);
    CHECK(rt->armed_key_count() == 1);
    rt->detach_rule("r3");
    rt->begin_stop();
}
//
// rung 9c PR-5a (#4221 up-101/ch-101): the death test above proves recovery when a
// DIFFERENT rule (r4) queues behind r2's tombstone. #4221's own up-101 criterion names
// the harder, untested case: the SAME rule_id ("r2") re-attaching behind ITS OWN
// not-yet-released tombstone. Before the incarnation-aware SparkKeyRuleIndex fix, the
// tombstone's retried release (keyed on rule_id alone) would erase the SECOND r2's
// live mapping out from under it the moment the drain swept the tombstone - a leaked
// watcher masquerading as a clean re-arm, and (per #4221) an eventually permanently
// unarmable key. Mutation-verify: pass generation 0 unconditionally from
// release_claim_index_locked() (or drop erase_rule()'s generation check) and this goes
// RED - the retried release destroys r2(second)'s live mapping mid-flight.
TEST_CASE("rung 9c PR-5a (#4221 up-101/ch-101): a same-rule_id re-attach behind its own "
          "not-yet-released tombstone keeps its own mapping and disarms cleanly",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    const auto key = spark_key(file_spec("/a"));

    // QueuedAttach (defined above, "rung 9c R5.2: per-key claim/queue" section) rather
    // than a raw std::thread: its destructor joins if still joinable, so a REQUIRE
    // failure between construction and the explicit .join() below unwinds safely
    // instead of destructing a joinable thread (std::terminate) - governance B1.
    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->detach_rule("r1"); // Case-0 withdraw: the dispatched head stays as the key's marker
    a1.t.join();
    REQUIRE_FALSE(a1.gen.has_value());
    CHECK(a1.gen.error() == "withdrawn");

    // In the drain's compensating gap: queue "r2" behind the withdrawn r1 head, then
    // make its own admission fail AND its index release throw inside that failure's
    // cleanup - producing a genuine tombstone (withdrawn, index_held retained pending
    // retry), exactly the setup the r4-based death test above uses.
    //
    // governance B2: the hook below runs on_arm_complete's own call stack - noexcept,
    // on the detached io_executor_ worker thread (this file's own doc comment on
    // on_arm_complete says so explicitly). A REQUIRE/CHECK in there would be a
    // concurrent call into Catch2's non-thread-safe assertion API from a second
    // thread, and any exception crossing that noexcept boundary is std::terminate
    // regardless. The hook only records/signals here (discards spin_until's return,
    // exactly like the sibling death test above at its own set_drain_gap_hook_for_test
    // call); every assertion runs on the MAIN thread after a2.t.join() instead.
    QueuedAttach a2;
    std::atomic<bool> r2_done{false};
    rt->set_drain_gap_hook_for_test([&] {
        a2.t = std::thread{[&] {
            a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
            r2_done.store(true);
        }};
        (void)yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                     std::chrono::seconds(10));
        rt->set_io_executor_fail_launch_for_test(true); // the refill's submit() is refused
        rt->set_index_remove_fault_for_test(true);      // ...and its cleanup's release throws
    });
    b->release_hang(); // r1's arm lands: drain -> gap hook -> compensation -> pop -> refill r2
    REQUIRE(yuzu::test::spin_until([&] { return r2_done.load(); }, std::chrono::seconds(30)));
    a2.t.join();
    rt->set_io_executor_fail_launch_for_test(false);
    REQUIRE_FALSE(a2.gen.has_value());
    CHECK(a2.gen.error() == "arm worker launch failed");
    CHECK(rt->claim_index_release_failures() == 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 1); // r2's FIRST attempt is now a
                                                     // tombstone: withdrawn, its index
                                                     // release failed and is retained
    CHECK(b->arms.load() == 1); // only r1's real arm so far - r2's first attempt never
                                // reached the backend at all (admission itself was
                                // refused)

    // THE ACTUAL up-101 SCENARIO: re-attach the SAME rule_id "r2" - not a different one
    // - behind its own tombstone. No hang needed this time: attach_core's own call
    // transfers index ownership to this second incarnation, then sweeps and dispatches
    // past the (now-unfaulted) tombstone synchronously before returning, so the
    // blocking wrapper resolves as soon as the real backend arm (FakeBackend's default,
    // non-hanging) completes.
    auto gen_r2b = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    REQUIRE(gen_r2b); // succeeds cleanly - not stuck behind its own stale tombstone
    CHECK(rt->claim_queue_depth_for_test(key) == 0); // tombstone swept, no leftover claim
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 2); // r1's real arm plus r2's second (real) attempt
    const auto armed_before_detach = b->armed_ids(); // {r1's sub, r2b's sub}, in arm order

    // The eventual detach disarms EXACTLY the subscription the second r2 adopted - not
    // zero (a leaked watcher), not a phantom entry the stale tombstone's erroneous
    // erase would have left behind. r1's own compensating disarm already ran earlier
    // (its late "success" was withdrawn, nobody adopted it) - wait for BOTH disarms,
    // not just the first one to land.
    rt->detach_rule("r2");
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 2; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarmed_ids() == armed_before_detach); // both real arms, each disarmed
                                                     // exactly once - nothing leaked,
                                                     // nothing double-disarmed

    // A further attach on the same key still succeeds - the key is not permanently
    // unarmable (#4221's stated worst-case consequence of the un-fixed defect).
    auto gen_r3 = rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true);
    REQUIRE(gen_r3);
    CHECK(rt->armed_key_count() == 1);
    rt->detach_rule("r3");
    rt->begin_stop();
}

// EXPLORATORY (not yet reviewed - do not treat as settled coverage): investigating
// whether publish_arm_verdicts_locked's ORDINARY (non-firewall) pop loop can leave a
// permanent ghost SparkKeyRuleIndex entry when a withdrawn sibling's
// release_claim_index_locked call fails exactly once and is never retried. Unlike the
// firewall branch (guardian_spark_runtime.cpp:602-620, which explicitly re-checks
// index_held and keeps a release-failed claim as a retained tombstone), the ordinary
// pop loop at :580-601 pops every finished claim based solely on outcome presence and
// fifo-front identity - it does not check whether that claim's index release actually
// succeeded. If confirmed, this produces an index entry with NO corresponding fifo
// residue at all (unlike up-101's tombstone), so no existing sweep can ever find it.
TEST_CASE("EXPLORATORY: a release failure on a withdrawn sibling during the ORDINARY "
          "(non-firewall) publish path - does the claim get popped while its index "
          "mapping survives?",
          "[spark][runtime][liveness][.exploratory]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    const auto key = spark_key(file_spec("/a"));

    // r1 hangs as the head. r2 queues behind it via a genuinely concurrent attach
    // (NOT the gap-hook trick - r2 must be live/queued, not withdrawn, at the moment
    // r1's arm resolves is NOT what we want here; we want r2 ALREADY withdrawn with a
    // FAILED release before r1 resolves, so r1's own "withdrawn siblings" loop is what
    // attempts r2's release).
    QueuedAttach a1;
    a1.t = std::thread{[&] { a1.gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    QueuedAttach a2;
    a2.t = std::thread{[&] { a2.gen = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); }};
    REQUIRE(yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key) == 2; },
                                   std::chrono::seconds(10)));

    // Withdraw r2 (Case-0: still Queued, behind r1) with its OWN index release forced
    // to fail. It should become a retained tombstone (matches up-101's own finding).
    rt->set_index_remove_fault_for_test(true);
    rt->detach_rule("r2");
    a2.t.join();
    REQUIRE_FALSE(a2.gen.has_value());
    CHECK(a2.gen.error() == "withdrawn");
    CHECK(rt->claim_index_release_failures() == 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 2); // r1 (head) + r2 (retained tombstone)

    // Re-arm the SAME seam again, from the main thread, BEFORE releasing r1's hang -
    // so that when r1's own on_arm_complete pass retries r2's release (in its
    // "withdrawn siblings" loop), THAT attempt fails too.
    rt->set_index_remove_fault_for_test(true);
    b->release_hang();
    a1.t.join();
    REQUIRE(a1.gen); // r1 itself succeeds and commits normally

    CHECK(rt->claim_index_release_failures() == 2); // r2's release failed a SECOND time
    CHECK(rt->rule_count() == 1);                   // only r1 is a real, live rule
    CHECK(rt->armed_key_count() == 1);

    // THE QUESTION: did r2 get popped from the fifo anyway, despite its release
    // failing? If the ordinary pop loop pops unconditionally (as read from source),
    // this should be 0 - r2 is gone from claims_[key] entirely, with NOTHING left to
    // sweep, even though its index entry was never actually released.
    INFO("claim_queue_depth after r1 commits: " << rt->claim_queue_depth_for_test(key));
    CHECK(rt->claim_queue_depth_for_test(key) == 0);

    // If the above is 0 (ghost with no fifo trace), r1's OWN eventual detach should
    // find refcount(key) == 2 (r1 + the ghost "r2"), so remove_rule("r1") reports
    // siblings remain and NEVER returns the ->0 edge - the real backend subscription
    // for r1 should therefore NEVER get disarmed, even though r1 is the only rule
    // left anywhere in rules_/keys_/claims_.
    const auto arms_before_detach = b->arms.load();
    const auto disarms_before_detach = b->disarms.load();
    rt->detach_rule("r1");
    CHECK(rt->rule_count() == 0);
    // CORRECTED prediction (first run showed my original guess was wrong in the WORSE
    // direction): armed_key_count() stays 1, not 0. keys_.erase() is gated on
    // detach_rule_locked's own `disarm_key` (only set when index_->remove_rule reports
    // the ->0 edge) - the ghost "r2" still counted in the index means remove_rule("r1")
    // reports siblings remain, so keys_[key] (and its live PerKey/subscription) is
    // NEVER erased, even though r1 was the only real rule left anywhere.
    CHECK(rt->armed_key_count() == 1);
    // Give any (unexpected) async disarm a moment to land, then check whether it did.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    INFO("arms before=" << arms_before_detach << " after=" << b->arms.load()
                        << " disarms before=" << disarms_before_detach
                        << " after=" << b->disarms.load());
    CHECK(b->disarms.load() == disarms_before_detach); // PREDICTED: no new disarm fired -
                                                       // the real subscription is leaked,
                                                       // permanently armed on the backend,
                                                       // because remove_rule("r1") still
                                                       // sees the ghost "r2" as a sibling.

    // Confirm the ghost is PERMANENT: a fresh attach for a NEW rule on the SAME spec
    // (same key) - does it see the key as already "claimed" or "armed" and behave
    // oddly, given keys_[key] never went away? And can the key EVER be torn down
    // again, e.g. via begin_stop's own teardown sweep?
    const auto arms_before_r4 = b->arms.load();
    auto gen_r4 = rt->attach_rule("r4", file_spec("/a"), file_exists_rule("r4"), true);
    INFO("r4 attach: has_value=" << gen_r4.has_value()
                                 << (gen_r4.has_value() ? "" : (" error=" + gen_r4.error()))
                                 << " arms before=" << arms_before_r4 << " after=" << b->arms.load()
                                 << " rule_count=" << rt->rule_count()
                                 << " armed_key_count=" << rt->armed_key_count());
    CHECK(gen_r4.has_value()); // does it even succeed?
    CHECK(rt->rule_count() == 1); // r1 was properly erased from rules_ regardless (the
                                  // ghost is index-only) - only r4 should be tracked
    CHECK(b->arms.load() == arms_before_r4); // PREDICTED: r4 silently reuses r1's OLD,
                                             // still-armed-on-the-backend subscription
                                             // via the stale keys_[key] entry, WITHOUT
                                             // a new backend arm() call - r4 ends up
                                             // sharing a subscription nobody re-verified
                                             // is even still valid for r4's OWN spec.

    rt->begin_stop();
}

// rung 9c PR-2 Unit 4 (adversarial review C1, PR #4318 fjarvis): on_arm_complete's
// compensating branch built the ArmCompensation continuation (a heap allocation plus
// a string copy) entirely OUTSIDE any try, while a live, un-disarmed backend
// subscription was tracked only by a local no longer guarded by `compensating`. A
// throw there escaped this noexcept function: std::terminate, the agent gone, the
// OS watcher never disarmed. Inverted death test: the child must exit 0, never die
// by SIGABRT.
TEST_CASE("rung 9c PR-2 Unit 4 (adversarial review C1, PR #4318): a throw while building "
          "the compensating-disarm continuation is contained on the noexcept drain "
          "(inverted death test: the child must not abort)",
          "[spark][runtime][liveness][death]") {
    // Mutation (the pre-fix shape): make_shared<ArmCompensation>()/the `key` copy ran
    // unguarded -> fault point 4's throw escapes on_arm_complete (noexcept) ->
    // std::terminate: the child dies by SIGABRT (WIFSIGNALED), exit code never reached.
    REQUIRE(yuzu::test::wait_until_quiescent());
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        // ---- child ----
        ::signal(SIGABRT, SIG_DFL);
        auto r = std::make_shared<FakeReader>();
        auto b = std::make_shared<FakeBackend>();
        b->hang_next_arm.store(true);
        auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

        std::atomic<bool> a_done{false};
        std::thread a_thread{[&] {
            rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
            a_done.store(true, std::memory_order_release);
        }};
        if (!b->wait_entered_hang(std::chrono::seconds(30)))
            ::_exit(90);

        // Withdraw while the arm is still parked (#2233 item 3's Case-0 shape): the
        // waiter resolves "withdrawn" now, but the backend's late arm - and the
        // compensating disarm it needs - only lands once release_hang() fires below.
        rt->detach_rule("r1");
        if (rt->rule_count() != 0 || rt->armed_key_count() != 0)
            ::_exit(91);

        // Arm fault point 4: on_arm_complete's compensating branch throws building
        // ArmCompensation itself, with the subscription already tracked only by a
        // local - exactly the window C1 found.
        rt->set_drain_fault_point_for_test(4);
        b->release_hang(); // the late arm lands -> compensating -> fault point 4
        if (!yuzu::test::spin_until([&] { return a_done.load(std::memory_order_acquire); },
                                    std::chrono::seconds(30)))
            ::_exit(92);
        if (!yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                    std::chrono::seconds(10)))
            ::_exit(93); // the direct-disarm-and-fall-through recovery never ran
        if (rt->rule_count() != 0 || rt->armed_key_count() != 0)
            ::_exit(94);
        if (rt->claim_drain_failures() != 1)
            ::_exit(95); // the caught throw must count as a drain failure, not vanish

        // Runtime is still healthy after the contained throw: a fresh attach on the
        // same key/rule arms cleanly.
        const auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        if (!gen.has_value())
            ::_exit(96);
        if (rt->armed_key_count() != 1 || b->arms.load() != 2)
            ::_exit(97);
        rt->begin_stop();
        ::_exit(0);
    }

    // ---- parent ---- poll, never block: a regression that hangs must fail, not stall the suite.
    int status = 0;
    bool reaped = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            reaped = true;
            break;
        }
        REQUIRE(w == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!reaped) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        FAIL("child never exited within 60 s");
    }
    INFO("child status: exited=" << WIFEXITED(status) << " code=" << (WIFEXITED(status) ? WEXITSTATUS(status) : -1)
                                 << " signaled=" << WIFSIGNALED(status)
                                 << " sig=" << (WIFSIGNALED(status) ? WTERMSIG(status) : 0));
    CHECK_FALSE(WIFSIGNALED(status)); // the pre-fix shape: SIGABRT from std::terminate
    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

// Gate 8 re-review (cpp-safety + security-guardian, PR #4318, independent of fjarvis's
// original C1): the FIRST fix shape assigned `cont = std::make_shared<ArmCompensation>()`
// before the fallible `cont->key = key` copy, so a throw on the key copy alone left
// `cont` non-null with an empty `key` - `std::string::operator=` gives the strong
// exception guarantee, so the failed assignment never touched `cont->key`. That made
// the `if (cont)` continuation branch run a SECOND time on top of the direct disarm the
// catch handler had already issued (harmless only because SparkEngine::disarm() happens
// to be id-idempotent - not a documented ISparkBackend contract), and made
// finalize_arm_compensation()'s claims_.find("") miss the real key entirely, leaving
// its already-terminal head claim un-popped and the key PERMANENTLY wedged (no further
// arm/disarm possible on it short of a process restart - a silent enforcement hole).
// Fault point 5 fires after the allocation succeeds but before the key copy runs, so
// this reproduces exactly that interleaving. Kept as an inverted death test, like Unit
// 4 above: the true fix leaves `cont` assigned only as the LAST statement of the try
// (regardless of which of the two fallible steps throws), so this must behave
// identically to fault point 4 - single disarm, one drain-failure count, and critically
// the same key re-arms cleanly afterward (proving it was never wedged).
TEST_CASE("rung 9c PR-2 Unit 4b (Gate 8 re-review, PR #4318): a throw AFTER the "
          "ArmCompensation allocation but before the key copy must not leave `cont` "
          "half-built (double disarm / wedged key)",
          "[spark][runtime][liveness][death]") {
    // Mutation (the first fix's own shape): `cont` was assigned straight from
    // make_shared() before the key copy was known to succeed -> fault point 5's throw
    // leaves a non-null, empty-keyed `cont` -> double disarm + claims_.find("") misses
    // the real key -> the head claim is never popped -> the key is wedged forever
    // (surfaced here as the second attach_rule() below never completing/arming).
    REQUIRE(yuzu::test::wait_until_quiescent());
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        // ---- child ----
        ::signal(SIGABRT, SIG_DFL);
        auto r = std::make_shared<FakeReader>();
        auto b = std::make_shared<FakeBackend>();
        b->hang_next_arm.store(true);
        auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

        std::atomic<bool> a_done{false};
        std::thread a_thread{[&] {
            rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
            a_done.store(true, std::memory_order_release);
        }};
        if (!b->wait_entered_hang(std::chrono::seconds(30)))
            ::_exit(90);

        rt->detach_rule("r1");
        if (rt->rule_count() != 0 || rt->armed_key_count() != 0)
            ::_exit(91);

        // Arm fault point 5: the allocation itself succeeds, then the key copy throws -
        // exactly the window a `cont`-assigned-before-the-copy fix shape leaves open.
        rt->set_drain_fault_point_for_test(5);
        b->release_hang(); // the late arm lands -> compensating -> fault point 5
        if (!yuzu::test::spin_until([&] { return a_done.load(std::memory_order_acquire); },
                                    std::chrono::seconds(30)))
            ::_exit(92);
        // Gate 8 re-review (quality-engineer, PR #4318): this file's own "withdrawn"
        // wakeup path (see the "#2233 item 3 (C5/k3)" test case earlier in this file,
        // where detach_rule_locked's Case 0 notifies the waiting attach_rule()
        // immediately) means `a_thread`'s attach_rule() can return - and this
        // spin_until can start polling - BEFORE release_hang() even runs, so there is
        // no ordering guarantee between when polling starts and when either disarm
        // lands. Empirically (Gate 8 red-test
        // against the pre-7c45c36a3 double-disarm shape, 15/15 runs, mixed timing)
        // the synchronous catch-handler disarm and the buggy shape's second,
        // io_executor_-submitted disarm land close enough together that this 1ms-
        // polling spin_until times out rather than ever observing exactly 1 - so this
        // check DOES still fail on a real double-disarm today, but by timeout, not by
        // directly witnessing ">1"; a slower/loaded second disarm could in principle
        // let this check see disarms==1 and pass, which is exactly why the explicit,
        // non-waiting recheck below exists as the check that cannot age out under load.
        if (!yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                    std::chrono::seconds(10)))
            ::_exit(93); // no disarm within 10s, or it never settled at exactly 1
        if (rt->rule_count() != 0 || rt->armed_key_count() != 0)
            ::_exit(94);
        if (rt->claim_drain_failures() != 1)
            ::_exit(95); // the caught throw must count as a drain failure, not vanish

        // The critical regression check: the key must NOT be wedged. If `cont` had
        // been half-built (non-null, empty key), the withdrawn head claim above would
        // never have been popped and this attach would queue behind it forever.
        const auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        if (!gen.has_value())
            ::_exit(96); // the key is wedged - exactly the bug this test guards against
        if (rt->armed_key_count() != 1 || b->arms.load() != 2)
            ::_exit(97);

        // Gate 8 re-review (quality-engineer, PR #4318): a non-waiting recheck, taken
        // here (not earlier) because by now the second attach_rule() above has fully
        // completed - any async disarm the buggy shape would have submitted has long
        // since landed, so this needs no spin/timeout of its own and never costs a
        // green run any wall-clock time. Catches a double-disarm even in a future
        // where the wedged-key symptom above (exit 96) is independently self-healed
        // without the underlying double-disarm itself being fixed.
        if (b->disarms.load() > 1)
            ::_exit(98); // a second, redundant disarm landed - the double-disarm bug is back
        rt->begin_stop();
        ::_exit(0);
    }

    // ---- parent ---- poll, never block: a regression that hangs must fail, not stall the suite.
    int status = 0;
    bool reaped = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            reaped = true;
            break;
        }
        REQUIRE(w == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!reaped) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        FAIL("child never exited within 60 s");
    }
    INFO("child status: exited=" << WIFEXITED(status) << " code=" << (WIFEXITED(status) ? WEXITSTATUS(status) : -1)
                                 << " signaled=" << WIFSIGNALED(status)
                                 << " sig=" << (WIFSIGNALED(status) ? WTERMSIG(status) : 0));
    CHECK_FALSE(WIFSIGNALED(status));
    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}
#endif

// rung 9c R5.2 - adversarial re-review r3 (C4): after detach_rule_locked's durable
// mutation, the compliance-outbox purge (outbox_.drop_rule builds an owning Key string
// per match) can throw. It is CONTAINED: the teardown completes, the queued disarm is
// still handed to the caller and driven, the "disarmed" audit is staged, the failure
// counted.
TEST_CASE("rung 9c R5.2 (adversarial re-review r3 C4): a throw in the outbox purge after the "
          "durable detach is contained - the queued disarm is still driven and the audit staged",
          "[spark][runtime][liveness]") {
    // Mutation (the pre-fix shape): drop_rule unwrapped -> the throw unwinds past the
    // claim hand-off: detach_rule throws, the disarm claim sits queued and undriven
    // (disarms stays 0), no "disarmed" audit entry.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->armed_ids().size() == 1);
    const auto key = spark_key(file_spec("/a"));

    rt->set_detach_post_fault_point_for_test(2);
    REQUIRE_NOTHROW(rt->detach_rule("r1"));
    CHECK(rt->detach_post_commit_failures() == 1);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    // rung 9c PR-2 Unit 3: the queued disarm dispatches off-lock through non-blocking
    // submit_disarm_off_lock() and is popped by its own completion callback - both
    // observed asynchronously, folded into one predicate (see the bad_alloc-building-
    // the-disarm-claim test above for why both must be checked together).
    REQUIRE(yuzu::test::spin_until(
        [&] { return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key) == 0; },
        std::chrono::seconds(10))); // the queued disarm was driven
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
    CHECK(drain_lifecycle(*rt).size() == 2); // "armed" at attach + "disarmed" at detach
}

// rung 9c R5.2 - adversarial re-review r3 (C4): the lifecycle-kind string copy, the
// caller-side allocation that used to sit AFTER the durable mutation, now runs before
// it, so a throw there fails the detach cleanly with the rule still confirmed.
TEST_CASE("rung 9c R5.2 (adversarial re-review r3 C4): a throw at the lifecycle-kind copy fails "
          "the detach BEFORE any durable mutation - the rule stays confirmed and a retried "
          "detach disarms once",
          "[spark][runtime][liveness]") {
    // Mutation (the pre-fix placement): the copy (and the seam) after rules_.erase /
    // keys_.erase -> the throw leaves rule_count() == 0 with the queued disarm undriven
    // and the retry finds nothing to detach (disarms stays 0).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->armed_ids().size() == 1);
    const auto key = spark_key(file_spec("/a"));

    rt->set_detach_post_fault_point_for_test(1);
    REQUIRE_THROWS_AS(rt->detach_rule("r1"), std::bad_alloc);
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    CHECK(b->disarms.load() == 0);
    CHECK(rt->detach_claim_failures() == 0);
    CHECK(rt->detach_post_commit_failures() == 0);

    rt->detach_rule("r1"); // the retry: one disarm of exactly the armed subscription
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    // rung 9c PR-2 Unit 3: observed asynchronously, folded into one predicate (see
    // the earlier bad_alloc-building-the-disarm-claim test for why).
    REQUIRE(yuzu::test::spin_until(
        [&] { return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key) == 0; },
        std::chrono::seconds(10)));
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]);
}

// ── governance pass-3 (independent fan-out) + adversarial round 4 code findings ──────

// cs-1: on_subscription_lost detaches every rule on the dead key; the last detach
// queues a Disarm claim for the DEAD id at the key's head. Before this fix that claim
// lingered undriven, and the next same-key attach first re-drove a guaranteed no-op
// backend disarm (a wasted bounded run() the attach had to wait out) before arming.
TEST_CASE("rung 9c R5.2 (governance pass-3 cs-1): a subscription reported dead completes its "
          "queued disarm claim in place - no backend call for a dead id; the key is clean and "
          "the next same-key attach arms at once",
          "[spark][runtime][liveness]") {
    // Mutation: drop the completion block in on_subscription_lost -> depth stays 1
    // after the Lost, and the next attach's redrive disarms the dead id (disarms == 1).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    const auto key = spark_key(file_spec("/a"));
    REQUIRE(b->armed_ids().size() == 1);

    b->set_health_for_test(b->armed_ids().front(), SubscriptionHealth::Dead);
    rt->revalidate_subscriptions(); // -> on_subscription_lost(key, dead id)
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->claim_queue_depth_for_test(key) == 0); // no undriven claim for a dead id
    CHECK(rt->dead_subscription_disarms_skipped() == 1);
    CHECK(b->disarms.load() == 0);

    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(b->arms.load() == 2);
    CHECK(b->disarms.load() == 0); // the dead id was never "disarmed" on the way
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
}

// rung 9c PR-5a (#4221 cs-103/ch-103): on_subscription_lost's rule-detach loop has no
// catch around it. #4221 calls this "contained/self-healing today per the design's own
// claim, but untested" - the real containment lives ONE LAYER UP, in SparkEngine's own
// consumer-dispatch loop (spark_engine.cpp: `try { consumer->handler(ev); } catch
// (...) { ...errors++... }`, verified directly against that source for this test), not
// in GuardianSparkRuntime itself. This test emulates that real containment explicitly
// (rather than requiring a full SparkEngine wiring just to prove GUARDIAN's own
// post-exception state) and proves the self-heal half #4221 flags as unverified: a
// repeat notification for the same dead subscription completes cleanly, and the key is
// never left permanently wedged.
//
// Uses set_detach_fault_for_test's existing seam, which fires inside
// detach_rule_locked() exactly at the LAST-rule-on-key case (refcount 1->0, right
// before the Disarm claim is constructed - matching #4221's own "throwing LAST
// detach" framing) - two rules share one key so the loop's first detach (not
// last-on-key) succeeds and only the second (last-on-key) hits the seam.
// Mutation-verify: this seam already exists and is exercised nowhere outside this
// test - removing this test silently loses the only coverage that a throw here
// neither corrupts state nor wedges the key permanently.
TEST_CASE("rung 9c PR-5a (#4221 cs-103/ch-103): a throwing LAST detach inside a Lost "
          "notification is contained one layer up and a repeat notification self-heals",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->rule_count() == 2);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1); // one shared watcher for both rules

    const auto key = spark_key(file_spec("/a"));
    const auto sub_id = b->armed_ids().at(0);

    rt->set_detach_fault_for_test(true); // consumed once, on the second (last-on-key) detach
    REQUIRE_THROWS_AS(
        rt->on_event(SparkEvent{.key = key, .kind = SparkEventKind::Lost, .subscription_id = sub_id}),
        std::bad_alloc);

    // Contained state, mid-loop: "r1" (detached first, before the throw) is gone;
    // "r2" (the throwing LAST detach) is UNTOUCHED - the seam fires before any of its
    // rules_/index_/keys_ mutation runs, so it is exactly as live as before the Lost
    // notification arrived. A real dead watch behind a still-"live" rule entry - the
    // design's own documented residual (an errored rule un-enforced until the next
    // recovery trigger), not a crash and not silent corruption.
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);

    // Self-heal: a repeat Lost notification for the SAME (key, subscription_id) - the
    // realistic retry shape (the mechanism re-firing, or the poll backstop
    // revalidate_subscriptions() re-observing the same dead id) - completes cleanly now
    // that the fault seam is spent.
    REQUIRE_NOTHROW(rt->on_event(
        SparkEvent{.key = key, .kind = SparkEventKind::Lost, .subscription_id = sub_id}));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);

    // The key is not permanently wedged: a fresh attach on it succeeds cleanly and
    // does not touch a REPLACEMENT subscription (there isn't one yet - proving the
    // contained throw didn't leave a stray claim or index entry behind either).
    REQUIRE(rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    rt->detach_rule("r3");
    rt->begin_stop();
}

// sg-3 / ar-4 / cs-5: a Dispatched head that already carries a published outcome is a
// tombstone the drain must never leave behind. Seam 3 throws inside the deferred
// publish AFTER the verdict write and BEFORE the pop, so step (3)'s catch sees a head
// with an outcome; before this fix it left that head in place (not re-Queued because
// it had an outcome, not popped because nothing did), and every later same-key attach
// queued behind it and timed out.
TEST_CASE("rung 9c R5.2 (governance pass-3 sg-3/ar-4/cs-5): a publish that throws after the "
          "verdicts are written still pops the terminal head instead of leaving a Dispatched "
          "tombstone - the next same-key attach arms (rung 9c PR-5d: this claim is now "
          "adopted, not disarmed, but the double-fault recovery shape is identical)",
          "[spark][runtime][liveness]") {
    // Mutation: step (3)'s catch keeps the old "re-Queue only if !outcome" shape ->
    // claim depth stays 1 forever and r2's attach returns "arm timed out".
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const auto key = spark_key(file_spec("/a"));

    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm timed out"); // waiter abandoned; the worker is still parked

    rt->set_drain_fault_point_for_test(3);
    // rung 9c PR-5d: "r1" was never withdrawn, so the late success is ADOPTED - the
    // adoption's own commit (rules_/keys_/index_) already succeeded BEFORE this
    // fault point fires (it lives inside publish_arm_verdicts_locked, called AFTER
    // the commit); the fault only interrupts the immediate publish attempt, and
    // the `if (!published)` recovery path's own firewalled re-publish sweeps the
    // now-purely-bookkeeping claim out of the fifo (its index_held is already
    // false - ownership passed to rules_/keys_ - so the firewall's own
    // erase_if(!index_held) condition removes it, same mechanism the pre-PR-5d
    // "hand back to Queued" recovery used for a claim WITHOUT an outcome yet;
    // this claim already has one from its original abandonment).
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key) == 0; },
                                   std::chrono::seconds(10)));
    CHECK(rt->claim_drain_failures() >= 1); // the catch fired (seam) and was contained
    CHECK(b->disarms.load() == 0); // adopted, not disarmed
    CHECK(rt->armed_key_count() == 1);

    auto gen2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    REQUIRE(gen2); // not queued behind a tombstone, nothing pops - joins the adopted watcher
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 2);
    CHECK(b->arms.load() == 1); // r1's adopted arm only - r2 joined it, no second arm() call
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
}

// cs-2: the firewall branch used to fifo.clear() even when a claim's index release had
// failed, dropping the claim while its (key, rule) mapping stayed in index_ - a ghost
// that made the next same-key attach take the shared-watcher branch (refcount 1->2,
// no 0->1 edge) against a key that has no PerKey: keys_.at(key) threw out of attach_rule.
TEST_CASE("rung 9c R5.2 (governance pass-3 cs-2): a firewalled drain whose index release fails "
          "keeps the claim as a tombstone and never a ghost mapping - the next same-key attach "
          "sweeps it and arms",
          "[spark][runtime][liveness]") {
    // Mutation: restore the unconditional fifo.clear() -> depth 0 with the mapping
    // still held; r2's attach throws std::out_of_range from keys_.at.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    // qe-101: the future is declared BEFORE the Cleanup guard (the file's idiom) so on
    // unwind the guard releases the parked backend first and the future's destructor
    // then joins an attach_rule that has already returned. Ownership order only: with
    // the 30 s REQUIRE and the 5 s backend_op_deadline the destructor could never stall
    // past the deadline either way (cpp-expert cx-202); the order is load-bearing for
    // the CHECKs under Catch2 abort mode, where the guard is the only release.
    auto fut = std::async(std::launch::async, [&] {
        return rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    });
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->set_drain_fault_point_for_test(1);   // bad_alloc before the fifo snapshot -> firewall
    rt->set_index_remove_fault_for_test(true); // the firewall's release of r1 fails once
    b->release_hang();
    auto gen = fut.get();
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm drain failed");
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10))); // (2b) compensated the arm
    CHECK(rt->claim_index_release_failures() == 1);
    // The tombstone is kept (not cleared) and then swept by the SAME publish's refill
    // step, whose sweep retries the release - the single-shot seam is consumed, so the
    // retry succeeds and the entry empties. What the fix guarantees is "no ghost
    // mapping", proven by r2's attach below: with the old fifo.clear() the mapping
    // survived the drop and keys_.at threw out of attach_rule.
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    CHECK(rt->rule_count() == 0);

    b->reset_hang();
    std::expected<std::uint64_t, std::string> gen2;
    REQUIRE_NOTHROW(gen2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    REQUIRE(gen2);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);
    CHECK(b->arms.load() == 2);
    CHECK(rt->claim_queue_depth_for_test(key) == 0); // tombstone swept, release retried
}

// adversarial round 4 K2/C5: index_add_rollback's .fn runs inside ~GuardianRollback,
// which swallows exceptions; remove_rule's key copy could throw there and leave a ghost
// mapping. erase_rule is the same walk without the copy (noexcept).
TEST_CASE("source tripwire: index_add_rollback's .fn uses the noexcept erase_rule rather than the "
          "allocating remove_rule (adversarial round 4 K2/C5)",
          "[spark][runtime][liveness][source_tripwire]") {
    // Mutation-verified: `index_->remove_rule(rule_id)` inside the lambda makes this fail.
    std::ifstream input(std::filesystem::path(YUZU_AGENT_SRC_DIR) / "guardian_spark_runtime.cpp");
    REQUIRE(input.is_open());
    const std::string source((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());
    const auto start = source.find("index_add_rollback.fn = [this, rule_id, gen, &index_added] {");
    REQUIRE(start != std::string::npos);
    const auto end = source.find("};", start);
    REQUIRE(end != std::string::npos);
    const std::string body = source.substr(start, end - start);
    CHECK(body.find("index_->erase_rule(rule_id, gen)") != std::string::npos);
    CHECK(body.find("index_->remove_rule(") == std::string::npos);
}

// qe-4: detach_all's claimed-only branch (a rule whose arm is in flight, no rules_
// entry yet) had no direct test.
TEST_CASE("rung 9c R5.2 (governance pass-3 qe-4): detach_all withdraws a rule that is still "
          "only CLAIMED - its waiter returns \"withdrawn\" and the late arm is disarmed",
          "[spark][runtime][liveness]") {
    // Mutation: drop the claimed-rules loop from detach_all -> the in-flight r1 commits
    // after release (gen has a value, rule_count() == 1, nothing disarmed).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    // qe-101: the future is declared BEFORE the Cleanup guard (the file's idiom) so on
    // unwind the guard releases the parked backend first and the future's destructor
    // then joins an attach_rule that has already returned. Ownership order only: with
    // the 30 s REQUIRE and the 5 s backend_op_deadline the destructor could never stall
    // past the deadline either way (cpp-expert cx-202); the order is load-bearing for
    // the CHECKs under Catch2 abort mode, where the guard is the only release.
    auto fut = std::async(std::launch::async, [&] {
        return rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    });
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    CHECK(rt->rule_count() == 0);                     // claimed, not committed
    CHECK(rt->claim_queue_depth_for_test(key) == 1);

    rt->detach_all(); // the claimed-only branch: withdraws r1's in-flight claim
    auto gen = fut.get();
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "withdrawn");

    b->release_hang(); // the late success has no live claim to adopt -> disarmed
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->armed_ids() == b->disarmed_ids());
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    REQUIRE(yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key) == 0; },
                                   std::chrono::seconds(10)));
}

// ── rung 9c PR-2, Unit 2 (non-waiting arm entry, Astra opine review 2026-09-12 /
// coordinator ruling same date) ─────────────────────────────────────────────────
// attach_rule(NonWaiting, ...) shares attach_core() with the blocking overload
// above (Unit 1) and never calls wait_for_claim(). Checkpoint invariant per the
// staged plan: returning Accepted never abandons a claim; completion-before-return
// and stop races preserve ownership. Nothing in production calls this overload yet
// (Unit 6) - these are runtime-level tests only.

TEST_CASE("attach_rule(NonWaiting, ...): an inline-type arm resolves immediately as "
          "Armed, exactly like the blocking overload",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1",
                               SparkSpec{SparkType::Startup, StartupSparkParams{}},
                               file_exists_rule("r1"), true);
    REQUIRE(res.has_value());
    CHECK(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Armed);
    CHECK(res->generation != 0);
    CHECK(rt->rule_count() == 1);
}

TEST_CASE("attach_rule(NonWaiting, ...): an inline-type arm failure resolves "
          "immediately as Failed, exactly like the blocking overload",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    b->fail_arm = true;
    auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1",
                               SparkSpec{SparkType::Startup, StartupSparkParams{}},
                               file_exists_rule("r1"), true);
    REQUIRE_FALSE(res.has_value());
    CHECK(rt->rule_count() == 0);
}

TEST_CASE("attach_rule(NonWaiting, ...): a parked bounded arm returns Accepted with "
          "a Pending receipt, and never abandons the claim - it commits normally "
          "once released",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                               file_exists_rule("r1"), true);
    // Release the parked worker on every exit path (governance cs-202 idiom, same
    // as the blocking-overload timeout tests above).
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    REQUIRE(res.has_value());
    CHECK(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK_FALSE(rt->is_terminal(res->receipt));
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);
    CHECK(rt->rule_count() == 0); // not yet committed - still claimed only

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(res->receipt); },
                                   std::chrono::seconds(10)));
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Committed);
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("attach_rule(NonWaiting, ...): a same-key call queued behind an "
          "in-flight blocking arm is Accepted too, and joins the same watcher "
          "without dispatching its own backend arm",
          "[spark][runtime][liveness]") {
    // Mirrors the blocking-overload "QUEUES behind an in-flight arm" test above, but
    // the SECOND (queued) call goes through the non-waiting overload - Astra opine
    // review Blocker 1: "Queued siblings need this handoff too. They may be
    // accepted without their own executor submission. Setting the flag only when
    // submit() succeeds would still abandon them."
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::thread a_thread{[&] { rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                file_exists_rule("r2"), true);
    REQUIRE(res2.has_value());
    CHECK(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);
    CHECK(b->arm_entries.load() == 1); // r2 queued - it never entered arm() itself

    b->release_hang();
    a_thread.join();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(res2->receipt); },
                                   std::chrono::seconds(10)));
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Committed);
    CHECK(rt->rule_count() == 2);       // r1 (blocking) and r2 (non-waiting) both committed
    CHECK(rt->armed_key_count() == 1);  // one shared watcher
    CHECK(b->arms.load() == 1);         // exactly one real backend arm - r2 joined it
}

TEST_CASE("expire_overdue_claims(): a non-waiting claim's own overdue arm, with "
          "nobody blocked in wait_for_claim() to notice, is ADOPTED once the late "
          "success arrives - ruling 14(b): apply by current desired state, and "
          "nobody withdrew this rule while it was wedged",
          "[spark][runtime][liveness]") {
    // rung 9c PR-5d: this narrows #3816's cleanup policy for asynchronous desired-
    // state ownership, it does not reverse it - exactly-once result delivery and
    // continuous subscription ownership stay intact (the claim is still adopted or
    // disarmed exactly once, never twice, never leaked). What changes is that a
    // late success's disposition is now conditional on current desired state
    // instead of unconditional: this is the STEADY-STATE case (nobody withdrew
    // "r1"), covered by the withdrawn-regression-guard test right below this one.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                               file_exists_rule("r1"), true);
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); } // idempotent - the explicit release below still fires
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res.has_value());
    REQUIRE(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);

    // Not yet overdue: a no-op, idempotent call changes nothing.
    CHECK(rt->expire_overdue_claims() == 0);
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);

    // Real wall-clock wait past the 50ms deadline - KeyClaim::deadline is
    // std::chrono::steady_clock, not the injected test clock make_rt() wires for
    // attach_now/debounce bookkeeping, so this must be an actual sleep.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->is_terminal(res->receipt));
    // rung 9c PR-5c (#4221): this claim timed out while Dispatching (the backend
    // arm() call itself hung, not merely queued) - WaiterTimedOutDispatched, which
    // the enum split now names Wedged rather than the pre-split Expired.
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->backend_op_timeouts() == 1);
    CHECK(rt->rule_count() == 0); // never committed yet - the expiry beat the arm

    // The worker is still parked; releasing it now delivers a late success for a
    // rule NOBODY has withdrawn - rung 9c PR-5d adopts it: one watcher, live and
    // enforcing, zero compensating disarms. The receipt's own Wedged status is a
    // historical fact about THIS episode's timeout and must not flip to Committed -
    // sticky-Wedged is untouched by adoption (assert this explicitly, per the
    // umbrella kickoff's own test requirement).
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0); // adopted, never compensated
    CHECK(rt->backend_op_late_arms() == 0); // this counter is the disarm-path's own signal
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->armed_key_count() == 1);
    const auto status = rt->status_for_rule("r1");
    REQUIRE(status.has_value());
}

TEST_CASE("expire_overdue_claims(): a non-waiting claim's own overdue arm is "
          "disarmed, not adopted, when the rule was WITHDRAWN while wedged - "
          "regression guard for the pre-PR-5d default behaviour",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                               file_exists_rule("r1"), true);
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); } // idempotent - the explicit release below still fires
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res.has_value());
    REQUIRE(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Withdrawal reaches this retained claim through the candidacy sweep,
    // even after abandonment released its index mapping.
    rt->detach_rule("r1");

    // The worker is still parked; releasing it now delivers a late success for a
    // rule that IS no longer wanted - disarmed, exactly like the pre-PR-5d default.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->backend_op_late_arms() == 1);
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
}

TEST_CASE("expire_overdue_claims(): a late FAILURE on a still-desired wedged rule "
          "stays failed - no adoption, nothing to disarm, nothing newly armed",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                               file_exists_rule("r1"), true);
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); } // idempotent - the explicit release below still fires
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res.has_value());
    REQUIRE(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Nobody withdrew "r1" (still desired), but the backend's own late answer is a
    // FAILURE, not a success - row 4 of the late-result matrix: stays failed, no
    // new behaviour. `armed_live` is false in on_arm_complete, so the adoption
    // branch (which requires a live subscription to commit) never engages at all.
    b->fail_arm.store(true);
    b->release_hang();
    // Nothing to spin on but the claim's own eventual resolution - the claim was
    // already terminal (Wedged) before the late failure landed, so its own status
    // cannot change further; spin on the backend having actually been entered a
    // second time (there is only one arm() call total here, already counted) is
    // moot. A short bounded wait for arm_entries staying 1 and rule_count staying 0
    // is the only observable signal a genuinely async failure gives this test.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->disarms.load() == 0); // nothing was ever armed - nothing to disarm
}

TEST_CASE("rung 9c PR-5d: a Reobserved retry's own late success is adopted too - "
          "both the original and the reobserved receipt see the same Wedged "
          "status, and both agree the rule is now live",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); } // idempotent - the explicit release below still fires
    } cleanup{b.get()};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res1.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // An identical (rule_id, spec) retry re-observes the same wedged head instead
    // of queuing a new claim (rung 9c PR-5c up-2) - the SAME underlying KeyClaim,
    // confirmed by pointer identity below.
    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(res2.has_value());
    REQUIRE(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(rt->wedged_reobservations() == 1);
    CHECK(res2->receipt.claim == res1->receipt.claim);

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->armed_key_count() == 1);
}

// ── rung 9c PR-2, Unit 4 (compensation continuation, Astra opine review 2026-09-12)
// ─────────────────────────────────────────────────────────────────────────────────
// on_arm_complete's compensating disarm now dispatches through submit(), not a
// bounded run(): the arm claim it owns stays the key's barrier - not popped, not
// published - until the REAL disarm completion runs finalize_arm_compensation(),
// however long that takes. Checkpoint invariant: "An unwanted successful arm is
// owned continuously; its replacement cannot dispatch ahead of compensation."

TEST_CASE("rung 9c PR-2 Unit 4: a same-key rearm queued behind a withdrawn arm's "
          "compensating disarm cannot dispatch its own backend arm until that "
          "disarm actually completes",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::expected<std::uint64_t, std::string> gen_r1;
    std::thread a_thread{[&] {
        gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    }};
    struct ArmCleanup {
        FakeBackend* backend;
        std::thread* t;
        ~ArmCleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } arm_cleanup{b.get(), &a_thread};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // Case-0 withdraw: r1's dispatched head stays as the key's marker; nothing to
    // disarm YET (the arm hasn't landed), so detach_rule() returns immediately.
    rt->detach_rule("r1");

    // Park the NEXT disarm too - the compensating disarm this withdrawal owes once
    // r1's late arm lands.
    b->hang_next_disarm.store(true);
    struct DisarmCleanup {
        FakeBackend* backend;
        ~DisarmCleanup() { backend->release_disarm_hang(); }
    } disarm_cleanup{b.get()};

    b->release_hang(); // r1's arm lands: withdrawn -> compensation owed -> submitted -> parks
    REQUIRE(b->wait_entered_disarm_hang(std::chrono::seconds(30)));

    // r2 queues behind r1's still-present head (the compensating disarm's barrier) -
    // Accepted, not dispatched: only r1's original arm has ever entered arm().
    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                file_exists_rule("r2"), true);
    REQUIRE(res2.has_value());
    CHECK(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);
    CHECK(b->arm_entries.load() == 1); // the proof: r2 has NOT dispatched ahead of compensation

    b->release_disarm_hang(); // r1's compensation actually completes now
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(res2->receipt); },
                                   std::chrono::seconds(10)));
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Committed);
    CHECK(b->arm_entries.load() == 2); // r2 dispatched for real only after the barrier cleared
    CHECK(b->arms.load() == 2);
    REQUIRE(b->disarmed_ids().size() == 1);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[0]); // r1's OLD subscription, disarmed
    REQUIRE(b->armed_ids().size() == 2);
    CHECK(rt->rule_count() == 1); // only r2 - r1 was withdrawn, never committed
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("rung 9c PR-2 Unit 4: begin_stop() while a compensating disarm is still "
          "parked drops a queued sibling but leaves the barrier claim for its own "
          "completion to retire",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});
    const auto key = spark_key(file_spec("/a"));

    std::expected<std::uint64_t, std::string> gen_r1;
    std::thread a_thread{[&] {
        gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    }};
    struct ArmCleanup {
        FakeBackend* backend;
        std::thread* t;
        ~ArmCleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } arm_cleanup{b.get(), &a_thread};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    rt->detach_rule("r1");
    b->hang_next_disarm.store(true);
    struct DisarmCleanup {
        FakeBackend* backend;
        ~DisarmCleanup() { backend->release_disarm_hang(); }
    } disarm_cleanup{b.get()};
    b->release_hang();
    REQUIRE(b->wait_entered_disarm_hang(std::chrono::seconds(30)));

    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                file_exists_rule("r2"), true);
    REQUIRE(res2.has_value());
    REQUIRE(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    REQUIRE(rt->claim_queue_depth_for_test(key) == 2); // r1's barrier + r2's queued claim

    const auto stopped_before = rt->claims_dropped_at_stop();
    rt->begin_stop(); // r2 (Queued) is dropped Stopped; r1 (Dispatched) is left in place

    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Stopped);
    CHECK(rt->claims_dropped_at_stop() == stopped_before + 1);
    CHECK(rt->claim_queue_depth_for_test(key) == 1); // only r1's barrier survives

    b->release_disarm_hang(); // r1's compensation completes: pops it, fifo empties, no refill
    REQUIRE(yuzu::test::spin_until([&] { return rt->claim_queue_depth_for_test(key) == 0; },
                                   std::chrono::seconds(10)));
    CHECK(b->arm_entries.load() == 1); // r2 never dispatched - dropped before the barrier cleared
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// rung 9c PR-5b (#4221): up-3 (compensating-disarm reservation), up-4 (terminal-
// recovery maintenance pass), ch-1 (fill-in-allocation fault seams), up-5
// (disarm_retained_ real lifecycle + convergence-lane redrive wiring).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("up-3 (#4221): the compensating-disarm reservation refuses at capacity, before "
          "any backend arm runs - the accumulation-to-ceiling path is now unreachable",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    b->arm_park.park_every = 1; // every arm() call parks until pulse()

    // File-class reservation capacity == GuardianIoExecutor::Config{}.file_quota == 4.
    constexpr int kCapacity = 4;
    std::vector<std::thread> threads;
    std::vector<std::expected<std::uint64_t, std::string>> results(static_cast<std::size_t>(kCapacity));
    for (int i = 0; i < kCapacity; ++i) {
        threads.emplace_back([&, i] {
            const auto rid = "r" + std::to_string(i);
            results[static_cast<std::size_t>(i)] = rt->attach_rule(
                rid, file_spec("/k" + std::to_string(i)), file_exists_rule(rid), true);
        });
    }
    REQUIRE(yuzu::test::spin_until([&] { return b->arm_entries.load() == kCapacity; },
                                   std::chrono::seconds(10)));

    // A 5th, distinct-key File attach: capacity is fully reserved by the 4 parked
    // arms above, so this must be refused BEFORE ever calling backend->arm().
    const auto res5 = rt->attach_rule("r4", file_spec("/k4"), file_exists_rule("r4"), true);
    REQUIRE_FALSE(res5.has_value());
    CHECK(res5.error() == "compensating-disarm reservation exhausted");
    CHECK(rt->compensation_reservation_refused() == 1);
    CHECK(b->arm_entries.load() == kCapacity); // the 5th never entered arm()
    CHECK(rt->io_executor_stats_for_test().counters[0].rejected_ceiling == 0); // never got that far

    b->arm_park.pulse(); // release all 4 parked arms
    for (auto& t : threads)
        t.join();
    for (int i = 0; i < kCapacity; ++i)
        CHECK(results[static_cast<std::size_t>(i)].has_value());
    CHECK(b->arm_park.watchdog_trips == 0);
    b->arm_park.park_every = 0; // done parking - the 6th key below must arm normally

    // Capacity has recovered: a 6th distinct key now succeeds.
    const auto res6 = rt->attach_rule("r5", file_spec("/k5"), file_exists_rule("r5"), true);
    REQUIRE(res6.has_value());
}

TEST_CASE("up-3 (#4221): the compensation reservation is released on synchronous submission "
          "failure - repeated LaunchFailed refusals never exhaust the pool",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->set_io_executor_fail_launch_for_test(true);
    // File capacity is 4; drive well past it on DISTINCT keys - if the reservation
    // ever leaked on this synchronous-failure path, a later attempt would fail with
    // the reservation-exhausted reason instead of the expected LaunchFailed one.
    for (int i = 0; i < 10; ++i) {
        const auto rid = "r" + std::to_string(i);
        const auto res =
            rt->attach_rule(rid, file_spec("/k" + std::to_string(i)), file_exists_rule(rid), true);
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error() == "arm worker launch failed");
    }
    rt->set_io_executor_fail_launch_for_test(false);
    CHECK(rt->compensation_reservation_refused() == 0); // never once hit the reservation gate
    const auto ok = rt->attach_rule("rok", file_spec("/kok"), file_exists_rule("rok"), true);
    REQUIRE(ok.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// rung 9c PR-5c (#4221): the Dispatching-window race. abandon_claim_locked() can
// tag a claim WaiterTimedOutDispatched while dispatch_arm_off_lock()'s own
// admission decision is still unresolved; fail_all_claims_locked()'s guard
// (`if (c->end == ClaimEnd::None)`) then can't overwrite that stale value once
// admission genuinely resolves. All three tests below reproduce a genuine REFILL
// dispatch for a second claim (r2) on the same key as a withdrawn r1: r2 must be
// queued only AFTER on_arm_complete() has already decided nobody is eligible to
// ADOPT r1's late result (i.e. from inside the drain-gap hook, which fires right
// before the compensating disarm is submitted) - queuing r2 any earlier makes it
// a legitimate adopter of r1's own watcher instead (the "N consumers, 1 watcher"
// dedup path), which resolves inline and never dispatches r2 separately at all.
// Only a genuine refill's own dispatch runs on a detached worker thread, separate
// from the caller that already holds r2's own receipt - which is what makes the
// corrected `end` value observable via receipt_status() at all.
//
// CI finding (macOS, 2026-09-16): the three tests below saw
// "std::future_error: The state of the promise has already been set" crash the
// "REFILLED claim ... reservation-exhaustion" variant on CI (not reproduced
// locally after 250+ runs, incl. under heavy artificial CPU contention). r2's
// own claim legitimately passes through a transient Wedged classification in
// that variant (its own REQUIRE below waits for receipt_status() to move away
// from Wedged).
//
// Root cause: UNCONFIRMED (governance follow-up, 2026-09-16 - a 7-reviewer
// round traced this hard; do not restate as settled). #4415 (filed, deferred,
// confirmed pre-existing/not introduced by this PR) was the original
// candidate - a full-ruleset teardown+rearm storm against a
// persistently-wedged key, driven every heartbeat cycle - but this round
// traced it against make_rt()'s actual harness and found no heartbeat thread
// exists here to drive it: expire_overdue_claims() (the real heartbeat
// driver) is called at most once per test. Two further candidates were
// traced and also refuted: expire_overdue_claims()'s own reap-and-refill path
// (reap_stranded_claims_locked deliberately excludes a Dispatching/Dispatched
// head per its own comment, and r2's claim stays Dispatching throughout this
// test's call), and r2's own reservation-exhaustion refusal
// (dispatch_arm_off_lock's compensation-reservation check fails
// SYNCHRONOUSLY, inline, before io_executor_.submit() is ever reached, so it
// cannot itself produce a second on_arm_complete() call). No mechanism this
// round traced legitimately reaches a second firing within this bare-runtime
// harness; whether the CI crash was a genuine second firing via a mechanism
// not yet found, or something else entirely, remains open - see #4415 for
// the live investigation, not this comment.
//
// The fix below is deliberately mechanism-agnostic: rather than chase the
// unconfirmed trigger, make the hook and its two signalling promises SAFE
// against a second firing instead of merely single-shot - a second gap_hook
// call is a no-op (r2 is already correctly set up by the first, and this is
// logged to stderr for CI-log forensic visibility - see
// gap_hook_fire_count's own comment below), and a second set_value() on
// either promise is an ignored late/duplicate signal rather than an
// uncaught exception. This assumes the test's OWN genuine firing arrives
// before any hypothetical second one; if that ordering ever inverted, the
// outcome is a bounded REQUIRE/CHECK failure downstream (this file's
// existing spin_until timeouts), not a hang (sre finding, governance
// follow-up, 2026-09-16).
//
// Lifetime, corrected (cpp-safety + security-guardian finding, governance
// follow-up, 2026-09-16): a stale gap-hook invocation that already copied
// the closure under registry_mu_ before Cleanup's destructor clears the
// registration is the SAME already-parked cross-teardown TOCTOU Cleanup's
// own destructor comment below describes ("tracked, not fixed" there;
// tracked as finding HC-1b-residual-toctou-already-copied-hook in
// governance.d/4417-spark-9c-pr5c-macos-tsan-fix.MinBIf.jsonl, referred to
// as "HC-1b" below for brevity), not a distinct hazard class -
// gap_hook_fire_count is one more [&]-captured local newly reachable
// through that pre-existing, deferred window, exactly like
// entered/release_hook/r2_thread already were. Independently confirmed
// unchanged/not worsened by this fix (narrows the blast radius of an
// in-frame second firing from a guaranteed crash to a safe no-op; does not
// itself widen or narrow that window). This is NOT a claim that these
// firings, if they happen, cannot outlive this TEST_CASE's own stack frame
// via that same TOCTOU - an earlier draft of this comment wrongly claimed
// that; see Cleanup's own destructor comment below for the actual,
// still-open window.
static void set_value_once(std::promise<void>& p) noexcept {
    try {
        p.set_value();
    } catch (const std::future_error& e) {
        // cpp-expert/cpp-safety/unhappy-path finding (governance follow-up,
        // 2026-09-16, UP-4): the catch clause itself still catches every
        // future_error code (security-guardian correction, Gate 8, 2026-09-16:
        // an earlier version of this comment said "narrowed from a blanket
        // catch", which overstated it) - what's new is discriminating INSIDE
        // the catch: promise_already_satisfied is the duplicate-wake case this
        // function exists to swallow; no_state (set_value on an empty/moved-
        // from promise) is a genuinely different defect class and must not be
        // silently absorbed. noexcept forbids rethrowing here, so report
        // loudly instead - fprintf(stderr) is safe from any thread (plain
        // stdio, not Catch2's non-thread-safe assertion machinery).
        if (e.code() != std::future_errc::promise_already_satisfied) {
            std::fprintf(stderr,
                         "set_value_once(): unexpected future_error (%s) - not "
                         "a duplicate-wake, swallowing anyway because this "
                         "function is noexcept; investigate\n",
                         e.what());
        }
        // Already satisfied by an earlier (first, or a late-arriving second)
        // firing - a duplicate wake, not a defect in the waiter's own logic.
    }
}
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("rung 9c PR-5c (#4221): the Dispatching-window race no longer misclassifies "
          "an ordinary admission failure on a REFILLED claim as Wedged",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    const auto key = spark_key(file_spec("/a"));

    std::expected<std::uint64_t, std::string> gen_r1;
    std::thread a_thread{[&] {
        gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->detach_rule("r1"); // Case 0: withdrawn, stays as the key's marker for its late result
    a_thread.join();
    REQUIRE_FALSE(gen_r1.has_value());
    CHECK(gen_r1.error() == "withdrawn");

    // From inside the drain-gap hook - fires once on_arm_complete() has already
    // decided nobody is eligible to adopt r1's late result, right before the
    // compensating disarm is submitted (its own doc comment: "the ONE gap where a
    // key's outcome is decided but its claims are still unpublished") - queue r2
    // and install our own entry hook for ITS eventual (genuine) refill dispatch.
    std::expected<GuardianSparkRuntime::ArmOutcome, GuardianSparkRuntime::ArmError> res2;
    std::thread r2_thread;
    std::promise<void> entered;
    std::promise<void> release_hook;
    bool released_by_test = false;
    auto entered_fut = entered.get_future();
    auto release_fut = release_hook.get_future().share(); // cpp-safety/chaos-injector
        // finding (governance follow-up, 2026-09-16, CH-3): get_future() throws
        // future_already_retrieved on any call after the first, REGARDLESS of
        // whether set_value() was ever called - retrieved once here, before any
        // hook registration, so the entry hook below can safely .wait() on the
        // shared_future even if it were ever invoked more than once. Today
        // prevented under this test's own sequencing (move-consumption at
        // dispatch_arm_off_lock's entry-hook read, under registry_mu_; no
        // other dispatch reaches this runtime instance between the drain-gap
        // hook's registration and r2's own consumption of it) - #4415 tracks
        // the open question of whether anything can violate that sequencing
        // (tracked as finding UP-5 in
        // governance.d/4417-spark-9c-pr5c-second-macos-followup.OatQnp.jsonl:
        // speculative, not confirmed as live, linked to #4415). This hoist is
        // defense-in-depth either way.
    std::atomic<bool> r2_queued_before_dispatch{false}; // set from the hook below (a
        // worker thread, not this one) - atomic per this file's own established
        // pattern for exactly this hook-thread-to-main-thread signal (see
        // r2_queue_wait_ok a few tests up); see the hook's own comment for why this
        // can't be a REQUIRE() there directly
    std::atomic<bool> hook_done{false}; // Gate 8 round 4 cpp-safety finding
        // (governance follow-up, 2026-09-16, HP-1): true ONLY as the hook's own
        // LAST statement below, once r2_queued_before_dispatch has already been
        // stored - unlike entered_fut (a DISPATCH-ENTRY signal that can fire from
        // r2_thread directly, independent of this hook, on the exact regression
        // this test exists to catch), this is a genuine HOOK-COMPLETION signal,
        // matching r2_queue_wait_ok's own precedent (its outer wait spins on its
        // own hook's LAST store, not on a different signal entirely). Declared
        // BEFORE Cleanup so it outlives Cleanup's destructor, which waits on it
        // FIRST, before touching r2_thread or anything else this frame owns.
    std::atomic<int> gap_hook_fire_count{0}; // cpp-safety/quality-engineer/
        // unhappy-path finding (governance follow-up, 2026-09-16, UP-1/QE-1):
        // was a bool gap_hook_ran - upgraded to a fire count so a repeat firing
        // is forensically visible in CI logs (see the hook body below) instead
        // of a silent no-op; a genuine (non-benign) repeat firing this file's
        // assertions cannot otherwise distinguish from #4415's still-unconfirmed
        // candidate mechanism (see the CI-finding comment above set_value_once)
        // now leaves a trace. Only the FIRST firing sets r2 up; every later one
        // is a no-op, not a re-spawn (re-running the body below would reassign
        // r2_thread while the first r2_thread may still be joinable -
        // std::terminate per [thread.thread.assign] - and double-register the
        // entry hook for no purpose, since r2 is already correctly parked by
        // the first firing). Reachable through the same pre-existing,
        // already-parked HC-1b TOCTOU as entered/release_hook/r2_thread - see
        // the CI-finding comment above set_value_once for the full account.
        // relaxed is sufficient (cpp-safety-confirmed, Gate 8 governance
        // follow-up, 2026-09-16): this guard's only job is exactly-one-winner
        // RMW mutual exclusion on ITS OWN modification order - it publishes no
        // other field through itself, so no stronger ordering is needed.
    std::atomic<int> entry_hook_fire_count{0}; // Gate 8 governance follow-up
        // (round 5, 2026-09-16) rewrite of the original external-review comment,
        // correcting two findings raised against it (quality-engineer,
        // consistency-auditor): `entered` IS the only promise this file's hooks
        // ever set from a worker thread (release_hook is always main-thread-
        // sequenced: set only in Cleanup's destructor and in this test's own
        // main-thread flow, never inside a hook lambda), but that does NOT make entry_hook
        // the more plausible duplicate-fire route - the opposite: production code
        // MOVES `dispatch_entry_hook_for_test_` out at first fire
        // (guardian_spark_runtime.cpp:557), so this hook is single-fire by
        // construction under normal operation, unlike `drain_gap_hook_for_test_`
        // (COPIED at :919, genuinely capable of firing again - why
        // gap_hook_fire_count needs its early-return guard and CHECK). A
        // CHECK==1 here would in fact be safely orderable too - entered_fut's
        // own wait_for()==ready already synchronizes-with the fetch_add below
        // (security-guardian/cpp-safety confirmed) - but is kept diagnostic-only:
        // a repeat firing here can only mean the same pre-existing, already-
        // tracked HC-1b TOCTOU (#4431) or an unspecified moved-from std::function edge
        // case, not a legitimate repeat path the way gap_hook_fire_count's is.
        // relaxed is sufficient (same reasoning as gap_hook_fire_count's own
        // note): this guard's only job is exactly-one-winner RMW mutual
        // exclusion on its own modification order - it publishes no other field
        // through itself.
    rt->set_drain_gap_hook_for_test([&] {
        // cpp-expert/security-guardian/unhappy-path finding (Gate 8 governance
        // follow-up, 2026-09-16): use fetch_add's OWN return value for the
        // printed count, not a separate .load() - under 3+ concurrent firings
        // a separate load could print a stale or duplicate count relative to
        // the caller's own fetch_add result.
        if (const int prior = gap_hook_fire_count.fetch_add(1, std::memory_order_relaxed);
            prior > 0) {
            std::fprintf(stderr,
                         "drain-gap hook fired again (fire #%d) after the first "
                         "firing already parked r2 - no-op (see "
                         "gap_hook_fire_count's own declaration comment). Plain "
                         "fprintf(stderr), not a Catch2 assertion, so safe from "
                         "this (non-main) thread.\n",
                         prior + 1);
            return;
        }
        // See entry_hook_fire_count's own declaration comment above for why
        // this hook is single-fire by construction (unlike the gap hook above)
        // and why no early-return guard is needed here: set_value_once already
        // makes a repeat set_value() safe, and a shared_future tolerates repeat
        // .wait() calls.
        rt->set_dispatch_entry_hook_for_test([&] {
            if (const int prior = entry_hook_fire_count.fetch_add(1, std::memory_order_relaxed);
                prior > 0) {
                std::fprintf(stderr,
                             "dispatch-entry hook fired again (fire #%d) - entered "
                             "was already set; set_value_once absorbs it safely, "
                             "but this is worth investigating (see "
                             "entry_hook_fire_count's own declaration comment).\n",
                             prior + 1);
            }
            set_value_once(entered);
            release_fut.wait();
        });
        r2_thread = std::thread{[&] {
            res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                   file_exists_rule("r2"), true);
        }};
        // CI finding (macOS crash, 2026-09-16): Catch2's assertion machinery is NOT
        // thread-safe from any thread but the one running the test case - this hook
        // runs on a detached io_executor_ worker (fired from inside
        // on_arm_complete()'s own drain), not the main test thread. A REQUIRE here
        // raced Catch2's internal OutputRedirect state under TSan (confirmed) and,
        // on a genuine failure, throws Catch::TestFailureException with no handler
        // on this thread - std::terminate (reproduced identically under artificial
        // CPU contention on Linux: "terminate called after throwing an instance of
        // 'Catch::TestFailureException'" at this exact line). Capture the result
        // instead; the real REQUIRE runs after entered_fut proves this hook has
        // already returned - see below.
        r2_queued_before_dispatch.store(
            yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));
        hook_done.store(true); // MUST be the hook's last statement - see hook_done's
                               // own declaration comment above.
    });
    struct Cleanup {
        std::atomic<bool>* hook_done;
        GuardianSparkRuntime* rt; // non-owning, same convention as the other raw-pointer
                                 // fields below; rt is declared far earlier in this
                                 // TEST_CASE so it outlives cleanup (LIFO destruction)
        std::promise<void>* release_hook;
        bool* released;
        std::thread* r2t;
        ~Cleanup() {
            // Gate 8 round 4 cpp-safety finding (governance follow-up, 2026-09-16,
            // HP-1): wait for the drain-gap hook's own worker thread to genuinely
            // finish BEFORE touching anything else this frame owns - on the exact
            // regression this test exists to catch, entered_fut (below) can go
            // ready, and REQUIRE(r2_queued_before_dispatch.load()) can throw and
            // start unwinding THIS destructor, while that worker thread is still
            // alive: without this wait, r2_queued_before_dispatch's storage (and
            // this test's own [&] hook, still registered on rt) would be destroyed
            // while that thread is still about to write into them - a genuine
            // use-after-free, not a residual/theoretical race. Bounded (matches the
            // outer wait's own margin), so a genuinely wedged hook still fails
            // loudly rather than hanging teardown. Ordering matters: this MUST run
            // before the joinable()/join() below, because the hook is what ASSIGNS
            // r2t (see r2_thread's own assignment above) - reading joinable() first
            // would itself race that assignment.
            // Never REQUIRE/CHECK/throw here: ~Cleanup() has no exception
            // specification, so per [class.dtor] it is implicitly noexcept(true)
            // regardless of unwind state - ANY throw here terminates unconditionally,
            // not merely "if already unwinding" (cpp-expert finding, governance
            // follow-up, 2026-09-16, Gate 8 round 5). Exactly the crash class this
            // whole file's governance history exists to avoid either way. A timeout
            // is loud (stderr), never silent, but never fatal from here.
            // quality-engineer finding (governance follow-up, 2026-09-16, Gate 8
            // round 5): spin_until() ALREADY multiplies its own timeout by
            // kSpinScale internally (test_helpers.hpp) - passing a pre-scaled
            // duration here double-scales to kSpinScale^2 (1080s under TSan/ASan,
            // not the intended 180s). Pass the bare, unscaled duration, matching
            // every other spin_until call site in this file.
            if (!yuzu::test::spin_until([&] { return hook_done->load(); },
                                        std::chrono::seconds(30))) {
                std::fprintf(stderr,
                             "Cleanup::~Cleanup(): hook_done wait timed out - the "
                             "drain-gap hook's worker thread did not finish within "
                             "its bound; proceeding anyway (see hook_done's own "
                             "declaration comment)\n");
            }
            // cpp-safety finding (governance follow-up, 2026-09-16, Gate 8 round 5,
            // HC-1): clear BOTH test hooks (each captures this frame's locals by
            // reference) BEFORE releasing/joining anything else - hook_done above
            // only proves the drain-gap hook's OWN first firing has finished; it says
            // nothing about whether on_arm_complete could invoke it AGAIN (e.g. for
            // r2's own eventual completion) while this frame is being torn down.
            // set_*_hook_for_test({}) takes the runtime's registry_mu_, the same lock
            // on_arm_complete copies the hook under, so this closes the window for
            // any not-yet-in-flight second firing. (A firing that already copied the
            // hook before this clear lands is a narrower, separate TOCTOU - tracked,
            // not fixed, in this pass.)
            rt->set_drain_gap_hook_for_test({});
            rt->set_dispatch_entry_hook_for_test({});
            if (!*released)
                set_value_once(*release_hook);
            if (r2t->joinable())
                r2t->join();
        }
    } cleanup{&hook_done, rt.get(), &release_hook, &released_by_test, &r2_thread};

    b->release_hang(); // r1's late arm lands: drain -> gap hook (queues r2) -> compensation
    // Gate 3 sre finding (governance follow-up, 2026-09-16): must be scaled by
    // kSpinScale like the file's own spin_until-based precedent (r2_queue_wait_ok
    // a few tests up uses spin_until for ITS outer wait too, which scales
    // internally) - the gap hook's own inner spin_until above is bounded to
    // std::chrono::seconds(10) but THAT bound is scaled by kSpinScale (up to 6x
    // under TSan/ASan). An unscaled 30s outer bound could then be shorter than a
    // scaled-up inner wait still legitimately running, so unwinding here could
    // start while the drain-gap hook's worker thread is still alive and about to
    // write into r2_queued_before_dispatch above - a stack lifetime hazard, not
    // just a slow test. Scale this bound the same way so it always stays the
    // larger of the two. Gate 4 unhappy-path (governance follow-up, 2026-09-16,
    // UP-1) found a tried 2x-margin variant of this fix (outer bound 20s) HALVED
    // the plain-build (kSpinScale==1) margin-over-the-inner-10s-bound from 20s
    // to 10s versus the pre-170778b42 baseline of 30s - and this commit's OWN
    // message records the original
    // crash reproduced under plain CPU contention on Linux, not only under
    // TSan/ASan, so a thin plain-build margin is not a safe trade. Reverted to
    // the file's usual 3x margin (30s); the CI-entry-timeout-budget concern
    // this 2x variant was chasing (a Gate 8 sre finding) is real but only bites
    // in an already-red, all-three-hang build and is better closed structurally
    // (its own meson entry, matching the [tsan-heavy] split precedent) than by
    // trimming this margin - tracked, not fixed, in this pass.
    REQUIRE(entered_fut.wait_for(std::chrono::seconds(30) * yuzu::test::kSpinScale) ==
            std::future_status::ready);
    // External review finding (fjarvis's adversarial panel, Codex+Kimi convergent,
    // 2026-09-16): entered_fut succeeding does NOT by itself prove the drain-gap
    // hook has returned or that r2_queued_before_dispatch has been stored (entry_hook
    // can fire from r2_thread directly, independent of the hook's own thread - see
    // hook_done's own declaration comment above - so entered_fut can go ready WHILE
    // the hook is still inside its own spin_until, before it has written anything).
    // An earlier version of this comment claimed the read below was "safe" because
    // Cleanup's destructor waits on hook_done - true for UAF-safety (HP-1, still
    // correct), but irrelevant to THIS read: the destructor only runs AFTER this
    // REQUIRE, on the unwind path IF it throws - it protects safe teardown of a
    // spurious failure, it does not prevent one. Wait for hook_done HERE, on the
    // main thread, before reading the flag it guards - bare duration (spin_until
    // scales internally, matching every other call site in this file); no deadlock
    // risk since the hook's own wait is bounded and depends on nothing from this
    // thread.
    REQUIRE(yuzu::test::spin_until([&] { return hook_done.load(); }, std::chrono::seconds(30)));
    REQUIRE(r2_queued_before_dispatch.load());
    r2_thread.join();
    rt->set_drain_gap_hook_for_test({});
    // quality-engineer/unhappy-path finding (Gate 8 governance follow-up,
    // 2026-09-16): unlike Cleanup's noexcept destructor (which must never
    // assert), THIS is a safe, ordinary main-thread assertion point - after
    // r2_thread has joined and the hook is cleared, so no further firing can
    // be registered. A stale ALREADY-in-flight copy from the pre-existing,
    // parked HC-1b TOCTOU could theoretically still land after this line, but
    // that window is unchanged by this file's own fix and already tracked
    // separately - this CHECK closes the ordinary case: on every one of this
    // round's 25 empirical runs the count was 1, never higher.
    CHECK(gap_hook_fire_count.load(std::memory_order_relaxed) == 1);
    REQUIRE(res2.has_value());
    REQUIRE(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);

    // r2 is now Dispatching (try_dispatch_head_locked flipped it before this
    // function was ever entered) but its own admission is still unresolved -
    // parked in the hook. Time it out from the test's own thread.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1); // only r2 - r1 already compensated and popped.

    // rung 9c PR-5e (#4221, K-bound closeout): this is EXACTLY the unsettled window
    // receipt_wedge_k_eligible() exists to exclude - receipt_status() already reads
    // Wedged (checked below, unchanged from before this PR), but r2's own `dispatch`
    // is still Dispatching (this test's own comment above), not yet Dispatched - a
    // K-waiver predicate relying on receipt_status() alone would treat this as
    // K-eligible one tick before dispatch_arm_off_lock's own re-lock corrects it.
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK_FALSE(rt->receipt_wedge_k_eligible(res2->receipt));

    // Adversarial review finding (Kimi K3 + Codex Sol independently converging,
    // mutation-proven): GuardianArmAckLedger::drain_locked()'s own PRIMARY per-pending
    // loop must ALSO gate on receipt_wedge_k_eligible() before inserting into
    // failed_receipts - not just the recovery-scan loop that re-validates EXISTING
    // entries a tick later. Drive a real ledger drain WHILE r2 sits in this exact
    // unsettled window (receipt_status() already Wedged, receipt_wedge_k_eligible()
    // still false) - deleting that insertion-site gate leaves every test in this file
    // and in test_guardian_arm_ack.cpp green (proven by mutation during review), since
    // none of them reach this specific window through a real ledger drain. This is
    // that missing regression test.
    {
        GuardianArmAckLedger ledger;
        ledger.begin_application(1, std::string(64, 'r'), false, 1);
        ledger.add_pending("r2", res2->receipt);
        CHECK(ledger.drain_locked(*rt, 10) == 1); // resolved (Wedged), but NOT K-eligible yet
        CHECK(ledger.failed_receipt_count_for_test() == 0); // must NOT be inserted while unsettled
        const auto s = ledger.arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1); // still counted as an ordinary failure - resolved_failed unaffected
    }

    // Let admission resolve for real, as an ORDINARY (non-Stopped) refusal.
    rt->set_io_executor_fail_launch_for_test(true);
    released_by_test = true;
    set_value_once(release_hook);
    // NOT is_terminal(): expire_overdue_claims() above already made that trivially
    // true (WaiterTimedOutDispatched/Wedged is itself a terminal-shaped status) -
    // wait specifically for the value to move AWAY from the stale Wedged result,
    // which only happens once the real (corrected) resolution below has actually run.
    REQUIRE(yuzu::test::spin_until(
        [&] {
            return rt->receipt_status(res2->receipt) != GuardianSparkRuntime::ReceiptStatus::Wedged;
        },
        std::chrono::seconds(10)));
    rt->set_io_executor_fail_launch_for_test(false);

    // rung 9c PR-5e (#4221, K-bound closeout): post-correction, receipt_status() has
    // moved to Failed (checked below, unchanged) - receipt_wedge_k_eligible() must
    // stay false too, for the OPPOSITE reason now: `dispatch` never reaches
    // Dispatched on this synchronous-admission-failure path (dispatch_arm_off_lock()
    // only ever writes Dispatched on a successful submission), so the strict
    // `dispatch == Dispatched` clause excludes it just as it did in the unsettled
    // window above - the two checks together never produce a false-eligible window
    // on either side of the correction.
    CHECK_FALSE(rt->receipt_wedge_k_eligible(res2->receipt));

    // Pre-fix: fail_all_claims_locked()'s guard could not overwrite the stale
    // WaiterTimedOutDispatched already on r2, so this stayed Wedged even though
    // the real cause was an ordinary admission rejection, not a timeout.
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Failed);
    CHECK(rt->rule_count() == 0); // r1 withdrawn, never committed; r2 failed too

    // The key fully recovers: a fresh attach now arms normally.
    const auto res3 = rt->attach_rule("r3", file_spec("/a"), file_exists_rule("r3"), true);
    REQUIRE(res3.has_value());
    CHECK(rt->rule_count() == 1);
}

TEST_CASE("rung 9c PR-5c (#4221): the Dispatching-window race, Stopped variant - a "
          "stop landing in the same window still reports Stopped, not a stale timeout",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});

    std::expected<std::uint64_t, std::string> gen_r1;
    std::thread a_thread{[&] {
        gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->detach_rule("r1");
    a_thread.join();
    REQUIRE_FALSE(gen_r1.has_value());

    std::expected<GuardianSparkRuntime::ArmOutcome, GuardianSparkRuntime::ArmError> res2;
    std::thread r2_thread;
    std::promise<void> entered;
    std::promise<void> release_hook;
    bool released_by_test = false;
    auto entered_fut = entered.get_future();
    auto release_fut = release_hook.get_future().share(); // cpp-safety/chaos-injector
        // finding (governance follow-up, 2026-09-16, CH-3): get_future() throws
        // future_already_retrieved on any call after the first, REGARDLESS of
        // whether set_value() was ever called - retrieved once here, before any
        // hook registration, so the entry hook below can safely .wait() on the
        // shared_future even if it were ever invoked more than once. Today
        // prevented under this test's own sequencing (move-consumption at
        // dispatch_arm_off_lock's entry-hook read, under registry_mu_; no
        // other dispatch reaches this runtime instance between the drain-gap
        // hook's registration and r2's own consumption of it) - #4415 tracks
        // the open question of whether anything can violate that sequencing
        // (tracked as finding UP-5 in
        // governance.d/4417-spark-9c-pr5c-second-macos-followup.OatQnp.jsonl:
        // speculative, not confirmed as live, linked to #4415). This hoist is
        // defense-in-depth either way.
    std::atomic<bool> r2_queued_before_dispatch{false}; // set from the hook below (a
        // worker thread, not this one) - atomic per this file's own established
        // pattern for exactly this hook-thread-to-main-thread signal (see
        // r2_queue_wait_ok a few tests up); see the hook's own comment for why this
        // can't be a REQUIRE() there directly
    std::atomic<bool> hook_done{false}; // Gate 8 round 4 cpp-safety finding
        // (governance follow-up, 2026-09-16, HP-1): true ONLY as the hook's own
        // LAST statement below, once r2_queued_before_dispatch has already been
        // stored - unlike entered_fut (a DISPATCH-ENTRY signal that can fire from
        // r2_thread directly, independent of this hook, on the exact regression
        // this test exists to catch), this is a genuine HOOK-COMPLETION signal,
        // matching r2_queue_wait_ok's own precedent (its outer wait spins on its
        // own hook's LAST store, not on a different signal entirely). Declared
        // BEFORE Cleanup so it outlives Cleanup's destructor, which waits on it
        // FIRST, before touching r2_thread or anything else this frame owns.
    std::atomic<int> gap_hook_fire_count{0}; // cpp-safety/quality-engineer/
        // unhappy-path finding (governance follow-up, 2026-09-16, UP-1/QE-1):
        // was a bool gap_hook_ran - upgraded to a fire count so a repeat firing
        // is forensically visible in CI logs (see the hook body below) instead
        // of a silent no-op; a genuine (non-benign) repeat firing this file's
        // assertions cannot otherwise distinguish from #4415's still-unconfirmed
        // candidate mechanism (see the CI-finding comment above set_value_once)
        // now leaves a trace. Only the FIRST firing sets r2 up; every later one
        // is a no-op, not a re-spawn (re-running the body below would reassign
        // r2_thread while the first r2_thread may still be joinable -
        // std::terminate per [thread.thread.assign] - and double-register the
        // entry hook for no purpose, since r2 is already correctly parked by
        // the first firing). Reachable through the same pre-existing,
        // already-parked HC-1b TOCTOU as entered/release_hook/r2_thread - see
        // the CI-finding comment above set_value_once for the full account.
        // relaxed is sufficient (cpp-safety-confirmed, Gate 8 governance
        // follow-up, 2026-09-16): this guard's only job is exactly-one-winner
        // RMW mutual exclusion on ITS OWN modification order - it publishes no
        // other field through itself, so no stronger ordering is needed.
    std::atomic<int> entry_hook_fire_count{0}; // Gate 8 governance follow-up
        // (round 5, 2026-09-16) rewrite of the original external-review comment,
        // correcting two findings raised against it (quality-engineer,
        // consistency-auditor): `entered` IS the only promise this file's hooks
        // ever set from a worker thread (release_hook is always main-thread-
        // sequenced: set only in Cleanup's destructor and in this test's own
        // main-thread flow, never inside a hook lambda), but that does NOT make entry_hook
        // the more plausible duplicate-fire route - the opposite: production code
        // MOVES `dispatch_entry_hook_for_test_` out at first fire
        // (guardian_spark_runtime.cpp:557), so this hook is single-fire by
        // construction under normal operation, unlike `drain_gap_hook_for_test_`
        // (COPIED at :919, genuinely capable of firing again - why
        // gap_hook_fire_count needs its early-return guard and CHECK). A
        // CHECK==1 here would in fact be safely orderable too - entered_fut's
        // own wait_for()==ready already synchronizes-with the fetch_add below
        // (security-guardian/cpp-safety confirmed) - but is kept diagnostic-only:
        // a repeat firing here can only mean the same pre-existing, already-
        // tracked HC-1b TOCTOU (#4431) or an unspecified moved-from std::function edge
        // case, not a legitimate repeat path the way gap_hook_fire_count's is.
        // relaxed is sufficient (same reasoning as gap_hook_fire_count's own
        // note): this guard's only job is exactly-one-winner RMW mutual
        // exclusion on its own modification order - it publishes no other field
        // through itself.
    rt->set_drain_gap_hook_for_test([&] {
        // cpp-expert/security-guardian/unhappy-path finding (Gate 8 governance
        // follow-up, 2026-09-16): use fetch_add's OWN return value for the
        // printed count, not a separate .load() - under 3+ concurrent firings
        // a separate load could print a stale or duplicate count relative to
        // the caller's own fetch_add result.
        if (const int prior = gap_hook_fire_count.fetch_add(1, std::memory_order_relaxed);
            prior > 0) {
            std::fprintf(stderr,
                         "drain-gap hook fired again (fire #%d) after the first "
                         "firing already parked r2 - no-op (see "
                         "gap_hook_fire_count's own declaration comment). Plain "
                         "fprintf(stderr), not a Catch2 assertion, so safe from "
                         "this (non-main) thread.\n",
                         prior + 1);
            return;
        }
        // See entry_hook_fire_count's own declaration comment above for why
        // this hook is single-fire by construction (unlike the gap hook above)
        // and why no early-return guard is needed here: set_value_once already
        // makes a repeat set_value() safe, and a shared_future tolerates repeat
        // .wait() calls.
        rt->set_dispatch_entry_hook_for_test([&] {
            if (const int prior = entry_hook_fire_count.fetch_add(1, std::memory_order_relaxed);
                prior > 0) {
                std::fprintf(stderr,
                             "dispatch-entry hook fired again (fire #%d) - entered "
                             "was already set; set_value_once absorbs it safely, "
                             "but this is worth investigating (see "
                             "entry_hook_fire_count's own declaration comment).\n",
                             prior + 1);
            }
            set_value_once(entered);
            release_fut.wait();
        });
        r2_thread = std::thread{[&] {
            res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                   file_exists_rule("r2"), true);
        }};
        // CI finding (macOS crash, 2026-09-16): Catch2's assertion machinery is NOT
        // thread-safe from any thread but the one running the test case - this hook
        // runs on a detached io_executor_ worker (fired from inside
        // on_arm_complete()'s own drain), not the main test thread. A REQUIRE here
        // raced Catch2's internal OutputRedirect state under TSan (confirmed) and,
        // on a genuine failure, throws Catch::TestFailureException with no handler
        // on this thread - std::terminate (reproduced identically under artificial
        // CPU contention on Linux: "terminate called after throwing an instance of
        // 'Catch::TestFailureException'" at this exact line). Capture the result
        // instead; the real REQUIRE runs after entered_fut proves this hook has
        // already returned - see below.
        r2_queued_before_dispatch.store(
            yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));
        hook_done.store(true); // MUST be the hook's last statement - see hook_done's
                               // own declaration comment above.
    });
    struct Cleanup {
        std::atomic<bool>* hook_done;
        GuardianSparkRuntime* rt; // non-owning, same convention as the other raw-pointer
                                 // fields below; rt is declared far earlier in this
                                 // TEST_CASE so it outlives cleanup (LIFO destruction)
        std::promise<void>* release_hook;
        bool* released;
        std::thread* r2t;
        ~Cleanup() {
            // Gate 8 round 4 cpp-safety finding (governance follow-up, 2026-09-16,
            // HP-1): wait for the drain-gap hook's own worker thread to genuinely
            // finish BEFORE touching anything else this frame owns - on the exact
            // regression this test exists to catch, entered_fut (below) can go
            // ready, and REQUIRE(r2_queued_before_dispatch.load()) can throw and
            // start unwinding THIS destructor, while that worker thread is still
            // alive: without this wait, r2_queued_before_dispatch's storage (and
            // this test's own [&] hook, still registered on rt) would be destroyed
            // while that thread is still about to write into them - a genuine
            // use-after-free, not a residual/theoretical race. Bounded (matches the
            // outer wait's own margin), so a genuinely wedged hook still fails
            // loudly rather than hanging teardown. Ordering matters: this MUST run
            // before the joinable()/join() below, because the hook is what ASSIGNS
            // r2t (see r2_thread's own assignment above) - reading joinable() first
            // would itself race that assignment.
            // Never REQUIRE/CHECK/throw here: ~Cleanup() has no exception
            // specification, so per [class.dtor] it is implicitly noexcept(true)
            // regardless of unwind state - ANY throw here terminates unconditionally,
            // not merely "if already unwinding" (cpp-expert finding, governance
            // follow-up, 2026-09-16, Gate 8 round 5). Exactly the crash class this
            // whole file's governance history exists to avoid either way. A timeout
            // is loud (stderr), never silent, but never fatal from here.
            // quality-engineer finding (governance follow-up, 2026-09-16, Gate 8
            // round 5): spin_until() ALREADY multiplies its own timeout by
            // kSpinScale internally (test_helpers.hpp) - passing a pre-scaled
            // duration here double-scales to kSpinScale^2 (1080s under TSan/ASan,
            // not the intended 180s). Pass the bare, unscaled duration, matching
            // every other spin_until call site in this file.
            if (!yuzu::test::spin_until([&] { return hook_done->load(); },
                                        std::chrono::seconds(30))) {
                std::fprintf(stderr,
                             "Cleanup::~Cleanup(): hook_done wait timed out - the "
                             "drain-gap hook's worker thread did not finish within "
                             "its bound; proceeding anyway (see hook_done's own "
                             "declaration comment)\n");
            }
            // cpp-safety finding (governance follow-up, 2026-09-16, Gate 8 round 5,
            // HC-1): clear BOTH test hooks (each captures this frame's locals by
            // reference) BEFORE releasing/joining anything else - hook_done above
            // only proves the drain-gap hook's OWN first firing has finished; it says
            // nothing about whether on_arm_complete could invoke it AGAIN (e.g. for
            // r2's own eventual completion) while this frame is being torn down.
            // set_*_hook_for_test({}) takes the runtime's registry_mu_, the same lock
            // on_arm_complete copies the hook under, so this closes the window for
            // any not-yet-in-flight second firing. (A firing that already copied the
            // hook before this clear lands is a narrower, separate TOCTOU - tracked,
            // not fixed, in this pass.)
            rt->set_drain_gap_hook_for_test({});
            rt->set_dispatch_entry_hook_for_test({});
            if (!*released)
                set_value_once(*release_hook);
            if (r2t->joinable())
                r2t->join();
        }
    } cleanup{&hook_done, rt.get(), &release_hook, &released_by_test, &r2_thread};

    b->release_hang();
    // Gate 3 sre finding (governance follow-up, 2026-09-16): must be scaled by
    // kSpinScale like the file's own spin_until-based precedent (r2_queue_wait_ok
    // a few tests up uses spin_until for ITS outer wait too, which scales
    // internally) - the gap hook's own inner spin_until above is bounded to
    // std::chrono::seconds(10) but THAT bound is scaled by kSpinScale (up to 6x
    // under TSan/ASan). An unscaled 30s outer bound could then be shorter than a
    // scaled-up inner wait still legitimately running, so unwinding here could
    // start while the drain-gap hook's worker thread is still alive and about to
    // write into r2_queued_before_dispatch above - a stack lifetime hazard, not
    // just a slow test. Scale this bound the same way so it always stays the
    // larger of the two. Gate 4 unhappy-path (governance follow-up, 2026-09-16,
    // UP-1) found a tried 2x-margin variant of this fix (outer bound 20s) HALVED
    // the plain-build (kSpinScale==1) margin-over-the-inner-10s-bound from 20s
    // to 10s versus the pre-170778b42 baseline of 30s - and this commit's OWN
    // message records the original
    // crash reproduced under plain CPU contention on Linux, not only under
    // TSan/ASan, so a thin plain-build margin is not a safe trade. Reverted to
    // the file's usual 3x margin (30s); the CI-entry-timeout-budget concern
    // this 2x variant was chasing (a Gate 8 sre finding) is real but only bites
    // in an already-red, all-three-hang build and is better closed structurally
    // (its own meson entry, matching the [tsan-heavy] split precedent) than by
    // trimming this margin - tracked, not fixed, in this pass.
    REQUIRE(entered_fut.wait_for(std::chrono::seconds(30) * yuzu::test::kSpinScale) ==
            std::future_status::ready);
    // External review finding (fjarvis's adversarial panel, Codex+Kimi convergent,
    // 2026-09-16): entered_fut succeeding does NOT by itself prove the drain-gap
    // hook has returned or that r2_queued_before_dispatch has been stored (entry_hook
    // can fire from r2_thread directly, independent of the hook's own thread - see
    // hook_done's own declaration comment above - so entered_fut can go ready WHILE
    // the hook is still inside its own spin_until, before it has written anything).
    // An earlier version of this comment claimed the read below was "safe" because
    // Cleanup's destructor waits on hook_done - true for UAF-safety (HP-1, still
    // correct), but irrelevant to THIS read: the destructor only runs AFTER this
    // REQUIRE, on the unwind path IF it throws - it protects safe teardown of a
    // spurious failure, it does not prevent one. Wait for hook_done HERE, on the
    // main thread, before reading the flag it guards - bare duration (spin_until
    // scales internally, matching every other call site in this file); no deadlock
    // risk since the hook's own wait is bounded and depends on nothing from this
    // thread.
    REQUIRE(yuzu::test::spin_until([&] { return hook_done.load(); }, std::chrono::seconds(30)));
    REQUIRE(r2_queued_before_dispatch.load());
    r2_thread.join();
    rt->set_drain_gap_hook_for_test({});
    // quality-engineer/unhappy-path finding (Gate 8 governance follow-up,
    // 2026-09-16): unlike Cleanup's noexcept destructor (which must never
    // assert), THIS is a safe, ordinary main-thread assertion point - after
    // r2_thread has joined and the hook is cleared, so no further firing can
    // be registered. A stale ALREADY-in-flight copy from the pre-existing,
    // parked HC-1b TOCTOU could theoretically still land after this line, but
    // that window is unchanged by this file's own fix and already tracked
    // separately - this CHECK closes the ordinary case: on every one of this
    // round's 25 empirical runs the count was 1, never higher.
    CHECK(gap_hook_fire_count.load(std::memory_order_relaxed) == 1);
    REQUIRE(res2.has_value());
    REQUIRE(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);

    // begin_stop() itself would drop a Queued claim outright, but r2 is already
    // Dispatching (retained in place by abandon_claim_locked above) - it survives
    // to reach dispatch_arm_off_lock()'s own submission attempt, which now observes
    // Stopped synchronously once the executor is stopping.
    rt->begin_stop();
    released_by_test = true;
    set_value_once(release_hook);
    // NOT is_terminal(): see the equivalent comment in the non-Stopped variant
    // above - wait for the value to move away from the stale Wedged result.
    REQUIRE(yuzu::test::spin_until(
        [&] {
            return rt->receipt_status(res2->receipt) != GuardianSparkRuntime::ReceiptStatus::Wedged;
        },
        std::chrono::seconds(10)));

    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Stopped);
}

TEST_CASE("rung 9c PR-5c (#4221): the Dispatching-window race on a REFILLED claim also "
          "reaches the compensation-reservation-exhaustion call site, not only submission",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                         std::chrono::milliseconds(50)});
    const auto key = spark_key(file_spec("/a"));

    std::expected<std::uint64_t, std::string> gen_r1;
    std::thread a_thread{[&] {
        gen_r1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    }};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->detach_rule("r1");
    a_thread.join();
    REQUIRE_FALSE(gen_r1.has_value());

    // r2 is queued and parked at its own dispatch entry - BEFORE it ever reaches
    // the reservation check - from inside the drain-gap hook, same as the other
    // two tests above.
    std::expected<GuardianSparkRuntime::ArmOutcome, GuardianSparkRuntime::ArmError> res2;
    std::thread r2_thread;
    std::promise<void> entered;
    std::promise<void> release_hook;
    bool released_by_test = false;
    auto entered_fut = entered.get_future();
    auto release_fut = release_hook.get_future().share(); // cpp-safety/chaos-injector
        // finding (governance follow-up, 2026-09-16, CH-3): get_future() throws
        // future_already_retrieved on any call after the first, REGARDLESS of
        // whether set_value() was ever called - retrieved once here, before any
        // hook registration, so the entry hook below can safely .wait() on the
        // shared_future even if it were ever invoked more than once. Today
        // prevented under this test's own sequencing (move-consumption at
        // dispatch_arm_off_lock's entry-hook read, under registry_mu_; no
        // other dispatch reaches this runtime instance between the drain-gap
        // hook's registration and r2's own consumption of it) - #4415 tracks
        // the open question of whether anything can violate that sequencing
        // (tracked as finding UP-5 in
        // governance.d/4417-spark-9c-pr5c-second-macos-followup.OatQnp.jsonl:
        // speculative, not confirmed as live, linked to #4415). This hoist is
        // defense-in-depth either way.
    std::atomic<bool> r2_queued_before_dispatch{false}; // set from the hook below (a
        // worker thread, not this one) - atomic per this file's own established
        // pattern for exactly this hook-thread-to-main-thread signal (see
        // r2_queue_wait_ok a few tests up); see the hook's own comment for why this
        // can't be a REQUIRE() there directly
    std::atomic<bool> hook_done{false}; // Gate 8 round 4 cpp-safety finding
        // (governance follow-up, 2026-09-16, HP-1): true ONLY as the hook's own
        // LAST statement below, once r2_queued_before_dispatch has already been
        // stored - unlike entered_fut (a DISPATCH-ENTRY signal that can fire from
        // r2_thread directly, independent of this hook, on the exact regression
        // this test exists to catch), this is a genuine HOOK-COMPLETION signal,
        // matching r2_queue_wait_ok's own precedent (its outer wait spins on its
        // own hook's LAST store, not on a different signal entirely). Declared
        // BEFORE Cleanup so it outlives Cleanup's destructor, which waits on it
        // FIRST, before touching r2_thread or anything else this frame owns.
    std::atomic<int> gap_hook_fire_count{0}; // cpp-safety/quality-engineer/
        // unhappy-path finding (governance follow-up, 2026-09-16, UP-1/QE-1):
        // was a bool gap_hook_ran - upgraded to a fire count so a repeat firing
        // is forensically visible in CI logs (see the hook body below) instead
        // of a silent no-op; a genuine (non-benign) repeat firing this file's
        // assertions cannot otherwise distinguish from #4415's still-unconfirmed
        // candidate mechanism (see the CI-finding comment above set_value_once)
        // now leaves a trace. Only the FIRST firing sets r2 up; every later one
        // is a no-op, not a re-spawn (re-running the body below would reassign
        // r2_thread while the first r2_thread may still be joinable -
        // std::terminate per [thread.thread.assign] - and double-register the
        // entry hook for no purpose, since r2 is already correctly parked by
        // the first firing). Reachable through the same pre-existing,
        // already-parked HC-1b TOCTOU as entered/release_hook/r2_thread - see
        // the CI-finding comment above set_value_once for the full account.
        // relaxed is sufficient (cpp-safety-confirmed, Gate 8 governance
        // follow-up, 2026-09-16): this guard's only job is exactly-one-winner
        // RMW mutual exclusion on ITS OWN modification order - it publishes no
        // other field through itself, so no stronger ordering is needed.
    std::atomic<int> entry_hook_fire_count{0}; // Gate 8 governance follow-up
        // (round 5, 2026-09-16) rewrite of the original external-review comment,
        // correcting two findings raised against it (quality-engineer,
        // consistency-auditor): `entered` IS the only promise this file's hooks
        // ever set from a worker thread (release_hook is always main-thread-
        // sequenced: set only in Cleanup's destructor and in this test's own
        // main-thread flow, never inside a hook lambda), but that does NOT make entry_hook
        // the more plausible duplicate-fire route - the opposite: production code
        // MOVES `dispatch_entry_hook_for_test_` out at first fire
        // (guardian_spark_runtime.cpp:557), so this hook is single-fire by
        // construction under normal operation, unlike `drain_gap_hook_for_test_`
        // (COPIED at :919, genuinely capable of firing again - why
        // gap_hook_fire_count needs its early-return guard and CHECK). A
        // CHECK==1 here would in fact be safely orderable too - entered_fut's
        // own wait_for()==ready already synchronizes-with the fetch_add below
        // (security-guardian/cpp-safety confirmed) - but is kept diagnostic-only:
        // a repeat firing here can only mean the same pre-existing, already-
        // tracked HC-1b TOCTOU (#4431) or an unspecified moved-from std::function edge
        // case, not a legitimate repeat path the way gap_hook_fire_count's is.
        // relaxed is sufficient (same reasoning as gap_hook_fire_count's own
        // note): this guard's only job is exactly-one-winner RMW mutual
        // exclusion on its own modification order - it publishes no other field
        // through itself.
    rt->set_drain_gap_hook_for_test([&] {
        // cpp-expert/security-guardian/unhappy-path finding (Gate 8 governance
        // follow-up, 2026-09-16): use fetch_add's OWN return value for the
        // printed count, not a separate .load() - under 3+ concurrent firings
        // a separate load could print a stale or duplicate count relative to
        // the caller's own fetch_add result.
        if (const int prior = gap_hook_fire_count.fetch_add(1, std::memory_order_relaxed);
            prior > 0) {
            std::fprintf(stderr,
                         "drain-gap hook fired again (fire #%d) after the first "
                         "firing already parked r2 - no-op (see "
                         "gap_hook_fire_count's own declaration comment). Plain "
                         "fprintf(stderr), not a Catch2 assertion, so safe from "
                         "this (non-main) thread.\n",
                         prior + 1);
            return;
        }
        // See entry_hook_fire_count's own declaration comment above for why
        // this hook is single-fire by construction (unlike the gap hook above)
        // and why no early-return guard is needed here: set_value_once already
        // makes a repeat set_value() safe, and a shared_future tolerates repeat
        // .wait() calls.
        rt->set_dispatch_entry_hook_for_test([&] {
            if (const int prior = entry_hook_fire_count.fetch_add(1, std::memory_order_relaxed);
                prior > 0) {
                std::fprintf(stderr,
                             "dispatch-entry hook fired again (fire #%d) - entered "
                             "was already set; set_value_once absorbs it safely, "
                             "but this is worth investigating (see "
                             "entry_hook_fire_count's own declaration comment).\n",
                             prior + 1);
            }
            set_value_once(entered);
            release_fut.wait();
        });
        r2_thread = std::thread{[&] {
            res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                   file_exists_rule("r2"), true);
        }};
        // CI finding (macOS crash, 2026-09-16): Catch2's assertion machinery is NOT
        // thread-safe from any thread but the one running the test case - this hook
        // runs on a detached io_executor_ worker (fired from inside
        // on_arm_complete()'s own drain), not the main test thread. A REQUIRE here
        // raced Catch2's internal OutputRedirect state under TSan (confirmed) and,
        // on a genuine failure, throws Catch::TestFailureException with no handler
        // on this thread - std::terminate (reproduced identically under artificial
        // CPU contention on Linux: "terminate called after throwing an instance of
        // 'Catch::TestFailureException'" at this exact line). Capture the result
        // instead; the real REQUIRE runs after entered_fut proves this hook has
        // already returned - see below.
        r2_queued_before_dispatch.store(
            yuzu::test::spin_until([&] { return rt->backend_op_queued() == 1; },
                                   std::chrono::seconds(10)));
        hook_done.store(true); // MUST be the hook's last statement - see hook_done's
                               // own declaration comment above.
    });
    struct Cleanup {
        std::atomic<bool>* hook_done;
        GuardianSparkRuntime* rt; // non-owning, same convention as the other raw-pointer
                                 // fields below; rt is declared far earlier in this
                                 // TEST_CASE so it outlives cleanup (LIFO destruction)
        std::promise<void>* release_hook;
        bool* released;
        std::thread* r2t;
        ~Cleanup() {
            // Gate 8 round 4 cpp-safety finding (governance follow-up, 2026-09-16,
            // HP-1): wait for the drain-gap hook's own worker thread to genuinely
            // finish BEFORE touching anything else this frame owns - on the exact
            // regression this test exists to catch, entered_fut (below) can go
            // ready, and REQUIRE(r2_queued_before_dispatch.load()) can throw and
            // start unwinding THIS destructor, while that worker thread is still
            // alive: without this wait, r2_queued_before_dispatch's storage (and
            // this test's own [&] hook, still registered on rt) would be destroyed
            // while that thread is still about to write into them - a genuine
            // use-after-free, not a residual/theoretical race. Bounded (matches the
            // outer wait's own margin), so a genuinely wedged hook still fails
            // loudly rather than hanging teardown. Ordering matters: this MUST run
            // before the joinable()/join() below, because the hook is what ASSIGNS
            // r2t (see r2_thread's own assignment above) - reading joinable() first
            // would itself race that assignment.
            // Never REQUIRE/CHECK/throw here: ~Cleanup() has no exception
            // specification, so per [class.dtor] it is implicitly noexcept(true)
            // regardless of unwind state - ANY throw here terminates unconditionally,
            // not merely "if already unwinding" (cpp-expert finding, governance
            // follow-up, 2026-09-16, Gate 8 round 5). Exactly the crash class this
            // whole file's governance history exists to avoid either way. A timeout
            // is loud (stderr), never silent, but never fatal from here.
            // quality-engineer finding (governance follow-up, 2026-09-16, Gate 8
            // round 5): spin_until() ALREADY multiplies its own timeout by
            // kSpinScale internally (test_helpers.hpp) - passing a pre-scaled
            // duration here double-scales to kSpinScale^2 (1080s under TSan/ASan,
            // not the intended 180s). Pass the bare, unscaled duration, matching
            // every other spin_until call site in this file.
            if (!yuzu::test::spin_until([&] { return hook_done->load(); },
                                        std::chrono::seconds(30))) {
                std::fprintf(stderr,
                             "Cleanup::~Cleanup(): hook_done wait timed out - the "
                             "drain-gap hook's worker thread did not finish within "
                             "its bound; proceeding anyway (see hook_done's own "
                             "declaration comment)\n");
            }
            // cpp-safety finding (governance follow-up, 2026-09-16, Gate 8 round 5,
            // HC-1): clear BOTH test hooks (each captures this frame's locals by
            // reference) BEFORE releasing/joining anything else - hook_done above
            // only proves the drain-gap hook's OWN first firing has finished; it says
            // nothing about whether on_arm_complete could invoke it AGAIN (e.g. for
            // r2's own eventual completion) while this frame is being torn down.
            // set_*_hook_for_test({}) takes the runtime's registry_mu_, the same lock
            // on_arm_complete copies the hook under, so this closes the window for
            // any not-yet-in-flight second firing. (A firing that already copied the
            // hook before this clear lands is a narrower, separate TOCTOU - tracked,
            // not fixed, in this pass.)
            rt->set_drain_gap_hook_for_test({});
            rt->set_dispatch_entry_hook_for_test({});
            if (!*released)
                set_value_once(*release_hook);
            if (r2t->joinable())
                r2t->join();
        }
    } cleanup{&hook_done, rt.get(), &release_hook, &released_by_test, &r2_thread};

    b->release_hang(); // r1's late arm is compensated, popped (releasing its OWN
                       // reservation as part of that same completion), and r2 is
                       // refilled -> parked in our hook, before its own reservation
                       // attempt.
    // Gate 3 sre finding (governance follow-up, 2026-09-16): must be scaled by
    // kSpinScale like the file's own spin_until-based precedent (r2_queue_wait_ok
    // a few tests up uses spin_until for ITS outer wait too, which scales
    // internally) - the gap hook's own inner spin_until above is bounded to
    // std::chrono::seconds(10) but THAT bound is scaled by kSpinScale (up to 6x
    // under TSan/ASan). An unscaled 30s outer bound could then be shorter than a
    // scaled-up inner wait still legitimately running, so unwinding here could
    // start while the drain-gap hook's worker thread is still alive and about to
    // write into r2_queued_before_dispatch above - a stack lifetime hazard, not
    // just a slow test. Scale this bound the same way so it always stays the
    // larger of the two. Gate 4 unhappy-path (governance follow-up, 2026-09-16,
    // UP-1) found a tried 2x-margin variant of this fix (outer bound 20s) HALVED
    // the plain-build (kSpinScale==1) margin-over-the-inner-10s-bound from 20s
    // to 10s versus the pre-170778b42 baseline of 30s - and this commit's OWN
    // message records the original
    // crash reproduced under plain CPU contention on Linux, not only under
    // TSan/ASan, so a thin plain-build margin is not a safe trade. Reverted to
    // the file's usual 3x margin (30s); the CI-entry-timeout-budget concern
    // this 2x variant was chasing (a Gate 8 sre finding) is real but only bites
    // in an already-red, all-three-hang build and is better closed structurally
    // (its own meson entry, matching the [tsan-heavy] split precedent) than by
    // trimming this margin - tracked, not fixed, in this pass.
    REQUIRE(entered_fut.wait_for(std::chrono::seconds(30) * yuzu::test::kSpinScale) ==
            std::future_status::ready);
    // External review finding (fjarvis's adversarial panel, Codex+Kimi convergent,
    // 2026-09-16): entered_fut succeeding does NOT by itself prove the drain-gap
    // hook has returned or that r2_queued_before_dispatch has been stored (entry_hook
    // can fire from r2_thread directly, independent of the hook's own thread - see
    // hook_done's own declaration comment above - so entered_fut can go ready WHILE
    // the hook is still inside its own spin_until, before it has written anything).
    // An earlier version of this comment claimed the read below was "safe" because
    // Cleanup's destructor waits on hook_done - true for UAF-safety (HP-1, still
    // correct), but irrelevant to THIS read: the destructor only runs AFTER this
    // REQUIRE, on the unwind path IF it throws - it protects safe teardown of a
    // spurious failure, it does not prevent one. Wait for hook_done HERE, on the
    // main thread, before reading the flag it guards - bare duration (spin_until
    // scales internally, matching every other call site in this file); no deadlock
    // risk since the hook's own wait is bounded and depends on nothing from this
    // thread.
    REQUIRE(yuzu::test::spin_until([&] { return hook_done.load(); }, std::chrono::seconds(30)));
    REQUIRE(r2_queued_before_dispatch.load());
    r2_thread.join();
    rt->set_drain_gap_hook_for_test({});
    // quality-engineer/unhappy-path finding (Gate 8 governance follow-up,
    // 2026-09-16): unlike Cleanup's noexcept destructor (which must never
    // assert), THIS is a safe, ordinary main-thread assertion point - after
    // r2_thread has joined and the hook is cleared, so no further firing can
    // be registered. A stale ALREADY-in-flight copy from the pre-existing,
    // parked HC-1b TOCTOU could theoretically still land after this line, but
    // that window is unchanged by this file's own fix and already tracked
    // separately - this CHECK closes the ordinary case: on every one of this
    // round's 25 empirical runs the count was 1, never higher.
    CHECK(gap_hook_fire_count.load(std::memory_order_relaxed) == 1);
    REQUIRE(res2.has_value());

    // NOW saturate File-class reservation capacity (4) with 4 parked arms on
    // distinct keys - r1's own reservation is already released (its whole
    // compensation completed before the refill above ever ran), so full capacity
    // is genuinely free here, and r2 is safely parked in our hook, unable to reach
    // its own reservation attempt until we release it below.
    b->arm_park.park_every = 1;
    constexpr int kFillerCount = 4;
    const int base_entries = b->arm_entries.load();
    std::vector<std::thread> fillers;
    std::vector<std::expected<std::uint64_t, std::string>> filler_results(
        static_cast<std::size_t>(kFillerCount));
    for (int i = 0; i < kFillerCount; ++i) {
        fillers.emplace_back([&, i] {
            const auto rid = "f" + std::to_string(i);
            filler_results[static_cast<std::size_t>(i)] = rt->attach_rule(
                rid, file_spec("/f" + std::to_string(i)), file_exists_rule(rid), true);
        });
    }
    // Constructed BEFORE the REQUIRE below can throw: a std::thread destructor
    // running while still joinable() is std::terminate(), not an exception - this
    // guard must survive a failed spin_until, not just the success path.
    struct FillerCleanup {
        BlockingGate* gate;
        std::vector<std::thread>* t;
        ~FillerCleanup() {
            gate->pulse();
            for (auto& th : *t)
                if (th.joinable())
                    th.join();
        }
    } filler_cleanup{&b->arm_park, &fillers};
    REQUIRE(yuzu::test::spin_until(
        [&] { return b->arm_entries.load() == base_entries + kFillerCount; },
        std::chrono::seconds(10)));
    // TSan finding (2026-09-16): arm_entries is bumped at arm() ENTRY, before
    // maybe_park() takes arm_park.mu (see arm()/maybe_park() above), so a filler
    // thread can still be racing toward that lock the instant spin_until above
    // is satisfied. An unguarded write here can interleave with maybe_park()'s
    // guarded read of park_every. Take the same lock to make this write visible
    // with the same mutex maybe_park() reads park_every under.
    {
        std::lock_guard<std::mutex> lk(b->arm_park.mu);
        b->arm_park.park_every = 0; // stop parking future arrivals - r2 must reach
                                   // the reservation check itself, not get parked
                                   // in arm()
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);

    released_by_test = true;
    set_value_once(release_hook); // r2 proceeds into a now-exhausted reservation pool
    // NOT is_terminal(): see the equivalent comment in the submission-failure
    // variant above - wait for the value to move away from the stale Wedged result.
    REQUIRE(yuzu::test::spin_until(
        [&] {
            return rt->receipt_status(res2->receipt) != GuardianSparkRuntime::ReceiptStatus::Wedged;
        },
        std::chrono::seconds(10)));

    CHECK(rt->compensation_reservation_refused() >= 1);
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Failed);
}

// ── rung 9c PR-5c (#4221 up-2): immediate refusal of a genuinely new claimant onto
// a Wedged key, paired with same-rule_id/same-spec re-observation ─────────────────

TEST_CASE("rung 9c PR-5c (#4221 up-2), coupling proof: an identical (rule_id, spec) "
          "retry onto a Wedged key re-observes the existing head instead of being "
          "refused - the actual coupling immediate-refusal-alone would break "
          "(manually confirmed empirically: reverting to unconditional refusal makes "
          "this test's res2/wedged_reobservations assertions fail). Also the PR-5d "
          "adversarial-review Blocker-1 regression guard: detach_all() (a routine "
          "full-sync retry's own teardown) must not permanently strand this rule's "
          "adoption candidacy when the very next reconciliation re-observes it as "
          "STILL desired - only a genuinely OMITTED rule stays deactivated.",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res1.has_value());
    REQUIRE(res1->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Simulate a routine full-sync retry's own teardown pass: a Wedged head is
    // waiter_abandoned, so detach_all()'s claimed-rule sweep (which explicitly
    // excludes waiter_abandoned claims) does not touch it - Fable's confirmed
    // no-op, from the PLAN doc's "Correction to the kickoff".
    rt->detach_all();
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1);

    // The identical retry: SAME rule_id, SAME spec.
    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(res2.has_value());
    CHECK(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    // Same underlying claim object - re-observation constructs nothing new.
    CHECK(res2->receipt.claim == res1->receipt.claim);
    CHECK(rt->wedged_reobservations() == 1);
    CHECK(rt->wedged_refusals() == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1); // unchanged
    CHECK(b->arm_entries.load() == 1); // never a second backend arm

    b->release_hang();
    // Adversarial-review Blocker-1 fix: the detach_all() above deactivated this
    // claim's adoption candidacy (correct for a rule the new push OMITS), but the
    // identical retry immediately above proved rule_id/spec are STILL desired -
    // the hoisted Reobserved branch now restores candidacy for exactly that case,
    // so the late success is ADOPTED, not disarmed (this is the behavior change
    // from the pre-fix version of this test, which asserted disarms==1/
    // rule_count==0 here - that was pinning the bug, not a correct baseline).
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0);
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // A different rule_id sharing the same spec (same key) still arms normally as
    // an ordinary live sibling of the now-adopted r1 - proves the reactivated
    // subscription is a real, healthy PerKey entry, not a stale/ghost one. "N
    // consumers, 1 watcher": the sibling reuses r1's already-live subscription,
    // no second backend arm() call.
    const auto res3 = rt->attach_rule("r-fresh", file_spec("/a"), file_exists_rule("r-fresh"), true);
    REQUIRE(res3.has_value());
    CHECK(rt->rule_count() == 2);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arm_entries.load() == 1);
}

TEST_CASE("#4508: full-sync withdrawal, re-observation and a real withdrawal",
          "[spark][runtime][liveness][wedge-candidates]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{
                               .backend_op_deadline = std::chrono::milliseconds(50)});
    const auto key = spark_key(file_spec("/a"));
    auto gate = b->park_next_arm_for_key(key);
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_all_key_gates(); }
    } cleanup{b.get()};
    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(res1.has_value());
    REQUIRE(gate->wait_entered(std::chrono::seconds(10)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    REQUIRE(rt->expire_overdue_claims() == 1);
    REQUIRE(rt->receipt_wedge_candidate_for_test(res1->receipt));

    rt->detach_all();
    CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
    CHECK_FALSE(rt->receipt_wedge_candidate_for_test(res1->receipt));
    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(res2.has_value());
    CHECK(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(res2->receipt.claim == res1->receipt.claim);
    CHECK(rt->receipt_wedge_candidate_for_test(res1->receipt));
    CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
    rt->detach_rule("r1");
    CHECK_FALSE(rt->receipt_wedge_candidate_for_test(res1->receipt));
    CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
    gate->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key) == 0;
    }, std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
}

TEST_CASE("Governance Gate 7 fix (rung 9c PR-5d follow-up round 2): a clean "
          "withdraw-then-redeploy-to-a-different-key sequence stays safe against a "
          "stale key-A late success - the rg->active check alone excludes adoption "
          "here (r1 was WITHDRAWN, not redeployed while still wedged); see the next "
          "test for the genuinely reachable rules_.contains guard branch",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const auto key_a = spark_key(file_spec("/a"));

    // Wedge r1 on key A.
    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res1.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Withdrawal must deactivate every candidate for r1 across keys.
    rt->detach_rule("r1");

    // Key B's arm resolves immediately (no hang) - only the stale key-A claim is
    // still outstanding.
    auto res2 = rt->attach_rule("r1", file_spec("/b"), file_exists_rule("r1"), true);
    REQUIRE(res2.has_value());
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1); // key B, live

    // The stale key-A backend arm() finally completes. r1 was WITHDRAWN before
    // the redeploy, so rg->active already reads false for the key-A claim -
    // adoption is refused by the pre-existing `claim->rg->active` check alone,
    // never reaching the new `rules_.contains` guard at all.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() >= 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    const auto res3 = rt->attach_rule("r-fresh", file_spec("/b"), file_exists_rule("r-fresh"), true);
    REQUIRE(res3.has_value());
    CHECK(rt->rule_count() == 2); // r1 (key B) + r-fresh, sharing key B's watcher
}

TEST_CASE("Governance Gate 8 finding (rung 9c PR-5d /governance run): an ordinary "
          "flip-flop redeploy - wedge on key A, redeploy to key B, redeploy BACK to "
          "key A while the original key-A arm is still in flight - reaches the "
          "rules_.contains defense-in-depth guard's true branch with NO fault "
          "injection. Corrects the prior (false) claim that this branch is "
          "unreachable via the public API: is_retained_wedge() never consults "
          "rg->active, so a Reobserved-restore on the return-to-A redeploy "
          "legitimately reactivates rg->active for the still-outstanding key-A "
          "claim even though rules_[\"r1\"] correctly stays live on key B "
          "throughout - proving the guard's own refuse-and-disarm path, not just "
          "its absence, under ordinary desired-state churn",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    CHECK(rt->wedge_adopt_stale_refused() == 0);

    // r1 wedges on key A - the original arm() call hangs indefinitely (FakeBackend
    // never resolves it until release_hang() below).
    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res1.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Redeploy r1 to key B - a different spec, so this is an ordinary detach(A)-
    // then-attach(B), NOT a reobservation. Resolves immediately (no hang on this
    // arm), committing rules_["r1"] live on key B.
    auto res2 = rt->attach_rule("r1", file_spec("/b"), file_exists_rule("r1"), true);
    REQUIRE(res2.has_value());
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1); // key B, live

    // Redeploy r1 BACK to key A - identical (rule_id, spec) to the STILL-wedged
    // key-A claim from step 1 (its backend arm() call has never returned).
    // is_retained_wedge() checks only kind/dispatch/waiter_abandoned/end - none of
    // which detach_rule_locked's earlier deactivation touched - so this matches
    // the Reobserved-restore branch and legitimately reactivates that claim's
    // rg->active, even though rules_["r1"] is correctly still live on key B.
    auto res3 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(res3.has_value());
    CHECK(res3->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(res3->receipt.claim == res1->receipt.claim); // same claim object as step 1
    CHECK(rt->wedged_reobservations() >= 1);

    // The ORIGINAL key-A arm() finally completes. rg->active now reads true
    // (restored by step 3) AND rules_["r1"] already holds key B's live
    // generation - exactly the guard's true branch, reached with zero fault
    // injection. It must refuse adoption and disarm the stale key-A success,
    // never touching the live key-B generation.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() >= 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->wedge_adopt_stale_refused() == 1);
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);

    // Key B's generation is genuinely untouched, not merely uncounted: a fresh
    // sibling on key B still reuses its one shared watcher, exactly as it would
    // if the flip-flop above had never happened.
    const auto res4 = rt->attach_rule("r-fresh", file_spec("/b"), file_exists_rule("r-fresh"), true);
    REQUIRE(res4.has_value());
    CHECK(rt->rule_count() == 2);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("#4508: re-observation supersedes a different wedged key before withdrawal",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const auto key_a = spark_key(file_spec("/a"));
    const auto key_b = spark_key(file_spec("/b"));

    // Wedge r1 on key A - its own backend arm() call hangs until release_hang()
    // below, shared across every hang in this test (single-gate FakeBackend, one
    // release wakes every still-parked call at once - exactly what this test
    // wants, since all three claims must resolve together at the very end).
    auto res_a = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                 file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res_a.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res_a->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->claim_queue_depth_for_test(key_a) == 1);

    // Redeploy to B: A loses candidacy but remains parked in its FIFO.
    b->hang_next_arm.store(true);
    auto res_b = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/b"),
                                 file_exists_rule("r1"), true);
    REQUIRE(res_b.has_value());
    CHECK(rt->rule_count() == 0); // never committed - still just a claim, on either key
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1); // wedges key B's claim too
    CHECK(rt->receipt_status(res_b->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->claim_queue_depth_for_test(key_b) == 1);

    // Re-observe A before B resolves; A becomes the freshest desired candidate.
    auto res_again_a = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                       file_exists_rule("r1"), true);
    REQUIRE(res_again_a.has_value());
    CHECK(res_again_a->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(res_again_a->receipt.claim == res_a->receipt.claim); // re-observes the SAME key-A claim
    CHECK(rt->wedged_reobservations() >= 1);

    // Withdrawal must deactivate every candidate for r1 across keys.
    rt->detach_rule("r1");

    // Release every parked backend call at once - both claim A's and claim B's
    // arm() calls resolve to a late SUCCESS (FakeBackend's default outcome).
    // r1 was withdrawn a moment ago: NEITHER should be adopted.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() >= 2; },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->receipt_status(res_a->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->receipt_status(res_b->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // The runtime stays healthy afterward - a fresh attach on either key arms
    // normally, proving neither key's index/subscription state was left corrupt
    // by the orphaned-then-disarmed claim.
    const auto res_fresh = rt->attach_rule("r-fresh", file_spec("/b"), file_exists_rule("r-fresh"),
                                           true);
    REQUIRE(res_fresh.has_value());
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("#4508: a later timeout yields to the re-observed candidate",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const auto key_a = spark_key(file_spec("/a"));
    const auto key_b = spark_key(file_spec("/b"));

    // Wedge r1 on key A - its own backend arm() call hangs until release_hang()
    // below, shared across every hang in this test (single-gate FakeBackend, one
    // release wakes every still-parked call at once).
    auto res_a = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                 file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res_a.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res_a->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Redeploy to B: A loses candidacy but remains parked in its FIFO.
    b->hang_next_arm.store(true);
    auto res_b = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/b"),
                                 file_exists_rule("r1"), true);
    REQUIRE(res_b.has_value());
    CHECK(rt->rule_count() == 0); // never committed - still just a claim, on either key

    // Re-observe A before B resolves; A becomes the freshest desired candidate.
    auto res_again_a = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                       file_exists_rule("r1"), true);
    REQUIRE(res_again_a.has_value());
    CHECK(res_again_a->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(res_again_a->receipt.claim == res_a->receipt.claim); // re-observes the SAME key-A claim
    CHECK(rt->wedged_reobservations() >= 1);

    // B times out after A was re-observed, so abandonment must yield to A.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1); // wedges key B's claim
    CHECK(rt->receipt_status(res_b->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Withdrawal must deactivate every candidate for r1 across keys.
    rt->detach_rule("r1");

    // Release every parked backend call at once - both claim A's and claim B's arm()
    // calls resolve to a late SUCCESS (FakeBackend's default outcome). r1 was
    // withdrawn a moment ago: NEITHER should be adopted. Pre-fix, claim A's
    // rg->active read true (never deactivated) and on_arm_complete wrongly adopted
    // it - only claim B disarmed, rule_count()/armed_key_count() wrongly read 1 (this
    // is the exact RED evidence this fix was empirically verified against:
    // disarms==1, rule_count()==1, armed_key_count()==1, instead of 2/0/0).
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() >= 2; },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->receipt_status(res_a->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->receipt_status(res_b->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // The runtime stays healthy afterward - a fresh attach on either key arms
    // normally, proving neither key's index/subscription state was left corrupt by
    // the orphaned-then-disarmed claim.
    const auto res_fresh = rt->attach_rule("r-fresh", file_spec("/a"), file_exists_rule("r-fresh"),
                                           true);
    REQUIRE(res_fresh.has_value());
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("This rung 9c PR-5d /governance run's own Gate 4 unhappy-path pass (fix "
          "shape independently confirmed by cpp-safety): detach_rule_locked's Case "
          "0 `return nullptr;`s from INSIDE its own loop the instant it matches a "
          "live, un-abandoned claim for rule_id - skipping every line after it in "
          "the function, including the wedge-lookup that used to sit below it. A "
          "flip-flop-back-and-withdraw sequence leaves a DIFFERENT, still-wedged "
          "claim on a stale key silently orphaned: Case 0 finds and withdraws the "
          "NEW key's still-Dispatching claim and returns before the OLD key's "
          "wedged claim's own rg->active is ever touched",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};
    const auto key_a = spark_key(file_spec("/a"));
    const auto key_b = spark_key(file_spec("/b"));

    // Wedge r1 on key A - its own backend arm() call hangs until release_hang()
    // below, shared across every hang in this test (single-gate FakeBackend, one
    // release wakes every still-parked call at once).
    auto res_a = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                 file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res_a.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res_a->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->claim_queue_depth_for_test(key_a) == 1);

    // Sweep wedge candidates before Case 0 can withdraw a different pending claim.
    b->hang_next_arm.store(true);
    auto res_b = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/b"),
                                 file_exists_rule("r1"), true);
    REQUIRE(res_b.has_value());
    CHECK(rt->rule_count() == 0); // never committed - still just a claim, on either key
    CHECK(rt->claim_queue_depth_for_test(key_b) == 1);
    CHECK(rt->claim_queue_depth_for_test(key_a) == 1); // claim A still parked, untouched

    // Re-observe A before B resolves; A becomes the freshest desired candidate.
    auto res_again_a = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                       file_exists_rule("r1"), true);
    REQUIRE(res_again_a.has_value());
    CHECK(res_again_a->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(res_again_a->receipt.claim == res_a->receipt.claim); // re-observes the SAME key-A claim
    CHECK(rt->wedged_reobservations() >= 1);

    // Sweep wedge candidates before Case 0 can withdraw a different pending claim.
    rt->detach_rule("r1");

    // Claim B was withdrawn while still Dispatching - Case 0's own branch, never
    // expire_overdue_claims()'d, so its outcome is "withdrawn"/ClaimEnd::Withdrawn,
    // not the wedge branch's sticky-Wedged receipt (matching the shape Case 0
    // itself produces - see that block's own comment - not
    // ClaimEnd::WaiterTimedOutDispatched/ReceiptStatus::Wedged). It stays queued as
    // the key's own marker (Case 0 only erases a Queued, not yet dispatched, claim
    // outright) until its own arm() call resolves, below.
    CHECK(rt->receipt_status(res_b->receipt) == GuardianSparkRuntime::ReceiptStatus::Withdrawn);
    CHECK(rt->claim_queue_depth_for_test(key_b) == 1);
    // Claim A's own receipt is untouched by this withdrawal - the sticky-Wedged
    // receipt from its ORIGINAL timeout, above, stays exactly what it already was;
    // what the fix corrects (rg->active) is not observable via receipt_status().
    CHECK(rt->receipt_status(res_a->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // Release every parked backend call at once - both claim A's and claim B's
    // arm() calls resolve to a late SUCCESS (FakeBackend's default outcome), NOT a
    // timeout for claim B this time. r1 was withdrawn a moment ago: NEITHER should
    // be adopted. Pre-fix, claim A's rg->active read true (never deactivated) and
    // on_arm_complete wrongly adopted it - only claim B's late success disarmed,
    // rule_count()/armed_key_count() wrongly read 1 instead of 2 disarms / 0 / 0.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() >= 2; },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->receipt_status(res_a->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->receipt_status(res_b->receipt) == GuardianSparkRuntime::ReceiptStatus::Withdrawn);

    // The runtime stays healthy afterward - a fresh attach on either key arms
    // normally, proving neither key's index/subscription state was left corrupt by
    // the orphaned-then-disarmed claim.
    const auto res_fresh = rt->attach_rule("r-fresh", file_spec("/a"), file_exists_rule("r-fresh"),
                                           true);
    REQUIRE(res_fresh.has_value());
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
}

TEST_CASE("rung 9c PR-5c (#4221 up-2): a genuinely new claimant (different rule_id) "
          "onto a Wedged key is refused immediately, synchronously, with no new "
          "claim ever queued",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res1.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                file_exists_rule("r2"), true);
    REQUIRE_FALSE(res2.has_value());
    CHECK(res2.error().message == "spark key wedged");
    // rung 9c PR-5c round 2 (#4221): this refusal fires at the hoisted pre-check,
    // before any detach_rule_locked("r2") could run - prior_state_preserved is
    // true, matching every hoisted-check refusal regardless of whether "r2" had
    // any prior state to begin with (it didn't, here).
    CHECK(res2.error().prior_state_preserved);
    CHECK(rt->wedged_refusals() == 1);
    CHECK(rt->wedged_reobservations() == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1); // no new claim queued
    CHECK(rt->rule_count() == 0);

    // rung 9c PR-5d: "r1" itself was never withdrawn - r2's refusal touches
    // nothing about it (the hoisted pre-check returns before detach_rule_locked
    // even runs) - so r1's own late success is adopted, not disarmed.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0);
}

TEST_CASE("rung 9c PR-5c (#4221 up-2): a refused new claimant does not disturb an "
          "UNRELATED live follower already queued behind the Wedged head - a "
          "same-rule_id follower would confound this via attach_core's own Case 0 "
          "detach_rule_locked, so this uses a genuinely third, unrelated rule_id",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res1.has_value());

    // Let r1's own deadline elapse well past overdue BEFORE r2 ever attaches, so
    // r2's own FRESH (not-yet-elapsed) deadline survives the single
    // expire_overdue_claims() sweep below - isolating r1 as the only claim
    // actually overdue at that point (expire_overdue_claims() scans every live
    // claim in every key's fifo, not just heads, so attaching r2 first would make
    // both overdue simultaneously and defeat this test's own setup).
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // r2 attaches HERE, while r1 is still merely Dispatching (nothing has
    // abandoned it yet - waiter_abandoned is still false) - it queues behind r1
    // the ordinary way, unaffected by up-2 (which only refuses an arrival reaching
    // an ALREADY-wedged head).
    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r2", file_spec("/a"),
                                file_exists_rule("r2"), true);
    REQUIRE(res2.has_value());
    CHECK(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 2);

    CHECK(rt->expire_overdue_claims() == 1); // r1 alone; r2's own deadline was just set
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);

    // r3: a genuinely new, UNRELATED claimant - its own rule_id, distinct from r2.
    auto res3 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r3", file_spec("/a"),
                                file_exists_rule("r3"), true);
    REQUIRE_FALSE(res3.has_value());
    CHECK(res3.error().message == "spark key wedged");
    CHECK(res3.error().prior_state_preserved); // hoisted pre-check, rung 9c PR-5c round 2
    CHECK(rt->wedged_refusals() == 1);

    // r2, the live follower, is exactly as it was - unaffected by r3's refusal.
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 2); // r1 + r2 only

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(res2->receipt); },
                                   std::chrono::seconds(10)));
    // r2 adopts r1's late success the ordinary "N consumers, 1 watcher" way - it
    // was never abandoned, so publish_arm_verdicts_locked's own `live` set still
    // includes it.
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Committed);
    CHECK(rt->rule_count() == 1);
    // Adversarial-review should-fix (rung 9c PR-5d follow-up): explicit proof r1
    // itself, NOT just "rule_count()==1", is the one NOT adopted here - the
    // `live.empty()` guard (not structural uniqueness, see the corrected comment
    // at on_arm_complete's adoption branch) is what excludes it while r2 is a
    // live follower. r1's own rule stays unenforced until the next Reapply
    // re-attaches it fresh; its receipt stays exactly what it already was.
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);
}

TEST_CASE("rung 9c PR-5c (#4221 up-2), crash-regression: the BLOCKING attach_rule() "
          "wrapper's Reobserved case returns the wedged head's own outcome "
          "immediately - a missing case here falls through to "
          "wait_for_claim(key, nullptr, ...), a null-pointer dereference, not merely "
          "a misclassification",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(500)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res1.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // The BLOCKING wrapper, same rule_id/spec - must hit Reobserved and return the
    // existing outcome immediately, well under backend_op_deadline (500ms), never
    // call wait_for_claim on a null arm_claim. A generous margin (300ms out of a
    // 500ms deadline) avoids CI timing flakiness while still conclusively proving
    // no full-deadline wait occurred.
    const auto started = std::chrono::steady_clock::now();
    auto gen2 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    REQUIRE_FALSE(gen2);
    CHECK(gen2.error() == "arm timed out");
    CHECK(elapsed < std::chrono::milliseconds(300));
    CHECK(rt->wedged_reobservations() == 1);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1);

    // rung 9c PR-5d: nobody withdrew "r1" - the late success is adopted.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0);
}

TEST_CASE("rung 9c PR-5c (#4221 up-2): repeated identical retries onto a Wedged key "
          "re-observe every time - the queue never grows and no new timeout is ever "
          "independently counted",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);

    for (int i = 1; i <= 5; ++i) {
        auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        REQUIRE_FALSE(gen);
        CHECK(gen.error() == "arm timed out");
        CHECK(rt->wedged_reobservations() == static_cast<std::uint64_t>(i));
        CHECK(rt->backend_op_timeouts() == 1); // never a second, independent timeout
        CHECK(rt->backend_op_queued() == 0);   // never a second claim
        CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1);
        CHECK(b->arm_entries.load() == 1);     // never a second backend arm
    }

    // rung 9c PR-5d: "r1" was never withdrawn across any of the 5 retries - its
    // late success is adopted, not disarmed.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);

    // Adversarial-review finding (2026-09-15): same ghost-mapping regression test as
    // the coupling-proof case above - repeated re-observation must leave nothing
    // behind that blocks a genuinely fresh arm on the same key afterward. Under
    // PR-5d "r1" is now adopted and already owns this key's watcher, so a
    // DIFFERENT rule_id on the SAME key joins it rather than minting a second arm.
    const auto res_fresh = rt->attach_rule("r-fresh", file_spec("/a"), file_exists_rule("r-fresh"), true);
    REQUIRE(res_fresh.has_value());
    CHECK(rt->rule_count() == 2);
    CHECK(b->arm_entries.load() == 1); // r1's original arm only - r-fresh joined it
}

TEST_CASE("rung 9c PR-5c (#4221 up-2): a changed spec on the SAME rule_id targets a "
          "DIFFERENT key entirely - ordinary replacement, never a wedge interaction",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // SAME rule_id "r1", a DIFFERENT spec ("/b", not "/a") - spark_key() encodes
    // the spec canonically, so this targets a completely different key, never
    // reaching the wedge check at all.
    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/b"),
                                file_exists_rule("r1"), true);
    REQUIRE(res2.has_value());
    CHECK(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted); // off-lock dispatch, ordinary
    CHECK(rt->wedged_reobservations() == 0);
    CHECK(rt->wedged_refusals() == 0);
    // The old key's wedged head is untouched: detach_rule_locked("r1") (Case 0,
    // run before the wedge check) explicitly excludes waiter_abandoned claims, so
    // it can never see or disturb it.
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(res2->receipt); },
                                   std::chrono::seconds(10)));
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Committed);
    CHECK(rt->rule_count() == 1);

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 1); // r1 on "/b" still armed; only the "/a" episode disarmed
}

TEST_CASE("rung 9c PR-5c (#4221 up-2): begin_stop() wins over re-observation - a "
          "same-rule_id retry onto a Wedged key during shutdown fails with "
          "\"stopping\", never touching either wedge counter",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    rt->begin_stop();

    auto gen2 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen2);
    // attach_core()'s stopping_ check runs FIRST, before the wedge check even
    // looks at the FIFO head - stopping always wins.
    CHECK(gen2.error() == "stopping");
    CHECK(rt->wedged_reobservations() == 0);
    CHECK(rt->wedged_refusals() == 0);

    b->release_hang();
}

TEST_CASE("rung 9c PR-5c (#4221 up-2): re-observation still works when the "
          "abandonment's own index release failed via the fault seam (index_held "
          "stuck true) - that seam must never corrupt the wedge classification",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto res1 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                file_exists_rule("r1"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    // Consumed once by the next release_claim_index_locked - abandon_claim_locked's
    // own unconditional call, inside expire_overdue_claims() below.
    rt->set_index_remove_fault_for_test(true);
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->claim_index_release_failures() == 1); // the seam fired, contained
    CHECK(rt->receipt_status(res1->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    auto gen2 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen2);
    CHECK(gen2.error() == "arm timed out");
    CHECK(rt->wedged_reobservations() == 1); // classified correctly despite index_held
    CHECK(rt->wedged_refusals() == 0);

    // rung 9c PR-5d: "r1" was never withdrawn - adopted, not disarmed, despite the
    // stuck index_held from the fault seam above (index_->add()'s own idempotent
    // no-op for an identical (key, rule_id, generation) makes this safe - see
    // on_arm_complete's adoption branch).
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Governance UP-1 (this governance run's finding, #4221 rung 9c PR-5c follow-up -
// NOT the PR's own "up-1/piece-1" Dispatching-window race above, a different
// finding that happens to share the "UP-1" label): retargeting a rule from a
// working key onto an already-Wedged key held by a DIFFERENT rule_id must not
// tear down the calling rule's own live arm before refusing - attach_core()
// used to call detach_rule_locked(rule_id) UNCONDITIONALLY, before the up-2
// wedge check even ran, so a retarget onto a wedged key left the calling rule
// with ZERO live arms and no automatic recovery path (the sticky-Wedged design
// means a same-rule retry never un-wedges the target key by itself, and a
// different-claimant refusal never creates a claim of its own).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("governance UP-1 (#4221 rung 9c PR-5c follow-up): retargeting a rule onto an "
          "already-Wedged key held by a DIFFERENT rule_id is refused WITHOUT tearing "
          "down the calling rule's own pre-existing live arm on its previous key",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    // (1) R attaches normally on K1 (/a) - a real, committed, working arm. Not
    // hung: hang_next_arm defaults false, so this arms synchronously.
    auto gen1 = rt->attach_rule("R", file_spec("/a"), file_exists_rule("R"), true);
    REQUIRE(gen1.has_value());
    REQUIRE(rt->rule_count() == 1);
    REQUIRE(rt->armed_key_count() == 1);
    REQUIRE(b->disarms.load() == 0);

    // (2) Hang the next arm, then R2 attaches on K2 (/b) - parks Dispatching.
    b->hang_next_arm.store(true);
    auto res2 = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "R2", file_spec("/b"),
                                file_exists_rule("R2"), true);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    REQUIRE(res2.has_value());
    REQUIRE(res2->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);

    // (3) K2's head goes Wedged - claimed by R2, not R.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(res2->receipt) == GuardianSparkRuntime::ReceiptStatus::Wedged);

    // (4) R retargets from K1 onto the now-Wedged K2 (a genuinely different
    // rule_id's wedge - R2, not R) - must be refused synchronously.
    auto gen3 = rt->attach_rule("R", file_spec("/b"), file_exists_rule("R"), true);
    REQUIRE_FALSE(gen3.has_value());
    CHECK(gen3.error() == "spark key wedged");
    CHECK(rt->wedged_refusals() == 1);
    CHECK(rt->wedged_reobservations() == 0);

    // The fix: R's ORIGINAL arm on K1 is still live - rule_count()/
    // armed_key_count() did not drop, and K1's real subscription was never
    // handed to a disarm. Pre-fix, detach_rule_locked("R") ran unconditionally
    // BEFORE the wedge check, synchronously erasing rules_["R"] and keys_[K1]
    // (and queuing K1's disarm) well before this call ever returned - both
    // counts would already read 0 here.
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->disarms.load() == 0); // K1's subscription was never torn down

    // R2's own hung, wedged claim still recovers normally once released - rung 9c
    // PR-5d: R2 was never withdrawn either (R's refusal never touched it - the
    // hoisted different-rule_id check returns before any detach runs), so its late
    // success is ADOPTED, joining R's own live arm as a second, independent rule.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 2; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 0); // neither R's nor R2's subscription was ever torn down
    CHECK(rt->armed_key_count() == 2); // K1 (R) and K2 (R2), both live
}

TEST_CASE("up-4 (#4221): a Queued, withdrawn head with no outcome (a double-fault residue) "
          "is reaped by expire_overdue_claims' new terminal-recovery pass - the CONFIRMED "
          "real defect (Fable review), reached here via genuine allocation-failure seams, "
          "not a fabricated state",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    // Construction: fault point 1 makes the initial staging throw before `finished`/
    // `verdicts` are ever populated - firewalled=true with an EMPTY finished, which is
    // the ONLY way publish_arm_verdicts_locked's firewall branch (not the ordinary
    // fill-in loop) is reached. The drain gap hook fires exactly once, synchronously,
    // between that catch and the (still-live) compensating-disarm continuation this
    // key's real, successful arm now owes - re-arming fault point 7 there, timed so it
    // fires inside the firewall loop AFTER release_claim_index_locked has already
    // failed (index_remove_fault_for_test) and marked the claim withdrawn+Queued, but
    // BEFORE its outcome is written. That exact window is the residue.
    std::atomic<bool> hook_fired{false};
    rt->set_index_remove_fault_for_test(true);
    rt->set_drain_fault_point_for_test(1);
    rt->set_drain_gap_hook_for_test([&] {
        rt->set_drain_fault_point_for_test(7);
        hook_fired.store(true, std::memory_order_release);
    });

    const auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                     file_exists_rule("r1"), true);
    REQUIRE(res.has_value());
    REQUIRE(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    // Do not clear the hook until it has actually fired (on_arm_complete runs
    // asynchronously - this NonWaiting attach can return before it even starts).
    // Clearing it prematurely would race the callback and silently skip re-arming
    // fault point 7, letting this claim resolve normally instead of stranding.
    REQUIRE(yuzu::test::spin_until([&] { return hook_fired.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    rt->set_drain_gap_hook_for_test({});

    // The compensating disarm (the real arm succeeded; nobody adopted it) must still
    // run - that part is unaffected by either fault seam.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));

    // The residue itself: still queued, no receipt resolution, no further sweep has
    // touched it (neither expire_overdue_claims's own overdue-arm scan - this claim
    // was never dispatched-and-abandoned - nor redrive_retained_disarms - this is an
    // Arm claim, not a Disarm).
    REQUIRE(rt->claim_queue_depth_for_test(key) == 1);
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);
    CHECK(rt->claim_drain_failures() >= 1);

    // The up-4 fix: the maintenance pass reaps it without any further same-key event.
    rt->expire_overdue_claims();
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    CHECK(rt->is_terminal(res->receipt));

    // Runtime stays healthy: a fresh attach on the same key arms cleanly afterward.
    const auto res2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    REQUIRE(res2.has_value());
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);
}

TEST_CASE("up-4/ch-1 (#4221, Gate 8 governance follow-up): fault point 9 - an allocation "
          "failure INSIDE reap_stranded_claims_locked's own synthesize_fallback_outcome_locked "
          "call degrades to retry-next-pass, never a terminate, now that its noexcept is "
          "correctly dropped",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    // Identical construction to the up-4 test above: strand a Queued, withdrawn,
    // no-outcome Arm claim via the same genuine double-fault window (fault point 1
    // at initial staging, a gap-hook re-arming fault point 7 inside the firewall
    // loop's own fill-in allocation) - see that test's own comment for the full
    // mechanics. This claim's rule is NEVER committed to rules_ (the firewalled
    // path never reaches the ordinary fill-in loop that would commit it), which is
    // exactly what makes reap_stranded_claims_locked's later call to
    // synthesize_fallback_outcome_locked take the FAILURE branch - the one guarded
    // by fault point 9 - rather than the Armed branch.
    std::atomic<bool> hook_fired{false};
    rt->set_index_remove_fault_for_test(true);
    rt->set_drain_fault_point_for_test(1);
    rt->set_drain_gap_hook_for_test([&] {
        rt->set_drain_fault_point_for_test(7);
        hook_fired.store(true, std::memory_order_release);
    });

    const auto res = rt->attach_rule(GuardianSparkRuntime::NonWaiting{}, "r1", file_spec("/a"),
                                     file_exists_rule("r1"), true);
    REQUIRE(res.has_value());
    REQUIRE(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    REQUIRE(yuzu::test::spin_until([&] { return hook_fired.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    rt->set_drain_gap_hook_for_test({});
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    REQUIRE(rt->claim_queue_depth_for_test(key) == 1);
    const auto failures_before = rt->claim_drain_failures();

    // Arm fault point 9 for exactly one throw, then call expire_overdue_claims():
    // reap_stranded_claims_locked reaches the stranded head, calls
    // synthesize_fallback_outcome_locked, which throws bad_alloc at the seam this
    // governance run added. The now-genuinely-functional try/catch around that call
    // (correctly contained ONLY because noexcept was dropped in the same fix - a
    // throw escaping a noexcept function would std::terminate before this catch
    // ever ran) must count the failure and leave the claim for the next pass,
    // never crash the process and never half-write the claim's outcome.
    rt->set_drain_fault_point_for_test(9);
    rt->expire_overdue_claims();
    CHECK(rt->claim_queue_depth_for_test(key) == 1); // NOT reaped this pass
    CHECK(rt->receipt_status(res->receipt) == GuardianSparkRuntime::ReceiptStatus::Pending);
    CHECK(rt->claim_drain_failures() > failures_before);

    // A clean pass (fault cleared - the one-shot compare_exchange already consumed
    // it, but be explicit) reaps it exactly as the up-4 test's own final step does.
    rt->expire_overdue_claims();
    CHECK(rt->claim_queue_depth_for_test(key) == 0);
    CHECK(rt->is_terminal(res->receipt));

    // Runtime stays healthy afterward.
    const auto res2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    REQUIRE(res2.has_value());
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);
}

TEST_CASE("up-5 (#4221): disarm_retained() is a real lifecycle count, not a monotonic "
          "counter - it decrements on the retained claim's own successful completion, "
          "and a repeated refusal on the SAME claim never inflates it",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));

    rt->set_io_executor_fail_launch_for_test(true);
    rt->detach_rule("r1");
    rt->set_io_executor_fail_launch_for_test(false);
    REQUIRE(rt->disarm_retained() == 1);

    // A repeated refusal on the SAME retained claim must not inflate the count.
    rt->set_io_executor_fail_launch_for_test(true);
    CHECK(rt->redrive_retained_disarms() == 1); // attempted, refused again
    rt->set_io_executor_fail_launch_for_test(false);
    CHECK(rt->disarm_retained() == 1); // still 1, not 2

    // Now let it succeed: the count must return to 0.
    REQUIRE(rt->redrive_retained_disarms() == 1);
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(rt->disarm_retained() == 0);
    CHECK(rt->claim_queue_depth_for_test(spark_key(file_spec("/a"))) == 0);
}

TEST_CASE("up-5 (#4221): the convergence lane's priority loop redrives a retained disarm "
          "on its own, with no further attach/detach/direct-redrive call - proving the "
          "scheduler wiring itself, not just the runtime function in isolation",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));

    rt->set_io_executor_fail_launch_for_test(true);
    rt->detach_rule("r1");
    REQUIRE(rt->disarm_retained() == 1);
    REQUIRE(rt->rule_count() == 0);
    REQUIRE(rt->armed_key_count() == 0);

    ConvergenceScheduler::Config cfg;
    cfg.priority_poll_ms = 20; // fast, deterministic-enough polling for a unit test
    cfg.jitter_pct = 0;
    ConvergenceScheduler sched{*rt, cfg};
    sched.start();

    // Clear the refusal and make NO further attach/detach/direct-redrive calls -
    // the scheduler alone must complete cleanup.
    rt->set_io_executor_fail_launch_for_test(false);
    REQUIRE(yuzu::test::spin_until([&] { return rt->disarm_retained() == 0; },
                                   std::chrono::seconds(10)));
    CHECK(b->disarms.load() == 1);
    sched.stop();
    CHECK(sched.sweep_exception_count() == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// rung 9c PR-5b hardening, this governance run (#4221): CompensationPermit /
// RetainedGuard RAII semantics, added when cpp-safety's Gate 3 adjudication
// declined the "impossibility" exception for the pre-hardening plain-bool manual
// acquire/release pairing (governance.d ledger, this run). These two types are
// exercised in full end-to-end fault scenarios above already (the up-3/up-3-b/
// up-4/up-5 cases), but nothing pinned their OWN move/engage/release contract in
// isolation - this does, directly against a local counter, independent of the
// wider runtime state machine.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("RAII hardening (#4221): CompensationPermit engage/move/release semantics",
          "[spark][runtime][liveness]") {
    std::atomic<int> slot{0};

    SECTION("default-constructed permit is disengaged - no-op reset, no decrement") {
        CompensationPermit p;
        p.reset();
        CHECK(slot.load() == 0);
    }

    SECTION("engaging increments the target exactly once; destruction releases exactly once") {
        slot.fetch_add(1); // simulate the caller's own increment (try_reserve's contract:
                            // the counter is bumped BEFORE the permit is constructed)
        {
            CompensationPermit p{&slot};
            CHECK(slot.load() == 1);
        }
        CHECK(slot.load() == 0);
    }

    SECTION("reset() is idempotent - a second reset() does not double-decrement") {
        slot.fetch_add(1);
        CompensationPermit p{&slot};
        p.reset();
        CHECK(slot.load() == 0);
        p.reset(); // must be a safe no-op, not a second fetch_sub
        CHECK(slot.load() == 0);
    }

    SECTION("move construction transfers ownership - the moved-from permit releases nothing") {
        slot.fetch_add(1);
        CompensationPermit p1{&slot};
        CompensationPermit p2{std::move(p1)};
        p1.reset(); // moved-from: must be a no-op, the slot is p2's now
        CHECK(slot.load() == 1);
        p2.reset();
        CHECK(slot.load() == 0);
    }

    SECTION("move assignment releases the assignee's own prior permit before adopting the new one") {
        std::atomic<int> slot2{0};
        slot.fetch_add(1);
        slot2.fetch_add(1);
        CompensationPermit p1{&slot};
        CompensationPermit p2{&slot2};
        p2 = std::move(p1); // p2's own slot2 reservation must release before adopting slot
        CHECK(slot2.load() == 0);
        CHECK(slot.load() == 1); // not yet released - p2 now owns it
        p2.reset();
        CHECK(slot.load() == 0);
    }

    SECTION("std::optional<CompensationPermit>::emplace/reset matches KeyClaim's own usage") {
        slot.fetch_add(1);
        std::optional<CompensationPermit> opt;
        opt.emplace(&slot);
        CHECK(slot.load() == 1);
        opt.reset(); // std::optional::reset() destroys the held permit -> releases
        CHECK(slot.load() == 0);
        opt.reset(); // no-op: nothing held
        CHECK(slot.load() == 0);
    }
}

TEST_CASE("RAII hardening (#4221): RetainedGuard engage/move/release semantics",
          "[spark][runtime][liveness]") {
    std::atomic<std::uint64_t> counter{0};

    SECTION("default-constructed guard is disengaged - no-op reset, no decrement") {
        RetainedGuard g;
        g.reset();
        CHECK(counter.load() == 0);
    }

    SECTION("engaging then destroying decrements exactly once, matching disarm_retained()'s own "
            "explicit-fetch_add-before-construct contract (mark_retained_locked's own shape)") {
        counter.fetch_add(1);
        {
            RetainedGuard g{&counter};
            CHECK(counter.load() == 1);
        }
        CHECK(counter.load() == 0);
    }

    SECTION("reset() is idempotent") {
        counter.fetch_add(1);
        RetainedGuard g{&counter};
        g.reset();
        CHECK(counter.load() == 0);
        g.reset();
        CHECK(counter.load() == 0);
    }

    SECTION("move construction transfers ownership") {
        counter.fetch_add(1);
        RetainedGuard g1{&counter};
        RetainedGuard g2{std::move(g1)};
        g1.reset();
        CHECK(counter.load() == 1);
        g2.reset();
        CHECK(counter.load() == 0);
    }

    SECTION("std::optional<RetainedGuard> emplace/reset matches KeyClaim::retained_guard's own usage, "
            "including the idempotency mark_retained_locked/clear_retained_locked rely on") {
        counter.fetch_add(1);
        std::optional<RetainedGuard> opt;
        opt.emplace(&counter);
        CHECK(counter.load() == 1);
        // mark_retained_locked's own idempotency check: "if already engaged, do nothing" -
        // re-emplace-guarded-by-caller (never re-emplace an already-engaged optional
        // directly, or it would re-engage without a matching counter bump; the runtime
        // guards this with `if (claim.retained_guard) return;` before ever calling
        // emplace - this SECTION pins that emplace() itself is a plain re-engage with no
        // built-in idempotency, so that caller-side guard is load-bearing, not optional).
        CHECK(bool{opt});
        opt.reset();
        CHECK(counter.load() == 0);
        opt.reset();
        CHECK(counter.load() == 0);
    }
}

TEST_CASE("#4508 CH-3: faulted withdrawal preserves an adopted unpublished generation",
          "[spark][runtime][liveness][wedge-candidates][ch3]") {
    using namespace std::chrono_literals;
    using RT = GuardianSparkRuntime;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, RT::Config{.backend_op_deadline = 50ms});
    const auto key_a = spark_key(file_spec("/a"));
    auto gA = b->park_next_arm_for_key(key_a);
    auto park = std::make_shared<DrainPark>();
    struct Cleanup {
        FakeBackend* b;
        DrainPark* park;
        ~Cleanup() { park->release(); b->release_all_key_gates(); }
    } cleanup{b.get(), park.get()};

    auto a = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(a.has_value());
    REQUIRE(gA->wait_entered(10s));
    std::this_thread::sleep_for(200ms);
    REQUIRE(rt->expire_overdue_claims() == 1);
    CHECK(rt->receipt_status(a->receipt) == RT::ReceiptStatus::Wedged);
    CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
    CHECK(rt->receipt_wedge_candidate_for_test(a->receipt));

    rt->set_drain_gap_hook_for_test([park] { park->wait(); });
    rt->set_drain_fault_point_for_test(3);
    gA->release();
    REQUIRE(yuzu::test::spin_until([&] { return park->entered.load(); }, 10s));
    REQUIRE(rt->rule_count() == 1);
    CHECK(rt->claim_queue_depth_for_test(key_a) == 1);
    CHECK(rt->receipt_recovered(a->receipt));
    CHECK(rt->receipt_status(a->receipt) == RT::ReceiptStatus::Wedged);
    CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
    CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
    CHECK(rt->rule_active_for_test("r1") == true);

    rt->set_detach_post_fault_point_for_test(1);
    REQUIRE_THROWS_AS(rt->detach_rule("r1"), std::bad_alloc);
    CHECK(rt->rule_active_for_test("r1") == true); // W0: rg aliases rules_' generation
    CHECK(rt->rule_count() == 1);
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->disarms.load() == 0);

    park->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return b->disarmed_ids().empty() && rt->claim_queue_depth_for_test(key_a) == 0;
    }, 10s));
    rt->set_drain_gap_hook_for_test({});
    CHECK(rt->claim_drain_failures() >= 1);
    CHECK(rt->rule_count() == 1);
    CHECK(rt->receipt_recovered(a->receipt));
    CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
    CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
    rt->detach_rule("r1");
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    REQUIRE(yuzu::test::spin_until([&] {
        return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key_a) == 0;
    }, 10s));
    CHECK(b->disarmed_ids() == b->armed_ids());
}

TEST_CASE("#4508 CH-4: expiry after ordinary commit preserves the real wedge candidate",
          "[spark][runtime][liveness][wedge-candidates][ch4]") {
    using namespace std::chrono_literals;
    using RT = GuardianSparkRuntime;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, RT::Config{.backend_op_deadline = 50ms});
    const auto key_a = spark_key(file_spec("/a"));
    const auto key_c = spark_key(file_spec("/c"));
    auto gA = b->park_next_arm_for_key(key_a);
    auto gC = b->park_next_arm_for_key(key_c);
    auto park = std::make_shared<DrainPark>();
    // Construct before step 1: even the first failed REQUIRE must release gA.
    struct Cleanup {
        FakeBackend* b;
        DrainPark* park;
        ~Cleanup() { park->release(); b->release_all_key_gates(); }
    } cleanup{b.get(), park.get()};

    auto a = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(a.has_value());
    REQUIRE(gA->wait_entered(10s));
    std::this_thread::sleep_for(200ms);
    REQUIRE(rt->expire_overdue_claims() == 1);
    CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
    CHECK(rt->receipt_wedge_candidate_for_test(a->receipt));

    auto c = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/c"), file_exists_rule("r1"), true);
    REQUIRE(c.has_value());
    REQUIRE(gC->wait_entered(10s));
    CHECK(rt->receipt_status(c->receipt) == RT::ReceiptStatus::Pending);
    CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
    CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
    rt->set_drain_gap_hook_for_test([park] { park->wait(); });
    rt->set_drain_fault_point_for_test(2);
    gC->release();
    REQUIRE(yuzu::test::spin_until([&] { return park->entered.load(); }, 10s));
    REQUIRE(rt->rule_count() == 1);
    CHECK(rt->claim_queue_depth_for_test(key_c) == 1);
    CHECK(rt->receipt_status(c->receipt) == RT::ReceiptStatus::Pending);
    CHECK(rt->receipt_recovered(c->receipt));
    CHECK(rt->keys_for_type(SparkType::File) == std::vector<std::string>{key_c});

    auto again = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(again.has_value());
    CHECK(again->kind == RT::ArmOutcomeKind::Accepted);
    CHECK(again->receipt.claim == a->receipt.claim);
    CHECK(rt->wedged_reobservations() >= 1);
    CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
    CHECK(rt->receipt_wedge_candidate_for_test(a->receipt));
    CHECK(rt->rule_count() == 1);
    std::this_thread::sleep_for(200ms);
    CHECK(rt->expire_overdue_claims() == 1); // C's rg was moved, whether commit succeeded or threw
    CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
    CHECK_FALSE(rt->receipt_wedge_candidate_for_test(c->receipt));
    CHECK(rt->receipt_status(c->receipt) == RT::ReceiptStatus::Wedged);
    CHECK(rt->receipt_recovered(c->receipt)); // H12: current receipt-history behavior
    CHECK(rt->receipt_wedge_candidate_for_test(a->receipt));

    park->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return b->disarmed_ids().empty() && rt->claim_queue_depth_for_test(key_c) == 0;
    }, 10s));
    rt->set_drain_gap_hook_for_test({});
    CHECK(rt->rule_count() == 1);
    gA->release();
    REQUIRE(yuzu::test::spin_until([&] {
        return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key_a) == 0;
    }, 10s));
    CHECK(rt->wedge_adopt_stale_refused() == 1);
    CHECK(rt->rule_count() == 1);
    CHECK(rt->keys_for_type(SparkType::File) == std::vector<std::string>{key_c});
    CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
    CHECK(rt->receipt_status(a->receipt) == RT::ReceiptStatus::Wedged);
    CHECK_FALSE(rt->receipt_recovered(a->receipt));
    // m-l: A is popped, still active, and not committed. Only membership rejects it.
    CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
    REQUIRE(b->armed_ids().size() == 2);
    CHECK(b->disarmed_ids()[0] == b->armed_ids()[1]);
    rt->detach_rule("r1");
    REQUIRE(yuzu::test::spin_until([&] {
        return b->disarmed_ids().size() == 2 && rt->claim_queue_depth_for_test(key_c) == 0;
    }, 10s));
    CHECK(rt->rule_count() == 0);
}

TEST_CASE("#4508 CH-1: three-key flip-flop preserves one desired wedge",
          "[spark][runtime][liveness][wedge-candidates][ch1]") {
    using namespace std::chrono_literals;
    using RT = GuardianSparkRuntime;
    // G1: two B-timeout positions x six release orders. G2: two B-timeout
    // positions x C pending/wedged. G3: C pending/wedged, global withdrawal.
    for (int row = 0; row != 18; ++row) {
        DYNAMIC_SECTION("row " << row) {
            const bool keep = row < 12;
            const bool withdraw_all = row >= 16;
            const bool b_expires_first = keep ? row < 6 : (row < 14 || withdraw_all);
            const bool c_wedges = keep || row % 2 == 0;
            auto r = std::make_shared<FakeReader>();
            auto b = std::make_shared<FakeBackend>();
            auto rt = make_rt(r, b, RT::Config{.backend_op_deadline = 50ms});
            const std::array specs{file_spec("/a"), file_spec("/b"), file_spec("/c")};
            const std::array keys{spark_key(specs[0]), spark_key(specs[1]), spark_key(specs[2])};
            const std::array gates{b->park_next_arm_for_key(keys[0]),
                                   b->park_next_arm_for_key(keys[1]),
                                   b->park_next_arm_for_key(keys[2])};
            struct Cleanup {
                FakeBackend* b;
                ~Cleanup() { b->release_all_key_gates(); }
            } cleanup{b.get()};
            const auto attach = [&](int i) {
                auto result = rt->attach_rule(RT::NonWaiting{}, "r1", specs[i],
                                               file_exists_rule("r1"), true);
                REQUIRE(result.has_value());
                REQUIRE(result->kind == RT::ArmOutcomeKind::Accepted);
                return result->receipt;
            };
            const auto expire = [&] {
                std::this_thread::sleep_for(200ms);
                REQUIRE(rt->expire_overdue_claims() == 1);
            };
            const auto a = attach(0);
            REQUIRE(gates[0]->wait_entered(10s));
            expire();
            CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
            CHECK(rt->receipt_wedge_candidate_for_test(a));
            const auto rb = attach(1);
            REQUIRE(gates[1]->wait_entered(10s));
            CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
            if (b_expires_first) {
                expire();
                CHECK(rt->receipt_wedge_candidate_for_test(rb));
            }
            CHECK(attach(0).claim == a.claim);
            CHECK(rt->receipt_wedge_candidate_for_test(a));
            if (!b_expires_first)
                expire();
            CHECK_FALSE(rt->receipt_wedge_candidate_for_test(rb));
            CHECK(rt->wedge_candidate_count_for_test("r1") == 1);

            const auto c = attach(2);
            REQUIRE(gates[2]->wait_entered(10s));
            CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a));
            CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
            if (c_wedges) {
                expire();
                CHECK(rt->receipt_wedge_candidate_for_test(c));
            }
            // Restore after C's creation. Pending C is explicitly withdrawn
            // below; no C-success-without-withdrawal H1 row is included.
            CHECK(attach(0).claim == a.claim);
            CHECK(rt->receipt_wedge_candidate_for_test(a));
            CHECK_FALSE(rt->receipt_wedge_candidate_for_test(c));
            CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
            if (!keep) {
                if (withdraw_all)
                    rt->detach_all();
                else
                    rt->detach_rule("r1");
                CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
                CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a));
            }
            const std::array<std::array<int, 3>, 6> orders{{
                {0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}};
            const auto order = keep ? orders[row % 6] : orders[5];
            std::size_t disarmed = 0;
            for (const auto i : order) {
                gates[i]->release();
                if (!keep || i != 0)
                    ++disarmed;
                REQUIRE(yuzu::test::spin_until([&] {
                    return b->disarmed_ids().size() == disarmed &&
                           rt->claim_queue_depth_for_test(keys[i]) == 0;
                }, 10s));
                CHECK(rt->wedge_candidate_count_for_test("r1") <= 1);
            }
            CHECK(rt->rule_count() == (keep ? 1 : 0));
            CHECK(rt->armed_key_count() == (keep ? 1 : 0));
            CHECK(rt->receipt_recovered(a) == keep);
            CHECK(rt->receipt_status(a) == RT::ReceiptStatus::Wedged);
            CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a));
            CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
            CHECK(rt->keys_for_type(SparkType::File) ==
                  (keep ? std::vector<std::string>{keys[0]} : std::vector<std::string>{}));
            const auto armed_ids = b->armed_ids();
            REQUIRE(armed_ids.size() == 3);
            auto expected_disarmed = armed_ids;
            if (keep) {
                const auto a_position = std::find(order.begin(), order.end(), 0) - order.begin();
                expected_disarmed.erase(expected_disarmed.begin() + a_position);
            }
            CHECK(b->disarmed_ids() == expected_disarmed);
            if (keep) {
                rt->detach_rule("r1");
                REQUIRE(yuzu::test::spin_until([&] {
                    return b->disarmed_ids().size() == 3 && rt->claim_queue_depth_for_test(keys[0]) == 0;
                }, 10s));
                CHECK(rt->rule_count() == 0);
            }
        }
    }
}

TEST_CASE("#4508 CH-1x: per-rule withdrawal isolates another rule's wedge",
          "[spark][runtime][liveness][wedge-candidates][ch1x]") {
    using namespace std::chrono_literals;
    using RT = GuardianSparkRuntime;
    for (const bool all : {false, true}) {
        DYNAMIC_SECTION("detach_all=" << all) {
            auto r = std::make_shared<FakeReader>();
            auto b = std::make_shared<FakeBackend>();
            auto rt = make_rt(r, b, RT::Config{.backend_op_deadline = 50ms});
            const auto key_x = spark_key(file_spec("/x"));
            const auto key_a = spark_key(file_spec("/a"));
            auto gX = b->park_next_arm_for_key(key_x);
            auto gA = b->park_next_arm_for_key(key_a);
            struct Cleanup {
                FakeBackend* b;
                ~Cleanup() { b->release_all_key_gates(); }
            } cleanup{b.get()};
            auto x = rt->attach_rule(RT::NonWaiting{}, "r2", file_spec("/x"), file_exists_rule("r2"), true);
            REQUIRE(x.has_value());
            REQUIRE(gX->wait_entered(10s));
            std::this_thread::sleep_for(200ms);
            REQUIRE(rt->expire_overdue_claims() == 1);
            auto a = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
            REQUIRE(a.has_value());
            REQUIRE(gA->wait_entered(10s));
            std::this_thread::sleep_for(200ms);
            REQUIRE(rt->expire_overdue_claims() == 1);
            if (all)
                rt->detach_all();
            else
                rt->detach_rule("r1");
            CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
            CHECK(rt->wedge_candidate_count_for_test("r2") == (all ? 0 : 1));
            CHECK(rt->receipt_wedge_candidate_for_test(x->receipt) == !all);
            gA->release();
            REQUIRE(yuzu::test::spin_until([&] {
                return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key_a) == 0;
            }, 10s));
            gX->release();
            REQUIRE(yuzu::test::spin_until([&] {
                return b->disarmed_ids().size() == (all ? 2 : 1) && rt->claim_queue_depth_for_test(key_x) == 0;
            }, 10s));
            CHECK(rt->rule_count() == (all ? 0 : 1));
            CHECK(rt->receipt_recovered(x->receipt) == !all);
            CHECK(rt->keys_for_type(SparkType::File) ==
                  (all ? std::vector<std::string>{} : std::vector<std::string>{key_x}));
            if (!all) {
                rt->detach_rule("r2");
                REQUIRE(yuzu::test::spin_until([&] {
                    return b->disarmed_ids().size() == 2 && rt->claim_queue_depth_for_test(key_x) == 0;
                }, 10s));
            }
        }
    }
}

TEST_CASE("#4508 CH-2: candidate reads follow claim outcomes and dispatch state",
          "[spark][runtime][liveness][wedge-candidates][ch2]") {
    using namespace std::chrono_literals;
    using RT = GuardianSparkRuntime;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, RT::Config{.backend_op_deadline = 50ms});
    const auto key = spark_key(file_spec("/a"));
    auto gate = b->park_next_arm_for_key(key);
    struct Cleanup {
        FakeBackend* b;
        ~Cleanup() { b->release_all_key_gates(); }
    } cleanup{b.get()};

    SECTION("a Dispatching wedge loses candidacy when admission is reclassified Stopped") {
        RT::ArmReceipt observed;
        rt->set_dispatch_entry_hook_for_test([&] {
            std::this_thread::sleep_for(200ms);
            REQUIRE(rt->expire_overdue_claims() == 1);
            auto again = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"),
                                          file_exists_rule("r1"), true);
            REQUIRE(again.has_value());
            observed = again->receipt;
            CHECK(rt->receipt_wedge_candidate_for_test(observed)); // Dispatching, not Dispatched
            CHECK(rt->wedge_candidate_count_for_test("r1") == 1);
            rt->begin_stop();
        });
        auto result = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"),
                                      file_exists_rule("r1"), true);
        CHECK_FALSE(result.has_value());
        REQUIRE(observed.claim);
        CHECK(rt->receipt_status(observed) == RT::ReceiptStatus::Stopped);
        // Discriminate WHY candidacy went false: the claim has already left
        // claims_ by the time the outer attach_rule call returns, so it's
        // membership (not the outcome/end classification) that the accessor's
        // false result rests on here - confirmed empirically, not assumed.
        CHECK(rt->claim_queue_depth_for_test(key) == 0);
        CHECK_FALSE(rt->receipt_wedge_candidate_for_test(observed));
        CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
        CHECK(b->arm_entries.load() == 0);
    }
    SECTION("withdrawn wedge late success is compensated") {
        auto a = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
        REQUIRE(a.has_value());
        REQUIRE(gate->wait_entered(10s));
        CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
        std::this_thread::sleep_for(200ms);
        REQUIRE(rt->expire_overdue_claims() == 1);
        CHECK(rt->receipt_wedge_candidate_for_test(a->receipt));
        rt->detach_rule("r1");
        CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
        gate->release();
        REQUIRE(yuzu::test::spin_until([&] {
            return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key) == 0;
        }, 10s));
        CHECK(rt->rule_count() == 0);
    }
    SECTION("a queued withdrawn follower never becomes a candidate") {
        auto a = rt->attach_rule(RT::NonWaiting{}, "head", file_spec("/a"), file_exists_rule("head"), true);
        REQUIRE(a.has_value());
        REQUIRE(gate->wait_entered(10s));
        auto follower = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
        REQUIRE(follower.has_value());
        CHECK(rt->claim_queue_depth_for_test(key) == 2);
        CHECK_FALSE(rt->receipt_wedge_candidate_for_test(follower->receipt));
        rt->detach_rule("r1");
        CHECK(rt->receipt_status(follower->receipt) == RT::ReceiptStatus::Withdrawn);
        CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
        CHECK_FALSE(rt->receipt_wedge_candidate_for_test(follower->receipt));
        std::this_thread::sleep_for(200ms);
        REQUIRE(rt->expire_overdue_claims() == 1);
        rt->detach_rule("head");
        gate->release();
        REQUIRE(yuzu::test::spin_until([&] {
            return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key) == 0;
        }, 10s));
        CHECK(rt->rule_count() == 0);
    }
    SECTION("a withdrawn but still-Dispatching claim is not re-abandoned by expiry (m-f)") {
        auto a = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
        REQUIRE(a.has_value());
        REQUIRE(gate->wait_entered(10s));
        // Still Dispatching (parked, never resolved) - withdraw it now, before it
        // ever wedges. Case 0 matches it (not yet waiter_abandoned, no outcome
        // yet) and sets outcome=Withdrawn/end=Withdrawn, but leaves it as the
        // key's fifo head (only a Queued claim is erased there).
        rt->detach_rule("r1");
        CHECK(rt->receipt_status(a->receipt) == RT::ReceiptStatus::Withdrawn);
        CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
        CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
        // Let its original deadline elapse while it's STILL parked (unresolved)
        // and already carries a terminal outcome. expire_overdue_claims's
        // outcome-check must skip it - re-abandoning it here would overwrite
        // `end` back to WaiterTimedOutDispatched and set waiter_abandoned=true,
        // resurrecting it as a wedge candidate for a rule just withdrawn (m-f).
        std::this_thread::sleep_for(200ms);
        CHECK(rt->expire_overdue_claims() == 0);
        CHECK(rt->receipt_status(a->receipt) == RT::ReceiptStatus::Withdrawn);
        CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
        CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
        gate->release();
        REQUIRE(yuzu::test::spin_until([&] {
            return b->disarmed_ids().size() == 1 && rt->claim_queue_depth_for_test(key) == 0;
        }, 10s));
        CHECK(rt->rule_count() == 0);
    }
    SECTION("a rollback whose claim was already withdrawn mid-dispatch is not re-abandoned (m-h)") {
        rt->set_dispatch_entry_hook_for_test([&] {
            rt->detach_rule("r1");
            throw std::runtime_error{"m-h hook"};
        });
        REQUIRE_THROWS_AS(
            rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true),
            std::runtime_error);
        rt->set_dispatch_entry_hook_for_test({});
        // claim_rollback.fn fired during the throw's unwind and must have seen
        // arm_claim->outcome already set (by detach_rule's own Case 0,
        // synchronously, inside the hook) and returned without touching it
        // again - a second abandon_claim_locked call would overwrite `end` back
        // to WaiterTimedOutDispatched and set waiter_abandoned=true, wrongly
        // resurrecting candidacy for a rule already withdrawn (m-h).
        CHECK(rt->claim_queue_depth_for_test(key) == 1);
        CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
        auto r2 = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
        REQUIRE(r2.has_value());
        CHECK(r2->kind == RT::ArmOutcomeKind::Accepted);
        CHECK(rt->receipt_status(r2->receipt) == RT::ReceiptStatus::Pending);
        CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
    }
    for (const bool throws : {false, true}) {
        DYNAMIC_SECTION("wedged backend failure, throws=" << throws) {
            auto a = rt->attach_rule(RT::NonWaiting{}, "r1", file_spec("/a"), file_exists_rule("r1"), true);
            REQUIRE(a.has_value());
            REQUIRE(gate->wait_entered(10s));
            std::this_thread::sleep_for(200ms);
            REQUIRE(rt->expire_overdue_claims() == 1);
            CHECK(rt->receipt_wedge_candidate_for_test(a->receipt));
            b->throw_arm.store(throws);
            b->fail_arm.store(!throws);
            gate->release();
            REQUIRE(yuzu::test::spin_until([&] {
                return b->disarmed_ids().empty() && rt->claim_queue_depth_for_test(key) == 0;
            }, 10s));
            CHECK(rt->rule_count() == 0);
            CHECK(rt->receipt_status(a->receipt) == RT::ReceiptStatus::Wedged);
            CHECK_FALSE(rt->receipt_recovered(a->receipt));
            CHECK_FALSE(rt->receipt_wedge_candidate_for_test(a->receipt));
            CHECK(rt->wedge_candidate_count_for_test("r1") == 0);
        }
    }
}
