// test_guardian_engine_spark_reconcile.cpp - GuardianEngine's rung-7 reconcile
// op: the mutual-exclusion invariant between the spark and legacy IGuard
// detection paths. Tested against a REAL SparkEngine with a fake mechanism
// (Sol's rev-1 review resolution: this is the right vehicle, not a separate
// fake-backend injection seam - it exercises wire_spark_engine's real
// register_consumer/arm/disarm calls, not a shortcut around them).

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "guaranteed_state.pb.h"
#include "guardian_arm_heartbeat.hpp" // GuardianArmStats complete type (rung 9c PR-3)
#include "guardian_backend.hpp" // guardian_backend_from_state/label (#2298 F13)
#include "guardian_convergence_scheduler.hpp" // ConvergenceScheduler (started_for_test, #2238)
#include "guardian_journal_format.hpp" // kJournalNamespace, parse_journal_batch (item 7 PR-Ag)
#include "guardian_joined_thread_role.hpp" // GuardianJoinedThreadRole (death test below)
#include "guardian_io_executor.hpp" // GuardianIoExecutor::submit() (rung 9c R5.1 death test)
#include "guardian_journal_heartbeat.hpp" // emit_guardian_journal_heartbeat_tags (aggregate inertness)
#include "guardian_lifecycle_journal.hpp" // GuardianLifecycleJournal (for the _for_test fault seam)
#include "guardian_outbox.hpp" // OutboxEntry, SendResult - full definitions for the test's send_fn
#include "guardian_outbox_drain_worker.hpp" // GuardianOutboxDrainWorker (started_for_test, #2238)
#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime::set_detach_fault_for_test (rung 9c PR-2 Unit 6 test (b))
#include "shutdown_deadline_guard.hpp" // #2233 item 3 ("S+") wedge-pattern test
#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <atomic>
#include <condition_variable>
#include <thread>
#include <version> // __cpp_lib_jthread
#include <vector>

#include <sqlite3.h> // real KV-write-failure seam (test_kv_store.cpp's own "drop the table
                     // through a second connection" pattern) - no fault-injection stand-in

#ifndef _WIN32
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace gpb = ::yuzu::guardian::v1;
using yuzu::agent::GuardianEngine;
using yuzu::agent::ISparkMechanism;
using yuzu::agent::KvStore;
using yuzu::agent::make_file_mechanism;
using yuzu::agent::make_registry_mechanism;
using yuzu::agent::make_service_mechanism;
using yuzu::agent::OutboxEntry;
using yuzu::agent::SendResult;
using yuzu::agent::ServiceSparkParams; // #2818 pin: the raw sibling's spec
using yuzu::agent::SparkData;
using yuzu::agent::SparkEmitFn;
using yuzu::agent::SparkEngine;
using yuzu::agent::SparkEvent; // #2818 pin: the raw sibling's queued handler
using yuzu::agent::SparkFaultFn;
using yuzu::agent::SparkParams;
using yuzu::agent::SparkSpec; // #2818 pin
using yuzu::agent::SparkType;

namespace {

/// Real KV-write-failure seam (rung 9c PR-2 Unit 6 gate, coordinator finding): opens a
/// SECOND connection to the SAME on-disk KvStore file and drops/recreates the
/// `kv_store` table, so `KvStore::set()` genuinely fails (a real SQLite "no such
/// table" error) or genuinely succeeds again on the SAME already-open KvStore object -
/// no fault-injection stand-in. Mirrors test_kv_store.cpp's own "dropping the table
/// through a second connection makes prepare_v2 fail for real" pattern. The schema
/// matches kv_store.cpp's own CREATE TABLE exactly (governance would flag drift here
/// as a truth mismatch against the real store).
/// RAII owner for the raw `sqlite3*` the two test helpers below open - governance
/// finding (Gate 3, cpp-safety, policy floor): sqlite3_open() allocates a handle
/// EVEN ON FAILURE (SQLite's own contract - it must always be closed), and the
/// bare-pointer version of these helpers called REQUIRE(sqlite3_open(...) ==
/// SQLITE_OK) BEFORE any sqlite3_close(), so a REQUIRE failure on that line threw
/// past the close and leaked the handle. A small scope-guard restores RAII without
/// otherwise changing either helper's shape.
struct ScopedTestSqlite3 {
    sqlite3* raw{nullptr};
    ~ScopedTestSqlite3() {
        if (raw)
            sqlite3_close(raw);
    }
    // Governance finding (Gate 8, cpp-safety, SHOULD): non-copyable so a future
    // accidental copy can never double-close this handle - neither helper below
    // copies it today, but the invariant should be compiler-enforced, not implicit.
    ScopedTestSqlite3() = default;
    ScopedTestSqlite3(const ScopedTestSqlite3&) = delete;
    ScopedTestSqlite3& operator=(const ScopedTestSqlite3&) = delete;
};

void drop_kv_store_table_for_test(const std::filesystem::path& db_path) {
    ScopedTestSqlite3 db;
    REQUIRE(sqlite3_open(db_path.string().c_str(), &db.raw) == SQLITE_OK);
    char* err = nullptr;
    const int rc = sqlite3_exec(db.raw, "DROP TABLE kv_store", nullptr, nullptr, &err);
    if (err)
        sqlite3_free(err);
    REQUIRE(rc == SQLITE_OK);
}
void recreate_kv_store_table_for_test(const std::filesystem::path& db_path) {
    ScopedTestSqlite3 db;
    REQUIRE(sqlite3_open(db_path.string().c_str(), &db.raw) == SQLITE_OK);
    char* err = nullptr;
    const int rc = sqlite3_exec(db.raw,
                                "CREATE TABLE IF NOT EXISTS kv_store ("
                                "    plugin     TEXT NOT NULL,"
                                "    key        TEXT NOT NULL,"
                                "    value      TEXT,"
                                "    updated_at INTEGER,"
                                "    PRIMARY KEY(plugin, key)"
                                ")",
                                nullptr, nullptr, &err);
    if (err)
        sqlite3_free(err);
    REQUIRE(rc == SQLITE_OK);
}

std::string uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME")) return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}
fs::path unique_kv_path() {
    const auto dir = fs::temp_directory_path() / ("yuzu_test_guardian_reconcile" + uid_suffix());
    return dir / (yuzu::test::unique_temp_path("reconcile_").filename().string() + ".db");
}

/// A minimal cross-platform stand-in for the real service mechanism (mirrors
/// test_spark_mechanism.cpp's FakeMechanism, trimmed to what these tests
/// need): records watch()/unwatch() calls, can be told to fail its NEXT
/// watch() (for the arm-failure test), and can be told to HANG its next
/// watch()/unwatch() until released (#2233 item 3 liveness repro, governance
/// Gate 3/4 consistency-auditor: this doc comment previously predated that
/// capability).
class FakeServiceMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        // rung 9c PR-2 Unit 6 test (a): counts every real invocation, unconditionally -
        // unlike watching_count() (reflects watched_, populated only past the hang
        // gate/failure checks below), this proves a SUPPRESSED retry never reaches the
        // mechanism at all, not merely that it hasn't (yet) committed.
        watch_calls_.fetch_add(1, std::memory_order_relaxed);
        bool hang = false;
        bool do_throw = false;
        {
            std::lock_guard<std::mutex> lk{mu_};
            if (fail_next_watch_) {
                fail_next_watch_ = false;
                return std::unexpected("forced watch failure");
            }
            hang = hang_next_watch_;
            hang_next_watch_ = false;
            do_throw = throw_next_watch_;
            throw_next_watch_ = false;
        }
        // #2233 item 3: the gate wait is deliberately OUTSIDE mu_ so release_hang()
        // (which only touches gate_mu_, never mu_) can never deadlock against a
        // concurrent is_watching()/watching_count() poll, and a parked test thread
        // never blocks this mechanism's own mu_ for the main thread. Shared by the
        // "S+" watchdog test (proves ShutdownDeadlineGuard fires during a real wedge)
        // and the raw characterisation tests below it (prove the wedge itself, with
        // no watchdog involved).
        if (hang) {
            std::unique_lock<std::mutex> gate_lk{gate_mu_};
            entered_hang_ = true;
            gate_cv_.notify_all();
            gate_cv_.wait(gate_lk, [this] { return released_; });
        }
        // #2818 pin: THROW rather than return std::unexpected, and do it AFTER the hang
        // gate. Both halves matter. `fail_next_watch_` is checked before the gate and
        // returns immediately, so it cannot produce the state that pin needs — a watch
        // still IN FLIGHT (key committed in armed_, teardown not yet run) while a second
        // consumer dedups onto it, which only THEN fails. Throwing also routes the
        // failure through watch_guarded's catch arm, the shape a real mechanism produces
        // under memory pressure.
        if (do_throw)
            throw std::runtime_error("forced watch throw");
        std::lock_guard<std::mutex> lk{mu_};
        watched_.insert(key);
        return {};
    }
    void unwatch(const std::string& key) override {
        bool hang = false;
        {
            std::lock_guard<std::mutex> lk{mu_};
            hang = hang_next_unwatch_;
            hang_next_unwatch_ = false;
        }
        if (hang) {
            std::unique_lock<std::mutex> gate_lk{gate_mu_};
            entered_hang_ = true;
            gate_cv_.notify_all();
            gate_cv_.wait(gate_lk, [this] { return released_; });
        }
        std::lock_guard<std::mutex> lk{mu_};
        watched_.erase(key);
    }
    void stop() override {}
    void set_fail_next_watch() {
        std::lock_guard<std::mutex> lk{mu_};
        fail_next_watch_ = true;
    }
    /// #2818 pin: next watch() THROWS (after the hang gate, if one is armed) instead of
    /// returning std::unexpected. See watch() for why the distinction is load-bearing.
    void set_throw_next_watch() {
        std::lock_guard<std::mutex> lk{mu_};
        throw_next_watch_ = true;
    }
    /// Next watch() blocks until release_hang() is called, from inside watch() with
    /// this mechanism's own mu_ released (mirrors the real contract: SparkEngine calls
    /// mechanism methods with its own lock released, spark_engine.cpp:759).
    void hang_next_watch() {
        std::lock_guard<std::mutex> lk{mu_};
        hang_next_watch_ = true;
    }
    void hang_next_unwatch() {
        std::lock_guard<std::mutex> lk{mu_};
        hang_next_unwatch_ = true;
    }
    /// Blocks until a hung watch()/unwatch() has actually entered its wait (avoids a
    /// racy sleep-based poll for "is it parked yet").
    bool wait_entered_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> gate_lk{gate_mu_};
        return gate_cv_.wait_for(gate_lk, timeout, [this] { return entered_hang_; });
    }
    void release_hang() {
        {
            std::lock_guard<std::mutex> gate_lk{gate_mu_};
            released_ = true;
        }
        gate_cv_.notify_all();
    }
    bool is_watching(const std::string& key) {
        std::lock_guard<std::mutex> lk{mu_};
        return watched_.count(key) > 0;
    }
    std::size_t watching_count() {
        std::lock_guard<std::mutex> lk{mu_};
        return watched_.size();
    }
    std::set<std::string> watched_snapshot() {
        std::lock_guard<std::mutex> lk{mu_};
        return watched_;
    }
    int watch_call_count() const { return watch_calls_.load(std::memory_order_relaxed); }

private:
    std::atomic<int> watch_calls_{0};
    std::mutex mu_;
    std::set<std::string> watched_;
    bool fail_next_watch_{false};
    bool throw_next_watch_{false};
    bool hang_next_watch_{false};
    bool hang_next_unwatch_{false};
    // Gate is a SEPARATE lock from mu_ (see watch()'s comment) - release_hang() must
    // never need mu_, or a caller blocked trying to take mu_ mid-hang (e.g. a concurrent
    // is_watching() from the test's own polling) could never be released.
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool entered_hang_{false};
    bool released_{false};
};

// Service: the ONE type with a mechanism registered in this fixture -> Arm.
// `service` defaults to "Spooler" so every existing call site is unaffected;
// tests that need to distinguish which of several rules armed pass a distinct
// name (#2238 item 1 - three rules sharing one service name would all derive
// the same spark key and be indistinguishable in the mechanism's watch set).
gpb::GuaranteedStateRule make_service_rule(const std::string& id, bool enabled = true,
                                           const std::string& service = "Spooler") {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("service-status-change");
    auto* a = r.mutable_assertion();
    a->set_type("service-running");
    (*a->mutable_params())["service_name"] = service;
    return r;
}

// File: NO mechanism registered in this fixture -> a routine Unsupported gap.
gpb::GuaranteedStateRule make_file_rule(const std::string& id, bool enabled = true) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("file-change");
    auto* a = r.mutable_assertion();
    a->set_type("file-exists");
    (*a->mutable_params())["path"] = "/tmp/yuzu-reconcile-test-target";
    return r;
}

// Registry: also NO mechanism registered in this fixture -> also a routine
// Unsupported gap (F7). Field shape mirrors test_guardian_engine.cpp's
// make_registry_rule() so validation/spec derivation succeeds identically.
gpb::GuaranteedStateRule make_registry_rule(const std::string& id, bool enabled = true) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("registry-change");
    auto* a = r.mutable_assertion();
    a->set_type("registry-value-equals");
    (*a->mutable_params())["hive"] = "HKCU";
    (*a->mutable_params())["key"] = "SOFTWARE\\YuzuTest\\GuardStatusTest";
    (*a->mutable_params())["value_name"] = "Flag";
    (*a->mutable_params())["value_type"] = "REG_DWORD";
    (*a->mutable_params())["expected"] = "1";
    return r;
}

// Invalid: an unrecognized spark type -> an authoring fault, never armed anywhere.
gpb::GuaranteedStateRule make_invalid_rule(const std::string& id) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(true);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("banana");
    r.mutable_assertion()->set_type("whatever");
    return r;
}

struct SparkReconcileFixture {
    yuzu::test::TempDbFile db_{unique_kv_path()};
    std::unique_ptr<KvStore> kv;
    SparkEngine spark_engine;
    FakeServiceMechanism* mechanism{nullptr}; // borrowed; owned by spark_engine
    std::unique_ptr<GuardianEngine> engine;
    std::mutex sent_mu;
    std::vector<OutboxEntry> sent;

    /// `periodic_bound_ms > 0` pins the drain worker's backstop before it is constructed,
    /// so a test can attribute a page to the reconnect kick rather than the backstop.
    /// `backend_op_deadline`, when set, shrinks GuardianSparkRuntime::Config's bounded
    /// arm/disarm wait (production default 5s) so a test can drive a deterministic
    /// "backend parked" scenario without a real multi-second wait (rung 9c PR-2:
    /// set_spark_backend_op_deadline_for_test, guardian_engine.hpp).
    explicit SparkReconcileFixture(std::uint64_t periodic_bound_ms = 0,
                                   std::optional<std::chrono::milliseconds> backend_op_deadline = std::nullopt) {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));

        auto mech = std::make_unique<FakeServiceMechanism>();
        mechanism = mech.get();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();

        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-test", /*prefer_spark=*/true);
        REQUIRE(engine->start_local().has_value());
        if (periodic_bound_ms > 0)
            engine->set_drain_worker_timing_for_test(periodic_bound_ms);
        if (backend_op_deadline)
            engine->set_spark_backend_op_deadline_for_test(*backend_op_deadline);
        engine->wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                                  [this](const OutboxEntry& e) {
                                      std::lock_guard<std::mutex> lk{sent_mu};
                                      sent.push_back(e);
                                      return SendResult::Sent;
                                  });
        REQUIRE(engine->spark_availability() == GuardianEngine::SparkAvailability::Available);
    }

    // GuardianEngine (and therefore spark_runtime_/scheduler/drain-worker) is
    // stopped/joined FIRST (via engine.reset(), whose dtor calls stop()) -
    // mirrors the production shutdown order (rung 7.7): Guardian's spark
    // teardown must complete before the SparkEngine it borrowed from is torn
    // down, since GuardianSparkEngineBackend holds a borrowed SparkEngine*.
    ~SparkReconcileFixture() {
        engine.reset();
        spark_engine.stop();
    }

    // Serialize-then-dispatch, NOT engine->apply_rules(p) directly: every rule
    // here carries an assertion params Map (service_name/hive/key/path), and on
    // Windows MSVC debug, populating that Map in the TEST EXE and then reading it
    // DLL-side hits the #501 cross-image abseil hash-seed split - .find() silently
    // misses ~50% of the time, producing an empty string exactly as if the field
    // were never set (confirmed on DGRHP: every service-type test here failed
    // spark validation with "spec derivation failed", i.e. guardian_assertion_
    // param("service_name") read back empty). guardian_dispatch_push_
    // bytes_for_test deserializes the bytes INSIDE the DLL, so the Map is
    // populated using the DLL's own seed - see guardian_engine.hpp's doc comment
    // on the helper for the full mechanism. Linux is blind to this class of bug
    // (single shared object, no split seed), which is why this went uncaught
    // until the first real Windows compile.
    //
    // rung 9c PR-2 Unit 6: does NOT settle - returns as soon as apply_rules()
    // does, which may be before an Accepted rule's arm has resolved. Most callers
    // want apply() below instead; use this raw form only when a test's own
    // premise is about that pre-settlement window (a persist-retry/durability
    // race against a specific injected fault - see the two journal tests that use
    // it directly instead of apply()).
    yuzu::agent::GuardianDispatchResult dispatch_raw(const gpb::GuaranteedStateRule& rule,
                                                     bool full_sync = true) {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(full_sync);
        *p.add_rules() = rule;
        return yuzu::agent::guardian_dispatch_push_bytes_for_test(*engine, p.SerializeAsString());
    }

    void apply(const gpb::GuaranteedStateRule& rule, bool full_sync = true) {
        auto dr = dispatch_raw(rule, full_sync);
        REQUIRE(dr.exit_code == 0);
        // rung 9c PR-2 Unit 6: apply_rules() no longer waits for an accepted arm to
        // resolve (§R5.1/R5.3) - settle here so every pre-existing caller of this
        // helper keeps observing "the push is fully reconciled" the way every one
        // of them assumed pre-cutover, rather than each test re-deriving its own
        // poll. The tick both drains resolved receipts (ack_pending_count_for_test
        // -> 0) and retries any pending journal persist, so one loop covers both
        // "is it armed yet" and "is it journaled yet" callers; an all-Unsupported/
        // Inert push never add_pending()s anything, so this returns at once.
        //
        // ack_pending_count_for_test() alone only covers ACCEPTED ARMS - a disable/
        // replace push's DISARM (Unit 3's own non-waiting cutover, unconditional
        // regardless of prefer_spark_) is never added to the ledger at all, so it
        // needs its own settle signal: active_io_workers() is the runtime's real
        // "any backend arm/disarm call still physically running" count (also used
        // for the F3 hard_exit orphan-worker contract), zero only once every
        // dispatched backend call - arm OR disarm - has actually finished.
        REQUIRE(yuzu::test::spin_until([&] {
            engine->journal_maintenance_tick();
            return engine->ack_pending_count_for_test() == 0 && engine->active_io_workers() == 0;
        }));
        // journal_maintenance_tick() persists BEFORE it drains the ack ledger (its own
        // doc comment: "neither reads the other's result"), so the very tick call
        // whose drain step FIRST observes ack_pending_count_for_test() drop to 0 may
        // have already run ITS OWN persist step against a pending_journal_ that still
        // predates the commit - the worker can stage the "armed" record in the gap
        // between this call's persist and drain steps. One more tick, now that the
        // settle loop above has already proven the commit (and therefore the staging
        // that happens-before it under the same lock) has happened, is guaranteed to
        // see it.
        engine->journal_maintenance_tick();
    }
};

} // namespace

TEST_CASE("#2818 — Guardian is notified when a sibling's failed watch kills their shared "
          "key, and reports the rule errored instead of still-armed",
          "[spark][guardian][reconcile]") {
    // The engine-level halves of this fix are pinned in test_spark_mechanism.cpp. THIS
    // case is the one that says why it matters: it shows the notification landing on
    // GUARDIAN, the real consumer, and shows what Guardian now reports afterwards.
    //
    // Guardian cannot be its own sibling - GuardianSparkRuntime's per-key claim FIFO
    // (rung 9c R5.2: a second same-key attach queues behind the in-flight head and joins
    // its subscription, never dispatching a second backend arm) makes two concurrent
    // Guardian arms of one key impossible. So the sibling here is a RAW SparkEngine consumer, which is exactly the
    // situation Stage 2 creates the moment anything other than Guardian arms a spark.
    SparkReconcileFixture f;

    // A raw consumer arms the SAME spec Guardian derives from make_service_rule("r1")
    // — SparkType::Service + service_name "Spooler" — and parks inside watch().
    auto raw = f.spark_engine.register_consumer("raw-sibling-2818", [](const SparkEvent&) {});
    REQUIRE(raw.has_value());
    const SparkSpec spec{SparkType::Service, ServiceSparkParams{"Spooler"}};

    f.mechanism->hang_next_watch();     // park mid-watch: key committed, watch in flight
    f.mechanism->set_throw_next_watch(); // …and fail once released
    std::expected<SparkEngine::SubscriptionId, std::string> raw_sub;
    std::thread armer([&] { raw_sub = f.spark_engine.arm(*raw, spec); });
    // cpp-safety Gate 3 finding (same class as the "hung watch()/unwatch() wedges
    // stop()" tests above): a REQUIRE between a thread spawn and its join can throw
    // and unwind past a still-joinable std::thread -> std::terminate() on the WHOLE
    // binary. Guard releases the hang and joins `armer` on any unwind path; harmless
    // no-op on the happy path below (release_hang() only matters once, join() on an
    // already-joined thread is a no-op via the joinable() check).
    struct ArmerGuard {
        FakeServiceMechanism* mech;
        std::thread* t;
        ~ArmerGuard() {
            mech->release_hang();
            if (t->joinable())
                t->join();
        }
    } armer_guard{f.mechanism, &armer};
    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds{5}));

    // Guardian now applies its rule. It derives the same spark key, dedups onto the raw
    // consumer's in-flight entry, and is handed a real subscription id. From Guardian's
    // side this is an ordinary, successful arm.
    f.apply(make_service_rule("r1"));
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.spark_engine.stats().subscriptions == 2); // raw + Guardian
    CHECK(f.spark_engine.stats().armed_sparks == 1);

    // Release: the raw consumer's watch throws, and arm_impl tears down the WHOLE key.
    f.mechanism->release_hang();
    armer.join();
    CHECK_FALSE(raw_sub.has_value()); // the raw consumer learns its arm failed

    // Nothing is armed and nothing is watched at the engine level…
    CHECK(f.spark_engine.stats().armed_sparks == 0);
    CHECK(f.spark_engine.stats().subscriptions == 0);
    CHECK(f.mechanism->watching_count() == 0);
    // …and Guardian is now told, asynchronously (the Lost notification crosses its own
    // "guardian-spark" consumer's dispatch thread), and detaches the rule as errored
    // rather than continuing to report it armed.
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 0; }));
    // No self-heal in this PR (Dave's call, 2026-09-06): the rule sits errored until the
    // next server-issued PushRules or an agent restart re-attaches it.
    // The legacy path does NOT pick the rule up either — this is not a silent fallback to
    // IGuard, it stays a genuine, honestly-reported detection hole until re-attached.
    CHECK(f.engine->armed_guard_count() == 0);

    // The lifecycle audit reflects WHY the rule stopped being enforced: "errored", not
    // "disarmed" (guardian_outbox.hpp's documented vocabulary) — Guardian didn't
    // withdraw the rule, its enforcement broke out from under it.
    REQUIRE(yuzu::test::spin_until([&] {
        std::lock_guard<std::mutex> lk{f.sent_mu};
        return std::any_of(f.sent.begin(), f.sent.end(), [](const OutboxEntry& e) {
            return e.rule_id == "r1" && e.lifecycle_kind == "errored";
        });
    }));
}

TEST_CASE("a supported type arms via spark, never in legacy guards_",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));

    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watching_count() == 1);
}

TEST_CASE("an unsupported type arms neither backend - a distinct terminal state, "
          "never a legacy fallback",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));

    // File has no mechanism registered in this fixture - a ROUTINE gap, terminal
    // per F7/#2298 rung 2: enforced by NEITHER backend (previously this test only
    // proved spark never claimed it and never checked armed_guard_count(), so it
    // passed identically under the old legacy-fallback behavior too).
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watching_count() == 0);
    const auto counts = f.engine->unsupported_counts_by_type();
    REQUIRE(counts.count(SparkType::File) == 1);
    CHECK(counts.at(SparkType::File) == 1);
}

TEST_CASE("repeating the same unsupported rule keeps the count at one",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    f.apply(make_file_rule("r1"), /*full_sync=*/false); // re-push, unchanged content
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1); // still 1, not 2
}

TEST_CASE("two unsupported rules of the same type aggregate to two",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    f.apply(make_file_rule("r2"), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 2);
}

TEST_CASE("an unsupported rule's type change moves the count between buckets, "
          "never double-counts",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // Same rule_id, spark type edited to a different (also-unsupported) type.
    // Registry has no mechanism registered in this fixture either.
    f.apply(make_registry_rule("r1"), /*full_sync=*/false);
    const auto counts = f.engine->unsupported_counts_by_type();
    CHECK(counts.count(SparkType::File) == 0);
    REQUIRE(counts.count(SparkType::Registry) == 1);
    CHECK(counts.at(SparkType::Registry) == 1);
}

TEST_CASE("unsupported -> Arm (mechanism becomes available) clears the count",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // Same rule_id, now a type WITH a mechanism registered in this fixture.
    f.apply(make_service_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
    CHECK(f.engine->spark_armed_rule_count() == 1);
}

TEST_CASE("unsupported -> disabled clears the count", "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    f.apply(make_file_rule("r1", /*enabled=*/false), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
}

TEST_CASE("unsupported -> invalid (unrecognized spark type) clears the count",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    f.apply(make_invalid_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
}

TEST_CASE("full_sync omitting a previously-unsupported rule clears its count",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // A full_sync naming only a DIFFERENT rule must forget r1's unsupported
    // bookkeeping too, exactly like it withdraws a spark-armed rule the new
    // push omits (see the sibling full_sync test below).
    f.apply(make_service_rule("r2"), /*full_sync=*/true);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
}

TEST_CASE("full_sync retaining a still-unsupported rule stays idempotent",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1")); // full_sync #1
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // A second full_sync retaining r1 unchanged: the count must stay exactly 1,
    // not double-count or drop it. NOTE what this does NOT verify: a blanket
    // unsupported_rules_.clear() before the per-rule loop (instead of the
    // precise post-loop sweep apply_rules actually uses) would make r1 look
    // "newly" unsupported and spuriously re-log on every full_sync, but it
    // converges to the SAME final count this asserts - the two designs are
    // indistinguishable by count alone. The log-edge-detection design (erase-
    // then-reinsert per outcome, sweep-not-blanket-clear on full_sync) is
    // verified by code inspection, not a runtime assertion here - this
    // codebase has no log-capture test seam to assert on spdlog output.
    f.apply(make_file_rule("r1"), /*full_sync=*/true);
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);
}

// Governance finding (quality-engineer, F7 #2298): the interaction between the new
// Unsupported branch and the pre-existing policy_generation hold-on-failure logic
// (apply_rules only advances policy_generation_ when reconcile_failures == 0) was
// previously asserted only in a code comment, never at runtime. An Unsupported
// classification returns false WITHOUT throwing, so it must never increment
// reconcile_failures and must never block generation advancement - holding the
// generation on an all-Unsupported push (e.g. every rule on macOS) would make that
// agent re-push forever.
TEST_CASE("an all-unsupported push still advances policy_generation, never holds it",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    REQUIRE(f.engine->policy_generation() == 0);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(5);
    *p.add_rules() = make_file_rule("r1"); // unsupported: no mechanism in this fixture
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);
    CHECK(f.engine->policy_generation() == 5); // advanced, not held
}

TEST_CASE("a production-order restart reconstructs unsupported_rules_ from cached KV",
          "[spark][guardian][reconcile][boot]") {
    // Mirrors "PRODUCTION boot order: wire_spark_engine before start_local" below -
    // unsupported_rules_ has no persisted representation of its own (it is derived
    // purely from re-running classify() against each cached rule during the
    // start_local() re-arm walk), so a restart must rebuild it correctly, in the
    // real wire-then-start_local order, not just the fixture's simplified order.
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};

    // Phase 1: persist a rule that is unsupported in THIS process, then go away.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine; // no mechanism registered - file-change is unsupported
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_file_rule("r1");
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        REQUIRE(engine.unsupported_counts_by_type().at(SparkType::File) == 1);
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: a fresh boot in PRODUCTION order (wire_spark_engine before start_local)
    // over that same store - no push this time, unsupported_rules_ must come back
    // purely from the start_local() re-arm walk over the cached rule.
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
    REQUIRE(engine.start_local().has_value());

    CHECK(engine.rule_count() == 1);
    CHECK(engine.spark_armed_rule_count() == 0);
    CHECK(engine.armed_guard_count() == 0);
    const auto counts = engine.unsupported_counts_by_type();
    REQUIRE(counts.count(SparkType::File) == 1);
    CHECK(counts.at(SparkType::File) == 1);

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("start_local degrades per-rule when a re-arm throws: the other cached rules "
          "still arm",
          "[spark][guardian][reconcile][boot]") {
    // #2238 item 1 (fixes BLOCKING-2a): guardian_engine.cpp's start_local() catches a
    // std::system_error thrown while re-arming a single cached rule (modelling a legacy
    // guard's std::thread ctor throwing under thread/handle exhaustion) and continues to
    // the next rule instead of letting the throw escape and terminate the agent. Nothing
    // in production can force that throw deterministically (see the handover's survey of
    // guard_systemd.cpp / guard_file.cpp / guard_registry.cpp), so this drives it via
    // set_rearm_fault_hook_for_test, aimed at exactly one rule by id, and proves: (a)
    // start_local() still returns success, (b) the OTHER cached rules still arm, and (c)
    // an error is logged naming the failed rule.
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};

    // Phase 1: seed three rules with distinct service names, all armable via spark.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        auto mech = std::make_unique<FakeServiceMechanism>();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_service_rule("r1", true, "SvcA");
        *p.add_rules() = make_service_rule("r2", true, "SvcB");
        *p.add_rules() = make_service_rule("r3", true, "SvcC");
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        // rung 9c PR-2 Unit 6: the arms are Accepted, not yet resolved, when dispatch
        // returns - settle before asserting the seeded state a later phase depends on.
        REQUIRE(yuzu::test::spin_until([&] { return engine.spark_armed_rule_count() == 3; }));
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: production order (wire_spark_engine before start_local), so spark is
    // Available during the re-arm walk and the un-poisoned rules can actually arm on
    // Linux (legacy guard start() stubs return false here - only the spark backend can
    // demonstrate "other rules still arm").
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    FakeServiceMechanism* mechanism = mech.get();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    engine.set_rearm_fault_hook_for_test([](const std::string& rule_id) {
        if (rule_id == "r2")
            throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again),
                                    "injected thread exhaustion");
    });

    REQUIRE(engine.start_local().has_value()); // degrade contract: success despite one poisoned rule

    // rung 9c PR-2 Unit 6: r1/r3's boot re-arms are Accepted, not yet resolved, when
    // start_local() returns - settle before asserting the degrade outcome.
    REQUIRE(yuzu::test::spin_until([&] { return engine.spark_armed_rule_count() == 2; }));

    // Assert BEFORE stop() - stop() unwinds spark watch state.
    CHECK(engine.rule_count() == 3);           // cache intact, including the poisoned rule
    CHECK(engine.spark_armed_rule_count() == 2); // r1 + r3 only
    const auto watched = mechanism->watched_snapshot();
    const bool has_a =
        std::any_of(watched.begin(), watched.end(), [](const std::string& k) { return k.find("SvcA") != std::string::npos; });
    const bool has_b =
        std::any_of(watched.begin(), watched.end(), [](const std::string& k) { return k.find("SvcB") != std::string::npos; });
    const bool has_c =
        std::any_of(watched.begin(), watched.end(), [](const std::string& k) { return k.find("SvcC") != std::string::npos; });
    CHECK(has_a);
    CHECK_FALSE(has_b); // the poisoned rule never armed
    CHECK(has_c);
    CHECK(mechanism->watching_count() == 2);

    // Read directly off the engine, not via spdlog: a captured-logger swap in the test
    // binary was found (macOS CI) to be invisible to spdlog:: calls made inside guardian_engine.cpp,
    // which is compiled into the separate libyuzu_agent_core shared library - the same class
    // of cross-image state-duplication problem as the #501 abseil hash-seed split. Plain
    // object-member state has no such hazard, hence last_rearm_degrade_message_for_test().
    // "re-armed=2" is deliberately not re-checked here - spark_armed_rule_count()==2 above
    // already proves the same fact more directly.
    const std::string degrade_msg = engine.last_rearm_degrade_message_for_test();
    CHECK(degrade_msg.find("r2") != std::string::npos);
    CHECK(degrade_msg.find("failed to re-arm") != std::string::npos);
    CHECK(degrade_msg.find("NOT enforcing") != std::string::npos);
    CHECK(degrade_msg.find("injected thread exhaustion") != std::string::npos);

    engine.set_rearm_fault_hook_for_test(nullptr);
    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=false never populates unsupported_rules_, even for a type "
          "with no mechanism",
          "[spark][guardian][reconcile]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine; // no mechanism registered - file-change would be
                              // unsupported IF spark were consulted at all
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // the production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_file_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    // try_spark is false unconditionally when prefer_spark_ is false - classify()
    // is never even called, so this can never be "Unsupported" (a per-rule spark
    // classification outcome), it goes straight to the legacy-selected path.
    CHECK(engine.unsupported_counts_by_type().empty());

    engine.stop();
    spark_engine.stop();
}

#if defined(__APPLE__)
TEST_CASE("macOS: every mechanism is unsupported under spark preference - the real "
          "platform posture, not a fixture artifact",
          "[spark][guardian][reconcile][darwin]") {
    // Built WITHOUT SparkReconcileFixture (which always injects a FakeServiceMechanism
    // regardless of platform) - the whole point here is to prove the REAL platform
    // factories, exactly as agent.cpp's production try_register does at boot, all
    // three of which return nullptr on macOS (design doc §R2 consequence 3 / #2298).
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};

    SparkEngine spark_engine;
    const auto try_register = [&](SparkType type, std::unique_ptr<ISparkMechanism> mech) {
        if (mech)
            REQUIRE(spark_engine.register_mechanism(type, std::move(mech)).has_value());
    };
    try_register(SparkType::File, make_file_mechanism());
    try_register(SparkType::Registry, make_registry_mechanism());
    try_register(SparkType::Service, make_service_mechanism());
    spark_engine.start(); // all three factories return nullptr on macOS, so nothing
                          // actually got registered above - that IS the thing under test

    GuardianEngine engine{&kv, "agent-test-macos", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_file_rule("f1");
    *p.add_rules() = make_service_rule("s1");
    *p.add_rules() = make_registry_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(engine.spark_armed_rule_count() == 0);
    CHECK(engine.armed_guard_count() == 0);
    const auto counts = engine.unsupported_counts_by_type();
    CHECK(counts.at(SparkType::File) == 1);
    CHECK(counts.at(SparkType::Registry) == 1);
    CHECK(counts.at(SparkType::Service) == 1);
    // No explicit stop() calls: engine/spark_engine are plain stack locals declared
    // spark_engine-then-engine, so scope-exit destroys engine first, spark_engine
    // second - the exact order SparkReconcileFixture's own dtor comment documents as
    // required (Guardian's spark teardown must finish before the SparkEngine it
    // borrowed from is torn down), for free via normal RAII reverse-order destruction.
}
#endif // defined(__APPLE__)

TEST_CASE("SparkDisabled never populates unsupported_rules_ either",
          "[spark][guardian][reconcile]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/true,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_file_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    // try_spark requires spark_availability_ == Available; SparkDisabled is not
    // Available regardless of prefer_spark_, so classify() is never reached here
    // either - the same code path as prefer_spark=false above.
    CHECK(engine.unsupported_counts_by_type().empty());

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("an invalid rule (unrecognized spark type) arms nowhere",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_invalid_rule("r1"));

    CHECK(f.engine->rule_count() == 1);       // still persisted
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0);
}

TEST_CASE("a spark arm failure is errored, NEVER a silent legacy fallback",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.mechanism->set_fail_next_watch();
    f.apply(make_service_rule("r1"));

    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0); // NOT armed via legacy either
    CHECK(f.engine->rule_count() == 1);        // still persisted (errored, not deleted)
}

TEST_CASE("disable withdraws from spark; re-enable re-arms via spark",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);

    f.apply(make_service_rule("r1", /*enabled=*/false), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.mechanism->watching_count() == 0);

    f.apply(make_service_rule("r1", /*enabled=*/true), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.mechanism->watching_count() == 1);
}

TEST_CASE("a same-id replace while spark-armed swaps generations, never double-arms",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);

    f.apply(make_service_rule("r1"), /*full_sync=*/false); // re-push, unchanged content
    CHECK(f.engine->spark_armed_rule_count() == 1); // still 1, not 2
}

TEST_CASE("a same-id replace from spark-armed to unsupported withdraws spark, "
          "lands in neither backend",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1")); // spark-armed (service mechanism registered)
    REQUIRE(f.engine->spark_armed_rule_count() == 1);
    REQUIRE(f.engine->armed_guard_count() == 0);

    // Same rule_id, now a type with no mechanism registered - F7/#2298 rung 2:
    // a distinct terminal state, enforced by NEITHER backend, with the prior
    // spark attachment fully withdrawn. (Previously this test's name/premise
    // said "must land ONLY in legacy" and its assertions passed vacuously -
    // neither checked armed_guard_count(), so "neither" and "legacy" were
    // indistinguishable to it.)
    f.apply(make_file_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0); // proves "neither", not "legacy"
    CHECK(f.mechanism->watching_count() == 0);
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);
}

TEST_CASE("a same-id replace from unsupported to spark-armed arms cleanly, no "
          "stale state",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1")); // unsupported (no mechanism for file-change);
                                   // this fixture is permanently prefer_spark_=true
                                   // + Available, so a file rule here can only ever
                                   // land Unsupported post-F7, never legacy-armed -
                                   // the scenario this test used to exercise no
                                   // longer occurs on this fixture.
    REQUIRE(f.engine->spark_armed_rule_count() == 0);
    REQUIRE(f.engine->armed_guard_count() == 0);
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // Same rule_id, now a spark-supported type - must land ONLY in spark, with
    // the prior unsupported bookkeeping cleared too.
    f.apply(make_service_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watching_count() == 1);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
}

TEST_CASE("full_sync withdraws a spark-armed rule the new push omits",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);

    // A full_sync naming only a DIFFERENT rule must withdraw r1's spark
    // attachment too, not just leave it dangling (Sol's rev-2 review).
    f.apply(make_service_rule("r2"), /*full_sync=*/true);
    CHECK(f.engine->rule_count() == 1);              // only r2 persisted; r1 is gone
    CHECK(f.engine->spark_armed_rule_count() == 1);  // still exactly 1 (r2), not 2
}

TEST_CASE("mutual exclusion holds across a full transition matrix (never both, "
          "exactly one for an armed rule)",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    auto unsupported_count = [&] {
        std::uint64_t n = 0;
        for (const auto& [type, c] : f.engine->unsupported_counts_by_type()) n += c;
        return n;
    };
    auto invariant_holds = [&] {
        // Never more than one of {legacy-armed, spark-armed, unsupported} (F7 adds
        // the third state to the pre-existing mutual-exclusion invariant). Aggregate
        // counts - per-rule cross-checking isn't exposed, but with exactly one
        // rule_id active at a time in this test the aggregate sum bounds it directly.
        return (f.engine->armed_guard_count() + f.engine->spark_armed_rule_count() +
                unsupported_count()) <= 1;
    };

    f.apply(make_service_rule("r1"));                                   // -> spark
    CHECK(invariant_holds());
    CHECK(f.engine->spark_armed_rule_count() == 1);

    f.apply(make_service_rule("r1", false), /*full_sync=*/false);       // -> disabled
    CHECK(invariant_holds());

    f.apply(make_invalid_rule("r1"), /*full_sync=*/false);              // -> invalid
    CHECK(invariant_holds());
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.engine->spark_armed_rule_count() == 0);

    f.mechanism->set_fail_next_watch();
    f.apply(make_service_rule("r1"), /*full_sync=*/false);              // -> arm-failure
    CHECK(invariant_holds());
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.engine->spark_armed_rule_count() == 0);

    f.apply(make_file_rule("r1"), /*full_sync=*/false);                 // -> unsupported (F7)
    CHECK(invariant_holds());
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(unsupported_count() == 1);

    f.apply(make_service_rule("r1"), /*full_sync=*/false);              // -> re-armed OK
    CHECK(invariant_holds());
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(unsupported_count() == 0);
}

TEST_CASE("wire_spark_engine reports Available; --spark-disable reports SparkDisabled; "
          "a failed boot reports SparkFailed",
          "[spark][guardian][reconcile]") {
    {
        SparkReconcileFixture f; // Available - proven by the fixture's own REQUIRE
        CHECK(f.engine->spark_availability() == GuardianEngine::SparkAvailability::Available);
    }
    {
        auto opened = KvStore::open(unique_kv_path());
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/true,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);
    }
    {
        auto opened = KvStore::open(unique_kv_path());
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/false, // boot failed
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkFailed);
    }
}

// ---------------------------------------------------------------------------
// rung 9c PR-3, Check A, governance fix (adversarial review CODEX-1/K1, both
// independently reproduced empirically before either reviewer saw the other's
// findings): the ORIGINAL shipped GuardianEngine::arm_stats() gated only on
// `prefer_spark_`, so a prefer_spark_=true agent whose Spark path is Unwired,
// SparkFailed, SparkDisabled, or stopped still emitted a false-present-healthy
// {0,0} pair - the exact inverted-Check-A trap this PR exists to prevent, one
// state further in than the original test above covered. These pin the fix:
// arm_stats() must return nullopt in EVERY one of these states, and remain
// present ONLY when prefer_spark_=true, not stopped, AND Available.
// ---------------------------------------------------------------------------

TEST_CASE("GuardianEngine::arm_stats(): prefer_spark_=true but Unwired (wire_spark_engine "
          "never called) stays ABSENT, not a false-present {0,0}",
          "[spark][guardian][arm_stats]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);

    // apply_rules() still opens an Application unconditionally (Check A's original
    // trap) even though Spark was never wired - the naive `current_ != nullptr` read
    // and the naive `prefer_spark_` read would BOTH wrongly call this "present".
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    REQUIRE(engine.apply_rules(p).has_value());
    CHECK_FALSE(engine.arm_stats().has_value());
}

TEST_CASE("GuardianEngine::arm_stats(): prefer_spark_=true but SparkFailed (boot failed) "
          "stays ABSENT",
          "[spark][guardian][arm_stats]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/false, // boot failed
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkFailed);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    REQUIRE(engine.apply_rules(p).has_value());
    CHECK_FALSE(engine.arm_stats().has_value());
}

TEST_CASE("GuardianEngine::arm_stats(): prefer_spark_=true but SparkDisabled "
          "(--spark-disable) stays ABSENT",
          "[spark][guardian][arm_stats]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/true,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    REQUIRE(engine.apply_rules(p).has_value());
    CHECK_FALSE(engine.arm_stats().has_value());
}

TEST_CASE("GuardianEngine::arm_stats(): a stopped engine stays ABSENT even though "
          "prefer_spark_ is immutable and stays true past stop()",
          "[spark][guardian][arm_stats]") {
    SparkReconcileFixture f; // Available - proven by the fixture's own REQUIRE
    f.apply(make_service_rule("r1"));
    REQUIRE(f.engine->arm_stats().has_value()); // present while genuinely live

    f.engine->stop();
    CHECK_FALSE(f.engine->arm_stats().has_value());
}

TEST_CASE("GuardianEngine::arm_stats(): prefer_spark_=true, Available, not stopped - a "
          "live application that has fully settled reads a REAL present {0, 0}, not "
          "absent - this is the healthy case Check A must not collapse into dormancy",
          "[spark][guardian][arm_stats]") {
    SparkReconcileFixture f; // Available - proven by the fixture's own REQUIRE
    f.apply(make_service_rule("r1")); // settles: waits for the drain to reach 0 pending
    const auto s = f.engine->arm_stats();
    REQUIRE(s.has_value());
    CHECK(s->pending == 0);
    CHECK(s->failed == 0);
}

TEST_CASE("GuardianEngine::arm_stats(): prefer_spark_=true, Available, not stopped, "
          "but start_local() never called - the ledger's OWN 'no current application' "
          "absence case, proven through the ENGINE's forwarding path, not just the "
          "ledger's own direct unit test (test_guardian_arm_ack.cpp)",
          "[spark][guardian][arm_stats]") {
    // Governance Gate 3 (quality-engineer) fix: the fourth, orthogonal absence
    // condition arm_stats()'s own doc comment calls out - "supplied by the ledger" -
    // was previously proven only at GuardianArmAckLedger::arm_stats()'s own call
    // site, never through GuardianEngine::arm_stats()'s forwarding.
    //
    // NOT SparkReconcileFixture: that fixture's constructor calls start_local()
    // (which unconditionally opens a boot-bookkeeping application, guardian_engine.cpp
    // ~line 503) BEFORE wire_spark_engine() - so by the time the fixture's own
    // constructor returns, ack_ledger_ already has a live application and this state
    // is unreachable through it. Uses the file's own documented PRODUCTION wire order
    // instead (wire_spark_engine() before start_local() - see "a production-order
    // restart..." above) and stops BEFORE calling start_local(), so ack_ledger_ has
    // never had begin_application() called on it at all.
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    CHECK_FALSE(engine.arm_stats().has_value());

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=false (the rung 7 production default) never attempts spark, "
          "even when Available",
          "[spark][guardian][reconcile]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    auto* mechanism = mech.get();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // the production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false, [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    // Serialize-then-dispatch, not apply_rules(p) directly - see the fixture's
    // apply() helper above for the #501 cross-image Map rationale. This
    // test's own assertions happen to pass either way (spark stays untouched
    // whether prefer_spark_ correctly gates it or the #501 bug invalidly
    // rejects the rule before that gate is even reached), but a wrong-reason
    // pass defeats the point of the test - fixed for correctness even though
    // it wasn't in DGRHP's failure list.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(engine.spark_armed_rule_count() == 0); // spark never even consulted
    CHECK(mechanism->watching_count() == 0);
    // Legacy DID attempt to arm (whether it succeeds depends on the platform's
    // real ServiceGuard/SystemdServiceGuard - not this test's concern; only
    // that spark was never touched).

    engine.stop();
    spark_engine.stop();
}

// ── Journal AGE gauges: dormancy is an ABSENCE (item 6 + #2364) ───────────────

TEST_CASE("journal_age_stats: present on a live prefer_spark worker, nullopt when dormant",
          "[spark][guardian][reconcile][journal]") {
    // prefer_spark=true + wired: the drain worker STARTED, its stamps are seeded, so the
    // age stats are PRESENT - including all-zero ages on a fresh worker (0 is a real
    // reading here; the emit layer ships the staleness pair including 0).
    {
        SparkReconcileFixture f;
        const auto ages = f.engine->journal_age_stats();
        REQUIRE(ages.has_value());
        // Fresh worker: ages in seconds must be tiny (the stamps were just seeded), and
        // no headroom episode exists.
        CHECK(ages->page_stale_seconds < 60);
        CHECK(ages->prune_stale_seconds < 60);
        CHECK(ages->headroom_blocked_seconds == 0);
        // COMPOSED with the real emitter (governance Gate 3 QE - the same
        // engine->emitter composition the counter family's aggregate-inertness test
        // pins): a live fresh worker ships EXACTLY the two staleness tags, including
        // their zero values, and no blocked tag.
        std::map<std::string, std::string> tags;
        yuzu::agent::emit_guardian_journal_age_tags(tags, ages);
        REQUIRE(tags.size() == 2);
        CHECK(tags.count("yuzu.guardian_journal_page_stale_seconds") == 1);
        CHECK(tags.count("yuzu.guardian_journal_prune_stale_seconds") == 1);
        CHECK(tags.count("yuzu.guardian_journal_headroom_blocked_seconds") == 0);
    }
    // prefer_spark=false + wired: the worker is CONSTRUCTED but never started (the flag
    // gates start()), and the ages must be ABSENT - not zero. This is the dormancy
    // posture that keeps a pre-flip fleet from paging on a "stale" inert journal: a
    // fabricated 0 would be wrong the other way (it claims a live fresh worker).
    {
        auto opened = KvStore::open(unique_kv_path());
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        auto mech = std::make_unique<FakeServiceMechanism>();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
        const auto ages = engine.journal_age_stats();
        CHECK_FALSE(ages.has_value());
        // Composed: nullopt through the real emitter ships NOTHING - the dormancy
        // contract at the exact seam agent.cpp uses.
        std::map<std::string, std::string> tags;
        yuzu::agent::emit_guardian_journal_age_tags(tags, ages);
        CHECK(tags.empty());
        engine.stop();
        spark_engine.stop();
    }
}

TEST_CASE("wire_spark_engine constructs the spark workers unconditionally but starts them "
          "ONLY under prefer_spark",
          "[spark][guardian][reconcile]") {
    // #2238 item 2 (fixes BLOCKING-2b): the convergence scheduler + drain worker are
    // CONSTRUCTED in wire_spark_engine() regardless of prefer_spark_, but only START()ed
    // under the flag (guardian_engine.cpp's `if (prefer_spark_) { ...->start(); ...
    // ->start(); }`). Reverting that gate to always-start fails no other existing test
    // (journal_age_stats() short-circuits on !prefer_spark_ before it would ever see a
    // started-but-dormant worker). This drives both classes' started_for_test() directly.
    {
        // prefer_spark=false + wired: both constructed, neither started.
        auto opened = KvStore::open(unique_kv_path());
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        auto mech = std::make_unique<FakeServiceMechanism>();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

        REQUIRE(engine.drain_worker_for_test() != nullptr);
        REQUIRE(engine.convergence_scheduler_for_test() != nullptr);
        CHECK_FALSE(engine.drain_worker_for_test()->started_for_test());
        CHECK_FALSE(engine.convergence_scheduler_for_test()->started_for_test());

        engine.stop();
        spark_engine.stop();
    }
    {
        // prefer_spark=true (SparkReconcileFixture): both constructed AND started.
        SparkReconcileFixture f;
        REQUIRE(f.engine->drain_worker_for_test() != nullptr);
        REQUIRE(f.engine->convergence_scheduler_for_test() != nullptr);
        CHECK(f.engine->drain_worker_for_test()->started_for_test());
        CHECK(f.engine->convergence_scheduler_for_test()->started_for_test());
    }
}

// ── Durable-journal persist boundary + inertness (item 7 PR-Ag C2) ───────────

TEST_CASE("prefer_spark=true: an armed rule's record is persisted to the durable journal",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1")); // arms via spark → stages "armed" → apply_rules flush persists

    // The journal namespace is distinct from the rule namespace and survives full_sync.
    auto rows = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty()); // a batch was durably written by the flush guard

    bool found_armed_r1 = false;
    for (const auto& row : *rows) {
        auto b = yuzu::agent::parse_journal_batch(row.value);
        REQUIRE(b.has_value());
        for (const auto& e : b->entries)
            if (e.rule_id == "r1" && e.kind == "armed")
                found_armed_r1 = true;
    }
    CHECK(found_armed_r1);
}

TEST_CASE("prefer_spark=true: journaled event_ids embed the real agent_id (#2237)",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f; // constructed with agent_id "agent-test"
    f.apply(make_service_rule("r1"));

    auto rows = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());

    bool found = false;
    for (const auto& row : *rows) {
        auto b = yuzu::agent::parse_journal_batch(row.value);
        REQUIRE(b.has_value());
        for (const auto& e : b->entries) {
            if (e.rule_id == "r1" && e.kind == "armed") {
                // make_event_id: "<agent_id>-<nonce>-<rule_id>-<wall_ms>-<seq>" - an
                // unwired provider (the pre-#2237 state) mints an empty-prefixed id
                // instead ("-<nonce>-r1-...").
                CHECK(e.event_id.starts_with("agent-test-"));
                found = true;
            }
        }
    }
    CHECK(found);
}

TEST_CASE("prefer_spark=false: no lifecycle record is journaled (inert)",
          "[spark][guardian][reconcile][journal]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    // Inert: persist_lifecycle_journal_locked is prefer_spark_-gated AND no spark staging
    // happened (the rule armed on the legacy backend). The maintenance tick is inert too.
    engine.journal_maintenance_tick();
    auto rows = kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    CHECK(rows->empty());

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=true: the maintenance tick retries a persist a write failure left pending",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f;
    f.engine->lifecycle_journal_for_test()->inject_write_failures_for_test(1);
    // rung 9c PR-2 Unit 6: apply_rules() no longer stages "armed" synchronously - the
    // arm is Accepted and resolves later on a detached worker, asynchronously and with
    // NO ordering guarantee relative to apply_rules() itself finishing its own exit
    // flush. A FAST backend (this fixture's fake mechanism has no artificial latency)
    // can commit and stage the record BEFORE dispatch_raw() even returns - a race an
    // earlier version of this test got backwards under TSan + full-suite load (it
    // assumed the exit flush ALWAYS predates staging, so the explicit tick below was
    // "the first real attempt" - false when the worker wins the race, which makes the
    // EXIT FLUSH the first attempt instead, consuming the injected failure earlier than
    // expected and leaving the explicit tick below to observe the record as durable
    // already). Force the ordering with a hang gate instead of assuming it: the watch()
    // stays parked across dispatch_raw()'s ENTIRE execution (including its exit flush),
    // so that flush is GUARANTEED to see nothing staged yet.
    f.mechanism->hang_next_watch();
    REQUIRE(f.dispatch_raw(make_service_rule("r1")).exit_code == 0);
    // dispatch_raw() has ALREADY returned here - its own exit flush already ran, and
    // the arm cannot possibly have committed yet (the worker has not even returned
    // from watch(), confirmed next) - so that flush provably saw nothing pending,
    // regardless of how it's scheduled relative to the worker.
    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(5)));
    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 1; }));

    // NOW pending_journal_ genuinely has something staged for the first time - this
    // tick is the FIRST real persist attempt, and the injected failure lands HERE, not
    // on the "retry" tick below.
    f.engine->journal_maintenance_tick();

    auto before = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(before.has_value());
    CHECK(before->empty()); // nothing durable yet - that first attempt failed

    f.engine->journal_maintenance_tick(); // NO new push/reconnect - the tick alone retries

    auto after = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(after.has_value());
    bool found = false;
    for (const auto& row : *after) {
        auto b = yuzu::agent::parse_journal_batch(row.value);
        REQUIRE(b.has_value());
        for (const auto& e : b->entries)
            if (e.rule_id == "r1" && e.kind == "armed")
                found = true;
    }
    CHECK(found); // BLOCKER-4: the failed write self-healed via the heartbeat tick
}

TEST_CASE("prefer_spark=true: stop() final-flushes records a write failure left pending",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f;
    f.engine->lifecycle_journal_for_test()->inject_write_failures_for_test(1);
    // Hang the watch so apply_rules()'s own exit flush is guaranteed to run before
    // anything is staged - see the sibling "maintenance tick retries" test just above
    // for why this determinism can't be assumed from timing alone.
    f.mechanism->hang_next_watch();
    REQUIRE(f.dispatch_raw(make_service_rule("r1")).exit_code == 0);
    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(5)));
    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 1; }));
    f.engine->journal_maintenance_tick(); // first real persist attempt - fails, stays pending
    CHECK(f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix)->empty());

    f.engine->stop(); // the final flush persists the leftover pending record

    auto rows = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    CHECK_FALSE(rows->empty()); // durable after stop's final flush
}

TEST_CASE("prefer_spark=true: page_journal kicks the drain worker into a paging pass",
          "[spark][guardian][reconcile][journal]") {
    // C0 (#2298 gate 1): page_journal no longer pages INLINE on the caller's (reconnect)
    // thread - it wakes the drain worker, which runs the pass. Same observable replay, minus
    // a full KvStore scan on the thread that has just re-established the stream.
    //
    // The worker's backstop is pinned to an hour BEFORE it is constructed, and the page
    // cadence defaults to 30 s, so within this test's window the ONLY thing that can cause a
    // paging pass is the kick. Without that pin the production 5 s backstop is already
    // ticking through fixture setup and could fire inside the assertion window, letting this
    // pass for the wrong reason (Gate 3 quality-engineer BLOCKING-1).
    SparkReconcileFixture f{/*periodic_bound_ms=*/3'600'000};
    auto* journal = f.engine->lifecycle_journal_for_test();

    // The worker forces one page on its first cycle (boot replay); wait that out first so the
    // assertion below is attributable solely to the kick.
    const auto deadline0 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (journal->pages() == 0 && std::chrono::steady_clock::now() < deadline0)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    REQUIRE(journal->pages() >= 1);

    const auto before = journal->pages();
    f.engine->page_journal();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (journal->pages() == before && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(journal->pages() > before); // only the kick could have caused this
}

TEST_CASE("prefer_spark=false: page_journal + tick are inert (no pass, journal untouched)",
          "[spark][guardian][reconcile][journal]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    // Seed the journal namespace with a batch that must be left untouched.
    const auto seed_key = yuzu::agent::journal_batch_key(1'700'000'000'000LL, "seed", 0);
    REQUIRE(kv.set(yuzu::agent::kJournalNamespace, seed_key,
                   R"({"v":4,"ts_ms":1700000000000,"entries":[{"rule_id":"r","generation":1,)"
                   R"("event_id":"e","enqueued_ns":1700000000000000000,"kind":"armed",)"
                   R"("guard_type":"file","rule_name":"n"}]})"));

    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });

    engine.page_journal();
    engine.journal_maintenance_tick();
    CHECK(engine.lifecycle_journal_for_test()->pages() == 0);            // no paging pass ran
    CHECK(kv.exists(yuzu::agent::kJournalNamespace, seed_key)); // seed untouched
    // A WELL-FORMED key on purpose: seeded with the retired pre-ts format this would
    // prove only "a row that prune would quarantine anyway is untouched", which is true
    // of a dormant journal for the wrong reason (governance Gate 3 architect/QE).

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=false: journal telemetry is all-zero (aggregate inertness)",
          "[spark][guardian][reconcile][journal]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });

    // Apply a rule + drive BOTH maintenance paths - none of it touches the journal.
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    engine.journal_maintenance_tick();
    engine.page_journal();

    // Every journal counter is zero, so the sparse emitter ships NO tags (design §7/§8).
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_guardian_journal_heartbeat_tags(tags, engine.journal_stats());
    CHECK(tags.empty());

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("journal_stats() surfaces evicted_unclassified from the engine's real journal",
          "[spark][guardian][reconcile][journal]") {
    // The one plumbing seam the fleet-tags sizeof static_assert cannot cover: the
    // GuardianEngine::journal_stats() assignment that copies the journal's counter into the
    // struct. Every other test reads the journal accessor or builds GuardianJournalStats
    // directly, so a dropped assignment there leaves them all green while the sparse emitter
    // ships field 0 -> the fleet gauge is permanently ABSENT, reading as "nothing to report".
    // This drives the engine's OWN journal to one unclassified eviction and asserts it arrives
    // through journal_stats(). Deleting the assignment turns this red (item 3, consult gap 1).
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    REQUIRE(spark_engine.register_mechanism(SparkType::Service,
                                            std::make_unique<FakeServiceMechanism>())
                .has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
    REQUIRE(engine.start_local().has_value());
    // Wiring the spark path is what constructs the lifecycle journal (prefer_spark=false only
    // gates the drain worker's start, not the journal), so journal_stats() has a real source.
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });

    auto* journal = engine.lifecycle_journal_for_test();
    REQUIRE(journal != nullptr);
    journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/0,
                                           /*max_bytes=*/std::numeric_limits<std::size_t>::max(),
                                           /*max_quarantine=*/100); // count cap 0 -> evict all
    const std::vector<std::shared_ptr<const yuzu::agent::JournalRecord>> pending{
        std::make_shared<const yuzu::agent::JournalRecord>(yuzu::agent::JournalRecord{
            .rule_id = "r1", .generation = 1, .event_id = "e1", .enqueued_ns = 1,
            .kind = "armed", .guard_type = "file", .rule_name = "n"})};
    REQUIRE(journal->persist(pending, nullptr, yuzu::agent::kJournalPersistUnbounded,
                             yuzu::agent::kJournalPersistUnbounded) == 1);
    // A correlated scan+read failure makes the single evicted batch land in unclassified. This
    // seam drives only the READ-FAILURE cause of unclassified; the shutdown-mid-pass and
    // throw-mid-classification causes are pinned at the component level in
    // test_guardian_lifecycle_journal.cpp. That is sufficient here because the plumbing line
    // under test (journal_stats()'s assignment) is cause-agnostic - it copies one atomic.
    journal->inject_prune_sent_scan_failures_for_test(1);
    journal->inject_prune_sent_read_failures_for_test(5);
    REQUIRE(journal->prune(0).evicted == 1);
    REQUIRE(journal->evicted_unclassified() == 1);

    CHECK(engine.journal_stats().evicted_unclassified == 1); // the assignment under test

    engine.stop();
    spark_engine.stop();
}

// ---------------------------------------------------------------------------
// Death test: the drain worker taking GuardianEngine::mtx_ must ABORT, not hang.
// ---------------------------------------------------------------------------
#ifndef _WIN32

TEST_CASE("a worker-thread mtx_ acquisition aborts the process (death test)",
          "[spark][guardian][reconcile][journal][death]") {
    // The invariant under test is the one that hangs a fleet: GuardianEngine::stop() holds
    // mtx_ across its whole body AND joins the drain worker inside it, so an mtx_ acquisition
    // on that worker deadlocks agent shutdown. WorkerHostileMutex is supposed to turn that
    // into a loud crash. Until now that abort was wired and its predicate was tested, but the
    // abort itself never executed - so this proves the actual failure mode, in a subprocess,
    // because a passing run necessarily kills the process it happens in.
    //
    // The hostile call used to be placed in the INJECTED SEND (an arbitrary std::function
    // supplied from agent.cpp) - but #2233 item 4 moved `send` onto GuardianOutboxSendExecutor's
    // detached worker (guardian_outbox_send_executor.hpp), which stop() does NOT join, so a
    // send taking mtx_ can no longer produce this deadlock and is no longer the exposure this
    // test needs. This drives the hostile call directly from a thread wearing
    // GuardianJoinedThreadRole instead - the same marker the REAL worker loop wears
    // (guardian_outbox_drain_worker.cpp) - which proves the abort mechanism itself independent
    // of which production call graph currently reaches the joined thread.
    if constexpr (!yuzu::agent::worker_mutex_guard_enabled()) {
        SUCCEED("WorkerHostileMutex is compiled out in this build; nothing to prove");
        return;
    }

    // fork() WITHOUT exec. Catch2 runs test cases sequentially and this one starts no threads
    // before forking - but an EARLIER case's detached executor worker can still be in its
    // exit tail here (its active_worker_count()==0 is the last self-observable point, not
    // OS-thread exit), and under TSan that makes the child die at its first thread start
    // (die_after_fork; seen 2 of 6 runs on rung 9c PR-1). Wait for quiescence first, loudly.
    // The child is short-lived and aborts; it never returns to the harness.
    REQUIRE(yuzu::test::wait_until_quiescent());
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);

    if (pid == 0) {
        // ---- child ----
        // Hand SIGABRT back to the default handler first. Catch2 installs its own fatal-signal
        // handler, which would intercept the abort, print a spurious "FAILED ... SIGABRT" from
        // the child into the parent's output, and make a PASSING run look like a failure.
        // With SIG_DFL the child dies silently and the parent observes the signal, which is
        // the whole assertion.
        ::signal(SIGABRT, SIG_DFL);

        auto opened = KvStore::open(unique_kv_path());
        if (!opened)
            ::_exit(90); // distinct codes so the parent can tell setup failure from no-abort
        KvStore kv{std::move(*opened)};

        // No SparkEngine/wire_spark_engine needed - the hostile call below is driven directly,
        // not through the drain worker's own call graph (see the comment above).
        GuardianEngine engine{&kv, "agent-death", /*prefer_spark=*/true};
        if (!engine.start_local())
            ::_exit(92);

        // A thread wearing the SAME marker the real drain worker's loop() wears, taking mtx_
        // via journal_stats() - must abort. GuardianJoinedThreadRole's ctor runs on entry to
        // the thread body, so this thread is "joined" for its entire lifetime, matching how
        // loop() wears it for the worker's entire lifetime (guardian_outbox_drain_worker.cpp).
        std::thread hostile([&engine] {
            yuzu::agent::GuardianJoinedThreadRole role_marker;
            (void)engine.journal_stats(); // takes mtx_ -> must abort
        });
        hostile.join(); // unreachable if the guard fires - the process aborts inside the thread

        // If the guard works we never get here - the process aborts. Give it a bounded window,
        // then report "no abort" with a distinct code.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        ::_exit(94);
    }

    // ---- parent ----
    // Poll rather than blocking in waitpid: if the guard has regressed, the child DEADLOCKS
    // (that being the bug) and a blocking wait would hang the whole suite instead of failing.
    int status = 0;
    bool reaped = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            reaped = true;
            break;
        }
        REQUIRE(r == 0); // -1 would be a wait error, not a still-running child
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!reaped) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        FAIL("child never exited: the worker took mtx_ and DEADLOCKED instead of aborting - "
             "exactly the fleet-wide shutdown hang WorkerHostileMutex exists to prevent");
    }

    INFO("child exit code (if it exited normally): " << (WIFEXITED(status) ? WEXITSTATUS(status)
                                                                          : -1));
    REQUIRE(WIFSIGNALED(status));            // died by signal, not a clean exit
    CHECK(WTERMSIG(status) == SIGABRT);      // and specifically via std::abort()
}

TEST_CASE("a GuardianIoExecutor::submit() completion callback taking mtx_ aborts the process "
          "(death test, rung 9c R5.1)",
          "[spark][guardian][reconcile][death]") {
    // The SECOND WorkerHostileMutex role (guardian_detached_worker_role.hpp): a detached
    // executor worker can never be joined and may outlive stop() or the F3 orphan grace,
    // so an mtx_ acquisition from its body or its completion callback is a
    // lock-vs-lifetime fault the tripwire must turn into a loud abort. Drives the hostile
    // call through the REAL dispatch form (submit() + on_complete on the worker), not a
    // hand-marked thread - the marker is applied by the executor's own worker lambda,
    // which is exactly the wiring under test. Mutation: revert abort_if_worker_thread()'s
    // predicate to the joined-thread role alone -> the child exits 94 (no abort).
    if constexpr (!yuzu::agent::worker_mutex_guard_enabled()) {
        SUCCEED("WorkerHostileMutex is compiled out in this build; nothing to prove");
        return;
    }

    // fork() WITHOUT exec, same posture as the case above. NOTE the enlarged suite: an
    // earlier case's detached executor worker can, in principle, still be alive at this
    // fork (every such case spins for active_worker_count()==0 before returning, which
    // bounds but does not prove it). Only the forking thread is duplicated, and the
    // child does nothing but open a KvStore, start an engine, spawn ONE worker and touch
    // mtx_, so a libc lock held by a stray thread at fork time is the residual risk;
    // an isolated child executable would remove it and is noted as the follow-up. Until
    // then, wait for thread quiescence (governance pass-3 qe-2/cp-1/cs-4) so the fork is
    // never taken with a stray worker alive - TSan kills such a child at its first thread.
    REQUIRE(yuzu::test::wait_until_quiescent());
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);

    if (pid == 0) {
        // ---- child ----
        ::signal(SIGABRT, SIG_DFL);

        auto opened = KvStore::open(unique_kv_path());
        if (!opened)
            ::_exit(90);
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-death-submit", /*prefer_spark=*/true};
        if (!engine.start_local())
            ::_exit(92);

        yuzu::agent::GuardianIoExecutor ex;
        const auto adm = ex.submit(yuzu::agent::IoClass::File, "death", [] { return 1; },
                                   [&engine](yuzu::agent::IoResult<int>&&) {
                                       (void)engine.journal_stats(); // takes mtx_ on the
                                                                     // detached worker -> abort
                                   });
        if (!adm)
            ::_exit(91); // admission refused: setup failure, not a verdict

        // If the guard works we never get here - the process aborts inside the worker.
        // Give it a bounded window, then report "no abort" with a distinct code.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        ::_exit(94);
    }

    // ---- parent ---- (poll, never block: a regressed guard leaves the child alive)
    int status = 0;
    bool reaped = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            reaped = true;
            break;
        }
        REQUIRE(r == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!reaped) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        FAIL("child never exited: the submit() worker took mtx_ and neither aborted nor "
             "returned - the lock-vs-lifetime wedge WorkerHostileMutex's second role exists "
             "to prevent");
    }

    INFO("child exit code (if it exited normally): " << (WIFEXITED(status) ? WEXITSTATUS(status)
                                                                          : -1));
    REQUIRE(WIFSIGNALED(status));            // died by signal, not a clean exit (94 = no abort)
    CHECK(WTERMSIG(status) == SIGABRT);      // and specifically via std::abort()
}

#endif // !_WIN32

TEST_CASE("PRODUCTION boot order: wire_spark_engine before start_local",
          "[spark][guardian][reconcile][journal][boot]") {
    // Every other test here (and SparkReconcileFixture itself) calls start_local() BEFORE
    // wire_spark_engine(). Production does the reverse - agent.cpp:969-1001 wires first and
    // documents it as a header contract - so the order that actually ships was untested
    // (#2298 Sol review).
    //
    // It matters because of C0: wire_spark_engine() start()s the drain worker, whose first
    // cycle runs IMMEDIATELY and does journal maintenance against the KvStore. start_local()
    // then loads cached rules and re-arms them from the SAME single-mutex KvStore. If that
    // contention delayed or broke the pre-network re-arm, it would mean enforcement gaps at
    // boot on every endpoint after the prefer_spark flip.
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};

    // Phase 1: an engine that persists cached rules AND a durable journal, then goes away.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        REQUIRE(spark_engine.register_mechanism(SparkType::Service,
                                                std::make_unique<FakeServiceMechanism>())
                    .has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Retain; });
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        // Distinct service names: the "Spooler" default collapses all five rules
        // onto ONE spark key, and phase 2 needs to prove five DISTINCT re-watches
        // survived the restart, not merely that some watch reappeared (#2298 F13).
        for (int i = 0; i < 5; ++i)
            *p.add_rules() = make_service_rule("r" + std::to_string(i), true,
                                               "Svc" + std::to_string(i));
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        // rung 9c PR-2 Unit 6: the arms are Accepted, not yet resolved, when dispatch
        // returns - settle (each tick also retries any pending journal persist, so
        // this doubles as "force the pending records durable" once armed). Generous
        // bound: 5 rules each dispatch to a detached worker thread, and under the FULL
        // agent suite's accumulated thread/scheduling load (thousands of prior test
        // cases) the default 5s spin_until bound was observed to be too tight for this
        // one - not a logic race (isolated and [spark][guardian]-only runs never miss).
        REQUIRE(yuzu::test::spin_until(
            [&] {
                engine.journal_maintenance_tick();
                return engine.spark_armed_rule_count() == 5; // armed via spark BEFORE the restart
            },
            std::chrono::seconds(30)));
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: a fresh boot in PRODUCTION order over that same store.
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};

    // The durable journal must SURVIVE the restart (#2298 F13 goal 2). Read it from
    // raw KV BEFORE constructing anything else: the phase-2 drain worker's first
    // maintenance cycle pages/prunes immediately on wire, so reading after any
    // engine exists would race that cycle instead of proving pre-restart durability.
    {
        auto surviving =
            kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
        REQUIRE(surviving.has_value());
        REQUIRE_FALSE(surviving->empty());
        bool survived_armed_r0 = false;
        for (const auto& row : *surviving) {
            auto b = yuzu::agent::parse_journal_batch(row.value);
            REQUIRE(b.has_value());
            for (const auto& e : b->entries)
                if (e.rule_id == "r0" && e.kind == "armed") survived_armed_r0 = true;
        }
        CHECK(survived_armed_r0);
    }

    SparkEngine spark_engine;
    auto mech2 = std::make_unique<FakeServiceMechanism>();
    auto* mechanism2 = mech2.get(); // borrowed; owned by spark_engine
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech2)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    // WIRE FIRST - the worker starts here and immediately begins journal maintenance.
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    // Spark machinery is running in the exact production window (post-wire,
    // pre-start_local) - the direct observable that re-arm below runs against a
    // LIVE spark backend, not one still spinning up.
    REQUIRE(engine.drain_worker_for_test() != nullptr);
    REQUIRE(engine.convergence_scheduler_for_test() != nullptr);
    CHECK(engine.drain_worker_for_test()->started_for_test());
    CHECK(engine.convergence_scheduler_for_test()->started_for_test());

    // ...and only THEN the pre-network re-arm, racing that maintenance on one KvStore.
    const auto start = std::chrono::steady_clock::now();
    REQUIRE(engine.start_local().has_value());
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // The re-arm must not have been starved by the boot maintenance scan. The KvStore busy
    // timeout is 5 s, so anything approaching it means the two are serialising badly.
    CHECK(elapsed < std::chrono::seconds(2));
    CHECK(engine.rule_count() == 5); // every cached rule came back

    // And the journal side still did its work rather than being crowded out.
    auto* journal = engine.lifecycle_journal_for_test();
    REQUIRE(journal != nullptr);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (journal->pages() == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(journal->pages() >= 1);

    // The core F13 gap: rule_count() only proves the rules were RE-DISCOVERED. Prove
    // they RE-ARMED VIA SPARK - mutual exclusion held, and each of the five distinct
    // services is actually re-watched by the (new, phase-2) mechanism.
    //
    // rung 9c PR-2 Unit 6: start_local()'s boot re-arm is Accepted, not yet resolved,
    // when it returns - settle (generous bound, see the Phase 1 seeding block's own
    // comment on this same class of full-agent-suite load sensitivity).
    REQUIRE(yuzu::test::spin_until([&] { return engine.spark_armed_rule_count() == 5; },
                                   std::chrono::seconds(30)));
    CHECK(engine.spark_armed_rule_count() == 5);
    CHECK(engine.armed_guard_count() == 0);
    CHECK(engine.unsupported_counts_by_type().empty());
    const auto watched = mechanism2->watched_snapshot();
    CHECK(mechanism2->watching_count() == 5);
    for (int i = 0; i < 5; ++i) {
        const std::string svc = "Svc" + std::to_string(i);
        CHECK(std::any_of(watched.begin(), watched.end(),
                          [&](const std::string& key) { return key.find(svc) != std::string::npos; }));
    }
    CHECK(std::string_view{yuzu::agent::guardian_backend_label(yuzu::agent::guardian_backend_from_state(
              /*prefer_spark=*/true, engine.spark_availability()))} == "spark");

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("source tripwire: Agent::run() calls guardian start_local() before opening "
          "the Subscribe stream (#2233 item 1, the pre-network property)",
          "[spark][guardian][reconcile][boot][source_tripwire]") {
    // The PRODUCTION boot order test above proves WHAT start_local() does with a
    // non-empty cached policy in the real production CALL order (wire_spark_engine then
    // start_local) - #2233 item 1's checklist wording verbatim ("test a non-empty
    // cached KV policy armed during pre-network startup"). What it cannot prove is WHEN
    // Agent::run() calls start_local() relative to the network-dependent Subscribe
    // stream: that ordering lives in agent.cpp, and this repo has no Agent-level test
    // harness (a mocked gRPC stub/channel) to exercise it behaviourally. This closes
    // the "pre-network" half as a textual ordering guarantee instead: if a future edit
    // moves start_local() to after the Subscribe stream opens, this fails loudly rather
    // than silently reopening the boot-ordering defect #2233 originally found.
    std::ifstream input(std::filesystem::path(YUZU_AGENT_SRC_DIR) / "agent.cpp");
    REQUIRE(input.is_open());
    const std::string source((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());

    const auto start_local_pos = source.find("guardian_->start_local()");
    REQUIRE(start_local_pos != std::string::npos);
    const auto subscribe_pos = source.find("stub->Subscribe(&sub_ctx)");
    REQUIRE(subscribe_pos != std::string::npos);
    CHECK(start_local_pos < subscribe_pos);
}

TEST_CASE("source tripwire: the legacy file-hash-equals arm path applies the #2233 "
          "item 6 ceiling",
          "[guardian][source_tripwire]") {
    // clamp_max_hash_bytes itself is directly unit-tested (test_guardian_rule_eval.cpp)
    // and the spark path's use of it is proven end to end
    // (test_guardian_spark_bridge.cpp's rule_assertion_from_rule tests). GuardianEngine's
    // legacy file-hash-equals parsing lives in a private member function
    // (start_guard_for_rule_locked) with no existing test seam to observe the resulting
    // FileGuard::Config::max_hash_bytes directly - this pins that the legacy call site
    // actually routes through the SAME shared function, rather than trusting the two
    // paths not to drift apart silently.
    std::ifstream input(std::filesystem::path(YUZU_AGENT_SRC_DIR) / "guardian_engine.cpp");
    REQUIRE(input.is_open());
    const std::string source((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());
    CHECK(source.find("clamp_max_hash_bytes(fcfg.max_hash_bytes)") != std::string::npos);
}

TEST_CASE("a production-order restart into each degraded spark posture: cached rules "
          "survive but spark NEVER half-arms",
          "[spark][guardian][reconcile][boot]") {
    // #2298 F13. The Available posture across a restart is covered above ("PRODUCTION
    // boot order") and by "start_local degrades per-rule when a re-arm throws" (partial
    // re-arm). This covers the other three SparkAvailability postures - SparkDisabled,
    // SparkFailed, and BOTH shapes of Unwired - proving each is not just reported
    // correctly on a single boot (see "wire_spark_engine reports Available; ..." above)
    // but survives a restart with the mutual-exclusion invariant intact: a degraded
    // posture NEVER silently falls back to legacy, and it never half-arms on spark
    // either.
    //
    // Every leg re-checks spark_availability() AFTER start_local() too, not just after
    // wire - stop()/start_local() never write spark_availability_, so pinning it twice
    // is what "correct ACROSS a restart" means literally, not just "correct at wire time".
    const auto seed_armed_rules = [](const fs::path& kv_path) {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        REQUIRE(spark_engine.register_mechanism(SparkType::Service,
                                                std::make_unique<FakeServiceMechanism>())
                    .has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_service_rule("r1", true, "SvcA");
        *p.add_rules() = make_service_rule("r2", true, "SvcB");
        *p.add_rules() = make_service_rule("r3", true, "SvcC");
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        // rung 9c PR-2 Unit 6: the arms are Accepted, not yet resolved, when dispatch
        // returns - settle before asserting the seeded state a later phase depends on.
        REQUIRE(yuzu::test::spin_until(
            [&] { return engine.spark_armed_rule_count() == 3; })); // armed BEFORE the restart
        engine.stop();
        spark_engine.stop();
    };

    { // SparkDisabled: --spark-disable at boot. Legacy is the CORRECT path here, not a
      // fallback (guardian_engine.hpp's SparkDisabled doc), so armed_guard_count() is
      // deliberately NOT asserted - Linux's legacy guard start() stubs return false
      // regardless of correctness (the same trap documented at lines ~511 and
      // ~889-891, in different test contexts), so the only portable assertion is
      // that spark itself was never touched.
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/true,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);
        REQUIRE(engine.start_local().has_value());

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);
        CHECK(engine.rule_count() == 3); // cache intact
        CHECK(engine.spark_armed_rule_count() == 0);
        CHECK(engine.unsupported_counts_by_type().empty()); // legacy-selected, not Unsupported
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr); // wire returns before construction
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "legacy");
        engine.stop();
    }

    { // SparkFailed (null-engine path): the boot machinery itself failed to construct.
      // Errored, NEVER a silent fallback to legacy - the reconcile mutual-exclusion
      // guard withdraws from BOTH backends.
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/false, // boot failed
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkFailed);
        REQUIRE(engine.start_local().has_value());

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkFailed);
        CHECK(engine.rule_count() == 3); // cache intact
        CHECK(engine.spark_armed_rule_count() == 0);
        // 0 today because reconcile_rule_locked's mutual-exclusion guard withdraws
        // BEFORE ever calling start_guard_for_rule_locked - never a legacy fallback,
        // and that holds on any host. Whether a HYPOTHETICAL regression here (the
        // guard deleted) would still be caught is host-dependent, though: it hinges
        // on whether SystemdServiceGuard::start() (the class make_service_guard
        // dispatches to on Linux) can reach a system bus. Where it can (a live
        // dbus.service - true on this box: the SparkDisabled leg's own log shows
        // real "watching unit" entries, not "system bus unavailable"), a deleted
        // guard would arm for real and armed_guard_count() would go nonzero,
        // catching the regression. On a D-Bus-less CI sandbox, start() fails
        // regardless of the guard's correctness (the SparkDisabled leg's own
        // documented trap), and a deleted guard would stay silently masked. This
        // assertion is deterministic proof against TODAY's code on any host; its
        // power to catch a future regression varies by host D-Bus reachability.
        CHECK(engine.armed_guard_count() == 0);
        CHECK(engine.unsupported_counts_by_type().empty());
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr); // null-engine branch returns first
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "spark_failed");
        // Phase 1 DID wire spark (seed_armed_rules), so a durable journal was written -
        // but this leg's phase-2 engine never constructs its own lifecycle_journal_ (the
        // null-engine branch returns first, see the CHECK above), so there is nothing to
        // page here. The raw-KV durability-survives-restart assertion lives in the
        // extended "PRODUCTION boot order" test above.
        engine.stop();
    }

    { // Unwired shape (a): never wired at all - the reconcile walk RUNS (rule_count()
      // loads from cache) but the mutual-exclusion guard withdraws every rule from both
      // backends, because SparkFailed/Unwired are NEVER a fallback path.
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);
        REQUIRE(engine.start_local().has_value());

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);
        CHECK(engine.rule_count() == 3); // the walk ran and loaded the cache
        CHECK(engine.spark_armed_rule_count() == 0);
        CHECK(engine.armed_guard_count() == 0); // see the SparkFailed leg's comment above -
                                                 // same mutual-exclusion-guard-vs-D-Bus-stub caveat
        CHECK(engine.unsupported_counts_by_type().empty());
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr);
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "unwired");
        engine.stop();
    }

    { // Unwired shape (b): the SIGTERM-beats-boot race - stop() lands before
      // wire_spark_engine(), which is sticky and no-ops. A real concurrent stop() would
      // simply block on the same mutex until start_local()'s walk finished, so a
      // sequential stop() before wire reproduces the race's only observable effect
      // faithfully (see stopped_'s two guard sites in guardian_engine.cpp).
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine; // a healthy engine, offered but never touched
        auto mech = std::make_unique<FakeServiceMechanism>();
        auto* mechanism = mech.get();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};

        engine.stop(); // SIGTERM beat boot; sets the sticky stopped_ flag
        engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        // no-oped
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);

        REQUIRE(engine.start_local().has_value()); // sticky-stop early return: SUCCESS, not an error

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);
        CHECK(engine.rule_count() == 0); // the walk never ran - refresh_count_locked() never fired
        CHECK(engine.spark_armed_rule_count() == 0);
        CHECK(engine.armed_guard_count() == 0);
        CHECK(engine.unsupported_counts_by_type().empty());
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr);
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(mechanism->watching_count() == 0); // offered, but the sticky stop kept it untouched
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "unwired");
        spark_engine.stop();
    }
}

TEST_CASE("prefer_spark=true: pending records are durable BEFORE stop() joins the drain worker",
          "[spark][guardian][reconcile][journal][chaos]") {
    // stop() joins the drain worker. Before #2233 item 4, that join was an unbounded blocking
    // wait on whatever thread the injected send happened to be running on; since item 4
    // (guardian_outbox_send_executor.hpp) the worker's own wait on a stalled send is bounded to
    // kGuardianSendOfferWait, so the join this test parks against is now bounded too - but a
    // bound is not zero, and a persist placed only AFTER the join still never runs if a
    // supervisor's stop timeout or an operator kill lands in that (now much shorter) window,
    // destroying the staged records - real loss of an audit record, not the at-least-once
    // redelivery the design guarantees. The property under test - persist-before-join, not
    // persist-only-after - is unchanged by item 4; only how long "still blocked" stays
    // observable changed (bounded ~200ms now, not indefinite).
    //
    // The observable has to be taken WHILE the join is still blocked; asserting after stop()
    // returns cannot tell the two orderings apart, because the post-join flush persists the
    // same record either way. RED with the pre-join persist removed: the journal is still
    // empty on disk at the moment the join is stuck.
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};

    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    FakeServiceMechanism* mechanism = mech.get(); // borrowed; owned by spark_engine
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();

    std::mutex send_mu;
    std::condition_variable send_cv;
    bool in_send = false;   ///< the worker is parked inside a send
    bool release = false;   ///< test lets it finish
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [&](const OutboxEntry&) {
                                 std::unique_lock<std::mutex> lk{send_mu};
                                 in_send = true;
                                 send_cv.notify_all();
                                 send_cv.wait(lk, [&] { return release; });
                                 return SendResult::Sent;
                             });

    // A fatal assertion at the wait boundary can unwind while the worker is racing into
    // the parked callback. Declared after engine so this releases the worker before
    // ~GuardianEngine joins it, while send_mu/send_cv/release are still alive.
    struct ReleaseParkedWorker {
        std::mutex& mu;
        std::condition_variable& cv;
        bool& release_flag;
        ~ReleaseParkedWorker() {
            {
                std::lock_guard<std::mutex> lk{mu};
                release_flag = true;
            }
            cv.notify_all();
        }
    } release_parked_worker{send_mu, send_cv, release};

    // rung 9c PR-2 Unit 6: no injected write failure needed any more (this test
    // pre-dates the cutover, where one was required - see below). apply_rules() no
    // longer stages "armed" synchronously: it returns as soon as the arm is
    // Accepted - but the detached worker's commit can still land BEFORE apply_
    // rules()'s own exit flush runs (a FAST fake backend can outrace the calling
    // thread; earlier revisions of this test assumed otherwise and were flaky
    // under TSan + full-suite load, sometimes finding the record already durable
    // right after dispatch). Hang the watch to force the ordering instead of
    // assuming it: apply_rules() returns immediately regardless (Unit 6's whole
    // point), so the exit flush runs and is provably a no-op while the worker is
    // still parked, well before it can commit or stage anything.
    mechanism->hang_next_watch();
    gpb::GuaranteedStatePush push;
    push.set_full_sync(true);
    *push.add_rules() = make_service_rule("r1");
    // Serialize-then-dispatch because the rule carries a protobuf Map; see the fixture's
    // apply() helper above for the Windows EXE/DLL abseil hash-seed boundary.
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, push.SerializeAsString())
                .exit_code == 0);
    REQUIRE(mechanism->wait_entered_hang(std::chrono::seconds(5)));
    REQUIRE(kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix)->empty());
    mechanism->release_hang();

    {   // Park the worker inside a send, so the join below cannot complete.
        // Generous deadline: on a saturated Windows CI runner the drain worker can
        // be starved well past its ~5 s periodic backstop before it reaches the
        // send callback (box-contention flake, not a logic bug - see the WeeTam
        // agent-suite timeouts). The deadline is NOT shrunk by pinning the
        // backstop cadence: a short backstop would let the worker persist the
        // pending record on its own timer BEFORE the stop()-path persist, which
        // would defeat this test's whole attribution. If the worker still misses
        // this window, ReleaseParkedWorker above makes the failure exit cleanly.
        std::unique_lock<std::mutex> lk{send_mu};
        REQUIRE(send_cv.wait_for(lk, std::chrono::seconds(30), [&] { return in_send; }));
    }

    std::atomic<bool> stop_returned{false};
    std::thread stopper{[&] {
        engine.stop();
        stop_returned.store(true, std::memory_order_release);
    }};

    // The assertion: the record reaches disk while stop() is still stuck in the join.
    bool durable_during_join = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        auto rows = kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
        if (rows.has_value() && !rows->empty()) {
            // Confirm the join really is still outstanding, so this cannot pass by observing
            // the POST-join flush of a stop() that had already returned.
            durable_during_join = !stop_returned.load(std::memory_order_acquire);
            break;
        }
        if (stop_returned.load(std::memory_order_acquire))
            break; // stop() finished with nothing on disk: the pre-join persist did not happen
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(durable_during_join);

    {
        std::lock_guard<std::mutex> lk{send_mu};
        release = true;
    }
    send_cv.notify_all();
    stopper.join();
    spark_engine.stop();
}

TEST_CASE("start-drain-then-stop: the this-capturing send races stop()'s join (TSan "
          "checkpoint)",
          "[spark][guardian][reconcile][drain][tsan]") {
    // #2238 item 3: no test started the drain worker with a REAL this-capturing send and
    // raced a stop()/teardown against an in-flight send. The literal production callback
    // (AgentImpl::send_guardian_outbox_entry, agent.cpp) is unlinkable from unit tests -
    // AgentImpl is file-local to agent.cpp with zero test references - so this drives the
    // fixture-level this-capturing send instead: SparkReconcileFixture's send lambda
    // captures `this` and writes through a mutex-guarded vector, the same shape as
    // production's stream_write_mu_-guarded write (agent.cpp's send_guardian_outbox_entry).
    // Licensed by the drain contract (guardian_outbox_drain_worker.hpp): send MAY capture
    // `this` because stop() always synchronously joins the worker before the callback's
    // captures can dangle.
    //
    // Asserts liveness only - no timing upper bound, no exact send count (standing flake
    // doctrine; see the drain-worker file's jitter-race test). This exists so nightly TSan
    // actually DRIVES the start-drain-then-stop race, "safe by inspection" being the same
    // posture the drain-worker file's own [tsan] checkpoints take for worker-vs-reader and
    // worker-vs-persister races.
    SparkReconcileFixture f{/*periodic_bound_ms=*/1};

    // Two independent dispatch threads contend against the live drain worker + 4
    // convergence-scheduler lanes. The pusher thread must NOT use Catch2 assertion
    // macros (REQUIRE/CHECK) - those are main-thread-only - so it records raw exit codes
    // for the main thread to assert after joining it.
    std::mutex pusher_mu;
    std::vector<int> pusher_exit_codes;
    std::thread pusher{[&] {
        for (int i = 0; i < 6; ++i) {
            gpb::GuaranteedStatePush p;
            p.set_full_sync(false);
            *p.add_rules() = make_service_rule("p" + std::to_string(i), true,
                                               "SvcP" + std::to_string(i));
            auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine,
                                                                         p.SerializeAsString());
            std::lock_guard<std::mutex> lk{pusher_mu};
            pusher_exit_codes.push_back(dr.exit_code);
        }
    }};
    // A fatal assertion in the main-thread loop below (f.apply()'s REQUIRE) can unwind
    // while pusher is still running. Join on scope exit so an unwind cannot destroy a
    // joinable std::thread (std::terminate) and mask the real assertion failure behind
    // a raw abort - same shape as ReleaseParkedWorker earlier in this file.
    struct JoinOnExit {
        std::thread& t;
        ~JoinOnExit() {
            if (t.joinable())
                t.join();
        }
    } join_pusher_on_exit{pusher};
    for (int i = 0; i < 6; ++i)
        f.apply(make_service_rule("m" + std::to_string(i), true, "SvcM" + std::to_string(i)),
                /*full_sync=*/false);

    // Test-side lifetime only: the pusher thread dereferences f.engine, so it must finish
    // before anything tears that down - not a production ordering constraint. Redundant
    // with JoinOnExit's destructor on the non-throwing path (join() on an already-joined
    // thread throws std::system_error, but joinable() is false by then, so the guard's
    // join is skipped).
    pusher.join();
    {
        std::lock_guard<std::mutex> lk{pusher_mu};
        for (int code : pusher_exit_codes)
            CHECK(code == 0);
    }

    REQUIRE(yuzu::test::spin_until([&] {
        std::lock_guard<std::mutex> lk{f.sent_mu};
        return !f.sent.empty();
    }));

    // Immediately tear down while sends may be in flight: ~GuardianEngine's stop() holds
    // mtx_ across scheduler stop + the drain worker's join, racing whatever send is
    // mid-callback right now. This is the race under test.
    f.engine.reset();

    std::lock_guard<std::mutex> lk{f.sent_mu};
    CHECK(!f.sent.empty());
    for (const auto& e : f.sent)
        CHECK(!e.event_id.empty());
}

// ---------------------------------------------------------------------------
// #2233 item 3 - arm/disarm liveness. The first case below ("S+") proves
// ShutdownDeadlineGuard fires while a REAL GuardianEngine::stop() is genuinely
// blocked (the confirmed #2233 hazard - the same lock chain
// GuardianEngine::apply_rules -> GuardianSparkRuntime::attach_rule ->
// SparkEngine::arm_impl -> a mechanism's watch()). Its watchdog action is an
// injected recorder, never the real hard_exit() - proving the watchdog FIRES
// under a real wedge, not that it terminates the test process. The real
// hard_exit() / production exit-code path is proven separately, in a
// subprocess, by test_shutdown_deadline_guard.cpp's own death test.
//
// The three cases after it are CHARACTERISATION, not a regression test for a
// fix: they assert CURRENT behaviour (a hung backend watch()/unwatch() wedges
// mtx_-holding operations, including stop() and an unrelated concurrent push)
// as the evidence backing #2233 item 3, ahead of any liveness fix. A future
// fix PR inverts case A into a strong regression assertion (stop() returns
// within N s WHILE watch() is still parked) rather than reusing this file's
// wedge-asserting form verbatim.
//
// FakeServiceMechanism's watch()/unwatch() are structurally identical to every
// other SparkType's call sites (SparkEngine::arm_impl/disarm key off
// mech_ops_mu_by_type_.at(spec.type) and backend_->arm(spec) generically) - the
// proof that a hang here wedges Guardian is not specific to Service. The
// "real watch() can actually hang this long" premise is File's own documented
// contract (spark_file.cpp's arm_ancestor: a hung fs::is_directory probe on a
// dead UNC path holds the mechanism lock for the full OS network timeout) -
// this fixture only has a Service mechanism registered, so Service carries the
// injected hang; the wedge shape downstream of the mechanism call is identical
// either way.
//
// Two Catch2 constraints threaded through the characterisation cases:
//   - No REQUIRE/CHECK off the main thread (see the "pusher" test above this
//     one for the established idiom) - a pusher/stopper thread stashes a raw
//     result in an atomic; the main thread asserts after join().
//   - During the parked window the main thread may only read atomics/gate
//     state - every GuardianEngine accessor (rule_count(),
//     spark_armed_rule_count(), ...) takes mtx_ and would wedge alongside the
//     parked thread.
// ---------------------------------------------------------------------------

TEST_CASE("rung 9c PR-2 Unit 6: ShutdownDeadlineGuard stays quiet - stop() is no longer "
          "blocked by a hung watch()",
          "[spark][guardian][reconcile][shutdown_deadline_guard]") {
    // Supersedes "#2233 item 3 (S+): the watchdog fires while GuardianEngine::stop() is
    // genuinely blocked" (this test's name and premise, pre rung 9c PR-2 Unit 6). That
    // wedge was apply_rules() (the push thread) holding mtx_ synchronously inside
    // attach_rule()'s blocking wait, so stop() (needing mtx_ too) queued behind it long
    // enough for a 200ms watchdog to fire. Unit 6's non-waiting cutover means
    // apply_rules() returns as soon as the arm is ACCEPTED - stop() is never blocked on
    // a hung watch() any more, so the watchdog it exists to catch here never has
    // anything to catch. ShutdownDeadlineGuard's own fire-on-deadline behavior is
    // independently covered against a synthetic seam in test_shutdown_deadline_guard.cpp
    // ("an un-cancelled guard fires the action exactly once after the grace period") -
    // this test only needs to prove the REAL wedge it used to catch here is gone, not
    // re-prove the guard fires at all.
    SparkReconcileFixture f;
    f.mechanism->hang_next_watch();

    std::atomic<int> push_exit_code{-1};
    std::atomic<bool> push_done{false};
    // watchdog_fired is declared here, BEFORE Cleanup, so it outlives every thread that
    // could reference it - same reverse-declaration-order reasoning as Cleanup's own
    // members below.
    auto watchdog_fired = std::make_shared<std::atomic<bool>>(false);
    std::atomic<bool> stop_returned{false};

    // Cleanup OWNS both worker threads as members (never a pointer to a separately-
    // declared local): on ANY unwind (a fatal REQUIRE below), the destructor releases the
    // mechanism's hang gate FIRST - so the thread parked in watch() can actually finish -
    // THEN joins both. Joining before releasing would deadlock the test's own cleanup.
    struct Cleanup {
        FakeServiceMechanism* mech;
        std::thread pusher_thread;
        std::optional<std::thread> stopper_thread;
        ~Cleanup() {
            mech->release_hang();
            if (pusher_thread.joinable())
                pusher_thread.join();
            if (stopper_thread && stopper_thread->joinable())
                stopper_thread->join();
        }
    } cleanup{f.mechanism, std::thread{[&] {
                  gpb::GuaranteedStatePush p;
                  p.set_full_sync(true);
                  *p.add_rules() = make_service_rule("r1");
                  auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
                      *f.engine, p.SerializeAsString());
                  push_exit_code.store(dr.exit_code, std::memory_order_release);
                  push_done.store(true, std::memory_order_release);
              }}};

    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));

    // The push itself must already have returned - proving apply_rules() does NOT wait
    // for the hung watch() to release.
    REQUIRE(yuzu::test::spin_until([&] { return push_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(push_exit_code.load(std::memory_order_acquire) == 0);

    // mtx_ is free the moment apply_rules() returned above - stop() proves it by also
    // returning promptly, with the watch() STILL hung. The grace is deliberately WIDE
    // (120s, comfortably past this test's own 10s spin bound even at TSan's 6x scale) -
    // standing flake doctrine (this file, throughout): a real-wall-clock upper bound on
    // stop() itself would make this a timing assertion in disguise, racing CI-runner
    // scheduling noise rather than proving the wedge is gone. A short grace was the
    // OLD test's whole point (catching a genuine multi-second wedge quickly); this one
    // only needs to prove the watchdog never fires at all, so wider is strictly safer.
    cleanup.stopper_thread.emplace([&] {
        yuzu::agent::ShutdownDeadlineGuard watchdog{
            std::chrono::seconds(120),
            [watchdog_fired] { watchdog_fired->store(true, std::memory_order_release); }};
        f.engine->stop();
        stop_returned.store(true, std::memory_order_release);
    });
    REQUIRE(yuzu::test::spin_until(
        [&] { return stop_returned.load(std::memory_order_acquire); },
        std::chrono::seconds(10)));
    CHECK_FALSE(watchdog_fired->load(std::memory_order_acquire)); // never had anything to fire on

    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.mechanism->watching_count() == 0; },
                                   std::chrono::seconds(10)));

    cleanup.stopper_thread->join();
    cleanup.pusher_thread.join();
}

TEST_CASE("rung 9c PR-2 Unit 6: a hung watch() no longer wedges apply_rules() or "
          "stop() - the arm is dispatched off-lock, not waited for",
          "[spark][guardian][reconcile][liveness]") {
    // Supersedes "#2233 item 3: a hung watch() wedges stop() until released" (this
    // test's name and premise, pre rung 9c PR-2 Unit 6). That test's wedge was never
    // stop() making a direct blocking arm call - it was apply_rules() (the push
    // thread) holding GuardianEngine::mtx_ synchronously inside attach_rule()'s
    // (then blocking) bounded wait, so stop() (which also needs mtx_) queued behind
    // it. Unit 6 cut reconcile_rule_locked() over to attach_rule(NonWaiting{}, ...):
    // apply_rules() now returns as soon as the arm is ACCEPTED, holding mtx_ for
    // nowhere near the duration of a hung watch() - so neither the push nor a later
    // stop() wedges on it any more. This is the arm-side half of this PR's own title
    // ("wire apply_rules()/detach_all() onto the non-waiting executor path") landing
    // in production, matching Unit 3's disarm-side transformation of the unwatch
    // analogue of this same test (above, in this file).
    SparkReconcileFixture f;
    f.mechanism->hang_next_watch();

    std::atomic<int> push_exit_code{-1};
    std::atomic<bool> push_done{false};
    std::atomic<bool> stop_returned{false};

    // Cleanup OWNS both worker threads as members (never a pointer to a separately-
    // declared local) - see the analogous unwatch test's own comment (Unit 3, above)
    // for the reverse-declaration-order reasoning this guards against. On ANY unwind
    // (a fatal REQUIRE below), the destructor releases the mechanism's hang gate
    // FIRST - so whichever thread is parked in watch() can actually finish - THEN
    // joins both.
    struct Cleanup {
        FakeServiceMechanism* mech;
        std::thread pusher_thread;
        std::optional<std::thread> stopper_thread;
        ~Cleanup() {
            mech->release_hang();
            if (pusher_thread.joinable())
                pusher_thread.join();
            if (stopper_thread && stopper_thread->joinable())
                stopper_thread->join();
        }
    } cleanup{f.mechanism, std::thread{[&] {
                  gpb::GuaranteedStatePush p;
                  p.set_full_sync(true);
                  *p.add_rules() = make_service_rule("r1");
                  auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
                      *f.engine, p.SerializeAsString());
                  push_exit_code.store(dr.exit_code, std::memory_order_release);
                  push_done.store(true, std::memory_order_release);
              }}};

    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));

    // The push itself must already have returned - proving apply_rules() does NOT
    // wait for the hung watch() to release. A regression back to a blocking arm wait
    // makes this REQUIRE time out rather than silently pass (the mechanism is still
    // hung at this point - release_hang() is not called until after this).
    REQUIRE(yuzu::test::spin_until([&] { return push_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(push_exit_code.load(std::memory_order_acquire) == 0);

    // mtx_ is free the moment apply_rules() returned above - stop() proves it by
    // also returning promptly, with the watch() STILL hung (relies on the same
    // implicitly-noexcept treatment ~GuardianEngine() itself gives stop(), governance
    // Gate 4 unhappy-path UP-1 - not a new risk, just exercised off the main thread).
    cleanup.stopper_thread.emplace([&] {
        f.engine->stop();
        stop_returned.store(true, std::memory_order_release);
    });
    REQUIRE(yuzu::test::spin_until([&] { return stop_returned.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));

    // The arm claim is still a real, owned attempt (Unit 6's whole point is
    // non-blocking, not abandoned) - releasing the hang lets it actually resolve.
    // Post-stop, a late-arriving success is disarmed rather than left live (§R5.5),
    // so this settles at 0 either way - waiting for it also gives the detached
    // worker a safe join point before the fixture tears down f.mechanism.
    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.mechanism->watching_count() == 0; },
                                   std::chrono::seconds(10)));

    cleanup.stopper_thread->join();
    cleanup.pusher_thread.join();
}

TEST_CASE("rung 9c PR-2 Unit 6: a hung watch() on one rule no longer blocks an "
          "unrelated concurrent push",
          "[spark][guardian][reconcile][liveness]") {
    // Supersedes "#2233 item 3: a hung watch() on one rule blocks an unrelated
    // concurrent push" (this test's name and premise, pre rung 9c PR-2 Unit 6): push
    // A used to hold mtx_ synchronously inside attach_rule()'s blocking wait, so push
    // B queued behind it. Unit 6's non-waiting cutover means push A returns as soon
    // as its arm is ACCEPTED - push B is never blocked by it at all any more.
    SparkReconcileFixture f;
    f.mechanism->hang_next_watch();

    std::atomic<int> push_a_exit_code{-1};
    std::atomic<bool> push_a_done{false};
    std::atomic<int> push_b_exit_code{-1};
    std::atomic<bool> push_b_done{false};

    // See the analogous wedge test above for why Cleanup must OWN both threads as
    // members rather than point to separately-declared locals.
    struct Cleanup {
        FakeServiceMechanism* mech;
        std::thread pusher_a_thread;
        std::optional<std::thread> pusher_b_thread;
        ~Cleanup() {
            mech->release_hang();
            if (pusher_a_thread.joinable())
                pusher_a_thread.join();
            if (pusher_b_thread && pusher_b_thread->joinable())
                pusher_b_thread->join();
        }
    } cleanup{f.mechanism, std::thread{[&] {
                  gpb::GuaranteedStatePush p;
                  p.set_full_sync(true);
                  *p.add_rules() = make_service_rule("r1");
                  auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
                      *f.engine, p.SerializeAsString());
                  push_a_exit_code.store(dr.exit_code, std::memory_order_release);
                  push_a_done.store(true, std::memory_order_release);
              }}};

    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));

    // Push A must already have returned - proving apply_rules() does not hold mtx_
    // for the hung watch()'s duration.
    REQUIRE(yuzu::test::spin_until([&] { return push_a_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(push_a_exit_code.load(std::memory_order_acquire) == 0);

    // Push B (a distinct spark key, full_sync=false, so it doesn't also try to
    // detach r1) proves mtx_ is free: it returns promptly too, with r1's watch()
    // STILL hung.
    cleanup.pusher_b_thread.emplace([&] {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(false);
        *p.add_rules() = make_service_rule("r2", true, "OtherSvc");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine,
                                                                     p.SerializeAsString());
        push_b_exit_code.store(dr.exit_code, std::memory_order_release);
        push_b_done.store(true, std::memory_order_release);
    });
    REQUIRE(yuzu::test::spin_until([&] { return push_b_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(push_b_exit_code.load(std::memory_order_acquire) == 0);

    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.mechanism->watching_count() == 2; },
                                   std::chrono::seconds(10)));

    cleanup.pusher_a_thread.join();
    cleanup.pusher_b_thread->join();
}

TEST_CASE("rung 9c PR-2 Unit 3: a hung unwatch() no longer wedges apply_rules() or "
          "stop() - detach_all()'s disarm is dispatched off-lock, not waited for",
          "[spark][guardian][reconcile][liveness]") {
    // Supersedes "#2233 item 3: a hung unwatch() wedges stop() until released" (this
    // test's name and premise, pre rung 9c PR-2 Unit 3). That test's wedge was never
    // stop() making a direct blocking disarm call - it was apply_rules() (the PUSH
    // thread) holding GuardianEngine::mtx_ synchronously inside detach_all()'s (then
    // run()-based) disarm, so stop() (which also needs mtx_) queued behind it. Unit
    // 3 made submit_disarm_off_lock() genuinely non-blocking (submit(), not run()):
    // apply_rules() now returns as soon as the disarm is ADMITTED, holding mtx_ for
    // nowhere near the duration of a hung unwatch() - so neither the push nor a
    // later stop() wedges on it any more. This is the disarm-side half of this PR's
    // own title ("wire apply_rules()/detach_all() onto the non-waiting executor
    // path") already landing in production, ahead of Unit 6's arm-side cutover -
    // detach_rule()/detach_all() are called by GuardianEngine unconditionally,
    // regardless of prefer_spark_.
    //
    // Arm r1 normally first (no hang yet), so the hang below is specifically on the
    // detach path. The second push below is full_sync=true, so the hang is entered
    // via apply_rules()'s UNCONDITIONAL detach_all() sweep (guardian_engine.cpp,
    // before the per-rule loop) -> detach_rule_locked -> backend_->disarm ->
    // SparkEngine::disarm -> mech->unwatch.
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));
    REQUIRE(f.mechanism->watching_count() == 1);

    f.mechanism->hang_next_unwatch();

    std::atomic<int> push_exit_code{-1};
    std::atomic<bool> push_done{false};
    // stop_returned is declared here, BEFORE Cleanup - see the "hung watch() wedges
    // stop()" test above for why (governance Gate 3 - cpp-expert and cpp-safety
    // independently found this class of gap for the second thread's result atomics).
    std::atomic<bool> stop_returned{false};

    struct Cleanup {
        FakeServiceMechanism* mech;
        std::thread pusher_thread;
        std::optional<std::thread> stopper_thread;
        ~Cleanup() {
            mech->release_hang();
            if (pusher_thread.joinable())
                pusher_thread.join();
            if (stopper_thread && stopper_thread->joinable())
                stopper_thread->join();
        }
    } cleanup{f.mechanism, std::thread{[&] {
                  gpb::GuaranteedStatePush p;
                  p.set_full_sync(true);
                  *p.add_rules() = make_service_rule("r1", /*enabled=*/false);
                  auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
                      *f.engine, p.SerializeAsString());
                  push_exit_code.store(dr.exit_code, std::memory_order_release);
                  push_done.store(true, std::memory_order_release);
              }}};

    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));

    // The push itself must return promptly - proving apply_rules() does NOT wait for
    // the hung unwatch() to release. A regression back to a blocking disarm wait
    // makes this REQUIRE time out rather than silently pass (the mechanism is still
    // hung at this point - release_hang() is not called until after this).
    REQUIRE(yuzu::test::spin_until([&] { return push_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(push_exit_code.load(std::memory_order_acquire) == 0);

    // mtx_ is free the moment apply_rules() returned above - stop() proves it by
    // also returning promptly, with the unwatch() STILL hung (relies on the same
    // implicitly-noexcept treatment ~GuardianEngine() itself gives stop(), governance
    // Gate 4 unhappy-path UP-1 - not a new risk, just exercised off the main thread).
    cleanup.stopper_thread.emplace([&] {
        f.engine->stop();
        stop_returned.store(true, std::memory_order_release);
    });
    REQUIRE(yuzu::test::spin_until([&] { return stop_returned.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));

    // The disarm claim is still a real, owned attempt (Unit 3's whole point is
    // non-blocking, not abandoned) - releasing the hang lets it actually finish.
    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.mechanism->watching_count() == 0; },
                                   std::chrono::seconds(10)));
}

// ---------------------------------------------------------------------------
// #2233 item 3: the OTHER half of the liveness fix - a genuinely failed (timed
// out) arm must be COUNTED, so apply_rules' policy_generation hold-on-failure
// gate sees it and the server retries, rather than the push being silently
// treated as fully applied. This is the fix for the reconcile_failures
// asymmetry Fable's review of the bounded-wait design flagged: attach_rule's
// new timeout error flows through the exact call site that used to discard a
// returned (non-thrown) arm failure entirely. Real time: this rides out the
// PRODUCTION backend_op_deadline (5s, GuardianSparkRuntime::Config's default -
// this fixture wires GuardianEngine's own spark_runtime_, which has no test
// seam to shrink it), same order of magnitude as this file's other liveness
// tests' REQUIRE(..., seconds(30)) waits.
// ---------------------------------------------------------------------------

TEST_CASE("#2233 item 3: a timed-out arm holds policy_generation for retry, not "
          "silently applied",
          "[spark][guardian][reconcile][liveness]") {
    SparkReconcileFixture f;
    f.mechanism->hang_next_watch();
    // Release the parked mechanism on EVERY exit path, declared after `f` so it runs
    // BEFORE the fixture tears down SparkEngine/GuardianEngine: a failing REQUIRE
    // below used to skip the end-of-body release and destroy spark_engine while the
    // detached worker was still parked inside a mechanism it owns (governance cs-202).
    struct ReleaseHangOnExit {
        SparkReconcileFixture& fx;
        ~ReleaseHangOnExit() { fx.mechanism->release_hang(); }
    };
    ReleaseHangOnExit release_parked{f};
    REQUIRE(f.engine->policy_generation() == 0);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(5);
    *p.add_rules() = make_service_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());

    REQUIRE(dr.exit_code == 0); // the push ITSELF still dispatches cleanly - no crash, no hang
    // The rule's arm timed out (never released - see below): NOT armed, held for
    // retry, unlike an Unsupported/disabled rule (see the sibling
    // "an all-unsupported push still advances policy_generation" test above,
    // whose whole point is the opposite outcome for a routine, non-failure gap).
    CHECK(f.engine->policy_generation() == 0); // held, NOT advanced to 5
    CHECK(f.engine->rule_count() == 1);        // persisted (put_rule_locked ran)
    CHECK(f.engine->spark_armed_rule_count() == 0);
    // (the parked mechanism is released by `release_parked` above on every exit path)
}

#ifndef _WIN32
// The quiescence gate the fork()-without-exec death tests above rely on. Mutation: make
// wait_until_quiescent return true unconditionally -> the "false while a thread lives"
// branch fails; make it never return true -> the "true once it exits" branch times out.
TEST_CASE("test helper: wait_until_quiescent returns false while another thread lives and true once "
          "it has exited (fork death-test gate; governance pass-3 qe-2/cp-1/cs-4)",
          "[spark][guardian][reconcile][helpers]") {
#if !defined(__linux__)
    SUCCEED("wait_until_quiescent is a no-op off Linux; nothing to prove");
    return;
#else
    // Governance pass-4 cs-101: the second thread is joined on scope exit by construction,
    // never by a trailing manual join a throw could skip. std::jthread where the library
    // has it (loops on its own stop_token: a jthread destructor calls request_stop() and
    // would never set a hand-rolled release flag, so looping on such a flag would hang the
    // unwind path); a scope-exit join guard over std::thread on any toolchain that does not
    // define __cpp_lib_jthread. Not a hypothetical fallback: Apple Clang's libc++ does NOT
    // provide std::jthread (this project's own compiler floor, README.md:168 and
    // docs/build-guide.md:17, includes "Apple Clang 15+"; that exact substitution already
    // broke Apple Clang's libc++ once in this codebase on #2580 -
    // docs/governance-skill-tuning-2026-07.md:86, .claude/skills/governance/SKILL.md:1422,
    // and the same guard convention at tests/unit/server/test_secret_codec.cpp:1104 and
    // tests/unit/server/test_license_store.cpp:459). No CI leg compiles this arm today (see
    // the structural note below), so nothing here has been exercised against a real macOS
    // toolchain by this PR - the guard exists because the fact is established elsewhere in
    // this tree, not because this test proves it.
    // NOTE (governance pass-6 xp-201/dw-304): no CI leg compiles the fallback arm today for a
    // STRUCTURAL reason, not toolchain ubiquity - this whole test is `#ifndef _WIN32` (Windows
    // excluded above) and returns via SUCCEED() before reaching this #if on any non-Linux
    // platform (see the `#if !defined(__linux__)` branch just above), so only Linux ever
    // reaches this selection, and every Linux CI leg builds against libstdc++, which does
    // define __cpp_lib_jthread. Treat this fallback as review-only code (no CI leg compiles
    // it today) and keep it trivially simple regardless.
#if defined(__cpp_lib_jthread)
    std::jthread t([](std::stop_token st) {
        while (!st.stop_requested())
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
    // A live second thread: the gate must NOT open (bounded: 150 ms, scaled).
    CHECK_FALSE(yuzu::test::wait_until_quiescent(std::chrono::milliseconds(150)));
    t.request_stop();
    t.join(); // explicit here so the next CHECK observes the exited thread; the
              // destructor's join is the exception-path guarantee, not the happy path
#else
    std::atomic<bool> release{false};
    std::thread t([&] {
        while (!release.load(std::memory_order_acquire))
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
    struct JoinOnExit {
        std::atomic<bool>& release;
        std::thread& t;
        JoinOnExit(std::atomic<bool>& r, std::thread& th) : release(r), t(th) {}
        JoinOnExit(const JoinOnExit&) = delete;            // qe-204: one owner, one join
        JoinOnExit& operator=(const JoinOnExit&) = delete;
        ~JoinOnExit() {
            release.store(true, std::memory_order_release);
            if (t.joinable())
                t.join();
        }
    } join_guard{release, t};
    // A live second thread: the gate must NOT open (bounded: 150 ms, scaled).
    CHECK_FALSE(yuzu::test::wait_until_quiescent(std::chrono::milliseconds(150)));
    release.store(true, std::memory_order_release);
    t.join(); // explicit for the next CHECK; the guard is the exception-path join
#endif
    // Exited -> quiescent (TSan's background thread is excluded by the helper's threshold).
    CHECK(yuzu::test::wait_until_quiescent(std::chrono::seconds(5)));
#endif
}
#endif // !_WIN32 - wait_until_quiescent is the fork-death-test gate, Linux/macOS only

// ---------------------------------------------------------------------------
// rung 9c PR-2 (non-waiting cutover) - RED, target-behaviour regression net
// ---------------------------------------------------------------------------
//
// This test asserts docs/spark-stage2-guardian-consumer-design.md R5's rules for
// GuardianEngine::apply_rules() under the rung 9c PR-2 cutover. It was checked in
// RED (tagged `[!shouldfail]`) before Unit 6 implemented the cutover - apply_rules()
// used to hold mtx_ across GuardianSparkRuntime::attach_rule()'s bounded
// wait_for_claim() (rung 9c PR-1). Unit 6 flipped it to a real, unexpected pass
// against the untagged assertions, exactly as this comment block originally said
// whoever implemented the cutover should do; the tag is removed and this is now an
// ordinary enforced regression test.
TEST_CASE("rung 9c PR-2: apply_rules returns before a slow-arming rule resolves, "
          "and holds the policy generation until it does",
          "[spark][guardian][reconcile]") {
    // Shrink backend_op_deadline (production 5s), but keep a WIDE margin over the poll
    // window below even after sanitizer scaling (Astra opine review, 2026-09-12: the
    // original 300ms deadline / 60ms poll window was scheduling-sensitive, not
    // deterministic - test_helpers.hpp's spin_until scales ITS OWN timeout by
    // kSpinScale, 6x under TSan/ASan, but never scales this deadline, which is real
    // wall-clock time enforced inside production code. A 60ms request becomes an
    // effective 360ms wait under a sanitizer build - LARGER than the original 300ms
    // deadline - so on those legs alone, today's genuinely-blocking code could complete
    // and return within the scaled window purely from that scale factor, flipping this
    // `[!shouldfail]` case to an unexpected, environment-dependent pass having proven
    // nothing). 2000ms deadline / 100ms request (600ms scaled) keeps over 3x headroom
    // either way.
    SparkReconcileFixture f{/*periodic_bound_ms=*/0,
                            /*backend_op_deadline=*/std::chrono::milliseconds{2000}};

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(1);
    *p.add_rules() = make_service_rule("r1");
    const std::string push_bytes = p.SerializeAsString();

    REQUIRE(f.engine->policy_generation() == 0);
    f.mechanism->hang_next_watch(); // park mid-arm: the backend call never returns
                                    // until release_hang() below

    std::atomic<bool> dispatch_returned{false};
    yuzu::agent::GuardianDispatchResult dr{};
    std::thread pusher([&] {
        dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, push_bytes);
        dispatch_returned.store(true, std::memory_order_release);
    });
    // cpp-safety Gate 3 shape (matching the #2818 test above): release the hang and join
    // on ANY exit path, so a failed REQUIRE between spawn and join can never unwind past
    // a still-joinable std::thread. A non-waiting `pusher.join()` below only proves the
    // dispatch call itself returned, NOT that every detached runtime callback has
    // finished (Astra opine review) - this test additionally spins on
    // spark_armed_rule_count() before the fixture tears down, so by the time
    // SparkReconcileFixture's destructor runs (engine.reset() then spark_engine.stop()),
    // the one callback this test drives has already committed; it does not generalise to
    // a test that returns without observing that.
    struct PusherGuard {
        FakeServiceMechanism* mech;
        std::thread* t;
        ~PusherGuard() {
            mech->release_hang();
            if (t->joinable())
                t->join();
        }
    } pusher_guard{f.mechanism, &pusher};

    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds{5}));

    // TARGET (rung 9c PR-2): apply_rules() must already have returned here, while the
    // backend call is still parked - it must not still be blocked inside attach_rule's
    // bounded wait. spin_until is liveness-only (never a bare sleep-based timing
    // assertion, per its own doc); the margin between this 100ms request (600ms worst-
    // case scaled) and the 2000ms deadline above is what made this fail, before Unit 6,
    // for the intended reason (apply_rules was still blocked, having not reached
    // anywhere near its own deadline) rather than by scheduling accident.
    REQUIRE(yuzu::test::spin_until([&] { return dispatch_returned.load(std::memory_order_acquire); },
                                   std::chrono::milliseconds{100}));

    // TARGET: the push was accepted (dispatch succeeded) but the rule's arm has not yet
    // resolved - the generation must NOT have advanced while it's still parked.
    CHECK(dr.exit_code == 0);
    CHECK(f.engine->policy_generation() == 0);

    // Release the parked backend call: NOW the arm resolves.
    f.mechanism->release_hang();

    // Prove the runtime's OWN commit is observable before asserting anything about the
    // generation (Astra opine review, 2026-09-12) - spark_armed_rule_count() reflects
    // commit_new_generation_locked()'s write, independent of any acknowledgment
    // bookkeeping, so this synchronizes on "the arm actually resolved" without racing
    // whatever advances (or wrongly fails to advance) the generation.
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 1; }));

    // TARGET (R5.3/R5.4): acknowledgment is TICK-DRIVEN (the heartbeat-bounded drain),
    // never automatic on resolution - and an executor completion callback may never
    // take mtx_ (the routed-concern chokepoint this file's own fixture exercises), so
    // the generation must still be UNCHANGED here, strictly BEFORE any tick runs.
    // Without this assertion, an implementation that (wrongly) advances the generation
    // directly from the completion callback - skipping the tick-driven drain R5.3/R5.4
    // require - would also satisfy the tick-driven check below, since nothing yet
    // distinguishes "advanced by the tick" from "already advanced before it".
    CHECK(f.engine->policy_generation() == 0);

    // NOW drive the tick explicitly (rather than spinning on wall-clock alone, which
    // could not distinguish "hasn't ticked yet" from a genuine cutover bug where the
    // generation never advances at all) and observe the acknowledgment it produces.
    // The fixture's prefer_spark=true means the tick's own !prefer_spark_ early return
    // doesn't apply here.
    REQUIRE(yuzu::test::spin_until([&] {
        f.engine->journal_maintenance_tick();
        return f.engine->policy_generation() == 1;
    }));

    pusher.join();
}

// ---------------------------------------------------------------------------
// rung 9c PR-2 Unit 6 - additional advisor-required coverage
// ---------------------------------------------------------------------------

// Advisor round (a): §R5.3's duplicate-retry suppression, at the engine level (the
// ledger's own decide_retry() unit tests already cover the decision in isolation -
// see test_guardian_arm_ack.cpp - this proves apply_rules() actually WIRES it, so a
// same-generation full_sync heartbeat retry while r1 is still parked never reaches
// the mechanism a second time).
TEST_CASE("rung 9c PR-2 Unit 6: a same-generation retry while the prior push's arm is still "
          "parked is suppressed before it ever reaches the mechanism",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0,
                            /*backend_op_deadline=*/std::chrono::milliseconds{2000}};

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(1);
    *p.add_rules() = make_service_rule("r1");
    const std::string push_bytes = p.SerializeAsString();

    f.mechanism->hang_next_watch();

    std::atomic<bool> first_returned{false};
    yuzu::agent::GuardianDispatchResult dr1{};
    std::thread pusher([&] {
        dr1 = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, push_bytes);
        first_returned.store(true, std::memory_order_release);
    });
    // Same exception-safety shape as the target cutover test above: release + join on
    // ANY exit path, so a failed REQUIRE between spawn and join can never unwind past
    // a still-joinable std::thread.
    struct PusherGuard {
        FakeServiceMechanism* mech;
        std::thread* t;
        ~PusherGuard() {
            mech->release_hang();
            if (t->joinable())
                t->join();
        }
    } pusher_guard{f.mechanism, &pusher};

    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds{5}));
    REQUIRE(yuzu::test::spin_until([&] { return first_returned.load(std::memory_order_acquire); },
                                   std::chrono::milliseconds{100}));
    CHECK(dr1.exit_code == 0);
    CHECK(f.mechanism->watch_call_count() == 1);
    CHECK(f.mechanism->watching_count() == 0); // still parked mid-watch, not yet committed

    // Same generation, identical content, sent again while r1 is still parked. This
    // call runs on THIS (the test) thread, not a spawned one - decide_retry()'s
    // Suppress means apply_rules() returns without ever reaching the full_sync
    // teardown or the per-rule reconcile loop a second time, so unlike the first
    // push it needs no hang-gate/thread pair of its own to prove it doesn't block.
    const auto dr2 =
        yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, push_bytes);
    CHECK(dr2.exit_code == 0);
    CHECK(f.mechanism->watch_call_count() == 1); // no second watch() - suppressed upstream of it
    CHECK(f.engine->policy_generation() == 0);   // still held: r1 is still unresolved

    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 1; }));
    REQUIRE(yuzu::test::spin_until([&] {
        f.engine->journal_maintenance_tick();
        return f.engine->policy_generation() == 1;
    }));
    pusher.join();
}

// Advisor round (b): at the time this was written, the one synchronous Failed path
// GuardianSparkRuntime::attach_core() could take post-cutover was the stopping_ race,
// which apply_rules() can never observe under mtx_ (stop() holds it across
// begin_stop()) - so a genuine per-rule synchronous ReconcileOutcome::Failed was not
// exercisable here at the time. STALE as of rung 9c PR-5c (#4221 up-2): the
// wedged-key refusal added a second synchronous Failed path, reachable through an
// ordinary attach_rule(NonWaiting, ...) call - see the "governance UP-1 residual
// round 2" test below, which drives exactly that outcome through apply_rules().
// What was ALSO still reachable, and still had no test, is apply_rules()'s OWN
// full_sync-teardown throw
// (guardian_spark_runtime.cpp's detach_all()/detach_rule_locked() "the claim allocation
// threw" seam, the same one that file's own rung 9c R5.2 adversarial-review-r2-C1 test
// exercises directly against the runtime) - reconcile_failures > 0 latches the
// application even though every rule THIS push actually reconciles goes on to commit.
TEST_CASE("rung 9c PR-2 Unit 6: a full_sync teardown throw holds the generation even though "
          "the same push's own rule commits fine",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0,
                            /*backend_op_deadline=*/std::chrono::milliseconds{2000}};

    // r1 commits via an ordinary push first, so it is a genuine armed rules_ entry -
    // the "known, last-on-key, queued-tier" condition detach_rule_locked's
    // detach_fault_here_for_test() seam requires.
    f.apply(make_service_rule("r1", true, "SvcA"));
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 1; }));
    REQUIRE(f.engine->policy_generation() == 0); // f.apply()'s push never sets a generation

    // Consumed once (GuardianSparkRuntime::detach_fault_here_for_test's exchange(false)):
    // fires on r1, the only currently-armed rule, inside the incoming full_sync's
    // detach_all().
    f.engine->spark_runtime_for_test()->set_detach_fault_for_test(true);

    gpb::GuaranteedStatePush p2;
    p2.set_full_sync(true);
    p2.set_policy_generation(1); // > policy_generation_ (0) - would advance without the latch
    *p2.add_rules() = make_service_rule("r2", true, "SvcB");
    const auto dr =
        yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p2.SerializeAsString());
    // apply_rules() itself does not fail on this - the teardown throw is caught and
    // counted by guardian_engine.cpp's own full_sync-teardown try/catch, never
    // propagated to the dispatch caller.
    CHECK(dr.exit_code == 0);

    // r2 gets a fair shot: the caught throw doesn't abort the rest of the push - it
    // still reconciles, arms and commits normally. r1 is left exactly as it was (the
    // seam fires before any durable mutation, per detach_rule_locked's own comment),
    // so both end up armed.
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 2; }));

    // TARGET: the teardown throw latched this application's failure - the generation
    // must stay held even after r2's own arm resolves cleanly and repeated ticks run.
    for (int i = 0; i < 5; ++i)
        f.engine->journal_maintenance_tick();
    CHECK(f.engine->policy_generation() == 0);
}

// ---------------------------------------------------------------------------
// rung 9c PR-2 Unit 6 gate (coordinator finding) - persist_generation_locked()'s
// publish-before-persist ordering
// ---------------------------------------------------------------------------

TEST_CASE("rung 9c PR-2 Unit 6 gate: journal_maintenance_tick() does not advance "
          "policy_generation() when persisting it fails, and retries cleanly once "
          "the KV write succeeds",
          "[spark][guardian][reconcile]") {
    // Was RED before the fix: persist_generation_locked() published policy_generation_
    // to the candidate value BEFORE attempting (and discarding the result of) the KV
    // write - a failed write left policy_generation_ already advanced with nothing
    // durable behind it, and the tick's own gen > policy_generation_ recheck was
    // therefore false on every later tick, permanently (the server's heartbeat
    // reconcile only re-pushes while the agent reports a generation BEHIND its own -
    // this would silently and permanently stop that retry).
    SparkReconcileFixture f;

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(1);
    *p.add_rules() = make_service_rule("r1");
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString())
                .exit_code == 0);
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->spark_armed_rule_count() == 1; }));
    REQUIRE(f.engine->policy_generation() == 0); // not yet acknowledged - no tick has run

    // A real KV-write failure (not a fault-injection stand-in): drop the table through
    // a second connection to the SAME on-disk file, so persist_generation_locked()'s
    // kv_->set() call genuinely fails ("no such table") on THIS tick.
    drop_kv_store_table_for_test(f.db_.path);
    f.engine->journal_maintenance_tick();
    // TARGET: the failed persist must NOT have published policy_generation_. Before the
    // fix, this was already 1 here - the exact bug the coordinator's gate caught.
    CHECK(f.engine->policy_generation() == 0);

    // KV healthy again: the SAME condition (gen > policy_generation_) that failed to
    // persist above is still true, so the very next tick retries it with no separate
    // retry bookkeeping - and this time it durably succeeds.
    recreate_kv_store_table_for_test(f.db_.path);
    f.engine->journal_maintenance_tick();
    CHECK(f.engine->policy_generation() == 1);
}

// ---------------------------------------------------------------------------
// Governance hardening round (Gates 2-6, rung 9c PR-2): sec-1/arch-1's
// production-live repeat-push regression. The test above exercises RECOVERY
// via journal_maintenance_tick()'s own drain, at prefer_spark=true. sre's and
// enterprise-readiness's independent Gate 6 traces proved the wedge is
// reachable TODAY at prefer_spark=false too - the production default - because
// spark_runtime_ is wired unconditionally at boot regardless of prefer_spark_,
// and apply_rules()'s decide_retry() gate checks only spark_runtime_, never
// prefer_spark_. At prefer_spark_=false, Accepted (and therefore any pending
// ledger entry) is unreachable, so decide_retry() used to vacuously Suppress
// EVERY identical retry - including the one that would have retried a failed
// persist_generation_locked() write - permanently wedging the reported
// generation until restart. This test drives that exact path: a real repeat
// push through apply_rules() (not journal_maintenance_tick()'s drain), at
// prefer_spark=false, with a genuinely failed-then-recovered KV write.
// ---------------------------------------------------------------------------

TEST_CASE("rung 9c PR-2 governance hardening: an IDENTICAL repeat push recovers "
          "a policy_generation() held by a failed persist, at prefer_spark=false "
          "(the production default) - sec-1/arch-1 regression",
          "[spark][guardian][reconcile]") {
    // Was RED before the fix: decide_retry() vacuously Suppressed the second,
    // identical dispatch below (pending was empty - Accepted never occurs at
    // prefer_spark=false), so apply_rules() returned before ever re-attempting
    // persist_generation_locked() - policy_generation() stayed wedged at 0
    // forever, exactly the production-live defect governance found.
    const auto kv_path = unique_kv_path();
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // the production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    // Matches production: spark_runtime_ is wired (non-null) even though prefer_spark_
    // stays false - this is exactly what makes decide_retry() live today.
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    // A zero-rule push isolates the persist-retry-suppression mechanism from any
    // platform-dependent legacy guard arm behaviour (ServiceGuard/SystemdServiceGuard) -
    // reconcile_failures stays 0 by construction, so the only thing gating the
    // generation advance is ack_ledger_->can_advance() (trivially true, nothing ever
    // Accepted at prefer_spark=false) and the persist itself.
    //
    // Scope note (Gate 8, unhappy-path UP-9): a REAL push whose rules also live in
    // the dropped kv_store table would fail at put_rule_locked() first (the
    // pre-existing, already-correct latch_failure()->Reapply path) before ever
    // reaching the tail-gate persist this test targets - this whole-table-drop
    // fault can't isolate "rules durably stored, only the generation marker's own
    // write fails" from "everything in the table fails together". decide_retry()'s
    // pending.empty() fix does not itself depend on rule count or content (proven
    // independently, rule-content-free, by the ledger-level "EMPTY pending map"
    // unit test in test_guardian_arm_ack.cpp) - but a selective-KV-fault test
    // exercising this exact tail-gate failure with real, already-armed rules
    // present is tracked as a follow-up, not fixed here.
    gpb::GuaranteedStatePush p;
    p.set_full_sync(false);
    p.set_policy_generation(1);
    const std::string push_bytes = p.SerializeAsString();

    drop_kv_store_table_for_test(kv_path);
    auto dr1 = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, push_bytes);
    CHECK(dr1.exit_code == 0); // the push itself is not an error - the persist just held
    CHECK(engine.policy_generation() == 0); // failed write must not have published it

    recreate_kv_store_table_for_test(kv_path);
    // Identical (generation, content, full_sync) as the first dispatch - the server's
    // own retry shape. TARGET: this must NOT be vacuously Suppressed just because
    // nothing was ever pending (Accepted is unreachable at prefer_spark=false) - it
    // must Reapply, re-run the (empty) reconcile loop, and retry the persist, which
    // now succeeds.
    auto dr2 = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, push_bytes);
    CHECK(dr2.exit_code == 0);
    CHECK(engine.policy_generation() == 1);

    engine.stop();
    spark_engine.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// Governance UP-1 residual, round 2 (#4221, rung 9c PR-5c follow-up governance
// round 2): round 1 fixed GuardianSparkRuntime::attach_core() itself (see the
// raw-API-level "governance UP-1" test in test_guardian_spark_runtime.cpp) so a
// retarget refused onto a wedged key leaves the calling rule's PRIOR generation
// untouched. But the PRODUCTION CALLER, GuardianEngine::reconcile_rule_locked(),
// undid that fix one call later: its own defensive `spark_runtime_->
// detach_rule(rule.rule_id())` used to run UNCONDITIONALLY on every Failed
// result, on the (round-1-stale) premise "attach_rule leaves nothing on
// failure" - true for every OTHER Failed path, but false for exactly the one
// round 1 introduced. detach_rule() looks up rule_id's CURRENT key via the
// index - which, after a round-1-only refusal, still resolves to the calling
// rule's real, committed, untouched arm on its OWN key - and tears it down for
// real, reproducing UP-1's "zero live arms, no recovery" defect one function
// call downstream of where round 1 closed it. The raw GuardianSparkRuntime-level
// test never catches this because it calls attach_rule() directly, never
// through reconcile_rule_locked() - this test closes that coverage gap by
// driving the identical scenario through the real GuardianEngine::apply_rules()
// production entry point instead of the raw runtime API.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("governance UP-1 residual, round 2 (#4221): retargeting a rule onto an "
          "already-Wedged key held by a DIFFERENT rule, driven through "
          "GuardianEngine::apply_rules()/reconcile_rule_locked() rather than the "
          "raw GuardianSparkRuntime API, must not let the CALLER's own defensive "
          "cleanup tear down the calling rule's real, still-live arm",
          "[spark][guardian][reconcile][liveness]") {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0,
                            /*backend_op_deadline=*/std::chrono::milliseconds(50)};

    // (1) R arms normally on K1 ("Spooler") through an ordinary push - a real,
    // committed, working arm.
    f.apply(make_service_rule("R", true, "Spooler"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);
    REQUIRE(f.engine->spark_runtime_for_test()->armed_key_count() == 1);
    REQUIRE(f.mechanism->watching_count() == 1);

    // (2) Hang the next watch(), then push R2 - a genuinely DIFFERENT rule_id -
    // onto K2 ("Notepad") as an ordinary incremental push. rung 9c PR-2 Unit 6:
    // apply_rules() -> attach_rule(NonWaiting, ...) dispatches the backend arm()
    // call off-lock and returns as soon as it is ACCEPTED, so this push (and the
    // watch() call it kicks off on a detached executor worker) returns without
    // ever blocking THIS thread - no separate pusher thread is needed, unlike the
    // concurrent-stop() characterisation tests above. Uses dispatch_raw(), not
    // apply() - apply()'s own settle loop waits for active_io_workers() == 0,
    // which this hung watch() deliberately keeps above zero until release_hang()
    // below, well after the assertions this test cares about.
    f.mechanism->hang_next_watch();
    const auto dr2 = f.dispatch_raw(make_service_rule("R2", true, "Notepad"), /*full_sync=*/false);
    REQUIRE(dr2.exit_code == 0);
    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));
    // Safety net for any REQUIRE/CHECK failure below unwinding past a still-parked
    // worker - matches this file's own established idiom (e.g. ArmerGuard above).
    // release_hang() is idempotent (see its own doc comment), so the explicit
    // release_hang() call near the end of the happy path below and this
    // destructor's own call never conflict.
    struct Cleanup {
        FakeServiceMechanism* mech;
        ~Cleanup() { mech->release_hang(); }
    } cleanup{f.mechanism};

    // (3) K2's head goes Wedged - claimed by R2, not R. expire_overdue_claims() is
    // the same test-only seam the raw GuardianSparkRuntime-level UP-1 test uses,
    // reached here through GuardianEngine's own borrowed runtime
    // (spark_runtime_for_test()), not a separate fixture.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(f.engine->spark_runtime_for_test()->expire_overdue_claims() == 1);

    // (4) R retargets from K1 onto the now-Wedged K2 (owned by R2, a genuinely
    // different rule_id) - through the REAL apply_rules()/reconcile_rule_locked()
    // production path, never GuardianSparkRuntime::attach_rule() directly. Must be
    // refused synchronously; the push itself is not an error (only R's own
    // reconcile fails) - same "not an error at the push level" contract the
    // "a spark arm failure is errored" test above already establishes.
    const auto dr3 = f.dispatch_raw(make_service_rule("R", true, "Notepad"), /*full_sync=*/false);
    CHECK(dr3.exit_code == 0);
    CHECK(f.engine->spark_runtime_for_test()->wedged_refusals() == 1);

    // THE FIX (round 2): R's ORIGINAL arm on K1 is still live all the way through
    // reconcile_rule_locked()'s OWN defensive-cleanup branch, not merely inside
    // attach_core() itself. Before the round-2 fix, reconcile_rule_locked()'s
    // unconditional spark_runtime_->detach_rule("R") on this exact Failed result
    // found R's real, round-1-preserved arm on K1 and tore it down for real - both
    // counts below would already read 0 here, and R's real subscription would
    // already have been handed to a disarm.
    CHECK(f.engine->spark_armed_rule_count() == 1);                    // still just R
    CHECK(f.engine->spark_runtime_for_test()->armed_key_count() == 1); // still K1
    CHECK(f.mechanism->watching_count() == 1);                         // K1's real watch untouched

    // Once released, R2's wedged claim is ADOPTED (#4508, CommitPath::CallbackAdopt):
    // R2 is still the desired rule for K2 and nothing superseded it, so the late
    // watch() success commits as R2's real arm rather than being unwatched. The
    // terminal state is therefore TWO watches and TWO armed rules - R on K1, R2 on
    // K2. This test predates #4508 and used to wait for watching_count() == 1,
    // which was already true BEFORE the worker committed, so it passed vacuously
    // whenever the test thread won the race and timed out whenever the worker
    // inserted first (#4863). Wait for the real terminal state instead.
    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until(
        [&] {
            return f.mechanism->watching_count() == 2 && f.engine->spark_armed_rule_count() == 2;
        },
        std::chrono::seconds(10)));
    const auto watched = f.mechanism->watched_snapshot();
    const auto watches = [&](std::string_view svc) {
        return std::any_of(watched.begin(), watched.end(),
                           [&](const std::string& k) { return k.find(svc) != std::string::npos; });
    };
    CHECK(watches("Spooler")); // R's K1 arm survived the whole scenario (the UP-1 invariant)
    CHECK(watches("Notepad")); // R2's adopted arm on K2
    CHECK(f.engine->spark_runtime_for_test()->armed_key_count() == 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// rung 9c PR-5e (#4221, K-bound closeout, decision 1): end-to-end proof the
// FULL production wiring - apply_rules() -> decide_retry()/begin_application()
// -> journal_maintenance_tick()'s drain -> can_advance() -> persist+advance -
// K-waives a persistently Wedged-only rule after exactly
// kReapplyWaiverThreshold identical server retries, through the real
// GuardianEngine entry point rather than the raw GuardianSparkRuntime/
// GuardianArmAckLedger APIs the sibling ledger-level tests exercise directly.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("rung 9c PR-5e (#4221): K-bound waives a persistently Wedged-only rule "
          "after 3 identical server retries, advancing policy_generation, through "
          "GuardianEngine::apply_rules()/journal_maintenance_tick() end to end",
          "[spark][guardian][reconcile][liveness]") {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0,
                            /*backend_op_deadline=*/std::chrono::milliseconds(50)};
    REQUIRE(f.engine->policy_generation() == 0);

    // hang_next_watch() is consumed by the FIRST watch() call only - up-2's
    // Reobserved path means every SUBSEQUENT identical retry re-observes the
    // SAME already-wedged claim without ever calling watch() again, so this
    // single arm covers the whole test; no re-arming needed between retries.
    f.mechanism->hang_next_watch();
    struct ReleaseHangOnExit {
        SparkReconcileFixture& fx;
        ~ReleaseHangOnExit() { fx.mechanism->release_hang(); }
    } release_parked{f};

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(5);
    *p.add_rules() = make_service_rule("r1");
    const auto push_bytes = p.SerializeAsString(); // identical bytes every retry

    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, push_bytes);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    f.engine->journal_maintenance_tick(); // drains: r1 resolves Wedged, retained+eligible

    CHECK(f.engine->policy_generation() == 0); // held - reapply_count 0 < K
    {
        const auto s = f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
    }

    // 3 more identical server retries (4 established applications in total - see
    // the sibling ledger-level K-bound test's own comment on this exact
    // arithmetic: begin_application()'s reapply_count starts at 0 on the FIRST
    // application, so K==3 needs 3 MORE identical begin_application() calls).
    for (int i = 0; i < 3; ++i) {
        dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, push_bytes);
        REQUIRE(dr.exit_code == 0);
        f.engine->journal_maintenance_tick();
        // governance Gate 4/happy-path finding: assert the intermediate ticks too,
        // not just before/after the loop - proves the waiver genuinely fires at
        // exactly the 3rd retry, not one (or more) retries early.
        if (i < 2)
            CHECK(f.engine->policy_generation() == 0);
    }

    // The 3rd retry installed reapply_count == 3 == K, and the single remaining
    // failure is still genuinely, settledly Wedged (the mechanism's watch() call
    // is still parked in the hook this whole time) - K-waived. The generation
    // advances and is durably persisted.
    CHECK(f.engine->policy_generation() == 5);
    {
        const auto s = f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1); // telemetry still reports it - K-waiver never erases it
    }

    // (the parked mechanism is released by `release_parked` above on every exit path)
}
