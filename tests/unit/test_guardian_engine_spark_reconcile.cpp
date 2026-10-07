// test_guardian_engine_spark_reconcile.cpp - GuardianEngine's rung-7 reconcile
// op: the mutual-exclusion invariant between the spark and legacy IGuard
// detection paths. Tested against a REAL SparkEngine with a fake mechanism
// (Sol's rev-1 review resolution: this is the right vehicle, not a separate
// fake-backend injection seam - it exercises wire_spark_engine's real
// register_consumer/arm/disarm calls, not a shortcut around them).

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp> // sha256_file (#4045: the expected baseline hashes)

#include "guaranteed_state.pb.h"
#include "guardian_arm_ack.hpp" // kWedgeSuppressMaxDecisions (#5459: the held-generation valve test)
#include "guardian_baseline_heartbeat.hpp" // emit_guardian_baseline_persist_heartbeat_tags (#4045)
#include "guardian_baseline_persister.hpp" // GuardianBaselinePersister (#4045)
#include "guardian_arm_heartbeat.hpp" // GuardianArmStats complete type (rung 9c PR-3)
#include "guardian_backend.hpp" // guardian_backend_from_state/label (#2298 F13)
#include "guardian_convergence_scheduler.hpp" // ConvergenceScheduler (started_for_test, #2238)
#include "guardian_journal_format.hpp" // kJournalNamespace, parse_journal_batch (item 7 PR-Ag)
#include "guardian_health_heartbeat.hpp" // #5403: the pending-Disarm age / deadline-count emitters
#include "guardian_joined_thread_role.hpp" // GuardianJoinedThreadRole (death test below)
#include "guardian_io_executor.hpp" // GuardianIoExecutor::submit() (rung 9c R5.1 death test)
#include "guardian_journal_heartbeat.hpp" // emit_guardian_journal_heartbeat_tags (aggregate inertness)
#include "guardian_lifecycle_journal.hpp" // GuardianLifecycleJournal (for the _for_test fault seam)
#include "guardian_outbox.hpp" // OutboxEntry, SendResult - full definitions for the test's send_fn
#include "guardian_outbox_drain_worker.hpp" // GuardianOutboxDrainWorker (started_for_test, #2238)
#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime::set_detach_fault_for_test (rung 9c PR-2 Unit 6 test (b))
#include "shutdown_deadline_guard.hpp" // #2233 item 3 ("S+") wedge-pattern test
#include "spark_engine.hpp"
#include "spark_heartbeat.hpp" // emit_spark_heartbeat_tags (#4685 AC8)
#include "spark_mechanism.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp> // #4045: the persisted baseline record

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
using yuzu::agent::emit_spark_heartbeat_tags; // #4685 AC8
using yuzu::agent::FileMechanismTestControls; // #4685 AC2 (Windows-only real-mechanism test)
using yuzu::agent::FileSparkParams;           // #4685 AC2/AC7 raw-consumer spec
using yuzu::agent::GuardianBaselinePersister;
using yuzu::agent::GuardianEngine;
using yuzu::agent::ISparkMechanism;
using yuzu::agent::KvStore;
using yuzu::agent::make_file_mechanism;
using yuzu::agent::make_registry_mechanism;
using yuzu::agent::make_service_mechanism;
using yuzu::agent::OutboxEntry;
using yuzu::agent::RegistryMechanismTestControls; // #4685 AC3 (Windows-only real-mechanism test)
using yuzu::agent::RegistrySparkParams;            // #4685 AC3 raw-consumer spec
using yuzu::agent::SendResult;
using yuzu::agent::set_file_test_controls_for_test;     // #4685 AC2
using yuzu::agent::set_registry_test_controls_for_test; // #4685 AC3
using yuzu::agent::ServiceSparkParams; // #2818 pin: the raw sibling's spec
using yuzu::agent::SparkData;
using yuzu::agent::SparkEmitFn;
using yuzu::agent::SparkEngine;
using yuzu::agent::SparkEvent; // #2818 pin: the raw sibling's queued handler
using yuzu::agent::SparkFaultFn;
using yuzu::agent::SparkMechanismStats; // #4685
using yuzu::agent::SparkParams;
using yuzu::agent::spark_type_token; // #4685 AC8
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
    // The engine's own KvStore connection holds this file open in WAL mode with a 5 s busy
    // timeout; this second connection must wait for it too, or the DDL races a checkpoint
    // or a commit under load and fails SQLITE_BUSY (observed as rc 5 at 24-40 parallel runs).
    sqlite3_busy_timeout(db.raw, 5000);
    char* err = nullptr;
    const int rc = sqlite3_exec(db.raw, "DROP TABLE kv_store", nullptr, nullptr, &err);
    if (err)
        sqlite3_free(err);
    REQUIRE(rc == SQLITE_OK);
}
void recreate_kv_store_table_for_test(const std::filesystem::path& db_path) {
    ScopedTestSqlite3 db;
    REQUIRE(sqlite3_open(db_path.string().c_str(), &db.raw) == SQLITE_OK);
    // The engine's own KvStore connection holds this file open in WAL mode with a 5 s busy
    // timeout; this second connection must wait for it too, or the DDL races a checkpoint
    // or a commit under load and fails SQLITE_BUSY (observed as rc 5 at 24-40 parallel runs).
    sqlite3_busy_timeout(db.raw, 5000);
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
        // #5459 FU-10: the 1-based ORDER in which watch() calls entered (SparkEngine serialises a
        // type's mechanism calls, so for one type this is the lock order).
        const int ordinal = watch_calls_.fetch_add(1, std::memory_order_relaxed) + 1;
        bool hang = false;
        bool do_throw = false;
        {
            std::lock_guard<std::mutex> lk{mu_};
            if (first_watch_key_.empty())
                first_watch_key_ = key; // #5459: the key the (hung) first arm was for
            if (fail_next_watch_) {
                fail_next_watch_ = false;
                return std::unexpected("forced watch failure");
            }
            hang = hang_next_watch_;
            hang_next_watch_ = false;
            if (hang_on_ordinal_ != 0 && ordinal == hang_on_ordinal_) {
                hang = true; // #5459 FU-10: the Nth watch() to enter hangs, whichever rule it is for
                hang_on_ordinal_ = 0;
            }
            if (hang)
                hung_watch_key_ = key;
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
        // #5168: park-ALL gate, unlike the one-shot hang above. Every watch() blocks
        // here until release_park_all(), so a test can hold the Service class's whole
        // I/O quota AND its compensating-disarm reservation exhausted at once and
        // assert what the runtime does with the arms that cannot be admitted -
        // deterministically, with no dependence on how fast a fake watch() returns.
        {
            std::unique_lock<std::mutex> gate_lk{gate_mu_};
            if (park_all_) {
                ++parked_watches_;
                gate_cv_.notify_all();
                gate_cv_.wait(gate_lk, [this] { return !park_all_; });
                --parked_watches_;
            }
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
        // #5459: a ONE-SHOT outcome decided AFTER the gate, i.e. while the arm is parked
        // and only when it is finally released. fail_next_watch_ cannot do this (it
        // returns before the gate, so the arm never hangs) and do_throw above is captured
        // at ENTRY, so a test that decides the outcome after the arm is already parked
        // needs this one. Consumed here, so a later watch() (a recovery attempt) is never
        // affected: injection cannot be left on.
        LateWatchOutcome late = LateWatchOutcome::None;
        {
            std::lock_guard<std::mutex> lk{mu_};
            late = late_watch_outcome_;
            late_watch_outcome_ = LateWatchOutcome::None;
        }
        if (late == LateWatchOutcome::Refuse)
            return std::unexpected("forced late watch refusal");
        if (late == LateWatchOutcome::Throw)
            throw std::runtime_error("forced late watch throw");
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
        // #4472: an unwatch() hang with its OWN gate, so a test can hold a disarm after the
        // shared gate above has already been released for a hung arm (that gate latches open).
        bool isolated_hang = false;
        {
            std::lock_guard<std::mutex> lk{mu_};
            isolated_hang = isolated_hang_next_unwatch_;
            isolated_hang_next_unwatch_ = false;
        }
        if (isolated_hang) {
            std::unique_lock<std::mutex> gate_lk{isolated_gate_mu_};
            isolated_entered_ = true;
            isolated_gate_cv_.notify_all();
            isolated_gate_cv_.wait(gate_lk, [this] { return isolated_released_; });
        }
        {
            std::lock_guard<std::mutex> lk{mu_};
            watched_.erase(key);
        }
        unwatch_completed_.fetch_add(1, std::memory_order_relaxed);
    }
    void stop() override {}
    /// #4685: drives Guardian's capability-set inputs directly - both default false,
    /// matching SparkMechanismStats' own field defaults, so a test that never calls
    /// either sees byte-identical stats() output to before this seam existed
    /// (governance risk-register item 6: this default must never silently flip a
    /// pre-existing test onto the Unsupported path). Lock-free, like every real
    /// mechanism's stats() - called under the engine's own lock, never this
    /// mechanism's mu_.
    [[nodiscard]] SparkMechanismStats stats() const override {
        return {.inert = inert_for_test_.load(std::memory_order_relaxed),
                .boot_inert = boot_inert_for_test_.load(std::memory_order_relaxed)};
    }
    void set_inert(bool b) { inert_for_test_.store(b, std::memory_order_relaxed); }
    void set_boot_inert(bool b) { boot_inert_for_test_.store(b, std::memory_order_relaxed); }
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
    /// #5459: what the next watch() does once it is released from the hang gate (see the
    /// consume site in watch()). None = succeed. One-shot. Refuse returns an error; Throw
    /// throws, which SparkEngine's watch_guarded() turns into the SAME refusal-shaped
    /// failure (a mechanism throw can never surface as the runtime's IoFailure::WorkerThrew).
    enum class LateWatchOutcome { None, Refuse, Throw };
    void set_late_watch_outcome(LateWatchOutcome o) {
        std::lock_guard<std::mutex> lk{mu_};
        late_watch_outcome_ = o;
    }
    /// #5459: the key of the FIRST watch() this mechanism ever received; empty before one.
    std::string first_watch_key() {
        std::lock_guard<std::mutex> lk{mu_};
        return first_watch_key_;
    }
    /// #5459 FU-10: the Nth watch() to ENTER this mechanism (1-based, counted from construction)
    /// hangs on the shared gate, whichever rule it is for. Lets a test that arms two same-type
    /// rules in ONE push hang exactly the second to enter without depending on which rule the
    /// engine's two arm workers reach the type lock with first: the first one commits, the second
    /// hangs. One-shot; 0 = off (the default, so every other test is unaffected).
    void hang_watch_ordinal(int n) {
        std::lock_guard<std::mutex> lk{mu_};
        hang_on_ordinal_ = n;
    }
    /// #5459 FU-10: the key of the watch() that took the hang gate (either hang_next_watch() or
    /// hang_watch_ordinal()); empty before one.
    std::string hung_watch_key() {
        std::lock_guard<std::mutex> lk{mu_};
        return hung_watch_key_;
    }
    /// #5459: unwatch() calls that RAN TO COMPLETION (after any hang gate), so a test can
    /// tell a stale subscription's disarm having finished from it merely being parked.
    int unwatch_completed_count() const { return unwatch_completed_.load(std::memory_order_relaxed); }
    /// #4472: the next unwatch() parks on a gate independent of hang_next_watch()'s.
    void hang_next_unwatch_isolated() {
        std::lock_guard<std::mutex> lk{mu_};
        isolated_hang_next_unwatch_ = true;
    }
    bool wait_entered_isolated_unwatch(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> gate_lk{isolated_gate_mu_};
        return isolated_gate_cv_.wait_for(gate_lk, timeout, [this] { return isolated_entered_; });
    }
    void release_isolated_unwatch_hang() {
        {
            std::lock_guard<std::mutex> gate_lk{isolated_gate_mu_};
            isolated_released_ = true;
        }
        isolated_gate_cv_.notify_all();
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
    /// #5168: every subsequent watch() parks until release_park_all().
    void set_park_all_watches() {
        std::lock_guard<std::mutex> gate_lk{gate_mu_};
        park_all_ = true;
    }
    void release_park_all() {
        {
            std::lock_guard<std::mutex> gate_lk{gate_mu_};
            park_all_ = false;
        }
        gate_cv_.notify_all();
    }
    int parked_watch_count() {
        std::lock_guard<std::mutex> gate_lk{gate_mu_};
        return parked_watches_;
    }

private:
    std::atomic<int> watch_calls_{0};
    std::atomic<int> unwatch_completed_{0}; ///< #5459
    LateWatchOutcome late_watch_outcome_{LateWatchOutcome::None}; ///< #5459, guarded by mu_
    std::string first_watch_key_;                                  ///< #5459, guarded by mu_
    int hang_on_ordinal_{0};                                       ///< #5459 FU-10, guarded by mu_
    std::string hung_watch_key_;                                   ///< #5459 FU-10, guarded by mu_
    std::atomic<bool> inert_for_test_{false};
    std::atomic<bool> boot_inert_for_test_{false};
    std::mutex mu_;
    std::set<std::string> watched_;
    bool fail_next_watch_{false};
    bool throw_next_watch_{false};
    bool hang_next_watch_{false};
    bool hang_next_unwatch_{false};
    bool isolated_hang_next_unwatch_{false}; ///< #4472, guarded by mu_
    std::mutex isolated_gate_mu_;
    std::condition_variable isolated_gate_cv_;
    bool isolated_entered_{false};  ///< guarded by isolated_gate_mu_
    bool isolated_released_{false}; ///< guarded by isolated_gate_mu_
    // Gate is a SEPARATE lock from mu_ (see watch()'s comment) - release_hang() must
    // never need mu_, or a caller blocked trying to take mu_ mid-hang (e.g. a concurrent
    // is_watching() from the test's own polling) could never be released.
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool entered_hang_{false};
    bool released_{false};
    bool park_all_{false};      ///< #5168, guarded by gate_mu_
    int parked_watches_{0};     ///< #5168, guarded by gate_mu_
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
// `path` defaults to a fixed placeholder (this fixture never registers a File
// mechanism, so nothing ever opens it); #4685's real-mechanism tests pass a real
// ScratchDir path instead, mirroring make_service_rule's `service` parameter.
gpb::GuaranteedStateRule
make_file_rule(const std::string& id, bool enabled = true,
               const std::string& path = "/tmp/yuzu-reconcile-test-target") {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("file-change");
    auto* a = r.mutable_assertion();
    a->set_type("file-exists");
    (*a->mutable_params())["path"] = path;
    return r;
}

// #4045: file-hash-equals, no authored expected_hash by default (baseline-on-arm). Spark type
// file-change, so under prefer_spark_=true with a File mechanism registered it arms via Spark.
gpb::GuaranteedStateRule
make_file_hash_rule(const std::string& id, const std::string& path,
                    const std::string& expected_hash = "") {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(true);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("file-change");
    auto* a = r.mutable_assertion();
    a->set_type("file-hash-equals");
    (*a->mutable_params())["path"] = path;
    if (!expected_hash.empty())
        (*a->mutable_params())["expected_hash"] = expected_hash;
    return r;
}

// Registry: also NO mechanism registered in this fixture -> also a routine
// Unsupported gap (F7). Field shape mirrors test_guardian_engine.cpp's
// make_registry_rule() so validation/spec derivation succeeds identically.
// `key` defaults to a fixed placeholder; #4685's real-mechanism test passes a
// real ScratchRegKey subkey instead, mirroring make_service_rule's `service`
// parameter.
gpb::GuaranteedStateRule
make_registry_rule(const std::string& id, bool enabled = true,
                   const std::string& key = "SOFTWARE\\YuzuTest\\GuardStatusTest") {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("registry-change");
    auto* a = r.mutable_assertion();
    a->set_type("registry-value-equals");
    (*a->mutable_params())["hive"] = "HKCU";
    (*a->mutable_params())["key"] = key;
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
    /// #5459: a SECOND, independent mechanism registered under SparkType::Registry when the
    /// fixture is built with `with_registry_sibling`, so a test can hold the Service type's
    /// watch() parked (mechanism ops are serialised PER TYPE) while a healthy Registry rule arms,
    /// commits and is observably torn down / re-armed (or, being suppressed, left alone).
    FakeServiceMechanism* sibling_mechanism{nullptr}; // borrowed; owned by spark_engine
    std::unique_ptr<GuardianEngine> engine;
    std::mutex sent_mu;
    std::vector<OutboxEntry> sent;

    /// `periodic_bound_ms > 0` pins the drain worker's backstop before it is constructed,
    /// so a test can attribute a page to the reconnect kick rather than the backstop.
    /// `backend_op_deadline`, when set, shrinks GuardianSparkRuntime::Config's bounded
    /// arm/disarm wait (production default 5s) so a test can drive a deterministic
    /// "backend parked" scenario without a real multi-second wait (rung 9c PR-2:
    /// set_spark_backend_op_deadline_for_test, guardian_engine.hpp). `mechanism_type`
    /// (#4685) defaults to Service, unchanged for every existing call site - a test
    /// wanting Registry parity for a fake-mechanism scenario passes
    /// SparkType::Registry and builds its rules with make_registry_rule() instead of
    /// make_service_rule(); FakeServiceMechanism is entirely type-agnostic (its
    /// watch()/unwatch() do not look at which SparkType it is registered under), so
    /// this changes only what the fixture registers it AS, nothing else.
    explicit SparkReconcileFixture(std::uint64_t periodic_bound_ms = 0,
                                   std::optional<std::chrono::milliseconds> backend_op_deadline = std::nullopt,
                                   SparkType mechanism_type = SparkType::Service,
                                   bool with_registry_sibling = false) {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));

        auto mech = std::make_unique<FakeServiceMechanism>();
        mechanism = mech.get();
        REQUIRE(spark_engine.register_mechanism(mechanism_type, std::move(mech)).has_value());
        if (with_registry_sibling) {
            REQUIRE(mechanism_type != SparkType::Registry);
            auto sib = std::make_unique<FakeServiceMechanism>();
            sibling_mechanism = sib.get();
            REQUIRE(spark_engine.register_mechanism(SparkType::Registry, std::move(sib)).has_value());
        }
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

TEST_CASE("#5168: boot re-arm of more Service rules than the compensating-disarm reservation "
          "holds arms every rule - the surplus is parked and redriven and never left unenforced",
          "[spark][guardian][reconcile][boot]") {
    // Service reservation capacity == GuardianIoExecutor::Config{}.service_quota == 3.
    // Before #5168 the 4th+ rule of a cached policy was REFUSED synchronously at boot
    // ("compensating-disarm reservation exhausted") and stayed unenforced until the
    // next policy push. The park-all gate holds the first three arms in watch(), so
    // the pool is deterministically exhausted while the remaining three are attached.
    constexpr int kRules = 6;
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};
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
        for (int i = 0; i < kRules; ++i)
            *p.add_rules() = make_service_rule("r" + std::to_string(i), true,
                                               "Svc" + std::to_string(i));
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        REQUIRE(yuzu::test::spin_until(
            [&] {
                engine.journal_maintenance_tick();
                return engine.spark_armed_rule_count() == kRules;
            },
            std::chrono::seconds(30)));
        engine.stop();
        spark_engine.stop();
    }

    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    auto* mechanism = mech.get(); // borrowed; owned by spark_engine
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    mechanism->set_park_all_watches();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    // Declared AFTER engine so it runs BEFORE engine's destructor: a failed REQUIRE below
    // must not leave watch() parked while engine.stop() waits on the workers.
    struct Release {
        FakeServiceMechanism* m;
        ~Release() { m->release_park_all(); }
    } release_guard{mechanism};
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.start_local().has_value());
    REQUIRE(engine.rule_count() == kRules);

    auto* rt = engine.spark_runtime_for_test();
    REQUIRE(rt != nullptr);
    // Three arms hold the whole Service quota and reservation; the other three are
    // parked (not failed): nothing armed yet, nothing left unenforced-for-good.
    // watch() is per-type-serialised (spark_mechanism.hpp), so only ONE of the three
    // admitted arms is inside the fake at a time; the other two wait on that lock
    // while still holding their quota slot and reservation permit.
    REQUIRE(yuzu::test::spin_until([&] { return mechanism->parked_watch_count() == 1; }));
    REQUIRE(yuzu::test::spin_until([&] { return rt->arms_parked() == 3; }));
    CHECK(mechanism->watch_call_count() == 1);
    CHECK(rt->compensation_reservation_refused() == 3);
    CHECK(rt->arms_parked_total() == 3);
    CHECK(engine.spark_armed_rule_count() == 0);

    mechanism->release_park_all();
    REQUIRE(yuzu::test::spin_until([&] { return engine.spark_armed_rule_count() == kRules; }));
    CHECK(mechanism->watch_call_count() == kRules);
    CHECK(mechanism->watching_count() == kRules);
    CHECK(rt->arms_parked() == 0);
    CHECK(engine.armed_guard_count() == 0);
    // The rules stay armed: a maintenance tick (which also runs the claim-deadline
    // expiry pass) must not re-expire or tear down anything.
    engine.journal_maintenance_tick();
    CHECK(engine.spark_armed_rule_count() == kRules);
    CHECK(mechanism->watching_count() == kRules);

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("#5168: with the production default (prefer_spark false) no rule reaches the spark "
          "runtime, so nothing is ever parked",
          "[spark][guardian][reconcile][boot]") {
    // The parked-arm path lives in the spark arm path, which production leaves off (the
    // two-argument GuardianEngine constructor, agent.cpp). This pins that the change is
    // dormant there: the changelog and design docs scope the fix to the spark backend.
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    auto* mechanism = mech.get(); // borrowed; owned by spark_engine
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test"};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Retain; });
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    for (int i = 0; i < 6; ++i)
        *p.add_rules() = make_service_rule("d" + std::to_string(i), true, "Svc" + std::to_string(i));
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                .exit_code == 0);
    auto* rt = engine.spark_runtime_for_test();
    REQUIRE(rt != nullptr);
    // Spark arms are asynchronous, so an immediate read proves nothing: give a spark arm
    // (which would reach the mechanism within milliseconds) time to show itself. A
    // negative assertion, so a bounded sleep is the honest tool here.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    engine.journal_maintenance_tick();
    CHECK(mechanism->watch_call_count() == 0); // nothing reached the spark mechanism
    CHECK(rt->arms_parked_total() == 0);
    CHECK(rt->arms_parked() == 0);
    CHECK(engine.spark_armed_rule_count() == 0);
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

// #5403 export half, through the REAL GuardianEngine + SparkEngine + runtime: a Disarm whose
// mechanism unwatch() is parked is reported by the engine's heartbeat accessors, aged with a
// synthetic `now` (never a sleep), latched once past the observation threshold, and gone from
// the age export when the call completes. The runtime-level semantics have their own tests in
// test_guardian_spark_runtime.cpp; this one proves the engine forwards them and that the
// agent's real emitters turn them into the pinned tags.
TEST_CASE("#5403: the engine exports a hung Disarm's age and deadline count as heartbeat tags, "
          "and the age disappears on completion",
          "[spark][guardian][reconcile][liveness][disarm]") {
    SparkReconcileFixture f;
    // Release the parked mechanism on EVERY exit path, declared after `f` so it runs BEFORE
    // the fixture tears down SparkEngine/GuardianEngine (same rationale as the #2233 test).
    struct ReleaseHangOnExit {
        SparkReconcileFixture& fx;
        ~ReleaseHangOnExit() { fx.mechanism->release_hang(); }
    };
    ReleaseHangOnExit release_parked{f};

    f.apply(make_service_rule("r1"));
    REQUIRE(f.mechanism->watching_count() == 1);

    // Quiet agent: no Disarm pending, so BOTH exports are silent (the age is absent, not 0).
    CHECK_FALSE(f.engine->oldest_pending_disarm_age_seconds().has_value());
    CHECK(f.engine->disarm_deadline_elapsed() == 0);
    {
        // Through the SAME helper agent.cpp's heartbeat calls (not a hand-assembled copy).
        std::map<std::string, std::string> tags;
        yuzu::agent::collect_guardian_spark_health_tags(*f.engine, tags,
                                                         std::chrono::steady_clock::now());
        CHECK(tags.empty());
    }

    f.mechanism->hang_next_unwatch();
    // full_sync with the rule disabled: detach_all() -> off-lock Disarm -> parked unwatch().
    auto dr = f.dispatch_raw(make_service_rule("r1", /*enabled=*/false));
    REQUIRE(dr.exit_code == 0);
    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));

    // Pending: the age is present (young, so it floors to a small whole number of seconds).
    REQUIRE(f.engine->oldest_pending_disarm_age_seconds().has_value());
    // Synthetic clock, no sleep: 95 s after now the same claim reads at least 95 whole seconds.
    const auto later = std::chrono::steady_clock::now() + std::chrono::seconds(95);
    const auto aged = f.engine->oldest_pending_disarm_age_seconds(later);
    REQUIRE(aged.has_value());
    CHECK(*aged >= 95);
    // A `now` that predates the claim clamps to zero rather than wrapping.
    const auto before = f.engine->oldest_pending_disarm_age_seconds(
        std::chrono::steady_clock::time_point{});
    REQUIRE(before.has_value());
    CHECK(*before == 0);

    // Latch: a pass 31 s on observes the Disarm pending past the threshold, once.
    REQUIRE(f.engine->spark_runtime_for_test() != nullptr);
    const auto thirty_one = std::chrono::steady_clock::now() + std::chrono::seconds(31);
    f.engine->spark_runtime_for_test()->expire_overdue_claims_at_for_test(thirty_one);
    f.engine->spark_runtime_for_test()->expire_overdue_claims_at_for_test(thirty_one + std::chrono::seconds(5));
    CHECK(f.engine->disarm_deadline_elapsed() == 1);

    {
        std::map<std::string, std::string> tags;
        yuzu::agent::collect_guardian_spark_health_tags(*f.engine, tags, later);
        REQUIRE(tags.count("yuzu.guardian_disarm_pending_age_seconds") == 1);
        CHECK(std::stoull(tags.at("yuzu.guardian_disarm_pending_age_seconds")) >= 95);
        CHECK(tags.at("yuzu.guardian_disarm_deadline_elapsed") == "1");
    }

    // Completion: the call returns, the claim pops, the age export disappears. The
    // cumulative count is not undone.
    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until(
        [&] { return !f.engine->oldest_pending_disarm_age_seconds(later).has_value(); },
        std::chrono::seconds(10)));
    CHECK(f.engine->disarm_deadline_elapsed() == 1);
    // The age is gone; the cumulative count is not, so exactly that one tag remains.
    std::map<std::string, std::string> after;
    yuzu::agent::collect_guardian_spark_health_tags(*f.engine, after,
                                                     std::chrono::steady_clock::now());
    CHECK(after.count("yuzu.guardian_disarm_pending_age_seconds") == 0);
    CHECK(after.size() == 1);
    CHECK(after.at("yuzu.guardian_disarm_deadline_elapsed") == "1");
}

// #5404 export half, through the REAL GuardianEngine + runtime: the engine's claim-lifecycle
// snapshot is all-zero on a healthy engine (so the sparse emitter ships NO tag), and a counter
// the runtime bumps through its own production path reaches the snapshot and the pinned tag.
// The accessor -> field mapping itself is pinned in test_guardian_health_heartbeat.cpp; this
// proves the engine reads the wired runtime and forwards it.
TEST_CASE("#5404: the engine's claim-lifecycle snapshot is silent when healthy and carries a "
          "runtime counter bumped through the ack-drain tick",
          "[spark][guardian][reconcile][claim]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1")); // a live armed rule: the healthy steady state
    REQUIRE(f.mechanism->watching_count() == 1);

    {
        const auto quiet = f.engine->spark_claim_health_stats();
        CHECK(quiet.orphan_disarms_started == 0);
        CHECK(quiet.dead_watchers_erased_on_lost == 0);
        CHECK(quiet.tombstones_released_by_reaper == 0);
        CHECK(quiet.claim_index_release_failures == 0);
        CHECK(quiet.claim_drain_failures == 0);
        CHECK(quiet.retained_tombstones == 0);
        CHECK(quiet.detach_sweep_left_residue == 0);
        CHECK(quiet.detach_claim_failures == 0);
        CHECK(quiet.detach_post_commit_failures == 0);
        CHECK(quiet.claims_dropped_at_stop == 0);
        CHECK(quiet.ack_maint_exceptions == 0);
        CHECK(f.engine->ack_maint_exceptions() == 0);
        std::map<std::string, std::string> tags;
        yuzu::agent::emit_guardian_health_heartbeat_tags(tags, quiet);
        CHECK(tags.empty()); // sparse: a healthy engine reports nothing
    }

    // The runtime's orphan pass (inside the ack-drain tick's expiry call) throws once at its
    // top; the runtime contains it and counts it in claim_drain_failures. Nothing else moves.
    REQUIRE(f.engine->spark_runtime_for_test() != nullptr);
    f.engine->spark_runtime_for_test()->set_drain_fault_point_for_test(15);
    f.engine->journal_maintenance_tick();
    CHECK(f.engine->spark_runtime_for_test()->claim_drain_failures() == 1);

    const auto stats = f.engine->spark_claim_health_stats();
    CHECK(stats.claim_drain_failures == 1);
    CHECK(stats.orphan_disarms_started == 0);
    CHECK(stats.claim_index_release_failures == 0);
    CHECK(stats.detach_claim_failures == 0);
    CHECK(stats.ack_maint_exceptions == 0); // the runtime contained it; the ack firewall did not
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_guardian_health_heartbeat_tags(tags, stats);
    REQUIRE(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_claim_drain_failures") == "1");
}

TEST_CASE("#5404: an engine with no Spark runtime wired reports an all-zero claim-lifecycle "
          "snapshot",
          "[spark][guardian][reconcile][claim]") {
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
    REQUIRE(engine.start_local().has_value()); // never wire_spark_engine()'d: no runtime
    CHECK(engine.spark_runtime_for_test() == nullptr);
    const auto s = engine.spark_claim_health_stats();
    CHECK(s.claim_drain_failures == 0);
    CHECK(s.retained_tombstones == 0);
    CHECK(s.ack_maint_exceptions == 0);
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_guardian_health_heartbeat_tags(tags, s);
    CHECK(tags.empty());
    engine.stop();
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

// ---------------------------------------------------------------------------
// #4472 compensation hold, engine level (re-based on #5459 option D). An operator withdraws a
// rule whose arm is hung and re-adds the identical rule while the arm's late success is
// compensated: the late success lands after the withdrawal (so it is disarmed, not adopted) and
// its compensating disarm is parked inside unwatch(). The re-add re-observes the same retained
// Wedged claim and the generation is held. The server's identical re-pushes then arrive while the
// compensating teardown is outstanding: each is SUPPRESSED (the ledger retains the claim as
// compensation-pending), so none pays a teardown or a new watch(), and none acknowledges. The
// disarm then finishes and pops the claim with no replacement arm; the next push is a Reapply.
// Pass condition: the generation is NOT acknowledged while the disarm is outstanding, the held
// pushes cost the mechanism nothing, AND the rule ends armed on the mechanism. The runtime-level
// twin (test_guardian_spark_runtime.cpp, "#4472: ...") drives the same ledger decision with the
// late success landing inside a single full_sync's detach_all / re-attach window, which an
// engine test cannot park.
// ---------------------------------------------------------------------------
namespace {
// These two mirror guardian_engine.cpp's file-local kKvNamespace / kKeyGen (the on-disk
// layout of the persisted generation); a rename there must be mirrored here.
constexpr std::string_view kGuardianKvNamespace5459 = "__guardian__";
constexpr std::string_view kGuardianGenerationKey5459 = "meta:policy_generation";

/// `finish_disarm_before_drain` false: the compensating disarm is still parked when the fourth
/// identical application's heartbeat drain runs (the repro). True: it is released after that
/// application's re-attach but before the drain (the control).
void run_post_k_4472_scenario(bool finish_disarm_before_drain) {
    using namespace std::chrono_literals;
    SparkReconcileFixture f;
    struct ReleaseOnExit {
        SparkReconcileFixture& fx;
        ~ReleaseOnExit() {
            fx.mechanism->release_isolated_unwatch_hang();
            fx.mechanism->release_hang();
        }
    };
    ReleaseOnExit release_parked{f};

    const auto push = [&](std::uint64_t generation, bool with_rule) {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(generation);
        if (with_rule)
            *p.add_rules() = make_service_rule("r1");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    };
    const auto drain_pending = [&] {
        REQUIRE(yuzu::test::spin_until(
            [&] {
                f.engine->journal_maintenance_tick();
                return f.engine->ack_pending_count_for_test() == 0;
            },
            10s));
    };

    // The arm hangs inside the mechanism; the synthetic clock expires its claim to a retained
    // Wedged head without any wait. Generation 5 is held.
    f.mechanism->hang_next_watch();
    push(5, true);
    REQUIRE(f.mechanism->wait_entered_hang(30s));
    REQUIRE(f.engine->spark_runtime_for_test() != nullptr);
    REQUIRE(f.engine->spark_runtime_for_test()->expire_overdue_claims_at_for_test(
                std::chrono::steady_clock::now() + 600s) == 1);
    drain_pending();
    REQUIRE(f.engine->policy_generation() == 0);

    // Withdrawal (full_sync omitting r1): the wedge is deactivated. Then the hung arm returns its
    // subscription; with the rule no longer wanted it is compensated, and that disarm parks.
    push(6, false);
    drain_pending();
    f.mechanism->hang_next_unwatch_isolated();
    f.mechanism->release_hang();
    REQUIRE(f.mechanism->wait_entered_isolated_unwatch(30s));

    // The identical re-add (the one real application: it re-observes the retained claim), then
    // three more identical pushes, each followed by the heartbeat drain. While the compensating
    // teardown is outstanding each of those three is SUPPRESSED by decide_retry(): the open
    // application survives (pending 0 / failed 1), and the mechanism sees no new watch() and no
    // unwatch() completing. In the control the teardown is released AFTER the fourth push is
    // decided, so that push is suppressed too.
    int watches_after_readd = 0;
    int unwatches_after_readd = 0;
    for (int i = 0; i < 4; ++i) {
        push(7, true);
        if (i > 0) {
            const auto s = f.engine->arm_stats();
            REQUIRE(s.has_value());
            CHECK(s->pending == 0); // no new application was opened: the push was suppressed
            CHECK(s->failed == 1);  // the compensating wedge is still the open failure
            CHECK(f.mechanism->watch_call_count() == watches_after_readd);
            CHECK(f.mechanism->unwatch_completed_count() == unwatches_after_readd);
        }
        if (i == 3 && finish_disarm_before_drain) {
            f.mechanism->release_isolated_unwatch_hang();
            REQUIRE(yuzu::test::spin_until([&] { return f.engine->active_io_workers() == 0; }, 10s));
        }
        drain_pending();
        if (i == 0) {
            watches_after_readd = f.mechanism->watch_call_count();
            unwatches_after_readd = f.mechanism->unwatch_completed_count();
        }
        if (i < 3)
            REQUIRE(f.engine->policy_generation() < 7);
    }

    // (a) With the disarm outstanding the generation must not have been acknowledged, or the
    // server stops re-sending (agent_gen >= current). In the control it is held too: the claim
    // is popped, the wedge is no longer outstanding, and the counted failure still holds the
    // generation (nothing acknowledges it; only a later successful application can).
    const bool acknowledged = f.engine->policy_generation() >= 7;
    CHECK_FALSE(acknowledged);
    if (finish_disarm_before_drain)
        REQUIRE_FALSE(acknowledged); // the retry below is only owed (and modelled) in this case

    // The disarm completes; the compensated claim is popped.
    f.mechanism->release_isolated_unwatch_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->active_io_workers() == 0; }, 10s));

    // (b) With an acknowledged generation nothing re-sends the rule; with a held one the server's
    // identical retry arrives. Either way the rule must end armed on the mechanism.
    if (!acknowledged) {
        push(7, true);
        REQUIRE(yuzu::test::spin_until(
            [&] {
                f.engine->journal_maintenance_tick();
                return f.engine->ack_pending_count_for_test() == 0 &&
                       f.engine->active_io_workers() == 0;
            },
            10s));
    }
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.mechanism->watching_count() == 1);
    // The heal is exactly ONE fresh arm after the pop (the original hung arm's watch() plus the
    // replacement), never a leaked second dispatch while the compensation was outstanding.
    CHECK(f.mechanism->watch_call_count() == 2);
    // The scenario's end state: the rule is armed, so the held generation is finally
    // acknowledged by the heartbeat tick AND durably stored (the same final check the [5459]
    // rig tests make).
    REQUIRE(yuzu::test::spin_until(
        [&] {
            f.engine->journal_maintenance_tick();
            return f.engine->policy_generation() == 7;
        },
        10s));
    const auto stored = f.kv->get(kGuardianKvNamespace5459, kGuardianGenerationKey5459);
    REQUIRE(stored.has_value());
    CHECK(std::stoull(*stored) == 7);
}
} // namespace

TEST_CASE("#4472: a compensating disarm still outstanding at the heartbeat drain is never "
          "acknowledged, the held pushes are suppressed, and the rule must end armed",
          "[spark][guardian][reconcile][liveness][4472]") {
    run_post_k_4472_scenario(/*finish_disarm_before_drain=*/false);
}

TEST_CASE("#4472 control: a compensating disarm that finished before the heartbeat drain holds "
          "the generation, and the retry arms the rule",
          "[spark][guardian][reconcile][liveness][4472]") {
    run_post_k_4472_scenario(/*finish_disarm_before_drain=*/true);
}

// #4472 export half, through the REAL GuardianEngine + SparkEngine + runtime: a compensating
// teardown whose mechanism unwatch() is parked is reported by the engine's heartbeat accessors
// (an age from the instant the compensation became owed, never a plain-Disarm age), aged with a
// synthetic `now` (never a sleep), latched once past its deadline, and gone from the age export
// when the teardown completes. The agent's real emitters turn them into the pinned tags.
TEST_CASE("#4472: the engine exports an outstanding compensating teardown's age and deadline "
          "count as heartbeat tags, and the age disappears on completion",
          "[spark][guardian][reconcile][liveness][4472]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f;
    struct ReleaseOnExit {
        SparkReconcileFixture& fx;
        ~ReleaseOnExit() {
            fx.mechanism->release_isolated_unwatch_hang();
            fx.mechanism->release_hang();
        }
    };
    ReleaseOnExit release_parked{f};

    const auto push = [&](std::uint64_t generation, bool with_rule) {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(generation);
        if (with_rule)
            *p.add_rules() = make_service_rule("r1");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    };
    const auto drain_pending = [&] {
        REQUIRE(yuzu::test::spin_until(
            [&] {
                f.engine->journal_maintenance_tick();
                return f.engine->ack_pending_count_for_test() == 0;
            },
            10s));
    };
    const auto emit_tags = [&](std::chrono::steady_clock::time_point now) {
        // The SAME helper agent.cpp's heartbeat calls, not a hand-assembled copy.
        std::map<std::string, std::string> tags;
        yuzu::agent::collect_guardian_spark_health_tags(*f.engine, tags, now);
        return tags;
    };

    // Quiet agent: both exports are silent (the age is absent, not 0).
    CHECK_FALSE(f.engine->oldest_outstanding_compensation_age_seconds().has_value());
    CHECK(emit_tags(std::chrono::steady_clock::now()).empty());

    // A hung arm that wedges, a withdrawal, then the arm's late success: compensated, and that
    // disarm parks inside unwatch().
    f.mechanism->hang_next_watch();
    push(5, true);
    REQUIRE(f.mechanism->wait_entered_hang(30s));
    REQUIRE(f.engine->spark_runtime_for_test() != nullptr);
    REQUIRE(f.engine->spark_runtime_for_test()->expire_overdue_claims_at_for_test(
                std::chrono::steady_clock::now() + 600s) == 1);
    drain_pending();
    // A hung arm is not a compensation: still nothing to export.
    CHECK_FALSE(f.engine->oldest_outstanding_compensation_age_seconds().has_value());
    push(6, false);
    drain_pending();
    f.mechanism->hang_next_unwatch_isolated();
    f.mechanism->release_hang();
    REQUIRE(f.mechanism->wait_entered_isolated_unwatch(30s));

    // Pending: present, young; a plain-Disarm age is absent (this is an Arm claim's teardown).
    REQUIRE(f.engine->oldest_outstanding_compensation_age_seconds().has_value());
    CHECK_FALSE(f.engine->oldest_pending_disarm_age_seconds().has_value());
    const auto later = std::chrono::steady_clock::now() + 95s;
    const auto aged = f.engine->oldest_outstanding_compensation_age_seconds(later);
    REQUIRE(aged.has_value());
    CHECK(*aged >= 95);
    const auto before =
        f.engine->oldest_outstanding_compensation_age_seconds(std::chrono::steady_clock::time_point{});
    REQUIRE(before.has_value());
    CHECK(*before == 0);

    // Latch: two passes well past the deadline observe it once.
    const auto far_future = std::chrono::steady_clock::now() + 3600s;
    f.engine->spark_runtime_for_test()->expire_overdue_claims_at_for_test(far_future);
    f.engine->spark_runtime_for_test()->expire_overdue_claims_at_for_test(far_future + 5s);
    {
        const auto tags = emit_tags(later);
        REQUIRE(tags.count("yuzu.guardian_compensation_pending_age_seconds") == 1);
        CHECK(std::stoull(tags.at("yuzu.guardian_compensation_pending_age_seconds")) >= 95);
        REQUIRE(tags.count("yuzu.guardian_compensation_deadline_elapsed") == 1);
        CHECK(tags.at("yuzu.guardian_compensation_deadline_elapsed") == "1");
        CHECK(tags.count("yuzu.guardian_disarm_pending_age_seconds") == 0);
    }

    // Completion: the teardown returns, the claim pops, the age export disappears; the
    // cumulative count is not undone.
    f.mechanism->release_isolated_unwatch_hang();
    REQUIRE(yuzu::test::spin_until(
        [&] { return !f.engine->oldest_outstanding_compensation_age_seconds(later).has_value(); },
        10s));
    const auto after = emit_tags(later);
    CHECK(after.count("yuzu.guardian_compensation_pending_age_seconds") == 0);
    CHECK(after.at("yuzu.guardian_compensation_deadline_elapsed") == "1");
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
    // nothing-outstanding fix does not itself depend on rule count or content (proven
    // independently, rule-content-free, by the ledger-level "decide_retry(): no pending
    // receipts and no retained outstanding work is Reapply" unit test in
    // test_guardian_arm_ack.cpp) - but a selective-KV-fault test
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
// #5459 (option D) - a still-hung arm HOLDS its generation; it is never acknowledged.
//
// History: rung 9c PR-5e (#4221, K-bound closeout) acknowledged a persistently Wedged-only
// rule after three identical server retries. The server then stopped re-pushing
// (agent_gen >= current), so if the parked call later FAILED, its completion callback popped
// the claim with no replacement arm and the rule was desired, acknowledged and unarmed
// (#5459). The waiver is DELETED: the generation stays honestly HELD, the server's re-push
// keeps arriving, and GuardianArmAckLedger::decide_retry() Suppresses each identical held push
// (no teardown, no re-arm, no new watch()) for as long as the wedge (or its compensating
// teardown) is outstanding, up to kWedgeSuppressMaxDecisions, then forces ONE Reapply.
// When the wedged claim pops, the next push is a Reapply and the rule re-arms.
//
// These cases live in the engine fixture because the ownership question is the ENGINE's:
// nothing at the runtime or ledger level can say whether the rule ends armed once the held
// generation is finally acknowledged, only the real GuardianEngine + SparkEngine + mechanism
// can. Every end-state assertion is about the rule's LIVE subscription (right key, once, on a
// fresh incarnation), never about a counter.
//
// What "live subscription for the correct rule and incarnation" means in this fixture: the
// runtime holds r1 (spark_armed_rule_count), the mechanism is watching exactly the key the
// first arm was for (not a sibling's, not a second key), the runtime's own status accessor
// knows r1, and the replacement arm is exactly one MORE watch() call than the failed one.
// FakeServiceMechanism ignores the incarnation argument, so that last count is the closest
// this fixture gets to "the correct incarnation".
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// How long the maintenance-driven recovery wait may take. The recovery is tick-driven, so a
/// working fix needs a few ticks, not wall time and a passing run exits the poll at once; this
/// bound only caps a failing run, and is the file's usual 10 s so a loaded runner (or the
/// sanitizer scale applied by spin_until) cannot turn a slow worker re-arm into a false red.
constexpr std::chrono::seconds kRecoveryWindow5459{10};

/// The generation every rig push carries (the held one).
constexpr std::uint64_t kHeldGeneration5459 = 5;

struct LateFailureRig5459 {
    SparkReconcileFixture f;
    // Declared AFTER `f` so it destructs FIRST (before the engine is torn down) on every
    // exit path, including a failed REQUIRE: both gates are released, so no parked worker
    // outlives the fixture and engine.reset() cannot wait on a gate nobody will open.
    struct ReleaseGatesOnExit {
        SparkReconcileFixture& fx;
        ~ReleaseGatesOnExit() {
            fx.mechanism->release_isolated_unwatch_hang();
            fx.mechanism->release_hang();
            // A worker still alive after both gates are open is a leak that must not read
            // green. FAIL_CHECK records a failure without throwing (safe in a destructor,
            // including during a failing REQUIRE's unwind) unless the binary runs with
            // Catch2's --abort/-x, which makes it throw (then a real leak terminates the
            // process instead of reporting a red assertion; nothing here uses -x).
            if (auto* rt = fx.engine->spark_runtime_for_test()) {
                const bool drained = yuzu::test::spin_until(
                    [&] { return rt->active_backend_op_workers() == 0; }, std::chrono::seconds(10));
                if (!drained)
                    FAIL_CHECK("LateFailureRig5459: a backend worker was still alive after both "
                               "gates were released (leaked parked worker)");
            }
        }
    } release_gates{f};

    std::string push_bytes;
    std::string key; // the key the hung first arm was for
    /// 1 when the push also carries a healthy sibling "r2", a REGISTRY rule on its own mechanism
    /// (`f.sibling_mechanism`). Mechanism calls are serialised per type, so a Service-type sibling
    /// could not arm while r1's watch() is parked; a Registry one can. r2 arms and commits normally
    /// and is the observable victim of an unwanted teardown + re-arm of the whole push.
    int siblings{0};
    /// #5459 FU-10: 1 when the push also carries a healthy SAME-TYPE sibling "r3" (a second Service
    /// rule, distinct service name so a distinct key, on the SAME mechanism and so under the same
    /// per-type lock as r1). Which of r1/r3 hangs is not fixed: park_and_wedge() hangs the SECOND
    /// watch() to enter the mechanism, so the first commits and is the sibling, whichever rule the
    /// engine's two arm workers reach the type lock with first. `key` is the hung rule's key and
    /// `sibling_key` the committed one.
    bool same_type{false};
    std::string sibling_key;

    explicit LateFailureRig5459(std::uint64_t generation = kHeldGeneration5459,
                                bool with_sibling = false, bool same_type_sibling = false)
        : f(/*periodic_bound_ms=*/0, /*backend_op_deadline=*/std::nullopt, SparkType::Service,
            with_sibling),
          siblings(with_sibling ? 1 : 0), same_type(same_type_sibling) {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(generation);
        *p.add_rules() = make_service_rule("r1");
        if (with_sibling)
            *p.add_rules() = make_registry_rule("r2");
        if (same_type_sibling)
            *p.add_rules() = make_service_rule("r3", true, "Notepad");
        push_bytes = p.SerializeAsString(); // identical bytes on every re-application
    }

    yuzu::agent::GuardianSparkRuntime& runtime() {
        auto* rt = f.engine->spark_runtime_for_test();
        REQUIRE(rt != nullptr);
        return *rt;
    }
    void push() {
        const auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, push_bytes);
        REQUIRE(dr.exit_code == 0);
    }
    /// The generation as DURABLY stored (what a restart would read), not the in-memory value.
    std::optional<std::uint64_t> persisted_generation() {
        const auto v = f.kv->get(kGuardianKvNamespace5459, kGuardianGenerationKey5459);
        if (!v)
            return std::nullopt;
        return static_cast<std::uint64_t>(std::stoull(*v));
    }
    /// The generation is HELD: neither the in-memory nor the durable value has moved.
    void require_generation_held() {
        REQUIRE(f.engine->policy_generation() == 0);
        REQUIRE(persisted_generation().value_or(0) == 0);
    }

    /// Step 1. The first arm ENTERS its real backend call and parks there; its claim is
    /// then expired with a synthetic clock (never a sleep), so the heartbeat drain sees a
    /// retained outstanding Wedged receipt, and generation 5 is held.
    void park_and_wedge() {
        using namespace std::chrono_literals;
        if (same_type)
            f.mechanism->hang_watch_ordinal(2); // the first watch() commits, the second hangs
        else
            f.mechanism->hang_next_watch();
        push();
        REQUIRE(f.mechanism->wait_entered_hang(30s)); // event-driven: the arm is IN watch()
        if (same_type) {
            key = f.mechanism->hung_watch_key();
            sibling_key = f.mechanism->first_watch_key();
            REQUIRE_FALSE(key.empty());
            REQUIRE_FALSE(sibling_key.empty());
            REQUIRE(key != sibling_key);
        } else {
            key = f.mechanism->first_watch_key();
            REQUIRE_FALSE(key.empty());
        }
        if (siblings > 0) {
            // r1's Service arm is the parked one; the Registry sibling's arm commits on its own
            // mechanism and key, independently.
            REQUIRE(yuzu::test::spin_until(
                [&] {
                    return f.sibling_mechanism->watching_count() == 1 &&
                           f.engine->spark_armed_rule_count() == 1;
                },
                10s));
        }
        if (same_type) {
            // The first watch() returned before the second entered, so the sibling's subscription
            // is physically registered; its commit into the runtime is the worker's next step.
            REQUIRE(yuzu::test::spin_until(
                [&] { return f.engine->spark_armed_rule_count() == 1; }, 10s));
            REQUIRE(f.mechanism->watched_snapshot() == std::set<std::string>{sibling_key});
        }
        // Outstanding, and this key really is the claim's key (a wrong key would read 0).
        REQUIRE(f.mechanism->watch_call_count() == (same_type ? 2 : 1));
        REQUIRE(f.mechanism->watching_count() == (same_type ? 1u : 0u));
        // Only r1's hung worker is left alive (a sibling's worker may still be unwinding).
        // Resolved ONCE, outside every poll: runtime() contains a REQUIRE, and a REQUIRE
        // inside a spin_until predicate runs once per poll and inflates the assertion count
        // by a timing-dependent amount.
        auto& rt = runtime();
        REQUIRE(yuzu::test::spin_until([&] { return rt.active_backend_op_workers() == 1; }, 10s));
        REQUIRE(rt.claim_queue_depth_for_test(key) == 1);
        REQUIRE(f.engine->spark_armed_rule_count() ==
                static_cast<std::size_t>(siblings + (same_type ? 1 : 0)));
        REQUIRE(rt.expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() + 600s) == 1);
        REQUIRE(yuzu::test::spin_until(
            [&] {
                f.engine->journal_maintenance_tick();
                return f.engine->ack_pending_count_for_test() == 0;
            },
            10s));
        require_generation_held();
        // The wedge is the one retained failure the ledger's retry suppression keys on.
        const auto s = f.engine->arm_stats();
        REQUIRE(s.has_value());
        REQUIRE(s->failed == 1);
        REQUIRE(s->pending == 0);
    }

    /// One identical server re-push while the generation is still behind, expected to be
    /// SUPPRESSED: the open Application survives (a Reapply would begin a fresh one, whose
    /// arm_stats read pending 1 / failed 0 until its drain), nothing reaches the mechanism
    /// (no new watch(), no unwatch() beyond `unwatch_baseline`), and nothing is acknowledged.
    void suppressed_repush(int unwatch_baseline = 0) {
        REQUIRE(f.engine->policy_generation() < kHeldGeneration5459); // server-like: only while behind
        const int watches_before = f.mechanism->watch_call_count();
        push();
        const auto s = f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0); // no new application: nothing was re-armed
        CHECK(s->failed == 1);  // the wedge's failure is still on the open application
        CHECK(f.mechanism->watch_call_count() == watches_before);
        CHECK(f.mechanism->unwatch_completed_count() == unwatch_baseline);
        CHECK(runtime().claim_queue_depth_for_test(key) == 1); // the same claim, still outstanding
        f.engine->journal_maintenance_tick();
        require_generation_held();
    }
    void suppressed_repushes(int n) {
        for (int i = 0; i < n; ++i)
            suppressed_repush();
    }

    /// Wait until the released call's completion callback has FINISHED: the worker has
    /// returned and the claim is gone from its key's FIFO. Event-driven; no tick involved.
    void await_late_result_landed() {
        using namespace std::chrono_literals;
        auto& rt = runtime(); // once, outside the poll (runtime() holds a REQUIRE)
        REQUIRE(yuzu::test::spin_until(
            [&] {
                return rt.active_backend_op_workers() == 0 && rt.claim_queue_depth_for_test(key) == 0;
            },
            10s));
    }

    /// After the late FAILURE has popped the claim: a bounded number of maintenance ticks (a
    /// count, not a wait) neither arm the rule nor acknowledge the generation. The recovery
    /// owner is the server's next re-push, and it is owed precisely because the generation
    /// is still held.
    void require_unarmed_and_still_held_after_failure() {
        for (int i = 0; i < 20; ++i)
            f.engine->journal_maintenance_tick();
        REQUIRE(f.engine->spark_armed_rule_count() == 0);
        REQUIRE(f.mechanism->watching_count() == 0);
        require_generation_held();
    }

    [[nodiscard]] bool has_live_subscription() {
        return f.engine->spark_armed_rule_count() == 1 && f.mechanism->watching_count() == 1;
    }
    /// Drive ONLY the heartbeat maintenance tick until the rule has a live subscription or
    /// the window closes. Returns whether it got there; the caller asserts the individual
    /// signals so a failure names the one that is missing.
    bool recovers_by_maintenance_only() {
        return yuzu::test::spin_until(
            [&] {
                f.engine->journal_maintenance_tick();
                return has_live_subscription();
            },
            kRecoveryWindow5459);
    }
    /// The end state: r1 is armed for the right key, once, and on a fresh incarnation
    /// (`expected_watch_calls` counts every watch() including the failed first one).
    void check_live_correct_subscription(int expected_watch_calls) {
        REQUIRE(f.engine->spark_armed_rule_count() == 1); // the runtime holds r1 (not just rule_count())
        CHECK(f.mechanism->watching_count() == 1);
        CHECK(f.mechanism->watched_snapshot() == std::set<std::string>{key}); // THIS rule's key
        CHECK(runtime().status_for_rule("r1").has_value());
        CHECK(runtime().armed_key_count() == 1);
        CHECK(f.mechanism->watch_call_count() == expected_watch_calls);
        // A stale or doubled subscription would leave the failed arm's key still registered
        // elsewhere or more watchers than keys; one key, one watcher is the whole picture.
    }
    /// The held generation is acknowledged AND durably stored - and only after the rule is
    /// live (the callers assert the subscription first).
    void require_acknowledged_after_arm(std::uint64_t generation = kHeldGeneration5459) {
        REQUIRE(yuzu::test::spin_until(
            [&] {
                f.engine->journal_maintenance_tick();
                return f.engine->policy_generation() == generation;
            },
            std::chrono::seconds(10)));
        REQUIRE(persisted_generation().has_value());
        CHECK(*persisted_generation() == generation);
    }
    /// The server's next re-push after a late failure, sent because the agent still reports a
    /// generation behind its own: the rule re-arms through the normal path, and only THEN is
    /// the generation acknowledged and persisted.
    void repush_rearms_then_acknowledges(int expected_watch_calls) {
        REQUIRE(f.engine->policy_generation() < kHeldGeneration5459);
        push();
        REQUIRE(recovers_by_maintenance_only());
        check_live_correct_subscription(expected_watch_calls);
        require_acknowledged_after_arm();
    }
};

} // namespace

TEST_CASE("#5459 held generation: identical pushes while a hung arm is outstanding are "
          "SUPPRESSED (no teardown, no new watch(), a healthy sibling untouched), never "
          "acknowledged; the safety valve forces one Reapply that re-observes the SAME claim, "
          "then suppression resumes",
          "[spark][guardian][reconcile][liveness][5459][5459held]") {
    using namespace std::chrono_literals;
    // r1 (Service) hangs; r2 is a healthy sibling (Registry, its own mechanism and key). A
    // teardown + re-arm of the whole push is the cost suppression avoids, and r2 is where that cost
    // is observable: a suppressed push leaves its watch/unwatch counts and its live subscription
    // exactly as they were, while a real Reapply moves both.
    LateFailureRig5459 r{kHeldGeneration5459, /*with_sibling=*/true};
    r.park_and_wedge();
    auto& sib = *r.f.sibling_mechanism;
    const auto sibling_watched = sib.watched_snapshot();
    REQUIRE(sibling_watched.size() == 1);
    REQUIRE(sib.watch_call_count() == 1);
    REQUIRE(sib.unwatch_completed_count() == 0);

    // Held: every identical push up to the budget is Suppressed. The Application survives
    // each one (pending 0 / failed 1), the mechanisms see nothing, nothing is acknowledged.
    r.suppressed_repushes(static_cast<int>(yuzu::agent::kWedgeSuppressMaxDecisions));
    CHECK(r.f.mechanism->watch_call_count() == 1);
    CHECK(r.f.mechanism->unwatch_completed_count() == 0);
    CHECK(sib.watch_call_count() == 1);
    CHECK(sib.unwatch_completed_count() == 0);
    CHECK(sib.watched_snapshot() == sibling_watched); // the sibling's subscription untouched
    CHECK(r.f.engine->spark_armed_rule_count() == 1);

    // Budget exhausted: the NEXT identical push is a forced Reapply - a fresh Application whose
    // re-attach re-observes the SAME retained claim (no new watch(): a forced Reapply does not
    // unstick the worker, it only bounds the dependence on the suppress classification).
    r.push();
    {
        const auto s = r.f.engine->arm_stats();
        REQUIRE(s.has_value());
        // A new Application: r1's re-observed (hung) claim is registered in this application's
        // pending set (its Wedged receipt is already terminal when registered, and it only moves
        // to failed_receipts at the next drain tick, which has not run yet), so r1 contributes
        // pending 1 deterministically. r2's re-arm is a separate worker that may or may not have
        // resolved by now (it did under load: pending 1), so only r1's contribution is asserted
        // here; r2's re-arm is awaited event-driven just below.
        CHECK(s->pending >= 1);
        CHECK(s->failed == 0);
    }
    CHECK(r.f.mechanism->watch_call_count() == 1);
    CHECK(r.f.mechanism->unwatch_completed_count() == 0);
    CHECK(r.runtime().claim_queue_depth_for_test(r.key) == 1); // the very same claim
    // The real Reapply is what moves the sibling: its teardown unwatches r2 and the re-arm
    // watches it again (+1 each).
    REQUIRE(yuzu::test::spin_until(
        [&] {
            return sib.unwatch_completed_count() == 1 && sib.watch_call_count() == 2 &&
                   sib.watching_count() == 1;
        },
        10s));
    CHECK(sib.watched_snapshot() == sibling_watched); // r2 re-armed on its own key
    // Wedge ownership survived the valve: the next drain retains it again, and the generation
    // is STILL held (the valve acknowledges nothing).
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return r.f.engine->ack_pending_count_for_test() == 0;
        },
        std::chrono::seconds(10)));
    {
        const auto s = r.f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
        CHECK(s->pending == 0);
    }
    r.require_generation_held();

    // The budget is back to zero: the following push is Suppressed again, not another Reapply
    // (suppressed_repush asserts no new Service watch() and no Service unwatch; the sibling is
    // checked here).
    r.suppressed_repush();
    CHECK(sib.watch_call_count() == 2);
    CHECK(sib.unwatch_completed_count() == 1);
    CHECK(sib.watched_snapshot() == sibling_watched);

    // The claim was re-owned by the new Application (the rule is active again), so the hung
    // arm's late SUCCESS is still adopted, and only then is the generation acknowledged.
    r.f.mechanism->release_hang();
    r.await_late_result_landed();
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return r.f.engine->spark_armed_rule_count() == 2 && r.f.mechanism->watching_count() == 1;
        },
        kRecoveryWindow5459));
    CHECK(r.f.mechanism->watch_call_count() == 1); // r1 adopted its ORIGINAL arm, no replacement
    CHECK(r.f.mechanism->unwatch_completed_count() == 0);
    CHECK(r.f.mechanism->is_watching(r.key));
    CHECK(sib.watch_call_count() == 2);
    CHECK(sib.unwatch_completed_count() == 1);
    r.require_acknowledged_after_arm();
}

TEST_CASE("#5459 (a): a hung arm that later REFUSES holds its generation, ends armed on the "
          "server's next re-push, and only then is acknowledged",
          "[spark][guardian][reconcile][5459][5459a]") {
    LateFailureRig5459 r;
    r.park_and_wedge();
    r.suppressed_repushes(3); // the held re-pushes while the arm is still hung cost nothing

    // Only now does the parked call return, as a refusal.
    r.f.mechanism->set_late_watch_outcome(FakeServiceMechanism::LateWatchOutcome::Refuse);
    r.f.mechanism->release_hang();
    r.await_late_result_landed();

    // The failure has landed; NOTHING was acknowledged (that is the whole fix) and nothing
    // re-arms by maintenance alone - the owed recovery event is the held generation's re-push.
    r.require_unarmed_and_still_held_after_failure();
    r.repush_rearms_then_acknowledges(/*expected_watch_calls=*/2);
}

TEST_CASE("#5459 (a): a hung arm that later THROWS holds its generation, ends armed on the "
          "server's next re-push, and only then is acknowledged",
          "[spark][guardian][reconcile][5459][5459a]") {
    // A mechanism throw is contained by SparkEngine's watch_guarded() and arrives at the
    // runtime as the same refusal-shaped failure as the case above, NOT as the executor's
    // IoFailure::WorkerThrew (no seam produces that AFTER a parked mechanism call). This case
    // still earns its place: it is the other way a real mechanism fails.
    LateFailureRig5459 r;
    r.park_and_wedge();
    r.suppressed_repushes(3);

    r.f.mechanism->set_late_watch_outcome(FakeServiceMechanism::LateWatchOutcome::Throw);
    r.f.mechanism->release_hang();
    r.await_late_result_landed();

    r.require_unarmed_and_still_held_after_failure();
    r.repush_rearms_then_acknowledges(/*expected_watch_calls=*/2);
}

TEST_CASE("#5459 (b): a hung arm whose late SUCCESS fails to be adopted holds its generation "
          "through the compensating disarm (pushes suppressed), ends armed on the next re-push, "
          "and only then is acknowledged",
          "[spark][guardian][reconcile][5459][5459b]") {
    using namespace std::chrono_literals;
    LateFailureRig5459 r;
    r.park_and_wedge();
    r.suppressed_repushes(2); // pre-compensation: the plain hung-wedge flavour
    REQUIRE_FALSE(r.f.engine->oldest_outstanding_compensation_age_seconds().has_value());

    // The late arm will SUCCEED, but its adoption fails (fault point 12: after index_->add
    // moved the mapping), so on_arm_complete falls to the compensating-disarm path; that
    // disarm is parked on its own isolated gate so the window can be held open.
    r.runtime().set_drain_fault_point_for_test(12); // one-shot, self-clearing
    r.f.mechanism->hang_next_unwatch_isolated();
    r.f.mechanism->release_hang();
    REQUIRE(r.f.mechanism->wait_entered_isolated_unwatch(30s)); // compensation is outstanding

    // The claim is a compensating head now (CompensationPending, not a hung arm). The
    // generation is still held, and the compensating-teardown flavour of the wedge is still
    // tracked by the ledger, so held pushes stay Suppressed across it as well.
    REQUIRE(r.f.engine->oldest_outstanding_compensation_age_seconds().has_value());
    r.require_generation_held();

    // No premature replacement arm while the compensation is outstanding: a bounded number of
    // ticks (a count, not a wait) must not start a second watch(), and the claim is still the
    // key's marker. The held re-pushes meanwhile are suppressed (no teardown, no re-arm).
    for (int i = 0; i < 20; ++i)
        r.f.engine->journal_maintenance_tick();
    CHECK(r.f.mechanism->watch_call_count() == 1);
    CHECK(r.runtime().claim_queue_depth_for_test(r.key) == 1);
    CHECK(r.f.mechanism->unwatch_completed_count() == 0);
    r.suppressed_repushes(3);
    r.require_generation_held();

    // The compensation finishes; the stale subscription is torn down and the claim popped.
    r.f.mechanism->release_isolated_unwatch_hang();
    r.await_late_result_landed();
    CHECK(r.f.mechanism->unwatch_completed_count() == 1);

    r.require_unarmed_and_still_held_after_failure();
    r.repush_rearms_then_acknowledges(/*expected_watch_calls=*/2);
}

TEST_CASE("#5459 control: a hung arm whose late SUCCESS is adopted ends armed with no re-push "
          "and only then acknowledges the held generation (the harness CAN observe a live "
          "subscription)",
          "[spark][guardian][reconcile][5459][5459control]") {
    LateFailureRig5459 r;
    r.park_and_wedge();
    r.suppressed_repushes(2);

    // The same scenario, released into SUCCESS instead of failure. #4508's late-adoption
    // path commits the original subscription, so the recovery drain decrements the failure and
    // the held generation is acknowledged by the maintenance tick alone. No replacement arm:
    // the original watch() is the only one.
    r.require_generation_held(); // still held right up to the release
    r.f.mechanism->release_hang();
    r.await_late_result_landed();
    REQUIRE(r.recovers_by_maintenance_only());
    r.check_live_correct_subscription(/*expected_watch_calls=*/1);
    r.require_acknowledged_after_arm();
    CHECK(r.f.mechanism->unwatch_completed_count() == 0);
}

TEST_CASE("#5459 valve spent, then the late success is adopted: the next identical push is at "
          "most ONE forced Reapply (a teardown and re-arm of the just-armed rule), never an "
          "acknowledgment, and the following ticks acknowledge",
          "[spark][guardian][reconcile][5459][5459valve]") {
    LateFailureRig5459 r;
    r.park_and_wedge();
    r.suppressed_repushes(static_cast<int>(yuzu::agent::kWedgeSuppressMaxDecisions)); // budget spent

    // The hung arm succeeds and nobody withdrew the rule: adopted. NO tick runs between the
    // adoption and the next push, so the ledger still holds the entry as Recovered-but-uncleared.
    r.f.mechanism->release_hang();
    r.await_late_result_landed();
    REQUIRE(r.f.engine->spark_armed_rule_count() == 1);
    REQUIRE(r.f.mechanism->watch_call_count() == 1);
    REQUIRE(r.f.mechanism->unwatch_completed_count() == 0);
    r.require_generation_held();

    // The valve is spent, so this identical push is a forced Reapply: a fresh application, so
    // the stale one's arm_stats (failed 1) is gone, and the push itself acknowledges nothing.
    //
    // The replacement arm is PARKED inside the mechanism for the duration of the push, so the
    // "held, not acknowledged" state is observable deterministically. Without the park the
    // re-armed rule could go live inside the push window and apply_rules would then legitimately
    // acknowledge the generation inline: a timing-dependent outcome under load, not the property
    // under test. (The one-shot hang gate latches open once released, so the re-armable park-all
    // gate is the one to use here.)
    struct ReleaseParkOnExit {
        FakeServiceMechanism& m;
        ~ReleaseParkOnExit() { m.release_park_all(); }
    } release_park{*r.f.mechanism};
    r.f.mechanism->set_park_all_watches();
    r.push();
    REQUIRE(yuzu::test::spin_until([&] { return r.f.mechanism->parked_watch_count() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(r.f.mechanism->watch_call_count() == 2);        // the replacement arm, in flight
    CHECK(r.f.mechanism->unwatch_completed_count() == 1); // the just-armed one was torn down
    CHECK(r.f.engine->spark_armed_rule_count() == 0);
    r.require_generation_held();
    {
        const auto s = r.f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0); // a NEW application (a Suppress would have kept failed == 1)
    }

    // Release the replacement arm. The following ticks acknowledge only once it is live; the
    // whole cost is ONE teardown of the just-armed subscription and ONE replacement watch(),
    // never an acknowledgment of the stale state.
    r.f.mechanism->release_park_all();
    REQUIRE(r.recovers_by_maintenance_only());
    r.check_live_correct_subscription(/*expected_watch_calls=*/2);
    r.require_acknowledged_after_arm();
    CHECK(r.f.mechanism->unwatch_completed_count() == 1);
    CHECK(r.f.mechanism->watch_call_count() == 2);
}

// FU-10 (AC-16, a flip precondition). The per-type mechanism lock is why a Service-type sibling
// cannot arm while one Service watch() is parked, and it is also why the forced Reapply the safety
// valve buys is not free for a healthy same-type sibling: the Reapply's teardown of the sibling,
// and its re-arm, queue behind the hung call. The Registry sibling in [5459held] is on its OWN
// mechanism and so cannot show this; this test puts the sibling on the SAME one.
TEST_CASE("#5459 FU-10 (AC-16): the forced Reapply during a hung same-type watch() withdraws a "
          "healthy same-type sibling; its teardown and re-arm queue behind the hung call, the "
          "re-arm expires CongestionExpired, the generation stays held, and only once the hang is "
          "released and the next push re-arms both rules is it acknowledged",
          "[spark][guardian][reconcile][liveness][5459][5459fu10]") {
    using namespace std::chrono_literals;
    LateFailureRig5459 r{kHeldGeneration5459, /*with_sibling=*/false, /*same_type_sibling=*/true};
    // Declared after `r` so it destructs first: the re-armable park gate is open on every exit path.
    struct ReleaseParkOnExit {
        FakeServiceMechanism& m;
        ~ReleaseParkOnExit() { m.release_park_all(); }
    } release_park{*r.f.mechanism};

    r.park_and_wedge(); // `key` = the hung rule's key, `sibling_key` = the committed same-type one
    auto& m = *r.f.mechanism;
    auto& rt = r.runtime(); // once, outside every poll (runtime() holds a REQUIRE)
    const std::string hung_key = r.key;
    const std::string sib_key = r.sibling_key;
    REQUIRE(r.f.engine->spark_armed_rule_count() == 1); // the sibling is live: the premise
    REQUIRE(m.watch_call_count() == 2);

    // The valve's budget is spent by identical retained-wedge pushes, none of which touches the
    // healthy sibling (the contrast the forced Reapply below breaks).
    r.suppressed_repushes(static_cast<int>(yuzu::agent::kWedgeSuppressMaxDecisions));
    CHECK(m.watch_call_count() == 2);
    CHECK(m.unwatch_completed_count() == 0);
    CHECK(r.f.engine->spark_armed_rule_count() == 1);

    // The forced Reapply: a fresh application whose full_sync teardown withdraws EVERY rule in
    // the push, the healthy sibling included.
    r.push();
    CHECK(r.f.engine->spark_armed_rule_count() == 0); // the sibling's detection is logically off at once
    {
        const auto s = r.f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0); // a NEW application (a Suppress would have kept failed == 1)
    }
    // Its teardown is a real disarm worker, alive but blocked behind the hung call on the same
    // per-type lock, and its re-arm is queued behind that disarm on the same key: two claims.
    REQUIRE(yuzu::test::spin_until([&] { return rt.active_backend_op_workers() == 2; }, 10s));
    CHECK(rt.claim_queue_depth_for_test(sib_key) == 2);
    CHECK(rt.claim_queue_depth_for_test(hung_key) == 1); // the very same hung claim, re-observed
    // Nothing of the sibling's reaches the mechanism while the hang lasts: a bounded number of
    // maintenance ticks (a count, not a wait) neither completes its teardown nor starts its re-arm.
    for (int i = 0; i < 20; ++i)
        r.f.engine->journal_maintenance_tick();
    CHECK(m.unwatch_completed_count() == 0);
    CHECK(m.watch_call_count() == 2);
    CHECK(r.f.engine->spark_armed_rule_count() == 0);
    r.require_generation_held();

    // The re-arm ages past its deadline (a synthetic clock, never a sleep): a QUEUED arm claim is
    // abandoned and ends CongestionExpired. The disarm ahead of it stays, so the key's queue
    // loses exactly the arm claim.
    REQUIRE(rt.expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() + 600s) == 1);
    CHECK(rt.claim_queue_depth_for_test(sib_key) == 1);
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return r.f.engine->ack_pending_count_for_test() == 0;
        },
        10s));
    {
        const auto s = r.f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0);
        CHECK(s->failed == 2); // the hung rule's wedge plus the sibling's expired re-arm
    }
    r.require_generation_held(); // in memory and on disk
    CHECK(m.watch_call_count() == 2);
    CHECK(m.unwatch_completed_count() == 0);

    // The sibling's expiry ENDS the suppression: the application now counts two failures but
    // retains only one wedge, so decide_retry() no longer Suppresses. The next identical push
    // is a real Reapply (detach_all's epoch moves, a new application begins) and re-queues the
    // sibling's re-arm behind its still-pending teardown, instead of the valve's "about every
    // 330 s" for as long as the hang lasts. (Pinned so the docs cannot claim the bound for a
    // push set with a same-type sibling.)
    {
        const auto epoch_before = rt.application_fence_for_test().first;
        r.push();
        CHECK(rt.application_fence_for_test().first == epoch_before + 1);
        const auto s = r.f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0); // a NEW application (a Suppress would have kept failed == 2)
        CHECK(rt.claim_queue_depth_for_test(sib_key) == 2); // the same pending disarm, plus a new re-arm
        CHECK(rt.claim_queue_depth_for_test(hung_key) == 1);
        CHECK(r.f.engine->spark_armed_rule_count() == 0);
        CHECK(m.watch_call_count() == 2); // still queued behind the hung call
        CHECK(m.unwatch_completed_count() == 0);
        r.require_generation_held();
        // That new re-arm ages out like the first one, so the rest of the scenario is unchanged.
        REQUIRE(rt.expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() + 600s) == 1);
        REQUIRE(yuzu::test::spin_until(
            [&] {
                r.f.engine->journal_maintenance_tick();
                return r.f.engine->ack_pending_count_for_test() == 0;
            },
            10s));
        const auto s2 = r.f.engine->arm_stats();
        REQUIRE(s2.has_value());
        CHECK(s2->pending == 0);
        CHECK(s2->failed == 2);
        CHECK(rt.claim_queue_depth_for_test(sib_key) == 1);
        r.require_generation_held();
    }

    // Release the hang. The hung arm's late success is adopted; the sibling's queued teardown
    // now runs (its subscription is finally removed), but its expired re-arm is gone, so the
    // sibling is NOT back, and the generation stays held with it unarmed.
    m.release_hang();
    r.await_late_result_landed();
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return m.unwatch_completed_count() == 1 && r.f.engine->spark_armed_rule_count() == 1;
        },
        kRecoveryWindow5459));
    CHECK(m.watch_call_count() == 2); // no replacement arm for the sibling: its claim expired
    CHECK(m.watched_snapshot() == std::set<std::string>{hung_key});
    for (int i = 0; i < 20; ++i)
        r.f.engine->journal_maintenance_tick();
    r.require_generation_held();

    // The server's next identical re-push is a real Reapply (the sibling's expired arm is a
    // settled failure, not a retained wedge) and re-arms both rules. The re-arms are parked at
    // the mechanism so "held until both are live" is observed, not raced.
    m.set_park_all_watches();
    r.push();
    REQUIRE(yuzu::test::spin_until([&] { return m.parked_watch_count() == 1; }, 10s));
    // Tick while the re-arms are parked. This loop is redundant by construction: both re-arms
    // sit in `pending`, so can_advance() is already false through pending.empty() alone (the
    // tick and the apply_rules tail both gate on it), and an early acknowledgment would
    // already have failed the rig's earlier hold checks. It documents the held state at this
    // phase rather than adding an observation the earlier phases do not make.
    for (int i = 0; i < 20; ++i)
        r.f.engine->journal_maintenance_tick();
    r.require_generation_held();
    CHECK(r.f.engine->spark_armed_rule_count() == 0);
    m.release_park_all();
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return r.f.engine->spark_armed_rule_count() == 2 && m.watching_count() == 2;
        },
        kRecoveryWindow5459));
    CHECK(m.watched_snapshot() == std::set<std::string>{hung_key, sib_key});
    r.require_acknowledged_after_arm();
}

// FU-11 (a flip precondition). A subscription armed LATE (a wedged arm whose late success is
// adopted) must stay live across the next identical push and the following acknowledgment.
// [5459control] and the last phase of [5459held] pin adoption followed by the acknowledgment with
// no push in between, and [5459valve] pins the push when the valve budget is already spent. What
// they leave open, and this test pins: (1) the identical push that lands in the window between the
// adoption and the next heartbeat tick, with the valve budget UNSPENT; (2) the identical push
// that arrives AFTER the acknowledgment (the server may still send one).
TEST_CASE("#5459 FU-11: a subscription armed late stays live across the next identical push and "
          "the following acknowledgment; a re-push after the acknowledgment re-arms it to exactly "
          "one live subscription with the generation still acknowledged",
          "[spark][guardian][reconcile][liveness][5459][5459fu11]") {
    using namespace std::chrono_literals;
    LateFailureRig5459 r;
    r.park_and_wedge();
    r.suppressed_repushes(2); // budget NOT spent: a handful of the kWedgeSuppressMaxDecisions
    auto& m = *r.f.mechanism;
    auto& rt = r.runtime(); // once, outside every poll

    // The hung arm's late success is adopted. NO maintenance tick runs after it, so the ledger
    // still holds the entry as adopted-but-uncleared (the generation is not yet acknowledged).
    m.release_hang();
    r.await_late_result_landed();
    REQUIRE(r.f.engine->spark_armed_rule_count() == 1);
    REQUIRE(m.watch_call_count() == 1);
    REQUIRE(m.unwatch_completed_count() == 0);
    r.require_generation_held();

    // The next identical push: adopted-but-uncleared is outstanding work, so with budget left it
    // is SUPPRESSED, not a teardown. The same application survives (failed 1, nothing pending),
    // the subscription is never withdrawn and no second watch() is made.
    r.push();
    {
        const auto s = r.f.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0);
        CHECK(s->failed == 1); // a Reapply would have begun a new application (failed 0)
    }
    CHECK(m.watch_call_count() == 1);
    CHECK(m.unwatch_completed_count() == 0);
    CHECK(r.f.engine->spark_armed_rule_count() == 1);
    CHECK(m.watched_snapshot() == std::set<std::string>{r.key});
    r.require_generation_held();

    // The following ticks clear the adopted entry and acknowledge, on the ORIGINAL subscription.
    REQUIRE(r.recovers_by_maintenance_only());
    r.check_live_correct_subscription(/*expected_watch_calls=*/1);
    r.require_acknowledged_after_arm();
    CHECK(m.unwatch_completed_count() == 0);

    // After the acknowledgment an identical push can still arrive. Nothing is outstanding, so it
    // is a real Reapply (decide_retry's empty-pending case): the subscription is torn down and
    // re-armed once. The end state is the invariant: one live subscription for the right key
    // (not two), and the generation still acknowledged and durably stored.
    r.push();
    CHECK(r.f.engine->policy_generation() == kHeldGeneration5459); // the push itself never regresses it
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return m.watch_call_count() == 2 && m.unwatch_completed_count() == 1 &&
                   r.has_live_subscription() && rt.active_backend_op_workers() == 0;
        },
        kRecoveryWindow5459));
    r.check_live_correct_subscription(/*expected_watch_calls=*/2);
    CHECK(m.unwatch_completed_count() == 1);
    for (int i = 0; i < 20; ++i)
        r.f.engine->journal_maintenance_tick();
    CHECK(r.f.engine->spark_armed_rule_count() == 1);
    CHECK(m.watching_count() == 1);
    CHECK(m.watch_call_count() == 2); // no duplicate watch
    CHECK(r.f.engine->policy_generation() == kHeldGeneration5459);
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kHeldGeneration5459);
}

TEST_CASE("#5459 valve spent, then the KV store fails mid-push: every push is a real Reapply "
          "while the fault lasts (the rules stay torn down, the generation stays held in memory, "
          "and on disk up to the fault), and once the store is back the next push re-arms every "
          "rule and only then acknowledges",
          "[spark][guardian][reconcile][5459][5459kv]") {
    using namespace std::chrono_literals;
    // r1 hangs (Service); r2 is a healthy sibling on its own mechanism, so a teardown is
    // observable as an armed count that drops.
    LateFailureRig5459 r{kHeldGeneration5459, /*with_sibling=*/true};
    r.park_and_wedge();
    auto& sib = *r.f.sibling_mechanism;
    REQUIRE(r.f.engine->spark_armed_rule_count() == 1); // r2 only; r1 is the hung arm
    r.suppressed_repushes(static_cast<int>(yuzu::agent::kWedgeSuppressMaxDecisions)); // budget spent

    // Before the fault the generation is held both in memory and on disk (a real, readable
    // store: this is the only point at which the on-disk half is meaningful).
    r.require_generation_held();

    // The store fails. The next identical push is the valve's forced Reapply: it tears the
    // active set down (full_sync), then its rule persist fails and the push is refused.
    drop_kv_store_table_for_test(r.f.db_.path);
    const auto fault_push = [&] {
        return yuzu::agent::guardian_dispatch_push_bytes_for_test(*r.f.engine, r.push_bytes);
    };
    for (int i = 0; i < 3; ++i) {
        // i == 0 is the forced Reapply; i > 0 is a Reapply because the failed application
        // latched a failure. Either way the push is NOT suppressed: the sibling stays torn down.
        const auto dr = fault_push();
        CHECK(dr.exit_code != 0);
        CHECK(r.f.engine->spark_armed_rule_count() == 0);
        // The mechanism-side unwatch completes on the teardown's own worker: event-driven wait.
        CHECK(yuzu::test::spin_until([&] { return sib.watching_count() == 0; }, 10s));
        r.f.engine->journal_maintenance_tick();
        CHECK(r.f.engine->policy_generation() == 0); // held in memory (never published)
    }
    // The recreated table is empty, so nothing about the durable value can be read back here;
    // the on-disk half was asserted before the fault, and the acknowledged-and-persisted
    // generation is asserted after recovery below.
    recreate_kv_store_table_for_test(r.f.db_.path);

    // The store is healthy: the next push is applied in full. r1 re-observes its still-hung
    // claim; r2 re-arms. Nothing is acknowledged until every rule is live.
    r.push();
    // Drain BEFORE the hung arm returns, so the ledger retains the re-observed wedge (a wedge
    // first drained after its late success was adopted is the documented one-avoidable-Reapply
    // limit, not what this case is about).
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return r.f.engine->ack_pending_count_for_test() == 0 && sib.watching_count() == 1;
        },
        10s));
    r.require_generation_held();
    r.f.mechanism->release_hang();
    r.await_late_result_landed();
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.f.engine->journal_maintenance_tick();
            return r.f.engine->spark_armed_rule_count() == 2 && r.f.mechanism->watching_count() == 1;
        },
        kRecoveryWindow5459));
    CHECK(r.f.mechanism->is_watching(r.key));
    CHECK(sib.watching_count() == 1);
    r.require_acknowledged_after_arm();
}

// Sub-class 3 of #5459 (the drain-to-persist gap), restated for option D. Under the waiver, a
// drain observed the wedge "eligible", acknowledged the generation, and a completion that landed
// between that observation and the persist stranded the rule. There is no waiver now: once a
// drain has retained a wedge, can_advance() is false whether or not the claim has since popped,
// so a pop between the retaining drain and the next tick changes nothing about acknowledgement.
// Closed by construction, not by timing.
TEST_CASE("#5459 sub-class 3: a pop between the drain that retained a wedge and the next tick "
          "changes nothing, because can_advance() is false either way",
          "[spark][guardian][reconcile][5459][5459subclass3]") {
    LateFailureRig5459 r;
    r.park_and_wedge(); // the drain retained the wedge; the generation is held
    // Land the late failure with NO tick in between (the exact window the waiver lost).
    r.f.mechanism->set_late_watch_outcome(FakeServiceMechanism::LateWatchOutcome::Refuse);
    r.f.mechanism->release_hang();
    r.await_late_result_landed();
    r.require_generation_held();      // checked before ANY further tick has observed the pop
    r.require_unarmed_and_still_held_after_failure(); // and after a bounded run of them
    r.repush_rearms_then_acknowledges(/*expected_watch_calls=*/2);
}

// OPTION D PROBE, NOT PART OF THE REGRESSION SET (hence no [5459] tag). Q1: after the late
// failure has popped the claim, does a FRESH re-attach - a server re-push, which is the one
// event a held generation keeps producing - take the normal arm path and arm the rule? Under D
// it is the recovery owner, so this stays as the minimal statement of that fact, for both a
// same-generation re-push and a distinct next generation.
TEST_CASE("#5459 option D probe (NOT part of the regression set): after the late failure, a "
          "server re-push re-arms the rule",
          "[spark][guardian][reconcile][5459probe]") {
    SECTION("the same generation (what a still-held generation re-pushes)") {
        LateFailureRig5459 r;
        r.park_and_wedge();
        r.f.mechanism->set_late_watch_outcome(FakeServiceMechanism::LateWatchOutcome::Refuse);
        r.f.mechanism->release_hang();
        r.await_late_result_landed();
        r.require_unarmed_and_still_held_after_failure(); // nothing re-arms by itself

        r.push();
        REQUIRE(r.recovers_by_maintenance_only());
        r.check_live_correct_subscription(/*expected_watch_calls=*/2);
        r.require_acknowledged_after_arm();
    }
    SECTION("the next generation (a distinct generation arriving)") {
        LateFailureRig5459 r;
        r.park_and_wedge();
        r.f.mechanism->set_late_watch_outcome(FakeServiceMechanism::LateWatchOutcome::Refuse);
        r.f.mechanism->release_hang();
        r.await_late_result_landed();
        r.require_unarmed_and_still_held_after_failure();

        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(6);
        *p.add_rules() = make_service_rule("r1");
        const auto dr =
            yuzu::agent::guardian_dispatch_push_bytes_for_test(*r.f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
        REQUIRE(r.recovers_by_maintenance_only());
        r.check_live_correct_subscription(/*expected_watch_calls=*/2);
        // The new generation is acknowledged by the NEXT drain after its arm commits.
        r.require_acknowledged_after_arm(6);
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// #4685 — Guardian's capability filter must key off `boot_inert` alone
// (registered, but start() refused to bind the OS facility) rather than the
// UNION `inert` (which also includes a mechanism's TRANSIENT runtime-degraded
// episode - Registry's sweeper / File's worker, three consecutive failed
// passes, cleared on the next success). Before this fix, a reconcile that ran
// during such an episode misclassified every rule of that type Unsupported,
// withdrew it from both backends, and left it stranded there with nothing to
// proactively re-reconcile once the mechanism recovered. `inert` itself is
// UNCHANGED - still the union the heartbeat CSV (spark_heartbeat.hpp) and the
// subscription_establishment() coverage overlay (spark_engine.cpp) read; only
// Guardian's OWN capability filter (guardian_engine.cpp's
// reconcile_rule_locked) narrows to `!boot_inert`.
//
// FakeServiceMechanism is entirely type-agnostic (its watch()/unwatch() never
// look at which SparkType they were registered under), so Registry parity for
// every fake-based case below is a second TEST_CASE registering the SAME kind
// of fake under SparkType::Registry via SparkReconcileFixture's
// `mechanism_type` parameter and building rules with make_registry_rule()
// instead of make_service_rule() - never a second, hand-duplicated
// engine/mechanism wiring block. File's real-mechanism coverage (AC2/AC3) is
// the Windows-only section at the end of this file.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

gpb::GuaranteedStateRule make_rule_for_type(SparkType type, const std::string& id,
                                            bool enabled = true) {
    switch (type) {
    case SparkType::Registry: return make_registry_rule(id, enabled);
    case SparkType::File: return make_file_rule(id, enabled);
    default: return make_service_rule(id, enabled);
    }
}

/// AC8 (scoped per plan §9 must-fix 2 - no rule -> SubscriptionId / establishment-sink
/// test seam exists on FakeServiceMechanism or GuardianEngine, so this stays at what IS
/// testable without inventing one): a runtime-degraded (not boot-inert) mechanism
/// drops out of the heartbeat CSV (the UNION `inert` spark_heartbeat.hpp reads,
/// unchanged by this fix) but stays Guardian-armable (the narrower `!boot_inert`
/// guardian_engine.cpp's capability filter reads, #4685). The union-overlay's own
/// coverage behavior (seed a cached Notification report -> None while inert ->
/// restored Notification on clear, with no new report in between) is ALREADY pinned
/// by "Establishment: an inert mechanism overlays coverage to None..." in
/// test_spark_mechanism.cpp - untouched by this fix, not re-tested here. Also doubles
/// as AC4's "degraded alone (no hang) -> Committed" case via the arm_stats() check
/// below (the hanging variant is the separate Wedged-parity case further down).
void check_runtime_degraded_stays_armable(SparkType type) {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0, std::nullopt, type};
    f.mechanism->set_inert(true); // runtime-degraded (union `inert`); boot_inert stays false

    std::map<std::string, std::string> tags;
    emit_spark_heartbeat_tags(tags, f.spark_engine.is_running(), f.spark_engine.stats(),
                              f.spark_engine.stats_by_type());
    CAPTURE(tags["yuzu.spark_mechs"]);
    CHECK(tags["yuzu.spark_mechs"].find(spark_type_token(type)) == std::string::npos);

    f.apply(make_rule_for_type(type, "r1"));
    CHECK(f.engine->spark_armed_rule_count() == 1); // Arm, not Unsupported
    CHECK(f.engine->unsupported_counts_by_type().count(type) == 0);
    CHECK(f.mechanism->watch_call_count() == 1); // a real watch() was made - never filtered out
    CHECK(f.engine->last_unsupported_log_for_test().edge_count == 0); // never Unsupported

    const auto s = f.engine->arm_stats(); // AC4: Committed, never Wedged/Failed
    REQUIRE(s.has_value());
    CHECK(s->failed == 0);
}

/// AC6: a mechanism that IS registered but BOOT-INERT (start() refused to bind its OS
/// facility) still classifies Unsupported - but the log now distinguishes this from
/// "no mechanism at all" (never emitted for a runtime-only episode, which stays
/// armable and never reaches this branch at all - see
/// check_runtime_degraded_stays_armable above). boot_inert and (union) inert are
/// correlated, not independent, in this case (plan §8) - both are set together. The
/// pre-existing "no mechanism at all -> info" case is already pinned by "an
/// unsupported type arms neither backend..." above - untouched by this fix.
void check_boot_inert_registered_warns(SparkType type) {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0, std::nullopt, type};
    f.mechanism->set_boot_inert(true);
    f.mechanism->set_inert(true);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(7);
    *p.add_rules() = make_rule_for_type(type, "r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watch_call_count() == 0); // never reached watch() at all
    CHECK(f.engine->unsupported_counts_by_type().at(type) == 1);
    CHECK(f.engine->policy_generation() == 7); // Unsupported/Inert still advances generation

    const auto log = f.engine->last_unsupported_log_for_test();
    CHECK(log.level == GuardianEngine::UnsupportedLogLevel::Warn);
    CHECK(log.rule_id == "r1");
    CHECK(log.type == type);
    CHECK(log.edge_count == 1);
}

/// AC7: a runtime-degraded (not boot-inert) mechanism, degraded BEFORE
/// wire_spark_engine()/start_local() run, still Arms a rule cached from a prior boot's
/// KV, in PRODUCTION wiring order (agent.cpp: register_mechanism -> start() ->
/// wire_spark_engine -> start_local(), NOT the fixture's reversed order). Mirrors "a
/// production-order restart reconstructs unsupported_rules_ from cached KV" above,
/// which pins the analogous NO-mechanism-at-all case.
void check_production_order_degraded_still_arms(SparkType type) {
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};

    // Phase 1: persist the rule definition while the mechanism is healthy - only the
    // durable KV row matters here; how phase 1 itself classified the rule is not under
    // test.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        auto mech = std::make_unique<FakeServiceMechanism>();
        REQUIRE(spark_engine.register_mechanism(type, std::move(mech)).has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_rule_for_type(type, "r1");
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        // Settle before stop(): the dispatch's attach is NonWaiting (rung 9c PR-2 Unit
        // 6) - calling stop() while that attempt is still in flight raced a SIGSEGV
        // under repeated seeded reruns (#4685 PR #5021, external adversarial review).
        // Every test whose push actually arms something settles before tearing down
        // (a push that only classifies Unsupported, e.g. :769, never add_pending()s
        // anything, so there's nothing to settle); this Phase-1 block's push arms a
        // rule (its own classification isn't under test) and had skipped it.
        REQUIRE(yuzu::test::spin_until([&] {
            engine.journal_maintenance_tick();
            return engine.ack_pending_count_for_test() == 0 && engine.active_io_workers() == 0;
        }));
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: fresh boot, PRODUCTION order - the mechanism is runtime-degraded BEFORE
    // wire_spark_engine()/start_local() run over the cached rule (#4685 AC7).
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    FakeServiceMechanism* mechanism = mech.get();
    REQUIRE(spark_engine.register_mechanism(type, std::move(mech)).has_value());
    spark_engine.start();
    mechanism->set_inert(true);

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
    REQUIRE(engine.start_local().has_value());

    // start_local()'s re-arm walk dispatches the arm the same NonWaiting way apply_rules()
    // does (rung 9c PR-2 Unit 6) - it does not settle before returning, so wait for the
    // commit rather than asserting immediately (mirrors "start_local degrades per-rule..."
    // above: REQUIRE(spin_until([&] { return engine.spark_armed_rule_count() == 2; })).
    // Also wait for full quiescence (ack_pending_count_for_test()==0 &&
    // active_io_workers()==0), not just the count becoming visible, before this
    // function's own stop() calls below - same class of gap as the AC7 Phase-1
    // SIGSEGV this file's other settle-waits were added to fix (cpp-safety Gate 3,
    // this scoped review round).
    REQUIRE(yuzu::test::spin_until([&] {
        engine.journal_maintenance_tick();
        return engine.spark_armed_rule_count() == 1 && engine.ack_pending_count_for_test() == 0 &&
               engine.active_io_workers() == 0;
    }));

    CHECK(engine.rule_count() == 1);
    CHECK(engine.armed_guard_count() == 0);
    CHECK(engine.unsupported_counts_by_type().count(type) == 0);

    engine.stop();
    spark_engine.stop();
}

/// Direct regression for option (b)'s own failure-mode rationale (plan §8): boot_inert
/// stays false, but the mechanism SYNCHRONOUSLY refuses the watch() call - a genuine
/// arm ATTEMPT that failed, never a misclassification into Unsupported (which would
/// require boot_inert) and never a silent legacy fallback. Distinct from the
/// hanging-watch Wedged case pinned elsewhere in this file: a synchronous refusal
/// resolves Failed immediately, never an outstanding wedge (so never suppressed by
/// decide_retry() and never acknowledged), so the generation stays held across every
/// identical retry, each of which is a real Reapply.
void check_boot_inert_false_but_watch_refused_stays_failed(SparkType type) {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0, std::nullopt, type};

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(11);
    *p.add_rules() = make_rule_for_type(type, "r1");
    const auto push_bytes = p.SerializeAsString();

    for (int i = 0; i < 3; ++i) {
        f.mechanism->set_fail_next_watch(); // single-shot - re-arm before every retry
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, push_bytes);
        REQUIRE(dr.exit_code == 0);
        // Drain to full quiescence before asserting or re-arming the fail flag for the
        // next iteration - guardian_dispatch_push_bytes_for_test's own attach is
        // NonWaiting (rung 9c PR-2 Unit 6): without this wait, a still-in-flight
        // resolution from THIS iteration can consume the NEXT iteration's single-shot
        // set_fail_next_watch() instead of a fresh watch() call, so a genuine refusal
        // gets silently skipped and the retry arms for real - observed as a CI flake
        // (spark_armed_rule_count()==1 on an intermediate retry, #4685 PR #5021).
        REQUIRE(yuzu::test::spin_until([&] {
            f.engine->journal_maintenance_tick();
            return f.engine->ack_pending_count_for_test() == 0 && f.engine->active_io_workers() == 0;
        }));
        CHECK(f.engine->policy_generation() == 0); // held, every retry - a Failed arm is never acknowledged
        CHECK(f.engine->armed_guard_count() == 0); // no legacy fallback
        CHECK(f.engine->spark_armed_rule_count() == 0);
        CHECK(f.engine->unsupported_counts_by_type().count(type) == 0); // Failed, not Unsupported
    }
}

/// AC5(i) (plan §8 split): a COMMITTED rule going away (disabled here, to sidestep the
/// "a replacement may legitimately leave a NEW generation armed" ambiguity a
/// superseding-push variant would carry - see §8) during an OPEN runtime-degraded
/// episode still withdraws exactly as it would with a healthy mechanism - the episode
/// never changes disarm semantics. Mirrors "disable withdraws from spark; re-enable
/// re-arms via spark" above, adding the degraded episode and the "disarmed" journal
/// assertion.
void check_committed_rule_disable_during_degraded_episode_disarms(SparkType type) {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0, std::nullopt, type};
    f.apply(make_rule_for_type(type, "r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);

    f.mechanism->set_inert(true); // episode open at disable time

    f.apply(make_rule_for_type(type, "r1", /*enabled=*/false), /*full_sync=*/false);

    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.mechanism->watching_count() == 0);
    REQUIRE(yuzu::test::spin_until([&] {
        std::lock_guard<std::mutex> lk{f.sent_mu};
        return std::any_of(f.sent.begin(), f.sent.end(), [](const OutboxEntry& e) {
            return e.rule_id == "r1" && e.lifecycle_kind == "disarmed";
        });
    }));
}

/// AC5(ii) (plan §8 split): an arm that never committed (still parked mid watch()) is
/// withdrawn (disabled) WHILE pending - cancellation/cleanup only, no "disarmed" audit
/// (the rule was never actually armed -
/// GuardianSparkRuntime::withdraw_rule_after_wedge_sweep_locked's own "pending arm
/// withdrawn -> no lifecycle entry" contract, guardian_spark_runtime.cpp:2621). The
/// episode being open at the time changes nothing about this contract.
void check_pending_arm_withdrawal_no_disarmed_record(SparkType type) {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0, std::nullopt, type};
    f.mechanism->set_inert(true); // episode open - still armable, still reaches watch()
    f.mechanism->hang_next_watch();
    struct ReleaseOnExit {
        FakeServiceMechanism* mech;
        ~ReleaseOnExit() { mech->release_hang(); }
    } release_guard{f.mechanism};

    auto dr1 = f.dispatch_raw(make_rule_for_type(type, "r1"));
    REQUIRE(dr1.exit_code == 0);
    REQUIRE(f.mechanism->wait_entered_hang(std::chrono::seconds(30)));
    CHECK(f.engine->spark_armed_rule_count() == 0); // still pending, never committed

    auto dr2 = f.dispatch_raw(make_rule_for_type(type, "r1", /*enabled=*/false));
    REQUIRE(dr2.exit_code == 0);

    f.mechanism->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return f.engine->active_io_workers() == 0; },
                                   std::chrono::seconds(15)));
    CHECK(f.engine->spark_armed_rule_count() == 0);
    {
        std::lock_guard<std::mutex> lk{f.sent_mu};
        CHECK_FALSE(std::any_of(f.sent.begin(), f.sent.end(), [](const OutboxEntry& e) {
            return e.rule_id == "r1" && e.lifecycle_kind == "disarmed";
        }));
    }
}

/// AC5(iii) (plan §8 split): stop() during an OPEN episode is sticky, exactly as during
/// a healthy shutdown - GuardianEngine::stop() does not call detach_all() (§8), and
/// journal_maintenance_tick() is a documented no-op once stopped_ is set
/// (guardian_engine.cpp's own stop() comment), so nothing commits and nothing crashes
/// post-shutdown. Cleanup runs via the real owner shutdown sequence (stop(), not a
/// test-only teardown shortcut).
void check_shutdown_during_degraded_episode_is_sticky(SparkType type) {
    SparkReconcileFixture f{/*periodic_bound_ms=*/0, std::nullopt, type};
    f.apply(make_rule_for_type(type, "r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);
    const auto gen_before = f.engine->policy_generation();

    f.mechanism->set_inert(true); // episode still open at shutdown

    f.engine->stop(); // real owner shutdown sequence - matches the fixture's own dtor order

    CHECK(f.engine->spark_armed_rule_count() == 1); // sticky - stop() never erases it (R4)
    f.engine->journal_maintenance_tick(); // documented no-op post-stop; must not crash
    CHECK(f.engine->policy_generation() == gen_before); // no new commit post-shutdown
}

} // namespace

TEST_CASE("#4685 AC4/AC8: a runtime-degraded (not boot-inert) mechanism stays "
          "Guardian-armable though the heartbeat CSV drops it - Service",
          "[spark][guardian][reconcile][boot_inert]") {
    check_runtime_degraded_stays_armable(SparkType::Service);
}
TEST_CASE("#4685 AC4/AC8: a runtime-degraded (not boot-inert) mechanism stays "
          "Guardian-armable though the heartbeat CSV drops it - Registry parity",
          "[spark][guardian][reconcile][boot_inert]") {
    check_runtime_degraded_stays_armable(SparkType::Registry);
}

TEST_CASE("#4685 AC6: a registered but boot-inert mechanism still classifies "
          "Unsupported, warn-level and distinguished from the no-mechanism-at-all "
          "case - Service",
          "[spark][guardian][reconcile][boot_inert]") {
    check_boot_inert_registered_warns(SparkType::Service);
}
TEST_CASE("#4685 AC6: a registered but boot-inert mechanism still classifies "
          "Unsupported, warn-level and distinguished from the no-mechanism-at-all "
          "case - Registry parity",
          "[spark][guardian][reconcile][boot_inert]") {
    check_boot_inert_registered_warns(SparkType::Registry);
}
TEST_CASE("#4685 AC6: a registered but boot-inert mechanism still classifies "
          "Unsupported, warn-level and distinguished from the no-mechanism-at-all "
          "case - File parity (the issue's own AC6 names File, Registry AND Service)",
          "[spark][guardian][reconcile][boot_inert]") {
    check_boot_inert_registered_warns(SparkType::File);
}

TEST_CASE("#4685 AC7: production-order restart - a runtime-degraded mechanism still "
          "Arms the cached rule via start_local()'s re-arm walk - Service",
          "[spark][guardian][reconcile][boot][boot_inert]") {
    check_production_order_degraded_still_arms(SparkType::Service);
}
TEST_CASE("#4685 AC7: production-order restart - a runtime-degraded mechanism still "
          "Arms the cached rule via start_local()'s re-arm walk - Registry parity",
          "[spark][guardian][reconcile][boot][boot_inert]") {
    check_production_order_degraded_still_arms(SparkType::Registry);
}

TEST_CASE("#4685 option-(b) regression: boot_inert=false but watch() is synchronously "
          "refused - Failed, held generation across repeated retries, never "
          "Unsupported, never a legacy fallback - Service",
          "[spark][guardian][reconcile][boot_inert]") {
    check_boot_inert_false_but_watch_refused_stays_failed(SparkType::Service);
}
TEST_CASE("#4685 option-(b) regression: boot_inert=false but watch() is synchronously "
          "refused - Failed, held generation across repeated retries, never "
          "Unsupported, never a legacy fallback - Registry parity",
          "[spark][guardian][reconcile][boot_inert]") {
    check_boot_inert_false_but_watch_refused_stays_failed(SparkType::Registry);
}

TEST_CASE("#4685 AC5(i): a committed rule's disable during an open runtime-degraded "
          "episode still withdraws and journals \"disarmed\" - Service",
          "[spark][guardian][reconcile][boot_inert]") {
    check_committed_rule_disable_during_degraded_episode_disarms(SparkType::Service);
}
TEST_CASE("#4685 AC5(i): a committed rule's disable during an open runtime-degraded "
          "episode still withdraws and journals \"disarmed\" - Registry parity",
          "[spark][guardian][reconcile][boot_inert]") {
    check_committed_rule_disable_during_degraded_episode_disarms(SparkType::Registry);
}

TEST_CASE("#4685 AC5(ii): a pending (never-committed) arm withdrawn during an open "
          "episode is cancelled with no \"disarmed\" audit - Service",
          "[spark][guardian][reconcile][boot_inert]") {
    check_pending_arm_withdrawal_no_disarmed_record(SparkType::Service);
}
TEST_CASE("#4685 AC5(ii): a pending (never-committed) arm withdrawn during an open "
          "episode is cancelled with no \"disarmed\" audit - Registry parity",
          "[spark][guardian][reconcile][boot_inert]") {
    check_pending_arm_withdrawal_no_disarmed_record(SparkType::Registry);
}

TEST_CASE("#4685 AC5(iii): stop() during an open runtime-degraded episode is sticky - "
          "no new committed generation, no active processing post-shutdown - Service",
          "[spark][guardian][reconcile][boot_inert]") {
    check_shutdown_during_degraded_episode_is_sticky(SparkType::Service);
}
TEST_CASE("#4685 AC5(iii): stop() during an open runtime-degraded episode is sticky - "
          "no new committed generation, no active processing post-shutdown - Registry "
          "parity",
          "[spark][guardian][reconcile][boot_inert]") {
    check_shutdown_during_degraded_episode_is_sticky(SparkType::Registry);
}

// ── #4685 AC2/AC3 — Windows-only, REAL File/Registry mechanisms ─────────────────────
// The fake-mechanism coverage above proves Guardian's OWN classifier change; these
// prove the real mechanisms' stats() split (spark_file.cpp/spark_registry.cpp) feeds
// it correctly end to end, mirroring the "direct" pass-failure tests in
// test_spark_mechanism.cpp (File: pass_fail_hook, ~:7005; Registry: sweep_hook,
// ~:10957) but through GuardianEngine::reconcile_rule_locked rather than the raw
// mechanism, and covering the SAME already-armed-rule-mid-episode shape §8 asks for.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {

// Mirrors test_spark_mechanism.cpp's ScratchDir exactly (own copy: that struct is
// file-local to test_spark_mechanism.cpp, not exported).
struct Guardian4685ScratchDir {
    std::filesystem::path dir;
    std::filesystem::path file;
    explicit Guardian4685ScratchDir(const char* tag) {
        dir = yuzu::test::unique_temp_path("yuzu_test_guardian_4685_" + std::string(tag) + "_");
        std::filesystem::create_directories(dir);
        file = dir / "watched.txt";
        { std::ofstream(file) << "seed"; }
    }
    ~Guardian4685ScratchDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    Guardian4685ScratchDir(const Guardian4685ScratchDir&) = delete;
    Guardian4685ScratchDir& operator=(const Guardian4685ScratchDir&) = delete;
};

// Mirrors test_spark_mechanism.cpp's ScratchRegKey exactly (own copy, same reason).
struct Guardian4685ScratchRegKey {
    std::string sub;
    HKEY h{nullptr};
    explicit Guardian4685ScratchRegKey(const char* tag) {
        static std::atomic<int> n{0};
        sub = std::string("Software\\Yuzu\\Guardian4685_") + tag + "_" +
              std::to_string(::GetCurrentProcessId()) + "_" +
              std::to_string(yuzu::test::process_random_salt() % 1000000000) + "_" +
              std::to_string(n.fetch_add(1));
        ::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &h,
                          nullptr);
    }
    ~Guardian4685ScratchRegKey() {
        if (h)
            ::RegCloseKey(h);
        ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
    }
    Guardian4685ScratchRegKey(const Guardian4685ScratchRegKey&) = delete;
    Guardian4685ScratchRegKey& operator=(const Guardian4685ScratchRegKey&) = delete;
};

} // namespace

TEST_CASE("#4685 AC2 (File, real mechanism): an already-armed rule undergoing a full "
          "sync mid runtime-degraded episode stays Arm/Committed, coverage stays None "
          "and recovers with no second push",
          "[spark][guardian][reconcile][windows][boot_inert]") {
    Guardian4685ScratchDir a("file");
    auto mech_owned = make_file_mechanism();
    REQUIRE(mech_owned != nullptr);
    ISparkMechanism* mech = mech_owned.get(); // borrowed - the engine takes ownership below

    std::atomic<bool> failing{false};
    std::atomic<int> throws{0};
    {
        FileMechanismTestControls ctl;
        ctl.sweep_cadence = std::chrono::milliseconds(50); // fast retry, bounded test runtime
        ctl.pass_fail_hook = [&] {
            if (failing.load(std::memory_order_acquire)) {
                throws.fetch_add(1, std::memory_order_relaxed);
                throw std::bad_alloc{};
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(ctl)));
    }

    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    REQUIRE(spark_engine.register_mechanism(SparkType::File, std::move(mech_owned)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test-4685-file", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    // First push, mechanism healthy: the rule arms for real.
    gpb::GuaranteedStatePush p1;
    p1.set_full_sync(true);
    *p1.add_rules() = make_file_rule("r1", true, a.file.string());
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p1.SerializeAsString())
                .exit_code == 0);
    REQUIRE(yuzu::test::spin_until([&] {
        engine.journal_maintenance_tick();
        return engine.ack_pending_count_for_test() == 0 && engine.active_io_workers() == 0;
    }));
    REQUIRE(engine.spark_armed_rule_count() == 1);

    // A raw consumer arms the IDENTICAL spec (same spark key) purely to obtain a
    // SubscriptionId this test can query directly: Guardian itself exposes no
    // rule_id -> SubscriptionId accessor (the same gap plan §9 must-fix 2 names for
    // AC8). arm_impl() DEDUPS an identical key onto the SAME armed_[key] entry rather
    // than dispatching a second backend watch (spark_engine.cpp's own comment on the
    // "fresh key on a running engine" vs "dedup" split), so this SubscriptionId's
    // subscription_establishment() reads the IDENTICAL coverage Guardian's own arm
    // produced - the same technique the "#2818" sibling-consumer test earlier in this
    // file already uses for an unrelated purpose, not a new seam.
    auto raw = spark_engine.register_consumer("raw-4685-file", [](const SparkEvent&) {});
    REQUIRE(raw.has_value());
    const SparkSpec spec{SparkType::File, FileSparkParams{a.file.string()}};
    auto raw_sub = spark_engine.arm(*raw, spec);
    REQUIRE(raw_sub.has_value());

    // Open the runtime-degraded episode and wait for the mechanism to genuinely report
    // it (three consecutive failed passes, #4658) BEFORE the mid-episode full sync.
    // A real, established, Idle File watch has NOTHING due - wait_timeout_locked()'s
    // default is a 1h ceiling, and nothing else re-invokes run_pass_hook_locked() on
    // its own once the initial arm's own control-wake pass already happened (before
    // `failing` flipped true, so it didn't throw). Force exactly ONE more pass via
    // apply_test_controls()'s own existing "nudge" (it unconditionally posts a control
    // wake - see its own comment at the end of apply_test_controls()); that single
    // hook throw alone starts note_pass_outcome_locked's backoff episode, which is then
    // self-sustaining (every failed pass reschedules its own retry via
    // wait_timeout_locked's pass-failure-backoff clause) all the way to the 3rd
    // consecutive failure with no further nudging needed.
    failing.store(true, std::memory_order_release);
    {
        FileMechanismTestControls nudge;
        nudge.sweep_cadence = std::chrono::milliseconds(50);
        nudge.pass_fail_hook = [&] {
            if (failing.load(std::memory_order_acquire)) {
                throws.fetch_add(1, std::memory_order_relaxed);
                throw std::bad_alloc{};
            }
        };
        REQUIRE(set_file_test_controls_for_test(*mech, std::move(nudge)));
    }
    REQUIRE(yuzu::test::spin_until([&] { return mech->stats().inert; }, std::chrono::seconds(10)));
    CHECK_FALSE(mech->stats().boot_inert); // runtime, never boot-time

    // A full sync mid-episode - the real destructive detach-and-reconcile path
    // (#4685 AC2): the rule stays Arm/Committed, never Unsupported.
    gpb::GuaranteedStatePush p2;
    p2.set_full_sync(true);
    p2.set_policy_generation(3);
    *p2.add_rules() = make_file_rule("r1", true, a.file.string());
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p2.SerializeAsString())
                .exit_code == 0);
    REQUIRE(yuzu::test::spin_until([&] {
        engine.journal_maintenance_tick();
        return engine.ack_pending_count_for_test() == 0 && engine.active_io_workers() == 0;
    }));

    CHECK(engine.spark_armed_rule_count() == 1); // still Arm/Committed
    CHECK(engine.policy_generation() == 3);      // advanced - never held for an Unsupported push
    CHECK(engine.unsupported_counts_by_type().count(SparkType::File) == 0);
    CHECK(engine.last_unsupported_log_for_test().edge_count == 0); // no "gap" line, either level

    const auto mid_est = spark_engine.subscription_establishment(*raw_sub);
    REQUIRE(mid_est.has_value());
    CHECK(mid_est->coverage == yuzu::agent::SparkCoverage::None); // overlaid while degraded

    // Recovery: no second push, no restart - just the mechanism's next successful pass.
    failing.store(false, std::memory_order_release);
    REQUIRE(yuzu::test::spin_until([&] { return !mech->stats().inert; }, std::chrono::seconds(15)));
    REQUIRE(yuzu::test::spin_until(
        [&] {
            const auto est = spark_engine.subscription_establishment(*raw_sub);
            return est.has_value() && est->coverage != yuzu::agent::SparkCoverage::None;
        },
        std::chrono::seconds(15)));

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("#4685 AC3 (Registry, real mechanism): an already-armed rule undergoing a "
          "full sync mid runtime-degraded episode stays Arm/Committed, coverage stays "
          "None and recovers with no second push",
          "[spark][guardian][reconcile][windows][boot_inert]") {
    Guardian4685ScratchRegKey a("registry");
    auto mech_owned = make_registry_mechanism();
    REQUIRE(mech_owned != nullptr);
    ISparkMechanism* mech = mech_owned.get();

    std::atomic<bool> failing{false};
    std::atomic<int> throws{0};
    {
        RegistryMechanismTestControls ctl;
        ctl.sweep_cadence = std::chrono::milliseconds(5);
        ctl.sweep_hook = [&] {
            if (failing.load(std::memory_order_acquire)) {
                throws.fetch_add(1, std::memory_order_relaxed);
                throw std::bad_alloc{};
            }
        };
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(ctl)));
    }

    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    REQUIRE(
        spark_engine.register_mechanism(SparkType::Registry, std::move(mech_owned)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test-4685-registry", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p1;
    p1.set_full_sync(true);
    *p1.add_rules() = make_registry_rule("r1", true, a.sub);
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p1.SerializeAsString())
                .exit_code == 0);
    REQUIRE(yuzu::test::spin_until([&] {
        engine.journal_maintenance_tick();
        return engine.ack_pending_count_for_test() == 0 && engine.active_io_workers() == 0;
    }));
    REQUIRE(engine.spark_armed_rule_count() == 1);

    auto raw = spark_engine.register_consumer("raw-4685-registry", [](const SparkEvent&) {});
    REQUIRE(raw.has_value());
    const SparkSpec spec{SparkType::Registry, RegistrySparkParams{"HKCU", a.sub}};
    auto raw_sub = spark_engine.arm(*raw, spec);
    REQUIRE(raw_sub.has_value());

    // Unlike File's wait_timeout_locked (which has an explicit "an open failure
    // episode always has a retry scheduled" clause, #4658), spark_registry.cpp's
    // next_wake_locked() has NO failure-backoff clause at all: sweeper_main()'s own
    // post-failure cv_.wait_until(delay) (the "retrying in N ms" log line) elapses,
    // but the very next loop iteration recomputes next_wake_locked() from scratch,
    // which for an Idle/armed/no-resync-debt watch returns its ~1h default ceiling -
    // so a single nudge opens the episode (confirmed: exactly one "consecutive #1"
    // log line, then nothing for the rest of a 10s window) but does not keep it
    // self-sustaining. Real production traffic (another Pending probe, a resync,
    // etc.) would normally supply that wake; this test's single Idle watch has none,
    // so it supplies its own repeated nudge instead - same primitive as the File
    // twin above, just applied throughout the wait rather than once.
    auto nudge_registry = [&] {
        RegistryMechanismTestControls c;
        c.sweep_cadence = std::chrono::milliseconds(5);
        c.sweep_hook = [&] {
            if (failing.load(std::memory_order_acquire)) {
                throws.fetch_add(1, std::memory_order_relaxed);
                throw std::bad_alloc{};
            }
        };
        REQUIRE(set_registry_test_controls_for_test(*mech, std::move(c)));
    };

    failing.store(true, std::memory_order_release);
    bool became_degraded = false;
    for (int i = 0; i < 2000 && !became_degraded; ++i) {
        nudge_registry();
        became_degraded = mech->stats().inert;
        if (!became_degraded)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    REQUIRE(became_degraded);
    CHECK_FALSE(mech->stats().boot_inert);

    gpb::GuaranteedStatePush p2;
    p2.set_full_sync(true);
    p2.set_policy_generation(3);
    *p2.add_rules() = make_registry_rule("r1", true, a.sub);
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p2.SerializeAsString())
                .exit_code == 0);
    REQUIRE(yuzu::test::spin_until([&] {
        engine.journal_maintenance_tick();
        return engine.ack_pending_count_for_test() == 0 && engine.active_io_workers() == 0;
    }));

    CHECK(engine.spark_armed_rule_count() == 1);
    CHECK(engine.policy_generation() == 3);
    CHECK(engine.unsupported_counts_by_type().count(SparkType::Registry) == 0);
    CHECK(engine.last_unsupported_log_for_test().edge_count == 0);

    const auto mid_est = spark_engine.subscription_establishment(*raw_sub);
    REQUIRE(mid_est.has_value());
    CHECK(mid_est->coverage == yuzu::agent::SparkCoverage::None);

    // Recovery: same gap as above - a successful pass needs the sweeper to actually
    // run one, which next_wake_locked() alone will not schedule promptly for this
    // test's single Idle watch. Keep supplying the nudge (now non-throwing, since
    // `failing` is false) until the mechanism and the coverage overlay both observe
    // the recovery - no second push, no restart, matching AC3's own acceptance
    // criterion, just not a bare wall-clock wait.
    failing.store(false, std::memory_order_release);
    bool recovered = false;
    for (int i = 0; i < 3000 && !recovered; ++i) {
        nudge_registry();
        recovered = !mech->stats().inert;
        if (!recovered)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    REQUIRE(recovered);

    bool coverage_restored = false;
    for (int i = 0; i < 3000 && !coverage_restored; ++i) {
        nudge_registry();
        const auto est = spark_engine.subscription_establishment(*raw_sub);
        coverage_restored = est.has_value() && est->coverage != yuzu::agent::SparkCoverage::None;
        if (!coverage_restored)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    REQUIRE(coverage_restored);

    engine.stop();
    spark_engine.stop();
}

#endif // _WIN32

// ── #4045 ─────────────────────────────────────────────────────────────────────────────────
// Spark's baseline-on-arm capture must reach the #4021 KV record. The runtime STAGES the
// capture edge (test_guardian_spark_runtime.cpp, "#4045 R1-R7"); an engine-owned persister
// drains it from apply_rules (before any re-arm seeds), stop(), and the drain worker. These
// drive the real engine + a REAL temp file through the fixture's File-typed fake mechanism
// (the real File mechanism is Windows-only; GuardianStateReader::read_file is not).
//
// ARM-TIME EVAL: an accepted arm evaluates the key once itself (the "T_detect ... via=callback-arm"
// pass inside apply()), so a target that EXISTS when apply() runs is captured before the test
// can do anything. The failure-path cases (E2/E3/E5/E8) therefore apply against an ABSENT
// target, break the KV, and only then create the file and evaluate: the capture lands with the
// store already failing. The explicit evaluate_key calls elsewhere are redundant but harmless.
//
// Waiting discipline: a FORCED persist pass (persist_now_4045) and evaluate_key make the flow
// synchronous. The background drain worker may ALSO persist after an enqueue wake (its backstop
// is pinned to one hour, so only the wake can run it), and after a FAILED worker pass it backs
// off for 5 s, so tests that need a deterministic pass park the worker first
// (drain_worker_for_test()->stop()) and every assertion is on END STATE; failure counts are
// ">=" wherever the worker can still run.
namespace {

struct Spark4045Target {
    yuzu::test::TempDir dir{"yuzu_test_4045_"};
    Spark4045Target() { fs::create_directories(dir.path); }
    [[nodiscard]] fs::path file(const std::string& name = "target.txt") const {
        return dir.path / name;
    }
    static void write(const fs::path& p, const std::string& content) {
        std::ofstream o(p, std::ios::binary | std::ios::trunc);
        o << content;
        REQUIRE(o.good());
    }
};

std::string spark_file_key_4045(const fs::path& p) {
    return yuzu::agent::spark_key(SparkSpec{SparkType::File, FileSparkParams{p.string()}});
}
std::string baseline_fingerprint_4045(const fs::path& p) {
    return "file-hash-equals|" + p.string(); // guardian_baseline_fingerprint's layout
}
void eval_initial_4045(GuardianEngine& e, const fs::path& p) {
    auto* rt = e.spark_runtime_for_test();
    REQUIRE(rt != nullptr);
    rt->evaluate_key(spark_file_key_4045(p), yuzu::agent::EvalReason::Initial);
}
/// One FORCED persist pass (the apply_rules/stop() trigger: it ignores the worker's retry
/// backoff, which a failed worker pass has set for 5 s).
GuardianBaselinePersister::Outcome persist_now_4045(GuardianEngine& e) {
    auto* persister = e.baseline_persister_for_test();
    auto* rt = e.spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    return persister->persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
}
/// Run `sql` on a SECOND connection to the engine's KV file (real SQLite fault injection).
void exec_sql_4045(const fs::path& db_path, const std::string& sql) {
    ScopedTestSqlite3 db;
    REQUIRE(sqlite3_open(db_path.string().c_str(), &db.raw) == SQLITE_OK);
    sqlite3_busy_timeout(db.raw, 5000);
    char* err = nullptr;
    const int rc = sqlite3_exec(db.raw, sql.c_str(), nullptr, nullptr, &err);
    if (err)
        sqlite3_free(err);
    REQUIRE(rc == SQLITE_OK);
}
/// Make every baseline write whose key matches `key_like` (a SQL LIKE pattern) fail for real,
/// while rule and journal writes keep succeeding. BEFORE INSERT fires for the upsert too.
void fail_baseline_writes_4045(const fs::path& db_path, const std::string& key_like = "baseline:%") {
    exec_sql_4045(db_path, "CREATE TRIGGER yuzu_test_4045_fail BEFORE INSERT ON kv_store WHEN "
                           "NEW.key LIKE '" + key_like +
                               "' BEGIN SELECT RAISE(ABORT,'injected baseline write failure'); END;");
}
void heal_baseline_writes_4045(const fs::path& db_path) {
    exec_sql_4045(db_path, "DROP TRIGGER yuzu_test_4045_fail;");
}
/// Joins on scope exit, so a REQUIRE that throws cannot unwind past a joinable std::thread.
struct Join4045 {
    std::thread& t;
    ~Join4045() {
        if (t.joinable())
            t.join();
    }
};
/// Clears every engine and persister test hook on ANY exit, including a failing REQUIRE. The
/// hooks capture test locals by reference, so one left installed would let the fixture's own
/// stop() pass (or the drain worker) invoke a dangling hook while the failure unwinds. Declare
/// it AFTER the locals the hooks capture so it destructs BEFORE them.
struct HookGuard4045 {
    GuardianEngine& e;
    ~HookGuard4045() {
        e.set_apply_post_drain_hook_for_test(nullptr);
        e.set_seed_read_hook_for_test(nullptr);
        e.set_post_attach_hook_for_test(nullptr);
        if (auto* p = e.baseline_persister_for_test()) {
            p->set_post_snapshot_hook_for_test(nullptr);
            p->set_post_write_hook_for_test(nullptr);
        }
    }
};
std::vector<OutboxEntry> compliance_4045(SparkReconcileFixture& f, const std::string& rule_id) {
    std::lock_guard<std::mutex> lk{f.sent_mu};
    std::vector<OutboxEntry> out;
    for (const auto& e : f.sent)
        if (e.domain == yuzu::agent::OutboxDomain::Compliance && e.rule_id == rule_id)
            out.push_back(e);
    return out;
}
bool has_compliant_4045(SparkReconcileFixture& f, const std::string& rule_id) {
    for (const auto& e : compliance_4045(f, rule_id))
        if (e.drift.compliant)
            return true;
    return false;
}
/// The first NON-compliant (drift) entry for `rule_id`, if one has been sent.
std::optional<OutboxEntry> first_drift_4045(SparkReconcileFixture& f, const std::string& rule_id) {
    for (const auto& e : compliance_4045(f, rule_id))
        if (!e.drift.compliant)
            return e;
    return std::nullopt;
}
std::optional<nlohmann::json> baseline_record_4045(KvStore& kv, const std::string& rule_id) {
    auto v = kv.get(GuardianEngine::kv_namespace(), "baseline:" + rule_id);
    if (!v)
        return std::nullopt;
    return nlohmann::json::parse(*v);
}
std::string hash_of_4045(const fs::path& p) { return yuzu::agent::sha256_file(p); }

} // namespace

TEST_CASE("#4045 E1: Spark's first capture is persisted and a full_sync re-arm keeps it "
          "(headline: no laundered compliant)",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t; // declared first: outlives the fixture's engine
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file();
    Spark4045Target::write(target, "content A");
    const std::string h_a = hash_of_4045(target);

    f.apply(make_file_hash_rule("r1", target.string()));
    eval_initial_4045(*f.engine, target);
    REQUIRE(yuzu::test::spin_until([&] { return has_compliant_4045(f, "r1"); }));
    CHECK(compliance_4045(f, "r1").front().drift.expected_value == h_a);

    persist_now_4045(*f.engine);
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value()); // the capture was persisted
    CHECK(rec->value("schema", -1) == 1);
    CHECK(rec->value("fingerprint", std::string{}) == baseline_fingerprint_4045(target));
    CHECK(rec->value("hash", std::string{}) == h_a);

    // The file drifts, then ANY fleet push re-arms the rule (full_sync teardown + attach).
    Spark4045Target::write(target, "content B, longer");
    const std::string h_b = hash_of_4045(target);
    REQUIRE(h_b != h_a);
    f.apply(make_file_hash_rule("r1", target.string()), /*full_sync=*/true);
    eval_initial_4045(*f.engine, target);

    // The re-armed generation is seeded with A, so B is DRIFT, not a re-baselined compliant.
    REQUIRE(yuzu::test::spin_until([&] { return first_drift_4045(f, "r1").has_value(); }));
    const auto drift = first_drift_4045(f, "r1");
    CHECK(drift->drift.expected_value == h_a);
    CHECK(drift->drift.detected_value == h_b);
    const auto after = baseline_record_4045(*f.kv, "r1");
    REQUIRE(after.has_value());
    CHECK(after->value("hash", std::string{}) == h_a); // the guard never lets drift replace it
}

TEST_CASE("#4045 E2: the apply_rules drain persists a failed-then-recovered capture BEFORE the "
          "re-arm seeds",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file(); // ABSENT at apply(): see the ARM-TIME EVAL note above
    const auto rule = make_file_hash_rule("r1", target.string());

    f.apply(rule); // apply()'s own rule write needs the table, so break it AFTER
    drop_kv_store_table_for_test(f.db_.path);
    Spark4045Target::write(target, "content A"); // the first good read: the capture's persist
    const std::string h_a = hash_of_4045(target); // attempt must fail and stay staged
    eval_initial_4045(*f.engine, target);
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    // The enqueue-triggered worker attempt has provably run and failed...
    REQUIRE(yuzu::test::spin_until([&] { return persister->persist_failures() >= 1; }));
    // ...and the worker is now parked for good. Without this the worker, woken by the re-arm's
    // own teardown enqueues, could persist the still-staged capture before apply_rules reaches its
    // seed read and the test would pass without apply_rules' drain. From here ONLY that drain
    // can persist A, and entries are read straight off the runtime (no worker to send them).
    f.engine->drain_worker_for_test()->stop();

    Spark4045Target::write(target, "content B, longer");
    const std::string h_b = hash_of_4045(target);
    recreate_kv_store_table_for_test(f.db_.path);
    f.apply(rule, /*full_sync=*/true); // no seam call
    eval_initial_4045(*f.engine, target);

    std::vector<OutboxEntry> drained;
    REQUIRE(yuzu::test::spin_until([&] {
        rt->drain([&](const OutboxEntry& e) {
            drained.push_back(e);
            return SendResult::Sent;
        });
        for (const auto& e : drained)
            if (e.domain == yuzu::agent::OutboxDomain::Compliance && !e.drift.compliant &&
                e.drift.expected_value == h_a && e.drift.detected_value == h_b)
                return true;
        return false;
    }));
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_a);
}

TEST_CASE("#4045 E3: a failed persist is counted, stays staged and is retried; success clears it",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file(); // ABSENT at apply(): see the ARM-TIME EVAL note above

    f.apply(make_file_hash_rule("r1", target.string()));
    drop_kv_store_table_for_test(f.db_.path);
    Spark4045Target::write(target, "content A");
    const std::string h_a = hash_of_4045(target);
    eval_initial_4045(*f.engine, target);
    const auto failed_pass = persist_now_4045(*f.engine);
    CHECK(failed_pass.failed == 1);

    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    REQUIRE(yuzu::test::spin_until([&] { return persister->persist_failures() >= 1; }));
    // Never dropped: a failed tuple was never out of staging (snapshot-and-erase-by-identity).
    CHECK(rt->staged_baseline_count_for_test() == 1);

    recreate_kv_store_table_for_test(f.db_.path);
    persist_now_4045(*f.engine);
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_a);
    CHECK(yuzu::test::spin_until([&] { return rt->staged_baseline_count_for_test() == 0; }));
}

TEST_CASE("#4045 E4: a retarget persists the new target's capture over the old record",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path p1 = t.file("one.txt");
    const fs::path p2 = t.file("two.txt");
    Spark4045Target::write(p1, "content A");
    Spark4045Target::write(p2, "content C, a different target");
    const std::string h_c = hash_of_4045(p2);

    f.apply(make_file_hash_rule("r1", p1.string()));
    eval_initial_4045(*f.engine, p1);
    REQUIRE(yuzu::test::spin_until([&] { return has_compliant_4045(f, "r1"); }));
    persist_now_4045(*f.engine);
    const auto first = baseline_record_4045(*f.kv, "r1");
    REQUIRE(first.has_value()); // the capture was persisted
    CHECK(first->value("fingerprint", std::string{}) == baseline_fingerprint_4045(p1));

    // Same rule_id re-authored against a different path (non-full_sync replace): the seed's
    // fingerprint mismatch means "capture fresh", and that capture replaces the record.
    f.apply(make_file_hash_rule("r1", p2.string()), /*full_sync=*/false);
    eval_initial_4045(*f.engine, p2);
    persist_now_4045(*f.engine);

    REQUIRE(yuzu::test::spin_until([&] {
        const auto rec = baseline_record_4045(*f.kv, "r1");
        return rec && rec->value("fingerprint", std::string{}) == baseline_fingerprint_4045(p2);
    }));
    const auto rec = baseline_record_4045(*f.kv, "r1");
    CHECK(rec->value("hash", std::string{}) == h_c);
    // A fresh capture on the new target is compliant: never a drift against the OLD target.
    CHECK_FALSE(first_drift_4045(f, "r1").has_value());
}

TEST_CASE("#4045 E5: the overwrite guard holds on the Spark path (a refusal is counted apart, "
          "not a failure)",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file(); // ABSENT at apply(): see the ARM-TIME EVAL note above

    f.apply(make_file_hash_rule("r1", target.string())); // Absent record: the capture path
    drop_kv_store_table_for_test(f.db_.path);
    Spark4045Target::write(target, "content A");
    eval_initial_4045(*f.engine, target); // capture staged; the worker's attempt fails, stays staged
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    REQUIRE(yuzu::test::spin_until([&] { return persister->persist_failures() >= 1; }));
    // Parked for good: a late worker cycle must not run the guard between the table coming
    // back and the direct write below (it could otherwise see the transient stale-schema read
    // error and degrade to write-anyway, overwriting the record this test sets up).
    f.engine->drain_worker_for_test()->stop();

    // The table returns holding a DIFFERENT well-formed baseline for the same target (as if
    // the arm-time seed read had failed while a good record existed). Written directly, not
    // via the guard, so a late worker cycle cannot make this setup itself refuse.
    recreate_kv_store_table_for_test(f.db_.path);
    const std::string h_x(64, 'a');
    nlohmann::json existing;
    existing["schema"] = 1;
    existing["fingerprint"] = baseline_fingerprint_4045(target);
    existing["hash"] = h_x;
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", existing.dump()));

    const auto failures_before = f.engine->baseline_persist_failures();
    const auto outcome = persister->persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    CHECK(outcome.written == 0); // the guard refused: first capture on record wins
    CHECK(outcome.refused == 1);
    CHECK(outcome.failed == 0);  // ...and a refusal is not a failure (erased, never retried)
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_x);
    CHECK(rt->staged_baseline_count_for_test() == 0);
    // Counted on its own accessor, NOT in the failure aggregate (the guard worked).
    CHECK(f.engine->baseline_persist_refusals() == 1);
    CHECK(f.engine->baseline_persist_failures() == failures_before);
}

TEST_CASE("#4045 E6: a production-order restart re-seeds Spark's persisted capture",
          "[spark][guardian][baseline][reconcile][boot]") {
    // Two-phase production-order pattern (wire_spark_engine BEFORE start_local) of "a
    // production-order restart reconstructs unsupported_rules_ from cached KV", inlined on
    // purpose: no shared production-order fixture is added here.
    Spark4045Target t;
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};
    const fs::path target = t.file();
    Spark4045Target::write(target, "content A");
    const std::string h_a = hash_of_4045(target);
    const auto rule = make_file_hash_rule("r1", target.string());

    // Phase 1: arm, capture, persist, shut down.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        REQUIRE(spark_engine.register_mechanism(SparkType::File,
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
        *p.add_rules() = rule;
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        REQUIRE(yuzu::test::spin_until([&] {
            engine.journal_maintenance_tick();
            return engine.spark_armed_rule_count() == 1 && engine.ack_pending_count_for_test() == 0 &&
                   engine.active_io_workers() == 0;
        }));
        eval_initial_4045(engine, target);
        persist_now_4045(engine);
        engine.stop();
        spark_engine.stop();
    }

    // The target drifts while the agent is down.
    Spark4045Target::write(target, "content B, longer");
    const std::string h_b = hash_of_4045(target);
    REQUIRE(h_b != h_a);

    // Phase 2: a fresh boot over the same store, in PRODUCTION order, with no push.
    std::mutex sent_mu;
    std::vector<OutboxEntry> sent;
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    REQUIRE(spark_engine.register_mechanism(SparkType::File, std::make_unique<FakeServiceMechanism>())
                .has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    engine.wire_spark_engine(&spark_engine, false, [&](const OutboxEntry& e) {
        std::lock_guard<std::mutex> lk{sent_mu};
        sent.push_back(e);
        return SendResult::Sent;
    });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
    REQUIRE(engine.start_local().has_value());
    // The boot arm settles OFF-lock; evaluate_key returns early while the key is not yet armed.
    REQUIRE(yuzu::test::spin_until([&] {
        engine.journal_maintenance_tick();
        return engine.spark_armed_rule_count() == 1 && engine.ack_pending_count_for_test() == 0 &&
               engine.active_io_workers() == 0;
    }));
    eval_initial_4045(engine, target);

    REQUIRE(yuzu::test::spin_until([&] {
        std::lock_guard<std::mutex> lk{sent_mu};
        for (const auto& e : sent)
            if (e.domain == yuzu::agent::OutboxDomain::Compliance && e.rule_id == "r1" &&
                !e.drift.compliant)
                return e.drift.expected_value == h_a && e.drift.detected_value == h_b;
        return false;
    }));
    engine.stop();
    spark_engine.stop();
}

TEST_CASE("#4045 E7: prefer_spark=false is inert (nothing staged, no record)",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    REQUIRE(spark_engine.register_mechanism(SparkType::File, std::make_unique<FakeServiceMechanism>())
                .has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // the production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    const fs::path target = t.file();
    Spark4045Target::write(target, "content A");
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_file_hash_rule("r1", target.string());
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                .exit_code == 0);

    auto* rt = engine.spark_runtime_for_test();
    REQUIRE(rt != nullptr); // the runtime exists even under prefer_spark=false...
    eval_initial_4045(engine, target); // ...but no key is armed on it, so this is a no-op
    CHECK(engine.spark_armed_rule_count() == 0);
    CHECK(rt->staged_baseline_count_for_test() == 0);
    CHECK_FALSE(kv.get(GuardianEngine::kv_namespace(), "baseline:r1").has_value());

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("#4045 E8: stop() flushes a still-staged capture",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file(); // ABSENT at apply(): see the ARM-TIME EVAL note above

    f.apply(make_file_hash_rule("r1", target.string()));
    drop_kv_store_table_for_test(f.db_.path);
    Spark4045Target::write(target, "content A");
    const std::string h_a = hash_of_4045(target);
    eval_initial_4045(*f.engine, target); // staged; the worker's attempt fails, stays staged
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    REQUIRE(yuzu::test::spin_until([&] { return persister->persist_failures() >= 1; }));

    recreate_kv_store_table_for_test(f.db_.path);
    f.engine->stop(); // the final drain runs after the worker is joined and begin_stop()

    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_a);
    CHECK(rt->staged_baseline_count_for_test() == 0);
}

TEST_CASE("#4045 E9: the drain worker alone persists a capture (no seam, no apply_rules, no stop)",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file();
    Spark4045Target::write(target, "content A"); // PRESENT at apply(): the capture lands inside it
    const std::string h_a = hash_of_4045(target);

    f.apply(make_file_hash_rule("r1", target.string()));

    // The periodic backstop is pinned at one hour, so only the capture's compliant-edge enqueue
    // can wake the worker: nothing here calls the persist seam, re-enters apply_rules, or stops
    // the engine, so this fails if the worker loop does not run the persist step.
    REQUIRE(yuzu::test::spin_until(
        [&] { return baseline_record_4045(*f.kv, "r1").has_value(); }));
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_a);
    // The worker erases the entry from staging just AFTER its write returns, so the record can
    // be visible a moment before staging is empty: wait for the end state.
    CHECK(yuzu::test::spin_until(
        [&] { return f.engine->spark_runtime_for_test()->staged_baseline_count_for_test() == 0; }));

    // A healthy persist is a zero count, and a zero count ships no heartbeat tag.
    CHECK(f.engine->baseline_persist_failures() == 0);
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_guardian_baseline_persist_heartbeat_tags(tags, f.engine->baseline_persist_failures());
    CHECK(tags.empty());
}

TEST_CASE("#4045 E10: a failing baseline persist surfaces on the heartbeat tag",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file(); // ABSENT at apply(): see the ARM-TIME EVAL note above

    f.apply(make_file_hash_rule("r1", target.string()));
    drop_kv_store_table_for_test(f.db_.path);
    Spark4045Target::write(target, "content A");
    eval_initial_4045(*f.engine, target); // staged; the persist attempt fails and stays staged
    auto* persister = f.engine->baseline_persister_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(yuzu::test::spin_until([&] { return persister->persist_failures() >= 1; }));

    // The heartbeat reads the engine accessor; it must carry the persister's failure count.
    CHECK(f.engine->baseline_persist_failures() >= 1);
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_guardian_baseline_persist_heartbeat_tags(tags, f.engine->baseline_persist_failures());
    REQUIRE(tags.count("yuzu.guardian_baseline_persist_failures") == 1);
    CHECK(std::stoull(tags.at("yuzu.guardian_baseline_persist_failures")) >= 1);
    recreate_kv_store_table_for_test(f.db_.path); // let the stop() flush succeed quietly
}

// ── #4045 adversarial-review fixes ───────────────────────────────────────────────────────
// C4045-1: persist-before-seed must hold even when an in-flight evaluation of the OLD
// generation stages its first-ever capture AFTER apply_rules' drain. The two engine seams fire
// at the exact windows (post-drain; post-seed-read) so the interleaving is deterministic: the
// hook body runs the old generation's evaluation inline (it is still live), and the file then
// changes A -> B. Without the fence the replacement finds no record, captures B as compliant
// and never reports drift; with it the replacement is seeded from the staged A.
//
// The drain worker is stopped first so it cannot persist A on its own wake (that would make the
// KV seed find A and the test pass without the fence).
namespace {

enum class HookPoint4045 { PostDrain, PostSeedRead };

void run_old_gen_stages_late_4045(bool full_sync, HookPoint4045 where) {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file(); // ABSENT at the first apply: no capture yet
    const auto rule = make_file_hash_rule("r1", target.string());
    f.apply(rule);
    // The arm-time evaluation (it reads the ABSENT target and reports it) runs asynchronously
    // after apply() settles. Wait until it is observed, BEFORE the target is written, so it can
    // never read A early, stage it ahead of the hook and make this exercise the drain instead
    // of the fence (QE-4). Only then park the worker.
    REQUIRE(yuzu::test::spin_until([&] { return !compliance_4045(f, "r1").empty(); }));
    f.engine->drain_worker_for_test()->stop();

    auto* rt = f.engine->spark_runtime_for_test();
    auto* persister = f.engine->baseline_persister_for_test();
    REQUIRE(rt != nullptr);
    REQUIRE(persister != nullptr);
    Spark4045Target::write(target, "content A");
    const std::string h_a = hash_of_4045(target);
    std::string h_b;

    auto old_generation_stages_then_file_drifts = [&] {
        eval_initial_4045(*f.engine, target); // the still-live OLD generation reads A and stages it
        CHECK(rt->staged_baseline_count_for_test() == 1);
        Spark4045Target::write(target, "content B, longer");
        h_b = hash_of_4045(target);
    };
    HookGuard4045 hooks{*f.engine};
    if (where == HookPoint4045::PostDrain)
        f.engine->set_apply_post_drain_hook_for_test(old_generation_stages_then_file_drifts);
    else
        f.engine->set_seed_read_hook_for_test(
            [&](const std::string&) { old_generation_stages_then_file_drifts(); });

    f.apply(rule, full_sync);
    f.engine->set_apply_post_drain_hook_for_test(nullptr);
    f.engine->set_seed_read_hook_for_test(nullptr);
    REQUIRE_FALSE(h_b.empty()); // the hook ran
    REQUIRE(h_b != h_a);
    eval_initial_4045(*f.engine, target);

    // The replacement generation must be seeded with A, so B is DRIFT against A.
    std::vector<OutboxEntry> drained;
    const bool drifted = yuzu::test::spin_until([&] {
        rt->drain([&](const OutboxEntry& e) {
            drained.push_back(e);
            return SendResult::Sent;
        });
        for (const auto& e : drained)
            if (e.domain == yuzu::agent::OutboxDomain::Compliance && !e.drift.compliant &&
                e.drift.expected_value == h_a && e.drift.detected_value == h_b)
                return true;
        return false;
    });
    CHECK(drifted); // RED without the fence: the replacement captured B as compliant
    for (const auto& e : drained) // and never a compliant edge on B
        CHECK_FALSE((e.domain == yuzu::agent::OutboxDomain::Compliance && e.drift.compliant &&
                     e.drift.expected_value == h_b));

    // The durable record is the first capture, A.
    (void)persister->persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_a);
}

} // namespace

TEST_CASE("#4045 E11: a capture the old generation stages after the apply drain still seeds a "
          "full_sync re-arm",
          "[spark][guardian][baseline][reconcile]") {
    run_old_gen_stages_late_4045(/*full_sync=*/true, HookPoint4045::PostDrain);
}

TEST_CASE("#4045 E12: a capture the old generation stages after the apply drain still seeds a "
          "same-id replace",
          "[spark][guardian][baseline][reconcile]") {
    run_old_gen_stages_late_4045(/*full_sync=*/false, HookPoint4045::PostDrain);
}

TEST_CASE("#4045 E13: a capture staged between the seed read and the attach still seeds the "
          "replacement (the old generation is live until attach_core detaches it)",
          "[spark][guardian][baseline][reconcile]") {
    run_old_gen_stages_late_4045(/*full_sync=*/false, HookPoint4045::PostSeedRead);
}

TEST_CASE("#4045 E14a: the persister's seed fence is held from a baseline-on-arm seed read "
          "THROUGH attach_rule (past attach_core's staged read) and released when the reconcile "
          "returns",
          "[spark][guardian][baseline][reconcile]") {
    // The fence is REQUIRED (not an optimisation) now that an entry leaves staging after its
    // write: without it a worker pass could write and erase a capture between the engine's KV
    // seed read and attach_core's staged read, and neither read would see it (E17 drives that
    // schedule end to end). persist_mu_ is the pass lock; the engine holds it from the seed
    // read through attach_rule. Probed from another thread (try_lock on the owning thread
    // would be undefined) at the post-seed-read hook AND at the post-attach hook (which fires
    // after attach_rule has returned, so after attach_core's staged read): releasing the fence
    // anywhere earlier turns the second probe red (QE-9). The worker is parked first so it
    // cannot hold persist_mu_ itself at any probe (every wake takes it for one pass), which
    // would satisfy a "held" probe without the fence and fail the "released" one (QE-3).
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    const fs::path target = t.file();
    auto* persister = f.engine->baseline_persister_for_test();
    REQUIRE(persister != nullptr);
    std::atomic<int> fires{0};
    std::atomic<int> attach_fires{0};
    std::atomic<bool> held_in_hook{false};
    std::atomic<bool> held_post_attach{false};
    HookGuard4045 hooks{*f.engine};
    f.engine->set_seed_read_hook_for_test([&](const std::string&) {
        fires.fetch_add(1);
        std::thread probe([&] { held_in_hook.store(persister->seed_fence_held_for_test()); });
        probe.join();
    });
    f.engine->set_post_attach_hook_for_test([&](const std::string&) {
        attach_fires.fetch_add(1);
        std::thread probe([&] { held_post_attach.store(persister->seed_fence_held_for_test()); });
        probe.join();
    });
    f.apply(make_file_hash_rule("r1", target.string()));
    f.engine->set_seed_read_hook_for_test(nullptr);
    f.engine->set_post_attach_hook_for_test(nullptr);
    REQUIRE(fires.load() >= 1);
    REQUIRE(attach_fires.load() >= 1);
    CHECK(held_in_hook.load());     // RED without the fence: persist_mu_ is free at the seed read
    CHECK(held_post_attach.load()); // RED if released before the attach returns
    bool held_after = true;
    std::thread probe([&] { held_after = persister->seed_fence_held_for_test(); });
    probe.join();
    CHECK_FALSE(held_after); // released when reconcile returns
}

TEST_CASE("#4045 E14b: a drain waiting on an in-flight pass is bounded by that pass's BUDGET: "
          "a failing KV costs at most max_failures failed writes per pass, never one per staged "
          "capture",
          "[spark][guardian][baseline][reconcile]") {
    // A worker pass is parked mid-flight (post-snapshot hook, persist_mu_ held) while
    // apply_rules' own drain arrives and waits behind it. With the default budget each pass
    // attempts at most max_failures (3) writes, so the total is 6 failed writes for 6 staged
    // captures across the two passes (the old unbudgeted loop made 12, the first-failure abort
    // made 2), and the staged captures stay visible to attach_core (still in staging) the whole
    // time. The rotation cursor makes the second pass start where the first stopped.
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file();
    const auto rule = make_file_hash_rule("r1", target.string());
    f.apply(rule);
    REQUIRE(yuzu::test::spin_until([&] { return !compliance_4045(f, "r1").empty(); }));
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);

    fail_baseline_writes_4045(f.db_.path); // rule/journal writes keep working; baseline ones fail
    constexpr int kN = 6;
    for (int i = 0; i < kN; ++i)
        rt->stage_baseline_for_test("s" + std::to_string(i), "/yuzu_test_4045_b/" + std::to_string(i),
                                    std::string(64, 'a'));
    const auto failures_before = persister->persist_failures();

    std::atomic<bool> in_pass{false};
    std::atomic<bool> release{false};
    std::atomic<std::size_t> staged_in_pass{0};
    std::atomic<bool> hook_armed{true};
    HookGuard4045 hooks{*f.engine};
    persister->set_post_snapshot_hook_for_test([&] {
        if (!hook_armed.exchange(false))
            return; // only the first pass parks
        staged_in_pass.store(rt->staged_baseline_count_for_test());
        in_pass.store(true);
        (void)yuzu::test::spin_until([&] { return release.load(); });
    });
    GuardianBaselinePersister::Outcome worker_pass;
    std::thread p1([&] {
        worker_pass = persister->persist_staged(*rt, GuardianBaselinePersister::Trigger::Worker);
    });
    Join4045 join_p1{p1};
    REQUIRE(yuzu::test::spin_until([&] { return in_pass.load(); }));

    int apply_exit = -1;
    std::atomic<bool> apply_done{false};
    std::thread a([&] {
        apply_exit = f.dispatch_raw(rule, /*full_sync=*/false).exit_code;
        apply_done.store(true);
    });
    Join4045 join_a{a};
    // apply_rules' forced drain is now blocked behind the parked pass: observed, not slept.
    REQUIRE(yuzu::test::spin_until([&] { return persister->lock_waiters_for_test() == 1; }));
    CHECK_FALSE(apply_done.load());
    CHECK(staged_in_pass.load() == static_cast<std::size_t>(kN)); // visible while the pass runs

    release.store(true);
    p1.join();
    a.join();
    persister->set_post_snapshot_hook_for_test(nullptr);
    CHECK(worker_pass.failed == 3); // max_failures, not one per staged capture
    CHECK(worker_pass.written == 0);
    CHECK_FALSE(worker_pass.budget_exhausted); // it FAILED: the backoff, not a prompt re-run
    CHECK(apply_exit == 0);
    // One failed PASS each (the parked worker pass and the apply drain), 3 writes apiece.
    CHECK(persister->persist_failures() == failures_before + 2);
    CHECK(rt->staged_baseline_count_for_test() == static_cast<std::size_t>(kN)); // none lost
    heal_baseline_writes_4045(f.db_.path);
}

TEST_CASE("#4045 E17: a worker pass launched between the seed read and the attach cannot hide "
          "the capture: the replacement still drifts against it (the fence keeps the race closed)",
          "[spark][guardian][baseline][reconcile]") {
    // The schedule that makes the fence REQUIRED: T_s (engine KV seed read: empty, the capture
    // is only staged) < W (a pass writes the capture) < E (the pass erases it from staging) <
    // T_a (attach_core's staged read). Without the fence neither read sees the capture, the
    // replacement captures the drifted content as compliant, and no drift is ever reported.
    // Here the seed-read hook launches the "worker" pass and waits until it has either FINISHED
    // (no fence: it ran in the gap) or is observed BLOCKED on persist_mu_ (fence: lock_waiters
    // is only incremented when the try_lock found the mutex held). Both outcomes are observed,
    // never slept for, so the unmutated run and the mutated run are both deterministic.
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    const fs::path target = t.file(); // ABSENT at the first apply: no capture yet
    const auto rule = make_file_hash_rule("r1", target.string());
    f.apply(rule);
    REQUIRE(yuzu::test::spin_until([&] { return !compliance_4045(f, "r1").empty(); }));
    f.engine->drain_worker_for_test()->stop();
    auto* rt = f.engine->spark_runtime_for_test();
    auto* persister = f.engine->baseline_persister_for_test();
    REQUIRE(rt != nullptr);
    REQUIRE(persister != nullptr);

    Spark4045Target::write(target, "content A");
    const std::string h_a = hash_of_4045(target);
    std::string h_b;
    // After apply_rules' drain: the still-live OLD generation reads A and stages it.
    f.engine->set_apply_post_drain_hook_for_test([&] { eval_initial_4045(*f.engine, target); });

    std::atomic<bool> w_done{false};
    GuardianBaselinePersister::Outcome w_out;
    std::thread w;
    Join4045 join_w{w};
    std::atomic<bool> held_past_attach{false};
    HookGuard4045 hooks{*f.engine};
    // The fence must span the ATTACH too (QE-9): the "worker" launched at the seed read is
    // still blocked, not finished, when attach_rule has returned.
    f.engine->set_post_attach_hook_for_test([&](const std::string&) {
        held_past_attach.store(!w_done.load() && persister->lock_waiters_for_test() >= 1);
    });
    f.engine->set_seed_read_hook_for_test([&](const std::string&) {
        // The seed read just found the KV empty. Launch the pass, then drift the file.
        w = std::thread([&] {
            w_out = persister->persist_staged(*rt, GuardianBaselinePersister::Trigger::Worker);
            w_done.store(true);
        });
        CHECK(yuzu::test::spin_until(
            [&] { return w_done.load() || persister->lock_waiters_for_test() >= 1; }));
        Spark4045Target::write(target, "content B, longer");
        h_b = hash_of_4045(target);
    });
    f.apply(rule, /*full_sync=*/false);
    f.engine->set_apply_post_drain_hook_for_test(nullptr);
    f.engine->set_seed_read_hook_for_test(nullptr);
    if (w.joinable())
        w.join();
    REQUIRE_FALSE(h_b.empty()); // the hook ran
    REQUIRE(h_b != h_a);
    CHECK(held_past_attach.load()); // RED if the fence is released before attach_rule returns
    CHECK(w_out.written == 1); // the pass did run, after the reconcile released the fence

    eval_initial_4045(*f.engine, target);
    std::vector<OutboxEntry> drained;
    const bool drifted = yuzu::test::spin_until([&] {
        rt->drain([&](const OutboxEntry& e) {
            drained.push_back(e);
            return SendResult::Sent;
        });
        for (const auto& e : drained)
            if (e.domain == yuzu::agent::OutboxDomain::Compliance && !e.drift.compliant &&
                e.drift.expected_value == h_a && e.drift.detected_value == h_b)
                return true;
        return false;
    });
    CHECK(drifted); // RED without the fence: the replacement captured B as compliant
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_a);
}

// C4045-2: every staging-loss channel must reach the heartbeat aggregate.
TEST_CASE("#4045 E15: captures dropped from staging surface on the heartbeat tag",
          "[spark][guardian][baseline][reconcile]") {
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    // Parked first: a worker pass between the inserts would persist and erase them.
    f.engine->drain_worker_for_test()->stop();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(rt != nullptr);
    CHECK(f.engine->baseline_persist_failures() == 0);

    // A retarget over a still-unpersisted capture loses the first capture (A -> B)...
    rt->stage_baseline_for_test("cap-rule", "/yuzu_test_4045_cap/a", std::string(64, 'a'));
    rt->stage_baseline_for_test("cap-rule", "/yuzu_test_4045_cap/b", std::string(64, 'b'));
    CHECK(rt->staged_baseline_drops() == 1);
    CHECK(f.engine->baseline_persist_failures() == 1);
    // ...and an allocation failure while staging drops the new capture.
    rt->fail_next_stage_baseline_for_test();
    rt->stage_baseline_for_test("alloc-rule", "/yuzu_test_4045_cap/c", std::string(64, 'c'));
    CHECK(rt->staged_baseline_drops() == 2);

    // No KV write failed and nothing threw: the ONLY signal is the drops, and it is exported.
    CHECK(f.engine->baseline_persist_failures() == 2);
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_guardian_baseline_persist_heartbeat_tags(tags, f.engine->baseline_persist_failures());
    REQUIRE(tags.count("yuzu.guardian_baseline_persist_failures") == 1);
    CHECK(tags.at("yuzu.guardian_baseline_persist_failures") == "2");
    CHECK(std::string{yuzu::agent::kGuardianBaselinePersistFailuresTag} ==
          "yuzu.guardian_baseline_persist_failures");
}

TEST_CASE("#4045 E16: a capture staged with no KV store is counted, logged once and kept",
          "[spark][guardian][baseline][reconcile]") {
    // A standalone persister over a null store and the fixture's runtime (the engine itself
    // refuses apply_rules without a store, so the engine-level path cannot stage this).
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(rt != nullptr);
    rt->stage_baseline_for_test("r1", "/yuzu_test_4045_nostore", std::string(64, 'b'));
    REQUIRE(rt->staged_baseline_count_for_test() == 1);

    yuzu::agent::GuardianBaselinePersister no_store{nullptr};
    CHECK(no_store.no_store_pending() == 0);
    (void)no_store.persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    (void)no_store.persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    (void)no_store.persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    CHECK(no_store.no_store_pending() == 3);       // counted per pass that finds a capture
    CHECK(no_store.no_store_logs_for_test() == 1); // ...but logged ONCE
    CHECK(no_store.persist_failures() == 0);
    CHECK(rt->staged_baseline_count_for_test() == 1); // never discarded

    // Nothing staged -> nothing counted (a quiescent no-store engine is not an incident).
    rt->erase_staged_baselines_if_unchanged(rt->snapshot_staged_baselines());
    (void)no_store.persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    CHECK(no_store.no_store_pending() == 3);
}

// ── #4045 governance fix round 1 and 2 ───────────────────────────────────────────────────
TEST_CASE("#4045 E18: a failing tuple does NOT block the ones behind it (no head-of-line "
          "starvation), and a pass gives up after max_failures failed writes",
          "[spark][guardian][baseline][reconcile]") {
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    for (int i = 0; i < 5; ++i)
        rt->stage_baseline_for_test("r" + std::to_string(i), "/yuzu_test_4045_e18/" + std::to_string(i),
                                    std::string(64, 'a'));
    // r0, the FIRST tuple in rule_id order, fails for real on every pass (a per-key fault). The
    // first-failure abort of the previous round persisted none of the five behind it.
    fail_baseline_writes_4045(f.db_.path, "baseline:r0");

    const auto out = persist_now_4045(*f.engine);
    CHECK(out.written == 4);
    CHECK(out.failed == 1);
    CHECK_FALSE(out.budget_exhausted);
    CHECK(persister->persist_failures() == 1); // one failed PASS
    CHECK(rt->staged_baseline_count_for_test() == 1); // only r0 stays staged
    CHECK_FALSE(baseline_record_4045(*f.kv, "r0").has_value());
    CHECK(baseline_record_4045(*f.kv, "r1").has_value());
    CHECK(baseline_record_4045(*f.kv, "r4").has_value());

    // A GLOBAL fault: every write fails. The pass attempts max_failures (3) of the 5 and stops;
    // it is still ONE failed pass, and nothing is lost.
    heal_baseline_writes_4045(f.db_.path);
    rt->erase_staged_baselines_if_unchanged(rt->snapshot_staged_baselines());
    for (int i = 0; i < 5; ++i)
        rt->stage_baseline_for_test("g" + std::to_string(i), "/yuzu_test_4045_e18g/" + std::to_string(i),
                                    std::string(64, 'b'));
    fail_baseline_writes_4045(f.db_.path);
    const auto before = persister->persist_failures();
    const auto global = persist_now_4045(*f.engine);
    CHECK(global.written == 0);
    CHECK(global.failed == 3); // max_failures
    CHECK(persister->persist_failures() == before + 1);
    CHECK(rt->staged_baseline_count_for_test() == 5); // none lost, two never attempted
    CHECK_FALSE(baseline_record_4045(*f.kv, "g4").has_value());

    heal_baseline_writes_4045(f.db_.path);
    const auto healed = persist_now_4045(*f.engine);
    CHECK(healed.written == 5);
    CHECK(healed.failed == 0);
    CHECK(rt->staged_baseline_count_for_test() == 0);
    CHECK(baseline_record_4045(*f.kv, "g4").has_value());
}

TEST_CASE("#4045 E19: staging has no cap and a pass has a tuple budget: 300 captures all persist "
          "over back-to-back budget-exhausted passes, none dropped",
          "[spark][guardian][baseline][reconcile]") {
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* rt = f.engine->spark_runtime_for_test();
    auto* persister = f.engine->baseline_persister_for_test();
    REQUIRE(rt != nullptr);
    REQUIRE(persister != nullptr);
    constexpr int kN = 300; // the old staging cap was 256
    for (int i = 0; i < kN; ++i)
        rt->stage_baseline_for_test("r" + std::to_string(i), "/yuzu_test_4045_e19/" + std::to_string(i),
                                    std::string(64, 'a'));
    CHECK(rt->staged_baseline_count_for_test() == static_cast<std::size_t>(kN));
    CHECK(f.engine->baseline_persist_failures() == 0); // nothing dropped

    // 64 tuples per pass (kBaselinePassBudget): 4 full passes report budget_exhausted, the
    // 5th drains the last 44. A budget-exhausted pass is NOT a failure and sets no backoff.
    std::size_t written = 0;
    int passes = 0;
    int exhausted = 0;
    while (rt->staged_baseline_count_for_test() != 0 && passes < 20) {
        const auto out = persist_now_4045(*f.engine);
        ++passes;
        written += out.written;
        CHECK(out.failed == 0);
        if (out.budget_exhausted)
            ++exhausted;
    }
    CHECK(written == static_cast<std::size_t>(kN));
    CHECK(passes == 5);
    CHECK(exhausted == 4);
    CHECK(persister->persist_failures() == 0);
    CHECK(persister->backoff_for_test() == std::chrono::seconds{0});
    CHECK(baseline_record_4045(*f.kv, "r0").has_value());
    CHECK(baseline_record_4045(*f.kv, "r299").has_value());
}

TEST_CASE("#4045 E20: the worker retry backoff doubles 5 s -> 60 s, forced drains ignore it, "
          "success resets it (injected clock, no sleeps)",
          "[spark][guardian][baseline][reconcile]") {
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    using Trig = GuardianBaselinePersister::Trigger;
    using namespace std::chrono_literals;

    auto now_s = std::make_shared<std::atomic<std::int64_t>>(1000);
    const auto base = std::chrono::steady_clock::time_point{};
    persister->set_clock_for_test(
        [now_s, base] { return base + std::chrono::seconds{now_s->load()}; });
    rt->stage_baseline_for_test("r1", "/yuzu_test_4045_e20", std::string(64, 'a'));
    fail_baseline_writes_4045(f.db_.path);

    auto w1 = persister->persist_staged(*rt, Trig::Worker);
    CHECK(w1.failed == 1);
    CHECK(persister->backoff_for_test() == 5s);
    now_s->store(1004); // 4 s later: the retry is not due
    auto w2 = persister->persist_staged(*rt, Trig::Worker);
    CHECK(w2.backoff_deferred);
    CHECK(w2.failed == 0);
    CHECK(persister->persist_failures() == 1); // nothing was attempted
    now_s->store(1005); // due
    auto w3 = persister->persist_staged(*rt, Trig::Worker);
    CHECK(w3.failed == 1);
    CHECK(persister->backoff_for_test() == 10s);
    // A forced drain (apply_rules / stop) attempts regardless of the backoff...
    auto f1 = persister->persist_staged(*rt, Trig::Forced);
    CHECK_FALSE(f1.backoff_deferred);
    CHECK(f1.failed == 1);
    CHECK(persister->backoff_for_test() == 20s); // ...and a failed pass widens it
    // The width doubles up to the 60 s cap.
    for (int i = 0; i < 3; ++i) {
        now_s->fetch_add(1000);
        (void)persister->persist_staged(*rt, Trig::Worker);
    }
    CHECK(persister->backoff_for_test() == 60s);
    CHECK(persister->persist_failures() == 6);

    // Healing: once the backoff has elapsed the worker pass writes, and the width resets.
    heal_baseline_writes_4045(f.db_.path);
    now_s->fetch_add(1000);
    auto w4 = persister->persist_staged(*rt, Trig::Worker);
    CHECK(w4.written == 1);
    CHECK(persister->backoff_for_test() == 0s);
    CHECK(rt->staged_baseline_count_for_test() == 0);
    persister->set_clock_for_test({});
}

TEST_CASE("#4045 E21: the heartbeat getter never waits on mtx_ or on a persist pass",
          "[spark][guardian][baseline][reconcile]") {
    // baseline_persist_failures() is lock-free: it must return while apply_rules holds mtx_
    // (the post-drain hook runs with mtx_ held) AND while a persist pass is parked holding
    // persist_mu_. Probed from another thread, bounded by spin_until, so a regression to a
    // mtx_-taking getter fails the CHECK instead of hanging the binary.
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);

    std::atomic<bool> got{false};
    std::atomic<std::uint64_t> seen{99};
    std::thread probe;
    Join4045 join_probe{probe};
    std::atomic<bool> hook_ok{false};
    HookGuard4045 hooks{*f.engine};
    f.engine->set_apply_post_drain_hook_for_test([&] {
        probe = std::thread([&] {
            seen.store(f.engine->baseline_persist_failures());
            got.store(true);
        });
        hook_ok.store(yuzu::test::spin_until([&] { return got.load(); }));
    });
    f.apply(make_file_hash_rule("r1", t.file().string()));
    f.engine->set_apply_post_drain_hook_for_test(nullptr);
    CHECK(hook_ok.load()); // RED if the getter takes mtx_ (it would wait for apply_rules)
    CHECK(seen.load() == 0);
    if (probe.joinable())
        probe.join();

    // And while a pass is parked mid-flight holding persist_mu_.
    rt->stage_baseline_for_test("r9", "/yuzu_test_4045_e21", std::string(64, 'a'));
    std::atomic<bool> in_pass{false};
    std::atomic<bool> release{false};
    persister->set_post_snapshot_hook_for_test([&] {
        in_pass.store(true);
        (void)yuzu::test::spin_until([&] { return release.load(); });
    });
    std::thread pass([&] { (void)persister->persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced); });
    Join4045 join_pass{pass};
    REQUIRE(yuzu::test::spin_until([&] { return in_pass.load(); }));
    std::atomic<bool> got2{false};
    std::thread probe2([&] {
        (void)f.engine->baseline_persist_failures();
        got2.store(true);
    });
    Join4045 join_probe2{probe2};
    CHECK(yuzu::test::spin_until([&] { return got2.load(); }, std::chrono::milliseconds{500}));
    release.store(true);
    pass.join();
    probe2.join();
    persister->set_post_snapshot_hook_for_test(nullptr);
}

TEST_CASE("#4045 E22: a throw out of the snapshot is firewalled and counted on the engine "
          "aggregate, and loses no capture (engine and worker firewalls)",
          "[spark][guardian][baseline][reconcile]") {
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    CHECK(f.engine->baseline_persist_failures() == 0);

    // Worker firewall: park-free, the worker is live; wake it with the seam armed.
    persister->set_backoff_for_test(std::chrono::milliseconds{1}, std::chrono::milliseconds{1});
    rt->stage_baseline_for_test("r1", "/yuzu_test_4045_e22", std::string(64, 'a'));
    rt->fail_next_snapshot_for_test();
    f.engine->drain_worker_for_test()->notify();
    REQUIRE(yuzu::test::spin_until([&] { return persister->firewalled_exceptions() >= 1; }));
    // ...nothing was lost to the throw: the worker's next pass persists it once the backoff the
    // throw set (shortened here to 1 ms so the test does not wait out 5 s) has elapsed. The
    // throw consumed the wake that triggered it and the backstop is pinned to an hour, so each
    // poll wakes it again.
    REQUIRE(yuzu::test::spin_until([&] {
        f.engine->drain_worker_for_test()->notify();
        return baseline_record_4045(*f.kv, "r1").has_value();
    }));

    // Engine firewall (apply_rules' drain): park the worker so only apply_rules runs a pass.
    f.engine->drain_worker_for_test()->stop();
    const auto before = persister->firewalled_exceptions();
    rt->stage_baseline_for_test("r2", "/yuzu_test_4045_e22b", std::string(64, 'b'));
    rt->fail_next_snapshot_for_test();
    f.apply(make_file_hash_rule("r1", t.file().string()));
    CHECK(persister->firewalled_exceptions() == before + 1);
    CHECK(rt->staged_baseline_count_for_test() >= 1); // r2 is still staged, never lost
    CHECK(f.engine->baseline_persist_failures() >= before + 1);
    // The aggregate is the sum of the persister's terms (E23 pins each term).
    CHECK(f.engine->baseline_persist_failures() == persister->failure_signals());
}

TEST_CASE("#4045 E23: every term of the heartbeat aggregate is pinned",
          "[spark][guardian][baseline][reconcile]") {
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(rt != nullptr);

    auto drops = std::make_shared<std::atomic<std::uint64_t>>(0);
    yuzu::agent::GuardianBaselinePersister no_store{nullptr, drops};
    CHECK(no_store.failure_signals() == 0);
    drops->store(3); // runtime drops
    CHECK(no_store.failure_signals() == 3);
    rt->stage_baseline_for_test("r1", "/yuzu_test_4045_e23", std::string(64, 'a'));
    (void)no_store.persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced); // one pass that found a capture and no store
    CHECK(no_store.failure_signals() == 4);
    no_store.note_firewalled_exception(); // a firewalled throw
    CHECK(no_store.failure_signals() == 5);

    // The failed-pass term, on a persister over the real store with every write failing.
    yuzu::agent::GuardianBaselinePersister real{f.kv.get(), drops};
    fail_baseline_writes_4045(f.db_.path);
    (void)real.persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    CHECK(real.persist_failures() == 1);
    CHECK(real.failure_signals() == 4); // 3 drops + 1 failed pass
    heal_baseline_writes_4045(f.db_.path);
    // A refusal is NOT a term: the guard working must not read as a failure.
    nlohmann::json existing;
    existing["schema"] = 1;
    existing["fingerprint"] = "file-hash-equals|/yuzu_test_4045_e23";
    existing["hash"] = std::string(64, 'c');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", existing.dump()));
    (void)real.persist_staged(*rt, GuardianBaselinePersister::Trigger::Forced);
    CHECK(real.persist_refusals() == 1);
    CHECK(real.failure_signals() == 4);
}

// ── #4045 governance fix round 2 ─────────────────────────────────────────────────────────
TEST_CASE("#4045 E24: a capture that could not be staged is NOT committed: the next evaluation "
          "captures and stages it, it persists, and the live baseline equals the durable record",
          "[spark][guardian][baseline][reconcile]") {
    // Gate 8 SEC F-1: an allocation failure while staging used to be counted but the evaluation
    // still committed the baseline, so the capture was neither staged nor durable and the next
    // full_sync recaptured drifted content as compliant (no record, no drift).
    Spark4045Target t;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(rt != nullptr);
    const fs::path target = t.file();
    Spark4045Target::write(target, "content A");
    const std::string h_a = hash_of_4045(target);

    rt->fail_next_stage_baseline_for_test(); // consumed by the arm-time evaluation inside apply()
    f.apply(make_file_hash_rule("r1", target.string()));
    REQUIRE(yuzu::test::spin_until([&] { return rt->staged_baseline_drops() == 1; }));
    CHECK(rt->staged_baseline_count_for_test() == 0);
    CHECK(f.engine->baseline_persist_failures() == 1); // counted on the heartbeat aggregate

    // Nothing was committed as the baseline, so the next evaluation captures A again and this
    // time stages it...
    eval_initial_4045(*f.engine, target);
    CHECK(rt->staged_baseline_count_for_test() == 1);
    // ...and it persists.
    const auto out = persist_now_4045(*f.engine);
    CHECK(out.written == 1);
    const auto rec = baseline_record_4045(*f.kv, "r1");
    REQUIRE(rec.has_value());
    CHECK(rec->value("hash", std::string{}) == h_a);

    // The file drifts and a full_sync re-arms: the live baseline is the DURABLE one, so the
    // drift is reported against A and the record is untouched (no laundering).
    Spark4045Target::write(target, "content B, longer");
    const std::string h_b = hash_of_4045(target);
    REQUIRE(h_b != h_a);
    f.apply(make_file_hash_rule("r1", target.string()), /*full_sync=*/true);
    eval_initial_4045(*f.engine, target);
    std::vector<OutboxEntry> drained;
    const bool drifted = yuzu::test::spin_until([&] {
        rt->drain([&](const OutboxEntry& e) {
            drained.push_back(e);
            return SendResult::Sent;
        });
        for (const auto& e : drained)
            if (e.domain == yuzu::agent::OutboxDomain::Compliance && !e.drift.compliant &&
                e.drift.expected_value == h_a && e.drift.detected_value == h_b)
                return true;
        return false;
    });
    CHECK(drifted);
    CHECK(baseline_record_4045(*f.kv, "r1")->value("hash", std::string{}) == h_a);
}

namespace {
/// An injected steady clock the test advances by hand; the persister reads it for the backoff
/// and the pass wall budget. Restores the real clock on any exit.
struct FakeClock4045 {
    std::shared_ptr<std::atomic<std::int64_t>> ms = std::make_shared<std::atomic<std::int64_t>>(1'000'000);
    GuardianBaselinePersister& p;
    explicit FakeClock4045(GuardianBaselinePersister& persister) : p(persister) {
        auto m = ms;
        p.set_clock_for_test([m] {
            return std::chrono::steady_clock::time_point{} + std::chrono::milliseconds{m->load()};
        });
    }
    ~FakeClock4045() { p.set_clock_for_test({}); }
    void advance(std::int64_t d) { ms->fetch_add(d); }
};
void stage_n_4045(yuzu::agent::GuardianSparkRuntime& rt, int n, const char* tag, char fill = 'a') {
    for (int i = 0; i < n; ++i)
        rt.stage_baseline_for_test("r" + std::to_string(i), std::string{"/yuzu_test_4045_"} + tag + "/" + std::to_string(i),
                                   std::string(64, fill));
}
} // namespace

TEST_CASE("#4045 E25: the pass wall budget stops a run of SLOW but successful writes, and a "
          "budget-exhausted pass is not a failure (no backoff)",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    FakeClock4045 clock{*persister};
    HookGuard4045 hooks{*f.engine};
    // Every write "takes" 600 ms on the injected clock: the 2 s wall budget is reached after the
    // 4th write (elapsed 2400 ms at the next between-tuples check), whatever the 10 captures.
    persister->set_post_write_hook_for_test([&] { clock.advance(600); });
    stage_n_4045(*rt, 10, "e25");

    using Trig = GuardianBaselinePersister::Trigger;
    const auto first = persister->persist_staged(*rt, Trig::Worker);
    CHECK(first.written == 4);
    CHECK(first.failed == 0);
    CHECK(first.budget_exhausted);
    CHECK(rt->staged_baseline_count_for_test() == 6);
    CHECK(persister->persist_failures() == 0);
    CHECK(persister->backoff_for_test() == 0ms); // exhausted is NOT a failure: no backoff
    // ...so the very next worker pass is not deferred and carries on from where it stopped.
    const auto second = persister->persist_staged(*rt, Trig::Worker);
    CHECK_FALSE(second.backoff_deferred);
    CHECK(second.written == 4);
    const auto third = persister->persist_staged(*rt, Trig::Worker);
    CHECK(third.written == 2);
    CHECK_FALSE(third.budget_exhausted);
    CHECK(rt->staged_baseline_count_for_test() == 0);
    CHECK(persister->backoff_deferrals_for_test() == 0);
}

TEST_CASE("#4045 E26: the tuple budget caps a pass, and the wall budget is wall-time not "
          "wall-count (a stalled FAILING write ends the pass at once)",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    FakeClock4045 clock{*persister};
    HookGuard4045 hooks{*f.engine};
    using Trig = GuardianBaselinePersister::Trigger;
    stage_n_4045(*rt, 7, "e26");

    persister->set_budgets_for_test({3, 3, 1h}, {3, 1, 1h}); // 3 tuples per pass, effectively no wall
    CHECK(persister->persist_staged(*rt, Trig::Forced).written == 3);
    CHECK(persister->persist_staged(*rt, Trig::Forced).written == 3);
    const auto last = persister->persist_staged(*rt, Trig::Forced);
    CHECK(last.written == 1);
    CHECK_FALSE(last.budget_exhausted);

    // A BUSY store: every write fails after a 5 s busy timeout. After the FIRST failure the wall
    // budget (2 s) is spent, so the pass stops with 1 failed write although max_failures is 3.
    persister->set_budgets_for_test(yuzu::agent::GuardianBaselinePassBudget{64, 3, 2000ms}, yuzu::agent::kBaselineStopBudget);
    stage_n_4045(*rt, 5, "e26b", 'b');
    fail_baseline_writes_4045(f.db_.path);
    persister->set_post_write_hook_for_test([&] { clock.advance(5000); });
    const auto busy = persister->persist_staged(*rt, Trig::Forced);
    CHECK(busy.failed == 1);
    CHECK(busy.written == 0);
    CHECK_FALSE(busy.budget_exhausted); // it failed: the failure backoff governs, not a re-run
    CHECK(rt->staged_baseline_count_for_test() == 5);
    heal_baseline_writes_4045(f.db_.path);
}

TEST_CASE("#4045 E27: the rotating cursor stops a tuple that fails every time from starving the "
          "ones sorted behind it, across passes",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    using Trig = GuardianBaselinePersister::Trigger;
    // ONE failure ends a pass (the stop-style budget on every pass), so without rotation the
    // deterministic failer r0 would end every pass before any later tuple was tried.
    persister->set_budgets_for_test({64, 1, 1h}, {64, 1, 1h});
    stage_n_4045(*rt, 5, "e27");
    fail_baseline_writes_4045(f.db_.path, "baseline:r0");

    const auto p1 = persister->persist_staged(*rt, Trig::Forced);
    CHECK(p1.failed == 1);
    CHECK(p1.written == 0); // r0 first, then the pass gave up
    CHECK(rt->staged_baseline_count_for_test() == 5);
    const auto p2 = persister->persist_staged(*rt, Trig::Forced);
    // Starts AFTER r0: r1..r4 persist, then the lap wraps to r0 and fails.
    CHECK(p2.written == 4);
    CHECK(p2.failed == 1);
    CHECK(rt->staged_baseline_count_for_test() == 1); // only the poisoned r0
    CHECK(baseline_record_4045(*f.kv, "r1").has_value());
    CHECK(baseline_record_4045(*f.kv, "r4").has_value());
    CHECK_FALSE(baseline_record_4045(*f.kv, "r0").has_value());
    heal_baseline_writes_4045(f.db_.path);
    CHECK(persister->persist_staged(*rt, Trig::Forced).written == 1);
    CHECK(rt->staged_baseline_count_for_test() == 0);
}

TEST_CASE("#4045 E28: stop() runs under the tighter stop budget and SKIPS its pass after a slow "
          "failed pass, but still tries after a fast one",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    FakeClock4045 clock{*persister};
    HookGuard4045 hooks{*f.engine};
    using Trig = GuardianBaselinePersister::Trigger;
    stage_n_4045(*rt, 5, "e28");
    fail_baseline_writes_4045(f.db_.path);

    // Stop budget: ONE failure ends the pass, even though the (fast) failure spent no wall.
    const auto stop1 = persister->persist_staged(*rt, Trig::Stop);
    CHECK(stop1.failed == 1);
    CHECK_FALSE(stop1.skipped_after_stall);
    // A FAST failure is not a stall: stop still tries (nothing slow to repeat).
    const auto stop2 = persister->persist_staged(*rt, Trig::Stop);
    CHECK_FALSE(stop2.skipped_after_stall);
    CHECK(stop2.failed == 1);

    // A SLOW failed pass (a BUSY store: each write burns a busy timeout) marks the store
    // stalled; stop's pass is then skipped without touching the store.
    persister->set_post_write_hook_for_test([&] { clock.advance(5000); });
    const auto slow = persister->persist_staged(*rt, Trig::Forced);
    CHECK(slow.failed == 1);
    const auto failures = persister->persist_failures();
    const auto stop3 = persister->persist_staged(*rt, Trig::Stop);
    CHECK(stop3.skipped_after_stall);
    CHECK(stop3.failed == 0);
    CHECK(stop3.written == 0);
    CHECK(persister->persist_failures() == failures); // nothing was attempted
    CHECK(rt->staged_baseline_count_for_test() == 5);  // and nothing was lost

    // A pass that persists anything clears the stall, so a later stop tries again.
    heal_baseline_writes_4045(f.db_.path);
    persister->set_post_write_hook_for_test(nullptr);
    CHECK(persister->persist_staged(*rt, Trig::Forced).written == 5);
    stage_n_4045(*rt, 2, "e28b", 'c');
    const auto stop4 = persister->persist_staged(*rt, Trig::Stop);
    CHECK_FALSE(stop4.skipped_after_stall);
    CHECK(stop4.written == 2);
}

TEST_CASE("#4045 E29: the REAL worker honours the retry backoff: wakes while a failed pass's "
          "backoff is pending are deferred, not retried (a Forced worker pass would retry at once)",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    auto* worker = f.engine->drain_worker_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    REQUIRE(worker != nullptr);
    // A one-hour backoff makes the REAL clock irrelevant: once a pass has failed, no wall time
    // this test can take makes the next worker pass due. (The setter is locked, so it is safe
    // against the live worker; the hour-long periodic backstop means only notify() wakes it.)
    persister->set_backoff_for_test(1h, 1h);
    stage_n_4045(*rt, 1, "e29");
    fail_baseline_writes_4045(f.db_.path);
    worker->notify();
    REQUIRE(yuzu::test::spin_until([&] { return persister->persist_failures() == 1; }));
    for (std::uint64_t i = 1; i <= 5; ++i) {
        worker->notify();
        REQUIRE(yuzu::test::spin_until([&] { return persister->backoff_deferrals_for_test() >= i; }));
    }
    CHECK(persister->persist_failures() == 1); // RED if the worker passed Forced: one per wake
    CHECK(persister->backoff_for_test() == 1h);
    heal_baseline_writes_4045(f.db_.path);
}

TEST_CASE("#4045 E30: a Worker pass that was waiting on the lock re-checks the backoff after it "
          "gets the lock (another drainer failed while it waited)",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    FakeClock4045 clock{*persister};
    HookGuard4045 hooks{*f.engine};
    using Trig = GuardianBaselinePersister::Trigger;
    stage_n_4045(*rt, 1, "e30");
    fail_baseline_writes_4045(f.db_.path);

    std::atomic<bool> in_pass{false};
    std::atomic<bool> release{false};
    std::atomic<bool> hook_armed{true};
    persister->set_post_snapshot_hook_for_test([&] {
        if (!hook_armed.exchange(false))
            return;
        in_pass.store(true);
        (void)yuzu::test::spin_until([&] { return release.load(); });
    });
    GuardianBaselinePersister::Outcome forced;
    std::thread a([&] { forced = persister->persist_staged(*rt, Trig::Forced); });
    Join4045 join_a{a};
    REQUIRE(yuzu::test::spin_until([&] { return in_pass.load(); }));
    // The Worker pass sees no backoff yet (nothing has failed), so it queues on the lock...
    GuardianBaselinePersister::Outcome worker;
    std::thread b([&] { worker = persister->persist_staged(*rt, Trig::Worker); });
    Join4045 join_b{b};
    REQUIRE(yuzu::test::spin_until([&] { return persister->lock_waiters_for_test() == 1; }));
    release.store(true);
    a.join();
    b.join();
    // ...the Forced pass fails and sets the backoff, and the waiter must NOT write again.
    CHECK(forced.failed == 1);
    CHECK(worker.backoff_deferred); // RED without the post-lock due() re-check
    CHECK(worker.failed == 0);
    CHECK(persister->persist_failures() == 1);
    CHECK(persister->lock_waiters_for_test() == 0);
    heal_baseline_writes_4045(f.db_.path);
}

TEST_CASE("#4045 E31: the INFO line for a persisted capture carries the rule id through "
          "log_id_token only, and is emitted once per Written capture",
          "[spark][guardian][baseline][reconcile]") {
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    // The line is a pure function of the rule id (no path and no hash can be passed in), and a
    // hostile id cannot forge a log line.
    const std::string line = GuardianBaselinePersister::persisted_log_line("evil\nrule id=x");
    CHECK(line.find('\n') == std::string::npos);
    CHECK(line.find(' ' + std::string{"id=x"}) == std::string::npos);
    CHECK(line == "Guardian: persisted Spark baseline capture for rule 'evil_rule_id_x' (#4045)");

    stage_n_4045(*rt, 3, "e31");
    CHECK(persister->info_logs_for_test() == 0);
    CHECK(persist_now_4045(*f.engine).written == 3);
    CHECK(persister->info_logs_for_test() == 3);
    // A refusal is not a persisted capture: no line.
    rt->stage_baseline_for_test("r0", "/yuzu_test_4045_e31/0", std::string(64, 'z'));
    (void)persist_now_4045(*f.engine);
    CHECK(persister->persist_refusals() == 1);
    CHECK(persister->info_logs_for_test() == 3);
}

TEST_CASE("#4045 E32: the LIVE worker re-runs at once while a budget-exhausted pass leaves "
          "captures staged (no failure, no wait for the next wake or the backstop)",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    // The periodic backstop is pinned to one hour, so only a wake or the immediate re-run can
    // start another pass. 2 tuples per pass, 9 captures: one wake must drain all of them.
    persister->set_budgets_for_test({2, 3, 1h}, {2, 1, 1h}); // locked: safe against the live worker
    stage_n_4045(*rt, 9, "e32");
    f.engine->drain_worker_for_test()->notify(); // ONE wake
    REQUIRE(yuzu::test::spin_until([&] { return rt->staged_baseline_count_for_test() == 0; }));
    CHECK(baseline_record_4045(*f.kv, "r0").has_value());
    CHECK(baseline_record_4045(*f.kv, "r8").has_value());
    CHECK(persister->persist_failures() == 0);
    CHECK(persister->backoff_deferrals_for_test() == 0);
}

TEST_CASE("#4045 E33: a throw out of the snapshot widens the worker backoff, so a persistent "
          "allocation failure cannot re-run on every wake",
          "[spark][guardian][baseline][reconcile]") {
    using namespace std::chrono_literals;
    SparkReconcileFixture f{3'600'000, std::nullopt, SparkType::File};
    f.engine->drain_worker_for_test()->stop();
    auto* persister = f.engine->baseline_persister_for_test();
    auto* rt = f.engine->spark_runtime_for_test();
    REQUIRE(persister != nullptr);
    REQUIRE(rt != nullptr);
    FakeClock4045 clock{*persister};
    using Trig = GuardianBaselinePersister::Trigger;
    stage_n_4045(*rt, 1, "e33");
    rt->fail_next_snapshot_for_test();
    CHECK_THROWS_AS(persister->persist_staged(*rt, Trig::Worker), std::bad_alloc);
    CHECK(persister->backoff_for_test() == 5s);
    const auto deferred = persister->persist_staged(*rt, Trig::Worker);
    CHECK(deferred.backoff_deferred);
    CHECK(rt->staged_baseline_count_for_test() == 1); // nothing lost
    clock.advance(5000);
    CHECK(persister->persist_staged(*rt, Trig::Worker).written == 1); // due again: it persists
}
