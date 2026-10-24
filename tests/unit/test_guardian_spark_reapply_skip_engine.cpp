// test_guardian_spark_reapply_skip_engine.cpp - #4415 PR-A, ENGINE level, RED-FIRST.
//
// What this pins. Before #4415 every full_sync push tore down and re-armed EVERY Spark rule
// (GuardianSparkRuntime::detach_all() then a fresh attach per rule), so one stuck key made the
// whole ruleset pay a teardown + re-arm per Reapply, and an identical healthy re-push was not free
// either. PR-A replaced that with a per-rule skip (a rule that is already healthy and unchanged is
// left alone) and a full_sync detach scoped to the rules ABSENT from the push. These cases drive
// the REAL GuardianEngine (prefer_spark=true) + REAL SparkEngine + the real runtime / ack ledger /
// io executor with a counting fake ISparkMechanism, and assert EFFECT SETS (per-key watch/unwatch
// calls, the mechanism's live watch set, lifecycle and compliant outbox entries, the ack ledger's
// stats, the held generation in memory and on disk). They never assert on "applied" or arm_stats
// alone.
//
// COLOUR TAXONOMY (the report that accompanies this file states which is which):
//   RED-BY-DESIGN   fails on the baseline (origin/dev) at an effect assertion that names the
//                   storm ("expected watch==1 on a healthy sibling, got 2"). Turns green when the
//                   skip lands.
//   GUARD           deliberately GREEN on the baseline: it pins the other side of a skip term (an
//                   Unknown rule, a faulted subscription, an empty baseline seed must still be
//                   REBUILT). A guard is the only thing that stops "skip everything" from passing.
//                   Every guarded case also carries a sibling-untouched assertion, so the CASE as a
//                   whole is red on the baseline while its "rebuilt" half is a guard.
//
// MUTATION TARGETS (each case is built to go red under at least one): delete the skip branch; delete
// the scoped full_sync filter; drop the content term; drop the claims-empty term; drop the faulted
// bit; drop the backend-health term (the probe in attach_core, the sweep in detach_rules_except).
// See each case's `Mutations:` line.
//
// Effect assertions are CHECK, never REQUIRE, so a red case runs to its end and reports every
// mismatch; REQUIRE is reserved for SETUP PREMISES. No sleeps: every wait is spin_until on an
// observable event, and "this did not change" is asserted after a stable-signature settle.
//
// Rules are FILE-typed on real temp files (deterministic Known state on every OS) except where a
// case needs a hung arm on a DIFFERENT io class from its healthy siblings, which uses one Service
// rule that is never evaluated while hung. The File mechanism is a fake: the real one is Windows-only.

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp> // sha256_file

#include "guaranteed_state.pb.h"
#include "guardian_arm_ack.hpp" // kWedgeSuppressMaxDecisions
#include "guardian_arm_heartbeat.hpp"
#include "guardian_baseline_persister.hpp"
#include "guardian_outbox.hpp"
#include "guardian_spark_runtime.hpp"
#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <sqlite3.h> // the KV write-effect probe (a second connection with row triggers)

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace gpb = ::yuzu::guardian::v1;
using yuzu::agent::FileSparkParams;
using yuzu::agent::GuardianBaselinePersister;
using yuzu::agent::GuardianEngine;
using yuzu::agent::ISparkMechanism;
using yuzu::agent::KvStore;
using yuzu::agent::OutboxDomain;
using yuzu::agent::OutboxEntry;
using yuzu::agent::SendResult;
using yuzu::agent::ServiceSparkParams;
using yuzu::agent::SparkEmitFn;
using yuzu::agent::SparkEngine;
using yuzu::agent::SparkFaultFn;
using yuzu::agent::SparkMechanismStats;
using yuzu::agent::SparkParams;
using yuzu::agent::SparkSpec;
using yuzu::agent::SparkType;

namespace {

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------------------------
// A counting fake mechanism. Per-key counters are taken at ENTRY (before any gate), so "this key
// was not touched" is exact; the hang gate is the one-shot shape FakeServiceMechanism uses.
// ---------------------------------------------------------------------------------------------
class CountingMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn, SparkFaultFn fault) override {
        std::lock_guard<std::mutex> lk{mu_};
        fault_ = std::move(fault);
    }

    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        bool hang = false;
        {
            std::lock_guard<std::mutex> lk{mu_};
            ++counts_[key].watch;
            ++total_watch_;
            const int ordinal = ++ordinal_;
            hang = hang_next_;
            hang_next_ = false;
            if (hang_ordinal_ != 0 && ordinal == hang_ordinal_) {
                hang = true;
                hang_ordinal_ = 0;
            }
            if (hang)
                hung_key_ = key;
        }
        if (hang) {
            std::unique_lock<std::mutex> gate{gate_mu_};
            entered_hang_ = true;
            gate_cv_.notify_all();
            gate_cv_.wait(gate, [this] { return released_; });
            if (late_refuse_.load(std::memory_order_relaxed))
                return std::unexpected("forced late watch refusal");
        }
        std::lock_guard<std::mutex> lk{mu_};
        watched_.insert(key);
        return {};
    }

    void unwatch(const std::string& key) override {
        bool hang = false;
        {
            std::lock_guard<std::mutex> lk{mu_};
            ++counts_[key].unwatch;
            ++total_unwatch_;
            watched_.erase(key);
            hang = hang_next_unwatch_;
            hang_next_unwatch_ = false;
        }
        if (hang) { // #5547: a compensating teardown that never returns (CompensationPending)
            std::unique_lock<std::mutex> gate{gate_mu_};
            entered_unwatch_ = true;
            gate_cv_.notify_all();
            gate_cv_.wait(gate, [this] { return unwatch_released_; });
        }
    }

    void stop() override {}
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }

    // ---- control ----
    void hang_next_watch() {
        std::lock_guard<std::mutex> lk{mu_};
        hang_next_ = true;
    }
    /// The Nth watch() to ENTER this mechanism (1-based) hangs; SparkEngine serialises a type's
    /// mechanism calls, so for one type this is the lock order.
    void hang_watch_ordinal(int n) {
        std::lock_guard<std::mutex> lk{mu_};
        hang_ordinal_ = n;
    }
    void set_late_refuse() { late_refuse_.store(true, std::memory_order_relaxed); }
    /// #5547: the next unwatch() to ENTER this mechanism parks until release_unwatch().
    void hang_next_unwatch() {
        std::lock_guard<std::mutex> lk{mu_};
        hang_next_unwatch_ = true;
    }
    bool wait_entered_unwatch(std::chrono::seconds t) {
        std::unique_lock<std::mutex> gate{gate_mu_};
        return gate_cv_.wait_for(gate, t, [this] { return entered_unwatch_; });
    }
    void release_unwatch() {
        {
            std::lock_guard<std::mutex> gate{gate_mu_};
            unwatch_released_ = true;
        }
        gate_cv_.notify_all();
    }
    bool wait_entered_hang(std::chrono::seconds t) {
        std::unique_lock<std::mutex> gate{gate_mu_};
        return gate_cv_.wait_for(gate, t, [this] { return entered_hang_; });
    }
    void release_hang() {
        {
            std::lock_guard<std::mutex> gate{gate_mu_};
            released_ = true;
        }
        gate_cv_.notify_all();
    }
    /// A mechanism-reported fault / recovery on `key` (what an OS handle going deaf looks like).
    void fire_fault(const std::string& key, bool faulted, const std::string& reason) {
        SparkFaultFn f;
        {
            std::lock_guard<std::mutex> lk{mu_};
            f = fault_;
        }
        REQUIRE(static_cast<bool>(f));
        f(key, faulted, reason);
    }

    // ---- observation ----
    int watch_calls(const std::string& key) {
        std::lock_guard<std::mutex> lk{mu_};
        const auto it = counts_.find(key);
        return it == counts_.end() ? 0 : it->second.watch;
    }
    int unwatch_calls(const std::string& key) {
        std::lock_guard<std::mutex> lk{mu_};
        const auto it = counts_.find(key);
        return it == counts_.end() ? 0 : it->second.unwatch;
    }
    int total_watch() {
        std::lock_guard<std::mutex> lk{mu_};
        return total_watch_;
    }
    int total_unwatch() {
        std::lock_guard<std::mutex> lk{mu_};
        return total_unwatch_;
    }
    std::set<std::string> watched_snapshot() {
        std::lock_guard<std::mutex> lk{mu_};
        return watched_;
    }
    std::string hung_key() {
        std::lock_guard<std::mutex> lk{mu_};
        return hung_key_;
    }

private:
    struct KeyCounts {
        int watch{0};
        int unwatch{0};
    };
    std::mutex mu_;
    std::map<std::string, KeyCounts> counts_;
    std::set<std::string> watched_;
    SparkFaultFn fault_;
    int total_watch_{0};
    int total_unwatch_{0};
    int ordinal_{0};
    bool hang_next_{false};
    int hang_ordinal_{0};
    std::string hung_key_;
    std::atomic<bool> late_refuse_{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool entered_hang_{false};
    bool released_{false};
    bool hang_next_unwatch_{false};  // guarded by mu_
    bool entered_unwatch_{false};    // guarded by gate_mu_
    bool unwatch_released_{false};   // guarded by gate_mu_
};

// ---------------------------------------------------------------------------------------------
// Rule builders (the originals live in another test file's anonymous namespace).
// ---------------------------------------------------------------------------------------------
gpb::GuaranteedStateRule file_rule(const std::string& id, const fs::path& path,
                                   const std::string& name = {}) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(name.empty() ? id : name);
    r.set_enabled(true);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("file-change");
    auto* a = r.mutable_assertion();
    a->set_type("file-exists");
    (*a->mutable_params())["path"] = path.string();
    return r;
}

// file-hash-equals; no authored expected_hash => baseline-on-arm (#4045).
gpb::GuaranteedStateRule file_hash_rule(const std::string& id, const fs::path& path) {
    gpb::GuaranteedStateRule r = file_rule(id, path);
    r.mutable_assertion()->set_type("file-hash-equals");
    return r;
}

gpb::GuaranteedStateRule service_rule(const std::string& id, const std::string& service) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(true);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("service-status-change");
    auto* a = r.mutable_assertion();
    a->set_type("service-running");
    (*a->mutable_params())["service_name"] = service;
    return r;
}

/// Serialised ONCE and re-sent byte-for-byte, so an "identical re-push" is genuinely identical
/// (the same content id), never a rebuilt proto that merely compares equal.
std::string push_bytes(const std::vector<gpb::GuaranteedStateRule>& rules, std::uint64_t generation,
                       bool full_sync = true) {
    gpb::GuaranteedStatePush p;
    p.set_full_sync(full_sync);
    p.set_policy_generation(generation);
    for (const auto& r : rules)
        *p.add_rules() = r;
    return p.SerializeAsString();
}

std::string file_key(const fs::path& p) {
    return yuzu::agent::spark_key(SparkSpec{SparkType::File, FileSparkParams{p.string()}});
}
std::string service_key(const std::string& name) {
    return yuzu::agent::spark_key(SparkSpec{SparkType::Service, ServiceSparkParams{name}});
}

fs::path unique_kv_path() {
#ifdef _WIN32
    const std::string uid = "_win";
#else
    const std::string uid = "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
    const auto dir = fs::temp_directory_path() / ("yuzu_test_guardian_4415pra" + uid);
    return dir / (yuzu::test::unique_temp_path("skip_").filename().string() + ".db");
}

constexpr std::uint64_t kGen = 5;
constexpr std::string_view kKvNs = "__guardian__";
constexpr std::string_view kKvGenKey = "meta:policy_generation";

// ---------------------------------------------------------------------------------------------
// The rig: a restartable GuardianEngine (prefer_spark=true) over ONE on-disk KV, a SparkEngine with
// a File and a Service counting mechanism, and a send sink that records every outbox entry.
// ---------------------------------------------------------------------------------------------
struct Rig {
    yuzu::test::TempDbFile db{unique_kv_path()}; // declared first: destroyed last
    yuzu::test::TempDir dir{"yuzu_test_4415pra_"};
    std::unique_ptr<KvStore> kv;
    std::unique_ptr<SparkEngine> spark;
    CountingMechanism* fm{nullptr}; // File; owned by `spark`
    CountingMechanism* sm{nullptr}; // Service; owned by `spark`
    std::unique_ptr<GuardianEngine> engine;
    std::mutex sent_mu;
    std::vector<OutboxEntry> sent;
    bool prefer_spark{true}; ///< false = the production configuration (legacy guards detect)

    Rig() {
        fs::create_directories(dir.path);
        fs::create_directories(db.path.parent_path());
    }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;
    ~Rig() { close(); }

    /// One engine incarnation in the PRODUCTION boot order (wire_spark_engine before start_local).
    /// A claim deadline of an hour means only the synthetic clock ever expires a claim.
    void open(std::function<void(const std::string&)> rearm_hook = nullptr) {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));
        spark = std::make_unique<SparkEngine>();
        auto f = std::make_unique<CountingMechanism>();
        CountingMechanism* const file_mech = f.get();
        REQUIRE(spark->register_mechanism(SparkType::File, std::move(f)).has_value());
        fm = file_mech; // aliased only once the SparkEngine owns it
        auto s = std::make_unique<CountingMechanism>();
        CountingMechanism* const service_mech = s.get();
        REQUIRE(spark->register_mechanism(SparkType::Service, std::move(s)).has_value());
        sm = service_mech;
        spark->start();
        {
            std::lock_guard<std::mutex> lk{sent_mu};
            sent.clear();
        }
        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-4415", prefer_spark);
        engine->set_spark_backend_op_deadline_for_test(std::chrono::hours(1));
        if (rearm_hook)
            engine->set_rearm_fault_hook_for_test(std::move(rearm_hook));
        engine->wire_spark_engine(spark.get(), /*spark_disabled_by_config=*/false,
                                  [this](const OutboxEntry& e) {
                                      std::lock_guard<std::mutex> lk{sent_mu};
                                      sent.push_back(e);
                                      return SendResult::Sent;
                                  });
        REQUIRE(engine->start_local().has_value());
        if (prefer_spark)
            REQUIRE(engine->spark_availability() == GuardianEngine::SparkAvailability::Available);
    }

    /// Releases every gate FIRST (a parked worker would otherwise outlive the engine that owns its
    /// claim), waits (bounded, no REQUIRE: this also runs from the destructor) for the workers,
    /// then tears down in production order: engine, SparkEngine, KV.
    void close() {
        if (fm) {
            fm->release_hang();
            fm->release_unwatch();
        }
        if (sm) {
            sm->release_hang();
            sm->release_unwatch();
        }
        if (engine) {
            if (!yuzu::test::spin_until([&] { return engine->active_io_workers() == 0; }, 10s))
                FAIL_CHECK("Rig::close: a backend worker was still alive after every gate was released");
        }
        engine.reset();
        if (spark)
            spark->stop();
        spark.reset();
        fm = nullptr;
        sm = nullptr;
        kv.reset();
    }

    fs::path make_file(const std::string& name, const std::string& content = "x") {
        const fs::path p = dir.path / name;
        std::ofstream o(p, std::ios::binary | std::ios::trunc);
        o << content;
        REQUIRE(o.good());
        return p;
    }

    yuzu::agent::GuardianSparkRuntime& rt() {
        auto* r = engine->spark_runtime_for_test();
        REQUIRE(r != nullptr);
        return *r;
    }

    void dispatch(const std::string& bytes) {
        const auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*engine, bytes);
        REQUIRE(dr.exit_code == 0);
    }

    // ---- outbox observation ----
    std::size_t count_entries(OutboxDomain d, const std::string& rule_id = {},
                              const std::string& kind = {}) {
        std::lock_guard<std::mutex> lk{sent_mu};
        return static_cast<std::size_t>(std::count_if(sent.begin(), sent.end(), [&](const OutboxEntry& e) {
            return e.domain == d && (rule_id.empty() || e.rule_id == rule_id) &&
                   (kind.empty() || e.lifecycle_kind == kind);
        }));
    }
    std::size_t lifecycle(const std::string& rule_id = {}, const std::string& kind = {}) {
        return count_entries(OutboxDomain::Lifecycle, rule_id, kind);
    }
    std::size_t compliant_events(const std::string& rule_id = {}) {
        std::lock_guard<std::mutex> lk{sent_mu};
        return static_cast<std::size_t>(std::count_if(sent.begin(), sent.end(), [&](const OutboxEntry& e) {
            return e.domain == OutboxDomain::Compliance && e.drift.compliant &&
                   (rule_id.empty() || e.rule_id == rule_id);
        }));
    }
    std::size_t health_events(const std::string& rule_id, bool healthy) {
        std::lock_guard<std::mutex> lk{sent_mu};
        return static_cast<std::size_t>(std::count_if(sent.begin(), sent.end(), [&](const OutboxEntry& e) {
            return e.domain == OutboxDomain::Health && e.rule_id == rule_id && e.healthy == healthy;
        }));
    }

    // ---- waits (event-driven) ----
    bool wait_armed(std::size_t n, std::chrono::milliseconds t = 15s) {
        return yuzu::test::spin_until(
            [&] {
                engine->journal_maintenance_tick();
                return engine->spark_armed_rule_count() == n;
            },
            t);
    }
    bool wait_compliant(const std::vector<std::string>& ids, std::chrono::milliseconds t = 15s) {
        return yuzu::test::spin_until(
            [&] {
                return std::all_of(ids.begin(), ids.end(),
                                   [&](const std::string& id) { return compliant_events(id) >= 1; });
            },
            t);
    }
    bool wait_generation(std::uint64_t g, std::chrono::milliseconds t = 15s) {
        return yuzu::test::spin_until(
            [&] {
                engine->journal_maintenance_tick();
                return engine->policy_generation() == g;
            },
            t);
    }
    std::optional<std::uint64_t> persisted_generation() {
        const auto v = kv->get(kKvNs, kKvGenKey);
        if (!v)
            return std::nullopt;
        return static_cast<std::uint64_t>(std::stoull(*v));
    }
    /// The generation is HELD: neither the in-memory nor the durable value has moved.
    void require_generation_held() {
        REQUIRE(engine->policy_generation() == 0);
        REQUIRE(persisted_generation().value_or(0) == 0);
    }

    /// Ticks the heartbeat maintenance and polls a state signature until it has been unchanged
    /// for `stable` consecutive polls. This is how "nothing happened" is asserted without a sleep:
    /// settle, snapshot, push, settle, compare. The signature covers every observable a rebuild
    /// moves (mechanism calls, outbox entries, ledger, workers, armed set).
    bool settle(int stable = 10, std::chrono::milliseconds t = 10s) {
        using Sig = std::array<std::uint64_t, 9>;
        const auto sig = [&]() -> Sig {
            std::uint64_t sent_n = 0;
            {
                std::lock_guard<std::mutex> lk{sent_mu};
                sent_n = sent.size();
            }
            return {static_cast<std::uint64_t>(fm->total_watch()),
                    static_cast<std::uint64_t>(fm->total_unwatch()),
                    static_cast<std::uint64_t>(sm->total_watch()),
                    static_cast<std::uint64_t>(sm->total_unwatch()),
                    sent_n,
                    engine->ack_pending_count_for_test(),
                    engine->active_io_workers(),
                    engine->spark_armed_rule_count(),
                    engine->ack_failed_receipt_count_for_test()};
        };
        Sig last = sig();
        int same = 0;
        return yuzu::test::spin_until(
            [&] {
                engine->journal_maintenance_tick();
                const Sig now = sig();
                if (now == last)
                    ++same;
                else {
                    same = 0;
                    last = now;
                }
                return same >= stable;
            },
            t);
    }

    /// settle() plus the quiescence a stable signature alone does not prove: exactly `armed`
    /// rules armed, no arm acknowledgement still pending and no backend worker alive. For the
    /// cases whose healthy rules must have finished, unlike the hung-arm cases that settle on
    /// purpose with a worker parked.
    bool settle_idle(std::size_t armed, std::chrono::milliseconds t = 10s) {
        if (!settle(10, t))
            return false;
        return yuzu::test::spin_until(
            [&] {
                engine->journal_maintenance_tick();
                return engine->spark_armed_rule_count() == armed &&
                       engine->ack_pending_count_for_test() == 0 &&
                       engine->active_io_workers() == 0;
            },
            t);
    }
};

/// `key` was armed exactly once and never torn down on `m`.
void check_untouched(CountingMechanism& m, const std::string& what, const std::string& key) {
    CAPTURE(what);
    CHECK(m.watch_calls(key) == 1);
    CHECK(m.unwatch_calls(key) == 0);
}
/// `key` was rebuilt exactly once: one teardown and one more arm.
void check_rebuilt_once(CountingMechanism& m, const std::string& what, const std::string& key) {
    CAPTURE(what);
    CHECK(m.watch_calls(key) == 2);
    CHECK(m.unwatch_calls(key) == 1);
}

// ---------------------------------------------------------------------------------------------
// Wedge scaffolding shared by cases 6, 7, 9a and 9b: one hung arm (expired by the synthetic clock
// into a retained wedge), generation 5 held, the held pushes Suppressed up to the safety valve.
// ---------------------------------------------------------------------------------------------

/// Waits for `hm`'s hang to be entered, for `expected_armed` rules to commit, wedges the hung
/// claim with the synthetic clock, drains the ledger, and verifies generation 5 is HELD.
/// Returns the hung key.
std::string park_and_wedge(Rig& r, CountingMechanism& hm, std::size_t expected_armed) {
    REQUIRE(hm.wait_entered_hang(30s)); // event-driven: the arm is IN watch()
    const std::string hk = hm.hung_key();
    REQUIRE_FALSE(hk.empty());
    REQUIRE(r.wait_armed(expected_armed));
    auto& rt = r.rt(); // once, outside every poll (rt() holds a REQUIRE)
    REQUIRE(yuzu::test::spin_until([&] { return rt.active_backend_op_workers() == 1; }, 10s));
    REQUIRE(rt.claim_queue_depth_for_test(hk) == 1);
    REQUIRE(rt.expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() + 2h) == 1);
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.engine->journal_maintenance_tick();
            return r.engine->ack_pending_count_for_test() == 0;
        },
        10s));
    r.require_generation_held();
    const auto s = r.engine->arm_stats();
    REQUIRE(s.has_value());
    REQUIRE(s->failed == 1); // the wedge is the one retained failure suppression keys on
    REQUIRE(s->pending == 0);
    return hk;
}

/// One identical re-push while the generation is held and the wedge is outstanding: it must be
/// SUPPRESSED (nothing reaches either mechanism, the open application survives, the detach epoch
/// does not move, nothing is acknowledged).
void suppressed_repush(Rig& r, const std::string& bytes, const std::string& hung_key) {
    const int fw = r.fm->total_watch(), fu = r.fm->total_unwatch();
    const int sw = r.sm->total_watch(), su = r.sm->total_unwatch();
    auto& rt = r.rt();
    const auto epoch = rt.application_fence_for_test().first;
    r.dispatch(bytes);
    const auto s = r.engine->arm_stats();
    REQUIRE(s.has_value());
    CHECK(s->pending == 0);
    CHECK(s->failed == 1); // a Reapply would begin a new application (failed 0)
    CHECK(r.fm->total_watch() == fw);
    CHECK(r.fm->total_unwatch() == fu);
    CHECK(r.sm->total_watch() == sw);
    CHECK(r.sm->total_unwatch() == su);
    CHECK(rt.claim_queue_depth_for_test(hung_key) == 1);
    CHECK(rt.application_fence_for_test().first == epoch); // a pure hold never moves the epoch
    r.engine->journal_maintenance_tick();
    r.require_generation_held();
}
void suppressed_repushes(Rig& r, const std::string& bytes, const std::string& hung_key, int n) {
    for (int i = 0; i < n; ++i)
        suppressed_repush(r, bytes, hung_key);
}

/// Waits for the released hung call's completion callback to FINISH: the worker has returned and
/// the claim is gone from its key's FIFO.
void await_late_result_landed(Rig& r, const std::string& hung_key) {
    auto& rt = r.rt();
    REQUIRE(yuzu::test::spin_until(
        [&] { return rt.active_backend_op_workers() == 0 && rt.claim_queue_depth_for_test(hung_key) == 0; },
        10s));
}

constexpr int kValve = static_cast<int>(yuzu::agent::kWedgeSuppressMaxDecisions);

/// #5547: counts reconcile_rule_locked's attach step per rule id, and can make it throw once for
/// one id. The engine's post-attach hook fires once per attach_rule call, so a count that does
/// not move across a push proves apply_rules did not reconcile the rule (a Suppressed retry),
/// and one that moves proves it did (a Reapply). A throw there reaches apply_rules' per-rule
/// firewall exactly like any other reconcile throw. Held by shared_ptr so the engine's copy of
/// the hook never outlives it.
struct AttachProbe {
    std::mutex mu;
    std::map<std::string, int> calls;
    std::string throw_for; ///< consumed on first use
    int count(const std::string& id) {
        std::lock_guard<std::mutex> lk{mu};
        const auto it = calls.find(id);
        return it == calls.end() ? 0 : it->second;
    }
    void throw_once(std::string id) {
        std::lock_guard<std::mutex> lk{mu};
        throw_for = std::move(id);
    }
};
std::shared_ptr<AttachProbe> install_attach_probe(Rig& r) {
    auto probe = std::make_shared<AttachProbe>();
    r.engine->set_post_attach_hook_for_test([probe](const std::string& id) {
        bool do_throw = false;
        {
            std::lock_guard<std::mutex> lk{probe->mu};
            ++probe->calls[id];
            if (!probe->throw_for.empty() && probe->throw_for == id) {
                probe->throw_for.clear();
                do_throw = true;
            }
        }
        if (do_throw)
            throw std::runtime_error("injected post-attach throw");
    });
    return probe;
}

/// Ticks until the ledger has nothing pending (every accepted arm has been drained).
void drain_until_idle(Rig& r) {
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.engine->journal_maintenance_tick();
            return r.engine->ack_pending_count_for_test() == 0;
        },
        10s));
}

/// A bounded COUNT of ticks (not a wait): nothing re-arms or acknowledges on its own, so after
/// this a held generation has been given every chance to advance.
void tick_n(Rig& r, int n = 20) {
    for (int i = 0; i < n; ++i)
        r.engine->journal_maintenance_tick();
}

} // namespace

// =================================================================================================
// 1. An identical full_sync re-push of R healthy rules touches NO healthy rule.
//    RED-BY-DESIGN. Mutations: delete the skip branch (red).
// =================================================================================================
TEST_CASE("#4415 PR-A (1): an identical full_sync re-push of R healthy rules touches no rule - no "
          "watch, no unwatch, the live watch set, lifecycle and compliant entries all unchanged",
          "[spark][guardian][reconcile][4415prA]") {
    constexpr int R = 5;
    Rig r;
    r.open();
    std::vector<gpb::GuaranteedStateRule> rules;
    std::vector<std::string> ids, keys;
    for (int i = 0; i < R; ++i) {
        const auto p = r.make_file("t" + std::to_string(i));
        ids.push_back("r" + std::to_string(i));
        keys.push_back(file_key(p));
        rules.push_back(file_rule(ids.back(), p));
    }
    const std::string bytes = push_bytes(rules, kGen);

    r.dispatch(bytes);
    REQUIRE(r.wait_armed(R));
    REQUIRE(r.wait_compliant(ids));
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());
    for (const auto& k : keys)
        REQUIRE(r.fm->watch_calls(k) == 1);
    const auto watched_before = r.fm->watched_snapshot();
    REQUIRE(watched_before.size() == R);
    const auto lifecycle_before = r.lifecycle();
    const auto compliant_before = r.compliant_events();
    std::map<std::string, std::size_t> compliant_by_rule;
    for (const auto& id : ids)
        compliant_by_rule[id] = r.compliant_events(id);
    REQUIRE(lifecycle_before == R);

    r.dispatch(bytes); // byte-identical re-push
    CHECK(r.settle_idle(R));

    // Headline: the whole ruleset's mechanism traffic across the identical re-push.
    CHECK(r.fm->total_watch() == R);
    CHECK(r.fm->total_unwatch() == 0);
    CHECK(r.fm->watched_snapshot() == watched_before);
    for (int i = 0; i < R; ++i)
        check_untouched(*r.fm, ids[i], keys[i]);
    CHECK(r.lifecycle() == lifecycle_before);
    CHECK(r.compliant_events() == compliant_before);
    for (const auto& id : ids) {
        CAPTURE(id);
        CHECK(r.lifecycle(id, "disarmed") == 0);
        CHECK(r.compliant_events(id) == compliant_by_rule[id]);
    }
    CHECK(r.engine->spark_armed_rule_count() == R);
    CHECK(r.engine->policy_generation() == kGen);
}

// =================================================================================================
// 2. full_sync OMITTING a rule detaches exactly that rule's key, including the shared-key case.
//    RED-BY-DESIGN. Mutations: delete the scoped full_sync filter (re-introduces the global
//    detach_all: red); delete the skip branch (red).
// =================================================================================================
TEST_CASE("#4415 PR-A (2): a full_sync omitting rule X detaches exactly X's key; when X and Y share "
          "one spark key, Y stays attached and its subscription is never torn down",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto shared = r.make_file("shared");
    const auto pb = r.make_file("b");
    const auto pc = r.make_file("c");
    const std::string ka = file_key(shared), kb = file_key(pb), kc = file_key(pc);
    // X and Y are two rules on the SAME path, hence the same spark key.
    const auto X = file_rule("X", shared), Y = file_rule("Y", shared);
    const auto Z = file_rule("Z", pb), W = file_rule("W", pc);

    r.dispatch(push_bytes({X, Y, Z, W}, kGen));
    REQUIRE(r.wait_armed(4));
    REQUIRE(r.wait_compliant({"X", "Y", "Z", "W"}));
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());
    REQUIRE(r.fm->watch_calls(ka) == 1); // one subscription serves both rules
    REQUIRE(r.fm->watch_calls(kb) == 1);
    REQUIRE(r.fm->watch_calls(kc) == 1);
    const auto lifecycle_y_before = r.lifecycle("Y");
    const auto lifecycle_z_before = r.lifecycle("Z");
    const auto lifecycle_w_before = r.lifecycle("W");
    const auto x_disarmed_before = r.lifecycle("X", "disarmed");

    // Phase 1: omit X only. Y still holds the shared key, so NOTHING about that key may change.
    r.dispatch(push_bytes({Y, Z, W}, kGen));
    CHECK(r.settle());
    CHECK(r.fm->watch_calls(ka) == 1);   // Y's key: not re-armed
    CHECK(r.fm->unwatch_calls(ka) == 0); // ...and not torn down
    check_untouched(*r.fm, "Z", kb);
    check_untouched(*r.fm, "W", kc);
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{ka, kb, kc});
    CHECK(r.engine->spark_armed_rule_count() == 3);
    CHECK(r.lifecycle("X", "disarmed") == x_disarmed_before + 1); // X is withdrawn, once
    CHECK(r.lifecycle("Y") == lifecycle_y_before);
    CHECK(r.lifecycle("Z") == lifecycle_z_before);
    CHECK(r.lifecycle("W") == lifecycle_w_before);
    CHECK(r.rt().status_for_rule("Y").has_value());
    CHECK_FALSE(r.rt().status_for_rule("X").has_value());

    // Phase 2: omit Y too. Now (and only now) the shared key goes, exactly once.
    r.dispatch(push_bytes({Z, W}, kGen));
    CHECK(r.settle());
    CHECK(r.fm->watch_calls(ka) == 1);
    CHECK(r.fm->unwatch_calls(ka) == 1);
    check_untouched(*r.fm, "Z", kb);
    check_untouched(*r.fm, "W", kc);
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{kb, kc});
    CHECK(r.engine->spark_armed_rule_count() == 2);
    CHECK(r.lifecycle("Y", "disarmed") == 1);
    CHECK(r.lifecycle("Z") == lifecycle_z_before);
    CHECK(r.lifecycle("W") == lifecycle_w_before);
    CHECK_FALSE(r.rt().status_for_rule("Y").has_value());
}

// =================================================================================================
// 3. A one-rule content change rebuilds only that rule; siblings are untouched.
//    RED-BY-DESIGN. Mutations: drop the content term (phase 1 goes red because the changed rule is
//    then skipped: its key counts stay 1/0 and the new name never appears); delete the skip branch.
// =================================================================================================
TEST_CASE("#4415 PR-A (3): a one-rule content change rebuilds only that rule (same key, different "
          "content, and a retarget); every sibling is untouched",
          "[spark][guardian][reconcile][4415prA]") {
    constexpr int R = 4;
    Rig r;
    r.open();
    std::vector<fs::path> paths;
    std::vector<std::string> ids, keys;
    for (int i = 0; i < R; ++i) {
        paths.push_back(r.make_file("t" + std::to_string(i)));
        ids.push_back("r" + std::to_string(i));
        keys.push_back(file_key(paths.back()));
    }
    const auto build = [&](const std::string& r2_name, const fs::path& r2_path) {
        std::vector<gpb::GuaranteedStateRule> v;
        for (int i = 0; i < R; ++i)
            v.push_back(i == 2 ? file_rule(ids[i], r2_path, r2_name) : file_rule(ids[i], paths[i]));
        return push_bytes(v, kGen);
    };

    r.dispatch(build({}, paths[2]));
    REQUIRE(r.wait_armed(R));
    REQUIRE(r.wait_compliant(ids));
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());
    const auto armed_r2_before = r.lifecycle("r2", "armed");
    REQUIRE(armed_r2_before == 1);

    // Phase 1: same key (name is content, not part of the spark spec), different content.
    r.dispatch(build("renamed-r2", paths[2]));
    CHECK(r.settle());
    check_rebuilt_once(*r.fm, "r2 (content changed, same key)", keys[2]);
    for (int i : {0, 1, 3})
        check_untouched(*r.fm, ids[i], keys[i]);
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{keys[0], keys[1], keys[2], keys[3]});
    CHECK(r.lifecycle("r2", "armed") == armed_r2_before + 1); // the new generation is live
    {
        // The new content is what is live: the fresh "armed" entry carries the new name.
        std::lock_guard<std::mutex> lk{r.sent_mu};
        std::string last_name;
        for (const auto& e : r.sent)
            if (e.domain == OutboxDomain::Lifecycle && e.rule_id == "r2" && e.lifecycle_kind == "armed")
                last_name = e.rule_name;
        CHECK(last_name == "renamed-r2");
    }

    // Phase 2: a retarget (different path, so a different key). The old key goes, the new one
    // arms, and the siblings are still untouched.
    const auto moved = r.make_file("moved");
    const std::string moved_key = file_key(moved);
    r.dispatch(build("renamed-r2", moved));
    CHECK(r.settle());
    CHECK(r.fm->watch_calls(moved_key) == 1);
    CHECK(r.fm->unwatch_calls(keys[2]) == 2); // phase 1's teardown plus this one
    for (int i : {0, 1, 3})
        check_untouched(*r.fm, ids[i], keys[i]);
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{keys[0], keys[1], keys[3], moved_key});
}

// =================================================================================================
// 3b. A changed AUTHORED expected_hash is content the identity deliberately leaves out (a
//     baseline-on-arm rule's seed differs push to push), so reuse_existing_locked compares it
//     against the live effective hash. Everything else identical, H1 -> H2 must rebuild ONLY that
//     rule. Mutation: delete the `pushed.expected_hash != live_hash` clause (the changed rule is
//     skipped and keeps H1: its key counts stay 1/0), or the `pushed_hash` term on the claims branch.
// =================================================================================================
TEST_CASE("#4415 PR-A (3b): a changed authored expected_hash rebuilds that rule only",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("h0"), p1 = r.make_file("h1");
    const std::string h1(64, 'a'), h2(64, 'b');
    const auto build = [&](const std::string& hash) {
        auto hr = file_hash_rule("hr", p0);
        (*hr.mutable_assertion()->mutable_params())["expected_hash"] = hash;
        return push_bytes({hr, file_rule("s1", p1)}, kGen);
    };
    r.dispatch(build(h1));
    REQUIRE(r.wait_armed(2));
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());
    const std::string kh = file_key(p0), ks = file_key(p1);

    r.dispatch(build(h1)); // identical: both skipped
    CHECK(r.settle_idle(2));
    check_untouched(*r.fm, "hr (identical hash)", kh);
    check_untouched(*r.fm, "s1", ks);

    r.dispatch(build(h2)); // only the authored hash differs
    CHECK(r.settle_idle(2));
    check_rebuilt_once(*r.fm, "hr (authored hash changed)", kh);
    check_untouched(*r.fm, "s1", ks);
}

// =================================================================================================
// 4. Baseline-on-arm (AC-10 case 6).
//    4a RED-BY-DESIGN: a persisted baseline equal to the live one is SKIPPED.
//    4b MIXED: with the persisted baseline gone (EMPTY seed) the baseline rule is REBUILT (a GUARD,
//       green on the baseline: the "until its next re-arm" window must not widen to "until
//       restart") while the siblings are untouched (red on the baseline).
//    Mutations: drop the baseline term (4b's rebuilt-once assertion goes red: the rule is skipped
//    on an empty seed); delete the skip branch (4a red).
// =================================================================================================
namespace {
struct BaselineRig {
    Rig r;
    fs::path target;
    std::string hash;
    std::vector<std::string> ids{"hr", "s0", "s1"};
    std::string kh, k0, k1;
    std::string bytes;

    void build() {
        r.open();
        target = r.make_file("baseline_target", "content A");
        hash = yuzu::agent::sha256_file(target);
        const auto p0 = r.make_file("s0"), p1 = r.make_file("s1");
        kh = file_key(target);
        k0 = file_key(p0);
        k1 = file_key(p1);
        bytes = push_bytes({file_hash_rule("hr", target), file_rule("s0", p0), file_rule("s1", p1)}, kGen);
        r.dispatch(bytes);
        REQUIRE(r.wait_armed(3));
        REQUIRE(r.wait_compliant(ids));
        // The capture reaches the durable KV record through the persister (a forced pass).
        auto* persister = r.engine->baseline_persister_for_test();
        REQUIRE(persister != nullptr);
        persister->persist_staged(r.rt(), GuardianBaselinePersister::Trigger::Forced);
        REQUIRE(baseline_hash().value_or("") == hash);
        REQUIRE(r.wait_generation(kGen));
        REQUIRE(r.settle());
    }
    std::optional<std::string> baseline_hash() {
        const auto v = r.kv->get(GuardianEngine::kv_namespace(), "baseline:hr");
        if (!v)
            return std::nullopt;
        return nlohmann::json::parse(*v).value("hash", std::string{});
    }
};
} // namespace

TEST_CASE("#4415 PR-A (4a): a baseline-on-arm rule whose persisted baseline equals the live one is "
          "skipped on an identical re-push, with every sibling",
          "[spark][guardian][reconcile][4415prA]") {
    BaselineRig b;
    b.build();
    auto& r = b.r;

    r.dispatch(b.bytes);
    CHECK(r.settle());
    check_untouched(*r.fm, "hr (baseline-on-arm, persisted == live)", b.kh);
    check_untouched(*r.fm, "s0", b.k0);
    check_untouched(*r.fm, "s1", b.k1);
    CHECK(r.fm->total_watch() == 3);
    CHECK(r.fm->total_unwatch() == 0);
    CHECK(r.lifecycle("hr", "disarmed") == 0);
    CHECK(b.baseline_hash().value_or("") == b.hash); // the durable baseline is unchanged
}

TEST_CASE("#4415 PR-A (4b): with the persisted baseline gone (an EMPTY seed) the baseline-on-arm "
          "rule is rebuilt - the skip never widens the AC-10 window - and its siblings stay untouched",
          "[spark][guardian][reconcile][4415prA]") {
    BaselineRig b;
    b.build();
    auto& r = b.r;
    REQUIRE(r.kv->del(GuardianEngine::kv_namespace(), "baseline:hr"));
    REQUIRE_FALSE(b.baseline_hash().has_value());

    r.dispatch(b.bytes);
    CHECK(r.settle());
    // GUARD (green on the baseline): the empty seed forces the rebuild.
    check_rebuilt_once(*r.fm, "hr (empty baseline seed)", b.kh);
    // RED on the baseline: the siblings have no reason to move.
    check_untouched(*r.fm, "s0", b.k0);
    check_untouched(*r.fm, "s1", b.k1);
}

// =================================================================================================
// 5. A rule in an Unknown-eval episode, and a rule whose subscription faulted, are REBUILT.
//    5a/5b are GUARDS for their rebuilt half (green on the baseline, which rebuilds everything) and
//    RED-BY-DESIGN for the sibling-untouched half. Mutations: drop the !in_unknown term (5a's
//    rebuilt-once goes red); drop the faulted bit (5b's goes red, and its recovery phase pins the
//    bit's clear edge).
// =================================================================================================
TEST_CASE("#4415 PR-A (5a): a rule in an Unknown-eval episode is rebuilt on an identical re-push; "
          "healthy siblings are not",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    // A symlink loop makes read_file_blocking return Unknown (open ELOOP, stat ELOOP), on every
    // user including root, with no permission dependency.
    const fs::path a = r.dir.path / "loop_a", b = r.dir.path / "loop_b";
    std::error_code link_ec;
    fs::create_symlink("loop_b", a, link_ec);
    if (!link_ec)
        fs::create_symlink("loop_a", b, link_ec);
    if (link_ec)
        SKIP("symlinks are unavailable here (" << link_ec.message() << "): the Unknown-read premise needs a loop");
    const auto p0 = r.make_file("s0"), p1 = r.make_file("s1");
    const std::string ku = file_key(a), k0 = file_key(p0), k1 = file_key(p1);
    const std::string bytes =
        push_bytes({file_rule("u1", a), file_rule("s0", p0), file_rule("s1", p1)}, kGen);

    r.dispatch(bytes);
    REQUIRE(r.wait_armed(3));
    REQUIRE(r.wait_compliant({"s0", "s1"}));
    REQUIRE(yuzu::test::spin_until(
        [&] {
            const auto st = r.rt().status_for_rule("u1");
            return st.has_value() && st->in_unknown;
        },
        15s)); // the premise: u1 is in an Unknown episode
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());

    r.dispatch(bytes);
    CHECK(r.settle());
    check_rebuilt_once(*r.fm, "u1 (Unknown episode)", ku); // GUARD
    check_untouched(*r.fm, "s0", k0);                       // RED on the baseline
    check_untouched(*r.fm, "s1", k1);
}

TEST_CASE("#4415 PR-A (5b): a rule whose subscription the mechanism reported faulted is rebuilt on "
          "an identical re-push, healthy siblings are not, and once the fault has recovered a "
          "further identical re-push touches nothing",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0"), p1 = r.make_file("s1"), p2 = r.make_file("s2");
    const std::string k0 = file_key(p0), k1 = file_key(p1), k2 = file_key(p2);
    const std::string bytes =
        push_bytes({file_rule("s0", p0), file_rule("s1", p1), file_rule("s2", p2)}, kGen);

    r.dispatch(bytes);
    REQUIRE(r.wait_armed(3));
    REQUIRE(r.wait_compliant({"s0", "s1", "s2"}));
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());

    // Phase A: s1's handle goes deaf (the runtime hears it as a Health entry, asynchronously).
    r.fm->fire_fault(k1, true, "handle went deaf");
    REQUIRE(yuzu::test::spin_until([&] { return r.health_events("s1", /*healthy=*/false) >= 1; }, 15s));
    r.dispatch(bytes);
    CHECK(r.settle());
    check_rebuilt_once(*r.fm, "s1 (faulted subscription)", k1); // GUARD
    check_untouched(*r.fm, "s0", k0);                           // RED on the baseline
    check_untouched(*r.fm, "s2", k2);

    // Phase B: s2 faults and RECOVERS before the next push: the bit is clear, nothing is rebuilt.
    r.fm->fire_fault(k2, true, "handle went deaf");
    REQUIRE(yuzu::test::spin_until([&] { return r.health_events("s2", false) >= 1; }, 15s));
    r.fm->fire_fault(k2, false, "recovered");
    REQUIRE(yuzu::test::spin_until([&] { return r.health_events("s2", true) >= 1; }, 15s));
    REQUIRE(r.settle());
    const int w_before = r.fm->total_watch(), u_before = r.fm->total_unwatch();
    r.dispatch(bytes);
    CHECK(r.settle());
    CHECK(r.fm->total_watch() == w_before);   // RED on the baseline
    CHECK(r.fm->total_unwatch() == u_before);
}

// =================================================================================================
// 5c. Two rules share ONE key and the mechanism reports it faulted. Each rule is non-skipped by the
//    faulted bit, but each detach only drops the key's refcount from 2 to 1, so without a repair
//    both rejoin the SAME deaf watcher (the old detach_all() tore the key down). The full_sync
//    detach must rebuild the key once, with both rules re-armed.
//    RED on stage 1 alone. Mutation: drop the faulted-key term in detach_rules_except.
// =================================================================================================
TEST_CASE("#4415 PR-A (5c): two rules sharing one faulted key are both re-armed on a fresh watcher "
          "by an identical full_sync re-push; a further identical re-push touches nothing",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto shared = r.make_file("shared"), other = r.make_file("other");
    const std::string ks = file_key(shared), ko = file_key(other);
    const std::string bytes = push_bytes(
        {file_rule("a", shared), file_rule("b", shared), file_rule("s", other)}, kGen);

    r.dispatch(bytes);
    REQUIRE(r.wait_armed(3));
    REQUIRE(r.wait_compliant({"a", "b", "s"}));
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());
    REQUIRE(r.fm->watch_calls(ks) == 1); // the premise: ONE watcher serves both rules

    r.fm->fire_fault(ks, true, "handle went deaf");
    REQUIRE(yuzu::test::spin_until(
        [&] { return r.health_events("a", false) >= 1 && r.health_events("b", false) >= 1; }, 15s));
    r.dispatch(bytes);
    CHECK(r.settle());
    check_rebuilt_once(*r.fm, "the shared faulted key", ks); // RED on stage 1: still one watch
    check_untouched(*r.fm, "s (healthy sibling)", ko);
    CHECK(r.engine->spark_armed_rule_count() == 3);
    CHECK(r.fm->watched_snapshot().contains(ks)); // re-established, not left torn down

    // The rebuilt key starts clear: nothing more is rebuilt.
    const int w_before = r.fm->total_watch(), u_before = r.fm->total_unwatch();
    r.dispatch(bytes);
    CHECK(r.settle());
    CHECK(r.fm->total_watch() == w_before);
    CHECK(r.fm->total_unwatch() == u_before);
}

// =================================================================================================
// 6. Wedge on a DIFFERENT io class + healthy siblings, valve spent: the forced Reapply leaves the
//    siblings untouched, the generation stays held in memory AND on disk, the wedge is re-counted.
//    RED-BY-DESIGN. Mutations: delete the skip branch; delete the scoped full_sync filter.
// =================================================================================================
TEST_CASE("#4415 PR-A (6): a hung Service arm plus healthy File siblings, safety valve spent: the "
          "forced Reapply leaves the siblings untouched, holds the generation (memory and disk) and "
          "re-counts the wedge",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0"), p1 = r.make_file("s1");
    const std::string k0 = file_key(p0), k1 = file_key(p1), ksvc = service_key("yuzu-4415-hung");
    const std::string bytes = push_bytes(
        {service_rule("h", "yuzu-4415-hung"), file_rule("s0", p0), file_rule("s1", p1)}, kGen);

    r.sm->hang_next_watch();
    r.dispatch(bytes);
    const std::string hk = park_and_wedge(r, *r.sm, /*expected_armed=*/2);
    REQUIRE(hk == ksvc);
    REQUIRE(r.wait_compliant({"s0", "s1"}));
    suppressed_repushes(r, bytes, hk, kValve); // the budget is spent by pure holds
    check_untouched(*r.fm, "s0", k0);
    check_untouched(*r.fm, "s1", k1);

    // The forced Reapply.
    r.dispatch(bytes);
    CHECK(r.settle());
    check_untouched(*r.fm, "s0 (healthy sibling, forced Reapply)", k0);
    check_untouched(*r.fm, "s1", k1);
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{k0, k1});
    CHECK(r.fm->total_watch() == 2);
    CHECK(r.fm->total_unwatch() == 0);
    CHECK(r.sm->watch_calls(hk) == 1); // the hung claim is re-observed, never re-armed
    CHECK(r.sm->unwatch_calls(hk) == 0);
    CHECK(r.lifecycle("s0", "disarmed") == 0);
    CHECK(r.lifecycle("s1", "disarmed") == 0);
    CHECK(r.rt().claim_queue_depth_for_test(hk) == 1);
    CHECK(r.engine->spark_armed_rule_count() == 2);
    // The wedge is re-counted by the new application once its ledger drains; nothing else fails.
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.engine->journal_maintenance_tick();
            return r.engine->ack_pending_count_for_test() == 0;
        },
        10s));
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
        CHECK(s->pending == 0);
    }
    CHECK(r.engine->policy_generation() == 0); // held in memory...
    CHECK(r.persisted_generation().value_or(0) == 0); // ...and on disk

    // Suppression resumes (the valve's budget is back to zero) and still touches nothing.
    suppressed_repush(r, bytes, hk);
    check_untouched(*r.fm, "s0 (after the valve)", k0);
}

// =================================================================================================
// 7. A late failure of one rule rebuilds exactly that rule.
//    RED-BY-DESIGN. Mutations: delete the skip branch; delete the scoped full_sync filter.
// =================================================================================================
TEST_CASE("#4415 PR-A (7): a hung arm that later REFUSES is rebuilt by the next push and ONLY it; "
          "the healthy siblings are untouched, and only then is the generation acknowledged",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0"), p1 = r.make_file("s1");
    const std::string k0 = file_key(p0), k1 = file_key(p1);
    const std::string bytes = push_bytes(
        {service_rule("h", "yuzu-4415-late"), file_rule("s0", p0), file_rule("s1", p1)}, kGen);

    r.sm->hang_next_watch();
    r.dispatch(bytes);
    const std::string hk = park_and_wedge(r, *r.sm, 2);
    REQUIRE(r.wait_compliant({"s0", "s1"}));
    suppressed_repushes(r, bytes, hk, 3);

    // Only now does the parked call return, as a refusal.
    r.sm->set_late_refuse();
    r.sm->release_hang();
    await_late_result_landed(r, hk);
    for (int i = 0; i < 20; ++i)
        r.engine->journal_maintenance_tick(); // a count of ticks, not a wait: nothing re-arms alone
    REQUIRE(r.engine->spark_armed_rule_count() == 2);
    r.require_generation_held();
    REQUIRE(r.sm->watch_calls(hk) == 1);

    r.dispatch(bytes); // the owed re-push: the wedge has popped, so this is a real Reapply
    CHECK(r.settle());
    CHECK(r.sm->watch_calls(hk) == 2); // the failed rule, and only it, is rebuilt
    check_untouched(*r.fm, "s0 (healthy sibling, late failure of another rule)", k0);
    check_untouched(*r.fm, "s1", k1);
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{k0, k1});
    CHECK(r.lifecycle("s0", "disarmed") == 0);
    CHECK(r.lifecycle("s1", "disarmed") == 0);
    CHECK(r.wait_generation(kGen)); // acknowledged once the rule is live again
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);
}

// =================================================================================================
// 8. #5513 catch-up: the same-generation catch-up push re-arms ONLY the boot-failed rule.
//    RED-BY-DESIGN. Mutations: delete the skip branch; delete the scoped full_sync filter.
// =================================================================================================
TEST_CASE("#4415 PR-A (8): #5513 boot catch-up (prefer_spark=true): the catch-up push re-arms only "
          "the rule whose boot re-arm failed; the two that armed at boot are untouched",
          "[spark][guardian][reconcile][4415prA][5513]") {
    constexpr std::uint64_t kBootGen = 7;
    Rig r;
    std::string bytes;
    std::string k0, k1, k2;
    {
        // Incarnation 1: arm three rules, acknowledge, shut down. The KV keeps rules + generation.
        r.open();
        const auto p0 = r.make_file("b0"), p1 = r.make_file("b1"), p2 = r.make_file("b2");
        k0 = file_key(p0);
        k1 = file_key(p1);
        k2 = file_key(p2);
        bytes = push_bytes({file_rule("r0", p0), file_rule("r1", p1), file_rule("r2", p2)}, kBootGen);
        r.dispatch(bytes);
        REQUIRE(r.wait_armed(3));
        REQUIRE(r.wait_generation(kBootGen));
        REQUIRE(r.settle());
        r.close();
    }
    // Incarnation 2: r1's boot re-arm throws (injected thread exhaustion); r0 and r2 arm at boot.
    r.open([](const std::string& rule_id) {
        if (rule_id == "r1")
            throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again),
                                    "injected thread exhaustion");
    });
    REQUIRE(r.engine->boot_rearm_unresolved());
    REQUIRE(r.engine->policy_generation() == 0); // reports 0 until the catch-up resolves it
    REQUIRE(r.wait_armed(2));
    REQUIRE(r.settle());
    REQUIRE(r.fm->watch_calls(k0) == 1);
    REQUIRE(r.fm->watch_calls(k2) == 1);
    REQUIRE(r.fm->watch_calls(k1) == 0);

    r.dispatch(bytes); // the server's catch-up push: same rules, same generation
    CHECK(r.settle());
    CHECK(r.fm->watch_calls(k1) == 1); // the boot-failed rule is armed now
    check_untouched(*r.fm, "r0 (armed at boot)", k0);
    check_untouched(*r.fm, "r2 (armed at boot)", k2);
    CHECK(r.fm->unwatch_calls(k1) == 0);
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{k0, k1, k2});
    CHECK(r.engine->spark_armed_rule_count() == 3);
    CHECK(r.wait_generation(kBootGen));
    CHECK_FALSE(r.engine->boot_rearm_unresolved());
}

// =================================================================================================
// 9. The DESIRED post-fix semantics of the existing [5459valve] / [5459fu10] cases, as NEW cases.
//    The old cases pin the defect (a forced Reapply tears down and re-arms the just-armed rule / the
//    healthy same-type sibling) and are to be REWRITTEN at implementation time, not weakened.
// =================================================================================================

// 9a. [5459valve], post-fix: valve spent, then the late success is adopted: the next identical push
//     is NOT a teardown and acknowledges the held generation inline (AC-9's last sentence).
//     RED-BY-DESIGN. Mutations: delete the skip branch (a forced Reapply tears the rule down).
TEST_CASE("#4415 PR-A (9a): valve spent, then the late success is adopted: the next identical push "
          "tears nothing down and acknowledges the held generation inline on that very push",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto p = r.make_file("h");
    const std::string kh = file_key(p);
    const std::string bytes = push_bytes({file_rule("h", p)}, kGen);

    r.fm->hang_next_watch();
    r.dispatch(bytes);
    const std::string hk = park_and_wedge(r, *r.fm, /*expected_armed=*/0);
    REQUIRE(hk == kh);
    suppressed_repushes(r, bytes, hk, kValve); // budget spent

    // The hung arm succeeds and nobody withdrew the rule: adopted. NO tick runs between the
    // adoption and the next push, so the ledger still holds the entry as Recovered-but-uncleared.
    r.fm->release_hang();
    await_late_result_landed(r, hk);
    REQUIRE(r.engine->spark_armed_rule_count() == 1);
    REQUIRE(r.fm->watch_calls(kh) == 1);
    REQUIRE(r.fm->unwatch_calls(kh) == 0);
    r.require_generation_held();

    r.dispatch(bytes); // the valve is spent: a forced Reapply, which must now be a no-op for `h`
    // Acknowledged inline: no tick, no wait. The new application has no receipt, so it can advance.
    CHECK(r.engine->policy_generation() == kGen);
    CHECK(r.settle());
    CHECK(r.fm->watch_calls(kh) == 1);   // no replacement arm
    CHECK(r.fm->unwatch_calls(kh) == 0); // no teardown of the just-armed subscription
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{kh});
    CHECK(r.engine->spark_armed_rule_count() == 1);
    CHECK(r.lifecycle("h", "disarmed") == 0);
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0);
        CHECK(s->pending == 0);
    }
}

// 9b. [5459fu10] (AC-16), post-fix: a hung File arm with a healthy SAME-type sibling, valve spent:
//     the forced Reapply does NOT withdraw the sibling (no disarm worker, no queued re-arm, no
//     CongestionExpired), the wedge is re-counted once, the generation stays held, the next push
//     suppresses again, and the late success is acknowledged by maintenance alone.
//     RED-BY-DESIGN. Mutations: delete the skip branch; delete the scoped full_sync filter; drop
//     the claims-empty term (a sibling whose key still has a claim is not skipped).
TEST_CASE("#4415 PR-A (9b): AC-16 post-fix: the forced Reapply during a hung same-type watch() does "
          "not withdraw the healthy same-type sibling; nothing queues behind the hung call and "
          "nothing expires",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto pa = r.make_file("a"), pb = r.make_file("b");
    const std::string bytes = push_bytes({file_rule("ra", pa), file_rule("rb", pb)}, kGen);

    r.fm->hang_watch_ordinal(2); // the first File watch() commits, the second hangs
    r.dispatch(bytes);
    const std::string hk = park_and_wedge(r, *r.fm, /*expected_armed=*/1);
    const auto watched = r.fm->watched_snapshot();
    REQUIRE(watched.size() == 1);
    const std::string sib = *watched.begin();
    REQUIRE(sib != hk);
    REQUIRE((sib == file_key(pa) || sib == file_key(pb)));
    REQUIRE(r.wait_compliant({sib == file_key(pa) ? "ra" : "rb"}));
    suppressed_repushes(r, bytes, hk, kValve);
    check_untouched(*r.fm, "sibling during pure holds", sib);

    // The forced Reapply.
    r.dispatch(bytes);
    CHECK(r.settle());
    auto& rt = r.rt();
    check_untouched(*r.fm, "same-type sibling, forced Reapply", sib);
    CHECK(rt.claim_queue_depth_for_test(sib) == 0); // no pending disarm, no queued re-arm
    CHECK(rt.claim_queue_depth_for_test(hk) == 1);  // the very same hung claim, re-observed
    CHECK(rt.active_backend_op_workers() == 1);     // only the hung call: no disarm worker blocked behind it
    CHECK(r.fm->watched_snapshot() == std::set<std::string>{sib});
    CHECK(r.engine->spark_armed_rule_count() == 1);
    CHECK(rt.expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() + 2h) == 0); // no CongestionExpired
    REQUIRE(yuzu::test::spin_until(
        [&] {
            r.engine->journal_maintenance_tick();
            return r.engine->ack_pending_count_for_test() == 0;
        },
        10s));
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0);
        CHECK(s->failed == 1); // the wedge alone; the baseline reads 2 (the sibling's expired re-arm)
    }
    CHECK(r.engine->policy_generation() == 0); // held in memory...
    CHECK(r.persisted_generation().value_or(0) == 0); // ...and on disk

    // The following push is a Suppress again (budget back to zero), and touches nothing.
    suppressed_repush(r, bytes, hk);
    check_untouched(*r.fm, "sibling after the valve", sib);

    // The hang is released: the hung arm's late success is adopted and, with the sibling never
    // withdrawn, the held generation is acknowledged by maintenance alone (no re-push needed).
    r.fm->release_hang();
    await_late_result_landed(r, hk);
    REQUIRE(r.wait_armed(2));
    CHECK(r.wait_generation(kGen));
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);
    CHECK(r.fm->watch_calls(hk) == 1); // adopted its ORIGINAL arm
    CHECK(r.fm->unwatch_calls(hk) == 0);
    check_untouched(*r.fm, "sibling at the end", sib);
}

// =================================================================================================
// KV PERSISTENCE (#4415 PR-A, third commit: "KV skip"). Every full_sync push today deletes EVERY
// `rule:` row (list_entries + del_keys) and then re-persists every rule (put_rule_locked ->
// kv_->set), so an identical re-push costs ~2R KV events and a crash between the sweep and the
// re-persist loses the whole persisted ruleset. The fix: (a) delete only the `rule:` rows ABSENT
// from the push; (b) put_rule_locked skips the write when the stored bytes already equal
// rule_to_json(rule).dump() (an unreadable stored row falls through to a write). Every existing
// failure latch stays.
//
// OBSERVABILITY. KvStore is `final` with no virtual surface (only the narrow IJournalStore seam, which
// GuardianEngine does not use), so the writes are observed where they land: a SECOND SQLite
// connection to the same on-disk file installs AFTER INSERT / AFTER UPDATE / AFTER DELETE row
// triggers on kv_store that append (op, key) to a log table in the same file. The upsert
// (INSERT .. ON CONFLICT DO UPDATE) fires AFTER UPDATE even when the new bytes equal the old, so an
// identical rewrite IS a logged write. The triggers are the test's own DDL; no product seam.
// Assertions are on EFFECT SETS (which keys were written / deleted), never on log text.
// KNOWN GAP, stated rather than hidden: put_rule_locked's stored-row READ failing cannot be
// injected (KvStore is final and non-virtual, with no read-failure seam), so the "an unreadable
// row is written, never skipped" arm is held only by the shape of its guard (a skip needs a
// present, equal row) and by KV-5's differing-bytes case. A failed del_keys and a failed row
// scan ARE injected (KV-8a, KV-8b).
// The apply_rules KV work is synchronous inside dispatch(), so the log is complete when dispatch
// returns; settle() is still called so nothing asynchronous is left running at close().
// =================================================================================================
namespace {

struct KvOp {
    char op; // 'W' = insert or update (a write), 'D' = delete
    std::string key;
};

class KvProbe {
public:
    KvProbe() = default;
    KvProbe(const KvProbe&) = delete;
    KvProbe& operator=(const KvProbe&) = delete;
    ~KvProbe() {
        if (db_)
            sqlite3_close(db_); // closes even a handle whose sqlite3_open() failed
    }

    /// Opens the probe connection (the kv_store table must already exist: call after Rig::open()).
    void install(const fs::path& db_path) {
        const int rc = sqlite3_open(db_path.string().c_str(), &db_);
        REQUIRE(rc == SQLITE_OK);
        sqlite3_busy_timeout(db_, 5000);
        exec("CREATE TABLE IF NOT EXISTS yuzu_test_kvlog("
             " seq INTEGER PRIMARY KEY AUTOINCREMENT, op TEXT NOT NULL, k TEXT NOT NULL);"
             "CREATE TRIGGER IF NOT EXISTS yuzu_test_kv_ins AFTER INSERT ON kv_store"
             " WHEN NEW.plugin = '__guardian__'"
             " BEGIN INSERT INTO yuzu_test_kvlog(op, k) VALUES('W', NEW.key); END;"
             "CREATE TRIGGER IF NOT EXISTS yuzu_test_kv_upd AFTER UPDATE ON kv_store"
             " WHEN NEW.plugin = '__guardian__'"
             " BEGIN INSERT INTO yuzu_test_kvlog(op, k) VALUES('W', NEW.key); END;"
             "CREATE TRIGGER IF NOT EXISTS yuzu_test_kv_del AFTER DELETE ON kv_store"
             " WHEN OLD.plugin = '__guardian__'"
             " BEGIN INSERT INTO yuzu_test_kvlog(op, k) VALUES('D', OLD.key); END;");
    }
    void exec(const char* sql) {
        REQUIRE(db_ != nullptr);
        char* raw_err = nullptr;
        const int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &raw_err);
        // Owned before the message string is built, so a throwing std::string cannot leak it.
        const std::unique_ptr<char, decltype(&sqlite3_free)> err{raw_err, &sqlite3_free};
        const std::string msg = err ? err.get() : "";
        CAPTURE(sql, msg);
        REQUIRE(rc == SQLITE_OK);
    }
    void clear() { exec("DELETE FROM yuzu_test_kvlog"); }

    std::vector<KvOp> ops() {
        REQUIRE(db_ != nullptr);
        std::vector<KvOp> out;
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> st{nullptr, &sqlite3_finalize};
        {
            sqlite3_stmt* raw = nullptr;
            const int rc = sqlite3_prepare_v2(db_, "SELECT op, k FROM yuzu_test_kvlog ORDER BY seq",
                                              -1, &raw, nullptr);
            st.reset(raw); // owned even when prepare reports an error
            REQUIRE(rc == SQLITE_OK);
        }
        while (sqlite3_step(st.get()) == SQLITE_ROW) {
            const auto* o = sqlite3_column_text(st.get(), 0);
            const auto* k = sqlite3_column_text(st.get(), 1);
            out.push_back({static_cast<char>(o ? o[0] : '?'),
                           k ? reinterpret_cast<const char*>(k) : ""});
        }
        return out;
    }
    /// The keys written / deleted (with multiplicity: a key hit twice appears twice) under `prefix`.
    std::vector<std::string> keys(char op, std::string_view prefix) {
        std::vector<std::string> out;
        for (auto& o : ops())
            if (o.op == op && o.key.rfind(prefix, 0) == 0)
                out.push_back(o.key);
        std::sort(out.begin(), out.end());
        return out;
    }
    std::vector<std::string> writes(std::string_view prefix = "rule:") { return keys('W', prefix); }
    std::vector<std::string> deletes(std::string_view prefix = "rule:") { return keys('D', prefix); }

private:
    sqlite3* db_{nullptr};
};

/// Rig + probe; the probe closes first (declared after the rig).
struct KvRig {
    Rig r;
    KvProbe probe;
    void start() {
        r.open();
        probe.install(r.db.path);
    }
    std::map<std::string, std::string> rule_rows() {
        auto rows = r.kv->list_entries(kKvNs, "rule:");
        REQUIRE(rows.has_value());
        std::map<std::string, std::string> out;
        for (auto& row : *rows)
            out[row.key] = row.value;
        return out;
    }
    std::vector<std::string> rule_row_keys() {
        std::vector<std::string> out;
        for (auto& [k, v] : rule_rows())
            out.push_back(k);
        return out;
    }
};

struct KvRules {
    std::vector<fs::path> paths;
    std::vector<std::string> ids, row_keys, spark_keys;
    std::vector<gpb::GuaranteedStateRule> rules;
};
KvRules make_kv_rules(Rig& r, int n) {
    KvRules s;
    for (int i = 0; i < n; ++i) {
        s.paths.push_back(r.make_file("kv" + std::to_string(i)));
        s.ids.push_back("r" + std::to_string(i));
        s.row_keys.push_back("rule:" + s.ids.back());
        s.spark_keys.push_back(file_key(s.paths.back()));
        s.rules.push_back(file_rule(s.ids.back(), s.paths.back()));
    }
    return s;
}
std::vector<std::string> sorted(std::vector<std::string> v) {
    std::sort(v.begin(), v.end());
    return v;
}

/// First push of `bytes`, waited to quiescence, with the setup PREMISES that make the probe and the
/// arm trustworthy: the probe really saw R row writes, and the rules armed.
void first_push(KvRig& k, const KvRules& s, const std::string& bytes) {
    k.probe.clear();
    k.r.dispatch(bytes);
    REQUIRE(k.r.wait_armed(s.ids.size()));
    REQUIRE(k.r.wait_compliant(s.ids));
    REQUIRE(k.r.wait_generation(kGen));
    REQUIRE(k.r.settle());
    // Premise: the probe works (every rule row was written exactly once by the first push).
    REQUIRE(k.probe.writes() == sorted(s.row_keys));
    REQUIRE(k.rule_row_keys() == sorted(s.row_keys));
}

} // namespace

// -------------------------------------------------------------------------------------------------
// KV-1. An identical full_sync re-push of R rules: ZERO rule-row deletes and ZERO rule-row writes.
//       RED-BY-DESIGN (baseline: R deletes then R writes). Mutations: delete the delete-only-absent
//       filter (deletes go red); delete the equal-bytes skip (writes go red).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (1): an identical full_sync re-push of R rules deletes no rule row and "
          "writes no rule row; the row bytes and the persisted generation are unchanged",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    constexpr int R = 5;
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, R);
    const std::string bytes = push_bytes(s.rules, kGen);
    first_push(k, s, bytes);
    const auto rows_before = k.rule_rows();

    k.probe.clear();
    k.r.dispatch(bytes); // byte-identical re-push
    CHECK(k.r.settle_idle(R));

    CHECK(k.probe.deletes().empty());
    CHECK(k.probe.writes().empty());
    CHECK(k.rule_rows() == rows_before);
    REQUIRE(k.r.persisted_generation().has_value());
    CHECK(*k.r.persisted_generation() == kGen);
    CHECK(k.r.engine->policy_generation() == kGen);
}

// -------------------------------------------------------------------------------------------------
// KV-1d. An identical DELTA (full_sync=false) re-push of a subset of the rules: the pushed rules are
//        skipped (no mechanism call), no row is deleted or rewritten, and the rules the delta does
//        not carry are untouched. Mutation: delete the skip branch (the pushed rules' key counts
//        move); delete the equal-bytes skip (writes go red).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (1d): an identical delta re-push skips the pushed rules, rewrites no row "
          "and leaves the rules it does not carry alone",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    constexpr int R = 4;
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, R);
    first_push(k, s, push_bytes(s.rules, kGen));
    const auto rows_before = k.rule_rows();

    const std::string delta = push_bytes({s.rules[0], s.rules[1]}, kGen + 1, /*full_sync=*/false);
    k.probe.clear();
    k.r.dispatch(delta);
    CHECK(k.r.settle_idle(R));

    for (int i = 0; i < R; ++i)
        check_untouched(*k.r.fm, s.ids[static_cast<std::size_t>(i)], s.spark_keys[static_cast<std::size_t>(i)]);
    CHECK(k.probe.deletes().empty());
    CHECK(k.probe.writes().empty());
    CHECK(k.rule_rows() == rows_before);
    CHECK(k.r.engine->spark_armed_rule_count() == R);
}

// -------------------------------------------------------------------------------------------------
// KV-2. A changed rule in an otherwise identical push: ONLY that row is rewritten, none deleted, and
//       the new content is what is stored (and what a restart would load).
//       RED-BY-DESIGN on "others untouched" (the changed-row-readable half is a GUARD).
//       Mutations: skip on rule_id alone, ignoring the bytes (the new content is never stored: the
//       readable assertion goes red); delete the equal-bytes skip (writes go red).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (2): a changed rule in an otherwise identical push rewrites ONLY its own "
          "row; every other row is neither deleted nor rewritten; the new content is stored",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    KvRig k;
    k.start();
    auto s = make_kv_rules(k.r, 4);
    first_push(k, s, push_bytes(s.rules, kGen));
    const auto rows_before = k.rule_rows();

    auto changed = s.rules;
    changed[1].set_name("r1 renamed by 4415 KV test"); // same rule_id, same spark key, new content
    k.probe.clear();
    k.r.dispatch(push_bytes(changed, kGen));
    CHECK(k.r.settle());

    // GUARD (green on the baseline): the changed row holds the NEW bytes.
    const auto after = k.r.kv->get(kKvNs, "rule:r1");
    REQUIRE(after.has_value());
    CHECK(after->find("r1 renamed by 4415 KV test") != std::string::npos);
    CHECK(*after != rows_before.at("rule:r1"));
    // RED on the baseline: only that row moved.
    CHECK(k.probe.writes() == std::vector<std::string>{"rule:r1"});
    CHECK(k.probe.deletes().empty());
    const auto rows_after = k.rule_rows();
    for (const auto& key : {"rule:r0", "rule:r2", "rule:r3"}) {
        CAPTURE(key);
        CHECK(rows_after.at(key) == rows_before.at(key));
    }
}

// -------------------------------------------------------------------------------------------------
// KV-3. A rule removed from the push: its row is deleted, the others are neither deleted nor
//       rewritten. The row-deleted half is a GUARD (green on the baseline); the rest is RED.
//       Mutations: stop deleting absent rows (the guard goes red); delete-all (deletes go red).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (3): a rule removed from the push has its row deleted; the surviving rows "
          "are neither deleted nor rewritten",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, 4);
    first_push(k, s, push_bytes(s.rules, kGen));
    const auto rows_before = k.rule_rows();

    const std::vector<gpb::GuaranteedStateRule> kept{s.rules[0], s.rules[1], s.rules[3]};
    k.probe.clear();
    k.r.dispatch(push_bytes(kept, kGen));
    CHECK(k.r.settle());

    // GUARD (green on the baseline): the removed rule's row is gone, in the store and in the log.
    CHECK_FALSE(k.r.kv->get(kKvNs, "rule:r2").has_value());
    const auto del = k.probe.deletes();
    CHECK(std::find(del.begin(), del.end(), "rule:r2") != del.end());
    // RED on the baseline: it is the ONLY row deleted and no row is rewritten.
    CHECK(del == std::vector<std::string>{"rule:r2"});
    CHECK(k.probe.writes().empty());
    auto expected = rows_before;
    expected.erase("rule:r2");
    CHECK(k.rule_rows() == expected);
}

// -------------------------------------------------------------------------------------------------
// KV-3b. A stale row whose rule_id is outside the #4665 charset (and absent from the push) is still
//        deleted - the hard cutover is unchanged - and the pushed rows are untouched.
//        MIXED: the stale-row-deleted half is a GUARD; "siblings untouched" is RED.
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (3b): a stale row with a non-conforming rule_id absent from the push is "
          "still deleted (#4665 hard cutover); the pushed rows are untouched",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, 3);
    const std::string bytes = push_bytes(s.rules, kGen);
    first_push(k, s, bytes);
    const std::string stale = "rule:bad id!";
    REQUIRE(k.r.kv->set(kKvNs, stale, R"({"rule_id":"bad id!"})"));
    const auto rows_before = k.rule_rows();
    REQUIRE(rows_before.count(stale) == 1);

    k.probe.clear();
    k.r.dispatch(bytes);
    CHECK(k.r.settle());

    CHECK_FALSE(k.r.kv->get(kKvNs, stale).has_value());           // GUARD
    CHECK(k.probe.deletes() == std::vector<std::string>{stale}); // RED: nothing else deleted
    CHECK(k.probe.writes().empty());                             // RED: nothing rewritten
    CHECK(k.rule_row_keys() == sorted(s.row_keys));
}

// -------------------------------------------------------------------------------------------------
// KV-4. A new rule added to the push: its row is written, the existing rows are neither deleted nor
//       rewritten. The new-row-stored half is a GUARD; the rest is RED.
//       Mutations: skip when the key is absent (the guard goes red); delete-all/rewrite-all.
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (4): a rule added to the push is written; the existing rows are neither "
          "deleted nor rewritten",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    KvRig k;
    k.start();
    auto s = make_kv_rules(k.r, 4);
    const std::vector<gpb::GuaranteedStateRule> initial{s.rules[0], s.rules[1], s.rules[2]};
    {
        KvRules first = s;
        first.ids.pop_back();
        first.row_keys.pop_back();
        first.spark_keys.pop_back();
        first.rules = initial;
        first_push(k, first, push_bytes(initial, kGen));
    }
    const auto rows_before = k.rule_rows();

    k.probe.clear();
    k.r.dispatch(push_bytes(s.rules, kGen)); // r0..r2 identical, r3 new
    CHECK(k.r.settle());

    CHECK(k.r.kv->get(kKvNs, "rule:r3").has_value()); // GUARD
    CHECK(k.probe.writes() == std::vector<std::string>{"rule:r3"});
    CHECK(k.probe.deletes().empty());
    const auto rows_after = k.rule_rows();
    for (const auto& id : {"rule:r0", "rule:r1", "rule:r2"}) {
        CAPTURE(id);
        CHECK(rows_after.at(id) == rows_before.at(id));
    }
    CHECK(rows_after.size() == 4);
}

// -------------------------------------------------------------------------------------------------
// KV-5. A stored row that DIFFERS from the pushed rule's bytes (corrupt / hand-edited / older
//       serialisation) is rewritten to the canonical bytes; its identical siblings are not touched.
//       This is the observable half of "an unreadable or non-equal stored row falls through to a
//       write, never a skip". The rewritten-to-canonical half is a GUARD; "only that row" is RED.
//       (A genuine store READ failure cannot be separated from a write failure with a real store:
//       see the report.) Mutations: skip when the key merely exists (the guard goes red).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (5): a stored row whose bytes differ from the pushed rule is rewritten to "
          "the canonical bytes; the rows that already match are not touched",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, 3);
    const std::string bytes = push_bytes(s.rules, kGen);
    first_push(k, s, bytes);
    const auto canonical = k.rule_rows();
    REQUIRE(k.r.kv->set(kKvNs, "rule:r1", "{not json"));

    k.probe.clear(); // (the corrupting write above is not part of the push's effect set)
    k.r.dispatch(bytes);
    CHECK(k.r.settle());

    CHECK(k.rule_rows() == canonical);                                      // GUARD: repaired
    CHECK(k.probe.writes() == std::vector<std::string>{"rule:r1"});         // RED: only that row
    CHECK(k.probe.deletes().empty());                                       // RED
}

// -------------------------------------------------------------------------------------------------
// KV-6. Restart re-arm sees EXACTLY the pushed set after (a) an identical re-push, (b) a changed
//       push, (c) a removal push. GUARD (green on the baseline AND after the fix): the persisted rows
//       are what start_local() re-arms, so a skipped or scoped KV write must not lose or resurrect a
//       rule across a restart.
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (6): after an identical, a changed or a removal re-push, a restart re-arms "
          "exactly the pushed set - nothing lost, nothing resurrected",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, 3);
    first_push(k, s, push_bytes(s.rules, kGen));

    std::vector<gpb::GuaranteedStateRule> second = s.rules;
    std::set<std::string> expected_spark;
    std::vector<std::string> expected_rows;
    std::string absent_spark; // a spark key that must NOT be armed after the restart

    SECTION("identical re-push") {
        k.r.dispatch(push_bytes(second, kGen));
        expected_spark = {s.spark_keys[0], s.spark_keys[1], s.spark_keys[2]};
        expected_rows = sorted(s.row_keys);
    }
    SECTION("changed re-push (r1 retargeted to a new path)") {
        const auto moved = k.r.make_file("kv1_moved");
        second[1] = file_rule("r1", moved);
        k.r.dispatch(push_bytes(second, kGen));
        expected_spark = {s.spark_keys[0], file_key(moved), s.spark_keys[2]};
        expected_rows = sorted(s.row_keys);
        absent_spark = s.spark_keys[1];
    }
    SECTION("removal re-push (r1 dropped)") {
        second = {s.rules[0], s.rules[2]};
        k.r.dispatch(push_bytes(second, kGen));
        expected_spark = {s.spark_keys[0], s.spark_keys[2]};
        expected_rows = sorted(std::vector<std::string>{s.row_keys[0], s.row_keys[2]});
        absent_spark = s.spark_keys[1];
    }
    REQUIRE(k.r.settle());
    CHECK(k.rule_row_keys() == expected_rows);

    k.r.close();
    k.r.open(); // a fresh engine over the same KV: start_local()'s restart re-arm loop
    CHECK(k.r.wait_armed(expected_spark.size()));
    CHECK(k.r.settle());
    CHECK(k.r.fm->watched_snapshot() == expected_spark);
    CHECK(k.r.engine->spark_armed_rule_count() == expected_spark.size());
    if (!absent_spark.empty())
        CHECK(k.r.fm->watch_calls(absent_spark) == 0);
    CHECK(k.rule_row_keys() == expected_rows);
}

// -------------------------------------------------------------------------------------------------
// KV-7. Baseline rows (#4021) and the generation key survive identical re-push AND a removal push
//       that drops the baseline's own rule. GUARD (green on the baseline AND after the fix): pins
//       that scoping the sweep to `rule:` rows never widens it.
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (7): baseline rows and the generation key are never deleted by an identical "
          "re-push or by a removal push, including a removal of the baseline's own rule",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    BaselineRig b;
    b.build(); // rules hr (file-hash-equals, baseline persisted), s0, s1
    auto& r = b.r;
    KvProbe probe;
    probe.install(r.db.path);
    const std::string sentinel = "baseline:yuzu_test_orphan"; // a baseline with NO rule in any push
    REQUIRE(r.kv->set(kKvNs, sentinel, R"({"hash":"deadbeef"})"));
    const auto baseline_hr = r.kv->get(kKvNs, "baseline:hr");
    REQUIRE(baseline_hr.has_value());

    probe.clear();
    r.dispatch(b.bytes); // identical re-push
    CHECK(r.settle());
    CHECK(probe.deletes("baseline:").empty());
    CHECK(probe.deletes("meta:").empty());
    CHECK(r.kv->get(kKvNs, "baseline:hr") == baseline_hr);
    CHECK(r.kv->get(kKvNs, sentinel).value_or("") == R"({"hash":"deadbeef"})");
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);

    // Removal push dropping hr itself: its baseline is deliberately kept (absence is not deletion).
    const auto p0 = r.dir.path / "s0", p1 = r.dir.path / "s1";
    probe.clear();
    r.dispatch(push_bytes({file_rule("s0", p0), file_rule("s1", p1)}, kGen));
    CHECK(r.settle());
    CHECK(probe.deletes("baseline:").empty());
    CHECK(probe.deletes("meta:").empty());
    CHECK(r.kv->get(kKvNs, "baseline:hr") == baseline_hr);
    CHECK(r.kv->get(kKvNs, sentinel).has_value());
    CHECK_FALSE(r.kv->get(kKvNs, "rule:hr").has_value()); // the rule row itself IS removed
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);
}

// -------------------------------------------------------------------------------------------------
// KV-8a. A del_keys that FAILS (an aborting BEFORE DELETE trigger, the test's own DDL) is an
//        undercount: the generation is HELD, in memory and on disk, and no row is lost. After the
//        fault is removed, the repeat push heals it. GUARD (green on the baseline AND after the fix;
//        the removal push forces a delete on both).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (8a): a failed del_keys on a removal push holds the generation and loses no "
          "row; the repeat push after the fault clears advances it",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    constexpr std::uint64_t kNext = kGen + 1;
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, 3);
    first_push(k, s, push_bytes(s.rules, kGen));
    const auto rows_before = k.rule_rows();

    k.probe.exec("CREATE TRIGGER yuzu_test_kv_veto BEFORE DELETE ON kv_store"
                 " WHEN OLD.plugin = '__guardian__' AND OLD.key LIKE 'rule:%'"
                 " BEGIN SELECT RAISE(ABORT, 'yuzu_test injected del_keys failure'); END;");
    const std::vector<gpb::GuaranteedStateRule> kept{s.rules[0], s.rules[1]}; // r2 removed
    const std::string removal = push_bytes(kept, kNext);
    k.probe.clear();
    k.r.dispatch(removal);
    CHECK(k.r.settle());

    CHECK(k.probe.deletes().empty()); // the vetoed deletes rolled back: no row was lost
    CHECK(k.r.engine->policy_generation() == kGen); // HELD in memory...
    REQUIRE(k.r.persisted_generation().has_value());
    CHECK(*k.r.persisted_generation() == kGen); // ...and on disk
    for (const auto& key : {"rule:r0", "rule:r1", "rule:r2"})
        CHECK(k.r.kv->get(kKvNs, key).has_value());

    k.probe.exec("DROP TRIGGER yuzu_test_kv_veto");
    k.r.dispatch(removal); // the server's retry
    CHECK(k.r.settle());
    CHECK(k.r.wait_generation(kNext));
    CHECK_FALSE(k.r.kv->get(kKvNs, "rule:r2").has_value());
    CHECK(k.rule_row_keys() == sorted(std::vector<std::string>{"rule:r0", "rule:r1"}));
}

// -------------------------------------------------------------------------------------------------
// KV-8b. A store whose read path is broken (the `value` column renamed through the probe connection,
//        which breaks list_entries, get and set alike - SQLite offers no seam that fails ONLY
//        list_entries) holds the generation and deletes NOTHING: the sweep is skipped, never run on
//        a guess. DELETE does not name `value`, so a wrongly-proceeding sweep WOULD succeed here and
//        show up as logged deletes. GUARD (green on the baseline AND after the fix). The hold is
//        double-sourced (the list_entries latch and put_rule_locked's failure), so this pins the
//        pair, not the list_entries latch alone.
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (8b): an unreadable rule-row scan holds the generation and deletes no row",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    constexpr std::uint64_t kNext = kGen + 1;
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, 3);
    first_push(k, s, push_bytes(s.rules, kGen));
    const auto rows_before = k.rule_rows();

    k.probe.exec("ALTER TABLE kv_store RENAME COLUMN value TO yuzu_test_value");
    const std::vector<gpb::GuaranteedStateRule> kept{s.rules[0], s.rules[1]}; // r2 removed
    k.probe.clear();
    const auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*k.r.engine,
                                                                       push_bytes(kept, kNext));
    (void)dr; // the push may report failure (the rule write cannot persist); only the effects matter
    CHECK(k.r.settle());
    const auto deletes = k.probe.deletes(""); // every key, not only rule:
    k.probe.exec("ALTER TABLE kv_store RENAME COLUMN yuzu_test_value TO value");

    CHECK(deletes.empty()); // no sweep on an unreadable scan
    CHECK(k.r.engine->policy_generation() == kGen);
    REQUIRE(k.r.persisted_generation().has_value());
    CHECK(*k.r.persisted_generation() == kGen);
    CHECK(k.rule_rows() == rows_before); // every row intact, bytes included
}

// =================================================================================================
// PRESERVED-RULE LOG LINE (#4415 PR-A). A full_sync names the rules it skipped, so a reader can
// account for every rule in the push (re-armed, preserved, or neither = failed) instead of
// inferring the preserved set by count. The line is recorded at emission
// (last_full_sync_preserved_line_for_test), not captured from spdlog: the agent core is a shared
// library on some toolchains and a test-side default-logger swap does not reach it (#3355).
// Mutations: delete the note() call in reconcile_rule_locked (every `ids=` goes empty: red);
// reset the tally after the loop instead of before (the line reports the previous push: red);
// drop the `if (!skipped)` distinction by noting every Armed outcome (the changed rule appears: red).
// =================================================================================================
TEST_CASE("#4415 PR-A (10): a full_sync names exactly the rules it skipped - none on the first push, "
          "all on an identical re-push, not the changed rule, not an omitted one",
          "[spark][guardian][reconcile][4415prA]") {
    constexpr int R = 4;
    Rig r;
    r.open();
    std::vector<fs::path> paths;
    std::vector<std::string> ids;
    for (int i = 0; i < R; ++i) {
        paths.push_back(r.make_file("t" + std::to_string(i)));
        ids.push_back("r" + std::to_string(i));
    }
    const auto build = [&](const std::string& r2_name, int omit) {
        std::vector<gpb::GuaranteedStateRule> v;
        for (int i = 0; i < R; ++i) {
            if (i == omit)
                continue;
            v.push_back(i == 2 ? file_rule(ids[i], paths[i], r2_name) : file_rule(ids[i], paths[i]));
        }
        return push_bytes(v, kGen);
    };

    CHECK(r.engine->last_full_sync_preserved_line_for_test().empty()); // nothing emitted yet

    r.dispatch(build({}, -1));
    REQUIRE(r.wait_armed(R));
    REQUIRE(r.wait_compliant(ids));
    REQUIRE(r.wait_generation(kGen));
    REQUIRE(r.settle());
    // First push: every rule is built, none skipped. The line is still emitted (N = 0).
    CHECK(r.engine->last_full_sync_preserved_line_for_test() ==
          "Guardian: full_sync preserved 0 rule(s) (skipped re-arm) ids=[] more=0");

    r.dispatch(build({}, -1)); // byte-identical
    REQUIRE(r.settle());
    CHECK(r.engine->last_full_sync_preserved_line_for_test() ==
          "Guardian: full_sync preserved 4 rule(s) (skipped re-arm) ids=[r0,r1,r2,r3] more=0");

    r.dispatch(build("renamed-r2", -1)); // r2's content changed: rebuilt, so NOT preserved
    REQUIRE(r.settle());
    CHECK(r.engine->last_full_sync_preserved_line_for_test() ==
          "Guardian: full_sync preserved 3 rule(s) (skipped re-arm) ids=[r0,r1,r3] more=0");

    r.dispatch(build("renamed-r2", 3)); // r3 omitted (detached), the rest unchanged
    REQUIRE(r.settle());
    CHECK(r.engine->last_full_sync_preserved_line_for_test() ==
          "Guardian: full_sync preserved 3 rule(s) (skipped re-arm) ids=[r0,r1,r2] more=0");
}

// RED before the pending split: a rule whose identical arm is still IN FLIGHT was tallied with the
// committed ones, so the reader counted an unconfirmed arm as accounted for (R5.7 completeness).
// Mutation: note() every `skipped` outcome regardless of kind (the hung rule joins `ids=`: red).
TEST_CASE("#4415 PR-A (10c): a rule whose identical arm is still in flight is reported separately "
          "from the committed-preserved ones",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0"), p1 = r.make_file("s1");
    const std::string bytes = push_bytes(
        {service_rule("h", "yuzu-4415-hung"), file_rule("s0", p0), file_rule("s1", p1)}, kGen);

    r.sm->hang_next_watch(); // the Service arm parks mid-watch(): its claim stays Pending
    r.dispatch(bytes);
    REQUIRE(r.sm->wait_entered_hang(10s));
    REQUIRE(r.wait_armed(2)); // the two File siblings committed
    REQUIRE(r.wait_compliant({"s0", "s1"}));

    // An IDENTICAL re-push while h is pending is a retry the ledger suppresses (no apply_rules), so
    // the push must differ: an added rule makes it a real re-apply that re-observes h's live arm.
    const auto p2 = r.make_file("s2");
    r.dispatch(push_bytes({service_rule("h", "yuzu-4415-hung"), file_rule("s0", p0),
                           file_rule("s1", p1), file_rule("s2", p2)},
                          kGen));
    CHECK(r.settle());
    CHECK(r.engine->last_full_sync_preserved_line_for_test() ==
          "Guardian: full_sync preserved 2 rule(s) (skipped re-arm) ids=[s0,s1] more=0 "
          "pending_reused 1 ids=[h] more=0");
    CHECK(r.sm->watch_calls(service_key("yuzu-4415-hung")) == 1); // re-observed, not re-armed
}

// A re-observed in-flight arm must not launder a failure: when its late result is a REFUSAL the
// generation stays held (the re-observation was not an acknowledgement), and the next differing
// push rebuilds ONLY that rule while every committed sibling is still untouched.
// Pins: the generation hold and the single-rule rebuild after a refused re-observed arm.
// Not mutation-checked by a seam. The recipe, applied by hand: make the re-observed claim report
// Armed (not Accepted) from attach_core, or skip registering its receipt with the application;
// either leaves the ledger nothing to fail and the generation reaches kGen, so the hold CHECK
// below goes red.
TEST_CASE("#4415 PR-A (10e): a re-observed in-flight arm that then refuses holds the generation, "
          "and the next push rebuilds only that rule",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0"), p1 = r.make_file("s1"), p2 = r.make_file("s2");
    const std::string hk = service_key("yuzu-4415-refused");
    const auto hung = service_rule("h", "yuzu-4415-refused");

    r.sm->hang_next_watch();
    r.dispatch(push_bytes({hung, file_rule("s0", p0), file_rule("s1", p1)}, kGen));
    REQUIRE(r.sm->wait_entered_hang(10s));
    REQUIRE(r.wait_armed(2));
    REQUIRE(r.wait_compliant({"s0", "s1"}));
    // A differing push (a rule is added) re-observes h's live arm rather than re-arming it.
    r.dispatch(push_bytes({hung, file_rule("s0", p0), file_rule("s1", p1), file_rule("s2", p2)}, kGen));
    REQUIRE(r.wait_armed(3));
    CHECK(r.sm->watch_calls(hk) == 1);

    r.sm->set_late_refuse();
    r.sm->release_hang();
    REQUIRE(yuzu::test::spin_until(
        [&] { return r.rt().active_backend_op_workers() == 0 && r.rt().claim_queue_depth_for_test(hk) == 0; },
        10s));
    r.engine->journal_maintenance_tick();
    CHECK(r.engine->policy_generation() == 0); // held: the refused arm was never acknowledged
    CHECK(r.engine->spark_armed_rule_count() == 3);

    const auto p3 = r.make_file("s3");
    r.dispatch(push_bytes({hung, file_rule("s0", p0), file_rule("s1", p1), file_rule("s2", p2),
                           file_rule("s3", p3)},
                          kGen));
    CHECK(r.settle());
    CHECK(r.sm->watch_calls(hk) == 2); // h alone is attempted again
    for (const auto& [id, p] : {std::pair<const char*, fs::path>{"s0", p0}, {"s1", p1}, {"s2", p2}})
        check_untouched(*r.fm, id, file_key(p));
}

TEST_CASE("#4415 PR-A (10d): the pending-reused list is bounded and sanitised like the committed one, "
          "and a push with none keeps the exact pre-pending line",
          "[spark][guardian][4415prA]") {
    using yuzu::agent::GuardianPreservedTally;
    GuardianPreservedTally t;
    t.note("a");
    CHECK(t.format() == "Guardian: full_sync preserved 1 rule(s) (skipped re-arm) ids=[a] more=0");
    CHECK(t.pending_count() == 0);

    t.note_pending("p b\nx");
    CHECK(t.pending_count() == 1);
    CHECK(t.format().find('\n') == std::string::npos);
    CHECK(t.format() == "Guardian: full_sync preserved 1 rule(s) (skipped re-arm) ids=[a] more=0 "
                        "pending_reused 1 ids=[p_b_x] more=0");

    const std::size_t n = GuardianPreservedTally::kMaxIds + 7;
    for (std::size_t i = 0; i < n; ++i)
        t.note_pending("q" + std::to_string(i));
    CHECK(t.pending_ids().size() == GuardianPreservedTally::kMaxIds);
    CHECK(t.format().ends_with("more=" + std::to_string(n + 1 - GuardianPreservedTally::kMaxIds)));
    t.reset();
    CHECK(t.pending_count() == 0);
    CHECK(t.format() == "Guardian: full_sync preserved 0 rule(s) (skipped re-arm) ids=[] more=0");
}

TEST_CASE("#4415 PR-A (10b): the preserved tally is bounded and sanitised - ids are capped with the "
          "remainder counted in `more`, and a hostile id cannot forge a field or a line",
          "[spark][guardian][4415prA]") {
    using yuzu::agent::GuardianPreservedTally;
    GuardianPreservedTally t;
    CHECK(t.format() == "Guardian: full_sync preserved 0 rule(s) (skipped re-arm) ids=[] more=0");

    const std::size_t n = GuardianPreservedTally::kMaxIds + 40;
    for (std::size_t i = 0; i < n; ++i)
        t.note("rule-" + std::to_string(i));
    CHECK(t.count() == n);
    CHECK(t.ids().size() == GuardianPreservedTally::kMaxIds);
    const auto line = t.format();
    CHECK(line.find("preserved " + std::to_string(n) + " rule(s)") != std::string::npos);
    CHECK(line.ends_with("more=40"));
    CHECK(line.find("rule-" + std::to_string(GuardianPreservedTally::kMaxIds)) == std::string::npos);

    // Byte budget: a few maximum-length ids stop the list well short of kMaxIds, still counted.
    t.reset();
    CHECK(t.count() == 0);
    const std::string longid(yuzu::kGuardianLogIdMaxBytes, 'x');
    for (int i = 0; i < 40; ++i)
        t.note(longid);
    CHECK(t.count() == 40);
    CHECK(t.ids().size() < 40);
    CHECK(t.ids().size() * yuzu::kGuardianLogIdMaxBytes <= GuardianPreservedTally::kMaxIdBytes);
    CHECK(t.format().ends_with("more=" + std::to_string(40 - t.ids().size())));

    // Hostile id: newline, space, '=', ',' and ']' must not survive as separators.
    t.reset();
    t.note("a b\nGuardian: x=1,y]");
    const auto hostile = t.format();
    CHECK(hostile.find('\n') == std::string::npos);
    CHECK(t.ids().size() == 1);
    CHECK(t.ids()[0].find_first_of(" \n=,") == std::string::npos);
}

// -------------------------------------------------------------------------------------------------
// KV-9. The PRODUCTION configuration (prefer_spark=false): the rule rows follow the same shape on
//       the legacy detection path, which is the path that is live today. An identical full_sync
//       re-push writes and deletes nothing; omitting one rule deletes exactly that row.
//       Mutation: remove the equal-bytes skip in put_rule_locked (the writes CHECKs go red).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (9): on the legacy path an identical full_sync writes and deletes no rule "
          "row, and omitting one rule deletes exactly its row",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    constexpr int R = 4;
    KvRig k;
    k.r.prefer_spark = false;
    k.start();
    const auto s = make_kv_rules(k.r, R);
    const std::string bytes = push_bytes(s.rules, kGen);
    k.probe.clear();
    k.r.dispatch(bytes);
    REQUIRE(k.r.wait_generation(kGen));
    REQUIRE(k.probe.writes() == sorted(s.row_keys)); // premise: the probe sees every first write
    const auto rows_before = k.rule_rows();

    k.probe.clear();
    k.r.dispatch(bytes); // byte-identical re-push
    CHECK(k.probe.deletes().empty());
    CHECK(k.probe.writes().empty());
    CHECK(k.rule_rows() == rows_before);
    CHECK(k.r.engine->policy_generation() == kGen);

    const std::vector<gpb::GuaranteedStateRule> kept{s.rules[0], s.rules[1], s.rules[3]};
    k.probe.clear();
    k.r.dispatch(push_bytes(kept, kGen));
    CHECK(k.probe.deletes() == std::vector<std::string>{"rule:r2"});
    CHECK(k.probe.writes().empty());
    auto expected = rows_before;
    expected.erase("rule:r2");
    CHECK(k.rule_rows() == expected);
}

// -------------------------------------------------------------------------------------------------
// KV-10 (CH-2a). A rule-row write fails mid-push, after the absent-row sweep: the omitted rule's
//       row is gone and its rule is detached, the generation is held (memory and disk), the kept
//       rules KEEP ENFORCING their old content (AC-18 loss 5: the loop returned before reaching
//       them, so none was rebuilt), no preserved-line is recorded for the aborted push, and the
//       server's retry after the fault clears converges. The abort is a trigger on the engine's
//       own table (PRAGMA max_page_count does not reach the engine's connection).
//       Mutations (each goes red): pass an empty keep-set to detach_rules_except in apply_rules
//       (every kept rule is torn down, so the untouched-watch checks fail); skip the absent-row
//       delete (r7's row survives).
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (10): a failed rule-row write mid-push holds the generation, leaves the "
          "kept rules enforcing their old content and converges on the retry",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    constexpr int R = 10;
    constexpr std::uint64_t kNext = kGen + 1;
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, R);
    first_push(k, s, push_bytes(s.rules, kGen));
    const auto rows_before = k.rule_rows();
    const std::string line_before = k.r.engine->last_full_sync_preserved_line_for_test();

    k.probe.exec("CREATE TRIGGER yuzu_test_kv_veto_ins BEFORE INSERT ON kv_store"
                 " WHEN NEW.plugin = '__guardian__' AND NEW.key = 'rule:r3'"
                 " BEGIN SELECT RAISE(ABORT, 'yuzu_test injected rule write failure'); END;"
                 "CREATE TRIGGER yuzu_test_kv_veto_upd BEFORE UPDATE ON kv_store"
                 " WHEN NEW.plugin = '__guardian__' AND NEW.key = 'rule:r3'"
                 " BEGIN SELECT RAISE(ABORT, 'yuzu_test injected rule write failure'); END;");
    std::vector<gpb::GuaranteedStateRule> next;
    for (int i = 0; i < R; ++i) {
        if (i == 7)
            continue; // omitted
        next.push_back(i == 3 ? file_rule("r3", s.paths[3], "r3-renamed") : s.rules[i]);
    }
    const std::string bytes = push_bytes(next, kNext);
    k.probe.clear();
    (void)yuzu::agent::guardian_dispatch_push_bytes_for_test(*k.r.engine, bytes); // fails: r3
    CHECK(k.r.settle());

    CHECK(k.r.engine->policy_generation() == kGen); // HELD in memory...
    REQUIRE(k.r.persisted_generation().has_value());
    CHECK(*k.r.persisted_generation() == kGen); // ...and on disk
    CHECK(k.probe.deletes() == std::vector<std::string>{"rule:r7"}); // the sweep ran first
    CHECK_FALSE(k.r.kv->get(kKvNs, "rule:r7").has_value());
    CHECK(k.r.fm->unwatch_calls(s.spark_keys[7]) == 1); // the omitted rule is detached...
    for (int i = 0; i < R; ++i) {
        if (i != 7)
            check_untouched(*k.r.fm, "kept rule " + s.ids[i], s.spark_keys[i]); // ...kept ones are not
    }
    CHECK(k.r.engine->spark_armed_rule_count() == R - 1);
    auto expected = rows_before;
    expected.erase("rule:r7");
    CHECK(k.rule_rows() == expected); // r3's row still carries its OLD bytes
    CHECK(k.r.engine->last_full_sync_preserved_line_for_test() == line_before); // none recorded

    k.probe.exec("DROP TRIGGER yuzu_test_kv_veto_ins; DROP TRIGGER yuzu_test_kv_veto_upd;");
    k.r.dispatch(bytes); // the server's retry
    CHECK(k.r.settle());
    CHECK(k.r.wait_generation(kNext));
    const auto rows_after = k.rule_rows();
    CHECK(rows_after.size() == static_cast<std::size_t>(R - 1));
    CHECK(rows_after.count("rule:r7") == 0);
    CHECK(rows_after.at("rule:r3") != rows_before.at("rule:r3")); // the change landed
    check_rebuilt_once(*k.r.fm, "r3 (changed)", s.spark_keys[3]);
    for (int i = 0; i < R; ++i) {
        if (i != 7 && i != 3)
            check_untouched(*k.r.fm, "r" + std::to_string(i), s.spark_keys[i]);
    }
}

// -------------------------------------------------------------------------------------------------
// KV-11 (CH-2b). The crash window after the absent-row sweep and before any rewrite. The KV image
//       is FROZEN there by triggers (the delete of r7's row arms a flag, and every later write,
//       generation included, is vetoed), then the engine is closed and reopened on the same db.
//       Boot re-arms exactly the surviving rows (the omitted rule stays gone, the kept ones carry
//       their OLD content), the generation is the old one, and a re-push converges.
//       Mutation: skip the absent-row delete (the freeze never arms, the push completes before the
//       "crash", and the pre-restart row image check goes red). An empty keep-set stays green here:
//       the KV rows alone drive the boot re-arm, and the keep-set is pinned by KV-10 and 7b.
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A KV (11): a restart in the window after the absent-row sweep re-arms exactly "
          "the surviving rows at the old generation, and a re-push converges",
          "[spark][guardian][reconcile][4415prA][4415kv]") {
    constexpr int R = 6;
    constexpr std::uint64_t kNext = kGen + 1;
    KvRig k;
    k.start();
    const auto s = make_kv_rules(k.r, R);
    first_push(k, s, push_bytes(s.rules, kGen));
    const auto rows_before = k.rule_rows();

    k.probe.exec("CREATE TABLE yuzu_test_freeze(x INTEGER);"
                 "CREATE TRIGGER yuzu_test_freeze_arm AFTER DELETE ON kv_store"
                 " WHEN OLD.plugin = '__guardian__' AND OLD.key = 'rule:r4'"
                 " BEGIN INSERT INTO yuzu_test_freeze VALUES(1); END;"
                 "CREATE TRIGGER yuzu_test_freeze_ins BEFORE INSERT ON kv_store"
                 " WHEN NEW.plugin = '__guardian__' AND EXISTS(SELECT 1 FROM yuzu_test_freeze)"
                 " BEGIN SELECT RAISE(ABORT, 'yuzu_test frozen image'); END;"
                 "CREATE TRIGGER yuzu_test_freeze_upd BEFORE UPDATE ON kv_store"
                 " WHEN NEW.plugin = '__guardian__' AND EXISTS(SELECT 1 FROM yuzu_test_freeze)"
                 " BEGIN SELECT RAISE(ABORT, 'yuzu_test frozen image'); END;"
                 "CREATE TRIGGER yuzu_test_freeze_del BEFORE DELETE ON kv_store"
                 " WHEN OLD.plugin = '__guardian__' AND EXISTS(SELECT 1 FROM yuzu_test_freeze)"
                 " BEGIN SELECT RAISE(ABORT, 'yuzu_test frozen image'); END;");
    std::vector<gpb::GuaranteedStateRule> next;
    for (int i = 0; i < R; ++i) {
        if (i == 4)
            continue; // omitted
        next.push_back(i == 1 ? file_rule("r1", s.paths[1], "r1-renamed") : s.rules[i]);
    }
    const std::string bytes = push_bytes(next, kNext);
    (void)yuzu::agent::guardian_dispatch_push_bytes_for_test(*k.r.engine, bytes);
    CHECK(k.r.settle());
    k.r.close(); // the "crash"

    k.probe.exec("DROP TRIGGER yuzu_test_freeze_arm; DROP TRIGGER yuzu_test_freeze_ins;"
                 "DROP TRIGGER yuzu_test_freeze_upd; DROP TRIGGER yuzu_test_freeze_del;"
                 "DROP TABLE yuzu_test_freeze;");
    auto expected = rows_before;
    expected.erase("rule:r4");
    k.r.open();
    CHECK(k.rule_rows() == expected); // the image the crash left: r4 gone, r1 with OLD bytes
    REQUIRE(k.r.wait_armed(R - 1));
    CHECK(k.r.engine->policy_generation() == kGen);
    std::set<std::string> live;
    for (int i = 0; i < R; ++i)
        if (i != 4)
            live.insert(s.spark_keys[i]);
    CHECK(k.r.fm->watched_snapshot() == live);
    CHECK(k.r.fm->watch_calls(s.spark_keys[4]) == 0);

    k.r.dispatch(bytes); // the server re-pushes: it never saw the new generation acknowledged
    CHECK(k.r.settle());
    CHECK(k.r.wait_generation(kNext));
    const auto rows_after = k.rule_rows();
    CHECK(rows_after.size() == static_cast<std::size_t>(R - 1));
    CHECK(rows_after.at("rule:r1") != rows_before.at("rule:r1"));
    check_rebuilt_once(*k.r.fm, "r1 (changed)", s.spark_keys[1]);
    CHECK(k.r.fm->watched_snapshot() == live);
}

// -------------------------------------------------------------------------------------------------
// CH-5. A disable then a re-enable of a rule whose Disarm is stuck behind a hung call of the same
//       mechanism type queues [Disarm, Arm] on its key; once the disarm is abandoned (retained) an
//       identical push re-observes the queued Arm and drives nothing itself. The arm must still be
//       driven once the hang is released, within a 10 s cap here (the redrive cadence is about 5 s
//       in production). Observed: it is driven without waiting for the redrive: making
//       redrive_retained_disarms() return 0 leaves this case green, so it pins the outcome, not the
//       redrive mechanism, and the "waits for the redrive" wording of UP-8 is a worst-case bound.
// -------------------------------------------------------------------------------------------------
TEST_CASE("#4415 PR-A (CH-5): a re-enabled rule behind a retained disarm is driven once the hang "
          "is released, after an identical push re-observes it",
          "[spark][guardian][reconcile][4415prA]") {
    Rig r;
    r.open();
    const std::string svc_h = "yuzu-4415-ch5h", svc_x = "yuzu-4415-ch5x";
    const auto h = service_rule("h", svc_h);
    const auto x = service_rule("x", svc_x);
    auto x_off = x;
    x_off.set_enabled(false);
    const std::string hk = service_key(svc_h), xk = service_key(svc_x);

    r.dispatch(push_bytes({x}, kGen));
    REQUIRE(r.wait_armed(1));
    // x must be a Service rule (same mechanism type as h, so its calls queue behind the hang) and
    // must be SKIPPED by the next push so that h's arm takes the hang. On a host with no system
    // bus (macOS, a bare container) a Service rule reads Unknown and is rebuilt instead, so x's
    // own watch would take the hang: wait for x's first verdict and SKIP the case on such a host.
    {
        auto& rt = r.rt(); // once, outside the poll
        decltype(rt.status_for_rule("x")) first_verdict; // the snapshot that satisfied the poll
        REQUIRE(yuzu::test::spin_until(
            [&] {
                first_verdict = rt.status_for_rule("x");
                return first_verdict.has_value() &&
                       (first_verdict->last_compliant.has_value() || first_verdict->in_unknown);
            },
            30s));
        if (first_verdict->in_unknown)
            SKIP("this host reads the Service rule Unknown (no system bus), so the re-push rebuilds it instead of skipping it");
    }
    r.sm->hang_next_watch();
    r.dispatch(push_bytes({x, h}, kGen));
    REQUIRE(r.sm->wait_entered_hang(10s));
    REQUIRE(r.sm->hung_key() == hk);
    r.dispatch(push_bytes({h, x_off}, kGen)); // x disabled: its disarm waits behind the hung call
    REQUIRE(yuzu::test::spin_until([&] { return r.rt().claim_queue_depth_for_test(xk) == 1; }, 10s));
    r.dispatch(push_bytes({h, x}, kGen)); // re-enabled: the arm queues behind the disarm
    REQUIRE(yuzu::test::spin_until([&] { return r.rt().claim_queue_depth_for_test(xk) == 2; }, 10s));
    // h's hung arm becomes a retained wedge and x's stuck disarm a retained disarm.
    REQUIRE(r.rt().expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() + 2h) == 2);
    r.dispatch(push_bytes({h, x}, kGen)); // identical: re-observes, drives nothing itself
    CHECK(r.rt().claim_queue_depth_for_test(xk) == 2); // premise: [Disarm, Arm] still queued
    r.sm->release_hang();
    CHECK(yuzu::test::spin_until(
        [&] {
            r.engine->journal_maintenance_tick();
            return r.rt().claim_queue_depth_for_test(xk) == 0 && r.sm->watched_snapshot().count(xk) == 1;
        },
        10s));
    CHECK(r.sm->watched_snapshot().count(xk) == 1); // x is enforcing again
}

// -------------------------------------------------------------------------------------------------
// #5547 - a delta push that omits an unresolved rule must not drop that rule's retry obligation.
//
// Before the fix GuardianArmAckLedger::begin_application() replaced the open application
// wholesale, so a delta (additive, no teardown) that did not name a rule with a still-pending arm,
// a retained wedge, a drained failure or a synchronous failure opened an application that knew
// nothing of it, was clean, and acknowledged the generation while the rule was unarmed. The cases
// below drive the REAL engine, runtime and ledger and assert EFFECT SETS: the held generation (in
// memory and on disk), arm_stats(), and whether apply_rules reconciled a rule (the attach probe).
// None of them reads ack_failed_receipt_count_for_test() alone as the proof of tracking: it reads
// 0 both with and without the fix for a receipt that is merely pending.
//
// FALSE-GREEN TRAPS avoided here: a synchronous refusal in place of a hang (the refusal is not
// the unresolved arm), the repairing full_sync pushed BEFORE the hold is asserted, and a default
// generation-zero push (it can never advance anything).
// -------------------------------------------------------------------------------------------------

// CH-7 (flipped). An arm re-observed by an identical full_sync, then followed by a DELTA that does
// not name the rule, which finally REFUSES. A delta has no teardown, so nothing withdraws the
// rule; the open application's pending receipt for it is CARRIED into the delta's application, so
// the refusal is counted, the generation is never acknowledged, and the next full_sync repairs it.
// Mutations: begin_delta_application replaced by begin_full_application (nothing carried); the
// carry loop for `pending` deleted.
TEST_CASE("#4415 PR-A (CH-7, #5547): a re-observed arm that a delta leaves unnamed and that later "
          "refuses holds the generation, and the next full_sync repairs it",
          "[spark][guardian][reconcile][4415prA][5547]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0");
    const std::string svc = "yuzu-4415-ch7";
    const std::string hk = service_key(svc);
    const auto h = service_rule("h", svc);
    const auto s0 = file_rule("s0", p0);
    const std::string bytes = push_bytes({h, s0}, kGen);

    r.sm->hang_next_watch();
    r.dispatch(bytes);
    REQUIRE(r.sm->wait_entered_hang(10s));
    REQUIRE(r.wait_armed(1));
    r.dispatch(bytes); // identical full_sync: h's in-flight arm is re-observed
    CHECK(r.sm->watch_calls(hk) == 1);
    REQUIRE(r.engine->policy_generation() != kGen); // premise: not yet acknowledged
    r.dispatch(push_bytes({s0}, kGen, /*full_sync=*/false)); // a delta that does not name h

    // The delta did not acknowledge anything, and h's still-pending receipt is tracked by the
    // application the delta opened (a delta without the carry opens one with pending == 0).
    r.require_generation_held();
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 1);
        CHECK(s->failed == 0);
    }

    r.sm->set_late_refuse();
    r.sm->release_hang();
    await_late_result_landed(r, hk);
    drain_until_idle(r);
    tick_n(r);
    CHECK(r.engine->spark_armed_rule_count() == 1); // h is not armed
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->pending == 0);
        CHECK(s->failed == 1); // the refusal is counted by the carried receipt
    }
    r.require_generation_held(); // the loss CH-7 used to pin: the generation was acknowledged here

    r.dispatch(bytes); // the next full_sync repairs it
    CHECK(r.settle());
    CHECK(r.sm->watch_calls(hk) == 2);
    CHECK(r.engine->spark_armed_rule_count() == 2);
    check_untouched(*r.fm, "s0 (healthy sibling)", file_key(p0));
    CHECK(r.wait_generation(kGen)); // acknowledged only now
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);
}

// AC 1 (wedge variant). A retained wedge survives a delta that omits it: the generation stays held,
// an identical delta re-push is Suppressed (the wedge is outstanding), and when the hung arm finally
// succeeds the adopted rule is acknowledged without a second arm.
// Mutations: the carry loop for `failed_receipts` deleted (ack_failed_receipt_count_for_test()
// reads 0 and the delta acknowledges); begin_delta_application replaced by begin_full_application.
TEST_CASE("#5547 AC 1: a retained wedge survives a delta that omits it, the identical delta is "
          "suppressed, and the late success is adopted and then acknowledged",
          "[spark][guardian][reconcile][5547]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0");
    const std::string svc = "yuzu-5547-ac1";
    const std::string hk = service_key(svc);
    const auto s0 = file_rule("s0", p0);
    auto probe = install_attach_probe(r);

    r.sm->hang_next_watch();
    r.dispatch(push_bytes({service_rule("h", svc), s0}, kGen));
    REQUIRE(park_and_wedge(r, *r.sm, /*expected_armed=*/1) == hk);
    REQUIRE(r.wait_compliant({"s0"}));

    const std::string delta = push_bytes({s0}, kGen, /*full_sync=*/false);
    r.dispatch(delta);
    CHECK(r.engine->ack_failed_receipt_count_for_test() == 1); // h's retained wedge was carried
    r.engine->journal_maintenance_tick();
    r.require_generation_held();
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
        CHECK(s->pending == 0);
    }

    // An identical re-push is a Suppress: apply_rules does not reconcile s0 again.
    const int attaches = probe->count("s0");
    REQUIRE(attaches >= 2); // the full_sync and the first delta
    r.dispatch(delta);
    CHECK(probe->count("s0") == attaches);
    r.require_generation_held();

    // The hang returns a success the runtime adopts (h is still desired): acknowledged, no re-arm.
    r.sm->release_hang();
    await_late_result_landed(r, hk);
    CHECK(r.wait_generation(kGen));
    CHECK(r.sm->watch_calls(hk) == 1);
    CHECK(r.engine->spark_armed_rule_count() == 2);
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);
}

// A synchronous refusal (ReconcileOutcome::Failed) is attributed to its rule and survives a delta
// that omits the rule. The refusal is real: x targets the key a DIFFERENT rule's wedge holds.
// Sequence: wedge h; delta {x} (x refused); the hang returns a refusal; delta {h} re-arms h cleanly
// (x is carried by it); the generation is STILL held, now by x's synchronous failure alone; an
// identical delta is a Reapply; a delta naming x clears it. The last step also pins that the
// failure was recorded against x and not as an application-wide latch (which would be inherited by
// every later application and never cleared by a delta).
// Mutations: the Failed-site note_sync_failure deleted (the {h} delta acknowledges); the tail latch
// keyed on the TOTAL failure count instead of the unattributed subset (the {x} delta never clears).
TEST_CASE("#5547: a synchronous per-rule refusal survives a delta that omits the rule, forces a "
          "Reapply, and is cleared only by a push that names the rule",
          "[spark][guardian][reconcile][5547]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0");
    const std::string svc = "yuzu-5547-sx";
    const std::string hk = service_key(svc);
    const auto h = service_rule("h", svc);
    const auto x = service_rule("x", svc); // same service, so the same key as h
    auto probe = install_attach_probe(r);

    r.sm->hang_next_watch();
    r.dispatch(push_bytes({h, file_rule("s0", p0)}, kGen));
    REQUIRE(park_and_wedge(r, *r.sm, /*expected_armed=*/1) == hk);

    const auto refusals = r.rt().wedged_refusals();
    r.dispatch(push_bytes({x}, kGen, /*full_sync=*/false));
    REQUIRE(r.rt().wedged_refusals() == refusals + 1); // premise: x was refused synchronously
    REQUIRE(r.sm->watch_calls(hk) == 1);               // and nothing re-armed the key

    // The hung call returns a refusal: h's wedge pops. Drain it (it settles to an ordinary failure).
    r.sm->set_late_refuse();
    r.sm->release_hang();
    await_late_result_landed(r, hk);
    tick_n(r);
    r.require_generation_held();

    // A delta naming h re-arms it; x is omitted and its synchronous failure is carried.
    r.dispatch(push_bytes({h}, kGen, /*full_sync=*/false));
    REQUIRE(yuzu::test::spin_until([&] { return r.engine->spark_armed_rule_count() == 2; }, 10s));
    drain_until_idle(r);
    tick_n(r);
    CHECK(r.sm->watch_calls(hk) == 2);
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 0); // synchronous failures are outside the accepted-receipt gauge
        CHECK(s->pending == 0);
    }
    r.require_generation_held(); // held by x's failure alone

    const std::string delta_h = push_bytes({h}, kGen, /*full_sync=*/false);
    const int before = probe->count("h");
    r.dispatch(delta_h); // identical to the delta the open application came from
    CHECK(probe->count("h") == before + 1); // a Reapply, not a Suppress
    r.require_generation_held();

    // x joins h's now-healthy key; naming it clears exactly its own failure.
    r.dispatch(push_bytes({x}, kGen, /*full_sync=*/false));
    CHECK(r.wait_generation(kGen));
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kGen);
}

// The per-rule THROW site of the same obligation (reconcile throws after the attach).
// Mutations: the throw-site note_sync_failure deleted.
TEST_CASE("#5547: a per-rule reconcile throw survives a delta that omits the rule and is cleared by "
          "naming it",
          "[spark][guardian][reconcile][5547]") {
    Rig r;
    r.open();
    const auto pa = r.make_file("a"), pb = r.make_file("b");
    const auto a = file_rule("a", pa), b = file_rule("b", pb);
    auto probe = install_attach_probe(r);

    probe->throw_once("a");
    r.dispatch(push_bytes({a, b}, kGen, /*full_sync=*/false));
    tick_n(r);
    r.require_generation_held();

    const std::string delta_b = push_bytes({b}, kGen, /*full_sync=*/false);
    r.dispatch(delta_b); // omits a
    tick_n(r);
    r.require_generation_held();

    const int before = probe->count("b");
    r.dispatch(delta_b); // identical: a carried synchronous failure forces a Reapply
    CHECK(probe->count("b") == before + 1);
    r.require_generation_held();

    r.dispatch(push_bytes({a}, kGen, /*full_sync=*/false)); // names a; it no longer throws
    CHECK(r.wait_generation(kGen));
}

// A wedge whose compensating teardown is outstanding (CompensationPending) is carried too. The
// withdrawal is injected at the runtime: the production routes that withdraw a rule are a push that
// NAMES it (its entry is dropped by design) or a full_sync (which carries nothing), neither of
// which leaves a carried entry to turn compensation-pending.
// Mutations: the carry loop for `failed_receipts` deleted.
TEST_CASE("#5547: a wedge that turns compensation-pending after a delta omitted it stays held, "
          "suppresses the identical delta, then forces a Reapply once the teardown pops it",
          "[spark][guardian][reconcile][5547]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0");
    const std::string svc = "yuzu-5547-comp";
    const std::string hk = service_key(svc);
    const auto s0 = file_rule("s0", p0);
    auto probe = install_attach_probe(r);

    r.sm->hang_next_watch();
    r.dispatch(push_bytes({service_rule("h", svc), s0}, kGen));
    REQUIRE(park_and_wedge(r, *r.sm, /*expected_armed=*/1) == hk);

    const std::string delta = push_bytes({s0}, kGen, /*full_sync=*/false);
    r.dispatch(delta); // omits h: its retained wedge is carried
    REQUIRE(r.engine->ack_failed_receipt_count_for_test() == 1);

    // h is withdrawn while the hung arm is outstanding; the arm then returns, is not adopted, and
    // its compensating unwatch parks.
    r.sm->hang_next_unwatch();
    r.rt().detach_rule("h");
    r.sm->release_hang();
    REQUIRE(r.sm->wait_entered_unwatch(10s));
    tick_n(r);
    CHECK(r.engine->ack_failed_receipt_count_for_test() == 1); // still retained: compensation outstanding
    r.require_generation_held();

    const int attaches = probe->count("s0");
    r.dispatch(delta);
    CHECK(probe->count("s0") == attaches); // Suppressed while the teardown is outstanding
    r.require_generation_held();

    // The teardown finishes and pops the claim: the wedge settles to an ordinary failure, which is
    // still counted (arm_stats) and still holds; the identical delta is now a Reapply.
    r.sm->release_unwatch();
    REQUIRE(yuzu::test::spin_until([&] { return r.rt().claim_queue_depth_for_test(hk) == 0; }, 10s));
    drain_until_idle(r);
    tick_n(r);
    CHECK(r.engine->ack_failed_receipt_count_for_test() == 0);
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1);
    }
    r.require_generation_held();
    r.dispatch(delta);
    CHECK(probe->count("s0") == attaches + 1);
    r.require_generation_held();

    // h is not in the desired set any more: a full_sync without it repairs.
    r.dispatch(push_bytes({s0}, kGen));
    CHECK(r.wait_generation(kGen));
}

// Option A (flip-gate AC-15, deliberately NOT changed by #5547). A Wedged receipt that is drained
// after its claim already popped (here: the late success was adopted before the first drain) has
// neither wedge flag, so it is counted as an ordinary failure and its receipt is discarded. That
// false failure used to cost one avoidable Reapply; it is now CARRIED, so it holds the generation
// across omitting deltas until a full_sync or a push that names the rule. This case pins that
// documented behaviour, not a no-hold outcome.
// Mutations: the carry loop for `failed_ids` deleted.
TEST_CASE("#5547 (option A): a wedge drained after its claim popped is a carried false failure that "
          "only a full_sync or a naming push clears",
          "[spark][guardian][reconcile][5547]") {
    Rig r;
    r.open();
    const auto p0 = r.make_file("s0");
    const std::string svc = "yuzu-5547-optA";
    const std::string hk = service_key(svc);
    const auto h = service_rule("h", svc);
    const auto s0 = file_rule("s0", p0);
    auto probe = install_attach_probe(r);

    r.sm->hang_next_watch();
    r.dispatch(push_bytes({h, s0}, kGen));
    REQUIRE(r.sm->wait_entered_hang(30s));
    REQUIRE(yuzu::test::spin_until([&] { return r.engine->spark_armed_rule_count() == 1; }, 10s));
    // NO tick from here until the claim has popped: the first drain must see it already gone.
    REQUIRE(r.rt().expire_overdue_claims_at_for_test(std::chrono::steady_clock::now() + 2h) == 1);
    r.sm->release_hang(); // a late success; h is still desired, so it is adopted
    await_late_result_landed(r, hk);
    REQUIRE(r.engine->spark_armed_rule_count() == 2); // h IS armed
    drain_until_idle(r);
    REQUIRE(r.engine->ack_failed_receipt_count_for_test() == 0); // not retained: the premise of AC-15
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        REQUIRE(s->failed == 1); // ... yet counted
    }
    r.require_generation_held();

    const std::string delta = push_bytes({s0}, kGen, /*full_sync=*/false);
    r.dispatch(delta); // omits h
    tick_n(r);
    r.require_generation_held();
    {
        const auto s = r.engine->arm_stats();
        REQUIRE(s.has_value());
        CHECK(s->failed == 1); // sustained across the omitting delta (it used to reset to 0)
    }
    const int before = probe->count("s0");
    r.dispatch(delta);
    CHECK(probe->count("s0") == before + 1); // a failure with no wedge to protect: Reapply every time
    r.require_generation_held();

    // The skip below needs the Service rule to read Known, not Unknown. A host with no system bus
    // or no service reader (a bare container, macOS) reads it Unknown, so the full_sync rebuilds
    // it instead; the watch and unwatch counts then say nothing about the carry, and only the
    // generation is checked there, with a WARN so the run says it skipped them. The poll is
    // bounded and its result unused (nothing here REQUIREs a verdict, so the bound only limits
    // the wait): a verdict that never settles keeps the checks on and a slow read fails visibly.
    bool h_reads_unknown = false;
    {
        auto& rt = r.rt(); // once, outside the poll
        decltype(rt.status_for_rule("h")) verdict;
        (void)yuzu::test::spin_until(
            [&] {
                verdict = rt.status_for_rule("h");
                return verdict.has_value() &&
                       (verdict->last_compliant.has_value() || verdict->in_unknown);
            },
            5s);
        h_reads_unknown = verdict.has_value() && verdict->in_unknown;
    }
    r.dispatch(push_bytes({h, s0}, kGen)); // a full_sync names h: healthy and unchanged, skipped
    CHECK(r.wait_generation(kGen));
    if (h_reads_unknown) {
        WARN("the Service rule h read Unknown on this host, so the full_sync rebuilt it: the skip "
             "checks (watch_calls == 1, unwatch_calls == 0) were not run");
    } else {
        CHECK(r.sm->watch_calls(hk) == 1);
        CHECK(r.sm->unwatch_calls(hk) == 0);
    }
}

// Astra's scenario (plan section 2). The unattributed debt of a failed full_sync is inherited by
// every later application. A later full_sync that sweeps fine but fails to reconcile A is NOT a
// successful authoritative full sync, so the inherited debt survives it, and a delta naming A can
// clear only A. Only a clean full_sync discharges the debt, and it acknowledges in that same call.
// The unattributed debt is a teardown throw (the runtime's detach fault).
// Mutations: the discharge conditioned on full_sync() alone (the second full_sync clears the debt,
// so the delta naming A acknowledges); the discharge deleted (the last full_sync never clears it);
// begin_full_application dropping the inherited latch (the debt is forgotten at the second step).
TEST_CASE("#5547: an inherited latch survives a full_sync that fails to reconcile a rule, and a delta "
          "naming that rule clears only the rule",
          "[spark][guardian][reconcile][5547]") {
    constexpr std::uint64_t kNext = kGen + 1;
    Rig r;
    r.open();
    const auto p1 = r.make_file("r1"), pa = r.make_file("a"), px = r.make_file("x");
    const auto r1 = file_rule("r1", p1), a = file_rule("a", pa), x = file_rule("x", px);
    auto probe = install_attach_probe(r);

    r.dispatch(push_bytes({r1}, kGen));
    REQUIRE(r.wait_armed(1));
    REQUIRE(r.wait_generation(kGen));

    // Step 1: a full_sync that omits r1 and whose teardown of r1 throws. Unattributed failure.
    r.rt().set_detach_fault_for_test(true);
    r.dispatch(push_bytes({x}, kNext));
    REQUIRE(r.wait_armed(2)); // r1 survived the failed teardown; x armed
    tick_n(r);
    REQUIRE(r.engine->policy_generation() == kGen); // premise: held below kNext
    REQUIRE(r.persisted_generation().value_or(0) == kGen);

    // Step 2: a full_sync that sweeps fine but whose reconcile of a throws.
    probe->throw_once("a");
    r.dispatch(push_bytes({x, a}, kNext));
    tick_n(r);
    CHECK(r.engine->policy_generation() == kGen);

    // Step 3: a delta naming a (no longer throwing) clears a's own failure but not the debt.
    r.dispatch(push_bytes({a}, kNext, /*full_sync=*/false));
    tick_n(r);
    CHECK(r.engine->policy_generation() == kGen);
    CHECK(r.persisted_generation().value_or(0) == kGen);

    // Step 4: a clean full_sync discharges the debt and acknowledges in that same call.
    r.dispatch(push_bytes({x, a}, kNext));
    CHECK(r.engine->policy_generation() == kNext); // no tick between the dispatch and this read
    REQUIRE(r.persisted_generation().has_value());
    CHECK(*r.persisted_generation() == kNext);
}
