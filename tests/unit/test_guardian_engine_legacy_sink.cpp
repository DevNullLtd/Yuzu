/**
 * test_guardian_engine_legacy_sink.cpp — #4783 fix proof: the legacy Guardian
 * sink call (GuardianEngine::emit_guard_event -> EventSink -> AgentImpl's gRPC
 * Write() on the Subscribe stream) no longer runs on the guard's own detection
 * thread. Before this fix, a stalled (not dead) gRPC stream blocked that
 * thread indefinitely: a legacy guard worker parked mid-report could not
 * notice a subsequent real endpoint transition until the stream unblocked,
 * and GuardianEngine::stop() / a rule-dropping apply_rules() both joined
 * guard threads under mtx_, so either could hang the whole engine (and, in
 * production, the agent's shutdown or rule-management path) on one wedged
 * sender.
 *
 * Commit 3 of the delivery plan routes emit_guard_event() through
 * GuardianLegacySinkExecutor (guardian_legacy_sink_executor.hpp, added in
 * commit 2): the guard's own thread only ENQUEUES and returns immediately — a
 * blocking (or merely slow) network send now runs on the executor's own
 * DETACHED worker, never on the thread that detected the drift. These cases
 * were committed RED (commit 1, tagged [!mayfail]) against the pre-fix engine
 * and are GREEN against the fix landed here — see:
 *   ~/.claude/plans/4783-legacy-guard-sink-blocking-PLAN-v2.md, S4 (T2) and S5
 *   (commits 1 and 3).
 *
 * Every operation that could hang under the (now-fixed) hazard still runs on
 * a helper thread behind `run_bounded()` below, which always releases the
 * blocking sink's latch and joins the helper before returning — so a
 * regression here is a clean, reported CHECK failure, never a wedged test
 * binary. `run_bounded()` aborts the WHOLE process (spdlog::critical +
 * std::abort()) only if the helper fails to recover even after the latch is
 * released, i.e. a genuinely different hazard than the one this file exists
 * to guard against. Every case ALSO physically retires the legacy-sink
 * executor's detached worker before its locals destruct
 * (`require_legacy_sink_retired()` below, via a `ScopeExit` so it runs on
 * every exit path including a failed REQUIRE/CHECK): `BlockingSink`/
 * `CountingSink` capture `this` by raw pointer, and delivery is now
 * asynchronous, so nothing may still reference either after this test
 * function's locals start unwinding.
 *
 * Local fixture: LegacySinkFixture below is a minimal, INDEPENDENT analogue
 * of test_guardian_engine.cpp's GuardianFixture — that fixture lives inside
 * an anonymous namespace in a different translation unit and cannot be
 * reused from here (see this file's own PLAN section, and the plan doc's
 * T2 header note). guard_*.{hpp,cpp} are untouched by this commit — only
 * guardian_engine.{hpp,cpp} and agent.cpp (see the plan's commit-3 scope).
 *
 * CH-1(a)/(b) and CH-2 arm a REAL FileGuard, which is Windows-only for the
 * MVP (FileGuard::start() is a no-op returning false off Windows —
 * guard_file.cpp) — those cases (plus the Windows-only shutdown-path
 * regression added in commit 3) are #ifdef _WIN32 and simply do not exist in
 * a non-Windows build. CH-1 L1 and the two cross-platform commit-3 additions
 * (FIFO preservation, stop()-discards-backlog) drive the synchronous half of
 * emit_guard_event() directly via guardian_emit_drift_for_test(), with no
 * real guard thread involved, and are the only cases exercised on this
 * (Linux) build.
 */

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "guaranteed_state.pb.h"
#include "guardian_legacy_sink_executor.hpp" // LegacySendOutcome, legacy_sink_executor_for_test()'s type

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace gpb = ::yuzu::guardian::v1;
using yuzu::agent::GuardianEngine;
using yuzu::agent::KvStore;

namespace {

std::string uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME")) return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

// Same salted-path convention as test_guardian_engine.cpp's unique_kv_path()
// (own copy — different TU, different anonymous namespace, deliberately not
// shared; see this file's header comment). A distinct base directory name
// ("..._legacy_sink") keeps the two files' fixtures from ever colliding on
// disk even though both run in the same suite.
fs::path unique_kv_path() {
    const auto dir = fs::temp_directory_path() / ("yuzu_test_guardian_legacy_sink" + uid_suffix());
    return dir / (yuzu::test::unique_temp_path("legacy_sink_").filename().string() + ".db");
}

/// Minimal local analogue of test_guardian_engine.cpp's GuardianFixture:
/// KvStore + GuardianEngine + start_local(), plus the two rule/push builders
/// this file's cases need. NOT a reuse of that fixture (it is private to its
/// own TU) — see this file's header comment.
struct LegacySinkFixture {
    // FIRST member, same rationale as GuardianFixture's own db_: the
    // destructor fires even if downstream construction throws, so a partial
    // REQUIRE failure below does not leak the .db/-wal/-shm trio.
    yuzu::test::TempDbFile db_{unique_kv_path()};
    std::unique_ptr<KvStore> kv;
    std::unique_ptr<GuardianEngine> engine;

    /// `legacy_sink_max_events_for_test` (#4783 commit 4): 0 (default) leaves the
    /// executor's default Config in place, matching every case in this file before
    /// commit 4; non-zero overrides GuardianLegacySinkExecutor::Config::max_events
    /// BEFORE start_local() runs (GuardianEngine::set_legacy_sink_max_events_for_test's
    /// own precondition) so a test can force a deterministic RefusedCapacity without
    /// pushing thousands of events. `prefer_spark` (#4783 commit 4): defaults false,
    /// matching every prior case (the legacy IGuard path is the sole live production
    /// path, routed-concerns.md Spark row) — a test can pass true to prove
    /// legacy_sink_kick()'s gap-repair path runs regardless of the flip, which is the
    /// whole reason it does not share journal_maintenance_tick()'s prefer_spark_ gate.
    explicit LegacySinkFixture(std::size_t legacy_sink_max_events_for_test = 0,
                               bool prefer_spark = false) {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));
        engine =
            std::make_unique<GuardianEngine>(kv.get(), "agent-legacy-sink-test", prefer_spark);
        if (legacy_sink_max_events_for_test != 0)
            engine->set_legacy_sink_max_events_for_test(legacy_sink_max_events_for_test);
        REQUIRE(engine->start_local().has_value());
    }

    static gpb::GuaranteedStateRule make_rule(const std::string& id) {
        gpb::GuaranteedStateRule r;
        r.set_rule_id(id);
        r.set_name(id);
        r.set_yaml_source("name: " + id + "\n");
        r.set_version(1);
        r.set_enabled(true);
        r.set_enforcement_mode("enforce");
        return r;
    }

    /// A file-exists rule (file-change spark + file-exists assertion, B1):
    /// drift when presence != expect_present. `expected` is left at its
    /// default ("present" — the params map key is simply omitted), so drift
    /// means "the file is missing". FileGuard::start() is a no-op off
    /// Windows for the MVP (guard_file.cpp) — only the #ifdef _WIN32 cases in
    /// this file actually arm one; mirrors GuardianFixture::make_file_hash_rule's
    /// own doc note in test_guardian_engine.cpp.
    static gpb::GuaranteedStateRule make_file_exists_rule(const std::string& id,
                                                          const std::string& path) {
        gpb::GuaranteedStateRule r = make_rule(id);
        r.mutable_spark()->set_type("file-change");
        auto* a = r.mutable_assertion();
        a->set_type("file-exists");
        (*a->mutable_params())["path"] = path;
        return r;
    }

    /// Builds the push and dispatches it via
    /// guardian_dispatch_push_bytes_for_test — never a direct apply_rules(push)
    /// call — so the rule's params Map above is both POPULATED and READ inside
    /// the agent-core DLL/so (the #501 cross-image abseil hash-seed split;
    /// GuardianFixture in test_guardian_engine.cpp documents the identical
    /// requirement for any rule carrying assertion params).
    yuzu::agent::GuardianDispatchResult make_push(std::vector<gpb::GuaranteedStateRule> rules,
                                                  bool full_sync) {
        gpb::GuaranteedStatePush push;
        push.set_full_sync(full_sync);
        for (auto& r : rules)
            *push.add_rules() = std::move(r);
        return yuzu::agent::guardian_dispatch_push_bytes_for_test(*engine, push.SerializeAsString());
    }
};

/// Non-blocking recording EventSink used for the arm barrier (every
/// #ifdef _WIN32 case below): waits for a specific rule's arm-time
/// `guard.compliant` edge to arrive, BY IDENTITY, before the test swaps in a
/// BlockingSink — FileGuard::start() spawns its watch thread asynchronously
/// (guard_file.cpp) and the first eval is not synchronous with apply_rules()
/// returning, so without this wait the arm-time edge and the blocking sink
/// installed right after it can race.
class CountingSink {
public:
    yuzu::agent::GuardianEngine::EventSink sink() {
        return [this](const gpb::GuaranteedStateEvent& ev) {
            std::lock_guard lk(mu_);
            events_.emplace_back(ev.rule_id(), ev.event_type());
            return yuzu::agent::LegacySendOutcome::Sent;
        };
    }

    bool wait_for(const std::string& rule_id, const std::string& event_type,
                  std::chrono::milliseconds bound) {
        return yuzu::test::spin_until(
            [this, rule_id, event_type] {
                std::lock_guard lk(mu_);
                return std::any_of(events_.begin(), events_.end(), [&](const auto& e) {
                    return e.first == rule_id && e.second == event_type;
                });
            },
            bound);
    }

private:
    mutable std::mutex mu_;
    std::vector<std::pair<std::string, std::string>> events_;
};

/// The blocking EventSink at the center of every case below — this is the
/// #4783 hazard's stand-in: the FIRST call parks the calling thread (the
/// legacy-sink executor's own detached worker, #4783 — never a real guard
/// thread any more) until release() runs on a DIFFERENT thread, standing in
/// for a stalled (not dead) gRPC stream's synchronous Write(). Every call —
/// including ones that arrive after release() — records
/// (rule_id, event_type, event_id) in arrival order under the same mutex, so
/// order()/event_ids() are ground truth for the ordering assertions.
/// entered() lets a caller wait until a call is GENUINELY parked before doing
/// a racy follow-up (deleting/recreating the watched file, or offering a
/// second event) instead of guessing with a fixed sleep.
class BlockingSink {
public:
    yuzu::agent::GuardianEngine::EventSink sink() {
        return [this](const gpb::GuaranteedStateEvent& ev) { return on_event(ev); };
    }

    /// One-shot latch: unblocks every call parked in on_event() now and
    /// forever after. Safe (and a no-op) to call more than once — every
    /// cleanup path below (require_legacy_sink_retired / run_bounded's own
    /// ScopeExit) calls it unconditionally.
    void release() {
        std::lock_guard lk(mu_);
        released_ = true;
        cv_.notify_all();
    }

    std::size_t entered() const {
        std::lock_guard lk(mu_);
        return entered_;
    }

    std::size_t delivered() const {
        std::lock_guard lk(mu_);
        return order_.size();
    }

    std::vector<std::pair<std::string, std::string>> order() const {
        std::lock_guard lk(mu_);
        return order_;
    }

    /// event_id per delivery, in the SAME arrival order as order() above
    /// (#4783 commit 3 — the FIFO-identity proof the A,A,A case below needs on
    /// top of type ordering).
    std::vector<std::string> event_ids() const {
        std::lock_guard lk(mu_);
        return event_ids_;
    }

private:
    yuzu::agent::LegacySendOutcome on_event(const gpb::GuaranteedStateEvent& ev) {
        std::unique_lock lk(mu_);
        ++entered_;
        cv_.notify_all();
        cv_.wait(lk, [this] { return released_; }); // the hazard stand-in: parks here
        order_.emplace_back(ev.rule_id(), ev.event_type());
        event_ids_.push_back(ev.event_id());
        return yuzu::agent::LegacySendOutcome::Sent;
    }

    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool released_{false};
    std::size_t entered_{0};
    std::vector<std::pair<std::string, std::string>> order_;
    std::vector<std::string> event_ids_;
};

/// Cleanup used by every case below (plan hygiene rules 2/3/6): idempotently
/// release the blocking sink's latch, then REQUIRE the legacy-sink executor's
/// worker(s) to physically retire within 30s before returning.
/// `CountingSink`/`BlockingSink` capture `this` by raw pointer and delivery is
/// now asynchronous (the executor's own detached worker, #4783), so nothing
/// captured by either may still be reachable by a worker once this function's
/// CALLER's locals start destructing — aborts the WHOLE process
/// (spdlog::critical + std::abort()), the same posture run_bounded() takes
/// for a different failure mode, rather than let unwind proceed into a
/// captured-`this` use-after-free. Declare the ScopeExit that calls this
/// AFTER every local it must outlive (fixture, sinks, TempDir, ...) so its
/// destructor — which runs FIRST on unwind — retires the worker before any
/// of them tears down.
void require_legacy_sink_retired(GuardianEngine& engine, BlockingSink& sink, const char* what) {
    sink.release();
    if (!engine.retire_legacy_sink_workers_for_test(std::chrono::seconds{30})) {
        spdlog::critical(
            "legacy_sink cleanup: '{}' - executor worker(s) did not retire even after "
            "releasing the blocking sink latch (30s) - aborting rather than letting scope "
            "unwind into a captured-this use-after-free",
            what);
        std::abort();
    }
}

/// Runs `op` on a helper thread and returns whether it completed within
/// `bound`. Whatever the outcome, by the time this function returns the
/// helper has ALREADY been joined: its cleanup unconditionally releases
/// `sink`'s latch (idempotent) and waits — generously, 30s — for the op to
/// finish before joining it (hygiene rule 2/3 from the #4783 plan, folded in
/// here so every call site gets it for free instead of hand-rolling a
/// ScopeExit per test). NOTE: releasing the latch here unblocks the
/// EXECUTOR's detached worker, not `op` itself in every case (e.g. `op` may
/// be `stop()`, which does not wait on that worker at all) — this function
/// only proves `op` completed within `bound`; it does NOT prove delivery
/// completed, since delivery runs on a separate, un-joined thread. Callers
/// that need to observe delivery must flush/retire afterward (see
/// flush_legacy_sink_for_test / retire_legacy_sink_workers_for_test below).
/// A genuine post-release hang — something OTHER than a network-shaped
/// stall this file exists to reproduce — aborts the whole binary with a
/// diagnostic rather than wedging the rest of the suite (a crash with a
/// clear message beats a silent meson kill).
///
/// Never itself polls any GuardianEngine accessor: the caller does that only
/// after this function has returned, i.e. only once the operation is known
/// to have completed and mtx_ is known to be free (hygiene rule 4).
template <typename F>
bool run_bounded(F&& op, std::chrono::milliseconds bound, BlockingSink& sink, const char* what) {
    std::atomic<bool> done{false};
    std::thread th([&op, &done] {
        op();
        done.store(true, std::memory_order_release);
    });
    yuzu::test::ScopeExit cleanup([&] {
        sink.release();
        if (!done.load(std::memory_order_acquire) &&
            !yuzu::test::spin_until([&done] { return done.load(std::memory_order_acquire); },
                                    std::chrono::seconds{30})) {
            spdlog::critical(
                "legacy_sink watchdog: '{}' never completed even after releasing the "
                "blocking sink latch - aborting rather than hanging the whole test "
                "binary (#4783)",
                what);
            std::abort();
        }
        th.join();
    });
    return yuzu::test::spin_until([&done] { return done.load(std::memory_order_acquire); }, bound);
}

/// #4783 Gate 8 re-review: a one-shot pause latch for
/// legacy_sink_persist_race_hook_for_test_ - same entered()/release() shape as
/// BlockingSink above, but standing in for GuardianEngine's own
/// legacy_sink_persist_mu_ persist-race seam instead of an EventSink.
/// wait_entered() lets the orchestrating thread block deterministically until
/// the hook has actually fired (and, on the fixed engine, until
/// legacy_sink_persist_mu_ is therefore actually held by the parked thread)
/// instead of guessing with a fixed sleep.
class PersistRaceLatch {
public:
    void hook() {
        std::unique_lock lk(mu_);
        entered_ = true;
        cv_.notify_all();
        cv_.wait(lk, [this] { return released_; }); // parks here, holding whatever the
                                                     // caller held when it invoked us
    }

    bool wait_entered(std::chrono::milliseconds bound) {
        return yuzu::test::spin_until(
            [this] {
                std::lock_guard lk(mu_);
                return entered_;
            },
            bound);
    }

    /// One-shot: safe (and a no-op) to call more than once, same as
    /// BlockingSink::release() above - every cleanup path below calls it
    /// unconditionally.
    void release() {
        std::lock_guard lk(mu_);
        released_ = true;
        cv_.notify_all();
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool entered_{false};
    bool released_{false};
};

} // namespace

// ── #4783 governance follow-up: legacy_sink_dropped_unwired() ───────────────

TEST_CASE("legacy_sink_dropped_unwired(): 0 until a sink is wired, then increments once "
          "per emit_guard_event() call that runs with no sink - and stays independent of "
          "events_lost()/gap_rules(), which this drop mode never touches (#4783 "
          "governance follow-up)",
          "[guardian][engine][legacy_sink]") {
    LegacySinkFixture f; // no set_event_sink() call below - the sink stays unwired
                         // throughout, standing in for the pre-network-arm window
                         // between start_local() and agent.cpp's post-Subscribe
                         // set_event_sink() call.

    CHECK(f.engine->legacy_sink_dropped_unwired() == 0);

    yuzu::agent::GuardDrift d;
    d.guard_type = "file";
    d.rule_id = "dropped-unwired-rule";
    d.rule_name = "dropped-unwired-rule";
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);

    CHECK(f.engine->legacy_sink_dropped_unwired() == 1);
    // This drop mode never reaches legacy_sink_executor_ (emit_guard_event() bails
    // before ever calling offer()), so it opens no integrity gap and is never
    // counted by events_lost()/gap_rules() - the whole point of adding a THIRD,
    // independent counter rather than folding this into an existing one.
    CHECK(f.engine->legacy_sink_gap_rules() == 0);
    CHECK(f.engine->legacy_sink_events_lost() == 0);

    // A second unwired call accumulates rather than resetting.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);
    CHECK(f.engine->legacy_sink_dropped_unwired() == 2);

    f.engine->stop();
}

// ── CH-1 L1 (cross-platform): the detached send stalls, never the emitter ───

TEST_CASE("CH-1 L1: a blocking legacy sink stalls the DETACHED SEND, never the emitting "
          "thread — delivered in FIFO order once released (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink sink;
    LegacySinkFixture f; // declared after sink — destruction order between these two no
                         // longer matters on its own now that delivery is asynchronous
                         // (the detached worker can outlive both); the ScopeExit below
                         // physically retires the worker before either destructs.
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, sink, "CH-1 L1 cleanup"); });

    f.engine->set_event_sink(sink.sink());

    auto emit_abc = [&f] {
        auto drift_for = [](const std::string& rule_id) {
            yuzu::agent::GuardDrift d;
            d.guard_type = "file";
            d.rule_id = rule_id;
            d.rule_name = rule_id;
            return d;
        };
        // #4783: emit_guard_event() only ENQUEUES on the detached executor — each
        // of these three calls returns immediately regardless of whether a prior
        // event's SEND is still blocked in the sink.
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-A"));
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-B"));
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-C"));
    };

    // THE fix proof: all three enqueue instantly (offer() never blocks), so the
    // helper returns within 1s even though the FIRST send is still parked inside
    // sink.sink() at that moment (only released by run_bounded's own cleanup).
    const bool finished_within_1s =
        run_bounded(emit_abc, std::chrono::seconds{1}, sink, "CH-1 L1: emit drift for A,B,C");
    CHECK(finished_within_1s);

    // run_bounded's cleanup already released the latch and joined the "op" helper
    // thread (the one that called offer() three times) — but delivery itself runs
    // on the executor's OWN detached worker, which nobody has waited on yet. Flush
    // before reading order(), or this read races that worker.
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));

    const auto delivered = sink.order();
    REQUIRE(delivered.size() == 3);
    CHECK(delivered[0].first == "rule-A");
    CHECK(delivered[0].second == "drift.detected");
    CHECK(delivered[1].first == "rule-B");
    CHECK(delivered[1].second == "drift.detected");
    CHECK(delivered[2].first == "rule-C");
    CHECK(delivered[2].second == "drift.detected");

    // Aggregate-count assertion (#4783 commit 3): after the op, the legacy-sink
    // executor's contribution to active_io_workers() must also have retired.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 3: FIFO preservation at the engine level (mirrors T1) ──────

TEST_CASE("Three offers for the SAME rule while a send is blocked are delivered in FIFO "
          "order, none dropped or merged (#4783 commit 3, engine-level FIFO-preservation "
          "regression, mirrors GuardianLegacySinkExecutor's own unit-level A,A,A test)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink sink;
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, sink, "A,A,A cleanup"); });

    f.engine->set_event_sink(sink.sink());

    // Drift, then compliant, then drift again — same rule_id, distinct
    // event_types (mirrors T1's own "A-drift, A-compliant, A-drift" case) so "no
    // coalescing" bites on TYPE, not merely on the event_id sequence checked below.
    yuzu::agent::GuardDrift drift;
    drift.guard_type = "file";
    drift.rule_id = "rule-A";
    drift.rule_name = "rule-A";
    yuzu::agent::GuardDrift compliant = drift;
    compliant.compliant = true;

    // offer() never blocks (#4783) — this first emit's SEND is what parks inside
    // `sink`, not this call.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift);
    // Handshake (plan hygiene rule 9): wait until the worker is GENUINELY parked
    // inside the sink before offering the next two, so this deterministically
    // exercises "queued behind an in-flight send", not a race.
    REQUIRE(yuzu::test::spin_until([&] { return sink.entered() >= 1; }, std::chrono::seconds{30}));

    // Two more offers for the SAME rule_id while the first is still in flight —
    // pure FIFO queueing, never coalesced/replaced/reordered
    // (guardian_legacy_sink_executor.hpp's queue policy). Deterministic, no spin
    // needed: both calls run on this thread while the only worker is parked.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, compliant);
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift);
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 2);

    sink.release();

    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    const auto delivered = sink.order();
    REQUIRE(delivered.size() == 3);
    CHECK(delivered[0].first == "rule-A");
    CHECK(delivered[0].second == "drift.detected");
    CHECK(delivered[1].first == "rule-A");
    CHECK(delivered[1].second == "guard.compliant");
    CHECK(delivered[2].first == "rule-A");
    CHECK(delivered[2].second == "drift.detected");

    // Identity-bearing on top of type ordering: each event_id's trailing
    // per-engine seq (assigned synchronously in emit_guard_event(), BEFORE the
    // async hand-off) must strictly increase in emission order — proof the
    // executor delivered them in the order they were OFFERED, not merely "three
    // of the right types".
    const auto ids = sink.event_ids();
    REQUIRE(ids.size() == 3);
    auto seq_of = [](const std::string& id) -> std::uint64_t {
        const auto pos = id.rfind('-');
        REQUIRE(pos != std::string::npos);
        return std::stoull(id.substr(pos + 1));
    };
    CHECK(seq_of(ids[0]) < seq_of(ids[1]));
    CHECK(seq_of(ids[1]) < seq_of(ids[2]));

    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 3: stop() discards the backlog, not an in-flight send ──────

TEST_CASE("stop() discards the backlog it never sent, but does not touch a send already "
          "in flight (#4783 commit 3, D3 — discarded_at_stop counts exactly what was "
          "discarded)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink sink;
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, sink, "stop()-discards-backlog cleanup"); });

    f.engine->set_event_sink(sink.sink());

    auto drift_for = [](const std::string& rule_id) {
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = rule_id;
        d.rule_name = rule_id;
        return d;
    };

    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-A")); // A: goes in-flight
    REQUIRE(yuzu::test::spin_until([&] { return sink.entered() >= 1; }, std::chrono::seconds{30}));
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-B")); // B: queued behind A
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 1);

    const bool finished = run_bounded([&] { f.engine->stop(); }, std::chrono::seconds{5}, sink,
                                      "stop()-discards-backlog: stop() while A in flight, B queued");
    CHECK(finished);

    // run_bounded's cleanup already released the latch — wait for A's now-unblocked
    // send (and the worker's own physical retirement) rather than racing it.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));

    CHECK(sink.delivered() == 1); // only A — B was discarded by stop(), never sent
    const auto delivered = sink.order();
    REQUIRE(delivered.size() == 1);
    CHECK(delivered[0].first == "rule-A");
    CHECK(f.engine->legacy_sink_executor_for_test().stats().discarded_at_stop == 1);
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 4: legacy_sink_kick() repairs a sticky gap end to end ──────

TEST_CASE("legacy_sink_kick(): a capacity-refused event opens a sticky gap, and the "
          "heartbeat kick repairs it with a synthesized guard.unhealthy report "
          "bearing the fixed detail string; a Sent repair clears the gap and "
          "events_lost stays cumulative (#4783 commit 4)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink blocking;
    // max_events=1: forces the THIRD offer below to be RefusedCapacity once the
    // queue already holds one item — see set_legacy_sink_max_events_for_test's own
    // doc comment for why this must be supplied before start_local() runs, which is
    // exactly what LegacySinkFixture's constructor now does on our behalf.
    LegacySinkFixture f{/*legacy_sink_max_events_for_test=*/1};
    yuzu::test::ScopeExit cleanup([&] {
        require_legacy_sink_retired(*f.engine, blocking, "legacy_sink_kick gap-repair cleanup");
    });

    f.engine->set_event_sink(blocking.sink());

    auto drift_for = [](const std::string& rule_id) {
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = rule_id;
        d.rule_name = rule_id;
        return d;
    };

    // #1: dequeued almost immediately — its SEND is what parks inside `blocking`,
    // so the queue itself is empty again by the time #2 is offered.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-1"));
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // #2: admitted — occupies the sole max_events=1 slot.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-2"));
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 1);

    // #3: the queue is already at max_events(1) — REFUSED, opening a sticky
    // integrity gap for "gapped-rule" (never queued, so it is not among the
    // deliveries `blocking` will see below).
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("gapped-rule"));
    CHECK(f.engine->legacy_sink_executor_for_test().stats().events_lost == 1);
    CHECK(f.engine->legacy_sink_gap_rules() == 1);
    CHECK(f.engine->legacy_sink_events_lost() == 1); // the production accessor, not just stats()

    // Release: #1 and #2 deliver (both admitted before the refusal); #3 was never
    // queued and cannot appear.
    blocking.release();
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(blocking.delivered() == 2);

    // Swap in a capturing sink so legacy_sink_kick()'s synthesized repair report is
    // observable in full, including detail_json — CountingSink only records
    // (rule_id, event_type), not enough to pin the fixed detail string.
    std::mutex cap_mu;
    std::vector<gpb::GuaranteedStateEvent> captured;
    f.engine->set_event_sink([&](const gpb::GuaranteedStateEvent& ev) {
        std::lock_guard lk(cap_mu);
        captured.push_back(ev);
        return yuzu::agent::LegacySendOutcome::Sent;
    });

    f.engine->legacy_sink_kick(); // the method under test
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));

    {
        std::lock_guard lk(cap_mu);
        REQUIRE(captured.size() == 1);
        CHECK(captured[0].rule_id() == "gapped-rule");
        CHECK(captured[0].event_type() == "guard.unhealthy");
        CHECK(captured[0].guard_type() == "file");
        // The fixed, short kLegacySinkDeliveryGapDetail constant — D1b: never
        // built from the gap's own rule/lost-count metadata, so no length cap
        // applies (same argument PR #4748 relied on for its own health_detail).
        CHECK(captured[0].detail_json() == R"({"detail":"legacy-sink-delivery-gap"})");
    }

    // Sent -> the gap closes; events_lost is CUMULATIVE and does not decrement.
    CHECK(f.engine->legacy_sink_gap_rules() == 0);
    CHECK(f.engine->legacy_sink_events_lost() == 1);
    CHECK(f.engine->legacy_sink_executor_for_test().stats().gap_rules == 0);

    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 4: independence from prefer_spark_ ──────────────────────────

TEST_CASE("legacy_sink_kick(): the gap-repair path runs and repairs a gap with "
          "prefer_spark_==true too — it deliberately does NOT share "
          "journal_maintenance_tick()'s prefer_spark_ gate (#4783 commit 4)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink blocking;
    LegacySinkFixture f{/*legacy_sink_max_events_for_test=*/1, /*prefer_spark=*/true};
    yuzu::test::ScopeExit cleanup([&] {
        require_legacy_sink_retired(*f.engine, blocking,
                                    "legacy_sink_kick prefer_spark=true cleanup");
    });
    REQUIRE(f.engine->prefer_spark());

    // Negative control: journal_maintenance_tick() itself stays a documented no-op
    // here (prefer_spark_ true but spark never wired via wire_spark_engine(), so
    // spark_runtime_/lifecycle_journal_ are still null) - proving this test's
    // engine really is in the "prefer_spark true, spark unwired" shape the
    // production flip transiently produces, and that calling it does not crash.
    f.engine->journal_maintenance_tick();

    f.engine->set_event_sink(blocking.sink());

    auto drift_for = [](const std::string& rule_id) {
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = rule_id;
        d.rule_name = rule_id;
        return d;
    };

    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-1"));
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-2"));
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 1);
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("gapped-rule-2"));
    REQUIRE(f.engine->legacy_sink_gap_rules() == 1);

    blocking.release();
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));

    std::mutex cap_mu;
    std::vector<gpb::GuaranteedStateEvent> captured;
    f.engine->set_event_sink([&](const gpb::GuaranteedStateEvent& ev) {
        std::lock_guard lk(cap_mu);
        captured.push_back(ev);
        return yuzu::agent::LegacySendOutcome::Sent;
    });

    f.engine->legacy_sink_kick(); // prefer_spark_==true for this engine instance
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));

    {
        std::lock_guard lk(cap_mu);
        REQUIRE(captured.size() == 1);
        CHECK(captured[0].rule_id() == "gapped-rule-2");
        CHECK(captured[0].event_type() == "guard.unhealthy");
    }
    CHECK(f.engine->legacy_sink_gap_rules() == 0);

    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 follow-up review: seq-guarded clearing + last_lost stamping ───────
//
// End-to-end proof of the reported regression and its fix: a stale synthetic
// gap-repair must never overwrite an already-delivered, newer real verdict.
// See guardian_legacy_sink_executor.hpp's class doc comment (SEQ-GUARDED
// CLEARING / DEQUEUE-TIME SUPERSESSION) and emit_guard_event()'s doc comment
// in guardian_engine.hpp (part (c), the last_lost timestamp override) for the
// full design this pair of cases exercises at the GuardianEngine level.

TEST_CASE("#4783 gap: a repair never overwrites a real recovery - a real verdict "
          "delivered after a loss clears the gap, and legacy_sink_kick() then "
          "offers no repair for that rule",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink blocking;
    // max_events=1: forces the third offer below to be RefusedCapacity once the
    // queue already holds one item, exactly as in the capacity-refusal case
    // above.
    LegacySinkFixture f{/*legacy_sink_max_events_for_test=*/1};
    yuzu::test::ScopeExit cleanup([&] {
        require_legacy_sink_retired(*f.engine, blocking,
                                    "#4783 gap: repair never overwrites recovery cleanup");
    });

    f.engine->set_event_sink(blocking.sink());

    auto drift_for = [](const std::string& rule_id) {
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = rule_id;
        d.rule_name = rule_id;
        return d;
    };

    // #1: dequeued almost immediately - its SEND is what parks inside
    // `blocking`.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-1"));
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // #2: admitted - occupies the sole max_events=1 slot.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-2"));
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 1);

    // #3: refused - opens a sticky integrity gap for "gapped-rule".
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("gapped-rule"));
    REQUIRE(f.engine->legacy_sink_gap_rules() == 1);

    blocking.release();
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(blocking.delivered() == 2);

    // A REAL guard.compliant verdict for "gapped-rule", delivered successfully
    // over a plain (non-blocking, always-Sent) sink - strictly AFTER the loss
    // that opened its gap, so its admission-time seq is strictly newer than the
    // gap's lost_seq.
    f.engine->set_event_sink(
        [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });
    yuzu::agent::GuardDrift compliant = drift_for("gapped-rule");
    compliant.compliant = true;
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, compliant);
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));

    // The real recovery already closed the gap on its own - no repair was ever
    // dispatched for it.
    CHECK(f.engine->legacy_sink_gap_rules() == 0);

    // Swap in a capturing sink: legacy_sink_kick() must offer NOTHING for
    // "gapped-rule" - the gap it would have repaired is already gone, so it is
    // not even a candidate in gapped_rules_needing_repair().
    std::mutex cap_mu;
    std::vector<gpb::GuaranteedStateEvent> captured;
    f.engine->set_event_sink([&](const gpb::GuaranteedStateEvent& ev) {
        std::lock_guard lk(cap_mu);
        captured.push_back(ev);
        return yuzu::agent::LegacySendOutcome::Sent;
    });

    f.engine->legacy_sink_kick(); // the method under test
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));

    {
        std::lock_guard lk(cap_mu);
        CHECK(captured.empty());
    }

    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

TEST_CASE("#4783 gap: legacy_sink_kick() stamps a still-open gap's repair with "
          "the gap's own last_lost, never the kick's own wall-clock now",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink blocking;
    LegacySinkFixture f{/*legacy_sink_max_events_for_test=*/1};
    yuzu::test::ScopeExit cleanup([&] {
        require_legacy_sink_retired(*f.engine, blocking, "#4783 gap: repair timestamp cleanup");
    });

    f.engine->set_event_sink(blocking.sink());

    auto drift_for = [](const std::string& rule_id) {
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = rule_id;
        d.rule_name = rule_id;
        return d;
    };

    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-1"));
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-2"));
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 1);
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("gapped-rule"));
    REQUIRE(f.engine->legacy_sink_gap_rules() == 1);

    // The gap's last_lost, recorded at the moment the refusal above opened it -
    // read BEFORE releasing/kicking, since a Sent repair would erase the gap
    // record entirely (nothing left to read afterward).
    auto gaps = f.engine->legacy_sink_executor_for_test().gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    const auto last_lost_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                    gaps[0].second.last_lost.time_since_epoch())
                                    .count();

    blocking.release();
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));

    // Timestamps here are second-granular (GuaranteedStateEvent.timestamp is a
    // google.protobuf.Timestamp with only `seconds` ever set - see
    // emit_guard_event()). Without letting real wall-clock time move into a
    // LATER second than last_lost, a kick() firing immediately after the loss
    // would stamp the same second whether it used `now` or `last_lost`, and the
    // assertion below would not actually discriminate between the fix and the
    // pre-fix `now`-stamping behaviour.
    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    const auto now_at_kick_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count();
    REQUIRE(now_at_kick_secs > last_lost_secs);

    std::mutex cap_mu;
    std::vector<gpb::GuaranteedStateEvent> captured;
    f.engine->set_event_sink([&](const gpb::GuaranteedStateEvent& ev) {
        std::lock_guard lk(cap_mu);
        captured.push_back(ev);
        return yuzu::agent::LegacySendOutcome::Sent;
    });

    f.engine->legacy_sink_kick(); // the method under test
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));

    {
        std::lock_guard lk(cap_mu);
        REQUIRE(captured.size() == 1);
        CHECK(captured[0].rule_id() == "gapped-rule");
        CHECK(captured[0].event_type() == "guard.unhealthy");
        // Stamped from the gap's last_lost - NOT the kick's own wall-clock now,
        // which by construction (the sleep above) is in a strictly LATER second.
        CHECK(captured[0].timestamp().seconds() == last_lost_secs);
        CHECK(captured[0].timestamp().seconds() < now_at_kick_secs);
    }

    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

#ifdef _WIN32

// ── CH-1(a) Windows: detection resumes once the block releases ──────────────

TEST_CASE("CH-1(a) Windows: file-guard detection continues (the guard thread never "
          "blocks) while a legacy-sink send is wedged, and the pending recreate-edge is "
          "queued, not lost (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch1a_"};
    fs::create_directories(dir.path);
    const auto target = dir.path / "guarded.txt";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-1(a) cleanup"); });

    // Arm barrier (plan hygiene rule 8): the file already exists, so
    // FileGuard's initial eval is compliant. Wait for that arm-time
    // guard.compliant edge BY IDENTITY before swapping in the blocking sink.
    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", target.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));

    f.engine->set_event_sink(blocking.sink());

    // Delete the file: presence (absent) now differs from the rule's default
    // expect_present==true -> a drift report. #4783: the guard's own worker
    // thread merely OFFERS this to the detached executor and returns; it is the
    // EXECUTOR's worker that parks inside the blocking sink, standing in for a
    // stalled Write() on the Subscribe stream — the guard thread itself stays
    // free to keep detecting.
    fs::remove(target);
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // Recreate WHILE the sender is still wedged - the scenario #4783 is about: a
    // legacy guard thread must notice (and REPORT) a subsequent real endpoint
    // transition even while the PRIOR report's send is still stuck.
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v2";
    }

    // #4783 commit 3: directly observable now — the recreate's compliant edge is
    // QUEUED (not merely "eventually noticed") while the sender is still wedged.
    // FileGuard's own watch loop is asynchronous/poll-driven, so this is a
    // bounded wait, not an immediate assertion.
    REQUIRE(yuzu::test::spin_until(
        [&] { return f.engine->legacy_sink_executor_for_test().pending_count_for_test() >= 1; },
        std::chrono::seconds{30}));

    blocking.release();

    // Flush (idle), then assert the exact count — deterministic rather than a
    // polling spin on delivered().
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{30}));
    // 2 deliveries total under `blocking` (the delete's drift, then the
    // recreate's compliant edge) — the ARM-TIME compliant edge above was
    // captured by `arm_sink`, installed before `blocking`, so it is not one of
    // these two.
    CHECK(blocking.delivered() == 2);

    const auto events = blocking.order();
    INFO("blocking sink delivered " << events.size() << " event(s)");
    if (events.size() >= 2) {
        CHECK(events[0].first == "r-a");
        CHECK(events[0].second == "drift.detected");
        CHECK(events[1].first == "r-a");
        CHECK(events[1].second == "guard.compliant");
    }

    // Aggregate-count assertion (#4783 commit 3).
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);

    f.engine->stop(); // tidy, deterministic teardown before the fixture destructs
}

// ── CH-1(b) Windows: stop() must complete promptly while blocked ────────────

TEST_CASE("CH-1(b) Windows: GuardianEngine::stop() completes promptly while a "
          "legacy-sink send is wedged in the blocking sink (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch1b_"};
    fs::create_directories(dir.path);
    const auto target = dir.path / "guarded.txt";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    LegacySinkFixture f; // declared last — see CH-1(a)'s comment on this order.
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-1(b) cleanup"); });

    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", target.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));

    f.engine->set_event_sink(blocking.sink());
    fs::remove(target); // drift: the executor's worker (not the guard thread, #4783) parks
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // GuardianEngine::stop() joins the (now-prompt) legacy guard thread and then
    // only stops the executor from ADMITTING new sends — it does not wait for
    // this already-in-flight one. #4783's actual fix: before it, stop() held
    // mtx_ across stop_all_guards_locked(), which joined the (wedged) legacy
    // guard thread — the exact deadlock this test exists to prove is gone, on
    // the shutdown path this time (CH-2, below, is the rule-management-path
    // counterpart).
    const bool finished = run_bounded([&] { f.engine->stop(); }, std::chrono::seconds{5}, blocking,
                                      "CH-1(b): stop() while blocked");
    CHECK(finished);

    // run_bounded already released the latch and joined the stop() helper — the
    // engine is fully stopped either way; wait for the executor's worker to
    // physically retire and confirm the aggregate count reflects it (#4783
    // commit 3).
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 3: shutdown-path aggregate-count regression ────────────────

TEST_CASE("CH-1(b) engine regression: the legacy-sink executor's physical worker count "
          "reads 1 while GuardianEngine::stop() is blocked on a wedged send and reaches "
          "0 only after it releases (#4783 commit 3, aggregate active_io_workers() proof)",
          "[guardian][engine][legacy_sink][chaos]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch1b_regr_"};
    fs::create_directories(dir.path);
    const auto target = dir.path / "guarded.txt";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-1(b) engine regression cleanup"); });

    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", target.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));

    f.engine->set_event_sink(blocking.sink());
    fs::remove(target); // drift -> the executor's worker (not the guard thread) blocks
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // mtx_ is free here — no watchdogged op is running yet, so this is a safe
    // direct poll (hygiene rule 4), asserted BEFORE the watchdogged stop() below
    // rather than racing its own release. This is the aggregate counterpart to
    // T1's own single-executor active_worker_count() assertion.
    CHECK(f.engine->legacy_sink_executor_for_test().active_worker_count() == 1);
    CHECK(f.engine->active_io_workers() == 1);

    // stop() itself must complete promptly (#4783's actual fix): it joins the
    // guard thread (which never entered Write()) and then only stops the
    // executor from ADMITTING new sends — it does not wait for this
    // already-in-flight one.
    const bool finished = run_bounded([&] { f.engine->stop(); }, std::chrono::seconds{5},
                                      blocking, "CH-1(b) engine regression: stop() while blocked");
    CHECK(finished);

    // run_bounded's own cleanup already released the latch and joined the
    // stop() helper — re-asserting "still 1" here would race the worker
    // actually finishing, so wait for physical retirement instead and check it
    // lands at 0.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->legacy_sink_executor_for_test().active_worker_count() == 0);
    CHECK(f.engine->active_io_workers() == 0);
}

// ── CH-2 Windows: a rule-dropping full_sync must not hang on a wedged peer ──

TEST_CASE("CH-2 Windows: a full_sync push dropping a rule whose legacy-sink send is "
          "wedged does not hang apply_rules (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch2_"};
    fs::create_directories(dir.path);
    const auto path_a = dir.path / "guarded-a.txt";
    const auto path_b = dir.path / "guarded-b.txt";
    for (const auto& p : {path_a, path_b}) {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    LegacySinkFixture f; // declared last — see CH-1(a)'s comment on this order.
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-2 cleanup"); });

    // Arm A and B together; both files pre-exist, so both arm-time evals are
    // compliant edges.
    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", path_a.string()),
                           LegacySinkFixture::make_file_exists_rule("r-b", path_b.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));
    REQUIRE(arm_sink.wait_for("r-b", "guard.compliant", std::chrono::seconds{30}));
    REQUIRE(f.engine->armed_guard_count() == 2); // safe here: nothing is blocked yet

    f.engine->set_event_sink(blocking.sink());

    fs::remove(path_a); // drift on A only -> its offer()'d send parks in the blocking sink
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    const auto arm_failures_before = f.engine->arm_failure_count();

    // apply_rules(full_sync=true, {B only}) unconditionally tears down EVERY
    // currently-armed guard (stop_all_guards_locked(), guardian_engine.cpp)
    // before re-arming from the new push — including A. #4783: A's guard
    // thread itself never entered Write(), so this join is prompt regardless
    // of A's send still being wedged on the executor's own worker.
    yuzu::agent::GuardianDispatchResult push_result;
    const bool finished =
        run_bounded([&] { push_result = f.make_push(
                              {LegacySinkFixture::make_file_exists_rule("r-b", path_b.string())},
                              /*full_sync=*/true); },
                    std::chrono::seconds{5}, blocking,
                    "CH-2: full_sync push dropping A while wedged");
    CHECK(finished);

    // Safe only now that run_bounded has returned: the latch has already
    // been released and the helper already joined (hygiene rule 4 — never
    // poll an mtx_-guarded accessor while a watchdogged op could still hold
    // mtx_).
    CHECK(push_result.exit_code == 0);
    CHECK(f.engine->armed_guard_count() == 1); // only B survives the full_sync
    CHECK(f.engine->arm_failure_count() == arm_failures_before); // B's re-arm is a routine success

    // Aggregate-count assertion (#4783 commit 3): wait for both A's now-released
    // send and B's arm-time compliant edge (queued behind it) to fully drain.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);

    f.engine->stop(); // tidy, deterministic teardown before the fixture destructs
}

#endif // _WIN32

// ── #4783 Gate 4 UP-3/UP-4: the restart-durable loss ledger (KV wiring) ─────
//
// Cross-platform: exercises GuardianEngine::start_local()/legacy_sink_kick()/
// stop() directly via guardian_emit_drift_for_test() + admission-fault
// injection (no real guard, no BlockingSink/thread orchestration needed - see
// test_guardian_legacy_sink_executor.cpp's own restore() cases for the same
// deterministic-loss technique). A simulated restart is a fresh KvStore +
// GuardianEngine pair opened against the SAME db path AFTER the first pair
// has been fully destroyed - mirroring how LegacySinkFixture's own db_ member
// is a TempDbFile (deletes the file on ITS destruction), these cases own an
// explicit TempDbFile so the path survives across both "processes".

TEST_CASE("#4783 Gate 4 UP-3: an open gap persisted by kick() survives a simulated "
          "agent restart - the new engine's start_local() restores it without a "
          "fresh loss",
          "[guardian][engine][legacy_sink]") {
    yuzu::test::TempDbFile db{unique_kv_path()};

    // "Process 1".
    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-restart-test", false);
        REQUIRE(engine.start_local().has_value());
        engine.set_event_sink(
            [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });

        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::ThrowOnNode);
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = "gapped-rule";
        d.rule_name = "gapped-rule";
        yuzu::agent::guardian_emit_drift_for_test(engine, d);
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::None);
        REQUIRE(engine.legacy_sink_gap_rules() == 1);

        // Unwire the sink BEFORE kick(): kick()'s own repair-dispatch loop would
        // otherwise synthesize a guard.unhealthy report for "gapped-rule" and,
        // with a real (always-Sent) sink still installed, successfully deliver
        // and CLEAR the very gap this test is about to verify survived the
        // persist - emit_guard_event() bails at "no sink wired" before ever
        // reaching offer() when the sink is null, so this isolates "kick()
        // persists the CURRENT ledger" from "a repair happened to race ahead
        // and cleared it first".
        engine.set_event_sink(nullptr);
        engine.legacy_sink_kick(); // the write under test
        REQUIRE(engine.legacy_sink_gap_rules() == 1); // still open - no repair could send
        // "Process 1" ends here - engine/kv destruct (simulating an agent exit).
    }

    // "Process 2": a fresh KvStore + GuardianEngine at the SAME path.
    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-restart-test", false);
        REQUIRE(engine.start_local().has_value());

        CHECK(engine.legacy_sink_gap_rules() == 1);
        CHECK(engine.legacy_sink_events_lost() >= 1);
        const auto gaps = engine.legacy_sink_executor_for_test().all_gaps_for_test();
        REQUIRE(gaps.size() == 1);
        CHECK(gaps[0].first == "gapped-rule");
        // Fresh in-process sequencing (restore()'s own contract) - immediately
        // eligible for repair, no fresh loss occurred in this second process.
        CHECK(gaps[0].second.repair_seq == 0);
        CHECK(gaps[0].second.last_attempt_kick == 0);

        engine.stop();
    }
}

// ── #4783 governance follow-up: dropped_unwired is NOT restart-durable, ────
// unlike its two persisted siblings above ──────────────────────────────────

TEST_CASE("#4783 governance follow-up: legacy_sink_dropped_unwired() does NOT survive a "
          "simulated agent restart, unlike its two persisted siblings events_lost()/"
          "gap_rules() above - it lives on GuardianEngine directly and is never part of "
          "the restart-durable Snapshot/Stats record",
          "[guardian][engine][legacy_sink]") {
    yuzu::test::TempDbFile db{unique_kv_path()};

    // "Process 1": produce BOTH loss kinds in the same pass - a real gap (the same
    // admission-fault-injection seam the UP-3 restart case above uses) AND an
    // unwired-sink drop (the same seam the "0 until a sink is wired" case above
    // uses: guardian_emit_drift_for_test() with no sink installed, which bails
    // inside emit_guard_event() before ever reaching offer()) - then kick() to
    // persist.
    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-restart-asymmetry-test", false);
        REQUIRE(engine.start_local().has_value());
        engine.set_event_sink(
            [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });

        // (a) a real gap: force a RefusedCapacity-shaped admission failure so
        // events_lost()/gap_rules() become nonzero (same seam as the UP-3 restart
        // case above).
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::ThrowOnNode);
        yuzu::agent::GuardDrift gap_drift;
        gap_drift.guard_type = "file";
        gap_drift.rule_id = "gapped-rule-asymmetry";
        gap_drift.rule_name = "gapped-rule-asymmetry";
        yuzu::agent::guardian_emit_drift_for_test(engine, gap_drift);
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::None);
        REQUIRE(engine.legacy_sink_gap_rules() == 1);

        // Unwire the sink BEFORE the unwired-drop event and BEFORE kick() - same
        // rationale as the UP-3 restart case above: with a real (always-Sent) sink
        // still installed, kick()'s own repair-dispatch loop would successfully
        // deliver and clear the very gap this test is about to verify survives the
        // persist.
        engine.set_event_sink(nullptr);

        // (b) an unwired-sink drop: emit_guard_event() bails at "no sink wired"
        // before ever reaching offer() (see the "0 until a sink is wired" case
        // above) - this is the seam that increments legacy_sink_dropped_unwired_.
        yuzu::agent::GuardDrift unwired_drift;
        unwired_drift.guard_type = "file";
        unwired_drift.rule_id = "dropped-unwired-rule-asymmetry";
        unwired_drift.rule_name = "dropped-unwired-rule-asymmetry";
        yuzu::agent::guardian_emit_drift_for_test(engine, unwired_drift);
        REQUIRE(engine.legacy_sink_dropped_unwired() == 1);

        engine.legacy_sink_kick(); // the write under test - persists events_lost/
                                   // gap_rules (via the executor's Snapshot/Stats)
                                   // only; dropped_unwired_ is not part of that type.
                                   // kick()'s OWN repair-dispatch loop also calls
                                   // emit_guard_event() for "gapped-rule-asymmetry"
                                   // (gap.repair_seq == 0, so it is due a repair
                                   // attempt) - with the sink still unwired that
                                   // call bails the same "no sink wired" way, so
                                   // dropped_unwired_ goes 1 -> 2 here too. Real
                                   // production behaviour, not a test artifact.

        // All three counters nonzero before the simulated restart.
        REQUIRE(engine.legacy_sink_gap_rules() == 1);
        REQUIRE(engine.legacy_sink_events_lost() >= 1);
        REQUIRE(engine.legacy_sink_dropped_unwired() == 2);
        // "Process 1" ends here - engine/kv destruct (simulating an agent exit).
    }

    // "Process 2": a fresh KvStore + GuardianEngine at the SAME path.
    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-restart-asymmetry-test", false);
        REQUIRE(engine.start_local().has_value());

        // The two persisted siblings restore, matching the UP-3 restart case above.
        CHECK(engine.legacy_sink_gap_rules() == 1);
        CHECK(engine.legacy_sink_events_lost() >= 1);

        // NEW assertion this test adds: legacy_sink_dropped_unwired_ is a bare
        // GuardianEngine member, never folded into
        // GuardianLegacySinkExecutor::Snapshot/Stats and never touched by
        // restore() (see persist_legacy_sink_loss_ledger()/
        // legacy_sink_snapshot_to_json() in guardian_engine.cpp, and
        // legacy_sink_dropped_unwired_'s own doc comment in guardian_engine.hpp) -
        // so, unlike its two siblings above, it does NOT survive the restart. A
        // future refactor that accidentally folded this counter into the
        // persisted record would read nonzero here instead of 0, failing this
        // CHECK.
        CHECK(engine.legacy_sink_dropped_unwired() == 0);

        engine.stop();
    }
}

TEST_CASE("#4783 Gate 4 UP-3: an absent, malformed, or schema-mismatched legacy-sink "
          "loss-ledger record self-heals at boot - no restore, no crash",
          "[guardian][engine][legacy_sink]") {
    // Absent: nothing written yet - a completely fresh KvStore.
    {
        yuzu::test::TempDbFile db{unique_kv_path()};
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-ledger-absent-test", false);
        REQUIRE(engine.start_local().has_value()); // must not fail or crash
        CHECK(engine.legacy_sink_gap_rules() == 0);
        CHECK(engine.legacy_sink_events_lost() == 0);
        engine.stop();
    }

    // Malformed: garbage bytes under the exact key a real engine writes to.
    {
        yuzu::test::TempDbFile db{unique_kv_path()};
        {
            auto opened = KvStore::open(db.path);
            REQUIRE(opened.has_value());
            KvStore kv(std::move(*opened));
            REQUIRE(kv.set(GuardianEngine::kv_namespace(),
                           GuardianEngine::legacy_sink_loss_ledger_key_for_test(), "not json"));
        }
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-ledger-malformed-test", false);
        REQUIRE(engine.start_local().has_value()); // self-heals: logs, skips, boots
        CHECK(engine.legacy_sink_gap_rules() == 0);
        CHECK(engine.legacy_sink_events_lost() == 0);
        engine.stop();
    }

    // Schema-mismatched: well-formed JSON, wrong schema version - a distinct
    // Malformed cause from bad JSON (mirrors read_baseline_record's own
    // schema-drift-is-a-separate-case posture).
    {
        yuzu::test::TempDbFile db{unique_kv_path()};
        {
            auto opened = KvStore::open(db.path);
            REQUIRE(opened.has_value());
            KvStore kv(std::move(*opened));
            REQUIRE(kv.set(GuardianEngine::kv_namespace(),
                           GuardianEngine::legacy_sink_loss_ledger_key_for_test(),
                           R"({"schema":99,"counters":{},"gaps":[]})"));
        }
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-ledger-schema-test", false);
        REQUIRE(engine.start_local().has_value());
        CHECK(engine.legacy_sink_gap_rules() == 0);
        CHECK(engine.legacy_sink_events_lost() == 0);
        engine.stop();
    }
}

TEST_CASE("#4783 Gate 4 unhappy-path finding, 2026-09-24: a single empty-rule_id "
          "gap entry in an otherwise-valid record is SKIPPED, not treated as "
          "Malformed - every OTHER rule's legitimate gap state still restores",
          "[guardian][engine][legacy_sink]") {
    // Reproduces the reported amplification chain's restore half directly: a
    // rare local fault (worker_loop's own guard against this now refuses to
    // CREATE such an entry in the first place - see its doc comment - but this
    // proves the RESTORE side is hardened independently, defense in depth) can
    // in principle leave one empty-rule_id entry in the persisted record
    // alongside genuinely legitimate ones. Before this fix, ANY empty-rule_id
    // entry made read_legacy_sink_loss_record() reject the WHOLE record as
    // Malformed - silently discarding every other rule's real open-gap state
    // on restart. Now it is skipped individually.
    yuzu::test::TempDbFile db{unique_kv_path()};
    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        REQUIRE(kv.set(GuardianEngine::kv_namespace(),
                       GuardianEngine::legacy_sink_loss_ledger_key_for_test(),
                       R"({"schema":1,"counters":{"events_lost":2},"gaps":[)"
                       R"({"rule_id":"","guard_type":"file","rule_name":"phantom",)"
                       R"("lost":1,"first_lost_ms":1000,"last_lost_ms":1000},)"
                       R"({"rule_id":"real-rule","guard_type":"file","rule_name":"rn",)"
                       R"("lost":1,"first_lost_ms":2000,"last_lost_ms":2000}]})"));
    }
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv(std::move(*opened));
    GuardianEngine engine(&kv, "agent-ledger-phantom-skip-test", false);
    REQUIRE(engine.start_local().has_value());
    // The legitimate rule's gap AND the counters survived - proving this
    // was NOT treated as Malformed (which would have discarded both).
    CHECK(engine.legacy_sink_gap_rules() == 1); // "" was skipped, "real-rule" kept
    CHECK(engine.legacy_sink_events_lost() == 2); // counters restored normally
    // #4783 Gate 6 sre finding, 2026-09-24: the skip is folded into
    // gap_ledger_faults (a durable, persisted counter) rather than being a
    // log-only signal an operator has to be watching for at the exact
    // restart moment - see that field's own doc comment.
    CHECK(engine.legacy_sink_executor_for_test().stats().gap_ledger_faults == 1);
    engine.stop();
}

TEST_CASE("#4783 Gate 4 UP-3: stop() persists a final snapshot even with no prior "
          "kick() having run - an open gap survives an immediate shutdown",
          "[guardian][engine][legacy_sink]") {
    yuzu::test::TempDbFile db{unique_kv_path()};

    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-stop-flush-test", false);
        REQUIRE(engine.start_local().has_value());
        engine.set_event_sink(
            [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });

        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::ThrowOnNode);
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = "gapped-rule-stop";
        d.rule_name = "gapped-rule-stop";
        yuzu::agent::guardian_emit_drift_for_test(engine, d);
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::None);
        REQUIRE(engine.legacy_sink_gap_rules() == 1);

        // Deliberately NO legacy_sink_kick() call anywhere in this scope -
        // stop() must flush the ledger unconditionally on its own. Verified
        // below via a second engine restored from whatever this stop() wrote.
        engine.stop();
    }

    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-stop-flush-test", false);
        REQUIRE(engine.start_local().has_value());
        CHECK(engine.legacy_sink_gap_rules() == 1);
        const auto gaps = engine.legacy_sink_executor_for_test().all_gaps_for_test();
        REQUIRE(gaps.size() == 1);
        CHECK(gaps[0].first == "gapped-rule-stop");
        engine.stop();
    }
}

// ── #4783 Gate 8 re-review: legacy_sink_persist_mu_ closes a lost-update ────
// race between legacy_sink_kick() and stop()'s final persist ───────────────

TEST_CASE("#4783 Gate 8: legacy_sink_kick() paused mid-persist does not clobber a "
          "fresher write from a concurrent stop() - the lost-update race is closed",
          "[guardian][engine][legacy_sink]") {
    // Reproduces the exact interleaving from the Gate 8 finding: kick() takes a
    // snapshot, decides a write is needed, and is then preempted BEFORE the
    // actual persist call - while it is parked there, stop() runs its own
    // final persist to completion against a NEWER executor state. Before
    // legacy_sink_persist_mu_ existed, kick() would then resume and
    // unconditionally overwrite the KV record with its now-stale snapshot,
    // regressing the persisted loss ledger. legacy_sink_persist_race_hook_for_test_
    // fires at exactly that point (own doc comment in guardian_engine.hpp),
    // with legacy_sink_persist_mu_ already held on the fixed engine - so a
    // real second thread (not same-thread re-entry, which would self-deadlock
    // on the lock; see that hook's own CONTRACT) is required to drive stop()
    // concurrently, mirroring this file's own PersistRaceLatch/BlockingSink
    // idiom rather than the reentrant single-thread hook pattern
    // guardian_outbox_send_executor's tests use (that idiom only works for a
    // race that occupies a GENUINELY unlocked gap - see PersistRaceLatch's own
    // doc comment).
    yuzu::test::TempDbFile db{unique_kv_path()};

    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-persist-race-test", false);
        REQUIRE(engine.start_local().has_value());
        // A real sink is needed WHILE the gaps below are opened -
        // emit_guard_event() bails before ever reaching offer() (so the
        // admission fault below would never fire) when no sink is wired yet
        // (legacy_sink_dropped_unwired_'s own doc comment). Unwired AFTER
        // both gaps exist (same rationale as the UP-3 restart case above):
        // isolates the persist path under test from kick()'s own
        // repair-dispatch loop, which would otherwise try to deliver (and
        // clear) a gap via a real send.
        engine.set_event_sink(
            [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });

        // Open the FIRST gap - this is what the kicker thread's snapshot will
        // capture and, on a reverted (unfixed) engine, unconditionally write
        // even after it is stale.
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::ThrowOnNode);
        yuzu::agent::GuardDrift d1;
        d1.guard_type = "file";
        d1.rule_id = "gapped-rule-1";
        d1.rule_name = "gapped-rule-1";
        yuzu::agent::guardian_emit_drift_for_test(engine, d1);
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::None);
        REQUIRE(engine.legacy_sink_gap_rules() == 1);
        engine.set_event_sink(nullptr);

        PersistRaceLatch latch;
        engine.set_legacy_sink_persist_race_hook_for_test([&] { latch.hook(); });

        std::thread kicker;
        std::thread stopper;
        std::atomic<bool> kicker_done{false};
        std::atomic<bool> stopper_done{false};
        // Exception-safe cleanup (plan hygiene rules 2/3/6, same posture as
        // require_legacy_sink_retired/run_bounded above): a failing
        // REQUIRE/CHECK below must not leave the kicker thread parked forever
        // holding legacy_sink_persist_mu_ (which would also wedge the stopper
        // thread blocked trying to acquire it, and the whole test binary with
        // it) - release the latch unconditionally and give both helpers a
        // generous, bounded chance to finish before aborting the process
        // (rather than hanging meson's runner).
        yuzu::test::ScopeExit cleanup([&] {
            latch.release();
            // A thread that was never launched (e.g. a REQUIRE fired before
            // `stopper`'s assignment below) is not joinable and is vacuously
            // "done" here - only a LAUNCHED-but-still-running helper should
            // hold up this wait; requiring done unconditionally on a
            // never-launched thread would spin the full 30s and then
            // std::abort() the whole binary on an ordinary, already-reported
            // REQUIRE failure.
            const bool both_done = yuzu::test::spin_until(
                [&] {
                    return (!kicker.joinable() || kicker_done.load(std::memory_order_acquire)) &&
                           (!stopper.joinable() || stopper_done.load(std::memory_order_acquire));
                },
                std::chrono::seconds{30});
            if (!both_done) {
                spdlog::critical(
                    "legacy_sink persist-race cleanup: kicker/stopper did not both "
                    "complete even after releasing the latch (30s) - aborting rather "
                    "than hanging the whole test binary (#4783)");
                std::abort();
            }
            if (kicker.joinable())
                kicker.join();
            if (stopper.joinable())
                stopper.join();
        });

        kicker = std::thread([&] {
            engine.legacy_sink_kick();
            kicker_done.store(true, std::memory_order_release);
        });
        REQUIRE(latch.wait_entered(std::chrono::seconds{5}));

        // While the kicker is parked (holding legacy_sink_persist_mu_ on the
        // fixed engine, holding nothing on a reverted one) with its stale
        // 1-gap snapshot already captured, open a SECOND gap - the executor's
        // real, current state is now 2 gaps, strictly newer than anything the
        // kicker already decided to write. Re-wire a sink first (same
        // "emit_guard_event() bails before offer() on a null sink" rationale
        // as the first gap above) and unwire it again afterward.
        engine.set_event_sink(
            [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::ThrowOnNode);
        yuzu::agent::GuardDrift d2;
        d2.guard_type = "file";
        d2.rule_id = "gapped-rule-2";
        d2.rule_name = "gapped-rule-2";
        yuzu::agent::guardian_emit_drift_for_test(engine, d2);
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::None);
        REQUIRE(engine.legacy_sink_gap_rules() == 2);
        engine.set_event_sink(nullptr);

        stopper = std::thread([&] {
            engine.stop();
            stopper_done.store(true, std::memory_order_release);
        });

        // Red-path head start only, deliberately NOT asserted either way: on
        // the FIXED engine, stop()'s own final persist blocks trying to
        // acquire legacy_sink_persist_mu_ (the kicker still holds it, parked
        // in the hook) and this always times out - that is the invariant
        // under test, not a defect in the wait. On a REVERTED (unfixed)
        // engine nothing serializes the two, so this generous window gives
        // stop() every opportunity to run to completion BEFORE the kicker
        // resumes - faithfully reproducing the production interleaving from
        // the bug report, where stop() finishes entirely while kick() is
        // still stuck mid-sequence.
        (void)yuzu::test::spin_until(
            [&] { return stopper_done.load(std::memory_order_acquire); },
            std::chrono::milliseconds{500});

        latch.release();

        REQUIRE(yuzu::test::spin_until(
            [&] {
                return kicker_done.load(std::memory_order_acquire) &&
                       stopper_done.load(std::memory_order_acquire);
            },
            std::chrono::seconds{30}));
        kicker.join();
        stopper.join();

        // Read the persisted record DIRECTLY, off the SAME kv handle, right
        // here - BEFORE `engine` goes out of scope below. Deliberately NOT a
        // "process 2" restart-and-restore check (contrast the UP-3 restart
        // case above): ~GuardianEngine() calls stop() again unconditionally
        // (idempotent per its own doc comment) once this scope ends, and that
        // SECOND, redundant stop() would perform its own fresh
        // snapshot+persist of the LIVE in-memory executor state - which the
        // race above never touched, only the ON-DISK record did - silently
        // re-repairing the very corruption this test exists to catch before
        // any later read ever observed it. The regression this closes: on a
        // reverted (unfixed) engine, the kicker's late, stale write regresses
        // the persisted ledger back to ONE gap, silently losing
        // gapped-rule-2 from the record. On the fixed engine, whichever of
        // the two persists actually lands LAST always does so with a
        // snapshot taken fresh under legacy_sink_persist_mu_ - reflecting
        // BOTH gaps regardless of which thread got there first.
        auto persisted =
            kv.get_entry(GuardianEngine::kv_namespace(),
                        GuardianEngine::legacy_sink_loss_ledger_key_for_test());
        REQUIRE(persisted.has_value());
        REQUIRE(persisted->has_value());
        const std::string& raw = **persisted;
        CHECK(raw.find("gapped-rule-1") != std::string::npos);
        CHECK(raw.find("gapped-rule-2") != std::string::npos);

        // "Process 1" ends here - engine/kv destruct (~GuardianEngine calls
        // stop() again; idempotent per its own doc comment, so this is just a
        // redundant, harmless re-persist of the same already-current
        // in-memory state - see the comment above for why that makes a
        // post-destruction read unsuitable as this test's proof).
    }
}

TEST_CASE("#4783 Gate 8: legacy_sink_kick() and stop() still both persist correctly "
          "with no contention - legacy_sink_persist_mu_ does not change the ordinary, "
          "non-racing case",
          "[guardian][engine][legacy_sink]") {
    yuzu::test::TempDbFile db{unique_kv_path()};

    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-persist-no-contention-test", false);
        REQUIRE(engine.start_local().has_value());
        // Hook left null throughout - proves the null-hook call site (the
        // production default) is inert. A real sink must be wired WHILE each
        // gap is opened (emit_guard_event() bails before ever reaching
        // offer() - and so before the admission fault below could fire - on a
        // null sink), then unwired before each kick() so its repair-dispatch
        // loop cannot deliver (and clear) the gap it would otherwise try to
        // report on.
        engine.set_event_sink(
            [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });

        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::ThrowOnNode);
        yuzu::agent::GuardDrift d1;
        d1.guard_type = "file";
        d1.rule_id = "gapped-rule-a";
        d1.rule_name = "gapped-rule-a";
        yuzu::agent::guardian_emit_drift_for_test(engine, d1);
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::None);
        REQUIRE(engine.legacy_sink_gap_rules() == 1);
        engine.set_event_sink(nullptr);

        // Sequential, uncontended kick(): persists the 1-gap state.
        engine.legacy_sink_kick();

        engine.set_event_sink(
            [](const gpb::GuaranteedStateEvent&) { return yuzu::agent::LegacySendOutcome::Sent; });
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::ThrowOnNode);
        yuzu::agent::GuardDrift d2;
        d2.guard_type = "file";
        d2.rule_id = "gapped-rule-b";
        d2.rule_name = "gapped-rule-b";
        yuzu::agent::guardian_emit_drift_for_test(engine, d2);
        engine.legacy_sink_executor_for_test().set_admission_fault_for_test(
            yuzu::agent::GuardianLegacySinkExecutor::AdmissionFaultForTest::None);
        REQUIRE(engine.legacy_sink_gap_rules() == 2);
        engine.set_event_sink(nullptr);

        // A second sequential, uncontended kick(): must persist the CHANGED
        // (2-gap) state, not silently skip because a prior write already ran.
        engine.legacy_sink_kick();

        // stop()'s own final persist, still sequential/uncontended: must
        // match the last real change (still 2 gaps - nothing changed since
        // the second kick()).
        engine.stop();
    }

    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        KvStore kv(std::move(*opened));
        GuardianEngine engine(&kv, "agent-persist-no-contention-test", false);
        REQUIRE(engine.start_local().has_value());
        CHECK(engine.legacy_sink_gap_rules() == 2);
        const auto gaps = engine.legacy_sink_executor_for_test().all_gaps_for_test();
        REQUIRE(gaps.size() == 2);
        std::vector<std::string> rule_ids;
        for (const auto& g : gaps)
            rule_ids.push_back(g.first);
        std::sort(rule_ids.begin(), rule_ids.end());
        CHECK(rule_ids == std::vector<std::string>{"gapped-rule-a", "gapped-rule-b"});
        engine.stop();
    }
}
