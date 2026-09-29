/**
 * test_spark_engine.cpp — SparkEngine core contract (spark_engine.cpp):
 * tier behaviour, arming dedup, consumer isolation, bounded-queue overflow,
 * and lifecycle. Uses the cadence-floor + disk-reader test seams so nothing
 * here waits on a real 30 s cadence or a real volume filling up.
 *
 * Timing style: assertions wait on observed effects with generous deadlines
 * (never "sleep then assert a count is exact") so the suite stays honest under
 * CI load and Defender-induced I/O serialisation (#473 lesson).
 */

#include "spark_engine.hpp"
#include "spark_heartbeat.hpp" // emit_spark_heartbeat_tags (rung-1 tag composition)
#include "test_helpers.hpp" // kSpinScale

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

constexpr std::uint64_t kGiB = 1024ULL * 1024 * 1024;

/// Poll `pred` until true or the deadline passes. Returns its final value.
template <typename Pred>
bool eventually(Pred pred, std::chrono::milliseconds deadline = 5000ms) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= until)
            return pred();
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

/// Thread-safe event collector handed to queued consumers.
struct Collector {
    std::mutex mu;
    std::vector<SparkEvent> events;

    SparkEngine::QueuedHandler handler() {
        return [this](const SparkEvent& ev) {
            std::lock_guard lk(mu);
            events.push_back(ev);
        };
    }
    std::size_t count() {
        std::lock_guard lk(mu);
        return events.size();
    }
    SparkEvent at(std::size_t i) {
        std::lock_guard lk(mu);
        return events.at(i);
    }
};

SparkSpec interval_spec(std::uint64_t ms) {
    return SparkSpec{SparkType::Interval, IntervalSparkParams{ms}};
}

} // namespace

TEST_CASE("SparkEngine: interval spark delivers to a queued consumer", "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    auto sub = engine.arm(*consumer, interval_spec(50));
    REQUIRE(sub.has_value());

    engine.start();
    REQUIRE(engine.is_running());
    CHECK(eventually([&] { return got.count() >= 3; }));

    // Events carry the armed key, the type, and a monotonically increasing seq.
    const SparkEvent first = got.at(0);
    CHECK(first.key == spark_key(interval_spec(50)));
    CHECK(first.type == SparkType::Interval);
    CHECK(got.at(1).seq == first.seq + 1);
    CHECK(std::holds_alternative<std::monostate>(first.data));

    engine.stop();
    const auto stats = engine.stats();
    CHECK(stats.events_total >= 3);
    CHECK(stats.queued_delivered_total >= 3);
}

TEST_CASE("SparkEngine: two distinct sparks due in one wheel tick both fire (no double-lock)",
          "[spark][engine]") {
    // Regression (governance HP-1): two DISTINCT-key timer sparks that clamp to
    // the same cadence floor get an identical next_due from start()'s shared
    // `now` and land in one wheel scan (due.size()==2). The prior wheel re-locked
    // mu_ per due item, so the second item's commit lk.lock() double-locked →
    // std::system_error, uncaught on the wheel thread → std::terminate (agent
    // crash). Every other multi-arm test reuses an IDENTICAL spec (dedup →
    // due.size()==1), so this path was never exercised. Without the fix this
    // test crashes the process.
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10); // both specs below clamp to 10ms
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    // Raw intervals 5 and 8 → distinct spark_keys (not deduped) but BOTH floored
    // to the 10ms test floor → identical cadence → identical next_due at start().
    REQUIRE(engine.arm(*ca, interval_spec(5)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(8)).has_value());
    CHECK(engine.stats().armed_sparks == 2); // two distinct armed sparks, not one

    engine.start(); // both scheduled off one `now` → collide on the first tick
    CHECK(eventually([&] { return a.count() >= 2 && b.count() >= 2; }));
    engine.stop();
}

TEST_CASE("SparkEngine: equal specs dedup to one armed spark, fan out to all subscribers",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    REQUIRE(engine.arm(*ca, interval_spec(50)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(50)).has_value());

    CHECK(engine.stats().armed_sparks == 1); // deduped: N consumers, 1 watcher
    CHECK(engine.stats().subscriptions == 2);

    engine.start();
    CHECK(eventually([&] { return a.count() >= 2 && b.count() >= 2; }));
    // One fire, one seq — both consumers observe the SAME event stream.
    CHECK(a.at(0).seq == b.at(0).seq);
    engine.stop();
}

TEST_CASE("SparkEngine: startup spark fires once; late arm still fires once",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    const SparkSpec startup{SparkType::Startup, StartupSparkParams{}};
    REQUIRE(engine.arm(*consumer, startup).has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    std::this_thread::sleep_for(100ms); // one-shot: give a re-fire the chance to (not) happen
    CHECK(got.count() == 1);
    CHECK(got.at(0).type == SparkType::Startup);

    // A late subscriber to the SAME startup spec still gets its one-shot —
    // and the earlier subscriber does NOT see "startup" a second time.
    Collector late;
    auto late_consumer = engine.register_consumer("late", late.handler());
    REQUIRE(late_consumer.has_value());
    REQUIRE(engine.arm(*late_consumer, startup).has_value());
    CHECK(eventually([&] { return late.count() >= 1; }));
    std::this_thread::sleep_for(100ms);
    CHECK(late.count() == 1);
    CHECK(got.count() == 1);

    engine.stop();
}

TEST_CASE("SparkEngine: disk spark emits breach and recovery edges through the wheel",
          "[spark][engine][disk]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    std::atomic<bool> healthy{true};
    engine.set_disk_reader_for_test([&](const std::string&) {
        DiskReading r;
        r.valid = true;
        r.total_bytes = 100 * kGiB;
        r.free_bytes = healthy.load() ? 50 * kGiB : 1 * kGiB;
        return r;
    });
    Collector got;
    auto consumer = engine.register_consumer("dex-ish", got.handler());
    REQUIRE(consumer.has_value());
    SparkSpec spec{SparkType::Disk, DiskSparkParams{"/", 90, 5 * kGiB, 20}};
    REQUIRE(engine.arm(*consumer, spec).has_value());

    engine.start();
    // Healthy polls emit nothing; flip to bad → exactly one Breach.
    healthy = false;
    CHECK(eventually([&] { return got.count() >= 1; }));
    const SparkEvent breach_ev = got.at(0);
    const auto* breach = std::get_if<DiskSparkData>(&breach_ev.data);
    REQUIRE(breach != nullptr);
    CHECK(breach->edge == DiskEdge::Breach);

    // Back to healthy → exactly one Recovery.
    healthy = true;
    CHECK(eventually([&] { return got.count() >= 2; }));
    const SparkEvent recovery_ev = got.at(1);
    const auto* recovery = std::get_if<DiskSparkData>(&recovery_ev.data);
    REQUIRE(recovery != nullptr);
    CHECK(recovery->edge == DiskEdge::Recovery);

    // No further edges while steady.
    std::this_thread::sleep_for(150ms);
    CHECK(got.count() == 2);
    engine.stop();
}

TEST_CASE("SparkEngine: a stuck queued consumer stalls neither watchers nor siblings",
          "[spark][engine][isolation]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    // Heap-allocated: if a scheduling delay ever pushed this wedged handler's
    // wakeup past stop()'s join budget, stop() would detach rather than hang
    // (UP-1) — a still-running detached thread must not reference stack locals
    // destroyed when this TEST_CASE returns (#1957).
    struct Sync {
        std::promise<void> unstick;
        std::shared_future<void> unstick_f = unstick.get_future().share();
        std::atomic<int> stuck_calls{0};
    };
    auto sync = std::make_shared<Sync>();
    auto stuck = engine.register_consumer("stuck", [sync](const SparkEvent&) {
        ++sync->stuck_calls;
        sync->unstick_f.wait(); // deliberately blocked (a popup open for minutes)
    });
    Collector healthy;
    auto ok = engine.register_consumer("healthy", healthy.handler());
    REQUIRE(stuck.has_value());
    REQUIRE(ok.has_value());
    REQUIRE(engine.arm(*stuck, interval_spec(30)).has_value());
    REQUIRE(engine.arm(*ok, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->stuck_calls.load() >= 1; }));
    // The stuck consumer is wedged in its first event — the sibling keeps
    // receiving, which also proves the WATCHER thread never blocked.
    const auto before = healthy.count();
    CHECK(eventually([&] { return healthy.count() >= before + 3; }));

    sync->unstick.set_value(); // release before stop() so the join can complete
    engine.stop();
}

TEST_CASE("SparkEngine: full queue drops oldest and counts, never blocks",
          "[spark][engine][isolation]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    // Heap-allocated: if a scheduling delay ever pushed this wedged handler's
    // wakeup past stop()'s join budget, stop() would detach rather than hang
    // (UP-1) — a still-running detached thread must not reference stack locals
    // destroyed when this TEST_CASE returns (#1957).
    struct Sync {
        std::promise<void> unstick;
        std::shared_future<void> unstick_f = unstick.get_future().share();
        std::atomic<int> calls{0};
    };
    auto sync = std::make_shared<Sync>();
    auto consumer = engine.register_consumer(
        "slow",
        [sync](const SparkEvent&) {
            ++sync->calls;
            sync->unstick_f.wait();
        },
        /*queue_cap=*/2);
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(20)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->calls.load() >= 1; }));
    // Handler wedged: the queue (cap 2) must overflow and drop rather than
    // block the wheel.
    CHECK(eventually([&] { return engine.stats().queued_dropped_total >= 2; }));

    sync->unstick.set_value();
    engine.stop();
}

TEST_CASE("SparkEngine: bounded queue drops the OLDEST — newest survives (drop identity)",
          "[spark][engine][isolation]") {
    // A count-only assertion passes even for a drop-NEWEST bug. Assert identity:
    // the surviving events are the most recent, and an early one was dropped.
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    // Heap-allocated: if a scheduling delay ever pushed this wedged handler's
    // wakeup past stop()'s join budget, stop() would detach rather than hang
    // (UP-1) — a still-running detached thread must not reference stack locals
    // destroyed when this TEST_CASE returns (#1957).
    struct Sync {
        std::promise<void> unstick;
        std::shared_future<void> uf = unstick.get_future().share();
        std::mutex m;
        std::vector<std::uint64_t> got;
        std::atomic<int> calls{0};
    };
    auto sync = std::make_shared<Sync>();
    auto consumer = engine.register_consumer(
        "slow",
        [sync](const SparkEvent& ev) {
            if (++sync->calls == 1)
                sync->uf.wait(); // wedge on the first fire so later fires pile up + drop
            std::lock_guard lk(sync->m);
            sync->got.push_back(ev.seq);
        },
        /*queue_cap=*/2);
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(15)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->calls.load() >= 1; }));                    // wedged on seq 1
    CHECK(eventually([&] { return engine.stats().queued_dropped_total >= 3; })); // middle seqs dropped
    sync->unstick.set_value();
    CHECK(eventually([&] {
        std::lock_guard lk(sync->m);
        return sync->got.size() >= 3;
    }));
    engine.stop();

    std::lock_guard lk(sync->m);
    REQUIRE(sync->got.size() >= 3);
    CHECK(sync->got[0] == 1);      // the wedged first fire
    CHECK(sync->got[1] > 2);       // seq 2 was dropped as oldest → a NEWER seq survived
    CHECK(sync->got[2] > sync->got[1]);  // monotonic — most-recent-wins, not most-recent-lost
}

TEST_CASE("SparkEngine: a handler blocked past the shutdown budget is detached, not hung (UP-1)",
          "[spark][engine]") {
    // Queued handlers may block (network/plugin I/O). stop() must bound the join
    // and DETACH a hung handler rather than hang agent shutdown (#1311 class).
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    engine.set_consumer_join_budget_for_test(120); // shrink the budget for the test
    // Heap-allocated: on budget expiry stop() DETACHES this handler's thread, so
    // it may still be inside cv.wait() reacquiring `m` after this TEST_CASE
    // returns. Stack locals captured by reference would be destroyed out from
    // under it (UAF on the mutex/cv, observed as a libc++ "condition_variable
    // wait failed" abort in an unrelated later test) — the shared_ptr keeps
    // them alive for as long as the detached thread is still running.
    struct Sync {
        std::mutex m;
        std::condition_variable cv;
        bool release = false;
        std::atomic<bool> in_handler{false};
        std::atomic<bool> finished{false}; // confirms the detached thread actually wakes
    };
    auto sync = std::make_shared<Sync>();
    auto consumer = engine.register_consumer("blocker", [sync](const SparkEvent&) {
        sync->in_handler.store(true);
        {
            std::unique_lock lk(sync->m);
            sync->cv.wait(lk, [&] { return sync->release; }); // block until the test frees us
        }
        sync->finished.store(true);
    });
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(20)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->in_handler.load(); })); // handler is now wedged

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop(); // MUST return within ~budget, not block on the wedged handler
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < 2000ms); // bounded (budget 120ms + generous slack), not hung
    CHECK(engine.stats().consumer_threads_detached >= 1);

    // Free the detached handler so its thread exits cleanly (no leaked blocker),
    // and confirm it actually does — a broken release/wakeup path would otherwise
    // leave the thread parked forever without failing anything.
    {
        std::lock_guard lk(sync->m);
        sync->release = true;
    }
    sync->cv.notify_all();
    CHECK(eventually([&] { return sync->finished.load(); }));
}

TEST_CASE("SparkEngine: N blocked handlers detach against ONE shared budget, not N× (UP2-3)",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    engine.set_consumer_join_budget_for_test(200);
    // Heap-allocated for the same reason as the UP-1 test above: the detached
    // handler threads may still be running (inside cv.wait()) after this
    // TEST_CASE returns, so stack locals captured by reference are unsafe.
    struct Sync {
        std::mutex m;
        std::condition_variable cv;
        bool release = false;
        std::atomic<int> wedged{0};
        std::atomic<int> finished{0}; // confirms every detached thread actually wakes
    };
    auto sync = std::make_shared<Sync>();
    auto blocker = [sync](const SparkEvent&) {
        sync->wedged.fetch_add(1);
        {
            std::unique_lock lk(sync->m);
            sync->cv.wait(lk, [&] { return sync->release; });
        }
        sync->finished.fetch_add(1);
    };
    for (int i = 0; i < 3; ++i) {
        auto c = engine.register_consumer("blk" + std::to_string(i), blocker);
        REQUIRE(c.has_value());
        REQUIRE(engine.arm(*c, interval_spec(20)).has_value()); // dedups → 1 spark, 3 subs
    }
    engine.start();
    CHECK(eventually([&] { return sync->wedged.load() >= 3; })); // all 3 handlers wedged

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    // Serial join-then-detach would be 3×200ms=600ms; the shared deadline makes
    // it ~200ms. Assert well under the serial cost (generous ceiling for CI jitter).
    CHECK(elapsed < 450ms);
    CHECK(engine.stats().consumer_threads_detached >= 3);

    {
        std::lock_guard lk(sync->m);
        sync->release = true;
    }
    sync->cv.notify_all();
    CHECK(eventually([&] { return sync->finished.load() >= 3; }));
}

TEST_CASE("SparkEngine: inline tier runs on the watcher thread and is duration-accounted",
          "[spark][engine][inline]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    // No Catch2 assertions inside the handler — it runs on the watcher thread
    // and Catch2 macros are not thread-safe. Capture, assert on the main thread.
    std::atomic<int> inline_calls{0};
    std::atomic<bool> type_ok{true};
    auto sub = engine.arm_inline(interval_spec(30), [&](const SparkEvent& ev) {
        const int n = ++inline_calls;
        if (ev.type != SparkType::Interval)
            type_ok = false;
        if (n == 1)
            std::this_thread::sleep_for(2ms); // make the watchdog measurably time a call
        if (n == 2)
            throw std::runtime_error("contract breach"); // watcher must survive
    });
    REQUIRE(sub.has_value());

    engine.start();
    CHECK(eventually([&] { return inline_calls.load() >= 4; })); // survived the throw
    engine.stop();

    CHECK(type_ok.load());
    const auto stats = engine.stats();
    CHECK(stats.inline_calls_total >= 4);
    CHECK(stats.inline_errors_total == 1);
    CHECK(stats.inline_us_max >= 1000);      // the 2ms call was actually timed
    CHECK(stats.inline_over_100us_total >= 1); // ...and hit the tail counter
}

TEST_CASE("SparkEngine: disarm stops delivery; last disarm removes the watcher entry",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    auto sub = engine.arm(*consumer, interval_spec(30));
    REQUIRE(sub.has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.disarm(*sub);
    CHECK(engine.stats().armed_sparks == 0);
    // Let anything already in-queue at disarm time drain before baselining.
    std::this_thread::sleep_for(50ms);
    const auto after = got.count();
    std::this_thread::sleep_for(150ms);
    CHECK(got.count() == after); // nothing delivered after disarm
    engine.disarm(*sub);         // idempotent
    engine.stop();
}

TEST_CASE("SparkEngine: arming validation", "[spark][engine]") {
    SparkEngine engine;
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());

    // Unknown consumer.
    CHECK_FALSE(engine.arm(9999, interval_spec(60'000)).has_value());

    // Mechanisms not in this slice are rejected loudly, not silently inert.
    CHECK_FALSE(engine.arm(*consumer, SparkSpec{SparkType::File, FileSparkParams{"/etc/hosts"}})
                    .has_value());
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Service, ServiceSparkParams{"sshd"}})
            .has_value());
    CHECK_FALSE(engine
                    .arm(*consumer,
                         SparkSpec{SparkType::Registry, RegistrySparkParams{"HKLM", "SOFTWARE"}})
                    .has_value());

    // Type/params mismatch.
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Disk, IntervalSparkParams{60'000}}).has_value());

    // Disk param sanity.
    CHECK_FALSE(engine.arm(*consumer, SparkSpec{SparkType::Disk, DiskSparkParams{"", 90, 0, 0}})
                    .has_value());
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Disk, DiskSparkParams{"/", 101, 0, 0}})
            .has_value());

    // Null handlers / empty names.
    CHECK_FALSE(engine.register_consumer("x", nullptr).has_value());
    CHECK_FALSE(engine.register_consumer("", got.handler()).has_value());
    CHECK_FALSE(engine.arm_inline(interval_spec(60'000), nullptr).has_value());
}

TEST_CASE("SparkEngine: unregister_consumer removes its subscriptions and joins its thread",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    REQUIRE(engine.arm(*ca, interval_spec(30)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    engine.unregister_consumer(*ca);
    CHECK(engine.stats().consumers == 1);
    CHECK(engine.stats().subscriptions == 1); // a's subscription went with it
    CHECK(engine.stats().armed_sparks == 1);  // b still holds the shared spark

    const auto a_after = a.count();
    const auto b_before = b.count();
    CHECK(eventually([&] { return b.count() >= b_before + 2; })); // b unaffected
    CHECK(a.count() == a_after);
    engine.stop();
}

TEST_CASE("SparkEngine: register_consumer racing stop() never strands an unjoined "
          "thread (governance Tr3kkR finding, PR #1927)",
          "[spark][engine]") {
    // Forces the exact interleaving the fix closes: stop() lands after
    // register_consumer's dispatch thread has started but before it is
    // inserted into consumers_. Before the fix, the insert proceeded
    // unconditionally — the new consumer was never signalled by stop(), and
    // its still-joinable std::thread inside consumers_ would std::terminate
    // the process (an un-joined joinable std::thread's destructor) once the
    // engine was destroyed.
    SparkEngine engine;
    engine.start();
    engine.set_register_race_hook_for_test([&] { engine.stop(); });

    Collector got;
    auto consumer = engine.register_consumer("racer", got.handler());

    // Lost the race: register_consumer must report failure, not silently
    // succeed into a stopped engine.
    CHECK_FALSE(consumer.has_value());
    CHECK(engine.stats().consumers == 0);
    CHECK_FALSE(engine.is_running());

    // ~SparkEngine (end of scope) must not terminate. That IS the regression
    // this test exists to catch: a joinable std::thread reachable from a live
    // shared_ptr<Consumer> at destruction crashes the whole test binary
    // (std::terminate), not just fails an assertion.
}

TEST_CASE("SparkEngine: register_consumer vs stop() under REAL concurrent scheduling "
          "never crashes (stress, governance quality-engineer finding, PR #1927)",
          "[spark][engine][stress]") {
    // The deterministic hook-based test above proves the re-check-then-branch
    // LOGIC is correct, but runs entirely on one thread — it would pass
    // identically even if stopped_ were reverted to a plain (non-atomic)
    // bool, since nothing there needs a second thread's write to become
    // visible. This test exercises the actual cross-thread memory-ordering
    // half of the fix with real concurrent scheduling and no seam, so a
    // future regression back to a non-atomic stopped_ has a real chance of
    // being caught here — and under the nightly TSan leg, which this test
    // is written for.
    for (int trial = 0; trial < 500; ++trial) {
        SparkEngine engine;
        engine.start();
        std::atomic<bool> go{false};
        std::thread registrar([&] {
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            // Result intentionally unchecked: either outcome (won or lost the
            // race) is valid. A no-op handler captures nothing, so even a
            // detached-but-never-armed consumer thread (see the sibling
            // deterministic test's own reasoning) can never touch freed test
            // state.
            (void)engine.register_consumer("racer", [](const SparkEvent&) {});
        });
        go.store(true, std::memory_order_release);
        engine.stop();
        registrar.join();
    }
    SUCCEED("500 concurrent register_consumer()/stop() trials completed without a crash or hang");
}

TEST_CASE("SparkEngine: stop is prompt and idempotent; engine is single-shot",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
    CHECK_FALSE(engine.is_running());
    engine.stop(); // idempotent

    // Single-shot: a restart attempt is refused, and post-stop arms fail.
    engine.start();
    CHECK_FALSE(engine.is_running());
    CHECK_FALSE(engine.arm(*consumer, interval_spec(30)).has_value());
    CHECK_FALSE(engine.register_consumer("post-stop", got.handler()).has_value());
}

namespace {
/// Fake event-driven mechanism reporting a FIXED SparkMechanismStats — verifies
/// the per-type breakdown (stats_by_type) and the engine-level mech_* sums
/// (#2011 rung 1) without needing a platform mechanism or any real watch.
struct StatStubMechanism : ISparkMechanism {
    SparkMechanismStats fixed;
    explicit StatStubMechanism(SparkMechanismStats s) : fixed(s) {}
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {}
    [[nodiscard]] SparkMechanismStats stats() const override { return fixed; }
};

/// Fault injector: start() throws (mimics thread-creation failure under EAGAIN),
/// used to prove SparkEngine tears down cleanly after a mid-boot throw.
struct ThrowingStartMechanism : ISparkMechanism {
    void start(SparkEmitFn, SparkFaultFn) override { throw std::runtime_error("start boom"); }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {}
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};

/// Parks inside stop() until released, so a test can hold a teardown open and force
/// ~SparkEngine to race an in-flight stop(). Models the real interleave: the Windows
/// SCM control thread is inside Agent::stop() while the main thread destroys the agent.
struct ParkingStopMechanism : ISparkMechanism {
    std::atomic<bool>& inside;
    std::atomic<bool>& release;
    ParkingStopMechanism(std::atomic<bool>& i, std::atomic<bool>& r) : inside(i), release(r) {}
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {
        inside.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire))
            std::this_thread::yield();
    }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};

/// Acquires a resource, THEN throws from start() — the exact shape of the real
/// LinuxServiceMechanism bug (governance Gate-3 cpp-safety B1): it published bus_ and
/// wake_fd_ and then the std::thread ctor threw EAGAIN, leaving started_ false, so its
/// bool-guarded stop() early-returned and leaked both fds for the process lifetime.
///
/// ThrowingStartMechanism above CANNOT catch that class — it holds nothing and its
/// stop() is empty, so it gives false confidence on precisely the path it was written
/// to cover. This one holds a resource and records its release.
struct LeakyThrowingMechanism : ISparkMechanism {
    bool& held; ///< set on acquire, cleared on release — the "fd"
    explicit LeakyThrowingMechanism(bool& h) : held(h) {}
    void start(SparkEmitFn, SparkFaultFn) override {
        held = true;                                  // acquire (bus_ / wake_fd_)
        throw std::runtime_error("thread ctor boom"); // then EAGAIN, before started_ = true
    }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    // Guards on the RESOURCE, not on a started_ bool — the fix under test.
    void stop() override { held = false; }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};
} // namespace

TEST_CASE("stats_by_type preserves the per-mechanism-type breakdown", "[spark][stats]") {
    SparkEngine engine;

    SparkMechanismStats file_stats;
    file_stats.retiring = 3;
    file_stats.retiring_cap = 256;
    file_stats.watch_rejected_total = 2;
    file_stats.quarantined_total = 1;
    file_stats.slow_op_total = 4;
    SparkMechanismStats svc_stats;
    svc_stats.watch_rejected_total = 5;
    svc_stats.slow_op_total = 7;

    REQUIRE(engine.register_mechanism(SparkType::File,
                                      std::make_unique<StatStubMechanism>(file_stats))
                .has_value());
    REQUIRE(engine.register_mechanism(SparkType::Service,
                                      std::make_unique<StatStubMechanism>(svc_stats))
                .has_value());

    // Per-type: keys preserved, only registered types appear, values not blended.
    const auto by_type = engine.stats_by_type();
    REQUIRE(by_type.size() == 2);
    REQUIRE(by_type.contains(SparkType::File));
    REQUIRE(by_type.contains(SparkType::Service));
    CHECK(by_type.at(SparkType::File).watch_rejected_total == 2);
    CHECK(by_type.at(SparkType::File).retiring_cap == 256);
    CHECK(by_type.at(SparkType::Service).watch_rejected_total == 5);
    CHECK(by_type.at(SparkType::Service).slow_op_total == 7);

    // Engine-level sum folds them together, including the new mech_retiring_cap.
    const auto s = engine.stats();
    CHECK(s.mech_watch_rejected_total == 7); // 2 + 5
    CHECK(s.mech_quarantined_total == 1);    // 1 + 0
    CHECK(s.mech_slow_op_total == 11);       // 4 + 7
    CHECK(s.mech_retiring == 3);             // 3 + 0
    CHECK(s.mech_retiring_cap == 256);       // 256 + 0
}

TEST_CASE("emit_spark_heartbeat_tags: always-present keys + sparse counters", "[spark][stats]") {
    std::map<std::string, std::string> tags;

    SECTION("quiescent engine (rung-1 steady state) ships only the capability keys") {
        SparkEngineStats ss;                          // all zero
        std::map<SparkType, SparkMechanismStats> by_type;
        by_type[SparkType::File] = {};
        by_type[SparkType::Service] = {};
        emit_spark_heartbeat_tags(tags, /*running=*/true, ss, by_type);

        CHECK(tags.at("yuzu.spark_running") == "1");
        CHECK(tags.at("yuzu.spark_mechs") == "file,service"); // map order: File(3) < Service(4)
        // No counter tags when every counter is 0 (sparse).
        CHECK(tags.size() == 2);
    }

    SECTION("non-zero counters emit; zero counters stay absent") {
        SparkEngineStats ss;
        ss.armed_faulted = 2;
        ss.watch_faults_total = 9;
        // queued_dropped_total and consumer_errors_total stay 0 -> absent.
        std::map<SparkType, SparkMechanismStats> by_type;
        SparkMechanismStats file_stats;
        file_stats.watch_rejected_total = 4;
        file_stats.slow_op_total = 1;
        // quarantined_total 0 -> absent.
        by_type[SparkType::File] = file_stats;
        emit_spark_heartbeat_tags(tags, /*running=*/true, ss, by_type);

        CHECK(tags.at("yuzu.spark_running") == "1");
        CHECK(tags.at("yuzu.spark_mechs") == "file");
        CHECK(tags.at("yuzu.spark_armed_faulted") == "2");
        CHECK(tags.at("yuzu.spark_watch_faults") == "9");
        CHECK_FALSE(tags.contains("yuzu.spark_queued_dropped"));
        CHECK_FALSE(tags.contains("yuzu.spark_consumer_errors"));
        CHECK(tags.at("yuzu.spark_file_watch_rejected") == "4");
        CHECK(tags.at("yuzu.spark_file_slow_op") == "1");
        CHECK_FALSE(tags.contains("yuzu.spark_file_quarantined"));
    }
}

TEST_CASE("emit_spark_heartbeat_tags: the four postures stay distinguishable",
          "[spark][stats]") {
    // Rung 1 exists to prove the engine runs and reports AT REST. That is worthless if
    // a boot FAILURE is indistinguishable from a deliberate opt-out and from an agent
    // that never had spark at all — a fleet-wide failure would simply go quiet.
    // (governance Gate-4 consistency + UP-10.)
    SparkEngineStats ss;
    std::map<SparkType, SparkMechanismStats> by_type;
    by_type[SparkType::Service] = {};

    SECTION("RUNNING -> running=1 + capability CSV") {
        std::map<std::string, std::string> tags;
        emit_spark_heartbeat_tags(tags, /*running=*/true, ss, by_type);
        CHECK(tags.at("yuzu.spark_running") == "1");
        CHECK(tags.at("yuzu.spark_mechs") == "service");
        CHECK_FALSE(tags.contains("yuzu.spark_disabled"));
    }

    SECTION("FAILED (enabled, boot threw) -> running=0, NO disabled key") {
        std::map<std::string, std::string> tags;
        emit_spark_absent_tags(tags, /*disabled=*/false);
        CHECK(tags.at("yuzu.spark_running") == "0");
        CHECK_FALSE(tags.contains("yuzu.spark_disabled"));
        CHECK(tags.size() == 1);
    }

    SECTION("DISABLED (--spark-disable) -> running=0 AND disabled=1") {
        std::map<std::string, std::string> tags;
        emit_spark_absent_tags(tags, /*disabled=*/true);
        CHECK(tags.at("yuzu.spark_running") == "0");
        CHECK(tags.at("yuzu.spark_disabled") == "1");
    }

    SECTION("a STOPPED engine emits NOTHING — it must not report running, nor FAILED") {
        // Two bugs, one section.
        //
        // UP-4: the old code hardcoded running="1", so after Agent::stop() had called
        // spark_engine_->stop() the still-non-null pointer shipped a healthy-looking
        // capability report from a STOPPED engine. `running` now comes from is_running().
        //
        // And the first fix for that was ALSO wrong: it degraded a stopped engine to the
        // FAILED posture (`spark_running=0`). But a graceful shutdown reaches exactly this
        // path — Agent::stop() and run()'s ScopeExit both stop the engine while the
        // heartbeat thread can still compose one more beat — so the server would have
        // counted every cleanly-restarting agent into yuzu_fleet_spark_failed{os}, the ONE
        // gauge documented "alert on it". Every systemctl restart and every OTA cycle
        // would page. STOPPED is not FAILED (Gate-2 security + Gate-3 cross-platform).
        //
        // Correct contract: a constructed-but-not-running engine emits NO spark tags at
        // all (ABSENT). FAILED is reserved for "enabled, but the engine is null because
        // boot-time instantiation threw", which only the caller can know.
        std::map<std::string, std::string> tags;
        emit_spark_heartbeat_tags(tags, /*running=*/false, ss, by_type);
        CHECK(tags.empty());
    }
}

TEST_CASE("emit_spark_heartbeat_tags: an INERT mechanism is not claimed as capability",
          "[spark][stats]") {
    // A mechanism that started but could not bind its OS facility (no systemd system
    // bus in a container, OpenSCManager denied, IOCP failed) stays REGISTERED so arm()
    // gets an honest rejection — but every watch() on it WILL be refused. Advertising
    // it in the capability CSV tells the fleet the agent can detect things it cannot:
    // "looks healthy, can detect nothing". Reached independently by Gate-3
    // cross-platform and Gate-6 sre.
    SparkEngineStats ss;
    std::map<SparkType, SparkMechanismStats> by_type;

    SparkMechanismStats live;                 // functional
    SparkMechanismStats dead;
    dead.inert = true;                        // e.g. containerised Linux: no system bus
    dead.watch_rejected_total = 7;            // still reports its counters
    by_type[SparkType::File] = live;
    by_type[SparkType::Service] = dead;

    std::map<std::string, std::string> tags;
    emit_spark_heartbeat_tags(tags, /*running=*/true, ss, by_type);

    // Capability lists ONLY the functional mechanism.
    CHECK(tags.at("yuzu.spark_mechs") == "file");
    // But inertness does not suppress telemetry — the counters still ship.
    CHECK(tags.at("yuzu.spark_service_watch_rejected") == "7");
}

TEST_CASE("emit_spark_heartbeat_tags: every mechanism inert -> empty capability CSV",
          "[spark][stats]") {
    // The macOS shape (all three factories return nullptr -> no mechanisms at all) and
    // the all-inert shape must both yield an EMPTY capability CSV while still reporting
    // spark_running=1 — the agent is running spark, it just cannot detect anything here.
    SparkEngineStats ss;

    SECTION("no mechanisms registered at all (macOS)") {
        std::map<SparkType, SparkMechanismStats> by_type; // empty
        std::map<std::string, std::string> tags;
        emit_spark_heartbeat_tags(tags, /*running=*/true, ss, by_type);
        CHECK(tags.at("yuzu.spark_running") == "1");
        CHECK(tags.at("yuzu.spark_mechs").empty());
        CHECK(tags.size() == 2);
    }

    SECTION("registered but all inert (container Linux)") {
        std::map<SparkType, SparkMechanismStats> by_type;
        SparkMechanismStats dead;
        dead.inert = true;
        by_type[SparkType::Service] = dead;
        std::map<std::string, std::string> tags;
        emit_spark_heartbeat_tags(tags, /*running=*/true, ss, by_type);
        CHECK(tags.at("yuzu.spark_running") == "1");
        CHECK(tags.at("yuzu.spark_mechs").empty());
    }
}

TEST_CASE("stats_by_type / stats are safe to call after stop()", "[spark][stats]") {
    // The heartbeat thread can call these AFTER the agent's stop()/engine stop() and
    // before it is joined — a stopped engine is a live object and mechanisms_ is not
    // cleared by stop(), so the read must stay valid (gov cs-S1 / UP-9).
    SparkEngine engine;
    SparkMechanismStats ms;
    ms.watch_rejected_total = 3;
    REQUIRE(
        engine.register_mechanism(SparkType::Service, std::make_unique<StatStubMechanism>(ms))
            .has_value());
    engine.start();
    engine.stop();

    const auto by_type = engine.stats_by_type();
    REQUIRE(by_type.size() == 1);
    CHECK(by_type.at(SparkType::Service).watch_rejected_total == 3);
    CHECK(engine.stats().mech_watch_rejected_total == 3);
    CHECK_FALSE(engine.is_running());
}

TEST_CASE("register_mechanism failure leaks nothing and leaves the engine usable",
          "[spark][stats]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File,
                                      std::make_unique<StatStubMechanism>(SparkMechanismStats{}))
                .has_value());
    // Duplicate for the same type is rejected; the rejected mechanism is freed by
    // register_mechanism's by-value param (no leak — ASan-clean under sanitizer runs).
    CHECK_FALSE(engine.register_mechanism(SparkType::File,
                                          std::make_unique<StatStubMechanism>(SparkMechanismStats{}))
                    .has_value());
    // A timer-driven type has no mechanism and is rejected too.
    CHECK_FALSE(engine.register_mechanism(SparkType::Interval,
                                          std::make_unique<StatStubMechanism>(SparkMechanismStats{}))
                    .has_value());
    // The engine still holds exactly the one good mechanism.
    CHECK(engine.stats_by_type().size() == 1);
}

TEST_CASE("SparkEngine tears down cleanly when a mechanism start() throws", "[spark][stats]") {
    // Mirrors the agent's degrade-to-no-spark path (gov cs-S2): start() propagates a
    // mechanism start() throw, and the engine must then destruct cleanly — joining the
    // wheel already spawned and no-opping the un-started mechanisms — with no crash,
    // hang, double-join, or leak (the property the agent's try/catch + reset() relies
    // on; TSan exercises the emit-during-unwind vs join race here).
    auto engine = std::make_unique<SparkEngine>();
    // File registers first (SparkType::File=3 < Service=4), starts as a no-op; Service
    // throws — so the wheel is up and one mechanism is started when the throw fires.
    REQUIRE(engine
                ->register_mechanism(SparkType::File,
                                     std::make_unique<StatStubMechanism>(SparkMechanismStats{}))
                .has_value());
    REQUIRE(engine->register_mechanism(SparkType::Service, std::make_unique<ThrowingStartMechanism>())
                .has_value());

    bool threw = false;
    try {
        engine->start();
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw); // start() propagated the mechanism throw (the agent catches it)

    engine.reset(); // ~SparkEngine → stop(): must not crash / hang / leak
    SUCCEED("engine destroyed cleanly after a partial-start throw");
}

TEST_CASE("a mechanism that ACQUIRES then throws from start() still gets released",
          "[spark][teardown]") {
    // Governance Gate-3 cpp-safety B1. The real LinuxServiceMechanism published its
    // sd_bus connection and eventfd, then the std::thread ctor threw EAGAIN — the very
    // thread-exhaustion case agent.cpp's degrade-to-no-spark guard exists to survive.
    // started_ was never set, its stop() early-returned on `if (!started_)`, and BOTH
    // fds leaked for the process lifetime (the dtor calls the same stop(), so it could
    // not recover either). The fix guards stop() on the RESOURCE, as the Windows
    // mechanisms already did.
    //
    // This pins the ENGINE half of the contract: a mechanism that threw from start()
    // must still have stop() called on it, so a resource-guarded stop() can release.
    //
    // #2050 DELIBERATE TIMING-CONTRACT CHANGE, stated explicitly (not a silent
    // assertion flip): start() now carries its own function-wide rollback
    // guard, which calls the SAME teardown as stop() on a mid-startup throw — so the
    // throwing mechanism's stop() (and therefore its release) now runs SYNCHRONOUSLY
    // inside start(), before start() returns the exception to its caller. The OLD
    // contract asserted release only at ~SparkEngine (cleanup-at-destruction); the NEW
    // one asserts it immediately (cleanup-at-throw). This does NOT reopen B1: the fix
    // that actually prevented the leak was guarding stop() on RESOURCE OWNERSHIP
    // (LeakyThrowingMechanism::stop() below), not on a started_ bool — that guard is
    // orthogonal to WHEN stop() is called, so moving the call earlier cannot
    // reintroduce the bug. See spark_engine.cpp's start() for the rollback guard and
    // its exact scope-placement rationale.
    bool held = false;
    {
        auto engine = std::make_unique<SparkEngine>();
        REQUIRE(engine
                    ->register_mechanism(SparkType::Service,
                                         std::make_unique<LeakyThrowingMechanism>(held))
                    .has_value());
        CHECK_FALSE(held);
        CHECK_THROWS(engine->start()); // acquires, then throws
        // NEW: released BEFORE engine.reset() — start()'s own rollback guard already
        // drove the teardown (and set teardown_complete_) by the time start() returns.
        CHECK_FALSE(held);
        engine.reset(); // ~SparkEngine → stop(): now a no-op (already torn down); must
                        // still not crash/hang, and must not re-acquire anything.
    }
    CHECK_FALSE(held); // still released after destruction — teardown fully completed
}

TEST_CASE("stop() racing ~SparkEngine does not terminate or use-after-free",
          "[spark][teardown]") {
    // Governance Gate-3 B3 / Gate-4 UP-1. stop()'s `if (stopped_) return;` had NO
    // completion barrier: the LOSER of the race returned immediately while the WINNER
    // was still inside wheel_thread_.join() and m->stop(). So ~SparkEngine could run on
    // to ~std::thread on a still-JOINABLE wheel thread (std::terminate), and destroy
    // mechanisms_ out from under the thread still executing m->stop() on them (UAF).
    //
    // NOT hypothetical: Agent::stop() is invoked from the Windows SCM control thread
    // (service_win.cpp handler_ex) concurrently with the main thread's teardown.
    //
    // The fix holds lifecycle_mu_ across the WHOLE of stop(), so ~SparkEngine's stop()
    // BLOCKS until the in-flight one has finished. This test forces the exact interleave:
    // the stopper is provably INSIDE the teardown (parked in the mechanism's stop())
    // before the destructor runs. Without the barrier the destructor sails past the
    // stopped_ flag and frees mechanisms_ under it. Run under TSan/ASan to see it.
    std::atomic<bool> stopper_inside{false};
    std::atomic<bool> release_stopper{false};

    auto engine = std::make_unique<SparkEngine>();
    REQUIRE(engine
                ->register_mechanism(SparkType::Service,
                                     std::make_unique<ParkingStopMechanism>(stopper_inside,
                                                                            release_stopper))
                .has_value());
    engine->start();

    // Raw pointer: the stopper models Agent::stop() on the SCM thread, which calls
    // through a still-live member while the main thread is tearing down. Safe ONLY
    // because ~SparkEngine must now block until this stop() returns — which is the
    // invariant under test.
    SparkEngine* raw = engine.get();
    std::thread stopper([raw] { raw->stop(); });

    // Park until the stopper is demonstrably inside the mechanism teardown.
    while (!stopper_inside.load(std::memory_order_acquire))
        std::this_thread::yield();

    // Now destroy the engine. ~SparkEngine → stop() → MUST block on lifecycle_mu_.
    // Let the stopper finish only after the destructor has had the chance to race it.
    std::thread releaser([&] {
        std::this_thread::sleep_for(50ms);
        release_stopper.store(true, std::memory_order_release);
    });
    engine.reset(); // blocks until the stopper's teardown completes

    stopper.join();
    releaser.join();
    SUCCEED("~SparkEngine waited for the in-flight stop() instead of racing it");
}

TEST_CASE("stop() on a started-but-never-armed engine releases every mechanism",
          "[spark][teardown]") {
    // Rung 1 is the FIRST caller of SparkEngine::start() in production, and it never
    // arms anything — so "started, never armed, then stopped" is a brand-new code path
    // that nothing previously exercised (governance Gate-3 cpp-safety SHOULD).
    SparkEngine engine;
    SparkMechanismStats ms;
    REQUIRE(engine.register_mechanism(SparkType::File, std::make_unique<StatStubMechanism>(ms))
                .has_value());
    REQUIRE(engine.register_mechanism(SparkType::Service, std::make_unique<StatStubMechanism>(ms))
                .has_value());
    engine.start();
    CHECK(engine.is_running());
    engine.stop();
    CHECK_FALSE(engine.is_running());
    engine.stop(); // idempotent, and must not block on itself
    SUCCEED("start-then-stop without arming is clean");
}

namespace {
/// stop() throws on its FIRST call only, counting every call. Drives the
/// teardown-retry contract: stop() is noexcept-with-catch, and a throw mid-teardown
/// must leave teardown_complete_ FALSE so the NEXT caller re-drives the mechanism
/// teardown instead of latching the failure away (governance Gate-3 QE-1 — this
/// branch's headline teardown-safety claim, previously asserted only in comments).
struct ThrowingStopMechanism : ISparkMechanism {
    int& stop_calls;
    explicit ThrowingStopMechanism(int& c) : stop_calls(c) {}
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {
        if (++stop_calls == 1)
            throw std::runtime_error("teardown boom");
    }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};

/// Counting no-throw sibling: proves the retry re-drives mechanisms the first,
/// throwing pass never reached.
struct CountingStopMechanism : ISparkMechanism {
    int& stop_calls;
    explicit CountingStopMechanism(int& c) : stop_calls(c) {}
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override { ++stop_calls; }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};
} // namespace

TEST_CASE("a throwing teardown is retried by the next stop(), not latched away",
          "[spark][teardown]") {
    // The early-out is on teardown_complete_, NOT stopped_ — conflating them was a
    // regression during this fix's own review (Gate-8 security-guardian), and this
    // test is what makes that regression go red instead of shipping green: if stop()
    // early-outed on stopped_, the second stop() below would be a no-op and a
    // never-stopped mechanism would stay that way forever.
    //
    // #2050 DELIBERATE CONTRACT CHANGE, stated explicitly (not a silent assertion
    // flip): stop()'s mechanism-teardown loop is now PER-ITERATION isolated — one
    // mechanism's stop() throwing no longer skips every mechanism after it in map
    // order. So on THIS test's first pass, Service (File < Service in the map, so it
    // iterates second) now DOES get its stop() called even though File's throws —
    // where the OLD contract left it at 0 until the retry pass ("never reached past
    // the throw"). What is UNCHANGED: a per-mechanism failure still leaves
    // teardown_complete_ false, so File — the one that actually failed — is still
    // retried (idempotently) on the next pass, and that retry now re-drives EVERY
    // mechanism again (idempotent by interface contract), not just the one that
    // failed last time.
    int file_stops = 0;
    int service_stops = 0;
    SparkEngine engine;
    REQUIRE(engine
                .register_mechanism(SparkType::File,
                                    std::make_unique<ThrowingStopMechanism>(file_stops))
                .has_value());
    REQUIRE(engine
                .register_mechanism(SparkType::Service,
                                    std::make_unique<CountingStopMechanism>(service_stops))
                .has_value());
    engine.start();
    REQUIRE(engine.is_running());

    // First stop(): File's stop() throws. stop() is noexcept — the throw must be
    // contained WITHOUT skipping Service (per-iteration isolation), and the teardown
    // must NOT be marked complete (File's own failure this pass).
    engine.stop();
    CHECK(file_stops == 1);
    CHECK(service_stops == 1); // NEW: reached despite File's throw, same pass
    CHECK_FALSE(engine.is_running());

    // Second stop() (in production: ~SparkEngine's) must RE-DRIVE the mechanism
    // teardown — both mechanisms again — and complete cleanly this time.
    engine.stop();
    CHECK(file_stops == 2);    // re-driven (idempotent contract), no throw this time
    CHECK(service_stops == 2); // re-driven too — the whole pass retries, not just File

    // Third stop(): teardown_complete_ is finally latched — a genuine no-op now.
    engine.stop();
    CHECK(file_stops == 2);
    CHECK(service_stops == 2);
}

namespace {
/// #2050: benign resource-tracking mechanism — start() acquires (held=true), stop()
/// releases (held=false), set_established_sink() is the boring default (returns
/// false, never throws). Used as the FIRST-STARTED SIBLING in the sink-fallibility
/// tests below: SparkType::File (3) sorts before Service (4) in mechanisms_'s
/// std::map, so this one's start() has ALREADY COMPLETED by the time a
/// Service-registered sink throws — the rollback must reach this already-started
/// sibling too, not only the mechanism that threw.
struct ResourceTrackingMechanism : ISparkMechanism {
    bool& held;
    explicit ResourceTrackingMechanism(bool& h) : held(h) {}
    void start(SparkEmitFn, SparkFaultFn) override { held = true; }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override { held = false; }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};

/// #2050: set_established_sink() throws BEFORE performing its own "store" (mirrors
/// spark_service.cpp's `established_ = std::move(sink)` member assignment — the
/// EARLIER of the two fallibility windows). set_established_sink() is called BEFORE
/// this mechanism's OWN start() in start()'s per-mechanism loop, so this throw
/// preempts that start() entirely — stop_calls, not a resource flag, is what proves
/// the rollback still reached this mechanism via the authoritative mechanisms_ map.
struct SinkThrowsBeforeStoreMechanism : ISparkMechanism {
    int& stop_calls;
    explicit SinkThrowsBeforeStoreMechanism(int& c) : stop_calls(c) {}
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    bool set_established_sink(SparkEstablishedFn) override {
        throw std::runtime_error("sink boom before store");
    }
    void stop() override { ++stop_calls; }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};

/// #2050: set_established_sink() completes its "store" (models
/// `established_ = std::move(sink)`), THEN throws — the LATER of the two
/// fallibility windows. Same preemption note as the BeforeStore sibling above: this
/// mechanism's own start() never runs either, since the throw escapes before
/// start()'s per-mechanism loop reaches the m->start() call for this entry.
struct SinkThrowsAfterStoreMechanism : ISparkMechanism {
    int& stop_calls;
    SparkEstablishedFn sink; ///< the "store"
    explicit SinkThrowsAfterStoreMechanism(int& c) : stop_calls(c) {}
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    bool set_established_sink(SparkEstablishedFn s) override {
        sink = std::move(s); // store completes before the throw
        throw std::runtime_error("sink boom after store");
    }
    void stop() override { ++stop_calls; }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};
} // namespace

TEST_CASE("start()'s rollback guard covers set_established_sink() throwing, both "
          "before and after its store",
          "[spark][teardown]") {
    // #2050 scope item 2: set_established_sink() (spark_mechanism.hpp:271,
    // [[nodiscard]] bool, no noexcept) is a confirmed-fallible site the start()
    // rollback guard must cover — installed BEFORE m->start() FOR THE SAME
    // mechanism (spark_engine.cpp), so a throw here preempts that mechanism's own
    // start(). Two mechanisms are registered so the assertions actually distinguish
    // "rollback ran" from "nothing happened yet" (a single sink-thrower's own
    // start() never runs, so a resource flag on it alone would pass vacuously):
    // File starts first and fully completes, Service's sink then throws, and the
    // rollback must reach BOTH — the already-started File sibling (file_held) and
    // the throwing Service mechanism itself (service_stops), against the shipped
    // overrides' actual shape (spark_service.cpp:283-288 / :1542-1547 assign a
    // member then return).
    SECTION("throws BEFORE storing the callback") {
        bool file_held = false;
        int service_stops = 0;
        auto engine = std::make_unique<SparkEngine>();
        REQUIRE(engine
                    ->register_mechanism(SparkType::File,
                                         std::make_unique<ResourceTrackingMechanism>(file_held))
                    .has_value());
        REQUIRE(engine
                    ->register_mechanism(
                        SparkType::Service,
                        std::make_unique<SinkThrowsBeforeStoreMechanism>(service_stops))
                    .has_value());
        CHECK_THROWS(engine->start());
        CHECK_FALSE(file_held);    // File fully started, then rolled back
        CHECK(service_stops == 1); // Service's stop() reached despite never starting
        engine.reset();
        CHECK_FALSE(file_held);
    }
    SECTION("throws AFTER storing the callback") {
        bool file_held = false;
        int service_stops = 0;
        auto engine = std::make_unique<SparkEngine>();
        REQUIRE(engine
                    ->register_mechanism(SparkType::File,
                                         std::make_unique<ResourceTrackingMechanism>(file_held))
                    .has_value());
        REQUIRE(engine
                    ->register_mechanism(
                        SparkType::Service,
                        std::make_unique<SinkThrowsAfterStoreMechanism>(service_stops))
                    .has_value());
        CHECK_THROWS(engine->start());
        CHECK_FALSE(file_held);
        CHECK(service_stops == 1);
        engine.reset();
        CHECK_FALSE(file_held);
    }
}

TEST_CASE("start()'s rollback guard covers Replay collection, mechanism-pointer "
          "collection, and wheel-thread spawn — none reachable via a mechanism fake",
          "[spark][teardown]") {
    // #2050: none of these three in-`{ lock_guard lk(mu_); ... }` sites is reachable
    // through a mechanism fake — they run before/around the per-mechanism loop — so
    // the start_fault_hook_for_test seam (fires with mu_ HELD, exactly where each of
    // these three statements sits) is the only way to deterministically exercise
    // start()'s rollback guard for them. All three fire with running_ already true
    // (latched right after the reject-check, before any of them can run), so a
    // correct rollback must always leave is_running() false afterward.
    //
    // CountingStopMechanism (never actually started at any of these three phases —
    // all fire before the per-mechanism start loop) proves rollback reaches it
    // anyway via the authoritative mechanisms_ map. A second start() call afterward
    // pins "terminal rollback, not restoration": stopped_ is latched by the
    // rollback's own teardown_locked(), so a restart attempt is refused, exactly
    // like an ordinary post-stop() restart attempt.
    SECTION("Replay collection fails") {
        int stop_calls = 0;
        auto engine = std::make_unique<SparkEngine>();
        REQUIRE(engine
                    ->register_mechanism(SparkType::Service,
                                         std::make_unique<CountingStopMechanism>(stop_calls))
                    .has_value());
        engine->set_start_fault_hook_for_test([](int phase) {
            if (phase == SparkEngine::kStartFaultPhaseReplayCollection)
                throw std::runtime_error("forced Replay-collection fault");
        });
        CHECK_THROWS(engine->start());
        CHECK_FALSE(engine->is_running());
        CHECK(stop_calls == 1); // rollback reached a never-started mechanism
        engine->start();        // terminal rollback: restart is refused, not retried
        CHECK_FALSE(engine->is_running());
        engine.reset(); // must not crash/hang — rollback already tore this down
    }
    SECTION("mechanism-pointer collection fails") {
        int stop_calls = 0;
        auto engine = std::make_unique<SparkEngine>();
        REQUIRE(engine
                    ->register_mechanism(SparkType::Service,
                                         std::make_unique<CountingStopMechanism>(stop_calls))
                    .has_value());
        engine->set_start_fault_hook_for_test([](int phase) {
            if (phase == SparkEngine::kStartFaultPhaseMechCollection)
                throw std::runtime_error("forced mechanism-pointer-collection fault");
        });
        CHECK_THROWS(engine->start());
        CHECK_FALSE(engine->is_running());
        CHECK(stop_calls == 1);
        engine->start();
        CHECK_FALSE(engine->is_running());
        engine.reset();
    }
    SECTION("wheel-thread spawn fails (std::system_error, mirroring a real thread-ctor "
            "failure)") {
        int stop_calls = 0;
        auto engine = std::make_unique<SparkEngine>();
        REQUIRE(engine
                    ->register_mechanism(SparkType::Service,
                                         std::make_unique<CountingStopMechanism>(stop_calls))
                    .has_value());
        engine->set_start_fault_hook_for_test([](int phase) {
            if (phase == SparkEngine::kStartFaultPhaseWheelSpawn)
                throw std::system_error(
                    std::make_error_code(std::errc::resource_unavailable_try_again),
                    "forced wheel-thread-spawn fault");
        });
        CHECK_THROWS(engine->start());
        CHECK_FALSE(engine->is_running());
        CHECK(stop_calls == 1);
        engine->start();
        CHECK_FALSE(engine->is_running());
        engine.reset(); // wheel_thread_ was never assigned — joinable() is false;
                        // must not hang trying to join a non-existent thread
    }
}

namespace {
/// #2050: the direct regression fake for the rollback guard's EXACT scope placement
/// (start()'s own comment explains why it matters). Stores the fault callback from
/// start(), then throws — start()'s rollback then calls this mechanism's stop(),
/// which SYNCHRONOUSLY calls the stored fault callback, landing in report_fault(),
/// which takes mu_. Under the CORRECT guard scope (declared after `life`, before the
/// `{ lk }` block) mu_ has already been released by the time rollback runs, so this
/// completes; under the WRONG scope (guard declared inside `{ lk }`) the guard would
/// destruct before `lk` on unwind and run this while mu_ is STILL held — the same
/// thread re-locking a non-recursive mutex it already owns, which hangs rather than
/// crashing (TSan cannot catch this; it is a lock-order/self-deadlock property, not
/// a race).
///
/// NOTE (adversarial-review C1-02/X2, 2026-09-19): a real shipped mechanism must
/// NEVER emit/fault synchronously from watch()/unwatch() — that prohibition is
/// scoped to those two calls specifically because they run with the per-type
/// mech_ops_mu_by_type_ lock held (spark_engine.hpp's doc comment on that lock;
/// ISparkMechanism's contract at spark_mechanism.hpp draws the same line). stop()
/// carries no such prohibition — it is documented only as idempotent and required
/// to quiesce before consumer dispatch. This fake's synchronous fault from stop()
/// is legal under the current contract; it is adversarial only in the sense that
/// it exercises the rollback's lock-scope guarantee (mu_ must already be released
/// by the time stop() runs) rather than violating any documented rule.
struct SyncFaultOnStopMechanism : ISparkMechanism {
    SparkFaultFn fault_fn;
    void start(SparkEmitFn, SparkFaultFn fault) override {
        fault_fn = std::move(fault);
        throw std::runtime_error("start boom, rollback's stop() then faults synchronously");
    }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {
        if (fault_fn)
            fault_fn("nonexistent-key", true, "synchronous fault from rollback's stop()");
    }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};
} // namespace

TEST_CASE("start()'s rollback runs with mu_ released — a mechanism that synchronously "
          "faults from its rollback stop() must not deadlock",
          "[spark][teardown][deadlock]") {
    // Direct regression test for #2050's guard-scope requirement. Catch2 assertions
    // stay on the main thread (this codebase's own convention — see the
    // register_consumer/stop() stress test above) and the worker thread only
    // reports whether start() threw.
    //
    // HONEST BOUND (adversarial-review C1-01/X1, 2026-09-19): the 5s wait_for below
    // bounds the REQUIRE itself — on a genuine deadlock it fails loudly at 5s, not
    // silently forever. It does NOT bound the whole test: on that same failing path,
    // unwinding past the failed REQUIRE destroys `fut`, and a std::future obtained
    // from std::async blocks in its destructor until the deadlocked task's shared
    // state is ready — which, being deadlocked, is never. So a real regression here
    // wedges this test binary rather than exiting non-zero in 5s; only Meson's
    // process-level timeout (tests/meson.build) eventually kills it. This is a
    // deliberate trade-off, not an oversight: the alternative (not waiting for the
    // future) would let `engine` be freed while the still-hung async thread might
    // still dereference it — a use-after-free is worse than a slow, loud CI failure.
    //
    // Raw pointer into a unique_ptr (not a shared_ptr captured by value), matching
    // this file's own convention for exactly this shape (see the "stop() racing
    // ~SparkEngine" test above) — and load-bearing here for a second reason: `engine`
    // is declared BEFORE `fut`, so on the FAILING path (wrong guard scope, genuine
    // deadlock) unwind destroys `fut` first. A future obtained from std::async
    // blocks in its destructor until its shared state is ready, so that destructor
    // never returns — `engine` is therefore NEVER reached and NEVER freed while the
    // still-hung async thread might still be dereferencing it. A shared_ptr captured
    // by value into the async lambda would instead tie the object's lifetime to
    // implementation-defined packaged_task teardown timing — avoided entirely here.
    auto engine = std::make_unique<SparkEngine>();
    REQUIRE(engine
                ->register_mechanism(SparkType::Service,
                                     std::make_unique<SyncFaultOnStopMechanism>())
                .has_value());
    SparkEngine* raw = engine.get();

    auto fut = std::async(std::launch::async, [raw]() -> bool {
        try {
            raw->start();
            return false; // did not throw — unexpected
        } catch (const std::exception&) {
            return true;
        }
    });
    // Scaled by yuzu::test::kSpinScale (adversarial-review/Gate-3 quality-engineer,
    // 2026-09-19): a bare 5s bound on a liveness wait in the shared agent_test_exe
    // binary is exactly the shape that already caused two nightly-sanitizer false
    // failures elsewhere in this suite (test_helpers.hpp's kSpinScale doc comment) —
    // this test isn't tagged [tsan-heavy], so it runs under every sanitizer leg.
    const auto status = fut.wait_for(5s * yuzu::test::kSpinScale);
    REQUIRE(status == std::future_status::ready); // else: wrong guard scope, deadlocked
    CHECK(fut.get());
    engine.reset(); // must not hang either — rollback already tore this down
    SUCCEED("rollback ran with mu_ released, so the mechanism's synchronous fault report "
            "completed instead of self-deadlocking");
}

namespace {
/// #2050: throws from BOTH start() and stop() with DISTINCT messages — models a
/// mechanism whose own cleanup path is unreliable. Proves the ORIGINAL startup
/// exception is what escapes start(), not whatever the rollback's own
/// teardown_locked() call encounters while cleaning up. This stop() throw is
/// contained by teardown_locked()'s own per-iteration mechanism-teardown catch (the
/// step-2 loop) — it never reaches the rollback guard's outer try/catch at all,
/// which exists for a throw from teardown_locked() ITSELF (wheel join, consumer
/// swap, spdlog), not from an individual mechanism. Either containment layer would
/// have to hold for this test to pass; this fake exercises the one it actually hits.
struct DoubleThrowMechanism : ISparkMechanism {
    // External reference, matching LeakyThrowingMechanism's pattern above: the
    // mechanism itself is destroyed inside engine.reset() (owned by SparkEngine's
    // mechanisms_ map), so a member counter read AFTER reset() would be a
    // use-after-free. Adversarial-review K1/C2-03: makes "rollback actually ran"
    // directly observable, rather than inferred only from the original exception
    // propagating (which would also happen with no rollback at all — an absent or
    // disarmed guard would leave this at 0 at the checkpoint below).
    int& stop_calls;
    explicit DoubleThrowMechanism(int& calls) : stop_calls(calls) {}
    void start(SparkEmitFn, SparkFaultFn) override {
        throw std::runtime_error("original startup failure");
    }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {
        ++stop_calls;
        throw std::runtime_error("cleanup boom");
    }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};
} // namespace

TEST_CASE("a cleanup throw during start()'s rollback does not replace the original "
          "startup exception",
          "[spark][teardown]") {
    auto engine = std::make_unique<SparkEngine>();
    int stop_calls = 0;
    REQUIRE(engine
                ->register_mechanism(SparkType::Service,
                                     std::make_unique<DoubleThrowMechanism>(stop_calls))
                .has_value());

    bool caught = false;
    try {
        engine->start();
    } catch (const std::exception& e) {
        caught = true;
        CHECK(std::string(e.what()) == "original startup failure");
    }
    CHECK(caught);
    // Rollback ran (not just "the exception happened to propagate") — checked BEFORE
    // engine.reset(), so this is the rollback's own call, not the destructor's later
    // retry. An absent or disarmed rollback guard would leave stop_calls at 0 here.
    CHECK(stop_calls == 1);
    // teardown_complete_ stays false (this mechanism's stop() throw is contained by
    // teardown_locked()'s own per-iteration mechanism catch, step 2 — see
    // DoubleThrowMechanism's comment) — the destructor retries the same
    // always-throwing stop() and must still not hang or crash; this mechanism never
    // fully tears down, which is the honest outcome for a mechanism whose stop() is
    // itself broken.
    engine.reset();
    CHECK(stop_calls == 2); // destructor's retry called it again; stop_calls outlives
                            // the mechanism, so this is safe to read post-reset()
    SUCCEED("the rollback's own cleanup failure did not mask the original exception, "
            "and the destructor's retry completed without hanging or crashing");
}

namespace {
/// Gate 5 chaos-injector, CH-1 (2026-09-20): the mechanism-start loop
/// (`for (auto& [type, m] : mechs) m->start(...)`) stops at the FIRST throw, so a
/// mechanism registered AFTER the throwing one in map order (SparkType's enum
/// value) never has start() called at all. The rollback's teardown_locked() then
/// iterates the AUTHORITATIVE `mechanisms_` map unconditionally — every registered
/// mechanism gets stop() called, including one whose start() was never invoked.
/// This exact shape (stop() without a preceding start()) is not new to #2050: the
/// pre-existing B1 fix already established that a mechanism must guard stop() on
/// RESOURCE OWNERSHIP, not a `started_` bool, precisely so stop() tolerates this —
/// what #2050 changes is only that it can now happen synchronously, immediately,
/// rather than "eventually, whenever ~SparkEngine next ran". No test previously
/// exercised 3+ mechanisms with one genuinely never-started sibling; this one does.
struct NeverStartedTrackingMechanism : ISparkMechanism {
    bool& start_called;
    bool& stop_called;
    explicit NeverStartedTrackingMechanism(bool& started, bool& stopped)
        : start_called(started), stop_called(stopped) {}
    void start(SparkEmitFn, SparkFaultFn) override { start_called = true; }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override { stop_called = true; }
    [[nodiscard]] SparkMechanismStats stats() const override { return {}; }
};
} // namespace

TEST_CASE("start()'s rollback stops a sibling mechanism whose start() was never "
          "reached, without crashing or misreporting it as started",
          "[spark][teardown]") {
    // SparkType::File(3) < Service(4) < Registry(5) — map/iteration order. File
    // starts cleanly; Service throws; Registry must never see start() but must
    // still see a clean stop() from the rollback.
    auto engine = std::make_unique<SparkEngine>();

    bool file_started = false, file_stopped = false;
    REQUIRE(engine
                ->register_mechanism(SparkType::File,
                                     std::make_unique<NeverStartedTrackingMechanism>(
                                         file_started, file_stopped))
                .has_value());
    REQUIRE(engine->register_mechanism(SparkType::Service, std::make_unique<ThrowingStartMechanism>())
                .has_value());
    bool registry_started = false, registry_stopped = false;
    REQUIRE(engine
                ->register_mechanism(SparkType::Registry,
                                     std::make_unique<NeverStartedTrackingMechanism>(
                                         registry_started, registry_stopped))
                .has_value());

    CHECK_THROWS(engine->start());

    CHECK(file_started);
    CHECK(file_stopped); // cleanly-started sibling still torn down by rollback
    CHECK_FALSE(registry_started); // never reached — start() aborted at Service
    CHECK(registry_stopped); // rollback still calls stop() on it — must not crash
                             // or skip it just because start() never ran

    engine.reset(); // must not hang, double-stop, or crash on retry
    SUCCEED("rollback correctly tore down both the started and the never-started "
            "sibling mechanisms without distinguishing them incorrectly");
}
