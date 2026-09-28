// test_log_handoff.cpp - #4666 PR-1: unit tests for the bounded async log hand-off
// primitive (agents/core/src/log_handoff.{hpp,cpp}). See that file's own banner for the
// full contract; this file exercises it directly, never through the global
// spdlog::default_logger() (LogCapture's own doc comment records why that swap is
// unreliable across a library-image boundary - irrelevant here since LogHandoff is
// constructed, driven and torn down entirely within this test binary's own image for
// every case below except the explicit install()/T2-default-logger checks in U4).
//
// GATE DISCIPLINE (load-bearing for every case that pauses a sink): a LogHandoff whose
// wrapped sink is still paused when the object destructs runs its fail-closed
// teardown() - which, if the sink never unblocks, waits out kLogTeardownGrace (2s) and
// then HARD_EXIT()s THIS ENTIRE TEST BINARY. Every case that pauses a sink therefore
// declares a yuzu::test::ScopeExit release guard immediately after constructing the
// Harness/sink, so the gate is released on every exit path - including a failed
// REQUIRE/CHECK - before the Harness's own destructor runs (reverse declaration order).

#include "guardian_spark_timing.hpp" // format_arm_committed_line (U2)
#include "log_handoff.hpp"

#include "log_handoff_test_sinks.hpp" // GatedCaptureSink, ThrowOnceSink (promoted #4666 PR-2)
#include "test_helpers.hpp"

#include <yuzu/json_log_formatter.hpp>

#include <spdlog/details/os.h> // spdlog::details::os::thread_id()
#include <spdlog/spdlog.h> // global spdlog::info() (U4)

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::drain_log_bounded;
using yuzu::agent::kLogQueueCapacity;
using yuzu::agent::LogHandoff;
using yuzu::test::GatedCaptureSink;
using yuzu::test::ThrowOnceSink;

namespace {

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------
//
// GatedCaptureSink and ThrowOnceSink live in log_handoff_test_sinks.hpp (promoted
// #4666 PR-2) - pulled in via the `using` declarations above. The park-on-#0 cases
// below (U1/U2/U3/U5) and U6's repeated toggling both rely on GatedCaptureSink's single
// block-while-paused_ gate; ThrowOnceSink backs U8. See the header's own class comments
// for the full mechanism.

/// Convenience bundle: a LogHandoff built over one GatedCaptureSink, with the sink kept
/// alive separately so the test can drive its gate and read its capture. `sink` MUST be
/// reset() (or otherwise dropped) before checking closed_flag() - see U4.
struct Harness {
    std::shared_ptr<GatedCaptureSink> sink;
    std::unique_ptr<LogHandoff> handoff;

    explicit Harness(bool initially_paused = true,
                     std::size_t queue_capacity = kLogQueueCapacity) {
        sink = std::make_shared<GatedCaptureSink>(initially_paused);
        auto result = LogHandoff::create_with_sinks({sink}, queue_capacity);
        REQUIRE(result.has_value());
        handoff = std::move(*result);
    }
};

} // namespace

// ---------------------------------------------------------------------------
// U1: non-waiting enqueue
// ---------------------------------------------------------------------------

TEST_CASE("U1: producer submits return promptly while the sink is parked, "
          "and every line up to capacity is eventually delivered in order",
          "[log_handoff]") {
    Harness h;
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

    auto logger = h.handoff->logger();
    logger->info("park"); // message #0: the worker picks this up immediately and
                          // blocks inside GatedCaptureSink::log() until release().
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

    constexpr int kProducers = 4;
    constexpr int kPerProducer = 1000;

    const auto submit_start = std::chrono::steady_clock::now();
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            for (int i = 0; i < kPerProducer; ++i)
                logger->info("p{}-{}", p, i);
        });
    }
    for (auto& t : producers)
        t.join();
    const auto submit_elapsed = std::chrono::steady_clock::now() - submit_start;

    // The whole 4000-message batch enqueues while the single worker is still parked on
    // message #0 - proving enqueue never waits on sink I/O (the guarantee stated in the
    // header). 200ms is generous for 4000 uncontended enqueues even on a loaded CI box;
    // scaled for sanitizer builds like every other liveness bound in this suite.
    CHECK(submit_elapsed < 200ms * yuzu::test::kSpinScale);
    // Nothing has been CAPTURED yet -- the worker is still inside log() for message #0,
    // blocked on the gate BEFORE that call appends to captured_ (see GatedCaptureSink's
    // own log() ordering: wait, then capture).
    CHECK(h.sink->count() == 0);

    h.sink->release();
    REQUIRE(yuzu::test::spin_until(
        [&] { return h.sink->count() == static_cast<std::size_t>(1 + kProducers * kPerProducer); },
        5s));
    CHECK(h.handoff->overrun_total() == 0); // capacity 8192 comfortably exceeds 4001

    // Every producer's own submissions arrive in the order it submitted them (FIFO
    // delivery, not reordered/lost) - checked per-producer since 4 concurrent
    // producers do not guarantee a single deterministic INTERLEAVED order.
    std::vector<int> next_expected(kProducers, 0);
    for (const auto& c : h.sink->snapshot()) {
        if (c.payload == "park")
            continue;
        int p = -1, i = -1;
        // "p{p}-{i}"
        const auto dash = c.payload.find('-');
        REQUIRE(dash != std::string::npos);
        p = std::stoi(c.payload.substr(1, dash - 1));
        i = std::stoi(c.payload.substr(dash + 1));
        REQUIRE((p >= 0 && p < kProducers));
        CHECK(i == next_expected[static_cast<std::size_t>(p)]);
        ++next_expected[static_cast<std::size_t>(p)];
    }
    for (int p = 0; p < kProducers; ++p)
        CHECK(next_expected[static_cast<std::size_t>(p)] == kPerProducer);
}

// ---------------------------------------------------------------------------
// U2 / U2b: timestamp and thread id survive the hand-off unchanged
// ---------------------------------------------------------------------------

namespace {

/// Shared body for U2/U2b: parks the worker on an EARLIER message, submits `text` from
/// a NAMED producer thread (distinct from both the test's main thread and the worker),
/// holds for 1500ms, releases, and asserts the captured record's raw time/thread_id
/// (not just the rendered text) match what the PRODUCER thread stamped - never a value
/// close to release time or matching the WORKER's thread id, which is exactly what a
/// "re-log at write time" regression would produce.
void run_stamp_preservation_case(const std::string& text) {
    Harness h;
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

    auto logger = h.handoff->logger();
    logger->set_pattern("%E.%e [%t] %v");

    logger->info("park"); // message #0 - parks the worker
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

    std::size_t producer_tid = 0;
    std::chrono::system_clock::time_point t0;
    std::thread producer([&] {
        producer_tid = spdlog::details::os::thread_id();
        t0 = std::chrono::system_clock::now();
        logger->info(text);
    });
    producer.join();

    std::this_thread::sleep_for(1500ms);
    const auto t_release = std::chrono::system_clock::now();
    h.sink->release();

    REQUIRE(yuzu::test::spin_until([&] { return h.sink->count() == 2; }, 5s));
    const auto snap = h.sink->snapshot();
    REQUIRE(snap.size() == 2);
    const auto& rec = snap[1];

    CHECK(rec.payload == text);

    const auto stamp_delta =
        std::chrono::duration_cast<std::chrono::milliseconds>(rec.time - t0);
    CHECK(std::abs(stamp_delta.count()) < 100);
    CHECK(rec.time < t_release - 1000ms);
    CHECK(rec.thread_id == producer_tid);

    // The rendered %t must show the PRODUCER's thread id, bracketed exactly as the
    // pattern places it - proof the wrapper's set_pattern()/set_formatter() forward
    // (1.2) AND that the formatter renders the preserved (not re-stamped) log_msg.
    const std::string bracketed = "[" + std::to_string(producer_tid) + "]";
    CHECK(rec.formatted.find(bracketed) != std::string::npos);
}

} // namespace

TEST_CASE("U2: call-site timestamp and thread id survive the async hand-off "
          "(arm-committed line)",
          "[log_handoff]") {
    const std::string text = yuzu::agent::format_arm_committed_line(
        "riga-4666-u2-001", /*epoch=*/7, /*incarnation=*/3, "Registry", "poll",
        /*attach_to_commit_ms=*/42);
    run_stamp_preservation_case(text);
}

TEST_CASE("U2b: call-site timestamp and thread id survive the async hand-off "
          "(T0d detach_all-complete line)",
          "[log_handoff]") {
    const std::string text =
        std::format("Guardian spark: detach_all complete (epoch={}, incarnation_floor={}, "
                    "detached_rules={}, withdrawn_claims={})",
                    7, 12, 5, 2);
    run_stamp_preservation_case(text);
}

// ---------------------------------------------------------------------------
// U3: deterministic overflow
// ---------------------------------------------------------------------------

TEST_CASE("U3: overrun_oldest deterministically evicts the oldest queued messages",
          "[log_handoff]") {
    Harness h(/*initially_paused=*/true, /*queue_capacity=*/8);
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

    auto logger = h.handoff->logger();
    logger->info("park"); // dequeued immediately - does not occupy a queue slot while parked
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

    for (int i = 0; i < 20; ++i)
        logger->info("msg-{}", i);

    h.sink->release();
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->queue_depth() == 0; }, 5s));
    REQUIRE(yuzu::test::spin_until([&] { return h.sink->count() == 1 + 8; }, 5s));

    CHECK(h.handoff->overrun_total() == 12);
    const auto snap = h.sink->snapshot();
    REQUIRE(snap.size() == 9);
    CHECK(snap[0].payload == "park");
    for (int i = 0; i < 8; ++i)
        CHECK(snap[static_cast<std::size_t>(1 + i)].payload == std::format("msg-{}", 12 + i));
}

// ---------------------------------------------------------------------------
// U4: healthy teardown (U10 folded in)
// ---------------------------------------------------------------------------

TEST_CASE("U4: teardown() on a healthy sink drains everything, destroys the sink, and "
          "leaves the process default logger safely swapped to a null sink (U10)",
          "[log_handoff]") {
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto closed_flag = sink->closed_flag();

    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto handoff = std::move(*result);
    sink.reset(); // drop OUR reference - the only remaining owner is handoff's own
                  // wrapped_sinks_, so teardown()'s T3 (wrapped_sinks_.clear()) is what
                  // actually destroys the object.

    for (int i = 0; i < 10; ++i)
        handoff->logger()->info("line-{}", i);

    std::atomic<int> action_fired{0};
    handoff->teardown_with_action_for_test(2s, [&] { action_fired.fetch_add(1); });

    CHECK(action_fired.load() == 0); // healthy drain - the deadline action never fires
    CHECK(closed_flag->load(std::memory_order_acquire)); // the sink was actually destroyed

    // T2 swapped the PROCESS default logger (in this image) to a null sink,
    // unconditionally - even though this handoff was never install()-ed. A straggler
    // call must not crash.
    CHECK_NOTHROW(spdlog::info("this goes to the null sink, not a crash"));

    // Link/smoke check only (#4666 PR-2): proves log_handoff_emit_probe_for_test()'s
    // exported symbol resolves across the test-binary/library boundary and does not
    // throw against the same null-sink default logger above. The later macOS
    // multi-image fixture is the actual consumer that exercises its cross-image
    // behavior - not this test.
    CHECK_NOTHROW(yuzu::agent::log_handoff_emit_probe_for_test("probe -> null sink"));
}

// ---------------------------------------------------------------------------
// U5: blocked teardown fires the deadline action
// ---------------------------------------------------------------------------

TEST_CASE("U5: teardown() on a wedged sink fires the deadline action within grace, "
          "without the action itself unblocking the join",
          "[log_handoff]") {
    Harness h; // initially paused
    // GATE DISCIPLINE (file banner) -- added (Gate 8 re-review, quality-engineer,
    // governance hardening round: this gap predates this commit but is cheap to
    // close while already in this file). Without this, a failure of the very first
    // REQUIRE below (before teardown_thread even exists) would unwind with the sink
    // still paused, and ~LogHandoff()'s fail-closed teardown() would block the full
    // (unscaled) kLogTeardownGrace and then hard_exit() the WHOLE test binary.
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};
    auto logger = h.handoff->logger();
    logger->info("park");
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

    std::mutex fired_mu;
    std::condition_variable fired_cv;
    bool fired = false;
    const auto grace = 300ms;

    std::thread teardown_thread([&] {
        h.handoff->teardown_with_action_for_test(grace, [&] {
            {
                std::lock_guard<std::mutex> lk(fired_mu);
                fired = true;
            }
            fired_cv.notify_all();
        });
    });

    bool ok;
    {
        std::unique_lock<std::mutex> lk(fired_mu);
        ok = fired_cv.wait_for(lk, (grace + 100ms) * yuzu::test::kSpinScale,
                               [&] { return fired; });
    }

    // Cleanup runs UNCONDITIONALLY, before any assertion on `ok` -- release the gate
    // so the worker's blocked log() call (and thus ~thread_pool's join inside
    // teardown_body()) can complete, then join the thread, regardless of whether the
    // wait above timed out. Governance hardening round (BLOCKING finding, cpp-safety
    // + quality-engineer independently): asserting on `ok` BEFORE this cleanup meant
    // that on exactly the regression this test exists to catch (the deadline action
    // never firing), REQUIRE's throw would unwind the stack while teardown_thread was
    // still joinable and blocked -- std::thread::~thread() on a joinable thread calls
    // std::terminate(), SIGABRTing the whole binary instead of failing this one test
    // cleanly. Matches "BLOCKER round-2"'s already-correct pattern below.
    h.sink->release();
    teardown_thread.join();

    REQUIRE(ok);
}

// ---------------------------------------------------------------------------
// BLOCKER-1 regression (#4666 PR-1 adversarial review, both reviewers independently
// reproduced with standalone repros): a concurrent drain_log_bounded() call must never
// let teardown()'s deadline watchdog cancel on a normal scope exit while the pool is
// still genuinely wedged. Before the drain-reader-lease fix, teardown_body()'s
// pool_.reset() was a non-destructive ref-decrement whenever a drain_log_bounded() call
// was concurrently holding a strong pool reference -- teardown() returned quickly, its
// ShutdownDeadlineGuard cancelled on that NORMAL return, and the deadline action never
// fired at all, even though the sink was (and remained) wedged. This test is the
// falsifier: RED on the unfixed code (the wait below times out because the action never
// fires), GREEN after the drain-reader lease closes the interleaving (teardown() blocks
// inside wait_for_drain_quiescence() until the drain thread releases its lease, so the
// watchdog is still armed when `grace` elapses and the action fires on schedule).
// ---------------------------------------------------------------------------

TEST_CASE("BLOCKER-1 regression: teardown()'s deadline watchdog still fires while a "
          "concurrent drain_log_bounded() call holds the pool wedged, and neither "
          "thread inherits an unwatched blocking join",
          "[log_handoff]") {
    Harness h; // initially paused
    // GATE DISCIPLINE (file banner) -- restored (Gate 8 re-review finding,
    // quality-engineer, governance hardening round): the unconditional-cleanup fix
    // below only covers the two threads spawned further down; the FIRST assertion
    // (in_write(), right below) runs BEFORE either thread exists, so if IT fails --
    // exactly the kind of regression it exists to catch -- `h` would otherwise unwind
    // with the sink still paused, and ~LogHandoff()'s fail-closed teardown() would
    // block the full (unscaled) kLogTeardownGrace and then hard_exit() the WHOLE test
    // binary -- the identical whole-binary-death class this commit's BLOCKING fix
    // was written to eliminate, reopened on a different trigger by dropping this
    // guard. release() is safely idempotent (BLOCKER round-2 already relies on that,
    // keeping both this guard and an explicit release() call).
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

    h.handoff->logger()->info("park");
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

    // A long-lived concurrent drain -- holds a strong pool ref for up to 2s while the
    // sink stays wedged, comfortably past teardown()'s own short grace below, so the
    // drain is still genuinely in flight at the moment the watchdog is expected to
    // fire.
    std::atomic<bool> drain_result{false};
    std::atomic<bool> drain_done{false};
    std::thread drain_thread([&] {
        drain_result.store(drain_log_bounded(2000ms), std::memory_order_release);
        drain_done.store(true, std::memory_order_release);
    });

    // Give the drain a moment to acquire its lease and start spinning before teardown()
    // begins -- matches both reviewers' repro timing (~50ms); scaled for sanitizer
    // builds like every other liveness bound in this suite.
    std::this_thread::sleep_for(100ms * yuzu::test::kSpinScale);

    std::mutex fired_mu;
    std::condition_variable fired_cv;
    bool fired = false;
    std::chrono::steady_clock::time_point fired_at;
    const auto teardown_start = std::chrono::steady_clock::now();
    const auto grace = 300ms;

    std::thread teardown_thread([&] {
        h.handoff->teardown_with_action_for_test(grace, [&] {
            {
                std::lock_guard<std::mutex> lk(fired_mu);
                fired = true;
                fired_at = std::chrono::steady_clock::now();
            }
            fired_cv.notify_all();
        });
    });

    // THE FALSIFIER: see this TEST_CASE's own header comment for the exact red/green
    // shape.
    bool ok;
    {
        std::unique_lock<std::mutex> lk(fired_mu);
        ok = fired_cv.wait_for(lk, (grace + 1000ms) * yuzu::test::kSpinScale,
                               [&] { return fired; });
    }
    // Capture the values these CHECKs need BEFORE the unconditional cleanup below can
    // change them -- drain_done specifically must reflect "was the drain still
    // in-flight at the moment we observed `fired`", not its value after we release
    // the sink a few lines down.
    const auto fired_after = ok ? (fired_at - teardown_start) : std::chrono::steady_clock::duration{};
    const bool drain_done_before_release = drain_done.load(std::memory_order_acquire);

    // Cleanup runs UNCONDITIONALLY, before REQUIRE(ok) -- same BLOCKING finding as
    // U5's (cpp-safety + quality-engineer independently, governance hardening round):
    // asserting on `ok` before releasing/joining means that on exactly the regression
    // this test exists to catch (the deadline action never firing), REQUIRE's throw
    // unwinds the stack while drain_thread/teardown_thread are still joinable and
    // blocked -- std::thread::~thread() on a joinable thread calls std::terminate(),
    // SIGABRTing the whole binary instead of failing this one test cleanly. Unwedge:
    // the drain thread's pending() check goes false and it returns (releasing its
    // lease well before its own 2s bound), which lets teardown()'s
    // wait_for_drain_quiescence() finally observe active_readers==0 and proceed.
    h.sink->release();
    drain_thread.join();
    teardown_thread.join();

    // Neither thread was left blocked on an unwatched join: both joined within this
    // test's own bounded waits above. Now safe to assert -- no joinable thread
    // remains for a throw to strand.
    REQUIRE(ok);
    CHECK(fired_after >= grace / 2);
    CHECK(fired_after < (grace + 1000ms) * yuzu::test::kSpinScale);
    // The drain thread must NOT have completed before we released the sink above --
    // it was still legitimately spinning inside its own 2s wait while the sink
    // stayed wedged. This proves the interleaving this test exists to exercise was
    // genuinely live at the moment the watchdog fired, not accidentally avoided by
    // scheduling luck.
    CHECK_FALSE(drain_done_before_release);
    SUCCEED("teardown()'s watchdog covered the concurrent drain; both threads joined cleanly");
}

// ---------------------------------------------------------------------------
// BLOCKER (round 2) regression (#4666 PR-1 second adversarial review round, Fable):
// the drain-reader lease above only protects drain_log_bounded() specifically.
// spdlog::async_logger::sink_it_()/flush_() both do
// `if (auto pool_ptr = thread_pool_.lock()) pool_ptr->post_log(...)` (or post_flush),
// so ANY thread calling ordinary logger()->info()/flush() -- not just
// drain_log_bounded() -- transiently holds its own strong shared_ptr<thread_pool>,
// completely outside the lease's visibility. Before the worker-exit-signal fix,
// teardown_body()'s pool_.reset() could be a non-destructive ref-decrement whenever an
// ordinary PRODUCER thread held that transient reference, letting the
// ShutdownDeadlineGuard cancel on a normal return while the sink was still genuinely
// wedged -- reproduced empirically (150/150 under 4-thread producer saturation against
// a wedged sink). This is the falsifier: RED on pre-worker-exit-signal code (the wait
// below times out because the action never fires, or fires only by scheduling luck --
// unreliably, not on the schedule the watchdog promises), GREEN after
// wait_for_worker_exit() anchors teardown() to the pool's worker thread's own genuine
// exit, independent of which thread's shared_ptr reset happens to trigger
// ~thread_pool(). Cleanup (stop producers, release the sink, join everything) runs
// UNCONDITIONALLY before the outcome is asserted, so a RED run never leaves an
// abandoned joinable thread behind.
// ---------------------------------------------------------------------------

TEST_CASE("BLOCKER round-2 regression: teardown()'s deadline watchdog still fires while "
          "ordinary producer threads (not drain_log_bounded()) are concurrently logging "
          "against a wedged sink, and no thread is left on an unwatched join",
          "[log_handoff]") {
    Harness h; // initially paused
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

    auto logger = h.handoff->logger();
    logger->info("park");
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

    // Producer saturation: 4 threads in a tight loop, each transiently holding its own
    // strong pool reference on every logger()->info() call (matches the reproducer's
    // own parameters -- this is what makes the race reliably reproducible rather than
    // a rare 1-in-200 occurrence).
    constexpr int kProducers = 4;
    std::atomic<bool> stop{false};
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            int i = 0;
            while (!stop.load(std::memory_order_relaxed))
                logger->info("p{}-{}", p, i++);
        });
    }

    // Give the producers a moment to actually start hammering before teardown begins.
    std::this_thread::sleep_for(100ms * yuzu::test::kSpinScale);

    std::mutex fired_mu;
    std::condition_variable fired_cv;
    bool fired = false;
    std::chrono::steady_clock::time_point fired_at;
    const auto teardown_start = std::chrono::steady_clock::now();
    const auto grace = 300ms;

    std::thread teardown_thread([&] {
        h.handoff->teardown_with_action_for_test(grace, [&] {
            {
                std::lock_guard<std::mutex> lk(fired_mu);
                fired = true;
                fired_at = std::chrono::steady_clock::now();
            }
            fired_cv.notify_all();
        });
    });

    bool ok = false;
    {
        std::unique_lock<std::mutex> lk(fired_mu);
        ok = fired_cv.wait_for(lk, (grace + 1000ms) * yuzu::test::kSpinScale,
                               [&] { return fired; });
    }
    const auto fired_after = fired ? (fired_at - teardown_start) : std::chrono::steady_clock::duration::zero();

    // Cleanup runs UNCONDITIONALLY, before any assertion on `ok` -- see this
    // TEST_CASE's own header comment for why: a RED run must never leave an abandoned
    // joinable thread behind (round 1's manual RED verification hit exactly that
    // hazard, which is why this round's test is written to avoid it from the start).
    stop.store(true, std::memory_order_relaxed);
    h.sink->release();
    for (auto& t : producers)
        t.join();
    teardown_thread.join();

    REQUIRE(ok);
    CHECK(fired_after >= grace / 2);
    CHECK(fired_after < (grace + 1000ms) * yuzu::test::kSpinScale);
    SUCCEED("teardown()'s watchdog covered the concurrent producer traffic; every "
            "thread joined cleanly");
}

// ---------------------------------------------------------------------------
// U6: TSan - concurrent producers plus a repeatedly toggled gate
// ---------------------------------------------------------------------------

TEST_CASE("U6: concurrent producers against a repeatedly toggled sink gate race cleanly",
          "[log_handoff][tsan]") {
    Harness h(/*initially_paused=*/false);
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->set_paused(false); }};

    auto logger = h.handoff->logger();
    std::atomic<bool> stop{false};

    constexpr int kProducers = 8;
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            int i = 0;
            while (!stop.load(std::memory_order_relaxed)) {
                logger->info("p{}-{}", p, i++);
            }
        });
    }

    for (int toggle = 0; toggle < 50; ++toggle) {
        h.sink->set_paused(toggle % 2 == 0);
        std::this_thread::sleep_for(2ms);
    }
    h.sink->set_paused(false);

    stop.store(true, std::memory_order_relaxed);
    for (auto& t : producers)
        t.join();

    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->queue_depth() == 0; }, 5s));
    SUCCEED("no TSan report across 8 producers and 50 gate toggles");
}

// ---------------------------------------------------------------------------
// U7 / U7b: construction failure, the two distinguishable surfaces
// ---------------------------------------------------------------------------

TEST_CASE("U7: an injected pool/logger construction failure returns an error and "
          "installs nothing",
          "[log_handoff]") {
    LogHandoff::set_construction_fault_for_test(true);
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE_FALSE(result.has_value());
    CHECK_FALSE(result.error().empty());

    // Nothing was installed: no LogHandoff is registered for drain_log_bounded() to
    // find.
    CHECK_FALSE(drain_log_bounded(10ms));

    // The fault is one-shot - a second call must succeed normally, proving the flag was
    // consumed rather than sticking for the rest of the binary.
    auto second = LogHandoff::create_with_sinks({sink});
    REQUIRE(second.has_value());
    (*second)->teardown_with_action_for_test(2s, [] {});
}

TEST_CASE("U7b: a --log-file open failure falls back to console-only logging instead "
          "of failing construction",
          "[log_handoff]") {
    // spdlog's rotating_file_sink auto-creates missing PARENT directories
    // (file_helper::open() -> os::create_dir), so a merely-nonexistent subdirectory is
    // not a real open failure. A genuinely unwritable directory is, matching the same
    // try-then-verify pattern already established in this repo (e.g.
    // test_autoruns_linux_local.cpp's "genuinely unreadable existing directory" case).
    yuzu::test::TempDir base{"yuzu_test_log_handoff_"};
    std::filesystem::create_directories(base.path);
    std::error_code ec;
    std::filesystem::permissions(base.path, std::filesystem::perms::none, ec);
    if (ec) {
        std::filesystem::permissions(base.path, std::filesystem::perms::owner_all, ec);
        SKIP("could not remove directory permissions");
    }

    LogHandoff::Options options;
    options.log_file = base.path / "sub" / "agent.log";

    auto result = LogHandoff::create(options);

    std::filesystem::permissions(base.path, std::filesystem::perms::owner_all, ec); // restore for cleanup

    if (result.has_value() && !(*result)->used_log_file_fallback())
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed the denial");

    REQUIRE(result.has_value()); // NOT EXIT_FAILURE-shaped - construction still succeeds
    auto handoff = std::move(*result);
    CHECK(handoff->used_log_file_fallback());
    CHECK_FALSE(handoff->log_file_fallback_reason().empty());
    handoff->teardown_with_action_for_test(2s, [] {});
}

// ---------------------------------------------------------------------------
// U8: a throwing sink is contained by the error handler
// ---------------------------------------------------------------------------

TEST_CASE("U8: a throwing sink is contained by the error handler; the worker "
          "continues and spdlog's own default fprintf handler is never reached",
          "[log_handoff]") {
    auto sink = std::make_shared<ThrowOnceSink>();
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto handoff = std::move(*result);

    auto logger = handoff->logger();
    logger->info("first line throws in the sink");
    logger->info("second line is delivered normally");

    REQUIRE(yuzu::test::spin_until([&] { return handoff->log_errors_total() >= 1; }, 5s));
    CHECK(handoff->log_errors_total() == 1);
    REQUIRE(yuzu::test::spin_until([&] { return sink->captured_count() == 1; }, 5s));

    handoff->teardown_with_action_for_test(2s, [] {});
}

// ---------------------------------------------------------------------------
// U9: drain_log_bounded()
// ---------------------------------------------------------------------------

TEST_CASE("U9: drain_log_bounded() delivers a pending breadcrumb when healthy, times "
          "out cleanly when wedged, and is null-safe with nothing installed",
          "[log_handoff]") {
    SECTION("healthy: returns true within the wait and the breadcrumb is captured") {
        Harness h(/*initially_paused=*/false);
        yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

        h.handoff->logger()->info("pre-abort breadcrumb");
        const auto start = std::chrono::steady_clock::now();
        const bool drained = drain_log_bounded(200ms);
        const auto elapsed = std::chrono::steady_clock::now() - start;

        CHECK(drained);
        CHECK(elapsed < 250ms * yuzu::test::kSpinScale);
        REQUIRE(yuzu::test::spin_until([&] { return h.sink->count() == 1; }));
        CHECK(h.sink->snapshot().front().payload == "pre-abort breadcrumb");
    }

    SECTION("wedged: returns false within wait plus a small epsilon") {
        Harness h; // initially paused
        yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

        h.handoff->logger()->info("park");
        REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

        const auto start = std::chrono::steady_clock::now();
        const bool drained = drain_log_bounded(200ms);
        const auto elapsed = std::chrono::steady_clock::now() - start;

        CHECK_FALSE(drained);
        CHECK(elapsed < 350ms * yuzu::test::kSpinScale);
    }

    SECTION("null-safe: no LogHandoff installed returns false immediately") {
        const auto start = std::chrono::steady_clock::now();
        const bool drained = drain_log_bounded(50ms);
        const auto elapsed = std::chrono::steady_clock::now() - start;

        CHECK_FALSE(drained);
        CHECK(elapsed < 20ms * yuzu::test::kSpinScale);
    }
}

// ---------------------------------------------------------------------------
// U-json: the wrapper forwards set_pattern()/set_formatter()
// ---------------------------------------------------------------------------

TEST_CASE("U-json: set_formatter() reaches the inner sink through the wrapper, so "
          "JSON formatting is not silently dropped back to the default text pattern",
          "[log_handoff]") {
    Harness h(/*initially_paused=*/false);
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

    h.handoff->logger()->set_formatter(std::make_unique<yuzu::JsonLogFormatter>("test"));
    h.handoff->logger()->info("json formatted line");

    REQUIRE(yuzu::test::spin_until([&] { return h.sink->count() == 1; }));
    const auto rec = h.sink->snapshot().front();
    REQUIRE_FALSE(rec.formatted.empty());
    CHECK(rec.formatted.front() == '{');
    CHECK(rec.formatted.find("\"message\"") != std::string::npos);
    // Not the default text pattern's shape.
    CHECK(rec.formatted.find('[') == std::string::npos);
}

// ---------------------------------------------------------------------------
// U10: two genuinely concurrent teardown() calls -- the loser-waits handshake
// under real thread contention, kept deterministically inside the SAFE half
// of the THREAD-SAFETY CONTRACT (log_handoff.hpp)
// ---------------------------------------------------------------------------

TEST_CASE("U10: two concurrent teardown() calls on a stably-owned object never race "
          "for use-after-free; the loser genuinely waits for the winner",
          "[log_handoff]") {
    // Governance scoped-review rounds 5/6 (#4666) found and then documented that the
    // loser-waits handshake (torn_down_ exchange, notify-under-lock,
    // wait_for_teardown_completion()) is safe ONLY when the object's memory outlives
    // the loser's own return from that wait -- true when the destructor is the
    // LOSER, false when the destructor (or whichever thread frees the object right
    // after its own call returns) is the WINNER. No test exercises the UNSAFE half
    // by design (see the header's "WHAT THIS DOES NOT COVER" paragraph): the only
    // way to observe it is to trigger a genuine heap-use-after-free, which is not
    // something to leave running in the ordinary (non-sanitized) shared test binary
    // -- a mis-timed race there would risk corrupting state for unrelated tests
    // sharing this process, not just failing cleanly.
    //
    // This test instead exercises the SAFE half's underlying mechanism directly:
    // two threads race to call teardown() on the SAME live object, but NEITHER of
    // them is the thread that frees it -- `h` (and its owning
    // unique_ptr<LogHandoff>) stays alive for the entire test and is only destroyed
    // after BOTH racing threads have already returned. That makes this
    // deterministically safe regardless of which thread wins the torn_down_
    // exchange, while still proving the loser genuinely BLOCKS until the winner's
    // teardown_body() has actually finished (observed via the paused sink below),
    // rather than racing ahead or returning early.
    Harness h; // initially paused
    yuzu::test::ScopeExit release_on_exit{[&] { h.sink->release(); }};

    auto logger = h.handoff->logger();
    logger->info("park");
    REQUIRE(yuzu::test::spin_until([&] { return h.handoff->in_write(); }));

    LogHandoff* raw = h.handoff.get(); // NOT the owner -- h.handoff owns it throughout

    std::atomic<bool> t1_done{false};
    std::atomic<bool> t2_done{false};
    std::thread t1([&] {
        raw->teardown();
        t1_done.store(true, std::memory_order_release);
    });
    std::thread t2([&] {
        raw->teardown();
        t2_done.store(true, std::memory_order_release);
    });

    // The sink is still paused, so whichever thread wins the exchange is now
    // genuinely blocked inside teardown_body()'s pool join (the worker can't finish
    // draining), and the loser is genuinely blocked inside
    // wait_for_teardown_completion() -- neither call has anything to return early
    // on. Give both threads a moment to reach that state (matches "BLOCKER round-2
    // regression"'s own sleep_for idiom above for the identical purpose), well
    // inside kLogTeardownGrace's 2s default so the watchdog cannot fire here.
    std::this_thread::sleep_for(100ms * yuzu::test::kSpinScale);
    CHECK_FALSE(t1_done.load(std::memory_order_acquire));
    CHECK_FALSE(t2_done.load(std::memory_order_acquire));

    // Release the gate: the parked worker finishes draining, the winner's pool join
    // completes, mark_teardown_complete() wakes the loser under the lock, and both
    // calls return.
    h.sink->release();

    const bool t1_ok =
        yuzu::test::spin_until([&] { return t1_done.load(std::memory_order_acquire); });
    const bool t2_ok =
        yuzu::test::spin_until([&] { return t2_done.load(std::memory_order_acquire); });

    // Cleanup runs unconditionally before any assertion (this file's GATE
    // DISCIPLINE convention): both threads must be joined before Harness's own
    // destructor -- a third, now purely sequential teardown() call, since both
    // racing calls have already returned -- runs.
    t1.join();
    t2.join();

    REQUIRE(t1_ok);
    REQUIRE(t2_ok);
    SUCCEED("two concurrent explicit teardown() calls on a live object both "
            "completed cleanly; the loser genuinely waited for the winner");
}
