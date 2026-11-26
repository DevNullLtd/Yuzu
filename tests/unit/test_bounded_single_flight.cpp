/**
 * test_bounded_single_flight.cpp -- yuzu::agent::SingleFlightSlot, detail::bounded_single_flight,
 * the BoundedStatus mapping (bounded_status.hpp) and the Net* page loop
 * yuzu::agent::win::detail::drain_net_pages (win_bounded_run.hpp).
 *
 * The driver is instantiated in THIS image with test-owned static slots (a slot must outlive any
 * abandoned worker). Ordering comes from promises and the slot's waiter count, every gate is
 * opened by a ScopeExit, waiters and recovery are awaited with yuzu::test::spin_until, and
 * anything an abandonable call touches is captured BY VALUE.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock and on thread creation): a deadline
 * on a detached worker is the property under test. The cases wait out a few deadlines of at most
 * one second each and start short-lived threads only; nothing touches disk or network.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/bounded_single_flight.hpp>

#include "local_dispatcher.hpp"
#include "test_bounded_return.hpp"
#include "test_helpers.hpp"
#include "thread_pool.hpp"
#include "win_bounded_run.hpp" // agents/core/src

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// The driver refuses to instantiate in a TU that links agent-core from outside it and is not a
// test image, which is every plugin. This TU is such a consumer, so it pins the refusal's trigger.
#if !defined(YUZU_AGENT_CORE_CONSUMER)
#error "yuzu_agent_core_dep no longer defines YUZU_AGENT_CORE_CONSUMER: plugins are unguarded"
#endif

using namespace std::chrono_literals;
using yuzu::agent::BoundedFlight;
using yuzu::agent::BoundedStatus;
using yuzu::agent::SingleFlightSlot;
using yuzu::agent::SlotWait;
using yuzu::agent::detail::bounded_single_flight;
using yuzu::agent::win::detail::drain_net_pages;
using yuzu::agent::win::detail::Drained;
using yuzu::agent::win::detail::kMaxNetPages;
using yuzu::agent::win::detail::NetPage;

namespace {

/// What an abandonable call blocks on. Copy `opened` into the call; open() is idempotent, so a
/// ScopeExit and the test body may both call it.
struct Gate {
    std::promise<void> promise;
    std::shared_future<void> opened = promise.get_future().share();
    bool done = false;
    void open() {
        if (!done) {
            done = true;
            promise.set_value();
        }
    }
};

/// True once the slot admits and completes a call again.
bool recovers(SingleFlightSlot& slot) {
    return yuzu::test::spin_until([&slot] {
        return bounded_single_flight(slot, 5000ms, SlotWait::none, [] { return 0; }).status ==
               BoundedStatus::Completed;
    });
}

/// Drains a scripted pager: `calls` counts the pages asked for, and one past the script throws.
Drained<int> drain_script(std::size_t max_entries, const std::vector<NetPage<int>>& script,
                          std::size_t& calls) {
    calls = 0;
    return drain_net_pages<int>(max_entries, [&] { return script.at(calls++); });
}

// The fake plugin behind the forward_bounded_failure case; execute runs on the test's thread.
BoundedStatus g_forward_status = BoundedStatus::Completed;
bool g_forwarded = false;

int forward_execute(YuzuCommandContext* raw, const char*, const YuzuParam*, std::size_t) {
    yuzu::CommandContext ctx{raw};
    g_forwarded = yuzu::agent::forward_bounded_failure(ctx, g_forward_status, "src");
    return 0;
}

} // namespace

TEST_CASE("bounded_cause names every status that is not Completed", "[bounded_os_call][agent]") {
    using yuzu::agent::bounded_cause;
    CHECK(bounded_cause(BoundedStatus::Completed).empty());
    CHECK(bounded_cause(BoundedStatus::TimedOut) == "deadline_exceeded");
    CHECK(bounded_cause(BoundedStatus::Rejected) == "deadline_exceeded");
    CHECK(bounded_cause(BoundedStatus::Busy) == "call_in_progress");
    CHECK(bounded_cause(BoundedStatus::Abandoned) == "abandoned_call_pending");
}

TEST_CASE("forward_bounded_failure reports CONSTRAINED and PARTIAL with prefix:cause",
          "[bounded_os_call][agent]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &forward_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto status : {BoundedStatus::TimedOut, BoundedStatus::Busy,
                              BoundedStatus::Abandoned, BoundedStatus::Rejected}) {
        g_forward_status = status;
        const auto r = dispatcher.run(&descriptor, "probe");
        CHECK(g_forwarded);
        CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(r.result_provenance == "src:" + std::string{yuzu::agent::bounded_cause(status)});
    }
    g_forward_status = BoundedStatus::Completed;
    const auto r = dispatcher.run(&descriptor, "probe");
    CHECK_FALSE(g_forwarded);
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(r.result_provenance.empty());
}

TEST_CASE("acquire_until takes a free slot, gives up on a held one and sees abandonment",
          "[bounded_os_call][agent]") {
    using Slot = SingleFlightSlot;
    Slot slot;
    // Free: taken even though the time point has passed by the time it is looked at.
    const auto t = slot.acquire_until(std::chrono::steady_clock::now());
    REQUIRE(t.result == Slot::Acquire::acquired);
    CHECK(slot.acquire_until(std::chrono::steady_clock::now() + 20ms).result ==
          Slot::Acquire::busy);
    slot.mark_abandoned(t.generation);
    Slot::Ticket u;
    yuzu::test::must_return_within(10s, "acquire_until on an abandoned slot", [&] {
        u = slot.acquire_until(std::chrono::steady_clock::now() + 1h);
    });
    CHECK(u.result == Slot::Acquire::abandoned);
    slot.release();
}

TEST_CASE("a spent budget releases the slot, starts nothing and answers TimedOut",
          "[bounded_os_call][agent]") {
    static SingleFlightSlot slot;
    auto calls = std::make_shared<std::atomic<int>>(0);
    for (const auto wait : {SlotWait::none, SlotWait::within_deadline}) {
        const auto r = bounded_single_flight(slot, 0ms, wait, [calls] { return ++*calls; });
        CHECK(r.status == BoundedStatus::TimedOut);
        CHECK_FALSE(r.value.has_value());
        const auto t = slot.try_acquire();
        CHECK(t.result == SingleFlightSlot::Acquire::acquired);
        slot.release();
    }
    CHECK(calls->load() == 0);
}

TEST_CASE("a never-returning call times out, then the slot answers Abandoned until it returns",
          "[bounded_os_call][agent]") {
    static SingleFlightSlot slot;
    Gate gate;
    yuzu::test::ScopeExit opener{[&gate] { gate.open(); }};
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto calls = std::make_shared<std::atomic<int>>(0);
    const auto stalled = [opened = gate.opened, entered, calls] {
        if (++*calls == 1)
            entered->set_value();
        opened.wait();
        return 1;
    };

    BoundedFlight<int> first;
    std::chrono::steady_clock::duration took{};
    yuzu::test::must_return_within(10s, "bounded call, never returns", [&] {
        const auto began = std::chrono::steady_clock::now();
        first = bounded_single_flight(slot, 200ms, SlotWait::within_deadline, stalled);
        took = std::chrono::steady_clock::now() - began;
    });
    CHECK(first.status == BoundedStatus::TimedOut);
    CHECK_FALSE(first.value.has_value());
    CHECK(took >= 150ms); // at the deadline, not before it (slack for coarse timers)
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    // Answered at once although this call may wait: the holder is past its deadline.
    BoundedFlight<int> next;
    yuzu::test::must_return_within(10s, "bounded call on an abandoned slot", [&] {
        next = bounded_single_flight(slot, 1h, SlotWait::within_deadline, stalled);
    });
    CHECK(next.status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    gate.open();
    CHECK(recovers(slot));
}

TEST_CASE("a healthy call is waited for with within_deadline and answered Busy with none",
          "[bounded_os_call][agent]") {
    static SingleFlightSlot slot;
    Gate gate;
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto calls = std::make_shared<std::atomic<int>>(0);
    std::future<BoundedFlight<int>> first;
    std::future<BoundedFlight<int>> second;
    // Declared AFTER the futures: destructs first, so a failing REQUIRE opens the gate before a
    // future's destructor joins.
    yuzu::test::ScopeExit opener{[&gate] { gate.open(); }};

    first = std::async(std::launch::async, [opened = gate.opened, entered, calls] {
        return bounded_single_flight(slot, 30000ms, SlotWait::within_deadline,
                                     [opened, entered, calls] {
                                         ++*calls;
                                         entered->set_value();
                                         opened.wait();
                                         return 1;
                                     });
    });
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    BoundedFlight<int> none;
    yuzu::test::must_return_within(10s, "bounded call, SlotWait::none on a held slot", [&] {
        none = bounded_single_flight(slot, 1h, SlotWait::none, [calls] { return ++*calls; });
    });
    CHECK(none.status == BoundedStatus::Busy);
    CHECK_FALSE(none.value.has_value());

    second = std::async(std::launch::async, [calls] {
        return bounded_single_flight(slot, 30000ms, SlotWait::within_deadline, [calls] {
            ++*calls;
            return 2;
        });
    });
    // Parked behind the healthy call before the gate opens, so only release() can wake it in time.
    REQUIRE(yuzu::test::spin_until([] { return slot.waiters() == 1; }));
    CHECK(calls->load() == 1);

    gate.open();
    const auto a = first.get();
    const auto b = second.get();
    REQUIRE(a.status == BoundedStatus::Completed);
    REQUIRE(b.status == BoundedStatus::Completed);
    CHECK(a.value == 1);
    CHECK(b.value == 2);
    CHECK(calls->load() == 2);
}

// No deadline orders this case: the test holds the slot and abandons it only once the caller is
// parked, so a slow runner cannot reorder the two.
TEST_CASE("mark_abandoned wakes a parked caller, which is answered Abandoned",
          "[bounded_os_call][agent]") {
    static SingleFlightSlot slot;
    const auto held = slot.try_acquire();
    REQUIRE(held.result == SingleFlightSlot::Acquire::acquired);
    auto calls = std::make_shared<std::atomic<int>>(0);
    std::future<BoundedFlight<int>> queued;
    // After the future: releases the slot first, so a failing REQUIRE cannot leave it parked.
    yuzu::test::ScopeExit releaser{[] { slot.release(); }};

    queued = std::async(std::launch::async, [calls] {
        return bounded_single_flight(slot, 1h, SlotWait::within_deadline,
                                     [calls] { return ++*calls; });
    });
    REQUIRE(yuzu::test::spin_until([] { return slot.waiters() == 1; }));
    slot.mark_abandoned(held.generation);
    REQUIRE(queued.wait_for(10s) == std::future_status::ready);
    CHECK(queued.get().status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 0);
}

// The same through the driver's own timeout. The second caller may park before that deadline or,
// on a slow runner, arrive after it: the answer is Abandoned either way.
TEST_CASE("a caller queued behind a call that times out is answered Abandoned",
          "[bounded_os_call][agent]") {
    static SingleFlightSlot slot;
    Gate gate;
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto calls = std::make_shared<std::atomic<int>>(0);
    std::future<BoundedFlight<int>> first;
    std::future<BoundedFlight<int>> queued;
    yuzu::test::ScopeExit opener{[&gate] { gate.open(); }}; // after the futures (see above)

    first = std::async(std::launch::async, [opened = gate.opened, entered, calls] {
        return bounded_single_flight(slot, 1000ms, SlotWait::within_deadline,
                                     [opened, entered, calls] {
                                         ++*calls;
                                         entered->set_value();
                                         opened.wait();
                                         return 1;
                                     });
    });
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);
    queued = std::async(std::launch::async, [calls] {
        return bounded_single_flight(slot, 1h, SlotWait::within_deadline,
                                     [calls] { return ++*calls; });
    });
    // The gate is still shut: only the first call's deadline can release this caller.
    REQUIRE(queued.wait_for(10s) == std::future_status::ready);
    CHECK(queued.get().status == BoundedStatus::Abandoned);
    CHECK(first.get().status == BoundedStatus::TimedOut);
    CHECK(calls->load() == 1);

    gate.open();
    CHECK(recovers(slot));
}

TEST_CASE("a Rejected admission leaves the slot free", "[bounded_os_call][agent]") {
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::kMaxOutstandingBoundedCalls;
    const auto drained = [] {
        return g_outstanding_bounded_calls.load() == 0;
    };

    // Starts from zero outstanding calls in this image (sibling tests' guards are released on
    // their own threads shortly after they finish).
    REQUIRE(yuzu::test::spin_until(drained, 10s));

    static SingleFlightSlot slot;
    auto calls = std::make_shared<std::atomic<int>>(0);
    {
        Gate gate;
        yuzu::test::ScopeExit opener{[&gate] { gate.open(); }};
        for (int i = 0; i < kMaxOutstandingBoundedCalls; ++i) {
            auto parked = yuzu::shared::bounded_call_ex(1ms, [opened = gate.opened] {
                opened.wait();
                return true;
            });
            REQUIRE(parked.status == yuzu::shared::BoundedCallStatus::TimedOut);
        }

        const auto r = bounded_single_flight(slot, 5000ms, SlotWait::within_deadline,
                                             [calls] { return ++*calls; });
        CHECK(r.status == BoundedStatus::Rejected);
        CHECK_FALSE(r.value.has_value());
        CHECK(calls->load() == 0);
        // The worker never ran, so the caller released the slot: it is acquirable again.
        CHECK(slot.try_acquire().result == SingleFlightSlot::Acquire::acquired);
        slot.release();
    }
    CHECK(yuzu::test::spin_until(drained, 10s)); // later cases need admissions again
}

TEST_CASE("a stalled slot does not wedge the thread pool", "[bounded_os_call][agent]") {
    constexpr std::size_t kTasks = 12;
    static SingleFlightSlot slot;
    Gate gate;
    std::mutex m;
    std::condition_variable cv;
    std::vector<BoundedStatus> seen;
    std::promise<void> plain_ran;
    auto plain_f = plain_ran.get_future();
    // Declared after everything the tasks touch, so its destructor joins them first.
    yuzu::agent::ThreadPool pool(4);
    yuzu::test::ScopeExit opener{[&gate] { gate.open(); }};

    for (std::size_t i = 0; i < kTasks; ++i) {
        REQUIRE(pool.submit([&, opened = gate.opened] {
            const auto r = bounded_single_flight(slot, 200ms, SlotWait::within_deadline, [opened] {
                opened.wait();
                return 0;
            });
            const std::lock_guard lock{m};
            seen.push_back(r.status);
            cv.notify_all();
        }));
    }
    {
        std::unique_lock lock{m};
        REQUIRE(cv.wait_for(lock, 30s, [&] { return seen.size() == kTasks; }));
        CHECK(std::ranges::count(seen, BoundedStatus::TimedOut) == 1);
        CHECK(std::ranges::all_of(seen, [](BoundedStatus s) {
            return s == BoundedStatus::TimedOut || s == BoundedStatus::Abandoned ||
                   s == BoundedStatus::Busy;
        }));
    }

    REQUIRE(pool.submit([&plain_ran] { plain_ran.set_value(); }));
    CHECK(plain_f.wait_for(10s) == std::future_status::ready);

    gate.open();
    CHECK(recovers(slot));
}

TEST_CASE("drain_net_pages returns every item of every page in order", "[bounded_os_call][agent]") {
    std::size_t calls = 0;
    const auto one = drain_script(10, {{0, 2, {1, 2}}}, calls);
    CHECK(one.items == std::vector<int>{1, 2});
    CHECK(one.nerr == 0);
    CHECK_FALSE(one.truncated);
    CHECK_FALSE(one.no_progress);
    CHECK(calls == 1);

    // The second page read an entry the caller did not copy: that is still progress.
    const auto paged =
        drain_script(10, {{234, 2, {1, 2}}, {234, 1, {}}, {234, 1, {3}}, {0, 1, {4}}}, calls);
    CHECK(paged.items == std::vector<int>{1, 2, 3, 4});
    CHECK(paged.nerr == 0);
    CHECK_FALSE(paged.truncated);
    CHECK_FALSE(paged.no_progress);
    CHECK(calls == 4);
}

TEST_CASE("drain_net_pages stops at the entry past max_entries", "[bounded_os_call][agent]") {
    std::size_t calls = 0;
    const auto over = drain_script(3, {{234, 2, {1, 2}}, {234, 2, {3, 4}}}, calls);
    CHECK(over.items == std::vector<int>{1, 2, 3});
    CHECK(over.truncated);
    CHECK_FALSE(over.no_progress);
    CHECK(over.nerr == 0);
    CHECK(calls == 2);

    const auto exact = drain_script(3, {{0, 3, {1, 2, 3}}}, calls);
    CHECK(exact.items.size() == 3);
    CHECK_FALSE(exact.truncated);
}

TEST_CASE("drain_net_pages ends a pager that makes no progress", "[bounded_os_call][agent]") {
    std::size_t calls = 0;
    const auto empty = drain_script(10, {{234, 0, {}}}, calls);
    CHECK(empty.no_progress);
    CHECK_FALSE(empty.truncated);
    CHECK(empty.nerr == 0);
    CHECK(calls == 1);

    calls = 0;
    const auto endless = drain_net_pages<int>(kMaxNetPages + 1, [&calls] {
        ++calls;
        return NetPage<int>{234, 1, {7}};
    });
    CHECK(calls == kMaxNetPages);
    CHECK(endless.items.size() == kMaxNetPages);
    CHECK(endless.no_progress);
    CHECK_FALSE(endless.truncated);
    CHECK(endless.nerr == 0);
}

TEST_CASE("drain_net_pages keeps earlier pages when a later one fails",
          "[bounded_os_call][agent]") {
    std::size_t calls = 0;
    const auto r = drain_script(10, {{234, 2, {1, 2}}, {5, 1, {3}}}, calls);
    CHECK(r.nerr == 5);
    CHECK(r.items == std::vector<int>{1, 2});
    CHECK_FALSE(r.truncated);
    CHECK_FALSE(r.no_progress);
    CHECK(calls == 2);
}
