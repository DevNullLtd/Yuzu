/**
 * test_ota_transfer_watchdog.cpp — deadline enforcement for in-flight OTA
 * `DownloadUpdate` transfers (issue #911, UP-101).
 *
 * Every case runs the watchdog in its NO-THREAD mode (`sweep_interval == 0`) and
 * drives `sweep_once()` directly against a STEPPED injected clock. Nothing here
 * sleeps, and nothing depends on a background thread being scheduled — the
 * sweeper thread is a cadence detail; the decision being tested is "has this
 * transfer's deadline passed, and was it cancelled exactly once".
 *
 * Pure in-memory primitive — no gRPC and no PostgreSQL required. The watchdog
 * takes an opaque CancelFn precisely so this file needs neither.
 */

#include "ota_transfer_watchdog.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

using yuzu::server::OtaTransferWatchdog;

namespace {

// Constructs a watchdog with no sweeper thread and a clock the test steps.
struct Harness {
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::now()};
    OtaTransferWatchdog wd{std::chrono::milliseconds(0)};

    Harness() {
        wd.set_clock_for_test([this] { return now; });
    }
    ~Harness() { wd.set_clock_for_test({}); }

    std::chrono::steady_clock::time_point in(std::chrono::seconds s) const { return now + s; }
};

} // namespace

TEST_CASE("OtaTransferWatchdog: a transfer inside its deadline is not cancelled",
          "[ota][watchdog]") {
    Harness h;
    bool cancelled = false;
    auto reg = h.wd.register_transfer([&cancelled] { cancelled = true; },
                                      h.in(std::chrono::seconds(30)));

    h.now += std::chrono::seconds(29);
    CHECK(h.wd.sweep_once() == 0);
    CHECK_FALSE(cancelled);
    CHECK_FALSE(reg.cancelled());
    CHECK(h.wd.in_flight_count() == 1);
}

TEST_CASE("OtaTransferWatchdog: an expired transfer is cancelled", "[ota][watchdog]") {
    Harness h;
    bool cancelled = false;
    auto reg = h.wd.register_transfer([&cancelled] { cancelled = true; },
                                      h.in(std::chrono::seconds(30)));

    // Stepping past the deadline is what cancels it — no real time elapses. In
    // production this is the mechanism that unblocks a `ServerWriter::Write`
    // stalled on a zero receive window, which nothing else can interrupt.
    h.now += std::chrono::seconds(31);
    CHECK(h.wd.sweep_once() == 1);
    CHECK(cancelled);
    CHECK(reg.cancelled());
}

TEST_CASE("OtaTransferWatchdog: a cancelled transfer is never cancelled twice",
          "[ota][watchdog]") {
    Harness h;
    int calls = 0;
    auto reg = h.wd.register_transfer([&calls] { ++calls; }, h.in(std::chrono::seconds(1)));

    h.now += std::chrono::seconds(2);
    CHECK(h.wd.sweep_once() == 1);
    // The entry stays live until the handler's Registration erases it, so every
    // subsequent sweep sees it again. Without the `cancelled` latch each of those
    // sweeps would re-invoke TryCancel on the same call for as long as the handler
    // takes to unwind.
    CHECK(h.wd.sweep_once() == 0);
    CHECK(h.wd.sweep_once() == 0);
    CHECK(calls == 1);
}

TEST_CASE("OtaTransferWatchdog: the registration erases its entry on destruction",
          "[ota][watchdog]") {
    Harness h;
    bool cancelled = false;
    {
        auto reg = h.wd.register_transfer([&cancelled] { cancelled = true; },
                                          h.in(std::chrono::seconds(1)));
        CHECK(h.wd.in_flight_count() == 1);
    }
    // The handler frame has returned. This is the invariant that makes the
    // sweeper's dereference safe: after the frame goes, its entry is gone, so a
    // later sweep cannot call into a captured context that no longer exists.
    CHECK(h.wd.in_flight_count() == 0);

    h.now += std::chrono::seconds(10);
    CHECK(h.wd.sweep_once() == 0);
    CHECK_FALSE(cancelled);
}

TEST_CASE("OtaTransferWatchdog: reset() is idempotent and early-erases", "[ota][watchdog]") {
    Harness h;
    auto reg = h.wd.register_transfer([] {}, h.in(std::chrono::seconds(1)));
    REQUIRE(h.wd.in_flight_count() == 1);

    reg.reset();
    CHECK(h.wd.in_flight_count() == 0);
    reg.reset();  // no double-erase, no crash
    CHECK(h.wd.in_flight_count() == 0);
    CHECK_FALSE(reg.cancelled());  // empty handle reports false, never dereferences
}

TEST_CASE("OtaTransferWatchdog: a moved-from registration does not erase twice",
          "[ota][watchdog]") {
    Harness h;
    auto reg = h.wd.register_transfer([] {}, h.in(std::chrono::seconds(1)));
    {
        auto moved = std::move(reg);
        CHECK(h.wd.in_flight_count() == 1);
    }  // `moved` erases here
    CHECK(h.wd.in_flight_count() == 0);
    // `reg` is empty; its destructor at scope exit must be a no-op rather than
    // erasing an id that a LATER registration may since have been given.
}

TEST_CASE("OtaTransferWatchdog: independent transfers expire independently",
          "[ota][watchdog]") {
    Harness h;
    std::vector<std::string> fired;
    auto slow = h.wd.register_transfer([&fired] { fired.emplace_back("slow"); },
                                       h.in(std::chrono::seconds(60)));
    auto fast = h.wd.register_transfer([&fired] { fired.emplace_back("fast"); },
                                       h.in(std::chrono::seconds(5)));

    h.now += std::chrono::seconds(10);
    CHECK(h.wd.sweep_once() == 1);
    REQUIRE(fired.size() == 1);
    CHECK(fired.front() == "fast");
    CHECK(fast.cancelled());
    CHECK_FALSE(slow.cancelled());

    h.now += std::chrono::seconds(60);
    CHECK(h.wd.sweep_once() == 1);
    CHECK(slow.cancelled());
}

TEST_CASE("OtaTransferWatchdog: the sweeper thread mode constructs and tears down cleanly",
          "[ota][watchdog]") {
    // The one case that exercises the real thread. It asserts LIFECYCLE only —
    // that construction starts a sweeper and destruction stops and joins it
    // without hanging — deliberately not timing behaviour, which every case above
    // covers deterministically.
    bool cancelled = false;
    {
        OtaTransferWatchdog wd{std::chrono::milliseconds(5)};
        auto reg = wd.register_transfer([&cancelled] { cancelled = true; },
                                        std::chrono::steady_clock::now() +
                                            std::chrono::hours(1));
        CHECK(wd.in_flight_count() == 1);
    }
    // A far-future deadline must not have fired, and the destructor must have
    // joined rather than detached — if it detached, the sweeper could outlive the
    // watchdog and touch freed state.
    CHECK_FALSE(cancelled);
}
