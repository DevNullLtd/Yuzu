/**
 * test_win_vss_snapshots.cpp -- yuzu::agent::win::read_vss_snapshots (agent-core).
 *
 * The injected-reader cases run on every OS and share the production process-wide slot, so each
 * one that blocks a reader opens its gate with a ScopeExit and waits for the slot to recover.
 * Ordering comes from promises; anything an abandonable reader touches is captured BY VALUE.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock, thread creation and, in the one real
 * case, an OS service): the deadline on a detached worker is the property under test (one 200 ms
 * wait). The real case is one bounded read of the local shadow copies; on Windows it is the only
 * check that the shipped reader answers at all.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/win_vss_snapshots.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>

using namespace std::chrono_literals;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::read_vss_snapshots;
using yuzu::agent::win::read_vss_snapshots_for_test;
using yuzu::agent::win::VssSnapshotsRead;
using yuzu::agent::win::VssStep;

TEST_CASE("read_vss_snapshots_for_test returns the injected snapshots",
          "[bounded_os_call][agent]") {
    const auto r = read_vss_snapshots_for_test(5000ms, [] {
        VssSnapshotsRead out;
        out.failed_step = VssStep::next;
        out.hr = -1;
        out.context_narrowed = true;
        out.skipped_wrong_type = true;
        out.truncated = true;
        out.snapshots.push_back({"id-a", "volume-a", "device-a"});
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.api_available);
    CHECK(r.failed_step == VssStep::next);
    CHECK(r.hr == -1);
    CHECK(r.context_narrowed);
    CHECK(r.skipped_wrong_type);
    CHECK(r.truncated);
    REQUIRE(r.snapshots.size() == 1);
    const auto& s = r.snapshots.front();
    CHECK(s.snapshot_id == "id-a");
    CHECK(s.original_volume == "volume-a");
    CHECK(s.device_object == "device-a");
}

TEST_CASE("a never-returning VSS reader times out, then Abandoned, then recovers",
          "[bounded_os_call][agent]") {
    std::promise<void> gate;
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    // A failing REQUIRE must not leave a worker wedged: it holds the process-wide slot.
    yuzu::test::ScopeExit opener{release};
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto calls = std::make_shared<std::atomic<int>>(0);
    const std::function<VssSnapshotsRead()> stalled = [opened = gate.get_future().share(), entered,
                                                       calls] {
        if (++*calls == 1)
            entered->set_value();
        opened.wait();
        return VssSnapshotsRead{};
    };

    const auto first = read_vss_snapshots_for_test(200ms, stalled);
    CHECK(first.status == BoundedStatus::TimedOut);
    CHECK(first.snapshots.empty());
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    const auto second = read_vss_snapshots_for_test(5000ms, stalled);
    CHECK(second.status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    release();
    CHECK(yuzu::test::spin_until([] {
        return read_vss_snapshots_for_test(5000ms, [] { return VssSnapshotsRead{}; }).status ==
               BoundedStatus::Completed;
    }));
}

TEST_CASE("read_vss_snapshots completes with this OS's answer", "[bounded_os_call][agent]") {
    const auto r = read_vss_snapshots(yuzu::agent::win::kVssDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
#ifdef _WIN32
    // Without administrative rights the walk is refused: E_ACCESSDENIED, and nothing else.
    const bool denied = r.hr == static_cast<std::int32_t>(0x80070005u);
    INFO("failed_step " << static_cast<int>(r.failed_step) << " hr " << r.hr);
    CHECK((r.failed_step == VssStep::none || denied));
#else
    CHECK_FALSE(r.api_available);
    CHECK(r.failed_step == VssStep::none);
    CHECK(r.snapshots.empty());
#endif
}
