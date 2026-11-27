/**
 * test_win_adapter_list.cpp -- yuzu::agent::win::read_adapters (agent-core).
 *
 * The injected-reader cases run on every OS and share the production process-wide slot, so the
 * one that blocks a reader opens its gate with a ScopeExit and waits for the slot to recover.
 * Ordering comes from promises; anything an abandonable reader touches is captured BY VALUE.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock, thread creation and, in the one real
 * case, an OS read): the deadline on a detached worker is the property under test (one 200 ms
 * wait). The real case is one bounded read of the local adapter list; on Windows it is the only
 * check that the shipped reader answers at all.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/win_adapter_list.hpp>

#include "test_helpers.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>

using namespace std::chrono_literals;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::AdapterList;
using yuzu::agent::win::read_adapters;
using yuzu::agent::win::read_adapters_for_test;

TEST_CASE("read_adapters_for_test returns the injected list", "[bounded_os_call][agent]") {
    const auto r = read_adapters_for_test(5000ms, [] {
        AdapterList out;
        yuzu::agent::win::Adapter a;
        a.friendly_name = "adapter-a";
        a.if_type = 6;
        a.physical_address = {1, 2, 3, 4, 5, 6};
        a.unicast.push_back({"192.0.2.1", 4, 24});
        a.gateways.push_back("192.0.2.254");
        a.dns_servers.push_back({"2001:db8::53", 6, 0});
        out.adapters.push_back(std::move(a));
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.win_error == 0);
    CHECK_FALSE(r.empty_table);
    REQUIRE(r.adapters.size() == 1);
    const auto& a = r.adapters.front();
    CHECK(a.friendly_name == "adapter-a");
    CHECK(a.if_type == 6);
    CHECK(a.physical_address.size() == 6);
    REQUIRE(a.unicast.size() == 1);
    CHECK(a.unicast.front().address == "192.0.2.1");
    CHECK(a.unicast.front().prefix_len == 24);
    REQUIRE(a.gateways.size() == 1);
    CHECK(a.gateways.front() == "192.0.2.254");
    REQUIRE(a.dns_servers.size() == 1);
    CHECK(a.dns_servers.front().family == 6);
}

TEST_CASE("a never-returning adapter reader times out, then Abandoned, then recovers",
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
    const std::function<AdapterList()> stalled = [opened = gate.get_future().share(), entered,
                                                  calls] {
        if (++*calls == 1)
            entered->set_value();
        opened.wait();
        return AdapterList{};
    };

    const auto first = read_adapters_for_test(200ms, stalled);
    CHECK(first.status == BoundedStatus::TimedOut);
    CHECK(first.adapters.empty());
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    const auto second = read_adapters_for_test(5000ms, stalled);
    CHECK(second.status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    release();
    CHECK(yuzu::test::spin_until([] {
        return read_adapters_for_test(5000ms, [] { return AdapterList{}; }).status ==
               BoundedStatus::Completed;
    }));
}

TEST_CASE("read_adapters completes with this OS's answer", "[bounded_os_call][agent]") {
    const auto r = read_adapters(yuzu::agent::win::kAdapterListDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
#ifdef _WIN32
    CHECK(r.win_error == 0);
    // Every Windows host lists its software loopback adapter (IF_TYPE_SOFTWARE_LOOPBACK).
    CHECK(std::any_of(r.adapters.begin(), r.adapters.end(),
                      [](const auto& a) { return a.if_type == 24; }));
#else
    CHECK(r.win_error == 120);
    CHECK(r.adapters.empty());
#endif
}
