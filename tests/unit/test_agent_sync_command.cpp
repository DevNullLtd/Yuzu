// Pure unit tests for sync_now_decision.hpp's decide_sync_now — the
// `__sync__.now` reserved-command DECISION core extracted from agent.cpp's
// main gRPC command-read loop (agents/core/src/agent.cpp, the
// `cmd.plugin() == "__sync__"` branch). This intercept sits in front of the
// plugin-match loop and had no independent test coverage before this file:
// the existing LocalDispatcher/PluginHandle harnesses test PLUGIN dispatch,
// which happens strictly after this reserved-command check.
//
// No gRPC, no live command loop, no mocking of the agent itself: the only
// non-trivial dependency, SyncScheduler, is itself gRPC/SQLite-free (see
// sync_scheduler.hpp) and is constructed here with the identical injected
// kv_get/kv_set/sender lambda pattern tests/unit/test_inventory_sync.cpp
// already uses — a real (not mocked) SyncScheduler.

#include "sync_now_decision.hpp"
#include "sync_scheduler.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using yuzu::agent::SyncNowDecision;
using yuzu::agent::SyncScheduler;
using yuzu::agent::SyncSource;
using yuzu::agent::decide_sync_now;

namespace {

// Same construction pattern as test_inventory_sync.cpp's SchedulerFixture:
// an in-memory kv map plus a sender_ that always "succeeds" with no
// need_full. decide_sync_now never ticks the scheduler (it only calls
// request_now()/source_names()), so collect()/sender() are never actually
// invoked here — they exist only because SyncSource/SyncScheduler require
// them to be constructed.
std::unique_ptr<SyncScheduler> make_fake_scheduler() {
    auto kv = std::make_shared<std::map<std::string, std::string>>();
    auto kv_get = [kv](const std::string& k) {
        auto it = kv->find(k);
        return it == kv->end() ? std::string{} : it->second;
    };
    auto kv_set = [kv](const std::string& k, const std::string& v) { (*kv)[k] = v; };
    auto sender = [](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> { return std::vector<std::string>{}; };
    auto sched = std::make_unique<SyncScheduler>("agent-sync-cmd", kv_get, kv_set, sender);

    SyncSource installed_software;
    installed_software.name = "installed_software";
    installed_software.interval = std::chrono::seconds{86400};
    installed_software.collect =
        []() -> std::optional<std::pair<std::string, std::string>> { return std::nullopt; };
    sched->add_source(installed_software);

    SyncSource device_ci;
    device_ci.name = "device_ci";
    device_ci.interval = std::chrono::seconds{86400};
    device_ci.collect =
        []() -> std::optional<std::pair<std::string, std::string>> { return std::nullopt; };
    sched->add_source(device_ci);

    return sched;
}

} // namespace

TEST_CASE("decide_sync_now: unknown action fails, exit_code 2", "[sync][agent_command]") {
    auto decision = decide_sync_now("status", "all", /*inventory_disable=*/false, nullptr);
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 2);
    CHECK(decision.output == "unknown __sync__ action: status");
}

TEST_CASE("decide_sync_now: no scheduler + --inventory-disable names the flag",
          "[sync][agent_command]") {
    auto decision = decide_sync_now("now", "all", /*inventory_disable=*/true, nullptr);
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 1);
    CHECK(decision.output == "daily-sync disabled (--inventory-disable)");
}

TEST_CASE("decide_sync_now: no scheduler, sync not disabled, says not connected",
          "[sync][agent_command]") {
    auto decision = decide_sync_now("now", "all", /*inventory_disable=*/false, nullptr);
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 1);
    CHECK(decision.output == "daily-sync not running (not connected)");
}

TEST_CASE("decide_sync_now: real scheduler + unknown source lists valid names",
          "[sync][agent_command]") {
    auto sched = make_fake_scheduler();
    auto decision = decide_sync_now("now", "bogus_source", /*inventory_disable=*/false, sched.get());
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 2);
    CHECK(decision.output ==
          "unknown sync source 'bogus_source' — expected one of installed_software,device_ci or all");
}

TEST_CASE("decide_sync_now: real scheduler + explicit valid source succeeds",
          "[sync][agent_command]") {
    auto sched = make_fake_scheduler();
    auto decision = decide_sync_now("now", "device_ci", /*inventory_disable=*/false, sched.get());
    CHECK(decision.status == SyncNowDecision::Status::Success);
    CHECK(decision.exit_code == 0);
    CHECK(decision.output == "requested|device_ci");
}

TEST_CASE("decide_sync_now: real scheduler + kAllSources arms every registered source",
          "[sync][agent_command]") {
    auto sched = make_fake_scheduler();
    auto decision =
        decide_sync_now("now", SyncScheduler::kAllSources, /*inventory_disable=*/false, sched.get());
    CHECK(decision.status == SyncNowDecision::Status::Success);
    CHECK(decision.exit_code == 0);
    CHECK(decision.output == "requested|installed_software,device_ci");
}
