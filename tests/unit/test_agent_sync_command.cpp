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

#include "collection_settings_agent.hpp"
#include "sync_now_decision.hpp"
#include "sync_scheduler.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using yuzu::agent::AgentCollectionSettings;
using yuzu::agent::SettingsHooks;
using yuzu::agent::SyncNowDecision;
using yuzu::agent::SyncScheduler;
using yuzu::agent::SyncSource;
using yuzu::agent::decide_sync_now;
using yuzu::agent::decide_sync_settings;

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

// Same as make_fake_scheduler but collect() counts calls per source name, so a test can prove
// a request armed nothing (a forced source would be collected in the very next tick) or when a
// delayed one fires. `collects` only gains an entry once that source's collect() has run.
std::unique_ptr<SyncScheduler> make_counting_scheduler(std::map<std::string, int>& collects) {
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
    for (const char* name : {"installed_software", "device_ci"}) {
        SyncSource src;
        src.name = name;
        src.interval = std::chrono::seconds{86400};
        src.collect = [&collects, name = std::string{name}]()
            -> std::optional<std::pair<std::string, std::string>> {
            ++collects[name];
            return std::nullopt;
        };
        sched->add_source(src);
    }
    return sched;
}

} // namespace

TEST_CASE("decide_sync_now: unknown action fails, exit_code 2", "[sync][agent_command]") {
    auto decision = decide_sync_now("status", "all", std::nullopt, /*inventory_disable=*/false, nullptr);
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 2);
    CHECK(decision.output == "unknown __sync__ action: status");
}

TEST_CASE("decide_sync_now: no scheduler + --inventory-disable names the flag",
          "[sync][agent_command]") {
    auto decision = decide_sync_now("now", "all", std::nullopt, /*inventory_disable=*/true, nullptr);
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 1);
    CHECK(decision.output == "daily-sync disabled (--inventory-disable)");
}

TEST_CASE("decide_sync_now: no scheduler, sync not disabled, says not connected",
          "[sync][agent_command]") {
    auto decision = decide_sync_now("now", "all", std::nullopt, /*inventory_disable=*/false, nullptr);
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 1);
    CHECK(decision.output == "daily-sync not running (not connected)");
}

TEST_CASE("decide_sync_now: real scheduler + unknown source lists valid names",
          "[sync][agent_command]") {
    auto sched = make_fake_scheduler();
    auto decision = decide_sync_now("now", "bogus_source", std::nullopt, /*inventory_disable=*/false, sched.get());
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 2);
    CHECK(decision.output ==
          "unknown sync source 'bogus_source' — expected one of installed_software,device_ci or all");
}

TEST_CASE("decide_sync_now: real scheduler + explicit valid source succeeds",
          "[sync][agent_command]") {
    auto sched = make_fake_scheduler();
    auto decision = decide_sync_now("now", "device_ci", std::nullopt, /*inventory_disable=*/false, sched.get());
    CHECK(decision.status == SyncNowDecision::Status::Success);
    CHECK(decision.exit_code == 0);
    CHECK(decision.output == "requested|device_ci");
}

TEST_CASE("decide_sync_now: real scheduler + kAllSources arms every registered source",
          "[sync][agent_command]") {
    auto sched = make_fake_scheduler();
    auto decision =
        decide_sync_now("now", SyncScheduler::kAllSources, std::nullopt, /*inventory_disable=*/false, sched.get());
    CHECK(decision.status == SyncNowDecision::Status::Success);
    CHECK(decision.exit_code == 0);
    CHECK(decision.output == "requested|installed_software,device_ci");
}

TEST_CASE("decide_sync_now: delay_max_s accepts an integer in 0..86400", "[sync][agent_command]") {
    for (const char* ok : {"0", "120", "86400"}) {
        auto sched = make_fake_scheduler();
        auto decision =
            decide_sync_now("now", "device_ci", ok, /*inventory_disable=*/false, sched.get());
        INFO("delay_max_s=" << ok);
        CHECK(decision.status == SyncNowDecision::Status::Success);
        CHECK(decision.output == "requested|device_ci");
    }
}

TEST_CASE("decide_sync_now: delay_max_s reaches the scheduler: 0 collects in the same tick, "
          "a positive value only once the stable offset has passed",
          "[sync][agent_command]") {
    constexpr std::int64_t kNow = 1000;
    SECTION("absent and 0 are the immediate path") {
        for (std::optional<std::string_view> immediate :
             {std::optional<std::string_view>{}, std::optional<std::string_view>{"0"}}) {
            std::map<std::string, int> collects;
            auto sched = make_counting_scheduler(collects);
            auto decision = decide_sync_now("now", "device_ci", immediate,
                                            /*inventory_disable=*/false, sched.get());
            REQUIRE(decision.status == SyncNowDecision::Status::Success);
            sched->tick(kNow);
            CHECK(collects["device_ci"] == 1);
        }
    }
    SECTION("120 is deferred to a later tick") {
        std::map<std::string, int> collects;
        auto sched = make_counting_scheduler(collects);
        auto decision = decide_sync_now("now", "device_ci", "120", /*inventory_disable=*/false,
                                        sched.get());
        REQUIRE(decision.status == SyncNowDecision::Status::Success);
        sched->tick(kNow);
        CHECK(collects["device_ci"] == 0); // would be 1 if the delay were dropped on the way in
        sched->tick(kNow + 120); // the stable offset is inside [0, 120)
        CHECK(collects["device_ci"] == 1);
    }
}

TEST_CASE("decide_sync_now: malformed or out-of-range delay_max_s fails exit 2 and arms nothing",
          "[sync][agent_command]") {
    // "" is a present-but-empty value: malformed, not absent (absent is std::nullopt above).
    // "+5" and "5 " are rejected by from_chars (no leading '+', no trailing characters).
    for (const char* bad :
         {"", "abc", "-1", "90000", "1.5", "12s", " 5", "+5", "5 ", "99999999999999999999"}) {
        std::map<std::string, int> collects;
        auto sched = make_counting_scheduler(collects);
        auto decision =
            decide_sync_now("now", "device_ci", bad, /*inventory_disable=*/false, sched.get());
        INFO("delay_max_s=" << bad);
        CHECK(decision.status == SyncNowDecision::Status::Failure);
        CHECK(decision.exit_code == 2);
        CHECK(decision.output ==
              std::string("invalid delay_max_s '") + bad + "' — expected an integer 0..86400");
        sched->tick(1000); // a forced source would be collected at once
        CHECK(collects.empty());
    }
}

TEST_CASE("decide_sync_now: a source list is all-or-nothing", "[sync][agent_command]") {
    SECTION("every name known: armed in registration order") {
        auto sched = make_fake_scheduler();
        auto decision = decide_sync_now("now", "device_ci,installed_software", std::nullopt,
                                        /*inventory_disable=*/false, sched.get());
        CHECK(decision.status == SyncNowDecision::Status::Success);
        CHECK(decision.output == "requested|installed_software,device_ci");
    }
    SECTION("one unknown name: failure naming the valid set, nothing armed") {
        std::map<std::string, int> collects;
        auto sched = make_counting_scheduler(collects);
        auto decision = decide_sync_now("now", "device_ci,bogus", std::nullopt,
                                        /*inventory_disable=*/false, sched.get());
        CHECK(decision.status == SyncNowDecision::Status::Failure);
        CHECK(decision.exit_code == 2);
        CHECK(decision.output ==
              "unknown sync source 'device_ci,bogus' — expected one of installed_software,device_ci or all");
        sched->tick(1000);
        CHECK(collects.empty());
    }
    SECTION("an empty list entry is unknown") {
        auto sched = make_fake_scheduler();
        auto decision = decide_sync_now("now", "device_ci,", std::nullopt, /*inventory_disable=*/false,
                                        sched.get());
        CHECK(decision.status == SyncNowDecision::Status::Failure);
    }
}

// ---------------------------------------------------------------------------
// SAM-39: the `settings` action of the same reserved command (collection_settings_agent.hpp).
// ---------------------------------------------------------------------------

TEST_CASE("decide_sync_now: settings is not a now-action; it has its own decision",
          "[sync][agent_command][collection_settings]") {
    auto decision = decide_sync_now("settings", "all", std::nullopt, /*inventory_disable=*/false, nullptr);
    CHECK(decision.status == SyncNowDecision::Status::Failure);
    CHECK(decision.exit_code == 2);
    CHECK(decision.output == "unknown __sync__ action: settings");
}

TEST_CASE("decide_sync_settings: a valid command reaches the scheduler and arms no sync",
          "[sync][agent_command][collection_settings]") {
    std::map<std::string, int> collects;
    auto sched = make_counting_scheduler(collects);
    const std::string doc =
        "v1\ninterval=172800\nwindow=none\ntz=\n"
        "plugin.installed_apps=1\nplugin.middleware=1\nplugin.msi_packages=1\n"
        "plugin.pkg_inventory=1\nplugin.runtimes=1\nplugin.windows_optional_features=1\n";
    const std::map<std::string, std::string> params{{"version", yuzu::agent::sha256_hex(doc)},
                                                    {"document", doc}};
    std::optional<AgentCollectionSettings> applied;
    std::map<std::string, std::string> kv;
    const SettingsHooks hooks{
        [&](std::string_view k, std::string_view v) {
            kv[std::string{k}] = std::string{v};
            return true;
        },
        [&](const AgentCollectionSettings& s) {
            applied = s;
            sched->apply_settings(yuzu::agent::kSettingsSyncSource,
                                  std::chrono::seconds{s.interval_s}, s.window);
        }};
    const auto decision = decide_sync_settings(params, /*inventory_disable=*/false,
                                               /*scheduler_running=*/true, hooks);
    CHECK(decision.status == SyncNowDecision::Status::Success);
    CHECK(decision.output == "applied|" + yuzu::agent::sha256_hex(doc));
    REQUIRE(applied.has_value());
    CHECK(kv.at("settings.document") == doc);
    sched->tick(1000); // a forced source would be collected here
    CHECK(collects.empty());
}
