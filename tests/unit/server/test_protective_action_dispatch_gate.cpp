/**
 * test_protective_action_dispatch_gate.cpp — protective actions (the
 * quarantine plugin's four actions plus `__guard__.push_rules`) are never
 * refused by plugin enablement. Mirrors test_os_kill_switch_dispatch_gate.cpp:
 * every gate is bound with a real `AgentRegistry` and the exact send set
 * (`drain_gateway_pending`), with `tar.sql` as the control that is still
 * refused at every gate. Presence is an injected stub — no Postgres, no I/O.
 */

#include "agent_registry.hpp"
#include "capability_decls/core_dispatch_capabilities.hpp"
#include "capability_decls/plugin_action_catalogue_c.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"
#include "event_bus.hpp"
#include "plugin_config_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

using yuzu::server::CommandCapability;
using yuzu::server::ContainmentGate;
using yuzu::server::DispatchClass;
using yuzu::server::Mutability;
using yuzu::server::PresenceReadError;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::ClassifiedCommand;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::KillSwitchFn;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

using IdSet = std::unordered_set<std::string>;
using Presence = std::vector<yuzu::server::PresenceIdentity>;

constexpr CommandCapability protective_cap(std::string_view plugin, std::string_view action,
                                           bool system_reserved = false) {
    return CommandCapability{
        .plugin = plugin,
        .action = action,
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Security",
        .operation = yuzu::server::authz::Operation::Execute,
        .risk_tier = yuzu::server::authz::RiskTier::Medium,
        .system_reserved = system_reserved,
    };
}

constexpr CommandCapability kTarSql{
    .plugin = "tar",
    .action = "sql",
    .dispatch_class = DispatchClass::ReadOnly,
    .mutability = Mutability::None,
    .securable = "Infrastructure",
    .operation = yuzu::server::authz::Operation::Read,
    .risk_tier = yuzu::server::authz::RiskTier::Low,
    .system_reserved = false,
};

/// A KillSwitchFn that counts invocations and returns `result`.
struct CountingSwitch {
    std::optional<IdSet> result;
    std::shared_ptr<int> calls = std::make_shared<int>(0);
    KillSwitchFn fn() const {
        return [r = result, c = calls](std::string_view, std::string_view) {
            ++*c;
            return r;
        };
    }
};

agent_pb::AgentInfo make_info(const std::string& id, const std::string& os,
                              const std::vector<std::string>& plugins = {}) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname("host.local");
    a.mutable_platform()->set_os(os);
    for (const auto& p : plugins)
        a.add_plugins()->set_name(p);
    return a;
}

ClassifiedCommand finalize(const CommandCapability& cap, const KillSwitchFn& fn) {
    auto r = yuzu::server::detail::finalize_classified_command(
        cap, fn, cap.plugin, cap.action, "protective-cmd", {}, {}, 0, 0, {}, {});
    REQUIRE(r.has_value());
    return std::move(*r);
}

void route_via_gateway(AgentRegistry& registry, const std::vector<std::string>& ids) {
    for (const auto& id : ids)
        REQUIRE(registry.set_gateway_route(
            id, {}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
}

/// The exact send set: sorted agent ids queued for the gateway.
std::vector<std::string> drained(AgentRegistry& registry) {
    std::vector<std::string> v;
    for (const auto& p : registry.drain_gateway_pending())
        v.push_back(p.agent_id);
    std::sort(v.begin(), v.end());
    return v;
}

constexpr std::chrono::seconds kTtl{77};

/// Presence stub: records calls and the ttl it was given.
struct PresenceStub {
    std::shared_ptr<int> calls = std::make_shared<int>(0);
    std::shared_ptr<std::chrono::seconds> ttl = std::make_shared<std::chrono::seconds>(0);
    bool truncated = true;
    AgentRegistry::PresenceReadFn fn() const {
        return [c = calls, t = ttl, trunc = truncated](std::chrono::seconds s)
                   -> std::expected<Presence, PresenceReadError> {
            ++*c;
            *t = s;
            if (trunc)
                return std::unexpected(PresenceReadError::Truncated);
            return Presence{};
        };
    }
};

yuzu::server::ConfinedDispatchOutcome wire(AgentRegistry& registry, const ClassifiedCommand& cmd,
                                           const std::vector<std::string>& ids) {
    auto noop = [](const std::string&, const std::string&, const std::string&,
                   const std::string&) {};
    return yuzu::server::wire_and_dispatch_confined(
        registry, nullptr, nullptr, nullptr, nullptr, nullptr, noop, noop, "protective-cmd",
        "exec-1", "", ids, "", std::nullopt, false, ContainmentGate::exempt_control_plugin(), cmd);
}

const std::vector<std::pair<std::string, std::string>> kProtectiveWire{
    {"quarantine", "quarantine"},
    {"quarantine", "unquarantine"},
    {"quarantine", "status"},
    {"quarantine", "whitelist"}};

} // namespace

TEST_CASE("kill_switch_denial: a protective action is never refused and never consults the switch",
          "[server][dispatch][protective][security]") {
    for (const auto& [plugin, action] : kProtectiveWire) {
        // nullopt is both "switched off" and "degraded store".
        CountingSwitch off{std::nullopt};
        const auto cap = protective_cap(plugin, action);
        const auto r = yuzu::server::detail::kill_switch_denial(cap, off.fn());
        REQUIRE(r.has_value());
        CHECK(r->empty());
        CHECK(*off.calls == 0);

        CountingSwitch os_off{IdSet{"windows"}};
        const auto cmd = finalize(cap, os_off.fn());
        CHECK(cmd.kill_switched_os().empty());
        CHECK(*os_off.calls == 0);
    }
    CountingSwitch off{std::nullopt};
    const auto guard = protective_cap("__guard__", "push_rules", /*system_reserved=*/true);
    const auto r = yuzu::server::detail::kill_switch_denial(guard, off.fn());
    REQUIRE(r.has_value());
    CHECK(r->empty());
    CHECK(*off.calls == 0);
    CountingSwitch os_off{IdSet{"windows"}};
    CHECK(finalize(guard, os_off.fn()).kill_switched_os().empty());
}

TEST_CASE("kill_switch_denial: control — tar.sql is still refused / still carries its OS set",
          "[server][dispatch][protective][security]") {
    CountingSwitch off{std::nullopt};
    const auto r = yuzu::server::detail::kill_switch_denial(kTarSql, off.fn());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().reason == yuzu::server::detail::DispatchDenialReason::KillSwitched);
    CHECK(r.error().securable == "Infrastructure");
    CHECK(*off.calls == 1);

    CountingSwitch os_off{IdSet{"windows"}};
    CHECK(finalize(kTarSql, os_off.fn()).kill_switched_os() == IdSet{"windows"});
}

TEST_CASE("ids_missing_plugin: protective pairs are never reported missing",
          "[server][dispatch][protective][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("dev-A", "windows", {"os_info"}));

    for (const auto& [plugin, action] : kProtectiveWire)
        CHECK_FALSE(registry.ids_missing_plugin(plugin, action).contains("dev-A"));
    CHECK_FALSE(registry.ids_missing_plugin("__guard__", "push_rules").contains("dev-A"));

    CHECK(registry.ids_missing_plugin("quarantine", "reapply").contains("dev-A"));
    CHECK(registry.ids_missing_plugin("tar", "sql").contains("dev-A"));
}

TEST_CASE("wire_and_dispatch_confined: protective dispatch reaches every target past an OS-off "
          "row and a stale inventory and a >100k presence read; tar.sql does not",
          "[server][dispatch][protective][security]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("dev-A", "windows", {"os_info"})); // no quarantine plugin
    registry.register_agent(make_info("dev-B", "linux"));
    route_via_gateway(registry, {"dev-A", "dev-B"});

    PresenceStub stub; // Truncated: what query_live_ids returns past kQueryRowCap
    registry.configure_presence(stub.fn(), kTtl);

    const std::vector<std::string> ids{"dev-A", "dev-B"};
    for (const auto& [plugin, action] : kProtectiveWire) {
        CountingSwitch os_off{IdSet{"windows"}};
        const auto cmd = finalize(protective_cap(plugin, action), os_off.fn());
        const auto out = wire(registry, cmd, ids);
        INFO(plugin << "." << action);
        CHECK(out.sent == 2);
        CHECK_FALSE(out.os_gate_unreadable);
        CHECK(out.kill_switched_os.empty());
        CHECK(out.unknown_plugin.empty());
        CHECK(drained(registry) == ids);
    }
    CHECK(*stub.calls == 0); // the presence reader is never invoked

    // Control: tar.sql with the same registry / stub / OS-off fn is refused.
    CountingSwitch os_off{IdSet{"windows"}};
    const auto control = wire(registry, finalize(kTarSql, os_off.fn()), ids);
    CHECK(control.os_gate_unreadable);
    CHECK(control.sent == 0);
    CHECK(*stub.calls == 1);
    CHECK(*stub.ttl == kTtl); // the injected overload propagates the TTL
    CHECK(drained(registry).empty());
}

TEST_CASE("wire_and_dispatch_confined: a degraded store never stops a protective dispatch",
          "[server][dispatch][protective][security]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("dev-A", "windows", {"os_info"}));
    registry.register_agent(make_info("dev-B", "linux"));
    route_via_gateway(registry, {"dev-A", "dev-B"});

    CountingSwitch degraded{std::nullopt};
    const std::vector<std::string> ids{"dev-A", "dev-B"};

    // tar.sql never reaches the wire.
    CHECK_FALSE(yuzu::server::detail::finalize_classified_command(
                    kTarSql, degraded.fn(), "tar", "sql", "protective-cmd", {}, {}, 0, 0, {}, {})
                    .has_value());

    for (const auto& [plugin, action] : kProtectiveWire) {
        const auto out =
            wire(registry, finalize(protective_cap(plugin, action), degraded.fn()), ids);
        CHECK(out.sent == 2);
        CHECK(drained(registry) == ids);
    }
}

TEST_CASE("send_to: __guard__.push_rules reaches a device whose OS switch is off; tar.sql does not",
          "[server][dispatch][protective][security][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("dev-A", "windows"));
    route_via_gateway(registry, {"dev-A"});

    CountingSwitch os_off{IdSet{"windows"}};
    const auto push = finalize(protective_cap("__guard__", "push_rules", true), os_off.fn());
    CHECK(registry.send_to("dev-A", push));
    CHECK(drained(registry) == std::vector<std::string>{"dev-A"});
    CHECK(registry.send_to_all(push) == 1);
    CHECK(drained(registry) == std::vector<std::string>{"dev-A"});

    const auto control = finalize(kTarSql, os_off.fn());
    CHECK_FALSE(registry.send_to("dev-A", control));
    CHECK(drained(registry).empty());
}

TEST_CASE("send_to / send_to_all: __guard__.push_rules reaches its targets under a degraded store "
          "and a >100k presence read",
          "[server][dispatch][protective][security][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("dev-A", "windows"));
    registry.register_agent(make_info("dev-B", "linux"));
    route_via_gateway(registry, {"dev-A", "dev-B"});

    PresenceStub stub; // Truncated: what query_live_ids returns past kQueryRowCap
    registry.configure_presence(stub.fn(), kTtl);

    // nullopt is the degraded-store answer; the Guardian push must not consult it.
    CountingSwitch degraded{std::nullopt};
    const auto push = finalize(protective_cap("__guard__", "push_rules", true), degraded.fn());

    CHECK(registry.send_to("dev-A", push));
    CHECK(drained(registry) == std::vector<std::string>{"dev-A"});
    CHECK(registry.send_to_all(push) == 2);
    CHECK(drained(registry) == (std::vector<std::string>{"dev-A", "dev-B"}));
    CHECK(*degraded.calls == 0);
    CHECK(*stub.calls == 0);
}

TEST_CASE("every other action is still refused at each gate (regression guard)",
          "[server][dispatch][protective][security]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("dev-A", "windows", {"os_info"}));
    registry.register_agent(make_info("dev-B", "linux"));
    route_via_gateway(registry, {"dev-A", "dev-B"});

    PresenceStub healthy;
    healthy.truncated = false;
    registry.configure_presence(healthy.fn(), kTtl);

    const std::vector<std::string> ids{"dev-A", "dev-B"};
    CountingSwitch os_off{IdSet{"windows"}};
    const auto withheld = wire(registry, finalize(kTarSql, os_off.fn()), ids);
    CHECK(withheld.kill_switched_os == std::vector<std::string>{"dev-A"});
    CHECK(withheld.sent == 1);
    CHECK(drained(registry) == std::vector<std::string>{"dev-B"});

    CountingSwitch no_os{IdSet{}};
    const auto absent = wire(registry, finalize(kTarSql, no_os.fn()), ids);
    CHECK(absent.unknown_plugin == std::vector<std::string>{"dev-A"});
}

TEST_CASE("the protective set is tied to the real catalogue rows and the push label",
          "[server][dispatch][protective][security]") {
    using yuzu::protective::is_protective_action;
    namespace capdecls = yuzu::server::capdecls;

    // Every system-reserved push label is "<plugin>.<action>"; only the Guardian
    // rule push is protective. A rename on either side fails here.
    for (const auto push : yuzu::server::kSystemReservedPushes) {
        const auto label = yuzu::server::system_reserved_push_label(push);
        const auto dot = label.find('.');
        REQUIRE(dot != std::string_view::npos);
        CHECK(is_protective_action(label.substr(0, dot), label.substr(dot + 1)) ==
              (push == yuzu::server::SystemReservedPush::guardian_push_rules));
    }

    // The real rows that carry a protective pair: exactly the quarantine
    // plugin's four actions plus __guard__.push_rules.
    std::set<std::string> protective;
    for (const auto rows : {capdecls::plugin_action_catalogue_c(),
                            capdecls::core_dispatch_capabilities()})
        for (const auto& cap : rows)
            if (is_protective_action(cap.plugin, cap.action))
                protective.insert(std::string(cap.plugin) + "." + std::string(cap.action));
    CHECK(protective == std::set<std::string>{"quarantine.quarantine", "quarantine.unquarantine",
                                             "quarantine.status", "quarantine.whitelist",
                                             "__guard__.push_rules"});

    // The plugin-level label predicate is tied to the same rows: it must be true for
    // exactly the plugins that carry a protective row, so widening it to a plugin
    // the set does not cover (or narrowing it away from one it does) fails here.
    std::set<std::string> protective_plugins;
    for (const auto& pair : protective)
        protective_plugins.insert(pair.substr(0, pair.find('.')));
    for (const auto rows : {capdecls::plugin_action_catalogue_c(),
                            capdecls::core_dispatch_capabilities()})
        for (const auto& cap : rows)
            CHECK(yuzu::protective::plugin_owns_protective_actions(cap.plugin) ==
                  (protective_plugins.count(std::string(cap.plugin)) != 0));
}

TEST_CASE("kill_switch_row_covers_protective: labels rows that can never gate dispatch",
          "[server][dispatch][protective][security]") {
    using yuzu::server::plugin_config::KillSwitchScope;
    using yuzu::server::plugin_config::kill_switch_row_covers_protective;
    CHECK(kill_switch_row_covers_protective(KillSwitchScope{"quarantine", "unquarantine", ""}));
    CHECK(kill_switch_row_covers_protective(KillSwitchScope{"quarantine", "status", "windows"}));
    CHECK(kill_switch_row_covers_protective(KillSwitchScope{"__guard__", "push_rules", ""}));
    // Plugin-level rows for the two plugins that own protective actions.
    CHECK(kill_switch_row_covers_protective(KillSwitchScope{"quarantine", "", ""}));
    CHECK(kill_switch_row_covers_protective(KillSwitchScope{"__guard__", "", "linux"}));
    // Everything else is an ordinary, effective row.
    CHECK_FALSE(kill_switch_row_covers_protective(KillSwitchScope{"__guard__", "get_status", ""}));
    CHECK_FALSE(kill_switch_row_covers_protective(KillSwitchScope{"firewall", "", ""}));
    CHECK_FALSE(kill_switch_row_covers_protective(KillSwitchScope{"tar", "sql", ""}));

    // The audit-evidence detail both write surfaces share (their only other
    // bindings are [pg]-tagged and SKIP without a DSN).
    using yuzu::server::plugin_config::kill_switch_set_detail;
    CHECK(kill_switch_set_detail(KillSwitchScope{"quarantine", "unquarantine", ""}, false) ==
          "enabled=false, protective_exempt=true");
    CHECK(kill_switch_set_detail(KillSwitchScope{"__guard__", "", "linux"}, true) ==
          "enabled=true, protective_exempt=true");
    CHECK(kill_switch_set_detail(KillSwitchScope{"tar", "sql", ""}, false) == "enabled=false");
}

TEST_CASE("configure_presence: reconfiguring resets the cache age so the next read uses the "
          "new reader",
          "[server][dispatch][protective][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    PresenceStub first;
    first.truncated = false;
    registry.configure_presence(first.fn(), kTtl);
    (void)registry.all_ids();
    CHECK(*first.calls >= 1);
    CHECK(*first.ttl == kTtl);

    PresenceStub second;
    second.truncated = false;
    registry.configure_presence(second.fn(), std::chrono::seconds{91});
    const int first_calls = *first.calls;
    (void)registry.all_ids();
    CHECK(*second.calls == 1);
    CHECK(*second.ttl == std::chrono::seconds{91});
    CHECK(*first.calls == first_calls);
}

namespace {

/// Parks a presence read in flight: `entered` flips once the reader is inside,
/// the reader then blocks until `release()`. Every wait is a bounded condition
/// variable wait, never sleep+poll.
struct ParkedRead {
    std::mutex mu;
    std::condition_variable cv;
    bool entered = false;
    bool released = false;
    std::atomic<int> seq{0};
    std::atomic<int> exit_stamp{0};
    std::atomic<int> calls{0};

    AgentRegistry::PresenceReadFn fn() {
        return [this](std::chrono::seconds) -> std::expected<Presence, PresenceReadError> {
            ++calls;
            std::unique_lock lk(mu);
            entered = true;
            cv.notify_all();
            cv.wait_for(lk, std::chrono::seconds(30), [this] { return released; });
            exit_stamp = ++seq;
            return Presence{};
        };
    }
    bool wait_entered() {
        std::unique_lock lk(mu);
        return cv.wait_for(lk, std::chrono::seconds(30), [this] { return entered; });
    }
    void release() {
        {
            std::lock_guard lk(mu);
            released = true;
        }
        cv.notify_all();
    }
};

} // namespace

TEST_CASE("configure_presence: a reconfigure cannot return while a presence read is in flight",
          "[server][dispatch][protective][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    ParkedRead a;
    PresenceStub b;
    b.truncated = false;
    registry.configure_presence(a.fn(), kTtl);

    std::mutex done_mu;
    std::condition_variable done_cv;
    bool reconf_started = false;
    bool reconf_done = false;
    std::atomic<int> reconf_stamp{0};

    std::jthread reader([&] { (void)registry.all_ids(); });
    // Declared after `reader` so a failing REQUIRE still unparks A before the
    // jthread joins.
    struct Unpark {
        ParkedRead& p;
        ~Unpark() { p.release(); }
    } unpark{a};
    REQUIRE(a.wait_entered());

    std::jthread reconf([&] {
        {
            std::lock_guard lk(done_mu);
            reconf_started = true;
        }
        done_cv.notify_all();
        registry.configure_presence(b.fn(), std::chrono::seconds{91});
        reconf_stamp = ++a.seq;
        {
            std::lock_guard lk(done_mu);
            reconf_done = true;
        }
        done_cv.notify_all();
    });
    {
        std::unique_lock lk(done_mu);
        CHECK(done_cv.wait_for(lk, std::chrono::seconds(30), [&] { return reconf_started; }));
        // Under the lock the reconfigure cannot finish while A is parked, so this
        // bounded wait is expected to time out; completing means the guard is gone.
        CHECK_FALSE(done_cv.wait_for(lk, std::chrono::milliseconds(100),
                                     [&] { return reconf_done; }));
    }
    a.release();
    reader.join();
    {
        std::unique_lock lk(done_mu);
        CHECK(done_cv.wait_for(lk, std::chrono::seconds(30), [&] { return reconf_done; }));
    }
    reconf.join();

    CHECK(a.exit_stamp.load() < reconf_stamp.load());
    (void)registry.all_ids();
    CHECK(*b.calls == 1);
    CHECK(*b.ttl == std::chrono::seconds{91});
    CHECK(a.calls == 1);
}
