/**
 * test_protective_action_dispatch_gate.cpp — protective actions (the
 * quarantine plugin's four actions plus `__guard__.push_rules`) are never
 * refused by plugin enablement. Mirrors test_os_kill_switch_dispatch_gate.cpp:
 * every gate is bound with a real `AgentRegistry` and the exact send set
 * (`drain_gateway_pending`), with `tar.sql` as the control that is still
 * refused at every gate. Presence is an injected stub — no Postgres, no I/O.
 */

#include "agent_registry.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"
#include "event_bus.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
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
        cap, fn, cap.plugin, cap.action, "pm01-cmd", {}, {}, 0, 0, {}, {});
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
        registry, nullptr, nullptr, nullptr, nullptr, nullptr, noop, noop, "pm01-cmd", "exec-1", "",
        ids, "", std::nullopt, false, ContainmentGate::exempt_control_plugin(), cmd);
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
          "row, a stale inventory and a >100k presence read; tar.sql does not",
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
                    kTarSql, degraded.fn(), "tar", "sql", "pm01-cmd", {}, {}, 0, 0, {}, {})
                    .has_value());

    for (const auto& [plugin, action] : kProtectiveWire) {
        const auto out = wire(registry, finalize(protective_cap(plugin, action), degraded.fn()), ids);
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
