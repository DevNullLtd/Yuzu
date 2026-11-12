// test_protective_actions.cpp -- pure tests of
// common/include/yuzu/protective_actions.hpp (protective-action exemption): the ONE closed set of
// (plugin, action) pairs plugin enablement must never refuse.

#include <yuzu/protective_actions.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::protective::is_protective_action;
using yuzu::protective::plugin_owns_protective_actions;
using yuzu::protective::is_quarantine_control_plugin;

TEST_CASE("is_quarantine_control_plugin: the closed four-action firewall set (case-insensitive)",
          "[protective][security]") {
    for (const auto plugin : {"firewall", "Firewall", "FIREWALL"}) {
        for (const auto action : {"quarantine", "release", "quarantine_status", "quarantine_allow",
                                  "Quarantine_Status", "RELEASE"})
            CHECK(is_quarantine_control_plugin(plugin, action));
    }
    CHECK_FALSE(is_quarantine_control_plugin("firewalls", "release"));
    CHECK_FALSE(is_quarantine_control_plugin("firewal", "release"));
    CHECK_FALSE(is_quarantine_control_plugin("", "release"));
    // Closed set: the plugin's ordinary actions, and any later one, get no exemption.
    CHECK_FALSE(is_quarantine_control_plugin("firewall", "state"));
    CHECK_FALSE(is_quarantine_control_plugin("firewall", "rules"));
    CHECK_FALSE(is_quarantine_control_plugin("firewall", "reapply"));
    CHECK_FALSE(is_quarantine_control_plugin("firewall", ""));
}

TEST_CASE("is_protective_action: firewall containment set plus __guard__.push_rules only",
          "[protective][security]") {
    for (const auto action : {"quarantine", "release", "quarantine_status", "quarantine_allow"})
        CHECK(is_protective_action("firewall", action));
    CHECK(is_protective_action("__guard__", "push_rules"));
    CHECK(is_protective_action("__GUARD__", "PUSH_RULES"));

    // The plugin name `quarantine` no longer exists: no action on it is protective.
    for (const auto action : {"quarantine", "release", "status", "whitelist", ""})
        CHECK_FALSE(is_protective_action("quarantine", action));

    // firewall's ordinary actions are NOT protective.
    CHECK_FALSE(is_protective_action("firewall", "state"));
    CHECK_FALSE(is_protective_action("firewall", "rules"));
    CHECK_FALSE(is_protective_action("firewall", ""));

    // The other SystemReservedPush channels are NOT protective.
    CHECK_FALSE(is_protective_action("__guard__", "get_status"));
    CHECK_FALSE(is_protective_action("__guard__", "reconcile"));
    CHECK_FALSE(is_protective_action("__sync__", "now"));
    CHECK_FALSE(is_protective_action("echo", "fleet_snapshot"));
    CHECK_FALSE(is_protective_action("asset_tags", "sync"));
    CHECK_FALSE(is_protective_action("echo", "sql"));
    CHECK_FALSE(is_protective_action("", ""));
}

TEST_CASE("is_protective_action: exactly five pairs across the cross product",
          "[protective][security]") {
    int protective = 0;
    for (const auto plugin : {"firewall", "__guard__", "echo", "quarantine"}) {
        for (const auto action : {"quarantine", "release", "quarantine_status", "quarantine_allow",
                                  "state", "rules", "push_rules", "sql"}) {
            if (is_protective_action(plugin, action))
                ++protective;
        }
    }
    CHECK(protective == 5);
}

TEST_CASE("plugin_owns_protective_actions: true exactly for plugins with a protective action",
          "[protective][security]") {
    // The tie between the two lists: fails if either drifts.
    for (const auto plugin : {"firewall", "Firewall", "__guard__", "echo", "quarantine", ""}) {
        bool any = false;
        for (const auto action : {"quarantine", "release", "quarantine_status", "quarantine_allow",
                                  "state", "rules", "push_rules", "sql", ""})
            any = any || is_protective_action(plugin, action);
        CHECK(plugin_owns_protective_actions(plugin) == any);
    }
    CHECK(plugin_owns_protective_actions("firewall"));
    CHECK(plugin_owns_protective_actions("__guard__"));
    CHECK_FALSE(plugin_owns_protective_actions("quarantine"));
}
