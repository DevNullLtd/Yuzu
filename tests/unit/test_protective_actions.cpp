// test_protective_actions.cpp -- pure tests of
// common/include/yuzu/protective_actions.hpp (protective-action exemption): the ONE closed set of
// (plugin, action) pairs plugin enablement must never refuse.

#include <yuzu/protective_actions.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::protective::is_protective_action;
using yuzu::protective::plugin_owns_protective_actions;
using yuzu::protective::is_quarantine_control_plugin;

TEST_CASE("is_quarantine_control_plugin: the closed four-action set (case-insensitive)",
          "[protective][security]") {
    for (const auto plugin : {"quarantine", "Quarantine", "QUARANTINE"}) {
        for (const auto action : {"quarantine", "unquarantine", "status", "whitelist", "Status"})
            CHECK(is_quarantine_control_plugin(plugin, action));
    }
    CHECK_FALSE(is_quarantine_control_plugin("quarantined", "status"));
    CHECK_FALSE(is_quarantine_control_plugin("quarantin", "status"));
    CHECK_FALSE(is_quarantine_control_plugin("", "status"));
    CHECK_FALSE(is_quarantine_control_plugin("firewall", "status"));
    // Closed set: a fifth action on the quarantine plugin gets no exemption.
    CHECK_FALSE(is_quarantine_control_plugin("quarantine", "reapply"));
    CHECK_FALSE(is_quarantine_control_plugin("quarantine", "ping"));
    CHECK_FALSE(is_quarantine_control_plugin("quarantine", ""));
}

TEST_CASE("is_protective_action: quarantine control set plus __guard__.push_rules only",
          "[protective][security]") {
    for (const auto action : {"quarantine", "unquarantine", "status", "whitelist"})
        CHECK(is_protective_action("quarantine", action));
    CHECK(is_protective_action("__guard__", "push_rules"));
    CHECK(is_protective_action("__GUARD__", "PUSH_RULES"));

    // The other SystemReservedPush channels are NOT protective.
    CHECK_FALSE(is_protective_action("__guard__", "get_status"));
    CHECK_FALSE(is_protective_action("__guard__", "reconcile"));
    CHECK_FALSE(is_protective_action("__sync__", "now"));
    CHECK_FALSE(is_protective_action("tar", "fleet_snapshot"));
    CHECK_FALSE(is_protective_action("asset_tags", "sync"));
    CHECK_FALSE(is_protective_action("tar", "sql"));
    CHECK_FALSE(is_protective_action("", ""));
}

TEST_CASE("is_protective_action: exactly five pairs across the cross product",
          "[protective][security]") {
    int protective = 0;
    for (const auto plugin : {"quarantine", "__guard__", "tar"}) {
        for (const auto action :
             {"quarantine", "unquarantine", "status", "whitelist", "push_rules", "sql"}) {
            if (is_protective_action(plugin, action))
                ++protective;
        }
    }
    CHECK(protective == 5);
}

TEST_CASE("plugin_owns_protective_actions: true exactly for plugins with a protective action",
          "[protective][security]") {
    // The tie between the two lists: fails if either drifts.
    for (const auto plugin : {"quarantine", "Quarantine", "__guard__", "tar", "firewall", ""}) {
        bool any = false;
        for (const auto action :
             {"quarantine", "unquarantine", "status", "whitelist", "push_rules", "sql", ""})
            any = any || is_protective_action(plugin, action);
        CHECK(plugin_owns_protective_actions(plugin) == any);
    }
}
