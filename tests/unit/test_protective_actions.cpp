// test_protective_actions.cpp -- pure tests of
// common/include/yuzu/protective_actions.hpp (protective-action exemption): the ONE closed set of
// (plugin, action) pairs plugin enablement must never refuse.

#include <yuzu/protective_actions.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string_view>

using yuzu::protective::is_firewall_control_plugin;
using yuzu::protective::is_protective_action;
using yuzu::protective::plugin_mixes_protective_and_ordinary_actions;
using yuzu::protective::plugin_owns_protective_actions;

TEST_CASE("is_firewall_control_plugin: the closed four-action set (case-insensitive)",
          "[protective][security]") {
    for (const auto plugin : {"firewall", "Firewall", "FIREWALL"}) {
        for (const auto action :
             {"quarantine", "release", "quarantine_status", "quarantine_allow", "Release",
              "QUARANTINE_STATUS", "Quarantine_Status"})
            CHECK(is_firewall_control_plugin(plugin, action));
    }
    // The plugin's other actions are ordinary: a kill switch may refuse them, and any later
    // action gets no exemption (the set is closed against the plugin's action table).
    for (const auto action : {"state", "rules", "reapply", "add_rule", "remove_rule", "status",
                              "allow", "whitelist", "ping", ""})
        CHECK_FALSE(is_firewall_control_plugin("firewall", action));
    // Near-miss plugin names and the removed plugin's name inherit nothing.
    for (const auto plugin : {"firewalls", "firewal", "fw", "", "quarantine", "__guard__"})
        CHECK_FALSE(is_firewall_control_plugin(plugin, "release"));
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
    // Four firewall containment actions and one __guard__ push: widening this count is a
    // security decision, never a drive-by edit. The removed plugin's four pairs are in the
    // cross product on purpose and must stay out.
    int protective = 0;
    for (const auto plugin : {"quarantine", "firewall", "__guard__", "echo"}) {
        for (const auto action :
             {"quarantine", "release", "quarantine_status", "status", "whitelist",
              "quarantine_allow", "state", "rules", "push_rules", "sql"}) {
            if (is_protective_action(plugin, action))
                ++protective;
        }
    }
    CHECK(protective == 5);
}

TEST_CASE("plugin_owns_protective_actions: true exactly for plugins with a protective action",
          "[protective][security]") {
    // The tie between the two lists: fails if either drifts.
    for (const auto plugin :
         {"quarantine", "Quarantine", "__guard__", "echo", "firewall", "Firewall", "firewalls",
          ""}) {
        bool any = false;
        for (const auto action :
             {"quarantine", "release", "quarantine_status", "status", "whitelist",
              "quarantine_allow", "state", "rules", "push_rules", "sql", ""})
            any = any || is_protective_action(plugin, action);
        CHECK(plugin_owns_protective_actions(plugin) == any);
    }
    CHECK(plugin_owns_protective_actions("firewall"));
    CHECK(plugin_owns_protective_actions("__guard__"));
    CHECK_FALSE(plugin_owns_protective_actions("quarantine"));
}

TEST_CASE("plugin_mixes_protective_and_ordinary_actions: only firewall, and only an owner",
          "[protective][security]") {
    for (const auto plugin :
         {"quarantine", "Quarantine", "__guard__", "echo", "firewall", "Firewall", "firewalls",
          ""}) {
        const bool mixes = plugin_mixes_protective_and_ordinary_actions(plugin);
        // A plugin cannot mix without owning a protective action ...
        if (mixes)
            CHECK(plugin_owns_protective_actions(plugin));
        // ... and the answer is the hand-written table: only `firewall` (any case) mixes.
        const bool expected =
            plugin == std::string_view{"firewall"} || plugin == std::string_view{"Firewall"};
        CHECK(mixes == expected);
    }
    CHECK_FALSE(is_protective_action("firewall", "state"));
    CHECK_FALSE(is_protective_action("firewall", "rules"));
}
