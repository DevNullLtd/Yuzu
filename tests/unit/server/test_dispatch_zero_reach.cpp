/**
 * test_dispatch_zero_reach.cpp -- the pure zero-reach cause classifier that new
 * v1 routes and MCP tools share (dispatch_zero_reach.hpp).
 *
 * Binds the FIXED priority order copied from the MCP execute_instruction
 * cascade, with #7114's chokepoint denial ranked first: dispatch_denied >
 * invalid_scope > containment_unreadable > route_unreadable >
 * os_gate_unreadable > quarantined > plugin_not_found > kill_switched_os >
 * no_agents_reached. Each adjacent pair is asserted with both flags set so a
 * swapped branch fails.
 */

#include "dispatch_zero_reach.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <string_view>

using yuzu::server::classify_zero_reach;
using yuzu::server::ConfinedDispatchOutcome;
using yuzu::server::zero_reach_retryable;
using yuzu::server::zero_reach_token;
using yuzu::server::ZeroReachCause;
using yuzu::server::detail::DispatchDenial;
using yuzu::server::detail::DispatchDenialReason;

namespace {

ConfinedDispatchOutcome with_scope_error() {
    ConfinedDispatchOutcome o;
    o.scope_parse_error = "bad expression";
    return o;
}
ConfinedDispatchOutcome with_containment() {
    ConfinedDispatchOutcome o;
    o.containment_unreadable = true;
    return o;
}
ConfinedDispatchOutcome with_route() {
    ConfinedDispatchOutcome o;
    o.route_unreadable = true;
    return o;
}
ConfinedDispatchOutcome with_os_gate() {
    ConfinedDispatchOutcome o;
    o.os_gate_unreadable = true;
    return o;
}
ConfinedDispatchOutcome with_quarantined() {
    ConfinedDispatchOutcome o;
    o.denied_quarantined_count = 1;
    return o;
}
ConfinedDispatchOutcome with_unknown_plugin() {
    ConfinedDispatchOutcome o;
    o.unknown_plugin_count = 1;
    return o;
}
ConfinedDispatchOutcome with_kill_switched() {
    ConfinedDispatchOutcome o;
    o.kill_switched_os_count = 1;
    return o;
}

/// Every flag set at once.
ConfinedDispatchOutcome with_everything() {
    ConfinedDispatchOutcome o;
    o.scope_parse_error = "bad expression";
    o.containment_unreadable = true;
    o.route_unreadable = true;
    o.os_gate_unreadable = true;
    o.denied_quarantined_count = 3;
    o.unknown_plugin_count = 2;
    o.kill_switched_os_count = 1;
    return o;
}

} // namespace

TEST_CASE("zero_reach: each cause in isolation", "[dispatch_zero_reach]") {
    CHECK(classify_zero_reach(with_scope_error(), false) == ZeroReachCause::InvalidScope);
    CHECK(classify_zero_reach(with_containment(), false) == ZeroReachCause::ContainmentUnreadable);
    CHECK(classify_zero_reach(with_route(), false) == ZeroReachCause::RouteUnreadable);
    CHECK(classify_zero_reach(with_os_gate(), false) == ZeroReachCause::OsGateUnreadable);
    CHECK(classify_zero_reach(with_quarantined(), false) == ZeroReachCause::Quarantined);
    CHECK(classify_zero_reach(with_unknown_plugin(), false) == ZeroReachCause::PluginNotFound);
    CHECK(classify_zero_reach(with_kill_switched(), false) == ZeroReachCause::KillSwitchedOs);
}

TEST_CASE("zero_reach: a default outcome is the catch-all", "[dispatch_zero_reach]") {
    CHECK(classify_zero_reach(ConfinedDispatchOutcome{}, false) == ZeroReachCause::Generic);
    CHECK(classify_zero_reach(ConfinedDispatchOutcome{}, true) == ZeroReachCause::Generic);
}

TEST_CASE("zero_reach: empty identity vectors do not count, only the counts do",
          "[dispatch_zero_reach]") {
    // Under a fail-closed denial the id vectors are empty while the count is not;
    // the classifier must read the counts.
    ConfinedDispatchOutcome o;
    o.denied_quarantined_count = 5;
    REQUIRE(o.denied_quarantined.empty());
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::Quarantined);

    ConfinedDispatchOutcome ids_only;
    ids_only.denied_quarantined = {"a"};
    ids_only.unknown_plugin = {"a"};
    ids_only.kill_switched_os = {"a"};
    CHECK(classify_zero_reach(ids_only, false) == ZeroReachCause::Generic);
}

TEST_CASE("zero_reach: full priority order, winner with all flags set", "[dispatch_zero_reach]") {
    auto o = with_everything();
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::InvalidScope);

    o.scope_parse_error.reset();
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::ContainmentUnreadable);

    o.containment_unreadable = false;
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::RouteUnreadable);

    o.route_unreadable = false;
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::OsGateUnreadable);

    o.os_gate_unreadable = false;
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::Quarantined);

    o.denied_quarantined_count = 0;
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::PluginNotFound);

    o.unknown_plugin_count = 0;
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::KillSwitchedOs);

    o.kill_switched_os_count = 0;
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::Generic);
}

TEST_CASE("zero_reach: adjacent pairs, the earlier cause wins", "[dispatch_zero_reach]") {
    SECTION("route_unreadable over os_gate_unreadable") {
        auto o = with_route();
        o.os_gate_unreadable = true;
        CHECK(classify_zero_reach(o, false) == ZeroReachCause::RouteUnreadable);
    }
    SECTION("os_gate_unreadable over quarantined") {
        auto o = with_os_gate();
        o.denied_quarantined_count = 1;
        CHECK(classify_zero_reach(o, false) == ZeroReachCause::OsGateUnreadable);
    }
    SECTION("quarantined over plugin_not_found") {
        auto o = with_quarantined();
        o.unknown_plugin_count = 1;
        CHECK(classify_zero_reach(o, false) == ZeroReachCause::Quarantined);
    }
    SECTION("plugin_not_found over kill_switched_os") {
        auto o = with_unknown_plugin();
        o.kill_switched_os_count = 1;
        CHECK(classify_zero_reach(o, false) == ZeroReachCause::PluginNotFound);
    }
    SECTION("containment_unreadable over route_unreadable") {
        auto o = with_containment();
        o.route_unreadable = true;
        CHECK(classify_zero_reach(o, false) == ZeroReachCause::ContainmentUnreadable);
    }
    SECTION("invalid_scope over containment_unreadable") {
        auto o = with_scope_error();
        o.containment_unreadable = true;
        CHECK(classify_zero_reach(o, false) == ZeroReachCause::InvalidScope);
    }
}

TEST_CASE("zero_reach: a protective action never yields os_gate, plugin_not_found or "
          "kill_switched_os",
          "[dispatch_zero_reach]") {
    CHECK(classify_zero_reach(with_os_gate(), true) == ZeroReachCause::Generic);
    CHECK(classify_zero_reach(with_unknown_plugin(), true) == ZeroReachCause::Generic);
    CHECK(classify_zero_reach(with_kill_switched(), true) == ZeroReachCause::Generic);

    // All three together still collapse to the catch-all.
    ConfinedDispatchOutcome three;
    three.os_gate_unreadable = true;
    three.unknown_plugin_count = 1;
    three.kill_switched_os_count = 1;
    CHECK(classify_zero_reach(three, true) == ZeroReachCause::Generic);
}

TEST_CASE("zero_reach: protective suppression falls through to the next real cause",
          "[dispatch_zero_reach]") {
    auto o = with_os_gate();
    o.denied_quarantined_count = 1;
    CHECK(classify_zero_reach(o, true) == ZeroReachCause::Quarantined);

    auto p = with_unknown_plugin();
    p.kill_switched_os_count = 1;
    p.denied_quarantined_count = 1;
    CHECK(classify_zero_reach(p, true) == ZeroReachCause::Quarantined);
}

TEST_CASE("zero_reach: a protective action does not suppress the other four causes",
          "[dispatch_zero_reach]") {
    CHECK(classify_zero_reach(with_scope_error(), true) == ZeroReachCause::InvalidScope);
    CHECK(classify_zero_reach(with_containment(), true) == ZeroReachCause::ContainmentUnreadable);
    CHECK(classify_zero_reach(with_route(), true) == ZeroReachCause::RouteUnreadable);
    CHECK(classify_zero_reach(with_quarantined(), true) == ZeroReachCause::Quarantined);
    CHECK(classify_zero_reach(with_everything(), true) == ZeroReachCause::InvalidScope);
}

TEST_CASE("zero_reach: sent and command_id do not influence the classification",
          "[dispatch_zero_reach]") {
    auto o = with_quarantined();
    o.command_id = "cmd-1";
    o.not_sent = {"a", "b"};
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::Quarantined);
}

TEST_CASE("zero_reach: wire tokens are the existing status and reason strings",
          "[dispatch_zero_reach]") {
    CHECK(zero_reach_token(ZeroReachCause::Denied) == "dispatch_denied");
    CHECK(zero_reach_token(ZeroReachCause::InvalidScope) == "invalid_scope");
    CHECK(zero_reach_token(ZeroReachCause::ContainmentUnreadable) == "containment_unreadable");
    CHECK(zero_reach_token(ZeroReachCause::RouteUnreadable) == "route_unreadable");
    CHECK(zero_reach_token(ZeroReachCause::OsGateUnreadable) == "os_gate_unreadable");
    CHECK(zero_reach_token(ZeroReachCause::Quarantined) == "quarantined");
    CHECK(zero_reach_token(ZeroReachCause::PluginNotFound) == "plugin_not_found");
    CHECK(zero_reach_token(ZeroReachCause::KillSwitchedOs) == "kill_switched_os");
    CHECK(zero_reach_token(ZeroReachCause::Generic) == "no_agents_reached");
}

TEST_CASE("zero_reach: tokens are distinct and non-empty", "[dispatch_zero_reach]") {
    constexpr std::array<ZeroReachCause, 9> all{
        ZeroReachCause::Denied,           ZeroReachCause::InvalidScope,     ZeroReachCause::ContainmentUnreadable,
        ZeroReachCause::RouteUnreadable,  ZeroReachCause::OsGateUnreadable,
        ZeroReachCause::Quarantined,      ZeroReachCause::PluginNotFound,
        ZeroReachCause::KillSwitchedOs,   ZeroReachCause::Generic};
    for (std::size_t i = 0; i < all.size(); ++i) {
        CHECK_FALSE(zero_reach_token(all[i]).empty());
        for (std::size_t j = i + 1; j < all.size(); ++j)
            CHECK(zero_reach_token(all[i]) != zero_reach_token(all[j]));
    }
}

TEST_CASE("zero_reach: retryable flags match the existing semantics", "[dispatch_zero_reach]") {
    // Transient systemic failures and the mixed catch-all are retryable.
    CHECK(zero_reach_retryable(ZeroReachCause::ContainmentUnreadable));
    CHECK(zero_reach_retryable(ZeroReachCause::RouteUnreadable));
    CHECK(zero_reach_retryable(ZeroReachCause::OsGateUnreadable));
    CHECK(zero_reach_retryable(ZeroReachCause::Generic));
    // A caller error or a permanent policy withhold is not.
    CHECK_FALSE(zero_reach_retryable(ZeroReachCause::InvalidScope));
    CHECK_FALSE(zero_reach_retryable(ZeroReachCause::Quarantined));
    CHECK_FALSE(zero_reach_retryable(ZeroReachCause::PluginNotFound));
    CHECK_FALSE(zero_reach_retryable(ZeroReachCause::KillSwitchedOs));
    CHECK_FALSE(zero_reach_retryable(ZeroReachCause::Denied));
}

TEST_CASE("zero_reach: denied wins over every other flag", "[dispatch_zero_reach][security]") {
    auto o = with_everything();
    o.denied = DispatchDenial{DispatchDenialReason::ApprovalRequired, "Execution",
                              yuzu::server::authz::Operation::Execute};
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::Denied);
    // A protective action is not exempt from the chokepoint's own refusal.
    CHECK(classify_zero_reach(o, true) == ZeroReachCause::Denied);
    // Alone, and with nothing else set.
    ConfinedDispatchOutcome only;
    only.denied = DispatchDenial{DispatchDenialReason::Forbidden, "Execution",
                                 yuzu::server::authz::Operation::Execute};
    CHECK(classify_zero_reach(only, false) == ZeroReachCause::Denied);
    // Without it the same outcome falls back to the next cause (invalid_scope).
    o.denied.reset();
    CHECK(classify_zero_reach(o, false) == ZeroReachCause::InvalidScope);
}
