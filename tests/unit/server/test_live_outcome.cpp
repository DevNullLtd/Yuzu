/// @file test_live_outcome.cpp
/// Pins the closed vocabulary in live_outcome.hpp: the outcome tokens, the two surface tokens and
/// the kind label. These are metric label values for
/// `yuzu_server_live_requests_total{surface, kind, outcome}`, so the set must stay closed and
/// every value must be a stable, bounded, lowercase token.

#include "live_outcome.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <set>
#include <string>
#include <string_view>

namespace live = yuzu::server::live;

TEST_CASE("LiveOutcome: every enumerator maps to a unique, non-empty lowercase token", "[live][outcome]") {
    std::set<std::string> seen;
    for (std::size_t i = 0; i < live::kAllLiveOutcomes.size(); ++i) {
        const auto o = live::kAllLiveOutcomes[i];
        // The array is in declaration order, so index == enumerator value (no gaps, no repeats).
        CHECK(static_cast<std::size_t>(o) == i);
        const std::string t(live::to_token(o));
        CAPTURE(i, t);
        REQUIRE_FALSE(t.empty());
        CHECK(t.size() <= 32);
        for (const char c : t)
            CHECK(((c >= 'a' && c <= 'z') || c == '_'));
        CHECK(seen.insert(t).second);
    }
    CHECK(seen.size() == live::kAllLiveOutcomes.size());
}

TEST_CASE("LiveOutcome: the closed token set is exactly the ruled one", "[live][outcome]") {
    const std::set<std::string> expected = {
        "ok", "not_configured", "gate_refused", "bad_kind", "unavailable", "over_budget_principal",
        "over_budget_surface", "over_budget_global", "audit_failed", "permission_revoked",
        "caller_unresolved", "dispatch_denied", "invalid_scope", "containment_unreadable",
        "route_unreadable", "os_gate_unreadable", "quarantined", "plugin_not_found",
        "kill_switched_os", "device_failed", "device_error", "output_too_large", "timeout",
        "store_degraded", "internal", "tier_refused", "read_only_refused", "approval_refused"};
    std::set<std::string> actual;
    for (const auto o : live::kAllLiveOutcomes)
        actual.insert(std::string(live::to_token(o)));
    CHECK(actual == expected);
}

TEST_CASE("LiveOutcome: the zero-reach tokens match the shared classifier's spelling", "[live][outcome]") {
    // The REST and MCP surfaces report the zero-reach cause token as `reason`; the metric label
    // for the same event is the same string.
    CHECK(live::to_token(live::LiveOutcome::kDispatchDenied) == "dispatch_denied");
    CHECK(live::to_token(live::LiveOutcome::kInvalidScope) == "invalid_scope");
    CHECK(live::to_token(live::LiveOutcome::kContainmentUnreadable) == "containment_unreadable");
    CHECK(live::to_token(live::LiveOutcome::kRouteUnreadable) == "route_unreadable");
    CHECK(live::to_token(live::LiveOutcome::kOsGateUnreadable) == "os_gate_unreadable");
    CHECK(live::to_token(live::LiveOutcome::kQuarantined) == "quarantined");
    CHECK(live::to_token(live::LiveOutcome::kPluginNotFound) == "plugin_not_found");
    CHECK(live::to_token(live::LiveOutcome::kKillSwitchedOs) == "kill_switched_os");
}

TEST_CASE("LiveSurface and kind_label: bounded label values", "[live][outcome]") {
    CHECK(live::to_token(live::LiveSurface::kRest) == "rest");
    CHECK(live::to_token(live::LiveSurface::kMcp) == "mcp");

    CHECK(live::kind_label("uptime") == "uptime");
    CHECK(live::kind_label("processes") == "processes");
    // Anything else, including a caller-controlled string, collapses to one bounded value.
    CHECK(live::kind_label("services") == "unknown");
    CHECK(live::kind_label("") == "unknown");
    CHECK(live::kind_label("UPTIME") == "unknown");
    CHECK(live::kind_label("uptime\n") == "unknown");
    CHECK(live::kind_label(std::string(10000, 'x')) == "unknown");
}
