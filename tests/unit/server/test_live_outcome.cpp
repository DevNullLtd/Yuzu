/// @file test_live_outcome.cpp
/// Pins the closed vocabulary in live_outcome.hpp: the outcome tokens, the two surface tokens and
/// the kind label. These are metric label values for
/// `yuzu_server_live_requests_total{surface, kind, outcome}`, so the set must stay closed and
/// every value must be a stable, bounded, lowercase token.

#include "dispatch_zero_reach.hpp"
#include "live_outcome.hpp"
#include "live_zero_reach_outcome.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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
        "store_degraded", "internal", "tier_refused", "read_only_refused", "approval_refused",
        "shutting_down", "incomplete", "gate_unreadable"};
    std::set<std::string> actual;
    for (const auto o : live::kAllLiveOutcomes)
        actual.insert(std::string(live::to_token(o)));
    CHECK(actual == expected);
    // The vocabulary is 31 tokens: 2 surfaces x 3 kinds x 31 outcomes = 186 series once pre-seeded.
    CHECK(live::kAllLiveOutcomes.size() == 31);
    CHECK(expected.size() == 31);
}

TEST_CASE("LiveOutcome: the three tokens added after the first release keep their spelling and index", "[live][outcome]") {
    CHECK(live::to_token(live::LiveOutcome::kShuttingDown) == "shutting_down");
    CHECK(live::to_token(live::LiveOutcome::kIncomplete) == "incomplete");
    CHECK(live::to_token(live::LiveOutcome::kGateUnreadable) == "gate_unreadable");
    // Appended after kApprovalRefused, so the existing enumerator values did not move.
    CHECK(static_cast<std::size_t>(live::LiveOutcome::kApprovalRefused) == 27);
    CHECK(static_cast<std::size_t>(live::LiveOutcome::kShuttingDown) == 28);
    CHECK(static_cast<std::size_t>(live::LiveOutcome::kIncomplete) == 29);
    CHECK(static_cast<std::size_t>(live::LiveOutcome::kGateUnreadable) == 30);
}

TEST_CASE("live_outcome_for: every ZeroReachCause maps to the outcome with its own token", "[live][outcome]") {
    using yuzu::server::ZeroReachCause;
    constexpr ZeroReachCause kAllCauses[] = {
        ZeroReachCause::Denied,         ZeroReachCause::InvalidScope,    ZeroReachCause::ContainmentUnreadable,
        ZeroReachCause::RouteUnreadable, ZeroReachCause::OsGateUnreadable, ZeroReachCause::Quarantined,
        ZeroReachCause::PluginNotFound,  ZeroReachCause::KillSwitchedOs,   ZeroReachCause::Generic};
    for (const auto cause : kAllCauses) {
        const auto outcome = live::live_outcome_for(cause);
        CAPTURE(static_cast<int>(cause), live::to_token(outcome), yuzu::server::zero_reach_token(cause));
        if (cause == ZeroReachCause::Generic) {
            // The documented exception: nothing was sent and no named cause applies (the device is
            // offline, or a residual race), which this vocabulary calls `unavailable`.
            CHECK(outcome == live::LiveOutcome::kUnavailable);
            CHECK(live::to_token(outcome) != yuzu::server::zero_reach_token(cause));
        } else {
            CHECK(live::to_token(outcome) == yuzu::server::zero_reach_token(cause));
        }
    }
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

// UP-8: the outcome of a REFUSED re-decision of the per-device scoped gate. A store degrade is
// never a revocation: only a definitive denial is `permission_revoked`.
TEST_CASE("live_outcome_for(ScopedGateOutcome): a denial is permission_revoked, every unreadable class "
          "is gate_unreadable, a lapsed session is caller_unresolved",
          "[live][outcome][2146]") {
    using yuzu::server::ScopedGateOutcome;
    CHECK(live::live_outcome_for(ScopedGateOutcome::Denied) == live::LiveOutcome::kPermissionRevoked);
    CHECK(live::live_outcome_for(ScopedGateOutcome::Unauthenticated) ==
          live::LiveOutcome::kCallerUnresolved);
    CHECK(live::live_outcome_for(ScopedGateOutcome::Unavailable) == live::LiveOutcome::kGateUnreadable);
    CHECK(live::live_outcome_for(ScopedGateOutcome::RbacReadDegraded) ==
          live::LiveOutcome::kGateUnreadable);
    CHECK(live::live_outcome_for(ScopedGateOutcome::MgmtGroupReadDegraded) ==
          live::LiveOutcome::kGateUnreadable);
    // The tokens the audit rows and the metric carry.
    CHECK(live::to_token(live::live_outcome_for(ScopedGateOutcome::Denied)) == "permission_revoked");
    CHECK(live::to_token(live::live_outcome_for(ScopedGateOutcome::RbacReadDegraded)) ==
          "gate_unreadable");
    // Not a refusal: never named a revocation.
    CHECK(live::live_outcome_for(ScopedGateOutcome::Admitted) == live::LiveOutcome::kInternal);
}

TEST_CASE("live metric names and the closed label walks", "[live][outcome][2146]") {
    CHECK(std::string_view(live::kLiveRequestsMetric) == "yuzu_server_live_requests_total");
    CHECK(std::string_view(live::kLiveInFlightMetric) == "yuzu_server_live_in_flight");
    CHECK(live::kAllLiveSurfaces.size() == 2);
    // Every value kind_label can return is in the walk, and nothing else is.
    for (const auto k : {"uptime", "processes", "anything-else", ""}) {
        const auto label = live::kind_label(k);
        CHECK(std::find(live::kAllKindLabels.begin(), live::kAllKindLabels.end(), label) !=
              live::kAllKindLabels.end());
    }
    CHECK(live::kAllKindLabels.size() == 3);
}
