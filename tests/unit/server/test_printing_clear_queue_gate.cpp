/**
 * test_printing_clear_queue_gate.cpp — pins `printing`'s capability
 * fragment (`plugin_action_catalogue_printing.hpp`) and proves, FOR THE
 * ROUTE-HANDLER GATE ONLY, that `clear_queue`'s Destructive classification
 * behaves exactly like every other Destructive row against
 * `evaluate_destructive_targeting` (`dispatch_destructive_gate.hpp`) and
 * `classify_and_authorize_dispatch` (`agent_registry.hpp`).
 *
 * SCOPE, STATED EXPLICITLY (same posture as
 * `plugin_action_catalogue_printing.hpp`'s own banner): `evaluate_destructive
 * _targeting` is applied by exactly THREE operator-facing route handlers —
 * REST `/api/command`, MCP `execute_instruction`, and the dashboard exec
 * console (`server.cpp`:1344-1350). Schedules (`ScheduleRunner::
 * dispatch_tracked`), workflows, and `instruction_execute` apply NO
 * Destructive targeting gate by design — pinned separately by
 * `test_dispatch_confined_arms.cpp`'s "the shared confined-dispatch seam
 * does not refuse a Destructive fan-out (dispatch_destructive_gate.hpp D3)"
 * case. This file proves the route-handler property only, nothing more —
 * it does not, and cannot, assert anything about the schedule/workflow
 * paths' own (deliberately different) posture.
 */

#include "dispatch_destructive_gate.hpp"

#include "agent_registry.hpp"
#include "capability_decls/plugin_action_catalogue_printing.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"

#include <catch2/catch_test_macros.hpp>

#include <span>

using yuzu::server::authz::Operation;
using yuzu::server::CommandCapability;
using yuzu::server::CommandCapabilityRegistry;
using yuzu::server::detail::classify_and_authorize_dispatch;
using yuzu::server::detail::DispatchDenialReason;
using yuzu::server::DispatchCaller;
using yuzu::server::DispatchClass;
using yuzu::server::evaluate_destructive_targeting;
using yuzu::server::ExecuteGate;
using yuzu::server::Mutability;

namespace {
[[nodiscard]] bool always_allow(std::string_view, std::string_view, Operation) { return true; }
} // namespace

// ─────────────────────────────────────── fragment classification pins ──

TEST_CASE("printing.clear_queue is classified Destructive/Irreversible/Infrastructure/Write/"
          "Medium/AdminOrApproval",
          "[server][dispatch][security][capability][printing]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_printing()};
    auto classified = registry.classify("printing", "clear_queue");
    REQUIRE(classified.has_value());

    CHECK(classified->dispatch_class == DispatchClass::Destructive);
    CHECK(classified->mutability == Mutability::Irreversible);
    CHECK(classified->securable == "Infrastructure");
    CHECK(classified->operation == Operation::Write);
    CHECK(classified->risk_tier == yuzu::server::authz::RiskTier::Medium);
    CHECK(classified->execute_gate == ExecuteGate::AdminOrApproval);
}

TEST_CASE("printing.printers and printing.jobs are classified ReadOnly/None/Inventory/Read/None",
          "[server][dispatch][security][capability][printing]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_printing()};

    for (const char* action : {"printers", "jobs"}) {
        auto classified = registry.classify("printing", action);
        REQUIRE(classified.has_value());
        CHECK(classified->dispatch_class == DispatchClass::ReadOnly);
        CHECK(classified->mutability == Mutability::None);
        CHECK(classified->securable == "Inventory");
        CHECK(classified->operation == Operation::Read);
        CHECK(classified->execute_gate == ExecuteGate::None);
    }
}

// ───────────────────────── route-handler targeting gate: RefuseUntargeted ──

TEST_CASE("clear_queue: scope/broadcast dispatch is RefuseUntargeted at the route-handler gate",
          "[server][dispatch][security][capability][printing]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_printing()};
    auto classified = registry.classify("printing", "clear_queue");
    REQUIRE(classified.has_value());

    // No agent_ids, no scope — the ordinary omitted-target broadcast shape.
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/false,
                                                          /*scope_key_present=*/false);
        CHECK(gate.verdict == yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted);
    }
    // scope:"__all__" explicit broadcast alongside agent_ids — the one shape
    // check_targeting_shape uniquely permits through to this gate.
    {
        const auto gate = evaluate_destructive_targeting(classified,
                                                          /*valid_nonempty_agent_ids=*/true,
                                                          /*scope_key_present=*/true);
        CHECK(gate.verdict == yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted);
    }
}

TEST_CASE("clear_queue: explicit non-empty agent_ids, no scope, is Targeted at the route-handler "
          "gate",
          "[server][dispatch][security][capability][printing]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_printing()};
    auto classified = registry.classify("printing", "clear_queue");
    REQUIRE(classified.has_value());

    const auto gate = evaluate_destructive_targeting(classified,
                                                      /*valid_nonempty_agent_ids=*/true,
                                                      /*scope_key_present=*/false);
    CHECK(gate.verdict == yuzu::server::DestructiveTargetingVerdict::Targeted);
    REQUIRE(gate.capability.has_value());
    CHECK(gate.capability->plugin == "printing");
    CHECK(gate.capability->action == "clear_queue");
}

// ───────────────────────── AdminOrApproval: deny/allow through the chokepoint ──

TEST_CASE("clear_queue: non-Administrator caller with no approval provenance is denied at "
          "classify_and_authorize_dispatch (ApprovalRequired)",
          "[server][dispatch][security][capability][printing]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_printing()};
    DispatchCaller caller{.principal = "alice", .principal_role = "operator"};
    // principal_is_admin defaults false, approval_provenance defaults None.

    auto result =
        classify_and_authorize_dispatch(registry, caller, "printing", "clear_queue", always_allow);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().reason == DispatchDenialReason::ApprovalRequired);
    CHECK(result.error().securable == "Infrastructure");
}

TEST_CASE("clear_queue: effective-Administrator caller is allowed through "
          "classify_and_authorize_dispatch with no approval provenance (AdminOrApproval's "
          "admin bypass)",
          "[server][dispatch][security][capability][printing]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_printing()};
    DispatchCaller caller{
        .principal = "admin-alice",
        .principal_role = "admin",
        .principal_is_admin = true,
    };

    auto result =
        classify_and_authorize_dispatch(registry, caller, "printing", "clear_queue", always_allow);
    REQUIRE(result.has_value());
    CHECK(result->plugin == "printing");
    CHECK(result->action == "clear_queue");
}

TEST_CASE("clear_queue: a non-admin caller carrying real approval provenance is allowed through "
          "classify_and_authorize_dispatch",
          "[server][dispatch][security][capability][printing]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_printing()};
    DispatchCaller caller{
        .principal = "bob",
        .principal_role = "operator",
        .approval_provenance = yuzu::server::ApprovalProvenance::Ticket,
    };

    auto result =
        classify_and_authorize_dispatch(registry, caller, "printing", "clear_queue", always_allow);
    REQUIRE(result.has_value());
}
