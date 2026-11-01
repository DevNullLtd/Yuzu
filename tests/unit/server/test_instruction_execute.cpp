/**
 * test_instruction_execute.cpp -- the shared core (instruction_execute.hpp) and the v1 REST twin
 * (POST /api/v1/instructions/{id}/execute) of the instruction-definition execute capability.
 * Ledger row post.api-instructions-param-execute (#2146).
 *
 * NO POSTGRES. InstructionStore, ApprovalManager and ExecutionTracker are all Postgres-backed,
 * so every one of them is a std::function SEAM on instruction_execute::Ports and is faked here.
 * What this file therefore does NOT prove (and the senior should know): the real store
 * round-trip (definition read, approval row, execution row, the ADR-1007 claim INSERT/UPDATE
 * inside wire_and_dispatch_confined, which needs an ExecutionTracker). Everything that decides
 * who is reached IS real: the chokepoint dry run (classify_and_authorize_dispatch over a real
 * CommandCapabilityRegistry), and wire_and_dispatch_confined over a real AgentRegistry, observed
 * through drain_gateway_pending (the technique of test_rest_quarantine_create_gate.cpp), so the
 * confinement cases assert the EXACT recipients rather than that a VisibleSet was handed over.
 */

#include "agent_registry.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_scope_ladder.hpp"
#include "dispatch_target_shape.hpp"
#include "dispatch_zero_reach.hpp"
#include "instruction_execute.hpp"
#include "instruction_execute_routes.hpp"
#include "mcp_instruction_execute.hpp" // kSubmitterPendingCap alias
#include "service_scope_policy.hpp"

#include "../test_helpers.hpp"
#include "test_instruction_execute_rig.hpp"
#include "test_route_sink.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <functional>
#include <map>
#include <span>
#include <unordered_set>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::instruction_execute;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::DispatchDenial;
using yuzu::server::detail::DispatchDenialReason;
using yuzu::server::detail::EventBus;
using json = nlohmann::json;

using namespace yuzu::test::instr_exec;

namespace {

} // namespace

// ---------------------------------------------------------------------------------------------
// The approval verdict, pinned as a matrix (owner ruling 2026-10-30).
// ---------------------------------------------------------------------------------------------

TEST_CASE("definition_needs_approval: the approval_mode matrix", "[instruction_execute][approval]") {
    CHECK_FALSE(definition_needs_approval("auto", false));
    CHECK_FALSE(definition_needs_approval("auto", true));
    CHECK(definition_needs_approval("always", false));
    CHECK(definition_needs_approval("always", true)); // an administrator does not skip "always"
    CHECK(definition_needs_approval("role-gated", false));
    CHECK_FALSE(definition_needs_approval("role-gated", true));
    // Fail closed: a typo or an empty stored value must not open the gate.
    CHECK(definition_needs_approval("", true));
    CHECK(definition_needs_approval("Auto", true));
    CHECK(definition_needs_approval("autoo", false));
    CHECK(definition_needs_approval("role_gated", true));
}

// ---------------------------------------------------------------------------------------------
// Definition lookup and authorization: nothing dispatches, nothing is minted.
// ---------------------------------------------------------------------------------------------

TEST_CASE("execute: an unwired or failing definition store is 503-class and dispatches nothing",
          "[instruction_execute]") {
    Rig r;
    r.defs["d"] = make_def("d");
    SECTION("unwired") {
        r.store_unwired = true;
    }
    SECTION("read error") {
        r.store_error = true;
    }
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kStoreUnavailable);
    CHECK(ref->retry_after_ms == 5000);
    CHECK(r.calls.empty());
    CHECK(r.rows.empty());
    CHECK(r.approvals.empty());
}

TEST_CASE("execute: an unknown definition is NotFound and dispatches nothing",
          "[instruction_execute]") {
    Rig r;
    auto out = run(r.request("nope", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kNotFound);
    CHECK_FALSE(ref->retry_after_ms.has_value());
    CHECK(r.calls.empty());
    CHECK(r.audits.empty()); // no existence oracle in the audit log either
}

TEST_CASE("execute: the chokepoint dry run refuses BEFORE any body work or ticket",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["d"] = make_def("d", "ping", "always"); // would mint an approval if it got that far
    r.denied_securables.insert("Infrastructure");
    // A malformed body AND a denied caller: the caller learns nothing about the body.
    auto out = run(r.request("d", json::array(), make_caller("u", false)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kDispatchDenied);
    REQUIRE(ref->denial);
    CHECK(ref->denial->reason == DispatchDenialReason::Forbidden);
    CHECK(r.calls.empty());
    CHECK(r.approvals.empty());
    CHECK(r.rows.empty());
    CHECK(r.counter("yuzu_server_dispatch_denied_total", {{"reason", "forbidden"}}) == 1);
    REQUIRE(r.audits.size() == 1);
    CHECK(r.audits[0].result == "denied");
}

TEST_CASE("execute: an unwired authorizer fails closed, never to no gate", "[instruction_execute]") {
    Rig r;
    r.defs["d"] = make_def("d");
    r.authorize_unwired = true;
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kMisconfigured);
    CHECK(r.calls.empty());
}

// CA-7 (#2146): a kMisconfigured refusal is a server defect (a port never wired at boot). It does
// not clear by itself, so it must advertise NO retry (`retry_after_ms` null) and its remediation
// must say it is a configuration defect, on the core and on both wire surfaces.
TEST_CASE("execute: every kMisconfigured arm carries no retry hint and a defect remediation",
          "[instruction_execute][retryhint]") {
    const auto check_refusal = [](const Outcome& out, const char* reason) {
        REQUIRE(as_refusal(out));
        const auto& ref = *as_refusal(out);
        CHECK(ref.kind == RefusalKind::kMisconfigured);
        CHECK(ref.reason == reason);
        CHECK_FALSE(ref.retry_after_ms.has_value());
        CHECK(ref.remediation.find("retrying will not help") != std::string::npos);
        CHECK(ref.remediation.find("configuration defect") != std::string::npos);
    };
    SECTION("authorizer") {
        Rig r;
        r.defs["d"] = make_def("d");
        r.authorize_unwired = true;
        check_refusal(run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit()),
                      "authorizer_unconfigured");
    }
    SECTION("validators") {
        Rig r;
        auto d = make_def("d");
        d.parameter_schema = kLevelSchema;
        r.defs["d"] = d;
        auto p = r.ports();
        p.validators = nullptr;
        check_refusal(run(r.request("d", json{{"params", json{{"level", "x"}}}}, make_caller("u", true)),
                          p, r.audit()),
                      "validators_unconfigured");
    }
    SECTION("dispatch") {
        Rig r;
        r.defs["d"] = make_def("d");
        auto p = r.ports();
        p.dispatch = nullptr;
        check_refusal(run(r.request("d", json::object(), make_caller("u", true)), p, r.audit()),
                      "dispatch_unconfigured");
    }
}

TEST_CASE("execute: the AdminOrApproval gate admits an administrator and refuses a non-admin",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["g"] = make_def("g", "gated");
    {
        auto out = run(r.request("g", json::object(), make_caller("u", false)), r.ports(), r.audit());
        REQUIRE(as_refusal(out));
        REQUIRE(as_refusal(out)->denial);
        CHECK(as_refusal(out)->denial->reason == DispatchDenialReason::ApprovalRequired);
        CHECK(r.calls.empty());
    }
    {
        auto out = run(r.request("g", json::object(), make_caller("root", true)), r.ports(), r.audit());
        CHECK(as_dispatched(out));
    }
}

TEST_CASE("execute: an unwired dispatch is refused BEFORE the 'requested' audit row is written",
          "[instruction_execute]") {
    Rig r;
    r.defs["d"] = make_def("d");
    auto p = r.ports();
    p.dispatch = nullptr;
    auto out = run(r.request("d", json::object(), make_caller("u", true)), p, r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kMisconfigured);
    CHECK(r.audits.empty()); // no evidence row for a call that could never have run
    CHECK(r.rows.empty());
}

TEST_CASE("execute: prepare() refuses a gated pair for a non-admin and tolerates no denial",
          "[instruction_execute][security]") {
    // sec-F1 (#2146): there is no tolerance switch any more. The MCP pre-mint probe is this same
    // prepare(), so a gated pair is refused BEFORE a tier ticket can be minted for it.
    Rig r;
    r.defs["g"] = make_def("g", "gated");
    auto prep = prepare(r.request("g", json::object(), make_caller("u", false)), r.ports(), r.audit());
    REQUIRE(std::holds_alternative<Refusal>(prep.result));
    REQUIRE(std::get<Refusal>(prep.result).denial);
    CHECK(std::get<Refusal>(prep.result).denial->reason == DispatchDenialReason::ApprovalRequired);

    // An administrator clears the gate and gets a Plan.
    auto ok = prepare(r.request("g", json::object(), make_caller("root", true)), r.ports(), r.audit());
    CHECK(std::holds_alternative<Plan>(ok.result));

    // A Forbidden caller is still refused.
    r.denied_securables.insert("Infrastructure");
    auto prep2 = prepare(r.request("g", json::object(), make_caller("root", true)), r.ports(), r.audit());
    REQUIRE(std::holds_alternative<Refusal>(prep2.result));
    CHECK(std::get<Refusal>(prep2.result).denial->reason == DispatchDenialReason::Forbidden);
    CHECK(r.calls.empty());
}

// ---------------------------------------------------------------------------------------------
// Body shape, targeting shape, parameter schema: all before any approval / row / dispatch.
// ---------------------------------------------------------------------------------------------

TEST_CASE("execute: a non-object body is refused, not read as 'no target' and broadcast",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["d"] = make_def("d");
    for (const json& body : {json::array({"agent-A", "agent-B"}), json("scalar"), json(7), json(nullptr)}) {
        auto out = run(r.request("d", body, make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kBadRequest);
        CHECK(ref->reason == "body_type");
    }
    CHECK(r.calls.empty());
    CHECK(r.counter("yuzu_server_dispatch_target_rejected_total",
                    {{"route", "instruction_execute"}, {"reason", "body_type"}}) == 4);
}

TEST_CASE("execute: a supplied targeting argument that names nothing is refused, never widened",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["d"] = make_def("d", "ping", "always"); // an approval would be minted if shape were skipped
    struct Case {
        json body;
        const char* reason;
    };
    const Case cases[] = {
        {json{{"agent_ids", json::array()}}, "agent_ids_empty"},
        {json{{"agent_ids", "agent-A"}}, "agent_ids_type"},
        {json{{"agent_ids", json::array({1})}}, "agent_id_type"},
        {json{{"scope", ""}}, "scope_empty"},
        {json{{"scope", 5}}, "scope_type"},
        {json{{"agent_ids", json::array({"agent-A"})}, {"scope", "tag:x"}}, "target_conflict"},
    };
    for (const auto& c : cases) {
        auto out = run(r.request("d", c.body, make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kBadRequest);
        CHECK(ref->reason == c.reason);
        CHECK(r.counter("yuzu_server_dispatch_target_rejected_total",
                        {{"route", "instruction_execute"}, {"reason", c.reason}}) == 1);
    }
    CHECK(r.calls.empty());
    CHECK(r.approvals.empty());
    CHECK(r.rows.empty());
}

TEST_CASE("execute: a parameter-schema violation dispatches NOTHING and queues no approval",
          "[instruction_execute][security]") {
    Rig r;
    auto d = make_def("d", "ping", "always"); // "always": the approval step would otherwise run
    d.parameter_schema = kLevelSchema;
    r.defs["d"] = d;

    auto out = run(r.request("d", json{{"params", json{{"level", "SECRET-VALUE"}}}}, make_caller("u", true)),
                   r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kBadRequest);
    CHECK(ref->reason == "param_schema");
    CHECK(ref->message.starts_with("invalid params: "));
    CHECK(r.calls.empty());
    CHECK(r.approvals.empty());
    CHECK(r.rows.empty());
    CHECK(r.counter("yuzu_server_instruction_param_rejected_total",
                    {{"route", "instruction_execute"}, {"reason", "violation"}}) == 1);

    // params that is not an object at all counts as `shape`.
    auto out2 = run(r.request("d", json{{"params", "x"}}, make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_refusal(out2));
    CHECK(r.counter("yuzu_server_instruction_param_rejected_total",
                    {{"route", "instruction_execute"}, {"reason", "shape"}}) == 1);

    // The caller-supplied value never reaches the audit detail or the message (only the path).
    CHECK(ref->message.find("SECRET-VALUE") == std::string::npos);
    for (const auto& a : r.audits)
        CHECK(a.detail.find("SECRET-VALUE") == std::string::npos);
    REQUIRE_FALSE(r.audits.empty());
    CHECK(r.audits.front().detail.find("reason=param_schema path=/level") == 0);
}

TEST_CASE("execute: params that is not an object is refused even with no stored schema, never dropped",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["d"] = make_def("d", "ping", "always"); // no parameter_schema
    for (const json& bad : {json("{\"a\":1}"), json(7), json::array({1}), json(true)}) {
        auto out = run(r.request("d", json{{"params", bad}}, make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kBadRequest);
        CHECK(ref->reason == "params_type");
    }
    CHECK(r.calls.empty());
    CHECK(r.approvals.empty());
    // null and an object stay fine.
    r.defs["d"].approval_mode = "auto";
    CHECK(as_dispatched(run(r.request("d", json{{"params", nullptr}}, make_caller("u", true)), r.ports(), r.audit())));
    CHECK(as_dispatched(run(r.request("d", json{{"params", json::object()}}, make_caller("u", true)), r.ports(), r.audit())));
}

TEST_CASE("execute: an unpreparable stored schema fails CLOSED", "[instruction_execute][security]") {
    Rig r;
    auto d = make_def("d");
    d.parameter_schema = R"({"type":"object","properties":{"n":{"type":"nonsense-type"}}})";
    r.defs["d"] = d;
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kSchemaInvalid);
    CHECK(r.calls.empty());
    CHECK(r.counter("yuzu_server_instruction_param_rejected_total",
                    {{"route", "instruction_execute"}, {"reason", "schema_invalid"}}) == 1);
}

TEST_CASE("execute: a valid params object passes and is forwarded as strings",
          "[instruction_execute]") {
    Rig r;
    auto d = make_def("d");
    d.parameter_schema = R"({"type":"object","properties":{"n":{"type":"int32"},"s":{"type":"string"}}})";
    r.defs["d"] = d;
    auto out = run(r.request("d", json{{"params", json{{"n", 5}, {"s", "x"}}}}, make_caller("u", true)),
                   r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    REQUIRE(r.calls.size() == 1);
    CHECK(r.calls[0].params.at("n") == "5");
    CHECK(r.calls[0].params.at("s") == "x");
}

// ---------------------------------------------------------------------------------------------
// The approval matrix and its independence from the tier / ticket (the binding security rule).
// ---------------------------------------------------------------------------------------------

TEST_CASE("execute: approval_mode matrix (auto / always / role-gated / unknown) x admin",
          "[instruction_execute][approval][security]") {
    struct Case {
        const char* mode;
        bool admin;
        bool pending;
    };
    const Case cases[] = {
        {"auto", false, false},       {"auto", true, false},
        {"always", false, true},      {"always", true, true},
        {"role-gated", false, true},  {"role-gated", true, false},
        {"weird", true, true},        {"", false, true},
    };
    for (const auto& c : cases) {
        INFO(c.mode << " admin=" << c.admin);
        Rig r;
        r.defs["d"] = make_def("d", "ping", c.mode);
        auto out = run(r.request("d", json{{"scope", "tag:x"}}, make_caller("u", c.admin)),
                       r.ports(), r.audit());
        if (c.pending) {
            const auto* p = as_pending(out);
            REQUIRE(p);
            CHECK(p->approval_id == "appr-1");
            CHECK(p->definition_id == "d");
            REQUIRE(r.approvals.size() == 1);
            // The ticket carries the identity, the caller's scope verbatim and the pair.
            CHECK(r.approvals[0].def == "d");
            CHECK(r.approvals[0].user == "u");
            CHECK(r.approvals[0].scope == "tag:x");
            CHECK(r.approvals[0].plugin == "testplug");
            CHECK(r.approvals[0].action == "ping");
            // NOTHING dispatches, and no execution row exists for a call that did not run.
            CHECK(r.calls.empty());
            CHECK(r.rows.empty());
            REQUIRE_FALSE(r.audits.empty());
            CHECK(r.audits.back().result == "pending");
        } else {
            CHECK(as_dispatched(out));
            CHECK(r.approvals.empty());
            CHECK(r.calls.size() == 1);
        }
    }
}

TEST_CASE("execute: a consumed MCP ticket or a tier auto-approval cannot skip the definition's gate",
          "[instruction_execute][approval][security]") {
    // The caller carries a Ticket provenance (what C8 stamps after consuming a supervised
    // ticket). That is a TIER fact; the definition gate must not read it.
    for (const char* mode : {"always", "role-gated", "bogus"}) {
        INFO(mode);
        Rig r;
        r.defs["d"] = make_def("d", "ping", mode);
        auto caller = make_caller("u", /*admin=*/false);
        caller.approval_provenance = ApprovalProvenance::Ticket;
        auto out = run(r.request("d", json::object(), caller, Surface::kMcp), r.ports(), r.audit());
        REQUIRE(as_pending(out));
        CHECK(r.calls.empty());
        CHECK(r.rows.empty());
    }
    // And "always" is not skipped by an administrator carrying a ticket either.
    Rig r2;
    r2.defs["d"] = make_def("d", "ping", "always");
    auto caller = make_caller("root", /*admin=*/true);
    caller.approval_provenance = ApprovalProvenance::Ticket;
    auto out = run(r2.request("d", json::object(), caller, Surface::kMcp), r2.ports(), r2.audit());
    REQUIRE(as_pending(out));
    CHECK(r2.calls.empty());
}

TEST_CASE("execute: a non-auto definition with no approval manager is 503, never auto-dispatch",
          "[instruction_execute][approval][security]") {
    Rig r;
    r.approvals_wired = false;
    r.defs["d"] = make_def("d", "ping", "always");
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kApprovalUnavailable);
    // An unwired approval manager is a server defect: it never clears by itself, so no retry hint.
    CHECK_FALSE(ref->retry_after_ms.has_value());
    CHECK(ref->remediation.find("retrying will not help") != std::string::npos);
    CHECK(ref->remediation.find("configuration defect") != std::string::npos);
    CHECK(ref->remediation.find("retry shortly") == std::string::npos);
    CHECK(r.calls.empty());
    CHECK(r.rows.empty());
    // ... while an AUTO definition does not need one.
    r.defs["a"] = make_def("a", "ping", "auto");
    CHECK(as_dispatched(run(r.request("a", json::object(), make_caller("u", true)), r.ports(), r.audit())));
}

TEST_CASE("execute: an approval store failure is a 500-class refusal that dispatches nothing",
          "[instruction_execute][approval]") {
    Rig r;
    r.approval_fails = true;
    r.defs["d"] = make_def("d", "ping", "always");
    auto out = run(r.request("d", json::object(), make_caller("u", false)), r.ports(), r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kApprovalSubmitFailed);
    CHECK(r.calls.empty());
}

TEST_CASE("execute: the per-submitter pending cap (MCP) refuses before minting",
          "[instruction_execute][approval]") {
    Rig r;
    r.pending_for = 25;
    r.defs["d"] = make_def("d", "ping", "always");
    auto rq = r.request("d", json::object(), make_caller("u", false), Surface::kMcp);
    rq.submitter_pending_cap = 25;
    auto out = run(rq, r.ports(), r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kApprovalCapReached);
    CHECK(r.approvals.empty());
    r.pending_for = 24;
    CHECK(as_pending(run(rq, r.ports(), r.audit())));
}

// ---------------------------------------------------------------------------------------------
// The legacy route's events (approval.created / instruction.executed), published by the twins.
// ---------------------------------------------------------------------------------------------

namespace {
struct CoreEmitted {
    struct Ev {
        std::string type;
        json attrs, payload;
    };
    std::vector<Ev> events;
    bool throws{false};
    yuzu::server::EventEmitHook hook() {
        return [this](std::string_view type, const json& attrs, const json& payload) {
            events.push_back({std::string(type), attrs, payload});
            if (throws)
                throw std::runtime_error("analytics sink blew up");
        };
    }
};
} // namespace

TEST_CASE("execute: a dispatch publishes instruction.executed once, with the legacy null shape",
          "[instruction_execute][events]") {
    Rig r;
    r.defs["d"] = make_def("d");
    CoreEmitted em;
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit(),
                   em.hook());
    REQUIRE(as_dispatched(out));
    REQUIRE(em.events.size() == 1);
    CHECK(em.events[0].type == "instruction.executed");
    CHECK(em.events[0].attrs.is_null());
    CHECK(em.events[0].payload.is_null());
    // The success row precedes the event (the outcome is already evidenced).
    CHECK(r.audits.back().result == "success");
}

TEST_CASE("execute: a pending approval publishes approval.created once and no instruction.executed",
          "[instruction_execute][events]") {
    Rig r;
    r.defs["d"] = make_def("d", "ping", "always");
    CoreEmitted em;
    auto out = run(r.request("d", json::object(), make_caller("u", false)), r.ports(), r.audit(),
                   em.hook());
    REQUIRE(as_pending(out));
    REQUIRE(em.events.size() == 1);
    CHECK(em.events[0].type == "approval.created");
    CHECK(r.calls.empty());
}

TEST_CASE("execute: prepare() alone emits approval.created for a pending approval and nothing "
          "for a Plan",
          "[instruction_execute][events]") {
    CoreEmitted em;
    {
        Rig r;
        r.defs["d"] = make_def("d");
        auto prep = prepare(r.request("d", json::object(), make_caller("u", true)), r.ports(),
                            r.audit(), em.hook());
        CHECK(std::holds_alternative<Plan>(prep.result));
        CHECK(em.events.empty()); // the MCP probe on an auto definition: no event until dispatch
    }
    {
        Rig r;
        r.defs["d"] = make_def("d", "ping", "always");
        auto prep = prepare(r.request("d", json::object(), make_caller("u", false)), r.ports(),
                            r.audit(), em.hook());
        CHECK(std::holds_alternative<PendingApproval>(prep.result));
        REQUIRE(em.events.size() == 1);
        CHECK(em.events[0].type == "approval.created");
    }
}

TEST_CASE("execute: no event on a refusal, a cap, a zero-reach or a throwing dispatch",
          "[instruction_execute][events]") {
    SECTION("not found") {
        Rig r;
        CoreEmitted em;
        (void)run(r.request("nope", json::object(), make_caller("u", true)), r.ports(), r.audit(),
                  em.hook());
        CHECK(em.events.empty());
    }
    SECTION("per-principal cap") {
        Rig r;
        r.pending_for = kSubmitterPendingCap;
        r.defs["d"] = make_def("d", "ping", "always");
        CoreEmitted em;
        auto rq = r.request("d", json::object(), make_caller("u", false));
        rq.submitter_pending_cap = kSubmitterPendingCap;
        (void)run(rq, r.ports(), r.audit(), em.hook());
        CHECK(r.approvals.empty());
        CHECK(em.events.empty());
    }
    SECTION("approval store failure") {
        Rig r;
        r.approval_fails = true;
        r.defs["d"] = make_def("d", "ping", "always");
        CoreEmitted em;
        (void)run(r.request("d", json::object(), make_caller("u", false)), r.ports(), r.audit(),
                  em.hook());
        CHECK(em.events.empty());
    }
    SECTION("the requested audit row cannot be stored") {
        Rig r;
        r.audit_requested_fails = true;
        r.defs["d"] = make_def("d");
        CoreEmitted em;
        (void)run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit(),
                  em.hook());
        CHECK(r.calls.empty());
        CHECK(em.events.empty());
    }
    SECTION("the dispatch throws") {
        Rig r;
        r.dispatch_throws = true;
        r.defs["d"] = make_def("d");
        CoreEmitted em;
        (void)run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit(),
                  em.hook());
        CHECK(em.events.empty());
    }
}

TEST_CASE("execute: a throwing event hook never changes the outcome", "[instruction_execute][events]") {
    Rig r;
    r.defs["d"] = make_def("d");
    r.defs["a"] = make_def("a", "ping", "always");
    CoreEmitted em;
    em.throws = true;
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit(),
                   em.hook());
    CHECK(as_dispatched(out));
    CHECK(r.calls.size() == 1);
    auto pend = run(r.request("a", json::object(), make_caller("u", false)), r.ports(), r.audit(),
                    em.hook());
    CHECK(as_pending(pend));
    CHECK(em.events.size() == 2); // each attempted once
}

TEST_CASE("execute: the cap refusal is counted, creates no approval, and is per principal",
          "[instruction_execute][approval][metrics]") {
    Rig r;
    r.pending_counts_submitted = true;
    r.defs["d"] = make_def("d", "ping", "always");
    const yuzu::Labels cap{{"reason", "approval_cap_reached"}};
    auto submit_as = [&](const char* user) {
        auto rq = r.request("d", json::object(), make_caller(user, false), Surface::kRest);
        rq.submitter_pending_cap = kSubmitterPendingCap;
        return run(rq, r.ports(), r.audit());
    };
    // Below the cap every submit lands a pending approval.
    for (int i = 0; i < kSubmitterPendingCap; ++i)
        REQUIRE(as_pending(submit_as("alice")));
    CHECK(r.approvals.size() == static_cast<std::size_t>(kSubmitterPendingCap));
    CHECK(r.counter(std::string(kApprovalRefusedMetric), cap) == 0);

    // At the cap: refused, nothing created, counted exactly once per refusal.
    auto out = submit_as("alice");
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kApprovalCapReached);
    CHECK(as_refusal(out)->reason == "approval_cap_reached");
    CHECK_FALSE(as_refusal(out)->retry_after_ms.has_value());
    CHECK(r.approvals.size() == static_cast<std::size_t>(kSubmitterPendingCap));
    CHECK(r.counter(std::string(kApprovalRefusedMetric), cap) == 1);
    CHECK(as_refusal(submit_as("alice")));
    CHECK(r.counter(std::string(kApprovalRefusedMetric), cap) == 2);

    // Another principal is unaffected by alice's share.
    CHECK(as_pending(submit_as("bob")));
    CHECK(r.approvals.back().user == "bob");
    CHECK(r.counter(std::string(kApprovalRefusedMetric), cap) == 2);
    CHECK(r.calls.empty()); // nothing dispatched on any path
}

TEST_CASE("execute: a cap with an unwired pending counter fails closed, never uncapped",
          "[instruction_execute][approval][security]") {
    Rig r;
    r.defs["d"] = make_def("d", "ping", "always");
    auto ports = r.ports();
    ports.pending_count_for = nullptr;
    auto rq = r.request("d", json::object(), make_caller("u", false), Surface::kRest);
    rq.submitter_pending_cap = kSubmitterPendingCap;
    auto out = run(rq, ports, r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kApprovalUnavailable);
    CHECK_FALSE(as_refusal(out)->retry_after_ms.has_value());
    CHECK(as_refusal(out)->remediation.find("retrying will not help") != std::string::npos);
    CHECK(r.approvals.empty());
    CHECK(r.counter(std::string(kApprovalRefusedMetric),
                    {{"reason", "approval_unavailable"}}) == 1);
}

TEST_CASE("execute: an UNREADABLE pending count refuses (never admits), counted, retryable, "
          "creates no approval",
          "[instruction_execute][approval][security][up8-1]") {
    for (const int fault : {1, 2}) {
        INFO("fault=" << fault << (fault == 1 ? " (nullopt)" : " (throws)"));
        Rig r;
        r.pending_count_fault = fault;
        r.defs["d"] = make_def("d", "ping", "always");
        auto rq = r.request("d", json::object(), make_caller("u", false), Surface::kRest);
        rq.submitter_pending_cap = kSubmitterPendingCap;
        auto out = run(rq, r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kApprovalUnavailable);
        CHECK(ref->reason == "approval_unavailable");
        // A store fault, not a wiring defect: a retry can succeed, unlike the unwired refusals.
        REQUIRE(ref->retry_after_ms.has_value());
        CHECK(ref->remediation.find("retrying will not help") == std::string::npos);
        CHECK(r.approvals.empty());
        CHECK(r.calls.empty());
        CHECK(r.counter(std::string(kApprovalRefusedMetric), {{"reason", "approval_unavailable"}}) == 1);
        CHECK(r.counter(std::string(kApprovalRefusedMetric), {{"reason", "approval_cap_reached"}}) == 0);
        REQUIRE_FALSE(r.audits.empty());
        CHECK(r.audits.back().result == "failure");
        CHECK(r.audits.back().detail.find("cause=pending_count_unreadable") != std::string::npos);
    }
}

TEST_CASE("execute: an unreadable pending count is not consulted when no cap is requested",
          "[instruction_execute][approval]") {
    Rig r;
    r.pending_count_fault = 1;
    r.defs["d"] = make_def("d", "ping", "always");
    auto rq = r.request("d", json::object(), make_caller("u", false)); // submitter_pending_cap == 0
    auto out = run(rq, r.ports(), r.audit());
    CHECK(as_pending(out));
}

TEST_CASE("execute: a FULL global approval queue is its own refusal: counted, no retry hint, "
          "a remediation that names the reviewer, and never approval_submit_failed",
          "[instruction_execute][approval][metrics][queue-full]") {
    Rig r;
    r.approval_queue_full = true;
    r.defs["d"] = make_def("d", "ping", "always");
    auto out = run(r.request("d", json::object(), make_caller("u", false)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kApprovalQueueFull);
    CHECK(ref->reason == "approval_queue_full");
    CHECK_FALSE(ref->retry_after_ms.has_value()); // only a reviewer or the expiry clears it
    CHECK(ref->remediation.find("human reviewer must decide pending approvals") != std::string::npos);
    CHECK(ref->remediation.find("retrying will not help") != std::string::npos);
    CHECK(r.calls.empty());
    CHECK(r.counter(std::string(kApprovalRefusedMetric), {{"reason", "approval_queue_full"}}) == 1);
    CHECK(r.counter(std::string(kApprovalRefusedMetric), {{"reason", "approval_submit_failed"}}) == 0);
    REQUIRE_FALSE(r.audits.empty());
    CHECK(r.audits.back().result == "denied");
    CHECK(r.audits.back().detail.find("reason=approval_queue_full") != std::string::npos);

    // A genuine store fault keeps the retryable submit-failed answer.
    Rig f;
    f.approval_fails = true;
    f.defs["d"] = make_def("d", "ping", "always");
    auto fo = run(f.request("d", json::object(), make_caller("u", false)), f.ports(), f.audit());
    REQUIRE(as_refusal(fo));
    CHECK(as_refusal(fo)->kind == RefusalKind::kApprovalSubmitFailed);
    CHECK(as_refusal(fo)->retry_after_ms.has_value());
    CHECK(f.counter(std::string(kApprovalRefusedMetric), {{"reason", "approval_submit_failed"}}) == 1);
    CHECK(f.counter(std::string(kApprovalRefusedMetric), {{"reason", "approval_queue_full"}}) == 0);
}

TEST_CASE("execute: approval store failure and a missing approval manager are counted",
          "[instruction_execute][approval][metrics]") {
    Rig r;
    r.defs["d"] = make_def("d", "ping", "always");
    r.approval_fails = true;
    (void)run(r.request("d", json::object(), make_caller("u", false)), r.ports(), r.audit());
    CHECK(r.counter(std::string(kApprovalRefusedMetric),
                    {{"reason", "approval_submit_failed"}}) == 1);
    r.approval_fails = false;
    r.approvals_wired = false;
    (void)run(r.request("d", json::object(), make_caller("u", false)), r.ports(), r.audit());
    CHECK(r.counter(std::string(kApprovalRefusedMetric),
                    {{"reason", "approval_unavailable"}}) == 1);
    CHECK(r.counter(std::string(kApprovalRefusedMetric),
                    {{"reason", "approval_cap_reached"}}) == 0);
}

TEST_CASE("the shared cap constant is ONE value across REST, MCP and the C8 mint",
          "[instruction_execute][approval]") {
    CHECK(kSubmitterPendingCap == 25);
    CHECK(yuzu::server::mcp::instruction_definition::kSubmitterPendingCap == kSubmitterPendingCap);
    // The closed reason set the boot seed iterates.
    CHECK(kApprovalRefusedReasons.size() == 4);
    // Exactly these four, in this order (the boot seed iterates it).
    CHECK(kApprovalRefusedReasons[0] == "approval_cap_reached");
    CHECK(kApprovalRefusedReasons[1] == "approval_unavailable");
    CHECK(kApprovalRefusedReasons[2] == "approval_submit_failed");
    CHECK(kApprovalRefusedReasons[3] == "approval_queue_full");
}

// ---------------------------------------------------------------------------------------------
// Destructive / Forensics targeting.
// ---------------------------------------------------------------------------------------------

TEST_CASE("execute: a Destructive action refuses broadcast, scope and omitted targets (400)",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["w"] = make_def("w", "wipe", "always"); // approval would mint if this gate were skipped
    for (const json& body : {json::object(), json{{"scope", "__all__"}}, json{{"scope", "tag:x"}}}) {
        auto out = run(r.request("w", body, make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kBadRequest);
        CHECK(ref->reason == "destructive_untargeted");
        CHECK(ref->message == std::string(kDestructiveUntargetedMessage));
    }
    CHECK(r.calls.empty());
    CHECK(r.approvals.empty());
    CHECK(r.counter("yuzu_server_dispatch_target_rejected_total",
                    {{"route", "instruction_execute"}, {"reason", "destructive_untargeted"}}) == 3);
}

TEST_CASE("execute: a Destructive action confines named targets to the visible set (404 when none)",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["w"] = make_def("w", "wipe");
    // Visible: A only. Named: A and B. Only A may reach dispatch.
    r.visible_agents = std::vector<std::string>{kA};
    auto out = run(r.request("w", json{{"agent_ids", json::array({kA, kB})}}, make_caller("u", true)),
                   r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    REQUIRE(r.calls.size() == 1);
    CHECK(r.calls[0].agent_ids == std::vector<std::string>{kA});

    // None visible -> 404 destructive_no_visible_target, nothing dispatched.
    r.calls.clear();
    r.visible_agents = std::vector<std::string>{kC};
    auto out2 = run(r.request("w", json{{"agent_ids", json::array({kA, kB})}}, make_caller("u", true)),
                    r.ports(), r.audit());
    const auto* ref = as_refusal(out2);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kNoVisibleTarget);
    CHECK(ref->reason == "destructive_no_visible_target");
    CHECK(r.calls.empty());
    CHECK(r.counter("yuzu_server_dispatch_target_rejected_total",
                    {{"route", "instruction_execute"}, {"reason", "destructive_no_visible_target"}}) == 1);
}

TEST_CASE("execute: an absent or degraded management-group read FAILS CLOSED for a Destructive action",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["w"] = make_def("w", "wipe");
    r.visible_agents = std::nullopt; // degraded (ADR-0042): the opposite of VisibleSet nullopt
    auto out = run(r.request("w", json{{"agent_ids", json::array({kA})}}, make_caller("u", true)),
                   r.ports(), r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kNoVisibleTarget);
    CHECK(r.calls.empty());
}

TEST_CASE("execute: a Forensics action needs EXACTLY one explicit agent id",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["f"] = make_def("f", "forensic");
    r.visible_agents = std::vector<std::string>{kA, kB};
    auto two = run(r.request("f", json{{"agent_ids", json::array({kA, kB})}}, make_caller("u", true)),
                   r.ports(), r.audit());
    REQUIRE(as_refusal(two));
    CHECK(as_refusal(two)->reason == "forensic_untargeted");
    auto none = run(r.request("f", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_refusal(none));
    CHECK(as_refusal(none)->reason == "forensic_untargeted");
    CHECK(r.calls.empty());
    auto one = run(r.request("f", json{{"agent_ids", json::array({kA})}}, make_caller("u", true)),
                   r.ports(), r.audit());
    CHECK(as_dispatched(one));
}

TEST_CASE("execute: an unwired classifier fails closed (503)", "[instruction_execute]") {
    Rig r;
    r.defs["d"] = make_def("d");
    auto p = r.ports();
    p.classify = nullptr;
    auto out = run(r.request("d", json::object(), make_caller("u", true)), p, r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kClassifierUnavailable);
    CHECK(r.calls.empty());
}

// #2146: an unwired classifier is a server wiring defect, exactly like kMisconfigured: retrying
// will not help, so the refusal carries NO retry hint and a defect remediation (core, REST, MCP).
TEST_CASE("execute: an unwired classifier advertises no retry and says it is a server defect",
          "[instruction_execute][retryhint]") {
    {
        Rig r;
        r.defs["d"] = make_def("d");
        auto p = r.ports();
        p.classify = nullptr;
        auto out = run(r.request("d", json::object(), make_caller("u", true)), p, r.audit());
        REQUIRE(as_refusal(out));
        const auto& ref = *as_refusal(out);
        CHECK(ref.kind == RefusalKind::kClassifierUnavailable);
        CHECK_FALSE(ref.retry_after_ms.has_value());
        CHECK(ref.remediation.find("retrying will not help") != std::string::npos);
        CHECK(ref.remediation.find("configuration defect") != std::string::npos);
        CHECK(ref.remediation.find("retry shortly") == std::string::npos);
    }
}

// ---------------------------------------------------------------------------------------------
// Audit-first, execution row, claim parameters, bookkeeping.
// ---------------------------------------------------------------------------------------------

TEST_CASE("execute: the audit row is written BEFORE dispatch and a failure dispatches NOTHING",
          "[instruction_execute][audit][security]") {
    SECTION("persist failure") {
        Rig r;
        r.audit_requested_fails = true;
        r.defs["d"] = make_def("d");
        auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kAuditUnavailable);
        CHECK(ref->retry_after_ms == 5000);
        CHECK(r.calls.empty());
        CHECK(r.rows.empty()); // not even an execution row
        CHECK(r.approvals.empty());
    }
    SECTION("the hook throws (bad_alloc class)") {
        Rig r;
        r.audit_throws = true;
        r.defs["d"] = make_def("d");
        auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
        REQUIRE(as_refusal(out));
        CHECK(as_refusal(out)->kind == RefusalKind::kAuditUnavailable);
        CHECK(r.calls.empty());
    }
    SECTION("ordering: requested precedes the dispatch and the success row follows it") {
        Rig r;
        r.defs["d"] = make_def("d");
        std::vector<std::string> trace;
        auto p = r.ports();
        auto inner = p.dispatch;
        p.dispatch = [&](const std::string& a, const std::string& b, const std::vector<std::string>& c,
                         const std::string& d, const std::unordered_map<std::string, std::string>& e,
                         const std::string& f, const DispatchCaller& g, const std::string& h,
                         const std::string& i) {
            trace.push_back("dispatch");
            return inner(a, b, c, d, e, f, g, h, i);
        };
        AuditHook hook = [&](std::string_view result, const std::string&) {
            trace.push_back(std::string("audit:") + std::string(result));
            return true;
        };
        auto out = run(r.request("d", json::object(), make_caller("u", true)), p, hook);
        REQUIRE(as_dispatched(out));
        REQUIRE(trace.size() == 3);
        CHECK(trace[0] == "audit:requested");
        CHECK(trace[1] == "dispatch");
        CHECK(trace[2] == "audit:success");
    }
}

TEST_CASE("execute: a dropped best-effort audit row is reported, the dispatch still stands",
          "[instruction_execute][audit]") {
    Rig r;
    r.audit_other_fails = true; // `success` (and `denied`/`pending`) drop; `requested` persists
    r.defs["d"] = make_def("d");
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    CHECK(out.audit_dropped);
}

TEST_CASE("execute: the execution row carries definition_id and a REDACTED parameter copy; dispatch "
          "carries the claim parameters and the raw params",
          "[instruction_execute]") {
    Rig r;
    auto d = make_def("my.def");
    d.concurrency_mode = "per-device";
    r.defs["my.def"] = d;
    auto out = run(r.request("my.def",
                             json{{"scope", "tag:x"}, {"params", json{{"client_secret", "hunter2"}, {"keep", "v"}}}},
                             make_caller("alice", true)),
                   r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].definition_id == "my.def");
    CHECK(r.rows[0].dispatched_by == "alice");
    CHECK(r.rows[0].scope_expression == "tag:x");
    CHECK(r.rows[0].parameter_values.find("hunter2") == std::string::npos); // redacted at rest
    CHECK(r.rows[0].parameter_values.find("keep") != std::string::npos);
    REQUIRE(r.calls.size() == 1);
    CHECK(r.calls[0].params.at("client_secret") == "hunter2"); // the live dispatch still gets it
    CHECK(r.calls[0].definition_id == "my.def");           // ADR-1007 claim key
    CHECK(r.calls[0].concurrency_mode == "per-device");
    CHECK(r.calls[0].execution_id == "exec-1");             // known BEFORE dispatch (UP2-4)
    CHECK(r.calls[0].principal == "alice");
    CHECK(r.calls[0].provenance == ApprovalProvenance::None); // never stamped by the core
    CHECK(as_dispatched(out)->execution_id == "exec-1");
    CHECK(as_dispatched(out)->agents_reached == 1);
    // Bookkeeping after success.
    REQUIRE(r.targeted.size() == 1);
    CHECK(r.targeted[0] == std::make_pair(std::string("exec-1"), 1));
    CHECK(r.refreshed == std::vector<std::string>{"exec-1"});
    CHECK(r.cancelled.empty());
}

TEST_CASE("execute: omitted agent_ids AND scope is the NAMED broadcast", "[instruction_execute]") {
    Rig r;
    r.defs["d"] = make_def("d");
    REQUIRE(as_dispatched(run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit())));
    REQUIRE(r.calls.size() == 1);
    CHECK(r.calls[0].scope == std::string(kBroadcastScope));
    CHECK(r.calls[0].agent_ids.empty());
    // A named scope is passed verbatim, never rewritten.
    r.calls.clear();
    REQUIRE(as_dispatched(run(r.request("d", json{{"scope", "tag:x"}}, make_caller("u", true)), r.ports(), r.audit())));
    CHECK(r.calls[0].scope == "tag:x");
}

TEST_CASE("execute: no execution tracker still dispatches, with an empty execution_id",
          "[instruction_execute]") {
    Rig r;
    r.ledger_wired = false;
    r.defs["d"] = make_def("d");
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    CHECK(as_dispatched(out)->execution_id.empty());
    CHECK(r.calls[0].execution_id.empty());
}

TEST_CASE("execute: a dispatch that throws (std or non-std) leaves the execution row running (NOT "
          "cancelled), writes a failure row, advertises NO retry and says so in the remediation",
          "[instruction_execute]") {
    for (const bool nonstd : {false, true}) {
        INFO("nonstd=" << nonstd);
        Rig r;
        (nonstd ? r.dispatch_throws_nonstd : r.dispatch_throws) = true;
        r.defs["d"] = make_def("d");
        auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kDispatchFailed);
        CHECK(ref->reason == "dispatch_exception");
        // A thrown dispatch may have partially sent: no hint on the wire, none in the prose.
        CHECK_FALSE(ref->retry_after_ms.has_value());
        CHECK(ref->message.find("retry") == std::string::npos);
        CHECK(ref->remediation.find("retry") == std::string::npos);
        // up8-3 / sg-5: some agent may hold the command, so the row must not read `cancelled`
        // with agents_targeted 0. The remediation names the row and says it was left running.
        CHECK(r.cancelled.empty());
        CHECK(r.targeted.empty());
        CHECK(ref->remediation.find("exec-1") != std::string::npos);
        CHECK(ref->remediation.find("left running, not cancelled") != std::string::npos);
        CHECK(r.calls.size() == 1); // dispatched exactly once, never re-driven
        REQUIRE(r.audits.size() == 2);
        CHECK(r.audits[0].result == "requested");
        CHECK(r.audits[1].result == "failure");
        CHECK(r.audits[1].detail.find("reason=dispatch_exception") != std::string::npos);
        CHECK(r.audits[1].detail.find("execution_id=exec-1") != std::string::npos);
        CHECK_FALSE(out.audit_dropped);
    }
}

TEST_CASE("execute: a dispatch that throws with no execution tracker says no record exists",
          "[instruction_execute]") {
    Rig r;
    r.ledger_wired = false;
    r.dispatch_throws = true;
    r.defs["d"] = make_def("d");
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kDispatchFailed);
    CHECK(ref->remediation.find("no execution record was created") != std::string::npos);
    CHECK(ref->remediation.find("left running") == std::string::npos);
}

TEST_CASE("execute: a create_execution that throws (std or non-std) writes a failure row, "
          "dispatches nothing and is retryable",
          "[instruction_execute]") {
    for (const bool nonstd : {false, true}) {
        INFO("nonstd=" << nonstd);
        Rig r;
        (nonstd ? r.create_throws_nonstd : r.create_throws) = true;
        r.defs["d"] = make_def("d");
        auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kStoreUnavailable);
        CHECK(ref->reason == "execution_record_unavailable");
        CHECK(ref->retry_after_ms.has_value()); // nothing was sent: a retry is safe
        CHECK(r.calls.empty());
        REQUIRE(r.audits.size() == 2);
        CHECK(r.audits[0].result == "requested");
        CHECK(r.audits[1].result == "failure");
        CHECK(r.audits[1].detail.find("reason=execution_record_exception") != std::string::npos);
        CHECK_FALSE(out.audit_dropped);
    }
}

TEST_CASE("execute: a lost failure row after a throwing dispatch is reported as audit_dropped",
          "[instruction_execute][audit]") {
    Rig r;
    r.dispatch_throws_nonstd = true;
    r.audit_other_fails = true;
    r.defs["d"] = make_def("d");
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_refusal(out));
    CHECK(as_refusal(out)->kind == RefusalKind::kDispatchFailed);
    CHECK(out.audit_dropped);
}

TEST_CASE("execute: a failed set_agents_targeted is counted, the dispatch still stands",
          "[instruction_execute]") {
    Rig r;
    r.set_targeted_ok = false;
    r.defs["d"] = make_def("d");
    REQUIRE(as_dispatched(run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit())));
    CHECK(r.counter("yuzu_exec_tracker_bookkeeping_failed_total",
                    {{"op", "set_agents_targeted"}, {"surface", "rest"}}) == 1);
}

// ---------------------------------------------------------------------------------------------
// Zero reach: every cause, with the execution row cancelled.
// ---------------------------------------------------------------------------------------------

TEST_CASE("execute: every zero-reach cause is discriminated and cancels the execution row",
          "[instruction_execute][zero_reach]") {
    struct Case {
        const char* name;
        ConfinedDispatchOutcome outcome;
        ZeroReachCause cause;
        bool retryable;
    };
    auto mk = [](auto&& f) {
        ConfinedDispatchOutcome o{.sent = 0, .command_id = "cmd-z"};
        f(o);
        return o;
    };
    const Case cases[] = {
        {"invalid_scope", mk([](auto& o) { o.scope_parse_error = "bad token"; }), ZeroReachCause::InvalidScope, false},
        {"containment", mk([](auto& o) { o.containment_unreadable = true; }), ZeroReachCause::ContainmentUnreadable, true},
        {"route", mk([](auto& o) { o.route_unreadable = true; }), ZeroReachCause::RouteUnreadable, true},
        {"os_gate", mk([](auto& o) { o.os_gate_unreadable = true; }), ZeroReachCause::OsGateUnreadable, true},
        {"quarantined", mk([](auto& o) { o.denied_quarantined_count = 2; }), ZeroReachCause::Quarantined, false},
        {"plugin", mk([](auto& o) { o.unknown_plugin_count = 1; }), ZeroReachCause::PluginNotFound, false},
        {"killsw", mk([](auto& o) { o.kill_switched_os_count = 3; }), ZeroReachCause::KillSwitchedOs, false},
        {"generic", mk([](auto&) {}), ZeroReachCause::Generic, true},
    };
    for (const auto& c : cases) {
        INFO(c.name);
        Rig r;
        r.defs["d"] = make_def("d");
        r.stub_outcome = c.outcome;
        auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
        const auto* z = as_zero(out);
        REQUIRE(z);
        CHECK(z->cause == c.cause);
        CHECK(zero_reach_retryable(z->cause) == c.retryable);
        CHECK_FALSE(z->message.empty());
        CHECK(z->execution_id == "exec-1");
        CHECK(z->command_id == "cmd-z");
        CHECK(r.cancelled == std::vector<std::string>{"exec-1"}); // never left 'running'
        CHECK(r.targeted.empty());
        REQUIRE_FALSE(r.audits.empty());
        CHECK(r.audits.back().result == "failure");
        CHECK(r.audits.back().detail.find(std::string(zero_reach_token(z->cause))) != std::string::npos);
    }
    // invalid_scope's text carries the parser's reason.
    Rig r;
    r.defs["d"] = make_def("d");
    r.stub_outcome = ConfinedDispatchOutcome{.sent = 0, .scope_parse_error = "bad token"};
    auto out = run(r.request("d", json{{"scope", "tag:(("}}, make_caller("u", true)), r.ports(), r.audit());
    CHECK(as_zero(out)->message == "invalid scope: bad token");
}

TEST_CASE("execute: a protective action never reports os_gate_unreadable / plugin_not_found / kill_switched_os",
          "[instruction_execute][zero_reach]") {
    Rig r;
    auto d = make_def("q");
    d.plugin = "quarantine";
    d.action = "status";
    r.defs["q"] = d;
    r.stub_outcome = ConfinedDispatchOutcome{.sent = 0, .unknown_plugin_count = 1, .os_gate_unreadable = true};
    auto out = run(r.request("q", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_zero(out));
    CHECK(as_zero(out)->cause == ZeroReachCause::Generic);
}

// ---------------------------------------------------------------------------------------------
// EXACT SEND SET: real AgentRegistry + wire_and_dispatch_confined, per targeting arm.
// ---------------------------------------------------------------------------------------------

TEST_CASE("execute: a confined caller reaches exactly its visible agents, per targeting arm",
          "[instruction_execute][confinement][security]") {
    Rig r;
    r.real_dispatch = true;
    r.defs["d"] = make_def("d");
    const authz::VisibleSet only_a = std::unordered_set<std::string>{kA};
    const auto caller = make_caller("op", /*admin=*/true, only_a);

    SECTION("explicit ids: B is silently out") {
        auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB})}}, caller), r.ports(), r.audit());
        REQUIRE(as_dispatched(out));
        CHECK(as_dispatched(out)->agents_reached == 1);
        CHECK(r.drain() == std::vector<std::pair<std::string, std::string>>{{kA, "testplug.ping"}});
    }
    SECTION("explicit ids all out of scope: reaches nobody, discriminated as zero reach") {
        auto out = run(r.request("d", json{{"agent_ids", json::array({kB, kC})}}, caller), r.ports(), r.audit());
        REQUIRE(as_zero(out));
        CHECK(r.drain().empty());
        CHECK(r.cancelled.size() == 1);
    }
    SECTION("omitted targets (broadcast): the fleet is intersected with the visible set") {
        auto out = run(r.request("d", json::object(), caller), r.ports(), r.audit());
        REQUIRE(as_dispatched(out));
        CHECK(r.drain() == std::vector<std::pair<std::string, std::string>>{{kA, "testplug.ping"}});
    }
    SECTION("an unfiltered caller (nullopt) reaches all three") {
        auto out = run(r.request("d", json::object(), make_caller("root", true)), r.ports(), r.audit());
        REQUIRE(as_dispatched(out));
        CHECK(as_dispatched(out)->agents_reached == 3);
        CHECK(r.drain().size() == 3);
    }
    SECTION("a present-EMPTY visible set (the fail-closed default) reaches nobody") {
        auto out = run(r.request("d", json::object(), make_caller("op", true, authz::deny_all())), r.ports(), r.audit());
        REQUIRE(as_zero(out));
        CHECK(r.drain().empty());
    }
    SECTION("a pending approval sends NOTHING to anyone") {
        r.defs["d"].approval_mode = "always";
        auto out = run(r.request("d", json::object(), make_caller("root", true)), r.ports(), r.audit());
        REQUIRE(as_pending(out));
        CHECK(r.drain().empty());
    }
}

TEST_CASE("execute: a refused call sends nothing to any agent", "[instruction_execute][confinement]") {
    Rig r;
    r.real_dispatch = true;
    r.defs["d"] = make_def("d", "ping", "always");
    r.defs["bad"] = make_def("bad");
    r.defs["bad"].parameter_schema = kLevelSchema;
    (void)run(r.request("bad", json::object(), make_caller("root", true)), r.ports(), r.audit());
    (void)run(r.request("d", json{{"agent_ids", json::array()}}, make_caller("root", true)), r.ports(), r.audit());
    (void)run(r.request("nope", json::object(), make_caller("root", true)), r.ports(), r.audit());
    CHECK(r.drain().empty());
}

// ---------------------------------------------------------------------------------------------
// Pure policy facts the REST/MCP gates rest on (the gates themselves are AuthRoutes::require_*).
// ---------------------------------------------------------------------------------------------

TEST_CASE("service-scope allow-list stays EMPTY: Execution:Execute is not global-safe",
          "[instruction_execute][security][service_scope]") {
    // Both twins gate on the plain, global Execution:Execute pair. A service-scoped token is
    // refused by require_permission because this stays false; widening it is a security decision.
    CHECK_FALSE(authz::service_scope_global_safe("Execution", "Execute"));
    CHECK(authz::kServiceScopeGlobalSafe.empty());
}

// ---------------------------------------------------------------------------------------------
// The v1 REST route (TestRouteSink).
// ---------------------------------------------------------------------------------------------

namespace {

struct RouteRig {
    Rig core;
    yuzu::server::test::TestRouteSink sink;
    std::vector<std::pair<std::string, std::string>> perm_calls;
    bool perm_grant{true};
    DispatchCaller caller = make_caller("alice", true);
    bool caller_wired{true};
    int audit_calls{0};
    struct Emitted {
        std::string type;
        json attrs, payload;
    };
    std::vector<Emitted> emitted;
    bool emit_throws{false};

    // `pre` arranges the core fake BEFORE the routes are registered: which seams are wired is a
    // construction-time fact (everything else is read live through `core`).
    explicit RouteRig(const std::function<void(Rig&)>& pre = {}, bool audit_wired = true) {
        if (pre)
            pre(core);
        RouteDeps deps;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& s,
                              const std::string& o) {
            perm_calls.emplace_back(s, o);
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        if (audit_wired) {
            deps.audit_fn = [this](const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string& type,
                                   const std::string& id, const std::string& detail_text) {
                ++audit_calls;
                CHECK(action == "instruction.execute");
                CHECK(type == "instruction");
                core.audits.push_back({result, detail_text + " [id=" + id + "]"});
                if (result == "requested")
                    return !core.audit_requested_fails;
                return !core.audit_other_fails;
            };
        }
        if (caller_wired)
            deps.caller_fn = [this](const httplib::Request&) { return caller; };
        deps.emit_event_fn = [this](const std::string& type, const httplib::Request&,
                                    const json& attrs, const json& payload) {
            emitted.push_back({type, attrs, payload});
            if (emit_throws)
                throw std::runtime_error("analytics sink blew up");
        };
        deps.ports = core.ports();
        register_instruction_execute_routes(sink, std::move(deps));
    }

    auto post(const std::string& id, const std::string& body) {
        return sink.Post("/api/v1/instructions/" + id + "/execute", body);
    }
};

} // namespace

TEST_CASE("REST execute: 200 envelope, gate pair, audit rows", "[instruction_execute][rest]") {
    RouteRig r;
    r.core.defs["d"] = make_def("d");
    auto res = r.post("d", R"({"params":{"a":"b"}})");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto j = json::parse(res->body);
    CHECK(j["meta"]["api_version"] == "v1");
    CHECK(j["data"]["command_id"] == "cmd-1");
    CHECK(j["data"]["execution_id"] == "exec-1");
    CHECK(j["data"]["agents_reached"] == 1);
    CHECK(j["data"]["definition_id"] == "d");
    REQUIRE(r.perm_calls.size() == 1);
    CHECK(r.perm_calls[0] == std::make_pair(std::string("Execution"), std::string("Execute")));
    REQUIRE(r.core.audits.size() == 2);
    CHECK(r.core.audits[0].result == "requested");
    CHECK(r.core.audits[1].result == "success");
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
}

TEST_CASE("REST execute: a chokepoint denial names the definition's plugin.action in its text",
          "[instruction_execute][rest]") {
    RouteRig r;
    r.core.defs["g"] = make_def("g", "gated");
    r.caller = make_caller("bob", /*admin=*/false);
    auto res = r.post("g", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "approval_required");
    CHECK(j["error"]["message"].get<std::string>().find("testplug.gated") != std::string::npos);
}

TEST_CASE("REST execute: a denied gate runs nothing", "[instruction_execute][rest][security]") {
    RouteRig r;
    r.core.defs["d"] = make_def("d");
    r.perm_grant = false;
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(r.core.calls.empty());
    CHECK(r.core.audits.empty());
}

TEST_CASE("REST execute: 400 for a nested or malformed body before any lookup",
          "[instruction_execute][rest]") {
    RouteRig r;
    r.core.defs["d"] = make_def("d");
    std::string deep;
    for (int i = 0; i < 200; ++i)
        deep += "[";
    auto res = r.post("d", deep);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(json::parse(res->body)["error"]["reason"] == "body_depth");
    auto res2 = r.post("d", "{not json");
    CHECK(res2->status == 400);
    CHECK(json::parse(res2->body)["error"]["reason"] == "invalid_json");
    CHECK(r.core.calls.empty());
}

TEST_CASE("REST execute: status mapping of every refusal", "[instruction_execute][rest]") {
    struct Case {
        const char* what;
        std::function<void(RouteRig&)> arrange;
        std::string id;
        std::string body;
        int status;
        const char* reason;
    };
    const Case cases[] = {
        {"not found", [](RouteRig&) {}, "nope", "{}", 404, "not_found"},
        {"store error", [](RouteRig& r) { r.core.store_error = true; }, "d", "{}", 503, "store_unavailable"},
        {"array body", [](RouteRig&) {}, "d", "[1]", 400, "body_type"},
        {"empty agent_ids", [](RouteRig&) {}, "d", R"({"agent_ids":[]})", 400, "agent_ids_empty"},
        {"param violation",
         [](RouteRig& r) { r.core.defs["d"].parameter_schema = kLevelSchema; },
         "d", "{}", 400, "param_schema"},
        {"bad stored schema",
         [](RouteRig& r) { r.core.defs["d"].parameter_schema = R"({"type":"zzz"})"; }, "d", "{}", 500, "param_schema_invalid"},
        {"destructive untargeted", [](RouteRig& r) { r.core.defs["d"].action = "wipe"; }, "d", "{}", 400, "destructive_untargeted"},
        {"destructive none visible",
         [](RouteRig& r) {
             r.core.defs["d"].action = "wipe";
             r.core.visible_agents = std::vector<std::string>{};
         },
         "d", R"({"agent_ids":["agent-A"]})", 404, "destructive_no_visible_target"},
        {"dispatch denied (forbidden)",
         [](RouteRig& r) { r.core.denied_securables.insert("Infrastructure"); }, "d", "{}", 403, "forbidden"},
        {"dispatch denied (unclassified)",
         [](RouteRig& r) { r.core.defs["d"].action = "mystery"; }, "d", "{}", 400, "unclassified"},
        {"audit unavailable", [](RouteRig& r) { r.core.audit_requested_fails = true; }, "d", "{}", 503, "audit_unavailable"},
        {"dispatch throws", [](RouteRig& r) { r.core.dispatch_throws = true; }, "d", "{}", 500, "dispatch_exception"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        c.arrange(r); // `ports()` captured the Rig by reference: later state changes are live
        auto res = r.post(c.id, c.body);
        REQUIRE(res);
        CHECK(res->status == c.status);
        const auto j = json::parse(res->body);
        CHECK(j["error"]["code"] == c.status);
        CHECK(j["error"]["reason"] == c.reason);
        CHECK(j["error"].contains("correlation_id"));
        CHECK(j["error"].contains("retry_after_ms")); // always present, nullable
        CHECK(j["meta"]["api_version"] == "v1");
        if (c.status == 503 && std::string(c.reason) == "audit_unavailable")
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
}

TEST_CASE("REST execute: a throwing dispatch is a 500 with NO retry hint (std and non-std), "
          "Sec-Audit-Failed only when the failure row is lost",
          "[instruction_execute][rest][security]") {
    for (const bool nonstd : {false, true}) {
        for (const bool lose_row : {false, true}) {
            INFO("nonstd=" << nonstd << " lose_row=" << lose_row);
            RouteRig r;
            r.core.defs["d"] = make_def("d");
            (nonstd ? r.core.dispatch_throws_nonstd : r.core.dispatch_throws) = true;
            r.core.audit_other_fails = lose_row;
            auto res = r.post("d", "{}");
            REQUIRE(res);
            CHECK(res->status == 500);
            const auto err = json::parse(res->body)["error"];
            CHECK(err["reason"] == "dispatch_exception");
            CHECK(err["retry_after_ms"].is_null());
            CHECK(err["message"].get<std::string>().find("retry") == std::string::npos);
            CHECK(err.value("remediation", std::string{}).find("retry") == std::string::npos);
            CHECK(r.core.calls.size() == 1);
            REQUIRE(r.core.audits.size() == 2);
            CHECK(r.core.audits[1].result == "failure");
            CHECK(res->get_header_value("Sec-Audit-Failed") == (lose_row ? "true" : ""));
        }
    }
}

TEST_CASE("REST execute: a non-auto definition with no approval manager is 503, nothing dispatched",
          "[instruction_execute][rest][approval][security]") {
    RouteRig r([](Rig& core) {
        core.approvals_wired = false;
        core.defs["x"] = make_def("x", "ping", "always");
    });
    auto res = r.post("x", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "approval_unavailable");
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(j["error"]["remediation"].get<std::string>().find("retrying will not help") !=
          std::string::npos);
    CHECK(r.core.calls.empty());
}

TEST_CASE("REST execute: 202 pending_approval body, and nothing dispatched",
          "[instruction_execute][rest][approval]") {
    RouteRig r;
    r.core.defs["d"] = make_def("d", "ping", "role-gated");
    r.caller = make_caller("bob", /*admin=*/false);
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto j = json::parse(res->body);
    CHECK(j["data"]["status"] == "pending_approval");
    CHECK(j["data"]["approval_id"] == "appr-1");
    CHECK(j["data"]["approval_mode"] == "role-gated");
    CHECK(j["data"]["definition_id"] == "d");
    CHECK(r.core.calls.empty());
    CHECK(r.core.rows.empty());
    CHECK(r.core.drain().empty());

    // The same definition for an administrator dispatches.
    r.caller = make_caller("root", true);
    CHECK(r.post("d", "{}")->status == 200);
}

TEST_CASE("REST execute: publishes instruction.executed on 200 and approval.created on 202, "
          "nothing on a refusal, and a throwing emitter does not fail the call",
          "[instruction_execute][rest][events]") {
    SECTION("200 -> instruction.executed once") {
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        auto res = r.post("d", "{}");
        REQUIRE(res);
        CHECK(res->status == 200);
        REQUIRE(r.emitted.size() == 1);
        CHECK(r.emitted[0].type == "instruction.executed");
        CHECK(r.emitted[0].attrs.is_null());
        CHECK(r.emitted[0].payload.is_null());
    }
    SECTION("202 -> approval.created once, no instruction.executed") {
        RouteRig r;
        r.core.defs["d"] = make_def("d", "ping", "role-gated");
        r.caller = make_caller("bob", /*admin=*/false);
        auto res = r.post("d", "{}");
        REQUIRE(res);
        CHECK(res->status == 202);
        REQUIRE(r.emitted.size() == 1);
        CHECK(r.emitted[0].type == "approval.created");
    }
    SECTION("refusals publish nothing") {
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        CHECK(r.post("nope", "{}")->status == 404);
        CHECK(r.post("d", "[1]")->status == 400);
        r.perm_grant = false;
        CHECK(r.post("d", "{}")->status == 403);
        CHECK(r.emitted.empty());
    }
    SECTION("a throwing emitter: still 200, the failure is counted") {
        RouteRig r;
        r.emit_throws = true;
        r.core.defs["d"] = make_def("d");
        auto res = r.post("d", "{}");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(r.emitted.size() == 1);
        CHECK(r.core.counter("yuzu_server_event_emit_failed_total",
                             {{"event_type", "instruction.executed"}}) == 1);
        CHECK(r.core.counter("yuzu_server_event_emit_failed_total", {{"event_type", "other"}}) == 0);
    }
}

TEST_CASE("REST execute: an unreadable pending count answers 503 approval_unavailable with a retry "
          "hint and creates nothing",
          "[instruction_execute][rest][approval][security][up8-1]") {
    RouteRig r([](Rig& c) { c.pending_count_fault = 1; });
    r.core.defs["d"] = make_def("d", "ping", "always");
    r.caller = make_caller("bob", /*admin=*/false);
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "approval_unavailable");
    CHECK(j["error"]["retry_after_ms"] == 5000);
    CHECK(r.core.approvals.empty());
    CHECK(r.core.counter(std::string(kApprovalRefusedMetric),
                         {{"reason", "approval_unavailable"}}) == 1);
}

TEST_CASE("REST execute: a full global approval queue answers 503 approval_queue_full with a null "
          "retry_after_ms and a reviewer remediation",
          "[instruction_execute][rest][approval][queue-full]") {
    RouteRig r([](Rig& c) { c.approval_queue_full = true; });
    r.core.defs["d"] = make_def("d", "ping", "always");
    r.caller = make_caller("bob", /*admin=*/false);
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "approval_queue_full");
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(j["error"]["remediation"].get<std::string>().find("human reviewer") != std::string::npos);
    CHECK(r.core.counter(std::string(kApprovalRefusedMetric),
                         {{"reason", "approval_queue_full"}}) == 1);
}

TEST_CASE("REST execute: the per-principal pending-approval cap answers 429 and creates nothing",
          "[instruction_execute][rest][approval]") {
    RouteRig r([](Rig& c) { c.pending_counts_submitted = true; });
    r.core.defs["d"] = make_def("d", "ping", "always");
    r.caller = make_caller("bob", /*admin=*/false);
    // The route applies the shared cap WITHOUT the test setting it on a Request.
    for (int i = 0; i < kSubmitterPendingCap; ++i) {
        auto ok = r.post("d", "{}");
        REQUIRE(ok);
        REQUIRE(ok->status == 202);
    }
    CHECK(r.core.approvals.size() == static_cast<std::size_t>(kSubmitterPendingCap));
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 429);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["code"] == 429);
    CHECK(j["error"]["reason"] == "approval_cap_reached");
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(j["error"].contains("correlation_id"));
    CHECK(j["error"].contains("remediation"));
    CHECK(r.core.approvals.size() == static_cast<std::size_t>(kSubmitterPendingCap));
    CHECK(r.core.audits.back().result == "denied");
    CHECK(r.core.counter(std::string(kApprovalRefusedMetric),
                         {{"reason", "approval_cap_reached"}}) == 1);

    // Another principal is not throttled by bob's share.
    r.caller = make_caller("carol", /*admin=*/false);
    CHECK(r.post("d", "{}")->status == 202);
    // An auto definition is unaffected by the approval cap (it needs no approval).
    r.core.defs["a"] = make_def("a", "ping", "auto");
    r.caller = make_caller("bob", /*admin=*/false);
    CHECK(r.post("a", "{}")->status == 200);
}

TEST_CASE("REST execute: zero reach maps to 400 (invalid_scope) or 503 with an honest retry hint",
          "[instruction_execute][rest][zero_reach]") {
    struct Case {
        ConfinedDispatchOutcome o;
        int status;
        const char* reason;
        bool retry;
    };
    auto mk = [](auto&& f) {
        ConfinedDispatchOutcome o{.sent = 0, .command_id = "cmd-z"};
        f(o);
        return o;
    };
    const Case cases[] = {
        {mk([](auto& o) { o.scope_parse_error = "bad"; }), 400, "invalid_scope", false},
        {mk([](auto& o) { o.containment_unreadable = true; }), 503, "containment_unreadable", true},
        {mk([](auto& o) { o.route_unreadable = true; }), 503, "route_unreadable", true},
        {mk([](auto& o) { o.os_gate_unreadable = true; }), 503, "os_gate_unreadable", true},
        {mk([](auto& o) { o.denied_quarantined_count = 1; }), 503, "quarantined", false},
        {mk([](auto& o) { o.unknown_plugin_count = 1; }), 503, "plugin_not_found", false},
        {mk([](auto& o) { o.kill_switched_os_count = 1; }), 503, "kill_switched_os", false},
        {mk([](auto&) {}), 503, "no_agents_reached", true},
    };
    for (const auto& c : cases) {
        INFO(c.reason);
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        r.core.stub_outcome = c.o;
        auto res = r.post("d", "{}");
        REQUIRE(res);
        CHECK(res->status == c.status);
        const auto j = json::parse(res->body);
        CHECK(j["error"]["reason"] == c.reason);
        if (c.retry)
            CHECK(j["error"]["retry_after_ms"] == 5000);
        else
            CHECK(j["error"]["retry_after_ms"].is_null());
        CHECK(j["error"]["execution_id"] == "exec-1");
        CHECK(j["error"].contains("agents_quarantined"));
    }
}

TEST_CASE("REST execute: a dropped best-effort audit sets Sec-Audit-Failed on a 200",
          "[instruction_execute][rest][audit]") {
    RouteRig r;
    r.core.defs["d"] = make_def("d");
    r.core.audit_other_fails = true;
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("REST execute: an UNWIRED audit sink is a 503 with Sec-Audit-Failed, never audit-off",
          "[instruction_execute][rest][audit][security]") {
    RouteRig r({}, /*audit_wired=*/false);
    r.core.real_dispatch = true;
    r.core.defs["d"] = make_def("d");
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "audit_unavailable");
    CHECK(j["error"]["retry_after_ms"].is_null()); // a server defect, not a transient fault
    // Nothing was dispatched, no execution row was created, and the gate still ran first.
    CHECK(r.core.drain().empty());
    CHECK(r.audit_calls == 0);
    CHECK(r.perm_calls.size() == 1);
}

TEST_CASE("REST and MCP: a kMisconfigured refusal is 500 / -32603 with retry_after_ms null",
          "[instruction_execute][rest][retryhint]") {
    // REST: the authorizer is unwired.
    RouteRig r([](Rig& core) { core.authorize_unwired = true; });
    r.core.defs["d"] = make_def("d");
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 500);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "authorizer_unconfigured");
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(j["error"]["remediation"].get<std::string>().find("retrying will not help") !=
          std::string::npos);

    // MCP: the same refusal rendered by the MCP surface.
    Refusal ref;
    ref.kind = RefusalKind::kMisconfigured;
    ref.reason = "dispatch_unconfigured";
    ref.message = "command dispatch unavailable";
    ref.remediation = "this is a server configuration defect and retrying will not help";
    const auto rendered = yuzu::server::mcp::instruction_definition::render_refusal(ref, false, "cid");
    CHECK(rendered.is_error);
    const auto d = json::parse(rendered.data_json);
    CHECK(d["retry_after_ms"].is_null());
    CHECK(d["remediation"].is_string());
    CHECK(d["reason"] == "dispatch_unconfigured");
}

TEST_CASE("REST and MCP: an unwired classifier is 503 / -32603 with retry_after_ms null",
          "[instruction_execute][rest][retryhint]") {
    // REST: 503 with a null retry_after_ms.
    RouteRig rr([](Rig& core) { core.classify_unwired = true; });
    rr.core.defs["d"] = make_def("d");
    auto res = rr.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "classifier_unavailable");
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(j["error"]["remediation"].get<std::string>().find("retrying will not help") !=
          std::string::npos);
    // MCP rendering of the same refusal.
    Refusal ref;
    ref.kind = RefusalKind::kClassifierUnavailable;
    ref.reason = "classifier_unavailable";
    ref.message = "capability registry not available";
    ref.remediation = "this is a server configuration defect and retrying will not help";
    const auto rendered = yuzu::server::mcp::instruction_definition::render_refusal(ref, false, "cid");
    CHECK(rendered.is_error);
    CHECK(json::parse(rendered.data_json)["retry_after_ms"].is_null());
}

TEST_CASE("REST execute: an unwired caller derivation fails closed on visibility",
          "[instruction_execute][rest][confinement][security]") {
    Rig core;
    core.real_dispatch = true;
    core.defs["d"] = make_def("d");
    yuzu::server::test::TestRouteSink sink;
    RouteDeps deps;
    deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) { return true; };
    deps.audit_fn = [](const httplib::Request&, const std::string&, const std::string&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    // caller_fn deliberately left unset.
    deps.ports = core.ports();
    register_instruction_execute_routes(sink, std::move(deps));
    auto res = sink.Post("/api/v1/instructions/d/execute", "{}");
    REQUIRE(res);
    // deny-all (present-EMPTY), never unfiltered: nothing reaches any agent.
    CHECK(core.drain().empty());
    CHECK(res->status != 200);
}

TEST_CASE("REST execute: a confined operator reaches exactly its visible agent (end to end)",
          "[instruction_execute][rest][confinement][security]") {
    RouteRig r;
    r.core.real_dispatch = true;
    r.core.defs["d"] = make_def("d");
    r.caller = make_caller("op", true, std::unordered_set<std::string>{kB});
    auto res = r.post("d", R"({"agent_ids":["agent-A","agent-B","agent-C"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["data"]["agents_reached"] == 1);
    CHECK(r.core.drain() == std::vector<std::pair<std::string, std::string>>{{kB, "testplug.ping"}});
}
