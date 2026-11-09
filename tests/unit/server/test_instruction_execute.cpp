/**
 * test_instruction_execute.cpp -- the shared core (instruction_execute.hpp) and the v1 REST twin
 * (POST /api/v1/instructions/{id}/execute) of the instruction-definition execute capability.
 * Ledger row post.api-instructions-param-execute (#2146).
 *
 * NO POSTGRES, except the [pg]-tagged cases (the throwing-dispatch wedge tests), which drive a
 * throwing dispatch through the production make_ports binding over a REAL ExecutionTracker and,
 * for the zero-sent case, the real stuck-execution reaper. InstructionStore, ApprovalManager and ExecutionTracker are all Postgres-backed,
 * so every one of them is a std::function SEAM on instruction_execute::Ports and is faked here.
 * What this file therefore does NOT prove (and the senior should know): the real store
 * round-trip (definition read, approval row, execution row, the ADR-1007 claim INSERT/UPDATE
 * inside wire_and_dispatch_confined, which needs an ExecutionTracker). Everything that decides
 * who is reached IS real: the chokepoint dry run (classify_and_authorize_dispatch over a real
 * CommandCapabilityRegistry), and wire_and_dispatch_confined over a real AgentRegistry, observed
 * through drain_gateway_pending (the technique of test_rest_quarantine_create_gate.cpp), so the
 * confinement cases assert the EXACT recipients rather than that a VisibleSet was handed over.
 */

#include <algorithm>

#include "agent_registry.hpp"
#include "command_outbox_store.hpp" // the reaper reads the outbox schema
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_scope_ladder.hpp"
#include "dispatch_target_shape.hpp"
#include "dispatch_zero_reach.hpp"
#include "instruction_execute.hpp"
#include "instruction_execute_ports.hpp"
#include "instruction_execute_routes.hpp"
#include "mcp_instruction_execute.hpp" // kSubmitterPendingCap alias
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "service_scope_policy.hpp"

#include "../test_helpers.hpp"
#include "test_execution_tracker_pg_helper.hpp"
#include "test_instruction_execute_rig.hpp"
#include "test_partial_send_dispatch.hpp"
#include "test_route_sink.hpp"

#include "agent.pb.h"

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
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
    const bool unwired = r.store_unwired;
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kStoreUnavailable);
    CHECK(ref->reason == "store_unavailable");
    if (unwired) {
        // A port that was NEVER wired is a server defect that does not clear by itself: no retry
        // hint, and a remediation that says so (the kMisconfigured class).
        CHECK_FALSE(ref->retry_after_ms.has_value());
        CHECK(ref->remediation.find("retrying will not help") != std::string::npos);
        CHECK(ref->remediation.find("retry shortly") == std::string::npos);
    } else {
        // A wired port whose read FAILED is a fault a retry can clear: it keeps its hint.
        CHECK(ref->retry_after_ms == 5000);
        CHECK(ref->remediation.find("retry shortly") != std::string::npos);
    }
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
    // A `denied` row, like command_v1's unknown-definition refusal (co-2): the 404 already
    // tells the caller the id is unknown, and the audit log is operator-only evidence.
    REQUIRE(r.audits.size() == 1);
    CHECK(r.audits[0].result == "denied");
    CHECK(r.audits[0].detail.find("reason=not_found definition=nope") != std::string::npos);
}

// up-c4: the Postgres binding passes the id as a C string, so "foo\0xyz" used to resolve the
// definition `foo` while every audit row recorded a different string. A control byte is refused
// before any store read, on every surface (the predicate and the refusal live in the one core).
TEST_CASE("execute: a definition id with a control byte is refused before any store read, a normal "
          "id still dispatches",
          "[instruction_execute][security]") {
    struct Hostile {
        const char* label;
        std::string id;
    };
    const std::vector<Hostile> hostile{{"NUL", std::string("d\0xyz", 5)},
                                       {"0x7F", std::string("d\x7f")},
                                       {"0x1F", std::string("d\x1f")},
                                       {"0x01 leading", std::string("\x01") + "d"},
                                       {"LF", std::string("d\nx")}};
    for (const auto& h : hostile) {
        INFO(h.label);
        Rig r;
        r.defs["d"] = make_def("d"); // the C-string prefix of the NUL case resolves to this
        auto out = run(r.request(h.id, json::object(), make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kBadRequest);
        CHECK(ref->reason == "invalid_definition_id");
        CHECK_FALSE(ref->retry_after_ms.has_value());
        CHECK(r.lookups == 0); // refused BEFORE the store was read
        CHECK(r.calls.empty());
        CHECK(r.rows.empty());
        REQUIRE(r.audits.size() == 1);
        CHECK(r.audits[0].result == "denied");
        CHECK(r.audits[0].detail.find("reason=invalid_definition_id") != std::string::npos);
        // The row text carries no raw control byte (log_token cleans the echoed id).
        for (const char ch : r.audits[0].detail) {
            CHECK(static_cast<unsigned char>(ch) >= 0x20);
            CHECK(static_cast<unsigned char>(ch) != 0x7F);
        }
    }
    SECTION("a normal id (positive control, including a UTF-8 id) is untouched") {
        for (const std::string& id : std::vector<std::string>{"d", "my-def_1.v2", "d\xC3\xA9"}) {
            INFO(id);
            Rig r;
            r.defs[id] = make_def(id);
            auto out = run(r.request(id, json::object(), make_caller("u", true)), r.ports(), r.audit());
            CHECK(as_dispatched(out));
        }
    }
    CHECK_FALSE(definition_id_has_control_byte("abc"));
    CHECK_FALSE(definition_id_has_control_byte("\xC3\xA9"));
    CHECK(definition_id_has_control_byte(std::string_view("a\0b", 3)));
    CHECK(definition_id_has_control_byte("a\x1f"));
    CHECK(definition_id_has_control_byte("a\x7f"));
}

// unhappy p4-3: httplib percent-decodes the path, so %C0%80 / %FF arrive as raw bytes. Handed to the
// store they raise SQLSTATE 22021, which used to read as a retryable 503 for an input that can never
// succeed. The same step-0 refusal now covers them, with the same denied row and no store read.
TEST_CASE("execute: a definition id that is not valid UTF-8 is refused at step 0 like a control byte, "
          "a valid multibyte id is not",
          "[instruction_execute][security]") {
    struct Bad {
        const char* label;
        std::string id;
    };
    const std::vector<Bad> bad{{"overlong NUL C0 80", std::string("d\xC0\x80")},
                               {"lone 0xFF", std::string("d\xFF")},
                               {"truncated 2-byte lead", std::string("d\xC3")},
                               {"truncated 3-byte", std::string("d\xE2\x82")},
                               {"surrogate ED A0 80", std::string("d\xED\xA0\x80")},
                               {"above U+10FFFF F4 90 80 80", std::string("d\xF4\x90\x80\x80")},
                               {"stray continuation", std::string("\x80" "d")}};
    for (const auto& b : bad) {
        INFO(b.label);
        CHECK(definition_id_is_invalid_utf8(b.id));
        CHECK(definition_id_is_malformed(b.id));
        CHECK_FALSE(definition_id_has_control_byte(b.id)); // the NEW half, not the old predicate
        Rig r;
        r.defs["d"] = make_def("d");
        auto out = run(r.request(b.id, json::object(), make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kBadRequest);
        CHECK(ref->reason == "invalid_definition_id");
        CHECK_FALSE(ref->retry_after_ms.has_value()); // never a retry hint: it can never succeed
        CHECK(r.lookups == 0);
        CHECK(r.calls.empty());
        REQUIRE(r.audits.size() == 1);
        CHECK(r.audits[0].result == "denied");
        CHECK(r.audits[0].detail.find("reason=invalid_definition_id") != std::string::npos);
        // The cleaned echo is itself valid UTF-8 (log_token folds the bad bytes).
        CHECK_FALSE(definition_id_is_invalid_utf8(r.audits[0].detail));
    }
    SECTION("a valid multibyte id (U+00E9, CJK, 4-byte) is NOT malformed: it reaches the lookup") {
        for (const std::string& id : std::vector<std::string>{"d\xC3\xA9", "d\xE4\xB8\xAD",
                                                               "d\xF0\x9F\x98\x80"}) {
            INFO(id);
            CHECK_FALSE(definition_id_is_malformed(id));
            Rig r; // no such definition: the refusal is not_found, from the lookup
            auto out = run(r.request(id, json::object(), make_caller("u", true)), r.ports(), r.audit());
            const auto* ref = as_refusal(out);
            REQUIRE(ref);
            CHECK(ref->kind == RefusalKind::kNotFound);
            CHECK(r.lookups == 1);
        }
    }
    SECTION("an over-long VALID ascii id still reaches the lookup (the 128-byte audit clamp, not "
            "this check, bounds its text)") {
        const std::string id(4096, 'a');
        CHECK_FALSE(definition_id_is_malformed(id));
        Rig r;
        auto out = run(r.request(id, json::object(), make_caller("u", true)), r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kNotFound);
        CHECK(r.lookups == 1); // step 0 did not refuse it: the lookup ran
        // The clamp the section name claims: the denied row holds the bounded id (128 bytes plus
        // "..."), never the 4096-byte original.
        REQUIRE(r.audits.size() == 1);
        CHECK(r.audits[0].detail.find(std::string(kAuditDefinitionIdMax + 1, 'a')) ==
              std::string::npos);
        CHECK(r.audits[0].detail.find(std::string(kAuditDefinitionIdMax, 'a') + "...") !=
              std::string::npos);
    }
}

// L1 (#2146): `Request::expected_effect` is the MCP supervised tier's hold on the dispatch stage's
// own fresh lookup. A definition that no longer resolves to the bound effect is refused BEFORE the
// authorizer, any audit row of the `requested` family, any execution row or any send.
TEST_CASE("execute: an expected_effect that no longer matches the looked-up definition is refused "
          "before the authorizer, any row or any send; a matching one runs",
          "[instruction_execute][security][c8_effect]") {
    const auto bound = effect_binding("testplug", "ping", "auto", "per-device");
    CHECK(bound == "effect=[\"testplug\",\"ping\",\"auto\",\"per-device\"]\n");
    {
        Rig r;
        r.defs["d"] = make_def("d", "scrub"); // repointed since the effect was bound
        auto rq = r.request("d", json::object(), make_caller("u", true));
        rq.expected_effect = bound;
        auto out = run(rq, r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->kind == RefusalKind::kBadRequest);
        CHECK(ref->reason == "definition_changed");
        CHECK_FALSE(ref->retry_after_ms.has_value());
        CHECK(r.calls.empty());
        CHECK(r.rows.empty());
        REQUIRE(r.audits.size() == 1);
        CHECK(r.audits[0].result == "denied");
        CHECK(r.audits[0].detail.find("reason=definition_changed") != std::string::npos);
    }
    for (const char* tweak : {"mode", "concurrency"}) {
        INFO(tweak);
        Rig r;
        r.defs["d"] = make_def("d", "ping");
        if (std::string(tweak) == "mode")
            r.defs["d"].approval_mode = "role-gated";
        else
            r.defs["d"].concurrency_mode = "per-definition";
        auto rq = r.request("d", json::object(), make_caller("u", true));
        rq.expected_effect = bound;
        const auto out = run(rq, r.ports(), r.audit());
        const auto* ref = as_refusal(out);
        REQUIRE(ref);
        CHECK(ref->reason == "definition_changed");
        CHECK(r.calls.empty());
    }
    {
        Rig r;
        r.defs["d"] = make_def("d", "ping");
        auto rq = r.request("d", json::object(), make_caller("u", true));
        rq.expected_effect = bound;
        auto out = run(rq, r.ports(), r.audit());
        CHECK(as_refusal(out) == nullptr);
        CHECK(r.calls.size() == 1);
    }
    {
        // Unset (REST, the operator tier, the probe itself): no hold, behaviour unchanged.
        Rig r;
        r.defs["d"] = make_def("d", "scrub");
        auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
        CHECK(as_refusal(out) == nullptr);
        CHECK(r.calls.size() == 1);
    }
}

TEST_CASE("effect_binding: JSON-encoded so a hostile stored value cannot forge a field or a line, "
          "and invalid UTF-8 does not throw",
          "[instruction_execute][security][c8_effect]") {
    const auto hostile = effect_binding("p\n\"x", "a,b\"]", "m\r", std::string("c\xFF", 2));
    // Exactly one raw newline: the terminator. Every control byte in a value is escaped.
    CHECK(std::count(hostile.begin(), hostile.end(), '\n') == 1);
    CHECK(hostile.back() == '\n');
    CHECK(hostile.find('\r') == std::string::npos);
    CHECK(hostile.starts_with("effect=["));
    // Two different effects never bind identically (field boundaries are unforgeable).
    CHECK(effect_binding("a", "b,c", "", "") != effect_binding("a,b", "c", "", ""));
    CHECK(effect_binding("a", "b", "", "") != std::string(kUnresolvedEffect));
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

// ---------------------------------------------------------------------------------------------
// ONE correlation id per call (UP-9 / co-3 / er-5, co-2). Every row the call writes carries it as
// the trailing `correlation_id=<id>` token (command_v1's spelling), so an orphan `requested` row
// pairs with its outcome row and with the error body the caller saw.
// ---------------------------------------------------------------------------------------------

namespace {

/// The `correlation_id=` token at the END of a detail string ("" when absent or not trailing).
std::string trailing_cid(const std::string& detail) {
    constexpr std::string_view kKey = " correlation_id=";
    const auto p = detail.rfind(kKey);
    if (p == std::string::npos)
        return {};
    const std::string cid = detail.substr(p + kKey.size());
    return cid.find(' ') == std::string::npos ? cid : std::string{};
}

} // namespace

TEST_CASE("execute: requested and success carry the SAME correlation id, the supplied one",
          "[instruction_execute][audit][correlation]") {
    Rig r;
    r.defs["d"] = make_def("d");
    auto rq = r.request("d", json::object(), make_caller("u", true));
    rq.correlation_id = "cid-supplied-1";
    const auto out = run(rq, r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    CHECK(out.correlation_id == "cid-supplied-1");
    REQUIRE(r.audits.size() == 2);
    CHECK(r.audits[0].result == "requested");
    CHECK(r.audits[1].result == "success");
    CHECK(trailing_cid(r.audits[0].detail) == "cid-supplied-1");
    CHECK(trailing_cid(r.audits[1].detail) == "cid-supplied-1");
}

TEST_CASE("execute: with no supplied id the core mints ONE, shared by every row and the outcome",
          "[instruction_execute][audit][correlation]") {
    Rig r;
    r.defs["d"] = make_def("d");
    const auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    CHECK_FALSE(out.correlation_id.empty());
    REQUIRE(r.audits.size() == 2);
    CHECK(trailing_cid(r.audits[0].detail) == out.correlation_id);
    CHECK(trailing_cid(r.audits[1].detail) == out.correlation_id);
    // A second call mints a different one.
    Rig r2;
    r2.defs["d"] = make_def("d");
    const auto out2 =
        run(r2.request("d", json::object(), make_caller("u", true)), r2.ports(), r2.audit());
    CHECK(out2.correlation_id != out.correlation_id);
}

TEST_CASE("execute: a dispatch that throws pairs its requested and failure rows by correlation id",
          "[instruction_execute][audit][correlation]") {
    Rig r;
    r.defs["d"] = make_def("d");
    r.dispatch_throws = true;
    auto rq = r.request("d", json::object(), make_caller("u", true));
    rq.correlation_id = "cid-throw";
    const auto out = run(rq, r.ports(), r.audit());
    REQUIRE(as_refusal(out));
    REQUIRE(r.audits.size() == 2);
    CHECK(r.audits[0].result == "requested");
    CHECK(r.audits[1].result == "failure");
    CHECK(trailing_cid(r.audits[0].detail) == "cid-throw");
    CHECK(trailing_cid(r.audits[1].detail) == "cid-throw");
    CHECK(out.correlation_id == "cid-throw");
}

TEST_CASE("execute: a zero-reach outcome pairs requested and failure by correlation id",
          "[instruction_execute][audit][correlation]") {
    Rig r;
    r.defs["d"] = make_def("d");
    r.stub_outcome = ConfinedDispatchOutcome{.sent = 0, .command_id = "cmd-0"};
    auto rq = r.request("d", json::object(), make_caller("u", true));
    rq.correlation_id = "cid-zero";
    const auto out = run(rq, r.ports(), r.audit());
    REQUIRE(as_zero(out));
    REQUIRE(r.audits.size() == 2);
    CHECK(trailing_cid(r.audits[0].detail) == "cid-zero");
    CHECK(trailing_cid(r.audits[1].detail) == "cid-zero");
}

TEST_CASE("execute: a pending approval's row carries the correlation id",
          "[instruction_execute][audit][correlation]") {
    Rig r;
    r.defs["d"] = make_def("d", "ping", "always");
    auto rq = r.request("d", json::object(), make_caller("u", true));
    rq.correlation_id = "cid-pending";
    const auto out = run(rq, r.ports(), r.audit());
    REQUIRE(as_pending(out));
    REQUIRE(r.audits.size() == 1);
    CHECK(r.audits[0].result == "pending");
    CHECK(trailing_cid(r.audits[0].detail) == "cid-pending");
    CHECK(out.correlation_id == "cid-pending");
}

TEST_CASE("execute: every refusal writes exactly ONE row, stamped with the outcome's correlation id",
          "[instruction_execute][audit][correlation][security]") {
    struct Case {
        const char* what;
        std::function<void(Rig&)> arrange;
        json body;
        bool admin;
        const char* row_result;
        const char* reason; // substring of the detail
    };
    const Case cases[] = {
        {"unknown definition", [](Rig&) {}, json::object(), true, "denied", "reason=not_found"},
        {"dispatch denied",
         [](Rig& r) { r.denied_securables.insert("Infrastructure"); }, json::object(), false,
         "denied", "reason=forbidden"},
        {"body not an object", [](Rig&) {}, json::array(), true, "denied", "reason=body_type"},
        {"empty agent_ids", [](Rig&) {}, json{{"agent_ids", json::array()}}, true, "denied",
         "reason=agent_ids_empty"},
        {"param violation",
         [](Rig& r) { r.defs["d"].parameter_schema = kLevelSchema; }, json::object(), true,
         "denied", "reason=param_schema"},
        {"unpreparable schema",
         [](Rig& r) { r.defs["d"].parameter_schema = R"({"type":"zzz"})"; }, json::object(), true,
         "failure", "reason=param_schema_invalid"},
        {"destructive untargeted", [](Rig& r) { r.defs["d"].action = "wipe"; }, json::object(),
         true, "denied", "reason=destructive_untargeted"},
        {"destructive none visible",
         [](Rig& r) {
             r.defs["d"].action = "wipe";
             r.visible_agents = std::vector<std::string>{};
         },
         json{{"agent_ids", {"agent-A"}}}, true, "denied", "reason=destructive_no_visible_target"},
        {"approval cap",
         [](Rig& r) {
             r.defs["d"].approval_mode = "always";
             r.pending_for = kSubmitterPendingCap;
         },
         json::object(), true, "denied", "reason=approval_cap_reached"},
        {"approval queue full",
         [](Rig& r) {
             r.defs["d"].approval_mode = "always";
             r.approval_queue_full = true;
         },
         json::object(), true, "denied", "reason=approval_queue_full"},
        {"approval submit failed",
         [](Rig& r) {
             r.defs["d"].approval_mode = "always";
             r.approval_fails = true;
         },
         json::object(), true, "failure", "reason=approval_submit_failed"},
        {"pending count unreadable",
         [](Rig& r) {
             r.defs["d"].approval_mode = "always";
             r.pending_count_fault = 1;
         },
         json::object(), true, "failure", "cause=pending_count_unreadable"},
        {"execution row throws",
         [](Rig& r) { r.create_throws = true; }, json::object(), true, "failure",
         "reason=execution_record_exception"},
    };
    // Twice: with a healthy sink, and with every best-effort row LOST (qe-b3). Every refusal in
    // the table owes a best-effort row, so a lost one must surface as `audit_dropped` (REST
    // Sec-Audit-Failed, MCP audit_persisted:false) without changing the refusal.
    for (const bool lose_rows : {false, true}) {
        INFO("lose_rows=" << lose_rows);
        for (const auto& c : cases) {
            INFO(c.what);
            Rig r;
            r.defs["d"] = make_def("d");
            c.arrange(r);
            r.audit_other_fails = lose_rows;
            auto rq = r.request(std::string(c.what) == "unknown definition" ? "nope" : "d", c.body,
                                make_caller("u", c.admin));
            rq.correlation_id = std::string("cid-") + std::to_string(&c - cases);
            rq.submitter_pending_cap = kSubmitterPendingCap;
            const auto out = run(rq, r.ports(), r.audit());
            REQUIRE(as_refusal(out));
            CHECK(out.correlation_id == rq.correlation_id);
            CHECK(out.audit_dropped == lose_rows);
            // The execution-row failure is the one case with a `requested` row before it.
            const std::size_t expect = std::string(c.what) == "execution row throws" ? 2 : 1;
            REQUIRE(r.audits.size() == expect);
            const auto& row = r.audits.back();
            CHECK(row.result == c.row_result);
            CHECK(row.detail.find(c.reason) != std::string::npos);
            for (const auto& a : r.audits)
                CHECK(trailing_cid(a.detail) == rq.correlation_id);
        }
    }
}

TEST_CASE("execute: audit_pre_core_denial writes ONE denied row, cleans hostile bytes, and reports a "
          "lost row",
          "[instruction_execute][audit][correlation][security]") {
    Rig r;
    CHECK(audit_pre_core_denial(r.audit(), "cid-pre", "body_depth", "d"));
    REQUIRE(r.audits.size() == 1);
    CHECK(r.audits[0].result == "denied");
    CHECK(r.audits[0].detail == "reason=body_depth definition=d correlation_id=cid-pre");

    // CWE-117: a hostile definition id (it is a URL path segment) cannot forge a second field.
    Rig r2;
    CHECK(audit_pre_core_denial(r2.audit(), "cid-pre", "invalid_json", "d\nresult=success"));
    REQUIRE(r2.audits.size() == 1);
    CHECK(r2.audits[0].detail.find('\n') == std::string::npos);
    CHECK(r2.audits[0].detail.find("result=success") == std::string::npos); // no forged field

    Rig lost;
    lost.audit_other_fails = true;
    CHECK_FALSE(audit_pre_core_denial(lost.audit(), "cid-pre", "body_depth", "d"));
    Rig throws;
    throws.audit_throws = true;
    CHECK_FALSE(audit_pre_core_denial(throws.audit(), "cid-pre", "body_depth", "d"));
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
        // sre-b1: counted on the shared fan-out-throw family, once, under this surface's route.
        CHECK(r.counter("yuzu_server_dispatch_fanout_throw_total",
                        {{"route", "instruction_execute"}, {"phase", "dispatch"}}) == 1);
        CHECK(r.counter("yuzu_server_dispatch_fanout_throw_total",
                        {{"route", "mcp"}, {"phase", "dispatch"}}) == 0);
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

// The wedge this closes: a dispatch that throws mid fan-out used to leave agents_targeted at 0, and
// refresh_counts only promotes a row to terminal when agents_targeted > 0 while the reaper skips
// any row an agent has answered, so the row could never close. The send path's accepted-send
// count is now stored on the throw.
TEST_CASE("execute: a dispatch that throws after confirmed sends records that count so the row "
          "can complete",
          "[instruction_execute][send_progress]") {
    Rig r;
    r.defs["d"] = make_def("d");
    r.custom_dispatch = [](const std::vector<std::string>& ids) {
        return yuzu::test::dispatch_throwing_on_nth_send(ids, /*throw_on_nth=*/2);
    };
    auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB, kC})}},
                             make_caller("u", true)),
                   r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kDispatchFailed);
    CHECK_FALSE(ref->retry_after_ms.has_value());
    // The first send was accepted before the second threw: ONE agent holds the command.
    REQUIRE(r.targeted.size() == 1);
    CHECK(r.targeted[0] == std::pair<std::string, int>{"exec-1", 1});
    REQUIRE(r.refreshed.size() == 1); // responses that beat the count can now close the row
    CHECK(r.refreshed[0] == "exec-1");
    CHECK(r.cancelled.empty()); // still NOT cancelled: an agent holds the command
    // The remediation is true: names the row, the count, that results still arrive, and the
    // way to close it; and still advertises no retry.
    CHECK(ref->remediation.find("exec-1") != std::string::npos);
    CHECK(ref->remediation.find("at least 1 agent(s) were sent the command") != std::string::npos);
    CHECK(ref->remediation.find("will complete it") != std::string::npos);
    CHECK(ref->remediation.find("cancel_execution") != std::string::npos);
    CHECK(ref->remediation.find("retry") == std::string::npos);
    REQUIRE(r.audits.size() == 2);
    CHECK(r.audits[1].result == "failure");
    CHECK(r.audits[1].detail.find("reason=dispatch_exception") != std::string::npos);
    CHECK(r.audits[1].detail.find("agents_sent=1") != std::string::npos);
    CHECK(r.audits[1].detail.find("execution_id=exec-1") != std::string::npos);
}

TEST_CASE("execute: a dispatch that throws before any confirmed send records no count and leaves "
          "the row running for the reaper",
          "[instruction_execute][send_progress]") {
    Rig r;
    r.defs["d"] = make_def("d");
    r.custom_dispatch = [](const std::vector<std::string>& ids) {
        return yuzu::test::dispatch_throwing_on_nth_send(ids, /*throw_on_nth=*/1);
    };
    auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB, kC})}},
                             make_caller("u", true)),
                   r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kDispatchFailed);
    CHECK(r.targeted.empty());
    CHECK(r.refreshed.empty());
    CHECK(r.cancelled.empty()); // an in-flight first send is indeterminate: never cancel
    CHECK(ref->remediation.find("some agents may already have received the command") !=
          std::string::npos);
    CHECK(ref->remediation.find("left running, not cancelled") != std::string::npos);
    CHECK(r.audits[1].detail.find("agents_sent") == std::string::npos);
}

TEST_CASE("execute: a failed partial-count write is counted, keeps agents_sent on the row and says "
          "the record will not close by itself",
          "[instruction_execute][send_progress]") {
    Rig r;
    r.set_targeted_ok = false;
    r.defs["d"] = make_def("d");
    r.custom_dispatch = [](const std::vector<std::string>& ids) {
        return yuzu::test::dispatch_throwing_on_nth_send(ids, 3);
    };
    auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB, kC})}},
                             make_caller("u", true)),
                   r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    REQUIRE(r.targeted.size() == 1); // two sends were accepted; the store refused the write
    CHECK(r.targeted[0].second == 2);
    CHECK(r.counter("yuzu_exec_tracker_bookkeeping_failed_total",
                    {{"op", "set_agents_targeted"}, {"surface", "rest"}}) == 1);
    CHECK_FALSE(ref->retry_after_ms.has_value());
    // The count is known even though the write failed: the row carries it (g5 / comp-c1).
    REQUIRE(r.audits.size() == 2);
    CHECK(r.audits[1].detail.find("agents_sent=2") != std::string::npos);
    // The positive "will complete it" claim is NOT made; the honest one is: the server closes the
    // record by itself ONLY if no agent ever answers, and cancel_execution closes it otherwise.
    CHECK(ref->remediation.find("will complete it") == std::string::npos);
    CHECK(ref->remediation.find("at least 2 agent(s) were sent the command") != std::string::npos);
    CHECK(ref->remediation.find("could NOT be recorded") != std::string::npos);
    CHECK(ref->remediation.find("ONLY if no agent ever responds") != std::string::npos);
    CHECK(ref->remediation.find("will NOT close by itself") != std::string::npos);
    CHECK(ref->remediation.find("cancel_execution") != std::string::npos);
    CHECK(ref->remediation.find("retry") == std::string::npos);
}

TEST_CASE("execute: confirmed sends with no execution row still put agents_sent on the failure row",
          "[instruction_execute][send_progress]") {
    Rig r;
    r.create_fails = true; // the ledger is wired but the row was not created: execution_id empty
    r.defs["d"] = make_def("d");
    r.custom_dispatch = [](const std::vector<std::string>& ids) {
        return yuzu::test::dispatch_throwing_on_nth_send(ids, 3);
    };
    auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB, kC})}},
                             make_caller("u", true)),
                   r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(r.targeted.empty()); // nothing to store the count on
    REQUIRE(r.audits.size() == 2);
    CHECK(r.audits[1].detail.find("agents_sent=2") != std::string::npos);
    CHECK(ref->remediation.find("at least 2 agent(s) were sent the command") != std::string::npos);
    CHECK(ref->remediation.find("no execution record was created") != std::string::npos);
    CHECK(ref->remediation.find("cancel_execution") == std::string::npos); // there is no row
}

TEST_CASE("execute: the throw arm writes the failure row BEFORE it records the partial count, and a "
          "lost row never skips the count",
          "[instruction_execute][send_progress]") {
    for (const bool row_lost : {false, true}) {
        INFO("row_lost=" << row_lost);
        Rig r;
        r.audit_other_fails = row_lost; // the failure row is "other" than `requested`
        r.defs["d"] = make_def("d");
        r.custom_dispatch = [](const std::vector<std::string>& ids) {
            return yuzu::test::dispatch_throwing_on_nth_send(ids, 3);
        };
        auto ports = r.ports();
        std::vector<std::string> rows_when_counted;
        ports.set_agents_targeted = [&](const std::string& id, int n) {
            for (const auto& a : r.audits)
                rows_when_counted.push_back(a.result);
            r.targeted.emplace_back(id, n);
            return true;
        };
        auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB, kC})}},
                                 make_caller("u", true)),
                       ports, r.audit());
        REQUIRE(as_refusal(out));
        // A later allocation failure in the count / metric steps must find the row already out.
        CHECK(rows_when_counted == std::vector<std::string>{"requested", "failure"});
        REQUIRE(r.targeted.size() == 1);
        CHECK(r.targeted[0].second == 2);
        CHECK(out.audit_dropped == row_lost);
    }
}

TEST_CASE("execute: the generic throw remediation says the record closes by itself ONLY when no "
          "agent responds",
          "[instruction_execute][send_progress]") {
    Rig r;
    r.dispatch_throws = true;
    r.defs["d"] = make_def("d");
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->remediation.find("ONLY if no agent ever responds") != std::string::npos);
    CHECK(ref->remediation.find("will NOT close by itself") != std::string::npos);
    CHECK(ref->remediation.find("cancel_execution") != std::string::npos);
    CHECK(ref->remediation.find("retry") == std::string::npos);
}

TEST_CASE("execute: a throwing dispatch with no tracker wired records nothing",
          "[instruction_execute][send_progress]") {
    Rig r;
    r.ledger_wired = false;
    r.defs["d"] = make_def("d");
    r.custom_dispatch = [](const std::vector<std::string>& ids) {
        return yuzu::test::dispatch_throwing_on_nth_send(ids, 2);
    };
    // The rig unwires set_agents_targeted TOGETHER with the rest of the ledger, so the port is
    // re-wired here: the empty-execution_id guard in the throw arm is then what keeps the count
    // from being stored against a row that does not exist. With the port left unwired this
    // assertion could not fail.
    auto ports = r.ports();
    ports.set_agents_targeted = [&r](const std::string& id, int n) {
        r.targeted.emplace_back(id, n);
        return true;
    };
    auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB})}},
                             make_caller("u", true)),
                   ports, r.audit());
    REQUIRE(as_refusal(out));
    CHECK(r.targeted.empty());
    CHECK(as_refusal(out)->remediation.find("no execution record was created") !=
          std::string::npos);
}

namespace {
std::string execution_id_of(const std::string& audit_detail) {
    const auto at = audit_detail.find("execution_id=");
    REQUIRE(at != std::string::npos);
    const auto from = at + std::string("execution_id=").size();
    return audit_detail.substr(from, audit_detail.find(' ', from) - from);
}
} // namespace

// The production binding over a REAL tracker: the wedge is a property of refresh_counts and the
// reaper, so a fake tracker cannot show it closed.
TEST_CASE("execute: [pg] a dispatch that throws on the 2nd of 3 sends leaves a row that the one "
          "sent agent's answer completes",
          "[pg][instruction_execute][send_progress]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Rig r;
    r.defs["d"] = make_def("d");
    const Ports rig_ports = r.ports();

    StoreBindings b;
    b.execution_tracker = tracker.get();
    b.capability_registry = &r.caps;
    b.authorize = rig_ports.authorize;
    b.validators = std::make_shared<instr::ParamValidatorCache>();
    b.metrics = &r.metrics;
    int throw_on = 2;
    b.dispatch = [&throw_on](const std::string&, const std::string&,
                             const std::vector<std::string>& ids,
                             const std::string&,
                             const std::unordered_map<std::string, std::string>&,
                             const std::string&, const DispatchCaller&, const std::string&,
                             const std::string&) {
        return yuzu::test::dispatch_throwing_on_nth_send(ids, throw_on);
    };
    Ports ports = make_ports(b);
    ports.lookup_definition = rig_ports.lookup_definition; // InstructionStore is not under test
    ports.readmit = rig_ports.readmit;                     // the surface's post-write recheck (#7110)

    auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB, kC})}},
                             make_caller("u", true)),
                   ports, r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kDispatchFailed);
    REQUIRE(r.audits.size() == 2);
    const std::string id = execution_id_of(r.audits[1].detail);

    auto row = tracker->get_execution(id);
    REQUIRE(row.has_value());
    CHECK(row->agents_targeted == 1); // the one send accepted before the throw
    CHECK(row->status == "running");  // NOT cancelled: that agent holds the command
    CHECK(ref->remediation.find(id) != std::string::npos);

    // The sent agent answers: this is the result that could never close the row before.
    yuzu::server::AgentExecStatus st;
    st.agent_id = kA;
    st.status = "success";
    tracker->update_agent_status(id, st);
    tracker->refresh_counts(id);
    row = tracker->get_execution(id);
    REQUIRE(row.has_value());
    CHECK(row->agents_responded == 1);
    CHECK(row->status == "succeeded");
    CHECK(row->completed_at > 0);
}

TEST_CASE("execute: [pg] a dispatch that throws on the 1st send leaves the row running with no "
          "target count, for the reaper",
          "[pg][instruction_execute][send_progress]") {
    yuzu::test::ExecutionTrackerPg tracker;
    Rig r;
    r.defs["d"] = make_def("d");
    const Ports rig_ports = r.ports();
    StoreBindings b;
    b.execution_tracker = tracker.get();
    b.capability_registry = &r.caps;
    b.authorize = rig_ports.authorize;
    b.validators = std::make_shared<instr::ParamValidatorCache>();
    b.metrics = &r.metrics;
    b.dispatch = [](const std::string&, const std::string&, const std::vector<std::string>& ids,
                    const std::string&, const std::unordered_map<std::string, std::string>&,
                    const std::string&, const DispatchCaller&, const std::string&,
                    const std::string&) {
        return yuzu::test::dispatch_throwing_on_nth_send(ids, 1);
    };
    Ports ports = make_ports(b);
    ports.lookup_definition = rig_ports.lookup_definition;
    ports.readmit = rig_ports.readmit; // the surface's post-write recheck (#7110)

    auto out = run(r.request("d", json{{"agent_ids", json::array({kA, kB})}},
                             make_caller("u", true)),
                   ports, r.audit());
    REQUIRE(as_refusal(out));
    REQUIRE(r.audits.size() == 2);
    const std::string id = execution_id_of(r.audits[1].detail);
    const auto row = tracker->get_execution(id);
    REQUIRE(row.has_value());
    CHECK(row->agents_targeted == 0);
    CHECK(row->status == "running"); // not cancelled: the first send is indeterminate
    CHECK(r.audits[1].detail.find("agents_sent") == std::string::npos);

    // The row's whole recovery story is the stuck-execution reaper: no agent ever answered and
    // nothing was targeted, so once it is older than the reaper's window the sweep cancels it.
    // The reaper's candidate query reads the outbox schema too, so it is migrated into the SAME
    // database; the row is aged with the test-only UPDATE the tracker tests use.
    yuzu::server::pg::PgPool pool{{.conninfo = tracker.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    yuzu::server::CommandOutboxStore outbox{pool};
    REQUIRE(outbox.is_open());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto aged = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.executions SET dispatched_at = dispatched_at - $1 "
            "WHERE id = $2",
            std::vector<std::string>{"3600", id});
        REQUIRE(aged.status() == PGRES_COMMAND_OK);
    }
    const auto reaped = tracker->reap_stuck_running_executions();
    REQUIRE(reaped.has_value());
    CHECK(reaped->cancelled == 1);
    const auto after = tracker->get_execution(id);
    REQUIRE(after.has_value());
    CHECK(after->status == "cancelled");
}

TEST_CASE("send progress: instrument_sink is the identity outside a scope, counts inside one, and "
          "scopes nest",
          "[instruction_execute][send_progress]") {
    const auto make = [] {
        ConfinedDispatchSink s;
        s.send_to = [](const std::string& aid) { return aid != "down"; };
        s.send_to_all_unfiltered = [] { return 3; };
        return s;
    };
    {
        const auto plain = instrument_sink(make());
        CHECK(plain.send_to("a"));
        CHECK(plain.send_to_all_unfiltered() == 3);
        CHECK(SendProgressScope::current() == nullptr);
    }
    SendProgress outer;
    {
        const SendProgressScope outer_scope(outer);
        CHECK(SendProgressScope::current() == &outer);
        const auto counted = instrument_sink(make());
        CHECK(counted.send_to("a"));
        CHECK_FALSE(counted.send_to("down")); // an undelivered send is not counted
        CHECK(counted.send_to_all_unfiltered() == 3);
        CHECK(outer.sent == 4);
        SendProgress inner;
        {
            const SendProgressScope inner_scope(inner);
            CHECK(SendProgressScope::current() == &inner);
            CHECK(instrument_sink(make()).send_to("b"));
        }
        CHECK(inner.sent == 1);
        CHECK(SendProgressScope::current() == &outer); // restored
        CHECK(outer.sent == 4);
    }
    CHECK(SendProgressScope::current() == nullptr);
}

TEST_CASE("send progress: wire_and_dispatch_confined counts the sends it actually makes",
          "[instruction_execute][send_progress]") {
    Rig r;
    SendProgress progress;
    {
        const SendProgressScope scope(progress);
        // The production wire function over a real AgentRegistry: three delivered sends.
        auto out = r.real("testplug", "ping", {kA, kB, kC}, "", {}, "exec-x",
                          make_caller("u", true), "d", "per-device");
        CHECK(out.sent == 3);
    }
    CHECK(progress.sent == 3);
    // Outside the scope the same call still sends but is NOT counted: the scope's progress is
    // unchanged (this assertion fails if the instrumented sink outlives its scope).
    CHECK(r.real("testplug", "ping", {kA}, "", {}, "exec-y", make_caller("u", true), "d",
                 "per-device")
              .sent == 1);
    CHECK(progress.sent == 3);
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
    std::vector<std::string> target_ids; // the `target_id` column value of every audit row
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
                target_ids.push_back(id);
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
    // The gate runs at admission and again after the requested row (#7110): the same pair both times.
    REQUIRE(r.perm_calls.size() == 2);
    CHECK(r.perm_calls[0] == std::make_pair(std::string("Execution"), std::string("Execute")));
    CHECK(r.perm_calls[1] == r.perm_calls[0]);
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

TEST_CASE("REST execute: a definition id with a control byte is a 400 invalid_definition_id with ONE "
          "denied row and no store read; a normal id still runs",
          "[instruction_execute][rest][security]") {
    for (const auto& id :
         {std::string("d\0xyz", 5), std::string("d\x7f"), std::string("d\x1f")}) {
        INFO(id.size());
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        auto res = r.post(id, "{}");
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto j = json::parse(res->body);
        CHECK(j["error"]["reason"] == "invalid_definition_id");
        CHECK(j["error"]["retry_after_ms"].is_null());
        CHECK(r.core.lookups == 0);
        CHECK(r.core.calls.empty());
        REQUIRE(r.core.audits.size() == 1);
        CHECK(r.core.audits[0].result == "denied");
        CHECK(r.core.audits[0].detail.find("reason=invalid_definition_id") != std::string::npos);
        CHECK(r.core.audits[0].detail.find("correlation_id=" +
                                           j["error"]["correlation_id"].get<std::string>()) !=
              std::string::npos);
    }
    RouteRig ok;
    ok.core.defs["d"] = make_def("d");
    auto res = ok.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 200);
}

// sec p4-sg1: the row's `target_id` column used to carry the hostile id verbatim (the detail text
// was cleaned, the column was not), and sanitize_pg_text repairs only invalid UTF-8 and NUL.
TEST_CASE("REST execute: a hostile definition id never reaches the audit target_id with a control "
          "byte; a normal id is stored unchanged",
          "[instruction_execute][rest][security]") {
    const auto has_control = [](const std::string& v) {
        for (const char ch : v) {
            const auto b = static_cast<unsigned char>(ch);
            if (b < 0x20 || b == 0x7F)
                return true;
        }
        return false;
    };
    for (const auto& id : {std::string("d\r\nforged"), std::string("d\x1b[31m"),
                                 std::string("d\x7f"), std::string("d\0xyz", 5)}) {
        INFO(id.size());
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        auto res = r.post(id, "{}");
        REQUIRE(res);
        CHECK(res->status == 400);
        REQUIRE_FALSE(r.target_ids.empty());
        for (const auto& t : r.target_ids) {
            CHECK_FALSE(has_control(t));
            CHECK_FALSE(t.empty());
        }
    }
    // The pre-core refusals (unparseable body) write through the same lambda.
    {
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        auto res = r.post(std::string("d\r\nx"), "{not json");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(json::parse(res->body)["error"]["reason"] == "invalid_json");
        REQUIRE_FALSE(r.target_ids.empty());
        for (const auto& t : r.target_ids)
            CHECK_FALSE(has_control(t));
    }
    // Positive control: a normal id (with a character log_token would neutralise) is unchanged.
    RouteRig ok;
    ok.core.defs["my def=1,v"] = make_def("my def=1,v");
    auto res = ok.post("my def=1,v", "{}");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE_FALSE(ok.target_ids.empty());
    for (const auto& t : ok.target_ids)
        CHECK(t == "my def=1,v");
}

TEST_CASE("REST execute: a definition id that is not valid UTF-8 is a 400 invalid_definition_id "
          "with no retry hint, ONE denied row and no store read; a valid multibyte id is looked up",
          "[instruction_execute][rest][security]") {
    for (const auto& id : {std::string("d\xC0\x80"), std::string("d\xFF"), std::string("d\xE2\x82"),
                           std::string("d\xED\xA0\x80")}) {
        INFO(id.size());
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        auto res = r.post(id, "{}");
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto j = json::parse(res->body);
        CHECK(j["error"]["reason"] == "invalid_definition_id");
        CHECK(j["error"]["retry_after_ms"].is_null());
        CHECK(r.core.lookups == 0);
        CHECK(r.core.calls.empty());
        REQUIRE(r.core.audits.size() == 1);
        CHECK(r.core.audits[0].result == "denied");
        // The stored target_id is valid UTF-8 (the hostile bytes were folded by log_token).
        REQUIRE_FALSE(r.target_ids.empty());
        for (const auto& t : r.target_ids)
            CHECK_FALSE(definition_id_is_invalid_utf8(t));
    }
    RouteRig ok; // positive control: U+00E9 reaches the lookup and not_found comes from it
    auto res = ok.post("d\xC3\xA9", "{}");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(ok.core.lookups == 1);
}

// compliance p5-c3: log_token also folds C1 controls, U+2028 and U+2029, but step 0 lets them
// through (they are valid UTF-8, not control BYTES). The audit target_id must be folded like the
// detail token anyway, while the id itself stays valid and reaches the lookup.
TEST_CASE("REST execute: an id holding a C1 control, U+2028 or U+2029 is folded in the audit "
          "target_id but is NOT refused at step 0",
          "[instruction_execute][rest][security]") {
    // log_token folds ONE '_' per folded code point (not per byte), so the expected target_id is
    // exact: the audit subject and the `definition=` detail token are the same folded string.
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"d\xC2\x85x", "d_x"},     // U+0085
        {"d\xE2\x80\xA8x", "d_x"}, // U+2028
        {"d\xE2\x80\xA9x", "d_x"}, // U+2029
        {"d\xC2\x9F", "d_"},       // U+009F
    };
    for (const auto& [id, folded] : cases) {
        INFO(id.size());
        CHECK(definition_id_needs_audit_fold(id));
        CHECK_FALSE(definition_id_is_malformed(id)); // step 0 must not widen
        RouteRig r;                                  // no definitions: the lookup answers not_found
        auto res = r.post(id, "{}");
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(json::parse(res->body)["error"]["reason"] == "not_found");
        CHECK(r.core.lookups == 1); // it went to the lookup
        REQUIRE_FALSE(r.target_ids.empty());
        for (const auto& t : r.target_ids)
            CHECK(t == folded);
    }
    // Positive controls: a normal id and a valid multibyte id outside the folded set are not
    // folded (the predicate is false and target_id is the id itself).
    CHECK_FALSE(definition_id_needs_audit_fold("my def=1,v"));
    CHECK_FALSE(definition_id_needs_audit_fold("d\xC3\xA9"));       // U+00E9
    CHECK_FALSE(definition_id_needs_audit_fold("d\xE2\x80\xA7"));   // U+2027, one below U+2028
    CHECK_FALSE(definition_id_needs_audit_fold("d\xE2\x80\xAA"));   // U+202A, one above U+2029
    CHECK_FALSE(definition_id_needs_audit_fold("d\xC2\xA0"));       // U+00A0, one above U+009F
    RouteRig ok;
    ok.core.defs["d\xC3\xA9"] = make_def("d\xC3\xA9");
    auto res = ok.post("d\xC3\xA9", "{}");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE_FALSE(ok.target_ids.empty());
    for (const auto& t : ok.target_ids)
        CHECK(t == "d\xC3\xA9");
}

// The predicate decides whether the REST route folds the audit target_id; log_token decides what
// the detail token folds. They must agree on every well-formed code point in the region log_token
// folds (and its neighbours), so a future widening of log_token's fold set that forgets the
// predicate fails here instead of leaving an unfolded target_id next to a folded definition=.
TEST_CASE("definition_id_has_log_folded_codepoint agrees with log_token on C1, U+2028 and U+2029",
          "[instruction_execute][security]") {
    const auto utf8 = [](unsigned cp) {
        std::string o;
        if (cp < 0x800) {
            o.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            o.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            o.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            o.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            o.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        return o;
    };
    std::vector<unsigned> cps;
    for (unsigned cp = 0x80; cp <= 0x9F; ++cp)
        cps.push_back(cp);
    cps.push_back(0x2028);
    cps.push_back(0x2029);
    for (const unsigned cp : cps) {
        const std::string id = "d" + utf8(cp) + "x";
        INFO("U+" << std::hex << cp);
        REQUIRE_FALSE(definition_id_is_malformed(id)); // a valid id: only the fold decision differs
        CHECK(yuzu::log_token(id) != id);              // log_token folds it
        CHECK(definition_id_has_log_folded_codepoint(id) == (yuzu::log_token(id) != id));
    }
    // Neighbours log_token leaves alone: the predicate must stay false for exactly these.
    for (const unsigned cp : {0xA0u, 0x7FFu, 0x2027u, 0x202Au}) {
        const std::string id = "d" + utf8(cp) + "x";
        INFO("U+" << std::hex << cp);
        CHECK(yuzu::log_token(id) == id);
        CHECK(definition_id_has_log_folded_codepoint(id) == (yuzu::log_token(id) != id));
    }
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

namespace {
/// The `correlation_id=` token at the end of an audit detail (RouteRig appends " [id=...]").
std::string rest_row_cid(const std::string& detail_with_id_suffix) {
    std::string d = detail_with_id_suffix;
    if (const auto p = d.rfind(" [id="); p != std::string::npos)
        d.erase(p);
    return trailing_cid(d);
}
} // namespace

TEST_CASE("REST execute: a body-depth or unparseable-JSON refusal writes ONE denied row whose "
          "correlation id is the response's",
          "[instruction_execute][rest][audit][correlation]") {
    std::string deep;
    for (int i = 0; i < 200; ++i)
        deep += "[";
    const std::pair<std::string, std::string> cases[] = {{deep, "body_depth"},
                                                          {"{not json", "invalid_json"}};
    for (const auto& [body, reason] : cases) {
        INFO(reason);
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        auto res = r.post("d", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto j = json::parse(res->body);
        REQUIRE(r.core.audits.size() == 1);
        CHECK(r.core.audits[0].result == "denied");
        CHECK(r.core.audits[0].detail.find("reason=" + reason + " definition=d") !=
              std::string::npos);
        const std::string cid = j["error"]["correlation_id"].get<std::string>();
        CHECK_FALSE(cid.empty());
        CHECK(rest_row_cid(r.core.audits[0].detail) == cid);
        CHECK(res->get_header_value("X-Correlation-Id") == cid);
        CHECK(res->get_header_value("Sec-Audit-Failed").empty());
        CHECK(r.core.calls.empty());
    }
}

TEST_CASE("REST execute: a LOST body-refusal denied row sets Sec-Audit-Failed, the 400 stands",
          "[instruction_execute][rest][audit][correlation][security]") {
    RouteRig r;
    r.core.defs["d"] = make_def("d");
    r.core.audit_other_fails = true;
    auto res = r.post("d", "{not json");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(json::parse(res->body)["error"]["reason"] == "invalid_json");
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("REST execute: an unknown definition writes ONE denied row with the response's id",
          "[instruction_execute][rest][audit][correlation]") {
    RouteRig r;
    auto res = r.post("nope", "{}");
    REQUIRE(res);
    CHECK(res->status == 404);
    REQUIRE(r.core.audits.size() == 1);
    CHECK(r.core.audits[0].result == "denied");
    CHECK(rest_row_cid(r.core.audits[0].detail) ==
          json::parse(res->body)["error"]["correlation_id"].get<std::string>());
}

// Gate 8 pass 2 (sre-b2): the REST id is the raw path capture, kilobytes long, and used to land
// unclipped in `target_id` and the `definition=` detail of every row.
TEST_CASE("bounded_definition_id: a short id is untouched, a long one is cut on a code point "
          "boundary and marked",
          "[instruction_execute][audit]") {
    CHECK(bounded_definition_id("d") == "d");
    const std::string exact(kAuditDefinitionIdMax, 'a');
    CHECK(bounded_definition_id(exact) == exact);
    CHECK(bounded_definition_id(exact + "b") == exact + "...");
    // A 2-byte character that straddles the limit is dropped whole, never half kept.
    const std::string straddle = std::string(kAuditDefinitionIdMax - 1, 'a') + "\xC3\xA9" + "tail";
    CHECK(bounded_definition_id(straddle) == std::string(kAuditDefinitionIdMax - 1, 'a') + "...");
    // A 4-byte character that straddles it (3 of its 4 bytes inside) is dropped whole too.
    const std::string four = std::string(kAuditDefinitionIdMax - 3, 'a') + "\xF0\x9F\x98\x80" + "x";
    CHECK(bounded_definition_id(four) == std::string(kAuditDefinitionIdMax - 3, 'a') + "...");
    // A character that ends exactly on the limit is kept.
    const std::string fits = std::string(kAuditDefinitionIdMax - 2, 'a') + "\xC3\xA9" + "x";
    CHECK(bounded_definition_id(fits) == std::string(kAuditDefinitionIdMax - 2, 'a') + "\xC3\xA9...");
}

TEST_CASE("REST execute: a 4 KiB definition id writes bounded audit rows (denied, requested, success) "
          "yet is still looked up by the raw id",
          "[instruction_execute][rest][audit]") {
    const std::string long_id(4096, 'x');
    const auto id_of = [](const std::string& detail) {
        const auto at = detail.rfind("[id=");
        REQUIRE(at != std::string::npos);
        return detail.substr(at + 4, detail.size() - at - 5);
    };
    const auto bounded = [](const std::string& detail) {
        // The whole row (detail text + the fake's "[id=...]" suffix) stays small: nothing carries
        // the 4 KiB id.
        return detail.size() < 400 && detail.find(std::string(200, 'x')) == std::string::npos;
    };
    SECTION("an unknown definition (core denied row)") {
        RouteRig r;
        auto res = r.post(long_id, "{}");
        REQUIRE(res);
        CHECK(res->status == 404);
        REQUIRE(r.core.audits.size() == 1);
        CHECK(bounded(r.core.audits[0].detail));
        CHECK(id_of(r.core.audits[0].detail).size() == kAuditDefinitionIdMax + 3);
    }
    SECTION("a body refusal before the core (audit_pre_core_denial)") {
        RouteRig r;
        auto res = r.post(long_id, "{not json");
        REQUIRE(res);
        CHECK(res->status == 400);
        REQUIRE(r.core.audits.size() == 1);
        CHECK(bounded(r.core.audits[0].detail));
        CHECK(id_of(r.core.audits[0].detail).size() == kAuditDefinitionIdMax + 3);
    }
    SECTION("an existing definition with that id: looked up raw, rows bounded") {
        RouteRig r;
        r.core.defs[long_id] = make_def(long_id);
        auto res = r.post(long_id, "{}");
        REQUIRE(res);
        CHECK(res->status == 200); // found by the RAW id and dispatched
        REQUIRE(r.core.audits.size() == 2);
        for (const auto& a : r.core.audits) {
            INFO(a.result);
            CHECK(bounded(a.detail));
        }
        CHECK(r.core.calls.size() == 1);
    }
}

TEST_CASE("REST execute: requested and success share the response's correlation id; an error body "
          "after the requested row joins it",
          "[instruction_execute][rest][audit][correlation]") {
    {
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        auto res = r.post("d", "{}");
        REQUIRE(res);
        CHECK(res->status == 200);
        const std::string cid = res->get_header_value("X-Correlation-Id");
        CHECK_FALSE(cid.empty());
        REQUIRE(r.core.audits.size() == 2);
        CHECK(rest_row_cid(r.core.audits[0].detail) == cid);
        CHECK(rest_row_cid(r.core.audits[1].detail) == cid);
    }
    {
        // A throwing dispatch: `requested` is already written, the error body must be the
        // same id so the orphan row can be paired.
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        r.core.dispatch_throws = true;
        auto res = r.post("d", "{}");
        REQUIRE(res);
        CHECK(res->status == 500);
        const std::string cid = json::parse(res->body)["error"]["correlation_id"].get<std::string>();
        REQUIRE(r.core.audits.size() == 2);
        CHECK(r.core.audits[0].result == "requested");
        CHECK(rest_row_cid(r.core.audits[0].detail) == cid);
        CHECK(rest_row_cid(r.core.audits[1].detail) == cid);
    }
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

// qe-b3: a core refusal owes a best-effort row; when it is lost the REST route adds
// Sec-Audit-Failed to the unchanged refusal, and a healthy sink adds nothing.
TEST_CASE("REST execute: a LOST refusal row sets Sec-Audit-Failed on core refusals, the status "
          "stands",
          "[instruction_execute][rest][audit][security]") {
    struct Case {
        const char* what;
        std::function<void(RouteRig&)> arrange;
        std::string body;
        int status;
        const char* reason;
    };
    const Case cases[] = {
        {"forbidden", [](RouteRig& r) { r.core.denied_securables.insert("Infrastructure"); }, "{}",
         403, "forbidden"},
        {"destructive untargeted", [](RouteRig& r) { r.core.defs["d"].action = "wipe"; }, "{}", 400,
         "destructive_untargeted"},
        {"approval cap reached",
         [](RouteRig& r) {
             r.core.defs["d"].approval_mode = "always";
             r.core.pending_for = kSubmitterPendingCap;
         },
         "{}", 429, "approval_cap_reached"},
        {"approval queue full",
         [](RouteRig& r) {
             r.core.defs["d"].approval_mode = "always";
             r.core.approval_queue_full = true;
         },
         "{}", 503, "approval_queue_full"},
    };
    for (const bool lose_rows : {false, true}) {
        for (const auto& c : cases) {
            INFO(c.what << " lose_rows=" << lose_rows);
            RouteRig r;
            r.core.defs["d"] = make_def("d");
            c.arrange(r);
            r.core.audit_other_fails = lose_rows;
            // The caller of the "forbidden" case must not be an administrator.
            if (std::string(c.what) == "forbidden")
                r.caller = make_caller("alice", false);
            auto res = r.post("d", c.body);
            REQUIRE(res);
            CHECK(res->status == c.status);
            CHECK(json::parse(res->body)["error"]["reason"] == c.reason);
            CHECK(res->get_header_value("Sec-Audit-Failed") == (lose_rows ? "true" : ""));
        }
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
            // cb-c1: the row the throw left running is a TYPED field (as in POST /api/v1/commands);
            // no send was accepted, so there is no agents_sent.
            CHECK(err["execution_id"] == "exec-1");
            CHECK_FALSE(err.contains("agents_sent"));
        }
    }
}

TEST_CASE("REST execute: a dispatch that throws after confirmed sends carries execution_id and "
          "agents_sent as typed error fields, and none for other refusals",
          "[instruction_execute][rest][send_progress]") {
    SECTION("confirmed sends") {
        RouteRig r;
        r.core.defs["d"] = make_def("d");
        r.core.custom_dispatch = [](const std::vector<std::string>& ids) {
            return yuzu::test::dispatch_throwing_on_nth_send(ids, 3);
        };
        auto res = r.post("d", R"({"agent_ids":["agent-A","agent-B","agent-C"]})");
        REQUIRE(res);
        CHECK(res->status == 500);
        const auto err = json::parse(res->body)["error"];
        CHECK(err["reason"] == "dispatch_exception");
        CHECK(err["execution_id"] == "exec-1");
        CHECK(err["agents_sent"] == 2);
        CHECK(err["retry_after_ms"].is_null());
    }
    SECTION("no execution record: execution_id is the empty string, still present") {
        RouteRig r([](Rig& c) { c.ledger_wired = false; });
        r.core.defs["d"] = make_def("d");
        r.core.dispatch_throws = true;
        auto res = r.post("d", "{}");
        REQUIRE(res);
        const auto err = json::parse(res->body)["error"];
        REQUIRE(err.contains("execution_id"));
        CHECK(err["execution_id"] == "");
    }
    SECTION("an unrelated refusal carries neither field") {
        RouteRig r;
        auto res = r.post("nope", "{}");
        REQUIRE(res);
        const auto err = json::parse(res->body)["error"];
        CHECK_FALSE(err.contains("execution_id"));
        CHECK_FALSE(err.contains("agents_sent"));
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

// ---------------------------------------------------------------------------------------------
// #7110: the post-`requested`-row recheck (Ports::readmit) and #7114: the dispatch denial.
// ---------------------------------------------------------------------------------------------

TEST_CASE("instruction execute: a readmit that withdraws (nullopt, or throws = fail closed) inside the "
          "execution-row write dispatches nothing, cancels the row and writes failure permission_revoked",
          "[instruction_execute][security]") {
    // Each row flips the one Rig flag the readmit port reads; both inside the execution-row write,
    // the core's last own write before the dispatch.
    const std::vector<std::pair<const char*, bool Rig::*>> withdrawals = {
        {"readmit nullopt", &Rig::readmit_withdrawn},
        {"readmit throws reads as withdrawn (fail closed)", &Rig::readmit_throws},
        // The authorizer re-runs for the fresh caller after the rows: a throw there must close them
        // too, not unwind past a `requested` row and a running execution with no outcome.
        {"the post-write authorizer throws reads as withdrawn (fail closed)", &Rig::authorize_throws},
    };
    for (const auto& [name, flag] : withdrawals) {
        DYNAMIC_SECTION(name) {
            Rig r;
            r.defs["d"] = make_def("d");
            r.on_create = [&] { r.*flag = true; }; // withdrawn INSIDE the row write
            auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
            const auto* ref = as_refusal(out);
            REQUIRE(ref);
            CHECK(ref->kind == RefusalKind::kPermissionRevoked);
            CHECK(ref->reason == "permission_revoked");
            CHECK_FALSE(ref->denial);
            CHECK_FALSE(ref->retry_after_ms);
            CHECK(r.readmits == 1);
            CHECK(r.calls.empty());
            CHECK(r.rows.size() == 1); // the row exists ...
            CHECK(r.cancelled == std::vector<std::string>{"exec-1"}); // ... and is closed, not left running
            REQUIRE(r.audits.size() == 2);
            CHECK(r.audits[0].result == "requested");
            CHECK(r.audits[1].result == "failure");
            CHECK(r.audits[1].detail.find("reason=permission_revoked") != std::string::npos);
            CHECK(r.audits[1].detail.find("execution_id=exec-1") != std::string::npos);
        }
    }
}

TEST_CASE("instruction execute: an unset readmit port is Misconfigured (fail closed)",
          "[instruction_execute][security]") {
    Rig r;
    r.readmit_unwired = true;
    r.defs["d"] = make_def("d");
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kMisconfigured);
    CHECK(ref->reason == "readmit_unconfigured");
    CHECK(r.calls.empty());
    // Refused BEFORE the requested row: nothing is recorded for a request that cannot be gated.
    CHECK(std::none_of(r.audits.begin(), r.audits.end(),
                       [](const auto& a) { return a.result == "requested"; }));
}

TEST_CASE("instruction execute: the re-derived caller is the one dispatched",
          "[instruction_execute][security][confinement]") {
    Rig r;
    r.defs["d"] = make_def("d");
    // The caller the request was built with sees everything; the one re-derived after the writes
    // sees only agent-B (its visible set shrank while the execution row was written).
    r.on_create = [&] { r.readmit_caller = make_caller("u", true, std::unordered_set<std::string>{kB}); };
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    REQUIRE(as_dispatched(out));
    REQUIRE(r.calls.size() == 1);
    CHECK(r.calls[0].exec_visible == authz::VisibleSet{std::unordered_set<std::string>{kB}});
}

TEST_CASE("instruction execute: the dry run repeats for the re-derived caller",
          "[instruction_execute][security]") {
    Rig r;
    r.defs["d"] = make_def("d", "gated"); // AdminOrApproval: refuses a non-admin
    // Admin at the first decision; demoted by the time the execution row is written.
    r.on_create = [&] { r.readmit_caller = make_caller("u", false); };
    auto out = run(r.request("d", json::object(), make_caller("u", true)), r.ports(), r.audit());
    const auto* ref = as_refusal(out);
    REQUIRE(ref);
    CHECK(ref->kind == RefusalKind::kDispatchDenied);
    REQUIRE(ref->denial);
    CHECK(r.calls.empty());
    CHECK(r.cancelled == std::vector<std::string>{"exec-1"}); // the execution row is closed
    REQUIRE(r.audits.size() == 2);
    CHECK(r.audits[0].result == "requested");
    CHECK(r.audits[1].result == "failure"); // the requested row exists: a failure, not a denied
}

TEST_CASE("instruction execute: a dispatch denial on the outcome is zero-reach dispatch_denied (403)",
          "[instruction_execute][rest][security]") {
    RouteRig r([](Rig& core) {
        core.custom_dispatch = [](const std::vector<std::string>&) {
            return ConfinedDispatchOutcome{
                .command_id = "cmd-x",
                .denied = DispatchDenial{DispatchDenialReason::ApprovalRequired, "Infrastructure",
                                         authz::Operation::Write}};
        };
    });
    r.core.defs["d"] = make_def("d");
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "dispatch_denied");
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(j["error"]["message"].get<std::string>().find("approval_required") != std::string::npos);
}

TEST_CASE("render: kPermissionRevoked renders REST 403 with reason permission_revoked and no "
          "retry_after; MCP renders kPermissionDenied (no denial dereferenced)",
          "[instruction_execute][rest][security]") {
    // REST, end to end: the route's own permission withdrawn inside the execution-row write.
    RouteRig r;
    r.core.defs["d"] = make_def("d");
    r.core.on_create = [&] { r.perm_grant = false; };
    auto res = r.post("d", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["reason"] == "permission_revoked");
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(r.core.calls.empty());
    CHECK(r.core.cancelled == std::vector<std::string>{"exec-1"}); // the row it created is closed
    REQUIRE_FALSE(r.core.audits.empty());
    CHECK(r.core.audits.back().result == "failure");
    CHECK(r.core.audits.back().detail.find("reason=permission_revoked") != std::string::npos);

    // MCP: the same refusal, with NO denial engaged.
    Refusal ref;
    ref.kind = RefusalKind::kPermissionRevoked;
    ref.reason = "permission_revoked";
    ref.message = "permission revoked after the request was recorded";
    REQUIRE_FALSE(ref.denial);
    const auto rendered =
        yuzu::server::mcp::instruction_definition::render_refusal(ref, false, "cid");
    CHECK(rendered.is_error);
    CHECK(rendered.code == yuzu::server::mcp::kPermissionDenied);
    const auto d = json::parse(rendered.data_json);
    CHECK(d["retry_after_ms"].is_null());
    CHECK(d["reason"] == "permission_revoked");
}

TEST_CASE("REST execute: the caller is re-derived after the row", "[instruction_execute][rest][security]") {
    RouteRig r;
    r.core.real_dispatch = true;
    r.core.defs["d"] = make_def("d");
    r.caller = make_caller("op", true);
    // The visible set shrinks to agent-B while the execution row is written.
    r.core.on_create = [&] { r.caller = make_caller("op", true, std::unordered_set<std::string>{kB}); };
    auto res = r.post("d", R"({"agent_ids":["agent-A","agent-B"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(r.core.drain() == std::vector<std::pair<std::string, std::string>>{{kB, "testplug.ping"}});
}
