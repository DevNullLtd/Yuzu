#pragma once

// Shared fakes for the instruction-definition execute tests (test_instruction_execute.cpp for the
// pipeline + REST twin, test_mcp_server.cpp for the MCP twin): a Ports rig with NO Postgres
// (every store is a std::function seam), a real CommandCapabilityRegistry over a test catalogue,
// and a real AgentRegistry + wire_and_dispatch_confined so confinement cases assert the exact
// recipients. See test_instruction_execute.cpp's banner for what this does not prove.

#include "agent_registry.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_scope_ladder.hpp"
#include "dispatch_target_shape.hpp"
#include "instruction_execute.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::test::instr_exec {

using namespace yuzu::server;
using namespace yuzu::server::instruction_execute;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::DispatchDenial;
using yuzu::server::detail::DispatchDenialReason;
using yuzu::server::detail::EventBus;
using json = nlohmann::json;

inline constexpr CommandCapability row(std::string_view plugin, std::string_view action, DispatchClass dc,
                                Mutability mu, std::string_view securable,
                                authz::Operation op, ExecuteGate gate) {
    return CommandCapability{.plugin = plugin,
                             .action = action,
                             .dispatch_class = dc,
                             .mutability = mu,
                             .securable = securable,
                             .operation = op,
                             .risk_tier = authz::RiskTier::Low,
                             .system_reserved = false,
                             .execute_gate = gate};
}

// Test catalogue. "testplug" is NOT a production plugin; every row exists for one rule below.
inline constexpr std::array<CommandCapability, 5> kFixture{{
    row("testplug", "ping", DispatchClass::ReadOnly, Mutability::None, "Infrastructure",
        authz::Operation::Read, ExecuteGate::None),
    row("testplug", "wipe", DispatchClass::Destructive, Mutability::Irreversible, "Infrastructure",
        authz::Operation::Delete, ExecuteGate::None),
    row("testplug", "gated", DispatchClass::Mutating, Mutability::Reversible, "Infrastructure",
        authz::Operation::Write, ExecuteGate::AdminOrApproval),
    row("testplug", "forensic", DispatchClass::ReadOnly, Mutability::None, "Forensics",
        authz::Operation::Read, ExecuteGate::None),
    // The quarantine control plugin is protective: never os_gate_unreadable / plugin_not_found.
    row("quarantine", "status", DispatchClass::ReadOnly, Mutability::None, "Security",
        authz::Operation::Read, ExecuteGate::None),
}};

inline constexpr const char* kLevelSchema =
    R"({"type":"object","properties":{"level":{"type":"string","enum":["info","debug"]}},"required":["level"]})";

inline constexpr const char* kA = "agent-A";
inline constexpr const char* kB = "agent-B";
inline constexpr const char* kC = "agent-C";

inline InstructionDefinition make_def(std::string id, std::string action = "ping",
                               std::string mode = "auto") {
    InstructionDefinition d;
    d.id = std::move(id);
    d.plugin = "testplug";
    d.action = std::move(action);
    d.approval_mode = std::move(mode);
    d.concurrency_mode = "per-device";
    return d;
}

inline DispatchCaller make_caller(std::string who, bool admin, authz::VisibleSet vis = std::nullopt) {
    DispatchCaller c;
    c.principal = std::move(who);
    c.principal_role = admin ? "admin" : "user";
    c.principal_is_admin = admin;
    c.exec_visible = std::move(vis);
    return c;
}

struct DispatchCall {
    std::string plugin, action, scope, execution_id, definition_id, concurrency_mode;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
    std::string principal;
    authz::VisibleSet exec_visible;
    ApprovalProvenance provenance{ApprovalProvenance::None};
};

struct Rig {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    CommandCapabilityRegistry caps{std::span<const CommandCapability>(kFixture)};
    instr::ParamValidatorCache validators;

    std::map<std::string, InstructionDefinition> defs;
    bool store_error{false};
    bool store_unwired{false};

    bool approvals_wired{true};
    bool approval_fails{false};
    int pending_for{0};
    /// When set, `pending_count_for(user)` is `pending_for` plus the approvals THIS rig has
    /// accepted for that user, so a loop of real submits walks into the per-principal cap and
    /// another principal's count stays independent (the production counter is per submitter).
    bool pending_counts_submitted{false};
    /// 0 = readable; 1 = the counter reports it could not be read (nullopt); 2 = it throws.
    int pending_count_fault{0};
    struct ApprovalCall {
        std::string def, user, scope, plugin, action;
    };
    std::vector<ApprovalCall> approvals;

    std::optional<std::vector<std::string>> visible_agents{std::vector<std::string>{}};

    bool ledger_wired{true};
    bool create_fails{false};
    std::vector<ExecutionRow> rows;
    std::vector<std::string> cancelled;
    std::vector<std::pair<std::string, int>> targeted;
    std::vector<std::string> refreshed;
    bool set_targeted_ok{true};

    std::vector<DispatchCall> calls;
    bool real_dispatch{false};
    bool dispatch_throws{false};
    bool dispatch_throws_nonstd{false}; // throws an int, not a std::exception
    bool create_throws{false};          // create_execution throws a std::exception
    bool create_throws_nonstd{false};   // ... or an int
    ConfinedDispatchOutcome stub_outcome{.sent = 1, .command_id = "cmd-1"};
    std::int64_t seq{0};

    std::optional<DispatchDenial> force_denial;
    std::set<std::string> denied_securables; // has_permission() answers false for these
    bool authorize_unwired{false};
    bool classify_unwired{false};

    struct AuditRow {
        std::string result, detail;
    };
    std::vector<AuditRow> audits;
    bool audit_requested_fails{false};
    bool audit_other_fails{false};
    bool audit_throws{false};

    Rig() {
        for (const char* id : {kA, kB, kC}) {
            ::yuzu::agent::v1::AgentInfo info;
            info.set_agent_id(id);
            info.set_hostname(std::string(id) + ".local");
            (void)registry.register_agent(info);
            REQUIRE(registry.set_gateway_route(
                id, /*session_id=*/{}, "test-gateway",
                {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
        }
    }

    bool has_permission(std::string_view, std::string_view securable, authz::Operation) const {
        return !denied_securables.contains(std::string(securable));
    }

    std::vector<std::pair<std::string, std::string>> drain() {
        std::vector<std::pair<std::string, std::string>> out;
        for (auto& p : registry.drain_gateway_pending())
            out.emplace_back(p.agent_id, p.cmd.plugin() + "." + p.cmd.action());
        return out;
    }

    ConfinedDispatchOutcome real(const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>& ids, const std::string& scope,
                                 const std::unordered_map<std::string, std::string>& params,
                                 const std::string& execution_id, const DispatchCaller& caller,
                                 const std::string& def_id, const std::string& mode) {
        const std::string command_id = plugin + "-cmd-" + std::to_string(++seq);
        auto decision = yuzu::server::detail::classify_and_authorize_dispatch(
            caps, caller, plugin, action,
            [this](std::string_view p, std::string_view s, authz::Operation o) {
                return has_permission(p, s, o);
            });
        if (!decision)
            return ConfinedDispatchOutcome{.command_id = command_id};
        const auto arm = classify_dispatch_arm(!ids.empty(), scope);
        auto classified = yuzu::server::detail::finalize_classified_command(
            *decision, yuzu::server::detail::KillSwitchFn{}, plugin, action, command_id, params, {}, 0, 0,
            std::string(dispatch_arm_label(arm)), execution_id);
        if (!classified)
            return ConfinedDispatchOutcome{.command_id = command_id};
        const auto gate = ContainmentGate::enforcing(/*fail_closed_in=*/false, {});
        auto noop = [](const std::string&, const std::string&, const std::string&,
                       const std::string&) {};
        // execution_tracker == nullptr: no ADR-1007 claim is taken here (PG-only); def_id and
        // mode are passed through exactly as the production closure does.
        return wire_and_dispatch_confined(registry, nullptr, nullptr, nullptr, nullptr, nullptr,
                                          noop, noop, command_id, execution_id,
                                          caller.principal_role, ids, scope, caller.exec_visible,
                                          /*broadcast_on_none=*/false, gate, *classified, def_id,
                                          mode);
    }

    Ports ports() {
        Ports p;
        if (!store_unwired) {
            p.lookup_definition = [this](const std::string& id) -> DefinitionLookup {
                if (store_error)
                    return std::unexpected(std::string("db down"));
                if (auto it = defs.find(id); it != defs.end())
                    return std::optional<InstructionDefinition>(it->second);
                return std::optional<InstructionDefinition>{};
            };
        }
        p.validators = &validators;
        if (!classify_unwired) {
            p.classify = [this](std::string_view pl, std::string_view ac) {
                return caps.classify(pl, ac);
            };
        }
        if (!authorize_unwired) {
            p.authorize = [this](const DispatchCaller& caller, std::string_view pl,
                                 std::string_view ac)
                -> std::expected<CommandCapability, DispatchDenial> {
                if (force_denial)
                    return std::unexpected(*force_denial);
                return yuzu::server::detail::classify_and_authorize_dispatch(
                    caps, caller, pl, ac,
                    [this](std::string_view pr, std::string_view s, authz::Operation o) {
                        return has_permission(pr, s, o);
                    });
            };
        }
        if (approvals_wired) {
            p.submit_approval = [this](const std::string& d, const std::string& u,
                                       const std::string& s, const std::string& pl,
                                       const std::string& ac) -> std::expected<std::string, std::string> {
                if (approval_fails)
                    return std::unexpected(std::string("queue full"));
                approvals.push_back({d, u, s, pl, ac});
                return std::string("appr-") + std::to_string(approvals.size());
            };
            p.pending_count_for = [this](const std::string& user) -> std::optional<int> {
                if (pending_count_fault == 1)
                    return std::nullopt;
                if (pending_count_fault == 2)
                    throw std::runtime_error("count boom");
                int n = pending_for;
                if (pending_counts_submitted)
                    for (const auto& a : approvals)
                        if (a.user == user)
                            ++n;
                return n;
            };
        }
        p.visible_agents = [this](const std::string&) { return visible_agents; };
        if (ledger_wired) {
            p.create_execution = [this](const ExecutionRow& r) -> std::optional<std::string> {
                if (create_throws)
                    throw std::runtime_error("create boom");
                if (create_throws_nonstd)
                    throw 42; // NOLINT(hicpp-exception-baseclass): a non-std throw is the point
                if (create_fails)
                    return std::nullopt;
                rows.push_back(r);
                return std::string("exec-") + std::to_string(rows.size());
            };
            p.mark_cancelled = [this](const std::string& id, const std::string&) {
                cancelled.push_back(id);
                return true;
            };
            p.set_agents_targeted = [this](const std::string& id, int n) {
                targeted.emplace_back(id, n);
                return set_targeted_ok;
            };
            p.refresh_counts = [this](const std::string& id) { refreshed.push_back(id); };
        }
        p.dispatch = [this](const std::string& pl, const std::string& ac,
                            const std::vector<std::string>& ids, const std::string& sc,
                            const std::unordered_map<std::string, std::string>& pa,
                            const std::string& ex, const DispatchCaller& caller,
                            const std::string& def_id, const std::string& mode) {
            DispatchCall c;
            c.plugin = pl;
            c.action = ac;
            c.agent_ids = ids;
            c.scope = sc;
            c.params = pa;
            c.execution_id = ex;
            c.definition_id = def_id;
            c.concurrency_mode = mode;
            c.principal = caller.principal;
            c.exec_visible = caller.exec_visible;
            c.provenance = caller.approval_provenance;
            calls.push_back(c);
            if (dispatch_throws)
                throw std::runtime_error("boom");
            if (dispatch_throws_nonstd)
                throw 42; // NOLINT: a non-std throw is the point
            if (real_dispatch)
                return real(pl, ac, ids, sc, pa, ex, caller, def_id, mode);
            return stub_outcome;
        };
        p.metrics = &metrics;
        return p;
    }

    AuditHook audit() {
        return [this](std::string_view result, const std::string& detail_text) -> bool {
            if (audit_throws)
                throw std::runtime_error("audit boom");
            audits.push_back({std::string(result), detail_text});
            if (result == "requested")
                return !audit_requested_fails;
            return !audit_other_fails;
        };
    }

    Request request(const std::string& def_id, json body, DispatchCaller caller,
                    Surface s = Surface::kRest) {
        Request r;
        r.surface = s;
        r.definition_id = def_id;
        r.body = std::move(body);
        r.caller = std::move(caller);
        return r;
    }

    std::uint64_t counter(const std::string& name, const yuzu::Labels& l) {
        return metrics.counter(name, l).value();
    }
};

inline const Refusal* as_refusal(const Outcome& o) { return std::get_if<Refusal>(&o.result); }
inline const PendingApproval* as_pending(const Outcome& o) { return std::get_if<PendingApproval>(&o.result); }
inline const Dispatched* as_dispatched(const Outcome& o) { return std::get_if<Dispatched>(&o.result); }
inline const ZeroReach* as_zero(const Outcome& o) { return std::get_if<ZeroReach>(&o.result); }


} // namespace yuzu::test::instr_exec
