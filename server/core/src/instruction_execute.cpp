#include "instruction_execute.hpp"

#include "dispatch_denial_text.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_target_shape.hpp"
#include "sensitive_instruction_params.hpp"

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>
#include <yuzu/protective_actions.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <format>

namespace yuzu::server::instruction_execute {

namespace {

constexpr int kRetryAfterMs = 5000;

/// A kMisconfigured, kClassifierUnavailable or kApprovalUnavailable refusal is a SERVER defect (a
/// required port was never wired at boot): it does not clear by itself, so it carries NO retry
/// hint (`retry_after_ms` stays null) and says so.
constexpr std::string_view kMisconfiguredRemediation =
    "this is a server configuration defect and retrying will not help; report it to the server "
    "operator";

/// An audit hook that throws (bad_alloc class) must not turn a refusal into a 500 or, worse,
/// skip the fail-closed gate: a throw reads as "did not persist".
bool safe_audit(const AuditHook& hook, std::string_view result, const std::string& detail) noexcept {
    if (!hook)
        return true; // audit-off mode (unit harness); production always wires it
    try {
        return hook(result, detail);
    } catch (...) {
        return false;
    }
}

/// Observability must never fail a request.
void bump(const Ports& ports, const char* family, yuzu::Labels labels) noexcept {
    if (!ports.metrics)
        return;
    try {
        ports.metrics->counter(family, labels).increment();
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

struct Ctx {
    const Request& rq;
    const Ports& ports;
    const AuditHook& hook;
    const EventEmitHook& emit;
    bool audit_dropped{false};

    void audit(std::string_view result, const std::string& detail) {
        if (!safe_audit(hook, result, detail))
            audit_dropped = true;
    }
    std::string route() const { return std::string(route_label(rq.surface)); }
};

Refusal make_refusal(RefusalKind kind, std::string reason, std::string message,
                     std::string remediation = {}, std::optional<int> retry = std::nullopt) {
    Refusal r;
    r.kind = kind;
    r.reason = std::move(reason);
    r.message = std::move(message);
    r.remediation = std::move(remediation);
    r.retry_after_ms = retry;
    return r;
}

PrepareOutcome refuse(Ctx& c, Refusal r) {
    return PrepareOutcome{std::move(r), c.audit_dropped};
}

std::string ident_pair(const InstructionDefinition& d) {
    return ::yuzu::log_token(d.plugin) + ":" + ::yuzu::log_token(d.action);
}

} // namespace

bool definition_needs_approval(std::string_view approval_mode, bool caller_is_admin) noexcept {
    if (approval_mode == "auto")
        return false;
    if (approval_mode == "always")
        return true;
    if (approval_mode == "role-gated")
        return !caller_is_admin;
    // Unknown (or empty) mode: fail closed. A typo must not silently open the gate.
    return true;
}

PrepareOutcome prepare(const Request& rq, const Ports& ports, const AuditHook& audit,
                       const EventEmitHook& emit) {
    Ctx c{rq, ports, audit, emit};

    // 1. Definition lookup. A store fault is not "no such definition".
    if (!ports.lookup_definition) {
        return refuse(c, make_refusal(RefusalKind::kStoreUnavailable, "store_unavailable",
                                      "instruction store not available",
                                      "retry shortly; the definition store is unavailable",
                                      kRetryAfterMs));
    }
    auto looked_up = ports.lookup_definition(rq.definition_id);
    if (!looked_up) {
        spdlog::warn("instruction execute: definition lookup failed for '{}': {}",
                     ::yuzu::log_token(rq.definition_id), looked_up.error());
        return refuse(c, make_refusal(RefusalKind::kStoreUnavailable, "store_unavailable",
                                      "instruction store not available",
                                      "retry shortly; the definition store is unavailable",
                                      kRetryAfterMs));
    }
    if (!*looked_up) {
        return refuse(c, make_refusal(RefusalKind::kNotFound, "not_found",
                                      "instruction definition not found",
                                      "list definitions and re-call with a valid definition id"));
    }
    InstructionDefinition def = std::move(**looked_up);
    const std::string def_token = ::yuzu::log_token(rq.definition_id);

    // 2. The shared chokepoint's dry run for the definition's own (plugin, action), BEFORE any
    //    body work: a caller who may not run this pair learns nothing about its parameters, and
    //    the 403-before-400 order of POST /api/command is preserved for destructive pairs.
    if (!ports.authorize) {
        return refuse(c, make_refusal(RefusalKind::kMisconfigured, "authorizer_unconfigured",
                                      "dispatch authorizer not configured",
                                      std::string(kMisconfiguredRemediation)));
    }
    if (auto decision = ports.authorize(rq.caller, def.plugin, def.action); !decision) {
        const auto& denial = decision.error();
        const std::string reason(detail::to_string(denial.reason));
        spdlog::warn("dispatch denied: {} reason={} securable={} caller={}", ident_pair(def),
                     reason, denial.securable.empty() ? "(none)" : denial.securable,
                     rq.caller.principal.empty() ? "(anonymous)"
                                                 : ::yuzu::log_token(rq.caller.principal));
        bump(ports, "yuzu_server_dispatch_denied_total", {{"reason", reason}});
        c.audit("denied", "reason=" + reason + " definition=" + def_token);
        Refusal r = make_refusal(RefusalKind::kDispatchDenied, reason, {});
        r.denial = denial;
        r.plugin = def.plugin;
        r.action = def.action;
        return refuse(c, std::move(r));
    }

    // 3. Body shape. `check_targeting_shape` requires an OBJECT: nlohmann's contains() is false
    //    for an array or scalar, so an array body would otherwise read as "named no target" and
    //    broadcast to the whole fleet.
    if (!rq.body.is_object()) {
        bump(ports, "yuzu_server_dispatch_target_rejected_total",
             {{"route", c.route()}, {"reason", std::string(kReasonBodyType)}});
        c.audit("denied", "reason=" + std::string(kReasonBodyType) + " definition=" + def_token);
        return refuse(c, make_refusal(RefusalKind::kBadRequest, std::string(kReasonBodyType),
                                      "request body must be a JSON object"));
    }
    if (auto bv = check_targeting_shape(rq.body)) {
        bump(ports, "yuzu_server_dispatch_target_rejected_total",
             {{"route", c.route()}, {"reason", bv->reason}});
        c.audit("denied", std::string("reason=") + bv->reason + " definition=" + def_token);
        return refuse(c, make_refusal(RefusalKind::kBadRequest, bv->reason, bv->message,
                                      "correct the targeting arguments and re-call; nothing was "
                                      "dispatched and no approval ticket was created"));
    }

    Plan plan;
    plan.def = def;
    for (const auto& a : rq.body.value("agent_ids", nlohmann::json::array()))
        plan.agent_ids.push_back(a.get<std::string>()); // shape-checked above: strings only
    if (rq.body.contains("scope") && rq.body["scope"].is_string())
        plan.scope = rq.body["scope"].get<std::string>();
    if (rq.body.contains("params") && rq.body["params"].is_object()) {
        for (auto& [k, v] : rq.body["params"].items())
            plan.params[k] = v.is_string() ? v.get<std::string>() : v.dump();
    }

    // 4. Stored parameter_schema, strict. BEFORE the approval step so a refused call never queues
    //    an approval (a ticket does not bind the params), creates an execution row or dispatches.
    {
        const std::string pr = c.route();
        const auto count_reject = [&](const char* reason) {
            bump(ports, "yuzu_server_instruction_param_rejected_total",
                 {{"route", pr}, {"reason", reason}});
        };
        if (!ports.validators) {
            return refuse(c, make_refusal(RefusalKind::kMisconfigured, "validators_unconfigured",
                                          "parameter validators not configured",
                                          std::string(kMisconfiguredRemediation)));
        }
        auto validator = ports.validators->get(def.id, def.parameter_schema);
        if (!validator) {
            // A stored schema that cannot be prepared: FAIL CLOSED, never "no validation".
            spdlog::warn("instruction '{}' has an invalid stored parameter_schema; execute refused "
                         "until it is replaced: {}",
                         def_token,
                         validator.error().empty() ? std::string("(no detail)")
                                                   : validator.error().front());
            count_reject("schema_invalid");
            c.audit("failure", "reason=param_schema_invalid definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kSchemaInvalid, "param_schema_invalid",
                                          "stored parameter schema for this instruction is invalid",
                                          "An administrator must export the definition, delete it "
                                          "and import it again with a corrected parameter_schema "
                                          "(signed, unless the server allows unsigned "
                                          "definitions)."));
        }
        if (!(*validator)->absent()) {
            // `params` omitted and `params: null` both mean no params.
            static const nlohmann::json kNoParams = nullptr;
            const nlohmann::json& raw = rq.body.contains("params") ? rq.body["params"] : kNoParams;
            if (auto violation = (*validator)->check(raw)) {
                const bool root = violation->path.empty();
                count_reject(!raw.is_null() && !raw.is_object() ? "shape" : "violation");
                c.audit("denied", "reason=param_schema path=" +
                                      (root ? std::string("(root)")
                                            : ::yuzu::log_token(violation->path)) +
                                      " definition=" + def_token);
                return refuse(c, make_refusal(RefusalKind::kBadRequest, "param_schema",
                                              "invalid params: " +
                                                  (root ? std::string("(root)") : violation->path) +
                                                  ": " + violation->reason,
                                              "Correct params to match the instruction's "
                                              "parameter schema and re-call; nothing was "
                                              "dispatched and no approval ticket was created."));
            }
        } else if (rq.body.contains("params") && !rq.body["params"].is_null() &&
                   !rq.body["params"].is_object()) {
            // No stored schema to hold `params` to a shape, but a supplied value that is not an
            // object (stringified JSON is the likely mistake) would otherwise be dropped and the
            // action run with its defaults. Refuse it rather than ignore it.
            count_reject("shape");
            c.audit("denied", "reason=params_type definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kBadRequest, "params_type",
                                          "params must be a JSON object",
                                          "send params as an object of named values and re-call; "
                                          "nothing was dispatched and no approval ticket was "
                                          "created"));
        }
    }

    // 5. Destructive / Forensics targeting. Same chokepoint functions as /api/command and MCP
    //    execute_instruction; both refusal strings come from dispatch_destructive_gate.hpp.
    if (!ports.classify) {
        return refuse(c, make_refusal(RefusalKind::kClassifierUnavailable, "classifier_unavailable",
                                      "capability registry not available",
                                      std::string(kMisconfiguredRemediation)));
    }
    {
        const auto gate = evaluate_destructive_targeting(
            ports.classify(def.plugin, def.action),
            /*valid_nonempty_agent_ids=*/!plan.agent_ids.empty(),
            /*scope_key_present=*/!plan.scope.empty(),
            /*agent_id_count=*/plan.agent_ids.size());
        switch (gate.verdict) {
        case DestructiveTargetingVerdict::NotDestructive:
            break;
        case DestructiveTargetingVerdict::ClassifyMiss:
            // Policy B, as at the other callers: the dry run above already denies a miss
            // (Unclassified / Ambiguous) before we get here, so this is unreachable with a
            // wired authorizer; falling through lets the dispatch chokepoint deny it too.
            break;
        case DestructiveTargetingVerdict::Targeted: {
            // Confine to the operator's visible agents. absent or degraded -> empty -> 404.
            std::optional<std::vector<std::string>> vis;
            if (ports.visible_agents)
                vis = ports.visible_agents(rq.caller.principal);
            plan.agent_ids =
                confine_destructive_targets(plan.agent_ids, DestructiveVisibleAgents{std::move(vis)});
            if (plan.agent_ids.empty()) {
                bump(ports, "yuzu_server_dispatch_target_rejected_total",
                     {{"route", c.route()},
                      {"reason", std::string(kReasonDestructiveNoVisibleTarget)}});
                c.audit("denied", "reason=" + std::string(kReasonDestructiveNoVisibleTarget) +
                                      " definition=" + def_token);
                return refuse(c, make_refusal(RefusalKind::kNoVisibleTarget,
                                              std::string(kReasonDestructiveNoVisibleTarget),
                                              std::string(kDestructiveNoVisibleAgentMessage)));
            }
            break;
        }
        case DestructiveTargetingVerdict::RefuseUntargeted: {
            bump(ports, "yuzu_server_dispatch_target_rejected_total",
                 {{"route", c.route()}, {"reason", std::string(gate.refusal_reason)}});
            c.audit("denied", "reason=" + std::string(gate.refusal_reason) +
                                  " definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kBadRequest, std::string(gate.refusal_reason),
                                          std::string(gate.refusal_message),
                                          std::string(remediation_for_refusal_reason(
                                              gate.refusal_reason)) +
                                              "; nothing was dispatched and no approval ticket "
                                              "was created"));
        }
        }
    }

    // 6. The definition's OWN approval_mode. Nothing about the caller's MCP tier is read here.
    if (definition_needs_approval(def.approval_mode, rq.caller.principal_is_admin)) {
        if (!ports.submit_approval) {
            spdlog::error("instruction '{}' requires approval (mode={}) but no approval manager is "
                          "available: rejecting execution",
                          def_token, ::yuzu::log_token(def.approval_mode));
            bump(ports, kApprovalRefusedMetric,
                 {{"reason", kReasonApprovalUnavailable}});
            c.audit("failure", "reason=approval_unavailable mode=" +
                                   ::yuzu::log_token(def.approval_mode) + " definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalUnavailable, kReasonApprovalUnavailable,
                                          "approval system unavailable: cannot execute an "
                                          "approval-gated instruction",
                                          std::string(kMisconfiguredRemediation)));
        }
        // A cap was requested but its counter is unwired: refuse, never silently run uncapped
        // (the same fail-closed stance as an unwired approval manager above).
        if (rq.submitter_pending_cap > 0 && !ports.pending_count_for) {
            spdlog::error("instruction '{}' requires approval but the pending-approval counter is "
                          "unwired: rejecting rather than running without the per-principal cap",
                          def_token);
            bump(ports, kApprovalRefusedMetric, {{"reason", kReasonApprovalUnavailable}});
            c.audit("failure", "reason=approval_unavailable mode=" +
                                   ::yuzu::log_token(def.approval_mode) + " definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalUnavailable, kReasonApprovalUnavailable,
                                          "approval system unavailable: cannot execute an "
                                          "approval-gated instruction",
                                          std::string(kMisconfiguredRemediation)));
        }
        std::optional<int> pending_now;
        if (rq.submitter_pending_cap > 0) {
            // up8-1 / sre-2: an unreadable count must refuse, not read as zero. The cap exists to
            // bound one principal's share of the global pending queue, and a store that cannot
            // be counted is exactly when every principal would otherwise be admitted.
            try {
                pending_now = ports.pending_count_for(rq.caller.principal);
            } catch (...) {
                pending_now = std::nullopt;
            }
            if (!pending_now) {
                spdlog::error("instruction '{}': the pending-approval count could not be read; "
                              "refusing rather than running without the per-principal cap",
                              def_token);
                bump(ports, kApprovalRefusedMetric, {{"reason", kReasonApprovalUnavailable}});
                c.audit("failure", "reason=approval_unavailable cause=pending_count_unreadable "
                                   "definition=" + def_token);
                // A store fault (pool timeout or query failure), not a wiring defect: unlike the
                // unwired-port refusals above, a retry can succeed.
                return refuse(c, make_refusal(RefusalKind::kApprovalUnavailable,
                                              kReasonApprovalUnavailable,
                                              "approval system unavailable: the pending-approval "
                                              "count could not be read",
                                              "retry shortly; the approval store could not be read",
                                              kRetryAfterMs));
            }
        }
        if (rq.submitter_pending_cap > 0 && *pending_now >= rq.submitter_pending_cap) {
            bump(ports, kApprovalRefusedMetric,
                 {{"reason", kReasonApprovalCapReached}});
            c.audit("denied", "reason=approval_cap_reached definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalCapReached, kReasonApprovalCapReached,
                                          "too many pending approvals for this principal; approve "
                                          "or let existing requests expire before creating more",
                                          "wait for your pending approvals to be reviewed"));
        }
        auto submitted = ports.submit_approval(rq.definition_id, rq.caller.principal, plan.scope,
                                               def.plugin, def.action);
        if (!submitted) {
            spdlog::error("approval submit failed for '{}': {}", def_token, submitted.error());
            bump(ports, kApprovalRefusedMetric,
                 {{"reason", kReasonApprovalSubmitFailed}});
            c.audit("failure", "reason=approval_submit_failed definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalSubmitFailed,
                                          kReasonApprovalSubmitFailed,
                                          "failed to create approval request", "retry later",
                                          kRetryAfterMs));
        }
        c.audit("pending", "approval_id=" + ::yuzu::log_token(*submitted) +
                               " mode=" + ::yuzu::log_token(def.approval_mode) +
                               " definition=" + def_token);
        emit_event_guarded(c.emit, "approval.created"); // the legacy route's event
        return PrepareOutcome{PendingApproval{*submitted, def.approval_mode, rq.definition_id},
                              c.audit_dropped};
    }

    return PrepareOutcome{std::move(plan), c.audit_dropped};
}

namespace {

std::string zero_reach_text(ZeroReachCause cause, const ConfinedDispatchOutcome& o) {
    switch (cause) {
    case ZeroReachCause::InvalidScope:
        return "invalid scope: " + o.scope_parse_error.value_or("(unparsed)");
    case ZeroReachCause::ContainmentUnreadable:
        return "containment state is unreadable: dispatch is failing closed and reaching no agent; "
               "check the quarantine store";
    case ZeroReachCause::RouteUnreadable:
        return "the gateway routing directory could not be read for one or more targets: dispatch "
               "is failing closed rather than guessing where to route";
    case ZeroReachCause::OsGateUnreadable:
        return "agent presence could not be read while a per-OS kill switch is set: dispatch is "
               "failing closed and reaching no agent";
    case ZeroReachCause::Quarantined:
        return std::format("{} target(s) are quarantined: dispatch to them was withheld, not "
                           "attempted, and no agent was reached",
                           o.denied_quarantined_count);
    case ZeroReachCause::PluginNotFound:
        return std::format("the dispatched plugin is not in the reported inventory of {} target(s): "
                           "dispatch was withheld, not attempted, and no agent was reached",
                           o.unknown_plugin_count);
    case ZeroReachCause::KillSwitchedOs:
        return std::format("{} target(s) run an OS for which this plugin action is switched off: "
                           "dispatch was withheld, not attempted, and no agent was reached",
                           o.kill_switched_os_count);
    case ZeroReachCause::Generic:
        return "no agents reached: every target was unreachable or excluded by an in-flight "
               "per-device concurrency claim (check yuzu_server_dispatch_concurrency_skipped_total "
               "before treating this as an agent-connectivity fault)";
    }
    return "no agents reached";
}

void cancel_row(Ctx& c, const std::string& execution_id) {
    const Ports& p = c.ports;
    if (!p.mark_cancelled || execution_id.empty())
        return;
    bool ok = false;
    try {
        ok = p.mark_cancelled(execution_id, c.rq.caller.principal);
    } catch (...) {
        ok = false;
    }
    if (!ok) {
        spdlog::error("instruction execute: mark_cancelled failed for execution_id={}", execution_id);
        bump(p, "yuzu_exec_tracker_bookkeeping_failed_total",
             {{"op", "mark_cancelled"}, {"surface", std::string(bookkeeping_label(c.rq.surface))}});
    }
}

Outcome dispatch_stage(Ctx& c, Plan plan) {
    const Ports& p = c.ports;
    const Request& rq = c.rq;
    const InstructionDefinition& def = plan.def;
    const std::string def_token = ::yuzu::log_token(rq.definition_id);

    if (!p.dispatch) {
        return Outcome{make_refusal(RefusalKind::kMisconfigured, "dispatch_unconfigured",
                                    "command dispatch unavailable",
                                    std::string(kMisconfiguredRemediation)),
                       c.audit_dropped};
    }

    // 7. Audit BEFORE the side effect, fail closed (house v1 dispatch pattern).
    if (!safe_audit(c.hook, "requested",
                    "definition=" + def_token + " " + ident_pair(def) +
                        " targets=" + (plan.agent_ids.empty() ? std::string(plan.scope.empty() ? "all" : "scope")
                                                              : std::to_string(plan.agent_ids.size())))) {
        return Outcome{make_refusal(RefusalKind::kAuditUnavailable, "audit_unavailable",
                                    "audit subsystem unavailable: refusing to dispatch without "
                                    "durable evidence",
                                    "retry the request", kRetryAfterMs),
                       c.audit_dropped};
    }

    // 8. The execution row BEFORE dispatch, so its id is known when the dispatch registers the
    //    command_id -> execution_id mapping (closes the fast-agent race, UP2-4).
    std::string execution_id;
    if (p.create_execution) {
        ExecutionRow row;
        row.definition_id = rq.definition_id;
        row.scope_expression = plan.scope;
        // A REDACTED copy is persisted; the live dispatch below still uses the raw map.
        row.parameter_values =
            nlohmann::json(redact_sensitive_instruction_params(plan.params)).dump();
        row.dispatched_by = rq.caller.principal;
        // up8-3: the port may throw (a pool or driver fault). The `requested` row is already
        // written, so an unwound exception would leave it with no outcome row. Nothing has been
        // dispatched yet, so this refuses (retryable) after writing the `failure` row.
        bool create_threw = false;
        std::optional<std::string> created;
        try {
            created = p.create_execution(row);
        } catch (const std::exception& e) {
            spdlog::error("instruction execute: create_execution failed for '{}': {}", def_token,
                          e.what());
            create_threw = true;
        } catch (...) {
            spdlog::error("instruction execute: create_execution failed for '{}': unknown exception",
                          def_token);
            create_threw = true;
        }
        if (create_threw) {
            c.audit("failure", "reason=execution_record_exception definition=" + def_token);
            return Outcome{make_refusal(RefusalKind::kStoreUnavailable, "execution_record_unavailable",
                                        "execution history unavailable: nothing was dispatched",
                                        "retry the request", kRetryAfterMs),
                           c.audit_dropped};
        }
        if (created.has_value())
            execution_id = *created;
        else
            spdlog::warn("instruction execute: execution row not created for '{}'; dispatching "
                         "with an empty execution_id",
                         def_token);
    }

    // OMITTED agent_ids + OMITTED scope is a deliberate broadcast and is NAMED, never inferred
    // from "both happen to be empty" (the shape check guarantees that arriving here empty means
    // the caller omitted both).
    const std::string dispatch_scope = (plan.agent_ids.empty() && plan.scope.empty())
                                           ? std::string(kBroadcastScope)
                                           : plan.scope;
    ConfinedDispatchOutcome o;
    bool threw = false;
    try {
        o = p.dispatch(def.plugin, def.action, plan.agent_ids, dispatch_scope, plan.params,
                       execution_id, rq.caller, def.id, def.concurrency_mode);
    } catch (const std::exception& e) {
        spdlog::error("instruction execute: dispatch failed for '{}': {}", def_token, e.what());
        threw = true;
    } catch (...) {
        spdlog::error("instruction execute: dispatch failed for '{}': unknown exception",
                      def_token);
        threw = true;
    }
    if (threw) {
        // up8-3 / sg-5: the execution row is deliberately NOT cancelled. Whether any agent
        // already received the command is unknown once the dispatch has thrown, and a row marked
        // `cancelled` (agents_targeted 0) would tell every reader that nothing was sent. Left at
        // `running`, a response from any agent that did receive it is still recorded against the
        // row (update_agent_status), and the stuck-execution reaper
        // (ExecutionTracker::reap_stuck_running_executions: status 'running', agents_targeted 0,
        // no agent response) closes it as cancelled only when no agent ever answered. The
        // tracker has no `failed` execution status, so `running` is the honest "unknown" state.
        c.audit("failure", "reason=dispatch_exception definition=" + def_token +
                               " execution_id=" + execution_id);
        // NO retry hint, on the wire or in prose: whether any agent already received the command
        // is unknown once the dispatch has thrown, so a blind retry could dispatch it twice.
        // (command_v1_routes.cpp's dispatch_exception arm drops it for the same reason.)
        std::string remediation =
            "the dispatch failed part-way and some agents may already have received the command; ";
        if (execution_id.empty()) {
            remediation += "no execution record was created, so there are no per-agent results "
                           "to check; confirm on the devices before running it again";
        } else {
            remediation += "execution " + execution_id +
                           " was left running, not cancelled, so results from any agent that did "
                           "receive the command are still recorded against it; check that "
                           "execution's per-agent results before running the definition again "
                           "(the server closes the record by itself if no agent ever responds)";
        }
        return Outcome{make_refusal(RefusalKind::kDispatchFailed, "dispatch_failed",
                                    "dispatch failed", std::move(remediation)),
                       c.audit_dropped};
    }

    if (o.sent == 0) {
        cancel_row(c, execution_id);
        const bool protective = yuzu::protective::is_protective_action(def.plugin, def.action);
        const ZeroReachCause cause = classify_zero_reach(o, protective);
        ZeroReach z;
        z.cause = cause;
        z.command_id = o.command_id;
        z.execution_id = execution_id;
        z.message = zero_reach_text(cause, o);
        z.definition_id = rq.definition_id;
        z.plugin = def.plugin;
        z.action = def.action;
        z.agents_quarantined = o.denied_quarantined_count;
        z.agents_unknown_plugin = o.unknown_plugin_count;
        z.agents_kill_switched_os = o.kill_switched_os_count;
        c.audit("failure", "reason=" + std::string(zero_reach_token(cause)) +
                               " definition=" + def_token + " execution_id=" + execution_id);
        return Outcome{std::move(z), c.audit_dropped};
    }

    // 9. Success. Record the targeted count, then re-evaluate counters: responses that arrived
    //    BEFORE the count was set could not move the row to terminal.
    if (p.set_agents_targeted && !execution_id.empty()) {
        bool ok = false;
        try {
            ok = p.set_agents_targeted(execution_id, o.sent);
        } catch (...) {
            ok = false;
        }
        if (!ok) {
            spdlog::error("instruction execute: set_agents_targeted failed for execution_id={}",
                          execution_id);
            bump(p, "yuzu_exec_tracker_bookkeeping_failed_total",
                 {{"op", "set_agents_targeted"},
                  {"surface", std::string(bookkeeping_label(rq.surface))}});
        }
        if (p.refresh_counts) {
            try {
                p.refresh_counts(execution_id);
            } catch (const std::exception& e) {
                spdlog::warn("instruction execute: refresh_counts threw for execution_id={}: {}",
                             execution_id, e.what());
            } catch (...) {
                spdlog::warn("instruction execute: refresh_counts threw a non-standard exception "
                             "for execution_id={}",
                             execution_id);
            }
        }
    }
    c.audit("success", "command_id=" + ::yuzu::log_token(o.command_id) +
                           " execution_id=" + execution_id + " agents=" + std::to_string(o.sent) +
                           " definition=" + def_token);
    emit_event_guarded(c.emit, "instruction.executed"); // the legacy route's event
    Dispatched d;
    d.command_id = o.command_id;
    d.execution_id = execution_id;
    d.agents_reached = o.sent;
    d.definition_id = rq.definition_id;
    d.plugin = def.plugin;
    d.action = def.action;
    return Outcome{std::move(d), c.audit_dropped};
}

} // namespace

Outcome run(const Request& rq, const Ports& ports, const AuditHook& audit,
            const EventEmitHook& emit) {
    PrepareOutcome prep = prepare(rq, ports, audit, emit);
    if (auto* plan = std::get_if<Plan>(&prep.result)) {
        Ctx c{rq, ports, audit, emit};
        c.audit_dropped = prep.audit_dropped;
        return dispatch_stage(c, std::move(*plan));
    }
    if (auto* pending = std::get_if<PendingApproval>(&prep.result))
        return Outcome{std::move(*pending), prep.audit_dropped};
    return Outcome{std::move(std::get<Refusal>(prep.result)), prep.audit_dropped};
}

} // namespace yuzu::server::instruction_execute
