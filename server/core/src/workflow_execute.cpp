#include "workflow_execute.hpp"

#include "compliance_eval.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_target_shape.hpp"
#include "instruction_store.hpp"
#include "mcp_input_bounds.hpp"
#include "store_errors.hpp"
#include "web_utils.hpp" // audit_token (CWE-117)

#include <yuzu/protective_actions.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

constexpr std::string_view kActionExecute = "workflow.execute";
// A workflow or instruction id in an audit detail is cut here after neutralisation so a
// hostile stored id cannot inflate a row.
constexpr std::size_t kAuditIdMax = 128;

std::string clip_token(std::string_view s) {
    return audit_token(s.substr(0, std::min(s.size(), kAuditIdMax)));
}

WorkflowExecuteOutcome refuse(WorkflowExecuteStatus status, std::string message,
                              std::string reason = {}, bool retryable = false) {
    WorkflowExecuteOutcome o;
    o.status = status;
    o.message = std::move(message);
    o.reason = std::move(reason);
    o.retryable = retryable;
    return o;
}

WorkflowStepInstruction to_step_instruction(const InstructionDefinition& d) {
    return WorkflowStepInstruction{d.id, d.plugin, d.action, d.approval_mode, d.concurrency_mode};
}

} // namespace

// ── body parse ────────────────────────────────────────────────────────────

std::expected<std::vector<std::string>, WorkflowExecuteBodyError>
parse_workflow_execute_body(const nlohmann::json& body) {
    if (!body.is_object())
        return std::unexpected(WorkflowExecuteBodyError{std::string(kReasonBodyType),
                                                        "request body must be a JSON object"});
    // No scope arm: a workflow run names its devices. Refused BEFORE the shape check so the
    // answer names the field the caller actually sent instead of a conflict with agent_ids.
    if (body.contains("scope"))
        return std::unexpected(WorkflowExecuteBodyError{
            std::string(kReasonScopeUnsupported),
            "scope is not supported here; name the devices in agent_ids"});
    if (!body.contains("agent_ids"))
        return std::unexpected(WorkflowExecuteBodyError{
            "agent_ids_required",
            "agent_ids (a non-empty array of agent id strings) is required; a workflow run "
            "names its devices explicitly"});
    if (const auto v = check_targeting_shape(body))
        return std::unexpected(WorkflowExecuteBodyError{v->reason, v->message});

    const auto& arr = body["agent_ids"]; // array, non-empty, all strings: the shape check proved it
    if (arr.size() > mcp::kExecInstrAgentIdsMaxItems)
        return std::unexpected(WorkflowExecuteBodyError{
            "agent_ids_count", "agent_ids may name at most " +
                                   std::to_string(mcp::kExecInstrAgentIdsMaxItems) + " agents"});
    std::vector<std::string> ids;
    ids.reserve(arr.size());
    for (const auto& v : arr) {
        const auto& s = v.get_ref<const std::string&>();
        if (s.empty() || s.size() > mcp::kExecInstrIdentMaxLen)
            return std::unexpected(WorkflowExecuteBodyError{
                "agent_id_len", "each agent id must be 1 to " +
                                    std::to_string(mcp::kExecInstrIdentMaxLen) + " bytes"});
        ids.push_back(s);
    }
    return ids;
}

// ── per-step admission ────────────────────────────────────────────────────

bool step_approval_blocked(std::string_view approval_mode, bool principal_is_admin) {
    if (approval_mode == "auto")
        return false;
    if (approval_mode == "role-gated")
        return !principal_is_admin; // effective (JIT-aware) role, mirrored on DispatchCaller
    return true; // "always", and any unknown mode: fail closed
}

StepAdmissionDecision admit_step(const WorkflowStepInstruction& def,
                                 const WorkflowClassifyFn& classify,
                                 const std::vector<std::string>& agent_ids,
                                 const DispatchCaller& caller) {
    if (step_approval_blocked(def.approval_mode, caller.principal_is_admin))
        return {StepAdmission::kApprovalRequired, "approval_required", {}};

    const auto classified = classify(def.plugin, def.action);
    const auto gate = evaluate_destructive_targeting(
        classified, /*valid_nonempty_agent_ids=*/!agent_ids.empty(),
        /*scope_key_present=*/false, /*agent_id_count=*/agent_ids.size());
    switch (gate.verdict) {
    case DestructiveTargetingVerdict::ClassifyMiss:
        return {StepAdmission::kUnclassified, "step_unclassified", {}};
    case DestructiveTargetingVerdict::RefuseUntargeted:
        return {StepAdmission::kDestructiveUntargeted, gate.refusal_reason, gate.refusal_message};
    case DestructiveTargetingVerdict::NotDestructive:
        return {StepAdmission::kAdmitted, {}, {}};
    case DestructiveTargetingVerdict::Targeted:
        break;
    }
    // Explicitly targeted Destructive/Forensics step. If the caller's visible set is engaged and
    // contains none of the named agents, the dispatch would reach nobody and look like an empty
    // fleet; say so up front, as /api/command does.
    if (caller.exec_visible) {
        const bool any_visible = std::any_of(
            agent_ids.begin(), agent_ids.end(),
            [&](const std::string& id) { return caller.exec_visible->contains(id); });
        if (!any_visible)
            return {StepAdmission::kDestructiveNoVisibleTarget, kReasonDestructiveNoVisibleTarget,
                    "none of the named agents is visible to this caller"};
    }
    return {StepAdmission::kAdmitted, {}, {}};
}

nlohmann::json workflow_execute_result_json(const WorkflowExecuteOutcome& o,
                                            const std::string& workflow_id) {
    nlohmann::json steps = nlohmann::json::array();
    for (const auto& n : o.steps) {
        nlohmann::json e = {{"instruction_id", n.instruction_id},
                            {"command_id", n.command_id},
                            {"agents_reached", n.agents_reached}};
        if (n.agents_reached == 0) {
            e["reason"] = n.reason;
            e["retryable"] = n.retryable;
            e["agents_quarantined"] = n.agents_quarantined;
            e["agents_unknown_plugin"] = n.agents_unknown_plugin;
            e["agents_kill_switched_os"] = n.agents_kill_switched_os;
        }
        steps.push_back(std::move(e));
    }
    nlohmann::json j = {{"execution_id", o.execution_id},
                        {"workflow_id", workflow_id},
                        {"status", o.run_status},
                        {"late_denied", o.late_denied},
                        {"steps", std::move(steps)}};
    if (!o.audit_persisted)
        j["audit_persisted"] = false;
    return j;
}

WorkflowInstructionLookupFn make_instruction_lookup(InstructionStore* store) {
    if (!store)
        return {};
    return [store](const std::string& id)
               -> std::expected<std::optional<WorkflowStepInstruction>, std::string> {
        auto r = store->get_definition(id);
        if (!r)
            return std::unexpected(r.error());
        if (!*r)
            return std::optional<WorkflowStepInstruction>{};
        return std::optional<WorkflowStepInstruction>{to_step_instruction(**r)};
    };
}

// ── the sequence ──────────────────────────────────────────────────────────

namespace {

std::string refusal_message_for(StepAdmission v, const WorkflowStep& step,
                                const WorkflowStepInstruction& def,
                                const StepAdmissionDecision& d) {
    switch (v) {
    case StepAdmission::kApprovalRequired:
        return "workflow step '" + step.label + "' references instruction '" + def.id +
               "' which requires approval (mode: " + def.approval_mode +
               "). Submit each instruction individually for approval.";
    case StepAdmission::kUnclassified:
        return "workflow step '" + step.label + "' runs " + def.plugin + "." + def.action +
               ", which is not in the capability catalogue; it would be refused at dispatch";
    case StepAdmission::kDestructiveUntargeted:
    case StepAdmission::kDestructiveNoVisibleTarget:
        return std::string(d.message);
    case StepAdmission::kAdmitted:
        break;
    }
    return {};
}

WorkflowExecuteStatus status_for(StepAdmission v) {
    switch (v) {
    case StepAdmission::kApprovalRequired:
        return WorkflowExecuteStatus::kApprovalRequired;
    case StepAdmission::kUnclassified:
        return WorkflowExecuteStatus::kUnclassifiedStep;
    case StepAdmission::kDestructiveUntargeted:
        return WorkflowExecuteStatus::kDestructiveUntargeted;
    case StepAdmission::kDestructiveNoVisibleTarget:
        return WorkflowExecuteStatus::kDestructiveNoVisibleTarget;
    case StepAdmission::kAdmitted:
        break;
    }
    return WorkflowExecuteStatus::kExecuteFailed;
}

} // namespace

WorkflowExecuteOutcome apply_workflow_execute(const WorkflowExecutePorts& ports,
                                              const WorkflowExecuteRequest& req) {
    // ── 1. wiring: fail CLOSED, before any read or effect ────────────────
    if (!ports.api || !ports.run)
        return refuse(WorkflowExecuteStatus::kUnavailable, "workflow engine not available",
                      "workflow_engine_unavailable");
    if (!ports.instruction_store_open || !ports.lookup)
        return refuse(WorkflowExecuteStatus::kUnavailable, "instruction store not available",
                      "instruction_store_unavailable");
    if (!ports.approval_gate_available)
        return refuse(WorkflowExecuteStatus::kUnavailable,
                      "approval gate not available; a workflow is not run without it",
                      "approval_gate_unavailable");
    if (!ports.classify || !ports.dispatch || !ports.audit)
        return refuse(WorkflowExecuteStatus::kUnavailable, "workflow dispatch not available",
                      "dispatch_unavailable");
    if (req.caller.principal.empty() && !req.caller.system)
        return refuse(WorkflowExecuteStatus::kNoPrincipal,
                      "authenticated session has no principal", "no_principal");

    const std::string target_id = clip_token(req.workflow_id);
    auto deny_audit = [&](std::string_view reason, const std::string& extra) {
        // Set-and-proceed: nothing has been dispatched on a refusal, so a lost denial row does
        // not change what the caller is told; the persist outcome is deliberately not consulted.
        (void)ports.audit(std::string(kActionExecute), "denied", target_id,
                          req.audit_context + " reason=" + std::string(reason) + extra);
    };
    auto count_rejected = [&](std::string_view reason) {
        if (ports.count_target_rejected)
            ports.count_target_rejected(reason);
    };

    // ── 2. the workflow ──────────────────────────────────────────────────
    const auto wf = ports.api->get_workflow(req.workflow_id);
    if (!wf) {
        spdlog::warn("workflow execute: get_workflow failed: {}",
                     genericize_db_error("get_workflow", wf.error()));
        return refuse(WorkflowExecuteStatus::kStoreFailed, "workflow store unavailable",
                      "store_unavailable", /*retryable=*/true);
    }
    if (!*wf)
        return refuse(WorkflowExecuteStatus::kWorkflowNotFound, "workflow not found",
                      "workflow_not_found");
    const Workflow& workflow = **wf;
    if (workflow.steps.empty())
        return refuse(WorkflowExecuteStatus::kInvalidWorkflow, "workflow has no steps",
                      "workflow_no_steps");

    // ── 3 + 4. every step admitted, or the whole run is refused ──────────
    for (const auto& step : workflow.steps) {
        const auto def_r = ports.lookup(step.instruction_id);
        if (!def_r) {
            spdlog::warn("workflow execute: instruction lookup failed: {}",
                         genericize_db_error("workflow execute instruction lookup", def_r.error()));
            return refuse(WorkflowExecuteStatus::kStoreFailed, "instruction store unavailable",
                          "store_unavailable", /*retryable=*/true);
        }
        if (!*def_r)
            return refuse(WorkflowExecuteStatus::kUnknownInstruction,
                          "workflow step '" + step.label + "' references unknown instruction: " +
                              step.instruction_id,
                          "unknown_instruction");
        const WorkflowStepInstruction& def = **def_r;
        const auto d = admit_step(def, ports.classify, req.agent_ids, req.caller);
        if (d.verdict == StepAdmission::kAdmitted)
            continue;
        if (d.verdict == StepAdmission::kDestructiveUntargeted ||
            d.verdict == StepAdmission::kDestructiveNoVisibleTarget)
            count_rejected(d.reason);
        deny_audit(d.reason, " step=" + clip_token(step.instruction_id) + " action=" +
                                 clip_token(def.plugin) + "." + clip_token(def.action));
        return refuse(status_for(d.verdict), refusal_message_for(d.verdict, step, def, d),
                      std::string(d.reason));
    }

    // ── 5. the requested row, BEFORE anything is dispatched ──────────────
    if (!ports.audit(std::string(kActionExecute), "requested", target_id,
                     req.audit_context + " agents=" + std::to_string(req.agent_ids.size()) +
                         " steps=" + std::to_string(workflow.steps.size())))
        return refuse(WorkflowExecuteStatus::kAuditFailed,
                      "audit subsystem unavailable; refusing to dispatch without durable evidence",
                      "audit_unavailable", /*retryable=*/true);

    // ── 6. run: the engine drives the steps synchronously through this callback ──
    std::vector<WorkflowStepDispatchNote> notes;
    bool late_denied = false;
    const StepDispatchFn dispatch_fn =
        [&](const std::string& instruction_id, const std::string& /*agent_ids_json*/,
            const std::string& parameters_json) -> std::expected<std::string, std::string> {
        // The engine hands back the JSON of the list it was given, which is ours; the request's
        // own vector is used so a parse of it cannot narrow or widen the target set.
        const auto def_r = ports.lookup(instruction_id);
        if (!def_r)
            return std::unexpected(genericize_db_error("workflow execute instruction lookup",
                                                       def_r.error()));
        if (!*def_r)
            return std::unexpected("unknown instruction: " + instruction_id);
        const WorkflowStepInstruction& def = **def_r;

        // Re-run the admission against the FRESH definition: an instruction edited after the
        // preflight (a safe action turned destructive, an approval mode raised) is refused here,
        // and audited NOW, before any later step or the response.
        const auto d = admit_step(def, ports.classify, req.agent_ids, req.caller);
        if (d.verdict != StepAdmission::kAdmitted) {
            late_denied = true;
            if (d.verdict == StepAdmission::kDestructiveUntargeted ||
                d.verdict == StepAdmission::kDestructiveNoVisibleTarget)
                count_rejected(d.reason);
            deny_audit(d.reason, " step=" + clip_token(instruction_id) + " (late)");
            notes.push_back(WorkflowStepDispatchNote{.instruction_id = instruction_id,
                                                     .reason = "late_denied"});
            switch (d.verdict) {
            case StepAdmission::kApprovalRequired:
                return std::unexpected("step now requires approval; refused");
            case StepAdmission::kUnclassified:
                return std::unexpected("step is not in the capability catalogue; refused");
            default:
                return std::unexpected(std::string(d.message));
            }
        }

        std::unordered_map<std::string, std::string> params;
        const auto pj = nlohmann::json::parse(parameters_json, nullptr, false);
        if (pj.is_object()) {
            for (const auto& [k, v] : pj.items())
                params[k] = v.is_string() ? v.get<std::string>() : v.dump();
        }

        const ConfinedDispatchOutcome out = ports.dispatch(def, req.agent_ids, params, req.caller);
        WorkflowStepDispatchNote note;
        note.instruction_id = instruction_id;
        note.command_id = out.command_id;
        note.agents_reached = out.sent;
        note.agents_quarantined = out.denied_quarantined_count;
        note.agents_unknown_plugin = out.unknown_plugin_count;
        note.agents_kill_switched_os = out.kill_switched_os_count;
        if (out.sent == 0) {
            const auto cause =
                classify_zero_reach(out, yuzu::protective::is_protective_action(def.plugin,
                                                                                  def.action));
            note.reason = std::string(zero_reach_token(cause));
            note.retryable = zero_reach_retryable(cause);
            notes.push_back(note);
            return std::unexpected("no agents reached for " + instruction_id + " (" + note.reason +
                                   ")");
        }
        notes.push_back(note);
        return nlohmann::json({{"status", "dispatched"},
                               {"command_id", out.command_id},
                               {"agents_reached", out.sent}})
            .dump();
    };
    const ConditionEvalFn condition_fn = [](const std::string& expression,
                                            const std::map<std::string, std::string>& fields) {
        return evaluate_compliance_bool(expression, fields);
    };

    const auto run = ports.run(req.workflow_id, req.agent_ids, dispatch_fn, condition_fn,
                               WorkflowRunControl{});
    if (!run) {
        const bool db = is_generic_db_error(run.error());
        const bool gone = run.error().starts_with("workflow not found");
        const auto status = db ? WorkflowExecuteStatus::kStoreFailed
                               : gone ? WorkflowExecuteStatus::kWorkflowNotFound
                                      : WorkflowExecuteStatus::kExecuteFailed;
        const std::string msg = db ? "workflow store unavailable"
                                   : gone ? "workflow not found" : run.error();
        (void)ports.audit(std::string(kActionExecute), "failure", target_id,
                          req.audit_context + " reason=" +
                              (db ? "store_unavailable" : gone ? "workflow_not_found" : "rejected") +
                              (db ? "" : " detail=" + clip_token(run.error())));
        WorkflowExecuteOutcome o = refuse(status, msg, db ? "store_unavailable" : "rejected",
                                          /*retryable=*/db);
        o.steps = std::move(notes);
        o.late_denied = late_denied;
        return o;
    }

    WorkflowExecuteOutcome o;
    o.execution_id = *run;
    o.late_denied = late_denied;
    o.steps = std::move(notes);
    o.run_status = "unknown";
    if (const auto ex = ports.api->get_workflow_execution(*run); ex && *ex)
        o.run_status = (*ex)->status;

    const bool any_reached = std::any_of(o.steps.begin(), o.steps.end(),
                                         [](const auto& n) { return n.agents_reached > 0; });
    const WorkflowStepDispatchNote* first_zero = nullptr;
    for (const auto& n : o.steps) {
        if (n.agents_reached == 0) { // a zero-reach cause, or "late_denied" (permanent)
            first_zero = &n;
            break;
        }
    }
    if (!any_reached && first_zero) {
        o.status = WorkflowExecuteStatus::kNoAgentsReached;
        o.reason = first_zero->reason;
        o.retryable = first_zero->retryable;
        o.message = first_zero->reason == "late_denied"
                        ? "the workflow started but a step was refused at dispatch because its "
                          "definition changed after the preflight"
                        : "the workflow started but no step reached any agent (" +
                              first_zero->reason + ")";
    } else {
        o.status = WorkflowExecuteStatus::kOk;
    }

    const std::string result = late_denied ? "denied"
                               : o.status == WorkflowExecuteStatus::kOk ? "success" : "failure";
    std::size_t reached_total = 0;
    for (const auto& n : o.steps)
        reached_total += static_cast<std::size_t>(n.agents_reached);
    o.audit_persisted = ports.audit(
        std::string(kActionExecute), result, target_id,
        req.audit_context + " execution_id=" + clip_token(o.execution_id) +
            " run_status=" + clip_token(o.run_status) +
            " dispatches=" + std::to_string(o.steps.size()) +
            " agents_reached=" + std::to_string(reached_total) +
            (late_denied ? " late_denied=true" : "") +
            (o.status == WorkflowExecuteStatus::kNoAgentsReached ? " reason=" + o.reason : ""));
    return o;
}

} // namespace yuzu::server
