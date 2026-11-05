#include "workflow_execute.hpp"

#include "compliance_eval.hpp"
#include "dispatch_denial_text.hpp"
#include "dispatch_send_progress.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_target_shape.hpp"
#include "instruction_store.hpp"
#include "mcp_input_bounds.hpp"
#include "sha256_hex.hpp"
#include "store_errors.hpp"
#include "web_utils.hpp" // audit_token (CWE-117)
#include "workflow_wait.hpp"

#include <yuzu/server/auth.hpp> // auth::CredentialCheck (forward-declared in the header)

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>
#include <yuzu/protective_actions.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <set>
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

// The approver-facing summary names this many steps; the digest covers all of them.
constexpr std::size_t kEffectSummarySteps = 3;
constexpr std::size_t kEffectLabelMax = 64;
constexpr std::string_view kEffectDigestDomain = "yuzu-workflow-step-effects-v1\n";

std::string dump_replacing(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

bool step_matches_expected(const WorkflowStepEffects& expected, const WorkflowStepInstruction& def) {
    const auto it = expected.find(def.id);
    return it != expected.end() && it->second == workflow_step_effect(def);
}

constexpr std::string_view kDefinitionChangedMessage =
    "a step's instruction changed after this call's approval ticket was checked; nothing was "
    "sent for it";

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
    const bool incomplete = o.status == WorkflowExecuteStatus::kRunIncomplete;
    nlohmann::json j = {{"execution_id", o.execution_id},
                        {"workflow_id", workflow_id},
                        {"status", incomplete ? std::string(workflow_run_outcome_token(o.run_outcome))
                                              : o.run_status},
                        {"late_denied", o.late_denied},
                        {"steps", std::move(steps)}};
    if (incomplete) {
        j["run_status"] = o.run_status;
        j["retryable"] = false;
        j["message"] = o.message;
        if (o.deadline_exceeded || o.interrupted || !o.credential_stop.empty())
            j["reason"] = o.reason; // deadline_exceeded | server_shutdown | credential_revoked | credential_indeterminate
    }
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

// ── how a run ended ───────────────────────────────────────────────────────

std::string_view workflow_run_outcome_token(WorkflowRunOutcome outcome) {
    switch (outcome) {
    case WorkflowRunOutcome::kSucceeded:
        return "succeeded";
    case WorkflowRunOutcome::kFailed:
        return "failed";
    case WorkflowRunOutcome::kPartial:
        return "partial";
    case WorkflowRunOutcome::kInterrupted:
        return "interrupted";
    case WorkflowRunOutcome::kAborted:
        return "aborted";
    }
    return "failed";
}

WorkflowRunOutcome classify_workflow_run(std::string_view run_status, bool late_denied,
                                         const std::vector<WorkflowStepDispatchNote>& steps,
                                         bool deadline_exceeded, bool interrupted,
                                         bool credential_stopped) {
    if (late_denied || deadline_exceeded || credential_stopped)
        return WorkflowRunOutcome::kAborted;
    if (interrupted)
        return WorkflowRunOutcome::kInterrupted;
    const bool any_reached = std::any_of(steps.begin(), steps.end(),
                                         [](const auto& n) { return n.agents_reached > 0; });
    const bool all_reached = std::all_of(steps.begin(), steps.end(),
                                         [](const auto& n) { return n.agents_reached > 0; });
    // Only the engine's own "completed" counts: "unknown" (unreadable), "running" (a finalize
    // that did not land), "failed" and "cancelled" are all not success.
    if (run_status == "completed" && all_reached)
        return WorkflowRunOutcome::kSucceeded;
    return any_reached ? WorkflowRunOutcome::kPartial : WorkflowRunOutcome::kFailed;
}

// ── admission ─────────────────────────────────────────────────────────────

WorkflowRunAdmission admit_workflow_run(detail::StreamBudget* budget,
                                        const std::function<bool()>& draining,
                                        const std::string& principal,
                                        yuzu::MetricsRegistry* metrics) {
    WorkflowRunAdmission out;
    const auto count = [&](std::string_view reason) {
        if (!metrics)
            return;
        try {
            metrics->counter(kWorkflowRunRefusedMetric, {{"reason", std::string(reason)}})
                .increment();
        } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail a refusal
        }
    };
    // Draining first: StreamBudget::try_acquire does not consult its closing flag, and a run
    // admitted now would hold the drain open for up to the whole run budget.
    if (draining && draining()) {
        count(kWorkflowRunRefusedDraining);
        out.refusal = refuse(WorkflowExecuteStatus::kDraining,
                             "the server is shutting down and is not starting new workflow runs",
                             kWorkflowRunRefusedDraining, /*retryable=*/true);
        out.refusal->remediation =
            "retry after the server restarts, or against another replica; nothing was sent";
        return out;
    }
    if (!budget)
        return out; // unmetered seam (test harness)
    auto acquired = budget->try_acquire(detail::SseSurface::kWorkflowRun, principal,
                                        detail::kPerPrincipalWorkflowRun);
    if (acquired.lease) {
        out.lease = std::move(acquired.lease);
        return out;
    }
    const std::string_view why = acquired.reject_reason != nullptr
                                     ? std::string_view(acquired.reject_reason)
                                     : std::string_view(detail::StreamBudget::kRejectGlobal);
    const bool per_principal = why == detail::StreamBudget::kRejectPerPrincipal;
    count(per_principal ? detail::StreamBudget::kRejectPerPrincipal
                        : detail::StreamBudget::kRejectGlobal);
    out.refusal = refuse(WorkflowExecuteStatus::kRunCapReached,
                         per_principal ? "this principal already has as many workflow runs in "
                                         "progress as it may"
                                       : "the server is running as many held-open requests as it "
                                         "is sized for",
                         per_principal ? detail::StreamBudget::kRejectPerPrincipal
                                       : detail::StreamBudget::kRejectGlobal,
                         /*retryable=*/true);
    out.refusal->remediation =
        per_principal
            ? "wait for one of your workflow runs to finish, then retry; nothing was sent"
            : "retry shortly; nothing was sent";
    return out;
}

// ── step-effect binding ───────────────────────────────────────────────────

std::string workflow_step_effect(const WorkflowStepInstruction& def) {
    return dump_replacing(nlohmann::json::array(
        {def.id, def.plugin, def.action, def.approval_mode, def.concurrency_mode}));
}

WorkflowStepEffects workflow_step_effects(const WorkflowExecutePlan& plan) {
    WorkflowStepEffects out;
    for (const auto& def : plan.steps)
        out.emplace(def.id, workflow_step_effect(def));
    return out;
}

std::expected<std::string, WorkflowExecuteOutcome>
workflow_effect_binding(const WorkflowExecutePorts& ports, const WorkflowExecutePlan& plan) {
    // A tuple dump holds no raw newline, so the join is unambiguous.
    std::string material(kEffectDigestDomain);
    for (const auto& def : plan.steps) {
        material += workflow_step_effect(def);
        material += '\n';
    }
    const auto digest = ports.digest ? ports.digest(material) : sha256_hex(material);
    if (!digest || digest->size() != 64)
        return std::unexpected(refuse(WorkflowExecuteStatus::kEffectDigestFailed,
                                      "the workflow's step effects could not be bound for approval",
                                      "effect_digest_unavailable"));
    nlohmann::json labels = nlohmann::json::array();
    for (std::size_t i = 0; i < plan.steps.size() && i < kEffectSummarySteps; ++i) {
        std::string label = plan.steps[i].plugin + "." + plan.steps[i].action;
        if (label.size() > kEffectLabelMax)
            label.resize(kEffectLabelMax);
        labels.push_back(std::move(label));
    }
    return "effect=" +
           dump_replacing(nlohmann::json::array(
               {"workflow", plan.steps.size(), std::move(labels), *digest})) +
           "\n";
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

std::expected<WorkflowExecutePlan, WorkflowExecuteOutcome>
prepare_workflow_execute(const WorkflowExecutePorts& ports, const WorkflowExecuteRequest& req) {
    // ── 1. wiring: fail CLOSED, before any read or effect ────────────────
    if (!ports.api || !ports.run)
        return std::unexpected(refuse(WorkflowExecuteStatus::kUnavailable,
                                      "workflow engine not available",
                                      "workflow_engine_unavailable"));
    if (!ports.instruction_store_open || !ports.lookup)
        return std::unexpected(refuse(WorkflowExecuteStatus::kUnavailable,
                                      "instruction store not available",
                                      "instruction_store_unavailable"));
    if (!ports.approval_gate_available)
        return std::unexpected(
            refuse(WorkflowExecuteStatus::kUnavailable,
                   "approval gate not available; a workflow is not run without it",
                   "approval_gate_unavailable"));
    if (!ports.classify || !ports.authorize || !ports.dispatch || !ports.audit)
        return std::unexpected(refuse(WorkflowExecuteStatus::kUnavailable,
                                      "workflow dispatch not available", "dispatch_unavailable"));
    if (req.caller.principal.empty() && !req.caller.system)
        return std::unexpected(refuse(WorkflowExecuteStatus::kNoPrincipal,
                                      "authenticated session has no principal", "no_principal"));

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
        return std::unexpected(refuse(WorkflowExecuteStatus::kStoreFailed,
                                      "workflow store unavailable", "store_unavailable",
                                      /*retryable=*/true));
    }
    if (!*wf)
        return std::unexpected(refuse(WorkflowExecuteStatus::kWorkflowNotFound,
                                      "workflow not found", "workflow_not_found"));
    const Workflow& workflow = **wf;
    if (workflow.steps.empty())
        return std::unexpected(refuse(WorkflowExecuteStatus::kInvalidWorkflow,
                                      "workflow has no steps", "workflow_no_steps"));
    // The synchronous budget: the most a run could SLEEP between retries, summed over the steps
    // (retry_count x retry_delay_seconds each), must fit inside kWorkflowSyncBudget. This models
    // sleeps only. It does not model dispatch time or `foreach` fan-out (each item is a dispatch
    // inside one attempt), so it is a prefilter for a workflow that cannot finish in the budget
    // even when every dispatch is instant; the run's deadline is the real bound. Like a workflow
    // with no steps this is a property of the stored workflow: no row is written, nothing is sent.
    {
        std::int64_t worst_sleep_s = 0;
        for (const auto& step : workflow.steps) {
            worst_sleep_s += static_cast<std::int64_t>(std::max(step.retry_count, 0)) *
                             std::max(step.retry_delay_seconds, 0);
            if (worst_sleep_s > kWorkflowSyncBudget.count()) {
                WorkflowExecuteOutcome o = refuse(
                    WorkflowExecuteStatus::kExceedsSyncBudget,
                    "the workflow's retry delays could add up to more than the " +
                        std::to_string(kWorkflowSyncBudget.count()) +
                        " second budget of one run",
                    "workflow_exceeds_sync_budget");
                o.remediation = "reduce the retry count or retry delay of the workflow's steps "
                                "(the sum over the steps of retryCount x retryDelay must not "
                                "exceed the budget) and create a new workflow; nothing was sent";
                return std::unexpected(std::move(o));
            }
        }
    }

    // ── 3 + 4. every step admitted, or the whole run is refused ──────────
    // The chokepoint dry run is asked once per distinct (plugin, action): its answer depends on
    // the caller and the pair only, never on the step or the targets.
    std::set<std::pair<std::string, std::string>> authorized;
    WorkflowExecutePlan plan{.step_count = workflow.steps.size(), .steps = {}};
    plan.steps.reserve(workflow.steps.size());
    for (const auto& step : workflow.steps) {
        const auto def_r = ports.lookup(step.instruction_id);
        if (!def_r) {
            spdlog::warn("workflow execute: instruction lookup failed: {}",
                         genericize_db_error("workflow execute instruction lookup", def_r.error()));
            return std::unexpected(refuse(WorkflowExecuteStatus::kStoreFailed,
                                          "instruction store unavailable", "store_unavailable",
                                          /*retryable=*/true));
        }
        if (!*def_r)
            return std::unexpected(
                refuse(WorkflowExecuteStatus::kUnknownInstruction,
                       "workflow step '" + step.label +
                           "' references unknown instruction: " + step.instruction_id,
                       "unknown_instruction"));
        const WorkflowStepInstruction& def = **def_r;
        const std::string step_detail = " step=" + clip_token(step.instruction_id) +
                                        " action=" + clip_token(def.plugin) + "." +
                                        clip_token(def.action);
        plan.steps.push_back(def);

        // The effect an approval ticket was bound to, held BEFORE the authorizer, any row or any
        // dispatch (the instruction twin's 1b): this is a second, fresh read of a definition an
        // editor may have repointed since the probe saw it, and the ticket is already spent, so
        // the only safe answer to a change is to send nothing.
        if (req.expected_step_effects && !step_matches_expected(*req.expected_step_effects, def)) {
            deny_audit("definition_changed", step_detail);
            return std::unexpected(refuse(WorkflowExecuteStatus::kDefinitionChanged,
                                          std::string(kDefinitionChangedMessage),
                                          "definition_changed"));
        }

        // Caller-level authority for the step's own pair, BEFORE any body or targeting work: a
        // caller who may not run this pair learns nothing about its targeting, and 403 precedes
        // 400 as on POST /api/command. Without this a refusal the chokepoint would make for the
        // caller on step N surfaced only AFTER steps 1..N-1 had been sent, as a retryable
        // "no agents reached".
        if (auto pair = std::make_pair(def.plugin, def.action); !authorized.contains(pair)) {
            if (const auto decision = ports.authorize(req.caller, def.plugin, def.action);
                !decision) {
                const auto& denial = decision.error();
                const std::string denial_token(detail::to_string(denial.reason));
                spdlog::warn("workflow execute: dispatch denied: {}.{} reason={} securable={} "
                             "caller={}",
                             ::yuzu::log_token(def.plugin), ::yuzu::log_token(def.action),
                             denial_token, denial.securable.empty() ? "(none)" : denial.securable,
                             req.caller.principal.empty()
                                 ? "(anonymous)"
                                 : ::yuzu::log_token(req.caller.principal));
                if (ports.count_dispatch_denied)
                    ports.count_dispatch_denied(denial_token);
                // An unclassifiable pair is refused as admit_step refuses it (400), not as a
                // permission denial.
                const bool unclassified =
                    denial.reason == detail::DispatchDenialReason::Unclassified ||
                    denial.reason == detail::DispatchDenialReason::Ambiguous;
                deny_audit(unclassified ? "step_unclassified" : "dispatch_denied",
                           (unclassified ? std::string{} : " denial=" + denial_token) +
                               step_detail);
                if (unclassified)
                    return std::unexpected(
                        refuse(WorkflowExecuteStatus::kUnclassifiedStep,
                               refusal_message_for(StepAdmission::kUnclassified, step, def, {}),
                               "step_unclassified"));
                const auto text = describe_dispatch_denial(denial.reason, def.plugin, def.action,
                                                           denial, DenialSurface::kRest);
                WorkflowExecuteOutcome o =
                    refuse(WorkflowExecuteStatus::kDispatchDenied,
                           "workflow step '" + step.label + "' (" + def.plugin + "." + def.action +
                               "): " + text.message,
                           "dispatch_denied");
                o.remediation = text.remediation;
                if (denial.reason == detail::DispatchDenialReason::ApprovalRequired) {
                    // The shared wording advises a supervised token's ticket flow, which is false
                    // here: no workflow transport stamps `approval_provenance`, so no ticket can
                    // lift the pair's gate.
                    o.message = "workflow step '" + step.label + "' (" + def.plugin + "." +
                                def.action +
                                "): approval required: this action is gated (admin "
                                "or approval) and a workflow run does not carry an approval for it";
                    o.remediation =
                        "this call cannot succeed for this caller and retrying will not help; run "
                        "it as an administrator, or ask an administrator to run the workflow or to "
                        "change the step to a non-gated action";
                }
                return std::unexpected(std::move(o));
            }
            authorized.insert(std::move(pair));
        }

        const auto d = admit_step(def, ports.classify, req.agent_ids, req.caller);
        if (d.verdict == StepAdmission::kAdmitted)
            continue;
        if (d.verdict == StepAdmission::kDestructiveUntargeted ||
            d.verdict == StepAdmission::kDestructiveNoVisibleTarget)
            count_rejected(d.reason);
        deny_audit(d.reason, step_detail);
        return std::unexpected(refuse(status_for(d.verdict),
                                      refusal_message_for(d.verdict, step, def, d),
                                      std::string(d.reason)));
    }
    return plan;
}

namespace {

/// What a run has done so far. Owned by `run_workflow_execute`, outside the function that drives
/// the run, so the throw arm can still read the execution id, the sends and the step notes after
/// the driver has unwound.
struct RunProgress {
    std::string execution_id;
    int agents_sent{0};
    std::vector<WorkflowStepDispatchNote> notes;
    bool late_denied{false};
    /// The engine asked `before_attempt` after the deadline and was told to stop.
    bool deadline_hit{false};
    /// The engine ended the run because the server is stopping (`on_interrupted`).
    bool interrupted{false};
    /// The credential check refused an attempt: `kReasonCredentialRevoked` or
    /// `kReasonCredentialIndeterminate`. Set at the moment the hook says no.
    std::string credential_stop;
};

/// The credential half of the `before_attempt` hook: true == the attempt may be made. See the
/// "CREDENTIAL LIVENESS" banner in the header. Records why it said no in `progress`.
bool credential_admits_attempt(const WorkflowExecuteRequest& req,
                               std::chrono::steady_clock::time_point deadline,
                               RunProgress& progress) {
    using Check = auth::CredentialCheck;
    // A throw is "could not answer", the same posture as an unreachable auth backend.
    const auto ask = [&req]() -> Check {
        try {
            return req.reauthorize();
        } catch (const std::exception& e) {
            spdlog::warn("workflow execute: credential re-check threw: {}", e.what());
        } catch (...) {
            spdlog::warn("workflow execute: credential re-check threw a non-standard exception");
        }
        return Check::kIndeterminate;
    };
    Check verdict = ask();
    if (verdict == Check::kIndeterminate) {
        // One bounded retry. The wait never runs past the deadline: when the deadline arrives
        // first the run is stopped by it, exactly as the deadline test above would have.
        const auto left = std::max(deadline - std::chrono::steady_clock::now(),
                                   std::chrono::steady_clock::duration::zero());
        (void)interruptible_wait(
            std::min<std::chrono::steady_clock::duration>(req.reauthorize_retry_delay, left),
            [] { return false; });
        if (std::chrono::steady_clock::now() >= deadline) {
            progress.deadline_hit = true;
            return false;
        }
        verdict = ask();
    }
    switch (verdict) {
    case Check::kValid:
    case Check::kValidStale:
        return true;
    case Check::kRevoked:
        progress.credential_stop = std::string(kReasonCredentialRevoked);
        return false;
    case Check::kIndeterminate:
        break;
    }
    // Still unanswered after the retry, or a value this build does not know: fail closed.
    progress.credential_stop = std::string(kReasonCredentialIndeterminate);
    return false;
}

/// Step 6 and the closing row. Anything it throws is answered by the caller as `kRunFailed`.
WorkflowExecuteOutcome drive_run(const WorkflowExecutePorts& ports, const WorkflowExecuteRequest& req,
                                 RunProgress& progress) {
    const std::string target_id = clip_token(req.workflow_id);
    auto deny_audit = [&](std::string_view reason, const std::string& extra) {
        (void)ports.audit(std::string(kActionExecute), "denied", target_id,
                          req.audit_context + " reason=" + std::string(reason) + extra);
    };
    auto count_rejected = [&](std::string_view reason) {
        if (ports.count_target_rejected)
            ports.count_target_rejected(reason);
    };

    // ── 6. run: the engine drives the steps synchronously through this callback ──
    std::vector<WorkflowStepDispatchNote>& notes = progress.notes;
    bool& late_denied = progress.late_denied;
    const StepDispatchFn dispatch_fn =
        [&](const std::string& instruction_id, const std::string& /*agent_ids_json*/,
            const std::string& parameters_json) -> std::expected<std::string, StepDispatchError> {
        // The engine hands back the JSON of the list it was given, which is ours; the request's
        // own vector is used so a parse of it cannot narrow or widen the target set.
        const auto def_r = ports.lookup(instruction_id);
        if (!def_r)
            return std::unexpected(genericize_db_error("workflow execute instruction lookup",
                                                       def_r.error()));
        if (!*def_r)
            return std::unexpected("unknown instruction: " + instruction_id);
        const WorkflowStepInstruction& def = **def_r;

        // Hold the fresh read to the effect the approval ticket was bound to, BEFORE the
        // admission below: a step whose instruction was repointed since is not sent, and the
        // refusal is audited now, with the same token as the instruction twin's.
        if (req.expected_step_effects && !step_matches_expected(*req.expected_step_effects, def)) {
            late_denied = true;
            deny_audit("definition_changed", " step=" + clip_token(instruction_id) + " (late)");
            notes.push_back(WorkflowStepDispatchNote{.instruction_id = instruction_id,
                                                     .reason = "definition_changed"});
            // Permanent: the definition will not move back, and a retry would audit the same
            // refusal again after a sleep.
            return std::unexpected(
                StepDispatchError{"step definition changed after approval; refused", true});
        }

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
            // Permanent, as above: an authorization refusal never improves with a retry.
            switch (d.verdict) {
            case StepAdmission::kApprovalRequired:
                return std::unexpected(
                    StepDispatchError{"step now requires approval; refused", true});
            case StepAdmission::kUnclassified:
                return std::unexpected(
                    StepDispatchError{"step is not in the capability catalogue; refused", true});
            default:
                return std::unexpected(StepDispatchError{std::string(d.message), true});
            }
        }

        std::unordered_map<std::string, std::string> params;
        const auto pj = nlohmann::json::parse(parameters_json, nullptr, false);
        if (pj.is_object()) {
            for (const auto& [k, v] : pj.items())
                params[k] = v.is_string() ? v.get<std::string>() : v.dump();
        }

        // Sends accepted before a throw, summed over the steps (dispatch_send_progress.hpp).
        SendProgress sends;
        ConfinedDispatchOutcome out;
        try {
            const SendProgressScope scope(sends);
            out = ports.dispatch(def, req.agent_ids, params, req.caller);
        } catch (...) {
            progress.agents_sent += sends.sent;
            throw;
        }
        progress.agents_sent += out.sent;
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

    WorkflowRunControl control;
    control.on_admitted = [&progress](const std::string& execution_id) {
        progress.execution_id = execution_id;
    };
    // The run is bounded (kWorkflowSyncBudget). The transport stamps the deadline when it takes
    // the call; a request without one is still bounded from here. The hook is the authority the
    // engine consults before every attempt, so "the run was stopped by its deadline" is recorded
    // here, at the moment of the refusal, and never inferred from a clock afterwards.
    const auto deadline = req.deadline.value_or(std::chrono::steady_clock::now() +
                                                kWorkflowSyncBudget);
    control.deadline = deadline;
    control.on_interrupted = [&progress] { progress.interrupted = true; };
    // The deadline first (no I/O), then the caller's credential: one hook, so the engine needs no
    // field of its own. The engine asks it before every dispatch attempt, which is before each
    // step's first attempt and after each retry sleep.
    control.before_attempt = [&progress, &req, deadline] {
        if (std::chrono::steady_clock::now() >= deadline) {
            progress.deadline_hit = true;
            return false;
        }
        if (!req.reauthorize)
            return true;
        return credential_admits_attempt(req, deadline, progress);
    };
    const auto run = ports.run(req.workflow_id, req.agent_ids, dispatch_fn, condition_fn, control);
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

    o.deadline_exceeded = progress.deadline_hit;
    o.interrupted = progress.interrupted;
    o.credential_stop = progress.credential_stop;
    o.run_outcome = classify_workflow_run(o.run_status, late_denied, o.steps, o.deadline_exceeded,
                                          o.interrupted, !o.credential_stop.empty());
    const bool any_reached = std::any_of(o.steps.begin(), o.steps.end(),
                                         [](const auto& n) { return n.agents_reached > 0; });
    if (o.run_outcome == WorkflowRunOutcome::kSucceeded) {
        o.status = WorkflowExecuteStatus::kOk;
    } else if (any_reached || o.run_outcome == WorkflowRunOutcome::kInterrupted ||
               !o.credential_stop.empty()) {
        // Something was sent (or the server's own shutdown, or the credential check, ended the
        // run, whatever it had sent), so the run is readable and its steps matter: a typed 2xx,
        // never a blind-retry invitation.
        o.status = WorkflowExecuteStatus::kRunIncomplete;
        o.reason = std::string(workflow_run_outcome_token(o.run_outcome));
        o.retryable = false;
        o.message =
            o.deadline_exceeded
                ? "the workflow started and some steps were sent, but the run reached its " +
                      std::to_string(kWorkflowSyncBudget.count()) +
                      " second time budget and was stopped; the remaining steps did not run"
            : o.interrupted
                ? "the workflow started but the server began shutting down and the run was "
                  "stopped; the remaining steps did not run and steps already sent are not "
                  "recalled; read the run with get_workflow_execution before starting another"
            : !o.credential_stop.empty()
                ? (o.credential_stop == kReasonCredentialRevoked
                       ? "the workflow started but the credential that made this call was no longer "
                         "valid before a step, so the run was stopped; the remaining steps did not "
                         "run and steps already sent are not recalled; read the run with "
                         "get_workflow_execution before starting another"
                       : "the workflow started but the credential that made this call could not be "
                         "confirmed before a step, so the run was stopped; the remaining steps did "
                         "not run and steps already sent are not recalled; read the run with "
                         "get_workflow_execution before starting another")
            : o.run_outcome == WorkflowRunOutcome::kAborted
                ? "the workflow started and some steps were sent, but a step was refused at "
                  "dispatch because its definition changed; the rest did not run"
                : "the workflow started and some steps were sent, but it did not complete on "
                  "every step; read the run with get_workflow_execution before starting another";
        if (o.deadline_exceeded)
            o.reason = "deadline_exceeded";
        else if (o.interrupted)
            o.reason = "server_shutdown";
        else if (!o.credential_stop.empty())
            o.reason = o.credential_stop;
    } else {
        o.status = WorkflowExecuteStatus::kNoAgentsReached;
        const WorkflowStepDispatchNote* first_zero = nullptr;
        for (const auto& n : o.steps) {
            if (n.agents_reached == 0) { // a zero-reach cause, or "late_denied" (permanent)
                first_zero = &n;
                break;
            }
        }
        if (o.deadline_exceeded) {
            // The deadline ended the run before any step reached an agent: it is the cause,
            // whatever an earlier zero-reach step said, and a retry would only race it again.
            o.reason = "deadline_exceeded";
            o.retryable = false;
            o.message = "the workflow started but reached its " +
                        std::to_string(kWorkflowSyncBudget.count()) +
                        " second time budget before any step reached an agent, and was stopped";
        } else if (first_zero) {
            o.reason = first_zero->reason;
            o.retryable = first_zero->retryable;
            o.message = first_zero->reason == "definition_changed"
                            ? "the workflow started but a step was refused at dispatch because its "
                              "definition changed after the approval ticket was checked"
                        : first_zero->reason == "late_denied"
                            ? "the workflow started but a step was refused at dispatch because its "
                              "definition changed after the preflight"
                            : "the workflow started but no step reached any agent (" +
                                  first_zero->reason + ")";
        } else {
            // The engine ended the run without a single dispatch attempt (a step failed before
            // it could be sent, or the row is not readable): nothing reached anyone.
            o.reason = "run_failed";
            o.retryable = false;
            o.message = "the workflow started but did not complete and no step reached any agent";
        }
    }

    const bool succeeded = o.status == WorkflowExecuteStatus::kOk;
    std::size_t reached_total = 0;
    for (const auto& n : o.steps)
        reached_total += static_cast<std::size_t>(n.agents_reached);
    o.audit_persisted = ports.audit(
        std::string(kActionExecute), succeeded ? "success" : "failure", target_id,
        req.audit_context + " execution_id=" + clip_token(o.execution_id) +
            " run_status=" + clip_token(o.run_status) +
            " dispatches=" + std::to_string(o.steps.size()) +
            " agents_reached=" + std::to_string(reached_total) +
            (late_denied ? " late_denied=true" : "") +
            (succeeded ? ""
                       : " run_outcome=" + std::string(workflow_run_outcome_token(o.run_outcome))) +
            (o.status == WorkflowExecuteStatus::kNoAgentsReached || o.deadline_exceeded ||
                     o.interrupted || !o.credential_stop.empty()
                 ? " reason=" + o.reason
                 : ""));
    return o;
}

} // namespace

WorkflowExecuteOutcome run_workflow_execute(const WorkflowExecutePorts& ports,
                                            const WorkflowExecuteRequest& req,
                                            const WorkflowExecutePlan& plan) {
    const std::string target_id = clip_token(req.workflow_id);

    // ── 5. the requested row, BEFORE anything is dispatched ──────────────
    if (!ports.audit(std::string(kActionExecute), "requested", target_id,
                     req.audit_context + " agents=" + std::to_string(req.agent_ids.size()) +
                         " steps=" + std::to_string(plan.step_count)))
        return refuse(WorkflowExecuteStatus::kAuditFailed,
                      "audit subsystem unavailable; refusing to dispatch without durable evidence",
                      "audit_unavailable", /*retryable=*/true);

    // From here a throw means steps may already have been sent, so it is answered as a started,
    // failed run and never as a retryable fault. The strings and the outcome are built BEFORE the
    // run (instruction_execute.cpp's throw arm): a second allocation failure in the arm must not
    // lose the closing row.
    std::string threw_detail = req.audit_context + " reason=dispatch_exception";
    WorkflowExecuteOutcome threw = refuse(
        WorkflowExecuteStatus::kRunFailed, "workflow run failed part-way",
        "dispatch_exception");
    threw.remediation =
        "the run failed part-way and some steps may already have been sent to agents, so it was "
        "not retried and must not be re-sent; read the run with get_workflow_execution "
        "(GET /api/v1/workflow-executions/{id}), where a step with no command_id was never "
        "sent, before starting another";
    RunProgress progress;
    try {
        return drive_run(ports, req, progress);
    } catch (const std::exception& e) {
        spdlog::error("workflow execute: run threw: {}", e.what());
    } catch (...) {
        spdlog::error("workflow execute: run threw a non-standard exception");
    }
    // ORDER: the closing row first, then the metric, then the bookkeeping that can allocate.
    try {
        threw_detail += " execution_id=" + clip_token(progress.execution_id) +
                        " agents_sent=" + std::to_string(progress.agents_sent);
    } catch (...) { // NOLINT(bugprone-empty-catch): the pre-built row text stands
    }
    try {
        threw.audit_persisted =
            ports.audit(std::string(kActionExecute), "failure", target_id, threw_detail);
    } catch (...) {
        threw.audit_persisted = false;
    }
    try {
        if (ports.count_run_threw)
            ports.count_run_threw();
    } catch (...) { // NOLINT(bugprone-empty-catch): observability must not fail the answer
    }
    threw.agents_sent = progress.agents_sent;
    threw.late_denied = progress.late_denied;
    try {
        threw.execution_id = progress.execution_id;
        threw.steps = std::move(progress.notes);
    } catch (...) { // NOLINT(bugprone-empty-catch): the typed fields above stand
    }
    return threw;
}

WorkflowExecuteOutcome apply_workflow_execute(const WorkflowExecutePorts& ports,
                                              const WorkflowExecuteRequest& req) {
    auto plan = prepare_workflow_execute(ports, req);
    if (!plan)
        return std::move(plan.error());
    return run_workflow_execute(ports, req, *plan);
}

} // namespace yuzu::server
