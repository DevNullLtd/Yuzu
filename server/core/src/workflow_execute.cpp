#include "workflow_execute.hpp"

#include "compliance_eval.hpp"
#include "dispatch_denial_text.hpp"
#include "dispatch_send_progress.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_target_shape.hpp"
#include "instruction_execute.hpp" // definition_id_is_malformed (the one id predicate)
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
#include <chrono>
#include <map>
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

std::optional<WorkflowExecuteOutcome> workflow_wiring_refusal(const WorkflowExecutePorts& ports,
                                                              const WorkflowExecuteRequest& req);

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
            std::string(kReasonWorkflowAgentIdsRequired),
            "agent_ids (a non-empty array of agent id strings) is required; a workflow run "
            "names its devices explicitly"});
    if (const auto v = check_targeting_shape(body))
        return std::unexpected(WorkflowExecuteBodyError{v->reason, v->message});

    const auto& arr = body["agent_ids"]; // array, non-empty, all strings: the shape check proved it
    if (arr.size() > mcp::kExecInstrAgentIdsMaxItems)
        return std::unexpected(WorkflowExecuteBodyError{
            std::string(kReasonWorkflowAgentIdsCount), "agent_ids may name at most " +
                                   std::to_string(mcp::kExecInstrAgentIdsMaxItems) + " agents"});
    std::vector<std::string> ids;
    ids.reserve(arr.size());
    for (const auto& v : arr) {
        const auto& s = v.get_ref<const std::string&>();
        if (s.empty() || s.size() > mcp::kExecInstrIdentMaxLen)
            return std::unexpected(WorkflowExecuteBodyError{
                std::string(kReasonWorkflowAgentIdLen), "each agent id must be 1 to " +
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
                            {"attempt", n.attempt},
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

// ── idempotency ───────────────────────────────────────────────────────────

namespace {

constexpr std::string_view kFingerprintDomain = "wf-exec-v2\n";

bool idempotency_key_char_ok(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == ':' || c == '-';
}

void count_idempotent(const WorkflowExecutePorts& ports, std::string_view outcome) {
    if (!ports.count_idempotent)
        return;
    try {
        ports.count_idempotent(outcome);
    } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail an answer
    }
}

/// The idempotent-counter outcome of a replay that was answered: `in_progress` while the run is
/// running, `indeterminate` when the replay body says so, `replayed` otherwise.
std::string_view replay_counter_outcome(const WorkflowExecuteOutcome& o) {
    if (o.replay_status == kReplayRunning)
        return "in_progress";
    if (o.replay_status == kReplayIndeterminate)
        return kWorkflowRunIdempotentIndeterminate;
    return "replayed";
}

/// Counts the run's first answer on `kWorkflowRunOutcomeMetric`. Never throws.
void count_run_outcome(const WorkflowExecutePorts& ports, std::string_view outcome,
                       std::string_view reason) noexcept {
    if (!ports.count_run_outcome)
        return;
    try {
        ports.count_run_outcome(outcome, reason);
    } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail an answer
    }
}

std::int64_t epoch_now(const WorkflowExecutePorts& ports) {
    if (ports.now_epoch)
        return ports.now_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// The replay `status` token of a class a stored run was judged to be.
std::string_view replay_token_for(WorkflowRunOutcome outcome) {
    switch (outcome) {
    case WorkflowRunOutcome::kSucceeded:
        return kReplayCompleted;
    case WorkflowRunOutcome::kPartial:
        return kReplayPartial;
    case WorkflowRunOutcome::kFailed:
        return kReplayFailed;
    case WorkflowRunOutcome::kAborted:
        return kReplayAborted;
    case WorkflowRunOutcome::kInterrupted:
        return kReplayInterrupted;
    }
    return kReplayIndeterminate;
}

/// What a replay of the run says. A `running`/`pending` row is `running` only while its age is
/// believable: past the stale bound, or dated further in the future than that (a replica clock far
/// ahead would otherwise leave it `running` for as long as the skew), it is `indeterminate`. A
/// TERMINAL row is judged from its stored steps, never from the engine's status alone: that status
/// says `completed` for a run whose `onFailure: continue` step reached nobody. What the rows
/// cannot prove is never `completed`: unreadable or unsettled rows are `indeterminate` for a run
/// the engine called completed and `failed` for one it called failed or cancelled. An unknown
/// engine status is `indeterminate` too.
std::string_view replay_status_for(const WorkflowExecutePorts& ports,
                                   const WorkflowIdempotentRun& run, std::int64_t now) {
    const std::string_view engine_status = run.status;
    if (engine_status == "running" || engine_status == "pending") {
        const std::int64_t age = now - run.started_at;
        const std::int64_t bound = kIdempotentRunStaleAfter.count();
        return (age > bound || -age > bound) ? kReplayIndeterminate : kReplayRunning;
    }
    if (engine_status != "completed" && engine_status != "failed" && engine_status != "cancelled")
        return kReplayIndeterminate;

    // The steps are read only for a terminal run: a client polling a live one costs no extra read.
    // A read that fails or throws is "could not prove", the same as rows that do not add up.
    try {
        const auto stored = ports.api->get_workflow_execution(run.execution_id);
        if (!stored) {
            spdlog::warn("workflow execute: replay step read failed: {}",
                         genericize_db_error("workflow replay step read", stored.error()));
        } else if (*stored && (*stored)->status == engine_status) {
            // Two reads of one terminal row must agree before the rows are believed: a terminal
            // status is final, so a disagreement is a row nobody can vouch for.
            if (const auto outcome = classify_stored_workflow_run(**stored))
                return replay_token_for(*outcome);
        }
    } catch (const std::exception& e) {
        spdlog::warn("workflow execute: replay step read threw: {}", e.what());
    } catch (...) {
        spdlog::warn("workflow execute: replay step read threw a non-standard exception");
    }
    return engine_status == "completed" ? kReplayIndeterminate : kReplayFailed;
}

WorkflowExecuteOutcome replay_outcome(const WorkflowExecutePorts& ports,
                                      const WorkflowIdempotentRun& run) {
    WorkflowExecuteOutcome o;
    o.status = WorkflowExecuteStatus::kIdempotentReplay;
    o.idempotent_replay = true;
    o.execution_id = run.execution_id;
    o.run_status = run.status;
    o.started_at = run.started_at;
    o.replay_status = std::string(replay_status_for(ports, run, epoch_now(ports)));
    o.reason = "idempotent_replay";
    o.retryable = o.replay_status == kReplayRunning;
    // The stored steps cannot prove a send was absent (the command id is written after the
    // dispatch returns, and that write can be dropped), so the one remediation for every terminal
    // class says so; a step left running, or stored failed by a throw, is no better evidence.
    const std::string read_and_rerun =
        "read the run for what ran (MCP get_workflow_execution, REST "
        "GET /api/v1/workflow-executions/{id}); " + std::string(kStepNotProvenUnsentText) +
        "; a step left running, or recorded failed because its dispatch threw, may have been sent "
        "too; a deliberate re-run needs a new idempotency key";
    if (o.replay_status == kReplayRunning) {
        o.message = "this idempotency key is bound to a run that is still in progress; nothing was "
                    "sent for this call";
        o.remediation = "poll the run on the execution_id (MCP get_workflow_execution, REST "
                        "GET /api/v1/workflow-executions/{id}); do not send this call again";
    } else if (o.replay_status == kReplayCompleted) {
        o.message = "this idempotency key is bound to a run that already completed; nothing was "
                    "sent for this call";
    } else if (o.replay_status == kReplayPartial) {
        o.message = "this idempotency key is bound to a run that sent some steps but did not "
                    "complete on every step; nothing was sent for this call";
        o.remediation = read_and_rerun;
    } else if (o.replay_status == kReplayAborted) {
        o.message = "this idempotency key is bound to a run in which a step was refused at dispatch, "
                    "or that reached its time budget or lost its credential; a step after a "
                    "refused one may still have run; nothing was sent for this call";
        o.remediation = read_and_rerun;
    } else if (o.replay_status == kReplayInterrupted) {
        o.message = "this idempotency key is bound to a run that the server's shutdown stopped; "
                    "nothing was sent for this call";
        o.remediation = read_and_rerun;
    } else if (o.replay_status == kReplayFailed) {
        o.message = "this idempotency key is bound to a run that failed; nothing was sent for "
                    "this call";
        o.remediation = read_and_rerun;
    } else {
        o.message = "this idempotency key is bound to a run whose outcome could not be confirmed; "
                    "nothing was sent for this call";
        o.remediation = "read the run (MCP get_workflow_execution, REST GET "
                        "/api/v1/workflow-executions/{id}); " +
                        std::string(kStepNotProvenUnsentText) +
                        "; if the run may still be live, wait for it before re-running; a "
                        "deliberate re-run needs a new key";
    }
    return o;
}

WorkflowExecuteOutcome conflict_outcome(const std::string& bound_execution_id) {
    WorkflowExecuteOutcome o = refuse(
        WorkflowExecuteStatus::kIdempotencyConflict,
        "this idempotency key is already bound to a different request; nothing was sent",
        "idempotency_key_conflict");
    o.execution_id = bound_execution_id;
    o.remediation = "use a new idempotency key for a different request; this key stays bound to "
                    "the run it started, readable with get_workflow_execution";
    return o;
}

} // namespace

std::optional<WorkflowExecuteBodyError> check_workflow_id(std::string_view id) {
    if (id.empty() || id.size() > mcp::kExecInstrIdentMaxLen ||
        instruction_execute::definition_id_is_malformed(id))
        return WorkflowExecuteBodyError{
            "invalid_workflow_id",
            "the workflow id must be 1 to " + std::to_string(mcp::kExecInstrIdentMaxLen) +
                " bytes of valid UTF-8 with no control byte (below 0x20 or 0x7F); re-call with "
                "the id exactly as the workflow list returns it"};
    return std::nullopt;
}

std::string workflow_audit_prefix(const WorkflowExecuteRequest& req) {
    std::string out = req.audit_context;
    if (!req.correlation_id.empty())
        out += " correlation_id=" + ::yuzu::log_token(req.correlation_id);
    if (!req.approval_id.empty())
        out += " approval_id=" + clip_token(req.approval_id);
    return out;
}

std::string workflow_audit_target(std::string_view workflow_id) {
    std::string target = instruction_execute::bounded_definition_id(workflow_id);
    if (instruction_execute::definition_id_needs_audit_fold(workflow_id))
        target = ::yuzu::log_token(target);
    return target;
}

bool audit_workflow_pre_core_denial(const WorkflowAuditFn& audit, std::string_view audit_context,
                                    std::string_view correlation_id, std::string_view reason,
                                    std::string_view workflow_id) {
    try {
        if (!audit)
            return false;
        return audit(std::string(kActionExecute), "denied", workflow_audit_target(workflow_id),
                     std::string(audit_context) +
                         " correlation_id=" + ::yuzu::log_token(std::string(correlation_id)) +
                         " reason=" + ::yuzu::log_token(std::string(reason)) + " workflow=" +
                         ::yuzu::log_token(instruction_execute::bounded_definition_id(workflow_id)));
    } catch (...) {
        return false;
    }
}

std::optional<WorkflowExecuteBodyError> check_workflow_idempotency_key(std::string_view key) {
    if (key.size() < kIdempotencyKeyMinLen || key.size() > kIdempotencyKeyMaxLen ||
        !std::all_of(key.begin(), key.end(), idempotency_key_char_ok))
        return WorkflowExecuteBodyError{
            "idempotency_key_invalid",
            "the idempotency key must be " + std::to_string(kIdempotencyKeyMinLen) + " to " +
                std::to_string(kIdempotencyKeyMaxLen) +
                " characters from A-Z a-z 0-9 . _ : -"};
    return std::nullopt;
}

std::optional<std::string> workflow_request_fingerprint(const WorkflowExecutePorts& ports,
                                                        const std::string& workflow_id,
                                                        const std::vector<std::string>& agent_ids) {
    // Sorted and deduped INSIDE the fingerprint only: the same set of devices in another order
    // is the same request, and the ticket's canonical arguments are untouched.
    std::set<std::string_view> ids;
    for (const auto& id : agent_ids)
        ids.insert(id);
    // Every field is `<byte length>:<bytes>`: an id holding any byte, `\n` and digits included,
    // cannot move a field boundary, so two different requests never share a preimage.
    std::string material(kFingerprintDomain);
    const auto frame = [&material](std::string_view field) {
        material += std::to_string(field.size());
        material += ':';
        material += field;
    };
    frame(workflow_id);
    for (const auto id : ids)
        frame(id);
    const auto digest = ports.fingerprint_digest ? ports.fingerprint_digest(material)
                                                 : sha256_hex(material);
    if (!digest || digest->size() != 64)
        return std::nullopt;
    return digest;
}

std::optional<WorkflowExecuteOutcome> check_workflow_idempotency(const WorkflowExecutePorts& ports,
                                                                 const WorkflowExecuteRequest& req) {
    if (req.idempotency_key.empty())
        return std::nullopt;
    // The wiring check, the same one prepare runs: a deployment that could not run the workflow
    // does not answer from a key either.
    if (auto refusal = workflow_wiring_refusal(ports, req))
        return refusal;
    // The lookup is wired with the run port in server.cpp; a build without it cannot honour a key,
    // and answering "no run bound" would dispatch a repeat. Fail closed.
    if (!ports.idempotency_lookup)
        return refuse(WorkflowExecuteStatus::kUnavailable, "workflow engine not available",
                      "workflow_engine_unavailable");
    // A key belongs to a principal. An empty one is refused whoever the caller is, `system`
    // included: under the store's unique index a NULL principal never conflicts, so the key
    // would silently stop being idempotent.
    if (req.caller.principal.empty())
        return refuse(WorkflowExecuteStatus::kNoPrincipal,
                      "an idempotency key needs an authenticated principal",
                      "idempotency_requires_principal");

    const std::string target_id = clip_token(req.workflow_id);
    const std::string key_detail = " idempotency_key=" + clip_token(req.idempotency_key);
    const auto fingerprint = workflow_request_fingerprint(ports, req.workflow_id, req.agent_ids);
    if (!fingerprint) {
        (void)ports.audit(std::string(kActionExecute), "failure", target_id,
                          workflow_audit_prefix(req) + " reason=request_fingerprint_unavailable" +
                              key_detail);
        return refuse(WorkflowExecuteStatus::kEffectDigestFailed,
                      "the request could not be fingerprinted for its idempotency key",
                      "request_fingerprint_unavailable");
    }

    const auto bound = ports.idempotency_lookup(req.caller, req.idempotency_key);
    if (!bound) {
        // A fault is NOT "no run bound": proceeding would dispatch, and the whole point of the
        // key is that a call whose first answer was lost cannot be sent twice. Nothing is written.
        spdlog::warn("workflow execute: idempotency lookup failed: {}",
                     genericize_db_error("workflow idempotency lookup", bound.error()));
        return refuse(WorkflowExecuteStatus::kStoreFailed, "workflow store unavailable",
                      "store_unavailable", /*retryable=*/true);
    }
    if (!*bound)
        return std::nullopt;
    const WorkflowIdempotentRun& run = **bound;

    if (run.request_fingerprint != *fingerprint) {
        (void)ports.audit(std::string(kActionExecute), "denied", target_id,
                          workflow_audit_prefix(req) + " reason=idempotency_key_conflict execution_id=" +
                              clip_token(run.execution_id) + key_detail);
        count_idempotent(ports, "conflict");
        return conflict_outcome(run.execution_id);
    }

    WorkflowExecuteOutcome o = replay_outcome(ports, run);
    if (o.replay_status == kReplayRunning) {
        // No audit row: a client polling a running run would write one per poll.
        count_idempotent(ports, "in_progress");
        return o;
    }
    o.audit_persisted = ports.audit(
        std::string(kActionExecute), "success", target_id,
        workflow_audit_prefix(req) + " execution_id=" + clip_token(run.execution_id) +
            " idempotent_replay=true run_status=" + o.replay_status + key_detail);
    count_idempotent(ports, replay_counter_outcome(o));
    return o;
}

nlohmann::json workflow_idempotent_replay_json(const WorkflowExecuteOutcome& o,
                                               const std::string& workflow_id) {
    nlohmann::json j = {{"execution_id", o.execution_id},
                        {"workflow_id", workflow_id},
                        {"status", o.replay_status},
                        {"idempotent_replay", true},
                        {"started_at", o.started_at},
                        {"message", o.message}};
    if (o.replay_status == kReplayRunning) {
        j["retry_after_ms"] = kIdempotentRunningRetryAfterMs;
    } else if (o.replay_status != kReplayCompleted) {
        j["retryable"] = false;
        if (!o.remediation.empty())
            j["remediation"] = o.remediation;
    }
    if (!o.audit_persisted)
        j["audit_persisted"] = false;
    return j;
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

namespace {

/// The zero-reach causes a workflow step's dispatch can note (`classify_zero_reach` minus
/// `invalid_scope`: a workflow names its agents, so the dispatch never parses a scope).
constexpr std::array<std::string_view, 8> kStepZeroReachCauses{
    zero_reach_token(ZeroReachCause::Denied),
    zero_reach_token(ZeroReachCause::ContainmentUnreadable),
    zero_reach_token(ZeroReachCause::RouteUnreadable),
    zero_reach_token(ZeroReachCause::OsGateUnreadable),
    zero_reach_token(ZeroReachCause::Generic),
    zero_reach_token(ZeroReachCause::Quarantined),
    zero_reach_token(ZeroReachCause::PluginNotFound),
    zero_reach_token(ZeroReachCause::KillSwitchedOs)};

constexpr std::string_view kReasonDeadlineExceeded = "deadline_exceeded";
constexpr std::string_view kReasonServerShutdown = "server_shutdown";
constexpr std::string_view kReasonLateDenied = "late_denied";
constexpr std::string_view kReasonDefinitionChanged = "definition_changed";
constexpr std::string_view kReasonRunFailed = "run_failed";

std::vector<WorkflowRunOutcomeSeries> build_outcome_series() {
    std::vector<WorkflowRunOutcomeSeries> v;
    const auto outcome = [](WorkflowRunOutcome o) { return workflow_run_outcome_token(o); };
    v.push_back({outcome(WorkflowRunOutcome::kSucceeded), kWorkflowRunReasonNone});
    v.push_back({outcome(WorkflowRunOutcome::kPartial), kWorkflowRunReasonNone});
    v.push_back({outcome(WorkflowRunOutcome::kInterrupted), kReasonServerShutdown});
    for (const auto cause : kStepZeroReachCauses)
        v.push_back({outcome(WorkflowRunOutcome::kFailed), cause});
    v.push_back({outcome(WorkflowRunOutcome::kFailed), kReasonRunFailed});
    v.push_back({outcome(WorkflowRunOutcome::kFailed), kWorkflowRunReasonDispatchException});
    for (const auto reason : {kReasonDeadlineExceeded, kReasonServerShutdown,
                              kReasonCredentialRevoked, kReasonCredentialIndeterminate,
                              kReasonLateDenied, kReasonDefinitionChanged})
        v.push_back({outcome(WorkflowRunOutcome::kAborted), reason});
    for (const auto cause : kStepZeroReachCauses)
        v.push_back({outcome(WorkflowRunOutcome::kAborted), cause});
    return v;
}

} // namespace

const std::vector<WorkflowRunOutcomeSeries>& workflow_run_outcome_series() {
    static const std::vector<WorkflowRunOutcomeSeries> series = build_outcome_series();
    return series;
}

std::string_view workflow_run_outcome_reason(const WorkflowExecuteOutcome& o) {
    if (o.deadline_exceeded)
        return kReasonDeadlineExceeded;
    if (o.interrupted)
        return kReasonServerShutdown;
    if (o.credential_stop == kReasonCredentialRevoked)
        return kReasonCredentialRevoked;
    if (o.credential_stop == kReasonCredentialIndeterminate)
        return kReasonCredentialIndeterminate;
    if (o.status == WorkflowExecuteStatus::kNoAgentsReached) {
        for (const auto& known : workflow_run_outcome_series()) {
            if (known.reason == o.reason)
                return known.reason; // the series' own constant: the view never aliases `o`
        }
        return kWorkflowRunReasonNone;
    }
    if (o.run_outcome == WorkflowRunOutcome::kAborted) {
        for (const auto& n : o.steps) {
            if (n.agents_reached == 0 && n.reason == kReasonDefinitionChanged)
                return kReasonDefinitionChanged;
            if (n.agents_reached == 0 && n.reason == kReasonLateDenied)
                return kReasonLateDenied;
        }
        return kReasonLateDenied;
    }
    return kWorkflowRunReasonNone;
}

std::function<void(std::string_view, std::string_view)>
make_workflow_run_outcome_counter(yuzu::MetricsRegistry* metrics) {
    if (!metrics)
        return {};
    return [metrics](std::string_view outcome, std::string_view reason) {
        try {
            metrics
                ->counter(kWorkflowRunOutcomeMetric,
                          {{"outcome", std::string(outcome)}, {"reason", std::string(reason)}})
                .increment();
        } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail an answer
        }
    };
}

void seed_workflow_run_metrics(yuzu::MetricsRegistry& metrics) {
    for (const auto reason : workflow_target_reject_reasons())
        metrics.counter("yuzu_server_dispatch_target_rejected_total",
                        {{"route", "workflow"}, {"reason", std::string(reason)}});
    for (const auto reason : kWorkflowRunRefusedReasons)
        metrics.counter(kWorkflowRunRefusedMetric, {{"reason", std::string(reason)}});
    for (const auto outcome : kWorkflowRunIdempotentOutcomes)
        metrics.counter(kWorkflowRunIdempotentMetric, {{"outcome", std::string(outcome)}});
    for (const auto& series : workflow_run_outcome_series())
        metrics.counter(kWorkflowRunOutcomeMetric, {{"outcome", std::string(series.outcome)},
                                                    {"reason", std::string(series.reason)}});
}

std::vector<std::string_view> workflow_target_reject_reasons() {
    return {kReasonBodyType,           kReasonScopeUnsupported,
            kReasonWorkflowAgentIdsRequired, kReasonAgentIdsType,
            kReasonAgentIdsEmpty,      kReasonAgentIdType,
            kReasonWorkflowAgentIdsCount, kReasonWorkflowAgentIdLen,
            kReasonDestructiveUntargeted, kReasonForensicUntargeted,
            kReasonDestructiveNoVisibleTarget};
}

WorkflowRunOutcome classify_workflow_run(std::string_view run_status, const WorkflowRunFacts& facts,
                                         const std::vector<WorkflowStepFinal>& finals) {
    if (facts.threw)
        return WorkflowRunOutcome::kFailed;
    if (facts.late_denied || facts.bound_stop)
        return WorkflowRunOutcome::kAborted;
    if (facts.interrupted)
        return WorkflowRunOutcome::kInterrupted;
    const bool any_sent = std::any_of(finals.begin(), finals.end(),
                                      [](const auto& f) { return f.sent; });
    const bool all_reached = std::all_of(finals.begin(), finals.end(),
                                         [](const auto& f) { return f.reached; });
    // Only the engine's own "completed" counts: "unknown" (unreadable), "running" (a finalize
    // that did not land), "failed" and "cancelled" are all not success.
    if (run_status == "completed" && all_reached)
        return WorkflowRunOutcome::kSucceeded;
    return any_sent ? WorkflowRunOutcome::kPartial : WorkflowRunOutcome::kFailed;
}

std::vector<WorkflowStepFinal> workflow_step_finals(const std::vector<WorkflowStepDispatchNote>& notes,
                                                    const std::map<int, int>& attempts) {
    std::vector<WorkflowStepFinal> out;
    for (const auto& [step_index, last_attempt] : attempts) {
        WorkflowStepFinal f{.step_index = step_index, .attempt = last_attempt};
        bool any_note_at_last = false;
        bool every_note_at_last_reached = true;
        for (const auto& n : notes) {
            if (n.step_index != step_index)
                continue;
            if (n.agents_reached > 0)
                f.sent = true;
            if (n.attempt != last_attempt)
                continue;
            any_note_at_last = true;
            every_note_at_last_reached = every_note_at_last_reached && n.agents_reached > 0;
        }
        f.reached = any_note_at_last && every_note_at_last_reached;
        out.push_back(f);
    }
    // A note nobody attributed to a step (a run port that never announces attempts) is its own step.
    for (const auto& n : notes) {
        if (n.step_index >= 0)
            continue;
        const bool reached = n.agents_reached > 0;
        out.push_back(WorkflowStepFinal{.step_index = -1,
                                        .attempt = n.attempt,
                                        .reached = reached,
                                        .sent = reached});
    }
    return out;
}

namespace {

/// What one stored step result says beyond its status. Read defensively: a result is an object
/// for a dispatched step, an array of `{"error": ...}` placeholders for a failed one, and `{}`
/// for a step never begun; nothing here may throw out of a replay.
struct StoredStepMarkers {
    bool run_stopped{false};
    bool shutdown{false};
    bool threw{false};
    bool late_denied{false};
    bool condition_not_met{false};
};

void read_step_markers(const nlohmann::json& j, StoredStepMarkers& m) {
    if (!j.is_object())
        return;
    if (const auto it = j.find("reason"); it != j.end() && it->is_string()) {
        const auto& r = it->get_ref<const std::string&>();
        if (r == kStepReasonRunStopped)
            m.run_stopped = true;
        else if (r == kStepReasonServerShutdown)
            m.shutdown = true;
        else if (r == kStepReasonDispatchException)
            m.threw = true;
        else if (r == kStepReasonConditionNotMet)
            m.condition_not_met = true;
    }
    if (const auto it = j.find("error"); it != j.end() && it->is_string()) {
        const auto& e = it->get_ref<const std::string&>();
        if (e.starts_with(kStepErrorLateDenied) || e.starts_with(kStepErrorDefinitionChanged))
            m.late_denied = true;
    }
}

StoredStepMarkers stored_step_markers(const std::string& result_json) {
    constexpr std::size_t kMaxParse = 256 * 1024; // a placeholder is a few hundred bytes
    StoredStepMarkers m;
    if (result_json.size() > kMaxParse)
        return m;
    const auto j = nlohmann::json::parse(result_json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded())
        return m;
    if (j.is_array()) {
        for (const auto& e : j)
            read_step_markers(e, m);
    } else {
        read_step_markers(j, m);
    }
    return m;
}

} // namespace

std::optional<WorkflowRunOutcome> classify_stored_workflow_run(const WorkflowExecution& stored) {
    if (stored.status != "completed" && stored.status != "failed" && stored.status != "cancelled")
        return std::nullopt;
    const bool completed = stored.status == "completed";
    WorkflowRunFacts facts;
    std::vector<WorkflowStepFinal> finals;
    bool unproven = stored.step_results.empty(); // a run always has its step rows
    for (const auto& r : stored.step_results) {
        const int attempt = std::max(r.attempt, 1);
        if (r.status == "success") {
            finals.push_back({.step_index = r.step_index, .attempt = attempt, .reached = true,
                              .sent = true});
        } else if (r.status == "failed") {
            const auto m = stored_step_markers(r.result_json);
            facts.late_denied = facts.late_denied || m.late_denied;
            facts.bound_stop = facts.bound_stop || m.run_stopped;
            facts.interrupted = facts.interrupted || m.shutdown;
            facts.threw = facts.threw || m.threw;
            finals.push_back({.step_index = r.step_index, .attempt = attempt, .reached = false,
                              .sent = false});
        } else if (r.status == "skipped") {
            const auto m = stored_step_markers(r.result_json);
            facts.bound_stop = facts.bound_stop || m.run_stopped;
            facts.interrupted = facts.interrupted || m.shutdown;
            // A skip a completed run can legitimately hold is its own condition's, or a stop's.
            if (!m.condition_not_met && !m.run_stopped && !m.shutdown)
                unproven = true;
        } else {
            unproven = true; // pending / running / unknown: the engine never settled this step
        }
    }
    // A run the engine did not fail must have every step accounted for. A failed or cancelled
    // one may legitimately hold unstarted steps, and is a non-success whatever they were.
    if (completed && unproven)
        return std::nullopt;
    return classify_workflow_run(stored.status, facts, finals);
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
    const auto refuse_draining = [&] {
        count(kWorkflowRunRefusedDraining);
        out.refusal = refuse(WorkflowExecuteStatus::kDraining,
                             "the server is shutting down and is not starting new workflow runs",
                             kWorkflowRunRefusedDraining, /*retryable=*/true);
        out.refusal->remediation =
            "retry after the server restarts, or against another replica; nothing was sent";
    };
    // Draining first: StreamBudget::try_acquire does not consult its closing flag, and a run
    // admitted now would hold the drain open for up to the whole run budget.
    if (draining && draining()) {
        refuse_draining();
        return out;
    }
    if (!budget)
        return out; // unmetered seam (test harness)
    auto acquired = budget->try_acquire(detail::SseSurface::kWorkflowRun, principal,
                                        detail::kPerPrincipalWorkflowRun);
    if (acquired.lease) {
        // Asked again now the lease is held: the shutdown drain counts leases under the budget's
        // mutex after it sets the flag, so a lease it did not count was taken after this read.
        if (draining && draining()) {
            refuse_draining(); // `acquired.lease` releases on the way out
            return out;
        }
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

namespace {

/// Step 1 of the banner, one copy for `prepare_workflow_execute` and the idempotency pre-check:
/// every port the sequence needs is wired, and the caller has a principal. A replay is refused
/// when the deployment could not run the workflow either (fail closed), so an unwired build
/// never answers from a key.
std::optional<WorkflowExecuteOutcome> workflow_wiring_refusal(const WorkflowExecutePorts& ports,
                                                              const WorkflowExecuteRequest& req) {
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
    if (!ports.classify || !ports.authorize || !ports.dispatch || !ports.audit)
        return refuse(WorkflowExecuteStatus::kUnavailable, "workflow dispatch not available",
                      "dispatch_unavailable");
    if (req.caller.principal.empty() && !req.caller.system)
        return refuse(WorkflowExecuteStatus::kNoPrincipal, "authenticated session has no principal",
                      "no_principal");
    return std::nullopt;
}

} // namespace

std::expected<WorkflowExecutePlan, WorkflowExecuteOutcome>
prepare_workflow_execute(const WorkflowExecutePorts& ports, const WorkflowExecuteRequest& req) {
    // ── 1. wiring: fail CLOSED, before any read or effect ────────────────
    if (auto refusal = workflow_wiring_refusal(ports, req))
        return std::unexpected(std::move(*refusal));

    const std::string target_id = clip_token(req.workflow_id);
    auto deny_audit = [&](std::string_view reason, const std::string& extra) {
        // Set-and-proceed: nothing has been dispatched on a refusal, so a lost denial row does
        // not change what the caller is told; the persist outcome is deliberately not consulted.
        (void)ports.audit(std::string(kActionExecute), "denied", target_id,
                          workflow_audit_prefix(req) + " reason=" + std::string(reason) + extra);
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
    /// The step and attempt the engine announced last (`WorkflowRunControl::on_attempt`), stamped
    /// on every note the dispatch callback records, and the last attempt announced per step: what
    /// `workflow_step_finals` judges the run by.
    int current_step{-1};
    int current_attempt{1};
    std::map<int, int> attempts;
    bool late_denied{false};
    /// The engine asked `before_attempt` after the deadline and was told to stop.
    bool deadline_hit{false};
    /// The engine ended the run because the server is stopping (`on_interrupted`).
    bool interrupted{false};
    /// The credential check refused an attempt: `kReasonCredentialRevoked` or
    /// `kReasonCredentialIndeterminate`. Set at the moment the hook says no.
    std::string credential_stop;
    /// The engine's atomic claim found the key already bound to a run (`on_replay`): this call
    /// lost the race and starts nothing.
    std::optional<WorkflowRunReplay> replay;
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
                                 const std::optional<WorkflowIdempotencyClaim>& claim,
                                 RunProgress& progress) {
    const std::string target_id = clip_token(req.workflow_id);
    auto deny_audit = [&](std::string_view reason, const std::string& extra) {
        (void)ports.audit(std::string(kActionExecute), "denied", target_id,
                          workflow_audit_prefix(req) + " reason=" + std::string(reason) + extra);
    };
    auto count_rejected = [&](std::string_view reason) {
        if (ports.count_target_rejected)
            ports.count_target_rejected(reason);
    };

    // ── 6. run: the engine drives the steps synchronously through this callback ──
    std::vector<WorkflowStepDispatchNote>& notes = progress.notes;
    bool& late_denied = progress.late_denied;
    // Every note belongs to the step and attempt the engine announced just before the callback.
    const auto stamped = [&progress](WorkflowStepDispatchNote n) {
        n.step_index = progress.current_step;
        n.attempt = progress.current_attempt;
        return n;
    };
    // The note of a step refused at send time: nothing was sent, `reason` says why.
    const auto refused_note = [&stamped](const std::string& instruction_id, const char* reason) {
        WorkflowStepDispatchNote n;
        n.instruction_id = instruction_id;
        n.reason = reason;
        return stamped(std::move(n));
    };
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
            notes.push_back(refused_note(instruction_id, "definition_changed"));
            // Permanent: the definition will not move back, and a retry would audit the same
            // refusal again after a sleep. The prefix is what the stored step result keeps of
            // the refusal (kStepErrorDefinitionChanged).
            return std::unexpected(StepDispatchError{
                std::string(kStepErrorDefinitionChanged) +
                    "step definition changed after approval; refused",
                true});
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
            notes.push_back(refused_note(instruction_id, "late_denied"));
            // Permanent, as above: an authorization refusal never improves with a retry. The
            // prefix is what the stored step result keeps of the refusal (kStepErrorLateDenied).
            switch (d.verdict) {
            case StepAdmission::kApprovalRequired:
                return std::unexpected(StepDispatchError{
                    std::string(kStepErrorLateDenied) + "step now requires approval; refused",
                    true});
            case StepAdmission::kUnclassified:
                return std::unexpected(StepDispatchError{
                    std::string(kStepErrorLateDenied) +
                        "step is not in the capability catalogue; refused",
                    true});
            default:
                return std::unexpected(StepDispatchError{
                    std::string(kStepErrorLateDenied) + std::string(d.message), true});
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
        WorkflowStepDispatchNote note = stamped({});
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
    control.principal = req.caller.principal;
    control.correlation_id = clip_token(req.correlation_id);
    control.on_interrupted = [&progress] { progress.interrupted = true; };
    control.stored_copy_first = [&req](const std::string& id) {
        return authz::in_scope(req.caller.exec_visible, id);
    };
    control.on_attempt = [&progress](int step_index, int attempt) {
        progress.current_step = step_index;
        progress.current_attempt = attempt;
        progress.attempts[step_index] = attempt;
    };
    if (claim) {
        control.idempotency = claim;
        control.on_replay = [&progress](const WorkflowRunReplay& r) { progress.replay = r; };
    }
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
    if (!run && progress.replay) {
        // The race: this call passed the pre-check, wrote its `requested` row, and lost the
        // engine's atomic claim to a call with the same key. Nothing was dispatched. Close the
        // row it opened and answer as the pre-check would have.
        const WorkflowRunReplay& won = *progress.replay;
        const bool differs = !claim || won.fingerprint != claim->fingerprint;
        (void)ports.audit(std::string(kActionExecute), "denied", target_id,
                          workflow_audit_prefix(req) + " reason=" +
                              (differs ? "idempotency_key_conflict" : "idempotent_duplicate") +
                              " execution_id=" + clip_token(won.execution_id) +
                              " idempotency_key=" + clip_token(req.idempotency_key));
        if (differs) {
            count_idempotent(ports, "conflict");
            return conflict_outcome(won.execution_id);
        }
        WorkflowExecuteOutcome o = replay_outcome(
            ports, WorkflowIdempotentRun{won.execution_id, won.workflow_id, won.fingerprint,
                                         won.status, won.started_at});
        count_idempotent(ports, replay_counter_outcome(o));
        return o;
    }
    if (!run) {
        const bool db = is_generic_db_error(run.error());
        const bool gone = run.error().starts_with("workflow not found");
        const auto status = db ? WorkflowExecuteStatus::kStoreFailed
                               : gone ? WorkflowExecuteStatus::kWorkflowNotFound
                                      : WorkflowExecuteStatus::kExecuteFailed;
        const std::string msg = db ? "workflow store unavailable"
                                   : gone ? "workflow not found" : run.error();
        (void)ports.audit(std::string(kActionExecute), "failure", target_id,
                          workflow_audit_prefix(req) + " reason=" +
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
    // The judgement is over each step's FINAL outcome, the function the idempotent replay feeds
    // from the stored rows: a step that failed and was retried to success is reached, a step the
    // engine left failed (onFailure: continue) is not.
    const auto finals = workflow_step_finals(o.steps, progress.attempts);
    o.run_outcome = classify_workflow_run(
        o.run_status,
        WorkflowRunFacts{.late_denied = late_denied,
                         .bound_stop = o.deadline_exceeded || !o.credential_stop.empty(),
                         .interrupted = o.interrupted},
        finals);
    const bool any_reached = std::any_of(finals.begin(), finals.end(),
                                         [](const auto& f) { return f.sent; });
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
                  "dispatch (its approval mode was raised or its definition changed); a step after "
                  "it may still have run when it was an onFailure: continue step, so read the "
                  "steps with get_workflow_execution before starting another"
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
        if (claim) {
            // The key was bound to this run when the engine admitted it, so a repeat of the same
            // call replays this failure and never runs again: a cause that would have been
            // retryable unkeyed is not retryable here, and no step's own flag may say otherwise.
            o.retryable = false;
            o.remediation = std::string(kKeyedRetryRemediation);
            for (auto& n : o.steps) {
                if (n.agents_reached == 0)
                    n.retryable = false;
            }
        }
    }

    const bool succeeded = o.status == WorkflowExecuteStatus::kOk;
    std::size_t reached_total = 0;
    for (const auto& n : o.steps)
        reached_total += static_cast<std::size_t>(n.agents_reached);
    o.audit_persisted = ports.audit(
        std::string(kActionExecute), succeeded ? "success" : "failure", target_id,
        workflow_audit_prefix(req) + " execution_id=" + clip_token(o.execution_id) +
            " run_status=" + clip_token(o.run_status) +
            " dispatches=" + std::to_string(o.steps.size()) +
            " agents_reached=" + std::to_string(reached_total) +
            (late_denied ? " late_denied=true" : "") +
            (req.idempotency_key.empty()
                 ? ""
                 : " idempotency_key=" + clip_token(req.idempotency_key)) +
            (succeeded ? ""
                       : " run_outcome=" + std::string(workflow_run_outcome_token(o.run_outcome))) +
            (o.status == WorkflowExecuteStatus::kNoAgentsReached || o.deadline_exceeded ||
                     o.interrupted || !o.credential_stop.empty()
                 ? " reason=" + o.reason
                 : ""));
    // The first answer of a classified run, once: after the evidence row, and never able to
    // change the answer. A replay, a refusal and a lost claim race returned above.
    count_run_outcome(ports, workflow_run_outcome_token(o.run_outcome),
                      workflow_run_outcome_reason(o));
    // The legacy route's event: the engine admitted and ran this call, so it is published whatever
    // the outcome (a failed run is still a run). Last, after the evidence row, and never able to
    // change the answer.
    emit_event_guarded(ports.emit, "workflow.executed");
    return o;
}

} // namespace

WorkflowExecuteOutcome run_workflow_execute(const WorkflowExecutePorts& ports,
                                            const WorkflowExecuteRequest& req,
                                            const WorkflowExecutePlan& plan) {
    const std::string target_id = clip_token(req.workflow_id);

    // ── 4b. the idempotency claim, built BEFORE the requested row ─────────
    // A key without a principal, or a request that cannot be fingerprinted, refuses here with no
    // row of the run's own: the engine's CHECK would refuse the insert anyway, but a refusal
    // after the `requested` row would read as a started run.
    std::optional<WorkflowIdempotencyClaim> claim;
    if (!req.idempotency_key.empty()) {
        if (req.caller.principal.empty())
            return refuse(WorkflowExecuteStatus::kNoPrincipal,
                          "an idempotency key needs an authenticated principal",
                          "idempotency_requires_principal");
        auto fingerprint = workflow_request_fingerprint(ports, req.workflow_id, req.agent_ids);
        if (!fingerprint) {
            (void)ports.audit(std::string(kActionExecute), "failure", target_id,
                              workflow_audit_prefix(req) + " reason=request_fingerprint_unavailable" +
                                  " idempotency_key=" + clip_token(req.idempotency_key));
            return refuse(WorkflowExecuteStatus::kEffectDigestFailed,
                          "the request could not be fingerprinted for its idempotency key",
                          "request_fingerprint_unavailable");
        }
        claim = WorkflowIdempotencyClaim{req.caller.principal, req.idempotency_key,
                                         std::move(*fingerprint)};
    }

    // ── 5. the requested row, BEFORE anything is dispatched ──────────────
    if (!ports.audit(std::string(kActionExecute), "requested", target_id,
                     workflow_audit_prefix(req) + " agents=" + std::to_string(req.agent_ids.size()) +
                         " steps=" + std::to_string(plan.step_count) +
                         (req.idempotency_key.empty()
                              ? ""
                              : " idempotency_key=" + clip_token(req.idempotency_key))))
        return refuse(WorkflowExecuteStatus::kAuditFailed,
                      "audit subsystem unavailable; refusing to dispatch without durable evidence",
                      "audit_unavailable", /*retryable=*/true);

    // From here a throw means steps may already have been sent, so it is answered as a started,
    // failed run and never as a retryable fault. The strings and the outcome are built BEFORE the
    // run (instruction_execute.cpp's throw arm): a second allocation failure in the arm must not
    // lose the closing row.
    std::string threw_detail =
        workflow_audit_prefix(req) + " run_outcome=" +
        std::string(workflow_run_outcome_token(WorkflowRunOutcome::kFailed)) +
        " reason=dispatch_exception";
    WorkflowExecuteOutcome threw = refuse(
        WorkflowExecuteStatus::kRunFailed, "workflow run failed part-way",
        "dispatch_exception");
    threw.remediation =
        "the run failed part-way and some steps may already have been sent to agents, so it was "
        "not retried and must not be re-sent; read the run with get_workflow_execution "
        "(GET /api/v1/workflow-executions/{id}); " +
        std::string(kStepNotProvenUnsentText);
    RunProgress progress;
    try {
        return drive_run(ports, req, claim, progress);
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
    count_run_outcome(ports, workflow_run_outcome_token(WorkflowRunOutcome::kFailed),
                      kWorkflowRunReasonDispatchException);
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
    if (!req.idempotency_prechecked) {
        if (auto early = check_workflow_idempotency(ports, req))
            return std::move(*early);
    }
    auto plan = prepare_workflow_execute(ports, req);
    if (!plan)
        return std::move(plan.error());
    return run_workflow_execute(ports, req, *plan);
}

} // namespace yuzu::server
