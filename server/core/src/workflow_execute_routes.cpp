#include "workflow_execute_routes.hpp"

#include "dispatch_target_shape.hpp"
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth (#2437)
#include "rest_a4_envelope_http.hpp"
#include "workflow_execute.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace yuzu::server {

namespace {

struct HttpShape {
    int code;
    bool retryable_hint; ///< true: the body carries retry_after_ms 5000
};

[[nodiscard]] HttpShape http_shape(const WorkflowExecuteOutcome& o) {
    using S = WorkflowExecuteStatus;
    switch (o.status) {
    case S::kOk:
        return {202, false};
    case S::kRunIncomplete: // sent something, did not fully succeed: typed status, never a retry hint
        return {202, false};
    case S::kUnavailable:
        return {503, false}; // a missing dependency is not a transient fault
    case S::kNoPrincipal:
    case S::kEffectDigestFailed:
    case S::kRunFailed: // started, failed part-way: steps may have been sent, so NO retry hint
        return {500, false};
    case S::kStoreFailed:
        return {503, true};
    case S::kWorkflowNotFound:
    case S::kDestructiveNoVisibleTarget:
        return {404, false};
    case S::kRunCapReached: // capacity: nothing was read or sent, so a retry is safe
        return {429, true};
    case S::kDraining:
        return {503, true};
    case S::kExceedsSyncBudget:
        return {400, false};
    case S::kInvalidWorkflow:
    case S::kUnknownInstruction:
    case S::kUnclassifiedStep:
    case S::kDestructiveUntargeted:
    case S::kExecuteFailed:
    case S::kDefinitionChanged:
        return {400, false};
    case S::kApprovalRequired:
    case S::kDispatchDenied:
        return {403, false};
    case S::kAuditFailed:
        return {503, true};
    case S::kNoAgentsReached:
        return {503, o.retryable};
    }
    return {500, false};
}

/// A4 error body plus the route-local `reason` (and `execution_id` once a run exists), the same
/// extension the instruction-execute route's zero-reach 503s carry. A run that threw part-way
/// names its row as a typed `execution_id` (empty when none was admitted) and the lower-bound
/// `agents_sent` when known, as the instruction-execute route's `dispatch_exception` does.
std::string error_body(httplib::Response& res, const WorkflowExecuteOutcome& o, int code,
                       bool retry_hint, std::string_view remediation = {}) {
    const std::string cid = detail::ensure_correlation_id(res);
    detail::A4ErrorOpts opts;
    if (retry_hint)
        opts.retry_after_ms = 5000;
    opts.remediation = remediation;
    auto j = nlohmann::json::parse(detail::error_json_a4(code, o.message, cid, opts));
    if (j.contains("error") && j["error"].is_object()) {
        if (!o.reason.empty())
            j["error"]["reason"] = o.reason;
        if (o.status == WorkflowExecuteStatus::kRunFailed) {
            j["error"]["execution_id"] = o.execution_id;
            if (o.agents_sent > 0)
                j["error"]["agents_sent"] = o.agents_sent;
        } else if (!o.execution_id.empty()) {
            j["error"]["execution_id"] = o.execution_id;
        }
    }
    return j.dump();
}

} // namespace

void register_workflow_execute_v1_route(HttpRouteSink& sink, WorkflowExecuteRouteDeps deps) {
    // POST /api/v1/workflows/:id/execute -- start a workflow run against named agents.
    //
    // SOLE surface gate: Workflow:Execute (global; the per-step confinement is the caller's own
    // DispatchCaller, applied at the shared dispatch chokepoint for every step). A service-scoped
    // token is refused by perm_fn (Workflow:Execute is not on kServiceScopeGlobalSafe, which is
    // empty); an engine principal resolves RBAC-only; a supervised MCP-tier token is refused by
    // the approval mirror in perm_fn (#520).
    sink.Post(
        R"(/api/v1/workflows/([^/]+)/execute)",
        [d = std::move(deps)](const httplib::Request& req, httplib::Response& res) {
            if (!d.perm_fn || !d.perm_fn(req, res, "Workflow", "Execute"))
                return;
            const std::string cid = detail::ensure_correlation_id(res);
            const std::string workflow_id = req.matches[1].str();

            // #2437-class guard: raw-text depth check BEFORE the parse.
            if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
                res.status = 400;
                res.set_content(detail::a4_error(res, "request body nests too deeply"),
                                "application/json");
                return;
            }
            const auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(detail::a4_error(res, "invalid JSON"), "application/json");
                return;
            }
            auto agent_ids = parse_workflow_execute_body(body);
            if (!agent_ids) {
                if (d.metrics) {
                    try {
                        d.metrics
                            ->counter("yuzu_server_dispatch_target_rejected_total",
                                      {{"route", "workflow"}, {"reason", agent_ids.error().reason}})
                            .increment();
                    } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail a refusal
                    }
                }
                res.status = 400;
                nlohmann::json j = nlohmann::json::parse(detail::error_json_a4(
                    400, agent_ids.error().message, cid, detail::A4ErrorOpts{}));
                j["error"]["reason"] = agent_ids.error().reason;
                res.set_content(j.dump(), "application/json");
                return;
            }

            // The caller's REAL DispatchCaller (identity, JIT-aware admin flag, visible set).
            // Unwired derivation fails closed on visibility (present-EMPTY set, never nullopt).
            // approval_provenance stays None: REST has no ticket flow.
            const DispatchCaller caller =
                d.caller_fn ? d.caller_fn(req) : DispatchCaller{.exec_visible = authz::deny_all()};

            // The run's clock starts here, so everything below counts against the budget.
            const auto deadline = std::chrono::steady_clock::now() + kWorkflowSyncBudget;

            // ADMISSION, before any read of the workflow and before the `requested` row: a
            // synchronous run holds this worker for up to the budget, so it leases from the one
            // shared held-open budget, and a draining server starts no new run. The lease is a
            // plain local: the response is synchronous, so a return or a throw releases it.
            auto admission = admit_workflow_run(d.stream_budget, d.draining, caller.principal,
                                                d.metrics);
            if (admission.refusal) {
                const auto& refused = *admission.refusal;
                const auto shape = http_shape(refused);
                res.status = shape.code;
                res.set_header("Retry-After",
                               std::to_string((kWorkflowRunCapRetryAfterMs + 999) / 1000));
                res.set_content(
                    error_body(res, refused, shape.code, shape.retryable_hint, refused.remediation),
                    "application/json");
                return;
            }

            WorkflowExecutePorts ports;
            ports.api = d.workflow_api.get();
            ports.run = d.workflow_run;
            ports.instruction_store_open = d.instruction_store_open && d.instruction_store_open();
            ports.approval_gate_available = d.approval_gate_available && d.approval_gate_available();
            ports.lookup = d.lookup;
            ports.classify = d.classify;
            ports.authorize = d.authorize;
            if (d.command_dispatch_fn || d.command_dispatch_fn_concurrency) {
                ports.dispatch = [&d](const WorkflowStepInstruction& def,
                                      const std::vector<std::string>& ids,
                                      const std::unordered_map<std::string, std::string>& params,
                                      const DispatchCaller& c) {
                    // ADR-1007 per-device concurrency gate when wired; plain otherwise.
                    return d.command_dispatch_fn_concurrency
                               ? d.command_dispatch_fn_concurrency(def.plugin, def.action, ids, "",
                                                                   params, /*execution_id=*/"", c,
                                                                   def.id, def.concurrency_mode)
                               : d.command_dispatch_fn(def.plugin, def.action, ids, "", params,
                                                       /*execution_id=*/"", c);
                };
            }
            ports.audit = [&](const std::string& action, const std::string& result,
                              const std::string& target_id, const std::string& detail_text) {
                if (d.persist_audit_fn)
                    return d.persist_audit_fn(req, action, result, "workflow", target_id,
                                              detail_text);
                if (d.audit_fn)
                    d.audit_fn(req, action, result, "workflow", target_id, detail_text);
                return true; // audit off: not a persist failure
            };
            ports.count_target_rejected = [&](std::string_view reason) {
                if (!d.metrics)
                    return;
                try {
                    d.metrics
                        ->counter("yuzu_server_dispatch_target_rejected_total",
                                  {{"route", "workflow"}, {"reason", std::string(reason)}})
                        .increment();
                } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail a refusal
                }
            };
            ports.count_run_threw = [&] {
                if (!d.metrics)
                    return;
                try {
                    d.metrics
                        ->counter("yuzu_server_dispatch_fanout_throw_total",
                                  {{"route", "workflow"}, {"phase", "dispatch"}})
                        .increment();
                } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail the answer
                }
            };
            ports.count_dispatch_denied = [&](std::string_view reason) {
                if (!d.metrics)
                    return;
                try {
                    d.metrics
                        ->counter("yuzu_server_dispatch_denied_total",
                                  {{"reason", std::string(reason)}})
                        .increment();
                } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail a refusal
                }
            };

            WorkflowExecuteRequest wreq;
            wreq.workflow_id = workflow_id;
            wreq.agent_ids = std::move(*agent_ids);
            wreq.caller = caller;
            wreq.audit_context = "surface=rest";
            wreq.deadline = deadline;
            // The run is synchronous on this handler thread, so `req` outlives every use of the
            // closure and no copy of it is kept. The principal is the one `caller_fn` resolved
            // (the session's username), the value `revalidate_stream` compares the credential to.
            wreq.reauthorize_retry_delay = d.reauthorize_retry_delay;
            if (d.revalidate)
                wreq.reauthorize = [&req, &d, principal = caller.principal] {
                    return d.revalidate(req, principal);
                };

            WorkflowExecuteOutcome out;
            try {
                out = apply_workflow_execute(ports, wreq);
            } catch (const std::exception& e) {
                // Reached only for a throw BEFORE the `requested` row (the prepare half): nothing
                // was sent, so retrying is safe. A throw after that row comes back as kRunFailed.
                spdlog::error("workflow execute (REST v1) threw: {}", e.what());
                out.status = WorkflowExecuteStatus::kStoreFailed;
                out.message = "workflow execution failed";
                out.reason = "internal_error";
                out.retryable = true;
            }

            // A run that sent something is a 202 whose `status` says how it ended: `completed`
            // for a full success, `partial`, `aborted` or `interrupted` (retryable:false) otherwise (D7: a 5xx
            // would invite a blind re-send of steps that were already sent).
            if (out.status == WorkflowExecuteStatus::kOk ||
                out.status == WorkflowExecuteStatus::kRunIncomplete) {
                if (!out.audit_persisted)
                    res.set_header("Sec-Audit-Failed", "true");
                res.status = 202;
                res.set_content(nlohmann::json({{"data", workflow_execute_result_json(out, workflow_id)},
                                                {"meta", {{"api_version", "v1"}}}})
                                    .dump(),
                                "application/json");
                return;
            }

            const auto shape = http_shape(out);
            res.status = shape.code;
            if (out.status == WorkflowExecuteStatus::kAuditFailed ||
                ((!out.execution_id.empty() || out.status == WorkflowExecuteStatus::kRunFailed) &&
                 !out.audit_persisted))
                res.set_header("Sec-Audit-Failed", "true");
            const std::string_view remediation =
                out.status == WorkflowExecuteStatus::kApprovalRequired
                    ? "run each instruction through its own approval; a workflow only runs steps "
                      "this caller may run without one"
                    : std::string_view{out.remediation};
            res.set_content(error_body(res, out, shape.code, shape.retryable_hint, remediation),
                            "application/json");
        });
}

} // namespace yuzu::server
