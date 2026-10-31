#include "instruction_execute_routes.hpp"

#include "dispatch_denial_text.hpp"
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth (#2437-class guard)
#include "rest_a4_envelope.hpp"
#include "rest_a4_envelope_http.hpp"

#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include <utility>

namespace yuzu::server::instruction_execute {

namespace {

constexpr std::string_view kAuditAction = "instruction.execute";

/// Hand-built A4 error body: `A4ErrorOpts` has no `reason`, and the reason token is what lets
/// an agentic caller branch without parsing prose. `correlation_id` and the always-present
/// nullable `retry_after_ms` keep it A4-complete.
std::string error_body(httplib::Response& res, int code, const std::string& message,
                       const std::string& reason, std::optional<int> retry_after_ms,
                       const std::string& remediation = {}) {
    nlohmann::json err{{"code", code},
                       {"message", message},
                       {"retry_after_ms", retry_after_ms ? nlohmann::json(*retry_after_ms)
                                                         : nlohmann::json(nullptr)},
                       {"correlation_id", detail::ensure_correlation_id(res)}};
    if (!reason.empty())
        err["reason"] = reason;
    if (!remediation.empty())
        err["remediation"] = remediation;
    return nlohmann::json{{"error", std::move(err)}, {"meta", {{"api_version", "v1"}}}}.dump();
}

void send_refusal(httplib::Response& res, const Refusal& r) {
    int status = 500;
    std::string message = r.message;
    std::string remediation = r.remediation;
    switch (r.kind) {
    case RefusalKind::kStoreUnavailable:
    case RefusalKind::kApprovalUnavailable:
    case RefusalKind::kClassifierUnavailable:
        status = 503;
        break;
    case RefusalKind::kAuditUnavailable:
        status = 503;
        res.set_header("Sec-Audit-Failed", "true");
        break;
    case RefusalKind::kNotFound:
    case RefusalKind::kNoVisibleTarget:
        status = 404;
        break;
    case RefusalKind::kBadRequest:
        status = 400;
        break;
    case RefusalKind::kApprovalCapReached:
        status = 429;
        break;
    case RefusalKind::kDispatchDenied: {
        const auto& d = *r.denial;
        const auto text = describe_dispatch_denial(d.reason, r.plugin, r.action, d, DenialSurface::kRest);
        message = text.message;
        remediation = text.remediation;
        switch (text.cls) {
        case DispatchDenialClass::kInvalidParams:
            status = 400;
            break;
        case DispatchDenialClass::kPermissionDenied:
            status = 403;
            break;
        case DispatchDenialClass::kInternal:
            status = 500;
            break;
        }
        break;
    }
    case RefusalKind::kSchemaInvalid:
    case RefusalKind::kApprovalSubmitFailed:
    case RefusalKind::kMisconfigured:
    case RefusalKind::kDispatchFailed:
        status = 500;
        break;
    }
    res.status = status;
    res.set_content(error_body(res, status, message, r.reason, r.retry_after_ms, remediation),
                    "application/json");
}

void send_zero_reach(httplib::Response& res, const ZeroReach& z) {
    const bool retry = zero_reach_retryable(z.cause);
    const int status = z.cause == ZeroReachCause::InvalidScope ? 400 : 503;
    res.status = status;
    nlohmann::json err{{"code", status},
                       {"message", z.message},
                       {"reason", std::string(zero_reach_token(z.cause))},
                       {"retry_after_ms", retry ? nlohmann::json(5000) : nlohmann::json(nullptr)},
                       {"correlation_id", detail::ensure_correlation_id(res)},
                       {"command_id", z.command_id},
                       {"execution_id", z.execution_id},
                       {"agents_quarantined", z.agents_quarantined},
                       {"agents_unknown_plugin", z.agents_unknown_plugin},
                       {"agents_kill_switched_os", z.agents_kill_switched_os}};
    res.set_content(
        nlohmann::json{{"error", std::move(err)}, {"meta", {{"api_version", "v1"}}}}.dump(),
        "application/json");
}

} // namespace

void register_instruction_execute_routes(HttpRouteSink& sink, RouteDeps deps) {
    sink.Post(R"(/api/v1/instructions/([^/]+)/execute)", [deps = std::move(deps)](
                                                              const httplib::Request& req,
                                                              httplib::Response& res) {
        // Gate first, the legacy route's own pair. Plain and global by design: see the header.
        if (!deps.perm_fn || !deps.perm_fn(req, res, "Execution", "Execute")) {
            if (!deps.perm_fn) { // unwired is misconfiguration, never "no gate"
                res.status = 500;
                res.set_content(error_body(res, 500, "authorization not configured",
                                           "misconfigured", std::nullopt),
                                "application/json");
            }
            return;
        }

        // An unwired audit sink fails CLOSED: this route is audit-first (the `requested` row is
        // written before any effect), so a deployment with no sink cannot be treated as "audit
        // off". Behind the gate (an unauthorised caller learns nothing about the configuration)
        // and before any body work, store read or dispatch. No retry hint: an unwired sink is a
        // server defect, not a transient fault.
        if (!deps.audit_fn) {
            res.status = 503;
            res.set_header("Sec-Audit-Failed", "true");
            res.set_content(error_body(res, 503, "audit subsystem not configured; nothing was sent",
                                       "audit_unavailable", std::nullopt,
                                       "the server has no audit sink wired; this is a server "
                                       "configuration defect and retrying will not help"),
                            "application/json");
            return;
        }

        // #2437-class guard: raw-text depth check BEFORE parse, so a pathologically nested
        // `params` cannot crash the dump below.
        if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
            res.status = 400;
            res.set_content(error_body(res, 400, "request body nests too deeply", "body_too_deep",
                                       std::nullopt),
                            "application/json");
            return;
        }
        auto body = nlohmann::json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(
                error_body(res, 400, "invalid request body", "invalid_json", std::nullopt),
                "application/json");
            return;
        }

        Request rq;
        rq.surface = Surface::kRest;
        rq.definition_id = req.matches[1].str();
        rq.body = std::move(body);
        // Unwired caller derivation fails CLOSED on visibility: a present-EMPTY set, never the
        // default VisibleSet (nullopt = unfiltered).
        rq.caller = deps.caller_fn ? deps.caller_fn(req)
                                   : DispatchCaller{.exec_visible = authz::deny_all()};

        // The same per-principal share of the pending-approval queue MCP has: a script looping on
        // an approval-gated definition must not fill the cap every other principal shares.
        rq.submitter_pending_cap = kSubmitterPendingCap;

        const std::string definition_id = rq.definition_id;
        const AuditHook audit = [&](std::string_view result, const std::string& detail_text) {
            if (!deps.audit_fn)
                return false; // unreachable past the guard above; never "audit off"
            return deps.audit_fn(req, std::string(kAuditAction), std::string(result),
                                 "instruction", definition_id, detail_text);
        };

        const Outcome out =
            run(rq, deps.ports, audit, bind_event_emit(deps.emit_event_fn, req, deps.ports.metrics));
        if (out.audit_dropped)
            res.set_header("Sec-Audit-Failed", "true");

        if (const auto* r = std::get_if<Refusal>(&out.result)) {
            send_refusal(res, *r);
            return;
        }
        if (const auto* p = std::get_if<PendingApproval>(&out.result)) {
            res.status = 202;
            res.set_content(nlohmann::json{{"data",
                                            {{"status", "pending_approval"},
                                             {"approval_id", p->approval_id},
                                             {"approval_mode", p->approval_mode},
                                             {"definition_id", p->definition_id}}},
                                           {"meta", {{"api_version", "v1"}}}}
                                .dump(),
                            "application/json");
            return;
        }
        if (const auto* z = std::get_if<ZeroReach>(&out.result)) {
            send_zero_reach(res, *z);
            return;
        }
        const auto& d = std::get<Dispatched>(out.result);
        res.status = 200;
        res.set_content(nlohmann::json{{"data",
                                        {{"command_id", d.command_id},
                                         {"execution_id", d.execution_id},
                                         {"agents_reached", d.agents_reached},
                                         {"definition_id", d.definition_id}}},
                                       {"meta", {{"api_version", "v1"}}}}
                            .dump(),
                        "application/json");
    });
}

} // namespace yuzu::server::instruction_execute
