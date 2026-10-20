#include "approval_routes.hpp"

#include "approval_manager.hpp"
#include "approver_assurance.hpp"
#include "audited_write.hpp" // WriteGate (same-site gate for the cookie-authorised write)
#include "http_route_sink.hpp"
#include "json_extract.hpp" // extract_json_string
#include "rest_a4_envelope.hpp" // detail::error_json_a4, make_correlation_id
#include "rest_audit.hpp" // detail::emit_behavioral_audit (audit-before-mutate)
#include "web_utils.hpp" // log_safe (#2542 PR-7 promotion, reused not duplicated)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::server::approval {

namespace {

enum class ReviewDecision { kApprove, kReject };

/// A4 error body for a refusal that happens BEFORE the ticket is touched.
void write_a4(httplib::Response& res, int code, std::string_view message,
              std::string_view remediation, std::int64_t retry_after_ms = -1) {
    res.status = code;
    const auto cid = detail::make_correlation_id();
    res.set_content(retry_after_ms >= 0
                        ? detail::error_json_a4(code, message, cid, retry_after_ms, remediation)
                        : detail::error_json_a4(code, message, cid, remediation),
                    "application/json");
}

/// Shared body of POST /api/approvals/:id/{approve,reject}. The two routes were
/// byte-twins; one copy means the four-eyes gates below cannot drift apart.
/// See approval_routes.hpp "APPROVER ASSURANCE" for the order and the rationale.
void handle_review(const Deps& deps, const httplib::Request& req, httplib::Response& res,
                   ReviewDecision decision) {
    const bool is_approve = decision == ReviewDecision::kApprove;
    const char* const verb = is_approve ? "approve" : "reject";
    const std::string audit_action = is_approve ? "approval.approve" : "approval.reject";

    if (!deps.perm_fn(req, res, "Approval", "Approve"))
        return;

    // Session first, store second: an unresolvable session or a non-human class
    // must be refused whether or not the store is reachable, and neither may
    // touch it. This is the SECOND, non-atomic resolve (perm_fn resolved once
    // internally); #4128 -- when it fails the request fails closed.
    auto session = deps.resolve_session_fn(req);
    if (!session) {
        spdlog::warn("approval {} refused: session could not be resolved after the permission "
                     "gate passed (#4128)",
                     verb);
        write_a4(res, 503, "session could not be resolved; the decision was not recorded",
                 "retry the request; the approval ticket is unchanged and still pending",
                 /*retry_after_ms=*/5000);
        return;
    }

    // Same-site gate (#6061, governance SG-1): after this change approve/reject
    // admit ONLY cookie sessions, which is exactly the ambient-credential class
    // `browser_write_is_cross_site` exists for -- every sibling cookie-write route
    // family carries it. The central pre-routing gate answers a cookie-session write
    // first; this copy is defence in depth and runs BEFORE the class check, step-up
    // and the `attempted` row, so a cross-site request mutates nothing and spends no
    // step-up. It is handed the
    // session resolved above rather than re-resolving (a third, non-atomic resolve).
    // A bearer/MCP token is exempt here and is refused by the class check below.
    const WriteGate write_gate{[&session](const httplib::Request&) { return session; },
                               deps.csrf_trusted_origins};
    if (write_gate.refuse_cross_site(deps.audit_fn, req, res, "approval"))
        return;

    if (const auto refusal = approval::check_approver_class(*session);
        refusal != approval::ApproverRefusal::kNone) {
        spdlog::warn("approval {} refused: reviewer={} auth_source={} principal_kind={} reason={}",
                     verb, log_safe(session->username), log_safe(session->auth_source, 64),
                     log_safe(session->principal_kind, 64),
                     approval::approver_refusal_reason(refusal));
        // Evidence that a bearer/engine caller reached the decision surface.
        // Best effort: the refusal is the control, this row is the trace.
        (void)deps.audit_fn(req, audit_action, "denied", "approval", req.matches[1].str(),
                            "approver_assurance:" +
                                std::string(approval::approver_refusal_reason(refusal)));
        write_a4(res, 403, approval::approver_refusal_message(refusal),
                 "approving or rejecting requires an interactive human session (local or OIDC "
                 "login) that passes the MFA step-up gate; API-token, MCP and engine "
                 "credentials cannot decide an approval. Use the dashboard Approvals page.");
        return;
    }

    if (!deps.approval_manager) {
        res.status = 503;
        res.set_content(
            R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
            "application/json");
        return;
    }

    if (!deps.step_up_fn) {
        spdlog::error("approval {} refused: no step_up_fn wired (fail closed)", verb);
        write_a4(res, 503, "MFA step-up is not available; the decision was not recorded",
                 "contact an administrator");
        return;
    }
    if (!deps.step_up_fn(req, res, *session,
                         std::string("POST /api/approvals/{id}/") + verb))
        return; // step-up wrote its own 401 envelope

    const auto id = req.matches[1].str();
    const auto comment = extract_json_string(req.body, "comment");
    const auto& reviewer = session->username;

    // ADR-0033 section 9 / #5823: no audit row, no mutation. The attempt row is
    // written BEFORE the store call; emit_behavioral_audit sets
    // `Sec-Audit-Failed: true` on failure, and the ticket stays pending.
    if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, audit_action, "attempted",
                                       "approval", id, "")) {
        write_a4(res, 503, "the audit record could not be written, so the decision was not applied",
                 "retry the request; the approval ticket is unchanged and still pending",
                 /*retry_after_ms=*/5000);
        return;
    }

    auto result = is_approve ? deps.approval_manager->approve(id, reviewer, comment)
                             : deps.approval_manager->reject(id, reviewer, comment);
    if (!result) {
        res.status = 400;
        // A denied review is an access-control decision (e.g. the
        // self-approval segregation-of-duties block) — leave an audit
        // trace like the other denial paths in this file (governance
        // compliance CC6.1/CC6.3), and a greppable server-side line.
        (void)deps.audit_fn(req, audit_action, "denied", "approval", id, result.error());
        spdlog::warn("approval {} denied: id={} reviewer={} reason={}", verb, log_safe(id),
                     reviewer, log_safe(result.error(), 256));
        // htmx doesn't swap a non-2xx response, so without a trigger
        // the denial (e.g. the self-approval block) is a silent no-op
        // in the dashboard (#1821). HX-Trigger headers ARE processed
        // on error responses — surface the reason as a toast. dump()
        // uses `replace`: the error can echo the raw URL id, and the
        // default handler throws on invalid UTF-8 (governance UP-5).
        nlohmann::json trigger = {{"showToast", {{"message", result.error()}, {"level", "error"}}}};
        res.set_header("HX-Trigger",
                       trigger.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
        res.set_content(nlohmann::json({{"error", result.error()}})
                            .dump(-1, ' ', false, nlohmann::json::error_handler_t::replace),
                        "application/json");
        return;
    }
    (void)deps.audit_fn(req, audit_action, "success", "approval", id, "");
    if (is_approve) {
        deps.emit_event_fn("approval.approved", req, {{"reviewer", reviewer}},
                           {{"approval_id", id}});
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Approved","level":"success"},"refreshApprovals":true})");
        res.set_content(R"({"status":"approved"})", "application/json");
    } else {
        deps.emit_event_fn("approval.rejected", req,
                           {{"reviewer", reviewer}, {"comment", comment}}, {{"approval_id", id}});
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Rejected","level":"warning"},"refreshApprovals":true})");
        res.set_content(R"({"status":"rejected"})", "application/json");
    }
}

} // namespace

void register_approval_routes(HttpRouteSink& sink, Deps deps) {
    // -- Approval API -----------------------------------------------------

    sink.Get("/api/approvals", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Approval", "Read"))
            return;
        if (!deps.approval_manager) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        ApprovalQuery q;
        if (req.has_param("status")) {
            q.status = req.get_param_value("status");
            // Gate 8 governance finding (#2146 A2-R4, same defect class just
            // fixed on GET /api/v1/approvals and MCP list_pending_approvals):
            // an unrecognized status silently produced a false-empty result
            // rather than a 400.
            if (std::find(ApprovalManager::allowed_status().begin(),
                          ApprovalManager::allowed_status().end(),
                          q.status) == ApprovalManager::allowed_status().end()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"invalid status"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
        }
        if (req.has_param("submitted_by"))
            q.submitted_by = req.get_param_value("submitted_by");

        auto approvals = deps.approval_manager->query(q);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& a : approvals) {
            arr.push_back({{"id", a.id},
                           {"definition_id", a.definition_id},
                           {"status", a.status},
                           {"submitted_by", a.submitted_by},
                           {"submitted_at", a.submitted_at},
                           {"reviewed_by", a.reviewed_by},
                           {"reviewed_at", a.reviewed_at},
                           {"review_comment", a.review_comment},
                           {"scope_expression", a.scope_expression}});
        }
        res.set_content(nlohmann::json({{"approvals", arr}}).dump(), "application/json");
    });

    sink.Get("/api/approvals/pending/count",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Approval", "Read"))
                     return;
                 if (!deps.approval_manager) {
                     res.set_content(R"({"count":0})", "application/json");
                     return;
                 }
                 auto count = deps.approval_manager->pending_count();
                 res.set_content(nlohmann::json({{"count", count}}).dump(), "application/json");
             });

    sink.Post(R"(/api/approvals/([^/]+)/approve)",
              [deps](const httplib::Request& req, httplib::Response& res) {
                  handle_review(deps, req, res, ReviewDecision::kApprove);
              });

    sink.Post(R"(/api/approvals/([^/]+)/reject)",
              [deps](const httplib::Request& req, httplib::Response& res) {
                  handle_review(deps, req, res, ReviewDecision::kReject);
              });
}

} // namespace yuzu::server::approval
