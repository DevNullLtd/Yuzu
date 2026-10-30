#include "approval_routes.hpp"

#include "approval_manager.hpp"
#include "approval_model.hpp" // approval_row_json (the shared read-row builder)
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

/// Remediation text for a refusal (class check or MFA gate, #6079). The un-enrolled case is
/// role-aware: the Settings page is an administrator's enrolment path, so a non-admin is
/// not sent there. A non-admin is told to sign in again (a session minted before the
/// deployment's `--mfa-enforcement` required MFA for its role never went through the
/// enrol-at-login step) and otherwise to ask an administrator. The text deliberately reads
/// no configuration: it must hold whichever mode is active.
std::string mfa_refusal_remediation(approval::ApproverRefusal refusal,
                                    const auth::Session& session) {
    switch (refusal) {
    case approval::ApproverRefusal::kMfaNotEnrolled:
        return auth::effective_role(session) == auth::Role::admin
                   ? "enrol under Settings > Security and sign-in > Two-factor sign-in, then "
                     "retry and enter a code when prompted."
                   : "sign out and sign in again: enrolment is offered at sign-in when this "
                     "deployment's --mfa-enforcement mode requires it for your role. If you are "
                     "not offered it, ask your Yuzu administrator to enrol you "
                     "(see \"Enrolling a non-admin approver\" in the Auth Store Recovery "
                     "Runbook), then retry.";
    case approval::ApproverRefusal::kMfaProofMissing:
        return "your single sign-on login left no usable second-factor proof: the identity "
               "provider sent no MFA amr, or the clocks of the identity provider, the Yuzu server "
               "and its database disagree. Sign in again through your identity provider with MFA, "
               "or ask an administrator to have the provider require MFA for approvers and report "
               "it in amr. If it repeats, ask your administrator to check clock synchronisation "
               "between the identity provider, the Yuzu server and its database.";
    case approval::ApproverRefusal::kSamlMfaUnsupported:
        return "MFA attestation is not available for SAML sessions (#4935); decide the request "
               "from a local or OIDC session.";
    case approval::ApproverRefusal::kAccountUnavailable:
        return "this account is deactivated or no longer exists. Sign in again, or contact an "
               "administrator.";
    default:
        return "approving or rejecting requires an interactive human session (local or OIDC "
               "login) with an enrolled MFA factor and a fresh proof; API-token, MCP and engine "
               "credentials cannot decide an approval. Use the dashboard Approvals page.";
    }
}

/// An approval id as the store mints it is 32 hex characters; this is the wider shape any
/// id in a request path may take before it is allowed into an audit row. The route regex is
/// `[^/]+`, so the captured segment can otherwise carry control bytes or arbitrary length.
/// It is the same shape GET /api/v1/approvals/{id} accepts in its route regex
/// (rest_api_v1.cpp), where it exists only as an inline pattern, not a shared predicate.
[[nodiscard]] bool approval_id_shape_ok(std::string_view id) {
    if (id.empty() || id.size() > 128)
        return false;
    return std::all_of(id.begin(), id.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               c == '_' || c == '-';
    });
}

/// Detail on the `attempted` and `success` rows: the decision was taken behind the enrolled-
/// factor, fresh-proof gate. It is also the cutover marker for rows written before that gate.
constexpr const char* kAssuranceDetail = "approver_assurance:enrolled_fresh_mfa";

/// Fixed, bounded stand-in written as an audit `target_id` when the path segment fails
/// `approval_id_shape_ok` (CWE-117: the raw bytes must never reach an audit row).
constexpr const char* kInvalidIdPlaceholder = "invalid-id";

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

    // Every audit row and log line below names the ticket through `audit_id`: the raw path
    // segment is attacker-shaped (the route regex is `[^/]+`) and a refusal row is written
    // before any ticket-existence check, so it is validated once here and a non-conforming
    // value is replaced by a fixed placeholder. The order of refusals is unchanged.
    const std::string id = req.matches[1].str();
    const bool id_ok = approval_id_shape_ok(id);
    const std::string audit_id = id_ok ? id : std::string(kInvalidIdPlaceholder);

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
    // first, then the central step-up check runs in the pre-request stage; this copy is
    // defence in depth and runs after both and after the permission gate (an
    // unauthorised caller keeps its 403), BEFORE the class check, this handler's
    // step-up call and the `attempted` row, so a cross-site request mutates nothing
    // and the handler's step-up call is never reached. It is handed the session
    // resolved above rather than re-resolving (a third, non-atomic resolve). A
    // bearer/MCP token is exempt here and is refused by the class check below.
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
        // Evidence that a non-interactive caller reached the decision surface. Over REST that
        // is a bearer-token (or other non-interactive) caller: an engine principal is refused
        // by the central step-up check and is reachable only via MCP. The refusal is the
        // control and stands whether or not this row persists; a failed row is surfaced as
        // Sec-Audit-Failed rather than swallowed.
        (void)detail::emit_behavioral_audit(
            deps.audit_fn, req, res, audit_action, "denied", "approval", audit_id,
            "approver_assurance:" + std::string(approval::approver_refusal_reason(refusal)));
        write_a4(res, 403, approval::approver_refusal_message(refusal),
                 mfa_refusal_remediation(refusal, *session)); // class reasons: the default text
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
        write_a4(res, 503, "MFA verification is not available; the decision was not recorded",
                 "contact an administrator");
        return;
    }
    if (!deps.approver_mfa_fn) {
        spdlog::error("approval {} refused: no approver_mfa_fn wired (fail closed)", verb);
        write_a4(res, 503, "MFA verification is not available; the decision was not recorded",
                 "contact an administrator");
        return;
    }
    // Each label is spelled out as a literal (not a prefix plus the verb) because the label pin in
    // test_step_up_route_inventory.cpp reads these call sites lexically and must see the text
    // kStepUpPolicy carries for the two approval rows.
    const bool stepped_up =
        is_approve ? deps.step_up_fn(req, res, *session, "POST /api/approvals/{id}/approve")
                   : deps.step_up_fn(req, res, *session, "POST /api/approvals/{id}/reject");
    if (!stepped_up)
        return; // step-up wrote its own 401 envelope

    // The approver gate (#6079) is stricter than the generic step-up above and does not
    // replace it: the pass the central check armed is consumed by the call above, and this
    // check then requires an ENROLLED factor with a proof no older than the approver window.
    const auto mfa =
        deps.approver_mfa_fn(req, res, *session, std::string("POST /api/approvals/{id}/") + verb);
    using MfaKind = ApproverMfaOutcome::Kind;
    switch (mfa.kind) {
    case MfaKind::kPass:
        break;
    case MfaKind::kChallengeWritten:
        // The gate wrote the 401 step-up envelope; add the ticket-specific evidence row.
        (void)detail::emit_behavioral_audit(
            deps.audit_fn, req, res, audit_action, "denied", "approval", audit_id,
            "approver_assurance:" + std::string(approval::approver_refusal_reason(
                                        approval::ApproverRefusal::kMfaProofStale)));
        return;
    case MfaKind::kStoreUnavailable:
        spdlog::error("approval {} refused: reviewer={} MFA state unreadable (fail closed)", verb,
                      log_safe(session->username));
        (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, audit_action, "error",
                                            "approval", audit_id,
                                            "approver_assurance:mfa_store_unavailable");
        write_a4(res, 503,
                 "the approver's MFA state could not be read, so the decision was not recorded",
                 "retry the request; the approval ticket is unchanged and still pending",
                 /*retry_after_ms=*/5000);
        return;
    case MfaKind::kProofClockSkew:
        // An SSO proof dated after the database clock: a server-side clock fault, not a store
        // fault and not something signing in again fixes. Same ordering and audit shape as the
        // store-unavailable arm (result=error, before any attempted row), with its own detail
        // token, no retry hint (retrying cannot help until the clocks are corrected) and no
        // increment of the store-fault counter (the gate did not touch it).
        spdlog::error("approval {} refused: reviewer={} MFA proof dated after the database clock "
                      "(fail closed)",
                      verb, log_safe(session->username));
        (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, audit_action, "error",
                                            "approval", audit_id,
                                            "approver_assurance:mfa_proof_clock_skew");
        write_a4(res, 503,
                 "the approver's identity-provider MFA proof is dated after the database clock",
                 "an administrator must correct clock synchronisation between the identity "
                 "provider, the Yuzu server and its database; retrying will not help until then");
        return;
    case MfaKind::kRefuse:
    default: {
        // Unmapped factor states still refuse (kNone coerced), never fall through.
        auto refusal = approval::refusal_for_factor(mfa.factor);
        if (refusal == approval::ApproverRefusal::kNone)
            refusal = approval::ApproverRefusal::kMfaNotEnrolled;
        spdlog::warn("approval {} refused: reviewer={} auth_source={} reason={}", verb,
                     log_safe(session->username), log_safe(session->auth_source, 64),
                     approval::approver_refusal_reason(refusal));
        (void)detail::emit_behavioral_audit(
            deps.audit_fn, req, res, audit_action, "denied", "approval", audit_id,
            "approver_assurance:" + std::string(approval::approver_refusal_reason(refusal)));
        write_a4(res, 403, approval::approver_refusal_message(refusal),
                 mfa_refusal_remediation(refusal, *session));
        return;
    }
    }

    const auto comment = extract_json_string(req.body, "comment");
    const auto& reviewer = session->username;

    // A denied review is an access-control decision (e.g. the self-approval segregation-of-
    // duties block) -- leave an audit trace like the other denial paths in this file
    // (governance compliance CC6.1/CC6.3), and a greppable server-side line. htmx doesn't
    // swap a non-2xx response, so without a trigger the denial is a silent no-op in the
    // dashboard (#1821). HX-Trigger headers ARE processed on error responses, so the reason
    // is surfaced as a toast. dump() uses `replace`: the default handler throws on invalid
    // UTF-8 (governance UP-5).
    const auto write_denied = [&](const std::string& error, const std::string& audit_detail) {
        res.status = 400;
        (void)deps.audit_fn(req, audit_action, "denied", "approval", audit_id, audit_detail);
        spdlog::warn("approval {} denied: id={} reviewer={} reason={}", verb, audit_id,
                     log_safe(reviewer), log_safe(error, 256));
        nlohmann::json trigger = {{"showToast", {{"message", error}, {"level", "error"}}}};
        res.set_header("HX-Trigger",
                       trigger.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
        res.set_content(nlohmann::json({{"error", error}})
                            .dump(-1, ' ', false, nlohmann::json::error_handler_t::replace),
                        "application/json");
    };

    // No ticket id has this shape, so there is nothing to decide and nothing to echo: the
    // store is not asked and the raw segment is neither audited nor reflected.
    // The denied row goes through the guarded helper (an audit failure or throw is absorbed
    // and flagged as Sec-Audit-Failed; the refusal stands either way), and the body is the
    // full A4 envelope. The legacy `{"error":"approval not found"}` shape of write_denied
    // remains only for the store-result arms below.
    if (!id_ok) {
        spdlog::warn("approval {} denied: id={} reviewer={} reason=invalid_approval_id", verb,
                     audit_id, log_safe(reviewer));
        (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, audit_action, "denied",
                                            "approval", audit_id, "invalid_approval_id");
        nlohmann::json trigger = {
            {"showToast", {{"message", "approval not found"}, {"level", "error"}}}};
        res.set_header("HX-Trigger",
                       trigger.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
        write_a4(res, 400, "approval not found",
                 "check the approval id and retry; list pending approvals at "
                 "GET /api/approvals");
        return;
    }

    // ADR-0033 section 9 / #5823: no audit row, no mutation. The attempt row is
    // written BEFORE the store call; emit_behavioral_audit sets
    // `Sec-Audit-Failed: true` on failure, and the ticket stays pending. The detail names
    // the assurance the gate above established, so a row written by this build is told
    // apart from one written before the enrolled-factor requirement existed.
    if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, audit_action, "attempted",
                                       "approval", audit_id, kAssuranceDetail)) {
        write_a4(res, 503, "the audit record could not be written, so the decision was not applied",
                 "retry the request; the approval ticket is unchanged and still pending",
                 /*retry_after_ms=*/5000);
        return;
    }

    auto result = is_approve ? deps.approval_manager->approve(id, reviewer, comment)
                             : deps.approval_manager->reject(id, reviewer, comment);
    if (!result) {
        write_denied(result.error(), result.error());
        return;
    }
    (void)deps.audit_fn(req, audit_action, "success", "approval", audit_id, kAssuranceDetail);
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
        // Shared builder (approval_model.hpp): the SAME rows as GET /api/v1/approvals and
        // MCP list_pending_approvals, a bound ticket's frozen request included (#6062).
        for (const auto& a : approvals)
            arr.push_back(approval_row_json(a));
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
