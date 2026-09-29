#include "approval_routes.hpp"

#include "approval_manager.hpp"
#include "http_route_sink.hpp"
#include "json_extract.hpp" // extract_json_string
#include "web_utils.hpp" // log_safe (#2542 PR-7 promotion, reused not duplicated)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <string>

namespace yuzu::server::approval {

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
                  if (!deps.perm_fn(req, res, "Approval", "Approve"))
                      return;
                  if (!deps.approval_manager) {
                      res.status = 503;
                      res.set_content(
                          R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                          "application/json");
                      return;
                  }

                  auto id = req.matches[1].str();
                  auto comment = extract_json_string(req.body, "comment");
                  // KNOWN GAP (#4128, pre-existing, not introduced by this extraction —
                  // verified byte-identical against origin/dev's pre-extraction inline
                  // code): this is a SECOND, non-atomic resolve_session call, independent
                  // of deps.perm_fn's own internal session resolution for the gate check
                  // above. If THIS call returns nullopt (a concurrent session eviction, or
                  // a Postgres session-store brownout past the 30s stale-serve bound) while
                  // the gate check above already succeeded, `reviewer` silently becomes
                  // "unknown" rather than failing the request closed — and "unknown" can
                  // never equal a real `submitted_by`, so the self-approval segregation-of-
                  // duties check in ApprovalManager::set_review_status cannot catch this
                  // specific path. Do not silently fix this here; see #4128 for the real
                  // remedy (reuse the identity perm_fn's gate already validated instead of
                  // re-resolving).
                  auto session = deps.resolve_session_fn(req);
                  auto reviewer = session ? session->username : "unknown";

                  auto result = deps.approval_manager->approve(id, reviewer, comment);
                  if (!result) {
                      res.status = 400;
                      // A denied review is an access-control decision (e.g. the
                      // self-approval segregation-of-duties block) — leave an audit
                      // trace like the other denial paths in this file (governance
                      // compliance CC6.1/CC6.3), and a greppable server-side line.
                      (void)deps.audit_fn(req, "approval.approve", "denied", "approval", id,
                                          result.error());
                      spdlog::warn("approval approve denied: id={} reviewer={} reason={}",
                                   log_safe(id), reviewer, log_safe(result.error(), 256));
                      // htmx doesn't swap a non-2xx response, so without a trigger
                      // the denial (e.g. the self-approval block) is a silent no-op
                      // in the dashboard (#1821). HX-Trigger headers ARE processed
                      // on error responses — surface the reason as a toast. dump()
                      // uses `replace`: the error can echo the raw URL id, and the
                      // default handler throws on invalid UTF-8 (governance UP-5).
                      nlohmann::json trigger = {
                          {"showToast", {{"message", result.error()}, {"level", "error"}}}};
                      res.set_header("HX-Trigger",
                                     trigger.dump(-1, ' ', false,
                                                  nlohmann::json::error_handler_t::replace));
                      res.set_content(nlohmann::json({{"error", result.error()}})
                                          .dump(-1, ' ', false,
                                                nlohmann::json::error_handler_t::replace),
                                      "application/json");
                      return;
                  }
                  (void)deps.audit_fn(req, "approval.approve", "success", "approval", id, "");
                  deps.emit_event_fn("approval.approved", req, {{"reviewer", reviewer}},
                                     {{"approval_id", id}});
                  res.set_header("HX-Trigger",
                                 R"({"showToast":{"message":"Approved","level":"success"}})");
                  res.set_content(R"({"status":"approved"})", "application/json");
              });

    sink.Post(R"(/api/approvals/([^/]+)/reject)",
              [deps](const httplib::Request& req, httplib::Response& res) {
                  if (!deps.perm_fn(req, res, "Approval", "Approve"))
                      return;
                  if (!deps.approval_manager) {
                      res.status = 503;
                      res.set_content(
                          R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                          "application/json");
                      return;
                  }

                  auto id = req.matches[1].str();
                  auto comment = extract_json_string(req.body, "comment");
                  // KNOWN GAP (#4128, pre-existing, not introduced by this extraction —
                  // verified byte-identical against origin/dev's pre-extraction inline
                  // code): this is a SECOND, non-atomic resolve_session call, independent
                  // of deps.perm_fn's own internal session resolution for the gate check
                  // above. If THIS call returns nullopt (a concurrent session eviction, or
                  // a Postgres session-store brownout past the 30s stale-serve bound) while
                  // the gate check above already succeeded, `reviewer` silently becomes
                  // "unknown" rather than failing the request closed — and "unknown" can
                  // never equal a real `submitted_by`, so the self-approval segregation-of-
                  // duties check in ApprovalManager::set_review_status cannot catch this
                  // specific path. Do not silently fix this here; see #4128 for the real
                  // remedy (reuse the identity perm_fn's gate already validated instead of
                  // re-resolving).
                  auto session = deps.resolve_session_fn(req);
                  auto reviewer = session ? session->username : "unknown";

                  auto result = deps.approval_manager->reject(id, reviewer, comment);
                  if (!result) {
                      res.status = 400;
                      // Same as the approve branch: audit the denial, log it, and
                      // surface it as a toast (#1821) — htmx swallows non-2xx
                      // bodies but processes HX-Trigger on them.
                      (void)deps.audit_fn(req, "approval.reject", "denied", "approval", id,
                                          result.error());
                      spdlog::warn("approval reject denied: id={} reviewer={} reason={}",
                                   log_safe(id), reviewer, log_safe(result.error(), 256));
                      nlohmann::json trigger = {
                          {"showToast", {{"message", result.error()}, {"level", "error"}}}};
                      res.set_header("HX-Trigger",
                                     trigger.dump(-1, ' ', false,
                                                  nlohmann::json::error_handler_t::replace));
                      res.set_content(nlohmann::json({{"error", result.error()}})
                                          .dump(-1, ' ', false,
                                                nlohmann::json::error_handler_t::replace),
                                      "application/json");
                      return;
                  }
                  (void)deps.audit_fn(req, "approval.reject", "success", "approval", id, "");
                  deps.emit_event_fn("approval.rejected", req,
                                     {{"reviewer", reviewer}, {"comment", comment}},
                                     {{"approval_id", id}});
                  res.set_header("HX-Trigger",
                                 R"({"showToast":{"message":"Rejected","level":"warning"}})");
                  res.set_content(R"({"status":"rejected"})", "application/json");
              });
}

} // namespace yuzu::server::approval
