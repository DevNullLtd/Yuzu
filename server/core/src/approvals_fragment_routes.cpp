#include "approvals_fragment_routes.hpp"

#include "approval_manager.hpp"
#include "approver_assurance.hpp"
#include "approvals_page_render.hpp"
#include "http_route_sink.hpp"
#include "refusal_log_throttle.hpp"
#include "instruction_store.hpp"
#include "reserved_definition_id.hpp"
#include "web_utils.hpp" // html_escape

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <ctime>
#include <expected>
#include <optional>
#include <string>

namespace yuzu::server::approvals_fragment {

namespace {

/// A 200 note. htmx drops 4xx/5xx bodies, so every non-happy answer of this fragment is a
/// 200 carrying one of these (`attr` is the machine-readable marker).
std::string note(std::string_view attr, std::string_view text) {
    std::string out = "<div class=\"empty-state\" ";
    out += attr;
    out += ">";
    out += html_escape(std::string(text));
    out += "</div>";
    return out;
}

/// The viewing session may not APPROVE `a` because of its excluded roots (#6062): named
/// in them, or the stored list is unreadable. A render hint only - the store refuses the
/// approval either way (`ApprovalManager::approve`) - and it decides through the store's
/// own `reviewer_is_excluded`, so the two cannot drift. It gates Approve ONLY: the store
/// lets an excluded root REJECT, so an excluded viewer is still offered Reject (the way a
/// designer withdraws a request). The submitter is different - barred from both verbs.
bool viewer_is_excluded(const Approval& a, const std::string& username) {
    if (a.excluded_roots_unreadable)
        return true;
    return !username.empty() && reviewer_is_excluded(username, a.excluded_roots);
}

/// A bound ticket whose stored request cannot be read or bounded (#6062). The summary
/// then shows the fixed "do not approve" notice, so the page also withholds Approve (the
/// store refuses the approval too) and leaves Reject, the only way to clear the row.
/// Logs once per call with the id prefix only, never the request: the id is a bearer
/// capability (see ApprovalManager's redact_id) and the request can be anything.
bool request_unreadable(const Approval& a) {
    if (a.request_json.empty() || bound_request_is_readable(a.request_json))
        return false;
    // A bad row is rendered on every page load and poll, in every status filter, so the line
    // is throttled per ticket (the repo's RefusalLogThrottle: one warn per id prefix per
    // minute, the rest demoted to debug). The page itself is unaffected.
    static RefusalLogThrottle throttle;
    const std::string prefix = a.id.substr(0, 8);
    if (throttle.should_warn(prefix))
        spdlog::warn("Approvals page: the stored request of ticket {}... cannot be read; "
                     "Approve is withheld",
                     prefix);
    else
        spdlog::debug("Approvals page: the stored request of ticket {}... still cannot be read",
                      prefix);
    return true;
}

} // namespace

void register_approvals_fragment_routes(HttpRouteSink& sink, Deps deps) {
    sink.Get(
        "/fragments/approvals", [deps](const httplib::Request& req, httplib::Response& res) {
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            // Gate on Approval:Read, mirroring the REST sibling GET /api/approvals
            // (#3040): this fragment renders the full approvals population
            // (submitted_by / status / scope_expression) and must not disclose it
            // to any authenticated session, only to Approval:Read holders (seeded
            // to Viewer). Approvals are workflow rows, not a per-agent fleet read, so
            // a bare require_permission is the gate here (not authorize_list_read), the
            // same gate every approval read carries. A BOUND ticket's frozen request
            // can name devices in its targets, and it is shown to any Approval:Read
            // holder under that same global gate - the REST v1 list/get and MCP
            // list_pending_approvals expose the very same request/digest/excluded_roots
            // through approval_row_json (#6062), so the page and the API twins agree on
            // who may see it. Confining a bound request by the viewer's management
            // groups would be a new decision, not an inherited one.
            if (!deps.perm_fn(req, res, "Approval", "Read")) {
                // The gate already wrote its 403 (and its audit row). htmx drops 4xx
                // bodies, so the panel would sit on "Loading..." forever: rewrite that
                // one status to a 200 note. Nothing from the gate's body (reason, role or
                // permission names) may reach the fragment. Any other status (401, 503)
                // is left exactly as the gate wrote it.
                if (res.status == 403) {
                    res.status = 200;
                    res.set_content(note("data-denied=\"true\"",
                                         operate_pages::kApprovalsDeniedNote),
                                    "text/html; charset=utf-8");
                }
                return;
            }

            // Filter: absent = every status for the tab, `pending` for the page; present
            // but empty = every status. Validated BEFORE the store is read, so a typo
            // answers "unknown filter" and never reads as an empty queue.
            const bool view_page = req.get_param_value("view") == "page";
            // Buttons are rendered only for a session the decide routes would accept on
            // class (#6061): an interactive human, non-engine session. A bearer / engine /
            // non-human viewer would only get a refusal, so the control is not offered.
            // This mirrors the route's check (the one shared predicate); the route stays
            // the authority.
            const bool approver_class_ok =
                approval::check_approver_class(*session) == approval::ApproverRefusal::kNone;
            std::string status = req.has_param("status") ? req.get_param_value("status")
                                                         : (view_page ? "pending" : "");
            const auto& allowed = ApprovalManager::allowed_status();
            if (!status.empty() && std::find(allowed.begin(), allowed.end(), status) == allowed.end()) {
                res.set_content(note("data-invalid=\"status\"",
                                     operate_pages::kApprovalsUnknownFilterNote),
                                "text/html; charset=utf-8");
                return;
            }

            if (!deps.approval_manager) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            // Checked read: a store failure is a degraded note, never "No approval
            // requests." (empty is not failed).
            auto listed = deps.approval_manager->query_checked(ApprovalQuery{.status = status});
            if (!listed) {
                res.set_content(note("data-degraded=\"store\"",
                                     operate_pages::kApprovalsDegradedNote),
                                "text/html; charset=utf-8");
                return;
            }

            // One probe per render, and only when some pending row is not the caller's own
            // (self-review is refused server-side whatever the grant). Never per row. Shared
            // by both views (#6061): the tab used to offer Approve/Reject on the class check
            // alone, so a Viewer-level approver-class session saw buttons the route would
            // refuse with a 403 the tab cannot surface.
            const bool decidable_row = std::any_of(
                listed->approvals.begin(), listed->approvals.end(), [&](const auto& a) {
                    // An excluded viewer still has Reject, so the row is decidable.
                    return a.status == "pending" &&
                           (session->username.empty() || a.submitted_by != session->username);
                });
            const bool can_decide = approver_class_ok && decidable_row && deps.probe_perm_fn &&
                                    deps.probe_perm_fn(req, "Approval", "Approve");

            if (view_page) {
                operate_pages::NameLookupMemo names(operate_pages::instruction_name_resolver(deps.instruction_store));
                operate_pages::ApprovalListView view;
                view.truncated = listed->truncated;
                view.status_filter = status;
                view.now = static_cast<int64_t>(std::time(nullptr));
                view.can_decide = can_decide;
                view.rows.reserve(listed->approvals.size());
                for (const auto& a : listed->approvals) {
                    operate_pages::ApprovalRowView row;
                    row.id = a.id;
                    row.definition_id = a.definition_id;
                    row.name = operate_pages::approval_display_name(a.definition_id, names);
                    row.status = a.status;
                    row.submitted_by = a.submitted_by;
                    row.scope_expression = a.scope_expression;
                    row.reviewed_by = a.reviewed_by;
                    row.review_comment = a.review_comment;
                    row.submitted_at = a.submitted_at;
                    row.reviewed_at = a.reviewed_at;
                    row.mine = !session->username.empty() && a.submitted_by == session->username;
                    row.mcp = is_mcp_definition_id(a.definition_id);
                    row.request_json = a.request_json;
                    row.request_digest = a.request_digest;
                    row.excluded = viewer_is_excluded(a, session->username);
                    (void)request_unreadable(a); // log only; the renderer derives the flag
                    view.rows.push_back(std::move(row));
                }
                res.set_content(operate_pages::render_approvals_page(view),
                                "text/html; charset=utf-8");
                return;
            }

            const auto& approvals = listed->approvals;
            std::string html;
            if (approvals.empty()) {
                html = "<div class=\"empty-state\">No approval requests.</div>";
            } else {
                html = "<section class=\"panel\"><div class=\"hd\"><h2>Approvals</h2></div>"
                       "<div class=\"tw\"><table><thead><tr><th>ID</th><th>Status</th>"
                       "<th>Submitted By</th><th>Scope</th><th></th></tr></thead><tbody>";
                for (const auto& a : approvals) {
                    auto status_cls = "status-" + a.status;
                    html += "<tr><td><code>" + html_escape(a.id.substr(0, 12)) +
                            "</code></td>"
                            "<td><span class=\"status-badge " +
                            status_cls + "\">" + html_escape(a.status) +
                            "</span></td>"
                            "<td>" +
                            html_escape(a.submitted_by) +
                            "</td>"
                            "<td><code>" +
                            html_escape(a.scope_expression) +
                            "</code>";
                    if (!a.request_json.empty()) {
                        // Bound ticket (#6062): the reviewer reads what is being approved.
                        // Text only, escaped; the raw JSON is never emitted.
                        html += "<details><summary>Request</summary><pre>" +
                                html_escape(operate_pages::summarize_bound_request(
                                    a.request_json, a.request_digest)) +
                                "</pre></details>";
                    }
                    html += "</td><td class=\"act\">";
                    if (a.status == "pending") {
                        if (a.submitted_by == session->username) {
                            // Self-review is denied server-side
                            // (ApprovalManager: "reviewer cannot be the
                            // same as the submitter") — don't render
                            // buttons that can only silently fail (#1821).
                            html += "<span class=\"hint\">"
                                    "You submitted this — another reviewer must "
                                    "approve</span>";
                        } else if (can_decide) {
                            // Approve is withheld when the store would refuse it: the
                            // viewer is an excluded root, or the request cannot be read.
                            // Reject stays in both cases.
                            if (viewer_is_excluded(a, session->username))
                                html += "<span class=\"hint\">You are excluded from approving "
                                        "this request. You can still reject it.</span> ";
                            if (!viewer_is_excluded(a, session->username) &&
                                !request_unreadable(a))
                                html += "<button class=\"btn btn-primary btn-sm\" "
                                        "hx-post=\"/api/approvals/" +
                                        a.id +
                                        "/approve\" hx-swap=\"none\">Approve</button> ";
                            html += "<button class=\"btn btn-danger btn-sm\" "
                                    "hx-post=\"/api/approvals/" +
                                    a.id +
                                    "/reject\" hx-swap=\"none\">Reject</button>";
                        }
                    }
                    html += "</td></tr>";
                }
                html += "</tbody></table></div></section>";
                // The decision POSTs answer JSON, which must not be swapped into the tab
                // (it replaced the table with raw JSON). The success HX-Trigger
                // `refreshApprovals` re-fetches this fragment through this listener.
                html += "<span hidden hx-get=\"/fragments/approvals\" "
                        "hx-trigger=\"refreshApprovals from:body\" "
                        "hx-target=\"#tab-approvals\" hx-swap=\"innerHTML\"></span>";
            }
            res.set_content(html, "text/html; charset=utf-8");
        });
}

} // namespace yuzu::server::approvals_fragment
