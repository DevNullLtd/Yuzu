#include "approvals_fragment_routes.hpp"

#include "approval_manager.hpp"
#include "http_route_sink.hpp"
#include "web_utils.hpp" // html_escape

#include <httplib.h>

#include <string>

namespace yuzu::server::approvals_fragment {

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
            // to Viewer). Approvals are workflow rows, not per-agent fleet data, so
            // a bare require_permission is correct here (not authorize_list_read).
            if (!deps.perm_fn(req, res, "Approval", "Read"))
                return;
            if (!deps.approval_manager) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            auto approvals = deps.approval_manager->query();
            std::string html;
            if (approvals.empty()) {
                html = "<div class=\"empty-state\">No approval requests.</div>";
            } else {
                html = "<table><thead><tr><th>ID</th><th>Status</th><th>Submitted "
                       "By</th><th>Scope</th><th></th></tr></thead><tbody>";
                for (const auto& a : approvals) {
                    auto status_cls = "status-" + a.status;
                    html += "<tr><td><code style=\"font-size:0.7rem\">" +
                            html_escape(a.id.substr(0, 12)) +
                            "</code></td>"
                            "<td><span class=\"status-badge " +
                            status_cls + "\">" + html_escape(a.status) +
                            "</span></td>"
                            "<td>" +
                            html_escape(a.submitted_by) +
                            "</td>"
                            "<td><code style=\"font-size:0.7rem\">" +
                            html_escape(a.scope_expression) +
                            "</code></td>"
                            "<td>";
                    if (a.status == "pending") {
                        if (a.submitted_by == session->username) {
                            // Self-review is denied server-side
                            // (ApprovalManager: "reviewer cannot be the
                            // same as the submitter") — don't render
                            // buttons that can only silently fail (#1821).
                            html += "<span style=\"font-size:0.65rem;color:var(--muted)\">"
                                    "You submitted this — another reviewer must "
                                    "approve</span>";
                        } else {
                            html += "<button class=\"btn btn-primary\" "
                                    "style=\"font-size:0.65rem;padding:0.15rem "
                                    "0.5rem;margin-right:0.3rem\" "
                                    "hx-post=\"/api/approvals/" +
                                    a.id +
                                    "/approve\" hx-target=\"#tab-approvals\" "
                                    "hx-swap=\"innerHTML\">Approve</button>"
                                    "<button class=\"btn btn-danger\" "
                                    "style=\"font-size:0.65rem;padding:0.15rem 0.5rem\" "
                                    "hx-post=\"/api/approvals/" +
                                    a.id +
                                    "/reject\" hx-target=\"#tab-approvals\" "
                                    "hx-swap=\"innerHTML\">Reject</button>";
                        }
                    }
                    html += "</td></tr>";
                }
                html += "</tbody></table>";
            }
            res.set_content(html, "text/html; charset=utf-8");
        });
}

} // namespace yuzu::server::approvals_fragment
