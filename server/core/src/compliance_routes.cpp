/// @file compliance_routes.cpp
/// Compliance dashboard HTMX routes plus the read-only policy/fragment/
/// compliance API routes (legacy + v1 twins). Extracted from server.cpp —
/// Phase 3a of the god-object decomposition; ADR-0031 WS-A4 Task B rewired
/// this file off `policy_store.hpp` and onto the store-free `ComplianceApi`
/// seam — see compliance_routes.hpp's file banner. The mutator/dispatch
/// routes (no public REST/MCP twin) live in policy_admin_routes.cpp.

#include "compliance_routes.hpp"

#include "compliance_model.hpp"      // shared REST/MCP/fragment builders (#4034, recipe Rule 1)
#include "rest_a4_envelope_http.hpp" // detail::a4_denial/a4_error/ensure_correlation_id — mints/
                                     // reuses X-Correlation-Id so header and body always agree
#include "rest_audit.hpp"           // detail::emit_behavioral_audit (#1647, #4034 follow-up)
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

// Compliance page HTML (defined in compliance_ui.cpp).
extern const char* const kComplianceHtml;

namespace yuzu::server {

namespace {

/// #4034 — local A4-envelope success wrappers, same shape/rationale as
/// rest_api_v1.cpp's/sle_routes.cpp's own TU-local `ok_json`/`list_json`
/// (each self-registering route module keeps its own copy rather than
/// sharing one across TUs — see sle_routes.cpp's file header for the
/// established precedent this file follows).
std::string ok_json(nlohmann::json data) {
    nlohmann::json out;
    out["data"] = std::move(data);
    out["meta"] = nlohmann::json{{"api_version", "v1"}};
    return out.dump();
}

std::string list_json(nlohmann::json data, int64_t total, int64_t start = 0,
                      int64_t page_size = 50) {
    nlohmann::json out;
    out["data"] = std::move(data);
    out["pagination"] =
        nlohmann::json{{"total", total}, {"start", start}, {"page_size", page_size}};
    out["meta"] = nlohmann::json{{"api_version", "v1"}};
    return out.dump();
}

} // namespace

// ── Static helpers ──────────────────────────────────────────────────────────

const char* ComplianceRoutes::compliance_level(int pct) {
    if (pct >= 90) return "good";
    if (pct >= 70) return "warn";
    return "bad";
}

// ── Fragment renderers ──────────────────────────────────────────────────────

std::string ComplianceRoutes::render_compliance_summary_fragment() {
    // Real policy data via the ComplianceApi seam (ADR-0031 WS-A4).
    struct PolicyRow {
        std::string id;
        std::string name;
        std::string scope;
        int pct;
        int compliant;
        int total;
        bool enabled;
    };

    std::vector<PolicyRow> policies;
    // ADR-0056: a degraded read must render distinctly from "genuinely no
    // policies" — collapsing them would show a false "0 policies, nothing to
    // see" state when the real answer is "could not ask the store".
    bool degraded = false;

    if (api_) {
        auto all_policies = api_->list_policies(PolicyQuery{});
        if (!all_policies) {
            degraded = true;
        } else {
            for (const auto& p : *all_policies) {
                auto cs = api_->compliance_summary(p.id);
                if (!cs) {
                    degraded = true;
                    continue;
                }
                // #4034 Rule 1: identity/scope/enabled and compliant/total come
                // from the SAME builders GET /api/v1/policies and
                // GET /api/v1/compliance/{id} call — this fragment cannot drift
                // from the REST/MCP field selection (docs/api-twin-recipe.md §1).
                nlohmann::json row_j = policy_list_row_json(p);
                nlohmann::json cs_j = compliance_summary_json(*cs);
                PolicyRow row;
                row.id = row_j.at("id").get<std::string>();
                row.name = row_j.at("name").get<std::string>();
                row.scope = row_j.at("scope_expression").get<std::string>();
                row.enabled = row_j.at("enabled").get<bool>();
                row.compliant = static_cast<int>(cs_j.at("compliant").get<int64_t>());
                row.total = static_cast<int>(cs_j.at("total").get<int64_t>());
                row.pct = (row.total > 0) ? (row.compliant * 100 / row.total) : 0;
                policies.push_back(std::move(row));
            }
        }
    }

    if (degraded) {
        return "<div class=\"detail-panel\"><div class=\"empty-state\">"
               "Policy data temporarily unavailable (store degraded) — try again shortly."
               "</div></div>";
    }

    // Fleet-level compliance via the seam
    FleetCompliance fc;
    if (api_) {
        auto fc_res = api_->fleet_compliance();
        if (!fc_res) {
            return "<div class=\"detail-panel\"><div class=\"empty-state\">"
                   "Fleet compliance temporarily unavailable (store degraded) — try again "
                   "shortly.</div></div>";
        }
        fc = *fc_res;
    }
    int fleet_pct = static_cast<int>(fc.compliance_pct);

    std::string html;

    // Hero: fleet compliance percentage + bar
    html += "<div class=\"compliance-hero\">"
            "<div class=\"compliance-pct ";
    html += compliance_level(fleet_pct);
    html += "\">" + std::to_string(fleet_pct) + "%</div>"
            "<div class=\"compliance-bar-wrap\">"
            "<div class=\"compliance-bar\">"
            "<div class=\"compliance-fill ";
    html += compliance_level(fleet_pct);
    html += "\" style=\"width:" + std::to_string(fleet_pct) + "%\"></div>"
            "</div>"
            "<div class=\"compliance-stats\">"
            "<span><strong>" + std::to_string(static_cast<int>(policies.size())) + "</strong> policies active</span>"
            "<span><strong>" + std::to_string(static_cast<int>(fc.total_checks)) + "</strong> device checks</span>"
            "</div></div></div>";

    // Policy table
    html += "<table class=\"policy-table\">"
            "<thead><tr>"
            "<th>#</th><th>Policy</th><th>Scope</th>"
            "<th>Compliance</th><th></th><th></th>"
            "</tr></thead><tbody>";

    if (policies.empty()) {
        html += "<tr><td colspan=\"6\" class=\"empty-state\">"
                "No policies defined. Create policies in the Policy Engine to track compliance."
                "</td></tr>";
    } else {
        int row = 0;
        for (const auto& p : policies) {
            ++row;
            html += "<tr>"
                    "<td style=\"color:var(--muted)\">" + std::to_string(row) + "</td>"
                    "<td class=\"policy-name\">" + html_escape(p.name) + "</td>"
                    "<td class=\"policy-scope\">" + html_escape(p.scope) + "</td>"
                    "<td>"
                    "<span class=\"policy-pct " + std::string(compliance_level(p.pct)) + "\">"
                    + std::to_string(p.pct) + "%</span>"
                    "<div class=\"mini-bar\"><div class=\"mini-fill " + std::string(compliance_level(p.pct)) +
                    "\" style=\"width:" + std::to_string(p.pct) + "%\"></div></div>"
                    "</td>"
                    "<td style=\"font-size:0.7rem;color:var(--muted)\">"
                    + std::to_string(p.compliant) + "/" + std::to_string(p.total) +
                    "</td>"
                    "<td>"
                    "<button class=\"btn btn-secondary btn-sm\" "
                    "hx-get=\"/fragments/compliance/" + html_escape(p.id) + "\" "
                    "hx-target=\"#compliance-detail\" "
                    "hx-swap=\"innerHTML\">"
                    "View</button>"
                    "</td></tr>";
        }
    }

    html += "</tbody></table>";
    return html;
}

std::string ComplianceRoutes::render_compliance_detail_fragment(const std::string& policy_id) {
    // Look up the policy via the seam. Low-stakes (page-title fallback
    // only) — a degraded read or not-found just keeps the id as the
    // displayed name; not worth a distinct error state here.
    std::string policy_name = policy_id;
    if (api_) {
        auto policy = api_->get_policy(policy_id);
        if (policy && *policy)
            policy_name = (*policy)->policy.name;
    }

    // Get real compliance statuses via the seam.
    struct AgentRow {
        std::string agent_id;
        std::string hostname;
        std::string os;
        std::string status;
        std::string last_check;
        std::string detail;
    };

    std::vector<AgentRow> agents;
    bool degraded = false;
    // #4034 Rule 1: same confined_policy_compliance tally REST's
    // GET /api/v1/compliance/{id} and MCP's get_policy_agent_statuses use to
    // count agents by status (scope=nullopt/TOP — this fragment has no
    // confinement gate of its own to derive a narrower scope from; the
    // fragment's separate lack-of-RBAC-gate gap is #4042's job, not this
    // one's). Default-constructed (all-zero) until the block below runs, so
    // it stays valid across the degraded/empty early-returns further down.
    ConfinedPolicyCompliance confined;
    confined.summary.policy_id = policy_id;
    if (api_) {
        auto statuses = api_->policy_agent_statuses(policy_id);
        if (!statuses) {
            degraded = true;
            statuses = std::vector<PolicyAgentStatus>{};
        }
        confined = confined_policy_compliance(*statuses, /*scope=*/std::nullopt, policy_id);
        for (const auto& s : confined.visible) {
            nlohmann::json row_j = policy_agent_status_json(s);
            AgentRow row;
            row.agent_id = row_j.at("agent_id").get<std::string>();
            row.status = row_j.at("status").get<std::string>();
            row.detail = row_j.at("check_result").get<std::string>();

            // Look up hostname/os from agent registry
            row.hostname = row.agent_id;
            row.os = "";
            try {
                auto agents_json_str = agents_json_fn_();
                auto arr = nlohmann::json::parse(agents_json_str);
                for (const auto& a : arr) {
                    if (a.value("agent_id", std::string{}) == row.agent_id) {
                        row.hostname = a.value("hostname", row.agent_id);
                        row.os = a.value("os", std::string{});
                        break;
                    }
                }
            } catch (...) {}

            // Format last_check as relative time
            const int64_t last_check_at = row_j.at("last_check_at").get<int64_t>();
            if (last_check_at > 0) {
                auto now = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
                auto delta = now - last_check_at;
                if (delta < 60) row.last_check = std::to_string(delta) + "s ago";
                else if (delta < 3600) row.last_check = std::to_string(delta / 60) + " min ago";
                else row.last_check = std::to_string(delta / 3600) + "h ago";
            } else {
                row.last_check = "never";
            }

            agents.push_back(std::move(row));
        }
    }

    if (degraded) {
        // ADR-0056: must not read the same as "no compliance data yet" —
        // that phrasing tells an operator to wait, when the real answer is
        // "the store could not be asked".
        return "<div class=\"detail-panel\">"
               "<h3>" + html_escape(policy_name) +
               " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
               "(" + html_escape(policy_id) + ")</span></h3>"
               "<div class=\"empty-state\">Compliance data temporarily unavailable (store "
               "degraded) — try again shortly.</div></div>";
    }
    if (agents.empty()) {
        return "<div class=\"detail-panel\">"
               "<h3>" + html_escape(policy_name) +
               " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
               "(" + html_escape(policy_id) + ")</span></h3>"
               "<div class=\"empty-state\">No compliance data yet. "
               "Agents will report status once the policy triggers fire.</div></div>";
    }

    // Status counts come from the SAME confined_policy_compliance tally the
    // agent-row loop above populated `confined.summary` with (#4034 Rule 1) —
    // no second hand-rolled status if/else chain.
    const int compliant = static_cast<int>(confined.summary.compliant);
    const int non_compliant = static_cast<int>(confined.summary.non_compliant);
    const int unknown = static_cast<int>(confined.summary.unknown);
    const int fixing = static_cast<int>(confined.summary.fixing);

    std::string html;
    html += "<div class=\"detail-panel\">"
            "<h3>" + html_escape(policy_name) +
            " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
            "(" + html_escape(policy_id) + ")</span></h3>";

    // Status summary badges
    html += "<div style=\"display:flex;gap:1rem;margin-bottom:0.75rem;font-size:0.75rem\">"
            "<span class=\"status-compliant\">" + std::to_string(compliant) + " compliant</span>"
            "<span class=\"status-non-compliant\">" + std::to_string(non_compliant) + " non-compliant</span>"
            "<span class=\"status-pending-eval\">" + std::to_string(unknown) + " unknown</span>"
            "<span class=\"status-remediated\">" + std::to_string(fixing) + " fixing</span>"
            "</div>";

    // Per-agent table
    html += "<table class=\"detail-table\">"
            "<thead><tr>"
            "<th>Agent</th><th>Hostname</th><th>OS</th>"
            "<th>Status</th><th>Last Check</th><th>Detail</th>"
            "</tr></thead><tbody>";

    for (const auto& a : agents) {
        std::string status_class = "status-compliant";
        if (a.status == "non_compliant") status_class = "status-non-compliant";
        else if (a.status == "unknown") status_class = "status-pending-eval";
        else if (a.status == "fixing") status_class = "status-remediated";
        else if (a.status == "error") status_class = "status-non-compliant";

        std::string status_label = a.status;
        if (status_label == "non_compliant") status_label = "Non-Compliant";
        else if (status_label == "compliant") status_label = "Compliant";
        else if (status_label == "unknown") status_label = "Unknown";
        else if (status_label == "fixing") status_label = "Fixing";
        else if (status_label == "error") status_label = "Error";

        html += "<tr>"
                "<td style=\"font-family:var(--mono);font-size:0.7rem;color:var(--yellow)\">"
                + html_escape(a.agent_id) + "</td>"
                "<td>" + html_escape(a.hostname) + "</td>"
                "<td style=\"font-size:0.75rem;color:var(--muted)\">" + html_escape(a.os) + "</td>"
                "<td><span class=\"" + status_class + "\">" + status_label + "</span></td>"
                "<td style=\"font-size:0.7rem;color:var(--muted)\">" + html_escape(a.last_check) + "</td>"
                "<td style=\"font-size:0.75rem\">" + html_escape(a.detail) + "</td>"
                "</tr>";
    }

    html += "</tbody></table></div>";
    return html;
}

// guardian-confinement-2298 PR3 §3e — see the declaration comment in
// compliance_routes.hpp for the ordering/throw-safety rationale (identical
// to GuardianRoutes::deny_service_scoped_).
bool ComplianceRoutes::deny_service_scoped_(const httplib::Request& req,
                                            httplib::Response& res) const {
    auto session = auth_fn_(req, res);
    if (!session)
        return true; // auth_fn_ already wrote 401/redirect; caller returns.
    if (session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after — a throwing audit_fn_ must not be
    // able to suppress the 403 (mirrors GuardianRoutes::deny_service_scoped_).
    res.status = 403;
    // No `.permission` label: this is a blanket deny with no perm_fn_ gate on
    // either fragment it covers — a service-scoped token HOLDING Policy:Read
    // is still denied here, so naming it as "the missing grant" would be a
    // false self-remediation claim (A4's permission field contract).
    //
    // `a4_denial` (not a hand-built `error_json_a4` + bare correlation id):
    // it mints/reuses the id via `ensure_correlation_id`, which ALSO sets the
    // X-Correlation-Id response header — a hand-built id embeds a
    // correlation_id in the body that the header never carries, breaking the
    // header/body-must-agree contract (found by consistency-auditor, Gate 4).
    res.set_content(
        detail::a4_denial(res, 403,
                          "service-scoped tokens may not read this fleet-wide compliance view"),
        "application/json");
    if (audit_fn_) {
        try {
            audit_fn_(req, "compliance.fragment.access_denied", "denied", "Policy", "",
                      "fleet-wide compliance dashboard fragment denied to a service-scoped "
                      "token (path=" +
                          req.path + ")");
        } catch (const std::exception& e) {
            spdlog::warn("compliance.fragment.access_denied: audit_fn_ threw: {}", e.what());
        } catch (...) {
            spdlog::warn("compliance.fragment.access_denied: audit_fn_ threw (non-std)");
        }
    }
    return true;
}

// ── Route registration ──────────────────────────────────────────────────────

void ComplianceRoutes::register_routes(httplib::Server& svr,
                                       AuthFn auth_fn,
                                       PermFn perm_fn,
                                       AuditFn audit_fn,
                                       ComplianceApiPtr api,
                                       AgentsJsonFn agents_json_fn,
                                       FleetReadFn fleet_read_fn) {
    // Production shim — wrap the real server in an HttplibRouteSink and
    // delegate to the sink-based overload. Same handlers, same lambdas,
    // same observable behaviour. Test code calls the sink overload directly
    // with a TestRouteSink (#2298 PR 3 §3e).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    std::move(api), std::move(agents_json_fn), std::move(fleet_read_fn));
}

void ComplianceRoutes::register_routes(HttpRouteSink& sink,
                                       AuthFn auth_fn,
                                       PermFn perm_fn,
                                       AuditFn audit_fn,
                                       ComplianceApiPtr api,
                                       AgentsJsonFn agents_json_fn,
                                       FleetReadFn fleet_read_fn) {
    // Store dependency pointers
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    api_ = std::move(api);
    agents_json_fn_ = std::move(agents_json_fn);
    fleet_read_fn_ = std::move(fleet_read_fn);

    // -- Compliance dashboard page ----------------------------------------
    sink.Get("/compliance",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         auto session = auth_fn_(req, res);
                         if (!session) {
                             res.set_redirect("/login");
                             return;
                         }
                         res.set_content(kComplianceHtml, "text/html; charset=utf-8");
                     });

    // -- Compliance HTMX fragment: fleet summary --------------------------
    sink.Get("/fragments/compliance/summary",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         if (deny_service_scoped_(req, res)) return;
                         auto session = auth_fn_(req, res);
                         if (!session) return;
                         res.set_content(render_compliance_summary_fragment(),
                                         "text/html; charset=utf-8");
                     });

    // -- Compliance HTMX fragment: per-policy agent detail ----------------
    sink.Get(R"(/fragments/compliance/(\w[\w\-]*))",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         if (deny_service_scoped_(req, res)) return;
                         auto session = auth_fn_(req, res);
                         if (!session) return;
                         auto policy_id = req.matches[1].str();
                         res.set_content(render_compliance_detail_fragment(policy_id),
                                         "text/html; charset=utf-8");
                     });

    // -- Policy Engine API (Phase 5, READ side) -------------------------------

    // GET /api/policy-fragments -- list all fragments
    sink.Get("/api/policy-fragments",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            FragmentQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto frags = api_->list_fragments(q);
            if (!frags) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& f : *frags) {
                arr.push_back({{"id", f.id},
                               {"name", f.name},
                               {"description", f.description},
                               {"check_instruction", f.check_instruction},
                               {"check_compliance", f.check_compliance},
                               {"fix_instruction", f.fix_instruction},
                               {"post_check_instruction", f.post_check_instruction},
                               {"created_at", f.created_at},
                               {"updated_at", f.updated_at}});
            }
            res.set_content(
                nlohmann::json({{"fragments", arr}, {"count", arr.size()}}).dump(),
                "application/json");
        });

    // GET /api/policies -- list all policies
    sink.Get("/api/policies",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            PolicyQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            if (req.has_param("fragment_id"))
                q.fragment_filter = req.get_param_value("fragment_id");
            if (req.has_param("enabled_only"))
                q.enabled_only = true;
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto policies = api_->list_policies(q);
            if (!policies) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : *policies) {
                nlohmann::json inputs_obj = nlohmann::json::object();
                for (const auto& inp : p.inputs)
                    inputs_obj[inp.key] = inp.value;

                nlohmann::json triggers_arr = nlohmann::json::array();
                for (const auto& t : p.triggers) {
                    triggers_arr.push_back({{"id", t.id},
                                            {"type", t.trigger_type},
                                            {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
                }

                arr.push_back({{"id", p.id},
                               {"name", p.name},
                               {"description", p.description},
                               {"fragment_id", p.fragment_id},
                               {"scope_expression", p.scope_expression},
                               {"enabled", p.enabled},
                               {"inputs", inputs_obj},
                               {"triggers", triggers_arr},
                               {"management_groups", p.management_groups},
                               {"created_at", p.created_at},
                               {"updated_at", p.updated_at}});
            }
            res.set_content(
                nlohmann::json({{"policies", arr}, {"count", arr.size()}}).dump(),
                "application/json");
        });

    // GET /api/policies/:id -- get policy detail
    sink.Get(R"(/api/policies/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            // ADR-0031 WS-A4: composite seam call — replaces the former
            // three-read inline assembly (get_policy + get_compliance_summary
            // + a fail-soft get_fragment lookup for remediation_available).
            auto policy_res = api_->get_policy(id);
            if (!policy_res) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            if (!*policy_res) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"policy not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            const PolicyDetail& pd = **policy_res;
            const Policy& policy = pd.policy;

            nlohmann::json inputs_obj = nlohmann::json::object();
            for (const auto& inp : policy.inputs)
                inputs_obj[inp.key] = inp.value;

            nlohmann::json triggers_arr = nlohmann::json::array();
            for (const auto& t : policy.triggers) {
                triggers_arr.push_back({{"id", t.id},
                                        {"type", t.trigger_type},
                                        {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
            }

            const ComplianceSummary& cs = pd.summary;

            res.set_content(
                nlohmann::json({{"id", policy.id},
                                {"name", policy.name},
                                {"description", policy.description},
                                {"yaml_source", policy.yaml_source},
                                {"fragment_id", policy.fragment_id},
                                {"scope_expression", policy.scope_expression},
                                {"enabled", policy.enabled},
                                {"remediation_available", pd.remediation_available},
                                {"inputs", inputs_obj},
                                {"triggers", triggers_arr},
                                {"management_groups", policy.management_groups},
                                {"created_at", policy.created_at},
                                {"updated_at", policy.updated_at},
                                {"compliance", {{"compliant", cs.compliant},
                                                 {"non_compliant", cs.non_compliant},
                                                 {"unknown", cs.unknown},
                                                 {"fixing", cs.fixing},
                                                 {"error", cs.error},
                                                 {"total", cs.total}}}})
                    .dump(),
                "application/json");
        });

    // GET /api/compliance -- fleet compliance summary
    sink.Get("/api/compliance",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto fc = api_->fleet_compliance();
            if (!fc) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            res.set_content(
                nlohmann::json({{"compliance_pct", fc->compliance_pct},
                                {"total_checks", fc->total_checks},
                                {"compliant", fc->compliant},
                                {"non_compliant", fc->non_compliant},
                                {"unknown", fc->unknown},
                                {"fixing", fc->fixing},
                                {"error", fc->error}})
                    .dump(),
                "application/json");
        });

    // GET /api/compliance/:policy_id -- per-policy compliance detail
    //
    // PRE-EXISTING GAP (senior-tracked follow-up, NOT introduced or widened
    // here): this legacy route serves check_result fleet-wide on perm_fn_
    // ALONE — no confinement, no audit, unlike its v1 twin below. Kept
    // BYTE-IDENTICAL through the ADR-0031 WS-A4 rewire; only its data source
    // moved from policy_store_ to the ComplianceApi seam.
    sink.Get(R"(/api/compliance/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto policy_id = req.matches[1].str();
            auto summary = api_->compliance_summary(policy_id);
            auto statuses = api_->policy_agent_statuses(policy_id);
            if (!summary || !statuses) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            nlohmann::json agents_arr = nlohmann::json::array();
            for (const auto& s : *statuses) {
                agents_arr.push_back({{"agent_id", s.agent_id},
                                      {"status", s.status},
                                      {"last_check_at", s.last_check_at},
                                      {"last_fix_at", s.last_fix_at},
                                      {"check_result", s.check_result}});
            }

            res.set_content(
                nlohmann::json({{"policy_id", policy_id},
                                {"summary", {{"compliant", summary->compliant},
                                              {"non_compliant", summary->non_compliant},
                                              {"unknown", summary->unknown},
                                              {"fixing", summary->fixing},
                                              {"error", summary->error},
                                              {"total", summary->total}}},
                                {"agents", agents_arr}})
                    .dump(),
                "application/json");
        });

    // ── /api/v1/compliance* + /api/v1/polic* — REST v1 twins of the legacy
    // /api/compliance*, /api/policies*, /api/policy-fragments routes above
    // (api-parity #4034). All five call the SAME shared builders
    // (compliance_model.hpp) the legacy routes' JSON bodies above are
    // hand-rolled duplicates of — Rule 1, docs/api-twin-recipe.md §1.
    // `GET /api/v1/compliance/{id}` is the one exception to plain
    // `perm_fn_`: its per-agent status list is a fan-out read of per-agent
    // data, so the routed-concerns RBAC row requires `fleet_read_fn_`
    // (require_fleet_read) as its SOLE gate instead — never stacked with
    // perm_fn_. The other four (aggregate/definition reads, no per-agent
    // identity data) stay unaudited, matching the legacy routes' existing
    // posture. `GET /api/v1/compliance/{id}` is the one exception on BOTH
    // axes: its per-agent list names agent_ids fleet-wide AND its
    // `check_result` field can carry raw, unrestricted agent-instruction
    // output, so it gets a FAIL-CLOSED (503) `emit_behavioral_audit` trail,
    // not a set-and-proceed one — see that route's own comment.

    // GET /api/v1/policy-fragments -- list all fragments (MCP twin:
    // list_policy_fragments)
    sink.Get("/api/v1/policy-fragments",
        [this](const httplib::Request& req, httplib::Response& res) {
            detail::ensure_correlation_id(res);
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "policy store not available"),
                                "application/json");
                return;
            }
            FragmentQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            // #4034 follow-up: clamp in 64-bit BEFORE narrowing — mirrors
            // GET /api/v1/inventory/software's identical idiom
            // (rest_api_v1.cpp) and MCP's list_policy_fragments sibling
            // (mcp_server.cpp), which already clamped its own `limit` arg to
            // [1,1000]. A negative or huge value can no longer reach the
            // store's SQL LIMIT unbounded, and the clamped value (not
            // FragmentQuery's raw default) drives pagination.page_size below
            // — previously hard-coded to list_json's own 50 default
            // regardless of what limit was actually applied.
            std::int64_t want_limit = q.limit; // FragmentQuery's own default (100)
            try {
                if (req.has_param("limit"))
                    want_limit = std::stoll(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(detail::a4_error(res, "invalid numeric query parameter"),
                                "application/json");
                return;
            }
            q.limit = static_cast<int>(std::clamp<std::int64_t>(want_limit, 1, 1000));
            auto frags = api_->list_fragments(q);
            if (!frags) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "policy store degraded"),
                                "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& f : *frags)
                arr.push_back(policy_fragment_list_row_json(f));
            res.set_content(
                list_json(arr, static_cast<int64_t>(frags->size()), /*start=*/0, q.limit),
                "application/json");
        });

    // GET /api/v1/policies -- list all policies (MCP twin: list_policies —
    // note that tool's own served fields are a narrower 5-field subset of
    // this row shape; see #4034's PR description for why it stays as-is)
    sink.Get("/api/v1/policies",
        [this](const httplib::Request& req, httplib::Response& res) {
            detail::ensure_correlation_id(res);
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "policy store not available"),
                                "application/json");
                return;
            }
            PolicyQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            if (req.has_param("fragment_id"))
                q.fragment_filter = req.get_param_value("fragment_id");
            // #4034 follow-up: `enabled_only` is a documented boolean query
            // parameter (docs/user-manual/rest-api.md) — presence alone must
            // not decide it, or `enabled_only=false` silently behaves like
            // `enabled_only=true` (the caller asked to see disabled policies
            // and got the opposite). An unrecognized value 400s, matching
            // this handler's own existing posture for a malformed `limit`.
            if (req.has_param("enabled_only")) {
                auto v = req.get_param_value("enabled_only");
                if (v == "true" || v == "1") {
                    q.enabled_only = true;
                } else if (v == "false" || v == "0") {
                    q.enabled_only = false;
                } else {
                    res.status = 400;
                    res.set_content(
                        detail::a4_error(res, "invalid boolean query parameter: enabled_only"),
                        "application/json");
                    return;
                }
            }
            // Clamp in 64-bit BEFORE narrowing — mirrors GET
            // /api/v1/inventory/software's identical idiom and MCP's
            // list_policy_fragments sibling; see the identical comment on
            // GET /api/v1/policy-fragments above for the full rationale.
            std::int64_t want_limit = q.limit; // PolicyQuery's own default (100)
            try {
                if (req.has_param("limit"))
                    want_limit = std::stoll(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(detail::a4_error(res, "invalid numeric query parameter"),
                                "application/json");
                return;
            }
            q.limit = static_cast<int>(std::clamp<std::int64_t>(want_limit, 1, 1000));
            auto policies = api_->list_policies(q);
            if (!policies) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "policy store degraded"),
                                "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : *policies)
                arr.push_back(policy_list_row_json(p));
            res.set_content(
                list_json(arr, static_cast<int64_t>(policies->size()), /*start=*/0, q.limit),
                "application/json");
        });

    // GET /api/v1/policies/:id -- single-policy detail (MCP twin: get_policy)
    sink.Get(R"(/api/v1/policies/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            detail::ensure_correlation_id(res);
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
                return;
            }
            auto id = req.matches[1].str();
            // ADR-0031 WS-A4: the seam's get_policy is COMPOSITE — one call
            // replaces the former get_policy + get_compliance_summary +
            // fail-soft get_fragment (remediation_available) trio.
            auto policy_res = api_->get_policy(id);
            if (!policy_res) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "policy store degraded"),
                                "application/json");
                return;
            }
            if (!*policy_res) {
                res.status = 404;
                res.set_content(detail::a4_error(res, "policy not found"), "application/json");
                return;
            }
            const PolicyDetail& pd = **policy_res;
            res.set_content(ok_json(single_policy_detail_json(pd.policy, pd.summary,
                                                               pd.remediation_available)),
                            "application/json");
        });

    // GET /api/v1/compliance -- fleet compliance summary (MCP twin:
    // get_fleet_compliance)
    sink.Get("/api/v1/compliance",
        [this](const httplib::Request& req, httplib::Response& res) {
            detail::ensure_correlation_id(res);
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
                return;
            }
            auto fc = api_->fleet_compliance();
            if (!fc) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "policy store degraded"),
                                "application/json");
                return;
            }
            res.set_content(ok_json(fleet_compliance_json(*fc)), "application/json");
        });

    // GET /api/v1/compliance/:policy_id -- per-policy compliance detail +
    // per-agent status fan-out (MCP twin: get_policy_agent_statuses — the
    // agents half; get_compliance_summary pre-exists for the summary-only
    // half, see #4034's PR description).
    sink.Get(R"(/api/v1/compliance/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            const auto cid = detail::ensure_correlation_id(res);
            if (!fleet_read_fn_) {
                spdlog::error("GET /api/v1/compliance/{{id}}: fleet_read_fn_ unwired — "
                              "misconfigured call site; failing closed; cid={}",
                              cid);
                res.status = 503;
                res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
                return;
            }
            // require_fleet_read is the SOLE gate here — never stacked with
            // perm_fn_ (routed-concerns RBAC row; the same BLOCKING rule
            // rest_api_v1.cpp's GET /api/v1/inventory/software route
            // documents). It renders 401/403/503 itself and returns
            // !admitted on denial.
            auto gate = fleet_read_fn_(req, res, "Policy", "Read");
            if (!gate.admitted)
                return;
            if (!api_) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
                return;
            }
            auto policy_id = req.matches[1].str();
            auto statuses = api_->policy_agent_statuses(policy_id);
            if (!statuses) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "policy store degraded"),
                                "application/json");
                return;
            }
            // The confined tally (never the store's own unfiltered aggregate)
            // — a confined caller must never see fleet-wide counts for
            // agents it cannot itself list. See compliance_model.hpp's
            // confined_policy_compliance doc comment.
            auto confined = confined_policy_compliance(*statuses, gate.scope, policy_id);
            nlohmann::json agents_arr = nlohmann::json::array();
            for (const auto& s : confined.visible)
                agents_arr.push_back(policy_agent_status_json(s));

            // #4034 follow-up: fail CLOSED on audit-persist failure, matching
            // this codebase's own documented REST-JSON contract
            // (rest_audit.hpp's header comment, #1647: "REST JSON
            // integrations FAIL CLOSED (503)") — the same posture GET
            // /api/v1/guaranteed-state/events' dex.device.view audit uses
            // (rest_api_v1.cpp). Reclassified from the original set-and-
            // proceed posture this route shipped with: `check_result`
            // (policy_agent_status_json) carries up to 1000 bytes of the RAW
            // output of whatever instruction the bound fragment's
            // check_instruction names — free-form, operator-authored at
            // fragment-creation time, and not restricted to a
            // non-behavioural content class (e.g. a fragment bound to
            // processes/list_hashed would put process names/paths here), so
            // this route cannot make the same "not behavioural PII" claim
            // GET /api/v1/inventory/software genuinely can (that route's
            // data is machine-scope by construction, ADR-0016 §8; this
            // route's is not, since check_instruction is unconstrained).
            // Refusing to serve on a KNOWN audit-persist failure is the
            // conservative, documented-contract-conformant choice. The MCP
            // twin (get_policy_agent_statuses) is unaffected by this change —
            // it already follows ITS OWN documented convention (surfacing
            // the gap via an `audit_persisted:false` body field rather than
            // a header/status code), which is what rest_audit.hpp prescribes
            // for MCP specifically ("MCP wraps the kernel itself and
            // surfaces the gap through its own body field").
            if (!detail::emit_behavioral_audit(
                    audit_fn_, req, res, "compliance.agent_statuses.view", "success", "Policy",
                    policy_id, "agents=" + std::to_string(agents_arr.size()) + " cid=" + cid)) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                     "audit subsystem unavailable; refusing to serve per-agent "
                                     "compliance status without durable evidence",
                                     detail::A4ErrorOpts{.retry_after_ms = 5000}),
                    "application/json");
                spdlog::warn(
                    "compliance.agent_statuses.view audit fail-closed (503) policy_id={} cid={}",
                    policy_id, cid);
                return;
            }

            nlohmann::json data;
            data["policy_id"] = policy_id;
            data["summary"] = compliance_summary_json(confined.summary);
            data["agents"] = agents_arr;
            res.set_content(ok_json(data), "application/json");
        });
}

} // namespace yuzu::server
