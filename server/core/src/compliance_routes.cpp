/// @file compliance_routes.cpp
/// Compliance dashboard HTMX routes plus the read-only policy/fragment/
/// compliance API routes (legacy + v1 twins). Extracted from server.cpp —
/// Phase 3a of the god-object decomposition; ADR-0031 WS-A4 Task B rewired
/// this file off `policy_store.hpp` and onto the store-free `ComplianceApi`
/// seam — see compliance_routes.hpp's file banner. The mutator/dispatch
/// routes (no public REST/MCP twin) live in policy_admin_routes.cpp.

#include "compliance_routes.hpp"

#include "compliance_fragments.hpp" // pure HTML renderers for the fragments below
#include "compliance_model.hpp"      // shared REST/MCP/fragment builders (#4034, recipe Rule 1)
#include "rest_a4_envelope_http.hpp" // detail::a4_denial/a4_error/ensure_correlation_id — mints/
                                     // reuses X-Correlation-Id so header and body always agree
#include "rest_audit.hpp"           // detail::emit_behavioral_audit (#1647, #4034 follow-up)
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
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

// ── Fragment renderers ──────────────────────────────────────────────────────
//
// Markup lives in compliance_fragments.hpp (pure, fixture-testable); this file
// owns the store reads, confinement and the degrade decisions.

std::string ComplianceRoutes::render_compliance_summary_fragment(bool can_write, bool can_execute,
                                                                 bool can_delete) {
    namespace ch = compliance_html;
    ch::SummaryView view;
    view.can_write = can_write;
    view.can_execute = can_execute;
    view.can_delete = can_delete;
    PolicyQuery query;
    view.policy_limit = static_cast<std::size_t>(query.limit);

    // ADR-0056: a degraded read must render distinctly from "genuinely no
    // policies" — collapsing them would show a false "0 policies, nothing to
    // see" state when the real answer is "could not ask the store".
    bool degraded = false;
    if (api_) {
        auto all_policies = api_->list_policies(query);
        if (!all_policies) {
            degraded = true;
        } else {
            for (const auto& p : *all_policies) {
                auto cs = api_->compliance_summary(p.id);
                if (!cs) {
                    degraded = true;
                    continue;
                }
                // #4034 Rule 1: identity/scope/enabled and the status tally come
                // from the SAME builders GET /api/v1/policies and
                // GET /api/v1/compliance/{id} call — this fragment cannot drift
                // from the REST/MCP field selection (docs/api-twin-recipe.md §1).
                nlohmann::json row_j = policy_list_row_json(p);
                nlohmann::json cs_j = compliance_summary_json(*cs);
                ch::PolicyRow row;
                row.id = row_j.at("id").get<std::string>();
                row.name = row_j.at("name").get<std::string>();
                row.scope = row_j.at("scope_expression").get<std::string>();
                row.enabled = row_j.at("enabled").get<bool>();
                row.compliant = cs_j.at("compliant").get<int64_t>();
                row.non_compliant = cs_j.at("non_compliant").get<int64_t>();
                row.unknown = cs_j.at("unknown").get<int64_t>();
                row.fixing = cs_j.at("fixing").get<int64_t>();
                row.error = cs_j.at("error").get<int64_t>();
                row.total = cs_j.at("total").get<int64_t>();
                view.policies.push_back(std::move(row));
            }
        }
    }

    if (degraded) {
        return ch::render_unavailable(
            "Policy data temporarily unavailable (store degraded) — try again shortly.");
    }

    if (api_) {
        auto fc_res = api_->fleet_compliance();
        if (!fc_res) {
            return ch::render_unavailable("Fleet compliance temporarily unavailable (store "
                                          "degraded) — try again shortly.");
        }
        view.fleet = *fc_res;
    }
    return ch::render_summary(view);
}

std::string ComplianceRoutes::render_compliance_detail_fragment(
    const std::string& policy_id, const authz::VisibleSet& scope,
    std::optional<std::size_t>& rows_read) {
    namespace ch = compliance_html;
    rows_read.reset();

    ch::DetailView view;
    view.policy_id = policy_id;
    view.policy_name = policy_id;
    view.confined = scope.has_value();

    if (api_) {
        // The header is best-effort: a degraded read or a not-found keeps the
        // id as the displayed name and omits the kv panel.
        auto policy = api_->get_policy(policy_id);
        if (policy && *policy) {
            const auto& d = **policy;
            view.have_policy = true;
            view.policy_name = d.policy.name;
            view.applies_to = d.policy.scope_expression;
            view.remediation_available = d.remediation_available;
            auto frags = api_->list_fragments(FragmentQuery{});
            if (frags) {
                for (const auto& f : *frags) {
                    if (f.id == d.policy.fragment_id) {
                        view.check = f.check_compliance;
                        break;
                    }
                }
            }
        }

        auto statuses = api_->policy_agent_statuses(policy_id);
        if (!statuses) {
            view.degraded = true;
        } else {
            // #4034 Rule 1 + ADR-0017: the SAME confined tally REST's
            // GET /api/v1/compliance/{id} and MCP's get_policy_agent_statuses
            // use, narrowed to the caller's own scope.
            auto confined = confined_policy_compliance(*statuses, scope, policy_id);
            view.summary = confined.summary;
            rows_read = confined.visible.size();

            // One registry read per render, not one per row.
            std::unordered_map<std::string, std::pair<std::string, std::string>> by_agent;
            try {
                auto arr = nlohmann::json::parse(agents_json_fn_());
                for (const auto& a : arr) {
                    by_agent[a.value("agent_id", std::string{})] = {
                        a.value("hostname", std::string{}), a.value("os", std::string{})};
                }
            } catch (...) {
                // Hostname/OS are display-only; fall back to the agent id.
            }

            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            for (const auto& s : confined.visible) {
                nlohmann::json row_j = policy_agent_status_json(s);
                ch::DetailAgent row;
                row.agent_id = row_j.at("agent_id").get<std::string>();
                row.status = row_j.at("status").get<std::string>();
                row.detail = row_j.at("check_result").get<std::string>();
                row.hostname = row.agent_id;
                auto it = by_agent.find(row.agent_id);
                if (it != by_agent.end()) {
                    if (!it->second.first.empty())
                        row.hostname = it->second.first;
                    row.os = it->second.second;
                }
                row.last_check = ch::format_age(now, row_j.at("last_check_at").get<int64_t>());
                view.agents.push_back(std::move(row));
            }
        }
    }
    return ch::render_detail(view);
}

std::string ComplianceRoutes::render_policy_fragments_fragment() {
    namespace ch = compliance_html;
    if (!api_) {
        return ch::render_unavailable("Fragments temporarily unavailable");
    }
    FragmentQuery fq;
    PolicyQuery pq;
    auto frags = api_->list_fragments(fq);
    auto policies = api_->list_policies(pq);
    if (!frags || !policies) {
        return ch::render_unavailable("Fragments temporarily unavailable");
    }

    ch::FragmentsView view;
    view.fragment_limit = static_cast<std::size_t>(fq.limit);
    // One policy read covers every fragment unless the policy list itself was
    // cut by its cap, in which case a count taken from it would undercount
    // (and make Delete look safe): fall back to one filtered read per
    // fragment, bounded by the fragment cap.
    const bool policies_capped = policies->size() >= static_cast<std::size_t>(pq.limit);
    std::unordered_map<std::string, int64_t> used_by;
    if (!policies_capped) {
        for (const auto& p : *policies)
            ++used_by[p.fragment_id];
    }
    for (const auto& f : *frags) {
        ch::FragmentRow row;
        row.id = f.id;
        row.name = f.name;
        row.check_instruction = f.check_instruction;
        if (!policies_capped) {
            auto it = used_by.find(f.id);
            row.used_by = it == used_by.end() ? 0 : it->second;
        } else {
            PolicyQuery per;
            per.fragment_filter = f.id;
            auto n = api_->list_policies(per);
            if (!n)
                return ch::render_unavailable("Fragments temporarily unavailable");
            row.used_by = static_cast<int64_t>(n->size());
            row.used_by_capped = n->size() >= static_cast<std::size_t>(per.limit);
        }
        view.fragments.push_back(std::move(row));
    }
    return ch::render_fragments(view);
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
    // #4042: service-scoped deny first (blanket), then the same Policy:Read
    // grant GET /api/v1/compliance asks for. perm_fn_ is a GLOBAL grant
    // check, so a holder whose Policy:Read comes only through a management
    // group is refused here (403) and never reaches the confined detail.
    sink.Get("/fragments/compliance/summary",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         if (deny_service_scoped_(req, res)) return;
                         if (!perm_fn_(req, res, "Policy", "Read")) return;
                         // Probe once per summary render, into a throwaway
                         // response (perm_fn_ writes a 403 into what it is
                         // handed and audits each denial). The detail and
                         // fragment panels reuse these flags client-side.
                         httplib::Response probe;
                         const bool can_write = perm_fn_(req, probe, "Policy", "Write");
                         const bool can_execute = perm_fn_(req, probe, "Policy", "Execute");
                         const bool can_delete = perm_fn_(req, probe, "Policy", "Delete");
                         res.set_content(render_compliance_summary_fragment(can_write, can_execute,
                                                                           can_delete),
                                         "text/html; charset=utf-8");
                     });

    // -- Policy fragments list (the HTML twin of GET /api/policy-fragments) --
    // Deliberately OUTSIDE /fragments/compliance/(\w[\w\-]*): that regex is
    // the per-policy id namespace and would swallow a sibling literal.
    sink.Get("/fragments/policy-fragments",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         if (deny_service_scoped_(req, res)) return;
                         if (!perm_fn_(req, res, "Policy", "Read")) return;
                         res.set_content(render_policy_fragments_fragment(),
                                         "text/html; charset=utf-8");
                     });

    // -- Compliance HTMX fragment: per-policy agent detail ----------------
    // #4042: the REST v1 twin's contract. fleet_read_fn_ is the SOLE gate
    // (never stacked with perm_fn_), rows are confined to the caller's
    // scope, and the per-agent read writes compliance.agent_statuses.view.
    // Audit posture follows the dashboard convention (set-and-proceed, flag
    // via Sec-Audit-Failed); the REST twin fails closed instead.
    sink.Get(R"(/fragments/compliance/(\w[\w\-]*))",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         if (deny_service_scoped_(req, res)) return;
                         if (!fleet_read_fn_) {
                             // Unwired is misconfiguration: 503, never a
                             // fall-through to an ungated render.
                             spdlog::error("GET /fragments/compliance/{{id}}: fleet_read_fn_ "
                                           "unwired — misconfigured call site; failing closed");
                             res.status = 503;
                             res.set_content(detail::a4_error(res, "service unavailable"),
                                             "application/json");
                             return;
                         }
                         auto gate = fleet_read_fn_(req, res, "Policy", "Read");
                         if (!gate.admitted) return;
                         auto policy_id = req.matches[1].str();
                         std::optional<std::size_t> rows_read;
                         auto html =
                             render_compliance_detail_fragment(policy_id, gate.scope, rows_read);
                         if (rows_read) {
                             (void)detail::emit_behavioral_audit(
                                 audit_fn_, req, res, "compliance.agent_statuses.view", "success",
                                 "Policy", policy_id,
                                 "agents=" + std::to_string(*rows_read) + " surface=dashboard");
                         }
                         res.set_content(html, "text/html; charset=utf-8");
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
