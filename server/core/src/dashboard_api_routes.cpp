#include "dashboard_api_routes.hpp"

#include "analytics_event_store.hpp"
#include "audit_store.hpp"
#include "data_export.hpp"
#include "http_route_sink.hpp"
#include "json_extract.hpp" // extract_json_string — shared JSON body-extraction helper
#include "rbac_store.hpp"
#include "scope_engine.hpp"

#include <exception>
#include <stdexcept>
#include <string>

namespace yuzu::server::dashboard_api {

void register_dashboard_api_routes(HttpRouteSink& sink, Deps deps) {
    // Fail fast at boot, not per-request: an unset visible_agents_json_fn is a
    // caller wiring bug, same class as CommandCapabilityRegistry's constructor
    // (command_capability.hpp) throwing on a missing required input — no other
    // *Deps-struct* field in this campaign asserts itself this way yet, so a
    // future field with the same "no safe degrade" property should follow this
    // shape. Catching it here means the server refuses to start rather than
    // serving a silent, permanent 503 with no signal (governance Gate 4/6
    // finding on the PR that introduced this module).
    if (!deps.visible_agents_json_fn) {
        throw std::invalid_argument(
            "register_dashboard_api_routes: deps.visible_agents_json_fn must be bound");
    }

    // -- Current user info (/api/me) --------------------------------------
    sink.Get("/api/me", [deps](const httplib::Request& req, httplib::Response& res) {
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;
        // #1837: `username` is the STABLE authorization principal (an
        // opaque `oidc:<iss>#<sub>` id for SSO sessions) — never render
        // it alone as the nav-bar identity. `display_name` is the
        // human-readable label consumed by every page's nav/context
        // bar JS below; falls back to `username` for a legacy session
        // created before this field existed.
        auto j = nlohmann::json(
            {{"username", session->username},
            {"display_name",
             session->display_name.empty() ? session->username : session->display_name},
            {"role", auth::role_to_string(session->role)}});
        // Add RBAC role if enabled
        if (deps.rbac_store && deps.rbac_store->is_rbac_enabled()) {
            j["rbac_enabled"] = true;
            auto roles = deps.rbac_store->get_principal_roles("user", session->username);
            if (!roles.empty()) {
                j["rbac_role"] = roles[0].role_name;
            } else {
                // Fallback: map legacy role to RBAC role name
                j["rbac_role"] =
                    session->role == auth::Role::admin ? "Administrator" : "Viewer";
            }
        } else {
            j["rbac_enabled"] = false;
            j["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
        }
        res.set_content(j.dump(), "application/json");
    });

    // -- Agent listing API ------------------------------------------------
    // Call order (perm_fn(Infrastructure,Read) before auth_fn) is preserved
    // verbatim from server.cpp. Do NOT read this as guaranteeing a 403 over a
    // 401 for a caller with neither a session nor the grant: `perm_fn` is
    // bound to `require_permission`, whose OWN first action is an internal
    // `require_auth` call — a session-less caller is already answered 401 by
    // that internal check before any permission verdict is reached, so this
    // external ordering does not change the caller-visible status code
    // (verified against auth_routes.cpp's require_permission/require_auth;
    // governance Gate 4 finding). What this order DOES guarantee is that
    // `perm_fn` is the first gate every request hits — the explicit
    // `auth_fn` call below is reached only after a permission verdict —
    // matching the pre-extraction code exactly.
    sink.Get("/api/agents", [deps](const httplib::Request& req,
                                   httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;
        res.set_content(deps.visible_agents_json_fn(session->username).dump(),
                        "application/json");
    });

    // -- Audit API -----------------------------------------------------------
    sink.Get("/api/audit", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "AuditLog", "Read"))
            return;

        if (!deps.audit_store || !deps.audit_store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"audit store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        AuditQuery q;
        if (req.has_param("principal"))
            q.principal = req.get_param_value("principal");
        if (req.has_param("action"))
            q.action = req.get_param_value("action");
        if (req.has_param("target_type"))
            q.target_type = req.get_param_value("target_type");
        if (req.has_param("target_id"))
            q.target_id = req.get_param_value("target_id");
        try {
            if (req.has_param("since"))
                q.since = std::stoll(req.get_param_value("since"));
            if (req.has_param("until"))
                q.until = std::stoll(req.get_param_value("until"));
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));
            if (req.has_param("offset"))
                q.offset = std::stoi(req.get_param_value("offset"));
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        // Range, not just parseability: a negative limit would otherwise
        // reach PG as `LIMIT -1`, error, and be reported as an audit-store
        // DEGRADE — 503 plus the read-degrade counter the availability
        // alert pages on — rather than the client error it is (Gate 2
        // security). A negative offset is already inert at the store, but
        // it is a client error here too, so say so.
        if (q.limit < 1 || q.offset < 0) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"limit must be >= 1 and offset >= 0"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // ADR-0040: reads are degrade-distinguishable. A store/pool failure
        // returns nullopt — surface 503, NEVER a false-empty 200 (an audit
        // blip must not read as "no activity" — evidence integrity).
        auto results = deps.audit_store->query(q);
        if (!results) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"audit store degraded"},"data":null})",
                "application/json");
            return;
        }

        nlohmann::json arr = nlohmann::json::array();
        for (const auto& e : *results) {
            arr.push_back({{"id", e.id},
                           {"timestamp", e.timestamp},
                           {"principal", e.principal},
                           {"principal_role", e.principal_role},
                           {"action", e.action},
                           {"target_type", e.target_type},
                           {"target_id", e.target_id},
                           {"detail", e.detail},
                           {"source_ip", e.source_ip},
                           {"result", e.result}});
        }
        // Total is a best-effort adornment now that the page rows are in
        // hand: it takes a SECOND, independent lease, so it can degrade while
        // the page rows are perfectly good. Do not answer a second 503 —
        // but do NOT substitute the page size either. That reads as
        // `count == total`, i.e. "this page is the whole trail", which is
        // plausible and wrong on the one store whose entire posture in this
        // change is that a blip must never read as an absence (Gate 3
        // cpp-expert + Gate 2 security; the old `0` was at least obviously
        // wrong). `null` is the honest answer and JSON has it.
        auto total = deps.audit_store->total_count();
        res.set_content(nlohmann::json({{"events", arr},
                                        {"count", arr.size()},
                                        {"total", total ? nlohmann::json(*total)
                                                        : nlohmann::json(nullptr)}})
                            .dump(),
                        "application/json");
    });

    // -- Generic JSON-to-CSV export -----------------------------------------
    sink.Post("/api/export/json-to-csv", [deps](const httplib::Request& req,
                                                httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Response", "Read"))
            return;

        auto csv = data_export::json_array_to_csv(req.body);
        if (csv.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid JSON array"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        res.set_header("Content-Disposition", "attachment; filename=\"export.csv\"");
        res.set_content(csv, "text/csv; charset=utf-8");
    });

    // -- Scope API --------------------------------------------------------
    sink.Post("/api/scope/validate", [deps](const httplib::Request& req,
                                            httplib::Response& res) {
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;

        auto expression = extract_json_string(req.body, "expression");
        if (expression.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"expression required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto result = yuzu::scope::validate(expression);
        if (result) {
            res.set_content(R"({"valid":true})", "application/json");
        } else {
            res.set_content(
                nlohmann::json({{"valid", false}, {"error", result.error()}}).dump(),
                "application/json");
        }
    });

    // -- Analytics API ---------------------------------------------------------
    sink.Get("/api/analytics/status",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                     return;

                 nlohmann::json j;
                 if (deps.analytics_store) {
                     // Degrade-distinguishable seam (ADR-0049): a
                     // transient PG blip 503s rather than
                     // rendering pending_count=0, which would be
                     // indistinguishable from a genuinely empty
                     // buffer.
                     auto pending = deps.analytics_store->pending_count();
                     if (!pending) {
                         res.status = 503;
                         res.set_content(
                             R"({"error":{"code":503,"message":)"
                             R"("analytics store degraded"},)"
                             R"("meta":{"api_version":"v1"}})",
                             "application/json");
                         return;
                     }
                     j["enabled"] = true;
                     j["pending_count"] = *pending;
                     j["total_emitted"] = deps.analytics_store->total_emitted();
                 } else {
                     j["enabled"] = false;
                     j["pending_count"] = 0;
                     j["total_emitted"] = 0;
                 }
                 res.set_content(j.dump(), "application/json");
             });

    sink.Get(
        "/api/analytics/recent", [deps](const httplib::Request& req, httplib::Response& res) {
            if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                return;

            int limit = 50;
            if (req.has_param("limit")) {
                try {
                    limit = std::stoi(req.get_param_value("limit"));
                } catch (...) {}
            }
            // A non-positive limit isn't a client-error worth a 400 (this
            // route has always silently ignored a malformed value), but
            // unlike SQLite's LIMIT -1 = "unlimited" idiom the old store
            // relied on, Postgres's LIMIT REJECTS a negative bind
            // outright — which query_recent() below can only report as
            // nullopt (degraded), and this route would then 503
            // "analytics store degraded" for a client-supplied bad
            // parameter, not an actual store problem (governance Gate 4
            // unhappy-path finding, 2026-08-16, following up on the
            // happy-path reviewer's flagged lead). Clamp instead.
            if (limit <= 0)
                limit = 50;
            if (!deps.analytics_store) {
                res.set_content(R"({"events":[],"count":0})", "application/json");
                return;
            }
            auto events = deps.analytics_store->query_recent(limit);
            if (!events) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":)"
                                R"("analytics store degraded"},)"
                                R"("meta":{"api_version":"v1"}})",
                                "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& e : *events) {
                arr.push_back(e);
            }
            res.set_content(nlohmann::json({{"events", arr}, {"count", arr.size()}}).dump(),
                            "application/json");
        });
}

} // namespace yuzu::server::dashboard_api
