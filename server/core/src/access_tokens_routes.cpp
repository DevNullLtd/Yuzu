// Tokens and principals page: route registration (see access_tokens_routes.hpp).

#include "access_tokens_routes.hpp"

#include "access_tokens_render.hpp"
#include "access_tokens_ui.hpp"
#include "http_route_sink.hpp"
#include "rest_audit.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <stdexcept>
#include <variant>

namespace yuzu::server {

// server/core/src/yuzu_tokens_js_bundle.cpp (embed_js.py, see server/core/meson.build)
extern const std::string kYuzuTokensJs;

namespace access_tokens {

namespace {

constexpr const char* kHtml = "text/html; charset=utf-8";

void respond_fragment(httplib::Response& res, const std::string& body) {
    // Principal and token metadata: never cached, never shared.
    res.set_header("Cache-Control", "no-store, private");
    res.set_content(body, kHtml);
}

// An engine credential carries mcp_tier=readonly, which `admin_fn` already refuses. This is
// the belt for a future engine auth path (same posture as the REST lifecycle routes).
bool deny_engine_session(const Deps& d, const auth::Session& s, const httplib::Request& req,
                         httplib::Response& res, const char* action) {
    if (s.principal_kind != "engine" && s.auth_source != "engine_token")
        return false;
    (void)detail::emit_behavioral_audit(d.audit_fn, req, res, action, "denied", "EnginePrincipal", "",
                                        "engine_session_denied");
    res.status = 403;
    res.set_header("Cache-Control", "no-store");
    res.set_content(R"({"error":{"code":403,"message":"engine principals cannot access this endpoint"}})",
                    "application/json");
    return true;
}

// The loud admin gate, then the session, then the engine belt. Nothing is read before this
// returns a session. `action` names the audit verb a denial is recorded under.
std::optional<auth::Session> gate_principals(const Deps& d, const httplib::Request& req,
                                             httplib::Response& res, const char* action) {
    if (!d.admin_fn(req, res))
        return std::nullopt;
    auto session = d.auth_fn(req, res);
    if (!session)
        return std::nullopt;
    if (deny_engine_session(d, *session, req, res, action))
        return std::nullopt;
    return session;
}

} // namespace

void register_access_tokens_routes(HttpRouteSink& sink, Deps deps) {
    if (!deps.auth_fn || !deps.admin_fn || !deps.perm_fn || !deps.audit_fn || !deps.rbac_enforced_fn ||
        !deps.now_fn || !deps.list_tokens_fn || !deps.list_principals_fn || !deps.all_roles_fn ||
        !deps.get_principal_fn || !deps.active_credentials_fn || !deps.principal_roles_fn ||
        !deps.revoke_detail_fn)
        throw std::invalid_argument(
            "access_tokens::register_access_tokens_routes: every Deps member is required");

    sink.Get("/access/tokens", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.auth_fn(req, res)) {
            res.set_redirect("/login");
            return;
        }
        // No page-level probe: each panel is gated by its own fragment.
        res.set_header("Cache-Control", "no-store");
        res.set_content(kAccessTokensHtml, kHtml);
    });

    sink.Get("/fragments/access/tokens/list",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "ApiToken", "Read"))
                     return;
                 const auto session = deps.auth_fn(req, res);
                 if (!session)
                     return;
                 const bool all_owners = sees_all_owners(*session);
                 // An empty filter means EVERY owner, so an empty username must never fall
                 // through to it: refuse rather than widen.
                 if (!all_owners && session->username.empty()) {
                     spdlog::error("access_tokens: authenticated session has an empty username");
                     res.status = 500;
                     res.set_header("Cache-Control", "no-store");
                     res.set_content("Session has no username.", "text/plain; charset=utf-8");
                     return;
                 }
                 const PageFlags flags{deps.now_fn(), all_owners, deps.rbac_enforced_fn()};
                 auto rows = deps.list_tokens_fn(all_owners ? std::string{} : session->username);
                 if (!rows) {
                     spdlog::warn("/fragments/access/tokens/list: {}", rows.error());
                     respond_fragment(res, render_tokens_list(Unavailable{}, flags));
                     return;
                 }
                 TokensView view;
                 view.rows = std::move(*rows);
                 view.all_owners = all_owners;
                 view.show_all = req.get_param_value("state") == "all";  // anything else = active
                 respond_fragment(res, render_tokens_list(view, flags));
             });

    sink.Get("/fragments/access/principals/list",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate_principals(deps, req, res, "engine_principal.list"))
                     return;
                 auto rows = deps.list_principals_fn();
                 if (!rows) {
                     spdlog::warn("/fragments/access/principals/list: {}", rows.error());
                     respond_fragment(res, render_principals_list(Unavailable{}));
                     return;
                 }
                 PrincipalsView view;
                 view.rows = std::move(*rows);
                 // The store returns oldest first; the cap banner promises the newest.
                 std::ranges::reverse(view.rows);
                 if (auto roles = deps.all_roles_fn(); roles)
                     view.roles = std::move(*roles);
                 else {
                     spdlog::warn("/fragments/access/principals/list roles: {}", roles.error());
                     view.roles = Unavailable{};
                 }
                 // Read posture shared with the REST twin: a dropped audit row sets
                 // Sec-Audit-Failed and the page still renders (the page script surfaces it).
                 (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, "engine_principal.list",
                                                     "success", "EnginePrincipal", "",
                                                     "count=" + std::to_string(view.rows.size()));
                 // The Roles column is a bulk privilege enumeration; the REST twin audits it too.
                 if (std::holds_alternative<std::vector<PrincipalRole>>(view.roles))
                     (void)detail::emit_behavioral_audit(
                         deps.audit_fn, req, res, "engine_principal.role.listed", "success",
                         "EnginePrincipal", "", "count=" + std::to_string(view.rows.size()));
                 respond_fragment(res, render_principals_list(view));
             });

    sink.Get("/fragments/access/principals/detail",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate_principals(deps, req, res, "engine_principal.get"))
                     return;
                 const std::string id = req.get_param_value("id");
                 // A malformed id is treated as no selection: no store read, no error text.
                 if (!valid_principal_id(id)) {
                     respond_fragment(res, render_select_principal());
                     return;
                 }
                 auto row = deps.get_principal_fn(id);
                 if (!row) {
                     spdlog::warn("/fragments/access/principals/detail: {}", row.error());
                     respond_fragment(res, render_principal_detail(Unavailable{}, id));
                     return;
                 }
                 if (!*row) {
                     respond_fragment(res, render_principal_detail(NotFound{}, id));
                     return;
                 }
                 PrincipalDetail d;
                 d.row = std::move(**row);
                 d.now = deps.now_fn();
                 if (auto c = deps.active_credentials_fn(id); c)
                     d.credentials = std::move(*c);
                 else
                     d.credentials = Unavailable{};
                 const bool roles_ok = [&] {
                     auto r = deps.principal_roles_fn(id);
                     if (!r) {
                         d.roles = Unavailable{};
                         return false;
                     }
                     d.roles = std::move(*r);
                     return true;
                 }();
                 d.revoke_detail = std::string{};
                 if (d.row.lifecycle_state != "active") {
                     if (auto rd = deps.revoke_detail_fn(id); rd)
                         d.revoke_detail = std::move(*rd);
                     else
                         d.revoke_detail = Unavailable{};
                 }
                 (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, "engine_principal.get",
                                                     "success", "EnginePrincipal", id, "");
                 if (roles_ok)
                     (void)detail::emit_behavioral_audit(deps.audit_fn, req, res,
                                                         "engine_principal.role.listed", "success",
                                                         "EnginePrincipal", id, "");
                 respond_fragment(res, render_principal_detail(d, id));
             });

    sink.Get("/static/yuzu-tokens.js", [](const httplib::Request&, httplib::Response& res) {
        // The script binds to fragment markup, so a long max-age would skew after an upgrade.
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(kYuzuTokensJs, "application/javascript; charset=utf-8");
    });
}

} // namespace access_tokens
} // namespace yuzu::server
