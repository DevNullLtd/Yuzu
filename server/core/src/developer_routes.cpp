#include "developer_routes.hpp"

#include "agent_registry.hpp"
#include "developer_render.hpp"
#include "discover_routes.hpp"
#include "http_route_sink.hpp"
#include "openapi_spec_access.hpp"
#include "rbac_store.hpp"

#include <spdlog/spdlog.h>

#include <exception>
#include <string>

// Page template, baked with the shell at static init (developer_ui.cpp).
extern const char* const kSettingsDeveloperHtml;

namespace yuzu::server::developer {

namespace {

using nlohmann::json;

void send_html(httplib::Response& res, const std::string& html) {
    // The REST twins send `private, max-age=300`; a settings page must always
    // read live, and the permissions fragment varies per caller.
    res.set_header("Cache-Control", "no-store");
    res.set_content(html, "text/html; charset=utf-8");
}

/// The route catalogue parses the compiled-in default OpenAPI document, about 650 KB
/// (measured as compact JSON of the literal without the guides, before ecosystem
/// token expansion; it grows as operations are added), so parse it once: the
/// document cannot change while the process runs. Filtering happens on the
/// parsed rows in render_routes_table.
const json& routes_doc() {
    static const json doc = json::parse(build_routes_catalog(openapi_spec_json()).json, nullptr,
                                        /*allow_exceptions=*/false);
    return doc;
}

/// Build-embedded plugin manifests: compiled in, never fleet-derived.
const json& plugin_docs_doc() {
    static const json doc =
        json::parse(plugin_docs_catalog().json, nullptr, /*allow_exceptions=*/false);
    return doc;
}

/// Every Developer fragment is admin-only, like the page: the admin gate first (it writes its own
/// 403 and denial row), then the twin's `Infrastructure:Read`. On the RBAC-off default the flat
/// Read gate admits any authenticated caller, so it cannot be the only check here.
bool gate(const Deps& deps, const httplib::Request& req, httplib::Response& res) {
    return deps.admin_fn(req, res) && deps.perm_fn(req, res, "Infrastructure", "Read");
}

std::string query_filter(const httplib::Request& req) {
    return req.has_param("q") ? clean_filter(req.get_param_value("q")) : std::string{};
}

} // namespace

void register_developer_routes(HttpRouteSink& sink, Deps deps) {
    sink.Get("/settings/developer", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.admin_fn(req, res)) {
            res.set_redirect("/");
            return;
        }
        res.set_content(kSettingsDeveloperHtml, "text/html; charset=utf-8");
    });

    sink.Get("/fragments/settings/developer/api",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, req, res))
                     return;
                 std::size_t n = 0;
                 const auto& doc = routes_doc();
                 if (doc.is_object() && doc.contains("count") && doc["count"].is_number_integer())
                     n = doc["count"].get<std::size_t>();
                 send_html(res, render_api_panel(n));
             });

    sink.Get("/fragments/settings/developer/routes",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, req, res))
                     return;
                 send_html(res, render_routes_table(routes_doc(), query_filter(req)));
             });

    sink.Get("/fragments/settings/developer/permissions",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, req, res))
                     return;
                 constexpr const char* kFail =
                     "The permission catalogue could not be read. This is not an empty list.";
                 if (!deps.rbac_store || !deps.rbac_store->is_open()) {
                     send_html(res, render_state("fail", kFail));
                     return;
                 }
                 try {
                     // Same decision the REST route makes: the role grid is the
                     // authorization topology and is gated by UserManagement:Read.
                     // Only a draw-time decision, so it uses the non-auditing probe
                     // (a denial row on every load would fill the audit log); the taxonomy
                     // still renders, with a denied note for the grid. No probe wired
                     // means no grid.
                     const bool include_roles =
                         deps.probe_fn && deps.probe_fn(req, "UserManagement", "Read");
                     const auto built = build_permissions_catalog(*deps.rbac_store, include_roles);
                     send_html(res, render_permissions_table(
                                        json::parse(built.json, nullptr, false), query_filter(req)));
                 } catch (const std::exception& e) {
                     spdlog::warn("developer page: permission catalogue read failed: {}", e.what());
                     send_html(res, render_state("fail", kFail));
                 }
             });

    sink.Get("/fragments/settings/developer/plugins",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, req, res))
                     return;
                 send_html(res, render_plugins_table(plugin_docs_doc()));
             });

    // Lazy: the observed list walks every connected agent's plugin metadata
    // under the registry lock, so it is fetched only when the operator asks.
    sink.Get("/fragments/settings/developer/plugins/observed",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, req, res))
                     return;
                 if (!deps.registry) {
                     send_html(res, render_state("fail", "The list of plugins reported by devices "
                                                         "could not be read."));
                     return;
                 }
                 const auto built = build_plugins_catalog(*deps.registry, nullptr);
                 send_html(res, render_observed_plugins(json::parse(built.json, nullptr, false),
                                                        plugin_docs_doc()));
             });
}

} // namespace yuzu::server::developer
