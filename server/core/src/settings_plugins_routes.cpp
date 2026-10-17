#include "settings_plugins_routes.hpp"

#include "plugin_config_parsers.hpp"
#include "plugin_config_store.hpp"
#include "plugin_page_model.hpp"
#include "product_pack_store.hpp"
#include "rbac_store.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <set>
#include <utility>

extern const char* const kSettingsPluginsHtml;

namespace yuzu::server::settings_plugins {

namespace {

namespace pp = yuzu::server::plugin_page;

constexpr const char* kHtml = "text/html; charset=utf-8";
constexpr std::size_t kPackShownLimit = 100;
constexpr std::size_t kConfigRowCap = 5000; // PluginConfigStore::kListRowCap (plugin_config_store.cpp)

/// Non-writing "may this principal do X?" for the render decision. `require_permission`
/// writes a 403 and an audit row on a refusal, which a fragment that answers 200 with a
/// note must not do. Mirrors that gate's outcome: an active elevation admits; with RBAC
/// enforced the grant decides; with RBAC off the page's own legacy-admin gate (already
/// passed) is the authority, and Read is always allowed there.
bool may(const Deps& d, const auth::Session& s, const std::string& type, const std::string& op) {
    if (auth::is_elevated(s) && s.token_scope_service.empty())
        return true;
    if (d.rbac_store && rbac_enforcement_in_effect(d.rbac_store))
        return d.rbac_store->check_permission(s.username, type, op);
    return true;
}

/// Resolve the session without letting auth_fn write into the real response.
std::optional<auth::Session> session_of(const Deps& d, const httplib::Request& req) {
    httplib::Response probe;
    return d.auth_fn ? d.auth_fn(req, probe) : std::nullopt;
}

/// Plugin names (and each plugin's action names) connected agents have reported.
struct Catalogue {
    bool available{false};
    std::vector<std::string> plugins;
    std::set<std::pair<std::string, std::string>> actions; // (plugin, action)
};

Catalogue read_catalogue(const Deps& d) {
    Catalogue c;
    if (!d.help_json_fn)
        return c;
    auto doc = nlohmann::json::parse(d.help_json_fn(), nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.is_object() || !doc.contains("plugins") ||
        !doc["plugins"].is_array())
        return c;
    c.available = true;
    for (const auto& p : doc["plugins"]) {
        if (!p.is_object() || !p.value("name", std::string()).size())
            continue;
        const std::string name = p.value("name", std::string());
        c.plugins.push_back(name);
        if (p.contains("actions") && p["actions"].is_array())
            for (const auto& a : p["actions"])
                if (a.is_object())
                    c.actions.emplace(name, a.value("name", std::string()));
    }
    std::sort(c.plugins.begin(), c.plugins.end());
    c.plugins.erase(std::unique(c.plugins.begin(), c.plugins.end()), c.plugins.end());
    return c;
}

} // namespace

void register_settings_plugins_routes(HttpRouteSink& sink, Deps deps) {
    // ── GET /settings/plugins ── legacy admin, redirect home on refusal (as /settings).
    sink.Get("/settings/plugins", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.admin_fn(req, res)) {
            res.set_redirect("/");
            return;
        }
        res.set_content(kSettingsPluginsHtml, kHtml);
    });

    // ── GET /fragments/settings/plugin-config ── twin: GET /api/v1/plugin-config
    //    (MCP list_plugin_config). ADR-0017 admit-then-filter: only AdmitAll serves the
    //    list; a management-group-confined grant is refused exactly as the REST twin does.
    sink.Get("/fragments/settings/plugin-config",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.admin_fn(req, res))
                     return;
                 res.set_header("Cache-Control", "no-store");
                 pp::ConfigPanel panel;
                 panel.row_cap = kConfigRowCap;
                 const auto session = session_of(deps, req);
                 if (!session) {
                     panel.state = pp::PanelState::Denied;
                 } else if (!deps.rbac_store || !deps.rbac_store->is_open()) {
                     panel.state = pp::PanelState::Degraded;
                 } else if (!auth::is_elevated(*session) &&
                            deps.rbac_store->authorize_list_read(session->username, "PluginConfig",
                                                                 "Read", deps.mgmt_store)
                                    .decision != ListReadDecision::AdmitAll) {
                     // An active JIT elevation is full admin for its window (as in
                     // AuthRoutes::require_list_read); authorize_list_read has no such concept.
                     panel.state = pp::PanelState::Denied;
                 } else if (!deps.config_store || !deps.config_store->is_open()) {
                     panel.state = pp::PanelState::Degraded;
                 } else {
                     bool truncated = false;
                     auto rows = deps.config_store->list_config("", &truncated);
                     if (!rows) {
                         panel.state = pp::PanelState::Degraded;
                     } else {
                         panel.truncated = truncated;
                         panel.rows.reserve(rows->size());
                         for (auto& e : *rows)
                             panel.rows.push_back({std::move(e.plugin), std::move(e.key),
                                                   std::move(e.value), e.updated_at_ms,
                                                   std::move(e.updated_by)});
                     }
                 }
                 res.set_content(pp::render_config_panel(panel), kHtml);
             });

    // ── GET /fragments/settings/kill-switch?plugin=&action= ── twin:
    //    GET /api/v1/plugin-config/{plugin}/kill-switch (MCP get_plugin_kill_switch).
    //    Lookup only: no route lists the switches that are set.
    sink.Get("/fragments/settings/kill-switch",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.admin_fn(req, res))
                     return;
                 res.set_header("Cache-Control", "no-store");
                 pp::KillSwitchPanel panel;
                 const auto session = session_of(deps, req);
                 if (!session || !may(deps, *session, "PluginConfig", "Read")) {
                     panel.state = pp::PanelState::Denied;
                     res.set_content(pp::render_kill_switch_panel(panel), kHtml);
                     return;
                 }
                 if (!deps.config_store || !deps.config_store->is_open()) {
                     panel.state = pp::PanelState::Degraded;
                     res.set_content(pp::render_kill_switch_panel(panel), kHtml);
                     return;
                 }

                 // Fleet-observed names feed the datalist and the name check. The discover
                 // catalogue is Infrastructure:Read on the REST side, so it is read here
                 // only when the principal holds that too.
                 Catalogue cat;
                 if (may(deps, *session, "Infrastructure", "Read"))
                     cat = read_catalogue(deps);
                 panel.catalogue_available = cat.available;
                 panel.known_plugins = cat.plugins;

                 panel.plugin = req.get_param_value("plugin");
                 panel.action = req.get_param_value("action");
                 if (panel.plugin.empty()) {
                     res.set_content(pp::render_kill_switch_panel(panel), kHtml);
                     return;
                 }
                 const auto scope = plugin_config::parse_kill_switch_scope(panel.plugin, panel.action);
                 if (!scope) {
                     panel.input_error =
                         "That plugin or action name is not valid. Names are lowercase letters, "
                         "digits and underscores, starting with a letter.";
                     res.set_content(pp::render_kill_switch_panel(panel), kHtml);
                     return;
                 }
                 panel.protective = plugin_config::kill_switch_row_covers_protective(*scope);
                 panel.plugin_known =
                     std::find(cat.plugins.begin(), cat.plugins.end(), panel.plugin) !=
                     cat.plugins.end();
                 panel.action_known =
                     panel.action.empty() || cat.actions.count({panel.plugin, panel.action}) > 0;

                 // All-OS layer, then each OS layer. With an `os` the store answers the
                 // EFFECTIVE value and names the deciding row in `source`.
                 std::size_t unreadable = 0;
                 for (const char* os : {"", "windows", "linux", "darwin"}) {
                     pp::SwitchLayer layer;
                     layer.os = os;
                     auto e = deps.config_store->get_kill_switch(panel.plugin, panel.action, os);
                     if (!e) {
                         ++unreadable; // never shown as Enabled
                     } else {
                         layer.state = e->enabled ? pp::SwitchState::Enabled
                                                  : pp::SwitchState::Disabled;
                         layer.reason = e->reason;
                         layer.set_by = e->set_by;
                         layer.updated_at_ms = e->updated_at_ms;
                         layer.source = e->source;
                     }
                     panel.layers.push_back(std::move(layer));
                 }
                 if (unreadable == panel.layers.size()) {
                     panel.layers.clear();
                     panel.state = pp::PanelState::Degraded;
                 }
                 res.set_content(pp::render_kill_switch_panel(panel), kHtml);
             });

    // ── GET /fragments/settings/product-packs ── twin: GET /api/v1/product-packs
    //    (MCP list_product_packs). N+1 requested so "First N shown" is exact.
    sink.Get("/fragments/settings/product-packs",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.admin_fn(req, res))
                     return;
                 res.set_header("Cache-Control", "no-store");
                 pp::PacksPanel panel;
                 panel.shown_limit = kPackShownLimit;
                 const auto session = session_of(deps, req);
                 if (!session || !may(deps, *session, "ProductPack", "Read")) {
                     panel.state = pp::PanelState::Denied;
                 } else if (!deps.pack_store || !deps.pack_store->is_open()) {
                     panel.state = pp::PanelState::Degraded;
                 } else {
                     ProductPackQuery q;
                     q.limit = static_cast<int>(kPackShownLimit) + 1;
                     auto packs = deps.pack_store->list(q);
                     if (!packs) {
                         panel.state = pp::PanelState::Degraded;
                     } else {
                         panel.more = packs->size() > kPackShownLimit;
                         const auto n = std::min(packs->size(), kPackShownLimit);
                         for (std::size_t i = 0; i < n; ++i) {
                             const auto& p = (*packs)[i];
                             pp::PackRow row{.id = p.id,
                                             .name = p.name,
                                             .version = p.version,
                                             .description = p.description,
                                             .installed_at = p.installed_at,
                                             .verified = p.verified};
                             for (const auto& it : p.items)
                                 row.items.push_back({it.kind, it.name, it.item_id});
                             panel.rows.push_back(std::move(row));
                         }
                     }
                 }
                 res.set_content(pp::render_packs_panel(panel), kHtml);
             });
}

} // namespace yuzu::server::settings_plugins
