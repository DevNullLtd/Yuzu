#include "settings_plugins_routes.hpp"

#include "plugin_config_parsers.hpp"
#include "plugin_config_store.hpp"
#include "plugin_page_model.hpp"
#include "product_pack_store.hpp"

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

/// The auto-loading fragments' admin gate: the quiet probe against a throwaway response, so a
/// refusal is rendered as a 200 note (htmx drops a 4xx body) and an interactive cookie session
/// writes no denial row. Unwired fails closed.
bool fragment_admin(const Deps& d, const httplib::Request& req) {
    httplib::Response scratch;
    return d.probe_admin_fn && d.probe_admin_fn(req, scratch);
}

/// May this principal read `type:Read`? The gate's own decision with its denial evidence
/// (withheld for a cookie session only). Unwired fails closed.
bool may_read(const Deps& d, const httplib::Request& req, const char* type) {
    return d.probe_perm_fn && d.probe_perm_fn(req, type, "Read");
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
    //    (MCP list_plugin_config). The twin's own rule, as ONE gate: `require_list_read`
    //    (ADR-0017 admit-then-filter, elevation admitted) via `probe_list_read_fn`, and as
    //    there a management-group-scoped admission is refused (this resource is not
    //    agent-scoped). The page is never wider than the API for any principal.
    sink.Get("/fragments/settings/plugin-config",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 res.set_header("Cache-Control", "no-store");
                 pp::ConfigPanel panel;
                 httplib::Response scratch; // the gate's 401/403/503 never reaches the page
                 if (!fragment_admin(deps, req) || !deps.probe_list_read_fn) {
                     panel.state = pp::PanelState::Denied;
                 } else if (const auto gate = deps.probe_list_read_fn(req, scratch, "PluginConfig", "Read");
                            !gate.admitted) {
                     // A 503 from the gate means the authorization store was unavailable:
                     // degraded, not a refusal. Defensive: an ordinary caller's closed or
                     // degraded RBAC store fails closed as a 403 (deny-on-degrade) and reads as
                     // Denied, and an engine principal, the only 503 source, never passes the
                     // admin probe above.
                     panel.state = scratch.status == 503 ? pp::PanelState::Degraded
                                                         : pp::PanelState::Denied;
                 } else if (gate.scope) {
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
                 res.set_header("Cache-Control", "no-store");
                 pp::KillSwitchPanel panel;
                 if (!fragment_admin(deps, req) || !may_read(deps, req, "PluginConfig")) {
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
                 if (may_read(deps, req, "Infrastructure"))
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
                 res.set_header("Cache-Control", "no-store");
                 pp::PacksPanel panel;
                 panel.shown_limit = kPackShownLimit;
                 if (!fragment_admin(deps, req) || !may_read(deps, req, "ProductPack")) {
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
