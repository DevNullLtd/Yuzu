/// @file inventory_routes.cpp
/// /inventory route registration — the /inventory -> /hardware redirect, the /software
/// page shell and the read-only SOFTWARE HTMX fragments. Renderers live in
/// inventory_ui.cpp. The catalogue / version drill / "devices >" expansion are
/// FLEET-WIDE aggregates gated on the GLOBAL Inventory:Read; the expansion additionally
/// applies the per-row management-group drop filter (+ omission audit) the REST sibling
/// does. An unwired provider degrades to an honest banner.

#include "inventory_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial
#include "rest_audit.hpp" // detail::try_persist_audit — throw-safe set-and-proceed audit kernel (#1647)

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

// Clamp a `limit` query param into [1, hi] in 64-bit BEFORE narrowing, so a
// negative/wrapped value can't defeat the cap (mirrors the REST route).
int clamp_limit(const httplib::Request& req, int dflt, int hi) {
    if (!req.has_param("limit"))
        return dflt;
    try {
        std::int64_t want = std::stoll(req.get_param_value("limit"));
        return static_cast<int>(std::clamp<std::int64_t>(want, 1, hi));
    } catch (...) {
        return dflt;
    }
}

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

} // namespace

void InventoryRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                      CatalogFn catalog_fn, CatalogMetaFn catalog_meta_fn,
                                      VersionsFn versions_fn, FleetSoftwareFn fleet_fn,
                                      ScopeFn scope_fn, StaleFn stale_fn, AuditFn audit_fn,
                                      HostnamesFn hostnames_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(catalog_fn),
                    std::move(catalog_meta_fn), std::move(versions_fn), std::move(fleet_fn),
                    std::move(scope_fn), std::move(stale_fn), std::move(audit_fn),
                    std::move(hostnames_fn));
}

void InventoryRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                      CatalogFn catalog_fn, CatalogMetaFn catalog_meta_fn,
                                      VersionsFn versions_fn, FleetSoftwareFn fleet_fn,
                                      ScopeFn scope_fn, StaleFn stale_fn, AuditFn audit_fn,
                                      HostnamesFn hostnames_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    catalog_fn_ = std::move(catalog_fn);
    catalog_meta_fn_ = std::move(catalog_meta_fn);
    versions_fn_ = std::move(versions_fn);
    fleet_fn_ = std::move(fleet_fn);
    scope_fn_ = std::move(scope_fn);
    stale_fn_ = std::move(stale_fn);
    audit_fn_ = std::move(audit_fn);
    hostnames_fn_ = std::move(hostnames_fn);

    // -- /inventory is retired in favour of /hardware (CI list) — a 302, not a
    // route removal, so bookmarks and the API-parity ledger's history stay intact.
    // Auth still gates first so an unauthenticated caller sees /login, not a
    // redirect loop through an authed-only destination.
    sink.Get("/inventory", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        res.set_redirect("/hardware");
    });

    // -- Page shell: Software catalogue — the nav-split successor to the
    // old /inventory shell's default landing tab. Devices moved to /hardware.
    sink.Get("/software", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        std::string html(kGuardianDetailPageHtml);
        auto sub = [&](const std::string& tok, const std::string& val) {
            for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
                html.replace(p, tok.size(), val);
        };
        sub("{{TITLE}}", "Yuzu \xE2\x80\x94 Software");
        sub("{{FRAGMENT}}", "/fragments/inventory/software");
        // Mark the Software nav item active, Guardian (the shell default) inactive.
        sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
            "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
        sub("<a href=\"/software\" class=\"nav-link\">Software</a>",
            "<a href=\"/software\" class=\"nav-link active\">Software</a>");
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        send_html(res, std::move(html));
    });

    // -- SOFTWARE catalogue (fleet-wide aggregate; global Inventory:Read) --
    sink.Get("/fragments/inventory/software",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 SoftwareCatalogQuery q;
                 q.q = req.has_param("q") ? req.get_param_value("q") : "";
                 q.limit = clamp_limit(req, 200, 2000);
                 // results_only=1 (round-3 item 8, mirrors hardware_ui.cpp's fix for
                 // the same class of bug): the search box's own hx-get swaps ONLY
                 // #sw-results, so a re-render never destroys the input mid-keystroke.
                 const bool results_only = req.has_param("results_only");
                 std::optional<std::vector<SoftwareCatalogRow>> cat;
                 if (catalog_fn_)
                     cat = catalog_fn_(q);
                 std::optional<CatalogRollupMeta> meta;
                 if (catalog_meta_fn_)
                     meta = catalog_meta_fn_();
                 const bool capped = cat && static_cast<int>(cat->size()) == q.limit;
                 std::optional<std::int64_t> stale;
                 if (stale_fn_)
                     stale = stale_fn_();
                 const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count();
                 // Set-and-proceed audit via the #1647 throw-safe kernel (a throwing
                 // audit sink → false, never an httplib 500): parity with the REST sibling.
                 (void)detail::try_persist_audit(
                     audit_fn_, req, "inventory.software.catalog", cat ? "success" : "failure",
                     "Inventory", q.q.empty() ? "fleet" : ("q=" + q.q),
                     cat ? ("titles=" + std::to_string(cat->size())) : "store degraded");
                 send_html(res, render_inventory_software_fragment(cat, meta, q.q, stale,
                                                                   capped, now, results_only));
             });

    // -- SOFTWARE "devices ›" expansion (round-3 item 8): which devices run title
    // `name`, inline under the catalogue row.
    // Fleet-wide read + per-row management-group scope drop.
    sink.Get("/fragments/inventory/software/devices",
             [this](const httplib::Request& req, httplib::Response& res) {
                 auto session = auth_fn_(req, res);
                 if (!session)
                     return;
                 if (!session->token_scope_service.empty()) {
                     res.status = 403;
                     res.set_content(
                         detail::a4_denial(
                             res, 403,
                             "service-scoped tokens may not run a fleet-wide software search"),
                         "application/json");
                     (void)detail::try_persist_audit(
                         audit_fn_, req, "inventory.software.query", "denied", "Inventory", "fleet",
                         "fleet-wide software search denied to a service-scoped token");
                     return;
                 }
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 const std::string name = req.has_param("name") ? req.get_param_value("name") : "";
                 SoftwareFleetQuery q;
                 q.name = name;
                 q.limit = clamp_limit(req, 1000, 1000);
                 std::optional<std::vector<SoftwareFleetRow>> rows_opt;
                 if (fleet_fn_ && !name.empty())
                     rows_opt = fleet_fn_(q);

                 std::unordered_map<std::string, std::string> hostnames;
                 if (hostnames_fn_)
                     hostnames = hostnames_fn_();

                 if (name.empty()) {
                     send_html(res, render_inventory_software_devices_fragment(
                                        name, std::nullopt, false, 0, hostnames));
                     return;
                 }
                 if (!rows_opt) {
                     (void)detail::try_persist_audit(audit_fn_, req, "inventory.software.query",
                                                     "failure", "Inventory", "name=" + name,
                                                     "store degraded");
                     send_html(res, render_inventory_software_devices_fragment(
                                        name, std::nullopt, false, 0, hostnames));
                     return;
                 }
                 auto& rows = *rows_opt;
                 const bool hit_cap = static_cast<int>(rows.size()) == q.limit;

                 std::size_t dropped = 0;
                 if (scope_fn_) {
                     std::unordered_map<std::string, bool> memo;
                     std::vector<SoftwareFleetRow> visible;
                     visible.reserve(rows.size());
                     for (auto& r : rows) {
                         auto [m, inserted] = memo.try_emplace(r.agent_id, false);
                         if (inserted)
                             m->second = scope_fn_(session->username, r.agent_id);
                         if (m->second)
                             visible.push_back(std::move(r));
                         else if (inserted)
                             ++dropped;
                     }
                     rows.swap(visible);
                 }
                 if (dropped > 0)
                     (void)detail::try_persist_audit(
                         audit_fn_, req, "inventory.software.query", "denied", "Inventory",
                         "name=" + name,
                         "scope: filtered " + std::to_string(dropped) +
                             " out-of-management-group device(s)");
                 (void)detail::try_persist_audit(audit_fn_, req, "inventory.software.query",
                                                 "success", "Inventory", "name=" + name,
                                                 "rows=" + std::to_string(rows.size()));
                 send_html(res, render_inventory_software_devices_fragment(
                                    name, rows_opt, hit_cap, dropped, hostnames));
             });

    // -- SOFTWARE version drill (installs per version for one title) --
    sink.Get("/fragments/inventory/software/versions",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 const std::string name = req.has_param("name") ? req.get_param_value("name") : "";
                 std::optional<std::vector<SoftwareVersionCount>> vers;
                 if (versions_fn_ && !name.empty())
                     vers = versions_fn_(name, 500);
                 if (!name.empty())
                     (void)detail::try_persist_audit(
                         audit_fn_, req, "inventory.software.versions", vers ? "success" : "failure",
                         "Inventory", "name=" + name,
                         vers ? ("versions=" + std::to_string(vers->size())) : "store degraded");
                 send_html(res, render_inventory_versions_fragment(name, vers));
             });
}

} // namespace yuzu::server
