/// @file inventory_routes.cpp
/// /inventory route registration — the page shell + the read-only HTMX fragments.
/// Renderers live in inventory_ui.cpp. SOFTWARE catalogue / version drill / FIND are
/// FLEET-WIDE aggregates gated on the GLOBAL Inventory:Read; FIND additionally applies
/// the per-row management-group drop filter (+ omission audit) the REST sibling does.
/// The PER-DEVICE software drill gates on scoped_perm_fn(Inventory,Read,id) and audits
/// the access (set-and-proceed — machine-scope data, lower sensitivity than the
/// behavioural-PII device lenses). An unwired provider degrades to an honest banner.

#include "inventory_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial
#include "rest_audit.hpp" // detail::try_persist_audit — throw-safe set-and-proceed audit kernel (#1647)

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <expected>
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
                                      ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn,
                                      CatalogMetaFn catalog_meta_fn, VersionsFn versions_fn,
                                      FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn,
                                      DevicesFn devices_fn, ScopeFn scope_fn, StaleFn stale_fn,
                                      AuditFn audit_fn, AgentCiFn agent_ci_fn,
                                      HostnamesFn hostnames_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(catalog_fn), std::move(catalog_meta_fn), std::move(versions_fn),
                    std::move(fleet_fn), std::move(agent_sw_fn), std::move(devices_fn),
                    std::move(scope_fn), std::move(stale_fn), std::move(audit_fn),
                    std::move(agent_ci_fn), std::move(hostnames_fn));
}

void InventoryRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                      ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn,
                                      CatalogMetaFn catalog_meta_fn, VersionsFn versions_fn,
                                      FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn,
                                      DevicesFn devices_fn, ScopeFn scope_fn, StaleFn stale_fn,
                                      AuditFn audit_fn, AgentCiFn agent_ci_fn,
                                      HostnamesFn hostnames_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    catalog_fn_ = std::move(catalog_fn);
    catalog_meta_fn_ = std::move(catalog_meta_fn);
    versions_fn_ = std::move(versions_fn);
    fleet_fn_ = std::move(fleet_fn);
    agent_sw_fn_ = std::move(agent_sw_fn);
    devices_fn_ = std::move(devices_fn);
    agent_ci_fn_ = std::move(agent_ci_fn);
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

    // -- Page shell: Software (catalogue + Find) — the nav-split successor to the
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
                 q.name_filter = req.has_param("q") ? req.get_param_value("q") : "";
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
                     "Inventory", q.name_filter.empty() ? "fleet" : ("q=" + q.name_filter),
                     cat ? ("titles=" + std::to_string(cat->size())) : "store degraded");
                 send_html(res, render_inventory_software_fragment(cat, meta, q.name_filter, stale,
                                                                   capped, now, results_only));
             });

    // -- SOFTWARE "devices ›" expansion (round-3 item 8): which devices run title
    // `name`, inline under the catalogue row instead of the separate Find tab.
    // Same fleet-wide read + per-row management-group scope drop as the Find
    // results route below (cloned deliberately, not refactored into a shared
    // handler, to keep each route's own audit verb / gate order independently
    // readable — the plan's own "clone, don't share" call for this route).
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

    // -- DEVICES (CI-enriched list; global Inventory:Read, scoped provider) --
    sink.Get("/fragments/inventory/devices",
             [this](const httplib::Request& req, httplib::Response& res) {
                 auto session = auth_fn_(req, res);
                 if (!session)
                     return;
                 // Fleet-wide GDPR-personal-data disclosure (SEC-2/SEC-3
                 // confinement-gap class, found during a docs sweep): devices_fn_
                 // below is username-keyed and does not confine a service-scoped
                 // API token whose principal resolves to an unscoped grant — the
                 // serial/system_uuid/primary_mac-bearing roster would still be
                 // fleet-wide. Same verb as the route's own success/failure audit.
                 if (!session->token_scope_service.empty()) {
                     // Write the 403 FIRST, audit after (normalized — #3167).
                     // `.permission` omitted: kServiceScopeGlobalSafe is
                     // compile-time-empty, so no grant admits a service-scoped
                     // caller here; naming one would be a false
                     // self-remediation claim.
                     res.status = 403;
                     res.set_content(
                         detail::a4_denial(
                             res, 403,
                             "service-scoped tokens may not read the fleet-wide device "
                             "inventory list"),
                         "application/json");
                     (void)detail::try_persist_audit(
                         audit_fn_, req, "inventory.devices", "denied", "Inventory", "fleet",
                         "fleet-wide device inventory list denied to a service-scoped token");
                     return;
                 }
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 InventoryDevicesResult result;
                 if (devices_fn_)
                     result = devices_fn_(session->username);
                 else
                     result.ci_degraded = true; // unwired closure: no CI enrichment possible
                 // Audit the identity-bearing roster read. PR2's device-CI columns (incl.
                 // serial — a device-persistent identifier, ADR-0016 §"personal data under
                 // GDPR") now ride this bulk read, so this is promoted to the
                 // emit_behavioral_audit tier (Sec-Audit-Failed on a persist failure) —
                 // gov Gate 2 review: ADR-0016 explicitly classifies serial/system_uuid/
                 // primary_mac as GDPR personal data, so the lighter machine-scope-data
                 // posture the OTHER inventory.* verbs use (host/OS/software titles — not
                 // device-persistent identifiers) does not transfer to this route now that
                 // it carries CI. Set-and-proceed: the HTML surface still renders.
                 // `result.ci_degraded` (#1785 review HIGH-1) discriminates "roster read
                 // fine, CI enrichment also fine" from "roster read fine, CI columns blank
                 // because the enrichment join failed" — the roster itself is offline-
                 // survivable and never fails on a CI-store outage (see InventoryDevicesResult),
                 // so this is "failure" only for the CI-enrichment half, never a 5xx.
                 // A degrade with an empty roster (`offline_endpoint_store_` unavailable, or
                 // an unwired provider) is worded distinctly from a degrade with a populated
                 // roster (the CI join specifically failed) — gov Gate 3 review: the roster
                 // never actually goes empty this way in a healthy boot (ADR-0012 fails the
                 // server closed on a missing offline_endpoint_store_), but the detail string
                 // shouldn't assert "roster rendered" when it wasn't.
                 (void)detail::emit_behavioral_audit(
                     audit_fn_, req, res, "inventory.devices",
                     result.ci_degraded ? "failure" : "success", "Inventory", "fleet",
                     "devices=" + std::to_string(result.rows.size()) +
                         (!result.ci_degraded
                              ? " (incl. CI columns: serial/model/cpu/ram)"
                          : result.rows.empty()
                              ? " (device roster or CI store unavailable)"
                              : " (CI store degraded; roster rendered without CI columns)"));
                 send_html(res, render_inventory_devices_fragment(result.rows, "", "", ""));
             });

    // -- PER-DEVICE software drill (scoped per-device; audited) --
    sink.Get("/fragments/inventory/device",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
                 const std::string host = req.has_param("host") ? req.get_param_value("host") : "";
                 const bool online =
                     req.has_param("online") && req.get_param_value("online") == "1";
                 if (id.empty()) {
                     res.status = 400;
                     send_html(res, "<div class=\"inv-empty\">Missing device id.</div>");
                     return;
                 }
                 // Tier + management-group scope gate (writes 403 on deny).
                 if (!scoped_perm_fn_(req, res, "Inventory", "Read", id))
                     return;
                 std::optional<std::vector<SoftwareEntry>> sw;
                 if (agent_sw_fn_)
                     sw = agent_sw_fn_(id);
                 // Set-and-proceed audit (machine-scope data; HTML surface still renders)
                 // via the #1647 throw-safe kernel.
                 (void)detail::try_persist_audit(
                     audit_fn_, req, "inventory.device.software", sw ? "success" : "failure",
                     "Inventory", "agent=" + id,
                     sw ? ("rows=" + std::to_string(sw->size())) : "store degraded");

                 // CI record (PR2). An unwired closure is treated the same as a live
                 // store failure (mirrors agent_sw_fn_ unwired -> nullopt -> degrade
                 // banner) — a real deployment always wires this.
                 std::expected<std::optional<DeviceCiRecord>, CiReadError> ci =
                     std::unexpected(CiReadError::kDegraded);
                 if (agent_ci_fn_)
                     ci = agent_ci_fn_(id);
                 // Separate, distinctly-countable audit verb — serial/system_uuid/primary_mac
                 // are device-persistent identifiers (GDPR personal data per ADR-0016), so
                 // this uses emit_behavioral_audit (Sec-Audit-Failed on a persist failure),
                 // the SAME tier as the tar.dns.read + tar.arp.read pair and DEX/Guardian
                 // per-device lenses — gov Gate 2 review corrected an earlier draft that
                 // used the lighter try_persist_audit tier (the installed-software drill's
                 // tier), which ADR-0016 doesn't support for CI data specifically. Reading
                 // OK even when the record is genuinely absent (a value holding
                 // std::nullopt) is "success", not "failure" — only the kDegraded
                 // store-failure case is a failure. Set-and-proceed: the HTML surface
                 // still renders even on a persist failure.
                 (void)detail::emit_behavioral_audit(
                     audit_fn_, req, res, "inventory.device.ci",
                     ci.has_value() ? "success" : "failure", "Inventory", "agent=" + id,
                     !ci.has_value()   ? "store degraded"
                     : ci->has_value() ? "found"
                                       : "absent");
                 const std::int64_t now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                                    std::chrono::system_clock::now().time_since_epoch())
                                                    .count();
                 send_html(res, render_inventory_device_software_fragment(id, host, sw, online, ci,
                                                                          now_secs));
             });

    // -- FIND shell (search box + empty results container) --
    sink.Get("/fragments/inventory/find",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 const std::string init = req.has_param("name") ? req.get_param_value("name") : "";
                 send_html(res, render_inventory_find_fragment(init));
             });

    // -- FIND results (which devices run X; per-row management-group scope filter) --
    sink.Get("/fragments/inventory/find/results",
             [this](const httplib::Request& req, httplib::Response& res) {
                 auto session = auth_fn_(req, res);
                 if (!session)
                     return;
                 // Same fleet-wide GDPR-adjacent confinement gap as
                 // /fragments/inventory/devices above: the per-agent scope_fn_
                 // filter below is management-group-only, so it never confines
                 // a service-scoped API token — this route would still return
                 // every device fleet-wide running a named piece of software.
                 // The REST/MCP twins migrated onto real confinement (#3290
                 // Phase 2); this dashboard fragment deliberately keeps this
                 // blanket deny for now — a follow-up, not an oversight. Same
                 // verb the route's own scope-drop/success rows already use,
                 // reused with result="denied" (governance finding: this
                 // file's sibling fix two routes above closed the same class
                 // here).
                 if (!session->token_scope_service.empty()) {
                     // Write the 403 FIRST, audit after (normalized — #3167).
                     // `.permission` omitted: kServiceScopeGlobalSafe is
                     // compile-time-empty, so no grant admits a service-scoped
                     // caller here; naming one would be a false
                     // self-remediation claim.
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

                 if (name.empty()) {
                     // No name → no data read → nothing to audit (the renderer prompts for input).
                     send_html(res, render_inventory_find_results_fragment(name, std::nullopt, false, 0));
                     return;
                 }
                 if (!rows_opt) {
                     (void)detail::try_persist_audit(audit_fn_, req, "inventory.software.query",
                                                     "failure", "Inventory", "name=" + name,
                                                     "store degraded");
                     send_html(res,
                               render_inventory_find_results_fragment(name, std::nullopt, false, 0));
                     return;
                 }
                 auto& rows = *rows_opt;
                 // Cap hit captured BEFORE the scope filter shrinks `rows` (mirrors REST).
                 const bool hit_cap = static_cast<int>(rows.size()) == q.limit;

                 // Per-agent management-group drop filter (mirrors the REST route / MCP tool):
                 // memoised per distinct agent_id. Unwired (RBAC-off / test) → no filter.
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
                 // Set-and-proceed via the throw-safe kernel. A scope drop emits BOTH a
                 // `denied` row (the dropped count, for cross-operator isolation evidence)
                 // AND the `success` row for the visible rows — mirrors the REST sibling.
                 if (dropped > 0)
                     (void)detail::try_persist_audit(
                         audit_fn_, req, "inventory.software.query", "denied", "Inventory",
                         "name=" + name,
                         "scope: filtered " + std::to_string(dropped) +
                             " out-of-management-group device(s)");
                 (void)detail::try_persist_audit(audit_fn_, req, "inventory.software.query", "success",
                                                 "Inventory", "name=" + name,
                                                 "rows=" + std::to_string(rows.size()));
                 send_html(res,
                           render_inventory_find_results_fragment(name, rows_opt, hit_cap, dropped));
             });
}

} // namespace yuzu::server
