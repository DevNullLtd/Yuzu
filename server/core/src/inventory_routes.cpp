/// @file inventory_routes.cpp
/// /software route registration — the /inventory redirect, the page shell + the read-only HTMX fragments.
/// Renderers live in inventory_ui.cpp.
///
/// The SOFTWARE page fragments (catalogue, versions, devices) gate SOLELY on
/// `fleet_read_fn` (ADR-0017 admit-then-filter) and parse, page, scope and audit through the
/// shared model (software_catalogue_model.hpp) — the same functions the REST and MCP twins
/// call, so the three surfaces cannot disagree. The fleet-wide catalogue aggregate cannot be
/// narrowed to a management group, so it is refused (audited `denied`) to a confined caller;
/// the host view and the devices table are admitted and scoped.

#include "inventory_routes.hpp"

#include "app_shell.hpp"
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial
#include "rest_audit.hpp" // detail::try_persist_audit — throw-safe set-and-proceed audit kernel (#1647)
#include "web_utils.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

namespace swc = software_catalogue;

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

std::string caveat_div(const std::string& msg) {
    return "<div class=\"inv-caveat\">" + html_escape(msg) + "</div>";
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// A non-negative integer UI hint (`shown`, `total`): full-consume parse, anything else is
/// ignored and never echoed.
std::optional<std::int64_t> int_hint(const httplib::Request& req, const char* key) {
    if (!req.has_param(key))
        return std::nullopt;
    const std::string v = req.get_param_value(key);
    std::int64_t n = 0;
    const auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
    // The ceiling keeps the devices handler's `shown + ids.size()` and the catalogue
    // renderer's `shown_before + rows.size()` far from overflow: an absurd hint is dropped
    // like a malformed one, never clamped into a fake count.
    if (ec != std::errc{} || p != v.data() + v.size() || n < 0 ||
        n > std::numeric_limits<std::int64_t>::max() / 4)
        return std::nullopt;
    return n;
}

/// Service-scoped API tokens never reach the fleet-wide software aggregates (403, no
/// `.permission` — kServiceScopeGlobalSafe is empty, so no grant would admit them). The ONE
/// copy for the three Software fragments; audited `denied`. True = the response is written.
bool deny_service_scoped(const auth::Session& session, const httplib::Request& req,
                         httplib::Response& res, const InventoryRoutes::AuditFn& audit_fn,
                         const char* verb) {
    if (session.token_scope_service.empty())
        return false;
    res.status = 403;
    res.set_content(detail::a4_denial(res, 403,
                                      "service-scoped tokens may not read the fleet-wide software "
                                      "inventory"),
                    "application/json");
    (void)detail::try_persist_audit(audit_fn, req, verb, "denied", "Inventory", "fleet",
                                    "fleet-wide software read denied to a service-scoped token");
    return true;
}

/// The Software fragments' sole gate. nullopt = the response is already written (unwired ->
/// 503 and an error log, the HardwareRoutes idiom; !admitted -> written by the gate).
std::optional<authz::FleetReadGate> admit(const InventoryRoutes::FleetReadFn& fleet_read_fn,
                                          const httplib::Request& req, httplib::Response& res) {
    if (!fleet_read_fn) {
        spdlog::error("inventory software fragments: fleet_read_fn unwired — misconfigured call "
                      "site; failing closed");
        res.status = 503;
        send_html(res, "<div class=\"inv-degrade\"><b>Software inventory unavailable.</b> The "
                       "authorization gate is not wired on this server.</div>");
        return std::nullopt;
    }
    auto gate = fleet_read_fn(req, res, "Inventory", "Read");
    if (!gate.admitted)
        return std::nullopt;
    return gate;
}

constexpr std::size_t kHostTypeaheadCap = 1000;
constexpr const char* kConfinedFleetMsg =
    "The software catalogue is a fleet-wide aggregate that cannot be narrowed to your "
    "management groups, so it is not shown to a group-scoped account. Open a device from "
    "Hardware to see its software, or ask for fleet-wide Inventory:Read.";
constexpr const char* kConfinedHostMsg =
    "This device is outside your management groups (or unknown), so its software is not shown.";
constexpr const char* kBuildingMsg =
    "Catalogue is building \xE2\x80\x94 the rollup refreshes hourly and populates shortly after "
    "startup. Reload in a moment.";
constexpr const char* kStaleCursorMsg =
    "The catalogue was refreshed since this page loaded; reload to restart from the first page.";

SoftwarePageFilters filters_of(const SoftwareCatalogQuery& q, std::string cursor) {
    SoftwarePageFilters f;
    f.q = q.q;
    f.kind = q.kind;
    f.ecosystem = q.ecosystem;
    f.source = q.source;
    f.agent_id = q.agent_id;
    f.versions_min = q.versions_min;
    f.cursor = std::move(cursor);
    return f;
}

} // namespace

void InventoryRoutes::register_routes(httplib::Server& svr, Deps deps) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(deps));
}

void InventoryRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);

    // -- /inventory is retired in favour of /hardware (CI list) — a 302, not a
    // route removal, so bookmarks and the API-parity ledger's history stay intact.
    // Auth still gates first so an unauthenticated caller sees /login, not a
    // redirect loop through an authed-only destination.
    sink.Get("/inventory", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        res.set_redirect("/hardware");
    });

    // -- Page shell: Software — the nav-split successor to the old /inventory shell's
    // default landing tab. Devices moved to /hardware.
    sink.Get("/software", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
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
        // The shared shell is baked with Guardian active; re-target it to Software.
        html = shell::apply_shell(std::move(html), {.active_key = "software"});
        // The page's own CSP-safe script (hash <-> filters, expansion toggles) rides the shell.
        if (const auto p = html.rfind("</body>"); p != std::string::npos)
            html.insert(p, software_page_script());
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        send_html(res, std::move(html));
    });

    // -- SOFTWARE catalogue: full page, `results_only=1` (#sw-results + out-of-band chips),
    // or `rows_only=1` (the Load-more page). Gate order: auth -> service-scope deny ->
    // fleet-read gate -> model parse -> scope rule -> reads -> audit -> render.
    sink.Get("/fragments/inventory/software", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (deny_service_scoped(*session, req, res, deps_.audit_fn, "inventory.software.catalog"))
            return;
        auto gate = admit(deps_.fleet_read_fn, req, res);
        if (!gate)
            return;
        const auto mode = req.has_param("rows_only")      ? SoftwarePageMode::Rows
                          : req.has_param("results_only") ? SoftwarePageMode::Results
                                                          : SoftwarePageMode::Full;
        SoftwarePageFilters f;
        SoftwarePageData d;
        d.now_secs = now_secs();
        auto reply = [&] { send_html(res, render_software_page(f, d, mode)); };

        auto parsed = swc::parse_catalogue_params(req.params);
        if (!parsed) {
            d.caveat = parsed.error(); // 200 + caveat: htmx does not swap 4xx
            reply();
            return;
        }
        swc::CatalogueRequest rq = std::move(*parsed);
        rq.query.limit = static_cast<int>(swc::kCatalogueDefaultLimit); // a fixed page size
        const auto& q = rq.query;
        f = filters_of(q, rq.cursor);
        const bool host = !q.agent_id.empty();
        const bool confined = gate->scope.has_value();
        const bool continuation = !rq.cursor.empty();
        const std::string target = swc::audit_target(q);

        // Scope rule: the fleet aggregate needs an unfiltered gate; the host view needs the
        // device in scope. Anything else is refused (and audited), never silently narrowed.
        if (host ? !authz::in_scope(gate->scope, q.agent_id) : confined) {
            d.confined = true;
            d.caveat = host ? kConfinedHostMsg : kConfinedFleetMsg;
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.catalog", "denied",
                                            "Inventory", target,
                                            "scope: fleet-wide aggregate or out-of-scope device");
            reply();
            return;
        }

        const swc::CatalogueReads io{
            [&] { return deps_.catalog_meta_fn ? deps_.catalog_meta_fn() : std::optional<CatalogRollupMeta>{}; },
            [&](const SoftwareCatalogQuery& c) {
                return deps_.catalog_fn ? deps_.catalog_fn(c)
                                   : std::optional<std::vector<SoftwareCatalogRow>>{};
            },
            [&](const SoftwareCatalogQuery& c) {
                return deps_.totals_fn ? deps_.totals_fn(c) : std::optional<SoftwareCatalogTotals>{};
            },
            // The coverage figures are read below, only for a Full render; the model's own KPI
            // derivation (a first fleet page) is not used, so its stale read stays inert.
            [](std::int64_t) { return std::optional<std::int64_t>{}; }};
        auto read = swc::read_catalogue_page(io, rq, d.now_secs);
        if (!read) {
            if (!read.error()) { // any read degraded (or the generation moved twice)
                (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.catalog", "failure",
                                                "Inventory", target, "store degraded");
                reply(); // rows nullopt -> the retry banner, never an empty table
                return;
            }
            d.caveat = *read.error() == swc::CursorError::kStale
                           ? std::string(kStaleCursorMsg)
                           : std::string(swc::cursor_error_message(*read.error()));
            reply();
            return;
        }
        auto page = std::move(*read);
        page.kpis.reset(); // computed with the inert stale stub above: never consumed, so never kept

        // Strip: fleet figures only for an unconfined caller (a confined host view reads
        // none, and its render carries no tiles). The coverage reads cost a registry walk
        // and a COUNT, so only the full page pays for them.
        if (mode != SoftwarePageMode::Rows && !confined) {
            auto meta = page.meta;
            if (!meta && deps_.catalog_meta_fn) // unconfined host view: the model skips the meta read
                meta = deps_.catalog_meta_fn();
            if (!meta) { // the strip cannot render: a whole-page degrade, audited as the failure it is
                (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.catalog", "failure",
                                                "Inventory", target, "meta degraded");
                reply(); // rows unset -> the retry banner
                return;
            }
            swc::Coverage cov;
            if (mode == SoftwarePageMode::Full) {
                if (deps_.connected_fn)
                    cov.connected = deps_.connected_fn();
                if (deps_.stale_fn)
                    cov.stale = deps_.stale_fn();
            }
            d.kpis = swc::derive_kpis(*meta, cov);
        }
        // Names: the host view's display name (Results/Full) and (Full) the type-ahead list.
        // Rows pages never render either. Never read for a confined caller (a whole-fleet
        // hostname map is fleet disclosure). The devices handler below copies the whole map
        // once per call and looks it up per visible row, for confined callers by design.
        if (!confined && deps_.hostnames_fn &&
            (mode == SoftwarePageMode::Full || (host && mode == SoftwarePageMode::Results))) {
            const auto names = deps_.hostnames_fn();
            if (host) {
                const auto it = names.find(q.agent_id);
                f.host_display = (it != names.end() && !it->second.empty()) ? it->second : q.agent_id;
            }
            if (mode == SoftwarePageMode::Full) {
                // ponytail: a kHostTypeaheadCap-name datalist; a server-side host search when fleets outgrow it
                for (const auto& [id, name] : names)
                    if (!name.empty())
                        d.hosts.emplace_back(name, id);
                std::ranges::sort(d.hosts);
                d.hosts_total = d.hosts.size();
                if (d.hosts.size() > kHostTypeaheadCap)
                    d.hosts.resize(kHostTypeaheadCap);
            }
        } else if (host) {
            f.host_display = q.agent_id;
        }

        d.confined = confined; // confined host view: no strip, no type-ahead
        d.shown_before = int_hint(req, "shown").value_or(0);
        if (!page.next_cursor.empty())
            d.next_cursor = page.next_cursor;
        (void)detail::try_persist_audit(
            deps_.audit_fn, req, "inventory.software.catalog", "success", "Inventory", target,
            "titles=" + std::to_string(page.rows.size()) + " totals=" +
                std::to_string(page.totals.titles) + "/" + std::to_string(page.totals.installs) +
                (continuation ? " page=continuation" : ""));
        d.rows = std::move(page.rows);
        d.totals = page.totals;
        reply();
    });

    // -- SOFTWARE version drill: installs per version for one title, inline under its row.
    sink.Get("/fragments/inventory/software/versions", [this](const httplib::Request& req,
                                                               httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (deny_service_scoped(*session, req, res, deps_.audit_fn, "inventory.software.versions"))
            return;
        auto gate = admit(deps_.fleet_read_fn, req, res);
        if (!gate)
            return;
        auto parsed = swc::parse_versions_params(req.params);
        if (!parsed) {
            send_html(res, caveat_div(parsed.error()));
            return;
        }
        auto q = std::move(parsed->query);
        q.limit = static_cast<int>(swc::kVersionsDefaultLimit);
        const bool host = !q.agent_id.empty();
        const bool confined = gate->scope.has_value();
        const std::string target = swc::audit_target(q);
        if (host ? !authz::in_scope(gate->scope, q.agent_id) : confined) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.versions", "denied",
                                            "Inventory", target,
                                            "scope: fleet-wide aggregate or out-of-scope device");
            send_html(res, caveat_div(host ? kConfinedHostMsg : kConfinedFleetMsg));
            return;
        }
        SoftwarePageFilters f;
        f.kind = q.kind;
        f.ecosystem = q.ecosystem;
        f.source = q.source;
        f.agent_id = q.agent_id;
        // The shared seam (as the REST/MCP twins): the unfiltered fleet drill reads the rollup, so
        // before its first refresh it is `building`, not an authoritative empty table.
        const swc::VersionsReads vio{
            [&] { return deps_.catalog_meta_fn ? deps_.catalog_meta_fn() : std::optional<CatalogRollupMeta>{}; },
            [&](const SoftwareVersionsQuery& v) {
                return deps_.versions_fn ? deps_.versions_fn(v)
                                         : std::optional<std::vector<SoftwareVersionCount>>{};
            }};
        auto read = swc::read_versions(vio, q);
        if (!read && read.error() == swc::VersionsError::kBuilding) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.versions", "failure",
                                            "Inventory", target, "building");
            send_html(res, caveat_div(std::string(kBuildingMsg)));
            return;
        }
        std::optional<std::vector<SoftwareVersionCount>> vers;
        if (read)
            vers = std::move(*read);
        (void)detail::try_persist_audit(
            deps_.audit_fn, req, "inventory.software.versions", vers ? "success" : "failure",
            "Inventory", target, vers ? ("versions=" + std::to_string(vers->size())) : "store degraded");
        // Same rule as the REST twin: a full read may have more rows than it returned.
        const bool truncated = vers && vers->size() == static_cast<std::size_t>(q.limit);
        send_html(res, render_software_versions_expansion(f, q.name, vers, confined, truncated));
    });

    // -- SOFTWARE devices table: which devices run a title (optionally one version), 100 per
    // page. Confined callers are ADMITTED — every row is a per-device read, narrowed by the
    // gate's scope (pushed into SQL up to kScopePushdownMaxIds, post-filtered above it).
    sink.Get("/fragments/inventory/software/devices", [this](const httplib::Request& req,
                                                              httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (deny_service_scoped(*session, req, res, deps_.audit_fn, "inventory.software.query"))
            return;
        auto gate = admit(deps_.fleet_read_fn, req, res);
        if (!gate)
            return;
        auto parsed = swc::parse_devices_params(req.params);
        if (!parsed) {
            send_html(res, caveat_div(parsed.error()));
            return;
        }
        swc::DevicesRequest rq = std::move(*parsed);
        auto& q = rq.query;
        if (q.name.empty()) { // nothing to read: no store call, nothing to audit
            send_html(res, caveat_div("A software title is required."));
            return;
        }
        q.limit = static_cast<int>(swc::kCatalogueDefaultLimit);
        const bool continuation = !rq.cursor.empty();
        const std::string target = swc::audit_target(q);

        SoftwareDevicesTable t;
        t.name = q.name;
        t.version = q.version;
        t.now_secs = now_secs();
        t.scoped = gate->scope.has_value();
        SoftwarePageFilters f;
        f.kind = q.kind;
        f.ecosystem = q.ecosystem;
        f.source = q.source;
        f.agent_id = q.agent_id;
        auto reply = [&] {
            send_html(res, render_software_devices_table(f, t, continuation));
        };

        // The model decodes the cursor, pushes the scope into SQL up to kScopePushdownMaxIds
        // (complete pages) and post-filters only a wider scope with a bounded refill; its cursor
        // never names a row the caller was not served.
        auto read = swc::read_devices_page(
            [&](const SoftwareFleetQuery& c) {
                return deps_.fleet_fn ? deps_.fleet_fn(c)
                                      : std::optional<std::vector<SoftwareFleetRow>>{};
            },
            rq, gate->scope);
        if (!read) {
            if (read.error()) { // 200 + caveat: htmx does not swap 4xx
                send_html(res, caveat_div(std::string(swc::cursor_error_message(*read.error()))));
                return;
            }
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.query", "failure",
                                            "Inventory", target, "store degraded");
            reply(); // t.rows nullopt -> the retry banner
            return;
        }
        std::optional<std::vector<SoftwareFleetRow>> rows{std::move(read->rows)};
        if (!read->next_cursor.empty())
            t.next_cursor = read->next_cursor;

        std::vector<std::string> ids;
        std::unordered_set<std::string> seen;
        for (const auto& r : *rows)
            if (seen.insert(r.agent_id).second)
                ids.push_back(r.agent_id);
        if (deps_.hostnames_fn)
            t.hostnames = deps_.hostnames_fn(); // ponytail: copies the whole 30-day map per page; a keyed lookup if it shows
        if (deps_.last_synced_fn)
            t.last_synced = deps_.last_synced_fn(ids);
        // `shown` hint + this page's DISTINCT devices (a device on two sources is two rows, one
        // device). ponytail: a device straddling a page boundary counts twice; exact dedupe
        // needs client state.
        t.shown_before = int_hint(req, "shown").value_or(0) + static_cast<std::int64_t>(ids.size());
        if (!t.scoped)
            t.total = int_hint(req, "total");

        if (const auto denied = swc::denied_detail(*read); !denied.empty())
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.query", "denied",
                                            "Inventory", target, denied);
        (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.software.query", "success",
                                        "Inventory", target,
                                        "rows=" + std::to_string(rows->size()) +
                                            (continuation ? " page=continuation" : ""));
        t.rows = std::move(rows);
        reply();
    });
}

} // namespace yuzu::server
