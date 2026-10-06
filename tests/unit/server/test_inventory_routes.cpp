/// @file test_inventory_routes.cpp
/// Tests for the /software dashboard — the PURE renderers (data-in / HTML-out) and
/// the route wiring driven in-process through TestRouteSink (no httplib acceptor,
/// #438). Focus areas: the authoritative-read DEGRADE-≠-EMPTY contract (a nullopt
/// data arg → an "unavailable" banner, never a silent empty table), the "devices ›"
/// per-row management-group scope drop (+ omission audit, mirroring the REST
/// sibling), and the service-scoped-token blanket deny.

#include "inventory_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

SoftwareCatalogRow cat_row(std::string n, std::string pub, std::int64_t dev, std::int64_t vers) {
    SoftwareCatalogRow r;
    r.name = std::move(n);
    r.publisher = std::move(pub);
    r.device_count = dev;
    r.version_count = vers;
    return r;
}

SoftwareFleetRow fleet_row(std::string agent, std::string name, std::string ver) {
    SoftwareFleetRow r;
    r.agent_id = std::move(agent);
    r.entry.name = std::move(name);
    r.entry.version = std::move(ver);
    return r;
}

} // namespace

// ───────────────────────── PURE renderers ──────────────────────────────────────

TEST_CASE("software fragment: degrade is a banner, never an empty table", "[inventory][ui]") {
    // cat nullopt = rollup unreadable → degrade banner (meta irrelevant).
    const std::string degraded =
        render_inventory_software_fragment(std::nullopt, std::nullopt, "", std::nullopt, false, 2000);
    REQUIRE(contains(degraded, "unavailable"));
    REQUIRE(contains(degraded, "authoritative"));
    // A degrade must NOT masquerade as a genuine "nothing installed".
    REQUIRE_FALSE(contains(degraded, "No installed-software inventory has been reported"));
}

TEST_CASE("software fragment: building vs genuine empty are distinct", "[inventory][ui]") {
    // meta.refreshed_at == 0 → rollup never computed → "building", NOT a false empty.
    const std::string building = render_inventory_software_fragment(
        std::optional<std::vector<SoftwareCatalogRow>>(std::vector<SoftwareCatalogRow>{}),
        std::optional<CatalogRollupMeta>(CatalogRollupMeta{0, 0, 0}), "", std::int64_t{0}, false,
        2000);
    REQUIRE(contains(building, "building"));
    REQUIRE_FALSE(contains(building, "No installed-software inventory has been reported"));

    // meta.refreshed_at > 0 + empty rollup → honest "nothing installed", not building/degrade.
    const std::string empty = render_inventory_software_fragment(
        std::optional<std::vector<SoftwareCatalogRow>>(std::vector<SoftwareCatalogRow>{}),
        std::optional<CatalogRollupMeta>(CatalogRollupMeta{1000, 0, 0}), "", std::int64_t{0}, false,
        2000);
    REQUIRE(contains(empty, "No installed-software inventory has been reported"));
    REQUIRE_FALSE(contains(empty, "unavailable"));
    REQUIRE_FALSE(contains(empty, "building"));
}

TEST_CASE("software fragment: rows render with counts, KPIs from meta, drill link", "[inventory][ui]") {
    std::vector<SoftwareCatalogRow> rows{cat_row("Google Chrome", "Google LLC", 1180, 3),
                                         cat_row("7-Zip", "Igor Pavlov", 889, 1)};
    const std::string html = render_inventory_software_fragment(
        rows, std::optional<CatalogRollupMeta>(CatalogRollupMeta{1000, 2, 1284}), "",
        std::int64_t{37}, /*capped=*/false, /*now=*/2000);
    REQUIRE(contains(html, "Google Chrome"));
    REQUIRE(contains(html, "1180"));
    REQUIRE(contains(html, "Igor Pavlov"));
    // Each row drills into the version breakdown.
    REQUIRE(contains(html, "/fragments/inventory/software/versions?name=Google%20Chrome"));
    // KPIs come from the rollup meta: titles, devices-reporting, stale, and the "as of" line.
    REQUIRE(contains(html, "1284")); // devices reporting (meta.total_devices)
    REQUIRE(contains(html, "37"));   // stale count
    REQUIRE(contains(html, "updated")); // "updated 16m ago" (now-refreshed_at = 1000s)
    // Fleet-wide scope caveat is present (ADR-0017 honesty).
    REQUIRE(contains(html, "not yet effective"));
}

TEST_CASE("software fragment: capped shows the list-capped banner", "[inventory][ui]") {
    std::vector<SoftwareCatalogRow> rows{cat_row("A", "p", 1, 1)};
    const std::string html = render_inventory_software_fragment(
        rows, std::optional<CatalogRollupMeta>(CatalogRollupMeta{1000, 1, 1}), "", std::nullopt,
        /*capped=*/true, /*now=*/2000);
    REQUIRE(contains(html, "list capped"));
}

TEST_CASE("versions fragment: degrade banner vs empty vs share bars", "[inventory][ui]") {
    // nullopt = store degrade → banner.
    REQUIRE(contains(render_inventory_versions_fragment("Chrome", std::nullopt), "unavailable"));

    // Empty-non-null (a title since fully uninstalled) = honest empty, NOT a degrade (gov F2).
    const std::string empty = render_inventory_versions_fragment(
        "Chrome", std::optional<std::vector<SoftwareVersionCount>>(std::vector<SoftwareVersionCount>{}));
    REQUIRE(contains(empty, "No version data"));
    REQUIRE_FALSE(contains(empty, "unavailable"));

    // Empty name = precondition miss → "select a title" note, NOT the store-failed banner (gov happy-NICE).
    const std::string noname = render_inventory_versions_fragment("", std::nullopt);
    REQUIRE(contains(noname, "Select a title"));
    REQUIRE_FALSE(contains(noname, "unavailable"));

    std::vector<SoftwareVersionCount> vers{{"126.0", 742}, {"125.0", 301}};
    const std::string html = render_inventory_versions_fragment("Chrome", vers);
    REQUIRE(contains(html, "126.0"));
    REQUIRE(contains(html, "742"));
    REQUIRE(contains(html, "Installs per version"));
    REQUIRE(contains(html, "width:100%")); // the top version is the full-width bar
}

// ───────────────────────── route wiring ────────────────────────────────────────

namespace {

struct InvHarness {
    yuzu::server::test::TestRouteSink sink;
    InventoryRoutes routes;

    bool allow_perm = true;          // global Inventory:Read
    bool degrade = false;            // make every store provider return nullopt
    bool service_scoped = false;     // simulate a service-scoped API token session
    std::vector<SoftwareFleetRow> fleet_rows;
    std::vector<std::string> in_scope_agents; // "devices ›" per-row scope predicate allow-list
    std::vector<std::string> audits;          // "action|result"
    std::vector<std::string> audit_full;      // "action|result|target_type|target_id" (parity check)
    std::vector<std::string> audit_details;   // detail strings, parallel to `audits`

    // Round-3 item 8 fixtures: agent_id -> hostname (HostnamesFn fake) for the
    // SOFTWARE "devices ›" expansion, and the last query object each fleet-wide
    // provider actually received (so a test can assert what the ROUTE forwarded,
    // not just what the fake chose to return).
    std::unordered_map<std::string, std::string> hostnames;
    std::optional<SoftwareCatalogQuery> last_catalog_query;
    std::optional<SoftwareFleetQuery> last_fleet_query; // /software/devices

    InvHarness() {
        auto auth = [this](const httplib::Request&, httplib::Response&) {
            auth::Session s;
            if (service_scoped)
                s.token_scope_service = "printers";
            return std::optional<auth::Session>(s);
        };
        auto perm = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                           const std::string&) {
            if (!allow_perm)
                res.status = 403;
            return allow_perm;
        };
        auto catalog = [this](const SoftwareCatalogQuery& q)
            -> std::optional<std::vector<SoftwareCatalogRow>> {
            last_catalog_query = q;
            if (degrade)
                return std::nullopt;
            return std::vector<SoftwareCatalogRow>{cat_row("Chrome", "Google", 5, 2)};
        };
        auto catalog_meta = [this]() -> std::optional<CatalogRollupMeta> {
            if (degrade)
                return std::nullopt;
            return CatalogRollupMeta{1000, 1, 5}; // refreshed_at>0 → not "building"
        };
        auto versions = [this](const std::string&, int)
            -> std::optional<std::vector<SoftwareVersionCount>> {
            if (degrade)
                return std::nullopt;
            return std::vector<SoftwareVersionCount>{{"1.0", 5}};
        };
        auto fleet = [this](const SoftwareFleetQuery& q)
            -> std::optional<std::vector<SoftwareFleetRow>> {
            last_fleet_query = q;
            if (degrade)
                return std::nullopt;
            return fleet_rows;
        };
        auto scope = [this](const std::string&, const std::string& agent_id) {
            for (const auto& a : in_scope_agents)
                if (a == agent_id)
                    return true;
            return false;
        };
        auto stale = [this]() -> std::optional<std::int64_t> {
            return degrade ? std::nullopt : std::optional<std::int64_t>(7);
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& tid,
                            const std::string& detail) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            audit_details.push_back(detail);
            return true;
        };
        auto hostnames_fn = [this]() -> std::unordered_map<std::string, std::string> {
            return hostnames;
        };
        routes.register_routes(sink, auth, perm, catalog, catalog_meta, versions, fleet, scope,
                               stale, audit, hostnames_fn);
    }
};

} // namespace

TEST_CASE("route: software fragment denied without Inventory:Read", "[inventory][route]") {
    InvHarness h;
    h.allow_perm = false;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "Chrome"));
}

TEST_CASE("route: software fragment renders catalogue + audits", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Chrome"));
    bool audited = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.catalog|success")
            audited = true;
    REQUIRE(audited);
    // Securable + target_id parity with audit-log.md (gov consistency NICE-1): a rename of
    // the securable or the target shape away from the doc must fail a test.
    bool target_ok = false;
    for (const auto& a : h.audit_full)
        if (a == "inventory.software.catalog|success|Inventory|fleet")
            target_ok = true;
    REQUIRE(target_ok);
}

TEST_CASE("route: software fragment degrade → banner, audited failure", "[inventory][route]") {
    InvHarness h;
    h.degrade = true;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(contains(res->body, "unavailable"));
    bool failed = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.catalog|failure")
            failed = true;
    REQUIRE(failed);
}

TEST_CASE("route: version drill — deny, success+audit, degrade", "[inventory][route]") {
    {
        InvHarness h;
        h.allow_perm = false;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(res->status == 403);
    }
    {
        InvHarness h;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(contains(res->body, "Installs per version"));
        bool ok = false;
        for (const auto& a : h.audits)
            if (a == "inventory.software.versions|success")
                ok = true;
        REQUIRE(ok);
    }
    {
        InvHarness h;
        h.degrade = true;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(contains(res->body, "unavailable"));
        bool failed = false;
        for (const auto& a : h.audits)
            if (a == "inventory.software.versions|failure")
                failed = true;
        REQUIRE(failed);
    }
}

// ───────────────── Round-3 items 8/9: search, devices expansion ────────────────────

TEST_CASE("route: software fragment results_only=1 returns only the #sw-results region",
          "[inventory][route]") {
    // Mirrors hardware_ui.cpp's results_only fix for the identical class of bug: the
    // search box's own hx-get must swap ONLY #sw-results, never the full page (which
    // would re-include the triggering <input> and destroy it mid-keystroke).
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software?results_only=1");
    REQUIRE(res);
    REQUIRE(contains(res->body, "id=\"sw-results\""));
    REQUIRE(contains(res->body, "Chrome")); // the catalogue row itself still renders
    // The full-page chrome (KPI strip / search box / sub-nav / <h1>) is excluded.
    REQUIRE_FALSE(contains(res->body, "inv-kpis"));
    REQUIRE_FALSE(contains(res->body, "id=\"sw-q\""));
    REQUIRE_FALSE(contains(res->body, "inv-subnav"));
    REQUIRE_FALSE(contains(res->body, "inv-h1"));
}

TEST_CASE("route: software fragment forwards q into the store's name_filter",
          "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software?q=adobe");
    REQUIRE(res);
    REQUIRE(h.last_catalog_query.has_value());
    REQUIRE(h.last_catalog_query->name_filter == "adobe");
}

TEST_CASE("route: software devices — hostname resolution, columns, filter-group id",
          "[inventory][route]") {
    InvHarness h;
    h.in_scope_agents = {"agent-known", "agent-unknown"}; // else the scope filter drops both rows
    h.hostnames = {{"agent-known", "HOST-A"}}; // agent-unknown carries no mapping
    h.fleet_rows = {fleet_row("agent-known", "Chrome", "1.0"),
                    fleet_row("agent-unknown", "Chrome", "1.0")};
    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // HostnamesFn resolution: a known mapping renders the HOSTNAME as the link
    // text; a miss falls back to the bare agent_id — both still link to the
    // per-device Hardware CI page (round-3 item 8).
    REQUIRE(contains(res->body, "<a href=\"/hardware/ci?id=agent-known\">HOST-A</a>"));
    REQUIRE(contains(res->body, "<a href=\"/hardware/ci?id=agent-unknown\">agent-unknown</a>"));

    // Columns: Version/Publisher/Install date/Signature/Ecosystem/Arch — Signature
    // and Ecosystem were previously unrendered anywhere (round-3 item 8 doc comment).
    REQUIRE(contains(res->body, "<th>Version</th>"));
    REQUIRE(contains(res->body, "<th>Publisher</th>"));
    REQUIRE(contains(res->body, "<th>Install date</th>"));
    REQUIRE(contains(res->body, "<th>Signature</th>"));
    REQUIRE(contains(res->body, "<th>Ecosystem</th>"));
    REQUIRE(contains(res->body, "<th>Arch</th>"));

    // Client filter-group: data-gpf is derived from the software name (id_safe),
    // matching the catalogue row's own hx-target for this expansion — the filter
    // input and every data row carry the SAME group.
    REQUIRE(contains(res->body, "data-gpf=\"swdev-nChrome-520456eb94564cdd\""));
}

TEST_CASE("route: software devices — service-scoped token denied, no data leaked, denial audited",
          "[inventory][route][security]") {
    InvHarness h;
    h.service_scoped = true;
    h.fleet_rows = {fleet_row("agent-alpha", "Chrome", "1.0")};

    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "agent-alpha"));
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
         body["error"]["correlation_id"].get<std::string>());
    bool denied = false;
    for (const auto& a : h.audits) {
        if (a == "inventory.software.query|denied")
            denied = true;
        REQUIRE(a != "inventory.software.query|success");
    }
    REQUIRE(denied);
}

TEST_CASE("route: software devices — per-row management-group drop count in pill and audit",
          "[inventory][route]") {
    InvHarness h;
    h.fleet_rows = {fleet_row("agent-alpha", "Chrome", "1.0"),
                    fleet_row("agent-bravo", "Chrome", "2.0")};
    h.in_scope_agents = {"agent-alpha"}; // agent-bravo is out of the operator's scope

    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "agent-alpha"));
    REQUIRE_FALSE(contains(res->body, "agent-bravo")); // dropped, not leaked
    REQUIRE(contains(res->body, "1 device(s) outside your scope")); // the rendered pill
    bool denied = false, ok = false;
    for (const auto& a : h.audits) {
        denied = denied || a == "inventory.software.query|denied";
        ok = ok || a == "inventory.software.query|success";
    }
    REQUIRE(denied);
    REQUIRE(ok);
    bool detail_ok = false;
    for (const auto& d : h.audit_details)
        if (contains(d, "scope: filtered 1 out-of-management-group device(s)"))
            detail_ok = true;
    REQUIRE(detail_ok); // the same drop count also lands in the audit row's detail
}

TEST_CASE("route: software devices — degraded fleet store renders an honest banner, "
          "not an empty table",
          "[inventory][route]") {
    InvHarness h;
    h.degrade = true;
    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "unavailable"));
    REQUIRE_FALSE(contains(res->body, "No devices run")); // never the "genuinely zero" wording
    bool failed = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.query|failure")
            failed = true;
    REQUIRE(failed);
}

TEST_CASE("route: software devices — empty name is a no-op: no data read, no audit",
          "[inventory][route]") {
    // Unreachable from the UI (the catalogue row's "devices ›" link always carries
    // ?name=); this is the renderer's precondition-miss short-circuit for a direct
    // fetch. fleet_fn_ must never be called for an empty name.
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software/devices");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(res->body.empty());
    REQUIRE_FALSE(h.last_fleet_query.has_value()); // no data read
    REQUIRE(h.audits.empty());                     // → nothing to audit
}

TEST_CASE("route: software devices — fleet_fn_'s limit is clamped into the route's bound",
          "[inventory][route]") {
    InvHarness h;
    auto over = h.sink.Get("/fragments/inventory/software/devices?name=Chrome&limit=999999");
    REQUIRE(over);
    REQUIRE(h.last_fleet_query.has_value());
    REQUIRE(h.last_fleet_query->limit == 1000); // clamped down to the route's hard ceiling

    auto within = h.sink.Get("/fragments/inventory/software/devices?name=Chrome&limit=50");
    REQUIRE(within);
    REQUIRE(h.last_fleet_query.has_value());
    REQUIRE(h.last_fleet_query->limit == 50); // a value already inside the bound passes through
}
