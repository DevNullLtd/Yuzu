/// @file test_inventory_routes.cpp
/// Tests for the /software dashboard — the PURE renderers (data-in / HTML-out) and
/// the route wiring driven in-process through TestRouteSink (no httplib acceptor,
/// #438). Focus areas: the authoritative-read DEGRADE-≠-EMPTY contract (a nullopt
/// data arg → an "unavailable" banner, never a silent empty table), the "devices ›"
/// per-row management-group scope drop (+ omission audit, mirroring the REST
/// sibling), and the service-scoped-token blanket deny.

#include "authz_model.hpp"
#include "inventory_routes.hpp"
#include "software_catalogue_model.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <expected>
#include <initializer_list>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
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

// ───────────────────────── route wiring ────────────────────────────────────────

namespace {

struct InvHarness {
    // #1786: handlers capture `this` of `routes`, so `routes` outlives the sink that holds them.
    InventoryRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    bool allow_fleet_read = true;    // Software fragments: the FleetReadFn gate
    authz::VisibleSet scope;         // nullopt = TOP (unfiltered); engaged = confined caller
    bool degrade = false;            // make every store provider return nullopt
    bool service_scoped = false;     // simulate a service-scoped API token session
    std::vector<SoftwareFleetRow> fleet_rows;
    std::vector<std::string> audits;          // "action|result"
    std::vector<std::string> audit_full;      // "action|result|target_type|target_id" (parity check)
    std::vector<std::string> audit_details;   // detail strings, parallel to `audits`

    // Software page fixtures. `titles` is served in (installs DESC, name) order and the fake
    // honours `after` and `limit` exactly like the store, so paging is exercised for real.
    std::vector<SoftwareCatalogRow> titles{cat_row("Chrome", "Google", 5, 2)};
    std::vector<SoftwareVersionCount> versions{{"1.0", 5, true}};
    std::unordered_map<std::string, std::string> hostnames;
    std::unordered_map<std::string, std::int64_t> last_synced;
    bool last_synced_degrade = false;
    bool meta_degrade = false; // only the rollup-meta read fails (every other provider answers)
    bool catalog_degrade = false; // only the catalogue rows read fails
    std::int64_t refreshed_at = 1000;
    int bump_refreshed_on_meta_call = 0; // 1-based: that meta read returns refreshed_at + 1
    std::vector<std::string> calls;      // provider order: "meta" | "catalog" | "totals" | ...
    std::optional<SoftwareCatalogQuery> last_catalog_query;
    std::optional<SoftwareVersionsQuery> last_versions_query;
    std::optional<SoftwareFleetQuery> last_fleet_query; // /software/devices
    std::vector<std::string> last_synced_ids;

    int count(const std::string& what) const {
        return static_cast<int>(std::ranges::count(calls, what));
    }

    // `wire_fleet_read` must be a constructor param: `register_routes` (below) runs once, here.
    explicit InvHarness(bool wire_fleet_read = true) {
        auto auth = [this](const httplib::Request&, httplib::Response&) {
            auth::Session s;
            if (service_scoped)
                s.token_scope_service = "printers";
            return std::optional<auth::Session>(s);
        };
        auto fleet_read = [this](const httplib::Request&, httplib::Response& res,
                                 const std::string&, const std::string&) -> authz::FleetReadGate {
            authz::FleetReadGate g;
            if (!allow_fleet_read) {
                res.status = 403;
                return g;
            }
            g.admitted = true;
            g.scope = scope;
            return g;
        };
        auto catalog = [this](const SoftwareCatalogQuery& q)
            -> std::optional<std::vector<SoftwareCatalogRow>> {
            calls.push_back("catalog");
            last_catalog_query = q;
            if (degrade || catalog_degrade)
                return std::nullopt;
            std::vector<SoftwareCatalogRow> out;
            for (const auto& r : titles) {
                if (q.after && !(r.device_count < q.after->installs ||
                                 (r.device_count == q.after->installs && r.name > q.after->name)))
                    continue;
                if (static_cast<int>(out.size()) == q.limit)
                    break;
                out.push_back(r);
            }
            return out;
        };
        auto catalog_meta = [this]() -> std::optional<CatalogRollupMeta> {
            calls.push_back("meta");
            if (degrade || meta_degrade)
                return std::nullopt;
            CatalogRollupMeta m{refreshed_at, 1, 5};
            if (bump_refreshed_on_meta_call == count("meta"))
                m.refreshed_at += 1;
            return m;
        };
        auto totals = [this](const SoftwareCatalogQuery&) -> std::optional<SoftwareCatalogTotals> {
            calls.push_back("totals");
            if (degrade)
                return std::nullopt;
            return SoftwareCatalogTotals{static_cast<std::int64_t>(titles.size()), 7};
        };
        auto versions_fn = [this](const SoftwareVersionsQuery& q)
            -> std::optional<std::vector<SoftwareVersionCount>> {
            last_versions_query = q;
            if (degrade)
                return std::nullopt;
            return versions;
        };
        auto fleet = [this](const SoftwareFleetQuery& q)
            -> std::optional<std::vector<SoftwareFleetRow>> {
            last_fleet_query = q;
            if (degrade)
                return std::nullopt;
            if (q.agent_ids && q.agent_ids->empty())
                return std::vector<SoftwareFleetRow>{}; // deny-all: the store returns empty, no SQL
            // Honours `after` and `limit` like the store (one title's fleet_rows, kept in agent_id order).
            std::vector<SoftwareFleetRow> out;
            std::int64_t skipped = 0;
            for (const auto& r : fleet_rows) {
                if (q.after && r.agent_id <= q.after->agent_id)
                    continue;
                if (q.agent_ids &&
                    std::ranges::find(*q.agent_ids, r.agent_id) == q.agent_ids->end())
                    continue;
                if (skipped < q.skip) { // rows to pass over after the anchor (the d2 cursor)
                    ++skipped;
                    continue;
                }
                if (static_cast<int>(out.size()) == q.limit)
                    break;
                out.push_back(r);
            }
            return out;
        };
        auto stale = [this]() -> std::optional<std::int64_t> {
            calls.push_back("stale");
            return degrade ? std::nullopt : std::optional<std::int64_t>(7);
        };
        auto connected = [this]() -> std::optional<std::int64_t> {
            calls.push_back("connected");
            return degrade ? std::nullopt : std::optional<std::int64_t>(9);
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
            calls.push_back("hostnames");
            return hostnames;
        };
        auto last_synced_fn = [this](const std::vector<std::string>& ids)
            -> std::optional<std::unordered_map<std::string, std::int64_t>> {
            last_synced_ids = ids;
            if (last_synced_degrade)
                return std::nullopt;
            return last_synced;
        };
        InventoryRoutes::FleetReadFn fleet_read_fn = fleet_read;
        if (!wire_fleet_read)
            fleet_read_fn = InventoryRoutes::FleetReadFn{};
        routes.register_routes(sink, InventoryRoutes::Deps{.auth_fn = auth,
                                                           .fleet_read_fn = fleet_read_fn,
                                                           .catalog_fn = catalog,
                                                           .catalog_meta_fn = catalog_meta,
                                                           .totals_fn = totals,
                                                           .versions_fn = versions_fn,
                                                           .fleet_fn = fleet,
                                                           .stale_fn = stale,
                                                           .connected_fn = connected,
                                                           .hostnames_fn = hostnames_fn,
                                                           .last_synced_fn = last_synced_fn,
                                                           .audit_fn = audit});
    }

    bool audited(const std::string& what) const {
        return std::ranges::find(audits, what) != audits.end();
    }
};

} // namespace

TEST_CASE("route: the retired /fragments/inventory devices/device/find/find/results paths are "
          "unregistered; /inventory still redirects to /hardware",
          "[inventory][route]") {
    InvHarness h;
    for (const char* path : {"/fragments/inventory/devices", "/fragments/inventory/device",
                             "/fragments/inventory/find", "/fragments/inventory/find/results"})
        REQUIRE_FALSE(h.sink.Get(path));

    auto r = h.sink.Get("/inventory");
    REQUIRE(r);
    REQUIRE(r->status == 302);
    REQUIRE(r->get_header_value("Location") == "/hardware");
}

// ───────────────────── Software page routes (M.9) ──────────────────────────────

namespace {

namespace swc = yuzu::server::software_catalogue;

std::string decode_amp(std::string s) {
    for (auto p = s.find("&amp;"); p != std::string::npos; p = s.find("&amp;", p + 1))
        s.replace(p, 5, "&");
    return s;
}

/// The Load-more sentinel's request path, pulled out of a fragment body.
std::string next_url(const std::string& body, const std::string& act = "more") {
    const std::string key = "data-act=\"" + act + "\" hx-get=\"";
    const auto p = body.find(key);
    REQUIRE(p != std::string::npos);
    const auto s = p + key.size();
    return decode_amp(body.substr(s, body.find('"', s) - s));
}

std::vector<SoftwareCatalogRow> many_titles(int n) {
    std::vector<SoftwareCatalogRow> v;
    for (int i = 0; i < n; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "t%04d", i);
        v.push_back(cat_row(name, "P", 1000 - i, 1));
    }
    return v;
}

std::string dev_id(int i) { // a000, a001, ... (agent_id order == numeric order)
    char id[8];
    std::snprintf(id, sizeof(id), "a%03d", i);
    return id;
}

authz::VisibleSet ids(std::initializer_list<const char*> v) {
    authz::VisibleSet s{std::unordered_set<std::string>{}};
    for (const char* x : v)
        s->insert(x);
    return s;
}

const char* kSoftware = "/fragments/inventory/software";
const char* kVersions = "/fragments/inventory/software/versions";
const char* kDevices = "/fragments/inventory/software/devices";

} // namespace

TEST_CASE("software routes: the fleet-read gate is the sole gate", "[inventory][route]") {
    {
        InvHarness h;
        h.allow_fleet_read = false;
        for (const char* path : {kSoftware, kVersions, kDevices}) {
            auto res = h.sink.Get(std::string(path) + "?name=Chrome");
            REQUIRE(res);
            REQUIRE(res->status == 403);
            REQUIRE_FALSE(contains(res->body, "Chrome"));
        }
        REQUIRE_FALSE(h.last_catalog_query);
        REQUIRE_FALSE(h.last_versions_query);
        REQUIRE_FALSE(h.last_fleet_query);
        REQUIRE(h.audits.empty());
    }
    {
        InvHarness h(/*wire_fleet_read=*/false);
        for (const char* path : {kSoftware, kVersions, kDevices}) {
            auto res = h.sink.Get(std::string(path) + "?name=Chrome");
            REQUIRE(res);
            REQUIRE(res->status == 503);
        }
        REQUIRE_FALSE(h.last_catalog_query);
    }
}

TEST_CASE("software routes: a service-scoped token is denied on all three fragments",
          "[inventory][route]") {
    InvHarness h;
    h.service_scoped = true;
    const std::array<std::pair<const char*, const char*>, 3> cases{{
        {kSoftware, "inventory.software.catalog"},
        {kVersions, "inventory.software.versions"},
        {kDevices, "inventory.software.query"},
    }};
    for (const auto& [path, verb] : cases) {
        auto res = h.sink.Get(std::string(path) + "?name=Chrome");
        REQUIRE(res);
        REQUIRE(res->status == 403);
        REQUIRE_FALSE(contains(res->body, "\"permission\""));
        REQUIRE(h.audited(std::string(verb) + "|denied"));
    }
    REQUIRE(h.audit_full.front() == "inventory.software.catalog|denied|Inventory|fleet");
    REQUIRE_FALSE(h.last_catalog_query);
    REQUIRE_FALSE(h.last_versions_query);
    REQUIRE_FALSE(h.last_fleet_query);
}

TEST_CASE("software routes: catalogue renders and audits success", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get(kSoftware);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(contains(res->body, "Chrome"));
    REQUIRE(contains(res->body, "id=\"sw-kpis\""));
    REQUIRE(h.audit_full.size() == 1);
    REQUIRE(h.audit_full[0] == "inventory.software.catalog|success|Inventory|fleet");
    REQUIRE(contains(h.audit_details[0], "titles=1 totals=1/7"));
    REQUIRE(h.count("connected") == 1);
    REQUIRE(h.count("stale") == 1);
    REQUIRE(h.count("hostnames") == 1); // the full page's type-ahead only
}

TEST_CASE("software routes: catalogue forwards the model's parse with a pinned page size",
          "[inventory][route]") {
    InvHarness h;
    const std::string qs = "?q=chrome&kind=app&ecosystem=brew&source=pkg_inventory.packages&"
                           "agent_id=a1&versions_min=3&limit=999";
    auto res = h.sink.Get(std::string(kSoftware) + qs);
    REQUIRE(res);
    REQUIRE(h.last_catalog_query);
    swc::Params p{{"q", "chrome"}, {"kind", "app"}, {"ecosystem", "brew"},
                  {"source", "pkg_inventory.packages"}, {"agent_id", "a1"},
                  {"versions_min", "3"}, {"limit", "999"}};
    auto model = swc::parse_catalogue_params(p);
    REQUIRE(model);
    const auto& got = *h.last_catalog_query;
    REQUIRE(got.q == model->query.q);
    REQUIRE(got.kind == model->query.kind);
    REQUIRE(got.ecosystem == model->query.ecosystem);
    REQUIRE(got.source == model->query.source);
    REQUIRE(got.agent_id == model->query.agent_id);
    REQUIRE(got.versions_min == model->query.versions_min);
    REQUIRE(got.limit == 100); // a fixed page size, whatever the caller asked
    REQUIRE(h.audit_full.back() == "inventory.software.catalog|success|Inventory|" +
                                       swc::audit_target(model->query));
}

TEST_CASE("software routes: a parse error is a 200 caveat with no read and no audit",
          "[inventory][route]") {
    InvHarness h;
    for (const char* qs : {"?versions_min=abc", "?kind=app&kind=pkg"}) {
        auto res = h.sink.Get(std::string(kSoftware) + qs);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        REQUIRE(contains(res->body, "inv-caveat"));
        REQUIRE_FALSE(contains(res->body, "<table"));
    }
    REQUIRE_FALSE(h.last_catalog_query);
    REQUIRE(h.audits.empty());
    auto v = h.sink.Get(std::string(kVersions) + "?versions=1");
    REQUIRE(v);
    REQUIRE(contains(v->body, "inv-caveat"));
    REQUIRE_FALSE(h.last_versions_query);
    REQUIRE(h.audits.empty());
}

TEST_CASE("software routes: confined caller is refused the fleet aggregate, audited",
          "[inventory][route]") {
    InvHarness h;
    h.scope = ids({"a1"});
    auto res = h.sink.Get(kSoftware);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(contains(res->body, "cannot be narrowed to your management groups"));
    REQUIRE_FALSE(contains(res->body, "<table"));
    REQUIRE_FALSE(contains(res->body, "<div class=\"inv-kpi"));
    REQUIRE(h.audited("inventory.software.catalog|denied"));
    REQUIRE_FALSE(h.audited("inventory.software.catalog|success"));
    REQUIRE(h.calls.empty()); // nothing read at all
    // The versions fleet view is refused the same way.
    auto v = h.sink.Get(std::string(kVersions) + "?name=Chrome");
    REQUIRE(contains(v->body, "cannot be narrowed to your management groups"));
    REQUIRE_FALSE(h.last_versions_query);
    REQUIRE(h.audited("inventory.software.versions|denied"));
}

TEST_CASE("software routes: confined host view reads no fleet figures", "[inventory][route]") {
    InvHarness h;
    h.scope = ids({"a1"});
    h.hostnames = {{"a1", "WIN-1"}};
    h.titles = {cat_row("Chrome", "Google", 1, 2)};
    h.titles[0].newest_version = "9.9";
    auto res = h.sink.Get(std::string(kSoftware) + "?agent_id=a1");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Chrome"));
    REQUIRE(h.last_catalog_query->agent_id == "a1");
    REQUIRE(h.count("meta") == 0);
    REQUIRE(h.count("stale") == 0);
    REQUIRE(h.count("connected") == 0);
    REQUIRE(h.count("hostnames") == 0);
    REQUIRE_FALSE(contains(res->body, "<div class=\"inv-kpi"));
    REQUIRE_FALSE(contains(res->body, "<datalist"));
    REQUIRE_FALSE(contains(res->body, "9.9")); // Newest in fleet is blanked
    REQUIRE(contains(res->body, "your management groups only"));
    // An out-of-scope device is refused and audited, never answered.
    auto out = h.sink.Get(std::string(kSoftware) + "?agent_id=a2");
    REQUIRE(contains(out->body, "This device is outside your management groups (or unknown)"));
    REQUIRE_FALSE(contains(out->body, "cannot be narrowed to your management groups"));
    REQUIRE(h.audited("inventory.software.catalog|denied"));
    auto vout = h.sink.Get(std::string(kVersions) + "?name=Chrome&agent_id=a2");
    REQUIRE(contains(vout->body, "This device is outside your management groups (or unknown)"));
}

TEST_CASE("software routes: an unfiltered caller gets the strip on the host view too",
          "[inventory][route]") {
    InvHarness h;
    h.hostnames = {{"a1", "WIN-1"}};
    auto res = h.sink.Get(std::string(kSoftware) + "?agent_id=a1");
    REQUIRE(res);
    REQUIRE(contains(res->body, "<div class=\"inv-kpi"));
    REQUIRE(contains(res->body, "value=\"WIN-1\"")); // the host box shows the name
    REQUIRE(contains(res->body, "host: WIN-1"));
    REQUIRE(h.count("hostnames") == 1);
    // A Results-mode refresh of the host view (every control's request) shows the name too.
    auto results = h.sink.Get(std::string(kSoftware) + "?results_only=1&agent_id=a1");
    REQUIRE(results);
    REQUIRE(contains(results->body, "host: WIN-1"));
    REQUIRE(h.count("hostnames") == 2);
    // The Load-more page never renders a host name, so it never reads the hostname map.
    auto more = h.sink.Get(std::string(kSoftware) + "?rows_only=1&agent_id=a1");
    REQUIRE(more);
    REQUIRE(more->body.rfind("<tr", 0) == 0);
    REQUIRE(h.count("hostnames") == 2);
}

TEST_CASE("software routes: a degraded rollup-meta read on the host view is a whole-page degrade",
          "[inventory][route]") {
    InvHarness h;
    h.meta_degrade = true; // the model skips the meta read on an unfiltered host view; the route reads it
    auto res = h.sink.Get(std::string(kSoftware) + "?agent_id=a1");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Inventory store unavailable."));
    REQUIRE_FALSE(contains(res->body, "<table"));
    REQUIRE(h.audited("inventory.software.catalog|failure"));
    REQUIRE_FALSE(h.audited("inventory.software.catalog|success"));
}

TEST_CASE("software routes: the host type-ahead is sorted, capped at 1000 and skips unnamed hosts",
          "[inventory][route]") {
    InvHarness h;
    for (int i = 1001; i >= 0; --i) { // inserted out of order: the route sorts
        char name[16];
        std::snprintf(name, sizeof(name), "h%04d", i);
        h.hostnames["id" + std::to_string(i)] = name;
    }
    h.hostnames["emptyid"] = "";
    auto res = h.sink.Get(kSoftware);
    REQUIRE(res);
    std::size_t options = 0;
    for (auto p = res->body.find("<option value=\""); p != std::string::npos;
         p = res->body.find("<option value=\"", p + 1))
        ++options;
    REQUIRE(options == 1000);
    REQUIRE(contains(res->body, "<option value=\"h0000\""));
    REQUIRE(res->body.find("<option value=\"h0000\"") == res->body.find("<option value=\""));
    REQUIRE_FALSE(contains(res->body, "<option value=\"h1001\""));
    REQUIRE_FALSE(contains(res->body, "data-id=\"emptyid\""));
    // The cap is disclosed with the true named-host count (1002 named: h0000..h1001).
    REQUIRE(contains(res->body, "type-ahead lists the first 1,000 of 1,002 named hosts"));
    InvHarness few; // under the cap: no note
    few.hostnames = {{"id1", "alpha"}};
    REQUIRE_FALSE(contains(few.sink.Get(kSoftware)->body, "type-ahead lists"));
}

TEST_CASE("software routes: keyset paging walks the catalogue 100 at a time", "[inventory][route]") {
    InvHarness h;
    h.titles = many_titles(150);
    auto p1 = h.sink.Get(kSoftware);
    REQUIRE(p1);
    REQUIRE(contains(p1->body, "t0000"));
    REQUIRE(contains(p1->body, "t0099"));
    REQUIRE_FALSE(contains(p1->body, "t0100"));
    REQUIRE(h.last_catalog_query->limit == 100);
    const std::string url = next_url(p1->body);
    REQUIRE(contains(url, "rows_only=1&cursor="));
    REQUIRE(contains(url, "&shown=100"));
    auto p2 = h.sink.Get(url);
    REQUIRE(p2);
    REQUIRE(p2->body.rfind("<tr", 0) == 0);
    REQUIRE_FALSE(contains(p2->body, "<table"));
    REQUIRE(contains(p2->body, "t0100"));
    REQUIRE(contains(p2->body, "t0149"));
    REQUIRE_FALSE(contains(p2->body, "t0099"));
    REQUIRE(h.last_catalog_query->after);
    REQUIRE(h.last_catalog_query->after->name == "t0099");
    REQUIRE_FALSE(contains(p2->body, "data-act=\"more\"")); // a short page has no sentinel
    REQUIRE(contains(p2->body, "All 150 matching titles are loaded."));
    // Success is audited on EVERY call; the continuation is tagged.
    REQUIRE(h.audit_details.size() == 2);
    REQUIRE_FALSE(contains(h.audit_details[0], "page=continuation"));
    REQUIRE(contains(h.audit_details[1], "page=continuation"));
}

TEST_CASE("software routes: cursor order, refusal and the skew retry", "[inventory][route]") {
    {
        InvHarness h;
        h.titles = many_titles(150);
        auto p1 = h.sink.Get(kSoftware);
        const std::string url = next_url(p1->body);
        h.calls.clear();
        auto p2 = h.sink.Get(url);
        REQUIRE(p2);
        // meta is read BEFORE the rows on a cursor page.
        REQUIRE(h.calls.front() == "meta");
        REQUIRE(std::ranges::find(h.calls, "catalog") != h.calls.end());
    }
    {
        // The rollup was refreshed since the token was issued: caveat, rows never read.
        InvHarness h;
        h.titles = many_titles(150);
        const std::string url = next_url(h.sink.Get(kSoftware)->body);
        h.refreshed_at = 2000;
        h.calls.clear();
        h.audits.clear();
        auto p2 = h.sink.Get(url);
        REQUIRE(p2);
        REQUIRE(contains(p2->body, "refreshed since this page loaded"));
        REQUIRE(h.count("catalog") == 0);
        REQUIRE(h.audits.empty());
    }
    {
        // A token for a different filter set is refused the same way (no read, no audit).
        InvHarness h;
        h.titles = many_titles(150);
        std::string url = next_url(h.sink.Get(std::string(kSoftware) + "?q=t")->body);
        const auto qpos = url.find("&q=t");
        REQUIRE(qpos != std::string::npos);
        url.replace(qpos, 4, "&q=u");
        h.calls.clear();
        h.audits.clear();
        auto res = h.sink.Get(url);
        REQUIRE(res);
        REQUIRE(contains(res->body, "inv-caveat"));
        REQUIRE(h.count("catalog") == 0);
        REQUIRE(h.audits.empty());
    }
    {
        // The generation moves between the first meta read and the re-check: ONE retry.
        InvHarness h;
        h.bump_refreshed_on_meta_call = 2;
        auto res = h.sink.Get(kSoftware);
        REQUIRE(res);
        REQUIRE(contains(res->body, "Chrome"));
        REQUIRE(h.count("catalog") == 2);
        REQUIRE(h.count("totals") == 2);
    }
}

TEST_CASE("software routes: any degraded read is the retry banner with an audited failure",
          "[inventory][route]") {
    InvHarness h;
    h.degrade = true;
    auto res = h.sink.Get(kSoftware);
    REQUIRE(res);
    REQUIRE(res->status == 200); // htmx does not swap 4xx
    REQUIRE(contains(res->body, "Inventory store unavailable."));
    REQUIRE(contains(res->body, "data-act=\"retry\""));
    REQUIRE_FALSE(contains(res->body, "<table"));
    REQUIRE(h.audited("inventory.software.catalog|failure"));
    // The Retry button re-requests the page with the current filters, and does not claim a 503.
    REQUIRE(contains(res->body, "hx-get=\"/fragments/inventory/software\" hx-target"));
    REQUIRE_FALSE(contains(res->body, "(503)"));
    auto filtered = h.sink.Get(std::string(kSoftware) + "?kind=app");
    REQUIRE(contains(filtered->body, "data-act=\"retry\" style=\"margin-left:.6rem\" "
                                     "hx-get=\"/fragments/inventory/software?kind=app\""));

    // ONE provider failing (the rows read; every other read answers) is the same degrade.
    InvHarness one;
    one.catalog_degrade = true;
    auto only = one.sink.Get(kSoftware);
    REQUIRE(only);
    REQUIRE(contains(only->body, "Inventory store unavailable."));
    REQUIRE_FALSE(contains(only->body, "<table"));
    REQUIRE(one.audited("inventory.software.catalog|failure"));
    REQUIRE_FALSE(one.audited("inventory.software.catalog|success"));

    // A Load-more continuation that degrades is a retry ROW, never a table.
    InvHarness more;
    more.degrade = true;
    auto row = more.sink.Get(std::string(kSoftware) + "?rows_only=1");
    REQUIRE(row);
    REQUIRE(row->body.rfind("<tr", 0) == 0);
    REQUIRE(contains(row->body, "inv-degrade"));
    REQUIRE_FALSE(contains(row->body, "<table"));
    REQUIRE(more.audited("inventory.software.catalog|failure"));
}

TEST_CASE("software routes: results_only and rows_only return their regions", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get(std::string(kSoftware) + "?results_only=1&kind=app");
    REQUIRE(res);
    REQUIRE(res->body.rfind("<div id=\"sw-results\"", 0) == 0);
    REQUIRE_FALSE(contains(res->body, "id=\"sw-q\""));
    REQUIRE(contains(res->body, "id=\"sw-sprawl\" "));
    REQUIRE(contains(res->body, "hx-swap-oob=\"true\""));
    REQUIRE(h.count("stale") == 0); // the coverage reads are for the full page only
    REQUIRE(h.count("connected") == 0);
    REQUIRE(h.count("hostnames") == 0);
    auto rows = h.sink.Get(std::string(kSoftware) + "?rows_only=1");
    REQUIRE(rows);
    REQUIRE(rows->body.rfind("<tr", 0) == 0);
}

TEST_CASE("software routes: versions drill", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get(std::string(kVersions) + "?name=Chrome&kind=app&ecosystem=brew&"
                                                     "source=s&agent_id=");
    REQUIRE(res);
    REQUIRE(contains(res->body, "installs per version"));
    REQUIRE(h.last_versions_query->name == "Chrome");
    REQUIRE(h.last_versions_query->kind == "app");
    REQUIRE(h.last_versions_query->ecosystem == "brew");
    REQUIRE(h.last_versions_query->source == "s");
    REQUIRE(h.last_versions_query->limit == 200);
    REQUIRE(h.audit_full.back() == "inventory.software.versions|success|Inventory|" +
                                       swc::audit_target(*h.last_versions_query));
    REQUIRE(contains(h.audit_details.back(), "versions=1"));
    // A read that returns exactly its limit may have more rows: the fragment says so.
    const auto vers_of = [](int n) {
        std::vector<SoftwareVersionCount> v;
        for (int i = 0; i < n; ++i)
            v.push_back({"v" + std::to_string(i), 1000 - i, false});
        return v;
    };
    InvHarness full_read;
    full_read.versions = vers_of(200);
    REQUIRE(contains(full_read.sink.Get(std::string(kVersions) + "?name=Chrome")->body,
                     "showing the 200 most-installed versions; this title may have more"));
    InvHarness short_read;
    short_read.versions = vers_of(199);
    REQUIRE_FALSE(contains(short_read.sink.Get(std::string(kVersions) + "?name=Chrome")->body,
                           "most-installed"));
    h.degrade = true;
    auto bad = h.sink.Get(std::string(kVersions) + "?name=Chrome");
    REQUIRE(contains(bad->body, "unavailable"));
    REQUIRE(h.audited("inventory.software.versions|failure"));
    // The unfiltered fleet drill reads the rollup, so before its first refresh it is `building`
    // (the shared read_versions seam), never an authoritative "No version data"; a filtered drill
    // reads no rollup and still answers.
    InvHarness building;
    building.refreshed_at = 0;
    auto early = building.sink.Get(std::string(kVersions) + "?name=Chrome");
    REQUIRE(early);
    REQUIRE(contains(early->body, "Catalogue is building"));
    REQUIRE_FALSE(contains(early->body, "No version data"));
    REQUIRE_FALSE(building.last_versions_query); // no rows were read
    REQUIRE(building.audits.back() == "inventory.software.versions|failure");
    REQUIRE(building.audit_details.back() == "building");
    REQUIRE(contains(building.sink.Get(std::string(kVersions) + "?name=Chrome&kind=app")->body,
                     "installs per version"));
    // Confined host view: admitted for an in-scope device, the newest mark is blanked.
    InvHarness c;
    c.scope = ids({"a1"});
    auto ok = c.sink.Get(std::string(kVersions) + "?name=Chrome&agent_id=a1");
    REQUIRE(contains(ok->body, "installs per version"));
    REQUIRE_FALSE(contains(ok->body, "newest in fleet"));
}

TEST_CASE("software routes: devices table scope arms", "[inventory][route]") {
    const auto rows = [] {
        return std::vector<SoftwareFleetRow>{fleet_row("a1", "Chrome", "1"),
                                             fleet_row("a2", "Chrome", "1"),
                                             fleet_row("a3", "Chrome", "1")};
    };
    const std::string url = std::string(kDevices) + "?name=Chrome&total=3";
    {   // TOP: nothing is pushed down, rows are complete, `of M` is available.
        InvHarness h;
        h.fleet_rows = rows();
        auto res = h.sink.Get(url);
        REQUIRE(res);
        REQUIRE_FALSE(h.last_fleet_query->agent_ids);
        REQUIRE(contains(res->body, "<b>3</b> devices run <b>Chrome</b>"));
        REQUIRE_FALSE(contains(res->body, "your management groups only"));
    }
    {   // Engaged scope within the push-down bound: the SQL carries the set.
        InvHarness h;
        h.scope = ids({"a1", "a3"});
        h.fleet_rows = rows();
        auto res = h.sink.Get(url);
        REQUIRE(h.last_fleet_query->agent_ids);
        std::set<std::string> got(h.last_fleet_query->agent_ids->begin(),
                                  h.last_fleet_query->agent_ids->end());
        REQUIRE(got == std::set<std::string>{"a1", "a3"});
        REQUIRE(contains(res->body, "/hardware/ci?id=a1"));
        REQUIRE(contains(res->body, "/hardware/ci?id=a3"));
        REQUIRE_FALSE(contains(res->body, "id=a2"));
        REQUIRE(contains(res->body, "your management groups only"));
        REQUIRE_FALSE(contains(res->body, "devices run <b>"));
    }
    {   // Present-empty (deny-all): an honest empty table, success audited with rows=0.
        InvHarness h;
        h.scope = authz::deny_all();
        h.fleet_rows = rows();
        auto res = h.sink.Get(url);
        REQUIRE(res);
        REQUIRE(contains(res->body, "No host matches."));
        REQUIRE(contains(h.audit_details.back(), "rows=0"));
    }
    {   // Wider than the push-down bound: the route filters itself and no out-of-scope ROW is
        // rendered, and the arms below pin that no cursor token names a row outside the scope.
        InvHarness h;
        authz::VisibleSet big{std::unordered_set<std::string>{}};
        for (std::size_t i = 0; i <= swc::kScopePushdownMaxIds; ++i)
            big->insert("syn" + std::to_string(i));
        big->insert("a1");
        h.scope = big;
        h.hostnames = {{"a2", "SECRET-HOST"}};
        h.fleet_rows = {fleet_row("a1", "Chrome", "1"), fleet_row("a2", "Chrome", "1")};
        auto res = h.sink.Get(url);
        REQUIRE(res);
        REQUIRE_FALSE(h.last_fleet_query->agent_ids); // not pushed down
        REQUIRE(contains(res->body, "id=a1"));
        REQUIRE_FALSE(contains(res->body, "a2"));
        REQUIRE_FALSE(contains(res->body, "SECRET-HOST"));
        REQUIRE(contains(res->body, "your management groups only"));
        REQUIRE(h.audited("inventory.software.query|denied")); // the post-filter drop is audited
        REQUIRE(h.audited("inventory.software.query|success"));
    }
    {   // A wide-scope page is REFILLED past a dropped row (bounded reads continue after the last
        // SCANNED row, in-process): a099 is dropped from the first read, a100 fills the page, and
        // the read ended exactly, so there is no sentinel and no token naming an out-of-scope row.
        InvHarness h;
        authz::VisibleSet big{std::unordered_set<std::string>{}};
        for (std::size_t i = 0; i <= swc::kScopePushdownMaxIds; ++i)
            big->insert("syn" + std::to_string(i));
        for (int i = 0; i < 99; ++i)
            big->insert(dev_id(i)); // a000..a098 in scope; a099 is not
        big->insert(dev_id(100));
        h.scope = big;
        for (int i = 0; i <= 100; ++i)
            h.fleet_rows.push_back(fleet_row(dev_id(i), "Chrome", "1"));
        auto p1 = h.sink.Get(url);
        REQUIRE(p1);
        REQUIRE_FALSE(h.last_fleet_query->agent_ids); // post-filter arm
        REQUIRE(contains(p1->body, "id=a098"));
        REQUIRE_FALSE(contains(p1->body, "id=a099"));
        REQUIRE(contains(p1->body, "id=a100"));
        REQUIRE_FALSE(contains(p1->body, "data-act=\"dmore\""));
    }
    {   // Four bounded reads, none in scope: the page is empty but NOT terminal. The cursor
        // re-anchors at the head with a skip count (never a dropped row's key); the next page
        // passes over the scanned rows in SQL and finds the in-scope row beyond them.
        InvHarness h;
        authz::VisibleSet big{std::unordered_set<std::string>{}};
        for (std::size_t i = 0; i <= swc::kScopePushdownMaxIds; ++i)
            big->insert("syn" + std::to_string(i));
        big->insert(dev_id(450)); // only a row beyond the four-read window is in scope
        h.scope = big;
        for (int i = 0; i <= 450; ++i)
            h.fleet_rows.push_back(fleet_row(dev_id(i), "Chrome", "1"));
        auto p1 = h.sink.Get(url);
        REQUIRE(p1);
        REQUIRE_FALSE(h.last_fleet_query->agent_ids); // post-filter arm
        REQUIRE_FALSE(contains(p1->body, "No host matches"));
        REQUIRE(contains(p1->body, "more may be in later pages"));
        REQUIRE(contains(p1->body, "data-act=\"dmore\""));
        REQUIRE_FALSE(contains(p1->body, "id=a0"));
        auto p2 = h.sink.Get(next_url(p1->body, "dmore"));
        REQUIRE(p2);
        REQUIRE_FALSE(h.last_fleet_query->after); // re-anchored at the head
        REQUIRE(h.last_fleet_query->skip == 400);
        REQUIRE(contains(p2->body, "id=a450"));
    }
    {   // An explicit agent_id outside the scope: nothing served, one denied row naming why.
        InvHarness h;
        h.scope = ids({"a1"});
        h.fleet_rows = {fleet_row("a2", "Chrome", "1")};
        auto res = h.sink.Get(std::string(kDevices) + "?name=Chrome&agent_id=a2");
        REQUIRE(res);
        REQUIRE(contains(res->body, "No host matches."));
        REQUIRE_FALSE(contains(res->body, "data-act=\"dmore\""));
        REQUIRE(std::ranges::count(h.audits, "inventory.software.query|denied") == 1);
        REQUIRE(h.audited("inventory.software.query|success"));
        for (std::size_t i = 0; i < h.audits.size(); ++i)
            if (h.audits[i] == "inventory.software.query|denied")
                REQUIRE(h.audit_details[i] == "scope: agent_id outside the caller's scope");
    }
}

TEST_CASE("software routes: devices parameters, cursor and audit", "[inventory][route]") {
    InvHarness h;
    h.fleet_rows = {fleet_row("a1", "Chrome", "1")};
    h.hostnames = {{"a1", "WIN-1"}};
    h.last_synced = {{"a1", 500}};
    auto res = h.sink.Get(std::string(kDevices) + "?name=Chrome&version=&kind=app&limit=5");
    REQUIRE(res);
    REQUIRE(h.last_fleet_query->version == std::optional<std::string>(""));
    REQUIRE(h.last_fleet_query->limit == 100);
    REQUIRE(h.last_fleet_query->kind == "app");
    REQUIRE(contains(res->body, ">WIN-1</a>"));
    REQUIRE(contains(res->body, "href=\"/hardware/ci?id=a1\""));
    REQUIRE(h.last_synced_ids == std::vector<std::string>{"a1"});
    REQUIRE(h.audit_full.back() ==
            "inventory.software.query|success|Inventory|" + swc::audit_target(*h.last_fleet_query));
    h.sink.Get(std::string(kDevices) + "?name=Chrome");
    REQUIRE_FALSE(h.last_fleet_query->version); // absent = any version
    // An unreadable bulk sync read dashes the cell (with its own tooltip) rather than inventing a time.
    h.last_synced_degrade = true;
    auto dash = h.sink.Get(std::string(kDevices) + "?name=Chrome");
    REQUIRE(contains(dash->body, "inv-tbl"));
    REQUIRE(contains(dash->body, "title=\"last sync time unavailable"));
    REQUIRE_FALSE(contains(dash->body, "ago"));
    // A bad cursor is a caveat, never a read.
    h.last_fleet_query.reset();
    h.audits.clear();
    auto bad = h.sink.Get(std::string(kDevices) + "?name=Chrome&cursor=garbage");
    REQUIRE(contains(bad->body, "inv-caveat"));
    REQUIRE_FALSE(h.last_fleet_query);
    REQUIRE(h.audits.empty());
    // An empty name reads nothing and audits nothing.
    auto none = h.sink.Get(std::string(kDevices) + "?name=");
    REQUIRE(contains(none->body, "inv-caveat"));
    REQUIRE_FALSE(h.last_fleet_query);
    REQUIRE(h.audits.empty());
    // Degrade: banner + audited failure.
    h.degrade = true;
    auto fail = h.sink.Get(std::string(kDevices) + "?name=Chrome");
    REQUIRE(contains(fail->body, "unavailable"));
    REQUIRE(h.audited("inventory.software.query|failure"));
}

TEST_CASE("software routes: devices paging follows the keyset and tags continuation audits",
          "[inventory][route]") {
    InvHarness h;
    for (int i = 0; i < 100; ++i) {
        char id[8];
        std::snprintf(id, sizeof(id), "a%03d", i);
        h.fleet_rows.push_back(fleet_row(id, "Chrome", "1"));
    }
    auto p1 = h.sink.Get(std::string(kDevices) + "?name=Chrome&total=250");
    REQUIRE(p1);
    const std::string url = next_url(p1->body, "dmore");
    REQUIRE(contains(url, "cursor="));
    REQUIRE(contains(url, "shown=100"));
    auto p2 = h.sink.Get(url);
    REQUIRE(p2);
    // The exact-multiple-of-100 case: the continuation is empty and final, so it appends nothing
    // (no "No host matches" beneath the hundred rows already on screen).
    REQUIRE(p2->body.empty());
    REQUIRE(h.last_fleet_query->after);
    REQUIRE(h.last_fleet_query->after->agent_id == "a099");
    REQUIRE(h.audit_details.size() == 2);
    REQUIRE(contains(h.audit_details[1], "page=continuation"));
}

TEST_CASE("software routes: a full devices page hands the last-synced read its distinct ids",
          "[inventory][route]") {
    InvHarness h;
    h.fleet_rows.push_back(fleet_row(dev_id(0), "Chrome", "1")); // a device on two sources: 2 rows
    h.fleet_rows.push_back(fleet_row(dev_id(0), "Chrome", "2"));
    h.fleet_rows.back().entry.source = "pkg_inventory.packages";
    for (int i = 1; i < 99; ++i)
        h.fleet_rows.push_back(fleet_row(dev_id(i), "Chrome", "1"));
    REQUIRE(h.fleet_rows.size() == 100); // a full page
    REQUIRE(h.sink.Get(std::string(kDevices) + "?name=Chrome"));
    std::vector<std::string> expect;
    for (int i = 0; i < 99; ++i)
        expect.push_back(dev_id(i));
    REQUIRE(h.last_synced_ids == expect);
}

TEST_CASE("software routes: device counts are distinct devices and hints are strict",
          "[inventory][route]") {
    InvHarness h;
    // One device carrying the title from two sources: two rows, ONE device.
    h.fleet_rows = {fleet_row("a1", "Chrome", "1"), fleet_row("a1", "Chrome", "2")};
    h.fleet_rows[1].entry.source = "pkg_inventory.packages";
    for (int i = 0; i < 98; ++i) // 100 rows = a full page, so a sentinel shows the running count
        h.fleet_rows.push_back(fleet_row("b" + std::to_string(i), "Chrome", "1"));
    auto res = h.sink.Get(std::string(kDevices) + "?name=Chrome&total=500&shown=7");
    REQUIRE(res);
    // 7 shown before + 99 distinct devices on this page (100 rows).
    REQUIRE(contains(res->body, "shown=106"));
    REQUIRE(contains(res->body, "106 of 500"));
    InvHarness g;
    g.fleet_rows = {fleet_row("a1", "Chrome", "1"), fleet_row("a1", "Chrome", "2")};
    auto one = g.sink.Get(std::string(kDevices) + "?name=Chrome&total=1");
    REQUIRE(contains(one->body, "<b>1</b> devices run"));
    // An absurd hint is dropped like a malformed one (never clamped, never overflowed): the
    // sentinel carries the page's own count.
    InvHarness big;
    for (int i = 0; i < 100; ++i)
        big.fleet_rows.push_back(fleet_row(dev_id(i), "Chrome", "1"));
    auto huge = big.sink.Get(std::string(kDevices) + "?name=Chrome&total=9223372036854775807&"
                                                       "shown=9223372036854775807");
    REQUIRE(huge);
    REQUIRE(contains(huge->body, "shown=100"));
    REQUIRE_FALSE(contains(huge->body, "9223372036854775807"));
    InvHarness cat;
    cat.titles = many_titles(150);
    auto crows = cat.sink.Get(std::string(kSoftware) + "?rows_only=1&shown=9223372036854775807");
    REQUIRE(crows);
    REQUIRE(contains(crows->body, "shown=100"));
    REQUIRE_FALSE(contains(crows->body, "9223372036854775807"));
    // Non-numeric / negative / exponent hints are ignored and never echoed.
    InvHarness b;
    b.fleet_rows = {fleet_row("a1", "Chrome", "1")};
    for (const char* hint : {"total=abc", "total=-1", "total=1e3", "shown=%3Cb%3E"}) {
        auto r = b.sink.Get(std::string(kDevices) + "?name=Chrome&" + hint);
        REQUIRE(r);
        REQUIRE_FALSE(contains(r->body, "1e3"));
        REQUIRE_FALSE(contains(r->body, "abc"));
        REQUIRE_FALSE(contains(r->body, "<b>-1</b>"));
    }
}

TEST_CASE("software routes: the shell carries the page script and /inventory redirects",
          "[inventory][route]") {
    InvHarness h;
    auto shell = h.sink.Get("/software");
    REQUIRE(shell);
    REQUIRE(contains(shell->body, "function swHost"));
    REQUIRE(contains(shell->body, "hx-get=\"/fragments/inventory/software\""));
    REQUIRE(contains(shell->body.substr(shell->body.rfind("function swHost")), "</body>"));
    auto redirect = h.sink.Get("/inventory");
    REQUIRE(redirect);
    REQUIRE(redirect->status == 302);
}

// #4644 Gate 7 (carried across the M.9 catalogue rewrite): `limit` is ONE base-10 integer. The
// software fragments no longer clamp it themselves (the page size is fixed), but a malformed
// value must still be refused by the shared model parser, not silently read as the default.
// The fragments answer 200 + caveat (htmx does not swap 4xx), with no store read.
TEST_CASE("software routes: a malformed limit is refused, not read as the default",
          "[inventory][route][numeric_params]") {
    InvHarness h;
    for (const char* bad : {"50abc", "0x10", "1e2", "99999999999999999999"}) {
        INFO("limit=" << bad);
        auto cat = h.sink.Get(std::string(kSoftware) + "?limit=" + bad);
        REQUIRE(cat);
        CHECK(cat->status == 200);
        CHECK(contains(cat->body, "inv-caveat"));
        auto dev = h.sink.Get(std::string(kDevices) + "?name=Chrome&limit=" + bad);
        REQUIRE(dev);
        CHECK(dev->status == 200);
        CHECK(contains(dev->body, "inv-caveat"));
    }
    CHECK_FALSE(h.last_catalog_query.has_value());
    CHECK_FALSE(h.last_fleet_query.has_value());
}
