/// @file test_software_page_ui.cpp
/// Pure-renderer tests for the rebuilt Software page (M.9): data in, HTML out, no store, no
/// clock, no request. Structural assertions ported from the approved mock-up's checks, plus the
/// escaping / htmx-attribute / CSP guards that protect the page. The route behaviour (gate,
/// scope, cursors, audit) lives in test_inventory_routes.cpp.

#include "inventory_routes.hpp"
#include "software_catalog_rules.hpp" // software_catalog::kEcosystemFamilies

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace swc = yuzu::server::software_catalogue;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

constexpr std::int64_t kNow = 1'000'000;

CatalogRollupMeta meta() {
    CatalogRollupMeta m;
    m.refreshed_at = kNow - 2400; // 40 m ago
    m.total_titles = 1200;
    m.total_devices = 70;
    m.total_publishers = 300;
    m.total_installs = 9000;
    m.installs_windows = 4500;
    m.installs_macos = 2700;
    m.installs_linux = 1800;
    m.current_installs = 600;
    m.current_total = 900;
    m.current_titles = 800;
    m.sprawl_titles = 140;
    m.rpm_total = 50;
    m.rpm_unsigned = 3;
    return m;
}

swc::KpiFigures kpis(std::optional<std::int64_t> connected = 80,
                     std::optional<std::int64_t> stale = 4) {
    swc::Coverage c;
    c.connected = connected;
    c.stale = stale;
    return swc::derive_kpis(meta(), c);
}

SoftwareCatalogRow row(std::string name, std::int64_t installs, std::int64_t versions = 3) {
    SoftwareCatalogRow r;
    r.name = std::move(name);
    r.publisher = "Pub";
    r.device_count = installs;
    r.version_count = versions;
    r.ecosystems = "windows,brew";
    r.kinds = "app,pkg";
    r.newest_version = "9.9";
    return r;
}

SoftwarePageData page(std::vector<SoftwareCatalogRow> rows = {row("Chrome", 1180)}) {
    SoftwarePageData d;
    d.totals = SoftwareCatalogTotals{static_cast<std::int64_t>(rows.size()), 1180};
    d.rows = std::move(rows);
    d.kpis = kpis();
    d.now_secs = kNow;
    return d;
}

SoftwareFleetRow fleet(std::string agent, std::string ver = "1.0", std::string eco = "windows") {
    SoftwareFleetRow r;
    r.agent_id = std::move(agent);
    r.entry.name = "Chrome";
    r.entry.version = std::move(ver);
    r.entry.ecosystem = std::move(eco);
    r.entry.source = "installed_apps.list_inventory";
    return r;
}

std::string full(const SoftwarePageFilters& f, const SoftwarePageData& d) {
    return render_software_page(f, d, SoftwarePageMode::Full);
}

} // namespace

TEST_CASE("software page: strip renders six tiles in mock order plus five hidden later tiles",
          "[inventory][ui]") {
    const std::string h = full({}, page());
    REQUIRE(count_of(h, "<div class=\"h\">") == 11); // six tiles + five later ones
    REQUIRE(count_of(h, "inv-kpi later\" hidden") == 5);
    const auto at = [&](const std::string& s) { return h.find(s); };
    REQUIRE(at("Inventory coverage") < at(">Titles<"));
    REQUIRE(at(">Titles<") < at(">Installs<"));
    REQUIRE(at(">Installs<") < at("Stay current"));
    REQUIRE(at("Stay current") < at("Version sprawl"));
    REQUIRE(at("Version sprawl") < at("Unsigned packages"));
    REQUIRE(has(h, "End-of-support titles"));
    REQUIRE(has(h, "needs a lifecycle feed (none today)"));
    REQUIRE(has(h, "Normalised"));
}

TEST_CASE("software page: tile texts come from KpiFigures without page arithmetic",
          "[inventory][ui]") {
    const auto k = kpis();
    const std::string h = full({}, page());
    REQUIRE(has(h, "distinct software names"));
    REQUIRE(has(h, "<b>300</b> publishers"));
    REQUIRE(has(h, "1,200"));
    // Coverage tile shows counts (v2.3 g): reporting big, connected + stale in the caption.
    REQUIRE(has(h, "devices report software"));
    REQUIRE(has(h, "<b>80</b> connected"));
    REQUIRE(has(h, "<b>4</b> stale (&gt;48 h)"));
    // OS bar widths are the model's integers.
    REQUIRE(has(h, "<span class=\"w\" style=\"width:" + std::to_string(k.windows_pct) + "%\">"));
    REQUIRE(has(h, "<span class=\"m\" style=\"width:" + std::to_string(k.macos_pct) + "%\">"));
    REQUIRE(has(h, "<span class=\"l\" style=\"width:" + std::to_string(k.linux_pct) + "%\">"));
    REQUIRE(has(h, "avg <b>" + std::to_string(k.avg_installs_per_device) + "</b> per device"));
    REQUIRE(has(h, "over <b>800</b> titles with a known version"));
    REQUIRE(has(h, "a proxy, not a vendor feed"));
    REQUIRE(has(h, "of <b>50</b> rpm packages"));
    REQUIRE(has(h, "only rpm reports signing"));
}

TEST_CASE("software page: warn classes follow stale and unsigned counts", "[inventory][ui]") {
    auto d = page();
    std::string h = full({}, d);
    // coverage warns (stale 4), unsigned warns (3)
    REQUIRE(count_of(h, "class=\"inv-kpi warn\"") == 2);
    d.kpis = kpis(80, 0);
    auto m2 = meta();
    m2.rpm_unsigned = 0;
    d.kpis = swc::derive_kpis(m2, swc::Coverage{80, 0});
    h = full({}, d);
    REQUIRE(count_of(h, "class=\"inv-kpi warn\"") == 0);
}

TEST_CASE("software page: unknown figures render a dash, never a number or a warn",
          "[inventory][ui]") {
    auto d = page();
    auto m2 = meta();
    m2.current_total = 0;
    m2.rpm_total = 0;
    m2.rpm_unsigned = 0;
    d.kpis = swc::derive_kpis(m2, swc::Coverage{std::nullopt, std::nullopt});
    const std::string h = full({}, d);
    REQUIRE_FALSE(d.kpis->stay_current_pct.has_value());
    REQUIRE(has(h, "<b>\xE2\x80\x94</b> connected"));
    REQUIRE(has(h, "<b>\xE2\x80\x94</b> stale"));
    REQUIRE(count_of(h, "class=\"inv-kpi warn\"") == 0); // null stale never warns
    REQUIRE(has(h, "no rpm packages in the fleet"));
    REQUIRE(has(h, "<div class=\"h\">Stay current</div><div class=\"big\">\xE2\x80\x94</div>"));
}

TEST_CASE("software page: sprawl tile is a toggle that flips versions_min 3 and 0",
          "[inventory][ui]") {
    SoftwarePageFilters f;
    std::string h = full(f, page());
    REQUIRE(has(h, "id=\"sw-sprawl\""));
    REQUIRE(has(h, "data-act=\"sprawl\" aria-pressed=\"false\""));
    REQUIRE(has(h, "hx-get=\"/fragments/inventory/software?results_only=1&amp;versions_min=3\""));
    f.versions_min = 3;
    h = full(f, page());
    REQUIRE(has(h, "aria-pressed=\"true\""));
    REQUIRE(has(h, "hx-get=\"/fragments/inventory/software?results_only=1\" hx-target"));
    REQUIRE(has(h, "<b>140</b>") == false); // big number is plain, not bold-wrapped
    REQUIRE(has(h, ">140<"));
}

TEST_CASE("software page: freshness line, stale prefix, building and the later toggle",
          "[inventory][ui]") {
    auto d = page();
    std::string h = full({}, d);
    REQUIRE(has(h, "Catalogue rollup updated 40m ago"));
    REQUIRE(has(h, "refreshes hourly"));
    REQUIRE(has(h, "onclick=\"swLater(this)\""));
    d.now_secs = kNow + 20000;
    REQUIRE(has(full({}, d), "Catalogue rollup stale"));
    auto m2 = meta();
    m2.refreshed_at = 0;
    d.kpis = swc::derive_kpis(m2, {});
    h = full({}, d);
    REQUIRE(has(h, "Catalogue is building"));
    REQUIRE_FALSE(has(h, "<table"));
}

TEST_CASE("software page: head and the ADR-0017 caveat", "[inventory][ui]") {
    const std::string h = full({}, page());
    REQUIRE(has(h, "<h1 class=\"inv-h1\">Software</h1>"));
    REQUIRE(has(h, "<a href=\"/hardware\">Hardware</a>"));
    REQUIRE_FALSE(has(h, "inv-subnav")); // the lone Software tab is gone
    REQUIRE(has(h, "Scope (ADR-0017)"));
    REQUIRE_FALSE(has(h, "Devices tab"));
    REQUIRE_FALSE(has(h, "Find is also"));
}

TEST_CASE("software page: search box carries the CSP-safe htmx wiring", "[inventory][ui]") {
    const std::string h = full({}, page());
    REQUIRE(has(h, "id=\"sw-q\" type=\"search\""));
    REQUIRE(has(h, "name=\"q\""));
    REQUIRE(has(h, "placeholder=\"Search software, publisher, ecosystem or found-by"));
    REQUIRE(has(h, "hx-trigger=\"keyup changed delay:400ms, search\""));
    // One shared sync scope (a stable container outside every swap) for every control that
    // re-requests the results, so a slow earlier response cannot overwrite a later one.
    REQUIRE(has(h, "hx-trigger=\"keyup changed delay:400ms, search\" hx-sync=\"#sw-filters:replace\""));
    REQUIRE_FALSE(has(h, "hx-sync=\"this:replace\""));
    REQUIRE(has(h, "<div id=\"sw-filters\""));
    REQUIRE(has(h, "hx-trigger=\"change\" hx-sync=\"#sw-filters:replace\" hx-include=\"#sw-state,#sw-q,#sw-agent\""));
    REQUIRE(has(h, "hx-include=\"#sw-q,#sw-agent\" hx-sync=\"#sw-filters:replace\""));
    REQUIRE(has(h, "hx-include=\"#sw-state,#sw-agent\""));
    // The search box sits before, and outside, the swapped results region.
    REQUIRE(count_of(h, "id=\"sw-q\"") == 1);
    REQUIRE(h.find("id=\"sw-q\"") < h.find("id=\"sw-results\""));
    REQUIRE_FALSE(has(h, "hx-on"));
    // No event filter ('[' inside an hx-trigger) - the no-unsafe-eval CSP silently drops it.
    for (auto p = h.find("hx-trigger=\""); p != std::string::npos; p = h.find("hx-trigger=\"", p + 1))
        REQUIRE(h.substr(p, h.find('"', p + 12) - p).find('[') == std::string::npos);
}

TEST_CASE("software page: kind control, ecosystem and found-by chips", "[inventory][ui]") {
    SoftwarePageFilters f;
    f.kind = "pkg";
    f.ecosystem = "brew";
    f.source = "pkg_inventory.packages";
    const std::string h = full(f, page());
    REQUIRE(has(h, "<button type=\"button\" class=\"inv-chip\" data-g=\"kind\" data-v=\"\""));
    REQUIRE(has(h, "class=\"inv-chip\" data-g=\"kind\" data-v=\"pkg\" aria-pressed=\"true\" "
                   "title=\"macOS pkgutil and Homebrew packages\""));
    REQUIRE(has(h, "data-g=\"kind\" data-v=\"\" aria-pressed=\"false\""));
    REQUIRE(has(h, "title=\"OS packages (rpm, deb, apk, pacman)\""));
    // One ecosystem chip per kEcosystemFamilies entry, in table order.
    std::size_t last = 0;
    for (const auto& e : software_catalog::kEcosystemFamilies) {
        const auto p = h.find("data-g=\"eco\" data-v=\"" + std::string(e.ecosystem) + "\"");
        REQUIRE(p != std::string::npos);
        REQUIRE(p > last);
        last = p;
    }
    REQUIRE(has(h, "data-g=\"eco\" data-v=\"brew\" aria-pressed=\"true\""));
    REQUIRE(has(h, "data-g=\"src\" data-v=\"installed_apps.list_inventory\" aria-pressed=\"false\""));
    REQUIRE(has(h, "data-g=\"src\" data-v=\"windows_optional_features.list\""));
    REQUIRE(count_of(h, "data-g=\"src\"") == 4);
}

TEST_CASE("software page: controls reuse hx-include and never embed q or agent_id",
          "[inventory][ui]") {
    SoftwarePageFilters f;
    f.q = "chrome";
    f.agent_id = "a1";
    f.host_display = "host-1";
    f.kind = "app";
    const std::string h = full(f, page());
    // Chips, pills and the sprawl tile re-request via hx-include for q and agent_id ...
    REQUIRE(has(h, "hx-include=\"#sw-q,#sw-agent\""));
    // ... and none of their URLs embeds those keys.
    for (auto p = h.find("hx-get=\"/fragments/inventory/software?results_only=1"); p != std::string::npos;
         p = h.find("hx-get=\"/fragments/inventory/software?results_only=1", p + 1)) {
        const auto url = h.substr(p, h.find("\" ", p) - p);
        REQUIRE(url.find("q=") == std::string::npos);
        REQUIRE(url.find("agent_id=") == std::string::npos);
    }
    // The Load-more sentinel DOES embed them (its cursor is bound to the whole filter set) and
    // has no hx-include.
    auto d = page();
    d.next_cursor = "c1:abc";
    const std::string rows = render_software_page(f, d, SoftwarePageMode::Rows);
    REQUIRE(has(rows, "rows_only=1&amp;cursor=c1%3Aabc&amp;q=chrome&amp;agent_id=a1&amp;kind=app"));
    REQUIRE_FALSE(has(rows, "hx-include"));
}

TEST_CASE("software page: host type-ahead pairs a datalist with a hidden agent id",
          "[inventory][ui]") {
    auto d = page();
    d.hosts = {{"alpha", "id-1"}, {"beta \"q\"", "id-2"}};
    const std::string h = full({}, d);
    REQUIRE(has(h, "id=\"sw-host\""));
    REQUIRE(has(h, "list=\"hostlist\""));
    REQUIRE(has(h, "id=\"sw-agent\" type=\"hidden\" name=\"agent_id\" value=\"\""));
    REQUIRE(has(h, "<option value=\"alpha\" data-id=\"id-1\">"));
    REQUIRE(has(h, "<option value=\"beta &quot;q&quot;\" data-id=\"id-2\">")); // escaped
    REQUIRE(has(h, "onchange=\"swHost(this)\""));
    REQUIRE(has(h, "oninput=\"this.setCustomValidity('')\""));
    REQUIRE_FALSE(has(h, "type-ahead lists")); // nothing was cut: no note
    // A capped list discloses the cap and the true named-host count.
    d.hosts_total = 1002;
    REQUIRE(has(full({}, d), "type-ahead lists the first 2 of 1,002 named hosts (by name); other "
                             "devices open from Hardware"));
}

TEST_CASE("software page: active pills, Clear all and the REST line", "[inventory][ui]") {
    SoftwarePageFilters f;
    f.q = "a&b c";
    f.kind = "app";
    f.ecosystem = "brew";
    f.source = "pkg_inventory.packages";
    f.agent_id = "id-1";
    f.host_display = "host-1";
    f.versions_min = 3;
    const std::string h = full(f, page());
    for (const char* p : {"search: a&amp;b c", "kind: app", "ecosystem: brew",
                          "found by: pkg_inventory.packages", "host: host-1", "on 3+ versions"})
        REQUIRE(has(h, std::string("<span class=\"inv-apill\">") + p));
    REQUIRE(count_of(h, "<span class=\"inv-apill\">") == 6);
    REQUIRE(has(h, "data-act=\"clear\""));
    REQUIRE(has(h, "hx-swap=\"outerHTML\" hx-sync=\"#sw-filters:replace\">Clear all</button>"));
    const std::string call = software_rest_call(f);
    REQUIRE(call == "/api/v1/inventory/software/catalogue?q=a%26b%20c&kind=app&ecosystem=brew&"
                    "source=pkg_inventory.packages&agent_id=id-1&versions_min=3&limit=100");
    REQUIRE(has(h, "data-copy=\"" + call.substr(0, 20))); // the copy button carries the same text
    REQUIRE(has(h, ">GET</span>"));
    // No filter -> no pills, no Clear all, the REST line is still there.
    const std::string bare = full({}, page());
    REQUIRE(count_of(bare, "<span class=\"inv-apill\">") == 0);
    REQUIRE_FALSE(has(bare, "data-act=\"clear\" onclick"));
    REQUIRE(has(bare, "limit=100"));
}

TEST_CASE("software page: table columns, row attributes and number formatting", "[inventory][ui]") {
    const std::string h = full({}, page());
    const std::array<const char*, 7> cols{"Software",    "Publisher",       "Ecosystem &middot; kind",
                                          "Installs",     "Versions",        "Newest in fleet",
                                          ""};
    std::size_t last = 0;
    for (const char* c : cols) {
        const auto p = h.find("<th scope=\"col\"", last);
        REQUIRE(p != std::string::npos);
        const auto gt = h.find('>', p);
        const auto end = h.find("</th>", gt);
        REQUIRE(gt != std::string::npos);
        REQUIRE(end != std::string::npos);
        // The header text starts with the expected label (Installs carries a trailing span).
        const std::string label = c;
        REQUIRE(h.compare(gt + 1, label.size(), label) == 0);
        if (label.empty())
            REQUIRE(end == gt + 1);
        last = end;
    }
    REQUIRE(count_of(h, "<th scope=\"col\"") == 7);
    REQUIRE(has(h, "counted exactly under the active filters"));
    REQUIRE(has(h, "aria-expanded=\"false\""));
    REQUIRE(has(h, "title=\"Click for installs per version\""));
    REQUIRE(has(h, "<td class=\"inv-num\">1,180</td>"));
    REQUIRE(has(h, "<span class=\"inv-pill win\">windows</span> <span class=\"inv-pill mac\">brew</span>"));
    REQUIRE(has(h, "<span class=\"inv-grey\">app/pkg</span>"));
    REQUIRE(has(h, "<td class=\"inv-mono\">9.9</td>"));
    // Empty publisher / newest render as a dash.
    auto r = row("Bare", 5);
    r.publisher.clear();
    r.newest_version.clear();
    const std::string h2 = full({}, page({r}));
    REQUIRE(has(h2, "<td class=\"inv-pub\"><span class=\"inv-grey\">\xE2\x80\x94</span></td>"));
    REQUIRE(has(h2, "<td class=\"inv-mono\"><span class=\"inv-grey\">\xE2\x80\x94</span></td>"));
}

TEST_CASE("software page: confined host view blanks Newest in fleet once and says why",
          "[inventory][ui]") {
    auto d = page({row("A", 1), row("B", 1)});
    d.confined = true;
    d.kpis.reset();
    SoftwarePageFilters f;
    f.agent_id = "a1";
    const std::string h = full(f, d);
    REQUIRE_FALSE(has(h, "9.9"));
    REQUIRE(count_of(h, "your management groups only") == 1);
    // P4: no fleet strip, no datalist, no counts from the fleet.
    REQUIRE(has(h, "<div id=\"sw-kpis\"><div class=\"inv-caveat\">"));
    REQUIRE_FALSE(has(h, "<div class=\"inv-kpi"));
    REQUIRE_FALSE(has(h, "<datalist"));
    REQUIRE_FALSE(has(h, "list=\"hostlist\""));
    // The fleet-wide scope banner is never drawn on a confined view (no fleet counts there).
    REQUIRE_FALSE(has(h, "Scope (ADR-0017)"));
}

TEST_CASE("software page: exports are download links; install exports omit versions_min",
          "[inventory][ui]") {
    SoftwarePageFilters f;
    f.q = "x";
    f.kind = "app";
    f.versions_min = 3;
    const std::string h = full(f, page());
    REQUIRE(count_of(h, "<a class=\"inv-btn sm\" data-act=\"export\"") == 3);
    REQUIRE(has(h, "download=\"software-installs.json\""));
    REQUIRE(has(h, "download=\"software-installs.csv\""));
    REQUIRE(has(h, "download=\"software-titles.csv\""));
    REQUIRE(has(h, "href=\"/api/v1/inventory/software?format=json&amp;q=x&amp;kind=app\""));
    REQUIRE(has(h, "href=\"/api/v1/inventory/software?format=csv&amp;q=x&amp;kind=app\""));
    REQUIRE(has(h, "href=\"/api/v1/inventory/software/catalogue?format=csv&amp;q=x&amp;kind=app&amp;"
                   "versions_min=3\""));
    REQUIRE(has(h, "the sprawl filter is not applied to install exports"));
}

TEST_CASE("software page: result bar counts and the Load-more sentinel", "[inventory][ui]") {
    auto d = page({row("Chrome", 1180), row("Zed", 7)});
    d.totals = SoftwareCatalogTotals{250, 20000};
    d.next_cursor = "c1:tok";
    d.shown_before = 100;
    SoftwarePageFilters f;
    std::string h = full(f, d);
    REQUIRE(has(h, "<b>250</b> titles &middot; <b>20,000</b> installs &middot; most installed first"));
    REQUIRE_FALSE(has(h, "match your filters"));
    REQUIRE(has(h, "data-act=\"more\" hx-get=\"/fragments/inventory/software?rows_only=1&amp;"
                   "cursor=c1%3Atok&amp;shown=102\""));
    REQUIRE(has(h, "hx-target=\"closest tr\" hx-swap=\"outerHTML\" hx-disabled-elt=\"this\">Load 100 more titles"));
    REQUIRE(has(h, "<span class=\"inv-cursor\">102 of 250 &middot; cursor after (7 installs, Zed)</span>"));
    f.q = "z";
    REQUIRE(has(full(f, d), "match your filters"));
    d.next_cursor.reset();
    d.shown_before = 0;
    REQUIRE(has(full({}, d), "All 250 matching titles are loaded."));
}

TEST_CASE("software page: modes return the right regions", "[inventory][ui]") {
    const auto d = page();
    const std::string res = render_software_page({}, d, SoftwarePageMode::Results);
    REQUIRE(res.rfind("<div id=\"sw-results\"", 0) == 0);
    REQUIRE(has(res, "id=\"sw-sprawl\" "));
    REQUIRE(has(res, "hx-swap-oob=\"true\""));
    REQUIRE(has(res, "<div id=\"sw-chips\" style=\"display:contents\" hx-swap-oob=\"true\">"));
    REQUIRE(has(res, "<div id=\"sw-active\" hx-swap-oob=\"true\">"));
    REQUIRE_FALSE(has(res, "id=\"sw-q\""));
    const std::string rows = render_software_page({}, d, SoftwarePageMode::Rows);
    REQUIRE(rows.rfind("<tr", 0) == 0);
    REQUIRE_FALSE(has(rows, "<table"));
    REQUIRE_FALSE(has(rows, "sw-results"));
    const std::string f = full({}, d);
    REQUIRE(has(f, "id=\"sw-kpis\""));
    REQUIRE(has(f, "id=\"sw-results\" data-hash=\"\""));
}

TEST_CASE("software page: panel wrappers stay balanced in every region", "[inventory][ui]") {
    // The inv-panel wrappers are concatenated by hand across both results_region return paths.
    auto balanced = [](const std::string& h) {
        INFO(h);
        REQUIRE(count_of(h, "<div ") + count_of(h, "<div>") == count_of(h, "</div>"));
    };
    auto d = page();
    balanced(full({}, d));
    balanced(render_software_page({}, d, SoftwarePageMode::Results));
    d = page({});
    d.totals = SoftwareCatalogTotals{0, 0};
    balanced(full({}, d));
    balanced(render_software_page({}, d, SoftwarePageMode::Results));
    d = page();
    d.rows.reset();
    balanced(render_software_page({}, d, SoftwarePageMode::Results));
}

TEST_CASE("software page: degrade, empty, filtered-empty and caveat states", "[inventory][ui]") {
    auto d = page();
    d.rows.reset();
    std::string h = full({}, d);
    REQUIRE(has(h, "Inventory store unavailable."));
    REQUIRE(has(h, "data-act=\"retry\""));
    REQUIRE_FALSE(has(h, "<table"));
    d = page();
    d.totals.reset();
    REQUIRE(has(full({}, d), "Inventory store unavailable."));
    d = page();
    d.kpis.reset();
    REQUIRE(has(full({}, d), "Inventory store unavailable."));
    // Results mode degrades inside the swap region, never an empty table.
    d = page();
    d.rows.reset();
    REQUIRE(has(render_software_page({}, d, SoftwarePageMode::Results), "Inventory store unavailable."));

    d = page({});
    d.totals = SoftwareCatalogTotals{0, 0};
    REQUIRE(has(full({}, d), "No device has reported installed software yet."));
    SoftwarePageFilters f;
    f.q = "nothing";
    h = full(f, d);
    REQUIRE(has(h, "No software matches these filters."));
    REQUIRE(has(h, "Clear all filters"));
    // No zero count line: the live region is drawn empty.
    REQUIRE(has(h, "<div class=\"inv-count\" aria-live=\"polite\"></div>"));

    d = page();
    d.caveat = "versions_min must be an integer";
    h = full({}, d);
    REQUIRE(has(h, "versions_min must be an integer"));
    REQUIRE_FALSE(has(h, "<table"));
    REQUIRE(has(render_software_page({}, d, SoftwarePageMode::Rows), "<tr><td colspan=\"7\">"));
    // The controls-less Full caveat offers a reset (the URL hash cannot be repaired from the page);
    // the swap regions do not.
    REQUIRE(has(h, "<a class=\"inv-link\" href=\"/software\" "
                   "onclick=\"history.replaceState(null,'',location.pathname)\">Clear all filters and reload</a>"));
    REQUIRE_FALSE(has(render_software_page({}, d, SoftwarePageMode::Results), "Clear all filters and reload"));
    REQUIRE_FALSE(has(render_software_page({}, d, SoftwarePageMode::Rows), "Clear all filters and reload"));

    d = page();
    d.confined = true;
    d.caveat = "fleet-wide aggregate";
    h = full({}, d);
    REQUIRE(has(h, "<div id=\"sw-kpis\"><div class=\"inv-caveat\">fleet-wide aggregate"));
    REQUIRE_FALSE(has(h, "<table"));
    REQUIRE_FALSE(has(h, "<div class=\"inv-kpi"));
    REQUIRE_FALSE(has(h, "Scope (ADR-0017)"));
    // A confined notice has no controls, so it carries the reset too (a bad #host= is repaired here).
    REQUIRE(has(h, "<a class=\"inv-link\" href=\"/software\" "
                   "onclick=\"history.replaceState(null,'',location.pathname)\">Clear all filters and reload</a>"));

    // Rows mode with the rows read degraded: a retry row, never a table.
    d = page();
    d.rows.reset();
    h = render_software_page({}, d, SoftwarePageMode::Rows);
    REQUIRE(h.starts_with("<tr"));
    REQUIRE(has(h, "inv-degrade"));
    REQUIRE_FALSE(has(h, "<table"));
}

TEST_CASE("software page: hostile text is escaped everywhere it lands", "[inventory][ui]") {
    const std::string evil = "<script>alert(1)</script> \"x\" 100%";
    const std::string img = "<img src=x onerror=alert(1)>";
    auto hostile = row(evil, 3);
    hostile.publisher = hostile.newest_version = hostile.ecosystems = hostile.kinds = img;
    auto d = page({hostile});
    SoftwarePageFilters f;
    f.kind = f.ecosystem = f.source = "\"><script>"; // echoed to pills and the hidden inputs
    f.q = evil;
    f.host_display = evil;
    f.agent_id = "id\"1";
    const std::string h = full(f, d);
    REQUIRE_FALSE(has(h, "<script>alert"));
    REQUIRE(has(h, "&lt;script&gt;alert(1)&lt;/script&gt;"));
    // Publisher, newest version, ecosystem and kind cells, and the kind/ecosystem/source filters.
    REQUIRE_FALSE(has(h, "<img"));
    REQUIRE(has(h, "&lt;img src=x onerror=alert(1)&gt;"));
    REQUIRE_FALSE(has(h, "\"><script>"));
    REQUIRE(has(h, "&quot;&gt;&lt;script&gt;"));
    // The row's element ids carry no raw punctuation from the title.
    const auto p = h.find("hx-target=\"#exp-");
    REQUIRE(p != std::string::npos);
    const auto id = h.substr(p + 15, h.find('"', p + 15) - p - 15);
    for (char c : id)
        REQUIRE((std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-'));
    // URLs percent-encode it.
    REQUIRE(has(h, "name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E%20%22x%22%20100%25"));
    REQUIRE(has(h, "data-hash=\"q=%3Cscript"));
}

TEST_CASE("software page: URL hash emits only the set keys", "[inventory][ui]") {
    SoftwarePageFilters f;
    REQUIRE(software_page_hash(f).empty());
    f.q = "a b";
    f.ecosystem = "brew";
    f.source = "s";
    f.agent_id = "id-1";
    f.versions_min = 3;
    f.kind = "app";
    REQUIRE(software_page_hash(f) == "q=a%20b&kind=app&eco=brew&src=s&host=id-1&vmin=3");
}

TEST_CASE("software page: versions expansion", "[inventory][ui]") {
    SoftwarePageFilters f;
    f.kind = "app";
    std::vector<SoftwareVersionCount> v{{"3.0", 100, true}, {"2.0", 50, false}, {"", 7, false}};
    std::string h = render_software_versions_expansion(f, "Chrome", v, false);
    REQUIRE(has(h, "<div class=\"inv-exp-body\"><span class=\"inv-close\" data-close"));
    REQUIRE(has(h, "close \xE2\x9C\x95"));
    REQUIRE(has(h, "<b>Chrome</b> <span class=\"inv-grey\">&middot; installs per version</span>"));
    REQUIRE(has(h, "<th>Version</th><th class=\"inv-num\">Installs</th><th>Share</th>"));
    REQUIRE(count_of(h, "newest in fleet") == 1);
    REQUIRE(has(h, "3.0 <span class=\"inv-pill on\">newest in fleet</span>"));
    REQUIRE(has(h, "style=\"width:100%\""));
    REQUIRE(has(h, "style=\"width:50%\""));
    REQUIRE(has(h, "style=\"width:7%\""));
    REQUIRE(has(h, "(unknown)"));
    // Each version's devices link carries version= (present even when empty) and total.
    REQUIRE(has(h, "version=3.0&amp;kind=app&amp;total=100"));
    REQUIRE(has(h, "name=Chrome&amp;version=&amp;kind=app&amp;total=7"));
    REQUIRE(count_of(h, "hx-target=\"#vdev-") == 3);
    // Confined: the mark is blanked.
    REQUIRE_FALSE(has(render_software_versions_expansion(f, "Chrome", v, true), "newest in fleet"));
    // L1: two (title, version) pairs that concatenate alike get distinct ids.
    const auto one = render_software_versions_expansion(f, "ab", {{{"c", 1, false}}}, false);
    const auto two = render_software_versions_expansion(f, "a", {{{"bc", 1, false}}}, false);
    const auto idof = [](const std::string& s) {
        const auto p = s.find("hx-target=\"#vdev-");
        return s.substr(p, s.find('"', p + 17) - p);
    };
    REQUIRE(idof(one) != idof(two));
    // A truncated read says so (the row's Versions column carries the true count); a full list does not.
    const std::string cut_line = "showing the 200 most-installed versions; this title may have more";
    std::vector<SoftwareVersionCount> many;
    for (int i = 0; i < 200; ++i)
        many.push_back({"v" + std::to_string(i), 200 - i, i == 0});
    REQUIRE(has(render_software_versions_expansion(f, "Chrome", many, false, true),
                "<div class=\"inv-grey\">" + cut_line + "</div>"));
    REQUIRE_FALSE(has(render_software_versions_expansion(f, "Chrome", many, false, false), "most-installed"));
    // Degrade / empty.
    REQUIRE(has(render_software_versions_expansion(f, "C", std::nullopt, false), "unavailable"));
    REQUIRE(has(render_software_versions_expansion(f, "C", std::vector<SoftwareVersionCount>{}, false),
                "No version data"));
}

TEST_CASE("software page: versions expansion escapes hostile text", "[inventory][ui]") {
    SoftwarePageFilters f;
    f.kind = f.ecosystem = f.source = "\"><script>";
    const std::string h = render_software_versions_expansion(
        f, "<img src=x onerror=alert(1)>", {{{"<b>", 3, true}, {"2.0", 1, false}}}, false);
    REQUIRE_FALSE(has(h, "<img"));
    REQUIRE_FALSE(has(h, "<td class=\"inv-mono\"><b>"));
    REQUIRE_FALSE(has(h, "\"><script>"));
    REQUIRE(has(h, "<b>&lt;img src=x onerror=alert(1)&gt;</b>"));
    REQUIRE(has(h, "<td class=\"inv-mono\">&lt;b&gt; <span class=\"inv-pill on\">newest in fleet</span>"));
}

TEST_CASE("software devices table: header, columns, host links and last synced", "[inventory][ui]") {
    SoftwareDevicesTable t;
    t.name = "Chrome";
    t.now_secs = kNow;
    t.total = 250;
    t.shown_before = 2;
    t.rows = std::vector<SoftwareFleetRow>{fleet("a1", "1.0", "windows"), fleet("a2", "2.0", "deb")};
    t.hostnames = {{"a1", "WIN-1"}};
    t.last_synced = std::unordered_map<std::string, std::int64_t>{{"a1", kNow - 3600},
                                                                  {"a2", kNow - 200000}};
    std::string h = render_software_devices_table({}, t, false);
    REQUIRE(has(h, "<b>250</b> devices run <b>Chrome</b> <span class=\"inv-grey\">(all versions)</span>"));
    REQUIRE(has(h, "<th>Host</th><th>OS</th><th>Version</th><th>Ecosystem &middot; found by</th>"
                   "<th>Installed</th><th>Last synced</th>"));
    REQUIRE(has(h, "<a class=\"inv-hostlink\" href=\"/hardware/ci?id=a1\""));
    REQUIRE(has(h, "<a class=\"inv-hostlink inv-unnamed\" href=\"/hardware/ci?id=a2\" "
                   "title=\"No host name on record; opens the device page by agent id\""));
    REQUIRE(has(h, ">a2</a>"));
    REQUIRE(has(h, "<span class=\"inv-pill win\">Windows</span>"));
    REQUIRE(has(h, "<span class=\"inv-pill lin\">Linux</span>"));
    REQUIRE(has(h, "<span class=\"inv-grey\">60m ago</span>"));
    REQUIRE(has(h, "<span class=\"inv-pill stale\" title=\"last sync more than 48h ago\">2d ago</span>"));
    REQUIRE_FALSE(has(h, "inv-devfilter")); // <= 8 rows: no filter box
    // One version: no Version column, the version shows in the head.
    t.version = "1.0";
    h = render_software_devices_table({}, t, false);
    REQUIRE_FALSE(has(h, "<th>Version</th>"));
    REQUIRE(has(h, "<span class=\"inv-mono\">1.0</span>"));
    // The empty-version bucket reads "(unknown)", as it does in the versions table.
    t.version = std::optional<std::string>("");
    h = render_software_devices_table({}, t, false);
    REQUIRE(has(h, "<span class=\"inv-mono\">(unknown)</span>"));
    REQUIRE_FALSE(has(h, "<span class=\"inv-mono\"></span>"));
    t.version = "1.0";
    // A device missing from a present map was never synced: a plain dash, no degrade tooltip.
    t.last_synced = std::unordered_map<std::string, std::int64_t>{{"a1", kNow - 3600}};
    h = render_software_devices_table({}, t, false);
    REQUIRE_FALSE(has(h, "last sync time unavailable"));
    // Bulk read degraded: every cell is a distinguishable dash, never a fake time.
    t.last_synced.reset();
    h = render_software_devices_table({}, t, false);
    REQUIRE(has(h, "<table class=\"inv-tbl inv-sub\">"));
    REQUIRE(has(h, "title=\"last sync time unavailable"));
    REQUIRE_FALSE(has(h, "ago"));
}

TEST_CASE("software devices table: filter box, sentinel, rows_only and scoped output",
          "[inventory][ui]") {
    SoftwareDevicesTable t;
    t.name = "Chrome";
    t.now_secs = kNow;
    t.total = 250;
    t.shown_before = 100;
    t.next_cursor = "d1:tok";
    std::vector<SoftwareFleetRow> rows;
    for (int i = 0; i < 9; ++i)
        rows.push_back(fleet("a" + std::to_string(i)));
    t.rows = rows;
    std::string h = render_software_devices_table({}, t, false);
    REQUIRE(has(h, "class=\"inv-hostin inv-devfilter\""));
    const auto grp = h.find("data-gpf=\"swdev-");
    REQUIRE(grp != std::string::npos);
    // The filter box and its rows share one group id.
    const auto gid = h.substr(grp, h.find('"', grp + 10) - grp);
    REQUIRE(count_of(h, gid) == 10);
    REQUIRE(has(h, "oninput=\"gpSearch(this)\""));
    REQUIRE(has(h, "data-act=\"dmore\" hx-get=\"/fragments/inventory/software/devices?name=Chrome&amp;"
                   "cursor=d1%3Atok&amp;total=250&amp;shown=100\""));
    REQUIRE(has(h, "hx-target=\"closest tr\" hx-swap=\"outerHTML\" hx-disabled-elt=\"this\">Load 100 more"));
    REQUIRE(has(h, "<span class=\"inv-cursor\">100 of 250</span>"));
    // rows_only: only <tr>s.
    const std::string r = render_software_devices_table({}, t, true);
    REQUIRE(r.rfind("<tr", 0) == 0);
    REQUIRE_FALSE(has(r, "<table"));
    // Scoped (confined caller): note, no devhead count, no `of M`.
    t.scoped = true;
    t.total.reset();
    h = render_software_devices_table({}, t, false);
    REQUIRE(has(h, "your management groups only"));
    REQUIRE(has(h, "Devices run <b>Chrome</b>"));
    REQUIRE_FALSE(has(h, "devices run <b>"));
    REQUIRE(has(h, "100 loaded"));
    REQUIRE_FALSE(has(h, " of "));
    // Degrade and empty.
    SoftwareDevicesTable bad;
    bad.name = "Chrome";
    REQUIRE(has(render_software_devices_table({}, bad, false), "unavailable"));
    // rows_only degrade: one row carrying the banner, never a table.
    const auto degraded_rows = render_software_devices_table({}, bad, true);
    REQUIRE(degraded_rows.starts_with("<tr><td colspan="));
    REQUIRE(has(degraded_rows, "unavailable"));
    REQUIRE_FALSE(has(degraded_rows, "<table"));
    bad.rows = std::vector<SoftwareFleetRow>{};
    REQUIRE(has(render_software_devices_table({}, bad, false), "No host matches."));
    // A continuation that comes back empty with no further cursor must not append the notice
    // beneath the rows already shown: it renders nothing at all.
    REQUIRE(render_software_devices_table({}, bad, true).empty());
    // Empty page but a cursor is offered (wide scope): never "No host matches", point at Load more.
    bad.next_cursor = "tok";
    for (const bool rows_only : {false, true}) {
        const auto h2 = render_software_devices_table({}, bad, rows_only);
        REQUIRE_FALSE(has(h2, "No host matches"));
        // The notice is first-page only: Load more swaps just its own row, so a continuation
        // render carries the next Load-more row alone.
        REQUIRE(has(h2, "more may be in later pages") == !rows_only);
        REQUIRE(has(h2, "data-act=\"dmore\""));
    }
}

TEST_CASE("software devices table: hostile text is escaped everywhere it lands", "[inventory][ui]") {
    SoftwareDevicesTable t;
    t.name = "<script>";
    t.now_secs = kNow;
    auto r = fleet("a&b", "<b>", "windows");
    r.entry.source = "\"x\"";
    r.entry.install_date = "<i id=d>";
    t.rows = std::vector<SoftwareFleetRow>{r};
    t.hostnames = {{"a&b", "<img src=x onerror=alert(1)>\""}};
    const std::string h = render_software_devices_table({}, t, false);
    REQUIRE_FALSE(has(h, "<img"));
    REQUIRE_FALSE(has(h, "<script"));
    REQUIRE_FALSE(has(h, "<td class=\"inv-mono\"><b>"));
    REQUIRE_FALSE(has(h, ">\"x\"<"));
    REQUIRE_FALSE(has(h, "<i id=d>"));
    REQUIRE(has(h, "&lt;i id=d&gt;"));
    REQUIRE(has(h, "&lt;img src=x onerror=alert(1)&gt;&quot;"));
    REQUIRE(has(h, "<b>&lt;script&gt;</b>"));
    REQUIRE(has(h, "<td class=\"inv-mono\">&lt;b&gt;</td>"));
    REQUIRE(has(h, "&quot;x&quot;"));
    REQUIRE(has(h, "href=\"/hardware/ci?id=a%26b\""));
    REQUIRE(has(h, "data-gpname=\"&lt;img src=x onerror=alert(1)&gt;&quot;\""));
}

TEST_CASE("software page: shell script is CSP-safe and wires the page's behaviour",
          "[inventory][ui]") {
    const std::string s = software_page_script();
    for (const char* need : {"htmx:configRequest", "htmx:afterSettle", "htmx:beforeRequest",
                             "replaceState", "swLater", "swHost", "swClear", "swClose", "gpSearch(",
                             "setCustomValidity('Not a listed host name')", "reportValidity()"})
        REQUIRE(has(s, need));
    for (const char* never : {"hx-on", "new Function", "eval("})
        REQUIRE_FALSE(has(s, never));
    REQUIRE(s.rfind("<script>", 0) == 0);
}

// The Inventory sources panel loads once with the full page and only there: the Results and
// Rows swaps must not re-request it. Kills: moving the host into results_region.
TEST_CASE("software page: Inventory sources host loads with the full page only",
          "[inventory][ui]") {
    const auto d = page();
    const std::string html = full({}, d);
    REQUIRE(has(html, "hx-get=\"/fragments/inventory/sources\" hx-trigger=\"load\""));
    REQUIRE_FALSE(has(render_software_page({}, d, SoftwarePageMode::Results),
                      "/fragments/inventory/sources"));
    REQUIRE_FALSE(has(render_software_page({}, d, SoftwarePageMode::Rows),
                      "/fragments/inventory/sources"));
}
