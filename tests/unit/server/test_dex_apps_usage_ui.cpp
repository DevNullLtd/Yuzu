/**
 * test_dex_apps_usage_ui.cpp -- the Usage view of the Digital Employee Experience Apps tab
 * (`render_dex_apps_usage_fragment`, `render_dex_apps_usage_refusal`, the View chips on the
 * Stability page, and GET /fragments/dex/apps/usage).
 *
 * Pure string assertions over hand-built `DexAppsUsageModel` values, and in-process route tests
 * through TestRouteSink with injected closures: no store, no Postgres, no process, no sleep, no
 * clock, no golden files. The page is compared with the REST payload of the same model
 * (`dex_apps_usage_json`), so the two cannot disagree.
 */
#include "dex_apps_ui.hpp"
#include "dex_pane.hpp"
#include "dex_routes.hpp"
#include "dex_usage_json.hpp"
#include "test_dex_api_double.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <format>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;
using Catch::Approx;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + needle.size()))
        ++n;
    return n;
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    for (auto at = s.find(from); at != std::string::npos; at = s.find(from, at + to.size()))
        s.replace(at, from.size(), to);
    return s;
}

// ── builders ──

constexpr std::int64_t kAsOf = 1'700'000'000; // 2023-11-14T22:13:20Z

DexAppsUsageModel base_model() {
    DexAppsUsageModel m;
    m.window = "7d";
    m.platform_scope = "all";
    m.population = 100;
    m.reporting_devices = 80;
    m.stale_devices = 10;
    m.floor = 1;
    m.as_of_epoch = kAsOf;
    return m;
}

DexAppsUsageControls controls_for(DexUsageSliceKind kind = DexUsageSliceKind::Fleet,
                                  const std::string& key = "") {
    DexAppsUsageControls c;
    c.window_days = 7;
    c.platform = "all";
    c.slice.kind = kind;
    c.slice.key = key;
    return c;
}

DexExposureRate rate_of(double est, double lo, double hi, double hours, std::int64_t crashes,
                        std::int64_t hangs, bool reliable = true) {
    DexExposureRate r;
    r.per_hour = DexInterval{est, lo, hi, reliable};
    r.hours = hours;
    r.crashes = crashes;
    r.hangs = hangs;
    return r;
}

DexAppUsage matched_app(const std::string& subject, std::int64_t devices, std::int64_t secs,
                        std::int64_t launches) {
    DexAppUsage a;
    a.subject = subject;
    a.state = DexUsageState::Matched;
    a.devices = devices;
    a.totals = DexUsageTotals{secs, launches};
    return a;
}

DexAppUsage with_rate(DexAppUsage a, const DexExposureRate& r) {
    a.rate = r;
    a.rate_withheld.clear();
    return a;
}

DexAppUsage withheld_app(const std::string& subject, const std::string& token) {
    DexAppUsage a = matched_app(subject, 40, 7200, 10);
    a.rate_withheld = token;
    return a;
}

DexAppUsage below_app(const std::string& subject) {
    DexAppUsage a = matched_app(subject, 3, 0, 0);
    a.totals.reset();
    a.rate_withheld = "below_floor";
    return a;
}

DexAppUsage no_usage_app(const std::string& subject) {
    DexAppUsage a;
    a.subject = subject;
    a.state = DexUsageState::NoUsage;
    a.rate_withheld = "no_usage";
    return a;
}

DexAppUsage ambiguous_app(const std::string& subject) {
    DexAppUsage a;
    a.subject = subject;
    a.state = DexUsageState::AmbiguousName;
    a.rate_withheld = "ambiguous_name";
    return a;
}

DexUsageCell cell_of(DexUsageCellKind kind, const std::string& label, std::int64_t devices,
                     std::int64_t secs, std::int64_t launches, bool small = false) {
    DexUsageCell c;
    c.kind = kind;
    c.label = label;
    c.devices = devices;
    c.totals = DexUsageTotals{secs, launches};
    c.small_cohort = small;
    return c;
}

// ── page navigation helpers ──

// The <tbody> that holds the application's link, found by its printed name.
std::string body_of(const std::string& page, const std::string& subject) {
    const auto at = page.find(">" + subject + "</button>");
    REQUIRE(at != std::string::npos);
    const auto b = page.rfind("<tbody", at);
    const auto e = page.find("</tbody>", at);
    REQUIRE(b != std::string::npos);
    REQUIRE(e != std::string::npos);
    return page.substr(b, e - b);
}

std::string head_row(const std::string& body) { return body.substr(0, body.find("</tr>")); }

// The printed rate estimate: the last <span class="v"> of the application's head row.
double printed_estimate(const std::string& body) {
    const std::string head = head_row(body);
    const std::string marker = "<span class=\"v\">";
    const auto at = head.rfind(marker);
    REQUIRE(at != std::string::npos);
    const auto s = at + marker.size();
    return std::stod(head.substr(s, head.find(' ', s) - s));
}

// The printed interval bounds, as text, from "(lower&ndash;upper)".
std::pair<std::string, std::string> printed_bounds(const std::string& body) {
    const std::string head = head_row(body);
    const std::string marker = "<span class=\"gp-mute nw\">(";
    const auto at = head.rfind(marker);
    REQUIRE(at != std::string::npos);
    const auto s = at + marker.size();
    const auto dash = head.find("&ndash;", s);
    const auto close = head.find(')', dash);
    REQUIRE(dash != std::string::npos);
    REQUIRE(close != std::string::npos);
    return {head.substr(s, dash - s), head.substr(dash + 7, close - dash - 7)};
}

// The hx-get value of the first control after `anchor`, with &amp; decoded as a browser would.
std::string hx_get_after(const std::string& page, const std::string& anchor) {
    const auto a = page.find(anchor);
    REQUIRE(a != std::string::npos);
    const std::string key = "hx-get=\"";
    const auto b = page.find(key, a);
    REQUIRE(b != std::string::npos);
    const auto s = b + key.size();
    return replace_all(page.substr(s, page.find('"', s) - s), "&amp;", "&");
}

// ── the Stability page ──

DexAppsModel stability_model() {
    DexAppsModel m;
    m.window = "7d";
    m.platform_scope = "all";
    m.population = 10;
    DexAppStability a;
    a.subject = "ledger.exe";
    a.figures.crashes = 3;
    a.figures.distinct_devices = 2;
    m.apps.push_back(a);
    return m;
}

std::string view_row(bool usage_on) {
    return "<div class=\"gp-filters\"><span class=\"dx-lbl\">View</span>" +
           dex_pane_chip("/fragments/dex/apps?window=7d&amp;platform=all", "Stability", !usage_on) +
           dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=all", "Usage", usage_on) + "</div>";
}

} // namespace

TEST_CASE("Usage UI: the Stability page adds only the View chips and one line", "[dex][apps_ui]") {
    const auto model = stability_model();
    const std::string hidden = render_dex_apps_fragment(model, 7, "all", DexAppsUsageEntry::Hidden);
    CHECK(render_dex_apps_fragment(model, 7, "all") == hidden); // the 3-argument call is the Hidden call
    CHECK_FALSE(contains(hidden, "/fragments/dex/apps/usage"));
    CHECK_FALSE(contains(hidden, "dx-lbl\">View<"));

    const std::string offered = render_dex_apps_fragment(model, 7, "all", DexAppsUsageEntry::Offered);
    CHECK(count_of(offered, "dx-lbl\">View<") == 1);
    CHECK(count_of(offered, ">Stability</button>") == 1);
    CHECK(count_of(offered, ">Usage</button>") == 1);
    CHECK(contains(offered, view_row(false)));
    CHECK(replace_all(offered, view_row(false), "") == hidden); // exactly the chips, nothing else

    struct Case {
        DexAppsUsageEntry entry;
        std::string line;
    };
    for (const auto& k :
         {Case{DexAppsUsageEntry::Refused,
               "<div class=\"gp-note\">Usage is not shown: it needs the Forensics read permission, which this "
               "account does not hold. Nothing else on this page is affected.</div>"},
          Case{DexAppsUsageEntry::GateUnavailable,
               "<div class=\"gp-note\">Usage is not shown: the permission check could not be completed. Try "
               "again in a moment. Nothing else on this page is affected.</div>"}}) {
        const std::string page = render_dex_apps_fragment(model, 7, "all", k.entry);
        CHECK(replace_all(page, view_row(false) + k.line, "") == hidden); // the chips and the line, nothing else
        CHECK(contains(page, "ledger.exe")); // the table and its figures are still there
    }

    // An unrecognised platform still draws the chips (they fall back to all) beside the error panel.
    const std::string bad = render_dex_apps_fragment(model, 7, "beos", DexAppsUsageEntry::Offered);
    CHECK(contains(bad, view_row(false)));
    CHECK(contains(bad, "Unknown platform"));
}

namespace {

DexAppsUsageModel mixed_model() {
    auto m = base_model();
    m.apps.push_back(with_rate(matched_app("ledger.exe", 40, 3'600'000, 900), rate_of(5.0 / 70.0, 0.031, 0.1415, 70.0, 4, 1)));
    m.apps.push_back(with_rate(matched_app("tiny.exe", 12, 36'000, 20), rate_of(0.000123456, 0.0001, 0.00015, 7.0, 1, 0, false)));
    m.apps.push_back(with_rate(matched_app("busy.exe", 60, 7'200'000, 50), rate_of(1234.5678, 1200.0, 1300.0, 3.0, 3000, 700)));
    m.apps.push_back(below_app("below.exe"));
    m.apps.push_back(no_usage_app("none.exe"));
    m.apps.push_back(ambiguous_app("inventory-collector-"));
    return m;
}

} // namespace

TEST_CASE("Usage UI: each row equals the REST payload of the same model", "[dex][apps_ui]") {
    const auto model = mixed_model();
    const std::string page = render_dex_apps_usage_fragment(controls_for(), model);
    const auto j = json::parse(dex_apps_usage_json(model));

    for (const auto& a : j["apps"]) {
        const std::string subject = a["subject"].get<std::string>();
        INFO("application " << subject);
        const std::string body = body_of(page, subject);
        if (!a["run_seconds_30d"].is_null()) {
            CHECK(contains(head_row(body), "<span class=\"v\">" + std::to_string(a["devices"].get<std::int64_t>()) + "</span>"));
            CHECK(contains(head_row(body),
                           std::format("{:.1f}", a["run_seconds_30d"].get<double>() / 3600.0) + " h</span>"));
            CHECK(contains(head_row(body), "<td class=\"gp-num\">" + std::to_string(a["launches_30d"].get<std::int64_t>()) + "</td>"));
        }
        if (!a["exposure_rate"].is_null()) {
            // The printed estimate and bounds are the payload's per-hour values, to four significant
            // digits: never rescaled, never collapsed to "<0.1".
            const auto& iv = a["exposure_rate"]["per_hour"];
            CHECK(printed_estimate(body) == Approx(iv["estimate"].get<double>()).epsilon(1e-3));
            const auto [lo, hi] = printed_bounds(body);
            CHECK(std::stod(lo) == Approx(iv["lower"].get<double>()).epsilon(1e-3));
            CHECK(std::stod(hi) == Approx(iv["upper"].get<double>()).epsilon(1e-3));
            const auto crashes = a["exposure_rate"]["crashes"].get<std::int64_t>();
            const auto hangs = a["exposure_rate"]["hangs"].get<std::int64_t>();
            CHECK(contains(body, std::to_string(crashes) + (crashes == 1 ? " crash" : " crashes") + " + " +
                                     std::to_string(hangs) + (hangs == 1 ? " hang" : " hangs") + " over " +
                                     std::format("{:.1f}", a["exposure_rate"]["hours"].get<double>()) + " h in 7d"));
            CHECK_FALSE(contains(body, "&lt;0.1"));
        }
    }
    // Page-level fields sit in the captions.
    CHECK(contains(page, "100 devices online now (all platforms)"));
    CHECK(contains(page, "80 reported usage in the last " + std::to_string(j["freshness_window_hours"].get<int>()) + " hours"));
    CHECK(contains(page, "10 last reported earlier"));
    CHECK(contains(page, "<b>Reporting floor</b> " + std::to_string(j["floor"].get<int>()) + " device,"));
    CHECK(contains(page, "<span class=\"nw\">2023-11-14</span> <span class=\"nw\">22:13:20Z</span>"));
    // The crashes and hangs are per hour, not per 1,000 hours.
    CHECK(contains(page, "Crashes and hangs per hour of use"));
    CHECK_FALSE(contains(page, "1,000 hours"));
    // A small value reads at its own precision.
    CHECK(contains(body_of(page, "tiny.exe"), "<span class=\"v\">0.0001235 "));
    CHECK(contains(body_of(page, "busy.exe"), "<span class=\"v\">1235 "));
}

TEST_CASE("Usage UI: payload key-set parity in both directions (R39)", "[dex][apps_ui]") {
    auto model = mixed_model();
    model.slice.kind = DexUsageSliceKind::Tag;
    model.slice.key = "site";
    model.apps[0].cells = {cell_of(DexUsageCellKind::Named, "hq", 30, 1000, 10),
                           cell_of(DexUsageCellKind::Untagged, "(untagged)", 10, 500, 5)};

    std::set<std::string> published;
    const std::function<void(const json&, const std::string&)> flatten = [&](const json& v, const std::string& prefix) {
        if (v.is_object()) {
            for (const auto& [k, child] : v.items()) {
                const std::string path = prefix.empty() ? k : prefix + "." + k;
                published.insert(path);
                flatten(child, path);
            }
        } else if (v.is_array()) {
            for (const auto& e : v)
                flatten(e, prefix + "[]");
        }
    };
    const auto payload = json::parse(dex_apps_usage_json(model));
    flatten(payload, "");

    std::set<std::string> shown;
    // Page-level: window, platform_scope and slice.* are the lit chips and the Slice caption;
    // population, reporting_devices, stale_devices and freshness_window_hours are the Population
    // caption; basis and as_of the Basis caption; floor and floor_scope the Reporting floor caption.
    for (const char* k : {"window", "platform_scope", "slice", "slice.kind", "slice.key", "as_of", "basis",
                          "freshness_window_hours", "floor", "floor_scope", "population", "reporting_devices",
                          "stale_devices", "apps"})
        shown.insert(k);
    for (const char* k : {"subject", "state", "devices", "run_seconds_30d", "launches_30d", "cells", "exposure_rate",
                          "rate_withheld"})
        shown.insert(std::string("apps[].") + k);
    for (const char* k : {"kind", "label", "devices", "run_seconds_30d", "launches_30d", "small_cohort"})
        shown.insert(std::string("apps[].cells[].") + k);
    for (const char* k : {"per_hour", "per_hour.estimate", "per_hour.lower", "per_hour.upper", "per_hour.reliable",
                          "hours", "crashes", "hangs", "basis"})
        shown.insert(std::string("apps[].exposure_rate.") + k);
    // Every published key is read on the page (a new key fails the first loop, a removed one the second).
    for (const auto& p : published) {
        INFO("payload key '" << p << "' is not read on the page");
        CHECK(shown.count(p) == 1);
    }
    for (const auto& p : shown) {
        INFO("page map names '" << p << "' but the payload no longer carries it");
        CHECK(published.count(p) == 1);
    }

    // The keys that are not figures are bound to where the page reads them.
    const std::string page = render_dex_apps_usage_fragment(controls_for(DexUsageSliceKind::Tag, "site"), model);
    CHECK(payload["floor_scope"] == "per_table");
    CHECK(contains(page, "per table"));
    CHECK(payload["slice"]["kind"] == "tag");
    CHECK(contains(page, dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=all&amp;slice=tag&amp;tag_key=site",
                                       "By tag", true)));
    CHECK(payload["slice"]["key"] == "site");
    CHECK(contains(page, "by tag <code class=\"dx-code\">site</code>"));
    CHECK(payload["basis"] == "estimated_from_30_day_usage");
    CHECK(contains(page, "<span class=\"gp-derived\">estimated from 30-day usage</span>"));
    CHECK(payload["platform_scope"] == "all");
    CHECK(payload["window"] == "7d");
}

TEST_CASE("Usage UI: every withheld state reads in words, never as a number", "[dex][apps_ui]") {
    auto m = base_model();
    m.apps.push_back(below_app("below.exe"));
    m.apps.push_back(no_usage_app("none.exe"));
    m.apps.push_back(ambiguous_app("ambiguous"));
    for (const char* token : {"unbounded_window", "window_exceeds_retention", "zero_usage", "no_statistic"})
        m.apps.push_back(withheld_app(std::string("w-") + token, token));
    m.apps.push_back(withheld_app("odd", "<b>new</b>"));
    const std::string page = render_dex_apps_usage_fragment(controls_for(), m);

    const std::string a = body_of(page, "ambiguous");
    CHECK(contains(a, "withheld: the name is shared"));
    CHECK(contains(a, "first 15 bytes"));
    CHECK_FALSE(contains(a, "at 15 characters"));
    CHECK_FALSE(contains(a, "class=\"v\""));    // no figure of any kind
    CHECK_FALSE(contains(a, "reporting</span>")); // and no device count, so no denominator

    const std::string b = body_of(page, "below.exe");
    CHECK(contains(b, "<span class=\"v\">3</span><span class=\"s nw\">of 80 reporting</span><span class=\"s nw\">count only</span>"));
    CHECK(contains(b, "below the reporting floor"));
    CHECK(contains(b, "not calculated: below the reporting floor"));

    const std::string c = body_of(page, "none.exe");
    CHECK(contains(c, "no reporting device ran it"));
    CHECK(contains(c, "of 80 reporting"));
    CHECK(contains(c, "no usage reported"));
    CHECK(contains(c, "not calculated: no usage reported"));

    CHECK(contains(body_of(page, "w-unbounded_window"), "not calculated: the All window has no length"));
    CHECK(contains(body_of(page, "w-window_exceeds_retention"),
                   "not calculated: the window is longer than the crash and hang history kept"));
    CHECK(contains(body_of(page, "w-zero_usage"), "not calculated: no run time recorded"));
    CHECK(contains(body_of(page, "w-no_statistic"), "not calculated: no statistic for these counts"));
    CHECK(contains(body_of(page, "odd"), "(reason: <code class=\"dx-code\">&lt;b&gt;new&lt;/b&gt;</code>)"));
    CHECK_FALSE(contains(page, "<b>new</b>"));

    // The no_usage wordings by population and by reporting.
    auto reporting_zero = base_model();
    reporting_zero.reporting_devices = 0;
    reporting_zero.stale_devices = 0;
    reporting_zero.apps.push_back(no_usage_app("none.exe"));
    const std::string p0 = render_dex_apps_usage_fragment(controls_for(), reporting_zero);
    const std::string p0_body = body_of(p0, "none.exe");
    CHECK(contains(p0_body, "no device has reported usage"));
    CHECK(contains(p0_body, "not calculated: no device has reported usage"));
    CHECK_FALSE(contains(p0_body, "reporting</span>")); // no count, so no denominator

    auto nobody = base_model();
    nobody.population = 0;
    nobody.reporting_devices = 0;
    nobody.stale_devices = 0;
    nobody.apps.push_back(no_usage_app("none.exe"));
    const std::string pn = render_dex_apps_usage_fragment(controls_for(), nobody);
    CHECK(contains(body_of(pn, "none.exe"), "no device online"));
    CHECK(contains(pn, "0 devices online now (all platforms). Usage needs at least one online device."));
}

TEST_CASE("Usage UI: a non-finite end reads in words, small figures keep their digits", "[dex][apps_ui]") {
    const double inf = std::numeric_limits<double>::infinity();
    const double nan = std::numeric_limits<double>::quiet_NaN();
    auto m = base_model();
    m.apps.push_back(with_rate(matched_app("open.exe", 40, 3'600'000, 10), rate_of(0.5, 0.01, inf, 70.0, 2, 0, false)));
    m.apps.push_back(with_rate(matched_app("noest.exe", 40, 3'600'000, 10), rate_of(nan, 0.0, inf, 70.0, 0, 0, false)));
    m.apps.push_back(with_rate(matched_app("calm.exe", 40, 3'600'000, 10), rate_of(0.0, 0.0, 0.05, 70.0, 0, 0, false)));
    m.apps.push_back(with_rate(matched_app("odd-basis.exe", 40, 3'600'000, 10), [] {
        auto r = rate_of(0.5, 0.4, 0.6, 70.0, 20, 5);
        r.basis = "<i>other</i>";
        return r;
    }()));
    const std::string page = render_dex_apps_usage_fragment(controls_for(), m);

    const std::string open = body_of(page, "open.exe");
    CHECK(contains(open, "no upper bound"));
    CHECK(contains(open, "under 20 events"));
    CHECK(contains(open, "estimated from 30-day usage"));
    for (const char* name : {"open.exe", "noest.exe", "calm.exe"}) {
        CHECK_FALSE(contains(body_of(page, name), "inf"));
        CHECK_FALSE(contains(body_of(page, name), "nan"));
        CHECK(contains(body_of(page, name), "estimated from 30-day usage")); // every rate carries it
    }
    CHECK(contains(body_of(page, "noest.exe"), "<span class=\"v\">no estimate "));
    CHECK(contains(body_of(page, "calm.exe"), "<span class=\"v\">0 "));
    CHECK(contains(body_of(page, "calm.exe"), "(0&ndash;0.05000)"));
    CHECK_FALSE(contains(body_of(page, "calm.exe"), "&lt;0.1"));
    const std::string odd = body_of(page, "odd-basis.exe");
    CHECK(contains(odd, "<span class=\"gp-derived\">&lt;i&gt;other&lt;/i&gt;</span>"));
    CHECK_FALSE(contains(odd, "under 20 events")); // 25 events: reliable
    CHECK_FALSE(contains(odd, "estimated from 30-day usage"));
}

TEST_CASE("Usage UI: cells are keyed on kind and their labels are escaped", "[dex][apps_ui]") {
    auto m = base_model();
    m.slice.kind = DexUsageSliceKind::Tag;
    m.slice.key = "site";
    DexAppUsage a = matched_app("cells.exe", 60, 36'000, 100);
    a.cells = {cell_of(DexUsageCellKind::Named, "other", 20, 1000, 10),
               cell_of(DexUsageCellKind::Named, "(untagged)", 15, 1000, 10),
               cell_of(DexUsageCellKind::Named, "<script>x</script>", 12, 1000, 10, true),
               cell_of(DexUsageCellKind::Named, std::string("rtl\xE2\x80\xAE") + "x", 5, 100, 1),
               cell_of(DexUsageCellKind::Untagged, "(untagged)", 5, 100, 1),
               cell_of(DexUsageCellKind::Other, "other", 3, 100, 1)};
    m.apps.push_back(a);
    const std::string page = render_dex_apps_usage_fragment(controls_for(DexUsageSliceKind::Tag, "site"), m);
    const std::string body = body_of(page, "cells.exe");
    CHECK(contains(body, "<td class=\"dx-indent\">other</td>"));
    CHECK(contains(body, "<td class=\"dx-indent\">(untagged)</td>"));
    CHECK(contains(body, "&lt;script&gt;x&lt;/script&gt;"));
    CHECK_FALSE(contains(body, "<script>"));
    CHECK(contains(body, "rtl&lt;U+202E&gt;x"));
    CHECK(contains(body, "Devices with no value for this tag"));
    CHECK_FALSE(contains(body, "merged")); // floor 1: nothing is merged in
    CHECK(count_of(body, "under 30 devices") == 1);
    CHECK(contains(body, "6 cells"));
    CHECK(contains(body, "<span class=\"s nw\">of all 80 reporting</span>"));
    CHECK(contains(body, "not split by cell"));

    // A platform slice prints platform names; a group slice the group's name, or the escaped id.
    auto p = base_model();
    p.slice.kind = DexUsageSliceKind::Platform;
    DexAppUsage pa = matched_app("plat.exe", 60, 36'000, 100);
    pa.cells = {cell_of(DexUsageCellKind::Named, "windows", 40, 1000, 10), cell_of(DexUsageCellKind::Named, "macos", 15, 100, 1),
                cell_of(DexUsageCellKind::Named, "linux", 5, 100, 1)};
    p.apps.push_back(pa);
    const std::string pb = body_of(render_dex_apps_usage_fragment(controls_for(DexUsageSliceKind::Platform), p), "plat.exe");
    CHECK(contains(pb, "<td class=\"dx-indent\">Windows</td>"));
    CHECK(contains(pb, "<td class=\"dx-indent\">macOS</td>"));
    CHECK(contains(pb, "<td class=\"dx-indent\">Linux</td>"));

    auto g = base_model();
    g.slice.kind = DexUsageSliceKind::Group;
    g.slice.key = "g-1";
    DexAppUsage ga = matched_app("grp.exe", 60, 36'000, 100);
    ga.cells = {cell_of(DexUsageCellKind::Named, "g-1", 40, 1000, 10), cell_of(DexUsageCellKind::Named, "<gone>", 5, 100, 1),
                cell_of(DexUsageCellKind::Other, "other", 15, 100, 1)};
    g.apps.push_back(ga);
    auto gc = controls_for(DexUsageSliceKind::Group, "g-1");
    gc.groups = {{"g-1", "Finance <laptops>"}};
    const std::string gpage = render_dex_apps_usage_fragment(gc, g);
    const std::string gb = body_of(gpage, "grp.exe");
    CHECK(contains(gb, "<td class=\"dx-indent\">Finance &lt;laptops&gt;</td>"));
    CHECK(contains(gb, "<td class=\"dx-indent\">&lt;gone&gt;</td>"));
    CHECK(contains(gpage, "by management group Finance &lt;laptops&gt;"));
}

// The renderer words the residual cell from the slice kind and from floor > 1 alone. Which devices
// land in the cell is the model's job and is pinned in test_dex_usage_model.cpp, so the models here
// are built by hand: one Other-kind cell per slice, at floor 1 and at floor 10.
TEST_CASE("Usage UI: the residual cell is named for what the model puts in it", "[dex][apps_ui]") {
    const std::string merged = "plus cells merged in so that no row is below the reporting floor";
    struct Case {
        DexUsageSliceKind kind;
        const char* key;
        const char* words;
    };
    for (const auto& c : {Case{DexUsageSliceKind::Platform, "", "Devices on a platform other than Windows, Linux or macOS"},
                          Case{DexUsageSliceKind::Group, "g-1", "Devices outside the group"},
                          Case{DexUsageSliceKind::Tag, "site", "Devices whose value is not among the 50 most common"}}) {
        INFO(c.words);
        for (const std::int64_t floor : {1, 10}) {
            auto m = base_model();
            m.slice.kind = c.kind;
            m.slice.key = c.key;
            m.floor = floor;
            DexAppUsage a = withheld_app("res.exe", "zero_usage");
            a.cells = {cell_of(DexUsageCellKind::Other, "other", 5, 3600, 1)};
            m.apps.push_back(a);
            const std::string body = body_of(render_dex_apps_usage_fragment(controls_for(c.kind, c.key), m), "res.exe");
            CHECK(contains(body, c.words));
            if (floor == 1) { // nothing is merged in at floor 1, so the suffix would be false
                CHECK_FALSE(contains(body, "floor"));
                CHECK_FALSE(contains(body, "merged"));
            } else {
                CHECK(contains(body, merged));
            }
        }
    }
}

TEST_CASE("Usage UI: slice controls carry the request and the pane attributes", "[dex][apps_ui]") {
    auto c = controls_for(DexUsageSliceKind::Group, "g-2");
    c.groups = {{"g-1", "Finance & <co>"}, {"g-2", "Eng \"x\""}};
    const std::string page = render_dex_apps_usage_fragment(c, base_model());
    CHECK_FALSE(contains(page, "hx-on"));

    for (const char* chip : {"Whole fleet", "By platform", "By tag"})
        CHECK(contains(page, std::string(chip) + "</button>"));
    CHECK(contains(page, dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=all&amp;slice=fleet", "Whole fleet", false)));
    CHECK(contains(page, dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=all&amp;slice=platform", "By platform", false)));
    CHECK(contains(page, dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=all&amp;slice=tag&amp;tag_key=model", "By tag", false)));
    // Window and platform chips keep the slice and its key.
    CHECK(contains(page, dex_pane_chip("/fragments/dex/apps/usage?window=30d&amp;platform=all&amp;slice=group&amp;group=g-2", "30d", false)));
    CHECK(contains(page, dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=linux&amp;slice=group&amp;group=g-2", "Linux", false)));
    CHECK(contains(page, dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=all&amp;slice=group&amp;group=g-2", "All platforms", true)));

    // The select: escaped names, the active group selected, a disabled placeholder.
    CHECK(contains(page, "<option value=\"g-1\">Finance &amp; &lt;co&gt;</option>"));
    CHECK(contains(page, "<option value=\"g-2\" selected>Eng &quot;x&quot;</option>"));
    CHECK(contains(page, "<option value=\"\" disabled>Choose a group</option>"));
    CHECK(contains(page, "name=\"tag_key\""));
    CHECK(contains(page, "value=\"model\""));

    auto t = controls_for(DexUsageSliceKind::Tag, "a\"b");
    const std::string tpage = render_dex_apps_usage_fragment(t, base_model());
    CHECK(contains(tpage, "value=\"a&quot;b\""));
    CHECK(contains(tpage, "<span class=\"dx-none\">none defined</span>"));
    CHECK_FALSE(contains(tpage, "<select"));
}

TEST_CASE("Usage UI: captions name the population, the basis and the cell denominator", "[dex][apps_ui]") {
    auto m = base_model();
    const std::string page = render_dex_apps_usage_fragment(controls_for(), m);
    CHECK(contains(page, "10 have never reported usage")); // 100 - 80 - 10
    CHECK(contains(page, "Estimated from 30-day usage"));
    CHECK(contains(page, "an answer is reused for up to 30 seconds"));
    CHECK(contains(page, "the rate scales run time to the 7d window"));
    CHECK_FALSE(contains(page, "<b>Slice</b>")); // a fleet read has no slice caption

    m.reporting_devices = 95; // more than population - stale: the never-reported count would be negative
    m.stale_devices = 10;
    CHECK_FALSE(contains(render_dex_apps_usage_fragment(controls_for(), m), "never reported usage"));

    auto all = base_model();
    all.window = "all";
    auto c = controls_for();
    c.window_days = 0;
    const std::string all_page = render_dex_apps_usage_fragment(c, all);
    CHECK(contains(all_page, "The All window has no length, so no rate is calculated"));

    auto sliced = base_model();
    sliced.slice.kind = DexUsageSliceKind::Platform;
    const std::string sliced_page = render_dex_apps_usage_fragment(controls_for(DexUsageSliceKind::Platform), sliced);
    CHECK(contains(sliced_page, "A cell&#39;s device count is read against all 80 reporting devices, not against the "
                                "cell&#39;s own size"));
}

TEST_CASE("Usage UI: every row that prints a device count prints the reporting population", "[dex][apps_ui]") {
    auto m = mixed_model();
    m.slice.kind = DexUsageSliceKind::Platform;
    m.apps[0].cells = {cell_of(DexUsageCellKind::Named, "windows", 30, 1000, 10, false),
                       cell_of(DexUsageCellKind::Named, "linux", 10, 500, 5, true)};
    const std::string page = render_dex_apps_usage_fragment(controls_for(DexUsageSliceKind::Platform), m);

    std::size_t at = 0;
    int heads = 0;
    int cells = 0;
    while ((at = page.find("<tr", at)) != std::string::npos) {
        const std::string row = page.substr(at, page.find("</tr>", at) - at);
        at += 3;
        if (contains(row, "class=\"dx-ver\"")) {
            ++cells;
            CHECK(contains(row, "of all 80 reporting"));
        } else if (contains(row, "dx-apphead")) {
            ++heads;
            INFO(row);
            if (contains(row, "inventory-collector-")) // an ambiguous name prints no count, so no denominator
                CHECK_FALSE(contains(row, "reporting</span>"));
            else
                CHECK(contains(row, "of 80 reporting"));
        }
    }
    CHECK(heads == 6);
    CHECK(cells == 2);
}

TEST_CASE("Usage UI: each refusal draws its own panel and nothing from a model", "[dex][apps_ui]") {
    const auto c = controls_for();
    struct Case {
        const char* reason;
        const char* detail;
        const char* words;
    };
    for (const auto& k : {Case{"invalid_scope", "", "The platform filter must be one of all, windows, macos or linux"},
                          Case{"invalid_slice", "unknown_group", "Unknown management group"},
                          Case{"invalid_slice", "no_group", "Choose a slice"},
                          Case{"invalid_slice", "invalid_tag_key", "needs a valid tag key"},
                          Case{"audit_unavailable", "", "The audit record for this read could not be stored"},
                          Case{"usage_unavailable", "fleet_too_large", "Trying again does not help; only a single platform"},
                          Case{"usage_unavailable", "concurrency_budget", "Usage is busy"},
                          Case{"usage_unavailable", "pool_acquire_timeout", "Usage is busy"},
                          Case{"usage_unavailable", "statement_timeout", "Try again in a moment, or choose a single platform"},
                          Case{"apps_degraded", "query_error", "The application list could not be read"},
                          Case{"group_unavailable", "query_error", "members could not be read"},
                          Case{"tag_unavailable", "", "The tag values could not be read"},
                          Case{"no_population", "", "No fleet source is connected"},
                          Case{"usage_unavailable", "not_wired", "The read could not be completed"}}) {
        INFO(k.reason << "/" << k.detail);
        const std::string page = render_dex_apps_usage_refusal(c, k.reason, k.detail);
        CHECK(contains(page, k.words));
        CHECK_FALSE(contains(page, "<table"));
        CHECK_FALSE(contains(page, "Reporting floor")); // nothing derived from a model
        CHECK_FALSE(contains(page, "<b>Population</b>"));
        CHECK(contains(page, "dx-lbl\">Slice<")); // the chrome and controls are still drawn
        CHECK(contains(page, view_row(true)));
    }
    const std::string timeout = render_dex_apps_usage_refusal(c, "usage_unavailable", "statement_timeout");
    CHECK_FALSE(contains(timeout, "shorter window"));
    const std::string hostile = render_dex_apps_usage_refusal(c, "usage_unavailable", "<script>x</script>");
    CHECK_FALSE(contains(hostile, "<script>"));
    CHECK(contains(hostile, "&lt;script&gt;x&lt;/script&gt;"));
}

TEST_CASE("Usage UI: an empty list and an empty fleet read in words and name no device", "[dex][apps_ui]") {
    auto m = base_model();
    const std::string page = render_dex_apps_usage_fragment(controls_for(), m);
    CHECK(contains(page, "No applications to show usage for"));
    CHECK_FALSE(contains(page, "<table"));
    auto linux_page_controls = controls_for();
    linux_page_controls.platform = "linux";
    m.platform_scope = "linux";
    CHECK(contains(render_dex_apps_usage_fragment(linux_page_controls, m), "crashed or hung on Linux devices in this window"));

    const std::string mixed = render_dex_apps_usage_fragment(controls_for(), mixed_model());
    CHECK_FALSE(contains(mixed, "agent_id"));
    CHECK_FALSE(contains(mixed, "device?id="));
}

TEST_CASE("Usage UI: the worst page stays under its size ceiling", "[dex][apps_ui]") {
    auto m = base_model();
    m.slice.kind = DexUsageSliceKind::Tag;
    m.slice.key = "model";
    for (int i = 0; i < 100; ++i) {
        DexAppUsage a = with_rate(matched_app("application-" + std::to_string(i) + ".exe", 500, 86'400'000, 12345),
                                  rate_of(0.0123456, 0.01, 0.02, 700.0, 9, 4));
        for (int k = 0; k < 50; ++k)
            a.cells.push_back(cell_of(DexUsageCellKind::Named, "Model " + std::to_string(k), 5, 86'400, 120, true));
        a.cells.push_back(cell_of(DexUsageCellKind::Untagged, "(untagged)", 5, 86'400, 120, true));
        a.cells.push_back(cell_of(DexUsageCellKind::Other, "other", 5, 86'400, 120, true));
        m.apps.push_back(a);
    }
    const std::string page = render_dex_apps_usage_fragment(controls_for(DexUsageSliceKind::Tag, "model"), m);
    CHECK(page.size() < 3U * 1024U * 1024U);
}

// ── the route ──

namespace {

struct UsageRead {
    std::string window;
    std::string scope;
    DexUsageSlice slice;
    std::int64_t floor{0};
    std::optional<std::unordered_set<std::string>> visible;
};

struct AuditRow {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct UsageRouteFixture {
    // State first: the closures below capture `this`, and `routes` owns them.
    std::vector<std::string> events; // the order of gates, audit and reads
    std::vector<UsageRead> reads;
    std::vector<AuditRow> audits;
    std::vector<std::pair<std::string, std::string>> apps_reads; // (window, scope) the Stability read saw
    bool permitted = true;
    bool gate_admitted = true;
    int gate_status = 403;
    bool audit_ok = true;
    bool audit_throws = false;
    bool usage_throws = false;
    authz::VisibleSet gate_scope = std::nullopt;
    std::expected<DexAppsUsageModel, DexUsageRefusal> next_usage{base_model()};
    DexAppsModel next_apps = stability_model();
    std::vector<DexGroupOption> groups;
    DexRoutes routes;
    yuzu::server::test::TestRouteSink sink; // after the owner: its handlers capture `routes`

    UsageRouteFixture(const UsageRouteFixture&) = delete;
    UsageRouteFixture& operator=(const UsageRouteFixture&) = delete;

    explicit UsageRouteFixture(bool wire_gate = true, bool wire_api = true) {
        auto okAuth = [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        };
        auto perm = [this](const httplib::Request&, httplib::Response& res, const std::string& securable,
                           const std::string& op) {
            events.push_back("perm:" + securable + ":" + op);
            if (!permitted)
                res.status = 403;
            return permitted;
        };
        auto audit = [this](const httplib::Request&, const std::string& action, const std::string& result,
                            const std::string& target_type, const std::string& target_id,
                            const std::string& detail) -> bool {
            if (audit_throws)
                throw std::runtime_error("audit sink down");
            events.push_back("audit");
            audits.push_back({action, result, target_type, target_id, detail});
            return audit_ok;
        };
        auto fleet = []() { return DexFleet{}; };
        auto group_list = [this]() { return groups; };
        DexRoutes::FleetReadFn gate;
        if (wire_gate)
            gate = [this](const httplib::Request&, httplib::Response& res, const std::string& securable,
                          const std::string& op) {
                events.push_back("gate:" + securable + ":" + op);
                if (!gate_admitted) {
                    res.status = gate_status;
                    return authz::FleetReadGate{.admitted = false};
                }
                return authz::FleetReadGate{.admitted = true, .scope = gate_scope};
            };
        routes.register_routes(sink, okAuth, perm, /*store=*/nullptr, fleet, audit, {}, {}, {}, {}, {}, group_list,
                               gate);
        if (wire_api) {
            auto api = std::make_shared<yuzu::server::test::FnDexApi>(
                yuzu::server::test::FnDexApi::DeviceScoreFn{}, yuzu::server::test::FnDexApi::DeviceHistoryFn{},
                yuzu::server::test::FnDexApi::ObservationFn{}, yuzu::server::test::FnDexApi::AppFn{},
                [this](const std::string& window, const std::string& scope) {
                    apps_reads.emplace_back(window, scope);
                    return next_apps;
                });
            api->set_apps_usage([this](const std::string& window, const std::string& scope, const DexUsageSlice& slice,
                                       std::int64_t floor, const std::optional<std::unordered_set<std::string>>& visible)
                                    -> std::expected<DexAppsUsageModel, DexUsageRefusal> {
                events.push_back("read");
                reads.push_back({window, scope, slice, floor, visible});
                if (usage_throws)
                    throw std::runtime_error("secret-database-detail");
                return next_usage;
            });
            routes.set_dex_api(api);
        }
    }

    std::unique_ptr<httplib::Response> get(const std::string& query = "") {
        return sink.Get("/fragments/dex/apps/usage" + (query.empty() ? std::string() : "?" + query));
    }
};

} // namespace

TEST_CASE("Usage route: both gates, then one audit row, then the read", "[dex][apps_ui]") {
    UsageRouteFixture f;
    f.gate_scope = authz::VisibleSet{std::unordered_set<std::string>{"WS-1"}};
    f.next_usage = mixed_model(); // a model with applications, so the table is drawn
    auto r = f.get("window=30d&platform=linux&slice=tag&tag_key=site");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "class=\"gp-table dx-apps dx-usage\""));
    REQUIRE(f.events.size() == 4);
    CHECK(f.events[0] == "perm:GuaranteedState:Read");
    CHECK(f.events[1] == "gate:Forensics:Read");
    CHECK(f.events[2] == "audit"); // before the read
    CHECK(f.events[3] == "read");
    REQUIRE(f.audits.size() == 1);
    CHECK(f.audits[0].action == "dex.apps.usage.view");
    CHECK(f.audits[0].result == "success");
    CHECK(f.audits[0].target_type == "Forensics");
    CHECK(f.audits[0].target_id.empty());
    CHECK(f.audits[0].detail.starts_with("dashboard DEX fleet application usage read cid="));
    CHECK(contains(f.audits[0].detail, " window=30d platform=linux slice=tag key=site floor=1"));
    REQUIRE(f.reads.size() == 1);
    CHECK(f.reads[0].window == "30d");
    CHECK(f.reads[0].scope == "linux");
    CHECK(f.reads[0].slice.kind == DexUsageSliceKind::Tag);
    CHECK(f.reads[0].slice.key == "site");
    CHECK(f.reads[0].floor == kDexCohortFloor);
    REQUIRE(f.reads[0].visible.has_value());
    CHECK(*f.reads[0].visible == std::unordered_set<std::string>{"WS-1"});
    CHECK(f.apps_reads.empty()); // the Stability model is not read for an admitted caller
}

TEST_CASE("Usage route: without the DEX read permission nothing is read or audited", "[dex][apps_ui]") {
    UsageRouteFixture f;
    f.permitted = false;
    auto r = f.get();
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(f.events == std::vector<std::string>{"perm:GuaranteedState:Read"});
    CHECK(f.audits.empty());
    CHECK(f.reads.empty());
}

TEST_CASE("Usage route: without Forensics read the answer is the Stability page and one line", "[dex][apps_ui]") {
    UsageRouteFixture f;
    f.gate_admitted = false;
    f.gate_status = 403;
    auto r = f.get();
    REQUIRE(r);
    CHECK(r->status == 200); // htmx drops a 4xx body, so the gate's 403 is never forwarded
    CHECK(contains(r->body, "Usage is not shown: it needs the Forensics read permission, which this account does not hold"));
    CHECK(contains(r->body, view_row(false)));
    CHECK(contains(r->body, "ledger.exe"));
    CHECK(f.apps_reads.size() == 1);
    CHECK(f.reads.empty());
    CHECK(f.audits.empty()); // the gate's own denial row is the gate's, not this verb's
}

TEST_CASE("Usage route: a failed or unwired permission check never reaches the read", "[dex][apps_ui]") {
    {
        UsageRouteFixture f;
        f.gate_admitted = false;
        f.gate_status = 503;
        auto r = f.get();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(contains(r->body, "the permission check could not be completed"));
        CHECK(f.reads.empty());
        CHECK(f.audits.empty());
    }
    {
        UsageRouteFixture f(/*wire_gate=*/false);
        auto r = f.get();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(contains(r->body, "the permission check could not be completed"));
        CHECK(f.reads.empty());
        CHECK(f.audits.empty());
    }
}

TEST_CASE("Usage route: a failed audit write fails closed", "[dex][apps_ui]") {
    {
        UsageRouteFixture f;
        f.audit_ok = false;
        auto r = f.get();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(contains(r->body, "The audit record for this read could not be stored"));
        CHECK(f.audits.size() == 1);
        CHECK(f.reads.empty());
    }
    {
        UsageRouteFixture f;
        f.audit_throws = true;
        auto r = f.get();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(contains(r->body, "The audit record for this read could not be stored"));
        CHECK(f.reads.empty());
    }
}

TEST_CASE("Usage route: bad parameters draw a panel, write no audit row and read nothing", "[dex][apps_ui]") {
    struct Case {
        const char* query;
        const char* words;
        const char* hostile; // a value that must never be reflected ("" = none)
    };
    for (const auto& k : {Case{"platform=beos", "Unknown platform", "beos"},
                          Case{"platform=%3Cscript%3E", "Unknown platform", "<script>"},
                          Case{"slice=bogus", "Choose a slice", "bogus"},
                          Case{"slice=group", "Choose a slice", ""},
                          Case{"slice=group&group=", "Choose a slice", ""},
                          Case{"slice=group&group=a%01b", "Choose a slice", "a\x01" "b"},
                          Case{"slice=tag&tag_key=bad%20key", "Choose a slice", "bad key"},
                          Case{"slice=tag&tag_key=%3Cscript%3E", "Choose a slice", "<script>"},
                          Case{"slice=fleet&group=g-1", "Choose a slice", ""},
                          Case{"slice=platform&group=g-1", "Choose a slice", ""},
                          Case{"slice=tag&group=g-1", "Choose a slice", ""},
                          Case{"slice=fleet&tag_key=model", "Choose a slice", ""},
                          Case{"slice=platform&tag_key=model", "Choose a slice", ""},
                          Case{"slice=group&group=g-1&tag_key=model", "Choose a slice", ""}}) {
        INFO(k.query);
        UsageRouteFixture f;
        auto r = f.get(k.query);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(contains(r->body, k.words));
        CHECK_FALSE(contains(r->body, "<table"));
        CHECK(f.audits.empty());
        CHECK(f.reads.empty());
        if (std::string(k.hostile).size() > 0) {
            CHECK_FALSE(contains(r->body, k.hostile));
            CHECK_FALSE(contains(r->body, "&lt;script&gt;")); // never reflected, not even escaped
        }
    }
}

TEST_CASE("Usage route: a control's request, as htmx completes it, reaches the read intact", "[dex][apps_ui]") {
    UsageRouteFixture f;
    f.groups = {{"g-1", "Finance"}, {"g-2", "Engineering"}};
    // Each control is taken from a page where its own parameter is live and not the default, under a
    // non-default window and platform. A URL that pre-carried tag_key or group would pin the old value
    // (the handler reads the first one), and a control that dropped the window or platform would reset it.
    auto tagged = f.get("window=30d&platform=linux&slice=tag&tag_key=site");
    auto grouped = f.get("window=30d&platform=linux&slice=group&group=g-1");
    REQUIRE(tagged);
    REQUIRE(grouped);
    const std::string tag_get = hx_get_after(tagged->body, "name=\"tag_key\"");
    const std::string group_get = hx_get_after(grouped->body, "name=\"group\"");
    f.events.clear();
    f.reads.clear();
    f.audits.clear();

    // htmx appends the control's own name=value to a GET.
    auto by_tag = f.sink.Get(tag_get + "&tag_key=rack");
    REQUIRE(by_tag);
    CHECK(by_tag->status == 200);
    REQUIRE(f.reads.size() == 1);
    CHECK(f.reads[0].window == "30d");
    CHECK(f.reads[0].scope == "linux");
    CHECK(f.reads[0].slice.kind == DexUsageSliceKind::Tag);
    CHECK(f.reads[0].slice.key == "rack");
    REQUIRE(f.audits.size() == 1);
    CHECK(contains(f.audits[0].detail, " window=30d platform=linux slice=tag key=rack "));

    auto by_group = f.sink.Get(group_get + "&group=g-2");
    REQUIRE(by_group);
    CHECK(by_group->status == 200);
    REQUIRE(f.reads.size() == 2);
    CHECK(f.reads[1].window == "30d");
    CHECK(f.reads[1].scope == "linux");
    CHECK(f.reads[1].slice.kind == DexUsageSliceKind::Group);
    CHECK(f.reads[1].slice.key == "g-2");
    REQUIRE(f.audits.size() == 2);
    CHECK(contains(f.audits[1].detail, " window=30d platform=linux slice=group key=g-2 "));
    CHECK(contains(by_group->body, "<option value=\"g-2\" selected>Engineering</option>"));
}

TEST_CASE("Usage route: the two page conventions that differ from REST", "[dex][apps_ui]") {
    UsageRouteFixture f;
    auto r = f.get("window=bogus&floor=9");
    REQUIRE(r);
    CHECK(r->status == 200);
    REQUIRE(f.reads.size() == 1);
    CHECK(f.reads[0].window == "7d"); // an unknown window reads as 7d; REST answers 400
    CHECK(f.reads[0].floor == kDexCohortFloor); // floor is not read; REST accepts it
    REQUIRE(f.audits.size() == 1);
    CHECK(contains(f.audits[0].detail, " window=7d "));
    CHECK(contains(f.audits[0].detail, " floor=1"));
    CHECK_FALSE(contains(f.audits[0].detail, "bogus"));
    CHECK(contains(r->body, dex_pane_chip("/fragments/dex/apps/usage?window=7d&amp;platform=all&amp;slice=fleet", "7d", true)));
}

TEST_CASE("Usage route: a refusal from the API is a 200 panel, the audit row stands", "[dex][apps_ui]") {
    // One case: every refusal takes the same pass-through, and the per-token panels are table-tested
    // above. This panel needs both the reason and the detail, so it also fails if the two are swapped.
    UsageRouteFixture f;
    f.next_usage = std::unexpected(DexUsageRefusal{"usage_unavailable", "fleet_too_large"});
    auto r = f.get();
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "Trying again does not help"));
    CHECK_FALSE(contains(r->body, "<table"));
    CHECK(f.audits.size() == 1); // the row records the admitted request, not the outcome
}

TEST_CASE("Usage route: a throwing API is contained and its text kept out of the page", "[dex][apps_ui]") {
    UsageRouteFixture f;
    f.usage_throws = true;
    auto r = f.get();
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "The read could not be completed"));
    CHECK(contains(r->body, "internal_error"));
    CHECK_FALSE(contains(r->body, "secret-database-detail"));
    CHECK(f.audits.size() == 1);
}

TEST_CASE("Usage route: an unwired API is a words panel with no audit row", "[dex][apps_ui]") {
    UsageRouteFixture f(/*wire_gate=*/true, /*wire_api=*/false);
    auto r = f.get();
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "not_wired"));
    CHECK(f.audits.empty());
    CHECK(f.reads.empty());
}

TEST_CASE("Usage route: omitted parameters take their defaults; the Stability page offers the Usage view", "[dex][apps_ui]") {
    UsageRouteFixture f;
    REQUIRE(f.get());
    REQUIRE(f.reads.size() == 1);
    CHECK(f.reads[0].window == "7d");
    CHECK(f.reads[0].scope == "all");
    CHECK(f.reads[0].slice.kind == DexUsageSliceKind::Fleet);
    CHECK(contains(f.audits[0].detail, " slice=fleet "));

    UsageRouteFixture t;
    REQUIRE(t.get("slice=tag"));
    REQUIRE(t.reads.size() == 1);
    CHECK(t.reads[0].slice.kind == DexUsageSliceKind::Tag);
    CHECK(t.reads[0].slice.key == "model"); // the default tag key

    UsageRouteFixture s;
    auto page = s.sink.Get("/fragments/dex/apps");
    REQUIRE(page);
    CHECK(page->status == 200);
    CHECK(contains(page->body, view_row(false)));
    CHECK(s.reads.empty());
}
