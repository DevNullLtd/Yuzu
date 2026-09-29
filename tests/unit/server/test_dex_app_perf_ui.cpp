/**
 * test_dex_app_perf_ui.cpp — slice-2 DEX app-perf-over-time dashboard renderers.
 *
 * Pure, DB-free coverage of the two HTMX fragment renderers (picker + per-version
 * trend). They render from the SAME reduced model the REST/MCP twins use, so these
 * assert only the presentation invariants the other surfaces can't: the honest
 * empty states, the open-top-bucket "≥" floor, the named-group sub-floor
 * suppression cell + works-council caption, and the CSP-safe scope selector.
 */
#include "app_perf_fleet_store.hpp" // AppPerfAppSummary
#include "dex_app_perf_model.hpp"   // AppPerfVersionSummary, HistPctile
#include "dex_app_perf_ui.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {
bool has(const std::string& h, const std::string& needle) {
    return h.find(needle) != std::string::npos;
}
} // namespace

TEST_CASE("render_dex_app_perf_picker: empty state + populated rows + cap note",
          "[dex][app_perf][ui]") {
    CHECK(has(render_dex_app_perf_picker({}, false, 30), "No application performance history"));

    std::vector<AppPerfAppSummary> apps = {
        {.app_name = "chrome.exe", .versions = 3, .last_day = 1'700'000'000}};
    const auto h = render_dex_app_perf_picker(apps, /*truncated=*/true, 30);
    CHECK(has(h, "chrome.exe"));
    CHECK(has(h, "/fragments/dex/perf/app?app=chrome.exe")); // drill into the trend
    CHECK(has(h, "/api/v1/dex/perf/apps"));                  // truncation points at the REST API
}

TEST_CASE("render_dex_app_perf_picker: top-level tab — subnav + Dashboard back-link",
          "[dex][app_perf][ui]") {
    std::vector<AppPerfAppSummary> apps = {
        {.app_name = "chrome.exe", .versions = 1, .last_day = 1}};
    const auto h = render_dex_app_perf_picker(apps, false, 7);
    CHECK(has(h, "gp-subnav"));
    // "App Performance" is the active tab and a SIBLING of "Performance" — both
    // present, not merged (dex_subnav row #4035's picker guard).
    CHECK(has(h, "class=\"on\" hx-get=\"/fragments/dex/perf/apps"));
    CHECK(has(h, ">Performance<"));
    CHECK(has(h, ">App Performance<"));
    CHECK(has(h, "href=\"/\">&larr; Dashboard</a>")); // top-level convention, not a sub-fragment back-link
}

TEST_CASE("render_dex_app_perf_picker: search filters by name, case-insensitive",
          "[dex][app_perf][ui]") {
    std::vector<AppPerfAppSummary> apps = {
        {.app_name = "Chrome.exe", .versions = 3, .last_day = 100},
        {.app_name = "firefox", .versions = 2, .last_day = 200},
    };
    const auto h = render_dex_app_perf_picker(apps, false, 7, "chr");
    CHECK(has(h, "Chrome.exe"));
    CHECK_FALSE(has(h, "firefox"));
    CHECK(has(h, "1 of 2 application")); // result count line
    CHECK(has(h, "match &quot;chr&quot;"));
    // The search box preserves its OWN value and re-issues with the other
    // params in its hx-get URL (window at minimum) — never a bare route.
    CHECK(has(h, "value=\"chr\""));
}

TEST_CASE("render_dex_app_perf_picker: search yielding nothing is an honest empty "
          "state, never a blank table",
          "[dex][app_perf][ui]") {
    std::vector<AppPerfAppSummary> apps = {{.app_name = "chrome.exe", .versions = 1, .last_day = 1}};
    const auto h = render_dex_app_perf_picker(apps, false, 7, "nonexistent-app-xyz");
    CHECK(has(h, "0 of 1 application"));
    CHECK(has(h, "No applications match"));
    CHECK_FALSE(has(h, "<table"));
}

TEST_CASE("render_dex_app_perf_picker: platform filter is a NAME-SUFFIX heuristic "
          "(.exe = windows), documented as such",
          "[dex][app_perf][ui]") {
    std::vector<AppPerfAppSummary> apps = {
        {.app_name = "Chrome.EXE", .versions = 1, .last_day = 1}, // mixed case suffix
        {.app_name = "sshd", .versions = 1, .last_day = 2},
    };
    const auto win = render_dex_app_perf_picker(apps, false, 7, "", "windows");
    CHECK(has(win, "Chrome.EXE"));
    CHECK_FALSE(has(win, ">sshd<"));

    const auto lin = render_dex_app_perf_picker(apps, false, 7, "", "linux");
    CHECK(has(lin, "sshd"));
    CHECK_FALSE(has(lin, "Chrome.EXE"));

    // The heuristic caveat is rendered honestly, not silently assumed.
    CHECK(has(win, "inferred from the app name"));

    // An unrecognized platform token falls back to "all" (never a 500/empty page).
    const auto bogus = render_dex_app_perf_picker(apps, false, 7, "", "solaris");
    CHECK(has(bogus, "Chrome.EXE"));
    CHECK(has(bogus, "sshd"));
}

TEST_CASE("render_dex_app_perf_picker: sort — last_seen (default), name, versions",
          "[dex][app_perf][ui]") {
    // Three independent rankings (a Latin square) so each sort produces a
    // DIFFERENT row order — a test that happened to share an order across
    // criteria couldn't tell a correct sort from an accidental one.
    //   last_seen desc (by last_day): charlie(300), alpha(200), bravo(100)
    //   name asc:                     alpha, bravo, charlie
    //   versions desc:                bravo(5), alpha(2), charlie(1)
    std::vector<AppPerfAppSummary> apps = {
        {.app_name = "charlie", .versions = 1, .last_day = 300},
        {.app_name = "alpha", .versions = 2, .last_day = 200},
        {.app_name = "bravo", .versions = 5, .last_day = 100},
    };
    auto row_order = [](const std::string& h, std::initializer_list<const char*> names) {
        std::size_t pos = 0;
        for (const char* n : names) {
            const auto p = h.find(n, pos);
            if (p == std::string::npos)
                return false;
            pos = p + 1;
        }
        return true;
    };

    // Default (no sort= given) and the explicit "last_seen" token both mean
    // most-recently-seen first.
    CHECK(row_order(render_dex_app_perf_picker(apps, false, 7), {"charlie", "alpha", "bravo"}));
    CHECK(row_order(render_dex_app_perf_picker(apps, false, 7, "", "", "last_seen"),
                    {"charlie", "alpha", "bravo"}));
    CHECK(row_order(render_dex_app_perf_picker(apps, false, 7, "", "", "name"),
                    {"alpha", "bravo", "charlie"}));
    CHECK(row_order(render_dex_app_perf_picker(apps, false, 7, "", "", "versions"),
                    {"bravo", "alpha", "charlie"}));

    // An unrecognized sort token falls back to the default (last_seen), never a crash.
    CHECK(row_order(render_dex_app_perf_picker(apps, false, 7, "", "", "bogus"),
                    {"charlie", "alpha", "bravo"}));
}

TEST_CASE("render_dex_app_perf_trend: floor pctile, suppression, scope selector",
          "[dex][app_perf][ui]") {
    AppPerfVersionSummary v1;
    v1.version = "124.0";
    v1.latest_day = 200;
    v1.device_count = 12;
    v1.day_count = 2;
    v1.cpu_mean = 6.0;
    v1.cpu_p95 = HistPctile{75.0, true}; // open top bucket → a floor
    v1.ws_mean = 1024LL * 1024 * 1024;   // 1 GB
    v1.cpu_series = {4.0, 6.0};

    AppPerfVersionSummary v2; // a sub-floor group slice → suppressed
    v2.version = "125.0";
    v2.latest_day = 200;
    v2.device_count = 3;
    v2.suppressed = true;

    std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng"}};

    // Fleet scope (group empty): selector present with "Whole fleet" selected.
    const auto fleet = render_dex_app_perf_trend("chrome.exe", {v1, v2}, "", groups, 10, 30);
    CHECK(has(fleet, "chrome.exe"));
    CHECK(has(fleet, "124.0"));
    CHECK(has(fleet, "&ge;"));        // open-top p95 rendered as "≥ value", never exact
    CHECK(has(fleet, "<svg"));        // server-rendered CSP-safe sparkline
    CHECK(has(fleet, "1.0 GB"));      // working-set mean formatted
    CHECK(has(fleet, "n too small")); // v2 suppressed → count only
    CHECK(has(fleet, "name=\"group\""));
    CHECK(has(fleet, ">Whole fleet</option>"));
    CHECK(has(fleet, ">Eng</option>")); // group option (names only — no N+1 count)
    CHECK_FALSE(has(fleet, "hx-on"));   // CSP: no eval-compiled handlers

    // Group scope: subtitle names the group, the works-council floor + the shorter
    // (B1, 31-day) window are both captioned.
    const auto grp = render_dex_app_perf_trend("chrome.exe", {v1}, "g1", groups, 10, 30);
    CHECK(has(grp, "Eng"));
    CHECK(has(grp, "works-council"));
    CHECK(has(grp, "31 days")); // window-divergence disambiguator

    // No versions → honest placeholder, never an empty table.
    CHECK(has(render_dex_app_perf_trend("x", {}, "", groups, 10, 30), "No performance history"));
}

// Pins the exact-key contract for the crash/hang cross-link (Apps tab ↔
// Performance tab): crash identity (process_name) and perf identity (app_name)
// are ALREADY the same canonicalized key at the agent, so the join must be
// byte-identical — never case-folded, never stripped of a ".exe" suffix, never
// a display-name/fuzzy lookup. A mixed-case, ".EXE"-suffixed name is the
// regression trap: any normalization would visibly change the rendered href.
TEST_CASE("render_dex_app_perf_trend: crash/hang cross-link uses the EXACT app-name "
          "key, never normalized",
          "[dex][app_perf][ui]") {
    AppPerfVersionSummary v1;
    v1.version = "1.0";
    v1.latest_day = 1;
    v1.device_count = 5;
    v1.cpu_mean = 1.0;

    std::vector<DexGroupOption> groups;
    const auto h = render_dex_app_perf_trend("MyApp.EXE", {v1}, "", groups, 10, 7);
    CHECK(has(h, "/fragments/dex/app?name=MyApp.EXE&amp;window=7d"));
    CHECK_FALSE(has(h, "myapp.exe")); // no case-fold
    CHECK_FALSE(has(h, "name=MyApp&amp;")); // no .EXE stripping
}

// The `active_version` (filtered) branch had ZERO coverage before this test —
// every prior TEST_CASE calls render_dex_app_perf_trend with the 6-arg form,
// which defaults `active_version` to "" (unfiltered). This exercises the
// filtered banner, the "all versions" back-link's querystring, per-row link
// suppression while filtered, the scope-selector's version-preserving base
// URL, and the filtered-empty-state fallback link.
TEST_CASE("render_dex_app_perf_trend: filtered (active_version set) — banner, "
          "back-link, link suppression, empty-state fallback",
          "[dex][app_perf][ui]") {
    AppPerfVersionSummary v1;
    v1.version = "1.2.0.0";
    v1.latest_day = 200;
    v1.device_count = 12;
    v1.cpu_mean = 6.0;

    SECTION("fleet scope, no group selector (groups={}) — banner + back-link + row "
            "is plain text, not a re-narrowing link") {
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1}, "", {}, 10, 7, "1.2.0.0");
        CHECK(has(h, "Filtered to version"));
        CHECK(has(h, ">1.2.0.0</span>")); // the banner names the active version
        // "all versions" back-link drops `version=`, no group (fleet scope) — the
        // exact querystring `all_qs` builds, as its own `<a hx-get="...">`.
        CHECK(has(h, "<a hx-get=\"/fragments/dex/perf/app?app=chrome.exe&amp;window=7d\" "));
        CHECK(has(h, "all versions"));
        // With no groups, the scope selector doesn't render at all, so the ONLY
        // way this exact qs (app+window+version, no group) could appear is as a
        // per-row narrow-to-version link — which must be absent while filtered:
        // the row renders as plain text instead.
        CHECK_FALSE(has(h, "<a hx-get=\"/fragments/dex/perf/app?app=chrome.exe&amp;window="
                          "7d&amp;version=1.2.0.0\""));
        CHECK(has(h, "<td><span style=\"font-family:var(--mono)\">1.2.0.0</span>"));
    }

    SECTION("groups present — scope-selector hx-get preserves the active version filter") {
        std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng"}};
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1}, "", groups, 10, 7, "1.2.0.0");
        // Anchored on the <select>'s own opening tag so this doesn't depend on
        // the per-row-suppression-while-filtered behaviour asserted elsewhere.
        CHECK(has(h, "<select name=\"group\" hx-get=\"/fragments/dex/perf/app?app=chrome.exe"
                    "&amp;window=7d&amp;version=1.2.0.0\""));
    }

    SECTION("group scope, filtered — back-link preserves group=, drops version=") {
        std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng"}};
        const auto h =
            render_dex_app_perf_trend("chrome.exe", {v1}, "g1", groups, 10, 7, "1.2.0.0");
        CHECK(has(h, "<a hx-get=\"/fragments/dex/perf/app?app=chrome.exe&amp;window=7d&amp;"
                    "group=g1\" "));
    }

    SECTION("filtered to a version with NO matching rows -> empty-state fallback link "
            "preserves group=") {
        std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng"}};
        const auto h = render_dex_app_perf_trend("chrome.exe", {}, "g1", groups, 10, 7, "9.9.9.9");
        CHECK(has(h, "No performance history"));
        // The empty-state fallback link specifically (not the top filtered-banner
        // link, which renders unconditionally before the versions.empty() check
        // and would satisfy a bare `hx-get` substring check on its own): anchor
        // on its distinct "&larr; all versions" display text, which only the
        // empty-state block emits (the banner's back-link reads "all versions
        // &rarr;" — opposite arrow, opposite word order).
        CHECK(has(h, "&amp;group=g1\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                    "style=\"cursor:pointer;\">&larr; all versions</a>"));
    }
}

// The device-model cohort filter (F2c): a SECOND named-scope selector,
// independent of and mutually exclusive with the management-group one above.
TEST_CASE("render_dex_app_perf_trend: device-model cohort filter — selector, "
          "header, floor wording, devices-cell suppression",
          "[dex][app_perf][ui]") {
    AppPerfVersionSummary v1;
    v1.version = "124.0";
    v1.latest_day = 200;
    v1.device_count = 4;
    v1.cpu_mean = 3.0;

    AppPerfVersionSummary v2; // sub-floor cohort slice → suppressed
    v2.version = "125.0";
    v2.latest_day = 200;
    v2.device_count = 2;
    v2.suppressed = true;

    std::vector<DexGroupOption> groups; // no management groups on this server
    std::vector<std::string> models = {"Latitude 5420", "OptiPlex 7090"};

    SECTION("no model selected — selector present, 'Whole fleet' selected, no cohort "
            "wording") {
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1}, "", groups, 10, 30, "",
                                                  models, "");
        CHECK(has(h, "name=\"model\""));
        CHECK(has(h, ">Whole fleet</option>"));
        CHECK(has(h, ">Latitude 5420</option>"));
        CHECK(has(h, ">OptiPlex 7090</option>"));
        CHECK(has(h, "the whole fleet"));
        CHECK_FALSE(has(h, "named cohort"));
        CHECK_FALSE(has(h, "hx-on")); // CSP
    }

    SECTION("model selected — header names it, floor caption says 'device model', "
            "sub-floor row still suppressed, devices-cell affordance omitted (v1 gap)") {
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1, v2}, "", groups, 10, 30, "",
                                                  models, "Latitude 5420");
        CHECK(has(h, "selected>Latitude 5420</option>"));
        CHECK(has(h, "devices modeled Latitude 5420"));
        CHECK(has(h, "named cohort of specific devices"));
        CHECK(has(h, "(device model)"));
        CHECK(has(h, "n too small")); // v2 still floors
        // Fleet-only devices-cell affordance must NOT appear for a model cohort
        // (same v1 gap as the management-group scope).
        CHECK_FALSE(has(h, "&#9656; devices"));
    }

    SECTION("model selected — per-row narrow link carries model=, not group=") {
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1}, "", groups, 10, 30, "",
                                                  models, "Latitude 5420");
        CHECK(has(h, "&amp;model=Latitude%205420"));
        CHECK_FALSE(has(h, "&amp;group="));
    }

    SECTION("both group and model supplied — group wins (mutual exclusion), no model "
            "wording") {
        std::vector<DexGroupOption> g = {{.id = "g1", .name = "Eng"}};
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1}, "g1", g, 10, 30, "", models,
                                                  "Latitude 5420");
        CHECK(has(h, "Eng"));
        CHECK_FALSE(has(h, "devices modeled"));
    }

    SECTION("no model values available — selector omitted, honest disclosure note shown "
            "instead (#4857 D1: fleet_snapshot has no degrade channel)") {
        const auto h =
            render_dex_app_perf_trend("chrome.exe", {v1}, "", groups, 10, 30, "", {}, "");
        CHECK_FALSE(has(h, "name=\"model\""));
        CHECK(has(h, "no device-model values in the current fleet snapshot"));
        CHECK_FALSE(has(h, "degraded"));
    }

    SECTION("model cohort with zero versions — honest empty state names the model scope") {
        const auto h = render_dex_app_perf_trend("chrome.exe", {}, "", groups, 10, 30, "", models,
                                                  "Latitude 5420");
        CHECK(has(h, "No device of this model reported"));
    }
}

TEST_CASE("render_dex_device_app_perf: empty state", "[dex][app_perf][ui]") {
    const auto h = render_dex_device_app_perf({});
    CHECK(has(h, "No application performance history for this device"));
    CHECK(has(h, "procperf_enabled")); // names the opt-in so the empty state isn't read as a bug
}

TEST_CASE("render_dex_device_app_perf: single-version app collapses to one row",
          "[dex][app_perf][ui]") {
    AppPerfDeviceVersion v;
    v.version = "3.2.1";
    v.latest_day = 300;
    v.day_count = 5;
    v.instances_max = 2;
    v.cpu_avg = 2.1;
    v.cpu_max = 7.0;
    v.ws_avg = 1024LL * 1024 * 1024; // 1 GB
    v.ws_max = 2LL * 1024 * 1024 * 1024;
    v.cpu_series = {2.0, 2.2, 2.1};
    AppPerfDeviceApp app;
    app.app_name = "AcmeCRM.exe";
    app.latest_day = 300;
    app.peak_cpu_avg = 2.1;
    app.versions = {v};

    const auto h = render_dex_device_app_perf({app});
    CHECK(has(h, "AcmeCRM.exe"));
    CHECK(has(h, "3.2.1"));      // version inline on the combined row
    CHECK(has(h, "2.1%"));       // avg CPU
    CHECK(has(h, "1.0 GB"));     // avg working set formatted
    CHECK(has(h, "<svg"));       // CSP-safe server-rendered sparkline
    CHECK(has(h, "central store")); // foot explains the retained-daily source
    CHECK(has(h, "crashes/hangs are deferred")); // deferred join is noted, not greyed
    CHECK_FALSE(has(h, "per-version below")); // single version → no app header row
    CHECK_FALSE(has(h, "hx-on"));             // CSP: no eval-compiled handlers
}

TEST_CASE("render_dex_device_app_perf: multi-version app shows header + latest tag",
          "[dex][app_perf][ui]") {
    AppPerfDeviceVersion newer;
    newer.version = "125.0";
    newer.latest_day = 300;
    newer.cpu_avg = 12.4;
    newer.cpu_series = {9.0, 12.4};
    AppPerfDeviceVersion older;
    older.version = "124.0";
    older.latest_day = 200;
    older.cpu_avg = 4.1;
    older.cpu_series = {4.0, 4.1};
    AppPerfDeviceApp app;
    app.app_name = "chrome.exe";
    app.latest_day = 300;
    app.peak_cpu_avg = 12.4;
    app.versions = {newer, older}; // already newest-first (as the reducer emits)

    const auto h = render_dex_device_app_perf({app});
    CHECK(has(h, "2 versions"));   // app header row for a multi-version app
    CHECK(has(h, "per-version below"));
    CHECK(has(h, "125.0"));
    CHECK(has(h, "124.0"));
    CHECK(has(h, "latest")); // tagged by max-latest_day equality, not row position
    CHECK(has(h, "12.4%"));
    CHECK(has(h, "4.1%"));
}

TEST_CASE("render_dex_device_app_perf: a day-tie tags both newest versions",
          "[dex][app_perf][ui]") {
    // The "latest" cue is by day-EQUALITY (max latest_day), not row position — so two
    // versions seen on the same most-recent day are both tagged honestly. This is the
    // property the day-equality fix protects (a position-based tag would tag only one).
    AppPerfDeviceVersion a;
    a.version = "2.0";
    a.latest_day = 300;
    a.cpu_avg = 5.0;
    a.cpu_series = {5.0, 5.0};
    AppPerfDeviceVersion b;
    b.version = "1.0";
    b.latest_day = 300; // same day as a
    b.cpu_avg = 4.0;
    b.cpu_series = {4.0, 4.0};
    AppPerfDeviceApp app;
    app.app_name = "tie.exe";
    app.latest_day = 300;
    app.peak_cpu_avg = 5.0;
    app.versions = {a, b};

    const auto h = render_dex_device_app_perf({app});
    // Two "latest" tags — one per version on the tied newest day.
    std::size_t n = 0, pos = 0;
    while ((pos = h.find("latest", pos)) != std::string::npos) {
        ++n;
        pos += 6;
    }
    CHECK(n == 2);
}

// The version-row "which devices" click-to-expand affordance: fleet-wide ONLY
// (never on a group-scoped trend, which does not yet narrow the drill to the
// group's own members — see dex_routes.cpp's registration comment), CSP-safe
// (hx-get/hx-target/hx-trigger, never hx-on), and present even for the
// "(no version)" bucket (version="" is unambiguous on this route, unlike the
// trend's own version-filter link).
TEST_CASE("render_dex_app_perf_trend: version-devices click-to-expand affordance",
          "[dex][app_perf][ui]") {
    AppPerfVersionSummary v1;
    v1.version = "124.0.0.0";
    v1.latest_day = 200;
    v1.device_count = 12;
    v1.cpu_mean = 6.0;

    AppPerfVersionSummary unknown; // Linux's "(no version)" bucket
    unknown.version = "";
    unknown.latest_day = 200;
    unknown.device_count = 4;
    unknown.cpu_mean = 3.0;

    SECTION("fleet scope: affordance present, targets the clicked row, CSP-safe") {
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1}, "", {}, 10, 7);
        CHECK(has(h, "/fragments/dex/perf/app/devices?app=chrome.exe&amp;version=124.0.0.0"));
        CHECK(has(h, "hx-target=\"closest tr\""));
        CHECK(has(h, "hx-swap=\"afterend\""));
        CHECK(has(h, "hx-trigger=\"click once\""));
        CHECK_FALSE(has(h, "hx-on")); // CSP: no eval-compiled handlers
    }

    SECTION("the unknown-version (\"\") bucket also gets the affordance") {
        const auto h = render_dex_app_perf_trend("linuxapp", {unknown}, "", {}, 10, 7);
        CHECK(has(h, "/fragments/dex/perf/app/devices?app=linuxapp&amp;version="));
    }

    SECTION("group scope: affordance is OMITTED (v1 does not narrow the drill to the group)") {
        std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng"}};
        const auto h = render_dex_app_perf_trend("chrome.exe", {v1}, "g1", groups, 10, 7);
        CHECK_FALSE(has(h, "/fragments/dex/perf/app/devices"));
    }

    SECTION("a suppressed (sub-floor group) row never gets the affordance either") {
        AppPerfVersionSummary suppressed;
        suppressed.version = "125.0";
        suppressed.latest_day = 200;
        suppressed.device_count = 3;
        suppressed.suppressed = true;
        std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng"}};
        const auto h = render_dex_app_perf_trend("chrome.exe", {suppressed}, "g1", groups, 10, 7);
        CHECK_FALSE(has(h, "/fragments/dex/perf/app/devices"));
    }
}

TEST_CASE("render_dex_app_perf_version_devices: empty state, populated rows, truncation note",
          "[dex][app_perf][ui]") {
    // Empty: an honest COMBINED explanation (top-N never named it, OR the
    // per-device 31-day retention aged out even though the 180-day trend still
    // shows it) — never a bare "no data".
    const auto empty = render_dex_app_perf_version_devices({}, false);
    CHECK(has(empty, "top-N"));
    CHECK(has(empty, "31-day"));
    CHECK(has(empty, "180 days"));

    AppPerfVersionDeviceRow d1;
    d1.agent_id = "agent-hi";
    d1.last_day = 1'700'000'000;
    d1.samples = 10;
    d1.cpu_avg = 42.5;
    d1.ws_avg_bytes = 1024LL * 1024 * 500; // 500 MB

    const auto h = render_dex_app_perf_version_devices({d1}, /*truncated=*/false);
    CHECK(has(h, "agent-hi"));
    CHECK(has(h, "42.5%"));
    CHECK(has(h, "500 MB"));
    CHECK(has(h, "not a full inventory")); // top-N caveat always present
    CHECK_FALSE(has(h, "capped"));

    const auto trunc = render_dex_app_perf_version_devices({d1}, /*truncated=*/true);
    CHECK(has(trunc, "capped"));
    CHECK(has(trunc, "highest-CPU"));
}
