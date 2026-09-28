/**
 * test_dex_dashboard_golden.cpp — CHARACTERIZATION ("golden") tests pinning the
 * exact rendered HTML of the ten /dex dashboard fragment renderers + the
 * /fragments/dex/observation route + dex_device_score's value, BEFORE the
 * WS-A4 DexApi seam rewire (PR-1 of the /dex dashboard -> DexApi ladder).
 * Mirrors PR #4860's 873a58ccc (`test_device_lens_routes.cpp`'s device-lens
 * characterization): seed helpers are MIRRORED (copied, not shared) from
 * test_dex_routes.cpp's `seed_signal`/`seed_crash`/`seed_hang` — each caller
 * in this ladder wants a slightly different subset of fields and its own
 * fixture shape, so a shared helper would just grow parameters no single test
 * needs. Assertions are targeted `find()` substrings anchored on distinctive,
 * derived markup (exact table rows, tile numbers, tone classes, suppressed-
 * score markers) rather than a single whole-body literal — full-body equality
 * is used only where the renderer's output is a short, deterministic
 * placeholder or a pure (non-store) template.
 *
 * NO PRODUCTION CODE CHANGES here — this file exists so PR-2's renderer
 * rewire (onto DexApi models) can be checked against these assertions
 * UNCHANGED, with one deliberate, DISCLOSED exception: the "every listed
 * device is out of the caller's scope" case for the signal-detail / app /
 * overview device tables currently renders an EMPTY `<tbody>` (the existing
 * per-row `visible` filter drops every row but the table shell was already
 * built) rather than an honest "no data" placeholder — an existence-oracle
 * leak PR-2 intentionally closes. Every such case below is tagged
 * "PR-2 DELTA" in its test name/comment so the later diff against these
 * assertions is reviewable, not a silent green-to-green flip.
 *
 * Time-dependence: every renderer computes `since` from the wall clock via
 * `dex_iso_since`/`dex_window_to_days`. Seed timestamps are anchored RELATIVE
 * TO NOW (via the local `iso_ago` helper below, mirroring dex_routes.cpp's own
 * `iso_days_ago` algorithm at minute/day granularity) rather than a fixed
 * calendar date, so the fixture never ages out of the 24h/7d/"all" windows
 * exercised here (cf. test_dex_routes.cpp's kDayA/kDayB comment, #the
 * 2026-06-15 window-drift lesson). The expected HTML embeds the SAME
 * variable used to seed the timestamp (never a re-computed wall-clock read at
 * assertion time), so there is no clock-race between seed and assert.
 */
#include "dex_routes.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstring>
#include <ctime>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template — mirrors test_dex_routes.cpp's own `guardian_pg_tpl`
// (kept as a separate instance per that file's own convention: each test file
// owns its template object).
yuzu::test::PgTestTemplate golden_pg_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

// ── Seed helpers — mirrored (not shared) from test_dex_routes.cpp's
// seed_signal/seed_crash/seed_hang, verbatim shape. ──
void seed_signal(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                 const std::string& type, const std::string& detail_json, const std::string& ts) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = type;
    e.severity = "info";
    e.detail_json = detail_json;
    e.timestamp = ts;
    REQUIRE(store.insert_event(e));
}

void seed_crash(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                const std::string& proc, const std::string& mod, const std::string& plat,
                const std::string& ts) {
    seed_signal(store, id, agent, "process.crashed",
                "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\","
                "\"symbolic\":\"ACCESS_VIOLATION\",\"component\":\"" + mod +
                "\",\"platform\":\"" + plat + "\"}",
                ts);
}

void seed_hang(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
               const std::string& proc, const std::string& ts) {
    seed_signal(store, id, agent, "process.hung",
                "{\"subject\":\"" + proc + "\",\"symbolic\":\"NOT_RESPONDING\","
                "\"platform\":\"windows\"}",
                ts);
}

// ISO-8601 UTC timestamp `dur` before *now* — mirrors dex_routes.cpp's own
// (file-local) `iso_days_ago`, but at arbitrary `std::chrono::duration`
// granularity so a fixture can place one event WITHIN the 24h window and
// another OUTSIDE it (iso_days_ago only offers whole-day granularity, too
// coarse to straddle that boundary deterministically).
std::string iso_ago(std::chrono::seconds dur) {
    const auto t = std::chrono::system_clock::now() - dur;
    std::time_t tt = std::chrono::system_clock::to_time_t(t);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// Anchors: one event 30 minutes ago (inside EVERY window, incl. 24h), one 3
// days ago (inside "7d"/"all", OUTSIDE "24h"). Computed once so every seed +
// assertion in this file agrees on the exact same literal timestamps.
const std::string kRecent = iso_ago(std::chrono::minutes(30));
const std::string kOld = iso_ago(std::chrono::hours(24 * 3));

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// 1. render_dex_catalogue_fragment — window 24h/all x os all/linux
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: catalogue fragment — null store placeholder", "[dex][golden]") {
    CHECK(render_dex_catalogue_fragment(nullptr, "", 7, DexFleet{}, "all") ==
         "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal observation store "
         "is not open.</div>");
}

TEST_CASE("DEX golden: catalogue fragment — App reliability card, window x os matrix",
          "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // D1 crashes twice (app1.exe): once recent (in every window), once old
    // (7d/all only). D2 hangs once (app2.exe), recent. Both windows-only-D1
    // and both-devices distinct-device counts stay 1 per signal type in
    // EITHER window, so the family's health score is window-INVARIANT here
    // (scored on device-radius, not event count) — only the event COUNT in
    // the card's "top signal" caption moves between windows.
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_hang(store, "h1", "dex-gold-2", "app2.exe", kRecent);

    DexFleet fleet;
    fleet.windows_online = 2;
    fleet.connected_os = {"windows"};

    // os=all, window=all: 3 App-reliability events (2 crashed + 1 hung),
    // max_signal_devices=1 (both signal types hit exactly 1 device) ->
    // deduction 12*1.0*(1/2)=6.0 -> score 94 ("ok").
    {
        const auto html = render_dex_catalogue_fragment(&store, "", 0, fleet, "all");
        CHECK(html.find("<div class=\"fn\">App reliability<span class=\"cnt\">12 of 12 "
                        "monitored</span></div><div class=\"fev ok\">94</div><div "
                        "class=\"fmeta\">health score</div><div class=\"ftop\"><b>App crash</b> "
                        "&middot; 3 events</div>") != std::string::npos);
    }
    // os=all, window=24h: only the recent crash + the hang are in-window (2
    // events); the score is UNCHANGED (94) since device-radius is unaffected.
    {
        const auto html =
            render_dex_catalogue_fragment(&store, dex_iso_since(1), 1, fleet, "all");
        CHECK(html.find("<div class=\"fn\">App reliability<span class=\"cnt\">12 of 12 "
                        "monitored</span></div><div class=\"fev ok\">94</div><div "
                        "class=\"fmeta\">health score</div><div class=\"ftop\"><b>App crash</b> "
                        "&middot; 2 events</div>") != std::string::npos);
    }
    // os=linux: no platform-tagged-"linux" events exist (everything above was
    // seeded platform=windows) and fleet.linux_online=0 -> the "no online
    // agents reporting" (no_data) branch: monitored (2 of the family's 12
    // types ARE Linux-collectible: process.crashed/process.hung) but
    // unscoreable. Window doesn't matter (0 either way).
    {
        const auto html = render_dex_catalogue_fragment(&store, "", 0, fleet, "linux");
        CHECK(html.find("<div class=\"fn\">App reliability<span class=\"cnt\">2 of 12 "
                        "monitored</span></div><div class=\"fev\">&mdash;</div><div "
                        "class=\"fmeta\">no online agents reporting</div><div class=\"ftop\">"
                        "monitored, but no device is online to report</div>") !=
             std::string::npos);
    }
    {
        const auto html =
            render_dex_catalogue_fragment(&store, dex_iso_since(1), 1, fleet, "linux");
        CHECK(html.find("<div class=\"fn\">App reliability<span class=\"cnt\">2 of 12 "
                        "monitored</span></div><div class=\"fev\">&mdash;</div><div "
                        "class=\"fmeta\">no online agents reporting</div><div class=\"ftop\">"
                        "monitored, but no device is online to report</div>") !=
             std::string::npos);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. render_dex_catalogue_group_fragment — window 24h/all x os all/linux
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: catalogue group fragment — null store placeholder", "[dex][golden]") {
    CHECK(render_dex_catalogue_group_fragment(nullptr, "", 7, "App reliability", DexFleet{},
                                              "all") ==
         "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal observation store "
         "is not open.</div>");
}

TEST_CASE("DEX golden: catalogue group fragment — App reliability drill-down, window x os matrix",
          "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_hang(store, "h1", "dex-gold-2", "app2.exe", kRecent);

    DexFleet fleet;
    fleet.windows_online = 2;
    fleet.connected_os = {"windows"};

    // os=all, window=all.
    {
        const auto html =
            render_dex_catalogue_group_fragment(&store, "", 0, "App reliability", fleet, "all");
        CHECK(html.find("<b>12</b> of 12 types <b>monitored</b> across your connected platforms "
                        "&middot; 2 active in this window.") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n ok\">94</div><div "
                        "class=\"l\">Health score</div><div class=\"sx\">100 &minus; "
                        "deduction</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n info\">12 of 12</div><div "
                        "class=\"l\">Monitored</div><div class=\"sx\">on your fleet</div></div>") !=
             std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">3</div><div "
                        "class=\"l\">Events (window)</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n \">1</div><div class=\"l\">Peak "
                        "signal devices</div><div class=\"sx\">largest single signal</div></div>") !=
             std::string::npos);
        CHECK(html.find("<tr hx-get=\"/fragments/dex/catalogue/signal?type=process.crashed&"
                        "window=all&os=all\" hx-target=\"#guardian-detail\" "
                        "hx-swap=\"innerHTML\" style=\"cursor:pointer\"><td>App crash</td><td>"
                        "<span class=\"gp-pill dep\">monitored</span> <span class=\"gp-mute\">"
                        "Windows</span></td><td class=\"gp-num\">2</td><td class=\"gp-num\">1</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
        CHECK(html.find("<tr hx-get=\"/fragments/dex/catalogue/signal?type=process.hung&"
                        "window=all&os=all\" hx-target=\"#guardian-detail\" "
                        "hx-swap=\"innerHTML\" style=\"cursor:pointer\"><td>App hang</td><td>"
                        "<span class=\"gp-pill dep\">monitored</span> <span class=\"gp-mute\">"
                        "Windows</span></td><td class=\"gp-num\">1</td><td class=\"gp-num\">1</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
        // One representative "monitored, quiet" watched row.
        CHECK(html.find("<tr class=\"gp-mute\" hx-get=\"/fragments/dex/catalogue/signal?"
                        "type=process.crashed_managed&window=all&os=all\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer\"><td>App crash (.NET)</td><td><span "
                        "class=\"gp-pill dep\">monitored</span> <span class=\"gp-mute\">Windows"
                        "</span></td><td class=\"gp-num\">0</td><td class=\"gp-num\">&mdash;</td>"
                        "<td>watched</td></tr>") != std::string::npos);
    }
    // os=all, window=24h — the two counts drop to 1 each (the old crash ages
    // out); the score stays 94 (device-radius unchanged), last_seen unchanged
    // (kRecent is the newest in EITHER window).
    {
        const auto html = render_dex_catalogue_group_fragment(&store, dex_iso_since(1), 1,
                                                               "App reliability", fleet, "all");
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n ok\">94</div>") !=
             std::string::npos);
        CHECK(html.find("<tr hx-get=\"/fragments/dex/catalogue/signal?type=process.crashed&"
                        "window=24h&os=all\" hx-target=\"#guardian-detail\" "
                        "hx-swap=\"innerHTML\" style=\"cursor:pointer\"><td>App crash</td><td>"
                        "<span class=\"gp-pill dep\">monitored</span> <span class=\"gp-mute\">"
                        "Windows</span></td><td class=\"gp-num\">1</td><td class=\"gp-num\">1</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
    }
    // os=linux: only process.crashed/process.hung are monitored (2 of 12);
    // no linux-platform events exist -> the health-score tile is OMITTED
    // entirely (score<0), a different shape from the catalogue card's
    // "&mdash;" marker.
    {
        const auto html =
            render_dex_catalogue_group_fragment(&store, "", 0, "App reliability", fleet, "linux");
        CHECK(html.find("<b>2</b> of 12 types <b>monitored</b> on linux &middot; 0 active in "
                        "this window.") != std::string::npos);
        // The score tile's LABEL div is omitted (score<0); "Health score" as
        // bare text still appears once, in the shared dex_subnav tab label
        // ("Overview · Apps · Catalogue · Health score · Trends · ..."),
        // which is unconditional chrome, not the tile.
        CHECK(html.find("<div class=\"l\">Health score</div>") == std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n info\">2 of 12</div><div "
                        "class=\"l\">Monitored</div><div class=\"sx\">on linux</div></div>") !=
             std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n \">0</div><div "
                        "class=\"l\">Events (window)</div></div>") != std::string::npos);
        CHECK(html.find("<tr class=\"gp-mute\" hx-get=\"/fragments/dex/catalogue/signal?"
                        "type=process.crashed&window=all&os=linux\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer\"><td>App crash</td><td><span "
                        "class=\"gp-pill dep\">monitored</span> <span class=\"gp-mute\">Linux"
                        "</span></td><td class=\"gp-num\">0</td><td class=\"gp-num\">&mdash;</td>"
                        "<td>watched</td></tr>") != std::string::npos);
        CHECK(html.find("<tr class=\"gp-mute\" hx-get=\"/fragments/dex/catalogue/signal?"
                        "type=process.crashed_managed&window=all&os=linux\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;opacity:.5\"><td>App crash (.NET)</td><td>"
                        "<span class=\"gp-pill draft\">not collected on linux</span></td>"
                        "<td class=\"gp-num\">&mdash;</td><td class=\"gp-num\">&mdash;</td>"
                        "<td>&mdash;</td></tr>") != std::string::npos);
    }
}

TEST_CASE("DEX golden: catalogue group fragment — unknown family name", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    CHECK(render_dex_catalogue_group_fragment(&store, "", 7, "No Such Family", DexFleet{}, "all") ==
         "<div class=\"gp-placeholder\"><b>Unknown family</b>No such signal family: No Such "
         "Family</div>");
}

// ─────────────────────────────────────────────────────────────────────────
// 3. render_dex_catalogue_signal_fragment — window x os x visible matrix,
//    including the all-out-of-scope PR-2 DELTA case.
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: catalogue signal fragment — null store placeholder", "[dex][golden]") {
    CHECK(render_dex_catalogue_signal_fragment(nullptr, "", 7, "process.crashed") ==
         "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal observation store "
         "is not open.</div>");
}

TEST_CASE("DEX golden: catalogue signal fragment — process.crashed drill-down, full matrix",
          "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // Same subject on both devices so the subjects table collapses to one row.
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_crash(store, "c3", "dex-gold-2", "app1.exe", "ntdll.dll", "windows", kRecent);

    // os=all, window=all, visible=nullptr: both devices' rows present.
    {
        const auto html = render_dex_catalogue_signal_fragment(&store, "", 0, "process.crashed");
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">3</div><div class=\"l\">"
                        "Events (window)</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n \">2</div><div class=\"l\">"
                        "Devices affected</div></div>") != std::string::npos);
        // process.crashed is collected on all three platforms (dex_obs_platforms).
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n info\">Windows + Linux + macOS"
                        "</div><div class=\"l\">Collected on</div><div class=\"sx\">cross-OS "
                        "signal</div></div>") != std::string::npos);
        CHECK(html.find("<tr><td>app1.exe</td><td class=\"gp-num\">3</td><td class=\"gp-num\">2"
                        "</td><td class=\"gp-mute\">" + kRecent + "</td></tr>") !=
             std::string::npos);
        CHECK(html.find("<tr><td>windows</td><td class=\"gp-num\">3</td><td class=\"gp-num\">2"
                        "</td></tr>") != std::string::npos);
        CHECK(html.find("<tr><td>dex-gold-1</td><td class=\"gp-num\">2</td><td class=\"gp-mute\">" +
                        kRecent + "</td></tr>") != std::string::npos);
        CHECK(html.find("<tr><td>dex-gold-2</td><td class=\"gp-num\">1</td><td class=\"gp-mute\">" +
                        kRecent + "</td></tr>") != std::string::npos);
    }
    // window=24h: the old crash ages out (events 3->2), device count unchanged.
    {
        const auto html =
            render_dex_catalogue_signal_fragment(&store, dex_iso_since(1), 1, "process.crashed");
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">2</div><div class=\"l\">"
                        "Events (window)</div></div>") != std::string::npos);
        CHECK(html.find("<tr><td>dex-gold-1</td><td class=\"gp-num\">1</td><td class=\"gp-mute\">" +
                        kRecent + "</td></tr>") != std::string::npos);
        CHECK(html.find("<tr><td>dex-gold-2</td><td class=\"gp-num\">1</td><td class=\"gp-mute\">" +
                        kRecent + "</td></tr>") != std::string::npos);
    }
    // os=linux: no linux-platform events -> the devices/subjects lists are
    // empty -> the "No data" placeholders (a different code path from the
    // visible-filter case below).
    {
        const auto html =
            render_dex_catalogue_signal_fragment(&store, "", 0, "process.crashed", "linux");
        CHECK(html.find("<div class=\"gp-placeholder\"><b>No data</b>No events for this signal "
                        "in the window.</div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-placeholder\"><b>No data</b>No devices reported this "
                        "signal in the window.</div>") != std::string::npos);
    }
    // visible = proper subset (dex-gold-1 only): dex-gold-2's row is dropped,
    // dex-gold-1's stays — the table shell + the surviving row both render.
    {
        std::set<std::string> visible{"dex-gold-1"};
        const auto html =
            render_dex_catalogue_signal_fragment(&store, "", 0, "process.crashed", "all", &visible);
        CHECK(html.find("<tr><td>dex-gold-1</td>") != std::string::npos);
        CHECK(html.find("dex-gold-2") == std::string::npos);
    }
    // PR-2 DELTA: visible = a set containing NEITHER listed device. Every row
    // is dropped by the per-row filter, but `devices` was non-empty BEFORE
    // filtering, so the code took the table branch, not the placeholder
    // branch — the table shell renders with an EMPTY <tbody>, which is an
    // existence oracle (a caller can distinguish "there is data, all of it
    // out of my scope" from "there is no data") that PR-2 is expected to
    // close by moving the visible-check ahead of the emptiness check. Pinned
    // here so that diff is reviewable against this exact byte sequence.
    {
        std::set<std::string> visible{"someone-else-entirely"};
        const auto html =
            render_dex_catalogue_signal_fragment(&store, "", 0, "process.crashed", "all", &visible);
        CHECK(html.find("<div class=\"gp-sech\">Most-affected devices</div>") != std::string::npos);
        CHECK(html.find("<table class=\"gp-table\"><thead><tr><th>Device</th><th class=\"gp-num\">"
                        "Events</th><th>Last seen</th></tr></thead><tbody></tbody></table>") !=
             std::string::npos);
        CHECK(html.find("dex-gold-1") == std::string::npos);
        CHECK(html.find("dex-gold-2") == std::string::npos);
    }
}

TEST_CASE("DEX golden: catalogue signal fragment — degenerate empty obs_type", "[dex][golden]") {
    CHECK(render_dex_catalogue_signal_fragment(nullptr, "", 7, "") ==
         "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal observation store "
         "is not open.</div>");
}

// ─────────────────────────────────────────────────────────────────────────
// 4. render_dex_health_fragment — window 24h/all
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: health fragment — null store placeholder", "[dex][golden]") {
    CHECK(render_dex_health_fragment(nullptr, "", 7, DexFleet{}, "default") ==
         "<div class=\"gp-placeholder\"><b>Health score unavailable</b>The signal observation "
         "store is not open.</div>");
}

TEST_CASE("DEX golden: health fragment — window matrix (score is window-invariant here)",
          "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_hang(store, "h1", "dex-gold-2", "app2.exe", kRecent);

    DexFleet fleet;
    fleet.windows_online = 2;

    // window=all: crash-free = 100*(2-1)/2 = 50.0%; total_crashes=2.
    {
        const auto html = render_dex_health_fragment(&store, "", 0, fleet, "default");
        CHECK(html.find("<div><div class=\"big\">50.0%</div><div class=\"lbl\">Crash-free "
                        "devices</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"vdiv\"></div><div><div class=\"big sec\">2</div><div "
                        "class=\"lbl\">Crashes (window)</div></div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"num\">94</div><div class=\"band band-excellent\">"
                        "Excellent</div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-ded\"><span class=\"fam\">App reliability</span><span "
                        "class=\"wt wt-high\">high</span><span><span class=\"bar\" "
                        "style=\"display:block;width:100%\"></span></span><span class=\"pts\" "
                        "style=\"color:var(--red)\">&minus;6.0</span></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-sscore\"><div class=\"nm\">App reliability</div><div "
                        "class=\"vv band-good\">78</div><div class=\"ds\">&minus;6.0 pts &middot; "
                        "high weight</div></div>") != std::string::npos);
    }
    // window=24h: only total_crashes drops (1); the composite is unaffected
    // (device-radius based, not event-count based).
    {
        const auto html = render_dex_health_fragment(&store, dex_iso_since(1), 1, fleet, "default");
        CHECK(html.find("<div><div class=\"big\">50.0%</div><div class=\"lbl\">Crash-free "
                        "devices</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"vdiv\"></div><div><div class=\"big sec\">1</div><div "
                        "class=\"lbl\">Crashes (window)</div></div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"num\">94</div>") != std::string::npos);
    }
}

TEST_CASE("DEX golden: health fragment — no reporting agents suppresses the composite",
          "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const auto html = render_dex_health_fragment(&store, "", 7, DexFleet{}, "default");
    // NOTE (surprising): `placeholder()` HTML-escapes its `sub` argument, but
    // this call site's literal ALREADY embeds the HTML entity "&mdash;" --
    // esc() escapes the "&" a second time, so the rendered text is the
    // double-escaped "&amp;mdash;" (a visible "&mdash;" in the browser, not a
    // real em-dash). Pinned as-is; not this PR's to fix.
    CHECK(html.find("<div class=\"gp-placeholder\"><b>Index suppressed</b>No reporting agents to "
                    "score &amp;mdash; a composite would be a fabricated 100, so it is withheld "
                    "rather than shown. It populates as agents report.</div>") !=
         std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────
// 5. render_dex_trends_fragment — window 24h/all
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: trends fragment — null store placeholder", "[dex][golden]") {
    CHECK(render_dex_trends_fragment(nullptr, "", 7, DexFleet{}) ==
         "<div class=\"gp-placeholder\"><b>Trends unavailable</b>The signal observation store is "
         "not open.</div>");
}

TEST_CASE("DEX golden: trends fragment — window matrix", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_hang(store, "h1", "dex-gold-2", "app2.exe", kRecent);

    DexFleet fleet;
    fleet.windows_online = 2;

    {
        const auto html = render_dex_trends_fragment(&store, "", 0, fleet);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n good\">50.0%</div><div "
                        "class=\"l\">Crash-free</div></div><div class=\"gp-tile\"><div "
                        "class=\"n\">2</div><div class=\"l\">Reporting</div></div>") !=
             std::string::npos);
        CHECK(html.find("<span class=\"smn\">App reliability</span><span class=\"smv\">3</span>") !=
             std::string::npos);
        CHECK(html.find("<span class=\"hlbl\">App reliability</span>") != std::string::npos);
    }
    {
        const auto html = render_dex_trends_fragment(&store, dex_iso_since(1), 1, fleet);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n good\">50.0%</div><div "
                        "class=\"l\">Crash-free</div></div><div class=\"gp-tile\"><div "
                        "class=\"n\">2</div><div class=\"l\">Reporting</div></div>") !=
             std::string::npos);
        CHECK(html.find("<span class=\"smn\">App reliability</span><span class=\"smv\">2</span>") !=
             std::string::npos);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 6. render_dex_overview_fragment — window x visible matrix, incl. the
//    all-out-of-scope PR-2 DELTA case (the "Most-affected devices" table).
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: overview fragment — null store placeholder", "[dex][golden]") {
    CHECK(render_dex_overview_fragment(nullptr, "", 7, DexFleet{}) ==
         "<div class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal observation "
         "store is not open.</div>");
}

TEST_CASE("DEX golden: overview fragment — window x visible matrix", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // Both devices crash app1.exe: D1 twice (recent+old), D2 once (recent) --
    // gives both devices a nonzero crash count so the "most-affected devices"
    // table + visible-subset filtering is meaningful for BOTH rows.
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_crash(store, "c3", "dex-gold-2", "app1.exe", "ntdll.dll", "windows", kRecent);

    DexFleet fleet;
    fleet.windows_online = 2;
    fleet.connected_os = {"windows"};
    fleet.connected_agents = {{"dex-gold-1", "windows"}, {"dex-gold-2", "windows"}};

    // window=all, visible=nullptr: median device score 98 (both devices
    // score >=90 -> 2 great/0 fair/0 poor); Device/App/Network = 100/88/100
    // (App reliability is the only family with a deduction: max_signal_devices=2
    // of N=2 -> impact 1.0 -> deduction 12 -> composite 88; Device/Network
    // untouched -> 100). Both devices' rows present in "Most-affected devices".
    {
        const auto html = render_dex_overview_fragment(&store, "", 0, fleet);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n good\">98</div><div "
                        "class=\"l\">Overall experience</div><div class=\"sx\">median of 2 "
                        "devices</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n good\">100</div><div "
                        "class=\"l\">Device</div><div class=\"sx\">stability &middot; perf "
                        "&middot; hardware</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">88</div><div "
                        "class=\"l\">App</div><div class=\"sx\">crashes &amp; hangs</div></div>") !=
             std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n good\">100</div><div "
                        "class=\"l\">Network</div><div class=\"sx\">connectivity</div></div>") !=
             std::string::npos);
        CHECK(html.find("<b style=\"color:#4ed27e\">2 great</b> &middot; <b "
                        "style=\"color:#ffcc00\">0 fair</b> &middot; <b style=\"color:#ff5765\">"
                        "0 poor</b>.") != std::string::npos);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/device?id=dex-gold-1&window=all\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">dex-gold-1</a></td><td class=\"gp-num\">2</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/device?id=dex-gold-2&window=all\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">dex-gold-2</a></td><td class=\"gp-num\">1</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
    }
    // window=24h: same composite (device-radius-based, window-invariant).
    {
        const auto html = render_dex_overview_fragment(&store, dex_iso_since(1), 1, fleet);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n good\">98</div><div "
                        "class=\"l\">Overall experience</div><div class=\"sx\">median of 2 "
                        "devices</div></div>") != std::string::npos);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/device?id=dex-gold-1&window=24h\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">dex-gold-1</a></td><td class=\"gp-num\">1</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
    }
    // visible = {dex-gold-1} only: dex-gold-2's row is dropped from the
    // "most-affected devices" table (the Experience distribution above is
    // NOT filtered by `visible` — it is computed over fleet.connected_agents
    // unconditionally; see this test file's report for that observation).
    {
        std::set<std::string> visible{"dex-gold-1"};
        const auto html = render_dex_overview_fragment(&store, "", 0, fleet, &visible);
        CHECK(html.find("dex-gold-1</a></td><td class=\"gp-num\">2</td>") != std::string::npos);
        CHECK(html.find("dex-gold-2") == std::string::npos);
    }
    // PR-2 DELTA: visible names neither device. Both rows drop, but `devices`
    // was non-empty before filtering, so the table shell (not the "No data"
    // placeholder) renders with an empty <tbody> — same existence-oracle
    // shape as the signal-detail case above, pinned for the same reason.
    {
        std::set<std::string> visible{"someone-else-entirely"};
        const auto html = render_dex_overview_fragment(&store, "", 0, fleet, &visible);
        CHECK(html.find("<div class=\"gp-sech\">Most-affected devices</div><table "
                        "class=\"gp-table\"><thead><tr><th>Device</th><th class=\"gp-num\">"
                        "Crashes</th><th>Last seen</th></tr></thead><tbody></tbody></table>") !=
             std::string::npos);
        CHECK(html.find("dex-gold-1</a>") == std::string::npos);
        CHECK(html.find("dex-gold-2</a>") == std::string::npos);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 7. render_dex_app_fragment — window x visible matrix, incl. the
//    all-out-of-scope PR-2 DELTA case.
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: app fragment — null store placeholder (window=24h)", "[dex][golden]") {
    CHECK(render_dex_app_fragment(nullptr, "app1.exe", "24h") ==
         "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=24h\" "
         "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
         "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store is not "
         "open.</div>");
}

TEST_CASE("DEX golden: app fragment — null store placeholder (window=all)", "[dex][golden]") {
    CHECK(render_dex_app_fragment(nullptr, "app1.exe", "all") ==
         "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=all\" "
         "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
         "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store is not "
         "open.</div>");
}

TEST_CASE("DEX golden: app fragment — app1.exe blast radius, window x visible matrix",
          "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_crash(store, "c3", "dex-gold-2", "app1.exe", "ntdll.dll", "windows", kRecent);

    // window=all, visible=nullptr: crashes=3, hangs=0, devices=2,
    // first_seen=kOld (the oldest event in-window), last_seen=kRecent.
    {
        const auto html = render_dex_app_fragment(&store, "app1.exe", "all");
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n bad\">3</div><div "
                        "class=\"l\">Crashes</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">0</div><div "
                        "class=\"l\">Hangs</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">2</div><div "
                        "class=\"l\">Devices affected</div><div class=\"sx\">blast radius</div>"
                        "</div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n mute\">" + kOld +
                        "</div><div class=\"l\">First seen</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n mute\">" + kRecent +
                        "</div><div class=\"l\">Last seen</div></div>") != std::string::npos);
        CHECK(html.find("<tr><td>ntdll.dll</td><td class=\"gp-num\">3</td></tr>") !=
             std::string::npos);
        CHECK(html.find("<tr><td>0xC0000005</td><td>ACCESS_VIOLATION</td><td class=\"gp-num\">3"
                        "</td></tr>") != std::string::npos);
        CHECK(html.find("dex-gold-1</a></td><td class=\"gp-num\">2</td>") != std::string::npos);
        CHECK(html.find("dex-gold-2</a></td><td class=\"gp-num\">1</td>") != std::string::npos);
    }
    // window=24h: the old crash ages out -> crashes=2, first_seen==last_seen
    // (only kRecent remains in-window).
    {
        const auto html = render_dex_app_fragment(&store, "app1.exe", "24h");
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n bad\">2</div><div "
                        "class=\"l\">Crashes</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n mute\">" + kRecent +
                        "</div><div class=\"l\">First seen</div></div>") != std::string::npos);
        CHECK(html.find("<tr><td>ntdll.dll</td><td class=\"gp-num\">2</td></tr>") !=
             std::string::npos);
    }
    // visible = {dex-gold-1} only: dex-gold-2's row drops.
    {
        std::set<std::string> visible{"dex-gold-1"};
        const auto html = render_dex_app_fragment(&store, "app1.exe", "all", &visible);
        CHECK(html.find("dex-gold-1</a></td><td class=\"gp-num\">2</td>") != std::string::npos);
        CHECK(html.find("dex-gold-2") == std::string::npos);
    }
    // PR-2 DELTA: visible names neither device -> the "Affected devices"
    // table shell renders with an empty <tbody> (the same existence-oracle
    // shape as the signal-detail/overview cases above).
    {
        std::set<std::string> visible{"someone-else-entirely"};
        const auto html = render_dex_app_fragment(&store, "app1.exe", "all", &visible);
        CHECK(html.find("<div class=\"gp-sech\">Affected devices</div><table "
                        "class=\"gp-table\"><thead><tr><th>Device</th><th class=\"gp-num\">"
                        "Crashes</th><th>Last seen</th></tr></thead><tbody></tbody></table>") !=
             std::string::npos);
        CHECK(html.find("dex-gold-1</a>") == std::string::npos);
        CHECK(html.find("dex-gold-2</a>") == std::string::npos);
    }
}

TEST_CASE("DEX golden: app fragment — no crashes/hangs for this app", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const auto html = render_dex_app_fragment(&store, "quiet-app.exe", "all");
    CHECK(html.find("<div class=\"gp-placeholder\"><b>No crashes</b>No crashes or hangs recorded "
                    "for this application.</div>") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────
// 8. render_dex_device_fragment — window 24h/all (no `visible` param)
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: device fragment — null store placeholder (window=24h)", "[dex][golden]") {
    CHECK(render_dex_device_fragment(nullptr, "dex-gold-1", "24h") ==
         "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=24h\" "
         "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
         "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store is not "
         "open.</div>");
}

TEST_CASE("DEX golden: device fragment — null store placeholder (window=all)", "[dex][golden]") {
    CHECK(render_dex_device_fragment(nullptr, "dex-gold-1", "all") ==
         "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=all\" "
         "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
         "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store is not "
         "open.</div>");
}

TEST_CASE("DEX golden: device fragment — dex-gold-1 signal history, window matrix",
          "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // One recent crash (in every window), one OLD hang (7d/all only, drops
    // out of 24h) -- so the history table's row COUNT is genuinely
    // window-dependent, not just its aggregate counts.
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_hang(store, "h1", "dex-gold-1", "app2.exe", kOld);

    // window=all: both rows.
    {
        const auto html = render_dex_device_fragment(&store, "dex-gold-1", "all");
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n bad\">1</div><div "
                        "class=\"l\">Crashes</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">1</div><div "
                        "class=\"l\">Hangs</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n info\">2</div><div "
                        "class=\"l\">All signals</div></div>") != std::string::npos);
        CHECK(html.find("<tr class=\"click\" hx-get=\"/fragments/dex/observation?"
                        "agent_id=dex-gold-1&amp;event_id=c1\" hx-target=\"#dex-obs-detail\" "
                        "hx-swap=\"innerHTML\"><td class=\"gp-mute\">" + kRecent +
                        "</td><td>App crash</td><td>app1.exe</td><td class=\"gp-drift\">"
                        "ACCESS_VIOLATION 0xC0000005</td><td>ntdll.dll</td></tr>") !=
             std::string::npos);
        CHECK(html.find("<tr class=\"click\" hx-get=\"/fragments/dex/observation?"
                        "agent_id=dex-gold-1&amp;event_id=h1\" hx-target=\"#dex-obs-detail\" "
                        "hx-swap=\"innerHTML\"><td class=\"gp-mute\">" + kOld +
                        "</td><td>App hang</td><td>app2.exe</td><td class=\"gp-drift\">"
                        "NOT_RESPONDING</td><td></td></tr>") != std::string::npos);
    }
    // window=24h: the hang ages out entirely (event_id=h1's row is gone).
    {
        const auto html = render_dex_device_fragment(&store, "dex-gold-1", "24h");
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n bad\">1</div><div "
                        "class=\"l\">Crashes</div></div>") != std::string::npos);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n warn\">0</div><div "
                        "class=\"l\">Hangs</div></div>") != std::string::npos);
        CHECK(html.find("event_id=c1") != std::string::npos);
        CHECK(html.find("event_id=h1") == std::string::npos);
    }
}

TEST_CASE("DEX golden: device fragment — no signals for this device", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const auto html = render_dex_device_fragment(&store, "quiet-device", "all");
    CHECK(html.find("<div class=\"gp-placeholder\"><b>No signals</b>No reliability signals "
                    "recorded for this device.</div>") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────
// 9. render_dex_apps_fragment — window 24h/all (no os/visible params)
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: apps fragment — null store placeholder, window matrix", "[dex][golden]") {
    CHECK(render_dex_apps_fragment(nullptr, "", 1).find("<div class=\"gp-placeholder\"><b>Apps "
                                                        "unavailable</b>The signal store is not "
                                                        "open.</div>") != std::string::npos);
    CHECK(render_dex_apps_fragment(nullptr, "", 0).find("<div class=\"gp-placeholder\"><b>Apps "
                                                        "unavailable</b>The signal store is not "
                                                        "open.</div>") != std::string::npos);
    CHECK(render_dex_apps_fragment(nullptr, "", 1).find("<h1>Applications</h1>") !=
         std::string::npos);
}

TEST_CASE("DEX golden: apps fragment — ranked app list, window matrix", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);
    seed_crash(store, "c3", "dex-gold-2", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_hang(store, "h1", "dex-gold-2", "app2.exe", kRecent);

    // window=all: app1.exe crashes=3, app2.exe hangs=1.
    {
        const auto html = render_dex_apps_fragment(&store, "", 0);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/app?name=app1.exe&window=all\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">app1.exe</a></td><td class=\"gp-num\">3</td>"
                        "<td class=\"gp-num\">0</td><td class=\"gp-num\">2</td><td "
                        "class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/app?name=app2.exe&window=all\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">app2.exe</a></td><td class=\"gp-num\">0</td>"
                        "<td class=\"gp-num\">1</td><td class=\"gp-num\">1</td><td "
                        "class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
    }
    // window=24h: app1.exe crashes drop to 2.
    {
        const auto html = render_dex_apps_fragment(&store, dex_iso_since(1), 1);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/app?name=app1.exe&window=24h\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">app1.exe</a></td><td class=\"gp-num\">2</td>"
                        "<td class=\"gp-num\">0</td><td class=\"gp-num\">2</td><td "
                        "class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
    }
}

TEST_CASE("DEX golden: apps fragment — no data in window", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const auto html = render_dex_apps_fragment(&store, "", 0);
    CHECK(html.find("<div class=\"gp-placeholder\"><b>No data</b>No app crashes or hangs "
                    "recorded in this window.</div>") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────
// 10. render_dex_observation_fragment (pure) + the /fragments/dex/observation
//     route's null-store behaviour.
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: observation fragment — every field, byte-exact", "[dex][golden]") {
    GuardianObservationRow r;
    r.event_id = "evt-golden-1";
    r.agent_id = "dex-gold-obs-1";
    r.observed_at = "2026-01-01T00:00:00Z";
    r.obs_type = "process.crashed";
    r.subject = "notepad.exe";
    r.reason = "0xC0000005";
    r.symbolic = "ACCESS_VIOLATION";
    r.component = "ntdll.dll";
    r.metric = 0.0; // process.crashed carries no metric -> "&mdash;"
    r.platform = "windows";

    CHECK(render_dex_observation_fragment(r) ==
         "<div class=\"gp-sech\">App crash <span class=\"gp-mute\" "
         "style=\"font-family:var(--mono);text-transform:none;letter-spacing:0\">process.crashed"
         "</span></div><div class=\"gp-spec\"><span class=\"k\">When</span><code>"
         "2026-01-01T00:00:00Z</code><span class=\"k\">Subject</span><code>notepad.exe</code>"
         "<span class=\"k\">Code</span><code>0xC0000005</code><span class=\"k\">Symbolic</span>"
         "<code>ACCESS_VIOLATION</code><span class=\"k\">Component</span><code>ntdll.dll</code>"
         "<span class=\"k\">Metric</span><code>&mdash;</code><span class=\"k\">Device</span>"
         "<code>dex-gold-obs-1</code><span class=\"k\">Platform</span><code>windows</code>"
         "<span class=\"k\">Event id</span><code>evt-golden-1</code></div>");
}

TEST_CASE("DEX golden: /fragments/dex/observation route — null store never distinguishes from "
          "'not found'",
          "[dex][golden]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{}; };

    yuzu::server::test::TestRouteSink sink;
    DexRoutes routes;
    routes.register_routes(sink, okAuth, okPerm, /*store=*/nullptr, fleet, /*audit_fn=*/{});

    auto r = sink.Get("/fragments/dex/observation?agent_id=dex-gold-1&event_id=evt-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    // Same 200 + placeholder shape as a genuinely-absent event (the route's
    // own enumeration-oracle-closing design) -- a null store is NOT
    // distinguishable from "no such event" at this route, unlike every other
    // DEX fragment (which has its own dedicated "store is not open" wording).
    CHECK(r->body == "<div class=\"gp-placeholder\"><b>Observation not found</b>No such event on "
                     "this device.</div>");
}

// ─────────────────────────────────────────────────────────────────────────
// 11. dex_device_score — window matrix (null store -> -1)
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: dex_device_score — null store returns -1", "[dex][golden]") {
    CHECK(dex_device_score(nullptr, "dex-gold-1", "") == -1);
    CHECK(dex_device_score(nullptr, "dex-gold-1", dex_iso_since(1)) == -1);
}

TEST_CASE("DEX golden: dex_device_score — window matrix", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // 2 crashes (all window), 1 of them recent (24h window).
    seed_crash(store, "c1", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kRecent);
    seed_crash(store, "c2", "dex-gold-1", "app1.exe", "ntdll.dll", "windows", kOld);

    // all window: events=2 -> impact=2/5=0.4 -> deduction=12*0.4=4.8 ->
    // score = round(100-4.8) = round(95.2) = 95.
    CHECK(dex_device_score(&store, "dex-gold-1", "") == 95);
    // 24h window: events=1 -> impact=0.2 -> deduction=2.4 ->
    // score = round(97.6) = 98.
    CHECK(dex_device_score(&store, "dex-gold-1", dex_iso_since(1)) == 98);
    // A device that has never reported anything scores 100 (no deductions).
    CHECK(dex_device_score(&store, "quiet-device", "") == 100);
}
