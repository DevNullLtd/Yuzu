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
 *
 * FULL-OUTPUT LAYER (added after the initial pass, per senior follow-up):
 * the `find()` anchors above catch drift AT the anchored points but cannot
 * see a change to the markup BETWEEN them. `check_golden(cell, html)` (below)
 * additionally compares the COMPLETE rendered body, byte-for-byte, against a
 * committed file under `tests/unit/server/golden/dex/<cell>.html` for every
 * matrix cell exercised in this file (one file per cell; every anchor stays,
 * since it documents WHY a cell's content is what it is). Regeneration is
 * `YUZU_UPDATE_GOLDEN=1`, which OVERWRITES the touched files and then FAILS
 * the run on purpose (a golden rewrite is never a silent pass) — re-run
 * without the env var to verify. `check_golden`'s own doc comment states the
 * ONE normalisation pattern applied to both sides before comparing.
 *
 * SECTION 9 (the Apps tab) is the one deliberate exception to the characterization
 * rule above: AP-3.2 rewired /fragments/dex/apps onto DexApi::apps and replaced the
 * store-fed renderer with the pure `render_dex_apps_fragment(DexAppsModel, ...)`, so
 * its five goldens were REGENERATED on purpose and seven states were added
 * (apps__error, __below-floor, __versions, __capped, __policy-custom,
 * __policy-refused, __no-population). Its cases are pure (no store, no Postgres): shard C.
 */
#include "dex_apps_ui.hpp"
#include "dex_read_builders.hpp" // dex_device_score -- dex_routes.hpp no longer re-exports it (WS-A4 PR-1 F1 fix)
#include "dex_routes.hpp"
#include "dex_read_model.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_dex_api_double.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <regex>
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
//
// kRecent is clamped to TODAY (UTC): the by-day charts bucket by calendar
// date, so a run between 00:00 and 00:30 UTC would otherwise push the recent
// event into yesterday's bucket and shift the golden markup (the date
// normaliser hides the label, not the bucket count).
std::chrono::seconds recent_offset() {
    const auto now = std::chrono::system_clock::now();
    const auto since_midnight = std::chrono::duration_cast<std::chrono::seconds>(
        now - std::chrono::floor<std::chrono::days>(now));
    return std::min<std::chrono::seconds>(std::chrono::minutes(30), since_midnight);
}
const std::string kRecent = iso_ago(recent_offset());
const std::string kOld = iso_ago(std::chrono::hours(24 * 3));

// ── Full-output golden-file layer ───────────────────────────────────────
//
// `tests/unit/server/golden/dex/` (committed) holds one `<cell>.html` file
// per exercised matrix cell. `YUZU_TEST_GOLDEN_DIR` (tests/meson.build)
// resolves the source-root-relative path at compile time so this works from
// the out-of-tree build directory the same way `YUZU_SERVER_SRC_DIR` does
// for test_body_cap_route_inventory.cpp.
std::filesystem::path golden_dir() { return std::filesystem::path(YUZU_TEST_GOLDEN_DIR) / "dex"; }

// The normalisation applied to BOTH the freshly-rendered HTML and the stored
// golden file before the byte-for-byte compare in `check_golden` below.
// Rewrites exactly three patterns, applied in this order (each later pattern
// only matches what the earlier ones left behind, since a full timestamp's
// leading "YYYY-MM-DD" would otherwise ALSO match pattern 2, and pattern 2's
// "YYYY-MM-DD" would otherwise ALSO contain pattern 3's bare "MM-DD" shape):
//   1. an ISO-8601 UTC timestamp, "YYYY-MM-DDTHH:MM:SSZ" (the shape of every
//      `kRecent`/`kOld` seed timestamp in this file, and so of every
//      `last_seen`/`observed_at`/`first_seen`/history-row timestamp the
//      renderers embed verbatim) -> the fixed token "<TS>".
//   2. a bare calendar date, "YYYY-MM-DD" (the by-day activity chart's title
//      attributes and the trends heatmap/day-bucket labels are grouped by
//      *calendar day*, so they carry today's/yesterday's real date with no
//      time component — a second, independently wall-clock-dependent shape
//      the seed timestamps above don't cover) -> the fixed token "<DATE>".
//   3. a bare "MM-DD" day label with no year, anchored ">MM-DD<" (the
//      signal-detail Activity chart and the overview Crashes-per-day chart
//      both render `d.day.substr(5)` — the same `by_day` bucket's full
//      "YYYY-MM-DD" minus its "YYYY-" prefix — as the small text label under
//      each bar; unlike pattern 2's title-attribute date, this label has no
//      surrounding digits or dashes, so the narrow ">...<" anchor is enough
//      to avoid matching anything that isn't this exact day-label shape)
//      -> "><MD><" (the substituted text keeps both boundary characters, so
//      the surrounding markup — e.g. the following "</small>"/"</div>" close
//      tag — is untouched).
// Exception: the Apps tab's "Last seen" cell. It splits the stamp at the 'T' into two
// `<span class="nw">` wrappers, so pattern 1 cannot match; the date half falls to pattern 2
// (<DATE>) and the time half stays literal ("04:00:00Z"). That is stable only because every
// Apps fixture stamp is a fixed literal; an Apps stamp derived from the wall clock would need
// its own pattern.
// Nothing else is rewritten— no whitespace collapsing, no other
// substitution. A cell with none of these shapes is unaffected: regex_replace
// with zero matches returns its input unchanged, so this is safe to call
// unconditionally rather than threading a per-cell "has timestamps?" flag.
std::string normalize_time(const std::string& in) {
    static const std::regex kIso8601Utc(R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)");
    static const std::regex kBareDate(R"(\d{4}-\d{2}-\d{2})");
    static const std::regex kBareDayLabel(R"(>\d{2}-\d{2}<)");
    return std::regex_replace(
        std::regex_replace(std::regex_replace(in, kIso8601Utc, "<TS>"), kBareDate, "<DATE>"),
        kBareDayLabel, "><MD><");
}

// Up to `ctx` bytes on each side of `pos` in `s`, clamped to `s`'s bounds —
// used by `check_golden`'s mismatch report so a multi-KB body diff doesn't
// dump the whole string into the test log.
std::string context_at(const std::string& s, std::size_t pos, std::size_t ctx = 200) {
    if (s.empty())
        return "(empty)";
    const std::size_t start = pos > ctx ? pos - ctx : 0;
    const std::size_t end = std::min(s.size(), pos + ctx);
    return s.substr(start, end - start);
}

// Golden-file byte-for-byte compare for one rendered HTML fragment (or, when
// YUZU_UPDATE_GOLDEN is set in the environment, REGENERATION instead of
// comparison). `cell` is a stable, descriptive filename stem (no
// extension) — `<renderer>__<matrix-cell-description>`, matching the call
// sites below.
//
// Regeneration: `YUZU_UPDATE_GOLDEN=1 <binary> "[golden]"` overwrites every
// golden file this run touches and the test FAILS afterwards ON PURPOSE
// (a golden-file rewrite must never read as a silent pass) — re-run WITHOUT
// the env var to confirm the freshly written files now compare equal.
void check_golden(const std::string& cell, const std::string& html) {
    const std::string actual = normalize_time(html);
    const auto path = golden_dir() / (cell + ".html");
    if (std::getenv("YUZU_UPDATE_GOLDEN") != nullptr) {
        std::error_code ec;
        std::filesystem::create_directories(golden_dir(), ec);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << actual;
        out.close();
        // safe-2/cpp8-2: a write/flush failure (disk full, a quota, an I/O
        // error surfacing only at close()) must not read as a silent
        // successful regeneration — check AFTER close(), not just after
        // open(), so this failure mode is caught too.
        REQUIRE(out.good());
        FAIL_CHECK("YUZU_UPDATE_GOLDEN=1: (re)wrote " << path.string()
             << " -- re-run WITHOUT YUZU_UPDATE_GOLDEN to verify it now matches.");
        return;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
        FAIL_CHECK("golden file missing: " << path.string()
             << " -- run with YUZU_UPDATE_GOLDEN=1 to create it, then re-run to verify.");
        return;
    }
    std::string expected((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    // CHECK (not a manual if/FAIL_CHECK) so a MATCHING golden also registers
    // as a counted, passing assertion — otherwise the successful-comparison
    // path is invisible in the assertion tally (a silent no-op that happens
    // to agree), which is exactly the kind of false-green closure this
    // golden layer exists to avoid for the rewire it's guarding.
    std::size_t diff = 0;
    const std::size_t n = std::min(expected.size(), actual.size());
    while (diff < n && expected[diff] == actual[diff])
        ++diff;
    INFO("golden mismatch for '" << cell << "' (" << path.string() << ") at byte offset " << diff
         << " (expected " << expected.size() << " bytes, got " << actual.size() << " bytes)\n"
         << "--- expected, around offset " << diff << " ---\n" << context_at(expected, diff)
         << "\n--- actual, around offset " << diff << " ---\n" << context_at(actual, diff));
    CHECK(expected == actual);
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// 1. render_dex_catalogue_fragment — window 24h/all x os all/linux
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: catalogue fragment — null store placeholder", "[dex][golden]") {
    const auto html = render_dex_catalogue_fragment(nullptr, "", 7, DexFleet{}, "all");
    CHECK(html == "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal "
                  "observation store is not open.</div>");
    check_golden("catalogue__null", html);
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
        check_golden("catalogue__os-all_win-all", html);
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
        check_golden("catalogue__os-all_win-24h", html);
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
        check_golden("catalogue__os-linux_win-all", html);
    }
    {
        const auto html =
            render_dex_catalogue_fragment(&store, dex_iso_since(1), 1, fleet, "linux");
        CHECK(html.find("<div class=\"fn\">App reliability<span class=\"cnt\">2 of 12 "
                        "monitored</span></div><div class=\"fev\">&mdash;</div><div "
                        "class=\"fmeta\">no online agents reporting</div><div class=\"ftop\">"
                        "monitored, but no device is online to report</div>") !=
             std::string::npos);
        check_golden("catalogue__os-linux_win-24h", html);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. render_dex_catalogue_group_fragment — window 24h/all x os all/linux
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: catalogue group fragment — null store placeholder", "[dex][golden]") {
    const auto html =
        render_dex_catalogue_group_fragment(nullptr, "", 7, "App reliability", DexFleet{}, "all");
    CHECK(html == "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal "
                  "observation store is not open.</div>");
    check_golden("catalogue_group__null", html);
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
        check_golden("catalogue_group__os-all_win-all", html);
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
        check_golden("catalogue_group__os-all_win-24h", html);
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
        CHECK(html.find("<tr class=\"gp-mute dx-off\" hx-get=\"/fragments/dex/catalogue/signal?"
                        "type=process.crashed_managed&window=all&os=linux\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer\"><td>App crash (.NET)</td><td>"
                        "<span class=\"gp-pill draft\">not collected on linux</span></td>"
                        "<td class=\"gp-num\">&mdash;</td><td class=\"gp-num\">&mdash;</td>"
                        "<td>&mdash;</td></tr>") != std::string::npos);
        check_golden("catalogue_group__os-linux_win-all", html);
    }
}

TEST_CASE("DEX golden: catalogue group fragment — unknown family name", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const auto html =
        render_dex_catalogue_group_fragment(&store, "", 7, "No Such Family", DexFleet{}, "all");
    CHECK(html == "<div class=\"gp-placeholder\"><b>Unknown family</b>No such signal family: No "
                  "Such Family</div>");
    check_golden("catalogue_group__unknown-family", html);
}

// ─────────────────────────────────────────────────────────────────────────
// 3. render_dex_catalogue_signal_fragment — window x os x visible matrix,
//    including the all-out-of-scope PR-2 DELTA case.
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: catalogue signal fragment — null store placeholder", "[dex][golden]") {
    const auto html = render_dex_catalogue_signal_fragment(nullptr, "", 7, "process.crashed");
    CHECK(html == "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal "
                  "observation store is not open.</div>");
    check_golden("catalogue_signal__null", html);
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
        check_golden("catalogue_signal__os-all_win-all_visible-null", html);
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
        check_golden("catalogue_signal__os-all_win-24h_visible-null", html);
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
        check_golden("catalogue_signal__os-linux_win-all_visible-null", html);
    }
    // visible = proper subset (dex-gold-1 only): dex-gold-2's row is dropped,
    // dex-gold-1's stays — the table shell + the surviving row both render.
    {
        std::set<std::string> visible{"dex-gold-1"};
        const auto html =
            render_dex_catalogue_signal_fragment(&store, "", 0, "process.crashed", "all", &visible);
        CHECK(html.find("<tr><td>dex-gold-1</td>") != std::string::npos);
        CHECK(html.find("dex-gold-2") == std::string::npos);
        check_golden("catalogue_signal__os-all_win-all_visible-subset", html);
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
        check_golden("catalogue_signal__os-all_win-all_visible-none", html);
    }
}

TEST_CASE("DEX golden: catalogue signal fragment — degenerate empty obs_type", "[dex][golden]") {
    const auto html = render_dex_catalogue_signal_fragment(nullptr, "", 7, "");
    CHECK(html == "<div class=\"gp-placeholder\"><b>Catalogue unavailable</b>The signal "
                  "observation store is not open.</div>");
    check_golden("catalogue_signal__degenerate-empty-obstype", html);
}

// ─────────────────────────────────────────────────────────────────────────
// 4. render_dex_health_fragment — window 24h/all
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: health fragment — null store placeholder", "[dex][golden]") {
    const auto html = render_dex_health_fragment(nullptr, "", 7, DexFleet{}, "default");
    CHECK(html == "<div class=\"gp-placeholder\"><b>Health score unavailable</b>The signal "
                  "observation store is not open.</div>");
    check_golden("health__null", html);
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
        check_golden("health__win-all", html);
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
        check_golden("health__win-24h", html);
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
    check_golden("health__no-reporting-agents", html);
}

// ─────────────────────────────────────────────────────────────────────────
// 5. render_dex_trends_fragment — window 24h/all
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: trends fragment — null store placeholder", "[dex][golden]") {
    const auto html = render_dex_trends_fragment(nullptr, "", 7, DexFleet{});
    CHECK(html == "<div class=\"gp-placeholder\"><b>Trends unavailable</b>The signal observation "
                  "store is not open.</div>");
    check_golden("trends__null", html);
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
        check_golden("trends__win-all", html);
    }
    {
        const auto html = render_dex_trends_fragment(&store, dex_iso_since(1), 1, fleet);
        CHECK(html.find("<div class=\"gp-tile\"><div class=\"n good\">50.0%</div><div "
                        "class=\"l\">Crash-free</div></div><div class=\"gp-tile\"><div "
                        "class=\"n\">2</div><div class=\"l\">Reporting</div></div>") !=
             std::string::npos);
        CHECK(html.find("<span class=\"smn\">App reliability</span><span class=\"smv\">2</span>") !=
             std::string::npos);
        check_golden("trends__win-24h", html);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 6. render_dex_overview_fragment — window x visible matrix, incl. the
//    all-out-of-scope PR-2 DELTA case (the "Most-affected devices" table).
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: overview fragment — null store placeholder", "[dex][golden]") {
    const auto html = render_dex_overview_fragment(nullptr, "", 7, DexFleet{});
    CHECK(html == "<div class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal "
                  "observation store is not open.</div>");
    check_golden("overview__null", html);
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
        CHECK(html.find("<b class=\"gp-ok\">2 great</b> &middot; <b "
                        "class=\"gp-drift\">0 fair</b> &middot; <b class=\"gp-err\">"
                        "0 poor</b>.") != std::string::npos);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/device?id=dex-gold-1&window=all\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">dex-gold-1</a></td><td class=\"gp-num\">2</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
        CHECK(html.find("<tr><td><a hx-get=\"/fragments/dex/device?id=dex-gold-2&window=all\" "
                        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                        "style=\"cursor:pointer;\">dex-gold-2</a></td><td class=\"gp-num\">1</td>"
                        "<td class=\"gp-mute\">" + kRecent + "</td></tr>") != std::string::npos);
        check_golden("overview__win-all_visible-null", html);
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
        check_golden("overview__win-24h_visible-null", html);
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
        check_golden("overview__win-all_visible-subset", html);
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
        check_golden("overview__win-all_visible-none", html);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 7. render_dex_app_fragment — window x visible matrix, incl. the
//    all-out-of-scope PR-2 DELTA case.
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: app fragment — null store placeholder (window=24h)", "[dex][golden]") {
    const auto html = render_dex_app_fragment(nullptr, "app1.exe", "24h");
    CHECK(html == "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=24h\" "
                  "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                  "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
                  "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store "
                  "is not open.</div>");
    check_golden("app__null_win-24h", html);
}

TEST_CASE("DEX golden: app fragment — null store placeholder (window=all)", "[dex][golden]") {
    const auto html = render_dex_app_fragment(nullptr, "app1.exe", "all");
    CHECK(html == "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=all\" "
                  "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                  "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
                  "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store "
                  "is not open.</div>");
    check_golden("app__null_win-all", html);
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
        check_golden("app__win-all_visible-null", html);
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
        check_golden("app__win-24h_visible-null", html);
    }
    // visible = {dex-gold-1} only: dex-gold-2's row drops.
    {
        std::set<std::string> visible{"dex-gold-1"};
        const auto html = render_dex_app_fragment(&store, "app1.exe", "all", &visible);
        CHECK(html.find("dex-gold-1</a></td><td class=\"gp-num\">2</td>") != std::string::npos);
        CHECK(html.find("dex-gold-2") == std::string::npos);
        check_golden("app__win-all_visible-subset", html);
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
        check_golden("app__win-all_visible-none", html);
    }
}

TEST_CASE("DEX golden: app fragment — no crashes/hangs for this app", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const auto html = render_dex_app_fragment(&store, "quiet-app.exe", "all");
    CHECK(html.find("<div class=\"gp-placeholder\"><b>No crashes</b>No crashes or hangs recorded "
                    "for this application.</div>") != std::string::npos);
    check_golden("app__no-crashes", html);
}

// ─────────────────────────────────────────────────────────────────────────
// 8. render_dex_device_fragment — window 24h/all (no `visible` param)
// ─────────────────────────────────────────────────────────────────────────

TEST_CASE("DEX golden: device fragment — null store placeholder (window=24h)", "[dex][golden]") {
    const auto html = render_dex_device_fragment(nullptr, "dex-gold-1", "24h");
    CHECK(html == "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=24h\" "
                  "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                  "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
                  "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store "
                  "is not open.</div>");
    check_golden("device__null_win-24h", html);
}

TEST_CASE("DEX golden: device fragment — null store placeholder (window=all)", "[dex][golden]") {
    const auto html = render_dex_device_fragment(nullptr, "dex-gold-1", "all");
    CHECK(html == "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview?window=all\" "
                  "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                  "style=\"cursor:pointer;\">&larr; Reliability overview</a><div "
                  "class=\"gp-placeholder\"><b>Reliability data unavailable</b>The signal store "
                  "is not open.</div>");
    check_golden("device__null_win-all", html);
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
        check_golden("device__win-all", html);
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
        check_golden("device__win-24h", html);
    }
}

TEST_CASE("DEX golden: device fragment — no signals for this device", "[pg][dex][golden]") {
    YUZU_REQUIRE_PG_DB_TPL(db, golden_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const auto html = render_dex_device_fragment(&store, "quiet-device", "all");
    CHECK(html.find("<div class=\"gp-placeholder\"><b>No signals</b>No reliability signals "
                    "recorded for this device.</div>") != std::string::npos);
    check_golden("device__no-signals", html);
}

// ─────────────────────────────────────────────────────────────────────────
// 9. render_dex_apps_fragment (AP-3.2) — PURE over DexAppsModel, so no store and no
//    Postgres: every case is in shard C. The page is pinned byte-for-byte by the
//    apps__* goldens and figure-for-figure against GET /api/v1/dex/apps
//    (dex_apps_json of the same model). The browser smoke gate serves
//    golden/dex/apps__versions.html through its stub, so that file is also the
//    fixture of the expander checks.
// ─────────────────────────────────────────────────────────────────────────

namespace {

using nlohmann::json;

DexAppStabilityRow apps_total_row(const std::string& subject, int64_t crashes, int64_t hangs,
                                  int64_t affected, int64_t cc, int64_t ch, int64_t version_count,
                                  int64_t apps_total, const std::string& last_seen) {
    DexAppStabilityRow r;
    r.subject = subject;
    r.crashes = crashes;
    r.hangs = hangs;
    r.affected_devices = affected;
    r.affected_online = affected; // every affected device is online: online figures = window-wide
    r.crashes_online = crashes;
    r.hangs_online = hangs;
    r.capped_crashes = cc;
    r.capped_hangs = ch;
    r.version_count = version_count;
    r.apps_total = apps_total;
    r.last_seen = last_seen;
    return r;
}

DexAppStabilityRow apps_version_row(const std::string& subject, const std::string& version,
                                    int64_t crashes, int64_t hangs, int64_t affected, int64_t cc,
                                    int64_t ch, const std::string& last_seen) {
    DexAppStabilityRow r = apps_total_row(subject, crashes, hangs, affected, cc, ch, 0, 0, last_seen);
    r.version = version;
    return r;
}

// Two applications, every figure distinct within its row so a swapped or misplaced one cannot pass.
// app1.exe is the hand-computed anchor of test_dex_apps_stability.cpp (population 50: 7 affected,
// 12 crashes + 3 hangs -> 14.0%, 300.0 per 1,000, 90.7 Excellent).
std::vector<DexAppStabilityRow> populated_rows() {
    return {
        apps_total_row("app1.exe", 12, 3, 7, 10, 3, 2, 2, "2026-10-14T01:00:00Z"),
        apps_version_row("app1.exe", "1.2.3", 8, 2, 5, 8, 2, "2026-10-14T02:00:00Z"),
        apps_version_row("app1.exe", "1.2.0", 4, 1, 2, 4, 1, "2026-10-13T03:00:00Z"),
        apps_total_row("wide.exe", 20, 6, 11, 18, 6, 2, 2, "2026-10-14T04:00:00Z"),
        apps_version_row("wide.exe", "", 15, 4, 8, 14, 4, "2026-10-14T05:00:00Z"),
        apps_version_row("wide.exe", "3.0.1", 5, 2, 3, 5, 2, "2026-10-12T06:00:00Z"),
    };
}

DexAppsModel model_of(const std::vector<DexAppStabilityRow>& rows, std::optional<int64_t> population,
                      const std::string& scope = "all", const DexPolicyInForce& policy = {}) {
    return dex_apps_model_from_rows("7d", scope, rows, population, policy);
}

DexAppsModel populated_model() { return model_of(populated_rows(), 50); }

DexAppsModel degraded_model(const std::string& reason) {
    DexAppsModel m;
    m.degraded = true;
    m.degraded_reason = reason;
    return m;
}

constexpr int kColApp = 0, kColScore = 1, kColCrashes = 2, kColHangs = 3, kColDevices = 4,
              kColShare = 5, kColRate = 6, kColLastSeen = 7;

// The `<td` chunk of one column in the row of `subject` (or of its `version`). No HTML parser: the
// page emits one <tbody class="dx-app"> per application, one <tr> per row, one <td> per column.
std::string cell(const std::string& page, const std::string& subject, const std::string& version,
                 int col) {
    const std::string app_tag = "<tbody class=\"dx-app\">";
    std::size_t at = 0;
    while ((at = page.find(app_tag, at)) != std::string::npos) {
        const std::size_t end = page.find("</tbody>", at);
        const std::string body = page.substr(at, end - at);
        at = end;
        const std::size_t head_end = body.find("</tr>");
        const std::string head = body.substr(0, head_end);
        if (head.find(">" + subject + "</a>") == std::string::npos)
            continue;
        std::string row = head;
        if (!version.empty()) {
            // a version row: the <tr class="dx-ver"> whose first cell names it
            const std::string want = ">" + version + "</span>";
            std::size_t r = head_end;
            row.clear();
            while ((r = body.find("<tr class=\"dx-ver\"", r)) != std::string::npos) {
                const std::size_t re = body.find("</tr>", r);
                const std::string cand = body.substr(r, re - r);
                if (cand.find(want) != std::string::npos) {
                    row = cand;
                    break;
                }
                r = re;
            }
        }
        std::size_t pos = 0;
        std::string chunk;
        for (int i = 0; i <= col; ++i) {
            pos = row.find("<td", pos);
            if (pos == std::string::npos)
                return {};
            const std::size_t next = row.find("<td", pos + 1);
            chunk = row.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
            pos += 1;
        }
        return chunk;
    }
    return {};
}

// `needle` as a whole number: `12` never matches inside `120` or `12.5`.
bool has_number(const std::string& hay, const std::string& needle) {
    auto digit = [](char c) { return c >= '0' && c <= '9'; };
    for (std::size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1)) {
        const bool left = p == 0 || !(digit(hay[p - 1]) || hay[p - 1] == '.');
        const std::size_t e = p + needle.size();
        const bool right =
            e >= hay.size() || !(digit(hay[e]) || (hay[e] == '.' && e + 1 < hay.size() && digit(hay[e + 1])));
        if (left && right)
            return true;
    }
    return false;
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

} // namespace

TEST_CASE("DEX apps UI: degraded model, window matrix (goldens)", "[dex][golden][apps_ui]") {
    const auto h24 = render_dex_apps_fragment(degraded_model(""), 1, "all");
    CHECK(contains(h24, "<h1>Applications</h1>"));
    CHECK(contains(h24, "<div class=\"gp-placeholder\"><b>Application stability is unavailable</b>"));
    CHECK(contains(h24, "class=\"gp-chip on\" aria-pressed=\"true\" hx-get=\"/fragments/dex/apps?window=24h&amp;platform=all\""));
    CHECK_FALSE(contains(h24, "No data"));
    check_golden("apps__null_win-24h", h24);

    const auto hall = render_dex_apps_fragment(degraded_model(""), 0, "all");
    CHECK(contains(hall, "class=\"gp-chip on\" aria-pressed=\"true\" hx-get=\"/fragments/dex/apps?window=all&amp;platform=all\""));
    check_golden("apps__null_win-all", hall);
}

TEST_CASE("DEX apps UI: populated page, window matrix (goldens)", "[dex][golden][apps_ui]") {
    const auto model = populated_model();
    // The hand-computed anchor row.
    const auto page_all = render_dex_apps_fragment(model, 0, "all");
    CHECK(contains(cell(page_all, "app1.exe", "", kColShare), "14.0%"));
    CHECK(contains(cell(page_all, "app1.exe", "", kColRate), "300.0"));
    CHECK(contains(cell(page_all, "app1.exe", "", kColScore), "excellent 90.7"));
    CHECK(contains(page_all, "<b>Window-wide figures:</b>"));
    // Every chip carries both the window and the platform, as canonical tokens: the four platform
    // chips keep the current window, the four window chips keep the current platform.
    CHECK(count_of(page_all, "&amp;platform=") == 8);
    CHECK(count_of(page_all, "hx-get=\"/fragments/dex/apps?window=all&amp;platform=") == 5);
    CHECK(count_of(page_all, "&amp;platform=all\" hx-target") == 5);
    // The drill link keeps its shape; the window is the canonical token.
    CHECK(contains(page_all, "<a hx-get=\"/fragments/dex/app?name=app1.exe&window=all\" "
                             "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
                             "style=\"cursor:pointer;\">app1.exe</a>"));
    check_golden("apps__win-all", page_all);

    const auto page_24h = render_dex_apps_fragment(model, 1, "all");
    CHECK(contains(page_24h, "/fragments/dex/app?name=wide.exe&window=24h"));
    CHECK(count_of(page_24h, "hx-get=\"/fragments/dex/apps?window=24h&amp;platform=") == 5);
    check_golden("apps__win-24h", page_24h);
}

TEST_CASE("DEX apps UI: healthy empty list says so in words", "[dex][golden][apps_ui]") {
    const auto page = render_dex_apps_fragment(model_of({}, 50), 0, "all");
    CHECK(contains(page, "<b>Nothing recorded</b>No application crashes or hangs were recorded in this window."));
    CHECK_FALSE(contains(page, "No data"));
    CHECK_FALSE(contains(page, "<table"));
    check_golden("apps__no-data", page);

    // A partial platform is not proof of stability.
    const auto linux_page = render_dex_apps_fragment(model_of({}, 5, "linux"), 7, "linux");
    CHECK(contains(linux_page, "Nothing recorded for Linux"));
    CHECK(contains(linux_page, "so an empty list is not proof that applications are stable"));
}

TEST_CASE("DEX apps UI: failed read states its own words", "[dex][golden][apps_ui]") {
    const auto page = render_dex_apps_fragment(degraded_model("score_policy_unavailable"), 7, "windows");
    CHECK(contains(page, "Application stability is unavailable"));
    CHECK(contains(page, "(reason: <code class=\"dx-code\">score_policy_unavailable</code>)"));
    // the chips come from the request, not from the default-constructed model's windows scope
    CHECK(contains(page, "class=\"gp-chip on\" aria-pressed=\"true\" hx-get=\"/fragments/dex/apps?window=7d&amp;platform=windows\""));
    check_golden("apps__error", page);
}

TEST_CASE("DEX apps UI: below-floor row reads count only", "[dex][golden][apps_ui]") {
    auto model = populated_model();
    REQUIRE(model.apps[0].subject == "wide.exe"); // ranked first: 26 events against 15
    auto& f = model.apps[0].figures; // not reachable from a live read (the floor is one device)
    f.score = stability_detail::withheld_result("below_floor");
    f.share_affected.reset();
    f.rate_per_1000.reset();
    const auto page = render_dex_apps_fragment(model, 7, "all");
    CHECK(contains(cell(page, "wide.exe", "", kColShare), "below the reporting floor: count only"));
    CHECK(contains(cell(page, "wide.exe", "", kColRate), "below the reporting floor: count only"));
    CHECK(contains(cell(page, "wide.exe", "", kColScore), "Below the reporting floor: count only."));
    CHECK(contains(cell(page, "wide.exe", "", kColDevices), "count only"));
    // the neighbouring row is untouched
    CHECK(contains(cell(page, "app1.exe", "", kColShare), "14.0%"));
    check_golden("apps__below-floor", page);
}

TEST_CASE("DEX apps UI: versions, incl. the unknown-version bucket", "[dex][golden][apps_ui]") {
    const std::vector<DexAppStabilityRow> rows = {
        apps_total_row("chrome.exe", 30, 6, 12, 26, 6, 3, 1, "2026-10-14T01:00:00Z"),
        apps_version_row("chrome.exe", "131.0.1", 18, 3, 7, 16, 3, "2026-10-14T02:00:00Z"),
        apps_version_row("chrome.exe", "130.0.9", 9, 2, 4, 9, 2, "2026-10-13T03:00:00Z"),
        apps_version_row("chrome.exe", "", 3, 1, 1, 3, 1, "2026-10-12T04:00:00Z"),
    };
    const auto page = render_dex_apps_fragment(model_of(rows, 50), 7, "all");
    CHECK(contains(page, "<details class=\"dx-vx\"><summary>3 versions</summary></details>"));
    CHECK(contains(page, "<span class=\"dx-vn unk\">unknown version</span>"));
    CHECK(count_of(page, "<tr class=\"dx-ver\">") == 3);
    // each version row has its own score cell
    CHECK(count_of(page, "<summary class=\"dx-sc ") == 4);
    // the version rows sit inside their application's own tbody
    CHECK(count_of(page, "<tbody class=\"dx-app\">") == 1);
    CHECK(contains(page, "tbody:has(.dx-vx[open]) .dx-ver{display:table-row}"));
    check_golden("apps__versions", page);
}

TEST_CASE("DEX apps UI: applications and versions capped", "[dex][golden][apps_ui]") {
    std::vector<DexAppStabilityRow> rows = {
        apps_total_row("big.exe", 40, 9, 17, 35, 9, 31, 250, "2026-10-14T01:00:00Z"),
        apps_version_row("big.exe", "9.1", 22, 5, 10, 20, 5, "2026-10-14T02:00:00Z"),
        apps_version_row("big.exe", "9.0", 18, 4, 7, 15, 4, "2026-10-13T03:00:00Z"),
        apps_total_row("small.exe", 3, 1, 2, 3, 1, 1, 250, "2026-10-14T04:00:00Z"),
        apps_version_row("small.exe", "1.0", 3, 1, 2, 3, 1, "2026-10-14T04:00:00Z"),
    };
    auto model = model_of(rows, 50);
    // 31 versions published, 2 listed here: the model's own numbers go into the note.
    model.apps[0].versions_truncated = true;
    const auto page = render_dex_apps_fragment(model, 7, "all");
    CHECK(model.apps_truncated);
    CHECK(contains(page, "Showing 2 of 250 applications: the 2 with the most devices affected, listed by "
                         "crashes plus hangs. 248 are not listed."));
    CHECK(contains(page, "Showing the 2 versions with the most devices affected; 29 more versions have "
                         "crashes or hangs in this window and are not listed."));
    CHECK(contains(page, "<summary>31 versions</summary>"));
    check_golden("apps__capped", page);
}

TEST_CASE("DEX apps UI: custom policy, renamed tiers, override row",
          "[dex][golden][apps_ui]") {
    DexPolicyInForce policy;
    policy.source = "custom";
    policy.revision = "7c41e9b2a05d3f68";
    policy.policy.tiers.names = {"Healthy", "Watch", "Degraded", "Critical"};
    policy.policy.tiers.edges = {92.0, 80.0, 55.0};
    policy.policy.interval_confidence = 0.90;
    DexScoreOverride o;
    o.image = "legacy.exe";
    o.names = {std::string("Stable"), std::string("Acceptable"), std::nullopt, std::nullopt};
    policy.policy.overrides.push_back(o);
    const std::vector<DexAppStabilityRow> rows = {
        apps_total_row("Teams", 12, 3, 7, 10, 3, 1, 2, "2026-10-14T01:00:00Z"),
        apps_version_row("Teams", "24295.1", 12, 3, 7, 10, 3, "2026-10-14T01:00:00Z"),
        apps_total_row("legacy.exe", 9, 2, 3, 9, 2, 1, 2, "2026-10-14T02:00:00Z"),
        apps_version_row("legacy.exe", "8.2", 9, 2, 3, 9, 2, "2026-10-14T02:00:00Z"),
    };
    const auto model = model_of(rows, 130, "linux", policy);
    const auto page = render_dex_apps_fragment(model, 7, "linux");
    CHECK(contains(page, "custom, revision <code class=\"dx-code\">7c41e9b2a05d3f68</code>"));
    CHECK(contains(page, "Healthy from 92, Watch from 80, Degraded from 55, Critical below 55"));
    CHECK(contains(page, "Intervals at 90% confidence"));
    CHECK(contains(page, "<span class=\"dx-tag\">override</span>"));
    // the override row names its own tier; the chip tone still follows the closed band token
    CHECK(contains(cell(page, "legacy.exe", "", kColScore), "Stable"));
    CHECK_FALSE(contains(cell(page, "legacy.exe", "", kColScore), "Healthy"));
    CHECK(contains(cell(page, "Teams", "", kColScore), "Healthy"));
    // a custom policy is a valid document, so the page never also claims it was refused
    CHECK_FALSE(contains(page, "The stored policy was refused"));
    CHECK(contains(page, "Linux partial: it needs systemd-coredump as the active handler."));
    CHECK(contains(page, "The application drill-down covers every platform."));
    check_golden("apps__policy-custom", page);
}

TEST_CASE("DEX apps UI: a refused stored policy with the shipped defaults in force",
          "[dex][golden][apps_ui]") {
    DexPolicyInForce policy;
    policy.revision = "5b0e3c91d7a24f60";
    policy.fault = "edge_gap_below_minimum";
    const auto page = render_dex_apps_fragment(model_of(populated_rows(), 50, "windows", policy), 7, "windows");
    CHECK(contains(page, "default (a stored policy was refused), revision <code class=\"dx-code\">5b0e3c91d7a24f60</code>"));
    CHECK(contains(page, "The shipped defaults are in force until a valid policy is saved."));
    CHECK(contains(page, "<b>The stored policy was refused.</b>"));
    CHECK(contains(page, "<code class=\"dx-code\">edge_gap_below_minimum</code>"));
    CHECK_FALSE(contains(page, "custom, revision"));
    check_golden("apps__policy-refused", page);
}

TEST_CASE("DEX apps UI: unknown and zero population read in words", "[dex][golden][apps_ui]") {
    const auto unknown = render_dex_apps_fragment(model_of(populated_rows(), std::nullopt), 7, "all");
    CHECK(contains(unknown, "<b>Population</b> unknown. No fleet source is connected"));
    CHECK(contains(cell(unknown, "app1.exe", "", kColShare), "not calculated: population unknown"));
    CHECK(contains(cell(unknown, "app1.exe", "", kColRate), "not calculated: population unknown"));
    CHECK(contains(cell(unknown, "app1.exe", "", kColScore), "Population unknown, so there is nothing to measure against."));
    CHECK(contains(cell(unknown, "app1.exe", "", kColDevices), "online count unknown"));
    CHECK(contains(cell(unknown, "app1.exe", "", kColCrashes), ">12<")); // window-wide counts still show
    CHECK_FALSE(contains(unknown, "<b>Small counts:</b>")); // no share or rate to tag
    check_golden("apps__no-population", unknown);

    const auto zero = render_dex_apps_fragment(model_of(populated_rows(), 0), 7, "all");
    CHECK(contains(zero, "<b>Population</b> 0 devices online now (all platforms)."));
    CHECK(contains(cell(zero, "app1.exe", "", kColShare), "not calculated: no device online"));
    CHECK(contains(cell(zero, "app1.exe", "", kColScore), "No device is online to measure against."));
    CHECK_FALSE(contains(zero, "<b>Small counts:</b>"));
}

TEST_CASE("DEX apps UI: a degraded model states nothing it did not read", "[dex][apps_ui]") {
    for (const char* reason :
         {"", "score_policy_unavailable", "score_policy_invalid", "invalid_scope", "novel_reason_token"}) {
        INFO("degraded_reason = '" << reason << "'");
        const auto page = render_dex_apps_fragment(degraded_model(reason), 7, "all");
        CHECK(contains(page, "class=\"gp-placeholder\""));
        CHECK(contains(page, "class=\"gp-chip"));
        for (const char* never : {"Population", "Scoring policy", "revision", "Intervals at",
                                  "Crash and hang sources", "<table", "No data", "Window-wide"})
            CHECK_FALSE(contains(page, never));
    }
    CHECK(contains(render_dex_apps_fragment(degraded_model("invalid_scope"), 7, "all"), "Unknown platform"));
    // An unrecognised platform is an error even when the caller hands in a healthy model.
    const auto bad = render_dex_apps_fragment(populated_model(), 7, "");
    CHECK(contains(bad, "<b>Unknown platform</b>"));
    CHECK_FALSE(contains(bad, "<table"));
    CHECK(count_of(bad, "aria-pressed=\"true\"") == 1); // only the window chip: no platform chip is lit
    CHECK(contains(bad, "hx-get=\"/fragments/dex/apps?window=7d&amp;platform=all\""));
}

TEST_CASE("DEX apps UI: each small-count tag names its own numerator", "[dex][apps_ui]") {
    // 1 affected device, 100 events, population 50: the share is on 1 device, the rate on 100 events.
    const auto few_devices = render_dex_apps_fragment(
        model_of({apps_total_row("x.exe", 100, 0, 1, 5, 0, 1, 1, "2026-10-14T01:00:00Z"),
                  apps_version_row("x.exe", "1", 100, 0, 1, 5, 0, "2026-10-14T01:00:00Z")},
                 50),
        7, "all");
    CHECK(contains(cell(few_devices, "x.exe", "", kColShare), "under 20 affected online devices"));
    CHECK_FALSE(contains(cell(few_devices, "x.exe", "", kColRate), "under 20"));

    // 25 affected devices with 25 events: neither is small.
    const auto many = render_dex_apps_fragment(
        model_of({apps_total_row("y.exe", 25, 0, 25, 25, 0, 1, 1, "2026-10-14T01:00:00Z"),
                  apps_version_row("y.exe", "1", 25, 0, 25, 25, 0, "2026-10-14T01:00:00Z")},
                 50),
        7, "all");
    CHECK_FALSE(contains(cell(many, "y.exe", "", kColShare), "under 20"));
    CHECK_FALSE(contains(cell(many, "y.exe", "", kColRate), "under 20"));

    // 5 devices, 5 events: both are small. An event count is never below the device count, so a
    // rate tagged "under 20 events" always has a tagged share too.
    const auto both = render_dex_apps_fragment(
        model_of({apps_total_row("z.exe", 5, 0, 5, 5, 0, 1, 1, "2026-10-14T01:00:00Z"),
                  apps_version_row("z.exe", "1", 5, 0, 5, 5, 0, "2026-10-14T01:00:00Z")},
                 50),
        7, "all");
    CHECK(contains(cell(both, "z.exe", "", kColShare), "under 20 affected online devices"));
    CHECK(contains(cell(both, "z.exe", "", kColRate), "under 20 events"));
    const auto model = populated_model();
    const auto page = render_dex_apps_fragment(model, 7, "all");
    for (const auto& a : model.apps) {
        const bool rate_tagged = contains(cell(page, a.subject, "", kColRate), "under 20 events");
        const bool share_tagged = contains(cell(page, a.subject, "", kColShare), "under 20 affected online devices");
        CHECK((!rate_tagged || share_tagged));
        CHECK_FALSE(contains(cell(page, a.subject, "", kColShare), "under 20 events"));
    }
    // wide.exe: 26 events (rate not small), 11 devices (share small)
    CHECK_FALSE(contains(cell(page, "wide.exe", "", kColRate), "under 20 events"));
    CHECK(contains(cell(page, "wide.exe", "", kColShare), "under 20 affected online devices"));
}

TEST_CASE("DEX apps UI: the population sits beside every share and rate", "[dex][apps_ui]") {
    const auto model = populated_model();
    const auto page = render_dex_apps_fragment(model, 7, "all");
    for (const auto& a : model.apps) {
        CHECK(contains(cell(page, a.subject, "", kColShare), " of 50 online"));
        CHECK(contains(cell(page, a.subject, "", kColRate), "per 1,000 of 50 online devices"));
        for (const auto& v : a.versions) {
            const std::string name = v.version.empty() ? "unknown version" : v.version;
            CHECK(contains(cell(page, a.subject, name, kColShare), " of 50 online"));
            CHECK(contains(cell(page, a.subject, name, kColRate), "per 1,000 of 50 online devices"));
        }
    }
    CHECK(contains(page, "<b>Population</b> 50 devices online now (all platforms)."));
}

TEST_CASE("DEX apps UI: Devices affected and the share keep the total and online figures apart",
          "[dex][apps_ui]") {
    // Rows of their own: populated_rows() has online == affected everywhere, which a swap of the two
    // figures cannot show. Application: 9 affected, 4 online. Its version: 6 affected, 3 online.
    auto app = apps_total_row("lag.exe", 12, 3, 9, 10, 3, 1, 1, "2026-10-14T01:00:00Z");
    app.affected_online = 4;
    auto ver = apps_version_row("lag.exe", "2.0", 8, 2, 6, 8, 2, "2026-10-14T02:00:00Z");
    ver.affected_online = 3;
    const auto model = model_of({app, ver}, 50);
    const auto page = render_dex_apps_fragment(model, 7, "all");
    const auto j = json::parse(dex_apps_json(model));
    REQUIRE(j["apps"].size() == 1);
    REQUIRE(j["apps"][0]["versions"].size() == 1);

    auto check_row = [&](const std::string& shown_version, const json& o, int64_t affected, int64_t online) {
        INFO("row lag.exe / '" << shown_version << "'");
        CHECK(o["distinct_devices"].get<int64_t>() == affected);
        CHECK(o["distinct_devices_online"].get<int64_t>() == online);
        CHECK(o["share_affected"]["estimate"].get<double>() == static_cast<double>(online) / 50.0);
        const auto devices = cell(page, "lag.exe", shown_version, kColDevices);
        CHECK(contains(devices, "<span class=\"v\">" + std::to_string(affected) + "</span>"));
        CHECK(contains(devices, "<span class=\"s nw\">" + std::to_string(online) + " online</span>"));
        // the share's numerator is the online figure, said beside the population
        CHECK(contains(cell(page, "lag.exe", shown_version, kColShare),
                       "<span class=\"s\">" + std::to_string(online) + " of 50 online</span>"));
    };
    check_row("", j["apps"][0], 9, 4);
    check_row("2.0", j["apps"][0]["versions"][0], 6, 3);
}

TEST_CASE("DEX apps UI: a non-finite interval value reads in words, never inf or nan", "[dex][apps_ui]") {
    // Defensive twin of the REST serializer, which sends a non-finite estimate or upper as null.
    auto model = populated_model();
    const std::string subject = model.apps[0].subject;
    REQUIRE(model.apps[0].figures.share_affected);
    REQUIRE(model.apps[0].figures.rate_per_1000);
    model.apps[0].figures.share_affected->upper = std::numeric_limits<double>::infinity();
    model.apps[0].figures.rate_per_1000->estimate = std::numeric_limits<double>::quiet_NaN();
    const auto page = render_dex_apps_fragment(model, 7, "all");
    const auto share = cell(page, subject, "", kColShare);
    const auto rate = cell(page, subject, "", kColRate);
    CHECK(contains(share, "no upper bound"));
    CHECK(contains(rate, "no estimate"));
    for (const char* bad : {"inf", "nan"}) {
        CHECK_FALSE(contains(share, bad));
        CHECK_FALSE(contains(rate, bad));
    }
}

TEST_CASE("DEX apps UI: every withheld score reads in words and the token is escaped", "[dex][apps_ui]") {
    struct Case {
        const char* token;
        const char* words;
    };
    const Case cases[] = {
        {"no_population", "No device is online to measure against."},
        {"offline_affected", "affected devices are offline, so no score is given."},
        {"below_floor", "Below the reporting floor: count only."},
        {"inconsistent", "The counts disagree, so no score is given."},
        {"invalid_weights", "The score policy is faulty, so no score is given."},
        {"invalid_edges", "The score policy is faulty, so no score is given."},
        {"invalid_model", "The score policy is faulty, so no score is given."},
    };
    for (const auto& c : cases) {
        INFO("withheld = " << c.token);
        auto model = populated_model();
        model.apps[0].figures.score = stability_detail::withheld_result(c.token);
        const auto page = render_dex_apps_fragment(model, 7, "all");
        const auto score = cell(page, model.apps[0].subject, "", kColScore);
        CHECK(contains(score, "<span class=\"dx-sc\">Withheld</span>"));
        CHECK(contains(score, c.words));
        CHECK_FALSE(contains(score, c.token)); // a known token is never printed raw
    }
    // an unknown token is shown, escaped
    auto model = populated_model();
    model.apps[0].figures.score = stability_detail::withheld_result("<i>odd");
    const auto score = cell(render_dex_apps_fragment(model, 7, "all"), model.apps[0].subject, "", kColScore);
    CHECK(contains(score, "No score is given (reason: <code class=\"dx-code\">&lt;i&gt;odd</code>)."));
    CHECK_FALSE(contains(score, "<i>odd"));
    // offline_affected names the gap in devices
    model = populated_model();
    model.apps[0].figures.distinct_devices = 9; // 7 online of 9 affected
    model.apps[0].figures.score = stability_detail::withheld_result("offline_affected");
    CHECK(contains(cell(render_dex_apps_fragment(model, 7, "all"), model.apps[0].subject, "", kColScore),
                   "2 of 9 affected devices are offline, so no score is given."));
}

TEST_CASE("DEX apps UI: the tone follows the closed band token, not the tier name", "[dex][apps_ui]") {
    DexPolicyInForce policy;
    policy.policy.tiers.names = {"One", "Two", "Three", "Four"};
    const struct {
        StabilityBand band;
        const char* tone;
        const char* name;
    } bands[] = {{StabilityBand::Excellent, "excellent", "One"},
                 {StabilityBand::Good, "good", "Two"},
                 {StabilityBand::Fair, "fair", "Three"},
                 {StabilityBand::Poor, "poor", "Four"}};
    for (const auto& b : bands) {
        auto model = model_of(populated_rows(), 50, "all", policy);
        model.apps[0].figures.score.band = b.band;
        const auto score = cell(render_dex_apps_fragment(model, 7, "all"), model.apps[0].subject, "", kColScore);
        CHECK(contains(score, std::string("<summary class=\"dx-sc ") + b.tone + "\">" + b.name + " "));
    }
}

TEST_CASE("DEX apps UI: the page equals GET /api/v1/dex/apps, per row and per column", "[dex][apps_ui]") {
    const auto model = populated_model();
    const auto page = render_dex_apps_fragment(model, 7, "all");
    const auto j = json::parse(dex_apps_json(model));
    REQUIRE(j["apps"].size() == 2);

    // Test-local formatting (not the renderer's helpers): the shown figure must equal the payload's.
    auto fig = [](double v) { return std::format("{:.1f}", v); };
    // `shown_version` is the version text on the page ("" addresses the application row).
    auto check_figures = [&](const std::string& subject, const std::string& shown_version, const json& o) {
        INFO("row " << subject << " / '" << shown_version << "'");
        const auto col = [&](int c) { return cell(page, subject, shown_version, c); };
        CHECK(has_number(col(kColCrashes), std::to_string(o["crashes"].get<int64_t>())));
        CHECK(has_number(col(kColHangs), std::to_string(o["hangs"].get<int64_t>())));
        // Anchored to the markup, so the total and the online figure cannot stand in for each other.
        CHECK(contains(col(kColDevices),
                       "<span class=\"v\">" + std::to_string(o["distinct_devices"].get<int64_t>()) + "</span>"));
        CHECK(contains(col(kColDevices), "<span class=\"s nw\">" +
                                             std::to_string(o["distinct_devices_online"].get<int64_t>()) +
                                             " online</span>"));
        for (const char* k : {"estimate", "lower", "upper"}) {
            CHECK(has_number(col(kColShare), fig(o["share_affected"][k].get<double>() * 100.0)));
            CHECK(has_number(col(kColRate), fig(o["rate_per_1000"][k].get<double>())));
        }
        CHECK(has_number(col(kColScore), fig(o["score"]["score"].get<double>())));
        for (const auto& d : o["score"]["deductions"]) {
            if (d["assessed"].get<bool>())
                CHECK(has_number(col(kColScore), std::format("{:.2f}", d["points"].get<double>())));
            else
                CHECK(contains(col(kColScore), "not assessed")); // an unassessed deduction has no points
        }
        // Last seen: the REST timestamp split at its 'T', each half in its own no-wrap span, in order.
        const std::string ts = o["last_seen"].get<std::string>();
        const auto t = ts.find('T');
        REQUIRE(t != std::string::npos);
        CHECK(contains(col(kColLastSeen), "<span class=\"nw\">" + ts.substr(0, t) +
                                              "</span> <span class=\"nw\">" + ts.substr(t + 1) + "</span>"));
    };
    for (const auto& a : j["apps"]) {
        const std::string subject = a["subject"];
        check_figures(subject, "", a);
        // version_count sits in that application's Versions expander
        CHECK(contains(cell(page, subject, "", kColApp),
                       "<summary>" + std::to_string(a["version_count"].get<int64_t>()) + " versions</summary>"));
        for (const auto& v : a["versions"]) {
            const std::string ver = v["version"].get<std::string>();
            check_figures(subject, ver.empty() ? "unknown version" : ver, v);
        }
    }

    // Page-level figures sit inside their own caption or note.
    CHECK(contains(page, "<b>Population</b> " + std::to_string(j["population"].get<int64_t>()) + " devices online now"));
    CHECK(j["population_basis"] == "all_online");
    for (const char* tier : {"excellent", "good", "fair"}) {
        const auto& t = j["policy"]["tiers"][tier];
        CHECK(contains(page, t["name"].get<std::string>() + " from " + std::format("{:g}", t["edge"].get<double>())));
    }
    CHECK(contains(page, j["policy"]["tiers"]["poor"]["name"].get<std::string>() + " below " +
                             std::format("{:g}", j["policy"]["tiers"]["fair"]["edge"].get<double>())));
    CHECK(contains(page, "revision <code class=\"dx-code\">" + j["policy"]["revision"].get<std::string>() + "</code>"));
}

TEST_CASE("DEX apps UI: payload key-set parity, both directions", "[dex][apps_ui]") {
    // Every key path the Apps payload publishes (arrays collapsed to `[]`). A field added to the payload
    // fails here until the page shows it, or this test declares it omitted below.
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
    const auto payload = json::parse(dex_apps_json(populated_model()));
    flatten(payload, "");

    std::set<std::string> shown;
    // population_basis is shown in words, in the Population caption; the test case "DEX apps UI:
    // population_basis is shown in words in the Population caption, per scope" binds each token to
    // its caption words.
    for (const char* k : {"window", "apps", "apps_total", "apps_truncated", "population", "population_basis",
                          "crash_source_coverage", "crash_source_coverage.windows",
                          "crash_source_coverage.macos", "crash_source_coverage.linux", "policy",
                          "policy.source", "policy.revision", "policy.fault", "policy.tiers"})
        shown.insert(k);
    for (const char* t : {"excellent", "good", "fair"})
        for (const char* f : {"", ".edge", ".name"})
            shown.insert(std::string("policy.tiers.") + t + f);
    shown.insert("policy.tiers.poor");
    shown.insert("policy.tiers.poor.name");
    auto figures = [&](const std::string& p) {
        for (const char* k : {"crashes", "hangs", "distinct_devices", "distinct_devices_online", "last_seen",
                              "share_affected", "rate_per_1000", "score", "score.score", "score.band",
                              "score.withheld", "score.deductions", "score.deductions[].name",
                              "score.deductions[].points", "score.deductions[].assessed"})
            shown.insert(p + "." + k);
        for (const char* g : {"share_affected", "rate_per_1000"})
            for (const char* f : {"estimate", "lower", "upper", "reliable"})
                shown.insert(p + "." + g + "." + f);
    };
    figures("apps[]");
    figures("apps[].versions[]");
    for (const char* k : {"subject", "profile", "versions", "version_count", "versions_truncated"})
        shown.insert(std::string("apps[].") + k);
    shown.insert("apps[].versions[].version");
    // Declared omitted, one reason each. policy.tiers.poor.edge: Poor's lower edge is the fixed floor of 0,
    // not a stored field (dex_read_model.cpp), so the page prints "<Poor> below <Fair edge>" and never
    // this key. The omission holds only while that floor is 0, pinned below.
    const std::set<std::string> declared_omitted = {"policy.tiers.poor.edge"};

    std::set<std::string> accounted = shown;
    accounted.insert(declared_omitted.begin(), declared_omitted.end());
    for (const auto& p : published) {
        INFO("payload key '" << p << "' is neither shown nor declared omitted");
        CHECK(accounted.count(p) == 1);
    }
    for (const auto& p : shown) {
        INFO("page map names '" << p << "' but the payload no longer carries it");
        CHECK(published.count(p) == 1);
    }
    for (const auto& p : declared_omitted) {
        INFO("declared omitted '" << p << "' but the payload no longer carries it (stale declaration)");
        CHECK(published.count(p) == 1);
        CHECK(shown.count(p) == 0);
    }
    CHECK(payload["policy"]["tiers"]["poor"]["edge"] == 0.0); // a non-zero floor fails until the page prints it

    // The one page figure with no Apps-REST key: the interval confidence level.
    for (const auto& p : published)
        CHECK(p.find("confidence") == std::string::npos);
    CHECK(contains(render_dex_apps_fragment(populated_model(), 7, "all"), "Intervals at 95% confidence"));
}

TEST_CASE("DEX apps UI: population_basis is shown in words in the Population caption, per scope",
          "[dex][apps_ui]") {
    // Test-local table of basis token to caption words; a token with no entry fails.
    const std::map<std::string, std::string> words = {{"all_online", "all platforms"},
                                                      {"windows_online", "Windows"},
                                                      {"macos_online", "macOS"},
                                                      {"linux_online", "Linux"}};
    for (const char* scope : {"all", "windows", "macos", "linux"}) {
        INFO("scope = " << scope);
        const auto model = model_of(populated_rows(), 50, scope);
        const auto basis = json::parse(dex_apps_json(model))["population_basis"].get<std::string>();
        const auto it = words.find(basis);
        REQUIRE(it != words.end());
        CHECK(contains(render_dex_apps_fragment(model, 7, scope),
                       "<b>Population</b> 50 devices online now (" + it->second + ")."));
    }
}

TEST_CASE("DEX apps UI: a non-zero figure never prints as zero", "[dex][apps_ui]") {
    const auto page = render_dex_apps_fragment(
        model_of({apps_total_row("rare.exe", 1, 0, 1, 1, 0, 1, 1, "2026-10-14T01:00:00Z")}, 1000000), 7, "all");
    CHECK(contains(cell(page, "rare.exe", "", kColRate), "&lt;0.1"));
    CHECK(contains(cell(page, "rare.exe", "", kColShare), "&lt;0.1%"));
}

TEST_CASE("DEX apps UI: platform and window chips are native buttons", "[dex][apps_ui]") {
    const struct {
        const char* platform;
        const char* label;
    } platforms[] = {{"all", "All platforms"}, {"windows", "Windows"}, {"macos", "macOS"}, {"linux", "Linux"}};
    for (const auto& sel : platforms) {
        const auto page = render_dex_apps_fragment(model_of(populated_rows(), 50, sel.platform), 30, sel.platform);
        INFO("platform = " << sel.platform);
        CHECK(contains(page, "<button type=\"button\" class=\"gp-chip"));
        CHECK_FALSE(contains(page, "<a class=\"gp-chip"));
        // exactly one pressed chip per row: the selected platform and the selected window
        CHECK(count_of(page, "aria-pressed=\"true\"") == 2);
        CHECK(count_of(page, "aria-pressed=\"false\"") == 6);
        CHECK(contains(page, std::string("class=\"gp-chip on\" aria-pressed=\"true\" hx-get=\"/fragments/dex/apps?window=30d&amp;platform=") + sel.platform + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + sel.label + "</button>"));
        CHECK(contains(page, std::string("class=\"gp-chip on\" aria-pressed=\"true\" hx-get=\"/fragments/dex/apps?window=30d&amp;platform=") + sel.platform + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">30d</button>"));
        CHECK(contains(page, "button.gp-chip{line-height:inherit;font-variant-numeric:inherit}"));
    }
    // No htmx handler attribute and no script ever ships on this page.
    const auto page = render_dex_apps_fragment(populated_model(), 7, "all");
    CHECK_FALSE(contains(page, "hx-on"));
    CHECK_FALSE(contains(page, "<script"));
    CHECK_FALSE(contains(page, "onclick"));
}

TEST_CASE("DEX apps UI: agent-reported and customer-authored strings are escaped", "[dex][apps_ui]") {
    DexPolicyInForce policy;
    policy.source = "custom";
    policy.revision = "<rev>&\"";
    policy.fault = "<fault>";
    policy.policy.tiers.names = {"<b>", "g&d", "fair\"", "<i>"};
    const std::string subject = "<script>\"x";
    const std::vector<DexAppStabilityRow> rows = {
        apps_total_row(subject, 12, 3, 7, 10, 3, 1, 1, "<ts>"),
        apps_version_row(subject, "a&b", 12, 3, 7, 10, 3, "<ts>"),
    };
    const auto page = render_dex_apps_fragment(model_of(rows, 50, "all", policy), 7, "all");
    for (const char* raw : {"<script>", "<rev>", "<fault>", "<ts>", "a&b", "g&d"})
        CHECK_FALSE(contains(page, raw));
    CHECK(contains(page, "&lt;b&gt;")); // a tier name, escaped
    CHECK(contains(page, "&lt;i&gt;"));
    CHECK(contains(page, "&lt;script&gt;&quot;x"));
    CHECK(contains(page, "a&amp;b"));
    CHECK(contains(page, "<span class=\"nw\">&lt;ts&gt;</span>")); // no 'T': one span around the escaped whole
    // the drill hx-get carries the percent-encoded subject
    CHECK(contains(page, "/fragments/dex/app?name=%3Cscript%3E%22x&window=7d"));
    // an empty subject is words, not a link
    const auto unk = render_dex_apps_fragment(
        model_of({apps_total_row("", 2, 0, 1, 2, 0, 1, 1, "2026-10-14T01:00:00Z")}, 50), 7, "all");
    CHECK(contains(unk, "&lt;unknown&gt;"));
    CHECK_FALSE(contains(unk, "/fragments/dex/app?name="));
    // a missing last_seen and a missing version list read in words
    auto model = populated_model();
    REQUIRE(model.apps[0].subject == "wide.exe"); // ranked first: 26 events against 15
    model.apps[0].figures.last_seen.clear();
    model.apps[1].versions.clear();
    model.apps[1].version_count = 0;
    const auto words = render_dex_apps_fragment(model, 7, "all");
    CHECK(contains(cell(words, "wide.exe", "", kColLastSeen), "unknown"));
    CHECK(contains(cell(words, "app1.exe", "", kColApp), "version not collected"));
}

TEST_CASE("DEX apps UI: the pre-rendered page stays under its size ceiling", "[dex][apps_ui]") {
    // 100 applications x 20 versions: every version is pre-rendered, so this is the worst page. It
    // measures about 2.5 MB uncompressed (every row carries its score decomposition and both
    // denominators); 3 MiB is the regression lock, and a lazy per-application versions resource is
    // the real fix.
    std::vector<DexAppStabilityRow> rows;
    for (int a = 0; a < 100; ++a) {
        const std::string name = "app" + std::to_string(a) + ".exe";
        rows.push_back(apps_total_row(name, 600 + a, 40, 30, 150, 40, 20, 100, "2026-10-14T01:00:00Z"));
        for (int v = 0; v < 20; ++v)
            rows.push_back(apps_version_row(name, "1." + std::to_string(v), 30, 2, 25 - (v % 5), 30, 2,
                                            "2026-10-14T01:00:00Z"));
    }
    const auto page = render_dex_apps_fragment(model_of(rows, 5000), 7, "all");
    INFO("rendered " << page.size() << " bytes");
    CHECK(page.size() < 3u * 1024u * 1024u);
}

namespace {
struct AppsRouteFixture {
    DexRoutes routes;
    yuzu::server::test::TestRouteSink sink; // after the route owner: its handlers capture `routes`
    std::vector<std::pair<std::string, std::string>> calls; // (window, scope) the API saw
    DexAppsModel next = populated_model();

    explicit AppsRouteFixture(bool wire_api = true) {
        auto okAuth = [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        };
        auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                         const std::string&) { return true; };
        auto fleet = []() { return DexFleet{}; };
        routes.register_routes(sink, okAuth, okPerm, /*store=*/nullptr, fleet, /*audit_fn=*/{});
        if (wire_api)
            routes.set_dex_api(std::make_shared<yuzu::server::test::FnDexApi>(
                yuzu::server::test::FnDexApi::DeviceScoreFn{}, yuzu::server::test::FnDexApi::DeviceHistoryFn{},
                yuzu::server::test::FnDexApi::ObservationFn{}, yuzu::server::test::FnDexApi::AppFn{},
                [this](const std::string& window, const std::string& scope) {
                    calls.emplace_back(window, scope);
                    return next;
                }));
    }
};
} // namespace

TEST_CASE("DEX apps UI: the route reads DexApi::apps with canonical window and platform", "[dex][apps_ui]") {
    AppsRouteFixture f;
    auto r = f.sink.Get("/fragments/dex/apps");
    REQUIRE(r);
    CHECK(r->status == 200);
    REQUIRE(f.calls.size() == 1);
    CHECK(f.calls[0] == std::make_pair(std::string("7d"), std::string("all")));
    CHECK(contains(r->body, "app1.exe"));

    r = f.sink.Get("/fragments/dex/apps?window=30d&platform=linux");
    REQUIRE(r);
    CHECK(r->status == 200);
    REQUIRE(f.calls.size() == 2);
    CHECK(f.calls[1] == std::make_pair(std::string("30d"), std::string("linux")));

    // A hostile window is canonicalised to 7d and never reflected.
    r = f.sink.Get("/fragments/dex/apps?window=%22%3E%3Cb%3Eevil&platform=all");
    REQUIRE(r);
    CHECK(r->status == 200);
    REQUIRE(f.calls.size() == 3);
    CHECK(f.calls[2].first == "7d");
    CHECK_FALSE(contains(r->body, "evil"));
}

TEST_CASE("DEX apps UI: an unknown platform never reaches the API", "[dex][apps_ui]") {
    AppsRouteFixture f;
    const auto r = f.sink.Get("/fragments/dex/apps?platform=%3Cscript%3Ealert(1)");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(f.calls.empty());
    CHECK(contains(r->body, "<b>Unknown platform</b>"));
    CHECK_FALSE(contains(r->body, "<script>alert"));
    CHECK_FALSE(contains(r->body, "%3Cscript"));
    CHECK_FALSE(contains(r->body, "alert(1)"));
}

TEST_CASE("DEX apps UI: no DexApi wired, or a degraded model, is an error panel (200)", "[dex][apps_ui]") {
    AppsRouteFixture unwired(/*wire_api=*/false);
    auto r = unwired.sink.Get("/fragments/dex/apps");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "Application stability is unavailable"));
    CHECK_FALSE(contains(r->body, "No data"));
    CHECK_FALSE(contains(r->body, "<table"));

    AppsRouteFixture degraded;
    degraded.next = degraded_model("score_policy_invalid");
    r = degraded.sink.Get("/fragments/dex/apps?platform=windows");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "Application stability is unavailable"));
    CHECK(contains(r->body, "score_policy_invalid"));
    CHECK_FALSE(contains(r->body, "Scoring policy"));
    CHECK_FALSE(contains(r->body, "Population"));
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

    const auto html = render_dex_observation_fragment(r);
    CHECK(html == "<div class=\"gp-sech\">App crash <span class=\"gp-mute mono\">"
                  "process.crashed</span></div><div class=\"gp-spec\"><span class=\"k\">When"
                  "</span><code>2026-01-01T00:00:00Z</code><span class=\"k\">Subject</span>"
                  "<code>notepad.exe</code><span class=\"k\">Code</span><code>0xC0000005</code>"
                  "<span class=\"k\">Symbolic</span><code>ACCESS_VIOLATION</code><span "
                  "class=\"k\">Component</span><code>ntdll.dll</code><span class=\"k\">Metric"
                  "</span><code>&mdash;</code><span class=\"k\">Device</span><code>"
                  "dex-gold-obs-1</code><span class=\"k\">Platform</span><code>windows</code>"
                  "<span class=\"k\">Event id</span><code>evt-golden-1</code></div>");
    // NOTE: this cell's `observed_at` literal ("2026-01-01T00:00:00Z") IS an
    // ISO-8601 UTC timestamp, so normalize_time() rewrites it to "<TS>" in
    // the golden file exactly like a wall-clock-anchored one — deliberate
    // (the normaliser can't and shouldn't distinguish "fixed literal" from
    // "computed from now()"; both are the same shape).
    check_golden("observation__full-fields", html);
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
    check_golden("observation_route__null-store", r->body);
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
