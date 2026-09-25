/**
 * test_dex_routes.cpp — DEX dashboard render + route gating (multi-signal).
 *
 * Pure render tests against a seeded GuaranteedStateStore:
 *   - null / empty store renders the "no data" placeholder (NO mock data)
 *   - a seeded store renders REAL aggregations (signals / apps / boot / modules)
 *   - crash-free-% computes from the fleet denominator; no denominator → honest "—"
 *   - hang column + boot panel + friendly signal labels (incl. unknown-type fallback)
 *   - agent-reported values are HTML-escaped (no stored XSS)
 *   - route gating: authed renders / unauth → 302 / perm-denied → 403 before audit
 */
#include "dex_routes.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_dex_perf_api_double.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own GuaranteedStateStore against a clone of this schema
// (ADR-0038 migration).
yuzu::test::PgTestTemplate guardian_pg_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};
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

void seed_boot(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
               double ms, const std::string& ts) {
    seed_signal(store, id, agent, "os.boot",
                "{\"subject\":\"boot\",\"metric\":" + std::to_string(ms) +
                    ",\"platform\":\"windows\"}",
                ts);
}

// Extracts one family's rendered health score from a Catalogue View-1 grid
// (render_dex_catalogue_fragment output) — nullopt when the card shows the
// suppressed "&mdash;" marker instead of a number. Anchors on the family name
// inside its own "fn" div so distinct cards never collide.
std::optional<int> family_score(const std::string& html, const std::string& family) {
    const auto name_pos = html.find("<div class=\"fn\">" + family + "<span");
    if (name_pos == std::string::npos)
        return std::nullopt;
    const auto fev_pos = html.find("<div class=\"fev", name_pos);
    if (fev_pos == std::string::npos)
        return std::nullopt;
    const auto gt = html.find('>', fev_pos);
    const auto lt = html.find('<', gt);
    const std::string inner = html.substr(gt + 1, lt - gt - 1);
    if (inner.find("mdash") != std::string::npos)
        return std::nullopt;
    return std::stoi(inner);
}

// Extracts the family drill-down's Health-score tile (render_dex_catalogue_group_fragment
// output, View 2) — nullopt when no Health-score tile rendered at all (mon==0 or the
// denominator is 0, so the score is suppressed rather than shown as a number).
std::optional<int> group_score(const std::string& html) {
    // Anchor on the tile's LABEL div — the drill-down's subnav also contains a
    // bare "Health score" link text, which must not match.
    const auto lbl_pos = html.find("<div class=\"l\">Health score");
    if (lbl_pos == std::string::npos)
        return std::nullopt;
    const auto n_pos = html.rfind("<div class=\"n ", lbl_pos);
    if (n_pos == std::string::npos)
        return std::nullopt;
    const auto gt = html.find('>', n_pos);
    const auto lt = html.find('<', gt);
    return std::stoi(html.substr(gt + 1, lt - gt - 1));
}

// Route fragments filter signals by a now()-relative window (the handler computes
// `dex_iso_since(window_to_days)` as the cutoff), so seeds with hardcoded calendar
// dates age out of the window and the route tests start failing once the wall
// clock passes them — they did on 2026-06-15, when the old 2026-06-08/09 seeds
// fell outside the default 7-day window. Anchor seed dates a few days back from
// *now* instead. Date-only: each seed appends its own "Thh:mm:ssZ" suffix, so
// intra-test ordering is preserved. dex_iso_since is the very helper the route
// cutoff uses, so these can never drift from it.
const std::string kDayA = dex_iso_since(3).substr(0, 10); // older (was 2026-06-08)
const std::string kDayB = dex_iso_since(2).substr(0, 10); // newer (was 2026-06-09)
} // namespace

TEST_CASE("DEX overview: null store renders no-data placeholder", "[dex][routes]") {
    auto html = render_dex_overview_fragment(nullptr, "", 7, DexFleet{});
    CHECK(html.find("gp-placeholder") != std::string::npos);
    CHECK(html.find("unavailable") != std::string::npos);
}

TEST_CASE("DEX catalogue: family fragments surface ALL 114 monitored types, quiet ones too",
          "[pg][dex][routes][catalogue]") {
    // Visibility contract (Dave 2026-06-10): operators must see what the fleet
    // is MONITORING, not just what fired — every catalogued type renders inside
    // its family, quiet ones as muted real-zero rows. Zeros are facts, not mock
    // data. The hub slimmed to summarise-and-link (the old All-signals panel was
    // retired), so the contract now lives on the Catalogue: rendering all 12
    // family fragments must surface every label. This list mirrors kAllObsTypes
    // in test_dex_signals.cpp — the two-sided drift net for catalogue additions.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // Raw family names (literal '&') match dex_signal_groups(); a wrong name
    // would render "Unknown family" and its labels would go missing below.
    std::string html;
    // All three platforms connected → every catalogued type is MONITORED
    // (coverage-first), so quiet types render as watched real-zero rows.
    const DexFleet all_os{1, 1, {"windows", "linux", "darwin"}};
    for (const char* family :
         {"App reliability", "Boot, start-up & shutdown", "Service health", "System stability",
          "Hardware & storage", "Performance", "File system", "Network", "Identity & logon",
          "Security & protection", "Updates & installs", "Policy & management", "Printing"})
        html += render_dex_catalogue_group_fragment(&store, "", 7, family, all_os);

    // All 114 labels.
    for (const char* label :
         {// wave 1
          "App crash", "App hang", "Service crash", "Service start failure",
          "Blue screen (bugcheck)", "Unexpected reboot", "Display driver reset",
          "Hardware error", "Disk error", "Filesystem corruption", "Memory exhaustion",
          ">Boot<", "Update failure", "App install failure", "Profile failure",
          "Group Policy failure", "Wi-Fi disconnect", "DNS timeout", "IP address conflict",
          "Print failure",
          // wave 2
          "Slow boot: application", "Slow boot: driver", "Slow boot: service",
          "Slow boot: device", ">Shutdown<", "Slow shutdown: application", "Standby/resume",
          "Slow resume", "Slow logon (subscriber)", "Uptime report", "Dirty shutdown",
          "Clock unsynchronized", "Windows activation failure", "Shadow copy error",
          "Registry hive recovered", "Disk check at boot", "App crash (.NET)",
          "App dependency error", "App activation failure", "COM server failure",
          "Error dialog shown", "App blocked shutdown", "Service hung",
          "Service start timeout", "Service logon failure", "Service recovery failure",
          "Disk SMART warning", "Disk nearly full", "Storage port reset", "Lost delayed write",
          "Database corruption", "Device start failure", "CPU throttled",
          "Wi-Fi connect failure", "DHCP failure", "VPN failure", "File share failure",
          "Name conflict", "No domain controller", "Kerberos error",
          "Profile unload blocked", "Folder redirection failure", "Real-time protection off",
          "Malware detected", "AV update failure", "Tamper attempt blocked",
          "App uninstall failure", "Store app install failure", "Download failure (BITS)",
          "Printer driver failure", "Print spooler plug-in failure",
          // wave 3
          "Fast startup failure", "Resume from sleep", "Restart initiated",
          "Restore points lost", "Crash dump disabled", "Window manager exited",
          "App file-access failure", "Notification platform error", "File association reset",
          "App repository error", "Service dependency failure", "Disk flush failure",
          "Peripheral driver error", "TPM error", "TCP port exhaustion", "Share write lost",
          "DNS registration failure", "Remote session disconnect", "Logon process terminated",
          "Machine trust failure", "Biometric sensor error", "Windows Hello error",
          "Entra ID token error", "Authentication error", "TLS failure",
          "Threat removal failure", "Protection engine error", "BitLocker error",
          "Certificate enrollment failure", "Update check failure", "Update download failure",
          "Policy extension failure", "MDM/Intune error",
          // A3 sustained perf breaches (Windows state poll, dex_perf_breach)
          "Sustained high CPU", "Memory pressure", "High disk latency",
          // wave 4 (2026-06-22) — power-management + driver reliability
          "Modern standby exit", "Adapter driver dump", "Driver load failure",
          "Battery error",
          // wave 4 batch 2 — cheap additions on already-armed channels
          "Service unresponsive", "Service shutdown failure", "Adapter reset"})
        CHECK(html.find(label) != std::string::npos);

    // No fabricated numbers: quiet rows carry a literal zero count. (The "All
    // 114 monitored signal types" headline is asserted on Catalogue View 1 by
    // the "lists every family + the sub-nav" test below.)
    CHECK(html.find("<td class=\"gp-num\">0</td>") != std::string::npos);
}

TEST_CASE("DEX catalogue grid lists every family + the sub-nav", "[pg][dex][routes][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // windows connected → all 114 catalogue types are monitored (coverage-first).
    const auto html =
        render_dex_catalogue_fragment(&store, "", 7, DexFleet{2, 2, {"windows"}}, "all");
    // shared DEX sub-nav (Overview + Catalogue live; Health/Trends muted)
    CHECK(html.find("/fragments/dex/overview") != std::string::npos);
    CHECK(html.find("gp-subnav") != std::string::npos);
    CHECK(html.find("actively monitored") != std::string::npos);
    CHECK(html.find("of 114 signal types") != std::string::npos);
    // every family heading renders as a card (escaped where needed)
    for (const char* fam : {"App reliability", "Network", "Hardware &amp; storage", "Printing",
                            "Service health", "Identity &amp; logon"})
        CHECK(html.find(fam) != std::string::npos);
    // a card drills into the family-detail fragment
    CHECK(html.find("/fragments/dex/catalogue/group?name=") != std::string::npos);
}

TEST_CASE("DEX catalogue: single-OS filter scores its OWN denominator + signals, "
          "no cross-OS bleed (#1746)",
          "[pg][dex][routes][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // network.wifi_drop (Network family) is monitored on both windows+macos
    // (dex_obs_platforms); seed it macOS-only so the family's macOS-scoped rollup
    // has exactly one signal, with a KNOWN max_signal_devices.
    seed_signal(store, "m1", "MAC-1", "network.wifi_drop",
                R"({"subject":"x","platform":"macos"})", kDayB + "T10:00:00Z");
    seed_signal(store, "m2", "MAC-2", "network.wifi_drop",
                R"({"subject":"x","platform":"macos"})", kDayB + "T10:05:00Z");

    DexFleet fleet;
    fleet.total_online = 10;
    fleet.windows_online = 7;
    fleet.macos_online = 3;

    const auto html_before = render_dex_catalogue_fragment(&store, "", 7, fleet, "macos");
    const auto score_before = family_score(html_before, "Network");
    REQUIRE(score_before.has_value()); // (b) numeric — never suppressed once macos_online > 0

    // Hand-computed against the SAME macOS-scoped signal: "Network" is "med"
    // severity (6 pts, dex_family_weights) with default-preset mult 1.0;
    // max_signal_devices=2 (both MAC-1/MAC-2 hit); N=macos_online=3.
    const double impact_macos = 2.0 / 3.0;
    const int expected_macos =
        static_cast<int>(std::clamp(100.0 - 6.0 * impact_macos, 0.0, 100.0) + 0.5);
    CHECK(*score_before == expected_macos);

    // (a) Differential: had the route kept borrowing fleet.windows_online as the
    // denominator (the #1746 bug) for this SAME macOS signal, the score would be
    // different — proves macos_online, not windows_online, actually drives the
    // number.
    const double impact_if_windows_online = 2.0 / 7.0;
    const int score_if_windows_online =
        static_cast<int>(std::clamp(100.0 - 6.0 * impact_if_windows_online, 0.0, 100.0) + 0.5);
    CHECK(*score_before != score_if_windows_online);

    // Now add a Windows-only signal in the SAME family, on MORE devices than the
    // macOS one — if signals_scoped were still the all-OS aggregate (the bug),
    // this would dominate max_signal_devices and move the macOS card's score.
    seed_signal(store, "w1", "WIN-1", "network.dns_timeout",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:10:00Z");
    seed_signal(store, "w2", "WIN-2", "network.dns_timeout",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:15:00Z");
    seed_signal(store, "w3", "WIN-3", "network.dns_timeout",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:20:00Z");
    const auto html_after = render_dex_catalogue_fragment(&store, "", 7, fleet, "macos");
    const auto score_after = family_score(html_after, "Network");
    REQUIRE(score_after.has_value());
    CHECK(*score_after == *score_before); // no cross-OS contamination

    // The Windows lens scores off windows_online + the Windows-only signal.
    const auto html_win = render_dex_catalogue_fragment(&store, "", 7, fleet, "windows");
    const auto score_win = family_score(html_win, "Network");
    REQUIRE(score_win.has_value());
    const double impact_win = 3.0 / 7.0; // 3 devices / windows_online(7)
    const int expected_win =
        static_cast<int>(std::clamp(100.0 - 6.0 * impact_win, 0.0, 100.0) + 0.5);
    CHECK(*score_win == expected_win);
}

TEST_CASE("DEX catalogue: os=windows lens matches the unchanged 'all' composite "
          "(no regression, #1746)",
          "[pg][dex][routes][catalogue]") {
    // A Windows-only fleet reporting Windows-only signals: the "all" lens (kept
    // byte-unchanged by #1746) and the "windows" lens now compute off the SAME
    // denominator (windows_online) and the SAME signals (nothing else to scope
    // away), so they must render the identical score — proving the per-OS
    // refactor didn't regress the pre-existing Windows-denominated composite.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "c1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayB + "T10:00:00Z");
    seed_crash(store, "c2", "WS-2", "chrome.exe", "ntdll.dll", "windows", kDayB + "T10:05:00Z");
    seed_hang(store, "h1", "WS-3", "chrome.exe", kDayB + "T10:10:00Z");

    DexFleet fleet;
    fleet.total_online = 5;
    fleet.windows_online = 5;
    fleet.connected_os = {"windows"};

    const auto html_all = render_dex_catalogue_fragment(&store, "", 7, fleet, "all");
    const auto html_win = render_dex_catalogue_fragment(&store, "", 7, fleet, "windows");
    const auto score_all = family_score(html_all, "App reliability");
    const auto score_win = family_score(html_win, "App reliability");
    REQUIRE(score_all.has_value());
    REQUIRE(score_win.has_value());
    CHECK(*score_all == *score_win);
    // Exact value: "App reliability" is "high" severity (12 pts); max_signal_devices
    // = 2 (process.crashed on WS-1+WS-2 beats process.hung's 1); N=windows_online=5.
    const int expected = static_cast<int>(std::clamp(100.0 - 12.0 * (2.0 / 5.0), 0.0, 100.0) + 0.5);
    CHECK(*score_win == expected);
}

TEST_CASE("DEX catalogue grid: linux lens scores off linux_online, not macos/windows_online "
          "(differential, #1746 follow-up QE-a)",
          "[pg][dex][routes][catalogue]") {
    // A fleet with three DISTINCT positive per-OS online counts, so a regression
    // that borrowed macos_online or windows_online instead of linux_online can't
    // hide behind an accidental equal denominator.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "l1", "LNX-1", "process.crashed",
                R"({"subject":"x","platform":"linux"})", kDayB + "T10:00:00Z");
    seed_signal(store, "l2", "LNX-2", "process.crashed",
                R"({"subject":"x","platform":"linux"})", kDayB + "T10:05:00Z");

    DexFleet fleet;
    fleet.total_online = 14;
    fleet.windows_online = 7;
    fleet.linux_online = 4;
    fleet.macos_online = 3;
    fleet.connected_os = {"windows", "linux", "darwin"};

    const auto html = render_dex_catalogue_fragment(&store, "", 7, fleet, "linux");
    const auto score = family_score(html, "App reliability");
    REQUIRE(score.has_value());

    // Hand-computed against the linux-scoped signal alone: "App reliability" is
    // "high" severity (12 pts, dex_family_weights) with default-preset mult 1.0;
    // max_signal_devices=2 (both LNX-1/LNX-2 hit); N=linux_online=4.
    const double impact_linux = 2.0 / 4.0;
    const int expected_linux =
        static_cast<int>(std::clamp(100.0 - 12.0 * impact_linux, 0.0, 100.0) + 0.5);
    CHECK(*score == expected_linux);

    // Differential: had the denominator been macos_online(3) or windows_online(7)
    // instead of linux_online(4), the score would be a DIFFERENT number — proves
    // linux_online, not a borrowed neighbor, actually drives this lens.
    const int score_if_macos_online =
        static_cast<int>(std::clamp(100.0 - 12.0 * (2.0 / 3.0), 0.0, 100.0) + 0.5);
    const int score_if_windows_online =
        static_cast<int>(std::clamp(100.0 - 12.0 * (2.0 / 7.0), 0.0, 100.0) + 0.5);
    CHECK(*score != score_if_macos_online);
    CHECK(*score != score_if_windows_online);
}

TEST_CASE("DEX catalogue grid: macos_online=0 suppresses the score even with macOS "
          "signals seeded (divide-by-zero guard, QE-b)",
          "[pg][dex][routes][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // network.wifi_drop (Network family) IS macOS-collected (dex_obs_platforms),
    // so this family is MONITORED under the macos lens — the suppression below
    // must come from the N==0 guard, not from "nothing collects this".
    seed_signal(store, "m1", "MAC-1", "network.wifi_drop",
                R"({"subject":"x","platform":"macos"})", kDayB + "T10:00:00Z");

    DexFleet fleet;
    fleet.total_online = 7;
    fleet.windows_online = 7;
    fleet.macos_online = 0; // no macOS agents online right now
    fleet.connected_os = {"windows", "darwin"};

    const auto html = render_dex_catalogue_fragment(&store, "", 7, fleet, "macos");
    CHECK(family_score(html, "Network") == std::nullopt); // suppressed, never a fabricated number

    // Confirm the suppression is the N==0 guard, not the "dark / not collected"
    // path. The family IS monitored (mon>0) but has no online macOS agent, so
    // the card shows the distinct "no online agents reporting" affordance
    // (UP-8) — NOT the dark "not collected on your fleet" text, and NOT a
    // fabricated "health score" number. The rendered marker is the suppressed
    // em-dash.
    const auto name_pos = html.find("<div class=\"fn\">Network<span");
    REQUIRE(name_pos != std::string::npos);
    const auto next_card = html.find("<a class=\"gp-fcard", name_pos);
    const std::string card = html.substr(
        name_pos, next_card == std::string::npos ? std::string::npos : next_card - name_pos);
    CHECK(card.find("&mdash;") != std::string::npos);                  // suppressed marker
    CHECK(card.find("no online agents reporting") != std::string::npos); // mon>0, N==0 (not dark)
    CHECK(card.find("not collected on your fleet") == std::string::npos); // NOT the dark case
}

TEST_CASE("DEX catalogue grid: \"all\" lens pins to windows_online + the COMBINED "
          "all-OS signal set on a differentiating fleet (QE-d)",
          "[pg][dex][routes][catalogue]") {
    // windows_online(7) != total_online(14) so a regression to total_online can't
    // hide behind an accidental equality; the seeded signal spans THREE distinct
    // windows agents + TWO distinct linux agents so a regression that scoped the
    // "all" lens down to windows-only signals (instead of the combined all-OS
    // set) produces a different max_signal_devices too.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "w1", "WIN-1", "process.crashed",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:00:00Z");
    seed_signal(store, "w2", "WIN-2", "process.crashed",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:05:00Z");
    seed_signal(store, "w3", "WIN-3", "process.crashed",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:10:00Z");
    seed_signal(store, "l1", "LNX-1", "process.crashed",
                R"({"subject":"x","platform":"linux"})", kDayB + "T10:15:00Z");
    seed_signal(store, "l2", "LNX-2", "process.crashed",
                R"({"subject":"x","platform":"linux"})", kDayB + "T10:20:00Z");

    DexFleet fleet;
    fleet.total_online = 14;
    fleet.windows_online = 7;
    fleet.linux_online = 4;
    fleet.macos_online = 3;
    fleet.connected_os = {"windows", "linux", "macos"};

    const auto html = render_dex_catalogue_fragment(&store, "", 7, fleet, "all");
    const auto score = family_score(html, "App reliability");
    REQUIRE(score.has_value());

    // Hand-computed: "App reliability" is "high" severity (12 pts) with default
    // mult 1.0; max_signal_devices=5 (the COMBINED process.crashed set: 3 windows
    // + 2 linux agents, ONE signal type under the unscoped rollup);
    // N=windows_online=7 (the established "all"-lens denominator, byte-unchanged
    // by #1746).
    const double impact_all = 5.0 / 7.0;
    const int expected_all =
        static_cast<int>(std::clamp(100.0 - 12.0 * impact_all, 0.0, 100.0) + 0.5);
    CHECK(*score == expected_all);

    // (a) Regression to total_online(14) as the denominator, same combined
    // signal set — a DIFFERENT number.
    const int score_if_total_online =
        static_cast<int>(std::clamp(100.0 - 12.0 * (5.0 / 14.0), 0.0, 100.0) + 0.5);
    CHECK(*score != score_if_total_online);

    // (b) Regression to a windows-only signal set (3 devices, not the combined 5)
    // under windows_online(7) — also a DIFFERENT number.
    const int score_if_windows_only_signals =
        static_cast<int>(std::clamp(100.0 - 12.0 * (3.0 / 7.0), 0.0, 100.0) + 0.5);
    CHECK(*score != score_if_windows_only_signals);
}

TEST_CASE("DEX catalogue family lists its signals; unknown family is escaped",
          "[pg][dex][routes][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // Windows connected → the Windows-collected Network types are MONITORED.
    const DexFleet win{1, 1, {"windows"}};
    const auto net = render_dex_catalogue_group_fragment(&store, "", 7, "Network", win);
    CHECK(net.find("Wi-Fi disconnect") != std::string::npos); // friendly label
    CHECK(net.find("monitored") != std::string::npos);        // coverage-first pill
    CHECK(net.find("Windows") != std::string::npos);          // coverage detail
    CHECK(net.find("&larr; All families") != std::string::npos);
    // OS chips are present IN the family view so the filter is changeable in place.
    CHECK(net.find("/fragments/dex/catalogue/group?name=Network&window=7d&os=windows") !=
          std::string::npos);
    // unknown family → placeholder; the reflected name is HTML-escaped (no XSS)
    const auto bad = render_dex_catalogue_group_fragment(&store, "", 7, "<script>x</script>", win);
    CHECK(bad.find("Unknown family") != std::string::npos);
    CHECK(bad.find("<script>") == std::string::npos);
    // OS filter persists: the back-link to the grid carries the lens.
    const DexFleet lin_fleet{0, 0, {"linux"}};
    const auto lin = render_dex_catalogue_group_fragment(&store, "", 7, "Network", lin_fleet, "linux");
    CHECK(lin.find("/fragments/dex/catalogue?window=7d&os=linux") != std::string::npos);
    // Coverage-first: a Windows-only type reads "not collected" under the Linux lens.
    CHECK(lin.find("not collected") != std::string::npos);
}

TEST_CASE("DEX catalogue drill-down: single-OS filter scores its OWN denominator + "
          "signals, no cross-OS bleed (BR-001, #1746 follow-up)",
          "[pg][dex][routes][catalogue]") {
    // BR-001 (Codex branch review, Architect-confirmed): the grid (View 1) scores
    // per-OS under a single-OS filter (see the "#1746" test above), but the family
    // drill-down (View 2) still read the all-OS signal set and scored with
    // fleet.windows_online — so clicking into a family silently reverted to a
    // Windows-denominated all-OS score under the same os= label. Same signal
    // shape as the grid's #1746 test, replayed against
    // render_dex_catalogue_group_fragment.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "m1", "MAC-1", "network.wifi_drop",
                R"({"subject":"x","platform":"macos"})", kDayB + "T10:00:00Z");
    seed_signal(store, "m2", "MAC-2", "network.wifi_drop",
                R"({"subject":"x","platform":"macos"})", kDayB + "T10:05:00Z");

    DexFleet fleet;
    fleet.total_online = 10;
    fleet.windows_online = 7;
    fleet.macos_online = 3;
    fleet.connected_os = {"windows", "darwin"};

    const auto html_before =
        render_dex_catalogue_group_fragment(&store, "", 7, "Network", fleet, "macos");
    const auto score_before = group_score(html_before);
    REQUIRE(score_before.has_value()); // (c) numeric — never the suppressed marker

    // Hand-computed against the macOS-scoped signal alone: "Network" is "med"
    // severity (6 pts, dex_family_weights) with default-preset mult 1.0;
    // max_signal_devices=2 (both MAC-1/MAC-2 hit); N=macos_online=3.
    const double impact_macos = 2.0 / 3.0;
    const int expected_macos =
        static_cast<int>(std::clamp(100.0 - 6.0 * impact_macos, 0.0, 100.0) + 0.5);
    CHECK(*score_before == expected_macos);

    // (a) Differential: had BR-001 persisted, this SAME macOS card would instead
    // read the all-OS signal set scored against windows_online — a provably
    // different number (same 2 devices, wrong denominator).
    const double impact_if_buggy = 2.0 / 7.0; // 2 devices / windows_online(7)
    const int score_if_buggy =
        static_cast<int>(std::clamp(100.0 - 6.0 * impact_if_buggy, 0.0, 100.0) + 0.5);
    CHECK(*score_before != score_if_buggy);

    // Now add a Windows-only signal in the SAME family, on MORE devices than the
    // macOS one — under BR-001 this all-OS signal would dominate
    // max_signal_devices and move the macOS card's score.
    seed_signal(store, "w1", "WIN-1", "network.dns_timeout",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:10:00Z");
    seed_signal(store, "w2", "WIN-2", "network.dns_timeout",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:15:00Z");
    seed_signal(store, "w3", "WIN-3", "network.dns_timeout",
                R"({"subject":"x","platform":"windows"})", kDayB + "T10:20:00Z");
    const auto html_after =
        render_dex_catalogue_group_fragment(&store, "", 7, "Network", fleet, "macos");
    const auto score_after = group_score(html_after);
    REQUIRE(score_after.has_value());
    CHECK(*score_after == *score_before); // (b) no cross-OS contamination

    // The Windows lens, by contrast, DOES pick up dns_timeout scored against
    // windows_online — the number BR-001 was wrongly giving the macOS card.
    const auto html_win =
        render_dex_catalogue_group_fragment(&store, "", 7, "Network", fleet, "windows");
    const auto score_win = group_score(html_win);
    REQUIRE(score_win.has_value());
    const double impact_win = 3.0 / 7.0; // 3 devices / windows_online(7)
    const int expected_win =
        static_cast<int>(std::clamp(100.0 - 6.0 * impact_win, 0.0, 100.0) + 0.5);
    CHECK(*score_win == expected_win);
}

TEST_CASE("DEX catalogue routes: os=macos param survives route dispatch into both the "
          "grid and drill-down renderers (QE-handler)",
          "[pg][dex][routes][catalogue]") {
    // The #1746/BR-001 tests above prove the RENDER fns are per-OS-honest when
    // called directly; this exercises the actual ROUTE handlers (query-string
    // parsing → fleet_fn → render) so a regression that dropped `os=` on the way
    // in — e.g. a route that stopped reading req.get_param_value("os") — would
    // fail here even though the render fns themselves are still correct.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "m1", "MAC-1", "network.wifi_drop",
                R"({"subject":"x","platform":"macos"})", kDayB + "T10:00:00Z");
    seed_signal(store, "m2", "MAC-2", "network.wifi_drop",
                R"({"subject":"x","platform":"macos"})", kDayB + "T10:05:00Z");

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() {
        DexFleet f;
        f.total_online = 10;
        f.windows_online = 7;
        f.macos_online = 3;
        f.connected_os = {"windows", "darwin"};
        return f;
    };

    yuzu::server::test::TestRouteSink sink;
    DexRoutes routes;
    routes.register_routes(sink, okAuth, okPerm, &store, fleet, /*audit_fn=*/{});

    // Same hand-computed score as the #1746/BR-001 tests: "Network" is "med"
    // severity (6 pts) with default-preset mult 1.0; max_signal_devices=2
    // (MAC-1/MAC-2); N=macos_online=3.
    const double impact_macos = 2.0 / 3.0;
    const int expected =
        static_cast<int>(std::clamp(100.0 - 6.0 * impact_macos, 0.0, 100.0) + 0.5);

    // (1) Grid: GET the query-string form the "OS" chips actually emit
    // (?window=7d&os=macos, no encoding needed — "macos" has no reserved chars,
    // matching how the existing chip/back-link tests above call the harness).
    auto grid = sink.Get("/fragments/dex/catalogue?window=7d&os=macos");
    REQUIRE(grid);
    CHECK(grid->status == 200);
    // The macOS chip renders as the ACTIVE chip (proves the route read os=macos,
    // not just defaulted to "all").
    CHECK(grid->body.find(
              "<a class=\"gp-chip on\" hx-get=\"/fragments/dex/catalogue?window=7d&os=macos\"") !=
          std::string::npos);
    CHECK(family_score(grid->body, "Network") == expected); // macOS-scoped score, route → renderer

    // (2) Drill-down: same lens, one level down.
    auto group = sink.Get("/fragments/dex/catalogue/group?name=Network&window=7d&os=macos");
    REQUIRE(group);
    CHECK(group->status == 200);
    CHECK(group->body.find("<a class=\"gp-chip on\" hx-get=\"/fragments/dex/catalogue/group?"
                           "name=Network&window=7d&os=macos\"") != std::string::npos);
    CHECK(group_score(group->body) == expected);
}

TEST_CASE("DEX catalogue signal drill-down: subjects + live OS split; type escaped",
          "[pg][dex][routes][catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& subject,
                   const std::string& plat) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = "network.wifi_drop";
        r.severity = "info";
        r.detail_json = "{\"subject\":\"" + subject + "\",\"platform\":\"" + plat + "\"}";
        r.timestamp = kDayB + "T10:00:00Z";
        REQUIRE(store.insert_event(r));
    };
    obs("a", "agent-A", "CorpNet", "windows");
    obs("b", "agent-B", "CorpNet", "windows");
    obs("c", "mac-1", "Wi-Fi", "macos");

    const auto html = render_dex_catalogue_signal_fragment(&store, "", 7, "network.wifi_drop");
    CHECK(html.find("Wi-Fi disconnect") != std::string::npos); // friendly label (title)
    CHECK(html.find("Top subjects") != std::string::npos);
    CHECK(html.find("CorpNet") != std::string::npos);          // top subject
    CHECK(html.find("Windows + macOS") != std::string::npos);  // DERIVED-LIVE collected-on
    CHECK(html.find("Behavioral data") != std::string::npos);  // per-device PII banner
    CHECK(html.find("/fragments/dex/catalogue/group?name=") != std::string::npos); // back link

    // empty selection + a nasty obs_type (reflected) are handled safely
    CHECK(render_dex_catalogue_signal_fragment(&store, "", 7, "").find("No signal selected") !=
          std::string::npos);
    const auto bad = render_dex_catalogue_signal_fragment(&store, "", 7, "<img src=x onerror=y>");
    CHECK(bad.find("<img src=x") == std::string::npos); // escaped, no XSS
}

TEST_CASE("dex_normalize_os_filter maps a caller os param to a store-ready platform token",
          "[dex][routes]") {
    // The single source of truth shared by the dashboard, REST and MCP surfaces.
    CHECK(dex_normalize_os_filter("windows") == "windows");
    CHECK(dex_normalize_os_filter("linux") == "linux");
    CHECK(dex_normalize_os_filter("macos") == "macos");
    CHECK(dex_normalize_os_filter("all").empty());     // sentinel → all-OS
    CHECK(dex_normalize_os_filter("").empty());        // omitted → all-OS
    CHECK(dex_normalize_os_filter("Windows").empty()); // not canonical (case-sensitive)
    CHECK(dex_normalize_os_filter("darwin").empty());  // not a caller token
    CHECK(dex_normalize_os_filter("' OR 1=1").empty()); // junk → all-OS (never reaches SQL raw)
}

TEST_CASE("DEX catalogue signal drill-down: single-OS lens scopes the subject list (C-DEX-1)",
          "[pg][dex][routes][catalogue]") {
    // A single-OS Catalogue filter must scope the drilldown's subject/device/day
    // lists to that OS — no cross-OS bleed. (by_os stays cross-OS; that's the
    // split chart, exercised elsewhere.)
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& subject,
                   const std::string& plat) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = "network.wifi_drop";
        r.severity = "info";
        r.detail_json = "{\"subject\":\"" + subject + "\",\"platform\":\"" + plat + "\"}";
        r.timestamp = kDayB + "T10:00:00Z";
        REQUIRE(store.insert_event(r));
    };
    obs("a", "agent-A", "CorpNet", "windows");
    obs("b", "agent-B", "CorpNet", "windows");
    obs("c", "mac-1", "AirportWiFi", "macos");

    SECTION("macOS lens hides the Windows-only subject") {
        const auto html =
            render_dex_catalogue_signal_fragment(&store, "", 7, "network.wifi_drop", "macos");
        CHECK(html.find("AirportWiFi") != std::string::npos); // the macOS subject shows
        CHECK(html.find("CorpNet") == std::string::npos);     // the Windows subject is scoped out
    }
    SECTION("Windows lens hides the macOS-only subject") {
        const auto html =
            render_dex_catalogue_signal_fragment(&store, "", 7, "network.wifi_drop", "windows");
        CHECK(html.find("CorpNet") != std::string::npos);
        CHECK(html.find("AirportWiFi") == std::string::npos);
    }
    SECTION("the all-OS lens shows both subjects") {
        const auto html =
            render_dex_catalogue_signal_fragment(&store, "", 7, "network.wifi_drop", "all");
        CHECK(html.find("CorpNet") != std::string::npos);
        CHECK(html.find("AirportWiFi") != std::string::npos);
    }
}

TEST_CASE("DEX health score: transparent composite, decomposition, suppression",
          "[pg][dex][routes][health]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& plat) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = type;
        r.severity = "info";
        r.detail_json = "{\"subject\":\"x\",\"platform\":\"" + plat + "\"}";
        r.timestamp = kDayB + "T10:00:00Z";
        REQUIRE(store.insert_event(r));
    };
    obs("a", "agent-A", "process.crashed", "windows");
    obs("b", "agent-B", "network.wifi_drop", "windows");

    DexFleet fleet;
    fleet.windows_online = 10;
    const auto html = render_dex_health_fragment(&store, "", 7, fleet, "default");
    CHECK(html.find("Experience health") != std::string::npos);
    CHECK(html.find("100 &minus; weighted deductions") != std::string::npos); // the formula is shown
    CHECK(html.find("derived &middot; secondary") != std::string::npos);
    CHECK(html.find("Why this score") != std::string::npos);
    CHECK(html.find("weighting:") != std::string::npos); // server-round-tripped presets
    // Every display family carries a weight entry (a family missing from
    // dex_family_weights silently never contributes to the score) — pin the
    // A3 addition via its per-family sub-score card.
    CHECK(html.find("Performance") != std::string::npos);

    // No reporting agents → suppressed (NEVER a fabricated 100).
    const auto suppressed = render_dex_health_fragment(&store, "", 7, DexFleet{}, "default");
    CHECK(suppressed.find("Index suppressed") != std::string::npos);

    // A bogus weighting falls back to "default" — the raw param is never echoed.
    const auto bad = render_dex_health_fragment(&store, "", 7, fleet, "<script>x</script>");
    CHECK(bad.find("<script>") == std::string::npos);
}

TEST_CASE("DEX trends: cross-OS cards (live scope), small-multiples, heatmap",
          "[pg][dex][routes][trends]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& plat, const std::string& day) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = type;
        r.severity = "info";
        r.detail_json = "{\"subject\":\"x\",\"platform\":\"" + plat + "\"}";
        r.timestamp = day + "T10:00:00Z";
        REQUIRE(store.insert_event(r));
    };
    obs("1", "w", "process.crashed", "windows", kDayA);
    obs("2", "w", "network.wifi_drop", "windows", kDayB);
    obs("3", "m", "process.crashed", "macos", kDayB);

    DexFleet fleet;
    fleet.windows_online = 5;
    const auto html = render_dex_trends_fragment(&store, "", 30, fleet);
    CHECK(html.find("Cross-OS") != std::string::npos);
    CHECK(html.find("By operating system") != std::string::npos);
    CHECK(html.find("Windows") != std::string::npos);
    CHECK(html.find("macOS") != std::string::npos);
    CHECK(html.find("gp-oscard pending") != std::string::npos);          // Linux pending (no data)
    CHECK(html.find("Signal families over time") != std::string::npos);  // small-multiples
    CHECK(html.find("Activity heatmap") != std::string::npos);           // heatmap
    CHECK(html.find("App reliability") != std::string::npos);            // a family row
    // DERIVED-LIVE scope caption — "of 114 signal types", not the mockup's stale 6
    CHECK(html.find("of 114 signal types") != std::string::npos);
}

TEST_CASE("DEX overview hub: explore cards link into the three deep pages",
          "[pg][dex][routes][hub]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    DexFleet fleet;
    fleet.windows_online = 5;
    const auto html = render_dex_overview_fragment(&store, "", 7, fleet);
    CHECK(html.find("Explore") != std::string::npos);
    CHECK(html.find("Signal catalogue") != std::string::npos);
    CHECK(html.find("Experience health") != std::string::npos);
    CHECK(html.find("Cross-OS &amp; trends") != std::string::npos);
    // each card drills into its deep page
    CHECK(html.find("/fragments/dex/catalogue?window=") != std::string::npos);
    CHECK(html.find("/fragments/dex/health?window=") != std::string::npos);
    CHECK(html.find("/fragments/dex/trends?window=") != std::string::npos);
    // with reporting agents the health teaser computes (not suppressed)
    CHECK(html.find("suppressed") == std::string::npos);

    // with no reporting agents the health teaser is suppressed (no fabricated score)
    const auto sup = render_dex_overview_fragment(&store, "", 7, DexFleet{});
    CHECK(sup.find("suppressed") != std::string::npos);
}

TEST_CASE("DEX overview: renders real multi-signal aggregations", "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");
    seed_crash(store, "e2", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T11:00:00Z");
    seed_hang(store, "e3", "WS-2", "chrome.exe", kDayB + "T09:00:00Z");
    seed_signal(store, "e4", "WS-2", "service.crashed",
                R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
                kDayB + "T10:00:00Z");
    seed_boot(store, "e5", "WS-1", 43210.0, kDayB + "T08:00:00Z");
    seed_boot(store, "e6", "WS-2", 91000.0, kDayB + "T08:05:00Z");

    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{10, 12});
    CHECK(html.find("Digital Employee Experience") != std::string::npos);
    // Hub slim: the All-signals / boot / faulting-modules panels moved to the
    // deep pages (Catalogue + App reliability) — the hub summarises and links.
    CHECK(html.find("All signals") == std::string::npos);
    CHECK(html.find("Boot performance") == std::string::npos);
    CHECK(html.find("Top faulting modules") == std::string::npos);
    // Top crashing apps table spans crashes + hangs, with a deep-page CTA.
    CHECK(html.find("Top crashing apps") != std::string::npos);
    CHECK(html.find("App reliability") != std::string::npos); // section CTA → catalogue family
    CHECK(html.find("chrome.exe") != std::string::npos);
    CHECK(html.find("Hangs") != std::string::npos);
    // Most-affected devices (crash-scoped) + the By-OS coverage teaser.
    CHECK(html.find("Most-affected devices") != std::string::npos);
    CHECK(html.find("WS-1") != std::string::npos);
    CHECK(html.find("By operating system") != std::string::npos);
    CHECK(html.find("Windows") != std::string::npos); // the one OS that reported
    CHECK(html.find("gp-table") != std::string::npos);
}

TEST_CASE("DEX catalogue: unknown obs_type falls back to the raw label under 'Other'",
          "[pg][dex][routes][catalogue]") {
    // Forward-compat: a signal added agent-side renders with NO server change.
    // The slimmed hub no longer carries the per-type rollup, so the "Other"
    // (uncatalogued) fallback now surfaces on the Catalogue.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "e1", "WS-1", "future.signal_type",
                R"({"subject":"thing","platform":"windows"})", kDayB + "T10:00:00Z");
    auto html = render_dex_catalogue_fragment(&store, "", 7, DexFleet{}, "all");
    CHECK(html.find("future.signal_type") != std::string::npos);
    CHECK(html.find(">Other") != std::string::npos);
}

TEST_CASE("DEX per-device score: clean 100; failures deduct; benign don't; null=-1",
          "[pg][dex][score]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // Null store → n/a sentinel.
    CHECK(dex_device_score(nullptr, "WS-1", "") == -1);
    // A device with no observations is a clean 100.
    CHECK(dex_device_score(&store, "CLEAN-1", "") == 100);
    // A failure signal (process.crashed = App reliability, high severity) deducts.
    seed_signal(store, "e1", "WS-1", "process.crashed",
                R"({"subject":"chrome.exe","platform":"windows"})", kDayA + "T10:00:00Z");
    CHECK(dex_device_score(&store, "WS-1", "") < 100);
    // The score is per-device: a different device is unaffected.
    CHECK(dex_device_score(&store, "OTHER-1", "") == 100);
    // Benign reports (uptime) never deduct → still 100.
    seed_signal(store, "e2", "BENIGN-1", "os.uptime_report",
                R"({"subject":"host","platform":"windows"})", kDayA + "T10:00:00Z");
    CHECK(dex_device_score(&store, "BENIGN-1", "") == 100);
    // os.modern_standby_exit (wave 4) fires on EVERY resume — it lives in the
    // benign "Boot, start-up & shutdown" family, so a laptop that sleeps a lot
    // must NOT have its score dragged down (mirrors os.uptime_report above).
    seed_signal(store, "e3", "SLEEPER-1", "os.modern_standby_exit",
                R"({"subject":"modern standby","reason":"32","metric":0,"platform":"windows"})",
                kDayA + "T10:00:00Z");
    CHECK(dex_device_score(&store, "SLEEPER-1", "") == 100);
}

TEST_CASE("DEX overview: Experience hero — per-device distribution + D/A/N; crashes demoted",
          "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "e1", "WS-1", "process.crashed",
                R"({"subject":"chrome.exe","platform":"windows"})", kDayA + "T10:00:00Z");
    // 2 connected Windows agents: WS-1 crashed (<100), WS-2 clean (100).
    DexFleet fleet{2, 2, {"windows"}, {{"WS-1", "windows"}, {"WS-2", "windows"}}};
    auto html = render_dex_overview_fragment(&store, "", 7, fleet);
    CHECK(html.find("Experience") != std::string::npos);         // new headline section
    CHECK(html.find("Overall experience") != std::string::npos); // per-device median tile
    CHECK(html.find("great") != std::string::npos);              // the distribution bar
    CHECK(html.find("Experience by segment") != std::string::npos); // the segment breakdown
    CHECK(html.find("Crash-free devices") != std::string::npos); // crashes demoted, not removed
}

// #4855: a degraded per-device signal-summary read must surface a COUNT of
// devices that could not be scored, never silently thin the great/fair/poor
// population (which would read as a healthier fleet than is actually known).
// DROP TABLE forces every connected device's per-device read to degrade
// while the store itself stays open.
TEST_CASE("DEX overview: a degraded per-device read counts + surfaces unscored devices, never "
          "silently thinning the scored population",
          "[pg][dex][routes][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_observations")};
        REQUIRE(d.ok());
    }

    DexFleet fleet{2, 2, {"windows"}, {{"WS-1", "windows"}, {"WS-2", "windows"}}};
    auto html = render_dex_overview_fragment(&store, "", 7, fleet);
    CHECK(html.find("2 device(s) could not be scored") != std::string::npos);
    // UP-3: scored==0 && unscored>0 must NOT claim "no devices reporting" —
    // 2 devices ARE reporting/connected, they just couldn't be scored (the
    // note above already says so). The Overall tile says so instead.
    CHECK(html.find("scores unavailable") != std::string::npos);
    CHECK(html.find("no devices reporting") == std::string::npos);

    // The pure model (build_dex_overview_model) must count the same thing.
    const auto model = build_dex_overview_model(&store, fleet, "7d", 7, "", nullptr);
    CHECK(model.unscored == 2);
    CHECK(model.overall_experience == -1);
    CHECK(model.great == 0);
    CHECK(model.fair == 0);
    CHECK(model.poor == 0);
    CHECK(dex_overview_json(model).find("\"unscored\":2") != std::string::npos);
}

TEST_CASE("DEX overview: crash-free rate from fleet denominator; none → honest no-data",
          "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");

    // 1 device impacted of 4 reporting Windows agents → crash-free 75.0%.
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{4, 5});
    CHECK(html.find("75.0%") != std::string::npos);
    CHECK(html.find("Crash-free devices") != std::string::npos);
    CHECK(html.find("Crashes / 1k device-days") != std::string::npos);

    // No denominator → no fabricated rate.
    auto html2 = render_dex_overview_fragment(&store, "", 7, DexFleet{0, 0});
    CHECK(html2.find("75.0%") == std::string::npos);
    CHECK(html2.find("no reporting agents") != std::string::npos);
}

TEST_CASE("DEX overview: crash-free rate is Windows-scoped — a macOS crash can't move it (C-DEX-1)",
          "[pg][dex][routes]") {
    // process.crashed now arrives from macOS agents too. The crash-free tile is
    // denominated over reporting WINDOWS agents, so a macOS crash must NOT lower
    // it. This guards a future edit that drops the "windows" scope from
    // dex_crash_summary in render_dex_overview_fragment — that regression would
    // count MAC-1 as impacted (2 of 4 → 50.0%) instead of the correct 75.0%.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "w1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");
    seed_crash(store, "m1", "MAC-1", "Safari", "", "macos", kDayA + "T11:00:00Z");

    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{4, 5});
    CHECK(html.find("75.0%") != std::string::npos); // 1 Windows device of 4 — unchanged by macOS
    CHECK(html.find("50.0%") == std::string::npos); // NOT 2 of 4 (the macOS crash is excluded)
}

TEST_CASE("DEX overview: hangs alone keep the crash-free rate honest (100%)",
          "[pg][dex][routes]") {
    // A hang is not a crash: the headline crash-free rate must stay crash-scoped.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_hang(store, "e1", "WS-1", "Teams.exe", kDayB + "T09:00:00Z");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{4, 5});
    CHECK(html.find("100.0%") != std::string::npos);    // 0 crash-impacted of 4
    CHECK(html.find("Teams.exe") != std::string::npos); // the hung app still surfaces (Hangs col)
}

TEST_CASE("DEX overview: escapes nasty subjects (no XSS)", "[pg][dex][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "WS-1", "<img src=x onerror=alert(1)>", "ntdll.dll", "windows",
               kDayA + "T10:00:00Z");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{10, 12});
    CHECK(html.find("<img src=x") == std::string::npos);     // raw tag must not appear
    CHECK(html.find("&lt;img src=x") != std::string::npos);  // escaped form does
}

TEST_CASE("DEX app drill-down: blast radius + hangs + modules + exceptions + devices",
          "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");
    seed_crash(store, "e2", "WS-2", "chrome.exe", "chrome.dll", "windows", kDayB + "T10:00:00Z");
    seed_hang(store, "e3", "WS-2", "chrome.exe", kDayB + "T11:00:00Z");

    auto html = render_dex_app_fragment(&store, "chrome.exe", "all");
    CHECK(html.find("chrome.exe") != std::string::npos);
    CHECK(html.find("Devices affected") != std::string::npos);
    CHECK(html.find("Hangs") != std::string::npos); // crash + hang summary tiles
    CHECK(html.find("Faulting modules") != std::string::npos);
    CHECK(html.find("Exceptions") != std::string::npos);
    CHECK(html.find("Affected devices") != std::string::npos);
    CHECK(html.find("ntdll.dll") != std::string::npos);
    CHECK(html.find("ACCESS_VIOLATION") != std::string::npos);
    CHECK(html.find("/fragments/dex/device?id=WS-1") != std::string::npos); // drill to device
}

TEST_CASE("DEX app drill-down: unknown app → no-crashes placeholder", "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto html = render_dex_app_fragment(&store, "nope.exe", "all");
    CHECK(html.find("No crashes") != std::string::npos);
}

TEST_CASE("DEX app drill-down: performance cross-link uses the EXACT process-name "
          "key, never normalized (no case-fold, no .exe strip) — shown even with no "
          "crash history",
          "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto html = render_dex_app_fragment(&store, "MyApp.EXE", "7d");
    CHECK(html.find("/fragments/dex/perf/app?app=MyApp.EXE&window=7d") != std::string::npos);
    CHECK(html.find("myapp.exe") == std::string::npos);    // no case-fold
    CHECK(html.find("app=MyApp&window=") == std::string::npos); // no .EXE stripping
}

TEST_CASE("DEX device drill-down: friendly multi-signal history (UP-4)",
          "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "WS-7", "AcmeCRM.exe", "AcmeCRM.dll", "windows",
               kDayA + "T10:00:00Z");
    seed_signal(store, "e2", "WS-7", "service.crashed",
                R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
                kDayB + "T10:00:00Z");
    seed_boot(store, "e3", "WS-7", 43210.0, kDayB + "T08:00:00Z");

    auto html = render_dex_device_fragment(&store, "WS-7", "all");
    CHECK(html.find("Behavioral data") == std::string::npos); // banner removed (Dave 2026-06-10);
                                                              // the gate + audit remain route-side
    CHECK(html.find("Signal history") != std::string::npos);
    CHECK(html.find("AcmeCRM.exe") != std::string::npos);
    CHECK(html.find("ACCESS_VIOLATION") != std::string::npos);
    // Friendly labels for non-crash rows; boot rows show the humanised duration
    // (>=10 s renders as seconds).
    CHECK(html.find("Service crash") != std::string::npos);
    CHECK(html.find("43.2 s") != std::string::npos);
    CHECK(html.find("__observation__") == std::string::npos); // friendly rows, not the sentinel
}

TEST_CASE("DEX device drill-down: escapes agent_id + subject (no XSS)",
          "[pg][dex][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "<b>evil</b>", "<img src=x>", "ntdll.dll", "windows",
               kDayA + "T10:00:00Z");
    auto html = render_dex_device_fragment(&store, "<b>evil</b>", "all");
    CHECK(html.find("<b>evil</b>") == std::string::npos);
    CHECK(html.find("&lt;b&gt;evil") != std::string::npos);
}

TEST_CASE("DEX single-observation detail: store lookup + render", "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "ev-100", "WS-7", "app.staterepo_error",
                R"({"subject":"app state repository","reason":"sr-100",)"
                R"("symbolic":"STATEREPO_ERROR","platform":"windows"})",
                kDayA + "T11:27:41Z");

    // store: indexed point lookup by event_id; unknown / empty id → nullopt
    auto obs = store.dex_observation("ev-100");
    REQUIRE(obs.has_value());
    CHECK(obs->agent_id == "WS-7");
    CHECK(obs->obs_type == "app.staterepo_error");
    CHECK(obs->reason == "sr-100");
    CHECK(obs->symbolic == "STATEREPO_ERROR");
    CHECK_FALSE(store.dex_observation("nope").has_value());
    CHECK_FALSE(store.dex_observation("").has_value());

    // render: friendly label + the raw obs_type + every captured field
    auto html = render_dex_observation_fragment(*obs);
    CHECK(html.find("App repository error") != std::string::npos);
    CHECK(html.find("app.staterepo_error") != std::string::npos);
    CHECK(html.find("sr-100") != std::string::npos);
    CHECK(html.find("STATEREPO_ERROR") != std::string::npos);
    CHECK(html.find("WS-7") != std::string::npos);
}

TEST_CASE("DEX single-observation detail: escapes fields (no XSS)",
          "[pg][dex][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_signal(store, "ev-x", "WS-7", "process.crashed",
                R"({"subject":"<img src=x>","reason":"0x1",)"
                R"("symbolic":"<b>evil</b>","platform":"windows"})",
                kDayA + "T10:00:00Z");
    auto obs = store.dex_observation("ev-x");
    REQUIRE(obs.has_value());
    auto html = render_dex_observation_fragment(*obs);
    CHECK(html.find("<img src=x>") == std::string::npos);
    CHECK(html.find("<b>evil</b>") == std::string::npos);
    CHECK(html.find("&lt;b&gt;evil") != std::string::npos);
}

TEST_CASE("DEX observation render: metric 0 → em-dash; unknown obs_type → escaped fallback",
          "[dex][routes]") {
    GuardianObservationRow r;
    r.event_id = "ev-z";
    r.agent_id = "WS-1";
    r.obs_type = "<weird>future.type"; // uncatalogued + hostile
    r.subject = "x";
    r.platform = "windows";
    r.metric = 0.0; // "no metric" sentinel — the Metric cell shows an em-dash, not "0"
    const auto html = render_dex_observation_fragment(r);
    CHECK(html.find("Metric</span><code>&mdash;</code>") != std::string::npos);
    // unknown obs_type falls back to the escaped raw label (no XSS, no crash)
    CHECK(html.find("<weird>") == std::string::npos);
    CHECK(html.find("&lt;weird&gt;future.type") != std::string::npos);
    // a real metric DOES render (no sci-notation for in-range values)
    r.metric = 75.0;
    const auto html2 = render_dex_observation_fragment(r);
    CHECK(html2.find("Metric</span><code>75</code>") != std::string::npos);
}

TEST_CASE("DEX observation render: metric is unit-formatted per obs_type (polymorphic)",
          "[dex][routes]") {
    auto render = [](const std::string& obs_type, double metric) {
        GuardianObservationRow r;
        r.event_id = "e";
        r.agent_id = "WS-1";
        r.platform = "windows";
        r.obs_type = obs_type;
        r.metric = metric;
        return render_dex_observation_fragment(r);
    };
    // DRIPS residency is a PERCENT, not a duration — must NOT render as "75 ms".
    CHECK(render("os.modern_standby_exit", 75.0).find("Metric</span><code>75%</code>") !=
          std::string::npos);
    // 0% DRIPS is a REAL reading (never reached deep idle) — it must render "0%",
    // NOT the "no metric" em-dash (grill #1: the signal's headline value was hidden).
    CHECK(render("os.modern_standby_exit", 0.0).find("Metric</span><code>0%</code>") !=
          std::string::npos);
    CHECK(render("os.modern_standby_exit", 0.0).find("Metric</span><code>&mdash;</code>") ==
          std::string::npos);
    // A forged negative DRIPS can't arise (extractor clamps [0,100]) but pins the
    // new guard's negative arm → em-dash, never a bogus "-1%".
    CHECK(render("os.modern_standby_exit", -1.0).find("Metric</span><code>&mdash;</code>") !=
          std::string::npos);
    // Duration metrics humanize ms → s.
    CHECK(render("os.boot", 64934.0).find("Metric</span><code>64.9 s</code>") != std::string::npos);
    // A long boot never flips to scientific notation (the bare-{:g} hazard).
    const auto big = render("os.boot", 1200000.0);
    CHECK(big.find("e+0") == std::string::npos);
    CHECK(big.find("Metric</span><code>1200.0 s</code>") != std::string::npos);
    // Seconds-valued (uptime) humanizes across all fmt_secs branches (d / h / min / s).
    CHECK(render("os.uptime_report", 90000.0).find("Metric</span><code>1.0 d</code>") !=
          std::string::npos);
    CHECK(render("os.uptime_report", 7200.0).find("Metric</span><code>2.0 h</code>") !=
          std::string::npos);
    CHECK(render("os.uptime_report", 300.0).find("Metric</span><code>5.0 min</code>") !=
          std::string::npos);
    CHECK(render("os.uptime_report", 30.0).find("Metric</span><code>30 s</code>") !=
          std::string::npos);
    // Counts + uncatalogued render as plain integers (no unit, no sci).
    CHECK(render("hw.battery_error", 2.0).find("Metric</span><code>2</code>") != std::string::npos);
    // A3 perf-breach family is reachable in this panel (projection stores any obs_type,
    // history filters none) — render with the RIGHT unit, not a bare number (governance
    // consistency S1). cpu/memory are %; disk latency is direct ms (NOT fmt_ms's "s").
    CHECK(render("perf.cpu_sustained", 85.0).find("Metric</span><code>85%</code>") !=
          std::string::npos);
    CHECK(render("perf.memory_pressure", 92.0).find("Metric</span><code>92%</code>") !=
          std::string::npos);
    CHECK(render("perf.disk_latency_high", 25.0).find("Metric</span><code>25 ms</code>") !=
          std::string::npos);
    // NaN / +inf / absurd are rejected defensively → em-dash, never "inf%" / "inf d"
    // / a 300-digit blob (UP-4/UP-5). The store range-guards on write; this keeps the
    // formatter robust independent of that.
    const double inf = std::numeric_limits<double>::infinity();
    CHECK(render("os.modern_standby_exit", inf).find("inf") == std::string::npos);
    CHECK(render("os.modern_standby_exit", inf).find("Metric</span><code>&mdash;</code>") !=
          std::string::npos);
    CHECK(render("os.boot", 1e300).find("Metric</span><code>&mdash;</code>") != std::string::npos);
}

TEST_CASE("DEX device history rows drill to the observation detail", "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "ev-1", "WS-7", "AcmeCRM.exe", "AcmeCRM.dll", "windows",
               kDayA + "T10:00:00Z");
    auto html = render_dex_device_fragment(&store, "WS-7", "all");
    // each row hx-gets its single-observation detail into the slot div
    CHECK(html.find("/fragments/dex/observation?agent_id=WS-7&amp;event_id=ev-1") !=
          std::string::npos);
    CHECK(html.find("id=\"dex-obs-detail\"") != std::string::npos);
}

TEST_CASE("DEX apps list: ranks apps by crashes+hangs, drillable", "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "c1", "WS-1", "AcmeCRM.exe", "AcmeCRM.dll", "windows", kDayA + "T10:00:00Z");
    seed_crash(store, "c2", "WS-2", "AcmeCRM.exe", "ntdll.dll", "windows", kDayA + "T11:00:00Z");
    seed_hang(store, "h1", "WS-1", "chrome.exe", kDayA + "T12:00:00Z");

    auto html = render_dex_apps_fragment(&store, "", 7);
    CHECK(html.find("Applications") != std::string::npos);
    CHECK(html.find("AcmeCRM.exe") != std::string::npos);
    CHECK(html.find("chrome.exe") != std::string::npos);
    // app rows drill to the per-app blast-radius view; the Apps subnav tab is present
    CHECK(html.find("name=AcmeCRM.exe") != std::string::npos);
    CHECK(html.find("/fragments/dex/apps") != std::string::npos);
}

TEST_CASE("DEX apps list: empty store → no-data placeholder", "[pg][dex][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto html = render_dex_apps_fragment(&store, "", 7);
    CHECK(html.find("No data") != std::string::npos);
}

TEST_CASE("DEX routes: auth/perm gating + dispatch", "[pg][dex][routes][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto noAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(std::nullopt);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto noPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                     const std::string&) {
        res.status = 403;
        return false;
    };
    auto fleet = []() { return DexFleet{4, 5}; };
    std::string audited, audited_detail;
    bool audit_ok = true;      // flip to simulate a dropped evidence row (#1549)
    bool audit_throws = false; // flip to simulate a bad_alloc-class throw (#1647)
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string&,
                     const std::string& ttype, const std::string& tid,
                     const std::string& detail) -> bool {
        audited = a + "|" + ttype + "|" + tid; // capture target_type to pin the PascalCase fix
        audited_detail = detail;               // capture detail to pin obs_type (works-council)
        if (audit_throws)
            throw std::runtime_error("audit DB write blew up");
        return audit_ok;
    };

    SECTION("authed shell + permitted fragments render") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);

        auto page = sink.Get("/dex");
        REQUIRE(page);
        CHECK(page->status == 200);
        CHECK(page->body.find("/fragments/dex/overview") != std::string::npos);

        auto ov = sink.Get("/fragments/dex/overview?window=7d");
        REQUIRE(ov);
        CHECK(ov->status == 200);
        CHECK(ov->body.find("chrome.exe") != std::string::npos);

        auto app = sink.Get("/fragments/dex/app?name=chrome.exe");
        REQUIRE(app);
        CHECK(app->body.find("Faulting modules") != std::string::npos);

        auto dev = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(dev);
        CHECK(dev->body.find("Signal history") != std::string::npos);
        CHECK(audited == "dex.device.view|Agent|WS-1"); // per-device open audited (PII), PascalCase target_type

        // The per-signal Catalogue view lists most-affected DEVICES for an
        // obs_type (behavioral data) AND shows an "audit-logged on open" banner —
        // so the route MUST audit each open, mirroring the device view (gov B4).
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(audited == "dex.signal.view|ObsType|process.crashed");
    }

    SECTION("signal drill-down 'Collected on' reflects the coverage map, incl. Linux") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        // process.crashed is collected on all three platforms; the caption is derived
        // from dex_obs_platforms (coverage), not observed events, so it must name
        // Linux and never regress to the old event-derived "Windows only". The
        // " + "-joined form is unique to the coverage caption (the by_os table can't
        // produce it), so this can't pass on incidental seeded Linux rows.
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(sig->body.find("Collected on") != std::string::npos);
        CHECK(sig->body.find("Windows + Linux + macOS") != std::string::npos);
        CHECK(sig->body.find("Windows only") == std::string::npos);
    }

    // Per-event observation route: the novel security-load-bearing logic (scope
    // gate before audit, binding-404 against a foreign event_id, audit-on-success
    // with the obs_type in the detail) must be exercised THROUGH the route, not
    // just via the store/render fns (gov QE BLOCKING; F1 works-council).
    SECTION("per-event /observation: permitted opens audit obs_type+event; foreign id is an opaque placeholder") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);

        // (1) Permitted open of the seeded WS-1 crash (event_id "e1") → 200 + audit;
        //     the detail carries the obs_type (usage-class countability) + the event id.
        auto ok = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(audited == "dex.observation.view|Agent|WS-1");
        CHECK(audited_detail.find("process.crashed") != std::string::npos); // F1 obs_type
        CHECK(audited_detail.find("e1") != std::string::npos);              // event id traceable

        // (2) Binding case: the event exists but on a DIFFERENT device → the same
        //     "Observation not found" placeholder as a genuinely-unknown id, with NO
        //     foreign data leaked. Status is 200 NOT 404 — the dashboard htmx config
        //     drops 4xx bodies (swap:false), so a 404 would blank the slot; 200 still
        //     closes the enumeration oracle (foreign == absent, indistinguishable) and
        //     the not-found branch does NOT audit.
        audited.clear();
        auto foreign = sink.Get("/fragments/dex/observation?agent_id=WS-2&event_id=e1");
        REQUIRE(foreign);
        CHECK(foreign->status == 200);
        CHECK(foreign->body.find("Observation not found") != std::string::npos);
        CHECK(foreign->body.find("chrome.exe") == std::string::npos); // WS-1's data does not leak
        auto unknown = sink.Get("/fragments/dex/observation?agent_id=WS-2&event_id=nope");
        REQUIRE(unknown);
        CHECK(unknown->status == 200);
        CHECK(foreign->body == unknown->body); // indistinguishable — oracle closed
        // Empty event_id (the degenerate guard) also lands on the placeholder, not a 500.
        auto empty = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=");
        REQUIRE(empty);
        CHECK(empty->status == 200);
        CHECK(empty->body == unknown->body); // complete oracle closure: empty ≡ unknown ≡ foreign
        CHECK(audited.empty());              // none of the not-found paths audit
    }

    SECTION("per-event /observation: agent-controlled obs_type/event_id sanitized in the audit detail") {
        // A compromised/buggy agent could emit an obs_type/event_id with control
        // chars or an embedded NUL; appended raw to the audit detail that would
        // truncate the audit row (sqlite3_bind_text -1) or inject into the trail
        // (UP-3). The event_id is clean here so the URL lookup resolves; the obs_type
        // carries a control byte that must be STRIPPED before it reaches the detail.
        seed_signal(store, "ev-ctrl", "WS-1", std::string("bad\x01type", 8),
                    R"({"subject":"x","platform":"windows"})", kDayA + "T10:00:00Z");
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        auto r = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=ev-ctrl");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(audited == "dex.observation.view|Agent|WS-1");
        CHECK(audited_detail.find('\x01') == std::string::npos); // control byte stripped
        CHECK(audited_detail.find("badtype") != std::string::npos); // rest of obs_type intact
    }

    SECTION("per-event /observation + /apps: perm gate runs before audit/render") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, noPerm, &store, fleet, audit);

        auto obsv = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(obsv);
        CHECK(obsv->status == 403);
        CHECK(audited.empty()); // perm gate before audit

        auto apps = sink.Get("/fragments/dex/apps");
        REQUIRE(apps);
        CHECK(apps->status == 403);
    }

    SECTION("per-event /observation is management-scoped: out-of-scope device → 403 before audit") {
        seed_crash(store, "e9", "WS-OTHER", "chrome.exe", "ntdll.dll", "windows",
                   kDayA + "T12:00:00Z");
        auto scopedPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&, const std::string& id) {
            if (id == "WS-OTHER") {
                res.status = 403;
                return false;
            }
            return true;
        };
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, scopedPerm);
        auto other = sink.Get("/fragments/dex/observation?agent_id=WS-OTHER&event_id=e9");
        REQUIRE(other);
        CHECK(other->status == 403);
        CHECK(audited.empty()); // scoped denial neither audits nor renders
        auto mine = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(mine);
        CHECK(mine->status == 200);
    }

    SECTION("/fragments/dex/apps renders the ranked app table when permitted") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        auto apps = sink.Get("/fragments/dex/apps");
        REQUIRE(apps);
        CHECK(apps->status == 200);
        CHECK(apps->body.find("chrome.exe") != std::string::npos); // the seeded crasher ranks
    }

    SECTION("unauthenticated shell redirects to /login") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, noAuth, okPerm, &store, fleet, audit);
        auto page = sink.Get("/dex");
        REQUIRE(page);
        CHECK(page->status == 302);
        CHECK(page->get_header_value("Location") == "/login");
    }

    SECTION("fragments denied without GuaranteedState:Read, before audit/render") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, noPerm, &store, fleet, audit);

        auto ov = sink.Get("/fragments/dex/overview");
        REQUIRE(ov);
        CHECK(ov->status == 403);
        CHECK(ov->body.find("chrome.exe") == std::string::npos); // no data leaked

        auto dev = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(dev);
        CHECK(dev->status == 403);
        CHECK(audited.empty()); // perm gate runs BEFORE the audit + render

        // Same for the per-signal device list — perm gate before audit/render, so
        // a denied caller neither sees data nor produces an audit row (gov B4).
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 403);
        CHECK(audited.empty());
    }

    SECTION("PII drill-down audit failure → Sec-Audit-Failed header but still renders (#1549)") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        audit_ok = false; // the evidence row cannot persist

        // The dashboard is an HTML surface: a transient audit hiccup flags the gap
        // via the header but must NOT blank the fragment (unlike the strict REST
        // per-device endpoints, which fail closed).
        auto dev = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(dev);
        CHECK(dev->status == 200);
        CHECK(dev->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(dev->body.find("Signal history") != std::string::npos); // still served

        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(sig->get_header_value("Sec-Audit-Failed") == "true");

        // The new per-event observation drill (#1639) now routes through the SAME
        // emit_behavioral_audit chokepoint — a dropped evidence row flags the header
        // but the detail panel still renders (HTML set-and-proceed).
        auto obs = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(obs);
        CHECK(obs->status == 200);
        CHECK(obs->get_header_value("Sec-Audit-Failed") == "true");
    }

    // #1647 item 1: a throwing audit_fn (bad_alloc-class) was previously silent on
    // these HTML sites (no try/catch). The shared helper catches it → header flagged,
    // fragment still rendered, throw never escapes the handler.
    SECTION("a throwing audit_fn is caught → Sec-Audit-Failed header, fragment still renders") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        audit_throws = true;

        auto dev = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(dev);
        CHECK(dev->status == 200);
        CHECK(dev->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(dev->body.find("Signal history") != std::string::npos); // still served

        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(sig->get_header_value("Sec-Audit-Failed") == "true");

        // The per-event observation drill (#1639) is caught by the same shared helper:
        // the throw never escapes the handler, header flagged, fragment still rendered.
        auto obs = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(obs);
        CHECK(obs->status == 200);
        CHECK(obs->get_header_value("Sec-Audit-Failed") == "true");
    }

    // Re-review blocker: the per-device DEX surface must be management-scoped (mirror
    // the /device routes) — an operator can't drill another team's device, and the
    // device-id lists must not enumerate out-of-scope agents.
    SECTION("per-device DEX surface is scoped: drill 403 + lists drop out-of-scope ids") {
        seed_crash(store, "e9", "WS-OTHER", "chrome.exe", "ntdll.dll", "windows",
                   kDayA + "T12:00:00Z");
        // Scoped gate: deny the per-device drill for the out-of-scope agent.
        auto scopedPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&, const std::string& id) {
            if (id == "WS-OTHER") {
                res.status = 403;
                return false;
            }
            return true;
        };
        // Visible set: only WS-1 is in the caller's scope (the lists must drop WS-OTHER).
        auto visibleSet = [](const std::string&) -> std::optional<std::set<std::string>> {
            return std::set<std::string>{"WS-1"};
        };
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, scopedPerm,
                               visibleSet);

        // (1) The per-device drill is scoped: out-of-scope → 403, in-scope still opens.
        auto other = sink.Get("/fragments/dex/device?id=WS-OTHER");
        REQUIRE(other);
        CHECK(other->status == 403);
        auto mine = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(mine);
        CHECK(mine->status == 200);

        // (2) The device-id lists drop the out-of-scope agent (no enumeration), while
        //     still showing the in-scope one.
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(sig->body.find("WS-1") != std::string::npos);
        CHECK(sig->body.find("WS-OTHER") == std::string::npos);

        auto app = sink.Get("/fragments/dex/app?name=chrome.exe");
        REQUIRE(app);
        CHECK(app->body.find("WS-OTHER") == std::string::npos);

        auto ov = sink.Get("/fragments/dex/overview?window=7d");
        REQUIRE(ov);
        CHECK(ov->body.find("WS-OTHER") == std::string::npos);
    }

    SECTION("hostile ?window= is canonicalised, never reflected into markup (Gate-8 XSS)") {
        // The raw window param flows into hx-get="…" attributes in drill-down
        // links; the route MUST canonicalise it to one of the four fixed tokens
        // before render. Must be exercised through the ROUTE (the raw param
        // entry point) — calling the render fns directly with a clean token
        // masks the bug. CSP is script-src 'self' 'unsafe-inline', so a
        // reflected attribute-break would execute.
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        const char* payload = R"(window="><script>alert(1)</script>)";

        auto ov = sink.Get(std::string("/fragments/dex/overview?window=") + payload);
        REQUIRE(ov);
        CHECK(ov->body.find("<script>") == std::string::npos);
        CHECK(ov->body.find("alert(1)") == std::string::npos); // payload not reflected anywhere

        auto app = sink.Get(std::string("/fragments/dex/app?name=chrome.exe&window=") + payload);
        REQUIRE(app);
        CHECK(app->body.find("<script>") == std::string::npos);
        CHECK(app->body.find("alert(1)") == std::string::npos);

        auto dev = sink.Get(std::string("/fragments/dex/device?id=WS-1&window=") + payload);
        REQUIRE(dev);
        CHECK(dev->body.find("<script>") == std::string::npos);
        CHECK(dev->body.find("alert(1)") == std::string::npos);
    }
}

// SEC-2/SEC-3 sibling class (found during a docs sweep): /fragments/dex/overview,
// /fragments/dex/catalogue/signal, /fragments/dex/app, and /fragments/dex/perf/devices
// each render more than one agent_id fleet-wide. Their resolve_visible() narrowing
// is username-keyed (VisibleSetFn) and does not confine a service-scoped API
// token — the same gap already closed on the REST/MCP/Guardian/network surfaces.
TEST_CASE("DEX routes: service-scoped token denied on every fleet-wide device-list "
          "fragment, denial audited",
          "[pg][dex][routes][rbac][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");

    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{4, 5}; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };
    yuzu::server::DexPerfFn perf_fn = [](const std::string&) {
        yuzu::server::DexPerfSnapshot snap;
        yuzu::server::DexPerfDevice d;
        d.agent_id = "WS-1";
        d.cpu_pct = 50.0;
        snap.devices.push_back(d);
        return snap;
    };

    DexRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
        perf_fn, yuzu::server::test::FnDexPerfApi::Providers{});
    routes.register_routes(sink, serviceScopedAuth, okPerm, &store, fleet, audit, /*dispatch_fn=*/{},
                           /*responses_fn=*/{}, {}, {}, dex_perf_api);

    auto ov = sink.Get("/fragments/dex/overview?window=7d");
    REQUIRE(ov);
    CHECK(ov->status == 403);
    CHECK(ov->body.find("WS-1") == std::string::npos);

    auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
    REQUIRE(sig);
    CHECK(sig->status == 403);
    CHECK(sig->body.find("WS-1") == std::string::npos);

    auto app = sink.Get("/fragments/dex/app?name=chrome.exe");
    REQUIRE(app);
    CHECK(app->status == 403);
    CHECK(app->body.find("WS-1") == std::string::npos);

    auto perf = sink.Get("/fragments/dex/perf/devices");
    REQUIRE(perf);
    CHECK(perf->status == 403);
    CHECK(perf->body.find("WS-1") == std::string::npos);

    REQUIRE(audit_log.size() == 4);
    CHECK(audit_log[0] == "dex.overview.view|denied");
    CHECK(audit_log[1] == "dex.signal.view|denied");
    CHECK(audit_log[2] == "dex.app.view|denied");
    CHECK(audit_log[3] == "dex.perf.device.view|denied");
}

TEST_CASE("DEX routes: ordinary session reaches /fragments/dex/perf/devices, "
          "dedicated success audit fires",
          "[pg][dex][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{4, 5}; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };
    yuzu::server::DexPerfFn perf_fn = [](const std::string&) {
        yuzu::server::DexPerfSnapshot snap;
        yuzu::server::DexPerfDevice d;
        d.agent_id = "WS-1";
        d.cpu_pct = 50.0;
        snap.devices.push_back(d);
        return snap;
    };

    DexRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
        perf_fn, yuzu::server::test::FnDexPerfApi::Providers{});
    routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, /*dispatch_fn=*/{},
                           /*responses_fn=*/{}, {}, {}, dex_perf_api);

    auto perf = sink.Get("/fragments/dex/perf/devices");
    REQUIRE(perf);
    CHECK(perf->status == 200);
    CHECK(perf->body.find("WS-1") != std::string::npos);
    bool saw_success = false;
    for (const auto& a : audit_log)
        if (a == "dex.perf.device.view|success")
            saw_success = true;
    CHECK(saw_success);
}

// ADR-0031 WS-A4 DexPerfApi seam (#4626) characterization: /fragments/dex/perf
// and /fragments/dex/perf/cohort-diff had NO route-level coverage before this
// seam's dashboard rewire. Pinned here BEFORE the rewire (perf_fn_ still the
// live provider) so the rewire onto DexPerfApi::fleet_snapshot cannot silently
// change the rendered HTML for these two fragments.
TEST_CASE("DEX perf fragment (F2a fleet-now): unwired placeholder vs wired snapshot",
          "[pg][dex][perf][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };

    SECTION("perf_fn unwired -> honest unavailable placeholder") {
        test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        auto r = sink.Get("/fragments/dex/perf");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("no perf snapshot provider wired") != std::string::npos);
    }

    SECTION("perf_fn wired -> fleet-now cards render the reporting device") {
        yuzu::server::DexPerfFn perf_fn = [](const std::string&) {
            yuzu::server::DexPerfSnapshot snap;
            yuzu::server::DexPerfDevice d;
            d.agent_id = "WS-1";
            d.os = "windows";
            d.cpu_pct = 50.0;
            snap.devices.push_back(d);
            return snap;
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            perf_fn, yuzu::server::test::FnDexPerfApi::Providers{});
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, /*dispatch_fn=*/{},
                               /*responses_fn=*/{}, {}, {}, dex_perf_api);
        auto r = sink.Get("/fragments/dex/perf");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Fleet now (last rollup cycle)") != std::string::npos);
        CHECK(r->body.find("CPU utilization") != std::string::npos);
        CHECK(r->body.find("50.0%") != std::string::npos);
    }
}

TEST_CASE("DEX perf cohort-diff fragment: unwired placeholder vs wired empty-cohort note",
          "[pg][dex][perf][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };

    SECTION("perf_fn unwired -> honest unavailable placeholder") {
        test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        auto r = sink.Get("/fragments/dex/perf/cohort-diff?a=x&b=y");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("no perf snapshot provider wired") != std::string::npos);
    }

    SECTION("perf_fn wired, no devices tagged -> both cohorts render absent") {
        yuzu::server::DexPerfFn perf_fn = [](const std::string&) {
            return yuzu::server::DexPerfSnapshot{}; // no devices, no keys
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            perf_fn, yuzu::server::test::FnDexPerfApi::Providers{});
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, /*dispatch_fn=*/{},
                               /*responses_fn=*/{}, {}, {}, dex_perf_api);
        auto r = sink.Get("/fragments/dex/perf/cohort-diff?a=imageA&b=imageB");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("no reporting devices") != std::string::npos);
        CHECK(r->body.find("absent") != std::string::npos);
        CHECK(r->body.find(">imageA</b>") != std::string::npos);
        CHECK(r->body.find(">imageB</b>") != std::string::npos);
    }
}

// kDexCohortFloor suppression at the route level (fleet + group + tag/model
// paths) — pinned before the DexPerfApi rewire so the floor can never
// silently drop out when the handler switches from AppPerfProviders.fleet/
// .group/.tag_cohort to DexPerfApi::app_fleet_trend/group_trend/tag_trend
// (all three apply the SAME app_perf_fleet_trend/app_perf_group_trend pure
// reduction + kDexCohortFloor — tag_trend shares group_trend's reduction).
TEST_CASE("DEX perf/app fragment: kDexCohortFloor suppresses a sub-floor point "
          "(fleet, group, and tag/model paths)",
          "[dex][app_perf][routes]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };

    auto sub_floor_row = []() {
        AppPerfFleetRow row;
        row.app_name = "chrome.exe";
        row.version = "125.0.0.0";
        row.day = 1'700'000'000;
        row.device_count = 3; // < kDexCohortFloor (10)
        row.cpu_sum = 30.0;
        row.cpu_max = 40.0;
        row.hist_version = kAppPerfHistVersion;
        return row;
    };

    SECTION("fleet path (no group/model) floors too") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = [&](std::string_view,
                              std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            return std::vector<AppPerfFleetRow>{sub_floor_row()};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=chrome.exe");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("n too small (fewer than 10 devices") != std::string::npos);
        // The exact CPU mean (30.0/3=10.0%) must be withheld once suppressed.
        CHECK(r->body.find("10.0%") == std::string::npos);
    }

    SECTION("group path floors identically") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.group = [&](std::string_view, std::string_view,
                              std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            return std::vector<AppPerfFleetRow>{sub_floor_row()};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=chrome.exe&group=G1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("n too small (fewer than 10 devices") != std::string::npos);
        CHECK(r->body.find("10.0%") == std::string::npos);
    }

    SECTION("tag/model path floors identically") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.tag_cohort =
            [&](std::string_view, std::string_view, std::string_view,
               std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            return std::vector<AppPerfFleetRow>{sub_floor_row()};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=chrome.exe&model=Latitude+5420");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("n too small (fewer than 10 devices") != std::string::npos);
        CHECK(r->body.find("10.0%") == std::string::npos);
    }
}

// ── A4: device perf sparklines (federated TAR query) ────────────────────────

TEST_CASE("DEX perf parse: schema-mapped columns, trailer skipped, chronological",
          "[dex][perf][parse]") {
    // Rows arrive DESC (the canned query's ORDER BY); parse must sort ASC and
    // skip the "total|N" trailer + map columns by NAME from the schema line.
    const std::string out = "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                            "7200|55.5|60.1|3000|1000\n"
                            "3600|20.0|40.0|500|2500\n"
                            "total|2\n";
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 2);
    CHECK(pts[0].hour_ts == 3600);
    CHECK(pts[0].cpu_avg == 20.0);
    CHECK(pts[0].disk_lat_ms == 2.5); // worse of read/write, us -> ms
    CHECK(pts[1].hour_ts == 7200);
    CHECK(pts[1].mem_avg == 60.1);
    CHECK(pts[1].disk_lat_ms == 3.0);
}

TEST_CASE("DEX perf parse: column order is schema-driven, not positional",
          "[dex][perf][parse]") {
    const std::string out = "__schema__|cpu_avg|hour_ts|write_lat_us_avg|mem_avg|read_lat_us_avg\n"
                            "75.0|3600|0|50.0|0\n";
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 1);
    CHECK(pts[0].cpu_avg == 75.0);
    CHECK(pts[0].hour_ts == 3600);
    CHECK(pts[0].mem_avg == 50.0);
}

TEST_CASE("DEX perf parse: error payload / wrong shape / garbage rows never render",
          "[dex][perf][parse]") {
    CHECK(parse_dex_perf_output("error|no such table").empty());
    CHECK(parse_dex_perf_output("").empty());
    // Schema missing a required column -> refuse rather than guess.
    CHECK(parse_dex_perf_output("__schema__|hour_ts|cpu_avg\n3600|50\n").empty());
    // Garbage cells: non-finite / negative / non-numeric rows are skipped;
    // a >100% percentage is clamped (forged data must not distort the chart).
    const std::string out = "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                            "3600|inf|50|0|0\n"
                            "3600|-5|50|0|0\n"
                            "3600|garbage|50|0|0\n"
                            "7200|9000|50|0|0\n";
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 1);
    CHECK(pts[0].cpu_avg == 100.0); // clamped
}

TEST_CASE("DEX perf parse: a forged disk latency is clamped, never crushes the sparkline",
          "[dex][perf][parse]") {
    // The SVG y-axis auto-scales to the series range, so one absurd-but-finite
    // disk-latency row (1e9 µs = 1e6 ms) would otherwise flatten every real
    // point to an invisible line. cell_double accepts it (finite, >=0, <=32
    // chars); the clamp at 1000 ms is the defence (gov QE B1).
    const std::string out = "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                            "3600|10|40|2000|1500\n"      // ~2 ms, real
                            "7200|10|40|1000000000|0\n";  // 1e9 µs forged
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 2);
    CHECK(pts[0].disk_lat_ms == 2.0);       // real point intact
    CHECK(pts[1].disk_lat_ms == 1000.0);    // forged row clamped, not 1e6
}

TEST_CASE("DEX perf panel: sparklines + now/min/max; empty input is honest",
          "[dex][perf][render]") {
    CHECK(render_dex_perf_panel({}).find("No performance history") != std::string::npos);

    std::vector<DexPerfPoint> pts;
    for (int i = 0; i < 5; ++i)
        pts.push_back({3600 * (i + 1), 10.0 * (i + 1), 42.0, 1.5});
    const auto html = render_dex_perf_panel(pts);
    CHECK(html.find("<svg") != std::string::npos); // server-rendered SVG, no JS
    CHECK(html.find("<polyline") != std::string::npos);
    CHECK(html.find("CPU busy") != std::string::npos);
    CHECK(html.find("Memory used") != std::string::npos);
    CHECK(html.find("Disk latency") != std::string::npos);
    CHECK(html.find("now 50%") != std::string::npos); // CPU last value
    CHECK(html.find("min 10%") != std::string::npos);
    CHECK(html.find("max 50%") != std::string::npos);
    CHECK(html.find("5 hourly rollups") != std::string::npos);
    CHECK(html.find("hx-on") == std::string::npos); // CSP rule: never hx-on
}

TEST_CASE("DEX device fragment embeds the CLICK-to-load perf panel", "[pg][dex][perf][render]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // With signals AND without - a quiet device still has perf history.
    const auto quiet = render_dex_device_fragment(&store, "WS-9", "7d");
    CHECK(quiet.find("/fragments/dex/device/perf?agent_id=WS-9") != std::string::npos);
    seed_crash(store, "e1", "WS-9", "app.exe", "m.dll", "windows", kDayB + "T10:00:00Z");
    const auto busy = render_dex_device_fragment(&store, "WS-9", "7d");
    CHECK(busy.find("/fragments/dex/device/perf?agent_id=WS-9") != std::string::npos);
    // Click-to-load, NEVER auto-load: the route dispatches a real command and
    // probes Execute (which audit-logs denials) — auto-loading would fire both
    // on every page view (grill finding 1). Pin the button + the absence of an
    // hx-trigger="load" auto-fire anywhere in the fragment.
    CHECK(busy.find("<button") != std::string::npos);
    CHECK(busy.find("Load performance") != std::string::npos);
    CHECK(busy.find("hx-trigger=\"load\"") == std::string::npos);
}

TEST_CASE("DEX perf routes: dispatch, poll, degrade, and authz posture",
          "[pg][dex][perf][routes][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    std::string audited;
    bool audit_ok = true;      // #1647: flip to drop the evidence row (audit_fn → false)
    bool audit_throws = false; // #1647: flip to throw a bad_alloc-class fault from audit_fn
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string& tid, const std::string&) -> bool {
        audited = a + "|" + r + "|" + tid;
        if (audit_throws)
            throw std::runtime_error("audit DB write blew up");
        return audit_ok;
    };

    // Fake dispatch + response store.
    int dispatched = 0;
    std::string seen_sql;
    int fake_sent = 1;
    auto dispatch = [&](const std::string& plugin, const std::string& action,
                        const std::vector<std::string>& ids, const std::string&,
                        const std::unordered_map<std::string, std::string>& params)
        -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatched;
        CHECK(plugin == "tar");
        CHECK(action == "sql");
        REQUIRE(ids.size() == 1);
        seen_sql = params.count("sql") ? params.at("sql") : "";
        return {.sent = fake_sent, .command_id = "tar-deadbeef"};
    };
    std::vector<DexAgentResponse> fake_rows;
    auto responses = [&](const std::string& command_id, const std::string& /*agent_id*/) {
        CHECK(command_id == "tar-deadbeef");
        return fake_rows;
    };

    yuzu::server::test::TestRouteSink sink;
    DexRoutes routes;
    routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, dispatch, responses);

    SECTION("dispatch returns the polling stub + audits the query") {
        auto r = sink.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(dispatched == 1);
        CHECK(seen_sql.find("$Perf_Hourly") != std::string::npos);
        CHECK(r->body.find("/fragments/dex/device/perf/result?command_id=tar-deadbeef") !=
              std::string::npos);
        CHECK(audited == "dex.device.perf.query|success|WS-1");
    }

    SECTION("offline device renders the honest note, no polling") {
        fake_sent = 0;
        auto r = sink.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->body.find("Device offline") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos);
    }

    SECTION("result poll: pending -> re-poll with n+1; data -> panel; error -> note") {
        auto pending =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(pending);
        CHECK(pending->body.find("&amp;n=2") != std::string::npos); // re-poll bumps the attempt

        fake_rows = {{"WS-1", 0,
                      "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                      "3600|33|44|0|0\n",
                      ""}};
        auto done =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(done);
        CHECK(done->body.find("<svg") != std::string::npos);
        CHECK(done->body.find("hx-trigger") == std::string::npos); // polling stopped
        // #4035: the poll route is where the parsed data actually reaches the
        // operator, so it must carry its own audit row (the dispatch's
        // "success" audit above is a SEPARATE row for the request, not the read).
        CHECK(audited == "dex.device.perf.query|rendered|WS-1");

        audited.clear();
        fake_rows = {{"WS-1", 0, "error|<b>no such table</b>", ""}};
        auto err =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(err);
        CHECK(err->body.find("reported an error") != std::string::npos);
        CHECK(err->body.find("<b>no such table</b>") == std::string::npos); // escaped, not raw
        CHECK(audited.empty()); // an agent-reported error is not an audited data access
    }

    SECTION("result poll: a valid-but-empty result renders 'no history', stops polling (gov S3)") {
        // The agent is online and answered, but $Perf_Hourly has no rows yet
        // (fresh agent, no rollup completed). Distinct from offline/timeout:
        // schema present, zero data rows. Must show the honest panel, not
        // re-poll forever — exercised THROUGH the route, not the render fn.
        fake_rows = {{"WS-1", 0,
                      "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                      "total|0\n",
                      ""}};
        auto empty =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(empty);
        CHECK(empty->body.find("No performance history") != std::string::npos);
        CHECK(empty->body.find("hx-trigger") == std::string::npos); // not re-polled
        CHECK(empty->body.find("<svg") == std::string::npos);
    }

    SECTION("result poll: another agent's rows never render; timeout is honest") {
        fake_rows = {{"OTHER-AGENT", 0,
                      "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                      "3600|33|44|0|0\n",
                      ""}};
        auto r =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(r);
        CHECK(r->body.find("<svg") == std::string::npos); // filtered out

        auto timeout = sink.Get(
            "/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=20");
        REQUIRE(timeout);
        CHECK(timeout->body.find("timed out") != std::string::npos);
        CHECK(timeout->body.find("hx-trigger") == std::string::npos);
    }

    SECTION("non-tar command_id is rejected - this route polls only tar dispatches") {
        auto r = sink.Get(
            "/fragments/dex/device/perf/result?command_id=script_exec-123&agent_id=WS-1&n=1");
        REQUIRE(r);
        CHECK(r->status == 400);
    }

    SECTION("read-only operator gets the in-panel Execute note, no dispatch") {
        auto readOnly = [](const httplib::Request&, httplib::Response& res,
                           const std::string& securable, const std::string& op) {
            if (securable == "Execution" && op == "Execute") {
                res.status = 403;
                return false;
            }
            return true;
        };
        yuzu::server::test::TestRouteSink sink2;
        DexRoutes routes2;
        routes2.register_routes(sink2, okAuth, readOnly, &store, fleet, audit, dispatch,
                                responses);
        auto r = sink2.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200); // in-panel note, NOT a swallowed 403
        CHECK(r->body.find("Execute") != std::string::npos);
        CHECK(dispatched == 0);
        auto poll = sink2.Get(
            "/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(poll);
        CHECK(poll->body.find("Execute") != std::string::npos); // result leg gated too
    }

    SECTION("no dispatch/responses wiring degrades to the unavailable note") {
        yuzu::server::test::TestRouteSink sink3;
        DexRoutes routes3;
        routes3.register_routes(sink3, okAuth, okPerm, &store, fleet, audit);
        auto r = sink3.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->body.find("unavailable") != std::string::npos);
    }

    // #1647 catch-arm parity: the perf/procperf dispatch audit set Sec-Audit-Failed on a
    // returns-false but had NO try/catch — a throwing audit_fn escaped the handler.
    // Routed through the shared rest_audit.hpp chokepoint, a throw is now caught and
    // flags the header while the set-and-proceed posture (still polls) is unchanged.
    SECTION("perf: a dropped audit row flags Sec-Audit-Failed, still polls") {
        audit_ok = false;
        auto r = sink.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(dispatched == 1);
        CHECK(r->body.find("/fragments/dex/device/perf/result") != std::string::npos);
    }
    SECTION("perf: a throwing audit_fn is caught, never escapes the handler") {
        audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = sink.Get("/fragments/dex/device/perf?agent_id=WS-1"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(dispatched == 1);
        CHECK(r->body.find("/fragments/dex/device/perf/result") != std::string::npos);
    }
    SECTION("procperf: a throwing audit_fn is caught + flags Sec-Audit-Failed") {
        audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = sink.Get("/fragments/dex/device/procperf?agent_id=WS-1"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(dispatched == 1);
        CHECK(seen_sql.find("$ProcPerf_Hourly") != std::string::npos);
        // The audit verb was actually reached (row recorded before the throw) — not a
        // header set by some unrelated path.
        CHECK(audited.find("dex.device.procperf.query") != std::string::npos);
    }
    SECTION("procperf: a dropped audit row flags Sec-Audit-Failed, still polls") {
        audit_ok = false;
        auto r = sink.Get("/fragments/dex/device/procperf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(dispatched == 1);
        CHECK(audited.find("dex.device.procperf.query") != std::string::npos);
    }
    // #4035: both /result poll routes previously had NO audit call at all — only
    // the dispatch half was audited. The poll is where the parsed data actually
    // reaches the operator, so it needs its own row (fires only when data is
    // actually rendered, never on a still-pending re-poll).
    SECTION("procperf result poll: rendered data is audited under its own verb") {
        fake_rows = {{"WS-1", 0,
                      "__schema__|name|samples|instances_max|cpu_avg|cpu_max|ws_avg|ws_max|hours\n"
                      "chrome.exe|10|3|25.5|40.0|1000000|2000000|5\n",
                      ""}};
        auto r = sink.Get(
            "/fragments/dex/device/procperf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(r);
        CHECK(r->body.find("chrome.exe") != std::string::npos);
        CHECK(audited == "dex.device.procperf.query|rendered|WS-1");
    }
    SECTION("procperf result poll: still pending is NOT audited (no per-attempt spam)") {
        auto r = sink.Get(
            "/fragments/dex/device/procperf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(r);
        CHECK(r->body.find("hx-trigger") != std::string::npos); // re-polling
        CHECK(audited.empty());
    }
    SECTION("perf clean path sets NO Sec-Audit-Failed header") {
        auto r = sink.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed").empty()); // audit_ok=true, no throw
        CHECK(audited == "dex.device.perf.query|success|WS-1");
    }
}

// ── Drift-net for the per-OS coverage map (dex_obs_platforms). The map must claim
// a platform collects a signal type ONLY when an agent on that platform actually
// emits it. This is the guard the comment by dex_obs_platforms promises but that
// never existed — its absence let the Linux column advertise kernel/sysfs signals
// whose collectors live in a separate PR (#1523), so a Linux fleet would read
// "monitored, quiet" as healthy for signals nothing collects. The server suite
// can't introspect the agent collectors, so the emitted set is pinned here; when
// collectors are added or removed, update BOTH the collector and the set below in
// the same change (that conscious edit is the point). ──
TEST_CASE("dex coverage map matches the emitted signal set (Linux + macOS)",
          "[dex][coverage]") {
    // What a Linux agent emits today — dex_linux_collector drives all of these: poll_perf
    // (the /proc CPU + memory + diskstats breach trio — perf.disk_latency_high is the
    // /proc/diskstats await breach, as live as cpu/mem on ordinary disks) + statvfs
    // storage (dex_linux_proc/storage), the sysfs throttle counter (dex_linux_sysfs), and
    // the journald poll (dex_linux_journal), whose _TRANSPORT=kernel lines are classified
    // by dex_linux_kmsg::classify_kernel_message. The server suite can't introspect the
    // agent collectors, so this set is pinned by hand — keep it in lockstep.
    const std::set<std::string> kLinuxEmitted = {
        "perf.cpu_sustained", "perf.memory_pressure",  "perf.disk_latency_high", "storage.low",
        "os.uptime_report",   "hw.cpu_throttled",      "process.crashed",        "service.crashed",
        "service.hung",       "os.time_unsynced",      "memory.exhausted",       "os.bugcheck",
        "os.dirty_shutdown",  "disk.error",            "fs.corruption",          "hw.error",
        "process.hung"};
    // What a macOS agent emits today — dex_macos_collector drives oslog + iokit +
    // signals/uptime. NOTE: process.resource_limit is also emitted but is NOT yet in
    // the catalogue taxonomy (it surfaces under "Other"); adding it to a family needs
    // the catalogued⇒Windows assumption relaxed, so it is correctly absent here for now.
    const std::set<std::string> kMacEmitted = {
        "process.crashed",  "process.hung",       "os.bugcheck",       "memory.exhausted",
        "os.uptime_report", "disk.smart_failure", "hw.error",          "storage.low",
        "hw.cpu_throttled", "service.crashed",    "network.wifi_drop", "update.failed",
        "print.failed",     "mgmt.mdm_error",     "logon.no_dc",       "fs.corruption"};

    // Size sentinels: the over/under-claim loops below skip a type absent from BOTH the
    // map and the emitted set, so a simultaneous deletion from kLinux[] + kLinuxEmitted
    // would pass silently. Pin the counts so accidental set-shrinkage fails loudly.
    REQUIRE(kLinuxEmitted.size() == 17);
    REQUIRE(kMacEmitted.size() == 16);

    auto claims = [](const std::string& obs_type, const char* os) {
        const auto p = dex_obs_platforms(obs_type);
        return std::find(p.begin(), p.end(), os) != p.end();
    };

    // Overclaim guard: every catalogued type the map marks for a platform must be in
    // that platform's emitted set — never advertise a signal nothing collects.
    for (const auto& g : dex_signal_groups()) {
        for (const char* t : g.types) {
            if (claims(t, "linux")) {
                INFO("coverage map claims Linux collects '"
                     << t << "' but no Linux collector emits it (see dex_obs_platforms)");
                CHECK(kLinuxEmitted.count(t) == 1);
            }
            if (claims(t, "macos")) {
                INFO("coverage map claims macOS collects '"
                     << t << "' but no macOS collector emits it (see dex_obs_platforms)");
                CHECK(kMacEmitted.count(t) == 1);
            }
        }
    }

    // Underclaim guard: every emitted signal is actually advertised by the map.
    for (const auto& t : kLinuxEmitted) {
        INFO("emitted Linux signal '" << t << "' is missing from the coverage map");
        CHECK(claims(t, "linux"));
    }
    for (const auto& t : kMacEmitted) {
        INFO("emitted macOS signal '" << t << "' is missing from the coverage map");
        CHECK(claims(t, "macos"));
    }

    // Windows is the whole EvtSubscribe catalogue — always present and first.
    const auto win = dex_obs_platforms("process.crashed");
    REQUIRE_FALSE(win.empty());
    CHECK(win.front() == "windows");
}

TEST_CASE("DEX device app-perf drill: gating, audit verb, and three read states",
          "[pg][dex][app_perf][routes][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto noPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return false; };
    auto fleet = []() { return DexFleet{1, 1}; };
    std::string audited;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string& ttype, const std::string& tid, const std::string&) -> bool {
        audited = a + "|" + r + "|" + ttype + "|" + tid;
        return true;
    };

    // B1 device provider: success rows, or a nullopt degrade when `degrade` is set.
    bool degrade = false;
    yuzu::server::test::FnDexPerfApi::Providers providers;
    providers.device =
        [&](std::string_view agent_id) -> std::optional<std::vector<AppPerfDailyRow>> {
        CHECK(agent_id == "WS-1"); // the route must thread the agent_id, not a constant
        if (degrade)
            return std::nullopt;
        AppPerfDailyRow row;
        row.app_name = "chrome.exe";
        row.version = "125";
        row.day = 1'700'000'000;
        row.samples = 10;
        row.instances_max = 8;
        row.cpu_avg = 12.4;
        row.cpu_max = 31.0;
        row.ws_avg_bytes = 1'800'000'000;
        row.ws_max_bytes = 2'400'000'000;
        return std::vector<AppPerfDailyRow>{row};
    };

    SECTION("rows -> rendered table + dex.device.app_perf.view audit") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/device/app-perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("chrome.exe") != std::string::npos);
        CHECK(r->body.find(">125</span>") != std::string::npos); // the version, in its mono span
        // Same usage-class verb as the REST drill, PascalCase target_type.
        CHECK(audited == "dex.device.app_perf.view|success|Agent|WS-1");
    }

    SECTION("empty rows -> \"No application performance history\" placeholder, not the "
            "unavailable note") {
        // A wired, healthy provider that simply has nothing retained yet for this
        // device (present-empty, distinct from the nullopt degrade below) must
        // render the honest-empty state, never the "unavailable" wording reserved
        // for an unwired/degraded read.
        providers.device =
            [](std::string_view agent_id) -> std::optional<std::vector<AppPerfDailyRow>> {
            CHECK(agent_id == "WS-1");
            return std::vector<AppPerfDailyRow>{};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/device/app-perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("No application performance history") != std::string::npos);
        CHECK(r->body.find("App performance data unavailable") == std::string::npos);
        CHECK(audited == "dex.device.app_perf.view|success|Agent|WS-1");
    }

    SECTION("store degrade (nullopt) -> 200 honest note (htmx drops 4xx/5xx), audit still fired") {
        degrade = true;
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/device/app-perf?agent_id=WS-1");
        REQUIRE(r);
        // 200, NOT 503: the dashboard htmx config (swap:false for [45]..) would drop a
        // 503 body, rendering nothing — the exact "fake empty" the note avoids.
        CHECK(r->status == 200);
        // SAME unified F2b wording as the trend/app-list fragments (C-1).
        CHECK(r->body.find("App performance data unavailable (not configured or "
                           "degraded) — retry shortly.") != std::string::npos);
        // The access audit fires BEFORE the read, so a degrade still carries the row.
        CHECK(audited == "dex.device.app_perf.view|success|Agent|WS-1");
    }

    SECTION("no provider wired -> graceful note, audit STILL fires (#4626 Concern A: over-audits)") {
        test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit); // dex_perf_api={}
        auto r = sink.Get("/fragments/dex/device/app-perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->body.find("App performance data unavailable (not configured or "
                           "degraded) — retry shortly.") != std::string::npos);
        // #4626: dex_perf_api_ is constructed UNCONDITIONALLY in production, so
        // there is no longer a distinct "provider unwired" signal to check
        // BEFORE the audit — the audit now fires even on this null-dex_perf_api_
        // path (over-audits, never under-audits).
        CHECK(audited == "dex.device.app_perf.view|success|Agent|WS-1");
    }

    SECTION("missing agent_id -> note at 200, no audit (guarded before the PII audit)") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/device/app-perf"); // no agent_id query param
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Missing agent_id") != std::string::npos);
        CHECK(audited.empty()); // rejected before the behavioural-PII audit
    }

    SECTION("scoped_perm_fn receives the device agent_id, not a constant (UP-6)") {
        std::string scoped_seen;
        auto scoped = [&](const httplib::Request&, httplib::Response&, const std::string& type,
                          const std::string& op, const std::string& id) {
            scoped_seen = type + ":" + op + ":" + id;
            return true;
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, scoped, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/device/app-perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(scoped_seen == "GuaranteedState:Read:WS-1"); // the scope gate got the device id
    }

    SECTION("perm-denied -> gate runs BEFORE audit + read (no audit row, no PII)") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, noPerm, &store, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/device/app-perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(audited.empty()); // denied before the behavioural-PII audit fires
        CHECK(r->body.find("chrome.exe") == std::string::npos);
    }
}

TEST_CASE("DEX version-devices drill fragment: gate, param validation, audit, "
          "visible-set threading",
          "[dex][app_perf][routes][rbac]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    std::string audited;
    std::string audited_result;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string& ttype, const std::string& tid, const std::string& d) -> bool {
        audited = a + "|" + r + "|" + ttype + "|" + tid + "|" + d;
        audited_result = r;
        return true;
    };

    std::optional<std::vector<std::string>> seen_visible_ids;
    bool seen_visible_ids_set = false;
    bool degrade = false;
    yuzu::server::test::FnDexPerfApi::Providers providers;
    providers.version_devices =
        [&](std::string_view app, std::string_view version,
            const std::optional<std::vector<std::string>>& visible_ids,
            bool& truncated) -> std::optional<std::vector<AppPerfVersionDeviceRow>> {
        CHECK(app == "chrome.exe");
        seen_visible_ids = visible_ids;
        seen_visible_ids_set = true;
        truncated = false;
        if (degrade)
            return std::nullopt;
        (void)version;
        AppPerfVersionDeviceRow r;
        r.agent_id = "WS-1";
        r.last_day = 1'700'000'000;
        r.samples = 5;
        r.cpu_avg = 42.0;
        r.ws_avg_bytes = 100;
        return std::vector<AppPerfVersionDeviceRow>{r};
    };

    auto admit_unfiltered = [](const httplib::Request&, httplib::Response&, const std::string&,
                               const std::string&) {
        return authz::FleetReadGate{.admitted = true, .scope = std::nullopt};
    };
    auto admit_scoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                           const std::string&) {
        return authz::FleetReadGate{
            .admitted = true,
            .scope = authz::VisibleSet{std::unordered_set<std::string>{"WS-1"}}};
    };
    auto deny = [](const httplib::Request&, httplib::Response& res, const std::string&,
                   const std::string&) {
        res.status = 403;
        return authz::FleetReadGate{.admitted = false};
    };

    SECTION("gate unwired -> 200 note, no read, no audit (fails closed, never falls back)") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}); // fleet_read_fn = {} (unwired)
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe&version=1.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("authorization gate not configured") != std::string::npos);
        CHECK_FALSE(seen_visible_ids_set); // provider never called
        CHECK(audited.empty());
    }

    SECTION("gate denies -> the gate's own status stands, no read, no audit") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}, deny);
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe&version=1.0");
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK_FALSE(seen_visible_ids_set);
        CHECK(audited.empty());
    }

    SECTION("missing app -> 200 note, gate never called, no read, no audit") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}, admit_unfiltered);
        auto r = sink.Get("/fragments/dex/perf/app/devices?version=1.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Missing or invalid") != std::string::npos);
        CHECK_FALSE(seen_visible_ids_set);
    }

    SECTION("missing version (absent, not empty) -> 200 note -- omission is NOT "
            "'all versions' on this route") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}, admit_unfiltered);
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Missing or invalid") != std::string::npos);
        CHECK_FALSE(seen_visible_ids_set);
    }

    SECTION("EMPTY version (present, explicit) IS accepted -- the unknown-version bucket") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}, admit_unfiltered);
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe&version=");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(seen_visible_ids_set); // reached the provider — "" was accepted
        CHECK(r->body.find("WS-1") != std::string::npos);
    }

    SECTION("nullopt gate scope (unfiltered) threads through as nullopt, not an empty vector") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}, admit_unfiltered);
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe&version=1.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        REQUIRE(seen_visible_ids_set);
        CHECK_FALSE(seen_visible_ids.has_value()); // unfiltered, not deny-all
        CHECK(r->body.find("WS-1") != std::string::npos);
        CHECK(r->body.find("42.0%") != std::string::npos);
        // Audit fires AFTER the read with the real device count.
        CHECK(audited.find("dex.app_perf.devices.view|success|GuaranteedState|") == 0);
        CHECK(audited.find("devices=1") != std::string::npos);
    }

    SECTION("engaged gate scope threads through the EXACT set (ADR-0017 push-into-query)") {
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}, admit_scoped);
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe&version=1.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        REQUIRE(seen_visible_ids_set);
        REQUIRE(seen_visible_ids.has_value());
        REQUIRE(seen_visible_ids->size() == 1);
        CHECK((*seen_visible_ids)[0] == "WS-1");
    }

    SECTION("store degrade -> 200 honest note, audit fires with result=failure") {
        degrade = true;
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {}, admit_unfiltered);
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe&version=1.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("could not be read") != std::string::npos);
        CHECK(audited_result == "failure");
    }

    SECTION("no provider wired -> graceful note, no audit") {
        test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               {}, {}, admit_unfiltered); // dex_perf_api = {} (unwired)
        auto r = sink.Get("/fragments/dex/perf/app/devices?app=chrome.exe&version=1.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("no app-perf device provider wired") != std::string::npos);
        CHECK(audited.empty());
    }
}

// Regression pin for a raw/canonical `version` split at the route seam: the
// handler used to thread the RAW query value to the provider call while ALSO
// passing it as `render_dex_app_perf_trend`'s `active_version` label — since the
// store canonicalizes via `canon_version` before filtering (empty OR
// non-numeric -> "", a short/leading-zero form -> its 4-group canonical form),
// a mismatched pair let the page claim "Filtered to version X" over data the
// store never actually filtered (X non-canonicalizable -> store applied NO
// filter), or echo the wrong string for a value that WAS correctly filtered
// (X short-form -> store filtered on the canonical form, banner showed the
// raw one). The fix canonicalizes ONCE in the handler and reuses that single
// value for both the provider call and the render call — these tests assert
// the provider and the rendered banner agree, not just that each looks right
// in isolation.
TEST_CASE("DEX perf/app fragment: version canonicalized once, provider and "
          "rendered banner never disagree",
          "[dex][app_perf][routes]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    auto audit = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };

    SECTION("short-form version canonicalizes before reaching the fleet provider AND the banner") {
        std::string seen_app, seen_version;
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = [&](std::string_view app,
                              std::string_view version) -> std::optional<std::vector<AppPerfFleetRow>> {
            seen_app = std::string(app);
            seen_version = std::string(version);
            return std::vector<AppPerfFleetRow>{}; // empty rows: banner still renders pre-empty-state
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&version=1.2");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(seen_app == "Foo");
        CHECK(seen_version == "1.2.0.0"); // provider got the canonical form, not raw "1.2"
        // Exact tag-boundary check (not a bare substring) — "1.2.0.0" contains
        // "1.2" as a substring, so a loose check would pass even if the banner
        // still echoed the raw value.
        CHECK(r->body.find(">1.2.0.0</span>") != std::string::npos);
        CHECK(r->body.find(">1.2</span>") == std::string::npos);
        CHECK(r->body.find("Filtered to version") != std::string::npos);
    }

    SECTION("non-canonicalizable version folds to unfiltered -- never rendered as \"filtered\"") {
        std::string seen_version = "not-yet-called";
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = [&](std::string_view,
                              std::string_view version) -> std::optional<std::vector<AppPerfFleetRow>> {
            seen_version = std::string(version);
            return std::vector<AppPerfFleetRow>{};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&version=latest");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(seen_version.empty()); // "latest" canonicalizes to "" -> the store's own
                                     // all-versions sentinel, same as if version were omitted
        // The page must not claim a filter is active when none was applied.
        CHECK(r->body.find("Filtered to version") == std::string::npos);
    }

    // `canon_version` folds an all-zero quad to "" via a DIFFERENT predicate
    // (`all_zero`) than a non-numeric string ("latest" above, `ngroups==0`) —
    // distinct branches that happen to share an outcome, so covering one at
    // this (route) level doesn't exercise the other.
    SECTION("all-zero version (\"0.0.0.0\") also folds to unfiltered") {
        std::string seen_version = "not-yet-called";
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = [&](std::string_view,
                              std::string_view version) -> std::optional<std::vector<AppPerfFleetRow>> {
            seen_version = std::string(version);
            return std::vector<AppPerfFleetRow>{};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&version=0.0.0.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(seen_version.empty());
        CHECK(r->body.find("Filtered to version") == std::string::npos);
    }

    SECTION("group path threads the SAME canonical version as the fleet path") {
        std::string seen_group, seen_app, seen_version;
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.group = [&](std::string_view group, std::string_view app,
                              std::string_view version) -> std::optional<std::vector<AppPerfFleetRow>> {
            seen_group = std::string(group);
            seen_app = std::string(app);
            seen_version = std::string(version);
            return std::vector<AppPerfFleetRow>{};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&group=G1&version=01.2.0.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(seen_group == "G1");
        CHECK(seen_app == "Foo");
        CHECK(seen_version == "1.2.0.0"); // leading-zero form canonicalized, matching the fleet path
        CHECK(r->body.find(">1.2.0.0</span>") != std::string::npos);
    }

    SECTION("model path fires tag_cohort with the SAME canonical version as the fleet path") {
        std::string seen_key, seen_value, seen_app, seen_version;
        bool group_called = false;
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.group = [&](std::string_view, std::string_view,
                              std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            group_called = true;
            return std::vector<AppPerfFleetRow>{};
        };
        providers.tag_cohort = [&](std::string_view key, std::string_view value,
                                   std::string_view app,
                                   std::string_view version) -> std::optional<std::vector<AppPerfFleetRow>> {
            seen_key = std::string(key);
            seen_value = std::string(value);
            seen_app = std::string(app);
            seen_version = std::string(version);
            return std::vector<AppPerfFleetRow>{};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&model=Latitude+5420&version=01.2.0.0");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_FALSE(group_called); // model= alone must dispatch tag_cohort, not group
        CHECK(seen_key == "model"); // default key
        CHECK(seen_value == "Latitude 5420");
        CHECK(seen_app == "Foo");
        CHECK(seen_version == "1.2.0.0"); // canonicalized, matching every other scope path
        CHECK(r->body.find(">1.2.0.0</span>") != std::string::npos);
    }

    SECTION("group wins when both group= and model= are present") {
        bool group_called = false, tag_called = false;
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.group = [&](std::string_view, std::string_view,
                              std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            group_called = true;
            return std::vector<AppPerfFleetRow>{};
        };
        providers.tag_cohort = [&](std::string_view, std::string_view, std::string_view,
                                   std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            tag_called = true;
            return std::vector<AppPerfFleetRow>{};
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&group=G1&model=Latitude+5420");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(group_called);
        CHECK_FALSE(tag_called);
    }

    SECTION("model path: unwired tag_cohort reader -> honest placeholder, never a crash") {
        yuzu::server::test::FnDexPerfApi::Providers providers; // .tag_cohort left null
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&model=Latitude+5420");
        REQUIRE(r);
        CHECK(r->status == 200); // dashboard htmx drops 4xx/5xx bodies -- always 200 + a note
        // #4626 Concern A: DexPerfApi::tag_trend collapses "unwired" and
        // "degraded" to the SAME nullopt — ONE honest wording, not the old
        // "no device-model cohort reader wired" placeholder.
        CHECK(r->body.find("App performance data unavailable (not configured or "
                           "degraded) — retry shortly.") != std::string::npos);
    }

    SECTION("model path: store degrade (tag_cohort returns nullopt) -> honest placeholder") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.tag_cohort = [](std::string_view, std::string_view, std::string_view,
                                  std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            return std::nullopt; // AUTHORITATIVE degrade (tag lookup OR the aggregate read failed)
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
            yuzu::server::DexPerfFn{}, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo&model=Latitude+5420");
        REQUIRE(r);
        CHECK(r->status == 200);
        // #4626 Concern A: ONE honest wording (see the sibling "unwired" test above).
        CHECK(r->body.find("App performance data unavailable (not configured or "
                           "degraded) — retry shortly.") != std::string::npos);
    }

    SECTION("model selector values come from DexPerfApi::fleet_snapshot cohorts "
            "(#4857 D1) — the SAME dex_perf_cohorts() derivation "
            "GET /api/v1/dex/perf/cohorts uses, not a standalone TagStore read; "
            "populates regardless of active scope branch") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = [](std::string_view,
                             std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            return std::vector<AppPerfFleetRow>{};
        };
        yuzu::server::DexPerfFn dex_perf_fn =
            [](const std::string& cohort_key) -> yuzu::server::DexPerfSnapshot {
            CHECK(cohort_key == "model"); // kDexDefaultCohortKey
            yuzu::server::DexPerfSnapshot snap;
            snap.cohort_key = cohort_key;
            yuzu::server::DexPerfDevice d1;
            d1.agent_id = "a1";
            d1.cpu_pct = 10.0;
            d1.cohort = "Latitude 5420";
            yuzu::server::DexPerfDevice d2;
            d2.agent_id = "a2";
            d2.cpu_pct = 20.0;
            d2.cohort = "OptiPlex 7090";
            snap.devices = {d1, d2};
            return snap;
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api =
            std::make_shared<yuzu::server::test::FnDexPerfApi>(dex_perf_fn, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo"); // fleet-wide, no scope selected
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("Latitude 5420") != std::string::npos);
        CHECK(r->body.find("OptiPlex 7090") != std::string::npos);
        CHECK(r->body.find("no device-model values in the current fleet snapshot") == std::string::npos);
    }

    SECTION("model selector: zero reporting devices this cycle -> lists nothing + an "
            "honest note, never a claimed \"degraded\" state (#4857 D1: "
            "fleet_snapshot has no degrade channel)") {
        yuzu::server::test::FnDexPerfApi::Providers providers;
        providers.fleet = [](std::string_view,
                             std::string_view) -> std::optional<std::vector<AppPerfFleetRow>> {
            return std::vector<AppPerfFleetRow>{}; // trend itself succeeds (empty)
        };
        yuzu::server::DexPerfFn dex_perf_fn =
            [](const std::string&) -> yuzu::server::DexPerfSnapshot {
            return yuzu::server::DexPerfSnapshot{}; // zero devices this cycle
        };
        test::TestRouteSink sink;
        DexRoutes routes;
        auto dex_perf_api =
            std::make_shared<yuzu::server::test::FnDexPerfApi>(dex_perf_fn, providers);
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               dex_perf_api, {});
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("name=\"model\"") == std::string::npos); // no selector
        CHECK(r->body.find("no device-model values in the current fleet snapshot") != std::string::npos);
        CHECK(r->body.find("degraded") == std::string::npos);
    }

    SECTION("model selector: dex_perf_api_ entirely unwired -> the base trend itself "
            "already fails closed with its own honest placeholder before the model "
            "note is ever reached (never a crash, never a different \"degraded\" "
            "wording)") {
        test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, audit, {}, {}, {}, {},
                               {}, {}); // dex_perf_api = {} (fully unwired)
        auto r = sink.Get("/fragments/dex/perf/app?app=Foo");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("App performance data unavailable (not configured or "
                           "degraded) — retry shortly.") != std::string::npos);
        CHECK(r->body.find("no device-model values in the current fleet snapshot") == std::string::npos);
        CHECK(r->body.find("name=\"model\"") == std::string::npos);
    }
}

TEST_CASE("DEX perf/apps picker route: q/platform/sort params reach the render "
          "function raw (normalization/filtering happens there)",
          "[dex][app_perf][routes]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };

    yuzu::server::test::FnDexPerfApi::Providers providers;
    providers.apps = [](bool& truncated) -> std::optional<std::vector<AppPerfAppSummary>> {
        truncated = false;
        return std::vector<AppPerfAppSummary>{
            {.app_name = "chrome.exe", .versions = 3, .last_day = 200},
            {.app_name = "sshd", .versions = 1, .last_day = 100},
        };
    };
    test::TestRouteSink sink;
    DexRoutes routes;
    auto dex_perf_api = std::make_shared<yuzu::server::test::FnDexPerfApi>(
        yuzu::server::DexPerfFn{}, providers);
    routes.register_routes(sink, okAuth, okPerm, nullptr, fleet, {}, {}, {}, {}, {}, dex_perf_api,
                           {});

    SECTION("no params: both apps render, unfiltered") {
        auto r = sink.Get("/fragments/dex/perf/apps");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("chrome.exe") != std::string::npos);
        CHECK(r->body.find("sshd") != std::string::npos);
    }

    SECTION("q= substring-filters by name") {
        auto r = sink.Get("/fragments/dex/perf/apps?q=chrome");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("chrome.exe") != std::string::npos);
        CHECK(r->body.find(">sshd<") == std::string::npos);
    }

    SECTION("platform=windows keeps only the .exe-suffixed row") {
        auto r = sink.Get("/fragments/dex/perf/apps?platform=windows");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("chrome.exe") != std::string::npos);
        CHECK(r->body.find(">sshd<") == std::string::npos);
    }

    SECTION("sort=name orders alphabetically") {
        auto r = sink.Get("/fragments/dex/perf/apps?sort=name");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("chrome.exe") < r->body.find("sshd")); // c before s
    }
}
