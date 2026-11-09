/// @file test_hardware_list_model.cpp
/// Tests for the PURE /hardware CI list model (hardware_list_model.hpp/.cpp) — no
/// httplib, no gRPC, no store dependency, so every case here is in-process and
/// instant (the whole point of splitting this header out of the route layer).
///
/// Coverage, per the code review's own named gaps:
///  - sort-key parse/token round-trip, incl. the new `version`/`ip` keys.
///  - normalise_hardware_query: os/status/sort validation, tag-filter key
///    validation (TagStore::validate_key's rules), limit clamping.
///  - hw_search_tokens: whitespace split, lowercase fold, 8-token cap.
///  - hw_row_matches: os/status/tag facets, and the search haystack's new
///    fields (agent_version, arch, ips, tag key, tag key=value).
///  - hardware_kpis: computed over the full roster, before q/os/status narrowing.
///  - build_hardware_list_page: the new `version`/`ip` sort keys (numeric
///    semver-3 / lexicographic, blanks sort LAST regardless of direction),
///    and offset/limit pagination.
///  - hardware_row_json / hardware_list_json: JSON-null normalisation for
///    blank/sentinel fields, never an empty string/array/-1.
///  - agent_supports_sync_now: the >= 0.13.1 semver-3 floor, exact boundary.
///  - hardware_query_from_args / scoped_roster / id_is_audit_safe / classify_hardware_ci_read:
///    the shared read core the REST handlers and the MCP twin both call.
///  - hardware_ci_json: ci_state discrimination (found/absent/degraded) and
///    the independent nullopt-vs-present-empty signal for software/tags.

#include "device_ci_kinds.hpp"
#include "device_ci_section_digest.hpp"
#include "hardware_list_model.hpp"
#include "hardware_section_integrity.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <yuzu/metrics.hpp>

#include "../test_log_capture.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

/// A minimal online row with a distinguishing agent_id — every field a given
/// TEST_CASE cares about is set explicitly on top of this.
InventoryDeviceRow make_row(std::string agent_id) {
    InventoryDeviceRow r;
    r.agent_id = std::move(agent_id);
    r.os = "linux";
    r.online = true;
    r.last_seen = "now";
    r.last_seen_ms = 1000;
    return r;
}

OfflineEndpoint make_offline_ep(const std::string& id, std::int64_t hb_ms) {
    OfflineEndpoint e;
    e.agent_id = id;
    e.hostname = "host-" + id;
    e.os = "linux";
    e.last_heartbeat_ms = hb_ms;
    return e;
}
std::string fake_age(std::int64_t) { return std::string("aged"); }
constexpr std::int64_t kDayMs = 24LL * 60 * 60 * 1000;

} // namespace

// ── parse_hw_sort_key / hw_sort_token ───────────────────────────────────────

TEST_CASE("parse_hw_sort_key / hw_sort_token round-trip every whitelisted token", "[hardware][model]") {
    constexpr std::array<std::pair<std::string_view, HwSortKey>, 12> kTokens{{
        {"name", HwSortKey::Name},
        {"os", HwSortKey::Os},
        {"status", HwSortKey::Status},
        {"last_seen", HwSortKey::LastSeen},
        {"manufacturer", HwSortKey::Manufacturer},
        {"model", HwSortKey::Model},
        {"serial", HwSortKey::Serial},
        {"cpu", HwSortKey::Cpu},
        {"ram", HwSortKey::Ram},
        {"os_version", HwSortKey::OsVersion},
        {"version", HwSortKey::Version}, // round-3 merge — agent_version, NOT DEX
        {"ip", HwSortKey::Ip},
    }};
    for (const auto& [token, key] : kTokens) {
        const auto parsed = parse_hw_sort_key(token);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == key);
        CHECK(hw_sort_token(key) == token);
    }
}

TEST_CASE("parse_hw_sort_key: unrecognised token is nullopt, never a fallback column",
          "[hardware][model]") {
    CHECK_FALSE(parse_hw_sort_key("").has_value());
    CHECK_FALSE(parse_hw_sort_key("bogus").has_value());
    CHECK_FALSE(parse_hw_sort_key("dex_score").has_value()); // version is NOT dex — not a token either
    CHECK_FALSE(parse_hw_sort_key("Name").has_value());      // case-sensitive at this layer
}

// ── normalise_hardware_query ─────────────────────────────────────────────────

TEST_CASE("normalise_hardware_query: blank os/status/sort default to all/all/name", "[hardware][model]") {
    HardwareListQuery raw;
    raw.os.clear();
    raw.status.clear();
    raw.sort.clear();
    raw.limit = 0;
    const auto q = normalise_hardware_query(raw);
    REQUIRE(q.has_value());
    CHECK(q->os == "all");
    CHECK(q->status == "all");
    CHECK(q->sort == "name");
    CHECK(q->limit == 50); // 0 reads as "unset" -> default 50, not clamped to the floor of 1
}

TEST_CASE("normalise_hardware_query: os/status/sort case-folded to lowercase", "[hardware][model]") {
    HardwareListQuery raw;
    raw.os = "WINDOWS";
    raw.status = "ONLINE";
    raw.sort = "VERSION";
    const auto q = normalise_hardware_query(raw);
    REQUIRE(q.has_value());
    CHECK(q->os == "windows");
    CHECK(q->status == "online");
    CHECK(q->sort == "version");
}

TEST_CASE("normalise_hardware_query: limit clamps to [1,200], never rejected", "[hardware][model]") {
    HardwareListQuery raw;
    raw.limit = 5000;
    auto q = normalise_hardware_query(raw);
    REQUIRE(q.has_value());
    CHECK(q->limit == 200);

    raw.limit = 1;
    q = normalise_hardware_query(raw);
    REQUIRE(q.has_value());
    CHECK(q->limit == 1);
}

TEST_CASE("normalise_hardware_query: unrecognised os/status/sort token is the only rejection case",
          "[hardware][model]") {
    HardwareListQuery raw;
    raw.os = "bsd";
    CHECK_FALSE(normalise_hardware_query(raw).has_value());

    raw = HardwareListQuery{};
    raw.status = "zombie";
    CHECK_FALSE(normalise_hardware_query(raw).has_value());

    raw = HardwareListQuery{};
    raw.sort = "nonsense";
    CHECK_FALSE(normalise_hardware_query(raw).has_value());
}

// ── normalise_hardware_query — tag filter (TagStore::validate_key's rules) ──

TEST_CASE("normalise_hardware_query: tag filter — bare key matches any value", "[hardware][model][tag]") {
    HardwareListQuery raw;
    raw.tag = "env";
    const auto q = normalise_hardware_query(raw);
    REQUIRE(q.has_value());
    CHECK(q->tag == "env");
}

TEST_CASE("normalise_hardware_query: tag filter — key=value matches exactly", "[hardware][model][tag]") {
    HardwareListQuery raw;
    raw.tag = "env=prod";
    const auto q = normalise_hardware_query(raw);
    REQUIRE(q.has_value());
    CHECK(q->tag == "env=prod");
}

TEST_CASE("normalise_hardware_query: empty tag = no filter, always valid", "[hardware][model][tag]") {
    HardwareListQuery raw;
    raw.tag.clear();
    CHECK(normalise_hardware_query(raw).has_value());
}

TEST_CASE("normalise_hardware_query: an invalid tag key returns nullopt (route layer 400s on it)",
          "[hardware][model][tag]") {
    // TagStore::validate_key admits only 1-64 chars of [A-Za-z0-9_.:-] — this test
    // covers the pure function's nullopt return only, not the HTTP 400 itself.
    HardwareListQuery raw;
    raw.tag = "bad key"; // space is outside the allowed set
    CHECK_FALSE(normalise_hardware_query(raw).has_value());

    raw.tag = "bad/key"; // slash is outside the allowed set
    CHECK_FALSE(normalise_hardware_query(raw).has_value());

    raw.tag = std::string(65, 'x'); // one over the 64-char cap
    CHECK_FALSE(normalise_hardware_query(raw).has_value());
}

TEST_CASE("normalise_hardware_query: an invalid key half rejects even with a value suffix",
          "[hardware][model][tag]") {
    HardwareListQuery raw;
    raw.tag = "bad key=prod"; // only the key half ("bad key") is validated, and it's invalid
    CHECK_FALSE(normalise_hardware_query(raw).has_value());
}

// ── hw_search_tokens ─────────────────────────────────────────────────────────

TEST_CASE("hw_search_tokens: lowercases and splits on whitespace", "[hardware][model]") {
    const auto tokens = hw_search_tokens("Dell  OptiPlex\tWIN-1\n");
    REQUIRE(tokens.size() == 3);
    CHECK(tokens[0] == "dell");
    CHECK(tokens[1] == "optiplex");
    CHECK(tokens[2] == "win-1");
}

TEST_CASE("hw_search_tokens: empty or all-whitespace query yields no tokens", "[hardware][model]") {
    CHECK(hw_search_tokens("").empty());
    CHECK(hw_search_tokens("   \t\r\n").empty());
}

TEST_CASE("hw_search_tokens: capped at 8 tokens", "[hardware][model]") {
    const auto tokens = hw_search_tokens("a b c d e f g h i j");
    CHECK(tokens.size() == 8);
    CHECK(tokens[0] == "a");
    CHECK(tokens[7] == "h");
}

// ── hw_row_matches — os/status/tag facets ───────────────────────────────────

TEST_CASE("hw_row_matches: os facet", "[hardware][model]") {
    InventoryDeviceRow r = make_row("a1");
    r.os = "windows";
    CHECK(hw_row_matches(r, {}, "all", "all", ""));
    CHECK(hw_row_matches(r, {}, "windows", "all", ""));
    CHECK_FALSE(hw_row_matches(r, {}, "linux", "all", ""));
}

TEST_CASE("hw_row_matches: status facet — offline includes stale", "[hardware][model]") {
    InventoryDeviceRow online = make_row("a1");
    online.online = true;
    CHECK(hw_row_matches(online, {}, "all", "online", ""));
    CHECK_FALSE(hw_row_matches(online, {}, "all", "offline", ""));

    InventoryDeviceRow stale = make_row("a2");
    stale.online = false;
    stale.stale = true;
    CHECK(hw_row_matches(stale, {}, "all", "offline", ""));
    CHECK_FALSE(hw_row_matches(stale, {}, "all", "online", ""));
}

TEST_CASE("hw_row_matches: tag facet — bare key matches any value", "[hardware][model][tag]") {
    InventoryDeviceRow r = make_row("a1");
    r.tags = {{"env", "prod"}};
    CHECK(hw_row_matches(r, {}, "all", "all", "env"));
    CHECK_FALSE(hw_row_matches(r, {}, "all", "all", "region"));
}

TEST_CASE("hw_row_matches: tag facet — key=value matches only that exact value",
          "[hardware][model][tag]") {
    InventoryDeviceRow r = make_row("a1");
    r.tags = {{"env", "prod"}};
    CHECK(hw_row_matches(r, {}, "all", "all", "env=prod"));
    CHECK_FALSE(hw_row_matches(r, {}, "all", "all", "env=staging"));
}

// ── hw_row_matches — search haystack, the new round-3 fields ────────────────

TEST_CASE("hw_row_matches: search finds a row by its agent_version", "[hardware][model][search]") {
    InventoryDeviceRow r = make_row("a1");
    r.agent_version = "0.13.1+9077";
    CHECK(hw_row_matches(r, hw_search_tokens("0.13.1"), "all", "all", ""));
}

TEST_CASE("hw_row_matches: search finds a row by its arch", "[hardware][model][search]") {
    InventoryDeviceRow r = make_row("a1");
    r.arch = "arm64";
    CHECK(hw_row_matches(r, hw_search_tokens("arm64"), "all", "all", ""));
}

TEST_CASE("hw_row_matches: search finds a row by any of its ips", "[hardware][model][search]") {
    InventoryDeviceRow r = make_row("a1");
    r.ips = {"10.0.0.5", "192.168.1.20"};
    CHECK(hw_row_matches(r, hw_search_tokens("10.0.0.5"), "all", "all", ""));
    CHECK(hw_row_matches(r, hw_search_tokens("192.168.1.20"), "all", "all", ""));
}

TEST_CASE("hw_row_matches: search finds a row by a bare tag key", "[hardware][model][search]") {
    InventoryDeviceRow r = make_row("a1");
    r.tags = {{"team", "platform"}};
    CHECK(hw_row_matches(r, hw_search_tokens("team"), "all", "all", ""));
}

TEST_CASE("hw_row_matches: search finds a row by a key=value tag pair", "[hardware][model][search]") {
    InventoryDeviceRow r = make_row("a1");
    r.tags = {{"team", "platform"}};
    CHECK(hw_row_matches(r, hw_search_tokens("team=platform"), "all", "all", ""));
}

TEST_CASE("hw_row_matches: search finds a row by asset tag or chassis serial or board serial",
          "[hardware][model][search]") {
    InventoryDeviceRow r = make_row("a1");
    r.ci_chassis_asset_tag = "AT-0042-Z";
    r.ci_chassis_serial = "CHS9X77";
    r.ci_board_serial = "BRD-SN-5150";
    CHECK(hw_row_matches(r, hw_search_tokens("at-0042-z"), "all", "all", "")); // case folded
    CHECK(hw_row_matches(r, hw_search_tokens("CHS9X77"), "all", "all", ""));
    CHECK(hw_row_matches(r, hw_search_tokens("brd-sn-5150"), "all", "all", ""));
    CHECK(hw_row_matches(r, hw_search_tokens("chs9x"), "all", "all", "")); // substring, as the other fields
    CHECK_FALSE(hw_row_matches(r, hw_search_tokens("no-such-tag"), "all", "all", ""));
}

// The agent writes `-` for "no value": it must never be a search term, so `q=-` finds nothing on a
// row whose only hyphens are those placeholders. Kills: dropping the placeholder filter.
TEST_CASE("hw_row_matches: the - placeholder in a v2 identifier is never searchable",
          "[hardware][model][search]") {
    InventoryDeviceRow r = make_row("a1");
    r.ci_chassis_asset_tag = "-";
    r.ci_chassis_serial = "-";
    r.ci_board_serial = "-";
    CHECK_FALSE(hw_row_matches(r, hw_search_tokens("-"), "all", "all", ""));
    // the older sentinels stay filtered too
    r.ci_chassis_asset_tag = "unknown";
    r.ci_chassis_serial = "";
    CHECK_FALSE(hw_row_matches(r, hw_search_tokens("unknown"), "all", "all", ""));
    // and a real value next to a placeholder still matches
    r.ci_board_serial = "REAL-1";
    CHECK(hw_row_matches(r, hw_search_tokens("real-1"), "all", "all", ""));
}

// ── hardware_kpis ────────────────────────────────────────────────────────────

TEST_CASE("hardware_kpis: total/online/offline/stale/with_ci over the full roster",
          "[hardware][model]") {
    InventoryDeviceRow a = make_row("a1");
    a.online = true;
    a.ci_serial = "SN1";

    InventoryDeviceRow b = make_row("a2");
    b.online = false;
    b.stale = false;

    InventoryDeviceRow c = make_row("a3");
    c.online = false;
    c.stale = true;

    InventoryDeviceRow d = make_row("a4");
    d.online = true;
    d.ci_model = "unknown"; // blank sentinel — not real CI

    const std::vector<InventoryDeviceRow> roster{a, b, c, d};
    const auto k = hardware_kpis(roster);
    CHECK(k.total == 4);
    CHECK(k.online == 2);
    CHECK(k.offline == 2);
    CHECK(k.stale == 1);
    CHECK(k.with_ci == 1); // only 'a' has a non-blank serial/model
}

// ── build_hardware_list_page — new sort keys ────────────────────────────────

TEST_CASE("build_hardware_list_page: version sort is numeric semver-3, blanks sort LAST both directions",
          "[hardware][model][sort]") {
    InventoryDeviceRow a = make_row("a");
    a.agent_version = "0.13.1+9077"; // build metadata ignored -> {0,13,1}
    InventoryDeviceRow b = make_row("b");
    b.agent_version = "0.13.0";
    InventoryDeviceRow c = make_row("c");
    c.agent_version = ""; // never reported
    InventoryDeviceRow d = make_row("d");
    d.agent_version = "1.2.0";

    const std::vector<InventoryDeviceRow> roster{a, b, c, d};
    HardwareListQuery q;
    q.sort = "version";
    q.limit = 50;

    q.desc = false;
    const auto asc = build_hardware_list_page(roster, q);
    REQUIRE(asc.rows.size() == 4);
    CHECK(asc.rows[0].agent_id == "b"); // 0.13.0
    CHECK(asc.rows[1].agent_id == "a"); // 0.13.1+9077
    CHECK(asc.rows[2].agent_id == "d"); // 1.2.0
    CHECK(asc.rows[3].agent_id == "c"); // blank sorts LAST even ascending

    q.desc = true;
    const auto desc = build_hardware_list_page(roster, q);
    REQUIRE(desc.rows.size() == 4);
    CHECK(desc.rows[0].agent_id == "d"); // 1.2.0
    CHECK(desc.rows[1].agent_id == "a"); // 0.13.1+9077
    CHECK(desc.rows[2].agent_id == "b"); // 0.13.0
    CHECK(desc.rows[3].agent_id == "c"); // blank still sorts LAST descending
}

TEST_CASE("build_hardware_list_page: ip sort compares the first claimed IP, blanks sort LAST both directions",
          "[hardware][model][sort]") {
    InventoryDeviceRow a = make_row("a");
    a.ips = {"10.0.0.5"};
    InventoryDeviceRow b = make_row("b");
    b.ips = {"192.168.1.1"};
    InventoryDeviceRow c = make_row("c"); // no live claim -> empty ips

    const std::vector<InventoryDeviceRow> roster{a, b, c};
    HardwareListQuery q;
    q.sort = "ip";
    q.limit = 50;

    q.desc = false;
    const auto asc = build_hardware_list_page(roster, q);
    REQUIRE(asc.rows.size() == 3);
    CHECK(asc.rows[0].agent_id == "a"); // "10.0.0.5" < "192.168.1.1"
    CHECK(asc.rows[1].agent_id == "b");
    CHECK(asc.rows[2].agent_id == "c"); // no live claim sorts LAST even ascending

    q.desc = true;
    const auto desc = build_hardware_list_page(roster, q);
    REQUIRE(desc.rows.size() == 3);
    CHECK(desc.rows[0].agent_id == "b");
    CHECK(desc.rows[1].agent_id == "a");
    CHECK(desc.rows[2].agent_id == "c"); // still LAST descending
}

TEST_CASE("build_hardware_list_page: offset/limit paginates the sorted, filtered result",
          "[hardware][model]") {
    std::vector<InventoryDeviceRow> roster;
    for (char c = 'a'; c <= 'e'; ++c) {
        InventoryDeviceRow r = make_row(std::string(1, c));
        r.hostname = std::string(1, c);
        roster.push_back(r);
    }
    HardwareListQuery q;
    q.sort = "name";
    q.offset = 1;
    q.limit = 2;
    const auto page = build_hardware_list_page(roster, q);
    CHECK(page.total_matching == 5);
    REQUIRE(page.rows.size() == 2);
    CHECK(page.rows[0].hostname == "b");
    CHECK(page.rows[1].hostname == "c");
    CHECK(page.query.offset == 1);
}

TEST_CASE("build_hardware_list_page: kpis describe the whole fleet, not the current filter",
          "[hardware][model]") {
    InventoryDeviceRow a = make_row("a");
    a.hostname = "match-me";
    InventoryDeviceRow b = make_row("b");
    b.hostname = "other";

    const std::vector<InventoryDeviceRow> roster{a, b};
    HardwareListQuery q;
    q.q = "match-me"; // narrows total_matching, but not the KPI strip
    q.sort = "name";
    q.limit = 50;
    const auto page = build_hardware_list_page(roster, q);
    CHECK(page.total_matching == 1);
    CHECK(page.kpis.total == 2);
}

// ── hardware_row_json — JSON-null normalisation ─────────────────────────────

TEST_CASE("hardware_row_json: agent_version/ips/dex_score render null when blank/unscored",
          "[hardware][model][json]") {
    InventoryDeviceRow r = make_row("a1");
    r.agent_version.clear();
    r.ips.clear();
    r.dex_score = -1;

    const auto j = hardware_row_json(r);
    CHECK(j["agent_version"].is_null());
    CHECK(j["ips"].is_null());
    CHECK(j["dex_score"].is_null());
}

TEST_CASE("hardware_row_json: agent_version/ips/dex_score render real values when present",
          "[hardware][model][json]") {
    InventoryDeviceRow r = make_row("a1");
    r.agent_version = "0.14.0";
    r.ips = {"10.0.0.1"};
    r.dex_score = 87;

    const auto j = hardware_row_json(r);
    CHECK(j["agent_version"] == "0.14.0");
    CHECK(j["ips"] == nlohmann::json::array({"10.0.0.1"}));
    CHECK(j["dex_score"] == 87);
}

TEST_CASE("hardware_row_json: arch renders null only when BOTH the self-report and ci_arch are blank",
          "[hardware][model][json]") {
    InventoryDeviceRow r = make_row("a1");
    r.arch.clear();
    r.ci_arch.clear();
    CHECK(hardware_row_json(r)["arch"].is_null());
}

TEST_CASE("hardware_row_json: arch falls back to ci_arch when the self-report is empty",
          "[hardware][model][json]") {
    InventoryDeviceRow r = make_row("a1");
    r.arch.clear();
    r.ci_arch = "aarch64";
    CHECK(hardware_row_json(r)["arch"] == "aarch64");
}

TEST_CASE("hardware_row_json: arch prefers the self-report over ci_arch when both are present",
          "[hardware][model][json]") {
    InventoryDeviceRow r = make_row("a1");
    r.arch = "x86_64";
    r.ci_arch = "aarch64"; // stale device-CI sync — self-report wins
    CHECK(hardware_row_json(r)["arch"] == "x86_64");
}

TEST_CASE("hardware_row_json: blank/unknown ci_* sentinels render null, ci_present false",
          "[hardware][model][json]") {
    InventoryDeviceRow r = make_row("a1");
    r.ci_serial = "unknown";
    r.ci_model.clear();
    const auto j = hardware_row_json(r);
    CHECK(j["serial"].is_null());
    CHECK(j["model"].is_null());
    CHECK(j["ci_present"] == false);
}

// ── hardware_list_json ───────────────────────────────────────────────────────

TEST_CASE("hardware_list_json: ci_degraded suppresses with_ci to null, never a stale count",
          "[hardware][model][json]") {
    const std::vector<InventoryDeviceRow> roster{make_row("a1")};
    HardwareListQuery q;
    q.sort = "name";
    q.limit = 50;
    const auto page = build_hardware_list_page(roster, q);

    const auto j = hardware_list_json(page, /*ci_degraded=*/true, /*devices_omitted=*/3,
                                      /*tags_degraded=*/true);
    CHECK(j["ci_degraded"] == true);
    CHECK(j["tags_degraded"] == true);
    CHECK(j["devices_omitted"] == 3);
    CHECK(j["kpis"]["with_ci"].is_null());
    CHECK(j["count"] == 1);
    CHECK(j["total_matching"] == 1);
}

TEST_CASE("hardware_list_json: with_ci renders the real count when not degraded",
          "[hardware][model][json]") {
    InventoryDeviceRow a = make_row("a1");
    a.ci_serial = "SN1";
    const std::vector<InventoryDeviceRow> roster{a};
    HardwareListQuery q;
    q.sort = "name";
    q.limit = 50;
    const auto page = build_hardware_list_page(roster, q);

    const auto j = hardware_list_json(page, /*ci_degraded=*/false, /*devices_omitted=*/0,
                                      /*tags_degraded=*/false);
    CHECK(j["kpis"]["with_ci"] == 1);
    CHECK(j["ci_degraded"] == false);
    CHECK(j["tags_degraded"] == false);
    CHECK(j["query"]["dir"] == "asc");
}

// ── agent_supports_sync_now ──────────────────────────────────────────────────

TEST_CASE("agent_supports_sync_now: semver-3 floor at 0.13.1, exact boundary", "[hardware][model]") {
    CHECK_FALSE(agent_supports_sync_now("0.13.0"));    // release line, below the floor
    CHECK(agent_supports_sync_now("0.13.1"));          // exactly the floor
    CHECK(agent_supports_sync_now("0.13.1+9077"));     // build-metadata suffix ignored
    CHECK(agent_supports_sync_now("0.14.0"));          // above the floor
    CHECK(agent_supports_sync_now("1.0.0"));           // well above
    CHECK_FALSE(agent_supports_sync_now(""));          // empty -> fail closed
    CHECK_FALSE(agent_supports_sync_now("garbage"));   // non-numeric -> fail closed
    CHECK_FALSE(agent_supports_sync_now("0.13.1-rc1")); // pre-release-tagged -> fail closed
}

// ── hardware_ci_json ─────────────────────────────────────────────────────────

TEST_CASE("hardware_ci_json: absent identity renders null identity fields, online false",
          "[hardware][model][json]") {
    HardwareCiDetail d;
    d.identity = std::nullopt;
    const auto j = hardware_ci_json(d, 0);
    CHECK(j["agent_id"].is_null());
    CHECK(j["hostname"].is_null());
    CHECK(j["os"].is_null());
    CHECK(j["online"] == false);
    CHECK(j["last_seen"].is_null());
    CHECK(j["identity_state"] == "absent");
}

// A set identity is a found identity: identity_degraded only describes an unanswered read.
TEST_CASE("hardware_ci_json: identity outranks identity_degraded in identity_state",
          "[hardware][model][json]") {
    HardwareCiDetail d;
    InventoryDeviceRow row;
    row.agent_id = "a1";
    d.identity = row;
    d.identity_degraded = true;
    CHECK(hardware_ci_json(d, 0)["identity_state"] == "found");
}

TEST_CASE("hardware_ci_json: ci_state discriminates degraded/absent/found", "[hardware][model][json]") {
    HardwareCiDetail degraded_detail;
    degraded_detail.ci = std::unexpected(CiReadError::kDegraded);
    const auto dj = hardware_ci_json(degraded_detail, 0);
    CHECK(dj["ci_state"] == "degraded");
    CHECK(dj["ci"].is_null());

    HardwareCiDetail absent_detail;
    absent_detail.ci = std::optional<DeviceCiRecord>{}; // read succeeded, no record yet
    const auto aj = hardware_ci_json(absent_detail, 0);
    CHECK(aj["ci_state"] == "absent");
    CHECK(aj["ci"].is_null());

    HardwareCiDetail found_detail;
    DeviceCiRecord rec;
    rec.manufacturer = "Dell Inc.";
    rec.serial = "SN1";
    found_detail.ci = std::optional<DeviceCiRecord>(rec);
    const auto fj = hardware_ci_json(found_detail, 0);
    CHECK(fj["ci_state"] == "found");
    CHECK(fj["ci"]["manufacturer"] == "Dell Inc.");
    CHECK(fj["ci"]["serial"] == "SN1");
}

TEST_CASE("hardware_ci_json: software/tags nullopt (degraded/unwired) render JSON null, not empty",
          "[hardware][model][json]") {
    HardwareCiDetail d;
    d.software = std::nullopt;
    d.tags = std::nullopt;
    const auto j = hardware_ci_json(d, 0);
    CHECK(j["software"].is_null());
    CHECK(j["tags"].is_null());
}

TEST_CASE("hardware_ci_json: software/tags present-but-empty render JSON empty arrays, not null",
          "[hardware][model][json]") {
    HardwareCiDetail d;
    d.software = std::vector<SoftwareEntry>{};
    d.tags = std::vector<DeviceTag>{};
    const auto j = hardware_ci_json(d, 0);
    REQUIRE(j["software"].is_array());
    CHECK(j["software"].empty());
    REQUIRE(j["tags"].is_array());
    CHECK(j["tags"].empty());
}

TEST_CASE("hardware_ci_json: sync_supported mirrors agent_supports_sync_now over agent_version",
          "[hardware][model][json]") {
    HardwareCiDetail d;
    d.agent_version = std::nullopt;
    CHECK(hardware_ci_json(d, 0)["sync_supported"] == false);
    CHECK(hardware_ci_json(d, 0)["agent_version"].is_null());

    d.agent_version = "0.13.0";
    CHECK(hardware_ci_json(d, 0)["sync_supported"] == false);

    d.agent_version = "0.13.1";
    CHECK(hardware_ci_json(d, 0)["sync_supported"] == true);
    CHECK(hardware_ci_json(d, 0)["agent_version"] == "0.13.1");
}

TEST_CASE("hardware_ci_json: software_last_seen distinguishes nullopt (degraded) from 0 (never synced)",
          "[hardware][model][json]") {
    HardwareCiDetail d;
    d.software_last_seen = std::nullopt;
    CHECK(hardware_ci_json(d, 0)["software_last_seen"].is_null());

    d.software_last_seen = 0;
    CHECK(hardware_ci_json(d, 0)["software_last_seen"] == 0);

    d.software_last_seen = 1234567;
    CHECK(hardware_ci_json(d, 0)["software_last_seen"] == 1234567);
}

// ── hardware_ci_json: the v2 scalars and sections (H.7) ──────────────────────

namespace {

DeviceCiSection make_section(std::string kind, std::string level, std::string reason = "",
                             std::vector<std::vector<std::string>> rows = {}) {
    DeviceCiSection s;
    s.kind = std::move(kind);
    s.level = std::move(level);
    s.reason = std::move(reason);
    s.rows = std::move(rows);
    return s;
}

HardwareCiDetail v2_detail(std::vector<DeviceCiSection> sections) {
    HardwareCiDetail d;
    DeviceCiRecord rec;
    rec.blob_version = 2;
    rec.chassis_type = "Laptop";
    rec.chassis_serial = "CHS1";
    rec.chassis_asset_tag = "AT1";
    rec.chassis_source = "smbios";
    rec.board_vendor = "Acme";
    rec.board_product = "B450";
    rec.board_serial = "BSN1";
    rec.board_source = "smbios";
    rec.machine_id_hash = "abcdef01";
    rec.machine_id_algorithm = "sha256";
    rec.machine_id_source = "etc_machine_id";
    d.ci = std::optional<DeviceCiRecord>(rec);
    d.ci_sections = std::move(sections);
    return d;
}

const nlohmann::json& section_of(const nlohmann::json& j, std::string_view kind) {
    static const nlohmann::json none;
    for (const auto& s : j["ci"]["sections"])
        if (s["kind"] == std::string(kind)) // not string_view: MSVC reads json == string_view as ambiguous (C2666)
            return s;
    return none;
}

} // namespace

TEST_CASE("hardware_ci_json: the v2 identity scalars are served and the - placeholder is null",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({});
    const auto j = hardware_ci_json(d, 0);
    CHECK(j["ci"]["chassis_type"] == "Laptop");
    CHECK(j["ci"]["chassis_serial"] == "CHS1");
    CHECK(j["ci"]["chassis_asset_tag"] == "AT1");
    CHECK(j["ci"]["chassis_source"] == "smbios");
    CHECK(j["ci"]["board_vendor"] == "Acme");
    CHECK(j["ci"]["board_product"] == "B450");
    CHECK(j["ci"]["board_serial"] == "BSN1");
    CHECK(j["ci"]["board_source"] == "smbios");
    CHECK(j["ci"]["machine_id_hash"] == "abcdef01");
    CHECK(j["ci"]["machine_id_algorithm"] == "sha256");
    CHECK(j["ci"]["machine_id_source"] == "etc_machine_id");

    // A v1 record (every v2 scalar blank), an agent that sent `-`, and an `unknown` all read null.
    HardwareCiDetail v1;
    DeviceCiRecord rec;
    rec.chassis_asset_tag = "-";
    rec.chassis_serial = "unknown";
    rec.machine_id_hash = "-";
    v1.ci = std::optional<DeviceCiRecord>(rec);
    const auto vj = hardware_ci_json(v1, 0);
    for (const char* k : {"chassis_type", "chassis_serial", "chassis_asset_tag", "chassis_source", "board_vendor",
                          "board_product", "board_serial", "board_source", "machine_id_hash",
                          "machine_id_algorithm", "machine_id_source"}) {
        INFO(k);
        REQUIRE(vj["ci"].contains(k));
        CHECK(vj["ci"][k].is_null());
    }
}

TEST_CASE("hardware_ci_json: a clean ok list section serves its rows keyed by the declared columns",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({make_section("cpu", "ok", "", {{"0", "Xeon", "8", "16", "2400", "CPU0", "-"}}),
                        make_section("disk", "ok", "", {{"0", "NVMe", "512", "ssd", "nvme"}})});
    const auto j = hardware_ci_json(d, 0);
    CHECK(j["sections_state"] == "found");
    const auto& cpu = section_of(j, "cpu");
    REQUIRE(cpu.is_object());
    CHECK(cpu["status"] == "ok");
    CHECK(cpu["complete"] == true);
    CHECK(cpu["reason"].is_null());
    CHECK(cpu["source"].is_null());
    REQUIRE(cpu["rows"].size() == 1);
    CHECK(cpu["rows"][0]["idx"] == "0");
    CHECK(cpu["rows"][0]["model"] == "Xeon");
    CHECK(cpu["rows"][0]["clock_mhz"] == "2400");
    CHECK(cpu["rows"][0]["socket_designation"] == "CPU0");
    CHECK(cpu["rows"][0]["stepping"].is_null()); // the `-` placeholder
    CHECK(cpu["rows"][0].size() == 7);
    CHECK(section_of(j, "disk")["rows"][0]["interface"] == "nvme");
}

// Kills: serving a constrained section as complete, or dropping its rows.
TEST_CASE("hardware_ci_json: a constrained section is incomplete and keeps its rows",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({make_section("dimm", "constrained", "agent:partial;server_cap:64",
                                     {{"A1", "8192", "DDR4", "3200", "Acme", "P1", "S1"}})});
    const auto j = hardware_ci_json(d, 0);
    const auto& dimm = section_of(j, "dimm");
    CHECK(dimm["status"] == "constrained");
    CHECK(dimm["complete"] == false);
    CHECK(dimm["reason"] == "agent:partial;server_cap:64");
    REQUIRE(dimm["rows"].size() == 1);
    CHECK(dimm["rows"][0]["slot"] == "A1");
    CHECK(dimm["rows"][0]["serial"] == "S1");
}

// Kills: rendering rows for a failed section.
TEST_CASE("hardware_ci_json: unavailable and permission_denied sections carry the reason and no rows",
          "[hardware][model][json][sections]") {
    // Rows are stored here on purpose: the serialiser must withhold them regardless of what the
    // store holds.
    auto d = v2_detail({make_section("swap", "unavailable", "linux:planned", {{"/swap", "1024", "file"}}),
                        make_section("volume", "permission_denied", "agent:denied", {{"C:", "C:\\", "d", "ntfs", "1", ""}}),
                        make_section("topology", "mystery", "", {{"lvm", "vg0", "u", "m", ""}})});
    const auto j = hardware_ci_json(d, 0);
    const auto& swap = section_of(j, "swap");
    CHECK(swap["status"] == "unavailable");
    CHECK(swap["reason"] == "linux:planned");
    CHECK(swap["complete"] == false);
    CHECK(swap["rows"].is_array());
    CHECK(swap["rows"].empty());
    const auto& vol = section_of(j, "volume");
    CHECK(vol["status"] == "permission_denied");
    CHECK(vol["reason"] == "agent:denied");
    CHECK(vol["complete"] == false);
    CHECK(vol["rows"].empty());
    // a level this server does not know is neither complete nor row-bearing
    const auto& topo = section_of(j, "topology");
    CHECK(topo["status"] == "mystery");
    CHECK(topo["complete"] == false);
    CHECK(topo["rows"].empty());
}

TEST_CASE("hardware_ci_json: status-only sections carry their source value and never rows",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({make_section("chassis", "ok"), make_section("baseboard", "ok", "-"),
                        make_section("machine_id", "constrained", "server:machine_id_shape")});
    const auto j = hardware_ci_json(d, 0);
    CHECK(section_of(j, "chassis")["source"] == "smbios");
    CHECK(section_of(j, "baseboard")["source"] == "smbios");
    CHECK(section_of(j, "baseboard")["reason"].is_null()); // `-` is "no reason"
    CHECK(section_of(j, "machine_id")["source"] == "etc_machine_id");
    CHECK(section_of(j, "machine_id")["complete"] == false);
    for (const char* k : {"chassis", "baseboard", "machine_id"})
        CHECK(section_of(j, k)["rows"].empty());
}

TEST_CASE("hardware_ci_json: sections are served in registry order whatever order they arrive in "
          "and an unregistered kind is never surfaced",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({make_section("topology", "ok"), make_section("bogus", "ok"),
                        make_section("cpu", "ok"), make_section("machine_id", "ok"),
                        make_section("disk", "ok")});
    const auto j = hardware_ci_json(d, 0);
    std::vector<std::string> kinds;
    for (const auto& s : j["ci"]["sections"])
        kinds.push_back(s["kind"].get<std::string>());
    CHECK(kinds == std::vector<std::string>{"machine_id", "cpu", "disk", "topology"});
}

// "Not reported" is not "has none": a v1 record reads absent with an empty list, a failed read
// reads degraded with a null list, and the three states never collapse.
TEST_CASE("hardware_ci_json: sections_state tells found from absent from degraded",
          "[hardware][model][json][sections]") {
    // v1 / nothing stored
    const auto absent = hardware_ci_json(v2_detail({}), 0);
    CHECK(absent["sections_state"] == "absent");
    REQUIRE(absent["ci"]["sections"].is_array());
    CHECK(absent["ci"]["sections"].empty());

    // the sections read failed
    auto failed = v2_detail({});
    failed.ci_sections = std::unexpected(CiReadError::kDegraded);
    CHECK(hardware_ci_sections_unreadable(failed));
    const auto fj = hardware_ci_json(failed, 0);
    CHECK(fj["sections_state"] == "degraded");
    CHECK(fj["ci"]["sections"].is_null());

    // the struct default (ci degraded, sections never read) reads degraded, not absent, and is not
    // a sections-read failure (the record route keeps its per-part 200 for a degraded ci)
    const HardwareCiDetail untouched;
    CHECK_FALSE(hardware_ci_sections_unreadable(untouched));
    CHECK(hardware_ci_json(untouched, 0)["sections_state"] == "degraded");

    // ci readable but no record yet, sections READ (an answered absence): nothing stored
    HardwareCiDetail none;
    none.ci = std::optional<DeviceCiRecord>{};
    none.ci_sections = std::vector<DeviceCiSection>{};
    CHECK(hardware_ci_json(none, 0)["sections_state"] == "absent");

    // The same detail with the sections NOT read (#7162): it was a bare default before and read
    // "absent"; a NotRead state never claims the sections were read, whatever ci says.
    HardwareCiDetail none_not_read;
    none_not_read.ci = std::optional<DeviceCiRecord>{};
    CHECK(hardware_ci_json(none_not_read, 0)["sections_state"] == "degraded");
}

// #7162: the not-read state is its own value and renders degraded/null, never "absent" and never a
// new literal (the published enum is found|absent|degraded). `v2_detail({})` is a RecordOnly
// detail once its sections are reset: a found ci whose sections were never read.
TEST_CASE(
    "hardware_ci_json: a RecordOnly detail with a found ci renders degraded with null sections",
    "[hardware][model][json][sections]") {
    auto d = v2_detail({});
    d.ci_sections.reset(); // what CiRead::RecordOnly leaves
    REQUIRE_FALSE(d.ci_sections.has_value());
    CHECK_FALSE(hardware_ci_sections_unreadable(d)); // not read is not a failed read
    const auto j = hardware_ci_json(d, 0);
    CHECK(j["ci_state"] == "found");
    CHECK(j["sections_state"] == "degraded");
    REQUIRE(j["ci"].contains("sections"));
    CHECK(j["ci"]["sections"].is_null());
    const auto state = j["sections_state"].get<std::string>();
    CHECK((state == "found" || state == "absent" || state == "degraded"));
    // The struct default is NOT READ, not "read and none".
    CHECK_FALSE(HardwareCiDetail{}.ci_sections.has_value());
}

// ── #5531: the pure store-to-bit mappings server.cpp's closures delegate to ───

// Kills: apply_roster_read treating a failed read as healthy (returns true / leaves a degraded
// bit unset), and a healthy read being flagged degraded.
TEST_CASE("apply_roster_read: failed read sets every degraded bit; healthy read touches nothing",
          "[hardware][model]") {
    InventoryDevicesResult failed;
    CHECK_FALSE(apply_roster_read(failed, OfflineRosterRead{std::unexpected(PresenceReadError::DbError)}));
    CHECK(failed.roster_degraded);
    CHECK(failed.ci_degraded);
    CHECK(failed.tags_degraded);

    InventoryDevicesResult healthy;
    CHECK(apply_roster_read(healthy, OfflineRosterRead{std::vector<OfflineEndpoint>{}}));
    CHECK_FALSE(healthy.roster_degraded);
    CHECK_FALSE(healthy.ci_degraded);
    CHECK_FALSE(healthy.tags_degraded);
}

// Kills: a failed key read collapsed to "no keys" (blank Tags column reads as authoritative), a
// failed values read ignored, the reader being called after a failed key read, a healthy read
// (incl. empty keys / a device with no tags) being flagged degraded, and tags not being attached.
TEST_CASE("apply_tag_read: every failed read degrades and every healthy read populates without degrading",
          "[hardware][model]") {
    using Keys = std::expected<std::vector<std::string>, TagReadError>;
    struct Row {
        const char* name;
        Keys keys;
        TagValuesRead values;
        bool reader_called;
        bool degraded;
        std::vector<std::pair<std::string, std::string>> a1_tags;
        std::vector<std::string> expected_keys; // what the reader must be handed
    };
    const TagValuesRead no_values{TagValuesRead::value_type{}};
    const std::array<Row, 5> table{{
        {"key read fails", std::unexpected(TagReadError::kDegraded), no_values, false, true, {}, {}},
        {"keys ok, values fail", Keys{std::vector<std::string>{"env"}},
         std::unexpected(TagReadError::kDegraded), true, true, {}, {"env"}},
        {"keys ok, values ok",
         Keys{std::vector<std::string>{"env"}},
         TagValuesRead{TagValuesRead::value_type{{"a1", {{"env", "prod"}}}}}, true, false, {{"env", "prod"}},
         {"env"}},
        {"keys ok but empty", Keys{std::vector<std::string>{}}, no_values, true, false, {}, {}},
        {"keys ok, device has no tags", Keys{std::vector<std::string>{"env"}},
         TagValuesRead{TagValuesRead::value_type{{"a2", {{"env", "dev"}}}}}, true, false, {},
         {"env"}},
    }};
    for (const auto& row : table) {
        CAPTURE(row.name);
        InventoryDevicesResult result;
        result.rows.resize(2);
        result.rows[0].agent_id = "a1";
        result.rows[1].agent_id = "a2";
        bool called = false;
        std::vector<std::string> seen;
        apply_tag_read(result, row.keys, [&](const std::vector<std::string>& keys) {
            called = true;
            seen = keys;
            return row.values;
        });
        CHECK(called == row.reader_called);
        if (row.reader_called)
            CHECK(seen == row.expected_keys); // the keys read are the ones handed to the values read
        CHECK(result.tags_degraded == row.degraded);
        CHECK(result.rows[0].tags == row.a1_tags);
    }
}

// Kills: offline_identity_row swallowing the read error into an empty optional ("not found"); and
// the stale-boundary mutant (`>=` for `>` on kHardwareStaleAfterMs).
TEST_CASE("offline_identity_row: error propagates; hit is offline; miss is nullopt",
          "[hardware][model]") {
    const auto err = offline_identity_row(
        OfflineRosterRead{std::unexpected(PresenceReadError::StoreUnavailable)}, "a1", 10 * kDayMs, fake_age);
    REQUIRE_FALSE(err.has_value());
    CHECK(err.error() == PresenceReadError::StoreUnavailable);

    const OfflineRosterRead roster{std::vector<OfflineEndpoint>{make_offline_ep("a1", 9 * kDayMs)}};
    const auto hit = offline_identity_row(roster, "a1", 10 * kDayMs, fake_age);
    REQUIRE(hit.has_value());
    REQUIRE(hit->has_value());
    CHECK((*hit)->hostname == "host-a1");
    CHECK_FALSE((*hit)->online);
    CHECK_FALSE((*hit)->stale); // 1 day old
    CHECK((*hit)->last_seen == "aged");

    const auto old = offline_identity_row(
        OfflineRosterRead{std::vector<OfflineEndpoint>{make_offline_ep("a1", 0)}}, "a1", 10 * kDayMs, fake_age);
    REQUIRE(old.has_value());
    CHECK((*old)->stale);

    // kHardwareStaleAfterMs boundary: the probes are derived from the constant, so its value is
    // pinned separately; at the edge is fresh, one millisecond over is stale.
    CHECK(kHardwareStaleAfterMs == 2 * kDayMs);
    const auto at_edge = offline_identity_row(
        OfflineRosterRead{
            std::vector<OfflineEndpoint>{make_offline_ep("a1", 10 * kDayMs - kHardwareStaleAfterMs)}},
        "a1", 10 * kDayMs, fake_age);
    REQUIRE(at_edge.has_value());
    CHECK_FALSE((*at_edge)->stale);
    const auto past_edge = offline_identity_row(
        OfflineRosterRead{
            std::vector<OfflineEndpoint>{make_offline_ep("a1", 10 * kDayMs - kHardwareStaleAfterMs - 1)}},
        "a1", 10 * kDayMs, fake_age);
    REQUIRE(past_edge.has_value());
    CHECK((*past_edge)->stale);

    const auto miss = offline_identity_row(roster, "zzz", 10 * kDayMs, fake_age);
    REQUIRE(miss.has_value());
    CHECK_FALSE(miss->has_value());
}

// Kills: apply_identity_read never setting identity_degraded, or setting it on a clean miss.
TEST_CASE("apply_identity_read: error degrades; nullopt is absent; row is identity", "[hardware][model]") {
    HardwareCiDetail d;
    apply_identity_read(d, std::unexpected(PresenceReadError::DbError));
    CHECK(d.identity_degraded);
    CHECK_FALSE(d.identity.has_value());

    HardwareCiDetail absent;
    apply_identity_read(absent, std::optional<InventoryDeviceRow>{});
    CHECK_FALSE(absent.identity_degraded);
    CHECK_FALSE(absent.identity.has_value());

    HardwareCiDetail found;
    InventoryDeviceRow row;
    row.agent_id = "a1";
    apply_identity_read(found, std::optional<InventoryDeviceRow>{row});
    CHECK_FALSE(found.identity_degraded);
    REQUIRE(found.identity.has_value());
    CHECK(found.identity->agent_id == "a1");
}

// ── hardware_query_from_args (the MCP argument parser, strict-typed per #4644) ──

TEST_CASE("hardware_query_from_args: an empty object yields the REST defaults", "[hardware][model][args]") {
    const auto q = hardware_query_from_args(nlohmann::json::object());
    REQUIRE(q.has_value());
    CHECK(q->q.empty());
    CHECK(q->os == "all");
    CHECK(q->status == "all");
    CHECK(q->sort == "name");
    CHECK_FALSE(q->desc);
    CHECK(q->offset == 0);
    CHECK(q->limit == 50);
    CHECK(q->tag.empty());
}

TEST_CASE("hardware_query_from_args: every documented argument is carried through",
          "[hardware][model][args]") {
    const auto q = hardware_query_from_args(nlohmann::json{
        {"q", "lap top"}, {"os", "windows"}, {"status", "offline"}, {"sort", "ram"},
        {"dir", "desc"}, {"tag", "site=emea"}, {"offset", 10}, {"limit", 200}});
    REQUIRE(q.has_value());
    CHECK(q->q == "lap top");
    CHECK(q->os == "windows");
    CHECK(q->status == "offline");
    CHECK(q->sort == "ram");
    CHECK(q->desc);
    CHECK(q->tag == "site=emea");
    CHECK(q->offset == 10);
    CHECK(q->limit == 200);
}

TEST_CASE("hardware_query_from_args: boundary limits are accepted, outside them refused",
          "[hardware][model][args]") {
    CHECK(hardware_query_from_args(nlohmann::json{{"limit", 1}}).has_value());
    CHECK(hardware_query_from_args(nlohmann::json{{"limit", 200}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", 0}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", 201}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", -1}}).has_value());
    CHECK(hardware_query_from_args(nlohmann::json{{"offset", 0}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"offset", -1}}).has_value());
    // Beyond int64: still an integer, still refused, never wrapped into a small value.
    CHECK(hardware_query_from_args(nlohmann::json{{"offset", 9223372036854775807ULL}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"offset", 18446744073709551615ULL}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", 18446744073709551615ULL}}).has_value());
}

TEST_CASE("hardware_query_from_args: a mistyped argument is refused, never coerced",
          "[hardware][model][args]") {
    // The REST query string coerces "50"; a typed JSON argument must not.
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", "50"}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"offset", "0"}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", 50.0}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", true}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", nullptr}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"q", 5}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"tag", nlohmann::json::array()}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"os", 1}}).has_value());
}

TEST_CASE("hardware_query_from_args: enums are exact documented tokens", "[hardware][model][args]") {
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"os", "bsd"}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"os", "Windows"}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"os", ""}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"status", "stale"}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"sort", "dex"}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"sort", "dex_score"}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"dir", "up"}}).has_value());
    for (const char* os : {"all", "windows", "linux", "macos"})
        CHECK(hardware_query_from_args(nlohmann::json{{"os", os}}).has_value());
    for (const char* st : {"all", "online", "offline"})
        CHECK(hardware_query_from_args(nlohmann::json{{"status", st}}).has_value());
    for (const char* sort : {"name", "os", "status", "last_seen", "manufacturer", "model", "serial",
                             "cpu", "ram", "os_version", "version", "ip"}) {
        CAPTURE(sort);
        const auto q = hardware_query_from_args(nlohmann::json{{"sort", sort}});
        REQUIRE(q.has_value());
        // The parser's tokens and the model's whitelist must stay in step.
        CHECK(parse_hw_sort_key(q->sort).has_value());
    }
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"dir", "asc"}})->desc);
    CHECK(hardware_query_from_args(nlohmann::json{{"dir", "desc"}})->desc);
}

TEST_CASE("hardware_query_from_args: text arguments are capped at 256 bytes", "[hardware][model][args]") {
    CHECK(hardware_query_from_args(nlohmann::json{{"q", std::string(256, 'a')}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"q", std::string(257, 'a')}}).has_value());
    CHECK(hardware_query_from_args(nlohmann::json{{"tag", std::string(256, 'a')}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"tag", std::string(257, 'a')}}).has_value());
}

TEST_CASE("hardware_query_from_args: unknown keys are ignored, a non-object is refused",
          "[hardware][model][args]") {
    CHECK(hardware_query_from_args(nlohmann::json{{"bogus", 1}, {"limit", 5}}).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json::array()).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json("x")).has_value());
    CHECK_FALSE(hardware_query_from_args(nlohmann::json(nullptr)).has_value());
}

TEST_CASE("hardware_query_from_args: the reason names the argument and the query still normalises",
          "[hardware][model][args]") {
    std::string why;
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"limit", "50"}}, &why).has_value());
    CHECK(why.find("limit") != std::string::npos);
    why.clear();
    CHECK_FALSE(hardware_query_from_args(nlohmann::json{{"os", "bsd"}}, &why).has_value());
    CHECK(why.find("os") != std::string::npos);

    // The parser output is RAW: tag-key validation stays in normalise_hardware_query.
    const auto q = hardware_query_from_args(nlohmann::json{{"tag", "bad key!=x"}});
    REQUIRE(q.has_value());
    CHECK_FALSE(normalise_hardware_query(*q).has_value());
}

// ── scoped_roster / id_is_audit_safe (lifted out of hardware_routes.cpp) ──

TEST_CASE("scoped_roster: TOP keeps every row, a set keeps members, empty drops all",
          "[hardware][model][scope]") {
    InventoryDevicesResult all;
    all.rows = {make_row("a"), make_row("b"), make_row("c")};

    auto [top_rows, top_dropped] = scoped_roster(all, authz::VisibleSet{});
    CHECK(top_rows.size() == 3);
    CHECK(top_dropped == 0);

    auto [some_rows, some_dropped] =
        scoped_roster(all, authz::VisibleSet{std::unordered_set<std::string>{"a", "c"}});
    REQUIRE(some_rows.size() == 2);
    CHECK(some_rows[0].agent_id == "a");
    CHECK(some_rows[1].agent_id == "c");
    CHECK(some_dropped == 1);

    auto [none_rows, none_dropped] = scoped_roster(all, authz::deny_all());
    CHECK(none_rows.empty());
    CHECK(none_dropped == 3);
}

TEST_CASE("id_is_audit_safe: bounded length and no control bytes", "[hardware][model][scope]") {
    CHECK(id_is_audit_safe("agent-1"));
    CHECK(id_is_audit_safe(std::string(256, 'a')));
    CHECK_FALSE(id_is_audit_safe(std::string(257, 'a')));
    CHECK_FALSE(id_is_audit_safe("agent\n1"));
    CHECK_FALSE(id_is_audit_safe("agent\r1"));
    CHECK_FALSE(id_is_audit_safe(std::string("a\0b", 3)));
    CHECK_FALSE(id_is_audit_safe(std::string("\x1f", 1)));
    CHECK(id_is_audit_safe("agent 1")); // 0x20 itself is not a control byte
}

// ── classify_hardware_ci_read (the single-record decision, shared by every transport) ──

TEST_CASE("classify_hardware_ci_read: found, not found, roster unreadable", "[hardware][model][classify]") {
    HardwareCiDetail empty;
    empty.ci = std::optional<DeviceCiRecord>{}; // the CI read answered: no record

    SECTION("nothing known and nothing failed is NotFound") {
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::NotFound);
    }
    SECTION("empty software and tag lists are still nothing") {
        empty.software = std::vector<SoftwareEntry>{};
        empty.tags = std::vector<DeviceTag>{};
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::NotFound);
    }
    SECTION("an unanswered software or tag read counts as empty, as REST always did") {
        empty.software = std::nullopt;
        empty.tags = std::nullopt;
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::NotFound);
    }
    SECTION("a failed identity fallback with nothing else known is RosterUnreadable, never a 404") {
        empty.identity_degraded = true;
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::RosterUnreadable);
    }
    SECTION("an identity row is Found, even when the fallback also reports degraded") {
        empty.identity = make_row("a1");
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::Found);
        empty.identity_degraded = true;
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::Found);
    }
    SECTION("a CI record alone is Found") {
        DeviceCiRecord rec;
        rec.agent_id = "a1";
        empty.ci = std::optional<DeviceCiRecord>{rec};
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::Found);
    }
    SECTION("a degraded CI read is Found (the body's ci_state says degraded), never NotFound") {
        HardwareCiDetail d; // default ci = unexpected(kDegraded)
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::Found);
        d.identity_degraded = true;
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::Found);
    }
    SECTION("a non-empty software or tag list is Found") {
        empty.software = std::vector<SoftwareEntry>(1);
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::Found);
        empty.software = std::nullopt;
        empty.tags = std::vector<DeviceTag>(1);
        CHECK(classify_hardware_ci_read(empty) == HardwareCiRead::Found);
    }
}

// #7162: the sections-unreadable decision is the classifier's fourth arm, in one fixed order.
TEST_CASE("classify_hardware_ci_read: a failed sections read is SectionsUnreadable, after NotFound",
          "[hardware][model][classify][sections]") {
    DeviceCiRecord rec;
    rec.agent_id = "a1";
    HardwareCiDetail d;
    d.ci = std::optional<DeviceCiRecord>{rec};

    SECTION("a record whose sections read failed is SectionsUnreadable") {
        d.ci_sections = std::unexpected(CiReadError::kDegraded);
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::SectionsUnreadable);
        CHECK(hardware_ci_sections_unreadable(d));
    }
    SECTION("sections read, none stored, is Found") {
        d.ci_sections = std::vector<DeviceCiSection>{};
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::Found);
    }
    SECTION("sections NOT READ is Found, never unreadable") {
        d.ci_sections.reset();
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::Found);
    }
    SECTION("precedence: NotFound beats SectionsUnreadable (artificial: nothing else known)") {
        d.ci = std::optional<DeviceCiRecord>{};
        d.ci_sections = std::unexpected(CiReadError::kDegraded);
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::NotFound);
    }
    SECTION("precedence: RosterUnreadable beats SectionsUnreadable") {
        d.ci = std::optional<DeviceCiRecord>{};
        d.identity_degraded = true;
        d.ci_sections = std::unexpected(CiReadError::kDegraded);
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::RosterUnreadable);
    }
    SECTION("an identity row with a failed sections read is still SectionsUnreadable") {
        d.identity = make_row("a1");
        d.ci_sections = std::unexpected(CiReadError::kDegraded);
        CHECK(classify_hardware_ci_read(d) == HardwareCiRead::SectionsUnreadable);
    }
}

// ── hardware_ci_json: section edge cases (H.7 Gate 3) ────────────────────────────────────────

// A row shorter than the registry's column count reads the missing trailing cells as null; a longer
// one has its extra cells ignored. Neither throws, and the row keeps exactly the declared keys.
TEST_CASE("hardware_ci_json: a section row shorter or longer than the declared columns is bounded",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({make_section("cpu", "ok", "",
                                     {{"0", "Xeon", "8"},
                                      {"1", "Epyc", "16", "32", "3000", "CPU1", "B2", "EXTRA1", "EXTRA2"}})});
    const auto j = hardware_ci_json(d, 0);
    const auto& rows = section_of(j, "cpu")["rows"];
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].size() == 7);
    CHECK(rows[0]["idx"] == "0");
    CHECK(rows[0]["cores"] == "8");
    CHECK(rows[0]["threads"].is_null());
    CHECK(rows[0]["stepping"].is_null());
    CHECK(rows[1].size() == 7); // the two extra cells are ignored
    CHECK(rows[1]["stepping"] == "B2");
    CHECK_FALSE(rows[1].contains("EXTRA1"));
}

// Rows are served only for the recognised `ok` and `constrained` levels, matched exactly: a blank
// level (rows stored but no status row) and a mixed-case level are neither complete nor row-bearing.
TEST_CASE("hardware_ci_json: a blank or mixed-case level serves no rows and is not complete",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({make_section("cpu", "", "", {{"0", "Xeon", "8", "16", "2400", "CPU0", "A"}}),
                        make_section("disk", "OK", "", {{"0", "NVMe", "512", "ssd", "nvme"}}),
                        make_section("swap", "Constrained", "r", {{"/swap", "1024", "file"}})});
    const auto j = hardware_ci_json(d, 0);
    const auto& cpu = section_of(j, "cpu");
    REQUIRE(cpu.is_object());
    CHECK(cpu["status"].is_null());
    CHECK(cpu["complete"] == false);
    CHECK(cpu["rows"].empty());
    const auto& disk = section_of(j, "disk");
    CHECK(disk["status"] == "OK"); // served as the agent sent it, never normalised into a recognised level
    CHECK(disk["complete"] == false);
    CHECK(disk["rows"].empty());
    CHECK(section_of(j, "swap")["complete"] == false);
    CHECK(section_of(j, "swap")["rows"].empty());
}

// The registry order picks the first stored section of a kind: a duplicate kind never doubles up.
TEST_CASE("hardware_ci_json: a duplicated section kind is served once and the first one wins",
          "[hardware][model][json][sections]") {
    auto d = v2_detail({make_section("cpu", "ok", "", {{"0", "First", "1", "1", "1", "S", "x"}}),
                        make_section("cpu", "unavailable", "dup", {})});
    const auto j = hardware_ci_json(d, 0);
    std::size_t n = 0;
    for (const auto& s : j["ci"]["sections"])
        n += s["kind"] == "cpu" ? 1 : 0;
    CHECK(n == 1);
    CHECK(section_of(j, "cpu")["status"] == "ok");
    CHECK(section_of(j, "cpu")["rows"][0]["model"] == "First");
}

// Every registry kind either has a `*_source` mapping in ci_sections_json (status-only kinds) or
// serves `source: null` (list kinds). A new status-only kind added to the registry without a
// mapping serves null here and fails, instead of silently carrying a null source.
TEST_CASE("hardware_ci_json: every status-only registry kind has a source mapping and list kinds serve null",
          "[hardware][model][json][sections]") {
    std::vector<DeviceCiSection> all;
    for (const auto& def : kDeviceCiSections)
        all.push_back(make_section(def.section, "ok"));
    auto d = v2_detail(all); // chassis_source, board_source, machine_id_source are all non-blank
    const auto j = hardware_ci_json(d, 0);
    REQUIRE(j["ci"]["sections"].size() == kDeviceCiSectionCount);
    for (const auto& def : kDeviceCiSections) {
        INFO(def.section);
        const auto& sec = section_of(j, def.section);
        REQUIRE(sec.is_object());
        if (def.table == nullptr)
            CHECK(sec["source"].is_string());
        else
            CHECK(sec["source"].is_null());
    }
}

// ── apply_ci_with_sections_read: the store result -> HardwareCiDetail mapping ────────────────

namespace {
DeviceCiRecord mapped_record(int blob_version) {
    DeviceCiRecord r;
    r.agent_id = "a1";
    r.blob_version = blob_version;
    r.chassis_serial = "CHS1";
    return r;
}
} // namespace

// Kills: leaving `ci_sections` at a stale value on a failed record read.
TEST_CASE("apply_ci_with_sections_read: a failed record read is a degraded ci and no sections",
          "[hardware][model][sections]") {
    HardwareCiDetail d;
    d.ci_sections = std::vector<DeviceCiSection>{make_section("cpu", "ok")};
    apply_ci_with_sections_read(d, std::unexpected(CiReadError::kDegraded));
    REQUIRE_FALSE(d.ci.has_value());
    CHECK(d.ci.error() == CiReadError::kDegraded);
    // No sections read was made: NOT READ (was an empty list before #7162, which read "none
    // stored").
    CHECK_FALSE(d.ci_sections.has_value());
    CHECK_FALSE(hardware_ci_sections_unreadable(d)); // ci degraded, not a sections failure
}

TEST_CASE("apply_ci_with_sections_read: an absent record is an answered nullopt with no sections",
          "[hardware][model][sections]") {
    HardwareCiDetail d;
    apply_ci_with_sections_read(d, DeviceCiWithSections{});
    REQUIRE(d.ci.has_value());
    CHECK_FALSE(d.ci->has_value());
    REQUIRE(d.ci_sections.has_value());
    REQUIRE(d.ci_sections->has_value());
    CHECK((*d.ci_sections)->empty());
}

TEST_CASE("apply_ci_with_sections_read: a v2 record moves its sections into ci_sections",
          "[hardware][model][sections]") {
    HardwareCiDetail d;
    DeviceCiWithSections read;
    read.record = mapped_record(2);
    read.record->sections = {make_section("cpu", "ok", "", {{"0", "Xeon"}}), make_section("swap", "unavailable")};
    apply_ci_with_sections_read(d, std::move(read));
    REQUIRE(d.ci.has_value());
    REQUIRE(d.ci->has_value());
    CHECK((*d.ci)->chassis_serial == "CHS1");
    CHECK((*d.ci)->sections.empty()); // one home for the rows
    REQUIRE(d.ci_sections.has_value());
    REQUIRE(d.ci_sections->has_value());
    REQUIRE((*d.ci_sections)->size() == 2);
    CHECK((**d.ci_sections)[0].kind == "cpu");
    CHECK((**d.ci_sections)[1].level == "unavailable");
    CHECK_FALSE(hardware_ci_sections_unreadable(d));
}

// Kills: dropping the `blob_version >= 2` guard (a v1 record never has sections to serve, whatever
// a caller left in the struct).
TEST_CASE("apply_ci_with_sections_read: a v1 record serves no sections even if some are present",
          "[hardware][model][sections]") {
    HardwareCiDetail d;
    DeviceCiWithSections read;
    read.record = mapped_record(1);
    read.record->sections = {make_section("cpu", "ok")};
    apply_ci_with_sections_read(d, std::move(read));
    REQUIRE(d.ci.has_value());
    REQUIRE(d.ci->has_value());
    REQUIRE(d.ci_sections.has_value());
    REQUIRE(d.ci_sections->has_value());
    CHECK((*d.ci_sections)->empty());
    CHECK(hardware_ci_json(d, 0)["sections_state"] == "absent");
}

// Kills: flattening a failed sections read into an empty vector (a 200 that reads "reports none").
TEST_CASE("apply_ci_with_sections_read: a failed sections read keeps the error and the record",
          "[hardware][model][sections]") {
    HardwareCiDetail d;
    DeviceCiWithSections read;
    read.record = mapped_record(2);
    read.sections_failed = true;
    apply_ci_with_sections_read(d, std::move(read));
    REQUIRE(d.ci.has_value());
    REQUIRE(d.ci->has_value());
    CHECK((*d.ci)->chassis_serial == "CHS1");
    REQUIRE(d.ci_sections.has_value());
    REQUIRE_FALSE(d.ci_sections->has_value());
    CHECK(d.ci_sections->error() == CiReadError::kDegraded);
    CHECK(hardware_ci_sections_unreadable(d));
}

// ── The persisted row-count check (up-2): a section whose child rows were lost out of band ────

namespace {

DeviceCiSection counted_section(std::string kind, std::string level, std::string reason, std::optional<int> count,
                                std::size_t rows) {
    std::vector<std::vector<std::string>> r;
    for (std::size_t i = 0; i < rows; ++i)
        r.push_back({std::to_string(i), "M", "4", "8", "2800", "S", "1"});
    auto s = make_section(std::move(kind), std::move(level), std::move(reason), std::move(r));
    s.row_count = count;
    return s;
}

} // namespace

// Kills: verifying a section with no persisted count (the pre-v3 upgrade path must read as before).
TEST_CASE("verify_section_row_count: a NULL count leaves the section exactly as stored",
          "[hardware][model][sections][row_count]") {
    for (const char* level : {"ok", "constrained", "unavailable", "permission_denied", "novel", ""}) {
        INFO(level);
        const auto v = verify_section_row_count(counted_section("cpu", level, "r", std::nullopt, 0));
        CHECK(v.level == level);
        CHECK(v.reason == "r");
    }
}

TEST_CASE("verify_section_row_count: an equal count leaves the section exactly as stored",
          "[hardware][model][sections][row_count]") {
    auto v = verify_section_row_count(counted_section("cpu", "ok", "", 3, 3));
    CHECK(v.level == "ok");
    CHECK(v.reason.empty());
    v = verify_section_row_count(counted_section("cpu", "ok", "", 0, 0)); // a verified-empty section
    CHECK(v.level == "ok");
    v = verify_section_row_count(counted_section("cpu", "constrained", "server_cap:32", 32, 32));
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server_cap:32");
}

// Kills: serving a section whose rows were deleted as complete (the up-2 defect).
TEST_CASE("verify_section_row_count: fewer rows than stored downgrades ok to constrained",
          "[hardware][model][sections][row_count]") {
    const auto v = verify_section_row_count(counted_section("cpu", "ok", "", 3, 0));
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server:row_count_mismatch");
    // An ok section that already carried a reason keeps it, with the token appended.
    const auto w = verify_section_row_count(counted_section("cpu", "ok", "agent:note", 3, 1));
    CHECK(w.level == "constrained");
    CHECK(w.reason == "agent:note;server:row_count_mismatch");
}

TEST_CASE("verify_section_row_count: more rows than stored is the same downgrade",
          "[hardware][model][sections][row_count]") {
    const auto v = verify_section_row_count(counted_section("cpu", "ok", "", 1, 2));
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server:row_count_mismatch");
}

TEST_CASE("verify_section_row_count: an already constrained section keeps its reason and gains the token once",
          "[hardware][model][sections][row_count]") {
    const auto v = verify_section_row_count(counted_section("cpu", "constrained", "server_cap:32", 32, 10));
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server_cap:32;server:row_count_mismatch");
    // Idempotent: a reason that already names the mismatch is not extended.
    const auto again = verify_section_row_count(
        counted_section("cpu", "constrained", "server:row_count_mismatch", 3, 1));
    CHECK(again.reason == "server:row_count_mismatch");
    // A constrained section with no reason takes just the token.
    CHECK(verify_section_row_count(counted_section("cpu", "constrained", "", 3, 1)).reason ==
          "server:row_count_mismatch");
}

// Kills: upgrading or reasoning over a level that has no rows by contract.
TEST_CASE("verify_section_row_count: unavailable and permission_denied and unknown and blank levels are never touched",
          "[hardware][model][sections][row_count]") {
    for (const char* level : {"unavailable", "permission_denied", "novel", ""}) {
        INFO(level);
        const auto v = verify_section_row_count(counted_section("cpu", level, "why", 5, 0));
        CHECK(v.level == level);
        CHECK(v.reason == "why");
    }
}

// Kills: a mismatch that reaches the model but not the wire, or one that still serves the rows read (#7165).
TEST_CASE("hardware_ci_json: a row-count mismatch is served constrained and incomplete with NO rows",
          "[hardware][model][json][sections][row_count]") {
    auto d = v2_detail({counted_section("cpu", "ok", "", 3, 1), counted_section("dimm", "ok", "", 2, 0),
                        counted_section("disk", "ok", "", std::nullopt, 0)});
    const auto j = hardware_ci_json(d, 0);
    const auto& cpu = section_of(j, "cpu");
    CHECK(cpu["status"] == "constrained");
    CHECK(cpu["complete"] == false);
    CHECK(cpu["reason"] == "server:row_count_mismatch");
    CHECK(cpu["rows"].is_array());
    CHECK(cpu["rows"].empty()); // the one row that remains is WITHHELD (#7165)
    const auto& dimm = section_of(j, "dimm");
    CHECK(dimm["status"] == "constrained");
    CHECK(dimm["complete"] == false);
    CHECK(dimm["rows"].empty());
    // No persisted count: exactly as before.
    const auto& disk = section_of(j, "disk");
    CHECK(disk["status"] == "ok");
    CHECK(disk["complete"] == true);
    CHECK(disk["reason"].is_null());
}

TEST_CASE("hardware_ci_json: a status-only section never takes the row-count check",
          "[hardware][model][json][sections][row_count]") {
    auto d = v2_detail({counted_section("chassis", "ok", "", 4, 0)});
    const auto j = hardware_ci_json(d, 0);
    CHECK(section_of(j, "chassis")["status"] == "ok");
    CHECK(section_of(j, "chassis")["complete"] == true);
}

// ── The section content digest (up2r-up-3): same-count drift the row count cannot see ──────────

namespace {

using Rows = std::vector<std::vector<std::string>>;

const DeviceCiSectionDef& def_of(std::string_view kind) {
    const auto idx = device_ci_section_index(kind);
    REQUIRE(idx.has_value());
    return kDeviceCiSections[*idx];
}

Rows cpu_rows(std::size_t n) {
    Rows r;
    for (std::size_t i = 0; i < n; ++i)
        r.push_back({std::to_string(i), "M", "4", "8", "2800", "S", "1"});
    return r;
}

// A section exactly as the store would hand it back: the count AND the digest of its own rows.
DeviceCiSection digested_section(std::string kind, std::string level, std::string reason, Rows rows) {
    const auto& def = def_of(kind);
    const auto digest = section_content_digest(def, rows);
    REQUIRE(digest.has_value());
    const auto n = static_cast<int>(rows.size());
    auto s = make_section(std::move(kind), std::move(level), std::move(reason), std::move(rows));
    s.row_count = n;
    s.content_digest = *digest;
    return s;
}

} // namespace

// Kills: a serialization where cell boundaries can shift (the classic ambiguity of a delimiter join).
TEST_CASE("section_content_digest: moving a byte across a cell boundary changes the digest",
          "[hardware][model][sections][digest]") {
    const auto& def = def_of("swap"); // 3 columns
    const auto a = section_content_digest(def, Rows{{"ab", "c", "d"}});
    const auto b = section_content_digest(def, Rows{{"a", "bc", "d"}});
    const auto c = section_content_digest(def, Rows{{"a", "b", "cd"}});
    REQUIRE(a.has_value());
    CHECK(a != b);
    CHECK(b != c);
    CHECK(a != c);
    // A delimiter-looking byte inside a cell is just a byte.
    CHECK(section_content_digest(def, Rows{{"a|b", "", ""}}) != section_content_digest(def, Rows{{"a", "b", ""}}));
}

// Kills: treating an empty cell and a missing cell, or an empty row and no row, as different - and
// the reverse: treating two different shapes as the same.
TEST_CASE("section_content_digest: a short row pads to blanks and an extra cell is ignored",
          "[hardware][model][sections][digest]") {
    const auto& def = def_of("swap");
    // The writer stores a short row padded with blanks and truncates a long one, so the digest of
    // the wire shape and of the stored shape must agree.
    CHECK(section_content_digest(def, Rows{{"d", "1"}}) == section_content_digest(def, Rows{{"d", "1", ""}}));
    CHECK(section_content_digest(def, Rows{{"d", "1", "s", "ignored"}}) ==
          section_content_digest(def, Rows{{"d", "1", "s"}}));
    // But a blank row is not the absence of a row.
    CHECK(section_content_digest(def, Rows{{"", "", ""}}) != section_content_digest(def, Rows{}));
    CHECK(section_content_digest(def, Rows{{"", "", ""}, {"", "", ""}}) !=
          section_content_digest(def, Rows{{"", "", ""}}));
}

// Kills: a digest that ignores row order (a generation swap that permutes rows is still drift).
TEST_CASE("section_content_digest: row order is part of the content and the kind is part of the preimage",
          "[hardware][model][sections][digest]") {
    const Rows fwd{{"d0", "1", "s"}, {"d1", "2", "s"}};
    const Rows rev{{"d1", "2", "s"}, {"d0", "1", "s"}};
    const auto& swap = def_of("swap");
    CHECK(section_content_digest(swap, fwd) != section_content_digest(swap, rev));
    // Stable: the same rows always give the same v1 digest (prefix plus 64 hex).
    const auto d = section_content_digest(swap, fwd);
    REQUIRE(d.has_value());
    CHECK(d->size() == 3 + 64);
    CHECK(d == section_content_digest(swap, fwd));
    // Same bytes under another kind of the same width never collide.
    const auto& other = def_of("swap");
    DeviceCiSectionDef renamed = other;
    renamed.section = "swapx";
    CHECK(section_content_digest(renamed, fwd) != d);
}

// Pins the serialization itself: a silent change would make every stored digest read as drift.
// Two rows, so a position that does not advance (every row at ord 0) is caught.
TEST_CASE("section_content_preimage layout is pinned", "[hardware][model][sections][digest]") {
    const std::string pre = section_content_preimage("swap", 3, Rows{{"a", "", "c"}, {"d", "e", "f"}});
    std::string want = "yuzu.device_ci.section.v1";
    auto u64 = [&](std::uint64_t v) {
        for (int sh = 56; sh >= 0; sh -= 8)
            want.push_back(static_cast<char>((v >> sh) & 0xff));
    };
    auto str = [&](std::string_view x) {
        u64(x.size());
        want.append(x);
    };
    str("swap");
    u64(3); // ncol
    u64(2); // nrows
    u64(0); // ord of the first row
    str("a");
    str("");
    str("c");
    u64(1); // ord of the second row
    str("d");
    str("e");
    str("f");
    CHECK(pre == want);
}

// A hard-coded vector, computed outside the code under test (python hashlib over the layout above):
// the digest function itself, prefix included, cannot drift without this failing.
TEST_CASE("section_content_digest: a fixed input has a fixed v1 digest", "[hardware][model][sections][digest]") {
    const auto d = section_content_digest(def_of("swap"), Rows{{"a", "", "c"}, {"d", "e", "f"}});
    REQUIRE(d.has_value());
    CHECK(*d == "v1:3e77875b5c562ab906284410143716a347521d08e6b9a6e3dc44fd5a3c94c2c4");
}

TEST_CASE("section_content_digest: the stored form is the v1 prefix then 64 lowercase hex",
          "[hardware][model][sections][digest]") {
    const auto d = section_content_digest(def_of("cpu"), cpu_rows(2));
    REQUIRE(d.has_value());
    CHECK(d->size() == 3 + 64);
    CHECK(d->substr(0, 3) == "v1:");
    CHECK(classify_stored_digest(*d) == StoredDigestForm::kCurrent);
    for (const char c : d->substr(3))
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
}

// The CLOSED classification of a stored (non-NULL) digest. Only a well-formed digest of a layout
// version other than 1 is unverified; everything else that is not the current form is damage.
TEST_CASE("classify_stored_digest: only a well-formed digest of another layout version is unverified",
          "[hardware][model][sections][digest]") {
    using F = StoredDigestForm;
    const std::string hex(64, 'a');
    // Current form.
    CHECK(classify_stored_digest("v1:" + hex) == F::kCurrent);
    CHECK(classify_stored_digest("v1:") == F::kCurrent); // compared (and mismatches): never unverified
    CHECK(classify_stored_digest("v1:xyz") == F::kCurrent);
    // A well-formed digest of another layout version: unverified.
    for (const char* v : {"v2:abc", "v10:abc", "v9:x", "v123456:z", "v2: leading space is the remainder"})
        CHECK(classify_stored_digest(v) == F::kOtherLayout);
    CHECK(classify_stored_digest("v2:" + hex) == F::kOtherLayout);
    // Everything else is malformed (a mismatch at the verifier).
    for (const char* v : {"", " ", "  ", "\n", "v", "v:", "v1", "vx:abc", "v0:abc", "v01:abc", "v001:abc",
                          "v2", "v2:", "v10:", "v1234567:abc", "V1:abc", "V2:abc", "x1:abc", "1:abc",
                          "sha256:abc", "garbage", "v-1:abc", "v+1:abc", " v2:abc", "v 2:abc", "v2 :abc"})
        CHECK(classify_stored_digest(v) == F::kMalformed);
    CHECK(classify_stored_digest(hex) == F::kMalformed);               // bare hex
    CHECK(classify_stored_digest(" v1:" + hex) == F::kMalformed);       // leading space
    CHECK(classify_stored_digest("V1:" + hex) == F::kMalformed);
}

// Kills: a digest over the cell WITH its NULs. pg::to_text_array drops 0x00 on store, so the cell
// reads back without it and the stored digest must be of that projection.
TEST_CASE("section_content_digest: a NUL byte in a cell is skipped to match what the store keeps",
          "[hardware][model][sections][digest]") {
    const auto& disk = def_of("disk");
    const std::string nul("m\0x", 3);
    REQUIRE(nul.size() == 3);
    CHECK(section_content_digest(disk, Rows{{"0", nul, "1", "ssd", "sata"}}) ==
          section_content_digest(disk, Rows{{"0", "mx", "1", "ssd", "sata"}}));
    // A cell of only NULs is the blank cell; a NUL does not hide a following cell boundary.
    CHECK(section_content_digest(disk, Rows{{"0", std::string(2, '\0'), "1", "ssd", "sata"}}) ==
          section_content_digest(disk, Rows{{"0", "", "1", "ssd", "sata"}}));
    CHECK(section_content_digest(disk, Rows{{"0", "m", "x", "ssd", "sata"}}) !=
          section_content_digest(disk, Rows{{"0", nul, "1", "ssd", "sata"}}));
    // A section hand-built with a NUL cell verifies, not a permanent mismatch.
    auto s = digested_section("disk", "ok", "", Rows{{"0", nul, "1", "ssd", "sata"}});
    CHECK(verify_section_content(s).level == "ok");
}

TEST_CASE("verify_section_content: an intact section is served exactly as stored",
          "[hardware][model][sections][digest]") {
    for (const char* level : {"ok", "constrained"}) {
        INFO(level);
        auto v = verify_section_content(digested_section("cpu", level, "r", cpu_rows(3)));
        CHECK(v.level == level);
        CHECK(v.reason == "r");
    }
    // A verified-empty section too.
    const auto e = verify_section_content(digested_section("cpu", "ok", "", Rows{}));
    CHECK(e.level == "ok");
    CHECK(e.reason.empty());
}

// Kills (by mutation: the verifier ignores the digest) the up2r-up-3 defect - same-count drift.
TEST_CASE("verify_section_content: a same-count edit of one cell downgrades ok to constrained",
          "[hardware][model][sections][digest]") {
    auto s = digested_section("cpu", "ok", "", cpu_rows(3));
    s.rows[1][1] = "Edited"; // count unchanged: the count rule alone sees nothing
    CHECK(verify_section_row_count(s).level == "ok");
    const auto v = verify_section_content(s);
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server:content_digest_mismatch");
    // Also with a reason already present, and idempotently.
    auto t = digested_section("cpu", "ok", "agent:note", cpu_rows(3));
    t.rows[0][2] = "9";
    CHECK(verify_section_content(t).reason == "agent:note;server:content_digest_mismatch");
    auto u = digested_section("cpu", "constrained", "server:content_digest_mismatch", cpu_rows(3));
    u.rows[0][2] = "9";
    CHECK(verify_section_content(u).reason == "server:content_digest_mismatch");
    // A capped section keeps its token and gains the digest one.
    auto cap = digested_section("cpu", "constrained", "server_cap:32", cpu_rows(3));
    cap.rows[2][0] = "x";
    const auto cv = verify_section_content(cap);
    CHECK(cv.level == "constrained");
    CHECK(cv.reason == "server_cap:32;server:content_digest_mismatch");
}

TEST_CASE("verify_section_content: rows swapped for another generation of the same size are caught",
          "[hardware][model][sections][digest]") {
    auto s = digested_section("cpu", "ok", "", cpu_rows(2));
    Rows other = cpu_rows(2);
    other[0][1] = "Other";
    other[1][1] = "Other";
    s.rows = other;
    const auto v = verify_section_content(s);
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server:content_digest_mismatch");
}

// Composition: a lost row reports the count token alone (the digest necessarily changes too).
TEST_CASE("verify_section_content: a count mismatch is reported alone and wins over the digest",
          "[hardware][model][sections][digest]") {
    auto s = digested_section("cpu", "ok", "", cpu_rows(3));
    s.rows.pop_back();
    const auto v = verify_section_content(s);
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server:row_count_mismatch");
    // And with the count unverifiable (NULL) the digest still catches the loss.
    auto n = digested_section("cpu", "ok", "", cpu_rows(3));
    n.row_count.reset();
    n.rows.pop_back();
    CHECK(verify_section_content(n).reason == "server:content_digest_mismatch");
}

namespace {
// A provider that always fails, as sha256_hex does when EVP_Digest returns an error (#7163).
std::optional<std::string> failing_digest(std::string_view) {
    return std::nullopt;
}
} // namespace

// #7163: the reader's provider-failure branch, reached through the DigestFn seam. A section whose
// stored digest is intact must NEVER be served ok when the server cannot recompute the digest, and
// (owner ruling 2026-11-09) it carries its own token: the fault is the server's, not the rows'.
TEST_CASE("verify_section_content: a failing digest provider is never served ok",
          "[hardware][model][sections][digest]") {
    const auto s = digested_section("cpu", "ok", "", cpu_rows(2));
    REQUIRE(verify_section_content(s).level == "ok"); // the default provider verifies it
    const auto v = verify_section_content(s, &failing_digest);
    CHECK(v.level == "constrained");
    CHECK(v.reason ==
          "server:content_digest_unverifiable"); // a server fault: not the mismatch token
    CHECK(v.fault == SectionFault::Unverifiable);
    // An already-constrained section keeps its level and tokens and gains the digest token.
    const auto c = digested_section("cpu", "constrained", "server_cap:2", cpu_rows(2));
    const auto cv = verify_section_content(c, &failing_digest);
    CHECK(cv.level == "constrained");
    CHECK(cv.reason == "server_cap:2;server:content_digest_unverifiable");
    // A section that needs no digest is not touched by a failing provider.
    auto none = digested_section("cpu", "ok", "", cpu_rows(2));
    none.content_digest.reset();
    CHECK(verify_section_content(none, &failing_digest).level == "ok");
    auto denied = digested_section("cpu", "permission_denied", "x", {});
    CHECK(verify_section_content(denied, &failing_digest).level == "permission_denied");
}

// ── #7159: the pure cause, the counter and the sampled WARN ────────────────────────────────────

namespace {
double integrity_count(yuzu::MetricsRegistry& m, const char* reason) {
    return m.counter("yuzu_hardware_section_integrity_total", {{"reason", reason}}).value();
}
} // namespace

TEST_CASE(
    "verify_section_content: the pure cause is None for an intact or agent-constrained section",
    "[hardware][model][sections][digest][metrics]") {
    CHECK(verify_section_content(digested_section("cpu", "ok", "", cpu_rows(2))).fault ==
          SectionFault::None);
    CHECK(
        verify_section_content(digested_section("cpu", "constrained", "agent:partial", cpu_rows(2)))
            .fault == SectionFault::None);
    auto none = digested_section("cpu", "ok", "", cpu_rows(2));
    none.content_digest.reset();
    none.row_count.reset();
    CHECK(verify_section_content(none).fault == SectionFault::None);
    CHECK(section_fault_token(SectionFault::None).empty());
    CHECK(section_fault_label(SectionFault::None).empty());
}

// The counted cause and the served token come from ONE verdict, so they cannot disagree: for each
// of the three causes the served reason contains exactly that fault's token, and the label counted
// for the same section is that fault's label.
TEST_CASE(
    "record_section_integrity: the counted cause equals the served token for the same section",
    "[hardware][model][sections][digest][metrics]") {
    struct Case {
        DeviceCiSection section;
        DigestFn digest;
        SectionFault expect;
        const char* label;
        const char* token;
    };
    auto lost = digested_section("cpu", "ok", "", cpu_rows(3));
    lost.rows.pop_back(); // count and digest both disagree: the count token alone
    auto edited = digested_section("cpu", "ok", "", cpu_rows(2));
    edited.rows[0][1] = "Edited"; // same count, different content
    const auto intact = digested_section("cpu", "ok", "", cpu_rows(2));
    const Case cases[] = {
        {lost, nullptr, SectionFault::RowCount, "row_count_mismatch", "server:row_count_mismatch"},
        {edited, nullptr, SectionFault::Content, "content_digest_mismatch",
         "server:content_digest_mismatch"},
        {intact, &failing_digest, SectionFault::Unverifiable, "digest_unverifiable",
         "server:content_digest_unverifiable"},
    };
    for (const auto& c : cases) {
        INFO(c.label);
        const auto verdict = verify_section_content(c.section, c.digest);
        REQUIRE(verdict.fault == c.expect);
        CHECK(verdict.reason.find(c.token) != std::string::npos);
        CHECK(section_fault_token(verdict.fault) == c.token);
        CHECK(section_fault_label(verdict.fault) == c.label);
        yuzu::MetricsRegistry m;
        record_section_integrity({c.section}, "agent-1", &m, c.digest);
        for (const char* reason :
             {"row_count_mismatch", "content_digest_mismatch", "digest_unverifiable"})
            CHECK(integrity_count(m, reason) == (std::string_view(reason) == c.label ? 1.0 : 0.0));
    }
}

TEST_CASE(
    "record_section_integrity: one increment per faulted section per call, nothing for intact ones",
    "[hardware][model][sections][digest][metrics]") {
    yuzu::MetricsRegistry m;
    auto lost = digested_section("cpu", "ok", "", cpu_rows(3));
    lost.rows.pop_back();
    auto lost_swap = digested_section("swap", "ok", "", Rows{{"a", "1", "2"}});
    lost_swap.rows.clear();
    auto edited = digested_section("cpu", "ok", "", cpu_rows(2));
    edited.rows[0][1] = "Edited";
    const std::vector<DeviceCiSection> sections = {
        lost, digested_section("cpu", "ok", "", cpu_rows(2)), lost_swap, edited,
        digested_section("cpu", "unavailable", "x", {})};
    record_section_integrity(sections, "agent-1", &m);
    CHECK(integrity_count(m, "row_count_mismatch") == 2.0);
    CHECK(integrity_count(m, "content_digest_mismatch") == 1.0);
    CHECK(integrity_count(m, "digest_unverifiable") == 0.0);
    // Counts reads composed with a faulted section, not distinct defects: the same call again
    // doubles it.
    record_section_integrity(sections, "agent-1", &m);
    CHECK(integrity_count(m, "row_count_mismatch") == 4.0);
    // An empty list (a v1 record, or nothing stored) counts nothing; a null registry is safe.
    yuzu::MetricsRegistry empty;
    record_section_integrity({}, "agent-1", &empty);
    CHECK(integrity_count(empty, "row_count_mismatch") == 0.0);
    record_section_integrity(sections, "agent-1", nullptr);
}

// The WARN names the device id and the section kind and never the row contents, and is sampled per
// reason: the leading edge of an episode logs, the rest of that episode does not.
TEST_CASE(
    "record_section_integrity: the WARN names agent and kind, never row contents, and is sampled",
    "[hardware][model][sections][digest][metrics]") {
    reset_section_integrity_log_state_for_test();
    auto lost = digested_section("cpu", "ok", "", cpu_rows(3));
    lost.rows.pop_back();
    lost.rows[0][1] = "SECRET-CPU-MODEL";
    std::string logs;
    {
        yuzu::test::LogCapture cap(spdlog::level::warn);
        record_section_integrity({lost}, "agent-warn", nullptr);
        record_section_integrity({lost}, "agent-warn", nullptr); // same episode: no second line
        cap.stop();
        logs = cap.text();
    }
    CHECK(logs.find("agent=agent-warn") != std::string::npos);
    CHECK(logs.find("kind=cpu") != std::string::npos);
    CHECK(logs.find("reason=row_count_mismatch") != std::string::npos);
    CHECK(logs.find("rows withheld") != std::string::npos); // the WARN says what was served (#7165)
    CHECK(logs.find("SECRET-CPU-MODEL") == std::string::npos);
    const auto first = logs.find("section integrity fault");
    REQUIRE(first != std::string::npos);
    CHECK(logs.find("section integrity fault", first + 1) == std::string::npos); // sampled
    // A different reason has its own episode and logs on its own leading edge.
    {
        yuzu::test::LogCapture cap(spdlog::level::warn);
        auto edited = digested_section("cpu", "ok", "", cpu_rows(2));
        edited.rows[0][1] = "Edited";
        record_section_integrity({edited}, "agent-warn", nullptr);
        cap.stop();
        CHECK(cap.text().find("reason=content_digest_mismatch") != std::string::npos);
        CHECK(cap.text().find("rows withheld") != std::string::npos);
        CHECK(cap.text().find("rows served") == std::string::npos);
    }
}

// Kills: a series that exists only after its first fault (a dashboard cannot tell "no fault" from
// "series absent"). The expected labels below are hand-kept on purpose: a new SectionFault must be
// added here too (the static_assert on kCountedFaults and -Wswitch flag the production side).
TEST_CASE("register_section_integrity_metrics: pre-seeds one series per counted fault at zero",
          "[hardware][model][sections][metrics]") {
    yuzu::MetricsRegistry m;
    register_section_integrity_metrics(m);
    const std::string text = m.serialize();
    std::size_t series = 0;
    for (const auto fault :
         {SectionFault::RowCount, SectionFault::Content, SectionFault::Unverifiable}) {
        const std::string label(section_fault_label(fault));
        INFO(label);
        REQUIRE_FALSE(label.empty());
        CHECK(text.find("yuzu_hardware_section_integrity_total{reason=\"" + label + "\"} 0\n") !=
              std::string::npos);
        CHECK(integrity_count(m, label.c_str()) == 0.0);
    }
    for (std::size_t at = 0;
         (at = text.find("yuzu_hardware_section_integrity_total{", at)) != std::string::npos; ++at)
        ++series;
    CHECK(series == 3); // exactly one per non-None SectionFault
    CHECK(text.find("# TYPE yuzu_hardware_section_integrity_total counter") != std::string::npos);
    CHECK(text.find("# HELP yuzu_hardware_section_integrity_total ") != std::string::npos);
}

// Kills: an unverifiable provider masking a count mismatch (the count is the more specific report
// and is checked first), in either order of evaluation.
TEST_CASE("verify_section_content: a count mismatch with a failing provider reports the count",
          "[hardware][model][sections][digest]") {
    auto s = digested_section("cpu", "ok", "", cpu_rows(3));
    s.rows.pop_back();
    const auto v = verify_section_content(s, &failing_digest);
    CHECK(v.fault == SectionFault::RowCount);
    CHECK(v.reason == "server:row_count_mismatch");
    CHECK(served_section_verdict(s, &failing_digest).fault == SectionFault::RowCount);
}

// Each fault token is appended after an agent-reported reason with a ';' and the level is
// downgraded to constrained, whichever of the three causes it is.
TEST_CASE("verify_section_content: every fault token is ';'-joined after an agent reason",
          "[hardware][model][sections][digest]") {
    auto lost = digested_section("cpu", "ok", "agent:note", cpu_rows(3));
    lost.rows.pop_back();
    CHECK(verify_section_content(lost).reason == "agent:note;server:row_count_mismatch");
    auto edited = digested_section("cpu", "ok", "agent:note", cpu_rows(2));
    edited.rows[0][1] = "Edited";
    CHECK(verify_section_content(edited).reason == "agent:note;server:content_digest_mismatch");
    const auto intact = digested_section("cpu", "ok", "agent:note", cpu_rows(2));
    const auto u = verify_section_content(intact, &failing_digest);
    CHECK(u.level == "constrained");
    CHECK(u.reason == "agent:note;server:content_digest_unverifiable");
    // An agent-constrained section with an intact digest keeps its reason and is counted as
    // nothing.
    const auto agent_only = digested_section("cpu", "constrained", "agent:note", cpu_rows(2));
    CHECK(served_section_verdict(agent_only).fault == SectionFault::None);
    CHECK(served_section_verdict(agent_only).reason == "agent:note");
}

// Kills: the counter counting a fault the body does not carry. A status-only kind (or an
// unregistered one) is served as stored and never compared, even if a row_count is stored for it;
// `verify_section_content` alone WOULD flag it, which is why both the body and the counter go
// through `served_section_verdict`. An unavailable / permission_denied section is likewise never
// compared.
TEST_CASE(
    "served_section_verdict: a non-table or unregistered kind is served as stored, never counted",
    "[hardware][model][sections][metrics]") {
    for (const char* kind : {"chassis", "baseboard", "machine_id", "no_such_kind"}) {
        INFO(kind);
        auto s = make_section(kind, "ok", "r", {});
        s.row_count = 3; // a stored count the (empty) rows would disagree with
        s.content_digest = "v1:" + std::string(64, 'a');
        const auto v = served_section_verdict(s);
        CHECK(v.level == "ok");
        CHECK(v.reason == "r");
        CHECK(v.fault == SectionFault::None);
        yuzu::MetricsRegistry m;
        record_section_integrity({s}, "agent-1", &m);
        CHECK(integrity_count(m, "row_count_mismatch") == 0.0);
        CHECK(integrity_count(m, "content_digest_mismatch") == 0.0);
        CHECK(integrity_count(m, "digest_unverifiable") == 0.0);
    }
    // The guard matters: the bare verifier would report the count for a status-only kind.
    auto chassis = make_section("chassis", "ok", "", {});
    chassis.row_count = 3;
    CHECK(verify_section_content(chassis).fault == SectionFault::RowCount);
    // No rows by contract for these levels: nothing to compare, nothing counted.
    for (const char* level : {"unavailable", "permission_denied"}) {
        INFO(level);
        auto s = digested_section("cpu", level, "x", cpu_rows(2));
        s.rows.clear();
        CHECK(served_section_verdict(s).fault == SectionFault::None);
        CHECK(served_section_verdict(s, &failing_digest).fault == SectionFault::None);
    }
}

// SectionFault::None has no sampler: passing it anywhere cannot pollute another reason's WARN
// state.
TEST_CASE("served_section_verdict: an intact table-backed section counts nothing and logs nothing",
          "[hardware][model][sections][metrics]") {
    reset_section_integrity_log_state_for_test();
    yuzu::MetricsRegistry m;
    std::string logs;
    {
        yuzu::test::LogCapture cap(spdlog::level::warn);
        record_section_integrity({digested_section("cpu", "ok", "", cpu_rows(2))}, "agent-quiet",
                                 &m);
        cap.stop();
        logs = cap.text();
    }
    CHECK(logs.find("section integrity fault") == std::string::npos);
    CHECK(integrity_count(m, "digest_unverifiable") == 0.0);
}

// Kills: verifying (or downgrading) a section that has no stored digest - the pre-feature path.
TEST_CASE("verify_section_content: a NULL digest leaves the section as the count rule left it",
          "[hardware][model][sections][digest]") {
    auto s = digested_section("cpu", "ok", "", cpu_rows(3));
    s.content_digest.reset();
    s.rows[0][1] = "Edited";
    const auto v = verify_section_content(s);
    CHECK(v.level == "ok");
    CHECK(v.reason.empty());
    // The count rule still applies on its own.
    s.rows.pop_back();
    CHECK(verify_section_content(s).reason == "server:row_count_mismatch");
}

// Kills: a verifier that early-returns on a stored digest of the wrong length, or compares only a
// prefix of it (fail-open on a corrupt column). A value that carries the v1 prefix is a digest this
// build can recompute, so any difference from it is a mismatch.
TEST_CASE("verify_section_content: a wrong or damaged v1 digest is a mismatch",
          "[hardware][model][sections][digest]") {
    const auto good = section_content_digest(def_of("cpu"), cpu_rows(2));
    REQUIRE(good.has_value());
    const std::string hex = good->substr(3);
    std::string upper = hex;
    for (auto& c : upper)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    const std::string bad_values[] = {
        "v1:deadbeef",                               // garbage, short
        "v1:",                                       // prefix only
        "v1:" + hex.substr(0, 8),                    // truncated to 8
        "v1:" + hex.substr(0, 63),                   // one short
        "v1:" + hex + "0",                           // one long
        "v1:" + hex.substr(0, 8) + std::string(56, '0'), // right head, wrong tail
        "v1:" + upper,                               // case changed
        "",                                          // empty
        " ",                                         // whitespace
        " " + *good,                                 // valid, leading space
        *good + " ",                                 // valid, trailing space
        "V1:" + hex,                                 // wrong case of the prefix
        hex,                                         // bare 64 hex (never shipped)
        "v1:" + hex + std::string(2, 'a'),           // 66 chars after the prefix
        "v:",                                        // malformed version forms
        "vx:abc",
        "v01:abc",
        "v0:abc",
        "v1",
        "v2:",                                       // another layout with nothing after it
        "garbage",
    };
    for (const auto& bad : bad_values) {
        INFO(bad);
        auto s = digested_section("cpu", "ok", "", cpu_rows(2));
        s.content_digest = bad;
        const auto v = verify_section_content(s);
        CHECK(v.level == "constrained");
        CHECK(v.reason == "server:content_digest_mismatch");
    }
}

// Kills: reading a well-formed digest of another layout version as drift (a false alarm on every
// row after a future layout bump), and the reverse: reading damage as unverified.
TEST_CASE("verify_section_content: a well-formed digest of another layout version is unverified",
          "[hardware][model][sections][digest]") {
    const auto good = section_content_digest(def_of("cpu"), cpu_rows(2));
    REQUIRE(good.has_value());
    const std::string hex = good->substr(3);
    for (const std::string& stored : {"v2:" + hex, std::string("v2:abc"), std::string("v10:abc"),
                                      std::string("v99:x")}) {
        INFO(stored);
        auto s = digested_section("cpu", "ok", "", cpu_rows(2));
        s.content_digest = stored;
        s.rows[0][1] = "Edited"; // would be a mismatch if the digest were understood
        const auto v = verify_section_content(s);
        CHECK(v.level == "ok");
        CHECK(v.reason.empty());
    }
}

// Kills: skipping the digest when no rows remain. With the count unknown (NULL) a section whose
// rows have all gone is visible only to the digest.
TEST_CASE("verify_section_content: a digest-only loss of every row is a mismatch",
          "[hardware][model][sections][digest]") {
    auto s = digested_section("cpu", "ok", "", cpu_rows(2));
    s.row_count.reset();
    s.rows.clear();
    const auto v = verify_section_content(s);
    CHECK(v.level == "constrained");
    CHECK(v.reason == "server:content_digest_mismatch");
}

TEST_CASE("verify_section_content: levels with no rows by contract are never touched",
          "[hardware][model][sections][digest]") {
    for (const char* level : {"unavailable", "permission_denied", "novel", ""}) {
        INFO(level);
        auto s = digested_section("cpu", "ok", "why", cpu_rows(2));
        s.level = level;
        s.rows[0][1] = "Edited";
        const auto v = verify_section_content(s);
        CHECK(v.level == level);
        CHECK(v.reason == "why");
    }
}

TEST_CASE("verify_section_content: a status-only or unregistered kind never takes the digest check",
          "[hardware][model][sections][digest]") {
    auto c = digested_section("cpu", "ok", "", cpu_rows(1));
    c.kind = "chassis"; // status-only
    c.rows[0][1] = "Edited";
    CHECK(verify_section_content(c).level == "ok");
    auto u = digested_section("cpu", "ok", "", cpu_rows(1));
    u.kind = "nosuchkind";
    CHECK(verify_section_content(u).level == "ok");
}

// Kills: a mismatch that reaches the model but not the wire, or one that still serves the rows (#7165).
TEST_CASE("hardware_ci_json: a content-digest mismatch is served constrained and incomplete with NO rows",
          "[hardware][model][json][sections][digest]") {
    auto cpu = digested_section("cpu", "ok", "", cpu_rows(2));
    cpu.rows[0][1] = "Edited";
    auto d = v2_detail({std::move(cpu), digested_section("disk", "ok", "", Rows{})});
    const auto j = hardware_ci_json(d, 0);
    const auto& c = section_of(j, "cpu");
    CHECK(c["status"] == "constrained");
    CHECK(c["complete"] == false);
    CHECK(c["reason"] == "server:content_digest_mismatch");
    CHECK(c["rows"].is_array());
    CHECK(c["rows"].empty()); // NOT the reported generation: withheld (#7165)
    CHECK(section_of(j, "disk")["complete"] == true);
}

// Kills: withholding only for a section the agent reported `ok`. An agent-reported `constrained`
// section (here a server cap) with edited rows is just as unreliable, so it is withheld too.
TEST_CASE("hardware_ci_json: an agent-constrained section with a content mismatch also loses its rows",
          "[hardware][model][json][sections][digest]") {
    auto cpu = digested_section("cpu", "constrained", "server_cap:32", cpu_rows(2));
    cpu.rows[0][1] = "Edited";
    auto d = v2_detail({std::move(cpu), digested_section("disk", "constrained", "server_cap:32", cpu_rows(0))});
    const auto j = hardware_ci_json(d, 0);
    const auto& c = section_of(j, "cpu");
    CHECK(c["status"] == "constrained");
    CHECK(c["complete"] == false);
    CHECK(c["reason"] == "server_cap:32;server:content_digest_mismatch");
    CHECK(c["rows"].empty());
}

// The decision is a function of the fault ENUM, not of token text, and every enumerator is pinned:
// the two mismatches withhold; `unverifiable` (the server could not compare) and `None` serve.
// Kills: withholding on Unverifiable (rows hidden for a server fault) or on None (all rows hidden).
TEST_CASE("section_rows_withheld: only the two mismatch faults withhold rows",
          "[hardware][model][sections][digest]") {
    CHECK(section_rows_withheld(SectionFault::RowCount));
    CHECK(section_rows_withheld(SectionFault::Content));
    CHECK_FALSE(section_rows_withheld(SectionFault::Unverifiable));
    CHECK_FALSE(section_rows_withheld(SectionFault::None));
}

// The whole row-serving decision, over every input ci_sections_json feeds it. Kills: withholding
// for Unverifiable (a server fault) or for None, serving a mismatch, serving rows of a level that
// has none by contract, and serving rows for a status-only kind (no table).
TEST_CASE("section_serves_rows: table, stored level and fault together decide",
          "[hardware][model][sections][digest]") {
    for (const char* level : {"ok", "constrained"}) {
        INFO(level);
        CHECK(section_serves_rows(true, level, SectionFault::None));
        CHECK(section_serves_rows(true, level, SectionFault::Unverifiable));
        CHECK_FALSE(section_serves_rows(true, level, SectionFault::RowCount));
        CHECK_FALSE(section_serves_rows(true, level, SectionFault::Content));
        CHECK_FALSE(section_serves_rows(false, level, SectionFault::None)); // status-only kind
    }
    for (const char* level : {"unavailable", "permission_denied", "", "somethingnew"}) {
        INFO(level);
        for (const auto f : {SectionFault::None, SectionFault::Unverifiable})
            CHECK_FALSE(section_serves_rows(true, level, f));
    }
}

// The digest binds n_fields; the INSERT and SELECT use the parsed column list. They must agree for
// every kind (also a build-time static_assert in device_ci_kinds.hpp; this reports which kind).
TEST_CASE("registry: n_fields equals the column count of every table-backed kind",
          "[hardware][model][sections][digest]") {
    for (const auto& d : kDeviceCiSections) {
        INFO(d.section);
        const std::string_view cols{d.columns};
        if (d.table == nullptr) {
            CHECK(cols.empty());
            CHECK(d.n_fields == 0);
            continue;
        }
        const auto n = 1 + std::count(cols.begin(), cols.end(), ',');
        CHECK(n == d.n_fields);
    }
}
