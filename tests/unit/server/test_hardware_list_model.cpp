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

#include "hardware_list_model.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
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
