// Pure tests of the /crypto widget catalogue (crypto_widget_catalogue.hpp): the closed window
// set (ADR-0070 D13), the catalogue and default layout, layout validation, ISO-week math, the
// Yuzu-issued parameter parsers (REST clamps, MCP refuses) and the JSON shapers. No database.

#include "crypto_widget_catalogue.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace cw = yuzu::server::crypto_widgets;
using Catch::Matchers::ContainsSubstring;

namespace {

crypto_library::Params params(std::initializer_list<std::pair<const char*, const char*>> kv) {
    crypto_library::Params p;
    for (const auto& [k, v] : kv)
        p.emplace(k, v);
    return p;
}

} // namespace

TEST_CASE("crypto widgets: the window set is the D13 closed set, versioned", "[crypto][widgets]") {
    CHECK(cw::kWindowSetVersion == "crypto_widget_windows_v1");
    CHECK(std::vector<int>(cw::kExpiringWindowDays.begin(), cw::kExpiringWindowDays.end()) ==
          std::vector<int>{3, 7, 14, 21, 30, 60});
    CHECK(std::vector<int>(cw::kExpiredWindowDays.begin(), cw::kExpiredWindowDays.end()) ==
          std::vector<int>{7, 30, 60, 90});
    CHECK(std::vector<int>(cw::kRevokedWindowDays.begin(), cw::kRevokedWindowDays.end()) ==
          std::vector<int>{7, 30, 60, 90});
    CHECK(cw::kIssuedWindowDays == 7);
    CHECK(cw::kWeeklyBuckets == 26);
}

TEST_CASE("crypto widgets: the catalogue - unique ids, criteria, Yuzu-issued labelling",
          "[crypto][widgets]") {
    std::set<std::string_view> ids;
    int ca = 0;
    for (const auto& w : cw::catalogue()) {
        CHECK(ids.insert(w.id).second);
        CHECK_FALSE(w.criterion.empty());
        if (w.group == cw::WidgetGroup::kYuzuCa) {
            ++ca;
            CHECK(w.id.starts_with("ca."));
            // ADR-0070 D6: never a fleet certificate; every title says so.
            CHECK_THAT(std::string(w.title), ContainsSubstring("Yuzu-issued"));
            CHECK(w.securable == "Security");
            CHECK(w.operation == "Read");
        } else {
            CHECK(w.id.starts_with("lib."));
            CHECK(w.securable == "Inventory");
            CHECK(w.operation == "Read");
        }
        // D13 condition 1: never a bare grading word.
        for (const auto* bad : {"at risk", "weak", "stale"}) {
            CHECK_THAT(std::string(w.title), !ContainsSubstring(bad));
            CHECK_THAT(std::string(w.criterion), !ContainsSubstring(bad));
        }
    }
    CHECK(cw::catalogue().size() == 23);
    CHECK(ca == 18);
    for (const char* id : {"lib.devices_reporting", "lib.devices_with_library", "lib.families_matched",
                           "lib.families_table", "lib.devices_by_family", "ca.active",
                           "ca.expiring_3d", "ca.expiring_60d", "ca.expired_90d", "ca.revoked_7d",
                           "ca.issued_7d", "ca.issued_per_week", "ca.revoked_per_week"})
        CHECK(cw::find_widget(id) != nullptr);
    CHECK(cw::find_widget("ca.expiring_45d") == nullptr);
    const auto* w = cw::find_widget("ca.expiring_30d");
    REQUIRE(w);
    CHECK(w->ca_kind == CaCertKind::kExpiring);
    CHECK(w->days == 30);
    CHECK(w->drill == cw::WidgetDrill::kCaCertificates);
    CHECK(cw::find_widget("ca.issued_per_week")->drill == cw::WidgetDrill::kCaWeek);
    CHECK(cw::find_widget("lib.devices_by_family")->kind == cw::WidgetKind::kBar);
}

TEST_CASE("crypto widgets: the default layout", "[crypto][widgets]") {
    CHECK(cw::default_layout_ids() ==
          std::vector<std::string>{"lib.devices_reporting", "lib.devices_with_library",
                                   "lib.families_matched", "lib.devices_by_family",
                                   "lib.families_table", "ca.active", "ca.expiring_30d",
                                   "ca.revoked_30d", "ca.issued_per_week"});
    CHECK_FALSE(cw::layout_error(cw::default_layout_ids()));
}

TEST_CASE("crypto widgets: layout validation - bound, unknown, repeat; position not bytes",
          "[crypto][widgets]") {
    CHECK_FALSE(cw::layout_error(std::vector<std::string>{}));
    CHECK_FALSE(cw::layout_error(std::vector<std::string>{"ca.active", "lib.families_table"}));
    const auto unknown = cw::layout_error(std::vector<std::string>{"ca.active", "<script>"});
    REQUIRE(unknown);
    CHECK(*unknown == "widgets[1] is not a catalogue widget id");
    const auto repeat = cw::layout_error(std::vector<std::string>{"ca.active", "ca.active"});
    REQUIRE(repeat);
    CHECK_THAT(*repeat, ContainsSubstring("widgets[1] repeats"));
    std::vector<std::string> many;
    for (const auto& w : cw::catalogue())
        many.emplace_back(w.id);
    while (many.size() <= cw::kMaxLayoutWidgets)
        many.push_back("ca.active");
    const auto too_many = cw::layout_error(many);
    REQUIRE(too_many);
    CHECK_THAT(*too_many, ContainsSubstring("at most 64"));
    CHECK(cw::layout_error(std::vector<std::string>{std::string(200, 'a')}));
}

TEST_CASE("crypto widgets: known_ids drops retired ids and repeats, keeps order",
          "[crypto][widgets]") {
    CHECK(cw::known_ids(std::vector<std::string>{"ca.revoked_7d", "retired.widget", "ca.active",
                                                 "ca.revoked_7d"}) ==
          std::vector<std::string>{"ca.revoked_7d", "ca.active"});
}

TEST_CASE("crypto widgets: ISO weeks - Monday starts, ISO-year boundaries, round trip",
          "[crypto][widgets]") {
    // 1970-01-05 was the first Monday of the epoch.
    CHECK(cw::week_start_of(0) == -3 * 86400);
    CHECK(cw::week_start_of(4 * 86400) == 4 * 86400);
    CHECK(cw::week_start_of(4 * 86400 - 1) == -3 * 86400);
    // 2026-10-19 08:00 UTC (a Monday) -> its own 00:00.
    CHECK(cw::week_start_of(1792368000 + 8 * 3600) == 1792368000);
    CHECK(cw::iso_week_label(1792368000) == "2026-W43");
    // 2024-12-30 (Monday) belongs to 2025-W01; 2021-01-04 is 2021-W01; 2020 has a W53.
    CHECK(cw::iso_week_label(1735516800) == "2025-W01");
    CHECK(cw::iso_week_label(1609718400) == "2021-W01");
    CHECK(cw::parse_iso_week("2025-W01") == std::optional<std::int64_t>{1735516800});
    CHECK(cw::parse_iso_week("2026-W43") == std::optional<std::int64_t>{1792368000});
    CHECK(cw::parse_iso_week("2020-W53").has_value());
    CHECK_FALSE(cw::parse_iso_week("2021-W53")); // a 52-week year
    for (const char* bad : {"", "2026-W00", "2026-W54", "2026W43", "2026-w43", "26-W43",
                            "2026-W4", "+026-W43", "2026-W43 "})
        CHECK_FALSE(cw::parse_iso_week(bad));
    // Round trip across a year of weeks.
    for (std::int64_t ws = 1735516800; ws < 1735516800 + 60 * 7 * 86400; ws += 7 * 86400)
        CHECK(cw::parse_iso_week(cw::iso_week_label(ws)) == std::optional<std::int64_t>{ws});
}

TEST_CASE("crypto widgets: week_starts - 26 Mondays, oldest first, last contains as_of",
          "[crypto][widgets]") {
    const std::int64_t as_of = 1792368000 + 3 * 86400 + 5; // Thursday of 2026-W43
    const auto ws = cw::week_starts(as_of);
    REQUIRE(ws.size() == 26);
    CHECK(ws.back() == 1792368000);
    for (std::size_t i = 1; i < ws.size(); ++i)
        CHECK(ws[i] - ws[i - 1] == 7 * 86400);
    CHECK(cw::iso_week_label(ws.front()) == "2026-W18");
}

TEST_CASE("crypto widgets: iso8601_utc", "[crypto][widgets]") {
    CHECK(cw::iso8601_utc(0) == "1970-01-01T00:00:00Z");
    CHECK(cw::iso8601_utc(1792368000 + 8 * 3600 + 61) == "2026-10-19T08:01:01Z");
    CHECK(cw::iso8601_utc(-1) == "1969-12-31T23:59:59Z");
}

TEST_CASE("crypto widgets: criterion text names the window", "[crypto][widgets]") {
    CHECK(cw::criterion_text(CaCertKind::kExpiring, 30) == "Expiring within 30 days");
    CHECK(cw::criterion_text(CaCertKind::kExpired, 7) == "Expired in the last 7 days");
    CHECK(cw::criterion_text(CaCertKind::kRevoked, 90) == "Revoked in the last 90 days");
    CHECK(cw::criterion_text(CaCertKind::kIssued, 7) == "Issued in the last 7 days");
    CHECK(cw::criterion_text(CaCertKind::kIssuedWeek, 0, "2026-W40") == "Issued in ISO week 2026-W40");
}

TEST_CASE("crypto widgets: REST certificate params - required, closed windows, clamp",
          "[crypto][widgets]") {
    auto q = cw::parse_cert_params(params({{"kind", "expiring"}, {"days", "30"}}));
    REQUIRE(q);
    CHECK(q->kind == CaCertKind::kExpiring);
    CHECK(q->days == 30);
    CHECK(q->limit == cw::kCertPageDefault);
    CHECK(q->offset == 0);
    q = cw::parse_cert_params(params({{"kind", "active"}, {"limit", "100000"}, {"offset", "7"}}));
    REQUIRE(q);
    CHECK(q->limit == cw::kCertPageMax); // REST clamps
    CHECK(q->offset == 7);
    q = cw::parse_cert_params(params({{"kind", "active"}, {"limit", "0"}}));
    REQUIRE(q);
    CHECK(q->limit == 1);
    q = cw::parse_cert_params(params({{"kind", "issued_week"}, {"week", "2026-W43"}}));
    REQUIRE(q);
    CHECK(q->week_start == 1792368000);

    for (const auto& bad : std::vector<crypto_library::Params>{
             params({}),                                             // kind required
             params({{"kind", "weak"}}),                             // unknown kind
             params({{"kind", "expiring"}}),                         // days required
             params({{"kind", "expiring"}, {"days", "45"}}),         // outside the set
             params({{"kind", "expired"}, {"days", "3"}}),           // 3 is expiring-only
             params({{"kind", "active"}, {"days", "7"}}),            // days does not apply
             params({{"kind", "issued_week"}}),                      // week required
             params({{"kind", "issued_week"}, {"week", "2021-W53"}}),
             params({{"kind", "revoked"}, {"days", "7"}, {"week", "2026-W43"}}),
             params({{"kind", "active"}, {"limit", "-1"}}),
             params({{"kind", "active"}, {"limit", "+5"}}),
             params({{"kind", "active"}, {"offset", "1000001"}}),
         })
        CHECK_FALSE(cw::parse_cert_params(bad));
    crypto_library::Params rep;
    rep.emplace("kind", "active");
    rep.emplace("kind", "revoked");
    CHECK_FALSE(cw::parse_cert_params(rep));
}

TEST_CASE("crypto widgets: MCP certificate args are strict (refuse, never clamp)",
          "[crypto][widgets]") {
    using nlohmann::json;
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "expiring"}, {"days", 30}}));
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "revoked_week"}, {"week", "2026-W43"}}));
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "active"}, {"limit", 500}, {"offset", 0}}));
    for (const auto& bad : std::vector<json>{
             json::array(), json{}, json{{"kind", 3}}, json{{"kind", "weak"}},
             json{{"kind", "expiring"}}, json{{"kind", "expiring"}, {"days", "30"}},
             json{{"kind", "expiring"}, {"days", 45}}, json{{"kind", "active"}, {"days", 7}},
             json{{"kind", "issued_week"}, {"week", "2026-W99"}},
             json{{"kind", "active"}, {"limit", 501}}, json{{"kind", "active"}, {"limit", 0}},
             json{{"kind", "active"}, {"limit", 1.5}},
             json{{"kind", "active"}, {"offset", -1}},
             json{{"kind", "active"}, {"offset", 18446744073709551615ULL}}})
        CHECK(cw::strict_cert_args_error(bad));
}

TEST_CASE("crypto widgets: layout args and body are strict", "[crypto][widgets]") {
    using nlohmann::json;
    CHECK_FALSE(cw::strict_layout_args_error(json{{"widgets", json::array({"ca.active"})}}));
    CHECK_FALSE(cw::strict_layout_args_error(json{{"widgets", json::array()}}));
    for (const auto& bad : std::vector<json>{json::array(), json{}, json{{"widgets", "ca.active"}},
                                             json{{"widgets", json::array({1})}},
                                             json{{"widgets", json::array()}, {"user", "bob"}}})
        CHECK(cw::strict_layout_args_error(bad));
    auto ids = cw::parse_layout_body(R"({"widgets":["ca.active","lib.families_table"]})");
    REQUIRE(ids);
    CHECK(*ids == std::vector<std::string>{"ca.active", "lib.families_table"});
    CHECK_FALSE(cw::parse_layout_body("not json"));
    CHECK_FALSE(cw::parse_layout_body("[]"));
    CHECK_FALSE(cw::parse_layout_body(R"({"widgets":["a"],"username":"bob"})"));
}

TEST_CASE("crypto widgets: widgets_json probes each permission pair once", "[crypto][widgets]") {
    std::vector<std::pair<std::string, std::string>> asked;
    const auto j = cw::widgets_json([&](std::string_view s, std::string_view o) {
        asked.emplace_back(s, o);
        return s == "Inventory";
    });
    CHECK(asked.size() == 2);
    CHECK(j["window_set"] == "crypto_widget_windows_v1");
    CHECK(j["max_layout_widgets"] == 64);
    CHECK(j["default_layout"].size() == 9);
    for (const auto& w : j["widgets"]) {
        if (w["securable"] == "Inventory")
            CHECK(w["available"] == true);
        else
            CHECK(w["available"] == false);
    }
    // An unwired probe is "not available", never "available".
    const auto none = cw::widgets_json({});
    for (const auto& w : none["widgets"])
        CHECK(w["available"] == false);
}

TEST_CASE("crypto widgets: ca_stats_json and ca_page_json carry as_of and the windows",
          "[crypto][widgets]") {
    CaCertStats s;
    s.as_of = 1792368000;
    s.active = 4;
    s.expiring = {{30, 2}};
    s.issued = {7, 1};
    s.weeks = {{1792368000, "2026-W43", 1, 0}};
    const auto j = cw::ca_stats_json(s);
    CHECK(j["scope"] == "yuzu_issued");
    CHECK(j["as_of"] == 1792368000);
    CHECK(j["as_of_iso"] == "2026-10-19T00:00:00Z");
    CHECK(j["active"]["count"] == 4);
    CHECK(j["expiring"][0]["days"] == 30);
    CHECK(j["expiring"][0]["criterion"] == "Expiring within 30 days");
    CHECK(j["issued"]["days"] == 7);
    CHECK(j["weeks"][0]["week"] == "2026-W43");

    CaCertPage p;
    p.query.kind = CaCertKind::kRevoked;
    p.query.days = 7;
    p.query.limit = 2;
    p.query.offset = 4;
    p.as_of = 1792368000;
    p.total = 9;
    p.truncated = true;
    p.rows = {{"AA", "CN=a", "agent", 1, 2, "revoked", 3}, {"BB", "CN=b", "agent", 1, 2, "active", 0}};
    const auto pj = cw::ca_page_json(p);
    CHECK(pj["kind"] == "revoked");
    CHECK(pj["days"] == 7);
    CHECK(pj["week"].is_null());
    CHECK(pj["criterion"] == "Revoked in the last 7 days");
    CHECK(pj["next_offset"] == 6);
    CHECK(pj["certificates"][0]["revoked_at"] == 3);
    CHECK(pj["certificates"][1]["revoked_at"].is_null());
    p.truncated = false;
    CHECK(cw::ca_page_json(p)["next_offset"].is_null());
}
