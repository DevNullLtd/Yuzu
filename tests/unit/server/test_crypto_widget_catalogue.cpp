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
    CHECK(cw::kWeeklyBuckets == 52); // owner ruling 2026-10-19: 52 ISO weeks, current one partial
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
            // ADR-0070 R2: the counts are Inventory:Read, withheld from a confined caller.
            CHECK(w.securable == "Inventory");
            CHECK(w.operation == "Read");
            CHECK(w.gate == cw::WidgetGate::kFleetWideOnly);
            // A windowed criterion is criterion_text word for word (one wording, every surface).
            if (cw::kind_takes_days(w.ca_kind) && w.ca_kind != CaCertKind::kRevoked)
                CHECK(std::string(w.criterion) == cw::criterion_text(w.ca_kind, w.days));
        } else {
            CHECK(w.id.starts_with("lib."));
            CHECK(w.securable == "Inventory");
            CHECK(w.operation == "Read");
            CHECK(w.gate == cw::WidgetGate::kFleetRead);
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
    CHECK(cw::unknown_ids(std::vector<std::string>{"new.widget", "ca.active", "new.widget",
                                                   "other.new"}) ==
          std::vector<std::string>{"new.widget", "other.new"});
}

TEST_CASE("crypto widgets: a save keeps another version's ids, after the caller's, capped (B7)",
          "[crypto][widgets]") {
    const std::vector<std::string> stored{"ca.active", "future.a", "lib.families_table", "future.b"};
    auto m = cw::merge_preserved(std::vector<std::string>{"ca.revoked_7d"}, stored, 64);
    CHECK(m.ids == std::vector<std::string>{"ca.revoked_7d", "future.a", "future.b"});
    CHECK(m.kept == 2);
    // The cap never cuts the caller's own ids.
    m = cw::merge_preserved(std::vector<std::string>{"ca.active", "ca.issued_7d"}, stored, 3);
    CHECK(m.ids == std::vector<std::string>{"ca.active", "ca.issued_7d", "future.a"});
    CHECK(m.kept == 1);
    CHECK(cw::is_default_layout(cw::default_layout_ids(), 0));
    CHECK_FALSE(cw::is_default_layout(cw::default_layout_ids(), 1));
    CHECK_FALSE(cw::is_default_layout(std::vector<std::string>{"ca.active"}, 0));
}

TEST_CASE("crypto widgets: AccessMemo asks each (gate, securable, op) once; fleet_access",
          "[crypto][widgets]") {
    int asked = 0;
    cw::AccessMemo memo([&](cw::WidgetGate g, std::string_view, std::string_view) {
        ++asked;
        return g == cw::WidgetGate::kGlobal ? cw::Access::kRefused : cw::Access::kAvailable;
    });
    for (const auto& w : cw::catalogue()) {
        (void)memo.widget(w);
        (void)memo.drill(w);
    }
    CHECK(asked == 3); // fleet_read, fleet_wide_only, global (the CA drill)
    CHECK(cw::fleet_access(cw::WidgetGate::kFleetRead, true, true, false) == cw::Access::kAvailable);
    CHECK(cw::fleet_access(cw::WidgetGate::kFleetWideOnly, true, true, false) ==
          cw::Access::kConfined);
    CHECK(cw::fleet_access(cw::WidgetGate::kFleetWideOnly, true, false, false) ==
          cw::Access::kAvailable);
    CHECK(cw::fleet_access(cw::WidgetGate::kFleetWideOnly, false, false, true) ==
          cw::Access::kDegraded);
    CHECK(cw::fleet_access(cw::WidgetGate::kFleetRead, false, false, false) == cw::Access::kRefused);
    cw::AccessMemo none({});
    CHECK(none.widget(cw::catalogue()[0]) == cw::Access::kRefused);
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

TEST_CASE("crypto widgets: week_starts - 52 Mondays, oldest first, last contains as_of",
          "[crypto][widgets]") {
    const std::int64_t as_of = 1792368000 + 3 * 86400 + 5; // Thursday of 2026-W43
    const auto ws = cw::week_starts(as_of);
    REQUIRE(ws.size() == 52);
    CHECK(ws.back() == 1792368000);
    for (std::size_t i = 1; i < ws.size(); ++i)
        CHECK(ws[i] - ws[i - 1] == 7 * 86400);
    CHECK(cw::iso_week_label(ws.front()) == "2025-W44");
}

TEST_CASE("crypto widgets: week_starts across a year boundary - 2027-W02 back through 2026-W53",
          "[crypto][widgets]") {
    // 2027-W02 starts Monday 2027-01-11; 2026 has 53 ISO weeks (2026-12-28 is 2026-W53).
    const auto w02 = cw::parse_iso_week("2027-W02");
    REQUIRE(w02);
    const auto ws = cw::week_starts(*w02 + 86400);
    REQUIRE(ws.size() == 52);
    CHECK(cw::iso_week_label(ws[51]) == "2027-W02");
    CHECK(cw::iso_week_label(ws[50]) == "2027-W01");
    CHECK(cw::iso_week_label(ws[49]) == "2026-W53");
    CHECK(cw::iso_week_label(ws[48]) == "2026-W52");
    CHECK(cw::parse_iso_week("2026-W53").has_value());
    CHECK_FALSE(cw::parse_iso_week("2027-W53").has_value());
}

TEST_CASE("crypto widgets: iso8601_utc", "[crypto][widgets]") {
    CHECK(cw::iso8601_utc(0) == "1970-01-01T00:00:00Z");
    CHECK(cw::iso8601_utc(1792368000 + 8 * 3600 + 61) == "2026-10-19T08:01:01Z");
    CHECK(cw::iso8601_utc(-1) == "1969-12-31T23:59:59Z");
}

TEST_CASE("crypto widgets: criterion text states the predicate (RFC 5280 boundary, buckets)",
          "[crypto][widgets]") {
    CHECK(cw::criterion_text(CaCertKind::kExpiring, 30) ==
          "Status active, notAfter from as_of through as_of + 30 days (valid through notAfter, "
          "inclusive)");
    // Owner ruling 2026-10-19: expired (like expiring) covers status active only.
    CHECK(cw::criterion_text(CaCertKind::kExpired, 7) ==
          "Status active, notAfter from as_of - 7 days up to, not including, as_of");
    CHECK_THAT(cw::criterion_text(CaCertKind::kIssued, 7), ContainsSubstring("excluding unpublished"));
    CHECK_THAT(cw::criterion_text(CaCertKind::kRevoked, 90, {}, RevokedBucket::kSuperseded),
               ContainsSubstring("superseded"));
    CHECK_THAT(cw::criterion_text(CaCertKind::kIssuedWeek, 0, "2026-W40"),
               ContainsSubstring("ISO week 2026-W40"));
    CHECK(cw::rule_id(CaCertKind::kRevoked, RevokedBucket::kOther) == "yuzu_ca_revoked_other");
    CHECK(cw::rule_id(CaCertKind::kExpiring) == "yuzu_ca_expiring");
    for (const auto k : {CaCertKind::kActive, CaCertKind::kExpiring, CaCertKind::kExpired,
                         CaCertKind::kRevoked, CaCertKind::kIssued}) {
        const auto t = cw::criterion_text(k, 7);
        for (const auto* bad : {"at risk", "weak", "stale", "healthy"})
            CHECK_THAT(t, !ContainsSubstring(bad));
    }
    // The criterion and the predicate agree on the edges (the one boundary definition).
    constexpr std::int64_t as_of = 1792368000;
    CHECK(cw::expiring_within(as_of, as_of, 3));
    CHECK_FALSE(cw::expired_within(as_of, as_of, 7));
    CHECK(cw::expired_within(as_of - 7 * 86400, as_of, 7));
}

namespace {
constexpr std::int64_t kNow = 1792368000;
} // namespace

TEST_CASE("crypto widgets: certificate params - required, closed windows, refuse out of range",
          "[crypto][widgets]") {
    auto q = cw::parse_cert_params(params({{"kind", "expiring"}, {"days", "30"}}), kNow);
    REQUIRE(q);
    CHECK(q->kind == CaCertKind::kExpiring);
    CHECK(q->days == 30);
    CHECK(q->limit == cw::kCertPageDefault);
    CHECK(q->offset == 0);
    CHECK_FALSE(q->as_of.has_value());
    q = cw::parse_cert_params(params({{"kind", "active"}, {"limit", "500"}, {"offset", "7"}}), kNow);
    REQUIRE(q);
    CHECK(q->limit == 500);
    CHECK(q->offset == 7);
    q = cw::parse_cert_params(params({{"kind", "issued_week"}, {"week", "2026-W43"}}), kNow);
    REQUIRE(q);
    CHECK(q->week_start == 1792368000);
    q = cw::parse_cert_params(
        params({{"kind", "revoked"}, {"days", "7"}, {"bucket", "unpublished"}, {"as_of", "1792367000"}}),
        kNow);
    REQUIRE(q);
    CHECK(q->bucket == RevokedBucket::kUnpublished);
    CHECK(q->as_of == std::optional<std::int64_t>{1792367000});

    // Table-driven: every malformed parameter names itself in the message.
    struct Bad {
        crypto_library::Params p;
        const char* names;
    };
    const std::vector<Bad> bad{
        {params({}), "kind"},
        {params({{"kind", "weak"}}), "kind"},
        {params({{"kind", "expiring"}}), "days"},
        {params({{"kind", "expiring"}, {"days", "45"}}), "days"},
        {params({{"kind", "expiring"}, {"days", "abc"}}), "days"},
        {params({{"kind", "expiring"}, {"days", "0"}}), "days"},
        {params({{"kind", "expired"}, {"days", "31"}}), "days"},
        {params({{"kind", "expired"}, {"days", "3"}}), "days"},
        {params({{"kind", "active"}, {"days", "7"}}), "days"},
        {params({{"kind", "issued_week"}, {"days", "7"}, {"week", "2026-W43"}}), "days"},
        {params({{"kind", "issued_week"}}), "week"},
        {params({{"kind", "issued_week"}, {"week", "2026-W00"}}), "week"},
        {params({{"kind", "issued_week"}, {"week", "2026-W54"}}), "week"},
        {params({{"kind", "issued_week"}, {"week", "2027-W53"}}), "week"},
        {params({{"kind", "revoked"}, {"days", "7"}, {"week", "2026-W43"}}), "week"},
        {params({{"kind", "active"}, {"bucket", "other"}}), "bucket"},
        {params({{"kind", "revoked"}, {"days", "7"}, {"bucket", "compromise"}}), "bucket"},
        {params({{"kind", "active"}, {"limit", "0"}}), "limit"},
        {params({{"kind", "active"}, {"limit", "-1"}}), "limit"},
        {params({{"kind", "active"}, {"limit", "abc"}}), "limit"},
        {params({{"kind", "active"}, {"limit", "501"}}), "limit"},
        {params({{"kind", "active"}, {"limit", "+5"}}), "limit"},
        {params({{"kind", "active"}, {"offset", "x"}}), "offset"},
        {params({{"kind", "active"}, {"offset", "1000001"}}), "offset"},
        {params({{"kind", "active"}, {"offset", "99999999999999999999"}}), "offset"},
        {params({{"kind", "active"}, {"as_of", "abc"}}), "as_of"},
        {params({{"kind", "active"}, {"as_of", "1792369000"}}), "as_of"}, // future (> now + 300 s)
        {params({{"kind", "active"}, {"as_of", "1791000000"}}), "as_of"}, // more than 7 days old
    };
    for (const auto& b : bad) {
        const auto r = cw::parse_cert_params(b.p, kNow);
        REQUIRE_FALSE(r);
        INFO(r.error());
        CHECK_THAT(r.error(), ContainsSubstring(b.names));
    }
    crypto_library::Params rep;
    rep.emplace("kind", "active");
    rep.emplace("kind", "revoked");
    CHECK_FALSE(cw::parse_cert_params(rep, kNow));
    // A small replica clock skew is accepted on a pinned as_of.
    CHECK(cw::parse_cert_params(params({{"kind", "active"}, {"as_of", "1792368200"}}), kNow));
    CHECK(cw::has_cert_filter_params(params({{"bucket", "other"}})));
    CHECK_FALSE(cw::has_cert_filter_params(params({{"limit", "5"}, {"offset", "0"}})));
}

TEST_CASE("crypto widgets: MCP certificate args are strict (refuse, never clamp)",
          "[crypto][widgets]") {
    using nlohmann::json;
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "expiring"}, {"days", 30}}, kNow));
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "revoked_week"}, {"week", "2026-W43"},
                                                {"bucket", "other"}},
                                           kNow));
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "active"}, {"limit", 500}, {"offset", 0},
                                                {"as_of", kNow - 60}},
                                           kNow));
    for (const auto& bad : std::vector<json>{
             json::array(), json{}, json{{"kind", 3}}, json{{"kind", "weak"}},
             json{{"kind", "expiring"}}, json{{"kind", "expiring"}, {"days", "30"}},
             json{{"kind", "expiring"}, {"days", 45}}, json{{"kind", "active"}, {"days", 7}},
             json{{"kind", "issued_week"}, {"week", "2026-W99"}},
             json{{"kind", "active"}, {"bucket", "other"}},
             json{{"kind", "revoked"}, {"days", 7}, {"bucket", 1}},
             json{{"kind", "active"}, {"as_of", kNow + 3600}},
             json{{"kind", "active"}, {"as_of", "1"}},
             json{{"kind", "active"}, {"limit", 501}}, json{{"kind", "active"}, {"limit", 0}},
             json{{"kind", "active"}, {"limit", 1.5}},
             json{{"kind", "active"}, {"offset", -1}},
             json{{"kind", "active"}, {"offset", 18446744073709551615ULL}}})
        CHECK(cw::strict_cert_args_error(bad, kNow));
}

TEST_CASE("crypto widgets: layout args and body are strict", "[crypto][widgets]") {
    using nlohmann::json;
    CHECK_FALSE(cw::strict_layout_args_error(json{{"widgets", json::array({"ca.active"})}}));
    CHECK_FALSE(cw::strict_layout_args_error(json{{"widgets", json::array()}, {"expected_version", 0}}));
    for (const auto& bad : std::vector<json>{json::array(), json{}, json{{"widgets", "ca.active"}},
                                             json{{"widgets", json::array({1})}},
                                             json{{"widgets", json::array()}, {"user", "bob"}},
                                             json{{"widgets", json::array()}, {"expected_version", -1}},
                                             json{{"widgets", json::array()}, {"expected_version", "1"}}})
        CHECK(cw::strict_layout_args_error(bad));
    auto body = cw::parse_layout_body(R"({"widgets":["ca.active","lib.families_table"],"expected_version":4})");
    REQUIRE(body);
    CHECK(body->widgets == std::vector<std::string>{"ca.active", "lib.families_table"});
    CHECK(body->expected_version == std::optional<std::int64_t>{4});
    CHECK_FALSE(cw::parse_layout_body(R"({"widgets":[]})")->expected_version.has_value());
    CHECK_FALSE(cw::parse_layout_body("not json"));
    CHECK_FALSE(cw::parse_layout_body("[]"));
    CHECK_FALSE(cw::parse_layout_body(R"({"widgets":["a"],"username":"bob"})"));
}

TEST_CASE("crypto widgets: widgets_json - availability per gate class, drill availability",
          "[crypto][widgets]") {
    int asked = 0;
    cw::AccessMemo memo([&](cw::WidgetGate g, std::string_view, std::string_view) {
        ++asked;
        switch (g) {
        case cw::WidgetGate::kFleetRead:
            return cw::Access::kAvailable;
        case cw::WidgetGate::kFleetWideOnly:
            return cw::Access::kConfined;
        case cw::WidgetGate::kGlobal:
            break;
        }
        return cw::Access::kRefused;
    });
    const auto j = cw::widgets_json(memo);
    CHECK(asked == 3);
    CHECK(j["window_set"] == "crypto_widget_windows_v1");
    CHECK(j["max_layout_widgets"] == 64);
    CHECK(j["default_layout"].size() == 9);
    CHECK(j["scope_note"] == std::string(cw::kScopeNote));
    for (const auto& w : j["widgets"]) {
        if (w["gate"] == "fleet_read") {
            CHECK(w["available"] == true);
        } else {
            CHECK(w["gate"] == "fleet_wide_only");
            CHECK(w["available"] == false);
            CHECK(w["availability"] == "confined");
            CHECK(w["drill_securable"] == "Security");
            CHECK(w["drill_available"] == false);
        }
    }
    cw::AccessMemo none({});
    for (const auto& w : cw::widgets_json(none)["widgets"])
        CHECK(w["available"] == false);
}

TEST_CASE("crypto widgets: ca_stats_json - D13 condition 1 beside every count, three buckets",
          "[crypto][widgets]") {
    CaCertStats s;
    s.as_of = 1792368000;
    s.active = 4;
    s.expiring = {{30, 2}};
    s.revoked = {{7, 1, 2, 3}};
    s.issued = {7, 1};
    CaWeekCount wk;
    wk.week_start = 1792368000;
    wk.label = "2026-W43";
    wk.issued = 1;
    wk.revoked_other = 5;
    wk.partial = true;
    s.weeks = {wk};
    const auto j = cw::ca_stats_json(s);
    CHECK(j["scope"] == "yuzu_issued");
    CHECK(j["as_of"] == 1792368000);
    CHECK(j["as_of_iso"] == "2026-10-19T00:00:00Z");
    CHECK(j["active"]["count"] == 4);
    CHECK_FALSE(j.contains("expiring"));
    CHECK_FALSE(j.contains("expired"));
    CHECK_FALSE(j.contains("revoked"));
    const auto& e = j["expiring_within_days"][0];
    CHECK(e["threshold_days"] == 30);
    CHECK(e["rule_id"] == "yuzu_ca_expiring");
    CHECK(e["rule_set_version"] == "crypto_widget_windows_v1");
    CHECK(e["as_of"] == 1792368000);
    CHECK(e["criterion"] == cw::criterion_text(CaCertKind::kExpiring, 30));
    REQUIRE(j["revoked_within_days"].size() == 3);
    CHECK(j["revoked_within_days"][0]["bucket"] == "superseded");
    CHECK(j["revoked_within_days"][0]["count"] == 1);
    CHECK(j["revoked_within_days"][1]["count"] == 2);
    CHECK(j["revoked_within_days"][2]["count"] == 3);
    CHECK(j["issued_within_days"]["threshold_days"] == 7);
    CHECK(j["weeks"][0]["partial"] == true);
    CHECK(j["weeks"][0]["issued"]["week"] == "2026-W43");
    CHECK(j["weeks"][0]["revoked"][2]["count"] == 5);
}

TEST_CASE("crypto widgets: ca_items_json / ca_filter_json - /ca/issued row shape and the filter",
          "[crypto][widgets]") {
    CaCertPage p;
    p.query.kind = CaCertKind::kRevoked;
    p.query.days = 7;
    p.query.bucket = RevokedBucket::kOther;
    p.as_of = 1792368000;
    p.total = 9;
    p.rows = {{"AA", "CN=a", "", "agent", 1, 2, "revoked", 3, "operator-supplied: superseded", "", ""}};
    const auto items = cw::ca_items_json(p);
    CHECK(items[0]["revocation_reason"] == "operator-supplied: superseded");
    CHECK(items[0]["revoked_at"] == 3);
    const auto f = cw::ca_filter_json(p);
    CHECK(f["kind"] == "revoked");
    CHECK(f["days"] == 7);
    CHECK(f["bucket"] == "other");
    CHECK(f["rule_id"] == "yuzu_ca_revoked_other");
    CHECK(f["as_of"] == 1792368000);
    CHECK(f["total"] == 9);
    CHECK(f["week"].is_null());
}
