// Pure tests of the /crypto widget catalogue (crypto_widget_catalogue.hpp): the closed window
// set (ADR-0070 D13), the catalogue and default layout, layout validation, ISO-week math, the
// Yuzu-issued parameter parsers (REST clamps, MCP refuses) and the JSON shapers. No database.

#include "crypto_widget_catalogue.hpp"

#include "authz_gates.hpp"
#include "crypto_access.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <expected>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
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
    auto q = cw::parse_cert_params(params({{"kind", "expiring"}, {"days", "30"}}));
    REQUIRE(q);
    CHECK(q->kind == CaCertKind::kExpiring);
    CHECK(q->days == 30);
    CHECK(q->limit == cw::kCertPageDefault);
    CHECK(q->cursor.empty());
    CHECK_FALSE(q->as_of.has_value());
    q = cw::parse_cert_params(params({{"kind", "active"}, {"limit", "500"}, {"cursor", "c1:x"}}));
    REQUIRE(q);
    CHECK(q->limit == 500);
    CHECK(q->cursor == "c1:x"); // decoded and bound to the filter by the read, not here
    q = cw::parse_cert_params(params({{"kind", "issued_week"}, {"week", "2026-W43"}}));
    REQUIRE(q);
    CHECK(q->week_start == 1792368000);
    q = cw::parse_cert_params(
        params({{"kind", "revoked"}, {"days", "7"}, {"bucket", "unpublished"}, {"as_of", "1792367000"}}));
    REQUIRE(q);
    CHECK(q->bucket == RevokedBucket::kUnpublished);
    CHECK(q->as_of == std::optional<std::int64_t>{1792367000});
    // M2: the as_of WINDOW is no longer judged on this replica's clock here - the read checks it
    // against the database clock - so any non-negative integer parses.
    CHECK(cw::parse_cert_params(params({{"kind", "active"}, {"as_of", "1"}})));

    // Table-driven: every malformed parameter names itself in the message.
    struct Bad {
        crypto_library::Params p;
        const char* names;
    };
    const std::string long_cursor(cw::kCertCursorMaxBytes + 1, 'a');
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
        // H2: the filtered list pages by cursor only.
        {params({{"kind", "active"}, {"offset", "0"}}), "offset"},
        {params({{"kind", "active"}, {"offset", "7"}}), "offset"},
        {params({{"kind", "active"}, {"cursor", ""}}), "cursor"},
        {params({{"kind", "active"}, {"cursor", long_cursor.c_str()}}), "cursor"},
        {params({{"kind", "active"}, {"as_of", "abc"}}), "as_of"},
        {params({{"kind", "active"}, {"as_of", "-5"}}), "as_of"},
    };
    for (const auto& b : bad) {
        const auto r = cw::parse_cert_params(b.p);
        REQUIRE_FALSE(r);
        INFO(r.error());
        CHECK_THAT(r.error(), ContainsSubstring(b.names));
    }
    crypto_library::Params rep;
    rep.emplace("kind", "active");
    rep.emplace("kind", "revoked");
    CHECK_FALSE(cw::parse_cert_params(rep));
    CHECK(cw::has_cert_filter_params(params({{"bucket", "other"}})));
    CHECK(cw::has_cert_filter_params(params({{"cursor", "c1:x"}})));
    CHECK_FALSE(cw::has_cert_filter_params(params({{"limit", "5"}, {"offset", "0"}})));
}

TEST_CASE("crypto widgets: MCP certificate args are strict (refuse, never clamp)",
          "[crypto][widgets]") {
    using nlohmann::json;
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "expiring"}, {"days", 30}}));
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "revoked_week"}, {"week", "2026-W43"},
                                                {"bucket", "other"}}));
    CHECK_FALSE(cw::strict_cert_args_error(json{{"kind", "active"}, {"limit", 500},
                                                {"as_of", kNow - 60}, {"cursor", "c1:x"}}));
    for (const auto& bad : std::vector<json>{
             json::array(), json{}, json{{"kind", 3}}, json{{"kind", "weak"}},
             json{{"kind", "expiring"}}, json{{"kind", "expiring"}, {"days", "30"}},
             json{{"kind", "expiring"}, {"days", 45}}, json{{"kind", "active"}, {"days", 7}},
             json{{"kind", "issued_week"}, {"week", "2026-W99"}},
             json{{"kind", "active"}, {"bucket", "other"}},
             json{{"kind", "revoked"}, {"days", 7}, {"bucket", 1}},
             json{{"kind", "active"}, {"as_of", -1}},
             json{{"kind", "active"}, {"as_of", "1"}},
             json{{"kind", "active"}, {"limit", 501}}, json{{"kind", "active"}, {"limit", 0}},
             json{{"kind", "active"}, {"limit", 1.5}},
             json{{"kind", "active"}, {"offset", 0}},
             json{{"kind", "active"}, {"offset", -1}},
             json{{"kind", "active"}, {"cursor", ""}},
             json{{"kind", "active"}, {"cursor", 3}},
             json{{"kind", "active"}, {"cursor", std::string(cw::kCertCursorMaxBytes + 1, 'a')}}})
        CHECK(cw::strict_cert_args_error(bad));
}

TEST_CASE("crypto widgets: the certificate cursor is opaque, filter-bound and strict",
          "[crypto][widgets]") {
    // H2: a cursor carries (sort key, serial_hex, as_of) and is bound to kind/days/week/bucket.
    CaCertQuery q;
    q.kind = CaCertKind::kExpiring;
    q.days = 30;
    const auto fp = cw::cert_cursor_fingerprint(q);
    const cw::CertCursor at{1792400000, "0A1b", 1792368000};
    const auto tok = cw::encode_cert_cursor(at, fp);
    CHECK(tok.starts_with("c1:"));
    const auto back = cw::decode_cert_cursor(tok, fp);
    REQUIRE(back);
    CHECK(back->sort_key == at.sort_key);
    CHECK(back->serial_hex == at.serial_hex);
    CHECK(back->as_of == at.as_of);
    // Another filter: refused with the restart advice.
    CaCertQuery other = q;
    other.days = 60;
    const auto mismatch = cw::decode_cert_cursor(tok, cw::cert_cursor_fingerprint(other));
    REQUIRE_FALSE(mismatch);
    CHECK_THAT(mismatch.error(), ContainsSubstring("cursor"));
    CHECK_THAT(mismatch.error(), ContainsSubstring("without a cursor"));
    // The bucket is part of the binding (nullopt differs from every bucket).
    CaCertQuery rv;
    rv.kind = CaCertKind::kRevoked;
    rv.days = 7;
    CaCertQuery rv_b = rv;
    rv_b.bucket = RevokedBucket::kOther;
    CHECK(cw::cert_cursor_fingerprint(rv) != cw::cert_cursor_fingerprint(rv_b));
    // Tampering: every edit of a canonical token is refused as "invalid cursor".
    std::vector<std::string> tampered{"", "c1:", "c2" + tok.substr(2), tok + "A", tok.substr(0, tok.size() - 1),
                                      "c1:" + std::string(16, 'z') + tok.substr(19)};
    std::string flip = tok;
    flip.back() = flip.back() == 'A' ? 'B' : 'A';
    tampered.push_back(flip);
    // A non-hex serial and a negative key, correctly framed and encoded, are refused too.
    tampered.push_back(cw::encode_cert_cursor({1, "zz", 2}, fp));
    tampered.push_back(cw::encode_cert_cursor({-1, "AA", 2}, fp));
    for (const auto& t : tampered) {
        INFO(t);
        const auto r = cw::decode_cert_cursor(t, fp);
        REQUIRE_FALSE(r);
        CHECK_THAT(r.error(), ContainsSubstring("cursor"));
    }
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
    CHECK(e["threshold"] == 30);
    CHECK(e["rule_id"] == "yuzu_ca_expiring");
    CHECK(e["rule_set_version"] == "crypto_widget_windows_v1");
    CHECK(e["as_of"] == 1792368000);
    CHECK(e["criterion"] == cw::criterion_text(CaCertKind::kExpiring, 30));
    REQUIRE(j["revoked_within_days"].size() == 3);
    CHECK(j["revoked_within_days"][0]["bucket"] == "superseded");
    CHECK(j["revoked_within_days"][0]["count"] == 1);
    CHECK(j["revoked_within_days"][1]["count"] == 2);
    CHECK(j["revoked_within_days"][2]["count"] == 3);
    CHECK(j["issued_within_days"]["threshold"] == 7);
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

// ── M4: the /crypto availability composition (ServerImpl::crypto_access) ─────

namespace {
// The production Auth is AuthRoutes; this fake has its two probe members, counting calls.
struct FakeAuthority {
    std::optional<std::unordered_set<std::string>> visible; // nullopt = unconfined (TOP)
    [[nodiscard]] const auto& visible_for_query() const { return visible; }
};
struct FakeAuth {
    bool permitted{false};
    std::expected<FakeAuthority, authz::GateFailure> probe{FakeAuthority{}};
    int fail_status{403};
    int has_permission_calls{0};
    int probe_calls{0};
    std::vector<std::pair<std::string, std::string>> probed;
    bool has_permission(const httplib::Request&, const std::string&, const std::string&) {
        ++has_permission_calls;
        return permitted;
    }
    std::expected<FakeAuthority, authz::GateFailure>
    probe_fleet_read(const httplib::Request&, httplib::Response& res, const std::string& sec,
                     const std::string& op) {
        ++probe_calls;
        probed.emplace_back(sec, op);
        if (!probe)
            res.status = fail_status;
        return probe;
    }
};
} // namespace

TEST_CASE("crypto widgets: audit_detail_inventory - the unfiltered list's success row",
          "[crypto][widgets]") {
    namespace cw = yuzu::server::crypto_widgets;
    CHECK(cw::audit_detail_inventory("c-1", 3, 200, 0, false) ==
          "cid=c-1 inventory rows=3 limit=200 offset=0 has_more=false");
    CHECK(cw::audit_detail_inventory("", 5, 5, 10, true) ==
          "inventory rows=5 limit=5 offset=10 has_more=true");
}

TEST_CASE("crypto widgets: audit_detail_with_standing - only a served standing is named, never a "
          "false available",
          "[crypto][widgets]") {
    namespace cw = yuzu::server::crypto_widgets;
    CHECK(cw::audit_detail_with_standing("x", cw::Access::kAvailable) == "x standing=available");
    // Only kAvailable is ever served. kRefused, kConfined and kDegraded are answered before any
    // success row; if one ever reached a row it must not read as the real `available` standing.
    CHECK(cw::audit_detail_with_standing("x", cw::Access::kRefused) == "x standing=unexpected");
    CHECK(cw::audit_detail_with_standing("x", cw::Access::kConfined) == "x standing=unexpected");
    CHECK(cw::audit_detail_with_standing("x", cw::Access::kDegraded) == "x standing=unexpected");
}

TEST_CASE("crypto widgets: the withheld audit token and message tell a confined caller from a "
          "caller with no grant",
          "[crypto][widgets]") {
    namespace cw = yuzu::server::crypto_widgets;
    CHECK(cw::audit_detail_ca_withheld("", cw::Access::kConfined).ends_with("withheld=confined"));
    CHECK(cw::audit_detail_ca_withheld("", cw::Access::kRefused).ends_with("withheld=refused"));
    CHECK(cw::audit_detail_ca_withheld("c-1", cw::Access::kRefused).starts_with("cid=c-1 "));
    // A standing that is never withheld must not read as a real withheld reason.
    CHECK(cw::audit_detail_ca_withheld("", cw::Access::kAvailable).ends_with("withheld=unexpected"));
    CHECK(cw::audit_detail_ca_withheld("", cw::Access::kDegraded).ends_with("withheld=unexpected"));
    CHECK(cw::withheld_message(cw::Access::kConfined) == cw::kConfinedWithheldMessage);
    CHECK(cw::withheld_message(cw::Access::kRefused) == cw::kRefusedWithheldMessage);
    CHECK(cw::kRefusedWithheldMessage != cw::kConfinedWithheldMessage);
}

TEST_CASE("crypto_access_for: a confined Inventory:Read holder - kConfined for fleet-wide-only, "
          "kAvailable for fleet-read",
          "[crypto][widgets][authz]") {
    httplib::Request req;
    FakeAuth auth;
    auth.probe = FakeAuthority{std::unordered_set<std::string>{"agent-1"}}; // confined
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kFleetWideOnly, "Inventory", "Read") ==
          cw::Access::kConfined);
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kFleetRead, "Inventory", "Read") ==
          cw::Access::kAvailable);
    CHECK(auth.probe_calls == 2);
    CHECK(auth.has_permission_calls == 0);
    CHECK(auth.probed[0] == std::pair<std::string, std::string>{"Inventory", "Read"});
    // An unconfined holder sees both.
    auth.probe = FakeAuthority{};
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kFleetWideOnly, "Inventory", "Read") ==
          cw::Access::kAvailable);
}

TEST_CASE("crypto_access_for: a degraded probe is kDegraded, a refusal kRefused",
          "[crypto][widgets][authz]") {
    httplib::Request req;
    FakeAuth auth;
    auth.probe = std::unexpected(authz::GateFailure::Degraded);
    auth.fail_status = 503;
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kFleetWideOnly, "Inventory", "Read") ==
          cw::Access::kDegraded);
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kFleetRead, "Inventory", "Read") ==
          cw::Access::kDegraded);
    auth.probe = std::unexpected(authz::GateFailure::Forbidden);
    auth.fail_status = 403;
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kFleetRead, "Inventory", "Read") ==
          cw::Access::kRefused);
}

TEST_CASE("crypto_access_for: kGlobal asks has_permission and never the fleet-read probe",
          "[crypto][widgets][authz]") {
    httplib::Request req;
    FakeAuth auth;
    auth.permitted = true;
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kGlobal, "Security", "Read") ==
          cw::Access::kAvailable);
    auth.permitted = false;
    CHECK(crypto_access_for(auth, req, cw::WidgetGate::kGlobal, "Security", "Read") ==
          cw::Access::kRefused);
    CHECK(auth.has_permission_calls == 2);
    CHECK(auth.probe_calls == 0);
}
