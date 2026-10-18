/**
 * @file test_access_audit_render.cpp
 * @brief Exact-output coverage of access_audit_render.{hpp,cpp}: the audit-log, sample and
 *        retention panels. Pure functions, no I/O, no clock.
 *
 * Pinned, in order of consequence:
 *   - an unreadable store renders a red box and never a table or "No events match";
 *   - a row shows only the REST twin's fields (source_ip / principal_role never appear);
 *   - every stored string is escaped, in text and in attributes, and every filter value in a
 *     paging URL is percent-encoded (hostile values `./x?` and `../y` included);
 *   - the Older button follows `has_more && offset + 50 <= 10,000`, with the ceiling said;
 *   - one time helper feeds the cell and its title, so they cannot disagree.
 */

#include "access_audit_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <limits>
#include <regex>
#include <set>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::access_audit;

namespace {

// 2026-10-13 09:41:12 UTC
constexpr std::int64_t kT = 1791884472;

AuditEvent event(std::int64_t id, std::string principal, std::string action, std::string result,
                 std::string tt = "User", std::string ti = "dave.rae", std::string detail = "") {
    AuditEvent e;
    e.id = id;
    e.timestamp = kT;
    e.principal = std::move(principal);
    e.action = std::move(action);
    e.result = std::move(result);
    e.target_type = std::move(tt);
    e.target_id = std::move(ti);
    e.detail = std::move(detail);
    // Present in the store and on the legacy route, absent from the twin: must never render.
    e.source_ip = "10.20.4.17";
    e.principal_role = "admin";
    e.user_agent = "curl/8";
    e.session_id = "sess-secret";
    return e;
}

LogView view(std::vector<AuditEvent> rows, int offset = 0, bool has_more = false) {
    LogView v;
    v.rows = std::move(rows);
    v.offset = offset;
    v.has_more = has_more;
    return v;
}

std::string log_of(const LogView& v) {
    return render_audit_log(v);
}

int count_of(const std::string& hay, const std::string& needle) {
    int n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

} // namespace

TEST_CASE("audit render: a populated row has five cells, a keyboard toggle and a detail row",
          "[access-audit][render]") {
    const auto out = log_of(view({event(184203, "dave.rae", "guaranteed_state.rule.update", "success",
                                        "GuaranteedState", "GLA-WS-0088", "enabled=true")}));
    CHECK_THAT(out, ContainsSubstring("<th>Time (UTC)</th><th>Who</th><th>Action</th><th>Target</th>"
                                      "<th>Result</th>"));
    CHECK_THAT(out, ContainsSubstring("<td title=\"2026-10-13T09:41:12Z\"><button type=\"button\" "
                                      "class=\"btn link sm\" data-act=\"toggle-row\" "
                                      "aria-expanded=\"false\" aria-controls=\"ev-184203\">"
                                      "13 Oct 09:41:12</button></td>"));
    CHECK_THAT(out, ContainsSubstring("<b>dave.rae</b>"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"mono\">guaranteed_state.rule.update</span>"
                                      "<span class=\"sub\" title=\"enabled=true\">enabled=true</span>"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"sub\">GuaranteedState</span>GLA-WS-0088"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"pill ok\" title=\"result = &quot;success&quot;\">"
                                      "Success</span>"));
    CHECK_THAT(out, ContainsSubstring("<tr class=\"result-detail\" id=\"ev-184203\">"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"detail-label\">Event id</span><span "
                                      "class=\"detail-value\">184203</span>"));
    CHECK_THAT(out, ContainsSubstring("2026-10-13T09:41:12Z (epoch 1791884472)"));
}

TEST_CASE("audit render: only the REST twin's fields appear; source_ip and role never do",
          "[access-audit][render]") {
    const auto out = log_of(view({event(1, "dave.rae", "auth.login", "ok")}));
    for (const char* never : {"10.20.4.17", "Source IP", "role admin", "principal_role", "curl/8",
                              "sess-secret"}) {
        INFO(never);
        CHECK_THAT(out, !ContainsSubstring(never));
    }
}

TEST_CASE("audit render: a pre-session row says Not signed in and keeps the attempted name in Target",
          "[access-audit][render]") {
    const auto out = log_of(view({event(2, "", "auth.login_failed", "error", "User", "m.graham")}));
    CHECK_THAT(out, ContainsSubstring("<span class=\"hint\" title=\"Pre-session event: the attempted "
                                      "username is in Target\">Not signed in</span>"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"sub\">User</span>m.graham"));
    CHECK_THAT(out, ContainsSubstring("(empty: not signed in)"));
    CHECK_THAT(out, ContainsSubstring("class=\"pill bad\""));
}

TEST_CASE("audit render: a row with no target or detail says None and omits the sub line",
          "[access-audit][render]") {
    const auto out = log_of(view({event(3, "dave.rae", "auth.logout", "ok", "", "", "")}));
    CHECK_THAT(out, ContainsSubstring("<span class=\"hint\">None</span>"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"detail-value\">(none)</span>"));
    CHECK_THAT(out, !ContainsSubstring("class=\"sub\" title"));
}

TEST_CASE("audit render: result tokens map to a tone and keep the raw token in the title",
          "[access-audit][render]") {
    struct Row {
        const char* raw;
        const char* tone;
        const char* label;
    };
    for (const auto& r : {Row{"ok", "ok", "Success"}, Row{"success", "ok", "Success"},
                          Row{"failure", "bad", "Failed"}, Row{"error", "bad", "Failed"},
                          Row{"denied", "warn", "Denied"}, Row{"partial", "warn", "Partial"},
                          Row{"not_found", "idle", "not_found"}, Row{"expired", "idle", "expired"}}) {
        INFO(r.raw);
        const auto out = log_of(view({event(4, "a", "x", r.raw)}));
        CHECK_THAT(out, ContainsSubstring(std::string("<span class=\"pill ") + r.tone +
                                          "\" title=\"result = &quot;" + r.raw + "&quot;\">" +
                                          r.label + "</span>"));
    }
}

TEST_CASE("audit render: hostile stored strings are escaped in text and in attributes",
          "[access-audit][render]") {
    const std::string evil = "<script>alert(1)</script>\"'&";
    const auto out = log_of(view({event(5, evil, evil, evil, evil, evil, evil)}));
    CHECK_THAT(out, !ContainsSubstring("<script"));
    CHECK_THAT(out, ContainsSubstring("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;"));
    // No attribute can be closed early: every title="..." value holds no raw quote.
    const std::regex titles(R"re(title="([^"]*)")re");
    int n = 0;
    for (std::sregex_iterator it(out.begin(), out.end(), titles), end; it != end; ++it, ++n)
        CHECK((*it)[1].str().find('<') == std::string::npos);
    CHECK(n > 0);
    // A large and a NUL-bearing value render bounded and inert.
    const std::string big(10 * 1024, 'A');
    const std::string nul = std::string("a\0b", 3);
    const auto out2 = log_of(view({event(6, big, nul, "ok", "T", "I", nul)}));
    CHECK(out2.size() < 100 * 1024);
}

TEST_CASE("audit render: an empty answered page is a true empty and names the window",
          "[access-audit][render]") {
    LogView v;
    v.range = Range::Hour;
    const auto out = log_of(v);
    CHECK_THAT(out, ContainsSubstring("No events match"));
    CHECK_THAT(out, ContainsSubstring("zero rows in the last hour"));
    CHECK_THAT(out, !ContainsSubstring("<table"));
    CHECK_THAT(out, !ContainsSubstring("role=\"alert\""));
    v.range = Range::Week;
    CHECK_THAT(log_of(v), ContainsSubstring("the last 7 days"));
}

TEST_CASE("audit render: an unreadable store is a red box, never a table or an empty state",
          "[access-audit][render]") {
    const auto out = render_audit_log(access::Unavailable{});
    CHECK_THAT(out, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(out, ContainsSubstring("The audit log could not be read."));
    CHECK_THAT(out, ContainsSubstring(std::string(kLogUnavailable)));
    CHECK_THAT(out, !ContainsSubstring("<table"));
    CHECK_THAT(out, !ContainsSubstring("No events match"));
    // Retry re-sends the toolbar's live values (the box carries no view of its own).
    CHECK_THAT(out, ContainsSubstring("hx-get=\"/fragments/access/audit/log\" "
                                      "hx-include=\"#audit-filters\" hx-target=\"#audit-log\""));
}

TEST_CASE("audit render: a refused request is a fixed note that echoes nothing",
          "[access-audit][render]") {
    for (const auto reason : {kBadRange, kBadText, kBadOffset}) {
        const auto out = render_audit_log(BadFilter{reason});
        CHECK_THAT(out, ContainsSubstring("role=\"note\""));
        CHECK_THAT(out, ContainsSubstring("That request was not understood"));
        CHECK_THAT(out, !ContainsSubstring("<table"));
    }
}

TEST_CASE("audit render: Older follows has_more and the 10,000-row ceiling, Newer follows the offset",
          "[access-audit][render]") {
    const auto rows = [] {
        std::vector<AuditEvent> r;
        for (int i = 0; i < kPageSize; ++i)
            r.push_back(event(1000 - i, "p", "a", "ok"));
        return r;
    };
    const auto btn = [](const std::string& out, const char* label) {
        const auto end = out.find(std::string(">") + label + "</button>");
        REQUIRE(end != std::string::npos);
        return out.substr(out.rfind("<button", end), end - out.rfind("<button", end));
    };

    auto out = log_of(view(rows(), 0, true));
    CHECK_THAT(btn(out, "Newer"), ContainsSubstring("disabled"));
    CHECK_THAT(btn(out, "Older"), ContainsSubstring("offset=50"));
    CHECK_THAT(out, ContainsSubstring("Rows 1 to 50, 50 per page."));

    out = log_of(view(rows(), 0, false));
    CHECK_THAT(btn(out, "Older"), ContainsSubstring("disabled"));
    CHECK_THAT(out, !ContainsSubstring("Paging stops"));

    // 9950 + 50 == 10000 is reachable; 10000 + 50 is not.
    out = log_of(view(rows(), 9950, true));
    CHECK_THAT(btn(out, "Older"), ContainsSubstring("offset=10000"));
    CHECK_THAT(btn(out, "Older"), !ContainsSubstring("disabled"));
    CHECK_THAT(out, !ContainsSubstring("Paging stops"));

    out = log_of(view(rows(), 10000, true));
    CHECK_THAT(btn(out, "Older"), ContainsSubstring("disabled"));
    CHECK_THAT(out, ContainsSubstring("Paging stops at 10,000 rows; narrow the time range."));

    out = log_of(view(rows(), 50, true));
    CHECK_THAT(btn(out, "Newer"), ContainsSubstring("offset=0"));
    out = log_of(view(rows(), 30, true));  // a hand-made odd offset never goes negative
    CHECK_THAT(btn(out, "Newer"), ContainsSubstring("offset=0"));
}

TEST_CASE("audit render: filters reach paging links percent-encoded, hostile values included",
          "[access-audit][render]") {
    LogView v = view({event(7, "p", "a", "ok")}, 0, true);
    v.principal = "oidc:https://x/y#sub";
    v.action = "a&b=c";
    auto out = log_of(v);
    CHECK_THAT(out, ContainsSubstring("principal=oidc%3Ahttps%3A%2F%2Fx%2Fy%23sub"));
    CHECK_THAT(out, ContainsSubstring("action=a%26b%3Dc"));
    CHECK_THAT(out, ContainsSubstring("&amp;offset=50"));

    v.principal = "../y";
    v.action = "./x?";
    out = log_of(v);
    CHECK_THAT(out, ContainsSubstring("principal=..%2Fy"));
    CHECK_THAT(out, ContainsSubstring("action=.%2Fx%3F"));
    CHECK_THAT(out, !ContainsSubstring("principal=../"));
    CHECK_THAT(out, !ContainsSubstring("action=./"));
    // The raw filter text never reaches an attribute unescaped.
    v.principal = "\"><script>";
    CHECK_THAT(log_of(v), !ContainsSubstring("<script"));
}

TEST_CASE("audit render: every aria-controls names exactly one detail row and ids are unique",
          "[access-audit][render]") {
    std::vector<AuditEvent> r;
    for (int i = 0; i < 5; ++i)
        r.push_back(event(100 + i, "p", "a", "ok"));
    const auto out = log_of(view(r));
    const std::regex ctl(R"re(aria-controls="(ev-[0-9]+)")re");
    std::set<std::string> ids;
    for (std::sregex_iterator it(out.begin(), out.end(), ctl), end; it != end; ++it) {
        const auto id = (*it)[1].str();
        CHECK(ids.insert(id).second);
        CHECK(count_of(out, "id=\"" + id + "\"") == 1);
    }
    CHECK(ids.size() == 5);
}

TEST_CASE("audit render: the panels carry no mutation construct", "[access-audit][render]") {
    SampleView s;
    s.rows = {event(8, "p", "auth.login", "ok")};
    const std::vector<std::string> outs = {
        log_of(view({event(9, "p", "a", "ok")}, 0, true)), render_auth_sample(s), render_retention(365),
        render_audit_log(access::Unavailable{})};
    for (const auto& o : outs)
        for (const char* bad : {"hx-post", "hx-put", "hx-delete", "hx-patch", "<form", "hx-on",
                                "javascript:", " onclick=", "innerHTML"}) {
            INFO(bad);
            CHECK_THAT(o, !ContainsSubstring(bad));
        }
}

TEST_CASE("audit time helpers: one source for the cell and the title", "[access-audit][render]") {
    CHECK(format_utc_short(kT) == "13 Oct 09:41:12");
    CHECK(format_utc_iso(kT) == "2026-10-13T09:41:12Z");
    for (const std::int64_t bad : {std::int64_t{0}, std::int64_t{-1},
                                   std::numeric_limits<std::int64_t>::max(),
                                   std::numeric_limits<std::int64_t>::min()}) {
        INFO(bad);
        CHECK(format_utc_short(bad) == "-");
        CHECK(format_utc_iso(bad) == "-");
    }
    // The same instant at the extreme renders a dash in BOTH the cell and the title.
    auto e = event(10, "p", "a", "ok");
    e.timestamp = std::numeric_limits<std::int64_t>::max();
    const auto out = log_of(view({e}));
    CHECK_THAT(out, ContainsSubstring("<td title=\"-\"><button"));
    CHECK_THAT(out, ContainsSubstring(">-</button>"));
    CHECK_THAT(out, !ContainsSubstring("1900"));
}

TEST_CASE("audit range tokens round-trip and anything else is refused", "[access-audit][render]") {
    for (const auto r : {Range::Hour, Range::Day, Range::Week})
        CHECK(parse_range(range_token(r)) == r);
    CHECK(range_seconds(Range::Hour) == 3600);
    CHECK(range_seconds(Range::Day) == 86400);
    CHECK(range_seconds(Range::Week) == 604800);
    for (const char* bad : {"", "1H", "30d", "24", "24h ", "all"})
        CHECK_FALSE(parse_range(bad).has_value());
}

TEST_CASE("audit sample render: rows, honest counts, and the audit-failed banner",
          "[access-audit][render]") {
    SampleView s;
    s.rows = {event(11, "", "auth.login_failed", "error"), event(12, "dave.rae", "mfa.step_up", "ok")};
    s.candidates = 842;
    auto out = render_auth_sample(s);
    CHECK_THAT(out, ContainsSubstring("2 rows drawn from 842 candidates (scan cap 10000; not "
                                      "recency-capped)."));
    CHECK_THAT(out, ContainsSubstring("<span class=\"mono\">auth.login_failed</span><span "
                                      "class=\"sub\">Not signed in</span>"));
    CHECK_THAT(out, ContainsSubstring("random sample for evidence, not a count"));
    CHECK_THAT(out, !ContainsSubstring("role=\"alert\""));

    s.recency_capped = true;
    CHECK_THAT(render_auth_sample(s), ContainsSubstring("recency-capped: the pool was only the newest"));

    s.audit_failed = true;
    out = render_auth_sample(s);
    CHECK_THAT(out, ContainsSubstring("The sample was drawn but its audit record could not be written."));
    CHECK_THAT(out, ContainsSubstring("role=\"alert\""));

    SampleView empty;
    CHECK_THAT(render_auth_sample(empty), ContainsSubstring("No authentication events"));
    CHECK_THAT(render_auth_sample(empty), !ContainsSubstring("<table"));
}

TEST_CASE("audit sample render: unavailable and refused are distinct fixed boxes",
          "[access-audit][render]") {
    const auto un = render_auth_sample(access::Unavailable{});
    CHECK_THAT(un, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring(std::string(kSampleUnavailable)));
    CHECK_THAT(un, !ContainsSubstring("<table"));
    const auto bad = render_auth_sample(BadFilter{kBadSample});
    CHECK_THAT(bad, ContainsSubstring(std::string(kBadSample)));
    CHECK_THAT(bad, !ContainsSubstring("role=\"alert\""));
}

TEST_CASE("audit retention render: days and the no-tamper-evidence statement, nothing else",
          "[access-audit][render]") {
    const auto out = render_retention(365);
    CHECK_THAT(out, ContainsSubstring("<span>Kept for</span><b>365 days</b>"));
    CHECK_THAT(out, ContainsSubstring("<span>Cleaned up</span><b>Hourly</b>"));
    CHECK_THAT(out, ContainsSubstring("no hash chain or signature exists"));
    CHECK_THAT(out, !ContainsSubstring("Events stored"));
}

TEST_CASE("audit retention render: zero or negative is Never, not a day count",
          "[access-audit][render]") {
    for (const int days : {0, -1}) {
        INFO(days);
        const auto out = render_retention(days);
        CHECK_THAT(out, ContainsSubstring("<span>Kept for</span><b>Never</b>"));
        CHECK_THAT(out, ContainsSubstring("<span>Cleaned up</span><b>Never</b>"));
        CHECK_THAT(out, !ContainsSubstring(" days"));
    }
}
