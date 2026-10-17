/**
 * @file test_groups_enrolment_render.cpp
 * @brief Pure-renderer tests for the three enrolment fragments (enrolment_render.hpp): tokens,
 *        agents waiting for approval, auto-approve rules. No store, no socket, no clock: `now`
 *        is injected, so "Expired" is decidable without a wait.
 *
 * What these pin: the three states stay distinct (populated / empty / store did not answer),
 * every agent- or operator-supplied string is escaped, the bulk actions are off whenever the
 * list is not whole, the rule copy is honest about what is matched, and the confirm text
 * follows the match mode (in "all" mode enabling narrows and removing widens), and an
 * agent- or store-supplied id reaches a URL path only as ONE percent-encoded segment.
 */

#include "enrolment_render.hpp"
#include "url_attr_scan.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::enrolment;
using Catch::Matchers::ContainsSubstring;
using Clock = std::chrono::system_clock;

namespace {

const auto kNow = Clock::time_point{std::chrono::seconds{1'800'000'000}};
constexpr const char* kXss = "<img src=x onerror=1>";

auth::EnrollmentToken token(std::string id, std::string label = "lab", int max_uses = 0,
                            int use_count = 0, bool revoked = false,
                            Clock::time_point expires = (Clock::time_point::max)()) {
    return {std::move(id), "hash", std::move(label), max_uses, use_count, kNow, expires, revoked, ""};
}

auth::PendingAgent agent(std::string id, std::string host,
                         auth::PendingStatus st = auth::PendingStatus::pending) {
    return {std::move(id), std::move(host), "linux", "x86_64", "1.2.3", kNow, st};
}

// Every hx-target="..." value in `html`, in order.
std::vector<std::string> hx_targets(const std::string& html) {
    std::vector<std::string> out;
    const std::string key = "hx-target=\"";
    for (auto p = html.find(key); p != std::string::npos; p = html.find(key, p + key.size())) {
        const auto from = p + key.size();
        out.push_back(html.substr(from, html.find('"', from) - from));
    }
    return out;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

} // namespace

// ── helpers ─────────────────────────────────────────────────────────────────

TEST_CASE("enrolment: utc_stamp is a fixed-width UTC string", "[groups][enrolment][render]") {
    CHECK(utc_stamp(Clock::time_point{}) == "1970-01-01 00:00 UTC");
    CHECK(utc_stamp(Clock::time_point{std::chrono::seconds{86'400 + 3'660}}) ==
          "1970-01-02 01:01 UTC");
    // A normal date; seconds are truncated, not rounded.
    CHECK(utc_stamp(Clock::time_point{std::chrono::seconds{1'800'000'059}}) ==
          "2027-01-15 08:00 UTC");
    // Sub-second ticks floor to the second (a pre-epoch fraction floors DOWN, so it is out of range).
    CHECK(utc_stamp(Clock::time_point{std::chrono::milliseconds{1'500}}) == "1970-01-01 00:00 UTC");
    CHECK(utc_stamp(Clock::time_point{std::chrono::milliseconds{-1}}) == "out of range");
}

// The calendar logic runs over plain int64 epoch seconds, so these boundaries do not depend on
// the clock's tick: libstdc++'s system_clock counts nanoseconds in an int64 and cannot even hold
// year 2263, let alone 9999, as a time_point.
TEST_CASE("enrolment: utc_stamp_epoch_secs formats the whole supported range",
          "[groups][enrolment][render]") {
    CHECK(utc_stamp_epoch_secs(0) == "1970-01-01 00:00 UTC");
    CHECK(utc_stamp_epoch_secs(86'400 + 3'660) == "1970-01-02 01:01 UTC");
    CHECK(utc_stamp_epoch_secs(1'800'000'059) == "2027-01-15 08:00 UTC");
    // Leap day, and the century rule (2000 leap, 2100 not).
    CHECK(utc_stamp_epoch_secs(951'782'400) == "2000-02-29 00:00 UTC");
    CHECK(utc_stamp_epoch_secs(4'107'542'400) == "2100-03-01 00:00 UTC");
    // The last second of year 9999 still formats; the next one does not.
    CHECK(utc_stamp_epoch_secs(253'402'300'799) == "9999-12-31 23:59 UTC");
    CHECK(utc_stamp_epoch_secs(253'402'300'800) == "out of range");
}

// The legacy enrollment-tokens.cfg import allows an epoch to year 9999 and beyond. The CRT
// route (gmtime_s then strftime on the zeroed result) terminates the process on MSVC and
// prints 1900-01-00 on POSIX, so an unrepresentable value is a fixed sentence, never a date.
TEST_CASE("enrolment: utc_stamp prints out of range instead of a bogus date",
          "[groups][enrolment][render]") {
    constexpr auto kMin = (std::numeric_limits<std::int64_t>::min)();
    constexpr auto kMax = (std::numeric_limits<std::int64_t>::max)();
    for (const std::int64_t secs : {std::int64_t{-1}, std::int64_t{-86'400}, std::int64_t{-62'135'596'800},
                                    std::int64_t{253'402'300'800}, std::int64_t{4'000'000'000'000},
                                    kMin, kMin + 1, kMax - 1, kMax}) {
        INFO("secs=" << secs);
        CHECK(utc_stamp_epoch_secs(secs) == "out of range");
    }
    // The clock extremes (whatever the tick) go through the same floor and are out of range
    // or a valid date, never UB: libc++'s microsecond max is year 294247, libstdc++'s
    // nanosecond max is year 2262.
    for (const auto tp : {(Clock::time_point::max)(), (Clock::time_point::min)()}) {
        const auto s = utc_stamp(tp);
        CHECK((s == "out of range" || s.size() == 20));
    }
    CHECK(utc_stamp((Clock::time_point::min)()) == "out of range");

    // End to end through a row: a far-future expiry that is NOT the never sentinel renders as a
    // date or "out of range" by the clock's reach, never "Never" and never Expired. The exact
    // text is derived from the same helper so the assertion holds on every standard library.
    const auto far_future = (Clock::time_point::max)() - std::chrono::hours(24);
    const std::vector<auth::EnrollmentToken> v = {token("farfuture", "x", 0, 0, false, far_future)};
    const auto html = render_tokens(&v, "", kNow);
    const auto want = utc_stamp_epoch_secs(
        std::chrono::floor<std::chrono::seconds>(far_future).time_since_epoch().count());
    CHECK_THAT(html, ContainsSubstring("<td>" + want + "</td>"));
    CHECK_THAT(html, !ContainsSubstring("<td>Never</td>"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill info\">Active</span>"));
}

// The element ids are baked into the Groups template and the Settings page, and an htmx swap
// lands in whatever hx-target names. A renderer that targeted another panel's id would drop its
// refreshed list into the wrong panel, so every target must be the section that owns the fragment.
TEST_CASE("enrolment: every hx-target is the section that owns the fragment",
          "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const auto check = [](const std::string& html, const std::string& section,
                          std::size_t at_least) {
        const auto targets = hx_targets(html);
        INFO("section=" << section);
        CHECK(targets.size() >= at_least); // not vacuous: the buttons and forms are really there
        for (const auto& t : targets)
            CHECK(t == section);
    };

    const std::vector<auth::EnrollmentToken> toks = {token("aaaaaaaa", "live"),
                                                     token("bbbbbbbb", "gone", 0, 0, true)};
    // Done + Revoke + the generate form.
    check(render_tokens(&toks, "secret", kNow), "#token-section", 3);
    check(render_tokens(nullptr, "", kNow), "#token-section", 0);

    const std::vector<auth::PendingAgent> agents = {agent("one", "h1"), agent("two", "h2"),
                                                    agent("three", "h3", auth::PendingStatus::denied)};
    // Approve + Deny + Forget for two rows, then Approve all and Deny all.
    check(render_pending(&agents), "#pending-section", 8);

    const std::vector<auth::AutoApproveRule> rules = {{T::hostname_glob, "a.corp", "", true},
                                                      {T::ip_subnet, "10.0.0.0/8", "", false}};
    // The other match mode, Toggle + Remove for two rules, and the Add form.
    check(render_auto_approve(rules, false), "#auto-approve-section", 6);
    check(render_auto_approve(rules, true), "#auto-approve-section", 6);
}

TEST_CASE("enrolment: match-everything detection", "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    // warns
    CHECK(rule_matches_everything(T::hostname_glob, "*"));
    CHECK(rule_matches_everything(T::hostname_glob, "**"));
    CHECK(rule_matches_everything(T::hostname_glob, "*?"));
    CHECK(rule_matches_everything(T::hostname_glob, "?*?"));
    CHECK(rule_matches_everything(T::ip_subnet, "0.0.0.0/0"));
    CHECK(rule_matches_everything(T::ip_subnet, "10.1.2.3/0"));
    // does not warn
    CHECK_FALSE(rule_matches_everything(T::hostname_glob, "*.corp"));
    CHECK_FALSE(rule_matches_everything(T::hostname_glob, "?"));
    CHECK_FALSE(rule_matches_everything(T::hostname_glob, ""));
    CHECK_FALSE(rule_matches_everything(T::ip_subnet, "/0"));       // matches nothing
    CHECK_FALSE(rule_matches_everything(T::ip_subnet, "10.0.0.0/8"));
    CHECK_FALSE(rule_matches_everything(T::ip_subnet, "0.0.0.0"));
    CHECK_FALSE(rule_matches_everything(T::ip_subnet, "999.0.0.0/0")); // not an address
    CHECK_FALSE(rule_matches_everything(T::ip_subnet, "::/0"));        // IPv6 is not matched
    CHECK_FALSE(rule_matches_everything(T::trusted_ca, "*"));
    CHECK_FALSE(rule_matches_everything(T::cloud_provider, "*"));
}

// ── tokens ──────────────────────────────────────────────────────────────────

TEST_CASE("enrolment tokens: an unanswered store is a failbox; never an empty table",
          "[groups][enrolment][render]") {
    const auto html = render_tokens(nullptr, "", kNow);
    CHECK_THAT(html, ContainsSubstring("failbox"));
    CHECK_THAT(html, ContainsSubstring("not an empty list"));
    CHECK_THAT(html, !ContainsSubstring("<table"));
    CHECK_THAT(html, !ContainsSubstring("No tokens"));
    CHECK_THAT(html, !ContainsSubstring("data-token-form")); // no generate form over an unknown store
}

TEST_CASE("enrolment tokens: a fresh secret survives a failed list read",
          "[groups][enrolment][render]") {
    const std::string raw(64, 'a');
    const auto html = render_tokens(nullptr, raw, kNow);
    CHECK_THAT(html, ContainsSubstring("<code class=\"mono\">" + raw + "</code>"));
    CHECK_THAT(html, ContainsSubstring("failbox"));
}

TEST_CASE("enrolment tokens: reveal block has Copy and Done; secret escaped; no timer",
          "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> none;
    const auto html = render_tokens(&none, std::string("ab<") + kXss, kNow);
    CHECK_THAT(html, ContainsSubstring("It will not be shown again"));
    CHECK_THAT(html, ContainsSubstring("data-copy-token"));
    // Done is an hx-get of the list: removes the block, needs no script.
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/settings/tokens\" "
                                       "hx-target=\"#token-section\""));
    CHECK_THAT(html, ContainsSubstring(">Done<"));
    CHECK_THAT(html, !ContainsSubstring("<img src=x"));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
    // The Copy button and <code> share one parent (the Settings page's copy handler walks it).
    const auto row = html.find("<div class=\"revealrow\">");
    REQUIRE(row != std::string::npos);
    const auto row_end = html.find("</div>", row);
    const auto sub = html.substr(row, row_end - row);
    CHECK_THAT(sub, ContainsSubstring("<code"));
    CHECK_THAT(sub, ContainsSubstring("data-copy-token"));
    CHECK_THAT(html, !ContainsSubstring("setTimeout"));
}

TEST_CASE("enrolment tokens: no reveal block unless a secret was minted",
          "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> none;
    CHECK_THAT(render_tokens(&none, "", kNow), !ContainsSubstring("revealrow"));
}

TEST_CASE("enrolment tokens: empty list says so and keeps the generate form",
          "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> none;
    const auto html = render_tokens(&none, "", kNow);
    CHECK_THAT(html, ContainsSubstring("No tokens yet."));
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/enrollment-tokens\""));
    // Form field names are the existing route's contract.
    for (const char* n : {"name=\"label\"", "name=\"max_uses\"", "name=\"ttl_hours\""})
        CHECK_THAT(html, ContainsSubstring(n));
    CHECK_THAT(html, ContainsSubstring("name=\"label\" maxlength=\"" +
                                       std::to_string(auth::kMaxEnrollmentTextLength) + "\""));
    // Both limits empty: the unlimited warning is on screen by default.
    CHECK_THAT(html, ContainsSubstring("data-token-unlimited"));
    CHECK_THAT(html, ContainsSubstring("Anyone holding this token can enrol agents indefinitely"));
}

TEST_CASE("enrolment tokens: Active; Expired; Exhausted and Revoked are distinct states",
          "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> v = {
        token("aaaaaaaa", "live", 5, 1),
        token("bbbbbbbb", "lapsed", 0, 0, false, kNow - std::chrono::hours(1)),
        token("cccccccc", "spent", 2, 2),
        token("dddddddd", "gone", 0, 0, true),
    };
    const auto html = render_tokens(&v, "", kNow);
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill info\">Active</span>"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill warn\">Expired</span>"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill idle\">Exhausted</span>"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill idle\">Revoked</span>"));
    // An Active (or lapsed) credential never wears the green OK pill.
    CHECK_THAT(html, !ContainsSubstring("pill ok"));
    // Legacy classes that exist only in the Settings page <style> are gone.
    for (const char* legacy : {"role-badge", "user-table", "btn-danger", "feedback-error",
                               "token-reveal", "mini-field", "add-user-form"})
        CHECK_THAT(html, !ContainsSubstring(legacy));
    // Revoked rows offer no Revoke.
    CHECK(count_of(html, ">Revoke</button>") == 3);
    CHECK_THAT(html, ContainsSubstring("Agents already enrolled stay enrolled."));
    CHECK_THAT(html, ContainsSubstring("hx-delete=\"/api/settings/enrollment-tokens/aaaaaaaa\""));
    CHECK_THAT(html, ContainsSubstring("1 / 5"));
    CHECK_THAT(html, ContainsSubstring("0 / \xe2\x88\x9e"));
}

namespace {
// The pill that follows a token row's id cell.
std::string pill_after(const std::string& html, const std::string& token_id) {
    const auto row = html.find("<code>" + token_id + "</code>");
    REQUIRE(row != std::string::npos);
    const auto pill = html.find("<span class=\"pill ", row);
    REQUIRE(pill != std::string::npos);
    return html.substr(pill, html.find("</span>", pill) + 7 - pill);
}
} // namespace

// The decision behind the pill, with the clock injected. The consume path needs
// `expires_at > now()` to enrol, so a token expiring exactly now is already Expired.
TEST_CASE("enrolment tokens: an expiry exactly at now is Expired and one second later is Active",
          "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> v = {
        token("atnowxxx", "x", 0, 0, false, kNow),
        token("latersec", "x", 0, 0, false, kNow + std::chrono::seconds(1)),
        token("earlier1", "x", 0, 0, false, kNow - std::chrono::seconds(1)),
        token("neverexp", "x"),
    };
    const auto html = render_tokens(&v, "", kNow);
    CHECK(pill_after(html, "atnowxxx") == "<span class=\"pill warn\">Expired</span>");
    CHECK(pill_after(html, "latersec") == "<span class=\"pill info\">Active</span>");
    CHECK(pill_after(html, "earlier1") == "<span class=\"pill warn\">Expired</span>");
    CHECK(pill_after(html, "neverexp") == "<span class=\"pill info\">Active</span>");
}

// Revoked beats exhausted beats expired, whatever the clock says.
TEST_CASE("enrolment tokens: revoked beats exhausted beats expired",
          "[groups][enrolment][render]") {
    const auto lapsed = kNow - std::chrono::hours(1);
    const std::vector<auth::EnrollmentToken> v = {
        token("revokedx", "x", 2, 2, true, lapsed),
        token("spentand", "x", 2, 2, false, lapsed),
        token("lapsedxx", "x", 2, 1, false, lapsed),
    };
    const auto html = render_tokens(&v, "", kNow);
    CHECK(pill_after(html, "revokedx") == "<span class=\"pill idle\">Revoked</span>");
    CHECK(pill_after(html, "spentand") == "<span class=\"pill idle\">Exhausted</span>");
    CHECK(pill_after(html, "lapsedxx") == "<span class=\"pill warn\">Expired</span>");
}

// A double submit of the generate form must not mint two tokens: htmx's own hx-disabled-elt
// (not hx-on, which the dashboard CSP blocks) disables the submit button while in flight.
TEST_CASE("enrolment tokens: the generate form disables its submit button while in flight",
          "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> none;
    const auto html = render_tokens(&none, "", kNow);
    const auto form = html.find("<form class=\"form\" hx-post=\"/api/settings/enrollment-tokens\"");
    REQUIRE(form != std::string::npos);
    const auto tag_end = html.find('>', form);
    CHECK_THAT(html.substr(form, tag_end - form),
               ContainsSubstring("hx-disabled-elt=\"find button[type=submit]\""));
    CHECK_THAT(html.substr(form), ContainsSubstring("<button class=\"btn primary\" type=\"submit\">Generate token"));
    CHECK_THAT(html, !ContainsSubstring("hx-on"));
}

TEST_CASE("enrolment tokens: expiry is a UTC date; never raw epoch seconds",
          "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> v = {
        token("aaaaaaaa", "x", 0, 0, false, Clock::time_point{std::chrono::seconds{1'900'000'000}}),
        token("bbbbbbbb", "y"),
    };
    const auto html = render_tokens(&v, "", kNow);
    CHECK_THAT(html, ContainsSubstring(utc_stamp(Clock::time_point{std::chrono::seconds{1'900'000'000}})));
    CHECK_THAT(html, !ContainsSubstring(">1900000000<"));
    CHECK_THAT(html, ContainsSubstring("<td>Never</td>"));
}

TEST_CASE("enrolment tokens: Active rows list first and the list is capped with a banner",
          "[groups][enrolment][render]") {
    std::vector<auth::EnrollmentToken> v;
    for (std::size_t i = 0; i < kRenderCap + 5; ++i)
        v.push_back(token("r" + std::to_string(1000000 + i), "revoked", 0, 0, true));
    v.push_back(token("activeid", "the-live-one")); // last in store order
    const auto html = render_tokens(&v, "", kNow);
    CHECK(count_of(html, "<tr><td><code>") == kRenderCap);
    CHECK_THAT(html, ContainsSubstring("Showing 200 of 206 tokens. Active tokens are listed first."));
    // Even though it was last, the live token made the cut.
    CHECK_THAT(html, ContainsSubstring("the-live-one"));
    CHECK(html.find("the-live-one") < html.find("revoked"));
}

TEST_CASE("enrolment tokens: operator text is escaped everywhere", "[groups][enrolment][render]") {
    const std::vector<auth::EnrollmentToken> v = {token("id<b>", kXss)};
    const auto html = render_tokens(&v, "", kNow);
    CHECK_THAT(html, !ContainsSubstring("<img src=x"));
    CHECK_THAT(html, !ContainsSubstring("id<b>"));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
}

// ── pending ─────────────────────────────────────────────────────────────────

TEST_CASE("enrolment pending: an unanswered store is a failbox", "[groups][enrolment][render]") {
    const auto html = render_pending(nullptr);
    CHECK_THAT(html, ContainsSubstring("failbox"));
    CHECK_THAT(html, !ContainsSubstring("No agents are waiting"));
    CHECK_THAT(html, !ContainsSubstring("<table"));
}

TEST_CASE("enrolment pending: empty; and approved rows are never shown",
          "[groups][enrolment][render]") {
    const std::vector<auth::PendingAgent> none;
    CHECK_THAT(render_pending(&none), ContainsSubstring("No agents are waiting."));
    const std::vector<auth::PendingAgent> only_approved = {
        agent("a1", "enrolled", auth::PendingStatus::approved)};
    const auto html = render_pending(&only_approved);
    CHECK_THAT(html, ContainsSubstring("No agents are waiting."));
    CHECK_THAT(html, !ContainsSubstring("enrolled"));
}

TEST_CASE("enrolment pending: row actions use the existing routes; Forget only on pending rows",
          "[groups][enrolment][render]") {
    const std::vector<auth::PendingAgent> v = {
        agent("agent-one", "host-one"),
        agent("agent-two", "host-two", auth::PendingStatus::denied),
    };
    const auto html = render_pending(&v);
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/pending-agents/agent-one/approve\""));
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/pending-agents/agent-one/deny\""));
    // Single-row Deny carries the same irreversibility sentence as the bulk Deny.
    CHECK_THAT(html, ContainsSubstring("hx-confirm=\"Deny agent enrollment? This page offers no way "
                                       "to reverse a denial.\""));
    CHECK_THAT(html, ContainsSubstring("hx-delete=\"/api/settings/pending-agents/agent-one\""));
    CHECK_THAT(html, ContainsSubstring("The agent is queued again the next time it asks to join."));
    // A denial is a durable record: no action on that row.
    CHECK_THAT(html, !ContainsSubstring("agent-two/approve"));
    CHECK_THAT(html, !ContainsSubstring("pending-agents/agent-two\""));
    CHECK_THAT(html, ContainsSubstring("denial recorded"));
    CHECK_THAT(html, ContainsSubstring("1 waiting, 1 denied"));
    // Requested time is shown (it was not before), in UTC.
    CHECK_THAT(html, ContainsSubstring(utc_stamp(kNow)));
    // Single approve has no confirm (parity).
    const auto a = html.find("agent-one/approve");
    REQUIRE(a != std::string::npos);
    CHECK_THAT(html.substr(a, html.find("</button>", a) - a), !ContainsSubstring("hx-confirm"));
    // No inline handler; the bulk bar is hx-post, not onclick.
    CHECK_THAT(html, !ContainsSubstring("onclick"));
}

TEST_CASE("enrolment pending: a hostile agent id reaches every row URL as one encoded segment",
          "[groups][enrolment][render][url_path_segment]") {
    for (const char* id : {"./bulk-approve?", "../auto-approve/mode?", "../enrollment-tokens?",
                           "a/b", "a#b", "a?b", "%252e", "caf\xC3\xA9", "a b&c", "x\"y"}) {
        INFO("id=" << id);
        const std::vector<auth::PendingAgent> v = {agent(id, "h"), agent("other", "h2")};
        const auto html = render_pending(&v);
        const auto urls = yuzu::test::url_attr_values(html);
        const std::string base = "/api/settings/pending-agents/" + url_path_segment(id);
        REQUIRE(yuzu::test::has_url(urls, base + "/approve"));
        REQUIRE(yuzu::test::has_url(urls, base + "/deny"));
        REQUIRE(yuzu::test::has_url(urls, base)); // Forget
        for (const auto& u : urls) {
            CHECK_FALSE(yuzu::test::path_has_dot_segment(u));
            // Skip only the two bulk routes themselves. A hostile id such as "./bulk-approve?"
            // encodes to a URL that merely CONTAINS "bulk-", and that is exactly the URL these
            // checks exist for.
            if (u.rfind("/api/settings/pending-agents/", 0) == 0 &&
                u != "/api/settings/pending-agents/bulk-approve" &&
                u != "/api/settings/pending-agents/bulk-deny") {
                // <prefix>/<one segment>[/<verb>]: the id contributes no slash, '?' or '#'.
                CHECK(yuzu::test::path_slashes(u) <= 5);
                CHECK(u.find('?') == std::string::npos);
                CHECK(u.find('#') == std::string::npos);
            }
        }
    }
}

TEST_CASE("enrolment pending: empty and dot-only ids get no row action; only the note",
          "[groups][enrolment][render][url_path_segment]") {
    for (const char* id : {"", ".", "..", "%2e%2e", "%2E", ".%2e"}) {
        INFO("id=" << id);
        const std::vector<auth::PendingAgent> v = {agent(id, "h"), agent("normal", "h2")};
        const auto html = render_pending(&v);
        const auto urls = yuzu::test::url_attr_values(html);
        for (const auto& u : urls) {
            CHECK_FALSE(yuzu::test::path_has_dot_segment(u));
            CHECK(u.find("pending-agents//") == std::string::npos);
            CHECK(u.find("pending-agents/./") == std::string::npos);
            CHECK(u.find("pending-agents/../") == std::string::npos);
        }
        CHECK(yuzu::test::has_url(urls, "/api/settings/pending-agents/normal/approve"));
        // Exactly one row (the unaddressable one) lacks actions; it says why.
        CHECK(count_of(html, "identifier not supported for row actions") == 1);
        CHECK(count_of(html, ">Approve</button>") == 1);
        CHECK(count_of(html, ">Forget</button>") == 1);
    }
}

TEST_CASE("enrolment pending: a lone unaddressable waiting agent still has the bulk actions",
          "[groups][enrolment][render][url_path_segment]") {
    const std::vector<auth::PendingAgent> lone = {agent("..", "h")};
    const auto html = render_pending(&lone);
    CHECK_THAT(html, ContainsSubstring("identifier not supported for row actions"));
    CHECK_THAT(html, !ContainsSubstring(">Approve</button>"));
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/pending-agents/bulk-approve\""));
    CHECK_THAT(html, ContainsSubstring("Approve all (1)"));
    // A lone ordinary agent keeps the old shape: row actions, no bulk bar.
    const std::vector<auth::PendingAgent> ok = {agent("fine", "h")};
    CHECK_THAT(render_pending(&ok), !ContainsSubstring("bulk-approve"));
}

TEST_CASE("enrolment tokens: the token id in a Revoke URL is one encoded segment",
          "[groups][enrolment][render][url_path_segment]") {
    const std::vector<auth::EnrollmentToken> v = {token("../x?y/z")};
    const auto html = render_tokens(&v, "", kNow);
    const auto urls = yuzu::test::url_attr_values(html);
    CHECK(yuzu::test::has_url(urls, "/api/settings/enrollment-tokens/" +
                                        url_path_segment("../x?y/z")));
    for (const auto& u : urls) {
        CHECK_FALSE(yuzu::test::path_has_dot_segment(u));
        if (u.rfind("/api/settings/enrollment-tokens/", 0) == 0)
            CHECK(yuzu::test::path_slashes(u) == 4);
    }
}

TEST_CASE("enrolment pending: bulk actions name the total and up to ten hostnames",
          "[groups][enrolment][render]") {
    std::vector<auth::PendingAgent> v;
    for (int i = 0; i < 12; ++i)
        v.push_back(agent("id" + std::to_string(i), i == 0 ? std::string(kXss) : "h" + std::to_string(i)));
    const auto html = render_pending(&v);
    CHECK_THAT(html, ContainsSubstring("Approve all (12)"));
    CHECK_THAT(html, ContainsSubstring("Deny all (12)"));
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/pending-agents/bulk-approve\""));
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/pending-agents/bulk-deny\""));
    CHECK_THAT(html, ContainsSubstring("(12 as of this view, including any that arrive since)?"));
    // The bulk Deny and the single-row Deny say it in the same words.
    CHECK_THAT(html, ContainsSubstring("including any that arrive since)? This page offers no way "
                                       "to reverse a denial."));
    CHECK_THAT(html, ContainsSubstring("and 2 more"));
    CHECK_THAT(html, !ContainsSubstring("<img src=x"));      // hostnames in the confirm are escaped
    CHECK_THAT(html, !ContainsSubstring(" disabled"));
    // Fewer than two waiting: no bulk bar at all.
    const std::vector<auth::PendingAgent> one = {agent("only", "h")};
    CHECK_THAT(render_pending(&one), !ContainsSubstring("Approve all"));
}

TEST_CASE("enrolment pending: past the render cap the bulk buttons are disabled and say why",
          "[groups][enrolment][render]") {
    std::vector<auth::PendingAgent> v;
    for (std::size_t i = 0; i < kRenderCap + 1; ++i)
        v.push_back(agent("id" + std::to_string(i), "h" + std::to_string(i)));
    const auto html = render_pending(&v);
    // N is counted BEFORE the cap, so the header and the bulk label say 201.
    CHECK_THAT(html, ContainsSubstring("201 waiting"));
    CHECK_THAT(html, ContainsSubstring("Approve all (201)"));
    CHECK(count_of(html, "<tr><td><code") == kRenderCap);
    // Both bulk buttons are disabled: the routes act on every pending row, shown or not.
    CHECK(count_of(html, "type=\"button\" disabled hx-post=\"/api/settings/pending-agents/bulk-") == 2);
    CHECK_THAT(html, ContainsSubstring("Showing 200 of 201."));
    // Per-row actions are still live.
    CHECK_THAT(html, ContainsSubstring("id0/approve"));
}

// Denied rows are listed after the waiting ones and are cut by the same cap. The bulk-bar banner
// only speaks when WAITING agents are cut, so a silent drop of denied rows needs its own note.
TEST_CASE("enrolment pending: denied rows cut off by the render cap are announced",
          "[groups][enrolment][render]") {
    std::vector<auth::PendingAgent> v = {agent("w1", "waiting-host")};
    for (std::size_t i = 0; i < kRenderCap + 5; ++i)
        v.push_back(agent("d" + std::to_string(i), "denied-host", auth::PendingStatus::denied));
    const auto html = render_pending(&v);
    CHECK(count_of(html, "<tr><td><code") == kRenderCap);
    CHECK_THAT(html, ContainsSubstring("Showing 200 of 206 agents. Every waiting agent is listed; "
                                       "the 6 other denied agents are not."));
    // Every waiting agent is shown, so the bulk actions stay on and the waiting-cut banner is absent.
    CHECK_THAT(html, ContainsSubstring("1 waiting, 205 denied"));
    CHECK_THAT(html, !ContainsSubstring("including the ones not shown"));

    // Nothing is cut: no note. Cut waiting agents: the bulk-bar banner, not this note.
    const std::vector<auth::PendingAgent> small_list = {agent("w1", "h"),
                                                   agent("d1", "h", auth::PendingStatus::denied)};
    CHECK_THAT(render_pending(&small_list), !ContainsSubstring("Showing "));
    std::vector<auth::PendingAgent> many;
    for (std::size_t i = 0; i < kRenderCap + 1; ++i)
        many.push_back(agent("p" + std::to_string(i), "h"));
    CHECK_THAT(render_pending(&many), !ContainsSubstring("Every waiting agent is listed"));
}

TEST_CASE("enrolment pending: pending rows are shown before denied ones under the cap",
          "[groups][enrolment][render]") {
    std::vector<auth::PendingAgent> v;
    for (std::size_t i = 0; i < kRenderCap; ++i)
        v.push_back(agent("d" + std::to_string(i), "denied-host", auth::PendingStatus::denied));
    v.push_back(agent("p-last", "the-waiting-host"));
    const auto html = render_pending(&v);
    CHECK_THAT(html, ContainsSubstring("the-waiting-host"));
}

TEST_CASE("enrolment pending: agent-supplied text is escaped", "[groups][enrolment][render]") {
    const std::vector<auth::PendingAgent> v = {agent(std::string("id") + kXss, kXss)};
    const auto html = render_pending(&v);
    CHECK_THAT(html, !ContainsSubstring("<img src=x"));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
}

// ── auto-approve rules ──────────────────────────────────────────────────────

TEST_CASE("enrolment rules: empty state and the two real match modes", "[groups][enrolment][render]") {
    const std::vector<auth::AutoApproveRule> none;
    const auto any = render_auto_approve(none, false);
    CHECK_THAT(any, ContainsSubstring("No auto-approve rules."));
    CHECK_THAT(any, ContainsSubstring("New agents wait for approval."));
    // The current mode is a disabled, pressed button; the other one posts the mode change.
    CHECK_THAT(any, ContainsSubstring("class=\"on\" type=\"button\" aria-pressed=\"true\" disabled>"
                                      "Any rule matches (first match)"));
    CHECK_THAT(any, ContainsSubstring("hx-vals=\"{&quot;mode&quot;:&quot;all&quot;}\""));
    CHECK_THAT(any, ContainsSubstring("Require every enabled rule to match? Fewer agents will "
                                      "join without approval."));
    const auto all = render_auto_approve(none, true);
    CHECK_THAT(all, ContainsSubstring("hx-vals=\"{&quot;mode&quot;:&quot;any&quot;}\""));
    CHECK_THAT(all, ContainsSubstring("Approve an agent when any enabled rule matches? More "
                                      "agents may join without approval."));
    // The fictional "Never" / "Everything" options do not exist.
    CHECK_THAT(any, !ContainsSubstring("Never"));
    CHECK_THAT(any, !ContainsSubstring("Everything"));
}

TEST_CASE("enrolment rules: rule text is honest about what is matched",
          "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const std::vector<auth::AutoApproveRule> v = {
        {T::hostname_glob, "EDI-*", "edinburgh", true},
        {T::ip_subnet, "10.0.0.0/8", "lan", true},
        {T::trusted_ca, "abc123", "ca", true},
        {T::cloud_provider, "aws", "cloud", false},
    };
    const auto html = render_auto_approve(v, false);
    CHECK_THAT(html, ContainsSubstring("Agent-reported hostname matches <code>EDI-*</code> (not verified)"));
    // The address is what the server saw, so it carries no caveat.
    CHECK_THAT(html, ContainsSubstring("Address the server sees matches <code>10.0.0.0/8</code></td>"));
    // A CA fingerprint is never populated at Register, so the rule can never match.
    CHECK_THAT(html, ContainsSubstring("Agent CA fingerprint <code>abc123</code> "
                                       "(never matches at this release)"));
    // The cloud provider is the agent's own claim (a bare compare), not an attestation.
    CHECK_THAT(html, ContainsSubstring("Agent-reported provider <code>aws</code> (not verified)"));
    CHECK_THAT(html, !ContainsSubstring("Attestation provider"));
    CHECK_THAT(html, ContainsSubstring("Address rules match IPv4 only, and never match an agent "
                                       "that enrols through a gateway (no address is passed on)."));
    CHECK(count_of(html, "enrols through a gateway") == 1); // one hint paragraph, not per row
    CHECK_THAT(html, !ContainsSubstring("Matches every agent"));
    // Index-keyed routes, as the engine addresses rules by list position.
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/auto-approve/3/toggle\""));
    CHECK_THAT(html, ContainsSubstring("hx-delete=\"/api/settings/auto-approve/0\""));
}

TEST_CASE("enrolment rules: a match-everything rule wears a warning", "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const std::vector<auth::AutoApproveRule> v = {
        {T::hostname_glob, "**", "a", true},
        {T::hostname_glob, "*?", "b", true},
        {T::ip_subnet, "0.0.0.0/0", "c", true},
        {T::ip_subnet, "/0", "d", true},
        {T::hostname_glob, "*.corp", "e", true},
    };
    const auto html = render_auto_approve(v, false);
    CHECK(count_of(html, "Matches every agent") == 3);
}

namespace {

// The hx-confirm text of the button whose opening tag contains `anchor`, as the browser shows it
// ("" when it has none).
std::string confirm_of(const std::string& html, const std::string& anchor) {
    const auto at = html.find(anchor);
    REQUIRE(at != std::string::npos);
    const auto end = html.find("</button>", at);
    const auto attr = html.find(" hx-confirm=\"", at);
    if (attr == std::string::npos || attr > end)
        return {};
    const auto from = attr + std::string(" hx-confirm=\"").size();
    std::string text = html.substr(from, html.find('"', from) - from);
    // The browser un-escapes the attribute; the fixtures only carry &quot;.
    for (auto q = text.find("&quot;"); q != std::string::npos; q = text.find("&quot;", q + 1))
        text.replace(q, 6, "\"");
    return text;
}

std::vector<auth::AutoApproveRule> rules_with(std::size_t enabled, std::size_t disabled) {
    std::vector<auth::AutoApproveRule> v;
    for (std::size_t i = 0; i < enabled; ++i)
        v.push_back({auth::AutoApproveRuleType::hostname_glob, "on" + std::to_string(i), "", true});
    for (std::size_t i = 0; i < disabled; ++i)
        v.push_back({auth::AutoApproveRuleType::hostname_glob, "off" + std::to_string(i), "", false});
    return v;
}

std::string toggle_confirm(const std::string& html, std::size_t index) {
    return confirm_of(html, "auto-approve/" + std::to_string(index) + "/toggle\"");
}
std::string remove_confirm_of(const std::string& html, std::size_t index) {
    return confirm_of(html, "hx-delete=\"/api/settings/auto-approve/" + std::to_string(index) + "\"");
}

// The confirm text names the rule's value, so the operator confirms THIS rule.
std::string enable_widens(const std::string& v) {
    return "Enable rule \"" + v + "\"? Matching agents will join without approval.";
}
std::string enable_narrows(const std::string& v) {
    return "Require rule \"" + v + "\" as well? Fewer agents will join without approval.";
}
std::string disable_last(const std::string& v) {
    return "Disable the last enabled rule \"" + v +
           "\"? No agent will join without approval until a rule is enabled.";
}
std::string disable_widens(const std::string& v) {
    return "Stop requiring rule \"" + v + "\"? More agents may join without approval.";
}
std::string remove_last(const std::string& v) {
    return "Remove rule \"" + v +
           "\"? It is the last enabled rule, so no agent will join without approval until a rule "
           "is enabled.";
}
std::string remove_widens(const std::string& v) {
    return "Remove rule \"" + v +
           "\"? It is currently required, so more agents may join without approval.";
}
std::string remove_plain(const std::string& v) {
    return "Remove rule \"" + v + "\"?";
}
// rules_with() names its rules on0.. (enabled) then off0.. (disabled).
std::string on(std::size_t i) { return "on" + std::to_string(i); }
std::string off(std::size_t i) { return "off" + std::to_string(i); }

} // namespace

// In "any" mode enabling widens and disabling narrows. The enabled-rule count does not matter.
TEST_CASE("enrolment rules: any mode confirm copy ignores the enabled count",
          "[groups][enrolment][render]") {
    for (std::size_t enabled : {0u, 1u, 3u}) {
        INFO("enabled=" << enabled);
        const auto html = render_auto_approve(rules_with(enabled, 1), false);
        CHECK(toggle_confirm(html, enabled) == enable_widens(off(0))); // the disabled rule
        CHECK(remove_confirm_of(html, enabled) == remove_plain(off(0)));
        if (enabled > 0) {
            CHECK(toggle_confirm(html, 0).empty()); // disabling narrows: no confirm
            CHECK(remove_confirm_of(html, 0) == remove_plain(on(0)));
        }
        CHECK_THAT(html, !ContainsSubstring("Stop requiring"));
        CHECK_THAT(html, !ContainsSubstring("Require rule"));
    }
}

// In "all" mode every enabled rule is required, so the engine admits nobody while NONE is
// enabled: enabling the first rule widens from nobody, and removing or disabling the last
// enabled rule leaves nobody admitted. "Fewer agents" / "More agents" are false at those ends.
TEST_CASE("enrolment rules: all mode confirm copy follows the number of enabled rules",
          "[groups][enrolment][render]") {
    SECTION("zero enabled: enabling the first rule widens admission") {
        const auto html = render_auto_approve(rules_with(0, 2), true);
        CHECK(toggle_confirm(html, 0) == enable_widens(off(0)));
        CHECK(toggle_confirm(html, 1) == enable_widens(off(1)));
        CHECK(remove_confirm_of(html, 0) == remove_plain(off(0))); // a disabled rule is not required
        CHECK_THAT(html, !ContainsSubstring("Require rule"));
    }
    SECTION("one enabled: it is the last, the other enables narrow") {
        const auto html = render_auto_approve(rules_with(1, 1), true);
        CHECK(toggle_confirm(html, 0) == disable_last(on(0)));
        CHECK(remove_confirm_of(html, 0) == remove_last(on(0)));
        CHECK(toggle_confirm(html, 1) == enable_narrows(off(0)));
        CHECK(remove_confirm_of(html, 1) == remove_plain(off(0)));
        CHECK_THAT(html, !ContainsSubstring("Stop requiring"));
        CHECK_THAT(html, !ContainsSubstring("It is currently required"));
    }
    SECTION("several enabled: disabling or removing one widens, enabling another narrows") {
        const auto html = render_auto_approve(rules_with(3, 1), true);
        for (std::size_t i = 0; i < 3; ++i) {
            CHECK(toggle_confirm(html, i) == disable_widens(on(i)));
            CHECK(remove_confirm_of(html, i) == remove_widens(on(i)));
        }
        CHECK(toggle_confirm(html, 3) == enable_narrows(off(0)));
        CHECK(remove_confirm_of(html, 3) == remove_plain(off(0)));
        CHECK_THAT(html, !ContainsSubstring("last enabled rule"));
    }
}

// The list position alone shifts under a concurrent edit, so each Toggle and Remove carries the
// rule it was rendered for (type, value, and for a toggle the enabled state it saw) and the
// route verifies it against the rule now at that index.
TEST_CASE("enrolment rules: Toggle and Remove carry the rule identity they were rendered for",
          "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const std::vector<auth::AutoApproveRule> v = {
        {T::hostname_glob, "EDI-*", "edinburgh", true},
        {T::ip_subnet, "10.0.0.0/8", "lan", false},
    };
    const auto html = render_auto_approve(v, false);
    const auto vals_of = [&](const std::string& anchor) {
        const auto at = html.find(anchor);
        REQUIRE(at != std::string::npos);
        const auto end = html.find("</button>", at);
        const auto attr = html.find(" hx-vals=\"", at);
        REQUIRE(attr != std::string::npos);
        REQUIRE(attr < end);
        const auto from = attr + std::string(" hx-vals=\"").size();
        return html.substr(from, html.find('"', from) - from);
    };
    CHECK(vals_of("auto-approve/0/toggle\"") ==
          "{&quot;type&quot;:&quot;hostname_glob&quot;,&quot;value&quot;:&quot;EDI-*&quot;,"
          "&quot;enabled&quot;:&quot;1&quot;}");
    CHECK(vals_of("auto-approve/1/toggle\"") ==
          "{&quot;type&quot;:&quot;ip_subnet&quot;,&quot;value&quot;:&quot;10.0.0.0/8&quot;,"
          "&quot;enabled&quot;:&quot;0&quot;}");
    // Remove states the rule but not its enabled state (a remove acts on the rule either way).
    CHECK(vals_of("hx-delete=\"/api/settings/auto-approve/0\"") ==
          "{&quot;type&quot;:&quot;hostname_glob&quot;,&quot;value&quot;:&quot;EDI-*&quot;}");
    CHECK(vals_of("hx-delete=\"/api/settings/auto-approve/1\"") ==
          "{&quot;type&quot;:&quot;ip_subnet&quot;,&quot;value&quot;:&quot;10.0.0.0/8&quot;}");
}

// A value is operator text: it is JSON-escaped first and then HTML-escaped, so it can neither
// close the JSON string and add a key, nor close the attribute.
TEST_CASE("enrolment rules: a hostile value stays inside its hx-vals string and attribute",
          "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const std::vector<auth::AutoApproveRule> v = {
        {T::hostname_glob, "a\"b\\c<img src=x onerror=1>&'", "", true}};
    const auto html = render_auto_approve(v, false);
    // JSON-escaped first (a\" and \\), then HTML-escaped (" -> &quot; and so on).
    CHECK_THAT(html, ContainsSubstring("&quot;value&quot;:&quot;a\\&quot;b\\\\c&lt;img src=x "
                                       "onerror=1&gt;&amp;&#39;&quot;"));
    CHECK_THAT(html, !ContainsSubstring("<img src=x"));
    // The attribute count is unchanged: no injected attribute.
    CHECK(count_of(html, " hx-vals=\"") == 3); // mode switch + Toggle + Remove
}

// In "all" mode every enabled rule must match, and a CA fingerprint rule never matches at this
// release, so an enabled one means no agent is ever auto-approved. The page says so where the
// operator creates that state (the mode switch, the Enable) and while it holds.
TEST_CASE("enrolment rules: an enabled CA fingerprint rule in all mode says nobody is auto-approved",
          "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const std::string sentence =
        "A CA fingerprint rule never matches at this release, so while all enabled rules must "
        "match no agent is auto-approved.";
    const std::vector<auth::AutoApproveRule> enabled_ca = {
        {T::hostname_glob, "a.corp", "", true}, {T::trusted_ca, std::string(64, 'a'), "", true}};
    const std::vector<auth::AutoApproveRule> disabled_ca = {
        {T::hostname_glob, "a.corp", "", true}, {T::trusted_ca, std::string(64, 'a'), "", false}};

    // The note is on the page only while it is true: all mode AND an enabled CA rule. (The
    // sentence also rides in the confirms below, so the note is told apart by its element.)
    const std::string note = "<div class=\"note warn\" role=\"note\">" + sentence;
    const auto all = render_auto_approve(enabled_ca, true);
    CHECK_THAT(all, ContainsSubstring(note));
    CHECK_THAT(render_auto_approve(enabled_ca, false), !ContainsSubstring("role=\"note\""));
    CHECK_THAT(render_auto_approve(disabled_ca, true), !ContainsSubstring("role=\"note\""));
    CHECK_THAT(render_auto_approve({{T::hostname_glob, "a.corp", "", true}}, true),
               !ContainsSubstring(sentence));

    // Switching to all mode with a CA rule enabled warns in the confirm.
    const auto any = render_auto_approve(enabled_ca, false);
    CHECK_THAT(any, ContainsSubstring("hx-confirm=\"Require every enabled rule to match? " + sentence));
    CHECK_THAT(render_auto_approve(disabled_ca, false),
               !ContainsSubstring("Require every enabled rule to match? A CA"));

    // Enabling the CA rule in all mode warns instead of the generic narrowing text.
    CHECK(toggle_confirm(render_auto_approve(disabled_ca, true), 1) ==
          "Require rule \"" + std::string(64, 'a') + "\" as well? " + sentence);
    // ... and a non-CA rule keeps its own copy.
    CHECK(toggle_confirm(render_auto_approve(rules_with(1, 1), true), 1) ==
          enable_narrows(off(0)));
}

TEST_CASE("enrolment rules: add form keeps the field names; blocks colons; no inline handlers",
          "[groups][enrolment][render]") {
    const std::vector<auth::AutoApproveRule> none;
    const auto html = render_auto_approve(none, false);
    for (const char* n : {"name=\"type\"", "name=\"value\"", "name=\"label\""})
        CHECK_THAT(html, ContainsSubstring(n));
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/auto-approve\""));
    CHECK_THAT(html, ContainsSubstring("data-rule-form"));
    // The static floor under the client-built Add confirm covers every agent-stated type.
    CHECK_THAT(html, ContainsSubstring("Hostnames and cloud providers are reported by the agent "
                                       "and are not verified."));
    CHECK_THAT(html, ContainsSubstring("A CA fingerprint rule never matches at this release."));
    CHECK_THAT(html, ContainsSubstring("pattern=\"[^:]*\""));
    // The advertised maxlength is the validator's own bound, not a hand-copied 256.
    const auto in_input = [&](const std::string& id) {
        const auto at = html.find("id=\"" + id + "\"");
        REQUIRE(at != std::string::npos);
        return html.substr(at, html.find('>', at) - at);
    };
    CHECK_THAT(in_input("rule-value"),
               ContainsSubstring("maxlength=\"" + std::to_string(auth::kMaxRuleValueLen) + "\""));
    CHECK_THAT(in_input("rule-label"),
               ContainsSubstring("maxlength=\"" + std::to_string(auth::kMaxRuleLabelLen) + "\""));
    CHECK(auth::kMaxRuleValueLen == 253);
    CHECK(auth::kMaxRuleLabelLen == 128);
    for (const char* bad : {"onclick", "onchange", "hx-on", "style=\"", "feedback-error",
                            "user-table", "mini-field"})
        CHECK_THAT(html, !ContainsSubstring(bad));
}

TEST_CASE("enrolment rules: operator text is escaped", "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const std::vector<auth::AutoApproveRule> v = {{T::hostname_glob, kXss, kXss, true}};
    const auto html = render_auto_approve(v, false);
    CHECK_THAT(html, !ContainsSubstring("<img src=x"));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
}
