/**
 * @file test_groups_enrolment_render.cpp
 * @brief Pure-renderer tests for the three enrolment fragments (enrolment_render.hpp): tokens,
 *        agents waiting for approval, auto-approve rules. No store, no socket, no clock: `now`
 *        is injected, so "Expired" is decidable without a wait.
 *
 * What these pin: the three states stay distinct (populated / empty / store did not answer),
 * every agent- or operator-supplied string is escaped, the bulk actions are off whenever the
 * list is not whole, the rule copy is honest about what is matched, and the confirm text
 * follows the match mode (in "all" mode enabling narrows and removing widens).
 */

#include "enrolment_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
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

TEST_CASE("enrolment tokens: an unanswered store is a failbox, never an empty table",
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

TEST_CASE("enrolment tokens: reveal block has Copy and Done, secret escaped, no timer",
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
    // Both limits empty: the unlimited warning is on screen by default.
    CHECK_THAT(html, ContainsSubstring("data-token-unlimited"));
    CHECK_THAT(html, ContainsSubstring("Anyone holding this token can enrol agents indefinitely"));
}

TEST_CASE("enrolment tokens: Active, Expired, Exhausted and Revoked are distinct states",
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

TEST_CASE("enrolment tokens: expiry is a UTC date, never raw epoch seconds",
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

TEST_CASE("enrolment pending: empty, and approved rows are never shown",
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
    CHECK_THAT(html, ContainsSubstring("hx-confirm=\"Deny agent enrollment?\""));
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
    CHECK_THAT(html, ContainsSubstring("Address the server sees matches <code>10.0.0.0/8</code>"));
    CHECK_THAT(html, ContainsSubstring("Agent CA fingerprint <code>abc123</code>"));
    CHECK_THAT(html, ContainsSubstring("Attestation provider <code>aws</code>"));
    CHECK_THAT(html, ContainsSubstring("Address rules match IPv4 only."));
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

TEST_CASE("enrolment rules: enable, disable and remove copy follows the match mode",
          "[groups][enrolment][render]") {
    using T = auth::AutoApproveRuleType;
    const std::vector<auth::AutoApproveRule> v = {
        {T::hostname_glob, "on-rule", "", true},
        {T::hostname_glob, "off-rule", "", false},
    };
    // any mode: enabling widens (confirm); disabling narrows (no confirm); remove keeps its text.
    const auto any = render_auto_approve(v, false);
    CHECK_THAT(any, ContainsSubstring("Enable this rule? Matching agents join without approval."));
    CHECK_THAT(any, !ContainsSubstring("Stop requiring this rule?"));
    CHECK_THAT(any, ContainsSubstring("hx-confirm=\"Remove this auto-approve rule?\""));
    // all mode: enabling narrows, disabling and removing an enabled rule widen.
    const auto all = render_auto_approve(v, true);
    CHECK_THAT(all, ContainsSubstring("Require this rule as well? Fewer agents will join without approval."));
    CHECK_THAT(all, ContainsSubstring("Stop requiring this rule? More agents may join without approval."));
    CHECK_THAT(all, ContainsSubstring("It is currently required, so more agents may join without approval."));
    // The disabled rule is not required: removing it widens nothing.
    CHECK(count_of(all, "It is currently required") == 1);
}

TEST_CASE("enrolment rules: add form keeps the field names, blocks colons, no inline handlers",
          "[groups][enrolment][render]") {
    const std::vector<auth::AutoApproveRule> none;
    const auto html = render_auto_approve(none, false);
    for (const char* n : {"name=\"type\"", "name=\"value\"", "name=\"label\""})
        CHECK_THAT(html, ContainsSubstring(n));
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/auto-approve\""));
    CHECK_THAT(html, ContainsSubstring("data-rule-form"));
    CHECK_THAT(html, ContainsSubstring("Hostnames are reported by the agent and are not verified."));
    CHECK_THAT(html, ContainsSubstring("pattern=\"[^:]*\""));
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
