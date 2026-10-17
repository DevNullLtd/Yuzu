/**
 * @file test_developer_writes.cpp
 * @brief System > Developer and API Load generator (SYS-6): the page markup and
 *        yuzu-developer.js pinned as text. Start and Stop are the only dispatch on any System
 *        page and reuse POST /api/command; these tests hold the script to that: a fixed
 *        (plugin, action) table, a body of exactly those two keys, no response markup read,
 *        no /events, no second route. No store, no browser, no process.
 */

#include "developer_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>

namespace yuzu::server {
extern const std::string kYuzuDeveloperJs;
extern const std::string kYuzuSystemJs;
} // namespace yuzu::server
extern const char* const kSettingsDeveloperHtml;

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;

namespace {

bool has(const std::string& h, const std::string& n) { return h.find(n) != std::string::npos; }

std::size_t count_of(const std::string& h, const std::string& n) {
    std::size_t c = 0;
    for (auto p = h.find(n); p != std::string::npos; p = h.find(n, p + n.size()))
        ++c;
    return c;
}

} // namespace

TEST_CASE("developer writes: the page adds no route; dispatch stays on the existing /api/command",
          "[system_writes][developer][security]") {
    test::TestRouteSink sink;
    developer::Deps deps;
    deps.admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
    deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    developer::register_developer_routes(sink, std::move(deps));

    // Every route the module registers is a GET. A write needs no route of its own here.
    for (const char* path :
         {"/settings/developer", "/fragments/settings/developer/api", "/fragments/settings/developer/routes",
          "/fragments/settings/developer/permissions", "/fragments/settings/developer/plugins",
          "/fragments/settings/developer/plugins/observed", "/api/command", "/api/chargen/start",
          "/api/chargen/stop", "/api/procfetch/fetch"})
        for (const char* method : {"POST", "PUT", "DELETE", "PATCH"}) {
            INFO(std::string(method) + " " + path);
            CHECK(sink.dispatch(method, path, "{}") == nullptr);
        }
}

TEST_CASE("developer writes: the Load generator panel is static copy with two buttons",
          "[system_writes][developer][ui]") {
    const std::string html = kSettingsDeveloperHtml;
    CHECK_THAT(html, ContainsSubstring("<h2 id=\"dev-load-h\">Load generator</h2>"));
    CHECK_THAT(html, ContainsSubstring("For testing only"));
    CHECK_THAT(html, ContainsSubstring("id=\"dev-chargen-start\""));
    CHECK_THAT(html, ContainsSubstring("id=\"dev-chargen-stop\""));
    CHECK_THAT(html, ContainsSubstring("It does not simulate devices."));
    // The scope is stated before the click, on the panel itself.
    CHECK_THAT(html, ContainsSubstring("every connected device you can see"));
    // Nothing the code cannot do is drawn: no State, no Simulated agents, no rate or scope field.
    for (const char* never : {"Simulated agents", "Stopped", "rate_ms", "name=\"scope\"", "agent_ids",
                              "Process data fetch", "Fetch process data"})
        CHECK_FALSE(has(html, never));
    // The markup names no route and opens no stream; the script owns both facts.
    CHECK_FALSE(has(html, "/api/command"));
    CHECK_FALSE(has(html, "/events"));
    CHECK_FALSE(has(html, "hx-on"));
}

TEST_CASE("developer writes: dialog, helper and controller load in that order",
          "[system_writes][developer][ui]") {
    const std::string html = kSettingsDeveloperHtml;
    const auto d = html.find("/static/yuzu-dialog.js");
    const auto s = html.find("/static/yuzu-system.js");
    const auto c = html.find("/static/yuzu-developer.js");
    REQUIRE(d != std::string::npos);
    REQUIRE(s != std::string::npos);
    REQUIRE(c != std::string::npos);
    CHECK(d < s);
    CHECK(s < c);
}

TEST_CASE("developer script: no markup sink, no stream, no storage, no timer",
          "[system_writes][developer][ui][security]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    REQUIRE(js.size() > 1000);
    for (const char* sink : {"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function(",
                             "document.write", "javascript:", "setTimeout", "setInterval", "hx-on",
                             "localStorage", "sessionStorage", "console.", "EventSource", "/events"})
        CHECK_FALSE(has(js, sink));
}

TEST_CASE("developer script: the (plugin, action) pairs are a fixed table keyed by button id",
          "[system_writes][developer][security]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    CHECK(has(js, "'dev-chargen-start': { plugin: 'chargen', action: 'chargen_start', confirm: true },"));
    CHECK(has(js, "'dev-chargen-stop': { plugin: 'chargen', action: 'chargen_stop', confirm: false }"));
    CHECK(has(js, "Object.prototype.hasOwnProperty.call(TABLE, btn.id)"));
    // The pair is read only from the table; never from an attribute, the URL or a response.
    CHECK_FALSE(has(js, "getAttribute('data-plugin')"));
    CHECK_FALSE(has(js, "getAttribute('data-action')"));
    CHECK_FALSE(has(js, "location."));
    CHECK_FALSE(has(js, "URLSearchParams"));
    CHECK(count_of(js, "plugin: '") == 2);
    CHECK(count_of(js, "action: '") == 2);
}

TEST_CASE("developer script: the body is exactly {plugin, action} to POST /api/command",
          "[system_writes][developer][security]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    CHECK(has(js, "S.send('POST', '/api/command', { json: { plugin: spec.plugin, action: spec.action } })"));
    CHECK(count_of(js, "S.send(") == 1);
    // None of the optional targeting or pacing keys can reach the request.
    for (const char* key : {"params", "agent_ids", "scope", "stagger", "delay", "rate_ms"}) {
        INFO(key);
        // The header comment names them as "never sent"; the code must not use them as keys.
        CHECK_FALSE(has(js, std::string(key) + ":"));
        CHECK_FALSE(has(js, "." + std::string(key)));
    }
    // The legacy diagnostics routes are never called.
    CHECK_FALSE(has(js, "/api/chargen"));
    CHECK_FALSE(has(js, "/api/procfetch"));
}

TEST_CASE("developer script: only counts are read from the response; thead_html never is",
          "[system_writes][developer][security]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    CHECK_FALSE(has(js, "thead_html"));
    CHECK(has(js, "d.agents_reached"));
    CHECK(has(js, "'withheld_quarantined'"));
    CHECK(has(js, "'withheld_unknown_plugin'"));
    CHECK(has(js, "'withheld_kill_switched_os'"));
    CHECK(has(js, "Number.isInteger(d.agents_reached) ? d.agents_reached : 0"));
    // "Sent" never claims running or stopped.
    CHECK(has(js, "'Sent to ' + n"));
    CHECK(has(js, "The action was sent but its audit record could not be written."));
}

TEST_CASE("developer script: Start confirms with the scope and volume disclosure, Stop does not",
          "[system_writes][developer][ui]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    CHECK(has(js, "title: 'Start the load generator on every device?'"));
    CHECK(has(js, "Every connected device you can see will start streaming test text to the server, about 10 lines a second each, until you stop it."));
    CHECK(has(js, "every open Dashboard will receive the rows."));
    CHECK(has(js, "A device that is already running restarts its session."));
    CHECK(has(js, "submitLabel: 'Start on all devices'"));
    // Stop is the safety action: it sends at once and reports its result.
    CHECK(has(js, "if (!spec.confirm) {"));
}

TEST_CASE("developer script: a second click is ignored and both buttons are disabled in flight",
          "[system_writes][developer]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    CHECK(has(js, "if (busy) return;"));
    CHECK(has(js, "setButtons(true, 'Waiting for the server.');"));
    // Both buttons come from the same table, so neither can be left live.
    CHECK(has(js, "Object.keys(TABLE).forEach(function (id) {"));
    // The dialog's own buttons are disabled while its submit() is pending (yuzu-dialog.js).
    CHECK(has(js, "submit: function () {"));
}

TEST_CASE("developer script: a lapsed session and a server refusal are shown, never bypassed",
          "[system_writes][developer][security]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    // 401 -> the sign-in sentence (YuzuSystem.failText); 403/503 -> the server's own text.
    CHECK(has(js, "say(S.failText(res), 'dev-err');"));
    CHECK(has(yuzu::server::kYuzuSystemJs, "if (res.status === 401) return 'Your session has ended. Sign in again.';"));
    // No retry loop, no escalation offer, no alternative route.
    CHECK_FALSE(has(js, "retry"));
    CHECK_FALSE(has(js, "approve"));
}

TEST_CASE("developer script: the online count is the shell's own unauthenticated read",
          "[system_writes][developer][ui]") {
    const auto& js = yuzu::server::kYuzuDeveloperJs;
    CHECK(has(js, "fetch('/api/health', opts)"));
    CHECK(has(js, "var opts = { credentials: 'omit', cache: 'no-store' };"));
    CHECK(has(js, "d.agents ? d.agents.online : null"));
    CHECK(has(js, "' (connected to this server)'"));
    // No devices: the buttons are disabled with the reason. An unreadable count never blocks.
    CHECK(has(js, "setButtons(n === 0, n === 0 ? 'No device is connected.' : '');"));
    CHECK(has(js, "if (out) out.textContent = 'Unknown';"));
    CHECK(has(js, "setButtons(false, '');"));
}
