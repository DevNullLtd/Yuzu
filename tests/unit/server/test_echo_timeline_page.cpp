/**
 * @file test_echo_timeline_page.cpp
 * @brief The hidden Echo timeline page shell and string pins on its interaction script.
 *
 * The shell is pure text (token substitution over a baked template), so it is pinned
 * directly. The script is run under node by tests/test_echo_timeline_script_behaviour.py;
 * these pins prove the things a run cannot: which sinks and globals the file never uses.
 */

#include "app_shell.hpp"
#include "echo_timeline_page_ui.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>

namespace yuzu::server {
extern const std::string kYuzuEchoTimelineJs;
}

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;

namespace {

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

const std::string& js() { return kYuzuEchoTimelineJs; }

/// The page without the shell chrome block (sidebar, header, their CSS and script), which is
/// not this page's markup and has its own pins.
std::string page_only(const std::string& html) {
    const auto b = html.find(shell::kShellBegin);
    const auto e = html.find(shell::kShellEnd);
    REQUIRE(b != std::string::npos);
    REQUIRE(e != std::string::npos);
    return html.substr(0, b) + html.substr(e);
}

} // namespace

TEST_CASE("echo timeline page: one shell block, Posture / Echo / Timeline, one CSS link, no inline CSS",
          "[echo][timeline][page]") {
    const std::string html = render_echo_timeline_page("agent-1", "");
    CHECK(count_of(html, std::string{shell::kShellBegin}) == 1);
    CHECK(count_of(html, std::string{shell::kShellEnd}) == 1);
    // The marker pair was filled: the chrome sits between the markers.
    const auto b = html.find(shell::kShellBegin);
    const auto e = html.find(shell::kShellEnd);
    REQUIRE(b != std::string::npos);
    REQUIRE(e != std::string::npos);
    CHECK(e - b > 1000);
    // The rendered chrome, not the helper that builds it: Posture / Echo / Timeline, Echo lit.
    CHECK_THAT(html, ContainsSubstring("<nav class=\"shell-crumb\" aria-label=\"Breadcrumb\"><span>Posture</span>"
                                       "<span class=\"shell-sep\">/</span><span>Echo</span>"
                                       "<span class=\"shell-sep\">/</span><b>Timeline</b></nav>"));
    CHECK_THAT(html, ContainsSubstring("<a class=\"shell-nav on\" href=\"/echo\" aria-current=\"page\">"));
    CHECK(count_of(html, "<link rel=\"stylesheet\" href=\"/static/yuzu.css\">") == 1);
    CHECK(count_of(html, "<script src=\"/static/htmx.js\"></script>") == 1);
    CHECK(count_of(html, "<script src=\"/static/yuzu-echo-timeline.js\" defer></script>") == 1);
    // Exactly two scripts of the page's own, both external: no inline script beside them.
    CHECK(count_of(page_only(html), "<script") == 2);
    // The page's own markup carries no CSS and no inline handler.
    const std::string own = page_only(html);
    CHECK(count_of(own, "<style") == 0);
    CHECK(count_of(own, "hx-on") == 0);
    CHECK(count_of(own, " onclick=") == 0);
    // Echo is the lit nav item.
    CHECK_THAT(html, ContainsSubstring("<title>Yuzu — Echo timeline</title>"));
}

TEST_CASE("echo timeline page: links and fragment URLs", "[echo][timeline][page]") {
    const std::string html = render_echo_timeline_page("agent-1", "");
    CHECK_THAT(html, ContainsSubstring("href=\"/hardware/ci?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("href=\"/echo#frame-process-tree\""));
    CHECK_THAT(html, ContainsSubstring("href=\"/echo\""));
    CHECK_THAT(html, ContainsSubstring("data-moment-url=\"/fragments/echo/timeline/moment?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("data-selected-url=\"/fragments/echo/timeline/selected?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/echo/timeline/run?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("hx-trigger=\"load\""));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-moment\""));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-selected\""));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-copy\""));
    CHECK(count_of(html, "{{") == 0);
}

TEST_CASE("echo timeline page: the agent id is percent-encoded, at only when it is digits",
          "[echo][timeline][page]") {
    const std::string hostile = "a\"b<c>&d/e?f#g";
    const std::string enc = url_query_value(hostile);
    const std::string html = render_echo_timeline_page(hostile, "");
    CHECK(count_of(html, "id=" + enc) == 4); // run, moment, selected, device link
    const std::string own = page_only(html);
    CHECK_THAT(own, !ContainsSubstring("a\"b"));
    CHECK_THAT(own, !ContainsSubstring("<c>"));
    CHECK_THAT(own, !ContainsSubstring("&d"));

    const std::string with_at = render_echo_timeline_page("agent-1", "1792486800");
    CHECK(count_of(with_at, "&at=1792486800") == 1);
    CHECK_THAT(with_at, ContainsSubstring("run?id=agent-1&at=1792486800\""));
    for (const std::string& bad : {std::string{"17x"}, std::string(25, '1'), std::string{"-5"},
                                  std::string{"1 2"}, std::string{"1\"onload=x"}}) {
        INFO(bad);
        CHECK(count_of(render_echo_timeline_page("agent-1", bad), "&at=") == 0);
    }
}

TEST_CASE("echo timeline page: playback controls and honest copy", "[echo][timeline][page]") {
    const std::string html = render_echo_timeline_page("agent-1", "");
    CHECK_THAT(html, ContainsSubstring("UTC"));
    // Play and Speed start disabled; the script enables them for a bound, valid, short window.
    CHECK_THAT(html, ContainsSubstring(
        "<button class=\"btn play\" id=\"tl-play\" type=\"button\" aria-pressed=\"false\" disabled>Play</button>"));
    CHECK_THAT(html, ContainsSubstring(
        "<button class=\"btn\" id=\"tl-speed\" type=\"button\" disabled>Speed 1x</button>"));
    // The button's own text names it (a label that differs from the text would hide the speed).
    CHECK_THAT(html, !ContainsSubstring("aria-label=\"Playback speed\""));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-play-note\""));
    CHECK_THAT(html, ContainsSubstring(
        "Play moves the moment line through the record already loaded; it does not show live data."));
    CHECK_THAT(html, ContainsSubstring("Drag the moment line, click the timeline,"));
    // The line is not yellow in every colour scheme.
    CHECK_THAT(page_only(html), !ContainsSubstring("yellow"));
    // No Slow pill, incident controls, story, user or fleet text on this page.
    const std::string own = page_only(html);
    for (const char* banned : {"Slow", "incident", "Story", "signed in", "fleet", "hx-on"}) {
        INFO(banned);
        CHECK(count_of(own, banned) == 0);
    }
}

TEST_CASE("echo timeline script: pinned tokens present", "[echo][timeline][js]") {
    for (const char* want :
         {"'use strict'", "typeof module", "module.exports", "typeof document === 'undefined'", "fetch(",
          "credentials: 'same-origin'", "AbortController", "setPointerCapture", "data-tl-bound", "data-ts",
          "data-from", "data-ref", "location.origin", "calc(var(--gut) + (100% - var(--gut)) * ",
          "aria-pressed", "visibilitychange", "htmx:afterSettle", "htmx:responseError", "htmx:sendError",
          "htmx:timeout", "'HX-Request': 'true'", "res.redirected", "assign('/login')", "performance.now()"}) {
        INFO(want);
        CHECK_THAT(js(), ContainsSubstring(want));
    }
}

TEST_CASE("echo timeline script: one markup sink, no eval, storage, console or absolute URL",
          "[echo][timeline][js]") {
    CHECK(count_of(js(), "innerHTML") == 1);
    for (const char* bad :
         {"hx-on", "eval(", "new Function", "document.write", "outerHTML", "insertAdjacentHTML",
          "localStorage", "sessionStorage", "XMLHttpRequest", "console.", "history.", "http://", "https://",
          "execCommand", "indexedDB", "postMessage", "sendBeacon", "javascript:", " onclick"}) {
        INFO(bad);
        CHECK_THAT(js(), !ContainsSubstring(bad));
    }
}

TEST_CASE("echo timeline script: playback is bounded by named limits, not open-ended timers",
          "[echo][timeline][js]") {
    // One playback interval and no other timer.
    CHECK(count_of(js(), "env.setInterval(") == 1);
    CHECK(count_of(js(), "env.clearInterval(") == 1);
    CHECK(count_of(js(), "env.setTimeout(") == 0);
    CHECK(count_of(js(), "requestAnimationFrame") == 0);
    CHECK_THAT(js(), ContainsSubstring("THROTTLE_MS = 1000"));
}
