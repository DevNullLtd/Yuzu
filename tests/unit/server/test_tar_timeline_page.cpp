/**
 * @file test_tar_timeline_page.cpp
 * @brief The hidden TAR timeline page shell and string pins on its interaction script.
 *
 * The shell is pure text (token substitution over a baked template), so it is pinned
 * directly. The script is run under node by tests/test_tar_timeline_script_behaviour.py;
 * these pins prove the things a run cannot: which sinks and globals the file never uses.
 */

#include "app_shell.hpp"
#include "tar_timeline_page_ui.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuTarTimelineJs;
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

const std::string& js() { return kYuzuTarTimelineJs; }

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

TEST_CASE("tar timeline page: one shell block, Posture / TAR / Timeline, one CSS link, no inline CSS",
          "[tar][timeline][page]") {
    const std::string html = render_tar_timeline_page("agent-1", "");
    CHECK(count_of(html, std::string{shell::kShellBegin}) == 1);
    CHECK(count_of(html, std::string{shell::kShellEnd}) == 1);
    // The marker pair was filled: the chrome sits between the markers.
    const auto b = html.find(shell::kShellBegin);
    const auto e = html.find(shell::kShellEnd);
    REQUIRE(b != std::string::npos);
    REQUIRE(e != std::string::npos);
    CHECK(e - b > 1000);
    CHECK(shell::breadcrumb_trail({.active_key = "tar", .title = "Timeline"}) ==
          std::vector<std::string>{"Posture", "TAR", "Timeline"});
    CHECK(count_of(html, "<link rel=\"stylesheet\" href=\"/static/yuzu.css\">") == 1);
    CHECK(count_of(html, "<script src=\"/static/htmx.js\"></script>") == 1);
    CHECK(count_of(html, "<script src=\"/static/yuzu-tar-timeline.js\" defer></script>") == 1);
    // The page's own markup carries no CSS and no inline handler.
    const std::string own = page_only(html);
    CHECK(count_of(own, "<style") == 0);
    CHECK(count_of(own, "hx-on") == 0);
    CHECK(count_of(own, " onclick=") == 0);
    // TAR is the lit nav item.
    CHECK_THAT(html, ContainsSubstring("<title>Yuzu — TAR timeline</title>"));
}

TEST_CASE("tar timeline page: links and fragment URLs", "[tar][timeline][page]") {
    const std::string html = render_tar_timeline_page("agent-1", "");
    CHECK_THAT(html, ContainsSubstring("href=\"/hardware/ci?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("href=\"/tar#frame-process-tree\""));
    CHECK_THAT(html, ContainsSubstring("href=\"/tar\""));
    CHECK_THAT(html, ContainsSubstring("data-moment-url=\"/fragments/tar/timeline/moment?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("data-selected-url=\"/fragments/tar/timeline/selected?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/tar/timeline/run?id=agent-1\""));
    CHECK_THAT(html, ContainsSubstring("hx-trigger=\"load\""));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-moment\""));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-selected\""));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-copy\""));
    CHECK(count_of(html, "{{") == 0);
}

TEST_CASE("tar timeline page: the agent id is percent-encoded, at only when it is digits",
          "[tar][timeline][page]") {
    const std::string hostile = "a\"b<c>&d/e?f#g";
    const std::string enc = url_query_value(hostile);
    const std::string html = render_tar_timeline_page(hostile, "");
    CHECK(count_of(html, "id=" + enc) == 4); // run, moment, selected, device link
    const std::string own = page_only(html);
    CHECK_THAT(own, !ContainsSubstring("a\"b"));
    CHECK_THAT(own, !ContainsSubstring("<c>"));
    CHECK_THAT(own, !ContainsSubstring("&d"));

    const std::string with_at = render_tar_timeline_page("agent-1", "1792486800");
    CHECK(count_of(with_at, "&at=1792486800") == 1);
    CHECK_THAT(with_at, ContainsSubstring("run?id=agent-1&at=1792486800\""));
    for (const std::string& bad : {std::string{"17x"}, std::string(25, '1'), std::string{"-5"},
                                  std::string{"1 2"}, std::string{"1\"onload=x"}}) {
        INFO(bad);
        CHECK(count_of(render_tar_timeline_page("agent-1", bad), "&at=") == 0);
    }
}

TEST_CASE("tar timeline page: playback controls and honest copy", "[tar][timeline][page]") {
    const std::string html = render_tar_timeline_page("agent-1", "");
    CHECK_THAT(html, ContainsSubstring("UTC"));
    // Play and Speed start disabled; the script enables them for a bound, valid, short window.
    CHECK_THAT(html, ContainsSubstring(
        "<button class=\"btn play\" id=\"tl-play\" type=\"button\" aria-pressed=\"false\" disabled>Play</button>"));
    CHECK_THAT(html, ContainsSubstring(
        "<button class=\"btn\" id=\"tl-speed\" type=\"button\" aria-label=\"Playback speed\" disabled>Speed 1x</button>"));
    CHECK_THAT(html, ContainsSubstring("id=\"tl-play-note\""));
    CHECK_THAT(html, ContainsSubstring(
        "Play moves the yellow line through the record already loaded; it does not show live data."));
    // No Slow pill, incident controls, story, user or fleet text on this page.
    const std::string own = page_only(html);
    for (const char* banned : {"Slow", "incident", "Story", "signed in", "fleet", "hx-on"}) {
        INFO(banned);
        CHECK(count_of(own, banned) == 0);
    }
}

TEST_CASE("tar timeline page: every template piece is under the MSVC literal cap",
          "[tar][timeline][page]") {
    for (const auto part : tar_timeline_page_parts())
        CHECK(part.size() < 16000);
    CHECK(tar_timeline_page_parts().size() >= 2);
}

TEST_CASE("tar timeline script: pinned tokens present", "[tar][timeline][js]") {
    for (const char* want :
         {"'use strict'", "typeof module", "module.exports", "typeof document === 'undefined'", "fetch(",
          "credentials: 'same-origin'", "AbortController", "setPointerCapture", "data-tl-bound", "data-ts",
          "data-from", "data-ref", "location.origin", "calc(var(--gut) + (100% - var(--gut)) * ",
          "aria-pressed", "visibilitychange", "htmx:afterSettle", "htmx:responseError"}) {
        INFO(want);
        CHECK_THAT(js(), ContainsSubstring(want));
    }
}

TEST_CASE("tar timeline script: one markup sink, no eval, storage, console or absolute URL",
          "[tar][timeline][js]") {
    CHECK(count_of(js(), "innerHTML") == 1);
    for (const char* bad :
         {"hx-on", "eval(", "new Function", "document.write", "outerHTML", "insertAdjacentHTML",
          "localStorage", "sessionStorage", "XMLHttpRequest", "console.", "history.", "http://", "https://",
          "execCommand", "indexedDB", "postMessage", "sendBeacon", "javascript:", " onclick"}) {
        INFO(bad);
        CHECK_THAT(js(), !ContainsSubstring(bad));
    }
}

TEST_CASE("tar timeline script: playback is bounded by named limits, not open-ended timers",
          "[tar][timeline][js]") {
    // One playback interval; the only other timer is the copy label.
    CHECK(count_of(js(), "env.setInterval(") == 1);
    CHECK(count_of(js(), "env.clearInterval(") == 1);
    CHECK(count_of(js(), "env.setTimeout(") == 1);
    CHECK(count_of(js(), "requestAnimationFrame") == 0);
    CHECK_THAT(js(), ContainsSubstring("THROTTLE_MS = 1000"));
}
