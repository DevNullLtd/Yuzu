/// @file test_home_ui.cpp
/// Page pins for the landing and sign-in page (home_ui.{hpp,cpp}, login_ui.cpp):
/// the fifteen tiles with the design's exact names and sentences, the family
/// tokens, no shell (no sidebar, header bar, search, bell, badge or account
/// menu), no fragment loads, the signed-out and signed-in variants, the
/// `next` allow-list, and the redirect location the auth chokepoint uses.

#include "home_ui.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <iterator>
#include <regex>
#include <string>
#include <string_view>

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;

namespace yuzu::server {
extern const std::string kYuzuCss; // server/core/static/yuzu.css (build-time embed)
} // namespace yuzu::server

namespace {

std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

home_ui::LandingView signed_out() {
    home_ui::LandingView v;
    v.server_name = "yuzu-01";
    v.version = "0.14.1";
    return v;
}

home_ui::LandingView signed_in() {
    auto v = signed_out();
    v.who = home_ui::SignedIn{.name = "dave.rae", .role = "Administrator"};
    return v;
}

// The design's table (HANDOVER-DELTA section 1), verbatim.
struct Expected {
    const char* family;
    const char* name;
    const char* href;
    const char* sentence;
};
constexpr Expected kTable[] = {
    {"Operate", "Dashboard", "/", "Ask every device a question and watch the answers arrive."},
    {"Operate", "Instructions", "/instructions",
     "A library of questions and actions, with approval where it matters."},
    {"Operate", "Result sets", "/result-sets", "Save answers, re-run them, reuse them as targets."},
    {"Posture", "Compliance", "/compliance", "Check devices against policy and fix the ones that fail."},
    {"Posture", "Guardian", "/guardian", "Hold settings to the state you set and undo drift."},
    {"Posture", "DEX", "/dex", "See crashes, slow starts and noisy apps as users feel them."},
    {"Posture", "TAR", "/tar", "A recorded history of what ran and connected on each device."},
    {"Estate", "Devices", "/devices", "Every device, with tags, properties and quarantine."},
    {"Estate", "Hardware", "/hardware", "CPU, memory, disks and firmware across the fleet."},
    {"Estate", "Software", "/software", "What is installed, how current it is, and roll out updates."},
    {"Estate", "Fleet", "/viz/fleet", "The estate as a 3D map. Open any machine and its processes."},
    {"Access", "Users and roles", "/access/users", "Accounts, roles and directory sync."},
    {"Access", "Tokens and principals", "/access/tokens",
     "API tokens and service identities, with expiry."},
    {"Access", "Audit and reviews", "/access/audit",
     "Who did what, and checks that access is still needed."},
    {"System", "Settings", "/settings", "Appearance, sign-in, integrations, certificates and data."},
};

} // namespace

TEST_CASE("landing: fifteen tiles in five families with the design's exact names and sentences",
          "[home][ui]") {
    const auto fams = home_ui::families();
    REQUIRE(fams.size() == 5);
    std::size_t i = 0;
    for (const auto& f : fams) {
        for (const auto& s : f.screens) {
            REQUIRE(i < std::size(kTable));
            INFO(kTable[i].name);
            CHECK(f.name == kTable[i].family);
            CHECK(s.name == kTable[i].name);
            CHECK(s.href == kTable[i].href);
            CHECK(s.sentence == kTable[i].sentence);
            CHECK_FALSE(s.icon.empty());
            ++i;
        }
    }
    CHECK(i == 15);

    const auto html = home_ui::render_landing(signed_out());
    CHECK(count_of(html, "<a class=\"tile\" href=\"") == 15);
    for (const auto& row : kTable) {
        CHECK_THAT(html, ContainsSubstring(std::string("<span class=\"tt\">") + row.name + "</span>"));
        CHECK_THAT(html, ContainsSubstring(std::string("<span class=\"ts\">") + row.sentence + "</span>"));
        CHECK_THAT(html, ContainsSubstring(std::string("<a class=\"tile\" href=\"") + row.href + "\">"));
    }
    // Families two to a row where they fit: Operate 3, Posture 4, Estate 4, Access 3, System 1.
    for (const char* cls : {"f-operate", "f-posture", "f-estate", "f-access", "f-system"})
        CHECK(count_of(html, std::string("<section class=\"fam ") + cls + "\"") == 1);
    CHECK(count_of(html, "class=\"tiles n3\"") == 2);
    CHECK(count_of(html, "class=\"tiles n4\"") == 2);
    CHECK(count_of(html, "class=\"tiles n1\"") == 1);
    CHECK_THAT(html, ContainsSubstring("<h2>What you can do in Yuzu</h2>"));
    // Tile icons are 24x24 stroke paths, no second tinted square, no image.
    CHECK(count_of(html, "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"") == 15);
    CHECK(count_of(html, "<img") == 0);
}

TEST_CASE("landing: no shell, no header-bar controls, no bell, no fragment loads, no data",
          "[home][ui]") {
    for (const auto& html : {home_ui::render_landing(signed_out()), home_ui::render_landing(signed_in())}) {
        CHECK(count_of(html, "<!--yuzu:shell-->") == 0);
        CHECK(count_of(html, "<aside") == 0);
        CHECK(count_of(html, "<nav") == 0);
        CHECK(count_of(html, "shell-") == 0); // no sidebar, header, search, bell, badge, account menu
        CHECK(count_of(html, "fetch(") == 0);
        CHECK(count_of(html, "hx-get") == 0);
        CHECK(count_of(html, "hx-trigger") == 0);
        CHECK(count_of(html, "hx-on") == 0);
        CHECK(count_of(html, "/fragments/") == 0);
        CHECK(count_of(html, "/api/") == 0);
        // Nothing from the old worklist.
        CHECK(count_of(html, "home-readout") == 0);
        CHECK(count_of(html, "Needs attention") == 0);
        CHECK(count_of(html, "Refresh") == 0);
        // htmx is loaded for the Sign out button only.
        std::regex src(R"(<script[^>]*\ssrc=\"([^\"]*)\")");
        for (std::sregex_iterator it(html.begin(), html.end(), src), end; it != end; ++it)
            CHECK((*it)[1].str() == "/static/htmx.js");
        CHECK(count_of(html, "<h1>") == 1);
        CHECK_THAT(html, ContainsSubstring("<h1>Ask every device a question.<br>Hold it to the state you set.</h1>"));
        CHECK_THAT(html, ContainsSubstring("<div class=\"rule\"></div>"));
        CHECK_THAT(html, ContainsSubstring("<a class=\"brand\" href=\"/home\" aria-label=\"Yuzu home\">Yuzu<i></i></a>"));
    }
}

TEST_CASE("landing: the slim bar shows the server name and version only to a signed-in user", "[home][ui]") {
    // Signed out the page is public: neither the server name nor the version appears.
    const auto out = home_ui::render_landing(signed_out());
    CHECK_THAT(out, ContainsSubstring("<span class=\"srv\"></span>"));
    CHECK(count_of(out, "yuzu-01") == 0);
    CHECK(count_of(out, "0.14.1") == 0);
    CHECK(count_of(out, "version ") == 0);
    // Signed in: name and version.
    const auto in = home_ui::render_landing(signed_in());
    CHECK_THAT(in, ContainsSubstring("<span class=\"srv\">yuzu-01 &middot; version 0.14.1</span>"));
    // With no server name: version only (signed in), nothing invented.
    auto bare = signed_in();
    bare.server_name = {};
    const auto bare_html = home_ui::render_landing(bare);
    CHECK_THAT(bare_html, ContainsSubstring("<span class=\"srv\">version 0.14.1</span>"));
    CHECK(count_of(bare_html, "&middot;") == 0);
}

TEST_CASE("landing signed out: the real sign-in form, labelled fields, no SSO or two-factor note by default",
          "[home][ui][login]") {
    const auto html = home_ui::render_landing(signed_out());
    CHECK_THAT(html, ContainsSubstring("<section class=\"panel login\" id=\"signin\" aria-label=\"Sign in\" data-next=\"\">"));
    CHECK_THAT(html, ContainsSubstring("<form id=\"login-form\" class=\"form\" onsubmit=\"doLogin(event)\">"));
    CHECK_THAT(html, ContainsSubstring("<label for=\"username\">Username</label>"));
    CHECK_THAT(html, ContainsSubstring("<label for=\"password\">Password</label>"));
    CHECK_THAT(html, ContainsSubstring("id=\"username\" name=\"username\" autocomplete=\"username\""));
    CHECK_THAT(html, ContainsSubstring("id=\"password\" name=\"password\" autocomplete=\"current-password\""));
    CHECK_THAT(html, ContainsSubstring("<button type=\"submit\" class=\"btn primary\" id=\"btn-login\">Sign in</button>"));
    // The script posts to the real auth routes and then stays on Home.
    CHECK_THAT(html, ContainsSubstring("xhr.open('POST', '/login');"));
    CHECK_THAT(html, ContainsSubstring("doCode(e, '/login/mfa',"));
    CHECK_THAT(html, ContainsSubstring("doCode(e, '/login/mfa/enroll',"));
    CHECK(count_of(html, "window.location.href = home();") == 3);
    CHECK(count_of(html, "window.location.href = '/'") == 0);
    CHECK_THAT(html, ContainsSubstring("return '/home' + (n ? '?next=' + encodeURIComponent(n) : '');"));
    // The MFA and enrolment steps are present but hidden until a 202.
    CHECK_THAT(html, ContainsSubstring("<form id=\"mfa-form\" class=\"form\" onsubmit=\"doMfa(event)\" style=\"display:none\">"));
    CHECK_THAT(html, ContainsSubstring("<form id=\"enroll-form\" class=\"form\" onsubmit=\"doEnroll(event)\" style=\"display:none\">"));
    CHECK_THAT(html, ContainsSubstring("<a id=\"recovery-continue\" class=\"btn primary\" href=\"/home\">"));
    // Lede, no notice, no SSO, no two-factor note, no signed-in region.
    CHECK_THAT(html, ContainsSubstring("<p class=\"lede\">Yuzu runs on your own servers. Sign in to see the estate, run instructions on it and review what changed.</p>"));
    CHECK(count_of(html, "signin-notice") == 0);
    CHECK(count_of(html, "single sign-on") == 0);
    CHECK(count_of(html, "two-factor") == 0);
    CHECK(count_of(html, "aria-label=\"Signed in\"") == 0);
    CHECK(count_of(html, "<div class=\"error-msg\" id=\"error-msg\" role=\"alert\" aria-live=\"polite\"></div>") == 1);
}

TEST_CASE("landing signed out: SSO link, two-factor note and SSO error render only when asked",
          "[home][ui][login]") {
    auto v = signed_out();
    v.sso_href = "/auth/oidc/start";
    v.mfa_note = true;
    v.error_message = home_ui::sso_error_message("sso_failed");
    const auto html = home_ui::render_landing(v);
    CHECK_THAT(html, ContainsSubstring("<div class=\"or\">or</div><a class=\"btn\" id=\"btn-sso\" href=\"/auth/oidc/start\">Sign in with single sign-on</a>"));
    CHECK_THAT(html, ContainsSubstring("<p class=\"small\">If two-factor is on for your account, you will be asked for a code next. Forgot your password, or need an account? Ask a Yuzu administrator.</p>"));
    CHECK_THAT(html, ContainsSubstring("role=\"alert\" aria-live=\"polite\">SSO authentication failed</div>"));

    CHECK(home_ui::sso_error_message("") == "");
    CHECK(home_ui::sso_error_message("sso_denied") == "SSO sign-in was denied by the identity provider");
    CHECK(home_ui::sso_error_message("sso_invalid") == "Invalid SSO response");
    CHECK(home_ui::sso_error_message("saml") == "SSO error");
    CHECK(home_ui::sso_error_message("<script>") == "SSO error"); // never echoed
}

TEST_CASE("landing signed out with next: notice above the form and the key on the panel",
          "[home][ui][login]") {
    auto v = signed_out();
    v.next = home_ui::screen_by_key("devices");
    REQUIRE(v.next);
    const auto html = home_ui::render_landing(v);
    CHECK_THAT(html, ContainsSubstring("id=\"signin\" aria-label=\"Sign in\" data-next=\"devices\">"));
    CHECK_THAT(html, ContainsSubstring("<div class=\"note\" id=\"signin-notice\">Sign in to open <b>Devices</b>.</div>"));
    // Tiles stay real links to their screens; the server, not the tile, sends a signed-out click here.
    CHECK_THAT(html, ContainsSubstring("<a class=\"tile\" href=\"/devices\">"));
    CHECK(count_of(html, "href=\"#signin\"") == 0);
}

TEST_CASE("landing signed in: the signed-in region replaces the form, Open <area> or Open Dashboard, Sign out",
          "[home][ui][login]") {
    const auto html = home_ui::render_landing(signed_in());
    CHECK_THAT(html, ContainsSubstring("<section class=\"panel login\" id=\"signed-in\" aria-label=\"Signed in\">"));
    CHECK_THAT(html, ContainsSubstring("<div class=\"who\"><b>dave.rae</b><span>Administrator</span></div>"));
    CHECK_THAT(html, ContainsSubstring("<a class=\"btn primary\" id=\"open-area\" href=\"/\">Open Dashboard</a>"));
    CHECK_THAT(html, ContainsSubstring("<button class=\"btn\" type=\"button\" hx-post=\"/logout\">Sign out</button>"));
    CHECK_THAT(html, ContainsSubstring("<p class=\"small\">You are signed in. Open the Dashboard, or pick an area below.</p>"));
    CHECK_THAT(html, ContainsSubstring("<p class=\"lede\">Yuzu runs on your own servers. Open the Dashboard to ask your first question, or pick an area below.</p>"));
    // No form, no sign-in script, no SSO error.
    CHECK(count_of(html, "id=\"signin\"") == 0);
    CHECK(count_of(html, "<form") == 0);
    CHECK(count_of(html, "<label") == 0);
    CHECK(count_of(html, "doLogin") == 0);
    CHECK(count_of(html, "error-msg") == 0);
    // Tiles are plain links to their screens.
    CHECK(count_of(html, "<a class=\"tile\" href=\"") == 15);

    auto v = signed_in();
    v.next = home_ui::screen_by_key("compliance");
    v.error_message = "SSO authentication failed"; // ignored once signed in
    const auto with_next = home_ui::render_landing(v);
    CHECK_THAT(with_next, ContainsSubstring("<a class=\"btn primary\" id=\"open-area\" href=\"/compliance\">Open Compliance</a>"));
    CHECK(count_of(with_next, "SSO authentication failed") == 0);
    CHECK(count_of(with_next, "signin-notice") == 0);
}

TEST_CASE("landing signed in: the display name and role are escaped", "[home][ui][login]") {
    auto v = signed_in();
    v.who->name = "<b>x</b>&";
    v.who->role = "<i>";
    const auto html = home_ui::render_landing(v);
    CHECK_THAT(html, ContainsSubstring("<b>&lt;b&gt;x&lt;/b&gt;&amp;</b><span>&lt;i&gt;</span>"));
}

TEST_CASE("next allow-list: only the fifteen keys resolve; paths, URLs and unknown keys do not",
          "[home][ui][login][next]") {
    for (const auto& f : home_ui::families())
        for (const auto& s : f.screens)
            CHECK(home_ui::screen_by_key(s.key) == &s);
    CHECK(home_ui::screen_by_key("") == nullptr);
    CHECK(home_ui::screen_by_key("nope") == nullptr);
    CHECK(home_ui::screen_by_key("/devices") == nullptr);
    CHECK(home_ui::screen_by_key("devices/") == nullptr);
    CHECK(home_ui::screen_by_key("Devices") == nullptr);
    CHECK(home_ui::screen_by_key("https://evil.example/") == nullptr);
    CHECK(home_ui::screen_by_key("//evil.example") == nullptr);
    CHECK(home_ui::screen_by_key("devices\n") == nullptr);
    // Screen hrefs are absolute paths on this server; the button can never leave it.
    for (const auto& f : home_ui::families())
        for (const auto& s : f.screens) {
            CHECK(s.href.starts_with("/"));
            CHECK_FALSE(s.href.starts_with("//"));
        }
}

TEST_CASE("sign_in_location: a screen request carries its key, a sub-page its parent's, anything else none",
          "[home][ui][login][next]") {
    CHECK(home_ui::sign_in_location("/") == "/home?next=dashboard");
    CHECK(home_ui::sign_in_location("/devices") == "/home?next=devices");
    CHECK(home_ui::sign_in_location("/viz/fleet") == "/home?next=fleet");
    CHECK(home_ui::sign_in_location("/settings") == "/home?next=settings");
    CHECK(home_ui::sign_in_location("/access/audit") == "/home?next=audit");
    // Shell sub-pages open as their family item.
    CHECK(home_ui::sign_in_location("/approvals") == "/home?next=instructions");
    CHECK(home_ui::sign_in_location("/executions") == "/home?next=instructions");
    CHECK(home_ui::sign_in_location("/auto") == "/home?next=software");
    CHECK(home_ui::sign_in_location("/network") == "/home?next=fleet");
    // Not a screen: plain /home, never the path itself.
    CHECK(home_ui::sign_in_location("/viz/host/abc") == "/home");
    CHECK(home_ui::sign_in_location("/device") == "/home");
    CHECK(home_ui::sign_in_location("/nope") == "/home");
    CHECK(home_ui::sign_in_location("") == "/home");
    CHECK(home_ui::sign_in_location("https://evil.example/") == "/home");
}

TEST_CASE("landing: the family tokens and the landing block are in yuzu.css, with no gradient, glow or blur",
          "[home][ui][css]") {
    const std::string& css = kYuzuCss;
    CHECK_THAT(css, ContainsSubstring("--fam-operate: var(--c1);"));
    CHECK_THAT(css, ContainsSubstring("--fam-posture: var(--c2);"));
    CHECK_THAT(css, ContainsSubstring("--fam-estate:  var(--c5);"));
    CHECK_THAT(css, ContainsSubstring("--fam-access:  var(--c3);"));
    CHECK_THAT(css, ContainsSubstring("--fam-system:  var(--mds-color-theme-text-tertiary);"));
    const auto start = css.find("/* Home landing (delta 2026-10-14)");
    REQUIRE(start != std::string::npos);
    const std::string block = css.substr(start);
    CHECK(count_of(block, "/* Home landing (delta 2026-10-14)") == 1);
    CHECK_THAT(block, ContainsSubstring("background: color-mix(in srgb, var(--fam) 10%, var(--surface));"));
    CHECK_THAT(block, ContainsSubstring("border: 1px solid color-mix(in srgb, var(--fam) 38%, var(--line));"));
    CHECK_THAT(block, ContainsSubstring(".tile:hover { background: color-mix(in srgb, var(--fam) 17%, var(--surface)); border-color: var(--fam); }"));
    CHECK_THAT(block, ContainsSubstring("stroke-width: 1.6;"));
    CHECK_THAT(block, ContainsSubstring(".land .ht h1 { font-size: 56px; font-weight: 600; letter-spacing: -.03em; line-height: 1.06; }"));
    CHECK_THAT(block, ContainsSubstring(".land .rule { width: 44px; height: 4px;"));
    CHECK_THAT(block, ContainsSubstring(".land .lc { flex: 0 1 380px;"));
    CHECK_THAT(block, ContainsSubstring("@media (max-width: 820px)"));
    CHECK_THAT(block, ContainsSubstring("@media (max-width: 700px)"));
    CHECK_THAT(block, ContainsSubstring(".land .ht h1 { font-size: 34px; }"));
    for (const char* banned : {"box-shadow", "gradient", "blur(", "transform: translate", "filter:"})
        CHECK(count_of(block, banned) == 0);
    CHECK(count_of(block, "176px") >= 4);
}

TEST_CASE("landing: every page piece is under the MSVC literal cap and the page carries no CSS",
          "[home][ui]") {
    CHECK(login_ui::sign_in_fields().size() < 16000);
    CHECK(login_ui::sign_in_steps().size() < 16000);
    CHECK(login_ui::sign_in_script().size() < 16000);
    const std::string html = home_ui::render_landing(signed_out());
    CHECK(count_of(html, "<style") == 0);
    CHECK(count_of(html, "<link rel=\"stylesheet\" href=\"/static/yuzu.css\">") == 1);
    // An empty icon, so a visitor's browser does not log a 404 for /favicon.ico on the first page.
    CHECK(count_of(html, "<link rel=\"icon\" href=\"data:,\">") == 1);
}
