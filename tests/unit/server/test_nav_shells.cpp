/**
 * @file test_nav_shells.cpp
 * @brief Pure tests for the app shell (app_shell.{hpp,cpp}): the nav model, the breadcrumb,
 *        the renderer, the marker swap the routes use, and that every full-page template
 *        actually carries a shell block with the right item active.
 *
 * The last group is the one that matters most. Before the shell, each page hand-copied its
 * nav and the per-route "make this link active" step was a plain string replace that
 * silently did nothing when the markup drifted. `apply_shell` is also silent when a page
 * has no marker pair, so these cases are what catches a page that lost its marker.
 */

#include "app_shell.hpp"
#include "result_sets_ui.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Full-page templates (defined at global scope in the *_ui.cpp translation units).
extern const char* const kDashboardIndexHtml;
extern const char* const kHelpHtml;
extern const char* const kInstructionPageHtml;
extern const char* const kTarPageHtml;
extern const char* const kVizFleetPageHtml;
extern const char* const kVizHostPageHtml;
extern const char* const kComplianceHtml;
extern const char* const kGuardianHtml;
extern const char* const kGuardianDetailPageHtml;
extern const char* const kSettingsHtml;

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server::shell;

namespace {

std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

/// The one `<a class="shell-nav on" href="X"` / sub-item `<a href="X" class="on"` pair
/// a page highlights, as the hrefs found.
std::vector<std::string> highlighted_hrefs(std::string_view html) {
    std::vector<std::string> out;
    static const std::regex top(R"re(<a class="shell-nav on" href="([^"]+)")re");
    static const std::regex sub(R"re(<a href="([^"]+)" class="on")re");
    const std::string s(html);
    for (const auto* re : {&top, &sub})
        for (std::sregex_iterator it(s.begin(), s.end(), *re), end; it != end; ++it)
            out.push_back((*it)[1].str());
    return out;
}

} // namespace

// ── Nav model ───────────────────────────────────────────────────────────────

TEST_CASE("app shell: nav is exactly the pages that exist, in design order", "[nav][shell]") {
    std::vector<std::string_view> titles;
    for (const auto& g : nav_groups())
        titles.push_back(g.title);
    CHECK(titles == std::vector<std::string_view>{"Operate", "Posture", "Estate", "System"});

    std::vector<std::string_view> labels;
    for (const auto& g : nav_groups())
        for (const auto& it : g.items)
            labels.push_back(it.label);
    CHECK(labels == std::vector<std::string_view>{"Dashboard", "Instructions", "Result sets",
                                                  "Compliance", "Guardian", "DEX", "TAR",
                                                  "Hardware", "Software", "Fleet", "Settings"});
}

TEST_CASE("app shell: keys and hrefs are unique and every top-level entry has an icon",
          "[nav][shell]") {
    std::set<std::string_view> keys, hrefs;
    for (const auto& g : nav_groups())
        for (const auto& it : g.items) {
            CHECK_FALSE(it.icon.empty());
            CHECK(keys.insert(it.key).second);
            CHECK(hrefs.insert(it.href).second);
            for (const auto& c : it.children) {
                CHECK(c.icon.empty());
                CHECK(c.children.empty());
                CHECK(keys.insert(c.key).second);
                CHECK(hrefs.insert(c.href).second);
            }
        }
}

TEST_CASE("app shell: only Software, Fleet and Settings have sub-items; Settings is the one admin-only entry",
          "[nav][shell]") {
    // Parent keys only: a System page adds its own child line to kSettingsSub without
    // touching this assertion (the child order is pinned by the next case).
    std::vector<std::string> with_children;
    for (const auto& g : nav_groups())
        for (const auto& it : g.items) {
            if (!it.children.empty())
                with_children.push_back(std::string(it.key));
            CHECK((it.key == "settings") == it.admin_only);
        }
    CHECK(with_children == std::vector<std::string>{"software", "fleet", "settings"});

    const auto groups = nav_groups();
    REQUIRE(groups.back().title == "System");
    REQUIRE(groups.back().items.size() == 1);
    CHECK(groups.back().items[0].href == "/settings");
}

TEST_CASE("app shell: Settings sub-items are System pages in artboard order, none on the "
          "parent's own href",
          "[nav][shell]") {
    const std::vector<std::string_view> artboard = {
        "settings-general",  "settings-security", "settings-integrations", "settings-pki",
        "settings-plugins",  "settings-data",     "settings-licence",      "settings-developer"};
    const auto groups = nav_groups();
    const auto& settings = groups.back().items[0];
    REQUIRE(settings.key == "settings");
    REQUIRE_FALSE(settings.children.empty());

    // The child keys are a subsequence of the artboard order: nothing out of order, nothing
    // unknown. Pages that have not landed are simply absent ("nav only for pages that exist").
    std::size_t at = 0;
    for (const auto& c : settings.children) {
        INFO(c.key);
        while (at < artboard.size() && artboard[at] != c.key)
            ++at;
        CHECK(at < artboard.size());
        ++at;
        CHECK(c.href != settings.href);
        CHECK(c.href.starts_with("/settings/"));
    }
}

// ── Breadcrumb ──────────────────────────────────────────────────────────────

TEST_CASE("app shell: breadcrumb is group / page, and a sub-item skips its parent",
          "[nav][shell]") {
    CHECK(breadcrumb_trail({.active_key = "dashboard"}) ==
          std::vector<std::string>{"Operate", "Dashboard"});
    CHECK(breadcrumb_trail({.active_key = "network"}) ==
          std::vector<std::string>{"Estate", "Network"});
    CHECK(breadcrumb_trail({.active_key = "auto"}) ==
          std::vector<std::string>{"Estate", "Deployments"});
}

TEST_CASE("app shell: a title extends the trail, a repeated label does not", "[nav][shell]") {
    CHECK(breadcrumb_trail({.active_key = "guardian", .title = "Baseline"}) ==
          std::vector<std::string>{"Posture", "Guardian", "Baseline"});
    CHECK(breadcrumb_trail({.active_key = "guardian", .title = "Guardian"}) ==
          std::vector<std::string>{"Posture", "Guardian"});
}

TEST_CASE("app shell: a page without a nav entry shows only its title; nothing known shows nothing",
          "[nav][shell]") {
    CHECK(breadcrumb_trail({.title = "Help"}) == std::vector<std::string>{"Help"});
    CHECK(breadcrumb_trail({.active_key = "no-such-page", .title = "Help"}) ==
          std::vector<std::string>{"Help"});
    CHECK(breadcrumb_trail({}).empty());
}

TEST_CASE("app shell: an explicit breadcrumb replaces the derived parent trail", "[nav][shell]") {
    CHECK(breadcrumb_trail({.active_key = "fleet", .title = "Host", .breadcrumb = "Estate / Fleet"}) ==
          std::vector<std::string>{"Estate", "Fleet", "Host"});
    // Blank segments and stray separators are dropped.
    CHECK(breadcrumb_trail({.title = "Leaf", .breadcrumb = " / A //  B /"}) ==
          std::vector<std::string>{"A", "B", "Leaf"});
}

// ── Renderer ────────────────────────────────────────────────────────────────

TEST_CASE("app shell: exactly one item is the current page", "[nav][shell]") {
    for (const auto& g : nav_groups())
        for (const auto& it : g.items) {
            INFO(it.key);
            const auto html = render_shell({.active_key = it.key});
            CHECK(count_of(html, "aria-current=\"page\"") == 1);
            CHECK_THAT(html, ContainsSubstring("href=\"" + std::string(it.href) + "\" aria-current=\"page\"") ||
                                 ContainsSubstring("href=\"" + std::string(it.href) +
                                                   "\" id=\"nav-settings-link\" aria-current=\"page\""));
        }
    CHECK(count_of(render_shell({.active_key = "no-such-page"}), "aria-current=\"page\"") == 0);
    CHECK(count_of(render_shell({}), "aria-current=\"page\"") == 0);
}

TEST_CASE("app shell: sub-items show only for the active family and light their parent",
          "[nav][shell]") {
    const auto on_dashboard = render_shell({.active_key = "dashboard"});
    CHECK(count_of(on_dashboard, "class=\"shell-sub\"") == 0);

    const auto on_software = render_shell({.active_key = "software"});
    CHECK(count_of(on_software, "class=\"shell-sub\"") == 1);
    CHECK_THAT(on_software, ContainsSubstring("<a href=\"/auto\">Deployments</a>"));
    CHECK(highlighted_hrefs(on_software) == std::vector<std::string>{"/software"});

    // The sub-item is the current page; its parent stays lit as the family.
    const auto on_auto = render_shell({.active_key = "auto"});
    CHECK_THAT(on_auto, ContainsSubstring("<a href=\"/auto\" class=\"on\" aria-current=\"page\">"));
    CHECK(highlighted_hrefs(on_auto) == std::vector<std::string>{"/software", "/auto"});

    const auto on_network = render_shell({.active_key = "network"});
    CHECK(highlighted_hrefs(on_network) == std::vector<std::string>{"/viz/fleet", "/network"});
}

TEST_CASE("app shell: keeps the identity hooks, Sign out and the admin-only Settings entry",
          "[nav][shell]") {
    const auto html = render_shell({.active_key = "dashboard"});
    // Ids the shell script fills / hides.
    CHECK(count_of(html, "id=\"nav-user\"") == 1);
    CHECK(count_of(html, "id=\"role-badge\"") == 1);
    CHECK(count_of(html, "id=\"context-user\"") == 1);
    CHECK(count_of(html, "id=\"nav-settings-link\"") == 1);
    CHECK_THAT(html, ContainsSubstring("href=\"/settings\" id=\"nav-settings-link\""));
    // Sign out posts to /logout through htmx, as the old nav's Logout button did.
    CHECK_THAT(html, ContainsSubstring("<button class=\"shell-out\" type=\"button\" hx-post=\"/logout\">Sign out</button>"));
    // The same /api/me read + non-admin rule the pages used to carry.
    CHECK_THAT(html, ContainsSubstring("fetch('/api/me')"));
    CHECK_THAT(html, ContainsSubstring("d.role!=='admin'&&role!=='Administrator'&&role!=='PlatformEngineer'"));
}

TEST_CASE("app shell: breadcrumb text is HTML-escaped", "[nav][shell]") {
    const auto html = render_shell({.title = "<img src=x onerror=alert(1)>"});
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=alert(1)&gt;"));
    CHECK_THAT(html, !ContainsSubstring("<img"));
}

TEST_CASE("app shell: styles come from tokens, never hex literals", "[nav][shell]") {
    static const std::regex hex(R"(#[0-9a-fA-F]{3,8}\b)");
    const auto html = render_shell({.active_key = "dashboard"});
    CHECK_FALSE(std::regex_search(html, hex));
    CHECK_THAT(html, !ContainsSubstring("box-shadow"));
    // Fonts only ever come from the page's font tokens.
    static const std::regex literal_family(R"(font-family:\s*(?!var\())");
    CHECK_FALSE(std::regex_search(html, literal_family));
    CHECK_THAT(html, !ContainsSubstring("text-transform"));
}

TEST_CASE("app shell: each raw literal in the renderer stays under MSVC's string limit",
          "[nav][shell]") {
    // The CSS and the script are the two large literals (C2026 at 16,380 bytes); each renders
    // verbatim between its own tags, so measure each one, not the whole block. The limit is
    // documented in docs/cpp-conventions.md; 16,000 leaves this test its own headroom.
    const auto html = render_shell({.active_key = "dashboard"});
    for (const auto& [open, close] : {std::pair<std::string_view, std::string_view>{"<style>", "</style>"},
                                      {"<script>", "</script>"}}) {
        INFO(open);
        const auto b = html.find(open);
        const auto e = html.find(close);
        REQUIRE(b != std::string::npos);
        REQUIRE(e != std::string::npos);
        CHECK(e + close.size() - b < 16000);
    }
}

TEST_CASE("app shell: header search is the existing Ctrl+K palette and nothing new",
          "[nav][shell]") {
    const auto html = render_shell({.active_key = "dashboard"});
    CHECK(count_of(html, "id=\"shell-search\"") == 1);
    CHECK_THAT(html, ContainsSubstring("aria-keyshortcuts=\"Control+K\""));
    CHECK_THAT(html, ContainsSubstring("<span>Search devices, instructions, help</span><kbd>Ctrl K</kbd>"));
    // It is a button (nothing to type into), wired in the shell's own script.
    CHECK_THAT(html, ContainsSubstring("<button class=\"shell-search\""));
    CHECK_THAT(html, !ContainsSubstring("<input"));
    // On `/`: a synthetic Ctrl+K on document (the dashboard's own handler).
    CHECK_THAT(html, ContainsSubstring("new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true,cancelable:true})"));
    CHECK_THAT(html, ContainsSubstring("if(location.pathname==='/'){openPalette();return;}"));
    // Elsewhere: the dashboard's own `?palette=1` hand-off, no second mechanism.
    CHECK_THAT(html, ContainsSubstring("location.href='/?palette=1'"));
    CHECK_THAT(html, !ContainsSubstring("sessionStorage"));
}

TEST_CASE("app shell: the Ctrl K hint is true on every page", "[nav][shell]") {
    const auto html = render_shell({.active_key = "dashboard"});
    // A `window` listener runs after every `document` listener, so a page that binds Ctrl+K
    // itself has already called preventDefault and is skipped; the dashboard is never touched.
    CHECK_THAT(html, ContainsSubstring("window.addEventListener('keydown',function(e){"));
    CHECK_THAT(html, ContainsSubstring("(e.ctrlKey||e.metaKey)&&e.key==='k'&&!e.defaultPrevented&&location.pathname!=='/'"));
    CHECK_THAT(html, ContainsSubstring("e.preventDefault();location.href='/?palette=1';"));
}

TEST_CASE("app shell: Ctrl K never navigates away from a field being typed in", "[nav][shell]") {
    const auto html = render_shell({.active_key = "dashboard"});
    // The guard runs before the navigation, on the event target and on the focused element.
    const auto guard = html.find("if(typing(e.target)||typing(document.activeElement))return;");
    const auto go = html.find("e.preventDefault();location.href='/?palette=1';");
    REQUIRE(guard != std::string::npos);
    REQUIRE(go != std::string::npos);
    CHECK(guard < go);
    // What counts as typing: contenteditable, an ARIA textbox or combobox (including a child of
    // one), a textarea, a select, and any input that takes text.
    CHECK_THAT(html, ContainsSubstring("t.isContentEditable"));
    CHECK_THAT(html, ContainsSubstring("t.closest('[role=textbox],[role=combobox]')"));
    CHECK_THAT(html, ContainsSubstring("t.tagName==='TEXTAREA'"));
    CHECK_THAT(html, ContainsSubstring("t.tagName==='SELECT'"));
    CHECK_THAT(html, ContainsSubstring("t.tagName==='INPUT'&&!/^(button|checkbox|radio|range|file|submit|reset|image|color)$/.test(t.type)"));
}

TEST_CASE("app shell: online counter is hidden until /api/health answers and polls every 30 s",
          "[nav][shell]") {
    const auto html = render_shell({.active_key = "dashboard"});
    CHECK_THAT(html, ContainsSubstring("<span class=\"shell-live\" id=\"shell-online\" hidden><i></i><b id=\"shell-online-n\"></b> online</span>"));
    CHECK_THAT(html, ContainsSubstring(".shell-live[hidden]{display:none}"));
    // No session cookie, so the server takes its cheap unauthenticated branch; bounded to 5 s.
    CHECK_THAT(html, ContainsSubstring("fetch('/api/health',{credentials:'omit',signal:AbortSignal.timeout(5000)})"));
    CHECK_THAT(html, ContainsSubstring("d.agents.online"));
    CHECK_THAT(html, ContainsSubstring("setInterval(pollOnline,30000)"));
    // One request at a time, and a tab coming back to the foreground polls at once.
    CHECK_THAT(html, ContainsSubstring("if(document.hidden||inflight)return;"));
    CHECK_THAT(html, ContainsSubstring("document.addEventListener('visibilitychange',pollOnline)"));
    // Only a number reveals the counter, and any failed poll hides it again.
    CHECK_THAT(html, ContainsSubstring("if(typeof n!=='number')throw new Error('payload');"));
    CHECK_THAT(html, ContainsSubstring("if(!r.ok)throw new Error('http');"));
    CHECK_THAT(html, ContainsSubstring(".catch(function(){el('shell-online').hidden=true;})"));
}

TEST_CASE("app shell: toasts sit below the header so one never covers Sign out", "[nav][shell]") {
    CHECK_THAT(render_shell({}), ContainsSubstring(".toast-container{top:calc(var(--shell-top-h) + var(--sp-4))}"));
}

// ── apply_shell / bake ──────────────────────────────────────────────────────

TEST_CASE("apply_shell: fills an empty marker pair and keeps the rest of the page", "[nav][shell]") {
    const std::string page = "<body>A<!--yuzu:shell--><!--/yuzu:shell-->B</body>";
    const auto out = apply_shell(page, {.active_key = "dex"});
    CHECK(out.starts_with("<body>A<!--yuzu:shell-->"));
    CHECK(out.ends_with("<!--/yuzu:shell-->B</body>"));
    CHECK(highlighted_hrefs(out) == std::vector<std::string>{"/dex"});
}

TEST_CASE("apply_shell: re-targets a page that is already baked, leaving exactly one block",
          "[nav][shell]") {
    const std::string page = "<body><!--yuzu:shell--><!--/yuzu:shell--><main>x</main></body>";
    const auto once = apply_shell(page, {.active_key = "guardian"});
    const auto twice = apply_shell(once, {.active_key = "hardware"});
    CHECK(highlighted_hrefs(twice) == std::vector<std::string>{"/hardware"});
    CHECK(count_of(twice, kShellBegin) == 1);
    CHECK(count_of(twice, kShellEnd) == 1);
    CHECK_THAT(twice, ContainsSubstring("<main>x</main>"));
    CHECK(apply_shell(twice, {.active_key = "hardware"}) == twice); // idempotent
}

TEST_CASE("apply_shell: a page without markers comes back unchanged", "[nav][shell]") {
    const std::string page = "<body><nav class=\"x\"></nav></body>";
    CHECK(apply_shell(page, {.active_key = "dex"}) == page);
    CHECK(apply_shell("<body><!--yuzu:shell--></body>", {.active_key = "dex"}) ==
          "<body><!--yuzu:shell--></body>"); // begin without end
}

TEST_CASE("bake: returns a stable, shell-bearing copy", "[nav][shell]") {
    const char* a = bake("<!--yuzu:shell--><!--/yuzu:shell-->one", {.active_key = "tar"});
    const char* b = bake("<!--yuzu:shell--><!--/yuzu:shell-->two", {.active_key = "dex"});
    CHECK_THAT(std::string(a), ContainsSubstring("one"));
    CHECK_THAT(std::string(b), ContainsSubstring("two"));
    CHECK(highlighted_hrefs(a) == std::vector<std::string>{"/tar"}); // a survives b's bake
}

// ── The page templates themselves ───────────────────────────────────────────

TEST_CASE("every full-page template carries one shell block with its own item active",
          "[nav][shell][pages]") {
    struct Page {
        const char* name;
        const char* html;
        std::vector<std::string> active; // hrefs highlighted
    };
    const std::vector<Page> pages = {
        {"dashboard", kDashboardIndexHtml, {"/"}},
        {"instructions", kInstructionPageHtml, {"/instructions"}},
        {"result sets", yuzu::server::kResultSetsPageHtml, {"/result-sets"}},
        {"compliance", kComplianceHtml, {"/compliance"}},
        {"guardian", kGuardianHtml, {"/guardian"}},
        {"guardian detail (shared shell default)", kGuardianDetailPageHtml, {"/guardian"}},
        {"tar", kTarPageHtml, {"/tar"}},
        {"settings", kSettingsHtml, {"/settings"}},
        {"fleet map", kVizFleetPageHtml, {"/viz/fleet"}},
        {"host map", kVizHostPageHtml, {"/viz/fleet"}},
        {"help", kHelpHtml, {}},
    };
    for (const auto& p : pages) {
        INFO(p.name);
        const std::string html(p.html);
        CHECK(count_of(html, kShellBegin) == 1);
        CHECK(count_of(html, kShellEnd) == 1);
        CHECK(highlighted_hrefs(html) == p.active);
        // The hand-written chrome is gone — nothing left to drift.
        CHECK_THAT(html, !ContainsSubstring("nav-bar"));
        CHECK_THAT(html, !ContainsSubstring("nav-link"));
        CHECK_THAT(html, !ContainsSubstring("context-bar"));
        // One identity read per page — the shell's, not a per-page copy.
        CHECK(count_of(html, "fetch('/api/me')") == 1);
    }
}

TEST_CASE("the shared detail shell re-targets to every route that reuses it", "[nav][shell][pages]") {
    // The five route files that fill kGuardianDetailPageHtml's tokens and then pick the
    // active item. Each key must light its own entry (and its family) and nothing else.
    struct Route {
        const char* key;
        std::vector<std::string> active;
    };
    const std::vector<Route> routes = {
        {"dex", {"/dex"}},
        {"hardware", {"/hardware"}},
        {"software", {"/software"}},
        {"auto", {"/software", "/auto"}},
        {"network", {"/viz/fleet", "/network"}},
    };
    for (const auto& r : routes) {
        INFO(r.key);
        const auto html = apply_shell(kGuardianDetailPageHtml, {.active_key = r.key});
        CHECK(highlighted_hrefs(html) == r.active);
        CHECK(count_of(html, kShellBegin) == 1);
        // The route's own token substitution still has its anchors.
        CHECK_THAT(html, ContainsSubstring("{{TITLE}}"));
        CHECK_THAT(html, ContainsSubstring("{{FRAGMENT}}"));
    }
}
