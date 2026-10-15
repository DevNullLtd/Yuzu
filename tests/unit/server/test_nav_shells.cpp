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
extern const char* const kApprovalsPageHtml;
extern const char* const kExecutionsPageHtml;
extern const char* const kWorkflowsPageHtml;
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

TEST_CASE("app shell: only Instructions Software and Fleet have sub-items; Settings is one "
          "admin-only entry",
          "[nav][shell]") {
    std::vector<std::string> with_children;
    for (const auto& g : nav_groups())
        for (const auto& it : g.items) {
            if (!it.children.empty())
                with_children.push_back(std::string(it.key) + ">" + std::string(it.children[0].key));
            CHECK((it.key == "settings") == it.admin_only);
        }
    CHECK(with_children ==
          std::vector<std::string>{"instructions>executions", "software>auto", "fleet>network"});

    const auto groups = nav_groups();
    REQUIRE(groups.back().title == "System");
    REQUIRE(groups.back().items.size() == 1);
    CHECK(groups.back().items[0].href == "/settings");
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
    CHECK(breadcrumb_trail({.active_key = "approvals"}) ==
          std::vector<std::string>{"Operate", "Approvals"});
    CHECK(breadcrumb_trail({.active_key = "executions"}) ==
          std::vector<std::string>{"Operate", "Executions"});
    CHECK(breadcrumb_trail({.active_key = "workflows"}) ==
          std::vector<std::string>{"Operate", "Workflows"});
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

    // Instructions' child (Operate pages): visible on the Instructions family only.
    const auto on_instructions = render_shell({.active_key = "instructions"});
    CHECK(count_of(on_instructions, "class=\"shell-sub\"") == 1);
    CHECK_THAT(on_instructions, ContainsSubstring("<a href=\"/executions\">Executions</a>"));
    CHECK_THAT(on_instructions, ContainsSubstring("<a href=\"/approvals\">Approvals<span class=\"shell-badge\""));
    CHECK_THAT(on_instructions, ContainsSubstring("<a href=\"/workflows\">Workflows</a>"));
    CHECK(count_of(on_instructions, "class=\"shell-sub\"") == 1);
    // Order: Executions, Workflows, Approvals.
    const auto pe = on_instructions.find("href=\"/executions\"");
    const auto pw = on_instructions.find("href=\"/workflows\"");
    const auto pa = on_instructions.find("href=\"/approvals\"");
    CHECK((pe < pw && pw < pa));
    const auto on_workflows = render_shell({.active_key = "workflows"});
    CHECK_THAT(on_workflows,
               ContainsSubstring("<a href=\"/workflows\" class=\"on\" aria-current=\"page\">"));
    CHECK(highlighted_hrefs(on_workflows) ==
          std::vector<std::string>{"/instructions", "/workflows"});
    const auto on_executions = render_shell({.active_key = "executions"});
    CHECK(highlighted_hrefs(on_executions) ==
          std::vector<std::string>{"/instructions", "/executions"});
    const auto on_approvals = render_shell({.active_key = "approvals"});
    CHECK_THAT(on_approvals,
               ContainsSubstring("<a href=\"/approvals\" class=\"on\" aria-current=\"page\">"));
    CHECK(highlighted_hrefs(on_approvals) ==
          std::vector<std::string>{"/instructions", "/approvals"});
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
    // The one shadow is the bell pop-over's (--shadow is for pop-overs and menus alone).
    CHECK(count_of(html, "box-shadow") == 1);
    CHECK_THAT(html, ContainsSubstring("box-shadow:var(--shadow)"));
    // Fonts only ever come from the page's font tokens.
    static const std::regex literal_family(R"(font-family:\s*(?!var\())");
    CHECK_FALSE(std::regex_search(html, literal_family));
    CHECK_THAT(html, !ContainsSubstring("text-transform"));
}

TEST_CASE("app shell: each raw literal in the renderer stays under MSVC's string limit",
          "[nav][shell]") {
    // The shell CSS/script and the bell CSS/script are the large literals (C2026 at 16,380
    // bytes); each renders verbatim between its own tags, so measure every block, not the
    // first. The limit is documented in docs/cpp-conventions.md; 16,000 leaves this test its
    // own headroom.
    const auto html = render_shell({.active_key = "dashboard"});
    for (const auto& [open, close] : {std::pair<std::string_view, std::string_view>{"<style>", "</style>"},
                                      {"<script>", "</script>"}}) {
        INFO(open);
        std::size_t blocks = 0;
        for (auto b = html.find(open); b != std::string::npos; b = html.find(open, b + 1)) {
            const auto e = html.find(close, b);
            REQUIRE(e != std::string::npos);
            CHECK(e + close.size() - b < 16000);
            ++blocks;
        }
        CHECK(blocks == 2); // shell + bell
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
    // At <=820px the sidebar becomes a wrapping row above a wrapped header, so no fixed top
    // offset clears them: toasts move to the bottom edge instead of covering the nav links.
    CHECK_THAT(render_shell({}), ContainsSubstring(".shell-search{flex-basis:100%;margin-left:0}\n.toast-container{top:auto;bottom:var(--sp-4)}\n}"));
}

// ── Notifications bell ──────────────────────────────────────────────────────

TEST_CASE("app shell: the bell is one hidden <details> before the account block", "[nav][shell][bell]") {
    for (const auto* key : {"dashboard", "settings", "dex", ""}) {
        INFO(key);
        const auto html = render_shell({.active_key = key});
        CHECK(count_of(html, "<details class=\"shell-pop\" id=\"shell-bell\" hidden>") == 1);
        CHECK(html.find("id=\"shell-bell\"") < html.find("class=\"shell-acct\""));
        CHECK_THAT(html, ContainsSubstring("<summary id=\"shell-bell-sum\" aria-label=\"Notifications\">"));
        CHECK_THAT(html, ContainsSubstring("Shared by all operators"));
        // Approvals are not drawn here: no feed rows, no link until the page exists.
        // (the sidebar's own Approvals link is outside the bell, so scope to the <details>.)
        const auto b0 = html.find("id=\"shell-bell\"");
        const auto b1 = html.find("</details>", b0);
        REQUIRE(b1 != std::string::npos);
        const auto bell = html.substr(b0, b1 - b0);
        CHECK_THAT(bell, !ContainsSubstring("Open approvals"));
        CHECK_THAT(bell, !ContainsSubstring("/approvals"));
    }
}

TEST_CASE("app shell: re-baking keeps exactly one bell, style and script", "[nav][shell][bell]") {
    const std::string page = "<body><!--yuzu:shell--><!--/yuzu:shell--></body>";
    const auto once = apply_shell(page, {.active_key = "dex"});
    const auto twice = apply_shell(once, {.active_key = "tar"});
    CHECK(count_of(twice, "id=\"shell-bell\"") == 1);
    CHECK(count_of(twice, "(function(){\n  var POLL_MS=") == 1);
    CHECK(count_of(twice, "<style>") == 2);
    CHECK(count_of(twice, "<script>") == 2);
    // The bell script sits inside the marker pair, before the end marker.
    CHECK(twice.find("var POLL_MS=") < twice.find(kShellEnd));
}

TEST_CASE("app shell: bell requests use the three existing routes, credentialed, bounded",
          "[nav][shell][bell]") {
    const auto html = render_shell({});
    CHECK_THAT(html, ContainsSubstring("var POLL_MS=60000, IDLE_MS=300000, TIMEOUT_MS=5000, LIMIT=10, CONFIRM_MS=3000, MSG_MAX=500;"));
    CHECK_THAT(html, ContainsSubstring("fetch('/api/notifications?limit='+LIMIT,{signal:AbortSignal.timeout(TIMEOUT_MS)})"));
    CHECK_THAT(html, ContainsSubstring("'/api/notifications/'+n.id+'/'+(kind==='read'?'read':'dismiss'),{method:'POST',signal:AbortSignal.timeout(TIMEOUT_MS)}"));
    CHECK_THAT(html, ContainsSubstring("Number.isSafeInteger(n.id)&&n.id>0"));
    // Default credentials: the session cookie is the whole auth, unlike the online counter.
    CHECK(count_of(html, "credentials:'omit'") == 1);
    // Shape guard: a 2xx with any other body is a failure, not an empty list.
    CHECK_THAT(html, ContainsSubstring("!Array.isArray(d.notifications)||typeof d.unread_count!=='number'"));
    // 401 and 403 hide the bell and stop; 403 on an action disables the buttons.
    CHECK_THAT(html, ContainsSubstring("if(r.status===401||r.status===403){root.hidden=true;stopped=true;return null;}"));
    CHECK_THAT(html, ContainsSubstring("if(r.status===403){return r.json()"));
    CHECK_THAT(html, ContainsSubstring("else{readOnly=true;"));
    CHECK_THAT(html, ContainsSubstring("Your account can view notifications but not change them."));
    // A same-site refusal is told apart from a read-only account, with the remedy named.
    CHECK_THAT(html, ContainsSubstring("refused as cross-site"));
    CHECK_THAT(html, ContainsSubstring("--csrf-trusted-origin"));
    CHECK_THAT(html, ContainsSubstring("No unread notifications."));
}

TEST_CASE("app shell: both bell actions take the two-click confirm", "[nav][shell][bell]") {
    const auto html = render_shell({});
    CHECK_THAT(html, ContainsSubstring("btn(n,'read','Mark read',it)"));
    CHECK_THAT(html, ContainsSubstring("btn(n,'dismiss','Dismiss',it)"));
    // One shared handler: the first click arms, only a second click on the same button sends.
    CHECK(count_of(html, "if(armed&&armed.btn===b){act(n,kind,itemEl);return;}") == 1);
    CHECK_THAT(html, ContainsSubstring("b.classList.add('btn-confirming');"));
    CHECK_THAT(html, ContainsSubstring("armTimer=setTimeout(disarm,CONFIRM_MS);"));
    CHECK_THAT(html, ContainsSubstring("b.textContent='Confirm '+label.toLowerCase();"));
}

TEST_CASE("app shell: bell polling is gated on recent input", "[nav][shell][bell]") {
    const auto html = render_shell({});
    CHECK_THAT(html, ContainsSubstring("['keydown','pointerdown','pointermove','scroll'].forEach("));
    // The age check lives in poll() so the timer and a foregrounded tab share it.
    CHECK_THAT(html, ContainsSubstring("if(!force&&Date.now()-last>IDLE_MS){paused=true;return;}"));
    CHECK_THAT(html, ContainsSubstring("function input(){last=Date.now();if(paused){paused=false;poll(false);}}"));
    // Not polled while the tab is hidden or the panel is open.
    CHECK_THAT(html, ContainsSubstring("(!force&&(document.hidden||root.open))"));
}

TEST_CASE("app shell: bell renders server text as text only", "[nav][shell][bell]") {
    const auto html = render_shell({});
    for (const auto* banned : {"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                               "new Function", " onclick=", "hx-on", "localStorage", "sessionStorage",
                               "__bellRefresh"}) {
        INFO(banned);
        CHECK_THAT(html, !ContainsSubstring(banned));
    }
    CHECK_THAT(html, ContainsSubstring("textContent"));
    // The message is clamped before it reaches the paragraph or the title attribute.
    const auto clamp = html.find("txt(n.message).slice(0,MSG_MAX)");
    REQUIRE(clamp != std::string::npos);
    CHECK(clamp < html.find("m.setAttribute('title',msg)"));
    // The level goes through a fixed map; the raw string is never a class.
    CHECK_THAT(html, ContainsSubstring("var LV={success:'s-on',warn:'s-w',error:'s-bad',info:'s-off'};"));
    CHECK_THAT(html, ContainsSubstring("Object.prototype.hasOwnProperty.call(LV,n.level)?n.level:'info'"));
    // Own row class (yuzu.css has no .row), hidden must beat the display rule.
    CHECK_THAT(html, ContainsSubstring("shell-pop-r"));
    CHECK_THAT(html, !ContainsSubstring("class=\"row\""));
    CHECK_THAT(html, ContainsSubstring(".shell-pop[hidden]{display:none}"));
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
        {"approvals", kApprovalsPageHtml, {"/instructions", "/approvals"}},
        {"executions", kExecutionsPageHtml, {"/instructions", "/executions"}},
        {"workflows", kWorkflowsPageHtml, {"/instructions", "/workflows"}},
        {"result sets", yuzu::server::kResultSetsPageHtml, {"/result-sets"}},
        {"compliance", kComplianceHtml, {"/compliance"}},
        {"guardian", kGuardianHtml, {"/guardian"}},
        {"guardian detail (shared shell default)", kGuardianDetailPageHtml, {"/guardian"}},
        {"tar", kTarPageHtml, {"/tar"}},
        {"settings", kSettingsHtml, {"/settings"}},
        {"fleet map", kVizFleetPageHtml, {"/viz/fleet"}},
        {"host map", kVizHostPageHtml, {"/viz/fleet"}},
        {"help", kHelpHtml, {}},
        // Not listed on purpose: /home is the landing and sign-in page and carries no
        // shell at all (test_home_ui.cpp pins that). The logo reaches it (below).
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
        // Sign out is `hx-post="/logout"`, so every page must load htmx (Help once did not,
        // and the button did nothing there).
        CHECK_THAT(html, ContainsSubstring("/static/htmx.js"));
        // The shell script owns the Ctrl+K hand-off, behind its typing guard. A page-local
        // handler that navigates to the palette runs first and bypasses that guard, so
        // outside the shell block no page may carry the `?palette=1` hand-off as a string
        // (the dashboard only mentions it in a comment, and reads the parameter on load).
        const auto sb = html.find(kShellBegin);
        const auto se = html.find(kShellEnd);
        REQUIRE(sb != std::string::npos);
        REQUIRE(se != std::string::npos);
        const auto page_only = html.substr(0, sb) + html.substr(se);
        CHECK(count_of(page_only, "palette=1'") + count_of(page_only, "palette=1\"") == 0);
    }
}

TEST_CASE("app shell: the brand link reaches the landing page, which has no nav item", "[nav][shell]") {
    const auto html = render_shell({.active_key = "dashboard"});
    CHECK(count_of(html, R"(<a class="shell-brand" href="/home" aria-label="Yuzu home">Yuzu<i></i></a>)") == 1);
    for (const auto& g : nav_groups())
        for (const auto& it : g.items)
            CHECK(it.href != "/home");
}

TEST_CASE("app shell: approvals badge is hidden until the count answers, polls every 30 s and stops on a refusal",
          "[nav][shell]") {
    const std::string_view badge =
        R"(<span class="shell-badge" id="nav-approvals-badge" hidden><span id="nav-approvals-n"></span>)"
        R"(<span class="shell-sr"> pending</span></span>)";
    for (const char* key : {"approvals", "executions", "workflows", "instructions"})
        CHECK(count_of(render_shell({.active_key = key}), badge) == 1);
    CHECK(count_of(render_shell({.active_key = "dashboard"}), badge) == 0);

    const auto html = render_shell({.active_key = "approvals"});
    CHECK(count_of(html, "fetch('/api/approvals/pending/count',{signal:AbortSignal.timeout(5000)})") == 1);
    CHECK(count_of(html, "setInterval(pollBadge,30000)") == 1);
    // A decision on the Approvals page refreshes the badge at once.
    CHECK(count_of(html, "document.addEventListener('yuzu:approvals-changed',pollBadge);") == 1);
    CHECK(count_of(html, "if(r.status===401||r.status===403){bstop=true;") == 1);
    CHECK(count_of(html, "if(!badge||bstop||document.hidden||binflight)return;") == 1);
    CHECK(count_of(html, "if(typeof n!=='number')throw new Error('payload');") == 2);
    CHECK(count_of(html, ".catch(function(){badge.hidden=true;})") == 1);
    CHECK(count_of(html, "badge.hidden=n<=0;") == 1);
    // The bell script (a separate <script>, emitted after this one) also caps its chip at 99+.
    const auto shell_js = html.substr(0, html.rfind("<script>"));
    CHECK(count_of(shell_js, "n>99?'99+'") == 1);
    // Only the health poll omits credentials; the badge fetch rides the session cookie.
    CHECK(count_of(html, "credentials:'omit'") == 1);
    // No aria-label on the span (A18) and no event dispatch (O7).
    CHECK_THAT(shell_js, !ContainsSubstring("setAttribute('aria-label'"));
    CHECK_THAT(shell_js, !ContainsSubstring("yuzu:approvals-count"));
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
