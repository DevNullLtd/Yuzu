/// test_integrations_page.cpp — the System "Integrations" page route, baked page and
/// page script (integrations_routes.*, integrations_ui.cpp, static/yuzu-integrations.js).
///
/// Pure: the page is a baked string, the script an embedded string, the route takes a
/// gate closure. Nothing here needs a store, a socket or a sleep.
///
///   - the page is admin-gated and a refused caller is redirected to `/`
///   - one h1, two loaders at the existing ids, no hx-on / inline handlers / script-side
///     HTML writes / eval, and nothing on the page that the code cannot back
///   - the script: delegated listeners, textContent only

#include "integrations_routes.hpp"

#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <httplib.h>

#include <regex>
#include <string>

extern const char* const kSettingsIntegrationsHtml;
namespace yuzu::server {
extern const std::string kYuzuIntegrationsJs;
}

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server::integrations;

namespace {

std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

} // namespace

// ── Page route and script ───────────────────────────────────────────────

TEST_CASE("integrations routes: the page is admin-gated and a refused caller is redirected",
          "[integrations][settings][routes][security]") {
    bool admin = true;
    yuzu::server::test::TestRouteSink sink;
    register_integrations_routes(sink, Deps{.admin_fn = [&](const httplib::Request&,
                                                            httplib::Response& res) {
        if (admin)
            return true;
        res.status = 403;
        return false;
    }});
    CHECK(sink.route_count() == 2);

    auto ok = sink.Get("/settings/integrations");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(ok->body, ContainsSubstring("<h1>Integrations</h1>"));

    admin = false;
    auto refused = sink.Get("/settings/integrations");
    REQUIRE(refused);
    CHECK(refused->status == 302);
    CHECK(refused->get_header_value("Location") == "/");
    CHECK(refused->body.find("<h1>") == std::string::npos);

    // The script is static: served without the admin gate, revalidated every load.
    auto js = sink.Get("/static/yuzu-integrations.js");
    REQUIRE(js);
    CHECK(js->status == 200);
    CHECK_THAT(js->get_header_value("Content-Type"), ContainsSubstring("application/javascript"));
    CHECK_THAT(js->get_header_value("Cache-Control"), ContainsSubstring("no-store"));
    CHECK(js->body == yuzu::server::kYuzuIntegrationsJs);
}

TEST_CASE("integrations page: structure and loaders at the existing ids and CSP-safe markup",
          "[integrations][settings][page]") {
    const std::string html = kSettingsIntegrationsHtml;
    CHECK(count_of(html, "<!--yuzu:shell-->") == 1);
    CHECK(count_of(html, "<h1>") == 1);
    CHECK(count_of(html, "fetch('/api/me')") == 1);

    // Five panels: MCP and Gateway at the ids the monolith and the ledger already use,
    // plus the three sync panels (webhooks, offload targets, directory sync).
    CHECK(count_of(html, "hx-get=\"/fragments/settings/") == 5);
    CHECK_THAT(html, ContainsSubstring("id=\"mcp-section\""));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/settings/mcp\""));
    CHECK_THAT(html, ContainsSubstring("id=\"gateway-section\""));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/settings/gateway\""));

    // The nav lights Integrations; the breadcrumb is Settings / Integrations.
    CHECK_THAT(html, ContainsSubstring("<a href=\"/settings/integrations\" class=\"on\" "
                                       "aria-current=\"page\">"));
    CHECK_THAT(html, ContainsSubstring("<span>Settings</span><span class=\"shell-sep\">/</span>"
                                       "<b>Integrations</b>"));

    // The page names only what it hosts; nothing is promised that is not on it.
    CHECK_THAT(html, ContainsSubstring(
                         "Directory sync, webhooks, offload targets, the MCP endpoint and the gateway."));
    for (const char* absent : {"SIEM", "Syslog", "Healthy", "Gateway nodes"})
        CHECK_THAT(html, !ContainsSubstring(absent));

    // Toast host and the script tag.
    CHECK_THAT(html, ContainsSubstring("id=\"toast-container\""));
    CHECK_THAT(html, ContainsSubstring("<script src=\"/static/yuzu-integrations.js\" defer></script>"));
    // Per-panel refresh events for the sync panels, then their controller.
    CHECK_THAT(html, ContainsSubstring("refreshWebhooks from:body"));
    CHECK_THAT(html, ContainsSubstring("refreshOffload from:body"));
    CHECK_THAT(html, ContainsSubstring("refreshDirectory from:body"));
    CHECK_THAT(html, ContainsSubstring("<script src=\"/static/yuzu-integrations-sync.js\" defer></script>"));
    // No inline script at all on this page: the script is the static file.
    CHECK(count_of(html, "<script>") == 2); // the shell's own two: identity/online and the header bell

    CHECK_THAT(html, !ContainsSubstring("hx-on"));
    static const std::regex inline_handler(R"re(\son[a-z]+\s*=)re");
    CHECK_FALSE(std::regex_search(html, inline_handler));
    static const std::regex html_write(R"re(\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML)re");
    CHECK_FALSE(std::regex_search(html, html_write));
    CHECK_THAT(html, !ContainsSubstring("eval("));
}

TEST_CASE("integrations script: delegated listeners and textContent only and no eval",
          "[integrations][settings][page]") {
    const std::string& js = yuzu::server::kYuzuIntegrationsJs;
    CHECK_FALSE(js.empty());
    CHECK_THAT(js, !ContainsSubstring("innerHTML"));
    CHECK_THAT(js, !ContainsSubstring("outerHTML"));
    CHECK_THAT(js, !ContainsSubstring("insertAdjacentHTML"));
    CHECK_THAT(js, !ContainsSubstring("eval("));
    CHECK_THAT(js, !ContainsSubstring("new Function"));
    CHECK_THAT(js, !ContainsSubstring("document.write"));
    // Server text (toast message, error body) is written with textContent.
    CHECK_THAT(js, ContainsSubstring("t.textContent = message"));
    // The three jobs: toast host, refused-request feedback, the state-dependent MCP confirm.
    CHECK_THAT(js, ContainsSubstring("addEventListener('showToast'"));
    CHECK_THAT(js, ContainsSubstring("addEventListener('htmx:responseError'"));
    CHECK_THAT(js, ContainsSubstring("addEventListener('htmx:confirm'"));
    CHECK_THAT(js, ContainsSubstring("f.id !== 'mcp-form'"));
    CHECK_THAT(js, ContainsSubstring("e.detail.issueRequest(true)"));
    // The field guard must run before the event is cancelled, else a markup change leaves
    // Save dead (the fallback hx-confirm never gets its turn).
    const auto guard = js.find("!f.elements.enabled || !f.elements.read_only");
    const auto cancel = js.find("e.preventDefault()");
    REQUIRE(guard != std::string::npos);
    REQUIRE(cancel != std::string::npos);
    CHECK(guard < cancel);
    // It must not smuggle the raw-string delimiter embed_js.py refuses.
    CHECK_THAT(js, !ContainsSubstring(")ECHARTSEMBED\""));
}
