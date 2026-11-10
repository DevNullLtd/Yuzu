/// @file test_settings_page_ui.cpp
/// Pure-string pins on the /settings page shell (`kSettingsHtml`, settings_ui.cpp,
/// served verbatim by GET /settings). The page is one static document whose 21 panels each
/// lazy-load one fragment, so a panel dropped, renamed or detached from its loader by a
/// restyle leaves every route test green. Data in, markup out: no server, no store, no
/// request. The fragment routes themselves are covered by the test_settings_routes_*.cpp
/// files and test_ca_routes.cpp.

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <regex>
#include <string>
#include <string_view>

// Page HTML constant (its own TU at global scope, like kVizFleetPageHtml).
extern const char* const kSettingsHtml;

namespace yuzu::server {
extern const std::string kYuzuTokensJs; // the AUDIT_FAILED sentence's home (#6749)
}

namespace {

struct Panel {
    std::string_view title;      // text of the .section-header, as written in the markup
    std::string_view section_id; // id of the lazy-load container inside the panel
    std::string_view fragment;   // the hx-get target that fills it
};

// In page order.
constexpr std::array<Panel, 21> kPanels{{
    {"Server Configuration", "server-config-section", "/fragments/settings/server-config"},
    {"TLS / mTLS Configuration", "tls-section", "/fragments/settings/tls"},
    {"HTTPS Console", "https-section", "/fragments/settings/https"},
    {"Internal Certificate Authority", "ca-section", "/fragments/settings/ca"},
    {"User Management", "user-section", "/fragments/settings/users"},
    {"Multi-Factor Authentication", "mfa-section", "/fragments/settings/mfa"},
    {"Enrollment Tokens", "token-section", "/fragments/settings/tokens"},
    {"API Tokens", "api-token-section", "/fragments/settings/api-tokens"},
    {"Engine Principals", "engine-principals-section", "/fragments/settings/engine-principals"},
    {"Access Reviews", "access-review-section", "/fragments/settings/access-reviews"},
    {"Auto-Approve Policies", "auto-approve-section", "/fragments/settings/auto-approve"},
    {"Pending Agent Approvals", "pending-section", "/fragments/settings/pending"},
    {"Plugin Code Signing", "plugin-signing-section", "/fragments/settings/plugin-signing"},
    {"Agent Updates (OTA)", "updates-section", "/fragments/settings/updates"},
    {"Gateway", "gateway-section", "/fragments/settings/gateway"},
    {"Analytics &amp; Telemetry", "analytics-section", "/fragments/settings/analytics"},
    {"Data Retention", "data-retention-section", "/fragments/settings/data-retention"},
    {"MCP (AI Integration)", "mcp-section", "/fragments/settings/mcp"},
    {"Vulnerability Management", "nvd-section", "/fragments/settings/nvd"},
    {"Management Groups", "mgmt-groups-section", "/fragments/settings/management-groups"},
    {"Directory Integration / OIDC SSO", "directory-section", "/fragments/settings/directory"},
}};

std::size_t count_of(const std::string& haystack, std::string_view needle) {
    std::size_t n = 0;
    for (auto pos = haystack.find(needle); pos != std::string::npos;
         pos = haystack.find(needle, pos + needle.size())) {
        ++n;
    }
    return n;
}

} // namespace

TEST_CASE("Settings page carries all 21 panels, each wired to its fragment loader",
          "[settings][settings_page]") {
    const std::string html = kSettingsHtml;

    CHECK(count_of(html, "class=\"section-header\"") == kPanels.size());
    CHECK(count_of(html, "hx-get=\"/fragments/settings/") == kPanels.size());

    std::size_t from = 0;
    for (const auto& p : kPanels) {
        INFO("panel: " << p.title);
        const std::string header =
            "<div class=\"section-header\">" + std::string{p.title} + "</div>";
        const auto header_at = html.find(header, from);
        REQUIRE(header_at != std::string::npos); // present, and after the previous panel

        const auto loader_at = html.find("<div id=\"" + std::string{p.section_id} + "\"", header_at);
        REQUIRE(loader_at != std::string::npos);
        const auto frag_at = html.find("hx-get=\"" + std::string{p.fragment} + "\"", loader_at);
        REQUIRE(frag_at != std::string::npos);

        // The loader belongs to THIS panel, not to a later one.
        const auto next_header_at =
            html.find("class=\"section-header\"", header_at + header.size());
        CHECK((next_header_at == std::string::npos || frag_at < next_header_at));
        from = frag_at;
    }
}

TEST_CASE("Settings page carries the static Settings heading", "[settings][settings_page]") {
    const std::string html = kSettingsHtml;
    CHECK(count_of(html, "<h1>Settings</h1>") == 1);
    CHECK(count_of(html, "<h1") == 1);
}

TEST_CASE("Settings page keeps the td-level state colours", "[settings][settings_page]") {
    const std::string html = kSettingsHtml;
    CHECK(count_of(html, ".user-table td.muted { color: var(--mut); }") == 1);
    CHECK(count_of(html, ".user-table td.feedback-error { color: var(--bad); }") == 1);
}

TEST_CASE("Settings page hides the unlimited-token hint once a limit is typed",
          "[settings][settings_page]") {
    // The enrolment-token fragment always renders the hint; the Settings page does not load
    // yuzu-groups.js, so its own script must follow the two limit fields. The logic is the
    // same as the Groups glue (pinned in test_groups_js.cpp).
    const std::string html = kSettingsHtml;
    CHECK(count_of(html, "document.addEventListener('input'") == 1);
    CHECK(count_of(html, "closest('[data-token-form]')") == 1);
    CHECK(count_of(html, "querySelector('[data-token-unlimited]')") == 1);
    CHECK(count_of(html, "zero('max_uses') && zero('ttl_hours')") == 1);
    // zero() counts only a literal zero (including the -0 spelling the route also reads as 0) —
    // a blank field takes the bounded default, not unlimited.
    CHECK(count_of(html, "v === '' ||") == 0);
    CHECK(count_of(html, "/^-?0+$/.test(v)") == 1);
}

TEST_CASE("Settings page shows the refreshed list a stale enrolment action returns with a 409",
          "[settings][settings_page]") {
    // htmx drops every 4xx body by default; the enrolment routes answer a stale click with a
    // 409 whose body is the refreshed panel. Same rule as the Groups glue.
    const std::string html = kSettingsHtml;
    CHECK(count_of(html, "'htmx:beforeSwap'") == 1);
    CHECK(count_of(html, "d.xhr.status === 409") == 1);
    CHECK(count_of(html, "'#token-section, #pending-section, #auto-approve-section'") == 1);
    CHECK(count_of(html, "indexOf('text/html') !== -1") == 1);
    CHECK(count_of(html, "d.shouldSwap = true;") == 1);
    CHECK(count_of(html, "d.isError = false;") == 1);
}

TEST_CASE("Settings page tells a caller the Engine Principals panel refused why, not 'Loading...' "
          "forever",
          "[settings][settings_page][engine_principal]") {
    // The panel gates on EnginePrincipal:Read (#5882), which the page's own administrator gate
    // does not imply, and htmx does not swap a 4xx body. A body listener scoped to the panel
    // says so. CSP-safe: no hx-on, no eval, text only.
    const std::string html = kSettingsHtml;
    CHECK(count_of(html, "'htmx:responseError'") == 1);
    CHECK(count_of(html, "el.id !== 'engine-principals-section'") == 1);
    CHECK(count_of(html, "It needs the EnginePrincipal:Read permission.") == 1);
    CHECK(count_of(html, "Sign in again to view this panel.") == 1);
    CHECK(count_of(html, "(HTTP ' + x.status + ')") == 1);
    // The 5xx/429 note offers the in-page Retry (kEngineRetryControl's wording) and never tells
    // the caller to reload: a reload discards a credential secret shown outside the section.
    CHECK(count_of(html, "Retry here instead of reloading the page, which would discard a "
                         "credential secret shown above.") == 1);
    CHECK(count_of(html, "htmx.trigger(document.body, 'refreshEnginePrincipals')") >= 1);
    CHECK(count_of(html, "Reload the page to try again.") == 0);
    // The note is written as text, never parsed as markup.
    const auto at = html.find("'htmx:responseError'");
    REQUIRE(at != std::string::npos);
    const auto end = html.find("\n    });", at); // the listener's own close, not a nested one
    REQUIRE(end != std::string::npos);
    const auto body = html.substr(at, end - at);
    CHECK(count_of(body, "el.textContent = ") == 3);
    CHECK(count_of(body, "innerHTML") == 0);
    // The listener writes only to the panel's own section, never to the secret-reveal element
    // that sits outside it (a mint or rotate response is shown there and must survive).
    CHECK(count_of(body, "engine-principal-reveal") == 0);
    CHECK(count_of(body, "getElementById") == 0);
    CHECK(count_of(body, "hx-on") == 0);
    CHECK(count_of(body, "new Function") == 0);
    CHECK(count_of(body, "eval(") == 0);
    // No element on the page carries an hx-on attribute (CSP has no 'unsafe-eval'; htmx compiles
    // hx-on:* with new Function() and the handler silently does nothing). Comments may name it.
    CHECK_FALSE(std::regex_search(html, std::regex{R"(<[a-zA-Z][^<>]*\shx-on[:\-])"}));
}

TEST_CASE("Settings page says so, once, when the Engine Principals roster read's audit row was not "
          "saved (#6749)",
          "[settings][settings_page][engine_principal]") {
    // The roster read answers 200 with `Sec-Audit-Failed: true` when its audit write failed: the
    // data is current, the evidence is missing. A body listener shows the same sentence the
    // Tokens and principals page shows. CSP-safe: no hx-on, no eval, text only.
    const std::string html = kSettingsHtml;
    constexpr std::string_view kSentence =
        "An audit record for this read could not be saved. The data shown is still current.";

    // The notice target is a sibling placed BEFORE the refreshing section and after the reveal
    // element, so neither the section's innerHTML swap nor the reveal's content touches it.
    const std::string target = "<div id=\"engine-principals-notices\"></div>";
    REQUIRE(count_of(html, target) == 1);
    const auto reveal = html.find("<div id=\"engine-principal-reveal\"></div>");
    const auto notices = html.find(target);
    const auto section = html.find("<div id=\"engine-principals-section\"");
    REQUIRE(reveal != std::string::npos);
    REQUIRE(section != std::string::npos);
    CHECK(reveal < notices);
    CHECK(notices < section);

    // Keyed on the REQUEST PATH (the section is the only requester of it), not on an element id,
    // and only on a 200: a 403 never claims "the data shown is still current".
    CHECK(count_of(html, "d.pathInfo.requestPath") == 1);
    CHECK(count_of(html,
                   "d.pathInfo.requestPath !== '/fragments/settings/engine-principals'") == 1);

    // The listener's slice: from its addEventListener to its own close.
    const auto at = html.find("document.getElementById('engine-principals-notices')");
    REQUIRE(at != std::string::npos);
    const auto start = html.rfind("addEventListener('htmx:afterRequest'", at);
    REQUIRE(start != std::string::npos);
    const auto end = html.find("\n    });", at);
    REQUIRE(end != std::string::npos);
    const auto body = html.substr(start, end - start);
    CHECK(count_of(body, "x.status !== 200") == 1);
    CHECK(count_of(body, "getResponseHeader('Sec-Audit-Failed') !== 'true'") == 1);
    CHECK(count_of(body, "notices.firstChild") == 1); // insert-once: repeated failures, one note
    CHECK(count_of(body, "className = 'failbox'") == 1);
    CHECK(count_of(body, "setAttribute('role', 'alert')") == 1);
    CHECK(count_of(body, "box.textContent = ") == 1);
    CHECK(count_of(body, "notices.appendChild(box)") == 1);
    // Each guard ends in `return;`, so a failed guard never reaches the insert.
    CHECK(count_of(body, ") return;") == 4);
    // Text only; never markup, never the secret-reveal element, never eval.
    CHECK(count_of(body, "innerHTML") == 0);
    CHECK(count_of(body, "engine-principal-reveal") == 0);
    CHECK(count_of(body, "hx-on") == 0);
    CHECK(count_of(body, "new Function") == 0);
    CHECK(count_of(body, "eval(") == 0);
    // getElementById is how the notices div is found (insert-once needs the lookup).
    CHECK(count_of(body, "getElementById('engine-principals-notices')") == 1);

    // The sentence is the Tokens and principals page's AUDIT_FAILED, byte for byte (a hand copy).
    CHECK(count_of(body, std::string("'") + std::string(kSentence) + "'") == 1);
    CHECK(count_of(yuzu::server::kYuzuTokensJs,
                   std::string("var AUDIT_FAILED = '") + std::string(kSentence) + "';") == 1);
}
