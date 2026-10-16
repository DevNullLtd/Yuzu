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
#include <string>
#include <string_view>

// Page HTML constant (its own TU at global scope, like kVizFleetPageHtml).
extern const char* const kSettingsHtml;

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
}
