/**
 * @file test_settings_pki_page.cpp
 * @brief System > Certificates and secrets: the page template pins, the page route gate and
 *        the KEK status fragment, all without Postgres (stub KekOps, in-process sink).
 *
 * The CA fragment's `?view=pki` shape needs a CaStore, so its route-level cases live in
 * test_ca_routes.cpp beside the existing [pg] harness; the pure renderer is covered by
 * test_ca_panel_render.cpp.
 */

#include "app_shell.hpp"
#include "kek_routes.hpp"
#include "pki_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cctype>
#include <chrono>
#include <regex>
#include <string>
#include <string_view>

extern const char* const kSettingsPkiHtml;

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;

namespace {

bool has(const std::string& h, const std::string& n) { return h.find(n) != std::string::npos; }

/// The templates wrap prose across source lines; collapse runs of whitespace so a phrase
/// assertion does not depend on where the line broke.
std::string squash(const std::string& s) {
    std::string out;
    bool space = false;
    for (unsigned char c : s) {
        if (std::isspace(c)) {
            space = true;
            continue;
        }
        if (space && !out.empty())
            out.push_back(' ');
        space = false;
        out.push_back(static_cast<char>(c));
    }
    return out;
}

std::size_t count_of(const std::string& h, std::string_view n) {
    std::size_t c = 0;
    for (auto p = h.find(n); p != std::string::npos; p = h.find(n, p + n.size()))
        ++c;
    return c;
}

} // namespace

// ── The page template ───────────────────────────────────────────────────────

TEST_CASE("pki page: one shell block, Settings / Certificates and secrets, its own entry lit",
          "[pki_page][pki][ui]") {
    const std::string html = kSettingsPkiHtml;
    CHECK(count_of(html, shell::kShellBegin) == 1);
    CHECK(count_of(html, shell::kShellEnd) == 1);
    CHECK(count_of(html, "fetch('/api/me')") == 1); // the shell's own identity read
    // The family and the child are both lit.
    CHECK_THAT(html, ContainsSubstring("<a class=\"shell-nav on\" href=\"/settings\""));
    CHECK_THAT(html, ContainsSubstring("<a href=\"/settings/pki\" class=\"on\""));
    CHECK_THAT(html, ContainsSubstring("<span>Settings</span><span class=\"shell-sep\">/</span>"
                                       "<b>Certificates and secrets</b>"));
}

TEST_CASE("pki page: the two panels load their fragments and refresh on refreshPki",
          "[pki_page][pki][ui]") {
    const std::string html = kSettingsPkiHtml;
    // The wrappers target #ca-section, so the page must keep that exact id.
    CHECK_THAT(html, ContainsSubstring("id=\"ca-section\""));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/settings/ca?view=pki\""));
    CHECK_THAT(html, ContainsSubstring("id=\"kek-section\""));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/settings/kek\""));
    CHECK(count_of(html, "hx-trigger=\"load, refreshPki from:body\"") == 2);
    // Notices and the (later) reveal box sit OUTSIDE the refreshing sections.
    const auto ca = html.find("id=\"ca-section\"");
    CHECK(html.find("id=\"pki-notices\"") < ca);
    CHECK(html.find("id=\"pki-reveal\"") < ca);
}

TEST_CASE("pki page: no hx-on, no inline handler, htmx eval off, toast host present",
          "[pki_page][pki][ui][security]") {
    const std::string html = kSettingsPkiHtml;
    CHECK_FALSE(has(html, "hx-on"));
    CHECK_FALSE(std::regex_search(html, std::regex(R"(\son[a-z]+\s*=\s*["'])")));
    CHECK_THAT(html, ContainsSubstring("\"allowEval\":false"));
    CHECK_THAT(html, ContainsSubstring("id=\"toast-container\""));
    CHECK_THAT(html, ContainsSubstring("addEventListener('showToast'"));
    // Server text reaches the DOM through textContent only.
    CHECK_FALSE(std::regex_search(html, std::regex(R"(\.innerHTML\s*=)")));
    CHECK_FALSE(has(html, "eval("));
    // The audit-failed banner reads the header every wrapper sets.
    CHECK_THAT(html, ContainsSubstring("Sec-Audit-Failed"));
    // A denied panel says why instead of an endless "Loading...".
    CHECK_THAT(html, ContainsSubstring("needs the Security:Read permission"));
}

TEST_CASE("pki page: the header note replaces the artboard's two unsupported sentences",
          "[pki_page][pki][ui]") {
    const std::string html = kSettingsPkiHtml;
    CHECK_FALSE(has(html, "safe to do while agents are connected"));
    CHECK_FALSE(has(html, "about a minute per 1,000 secrets"));
    CHECK_THAT(squash(html), ContainsSubstring("Key versions cannot be retired."));
}

// ── GET /settings/pki gate ──────────────────────────────────────────────────

TEST_CASE("pki page route: admin gets the page, a refusal redirects home", "[pki_page][pki]") {
    bool allow = true;
    test::TestRouteSink sink;
    pki::register_pki_routes(sink, {.admin_fn = [&](const httplib::Request&, httplib::Response& res) {
        if (!allow) {
            res.status = 403;
            return false;
        }
        return true;
    }});

    auto ok = sink.Get("/settings/pki");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK_THAT(ok->get_header_value("Content-Type"), ContainsSubstring("text/html"));
    CHECK_THAT(ok->body, ContainsSubstring("Certificates and secrets"));

    allow = false;
    auto no = sink.Get("/settings/pki");
    REQUIRE(no);
    CHECK(no->status == 302);
    CHECK(no->get_header_value("Location") == "/");
    CHECK_FALSE(has(no->body, "ca-section"));
}

// ── GET /fragments/settings/kek ─────────────────────────────────────────────

namespace {

struct KekHarness {
    test::TestRouteSink sink;
    bool perm_allow{true};
    std::string last_type, last_op;
    int status_calls{0};
    int rotate_calls{0};
    int rewrap_calls{0};
    KekOpResult status;

    KekHarness() {
        status.active_version = 7;
        status.oldest_in_use = 7;
        status.rotation_complete = true;
        status.live_versions = 7;
        status.lock_held = false;
    }

    void wire(bool status_set = true) {
        KekRoutes routes;
        KekOps ops;
        if (status_set)
            ops.status = [this]() {
                ++status_calls;
                return status;
            };
        ops.rotate = [this]() {
            ++rotate_calls;
            return KekOpResult{};
        };
        ops.rewrap = [this]() {
            ++rewrap_calls;
            return KekOpResult{};
        };
        routes.register_routes(
            sink,
            [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                   const std::string& o) {
                last_type = t;
                last_op = o;
                if (!perm_allow) {
                    res.status = 403;
                    res.set_content(R"({"error":{"code":403}})", "application/json");
                    return false;
                }
                return true;
            },
            [](const httplib::Request&, const std::string&, const std::string&, const std::string&,
               const std::string&, const std::string&) { return true; },
            ops);
    }
};

} // namespace

TEST_CASE("kek fragment: gated on Security:Read, never calls rotate or rewrap", "[kek_fragment][pki]") {
    KekHarness h;
    h.wire();
    auto r = h.sink.Get("/fragments/settings/kek");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(h.last_type == "Security");
    CHECK(h.last_op == "Read");
    CHECK(h.status_calls == 1);
    CHECK(h.rotate_calls == 0);
    CHECK(h.rewrap_calls == 0);
    CHECK_THAT(r->get_header_value("Content-Type"), ContainsSubstring("text/html"));
    CHECK(r->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(r->body, ContainsSubstring("secrets-kek-v7"));

    h.perm_allow = false;
    auto denied = h.sink.Get("/fragments/settings/kek");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(h.status_calls == 1); // refused before the status seam is touched
}

TEST_CASE("kek fragment: a degraded read answers 200 with a fixed sentence, not the twin's 503",
          "[kek_fragment][pki][security]") {
    KekHarness h;
    h.wire();
    for (auto [failure, text] :
         {std::pair{KekOpResult::Failure::Unavailable, "not available (secrets store not ready)"},
          std::pair{KekOpResult::Failure::QueryCanceled, "cancelled or timed out"},
          std::pair{KekOpResult::Failure::Internal, "internal error"},
          std::pair{KekOpResult::Failure::ClockAnomaly, "internal error"}}) {
        h.status = {};
        h.status.failure = failure;
        auto r = h.sink.Get("/fragments/settings/kek");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_THAT(r->body, ContainsSubstring(text));
        CHECK_FALSE(has(r->body, "secrets-kek-v"));
    }
}

TEST_CASE("kek fragment: an unset status seam is the unavailable sentence", "[kek_fragment][pki]") {
    KekHarness h;
    h.wire(/*status_set=*/false);
    auto r = h.sink.Get("/fragments/settings/kek");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_THAT(r->body, ContainsSubstring("Key management is not available"));
}

TEST_CASE("kek fragment: lock holder details and unknown figures survive the route",
          "[kek_fragment][pki]") {
    KekHarness h;
    h.status.rotation_complete = false;
    h.status.oldest_in_use = 6;
    h.status.live_versions.reset();
    h.status.lock_held = true;
    h.status.lock_holder_pid = 18342;
    h.status.lock_holder_captured_at =
        std::chrono::system_clock::time_point{std::chrono::seconds{1'800'000'000}};
    h.wire();
    auto r = h.sink.Get("/fragments/settings/kek");
    REQUIRE(r);
    CHECK_THAT(r->body, ContainsSubstring("Re-wrap incomplete:"));
    CHECK_THAT(r->body, ContainsSubstring("<span>Live key versions</span><b>Unknown</b>"));
    CHECK_THAT(r->body, ContainsSubstring("backend pid 18342, read at 08:00:00 UTC"));
}

TEST_CASE("kek fragment: the REST twin is untouched and still answers JSON", "[kek_fragment][pki]") {
    KekHarness h;
    h.wire();
    auto r = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_THAT(r->get_header_value("Content-Type"), ContainsSubstring("application/json"));
}
