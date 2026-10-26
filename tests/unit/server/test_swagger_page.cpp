/// @file test_swagger_page.cpp
/// The /swagger API-reference page: route gating (driven in-process through
/// TestRouteSink, no httplib acceptor, #438) and the properties of the page
/// text that a regression would silently break. The renderer itself runs in
/// the browser; what is pinned here is what the C++ side can promise.

#include "home_ui.hpp"
#include "page_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <optional>
#include <utility>
#include <string>

extern const char* const kSwaggerPageHtml;
extern const char* const kSwaggerHead;
extern const char* const kSwaggerCss;
extern const char* const kSwaggerBody;
extern const char* const kSwaggerJs1;
extern const char* const kSwaggerJs2;
extern const char* const kSwaggerTail;

using namespace yuzu::server;

namespace {

struct Harness {
    test::TestRouteSink sink;
    bool session_present{true};
    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    void wire() {
        page::Deps deps;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
                return false;
            }
            return true;
        };
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        page::register_page_routes(sink, deps);
    }
};

} // namespace

TEST_CASE("swagger page: a signed-out request is redirected to the landing page",
          "[server][routes][swagger]") {
    Harness h;
    h.session_present = false;
    h.wire();
    auto r = h.sink.Get("/swagger");
    REQUIRE(r);
    CHECK(r->status == 302);
    // The same redirect the pre-routing gate and the sibling pages use.
    CHECK(r->get_header_value("Location") == home_ui::sign_in_location("/swagger"));
}

TEST_CASE("swagger page: gated on Infrastructure:Read like /api/v1/openapi.json",
          "[server][routes][swagger]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    auto denied = h.sink.Get("/swagger");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
    CHECK(denied->body.find("API reference") == std::string::npos);

    Harness ok;
    ok.wire();
    auto r = ok.sink.Get("/swagger");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(r->body.find("API reference") != std::string::npos);
}

TEST_CASE("swagger page: renders from the live spec and builds the DOM safely",
          "[server][routes][swagger]") {
    const std::string html(kSwaggerPageHtml);
    // Reads the same document the API serves, with the operator's own session.
    CHECK(html.find("/api/v1/openapi.json") != std::string::npos);
    CHECK(html.find("credentials: 'same-origin'") != std::string::npos);
    // Spec text contains "<plugin>"-style text: it must never reach innerHTML or the parser.
    for (const char* sink : {"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                             "new Function", "srcdoc", "DOMParser", "createContextualFragment"}) {
        INFO(sink);
        CHECK(html.find(sink) == std::string::npos);
    }
    // htmx hx-on compiles handlers with new Function(); the dashboard CSP blocks it (CLAUDE.md).
    CHECK(html.find("hx-on") == std::string::npos);
    // The shell fills this marker pair in; the page has no nav entry because its shell context
    // names no active item, so it is reached by URL.
    CHECK(html.find("<!--yuzu:shell-->") != std::string::npos);
    // The live region that announces loading, failure and the filter count: the script only
    // writes text into it, so the markup that makes a screen reader speak it must stay on the
    // element (role=status, aria-live=polite).
    const auto at = html.find("id=\"sw-status\"");
    REQUIRE(at != std::string::npos);
    // The whole opening tag, whichever order its attributes are written in.
    const auto open = html.rfind('<', at);
    REQUIRE(open != std::string::npos);
    const std::string region = html.substr(open, html.find('>', at) - open);
    CHECK(region.find("role=\"status\"") != std::string::npos);
    CHECK(region.find("aria-live=\"polite\"") != std::string::npos);
}

TEST_CASE("swagger page: every raw literal stays under the MSVC C2026 ceiling",
          "[server][routes][swagger]") {
    // The page is assembled from separate raw literals; the limit applies to each one, not to the
    // total. 15,000 leaves headroom under 16,380.
    const std::pair<const char*, const char*> pieces[] = {
        {"head", kSwaggerHead}, {"css", kSwaggerCss}, {"body", kSwaggerBody},
        {"js1", kSwaggerJs1},   {"js2", kSwaggerJs2}, {"tail", kSwaggerTail}};
    for (const auto& [name, text] : pieces) {
        INFO(name);
        CHECK(std::strlen(text) < 15000);
    }
    // ...and the pieces are what the page is made of.
    const std::string html(kSwaggerPageHtml);
    CHECK(html.find("function guideBlock") != std::string::npos);
    CHECK(html.find(".sw-guide") != std::string::npos);
}
