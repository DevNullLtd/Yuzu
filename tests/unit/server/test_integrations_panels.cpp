/// test_integrations_panels.cpp — the MCP and Gateway panels of the System "Integrations"
/// page (integrations_render.*) and the MCP settings POST they write through.
///
/// Pure first. The MCP handler had no direct test before this file; the literal bodies
/// below are the ones the previous markup actually produced (a hidden `false` field then
/// the checkbox) and the partial bodies a stale page or a script could send.
///
///   - parse_mcp_form: key-boundary parsing, exactly one of each field, true/false only
///   - the rendered form always yields a body that parses, in all four states
///   - POST /api/settings/mcp: a refused body changes nothing; an accepted body changes
///     exactly the two flags, audits, and re-renders the panel
///   - Gateway and MCP panels: states, escaping, honest labels

#include "integrations_render.hpp"
#include "settings_routes.hpp"

#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::integrations;

namespace {

std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

/// What a browser submits for the rendered form: for each radio group, the checked
/// radio's value. Reads the MARKUP, so a render that checked two boxes, none, or posted a
/// hidden fallback would show up as a different body.
std::string browser_body(const std::string& html) {
    std::string body;
    for (const char* name : {"enabled", "read_only"}) {
        const std::regex checked(std::string("<input type=\"radio\" name=\"") + name +
                                 "\" value=\"([a-z]+)\" checked>");
        std::sregex_iterator it(html.begin(), html.end(), checked), end;
        std::vector<std::string> vals;
        for (; it != end; ++it)
            vals.push_back((*it)[1].str());
        for (const auto& v : vals) {
            if (!body.empty())
                body += '&';
            body += std::string(name) + "=" + v;
        }
    }
    return body;
}

} // namespace

// ── parse_mcp_form ──────────────────────────────────────────────────────

TEST_CASE("mcp form: exactly one enabled and one read_only and true or false",
          "[integrations][mcp][settings]") {
    auto ok = parse_mcp_form("enabled=true&read_only=false");
    REQUIRE(ok);
    CHECK(ok->enabled);
    CHECK_FALSE(ok->read_only);

    ok = parse_mcp_form("read_only=true&enabled=false");
    REQUIRE(ok);
    CHECK_FALSE(ok->enabled);
    CHECK(ok->read_only);

    // A field named like ours at a different key boundary is not ours.
    ok = parse_mcp_form("xenabled=true&enabled=false&myread_only=false&read_only=true");
    REQUIRE(ok);
    CHECK_FALSE(ok->enabled);
    CHECK(ok->read_only);
}

TEST_CASE("mcp form: the bodies the old panel and partial callers sent are refused",
          "[integrations][mcp][settings]") {
    struct Case {
        const char* body;
        const char* error;
    };
    const Case cases[] = {
        // The previous markup posted a hidden `false` and then the checkbox: first-match
        // parsing read `false`, so any change made while MCP was on switched it off.
        {"enabled=false&enabled=true&read_only=false", "enabled must be supplied exactly once"},
        {"enabled=true&read_only=true&read_only=false", "read_only must be supplied exactly once"},
        // An absent field used to mean false: this flipped Read-only to Full access.
        {"enabled=true", "read_only is required"},
        // ... and this one switched MCP off.
        {"read_only=true", "enabled is required"},
        {"", "enabled is required"},
        {"enabled=yes&read_only=true", "enabled must be true or false"},
        {"enabled=true&read_only=", "read_only must be true or false"},
        {"enabled=TRUE&read_only=false", "enabled must be true or false"},
        {"enabled&read_only=true", "enabled must be true or false"},
    };
    for (const auto& c : cases) {
        INFO(c.body);
        const auto r = parse_mcp_form(c.body);
        REQUIRE_FALSE(r);
        CHECK(r.error() == c.error);
    }
}

// ── MCP panel ───────────────────────────────────────────────────────────

TEST_CASE("mcp panel: one control per field and no hidden fallback and all four states parse",
          "[integrations][mcp][settings]") {
    for (const bool enabled : {true, false})
        for (const bool read_only : {true, false}) {
            INFO("enabled=" << enabled << " read_only=" << read_only);
            const auto html = render_mcp_panel({enabled, read_only, "http://localhost:8080/mcp/v1/"});
            CHECK_THAT(html, !ContainsSubstring("type=\"hidden\""));
            CHECK_THAT(html, !ContainsSubstring("type=\"checkbox\""));
            CHECK(count_of(html, "name=\"enabled\"") == 2);
            CHECK(count_of(html, "name=\"read_only\"") == 2);
            CHECK(count_of(html, " checked") == 2); // one per group

            // What the browser would send round-trips to exactly the state that was rendered.
            const auto form = parse_mcp_form(browser_body(html));
            REQUIRE(form);
            CHECK(form->enabled == enabled);
            CHECK(form->read_only == read_only);
        }
}

TEST_CASE("mcp panel: the three confirms ride on the form and fall back to hx-confirm",
          "[integrations][mcp][settings]") {
    const auto html = render_mcp_panel({true, true, "http://localhost:8080/mcp/v1/"});
    CHECK(count_of(html, "<form") == 1);
    CHECK_THAT(html, ContainsSubstring("hx-post=\"/api/settings/mcp\""));
    CHECK_THAT(html, ContainsSubstring("hx-target=\"#mcp-section\""));
    // The wording is review A2: three states, and Read-only does not claim write access.
    CHECK_THAT(html, ContainsSubstring("data-confirm-full=\"Allow agentic workers to run write and "
                                       "execute tools?"));
    CHECK_THAT(html, ContainsSubstring("data-confirm-readonly=\"Turn the MCP endpoint on in "
                                       "read-only mode?"));
    CHECK_THAT(html, ContainsSubstring("cannot run write or execute tools"));
    CHECK_THAT(html, ContainsSubstring("data-confirm-off=\"Stop the MCP endpoint? Connected "
                                       "agentic workers are refused immediately."));
    CHECK_THAT(html, ContainsSubstring("hx-confirm=\"Save the MCP settings?"));
    CHECK(std::string(kMcpConfirmReadOnly).find("write and execute tools?") == std::string::npos);
}

TEST_CASE("mcp panel: restart caveat always and --mcp-disable note only when disabled",
          "[integrations][mcp][settings]") {
    const auto on = render_mcp_panel({true, false, "http://h:1/mcp/v1/"});
    CHECK_THAT(on, ContainsSubstring("Changes apply until the server restarts"));
    CHECK_THAT(on, !ContainsSubstring("--mcp-disable"));

    const auto off = render_mcp_panel({false, false, "http://h:1/mcp/v1/"});
    CHECK_THAT(off, ContainsSubstring("Changes apply until the server restarts"));
    CHECK_THAT(off, ContainsSubstring("<code>--mcp-disable</code>"));
    CHECK_THAT(off, ContainsSubstring("has no effect until it restarts"));
}

TEST_CASE("mcp panel: endpoint is read-only text and escaped and with no Copy control and no 'section above'",
          "[integrations][mcp][settings][security]") {
    const auto hostile = render_mcp_panel({true, true, "http://x\"><img src=x onerror=1>/mcp/v1/"});
    CHECK_THAT(hostile, !ContainsSubstring("<img"));
    CHECK_THAT(hostile, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
    const auto html = render_mcp_panel({true, true, "http://h:8080/mcp/v1/"});
    // The endpoint is not an editable field and has no clipboard control.
    CHECK_THAT(html, !ContainsSubstring("type=\"text\""));
    CHECK_THAT(html, !ContainsSubstring("data-copy"));
    CHECK_THAT(html, !ContainsSubstring("section above"));
    CHECK_THAT(html, ContainsSubstring("Create them in the API Tokens panel on the"));
    // No inline handler of any kind in the fragment.
    static const std::regex inline_handler(R"re(\son[a-z]+\s*=)re");
    CHECK_FALSE(std::regex_search(html, inline_handler));
}

// ── Gateway panel ───────────────────────────────────────────────────────

TEST_CASE("gateway panel: running shows address and mode and the honestly named session count",
          "[integrations][gateway][settings]") {
    const auto html = render_gateway_panel({true, "0.0.0.0:50055", true, 7});
    CHECK_THAT(html, ContainsSubstring("<span>Upstream service</span><b><span class=\"pill ok\">"
                                       "Enabled</span></b>"));
    CHECK_THAT(html, ContainsSubstring("<code>0.0.0.0:50055</code>"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill ok\">Active</span>"));
    CHECK_THAT(html, ContainsSubstring("<span>Agents via gateway</span><b>7 agents</b>"));
    CHECK_THAT(html, !ContainsSubstring("Active Sessions"));
    CHECK_THAT(html, !ContainsSubstring("is not running"));

    CHECK_THAT(render_gateway_panel({true, "x", false, 1}),
               ContainsSubstring("<b>1 agent</b>"));
    CHECK_THAT(render_gateway_panel({true, "x", false, 0}),
               ContainsSubstring("<span class=\"pill idle\">Inactive</span>"));
}

TEST_CASE("gateway panel: not running keeps the flag guidance verbatim and hides the rows",
          "[integrations][gateway][settings]") {
    const auto html = render_gateway_panel({false, "", false, 0});
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill idle\">Disabled</span>"));
    for (const char* flag : {"--gateway-upstream 0.0.0.0:50055", "--gateway-peer-pin",
                             "--gateway-peer-pin-file", "--insecure-gateway-peer",
                             "Pins are read once at boot; changing them needs a restart."})
        CHECK_THAT(html, ContainsSubstring(flag));
    CHECK_THAT(html, !ContainsSubstring("Listen address"));
    CHECK_THAT(html, !ContainsSubstring("Agents via gateway"));
}

TEST_CASE("gateway panel: no invented figures and the env reference is complete and collapsed",
          "[integrations][gateway][settings]") {
    const auto html = render_gateway_panel({true, "0.0.0.0:50055", true, 3});
    // Drawn on the artboard but with no source in the code.
    CHECK_THAT(html, !ContainsSubstring("Gateway nodes"));
    CHECK_THAT(html, !ContainsSubstring("mutual TLS"));
    CHECK_THAT(html, ContainsSubstring("<details><summary>Erlang gateway environment variables"));
    CHECK(count_of(html, "<code>YUZU_GW_") == 10);
}

TEST_CASE("gateway panel: the listen address is escaped", "[integrations][gateway][settings][security]") {
    const auto html = render_gateway_panel({true, "<script>1</script>", false, 0});
    CHECK_THAT(html, !ContainsSubstring("<script>"));
    CHECK_THAT(html, ContainsSubstring("&lt;script&gt;"));
}

// ── POST /api/settings/mcp through SettingsRoutes ───────────────────────

namespace {

struct McpHarness {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    SettingsRoutes routes;

    bool admin_ok{true};
    struct Audit {
        std::string action, result, target_type, target_id, detail;
    };
    std::vector<Audit> audits;   // outcome rows (the void AuditFn)
    std::vector<Audit> attempts; // the audit-first `attempted` rows (the bool AuditReadFn)
    bool audit_persists{true};   // false: the audit-first hook reports a failed write

    yuzu::server::test::TestRouteSink sink; // last: handlers capture `this`

    McpHarness() {
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
        auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (admin_ok)
                return true;
            res.status = 403;
            res.set_content(R"({"error":{"code":403,"message":"admin role required"}})",
                            "application/json");
            return false;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti, const std::string& d) {
            audits.push_back({a, r, tt, ti, d});
        };
        auto audit_read_fn = [this](const httplib::Request&, const std::string& a,
                                    const std::string& r, const std::string& tt,
                                    const std::string& ti, const std::string& d) -> bool {
            attempts.push_back({a, r, tt, ti, d});
            return audit_persists;
        };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                               /*gateway_enabled=*/true, []() -> std::size_t { return 7; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                               nullptr, {}, audit_read_fn);
    }

    auto post(const std::string& body) {
        return sink.Post("/api/settings/mcp", body, "application/x-www-form-urlencoded");
    }
};

} // namespace

TEST_CASE("mcp POST: a refused body changes nothing and is not audited",
          "[integrations][mcp][settings][routes]") {
    McpHarness h;
    h.cfg.mcp_disable = false;
    h.cfg.mcp_read_only = true; // Read-only, MCP on

    for (const char* body :
         {"enabled=true",                                    // old handler: Read-only -> Full access
          "read_only=true",                                  // old handler: MCP off
          "",                                                // old handler: MCP off, Full access
          "enabled=false&enabled=true&read_only=false",      // what the old panel posted
          "enabled=maybe&read_only=true"}) {
        INFO(body);
        auto res = h.post(body);
        REQUIRE(res);
        CHECK(res->status == 400);
        // The A4 envelope, as on every other migrated /api/settings/* route: the body names
        // the refusal and its correlation id, and the same id rides the response header.
        const auto j = nlohmann::json::parse(res->body);
        CHECK(j.at("error").at("code").get<int>() == 400);
        CHECK_FALSE(j.at("error").at("message").get<std::string>().empty());
        const auto cid = res->get_header_value("X-Correlation-Id");
        CHECK_FALSE(cid.empty());
        CHECK(j.at("error").at("correlation_id").get<std::string>() == cid);
        // Observed state is untouched.
        CHECK_FALSE(h.cfg.mcp_disable);
        CHECK(h.cfg.mcp_read_only);
    }
    CHECK(h.audits.empty());
    CHECK(h.attempts.empty());
}

TEST_CASE("mcp POST: when the attempted row cannot be written nothing changes (mutation: "
          "mutate before auditing)",
          "[integrations][mcp][settings][routes][security]") {
    McpHarness h;
    h.cfg.mcp_disable = false;
    h.cfg.mcp_read_only = true;
    h.audit_persists = false;

    auto res = h.post("enabled=false&read_only=false");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(h.cfg.mcp_disable);
    CHECK(h.cfg.mcp_read_only);
    REQUIRE(h.attempts.size() == 1);
    CHECK(h.attempts[0].result == "attempted");
    CHECK(h.audits.empty());
}

TEST_CASE("mcp POST: a header-less cookie write is refused 403 and changes nothing",
          "[integrations][mcp][settings][routes][security]") {
    McpHarness h;
    h.cfg.mcp_disable = false;
    h.cfg.mcp_read_only = true;
    h.sink.default_headers = {{"Host", "yuzu.test"}}; // no Origin, no Referer

    auto res = h.post("enabled=false&read_only=false");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(h.cfg.mcp_disable);
    CHECK(h.cfg.mcp_read_only);
    CHECK(h.attempts.empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "csrf.denied");
}

TEST_CASE("mcp POST: a cross-site Origin is refused 403 and changes nothing",
          "[integrations][mcp][settings][routes][security]") {
    McpHarness h;
    h.cfg.mcp_disable = false;
    h.cfg.mcp_read_only = true;
    h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}};

    auto res = h.post("enabled=false&read_only=false");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(h.cfg.mcp_disable);
    CHECK(h.cfg.mcp_read_only);
    CHECK(h.attempts.empty());
}

TEST_CASE("mcp POST: an accepted body sets exactly the two flags and audits and re-renders",
          "[integrations][mcp][settings][routes]") {
    McpHarness h;
    h.cfg.mcp_disable = true;
    h.cfg.mcp_read_only = true;

    auto res = h.post("enabled=true&read_only=false");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(h.cfg.mcp_disable);
    CHECK_FALSE(h.cfg.mcp_read_only);

    REQUIRE(h.attempts.size() == 1); // audit-first: written before the flags move
    CHECK(h.attempts[0].action == "settings.mcp");
    CHECK(h.attempts[0].result == "attempted");
    CHECK(h.attempts[0].detail == "enabled=true, read_only=false");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "settings.mcp");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail == "enabled=true, read_only=false");

    // The response is the re-rendered panel in the new state, and a toast trigger.
    CHECK_THAT(res->body, ContainsSubstring("<span class=\"pill ok\">Enabled</span>"));
    CHECK_THAT(res->body, ContainsSubstring("<span class=\"pill info\">Full access</span>"));
    CHECK_THAT(res->get_header_value("HX-Trigger"), ContainsSubstring("MCP settings saved"));

    // Turning it off keeps the access mode the form carried.
    res = h.post("enabled=false&read_only=true");
    REQUIRE(res);
    CHECK(h.cfg.mcp_disable);
    CHECK(h.cfg.mcp_read_only);
}

TEST_CASE("mcp POST: a non-admin is refused before the body is read",
          "[integrations][mcp][settings][routes][security]") {
    McpHarness h;
    h.admin_ok = false;
    h.cfg.mcp_disable = false;
    auto res = h.post("enabled=false&read_only=true");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(h.cfg.mcp_disable);
    CHECK(h.audits.empty());
}

TEST_CASE("fragments: the existing URLs serve the rebuilt panels", "[integrations][settings][routes]") {
    McpHarness h;
    auto g = h.sink.Get("/fragments/settings/gateway");
    REQUIRE(g);
    CHECK_THAT(g->body, ContainsSubstring("<span>Agents via gateway</span><b>7 agents</b>"));

    h.cfg.mcp_read_only = true;
    auto m = h.sink.Get("/fragments/settings/mcp");
    REQUIRE(m);
    CHECK_THAT(m->body, ContainsSubstring("id=\"mcp-form\""));
    CHECK_THAT(m->body, ContainsSubstring("<span class=\"pill warn\">Read-only</span>"));

    h.admin_ok = false;
    for (const char* path : {"/fragments/settings/gateway", "/fragments/settings/mcp"}) {
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 403);
    }
}
