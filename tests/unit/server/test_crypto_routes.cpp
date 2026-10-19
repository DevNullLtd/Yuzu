// Route-level tests for the /crypto surface (CryptoRoutes): the page shell, both HTMX
// fragments and both REST v1 routes, over a fake CryptoApi and a fake fleet-read gate. No
// Postgres: the seam is faked, so these pin the gate / scope / audit / status-code / escaping
// contract of the route owner itself. The seam over the real store is test_crypto_api.cpp.

#include "authz_gates.hpp"
#include "crypto_library_model.hpp"
#include "crypto_routes.hpp"
#include "crypto_ui.hpp"
#include "crypto_widget_catalogue.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <expected>
#include <map>
#include <set>
#include <memory>
#include <optional>
#include <regex>
#include <unordered_set>
#include <string>
#include <vector>

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;

namespace {

// Calls the fake records, so a test can pin WHICH scope reached the seam and how often.
class FakeCryptoApi final : public CryptoApi {
public:
    std::expected<CryptoSummary, CryptoReadError> summary_result{CryptoSummary{}};
    std::expected<CryptoDevicesPage, CryptoReadError> devices_result{CryptoDevicesPage{}};
    mutable std::vector<authz::VisibleSet> scopes;
    mutable std::vector<CryptoDevicesQuery> devices_queries;
    mutable std::vector<CryptoSummaryQuery> summary_queries;
    mutable int summary_calls{0};

    std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const override {
        ++summary_calls;
        summary_queries.push_back(q);
        scopes.push_back(scope);
        return summary_result;
    }
    std::expected<CryptoDevicesPage, CryptoReadError>
    library_devices(const CryptoDevicesQuery& q, const authz::VisibleSet& scope) const override {
        scopes.push_back(scope);
        devices_queries.push_back(q);
        return devices_result;
    }

    // ── Dashboard widget methods ──
    std::expected<CaCertStats, CryptoReadError> stats_result{CaCertStats{}};
    std::expected<CaCertPage, CryptoReadError> certs_result{CaCertPage{}};
    // Per-user stored layouts: a user with no entry gets the catalogue default.
    mutable std::map<std::string, std::vector<std::string>> layouts;
    std::optional<CryptoReadError> layout_error;
    mutable std::vector<std::int64_t> stats_as_of;
    mutable std::vector<std::pair<CaCertQuery, std::int64_t>> cert_calls;
    mutable int layout_writes{0};

    std::expected<CaCertStats, CryptoReadError> ca_stats(std::int64_t as_of) const override {
        stats_as_of.push_back(as_of);
        if (!stats_result)
            return stats_result;
        auto s = *stats_result;
        s.as_of = as_of;
        return s;
    }
    std::expected<CaCertPage, CryptoReadError> ca_certificates(const CaCertQuery& q,
                                                               std::int64_t as_of) const override {
        cert_calls.emplace_back(q, as_of);
        if (!certs_result)
            return certs_result;
        auto p = *certs_result;
        p.query = q;
        p.as_of = as_of;
        return p;
    }
    std::expected<CryptoDashboardLayout, CryptoReadError>
    dashboard_layout(const std::string& username) const override {
        if (layout_error)
            return std::unexpected(*layout_error);
        if (const auto it = layouts.find(username); it != layouts.end())
            return CryptoDashboardLayout{it->second, false};
        return CryptoDashboardLayout{crypto_widgets::default_layout_ids(), true};
    }
    std::expected<CryptoDashboardLayout, CryptoReadError>
    set_dashboard_layout(const std::string& username,
                         const std::vector<std::string>& widgets) const override {
        ++layout_writes;
        if (layout_error)
            return std::unexpected(*layout_error);
        layouts[username] = widgets;
        return CryptoDashboardLayout{widgets, false};
    }
};

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

CryptoSummary sample_summary() {
    CryptoSummary s;
    CryptoFamilyRow f;
    f.id = "openssl";
    f.display = "OpenSSL";
    f.device_count = 7;
    f.versions.push_back({"3.0.13", "deb", 5, {"libssl3"}});
    f.versions.push_back({"", "rpm", 2, {"openssl-libs"}});
    s.families.push_back(f);
    s.coverage = {12, 7};
    s.names_from_catalogue = true;
    s.names_as_of = 1760000000; // 2025-10-09 08:53 UTC
    return s;
}

CryptoDevicesPage sample_page(const std::string& pkg = "libssl3",
                              const std::string& host = "host-1") {
    CryptoDevicesPage p;
    p.family = "openssl";
    p.devices.push_back({"agent-1", host, pkg, "3.0.13", "0ubuntu3.4", "deb", "package"});
    return p;
}

struct Harness {
    // `routes` first so it destructs LAST: `sink` captures its `this` (TestRouteSink convention).
    CryptoRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::shared_ptr<FakeCryptoApi> api = std::make_shared<FakeCryptoApi>();
    std::vector<AuditCall> audits;
    bool audit_ok{true};
    bool admitted{true};
    int deny_status{403}; // 503 = the gate DEGRADED (RBAC store unreadable) rather than refused
    authz::VisibleSet scope; // nullopt = TOP
    int gate_calls{0};
    // The Yuzu-issued gate (perm_fn Security:Read) and the drawing probe (has_perm_fn).
    bool security_read{true};
    int security_deny_status{403};
    std::vector<std::pair<std::string, std::string>> perm_calls;
    std::set<std::string> held{"Inventory:Read", "Security:Read"};
    int probe_calls{0};
    std::string username{"tester"};

    explicit Harness(bool wire_gate = true, bool wire_api = true, bool wire_perm = true) {
        CryptoRoutes::Deps d;
        d.auth_fn = [this](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = username;
            s.role = auth::Role::admin;
            return s;
        };
        if (wire_perm) {
            d.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                               const std::string& securable, const std::string& op) {
                perm_calls.emplace_back(securable, op);
                if (!security_read) {
                    res.status = security_deny_status;
                    res.set_content(R"({"error":{"message":"permission denied"}})",
                                    "application/json");
                    return false;
                }
                return true;
            };
            d.has_perm_fn = [this](const httplib::Request&, const std::string& securable,
                                   const std::string& op) {
                ++probe_calls;
                return held.contains(securable + ":" + op);
            };
        }
        // Unwired resolver = a cookie session: the PUT needs a same-site Origin.
        d.write_gate = WriteGate{};
        if (wire_gate)
            d.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const std::string& securable,
                                     const std::string& op) -> authz::FleetReadGate {
                ++gate_calls;
                CHECK(securable == "Inventory");
                CHECK(op == "Read");
                if (!admitted) {
                    res.status = deny_status;
                    res.set_content(R"({"error":{"message":"permission denied"}})",
                                    "application/json");
                    return {};
                }
                return {true, scope};
            };
        if (wire_api)
            d.api = api;
        d.audit_fn = [this](const httplib::Request&, const std::string& action,
                            const std::string& result, const std::string& target_type,
                            const std::string& target_id, const std::string& detail) -> bool {
            audits.push_back({action, result, target_type, target_id, detail});
            return audit_ok;
        };
        routes.register_routes(sink, std::move(d));
    }
};

nlohmann::json body_of(const httplib::Response& r) { return nlohmann::json::parse(r.body); }

} // namespace

TEST_CASE("crypto routes: the page shell lights the Crypto nav item and loads the fragment",
          "[crypto][routes]") {
    Harness h;
    auto res = h.sink.dispatch("GET", "/crypto");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("hx-get=\"/fragments/crypto/dashboard\""));
    CHECK_THAT(res->body, ContainsSubstring("<a class=\"shell-nav on\" href=\"/crypto\""));
    // The chart engine, adapter and cryDash helper load in <head>, on this page only.
    const auto head_end = res->body.find("</head>");
    REQUIRE(head_end != std::string::npos);
    for (const char* script : {"/static/echarts.min.js", "/static/yuzu-charts.js", "window.cryDash"}) {
        const auto at = res->body.find(script);
        REQUIRE(at != std::string::npos);
        CHECK(at < head_end);
    }
    const auto helper = crypto_html::dashboard_head_html();
    CHECK_THAT(helper, !ContainsSubstring("hx-on"));
    CHECK_THAT(helper, !ContainsSubstring("eval("));
    CHECK(res->get_header_value("Cache-Control") == "no-cache, no-store, must-revalidate");
    CHECK(h.gate_calls == 0); // auth-only chrome: the data gate lives on the fragment
}

TEST_CASE("crypto routes: REST summary - TOP scope reaches the seam and is audited",
          "[crypto][routes][rest]") {
    Harness h;
    h.api->summary_result = sample_summary();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/libraries?family=openssl");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto j = body_of(*res);
    CHECK(j["data"]["table_version"] == crypto_library::kCryptoTableVersion);
    CHECK(j["data"]["families"][0]["id"] == "openssl");
    CHECK(j["data"]["coverage"]["devices_reporting_inventory"] == 12);
    CHECK_FALSE(j["data"].contains("audit_persisted"));
    REQUIRE(h.api->scopes.size() == 1);
    CHECK_FALSE(h.api->scopes[0].has_value()); // TOP, passed straight through
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.libraries.view");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "Inventory");
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("cid="));
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("family=openssl"));
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("rows=1"));
    CHECK_THAT(h.audits[0].detail, !ContainsSubstring("page=continuation"));
}

TEST_CASE("crypto routes: a scoped caller's exact scope reaches the seam on every route",
          "[crypto][routes][security]") {
    Harness h;
    h.scope = authz::VisibleSet{std::unordered_set<std::string>{"a1", "a2"}};
    h.api->summary_result = sample_summary();
    h.api->devices_result = sample_page();
    for (const char* path : {"/api/v1/crypto/libraries", "/fragments/crypto/libraries",
                             "/api/v1/crypto/libraries/devices?family=openssl",
                             "/fragments/crypto/libraries/devices?family=openssl"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    REQUIRE(h.api->scopes.size() == 4);
    for (const auto& s : h.api->scopes) {
        REQUIRE(s.has_value());
        CHECK(*s == std::unordered_set<std::string>{"a1", "a2"});
    }
}

TEST_CASE("crypto routes: a refused gate - REST keeps the gate's 403; fragments answer 200 + caveat",
          "[crypto][routes][security]") {
    Harness h;
    h.admitted = false;
    for (const char* path : {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=nss"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, ContainsSubstring("permission denied")); // the gate's own body
    }
    for (const char* path :
         {"/fragments/crypto/libraries", "/fragments/crypto/libraries/devices?family=nss"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("cry-caveat"));
        CHECK_THAT(res->body, ContainsSubstring("Inventory:Read"));
    }
    CHECK(h.api->scopes.empty()); // no seam read after a refusal
    CHECK(h.audits.empty());      // the gate audits its own refusal; the route does not duplicate it
}

TEST_CASE("crypto routes: present-empty scope still reaches the seam (zero rows; not the fleet)",
          "[crypto][routes][security]") {
    Harness h;
    h.scope = authz::deny_all();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/libraries");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.api->scopes.size() == 1);
    REQUIRE(h.api->scopes[0].has_value());
    CHECK(h.api->scopes[0]->empty());
}

TEST_CASE("crypto routes: an unwired gate fails closed with 503 on every route",
          "[crypto][routes][security]") {
    Harness h(/*wire_gate=*/false);
    for (const char* path :
         {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=nss",
          "/fragments/crypto/libraries", "/fragments/crypto/libraries/devices?family=nss"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    CHECK(h.api->scopes.empty());
}

TEST_CASE("crypto routes: no seam (no inventory store) is a 503 / degrade banner; never empty",
          "[crypto][routes]") {
    Harness h(/*wire_gate=*/true, /*wire_api=*/false);
    auto rest = h.sink.dispatch("GET", "/api/v1/crypto/libraries");
    REQUIRE(rest);
    CHECK(rest->status == 503);
    auto frag = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(frag);
    CHECK(frag->status == 200);
    CHECK_THAT(frag->body, ContainsSubstring("cry-degrade"));
    CHECK_THAT(frag->body, !ContainsSubstring("No matching package rows"));
}

TEST_CASE("crypto routes: a degraded read is REST 503 + retry_after_ms; fragment 200 + banner",
          "[crypto][routes][rest]") {
    Harness h;
    h.api->summary_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    h.api->devices_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    for (const char* path :
         {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=openssl"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 503);
        const auto j = body_of(*res);
        CHECK(j["error"]["retry_after_ms"] == 5000);
    }
    for (const char* path :
         {"/fragments/crypto/libraries", "/fragments/crypto/libraries/devices?family=openssl"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
    }
    // The degraded access leaves a failure trail on every attempt.
    REQUIRE(h.audits.size() == 4);
    for (const auto& a : h.audits)
        CHECK(a.result == "failure");
}

TEST_CASE("crypto routes: a capacity shed and a store fault are worded apart on REST and on the "
          "page and row banners",
          "[crypto][routes][rest][ui]") {
    namespace cl = yuzu::server::crypto_library;
    Harness h;
    const char* cont = "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x";
    for (const auto cause : {CryptoReadCause::kCapacity, CryptoReadCause::kStoreDegraded}) {
        const bool shed = cause == CryptoReadCause::kCapacity;
        const CryptoReadError err{CryptoReadError::Kind::kDegraded,
                                  std::string(cl::degraded_message(cause)), cause};
        h.api->summary_result = std::unexpected(err);
        h.api->devices_result = std::unexpected(err);
        // REST: the text is the model's single wording (MCP uses the same function).
        for (const char* path :
             {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=openssl"}) {
            auto res = h.sink.dispatch("GET", path);
            REQUIRE(res);
            CHECK(res->status == 503);
            CHECK(body_of(*res)["error"]["message"] == std::string(cl::degraded_message(cause)));
        }
        // Page, first drill page and continuation row all follow the cause.
        for (const char* path :
             {"/fragments/crypto/libraries", "/fragments/crypto/libraries/devices?family=openssl", cont}) {
            auto res = h.sink.dispatch("GET", path);
            REQUIRE(res);
            CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
            if (shed) {
                CHECK_THAT(res->body, ContainsSubstring("Temporarily busy: two reads are already running"));
                CHECK_THAT(res->body, !ContainsSubstring("could not be read"));
            } else {
                CHECK_THAT(res->body, ContainsSubstring("The inventory store could not be read"));
                CHECK_THAT(res->body, !ContainsSubstring("Temporarily busy"));
            }
        }
    }
}

TEST_CASE("crypto routes: bad parameters are REST 400 and a fragment 200 caveat; with no read",
          "[crypto][routes][rest]") {
    Harness h;
    for (const char* path :
         {"/api/v1/crypto/libraries?family=nope", "/api/v1/crypto/libraries?family=nss&family=gnutls",
          "/api/v1/crypto/libraries/devices", "/api/v1/crypto/libraries/devices?family=nope",
          "/api/v1/crypto/libraries/devices?family=nss&limit=abc"}) {
        INFO(path);
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(body_of(*res).contains("error"));
    }
    for (const char* path :
         {"/fragments/crypto/libraries?family=nope", "/fragments/crypto/libraries/devices",
          "/fragments/crypto/libraries/devices?family=nss&limit=abc"}) {
        INFO(path);
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("cry-caveat"));
    }
    CHECK(h.api->scopes.empty());
    CHECK(h.audits.empty());
}

TEST_CASE("crypto routes: a seam-refused cursor is REST 400 and a fragment 200 caveat",
          "[crypto][routes]") {
    Harness h;
    h.api->devices_result =
        std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "invalid cursor"});
    auto rest = h.sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=nss&cursor=zzz");
    REQUIRE(rest);
    CHECK(rest->status == 400);
    CHECK_THAT(rest->body, ContainsSubstring("invalid cursor"));
    auto frag = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=nss&cursor=zzz");
    REQUIRE(frag);
    CHECK(frag->status == 200);
    CHECK_THAT(frag->body, ContainsSubstring("invalid cursor"));
}

TEST_CASE("crypto routes: a cursor page is audited as a continuation; the first page is not",
          "[crypto][routes][security]") {
    Harness h;
    h.api->devices_result = sample_page();
    REQUIRE(h.sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=openssl")->status == 200);
    REQUIRE(h.sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=openssl&cursor=k1:x")
                ->status == 200);
    REQUIRE(h.sink.dispatch("GET",
                            "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x")
                ->status == 200);
    REQUIRE(h.audits.size() == 3);
    CHECK(h.audits[0].action == "crypto.libraries.devices");
    CHECK_THAT(h.audits[0].detail, !ContainsSubstring("page=continuation"));
    CHECK_THAT(h.audits[1].detail, ContainsSubstring("page=continuation"));
    CHECK_THAT(h.audits[2].detail, ContainsSubstring("page=continuation"));
    CHECK_THAT(h.audits[1].detail, ContainsSubstring("family=openssl"));
    CHECK_THAT(h.audits[1].target_id, ContainsSubstring("family=openssl"));
    REQUIRE(h.api->devices_queries.size() == 3);
    CHECK(h.api->devices_queries[1].cursor == "k1:x");
}

TEST_CASE("crypto routes: a lost audit row is flagged; not fatal (set-and-proceed)",
          "[crypto][routes][security]") {
    Harness h;
    h.audit_ok = false;
    h.api->summary_result = sample_summary();
    h.api->devices_result = sample_page();
    for (const char* path :
         {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=openssl"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(body_of(*res)["data"]["audit_persisted"] == false);
    }
    auto frag = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(frag);
    CHECK(frag->status == 200);
    CHECK(frag->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("crypto routes: the library fragment renders the figures; the drill links and the "
          "permanent caveat",
          "[crypto][routes][ui]") {
    Harness h;
    h.api->summary_result = sample_summary();
    auto res = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("OpenSSL"));
    CHECK_THAT(res->body, ContainsSubstring("/fragments/crypto/libraries/devices?family=openssl"));
    CHECK_THAT(res->body, ContainsSubstring("version=3.0.13&amp;ecosystem=deb"));
    CHECK_THAT(res->body, ContainsSubstring("(unknown)")); // the empty-version bucket is labelled
    CHECK_THAT(res->body, ContainsSubstring("Package-level evidence only"));
    CHECK_THAT(res->body, ContainsSubstring("Certificates, SSH host keys and protocol settings"));
    CHECK_THAT(res->body, ContainsSubstring("Package names as of 2025-10-09 08:53 UTC"));
    CHECK_THAT(res->body, !ContainsSubstring("hx-on"));
    // Interpretation words never appear in the markup.
    for (const char* word : {"vulnerable", "weak", "outdated", "insecure", "quantum"})
        CHECK_THAT(res->body, !ContainsSubstring(word));
    // The empty result states what empty means.
    h.api->summary_result = CryptoSummary{};
    auto empty = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(empty);
    CHECK_THAT(empty->body, ContainsSubstring("not proof"));
    CHECK_THAT(empty->body, ContainsSubstring("Package-level evidence only"));
}

TEST_CASE("crypto page: the names note says catalogue time; read live; or nothing for an absurd stamp",
          "[crypto][routes][ui]") {
    Harness h;
    auto s = sample_summary();
    s.names_from_catalogue = false;
    s.names_as_of = 0;
    h.api->summary_result = s;
    auto live = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(live);
    CHECK_THAT(live->body, ContainsSubstring("Package names read live"));
    CHECK_THAT(live->body, !ContainsSubstring("Package names as of"));
    // A stamp beyond year 9999 is skipped, not rendered (std::format would be out of range).
    s.names_from_catalogue = true;
    s.names_as_of = std::int64_t{9000000000000};
    h.api->summary_result = s;
    auto absurd = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(absurd);
    CHECK(absurd->status == 200);
    CHECK_THAT(absurd->body, !ContainsSubstring("Package names as of"));
    CHECK_THAT(absurd->body, !ContainsSubstring("Package names read live"));
}

TEST_CASE("crypto page: a family whose version list was cut shows it even with no version rows",
          "[crypto][routes][ui]") {
    Harness h;
    auto s = sample_summary();
    s.families[0].versions.clear();
    s.families[0].versions_truncated = true;
    h.api->summary_result = s;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("versions not shown"));
}

TEST_CASE("crypto routes: hostile package and host names are HTML-escaped",
          "[crypto][routes][ui][security]") {
    Harness h;
    const std::string evil = "<script>alert(1)</script>";
    auto s = sample_summary();
    s.families[0].versions[0].version = evil;
    s.families[0].versions[0].ecosystem = "\"><img src=x>";
    s.families[0].versions[0].package_names = {evil};
    h.api->summary_result = s;
    h.api->devices_result = sample_page(evil, evil);
    for (const char* path : {"/fragments/crypto/libraries",
                             "/fragments/crypto/libraries/devices?family=openssl",
                             "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK_THAT(res->body, !ContainsSubstring("<script>alert"));
        CHECK_THAT(res->body, !ContainsSubstring("<img src=x>"));
    }
    auto drill = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl");
    CHECK_THAT(drill->body, ContainsSubstring("&lt;script&gt;"));
    // REST is JSON: the hostile text round-trips as data.
    auto rest = h.sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=openssl");
    CHECK(body_of(*rest)["data"]["devices"][0]["hostname"] == evil);
}

TEST_CASE("crypto routes: a device drill with a next cursor offers Load more; the last page does not",
          "[crypto][routes][ui]") {
    Harness h;
    h.api->devices_result = sample_page();
    h.api->devices_result->next_cursor = "k1:abc";
    auto first = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl");
    REQUIRE(first);
    CHECK_THAT(first->body, ContainsSubstring("cursor=k1%3Aabc"));
    CHECK_THAT(first->body, ContainsSubstring("Load more"));
    // A continuation response is rows only (swapped into the existing table).
    auto next = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x");
    REQUIRE(next);
    CHECK_THAT(next->body, ContainsSubstring("<tr"));
    CHECK_THAT(next->body, !ContainsSubstring("<table"));
    h.api->devices_result->next_cursor.clear();
    auto last = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl");
    CHECK_THAT(last->body, !ContainsSubstring("Load more"));
}

TEST_CASE("crypto routes: a gate that DEGRADED (503) shows the unavailable banner; a refusal does not",
          "[crypto][routes][ui]") {
    Harness h;
    h.admitted = false;
    h.deny_status = 503;
    for (const char* path :
         {"/fragments/crypto/libraries", "/fragments/crypto/libraries/devices?family=nss"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
        CHECK_THAT(res->body, ContainsSubstring("unavailable"));
        CHECK_THAT(res->body, !ContainsSubstring("not available to this account"));
    }
    // REST keeps the gate's own 503.
    CHECK(h.sink.dispatch("GET", "/api/v1/crypto/libraries")->status == 503);
    // A genuine 403 says "not available to this account" and is not a degrade banner.
    h.deny_status = 403;
    auto refused = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(refused);
    CHECK_THAT(refused->body, ContainsSubstring("not available to this account"));
    // The class attribute, not the bare name: the summary's note now carries the component CSS,
    // whose rules name .cry-degrade.
    CHECK_THAT(refused->body, !ContainsSubstring("class=\"cry-degrade\""));
    CHECK_THAT(refused->body, ContainsSubstring("class=\"cry-caveat\""));
    // A continuation page that is refused or degraded is ONE table row, never a bare block.
    const char* cont = "/fragments/crypto/libraries/devices?family=nss&cursor=k1:x";
    auto row403 = h.sink.dispatch("GET", cont);
    REQUIRE(row403);
    CHECK(row403->body.rfind("<tr", 0) == 0);
    CHECK_THAT(row403->body, ContainsSubstring("colspan"));
    h.deny_status = 503;
    auto row503 = h.sink.dispatch("GET", cont);
    REQUIRE(row503);
    CHECK(row503->body.rfind("<tr", 0) == 0);
    CHECK_THAT(row503->body, ContainsSubstring("cry-degrade"));
    CHECK_THAT(row503->body, ContainsSubstring("closest tr"));
}

TEST_CASE("crypto routes: a Load-more page that degrades; is refused a cursor or is a bad request "
          "answers one <tr> row; an empty page with a cursor still offers the next page",
          "[crypto][routes][ui]") {
    Harness h;
    const char* cont = "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x";
    h.api->devices_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    auto degraded = h.sink.dispatch("GET", cont);
    REQUIRE(degraded);
    CHECK(degraded->body.rfind("<tr", 0) == 0);
    CHECK_THAT(degraded->body, ContainsSubstring("hx-get=\"/fragments/crypto/libraries/devices?"));
    CHECK_THAT(degraded->body, ContainsSubstring("cry-degrade"));

    h.api->devices_result = std::unexpected(
        CryptoReadError{CryptoReadError::Kind::kInvalid, "cursor was issued for a different filter set"});
    auto invalid = h.sink.dispatch("GET", cont);
    REQUIRE(invalid);
    CHECK(invalid->body.rfind("<tr", 0) == 0);
    CHECK_THAT(invalid->body, ContainsSubstring("different filter set"));

    auto bad = h.sink.dispatch(
        "GET", "/fragments/crypto/libraries/devices?family=nope&cursor=k1:x");
    REQUIRE(bad);
    CHECK(bad->body.rfind("<tr", 0) == 0);

    // The first (non-continuation) page keeps the block form.
    auto first = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=nope");
    REQUIRE(first);
    CHECK(first->body.rfind("<div", 0) == 0);

    // Empty devices + a cursor: the Load-more row must still render, on both page kinds.
    CryptoDevicesPage empty;
    empty.family = "openssl";
    empty.next_cursor = "k1:more";
    h.api->devices_result = empty;
    auto page1 = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl");
    REQUIRE(page1);
    CHECK_THAT(page1->body, ContainsSubstring("Load more"));
    CHECK_THAT(page1->body, !ContainsSubstring("No matching package rows"));
    auto page2 = h.sink.dispatch("GET", cont);
    REQUIRE(page2);
    CHECK_THAT(page2->body, ContainsSubstring("Load more"));
}

TEST_CASE("crypto routes: a PRESENT ecosystem; even empty; is the exact ecosystem on every route",
          "[crypto][routes]") {
    Harness h;
    h.api->summary_result = sample_summary();
    h.api->devices_result = sample_page();
    for (const char* base : {"/api/v1/crypto/libraries", "/fragments/crypto/libraries"}) {
        REQUIRE(h.sink.dispatch("GET", std::string(base) + "?ecosystem=")->status == 200);
        REQUIRE(h.sink.dispatch("GET", base)->status == 200);
    }
    for (const char* base :
         {"/api/v1/crypto/libraries/devices", "/fragments/crypto/libraries/devices"}) {
        REQUIRE(h.sink.dispatch("GET", std::string(base) + "?family=openssl&ecosystem=")->status == 200);
        REQUIRE(h.sink.dispatch("GET", std::string(base) + "?family=openssl")->status == 200);
    }
    REQUIRE(h.api->summary_queries.size() == 4);
    for (int i : {0, 2}) {
        REQUIRE(h.api->summary_queries[i].ecosystem);
        CHECK(h.api->summary_queries[i].ecosystem->empty());
    }
    for (int i : {1, 3})
        CHECK_FALSE(h.api->summary_queries[i].ecosystem);
    REQUIRE(h.api->devices_queries.size() == 4);
    for (int i : {0, 2}) {
        REQUIRE(h.api->devices_queries[i].ecosystem);
        CHECK(h.api->devices_queries[i].ecosystem->empty());
    }
    for (int i : {1, 3})
        CHECK_FALSE(h.api->devices_queries[i].ecosystem);
}

TEST_CASE("crypto routes: every bucket chip carries its ecosystem; the empty one included",
          "[crypto][routes][ui]") {
    Harness h;
    auto s = sample_summary();
    s.families[0].versions.push_back({"9.9", "", 1, {"libssl3"}});
    h.api->summary_result = s;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("version=9.9&amp;ecosystem=\""));
    // the family row itself drills into every ecosystem: no ecosystem parameter
    CHECK_THAT(res->body, ContainsSubstring("devices?family=openssl\""));
}

TEST_CASE("crypto routes: a 200-byte version is drillable (bounds equal the ingest bound)",
          "[crypto][routes]") {
    Harness h;
    h.api->devices_result = sample_page();
    const std::string v(200, '1');
    CHECK(h.sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=openssl&version=" + v)
              ->status == 200);
    CHECK(h.sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=openssl&version=" +
                                     std::string(crypto_library::kVersionMaxBytes + 1, '1'))
              ->status == 400);
}

TEST_CASE("crypto routes: the audit detail is one key set on every page and verb",
          "[crypto][routes][security]") {
    Harness h;
    h.api->summary_result = sample_summary();
    h.api->devices_result = sample_page();
    REQUIRE(h.sink.dispatch("GET", "/api/v1/crypto/libraries")->status == 200);
    REQUIRE(h.sink.dispatch("GET", "/fragments/crypto/libraries")->status == 200);
    REQUIRE(h.sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=openssl&cursor=k1:x")
                ->status == 200);
    REQUIRE(h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl")->status == 200);
    REQUIRE(h.audits.size() == 4);
    const std::string tv = "tv=" + std::to_string(crypto_library::kCryptoTableVersion);
    for (const auto& a : h.audits) {
        CHECK_THAT(a.detail, ContainsSubstring("cid="));
        CHECK_THAT(a.detail, ContainsSubstring(tv));
        CHECK_THAT(a.detail, ContainsSubstring("family="));
        CHECK_THAT(a.detail, ContainsSubstring("rows="));
    }
    // A degraded read leaves the same cid + tv prefix.
    h.api->summary_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    REQUIRE(h.sink.dispatch("GET", "/api/v1/crypto/libraries")->status == 503);
    CHECK_THAT(h.audits.back().detail, ContainsSubstring(tv));
    CHECK_THAT(h.audits.back().detail, ContainsSubstring("store degraded"));
}

TEST_CASE("crypto routes: the page names the per-OS evidence sources and the table size",
          "[crypto][routes][ui]") {
    Harness h;
    h.api->summary_result = sample_summary();
    auto res = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("Homebrew packages only"));
    CHECK_THAT(res->body, ContainsSubstring("registered with the OS"));
    CHECK_THAT(res->body, ContainsSubstring("Families matched"));
    CHECK_THAT(res->body,
               ContainsSubstring("of " + std::to_string(crypto_library::families().size()) + " in the table"));
    CHECK_THAT(res->body, ContainsSubstring("planned and not yet available"));
    CHECK_THAT(res->body, !ContainsSubstring("later releases"));
}

TEST_CASE("crypto routes: a family whose versions were all cut says so instead of a dash",
          "[crypto][routes][ui]") {
    Harness h;
    auto s = sample_summary();
    s.families[0].versions.clear();
    s.families[0].versions_truncated = true;
    s.result_truncated = true;
    h.api->summary_result = s;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("versions not shown"));
    CHECK_THAT(res->body, ContainsSubstring("capped (row or size limit)"));
}

// ── Review #6056 round 1 ─────────────────────────────────────────────────────

TEST_CASE("crypto routes: a lost audit row shows a visible notice on both fragments and keeps the "
          "header",
          "[crypto][routes][ui][security]") {
    const std::string notice(crypto_html::kAuditNotPersistedNotice);
    for (const bool ok : {false, true}) {
        INFO("audit persisted: " << ok);
        Harness h;
        h.audit_ok = ok;
        h.api->summary_result = sample_summary();
        h.api->devices_result = sample_page();
        h.api->devices_result->next_cursor = "k1:more";
        for (const char* path : {"/fragments/crypto/libraries",
                                 "/fragments/crypto/libraries/devices?family=openssl",
                                 "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x"}) {
            INFO(path);
            auto res = h.sink.dispatch("GET", path);
            REQUIRE(res);
            CHECK(res->status == 200);
            if (ok) {
                CHECK_THAT(res->body, !ContainsSubstring(notice));
                CHECK_THAT(res->body, !ContainsSubstring("Audit not recorded"));
                CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
            } else {
                CHECK_THAT(res->body, ContainsSubstring(notice));
                CHECK_THAT(res->body, ContainsSubstring("yuzu_server_audit_emit_failed_total"));
                CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            }
        }
        // A continuation page's notice is a table row (it replaces the Load-more <tr>).
        auto cont = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x");
        CHECK(cont->body.rfind("<tr", 0) == 0);
        // The data is still served (set-and-proceed).
        auto lib = h.sink.dispatch("GET", "/fragments/crypto/libraries");
        CHECK_THAT(lib->body, ContainsSubstring("OpenSSL"));
    }
}

TEST_CASE("crypto routes: a degraded read whose failure audit row is lost shows the notice too",
          "[crypto][routes][ui][security]") {
    Harness h;
    h.audit_ok = false;
    h.api->summary_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    h.api->devices_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    for (const char* path : {"/fragments/crypto/libraries",
                             "/fragments/crypto/libraries/devices?family=openssl",
                             "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x"}) {
        INFO(path);
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring(std::string(crypto_html::kAuditNotPersistedNotice)));
        CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
    auto cont = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x");
    CHECK(cont->body.rfind("<tr", 0) == 0);
}

TEST_CASE("crypto routes: the four scoped data routes are no-store and private and vary on every "
          "credential",
          "[crypto][routes][security]") {
    Harness h;
    h.api->summary_result = sample_summary();
    h.api->devices_result = sample_page();
    for (const char* path : {"/api/v1/crypto/libraries", "/fragments/crypto/libraries",
                             "/api/v1/crypto/libraries/devices?family=openssl",
                             "/fragments/crypto/libraries/devices?family=openssl"}) {
        INFO(path);
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->get_header_value("Cache-Control") == "no-store, private");
        CHECK(res->get_header_value("Vary") == "Authorization, Cookie, X-Yuzu-Token");
    }
    // A refusal keeps the headers too (set before the gate).
    h.admitted = false;
    auto refused = h.sink.dispatch("GET", "/api/v1/crypto/libraries");
    REQUIRE(refused);
    CHECK(refused->status == 403);
    CHECK(refused->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("crypto routes: the audit detail says scope=fleet for TOP and scope=confined otherwise",
          "[crypto][routes][security]") {
    const char* paths[] = {"/api/v1/crypto/libraries", "/fragments/crypto/libraries",
                           "/api/v1/crypto/libraries/devices?family=openssl",
                           "/fragments/crypto/libraries/devices?family=openssl"};
    struct Case {
        authz::VisibleSet scope;
        const char* want;
    };
    for (const auto& c : {Case{std::nullopt, "scope=fleet"},
                          Case{authz::VisibleSet{std::unordered_set<std::string>{"a1"}}, "scope=confined"},
                          Case{authz::VisibleSet{std::unordered_set<std::string>{}}, "scope=confined"}}) {
        INFO(c.want);
        Harness h;
        h.scope = c.scope;
        h.api->summary_result = sample_summary();
        h.api->devices_result = sample_page();
        for (const char* path : paths)
            REQUIRE(h.sink.dispatch("GET", path)->status == 200);
        // and the failure rows
        h.api->summary_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
        h.api->devices_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
        for (const char* path : paths)
            REQUIRE(h.sink.dispatch("GET", path));
        REQUIRE(h.audits.size() == 8);
        for (const auto& a : h.audits) {
            INFO(a.result << " " << a.detail);
            CHECK_THAT(a.detail, ContainsSubstring(c.want));
        }
    }
}

TEST_CASE("crypto routes: a failed first-page drill retries the drill into its own box; not the "
          "summary",
          "[crypto][routes][ui]") {
    Harness h;
    h.api->devices_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    auto res = h.sink.dispatch(
        "GET", "/fragments/crypto/libraries/devices?family=openssl&version=3.0&ecosystem=deb");
    REQUIRE(res);
    CHECK(res->body.rfind("<div", 0) == 0);
    CHECK_THAT(res->body, ContainsSubstring(
                              "hx-get=\"/fragments/crypto/libraries/devices?family=openssl&amp;"
                              "version=3.0&amp;ecosystem=deb\""));
    CHECK_THAT(res->body, ContainsSubstring("hx-target=\"#cry-exp-openssl\""));
    CHECK_THAT(res->body, !ContainsSubstring("hx-get=\"/fragments/crypto/libraries\""));
    CHECK_THAT(res->body, !ContainsSubstring("#guardian-detail"));
    // The family row's drill box carries that same id.
    h.api->summary_result = sample_summary();
    auto lib = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    CHECK_THAT(lib->body, ContainsSubstring("id=\"cry-exp-openssl\""));
    // A gate that degraded on the first-page drill retries the drill too.
    h.admitted = false;
    h.deny_status = 503;
    auto gate = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl");
    REQUIRE(gate);
    CHECK_THAT(gate->body, ContainsSubstring("hx-target=\"#cry-exp-openssl\""));
    // The summary's own degrade still reloads the summary.
    h.admitted = true;
    h.api->summary_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    auto sum = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    CHECK_THAT(sum->body, ContainsSubstring("hx-get=\"/fragments/crypto/libraries\""));
}

TEST_CASE("crypto routes: every HTML sink escapes hostile text", "[crypto][routes][ui][security]") {
    // Each sink gets its OWN marker so a test failure names the unescaped field.
    auto evil = [](const std::string& tag) { return "<script>" + tag + "</script>\"'&"; };
    auto assert_escaped = [&](const std::string& body, const std::string& tag) {
        INFO("sink " << tag);
        CHECK_THAT(body, !ContainsSubstring("<script>" + tag));
        CHECK_THAT(body, ContainsSubstring("&lt;script&gt;" + tag + "&lt;/script&gt;"));
    };
    Harness h;
    CryptoSummary s;
    CryptoFamilyRow f;
    f.id = "openssl";
    f.display = evil("display");
    f.device_count = 2;
    f.versions.push_back({evil("version"), evil("ecosystem"), 2, {evil("pkgname")}});
    s.families.push_back(f);
    h.api->summary_result = s;
    const auto lib = h.sink.dispatch("GET", "/fragments/crypto/libraries")->body;
    for (const char* tag : {"display", "version", "ecosystem"})
        assert_escaped(lib, tag);
    CHECK_THAT(lib, !ContainsSubstring("\"'&\"")); // raw quote never closes an attribute

    CryptoDevicesPage p;
    p.family = evil("family"); // an unknown family id falls back to the raw id in the header
    p.version = evil("pversion");
    p.devices.push_back({evil("agent"), evil("host"), evil("package"), evil("dversion"),
                         evil("release"), evil("deco"), evil("kind")});
    h.api->devices_result = p;
    const auto drill =
        h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl&ecosystem=%3Cscript%3Eqeco%3C%2Fscript%3E")
            ->body;
    for (const char* tag : {"family", "pversion", "agent", "host", "package", "dversion", "release",
                            "deco", "kind"})
        assert_escaped(drill, tag);
    CHECK_THAT(drill, !ContainsSubstring("<script>qeco"));
    CHECK_THAT(drill, ContainsSubstring("&lt;script&gt;qeco"));
    const auto cont =
        h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x")->body;
    for (const char* tag : {"agent", "host", "package", "dversion", "release", "deco", "kind"})
        assert_escaped(cont, tag);

    // Error / caveat text: a seam refusal message is rendered as a caveat (block and row).
    h.api->devices_result =
        std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, evil("errmsg")});
    assert_escaped(h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl")->body,
                   "errmsg");
    assert_escaped(
        h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl&cursor=k1:x")->body,
        "errmsg");
    h.api->summary_result =
        std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, evil("sumerr")});
    assert_escaped(h.sink.dispatch("GET", "/fragments/crypto/libraries")->body, "sumerr");
    // The caveat renderers directly.
    assert_escaped(crypto_html::render_caveat(evil("cav")), "cav");
    assert_escaped(crypto_html::render_caveat_row(evil("cavrow")), "cavrow");
    assert_escaped(crypto_html::render_unavailable(evil("what")), "what");
    assert_escaped(crypto_html::render_unavailable_row(evil("rwhat"), evil("rurl")), "rwhat");
    assert_escaped(crypto_html::render_unavailable_row("x", evil("rurl")), "rurl");
    // The first-page drill banner: its `what` is escaped, and a hostile family id reaches the
    // Retry hx-get and the hx-target id only url-encoded (never a raw <, quote or &).
    CryptoDevicesQuery dq;
    dq.family = evil("dfam");
    const auto ud = crypto_html::render_unavailable_drill(evil("dwhat"), dq);
    assert_escaped(ud, "dwhat");
    CHECK_THAT(ud, !ContainsSubstring("<script>dfam"));
    CHECK_THAT(ud, !ContainsSubstring("dfam</script>"));
    CHECK_THAT(ud, ContainsSubstring("family=%3Cscript%3Edfam%3C%2Fscript%3E%22%27%26"));
    CHECK_THAT(ud, ContainsSubstring("hx-target=\"#cry-exp-%3Cscript%3Edfam%3C%2Fscript%3E%22%27%26\""));
    CHECK(crypto_html::drill_box_id(evil("bid")) == "cry-exp-%3Cscript%3Ebid%3C%2Fscript%3E%22%27%26");
}

TEST_CASE("crypto routes: a hostile family id in the summary is url-encoded in the drill URL and "
          "the drill box id",
          "[crypto][routes][ui][security]") {
    Harness h;
    CryptoSummary s;
    CryptoFamilyRow f;
    f.id = "<script>sfam</script>\"'& x";
    f.display = "Shown";
    f.device_count = 1;
    f.versions.push_back({"1.0", "deb", 1, {"pkg"}});
    s.families.push_back(f);
    h.api->summary_result = s;
    const auto lib = h.sink.dispatch("GET", "/fragments/crypto/libraries")->body;
    const std::string enc = "%3Cscript%3Esfam%3C%2Fscript%3E%22%27%26%20x";
    CHECK_THAT(lib, !ContainsSubstring("<script>sfam"));
    CHECK_THAT(lib, !ContainsSubstring("sfam</script>"));
    // The row and the chip drill URL, and the box id the row, the chip and the box itself use.
    CHECK_THAT(lib, ContainsSubstring("hx-get=\"/fragments/crypto/libraries/devices?family=" + enc + "\""));
    CHECK_THAT(lib, ContainsSubstring("hx-target=\"#cry-exp-" + enc + "\""));
    CHECK_THAT(lib, ContainsSubstring("id=\"cry-exp-" + enc + "\""));
}

TEST_CASE("crypto routes: the summary's unavailable answer carries the component CSS once",
          "[crypto][routes][ui]") {
    auto count = [](const std::string& hay, const std::string& needle) {
        std::size_t n = 0;
        for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
            ++n;
        return n;
    };
    const std::string css = ".cry-degrade .cry-btn{"; // one rule of the block, unique in it
    SECTION("a store degrade, with and without the audit notice") {
        for (const bool audit_ok : {true, false}) {
            INFO("audit_ok " << audit_ok);
            Harness h;
            h.audit_ok = audit_ok;
            h.api->summary_result =
                std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
            const auto body = h.sink.dispatch("GET", "/fragments/crypto/libraries")->body;
            CHECK(body.rfind("<style>", 0) == 0);
            CHECK(count(body, css) == 1);
            CHECK(count(body, "<style>") == 1);
            CHECK(body.find("<style>") < body.find("class=\"cry-degrade\""));
            CHECK((body.find(std::string(crypto_html::kAuditNotPersistedNotice)) !=
                   std::string::npos) == !audit_ok);
        }
    }
    SECTION("no seam, a degraded gate and an unwired gate") {
        Harness no_api(true, false);
        CHECK(count(no_api.sink.dispatch("GET", "/fragments/crypto/libraries")->body, css) == 1);
        Harness gate;
        gate.admitted = false;
        gate.deny_status = 503;
        CHECK(count(gate.sink.dispatch("GET", "/fragments/crypto/libraries")->body, css) == 1);
        Harness unwired(false, true);
        auto res = unwired.sink.dispatch("GET", "/fragments/crypto/libraries");
        CHECK(res->status == 503);
        CHECK(count(res->body, css) == 1);
    }
    SECTION("the summary's notes: a refusal, a bad parameter and a kInvalid read") {
        Harness refused;
        refused.admitted = false; // deny_status 403: a genuine refusal
        Harness bad_param;
        Harness invalid;
        invalid.api->summary_result =
            std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "bad filter"});
        const std::pair<Harness*, const char*> cases[] = {
            {&refused, "/fragments/crypto/libraries"},
            {&bad_param, "/fragments/crypto/libraries?family=nope"},
            {&invalid, "/fragments/crypto/libraries"},
        };
        for (const auto& [hp, path] : cases) {
            INFO(path);
            auto res = hp->sink.dispatch("GET", path);
            REQUIRE(res);
            CHECK(res->status == 200);
            CHECK(res->body.rfind("<style>", 0) == 0);
            CHECK(count(res->body, css) == 1);
            CHECK(count(res->body, "<style>") == 1);
            CHECK(res->body.find("<style>") < res->body.find("class=\"cry-caveat\""));
        }
        // The drill's notes add no style block: the page already carries it.
        Harness drill_refused;
        drill_refused.admitted = false;
        CHECK(count(drill_refused.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=nss")
                        ->body,
                    "<style>") == 0);
        Harness drill_bad;
        CHECK(count(drill_bad.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=nope")
                        ->body,
                    "<style>") == 0);
    }
    SECTION("the success path keeps its single style block; drills add none") {
        Harness h;
        h.audit_ok = false;
        h.api->summary_result = sample_summary();
        h.api->devices_result = sample_page();
        CHECK(count(h.sink.dispatch("GET", "/fragments/crypto/libraries")->body, "<style>") == 1);
        h.api->devices_result =
            std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
        CHECK(count(h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=openssl")
                        ->body,
                    "<style>") == 0);
    }
}

TEST_CASE("crypto routes: a degraded access gate names the access check; not the inventory store",
          "[crypto][routes][ui]") {
    Harness h;
    h.admitted = false;
    h.deny_status = 503;
    for (const char* path : {"/fragments/crypto/libraries",
                             "/fragments/crypto/libraries/devices?family=nss",
                             "/fragments/crypto/libraries/devices?family=nss&cursor=k1:x"}) {
        INFO(path);
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
        CHECK_THAT(res->body, ContainsSubstring("access check could not be completed"));
        CHECK_THAT(res->body, ContainsSubstring("one of its stores (permissions, management "
                                                "groups or tags) could not be read"));
        CHECK_THAT(res->body, !ContainsSubstring("inventory store"));
        CHECK_THAT(res->body, ContainsSubstring("Retry"));
    }
    // The continuation answer is ONE table row (it replaces the Load-more <tr>), and its Retry
    // re-requests the same cursor page, not the first page or the summary.
    {
        const auto cont =
            h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=nss&cursor=k1:x");
        REQUIRE(cont);
        CHECK(cont->body.rfind("<tr", 0) == 0);
        CHECK_THAT(cont->body, ContainsSubstring("hx-get=\"/fragments/crypto/libraries/devices?"));
        CHECK_THAT(cont->body, ContainsSubstring("cursor=k1%3Ax"));
        CHECK_THAT(cont->body, ContainsSubstring("hx-target=\"closest tr\""));
    }
    // An unparseable devices request on a gate 503 has nothing to retry: the caveat row on a
    // continuation, the caveat block on a first page.
    {
        const auto cont =
            h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=nope&cursor=k1:x");
        REQUIRE(cont);
        CHECK(cont->status == 200);
        CHECK(cont->body.rfind("<tr", 0) == 0);
        CHECK_THAT(cont->body, ContainsSubstring("cry-caveat"));
        CHECK_THAT(cont->body, ContainsSubstring("Crypto library devices unavailable."));
        CHECK_THAT(cont->body, !ContainsSubstring("Retry"));
        const auto first = h.sink.dispatch("GET", "/fragments/crypto/libraries/devices?family=nope");
        REQUIRE(first);
        CHECK(first->status == 200);
        CHECK(first->body.rfind("<div class=\"cry-caveat\"", 0) == 0);
        CHECK_THAT(first->body, ContainsSubstring("Crypto library devices unavailable."));
        CHECK_THAT(first->body, !ContainsSubstring("Retry"));
    }
    // A real store degrade still names the inventory store.
    Harness store;
    store.api->summary_result =
        std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x"});
    const auto body = store.sink.dispatch("GET", "/fragments/crypto/libraries")->body;
    CHECK_THAT(body, ContainsSubstring("inventory store could not be read"));
    CHECK_THAT(body, !ContainsSubstring("access check"));
    // REST keeps the gate's own 503; no crypto audit row is written for the gate's degrade.
    CHECK(h.sink.dispatch("GET", "/api/v1/crypto/libraries")->status == 503);
    CHECK(h.audits.empty());
}

// ── Dashboard widgets: catalogue, layout, Yuzu-issued (ADR-0070 D13) ──────────────────────────

namespace {

const std::unordered_map<std::string, std::string> kSameSite{{"Host", "yuzu.test"},
                                                             {"Origin", "https://yuzu.test"}};

CaCertStats sample_stats() {
    CaCertStats s;
    s.active = 5;
    for (const int d : crypto_widgets::kExpiringWindowDays)
        s.expiring.push_back({d, 1});
    for (const int d : crypto_widgets::kExpiredWindowDays)
        s.expired.push_back({d, 0});
    for (const int d : crypto_widgets::kRevokedWindowDays)
        s.revoked.push_back({d, 2});
    s.issued = {7, 3};
    s.weeks.push_back({1792368000, "2026-W43", 3, 1});
    return s;
}

CaCertPage sample_certs() {
    CaCertPage p;
    p.total = 1;
    p.rows.push_back({"0A1B", "CN=agent-1", "agent", 100, 200, "active", 0});
    return p;
}

std::int64_t wall_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

TEST_CASE("crypto routes: widgets - the catalogue with the caller's availability, no audit",
          "[crypto][routes][widgets]") {
    Harness h;
    h.held = {"Inventory:Read"};
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/widgets");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    const auto j = body_of(*res);
    CHECK(j["data"]["window_set"] == "crypto_widget_windows_v1");
    CHECK(j["data"]["widgets"].size() == crypto_widgets::catalogue().size());
    for (const auto& w : j["data"]["widgets"])
        CHECK(w["available"] == (w["securable"] == "Inventory"));
    CHECK(h.probe_calls == 2);     // one per distinct permission pair
    CHECK(h.perm_calls.empty());   // the drawing probe, never the auditing gate
    CHECK(h.audits.empty());
    CHECK(h.gate_calls == 0);
}

TEST_CASE("crypto routes: an unwired perm_fn / has_perm_fn fails closed (503)",
          "[crypto][routes][widgets][security]") {
    Harness h(true, true, /*wire_perm=*/false);
    for (const char* path : {"/api/v1/crypto/widgets", "/api/v1/crypto/ca/stats",
                             "/api/v1/crypto/ca/certificates?kind=active"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    CHECK(h.api->stats_as_of.empty());
    CHECK(h.api->cert_calls.empty());
}

TEST_CASE("crypto routes: layout GET serves the caller's own layout or the default",
          "[crypto][routes][widgets]") {
    Harness h;
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = body_of(*res);
    CHECK(j["data"]["is_default"] == true);
    CHECK(j["data"]["widgets"].size() == crypto_widgets::default_layout().size());
    h.api->layouts["tester"] = {"ca.active"};
    h.api->layouts["someone_else"] = {"ca.revoked_7d"};
    res = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
    j = body_of(*res);
    CHECK(j["data"]["is_default"] == false);
    CHECK(j["data"]["widgets"] == nlohmann::json::array({"ca.active"}));
}

TEST_CASE("crypto routes: layout PUT - saves the caller's own layout, audited attempted+success",
          "[crypto][routes][widgets]") {
    Harness h;
    h.username = "alice";
    auto res = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout",
                               R"({"widgets":["ca.active","lib.families_table"]})",
                               "application/json", kSameSite);
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto j = body_of(*res);
    CHECK(j["data"]["widgets"] == nlohmann::json::array({"ca.active", "lib.families_table"}));
    CHECK(j["data"]["is_default"] == false);
    CHECK_FALSE(j["data"].contains("audit_persisted"));
    CHECK(h.api->layouts["alice"] == std::vector<std::string>{"ca.active", "lib.families_table"});
    CHECK_FALSE(h.api->layouts.contains("tester"));
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "crypto.dashboard.layout.update");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_type == "CryptoDashboard");
    CHECK(h.audits[1].target_id == "alice");
    CHECK_THAT(h.audits[1].detail, ContainsSubstring("widgets=2"));

    // Per-user isolation: bob's read never sees alice's layout, and his save leaves hers alone.
    h.username = "bob";
    res = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
    CHECK(body_of(*res)["data"]["is_default"] == true);
    res = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout", R"({"widgets":[]})",
                          "application/json", kSameSite);
    CHECK(res->status == 200);
    CHECK(h.api->layouts["bob"].empty());
    CHECK(h.api->layouts["alice"].size() == 2);
}

TEST_CASE("crypto routes: layout PUT refuses a cross-site or header-less browser write",
          "[crypto][routes][widgets][security]") {
    Harness h;
    auto res = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout",
                               R"({"widgets":["ca.active"]})", "application/json",
                               {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}});
    REQUIRE(res);
    CHECK(res->status == 403);
    res = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout", R"({"widgets":["ca.active"]})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.api->layout_writes == 0);
    for (const auto& a : h.audits)
        CHECK(a.action == "csrf.denied");
}

TEST_CASE("crypto routes: layout PUT refuses bad bodies and ids with 400 before any audit",
          "[crypto][routes][widgets]") {
    Harness h;
    std::string many = R"({"widgets":[)";
    for (std::size_t i = 0; i <= crypto_widgets::kMaxLayoutWidgets; ++i)
        many += std::string(i ? "," : "") + "\"ca.active\"";
    many += "]}";
    for (const std::string& body :
         {std::string("not json"), std::string("[]"), std::string(R"({"widgets":"ca.active"})"),
          std::string(R"({"widgets":["ca.active","ca.active"]})"),
          std::string(R"({"widgets":["no.such.widget"]})"), std::string(R"({"widgets":[1]})"),
          std::string(R"({"widgets":[],"username":"bob"})"), many}) {
        auto res = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout", body,
                                   "application/json", kSameSite);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    auto big = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout",
                               std::string(crypto_widgets::kLayoutBodyMaxBytes + 1, ' '),
                               "application/json", kSameSite);
    REQUIRE(big);
    CHECK(big->status == 413);
    CHECK(h.api->layout_writes == 0);
    CHECK(h.audits.empty());
}

TEST_CASE("crypto routes: layout degrade - 503 + retry, never the default; no audit row, no write",
          "[crypto][routes][widgets]") {
    Harness h;
    h.api->layout_error = CryptoReadError{CryptoReadError::Kind::kDegraded,
                                          "dashboard layout read degraded",
                                          CryptoReadCause::kStoreDegraded};
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
    res = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout", R"({"widgets":["ca.active"]})",
                          "application/json", kSameSite);
    REQUIRE(res);
    CHECK(res->status == 503);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "failure");

    // An audit log that cannot take the attempted row refuses the change outright.
    Harness g;
    g.audit_ok = false;
    res = g.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout", R"({"widgets":["ca.active"]})",
                          "application/json", kSameSite);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(g.api->layout_writes == 0);
}

TEST_CASE("crypto routes: CA stats - Security:Read gate, as_of from the server clock, audited",
          "[crypto][routes][widgets]") {
    Harness h;
    h.api->stats_result = sample_stats();
    const auto before = wall_now();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/ca/stats");
    const auto after = wall_now();
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Vary") == "Authorization, Cookie, X-Yuzu-Token");
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Security", "Read"});
    REQUIRE(h.api->stats_as_of.size() == 1);
    CHECK(h.api->stats_as_of[0] >= before);
    CHECK(h.api->stats_as_of[0] <= after);
    const auto j = body_of(*res)["data"];
    CHECK(j["as_of"] == h.api->stats_as_of[0]);
    CHECK(j["scope"] == "yuzu_issued");
    CHECK(j["expiring"][4]["days"] == 30);
    CHECK(j["expiring"][4]["criterion"] == "Expiring within 30 days");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.ca.stats.view");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "Security");
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("ws=crypto_widget_windows_v1"));
    CHECK(h.gate_calls == 0); // never the fleet-read gate
}

TEST_CASE("crypto routes: CA routes keep the gate's 403 and never read on refusal",
          "[crypto][routes][widgets][security]") {
    Harness h;
    h.security_read = false;
    for (const char* path :
         {"/api/v1/crypto/ca/stats", "/api/v1/crypto/ca/certificates?kind=expiring&days=30"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, ContainsSubstring("permission denied"));
    }
    CHECK(h.api->stats_as_of.empty());
    CHECK(h.api->cert_calls.empty());
    CHECK(h.audits.empty());
}

TEST_CASE("crypto routes: CA degrade - 503 + retry_after_ms and a failure row, never zeros",
          "[crypto][routes][widgets]") {
    Harness h;
    const CryptoReadError degraded{CryptoReadError::Kind::kDegraded, "Yuzu CA read degraded",
                                   CryptoReadCause::kStoreDegraded};
    h.api->stats_result = std::unexpected(degraded);
    h.api->certs_result = std::unexpected(degraded);
    for (const char* path : {"/api/v1/crypto/ca/stats", "/api/v1/crypto/ca/certificates?kind=active"}) {
        auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 503);
        const auto j = body_of(*res);
        CHECK_FALSE(j.contains("data"));
        CHECK(j["error"]["retry_after_ms"] == 5000);
    }
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "crypto.ca.stats.view");
    CHECK(h.audits[0].result == "failure");
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("store degraded"));
    CHECK(h.audits[1].action == "crypto.ca.certificates.view");
    CHECK(h.audits[1].result == "failure");
}

TEST_CASE("crypto routes: CA certificates - strict parse, query reaches the seam, audited",
          "[crypto][routes][widgets]") {
    Harness h;
    h.api->certs_result = sample_certs();
    auto res = h.sink.dispatch("GET",
                               "/api/v1/crypto/ca/certificates?kind=expiring&days=30&limit=9999");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.api->cert_calls.size() == 1);
    CHECK(h.api->cert_calls[0].first.kind == CaCertKind::kExpiring);
    CHECK(h.api->cert_calls[0].first.days == 30);
    CHECK(h.api->cert_calls[0].first.limit == crypto_widgets::kCertPageMax); // REST clamps
    const auto j = body_of(*res)["data"];
    CHECK(j["criterion"] == "Expiring within 30 days");
    CHECK(j["certificates"][0]["serial_hex"] == "0A1B");
    CHECK(j["certificates"][0]["revoked_at"].is_null());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.ca.certificates.view");
    CHECK(h.audits[0].target_id == "kind=expiring days=30");
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("rows=1"));

    res = h.sink.dispatch("GET", "/api/v1/crypto/ca/certificates?kind=issued_week&week=2026-W43");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.api->cert_calls.back().first.week_start == 1792368000);

    for (const char* bad :
         {"/api/v1/crypto/ca/certificates", "/api/v1/crypto/ca/certificates?kind=weak",
          "/api/v1/crypto/ca/certificates?kind=expiring&days=45",
          "/api/v1/crypto/ca/certificates?kind=active&days=7",
          "/api/v1/crypto/ca/certificates?kind=revoked_week&week=2026-W99",
          "/api/v1/crypto/ca/certificates?kind=active&offset=-3"}) {
        auto r = h.sink.dispatch("GET", bad);
        REQUIRE(r);
        CHECK(r->status == 400);
    }
    CHECK(h.api->cert_calls.size() == 2);
}

TEST_CASE("crypto routes: a lost CA audit row is visible (header + audit_persisted false)",
          "[crypto][routes][widgets]") {
    Harness h;
    h.audit_ok = false;
    h.api->stats_result = sample_stats();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/ca/stats");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(body_of(*res)["data"]["audit_persisted"] == false);
}

// ── The widget dashboard fragments (ADR-0070 D13, phase 2) ───────────────────

namespace {

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

} // namespace

TEST_CASE("crypto dashboard: draws the caller's layout in order with lazy-loaded cards",
          "[crypto][routes][dashboard]") {
    Harness h;
    h.api->layouts["tester"] = {"ca.expiring_30d", "lib.devices_reporting", "ca.issued_per_week"};
    auto res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK(res->get_header_value("Vary") == "Authorization, Cookie, X-Yuzu-Token");
    const auto& b = res->body;
    const auto a = b.find("data-wid=\"ca.expiring_30d\"");
    const auto l = b.find("data-wid=\"lib.devices_reporting\"");
    const auto w = b.find("data-wid=\"ca.issued_per_week\"");
    REQUIRE(a != std::string::npos);
    REQUIRE(l != std::string::npos);
    REQUIRE(w != std::string::npos);
    CHECK(a < l);
    CHECK(l < w);
    // Each card lazy-loads its own data, serialised across the grid.
    CHECK_THAT(b, ContainsSubstring("hx-get=\"/fragments/crypto/widget/ca.expiring_30d\" "
                                    "hx-trigger=\"load\""));
    CHECK(count_of(b, "hx-sync=\"#cry-grid:queue all\"") == 3);
    // D13 condition 1: every card shows its criterion; the Yuzu-issued cards are labelled.
    CHECK_THAT(b, ContainsSubstring("Active, expiring after as_of and within 30 days"));
    CHECK(count_of(b, "<span class=\"cry-tag\">Yuzu-issued certificates</span>") == 2);
    // Add lists only entries not on the grid; the move buttons are disabled at the ends.
    CHECK_THAT(b, ContainsSubstring("<option value=\"ca.active\""));
    CHECK_THAT(b, !ContainsSubstring("<option value=\"ca.expiring_30d\""));
    CHECK_THAT(b, ContainsSubstring("<optgroup label=\"Yuzu-issued certificates\">"));
    CHECK(count_of(b, "onclick=\"cryDash.remove(this)\"") == 3);
    CHECK(count_of(b, " disabled>&larr;") == 1);
    CHECK(count_of(b, " disabled>&rarr;") == 1);
    CHECK_THAT(b, ContainsSubstring("id=\"cry-drill\""));
    CHECK_THAT(b, ContainsSubstring("onclick=\"cryDash.reset(this)\""));
    CHECK_THAT(b, !ContainsSubstring("hx-on"));
    // The library honesty caveat stays on the page.
    CHECK_THAT(b, ContainsSubstring("Package-level evidence only"));
    // Drawing reads no widget data and writes no audit row.
    CHECK(h.api->summary_calls == 0);
    CHECK(h.api->stats_as_of.empty());
    CHECK(h.audits.empty());
}

TEST_CASE("crypto dashboard: the default layout is drawn and said to be the default",
          "[crypto][routes][dashboard]") {
    Harness h;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("Showing the default layout."));
    for (const auto id : crypto_widgets::default_layout())
        CHECK_THAT(res->body, ContainsSubstring("data-wid=\"" + std::string(id) + "\""));
    std::string defaults;
    for (const auto id : crypto_widgets::default_layout())
        defaults += (defaults.empty() ? "" : " ") + std::string(id);
    CHECK_THAT(res->body, ContainsSubstring("data-default=\"" + defaults + "\""));
}

TEST_CASE("crypto dashboard: a card the caller lacks permission for is a note, not a load",
          "[crypto][routes][dashboard][security]") {
    Harness h;
    h.held = {"Inventory:Read"};
    h.api->layouts["tester"] = {"lib.devices_reporting", "ca.active"};
    auto res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("not available to this account (Security:Read "
                                            "required)"));
    CHECK_THAT(res->body, !ContainsSubstring("hx-get=\"/fragments/crypto/widget/ca.active\""));
    CHECK_THAT(res->body, ContainsSubstring("hx-get=\"/fragments/crypto/widget/lib.devices_reporting\""));
    // Not-readable catalogue entries are listed, disabled.
    CHECK_THAT(res->body, ContainsSubstring("<option value=\"ca.expiring_3d\" disabled>"));
}

TEST_CASE("crypto dashboard: a degraded layout read is a banner with Retry, never the default",
          "[crypto][routes][dashboard]") {
    Harness h;
    h.api->layout_error = CryptoReadError{CryptoReadError::Kind::kDegraded, "degraded",
                                          CryptoReadCause::kStoreDegraded};
    auto res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
    CHECK_THAT(res->body, ContainsSubstring("hx-get=\"/fragments/crypto/dashboard\""));
    CHECK_THAT(res->body, !ContainsSubstring("data-wid="));

    Harness none(true, /*wire_api=*/false);
    res = none.sink.dispatch("GET", "/fragments/crypto/dashboard");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("Crypto dashboard unavailable"));
}

TEST_CASE("crypto dashboard: a library number widget reads the summary, is audited, drills",
          "[crypto][routes][dashboard]") {
    Harness h;
    h.api->summary_result = sample_summary();
    auto res = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.devices_reporting");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK_THAT(res->body, ContainsSubstring(">12</button>"));
    CHECK_THAT(res->body, ContainsSubstring("data-url=\"/fragments/crypto/widget/lib.families_table\""));
    CHECK_THAT(res->body, ContainsSubstring("onclick=\"cryDash.drill(this)\""));
    CHECK(h.gate_calls == 1);
    CHECK(h.perm_calls.empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.libraries.view");
    CHECK(h.audits[0].result == "success");
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("family=all"));
}

TEST_CASE("crypto dashboard: the families table and the bar drill into the drill panel",
          "[crypto][routes][dashboard]") {
    Harness h;
    h.api->summary_result = sample_summary();
    auto table = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.families_table");
    REQUIRE(table);
    CHECK_THAT(table->body, ContainsSubstring(
                                "data-url=\"/fragments/crypto/libraries/devices?family=openssl\" "
                                "data-box=\"cry-exp-openssl\" onclick=\"cryDash.drill(this)\""));
    CHECK_THAT(table->body, ContainsSubstring("Package names as of")); // honesty notice kept
    auto bar = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.devices_by_family");
    REQUIRE(bar);
    CHECK_THAT(bar->body, ContainsSubstring("<script>cryDash.chart(\"cry-chart-lib.devices_by_family\","));
    CHECK_THAT(bar->body, ContainsSubstring("\"chart_type\":\"bar\""));
    CHECK_THAT(bar->body, ContainsSubstring(
                              "\"drill\":[\"/fragments/crypto/libraries/devices?family=openssl\"]"));
    CHECK_THAT(bar->body, ContainsSubstring("\"drill_box\":[\"cry-exp-openssl\"]"));

    // No library rows: the "not proof" note, never an empty chart.
    h.api->summary_result = CryptoSummary{};
    bar = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.devices_by_family");
    REQUIRE(bar);
    CHECK_THAT(bar->body, ContainsSubstring("This is not proof that no library is present"));
    CHECK_THAT(bar->body, !ContainsSubstring("cryDash.chart"));
}

TEST_CASE("crypto dashboard: a Yuzu-issued number widget shows its count, as_of and its drill",
          "[crypto][routes][dashboard]") {
    Harness h;
    h.api->stats_result = sample_stats();
    auto res = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.revoked_30d");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring(">2</button>"));
    CHECK_THAT(res->body,
               ContainsSubstring("data-url=\"/fragments/crypto/ca/certificates?kind=revoked&amp;days=30\""));
    CHECK_THAT(res->body, ContainsSubstring("as of "));
    CHECK_THAT(res->body, ContainsSubstring("window set crypto_widget_windows_v1"));
    CHECK(h.gate_calls == 0);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Security", "Read"});
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.ca.stats.view");
    CHECK(h.audits[0].target_id == "yuzu_ca");

    auto act = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.active");
    REQUIRE(act);
    CHECK_THAT(act->body, ContainsSubstring(">5</button>"));
    CHECK_THAT(act->body, ContainsSubstring("data-url=\"/fragments/crypto/ca/certificates?kind=active\""));
}

TEST_CASE("crypto dashboard: the per-week line chart carries one drill URL per week",
          "[crypto][routes][dashboard]") {
    Harness h;
    h.api->stats_result = sample_stats();
    auto res = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.revoked_per_week");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("\"chart_type\":\"line\""));
    CHECK_THAT(res->body, ContainsSubstring("\"labels\":[\"2026-W43\"]"));
    CHECK_THAT(res->body, ContainsSubstring("\"series\":[{\"data\":[1],\"name\":\"Revoked\"}]"));
    // `&` is \u0026-escaped inside the script.
    CHECK_THAT(res->body, ContainsSubstring(
                              "/fragments/crypto/ca/certificates?kind=revoked_week\\u0026week=2026-W43"));
}

TEST_CASE("crypto dashboard: a refused widget is a 'not available' note; a degraded gate a banner",
          "[crypto][routes][dashboard][security]") {
    Harness h;
    h.security_read = false;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.active");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("not available to this account (Security:Read required)"));
    CHECK(h.api->stats_as_of.empty());

    h.security_deny_status = 503;
    res = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.active");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
    CHECK_THAT(res->body, ContainsSubstring("access check could not be completed"));
    CHECK_THAT(res->body, ContainsSubstring("hx-get=\"/fragments/crypto/widget/ca.active\" "
                                            "hx-target=\"closest .cry-slot\""));

    h.admitted = false;
    res = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.families_matched");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("not available to this account (Inventory:Read required)"));
    h.deny_status = 503;
    res = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.families_matched");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("cry-degrade"));
    CHECK(h.api->summary_calls == 0);
    CHECK(h.audits.empty());

    auto unknown = h.sink.dispatch("GET", "/fragments/crypto/widget/fleet.weak_keys");
    REQUIRE(unknown);
    CHECK(unknown->status == 200);
    CHECK_THAT(unknown->body, ContainsSubstring("Unknown widget."));
}

TEST_CASE("crypto dashboard: a degraded widget read is a banner and a failure row, never zero",
          "[crypto][routes][dashboard]") {
    Harness h;
    h.api->stats_result = std::unexpected(CryptoReadError{
        CryptoReadError::Kind::kDegraded, "x", CryptoReadCause::kCapacity});
    h.api->summary_result = std::unexpected(CryptoReadError{
        CryptoReadError::Kind::kDegraded, "x", CryptoReadCause::kStoreDegraded});
    auto ca = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.expiring_7d");
    REQUIRE(ca);
    CHECK(ca->status == 200);
    CHECK_THAT(ca->body, ContainsSubstring("Temporarily busy"));
    CHECK_THAT(ca->body, ContainsSubstring("not</b> a count of zero"));
    CHECK_THAT(ca->body, !ContainsSubstring("cry-numbtn"));
    auto lib = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.devices_with_library");
    REQUIRE(lib);
    CHECK_THAT(lib->body, ContainsSubstring("inventory store could not be read"));
    CHECK_THAT(lib->body, !ContainsSubstring("cry-numbtn"));
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "crypto.ca.stats.view");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[1].action == "crypto.libraries.view");
    CHECK(h.audits[1].result == "failure");

    // A lost row is visible on the card.
    h.audit_ok = false;
    h.api->stats_result = sample_stats();
    ca = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.active");
    REQUIRE(ca);
    CHECK_THAT(ca->body, ContainsSubstring("Audit not recorded."));
    CHECK(ca->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("crypto dashboard: the Yuzu-issued drill lists certificates with Load more paging",
          "[crypto][routes][dashboard]") {
    Harness h;
    CaCertPage p;
    p.total = 250;
    p.truncated = true;
    p.rows.push_back({"0A1B", "CN=agent-1", "agent", 1760000000, 1790000000, "revoked", 1770000000});
    h.api->certs_result = p;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=expiring&days=30");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    const auto& b = res->body;
    for (const char* col : {"Serial", "Subject", "Purpose", "Issued", "Not after", "Status",
                            "Revoked at"})
        CHECK_THAT(b, ContainsSubstring(std::string("<th>") + col + "</th>"));
    CHECK_THAT(b, ContainsSubstring("Expiring within 30 days"));
    CHECK_THAT(b, ContainsSubstring("250 in total"));
    CHECK_THAT(b, ContainsSubstring("2025-10-09 08:53 UTC"));
    CHECK_THAT(b, ContainsSubstring(
                      "hx-get=\"/fragments/crypto/ca/certificates?kind=expiring&amp;days=30&amp;offset=1\""));
    CHECK_THAT(b, ContainsSubstring("hx-target=\"closest tr\""));
    REQUIRE(h.api->cert_calls.size() == 1);
    CHECK(h.api->cert_calls[0].first.offset == 0);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.ca.certificates.view");
    CHECK(h.audits[0].target_id == "kind=expiring days=30");

    // A continuation page is rows only; the last page offers no Load more.
    h.api->certs_result->truncated = false;
    res = h.sink.dispatch("GET",
                          "/fragments/crypto/ca/certificates?kind=expiring&days=30&offset=100");
    REQUIRE(res);
    CHECK(res->body.starts_with("<tr>"));
    CHECK_THAT(res->body, !ContainsSubstring("Load more"));
    CHECK(h.api->cert_calls.back().first.offset == 100);

    // A per-week drill names its week.
    res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=issued_week&week=2026-W43");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("2026-W43"));
}

TEST_CASE("crypto dashboard: the Yuzu-issued drill's refusal, bad request and degrade are 200s",
          "[crypto][routes][dashboard][security]") {
    Harness h;
    h.security_read = false;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=active");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("Security:Read required"));
    res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=active&offset=100");
    REQUIRE(res);
    CHECK(res->body.starts_with("<tr class=\"cry-more\"><td colspan=\"7\">"));
    CHECK(h.api->cert_calls.empty());

    h.security_read = true;
    res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=expiring&days=45");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("cry-caveat"));
    CHECK(h.api->cert_calls.empty());

    h.api->certs_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded, "x",
                                                          CryptoReadCause::kStoreDegraded});
    res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=revoked&days=7&offset=100");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.starts_with("<tr class=\"cry-more\"><td colspan=\"7\">"));
    CHECK_THAT(res->body, ContainsSubstring(
                              "hx-get=\"/fragments/crypto/ca/certificates?kind=revoked&amp;days=7&amp;offset=100\" "
                              "hx-target=\"closest tr\""));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "failure");
}

TEST_CASE("crypto dashboard: hostile text cannot break out of the HTML or the inline chart script",
          "[crypto][routes][dashboard][security]") {
    Harness h;
    CaCertPage p;
    p.total = 1;
    p.rows.push_back({"<b>", "CN=</script><script>alert(1)</script>", "x\"onmouseover=\"y",
                      100, 200, "active", 0});
    h.api->certs_result = p;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=active");
    REQUIRE(res);
    CHECK_THAT(res->body, !ContainsSubstring("</script>"));
    CHECK_THAT(res->body, !ContainsSubstring("<script>alert"));
    CHECK_THAT(res->body, ContainsSubstring("CN=&lt;/script&gt;"));

    // A family display name reaches the inline chart JSON: it must never close the script.
    CryptoSummary s = sample_summary();
    s.families[0].display = "</script><script>alert(1)</script>\xE2\x80\xA8<!--";
    h.api->summary_result = s;
    res = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.devices_by_family");
    REQUIRE(res);
    CHECK(count_of(res->body, "</script>") == 1); // the chart script's own close tag only
    CHECK_THAT(res->body, !ContainsSubstring("<!--"));
    CHECK_THAT(res->body, ContainsSubstring("\\u003c/script\\u003e"));
    CHECK_THAT(res->body, ContainsSubstring("\\u2028"));
    CHECK_THAT(res->body, !ContainsSubstring("\xE2\x80\xA8"));
}

TEST_CASE("crypto dashboard: script_json escapes every script-breaking sequence",
          "[crypto][ui][security]") {
    const auto out = crypto_html::script_json(
        nlohmann::json{{"k", "</script>&<!--\xE2\x80\xA8\xE2\x80\xA9"}});
    CHECK(out == "{\"k\":\"\\u003c/script\\u003e\\u0026\\u003c!--\\u2028\\u2029\"}");
    CHECK(nlohmann::json::parse(out)["k"] == "</script>&<!--\xE2\x80\xA8\xE2\x80\xA9");
}
