// Route-level tests for the /crypto surface (CryptoRoutes): the page shell, both HTMX
// fragments and both REST v1 routes, over a fake CryptoApi and a fake fleet-read gate. No
// Postgres: the seam is faked, so these pin the gate / scope / audit / status-code / escaping
// contract of the route owner itself. The seam over the real store is test_crypto_api.cpp.

#include "authz_gates.hpp"
#include "crypto_library_model.hpp"
#include "crypto_routes.hpp"
#include "crypto_ui.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <expected>
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
    mutable int summary_calls{0};

    std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery&, const authz::VisibleSet& scope) const override {
        ++summary_calls;
        scopes.push_back(scope);
        return summary_result;
    }
    std::expected<CryptoDevicesPage, CryptoReadError>
    library_devices(const CryptoDevicesQuery& q, const authz::VisibleSet& scope) const override {
        scopes.push_back(scope);
        devices_queries.push_back(q);
        return devices_result;
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
    authz::VisibleSet scope; // nullopt = TOP
    int gate_calls{0};

    explicit Harness(bool wire_gate = true, bool wire_api = true) {
        CryptoRoutes::Deps d;
        d.auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        if (wire_gate)
            d.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const std::string& securable,
                                     const std::string& op) -> authz::FleetReadGate {
                ++gate_calls;
                CHECK(securable == "Inventory");
                CHECK(op == "Read");
                if (!admitted) {
                    res.status = 403;
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
    CHECK_THAT(res->body, ContainsSubstring("/fragments/crypto/libraries"));
    CHECK_THAT(res->body, ContainsSubstring("<a class=\"shell-nav on\" href=\"/crypto\""));
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

TEST_CASE("crypto routes: a refused gate - REST keeps the gate's 403, fragments answer 200 + caveat",
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

TEST_CASE("crypto routes: present-empty scope still reaches the seam (zero rows, not the fleet)",
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

TEST_CASE("crypto routes: no seam (no inventory store) is a 503 / degrade banner, never empty",
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

TEST_CASE("crypto routes: a degraded read is REST 503 + retry_after_ms, fragment 200 + banner",
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

TEST_CASE("crypto routes: bad parameters are REST 400 and a fragment 200 caveat, with no read",
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

TEST_CASE("crypto routes: a lost audit row is flagged, not fatal (set-and-proceed)",
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

TEST_CASE("crypto routes: the library fragment renders the figures, the drill links and the "
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
    CHECK_THAT(res->body, ContainsSubstring("Package-level evidence only."));
    CHECK_THAT(res->body, ContainsSubstring("Certificates, SSH host keys and protocol settings"));
    CHECK_THAT(res->body, !ContainsSubstring("hx-on"));
    // Interpretation words never appear in the markup.
    for (const char* word : {"vulnerable", "weak", "outdated", "insecure", "quantum"})
        CHECK_THAT(res->body, !ContainsSubstring(word));
    // The empty result states what empty means.
    h.api->summary_result = CryptoSummary{};
    auto empty = h.sink.dispatch("GET", "/fragments/crypto/libraries");
    REQUIRE(empty);
    CHECK_THAT(empty->body, ContainsSubstring("not proof"));
    CHECK_THAT(empty->body, ContainsSubstring("Package-level evidence only."));
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
