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

TEST_CASE("crypto page: the names note says catalogue time, read live, or nothing for an absurd stamp",
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

TEST_CASE("crypto routes: a gate that DEGRADED (503) shows the unavailable banner, a refusal does not",
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
    CHECK_THAT(refused->body, !ContainsSubstring("cry-degrade"));
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

TEST_CASE("crypto routes: a Load-more page that degrades, is refused a cursor or is a bad request "
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

TEST_CASE("crypto routes: a PRESENT ecosystem, even empty, is the exact ecosystem on every route",
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

TEST_CASE("crypto routes: every bucket chip carries its ecosystem, the empty one included",
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
