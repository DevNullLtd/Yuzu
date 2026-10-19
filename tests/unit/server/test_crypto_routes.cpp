// Route-level tests for the /crypto surface (CryptoRoutes): the page shell, both HTMX
// fragments and both REST v1 routes, over a fake CryptoApi and a fake fleet-read gate. No
// Postgres: the seam is faked, so these pin the gate / scope / audit / status-code / escaping
// contract of the route owner itself. The seam over the real store is test_crypto_api.cpp.

#include "authz_gates.hpp"
#include "crypto_cbom.hpp"
#include "crypto_library_model.hpp"
#include "crypto_routes.hpp"
#include "crypto_ui.hpp"
#include "crypto_widget_catalogue.hpp"
#include "secure_random.hpp"
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
    mutable std::map<std::string, std::pair<std::vector<std::string>, std::int64_t>> layouts;
    std::optional<CryptoReadError> layout_error;
    std::size_t preserved_unknown{0};
    mutable std::vector<std::optional<std::int64_t>> stats_as_of;
    mutable std::vector<CaCertQuery> cert_calls;
    mutable int layout_reads{0};
    mutable int layout_writes{0};
    mutable std::vector<std::optional<std::int64_t>> expected_versions;
    static constexpr std::int64_t kDbAsOf = 1792368000 + 9 * 3600; // the "database clock"

    std::expected<CaCertStats, CryptoReadError>
    ca_stats(std::optional<std::int64_t> as_of) const override {
        stats_as_of.push_back(as_of);
        if (!stats_result)
            return stats_result;
        auto s = *stats_result;
        s.as_of = as_of.value_or(kDbAsOf);
        return s;
    }
    std::expected<CaCertPage, CryptoReadError> ca_certificates(const CaCertQuery& q) const override {
        cert_calls.push_back(q);
        if (!certs_result)
            return certs_result;
        auto p = *certs_result;
        p.query = q;
        p.as_of = q.as_of.value_or(kDbAsOf);
        return p;
    }
    std::expected<CryptoDashboardLayout, CryptoReadError>
    dashboard_layout(const std::string& username) const override {
        ++layout_reads;
        if (layout_error)
            return std::unexpected(*layout_error);
        if (const auto it = layouts.find(username); it != layouts.end())
            return CryptoDashboardLayout{it->second.first, false, it->second.second,
                                         preserved_unknown};
        return CryptoDashboardLayout{crypto_widgets::default_layout_ids(), true, 0, 0};
    }
    std::expected<CryptoDashboardLayout, CryptoReadError>
    set_dashboard_layout(const std::string& username, const std::vector<std::string>& widgets,
                         std::optional<std::int64_t> expected) const override {
        ++layout_writes;
        expected_versions.push_back(expected);
        if (layout_error)
            return std::unexpected(*layout_error);
        const std::int64_t have = layouts.contains(username) ? layouts[username].second : 0;
        // H1: an omitted version is a first save only (read as 0), as in the real seam.
        if (expected.value_or(0) != have) {
            CryptoReadError e{CryptoReadError::Kind::kConflict, "the layout changed"};
            e.version = have;
            return std::unexpected(e);
        }
        layouts[username] = {widgets, have + 1};
        return CryptoDashboardLayout{widgets, false, have + 1, 0};
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
    bool auth_ok{true};
    std::string token_scope_service;
    std::string mcp_tier;
    bool tier_allows{true};
    // The availability probe's answer for the two fleet gate classes when Inventory:Read is
    // held (the global class reads `held`). A confined caller: fleet_wide_access = kConfined.
    crypto_widgets::Access fleet_access{crypto_widgets::Access::kAvailable};
    crypto_widgets::Access fleet_wide_access{crypto_widgets::Access::kAvailable};

    explicit Harness(bool wire_gate = true, bool wire_api = true, bool wire_perm = true) {
        CryptoRoutes::Deps d;
        d.auth_fn = [this](const httplib::Request&, httplib::Response& res) -> std::optional<auth::Session> {
            if (!auth_ok) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = username;
            s.role = auth::Role::admin;
            s.token_scope_service = token_scope_service;
            s.mcp_tier = mcp_tier;
            return s;
        };
        d.tier_policy_fn = [this](const httplib::Request&, httplib::Response& res,
                                  const auth::Session& s, const std::string&, const std::string&) {
            if (s.mcp_tier.empty() || tier_allows)
                return true;
            res.status = 403;
            return false;
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
            d.access_fn = [this](const httplib::Request&, crypto_widgets::WidgetGate g,
                                 const std::string& securable, const std::string& op) {
                ++probe_calls;
                using A = crypto_widgets::Access;
                const bool has = held.contains(securable + ":" + op);
                switch (g) {
                case crypto_widgets::WidgetGate::kFleetRead:
                    return has ? fleet_access : A::kRefused;
                case crypto_widgets::WidgetGate::kFleetWideOnly:
                    return has ? fleet_wide_access : A::kRefused;
                case crypto_widgets::WidgetGate::kGlobal:
                    break;
                }
                return has ? A::kAvailable : A::kRefused;
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
    CHECK_THAT(res->body, ContainsSubstring("Library families found"));
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

// ── Dashboard widgets: catalogue, layout, Yuzu-issued (ADR-0070 D13, R2) ─────────────────────

namespace {

namespace cw = crypto_widgets;

const std::unordered_map<std::string, std::string> kSameSite{{"Host", "yuzu.test"},
                                                             {"Origin", "https://yuzu.test"}};

CaCertStats sample_stats() {
    CaCertStats s;
    s.active = 5;
    for (const int d : cw::kExpiringWindowDays)
        s.expiring.push_back({d, 1});
    for (const int d : cw::kExpiredWindowDays)
        s.expired.push_back({d, 0});
    for (const int d : cw::kRevokedWindowDays)
        s.revoked.push_back({d, 11, 22, 33});
    s.issued = {7, 3};
    CaWeekCount w;
    w.week_start = 1792368000;
    w.label = "2026-W43";
    w.issued = 3;
    w.revoked_other = 1;
    w.partial = true;
    s.weeks.push_back(w);
    return s;
}

CaCertPage sample_certs() {
    CaCertPage p;
    p.total = 1;
    p.rows.push_back({"0A1B", "CN=agent-1", "", "agent", 100, 200, "active", 0, "", "", ""});
    return p;
}

std::unique_ptr<httplib::Response> put_layout(Harness& h, const std::string& body) {
    return h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout", body, "application/json",
                           kSameSite);
}

std::size_t count_audits(const Harness& h, const std::string& action, const std::string& result) {
    return static_cast<std::size_t>(std::ranges::count_if(h.audits, [&](const AuditCall& a) {
        return a.action == action && a.result == result;
    }));
}

} // namespace

TEST_CASE("crypto widgets routes: every new route and fragment refuses unauthenticated (401)",
          "[crypto][routes][widgets][security]") {
    Harness h;
    h.auth_ok = false;
    for (const char* path : {"/api/v1/crypto/widgets", "/api/v1/crypto/dashboard/layout",
                             "/fragments/crypto/dashboard", "/fragments/crypto/widget/ca.active",
                             "/fragments/crypto/widget/lib.devices_reporting",
                             "/fragments/crypto/ca/certificates?kind=active"}) {
        INFO(path);
        const auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 401);
    }
    CHECK(put_layout(h, R"({"widgets":[]})")->status == 401);
    CHECK(h.audits.empty());
    CHECK(h.gate_calls == 0);
    CHECK(h.api->layout_reads == 0);
    CHECK(h.api->layout_writes == 0);
    CHECK(h.api->stats_as_of.empty());
    CHECK(h.api->cert_calls.empty());
    CHECK(h.api->summary_calls == 0);
}

TEST_CASE("crypto widgets routes: /widgets draws availability per gate class, one probe each",
          "[crypto][routes][widgets]") {
    Harness h;
    h.fleet_wide_access = cw::Access::kConfined; // a confined Inventory:Read holder
    h.held = {"Inventory:Read"};
    const auto res = h.sink.dispatch("GET", "/api/v1/crypto/widgets");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto j = body_of(*res);
    for (const auto& w : j["data"]["widgets"]) {
        if (w["gate"] == "fleet_read") {
            CHECK(w["available"] == true);
        } else {
            CHECK(w["available"] == false);
            CHECK(w["availability"] == "confined");
            CHECK(w["drill_available"] == false);
        }
    }
    CHECK(h.probe_calls == 3);
    CHECK(h.audits.empty());
}

TEST_CASE("crypto widgets routes: a confined operator sees library widgets on every surface",
          "[crypto][routes][widgets][confinement]") {
    Harness h;
    h.scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-1"}};
    h.fleet_wide_access = cw::Access::kConfined;
    h.api->summary_result = sample_summary();
    h.api->stats_result = sample_stats();
    h.api->layouts[h.username] = {{"lib.devices_reporting", "ca.active"}, 2};
    // The lib card fragment reads, scoped.
    auto card = h.sink.dispatch("GET", "/fragments/crypto/widget/lib.devices_reporting");
    REQUIRE(card);
    CHECK_THAT(card->body, ContainsSubstring("cry-numbtn"));
    REQUIRE_FALSE(h.api->scopes.empty());
    CHECK(h.api->scopes.back() == h.scope);
    // The CA card is withheld (R2): a note, never a narrowed count, audited denied.
    auto ca = h.sink.dispatch("GET", "/fragments/crypto/widget/ca.active");
    REQUIRE(ca);
    CHECK(ca->status == 200);
    CHECK_THAT(ca->body, ContainsSubstring(std::string(cw::kConfinedWithheldMessage)));
    CHECK(h.api->stats_as_of.empty());
    CHECK(count_audits(h, "crypto.ca.stats.view", "denied") == 1);
    // The dashboard draws the library card and the R2 note, with no CA read.
    auto dash = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    REQUIRE(dash);
    CHECK_THAT(dash->body, ContainsSubstring(std::string(cw::kConfinedWithheldMessage)));
    CHECK(h.api->stats_as_of.empty());
    // REST: 403 with no .permission (no grant would admit a confined view).
    auto rest = h.sink.dispatch("GET", "/api/v1/crypto/ca/stats");
    REQUIRE(rest);
    CHECK(rest->status == 403);
    const auto j = body_of(*rest);
    CHECK_FALSE(j["error"].contains("permission"));
    CHECK(h.api->stats_as_of.empty());
}

TEST_CASE("crypto widgets routes: layout GET/PUT refuse a service-scoped token and a read-only "
          "MCP tier",
          "[crypto][routes][widgets][security]") {
    {
        Harness h;
        h.token_scope_service = "printers";
        auto get = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
        CHECK(get->status == 403);
        CHECK_FALSE(body_of(*get)["error"].contains("permission"));
        CHECK(put_layout(h, R"({"widgets":[]})")->status == 403);
        CHECK(h.api->layout_reads == 0);
        CHECK(h.api->layout_writes == 0);
        // M5: each refusal is audited with its own verb, result `denied`, principal-free target.
        CHECK(count_audits(h, "crypto.dashboard.layout.access_denied", "denied") == 1);
        CHECK(count_audits(h, "crypto.dashboard.layout.update", "denied") == 1);
        CHECK(count_audits(h, "crypto.dashboard.layout.update", "attempted") == 0);
        for (const auto& a : h.audits)
            CHECK(a.target_id.empty());
    }
    {
        Harness h;
        h.mcp_tier = "readonly";
        h.tier_allows = false;
        CHECK(h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout")->status == 403);
        CHECK(put_layout(h, R"({"widgets":[]})")->status == 403);
        CHECK(h.api->layout_writes == 0);
    }
}

TEST_CASE("crypto widgets routes: layout PUT - versioned, audited, 409 on a stale version",
          "[crypto][routes][widgets]") {
    Harness h;
    auto res = put_layout(h, R"({"widgets":["ca.active","lib.families_table"],"expected_version":0})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = body_of(*res);
    CHECK(j["data"]["version"] == 1);
    CHECK(j["data"]["widgets"] == nlohmann::json::array({"ca.active", "lib.families_table"}));
    // REQUIRE the two rows first, then pin principal-free target and details.
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == h.username);
    CHECK_THAT(h.audits[1].detail, ContainsSubstring("version=1"));

    res = put_layout(h, R"({"widgets":["ca.active"],"expected_version":0})"); // stale
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(res->get_header_value("X-Crypto-Layout-Version") == "1");
    CHECK(body_of(*res)["error"]["retry_after_ms"].is_null());
    CHECK(count_audits(h, "crypto.dashboard.layout.update", "failure") == 1);
    CHECK_THAT(h.audits.back().detail, ContainsSubstring("outcome=conflict"));
    CHECK(h.audits.back().target_id == h.username);

    auto got = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
    CHECK(body_of(*got)["data"]["version"] == 1);
}

TEST_CASE("crypto widgets routes: layout PUT without expected_version is a first save only",
          "[crypto][routes][widgets]") {
    // H1 (owner decision 2026-10-19): no expected_version + no stored row = first write (200);
    // no expected_version + a stored row = 409 naming the stored version, nothing written.
    Harness h;
    auto res = put_layout(h, R"({"widgets":["ca.active"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(body_of(*res)["data"]["version"] == 1);
    REQUIRE(h.api->expected_versions.size() == 1);
    CHECK_FALSE(h.api->expected_versions[0].has_value());

    res = put_layout(h, R"({"widgets":["ca.issued_7d"]})");
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(res->get_header_value("X-Crypto-Layout-Version") == "1");
    CHECK(body_of(*res)["error"]["retry_after_ms"].is_null());
    CHECK(count_audits(h, "crypto.dashboard.layout.update", "failure") == 1);
    auto got = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
    CHECK(body_of(*got)["data"]["widgets"] == nlohmann::json::array({"ca.active"}));
}

TEST_CASE("crypto widgets routes: layout failures map to 422 corrupt, 503 outcome unknown, 400",
          "[crypto][routes][widgets]") {
    using K = CryptoReadError::Kind;
    {
        Harness h;
        CryptoReadError e{K::kCorrupt, "the stored layout cannot be read"};
        e.version = 6;
        h.api->layout_error = e;
        auto get = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
        CHECK(get->status == 422);
        CHECK(get->get_header_value("X-Crypto-Layout-Version") == "6");
        CHECK(body_of(*get)["error"]["retry_after_ms"].is_null());
        // The dashboard offers Reset against that version.
        auto dash = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
        CHECK_THAT(dash->body, ContainsSubstring("data-version=\"6\""));
        CHECK_THAT(dash->body, ContainsSubstring("cryDash.reset(this)"));
    }
    {
        Harness h;
        h.api->layout_error = CryptoReadError{K::kOutcomeUnknown, "save outcome unknown — reload to check"};
        auto res = put_layout(h, R"({"widgets":["ca.active"]})");
        CHECK(res->status == 503);
        CHECK_THAT(body_of(*res)["error"]["message"].get<std::string>(),
                   ContainsSubstring("save outcome unknown"));
        CHECK_FALSE(body_of(*res)["error"]["retry_after_ms"].is_null());
        CHECK_THAT(h.audits.back().detail, ContainsSubstring("outcome=unknown"));
    }
    {
        Harness h;
        h.api->layout_error = CryptoReadError{K::kInvalid, "this account's name cannot key a dashboard layout"};
        CHECK(h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout")->status == 400);
    }
    {
        // Busy vs degraded on the dashboard banner.
        Harness h;
        h.api->layout_error = CryptoReadError{K::kDegraded, "x", CryptoReadCause::kCapacity};
        CHECK_THAT(h.sink.dispatch("GET", "/fragments/crypto/dashboard")->body,
                   ContainsSubstring("Busy"));
        h.api->layout_error = CryptoReadError{K::kDegraded, "x", CryptoReadCause::kStoreDegraded};
        const auto body = h.sink.dispatch("GET", "/fragments/crypto/dashboard")->body;
        CHECK_THAT(body, ContainsSubstring("Database degraded"));
        CHECK_THAT(body, !ContainsSubstring("lib.devices_reporting\""));
    }
    {
        // The layout store did not open at boot (ADR-0071 degrade posture): REST answers 503
        // WITHOUT a retry hint (a retry cannot help until a restart), and the dashboard draws
        // the default layout read-only under a notice - not the Retry banner.
        Harness h;
        CryptoReadError e{K::kDegraded, "dashboard layouts unavailable: the layout store did not "
                                        "open at server start",
                          CryptoReadCause::kStoreDegraded};
        e.unavailable_until_restart = true;
        h.api->layout_error = e;
        auto get = h.sink.dispatch("GET", "/api/v1/crypto/dashboard/layout");
        CHECK(get->status == 503);
        CHECK(body_of(*get)["error"]["retry_after_ms"].is_null());
        auto put = put_layout(h, R"({"widgets":["ca.active"]})");
        CHECK(put->status == 503);
        CHECK(body_of(*put)["error"]["retry_after_ms"].is_null());
        const auto dash = h.sink.dispatch("GET", "/fragments/crypto/dashboard")->body;
        CHECK_THAT(dash, ContainsSubstring("Saved layouts are unavailable on this server"));
        CHECK_THAT(dash, !ContainsSubstring("Crypto dashboard unavailable"));
        CHECK_THAT(dash, ContainsSubstring("data-wid=\"lib.devices_reporting\""));
        // Read-only: no Add / Reset / move / remove controls.
        CHECK_THAT(dash, !ContainsSubstring("cryDash.reset(this)"));
        CHECK_THAT(dash, !ContainsSubstring("cryDash.add()"));
        CHECK_THAT(dash, !ContainsSubstring("cryDash.remove(this)"));
    }
}

TEST_CASE("crypto widgets routes: layout PUT refuses bad bodies 400 (each reason named), "
          "cross-site 403",
          "[crypto][routes][widgets]") {
    Harness h;
    struct Bad {
        const char* body;
        const char* says;
    };
    for (const auto& b : {Bad{"not json", "must be JSON"}, Bad{"[]", "JSON object"},
                          Bad{R"({"widgets":"x"})", "array"}, Bad{R"({"widgets":[1]})", "widgets[0]"},
                          Bad{R"({"widgets":[],"username":"bob"})", "unknown argument"},
                          Bad{R"({"widgets":["nope"]})", "widgets[0] is not a catalogue"},
                          Bad{R"({"widgets":["ca.active","ca.active"]})", "widgets[1] repeats"},
                          Bad{R"({"widgets":[],"expected_version":-1})", "expected_version"}}) {
        INFO(b.body);
        auto res = put_layout(h, b.body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK_THAT(body_of(*res)["error"]["message"].get<std::string>(), ContainsSubstring(b.says));
    }
    CHECK(h.audits.empty());
    auto cross = h.sink.dispatch("PUT", "/api/v1/crypto/dashboard/layout", R"({"widgets":[]})",
                                 "application/json",
                                 {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}});
    CHECK(cross->status == 403);
    CHECK(h.api->layout_writes == 0);
}

TEST_CASE("crypto widgets routes: CA stats - Inventory:Read, database as_of, D13 shape, audited",
          "[crypto][routes][widgets]") {
    Harness h;
    h.api->stats_result = sample_stats();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/ca/stats");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.api->stats_as_of.size() == 1);
    CHECK_FALSE(h.api->stats_as_of[0].has_value()); // never the replica clock
    const auto j = body_of(*res)["data"];
    CHECK(j["as_of"] == FakeCryptoApi::kDbAsOf);
    CHECK_FALSE(j.contains("expiring"));
    CHECK(j["revoked_within_days"][0]["bucket"] == "superseded");
    CHECK(j["revoked_within_days"][0]["count"] == 11);
    CHECK(j["weeks"][0]["partial"] == true);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.ca.stats.view");
    CHECK(h.audits[0].target_type == "Inventory");
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("as_of=" + std::to_string(FakeCryptoApi::kDbAsOf)));
    CHECK(h.perm_calls.empty()); // never Security:Read for the counts

    // Degrade: 503 + retry, a failure row, never zeros.
    h.api->stats_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kDegraded,
                                                          "Yuzu CA read degraded",
                                                          CryptoReadCause::kStoreDegraded});
    res = h.sink.dispatch("GET", "/api/v1/crypto/ca/stats");
    CHECK(res->status == 503);
    CHECK_FALSE(body_of(*res)["error"]["retry_after_ms"].is_null());
    CHECK(count_audits(h, "crypto.ca.stats.view", "failure") == 1);

    // An unwired seam is a 503 WITHOUT a retry hint (L3): a wiring fault lasts until a restart,
    // the same posture as layouts unavailable since boot (ADR-0071).
    Harness bare(true, false);
    auto unwired = bare.sink.dispatch("GET", "/api/v1/crypto/ca/stats");
    CHECK(unwired->status == 503);
    CHECK(body_of(*unwired)["error"]["retry_after_ms"].is_null());
}

TEST_CASE("crypto widgets routes: one audit row per source per dashboard render, not per card",
          "[crypto][routes][widgets]") {
    Harness h;
    h.api->summary_result = sample_summary();
    h.api->stats_result = sample_stats();
    h.api->layouts[h.username] = {{"lib.devices_reporting", "lib.families_matched", "ca.active",
                                   "ca.revoked_30d", "ca.issued_per_week"},
                                  4};
    auto res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    REQUIRE(res);
    CHECK(h.api->summary_calls == 1);
    CHECK(h.api->stats_as_of.size() == 1);
    REQUIRE(h.audits.size() == 2);
    CHECK(count_audits(h, "crypto.libraries.view", "success") == 1);
    CHECK(count_audits(h, "crypto.ca.stats.view", "success") == 1);
    for (const auto& a : h.audits)
        CHECK_THAT(a.detail, ContainsSubstring(a.action == "crypto.ca.stats.view" ? "widgets=3"
                                                                                  : "widgets=2"));
    // Cards are drawn inline (no per-card fetch), with the layout version for the next save.
    CHECK_THAT(res->body, !ContainsSubstring("hx-trigger=\"load\""));
    CHECK_THAT(res->body, ContainsSubstring("data-version=\"4\""));
    // Three revoked buckets, each its own drill; the scope line above the Yuzu-issued cards.
    for (const char* b : {"bucket=superseded", "bucket=unpublished", "bucket=other"})
        CHECK_THAT(res->body, ContainsSubstring(b));
    CHECK_THAT(res->body, ContainsSubstring("certificates on your devices are not covered"));
    CHECK_THAT(res->body, ContainsSubstring("partial"));
    // A standalone card is audited per request.
    (void)h.sink.dispatch("GET", "/fragments/crypto/widget/ca.active");
    CHECK(count_audits(h, "crypto.ca.stats.view", "success") == 2);
}

TEST_CASE("crypto widgets routes: dashboard - preserved unknown ids reported; default detected",
          "[crypto][routes][widgets]") {
    Harness h;
    auto res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    CHECK_THAT(res->body, ContainsSubstring("Showing the default layout."));
    h.api->layouts[h.username] = {{"ca.active"}, 2};
    h.api->preserved_unknown = 2;
    res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    CHECK_THAT(res->body, ContainsSubstring("2 widgets from another server version kept but not shown"));
    // Empty layout: the scope line still shows.
    h.api->layouts[h.username] = {{}, 3};
    h.api->preserved_unknown = 0;
    res = h.sink.dispatch("GET", "/fragments/crypto/dashboard");
    CHECK_THAT(res->body, ContainsSubstring("certificates on your devices are not covered"));
}

TEST_CASE("crypto widgets routes: CA drill fragment - Security:Read, keyset cursor on Load more",
          "[crypto][routes][widgets]") {
    Harness h;
    auto page = sample_certs();
    page.total = 3;
    page.truncated = true;
    page.next_cursor = "c1:0123456789abcdef:Zm9v";
    h.api->certs_result = page;
    auto res = h.sink.dispatch("GET",
                               "/fragments/crypto/ca/certificates?kind=revoked&days=30&bucket=other");
    REQUIRE(res);
    REQUIRE(h.api->cert_calls.size() == 1);
    CHECK(h.api->cert_calls[0].bucket == RevokedBucket::kOther);
    CHECK_FALSE(h.api->cert_calls[0].as_of.has_value());
    // H2: Load more carries the keyset cursor alone (it holds the as_of), never an offset.
    CHECK_THAT(res->body, ContainsSubstring("cursor=c1%3A0123456789abcdef%3AZm9v"));
    CHECK_THAT(res->body, !ContainsSubstring("offset="));
    CHECK_THAT(res->body, !ContainsSubstring("as_of="));
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Security", "Read"});
    CHECK(count_audits(h, "crypto.ca.certificates.view", "success") == 1);
    // The second page carries the cursor back and answers rows only (a continuation).
    page.next_cursor.clear();
    page.truncated = false;
    h.api->certs_result = page;
    auto next = h.sink.dispatch(
        "GET", "/fragments/crypto/ca/certificates?kind=revoked&days=30&bucket=other&cursor=c1%3A0123456789abcdef%3AZm9v");
    REQUIRE(next);
    REQUIRE(h.api->cert_calls.size() == 2);
    CHECK(h.api->cert_calls[1].cursor == "c1:0123456789abcdef:Zm9v");
    CHECK_THAT(next->body, !ContainsSubstring("Load more")); // the last page
    // An offset on the drill is refused by name (keyset only), with no read.
    auto off = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=active&offset=1");
    REQUIRE(off);
    CHECK_THAT(off->body, ContainsSubstring("offset"));
    CHECK(h.api->cert_calls.size() == 2);
}

TEST_CASE("crypto widgets routes: CA drill - no Security:Read says so; confined is withheld",
          "[crypto][routes][widgets][confinement]") {
    {
        Harness h;
        h.security_read = false;
        auto res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=active");
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("The certificate list needs Security:Read"));
        CHECK(h.api->cert_calls.empty());
    }
    {
        Harness h;
        h.fleet_wide_access = cw::Access::kConfined;
        auto res = h.sink.dispatch("GET", "/fragments/crypto/ca/certificates?kind=active");
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring(std::string(cw::kConfinedWithheldMessage)));
        CHECK(h.api->cert_calls.empty());
    }
}

TEST_CASE("crypto widgets routes: the head helper sends the layout version and handles 409",
          "[crypto][routes][widgets][ui]") {
    const auto js = crypto_html::dashboard_head_html();
    CHECK_THAT(js, ContainsSubstring("expected_version"));
    CHECK_THAT(js, ContainsSubstring("r.status === 409"));
    CHECK_THAT(js, ContainsSubstring("save outcome unknown"));
    CHECK_THAT(js, ContainsSubstring("audit_persisted === false"));
    CHECK_THAT(js, ContainsSubstring("YuzuCharts.dispose"));
    CHECK_THAT(js, !ContainsSubstring("hx-on"));
}


TEST_CASE("crypto dashboard: script_json escapes every script-breaking sequence",
          "[crypto][ui][security]") {
    const auto out = crypto_html::script_json(
        nlohmann::json{{"k", "</script>&<!--\xE2\x80\xA8\xE2\x80\xA9"}});
    CHECK(out == "{\"k\":\"\\u003c/script\\u003e\\u0026\\u003c!--\\u2028\\u2029\"}");
    CHECK(nlohmann::json::parse(out)["k"] == "</script>&<!--\xE2\x80\xA8\xE2\x80\xA9");
}

// ── GET /api/v1/crypto/cbom (the CycloneDX 1.7 export) ───────────────────────────────────────

TEST_CASE("crypto routes: REST cbom - a CycloneDX 1.7 BOM with the never-cache headers, audited",
          "[crypto][routes][cbom]") {
    Harness h;
    h.api->summary_result = sample_summary();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom?family=openssl");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "application/vnd.cyclonedx+json; version=1.7");
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK(res->get_header_value("Vary") == "Authorization, Cookie, X-Yuzu-Token");
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
    const auto j = body_of(*res);
    CHECK(j["bomFormat"] == "CycloneDX");
    CHECK(j["specVersion"] == "1.7");
    CHECK(j["version"] == 1);
    CHECK_FALSE(j.contains("data")); // the BOM itself, not the A4 data envelope
    CHECK(j["serialNumber"].get<std::string>().starts_with("urn:uuid:"));
    CHECK(j["components"].size() == 2);
    CHECK(j["components"][0]["type"] == "library");
    REQUIRE(h.api->summary_queries.size() == 1);
    CHECK(h.api->summary_queries[0].family == "openssl");
    REQUIRE(h.api->scopes.size() == 1);
    CHECK_FALSE(h.api->scopes[0].has_value()); // TOP, passed straight through
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.cbom.export");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "Inventory");
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("cid="));
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("family=openssl"));
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("rows=1"));
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("src=catalogue"));
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("scope=fleet"));
    // The audit row names the exact artefact: the BOM's own serialNumber, the ecosystem filter
    // (absent here, so no key) and the component count.
    CHECK_THAT(h.audits[0].detail,
               ContainsSubstring("serial=" + j["serialNumber"].get<std::string>()));
    CHECK_THAT(h.audits[0].detail, !ContainsSubstring("ecosystem="));
    CHECK_THAT(h.audits[0].detail, ContainsSubstring("components=2"));
    // Incomplete by nature (name match), and unconfined.
    REQUIRE(j.contains("compositions"));
    CHECK(j["compositions"][0]["aggregate"] == "incomplete");
    bool fleet_scope = false;
    for (const auto& p : j["metadata"]["properties"])
        if (p["name"] == "yuzu:crypto:scope")
            fleet_scope = p["value"] == "fleet";
    CHECK(fleet_scope);
    // Two exports never share a serial number.
    auto again = h.sink.dispatch("GET", "/api/v1/crypto/cbom?family=openssl");
    REQUIRE(again);
    CHECK(body_of(*again)["serialNumber"] != j["serialNumber"]);
}

TEST_CASE("crypto routes: REST cbom - a scoped caller's exact scope reaches the seam; "
          "present-empty is zero rows, not the fleet",
          "[crypto][routes][cbom][security]") {
    Harness h;
    h.api->summary_result = sample_summary();
    h.scope = authz::VisibleSet{std::unordered_set<std::string>{"a1", "a2"}};
    REQUIRE(h.sink.dispatch("GET", "/api/v1/crypto/cbom")->status == 200);
    h.scope = authz::deny_all();
    REQUIRE(h.sink.dispatch("GET", "/api/v1/crypto/cbom")->status == 200);
    REQUIRE(h.api->scopes.size() == 2);
    REQUIRE(h.api->scopes[0].has_value());
    CHECK(*h.api->scopes[0] == std::unordered_set<std::string>{"a1", "a2"});
    REQUIRE(h.api->scopes[1].has_value());
    CHECK(h.api->scopes[1]->empty());
    // A confined caller's BOM says so (machine-readable), and so does its audit row.
    auto confined = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
    REQUIRE(confined);
    bool marked = false;
    for (const auto& p : body_of(*confined)["metadata"]["properties"])
        if (p["name"] == "yuzu:crypto:scope")
            marked = p["value"] == "confined";
    CHECK(marked);
    CHECK_THAT(h.audits.back().detail, ContainsSubstring("scope=confined"));
}

// Service-scoped-token behaviour (403 while RBAC enforcement is off, ITServiceOwner ceiling
// when on) is owned by the shared fleet_read_fn gate, not by this route; this Harness stubs
// the gate, so that coverage is NOT repeated here for the sibling /libraries routes either.

TEST_CASE("crypto routes: REST cbom - a refused gate keeps the gate's body; unwired gate and "
          "missing seam fail closed",
          "[crypto][routes][cbom][security]") {
    {
        Harness h;
        h.admitted = false;
        auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, ContainsSubstring("permission denied"));
        CHECK(res->get_header_value("Cache-Control") == "no-store, private");
        CHECK(h.api->scopes.empty());
        CHECK(h.audits.empty()); // the gate audits its own refusal
    }
    {
        Harness h(/*wire_gate=*/false);
        auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.api->scopes.empty());
    }
    {
        Harness h(/*wire_gate=*/true, /*wire_api=*/false);
        auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
}

TEST_CASE("crypto routes: REST cbom - a degraded read is 503 + retry_after_ms and a failure audit, "
          "never an empty BOM",
          "[crypto][routes][cbom]") {
    for (const auto cause : {CryptoReadCause::kStoreDegraded, CryptoReadCause::kCapacity}) {
        Harness h;
        h.api->summary_result = std::unexpected(
            CryptoReadError{CryptoReadError::Kind::kDegraded, "x", cause});
        auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
        REQUIRE(res);
        CHECK(res->status == 503);
        const auto j = body_of(*res);
        CHECK(j["error"]["retry_after_ms"] == 5000);
        CHECK(j["error"]["message"] == std::string(crypto_library::degraded_message(cause)));
        CHECK_FALSE(j.contains("bomFormat"));
        CHECK(res->get_header_value("Cache-Control") == "no-store, private");
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "crypto.cbom.export");
        CHECK(h.audits[0].result == "failure");
    }
}

TEST_CASE("crypto routes: REST cbom - bad parameters are a 400 before any read",
          "[crypto][routes][cbom]") {
    Harness h;
    h.api->summary_result = sample_summary();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom?family=notalib");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(body_of(*res)["error"]["message"] == "unknown family");
    CHECK(h.api->summary_calls == 0);
    CHECK(h.audits.empty());
    // A seam-level refusal is a 400 too, not a 503.
    h.api->summary_result = std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "unknown family"});
    auto r2 = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
    REQUIRE(r2);
    CHECK(r2->status == 400);
    CHECK(body_of(*r2)["error"]["message"] == "unknown family");
}

TEST_CASE("crypto routes: REST cbom - a lost audit row is flagged in the header and metadata, the "
          "BOM is still served",
          "[crypto][routes][cbom][security]") {
    Harness h;
    h.audit_ok = false;
    h.api->summary_result = sample_summary();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    bool flagged = false;
    for (const auto& p : body_of(*res)["metadata"]["properties"])
        if (p["name"] == "yuzu:crypto:audit_persisted")
            flagged = p["value"] == "false";
    CHECK(flagged);
}

TEST_CASE("crypto routes: REST cbom - a CSPRNG failure is a retryable 503 BEFORE any store read",
          "[crypto][routes][cbom]") {
    Harness h;
    h.api->summary_result = sample_summary();
    test_hooks::force_next_failure_for_this_thread();
    auto res = h.sink.dispatch("GET", "/api/v1/crypto/cbom");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body_of(*res)["error"]["retry_after_ms"] == 5000);
    CHECK(h.audits.empty());
    // The identity is minted first: a CSPRNG failure costs no store read and no read slot.
    CHECK(h.api->summary_calls == 0);
    CHECK(h.api->scopes.empty());
}
