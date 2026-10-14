/**
 * @file test_access_reviews_routes.cpp
 * @brief HTTP-level coverage of access_reviews_routes.{hpp,cpp}, driven in-process through
 *        TestRouteSink. Every closure is injected; nothing reads a store or a clock.
 *
 * Pinned, in order of consequence:
 *   - the loud gate runs BEFORE any read, on exactly AccessReview:Read; the control hint is a
 *     SEPARATE probe on AccessReview:Attest and is never mistaken for the gate;
 *   - an engine-class session is refused like the REST twins refuse it (403, A4 body with a
 *     correlation id, a denied row with detail `engine_session_denied`) on EVERY fragment;
 *   - each success writes exactly the twin's audit tuple, a malformed id writes none and reads
 *     nothing, a store fault is a 200 red box with no audit row;
 *   - a dropped or throwing audit write sets Sec-Audit-Failed once and the page still renders.
 */

#include "access_reviews_render.hpp"
#include "access_reviews_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;

namespace {

constexpr const char* kDenyBody = R"({"error":{"code":403,"message":"permission denied"}})";
constexpr const char* kCampaigns = "/fragments/access/reviews/campaigns";
constexpr const char* kCampaign = "/fragments/access/reviews/campaign";
constexpr const char* kGrants = "/fragments/access/reviews/grants";

CampaignView one_campaign(const std::string& id) {
    CampaignView v;
    v.campaign.campaign_id = id;
    v.campaign.title = "Q4";
    v.campaign.status = "open";
    v.campaign.created_by = "dave";
    v.campaign.created_at_ms = 1791884472000;
    AccessReviewAttestationRow a;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "Operator";
    a.decision = "pending";
    v.attestations = {a};
    return v;
}

int count_of(const std::string& hay, const std::string& needle) {
    int n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

// `sink` is LAST: its handlers capture `this` and must not outlive the other members.
struct Harness {
    bool session_present{true};
    bool engine{false};
    bool allow_read{true};
    bool allow_attest{true};
    std::vector<std::pair<std::string, std::string>> gate_calls, probe_calls;
    int list_calls{0}, get_calls{0}, grants_calls{0};
    std::string last_get_id;
    std::expected<std::vector<AccessReviewCampaignRow>, std::string> list_result{
        std::vector<AccessReviewCampaignRow>{}};
    std::expected<CampaignView, std::string> get_result{one_campaign("abc123")};
    std::expected<access_reviews::GrantsView, std::string> grants_result{access_reviews::GrantsView{}};
    struct Audit {
        std::string action, result, tt, ti, detail;
    };
    std::vector<Audit> audits;
    bool audit_ok{true};
    bool audit_throws{false};
    yuzu::server::test::TestRouteSink sink;

    access_reviews::ReviewsDeps deps() {
        access_reviews::ReviewsDeps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = "rev";
            if (engine)
                s.principal_kind = "engine";
            return s;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& o) {
            gate_calls.emplace_back(t, o);
            if (allow_read)
                return true;
            res.status = 403;
            res.set_content(kDenyBody, "application/json");
            return false;
        };
        d.probe_perm_fn = [this](const httplib::Request&, const std::string& t, const std::string& o) {
            probe_calls.emplace_back(t, o);
            return allow_attest;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& ti, const std::string& dt) {
            if (audit_throws)
                throw std::runtime_error("audit sink down");
            audits.push_back({a, r, tt, ti, dt});
            return audit_ok;
        };
        d.list_campaigns_fn = [this] {
            ++list_calls;
            return list_result;
        };
        d.get_campaign_fn = [this](const std::string& id) {
            ++get_calls;
            last_get_id = id;
            return get_result;
        };
        d.grants_fn = [this] {
            ++grants_calls;
            return grants_result;
        };
        return d;
    }
    void wire() { access_reviews::register_access_reviews_routes(sink, deps()); }
    std::unique_ptr<httplib::Response> get(const std::string& path) { return sink.dispatch("GET", path); }
    int reads() const { return list_calls + get_calls + grants_calls; }
};

} // namespace

TEST_CASE("reviews routes: registration fails fast when any dependency is unbound",
          "[access-reviews][routes]") {
    using Member = std::function<void(access_reviews::ReviewsDeps&)>;
    const std::vector<Member> unbind = {
        [](auto& d) { d.auth_fn = nullptr; },           [](auto& d) { d.perm_fn = nullptr; },
        [](auto& d) { d.probe_perm_fn = nullptr; },     [](auto& d) { d.audit_fn = nullptr; },
        [](auto& d) { d.list_campaigns_fn = nullptr; }, [](auto& d) { d.get_campaign_fn = nullptr; },
        [](auto& d) { d.grants_fn = nullptr; },
    };
    for (const auto& f : unbind) {
        Harness h;
        auto d = h.deps();
        f(d);
        CHECK_THROWS_AS(access_reviews::register_access_reviews_routes(h.sink, d), std::invalid_argument);
    }
}

TEST_CASE("reviews routes: a denied caller gets the gate's exact response and costs no read",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    h.allow_read = false;
    for (const char* path : {kCampaigns, "/fragments/access/reviews/campaign?id=abc123", kGrants}) {
        INFO(path);
        const auto res = h.get(path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == kDenyBody);
        CHECK(res->get_header_value("Cache-Control").empty());
    }
    CHECK(h.reads() == 0);
    CHECK(h.audits.empty());
    CHECK(h.probe_calls.empty());
}

TEST_CASE("reviews routes: the gate is exactly AccessReview:Read and the hint is a separate Attest probe",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    (void)h.get(kCampaigns);
    (void)h.get("/fragments/access/reviews/campaign?id=abc123");
    (void)h.get(kGrants);
    using P = std::pair<std::string, std::string>;
    CHECK(h.gate_calls == std::vector<P>(3, P{"AccessReview", "Read"}));
    // The hint is probed for the two fragments that draw controls, and never for the grants.
    CHECK(h.probe_calls == std::vector<P>(2, P{"AccessReview", "Attest"}));
}

TEST_CASE("reviews routes: the Attest hint decides the controls and is not the gate",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    h.list_result = std::vector<AccessReviewCampaignRow>{[] {
        AccessReviewCampaignRow c;
        c.campaign_id = "abc123";
        c.title = "Q4";
        c.status = "open";
        return c;
    }()};
    auto res = h.get(kCampaigns);
    CHECK_THAT(res->body, ContainsSubstring("data-act=\"ar-open\""));
    res = h.get("/fragments/access/reviews/campaign?id=abc123");
    CHECK_THAT(res->body, ContainsSubstring("data-act=\"ar-attest\""));

    h.allow_attest = false;
    res = h.get(kCampaigns);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, !ContainsSubstring("data-act=\"ar-open\""));
    CHECK_THAT(res->body, !ContainsSubstring("data-act=\"ar-close\""));
    res = h.get("/fragments/access/reviews/campaign?id=abc123");
    CHECK(res->status == 200);
    CHECK_THAT(res->body, !ContainsSubstring("data-act=\"ar-attest\""));
    CHECK_THAT(res->body, ContainsSubstring("alice"));  // the evidence is still readable
}

TEST_CASE("reviews routes: an engine-class session is refused on every fragment like the twins refuse it",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    h.engine = true;
    struct Row {
        const char* path;
        const char* action;
    };
    for (const auto& r : {Row{kCampaigns, "access_review.list"},
                          Row{"/fragments/access/reviews/campaign?id=abc123", "access_review.get"},
                          Row{kGrants, "access_review.exported"}}) {
        INFO(r.path);
        h.audits.clear();
        const auto res = h.get(r.path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, ContainsSubstring("engine principals cannot access this endpoint"));
        CHECK_THAT(res->body, ContainsSubstring("\"code\":403"));
        CHECK_THAT(res->body, ContainsSubstring("correlation_id"));
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == r.action);
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].tt == "AccessReview");
        CHECK(h.audits[0].ti.empty());
        CHECK(h.audits[0].detail == "engine_session_denied");
    }
    CHECK(h.reads() == 0);
}

TEST_CASE("reviews routes: a missing session is refused before any read", "[access-reviews][routes]") {
    Harness h;
    h.wire();
    h.session_present = false;
    for (const char* p : {kCampaigns, kCampaign, kGrants}) {
        const auto res = h.get(p);
        REQUIRE(res);
        CHECK(res->status == 401);
    }
    CHECK(h.reads() == 0);
}

TEST_CASE("reviews routes: campaigns audits access_review.list with the count and is no-store",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    AccessReviewCampaignRow c;
    c.campaign_id = "x1";
    c.title = "T";
    c.status = "closed";
    h.list_result = std::vector<AccessReviewCampaignRow>{c, c};
    const auto res = h.get(kCampaigns);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK_THAT(res->get_header_value("Cache-Control"), ContainsSubstring("no-store"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "access_review.list");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].tt == "AccessReview");
    CHECK(h.audits[0].ti.empty());
    CHECK(h.audits[0].detail == "count=2");
}

TEST_CASE("reviews routes: a store fault is a 200 red box with no audit row and no store text",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    h.list_result = std::unexpected(std::string("ERROR: relation x PGRES_FATAL"));
    h.get_result = std::unexpected(std::string("ERROR: relation y PGRES_FATAL"));
    h.grants_result = std::unexpected(std::string("ERROR: relation z PGRES_FATAL"));
    for (const char* p : {kCampaigns, "/fragments/access/reviews/campaign?id=abc123", kGrants}) {
        INFO(p);
        const auto res = h.get(p);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(res->body, !ContainsSubstring("PGRES"));
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    CHECK(h.audits.empty());
}

TEST_CASE("reviews routes: campaign id validation reads nothing and audits nothing",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    // Empty or absent is the placeholder, not an error.
    auto res = h.get(kCampaign);
    CHECK_THAT(res->body, ContainsSubstring(std::string(access_reviews::kSelectCampaign)));
    res = h.get(std::string(kCampaign) + "?id=");
    CHECK_THAT(res->body, ContainsSubstring(std::string(access_reviews::kSelectCampaign)));

    for (const char* bad : {"..%2Fx", "%23", ".", "..", "a.b", "a%2Fb", "%3Cscript%3E", "a%22b", "a%27b"}) {
        INFO(bad);
        res = h.get(std::string(kCampaign) + "?id=" + bad);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("No campaign with that id"));
    }
    res = h.get(std::string(kCampaign) + "?id=" + std::string(65, 'a'));
    CHECK_THAT(res->body, ContainsSubstring("No campaign with that id"));
    CHECK(h.get_calls == 0);
    CHECK(h.audits.empty());
    CHECK(h.probe_calls.empty());

    // The 64-character boundary is valid and reaches the store.
    (void)h.get(std::string(kCampaign) + "?id=" + std::string(64, 'a'));
    CHECK(h.get_calls == 1);
    CHECK(h.last_get_id == std::string(64, 'a'));
}

TEST_CASE("reviews routes: not_found is a distinct note, any other fault is unavailable",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    h.get_result = std::unexpected(std::string("not_found: no such campaign"));
    auto res = h.get(std::string(kCampaign) + "?id=abc123");
    CHECK_THAT(res->body, ContainsSubstring("No campaign with that id"));
    CHECK_THAT(res->body, !ContainsSubstring("role=\"alert\""));
    CHECK(h.audits.empty());

    h.get_result = std::unexpected(std::string("connection lost"));
    res = h.get(std::string(kCampaign) + "?id=abc123");
    CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(res->body, ContainsSubstring("reviews/campaign?id=abc123"));  // Retry
    CHECK_THAT(res->body, !ContainsSubstring("No campaign with that id"));
    CHECK(h.audits.empty());
}

TEST_CASE("reviews routes: campaign success audits access_review.get with the id as target",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    const auto res = h.get(std::string(kCampaign) + "?id=abc123");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->get_header_value("Cache-Control"), ContainsSubstring("no-store"));
    CHECK(count_of(res->body, "id=\"ar-campaign-side\" hx-swap-oob=\"true\"") == 1);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "access_review.get");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].tt == "AccessReview");
    CHECK(h.audits[0].ti == "abc123");
    CHECK(h.audits[0].detail.empty());
    CHECK(h.last_get_id == "abc123");
}

TEST_CASE("reviews routes: grants audits access_review.exported with format=view and the stamp",
          "[access-reviews][routes]") {
    Harness h;
    h.wire();
    access_reviews::GrantsView g;
    g.rbac_enforcement = "disabled";
    g.rows.resize(3);
    h.grants_result = g;
    const auto res = h.get(kGrants);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("export?format=csv"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "access_review.exported");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].tt == "AccessReview");
    CHECK(h.audits[0].ti.empty());
    CHECK(h.audits[0].detail == "format=view rows=3 rbac_enforcement=disabled");
}

TEST_CASE("reviews routes: a dropped or throwing audit write sets Sec-Audit-Failed once and still renders",
          "[access-reviews][routes]") {
    for (const bool throws : {false, true}) {
        INFO("throws=" << throws);
        Harness h;
        h.wire();
        h.audit_ok = false;
        h.audit_throws = throws;
        for (const char* p : {kCampaigns, "/fragments/access/reviews/campaign?id=abc123", kGrants}) {
            INFO(p);
            const auto res = h.get(p);
            REQUIRE(res);
            CHECK(res->status == 200);
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            CHECK(res->get_header_value_count("Sec-Audit-Failed") == 1);
        }
    }
}
