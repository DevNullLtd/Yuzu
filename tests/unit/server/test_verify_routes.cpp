/**
 * test_verify_routes.cpp — route-handler coverage for the `/auto` Stage 3
 * VERIFY fragments (#2542): VerifyRoutes was registered directly on a raw
 * httplib::Server, so none of its three GET handlers were reachable by the
 * in-process TestRouteSink harness. `VerifyRoutes::register_routes` now has
 * an HttpRouteSink overload (the httplib::Server& overload wraps + delegates
 * to it, mirroring the ComplianceRoutes/DashboardRoutes precedent), so the
 * handlers are drivable here with no acceptor thread (#438 TSan trap).
 *
 * Pinned per handler:
 *   - the permission tier — Infrastructure:Read for the config form,
 *     GuaranteedState:Read for the aggregate result and the per-machine
 *     drill,
 *   - the aggregate result's input validation (missing params / invalid
 *     charset / baseline==candidate) renders an honest 200 note rather than
 *     a 4xx — the dashboard htmx config drops 4xx/5xx bodies,
 *   - the cohort-degrade path (cohort_fn returns nullopt) renders a distinct
 *     "could not be read" note,
 *   - the two audit verbs are genuinely distinct: `dex.app_perf.compare` for
 *     the identity-free aggregate vs `dex.app_perf.compare.drill` for the
 *     per-machine PII surface — a works-council accountability property, not
 *     an accident of the code, so a regression collapsing them to one verb
 *     must fail here.
 */

#include "verify_routes.hpp"
#include "test_route_sink.hpp"
#include "test_verify_api_double.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kBaseline = "1.0.0";
constexpr const char* kCandidate = "2.0.0";

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};
struct PermCall {
    std::string securable_type, op;
};

struct VerifyHarness {
    // Declaration order matters (CLAUDE.md TestRouteSink convention): `sink`
    // captures `routes`'s `this` in its registered handlers, so `routes`
    // must outlive `sink` — declare it FIRST so it destructs LAST.
    VerifyRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditCall> audit_calls;
    std::vector<PermCall> perm_calls;
    /// nullopt ⇒ perm_fn always allows and cohort_fn returns a populated
    /// (non-degraded) read; a test flips this to exercise the degrade path.
    bool cohort_degraded{false};

    VerifyHarness() {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "verify-op";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response&,
                              const std::string& securable_type, const std::string& op) -> bool {
            perm_calls.push_back({securable_type, op});
            return true;
        };
        auto groups_fn = []() -> std::vector<std::pair<std::string, std::string>> {
            return {{"grp_1", "All Devices"}};
        };
        AppPerfCohortFn cohort_fn = [this](std::string_view, std::string_view, std::string_view,
                                           std::string_view,
                                           int) -> std::optional<CohortRead> {
            if (cohort_degraded)
                return std::nullopt;
            CohortRead r;
            r.member_count = 3;
            return r; // empty rows: "insufficient", not a degrade — fine for these tests
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };

        auto api = std::make_shared<yuzu::server::test::FnVerifyApi>(cohort_fn);
        routes.register_routes(sink, auth_fn, perm_fn, groups_fn, audit_fn, api);
    }
};

std::string run_query(const std::string& baseline = kBaseline,
                      const std::string& candidate = kCandidate) {
    return "/fragments/auto/verify/run?group=grp_1&app=myapp&baseline=" + baseline +
           "&candidate=" + candidate;
}

std::string drill_query(const std::string& baseline = kBaseline,
                        const std::string& candidate = kCandidate) {
    return "/fragments/auto/verify/drill?group=grp_1&app=myapp&baseline=" + baseline +
           "&candidate=" + candidate;
}

} // namespace

TEST_CASE("/fragments/auto/verify: config form gates Infrastructure:Read",
          "[verify_routes][security]") {
    VerifyHarness h;
    auto res = h.sink.Get("/fragments/auto/verify");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0].securable_type == "Infrastructure");
    CHECK(h.perm_calls[0].op == "Read");
}

TEST_CASE("/fragments/auto/verify/run: gates GuaranteedState:Read", "[verify_routes][security]") {
    VerifyHarness h;
    auto res = h.sink.Get(run_query());
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0].securable_type == "GuaranteedState");
    CHECK(h.perm_calls[0].op == "Read");
}

TEST_CASE("/fragments/auto/verify/run: missing params renders a note, no audit",
          "[verify_routes]") {
    VerifyHarness h;
    auto res = h.sink.Get("/fragments/auto/verify/run?group=grp_1");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Pick a cohort") != std::string::npos);
    CHECK(h.audit_calls.empty());
}

TEST_CASE("/fragments/auto/verify/run: baseline==candidate renders a note, no audit",
          "[verify_routes]") {
    VerifyHarness h;
    auto res = h.sink.Get(run_query(kBaseline, kBaseline));
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("must be two different versions") != std::string::npos);
    CHECK(h.audit_calls.empty());
}

TEST_CASE("/fragments/auto/verify/run: cohort degrade renders a distinct note, no audit",
          "[verify_routes]") {
    VerifyHarness h;
    h.cohort_degraded = true;
    auto res = h.sink.Get(run_query());
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("could not be read") != std::string::npos);
    CHECK(h.audit_calls.empty());
}

TEST_CASE("/fragments/auto/verify/run: happy path audits dex.app_perf.compare",
          "[verify_routes]") {
    VerifyHarness h;
    auto res = h.sink.Get(run_query());
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.audit_calls.size() == 1);
    CHECK(h.audit_calls[0].action == "dex.app_perf.compare");
    CHECK(h.audit_calls[0].result == "success");
    CHECK(h.audit_calls[0].target_type == "GuaranteedState");
    CHECK(h.audit_calls[0].target_id == "grp_1");
}

TEST_CASE("/fragments/auto/verify/drill: gates GuaranteedState:Read and audits "
          "dex.app_perf.compare.drill, distinct from the aggregate verb",
          "[verify_routes][security]") {
    VerifyHarness h;
    auto res = h.sink.Get(drill_query());
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0].securable_type == "GuaranteedState");
    REQUIRE(h.audit_calls.size() == 1);
    CHECK(h.audit_calls[0].action == "dex.app_perf.compare.drill");
    CHECK(h.audit_calls[0].action != "dex.app_perf.compare");
}
