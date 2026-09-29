/**
 * test_compliance_routes.cpp — guardian-confinement-2298 PR3 §3e coverage for
 * the two compliance dashboard fragments (`/fragments/compliance/summary` and
 * `/fragments/compliance/{policy_id}`): both were `auth_fn`-only, no
 * `perm_fn` at all, rendering per-agent compliance rows fleet-wide with no
 * per-target parameter to scope against.
 *
 * ComplianceRoutes had no route-level test coverage before this file — the
 * sink-based `register_routes` overload (mirrors AuthRoutes/WorkflowRoutes,
 * added alongside this test) is what makes that possible without the #438
 * TSan-hostile live-socket pattern.
 */

#include "authz_gates.hpp"
#include "compliance_api_local.hpp" // make_local_compliance_api — ADR-0031 WS-A4
#include "compliance_routes.hpp"
#include "pg/pg_pool.hpp"
#include "policy_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct ComplianceHarness {
    // Declaration order matters (CLAUDE.md TestRouteSink convention): `sink`
    // captures `routes`'s `this` in its registered handlers, so `routes`
    // must outlive `sink` — declare it FIRST so it destructs LAST.
    ComplianceRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditCall> audit_calls;
    /// Empty ⇒ an ordinary session; a test sets this to prove the fragment
    /// deny fires independently of any perm_fn grant.
    std::string mock_token_scope_service;
    /// #4034: when false, audit_fn reports a persistence failure (returns
    /// false) so a test can exercise the set-and-proceed Sec-Audit-Failed
    /// header on GET /api/v1/compliance/{id}.
    bool audit_ok{true};

    /// #4034 — a fake `authz::FleetReadGate` gate the harness controls per
    /// test, same shape as test_rest_inventory_software.cpp's `InvHarness`.
    /// `nullopt` (default) ⇒ the gate does not exist (registered with no
    /// fleet_read_fn at all — misconfigured call site, 503); a test that
    /// wants the gate wired sets this via `wire_fleet_read_fn()` before
    /// constructing the harness is not possible (register_routes runs in
    /// the ctor), so this harness always wires a real fake gate and a test
    /// drives its behaviour via `fleet_admitted`/`fleet_scope` below.
    bool fleet_admitted{true};
    std::optional<std::unordered_set<std::string>> fleet_scope; // nullopt = TOP/unfiltered

    /// #4034 follow-up — `policy_store` defaults to nullptr (every
    /// pre-existing test above and the null-store 503 tests below rely on
    /// that), but a test can pass a REAL, live-Postgres-backed PolicyStore
    /// (see `policy_store_tpl` below) to exercise query parsing, pagination,
    /// and the audit fail-closed path end to end — the one thing the
    /// null-store harness can never reach. ADR-0031 WS-A4: routes now
    /// consume the store-free ComplianceApi seam, so a non-null store is
    /// wrapped in `make_local_compliance_api` before registration; a null
    /// store leaves the seam nullptr, matching the pre-seam null-store
    /// degrade path exactly.
    explicit ComplianceHarness(PolicyStore* policy_store = nullptr) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            s.token_scope_service = mock_token_scope_service;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return audit_ok;
        };
        auto agents_json_fn = []() -> std::string { return "[]"; };
        ComplianceRoutes::FleetReadFn fleet_read_fn =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                  const std::string&) -> authz::FleetReadGate {
            if (!fleet_admitted) {
                res.status = 403;
                res.set_content(R"({"error":{"message":"permission denied"}})",
                                "application/json");
                return {};
            }
            return {true, fleet_scope};
        };

        ComplianceRoutes::ComplianceApiPtr api;
        if (policy_store)
            api = make_local_compliance_api(*policy_store);

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, api, agents_json_fn,
                               std::move(fleet_read_fn));
    }
};

// ---- PG fixtures for the live-store tests below ---------------------------
// Same template KEY and byte-identical setup callback as
// test_policy_store.cpp's `policy_store_tpl` — PgTestTemplate explicitly
// supports (and replay-verifies) sharing a name across files that need the
// exact same store set, so this reuses that file's already-built template
// instead of paying a second migration pass.
yuzu::test::PgTestTemplate policy_store_tpl{
    "policystore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        PolicyStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("policy_store template: failed to migrate");
    }};

const std::string kFragmentYaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Check Service Running
description: Verify a Windows service is running
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
)";

// Fragment `name` (displayName) is uniqueness-checked pre-insert
// (policy_store.cpp #396) — a test that creates more than one fragment in
// the same (per-test, freshly-cloned) database must give each a distinct
// name, unlike policies, which carry no such constraint.
std::string make_fragment_yaml(const std::string& name) {
    return R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: )" +
           name + R"(
description: Verify a Windows service is running
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
)";
}

std::string make_policy_yaml(const std::string& fragment_id, const std::string& name) {
    return R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: )" +
           name + R"(
description: A test policy
fragment: )" +
           fragment_id + R"(
scope: "tags.env == 'production'"
)";
}

} // namespace

TEST_CASE("/fragments/compliance/summary: a service-scoped token is denied",
          "[compliance][security]") {
    ComplianceHarness h;
    h.mock_token_scope_service = "printers";

    auto res = h.sink.Get("/fragments/compliance/summary");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("service-scoped") != std::string::npos);
    // No permission field: this is a blanket deny with no perm_fn gate — the
    // A4 builder omits the field rather than name a grant that wouldn't help.
    CHECK_FALSE(j["error"].contains("permission"));
    // Header/body correlation-id parity (consistency-auditor, Gate 4): a
    // hand-built id used to land in the body only, never the header.
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());

    bool saw_denied = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "compliance.fragment.access_denied" && c.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

TEST_CASE("/fragments/compliance/summary: an ordinary session reaches the summary",
          "[compliance]") {
    ComplianceHarness h;

    auto res = h.sink.Get("/fragments/compliance/summary");
    REQUIRE(res);
    CHECK(res->status == 200);
    // policy_store is nullptr in this harness — the "No policies defined"
    // empty-state branch, not a denial. Confirms the deny above didn't also
    // block the legitimate path.
    CHECK(res->body.find("No policies defined") != std::string::npos);
    for (const auto& c : h.audit_calls) {
        CHECK(c.action != "compliance.fragment.access_denied");
    }
}

TEST_CASE("/fragments/compliance/{policy_id}: a service-scoped token is denied",
          "[compliance][security]") {
    ComplianceHarness h;
    h.mock_token_scope_service = "printers";

    auto res = h.sink.Get("/fragments/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("service-scoped") != std::string::npos);
    // Header/body correlation-id parity (consistency-auditor, Gate 4).
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());

    bool saw_denied = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "compliance.fragment.access_denied" && c.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

TEST_CASE("/fragments/compliance/{policy_id}: an ordinary session reaches the detail",
          "[compliance]") {
    ComplianceHarness h;

    auto res = h.sink.Get("/fragments/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 200);
    // policy_store is nullptr — the "No compliance data yet" empty-state
    // branch, not a denial.
    CHECK(res->body.find("No compliance data yet") != std::string::npos);
    for (const auto& c : h.audit_calls) {
        CHECK(c.action != "compliance.fragment.access_denied");
    }
}

// ═════════════════════════════════════════════════════════════════════════
// #4034 — GET /api/v1/compliance* + /api/v1/polic* REST v1 twins. The
// harness's `policy_store` is always nullptr (matching the pre-existing
// #3559 item 3 gap: ComplianceHarness cannot exercise a store-backed
// branch), so these pin the auth/gate/envelope/degraded-service wiring, not
// the real query/builder output — the confined_policy_compliance tally
// itself is unit-tested directly (pure, no store) in
// test_compliance_model.cpp.
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("GET /api/v1/policy-fragments: null store -> 503 A4 body",
          "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/policy-fragments");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
}

TEST_CASE("GET /api/v1/policies: null store -> 503 A4 body", "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/policies");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("GET /api/v1/policies/{id}: null store -> 503 A4 body", "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/policies/pol_1");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("GET /api/v1/compliance: null store -> 503 A4 body", "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/compliance");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("GET /api/v1/compliance/{id}: fleet_read_fn denies -> gate's own response, "
          "no store touched, no route audit",
          "[compliance][rest][security]") {
    ComplianceHarness h;
    h.fleet_admitted = false;

    auto res = h.sink.Get("/api/v1/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 403); // the fake gate's own denial response
    for (const auto& c : h.audit_calls)
        CHECK(c.action != "compliance.agent_statuses.view");
}

TEST_CASE("GET /api/v1/compliance/{id}: fleet_read_fn admits, null store -> 503, "
          "gate is the SOLE authorization (never stacked with perm_fn)",
          "[compliance][rest]") {
    ComplianceHarness h;
    h.fleet_admitted = true;

    auto res = h.sink.Get("/api/v1/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    // The route never reached the audit call (null-store short-circuit
    // precedes it) — same "no access, no audit row" contract as the null
    // store case above.
    for (const auto& c : h.audit_calls)
        CHECK(c.action != "compliance.agent_statuses.view");
}

// ═════════════════════════════════════════════════════════════════════════
// #4034 follow-up — live-store coverage for the REST v1 list routes' query
// parsing. The tests above pin the auth/gate/envelope/degraded-service
// wiring against a permanently-null store; these exercise the actual
// `enabled_only`/`limit`/`pagination.page_size` handling end to end against
// a real PolicyStore, closing the "no test reaches a successful response"
// gap the null-store harness could never reach. PG-gated: skips when
// YUZU_TEST_POSTGRES_DSN is unset.
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("GET /api/v1/policies: enabled_only=false does NOT filter (regression — "
          "presence alone used to silently mean true)",
          "[compliance][rest][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFragmentYaml);
    REQUIRE(frag.has_value());
    auto p1 = store.create_policy(make_policy_yaml(frag.value(), "Enabled Policy"));
    auto p2 = store.create_policy(make_policy_yaml(frag.value(), "Disabled Policy"));
    REQUIRE(p1.has_value());
    REQUIRE(p2.has_value());
    REQUIRE(store.disable_policy(p2.value()).has_value());

    ComplianceHarness h{&store};
    auto res = h.sink.Get("/api/v1/policies?enabled_only=false");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    // Both policies present — the filter must NOT have engaged.
    CHECK(j["data"].size() == 2);
}

TEST_CASE("GET /api/v1/policies: enabled_only=true filters to enabled only",
          "[compliance][rest][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFragmentYaml);
    REQUIRE(frag.has_value());
    auto p1 = store.create_policy(make_policy_yaml(frag.value(), "Enabled Policy"));
    auto p2 = store.create_policy(make_policy_yaml(frag.value(), "Disabled Policy"));
    REQUIRE(p1.has_value());
    REQUIRE(p2.has_value());
    REQUIRE(store.disable_policy(p2.value()).has_value());

    ComplianceHarness h{&store};
    auto res = h.sink.Get("/api/v1/policies?enabled_only=true");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["name"].get<std::string>() == "Enabled Policy");
}

TEST_CASE("GET /api/v1/policies: enabled_only with an unrecognized value -> 400",
          "[compliance][rest][pg]") {
    // Needs a real (non-null) store: the null-store 503 short-circuit runs
    // BEFORE query-parameter parsing, so a null-store harness can never
    // reach this branch (see the null-store 503 test above).
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    ComplianceHarness h{&store};
    auto res = h.sink.Get("/api/v1/policies?enabled_only=maybe");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("enabled_only") != std::string::npos);
}

TEST_CASE("GET /api/v1/policies: limit clamps and pagination.page_size reflects the "
          "resolved limit, not a hard-coded 50",
          "[compliance][rest][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFragmentYaml);
    REQUIRE(frag.has_value());
    REQUIRE(store.create_policy(make_policy_yaml(frag.value(), "Policy A")).has_value());
    REQUIRE(store.create_policy(make_policy_yaml(frag.value(), "Policy B")).has_value());
    REQUIRE(store.create_policy(make_policy_yaml(frag.value(), "Policy C")).has_value());

    ComplianceHarness h{&store};
    auto res = h.sink.Get("/api/v1/policies?limit=2");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"].size() == 2);
    CHECK(j["pagination"]["page_size"].get<int64_t>() == 2); // NOT the list_json default of 50
}

TEST_CASE("GET /api/v1/policies: a negative limit clamps to 1 rather than binding "
          "unbounded SQL LIMIT (no cap defeat)",
          "[compliance][rest][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFragmentYaml);
    REQUIRE(frag.has_value());
    REQUIRE(store.create_policy(make_policy_yaml(frag.value(), "Policy A")).has_value());
    REQUIRE(store.create_policy(make_policy_yaml(frag.value(), "Policy B")).has_value());

    ComplianceHarness h{&store};
    auto res = h.sink.Get("/api/v1/policies?limit=-5");
    REQUIRE(res);
    REQUIRE(res->status == 200); // clamps, does not 400 and does not defeat the cap
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"].size() == 1);
    CHECK(j["pagination"]["page_size"].get<int64_t>() == 1);
}

TEST_CASE("GET /api/v1/policy-fragments: limit clamps and page_size reflects the "
          "resolved limit",
          "[compliance][rest][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    REQUIRE(store.create_fragment(make_fragment_yaml("Fragment A")).has_value());
    REQUIRE(store.create_fragment(make_fragment_yaml("Fragment B")).has_value());
    REQUIRE(store.create_fragment(make_fragment_yaml("Fragment C")).has_value());

    ComplianceHarness h{&store};
    auto res = h.sink.Get("/api/v1/policy-fragments?limit=1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"].size() == 1);
    CHECK(j["pagination"]["page_size"].get<int64_t>() == 1);
}

// ═════════════════════════════════════════════════════════════════════════
// #4034 follow-up — GET /api/v1/compliance/{id}'s audit-failure posture,
// reclassified from set-and-proceed to fail-closed (503). See that route's
// own comment in compliance_routes.cpp for the full rationale.
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("GET /api/v1/compliance/{id}: audit-persist failure fails CLOSED (503), "
          "no per-agent data served — replaces the old set-and-proceed posture",
          "[compliance][rest][pg][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFragmentYaml);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value(), "Audit Test Policy"));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());

    ComplianceHarness h{&store};
    h.fleet_admitted = true;
    h.audit_ok = false; // simulate a dropped audit row

    auto res = h.sink.Get("/api/v1/compliance/" + pol.value());
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // No per-agent data leaked on the known-audit-failure path.
    CHECK(res->body.find("agent-1") == std::string::npos);

    bool saw_attempt = false;
    for (const auto& c : h.audit_calls)
        if (c.action == "compliance.agent_statuses.view")
            saw_attempt = true;
    CHECK(saw_attempt); // the audit was attempted (and reported failed), not skipped
}

TEST_CASE("GET /api/v1/compliance/{id}: audit succeeds -> 200 with the per-agent list "
          "and a confined summary tally",
          "[compliance][rest][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFragmentYaml);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value(), "Audit Success Policy"));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-2", "non_compliant").has_value());

    ComplianceHarness h{&store};
    h.fleet_admitted = true;
    h.audit_ok = true;

    auto res = h.sink.Get("/api/v1/compliance/" + pol.value());
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["agents"].size() == 2);
    CHECK(j["data"]["summary"]["compliant"].get<int64_t>() == 1);
    CHECK(j["data"]["summary"]["non_compliant"].get<int64_t>() == 1);

    bool saw_success = false;
    for (const auto& c : h.audit_calls)
        if (c.action == "compliance.agent_statuses.view" && c.result == "success")
            saw_success = true;
    CHECK(saw_success);
}
