/**
 * test_rest_tag_routes.cpp -- route-level regression tests for the REST v1
 * tag-mutation surface (PUT /api/v1/tags, DELETE /api/v1/tags/{id}/{key}) after
 * the CDX-03 / CDX-R4-02 / B4 hardening. These dispatch synthesized requests
 * through the captured route closures against an in-process TestRouteSink
 * (same pattern as test_rest_api_tokens.cpp), so they prove the LAMBDA WIRING
 * -- authenticate-first, scoped-gate-as-sole-authorization, fail-closed-when-
 * unwired -- not just the shared require_scoped_permission logic the MCP twin
 * already covers (K-05/CDX-R4-04: this route wiring previously had zero tests).
 */

#include "rest_api_v1.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"
#include "test_tag_store_pg_helper.hpp" // PG-backed TagStore (ADR-0050)

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_raii.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// A harness that registers ONLY the tag routes against a TestRouteSink, with a
// real TagStore and injectable auth / scoped-permission behaviour.
struct TagRouteHarness {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    yuzu::test::TagStorePg tag_bundle; // SKIPs the case when no PG DSN (ADR-0050)
    TagStore& tag_store = *tag_bundle;

    // auth: empty session_user => require_auth writes 401 and returns nullopt.
    std::string session_user{"alice"};
    // #3289: empty (default) => not service-scoped. Non-empty simulates a
    // service-scoped token's session for the tag-key mutation guard tests.
    std::string token_scope_service;
    // scope decision the stub returns; when `wire_scope` is false the route is
    // registered with an UNWIRED scoped fn (the fail-closed 500 case).
    bool scope_allow{true};
    bool scope_fn_called{false};
    std::string scoped_target;
    // action/result/target triples, in emission order (governance cmp-F1:
    // the v1 failure branches must leave audit rows).
    std::vector<std::string> audit_events;
    // target_type in the same emission order as audit_events, kept as a
    // parallel vector rather than folded into the string above so existing
    // has_audit()-style assertions don't need to change shape. Added for
    // the #3289 Gate 4/6 hardening round's target_type pin (was "Agent",
    // now "Tag" to match this file's own pre-existing convention).
    std::vector<std::string> audit_target_types;

    explicit TagRouteHarness(bool wire_scope = true) {
        REQUIRE(tag_store.is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (session_user.empty()) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            s.token_scope_service = token_scope_service;
            return s;
        };
        // Global perm_fn is intentionally permissive: after the CDX-03 change the
        // tag routes do NOT call it -- if a regression re-introduced a global
        // pre-gate, these tests would still pass, but the scope-deny case below
        // would then fail (proving the scoped gate is the one in force).
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target, const std::string&) -> bool {
            audit_events.push_back(action + "/" + result + "/" + target);
            audit_target_types.push_back(target_type);
            return true;
        };

        RestApiV1::ScopedPermFn scoped_fn{};
        if (wire_scope) {
            scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                               const std::string&, const std::string&,
                               const std::string& agent_id) -> bool {
                scope_fn_called = true;
                scoped_target = agent_id;
                if (scope_allow)
                    return true;
                res.status = 403;
                return false;
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, &tag_store,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{}, /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr, /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
                            /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, scoped_fn);
    }

    auto put(const std::string& body) {
        return sink.Put("/api/v1/tags", body, "application/json");
    }
    auto del(const std::string& agent, const std::string& key) {
        return sink.Delete("/api/v1/tags/" + agent + "/" + key);
    }
};

const std::string kBody = R"({"agent_id":"agent-B","key":"service","value":"ServiceA"})";

// Typed-read unwrap: asserts the read is not a degrade; absent tag == "".
std::string tag_value(TagStore& s, const std::string& agent, const std::string& key) {
    auto v = s.get_tag(agent, key);
    REQUIRE(v.has_value());
    return v->value_or("");
}

bool has_audit(const std::vector<std::string>& events, const std::string& needle) {
    return std::find(events.begin(), events.end(), needle) != events.end();
}

} // namespace

TEST_CASE("REST PUT /api/v1/tags requires authentication before any store/body work (CDX-R4-02)",
          "[pg][rest][tag][authz]") {
    TagRouteHarness h;
    h.session_user = ""; // no session
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK_FALSE(h.scope_fn_called);
    CHECK(tag_value(h.tag_store, "agent-B", "service").empty()); // no write
}

TEST_CASE("REST PUT /api/v1/tags is denied per-target by the scoped gate (403, no write)",
          "[pg][rest][tag][authz]") {
    TagRouteHarness h;
    h.scope_allow = false;
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.scope_fn_called);
    CHECK(h.scoped_target == "agent-B"); // scoped on the PARSED target
    CHECK(tag_value(h.tag_store, "agent-B", "service").empty());
}

TEST_CASE("REST PUT /api/v1/tags admits an in-scope caller and writes the tag (200)",
          "[pg][rest][tag][authz]") {
    TagRouteHarness h;
    h.scope_allow = true;
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.scope_fn_called);
    CHECK(tag_value(h.tag_store, "agent-B", "service") == "ServiceA");
}

TEST_CASE("REST PUT /api/v1/tags fails CLOSED (500) when the scope gate is unwired (B4)",
          "[pg][rest][tag][authz]") {
    TagRouteHarness h(/*wire_scope=*/false);
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 500); // never a silent global fallback
    CHECK(tag_value(h.tag_store, "agent-B", "service").empty());
}

TEST_CASE("REST DELETE /api/v1/tags admits in-scope and fails closed when unwired",
          "[pg][rest][tag][authz]") {
    SECTION("in-scope delete removes the tag") {
        TagRouteHarness h;
        REQUIRE(h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed").has_value());
        auto res = h.del("agent-B", "service");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.scoped_target == "agent-B");
        CHECK(tag_value(h.tag_store, "agent-B", "service").empty());
    }
    SECTION("unwired scope gate fails closed, tag untouched") {
        TagRouteHarness h(/*wire_scope=*/false);
        REQUIRE(h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed").has_value());
        auto res = h.del("agent-B", "service");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(tag_value(h.tag_store, "agent-B", "service") == "ServiceA"); // not deleted
    }
    SECTION("out-of-scope delete is denied (403), tag untouched") {
        TagRouteHarness h;
        h.scope_allow = false;
        REQUIRE(h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed").has_value());
        auto res = h.del("agent-B", "service");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(tag_value(h.tag_store, "agent-B", "service") == "ServiceA");
    }
}

// ── #3289: service-scoped tokens must not mutate their own confinement tag.
// The scoped gate below (`scope_fn_called`) authorizes a write using the
// PRE-WRITE `service` tag, so it must never be reached for a service-scoped
// session mutating the `service` key — the guard denies first.

TEST_CASE("REST PUT /api/v1/tags denies a service-scoped token writing the "
          "service tag (#3289: 403, no write, no .permission, scope gate "
          "never reached)",
          "[pg][rest][tag][service_scope]") {
    TagRouteHarness h;
    h.token_scope_service = "printers";
    auto res = h.put(kBody); // key="service"
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("service-scoped token may not modify") != std::string::npos);
    CHECK_FALSE(res->body.find(R"("permission")") != std::string::npos);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    CHECK_FALSE(h.scope_fn_called); // ordering pin: the TOCTOU guard runs first
    CHECK(tag_value(h.tag_store, "agent-B", "service").empty());
    CHECK(has_audit(h.audit_events, "tag.set/denied/agent-B:service"));
    // Gate 4/6 hardening round: pin target_type="Tag" — REST's own
    // convention for this event, which auth_routes.cpp's and mcp_server.cpp's
    // #3289 denials were fixed to match (they previously used "Agent").
    REQUIRE_FALSE(h.audit_target_types.empty());
    CHECK(h.audit_target_types.back() == "Tag");
}

TEST_CASE("REST PUT /api/v1/tags service-tag guard is case-insensitive ('Service')",
          "[pg][rest][tag][service_scope]") {
    TagRouteHarness h;
    h.token_scope_service = "printers";
    auto res = h.put(R"({"agent_id":"agent-B","key":"Service","value":"printers"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(h.scope_fn_called);
}

TEST_CASE("REST PUT /api/v1/tags service-tag deny is uniform whether the target "
          "is in or out of the token's own scope (no scope-membership oracle, #3289)",
          "[pg][rest][tag][service_scope]") {
    TagRouteHarness h_out_of_scope;
    h_out_of_scope.token_scope_service = "printers";
    h_out_of_scope.scope_allow = false; // would deny at the scoped gate too
    auto res_out = h_out_of_scope.put(kBody);

    TagRouteHarness h_in_scope;
    h_in_scope.token_scope_service = "printers";
    h_in_scope.scope_allow = true; // would admit at the scoped gate
    auto res_in = h_in_scope.put(kBody);

    REQUIRE(res_out);
    REQUIRE(res_in);
    // Neither reaches the scoped gate, so scope_allow never gets a chance to
    // differentiate the two — the deny fires identically either way.
    CHECK(res_out->status == 403);
    CHECK(res_in->status == 403);
    CHECK(res_out->body.find("service-scoped token may not modify") != std::string::npos);
    CHECK(res_in->body.find("service-scoped token may not modify") != std::string::npos);
    CHECK_FALSE(h_out_of_scope.scope_fn_called);
    CHECK_FALSE(h_in_scope.scope_fn_called);
}

TEST_CASE("REST DELETE /api/v1/tags/{agent}/service denies a service-scoped "
          "token (#3289: tag survives, scope gate never reached)",
          "[pg][rest][tag][service_scope]") {
    TagRouteHarness h;
    REQUIRE(h.tag_store.set_tag("agent-B", "service", "printers", "seed").has_value());
    h.token_scope_service = "printers";
    auto res = h.del("agent-B", "service");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(res->body.find(R"("permission")") != std::string::npos);
    CHECK_FALSE(h.scope_fn_called);
    CHECK(tag_value(h.tag_store, "agent-B", "service") == "printers"); // untouched
    CHECK(has_audit(h.audit_events, "tag.delete/denied/agent-B:service"));
}

TEST_CASE("REST PUT /api/v1/tags admits a service-scoped token writing a "
          "NON-service key on an in-scope agent (#3289 regression: only the "
          "service key is guarded)",
          "[pg][rest][tag][service_scope]") {
    TagRouteHarness h;
    h.token_scope_service = "printers";
    h.scope_allow = true;
    auto res = h.put(R"({"agent_id":"agent-B","key":"location","value":"hq"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.scope_fn_called);
    CHECK(tag_value(h.tag_store, "agent-B", "location") == "hq");
}

TEST_CASE("REST DELETE /api/v1/tags admits a service-scoped token deleting a "
          "NON-service key on an in-scope agent (#3289 regression)",
          "[pg][rest][tag][service_scope]") {
    TagRouteHarness h;
    REQUIRE(h.tag_store.set_tag("agent-B", "location", "hq", "seed").has_value());
    h.token_scope_service = "printers";
    h.scope_allow = true;
    auto res = h.del("agent-B", "location");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.scope_fn_called);
    CHECK(tag_value(h.tag_store, "agent-B", "location").empty());
}

TEST_CASE("REST DELETE /api/v1/tags — a non-service-scoped session deleting "
          "the service tag is unaffected (#3289 regression)",
          "[pg][rest][tag][service_scope]") {
    // Gate 4 happy-path coverage note: the PUT-side sibling below already
    // covered this for writes; DELETE had no equivalent test.
    TagRouteHarness h;
    REQUIRE(h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed").has_value());
    h.scope_allow = true;
    auto res = h.del("agent-B", "service");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.scope_fn_called);
    CHECK(tag_value(h.tag_store, "agent-B", "service").empty());
}

TEST_CASE("REST PUT /api/v1/tags — a non-service-scoped session writing the "
          "service tag is unaffected (#3289 regression)",
          "[pg][rest][tag][service_scope]") {
    // NOTE: the harness registers an empty service_group_fn, so this does
    // NOT exercise ensure_service_management_group's own firing — only that
    // the #3289 guard doesn't block a non-service-scoped write. The
    // management-group side effect has its own coverage in
    // test_rest_api_v1.cpp / the legacy-dashboard tests, not here.
    TagRouteHarness h; // token_scope_service left empty
    h.scope_allow = true;
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.scope_fn_called);
    CHECK(tag_value(h.tag_store, "agent-B", "service") == "ServiceA");
}

// ── Store-degrade classification at the ROUTE layer (governance qa-1: the
// db_error?503:400 split was a live surviving mutant — no route-level test
// drove either polarity — and cmp-F1: the failure branches must audit).

namespace {
void drop_tags_table(const std::string& dsn) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
    REQUIRE(r.ok());
}
} // namespace

TEST_CASE("REST v1 tag routes classify store degrade as 503 (retryable) and audit the failure",
          "[pg][rest][tag][failclosed]") {
    TagRouteHarness h;
    REQUIRE(h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed").has_value());
    drop_tags_table(h.tag_bundle.dsn());

    SECTION("GET /api/v1/tags → 503, never an empty tag map") {
        auto res = h.sink.Get("/api/v1/tags?agent_id=agent-B");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
    }

    SECTION("PUT → 503 with retry_after_ms and a tag.set failure audit") {
        auto res = h.put(kBody);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("tag store unavailable") != std::string::npos);
        CHECK(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
        CHECK(has_audit(h.audit_events, "tag.set/failure/agent-B:service"));
    }

    SECTION("DELETE → 503 (degrade), NOT 404, with a tag.delete failure audit") {
        auto res = h.del("agent-B", "service");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find(R"("retry_after_ms":5000)") != std::string::npos);
        CHECK(has_audit(h.audit_events, "tag.delete/failure/agent-B:service"));
    }
}

TEST_CASE("REST v1 tag routes classify caller errors as 400 (the 503/400 mutant killer)",
          "[pg][rest][tag][failclosed]") {
    TagRouteHarness h; // live store — validation failures must NOT be 503
    auto res = h.put(R"({"agent_id":"agent-B","key":"environment","value":"NotAllowed"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("allowed values") != std::string::npos);
    CHECK(has_audit(h.audit_events, "tag.set/failure/agent-B:environment"));
    // And the not-found DELETE stays 404 (successful read, no such tag).
    auto del = h.del("agent-B", "missing-key");
    REQUIRE(del);
    CHECK(del->status == 404);
    CHECK(has_audit(h.audit_events, "tag.delete/not_found/agent-B:missing-key"));
}
