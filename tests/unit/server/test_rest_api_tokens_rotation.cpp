/**
 * test_rest_api_tokens_rotation.cpp — HTTP-level tests for the human
 * self-service token-keyed rotation REST surface (P2 #11, SOC 2 CC6.3):
 *
 *   POST /api/v1/tokens/{id}/rotate
 *   POST /api/v1/tokens/{id}/confirm
 *
 * plus the GET /api/v1/tokens rotation-field extension. The store-level
 * state machine (ApiTokenStore::rotate_token/confirm_token_rotation) is
 * covered by test_api_token_store.cpp; this file exercises the REST gate
 * belt (ApiToken:Write, not Security:Write; store-open guard; auth;
 * deny_engine_session; step-up on every call; owner-vs-nonexistent 404),
 * the audit discipline (one reveal row per rotate success, a denied-owner
 * audit row, a failure row), and the response/serialization shape — the
 * same seam test_rest_api_tokens.cpp pins for DELETE and
 * test_engine_principal_lifecycle.cpp pins for the engine arm's analogous
 * routes, which this route deliberately mirrors on the HUMAN permission
 * axis (design doc §"Human arm" in api_token_store.hpp).
 *
 * Pattern: register RestApiV1 routes against an in-process TestRouteSink
 * and dispatch synthesized httplib::Request objects through the captured
 * handlers (no socket, no acceptor thread — TSan-safe, #438).
 */

#include "api_token_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePgShared
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp" // PgConn/PgResult — UP-11 partial-audit REST regression
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>
#include <libpq-fe.h> // PGconn/PQexec/PQconnectdb — UP-11 partial-audit REST regression

#include "../test_helpers.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct RestTokenRotationHarness {
    yuzu::test::ApiTokenStorePgShared token_store;

    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // Mock session/permission/step-up state — set before each dispatch,
    // same toggle pattern as RestEngineHarness
    // (test_engine_principal_lifecycle.cpp).
    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::user};
    std::string session_principal_kind; // "" (human) by default
    std::string session_auth_source{"local"};
    // Authority-inheritance guard threading (governance Gate 7): the
    // session's OWN mcp_tier/token_scope_service, mirroring the real
    // server-synthesized session (auth_routes.cpp's
    // synthesize_token_session) — empty by default (cookie/JIT-elevated
    // interactive session posture).
    std::string session_mcp_tier;
    std::string session_scope_service;
    bool session_present{true};
    bool perm_allow{true};
    bool step_up_allow{true};

    std::vector<AuditRecord> audit_log;
    // Round-3 review fix: records every (securable, action) pair perm_fn was
    // actually invoked with, so a test can pin ApiToken:Write vs
    // Security:Write rather than the mock silently accepting anything.
    std::vector<std::pair<std::string, std::string>> perm_checks;

    RestTokenRotationHarness() {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            s.principal_kind = session_principal_kind;
            s.auth_source = session_auth_source;
            s.mcp_tier = session_mcp_tier;
            s.token_scope_service = session_scope_service;
            return s;
        };

        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable, const std::string& action) -> bool {
            perm_checks.emplace_back(securable, action);
            if (!perm_allow) {
                res.status = 403;
                return false;
            }
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            return true;
        };

        auto step_up_fn = [this](const httplib::Request&, httplib::Response& res,
                                 const auth::Session&, const std::string&) -> bool {
            if (!step_up_allow) {
                res.status = 401;
                return false;
            }
            return true;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr, token_store.get(),
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, step_up_fn);
    }

    std::string create_token_for(const std::string& owner, const std::string& name,
                                 int64_t expires_at = 0, const std::string& scope_service = {},
                                 const std::string& mcp_tier = {}) {
        auto raw = token_store->create_token(name, owner, expires_at, scope_service, mcp_tier);
        REQUIRE(raw.has_value());
        auto listing = token_store->list_tokens(owner).value();
        // Match by NAME, never `.front()` on `created_at DESC` — created_at
        // is second-resolution, so two tokens minted for the same owner
        // inside one test (e.g. the round-3 two-token overlapping-rotation
        // regression below) can tie, and `.front()` is then whichever the
        // database happens to return first — this is exactly the same
        // "never newest created_at" hazard the production successor lookup
        // (token_rotation_lookup.hpp) exists to avoid, just on the test
        // fixture's own read instead of the route's. Every call site in
        // this file uses a distinct name per harness instance.
        for (const auto& t : listing)
            if (t.name == name)
                return t.token_id;
        FAIL("create_token_for: no token named '" << name << "' found for " << owner);
        return {};
    }

    auto rotate(const std::string& token_id, std::optional<int64_t> overlap_secs = std::nullopt) {
        nlohmann::json body = nlohmann::json::object();
        if (overlap_secs)
            body["overlap_secs"] = *overlap_secs;
        return sink.Post("/api/v1/tokens/" + token_id + "/rotate", body.dump());
    }

    // #3015 proof-of-possession: `secret` defaults to a fixed non-empty
    // placeholder so every EXISTING gate-belt / pre-store-denial call site
    // (403/401/404 tests that don't care what the secret's value is)
    // keeps getting the status it tested for, rather than always landing on
    // the new "secret required" 400 first. Pass the REAL raw successor
    // secret (the preceding rotate() response's "data"."token" field) for
    // any call expected to actually reach and succeed at the store.
    auto confirm(const std::string& token_id,
                 const std::string& secret = "placeholder-secret-value") {
        nlohmann::json body = nlohmann::json::object();
        body["secret"] = secret;
        return sink.Post("/api/v1/tokens/" + token_id + "/confirm", body.dump());
    }

    auto list_tokens() { return sink.Get("/api/v1/tokens"); }
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// Gate belt, in order: ApiToken:Write / store-open / auth / deny_engine_session
// / step-up (every call) / owner-vs-nonexistent 404 / body parsed last.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: 403 without ApiToken:Write",
          "[pg][rest][token][rotation][gate]") {
    RestTokenRotationHarness h;
    h.perm_allow = false;
    auto res = h.rotate("whatever-id");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: 401 without a session",
          "[pg][rest][token][rotation][gate]") {
    RestTokenRotationHarness h;
    h.session_present = false;
    auto res = h.rotate("whatever-id");
    REQUIRE(res);
    CHECK(res->status == 401);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: engine-classed session is denied "
          "(deny_engine_session belt)",
          "[pg][rest][token][rotation][gate]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";
    h.session_principal_kind = "engine";

    auto res = h.rotate(token_id);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("engine principals cannot access this endpoint") != std::string::npos);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.rotate");
    CHECK(h.audit_log[0].result == "denied");

    // Store state unchanged.
    auto looked_up = h.token_store->get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->rotation_group.empty());
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: 401 without step-up",
          "[pg][rest][token][rotation][gate]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";
    h.step_up_allow = false;

    auto res = h.rotate(token_id);
    REQUIRE(res);
    CHECK(res->status == 401);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: gate belt mirrors rotate — "
          "403 no perm, 401 no session, 403 engine-classed, 401 no step-up",
          "[pg][rest][token][rotation][gate]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    SECTION("403 without ApiToken:Write") {
        h.perm_allow = false;
        auto res = h.confirm(token_id);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    SECTION("401 without a session") {
        h.session_present = false;
        auto res = h.confirm(token_id);
        REQUIRE(res);
        CHECK(res->status == 401);
    }
    SECTION("403 engine-classed session") {
        h.session_user = "alice";
        h.session_principal_kind = "engine";
        auto res = h.confirm(token_id);
        REQUIRE(res);
        CHECK(res->status == 403);
        REQUIRE(h.audit_log.size() == 1);
        CHECK(h.audit_log[0].action == "api_token.confirm");
        CHECK(h.audit_log[0].result == "denied");
    }
    SECTION("401 without step-up") {
        h.session_user = "alice";
        h.step_up_allow = false;
        auto res = h.confirm(token_id);
        REQUIRE(res);
        CHECK(res->status == 401);
    }
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: step-up is re-validated on the "
          "SECOND call too (idempotent re-serve is never exempt)",
          "[pg][rest][token][rotation][gate][stepup]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto first = h.rotate(token_id);
    REQUIRE(first);
    CHECK(first->status == 200);

    // Same operator, same grace window -> the store would re-serve the
    // cached secret, but step-up must still be re-checked and must still
    // be able to block the call.
    h.step_up_allow = false;
    auto second = h.rotate(token_id);
    REQUIRE(second);
    CHECK(second->status == 401);
}

// ═══════════════════════════════════════════════════════════════════════════
// Owner-vs-nonexistent 404 belt (mirrors DELETE /api/v1/tokens/{id}), and
// its audit discipline.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: non-owner gets 404 (no oracle), "
          "self-service only — NO admin bypass",
          "[pg][rest][token][rotation][owner][idor]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "bob";
    h.session_role = auth::Role::user;
    auto res = h.rotate(token_id);
    REQUIRE(res);
    CHECK(res->status == 404);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.rotate");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == token_id);
    CHECK(h.audit_log[0].detail == "owner=alice");

    // Store state unchanged.
    auto looked_up = h.token_store->get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->rotation_group.empty());

    // Unlike DELETE, an ADMIN session does NOT bypass this — rotation is
    // self-service only (store header comment, "SELF-SERVICE ONLY").
    h.session_user = "root";
    h.session_role = auth::Role::admin;
    auto admin_res = h.rotate(token_id);
    REQUIRE(admin_res);
    CHECK(admin_res->status == 404);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: response body identical for "
          "unknown id and not-owner (enumeration oracle closed)",
          "[pg][rest][token][rotation][owner][idor]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "bob";

    auto not_owner = h.rotate(token_id);
    auto unknown = h.rotate("deadbeef1234567890");
    REQUIRE(not_owner);
    REQUIRE(unknown);
    CHECK(not_owner->status == unknown->status);
    CHECK(not_owner->body.find("token not found") != std::string::npos);
    CHECK(unknown->body.find("token not found") != std::string::npos);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: unknown token id returns 404 with "
          "no audit",
          "[pg][rest][token][rotation]") {
    RestTokenRotationHarness h;
    h.session_user = "alice";
    auto res = h.rotate("nonexistent1234");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(h.audit_log.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Authority-inheritance guard THREADING (governance Gate 7 CRITICAL fix): a
// store-only test stays green even if this route silently passed empty
// strings instead of the real session tier/scope — that is the exact
// false-green this pair of tests guards against. `RestTokenRotationHarness`'s
// `session_mcp_tier`/`session_scope_service` feed the SAME `auth::Session`
// fields `rest_api_v1.cpp`'s rotate handler reads (`session->mcp_tier`/
// `session->token_scope_service`) and threads into `rotate_token`.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: an operator-tier session is refused "
          "rotating its owner's UNTIERED sibling token — proves the route threads the "
          "REAL session tier, not empty strings",
          "[pg][rest][token][rotation][security]") {
    RestTokenRotationHarness h;
    // Predecessor is untiered/perpetual — the classic full-authority
    // credential the finding traces.
    auto token_id = h.create_token_for("alice", "alices-untiered-key");
    h.session_user = "alice";
    h.session_mcp_tier = "operator"; // caller's OWN authority, distinct from the token's

    auto res = h.rotate(token_id);
    REQUIRE(res);
    // The route's OWN pre-check (existence + ownership) passes here — this
    // IS alice's own token — so the request reaches the store, and the
    // rejection comes back as the STORE's own "no such token to rotate"
    // wording (ClientValidation -> 400), distinct from the route's
    // pre-check "token not found" 404 used for absent/non-owner. If the
    // route passed empty strings instead of the real session tier, this
    // would 200 and hand back a fresh untiered/perpetual successor (the
    // escalation this fix closes).
    CHECK(res->status == 400);
    CHECK(res->body.find("no such token to rotate") != std::string::npos);

    auto looked_up = h.token_store->get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->rotation_group.empty()); // no successor minted
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: an operator-tier session CAN rotate its "
          "own LIKE-TIERED token — the guard admits a genuine tier/scope match",
          "[pg][rest][token][rotation][security]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alices-operator-key", now_epoch() + 86400 * 30,
                                       /*scope_service=*/"", /*mcp_tier=*/"operator");
    h.session_user = "alice";
    h.session_mcp_tier = "operator"; // matches the token's own tier

    auto res = h.rotate(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);
}

// De-escalating direction — DECIDED by #2963 (see
// docs/user-manual/authentication.md "Rotating a Token" and
// docs/auth-architecture.md "Human API-token rotation" for the design
// record): the harness's session tier/scope default to `""`/`""` — the
// cookie/JIT-elevated interactive shape. Before #2963 this direction was
// refused (the guard was bare equality, so an untiered caller could not
// touch a tiered predecessor either, even though it holds a strict
// superset of that token's own authority). The decision: a caller
// presenting NO standing tier/scope at all may now rotate/confirm ANY of
// its own tokens regardless of that token's own tier/scope — a single
// special case, not a general "no broader than" ordering — because the
// successor still inherits the TOKEN's own narrower tier/scope verbatim,
// never the caller's, so nothing is escalated. This is what makes it
// possible to rotate a possibly-compromised MCP-tiered token from the
// dashboard, which could not reach it before. Nothing in this suite
// exercised this direction before the sibling test that preceded this one
// existed — the REST harness's tier/scope default IS untiered, so a route
// that silently passed empty strings for caller_mcp_tier/caller_scope_service
// (rather than the real session authority) would have stayed green on
// every OTHER test in this file.
TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: an UNTIERED (cookie-shaped) session CAN "
          "rotate its own TIERED token — the #2963 full-authority exception, and the "
          "successor inherits the TOKEN's own tier, never the caller's",
          "[pg][rest][token][rotation][security]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alices-tiered-key", now_epoch() + 86400 * 30,
                                       /*scope_service=*/"", /*mcp_tier=*/"operator");
    h.session_user = "alice";
    // h.session_mcp_tier left at its default "" — an untiered/cookie
    // session, distinct from the token's own "operator" tier. This is
    // exactly the #2963 exception's precondition.

    auto res = h.rotate(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    auto successor_id = body["data"]["token_id"].get<std::string>();
    auto successor = h.token_store->get_token(successor_id).value();
    REQUIRE(successor.has_value());
    // Inherits the PREDECESSOR's own tier — the caller's (empty) authority
    // never leaks into the successor.
    CHECK(successor->mcp_tier == "operator");

    auto predecessor = h.token_store->get_token(token_id).value();
    REQUIRE(predecessor.has_value());
    CHECK(predecessor->rotation_group == successor->rotation_group);
    CHECK_FALSE(predecessor->rotation_group.empty()); // successor WAS minted
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: a caller holding SOME non-empty tier is "
          "still refused rotating a DIFFERENT tier — the #2963 exception is narrow, never "
          "a lattice",
          "[pg][rest][token][rotation][security]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alices-supervised-key",
                                       now_epoch() + 86400 * 30,
                                       /*scope_service=*/"", /*mcp_tier=*/"supervised");
    h.session_user = "alice";
    h.session_mcp_tier = "operator"; // non-empty, but NOT "supervised"

    auto res = h.rotate(token_id);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("no such token to rotate") != std::string::npos);

    auto looked_up = h.token_store->get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->rotation_group.empty()); // no successor minted
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: non-owner gets 404 (no oracle), "
          "denied path audited",
          "[pg][rest][token][rotation][owner][idor]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "bob";
    auto res = h.confirm(token_id);
    REQUIRE(res);
    CHECK(res->status == 404);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.confirm");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail == "owner=alice");
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: a non-owner presenting the CORRECT "
          "secret still gets 404 — no cross-owner secret oracle (#3015)",
          "[pg][rest][token][rotation][owner][idor][pop]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto rotate_res = h.rotate(token_id);
    REQUIRE(rotate_res);
    auto rotate_data = nlohmann::json::parse(rotate_res->body)["data"];
    auto successor_id = rotate_data["token_id"].get<std::string>();
    auto secret = rotate_data["token"].get<std::string>();

    // bob is not alice, but somehow holds alice's REAL raw secret (e.g.
    // observed in transit) — the ownership check must still win, and the
    // outcome must be byte-identical to presenting no/a wrong secret.
    h.session_user = "bob";
    auto with_secret = h.confirm(successor_id, secret);
    auto without_secret = h.confirm(successor_id);
    REQUIRE(with_secret);
    REQUIRE(without_secret);
    CHECK(with_secret->status == 404);
    CHECK(with_secret->status == without_secret->status);
    // Same message content on both — correlation_id differs per request, so
    // this compares the meaningful text, not a byte-identical body (mirrors
    // the sibling "response body identical for unknown id and not-owner"
    // test above).
    CHECK(with_secret->body.find("token not found") != std::string::npos);
    CHECK(without_secret->body.find("token not found") != std::string::npos);

    // Nothing mutated, and alice's own confirm still works afterward.
    h.session_user = "alice";
    auto ok = h.confirm(successor_id, secret);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

// ═══════════════════════════════════════════════════════════════════════════
// Happy path: rotate -> reveal audit -> successor shape -> confirm ->
// predecessor revoked. successor_expires_at is never accepted from the
// request body (SENIOR RULING — lifetime-neutral rotation).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: owner rotates own token — 200, "
          "reveal audit, no-store headers, successor found structurally",
          "[pg][rest][token][rotation][happy]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto res = h.rotate(token_id, /*overlap_secs=*/86400);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control").find("no-store") != std::string::npos);

    auto body = nlohmann::json::parse(res->body);
    auto data = body["data"];
    REQUIRE(data.contains("token"));
    CHECK(data["token"].get<std::string>().size() > 0);
    auto successor_id = data["token_id"].get<std::string>();
    CHECK(successor_id != token_id);
    CHECK(data.contains("expires_at"));
    CHECK(data.contains("overlap_expires_at"));

    // One reveal audit row, action=api_token.reveal, not folded into the
    // rotate action.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.reveal");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_type == "ApiToken");
    CHECK(h.audit_log[0].target_id == token_id);

    // Store state: successor exists, linked via supersedes_token_id;
    // predecessor is stamped with the SAME rotation_group and an
    // overlap_expires_at, but is NOT yet revoked (still in the overlap
    // window).
    auto succ = h.token_store->get_token(successor_id).value();
    REQUIRE(succ.has_value());
    CHECK(succ->supersedes_token_id == token_id);
    CHECK(succ->token_id == successor_id);

    auto pred = h.token_store->get_token(token_id).value();
    REQUIRE(pred.has_value());
    CHECK_FALSE(pred->revoked);
    CHECK(pred->rotation_group == succ->rotation_group);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: successor inherits the predecessor's "
          "expiry verbatim — successor_expires_at is not accepted from the body",
          "[pg][rest][token][rotation][happy][senior-ruling]") {
    RestTokenRotationHarness h;
    const int64_t predecessor_expiry = now_epoch() + 30LL * 24 * 3600; // 30 days out
    auto token_id = h.create_token_for("alice", "alice-key", predecessor_expiry);
    h.session_user = "alice";

    // Attempt to smuggle a lifetime-extending field in — the handler must
    // never parse/honor it (it isn't even in the OpenAPI schema).
    nlohmann::json body{{"overlap_secs", 86400},
                        {"successor_expires_at", now_epoch() + 3650LL * 24 * 3600}};
    auto res = h.sink.Post("/api/v1/tokens/" + token_id + "/rotate", body.dump());
    REQUIRE(res);
    REQUIRE(res->status == 200);

    auto data = nlohmann::json::parse(res->body)["data"];
    CHECK(data["expires_at"].get<int64_t>() == predecessor_expiry);
}

// ═══════════════════════════════════════════════════════════════════════════
// Round-3 review fixes: the successor lookup must be scoped to the exact
// predecessor being rotated (BLOCKING — reproduced end-to-end against live
// Postgres), overlap_expires_at must describe the predecessor with a real
// value, and overlap_secs must be parsed defensively.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: successor lookup is scoped to the "
          "predecessor being rotated, not any linked row of the principal "
          "(round-3 BLOCKING regression — cross-token secret/id mismatch)",
          "[pg][rest][token][rotation][blocking]") {
    RestTokenRotationHarness h;
    auto token_a = h.create_token_for("alice", "token-a");
    auto token_b = h.create_token_for("alice", "token-b");
    h.session_user = "alice";

    // Rotate A first — alice now has an in-flight rotation group for A.
    auto rotate_a = h.rotate(token_a);
    REQUIRE(rotate_a);
    REQUIRE(rotate_a->status == 200);
    auto successor_a =
        nlohmann::json::parse(rotate_a->body)["data"]["token_id"].get<std::string>();

    // Rotate B while A's rotation is still inside its overlap window — alice
    // now has TWO unrelated in-flight rotation groups simultaneously, which
    // is legal (the <=2-active ceiling is per ROTATION GROUP, never per
    // principal — api_token_store.hpp's "Human arm" design note).
    auto rotate_b = h.rotate(token_b);
    REQUIRE(rotate_b);
    REQUIRE(rotate_b->status == 200);
    auto data_b = nlohmann::json::parse(rotate_b->body)["data"];
    auto successor_b = data_b["token_id"].get<std::string>();
    auto raw_b = data_b["token"].get<std::string>();

    // The BLOCKING bug: an unscoped scan over list_active_for_principal
    // matches "any" linked row — RELIABLY (not deterministically —
    // created_at is bigint SECONDS, so a same-second tie is possible in
    // principle; measured stable 8/8 against live Postgres) A's successor
    // here, since it was minted first — even though B is the token actually
    // rotated.
    CHECK(successor_b != successor_a);

    // Ground truth #1: ask the store directly which token B's response
    // should have described.
    auto b_row = h.token_store->get_token(successor_b).value();
    REQUIRE(b_row.has_value());
    CHECK(b_row->supersedes_token_id == token_b);

    // Ground truth #2 — the half the id-only check above doesn't cover: the
    // RAW SECRET the response actually returned must authenticate as the
    // SAME token_id the response also returned. The bug produced exactly
    // this mismatch (B's raw secret paired with A's successor token_id) —
    // pinning only the id leaves that pairing unverified.
    auto resolved = h.token_store->validate_token(raw_b);
    REQUIRE(resolved.has_value());
    CHECK(resolved->token_id == successor_b);

    // A's rotation is untouched by rotating B.
    auto a_pred = h.token_store->get_token(token_a).value();
    REQUIRE(a_pred.has_value());
    CHECK_FALSE(a_pred->revoked);
    auto a_succ = h.token_store->get_token(successor_a).value();
    REQUIRE(a_succ.has_value());
    CHECK(a_succ->supersedes_token_id == token_a);

    // The exploit path the reviewers reproduced: confirming B's successor id
    // must revoke ONLY B's predecessor. Under the bug, the response to
    // rotate(B) carried B's raw secret paired with A's successor token_id,
    // so confirming that id revoked A while B (the token whose secret the
    // caller actually holds) stayed live and unconfirmed.
    auto confirm_b = h.confirm(successor_b, raw_b);
    REQUIRE(confirm_b);
    REQUIRE(confirm_b->status == 200);

    auto b_pred_after = h.token_store->get_token(token_b).value();
    REQUIRE(b_pred_after.has_value());
    CHECK(b_pred_after->revoked); // B's predecessor is now revoked

    auto a_pred_after = h.token_store->get_token(token_a).value();
    REQUIRE(a_pred_after.has_value());
    CHECK_FALSE(a_pred_after->revoked); // A's predecessor must still be LIVE
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: overlap_expires_at describes the "
          "PREDECESSOR, is non-zero, and matches the store's stamped value "
          "(round-3 review — was structurally always 0, read off the successor row)",
          "[pg][rest][token][rotation]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    const int64_t before = now_epoch();
    auto res = h.rotate(token_id, /*overlap_secs=*/86400);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto data = nlohmann::json::parse(res->body)["data"];
    auto reported = data["overlap_expires_at"].get<int64_t>();

    CHECK(reported > 0);
    CHECK(reported >= before + 86400);
    CHECK(reported <= now_epoch() + 86400 + 5); // small clock-skew tolerance

    // Ground truth: the PREDECESSOR row's own overlap_expires_at column —
    // never the successor's, which the store never stamps.
    auto pred = h.token_store->get_token(token_id).value();
    REQUIRE(pred.has_value());
    CHECK(reported == pred->overlap_expires_at);

    auto succ_id = data["token_id"].get<std::string>();
    auto succ = h.token_store->get_token(succ_id).value();
    REQUIRE(succ.has_value());
    CHECK(succ->overlap_expires_at == 0); // confirms the response is NOT this
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: a committed mint whose successor "
          "read-back fails is audited 'partial', never 'failure' (UP-11) — REST twin of "
          "the MCP regression in test_mcp_server.cpp, rest_api_v1.cpp:2875",
          "[pg][rest][token][rotation]") {
    // UP-11: before this fix, the `!successor.found` branch (successor lookup
    // fails AFTER rotate_token already succeeded and committed) wrote
    // `api_token.rotate|failure` — a compliance record claiming no credential
    // exists when one plainly does. Reproduced deterministically via
    // `test_hook_before_mint_commit_` (same technique as the MCP twin above):
    // it hands the mint's OWN connection, still mid-transaction, right before
    // COMMIT, so poisoning the schema there survives the commit and breaks
    // every later read on that connection without any threading/wall-clock
    // race. This needs a DEDICATED database (ApiTokenStorePg-shaped, built by
    // hand here), NOT the shared-clone RestTokenRotationHarness — a DDL
    // saboteur poisons the shared clone for every later [pg] test in this
    // binary (test_api_token_pg_helper.hpp's own warning on
    // ApiTokenStorePgShared).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    yuzu::server::ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    const auto now = now_epoch();
    REQUIRE(store.create_token("up11-rest-key", "alice", now + 90 * 24 * 3600, "", "")
                .has_value());
    auto listing = store.list_tokens("alice").value();
    REQUIRE(!listing.empty());
    const std::string token_id = listing.front().token_id;

    store.test_hook_before_mint_commit_ = [&](PGconn* conn) {
        pg::PgResult r{PQexec(
            conn, "ALTER TABLE api_token_store.api_tokens RENAME COLUMN name TO up11_rest_gone")};
        REQUIRE(r.ok());
    };

    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;
    std::vector<AuditRecord> audit_log;

    auto auth_fn = [](const httplib::Request&,
                      httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "alice";
        s.role = auth::Role::user;
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [&audit_log](const httplib::Request&, const std::string& action,
                                 const std::string& result, const std::string& target_type,
                                 const std::string& target_id, const std::string& detail) -> bool {
        audit_log.push_back({action, result, target_type, target_id, detail});
        return true;
    };
    auto step_up_fn = [](const httplib::Request&, httplib::Response&, const auth::Session&,
                         const std::string&) -> bool { return true; };

    api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                        /*rbac_store=*/nullptr,
                        /*mgmt_store=*/nullptr, &store,
                        /*quarantine_store=*/nullptr,
                        /*response_store=*/nullptr,
                        /*instruction_store=*/nullptr,
                        /*execution_tracker=*/nullptr,
                        /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr,
                        /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr,
                        /*service_group_fn=*/{},
                        /*tag_push_fn=*/{},
                        /*inventory_store=*/nullptr,
                        /*product_pack_store=*/nullptr,
                        /*sw_deploy_store=*/nullptr,
                        /*device_token_store=*/nullptr,
                        /*license_store=*/nullptr,
                        /*guaranteed_state_store=*/nullptr,
                        /*metrics_registry=*/&metrics,
                        /*session_revoke_fn=*/{},
                        /*execution_event_bus=*/nullptr,
                        /*result_set_store=*/nullptr,
                        /*command_dispatch_fn=*/{}, step_up_fn);

    auto res = sink.Post("/api/v1/tokens/" + token_id + "/rotate", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);

    // THE ASSERTION THIS TEST EXISTS FOR: "partial", never "failure".
    REQUIRE(!audit_log.empty());
    const auto& row = audit_log.back();
    CHECK(row.action == "api_token.rotate");
    CHECK(row.result == "partial");
    CHECK(row.detail.find("successor") != std::string::npos);

    // Ground truth: rotate_token really did mint and commit a live successor
    // — the audit outcome above must match the database, not contradict it.
    // Queried through a SECOND, independent connection (the pool's own
    // connections all carry the renamed schema).
    {
        pg::PgConn side{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(side.get()) == CONNECTION_OK);
        pg::PgResult r{PQexec(side.get(),
                              ("SELECT count(*) FROM api_token_store.api_tokens "
                               "WHERE supersedes_token_id = '" +
                               token_id + "' AND revoked = FALSE")
                                  .c_str())};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "1");
    }
}

TEST_CASE("REST POST /api/v1/tokens/{id}/rotate: overlap_secs of the wrong JSON type "
          "returns a documented 400 (A4 envelope), never an unhandled exception "
          "(round-3 review — body.value<int64_t> throws json::type_error.302)",
          "[pg][rest][token][rotation]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto res = h.sink.Post("/api/v1/tokens/" + token_id + "/rotate", R"({"overlap_secs":"7d"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("overlap_secs must be an integer") != std::string::npos);
    // A4 envelope, not a bare httplib error page.
    CHECK(res->body.find("\"code\":400") != std::string::npos);

    // No rotation happened.
    auto pred = h.token_store->get_token(token_id).value();
    REQUIRE(pred.has_value());
    CHECK(pred->rotation_group.empty());
}

TEST_CASE("REST tokens rotate/confirm: pin ApiToken:Rotate, never Security:Write or "
          "ApiToken:Write (round-4 security finding — a shared op with create/list/revoke "
          "would admit an operator-tier MCP token to POST /api/v1/tokens too; see "
          "mcp_policy.hpp's tier_allows() operator-tier comment)",
          "[pg][rest][token][rotation][gate]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    SECTION("rotate") {
        h.perm_checks.clear();
        auto res = h.rotate(token_id);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        REQUIRE(h.perm_checks.size() == 1);
        CHECK(h.perm_checks[0].first == "ApiToken");
        CHECK(h.perm_checks[0].second == "Rotate");
    }
    SECTION("confirm") {
        auto rotate_res = h.rotate(token_id);
        REQUIRE(rotate_res);
        auto rotate_data = nlohmann::json::parse(rotate_res->body)["data"];
        auto successor_id = rotate_data["token_id"].get<std::string>();
        auto secret = rotate_data["token"].get<std::string>();
        h.perm_checks.clear();
        auto res = h.confirm(successor_id, secret);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        REQUIRE(h.perm_checks.size() == 1);
        CHECK(h.perm_checks[0].first == "ApiToken");
        CHECK(h.perm_checks[0].second == "Rotate");
    }
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: successor id in the path — 200, "
          "predecessor revoked, success audit",
          "[pg][rest][token][rotation][happy]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto rotate_res = h.rotate(token_id);
    REQUIRE(rotate_res);
    REQUIRE(rotate_res->status == 200);
    auto rotate_data = nlohmann::json::parse(rotate_res->body)["data"];
    auto successor_id = rotate_data["token_id"].get<std::string>();
    auto secret = rotate_data["token"].get<std::string>();
    h.audit_log.clear();

    auto confirm_res = h.confirm(successor_id, secret);
    REQUIRE(confirm_res);
    CHECK(confirm_res->status == 200);
    CHECK(nlohmann::json::parse(confirm_res->body)["data"]["confirmed"].get<bool>() == true);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.confirm");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_id == successor_id);

    // Predecessor is now revoked; successor's rotation linkage is cleared
    // by the store's confirm cutover.
    auto pred = h.token_store->get_token(token_id).value();
    REQUIRE(pred.has_value());
    CHECK(pred->revoked);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: replay after success is a "
          "terminal conflict (409), mapped via the shared classifier",
          "[pg][rest][token][rotation][conflict]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto rotate_res = h.rotate(token_id);
    REQUIRE(rotate_res);
    auto rotate_data = nlohmann::json::parse(rotate_res->body)["data"];
    auto successor_id = rotate_data["token_id"].get<std::string>();
    auto secret = rotate_data["token"].get<std::string>();

    auto first_confirm = h.confirm(successor_id, secret);
    REQUIRE(first_confirm);
    REQUIRE(first_confirm->status == 200);

    // Replay: the pair-state check (already confirmed) fires before PoP, so
    // the placeholder default secret still reaches the intended 409.
    auto replay = h.confirm(successor_id);
    REQUIRE(replay);
    CHECK(replay->status == 409);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: missing/empty secret is a "
          "distinct 400, before the store is ever reached",
          "[pg][rest][token][rotation][pop]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto rotate_res = h.rotate(token_id);
    REQUIRE(rotate_res);
    auto successor_id =
        nlohmann::json::parse(rotate_res->body)["data"]["token_id"].get<std::string>();

    // No "secret" key in the body at all.
    auto missing = h.sink.Post("/api/v1/tokens/" + successor_id + "/confirm", "{}");
    REQUIRE(missing);
    CHECK(missing->status == 400);
    CHECK(missing->body.find("secret required") != std::string::npos);

    // Present but empty.
    auto empty =
        h.sink.Post("/api/v1/tokens/" + successor_id + "/confirm", R"({"secret":""})");
    REQUIRE(empty);
    CHECK(empty->status == 400);
    CHECK(empty->body.find("secret required") != std::string::npos);

    // Nothing mutated — the real secret still confirms afterward.
    auto secret = nlohmann::json::parse(rotate_res->body)["data"]["token"].get<std::string>();
    auto ok = h.confirm(successor_id, secret);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: a WRONG secret is a distinct 403, "
          "never the not-found (404) or missing-secret (400) outcome",
          "[pg][rest][token][rotation][pop]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto rotate_res = h.rotate(token_id);
    REQUIRE(rotate_res);
    auto rotate_data = nlohmann::json::parse(rotate_res->body)["data"];
    auto successor_id = rotate_data["token_id"].get<std::string>();
    auto secret = rotate_data["token"].get<std::string>();

    auto wrong = h.confirm(successor_id, "definitely-not-the-real-secret");
    REQUIRE(wrong);
    CHECK(wrong->status == 403);
    CHECK(wrong->body.find("rotation secret mismatch") != std::string::npos);

    // Nothing mutated — the real secret still confirms afterward.
    auto ok = h.confirm(successor_id, secret);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("REST POST /api/v1/tokens/{id}/confirm: yuzu_api_token_confirm_total{surface=rest} "
          "counts store-reaching calls only, success then a conflict replay",
          "[pg][rest][token][rotation][metrics]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    yuzu::Labels success_labels{{"surface", "rest"}, {"result", "success"}};
    yuzu::Labels conflict_labels{{"surface", "rest"}, {"result", "conflict"}};
    REQUIRE(h.metrics.counter("yuzu_api_token_confirm_total", success_labels).value() == 0.0);
    REQUIRE(h.metrics.counter("yuzu_api_token_confirm_total", conflict_labels).value() == 0.0);

    auto rotate_res = h.rotate(token_id);
    REQUIRE(rotate_res);
    auto rotate_data = nlohmann::json::parse(rotate_res->body)["data"];
    auto successor_id = rotate_data["token_id"].get<std::string>();
    auto secret = rotate_data["token"].get<std::string>();

    // A pre-store denial (non-owner) must NOT touch the counter — same
    // scope contract as the engine confirm route.
    h.session_user = "bob";
    auto denied = h.confirm(successor_id);
    REQUIRE(denied);
    REQUIRE(denied->status == 404);
    CHECK(h.metrics.counter("yuzu_api_token_confirm_total", success_labels).value() == 0.0);

    h.session_user = "alice";
    auto first_confirm = h.confirm(successor_id, secret);
    REQUIRE(first_confirm);
    REQUIRE(first_confirm->status == 200);
    CHECK(h.metrics.counter("yuzu_api_token_confirm_total", success_labels).value() == 1.0);

    auto replay = h.confirm(successor_id);
    REQUIRE(replay);
    REQUIRE(replay->status == 409);
    CHECK(h.metrics.counter("yuzu_api_token_confirm_total", conflict_labels).value() == 1.0);
    // The replay must not have double-counted success.
    CHECK(h.metrics.counter("yuzu_api_token_confirm_total", success_labels).value() == 1.0);
}

TEST_CASE("REST tokens: unopened token DB returns 503 on rotate/confirm, never 404",
          "[rest][token][rotation][issue347][ch3]") {
    // Store construction pointed at a Postgres address nothing listens on —
    // deliberately does NOT need YUZU_TEST_POSTGRES_DSN.
    yuzu::server::pg::PgPool broken_pool{
        yuzu::server::pg::PgPool::Options{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1",
                                          .size = 1}};
    ApiTokenStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    auto auth_fn = [](const httplib::Request&,
                      httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "alice";
        s.role = auth::Role::user;
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };

    api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                        /*rbac_store=*/nullptr,
                        /*mgmt_store=*/nullptr, &broken_store,
                        /*quarantine_store=*/nullptr,
                        /*response_store=*/nullptr,
                        /*instruction_store=*/nullptr,
                        /*execution_tracker=*/nullptr,
                        /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr,
                        /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr,
                        /*service_group_fn=*/{},
                        /*tag_push_fn=*/{},
                        /*inventory_store=*/nullptr,
                        /*product_pack_store=*/nullptr,
                        /*sw_deploy_store=*/nullptr,
                        /*device_token_store=*/nullptr,
                        /*license_store=*/nullptr,
                        /*guaranteed_state_store=*/nullptr,
                        /*metrics_registry=*/&metrics);

    auto rotate_res = sink.Post("/api/v1/tokens/deadbeef/rotate", "{}");
    REQUIRE(rotate_res);
    CHECK(rotate_res->status == 503);
    CHECK(rotate_res->body.find("service unavailable") != std::string::npos);
    CHECK(rotate_res->body.find("not found") == std::string::npos);

    auto confirm_res = sink.Post("/api/v1/tokens/deadbeef/confirm", "{}");
    REQUIRE(confirm_res);
    CHECK(confirm_res->status == 503);
    CHECK(confirm_res->body.find("service unavailable") != std::string::npos);

    // The confirm route's store-open guard IS store-reaching (the store was
    // reached and found closed) — the transient label must be stamped.
    yuzu::Labels transient_labels{{"surface", "rest"}, {"result", "transient"}};
    CHECK(metrics.counter("yuzu_api_token_confirm_total", transient_labels).value() == 1.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /api/v1/tokens — rotation fields.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("REST GET /api/v1/tokens: rotation fields are omitted for a token that "
          "never rotated",
          "[pg][rest][token][rotation][list]") {
    RestTokenRotationHarness h;
    h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto res = h.list_tokens();
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto items = nlohmann::json::parse(res->body)["data"];
    REQUIRE(items.size() == 1);
    CHECK_FALSE(items[0].contains("rotation_group"));
    CHECK_FALSE(items[0].contains("supersedes_token_id"));
    CHECK_FALSE(items[0].contains("overlap_expires_at"));
    CHECK_FALSE(items[0].contains("confirmed_at"));
}

TEST_CASE("REST GET /api/v1/tokens: an in-flight rotation is visible on BOTH "
          "predecessor and successor rows",
          "[pg][rest][token][rotation][list]") {
    RestTokenRotationHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");
    h.session_user = "alice";

    auto rotate_res = h.rotate(token_id);
    REQUIRE(rotate_res);
    REQUIRE(rotate_res->status == 200);
    auto successor_id = nlohmann::json::parse(rotate_res->body)["data"]["token_id"].get<std::string>();

    auto res = h.list_tokens();
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto items = nlohmann::json::parse(res->body)["data"];
    REQUIRE(items.size() == 2);

    bool found_predecessor = false, found_successor = false;
    for (const auto& item : items) {
        auto id = item["token_id"].get<std::string>();
        if (id == token_id) {
            found_predecessor = true;
            REQUIRE(item.contains("rotation_group"));
            CHECK_FALSE(item["rotation_group"].get<std::string>().empty());
            REQUIRE(item.contains("overlap_expires_at"));
            CHECK_FALSE(item.contains("supersedes_token_id"));
        } else if (id == successor_id) {
            found_successor = true;
            REQUIRE(item.contains("supersedes_token_id"));
            CHECK(item["supersedes_token_id"].get<std::string>() == token_id);
            REQUIRE(item.contains("rotation_group"));
        }
    }
    CHECK(found_predecessor);
    CHECK(found_successor);
}
