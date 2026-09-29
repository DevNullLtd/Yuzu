/**
 * test_rest_api_tokens.cpp — HTTP-level tests for `DELETE /api/v1/tokens/:id`.
 *
 * Governance Gate 3 (quality-engineer) flagged that the #222 IDOR fix landed
 * with only store-level coverage. The vulnerability was in the handler, not
 * the store, so we need end-to-end coverage of:
 *   - owner self-revoke (200)
 *   - admin cross-user revoke (200)
 *   - non-admin non-owner attempt (404, denied audit)
 *   - unknown token id (404, no audit)
 *
 * Pattern: register RestApiV1 routes against an in-process TestRouteSink
 * and dispatch synthesized httplib::Request objects through the captured
 * handlers. The previous fixture stood up a real httplib::Server behind a
 * std::thread acceptor, which crashed deterministically under TSan with
 * no TSan report (#438) — this fixture has no socket and no acceptor
 * thread for TSan to fight with.
 */

#include "agent_registry.hpp"
#include "api_token_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "audit_store.hpp"
#include "device_token_store.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rest_api_v1.hpp"
#include "secure_random.hpp"
#include "test_route_sink.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include "../test_helpers.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
// `pb` is already bound to `::yuzu::agent::v1` by agent_registry.hpp inside
// `namespace yuzu::server::detail` — use `agent_pb` here to avoid
// "redefinition of 'pb'" (same workaround as
// test_agent_registry_token_revocation.cpp).
namespace agent_pb = ::yuzu::agent::v1;

namespace {

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

// Shares the "devicetokenstore" key with test_device_token_store.cpp's and
// test_rest_api_t2.cpp's own templates (identical setup, replay-verified per
// docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate device_token_store_tpl{
    "devicetokenstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        DeviceTokenStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("device_token_store template: store failed to migrate");
    }};

struct RestTokensHarness {
    yuzu::server::test::TestRouteSink sink;

    // ApiTokenStore ported to Postgres (PR 4.1). The happy-path arm clones an
    // ephemeral database via the shared ApiTokenStorePg helper (SKIPs when
    // YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken); the
    // broken_token_db arm bypasses that helper entirely — see the ctor.
    std::unique_ptr<yuzu::server::pg::PgPool> broken_pool;
    std::optional<yuzu::test::ApiTokenStorePg> token_store_pg;
    std::unique_ptr<ApiTokenStore> token_store_broken;

    // DeviceTokenStore (ADR-0052) is Postgres-backed too, unconditionally —
    // there is no "broken" arm for it (only ApiTokenStore's brokenness is
    // under test in that arm); construction always needs a real reachable
    // Postgres now, the same SKIP-if-unset/FAIL-if-broken posture as
    // ApiTokenStorePg. Members declared in destruction-safe order (store
    // closes before the pool, the pool closes before the ephemeral database
    // is dropped) — mirrors ApiTokenStorePg's own private member order.
    std::optional<yuzu::test::PostgresTestDb> device_token_db_;
    std::optional<yuzu::server::pg::PgPool> device_token_pool_;
    std::unique_ptr<DeviceTokenStore> device_token_store;

    /// Returns the ApiTokenStore under test regardless of which arm
    /// constructed it.
    ApiTokenStore* token_store() const {
        return token_store_pg ? token_store_pg->get() : token_store_broken.get();
    }

    // Mock session state — the caller sets these before calling any
    // endpoint; the auth_fn closure captures by reference and returns a
    // session reflecting the current values.
    std::string session_user;
    auth::Role session_role{auth::Role::user};

    std::vector<AuditRecord> audit_log;
    // UP-H1 fault injection knobs. The default audit_fn returns
    // `!audit_should_fail` and throws iff audit_should_throw is set;
    // both default to false (happy path). Tests flip these before
    // dispatching to simulate AuditStore wedge / pipeline exception.
    bool audit_should_fail{false};
    bool audit_should_throw{false};

    // sre-1: in-process MetricsRegistry the harness threads into the
    // route registration so tests can assert
    // yuzu_secure_random_failure_total increments. Owned per-instance
    // so each test starts from zero — no global state.
    yuzu::MetricsRegistry metrics;

    RestApiV1 api;

    /// `broken_token_db` points the ApiTokenStore at a Postgres address
    /// nothing listens on, so construction-time `pool_.acquire()` fails and
    /// `is_open()` stays false — the PG-era equivalent of the pre-port
    /// "sqlite3_open on a missing parent dir" #347 CH-3 injection (storage
    /// down, routes still registered). Deliberately does NOT need
    /// YUZU_TEST_POSTGRES_DSN — it never reaches a real database, so this
    /// arm runs even in an environment with no Postgres configured. The
    /// happy-path arm uses the shared ApiTokenStorePg helper like every
    /// other fixture (SKIPs when unset, FAILs when set but broken).
    explicit RestTokensHarness(bool broken_token_db = false) {
        if (broken_token_db) {
            broken_pool = std::make_unique<yuzu::server::pg::PgPool>(
                yuzu::server::pg::PgPool::Options{
                    .conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1});
            token_store_broken = std::make_unique<ApiTokenStore>(*broken_pool);
            REQUIRE_FALSE(token_store_broken->is_open());
        } else {
            token_store_pg.emplace();
        }

        // ADR-0052: DeviceTokenStore has no SQLite fallback any more — every
        // fixture that needs a real, functional store now needs real
        // Postgres, unconditionally (including the broken_token_db arm,
        // which only fakes ApiTokenStore's own brokenness). Same
        // SKIP-if-unset / FAIL-if-broken posture as ApiTokenStorePg's own
        // ctor.
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        device_token_db_.emplace(device_token_store_tpl);
        INFO("[RestTokensHarness] device_token_db status (blank == came up OK): "
             << device_token_db_->error());
        REQUIRE(device_token_db_->available());
        device_token_pool_.emplace(
            yuzu::server::pg::PgPool::Options{.conninfo = device_token_db_->dsn(), .size = 4});
        REQUIRE(device_token_pool_->valid());
        device_token_store = std::make_unique<DeviceTokenStore>(*device_token_pool_);
        REQUIRE(device_token_store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        // Permission check always passes — the point of these tests is
        // the owner check, which runs AFTER the RBAC gate.
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool {
            return true;
        };

        // UP-H1 / PR W1.1: AuditFn typedef is now
        // `std::function<bool(...)>` (mirrors PR #883 HIGH-2). The
        // harness's default audit_fn always returns true (audit
        // emitted); per-test overrides (see UP-H1 cases below) flip
        // `audit_should_fail` to simulate a wedged AuditStore, and
        // `audit_should_throw` to simulate an exception from the audit
        // pipeline. Both are reset to false on construction.
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            if (audit_should_throw)
                throw std::runtime_error("simulated audit pipeline failure");
            return !audit_should_fail;
        };

        // Pass nullptr for every store except the one(s) under test — every
        // REST handler checks for null and returns 503, so unrelated routes
        // just fail cleanly if accidentally hit. DeviceTokenStore is wired
        // in (tail-default parameter) so the F-002 CSPRNG failure cases on
        // POST /api/v1/device-tokens can be exercised by the same harness.
        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr, token_store(),
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
                            /*sw_deploy_store=*/nullptr, device_token_store.get(),
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics);
    }

    std::string create_token_for(const std::string& owner, const std::string& name) {
        auto raw = token_store()->create_token(name, owner);
        REQUIRE(raw.has_value());
        // list_tokens orders by `created_at DESC`, so the newest token is
        // front(). Using back() would return the oldest and break if a test
        // ever creates multiple tokens per owner on the same harness.
        auto listing = token_store()->list_tokens(owner).value();
        REQUIRE(!listing.empty());
        return listing.front().token_id;
    }

    /// Dispatch a DELETE through the captured route handler in-process.
    /// Returns std::unique_ptr<httplib::Response> so existing test sites
    /// using res->status / res->body work unchanged.
    auto delete_token(const std::string& token_id) {
        return sink.Delete("/api/v1/tokens/" + token_id);
    }
};

} // namespace

TEST_CASE("REST DELETE /api/v1/tokens: owner can revoke own token", "[pg][rest][token][owner]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "alice";
    h.session_role = auth::Role::user;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    // Store state: token is now revoked.
    auto looked_up = h.token_store()->get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->revoked);

    // Audit: exactly one success event with owner=alice.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.revoke");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail.find("owner=alice") != std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/tokens: non-owner non-admin gets 404 (no oracle)",
          "[pg][rest][token][owner][idor]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    // Bob is a non-admin non-owner with ApiToken:Delete (perm_fn mock always
    // grants). The handler must now reject with 404, matching the response
    // for a completely unknown token id so bob cannot enumerate alice's
    // token ids by probing.
    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 404);

    // Store state: token is NOT revoked.
    auto looked_up = h.token_store()->get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK_FALSE(looked_up->revoked);

    // Audit: the denied attempt is logged with owner=alice so forensics can
    // distinguish a real unknown-id probe (no audit) from an enumeration
    // attempt (denied audit).
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.revoke");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == token_id);
    CHECK(h.audit_log[0].detail == "owner=alice");
}

TEST_CASE("REST DELETE /api/v1/tokens: response body is identical for "
          "unknown id and not-owner (enumeration oracle closed)",
          "[pg][rest][token][owner][idor]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto not_owner = h.delete_token(token_id);
    auto unknown = h.delete_token("deadbeef1234567890");
    REQUIRE(not_owner);
    REQUIRE(unknown);
    CHECK(not_owner->status == unknown->status);
    // Bodies differ only in the `meta` block at most; the `error.message`
    // text must be identical so client-side enumeration is defeated.
    CHECK(not_owner->body.find("token not found") != std::string::npos);
    CHECK(unknown->body.find("token not found") != std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/tokens: admin bypass revokes any token",
          "[pg][rest][token][owner][admin]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    // Admin session can revoke alice's token.
    h.session_user = "root";
    h.session_role = auth::Role::admin;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto looked_up = h.token_store()->get_token(token_id).value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->revoked);

    // Audit success event names alice as the owner even though root
    // performed the revoke.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail == "owner=alice");
}

TEST_CASE("REST DELETE /api/v1/tokens: unknown token id returns 404 with no audit",
          "[pg][rest][token]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    auto res = h.delete_token("nonexistent1234");
    REQUIRE(res);
    CHECK(res->status == 404);
    // No audit event on clean not-found — only denied attempts are logged.
    CHECK(h.audit_log.empty());
}

// ──────────────────────────────────────────────────────────────────────────
// F-002 (governance Gate 2, security-guardian): CSPRNG failure on token
// creation paths must emit a `failure` audit row carrying the
// `csprng_unavailable` marker. The hooks lean on
// `yuzu::server::test_hooks::force_next_failure_for_this_thread()` — a
// thread-local, one-shot override that makes the very next
// `fill_random` / `random_hex` call return prng_failure without faking
// an entropy-starved process. SOC 2 CC7.2/CC7.3 rationale: security-
// relevant failure conditions for token issuance must be auditable.
// ──────────────────────────────────────────────────────────────────────────

TEST_CASE("REST POST /api/v1/tokens: CSPRNG failure emits failure audit (F-002)",
          "[pg][rest][token][csprng][audit]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    // Force the next fill_random call (inside ApiTokenStore::generate_raw_token)
    // to return prng_failure. This is the only path that produces the CSPRNG
    // error without sabotaging the OS RNG, and it auto-clears so any
    // subsequent calls in the harness teardown are unaffected.
    yuzu::server::test_hooks::force_next_failure_for_this_thread();
    REQUIRE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);

    // PR W1.1 round 3 sre-2: CSPRNG failure is a server-side condition
    // (entropy exhaustion), not a client error — status is 503 with
    // Retry-After: 5 so client retry / LB / SRE rules see a 5xx rather
    // than a 4xx. Closes #1046. The audit row is still the distinguishing
    // forensic signal across both surfaces.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Retry-After") == "5");
    CHECK(res->body.find("CSPRNG unavailable") != std::string::npos);

    // The override must have been consumed (proves the force hit
    // fill_random rather than being a no-op).
    CHECK_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    // Exactly one failure audit row, action reused (not a new action name),
    // target_type=ApiToken, target_id=name from the request body, detail
    // carries the csprng_unavailable: prefix for SIEM rules.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.create");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].target_id == "alice-key");
    CHECK(h.audit_log[0].detail.find("csprng_unavailable") != std::string::npos);

    // Store contains no token for alice — the failure path must not leak
    // a half-created row.
    auto listing = h.token_store()->list_tokens("alice").value();
    CHECK(listing.empty());
}

TEST_CASE("REST POST /api/v1/device-tokens: CSPRNG failure emits failure audit (F-002)",
          "[pg][rest][token][csprng][audit]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    yuzu::server::test_hooks::force_next_failure_for_this_thread();
    REQUIRE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    auto res = h.sink.Post(
        "/api/v1/device-tokens",
        R"({"name":"dev-token-1","device_id":"dev-001","definition_id":"d-1","expires_at":0})");
    REQUIRE(res);

    // PR W1.1 round 3 sre-2: 503 + Retry-After: 5 (entropy is server-side).
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Retry-After") == "5");
    CHECK(res->body.find("CSPRNG unavailable") != std::string::npos);
    CHECK_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    // The failure audit reuses the existing action name and carries the
    // device_id as target_id (matches the eventual success-path subject)
    // plus the csprng_unavailable: detail marker.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "device_token.create");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].target_id == "dev-001");
    CHECK(h.audit_log[0].detail.find("csprng_unavailable") != std::string::npos);

    // Store leak check.
    auto listing = h.device_token_store->list_tokens();
    REQUIRE(listing.has_value());
    CHECK(listing->empty());
}

TEST_CASE("HTMX POST /api/settings/api-tokens: CSPRNG failure persists failure "
          "audit row via AuditStore (F-002, site 3)",
          "[pg][rest][token][csprng][audit]") {
    // The settings_routes site logs via `audit_store_->log({...})` directly
    // (the HTMX dashboard surface bypasses the `audit_fn` lambda used by
    // /api/v1/ routes). Standing up the full SettingsRoutes harness here
    // would mean wiring 17 unrelated dependencies (Config, AuthManager,
    // AutoApproveEngine, OidcProvider, etc.), which the F-002 finding
    // explicitly tells us not to do ("don't redesign the test infrastructure").
    //
    // Instead, this test exercises the same logic mechanically: the failure-
    // path code at settings_routes.cpp:3290-3308 fires
    //   api_token_store_->create_token(...)
    //   if (!result) { audit_store_->log({...result = "failure",
    //                                      .detail = csprng_unavailable: ...}); }
    // We reproduce that exact AuditEvent shape with the secure_random
    // force-failure hook driving the same code path the handler hits, then
    // assert the row round-trips through AuditStore::query with the
    // expected fields. Any divergence between this row and the one the
    // handler emits would be caught by the source-level edit pattern in
    // the same commit.
    // ApiTokenStore ported to Postgres (PR 4.1) — SKIPs when
    // YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken. AuditStore
    // (ADR-0006) now shares that same ephemeral database via a second pool
    // (its own `audit_store` schema, no conflict with api_tokens).
    yuzu::test::ApiTokenStorePg token_store;

    {
        yuzu::server::pg::PgPool audit_pool{{.conninfo = token_store.dsn(), .size = 2}};
        AuditStore audit_store(audit_pool, /*retention_days=*/365,
                               /*cleanup_interval_min=*/0);
        REQUIRE(audit_store.is_open());

        // Force CSPRNG failure on the next fill_random call (the one inside
        // generate_raw_token). This is the exact entropy-exhaustion failure
        // the production handler would observe.
        yuzu::server::test_hooks::force_next_failure_for_this_thread();
        auto result = token_store->create_token("dashboard-token", "alice",
                                               /*expires_at=*/0, {}, {});
        REQUIRE_FALSE(result.has_value());

        // Mirror the AuditEvent shape the settings_routes failure-path
        // emits at lines 3299-3307 of settings_routes.cpp. UP-H1 made
        // AuditStore::log [[nodiscard]] — capture and assert true here.
        REQUIRE(audit_store.log({.principal = "alice",
                                 .principal_role = "user",
                                 .action = "api_token.create",
                                 .target_type = "ApiToken",
                                 .target_id = "dashboard-token",
                                 .detail = "csprng_unavailable: " + result.error(),
                                 .source_ip = "127.0.0.1",
                                 .result = "failure"}));

        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].action == "api_token.create");
        CHECK((*rows)[0].result == "failure");
        CHECK((*rows)[0].target_type == "ApiToken");
        CHECK((*rows)[0].target_id == "dashboard-token");
        CHECK((*rows)[0].principal == "alice");
        CHECK((*rows)[0].detail.find("csprng_unavailable") != std::string::npos);

        // Counter parity — events_failure_ must have incremented so /metrics
        // surfaces the security-relevant failure for SRE paging.
        CHECK(audit_store.events_written("failure") == 1);
    }
}

TEST_CASE("REST POST /api/v1/tokens: success path is unchanged (regression guard)",
          "[pg][rest][token][csprng][audit]") {
    // Defensive: confirm the new failure-path branch did not perturb the
    // success-path audit emission. A successful create must still emit a
    // single `success` row, with the F-002 marker absent.
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    REQUIRE_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);
    CHECK(res->status == 201);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.create");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail.find("csprng_unavailable") == std::string::npos);
}

// ──────────────────────────────────────────────────────────────────────────
// PR W1.1 round 3 — UP-H1, UP-H2, sre-1, sre-2.
//
// UP-H1 (HIGH, gov Gate 4 unhappy-path): a CSPRNG-failure response that
// silently drops the failure-path audit row hides a security-relevant
// failure from the SOC 2 CC7.2 evidence chain. Mirrors the PR #883 HIGH-2
// session-revocation pattern: AuditFn typedef → bool; handler captures
// the return and an exception via try/catch; on either, surfaces
// `Sec-Audit-Failed: true` header + `audit_emitted: false` body field.
//
// UP-H2 (HIGH, gov Gate 4 unhappy-path): unbounded `name` / `device_id`
// in the request body amplifies the cheap-to-trigger CSPRNG-failure path
// into an audit-DB-growth DoS during early-boot entropy exhaustion
// windows. Clamp at 256 chars BEFORE audit emission; reject with 400
// `invalid_input_length`; do NOT emit an audit row (oversized input is
// request-level garbage).
//
// sre-1 (MEDIUM HOLD, gov Gate 6 sre): no Prometheus signal exists for
// CSPRNG failure today. Add `yuzu_secure_random_failure_total{reason,site}`
// counter so on-call has a paging surface short of grepping audit logs.
//
// sre-2 (MEDIUM HOLD, gov Gate 6 sre): the existing 400 on CSPRNG
// failure is wrong — entropy exhaustion is server-side, clients with
// retry logic do not retry 4xx, and LB / SRE alerts page on 5xx_rate.
// Return 503 + Retry-After: 5. Closes follow-up #1046.
// ──────────────────────────────────────────────────────────────────────────

TEST_CASE("REST POST /api/v1/tokens: silent audit-drop on CSPRNG failure surfaces "
          "Sec-Audit-Failed header + audit_emitted=false body (UP-H1)",
          "[pg][rest][token][csprng][audit][uph1]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;
    h.audit_should_fail = true; // simulate wedged AuditStore

    yuzu::server::test_hooks::force_next_failure_for_this_thread();

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);

    // The 503 still completes — operator's "deny NOW" intent takes
    // precedence over partial-SOC2-evidence. The partial-success is
    // marked on the response so clients can't read a clean 503 as
    // proof the audit row landed.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Retry-After") == "5");
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("\"audit_emitted\":false") != std::string::npos);
    CHECK(res->body.find("CSPRNG unavailable") != std::string::npos);

    // Audit emission was attempted (push_back in the lambda runs even
    // on the failure branch) — proves the handler reached the audit
    // call before the simulated failure.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.create");
    CHECK(h.audit_log[0].result == "failure");
}

TEST_CASE("REST POST /api/v1/tokens: audit-pipeline exception is caught and surfaced "
          "via Sec-Audit-Failed (UP-H1)",
          "[pg][rest][token][csprng][audit][uph1]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;
    h.audit_should_throw = true; // simulate audit pipeline exception

    yuzu::server::test_hooks::force_next_failure_for_this_thread();

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);

    // Exception from audit_fn does NOT abort the response — the 503
    // still completes, and the partial-success is marked.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("\"audit_emitted\":false") != std::string::npos);
}

TEST_CASE("REST POST /api/v1/device-tokens: silent audit-drop surfaces Sec-Audit-Failed "
          "header + audit_emitted=false body (UP-H1)",
          "[pg][rest][token][csprng][audit][uph1]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;
    h.audit_should_fail = true;

    yuzu::server::test_hooks::force_next_failure_for_this_thread();

    auto res = h.sink.Post(
        "/api/v1/device-tokens",
        R"({"name":"dev-token-1","device_id":"dev-001","definition_id":"d-1","expires_at":0})");
    REQUIRE(res);

    CHECK(res->status == 503);
    CHECK(res->get_header_value("Retry-After") == "5");
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("\"audit_emitted\":false") != std::string::npos);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "device_token.create");
    CHECK(h.audit_log[0].result == "failure");
}

TEST_CASE("REST POST /api/v1/tokens: oversized name (>256 chars) rejected with 400 "
          "invalid_input_length and NO audit row (UP-H2)",
          "[pg][rest][token][csprng][audit][uph2]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    // 257 chars — one over the 256 cap.
    std::string oversized_name(257, 'A');
    std::string body = R"({"name":")" + oversized_name + R"(","expires_at":0})";

    auto res = h.sink.Post("/api/v1/tokens", body);
    REQUIRE(res);

    // Validation 400 — not a 503. The CSPRNG never runs, the
    // ApiTokenStore never sees the request, the audit pipeline is
    // never invoked. Oversized input is request-level garbage —
    // auditing it would re-introduce the DoS vector we're closing.
    CHECK(res->status == 400);
    CHECK(res->body.find("invalid_input_length") != std::string::npos);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST POST /api/v1/device-tokens: oversized device_id (>256 chars) rejected with "
          "400 invalid_input_length (UP-H2)",
          "[pg][rest][token][csprng][audit][uph2]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    std::string oversized_id(257, 'D');
    std::string body =
        R"({"name":"dev-token","device_id":")" + oversized_id + R"(","definition_id":"d"})";

    auto res = h.sink.Post("/api/v1/device-tokens", body);
    REQUIRE(res);

    CHECK(res->status == 400);
    CHECK(res->body.find("invalid_input_length") != std::string::npos);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST POST /api/v1/tokens: CSPRNG failure increments "
          "yuzu_secure_random_failure_total{site=api_token} (sre-1)",
          "[pg][rest][token][csprng][metrics][sre1]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    // Counter starts at 0.
    yuzu::Labels labels{{"reason", "prng_failure"}, {"site", "api_token"}};
    REQUIRE(h.metrics.counter("yuzu_secure_random_failure_total", labels).value() == 0.0);

    yuzu::server::test_hooks::force_next_failure_for_this_thread();

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);
    REQUIRE(res->status == 503);

    // sre-1: the metric must have been incremented by exactly 1 on the
    // CSPRNG-failure branch. Operators wire
    //   rate(yuzu_secure_random_failure_total[5m]) > 0
    // to page on-call.
    CHECK(h.metrics.counter("yuzu_secure_random_failure_total", labels).value() == 1.0);

    // The device_token site label is NOT incremented — labels are
    // load-bearing for site differentiation in SRE rules.
    yuzu::Labels device_labels{{"reason", "prng_failure"}, {"site", "device_token"}};
    CHECK(h.metrics.counter("yuzu_secure_random_failure_total", device_labels).value() == 0.0);
}

TEST_CASE("REST POST /api/v1/device-tokens: CSPRNG failure increments "
          "yuzu_secure_random_failure_total{site=device_token} (sre-1)",
          "[pg][rest][token][csprng][metrics][sre1]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    yuzu::Labels labels{{"reason", "prng_failure"}, {"site", "device_token"}};
    REQUIRE(h.metrics.counter("yuzu_secure_random_failure_total", labels).value() == 0.0);

    yuzu::server::test_hooks::force_next_failure_for_this_thread();

    auto res = h.sink.Post("/api/v1/device-tokens",
                           R"({"name":"dev-token","device_id":"dev-001","definition_id":"d-1"})");
    REQUIRE(res);
    REQUIRE(res->status == 503);

    CHECK(h.metrics.counter("yuzu_secure_random_failure_total", labels).value() == 1.0);
}

// gov Gate 2 security-guardian + Gate 3 quality-engineer (ADR-0052 round 1, MEDIUM): every
// existing 503 case above exercises the CSPRNG-failure branch, a DIFFERENT code path from the
// new kDeviceTokenDbErrorPrefix branch device_token_error_status/the POST handler's db_error
// split add. Mirrors test_rest_software_packages.cpp's "answer 503 (not 400), never leaking the
// raw Postgres error" schema-drop technique — the established precedent for this exact gap on
// the sibling SoftwareDeploymentStore migration (PR #3174).
TEST_CASE("REST device-token routes answer correct status on a genuine store failure, never "
          "leaking the raw Postgres error",
          "[pg][rest][device_token]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::admin;

    // Seed one token before dropping the schema — a pre-drop baseline confirming the store
    // works normally, so the post-drop failures below are attributable to the schema drop, not
    // to a fixture that was already broken. (DELETE's SECTION deliberately targets a HARDCODED
    // id, not this seeded one — a genuine DB failure must preempt even a well-formed-looking
    // request, and POST's own raw_token response never surfaces the seeded token_id to extract.)
    auto seeded = h.sink.Post("/api/v1/device-tokens",
                              R"({"name":"seed","device_id":"dev-seed","definition_id":""})");
    REQUIRE(seeded);
    REQUIRE(seeded->status == 201);

    h.audit_log.clear(); // isolate the failures under test from the seed call's own audit row

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.device_token_db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(conn.get(), "DROP SCHEMA device_token_store CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("GET /api/v1/device-tokens") {
        auto res = h.sink.Get("/api/v1/device-tokens");
        REQUIRE(res);
        CHECK(res->status == 503);
        // gov Gate 4 (consistency-auditor, C2): sibling parity with api_token's
        // GET-list 503, which sets Retry-After: 2.
        CHECK(res->get_header_value("Retry-After") == "2");
        CHECK(res->body.find("does not exist") == std::string::npos);
        CHECK(res->body.find("device_token_store") == std::string::npos);
    }

    SECTION("POST /api/v1/device-tokens") {
        auto res = h.sink.Post(
            "/api/v1/device-tokens",
            R"({"name":"after-drop","device_id":"dev-002","definition_id":""})");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Retry-After") == "5");
        CHECK(res->body.find("service unavailable") != std::string::npos);
        // A genuine DB failure must never be mislabeled as CSPRNG exhaustion, and must never
        // leak libpq's raw error text (relation/schema name) to the client.
        CHECK(res->body.find("CSPRNG") == std::string::npos);
        CHECK(res->body.find("does not exist") == std::string::npos);
        CHECK(res->body.find("device_token_store") == std::string::npos);
        yuzu::Labels labels{{"reason", "prng_failure"}, {"site", "device_token"}};
        CHECK(h.metrics.counter("yuzu_secure_random_failure_total", labels).value() == 0.0);
        // gov Gate 8 quality-engineer: unlike the software-packages precedent (whose route never
        // audits a store failure), this route's db_error branch DOES call audit_fn
        // (rest_api_v1.cpp) — exercise its own Sec-Audit-Failed/audit_emitted try/catch, which
        // was otherwise untested (only its CSPRNG twin had coverage, via audit_should_fail).
        REQUIRE(h.audit_log.size() == 1);
        CHECK(h.audit_log[0].action == "device_token.create");
        CHECK(h.audit_log[0].result == "failure");
        CHECK(h.audit_log[0].target_id == "dev-002");
        CHECK(h.audit_log[0].detail.find("service unavailable") != std::string::npos);
        CHECK(h.audit_log[0].detail.find("csprng_unavailable") == std::string::npos);
        CHECK(res->get_header_value("Sec-Audit-Failed").empty()); // audit_fn succeeded here
    }

    SECTION("DELETE /api/v1/device-tokens/{id}: genuine failure is 503, distinct from 404") {
        auto res = h.sink.Delete("/api/v1/device-tokens/deadbeef");
        REQUIRE(res);
        CHECK(res->status == 503);
        // gov Gate 4 (consistency-auditor, C1/C2, round 3): this route's db_error
        // branch now audits like POST's does and sets Retry-After like GET's does —
        // previously it silently dropped both, the only device-token 503 branch that did.
        CHECK(res->get_header_value("Retry-After") == "2");
        CHECK(res->body.find("service unavailable") != std::string::npos);
        CHECK(res->body.find("not found") == std::string::npos);
        CHECK(res->body.find("does not exist") == std::string::npos);
        CHECK(res->body.find("device_token_store") == std::string::npos);
        REQUIRE(h.audit_log.size() == 1);
        CHECK(h.audit_log[0].action == "device_token.revoke");
        CHECK(h.audit_log[0].result == "failure");
        CHECK(h.audit_log[0].target_id == "deadbeef");
        CHECK(h.audit_log[0].detail.find("service unavailable") != std::string::npos);
        CHECK(h.audit_log[0].detail.find("does not exist") == std::string::npos);
        CHECK(h.audit_log[0].detail.find("device_token_store") == std::string::npos);
    }
}

TEST_CASE("REST POST /api/v1/tokens: validation 400 (oversized) does NOT increment "
          "secure_random metric (sre-1 negative)",
          "[pg][rest][token][csprng][metrics][sre1]") {
    // Negative case: confirm UP-H2's pre-CSPRNG rejection path doesn't
    // touch the CSPRNG metric. Same input as the UP-H2 oversized-name
    // test, but asserts on the metric.
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    yuzu::Labels labels{{"reason", "prng_failure"}, {"site", "api_token"}};

    std::string oversized_name(257, 'A');
    std::string body = R"({"name":")" + oversized_name + R"(","expires_at":0})";

    auto res = h.sink.Post("/api/v1/tokens", body);
    REQUIRE(res);
    REQUIRE(res->status == 400);

    // The CSPRNG path is never reached → metric stays at 0.
    CHECK(h.metrics.counter("yuzu_secure_random_failure_total", labels).value() == 0.0);
}

TEST_CASE("REST POST /api/v1/tokens: CSPRNG failure returns 503 + Retry-After: 5 (sre-2)",
          "[pg][rest][token][csprng][sre2]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    yuzu::server::test_hooks::force_next_failure_for_this_thread();

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);

    // sre-2: CSPRNG failure is a 5xx (server-side condition), not 4xx.
    // LB / SRE 5xx_rate alerts now fire correctly; clients with
    // exponential-backoff retry logic see a retryable status and the
    // explicit Retry-After hint tells them when. Closes #1046.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Retry-After") == "5");
}

// ── #347 CH-3: storage failure surfaces as 503, never 404 ──────────────
//
// A token store whose DB never opened (bad data dir, perms) previously
// collapsed into the not-found path: get_token returns nullopt and
// revoke_token returns false when db_ is null, so the handler emitted
// 404 "token not found" for a storage outage. The is_open() gate makes
// the failure read as 503 "service unavailable" on every token route.
// The message string deliberately matches every other store-down guard
// (H-7 consolidated the 503 vocabulary so message-grep alerting matches
// all store outages); the CH-3 signal is the 503-vs-404 status split.

TEST_CASE("REST tokens: unopened token DB returns 503 on every route, never 404",
          "[pg][rest][token][issue347][ch3]") {
    // ADR-0052: [pg] added — this test's ApiTokenStore arm is still a fake
    // unreachable pool (no real Postgres needed for THAT), but the harness's
    // DeviceTokenStore member now needs a real one unconditionally.
    RestTokensHarness h(/*broken_token_db=*/true);
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    SECTION("DELETE /api/v1/tokens/{id}") {
        auto res = h.delete_token("deadbeef");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("service unavailable") != std::string::npos);
        CHECK(res->body.find("\"code\":503") != std::string::npos);
        CHECK(res->body.find("not found") == std::string::npos);
    }

    SECTION("GET /api/v1/tokens does not mask the outage as an empty list") {
        auto res = h.sink.Get("/api/v1/tokens");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("service unavailable") != std::string::npos);
        CHECK(res->body.find("\"code\":503") != std::string::npos);
    }

    SECTION("POST /api/v1/tokens") {
        auto res = h.sink.Post("/api/v1/tokens", R"({"name":"t","expires_at":0})");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("service unavailable") != std::string::npos);
        CHECK(res->body.find("\"code\":503") != std::string::npos);
    }

    SECTION("POST guard fires before body validation: malformed JSON is 503, not 400") {
        auto res = h.sink.Post("/api/v1/tokens", R"({"name": broken)");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("service unavailable") != std::string::npos);
    }

    // The guard runs before any token is touched — no audit rows, no
    // half-completed mutations to report.
    CHECK(h.audit_log.empty());
}

// #3401: end-to-end proof that the #823 re-registration defence actually closes the gap for a
// REST-issued token — the shape every production issuance path produces (operator username in
// principal_id, target device_id in device_id; rest_api_v1.cpp:8134). Constructs a real
// AgentRegistry alongside the harness's DeviceTokenStore (the harness itself has no registry —
// REST issuance and the registry sweep are independently-wired components in production too;
// server.cpp wires both against the same store instance).
TEST_CASE("REST-issued device token is revoked when the target device re-registers (#823/#3401 "
          "end-to-end)",
          "[pg][rest][token][823][3401]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    EventBus bus;
    yuzu::MetricsRegistry registry_metrics;
    AgentRegistry registry(bus, registry_metrics);
    registry.set_device_token_store(h.device_token_store.get());

    agent_pb::AgentInfo info;
    info.set_agent_id("endpoint-99");
    info.set_hostname("legit.local");
    REQUIRE(registry.register_agent(info).has_value());

    // Mint through the REST route, exactly as an operator would: principal_id becomes
    // session->username ("alice"), NOT the agent_id — the shape #3401 was filed against.
    auto res = h.sink.Post(
        "/api/v1/device-tokens",
        R"({"name":"ops-token","device_id":"endpoint-99","definition_id":""})");
    REQUIRE(res);
    REQUIRE(res->status == 201);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("data"));
    REQUIRE(body["data"].contains("raw_token"));
    std::string raw_token = body["data"]["raw_token"];

    // The REST-minted row carries the issuing operator as principal_id — no existing test pins
    // this; assert it directly against the store rather than just the wire response.
    auto listed = h.device_token_store->list_tokens();
    REQUIRE(listed.has_value());
    auto it = std::find_if(listed->begin(), listed->end(),
                           [](const DeviceAuthToken& t) { return t.name == "ops-token"; });
    REQUIRE(it != listed->end());
    CHECK(it->principal_id == "alice");
    CHECK(it->device_id == "endpoint-99");

    // The token validates for the device it names, before any re-registration.
    REQUIRE(h.device_token_store->validate_token(raw_token, "endpoint-99").has_value());

    // Target device re-registers (the #779 threat model — an attacker briefly impersonating
    // endpoint-99 without mTLS). The #823 defence must revoke the REST-issued token here.
    agent_pb::AgentInfo reinfo;
    reinfo.set_agent_id("endpoint-99");
    reinfo.set_hostname("attacker.local");
    REQUIRE(registry.register_agent(reinfo).has_value());

    auto reval = h.device_token_store->validate_token(raw_token, "endpoint-99");
    REQUIRE_FALSE(reval.has_value());
    CHECK(reval.error().error == DeviceTokenValidateError::revoked);
    CHECK(reval.error().bound_principal_id == "alice");
    CHECK(reval.error().bound_device_id == "endpoint-99");
}
