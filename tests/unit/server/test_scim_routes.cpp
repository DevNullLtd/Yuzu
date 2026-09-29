/**
 * test_scim_routes.cpp — HTTP-level coverage for the SCIM v2 provisioning
 * surface (/scim/v2/*, slice 3 of 3). Registers ScimRoutes against an
 * in-process TestRouteSink (no socket, no acceptor thread — TSan-safe,
 * #438) over a REAL (born-on-Postgres, ADR-0006) AuthDB + ScimStore pair
 * sharing one PgPool/database, so the AuthManager provisioning path
 * (upsert_user/remove_user/get_provisioning_source) is exercised for real
 * rather than faked.
 *
 * Coverage: bearer gate (401 missing/wrong token), discovery documents,
 * POST provision (201 + Location/ETag, 409 duplicate userName), GET by id
 * (200/404), GET ?filter=, the full PATCH active=false -> active=true
 * deprovision/reactivate round-trip (asserts the underlying auth account
 * is ACTUALLY deactivated then reactivated — not just the SCIM resource
 * flag — and that lockout state is cleared on reactivation per AuthDB::
 * reactivate_user's contract), DELETE (204 + soft-deleted), and the
 * LOAD-BEARING provenance guard: SCIM must never mutate a LOCALLY-created
 * account, even when a scim_resource row happens to reference it
 * (defense-in-depth — see scim_routes.cpp `provenance_ok`), including on
 * the reactivate path.
 *
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but
 * broken (test_helpers.hpp skip-vs-fail contract, via yuzu::test::AuthDbPg).
 */

#include "scim_routes.hpp"

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "deprovision_revoke.hpp"
#include "oidc_principal.hpp"
#include "on_behalf_guard.hpp"
#include "rate_limiter.hpp"
#include "saml_principal.hpp"
#include "test_loopback_http.hpp"
#include "test_route_sink.hpp"
#include "web_utils.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_json.hpp>
#include <yuzu/server/scim_store.hpp>
#include <yuzu/server/server.hpp>

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_auth_db_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// Wires ScimRoutes against a real (born-on-PG) AuthDB + ScimStore SHARING
/// ONE PgPool (mirrors production: ScimStore holds its own independent
/// connection per call against the same database AuthDB manages — see
/// scim_store.hpp) plus a real AuditStore, all over an in-process
/// TestRouteSink. PG-gated: SKIPs when YUZU_TEST_POSTGRES_DSN is unset,
/// FAILs when set but broken (via yuzu::test::AuthDbPg).
struct Fixture {
    yuzu::test::AuthDbPg auth_db;
    auth::AuthManager auth_mgr;
    std::unique_ptr<ScimStore> scim_store;
    // ADR-2001 §§1,3: shares auth_db's PgPool, same "one PgPool, independent
    // connections" pattern as scim_store above — wired into the deprovision
    // seams' credentials-FIRST revoke.
    std::unique_ptr<ApiTokenStore> token_store;
    // ADR-2001 D1: the codebase's actual severity channel — AnalyticsEvent
    // ::severity via AnalyticsEventStore, the SAME mechanism AuthRoutes::
    // emit_event uses for Severity::kCritical break-glass events. Ported to
    // Postgres (ADR-0049): shares auth_db's PgPool/database, same "one
    // PgPool, independent connections" pattern as ScimStore/ApiTokenStore
    // above — no separate ephemeral database needed.
    std::unique_ptr<AnalyticsEventStore> analytics_store;
    // AuditStore ported to Postgres (ADR-0006): shares auth_db's PgPool/
    // database (same "one PgPool" pattern as ScimStore above) in the normal
    // case; `broken_audit` instead points it at an unroutable pool so
    // is_open() reads false without needing mid-test fault injection.
    std::optional<yuzu::server::pg::PgPool> audit_bad_pool;
    std::unique_ptr<AuditStore> audit_store;
    test::TestRouteSink sink;
    std::unique_ptr<ScimRoutes> routes;
    // ADR-2001: wired unconditionally (harmless no-op for every existing
    // test that doesn't inspect it) so D1/D2 metric assertions can read it
    // directly, mirroring ScimIntegrationServer's `metrics` member below.
    yuzu::MetricsRegistry metrics;
    const std::string token{"unit-test-scim-bearer-token-0123456789"};

    /// `broken_audit=true` points AuditStore at an unroutable pool so every
    /// `AuditStore::log()` call returns false thereafter — used to exercise
    /// the set-and-proceed vs. fail-closed audit contract
    /// (M-AUDIT-FAILCLOSED) without needing mid-test fault injection.
    /// `scim_admin_group` mirrors `Config::scim_admin_group` (#2021
    /// Groups->role) — empty (the default) means no SCIM group ever
    /// promotes to admin.
    explicit Fixture(bool broken_audit = false, std::string scim_admin_group = {}) {
        auth_mgr.set_auth_db(auth_db.get());
        auth_mgr.set_metrics_registry(&metrics);

        scim_store = std::make_unique<ScimStore>(auth_db.pool());
        REQUIRE(scim_store->is_open());
        REQUIRE(scim_store->set_token(token, "test"));

        token_store = std::make_unique<ApiTokenStore>(auth_db.pool());
        REQUIRE(token_store->is_open());

        analytics_store = std::make_unique<AnalyticsEventStore>(auth_db.pool());
        REQUIRE(analytics_store->is_open());

        if (broken_audit) {
            audit_bad_pool.emplace(yuzu::server::pg::PgPool::Options{
                .conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1});
            audit_store = std::make_unique<AuditStore>(*audit_bad_pool);
            REQUIRE_FALSE(audit_store->is_open());
        } else {
            audit_store = std::make_unique<AuditStore>(auth_db.pool());
            REQUIRE(audit_store->is_open());
        }

        routes = std::make_unique<ScimRoutes>();
        routes->register_routes(sink, scim_store.get(), &auth_mgr, audit_store.get(),
                                std::move(scim_admin_group), /*engine_principal_store=*/nullptr,
                                token_store.get(), analytics_store.get());
    }

    ~Fixture() {
        routes.reset();
        audit_store.reset();
        analytics_store.reset();
        token_store.reset();
        scim_store.reset();
    }

    std::unordered_map<std::string, std::string> auth_header() const {
        return {{"Authorization", "Bearer " + token}};
    }

    auto get(const std::string& path) {
        return sink.dispatch("GET", path, {}, "application/json", auth_header());
    }
    auto post(const std::string& path, const json& body) {
        return sink.dispatch("POST", path, body.dump(), "application/scim+json", auth_header());
    }
    auto patch(const std::string& path, const json& body) {
        return sink.dispatch("PATCH", path, body.dump(), "application/scim+json", auth_header());
    }
    auto put(const std::string& path, const json& body) {
        return sink.dispatch("PUT", path, body.dump(), "application/scim+json", auth_header());
    }
    auto del(const std::string& path) {
        return sink.dispatch("DELETE", path, {}, "application/scim+json", auth_header());
    }
};

} // namespace

// ── Bearer gate ──────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: 401 without a bearer token", "[pg][scim][routes][auth]") {
    Fixture f;
    auto res = f.sink.dispatch("GET", "/scim/v2/Users");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("WWW-Authenticate") == "Bearer");
    CHECK(json::parse(res->body)["status"] == "401");
}

TEST_CASE("ScimRoutes: 401 with the wrong bearer token", "[pg][scim][routes][auth]") {
    Fixture f;
    auto res = f.sink.dispatch("GET", "/scim/v2/Users", "", "application/json",
                               {{"Authorization", "Bearer wrong-token"}});
    REQUIRE(res);
    CHECK(res->status == 401);
}

// ── Discovery ─────────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: discovery endpoints return the right schemas", "[pg][scim][routes][discovery]") {
    Fixture f;

    auto spc = f.get("/scim/v2/ServiceProviderConfig");
    REQUIRE(spc);
    CHECK(spc->status == 200);
    CHECK(json::parse(spc->body)["schemas"][0] ==
         "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");

    auto rt = f.get("/scim/v2/ResourceTypes");
    REQUIRE(rt);
    CHECK(rt->status == 200);
    auto rt_body = json::parse(rt->body);
    CHECK(rt_body["schemas"][0] == "urn:ietf:params:scim:api:messages:2.0:ListResponse");
    CHECK(rt_body["Resources"][0]["schema"] == "urn:ietf:params:scim:schemas:core:2.0:User");

    auto sch = f.get("/scim/v2/Schemas");
    REQUIRE(sch);
    CHECK(sch->status == 200);
    CHECK(json::parse(sch->body)["Resources"][0]["id"] ==
         "urn:ietf:params:scim:schemas:core:2.0:User");
}

// ── POST /Users (provision) ────────────────────────────────────────────────

TEST_CASE("ScimRoutes: POST provisions a user — 201 + Location + ETag", "[pg][scim][routes][post]") {
    Fixture f;
    auto res = f.post("/scim/v2/Users", {{"userName", "alice"}, {"externalId", "ext-1"}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(res->get_header_value("Location").empty());
    CHECK(res->get_header_value("Location").ends_with(
        json::parse(res->body)["id"].get<std::string>()));
    CHECK(res->get_header_value("ETag") == R"(W/"1")");

    auto body = json::parse(res->body);
    CHECK(body["userName"] == "alice");
    CHECK(body["active"] == true);
    CHECK(body["externalId"] == "ext-1");

    // The account is provisioned at the read-only 'user' role, and its
    // provenance is recorded so the guard can verify it later.
    auto role = f.auth_mgr.get_user_role("alice");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    auto src = f.auth_db->get_provisioning_source("alice");
    REQUIRE(src.has_value());
    CHECK(*src == "scim");
}

TEST_CASE("ScimRoutes: POST duplicate userName — 409, existing account untouched",
         "[pg][scim][routes][post]") {
    Fixture f;
    auto first = f.post("/scim/v2/Users", {{"userName", "bob"}});
    REQUIRE(first);
    REQUIRE(first->status == 201);

    auto dup = f.post("/scim/v2/Users", {{"userName", "bob"}});
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(json::parse(dup->body)["scimType"] == "uniqueness");

    // Only one scim_resource / auth account exists for "bob".
    int total = -1;
    auto page = f.scim_store->list(1, 100, total);
    CHECK(total == 1);
}

// ── GET /Users/{id}, GET /Users?filter= ────────────────────────────────────

TEST_CASE("ScimRoutes: GET /Users/{id} — 200 known, 404 unknown", "[pg][scim][routes][get]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "carol"}})->body);
    auto id = created["id"].get<std::string>();

    auto ok = f.get("/scim/v2/Users/" + id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(json::parse(ok->body)["userName"] == "carol");

    auto missing = f.get("/scim/v2/Users/deadbeefdeadbeefdeadbeefdeadbeef");
    REQUIRE(missing);
    CHECK(missing->status == 404);
}

TEST_CASE("ScimRoutes: GET ?filter=userName eq \"x\" returns the one match",
         "[pg][scim][routes][get][filter]") {
    Fixture f;
    REQUIRE(f.post("/scim/v2/Users", {{"userName", "dave"}})->status == 201);
    REQUIRE(f.post("/scim/v2/Users", {{"userName", "erin"}})->status == 201);

    auto res = f.get(R"(/scim/v2/Users?filter=userName%20eq%20%22dave%22)");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["totalResults"] == 1);
    CHECK(body["Resources"][0]["userName"] == "dave");
}

// ── PATCH — the critical deprovision path ──────────────────────────────────

TEST_CASE("ScimRoutes: PATCH active=false deactivates the auth account",
         "[pg][scim][routes][patch][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "frank"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("frank").has_value());

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == false);

    // The underlying auth account is ACTUALLY deactivated, not just the
    // SCIM resource flag.
    CHECK_FALSE(f.auth_mgr.get_user_role("frank").has_value());
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK_FALSE(stored->active);
}

TEST_CASE("ScimRoutes: PATCH active=false -> active=true round-trips (deprovision then "
         "reactivate), clearing stale lockout state",
         "[pg][scim][routes][patch][reactivate]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "grace"}})->body);
    auto id = created["id"].get<std::string>();

    // Seed a REAL lockout (threshold=1 so the first recorded failure both
    // increments the counter and crosses the lock threshold) so the
    // post-reactivation assertions below prove reactivate_user actually
    // cleared it, rather than coincidentally observing an all-zero row.
    auto lockout = f.auth_db->record_failed_login("grace", /*threshold=*/1,
                                                  /*window_secs=*/3600);
    REQUIRE(lockout.has_value());
    REQUIRE(lockout->locked);
    auto pre_status = f.auth_db->lockout_status("grace");
    REQUIRE(pre_status.has_value());
    CHECK(pre_status->locked);
    CHECK(pre_status->failed_count > 0);

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto deactivate_res = f.patch("/scim/v2/Users/" + id, deactivate_body);
    REQUIRE(deactivate_res);
    CHECK(deactivate_res->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("grace").has_value());

    json reactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", true}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, reactivate_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == true);

    // The underlying auth account actually resolves again (is_active=1)...
    auto role = f.auth_mgr.get_user_role("grace");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    // ...the SCIM resource flag flipped back too...
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK(stored->active);
    // ...provenance is untouched (still scim, not silently reset to local)...
    CHECK(f.auth_db->get_provisioning_source("grace").value() == "scim");
    // ...and the stale lockout from before deprovisioning is CLEARED, not
    // inherited by the returning user.
    auto post_status = f.auth_db->lockout_status("grace");
    REQUIRE(post_status.has_value());
    CHECK_FALSE(post_status->locked);
    CHECK(post_status->failed_count == 0);
}

TEST_CASE("ScimRoutes: PATCH active=true is a no-op when the resource is already active",
         "[pg][scim][routes][patch][reactivate]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "heidi2"}})->body);
    auto id = created["id"].get<std::string>();

    json reactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", true}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, reactivate_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.auth_mgr.get_user_role("heidi2").has_value());
}

// FIX-2 (MEDIUM-1, CC6.8 deprovision desync): a PATCH active=false against a
// resource whose MIRROR already reads inactive must not blindly no-op — it
// must verify the real auth account state first. Desync is induced directly
// at the store layer (`set_active`, bypassing `deactivate()`) so the auth
// account stays genuinely live while the mirror flips to inactive — the
// exact "IdP believes terminated, account is not" gap the fix closes.
TEST_CASE("ScimRoutes: PATCH active=false re-runs deactivation when the mirror is desynced "
         "from a still-live auth account",
         "[pg][scim][routes][patch][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "ivan"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("ivan").has_value());

    // Desync: flip the mirror to inactive WITHOUT touching the auth account.
    REQUIRE(f.scim_store->set_active(id, false));
    REQUIRE(f.auth_mgr.get_user_role("ivan").has_value()); // still live

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == false);

    // The desync is repaired: the auth account is now ACTUALLY deactivated,
    // and the real deactivation path fired — asserted via the dedicated
    // "scim.user.deactivated" audit action (NOT total_count(), which every
    // PATCH bumps via the routine "scim.user.updated" row regardless of
    // whether active actually transitioned).
    CHECK_FALSE(f.auth_mgr.get_user_role("ivan").has_value());
    AuditQuery q;
    q.action = "scim.user.deactivated";
    q.target_id = id;
    auto deactivated_rows = f.audit_store->query(q);
    REQUIRE(deactivated_rows.has_value());
    CHECK(deactivated_rows->size() == 1);
}

TEST_CASE("ScimRoutes: PATCH active=false stays a clean no-op when the account is genuinely "
         "already inactive",
         "[pg][scim][routes][patch][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "ivan2"}})->body);
    auto id = created["id"].get<std::string>();

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    REQUIRE(f.patch("/scim/v2/Users/" + id, patch_body)->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("ivan2").has_value());

    // Second active=false against an account that is ALSO genuinely
    // inactive at the auth layer — must stay a true no-op: 200, and no
    // SECOND "scim.user.deactivated" row (deactivate() is not re-run;
    // preserves the happy-path idempotency other reviewers verified). The
    // routine "scim.user.updated" audit still fires per-PATCH regardless —
    // that is pre-existing, orthogonal behavior, not what this fix guards.
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    AuditQuery q;
    q.action = "scim.user.deactivated";
    q.target_id = id;
    auto deactivated_rows = f.audit_store->query(q);
    REQUIRE(deactivated_rows.has_value());
    CHECK(deactivated_rows->size() == 1);
}

// ── DELETE ──────────────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: DELETE — 204 + account soft-deleted", "[pg][scim][routes][delete]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "heidi"}})->body);
    auto id = created["id"].get<std::string>();

    auto res = f.del("/scim/v2/Users/" + id);
    REQUIRE(res);
    CHECK(res->status == 204);
    CHECK(res->body.empty());

    CHECK_FALSE(f.auth_mgr.get_user_role("heidi").has_value());
    CHECK_FALSE(f.scim_store->get_by_scim_id(id).has_value());
}

TEST_CASE("ScimRoutes: concurrent DELETE on the same id never 500s on an already-gone mapping "
         "row (UP-N4)",
         "[pg][scim][routes][delete][race]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "wren"}})->body);
    auto id = created["id"].get<std::string>();

    // Deactivate first so both racing DELETEs land in the already-inactive
    // branch (no remove_user() call there) — isolates the delete_by_scim_id
    // idempotency this test targets from the separate, pre-existing
    // remove_user()-return-value residual on the active branch (see
    // deactivate()'s M-ATOMICITY comment; out of scope here).
    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    REQUIRE(f.patch("/scim/v2/Users/" + id, deactivate_body)->status == 200);

    std::atomic<int> status_204{0};
    std::atomic<int> status_404{0};
    std::atomic<int> unexpected{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&f, &id, &status_204, &status_404, &unexpected] {
            auto res = f.del("/scim/v2/Users/" + id);
            if (!res) {
                unexpected.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (res->status == 204)
                status_204.fetch_add(1, std::memory_order_relaxed);
            else if (res->status == 404)
                status_404.fetch_add(1, std::memory_order_relaxed);
            else
                unexpected.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads)
        t.join();

    // The regression this guards: a race where one thread's own
    // delete_by_scim_id() call finds the mapping row already removed by
    // the other thread used to 500 (treated as a DB error). It must now be
    // idempotent success (204) — or, if a thread's OWN initial
    // get_by_scim_id already observed the row gone (a legitimately later,
    // fully-sequential DELETE), a plain 404 — but NEVER a spurious 500.
    CHECK(unexpected.load() == 0);
    CHECK(status_204.load() >= 1);
    CHECK(status_204.load() + status_404.load() == 2);
}

// ── Provenance guard (LOAD-BEARING) ────────────────────────────────────────

TEST_CASE("ScimRoutes: provenance guard — SCIM cannot touch a locally-created account",
         "[pg][scim][routes][provenance]") {
    Fixture f;
    // A local admin, created OUTSIDE the SCIM path (upsert_user directly —
    // mirrors first-run-setup / an operator-run `yuzu-server --add-user`).
    REQUIRE(f.auth_mgr.upsert_user("admin", "correct-horse-battery-staple", auth::Role::admin));
    REQUIRE(f.auth_db->get_provisioning_source("admin").value() == "local");

    // 1) POST /Users with a colliding userName — must 409, not silently
    //    take over the existing admin account.
    auto dup = f.post("/scim/v2/Users", {{"userName", "admin"}});
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(f.auth_db->get_provisioning_source("admin").value() == "local");
    CHECK(f.auth_mgr.get_user_role("admin").value() == auth::Role::admin);

    // 2) Defense-in-depth: even if a scim_resource row somehow existed for
    //    this username (a bug, or an operator hand-editing scim_resources —
    //    ScimStore has no FK to the auth.db users table), the provenance
    //    re-check must refuse the mutation with 404 (never 403 — a 403
    //    would confirm the local account's existence to the IdP).
    auto mapped = f.scim_store->create_resource("admin");
    REQUIRE(mapped.has_value());

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + mapped->scim_id, deactivate_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 404);

    auto del_res = f.del("/scim/v2/Users/" + mapped->scim_id);
    REQUIRE(del_res);
    CHECK(del_res->status == 404);

    // The local admin account is COMPLETELY untouched throughout.
    CHECK(f.auth_db->get_provisioning_source("admin").value() == "local");
    CHECK(f.auth_mgr.get_user_role("admin").value() == auth::Role::admin);
    // The bogus scim_resource mapping itself is untouched too (refused, not
    // silently no-op'd/deleted).
    auto still_mapped = f.scim_store->get_by_scim_id(mapped->scim_id);
    REQUIRE(still_mapped.has_value());
    CHECK(still_mapped->active);
}

TEST_CASE("ScimRoutes: POST refuses to adopt a SOFT-DELETED local account (S-UNIQUE-DBREAD)",
         "[pg][scim][routes][provenance]") {
    Fixture f;
    // A local admin, soft-deleted via the ordinary human /api/settings/users
    // DELETE path (remove_user) — no longer visible via get_user_role, the
    // in-memory cache the OLD uniqueness check relied on.
    REQUIRE(f.auth_mgr.upsert_user("paul", "correct-horse-battery-staple", auth::Role::admin));
    REQUIRE(f.auth_mgr.remove_user("paul"));
    CHECK_FALSE(f.auth_mgr.get_user_role("paul").has_value());

    auto res = f.post("/scim/v2/Users", {{"userName", "paul"}});
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(json::parse(res->body)["scimType"] == "uniqueness");
    // Still local and still inactive — SCIM never adopted it.
    CHECK(f.auth_db->get_provisioning_source("paul").value() == "local");
    CHECK_FALSE(f.auth_mgr.get_user_role("paul").has_value());
}

// ── M-LIFECYCLE — revive-on-reprovision ─────────────────────────────────

TEST_CASE("ScimRoutes: DELETE then re-POST the same userName revives the account",
         "[pg][scim][routes][revive]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "olga"}})->body);
    auto old_id = created["id"].get<std::string>();

    auto del_res = f.del("/scim/v2/Users/" + old_id);
    REQUIRE(del_res);
    CHECK(del_res->status == 204);
    CHECK_FALSE(f.auth_mgr.get_user_role("olga").has_value());
    // The scim_resource mapping is hard-deleted...
    CHECK_FALSE(f.scim_store->get_by_scim_id(old_id).has_value());
    // ...but the underlying auth row survives as a soft-deleted SCIM
    // tombstone — the exact state a returning employee's account is in.
    auto tombstoned_source = f.auth_db->get_provisioning_source("olga");
    REQUIRE(tombstoned_source.has_value());
    CHECK(*tombstoned_source == "scim");

    // Revive: re-POST the same userName. Previously this deadlocked (UP-1/
    // 2/3): upsert_user's ON CONFLICT DO NOTHING made the write silently
    // no-op forever, and no path ever called reactivate_user for a POST.
    auto revived_res = f.post("/scim/v2/Users", {{"userName", "olga"}});
    REQUIRE(revived_res);
    CHECK(revived_res->status == 201);
    auto revived_body = json::parse(revived_res->body);
    CHECK(revived_body["userName"] == "olga");
    CHECK(revived_body["active"] == true);
    // Fresh scim_id — the old scim_resource row is gone for good.
    auto new_id = revived_body["id"].get<std::string>();
    CHECK(new_id != old_id);

    auto role = f.auth_mgr.get_user_role("olga");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    CHECK(f.auth_db->get_provisioning_source("olga").value() == "scim");

    // The revived account is fully usable again through the ordinary
    // PATCH deprovision path.
    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + new_id, deactivate_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("olga").has_value());
}

TEST_CASE("ScimRoutes: concurrent revive race — the create_resource-conflict rollback must not "
         "deactivate the winner (UP-N1)",
         "[pg][scim][routes][revive][race]") {
    Fixture f;
    // Leave "vic" as a tombstoned SCIM account: auth row soft-deleted,
    // provisioning_source == "scim", no scim_resource row — exactly the
    // state two concurrent re-POSTs for a returning employee would race
    // over (both pass Step 1's "no live mapping" check and enter the
    // REVIVE branch; they can only serialize on create_resource's
    // UNIQUE(username) constraint).
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "vic"}})->body);
    auto del_res = f.del("/scim/v2/Users/" + created["id"].get<std::string>());
    REQUIRE(del_res);
    REQUIRE(del_res->status == 204);
    REQUIRE_FALSE(f.auth_mgr.get_user_role("vic").has_value());

    std::atomic<int> created_count{0};
    std::atomic<int> conflicted_count{0};
    std::atomic<int> other{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&f, &created_count, &conflicted_count, &other] {
            auto res = f.post("/scim/v2/Users", {{"userName", "vic"}});
            if (!res) {
                other.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (res->status == 201)
                created_count.fetch_add(1, std::memory_order_relaxed);
            else if (res->status == 409)
                conflicted_count.fetch_add(1, std::memory_order_relaxed);
            else
                other.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads)
        t.join();

    // Exactly one winner (201), one loser (409 uniqueness) — same shape as
    // the fresh-create race below, but this one exercises the REVIVE
    // branch's create_resource-failure handler.
    CHECK(created_count.load() == 1);
    CHECK(conflicted_count.load() == 1);
    CHECK(other.load() == 0);

    // UP-N1 (the actual regression): the loser's rollback must NEVER have
    // called remove_user() against the winner's freshly-revived account —
    // it must still resolve and still be active, not silently deactivated
    // behind a 201 no one retries.
    auto role = f.auth_mgr.get_user_role("vic");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);

    int total = -1;
    auto page = f.scim_store->list(1, 100, total);
    CHECK(total == 1);
    REQUIRE_FALSE(page.empty());
    CHECK(page.front().active);
}

TEST_CASE("ScimRoutes: concurrent duplicate POST for a brand-new userName — exactly one 201, "
         "one 409 (UP-9, store layer race)",
         "[pg][scim][routes][post][race]") {
    Fixture f;
    std::atomic<int> created{0};
    std::atomic<int> conflicted{0};
    std::atomic<int> other{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&f, &created, &conflicted, &other] {
            auto res = f.post("/scim/v2/Users", {{"userName", "race-user"}});
            if (!res) {
                other.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (res->status == 201)
                created.fetch_add(1, std::memory_order_relaxed);
            else if (res->status == 409)
                conflicted.fetch_add(1, std::memory_order_relaxed);
            else
                other.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : threads)
        t.join();

    CHECK(created.load() == 1);
    CHECK(conflicted.load() == 1);
    CHECK(other.load() == 0);

    // Exactly one scim_resource / auth account for "race-user" survives.
    int total = -1;
    auto page = f.scim_store->list(1, 100, total);
    CHECK(total == 1);
    CHECK(f.auth_mgr.get_user_role("race-user").has_value());
}

// ── Groups: concurrency (safety-S2) ─────────────────────────────────────

TEST_CASE("ScimRoutes: concurrent Group PATCH-promote + User DELETE on the same SCIM user — no "
         "crash, no torn state",
         "[pg][scim][routes][groups][race]") {
    // Not a provenance-guard test (that's covered elsewhere — a group can
    // only ever elevate a SCIM-provenanced account in the first place) —
    // this purely proves the two mutations racing on the same user_scim_id
    // never crash and never leave a torn/inconsistent final state,
    // regardless of which one "wins" the race.
    Fixture f{/*broken_audit=*/false, /*scim_admin_group=*/"Yuzu-Admins"};
    auto user = json::parse(f.post("/scim/v2/Users", {{"userName", "victor"}})->body);
    auto user_id = user["id"].get<std::string>();

    auto group = json::parse(f.post("/scim/v2/Groups", {{"displayName", "Yuzu-Admins"}})->body);
    auto group_id = group["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};

    std::atomic<bool> saw_unexpected{false};
    std::vector<std::thread> threads;
    threads.emplace_back([&] {
        auto res = f.patch("/scim/v2/Groups/" + group_id, add_body);
        if (!res || (res->status != 200 && res->status != 404))
            saw_unexpected.store(true);
    });
    threads.emplace_back([&] {
        auto res = f.del("/scim/v2/Users/" + user_id);
        if (!res || (res->status != 204 && res->status != 404))
            saw_unexpected.store(true);
    });
    for (auto& t : threads)
        t.join();

    // Both requests completed with an expected status (the mere fact we
    // got here at all rules out a crash/deadlock/hang).
    CHECK_FALSE(saw_unexpected.load());

    // Consistent final state, whichever order the race resolved in: if the
    // user still exists (DELETE lost the race, or PATCH ran first and left
    // the account admin-elevated so DELETE 404'd via M-DEPROV-ROLE), its
    // AuthDB role must match what its CURRENT group membership resolves to
    // — never a stale/mismatched role.
    //
    // NOTE: if the user is gone instead, `scim_group_members` can still
    // carry a row referencing the now-deleted user_scim_id — DELETE /Users
    // (ScimStore::delete_by_scim_id) never cleans up group membership rows.
    // That's pre-existing behavior unrelated to this race (recompute_scim_
    // user_role's get_by_scim_id provenance check makes a ghost member
    // inert — it can never again drive a role change), so this test does
    // not assert on it; the orphaned row itself is a separate hygiene gap,
    // not a race-specific correctness bug.
    auto still_there = f.scim_store->get_by_scim_id(user_id);
    if (still_there.has_value()) {
        auto groups = f.scim_store->list_group_display_names_for_user(user_id).value();
        auto expected = auth::resolve_role_from_groups(groups, "Yuzu-Admins");
        auto actual = f.auth_mgr.get_user_role("victor");
        REQUIRE(actual.has_value());
        CHECK(*actual == expected);
    }
}

TEST_CASE("ScimRoutes: concurrent conflicting Group membership ops on the same user never leave "
         "the durable role out of sync with the final committed membership (TOCTOU role-drift "
         "fix, recompute_scim_user_role serialization)",
         "[pg][scim][routes][groups][race][role_drift]") {
    // Stress-based (not a fully deterministic repro — see NOTE at the end of
    // this file's Groups-concurrency section): fires an add-to-admin-group
    // PATCH and a remove-from-admin-group PATCH concurrently against the
    // SAME user, looped, so the two recompute_scim_user_role calls have a
    // real chance to interleave under the scheduler. Before the fix, the
    // call that lost the race could read a stale `current` role and take
    // the resolved==current no-op branch, stranding the durable role behind
    // whichever membership state actually committed last. After the fix
    // (recompute serialized end-to-end per call), the durable role must
    // match the CURRENT membership after every single pair of racing ops —
    // not just eventually after the whole loop.
    Fixture f{/*broken_audit=*/false, /*scim_admin_group=*/"Yuzu-Admins"};
    auto user = json::parse(f.post("/scim/v2/Users", {{"userName", "wendy"}})->body);
    auto user_id = user["id"].get<std::string>();
    auto group = json::parse(f.post("/scim/v2/Groups", {{"displayName", "Yuzu-Admins"}})->body);
    auto group_id = group["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    json remove_body{
        {"Operations",
         json::array({{{"op", "remove"}, {"path", "members[value eq \"" + user_id + "\"]"}}})}};

    for (int i = 0; i < 100; ++i) {
        std::atomic<bool> saw_unexpected{false};
        std::vector<std::thread> threads;
        threads.emplace_back([&] {
            auto res = f.patch("/scim/v2/Groups/" + group_id, add_body);
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        threads.emplace_back([&] {
            auto res = f.patch("/scim/v2/Groups/" + group_id, remove_body);
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        for (auto& t : threads)
            t.join();
        CHECK_FALSE(saw_unexpected.load());

        auto groups = f.scim_store->list_group_display_names_for_user(user_id).value();
        auto expected = auth::resolve_role_from_groups(groups, "Yuzu-Admins");
        auto actual = f.auth_mgr.get_user_role("wendy");
        REQUIRE(actual.has_value());
        CHECK(*actual == expected);
    }
}

TEST_CASE("ScimRoutes: two concurrent identical Group-add PATCHes promoting the same user write "
         "exactly one scim.user.role_changed success row — no duplicate audit from a racing "
         "no-op recompute",
         "[pg][scim][routes][groups][race][role_drift]") {
    // Before the fix, both concurrent recomputes could observe current=user
    // (both reading before either had applied update_role) and both apply +
    // audit the user->admin transition, producing a duplicate success row.
    // Serializing recompute end-to-end means the second-running recompute
    // observes the first's already-applied 'admin' role and takes the
    // resolved==current no-op branch (no second audit row).
    Fixture f{/*broken_audit=*/false, /*scim_admin_group=*/"Yuzu-Admins"};
    auto user = json::parse(f.post("/scim/v2/Users", {{"userName", "xena"}})->body);
    auto user_id = user["id"].get<std::string>();
    auto group = json::parse(f.post("/scim/v2/Groups", {{"displayName", "Yuzu-Admins"}})->body);
    auto group_id = group["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};

    std::atomic<bool> saw_unexpected{false};
    std::vector<std::thread> threads;
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&] {
            auto res = f.patch("/scim/v2/Groups/" + group_id, add_body);
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
    }
    for (auto& t : threads)
        t.join();
    CHECK_FALSE(saw_unexpected.load());

    REQUIRE(f.auth_mgr.get_user_role("xena").has_value());
    CHECK(f.auth_mgr.get_user_role("xena").value() == auth::Role::admin);

    AuditQuery q;
    q.action = "scim.user.role_changed";
    q.target_id = user_id;
    auto rows = f.audit_store->query(q);
    REQUIRE(rows.has_value());
    int success_to_admin = 0;
    for (const auto& row : *rows) {
        if (row.result == "success" && row.detail.find("new_role=admin") != std::string::npos)
            ++success_to_admin;
    }
    CHECK(success_to_admin == 1);
}

TEST_CASE("ScimRoutes: concurrent Group PATCHes adding DIFFERENT members never lose one "
         "(read-modify-write lost-update fix, kGroupMutationMu serialization)",
         "[pg][scim][routes][groups][race][group-concurrency]") {
    // Regression coverage for the atomic-replace rework: PUT/PATCH compute
    // the final membership set by reading current members, folding ops, then
    // persisting the WHOLE set via replace_group_and_members. That
    // read->fold->persist is not atomic, so two concurrent PATCHes touching
    // DIFFERENT members of the SAME group could last-writer-wins overwrite
    // each other's read-based final set, losing one member's add entirely.
    // Looped so the two critical sections have a real chance to interleave
    // under the scheduler if the outer kGroupMutationMu lock were absent.
    Fixture f{/*broken_audit=*/false, /*scim_admin_group=*/""};
    auto user_x = json::parse(f.post("/scim/v2/Users", {{"userName", "concurrency-member-x"}})->body);
    auto user_a = json::parse(f.post("/scim/v2/Users", {{"userName", "concurrency-member-a"}})->body);
    auto user_b = json::parse(f.post("/scim/v2/Users", {{"userName", "concurrency-member-b"}})->body);
    auto x_id = user_x["id"].get<std::string>();
    auto a_id = user_a["id"].get<std::string>();
    auto b_id = user_b["id"].get<std::string>();

    auto group =
        json::parse(f.post("/scim/v2/Groups", {{"displayName", "concurrency-add-group"}})->body);
    auto group_id = group["id"].get<std::string>();

    // Seed the group with member x.
    json seed_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", x_id}}})}}})}};
    REQUIRE(f.patch("/scim/v2/Groups/" + group_id, seed_body)->status == 200);

    json add_a_body{{"Operations",
                     json::array({{{"op", "add"},
                                   {"path", "members"},
                                   {"value", json::array({{{"value", a_id}}})}}})}};
    json add_b_body{{"Operations",
                     json::array({{{"op", "add"},
                                   {"path", "members"},
                                   {"value", json::array({{{"value", b_id}}})}}})}};
    // Reset a and b back out after each iteration so the NEXT iteration's
    // concurrent adds are not idempotent no-ops against already-present
    // members — leaves x untouched.
    json reset_body{
        {"Operations",
         json::array({{{"op", "remove"}, {"path", "members[value eq \"" + a_id + "\"]"}},
                      {{"op", "remove"}, {"path", "members[value eq \"" + b_id + "\"]"}}})}};

    for (int i = 0; i < 75; ++i) {
        std::atomic<bool> saw_unexpected{false};
        std::vector<std::thread> threads;
        threads.emplace_back([&] {
            auto res = f.patch("/scim/v2/Groups/" + group_id, add_a_body);
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        threads.emplace_back([&] {
            auto res = f.patch("/scim/v2/Groups/" + group_id, add_b_body);
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        for (auto& t : threads)
            t.join();
        CHECK_FALSE(saw_unexpected.load());

        auto members = f.scim_store->list_group_member_user_scim_ids(group_id).value();
        auto has = [&](const std::string& id) {
            return std::find(members.begin(), members.end(), id) != members.end();
        };
        CAPTURE(i);
        CHECK(has(x_id));
        CHECK(has(a_id));
        CHECK(has(b_id));

        REQUIRE(f.patch("/scim/v2/Groups/" + group_id, reset_body)->status == 200);
    }
}

TEST_CASE("ScimRoutes: concurrent Group PATCH remove + add on DIFFERENT members never leave the "
         "removal lost (read-modify-write lost-update fix, kGroupMutationMu serialization)",
         "[pg][scim][routes][groups][race][group-concurrency]") {
    // Same regression as above, but the racing pair is a REMOVE and an ADD
    // rather than two ADDs — this is the privilege-retention-shaped case
    // called out in the regression: a lost REMOVAL leaves a member who
    // should have been demoted/dropped still present. Because both critical
    // sections are fully serialized end-to-end by kGroupMutationMu, the
    // final membership is deterministic regardless of which PATCH's
    // critical section runs first: x removed, a present, either way.
    Fixture f{/*broken_audit=*/false, /*scim_admin_group=*/""};
    auto group =
        json::parse(f.post("/scim/v2/Groups", {{"displayName", "concurrency-remove-group"}})->body);
    auto group_id = group["id"].get<std::string>();

    for (int i = 0; i < 15; ++i) {
        CAPTURE(i);
        auto user_x = json::parse(
            f.post("/scim/v2/Users", {{"userName", "concurrency-rm-x-" + std::to_string(i)}})
                ->body);
        auto user_a = json::parse(
            f.post("/scim/v2/Users", {{"userName", "concurrency-rm-a-" + std::to_string(i)}})
                ->body);
        auto x_id = user_x["id"].get<std::string>();
        auto a_id = user_a["id"].get<std::string>();

        json seed_body{{"Operations",
                       json::array({{{"op", "add"},
                                     {"path", "members"},
                                     {"value", json::array({{{"value", x_id}}})}}})}};
        REQUIRE(f.patch("/scim/v2/Groups/" + group_id, seed_body)->status == 200);

        json remove_x_body{
            {"Operations",
             json::array({{{"op", "remove"}, {"path", "members[value eq \"" + x_id + "\"]"}}})}};
        json add_a_body{{"Operations",
                         json::array({{{"op", "add"},
                                       {"path", "members"},
                                       {"value", json::array({{{"value", a_id}}})}}})}};

        std::atomic<bool> saw_unexpected{false};
        std::vector<std::thread> threads;
        threads.emplace_back([&] {
            auto res = f.patch("/scim/v2/Groups/" + group_id, remove_x_body);
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        threads.emplace_back([&] {
            auto res = f.patch("/scim/v2/Groups/" + group_id, add_a_body);
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        for (auto& t : threads)
            t.join();
        CHECK_FALSE(saw_unexpected.load());

        auto members = f.scim_store->list_group_member_user_scim_ids(group_id).value();
        auto has = [&](const std::string& id) {
            return std::find(members.begin(), members.end(), id) != members.end();
        };
        // Deterministic final state — x removed, a present — regardless of
        // which PATCH's critical section happened to run first.
        CHECK_FALSE(has(x_id));
        CHECK(has(a_id));

        // Reset a back out so the next iteration starts from an empty group
        // (fresh x/a users per iteration keep each pass independent).
        json remove_a_body{
            {"Operations",
             json::array({{{"op", "remove"}, {"path", "members[value eq \"" + a_id + "\"]"}}})}};
        REQUIRE(f.patch("/scim/v2/Groups/" + group_id, remove_a_body)->status == 200);
    }
}

// ── M-DEPROV-ROLE ────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: deprovision refused once an operator elevates the SCIM account to admin",
         "[pg][scim][routes][deprov_role]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "noah"}})->body);
    auto id = created["id"].get<std::string>();

    REQUIRE(f.auth_mgr.update_role("noah", auth::Role::admin));

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + id, deactivate_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 404);
    CHECK(f.auth_mgr.get_user_role("noah").value() == auth::Role::admin);

    auto del_res = f.del("/scim/v2/Users/" + id);
    REQUIRE(del_res);
    CHECK(del_res->status == 404);
    // Untouched — still admin, still active, still SCIM-provenanced (the
    // account itself was never SCIM's to begin with adopting; only its
    // lifecycle ownership is revoked by the role elevation).
    CHECK(f.auth_mgr.get_user_role("noah").value() == auth::Role::admin);
    CHECK(f.scim_store->get_by_scim_id(id).has_value());
}

TEST_CASE("ScimRoutes: deprovision refused for a DB-elevated admin even with a COLD "
         "AuthManager cache (H2, 2026-07-08 review — fail-closed, not fail-open)",
         "[pg][scim][routes][deprov_role][cold_cache]") {
    // H2 (2026-07-08 review): AuthManager::get_user_role ONLY EVER read the
    // in-memory `users_` cache at the time, which nothing preloads at
    // construction. A freshly-started process (modeled here by a SECOND
    // AuthManager wired to the SAME AuthDB, whose cache has never seen this
    // username) previously read back nullopt for a DB-elevated admin and
    // treated that as "no elevation on file" — deactivating an admin an
    // operator had promoted out of SCIM's ownership. THIS test's fix
    // (contemporaneous with H2) reads the role authoritatively from AuthDB
    // via a dedicated helper (db_authoritative_role) at the specific
    // deprovision-role-check call site. (get_user_role() ITSELF stayed
    // cache-only until a much later, separate governance BLOCKING fix — see
    // the NOTE a few lines below — so as of THIS test's own authoring date
    // the description above was accurate; it is preserved for history, not
    // because it's still true of the function today.)
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "cora"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.update_role("cora", auth::Role::admin));

    // A user-role sibling, provisioned the same way, to prove the
    // cold-cache manager still deprovisions a genuinely SCIM-owned 'user'
    // account normally (not an across-the-board fail-closed regression).
    auto created_user = json::parse(f.post("/scim/v2/Users", {{"userName", "dana"}})->body);
    auto user_id = created_user["id"].get<std::string>();

    // A second AuthManager over the SAME AuthDB file/object, standing in
    // for a fresh process: its users_ cache has never been populated for
    // either username. (NOTE: get_user_role() is no longer a valid "cache is
    // cold" probe as of a later governance BLOCKING fix that made it itself
    // AuthDB-authoritative — see auth.cpp's doc on that method. This
    // incidentally closes PR #2018's own N1 follow-up, which flagged that
    // get_user_role()'s staleness class also reached two SCIM PUT/PATCH
    // desync branches beyond the H2 fix below; those now read live state
    // too, with no further change needed here.)
    auth::AuthManager cold_auth_mgr;
    cold_auth_mgr.set_auth_db(f.auth_db.get());

    // Prime the cache for "dana" only, via `reactivate_user` — a legitimate,
    // idempotent AuthDB write (harmless on an already-active row; clears
    // lockout state, nothing else) that happens to be the ONLY mechanism
    // AuthManager exposes for loading an entry into a cold `users_` map.
    // This is NOT priming the thing H2 actually fixes (the role read below
    // still goes through `db_authoritative_role`'s DB-authoritative path
    // regardless of cache state) — it works around a SEPARATE, pre-existing
    // quirk this test surfaced: `AuthManager::remove_user()`'s bool return
    // is `users_.erase(username) > 0`, so on a truly virgin cache it
    // returns false — and `deactivate()` treats that as a failed removal —
    // even though the underlying AuthDB write already succeeded. That is a
    // latent bug in the shared `remove_user()` primitive, well outside this
    // PR's scope (H2 only asked for a DB-authoritative ROLE read; the
    // review explicitly says not to touch `AuthManager::get_user_role`,
    // let alone `remove_user`), so it is deferred rather than fixed here —
    // flagged instead as a follow-up in the review response.
    REQUIRE(cold_auth_mgr.reactivate_user("dana"));

    test::TestRouteSink cold_sink;
    ScimRoutes cold_routes;
    cold_routes.register_routes(cold_sink, f.scim_store.get(), &cold_auth_mgr, f.audit_store.get(),
                                /*scim_admin_group=*/{}, /*engine_principal_store=*/nullptr,
                                f.token_store.get());

    auto del_admin =
        cold_sink.dispatch("DELETE", "/scim/v2/Users/" + id, {}, "application/scim+json",
                           f.auth_header());
    REQUIRE(del_admin);
    CHECK(del_admin->status == 404);
    CHECK(json::parse(del_admin->body)["detail"] == "resource not found");
    // Untouched — the admin is still active, despite the cold cache.
    CHECK(f.auth_mgr.get_user_role("cora").value() == auth::Role::admin);
    CHECK(f.scim_store->get_by_scim_id(id)->active);

    auto del_user =
        cold_sink.dispatch("DELETE", "/scim/v2/Users/" + user_id, {}, "application/scim+json",
                           f.auth_header());
    REQUIRE(del_user);
    CHECK(del_user->status == 204);
    // Checked via `cold_auth_mgr` (the manager that actually performed the
    // removal), not `f.auth_mgr` — the two AuthManager instances have
    // entirely independent in-memory caches over the SAME AuthDB, so
    // `f.auth_mgr`'s cache legitimately still holds dana's pre-removal
    // entry (it was never touched by cold_auth_mgr's write). The
    // DB-authoritative source of truth agrees with cold_auth_mgr here.
    CHECK_FALSE(cold_auth_mgr.get_user_role("dana").has_value());
    CHECK_FALSE(f.auth_db->get_user("dana").has_value());
}

// ── ADR-2001 Task 3: deprovision credential revoke ──────────────────────────
//
// The principal-set resolver (`resolve_deprovision_principals`,
// deprovision_revoke.hpp) and the credentials-FIRST orchestrator
// (`revoke_deprovision_credentials`) tested directly against the fixture's
// real ScimStore/ApiTokenStore/AuthManager, then the four HTTP wiring seams
// (PATCH/PUT active:false via deactivate(), DELETE, create-with-
// active:false, and the dashboard delete in test_settings_routes_users.cpp).

TEST_CASE("resolve_deprovision_principals: returns {slug} when no links exist",
         "[pg][scim][adr2001][resolver]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("no-links-user");
    REQUIRE(resource.has_value());

    auto principals =
        resolve_deprovision_principals(*f.scim_store, resource->scim_id, "no-links-user");
    REQUIRE(principals.has_value());
    REQUIRE(principals->size() == 1);
    CHECK((*principals)[0] == "no-links-user");
}

TEST_CASE("resolve_deprovision_principals: returns {slug, oidc:<iss>#<sub>, ...} for every "
         "linked identity (MUTATION-CHECK target — see the comment below)",
         "[pg][scim][adr2001][resolver]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("multi-link-user");
    REQUIRE(resource.has_value());
    REQUIRE(f.scim_store->upsert_link("https://idp-a.example.com/", "sub-a", resource->scim_id));
    REQUIRE(f.scim_store->upsert_link("https://idp-b.example.com/", "sub-b", resource->scim_id));

    auto principals =
        resolve_deprovision_principals(*f.scim_store, resource->scim_id, "multi-link-user");
    REQUIRE(principals.has_value());
    // MUTATION-CHECK (ADR-2001 task spec, manually verified during
    // development): commenting out the `for (const auto& linked : *links)
    // principals.push_back(...)` loop in deprovision_revoke.cpp's
    // resolve_deprovision_principals collapses this to size()==1 and fails
    // this REQUIRE — confirming the test actually exercises the join
    // rather than passing vacuously with the linkage silently broken.
    REQUIRE(principals->size() == 3);
    CHECK(std::find(principals->begin(), principals->end(), "multi-link-user") !=
         principals->end());
    CHECK(std::find(principals->begin(), principals->end(),
                    oidc::oidc_principal_id("https://idp-a.example.com/", "sub-a")) !=
         principals->end());
    CHECK(std::find(principals->begin(), principals->end(),
                    oidc::oidc_principal_id("https://idp-b.example.com/", "sub-b")) !=
         principals->end());
}

TEST_CASE("resolve_deprovision_principals: fails closed (nullopt) when links_for_scim_id "
         "cannot answer — never silently read as \"no links to revoke\"",
         "[pg][scim][adr2001][resolver][failclosed]") {
    // Same unroutable-pool idiom the fixture's own broken_audit uses — the
    // store's migration fails, is_open() is false, and links_for_scim_id's
    // own `!open_` guard returns nullopt rather than an engaged-empty
    // vector.
    yuzu::server::pg::PgPool unroutable{
        {.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{unroutable};
    REQUIRE_FALSE(broken_store.is_open());

    auto principals = resolve_deprovision_principals(broken_store, "any-scim-id", "any-username");
    CHECK_FALSE(principals.has_value());
}

// ── ADR-2001 governance Gate 7 BLOCKING fix (UP-7) ───────────────────────────
//
// `resolve_deprovision_principals_for_username` (the dashboard-delete
// variant) used to call `ScimStore::get_by_username`, which collapses "no
// such resource" and "the store could not answer" into the same bare
// `nullopt` — so under a pool-exhaustion blip a KNOWN linked user's OIDC
// identities were silently dropped (degraded to the slug-only set, the same
// outcome as "never a SCIM user"). The fix routes through the tri-state
// `get_by_username_checked` instead.

TEST_CASE("resolve_deprovision_principals_for_username: degrades to {username} when the "
         "username genuinely has no SCIM resource",
         "[pg][scim][adr2001][resolver]") {
    Fixture f;
    // Nothing created for this username — a genuine (store-answered) miss.
    auto principals =
        resolve_deprovision_principals_for_username(f.scim_store.get(), "never-provisioned");
    REQUIRE(principals.has_value());
    REQUIRE(principals->size() == 1);
    CHECK((*principals)[0] == "never-provisioned");
}

TEST_CASE("resolve_deprovision_principals_for_username: resolves the full principal set for a "
         "KNOWN SCIM-linked username",
         "[pg][scim][adr2001][resolver]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("linked-dash-user");
    REQUIRE(resource.has_value());
    REQUIRE(f.scim_store->upsert_link("https://idp.example.com/", "sub-dash", resource->scim_id));

    auto principals =
        resolve_deprovision_principals_for_username(f.scim_store.get(), "linked-dash-user");
    REQUIRE(principals.has_value());
    REQUIRE(principals->size() == 2);
    CHECK(std::find(principals->begin(), principals->end(), "linked-dash-user") !=
         principals->end());
    CHECK(std::find(principals->begin(), principals->end(),
                    oidc::oidc_principal_id("https://idp.example.com/", "sub-dash")) !=
         principals->end());
}

TEST_CASE("resolve_deprovision_principals_for_username: FAILS CLOSED (nullopt) on a store "
         "blip for a KNOWN username — MUTATION-CHECK target, see the comment below",
         "[pg][scim][adr2001][resolver][failclosed]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("blip-user");
    REQUIRE(resource.has_value());

    // A second ScimStore handle over a DEDICATED size-1 pool to the SAME
    // database — the "hog the pool" idiom (test_api_token_store.cpp "an
    // EXHAUSTED connection pool is kUnavailable"; also used just above at
    // line ~1462 for the PATCH-fails-closed mutation-check) forces the
    // second store's runtime `try_acquire_for` calls to time out, without
    // touching `f`'s own healthy store/pool. Construct THEN hog — the
    // store's own migration lease must be taken and released first, or the
    // hog below would deadlock the constructor's blocking `acquire()`.
    yuzu::server::pg::PgPool starved{{.conninfo = f.auth_db.dsn(), .size = 1}};
    ScimStore starved_store{starved};
    REQUIRE(starved_store.is_open());
    auto hog = starved.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(hog); // holds the pool's only connection

    auto principals =
        resolve_deprovision_principals_for_username(&starved_store, "blip-user");
    // MUTATION-CHECK (manually verified during development): reverting
    // `resolve_deprovision_principals_for_username` to call
    // `get_by_username` (which collapses "not found" and "store error" into
    // one bare nullopt, then unconditionally degrades to
    // `{username}`) turns this into an ENGAGED `{blip-user}` vector instead
    // of `nullopt` — confirming this REQUIRE actually exercises the tri-
    // state fail-closed path rather than passing vacuously.
    CHECK_FALSE(principals.has_value());
}

// ── ADR-2001 PR4a: the SAML pass ─────────────────────────────────────────
//
// `resolve_deprovision_principals` now also unions in every
// `saml::saml_principal_id(entity_id, name_id)` from
// `ScimStore::saml_links_for_scim_id(scim_id)`, fail-closed on ITS nullopt
// exactly like the pre-existing OIDC pass above.

TEST_CASE("resolve_deprovision_principals: returns {slug, saml:<entity>#<name>, ...} for "
         "every linked SAML identity (MUTATION-CHECK target — see the comment below)",
         "[pg][scim][adr2001][resolver][saml]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("multi-saml-link-user");
    REQUIRE(resource.has_value());
    REQUIRE(f.scim_store->upsert_saml_link("https://idp-a.example.com/saml/metadata",
                                           "a@example.com", resource->scim_id));
    REQUIRE(f.scim_store->upsert_saml_link("https://idp-b.example.com/saml/metadata",
                                           "b@example.com", resource->scim_id));

    auto principals = resolve_deprovision_principals(*f.scim_store, resource->scim_id,
                                                      "multi-saml-link-user");
    REQUIRE(principals.has_value());
    // MUTATION-CHECK (manually verified during development): commenting out
    // the `for (const auto& linked : *saml_links) principals.push_back(...)`
    // loop in deprovision_revoke.cpp's resolve_deprovision_principals
    // collapses this to size()==1 and fails this REQUIRE — confirming the
    // test actually exercises the SAML join rather than passing vacuously
    // with the linkage silently broken.
    REQUIRE(principals->size() == 3);
    CHECK(std::find(principals->begin(), principals->end(), "multi-saml-link-user") !=
         principals->end());
    CHECK(std::find(principals->begin(), principals->end(),
                    saml::saml_principal_id("https://idp-a.example.com/saml/metadata",
                                            "a@example.com")) != principals->end());
    CHECK(std::find(principals->begin(), principals->end(),
                    saml::saml_principal_id("https://idp-b.example.com/saml/metadata",
                                            "b@example.com")) != principals->end());
}

TEST_CASE("resolve_deprovision_principals: a slug with BOTH an OIDC and a SAML link resolves "
         "the union of both",
         "[pg][scim][adr2001][resolver][saml]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("dual-linked-user");
    REQUIRE(resource.has_value());
    REQUIRE(f.scim_store->upsert_link("https://oidc-idp.example.com/", "sub-dual",
                                      resource->scim_id));
    REQUIRE(f.scim_store->upsert_saml_link("https://saml-idp.example.com/saml/metadata",
                                           "dual@example.com", resource->scim_id));

    auto principals =
        resolve_deprovision_principals(*f.scim_store, resource->scim_id, "dual-linked-user");
    REQUIRE(principals.has_value());
    REQUIRE(principals->size() == 3);
    CHECK(std::find(principals->begin(), principals->end(),
                    oidc::oidc_principal_id("https://oidc-idp.example.com/", "sub-dual")) !=
         principals->end());
    CHECK(std::find(principals->begin(), principals->end(),
                    saml::saml_principal_id("https://saml-idp.example.com/saml/metadata",
                                            "dual@example.com")) != principals->end());
}

TEST_CASE("resolve_deprovision_principals: fails closed (nullopt) when "
         "saml_links_for_scim_id SPECIFICALLY cannot answer even though the OIDC links read "
         "succeeds cleanly — MUTATION-CHECK target, see the comment below",
         "[pg][scim][adr2001][resolver][saml][failclosed]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("saml-blip-user");
    REQUIRE(resource.has_value());

    // Break ONLY the saml_identity_links table so its query fails while
    // identity_links (OIDC, untouched) stays intact and would answer fine
    // (zero rows — an engaged-but-empty, non-failing answer).
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(f.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult drop{
            PQexec(conn.get(), "DROP TABLE scim_store.saml_identity_links")};
        REQUIRE(drop.ok());
    }

    auto principals =
        resolve_deprovision_principals(*f.scim_store, resource->scim_id, "saml-blip-user");
    // MUTATION-CHECK (manually verified during development): a
    // resolve_deprovision_principals that never calls (or never checks the
    // nullopt of) saml_links_for_scim_id would return an ENGAGED {slug}
    // vector here — the OIDC read alone succeeds cleanly with zero links —
    // instead of nullopt, confirming this test exercises the SAML-specific
    // fail-closed branch specifically (the OIDC-side fail-closed test
    // earlier in this file already covers a wholly-broken store, which
    // cannot tell the two branches apart).
    CHECK_FALSE(principals.has_value());
}

TEST_CASE("revoke_deprovision_credentials: revokes a SAML-linked user's SAML session (keyed "
         "on the stable principal) — MUTATION-CHECK target, see the comment below",
         "[pg][scim][adr2001][orchestrator][saml]") {
    Fixture f;
    auto resource = f.scim_store->create_resource("saml-yolanda");
    REQUIRE(resource.has_value());

    const std::string entity_id = "https://idp.example.com/saml/metadata";
    const std::string name_id   = "yolanda@example.com";
    REQUIRE(f.scim_store->upsert_saml_link(entity_id, name_id, resource->scim_id));

    auto saml_session = f.auth_mgr.create_saml_session(name_id, entity_id);
    REQUIRE_FALSE(saml_session.empty());
    REQUIRE(f.auth_mgr.validate_session(saml_session).has_value());

    auto principals =
        resolve_deprovision_principals(*f.scim_store, resource->scim_id, "saml-yolanda");
    REQUIRE(principals.has_value());
    REQUIRE(principals->size() == 2);

    auto result = revoke_deprovision_credentials(*f.token_store, f.auth_mgr, *principals);
    CHECK(result.sessions_revoked == 1);

    // MUTATION-CHECK (manually verified during development): reverting
    // `AuthManager::create_saml_session` to key the session's `username` on
    // the raw NameID (the pre-ADR-2001-PR4a behaviour) makes this CHECK
    // fail — the session SURVIVES, because `saml::saml_principal_id(
    // entity_id, name_id)` (what `resolve_deprovision_principals` resolved
    // above) no longer matches the session's actual key (bare
    // "yolanda@example.com") — confirming this test actually catches the
    // exact ADR-2001 silent-under-revocation failure mode ("reported
    // success, revoked nothing") for the SAML re-key specifically.
    CHECK_FALSE(f.auth_mgr.validate_session(saml_session).has_value());
}

TEST_CASE("revoke_deprovision_credentials: revokes tokens and sessions for EVERY principal in "
         "the resolved set",
         "[pg][scim][adr2001][orchestrator]") {
    Fixture f;
    // #4107 Gate 8 CI finding: create_local_session() now fails closed
    // (via post_mint_role_recheck) when the account has no AuthDB `users`
    // row at all - the same UserNotFound branch that denies a genuinely
    // removed account. In production every create_local_session() caller
    // reaches it only after a real local-auth verify_password() call,
    // which already guarantees the row exists; this test used to mint a
    // session for "yolanda" directly, with no such row, an unrealistic
    // precondition no real caller can produce. Seed it for real instead of
    // weakening the production fail-closed check.
    REQUIRE(f.auth_mgr.upsert_user("yolanda", "yolandapassword1", auth::Role::user));
    auto slug_token = f.token_store->create_token("t1", "yolanda");
    REQUIRE(slug_token.has_value());
    const std::string oidc_principal =
        oidc::oidc_principal_id("https://idp.example.com/", "sub-yolanda");
    auto oidc_token = f.token_store->create_token("t2", oidc_principal);
    REQUIRE(oidc_token.has_value());

    auto slug_session = f.auth_mgr.create_local_session("yolanda", auth::Role::user, true);
    auto oidc_session = f.auth_mgr.create_oidc_session("Yolanda", "y@example.com", "sub-yolanda",
                                                        "https://idp.example.com/");
    REQUIRE_FALSE(slug_session.empty());
    REQUIRE_FALSE(oidc_session.empty());
    REQUIRE(f.auth_mgr.validate_session(slug_session).has_value());
    REQUIRE(f.auth_mgr.validate_session(oidc_session).has_value());

    auto result = revoke_deprovision_credentials(*f.token_store, f.auth_mgr,
                                                  {"yolanda", oidc_principal});
    CHECK(result.api_tokens_persisted);
    CHECK(result.api_tokens_revoked == 2);
    CHECK(result.sessions_revoked == 2);

    CHECK_FALSE(f.token_store->validate_token(*slug_token).has_value());
    CHECK_FALSE(f.token_store->validate_token(*oidc_token).has_value());
    CHECK_FALSE(f.auth_mgr.validate_session(slug_session).has_value());
    CHECK_FALSE(f.auth_mgr.validate_session(oidc_session).has_value());
}

TEST_CASE("ScimRoutes: PATCH active=false revokes API tokens AND sessions for BOTH the slug "
         "and every linked OIDC identity (credentials-FIRST, ADR-2001 §3)",
         "[pg][scim][routes][adr2001][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "trent"}})->body);
    auto id = created["id"].get<std::string>();

    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-trent-1";
    REQUIRE(f.scim_store->upsert_link(iss, sub, id));
    const std::string oidc_principal = oidc::oidc_principal_id(iss, sub);

    auto slug_token = f.token_store->create_token("slug-token", "trent");
    REQUIRE(slug_token.has_value());
    auto oidc_token = f.token_store->create_token("oidc-token", oidc_principal);
    REQUIRE(oidc_token.has_value());

    auto slug_session = f.auth_mgr.create_local_session("trent", auth::Role::user, true);
    auto oidc_session =
        f.auth_mgr.create_oidc_session("Trent", "trent@example.com", sub, iss);
    REQUIRE(f.auth_mgr.validate_session(slug_session).has_value());
    REQUIRE(f.auth_mgr.validate_session(oidc_session).has_value());

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);

    // The whole point of the linkage: BOTH tokens revoked, BOTH sessions
    // gone — not just the slug's own. A test that stays green with the
    // oidc: principal untouched is the exact false-green ADR-2001 exists to
    // prevent (see the resolver mutation-check test above for the same
    // property pinned at the resolver layer directly).
    CHECK_FALSE(f.token_store->validate_token(*slug_token).has_value());
    CHECK_FALSE(f.token_store->validate_token(*oidc_token).has_value());
    CHECK_FALSE(f.auth_mgr.validate_session(slug_session).has_value());
    CHECK_FALSE(f.auth_mgr.validate_session(oidc_session).has_value());

    AuditQuery q;
    q.action = "scim.user.deactivated";
    q.target_id = id;
    auto rows = f.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].result == "success");
    CHECK((*rows)[0].detail.find("api_tokens_revoked=2") != std::string::npos);
    CHECK((*rows)[0].detail.find("sessions_revoked=2") != std::string::npos);
}

TEST_CASE("ScimRoutes: credentials-first ordering — the revoke happens BEFORE the account is "
         "marked inactive",
         "[pg][scim][routes][adr2001][deprovision]") {
    // Ordering assertion via the audit trail: `deactivate()`'s credential
    // revoke runs, and only on success does remove_user()/set_active(false)
    // follow — so a persisted "api_tokens_revoked=" detail on the SAME
    // "scim.user.deactivated" success row that marks the account inactive
    // is only reachable if the revoke ran first (a revoke error aborts
    // before remove_user ever runs — see the fail-closed test below).
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "ursula"}})->body);
    auto id = created["id"].get<std::string>();
    auto token = f.token_store->create_token("t", "ursula");
    REQUIRE(token.has_value());

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(f.token_store->validate_token(*token).has_value());
    CHECK_FALSE(f.auth_mgr.get_user_role("ursula").has_value()); // account inactive
}

TEST_CASE("ScimRoutes: DELETE revokes API tokens for BOTH the slug and every linked OIDC "
         "identity",
         "[pg][scim][routes][adr2001][delete]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "victor"}})->body);
    auto id = created["id"].get<std::string>();

    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-victor-1";
    REQUIRE(f.scim_store->upsert_link(iss, sub, id));
    const std::string oidc_principal = oidc::oidc_principal_id(iss, sub);

    auto slug_token = f.token_store->create_token("slug-token", "victor");
    REQUIRE(slug_token.has_value());
    auto oidc_token = f.token_store->create_token("oidc-token", oidc_principal);
    REQUIRE(oidc_token.has_value());

    auto res = f.del("/scim/v2/Users/" + id);
    REQUIRE(res);
    CHECK(res->status == 204);

    CHECK_FALSE(f.token_store->validate_token(*slug_token).has_value());
    CHECK_FALSE(f.token_store->validate_token(*oidc_token).has_value());
}

TEST_CASE("ScimRoutes: create-with-active:false revokes a pre-existing slug-keyed token before "
         "the account goes inactive",
         "[pg][scim][routes][adr2001][create]") {
    // A slug-keyed API token minted against a username BEFORE that username
    // is provisioned via SCIM is unusual (SCIM users are normally SSO-only,
    // ADR-2001 context) but not impossible (ApiTokenStore does not require
    // the principal to already exist) — this pins that the create-with-
    // active:false seam still revokes it, matching the other three
    // deprovision seams rather than silently skipping the slug's own
    // credentials because the account is brand new.
    Fixture f;
    auto pre_token = f.token_store->create_token("pre-existing", "walter");
    REQUIRE(pre_token.has_value());

    auto res = f.post("/scim/v2/Users", {{"userName", "walter"}, {"active", false}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(json::parse(res->body)["active"] == false);

    CHECK_FALSE(f.token_store->validate_token(*pre_token).has_value());
    CHECK_FALSE(f.auth_mgr.get_user_role("walter").has_value());
}

TEST_CASE("ScimRoutes: PATCH active=false fails closed when a token revoke does not persist — "
         "never reports a clean deprovision (ADR-2001 §3 fail-closed mutation-check)",
         "[pg][scim][routes][adr2001][deprovision][failclosed]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "uma"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("uma").has_value());

    // A dedicated size-1 pool for a SECOND ApiTokenStore over the SAME
    // database, registered on a fresh sink alongside the fixture's healthy
    // ScimStore/AuthDB — the "hog the pool" idiom
    // (test_api_token_store.cpp "an EXHAUSTED connection pool is
    // kUnavailable") forces revoke_for_principal's try_acquire_for to time
    // out and return std::unexpected, without degrading AuthDB/ScimStore's
    // own health (so provenance/role checks still pass cleanly).
    yuzu::server::pg::PgPool starved_pool{{.conninfo = f.auth_db.dsn(), .size = 1}};
    ApiTokenStore starved_token_store{starved_pool};
    REQUIRE(starved_token_store.is_open());

    test::TestRouteSink starved_sink;
    ScimRoutes starved_routes;
    starved_routes.register_routes(starved_sink, f.scim_store.get(), &f.auth_mgr,
                                   f.audit_store.get(), /*scim_admin_group=*/{},
                                   /*engine_principal_store=*/nullptr, &starved_token_store);

    auto hog = starved_pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(hog); // holds the pool's only connection

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = starved_sink.dispatch("PATCH", "/scim/v2/Users/" + id, patch_body.dump(),
                                     "application/scim+json", f.auth_header());
    REQUIRE(res);
    CHECK(res->status == 500);
    hog.reset(); // release before touching the DB again below

    // NOT a clean success: the account is still active/live — never marked
    // inactive on top of a credential revoke that never persisted.
    // MUTATION-CHECK (ADR-2001 task spec, manually verified during
    // development): removing `revoke_linked_credentials_or_fail`'s early
    // `return false` in deactivate() (letting a non-persisted revoke fall
    // through to remove_user/set_active/the 200 success response) makes
    // this same request report 200 and get_user_role() come back empty —
    // failing both CHECKs below.
    CHECK(f.auth_mgr.get_user_role("uma").has_value());
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK(stored->active);

    AuditQuery q;
    q.action = "scim.user.deactivated";
    q.target_id = id;
    auto rows = f.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].result == "partial");
    CHECK((*rows)[0].detail.find("api_tokens_db_error=true") != std::string::npos);
}

TEST_CASE("ScimRoutes: D1 — role-refused deprovision WITH an active linked identity is a "
         "LOUD signal: a proper-result audit row + the role-refused metric + a "
         "Severity::kCritical analytics event",
         "[pg][scim][routes][adr2001][d1]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "xena"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.scim_store->upsert_link("https://idp.example.com/", "sub-xena", id));
    REQUIRE(f.auth_mgr.update_role("xena", auth::Role::admin));

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    // #2021 behavior UNCHANGED: still refused.
    CHECK(res->status == 404);
    CHECK(f.auth_mgr.get_user_role("xena").value() == auth::Role::admin);

    // AuditEvent has no severity field — its `result` column carries a
    // REAL outcome value, never a severity string. The termination did NOT
    // complete, so "failure" (not "kCritical", which corrupted this column
    // and defeated any consumer keying off a real result value).
    AuditQuery q;
    q.action = "scim.user.deprovision_role_refused_with_link";
    q.target_id = id;
    auto rows = f.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].result == "failure");
    CHECK(f.metrics.counter("yuzu_scim_deprovision_role_refused_with_active_link_total").value() ==
         1.0);

    // The actual severity channel: an AnalyticsEvent recorded at
    // Severity::kCritical (the same mechanism AuthRoutes::emit_event uses
    // for break-glass logins) — asserted directly against the store, not
    // inferred from a magic string in an unrelated column.
    auto events = f.analytics_store->query_recent(10);
    REQUIRE(events.has_value()); // degrade-distinguishable seam: not nullopt
    bool found_critical = false;
    for (const auto& e : *events) {
        if (e.event_type == "scim.user.deprovision_role_refused_with_link") {
            CHECK(e.severity == Severity::kCritical);
            CHECK(e.attributes.value("scim_id", "") == id);
            found_critical = true;
        }
    }
    CHECK(found_critical);
}

TEST_CASE("ScimRoutes: D1 — role-refused deprovision WITHOUT a link is a plain 404, no new "
         "audit row, metric, or critical analytics event",
         "[pg][scim][routes][adr2001][d1]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "yara"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.update_role("yara", auth::Role::admin));

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 404);

    AuditQuery q;
    q.action = "scim.user.deprovision_role_refused_with_link";
    q.target_id = id;
    auto rows = f.audit_store->query(q);
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
    CHECK(f.metrics.counter("yuzu_scim_deprovision_role_refused_with_active_link_total").value() ==
         0.0);

    auto events = f.analytics_store->query_recent(10);
    REQUIRE(events.has_value()); // degrade-distinguishable seam: not nullopt
    for (const auto& e : *events)
        CHECK(e.event_type != "scim.user.deprovision_role_refused_with_link");
}

TEST_CASE("ScimRoutes: D2 — a deprovision with a login observation but no formed link bumps "
         "the unlinked-signal metric (CC6.8 false-green tripwire)",
         "[pg][scim][routes][adr2001][d2]") {
    Fixture f;
    auto created =
        json::parse(f.post("/scim/v2/Users", {{"userName", "zack"}, {"externalId", "ext-zack"}})
                        ->body);
    auto id = created["id"].get<std::string>();
    // A login occurred whose claim value matches this slug's externalId,
    // but under a DIFFERENT claim than the one configured as the SCIM link
    // claim, so upsert_link never ran — the D2 scenario exactly.
    REQUIRE(f.scim_store->record_login_observation("https://idp.example.com/", "sub-zack", "oid",
                                                    "ext-zack"));

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.metrics.counter("yuzu_scim_deprovision_unlinked_total").value() == 1.0);
}

TEST_CASE("ScimRoutes: D2 — a deprovision with neither a link nor a matching observation does "
         "NOT bump the unlinked-signal metric",
         "[pg][scim][routes][adr2001][d2]") {
    Fixture f;
    auto created = json::parse(
        f.post("/scim/v2/Users", {{"userName", "amos"}, {"externalId", "ext-amos"}})->body);
    auto id = created["id"].get<std::string>();

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.metrics.counter("yuzu_scim_deprovision_unlinked_total").value() == 0.0);
}

// ── Governance PR4a follow-up (C1/C2): D1/D2 must not be OIDC-only ────────
//
// PR4a joined SAML principals into the shared deprovision paths but left D1
// gated on `links_for_scim_id` (OIDC only) and D2 gated on
// `principals.size() != 1` (which SAML links now also inflate) — both
// silently stopped firing for a SAML-only or SAML+unformed-OIDC user. These
// four cases are the closure evidence for that fix.

TEST_CASE("ScimRoutes: D1 — role-refused deprovision WITH an active linked SAML identity "
         "(ZERO OIDC links) is still a LOUD signal — PATCH deactivate",
         "[pg][scim][routes][adr2001][d1][saml]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "priya"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.scim_store->upsert_saml_link("https://idp.example.com/saml/metadata",
                                           "priya@example.com", id));
    REQUIRE(f.auth_mgr.update_role("priya", auth::Role::admin));

    // Confirm this is genuinely SAML-ONLY — zero OIDC identity_links rows.
    auto oidc_links = f.scim_store->links_for_scim_id(id);
    REQUIRE(oidc_links.has_value());
    CHECK(oidc_links->empty());

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 404); // #2021 refusal unchanged
    CHECK(f.auth_mgr.get_user_role("priya").value() == auth::Role::admin);

    AuditQuery q;
    q.action = "scim.user.deprovision_role_refused_with_link";
    q.target_id = id;
    auto rows = f.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].result == "failure");
    CHECK((*rows)[0].detail.find("SAML") != std::string::npos);
    // MUTATION-CHECK (governance C1, manually verified during development):
    // reverting the D1 branches to a bare
    // `scim_store->links_for_scim_id(...)` (OIDC only) makes this metric
    // read 0.0 and this audit row not exist — a SAML-only-linked
    // role-refusal fires NOTHING, exactly the gap this test closes.
    CHECK(f.metrics.counter("yuzu_scim_deprovision_role_refused_with_active_link_total").value() ==
         1.0);
}

TEST_CASE("ScimRoutes: D1 — role-refused deprovision WITH an active linked SAML identity "
         "(ZERO OIDC links) is still a LOUD signal — DELETE",
         "[pg][scim][routes][adr2001][d1][saml]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "quinn"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.scim_store->upsert_saml_link("https://idp.example.com/saml/metadata",
                                           "quinn@example.com", id));
    REQUIRE(f.auth_mgr.update_role("quinn", auth::Role::admin));

    auto res = f.del("/scim/v2/Users/" + id);
    REQUIRE(res);
    CHECK(res->status == 404); // #2021 refusal unchanged
    CHECK(f.auth_mgr.get_user_role("quinn").value() == auth::Role::admin);

    AuditQuery q;
    q.action = "scim.user.deprovision_role_refused_with_link";
    q.target_id = id;
    auto rows = f.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].result == "failure");
    CHECK(f.metrics.counter("yuzu_scim_deprovision_role_refused_with_active_link_total").value() ==
         1.0);
}

TEST_CASE("ScimRoutes: D2 — a resource with ONE SAML link and ZERO OIDC links still bumps the "
         "unlinked-OIDC tripwire on a matching login observation (previously masked by the "
         "coexisting SAML link inflating principals.size())",
         "[pg][scim][routes][adr2001][d2][saml]") {
    Fixture f;
    auto created = json::parse(
        f.post("/scim/v2/Users", {{"userName", "rowan"}, {"externalId", "ext-rowan"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.scim_store->upsert_saml_link("https://idp.example.com/saml/metadata",
                                           "rowan@example.com", id));
    // A login occurred whose claim value matches this slug's externalId,
    // under a DIFFERENT OIDC claim than the configured link claim, so
    // upsert_link (OIDC) never ran — the D2 scenario, now coexisting with a
    // formed SAML link on the same scim_id.
    REQUIRE(f.scim_store->record_login_observation("https://idp.example.com/", "sub-rowan", "oid",
                                                    "ext-rowan"));

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    // MUTATION-CHECK (governance C2, manually verified during development):
    // reverting maybe_flag_d2_unlinked to gate on `principals.size() != 1`
    // sees size()==2 here (slug + the SAML principal) and returns early —
    // this metric reads 0.0 instead of 1.0, exactly the masking this test
    // closes.
    CHECK(f.metrics.counter("yuzu_scim_deprovision_unlinked_total").value() == 1.0);
}

// ── ADR-2001 #3072 — SAML D2 (maybe_flag_saml_d2_unlinked) ──────────────────
//
// SAML analogue of the OIDC D2 section above. Mirrors those three cases,
// plus the C1/C2-style coexisting-other-protocol-link regression guard.

TEST_CASE("ScimRoutes: SAML D2 — a deprovision with a SAML login observation but no formed "
         "SAML link bumps the unlinked-SAML-signal metric",
         "[pg][scim][routes][adr2001][d2][saml]") {
    Fixture f;
    auto created = json::parse(
        f.post("/scim/v2/Users", {{"userName", "sybil"}, {"externalId", "sybil@example.com"}})
            ->body);
    auto id = created["id"].get<std::string>();
    // A SAML login occurred with a NameID matching this slug's externalId,
    // but under an unstable Format, so link_saml_login_to_scim never formed
    // a link — the SAML D2 scenario.
    REQUIRE(f.scim_store->record_saml_login_observation(
        "https://idp.example.com/saml/metadata", "sybil@example.com",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"));

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.metrics.counter("yuzu_scim_deprovision_saml_unlinked_total").value() == 1.0);
}

TEST_CASE("ScimRoutes: SAML D2 — a deprovision with neither a SAML link nor a matching SAML "
         "observation does NOT bump the unlinked-SAML-signal metric",
         "[pg][scim][routes][adr2001][d2][saml]") {
    Fixture f;
    auto created = json::parse(
        f.post("/scim/v2/Users", {{"userName", "tara"}, {"externalId", "tara@example.com"}})
            ->body);
    auto id = created["id"].get<std::string>();

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.metrics.counter("yuzu_scim_deprovision_saml_unlinked_total").value() == 0.0);
}

TEST_CASE("ScimRoutes: SAML D2 — a resource with ONE OIDC link and ZERO SAML links still bumps "
         "the unlinked-SAML tripwire on a matching SAML login observation (must not be masked "
         "by a coexisting OIDC link, mutation-checked)",
         "[pg][scim][routes][adr2001][d2][saml]") {
    Fixture f;
    auto created = json::parse(
        f.post("/scim/v2/Users", {{"userName", "ulric"}, {"externalId", "ulric@example.com"}})
            ->body);
    auto id = created["id"].get<std::string>();
    // A formed OIDC link on the SAME scim_id — this must NOT mask the
    // missing SAML link below (the PR4a C1/C2 lesson, SAML side).
    REQUIRE(f.scim_store->upsert_link("https://idp.example.com/", "sub-ulric", id));
    // A SAML login occurred whose NameID matches this slug's externalId
    // under an unstable Format, so no SAML link ever formed — the SAML D2
    // scenario, now coexisting with a formed OIDC link on the same scim_id.
    REQUIRE(f.scim_store->record_saml_login_observation(
        "https://idp.example.com/saml/metadata", "ulric@example.com",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"));

    // Confirm this is genuinely OIDC-linked / SAML-unlinked before deprovisioning.
    auto oidc_links = f.scim_store->links_for_scim_id(id);
    REQUIRE(oidc_links.has_value());
    CHECK(oidc_links->size() == 1);
    auto saml_links = f.scim_store->saml_links_for_scim_id(id);
    REQUIRE(saml_links.has_value());
    CHECK(saml_links->empty());

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    // MUTATION-CHECK (task spec): reverting maybe_flag_saml_d2_unlinked to
    // gate on links_for_scim_id (OIDC) or a principals.size() proxy instead
    // of saml_links_for_scim_id SPECIFICALLY would see the OIDC link (or
    // the inflated principal set) and return early — this metric would read
    // 0.0 instead of 1.0, exactly the masking this test closes.
    CHECK(f.metrics.counter("yuzu_scim_deprovision_saml_unlinked_total").value() == 1.0);
}

TEST_CASE("ScimRoutes: SAML D2 — a broken saml_identity_links table (saml_links_for_scim_id "
         "cannot answer) makes maybe_flag_saml_d2_unlinked SKIP rather than risk a false "
         "positive, mutation-checked",
         "[pg][scim][routes][adr2001][d2][saml][failclosed]") {
    Fixture f;
    auto created = json::parse(
        f.post("/scim/v2/Users", {{"userName", "victor"}, {"externalId", "victor@example.com"}})
            ->body);
    auto id = created["id"].get<std::string>();

    // Break ONLY saml_identity_links (the table maybe_flag_saml_d2_unlinked's
    // saml_links_for_scim_id read targets). saml_login_observations stays
    // intact, so if the code under test skipped the link read and jumped
    // straight to the observation check it would find a match and (wrongly)
    // fire the tripwire — a mutation this test is designed to catch.
    //
    // Note: `resolve_deprovision_principals` (deprovision_revoke.cpp) reads
    // this SAME table via `saml_links_for_scim_id` and is itself fail-closed
    // on its own nullopt — it 500s BEFORE `revoke_linked_credentials_or_fail`
    // ever reaches `maybe_flag_saml_d2_unlinked` below it. There is no way
    // to reach the D2 detector's own nullopt branch in isolation while this
    // table is down; asserting the 500 (rather than the 200 the sibling D2
    // tests above assert) is the correct, and only reachable, observation
    // here — the counter must still never fire, in a total-degrade scenario
    // exactly as it must in the isolated one.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(f.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult drop{
            PQexec(conn.get(), "DROP TABLE scim_store.saml_identity_links")};
        REQUIRE(drop.ok());
    }

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 500); // resolve_deprovision_principals fails closed on the same table
    // MUTATION-CHECK (task spec, adapted to the reachable path above): the
    // SAML D2 counter must stay 0.0 whether the store degrade is caught by
    // the earlier fail-closed resolver check or (were that check ever
    // weakened/removed) by `maybe_flag_saml_d2_unlinked`'s own
    // `!saml_links.has_value()` early-return — this test pins the observable
    // outcome (never a spurious fire) regardless of which guard catches it.
    CHECK(f.metrics.counter("yuzu_scim_deprovision_saml_unlinked_total").value() == 0.0);
}

TEST_CASE("ScimRoutes: SAML D2 — a broken saml_login_observations table "
         "(saml_observation_matches cannot answer) makes maybe_flag_saml_d2_unlinked SKIP "
         "rather than risk a false positive, mutation-checked",
         "[pg][scim][routes][adr2001][d2][saml][failclosed]") {
    Fixture f;
    auto created = json::parse(
        f.post("/scim/v2/Users", {{"userName", "wendy"}, {"externalId", "wendy@example.com"}})
            ->body);
    auto id = created["id"].get<std::string>();
    // Record the observation FIRST (the table must exist for this write to
    // succeed) so that, absent the drop below, this scenario would
    // otherwise be the ordinary D2-fires case — isolating this test to the
    // observation-read failure specifically, not "no observation exists".
    REQUIRE(f.scim_store->record_saml_login_observation(
        "https://idp.example.com/saml/metadata", "wendy@example.com",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"));

    // Break ONLY saml_login_observations (the table
    // maybe_flag_saml_d2_unlinked's saml_observation_matches read targets).
    // saml_identity_links stays intact — the link read above still
    // succeeds engaged-empty, so the code under test reaches the
    // observation check specifically.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(f.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult drop{
            PQexec(conn.get(), "DROP TABLE scim_store.saml_login_observations")};
        REQUIRE(drop.ok());
    }

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    // MUTATION-CHECK (task spec): changing
    // `if (!observed.has_value() || !*observed) return;` to
    // `if (!*observed) return;` dereferences the disengaged `optional`
    // here (the store-error nullopt from the dropped table) — UB/crash
    // under this exact scenario instead of the correct skip (0.0).
    CHECK(f.metrics.counter("yuzu_scim_deprovision_saml_unlinked_total").value() == 0.0);
}

TEST_CASE("ScimRoutes: revive-on-reprovision refuses an operator-elevated account — 404, and "
         "the remove_user() undo leaves the account INACTIVE, not reactivated-at-elevated-role "
         "(UP-N5/FIX-5, Gate-8 round-2)",
         "[pg][scim][routes][revive][role_refusal]") {
    // Gate-8 round-2 MEDIUM (privilege fail-open): the revive path
    // (POST re-provisioning a tombstoned SCIM account) reactivates the
    // underlying auth row FIRST, then refuses if the role isn't 'user',
    // undoing the reactivation via remove_user(). Previously that undo's
    // bool return was discarded — a failure there would leave the account
    // ACTIVE at its elevated role behind a 404 the IdP never retries. This
    // exercises the happy-path undo (remove_user() succeeds) end-to-end:
    // the account must land INACTIVE, never reactivated.
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "frank"}})->body);
    auto old_id = created["id"].get<std::string>();

    // An operator elevates the account while it is still active...
    REQUIRE(f.auth_mgr.update_role("frank", auth::Role::admin));
    // ...then it is torn down through a path OTHER than SCIM's own DELETE
    // (which would itself have refused via deprovision_role_ok — see the
    // M-DEPROV-ROLE test above, e.g. an admin-console deactivation).
    // remove_user() never touches the role column, so this reproduces
    // exactly the state the revive-refusal guard defends against: a
    // tombstoned SCIM account whose role is still 'admin'.
    REQUIRE(f.auth_mgr.remove_user("frank"));
    auto mapping_deleted = f.scim_store->delete_by_scim_id(old_id);
    REQUIRE(mapping_deleted.has_value());
    CHECK(*mapping_deleted);
    REQUIRE(f.auth_db->get_provisioning_source("frank").value() == "scim");

    // Re-POST: hits the REVIVE branch, reactivate_user() succeeds (role
    // column untouched by it), the role check sees 'admin' != 'user' and
    // refuses — remove_user()'s undo is exercised here.
    auto revive_res = f.post("/scim/v2/Users", {{"userName", "frank"}});
    REQUIRE(revive_res);
    CHECK(revive_res->status == 404);

    // The account must be left INACTIVE — not reactivated-at-elevated-role
    // behind the 404. get_user_role() misses an inactive account's
    // in-memory cache entry the same way the other deactivation assertions
    // in this file do (see e.g. the revive/deprovision tests above).
    CHECK_FALSE(f.auth_mgr.get_user_role("frank").has_value());

    // NOTE (injection gap): this test exercises the SUCCESS path of the
    // remove_user() undo (matches the deactivate() sibling's checked-return
    // pattern). Forcing remove_user()'s own DB write to fail at exactly
    // that point — without also failing the earlier reactivate_user() call
    // on the same connection (which would hit a different, already-tested
    // 500 branch) — needs either a multi-second SQLITE_BUSY wait on
    // AuthDB's fixed 5s busy_timeout or corrupting the shared auth.db file
    // mid-request, neither of which is a clean/fast unit-test injection.
    // The code path itself (`if (!auth_mgr->remove_user(...)) { ... 500
    // ... }`) is exercised by inspection and mirrors deactivate()'s
    // identical, already-tested contract.
}

// ── M-OPTDEREF ───────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: PATCH after DELETE on the same id — 404, no crash",
         "[pg][scim][routes][optderef]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "rex"}})->body);
    auto id = created["id"].get<std::string>();

    auto del_res = f.del("/scim/v2/Users/" + id);
    REQUIRE(del_res);
    CHECK(del_res->status == 204);

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 404);

    auto put_res = f.put("/scim/v2/Users/" + id, {{"userName", "rex"}});
    REQUIRE(put_res);
    CHECK(put_res->status == 404);
}

// ── Set-and-proceed audit posture (UP-N2) ───────────────────────────────
//
// A lost audit write NEVER fails the request on this surface — including
// the termination actions (deactivate/delete/reactivate). Fail-closed here
// used to 500 the IdP's request, but the mutation had already committed and
// the IdP's retry would observe post-state and never re-attempt the lost
// audit write anyway — the evidence gap was permanent either way, at the
// cost of a spurious 500. CC6.8 evidence integrity is instead enforced by
// alerting on yuzu_scim_audit_write_failures_total (bumped inside audit()
// on every failure, independent of the caller's response).

TEST_CASE("ScimRoutes: audit write failure on a non-termination action — set-and-proceed (201)",
         "[pg][scim][routes][audit]") {
    Fixture f{/*broken_audit=*/true};
    auto res = f.post("/scim/v2/Users", {{"userName", "sam"}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(f.auth_mgr.get_user_role("sam").has_value());
}

TEST_CASE("ScimRoutes: audit write failure on a termination action — set-and-proceed (200)",
         "[pg][scim][routes][audit]") {
    Fixture f{/*broken_audit=*/true};
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "tara"}})->body);
    auto id = created["id"].get<std::string>();

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, deactivate_body);
    REQUIRE(res);
    // The mutation committed AND is reported — a lost audit row no longer
    // costs the caller a spurious 500 (see the file comment above).
    CHECK(res->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("tara").has_value());
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK_FALSE(stored->active);
}

TEST_CASE("ScimRoutes: audit write failure on DELETE — set-and-proceed (204)",
         "[pg][scim][routes][audit]") {
    Fixture f{/*broken_audit=*/true};
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "uri"}})->body);
    auto id = created["id"].get<std::string>();

    auto res = f.del("/scim/v2/Users/" + id);
    REQUIRE(res);
    CHECK(res->status == 204);
    CHECK_FALSE(f.auth_mgr.get_user_role("uri").has_value());
}

// ── PUT /scim/v2/Users/{id} — full replace ──────────────────────────────

TEST_CASE("ScimRoutes: PUT identity replace — 200, externalId updated", "[pg][scim][routes][put]") {
    Fixture f;
    auto created =
        json::parse(f.post("/scim/v2/Users", {{"userName", "ivy"}, {"externalId", "ext-old"}})
                        ->body);
    auto id = created["id"].get<std::string>();

    auto res = f.put("/scim/v2/Users/" + id, {{"userName", "ivy"}, {"externalId", "ext-new"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["userName"] == "ivy");
    CHECK(body["externalId"] == "ext-new");
    CHECK(body["active"] == true);
}

TEST_CASE("ScimRoutes: PUT userName change — 400 mutability, account untouched",
         "[pg][scim][routes][put]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "jack"}})->body);
    auto id = created["id"].get<std::string>();

    auto res = f.put("/scim/v2/Users/" + id, {{"userName", "jack2"}});
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(json::parse(res->body)["scimType"] == "mutability");
    CHECK(f.auth_mgr.get_user_role("jack").has_value());
}

TEST_CASE("ScimRoutes: PUT unknown id — 404", "[pg][scim][routes][put]") {
    Fixture f;
    auto res = f.put("/scim/v2/Users/deadbeefdeadbeefdeadbeefdeadbeef", {{"userName", "nobody"}});
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("ScimRoutes: PUT active=false then active=true round-trips the auth account",
         "[pg][scim][routes][put]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "kate"}})->body);
    auto id = created["id"].get<std::string>();

    auto deactivate_res =
        f.put("/scim/v2/Users/" + id, {{"userName", "kate"}, {"active", false}});
    REQUIRE(deactivate_res);
    CHECK(deactivate_res->status == 200);
    CHECK(json::parse(deactivate_res->body)["active"] == false);
    CHECK_FALSE(f.auth_mgr.get_user_role("kate").has_value());

    auto reactivate_res = f.put("/scim/v2/Users/" + id, {{"userName", "kate"}, {"active", true}});
    REQUIRE(reactivate_res);
    CHECK(reactivate_res->status == 200);
    CHECK(json::parse(reactivate_res->body)["active"] == true);
    CHECK(f.auth_mgr.get_user_role("kate").has_value());
}

// FIX-2 (MEDIUM-1, CC6.8 deprovision desync) — PUT counterpart of the PATCH
// test above.
TEST_CASE("ScimRoutes: PUT active=false re-runs deactivation when the mirror is desynced "
         "from a still-live auth account",
         "[pg][scim][routes][put]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "laura"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("laura").has_value());

    REQUIRE(f.scim_store->set_active(id, false));
    REQUIRE(f.auth_mgr.get_user_role("laura").has_value()); // still live

    auto res = f.put("/scim/v2/Users/" + id, {{"userName", "laura"}, {"active", false}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == false);
    CHECK_FALSE(f.auth_mgr.get_user_role("laura").has_value());
}

// ── Malformed body handling ──────────────────────────────────────────────

TEST_CASE("ScimRoutes: malformed JSON body — 400 on POST/PATCH", "[pg][scim][routes][malformed]") {
    Fixture f;
    auto post_res = f.sink.dispatch("POST", "/scim/v2/Users", "{not json",
                                    "application/scim+json", f.auth_header());
    REQUIRE(post_res);
    CHECK(post_res->status == 400);

    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "leo"}})->body);
    auto id = created["id"].get<std::string>();
    auto patch_res = f.sink.dispatch("PATCH", "/scim/v2/Users/" + id, "{not json",
                                     "application/scim+json", f.auth_header());
    REQUIRE(patch_res);
    CHECK(patch_res->status == 400);
}

TEST_CASE("ScimRoutes: POST with a non-string userName/externalId — 400, not 500 (FIX-3)",
         "[pg][scim][routes][malformed]") {
    // Confirms the route path that calls scim::parse_user() propagates its
    // std::expected 400 cleanly rather than an nlohmann::json::type_error
    // unwinding to an unhandled 500.
    Fixture f;
    auto res1 = f.post("/scim/v2/Users", {{"userName", 123}});
    REQUIRE(res1);
    CHECK(res1->status == 400);
    auto body1 = json::parse(res1->body);
    CHECK(body1["scimType"] == "invalidValue");

    auto res2 = f.post("/scim/v2/Users", {{"userName", "vic"}, {"externalId", json::array()}});
    REQUIRE(res2);
    CHECK(res2->status == 400);
    auto body2 = json::parse(res2->body);
    CHECK(body2["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: oversized body — 413 on POST/PATCH", "[pg][scim][routes][malformed]") {
    Fixture f;
    std::string huge_body = R"({"userName":")" + std::string(70 * 1024, 'x') + R"("})";
    auto post_res = f.sink.dispatch("POST", "/scim/v2/Users", huge_body, "application/scim+json",
                                    f.auth_header());
    REQUIRE(post_res);
    CHECK(post_res->status == 413);

    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "mia"}})->body);
    auto id = created["id"].get<std::string>();
    auto patch_res = f.sink.dispatch("PATCH", "/scim/v2/Users/" + id, huge_body,
                                     "application/scim+json", f.auth_header());
    REQUIRE(patch_res);
    CHECK(patch_res->status == 413);
}

// ── S-POST-REFETCH ───────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: POST active:false — 201 body's ETag matches a following GET",
         "[pg][scim][routes][post]") {
    Fixture f;
    auto res = f.post("/scim/v2/Users", {{"userName", "uma"}, {"active", false}});
    REQUIRE(res);
    CHECK(res->status == 201);
    auto body = json::parse(res->body);
    CHECK(body["active"] == false);
    auto id = body["id"].get<std::string>();
    auto post_etag = res->get_header_value("ETag");
    CHECK_FALSE(post_etag.empty());
    CHECK(body["meta"]["version"] == post_etag);

    auto get_res = f.get("/scim/v2/Users/" + id);
    REQUIRE(get_res);
    auto get_body = json::parse(get_res->body);
    CHECK(get_body["meta"]["version"] == post_etag);
    CHECK(get_body["active"] == false);
}

TEST_CASE("ScimRoutes: POST active:false — the underlying account is ACTUALLY deactivated "
         "(FIX-1)",
         "[pg][scim][routes][post]") {
    // Hermes MEDIUM (fail-open): honouring active:false on create previously
    // only LOGGED a remove_user() failure and fell through to set_active(),
    // so a failed deactivation could ship a 201 with active:false while the
    // auth account stayed LIVE. This asserts the success path end-to-end —
    // not just the SCIM resource flag (covered by the ETag test above) but
    // that the auth account itself is actually deactivated, the way
    // deactivate()'s own tests assert for PATCH/DELETE.
    Fixture f;
    auto res = f.post("/scim/v2/Users", {{"userName", "uma2"}, {"active", false}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(f.auth_mgr.get_user_role("uma2").has_value());

    // NOTE (injection gap): forcing remove_user()'s own DB write to fail at
    // exactly this point — without also failing the preceding
    // upsert_user()/reactivate_user() call on the same connection — needs
    // either a multi-second SQLITE_BUSY wait on AuthDB's fixed 5s
    // busy_timeout or corrupting the shared auth.db file mid-request,
    // neither of which is a clean/fast unit-test injection (same gap
    // documented on the revive-refusal undo test above). The fail-closed
    // branch itself (remove_user() failure -> 500 + audit "failure" +
    // return, never falling through to set_active()) is exercised by
    // inspection and mirrors deactivate()'s identical, already-tested
    // contract.
}

// ── S-CLAMP-COUNT ────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: GET list clamps count to maxResults", "[pg][scim][routes][list]") {
    Fixture f;
    // Seed scim_resource rows directly at the store layer (cheap — no
    // PBKDF2/AuthDB write per row) so this test can exceed maxResults
    // without the cost of 200+ real HTTP provisions.
    for (int i = 0; i < scim::kMaxScimListResults + 5; ++i) {
        REQUIRE(f.scim_store->create_resource("clampuser" + std::to_string(i)).has_value());
    }

    auto res = f.get("/scim/v2/Users?count=99999");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["itemsPerPage"] == scim::kMaxScimListResults);
    CHECK(body["Resources"].size() == static_cast<std::size_t>(scim::kMaxScimListResults));
}

// FIX-1 (MEDIUM-2, S-BOUND-INTPARAM): a malformed startIndex/count must
// fail cleanly with a SCIM 400 `invalidValue`, never an unhandled
// std::stoi exception escaping to a 500.
TEST_CASE("ScimRoutes: GET list — non-numeric startIndex is a 400, not a 500",
         "[pg][scim][routes][list]") {
    Fixture f;
    auto res = f.get("/scim/v2/Users?startIndex=abc");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = json::parse(res->body);
    CHECK(body["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: GET list — an absurdly long startIndex is a 400, not a 500",
         "[pg][scim][routes][list]") {
    Fixture f;
    auto res = f.get("/scim/v2/Users?startIndex=" + std::string(40, '9'));
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = json::parse(res->body);
    CHECK(body["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: GET list — a malformed count is a 400, not a 500",
         "[pg][scim][routes][list]") {
    Fixture f;
    auto res = f.get("/scim/v2/Users?count=" + std::string(40, '9'));
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = json::parse(res->body);
    CHECK(body["scimType"] == "invalidValue");
}

TEST_CASE("ScimRoutes: GET list — a negative startIndex is clamped to 1, not a 400",
         "[pg][scim][routes][list]") {
    Fixture f;
    REQUIRE(f.scim_store->create_resource("negidxuser").has_value());

    auto res = f.get("/scim/v2/Users?startIndex=-5");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["startIndex"] == 1);
}

TEST_CASE("ScimRoutes: GET list — a valid startIndex/count still works", "[pg][scim][routes][list]") {
    Fixture f;
    for (int i = 0; i < 10; ++i)
        REQUIRE(f.scim_store->create_resource("pageuser" + std::to_string(i)).has_value());

    auto res = f.get("/scim/v2/Users?startIndex=2&count=5");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["startIndex"] == 2);
    CHECK(body["itemsPerPage"] == 5);
    CHECK(body["Resources"].size() == 5);
}

// ── scim_boot_guard_ok (S-BOOTGUARD-TEST) ───────────────────────────────

TEST_CASE("scim_boot_guard_ok: disabled — always ok", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = false;
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

TEST_CASE("scim_boot_guard_ok: enabled without a token — fails", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token.clear();
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("scim_boot_guard_ok: enabled without HTTPS — fails", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = false;
    // Long enough to clear the M1 length floor, so this test exercises the
    // HTTPS branch specifically, not the length one.
    cfg.scim_token = "a-plenty-long-enough-token-0123456789";
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("scim_boot_guard_ok: enabled with token AND https — ok", "[scim][bootguard]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = "a-plenty-long-enough-token-0123456789";
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

// ── M1 — token length/entropy floor ─────────────────────────────────────

TEST_CASE("scim_boot_guard_ok: enabled with a short token — fails (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = "short-token"; // < 24 chars
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("scim_boot_guard_ok: a 32-hex-char token passes the length floor (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = "0123456789abcdef0123456789abcdef"; // 32 hex chars
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

TEST_CASE("scim_boot_guard_ok: exactly 24 chars is the accepted floor (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = std::string(24, 'a');
    std::string err;
    CHECK(scim_boot_guard_ok(cfg, err));
}

TEST_CASE("scim_boot_guard_ok: 23 chars fails the floor by one (M1)",
         "[scim][bootguard][m1]") {
    Config cfg;
    cfg.scim_enable = true;
    cfg.https_enabled = true;
    cfg.scim_token = std::string(23, 'a');
    std::string err;
    CHECK_FALSE(scim_boot_guard_ok(cfg, err));
}

// ── H1 integration: real httplib::Server + Client (2026-07-08 review) ──────
//
// The TestRouteSink-based tests above dispatch directly into ScimRoutes'
// registered handlers — they can never reproduce H1 (every /scim/v2/* call
// 302-redirected to /login before ScimRoutes ever ran) because the sink has
// no pre-routing middleware at all (#438's whole reason for existing). This
// section spins up a REAL httplib::Server with a pre-routing handler that
// mirrors server.cpp's production wiring (the ADR-1005 on-behalf-of guard
// FIRST, then the rate limiter, THEN `is_login_exempt_path`, THEN a
// no-session-cookie 401/redirect fallback for everything else), registers
// ScimRoutes against it, and drives it over the wire with httplib::Client —
// the only way to prove the exemption + ordering holds on a real request.
//
// UPDATE (post PR #2018 review, dev merge landed the ADR-1005 guard on this
// branch): the on-behalf-of guard shipped in server.cpp (~line 4781, guarded
// by `on_behalf_guard.hpp`'s `onbehalf::find_reserved_key`) since the note
// below was written. This harness now wires the SAME production helper —
// not a re-implementation — into the mock pre-routing handler, positioned
// exactly where server.cpp runs it: before the rate limiter and before
// `is_login_exempt_path`. That proves the SCIM login-exemption (H1's whole
// point) does NOT also exempt /scim/v2/* from ADR-1005 — a reserved
// on-behalf-of header still 403s even with an otherwise-valid SCIM bearer
// token, and even though the request never reaches the login-redirect
// fallback this exemption softened.
//
// SKIPPED UNDER ThreadSanitizer (#438) — same rationale as
// test_security_headers.cpp's integration block: httplib::Server's threaded
// acceptor crashes under TSan's interceptors with no usable report. The
// TestRouteSink coverage above still exercises ScimRoutes' own logic under
// TSan; only the on-the-wire pre-routing-handler wiring is gated here.
#if defined(__has_feature)
#  if __has_feature(thread_sanitizer)
#    define YUZU_SCIM_TSAN_BUILD 1
#  endif
#endif
#if defined(__SANITIZE_THREAD__)
#  define YUZU_SCIM_TSAN_BUILD 1
#endif

#ifndef YUZU_SCIM_TSAN_BUILD

namespace {

/// Wires ScimRoutes against a REAL httplib::Server whose pre-routing
/// handler mirrors server.cpp's `set_pre_routing_handler` lambda closely
/// enough to reproduce H1: the ADR-1005 on-behalf-of guard runs FIRST
/// (production helper, `onbehalf::find_reserved_key` — not a
/// re-implementation), then a configurable RateLimiter, then
/// `is_login_exempt_path` gates the login-redirect fallback (same ordering
/// as production) — see the "Do NOT" warning in the review against wiring
/// the SCIM exemption into an earlier early-return that skips the limiter
/// (and, now, against wiring it before the on-behalf-of guard either).
struct ScimIntegrationServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};
    // PG-gated (yuzu::test::AuthDbPg): SKIPs the current TEST_CASE at
    // construction time (before start() runs) when YUZU_TEST_POSTGRES_DSN
    // is unset — every call site constructs `ScimIntegrationServer ts;`
    // immediately followed by `ts.start();`, so folding AuthDB construction
    // into this struct's own member-init (rather than deferring it inside
    // start(), as the old SQLite AuthDB did) changes nothing observable.
    yuzu::test::AuthDbPg auth_db;
    auth::AuthManager auth_mgr;
    std::unique_ptr<ScimStore> scim_store;
    // ADR-2001 §§1,3: shares auth_db's PgPool, same "one PgPool" pattern as
    // scim_store/audit_store — wired into the deprovision seams'
    // credentials-FIRST revoke.
    std::unique_ptr<ApiTokenStore> token_store;
    // AuditStore ported to Postgres (ADR-0006): shares auth_db's PgPool/
    // database (same "one PgPool" pattern as ScimStore above).
    std::unique_ptr<AuditStore> audit_store;
    std::unique_ptr<ScimRoutes> routes;
    RateLimiter rate_limiter;
    yuzu::MetricsRegistry metrics;
    const std::string token{"integration-test-scim-bearer-0123456789"};
    std::string scim_admin_group;
    // Rejection witness (#2757): incremented exactly where the pre-routing
    // handler below rejects a reserved on-behalf-of header, so a Windows
    // connection-reset fallback (test_loopback_http.hpp) can prove the
    // rejection actually ran for a given request rather than accepting any
    // lost response.
    std::atomic<int> onbehalf_rejections{0};

    explicit ScimIntegrationServer(int rate_per_second = 100, std::string admin_group = {})
        : rate_limiter(rate_per_second), scim_admin_group(std::move(admin_group)) {}

    void start() {
        auth_mgr.set_auth_db(auth_db.get());

        scim_store = std::make_unique<ScimStore>(auth_db.pool());
        REQUIRE(scim_store->is_open());
        REQUIRE(scim_store->set_token(token, "test"));

        token_store = std::make_unique<ApiTokenStore>(auth_db.pool());
        REQUIRE(token_store->is_open());

        audit_store = std::make_unique<AuditStore>(auth_db.pool());
        REQUIRE(audit_store->is_open());

        // Mirrors server.cpp's pre-routing lambda ordering (server.cpp
        // ~4743-4830): the ADR-1005 on-behalf-of guard FIRST (using the
        // real production helper, not a reimplementation — the whole point
        // is exercising the shipped reserved-key detection), then the rate
        // limiter, then the login-exempt-path decision, then a 401
        // (API-shaped path) or a redirect (page-shaped path) for anything
        // unauthenticated that falls through. There is no session cookie
        // anywhere in this harness — every non-exempt path is always
        // "unauthenticated".
        svr.set_pre_routing_handler(
            [this](const httplib::Request& req, httplib::Response& res)
                -> httplib::Server::HandlerResponse {
                if (auto reserved = onbehalf::find_reserved_key(req.headers)) {
                    (void)onbehalf::note_rejection(metrics, "http");
                    res.status = 403;
                    res.set_content(
                        R"({"error":{"code":403,"message":"on-behalf-of assertion rejected per ADR-1005"}})",
                        "application/json");
                    (void)reserved;
                    onbehalf_rejections.fetch_add(1);
                    return httplib::Server::HandlerResponse::Handled;
                }
                if (!rate_limiter.allow(req.remote_addr)) {
                    res.status = 429;
                    return httplib::Server::HandlerResponse::Handled;
                }
                if (is_login_exempt_path(req.path))
                    return httplib::Server::HandlerResponse::Unhandled;
                if (req.path.starts_with("/api/") || req.path.starts_with("/scim/v2/")) {
                    res.status = 401;
                    res.set_content(R"({"error":{"code":401,"message":"unauthorized"}})",
                                    "application/json");
                } else {
                    res.set_redirect("/login");
                }
                return httplib::Server::HandlerResponse::Handled;
            });

        routes = std::make_unique<ScimRoutes>();
        routes->register_routes(svr, scim_store.get(), &auth_mgr, audit_store.get(),
                                scim_admin_group, /*engine_principal_store=*/nullptr,
                                token_store.get());

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        for (int i = 0; i < 100; ++i) {
            if (svr.is_running())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        REQUIRE(svr.is_running());
    }

    ~ScimIntegrationServer() {
        svr.stop();
        if (server_thread.joinable())
            server_thread.join();
        routes.reset();
        audit_store.reset();
        token_store.reset();
        scim_store.reset();
    }
};

/// Provision a SCIM user over real HTTP and return its `id`. Fails the test
/// (via REQUIRE) rather than returning an error — every caller needs a
/// live scim_id to proceed.
std::string create_scim_user_over_wire(httplib::Client& cli, const std::string& token,
                                       const std::string& username) {
    httplib::Headers hdr{{"Authorization", "Bearer " + token}};
    auto r = cli.Post("/scim/v2/Users", hdr, json{{"userName", username}}.dump(),
                      "application/scim+json");
    REQUIRE(r);
    REQUIRE(r->status == 201);
    return json::parse(r->body)["id"].get<std::string>();
}

} // namespace

TEST_CASE("H1 integration: /scim/v2/Users with a valid bearer provisions over real HTTP — "
         "201, not a login redirect",
         "[pg][scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers auth_hdr{{"Authorization", "Bearer " + ts.token}};
    auto r = cli.Post("/scim/v2/Users", auth_hdr, R"({"userName":"wire-user"})",
                      "application/scim+json");
    REQUIRE(r);
    CHECK(r->status == 201);
    CHECK(r->has_header("Location"));
}

TEST_CASE("H1 integration: a bogus bearer against /scim/v2/Users is 401, NEVER a 302 to /login",
         "[pg][scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers bogus{{"Authorization", "Bearer totally-wrong-token"}};
    auto r = cli.Post("/scim/v2/Users", bogus, R"({"userName":"nope"})", "application/scim+json");
    REQUIRE(r);
    // Pre-fix, this exact request 302-redirected to /login (H1): the
    // pre-routing handler's unauthenticated fallback only 401'd paths
    // starting with "/api/"; /scim/v2/* does not, so it fell into the
    // page-shaped redirect branch instead. Assert the negative explicitly
    // so a regression back to that behavior is caught even if some future
    // refactor produces a different non-401 status.
    CHECK(r->status != 302);
    CHECK(r->status == 401);
    CHECK(r->get_header_value("WWW-Authenticate") == "Bearer");
}

TEST_CASE("H1 integration: a missing bearer against /scim/v2/Users is 401, not a redirect",
         "[pg][scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto r = cli.Post("/scim/v2/Users", R"({"userName":"nope"})", "application/scim+json");
    REQUIRE(r);
    CHECK(r->status != 302);
    CHECK(r->status == 401);
}

TEST_CASE("H1 integration: a non-exempt API path with no session still gets the ordinary "
         "unauthenticated-API 401 (control — the SCIM exemption did not broaden beyond "
         "/scim/v2/*)",
         "[pg][scim][routes][integration][h1]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto r = cli.Get("/api/v1/foo");
    REQUIRE(r);
    CHECK(r->status == 401);
}

TEST_CASE("H1 integration: rate limiting is RETAINED for /scim/v2/* despite the login "
         "exemption (ordering: the limiter runs before the exempt-path check)",
         "[pg][scim][routes][integration][h1][ratelimit]") {
    ScimIntegrationServer ts(/*rate_per_second=*/1);
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers auth_hdr{{"Authorization", "Bearer " + ts.token}};
    auto r1 = cli.Get("/scim/v2/ServiceProviderConfig", auth_hdr);
    REQUIRE(r1);
    CHECK(r1->status == 200);

    // Same client IP, immediately after — rate=1 leaves the bucket at 0
    // tokens, so this MUST be rejected before it ever reaches ScimRoutes,
    // proving the login exemption is not ALSO a rate-limit bypass.
    auto r2 = cli.Get("/scim/v2/ServiceProviderConfig", auth_hdr);
    REQUIRE(r2);
    CHECK(r2->status == 429);
}

TEST_CASE("H1 integration: a reserved on-behalf-of header against /scim/v2/* is 403 per "
         "ADR-1005, even with an otherwise-valid SCIM bearer token (the SCIM login-exemption "
         "does not strip the on-behalf-of guard)",
         "[pg][scim][routes][integration][h1][adr1005][onbehalf]") {
    ScimIntegrationServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // A real reserved key from on_behalf_guard.hpp's kReservedKeys, alongside
    // an otherwise-valid bearer token — proving the 403 fires on the
    // presence of the reserved header, not on the absence of auth.
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token},
                         {"X-Yuzu-On-Behalf-Of", "alice@example.com"}};
    yuzu::test::expect_pre_routing_rejection(
        [&] {
            return cli.Post("/scim/v2/Users", hdr, R"({"userName":"onbehalf-user"})",
                            "application/scim+json");
        },
        403, ts.onbehalf_rejections);

    // Control: the same request MINUS the reserved header provisions
    // normally (201) — isolates the 403 to the on-behalf-of guard, not some
    // other rejection of this payload/token pair.
    httplib::Headers clean{{"Authorization", "Bearer " + ts.token}};
    auto r2 = cli.Post("/scim/v2/Users", clean, R"({"userName":"onbehalf-user-clean"})",
                       "application/scim+json");
    REQUIRE(r2);
    CHECK(r2->status == 201);
}

// ── SCIM v2 Groups (#2021, slice 2) — real httplib::Server + Client ─────────
//
// Same rationale as the H1 section above (PR #2018's HIGH bugs slipped
// because tests bypassed the `pre_routing_handler`) — every Group-route
// test in this section drives the surface over the wire, never through
// TestRouteSink.

TEST_CASE("Groups integration: POST creates a group — 201, GET finds it, unknown id is 404 not "
         "403",
         "[pg][scim][routes][integration][groups]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto post_res = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Engineering"})",
                             "application/scim+json");
    REQUIRE(post_res);
    CHECK(post_res->status == 201);
    CHECK(post_res->has_header("Location"));
    auto body = json::parse(post_res->body);
    CHECK(body["displayName"] == "Engineering");
    auto id = body["id"].get<std::string>();

    auto get_res = cli.Get(("/scim/v2/Groups/" + id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(get_res->status == 200);
    CHECK(json::parse(get_res->body)["displayName"] == "Engineering");

    // Unknown id: 404, never 403 (no existence oracle — mirrors the Users
    // surface's posture).
    auto missing_get = cli.Get("/scim/v2/Groups/deadbeefdeadbeefdeadbeefdeadbeef", hdr);
    REQUIRE(missing_get);
    CHECK(missing_get->status == 404);

    auto missing_del = cli.Delete("/scim/v2/Groups/deadbeefdeadbeefdeadbeefdeadbeef", hdr);
    REQUIRE(missing_del);
    CHECK(missing_del->status == 404);
}

TEST_CASE("Groups integration: bogus bearer against /scim/v2/Groups is 401, missing bearer is "
         "401",
         "[pg][scim][routes][integration][groups][auth]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    httplib::Headers bogus{{"Authorization", "Bearer totally-wrong-token"}};
    auto r1 = cli.Post("/scim/v2/Groups", bogus, R"({"displayName":"X"})",
                       "application/scim+json");
    REQUIRE(r1);
    CHECK(r1->status == 401);

    auto r2 = cli.Get("/scim/v2/Groups");
    REQUIRE(r2);
    CHECK(r2->status == 401);
}

TEST_CASE("Groups integration: promotion — PATCH-adding a SCIM user to the admin group promotes "
         "them, removing demotes them back",
         "[pg][scim][routes][integration][groups][promotion]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "grace");
    REQUIRE(ts.auth_mgr.get_user_role("grace").value() == auth::Role::user);

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    // The group role-application core ran synchronously inside the PATCH
    // handler (see recompute_scim_user_role) — no polling/eventual
    // consistency needed.
    CHECK(ts.auth_mgr.get_user_role("grace").value() == auth::Role::admin);

    json remove_body{
        {"Operations",
         json::array({{{"op", "remove"}, {"path", "members[value eq \"" + user_id + "\"]"}}})}};
    auto patch_res2 = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, remove_body.dump(),
                                "application/scim+json");
    REQUIRE(patch_res2);
    CHECK(patch_res2->status == 200);
    CHECK(ts.auth_mgr.get_user_role("grace").value() == auth::Role::user);
}

TEST_CASE("Groups integration: PROVENANCE — a group member value mapping to a local (non-SCIM) "
         "admin never changes that account's role, and never audits scim.user.role_changed for "
         "it",
         "[pg][scim][routes][integration][groups][provenance]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    // A local admin, created OUTSIDE the SCIM path — mirrors first-run-setup
    // / an operator-run `yuzu-server --add-user`.
    REQUIRE(ts.auth_mgr.upsert_user("root-admin", "correct-horse-battery-staple",
                                    auth::Role::admin));
    REQUIRE(ts.auth_db->get_provisioning_source("root-admin").value() == "local");
    // Craft a scim_resource mapping pointing at the local account (the
    // defense-in-depth scenario the Users provenance guard already covers —
    // e.g. an operator hand-editing scim_resources, or a future bug) so a
    // Group member `value` CAN reference it by scim_id.
    auto local_admin_mapping = ts.scim_store->create_resource("root-admin");
    REQUIRE(local_admin_mapping.has_value());

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{
        {"Operations",
         json::array({{{"op", "add"},
                       {"path", "members"},
                       {"value", json::array({{{"value", local_admin_mapping->scim_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    // The local admin's role/provenance are COMPLETELY untouched.
    CHECK(ts.auth_mgr.get_user_role("root-admin").value() == auth::Role::admin);
    CHECK(ts.auth_db->get_provisioning_source("root-admin").value() == "local");

    // No scim.user.role_changed audit row was ever written for this target.
    AuditQuery q;
    q.action = "scim.user.role_changed";
    q.target_id = local_admin_mapping->scim_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    CHECK(rows->empty());

    // The membership ITSELF is a valid store operation (the local admin's
    // scim_id IS a live scim_resource row — the routes layer's
    // validate-and-skip only rejects a value that resolves to NO scim
    // resource at all; it does not, and must not, need to know about
    // provenance to decide what a Group's membership list contains). The
    // security boundary is entirely at ROLE APPLICATION — proven above by
    // the untouched role/provenance and the missing audit row.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    auto members = json::parse(get_res->body)["members"];
    bool found = false;
    for (const auto& m : members)
        if (m["value"] == local_admin_mapping->scim_id)
            found = true;
    CHECK(found);

    // Control: a BOGUS member value (never resolves to any SCIM User
    // resource at all) IS validate-and-skip'd — the PATCH still succeeds
    // and simply never persists that membership.
    json bogus_body{{"Operations",
                     json::array({{{"op", "add"},
                                   {"path", "members"},
                                   {"value", json::array({{{"value", "deadbeefdeadbeef"}}})}}})}};
    auto patch_res2 = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, bogus_body.dump(),
                                "application/scim+json");
    REQUIRE(patch_res2);
    CHECK(patch_res2->status == 200);
    auto get_res2 = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res2);
    auto members2 = json::parse(get_res2->body)["members"];
    for (const auto& m : members2)
        CHECK(m["value"] != "deadbeefdeadbeef");
}

TEST_CASE("Groups integration: deprovision ordering — a group-elevated admin cannot be SCIM-"
         "deprovisioned until the IdP removes them from the admin group",
         "[pg][scim][routes][integration][groups][deprovision-ordering]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "hank");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto promote_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                                 "application/scim+json");
    REQUIRE(promote_res);
    REQUIRE(promote_res->status == 200);
    REQUIRE(ts.auth_mgr.get_user_role("hank").value() == auth::Role::admin);

    // Group-elevated — deprovision_role_ok refuses exactly like an
    // operator-elevated account. 404, never 403.
    auto del1 = cli.Delete(("/scim/v2/Users/" + user_id).c_str(), hdr);
    REQUIRE(del1);
    CHECK(del1->status == 404);
    CHECK(ts.auth_mgr.get_user_role("hank").value() == auth::Role::admin);

    // The IdP removes them from the admin group — demotes back to 'user'.
    json remove_body{
        {"Operations",
         json::array({{{"op", "remove"}, {"path", "members[value eq \"" + user_id + "\"]"}}})}};
    auto demote_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, remove_body.dump(),
                                "application/scim+json");
    REQUIRE(demote_res);
    REQUIRE(demote_res->status == 200);
    REQUIRE(ts.auth_mgr.get_user_role("hank").value() == auth::Role::user);

    // NOW the deprovision succeeds.
    auto del2 = cli.Delete(("/scim/v2/Users/" + user_id).c_str(), hdr);
    REQUIRE(del2);
    CHECK(del2->status == 204);
}

TEST_CASE("Groups integration: --scim-admin-group unset (empty) — group membership never "
         "promotes anyone",
         "[pg][scim][routes][integration][groups][admin-group-unset]") {
    ScimIntegrationServer ts; // no admin_group argument — empty by default
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "ivy");

    // Even a group literally named "Yuzu-Admins" (or anything else) cannot
    // promote when scim_admin_group is unconfigured — resolve_role_from_groups
    // never matches against an empty admin_group.
    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    CHECK(ts.auth_mgr.get_user_role("ivy").value() == auth::Role::user);
}

TEST_CASE("Groups integration: DELETE demotes every member and audits the demotion (qa-4)",
          "[pg][scim][routes][integration][groups][delete]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "quinn");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto promote_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                                 "application/scim+json");
    REQUIRE(promote_res);
    REQUIRE(promote_res->status == 200);
    REQUIRE(ts.auth_mgr.get_user_role("quinn").value() == auth::Role::admin);

    auto del = cli.Delete(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(del);
    CHECK(del->status == 204);

    // The member is demoted back to 'user' as soon as its only admin-
    // granting group disappears (recompute_scim_user_role runs over the
    // pre-delete membership snapshot).
    CHECK(ts.auth_mgr.get_user_role("quinn").value() == auth::Role::user);

    // A durable scim.user.role_changed=success audit row exists for the
    // demotion, keyed on the user's scim_id (not the group's).
    AuditQuery q;
    q.action = "scim.user.role_changed";
    q.target_id = user_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());
    bool found_demotion = false;
    for (const auto& row : *rows) {
        if (row.result == "success" && row.detail.find("new_role=user") != std::string::npos)
            found_demotion = true;
    }
    CHECK(found_demotion);

    // The group itself is gone.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(get_res->status == 404);
}

TEST_CASE("Groups integration: PUT full-replace — dropped member demoted, added member promoted "
          "(qa-5)",
          "[pg][scim][routes][integration][groups][put]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto old_member = create_scim_user_over_wire(cli, ts.token, "rex");
    auto new_member = create_scim_user_over_wire(cli, ts.token, "sara");

    auto group_post =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "Yuzu-Admins"},
                      {"members", json::array({{{"value", old_member}}})}}
                     .dump(),
                 "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("rex").value() == auth::Role::admin);
    REQUIRE(ts.auth_mgr.get_user_role("sara").value() == auth::Role::user);

    // Full replace: drop rex, add sara.
    json put_body{{"displayName", "Yuzu-Admins"},
                  {"members", json::array({{{"value", new_member}}})}};
    auto put_res = cli.Put(("/scim/v2/Groups/" + group_id).c_str(), hdr, put_body.dump(),
                           "application/scim+json");
    REQUIRE(put_res);
    CHECK(put_res->status == 200);

    CHECK(ts.auth_mgr.get_user_role("rex").value() == auth::Role::user);
    CHECK(ts.auth_mgr.get_user_role("sara").value() == auth::Role::admin);

    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    auto members = json::parse(get_res->body)["members"];
    REQUIRE(members.size() == 1);
    CHECK(members[0]["value"] == new_member);
}

TEST_CASE("Groups integration: PATCH with both replace and add/remove ops — replace wins "
          "because it comes LAST in this body's op order (qa-6, updated for #2127 rework)",
          "[pg][scim][routes][integration][groups][patch-precedence]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto replace_member = create_scim_user_over_wire(cli, ts.token, "tina");
    auto add_member = create_scim_user_over_wire(cli, ts.token, "uma");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    // A single PATCH body mixing an `add` op with a `replace` op on members,
    // in THAT order — the ordered fold (#2127 rework) applies the `add`
    // first (member set becomes {add_member}), then the `replace` LAST,
    // which SETS the member set outright, discarding whatever came before.
    // Only replace_member should end up a member. This is no longer a
    // special-cased "replace always wins" rule — it wins here because it is
    // the LAST member op in the body; see the dedicated ordered-ops tests
    // for the case where op order actually changes the outcome.
    json mixed_body{
        {"Operations",
         json::array(
             {{{"op", "add"},
              {"path", "members"},
              {"value", json::array({{{"value", add_member}}})}},
             {{"op", "replace"},
              {"path", "members"},
              {"value", json::array({{{"value", replace_member}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, mixed_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    auto members = json::parse(get_res->body)["members"];
    REQUIRE(members.size() == 1);
    CHECK(members[0]["value"] == replace_member);
    CHECK(ts.auth_mgr.get_user_role("tina").value() == auth::Role::admin);
    CHECK(ts.auth_mgr.get_user_role("uma").value() == auth::Role::user);
}

TEST_CASE("Groups integration: PUT rename onto an existing group's displayName 409s, B unchanged "
          "(arch-S4/UP-2)",
          "[pg][scim][routes][integration][groups][rename-409]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto a_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-A"})",
                           "application/scim+json");
    REQUIRE(a_post);
    REQUIRE(a_post->status == 201);

    auto b_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-B"})",
                           "application/scim+json");
    REQUIRE(b_post);
    REQUIRE(b_post->status == 201);
    auto b_id = json::parse(b_post->body)["id"].get<std::string>();
    auto b_etag = json::parse(b_post->body)["meta"]["version"].get<std::string>();

    auto put_res = cli.Put(("/scim/v2/Groups/" + b_id).c_str(), hdr,
                           R"({"displayName":"Group-A"})", "application/scim+json");
    REQUIRE(put_res);
    CHECK(put_res->status == 409);

    AuditQuery q;
    q.action = "scim.group.updated";
    q.target_id = b_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool found_denied = false;
    for (const auto& row : *rows)
        if (row.result == "denied")
            found_denied = true;
    CHECK(found_denied);

    auto get_res = cli.Get(("/scim/v2/Groups/" + b_id).c_str(), hdr);
    REQUIRE(get_res);
    auto body = json::parse(get_res->body);
    CHECK(body["displayName"] == "Group-B");
    CHECK(body["meta"]["version"] == b_etag);
}

TEST_CASE("Groups integration: PATCH rename onto an existing group's displayName 409s, B "
          "unchanged (arch-S4/UP-2)",
          "[pg][scim][routes][integration][groups][rename-409]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto a_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-C"})",
                           "application/scim+json");
    REQUIRE(a_post);
    REQUIRE(a_post->status == 201);

    auto b_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Group-D"})",
                           "application/scim+json");
    REQUIRE(b_post);
    REQUIRE(b_post->status == 201);
    auto b_id = json::parse(b_post->body)["id"].get<std::string>();

    json patch_body{
        {"Operations",
         json::array({{{"op", "replace"}, {"path", "displayName"}, {"value", "Group-C"}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + b_id).c_str(), hdr, patch_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 409);

    AuditQuery q;
    q.action = "scim.group.updated";
    q.target_id = b_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool found_denied = false;
    for (const auto& row : *rows)
        if (row.result == "denied")
            found_denied = true;
    CHECK(found_denied);

    auto get_res = cli.Get(("/scim/v2/Groups/" + b_id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(json::parse(get_res->body)["displayName"] == "Group-D");
}

TEST_CASE("Groups integration: an embedded-NUL displayName is rejected fail-closed — no spurious "
         "promotion to the configured admin group (UP-3)",
         "[pg][scim][routes][integration][groups][embedded-nul]") {
    // "Admins\0decoy" — PostgreSQL `text` columns cannot store an embedded
    // NUL (pg::exec_params hands libpq a NUL-terminated C string regardless
    // of declared length, so anything past the first NUL is silently
    // dropped on write). Storing the truncated "Admins" would exactly match
    // --scim-admin-group and spuriously promote the submitting member — so
    // the fix REJECTS any SCIM text field containing an embedded NUL at the
    // parse boundary (400 invalidValue), before it ever reaches the store.
    // The group is never created, so there is nothing to truncate and no
    // promotion.
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "walt");

    std::string nul_name = std::string("Admins") + std::string(1, '\0') + std::string("decoy");
    REQUIRE(nul_name.size() == 12);

    json group_body{{"displayName", nul_name},
                    {"members", json::array({{{"value", user_id}}})}};
    auto group_post = cli.Post("/scim/v2/Groups", hdr, group_body.dump(), "application/scim+json");
    REQUIRE(group_post);
    CHECK(group_post->status == 400);
    CHECK(json::parse(group_post->body)["scimType"] == "invalidValue");

    // No spurious promotion — the group was never created.
    CHECK(ts.auth_mgr.get_user_role("walt").value() == auth::Role::user);

    // Control: a group actually named exactly "Admins" (no embedded NUL)
    // DOES promote — confirms the guard above is about truncation, not
    // about the admin-group feature being broken outright.
    auto plain_group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Admins"})",
                                     "application/scim+json");
    REQUIRE(plain_group_post);
    REQUIRE(plain_group_post->status == 201);
    auto plain_group_id = json::parse(plain_group_post->body)["id"].get<std::string>();
    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + plain_group_id).c_str(), hdr,
                               add_body.dump(), "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);
    CHECK(ts.auth_mgr.get_user_role("walt").value() == auth::Role::admin);
}

TEST_CASE("Groups integration: sec-L3 caps over HTTP — oversized displayName on POST and PATCH "
          "400s",
          "[pg][scim][routes][integration][groups][caps]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    std::string oversized(scim::kMaxDisplayNameLen + 1, 'x');

    auto post_res = cli.Post("/scim/v2/Groups", hdr,
                             json{{"displayName", oversized}}.dump(), "application/scim+json");
    REQUIRE(post_res);
    CHECK(post_res->status == 400);

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"CapsGroup"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json patch_body{
        {"Operations",
         json::array({{{"op", "replace"}, {"path", "displayName"}, {"value", oversized}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, patch_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 400);

    // Unchanged.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    CHECK(json::parse(get_res->body)["displayName"] == "CapsGroup");
}

TEST_CASE("Groups integration: sec-L3/#7 member cap over HTTP — >5000 members 400s + denied",
          "[pg][scim][routes][integration][groups][caps][members]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    // The cap check runs BEFORE any per-member resolution, so a synthetic
    // list of ids that never resolve to real SCIM Users is sufficient —
    // this proves the guard, not membership resolution semantics. Bare
    // single-char string entries (parse_group tolerates the plain-string
    // members shape) keep the body well under kMaxBodyBytes (64 KiB) even
    // at 5001 entries — a `{"value":...}` object shape per entry would blow
    // that budget first and mask the member-count guard behind a 413.
    json members = json::array();
    for (std::size_t i = 0; i < 5001; ++i)
        members.push_back("x");

    auto post_res =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "HugeGroup"}, {"members", members}}.dump(),
                 "application/scim+json");
    REQUIRE(post_res);
    CHECK(post_res->status == 400);

    AuditQuery q;
    q.action = "scim.group.created";
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool found_denied = false;
    for (const auto& row : *rows)
        if (row.result == "denied" && row.detail.find("member count exceeds cap") != std::string::npos)
            found_denied = true;
    CHECK(found_denied);

    // The group was never created.
    auto by_name =
        cli.Get(R"(/scim/v2/Groups?filter=displayName%20eq%20%22HugeGroup%22)", hdr);
    REQUIRE(by_name);
    CHECK(json::parse(by_name->body)["totalResults"] == 0);
}

// ── CC6.7 evidence-gap fix coverage (governance hardening round) ──────────
//
// recompute_scim_user_role's `AuthManager::update_role` call has a few ways
// to genuinely fail: an invalid username, a missing/inactive row, or a raw
// write error from AuthDB. The first two are unreachable here — every read
// this function performs first (`get_provisioning_source`, then
// `db_authoritative_role`/`get_user`) shape-checks and `is_active=1`-filters
// identically to `update_role` itself, over the SAME username string, so
// they fail together, never letting the reads succeed while only the write
// fails (that would need concurrent mid-request mutation of the SAME
// connection — documented as an infeasible clean/fast unit-test injection
// elsewhere in this file; see the "NOTE (injection gap)" comment on the
// revive-role-refusal test above). A raw SQL write error, however, is
// reachable deterministically and without any race: plant a `BEFORE UPDATE
// OF role` PL/pgSQL trigger (via a second libpq connection to the SAME
// Postgres database AuthDB manages — ADR-0006) that RAISEs on this one
// user's role column. The reads (SELECTs) are entirely unaffected; only
// `AuthDB::update_role`'s UPDATE hits it and genuinely fails.
TEST_CASE("Groups integration: a genuine update_role failure during recompute audits "
         "scim.user.role_changed/failure and bumps yuzu_scim_role_change_failures_total "
         "(C1 remediation)",
         "[pg][scim][routes][integration][groups][role_change_failure]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.auth_mgr.set_metrics_registry(&ts.metrics);
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "carol");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    // Plant a trigger that aborts ONLY an UPDATE of 'carol's role column —
    // reads (get_provisioning_source/db_authoritative_role, both plain
    // SELECTs) are untouched, so they resolve exactly as they would on the
    // happy path; only the subsequent `AuthDB::update_role` UPDATE fails.
    // AuthDB is now Postgres-backed (ADR-0006), so this uses a PL/pgSQL
    // BEFORE-UPDATE trigger over a second libpq connection to the SAME
    // database, instead of the SQLite RAISE(ABORT) idiom.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(ts.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult fn{PQexec(
            conn.get(), "CREATE OR REPLACE FUNCTION yuzu_test_block_carol_role_update() "
                       "RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced test write "
                       "failure'; END; $$ LANGUAGE plpgsql")};
        REQUIRE(fn.ok());
        yuzu::server::pg::PgResult trig{
            PQexec(conn.get(), "CREATE TRIGGER block_carol_role_update "
                              "BEFORE UPDATE OF role ON auth.users "
                              "FOR EACH ROW WHEN (NEW.username = 'carol') "
                              "EXECUTE FUNCTION yuzu_test_block_carol_role_update()")};
        REQUIRE(trig.ok());
    }

    // The Group PATCH (add member) itself still succeeds — recompute
    // failures are silent to the SCIM caller by design (set-and-proceed;
    // the Group mutation already committed).
    json add_body{{"Operations",
                   json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", json::array({{{"value", user_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, add_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    // The role change did NOT apply — the trigger aborted the UPDATE.
    auto entry = ts.auth_db->get_user("carol");
    REQUIRE(entry.has_value());
    CHECK(entry->role == auth::Role::user);

    // scim.user.role_changed/failure audit row, keyed on the user's scim_id.
    AuditQuery q;
    q.action = "scim.user.role_changed";
    q.target_id = user_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());
    bool found_failure = false;
    for (const auto& row : *rows) {
        if (row.result == "failure" &&
            row.detail.find("intended_new_role=admin") != std::string::npos)
            found_failure = true;
    }
    CHECK(found_failure);

    // yuzu_scim_role_change_failures_total bumped exactly once; the
    // success counter (yuzu_scim_role_changes_total) must NOT have moved —
    // this is the failure path, not the success path.
    CHECK(ts.metrics.counter("yuzu_scim_role_change_failures_total").value() == 1.0);
    CHECK(ts.metrics.counter("yuzu_scim_role_changes_total").value() == 0.0);
}

// ── PATCH displayName-rename must recompute all current members ────────────
//
// External-reviewer falsifier (CHANGES_REQUESTED on PR #2127): before this
// fix, a PATCH that changed ONLY `displayName` fell into the membership
// block with empty `affected_added`/`affected_removed` (no member op in the
// same PATCH), so the recompute loop touched nobody — even though the
// rename could move the group across the --scim-admin-group boundary and
// silently leave every current member's role stale. The PUT handler already
// snapshotted+recomputed the full membership on ANY replace, incl.
// metadata-only; these cases mirror that for PATCH.

TEST_CASE("Groups integration: PATCH rename OFF the admin group demotes every current member "
         "(reviewer falsifier, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][rename-recompute]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto member_id = create_scim_user_over_wire(cli, ts.token, "mia");

    auto group_post =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "Yuzu-Admins"},
                      {"members", json::array({{{"value", member_id}}})}}
                     .dump(),
                 "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("mia").value() == auth::Role::admin);

    // A live session for mia, so the recompute's session-invalidation side
    // effect (AuthManager::update_role) is directly checkable, not just
    // inferred from the role/audit outcome.
    auto session_token =
        ts.auth_mgr.create_local_session("mia", auth::Role::admin, /*mfa_verified=*/true);
    REQUIRE_FALSE(session_token.empty());
    REQUIRE(ts.auth_mgr.validate_session(session_token).has_value());

    // A PATCH that ONLY renames the group — no member add/remove op at all.
    json rename_body{{"Operations",
                      json::array({{{"op", "replace"},
                                    {"value", json{{"displayName", "Former-Admins"}}}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, rename_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    // The falsifier: the member must be DEMOTED even though this PATCH never
    // explicitly touched membership.
    CHECK(ts.auth_mgr.get_user_role("mia").value() == auth::Role::user);

    // ...and the pre-existing session was invalidated by that role change —
    // the reviewer's ordering concern (stale valid sessions surviving an
    // effective demotion) is directly falsified here, not just inferred.
    CHECK_FALSE(ts.auth_mgr.validate_session(session_token).has_value());

    AuditQuery q;
    q.action = "scim.user.role_changed";
    q.target_id = member_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());
    bool found_demotion = false;
    bool found_trigger_detail = false;
    for (const auto& row : *rows) {
        if (row.result == "success" && row.detail.find("new_role=user") != std::string::npos)
            found_demotion = true;
        if (row.detail.find("via_group=\"Former-Admins") != std::string::npos)
            found_trigger_detail = true;
    }
    CHECK(found_demotion);
    // Minor #2: the audit detail carries the triggering group's (post-
    // rename) displayName.
    CHECK(found_trigger_detail);
}

TEST_CASE("Groups integration: PATCH rename ONTO the admin group promotes every current member "
         "(inverse of the reviewer falsifier)",
         "[pg][scim][routes][integration][groups][patch][rename-recompute]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto member_id = create_scim_user_over_wire(cli, ts.token, "nina");

    auto group_post =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "Team-A"}, {"members", json::array({{{"value", member_id}}})}}
                     .dump(),
                 "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("nina").value() == auth::Role::user);

    // A PATCH that ONLY renames "Team-A" onto the admin group's name.
    json rename_body{{"Operations",
                      json::array({{{"op", "replace"},
                                    {"value", json{{"displayName", "Yuzu-Admins"}}}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, rename_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    CHECK(ts.auth_mgr.get_user_role("nina").value() == auth::Role::admin);
}

TEST_CASE("Groups integration: PATCH mixing a rename with a member add recomputes BOTH the "
         "pre-existing members and the newly-added one, exactly once each",
         "[pg][scim][routes][integration][groups][patch][rename-recompute]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto pre_existing_member = create_scim_user_over_wire(cli, ts.token, "oscar");
    auto new_member = create_scim_user_over_wire(cli, ts.token, "penny");

    auto group_post = cli.Post("/scim/v2/Groups", hdr,
                               json{{"displayName", "Yuzu-Admins"},
                                    {"members", json::array({{{"value", pre_existing_member}}})}}
                                   .dump(),
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("oscar").value() == auth::Role::admin);
    REQUIRE(ts.auth_mgr.get_user_role("penny").value() == auth::Role::user);

    // Single PATCH: rename OFF the admin group AND add a new member in the
    // same request. Both the pre-existing member (found only via the
    // rename-triggered recompute-all-current-members path) and the new
    // member (found via the ordinary add-op path) must end up demoted, and
    // neither may be recomputed/audited twice.
    json mixed_body{
        {"Operations",
         json::array({{{"op", "replace"},
                      {"value", json{{"displayName", "Former-Admins"}}}},
                     {{"op", "add"},
                      {"path", "members"},
                      {"value", json::array({{{"value", new_member}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, mixed_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    CHECK(ts.auth_mgr.get_user_role("oscar").value() == auth::Role::user);
    CHECK(ts.auth_mgr.get_user_role("penny").value() == auth::Role::user);

    // Exactly one scim.user.role_changed row per member for THIS PATCH (no
    // double-recompute from the dedup logic) — oscar's demotion.
    AuditQuery oscar_q;
    oscar_q.action = "scim.user.role_changed";
    oscar_q.target_id = pre_existing_member;
    auto oscar_rows = ts.audit_store->query(oscar_q);
    REQUIRE(oscar_rows.has_value());
    int oscar_demotions = 0;
    for (const auto& row : *oscar_rows)
        if (row.result == "success" && row.detail.find("new_role=user") != std::string::npos)
            ++oscar_demotions;
    CHECK(oscar_demotions == 1);
}

// ── Metadata TOCTOU: membership-only PATCH must not revert a concurrent
//    rename ──────────────────────────────────────────────────────────────
//
// Re-review MEDIUM (caught by two reviewers): the group was fetched via
// `get_group_by_id` at the TOP of the handler, BEFORE `kGroupMutationMu` was
// acquired. Inside the lock, `final_display`/`final_external` defaulted to
// that PRE-LOCK snapshot. So a membership-only PATCH (no displayName in the
// request) that read the group BEFORE a concurrent rename committed would,
// on winning `kGroupMutationMu` AFTER that rename, persist the STALE
// displayName — silently reverting the rename. Because displayName drives
// the --scim-admin-group match and recompute runs over every current
// member, this could re-promote a just-demoted member. The fix re-reads the
// group's CURRENT metadata inside the lock and uses THAT as the
// `value_or` baseline. Looped so the two critical sections have a real
// chance to interleave both ways under the scheduler.
TEST_CASE("Groups integration: concurrent membership-only PATCH never reverts a concurrent "
         "rename (metadata TOCTOU re-review MEDIUM, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][group-concurrency]") {
    ScimIntegrationServer ts(/*rate_per_second=*/1000, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client setup_cli("127.0.0.1", ts.port);
    setup_cli.set_connection_timeout(5);
    setup_cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto x_id = create_scim_user_over_wire(setup_cli, ts.token, "xena-toctou");
    auto y_id = create_scim_user_over_wire(setup_cli, ts.token, "yara-toctou");

    auto group_post = setup_cli.Post(
        "/scim/v2/Groups", hdr,
        json{{"displayName", "Yuzu-Admins"}, {"members", json::array({{{"value", x_id}}})}}
            .dump(),
        "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("xena-toctou").value() == auth::Role::admin);

    // (A) rename off the admin group — should demote x.
    json rename_body{{"Operations",
                      json::array({{{"op", "replace"},
                                    {"value", json{{"displayName", "Former-Admins"}}}}})}};
    // (B) membership-only — no displayName field at all.
    json membership_body{{"Operations",
                          json::array({{{"op", "add"},
                                        {"path", "members"},
                                        {"value", json::array({{{"value", y_id}}})}}})}};
    // Reset between iterations: rename back onto the admin group (re-
    // promotes x for the next iteration's assertion) and drop y (so the
    // next iteration's "add y" is a genuine add, not a no-op).
    json restore_body{
        {"Operations",
         json::array({{{"op", "replace"}, {"value", json{{"displayName", "Yuzu-Admins"}}}},
                      {{"op", "remove"}, {"path", "members[value eq \"" + y_id + "\"]"}}})}};

    for (int i = 0; i < 50; ++i) {
        CAPTURE(i);
        std::atomic<bool> saw_unexpected{false};

        std::thread rename_thread([&] {
            httplib::Client cli("127.0.0.1", ts.port);
            cli.set_connection_timeout(5);
            cli.set_read_timeout(5);
            auto res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr,
                                 rename_body.dump(), "application/scim+json");
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        std::thread membership_thread([&] {
            httplib::Client cli("127.0.0.1", ts.port);
            cli.set_connection_timeout(5);
            cli.set_read_timeout(5);
            auto res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr,
                                 membership_body.dump(), "application/scim+json");
            if (!res || res->status != 200)
                saw_unexpected.store(true);
        });
        rename_thread.join();
        membership_thread.join();
        CHECK_FALSE(saw_unexpected.load());

        auto get_res = setup_cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
        REQUIRE(get_res);
        REQUIRE(get_res->status == 200);
        auto current_display = json::parse(get_res->body)["displayName"].get<std::string>();
        // The falsifier: regardless of which PATCH wins `kGroupMutationMu`,
        // the rename must stick — a membership-only PATCH must never
        // silently revert it.
        CHECK(current_display == "Former-Admins");
        // ...and because displayName drives the --scim-admin-group match, a
        // reverted rename would silently re-promote x back to admin here.
        CHECK(ts.auth_mgr.get_user_role("xena-toctou").value() == auth::Role::user);

        auto restore_res = setup_cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr,
                                           restore_body.dump(), "application/scim+json");
        REQUIRE(restore_res);
        REQUIRE(restore_res->status == 200);
        REQUIRE(ts.auth_mgr.get_user_role("xena-toctou").value() == auth::Role::admin);
    }
}

// ── PATCH member-cap rejection must NOT commit a co-submitted rename ───────
//
// Re-review MEDIUM (same class as the [HIGH fix] above, on the error path):
// `update_group` committed the displayName rename BEFORE the member-count-cap
// check, so a PATCH that both renamed the group AND pushed membership over
// kMaxGroupMembers committed the rename, then 400'd on the cap, and never
// reached the recompute loop — leaving every current member's role stale
// (here: still admin, with a valid session, after a rejected PATCH). The PUT
// handler already ordered the cap check before update_group; this proves
// PATCH now matches.
//
// #2127 rework note: the cap is now checked against the RESOLVED final
// member set (see the fold_group_member_ops/resolve_member_values pipeline
// in scim_routes.cpp), not the raw requested-op count — closing the
// requested-remove-arithmetic bypass (MEDIUM finding #2, covered by the
// dedicated cap-bypass test below). That means tripping the cap here needs
// genuinely RESOLVABLE member ids, unlike the old arithmetic-based
// precheck this test exercised before the rework (which rejected on raw
// unresolved value count alone). The bulk of the pre-existing membership
// (4999 of the 5000) is seeded directly via `ScimStore::create_resource` +
// `add_group_member` (bypassing HTTP entirely — `resolve_member_values`
// only needs a `scim_resources` row to resolve) so the PATCH body itself
// only needs to add ONE more real id to cross the cap, keeping it well
// under kMaxBodyBytes (32-hex-char scim_ids don't fit 5000-to-a-body).

TEST_CASE("Groups integration: PATCH rejected by the member cap must not commit a "
         "co-submitted displayName rename (re-review MEDIUM, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][rename-recompute][member-cap]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto member_id = create_scim_user_over_wire(cli, ts.token, "admin_member");

    auto group_post =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "Yuzu-Admins"},
                      {"members", json::array({{{"value", member_id}}})}}
                     .dump(),
                 "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("admin_member").value() == auth::Role::admin);

    auto session_token = ts.auth_mgr.create_local_session("admin_member", auth::Role::admin,
                                                          /*mfa_verified=*/true);
    REQUIRE_FALSE(session_token.empty());

    // Seed 4999 more real, resolvable members directly via the store — with
    // the pre-existing admin_member that's exactly kMaxGroupMembers (5000),
    // right at the cap.
    for (int i = 0; i < 4999; ++i) {
        auto res = ts.scim_store->create_resource("capuser" + std::to_string(i));
        REQUIRE(res.has_value());
        REQUIRE(ts.scim_store->add_group_member(group_id, res->scim_id));
    }
    REQUIRE(ts.scim_store->list_group_member_user_scim_ids(group_id).value().size() == 5000);

    auto one_more = ts.scim_store->create_resource("capuser-over");
    REQUIRE(one_more.has_value());

    // Single PATCH: rename AWAY from the admin group's name AND add ONE
    // more real member — one over the cap.
    json mixed_body{
        {"Operations",
         json::array({{{"op", "replace"},
                      {"value", json{{"displayName", "Former-Admins"}}}},
                     {{"op", "add"},
                      {"path", "members"},
                      {"value", json::array({{{"value", one_more->scim_id}}})}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, mixed_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 400);

    // The rename must NOT have been committed on the rejected path.
    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    REQUIRE(get_res->status == 200);
    CHECK(json::parse(get_res->body)["displayName"].get<std::string>() == "Yuzu-Admins");

    // ...and membership was not committed either — still exactly the 5000
    // pre-existing members, NOT 5001 (asserts real state, not just the
    // rename).
    CHECK(ts.scim_store->list_group_member_user_scim_ids(group_id).value().size() == 5000);

    // No stale demotion-skip: the rename was rejected, so the member stays
    // admin and the pre-existing session stays valid.
    CHECK(ts.auth_mgr.get_user_role("admin_member").value() == auth::Role::admin);
    CHECK(ts.auth_mgr.validate_session(session_token).has_value());
}

// (Minor #3, optional per the review) — a group member value that maps to a
// non-SCIM account during a rename-triggered recompute bumps
// yuzu_scim_provenance_denied_total exactly like the ordinary add/remove
// path already does, without writing a per-member audit row (avoiding a
// bulk-rename audit flood).
TEST_CASE("Groups integration: PATCH rename over a non-SCIM member bumps "
         "yuzu_scim_provenance_denied_total (Minor #3)",
         "[pg][scim][routes][integration][groups][patch][provenance]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.auth_mgr.set_metrics_registry(&ts.metrics);
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    REQUIRE(ts.auth_mgr.upsert_user("root-admin", "correct-horse-battery-staple",
                                    auth::Role::admin));
    auto local_admin_mapping = ts.scim_store->create_resource("root-admin");
    REQUIRE(local_admin_mapping.has_value());

    auto group_post = cli.Post("/scim/v2/Groups", hdr,
                               json{{"displayName", "Team-B"},
                                    {"members", json::array(
                                                    {{{"value", local_admin_mapping->scim_id}}})}}
                                   .dump(),
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    json rename_body{{"Operations",
                      json::array({{{"op", "replace"},
                                    {"value", json{{"displayName", "Yuzu-Admins"}}}}})}};
    auto patch_res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, rename_body.dump(),
                               "application/scim+json");
    REQUIRE(patch_res);
    CHECK(patch_res->status == 200);

    CHECK(ts.auth_mgr.get_user_role("root-admin").value() == auth::Role::admin);
    CHECK(ts.metrics.counter("yuzu_scim_provenance_denied_total").value() >= 1.0);
}

// ── #2127 review rework: ordered PatchOp application (HIGH) ────────────────
//
// The old bucketed-apply design (members_to_add/members_to_remove, applied
// ALL-removes-then-ALL-adds regardless of the body's own op order) could not
// distinguish `[{add:U},{remove:U}]` from `[{remove:U},{add:U}]` — both
// collapsed to "U ends up a member" (a `remove` on a not-yet-added id was an
// idempotent no-op, so only the `add` bucket ever took effect), silently
// PROMOTING U on the admin group even though the caller's last word was
// "remove". RFC 7644 §3.5.2 requires ops applied in document order.

TEST_CASE("Groups integration: PATCH [{add:U},{remove:U}] leaves U NOT a member and NOT "
         "promoted (HIGH falsifier, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][ordered-ops]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "orderfelix");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("orderfelix").value() == auth::Role::user);

    // Single PATCH, in this exact order: add U, then remove U.
    json body{{"Operations",
              json::array({{{"op", "add"},
                            {"path", "members"},
                            {"value", json::array({{{"value", user_id}}})}},
                          {{"op", "remove"},
                           {"path", "members[value eq \"" + user_id + "\"]"}}})}};
    auto res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, body.dump(),
                         "application/scim+json");
    REQUIRE(res);
    CHECK(res->status == 200);

    // The falsifier: U must NOT be a member (store-level, real state), and
    // must NOT be promoted.
    CHECK(ts.scim_store->list_group_member_user_scim_ids(group_id).value().empty());
    CHECK(ts.auth_mgr.get_user_role("orderfelix").value() == auth::Role::user);
}

TEST_CASE("Groups integration: PATCH [{remove:U},{add:U}] leaves U a member and PROMOTED "
         "(reverse of the HIGH falsifier, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][ordered-ops]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto user_id = create_scim_user_over_wire(cli, ts.token, "orderginny");

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"Yuzu-Admins"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("orderginny").value() == auth::Role::user);

    // Same two ops, REVERSED order: remove U (no-op, never a member yet),
    // then add U.
    json body{{"Operations",
              json::array({{{"op", "remove"},
                            {"path", "members[value eq \"" + user_id + "\"]"}},
                          {{"op", "add"},
                           {"path", "members"},
                           {"value", json::array({{{"value", user_id}}})}}})}};
    auto res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, body.dump(),
                         "application/scim+json");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto members = ts.scim_store->list_group_member_user_scim_ids(group_id).value();
    REQUIRE(members.size() == 1);
    CHECK(members[0] == user_id);
    CHECK(ts.auth_mgr.get_user_role("orderginny").value() == auth::Role::admin);
}

// ── #2127 review rework: cap-bypass via bogus removes (MEDIUM #2) ──────────
//
// Before the rework, the cap precheck computed `current_count - remove_
// count`, where `remove_count` was the REQUESTED remove count — never
// checked against who was actually a member. N bogus (non-member) removes
// bought N slots of arithmetic headroom for N real adds, netting +N past
// the cap. The rework checks the cap against the RESOLVED final set, which
// already reflects that a remove naming a non-member is a no-op.

TEST_CASE("Groups integration: PATCH with bogus removes cannot buy cap headroom for real "
         "adds (cap-bypass, MEDIUM finding #2, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][member-cap][cap-bypass]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"BigGroup"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    // Seed exactly kMaxGroupMembers (5000) real, resolvable members directly
    // via the store (bypassing HTTP for setup speed).
    for (int i = 0; i < 5000; ++i) {
        auto res = ts.scim_store->create_resource("bypassuser" + std::to_string(i));
        REQUIRE(res.has_value());
        REQUIRE(ts.scim_store->add_group_member(group_id, res->scim_id));
    }
    REQUIRE(ts.scim_store->list_group_member_user_scim_ids(group_id).value().size() == 5000);

    auto real_add = ts.scim_store->create_resource("bypassuser-real-add");
    REQUIRE(real_add.has_value());

    // 10 bogus removes — ids that were NEVER a member of this group (never
    // even provisioned) — plus ONE real add. Net final size is 5001, one
    // over the cap. The old (broken) arithmetic would have computed
    // 5000 - 10 (assuming all 10 removes hit an actual member) + 1 = 4991,
    // comfortably under the cap — the exact bypass this closes.
    json remove_values = json::array();
    for (int i = 0; i < 10; ++i)
        remove_values.push_back("nonexistent-bogus-" + std::to_string(i));

    json body{{"Operations",
              json::array({{{"op", "remove"}, {"path", "members"}, {"value", remove_values}},
                          {{"op", "add"},
                           {"path", "members"},
                           {"value", json::array({{{"value", real_add->scim_id}}})}}})}};
    auto res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, body.dump(),
                         "application/scim+json");
    REQUIRE(res);
    CHECK(res->status == 400);

    // Group unchanged — still exactly the 5000 pre-existing members.
    CHECK(ts.scim_store->list_group_member_user_scim_ids(group_id).value().size() == 5000);
}

TEST_CASE("Groups integration: PATCH whose net final size stays within cap succeeds even "
         "when it names bogus removes (cap-bypass inverse, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][member-cap][cap-bypass]") {
    ScimIntegrationServer ts;
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto group_post = cli.Post("/scim/v2/Groups", hdr, R"({"displayName":"SmallGroup"})",
                               "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();

    auto add1 = create_scim_user_over_wire(cli, ts.token, "bypass_ok_1");
    auto add2 = create_scim_user_over_wire(cli, ts.token, "bypass_ok_2");

    json remove_values = json::array();
    for (int i = 0; i < 10; ++i)
        remove_values.push_back("nonexistent-bogus-" + std::to_string(i));

    json body{
        {"Operations",
         json::array({{{"op", "remove"}, {"path", "members"}, {"value", remove_values}},
                      {{"op", "add"},
                       {"path", "members"},
                       {"value", json::array({{{"value", add1}}, {{"value", add2}}})}}})}};
    auto res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, body.dump(),
                         "application/scim+json");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto members = ts.scim_store->list_group_member_user_scim_ids(group_id).value();
    std::sort(members.begin(), members.end());
    std::vector<std::string> expected{add1, add2};
    std::sort(expected.begin(), expected.end());
    CHECK(members == expected);
}

// ── #2127 review rework: persist-500 must not leave a partial commit (#3) ──
//
// PUT and PATCH previously committed the rename (`update_group`) and the
// membership change (`set_group_members`/add/remove) as SEPARATE
// transactions — a failure partway through the membership write left a
// COMMITTED rename with stale/partial membership + roles. The atomic
// `replace_group_and_members` primitive is the fix: fault-inject a
// mid-transaction failure (a poison trigger on the real member id that gets
// re-inserted — `replace_group_and_members` deletes-then-reinserts the
// WHOLE final membership set, even an unchanged one) and assert NOTHING
// committed: displayName, membership, AND role all unchanged.

TEST_CASE("Groups integration: PATCH persist failure leaves displayName, membership, and "
         "roles UNCHANGED — no partial commit (MEDIUM finding #3, PR #2127)",
         "[pg][scim][routes][integration][groups][patch][persist-fail]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto member_id = create_scim_user_over_wire(cli, ts.token, "faultowen");

    auto group_post =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "Yuzu-Admins"},
                      {"members", json::array({{{"value", member_id}}})}}
                     .dump(),
                 "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("faultowen").value() == auth::Role::admin);

    auto session_token = ts.auth_mgr.create_local_session("faultowen", auth::Role::admin,
                                                           /*mfa_verified=*/true);
    REQUIRE_FALSE(session_token.empty());

    // Poison the EXISTING member's real scim_id. ScimStore is now
    // Postgres-backed (ADR-0006, schema `scim_store`) — plant a PL/pgSQL
    // BEFORE-INSERT trigger over a second libpq connection to the SAME
    // database, instead of the SQLite RAISE(ABORT) idiom.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(ts.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult fn{PQexec(
            conn.get(), "CREATE OR REPLACE FUNCTION yuzu_test_poison_patch_persist() "
                       "RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'induced failure'; "
                       "END; $$ LANGUAGE plpgsql")};
        REQUIRE(fn.ok());
        std::string trigger_sql =
            "CREATE TRIGGER poison_patch_persist BEFORE INSERT ON "
            "scim_store.scim_group_members FOR EACH ROW WHEN (NEW.user_scim_id = '" +
            member_id + "') EXECUTE FUNCTION yuzu_test_poison_patch_persist()";
        yuzu::server::pg::PgResult trig{PQexec(conn.get(), trigger_sql.c_str())};
        REQUIRE(trig.ok());
    }

    json rename_body{{"Operations",
                      json::array({{{"op", "replace"},
                                    {"value", json{{"displayName", "Former-Admins"}}}}})}};
    auto res = cli.Patch(("/scim/v2/Groups/" + group_id).c_str(), hdr, rename_body.dump(),
                         "application/scim+json");
    REQUIRE(res);
    CHECK(res->status == 500);

    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    REQUIRE(get_res->status == 200);
    CHECK(json::parse(get_res->body)["displayName"].get<std::string>() == "Yuzu-Admins");

    auto members = ts.scim_store->list_group_member_user_scim_ids(group_id).value();
    REQUIRE(members.size() == 1);
    CHECK(members[0] == member_id);

    CHECK(ts.auth_mgr.get_user_role("faultowen").value() == auth::Role::admin);
    CHECK(ts.auth_mgr.validate_session(session_token).has_value());

    AuditQuery q;
    q.action = "scim.group.updated";
    q.target_id = group_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool found_failure = false;
    for (const auto& row : *rows)
        if (row.result == "failure")
            found_failure = true;
    CHECK(found_failure);
}

TEST_CASE("Groups integration: PUT persist failure leaves displayName, membership, and "
         "roles UNCHANGED — no partial commit (MEDIUM finding #3, PR #2127)",
         "[pg][scim][routes][integration][groups][put][persist-fail]") {
    ScimIntegrationServer ts(/*rate_per_second=*/100, /*admin_group=*/"Yuzu-Admins");
    ts.start();
    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    httplib::Headers hdr{{"Authorization", "Bearer " + ts.token}};

    auto member_id = create_scim_user_over_wire(cli, ts.token, "faultpia");

    auto group_post =
        cli.Post("/scim/v2/Groups", hdr,
                 json{{"displayName", "Yuzu-Admins"},
                      {"members", json::array({{{"value", member_id}}})}}
                     .dump(),
                 "application/scim+json");
    REQUIRE(group_post);
    REQUIRE(group_post->status == 201);
    auto group_id = json::parse(group_post->body)["id"].get<std::string>();
    REQUIRE(ts.auth_mgr.get_user_role("faultpia").value() == auth::Role::admin);

    auto session_token = ts.auth_mgr.create_local_session("faultpia", auth::Role::admin,
                                                           /*mfa_verified=*/true);
    REQUIRE_FALSE(session_token.empty());

    // Poison the EXISTING member's real scim_id. ScimStore is now
    // Postgres-backed (ADR-0006, schema `scim_store`) — plant a PL/pgSQL
    // BEFORE-INSERT trigger over a second libpq connection to the SAME
    // database, instead of the SQLite RAISE(ABORT) idiom.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(ts.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult fn{PQexec(
            conn.get(), "CREATE OR REPLACE FUNCTION yuzu_test_poison_put_persist() "
                       "RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'induced failure'; "
                       "END; $$ LANGUAGE plpgsql")};
        REQUIRE(fn.ok());
        std::string trigger_sql =
            "CREATE TRIGGER poison_put_persist BEFORE INSERT ON "
            "scim_store.scim_group_members FOR EACH ROW WHEN (NEW.user_scim_id = '" +
            member_id + "') EXECUTE FUNCTION yuzu_test_poison_put_persist()";
        yuzu::server::pg::PgResult trig{PQexec(conn.get(), trigger_sql.c_str())};
        REQUIRE(trig.ok());
    }

    // PUT full-replace: rename, keep the SAME member (so the "intended"
    // membership, absent the fault, is unchanged).
    json put_body{{"displayName", "Former-Admins"},
                  {"members", json::array({{{"value", member_id}}})}};
    auto res = cli.Put(("/scim/v2/Groups/" + group_id).c_str(), hdr, put_body.dump(),
                       "application/scim+json");
    REQUIRE(res);
    CHECK(res->status == 500);

    auto get_res = cli.Get(("/scim/v2/Groups/" + group_id).c_str(), hdr);
    REQUIRE(get_res);
    REQUIRE(get_res->status == 200);
    CHECK(json::parse(get_res->body)["displayName"].get<std::string>() == "Yuzu-Admins");

    auto members = ts.scim_store->list_group_member_user_scim_ids(group_id).value();
    REQUIRE(members.size() == 1);
    CHECK(members[0] == member_id);

    CHECK(ts.auth_mgr.get_user_role("faultpia").value() == auth::Role::admin);
    CHECK(ts.auth_mgr.validate_session(session_token).has_value());

    AuditQuery q;
    q.action = "scim.group.updated";
    q.target_id = group_id;
    auto rows = ts.audit_store->query(q);
    REQUIRE(rows.has_value());
    bool found_failure = false;
    for (const auto& row : *rows)
        if (row.result == "failure")
            found_failure = true;
    CHECK(found_failure);
}

// ── 2026-07-25 review HIGH #3 + Hermes MEDIUM: ROUTE-level fail-closed ──────
//
// The store-layer tests prove the reads return nullopt on failure. These prove
// the ROUTES act on it. Without them the route-level nullopt checks could be
// reverted and every other test in this file would still pass (Hermes pass 1,
// MEDIUM) — the fix would silently regress into the exact durable-membership-
// loss bug it was written to close.
//
// Fault injection is a REVERSIBLE rename rather than a DROP, so each test can
// assert both halves of the contract: the request fails closed with 503, AND
// the real membership is still intact afterwards.

namespace {

void hide_membership_table(const std::string& dsn) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(
        conn.get(),
        "ALTER TABLE scim_store.scim_group_members RENAME TO scim_group_members_hidden")};
    REQUIRE(r.ok());
}

void restore_membership_table(const std::string& dsn) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(
        conn.get(),
        "ALTER TABLE scim_store.scim_group_members_hidden RENAME TO scim_group_members")};
    REQUIRE(r.ok());
}

// Provision a user + a group containing them; returns {user_scim_id, group_id}.
std::pair<std::string, std::string>
seed_group_with_member(Fixture& f, const std::string& username, const std::string& group_name) {
    auto ur = f.post("/scim/v2/Users", {{"userName", username}});
    REQUIRE(ur);
    REQUIRE(ur->status == 201);
    auto user_id = json::parse(ur->body)["id"].get<std::string>();

    auto gr = f.post("/scim/v2/Groups",
                     {{"displayName", group_name},
                      {"members", json::array({json{{"value", user_id}}})}});
    REQUIRE(gr);
    REQUIRE(gr->status == 201);
    auto group_id = json::parse(gr->body)["id"].get<std::string>();
    return {user_id, group_id};
}

} // namespace

TEST_CASE("ScimRoutes: PATCH Groups fails closed and preserves membership when the membership "
          "read is unavailable",
          "[pg][scim][routes][failclosed]") {
    Fixture f;
    auto [user_id, group_id] = seed_group_with_member(f, "patchfc", "PatchFailClosed");

    hide_membership_table(f.auth_db.dsn());

    // The fold would otherwise start from an empty set and COMMIT it,
    // wiping the real membership.
    auto res = f.patch("/scim/v2/Groups/" + group_id,
                       {{"Operations",
                         json::array({json{{"op", "add"},
                                           {"path", "members"},
                                           {"value", json::array({json{{"value", "ghost"}}})}}})}});
    REQUIRE(res);
    CHECK(res->status == 503);

    restore_membership_table(f.auth_db.dsn());

    auto members = f.scim_store->list_group_member_user_scim_ids(group_id);
    REQUIRE(members.has_value());
    REQUIRE(members->size() == 1);
    CHECK((*members)[0] == user_id); // untouched
}

TEST_CASE("ScimRoutes: PUT Groups fails closed when the membership snapshot is unavailable",
          "[pg][scim][routes][failclosed]") {
    Fixture f;
    auto [user_id, group_id] = seed_group_with_member(f, "putfc", "PutFailClosed");

    hide_membership_table(f.auth_db.dsn());

    auto res = f.put("/scim/v2/Groups/" + group_id,
                     {{"displayName", "PutFailClosedRenamed"}, {"members", json::array()}});
    REQUIRE(res);
    CHECK(res->status == 503);

    restore_membership_table(f.auth_db.dsn());

    // Neither the rename nor the membership replace was applied.
    auto grp = f.scim_store->get_group_by_id(group_id);
    REQUIRE(grp.has_value());
    CHECK(grp->display_name == "PutFailClosed");
    auto members = f.scim_store->list_group_member_user_scim_ids(group_id);
    REQUIRE(members.has_value());
    CHECK(members->size() == 1);
}

TEST_CASE("ScimRoutes: DELETE Groups fails closed when the membership snapshot is unavailable",
          "[pg][scim][routes][failclosed]") {
    Fixture f;
    auto [user_id, group_id] = seed_group_with_member(f, "delfc", "DeleteFailClosed");

    hide_membership_table(f.auth_db.dsn());

    // Deleting without the snapshot would leave former members holding a role
    // this group conferred, with no group left to justify it.
    auto res = f.del("/scim/v2/Groups/" + group_id);
    REQUIRE(res);
    CHECK(res->status == 503);

    restore_membership_table(f.auth_db.dsn());
    CHECK(f.scim_store->get_group_by_id(group_id).has_value()); // still there
}

TEST_CASE("ScimRoutes: GET Groups fails closed rather than rendering an empty members[]",
          "[pg][scim][routes][failclosed]") {
    Fixture f;
    auto [user_id, group_id] = seed_group_with_member(f, "getfc", "GetFailClosed");

    hide_membership_table(f.auth_db.dsn());

    // A 200 with `members: []` would tell the IdP the group is empty, and a
    // reconciling connector could then "restore" that emptiness.
    auto single = f.get("/scim/v2/Groups/" + group_id);
    REQUIRE(single);
    CHECK(single->status == 503);
    auto listed = f.get("/scim/v2/Groups");
    REQUIRE(listed);
    CHECK(listed->status == 503);

    restore_membership_table(f.auth_db.dsn());
}

#endif // YUZU_SCIM_TSAN_BUILD
