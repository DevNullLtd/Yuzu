/**
 * test_authz_topology_floor.cpp — coverage for the #2376 "topology floor":
 * a fresh install runs with RBAC OFF, and with RBAC off
 * `AuthRoutes::require_permission`/`require_scoped_permission` fall through
 * to a legacy branch that allows every `Read` to any authenticated
 * non-engine session. That legacy rule handed a plain `user` fleet-wide read
 * of the authorization TOPOLOGY itself — the access-review export (SOC 2
 * CC6.2 evidence), the RBAC role graph, and the engine-principal grant
 * graph. `authz_topology_floor.hpp`'s `kTopologyFloor` set closes exactly
 * that gap, and ONLY inside the RBAC-off legacy fallback — it must never run
 * ahead of (or instead of) a live RBAC grant, or it destroys the very
 * `Reviewer`/`AccessReview:Read` carve-out #2324 cut the securable for.
 *
 * See `server/core/src/authz_topology_floor.hpp` for the full rationale and
 * `server/core/src/auth_routes.cpp`'s two (require_permission/
 * require_scoped_permission) legacy-branch call sites.
 */

#include "auth_routes.hpp"
#include "authz_topology_floor.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "dashboard_api_routes.hpp"
#include "engine_principal_store.hpp"
#include "forensics_visibility.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg
#include "test_mgmt_group_pg_helper.hpp" // ManagementGroupStorePg
#include "test_rbac_store_pg_helper.hpp" // PG-backed RbacStore (ADR-0041)
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <httplib.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <set>
#include <thread>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

// AuditStore migrated to Postgres (ADR-0006) — mirrors
// test_auth_routes_hardened.cpp's HardenedHarness: a template-cloned
// ephemeral database + pool, cached once and cloned per fixture
// construction (12 TEST_CASEs below construct FloorFixture, so re-migrating
// from scratch each time would be wasteful). SKIPs the enclosing TEST_CASE
// when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken.
yuzu::test::PgTestTemplate authz_floor_audit_tpl{"authzflooraudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("authzflooraudit template: store failed to migrate");
}};

/// Wires a real SQLite-backed RbacStore + Postgres-backed AuditStore (ADR-0040)
/// behind AuthRoutes, so each test only has to mint a cookie session and call
/// require_permission/require_scoped_permission directly — no ApiTokenStore
/// (also PG-backed) or engine-principal machinery needed for the human-session
/// matrix below (`api_token_store=nullptr`; AuthRoutes null-guards it, and
/// resolve_session's cookie branch never touches it — mirrors
/// test_auth_routes_hardened.cpp's HardenedHarness).
struct FloorFixture {
    // RbacStore is a PG store (ADR-0041); the bundle SKIPs the TEST_CASE when
    // YUZU_TEST_POSTGRES_DSN is unset — declared first so that SKIP fires
    // before any other member construction. Every FloorFixture-constructing
    // TEST_CASE carries the `[pg]` tag.
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac_store = *rbac_bundle;
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    auth::AuthManager auth_mgr{};
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool> audit_pool;
    std::unique_ptr<AuditStore> audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;

    FloorFixture() {
        REQUIRE(rbac_store.is_open());
        audit_db.emplace(authz_floor_audit_tpl);
        INFO("[FloorFixture] audit db status (blank == ok): " << audit_db->error());
        REQUIRE(audit_db->available());
        audit_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit_store = std::make_unique<AuditStore>(*audit_pool);
        REQUIRE(audit_store->is_open());
        auth_mgr.set_metrics_registry(&metrics);
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac_store,
                                          /*api_token_store=*/nullptr, audit_store.get(),
                                          /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    }

    /// Mint a cookie-authenticated request for a fresh user carrying the
    /// given legacy role. Each call needs a distinct `username` (AuthManager
    /// is keyed by username).
    httplib::Request session_request(const std::string& username, auth::Role role) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", role));
        auto token = auth_mgr.create_local_session_for_test(username, role, /*mfa_verified=*/true);
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }

    /// Same as `session_request`, but the returned session carries an active
    /// JIT admin elevation (mirrors the production `/api/v1/elevate` route,
    /// minus the eligibility/MFA-step-up gates that route itself owns —
    /// `elevate_session`'s own contract puts eligibility on the caller).
    httplib::Request elevated_session_request(const std::string& username) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", auth::Role::user));
        auto token = auth_mgr.create_local_session_for_test(username, auth::Role::user, /*mfa_verified=*/true);
        REQUIRE(auth_mgr.elevate_session(token, std::chrono::seconds(300)).has_value());
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }
};

/// Literal, INDEPENDENT copy of the documented floored pairs — used by
/// every test below that needs to enumerate "the floored set" for anything
/// other than `topology_floor_applies` itself. Deliberately NOT derived from
/// `kTopologyFloor`: a test that iterates the production array to build its
/// own expectations shrinks in lockstep with an accidentally-shrunk array
/// and silently stops covering the missing entry (a false-green closure —
/// verified: the very failure mode this file's mutation-test evidence
/// exists to rule out). Only the cardinality/membership test above is
/// allowed to reference `kTopologyFloor` directly.
struct FloorPair {
    const char* securable;
    const char* operation;
};
constexpr FloorPair kExpectedFloorPairs[] = {
    {"AccessReview", "Read"},
    {"UserManagement", "Read"},
    {"EnginePrincipal", "Read"},
    // #4028 (api-parity programme #2146) — Settings read-twins.
    {"TlsConfig", "Read"},
    {"PluginSigning", "Read"},
    {"ServerConfig", "Read"},
    {"AnalyticsConfig", "Read"},
    // #4031: Enrollment/OidcConfig moved off admin_fn_ onto perm_fn_ with a
    // freshly-minted Administrator-only securable — floored so RBAC-off
    // doesn't silently widen admin-only to any-authenticated-user.
    {"Enrollment", "Read"},
    {"OidcConfig", "Read"},
    // Wave 7 PR7.2 (app_usage) — see authz_topology_floor.hpp's kTopologyFloor
    // comment for the rationale.
    {"Forensics", "Read"},
    // #5771 — the audit trail (evidence-grade data).
    {"AuditLog", "Read"},
};

} // namespace

// ── 1. Lock the set ──────────────────────────────────────────────────────

TEST_CASE("topology_floor_applies: exactly the eleven documented pairs are floored",
          "[authz][floor]") {
    // Positive: the eleven floored pairs (a change to kTopologyFloor's
    // MEMBERSHIP must break these). #4028 (api-parity programme #2146)
    // added the four Settings read-twin securables to the original three;
    // #4031 added Enrollment/OidcConfig; Wave 7 PR7.2 added Forensics; #5771
    // added AuditLog:Read — see authz_topology_floor.hpp's file-header note
    // on why these PRs extended this floor beyond its original
    // "authorization topology" framing.
    CHECK(topology_floor_applies("AccessReview", "Read"));
    CHECK(topology_floor_applies("UserManagement", "Read"));
    CHECK(topology_floor_applies("EnginePrincipal", "Read"));
    CHECK(topology_floor_applies("TlsConfig", "Read"));
    CHECK(topology_floor_applies("PluginSigning", "Read"));
    CHECK(topology_floor_applies("ServerConfig", "Read"));
    CHECK(topology_floor_applies("AnalyticsConfig", "Read"));
    CHECK(topology_floor_applies("Enrollment", "Read"));
    CHECK(topology_floor_applies("OidcConfig", "Read"));
    CHECK(topology_floor_applies("Forensics", "Read"));
    CHECK(topology_floor_applies("AuditLog", "Read"));

    // Negative: a representative spread of pairs that must NOT be floored —
    // proves the set is narrow, not "every Read" or "every op on these
    // securables".
    CHECK_FALSE(topology_floor_applies("Infrastructure", "Read"));
    CHECK_FALSE(topology_floor_applies("Security", "Read"));
    CHECK_FALSE(topology_floor_applies("AccessReview", "Attest"));
    CHECK_FALSE(topology_floor_applies("UserManagement", "Write"));
    CHECK_FALSE(topology_floor_applies("TlsConfig", "Write"));
    CHECK_FALSE(topology_floor_applies("PluginConfig", "Read")); // unrelated securable, not floored
    CHECK_FALSE(topology_floor_applies("Directory", "Read")); // #4031: NOT floored, see PR notes
    CHECK_FALSE(topology_floor_applies("Enrollment", "Write"));
    CHECK_FALSE(topology_floor_applies("Forensics", "Write"));
    CHECK_FALSE(topology_floor_applies("AuditLog", "Write")); // #5771: the READ pair only

    // Cardinality lock: a twelfth pair silently added to kTopologyFloor
    // without updating this file's positive/negative lists must still break
    // this test even though every entry it DOES check still round-trips.
    CHECK(std::size(kTopologyFloor) == 11);
}

// ── 1b. Every floored securable must actually EXIST in the catalogue ─────
//
// The floor matches by STRING and has no compile-time tie to the securable
// names `seed_defaults()` registers (adversarial-review finding F5, Kimi).
// The membership test above pins kTopologyFloor against a hand-copied literal
// list, which catches a typo in ONE of them — but if a securable were renamed
// in rbac_store.cpp and the floor entry updated to match a name that is never
// seeded, both would agree and the floor would silently protect nothing:
// `check_permission` would be asked about a securable the store does not
// recognise, and on an RBAC-off install the legacy branch is what actually
// answers anyway.
//
// This closes that by asserting against the STORE's own registry rather than
// another copy of the same literals.
TEST_CASE("kTopologyFloor: every floored securable is a real, seeded securable type",
          "[authz][floor][pg]") {
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& store = *rbac_bundle;
    REQUIRE(store.is_open());

    const auto types = store.list_securable_types();
    const auto ops = store.list_operations();

    for (const auto& entry : kTopologyFloor) {
        const std::string securable{entry.securable};
        const std::string operation{entry.operation};
        INFO("floored pair " << securable << ":" << operation);
        CHECK(std::find(types.begin(), types.end(), securable) != types.end());
        CHECK(std::find(ops.begin(), ops.end(), operation) != ops.end());
    }
}

// ── 2. RBAC OFF + non-admin → 403 on every floored pair ─────────────────

TEST_CASE("require_permission: RBAC off, non-admin is denied on every floored pair",
          "[pg][authz][floor]") {
    FloorFixture fix;
    auto req = fix.session_request("mallory", auth::Role::user);
    REQUIRE_FALSE(fix.rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK_FALSE(fix.ar->require_permission(req, res, entry.securable, entry.operation));
        CHECK(res.status == 403);
    }
}

// ── 3. RBAC OFF + non-admin → allowed on an UNFLOORED Read ──────────────

TEST_CASE("require_permission: RBAC off, non-admin still gets the ordinary legacy Read-allow "
          "on an unfloored securable",
          "[pg][authz][floor]") {
    FloorFixture fix;
    auto req = fix.session_request("frank", auth::Role::user);

    httplib::Response res;
    CHECK(fix.ar->require_permission(req, res, "Infrastructure", "Read"));
}

// ── 4. RBAC OFF + admin → allowed on every floored pair ──────────────────

TEST_CASE("require_permission: RBAC off, admin is allowed on every floored pair",
          "[pg][authz][floor]") {
    FloorFixture fix;
    auto req = fix.session_request("grace", auth::Role::admin);

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK(fix.ar->require_permission(req, res, entry.securable, entry.operation));
    }
}

// ── 5. RBAC ON + a real AccessReview:Read grant → allowed ───────────────
//
// The single most important assertion in this file: #2324 cut the dedicated
// AccessReview securable precisely so a non-admin Reviewer role could be
// seeded with AccessReview:Read. If the floor ever ran ahead of (or instead
// of) the live-RBAC branch, it would silently deny that seeded role and
// destroy the whole reason the securable exists.

TEST_CASE("require_permission: RBAC on, a non-admin with a real AccessReview:Read grant is "
          "allowed — the floor must never run ahead of a live RBAC grant",
          "[pg][authz][floor]") {
    FloorFixture fix;
    REQUIRE(fix.rbac_store.create_role({"ReviewerTest", "d", false, 0}).has_value());
    REQUIRE(fix.rbac_store.set_permission({"ReviewerTest", "AccessReview", "Read", "allow"})
                .has_value());
    REQUIRE(fix.rbac_store.assign_role({"user", "carol", "ReviewerTest"}).has_value());
    fix.rbac_store.set_rbac_enabled(true);

    auto req = fix.session_request("carol", auth::Role::user);
    httplib::Response res;
    CHECK(fix.ar->require_permission(req, res, "AccessReview", "Read"));
}

// ── 6. Same matrix through require_scoped_permission ─────────────────────
//
// No floored pair reaches this branch in production today — it is floored
// defensively so a FUTURE scoped topology read cannot silently bypass the
// floor. This is what stops that regressing.

TEST_CASE("require_scoped_permission: mirrors require_permission's floor (RBAC-off denial + "
          "RBAC-on granted-allow)",
          "[pg][authz][floor]") {
    FloorFixture fix;

    SECTION("RBAC off: non-admin is denied") {
        auto req = fix.session_request("dave", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_scoped_permission(req, res, "AccessReview", "Read", "agent-1"));
        CHECK(res.status == 403);
    }

    SECTION("RBAC on: a real AccessReview:Read grant is allowed") {
        REQUIRE(fix.rbac_store.create_role({"ReviewerTest2", "d", false, 0}).has_value());
        REQUIRE(fix.rbac_store.set_permission({"ReviewerTest2", "AccessReview", "Read", "allow"})
                    .has_value());
        REQUIRE(fix.rbac_store.assign_role({"user", "erin", "ReviewerTest2"}).has_value());
        fix.rbac_store.set_rbac_enabled(true);

        auto req = fix.session_request("erin", auth::Role::user);
        httplib::Response res;
        // A global grant short-circuits check_scoped_permission's step 1
        // (check_permission) regardless of agent_id/mgmt-group wiring — see
        // RbacStore::check_scoped_permission.
        CHECK(fix.ar->require_scoped_permission(req, res, "AccessReview", "Read", "agent-1"));
    }
}

// ── 7. JIT-elevated non-admin → allowed (elevation short-circuits above the floor) ──

TEST_CASE("require_permission: a JIT-elevated non-admin is allowed on every floored pair",
          "[pg][authz][floor]") {
    FloorFixture fix;
    auto req = fix.elevated_session_request("heidi");

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK(fix.ar->require_permission(req, res, entry.securable, entry.operation));
    }
}

// ── 9. Denial side-effects: audit reason + counter ────────────────────────

TEST_CASE("require_permission: a floored denial's audit reason and counter are distinguishable "
          "from an ordinary non-Read denial",
          "[pg][authz][floor]") {
    FloorFixture fix;

    SECTION("floored denial: audit reason starts 'topology floor: ' and the counter increments") {
        auto req = fix.session_request("ivan", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "AccessReview", "Read"));

        auto rows = fix.audit_store->query(AuditQuery{.action = "auth.permission_required", .limit = 1});
        REQUIRE(rows.has_value());
        REQUIRE_FALSE(rows->empty());
        CHECK(rows->front().detail.starts_with("topology floor: "));

        auto& counter = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                            {{"permission", "AccessReview:Read"}});
        CHECK(counter.value() == 1.0);
    }

    SECTION("ordinary non-Read denial: generic reason, counter does NOT bump") {
        auto req = fix.session_request("judy", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "Infrastructure", "Write"));

        auto rows = fix.audit_store->query(AuditQuery{.action = "auth.permission_required", .limit = 1});
        REQUIRE(rows.has_value());
        REQUIRE_FALSE(rows->empty());
        CHECK(rows->front().detail.starts_with("non-admin role denied "));
        CHECK_FALSE(rows->front().detail.starts_with("topology floor: "));

        auto& counter = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                            {{"permission", "Infrastructure:Write"}});
        CHECK(counter.value() == 0.0);
    }
}

// ── 9b. has_permission: the render-time probe (PR #5846 review; #5792) ─────

TEST_CASE("has_permission: gives require_permission's verdict and writes no denial row, while "
          "the gate still does (mutation: drop the probe guard in audit_log and the first "
          "assertion fails)",
          "[pg][authz][probe]") {
    FloorFixture fix;
    const AuditQuery denied_rows{.action = "auth.permission_required", .limit = 10};

    SECTION("a denied probe leaves no auth.permission_required row; the gate leaves one") {
        auto req = fix.session_request("kim", auth::Role::user);
        CHECK_FALSE(fix.ar->has_permission(req, "Infrastructure", "Write"));
        auto after_probe = fix.audit_store->query(denied_rows);
        REQUIRE(after_probe.has_value());
        CHECK(after_probe->empty());

        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "Infrastructure", "Write"));
        auto after_gate = fix.audit_store->query(denied_rows);
        REQUIRE(after_gate.has_value());
        CHECK(after_gate->size() == 1);

        // The suppression does not outlive the probe: a second probe adds nothing and a later
        // gate denial is recorded again.
        CHECK_FALSE(fix.ar->has_permission(req, "Infrastructure", "Write"));
        httplib::Response res2;
        CHECK_FALSE(fix.ar->require_permission(req, res2, "Infrastructure", "Write"));
        auto after_both = fix.audit_store->query(denied_rows);
        REQUIRE(after_both.has_value());
        CHECK(after_both->size() == 2);
    }

    SECTION("the probe answers exactly as the gate does: admit, role denial, floored denial, "
            "elevation") {
        struct Case {
            const char* user;
            auth::Role role;
            const char* securable;
            const char* operation;
            bool elevated;
        };
        const Case cases[] = {
            {"lee", auth::Role::user, "Infrastructure", "Read", false},    // legacy Read allowed
            {"mo", auth::Role::user, "Execution", "Execute", false},       // legacy needs admin
            {"ned", auth::Role::user, "AccessReview", "Read", false},      // topology floor
            {"ola", auth::Role::admin, "Execution", "Execute", false},     // admin
            {"pat", auth::Role::user, "Execution", "Execute", true},       // JIT elevation
        };
        for (const auto& c : cases) {
            INFO(c.user << " " << c.securable << ":" << c.operation);
            auto req = c.elevated ? fix.elevated_session_request(c.user)
                                  : fix.session_request(c.user, c.role);
            httplib::Response res;
            const bool gate = fix.ar->require_permission(req, res, c.securable, c.operation);
            const bool probe = fix.ar->has_permission(req, c.securable, c.operation);
            CHECK(probe == gate);
        }
    }

    SECTION("an unauthenticated request is simply not permitted, and nothing is written") {
        httplib::Request anon;
        CHECK_FALSE(fix.ar->has_permission(anon, "Infrastructure", "Read"));
        auto rows = fix.audit_store->query(denied_rows);
        REQUIRE(rows.has_value());
        CHECK(rows->empty());
    }
}

TEST_CASE("probe_fleet_read / probe_permission: the gate's verdict with no denial row (PR #5859 "
          "review; mutation: drop the AuditProbeScope in either and the row counts fail)",
          "[pg][authz][probe]") {
    FloorFixture fix;
    const AuditQuery fleet_rows{.action = "auth.fleet_read_required", .limit = 10};
    const AuditQuery perm_rows{.action = "auth.permission_required", .limit = 10};

    SECTION("a denied fleet-read probe writes no row; the gate writes one") {
        auto req = fix.session_request("quin", auth::Role::user);
        httplib::Response probe_res;
        // A non-Read operation is the gate's deterministic, audited refusal.
        auto probed = fix.ar->probe_fleet_read(req, probe_res, "Infrastructure", "Write");
        CHECK_FALSE(probed.has_value());
        CHECK(probe_res.status == 403); // the response is still written, for the caller to read
        auto after_probe = fix.audit_store->query(fleet_rows);
        REQUIRE(after_probe.has_value());
        CHECK(after_probe->empty());

        httplib::Response gate_res;
        auto gated = fix.ar->require_fleet_read(req, gate_res, "Infrastructure", "Write");
        CHECK_FALSE(gated.has_value());
        auto after_gate = fix.audit_store->query(fleet_rows);
        REQUIRE(after_gate.has_value());
        CHECK(after_gate->size() == 1);
    }

    SECTION("the probe answers with the gate's own verdict and status (this fixture has no "
            "management-group store, so the fleet gate fails closed for both; the admit path "
            "of the shared decision is covered by the has_permission cases above)") {
        for (auto role : {auth::Role::user, auth::Role::admin}) {
            auto req = fix.session_request(role == auth::Role::admin ? "rae" : "ray", role);
            httplib::Response a, b;
            auto probed = fix.ar->probe_fleet_read(req, a, "Infrastructure", "Read");
            auto gated = fix.ar->require_fleet_read(req, b, "Infrastructure", "Read");
            CHECK(probed.has_value() == gated.has_value());
            CHECK(a.status == b.status);
            if (probed && gated)
                CHECK(probed->visible_for_query() == gated->visible_for_query());
        }
    }

    SECTION("probe_permission keeps the gate's status and writes no row") {
        auto req = fix.session_request("sam", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->probe_permission(req, res, "Execution", "Execute"));
        CHECK(res.status == 403);
        auto rows = fix.audit_store->query(perm_rows);
        REQUIRE(rows.has_value());
        CHECK(rows->empty());
    }
}

TEST_CASE("probe_permission / probe_fleet_read: a token caller keeps its denial row while a cookie "
          "sign-in does not (mutation: drop the denial_row_may_be_withheld check in audit_log)",
          "[pg][authz][probe]") {
    FloorFixture fix;
    yuzu::server::ApiTokenStore tokens{*fix.audit_pool};
    REQUIRE(tokens.is_open());
    REQUIRE(fix.auth_mgr.upsert_user("tess", "password1234", auth::Role::user));
    const auto expiry = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count() +
                        3600;
    auto raw = tokens.create_token("probe-token", "tess", expiry);
    REQUIRE(raw.has_value());
    AuthRoutes ar(fix.cfg, fix.auth_mgr, &fix.rbac_store, &tokens, fix.audit_store.get(),
                  /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr, /*analytics_store=*/nullptr,
                  fix.oidc_mu, fix.oidc_provider);
    const AuditQuery perm_rows{.action = "auth.permission_required", .limit = 20};
    const AuditQuery fleet_rows{.action = "auth.fleet_read_required", .limit = 20};
    auto count = [&](const AuditQuery& q) {
        auto r = fix.audit_store->query(q);
        REQUIRE(r.has_value());
        return r->size();
    };

    httplib::Request bearer;
    bearer.headers.emplace("Authorization", "Bearer " + *raw);

    httplib::Response r1;
    CHECK_FALSE(ar.probe_permission(bearer, r1, "Execution", "Execute"));
    CHECK(count(perm_rows) == 1); // the token caller's denial is on the record

    httplib::Response r2;
    CHECK_FALSE(ar.probe_fleet_read(bearer, r2, "Infrastructure", "Write").has_value());
    CHECK(count(fleet_rows) == 1);

    // The same questions from an interactive cookie sign-in add nothing.
    auto cookie = fix.session_request("cora", auth::Role::user);
    httplib::Response r3, r4;
    CHECK_FALSE(ar.probe_permission(cookie, r3, "Execution", "Execute"));
    CHECK_FALSE(ar.probe_fleet_read(cookie, r4, "Infrastructure", "Write").has_value());
    CHECK(count(perm_rows) == 1);
    CHECK(count(fleet_rows) == 1);
}

TEST_CASE("probe_fleet_read: an elevated session is admitted exactly as the gate admits it, "
          "with the same scope",
          "[pg][authz][probe]") {
    FloorFixture fix;
    auto req = fix.elevated_session_request("elena");
    httplib::Response a, b;
    auto probed = fix.ar->probe_fleet_read(req, a, "Infrastructure", "Read");
    auto gated = fix.ar->require_fleet_read(req, b, "Infrastructure", "Read");
    REQUIRE(gated.has_value()); // guard: a vacuous both-denied must not pass
    REQUIRE(probed.has_value());
    CHECK(probed->visible_for_query() == gated->visible_for_query());
}

TEST_CASE("denial_row_may_be_withheld: only an interactive cookie sign-in qualifies",
          "[authz][probe]") {
    auto session = [](const char* source, const char* kind) {
        auth::Session s;
        s.auth_source = source;
        s.principal_kind = kind;
        return s;
    };
    CHECK(yuzu::server::denial_row_may_be_withheld(session("local", "user")));
    CHECK(yuzu::server::denial_row_may_be_withheld(session("oidc", "user")));
    CHECK(yuzu::server::denial_row_may_be_withheld(session("saml", "user")));
    // A machine credential or an engine principal keeps its denial rows.
    CHECK_FALSE(yuzu::server::denial_row_may_be_withheld(session("api_token", "user")));
    CHECK_FALSE(yuzu::server::denial_row_may_be_withheld(session("mcp_token", "user")));
    CHECK_FALSE(yuzu::server::denial_row_may_be_withheld(session("engine_token", "engine")));
    CHECK_FALSE(yuzu::server::denial_row_may_be_withheld(session("local", "engine")));
}

// ── 10. Securable seeding ─────────────────────────────────────────────────

TEST_CASE("RbacStore::seed_defaults: EnginePrincipal is seeded with Administrator+Viewer Read",
          "[pg][authz][floor]") {
    FloorFixture fix;

    auto types = fix.rbac_store.list_securable_types();
    CHECK(std::find(types.begin(), types.end(), "EnginePrincipal") != types.end());

    REQUIRE(fix.rbac_store.assign_role({"user", "kevin", "Administrator"}).has_value());
    CHECK(fix.rbac_store.check_permission("kevin", "EnginePrincipal", "Read"));

    REQUIRE(fix.rbac_store.assign_role({"user", "linda", "Viewer"}).has_value());
    CHECK(fix.rbac_store.check_permission("linda", "EnginePrincipal", "Read"));
}

// ── 7b. The UPGRADE path — the claim the no-migration decision rests on ──
//
// #2376 deliberately ships NO schema migration for the new `EnginePrincipal`
// securable. The whole justification is that `seed_defaults()` runs
// unconditionally on every construction and its `types[]` / Administrator-CRUD
// / `viewer_types[]` loops are all `INSERT OR IGNORE`, so an EXISTING
// deployment picks the securable and its grants up on the next boot with no
// migration at all — exactly how `AccessReview` and `SoftwareLicensing` were
// introduced. (A migration is needed only where a change cannot be an
// idempotent additive re-seed: `rbac_store.cpp`'s v4 DELETEs rows, which is
// why that one had to be one.)
//
// The seeding test above only proves that on a FRESH store. That is not the
// claim — the claim is about a database that already exists and predates the
// securable. This reconstructs that database (open, then delete the
// EnginePrincipal rows so the file looks pre-#2376 while its `schema_version`
// stays where it was), reopens it, and asserts the next boot restores
// everything. If someone later makes `seed_defaults()` conditional — a
// run-once guard, a version gate — this fails, which is the point: it would
// silently strand every upgraded deployment without the securable, and the
// engine-principal routes would 403 for Administrator and Viewer alike.
TEST_CASE("RbacStore: an EXISTING pre-#2376 database gains EnginePrincipal on the next boot, "
          "with no migration — the no-migration decision's actual claim",
          "[authz][floor][pg]") {
    // The pre-migrated, pre-seeded clone IS "boot once so the file exists and
    // is fully seeded/migrated" — the template's own setup already performed
    // that boot; every clone inherits its state.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::rbac_store_pg_template);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());

    // Strip the securable back out, and confirm the strip actually took — all
    // through raw SQL with NO RbacStore open, because merely constructing one
    // re-seeds and would restore the rows. An earlier draft of this test put a
    // store construction between the strip and the assertion; that made the
    // "upgrade boot" the third open and the test passed for the wrong reason.
    // Child-first delete order: role_permissions references securable_types.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto* c = lease.get();
        REQUIRE(yuzu::server::pg::exec_params(c,
                                              "DELETE FROM rbac_store.role_permissions "
                                              "WHERE securable_type = $1",
                                              std::vector<std::string>{"EnginePrincipal"})
                    .ok());
        REQUIRE(yuzu::server::pg::exec_params(c,
                                              "DELETE FROM rbac_store.securable_types "
                                              "WHERE name = $1",
                                              std::vector<std::string>{"EnginePrincipal"})
                    .ok());

        auto count_of = [&](const char* sql) {
            yuzu::server::pg::PgResult r =
                yuzu::server::pg::exec_params(c, sql, std::vector<std::string>{"EnginePrincipal"});
            REQUIRE(r.ok());
            return std::atoi(PQgetvalue(r.get(), 0, 0));
        };
        REQUIRE(count_of("SELECT COUNT(*) FROM rbac_store.securable_types WHERE name = $1") == 0);
        REQUIRE(count_of("SELECT COUNT(*) FROM rbac_store.role_permissions "
                        "WHERE securable_type = $1")
                == 0);
    }

    // The upgrade boot — the FIRST store construction since the strip.
    RbacStore upgraded{pool};
    REQUIRE(upgraded.is_open());

    auto types = upgraded.list_securable_types();
    CHECK(std::find(types.begin(), types.end(), "EnginePrincipal") != types.end());

    REQUIRE(upgraded.assign_role({"user", "morag", "Administrator"}).has_value());
    CHECK(upgraded.check_permission("morag", "EnginePrincipal", "Read"));

    REQUIRE(upgraded.assign_role({"user", "niall", "Viewer"}).has_value());
    CHECK(upgraded.check_permission("niall", "EnginePrincipal", "Read"));
}

// ── 8. Engine principal → still denied, behaviour unchanged by the floor ──
//
// PG-gated (ApiTokenStore + EnginePrincipalStore are both Postgres-backed —
// ADR-0006/ADR-0031): SKIPs when YUZU_TEST_POSTGRES_DSN is unset, FAILs when
// it is set but broken (the standard skip-vs-fail contract, test_helpers.hpp).
// The engine branch in require_permission/require_scoped_permission resolves
// BEFORE the legacy fallback the floor lives in (auth_routes.cpp: engine
// sessions return from their own RBAC-only block), so the floor's addition
// must be a complete no-op for an engine session — this locks that.

TEST_CASE("require_permission: an engine principal is still denied Read on every floored pair "
          "when RBAC is off — the floor never reaches the engine branch",
          "[pg][authz][floor]") {
    YUZU_REQUIRE_PG_DB(db);

    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore engine_store{pool};
    REQUIRE(engine_store.is_open());
    ApiTokenStore api_tokens{pool};
    REQUIRE(api_tokens.is_open());

    REQUIRE(engine_store
                .create("Floor Test Engine", "alice", "authz topology floor coverage", "internal",
                       "admin", "engine:floor-test")
                .has_value());
    api_tokens.set_engine_referent_check(
        [&](const std::string& id) { return engine_store.get_for_auth(id).status; });
    const auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    auto raw = api_tokens.create_token("engine-floor-token", "engine:floor-test", now_epoch + 3600,
                                       "", "readonly", "engine");
    REQUIRE(raw.has_value());

    Config cfg{};
    auth::AuthManager auth_mgr{};
    // RbacStore migrates+seeds its own `rbac_store` schema beside the
    // engine-principal/api-token schemas already open on this same fresh DB —
    // no second database needed.
    RbacStore rbac_store{pool};
    REQUIRE(rbac_store.is_open());
    REQUIRE_FALSE(rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    AuthRoutes ar(cfg, auth_mgr, &rbac_store, &api_tokens, /*audit_store=*/nullptr,
                 /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr, /*analytics_store=*/nullptr,
                 oidc_mu, oidc_provider);
    ar.set_engine_principal_store(&engine_store);

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + *raw);
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK_FALSE(ar.require_permission(req, res, entry.securable, entry.operation));
        CHECK(res.status == 403);
    }
}

// ── 11. Forensics:Read (Wave 7 PR7.2) — the new pair's own matrix ────────
//
// Forensics is deliberately absent from the Viewer read-list (rbac_store.cpp
// seed_defaults) — Administrator-only by design (docs/authz-model.md §4).
// This locks all three legs the app_usage read path depends on: the
// RBAC-off admin allow (the ordinary admin-role fast path, unaffected by the
// floor), the RBAC-on seeded-Administrator allow (the floor must never run
// ahead of a live grant — same principle section 5 locks for AccessReview),
// and the RBAC-on no-grant deny (a plain user, even with RBAC on, never
// gets Forensics:Read without an explicit grant).

TEST_CASE("require_permission: Forensics:Read — RBAC-off admin allowed, RBAC-on seeded "
          "Administrator grant allowed, RBAC-on no grant denied",
          "[pg][authz][floor]") {
    FloorFixture fix;

    SECTION("RBAC off: an admin cookie session is allowed") {
        auto req = fix.session_request("oscar", auth::Role::admin);
        httplib::Response res;
        CHECK(fix.ar->require_permission(req, res, "Forensics", "Read"));
    }

    SECTION("RBAC on: a user assigned the seeded Administrator role is allowed") {
        REQUIRE(fix.rbac_store.assign_role({"user", "peggy", "Administrator"}).has_value());
        fix.rbac_store.set_rbac_enabled(true);
        auto req = fix.session_request("peggy", auth::Role::user);
        httplib::Response res;
        CHECK(fix.ar->require_permission(req, res, "Forensics", "Read"));
    }

    SECTION("RBAC on: a non-admin with no Forensics grant is denied") {
        fix.rbac_store.set_rbac_enabled(true);
        auto req = fix.session_request("quentin", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "Forensics", "Read"));
        CHECK(res.status == 403);
    }
}

// ── 12. AuditLog:Read (#5771) — the audit trail's own matrix ──────────────
//
// The audit trail was the one evidence store readable by ANY signed-in
// session on the RBAC-off default. The generic matrix tests above iterate
// kExpectedFloorPairs, so they already cover the pair; this case pins what is
// specific to it — the pair-labelled counter and `topology floor:` audit
// reason — and the RBAC-on legs the floor must leave alone: a seeded holder
// and a custom grant are still admitted, and a non-holder's denial is an
// ordinary RBAC denial, never a floored one.

TEST_CASE("require_permission: AuditLog:Read — RBAC-off non-admin floored with the pair's own "
          "reason and counter; RBAC-on seeded and custom holders still admitted",
          "[pg][authz][floor]") {
    FloorFixture fix;

    SECTION("RBAC off: a non-admin is denied; the audit reason and counter name AuditLog:Read") {
        REQUIRE_FALSE(fix.rbac_store.is_rbac_enabled());
        auto req = fix.session_request("rita", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "AuditLog", "Read"));
        CHECK(res.status == 403);

        auto rows = fix.audit_store->query(AuditQuery{.action = "auth.permission_required", .limit = 1});
        REQUIRE(rows.has_value());
        REQUIRE_FALSE(rows->empty());
        CHECK(rows->front().detail.starts_with(
            "topology floor: non-admin role denied AuditLog:Read"));

        auto& counter = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                            {{"permission", "AuditLog:Read"}});
        CHECK(counter.value() == 1.0);
    }

    SECTION("RBAC off: an admin is admitted and the counter does not move") {
        auto req = fix.session_request("adam", auth::Role::admin);
        httplib::Response res;
        CHECK(fix.ar->require_permission(req, res, "AuditLog", "Read"));
        auto& counter = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                            {{"permission", "AuditLog:Read"}});
        CHECK(counter.value() == 0.0);
    }

    SECTION("RBAC on: users holding the seeded Operator and Viewer roles are admitted") {
        REQUIRE(fix.rbac_store.assign_role({"user", "olivia", "Operator"}).has_value());
        REQUIRE(fix.rbac_store.assign_role({"user", "vince", "Viewer"}).has_value());
        fix.rbac_store.set_rbac_enabled(true);
        for (const char* name : {"olivia", "vince"}) {
            INFO("user=" << name);
            auto req = fix.session_request(name, auth::Role::user);
            httplib::Response res;
            CHECK(fix.ar->require_permission(req, res, "AuditLog", "Read"));
        }
    }

    SECTION("RBAC on: a custom role granted the pair is admitted") {
        REQUIRE(fix.rbac_store.create_role({"AuditorTest", "d", false, 0}).has_value());
        REQUIRE(fix.rbac_store.set_permission({"AuditorTest", "AuditLog", "Read", "allow"})
                    .has_value());
        REQUIRE(fix.rbac_store.assign_role({"user", "carmen", "AuditorTest"}).has_value());
        fix.rbac_store.set_rbac_enabled(true);
        auto req = fix.session_request("carmen", auth::Role::user);
        httplib::Response res;
        CHECK(fix.ar->require_permission(req, res, "AuditLog", "Read"));
    }

    SECTION("RBAC on: a non-holder is denied by the ordinary RBAC branch, not the floor") {
        fix.rbac_store.set_rbac_enabled(true);
        auto req = fix.session_request("nell", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "AuditLog", "Read"));
        CHECK(res.status == 403);

        auto rows = fix.audit_store->query(AuditQuery{.action = "auth.permission_required", .limit = 1});
        REQUIRE(rows.has_value());
        REQUIRE_FALSE(rows->empty());
        CHECK(rows->front().detail == "RBAC denied AuditLog:Read");
        auto& counter = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                            {{"permission", "AuditLog:Read"}});
        CHECK(counter.value() == 0.0);
    }
}

// ── 13. Every REST audit surface, through the real chokepoint (#5771) ─────
//
// The floor keys on the (securable, operation) STRING each surface passes to
// `require_permission`, so a surface re-gated on any other securable would
// silently escape it. The route tests elsewhere stub the gate; this one wires
// the REAL `AuthRoutes::require_permission` behind the four REST audit
// surfaces and checks the acceptance behaviour directly: a non-admin cookie
// session gets 403 on each while RBAC is off, an admin session is still
// admitted, and each denial is a FLOORED denial (counter == one per route).
// The MCP twins are pinned in test_mcp_server.cpp.

TEST_CASE("AuditLog:Read floor: the four REST audit surfaces refuse a non-admin session while "
          "RBAC is off and admit an admin, through the real require_permission",
          "[pg][authz][floor]") {
    FloorFixture fix;
    REQUIRE_FALSE(fix.rbac_store.is_rbac_enabled());

    auto auth_fn = [&fix](const httplib::Request& req, httplib::Response& res) {
        return fix.ar->require_auth(req, res);
    };
    auto perm_fn = [&fix](const httplib::Request& req, httplib::Response& res,
                          const std::string& securable, const std::string& operation) {
        return fix.ar->require_permission(req, res, securable, operation);
    };

    yuzu::server::test::TestRouteSink sink;

    dashboard_api::Deps deps;
    deps.auth_fn = auth_fn;
    deps.perm_fn = perm_fn;
    deps.visible_agents_json_fn = [](const std::string&) { return nlohmann::json::array(); };
    deps.rbac_store = &fix.rbac_store;
    deps.audit_store = fix.audit_store.get();
    dashboard_api::register_dashboard_api_routes(sink, std::move(deps));

    RestApiV1 api;
    api.register_routes(
        sink, auth_fn, perm_fn,
        [](const httplib::Request&, const std::string&, const std::string&, const std::string&,
           const std::string&, const std::string&) { return true; },
        &fix.rbac_store, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
        /*quarantine_store=*/nullptr, /*response_store=*/nullptr, /*instruction_store=*/nullptr,
        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
        /*tag_store=*/nullptr, /*audit_store=*/fix.audit_store.get());

    const std::unordered_map<std::string, std::string> user_headers{
        {"Cookie", fix.session_request("uma", auth::Role::user).get_header_value("Cookie")}};
    const std::unordered_map<std::string, std::string> admin_headers{
        {"Cookie", fix.session_request("ada", auth::Role::admin).get_header_value("Cookie")}};
    REQUIRE_FALSE(user_headers.at("Cookie").empty());
    REQUIRE_FALSE(admin_headers.at("Cookie").empty());

    const std::vector<std::string> surfaces = {
        "/api/audit",
        "/api/v1/audit",
        "/api/v1/audit/auth-sample",
        "/api/v1/engine-principals/audit/no-admin",
    };

    for (const auto& path : surfaces) {
        INFO("non-admin: " << path);
        auto res = sink.Get(path, user_headers);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    auto& floored = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                        {{"permission", "AuditLog:Read"}});
    CHECK(floored.value() == static_cast<double>(surfaces.size()));

    for (const auto& path : surfaces) {
        INFO("admin: " << path);
        auto res = sink.Get(path, admin_headers);
        REQUIRE(res);
        // Admitted by the gate. The no-admin auditor then answers 503 because
        // no engine-principal store is wired in this fixture; the point is
        // that it is not a 401/403.
        CHECK(res->status != 401);
        CHECK(res->status != 403);
    }
    CHECK(floored.value() == static_cast<double>(surfaces.size())); // admin never bumps it
}

// ── 14. The floor runs BEFORE the audit filter validation (#5771 x filter parity) ──
//
// The audit filters and paging bounds (since/until/target_*/offset) answer 400 on
// bad input. A non-admin on a default (RBAC-off) install must be refused 403 first,
// valid filters or not: a 400/200 from the validation layer would tell a caller
// that has no AuditLog:Read about the query surface and its limits. The admin
// control proves each malformed query really is a 400 when the gate admits it.

TEST_CASE("AuditLog:Read floor: a non-admin is refused 403 on filtered and malformed audit "
          "queries, ahead of the 400 validation",
          "[pg][authz][floor][audit]") {
    FloorFixture fix;
    REQUIRE_FALSE(fix.rbac_store.is_rbac_enabled());

    auto auth_fn = [&fix](const httplib::Request& req, httplib::Response& res) {
        return fix.ar->require_auth(req, res);
    };
    auto perm_fn = [&fix](const httplib::Request& req, httplib::Response& res,
                          const std::string& securable, const std::string& operation) {
        return fix.ar->require_permission(req, res, securable, operation);
    };

    yuzu::server::test::TestRouteSink sink;

    dashboard_api::Deps deps;
    deps.auth_fn = auth_fn;
    deps.perm_fn = perm_fn;
    deps.visible_agents_json_fn = [](const std::string&) { return nlohmann::json::array(); };
    deps.rbac_store = &fix.rbac_store;
    deps.audit_store = fix.audit_store.get();
    dashboard_api::register_dashboard_api_routes(sink, std::move(deps));

    RestApiV1 api;
    api.register_routes(
        sink, auth_fn, perm_fn,
        [](const httplib::Request&, const std::string&, const std::string&, const std::string&,
           const std::string&, const std::string&) { return true; },
        &fix.rbac_store, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
        /*quarantine_store=*/nullptr, /*response_store=*/nullptr, /*instruction_store=*/nullptr,
        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
        /*tag_store=*/nullptr, /*audit_store=*/fix.audit_store.get());

    const std::unordered_map<std::string, std::string> user_headers{
        {"Cookie", fix.session_request("uma", auth::Role::user).get_header_value("Cookie")}};
    const std::unordered_map<std::string, std::string> admin_headers{
        {"Cookie", fix.session_request("ada", auth::Role::admin).get_header_value("Cookie")}};
    REQUIRE_FALSE(user_headers.at("Cookie").empty());
    REQUIRE_FALSE(admin_headers.at("Cookie").empty());

    // Each query is a 400 for an admitted caller (bad paging bound, unparseable bound, inverted or
    // negative window, a NUL in a string filter, target_id without target_type) except the
    // last, a valid filter.
    const std::vector<std::pair<std::string, int>> queries = {
        {"/api/audit?offset=10001", 400},
        {"/api/audit?since=abc", 400},
        // PR #5870 review: a decoded NUL would truncate the bound value (the v1/MCP twins refuse
        // it), and a negative or inverted window is a client error, not a query.
        {"/api/audit?principal=a%00b", 400},
        {"/api/audit?action=a%00b", 400},
        {"/api/audit?target_type=a%00b", 400},
        {"/api/audit?target_id=a%00b", 400},
        // Invalid UTF-8 would fail the Postgres bind: a false 503 and a false degrade count.
        {"/api/audit?principal=%C3%28", 400},
        {"/api/audit?target_id=%FF", 400},
        {"/api/audit?since=-1", 400},
        {"/api/audit?until=-5", 400},
        {"/api/audit?since=9&until=3", 400},
        {"/api/v1/audit?offset=10001", 400},
        {"/api/v1/audit?since=9&until=3", 400},
        {"/api/v1/audit?target_id=x", 400},
        {"/api/v1/audit?target_type=Tag&target_id=t1&since=1&until=9&offset=0", 200},
    };

    for (const auto& [path, admin_status] : queries) {
        INFO("admin: " << path);
        auto res = sink.Get(path, admin_headers);
        REQUIRE(res);
        CHECK(res->status == admin_status);
    }
    auto& floored = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                        {{"permission", "AuditLog:Read"}});
    CHECK(floored.value() == 0.0); // the admin control never bumps the floor counter

    for (const auto& [path, admin_status] : queries) {
        INFO("non-admin: " << path << " (admin status " << admin_status << ")");
        auto res = sink.Get(path, user_headers);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    CHECK(floored.value() == static_cast<double>(queries.size()));
}

// ═══════════════════════════════════════════════════════════════════════════
// #4990: the production Forensics-visibility resolver (forensics_visibility.hpp).
//
// These drive the REAL `resolve_forensics_visible` over a real AuthRoutes, a real PG RbacStore, a real
// ManagementGroupStore and real API-token / engine-principal sessions, so a regression in which
// gate family decides the global proof (the floored `has_permission`, never an fleet-read gate that
// admits everyone while RBAC is off) fails here. A stub function that records calls proves nothing.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

yuzu::test::PgTestTemplate forensics_vis_engine_tpl{
    "epforensicsvis", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        EnginePrincipalStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("forensicsvis template: engine principal store failed to migrate");
    }};

std::int64_t forensics_vis_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// The resolver's tri-state answer (forensics_visibility.hpp): Granted global / Denied
// (present-empty) are values, Unknown is the error. There is no subset answer.
bool is_present_empty(const ForensicsVisibility& r) {
    return r.has_value() && r->has_value() && (*r)->empty();
}
bool is_global(const ForensicsVisibility& r) { return r.has_value() && !r->has_value(); }
bool is_unknown(const ForensicsVisibility& r, ForensicsUnknown why) {
    return !r.has_value() && r.error() == why;
}

struct ForensicsVisRig {
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac = *rbac_bundle;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    yuzu::test::PostgresTestDb engine_db{forensics_vis_engine_tpl};
    std::optional<yuzu::server::pg::PgPool> engine_pool;
    std::unique_ptr<EnginePrincipalStore> engines;
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    auth::AuthManager auth_mgr{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;
    std::string group_id; // management group G = {agent-1, agent-2}

    ForensicsVisRig() {
        REQUIRE(rbac.is_open());
        INFO("[ForensicsVisRig] engine db status (blank == ok): " << engine_db.error());
        REQUIRE(engine_db.available());
        engine_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = engine_db.dsn(), .size = 2});
        engines = std::make_unique<EnginePrincipalStore>(*engine_pool);
        REQUIRE(engines->is_open());
        seed_forensics_tier_metrics(metrics); // as ServerImpl does at start: every reason at 0
        auth_mgr.set_metrics_registry(&metrics);
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(),
                                          /*audit_store=*/nullptr, &mgmt, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
        ar->set_engine_principal_store(engines.get());
        api_tokens->set_engine_referent_check(
            [this](const std::string& id) { return engines->get_for_auth(id).status; });

        // A custom role holding Forensics:Read, granted on one management group below. It exists to
        // prove a group-scoped Forensics:Read is NEVER consulted by the resolver (W1, #4990): the
        // store layer can still author one (create_role/set_permission), the resolver ignores it.
        REQUIRE(rbac.create_role({"ForensicsScoped", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ForensicsScoped", "Forensics", "Read", "allow"}).has_value());
        ManagementGroup g;
        g.name = "G";
        g.membership_type = "static";
        auto id = mgmt.create_group(g);
        REQUIRE(id.has_value());
        group_id = *id;
        REQUIRE(mgmt.add_member(group_id, "agent-1").has_value());
        REQUIRE(mgmt.add_member(group_id, "agent-2").has_value());
    }

    ForensicsVisibilityDeps deps() {
        return {.auth_routes = ar.get(), .metrics = &metrics};
    }

    // The withheld counter for `reason` (0 when the series was never created).
    double withheld(const std::string& reason) {
        return metrics.counter(kForensicsTierWithheldMetric, {{"reason", reason}}).value();
    }

    httplib::Request cookie_request(const std::string& username, auth::Role role) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", role));
        auto token = auth_mgr.create_local_session_for_test(username, role, /*mfa_verified=*/true);
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }

    httplib::Request bearer_request(const std::string& raw) {
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + raw);
        return req;
    }
};

} // namespace

TEST_CASE("yuzu_server_forensics_tier_withheld_total: every closed reason is pre-seeded at 0, HELP is "
          "7-bit ASCII",
          "[auth_routes][authz_topology_floor][forensics][metrics]") {
    yuzu::MetricsRegistry metrics;
    seed_forensics_tier_metrics(metrics);
    const std::string text = metrics.serialize();
    for (const auto why : kForensicsUnknownReasons) {
        const std::string series = std::string(kForensicsTierWithheldMetric) + "{reason=\"" +
                                   std::string(to_string(why)) + "\"} 0";
        INFO(series);
        CHECK(text.find(series) != std::string::npos);
    }
    // Exactly the closed set: no free-form series.
    std::size_t n = 0;
    for (std::size_t pos = 0; (pos = text.find("yuzu_server_forensics_tier_withheld_total{", pos)) !=
                              std::string::npos;
         ++pos)
        ++n;
    CHECK(n == std::size(kForensicsUnknownReasons));
    const auto help_at = text.find(std::string("# HELP ") + kForensicsTierWithheldMetric);
    REQUIRE(help_at != std::string::npos);
    const auto help_end = text.find('\n', help_at);
    CHECK(std::all_of(text.begin() + static_cast<std::ptrdiff_t>(help_at),
                      text.begin() + static_cast<std::ptrdiff_t>(help_end),
                      [](char c) { return static_cast<unsigned char>(c) < 0x80; }));
}

TEST_CASE("forensics visibility: RBAC off - an ordinary user sees no Forensics row, an admin sees all",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(false);

    // The legacy fallback admits every Read to any authenticated session; the topology floor is what
    // keeps Forensics:Read admin-only. A resolver built on a fleet-read gate would return nullopt here.
    auto viewer = rig.cookie_request("viewer1", auth::Role::user);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), viewer)));

    auto admin = rig.cookie_request("admin1", auth::Role::admin);
    CHECK(is_global(resolve_forensics_visible(rig.deps(), admin))); // nullopt = global
}

TEST_CASE("forensics visibility: RBAC on - Viewer none, Administrator and JIT elevation global",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);

    auto viewer = rig.cookie_request("viewer2", auth::Role::user);
    REQUIRE(rig.rbac.assign_role({"user", "viewer2", "Viewer"}).has_value());
    // Viewer holds Response:Read (the point of the bug) but no Forensics grant.
    CHECK(rig.rbac.check_permission("viewer2", "Response", "Read"));
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), viewer)));

    auto admin = rig.cookie_request("admin2", auth::Role::admin);
    REQUIRE(rig.rbac.assign_role({"user", "admin2", "Administrator"}).has_value());
    CHECK(is_global(resolve_forensics_visible(rig.deps(), admin)));

    // JIT elevation is a full-admin window (require_permission short-circuits on it).
    REQUIRE(rig.auth_mgr.upsert_user("elev1", "password1234", auth::Role::user));
    auto token = rig.auth_mgr.create_local_session_for_test("elev1", auth::Role::user, true);
    REQUIRE(rig.auth_mgr.elevate_session(token, std::chrono::seconds(300)).has_value());
    httplib::Request elevated;
    elevated.headers.emplace("Cookie", "yuzu_session=" + token);
    CHECK(is_global(resolve_forensics_visible(rig.deps(), elevated)));
}

TEST_CASE("forensics visibility: RBAC on - a group-scoped Forensics:Read grant is Denied, never rows "
          "and never a group lookup",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);

    auto scoped = rig.cookie_request("scoped1", auth::Role::user);
    REQUIRE(rig.mgmt.assign_role({rig.group_id, "user", "scoped1", "ForensicsScoped"}).has_value());
    // Not a global grant, so the global probe says no...
    CHECK_FALSE(rig.rbac.check_permission("scoped1", "Forensics", "Read"));
    // ...and the grant is real: the store-level scoped lookup still resolves it to the group's
    // agents. The resolver must not use it (there is no scoped Forensics read tier).
    auto lookup = rig.rbac.visible_agents_for_permission("scoped1", "Forensics", "Read", &rig.mgmt);
    REQUIRE(lookup.has_value());
    CHECK(std::set<std::string>(lookup->begin(), lookup->end()) ==
          std::set<std::string>{"agent-1", "agent-2"});
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), scoped)));

    // A user with no grant on the group gets the same answer.
    auto other = rig.cookie_request("scoped2", auth::Role::user);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), other)));

    // With enforcement OFF it is Denied too (the floor is administrator-only).
    rig.rbac.set_rbac_enabled(false);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), scoped)));

    // A definitive denial is correct behavior, never counted.
    for (const auto why : kForensicsUnknownReasons)
        CHECK(rig.withheld(std::string(to_string(why))) == 0.0);
}

TEST_CASE("forensics visibility: the resolver's dependencies are the auth routes and a metrics sink only",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    // Spelled out with ONLY these two members: a definitive global denial performs no
    // management-group (or other store) lookup because the resolver has no store to look in.
    const ForensicsVisibilityDeps deps{.auth_routes = rig.ar.get(), .metrics = &rig.metrics};

    auto viewer = rig.cookie_request("viewer20", auth::Role::user);
    REQUIRE(rig.rbac.assign_role({"user", "viewer20", "Viewer"}).has_value());
    CHECK(is_present_empty(resolve_forensics_visible(deps, viewer)));

    auto admin = rig.cookie_request("admin20", auth::Role::admin);
    REQUIRE(rig.rbac.assign_role({"user", "admin20", "Administrator"}).has_value());
    CHECK(is_global(resolve_forensics_visible(deps, admin)));

    // An unreachable management-group store behind the auth routes does not turn a definitive
    // denial into Unknown: the resolver never reads it.
    yuzu::server::pg::PgPool bad_pool{
        {.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ManagementGroupStore bad_mgmt(bad_pool);
    REQUIRE_FALSE(bad_mgmt.is_open());
    AuthRoutes ar_bad_mgmt(rig.cfg, rig.auth_mgr, &rig.rbac, rig.api_tokens.get(),
                           /*audit_store=*/nullptr, &bad_mgmt, /*tag_store=*/nullptr,
                           /*analytics_store=*/nullptr, rig.oidc_mu, rig.oidc_provider);
    const ForensicsVisibilityDeps bad_deps{.auth_routes = &ar_bad_mgmt, .metrics = &rig.metrics};
    auto scoped = rig.cookie_request("scoped20", auth::Role::user);
    REQUIRE(rig.mgmt.assign_role({rig.group_id, "user", "scoped20", "ForensicsScoped"}).has_value());
    CHECK(is_present_empty(resolve_forensics_visible(bad_deps, scoped)));
    CHECK(is_present_empty(resolve_forensics_visible(bad_deps, viewer)));
    for (const auto why : kForensicsUnknownReasons)
        CHECK(rig.withheld(std::string(to_string(why))) == 0.0);
}

TEST_CASE("forensics visibility: a service-scoped token never inherits its minter's Forensics authority",
          "[pg][auth_routes][authz_topology_floor][forensics][service_scope]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.auth_mgr.upsert_user("minter", "password1234", auth::Role::admin));
    // The minter holds BOTH a global Administrator grant and a scoped Forensics grant...
    REQUIRE(rig.rbac.assign_role({"user", "minter", "Administrator"}).has_value());
    REQUIRE(rig.mgmt.assign_role({rig.group_id, "user", "minter", "ForensicsScoped"}).has_value());
    auto minter_cookie = rig.cookie_request("minter", auth::Role::admin);
    CHECK(is_global(resolve_forensics_visible(rig.deps(), minter_cookie))); // sanity: global

    // ...yet a token it mints scoped to a service carries neither.
    auto raw = rig.api_tokens->create_token("svc", "minter", forensics_vis_now() + 3600, "billing");
    REQUIRE(raw.has_value());
    auto svc = rig.bearer_request(*raw);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), svc)));

    // A plain (non-service) token of the same user keeps the user's global authority.
    auto plain = rig.api_tokens->create_token("plain", "minter", forensics_vis_now() + 3600);
    REQUIRE(plain.has_value());
    auto plain_req = rig.bearer_request(*plain);
    CHECK(is_global(resolve_forensics_visible(rig.deps(), plain_req)));
}

TEST_CASE("forensics visibility: an engine principal without a grant sees nothing",
          "[pg][auth_routes][authz_topology_floor][forensics][engine_principal]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.auth_mgr.upsert_user("owner1", "password1234", auth::Role::admin));
    REQUIRE(rig.engines->create("Vuln Sync", "owner1", "forensics visibility test", "internal",
                                "admin", "engine:vuln")
                .has_value());
    auto raw = rig.api_tokens->create_token("engine-token", "engine:vuln",
                                            forensics_vis_now() + 3600, "", "readonly", "engine");
    REQUIRE(raw.has_value());
    auto req = rig.bearer_request(*raw);
    // Prove this really is an engine session, so the assertion below is not a "no session" pass.
    auto session = rig.ar->resolve_session(req);
    REQUIRE(session.has_value());
    REQUIRE(session->is_engine());
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), req)));

    // RBAC off: an engine principal has no legacy authority either.
    rig.rbac.set_rbac_enabled(false);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), req)));
}

TEST_CASE("forensics visibility: RBAC on - a ForensicsAnalyst holder is global, a Viewer is still nothing "
          "(#4990)",
          "[pg][auth_routes][authz_topology_floor][forensics][forensics_analyst]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);

    auto analyst = rig.cookie_request("ana1", auth::Role::user);
    REQUIRE(rig.rbac.assign_role({"user", "ana1", "ForensicsAnalyst"}).has_value());
    CHECK(rig.rbac.check_permission("ana1", "Forensics", "Read"));
    CHECK(is_global(resolve_forensics_visible(rig.deps(), analyst)));

    // The sibling read roles are unchanged: Viewer and Operator hold no Forensics grant.
    auto viewer = rig.cookie_request("viewer9", auth::Role::user);
    REQUIRE(rig.rbac.assign_role({"user", "viewer9", "Viewer"}).has_value());
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), viewer)));
    auto op = rig.cookie_request("op9", auth::Role::user);
    REQUIRE(rig.rbac.assign_role({"user", "op9", "Operator"}).has_value());
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), op)));

    // Operator + ForensicsAnalyst combine to a global Forensics read.
    REQUIRE(rig.rbac.assign_role({"user", "op9", "ForensicsAnalyst"}).has_value());
    CHECK(is_global(resolve_forensics_visible(rig.deps(), op)));

    // The grant is revocable: unassigning returns the holder to nothing.
    REQUIRE(rig.rbac.unassign_role("user", "ana1", "ForensicsAnalyst").has_value());
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), analyst)));
}

TEST_CASE("forensics visibility: RBAC off - an assigned ForensicsAnalyst grant does nothing, the floor stands "
          "(#4990)",
          "[pg][auth_routes][authz_topology_floor][forensics][forensics_analyst]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    auto analyst = rig.cookie_request("ana2", auth::Role::user);
    REQUIRE(rig.rbac.assign_role({"user", "ana2", "ForensicsAnalyst"}).has_value());
    REQUIRE(is_global(resolve_forensics_visible(rig.deps(), analyst))); // sanity: honored while enforced

    // Enforcement off: the legacy fallback plus the topology floor decide, and the floor keeps
    // Forensics:Read administrator-only. The stored grant is inert, not honored and not erased.
    rig.rbac.set_rbac_enabled(false);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), analyst)));
    CHECK(rig.rbac.get_principal_roles("user", "ana2").size() == 1);

    // Back on, the same grant works again.
    rig.rbac.set_rbac_enabled(true);
    CHECK(is_global(resolve_forensics_visible(rig.deps(), analyst)));
}

TEST_CASE("forensics visibility: a service-scoped token minted by a ForensicsAnalyst holder carries nothing "
          "(#4990)",
          "[pg][auth_routes][authz_topology_floor][forensics][forensics_analyst][service_scope]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.auth_mgr.upsert_user("ana3", "password1234", auth::Role::user));
    REQUIRE(rig.rbac.assign_role({"user", "ana3", "ForensicsAnalyst"}).has_value());

    auto plain = rig.api_tokens->create_token("plain", "ana3", forensics_vis_now() + 3600);
    REQUIRE(plain.has_value());
    auto plain_req = rig.bearer_request(*plain);
    CHECK(is_global(resolve_forensics_visible(rig.deps(), plain_req))); // a plain token is the user

    auto svc = rig.api_tokens->create_token("svc", "ana3", forensics_vis_now() + 3600, "billing");
    REQUIRE(svc.has_value());
    auto svc_req = rig.bearer_request(*svc);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), svc_req)));
}

TEST_CASE("forensics visibility: a degraded or unwired input is Unknown, a definitive refusal is Denied, neither is ever global",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    auto scoped = rig.cookie_request("scoped3", auth::Role::user);
    REQUIRE(rig.mgmt.assign_role({rig.group_id, "user", "scoped3", "ForensicsScoped"}).has_value());
    auto healthy = resolve_forensics_visible(rig.deps(), scoped);
    REQUIRE(healthy.has_value());
    REQUIRE(healthy->has_value());
    CHECK((*healthy)->empty()); // healthy baseline: a scoped-only holder is Denied (present-empty)

    SECTION("auth routes not wired (even for an administrator)") {
        ForensicsVisibilityDeps d = rig.deps();
        d.auth_routes = nullptr;
        auto admin = rig.cookie_request("admin3", auth::Role::admin);
        CHECK(is_unknown(resolve_forensics_visible(d, admin), ForensicsUnknown::Unwired));
    }
    SECTION("an unauthenticated request is a definitive refusal, and a refusal is never counted") {
        httplib::Request anonymous;
        CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), anonymous)));
        auto viewer = rig.cookie_request("viewer9", auth::Role::user);
        CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), viewer)));
        for (const auto why : kForensicsUnknownReasons)
            CHECK(rig.withheld(std::string(to_string(why))) == 0.0);
    }
    SECTION("an unavailable authorization store reads Unknown for an ordinary session too") {
        // The RBAC store behind the gate is not open. The global Forensics:Read proof cannot be
        // answered, which is NOT a definitive refusal: the resolver answers Unknown(RbacUnavailable)
        // for an ordinary session exactly as it does for an engine principal, so a surface shows
        // the retryable error or notice instead of a 200 with the Forensics rows silently missing.
        yuzu::server::pg::PgPool bad_pool{
            {.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
        RbacStore bad_rbac(bad_pool);
        REQUIRE_FALSE(bad_rbac.is_open());
        AuthRoutes bad_ar(rig.cfg, rig.auth_mgr, &bad_rbac, rig.api_tokens.get(),
                          /*audit_store=*/nullptr, &rig.mgmt, /*tag_store=*/nullptr,
                          /*analytics_store=*/nullptr, rig.oidc_mu, rig.oidc_provider);
        ForensicsVisibilityDeps d{.auth_routes = &bad_ar, .metrics = &rig.metrics};
        CHECK(is_unknown(resolve_forensics_visible(d, scoped), ForensicsUnknown::RbacUnavailable));
        CHECK(rig.withheld("rbac_unavailable") == 1.0);
    }
    SECTION("an unavailable authorization store answers 503 to an engine principal: Unknown") {
        REQUIRE(rig.auth_mgr.upsert_user("owner2", "password1234", auth::Role::admin));
        REQUIRE(rig.engines->create("Vuln Sync 2", "owner2", "forensics visibility test", "internal",
                                    "admin", "engine:vuln2")
                    .has_value());
        auto raw = rig.api_tokens->create_token("engine-token2", "engine:vuln2",
                                                forensics_vis_now() + 3600, "", "readonly", "engine");
        REQUIRE(raw.has_value());
        auto req = rig.bearer_request(*raw);
        yuzu::server::pg::PgPool bad_pool{
            {.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
        RbacStore bad_rbac(bad_pool);
        REQUIRE_FALSE(bad_rbac.is_open());
        AuthRoutes bad_ar(rig.cfg, rig.auth_mgr, &bad_rbac, rig.api_tokens.get(),
                          /*audit_store=*/nullptr, &rig.mgmt, /*tag_store=*/nullptr,
                          /*analytics_store=*/nullptr, rig.oidc_mu, rig.oidc_provider);
        bad_ar.set_engine_principal_store(rig.engines.get());
        ForensicsVisibilityDeps d{.auth_routes = &bad_ar, .metrics = &rig.metrics};
        CHECK(is_unknown(resolve_forensics_visible(d, req), ForensicsUnknown::RbacUnavailable));
        CHECK(rig.withheld("rbac_unavailable") == 1.0);
    }
}

// ── Unavailable is not denied (#4990, typed RBAC outcome) ───────────────────────────────
namespace {

// A SECOND RbacStore replica over the rig's database, on its own one-connection pool, with its own
// AuthRoutes. The rig's grants are visible to it (same database); the pool, the permission cache
// and the breaker are its own, so each case can starve the pool, open the breaker or break the role
// read on THIS replica without touching the rig's healthy store.
struct DegradedReplica {
    yuzu::server::pg::PgPool pool;
    RbacStore store;
    yuzu::MetricsRegistry store_metrics;
    AuthRoutes ar;

    explicit DegradedReplica(ForensicsVisRig& rig)
        : pool{{.conninfo = rig.rbac_bundle.dsn(), .size = 1}}, store{pool},
          ar{rig.cfg,           rig.auth_mgr,          &store,        rig.api_tokens.get(),
             /*audit_store=*/nullptr, &rig.mgmt,       /*tag_store=*/nullptr,
             /*analytics_store=*/nullptr, rig.oidc_mu, rig.oidc_provider} {
        REQUIRE(store.is_open());
        store.set_metrics(&store_metrics);
        ar.set_engine_principal_store(rig.engines.get());
    }

    double degrade(const char* reason) {
        return store_metrics.counter("yuzu_server_rbac_read_degrade_total", {{"reason", reason}})
            .value();
    }
    ForensicsVisibilityDeps deps(ForensicsVisRig& rig) {
        return {.auth_routes = &ar, .metrics = &rig.metrics};
    }
};

// `rbac_store.principal_roles` moved aside and back: the role read (the first query of a
// permission-cache miss) genuinely fails while every other read keeps working.
struct RoleReadFault {
    std::string dsn;
    bool armed{false};
    explicit RoleReadFault(std::string d) : dsn(std::move(d)) {}
    void run(const char* sql) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(conn.get(), sql)};
        REQUIRE(r.ok());
    }
    void arm() {
        run("ALTER TABLE rbac_store.principal_roles RENAME TO principal_roles_gone");
        armed = true;
    }
    void repair() noexcept {
        if (!armed)
            return;
        try {
            yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
            if (PQstatus(conn.get()) == CONNECTION_OK) {
                yuzu::server::pg::PgResult r{PQexec(
                    conn.get(), "ALTER TABLE rbac_store.principal_roles_gone RENAME TO principal_roles")};
                if (r.ok())
                    armed = false;
            }
        } catch (...) {
        }
    }
    ~RoleReadFault() { repair(); }
};

nlohmann::json gate_body(const httplib::Response& res) { return nlohmann::json::parse(res.body); }

} // namespace

TEST_CASE("AuthRoutes: probe_permission_unavailable_aware answers 503 where an unavailable RBAC read "
          "is a 403 for require_permission, has_permission and probe_permission",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.rbac.assign_role({"user", "ana", "ForensicsAnalyst"}).has_value());
    REQUIRE(rig.rbac.assign_role({"user", "vic", "Viewer"}).has_value());
    auto ana = rig.cookie_request("ana", auth::Role::user);
    auto vic = rig.cookie_request("vic", auth::Role::user);

    // The three entry points that keep ADR-0041's 403 on an unavailable read.
    auto expect_default_403 = [](DegradedReplica& d, const httplib::Request& req) {
        httplib::Response probe_res;
        CHECK_FALSE(d.ar.probe_permission(req, probe_res, "Forensics", "Read"));
        CHECK(probe_res.status == 403);
        CHECK_FALSE(d.ar.has_permission(req, "Forensics", "Read"));
        httplib::Response gate_res;
        CHECK_FALSE(d.ar.require_permission(req, gate_res, "Forensics", "Read"));
        CHECK(gate_res.status == 403);
    };
    // The opt-in probe: a retryable 503, no `permission` field.
    auto expect_aware_503 = [](DegradedReplica& d, const httplib::Request& req) {
        httplib::Response res;
        CHECK_FALSE(d.ar.probe_permission_unavailable_aware(req, res, "Forensics", "Read"));
        CHECK(res.status == 503);
        const auto body = gate_body(res);
        CHECK(body["error"]["code"] == 503);
        CHECK(body["error"]["retry_after_ms"] == 5000);
        CHECK_FALSE(body["error"].contains("permission"));
    };

    SECTION("healthy store: a grant, a definitive denial and an empty role set are NOT 503") {
        DegradedReplica d(rig);
        httplib::Response ok_res;
        CHECK(d.ar.probe_permission_unavailable_aware(ana, ok_res, "Forensics", "Read"));
        CHECK(d.ar.probe_permission(ana, ok_res, "Forensics", "Read"));
        for (const auto* who : {&vic}) {
            httplib::Response denied;
            CHECK_FALSE(d.ar.probe_permission_unavailable_aware(*who, denied, "Forensics", "Read"));
            CHECK(denied.status == 403);
            httplib::Response plain;
            CHECK_FALSE(d.ar.probe_permission(*who, plain, "Forensics", "Read"));
            CHECK(plain.status == 403);
        }
        // A user with no role at all is the healthy-empty case: a definitive 403, not a 503.
        auto nobody = rig.cookie_request("nobody", auth::Role::user);
        httplib::Response empty_res;
        CHECK_FALSE(d.ar.probe_permission_unavailable_aware(nobody, empty_res, "Forensics", "Read"));
        CHECK(empty_res.status == 403);
        CHECK(d.degrade("query_error") == 0.0);
    }

    SECTION("a failed role query") {
        DegradedReplica d(rig);
        RoleReadFault fault(rig.rbac_bundle.dsn());
        fault.arm();
        expect_aware_503(d, ana); // first, so the counter below is this one failure
        CHECK(d.degrade("query_error") == 1.0);
        expect_default_403(d, ana);
        // A non-cookie session takes the same path.
        auto raw = rig.api_tokens->create_token("t", "ana", forensics_vis_now() + 3600);
        REQUIRE(raw.has_value());
        auto bearer = rig.bearer_request(*raw);
        expect_aware_503(d, bearer);
    }

    SECTION("a failed role query then recovery: the same caller is granted again") {
        DegradedReplica d(rig);
        RoleReadFault fault(rig.rbac_bundle.dsn());
        fault.arm();
        expect_aware_503(d, ana); // one failure: the breaker (threshold 2) stays closed
        fault.repair();
        httplib::Response res;
        CHECK(d.ar.probe_permission_unavailable_aware(ana, res, "Forensics", "Read"));
    }

    SECTION("a starved pool") {
        DegradedReplica d(rig);
        std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // clear the refresh gate
        auto held = d.pool.acquire();
        REQUIRE(held);
        expect_aware_503(d, ana);
        expect_default_403(d, ana);
    }

    SECTION("an open breaker") {
        DegradedReplica d(rig);
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        auto held = d.pool.acquire();
        REQUIRE(held);
        // Two uncached misses reach the trip threshold.
        CHECK_FALSE(d.store.check_permission("ana", "Forensics", "Write"));
        CHECK_FALSE(d.store.check_permission("ana", "Forensics", "Delete"));
        REQUIRE(d.store_metrics.gauge("yuzu_server_rbac_breaker_open").value() == 1.0);
        expect_aware_503(d, ana);
        expect_default_403(d, ana);
    }

    SECTION("a store that is not open") {
        yuzu::server::pg::PgPool bad_pool{
            {.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
        RbacStore bad_rbac(bad_pool);
        REQUIRE_FALSE(bad_rbac.is_open());
        AuthRoutes bad_ar(rig.cfg, rig.auth_mgr, &bad_rbac, rig.api_tokens.get(),
                          /*audit_store=*/nullptr, &rig.mgmt, /*tag_store=*/nullptr,
                          /*analytics_store=*/nullptr, rig.oidc_mu, rig.oidc_provider);
        httplib::Response aware;
        CHECK_FALSE(bad_ar.probe_permission_unavailable_aware(ana, aware, "Forensics", "Read"));
        CHECK(aware.status == 503);
        httplib::Response plain;
        CHECK_FALSE(bad_ar.probe_permission(ana, plain, "Forensics", "Read"));
        CHECK(plain.status == 403);
    }

    SECTION("an engine principal: a query-level failure is a 403 by default, a 503 when opted in") {
        REQUIRE(rig.auth_mgr.upsert_user("owner9", "password1234", auth::Role::admin));
        REQUIRE(rig.engines->create("Vuln Sync 9", "owner9", "typed unavailable test", "internal",
                                    "admin", "engine:vuln9")
                    .has_value());
        auto raw = rig.api_tokens->create_token("engine-token9", "engine:vuln9",
                                                forensics_vis_now() + 3600, "", "readonly", "engine");
        REQUIRE(raw.has_value());
        auto req = rig.bearer_request(*raw);
        DegradedReplica d(rig);
        RoleReadFault fault(rig.rbac_bundle.dsn());
        fault.arm();
        expect_aware_503(d, req);
        expect_default_403(d, req);
    }

    SECTION("a service-scoped token is unchanged: a degraded read is still a definitive 403") {
        REQUIRE(rig.auth_mgr.upsert_user("minter", "password1234", auth::Role::admin));
        REQUIRE(rig.rbac.assign_role({"user", "minter", "Administrator"}).has_value());
        auto raw = rig.api_tokens->create_token("svc", "minter", forensics_vis_now() + 3600, "billing");
        REQUIRE(raw.has_value());
        auto req = rig.bearer_request(*raw);
        DegradedReplica d(rig);
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        auto held = d.pool.acquire();
        REQUIRE(held);
        httplib::Response res;
        CHECK_FALSE(d.ar.probe_permission_unavailable_aware(req, res, "Forensics", "Read"));
        CHECK(res.status == 403); // the allow-list refuses it whatever the store says
    }
}

TEST_CASE("forensics visibility: an unavailable global proof is Unknown for every caller class, "
          "counted, and recovers; a definitive refusal stays Denied",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.rbac.assign_role({"user", "ana", "ForensicsAnalyst"}).has_value());
    REQUIRE(rig.rbac.assign_role({"user", "vic", "Viewer"}).has_value());
    auto ana = rig.cookie_request("ana", auth::Role::user);
    auto vic = rig.cookie_request("vic", auth::Role::user);

    SECTION("a failed role query: the analyst is Unknown, not silently Denied; recovery grants again") {
        DegradedReplica d(rig);
        const auto deps = d.deps(rig);
        RoleReadFault fault(rig.rbac_bundle.dsn());
        fault.arm();
        CHECK(is_unknown(resolve_forensics_visible(deps, ana), ForensicsUnknown::RbacUnavailable));
        CHECK(rig.withheld("rbac_unavailable") == 1.0);
        CHECK(d.degrade("query_error") >= 1.0);
        fault.repair();
        CHECK(is_global(resolve_forensics_visible(deps, ana)));
        CHECK(rig.withheld("rbac_unavailable") == 1.0); // no further movement once healthy
    }

    SECTION("a starved pool: ordinary cookie session and bearer token are both Unknown") {
        DegradedReplica d(rig);
        const auto deps = d.deps(rig);
        auto raw = rig.api_tokens->create_token("t2", "ana", forensics_vis_now() + 3600);
        REQUIRE(raw.has_value());
        auto bearer = rig.bearer_request(*raw);
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        auto held = d.pool.acquire();
        REQUIRE(held);
        CHECK(is_unknown(resolve_forensics_visible(deps, ana), ForensicsUnknown::RbacUnavailable));
        CHECK(is_unknown(resolve_forensics_visible(deps, bearer), ForensicsUnknown::RbacUnavailable));
        CHECK(rig.withheld("rbac_unavailable") == 2.0);
    }

    SECTION("a healthy store: a Viewer and a role-less user are Denied, never counted") {
        DegradedReplica d(rig);
        const auto deps = d.deps(rig);
        auto nobody = rig.cookie_request("nobody", auth::Role::user);
        CHECK(is_present_empty(resolve_forensics_visible(deps, vic)));
        CHECK(is_present_empty(resolve_forensics_visible(deps, nobody)));
        CHECK(is_global(resolve_forensics_visible(deps, ana)));
        for (const auto why : kForensicsUnknownReasons)
            CHECK(rig.withheld(std::string(to_string(why))) == 0.0);
        CHECK(d.degrade("query_error") == 0.0);
    }
}

// ── A scoped grant is never consulted, for any caller class (#4990, W1) ───────────────
// There is no scoped Forensics read tier: the resolver has one global proof and nothing else.
// Each of these cases gives the OWNER a scoped-only Forensics:Read grant (no global one) and
// asserts that NO caller class derived from that owner (cookie session, plain token, service-scoped
// token, MCP-tier token, engine principal) is handed a subset: every one is Denied (present-empty).
// A Denied answer is silent: no counter moves. These are regression pins against a future change
// that reintroduces a per-caller-class scoped composition.

TEST_CASE("forensics visibility: a scoped-grant holder gets nothing on any session or token, including "
          "a service-scoped token",
          "[pg][auth_routes][authz_topology_floor][forensics][service_scope]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.auth_mgr.upsert_user("sk1", "password1234", auth::Role::user));
    REQUIRE(rig.mgmt.assign_role({rig.group_id, "user", "sk1", "ForensicsScoped"}).has_value());

    auto cookie = rig.cookie_request("sk1", auth::Role::user);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), cookie)));

    auto plain = rig.api_tokens->create_token("plain", "sk1", forensics_vis_now() + 3600);
    REQUIRE(plain.has_value());
    auto plain_req = rig.bearer_request(*plain);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), plain_req)));

    auto svc = rig.api_tokens->create_token("svc", "sk1", forensics_vis_now() + 3600, "billing");
    REQUIRE(svc.has_value());
    auto svc_req = rig.bearer_request(*svc);
    auto session = rig.ar->resolve_session(svc_req);
    REQUIRE(session.has_value());
    REQUIRE_FALSE(session->token_scope_service.empty()); // prove it really is a service-scoped session
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), svc_req)));

    for (const auto why : kForensicsUnknownReasons)
        CHECK(rig.withheld(std::string(to_string(why))) == 0.0); // a refusal is never counted
}

TEST_CASE("forensics visibility: an MCP-tier token minted by a scoped-grant holder gets nothing, "
          "and a global holder's MCP-tier token keeps the global read",
          "[pg][auth_routes][authz_topology_floor][forensics]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.auth_mgr.upsert_user("mk1", "password1234", auth::Role::user));
    REQUIRE(rig.mgmt.assign_role({rig.group_id, "user", "mk1", "ForensicsScoped"}).has_value());

    auto mcp = rig.api_tokens->create_token("mcp", "mk1", forensics_vis_now() + 3600, "", "readonly");
    REQUIRE(mcp.has_value());
    auto mcp_req = rig.bearer_request(*mcp);
    auto session = rig.ar->resolve_session(mcp_req);
    REQUIRE(session.has_value());
    REQUIRE_FALSE(session->mcp_tier.empty()); // prove it really is an MCP-tier session
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), mcp_req)));

    // A user who holds the GLOBAL read keeps it through a read-tier MCP token (Read is allowed at
    // the readonly tier; the tier narrows operations, it does not remove a global grant).
    REQUIRE(rig.auth_mgr.upsert_user("mk2", "password1234", auth::Role::user));
    REQUIRE(rig.rbac.assign_role({"user", "mk2", "ForensicsAnalyst"}).has_value());
    auto mcp2 = rig.api_tokens->create_token("mcp2", "mk2", forensics_vis_now() + 3600, "", "readonly");
    REQUIRE(mcp2.has_value());
    auto mcp2_req = rig.bearer_request(*mcp2);
    CHECK(is_global(resolve_forensics_visible(rig.deps(), mcp2_req)));

    for (const auto why : kForensicsUnknownReasons)
        CHECK(rig.withheld(std::string(to_string(why))) == 0.0);
}

TEST_CASE("forensics visibility: an engine principal holding only a scoped grant gets nothing",
          "[pg][auth_routes][authz_topology_floor][forensics][engine_principal]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.auth_mgr.upsert_user("owner3", "password1234", auth::Role::admin));
    REQUIRE(rig.engines->create("Vuln Sync 3", "owner3", "forensics visibility test", "internal",
                                "admin", "engine:vuln3")
                .has_value());
    // The store API refuses a scoped engine grant ("engine principals cannot hold scoped role
    // assignments"), so the only way such a row can exist is direct SQL. Insert one and prove the
    // resolver still gives the engine nothing: the resolver never reads scoped grants, so the store
    // guard is not what this case depends on.
    auto refused = rig.mgmt.assign_role({rig.group_id, "engine", "engine:vuln3", "ForensicsScoped"});
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("cannot hold scoped") != std::string::npos);
    {
        yuzu::server::pg::PgPool pool{{.conninfo = rig.mgmt_bundle.dsn(), .size = 1}};
        auto lease = pool.acquire();
        REQUIRE(lease);
        REQUIRE(yuzu::server::pg::exec_params(
                    lease.get(),
                    "INSERT INTO management_group_store.management_group_roles "
                    "(group_id, principal_type, principal_id, role_name) VALUES ($1, 'engine', "
                    "'engine:vuln3', 'ForensicsScoped')",
                    std::vector<std::string>{rig.group_id})
                    .status() == PGRES_COMMAND_OK);
    }
    auto raw = rig.api_tokens->create_token("engine-token3", "engine:vuln3",
                                            forensics_vis_now() + 3600, "", "readonly", "engine");
    REQUIRE(raw.has_value());
    auto req = rig.bearer_request(*raw);
    auto session = rig.ar->resolve_session(req);
    REQUIRE(session.has_value());
    REQUIRE(session->is_engine());
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), req)));
    for (const auto why : kForensicsUnknownReasons)
        CHECK(rig.withheld(std::string(to_string(why))) == 0.0);
}

TEST_CASE("forensics visibility: an engine principal cannot be granted a Forensics read fleet-wide "
          "through a built-in role",
          "[pg][auth_routes][authz_topology_floor][forensics][engine_principal][forensics_analyst]") {
    ForensicsVisRig rig;
    rig.rbac.set_rbac_enabled(true);
    REQUIRE(rig.auth_mgr.upsert_user("owner4", "password1234", auth::Role::admin));
    REQUIRE(rig.engines->create("Vuln Sync 4", "owner4", "forensics visibility test", "internal",
                                "admin", "engine:vuln4")
                .has_value());
    // The delegable role is a built-in system role, so the engine-principal bar refuses it; the
    // resolver therefore never sees an engine principal with a global Forensics:Read from it.
    CHECK_FALSE(rig.rbac.assign_role({"engine", "engine:vuln4", "ForensicsAnalyst"}).has_value());
    auto raw = rig.api_tokens->create_token("engine-token4", "engine:vuln4",
                                            forensics_vis_now() + 3600, "", "readonly", "engine");
    REQUIRE(raw.has_value());
    auto req = rig.bearer_request(*raw);
    CHECK(is_present_empty(resolve_forensics_visible(rig.deps(), req)));
}
