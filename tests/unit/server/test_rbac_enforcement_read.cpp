/**
 * test_rbac_enforcement_read.cpp - `read_rbac_enforcement` (rbac_enforcement_read.hpp), the one
 * builder behind the machine twins of the Users and roles page's enforcement fragment, and the
 * REST route that serves it, `GET /api/v1/rbac/enforcement` (#6033).
 *
 * Three layers:
 *   1. The builder with no database: the wire spelling of the verdict, and the one error it has
 *      (a null or closed RBAC store), which the REST route answers as a retryable 503.
 *   2. The builder on a DEGRADED enforcement view. `unconfirmed` (the cached view's freshness) and
 *      `administrator` (the hint, whose verdict comes from the durable stores) answer different
 *      questions, and the builder neither forces nor suppresses the verdict on a degraded view:
 *      an engine or an MCP-tier credential on REST is `may_not`, a confirmed administrator is
 *      `may`, an administrator with no grant row follows the hint: `unconfirmed` while the
 *      cached value is a stale OFF (a store that cannot confirm the answer cannot call a missing
 *      row a denial), `may_not` while it is a stale ON (the label is then `enabled`).
 *   3. The REST route through the shared RbacRoleHarness: the body for RBAC off and on, the
 *      verdict equals `rbac_admin_hint(..., kRest)` for the personas the hint matrix already pins
 *      (P1, P2, P3, P7c, P13), the structural cases (MCP-tier token, engine, SAML, service-scoped),
 *      and the audit contract (one server-authored row per successful read, fail closed when the
 *      row cannot be persisted, nothing written for a bare 401 or an unavailable store). It also
 *      pins the SESSION-ONLY gate (a permission callback that denies everything is never
 *      consulted) and serves a degraded view through the route, so the wire `unconfirmed` is the
 *      store's flag and not a constant.
 *
 * Layers 2 and 3 are PG-gated and skip when YUZU_TEST_POSTGRES_DSN is unset (a skip is NOT a
 * pass). Layer 1 needs no database: its closed store is built over a pool that never connects.
 */

#include "mcp_retry.hpp" // mcp::kMcpStoreFaultRetryMs
#include "rbac_admin_predicate.hpp"
#include "rbac_enforcement_read.hpp"
#include "saml_principal.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "test_rbac_admin_surface_harness.hpp" // AuditRecord, RbacRoleHarness

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kPath = "/api/v1/rbac/enforcement";
constexpr const char* kAuditAction = "rbac.enforcement.read";

// The verdict spellings are a wire contract shared by REST and MCP, so they are pinned at compile
// time as well as at run time below.
static_assert(to_string(RbacAdminHint::kMay) == "may");
static_assert(to_string(RbacAdminHint::kMayNot) == "may_not");
static_assert(to_string(RbacAdminHint::kUnconfirmed) == "unconfirmed");

nlohmann::json parse_json(const std::string& body) {
    auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(j.is_discarded());
    return j;
}

/// The `data` object of a 200 answer, after checking the envelope and that `data` carries
/// exactly the three documented keys and nothing else.
nlohmann::json data_of(const std::string& body) {
    const auto j = parse_json(body);
    REQUIRE(j.is_object());
    REQUIRE(j.contains("data"));
    REQUIRE(j.contains("meta"));
    const auto& d = j["data"];
    REQUIRE(d.is_object());
    CHECK(d.size() == 3);
    REQUIRE(d.contains("enabled"));
    REQUIRE(d.contains("unconfirmed"));
    REQUIRE(d.contains("administrator"));
    CHECK(d["enabled"].is_boolean());
    CHECK(d["unconfirmed"].is_boolean());
    CHECK(d["administrator"].is_string());
    return d;
}

std::size_t count_rows(const RbacRoleHarness& h, const std::string& action) {
    std::size_t n = 0;
    for (const auto& r : h.audit_log)
        if (r.action == action)
            ++n;
    return n;
}

void make_user(RbacRoleHarness& h, const std::string& name, auth::Role role) {
    REQUIRE(h.auth_db->upsert_user(name, "hash", "salt", role).has_value());
}

/// A SAML session of the production shape (see test_rbac_admin_hint.cpp): the principal can never
/// be an auth.users row, so the regime check refuses it although the predicate admits.
void make_saml_caller(RbacRoleHarness& h) {
    h.session_user = saml::saml_principal_id("https://idp.example", "alice");
    h.session_auth_source = "saml";
    REQUIRE_FALSE(is_valid_username(h.session_user));
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
}

/// The break-glass rename P13 uses: the regime check's auth.users JOIN cannot run, while the
/// predicate (principal_roles) still answers.
void make_regime_store_unreadable(RbacRoleHarness& h) {
    auto lease = h.auth_db.pool().acquire();
    REQUIRE(lease);
    auto r = pg::exec_params(lease.get(), "ALTER TABLE auth.users RENAME TO users_hint_gone",
                             std::vector<std::string>{});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

/// Removes the durable `rbac_enabled` row from the disposable clone. The schema's CHECK constraint
/// (`rbac_meta_enabled_canonical`) rejects a non-canonical value at write time, so an absent row is
/// the one way to leave the flag unconfirmable on a refresh that still reads `write_generation`.
void delete_rbac_enabled_row(RbacRoleHarness& h) {
    auto lease = h.auth_db.pool().acquire();
    REQUIRE(lease);
    auto r = pg::exec_params(lease.get(),
                             "DELETE FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled'",
                             std::vector<std::string>{});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

RbacAdminHint hint_of(RbacRoleHarness& h) {
    return rbac_admin_hint(h.rest_session(), h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest);
}

/// The route answers 200, `administrator` is the spelling of the hint computed from the same
/// stores for the same session, and `enabled` / `unconfirmed` are the store's own display view.
/// Returns the parsed `data` so a caller can add checks.
nlohmann::json check_read_equals_hint(RbacRoleHarness& h, RbacAdminHint expected) {
    const auto hint = hint_of(h);
    INFO("hint=" << to_string(hint) << " expected=" << to_string(expected));
    CHECK(hint == expected);

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    REQUIRE(res->status == 200);
    const auto d = data_of(res->body);
    CHECK(d["administrator"].get<std::string>() == std::string(to_string(hint)));
    CHECK(d["enabled"].get<bool>() == h.rbac->is_rbac_enabled());
    CHECK(d["unconfirmed"].get<bool>() == h.rbac->rbac_enabled_view_degraded());
    return d;
}

/// Pushes `replica` past the stale-serve bound with a genuinely FAILED refresh (its one pooled
/// connection is held), then frees the connection so the replica's later durable reads work. This
/// is the construction test_rbac_admin_predicate.cpp documents for the degraded view: elapsed time
/// alone would let the next healthy refresh heal the view before the builder observed it.
void degrade_view(RbacStore& replica, pg::PgPool& pool) {
    replica.age_refresh_state_for_test(std::chrono::milliseconds(1100));
    auto held = pool.acquire();
    REQUIRE(held);
    (void)rbac_enforcement_in_effect(&replica); // a failed refresh, still inside the bound
    replica.age_refresh_state_for_test(std::chrono::milliseconds(4200));
    (void)rbac_enforcement_in_effect(&replica); // the failed refresh that exceeds the bound
    REQUIRE(replica.rbac_enabled_view_degraded());
    held.reset();
}

/// A bare REST registration for the cases the shared harness cannot express: an RBAC store that is
/// null or closed, and an unwired audit callback. The route under test only needs a session, the
/// two stores and the audit hook. `api` is declared before `sink` so the handlers' owner outlives
/// the sink holding them.
struct ReadRoute {
    std::vector<AuditRecord> audit_log;
    std::string username{"admin"};
    /// False stands in for the production auth callback on a request with no session: it writes
    /// the 401 itself and yields no session (the shared harness's hook writes nothing).
    bool authenticated{true};
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    // The handlers capture `this`, so a copy would point at the original's members.
    ReadRoute(const ReadRoute&) = delete;
    ReadRoute& operator=(const ReadRoute&) = delete;

    ReadRoute(RbacStore* rbac, AuthDB* auth_db, bool audit_wired) {
        RestApiV1::AuthFn auth_fn = [this](const httplib::Request&,
                                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!authenticated) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"unauthorized"}})",
                                "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = username;
            return s;
        };
        RestApiV1::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&) { return true; };
        RestApiV1::AuditFn audit_fn;
        if (audit_wired) {
            audit_fn = [this](const httplib::Request&, const std::string& action,
                              const std::string& result, const std::string& target_type,
                              const std::string& target_id, const std::string& detail) -> bool {
                audit_log.push_back({action, result, target_id, detail, target_type});
                return true;
            };
        }
        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/rbac,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
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
                            /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/auth_db);
    }
};

/// The 503 the route answers for an RBAC store it cannot use: a generic message, the shared retry
/// hint, no audit row, and none of the builder's log-only text.
void check_store_unavailable_503(ReadRoute& route) {
    const auto res = route.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    CHECK(res->status == 503);
    const auto j = parse_json(res->body);
    REQUIRE(j.contains("error"));
    CHECK(j["error"]["message"] == "service unavailable");
    REQUIRE(j["error"].contains("retry_after_ms"));
    REQUIRE(j["error"]["retry_after_ms"].is_number_integer());
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == mcp::kMcpStoreFaultRetryMs);
    CHECK_FALSE(j.contains("data"));
    CHECK(res->body.find("rbac store not open") == std::string::npos);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    CHECK(route.audit_log.empty());
}

} // namespace

// ── Layer 1: the builder, no database ────────────────────────────────────────

TEST_CASE("read_rbac_enforcement: to_string spells the three verdicts and fails safe on an unknown one",
          "[rbac_enforcement_read]") {
    CHECK(to_string(RbacAdminHint::kMay) == "may");
    CHECK(to_string(RbacAdminHint::kMayNot) == "may_not");
    CHECK(to_string(RbacAdminHint::kUnconfirmed) == "unconfirmed");
    // An enumerator the switch does not know reads as "could not confirm", never as an admit.
    CHECK(to_string(static_cast<RbacAdminHint>(99)) == "unconfirmed");
}

TEST_CASE("read_rbac_enforcement: a null RBAC store is the error on both surfaces",
          "[rbac_enforcement_read]") {
    auth::Session s;
    s.username = "whoever";
    for (const auto surface : {RbacAdminSurface::kRest, RbacAdminSurface::kMcp}) {
        const auto r = read_rbac_enforcement(s, nullptr, nullptr, surface);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "rbac store not open");
    }
}

TEST_CASE("read_rbac_enforcement: a closed RBAC store is the error on both surfaces",
          "[rbac_enforcement_read]") {
    // A pool whose DSN never connects leaves the store's construction lease empty, so migration
    // never runs and is_open() is false (the construction test_rbac_store.cpp uses).
    pg::PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                    .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());
    auth::Session s;
    s.username = "whoever";
    for (const auto surface : {RbacAdminSurface::kRest, RbacAdminSurface::kMcp}) {
        const auto r = read_rbac_enforcement(s, nullptr, &broken, surface);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "rbac store not open");
    }
}

TEST_CASE("GET /api/v1/rbac/enforcement: a null RBAC store answers 503 with the retry hint and no audit row",
          "[rbac_enforcement_read]") {
    ReadRoute route{nullptr, nullptr, /*audit_wired=*/true};
    check_store_unavailable_503(route);
}

TEST_CASE("GET /api/v1/rbac/enforcement: a closed RBAC store answers 503 with the retry hint and no audit row",
          "[rbac_enforcement_read]") {
    pg::PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                    .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());
    ReadRoute route{&broken, nullptr, /*audit_wired=*/true};
    check_store_unavailable_503(route);
}

// ── Layer 2: the builder on a degraded enforcement view (PG) ─────────────────

TEST_CASE("read_rbac_enforcement: a degraded view is unconfirmed:true and administrator still follows the hint",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    pg::PgPool pool_b{{.conninfo = h.auth_db.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());

    SECTION("a confirmed administrator reads may while the view is degraded") {
        h.make_caller_admin(/*rbac_on=*/true); // role=user + grant + active auth.users row
        RbacStore replica{pool_b};
        REQUIRE(replica.is_open());
        degrade_view(replica, pool_b);

        const auto r = read_rbac_enforcement(h.rest_session(), h.auth_db.get(), &replica,
                                             RbacAdminSurface::kRest);
        REQUIRE(r.has_value());
        CHECK(r->unconfirmed);
        CHECK(r->enabled); // a cached "on" gone stale: enforcement is in effect either way
        CHECK(r->administrator == RbacAdminHint::kMay);
    }

    SECTION("a stale-off view: an administrator with no grant row follows the hint (unconfirmed), not may_not") {
        make_user(h, h.session_user, auth::Role::user);
        RbacStore replica{pool_b};
        REQUIRE(replica.is_open());
        degrade_view(replica, pool_b);

        const auto hint = rbac_admin_hint(h.rest_session(), h.auth_db.get(), &replica,
                                          RbacAdminSurface::kRest);
        const auto r = read_rbac_enforcement(h.rest_session(), h.auth_db.get(), &replica,
                                             RbacAdminSurface::kRest);
        REQUIRE(r.has_value());
        CHECK(r->unconfirmed);
        CHECK(r->administrator == hint);
        // A stale OFF view cannot call a missing grant row a confirmed denial (a stale ON
        // view can: see the stale-on route case, which reads may_not).
        CHECK(r->administrator == RbacAdminHint::kUnconfirmed);
    }

    SECTION("an engine principal reads may_not while the view is degraded") {
        h.make_caller_admin(/*rbac_on=*/true);
        h.session_principal_kind = "engine";
        RbacStore replica{pool_b};
        REQUIRE(replica.is_open());
        degrade_view(replica, pool_b);

        const auto r = read_rbac_enforcement(h.rest_session(), h.auth_db.get(), &replica,
                                             RbacAdminSurface::kRest);
        REQUIRE(r.has_value());
        CHECK(r->unconfirmed);
        CHECK(r->administrator == RbacAdminHint::kMayNot);
    }

    SECTION("an MCP-tier credential on REST reads may_not while the view is degraded") {
        h.make_caller_admin(/*rbac_on=*/true);
        h.rest_session_mcp_tier = "supervised";
        RbacStore replica{pool_b};
        REQUIRE(replica.is_open());
        degrade_view(replica, pool_b);

        const auto r = read_rbac_enforcement(h.rest_session(), h.auth_db.get(), &replica,
                                             RbacAdminSurface::kRest);
        REQUIRE(r.has_value());
        CHECK(r->unconfirmed);
        CHECK(r->administrator == RbacAdminHint::kMayNot);
    }
}

// ── Layer 3: the REST route (PG) ─────────────────────────────────────────────

TEST_CASE("GET /api/v1/rbac/enforcement: RBAC off body, no-store header, one audit row",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.session_user = "audit-probe-user";
    h.make_caller_admin(/*rbac_on=*/false);

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    REQUIRE(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    const auto d = data_of(res->body);
    CHECK(d["enabled"] == false);
    CHECK(d["unconfirmed"] == false);
    CHECK(d["administrator"] == "may");

    // Exactly one row, and its detail is built from the answer alone: nothing from the session.
    REQUIRE(h.audit_log.size() == 1);
    const auto& row = h.audit_log.front();
    CHECK(row.action == kAuditAction);
    CHECK(row.result == "success");
    CHECK(row.target_type == "Setting");
    CHECK(row.target_id == "rbac_enabled");
    CHECK(row.detail == "enabled=false; unconfirmed=false; administrator=may");
    CHECK(row.detail.find("audit-probe-user") == std::string::npos);
}

TEST_CASE("GET /api/v1/rbac/enforcement: RBAC on body and audit detail",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.session_user = "audit-probe-user";
    h.make_caller_admin(/*rbac_on=*/true);

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    REQUIRE(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    const auto d = data_of(res->body);
    CHECK(d["enabled"] == true);
    CHECK(d["unconfirmed"] == false);
    CHECK(d["administrator"] == "may");

    REQUIRE(count_rows(h, kAuditAction) == 1);
    CHECK(h.audit_log.front().detail == "enabled=true; unconfirmed=false; administrator=may");
    CHECK(h.audit_log.front().detail.find("audit-probe-user") == std::string::npos);
}

TEST_CASE("GET /api/v1/rbac/enforcement: verdict equals rbac_admin_hint on kRest for P1 (base admin, RBAC off)",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    check_read_equals_hint(h, RbacAdminHint::kMay);
}

TEST_CASE("GET /api/v1/rbac/enforcement: verdict equals rbac_admin_hint on kRest for P2 (base admin, no grant, RBAC on)",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    const auto d = check_read_equals_hint(h, RbacAdminHint::kMayNot);
    CHECK(d["enabled"] == true);
}

TEST_CASE("GET /api/v1/rbac/enforcement: verdict equals rbac_admin_hint on kRest for P3 (base admin with the grant, RBAC on)",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_read_equals_hint(h, RbacAdminHint::kMay);
}

TEST_CASE("GET /api/v1/rbac/enforcement: verdict equals rbac_admin_hint on kRest for P7c (SAML principal with no auth.users row)",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    make_saml_caller(h);
    // The predicate admits (bare principal_roles membership); the regime check refuses, so a
    // predicate-only answer would overstate here.
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_read_equals_hint(h, RbacAdminHint::kMayNot);
}

TEST_CASE("GET /api/v1/rbac/enforcement: verdict equals rbac_admin_hint on kRest for P13 (regime store unreadable)",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    make_regime_store_unreadable(h);
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    REQUIRE(res->status == 200);
    const auto d = data_of(res->body);
    // The view is healthy (unconfirmed:false) while the hint could not be confirmed: the two
    // groups answer different questions.
    CHECK(d["unconfirmed"] == false);
    CHECK(d["administrator"] == "unconfirmed");
    CHECK(d["administrator"].get<std::string>() == std::string(to_string(hint_of(h))));
    // No driver or relation text reaches the caller.
    CHECK(res->body.find("users_hint_gone") == std::string::npos);
    CHECK(res->body.find("relation \"") == std::string::npos);
    CHECK(res->body.find("does not exist") == std::string::npos);
    CHECK(res->body.find("auth.users") == std::string::npos);
}

TEST_CASE("GET /api/v1/rbac/enforcement: an MCP-tier token on REST is 200 with administrator may_not",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.rest_session_mcp_tier = "supervised";
    const auto d = check_read_equals_hint(h, RbacAdminHint::kMayNot);
    CHECK(d["administrator"] == "may_not");
    CHECK(count_rows(h, kAuditAction) == 1); // a read, not a refusal: audited as a success
}

TEST_CASE("GET /api/v1/rbac/enforcement: an engine principal is 200 with administrator may_not",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_principal_kind = "engine";
    const auto d = check_read_equals_hint(h, RbacAdminHint::kMayNot);
    CHECK(d["administrator"] == "may_not");
}

TEST_CASE("GET /api/v1/rbac/enforcement: a SAML principal is 200 with administrator may_not",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    make_saml_caller(h);
    const auto d = check_read_equals_hint(h, RbacAdminHint::kMayNot);
    CHECK(d["administrator"] == "may_not");
}

TEST_CASE("GET /api/v1/rbac/enforcement: an OIDC-provisioned principal with a durable Administrator grant reads may",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.session_user = "oidc:https://idp.example#sub-1";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    SECTION("provisioned by the real login path: an active auth.users row, so the regime check admits") {
        // AuthDB::upsert_sso_identity is what an OIDC login provisions through (role user,
        // is_active TRUE), so an OIDC administrator who holds the grant is NOT a may_not case.
        REQUIRE(h.auth_db
                    ->upsert_sso_identity(h.session_user, "https://idp.example", "sub-1", "Alice",
                                          "oidc")
                    .has_value());
        const auto d = check_read_equals_hint(h, RbacAdminHint::kMay);
        CHECK(d["enabled"] == true);
        CHECK(d["unconfirmed"] == false);
        CHECK(d["administrator"] == "may");

        REQUIRE(count_rows(h, kAuditAction) == 1);
        CHECK(h.audit_log.front().detail == "enabled=true; unconfirmed=false; administrator=may");
    }
    SECTION("contrast: the same grant with no provisioned row reads may_not (P7 at the route)") {
        const auto d = check_read_equals_hint(h, RbacAdminHint::kMayNot);
        CHECK(d["administrator"] == "may_not");
    }
}

TEST_CASE("GET /api/v1/rbac/enforcement: session-only gate: with every permission denied the read still answers 200 and no permission is asked",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    // A plain local account with no admin authority and no grants: the sort of caller a
    // permission gate would refuse, and the one who most needs to read `may_not`.
    make_user(h, h.session_user, auth::Role::user);
    std::vector<std::string> asked;
    h.perm_override = [&asked](const std::string& type, const std::string& op) {
        asked.push_back(type + ":" + op);
        return false;
    };

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    REQUIRE(res->status == 200);
    const auto d = data_of(res->body);
    CHECK(d["enabled"] == false);
    CHECK(d["unconfirmed"] == false);
    CHECK(d["administrator"] == "may_not");
    CHECK(asked.empty()); // the route never consults the permission callback
    CHECK(count_rows(h, kAuditAction) == 1);
}

TEST_CASE("GET /api/v1/rbac/enforcement: a degraded view is served on the wire and audited as unconfirmed:true",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    pg::PgPool pool_b{{.conninfo = h.auth_db.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());

    SECTION("RBAC off: enabled:false, unconfirmed:true, administrator:unconfirmed") {
        // A local administrator with no Administrator grant row, RBAC durably off. The degraded
        // view is treated as enforcement in effect, so the missing row cannot be called a denial.
        make_user(h, h.session_user, auth::Role::admin);
        RbacStore replica{pool_b};
        REQUIRE(replica.is_open());
        degrade_view(replica, pool_b);

        ReadRoute route{&replica, h.auth_db.get(), /*audit_wired=*/true};
        route.username = h.session_user;
        const auto res = route.sink.Get(kPath);
        REQUIRE(res);
        INFO("status=" << res->status << " body=" << res->body);
        REQUIRE(res->status == 200);
        const auto d = data_of(res->body);
        CHECK(d["enabled"] == false);
        CHECK(d["unconfirmed"] == true);
        CHECK(d["administrator"] == "unconfirmed");

        REQUIRE(route.audit_log.size() == 1);
        CHECK(route.audit_log.front().action == kAuditAction);
        CHECK(route.audit_log.front().detail ==
              "enabled=false; unconfirmed=true; administrator=unconfirmed");
    }

    SECTION("RBAC on: a confirmed administrator reads may while unconfirmed is true") {
        h.make_caller_admin(/*rbac_on=*/true);
        RbacStore replica{pool_b};
        REQUIRE(replica.is_open());
        degrade_view(replica, pool_b);

        ReadRoute route{&replica, h.auth_db.get(), /*audit_wired=*/true};
        route.username = h.session_user;
        const auto res = route.sink.Get(kPath);
        REQUIRE(res);
        INFO("status=" << res->status << " body=" << res->body);
        REQUIRE(res->status == 200);
        const auto d = data_of(res->body);
        CHECK(d["enabled"] == true); // a cached "on" gone stale: enforcement is in effect either way
        CHECK(d["unconfirmed"] == true);
        CHECK(d["administrator"] == "may");

        REQUIRE(route.audit_log.size() == 1);
        CHECK(route.audit_log.front().detail == "enabled=true; unconfirmed=true; administrator=may");
    }
}

TEST_CASE("GET /api/v1/rbac/enforcement: a stale-on view with no grant row reads enabled:true, unconfirmed:true, administrator:may_not",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    pg::PgPool pool_b{{.conninfo = h.auth_db.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());

    // A local human account with no Administrator grant row, RBAC durably ON, so the replica
    // caches "on" at construction and then goes stale. Enforcement is on and a missing grant row
    // is a confirmed absence, so the verdict is may_not even though the view is unconfirmed (a
    // stale OFF, by contrast, cannot call the same missing row a denial: see the RBAC-off section
    // of the degraded-view case above).
    make_user(h, h.session_user, auth::Role::user);
    h.rbac->set_rbac_enabled(true);
    RbacStore replica{pool_b};
    REQUIRE(replica.is_open());
    degrade_view(replica, pool_b);

    ReadRoute route{&replica, h.auth_db.get(), /*audit_wired=*/true};
    route.username = h.session_user;
    const auto res = route.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    REQUIRE(res->status == 200);
    const auto d = data_of(res->body);
    CHECK(d["enabled"] == true);
    CHECK(d["unconfirmed"] == true);
    CHECK(d["administrator"] == "may_not");

    REQUIRE(route.audit_log.size() == 1);
    CHECK(route.audit_log.front().action == kAuditAction);
    CHECK(route.audit_log.front().detail == "enabled=true; unconfirmed=true; administrator=may_not");
}

TEST_CASE("GET /api/v1/rbac/enforcement: a missing rbac_enabled row is a 200 with unconfirmed:true after the stale-serve bound, never a 5xx",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    // With the durable row absent, a refresh still reads write_generation but cannot confirm
    // rbac_enabled: it leaves the cached value alone (never coerced to false) and does NOT advance
    // the freshness clock (maybe_refresh_generation, row_absent). Once the last confirmed refresh is
    // past the stale-serve bound the view therefore reads degraded. `administrator` is
    // `unconfirmed` in both sections: the regime check re-reads the durable flag
    // (read_rbac_enabled_lockfree), which fails on an absent row and so answers unavailable (the
    // cached-on section, where the caller holds the grant), and a stale-off view with no grant row
    // is unconfirmed (the cached-off section). It is also pinned equal to the hint computed from
    // the same stores.
    const auto verify = [&h](bool cached_on) {
        delete_rbac_enabled_row(h);
        h.rbac->age_refresh_state_for_test(std::chrono::milliseconds(5200));

        const auto res = h.sink.Get(kPath);
        REQUIRE(res);
        INFO("status=" << res->status << " body=" << res->body);
        REQUIRE(res->status == 200); // an unconfirmable flag is a degraded view, not an error
        const auto d = data_of(res->body);
        CHECK(d["unconfirmed"] == true);
        CHECK(d["enabled"] == cached_on); // the cached value is served unchanged
        CHECK(d["administrator"] == "unconfirmed");
        CHECK(d["administrator"].get<std::string>() == std::string(to_string(hint_of(h))));
        // No driver or relation text reaches the caller.
        CHECK(res->body.find("rbac_meta") == std::string::npos);
        CHECK(res->body.find("relation \"") == std::string::npos);
        CHECK(res->body.find("does not exist") == std::string::npos);

        REQUIRE(count_rows(h, kAuditAction) == 1);
        CHECK(h.audit_log.front().detail.starts_with(std::string("enabled=") +
                                                     (cached_on ? "true" : "false") +
                                                     "; unconfirmed=true; administrator=unconfirmed"));
    };

    SECTION("cached off") {
        h.make_caller_admin(/*rbac_on=*/false);
        verify(false);
    }
    SECTION("cached on") {
        h.make_caller_admin(/*rbac_on=*/true);
        verify(true);
    }
}

TEST_CASE("GET /api/v1/rbac/enforcement: a service-scoped token is 403 with a denied audit row and no permission named",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_token_scope_service = "payments";

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    CHECK(res->status == 403);
    const auto j = parse_json(res->body);
    REQUIRE(j.contains("error"));
    CHECK_FALSE(j.contains("data"));
    // The refusal names no permission: none would admit this caller.
    CHECK_FALSE(j["error"].contains("permission"));
    CHECK(res->body.find("administrator") == std::string::npos);

    // One denied row, written by the service-scope refusal; no success row.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log.front().action == kAuditAction);
    CHECK(h.audit_log.front().result == "denied");
    CHECK(h.audit_log.front().target_type == "Setting");
}

TEST_CASE("GET /api/v1/rbac/enforcement: an unauthenticated call writes no audit row and no body",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.auth_enabled = false; // the harness auth hook answers "no session" and writes nothing itself

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    // The harness hook writes no 401, so the status is the sink's pre-set default: the route
    // added no status, no body and no cache header of its own. The real 401 is the next case.
    CHECK(res->status == 200);
    CHECK(res->body.empty());
    CHECK_FALSE(res->has_header("Cache-Control"));
    CHECK(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/rbac/enforcement: a request with no session is the auth callback's 401 and no state",
          "[rbac_enforcement_read]") {
    // No database: the auth callback answers before any store is touched.
    ReadRoute route{nullptr, nullptr, /*audit_wired=*/true};
    route.authenticated = false;

    const auto res = route.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    CHECK(res->status == 401);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    CHECK(res->body.find("\"administrator\"") == std::string::npos);
    CHECK(res->body.find("\"enabled\"") == std::string::npos);
    CHECK(route.audit_log.empty());
}

TEST_CASE("GET /api/v1/rbac/enforcement: an audit row that cannot be persisted is a 503 with Sec-Audit-Failed and no state",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.audit_allow = false;

    const auto res = h.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // The verdict is never sent: the body is the error envelope and carries none of the state.
    const auto j = parse_json(res->body);
    REQUIRE(j.contains("error"));
    CHECK_FALSE(j.contains("data"));
    // The refusal is retryable, and says when: the same shared hint as the store-unavailable 503.
    REQUIRE(j["error"].contains("retry_after_ms"));
    REQUIRE(j["error"]["retry_after_ms"].is_number_integer());
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == mcp::kMcpStoreFaultRetryMs);
    CHECK(res->body.find("\"enabled\"") == std::string::npos);
    CHECK(res->body.find("\"unconfirmed\"") == std::string::npos);
    CHECK(res->body.find("\"administrator\"") == std::string::npos);
    // The attempt itself is on record (the sink was asked, it declined to persist).
    CHECK(count_rows(h, kAuditAction) == 1);
}

TEST_CASE("GET /api/v1/rbac/enforcement: an unwired audit callback still serves 200",
          "[pg][rbac_enforcement_read]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    // Same stores as the harness, but the route is registered with an empty audit callback: an
    // audit-off deployment is not a persist failure.
    ReadRoute route{h.rbac.get(), h.auth_db.get(), /*audit_wired=*/false};
    route.username = h.session_user;
    const auto res = route.sink.Get(kPath);
    REQUIRE(res);
    INFO("status=" << res->status << " body=" << res->body);
    REQUIRE(res->status == 200);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    const auto d = data_of(res->body);
    CHECK(d["administrator"] == "may");
    CHECK(route.audit_log.empty());
}
