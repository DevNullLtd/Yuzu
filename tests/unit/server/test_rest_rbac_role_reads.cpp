/**
 * test_rest_rbac_role_reads.cpp — GET /api/v1/rbac/roles and
 * GET /api/v1/rbac/roles/{role}/permissions fail closed.
 *
 * Both reads used to answer an authoritative-looking `200` with an empty list when the RBAC
 * store was degraded (closed, pool-acquire timeout, query error), and the permissions read
 * also answered `200 {"data":[]}` for a role that does not exist. An empty roles list or an
 * empty permission set is exactly what an operator reads as "nobody has any access", so a
 * degraded read must never look like one:
 *
 *   - degraded store                 -> 503 A4 envelope, retry_after_ms 5000, fixed message
 *   - role not in the roles table    -> 404 A4 envelope (permissions route only)
 *   - otherwise                      -> the unchanged 200
 *
 * The non-Postgres case drives a store that never opened (so the degraded path needs no
 * database and runs in every shard); the [pg] cases cover the live success shape, the 404
 * and a permissions read that fails AFTER the role is known. The roles-read query-error and
 * pool-timeout branches are store-level behaviour and are pinned in test_rbac_store.cpp.
 */

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_rbac_store_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <optional>
#include <string>

using namespace yuzu::server;
using json = nlohmann::json;
using namespace std::string_literals;

namespace {

/// One RestApiV1 with only the RBAC store wired (everything after `audit_store` in
/// `register_routes` is a trailing optional dependency, so the 15-argument form is the
/// shortest legal call). `perm_override` lets a test deny one (securable, operation).
struct RoleReadsHarness {
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink; // declared AFTER `api`: handlers capture it

    std::function<bool(const std::string&, const std::string&)> perm_override{};

    explicit RoleReadsHarness(RbacStore* rbac_store) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::user;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            if (perm_override && !perm_override(type, op)) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&,
                           const std::string&) -> bool { return true; };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn, rbac_store,
                            /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr);
    }
};

/// The shared degraded-read contract: a retryable A4 503 with a fixed message, and no data
/// envelope an empty list could be read from.
void check_degraded_503(const httplib::Response& res) {
    CHECK(res.status == 503);
    const json body = json::parse(res.body, nullptr, /*allow_exceptions=*/false);
    REQUIRE(body.is_object());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == 503);
    CHECK(body["error"]["message"] == "rbac store read degraded");
    CHECK(body["error"]["retry_after_ms"] == 5000);
    CHECK(body["error"].contains("correlation_id"));
    CHECK_FALSE(body.contains("data"));
    CHECK_FALSE(body.contains("pagination"));
}

void exec_on_db(const std::string& dsn, const char* sql) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(conn.get(), sql)};
    REQUIRE(r.ok());
}

} // namespace

TEST_CASE("RBAC role reads: a store that is not open is a 503 behind the gate, never an "
          "empty 200 or a 404",
          "[rest][rbac][reads]") {
    // Deliberately NOT tagged [pg]: the pool is dead, no database fixture runs, so the case
    // needs no Postgres and runs in the non-pg shards with or without a DSN.
    yuzu::server::pg::PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope "
                                              "connect_timeout=1",
                                  .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());
    RoleReadsHarness h{&broken};

    SECTION("the gate runs first: a caller without UserManagement:Read gets the 403, not the "
            "degrade") {
        h.perm_override = [](const std::string& securable, const std::string& op) {
            return !(securable == "UserManagement" && op == "Read");
        };
        for (const char* path :
             {"/api/v1/rbac/roles", "/api/v1/rbac/roles/Administrator/permissions"}) {
            INFO(path);
            auto res = h.sink.Get(path);
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(res->body.find("retry_after_ms") == std::string::npos);
        }
    }

    SECTION("GET /rbac/roles") {
        auto res = h.sink.Get("/api/v1/rbac/roles");
        REQUIRE(res);
        check_degraded_503(*res);
    }

    SECTION("GET /rbac/roles/{role}/permissions: the existence check must not turn a "
            "degraded read into a 404") {
        auto res = h.sink.Get("/api/v1/rbac/roles/Administrator/permissions");
        REQUIRE(res);
        CHECK(res->status != 404);
        check_degraded_503(*res);
    }
}

TEST_CASE("RBAC role reads: a live store lists roles, 404s a role that does not exist, and "
          "still lists a known role's permissions",
          "[rest][rbac][reads][pg]") {
    yuzu::test::RbacStorePg rbac_bundle; // SKIPs without a PG DSN
    RoleReadsHarness h{rbac_bundle.get()};

    // GET /rbac/roles: the unchanged success shape.
    {
        auto res = h.sink.Get("/api/v1/rbac/roles");
        REQUIRE(res);
        CHECK(res->status == 200);
        const json body = json::parse(res->body);
        REQUIRE(body["data"].is_array());
        CHECK(body["data"].size() >= 7);
        CHECK(body["pagination"]["total"] == body["data"].size());
        CHECK(std::any_of(body["data"].begin(), body["data"].end(),
                          [](const json& r) { return r["name"] == "Administrator"; }));
    }

    // A known role: 200 with its rows.
    {
        auto res = h.sink.Get("/api/v1/rbac/roles/Administrator/permissions");
        REQUIRE(res);
        CHECK(res->status == 200);
        const json body = json::parse(res->body);
        REQUIRE(body["data"].is_array());
        CHECK_FALSE(body["data"].empty());
    }

    // A name that is not in the roles table is a 404, never `200 {"data":[]}`. The existence
    // check is an exact compare: a different case, a name carrying a path separator, and a
    // name with an embedded NUL (libpq would have truncated it into the real role name) are
    // all absent.
    for (const std::string& name :
         {"NoSuchRole"s, "administrator"s, "Administrator"s + '\0' + "x", "Operator/extra"s}) {
        INFO("role name: " << name);
        auto res = h.sink.Get("/api/v1/rbac/roles/" + name + "/permissions");
        REQUIRE(res);
        CHECK(res->status == 404);
        const json body = json::parse(res->body, nullptr, /*allow_exceptions=*/false);
        REQUIRE(body.is_object());
        CHECK(body["error"]["message"] == "role not found");
        CHECK(body["error"].contains("correlation_id"));
        CHECK_FALSE(body.contains("data"));
    }
}

TEST_CASE("RBAC role reads: a permissions read that fails after the role is known is a 503, "
          "not an empty 200",
          "[rest][rbac][reads][pg]") {
    yuzu::test::RbacStorePg rbac_bundle; // SKIPs without a PG DSN
    RoleReadsHarness h{rbac_bundle.get()};

    // The roles table stays intact, so the existence check passes and only the permissions
    // read fails: the route must not fall back to an empty list.
    exec_on_db(rbac_bundle.dsn(), "DROP TABLE rbac_store.role_permissions CASCADE");

    auto res = h.sink.Get("/api/v1/rbac/roles/Administrator/permissions");
    REQUIRE(res);
    check_degraded_503(*res);

    // The roles list does not read that table and is unaffected.
    auto roles = h.sink.Get("/api/v1/rbac/roles");
    REQUIRE(roles);
    CHECK(roles->status == 200);
}
