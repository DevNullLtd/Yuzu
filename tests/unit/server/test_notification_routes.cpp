/**
 * test_notification_routes.cpp — route-handler coverage for the operator
 * notification feed (#2542): NotificationRoutes was registered directly on a
 * raw httplib::Server, so none of its three handlers were reachable by the
 * in-process TestRouteSink harness. `NotificationRoutes::register_routes`
 * now has an HttpRouteSink overload (the httplib::Server& overload wraps +
 * delegates to it, mirroring the VerifyRoutes precedent), so the handlers
 * are drivable here with no acceptor thread (#438 TSan trap).
 *
 * Pinned per handler (read from notification_routes.cpp, not guessed):
 *   - all three routes gate on the SAME securable/operation pair per verb —
 *     `Infrastructure:Read` for the GET list, `Infrastructure:Write` for
 *     both POST mutations;
 *   - `auth_fn` is accepted by `register_routes` but is NOT called by any
 *     handler in this file — there is no session/auth gate here today, only
 *     the permission gate. That is a pre-existing property of the file
 *     being migrated, not something this migration changes, so a test
 *     asserting "no auth_fn call happens" would be testing an omission, not
 *     a contract; the harness still wires an auth_fn (unused) to keep the
 *     call shape honest;
 *   - the GET list route 503s on `!notification_store || !notification_store->is_open()`;
 *     BOTH POST routes 503 on `!notification_store` alone (no `is_open()`
 *     check) — a real-but-closed store is NOT the same gate on every route;
 *   - audit is asymmetric: POST .../read never calls `audit_fn` at all
 *     (success or 404), while POST .../dismiss calls it on BOTH outcomes —
 *     `"failure"` on an unknown id, `"success"` on a real mark. A regression
 *     that added or dropped either call must fail here.
 */

#include "notification_routes.hpp"
#include "test_route_sink.hpp"

#include "notification_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

json body(const std::string& s) { return json::parse(s); }

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};
struct PermCall {
    std::string securable_type, op;
};

/// Owner declared BEFORE the TestRouteSink member (CLAUDE.md / test_route_sink.hpp
/// ordering invariant) even though NotificationRoutes's handlers here happen not
/// to capture `this` — matching the convention keeps this fixture safe if that
/// ever changes.
struct NotificationHarness {
    NotificationRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    NotificationStore* store{nullptr};
    bool perm_allow{true};
    std::vector<AuditCall> audit_calls;
    std::vector<PermCall> perm_calls;

    /// Registration reads `store` BY VALUE into each handler's capture list
    /// (NotificationRoutes has no members of its own — every lambda captures
    /// what it needs directly), so `store` must be set before `wire()` runs;
    /// setting it afterward would register handlers still holding nullptr.
    void wire() {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "notif-op";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable_type, const std::string& op) -> bool {
            perm_calls.push_back({securable_type, op});
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            audit_calls.push_back({action, result, target_type, target_id, detail});
        };
        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, store);
    }
};

} // namespace

// ── GET /api/notifications — gate + store-unavailable, no Postgres needed ──

TEST_CASE("GET /api/notifications: gates Infrastructure:Read", "[notification_routes][security]") {
    NotificationHarness h;
    h.wire();
    auto res = h.sink.Get("/api/notifications");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0].securable_type == "Infrastructure");
    CHECK(h.perm_calls[0].op == "Read");
}

TEST_CASE("GET /api/notifications: a denying perm_fn short-circuits before the null store is "
          "touched",
          "[notification_routes][security]") {
    NotificationHarness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.Get("/api/notifications");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/notifications: a null store answers 503 without crashing",
          "[notification_routes]") {
    NotificationHarness h;
    h.wire();
    auto res = h.sink.Get("/api/notifications");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body(res->body)["error"]["code"] == 503);
}

// ── POST .../read and .../dismiss — same null-store + gate shape ──────────

TEST_CASE("POST /api/notifications/:id/read: gates Infrastructure:Write",
          "[notification_routes][security]") {
    NotificationHarness h;
    h.wire();
    auto res = h.sink.Post("/api/notifications/1/read", "");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0].securable_type == "Infrastructure");
    CHECK(h.perm_calls[0].op == "Write");
}

TEST_CASE("POST /api/notifications/:id/read: a denying perm_fn short-circuits before the null "
          "store is touched",
          "[notification_routes][security]") {
    NotificationHarness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.Post("/api/notifications/1/read", "");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("POST /api/notifications/:id/read: a null store answers 503 without crashing",
          "[notification_routes]") {
    NotificationHarness h;
    h.wire();
    auto res = h.sink.Post("/api/notifications/1/read", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.audit_calls.empty()); // read never audits, even on the 503 path
}

TEST_CASE("POST /api/notifications/:id/dismiss: gates Infrastructure:Write",
          "[notification_routes][security]") {
    NotificationHarness h;
    h.wire();
    auto res = h.sink.Post("/api/notifications/1/dismiss", "");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0].securable_type == "Infrastructure");
    CHECK(h.perm_calls[0].op == "Write");
}

TEST_CASE("POST /api/notifications/:id/dismiss: a denying perm_fn short-circuits before the "
          "null store is touched",
          "[notification_routes][security]") {
    NotificationHarness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.Post("/api/notifications/1/dismiss", "");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("POST /api/notifications/:id/dismiss: a null store answers 503 without crashing, "
          "and never audits an unreachable store",
          "[notification_routes]") {
    NotificationHarness h;
    h.wire();
    auto res = h.sink.Post("/api/notifications/1/dismiss", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.audit_calls.empty());
}

// ── Postgres-backed cases — need a real, open NotificationStore ───────────
//
// Pre-migrated template (docs/postgres-store-playbook.md step 7), mirroring
// test_notification_store.cpp's own `notif_tpl`. Kept file-local per that
// playbook's guidance — this is a store-BEHAVIOUR-adjacent (route) suite,
// not the store's own unit tests.
namespace {

yuzu::test::PgTestTemplate notif_routes_tpl{
    "notifroutes", [](const std::string& dsn) {
        pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        NotificationStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("notifroutes template: store failed to migrate");
    }};

struct PgWired {
    pg::PgPool pool;
    NotificationStore store;

    explicit PgWired(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
    }
};

} // namespace

TEST_CASE("GET /api/notifications: happy path lists unread and reports unread_count",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto id = w.store.create("info", "Agent connected", "Agent abc123 registered successfully");
    REQUIRE(id > 0);

    auto res = h.sink.Get("/api/notifications");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = body(res->body);
    REQUIRE(j["notifications"].size() == 1);
    CHECK(j["notifications"][0]["id"] == id);
    CHECK(j["notifications"][0]["title"] == "Agent connected");
    CHECK(j["notifications"][0]["read"] == false);
    CHECK(j["unread_count"] == 1);
}

TEST_CASE("GET /api/notifications: all=true serves list_all (dismissed rows included) instead "
          "of list_unread",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto id = w.store.create("warn", "Execution failed", "detail");
    REQUIRE(id > 0);
    REQUIRE(w.store.dismiss(id));

    auto unread_only = h.sink.Get("/api/notifications");
    REQUIRE(unread_only);
    CHECK(body(unread_only->body)["notifications"].empty()); // dismissed drops from list_unread

    auto all = h.sink.Get("/api/notifications?all=true");
    REQUIRE(all);
    auto j = body(all->body);
    REQUIRE(j["notifications"].size() == 1);
    CHECK(j["notifications"][0]["id"] == id);
    CHECK(j["notifications"][0]["dismissed"] == true);
}

TEST_CASE("POST /api/notifications/:id/read: unknown id 404s with no audit row",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto res = h.sink.Post("/api/notifications/999999/read", "");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(h.audit_calls.empty()); // read never audits, success or not
}

TEST_CASE("POST /api/notifications/:id/read: happy path marks read, no audit row",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto id = w.store.create("info", "t", "m");
    REQUIRE(id > 0);

    auto res = h.sink.Post("/api/notifications/" + std::to_string(id) + "/read", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(body(res->body)["status"] == "ok");
    CHECK(h.audit_calls.empty()); // asymmetry vs. dismiss below — pinned deliberately

    auto unread = w.store.list_unread();
    CHECK(unread.empty()); // confirms the mutation actually landed, not just the 200
}

TEST_CASE("POST /api/notifications/:id/dismiss: unknown id 404s and audits a failure",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto res = h.sink.Post("/api/notifications/999999/dismiss", "");
    REQUIRE(res);
    CHECK(res->status == 404);
    REQUIRE(h.audit_calls.size() == 1);
    CHECK(h.audit_calls[0].action == "notification.dismiss");
    CHECK(h.audit_calls[0].result == "failure");
    CHECK(h.audit_calls[0].target_type == "notification");
    CHECK(h.audit_calls[0].target_id == "999999");
}

TEST_CASE("POST /api/notifications/:id/dismiss: happy path dismisses and audits a success",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto id = w.store.create("info", "t", "m");
    REQUIRE(id > 0);

    auto res = h.sink.Post("/api/notifications/" + std::to_string(id) + "/dismiss", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(body(res->body)["status"] == "ok");
    REQUIRE(h.audit_calls.size() == 1);
    CHECK(h.audit_calls[0].action == "notification.dismiss");
    CHECK(h.audit_calls[0].result == "success");
    CHECK(h.audit_calls[0].target_type == "notification");
    CHECK(h.audit_calls[0].target_id == std::to_string(id));

    auto all = w.store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].dismissed == true); // confirms the mutation actually landed
}
