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
 *   - both POST mutations are AUDIT-FIRST (PR #5859 review, ADR-0033 §9): an
 *     `attempted` row is written before the store is touched, a failed audit write
 *     refuses the mutation (503, `Sec-Audit-Failed`), and an outcome row (`success` or
 *     `failure`) follows;
 *   - both POSTs carry the same-site gate: a cookie session without a same-site
 *     Origin/Referer is refused 403 (audited `csrf.denied`) before anything is written;
 *     a token session is exempt;
 *   - the GET list answers 503, never an empty list, when the store read fails.
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
    bool audit_persists{true};
    std::string auth_source{"local"}; // a cookie session unless a test says otherwise
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
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return audit_persists;
        };
        auto resolve_fn = [this](const httplib::Request&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "notif-op";
            s.role = auth::Role::admin;
            s.auth_source = auth_source;
            return s;
        };
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, store, resolve_fn);
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
    CHECK(h.audit_calls.empty()); // an unreachable store is refused before any audit row
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

TEST_CASE("POST /api/notifications/:id/read: unknown id 404s, audit-first (attempted, then failure)",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto res = h.sink.Post("/api/notifications/999999/read", "");
    REQUIRE(res);
    CHECK(res->status == 404);
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].action == "notification.mark_read");
    CHECK(h.audit_calls[0].result == "attempted");
    CHECK(h.audit_calls[1].result == "failure");
    CHECK(h.audit_calls[1].target_id == "999999");
}

TEST_CASE("POST /api/notifications/:id/read: happy path marks read and audits attempted then success",
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
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].action == "notification.mark_read");
    CHECK(h.audit_calls[0].result == "attempted");
    CHECK(h.audit_calls[1].action == "notification.mark_read");
    CHECK(h.audit_calls[1].result == "success");
    CHECK(h.audit_calls[1].target_id == std::to_string(id));

    auto unread = w.store.list_unread();
    CHECK(unread.empty()); // confirms the mutation actually landed, not just the 200
}

TEST_CASE("POST /api/notifications/:id/dismiss: unknown id 404s, audits attempted then failure",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();

    auto res = h.sink.Post("/api/notifications/999999/dismiss", "");
    REQUIRE(res);
    CHECK(res->status == 404);
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].action == "notification.dismiss");
    CHECK(h.audit_calls[0].result == "attempted");
    CHECK(h.audit_calls[1].action == "notification.dismiss");
    CHECK(h.audit_calls[1].result == "failure");
    CHECK(h.audit_calls[1].target_type == "notification");
    CHECK(h.audit_calls[1].target_id == "999999");
}

TEST_CASE("POST /api/notifications/:id/dismiss: happy path dismisses and audits attempted then success",
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
    REQUIRE(h.audit_calls.size() == 2);
    CHECK(h.audit_calls[0].action == "notification.dismiss");
    CHECK(h.audit_calls[0].result == "attempted");
    CHECK(h.audit_calls[1].action == "notification.dismiss");
    CHECK(h.audit_calls[1].result == "success");
    CHECK(h.audit_calls[1].target_type == "notification");
    CHECK(h.audit_calls[1].target_id == std::to_string(id));

    auto all = w.store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].dismissed == true); // confirms the mutation actually landed
}

// ── Same-site gate (PR #5859 review item 4) ───────────────────────────────

TEST_CASE("bell POSTs: a cross-site or header-less cookie write is refused 403 before anything "
          "is written (mutation: drop the gate and the row is changed)",
          "[notification_routes][pg][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.wire();
    auto id = w.store.create("info", "t", "m");
    REQUIRE(id > 0);

    for (const char* verb : {"read", "dismiss"}) {
        INFO(verb);
        const auto path = "/api/notifications/" + std::to_string(id) + "/" + verb;
        h.audit_calls.clear();

        h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}};
        auto cross = h.sink.Post(path, "");
        REQUIRE(cross);
        CHECK(cross->status == 403);
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].action == "csrf.denied");

        // No Origin and no Referer: a browser always sends one on a write, so a cookie session
        // without either is refused, not waved through.
        h.sink.default_headers = {{"Host", "yuzu.test"}};
        auto bare = h.sink.Post(path, "");
        REQUIRE(bare);
        CHECK(bare->status == 403);
        h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};

        auto unread = w.store.list_unread();
        CHECK(unread.size() == 1); // nothing changed
    }
}

TEST_CASE("bell POSTs: a token session needs no Origin (it is not riding a cookie)",
          "[notification_routes][pg][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.auth_source = "api_token";
    h.wire();
    h.sink.default_headers = {{"Host", "yuzu.test"}}; // no Origin, no Referer
    auto id = w.store.create("info", "t", "m");
    REQUIRE(id > 0);

    auto res = h.sink.Post("/api/notifications/" + std::to_string(id) + "/read", "");
    REQUIRE(res);
    CHECK(res->status == 200);
}

// ── Audit-first (PR #5859 review item 5) ─────────────────────────────────

TEST_CASE("bell POSTs: when the attempted row cannot be written the mutation is refused 503 with "
          "Sec-Audit-Failed and the row is untouched (mutation: mutate before auditing)",
          "[notification_routes][pg][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    PgWired w{db.dsn()};
    NotificationHarness h;
    h.store = &w.store;
    h.audit_persists = false;
    h.wire();
    auto id = w.store.create("info", "t", "m");
    REQUIRE(id > 0);

    for (const char* verb : {"read", "dismiss"}) {
        INFO(verb);
        h.audit_calls.clear();
        auto res = h.sink.Post("/api/notifications/" + std::to_string(id) + "/" + verb, "");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        REQUIRE(h.audit_calls.size() == 1); // the attempted row was tried; nothing followed
        CHECK(h.audit_calls[0].result == "attempted");
        auto still = w.store.list_unread();
        REQUIRE(still.size() == 1);
        CHECK_FALSE(still[0].read);
        CHECK_FALSE(still[0].dismissed);
    }
}

// ── A read failure is an error, not an empty bell (PR #5859 review item 6) ─

TEST_CASE("GET /api/notifications: a store read that fails answers 503, never an empty list "
          "(mutation: use the display-only readers and this returns 200 with none)",
          "[notification_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, notif_routes_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    NotificationStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("info", "t", "m") > 0);
    NotificationHarness h;
    h.store = &store;
    h.wire();

    // Hold the only connection so the store's bounded acquire gives up: a real lease timeout.
    auto held = pool.acquire();
    REQUIRE(held);
    auto res = h.sink.Get("/api/notifications");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body(res->body)["error"]["code"] == 503);
    CHECK(res->body.find("\"notifications\"") == std::string::npos);
}
