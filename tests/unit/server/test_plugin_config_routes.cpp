/// @file test_plugin_config_routes.cpp
/// HTTP-level coverage for the plugin config/secret/kill-switch REST surface
/// (PR1.5b) — driven in-process through TestRouteSink (no httplib acceptor,
/// #438), mirroring test_kek_routes.cpp's / test_sle_routes.cpp's Harness
/// shape.
///
/// Split by whether a case needs a live Postgres-backed `PluginConfigStore`
/// (`PluginConfigStore` has no virtual seam — `Deps::store` is a concrete
/// pointer per this package's spec — so anything past the perm/auth/authz
/// gate needs a real store):
///   - Permission-gate securable/operation pins and the store-unavailable
///     503 run WITHOUT Postgres — every one of them returns before the
///     handler ever dereferences `deps.store` (store is left null). The
///     authz-mapping cases that need a real RbacStore are `[pg]` too since
///     ADR-0041 moved RbacStore onto Postgres.
///   - CRUD round-trips, the secret write-only response shape, the
///     kill-switch route's dispatch precedence over the generic
///     `:plugin/:key` route, the audit-failure-503 posture, and the list
///     route's AdmitAll happy path are `[pg]`, gated behind
///     YUZU_TEST_POSTGRES_DSN via a pre-migrated PgTestTemplate.

#include "plugin_config_routes.hpp"
#include "test_route_sink.hpp"

#include "key_provider.hpp"
#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_store.hpp"
#include "rbac_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

/// All providers injected and re-read per call, mirroring test_kek_routes.cpp
/// / test_sle_routes.cpp's Harness shape. `store` defaults to null — every
/// case that must NOT need Postgres leaves it null and relies on the route
/// returning (403/503) before it would be dereferenced.
struct Harness {
    yuzu::server::test::TestRouteSink sink;
    PluginConfigStore* store{nullptr};
    RbacStore* rbac_store{nullptr};
    const ManagementGroupStore* mgmt_store{nullptr};

    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    bool session_present{true};
    std::string session_username{"alice"};

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    void wire() {
        plugin_config::Deps deps;
        deps.store = store;
        deps.rbac_store = rbac_store;
        deps.mgmt_store = mgmt_store;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"unauthenticated"}})",
                                "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::admin;
            return s;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        plugin_config::register_plugin_config_routes(sink, deps);
    }
};

json body(const std::string& s) { return json::parse(s); }

} // namespace

// ── Permission-gate securable/operation pins (no Postgres needed — every
//    route returns 503 on a null store immediately after the gate, and the
//    gate itself is what's under test) ───────────────────────────────────

TEST_CASE("plugin_config_routes: every route gates on PluginConfig/PluginSecret with "
          "Read/Write/Delete only — never Suspend or Upload",
          "[server][routes][config]") {
    Harness h;
    h.wire();

    auto check = [&](auto call, const std::string& expect_type, const std::string& expect_op) {
        call();
        CHECK(h.last_perm_type == expect_type);
        CHECK(h.last_perm_op == expect_op);
        CHECK(h.last_perm_op != "Suspend");
        CHECK(h.last_perm_op != "Upload");
    };

    check([&] { h.sink.Get("/api/v1/plugin-config"); }, "PluginConfig", "Read");
    check([&] { h.sink.Get("/api/v1/plugin-config/email/host"); }, "PluginConfig", "Read");
    check([&] { h.sink.Put("/api/v1/plugin-config/email/host", "{}"); }, "PluginConfig", "Write");
    check([&] { h.sink.Delete("/api/v1/plugin-config/email/host"); }, "PluginConfig", "Delete");
    check([&] { h.sink.Put("/api/v1/plugin-config/email/host/secret", "{}"); }, "PluginSecret",
          "Write");
    check([&] { h.sink.Delete("/api/v1/plugin-config/email/host/secret"); }, "PluginSecret",
          "Delete");
    check([&] { h.sink.Get("/api/v1/plugin-config/email/kill-switch"); }, "PluginConfig", "Read");
    check([&] { h.sink.Put("/api/v1/plugin-config/email/kill-switch", "{}"); }, "PluginConfig",
          "Write");
}

TEST_CASE("plugin_config_routes: a denying perm_fn short-circuits before the store is touched",
          "[server][routes][config]") {
    Harness h; // store stays null — a dereference would crash; a 403 must never reach it
    h.perm_allow = false;
    h.wire();

    auto r1 = h.sink.Get("/api/v1/plugin-config/email/host");
    REQUIRE(r1);
    CHECK(r1->status == 403);

    auto r2 = h.sink.Put("/api/v1/plugin-config/email/host", R"({"value":"x"})");
    REQUIRE(r2);
    CHECK(r2->status == 403);
}

TEST_CASE("plugin_config_routes: a null/closed store answers 503 without crashing",
          "[server][routes][config]") {
    Harness h;
    h.wire();

    auto r1 = h.sink.Get("/api/v1/plugin-config/email/host");
    REQUIRE(r1);
    CHECK(r1->status == 503);

    auto r2 = h.sink.Put("/api/v1/plugin-config/email/host", R"({"value":"x"})");
    REQUIRE(r2);
    CHECK(r2->status == 503);

    auto r3 = h.sink.Put("/api/v1/plugin-config/email/host/secret", R"({"value":"s"})");
    REQUIRE(r3);
    CHECK(r3->status == 503);
}

namespace {
// RbacStore is Postgres-backed (ADR-0041); pre-migrated template for the
// authz-mapping cases below. `store` stays null in those cases — they return
// before it would be touched — so only the RBAC half needs a database.
yuzu::test::PgTestTemplate routes_rbac_tpl{"pluginroutesrbac", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("pluginroutes rbac template: store failed to migrate");
}};
} // namespace

#define ROUTES_RBAC(store_var)                                                                     \
    YUZU_REQUIRE_PG_DB_TPL(rbacdb_fx_, routes_rbac_tpl);                                           \
    yuzu::server::pg::PgPool rbacpool_fx_{{.conninfo = rbacdb_fx_.dsn(), .size = 2}};              \
    REQUIRE(rbacpool_fx_.valid());                                                                 \
    RbacStore store_var{rbacpool_fx_};                                                             \
    REQUIRE(store_var.is_open())

// ── List route: ADR-0017 authz mapping ────────────────────────────────────

TEST_CASE("plugin_config_routes: list route 403s when no grant exists anywhere (DenyAll)",
          "[pg][server][routes][config]") {
    ROUTES_RBAC(rbac);
    rbac.set_rbac_enabled(true); // enforcement ON, no roles granted to 'alice'
    Harness h;
    h.rbac_store = &rbac;
    h.wire();

    auto r = h.sink.Get("/api/v1/plugin-config");
    REQUIRE(r);
    CHECK(r->status == 403);
}

TEST_CASE("plugin_config_routes: list route 503s when rbac_store is unset",
          "[server][routes][config]") {
    Harness h; // rbac_store stays null
    h.wire();
    auto r = h.sink.Get("/api/v1/plugin-config");
    REQUIRE(r);
    CHECK(r->status == 503);
}

TEST_CASE("plugin_config_routes: list route fails closed on an authenticated-but-missing-session "
          "gate order (perm_fn runs, then auth_fn)",
          "[pg][server][routes][config]") {
    ROUTES_RBAC(rbac);
    Harness h;
    h.rbac_store = &rbac;
    h.session_present = false;
    h.wire();
    auto r = h.sink.Get("/api/v1/plugin-config");
    REQUIRE(r);
    CHECK(r->status == 401);
}

// ── [pg] cases: real PluginConfigStore ────────────────────────────────────

namespace {

yuzu::test::PgTestTemplate route_tpl{"pluginroutes", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    PluginConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("pluginroutes template: store failed to migrate");
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("pluginroutes template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("pluginroutes template: codec init failed");
    pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("pluginroutes template: kek_meta reset failed");
}};

struct PgWired {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider{keys.path};
    pg::SecretCodec codec{provider};
    pg::PgPool pool;
    PluginConfigStore store;

    explicit PgWired(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, store{pool, codec} {
        REQUIRE(store.is_open());
        pg::PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(codec.init(conn.get()).has_value());
    }
};

} // namespace

TEST_CASE("plugin_config_routes: config PUT/GET/DELETE round-trip over HTTP",
          "[pg][server][routes][config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto put = h.sink.Put("/api/v1/plugin-config/email/smtp.host", R"({"value":"mail.example.com"})");
    REQUIRE(put);
    CHECK(put->status == 200);
    auto put_body = body(put->body);
    CHECK(put_body["data"]["value"] == "mail.example.com");
    CHECK(put_body["data"]["updated_by"] == "alice");
    // BR-006: one mutation writes a PAIR of rows — `attempted` before the
    // store is touched, then the real outcome once it has answered. The
    // pre-mutation row must never claim `success`, or a mutation that fails
    // after the row lands leaves the log asserting a change that never was.
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "plugin_config.set");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_type == "PluginConfig");
    CHECK(h.audits[0].target_id == "email.smtp.host");
    CHECK(h.audits[1].action == "plugin_config.set");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == "email.smtp.host");

    auto get = h.sink.Get("/api/v1/plugin-config/email/smtp.host");
    REQUIRE(get);
    CHECK(get->status == 200);
    CHECK(body(get->body)["data"]["value"] == "mail.example.com");

    auto del = h.sink.Delete("/api/v1/plugin-config/email/smtp.host");
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(body(del->body)["deleted"] == true);

    auto missing = h.sink.Get("/api/v1/plugin-config/email/smtp.host");
    REQUIRE(missing);
    CHECK(missing->status == 404);
}

TEST_CASE("plugin_config_routes: secret PUT response is metadata only — no value field anywhere",
          "[pg][server][routes][config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string plaintext = "sk_live_dO_NoT_LeAk_987";
    auto sput = h.sink.Put("/api/v1/plugin-config/email/api_key/secret",
                           json{{"value", plaintext}}.dump());
    REQUIRE(sput);
    CHECK(sput->status == 200);
    // No key anywhere in the response body may be "value", and the raw
    // response text must not contain the plaintext at all.
    CHECK_FALSE(body(sput->body)["data"].contains("value"));
    CHECK(sput->body.find(plaintext) == std::string::npos);

    // The audit detail is redacted too — in EVERY row, not just the last.
    // BR-006 added a second (outcome) row per mutation, which is a second
    // place a secret could leak; asserting only `back()` would not see a
    // plaintext `attempted` row.
    REQUIRE(h.audits.size() == 2);
    for (const auto& row : h.audits) {
        CHECK(row.action == "plugin_secret.set");
        CHECK(row.detail.find(plaintext) == std::string::npos);
        CHECK(row.detail.find("REDACTED") != std::string::npos);
    }
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");

    auto sdel = h.sink.Delete("/api/v1/plugin-config/email/api_key/secret");
    REQUIRE(sdel);
    CHECK(sdel->status == 200);
}

TEST_CASE("plugin_config_routes: kill-switch route wins over the generic :plugin/:key route",
          "[pg][server][routes][config][killswitch]") {
    // "kill-switch" is not itself a stored config key here — if the generic
    // 2-segment route matched first this would 404 (NotFound); the
    // kill-switch handler instead answers 200 with the default-enabled
    // state (no row ever written), which is only possible if the more
    // specific pattern won.
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto get = h.sink.Get("/api/v1/plugin-config/firewall/kill-switch");
    REQUIRE(get);
    CHECK(get->status == 200);
    auto data = body(get->body)["data"];
    CHECK(data["plugin"] == "firewall");
    CHECK(data["enabled"] == true);
}

TEST_CASE("plugin_config_routes: kill-switch PUT flips the switch and is audited",
          "[pg][server][routes][config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto put = h.sink.Put("/api/v1/plugin-config/firewall/kill-switch?action=block",
                          json{{"enabled", false}, {"reason", "incident 99"}}.dump());
    REQUIRE(put);
    CHECK(put->status == 200);
    auto data = body(put->body)["data"];
    CHECK(data["enabled"] == false);
    CHECK(data["action"] == "block");
    CHECK(data["reason"] == "incident 99");
    CHECK(data["set_by"] == "alice");

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "plugin_config.kill_switch.set");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_id == "firewall.block");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == "firewall.block");

    auto get = h.sink.Get("/api/v1/plugin-config/firewall/kill-switch?action=block");
    REQUIRE(get);
    CHECK(body(get->body)["data"]["enabled"] == false);
}

// #3265 governance Gate 3 (quality-engineer): the MCP kill-switch surface got
// a dedicated reserved-namespace regression test during an earlier fix round
// (test_mcp_server.cpp) — this REST route shares the identical
// parse_kill_switch_scope pre-validation but had no equivalent case, the same
// coverage gap in a different transport.
TEST_CASE("plugin_config_routes: kill-switch PUT reaches the real dispatch chokepoint for "
          "the reserved-namespace __guard__.push_rules capability, not just an ordinary "
          "plugin.action",
          "[pg][server][routes][config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // Baseline: no row yet — the #3265 regression shape exactly.
    CHECK(w.store.action_allowed("__guard__", "push_rules"));

    auto put = h.sink.Put("/api/v1/plugin-config/__guard__/kill-switch?action=push_rules",
                          json{{"enabled", false}, {"reason", "incident"}}.dump());
    REQUIRE(put);
    CHECK(put->status == 200);
    CHECK(body(put->body)["data"]["enabled"] == false);

    // Proven against the real chokepoint, not the echoed response.
    CHECK_FALSE(w.store.action_allowed("__guard__", "push_rules"));

    auto put_on = h.sink.Put("/api/v1/plugin-config/__guard__/kill-switch?action=push_rules",
                             json{{"enabled", true}, {"reason", "resolved"}}.dump());
    REQUIRE(put_on);
    CHECK(put_on->status == 200);
    CHECK(w.store.action_allowed("__guard__", "push_rules"));
}

TEST_CASE("plugin_config_routes: a dropped audit row fails the write closed (503) AND the "
          "mutation never happens — audit is checked BEFORE the store is touched",
          "[pg][server][routes][config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.audit_succeeds = false;
    h.wire();

    auto put = h.sink.Put("/api/v1/plugin-config/email/host", R"({"value":"x"})");
    REQUIRE(put);
    CHECK(put->status == 503);
    // The whole point of auditing before mutating: a dropped audit row must
    // never leave a committed-but-unaudited change behind.
    CHECK_FALSE(w.store.get_config("email", "host").has_value());

    // Same posture for a kill-switch flip and a secret write.
    auto ks_put = h.sink.Put("/api/v1/plugin-config/firewall/kill-switch",
                             R"({"enabled":false,"reason":"x"})");
    REQUIRE(ks_put);
    CHECK(ks_put->status == 503);
    auto ks_entry = w.store.get_kill_switch("firewall", "");
    REQUIRE(ks_entry.has_value());
    CHECK(ks_entry->enabled); // still default-enabled — the flip never landed

    auto secret_put = h.sink.Put("/api/v1/plugin-config/email/api_key/secret",
                                 R"({"value":"sk_never_committed"})");
    REQUIRE(secret_put);
    CHECK(secret_put->status == 503);
    // No get_secret exists (write-only plane) — check directly for a row.
    pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult chk{PQexec(
        conn.get(),
        "SELECT 1 FROM plugin_config_store.secrets WHERE plugin = 'email' AND key = 'api_key'")};
    REQUIRE(chk.status() == PGRES_TUPLES_OK);
    CHECK(PQntuples(chk.get()) == 0);
}

TEST_CASE("plugin_config_routes: BR-006 — a mutation that fails AFTER the audit row lands is "
          "recorded as `failure`, never left asserting `success`",
          "[pg][server][routes][config][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // Deleting a SECRET that does not exist is a genuine post-audit store
    // failure. The secret plane is write-only by design, so its delete route
    // has no existence pre-check available: it audits `attempted`, calls
    // `delete_secret`, and only then learns the row was absent (NotFound).
    //
    // That is the exact window the old pre-audit-`success` posture lied
    // about — it wrote `success` first and never revisited it, so the
    // compliance log permanently asserted a secret deletion that never
    // happened. The CONFIG delete route is deliberately NOT used here: it
    // has a cheap existence pre-check and 404s before emitting any audit row
    // at all, so it cannot reach this window (and asserting against it was
    // this test's own first, wrong, premise).
    auto del = h.sink.Delete("/api/v1/plugin-config/email/never_existed/secret");
    REQUIRE(del);
    CHECK(del->status == 404);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "plugin_secret.delete");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == "plugin_secret.delete");
    CHECK(h.audits[1].result == "failure");
    // Neither row may claim the deletion succeeded.
    for (const auto& row : h.audits)
        CHECK(row.result != "success");
}

TEST_CASE("plugin_config_routes: deleting an absent CONFIG key emits no audit row at all "
          "(the existence pre-check runs first, by design)",
          "[pg][server][routes][config][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // The companion to the case above, pinning the deliberate asymmetry so a
    // later "consistency" change cannot quietly move the config route onto
    // the secret route's audit-then-discover shape. A double-delete/retry of
    // an already-absent config key must not manufacture an `attempted` row
    // for a mutation the server already knows it will not perform.
    auto del = h.sink.Delete("/api/v1/plugin-config/email/never.existed");
    REQUIRE(del);
    CHECK(del->status == 404);
    CHECK(h.audits.empty());
}

TEST_CASE("plugin_config_routes: PUT rejects a missing/non-string value field with 400",
          "[pg][server][routes][config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto missing = h.sink.Put("/api/v1/plugin-config/email/host", R"({})");
    REQUIRE(missing);
    CHECK(missing->status == 400);

    auto wrong_type = h.sink.Put("/api/v1/plugin-config/email/host", R"({"value":123})");
    REQUIRE(wrong_type);
    CHECK(wrong_type->status == 400);
}

TEST_CASE("plugin_config_routes: list route's AdmitAll (legacy-open RBAC) serves the real list",
          "[pg][server][routes][config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_tpl);
    PgWired w{db.dsn()};
    REQUIRE(w.store.set_config("email", "host", "mail.example.com", "alice").has_value());

    ROUTES_RBAC(rbac); // is_open() && !is_rbac_enabled() -> legacy-open -> AdmitAll
    Harness h;
    h.store = &w.store;
    h.rbac_store = &rbac;
    h.wire();

    auto r = h.sink.Get("/api/v1/plugin-config");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto data = body(r->body)["data"];
    REQUIRE(data.is_array());
    bool found = false;
    for (const auto& e : data)
        if (e["plugin"] == "email" && e["key"] == "host")
            found = true;
    CHECK(found);
}
