/**
 * test_config_routes.cpp — route-handler coverage for the 2-route Runtime
 * Configuration API (7.3, #2542 PR-12), driven in-process through
 * TestRouteSink (no httplib acceptor, #438), mirroring
 * test_schedule_routes.cpp's / test_custom_properties_routes.cpp's
 * MockHarness-plus-[pg]-Harness split.
 *
 *   - `MockHarness` (no Postgres needed): registration shape, gate pinning
 *     (GET -> Infrastructure:Read, PUT -> Infrastructure:Write), the null-
 *     and degraded-`runtime_config_store` 503 degrade on both routes
 *     (the degraded case uses an intentionally-invalid `PgPool` — the
 *     `test_runtime_config_store.cpp` "no Postgres required" trick: an
 *     invalid conninfo fails `PgPool`'s own parse step, so the store never
 *     opens and never attempts a network connection). PUT's body-shape
 *     validation is NOT covered here: the null-store gate runs BEFORE body
 *     parsing, so the invalid-conninfo trick 503s before ever reaching it.
 *   - `[pg]` cases (real `RuntimeConfigStore`): the GET effective-config +
 *     overrides round trip; PUT's write-then-read-back + audit shape,
 *     including the secret-key redaction (never the raw value in the audit
 *     detail); and PUT's body-shape validation (missing 'value', invalid
 *     JSON, non-numeric integer key) — these need a real-but-open store to
 *     reach the parsing logic at all.
 */

#include "config_routes.hpp"
#include "test_route_sink.hpp"

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "runtime_config_store.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

json body(const std::string& s) { return json::parse(s); }

/// MockHarness — no Postgres needed. `runtime_config_store` defaults null;
/// every gate-pinning / body-shape case relies on the route returning
/// (403/503/400) before a null/closed store would ever be touched.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct MockHarness {
    yuzu::server::Config cfg{};
    auth::AutoApproveEngine auto_approve{};
    RuntimeConfigStore* runtime_config_store{nullptr};

    bool auth_allow{true};
    std::string auth_username{"alice"};

    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perm_calls;

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        config::Deps deps;
        deps.cfg = &cfg;
        deps.auto_approve = &auto_approve;
        deps.runtime_config_store = runtime_config_store;
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!auth_allow) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"unauthenticated"}})",
                                "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = auth_username;
            return s;
        };
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            perm_calls.push_back({type, op});
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        config::register_config_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("config_routes: registers exactly 2 routes", "[server][routes][config_routes]") {
    MockHarness h;
    h.wire();
    CHECK(h.sink.route_count() == 2);
}

// ── Gate pinning (no Postgres needed) ───────────────────────────────────

TEST_CASE("config_routes: GET /api/config gates on Infrastructure:Read",
          "[server][routes][config_routes]") {
    MockHarness h;
    h.wire();
    auto res = h.sink.Get("/api/config");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Infrastructure", "Read"});
}

TEST_CASE("config_routes: PUT /api/config/:key gates on Infrastructure:Write",
          "[server][routes][config_routes]") {
    MockHarness h;
    h.wire();
    auto res = h.sink.Put("/api/config/log_level", R"({"value":"debug"})");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Infrastructure", "Write"});
}

TEST_CASE("config_routes: a perm_fn denial 403s on both routes before the store is touched, "
          "with no audit call",
          "[server][routes][config_routes]") {
    MockHarness h;
    h.perm_allow = false;
    h.wire();

    auto get_res = h.sink.Get("/api/config");
    REQUIRE(get_res);
    CHECK(get_res->status == 403);

    auto put_res = h.sink.Put("/api/config/log_level", R"({"value":"debug"})");
    REQUIRE(put_res);
    CHECK(put_res->status == 403);

    CHECK(h.audits.empty());
}

// ── Store-unavailable (no Postgres needed for the null case) ───────────

TEST_CASE("config_routes: a null runtime_config_store answers 503 on both routes",
          "[server][routes][config_routes]") {
    MockHarness h;
    h.wire();

    auto get_res = h.sink.Get("/api/config");
    REQUIRE(get_res);
    CHECK(get_res->status == 503);
    CHECK(body(get_res->body)["error"]["message"] == "runtime config store unavailable");

    auto put_res = h.sink.Put("/api/config/log_level", R"({"value":"debug"})");
    REQUIRE(put_res);
    CHECK(put_res->status == 503);
}

TEST_CASE("config_routes: a degraded (never-opened) runtime_config_store answers 503, "
          "NO Postgres connection ever attempted (invalid conninfo fails PgPool's own parse "
          "step)",
          "[server][routes][config_routes]") {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    pg::PgPool pool{{.conninfo = "this is not a valid conninfo :::", .size = 1}};
    REQUIRE_FALSE(pool.valid());
    RuntimeConfigStore store{pool, codec};
    REQUIRE_FALSE(store.is_open());

    MockHarness h;
    h.runtime_config_store = &store;
    h.wire();

    auto get_res = h.sink.Get("/api/config");
    REQUIRE(get_res);
    CHECK(get_res->status == 503);

    auto put_res = h.sink.Put("/api/config/log_level", R"({"value":"debug"})");
    REQUIRE(put_res);
    CHECK(put_res->status == 503);
}

// ── PUT body-shape validation (reachable past a null store gate — the null-store
//    check runs BEFORE body parsing, so these need a real-but-degraded store to
//    reach the parsing logic; using the same invalid-conninfo trick would 503
//    before ever reaching the body, so these specific cases are covered in the
//    [pg] section below where a real open store lets execution reach parsing) ──

// ── [pg] cases: real RuntimeConfigStore ─────────────────────────────────

namespace {

// Mirrors test_settings_routes_oidc.cpp's oidc_settings_tpl recipe exactly:
// pre-applies BOTH the runtime_config_store schema migration and the
// secrets schema migration (via a throwaway codec init), then resets
// secrets.kek_meta to the empty first-boot state so each test mints its
// own KEK against its own fresh keys TempDir.
yuzu::test::PgTestTemplate config_routes_tpl{"cfgroutes", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RuntimeConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("cfgroutes template: store failed to migrate");
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("cfgroutes template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("cfgroutes template: codec init failed");
    pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("cfgroutes template: kek_meta reset failed");
}};

struct PgWired {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider;
    pg::SecretCodec codec;
    pg::PgPool pool;
    RuntimeConfigStore store;

    explicit PgWired(const std::string& dsn)
        : provider(keys.path), codec(provider), pool{{.conninfo = dsn, .size = 4}},
          store{pool, codec} {
        REQUIRE(store.is_open());
        // Mint this test's own KEK -- the template reset kek_meta to empty,
        // so every PgWired instance needs its own init() before a secret
        // key's set() can encrypt (see this file's PUT-secret-key test).
        pg::PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto init_res = codec.init(conn.get());
        REQUIRE(init_res.has_value());
    }
};

} // namespace

TEST_CASE("config_routes: GET /api/config returns effective config + overrides + allowed_keys "
          "over a real store",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.cfg.response_retention_days = 42;
    h.wire();

    auto res = h.sink.Get("/api/config");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto b = body(res->body);
    CHECK(b["config"]["response_retention_days"] == 42);
    CHECK(b["overrides"].is_object());
    CHECK(b["allowed_keys"].is_array());
    CHECK(h.audits.empty()); // pure read, never audited
}

TEST_CASE("config_routes: PUT an integer key round-trips into cfg AND the store, and audits "
          "success",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    auto res = h.sink.Put("/api/config/response_retention_days", R"({"value":"120"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto b = body(res->body);
    CHECK(b["applied"] == true);
    CHECK(h.cfg.response_retention_days == 120); // in-memory cfg_ applied

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "config.update");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "RuntimeConfig");
    CHECK(h.audits[0].target_id == "response_retention_days");
    CHECK(h.audits[0].detail == "value=120");

    // The read-back half: GET must reflect the write via the store, not just
    // the in-memory cfg_ side effect checked above.
    auto get_res = h.sink.Get("/api/config");
    REQUIRE(get_res);
    CHECK(get_res->status == 200);
    auto get_b = body(get_res->body);
    REQUIRE(get_b["overrides"].contains("response_retention_days"));
    CHECK(get_b["overrides"]["response_retention_days"]["value"] == "120");
}

TEST_CASE("config_routes: PUT a non-numeric value for an integer key is a 400, cfg untouched, "
          "no audit (UP-R5 ghost-write guard)",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    int before = h.cfg.response_retention_days;
    h.wire();

    auto res = h.sink.Put("/api/config/response_retention_days", R"({"value":"not-a-number"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.cfg.response_retention_days == before);
    CHECK(h.audits.empty());
}

TEST_CASE("config_routes: PUT with a missing 'value' field is a 400 with no audit",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    auto res = h.sink.Put("/api/config/log_level", R"({})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.audits.empty());
}

TEST_CASE("config_routes: PUT an invalid JSON body is a 400 with no audit",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    auto res = h.sink.Put("/api/config/log_level", "not json");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.audits.empty());
}

// json-dump-depth-guard fix (#2437-class): nlohmann::json::dump() is
// unboundedly recursive. This body is an otherwise-VALID request ("value" is
// present) nested past the depth limit - the exact field this handler calls
// .dump() on when it is not a string - so on unguarded code the request
// proceeds to the store write. Uses "oidc_issuer" (a plain string key with
// no downstream value-shape validation of its own) rather than "log_level"
// (whose enumerated-value check would also 400 a dumped array, masking
// whether THIS guard fired); the message assertion additionally proves it
// was this guard that fired, not some other 400. depth 40 is trivially safe
// to build/dump directly in this test process; the real attack depth this
// guard exists for is many orders of magnitude higher (~100,000 levels).
TEST_CASE("config_routes: PUT a value nested past the depth limit is a 400 with no "
          "audit and no store write",
          "[pg][server][routes][config_routes][security][depth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    const std::string deep_array = std::string(40, '[') + std::string(40, ']');
    const std::string put_body = R"({"value":)" + deep_array + "}";
    auto res = h.sink.Put("/api/config/oidc_issuer", put_body);
    REQUIRE(res);
    CHECK(res->status == 400);
    auto res_b = body(res->body);
    CHECK(res_b["error"]["message"].get<std::string>().find("nests too deeply") !=
          std::string::npos);
    CHECK(h.audits.empty());

    auto get_res = h.sink.Get("/api/config");
    REQUIRE(get_res);
    auto get_b = body(get_res->body);
    CHECK_FALSE(get_b["overrides"].contains("oidc_issuer"));
}

TEST_CASE("config_routes: PUT a secret key never leaks the raw value into the audit detail "
          "or the response body",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    REQUIRE(RuntimeConfigStore::is_secret_key("oidc_client_secret"));
    auto res = h.sink.Put("/api/config/oidc_client_secret", R"({"value":"super-secret-value"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto b = body(res->body);
    CHECK_FALSE(b.contains("value")); // secret key: no value echoed back
    CHECK(b["applied"] == true);

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].detail.find("super-secret-value") == std::string::npos);
    CHECK(h.audits[0].detail == "value=" + std::string(RuntimeConfigStore::redacted_placeholder()));
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_config_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_config_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s both routes. Mirrors test_schedule_routes.cpp's
// tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("config_routes: wiring -- server.cpp still calls register_config_routes",
          "[server][routes][config_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_config_routes(") != std::string::npos);
}
