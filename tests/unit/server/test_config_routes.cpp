/**
 * test_config_routes.cpp — route-handler coverage for the Runtime Configuration API
 * (7.3, #2542 PR-12; the legacy GET/PUT pair plus their /api/v1 twins), driven in-process through
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
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

json body(const std::string& s) { return json::parse(s); }

/// Restores the process-wide spdlog level when the test ends, however it ends: the config routes
/// really set it (log_level is applied by RuntimeConfigStore::set), and a failed REQUIRE must not
/// leak a changed level into the tests that run after it.
struct LogLevelGuard {
    spdlog::level::level_enum saved{spdlog::default_logger()->level()};
    ~LogLevelGuard() { spdlog::default_logger()->set_level(saved); }
};

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
    // The session's OWN role. perm_fn admits a JIT-elevated session on its own, so an
    // "elevated" caller is perm_allow=true with session_role=user.
    auth::Role session_role{auth::Role::admin};
    bool session_elevated{false};  // a real, active JIT elevation on the session
    std::string session_mcp_tier;  // non-empty models an MCP-tier bearer token
    std::string session_token_scope_service; // non-empty models a service-scoped token
    /// Token callers are exempt from the same-site gate, so the existing cases keep working;
    /// the cross-site cases set a cookie source ("local") explicitly.
    std::string auth_source{"api_token"};

    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perm_calls;

    /// The step-up closure: refuses (403, as the real one does for a missing proof) when false.
    bool stepup_allow{true};
    bool stepup_wired{true};
    std::vector<std::string> stepup_labels;

    bool audit_succeeds{true};
    /// 0-based index of the one audit call that fails (-1: none); independent of audit_succeeds.
    int audit_fails_at{-1};
    /// The audit sink throws instead of returning (a store fault surfacing as an exception).
    bool audit_throws{false};
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
            s.role = session_role;
            s.mcp_tier = session_mcp_tier;
            s.token_scope_service = session_token_scope_service;
            if (session_elevated)
                s.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::hours(1);
            s.auth_source = auth_source;
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
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            if (audit_throws)
                throw std::runtime_error("audit sink fault");
            const int idx = static_cast<int>(audits.size());
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds && idx != audit_fails_at;
        };
        if (stepup_wired)
            deps.step_up_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const auth::Session&, const std::string& label) {
                stepup_labels.push_back(label);
                if (!stepup_allow) {
                    res.status = 403;
                    res.set_content(R"({"error":{"code":403,"message":"step-up required"}})",
                                    "application/json");
                    return false;
                }
                return true;
            };
        config::register_config_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("config_routes: registers exactly 4 routes", "[server][routes][config_routes]") {
    MockHarness h;
    h.wire();
    CHECK(h.sink.route_count() == 4); // GET and PUT, on /api/config and on /api/v1/config
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

// The score policy is one document with its own writer; the generic write refuses it. The
// refusal does not depend on the store, so a null store reaches it (a 503 here would mean
// the refusal sits behind the store gate).
TEST_CASE("config_routes: PUT /api/config/dex_score_policy is refused with a typed 400 naming "
          "the policy route with no audit row",
          "[server][routes][config_routes]") {
    MockHarness h;
    h.wire();
    auto res = h.sink.Put("/api/config/dex_score_policy", R"({"value":"{}"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    const auto b = body(res->body);
    CHECK(b["error"]["code"] == 400);
    CHECK(b["error"]["message"].get<std::string>().find("PUT /api/v1/dex/score-policy") !=
          std::string::npos);
    CHECK(b["error"].contains("remediation"));
    CHECK(h.audits.empty());
    // The permission gate still runs first.
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Infrastructure", "Write"});
}

// The same-site gate runs before the governed-key refusal, so a cross-site browser write to
// the key is audited as csrf.denied instead of getting the typed 400 (with a null store, and so
// without reaching the store gate either).
TEST_CASE("config_routes: a cross-site cookie PUT to dex_score_policy is a 403 with csrf.denied",
          "[server][routes][config_routes][security]") {
    MockHarness h;
    h.auth_source = "local"; // a cookie session
    h.wire();
    const std::string path = "/api/config/dex_score_policy";

    auto cross = h.sink.dispatch("PUT", path, R"({"value":"{}"})", "application/json",
                                 {{"Host", "yuzu.example"}, {"Origin", "https://evil.example"}});
    REQUIRE(cross);
    CHECK(cross->status == 403);
    CHECK(body(cross->body)["error"]["message"] == "cross-site request refused");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "csrf.denied");

    // A same-site cookie write reaches the typed 400, and writes no further audit row.
    auto same = h.sink.dispatch("PUT", path, R"({"value":"{}"})", "application/json",
                                {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}});
    REQUIRE(same);
    CHECK(same->status == 400);
    CHECK(h.audits.size() == 1);
}

// The same-site gate also sits before the store gate for an ordinary key: with a null store a
// cross-site browser write is the 403 with its csrf.denied row, never the store 503, and a
// same-site one still reaches the store 503. Fails if the gate moves below the store check.
TEST_CASE("config_routes: a cross-site cookie PUT to an ordinary key with a null store is a 403 "
          "with csrf.denied and a same-site one the store 503",
          "[server][routes][config_routes][security]") {
    MockHarness h;
    h.auth_source = "local"; // a cookie session
    h.wire();
    const std::string path = "/api/config/log_level";
    const std::string put_body = R"({"value":"debug"})";

    auto cross = h.sink.dispatch("PUT", path, put_body, "application/json",
                                 {{"Host", "yuzu.example"}, {"Origin", "https://evil.example"}});
    REQUIRE(cross);
    CHECK(cross->status == 403);
    CHECK(body(cross->body)["error"]["message"] == "cross-site request refused");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "csrf.denied");

    auto same = h.sink.dispatch("PUT", path, put_body, "application/json",
                                {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}});
    REQUIRE(same);
    CHECK(same->status == 503);
    CHECK(body(same->body)["error"]["message"] == "runtime config store unavailable");
    CHECK(h.audits.size() == 1);
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
    // The score policy is listed as an allowed key and as read-only here.
    const auto has = [](const json& arr, const std::string& k) {
        return std::find(arr.begin(), arr.end(), json(k)) != arr.end();
    };
    CHECK(has(b["allowed_keys"], "dex_score_policy"));
    REQUIRE(b["read_only_keys"].is_array());
    CHECK(has(b["read_only_keys"], "dex_score_policy"));
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

    // Audit-first: an `attempted` row before the change, the outcome row after.
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "config.update");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].detail.empty());
    CHECK(h.audits[1].action == "config.update");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_type == "RuntimeConfig");
    CHECK(h.audits[1].target_id == "response_retention_days");
    CHECK(h.audits[1].detail == "value=120");

    // The read-back half: GET must reflect the write via the store, not just
    // the in-memory cfg_ side effect checked above.
    auto get_res = h.sink.Get("/api/config");
    REQUIRE(get_res);
    CHECK(get_res->status == 200);
    auto get_b = body(get_res->body);
    REQUIRE(get_b["overrides"].contains("response_retention_days"));
    CHECK(get_b["overrides"]["response_retention_days"]["value"] == "120");
}

TEST_CASE("config_routes: PUT refuses the change when the attempted audit row cannot be "
          "written - no audit row, no mutation",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    const int before = h.cfg.response_retention_days;

    h.audit_fails_at = 0; // the attempted row
    auto res = h.sink.Put("/api/config/response_retention_days", R"({"value":"121"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    const auto refused = body(res->body);
    CHECK(refused["error"]["message"] == "audit log unavailable; the change was not made");
    CHECK(refused["error"]["retry_after_ms"] == 5000);
    CHECK(refused["error"].contains("correlation_id"));
    CHECK(h.cfg.response_retention_days == before); // live config untouched
    CHECK(h.audits.size() == 1);                    // no outcome row for a change never made

    auto get_res = h.sink.Get("/api/config");
    REQUIRE(get_res);
    CHECK_FALSE(body(get_res->body)["overrides"].contains("response_retention_days")); // store untouched
}

TEST_CASE("config_routes: PUT flags a lost outcome row with Sec-Audit-Failed and keeps the change",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    auto ok = h.sink.Put("/api/config/response_retention_days", R"({"value":"120"})");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK_FALSE(ok->has_header("Sec-Audit-Failed"));

    h.audits.clear();
    h.audit_fails_at = 1; // the outcome row
    auto res = h.sink.Put("/api/config/response_retention_days", R"({"value":"121"})");
    REQUIRE(res);
    CHECK(res->status == 200); // the attempted row exists; the change is applied, not rolled back
    CHECK(body(res->body)["applied"] == true);
    CHECK(h.cfg.response_retention_days == 121);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    REQUIRE(h.audits.size() == 2); // the lost row is the outcome row, not the attempted one
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");
}

TEST_CASE("config_routes: PUT a rejected value leaves an attempted and a failure row",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    auto res = h.sink.Put("/api/config/log_level", R"({"value":"loud"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "failure");
    // The failure row carries the operator-written refusal, never the submitted value.
    CHECK(h.audits[1].detail.find("one of") != std::string::npos);
    CHECK(h.audits[1].detail.find("loud") == std::string::npos);

    // A key that names no setting is refused before any audit row.
    h.audits.clear();
    auto unknown = h.sink.Put("/api/config/not_a_setting", R"({"value":"1"})");
    REQUIRE(unknown);
    CHECK(unknown->status == 400);
    CHECK(h.audits.empty());
}

TEST_CASE("config_routes: PUT heartbeat_timeout enforces the 30 second floor at the boundary",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    const auto before = h.cfg.session_timeout.count();

    for (const char* v : {"0", "1", "29"}) {
        INFO(v);
        auto res = h.sink.Put("/api/config/heartbeat_timeout",
                              std::string(R"({"value":")") + v + R"("})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.cfg.session_timeout.count() == before);
    }
    auto ok = h.sink.Put("/api/config/heartbeat_timeout", R"({"value":"30"})");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.cfg.session_timeout.count() == 30);
}

TEST_CASE("config_routes: PUT from a cookie session needs a same-site Origin or Referer",
          "[pg][server][routes][config_routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.auth_source = "local"; // a cookie session
    h.wire();
    const std::string path = "/api/config/response_retention_days";
    const std::string put_body = R"({"value":"120"})";
    const int before = h.cfg.response_retention_days;

    auto foreign = h.sink.dispatch("PUT", path, put_body, "application/json",
                                   {{"Host", "yuzu.example"}, {"Origin", "https://evil.example"}});
    REQUIRE(foreign);
    CHECK(foreign->status == 403);
    CHECK(body(foreign->body)["error"]["message"] == "cross-site request refused");
    CHECK(body(foreign->body)["error"].contains("correlation_id"));
    CHECK(h.cfg.response_retention_days == before);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "csrf.denied");

    auto headerless = h.sink.dispatch("PUT", path, put_body, "application/json",
                                      {{"Host", "yuzu.example"}});
    REQUIRE(headerless);
    CHECK(headerless->status == 403);
    CHECK(h.cfg.response_retention_days == before);

    auto same = h.sink.dispatch("PUT", path, put_body, "application/json",
                                {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}});
    REQUIRE(same);
    CHECK(same->status == 200);
    CHECK(h.cfg.response_retention_days == 120);

    // A token caller is not riding a cookie: no Origin needed.
    h.auth_source = "api_token";
    auto token = h.sink.dispatch("PUT", path, R"({"value":"121"})", "application/json", {});
    REQUIRE(token);
    CHECK(token->status == 200);
}

TEST_CASE("config_routes: PUT same-site gate sits after the permission gate and before the body",
          "[pg][server][routes][config_routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.auth_source = "local";
    h.cfg.csrf_trusted_origins = {"https://proxy.example"};
    h.wire();
    const std::string path = "/api/config/response_retention_days";
    const std::unordered_map<std::string, std::string> foreign{{"Host", "yuzu.example"},
                                                               {"Origin", "https://evil.example"}};

    // An unauthorised caller gets the permission 403, not the cross-site refusal or a row.
    h.perm_allow = false;
    auto unauth = h.sink.dispatch("PUT", path, "not json", "application/json", foreign);
    REQUIRE(unauth);
    CHECK(unauth->status == 403);
    CHECK(unauth->body.find("denied") != std::string::npos);
    CHECK(h.audits.empty());
    h.perm_allow = true;

    // A foreign browser write is refused before its (malformed) body is looked at.
    auto cross = h.sink.dispatch("PUT", path, "not json", "application/json", foreign);
    REQUIRE(cross);
    CHECK(cross->status == 403);
    CHECK(cross->body.find("cross-site") != std::string::npos);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "csrf.denied");

    // A same-site Referer with no Origin is admitted; so is a configured trusted origin.
    auto referer = h.sink.dispatch("PUT", path, R"({"value":"120"})", "application/json",
                                   {{"Host", "yuzu.example"},
                                    {"Referer", "https://yuzu.example/settings/general"}});
    REQUIRE(referer);
    CHECK(referer->status == 200);
    auto trusted = h.sink.dispatch("PUT", path, R"({"value":"121"})", "application/json",
                                   {{"Host", "internal:8080"}, {"Origin", "https://proxy.example"}});
    REQUIRE(trusted);
    CHECK(trusted->status == 200);
    CHECK(h.cfg.response_retention_days == 121);
}

TEST_CASE("config: LiveSeconds copies and assigns by value and is safe across threads",
          "[server][config_routes][concurrency]") {
    yuzu::server::Config a;
    CHECK(a.session_timeout.count() == 90);
    a.session_timeout = std::chrono::seconds(45);
    yuzu::server::Config b = a; // Config is passed and copied by value
    CHECK(b.session_timeout.count() == 45);
    b.session_timeout = std::chrono::seconds(60);
    a = b;
    CHECK(static_cast<std::chrono::seconds>(a.session_timeout) == std::chrono::seconds(60));

    // One writer and several readers/copiers on fixed iteration counts (no sleeps): every value
    // seen is one that was written. Under the CI sanitizer leg a plain seconds member races here.
    yuzu::server::Config shared;
    shared.session_timeout = std::chrono::seconds(30);
    std::atomic<bool> bad{false};
    std::thread writer([&] {
        for (int i = 0; i < 20000; ++i)
            shared.session_timeout = std::chrono::seconds(i % 2 ? 30 : 90);
    });
    std::vector<std::thread> readers;
    readers.reserve(3); // no throw between the writer starting and the joins
    for (int t = 0; t < 3; ++t)
        readers.emplace_back([&] {
            for (int i = 0; i < 20000; ++i) {
                const auto v = shared.session_timeout.count();
                const yuzu::server::Config copy = shared;
                const auto c = copy.session_timeout.count();
                if ((v != 30 && v != 90) || (c != 30 && c != 90))
                    bad = true;
            }
        });
    writer.join();
    for (auto& r : readers)
        r.join();
    CHECK_FALSE(bad.load());
}

TEST_CASE("config: clamp_heartbeat_timeout moves an out-of-range stored value to the nearest bound",
          "[server][config_routes]") {
    // A heartbeat stored before the floor or the ceiling existed is moved to the nearest bound at
    // boot, never dropped: a sub-floor value would flap every agent, a huge one would stop
    // stale-agent reaping.
    CHECK(clamp_heartbeat_timeout(1) == kMinHeartbeatTimeoutSeconds);
    CHECK(clamp_heartbeat_timeout(29) == kMinHeartbeatTimeoutSeconds);
    CHECK(clamp_heartbeat_timeout(30) == 30);
    CHECK(clamp_heartbeat_timeout(120) == 120);
    CHECK(clamp_heartbeat_timeout(86400) == 86400);
    CHECK(clamp_heartbeat_timeout(86401) == kMaxHeartbeatTimeoutSeconds);
    CHECK(clamp_heartbeat_timeout(std::numeric_limits<int>::max()) == kMaxHeartbeatTimeoutSeconds);
    static_assert(kMinHeartbeatTimeoutSeconds == 30 && kMaxHeartbeatTimeoutSeconds == 86400);
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

TEST_CASE("config_routes: PUT the redaction placeholder for a secret key is refused without echoing it",
          "[pg][server][routes][config_routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    const std::string placeholder(RuntimeConfigStore::redacted_placeholder());
    auto res = h.sink.Put("/api/config/oidc_client_secret", R"({"value":")" + placeholder + R"("})");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].detail.find("placeholder") != std::string::npos); // the refusal text
    CHECK(h.audits[1].detail.find(placeholder) == std::string::npos);   // never the submitted value
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

    REQUIRE(h.audits.size() == 2); // attempted (no value at all), then the redacted outcome
    for (const auto& a : h.audits)
        CHECK(a.detail.find("super-secret-value") == std::string::npos);
    CHECK(h.audits[1].detail == "value=" + std::string(RuntimeConfigStore::redacted_placeholder()));
}

// ── An elevated-only session cannot write the sign-in provider keys ──────────
//
// perm_fn admits a JIT-elevated session for any securable. The oidc_* keys decide who becomes
// an administrator at an SSO login (oidc_admin_group is read from the stored value at the next
// start), so those keys need the caller's OWN administrator role; every other key stays
// writable under Infrastructure:Write.

TEST_CASE("config_routes: an elevated-only session cannot write any oidc_* key; "
          "nothing is stored",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.session_role = auth::Role::user; // admitted by perm_fn only through the elevation
    h.session_elevated = true;
    h.wire();

    // The guard is a prefix match; build the key list from the store's allow-list so a new
    // oidc_* key is exercised too (and the count pins that the list did not silently shrink).
    std::vector<std::string> keys;
    for (const auto& k : RuntimeConfigStore::allowed_keys())
        if (k.starts_with("oidc_"))
            keys.push_back(k);
    REQUIRE(keys.size() == 6);

    for (const auto& key : keys) {
        INFO(key);
        h.audits.clear();
        auto res = h.sink.Put("/api/config/" + key, R"({"value":"x"})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body.find("own administrator role") != std::string::npos);
        // The standard error envelope: a correlation id in the body and in the header.
        const auto refused = body(res->body);
        CHECK(refused["error"]["code"] == 403);
        CHECK(refused["error"].contains("correlation_id"));
        CHECK(refused["error"].contains("retry_after_ms"));
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "config.update");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == key);
        CHECK(h.audits[0].detail == "elevated_session_oidc_setting_blocked");
        CHECK(w.store.get_value(key).empty()); // nothing persisted
    }
}

TEST_CASE("config_routes: a non-administrator Infrastructure:Write holder and an admin-minted "
          "MCP token are refused for oidc_* keys with a distinct audit detail",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    // A custom/service role holding Infrastructure:Write: perm_fn admits, own role is user.
    h.session_role = auth::Role::user;
    auto res = h.sink.Put("/api/config/oidc_admin_group", R"({"value":"g"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(body(res->body)["error"].contains("correlation_id"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].detail == "admin_role_required_oidc_setting_blocked");

    // A supervised MCP token minted by an administrator carries the creator's role (admin);
    // the settings route refuses it through require_admin, so this route must too.
    h.audits.clear();
    h.session_role = auth::Role::admin;
    h.session_mcp_tier = "supervised";
    res = h.sink.Put("/api/config/oidc_admin_group", R"({"value":"g"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("administrator account is required") != std::string::npos);
    CHECK(w.store.get_value("oidc_admin_group").empty());
    // The token class has its own detail, not the missing-role one: the role was fine.
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].detail == "token_session_oidc_setting_blocked");
}

TEST_CASE("config_routes: an elevated-only session can still write non-oidc keys; an "
          "administrator can write the oidc_* keys",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.session_role = auth::Role::user;
    h.session_elevated = true;
    h.wire();

    auto res = h.sink.Put("/api/config/response_retention_days", R"({"value":"120"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.cfg.response_retention_days == 120);
    res = h.sink.Put("/api/config/heartbeat_timeout", R"({"value":"300"})");
    REQUIRE(res);
    CHECK(res->status == 200);

    // The caller's own role is admin (a local account, or an IdP-mapped SSO session).
    h.session_role = auth::Role::admin;
    h.session_elevated = false;
    for (const auto& [key, value] :
         std::vector<std::pair<std::string, std::string>>{{"oidc_issuer", "https://idp.example"},
                                                          {"oidc_client_id", "cid"},
                                                          {"oidc_redirect_uri", "https://x/cb"},
                                                          {"oidc_admin_group", "group-1"},
                                                          {"oidc_skip_tls_verify", "false"}}) {
        INFO(key);
        res = h.sink.Put("/api/config/" + key, R"({"value":")" + value + R"("})");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(w.store.get_value(key) == value);
    }
    res = h.sink.Put("/api/config/oidc_client_secret", R"({"value":"s3cret"})");
    REQUIRE(res);
    CHECK(res->status == 200);
}

// ── Keys whose own settings route is administrator-only ──────────────────────
//
// The settings routes for these keys are `require_admin`: they refuse a service-scoped token, an
// MCP-tier token and a non-admin effective role. The generic PUT admits the same callers on
// Infrastructure:Write alone, so it applies the same verdict (RuntimeConfigStore::write_class).
//
// Reachability, so these cases are not read as more than they are: these tests give the route
// whatever session `auth_fn` returns and a `perm_fn` that admits, which isolates the route's own
// rule. In production `perm_fn` refuses a service-scoped token and a readonly or operator MCP
// tier first (`auth.permission_required`); the sessions that reach this rule are a
// supervised-tier MCP token and, with RBAC on, a non-admin role holding Infrastructure:Write.

namespace {
std::vector<std::string> admin_route_keys() {
    std::vector<std::string> keys;
    for (const auto& k : RuntimeConfigStore::allowed_keys())
        if (RuntimeConfigStore::write_class(k) == ConfigWriteClass::AdminRoute)
            keys.push_back(k);
    return keys;
}

// One refused PUT: 403, the A4 envelope without a `permission` field, exactly one denied row
// carrying `detail`, and nothing stored.
void check_refused(MockHarness& h, const std::string& key, const std::string& message_part,
                   const std::string& detail, const std::string& prefix = "/api/config/") {
    INFO(prefix + key);
    h.audits.clear();
    auto res = h.sink.Put(prefix + key, R"({"value":"true"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find(message_part) != std::string::npos);
    const auto err = body(res->body)["error"];
    CHECK(err.contains("correlation_id"));
    CHECK(err.contains("remediation"));
    CHECK_FALSE(err.contains("permission"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "config.update");
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].target_id == key);
    CHECK(h.audits[0].detail == detail);
}
} // namespace

TEST_CASE("config_routes: the administrator-only keys refuse a supervised MCP-tier token and a "
          "non-administrator before the store is consulted (no store, no PostgreSQL)",
          "[server][routes][config_routes][elevation]") {
    MockHarness h; // runtime_config_store left null: the refusal must not need it
    h.session_role = auth::Role::admin; // an admin-minted token carries its creator's role
    h.session_mcp_tier = "supervised";
    h.wire();

    const auto keys = admin_route_keys();
    REQUIRE(keys.size() == 7);
    for (const auto& key : keys)
        check_refused(h, key, "administrator account is required",
                      "token_session_admin_setting_blocked");

    // Defence in depth: a service-scoped session is refused by the same rule if it ever reaches it.
    h.session_mcp_tier.clear();
    h.session_token_scope_service = "svc-a";
    for (const auto& key : keys)
        check_refused(h, key, "administrator account is required",
                      "token_session_admin_setting_blocked");

    // A non-administrator role (an engine-principal-like session) holding Infrastructure:Write.
    h.session_token_scope_service.clear();
    h.session_role = auth::Role::user;
    for (const auto& key : keys)
        check_refused(h, key, "own administrator role", "admin_role_required_setting_blocked");

    // The oidc_* keys refuse a service-scoped session too, with the token wording and detail.
    h.session_role = auth::Role::admin;
    h.session_token_scope_service = "svc-a";
    check_refused(h, "oidc_admin_group", "administrator account is required",
                  "token_session_oidc_setting_blocked");

    // An admin with a null store is still answered 503 for a key the class lets through, and the
    // route-owned key keeps its 400: the class lookup did not change either answer.
    h.session_token_scope_service.clear();
    auto res = h.sink.Put("/api/config/plugin_signing_required", R"({"value":"true"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    res = h.sink.Put("/api/config/dex_score_policy", R"({"value":"{}"})");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("config_routes: a failing or throwing audit sink never turns a refusal into a 5xx",
          "[server][routes][config_routes][elevation]") {
    MockHarness h; // no store: the 403 holds without one, so this isolates the audit sink
    h.session_role = auth::Role::admin;
    h.session_mcp_tier = "supervised";
    h.wire();

    for (const bool throws : {false, true}) {
        h.audit_succeeds = throws; // false: returns false; true: unused, the sink throws instead
        h.audit_throws = throws;
        for (const auto& key : admin_route_keys()) {
            INFO(key << " throws=" << throws);
            auto res = h.sink.Put("/api/config/" + key, R"({"value":"true"})");
            REQUIRE(res);
            CHECK(res->status == 403); // the refusal holds without its evidence row
        }
    }
}

TEST_CASE("config_routes: a denied caller gets 403 before the body is parsed",
          "[server][routes][config_routes][elevation]") {
    MockHarness h;
    h.session_role = auth::Role::admin;
    h.session_mcp_tier = "supervised";
    h.wire();

    // Malformed JSON and a missing value would each be a 400 for an admitted caller; the class
    // refusal precedes both.
    for (const auto& [key, payload] : std::vector<std::pair<std::string, std::string>>{
             {"dex_blast_min_devices", "not json"},
             {"dex_blast_min_devices", R"({"nope":1})"},
             {"oidc_issuer", "not json"}}) {
        INFO(key << " " << payload);
        auto res = h.sink.Put("/api/config/" + key, payload);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
}

TEST_CASE("config_routes: a supervised MCP-tier token is refused for every administrator-only "
          "key with one denied row and nothing stored",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.session_role = auth::Role::admin;
    h.session_mcp_tier = "supervised";
    h.wire();

    const auto keys = admin_route_keys();
    REQUIRE(keys.size() == 7);
    for (const auto& key : keys) {
        check_refused(h, key, "administrator account is required",
                      "token_session_admin_setting_blocked");
        CHECK(w.store.get_value(key).empty());
    }
}

TEST_CASE("config_routes: a non-administrator Infrastructure:Write holder is refused for "
          "every administrator-only key; an administrator account and an elevated "
          "session are admitted, as on the settings routes",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.session_role = auth::Role::user; // perm_fn admits (Infrastructure:Write), own role is user
    h.wire();

    const auto keys = admin_route_keys();
    REQUIRE(keys.size() == 7);
    for (const auto& key : keys) {
        check_refused(h, key, "own administrator role", "admin_role_required_setting_blocked");
        CHECK(w.store.get_value(key).empty());
    }

    // Effective role counts (require_admin): an active elevation is admin for its window.
    h.session_elevated = true;
    auto res = h.sink.Put("/api/config/plugin_signing_required", R"({"value":"true"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(w.store.get_value("plugin_signing_required") == "true");

    // An administrator account writes every one of them: attempted, then success, and the
    // value is stored.
    h.session_elevated = false;
    h.session_role = auth::Role::admin;
    for (const auto& [key, value] :
         std::vector<std::pair<std::string, std::string>>{{"plugin_signing_required", "false"},
                                                          {"dex_alert_routing", "[]"},
                                                          {"dex_blast_min_devices", "5"},
                                                          {"dex_blast_window_seconds", "300"},
                                                          {"dex_blast_cooldown_seconds", "600"},
                                                          {"dex_cohort_export_key", "team"},
                                                          {"audit_retention_days", "400"}}) {
        INFO(key);
        h.audits.clear();
        res = h.sink.Put("/api/config/" + key, R"({"value":")" + value + R"("})");
        REQUIRE(res);
        CHECK(res->status == 200);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].result == "success");
        CHECK(w.store.get_value(key) == value);
    }
}

TEST_CASE("config_routes: an MCP-tier token can still write the general keys",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.session_role = auth::Role::admin;
    h.session_mcp_tier = "supervised";
    h.wire();

    auto res = h.sink.Put("/api/config/response_retention_days", R"({"value":"120"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    res = h.sink.Put("/api/config/log_level", R"({"value":"info"})");
    REQUIRE(res);
    CHECK(res->status == 200);

    // A plain (unelevated) non-administrator is not refused by the class for a general key either.
    h.session_mcp_tier.clear();
    h.session_role = auth::Role::user;
    res = h.sink.Put("/api/config/log_level", R"({"value":"warn"})");
    REQUIRE(res);
    CHECK(res->status == 200);
}

// ── v1 twins: GET /api/v1/config and PUT /api/v1/config/{param} ─────────────────────────────
//
// The twins share the core (config_write.hpp) and the handler with the legacy routes; the cases
// below pin the parts that differ (the envelope) and prove the parts that must not (the gate, the
// caller rule, the audit rows) by running both routes on the same input.

TEST_CASE("config_routes: the v1 twins gate on the same securables as the legacy routes",
          "[server][routes][config_routes]") {
    MockHarness h;
    h.wire();
    REQUIRE(h.sink.Get("/api/v1/config"));
    REQUIRE(h.sink.Put("/api/v1/config/log_level", R"({"value":"debug"})"));
    REQUIRE(h.perm_calls.size() == 2);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Infrastructure", "Read"});
    CHECK(h.perm_calls[1] == std::pair<std::string, std::string>{"Infrastructure", "Write"});
}

TEST_CASE("config_routes: a perm_fn denial 403s the v1 routes before the store or the body",
          "[server][routes][config_routes]") {
    MockHarness h;
    h.perm_allow = false;
    h.wire();
    auto get_res = h.sink.Get("/api/v1/config");
    REQUIRE(get_res);
    CHECK(get_res->status == 403);
    auto put_res = h.sink.Put("/api/v1/config/log_level", "not json");
    REQUIRE(put_res);
    CHECK(put_res->status == 403);
    CHECK(h.audits.empty());
}

TEST_CASE("config_routes: the v1 PUT refuses the administrator-only keys like the legacy PUT "
          "(no store, no PostgreSQL)",
          "[server][routes][config_routes][elevation]") {
    MockHarness h;
    h.session_role = auth::Role::admin;
    h.session_mcp_tier = "supervised";
    h.wire();
    const std::string v1 = "/api/v1/config/";

    const auto keys = admin_route_keys();
    REQUIRE(keys.size() == 7);
    for (const auto& key : keys)
        check_refused(h, key, "administrator account is required",
                      "token_session_admin_setting_blocked", v1);

    h.session_mcp_tier.clear();
    h.session_token_scope_service = "svc-a";
    for (const auto& key : keys)
        check_refused(h, key, "administrator account is required",
                      "token_session_admin_setting_blocked", v1);

    h.session_token_scope_service.clear();
    h.session_role = auth::Role::user;
    for (const auto& key : keys)
        check_refused(h, key, "own administrator role", "admin_role_required_setting_blocked", v1);

    h.session_role = auth::Role::admin;
    h.session_token_scope_service = "svc-a";
    check_refused(h, "oidc_admin_group", "administrator account is required",
                  "token_session_oidc_setting_blocked", v1);

    // An admin with a null store: 503 for a key the class admits, 400 for the route-owned key.
    h.session_token_scope_service.clear();
    auto res = h.sink.Put(v1 + "plugin_signing_required", R"({"value":"true"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body(res->body)["error"]["code"] == 503);
    CHECK(body(res->body)["error"].contains("retry_after_ms"));
    res = h.sink.Put(v1 + "dex_score_policy", R"({"value":"{}"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(body(res->body)["error"].contains("remediation"));
}

// Differential: the legacy and v1 PUT answer the same status and write the same audit rows for
// every allowed key under every caller shape, up to the store check (the store is null, so every
// admitted write ends there; the pg differential below covers validation, audit rows and the
// success path). A fix to one that misses the other fails here.
TEST_CASE("config_routes: the legacy and v1 PUT agree on every pre-store gate (csrf, refusals, "
          "route-owned, store check) for every key and caller shape",
          "[server][routes][config_routes][elevation]") {
    struct Caller {
        const char* name;
        auth::Role role;
        const char* mcp_tier;
        const char* scope_service;
        const char* auth_source;
        bool elevated;
    };
    const Caller callers[] = {
        {"admin api token", auth::Role::admin, "", "", "api_token", false},
        {"supervised mcp token", auth::Role::admin, "supervised", "", "api_token", false},
        {"service-scoped token", auth::Role::admin, "", "svc-a", "api_token", false},
        {"plain user", auth::Role::user, "", "", "api_token", false},
        {"elevated user", auth::Role::user, "", "", "api_token", true},
        {"cross-site cookie admin", auth::Role::admin, "", "", "local", false},
    };
    auto keys = RuntimeConfigStore::allowed_keys();
    keys.push_back("not_a_setting");

    for (const auto& c : callers) {
        MockHarness h; // null store: every admitted write ends at the store gate
        h.session_role = c.role;
        h.session_mcp_tier = c.mcp_tier;
        h.session_token_scope_service = c.scope_service;
        h.auth_source = c.auth_source;
        h.session_elevated = c.elevated;
        h.wire();
        for (const auto& key : keys) {
            INFO(std::string(c.name) + " / " + key);
            h.audits.clear();
            auto legacy = h.sink.Put("/api/config/" + key, R"({"value":"true"})");
            REQUIRE(legacy);
            const auto legacy_audits = h.audits;
            h.audits.clear();
            auto v1 = h.sink.Put("/api/v1/config/" + key, R"({"value":"true"})");
            REQUIRE(v1);
            CHECK(v1->status == legacy->status);
            REQUIRE(h.audits.size() == legacy_audits.size());
            for (std::size_t i = 0; i < legacy_audits.size(); ++i) {
                CHECK(h.audits[i].action == legacy_audits[i].action);
                CHECK(h.audits[i].result == legacy_audits[i].result);
                CHECK(h.audits[i].target_id == legacy_audits[i].target_id);
                CHECK(h.audits[i].detail == legacy_audits[i].detail);
            }
            if (v1->status >= 400)
                CHECK(body(v1->body)["error"]["code"] == v1->status);
        }
    }
}

TEST_CASE("config_routes: only the v1 PUT calls the MFA step-up closure, with its table label",
          "[server][routes][config_routes][stepup]") {
    MockHarness h;
    h.wire();
    REQUIRE(h.sink.Put("/api/config/log_level", R"({"value":"debug"})"));
    REQUIRE(h.sink.Get("/api/config"));
    REQUIRE(h.sink.Get("/api/v1/config"));
    CHECK(h.stepup_labels.empty()); // legacy PUT (pending row) and both GETs never call it

    REQUIRE(h.sink.Put("/api/v1/config/log_level", R"({"value":"debug"})"));
    REQUIRE(h.stepup_labels.size() == 1);
    CHECK(h.stepup_labels[0] == "PUT /api/v1/config/{key}");
}

TEST_CASE("config_routes: a missing step-up proof stops the v1 PUT before any refusal, audit or "
          "write; the legacy PUT is unaffected",
          "[server][routes][config_routes][stepup]") {
    MockHarness h;
    h.stepup_allow = false;
    h.session_mcp_tier = "supervised"; // would otherwise get the 403 refusal + denied row
    h.wire();

    auto v1 = h.sink.Put("/api/v1/config/plugin_signing_required", R"({"value":"true"})");
    REQUIRE(v1);
    CHECK(v1->status == 403);
    CHECK(v1->body.find("step-up required") != std::string::npos);
    CHECK(h.audits.empty());

    // The legacy route does not step up, so it reaches its own refusal.
    auto legacy = h.sink.Put("/api/config/plugin_signing_required", R"({"value":"true"})");
    REQUIRE(legacy);
    CHECK(legacy->status == 403);
    CHECK(legacy->body.find("administrator account is required") != std::string::npos);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "denied");
}

TEST_CASE("config_routes: an unwired step-up closure is skipped, not a fault",
          "[server][routes][config_routes][stepup]") {
    MockHarness h;
    h.stepup_wired = false;
    h.wire();
    auto res = h.sink.Put("/api/v1/config/not_a_setting", R"({"value":"x"})");
    REQUIRE(res);
    CHECK(res->status == 503); // null store: reached the store gate, so nothing blocked it earlier
}

TEST_CASE("config_routes: a degraded runtime_config_store answers the v1 routes 503 with a retry hint",
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
    auto check = [](const auto& res) {
        REQUIRE(res);
        CHECK(res->status == 503);
        const auto err = body(res->body)["error"];
        CHECK(err["code"] == 503);
        CHECK(err["retry_after_ms"] == 5000);
        CHECK(err.contains("correlation_id"));
    };
    check(h.sink.Get("/api/v1/config"));
    check(h.sink.Put("/api/v1/config/log_level", R"({"value":"debug"})"));
}

TEST_CASE("config_routes: GET /api/v1/config is the legacy body under data, secrets as is_set",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    REQUIRE(h.sink.Put("/api/config/response_retention_days", R"({"value":"120"})")->status == 200);
    REQUIRE(h.sink.Put("/api/config/oidc_client_secret", R"({"value":"s3cret"})")->status == 200);

    auto legacy = h.sink.Get("/api/config");
    auto v1 = h.sink.Get("/api/v1/config");
    REQUIRE(legacy);
    REQUIRE(v1);
    CHECK(v1->status == 200);
    CHECK(v1->get_header_value("Cache-Control") == "no-store");
    const auto envelope = body(v1->body);
    CHECK(envelope["meta"]["api_version"] == "v1");
    // The v1 view is the legacy view plus the withheld_keys declaration (empty for an
    // administrator: nothing is withheld).
    auto data = envelope["data"];
    CHECK(data["withheld_keys"] == json::array());
    data.erase("withheld_keys");
    CHECK(data == body(legacy->body));
    CHECK(envelope["data"]["overrides"]["response_retention_days"]["value"] == "120");
    CHECK(envelope["data"]["overrides"]["oidc_client_secret"]["is_set"] == true);
    CHECK(v1->body.find("s3cret") == std::string::npos);
}

// Every GET shape is scoped to the caller; only the v1 route and the MCP tool declare what is withheld.
TEST_CASE("config_routes: both GET routes withhold the overrides a caller could not write; the v1 "
          "route declares them",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h; // an administrator first, to store one override of each class
    h.runtime_config_store = &w.store;
    h.wire();
    for (const auto& [key, value] : std::vector<std::pair<std::string, std::string>>{
             {"oidc_admin_group", "grp-admins"},
             {"oidc_issuer", "https://idp.example.com"},
             {"oidc_client_secret", "s3cret"},
             {"plugin_signing_required", "true"},
             {"audit_retention_days", "400"},
             {"response_retention_days", "120"}})
        REQUIRE(h.sink.Put("/api/config/" + key, json({{"value", value}}).dump())->status == 200);

    // The oracle is spelled out, not derived: 6 oidc keys, plugin signing, audit retention, 5 dex.
    const std::vector<std::string> withheld_for_token{
        "audit_retention_days",       "dex_alert_routing",
        "dex_blast_cooldown_seconds", "dex_blast_min_devices",
        "dex_blast_window_seconds",   "dex_cohort_export_key",
        "oidc_admin_group",           "oidc_client_id",
        "oidc_client_secret",         "oidc_issuer",
        "oidc_redirect_uri",          "oidc_skip_tls_verify",
        "plugin_signing_required"};

    // An MCP-tier token and a plain user see the general override and none of the others.
    for (const bool token : {true, false}) {
        MockHarness t;
        t.runtime_config_store = &w.store;
        if (token)
            t.session_mcp_tier = "supervised";
        else
            t.session_role = auth::Role::user;
        t.wire();
        for (const bool v1_route : {true, false}) {
            INFO((token ? "token " : "user ") << (v1_route ? "v1" : "legacy"));
            auto res = t.sink.Get(v1_route ? "/api/v1/config" : "/api/config");
            REQUIRE(res);
            CHECK(res->status == 200);
            auto data = body(res->body);
            if (v1_route)
                data = data["data"];
            CHECK(data["overrides"].contains("response_retention_days"));
            for (const auto& k : withheld_for_token) {
                INFO(k);
                CHECK_FALSE(data["overrides"].contains(k));
            }
            CHECK_FALSE(data["config"].contains("audit_retention_days"));
            CHECK(data.contains("withheld_keys") == v1_route);
            if (v1_route)
                CHECK(data["withheld_keys"] == json(withheld_for_token));
            CHECK(res->body.find("grp-admins") == std::string::npos);
            CHECK(res->body.find("idp.example.com") == std::string::npos);
        }
    }

    // An administrator sees everything on both routes; the legacy body has no withheld_keys.
    auto legacy = h.sink.Get("/api/config");
    auto admin = h.sink.Get("/api/v1/config");
    REQUIRE(legacy);
    REQUIRE(admin);
    const auto old = body(legacy->body);
    CHECK(old["overrides"].contains("oidc_admin_group"));
    CHECK(old["overrides"]["oidc_client_secret"]["is_set"] == true);
    CHECK(old["config"].contains("audit_retention_days"));
    CHECK_FALSE(old.contains("withheld_keys"));
    const auto adm = body(admin->body)["data"];
    CHECK(adm["withheld_keys"] == json::array());
    auto adm_without = adm;
    adm_without.erase("withheld_keys");
    CHECK(adm_without == old);

    // An elevated-only user is refused the oidc_* keys but not the other admin-class ones.
    MockHarness e;
    e.runtime_config_store = &w.store;
    e.session_role = auth::Role::user;
    e.session_elevated = true;
    e.wire();
    const auto ev = body(e.sink.Get("/api/v1/config")->body)["data"];
    CHECK_FALSE(ev["overrides"].contains("oidc_admin_group"));
    CHECK(ev["overrides"].contains("plugin_signing_required"));
    CHECK(ev["withheld_keys"].size() == 6);
}

// A stored row the write classes know nothing about (stale, renamed) is shown only to an effective
// administrator: the scoped view defaults to deny.
TEST_CASE("config_routes: a stored row with no write class is withheld from a non-administrator",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult ins{PQexec(conn.get(),
                                "INSERT INTO runtime_config_store.runtime_config "
                                "(key, value, updated_by, updated_at) "
                                "VALUES ('legacy_removed_key', 'leftover', 'old', 1)")};
        REQUIRE(ins.ok());
    }
    MockHarness user;
    user.runtime_config_store = &w.store;
    user.session_role = auth::Role::user;
    user.wire();
    MockHarness admin;
    admin.runtime_config_store = &w.store;
    admin.wire();
    for (const char* path : {"/api/config", "/api/v1/config"}) {
        INFO(path);
        auto u = user.sink.Get(path);
        auto a = admin.sink.Get(path);
        REQUIRE(u);
        REQUIRE(a);
        CHECK(u->body.find("legacy_removed_key") == std::string::npos);
        CHECK(a->body.find("legacy_removed_key") != std::string::npos);
    }
}

// The view must fail, not read as empty, when the store is open but the read itself fails.
TEST_CASE("config_routes: an open store whose read fails answers 503 on every GET",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    REQUIRE(h.sink.Get("/api/config")->status == 200);
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult drop{PQexec(conn.get(), "ALTER TABLE runtime_config_store.runtime_config "
                                             "RENAME TO runtime_config_gone")};
        REQUIRE(drop.ok());
    }
    for (const char* path : {"/api/config", "/api/v1/config"}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(body(res->body)["error"]["code"] == 503);
        CHECK(res->body.find("overrides") == std::string::npos); // never an empty configuration
    }
}

TEST_CASE("config_write: concurrent writers and readers leave the store and the live config on the "
          "same value, and the live fields are safe to read (run under TSan in the nightly)",
          "[pg][server][config_write][tsan]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    yuzu::server::Config cfg{};
    auth::AutoApproveEngine engine{};
    const config::Backing backing{&cfg, &engine, &w.store};
    auth::Session admin;
    admin.username = "alice";
    admin.role = auth::Role::admin;

    constexpr int kWriters = 4;
    constexpr int kReaders = 2;
    constexpr int kIterations = 40;
    std::atomic<bool> stop{false};
    std::atomic<int> read_faults{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < kWriters; ++t)
        threads.emplace_back([&, t] {
            for (int i = 0; i < kIterations; ++i) {
                const int v = 100 + t * 1000 + i;
                auto r = config::write_and_apply(backing, "response_retention_days",
                                                 std::to_string(v), v, "writer");
                if (!r)
                    read_faults.fetch_add(1);
            }
        });
    for (int t = 0; t < kReaders; ++t)
        threads.emplace_back([&] {
            while (!stop.load()) {
                auto view = config::build_config_view(backing, admin, true);
                if (!view || !view->at("config").contains("response_retention_days"))
                    read_faults.fetch_add(1);
            }
        });
    for (int t = 0; t < kWriters; ++t)
        threads[static_cast<std::size_t>(t)].join();
    stop.store(true);
    for (std::size_t t = kWriters; t < threads.size(); ++t)
        threads[t].join();

    CHECK(read_faults.load() == 0);
    // The writers are serialised across the store write and the live apply, so whichever wrote
    // last left BOTH on its value: the store and the live config never disagree.
    CHECK(w.store.get_value("response_retention_days") ==
          std::to_string(cfg.response_retention_days.get()));
}

TEST_CASE("config_routes: an open store is not enough, the live config and the engine must be wired",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    yuzu::server::Config cfg{};
    auth::AutoApproveEngine engine{};
    CHECK(config::store_ready({&cfg, &engine, &w.store}));
    CHECK_FALSE(config::store_ready({nullptr, &engine, &w.store}));
    CHECK_FALSE(config::store_ready({&cfg, nullptr, &w.store}));
    auth::Session admin;
    admin.role = auth::Role::admin;
    CHECK_FALSE(config::build_config_view({nullptr, &engine, &w.store}, admin, true).has_value());
}

TEST_CASE("config_routes: the legacy and v1 PUT agree on validation, audit rows and the success "
          "path with a real store",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    struct Case {
        const char* key;
        const char* req_body;
    };
    const Case cases[] = {
        {"response_retention_days", R"({"value":"125"})"}, // success
        {"response_retention_days", R"({"value":"abc"})"}, // integer validation
        {"response_retention_days", R"({"value":"-0"})"},  // leading minus
        {"response_retention_days", R"({"value":"0"})"},   // store refuses a non-positive window
        {"log_level", R"({"value":"loud"})"},              // store refuses the value
        {"log_level", R"({"other":1})"},                   // missing value
        {"log_level", "{not json"},                        // invalid json
        {"not_a_setting", R"({"value":"x"})"},             // unknown key
        {"oidc_client_secret", R"({"value":"s3cret"})"},   // secret: redacted detail
        {"dex_score_policy", R"({"value":"{}"})"},         // route-owned
    };
    for (const auto& c : cases) {
        INFO(c.key << " " << c.req_body);
        h.audits.clear();
        auto legacy = h.sink.Put(std::string("/api/config/") + c.key, c.req_body);
        REQUIRE(legacy);
        const auto legacy_audits = h.audits;
        h.audits.clear();
        auto v1 = h.sink.Put(std::string("/api/v1/config/") + c.key, c.req_body);
        REQUIRE(v1);
        CHECK(v1->status == legacy->status);
        REQUIRE(h.audits.size() == legacy_audits.size());
        for (std::size_t i = 0; i < legacy_audits.size(); ++i) {
            CHECK(h.audits[i].result == legacy_audits[i].result);
            CHECK(h.audits[i].target_id == legacy_audits[i].target_id);
            CHECK(h.audits[i].detail == legacy_audits[i].detail);
        }
        if (v1->status >= 400)
            CHECK(body(v1->body)["error"]["code"] == v1->status);
    }
}

TEST_CASE("config_routes: PUT /api/v1/config/{param} writes, applies and audits like the legacy PUT",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    auto res = h.sink.Put("/api/v1/config/response_retention_days", R"({"value":"130"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    const auto b = body(res->body);
    CHECK(b["meta"]["api_version"] == "v1");
    CHECK(b["data"] == json({{"key", "response_retention_days"},
                             {"value", "130"},
                             {"applied", true},
                             {"effect", "stored_only"}}));
    CHECK(h.cfg.response_retention_days == 130);
    CHECK(w.store.get_value("response_retention_days") == "130");
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].detail.empty());
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_type == "RuntimeConfig");
    CHECK(h.audits[1].detail == "value=130");

    // A secret key: the value reaches neither the response nor the audit detail.
    h.audits.clear();
    res = h.sink.Put("/api/v1/config/oidc_client_secret", R"({"value":"s3cret-v1"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("s3cret-v1") == std::string::npos);
    CHECK_FALSE(body(res->body)["data"].contains("value"));
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].detail.find("s3cret-v1") == std::string::npos);

    // A JSON scalar is stored as its text, like the legacy route.
    res = h.sink.Put("/api/v1/config/heartbeat_timeout", R"({"value":45})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(w.store.get_value("heartbeat_timeout") == "45");
}

TEST_CASE("config_routes: the v1 PUT reports how soon a write takes effect; the legacy body has no effect field",
          "[pg][server][routes][config_routes]") {
    LogLevelGuard level_guard;
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    const std::vector<std::pair<std::string, std::pair<std::string, std::string>>> cases{
        {"log_level", {"info", "immediate"}},
        {"heartbeat_timeout", {"45", "immediate"}},
        {"dex_blast_min_devices", {"5", "deferred"}},
        {"plugin_signing_required", {"true", "stored_only"}},
        {"auto_approve_enabled", {"false", "stored_only"}},
        {"audit_retention_days", {"400", "stored_only"}},
        {"oidc_issuer", {"https://idp.example.com", "stored_only"}},
        {"oidc_admin_group", {"grp-admins", "deferred"}},
        {"oidc_redirect_uri", {"https://yuzu.example.com/auth/callback", "deferred"}}};
    for (const auto& [key, vv] : cases) {
        INFO(key);
        auto res = h.sink.Put("/api/v1/config/" + key, json({{"value", vv.first}}).dump());
        REQUIRE(res);
        REQUIRE(res->status == 200);
        CHECK(body(res->body)["data"]["effect"] == vv.second);
        auto legacy = h.sink.Put("/api/config/" + key, json({{"value", vv.first}}).dump());
        REQUIRE(legacy);
        CHECK_FALSE(body(legacy->body).contains("effect"));
    }
}

TEST_CASE("config_routes: heartbeat_timeout is bounded to 30..86400 on both PUT routes",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    for (const char* prefix : {"/api/config/", "/api/v1/config/"}) {
        INFO(prefix);
        for (const char* ok : {"30", "86400"}) {
            auto res = h.sink.Put(std::string(prefix) + "heartbeat_timeout",
                                  std::string(R"({"value":")") + ok + R"("})");
            REQUIRE(res);
            CHECK(res->status == 200);
        }
        for (const char* bad : {"29", "86401", "2147483647"}) {
            INFO(bad);
            auto res = h.sink.Put(std::string(prefix) + "heartbeat_timeout",
                                  std::string(R"({"value":")") + bad + R"("})");
            REQUIRE(res);
            CHECK(res->status == 400);
        }
    }
    CHECK(h.cfg.session_timeout.count() == 86400); // the last accepted write
}

TEST_CASE("config_routes: the v1 PUT takes a string or a JSON scalar, not null, an array or an object",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    for (const char* bad : {R"({"value":null})", R"({"value":[1]})", R"({"value":{"a":1}})"}) {
        INFO(bad);
        h.audits.clear();
        auto res = h.sink.Put("/api/v1/config/oidc_issuer", bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(body(res->body)["error"]["message"].get<std::string>().find("string, number or boolean") !=
              std::string::npos);
        CHECK(h.audits.empty());
        CHECK(w.store.get_value("oidc_issuer").empty());
    }
    for (const char* ok : {R"({"value":"x"})", R"({"value":true})", R"({"value":7})"}) {
        INFO(ok);
        auto res = h.sink.Put("/api/v1/config/oidc_issuer", ok);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
}

TEST_CASE("config_routes: log_level reads back in the spelling the write accepts",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    LogLevelGuard level_guard;
    REQUIRE(h.sink.Put("/api/v1/config/log_level", R"({"value":"warn"})")->status == 200);
    for (const char* path : {"/api/config", "/api/v1/config"}) {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        auto data = body(res->body);
        if (data.contains("data"))
            data = data["data"];
        CHECK(data["config"]["log_level"] == "warn");
        // and the value read is accepted by the write
        REQUIRE(h.sink.Put("/api/v1/config/log_level",
                           json({{"value", data["config"]["log_level"]}}).dump())
                    ->status == 200);
    }
}

TEST_CASE("config_routes: the v1 PUT refuses the change when the attempted row cannot be written, "
          "and flags a lost outcome row in the body",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();
    const int before = h.cfg.response_retention_days;

    h.audit_fails_at = 0; // the attempted row
    auto refused = h.sink.Put("/api/v1/config/response_retention_days", R"({"value":"131"})");
    REQUIRE(refused);
    CHECK(refused->status == 503);
    CHECK(refused->get_header_value("Sec-Audit-Failed") == "true");
    const auto err = body(refused->body)["error"];
    CHECK(err["message"] == "audit log unavailable; the change was not made");
    CHECK(err["retry_after_ms"] == 5000);
    CHECK(h.cfg.response_retention_days == before);
    CHECK(h.audits.size() == 1);

    h.audits.clear();
    h.audit_fails_at = 1; // the outcome row
    auto res = h.sink.Put("/api/v1/config/response_retention_days", R"({"value":"132"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(body(res->body)["data"]["audit_persisted"] == false);
    CHECK(h.cfg.response_retention_days == 132);
}

TEST_CASE("config_routes: the v1 PUT answers every rejected input in the A4 envelope",
          "[pg][server][routes][config_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.wire();

    struct Case {
        const char* what;
        const char* path;
        const char* req_body;
        const char* message_part;
    };
    const Case cases[] = {
        {"non-numeric integer", "/api/v1/config/response_retention_days", R"({"value":"abc"})",
         "non-negative integer"},
        {"missing value", "/api/v1/config/log_level", R"({"other":1})", "missing 'value'"},
        {"invalid json", "/api/v1/config/log_level", "{not json", "invalid JSON"},
        {"unknown key", "/api/v1/config/not_a_setting", R"({"value":"x"})", "not a configurable"},
        {"store-refused value", "/api/v1/config/log_level", R"({"value":"loud"})", "one of"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        h.audits.clear();
        auto res = h.sink.Put(c.path, c.req_body);
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto err = body(res->body)["error"];
        CHECK(err["code"] == 400);
        CHECK(err["message"].get<std::string>().find(c.message_part) != std::string::npos);
        CHECK(err.contains("correlation_id"));
    }
    CHECK(h.cfg.response_retention_days != 0);
}

TEST_CASE("config_routes: an MCP-tier token can still write the general keys through the v1 PUT",
          "[pg][server][routes][config_routes][elevation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, config_routes_tpl);
    PgWired w{db.dsn()};
    MockHarness h;
    h.runtime_config_store = &w.store;
    h.session_mcp_tier = "supervised";
    h.wire();
    for (const auto* key : {"heartbeat_timeout", "response_retention_days", "log_level"}) {
        INFO(key);
        const std::string value = std::string(key) == "log_level" ? "info" : "120";
        auto res = h.sink.Put(std::string("/api/v1/config/") + key, R"({"value":")" + value + R"("})");
        REQUIRE(res);
        CHECK(res->status == 200);
    }
}

// Drift tripwire (source scan; no PostgreSQL). The class table is only as good as its fit to the
// writers: a Settings route that writes a runtime-config key through
// `runtime_config_store_->set("key", ...)` is an administrator route by construction, so the
// generic PUT must not let a weaker caller write the same key. This fails when a settings writer
// names a key classified General. It names literal keys and `plugin_signing::
// kPluginSigningRequiredKey` only; a `set(` call with any other first argument fails the call
// count below, so a key built at runtime cannot slip past it unseen.
TEST_CASE("config_routes: every key a Settings route writes is not classified General",
          "[server][routes][config_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    static const std::regex kSet(
        R"re(runtime_config_store_->set\(\s*(?:"([a-z_]+)"|plugin_signing::(kPluginSigningRequiredKey)))re");
    static const std::regex kAnySet(R"re(runtime_config_store_?->set\()re");

    std::set<std::string> written;
    std::set<std::string> other_writers; // route files besides these two that write the store
    for (const auto& entry : std::filesystem::directory_iterator(YUZU_SERVER_SRC_DIR)) {
        const auto name = entry.path().filename().string();
        if (!name.ends_with("_routes.cpp"))
            continue;
        std::ifstream in(entry.path());
        REQUIRE(in.is_open());
        const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
        if (name == "settings_routes.cpp") {
            std::size_t recognised = 0;
            for (auto it = std::sregex_iterator(src.begin(), src.end(), kSet);
                 it != std::sregex_iterator(); ++it, ++recognised)
                written.insert((*it)[1].matched ? (*it)[1].str()
                                                : std::string("plugin_signing_required"));
            // Every set() call must be one the scan can name. A call whose key is computed
            // (a variable, a constant other than the one above, a formatted string) matches
            // kAnySet but not kSet, so it fails here instead of slipping past the class check.
            const auto any = static_cast<std::size_t>(std::distance(
                std::sregex_iterator(src.begin(), src.end(), kAnySet), std::sregex_iterator()));
            INFO("settings_routes.cpp has "
                 << any
                 << " runtime_config_store_->set( calls and the "
                    "scan names the key of "
                 << recognised
                 << ": use a string literal or "
                    "plugin_signing::kPluginSigningRequiredKey, or extend kSet");
            CHECK(any == recognised);
        } else if (name != "config_routes.cpp" && std::regex_search(src, kAnySet)) {
            other_writers.insert(name);
        }
    }

    // A new route file that writes runtime config is outside this scan: classify its keys and
    // extend the scan (and route the write through the shared class rule) before adding it.
    for (const auto& name : other_writers)
        FAIL_CHECK(name << " writes runtime_config_store_ but this scan only covers "
                           "settings_routes.cpp; extend the scan and classify its keys");

    // Guard against the scan rotting into a vacuous pass: the six administrator keys and the
    // oidc keys are all written by settings_routes.cpp today.
    // (audit_retention_days is administrator-only too but has no Settings writer, so it is not
    // here.)
    for (const char* key :
         {"plugin_signing_required", "dex_alert_routing", "dex_blast_min_devices",
          "dex_blast_window_seconds", "dex_blast_cooldown_seconds", "dex_cohort_export_key"}) {
        INFO(key << ": settings_routes.cpp changed shape? update this scan or classify the key");
        CHECK(written.count(key) == 1);
    }
    CHECK(written.count("oidc_admin_group") == 1);
    CHECK(written.size() >= 12);

    for (const auto& key : written) {
        INFO(key << " is written by a Settings route but classified General");
        const auto cls = RuntimeConfigStore::write_class(key);
        REQUIRE(cls.has_value());
        CHECK(*cls != ConfigWriteClass::General);
    }
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
    // The v1 PUT is step-up kRequired: its Deps must carry the shared closure. An unwired closure
    // is skipped silently by design (test below), so only this scan notices a dropped line.
    const auto cfg_deps = src.find("yuzu::server::config::Deps{");
    REQUIRE(cfg_deps != std::string::npos);
    CHECK(src.substr(cfg_deps, 700).find(".step_up_fn = step_up_fn") != std::string::npos);
    // The MCP tools read and write through the same cfg_, auto_approve_ and store.
    const auto mcp_wire = src.find("mcp_server_->set_runtime_config_backing(");
    REQUIRE(mcp_wire != std::string::npos);
    CHECK(src.substr(mcp_wire, 200).find("&cfg_, &auto_approve_, runtime_config_store_.get()") !=
          std::string::npos);
    // The boot loader raises a sub-floor stored heartbeat_timeout through the shared helper.
    CHECK(src.find("clamp_heartbeat_timeout(stored)") != std::string::npos);
    CHECK(src.find("cfg_.session_timeout = std::chrono::seconds(applied);") != std::string::npos);
    // The Developer role-grid probe is the non-auditing has_permission, not the auditing gate.
    const auto dev = src.find("yuzu::server::developer::Deps{");
    REQUIRE(dev != std::string::npos);
    const auto block = src.substr(dev, 900);
    CHECK(block.find(".probe_fn =") != std::string::npos);
    CHECK(block.find("auth_routes_->has_permission(") != std::string::npos);
}
