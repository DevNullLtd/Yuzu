/**
 * test_rest_audit_sample.cpp — HTTP-level coverage for
 * `GET /api/v1/audit/auth-sample` (#4 / SOC 2 CC7.2 sampled auth-log evidence
 * export). Uses the TestRouteSink dispatch pattern (no httplib acceptor thread,
 * #438) with a populated in-memory AuditStore wired into register_routes.
 *
 * Covers: gate (AuditLog:Read via perm_fn), 503 on no store, auth-action
 * scoping (auth./mfa./session. only — noise excluded), the limit cap, bad
 * from/to → 400, and the export emitting audit.auth_sample.exported.
 */

#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// AuditStore migrated to Postgres (ADR-0006) — the harness below clones this
// pre-migrated template instead of opening a SQLite path for its populated
// (store_opens=true) arm.
yuzu::test::PgTestTemplate rest_audit_sample_tpl{"sampleaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("sampleaudit template: store failed to migrate");
}};

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct AuthSampleHarness {
    yuzu::server::test::TestRouteSink sink;
    // AuditStore ported to Postgres (ADR-0006): `audit_db` (template clone)
    // backs the populated (store_opens=true) arm only; `audit_pool` backs
    // both arms — an unroutable pool for store_opens=false (no live PG
    // needed), a real one from `audit_db` otherwise.
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool> audit_pool;
    std::unique_ptr<AuditStore> audit_store;
    bool perm_grant{true};
    bool audit_should_fail{false};  // audit_fn returns false (emission did not persist)
    bool audit_should_throw{false}; // audit_fn throws (emission pipeline fault)
    std::vector<AuditCall> audit_log;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // store_opens=false constructs a wired-but-closed store (is_open()==false)
    // by pointing it at an unroutable pool, to exercise the store-down 503
    // guard — deliberately does NOT need YUZU_TEST_POSTGRES_DSN (mirrors
    // test_audit_store.cpp's "bad-path constructor" fixture).
    explicit AuthSampleHarness(bool with_store = true, bool store_opens = true) {
        if (with_store && !store_opens) {
            audit_pool.emplace(yuzu::server::pg::PgPool::Options{
                .conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1});
            audit_store = std::make_unique<AuditStore>(*audit_pool);
        } else if (with_store) {
            if (yuzu::test::pg_admin_dsn_env() == nullptr) {
                SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
            }
            audit_db.emplace(rest_audit_sample_tpl);
            INFO("[AuthSampleHarness] audit db status (blank == ok): " << audit_db->error());
            REQUIRE(audit_db->available());
            audit_pool.emplace(
                yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
            audit_store = std::make_unique<AuditStore>(*audit_pool);
            auto log = [&](const std::string& action, int64_t ts) {
                AuditEvent e;
                e.principal = "admin";
                e.principal_role = "admin";
                e.action = action;
                e.result = "success";
                e.timestamp = ts;
                audit_store->log(e);
            };
            // Auth-surface events (in window) + noise that must be excluded.
            log("auth.login", 1000);
            log("auth.login_failed", 1001);
            log("mfa.step_up.passed", 1002);
            log("session.revoke_all", 1003);
            log("instruction.execute", 1004); // noise
            log("tag.create", 1005);          // noise
        }

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            if (audit_should_throw)
                throw std::runtime_error("simulated audit pipeline fault");
            return !audit_should_fail;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/audit_store.get());
    }
};

} // namespace

TEST_CASE("auth-sample: scoped to the auth surface, noise excluded", "[pg][auth-sample][rest]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample?limit=100");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // The four auth-surface events present; the two noise events absent.
    CHECK(res->body.find("auth.login") != std::string::npos);
    CHECK(res->body.find("mfa.step_up.passed") != std::string::npos);
    CHECK(res->body.find("session.revoke_all") != std::string::npos);
    CHECK(res->body.find("instruction.execute") == std::string::npos);
    CHECK(res->body.find("tag.create") == std::string::npos);
}

TEST_CASE("auth-sample: limit is honoured", "[pg][auth-sample][rest]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample?limit=2");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // 4 auth events exist; a limit of 2 must return exactly 2. Count the per-event
    // "action": fields (format-independent of value spacing — JObj emits "k":v).
    auto count_substr = [](const std::string& hay, const std::string& needle) {
        size_t n = 0, pos = 0;
        while ((pos = hay.find(needle, pos)) != std::string::npos) {
            ++n;
            pos += needle.size();
        }
        return n;
    };
    CHECK(count_substr(res->body, "\"action\":") == 2);
}

TEST_CASE("auth-sample: exporting evidence is itself audited", "[pg][auth-sample][rest][audit]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    bool emitted = false;
    for (const auto& c : h.audit_log) {
        if (c.action == "audit.auth_sample.exported" && c.result == "success") {
            emitted = true;
            CHECK(c.detail.find("returned=") != std::string::npos);
        }
    }
    CHECK(emitted);
}

TEST_CASE("auth-sample: permission denied → 403", "[pg][auth-sample][rest][perm]") {
    AuthSampleHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/audit/auth-sample");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("auth-sample: no audit store → 503", "[auth-sample][rest]") {
    AuthSampleHarness h{/*with_store=*/false};
    auto res = h.sink.Get("/api/v1/audit/auth-sample");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// CC7.2 evidence honesty: a wired-but-closed store (DB failed to open/migrate)
// must FAIL LOUD with 503 — never a 200-empty that an auditor would read as
// "no authentication activity". Regression guard for the review High finding.
TEST_CASE("auth-sample: store wired but not open → 503, not 200-empty", "[auth-sample][rest]") {
    AuthSampleHarness h{/*with_store=*/true, /*store_opens=*/false};
    REQUIRE(h.audit_store);
    REQUIRE_FALSE(h.audit_store->is_open());
    auto res = h.sink.Get("/api/v1/audit/auth-sample");
    REQUIRE(res);
    CHECK(res->status == 503);
    // A4 envelope shape: carries a correlation_id and never an empty data set.
    CHECK(res->body.find("correlation_id") != std::string::npos);
    CHECK(res->body.find("\"total\":0") == std::string::npos);
}

TEST_CASE("auth-sample: malformed from/to → 400", "[pg][auth-sample][rest]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample?from=notanumber");
    REQUIRE(res);
    CHECK(res->status == 400);
    // Trailing junk is rejected too (strtoll-style partial parse must not pass).
    auto res2 = h.sink.Get("/api/v1/audit/auth-sample?to=123abc");
    REQUIRE(res2);
    CHECK(res2->status == 400);
}

TEST_CASE("auth-sample: inverted window from>to → 400 (Hermes L-3)", "[pg][auth-sample][rest]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample?from=2000&to=1000");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("auth-sample: malformed limit → 400 (Hermes L-2)", "[pg][auth-sample][rest]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample?limit=abc");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("auth-sample: response excludes session_id/source_ip (Hermes M-2)",
          "[pg][auth-sample][rest]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // Field set matches the sibling /api/v1/audit — no session/IP disclosure.
    CHECK(res->body.find("session_id") == std::string::npos);
    CHECK(res->body.find("source_ip") == std::string::npos);
}

TEST_CASE("auth-sample: audit-emission failure surfaces Sec-Audit-Failed (Hermes M-1)",
          "[pg][auth-sample][rest][audit]") {
    SECTION("audit_fn returns false") {
        AuthSampleHarness h;
        h.audit_should_fail = true;
        auto res = h.sink.Get("/api/v1/audit/auth-sample");
        REQUIRE(res);
        CHECK(res->status == 200); // the read still proceeds
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
    SECTION("audit_fn throws") {
        AuthSampleHarness h;
        h.audit_should_throw = true;
        auto res = h.sink.Get("/api/v1/audit/auth-sample");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
}

TEST_CASE("auth-sample: clean export does NOT set Sec-Audit-Failed", "[pg][auth-sample][rest][audit]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
}

TEST_CASE("auth-sample: response carries the sampling/recency_capped block",
          "[pg][auth-sample][rest]") {
    AuthSampleHarness h; // only 4 in-window auth events, well under the scan cap
    auto res = h.sink.Get("/api/v1/audit/auth-sample");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // Evidence-honesty signal present, and not capped for a small window.
    CHECK(res->body.find("\"sampling\":") != std::string::npos);
    CHECK(res->body.find("\"recency_capped\":false") != std::string::npos);
    CHECK(res->body.find("\"candidates_considered\":4") != std::string::npos);
}

TEST_CASE("auth-sample: scoping returns exactly the 4 auth events (count bound)",
          "[pg][auth-sample][rest]") {
    AuthSampleHarness h;
    auto res = h.sink.Get("/api/v1/audit/auth-sample?limit=100");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto count_substr = [](const std::string& hay, const std::string& needle) {
        size_t n = 0, pos = 0;
        while ((pos = hay.find(needle, pos)) != std::string::npos) {
            ++n;
            pos += needle.size();
        }
        return n;
    };
    CHECK(count_substr(res->body, "\"action\":") == 4); // not the 2 noise events
}
