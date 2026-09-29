/**
 * test_rest_offload_targets.cpp — HTTP-level coverage for the
 * /api/v1/offload-targets surface added in issue #255 (Phase 8.3).
 *
 * Mirrors test_rest_response_templates.cpp: register OffloadRoutes against
 * an in-process TestRouteSink and dispatch synthesised requests directly
 * into the captured handlers — no socket, no acceptor thread, TSan-safe.
 *
 * Coverage:
 *   - GET list returns empty array initially
 *   - POST creates target (201 + id)
 *   - GET list redacts auth_credential (never returned)
 *   - GET /:id returns single target
 *   - GET /:id 404 on missing
 *   - DELETE removes the target + audit event
 *   - DELETE 404 on missing
 *   - POST 400 on missing required fields
 *   - POST 400 on invalid JSON
 *   - POST 400 on bad URL scheme
 *   - 403 path: perm_fn denies
 *   - 503 path: null offload store
 */

#include "offload_routes.hpp"
#include "offload_target_store.hpp"
#include "test_offload_target_store_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::test::OffloadTargetStorePg;

namespace {

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

/// REST harness for OffloadRoutes.
///
/// **`store` is PG-backed (ADR-0059)** — `OffloadTargetStorePg` (see
/// test_offload_target_store_pg_helper.hpp) owns the ephemeral database +
/// FileKeyProvider + SecretCodec + PgPool + OffloadTargetStore chain and
/// SKIPs the whole TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset. Declared
/// as `std::optional` (not constructed) for the `with_store=false` harness
/// mode below, matching the SQLite-era `store` unique_ptr's optionality.
///
/// **`auth_fn` is captured but ignored** by the production
/// `OffloadRoutes::register_routes` overload — same shape as sibling
/// routes (`webhook_routes`, `notification_routes`). The middleware
/// layer in production runs auth before the route is dispatched; tests
/// gate access via `perm_fn`. Do not add tests asserting `auth_fn`
/// behaviour through this harness.
struct OffloadHarness {
    yuzu::server::test::TestRouteSink sink;
    std::optional<OffloadTargetStorePg> store;
    bool perm_grant{true};
    std::vector<AuditRecord> audit_log;
    OffloadRoutes routes;

    explicit OffloadHarness(bool with_store = true) {
        if (with_store) {
            store.emplace();
            REQUIRE(store->get()->is_open());
        }

        auto auth_fn = [](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string&, const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& ti, const std::string& d) -> bool {
            audit_log.push_back({a, r, tt, ti, d});
            return true;
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn,
                               store ? store->get() : nullptr);
    }
};

} // namespace

TEST_CASE("REST offload-targets: list empty", "[rest][offload][pg]") {
    OffloadHarness h;
    auto res = h.sink.Get("/api/v1/offload-targets");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("offload_targets"));
    CHECK(j["offload_targets"].is_array());
    CHECK(j["offload_targets"].empty());
}

TEST_CASE("REST offload-targets: create returns 201 and id", "[rest][offload][pg]") {
    OffloadHarness h;
    nlohmann::json body = {{"name", "siem-primary"},
                           {"url", "https://siem.example.com/ingest"},
                           {"auth_type", "bearer"},
                           {"auth_credential", "token-secret"},
                           {"event_types", "execution.completed"},
                           {"batch_size", 1}};

    auto res = h.sink.Post("/api/v1/offload-targets", body.dump());
    REQUIRE(res);
    CHECK(res->status == 201);

    auto j = nlohmann::json::parse(res->body);
    CHECK(j["status"] == "created");
    CHECK(j["id"].get<int64_t>() > 0);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "offload_target.create");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail == "siem-primary");
}

TEST_CASE("REST offload-targets: list redacts auth_credential", "[rest][offload][pg][security]") {
    OffloadHarness h;
    nlohmann::json body = {{"name", "secret-bearer"},
                           {"url", "https://x.example.com/h"},
                           {"auth_type", "bearer"},
                           {"auth_credential", "MUST-NOT-LEAK"},
                           {"event_types", "*"}};
    auto post = h.sink.Post("/api/v1/offload-targets", body.dump());
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["id"].get<int64_t>();

    // GET list — no auth_credential field, secret string absent from
    // anywhere in the body.
    auto list_res = h.sink.Get("/api/v1/offload-targets");
    REQUIRE(list_res);
    CHECK(list_res->status == 200);
    auto j = nlohmann::json::parse(list_res->body);
    REQUIRE(j["offload_targets"].size() == 1);
    CHECK_FALSE(j["offload_targets"][0].contains("auth_credential"));
    CHECK(list_res->body.find("MUST-NOT-LEAK") == std::string::npos);

    // GET /:id — same guarantee. (sec-INFO9)
    auto one = h.sink.Get("/api/v1/offload-targets/" + std::to_string(id));
    REQUIRE(one);
    CHECK(one->status == 200);
    auto jone = nlohmann::json::parse(one->body);
    CHECK_FALSE(jone.contains("auth_credential"));
    CHECK(one->body.find("MUST-NOT-LEAK") == std::string::npos);

    // GET /:id/deliveries — empty list, but verify the secret can't
    // leak through this surface either. (sec-INFO9)
    auto del = h.sink.Get("/api/v1/offload-targets/" + std::to_string(id) + "/deliveries");
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(del->body.find("MUST-NOT-LEAK") == std::string::npos);
}

TEST_CASE("REST offload-targets: rejects CRLF in auth_credential",
          "[rest][offload][pg][security]") {
    OffloadHarness h;
    // Bearer-type credential with embedded CRLF — would inject extra
    // HTTP headers on the outbound POST. Must be rejected at create.
    nlohmann::json body = {{"name", "evil"},
                           {"url", "https://x.example.com/h"},
                           {"auth_type", "bearer"},
                           {"auth_credential", "tok\r\nX-Evil: 1"}};
    auto res = h.sink.Post("/api/v1/offload-targets", body.dump());
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "offload_target.create");
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST offload-targets: GET /:id 404 on int64 overflow",
          "[rest][offload][pg]") {
    OffloadHarness h;
    // 21-digit integer overflows int64; std::stoll throws out_of_range
    // pre-fix. Post-fix the route returns 404 cleanly.
    auto res = h.sink.Get("/api/v1/offload-targets/999999999999999999999");
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("REST offload-targets: GET /:id/deliveries clamps limit",
          "[rest][offload][pg]") {
    OffloadHarness h;
    auto post = h.sink.Post("/api/v1/offload-targets",
                            R"({"name":"limit-test","url":"https://x.example.com/h"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["id"].get<int64_t>();

    // Out-of-range limit is silently clamped, not rejected — the response
    // is 200 with whatever rows exist (none here).
    auto res = h.sink.Get("/api/v1/offload-targets/" + std::to_string(id) +
                          "/deliveries?limit=2147483647");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["deliveries"].is_array());
    CHECK(j["deliveries"].empty());
}

TEST_CASE("REST offload-targets: GET /:id 200 then 404", "[rest][offload][pg]") {
    OffloadHarness h;
    auto post = h.sink.Post("/api/v1/offload-targets",
                            R"({"name":"one","url":"https://x.example.com/h"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["id"].get<int64_t>();

    auto ok = h.sink.Get("/api/v1/offload-targets/" + std::to_string(id));
    REQUIRE(ok);
    CHECK(ok->status == 200);
    auto j = nlohmann::json::parse(ok->body);
    CHECK(j["name"] == "one");
    CHECK_FALSE(j.contains("auth_credential"));

    auto missing = h.sink.Get("/api/v1/offload-targets/99999");
    REQUIRE(missing);
    CHECK(missing->status == 404);
}

TEST_CASE("REST offload-targets: DELETE removes and audits", "[rest][offload][pg]") {
    OffloadHarness h;
    auto post = h.sink.Post("/api/v1/offload-targets",
                            R"({"name":"doomed","url":"https://x.example.com/h"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["id"].get<int64_t>();
    h.audit_log.clear();

    auto del = h.sink.Delete("/api/v1/offload-targets/" + std::to_string(id));
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(nlohmann::json::parse(del->body)["status"] == "deleted");

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "offload_target.delete");
    CHECK(h.audit_log[0].result == "success");

    // Second delete: 404
    auto del2 = h.sink.Delete("/api/v1/offload-targets/" + std::to_string(id));
    REQUIRE(del2);
    CHECK(del2->status == 404);
}

TEST_CASE("REST offload-targets: POST 400 on missing fields", "[rest][offload][pg]") {
    OffloadHarness h;
    auto res = h.sink.Post("/api/v1/offload-targets", R"({"url":"https://x.example.com/h"})");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST offload-targets: POST 400 on invalid JSON", "[rest][offload][pg]") {
    OffloadHarness h;
    auto res = h.sink.Post("/api/v1/offload-targets", "{not-json");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST offload-targets: POST 400 on bad URL scheme",
          "[rest][offload][pg][security]") {
    OffloadHarness h;
    auto res = h.sink.Post("/api/v1/offload-targets",
                           R"({"name":"bad","url":"ftp://evil/h"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "offload_target.create");
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST offload-targets: POST 400 (not 500) on type-mismatched field",
          "[rest][offload][pg]") {
    OffloadHarness h;
    // batch_size as a string throws nlohmann::json::type_error out of
    // body.value() — must be a caller-mistake 400, never an unhandled 500.
    auto res = h.sink.Post(
        "/api/v1/offload-targets",
        R"({"name":"x","url":"https://x.example.com/h","batch_size":"not-an-int"})");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST offload-targets: POST 400 on unrecognized auth_type",
          "[rest][offload][pg]") {
    OffloadHarness h;
    auto res = h.sink.Post(
        "/api/v1/offload-targets",
        R"({"name":"x","url":"https://x.example.com/h","auth_type":"bearre"})");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST offload-targets: 403 when perm_fn denies", "[rest][offload][pg][rbac]") {
    OffloadHarness h;
    h.perm_grant = false;

    auto get = h.sink.Get("/api/v1/offload-targets");
    REQUIRE(get);
    CHECK(get->status == 403);

    auto post = h.sink.Post("/api/v1/offload-targets",
                            R"({"name":"x","url":"https://x.example.com/h"})");
    REQUIRE(post);
    CHECK(post->status == 403);
}

TEST_CASE("REST offload-targets: 503 when store is null", "[rest][offload]") {
    OffloadHarness h(/*with_store=*/false);

    auto res = h.sink.Get("/api/v1/offload-targets");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST offload-targets: GET /:id/deliveries empty list",
          "[rest][offload][pg]") {
    OffloadHarness h;
    auto post = h.sink.Post("/api/v1/offload-targets",
                            R"({"name":"d","url":"https://x.example.com/h"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["id"].get<int64_t>();

    auto res = h.sink.Get("/api/v1/offload-targets/" + std::to_string(id) + "/deliveries");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("deliveries"));
    CHECK(j["deliveries"].is_array());
    CHECK(j["deliveries"].empty());
}

TEST_CASE("REST offload-targets: GET /:id/deliveries 404 on missing target",
          "[rest][offload][pg]") {
    OffloadHarness h;
    // No target created — /deliveries on a non-existent id must 404
    // rather than 200 + empty array (HP-2 from Gate 4 happy-path).
    auto res = h.sink.Get("/api/v1/offload-targets/99999/deliveries");
    REQUIRE(res);
    CHECK(res->status == 404);
}
