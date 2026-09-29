/**
 * test_webhook_routes.cpp — HTTP-level coverage for the /api/webhooks
 * surface (ADR-0057).
 *
 * Mirrors test_rest_offload_targets.cpp: register WebhookRoutes against an
 * in-process TestRouteSink and dispatch synthesised requests directly into
 * the captured handlers — no socket, no acceptor thread, TSan-safe.
 *
 * Filed against gov Gate 3 quality-engineer's finding: WebhookStore's
 * Postgres migration (ADR-0057) added a genuinely new 400-vs-503-vs-404
 * classification at this REST layer with no route-handler-level test —
 * store-unit coverage of WebhookWriteError does not prove the ROUTE maps
 * it correctly, which is itself new code in this migration.
 *
 * [pg]-tagged: WebhookStore is Postgres-backed post-migration, so every
 * TEST_CASE here needs YUZU_TEST_POSTGRES_DSN (skip-if-unset, per
 * WebhookStorePg's own posture).
 *
 * Coverage:
 *   - GET list empty array initially, has_secret field present
 *   - POST creates webhook (200 + id), has_secret reflects secret presence
 *   - POST 400 on invalid URL scheme
 *   - POST 400 on invalid JSON
 *   - DELETE removes the webhook + audit event
 *   - DELETE 404 on missing
 *   - 403 path: perm_fn denies (both read and write routes)
 *   - 503 path: null webhook store (list/create/delete/deliveries)
 *   - the invalid_url failure-path audit_fn detail is distinct from a
 *     store/db failure's (gov Gate 4 consistency-auditor's fix) — the
 *     store_unavailable/db_error arms of audit_detail_for() are NOT
 *     independently exercised here (would need a pool-exhaustion/
 *     disconnect-mid-call fixture; gov Gate 3 quality-engineer, PR #3563
 *     full-PR review — this file previously overclaimed full coverage of
 *     all three WebhookWriteError arms)
 *   - webhook.create/webhook.delete audit rows carry the URL (create:
 *     success only; delete: a best-effort pre-delete snapshot, matching
 *     offload_routes.cpp's "compliance F-3" precedent), and every REST
 *     failure branch (invalid JSON, missing url, invalid_url, not-found)
 *     is now audited, not just the success/db-error paths (gov Gate 2/4/5,
 *     PR #3563 full-PR review)
 */

#include "test_webhook_store_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "webhook_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

/// REST harness for WebhookRoutes. Member order: `store` (a
/// yuzu::test::WebhookStorePg value member) must precede `routes`/`sink`
/// so the store outlives every handler that captures a raw pointer into
/// it — same discipline test_webhook_store_pg_helper.hpp's other consumers
/// (EventSinkScope) already follow.
struct WebhookRouteHarness {
    yuzu::test::WebhookStorePg store;
    bool perm_grant{true};
    std::vector<AuditRecord> audit_log;
    yuzu::server::test::TestRouteSink sink;
    WebhookRoutes routes;

    explicit WebhookRouteHarness(bool with_store = true) {
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
        auto emit_event_fn = [](const std::string&, const httplib::Request&,
                                const nlohmann::json&, const nlohmann::json&) {};

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_event_fn,
                               with_store ? store.get() : nullptr);
    }
};

} // namespace

TEST_CASE("REST webhooks[pg]: list empty", "[rest][webhook][pg]") {
    WebhookRouteHarness h;
    auto res = h.sink.Get("/api/webhooks");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("webhooks"));
    CHECK(j["webhooks"].is_array());
    CHECK(j["webhooks"].empty());
}

TEST_CASE("REST webhooks[pg]: create returns 200, id, and has_secret", "[rest][webhook][pg]") {
    WebhookRouteHarness h;
    nlohmann::json body = {{"url", "https://example.com/hook"},
                           {"event_types", "agent.registered"},
                           {"secret", "s3cret"}};

    auto res = h.sink.Post("/api/webhooks", body.dump());
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    CHECK(j["status"] == "created");
    CHECK(j["id"].get<int64_t>() > 0);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "webhook.create");
    CHECK(h.audit_log[0].result == "success");
    // gov Gate 2 security-guardian / Gate 4 consistency-auditor (PR #3563
    // full-PR review): the audit detail must carry the URL, not just the
    // id — a compromise-and-cleanup attacker must not be able to erase the
    // only durable record of where data was exfiltrated to.
    CHECK(h.audit_log[0].detail == "https://example.com/hook");

    auto list_res = h.sink.Get("/api/webhooks");
    REQUIRE(list_res);
    auto lj = nlohmann::json::parse(list_res->body);
    REQUIRE(lj["webhooks"].size() == 1);
    CHECK(lj["webhooks"][0]["has_secret"] == true);
    CHECK_FALSE(lj["webhooks"][0].contains("secret"));
    CHECK(list_res->body.find("s3cret") == std::string::npos);
}

TEST_CASE("REST webhooks[pg]: create without a secret sets has_secret=false",
         "[rest][webhook][pg]") {
    WebhookRouteHarness h;
    nlohmann::json body = {{"url", "https://example.com/hook"}, {"event_types", "*"}};
    auto res = h.sink.Post("/api/webhooks", body.dump());
    REQUIRE(res);
    CHECK(res->status == 200);

    auto list_res = h.sink.Get("/api/webhooks");
    REQUIRE(list_res);
    auto lj = nlohmann::json::parse(list_res->body);
    REQUIRE(lj["webhooks"].size() == 1);
    CHECK(lj["webhooks"][0]["has_secret"] == false);
}

TEST_CASE("REST webhooks[pg]: POST 400 on invalid URL scheme, audits invalid_url detail",
         "[rest][webhook][pg][security]") {
    WebhookRouteHarness h;
    auto res = h.sink.Post("/api/webhooks", R"({"url":"ftp://evil/h"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "webhook.create");
    CHECK(h.audit_log[0].result == "failure");
    // gov Gate 4 consistency-auditor: the audit detail must distinguish
    // invalid_url from a store/db failure, never collapse to one literal.
    CHECK(h.audit_log[0].detail == "invalid_url");
}

TEST_CASE("REST webhooks[pg]: POST 400 on missing url, and audits it",
         "[rest][webhook][pg]") {
    // gov Gate 5 chaos-injector CH-3 (PR #3563 full-PR review): this
    // branch previously skipped audit_fn entirely — an asymmetry with the
    // invalid_url branch a few lines away, which WAS audited.
    WebhookRouteHarness h;
    auto res = h.sink.Post("/api/webhooks", R"({"event_types":"*"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "webhook.create");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].detail == "url_required");
}

TEST_CASE("REST webhooks[pg]: POST 400 on invalid JSON, and audits it",
         "[rest][webhook][pg]") {
    // gov Gate 5 chaos-injector CH-3 (PR #3563 full-PR review): same
    // asymmetry as the missing-url case above.
    WebhookRouteHarness h;
    auto res = h.sink.Post("/api/webhooks", "{not-json");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "webhook.create");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].detail == "invalid_json");
}

TEST_CASE("REST webhooks[pg]: DELETE removes and audits, carrying the pre-delete URL snapshot",
         "[rest][webhook][pg]") {
    WebhookRouteHarness h;
    auto post = h.sink.Post("/api/webhooks", R"({"url":"https://example.com/hook"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["id"].get<int64_t>();
    h.audit_log.clear();

    auto del = h.sink.Delete("/api/webhooks/" + std::to_string(id));
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(nlohmann::json::parse(del->body)["status"] == "deleted");

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "webhook.delete");
    CHECK(h.audit_log[0].result == "success");
    // gov Gate 2/4/5 (PR #3563 full-PR review): the pre-delete
    // WebhookStore::get(id) snapshot must land in the audit detail — a
    // compromise-and-cleanup attacker who deletes the webhook must not
    // erase the only durable record of where the data was going.
    CHECK(h.audit_log[0].detail == "https://example.com/hook");

    // Second delete: 404, and — as of this fix round — audited too (this
    // branch previously had no audit_fn call at all, an asymmetry with the
    // invalid_url/store-unavailable branches that WERE audited).
    auto del2 = h.sink.Delete("/api/webhooks/" + std::to_string(id));
    REQUIRE(del2);
    CHECK(del2->status == 404);
    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[1].action == "webhook.delete");
    CHECK(h.audit_log[1].result == "failure");
    CHECK(h.audit_log[1].detail == "not_found");
}

TEST_CASE("REST webhooks[pg]: DELETE 404 on missing id, and audits it",
         "[rest][webhook][pg]") {
    WebhookRouteHarness h;
    auto res = h.sink.Delete("/api/webhooks/999999");
    REQUIRE(res);
    CHECK(res->status == 404);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "webhook.delete");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].detail == "not_found");
}

TEST_CASE("REST webhooks[pg]: 403 when perm_fn denies (read and write)",
         "[rest][webhook][pg][rbac]") {
    WebhookRouteHarness h;
    h.perm_grant = false;

    auto get = h.sink.Get("/api/webhooks");
    REQUIRE(get);
    CHECK(get->status == 403);

    auto post = h.sink.Post("/api/webhooks", R"({"url":"https://example.com/hook"})");
    REQUIRE(post);
    CHECK(post->status == 403);

    auto del = h.sink.Delete("/api/webhooks/1");
    REQUIRE(del);
    CHECK(del->status == 403);
}

TEST_CASE("REST webhooks: 503 when store is null (list/create/delete/deliveries)",
         "[rest][webhook]") {
    // Deliberately NOT [pg]-tagged / does not construct WebhookStorePg — a
    // null-store harness needs no Postgres at all, matching
    // test_rest_offload_targets.cpp's equivalent case.
    yuzu::server::test::TestRouteSink sink;
    WebhookRoutes routes;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return std::nullopt; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };
    auto emit_event_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                            const nlohmann::json&) {};
    routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_event_fn, nullptr);

    auto get = sink.Get("/api/webhooks");
    REQUIRE(get);
    CHECK(get->status == 503);

    auto post = sink.Post("/api/webhooks", R"({"url":"https://example.com/hook"})");
    REQUIRE(post);
    CHECK(post->status == 503);

    auto del = sink.Delete("/api/webhooks/1");
    REQUIRE(del);
    CHECK(del->status == 503);

    auto deliveries = sink.Get("/api/webhooks/1/deliveries");
    REQUIRE(deliveries);
    CHECK(deliveries->status == 503);
}

TEST_CASE("REST webhooks[pg]: GET /:id/deliveries empty list", "[rest][webhook][pg]") {
    WebhookRouteHarness h;
    auto post = h.sink.Post("/api/webhooks", R"({"url":"https://example.com/hook"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["id"].get<int64_t>();

    auto res = h.sink.Get("/api/webhooks/" + std::to_string(id) + "/deliveries");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("deliveries"));
    CHECK(j["deliveries"].is_array());
    CHECK(j["deliveries"].empty());
}
