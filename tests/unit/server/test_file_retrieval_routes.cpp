// file_retrieval_routes.cpp end-to-end coverage over TestRouteSink (PR1.6a,
// CC-06 server-side fix): the operator mint/list/revoke surface, the agent
// session-open/chunk/status/commit/cancel surface, the TLS gate, and the
// frozen error envelope's reason set as actually emitted on the wire.
// Exercises the REAL UploadGrantStore against Postgres (YUZU_REQUIRE_PG_DB_TPL)
// — the store has no interface seam to mock, so this is the genuine
// end-to-end path, not a store double. Each TEST_CASE opens its own
// pre-migrated clone (per the playbook's per-test-clone contract for
// store-BEHAVIOUR-plus-mutation tests) and builds a fresh sink over it —
// no shared Catch2 fixture class, since `YUZU_REQUIRE_PG_DB_TPL`'s SKIP
// must run as a direct statement in the test body, not in a constructor.

#include <catch2/catch_test_macros.hpp>

#include "file_retrieval_routes.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error — the #2057 negative test below
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"
#include "upload_grant_parsers.hpp" // kCredentialIdHexLen — the credential grammar
#include "upload_grant_store.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>

using yuzu::server::Deps;
using yuzu::server::RestApiV1;
using yuzu::server::UploadGrantListAuthorization;
using yuzu::server::UploadGrantListDecision;
using yuzu::server::UploadGrantStore;
using yuzu::server::pg::PgPool;
using yuzu::server::test::TestRouteSink;

namespace {

yuzu::test::PgTestTemplate routes_tpl{"uploadgrantroutes", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    UploadGrantStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("upload_grant routes template: store failed to migrate");
}};

/// Deps builder shared by every test case: "always admit" operator auth by
/// default, TLS on, and a clock the test controls through `*clock`. Callers
/// override individual fields on the returned struct for denial cases.
Deps make_deps(UploadGrantStore& store, const std::filesystem::path& blob_root,
               std::shared_ptr<std::int64_t> clock) {
    Deps deps;
    deps.auth_fn = [](const httplib::Request&, httplib::Response&) {
        return std::optional<yuzu::server::auth::Session>{
            yuzu::server::auth::Session{.username = "operator-1"}};
    };
    deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    deps.list_read_fn = [](const std::string&) {
        return UploadGrantListAuthorization{UploadGrantListDecision::kAdmitAll, {}};
    };
    deps.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) { return true; };
    deps.store = &store;
    deps.blob_root = blob_root;
    deps.tls_enabled = true;
    deps.now_fn = [clock]() { return *clock; };
    return deps;
}

nlohmann::json body_json(const std::unique_ptr<httplib::Response>& res) {
    REQUIRE(res != nullptr);
    auto parsed = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    return parsed;
}

std::string content_range(std::int64_t start, std::int64_t end, std::int64_t total) {
    return "bytes " + std::to_string(start) + "-" + std::to_string(end) + "/" +
          std::to_string(total);
}

std::string mint_and_open(TestRouteSink& sink, const std::string& agent_id,
                          std::int64_t declared_max_size, std::string& out_upload_id,
                          std::optional<std::int64_t> ttl_secs = std::nullopt) {
    nlohmann::json body = {{"agent_id", agent_id}, {"declared_max_size", declared_max_size}};
    if (ttl_secs)
        body["ttl_secs"] = *ttl_secs;
    auto minted = body_json(sink.dispatch("POST", "/api/v1/upload-grants", body.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    out_upload_id = opened["upload_id"].get<std::string>();
    return out_upload_id + "." + opened["session_secret"].get<std::string>();
}

} // namespace

// ── OpenAPI discoverability (A1) + the L8 doc-drift regression ──────────

namespace {

/// Minimal RestApiV1 registration used ONLY to exercise the served
/// /api/v1/openapi.json document. `register_file_retrieval_routes` (every
/// other fixture in this file) does not register that route — it is owned
/// by RestApiV1::register_routes, which server.cpp mounts on the SAME
/// httplib::Server alongside register_file_retrieval_routes. The
/// openapi.json handler is a static-string return (`openapi_spec()`) that
/// touches none of register_routes' many store/auth/audit dependencies, so
/// every one of them is safely null/empty here — no PG, no RBAC, hermetic.
/// #2057: the route is now gated `perm_fn(..., "Infrastructure", "Read")` —
/// a null (default-constructed) `PermFn` would `std::bad_function_call`
/// rather than 403, so this harness supplies an always-grant stub (the
/// negative "denied without a session" case is covered separately below).
struct OpenApiHarness {
    RestApiV1 api;
    TestRouteSink sink;

    explicit OpenApiHarness(RestApiV1::PermFn perm_fn = [](const httplib::Request&,
                                                           httplib::Response&, const std::string&,
                                                           const std::string&) { return true; }) {
        api.register_routes(sink, RestApiV1::AuthFn{}, std::move(perm_fn), RestApiV1::AuditFn{},
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr);
    }
};

} // namespace

TEST_CASE("OpenAPI doc: the removed legacy POST /api/v1/file-retrieval path is absent",
          "[server][routes][upload][openapi]") {
    // L8 (Codex): the hand-maintained OpenAPI string could silently keep
    // listing a route that no longer exists (or regain it on some future
    // revert) with nothing to catch the drift. Pin the negative fact: the
    // served document never lists the removed legacy path. Checked as a
    // JSON key (quoted, both bare and colon-terminated) so this can't
    // collide with an unrelated prose mention of the substring
    // "file-retrieval" — and confirmed by direct read of the raw OpenAPI
    // string in rest_api_v1.cpp that no such mention exists there either.
    OpenApiHarness h;
    auto res = h.sink.dispatch("GET", "/api/v1/openapi.json");
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);
    CHECK(res->body.find(R"("/file-retrieval")") == std::string::npos);
    CHECK(res->body.find("file-retrieval") == std::string::npos);
}

TEST_CASE("OpenAPI doc: the new upload-grant and plugin-config paths are present",
          "[server][routes][upload][openapi]") {
    // The other half of L8: the routes this branch ADDED must actually be
    // documented — pins the operator-facing mint/list/revoke surface plus
    // the plugin-config get/set/delete/kill-switch surface. Exact spelling
    // per rest_api_v1.cpp's "paths" object (no /api/v1 prefix), matching
    // the established test_rest_inventory_software.cpp /
    // test_rest_bundle.cpp idiom for this document.
    OpenApiHarness h;
    auto res = h.sink.dispatch("GET", "/api/v1/openapi.json");
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));
    const auto& paths = spec["paths"];

    // Upload-grant surface: operator mint/list/revoke + the agent session
    // routes (reachability of these is already exercised end-to-end
    // elsewhere in this file, e.g. "mint returns grant_id + grant_secret
    // once, 201" and "revoke: 204 then 404 on replay" — this test covers
    // only the DOCUMENT, not reachability, for that surface).
    REQUIRE(paths.contains("/upload-grants"));
    CHECK(paths["/upload-grants"].contains("post")); // mint
    CHECK(paths["/upload-grants"].contains("get"));  // list
    REQUIRE(paths.contains("/upload-grants/{grant_id}"));
    CHECK(paths["/upload-grants/{grant_id}"].contains("delete")); // revoke
    CHECK(paths.contains("/uploads"));
    CHECK(paths.contains("/uploads/{upload_id}/chunk"));
    CHECK(paths.contains("/uploads/{upload_id}"));
    CHECK(paths.contains("/uploads/{upload_id}/commit"));

    // Plugin-config surface: get/set/delete/kill-switch. Route
    // REACHABILITY (not just documentation) for this surface is already
    // covered by test_plugin_config_routes.cpp, so this test asserts the
    // document only.
    REQUIRE(paths.contains("/plugin-config"));
    CHECK(paths["/plugin-config"].contains("get"));
    REQUIRE(paths.contains("/plugin-config/{plugin}/{key}"));
    CHECK(paths["/plugin-config/{plugin}/{key}"].contains("get"));
    CHECK(paths["/plugin-config/{plugin}/{key}"].contains("put"));
    CHECK(paths["/plugin-config/{plugin}/{key}"].contains("delete"));
    CHECK(paths.contains("/plugin-config/{plugin}/{key}/secret"));
    REQUIRE(paths.contains("/plugin-config/{plugin}/kill-switch"));
    CHECK(paths["/plugin-config/{plugin}/kill-switch"].contains("get"));
    CHECK(paths["/plugin-config/{plugin}/kill-switch"].contains("put"));
}

TEST_CASE("OpenAPI doc: GET /api/v1/openapi.json is gated Infrastructure:Read (#2057)",
          "[server][routes][openapi][auth]") {
    // #2057: was unauthenticated. A denying perm_fn must refuse the request
    // with an A4-shaped body (code/message/correlation_id) — perm_fn itself
    // owns writing the denial status + body (matching every other
    // `Infrastructure:Read`-gated route in this file's sibling tests), so
    // this pins the observable outcome (denied, A4 body), not perm_fn's
    // internal mechanics.
    OpenApiHarness h{[](const httplib::Request&, httplib::Response& res, const std::string&,
                        const std::string&) {
        res.status = 403;
        res.set_content(
            yuzu::server::detail::a4_error(res, "permission denied"),
            "application/json");
        return false;
    }};
    auto res = h.sink.dispatch("GET", "/api/v1/openapi.json");
    REQUIRE(res != nullptr);
    CHECK((res->status == 401 || res->status == 403));
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"].contains("correlation_id"));
    CHECK(body["error"].contains("code"));
    CHECK(body["error"].contains("message"));
}

// ── Operator routes ─────────────────────────────────────────────────────

TEST_CASE("mint returns grant_id + grant_secret once, 201", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto res = sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump());
    REQUIRE(res != nullptr);
    CHECK(res->status == 201);
    auto j = body_json(res);
    CHECK_FALSE(j["grant_id"].get<std::string>().empty());
    CHECK(j["grant_secret"].get<std::string>().size() == 64);
}

TEST_CASE("mint denies when perm_fn refuses", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};

    auto deps = make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000));
    deps.perm_fn = [](const httplib::Request&, httplib::Response& res, const std::string&,
                      const std::string&) {
        res.status = 403;
        return false;
    };
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(sink, deps);

    auto res = sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump());
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
}

TEST_CASE("list honours kDenyAll / kAdmitAll / kAdmitScoped visibility", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    auto clock = std::make_shared<std::int64_t>(1000);

    TestRouteSink admit_all_sink;
    yuzu::server::register_file_retrieval_routes(admit_all_sink,
                                                 make_deps(store, blob_dir.path, clock));
    REQUIRE(admit_all_sink
                .dispatch("POST", "/api/v1/upload-grants",
                         nlohmann::json{{"agent_id", "agent-A"}, {"declared_max_size", 100}}.dump())
                ->status == 201);
    REQUIRE(admit_all_sink
                .dispatch("POST", "/api/v1/upload-grants",
                         nlohmann::json{{"agent_id", "agent-B"}, {"declared_max_size", 100}}.dump())
                ->status == 201);

    SECTION("kAdmitAll (default) sees everything") {
        auto res = admit_all_sink.dispatch("GET", "/api/v1/upload-grants");
        REQUIRE(res->status == 200);
        CHECK(body_json(res)["data"].size() >= 2);
    }

    SECTION("kDenyAll -> 403") {
        auto deps = make_deps(store, blob_dir.path, clock);
        deps.list_read_fn = [](const std::string&) {
            return UploadGrantListAuthorization{UploadGrantListDecision::kDenyAll, {}};
        };
        TestRouteSink deny_sink;
        yuzu::server::register_file_retrieval_routes(deny_sink, deps);
        auto res = deny_sink.dispatch("GET", "/api/v1/upload-grants");
        REQUIRE(res != nullptr);
        CHECK(res->status == 403);
    }

    SECTION("kAdmitScoped filters to the visible agent set") {
        auto deps = make_deps(store, blob_dir.path, clock);
        deps.list_read_fn = [](const std::string&) {
            return UploadGrantListAuthorization{UploadGrantListDecision::kAdmitScoped, {"agent-A"}};
        };
        TestRouteSink scoped_sink;
        yuzu::server::register_file_retrieval_routes(scoped_sink, deps);
        auto res = scoped_sink.dispatch("GET", "/api/v1/upload-grants");
        REQUIRE(res->status == 200);
        auto j = body_json(res);
        REQUIRE(j["data"].size() >= 1);
        for (auto& row : j["data"])
            CHECK(row["agent_id"] == "agent-A");
    }
}

TEST_CASE("revoke: 204 then 404 on replay", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump()));
    auto grant_id = minted["grant_id"].get<std::string>();

    auto res1 = sink.dispatch("DELETE", "/api/v1/upload-grants/" + grant_id);
    REQUIRE(res1 != nullptr);
    CHECK(res1->status == 204);

    auto res2 = sink.dispatch("DELETE", "/api/v1/upload-grants/" + grant_id);
    REQUIRE(res2 != nullptr);
    CHECK(res2->status == 404);
}

TEST_CASE("M9: revoke writes attempted -> success, and a not-found revoke writes "
         "attempted -> failure (never a dangling attempted-only row)",
         "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;

    struct AuditRow {
        std::string action, result, target_id;
    };
    std::vector<AuditRow> audits;
    auto deps = make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000));
    deps.audit_fn = [&audits](const httplib::Request&, const std::string& action,
                              const std::string& result, const std::string&,
                              const std::string& target_id, const std::string&) {
        audits.push_back({action, result, target_id});
        return true;
    };
    yuzu::server::register_file_retrieval_routes(sink, deps);

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump()));
    auto grant_id = minted["grant_id"].get<std::string>();
    audits.clear(); // drop the mint's own audit row(s) — this test is revoke-only

    auto res1 = sink.dispatch("DELETE", "/api/v1/upload-grants/" + grant_id);
    REQUIRE(res1 != nullptr);
    REQUIRE(res1->status == 204);
    REQUIRE(audits.size() == 2);
    CHECK(audits[0].action == "upload_grant.revoke");
    CHECK(audits[0].result == "attempted");
    CHECK(audits[0].target_id == grant_id);
    CHECK(audits[1].action == "upload_grant.revoke");
    CHECK(audits[1].result == "success");
    CHECK(audits[1].target_id == grant_id);

    // Replay: the store call itself now reports not-found — the pair
    // completes as attempted -> failure, never leaving the first row
    // standing alone (which would misrepresent an ORDINARY 404 as an
    // audit-persistence anomaly).
    audits.clear();
    auto res2 = sink.dispatch("DELETE", "/api/v1/upload-grants/" + grant_id);
    REQUIRE(res2 != nullptr);
    REQUIRE(res2->status == 404);
    REQUIRE(audits.size() == 2);
    CHECK(audits[0].result == "attempted");
    CHECK(audits[1].result == "failure");
    for (const auto& row : audits)
        CHECK(row.result != "success");
}

// ── Agent surface: TLS gate ──────────────────────────────────────────────

TEST_CASE("every agent route 400s tls_required when TLS is not enabled",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};

    auto deps = make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000));
    deps.tls_enabled = false; // the point of this test
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(sink, deps);

    auto assert_tls_required = [](const std::unique_ptr<httplib::Response>& res) {
        REQUIRE(res != nullptr);
        CHECK(res->status == 400);
        auto j = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(j.is_discarded());
        CHECK(j["error"]["reason"] == "tls_required");
    };

    assert_tls_required(sink.dispatch("POST", "/api/v1/uploads"));
    assert_tls_required(sink.dispatch("PUT", "/api/v1/uploads/" + std::string(32, 'a') + "/chunk"));
    assert_tls_required(sink.dispatch("GET", "/api/v1/uploads/" + std::string(32, 'a')));
    assert_tls_required(
        sink.dispatch("POST", "/api/v1/uploads/" + std::string(32, 'a') + "/commit"));
    assert_tls_required(sink.dispatch("DELETE", "/api/v1/uploads/" + std::string(32, 'a')));
}

// ── Agent surface: session open ──────────────────────────────────────────

TEST_CASE("session open: success, then a replay is grant_already_redeemed",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 12}}.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();

    auto opened = sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                {{"X-Yuzu-Upload-Grant", grant_cred}});
    REQUIRE(opened != nullptr);
    REQUIRE(opened->status == 201);
    auto oj = body_json(opened);
    CHECK_FALSE(oj["upload_id"].get<std::string>().empty());
    CHECK(oj["session_secret"].get<std::string>().size() == 64);
    CHECK(oj["offset"] == 0);

    auto replay = sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                {{"X-Yuzu-Upload-Grant", grant_cred}});
    REQUIRE(replay != nullptr);
    CHECK(replay->status == 409);
    CHECK(body_json(replay)["error"]["reason"] == "grant_already_redeemed");
}

TEST_CASE("session open with a wrong secret is grant_unknown, 401", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 12}}.dump()));
    const std::string bad_cred = minted["grant_id"].get<std::string>() + "." + std::string(64, 'f');

    auto res = sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                             {{"X-Yuzu-Upload-Grant", bad_cred}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 401);
    CHECK(body_json(res)["error"]["reason"] == "grant_unknown");
}

// ── Agent surface: chunk / status / commit / cancel ──────────────────────

TEST_CASE("chunk + commit happy path, then a wrong-hash commit is hash_mismatch and terminal",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    const std::string payload = "hello upload world!"; // 20 bytes
    std::string upload_id;
    const std::string session_cred =
        mint_and_open(sink, "agent-1", static_cast<std::int64_t>(payload.size()), upload_id);

    auto chunk_res = sink.dispatch(
        "PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload, "application/octet-stream",
        {{"X-Yuzu-Upload-Session", session_cred},
         {"Content-Range", content_range(0, static_cast<std::int64_t>(payload.size()) - 1,
                                         static_cast<std::int64_t>(payload.size()))}});
    REQUIRE(chunk_res != nullptr);
    REQUIRE(chunk_res->status == 200);
    CHECK(body_json(chunk_res)["offset"] == static_cast<std::int64_t>(payload.size()));

    auto status_res = sink.dispatch("GET", "/api/v1/uploads/" + upload_id, "", "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(status_res->status == 200);
    auto sj = body_json(status_res);
    CHECK(sj["state"] == "open");
    CHECK(sj["offset"] == static_cast<std::int64_t>(payload.size()));

    // Deliberately wrong hash — must 422 and terminate.
    auto bad_commit = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                                    nlohmann::json{{"sha256", std::string(64, '0')}}.dump(),
                                    "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(bad_commit != nullptr);
    CHECK(bad_commit->status == 422);
    CHECK(body_json(bad_commit)["error"]["reason"] == "hash_mismatch");

    // Terminal now — even a subsequent commit attempt is session_terminal.
    auto retry = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                               nlohmann::json{{"sha256", std::string(64, '0')}}.dump(),
                               "application/json", {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(retry != nullptr);
    CHECK(retry->status == 409);
    CHECK(body_json(retry)["error"]["reason"] == "session_terminal");
}

TEST_CASE("commit succeeds with the correct sha256 and returns actual_size", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    const std::string payload = "abc"; // SHA-256("abc") is a well-known test vector
    const std::string sha256_abc =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    std::string upload_id;
    const std::string session_cred =
        mint_and_open(sink, "agent-1", static_cast<std::int64_t>(payload.size()), upload_id);

    auto chunk_res =
        sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload,
                      "application/octet-stream",
                      {{"X-Yuzu-Upload-Session", session_cred}, {"Content-Range", content_range(0, 2, 3)}});
    REQUIRE(chunk_res->status == 200);

    auto commit_res = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                                    nlohmann::json{{"sha256", sha256_abc}}.dump(),
                                    "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(commit_res != nullptr);
    REQUIRE(commit_res->status == 200);
    auto cj = body_json(commit_res);
    CHECK(cj["state"] == "committed");
    CHECK(cj["actual_size"] == 3);
    CHECK(cj["sha256"] == sha256_abc);
}

TEST_CASE("unauthenticated chunk/commit/cancel requests never grow the write-lock map",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    // The lock map is a PROCESS-STATIC keyed by a client-supplied path
    // segment. It used to be acquire-then-authenticate with no erase and no
    // cap anywhere, so any well-formed-but-unauthenticated id permanently
    // added an entry — unbounded memory reachable without a credential.
    const auto before = yuzu::server::upload_write_lock_count_for_test();

    for (int i = 0; i < 50; ++i) {
        // kCredentialIdHexLen (32), not 16: a short id fails parse_credential's
        // grammar and 401s at the parse gate, which would still satisfy the
        // assertions below while never reaching the acquire-vs-authenticate
        // ordering this case exists to pin. Full-length ids drive the real path.
        const std::string fake_id(yuzu::server::upload_grant::kCredentialIdHexLen,
                                  static_cast<char>('a' + (i % 6)));
        const std::string fake_cred = fake_id + "." + std::string(64, 'f');
        const std::unordered_map<std::string, std::string> hdr{
            {"X-Yuzu-Upload-Session", fake_cred}};

        auto chunk = sink.dispatch("PUT", "/api/v1/uploads/" + fake_id + "/chunk", "x",
                                   "application/octet-stream",
                                   {{"X-Yuzu-Upload-Session", fake_cred},
                                    {"Content-Range", content_range(0, 0, 1)}});
        REQUIRE(chunk != nullptr);
        CHECK(chunk->status == 401);

        auto commit = sink.dispatch("POST", "/api/v1/uploads/" + fake_id + "/commit",
                                    nlohmann::json{{"sha256", std::string(64, '0')}}.dump(),
                                    "application/json", hdr);
        REQUIRE(commit != nullptr);
        CHECK(commit->status == 401);

        auto cancel =
            sink.dispatch("DELETE", "/api/v1/uploads/" + fake_id, "", "application/json", hdr);
        REQUIRE(cancel != nullptr);
        CHECK(cancel->status == 401);
    }

    CHECK(yuzu::server::upload_write_lock_count_for_test() == before);
}

TEST_CASE("M3: a degraded store answers 503 for the write-lock admission gate, and never "
         "allocates a lock entry for the unproven credential",
         "[server][routes][upload]") {
    // The exact defect: admit_to_write_lock used to admit on ANY outcome
    // other than kSessionUnknown, including kUnavailable — so a caller with
    // a well-formed but never-issued (upload_id, secret) pair, arriving
    // while the store's pool is exhausted or a query is failing, was
    // admitted to allocate/contend a lock AND drive a second
    // authenticate_session call once inside it. That is exactly the wrong
    // direction: a degraded store is the condition under which admitting
    // unproven credentials does the most damage.
    //
    // Genuinely exhausts a size-1 pool by holding its only lease for the
    // duration of the call, rather than mocking the store (UploadGrantStore
    // has no virtual seam) — the real path authenticate_session's
    // kReadTimeout{1500} takes, so this test's cost is that bounded ~1.5s,
    // not a flaky timing assumption.
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    const auto before = yuzu::server::upload_write_lock_count_for_test();

    // Hold the pool's ONLY lease for the duration of the routed calls below,
    // so authenticate_session's try_acquire_for(kReadTimeout) inside them
    // times out and returns kUnavailable — a real degraded-store condition,
    // not a simulated one.
    auto held_lease = pool.acquire();
    REQUIRE(held_lease);

    // kCredentialIdHexLen (32), not 16 — a short id is rejected by
    // parse_credential's grammar and 401s BEFORE authenticate_session is
    // ever called, so the degraded-store path asserted below (kUnavailable
    // -> 503) never executed and this case failed claiming a 401-vs-503
    // mismatch it had itself created.
    const std::string fake_id(yuzu::server::upload_grant::kCredentialIdHexLen, 'd');
    const std::string fake_cred = fake_id + "." + std::string(64, 'f');
    const std::unordered_map<std::string, std::string> hdr{
        {"X-Yuzu-Upload-Session", fake_cred}};

    auto chunk = sink.dispatch("PUT", "/api/v1/uploads/" + fake_id + "/chunk", "x",
                               "application/octet-stream",
                               {{"X-Yuzu-Upload-Session", fake_cred},
                                {"Content-Range", content_range(0, 0, 1)}});
    REQUIRE(chunk != nullptr);
    CHECK(chunk->status == 503); // NOT 401 — the store's degraded state is real,
                                 // never mistaken for "no such session"

    auto cancel = sink.dispatch("DELETE", "/api/v1/uploads/" + fake_id, "", "application/json", hdr);
    REQUIRE(cancel != nullptr);
    CHECK(cancel->status == 503);

    held_lease.reset(); // release before the store/pool destruct

    CHECK(yuzu::server::upload_write_lock_count_for_test() == before);
}

TEST_CASE("a completed authenticated upload leaves no write-lock entry behind",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    // The authenticated path must be bounded too: eviction is what makes the
    // map's lifetime "while someone holds it" rather than "forever".
    const auto before = yuzu::server::upload_write_lock_count_for_test();

    const std::string payload = "abc";
    const std::string sha256_abc =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    std::string upload_id;
    const std::string session_cred = mint_and_open(sink, "agent-1", 4096, upload_id);

    auto chunk_res = sink.dispatch(
        "PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload, "application/octet-stream",
        {{"X-Yuzu-Upload-Session", session_cred}, {"Content-Range", content_range(0, 2, 3)}});
    REQUIRE(chunk_res->status == 200);

    auto commit_res = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                                    nlohmann::json{{"sha256", sha256_abc}}.dump(),
                                    "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(commit_res->status == 200);

    CHECK(yuzu::server::upload_write_lock_count_for_test() == before);
}

TEST_CASE("commit succeeds when the upload is SMALLER than the grant's declared_max_size",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    // Every other commit test in this file mints `declared_max_size ==
    // payload.size()`, which is exactly why the `!=` size check survived: the
    // field is a CAP, and an operator minting a generous grant for a file
    // whose final size is not known up front is the ORDINARY case. Under the
    // old equality test this 422'd, cancelled the session and deleted the
    // blob — with the grant already redeemed, so there was no retry.
    const std::string payload = "abc";
    const std::string sha256_abc =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    std::string upload_id;
    const std::string session_cred =
        mint_and_open(sink, "agent-1", /*declared_max_size=*/4096, upload_id);

    auto chunk_res = sink.dispatch(
        "PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload, "application/octet-stream",
        {{"X-Yuzu-Upload-Session", session_cred}, {"Content-Range", content_range(0, 2, 3)}});
    REQUIRE(chunk_res != nullptr);
    REQUIRE(chunk_res->status == 200);

    auto commit_res = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                                    nlohmann::json{{"sha256", sha256_abc}}.dump(),
                                    "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(commit_res != nullptr);
    REQUIRE(commit_res->status == 200);
    auto cj = body_json(commit_res);
    CHECK(cj["state"] == "committed");
    CHECK(cj["actual_size"] == 3); // the ACTUAL size, not the declared cap
    CHECK(cj["sha256"] == sha256_abc);
}

TEST_CASE("chunk offset_mismatch carries the authoritative offset", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    std::string upload_id;
    const std::string session_cred = mint_and_open(sink, "agent-1", 100, upload_id);

    auto res = sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", "xxxxx",
                             "application/octet-stream",
                             {{"X-Yuzu-Upload-Session", session_cred},
                              {"Content-Range", content_range(5, 9, 100)}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 409);
    auto j = body_json(res);
    CHECK(j["error"]["reason"] == "offset_mismatch");
    CHECK(j["error"]["offset"] == 0);
}

TEST_CASE("an oversized chunk is rejected by its Content-Range alone (no large body sent)",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100000000}}.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    const std::string upload_id = opened["upload_id"].get<std::string>();
    const std::string session_cred = upload_id + "." + opened["session_secret"].get<std::string>();
    const std::int64_t chunk_max = opened["chunk_max_bytes"].get<std::int64_t>();

    // The cap check runs against the PARSED Content-Range before the body
    // length is even compared — a tiny actual body proves the route
    // rejects on the declared range alone, no multi-megabyte payload needed.
    auto res = sink.dispatch(
        "PUT", "/api/v1/uploads/" + upload_id + "/chunk", "x", "application/octet-stream",
        {{"X-Yuzu-Upload-Session", session_cred},
         {"Content-Range", content_range(0, chunk_max, chunk_max + 1)}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 413);
    CHECK(body_json(res)["error"]["reason"] == "chunk_too_large");
}

TEST_CASE("exceeding the grant's declared size terminates the session, size_exceeded",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    std::string upload_id;
    const std::string session_cred = mint_and_open(sink, "agent-1", 10, upload_id);

    const std::string payload(20, 'z'); // declared max is only 10
    auto res = sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload,
                             "application/octet-stream",
                             {{"X-Yuzu-Upload-Session", session_cred},
                              {"Content-Range", content_range(0, 19, 20)}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 413);
    CHECK(body_json(res)["error"]["reason"] == "size_exceeded");

    auto status_res = sink.dispatch("GET", "/api/v1/uploads/" + upload_id, "", "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(status_res->status == 200);
    CHECK(body_json(status_res)["state"] == "cancelled");
}

TEST_CASE("cancel discards the partial blob and reports 204", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    const std::string upload_id = opened["upload_id"].get<std::string>();
    const std::string session_cred = upload_id + "." + opened["session_secret"].get<std::string>();

    auto chunk_res = sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", "abcde",
                                   "application/octet-stream",
                                   {{"X-Yuzu-Upload-Session", session_cred},
                                    {"Content-Range", content_range(0, 4, 100)}});
    REQUIRE(chunk_res->status == 200);
    auto blob_path = blob_dir.path / "standard" / minted["grant_id"].get<std::string>();
    CHECK(std::filesystem::exists(blob_path));

    auto cancel_res = sink.dispatch("DELETE", "/api/v1/uploads/" + upload_id, "", "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(cancel_res != nullptr);
    CHECK(cancel_res->status == 204);
    CHECK_FALSE(std::filesystem::exists(blob_path));

    auto second = sink.dispatch("DELETE", "/api/v1/uploads/" + upload_id, "", "application/json",
                                {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(second != nullptr);
    CHECK(second->status == 409);
    CHECK(body_json(second)["error"]["reason"] == "session_terminal");
}

TEST_CASE("any request after expiry is 410 expired, even a status poll", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    auto clock = std::make_shared<std::int64_t>(1000);
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(sink, make_deps(store, blob_dir.path, clock));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}, {"ttl_secs", 10}}
            .dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    const std::string upload_id = opened["upload_id"].get<std::string>();
    const std::string session_cred = upload_id + "." + opened["session_secret"].get<std::string>();

    *clock = opened["expires_at"].get<std::int64_t>() + 1; // one second past expiry

    auto res = sink.dispatch("GET", "/api/v1/uploads/" + upload_id, "", "application/json",
                             {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 410);
    CHECK(body_json(res)["error"]["reason"] == "expired");
}
