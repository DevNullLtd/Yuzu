/// @file test_tag_routes.cpp
/// HTTP-level coverage for the 4-route Tags API (#2542 PR-11) — driven
/// in-process through TestRouteSink (no httplib acceptor, #438), mirroring
/// test_custom_properties_routes.cpp's / test_schedule_routes.cpp's Harness
/// shape.
///
/// Split into two Harnesses:
///   - `MockHarness` (no Postgres needed): registration shape, the
///     GET/POST-query gate pin (`perm_fn` Tag:Read), and the auth-then-store
///     ordering on POST /set and /delete (`auth_fn` denial 401s before the
///     null-store check ever runs; an ALLOWED auth with a null store then
///     503s) — every case here returns before `deps.store` (a concrete
///     `TagStore*`, no virtual seam) would be dereferenced past the null
///     check.
///   - `PgHarness` (real `TagStore` via the shared `TagStorePg` helper,
///     `[pg]`): everything past the null-store check on /set and /delete
///     needs a real, non-null store even to prove GATE ORDERING (the
///     null-check is `!deps.store` only — no `is_open()` — so a real but
///     never-migrated store would still pass it, but using the real
///     migrated fixture throughout keeps this file's PG-vs-not split
///     aligned with `TagStorePg`'s own SKIP-if-no-DSN contract instead of
///     hand-rolling a second one). Covers: `deny_service_scoped_tag_
///     mutation_fn` firing BEFORE `scoped_perm_fn` (#3289 TOCTOU guard
///     ordering), `scoped_perm_fn`'s exact (type, op, agent_id) per route,
///     the two `ServerImpl`-side-effect closures
///     (`ensure_service_management_group_fn` on `key=="service"`,
///     `push_asset_tags_to_agent_fn` on a structured-category key), the
///     audit-row asymmetry `tag_routes.hpp` documents, and
///     a genuine happy-path round-trip for all 4 routes.

#include "tag_routes.hpp"
#include "test_route_sink.hpp"

#include "test_tag_store_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
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

struct DenyCall {
    std::string action, agent_id, key;
};

// ── MockHarness: no Postgres needed ─────────────────────────────────────────

/// `store` defaults to null — every case here relies on a route returning
/// (401/403/503) before `deps.store` would be dereferenced.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct MockHarness {
    TagStore* store{nullptr};

    bool auth_allow{true};
    std::string auth_username{"tester"};
    int auth_fn_calls{0};

    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        tag::Deps deps;
        deps.store = store;
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            ++auth_fn_calls;
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
        deps.scoped_perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                                 const std::string&, const std::string&) { return true; };
        deps.deny_service_scoped_tag_mutation_fn =
            [](const httplib::Request&, httplib::Response&, const std::string&,
               const std::string&, const std::string&) { return false; };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
        deps.ensure_service_management_group_fn = [](const std::string&) {};
        deps.push_asset_tags_to_agent_fn = [](const std::string&) {};
        tag::register_tag_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("tag_routes: registers exactly 4 routes", "[server][routes][tag_routes]") {
    MockHarness h;
    h.wire();
    CHECK(h.sink.route_count() == 4);
}

// ── Gate pinning (no Postgres needed) ───────────────────────────────────────

TEST_CASE("tag_routes: GET /api/tags gates on Tag:Read, and a null/closed store 503s "
          "after",
          "[server][routes][tag_routes]") {
    MockHarness h; // store stays null
    h.wire();
    auto r = h.sink.Get("/api/tags?agent_id=agent-1");
    REQUIRE(r);
    CHECK(h.last_perm_type == "Tag");
    CHECK(h.last_perm_op == "Read");
    CHECK(r->status == 503);
}

TEST_CASE("tag_routes: GET /api/tags -- a perm_fn denial 403s before the store is touched",
          "[server][routes][tag_routes]") {
    MockHarness h;
    h.perm_allow = false;
    h.wire();
    auto r = h.sink.Get("/api/tags?agent_id=agent-1");
    REQUIRE(r);
    CHECK(r->status == 403);
}

TEST_CASE("tag_routes: POST /api/tags/query gates on Tag:Read, and a null store 503s after",
          "[server][routes][tag_routes]") {
    MockHarness h; // store stays null
    h.wire();
    auto r = h.sink.Post("/api/tags/query", R"({"key":"role"})");
    REQUIRE(r);
    CHECK(h.last_perm_type == "Tag");
    CHECK(h.last_perm_op == "Read");
    CHECK(r->status == 503);
}

TEST_CASE("tag_routes: POST /api/tags/set -- auth_fn is called BEFORE the null-store check; "
          "a denied auth never touches the store",
          "[server][routes][tag_routes]") {
    MockHarness h; // store stays null
    h.auth_allow = false;
    h.wire();
    auto r = h.sink.Post("/api/tags/set", R"({"agent_id":"agent-1","key":"role","value":"x"})");
    REQUIRE(r);
    CHECK(r->status == 401);
    CHECK(h.auth_fn_calls == 1);
    CHECK(h.audits.empty());
}

TEST_CASE("tag_routes: POST /api/tags/set -- an allowed auth with a null store 503s, "
          "past auth but before any body parsing/gate",
          "[server][routes][tag_routes]") {
    MockHarness h; // store stays null
    h.wire();
    auto r = h.sink.Post("/api/tags/set", R"({"agent_id":"agent-1","key":"role","value":"x"})");
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(h.auth_fn_calls == 1);
}

TEST_CASE("tag_routes: POST /api/tags/delete -- auth_fn is called BEFORE the null-store "
          "check; a denied auth never touches the store",
          "[server][routes][tag_routes]") {
    MockHarness h; // store stays null
    h.auth_allow = false;
    h.wire();
    auto r = h.sink.Post("/api/tags/delete", R"({"agent_id":"agent-1","key":"role"})");
    REQUIRE(r);
    CHECK(r->status == 401);
    CHECK(h.auth_fn_calls == 1);
}

TEST_CASE("tag_routes: POST /api/tags/delete -- an allowed auth with a null store 503s",
          "[server][routes][tag_routes]") {
    MockHarness h; // store stays null
    h.wire();
    auto r = h.sink.Post("/api/tags/delete", R"({"agent_id":"agent-1","key":"role"})");
    REQUIRE(r);
    CHECK(r->status == 503);
}

// ── PG-backed: real TagStore via the shared TagStorePg helper ──────────────

namespace {

/// Declaration order: `tag_store` before `sink` (see MockHarness's comment
/// above -- `sink`'s captured handlers hold `deps.store`, a raw pointer into
/// `tag_store`).
struct PgHarness {
    yuzu::test::TagStorePg tag_store; // SKIPs the TEST_CASE if no PG DSN.

    bool auth_allow{true};
    std::string auth_username{"tester"};

    bool perm_allow{true};

    bool scoped_perm_allow{true};
    std::string last_scoped_type, last_scoped_op, last_scoped_agent_id;
    int scoped_perm_fn_calls{0};

    bool deny_result{false};
    std::vector<DenyCall> deny_calls;

    std::vector<AuditRow> audits;
    std::vector<std::string> ensure_calls;
    std::vector<std::string> push_calls;

    yuzu::server::test::TestRouteSink sink; // LAST — see MockHarness's comment.

    PgHarness() {
        tag::Deps deps;
        deps.store = tag_store.get();
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
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) {
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.scoped_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const std::string& type, const std::string& op,
                                     const std::string& agent_id) {
            ++scoped_perm_fn_calls;
            last_scoped_type = type;
            last_scoped_op = op;
            last_scoped_agent_id = agent_id;
            if (!scoped_perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.deny_service_scoped_tag_mutation_fn =
            [this](const httplib::Request&, httplib::Response& res, const std::string& action,
                  const std::string& agent_id, const std::string& key) -> bool {
            deny_calls.push_back({action, agent_id, key});
            if (deny_result) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return true;
            }
            return false;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
        deps.ensure_service_management_group_fn = [this](const std::string& v) {
            ensure_calls.push_back(v);
        };
        deps.push_asset_tags_to_agent_fn = [this](const std::string& id) {
            push_calls.push_back(id);
        };
        tag::register_tag_routes(sink, deps);
    }
};

} // namespace

// ── POST /api/tags/set: gate ordering + side effects ────────────────────────

TEST_CASE("POST /api/tags/set: deny_service_scoped_tag_mutation_fn is called BEFORE "
          "scoped_perm_fn, and a deny short-circuits before it",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    h.deny_result = true;
    auto r = h.sink.Post("/api/tags/set",
                         R"({"agent_id":"agent-1","key":"role","value":"eng"})");
    REQUIRE(r);
    CHECK(r->status == 403);
    REQUIRE(h.deny_calls.size() == 1);
    CHECK(h.deny_calls[0].action == "tag.set");
    CHECK(h.deny_calls[0].agent_id == "agent-1");
    CHECK(h.deny_calls[0].key == "role");
    CHECK(h.scoped_perm_fn_calls == 0); // never reached
}

TEST_CASE("POST /api/tags/set: scoped_perm_fn gates Tag:Write scoped to agent_id",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/set",
                         R"({"agent_id":"agent-1","key":"role","value":"eng"})");
    REQUIRE(r);
    REQUIRE(h.scoped_perm_fn_calls == 1);
    CHECK(h.last_scoped_type == "Tag");
    CHECK(h.last_scoped_op == "Write");
    CHECK(h.last_scoped_agent_id == "agent-1");
    CHECK(r->status == 200);
}

TEST_CASE("POST /api/tags/set: a scoped_perm_fn denial 403s and writes nothing",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    h.scoped_perm_allow = false;
    auto r = h.sink.Post("/api/tags/set",
                         R"({"agent_id":"agent-1","key":"role","value":"eng"})");
    REQUIRE(r);
    CHECK(r->status == 403);
    auto tags = h.tag_store->get_all_tags("agent-1");
    REQUIRE(tags.has_value());
    CHECK(tags->empty());
}

TEST_CASE("POST /api/tags/set: happy path writes the tag, audits success, and triggers "
          "push_asset_tags_to_agent_fn for a structured category key",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/set",
                         R"({"agent_id":"agent-1","key":"role","value":"engineer"})");
    REQUIRE(r);
    CHECK(r->status == 200);

    auto tags = h.tag_store->get_all_tags("agent-1");
    REQUIRE(tags.has_value());
    REQUIRE(tags->size() == 1);
    CHECK((*tags)[0].key == "role");
    CHECK((*tags)[0].value == "engineer");

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "tag.set");
    CHECK(h.audits[0].result == "success");

    REQUIRE(h.push_calls.size() == 1);
    CHECK(h.push_calls[0] == "agent-1");
    CHECK(h.ensure_calls.empty()); // key != "service"
}

TEST_CASE("POST /api/tags/set: key=\"service\" triggers ensure_service_management_group_fn "
          "with the tag value",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/set",
                         R"({"agent_id":"agent-1","key":"service","value":"printers"})");
    REQUIRE(r);
    CHECK(r->status == 200);
    REQUIRE(h.ensure_calls.size() == 1);
    CHECK(h.ensure_calls[0] == "printers");
}

TEST_CASE("POST /api/tags/set: a non-category free-form key does NOT trigger "
          "push_asset_tags_to_agent_fn",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/set",
                         R"({"agent_id":"agent-1","key":"custom_note","value":"hello"})");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(h.push_calls.empty());
}

TEST_CASE("POST /api/tags/set: an invalid tag key is a 400, unaudited, gates never reached",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/set",
                         R"({"agent_id":"agent-1","key":"bad key!","value":"x"})");
    REQUIRE(r);
    CHECK(r->status == 400);
    CHECK(h.deny_calls.empty());
    CHECK(h.scoped_perm_fn_calls == 0);
    CHECK(h.audits.empty());
}

TEST_CASE("POST /api/tags/set: missing agent_id/key is a 400 before any gate",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/set", R"({"key":"role","value":"x"})");
    REQUIRE(r);
    CHECK(r->status == 400);
    CHECK(h.deny_calls.empty());
}

// ── POST /api/tags/delete: gate ordering + audit ────────────────────────────

TEST_CASE("POST /api/tags/delete: deny_service_scoped_tag_mutation_fn is called BEFORE "
          "scoped_perm_fn",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    (void)h.tag_store->set_tag("agent-1", "role", "engineer", "api");
    h.deny_result = true;
    auto r = h.sink.Post("/api/tags/delete", R"({"agent_id":"agent-1","key":"role"})");
    REQUIRE(r);
    CHECK(r->status == 403);
    REQUIRE(h.deny_calls.size() == 1);
    CHECK(h.deny_calls[0].action == "tag.delete");
    CHECK(h.scoped_perm_fn_calls == 0);
    // Nothing deleted.
    auto tags = h.tag_store->get_all_tags("agent-1");
    REQUIRE(tags.has_value());
    CHECK(tags->size() == 1);
}

TEST_CASE("POST /api/tags/delete: happy path deletes the tag, scoped_perm_fn gates "
          "Tag:Delete scoped to agent_id, and audits success",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    (void)h.tag_store->set_tag("agent-1", "role", "engineer", "api");

    auto r = h.sink.Post("/api/tags/delete", R"({"agent_id":"agent-1","key":"role"})");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto body = json::parse(r->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["deleted"] == true);

    REQUIRE(h.scoped_perm_fn_calls == 1);
    CHECK(h.last_scoped_type == "Tag");
    CHECK(h.last_scoped_op == "Delete");
    CHECK(h.last_scoped_agent_id == "agent-1");

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "tag.delete");
    CHECK(h.audits[0].result == "success");

    auto tags = h.tag_store->get_all_tags("agent-1");
    REQUIRE(tags.has_value());
    CHECK(tags->empty());
}

TEST_CASE("POST /api/tags/delete: deleting a nonexistent tag audits not_found, not "
          "success",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/delete", R"({"agent_id":"agent-1","key":"role"})");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto body = json::parse(r->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["deleted"] == false);

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "not_found");
}

// ── GET /api/tags + POST /api/tags/query: happy paths, unaudited ───────────

TEST_CASE("GET /api/tags: happy path lists an agent's tags, unaudited",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    (void)h.tag_store->set_tag("agent-1", "role", "engineer", "api");

    auto r = h.sink.Get("/api/tags?agent_id=agent-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto body = json::parse(r->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["agent_id"] == "agent-1");
    REQUIRE(body["tags"].size() == 1);
    CHECK(body["tags"][0]["key"] == "role");
    CHECK(body["tags"][0]["value"] == "engineer");
    CHECK(h.audits.empty());
}

TEST_CASE("GET /api/tags: a missing agent_id parameter is a 400",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Get("/api/tags");
    REQUIRE(r);
    CHECK(r->status == 400);
}

TEST_CASE("POST /api/tags/query: happy path returns the agents carrying a tag, unaudited",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    (void)h.tag_store->set_tag("agent-1", "role", "engineer", "api");
    (void)h.tag_store->set_tag("agent-2", "role", "manager", "api");

    auto r = h.sink.Post("/api/tags/query", R"({"key":"role","value":"engineer"})");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto body = json::parse(r->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["agents"].size() == 1);
    CHECK(body["agents"][0] == "agent-1");
    CHECK(h.audits.empty());
}

TEST_CASE("POST /api/tags/query: a missing key is a 400",
          "[server][routes][tag_routes][rest][pg]") {
    PgHarness h;
    auto r = h.sink.Post("/api/tags/query", R"({})");
    REQUIRE(r);
    CHECK(r->status == 400);
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_tag_routes' OWN handlers
// are correct, but nothing above reads server.cpp — a future edit that drops
// the production `register_tag_routes(...)` call at server.cpp's
// registration site would leave every case above green while the real
// server 404s all 4 routes. Mirrors test_schedule_routes.cpp's tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("tag_routes: wiring -- server.cpp still calls register_tag_routes",
          "[server][routes][tag_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_tag_routes(") != std::string::npos);
}
