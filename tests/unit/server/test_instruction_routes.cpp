/// @file test_instruction_routes.cpp
/// HTTP-level coverage for the 13-route Instruction Definitions +
/// Instruction Sets API (#2542 PR-7) — driven in-process through
/// TestRouteSink (no httplib acceptor, #438), mirroring
/// test_custom_properties_routes.cpp's / test_result_set_routes.cpp's
/// Harness shape.
///
/// Split by whether a case needs a live Postgres-backed `InstructionStore`
/// (it has no virtual seam — `Deps::store` is a concrete pointer, per
/// #2542 PR-7 — so anything past the gate that touches a real store
/// needs Postgres):
///   - Every gate-denial pin (which securable/operation each route passes),
///     the null-store degrade (503 for the JSON API routes, 200 HTML for
///     the two YAML endpoints, and the editor fragment's own null-store
///     fallback to its "new definition" template), and the plain
///     validation 400s that never reach the store, all run WITHOUT
///     Postgres.
///   - The CRUD round-trips, the audit-row shapes (including the
///     ASYMMETRIES this module preserves verbatim from the pre-extraction
///     inline code — see instruction_routes.hpp's file header for the full
///     per-route breakdown: `POST /api/instruction-sets` audits NOTHING on
///     any branch; `DELETE /api/instruction-sets/:id` audits db-error/
///     not-found but NOT success, unlike its `/api/instructions/:id`
///     sibling), are `[pg]`, gated behind YUZU_TEST_POSTGRES_DSN via a
///     pre-migrated PgTestTemplate sharing test_instruction_store.cpp's
///     `"instructionstore"` template key.
///
/// This file is also the wiring-regression tripwire for all 13 routes: a
/// real dispatch through the actual registered handler is strictly
/// stronger evidence that a route still calls the right gate than a regex
/// over source text would be.

#include "instruction_routes.hpp"
#include "test_route_sink.hpp"

#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// Minimal `application/x-www-form-urlencoded` value encoder for building
/// synthetic form bodies (the YAML endpoints below post a multi-line
/// `yaml_source` field) — a local helper rather than reaching for one of
/// httplib's own internal encoders, since none is otherwise used by this
/// test suite and TestRouteSink's own header comment already pins the
/// `httplib::detail::` surface it depends on to a specific httplib version.
std::string url_encode_form(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else if (c == ' ') {
            out.push_back('+');
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

struct EmitRow {
    std::string event_type;
    json attrs;
    json payload_data;
};

/// All providers injected and re-read per call, mirroring
/// test_custom_properties_routes.cpp's Harness shape. `store` defaults to
/// null — every case that must NOT need Postgres leaves it null and relies
/// on the route returning (503 / 200-HTML-error) before it would be
/// dereferenced.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    InstructionStore* store{nullptr};

    // deps.auth_fn (require_auth) — blocking, writes 401 on failure.
    bool auth_allow{true};
    std::string auth_username{"alice"};

    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    // deps.resolve_session_fn (resolve_session) — non-blocking, never
    // writes to `res`. Empty means "no session resolved". Independent of
    // auth_allow/auth_username so tests can prove a route never gates on
    // it (see instruction_routes.hpp's header comment).
    std::string resolve_session_username{"alice"};

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    std::vector<EmitRow> emits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        instruction::Deps deps;
        deps.store = store;
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
        deps.resolve_session_fn =
            [this](const httplib::Request&) -> std::optional<auth::Session> {
            if (resolve_session_username.empty())
                return std::nullopt;
            auth::Session s;
            s.username = resolve_session_username;
            return s;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        deps.emit_event_fn = [this](const std::string& event_type, const httplib::Request&,
                                    const json& attrs, const json& payload_data) {
            emits.push_back({event_type, attrs, payload_data});
        };
        instruction::register_instruction_routes(sink, deps);
    }
};

json body(const std::string& s) { return json::parse(s); }

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("instruction_routes: registers exactly 13 routes",
          "[server][routes][instruction_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 13);
}

// ── Gate pinning (no Postgres needed) ───────────────────────────────────────

TEST_CASE("instruction_routes: the 10 plain JSON/API routes gate on perm_fn with the "
          "documented (securable, operation) pair",
          "[server][routes][instruction_routes]") {
    Harness h;
    h.wire();

    h.sink.Get("/api/instructions");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Read");

    h.sink.Post("/api/instructions", R"({"name":"x"})");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Write");

    h.sink.Get("/api/instructions/def-1");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Read");

    h.sink.Put("/api/instructions/def-1", R"({"name":"y"})");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Write");

    h.sink.Delete("/api/instructions/def-1");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Delete");

    h.sink.Get("/api/instructions/def-1/export");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Read");

    h.sink.Post("/api/instructions/import", R"({})");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Write");

    h.sink.Get("/api/instruction-sets");
    CHECK(h.last_perm_type == "InstructionSet");
    CHECK(h.last_perm_op == "Read");

    h.sink.Post("/api/instruction-sets", R"({"name":"x"})");
    CHECK(h.last_perm_type == "InstructionSet");
    CHECK(h.last_perm_op == "Write");

    h.sink.Delete("/api/instruction-sets/set-1");
    CHECK(h.last_perm_type == "InstructionSet");
    CHECK(h.last_perm_op == "Delete");

    // POST /api/instructions/validate-yaml — form-encoded, no store touch.
    auto r = h.sink.Post("/api/instructions/validate-yaml", "yaml_source=bogus",
                         "application/x-www-form-urlencoded");
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Read");
    REQUIRE(r);
    CHECK(r->status == 200); // pure validation, always 200 (error text in the body)
}

TEST_CASE("instruction_routes: a perm_fn denial 403s the 10 plain JSON/API routes "
          "before the store is touched",
          "[server][routes][instruction_routes]") {
    Harness h; // store stays null -- a dereference would crash; 403 must win first
    h.perm_allow = false;
    h.wire();

    auto checks = {
        std::pair{h.sink.Get("/api/instructions"), 0},
    };
    (void)checks;

    auto r1 = h.sink.Get("/api/instructions");
    REQUIRE(r1);
    CHECK(r1->status == 403);

    auto r2 = h.sink.Post("/api/instructions", R"({"name":"x"})");
    REQUIRE(r2);
    CHECK(r2->status == 403);

    auto r3 = h.sink.Get("/api/instructions/def-1");
    REQUIRE(r3);
    CHECK(r3->status == 403);

    auto r4 = h.sink.Put("/api/instructions/def-1", R"({"name":"y"})");
    REQUIRE(r4);
    CHECK(r4->status == 403);

    auto r5 = h.sink.Delete("/api/instructions/def-1");
    REQUIRE(r5);
    CHECK(r5->status == 403);

    auto r6 = h.sink.Get("/api/instructions/def-1/export");
    REQUIRE(r6);
    CHECK(r6->status == 403);

    auto r7 = h.sink.Post("/api/instructions/import", R"({})");
    REQUIRE(r7);
    CHECK(r7->status == 403);

    auto r8 = h.sink.Get("/api/instruction-sets");
    REQUIRE(r8);
    CHECK(r8->status == 403);

    auto r9 = h.sink.Post("/api/instruction-sets", R"({"name":"x"})");
    REQUIRE(r9);
    CHECK(r9->status == 403);

    auto r10 = h.sink.Delete("/api/instruction-sets/set-1");
    REQUIRE(r10);
    CHECK(r10->status == 403);
}

TEST_CASE("instruction_routes: a null store answers 503 on every plain JSON/API route "
          "without crashing",
          "[server][routes][instruction_routes]") {
    Harness h;
    h.wire();

    auto r1 = h.sink.Get("/api/instructions");
    REQUIRE(r1);
    CHECK(r1->status == 503);

    auto r2 = h.sink.Post("/api/instructions", R"({"name":"x"})");
    REQUIRE(r2);
    CHECK(r2->status == 503);

    auto r3 = h.sink.Get("/api/instructions/def-1");
    REQUIRE(r3);
    CHECK(r3->status == 503);

    auto r4 = h.sink.Put("/api/instructions/def-1", R"({"name":"y"})");
    REQUIRE(r4);
    CHECK(r4->status == 503);

    auto r5 = h.sink.Delete("/api/instructions/def-1");
    REQUIRE(r5);
    CHECK(r5->status == 503);

    auto r6 = h.sink.Get("/api/instructions/def-1/export");
    REQUIRE(r6);
    CHECK(r6->status == 503);

    auto r7 = h.sink.Post("/api/instructions/import", R"({})");
    REQUIRE(r7);
    CHECK(r7->status == 503);

    auto r8 = h.sink.Get("/api/instruction-sets");
    REQUIRE(r8);
    CHECK(r8->status == 503);

    auto r9 = h.sink.Post("/api/instruction-sets", R"({"name":"x"})");
    REQUIRE(r9);
    CHECK(r9->status == 503);

    auto r10 = h.sink.Delete("/api/instruction-sets/set-1");
    REQUIRE(r10);
    CHECK(r10->status == 503);

    CHECK(h.audits.empty()); // every store-unavailable branch returns before any audit call
}

// NOTE: `POST /api/instructions`'s bad-approval_mode 400 is NOT reachable
// with a null store — `deps.store` is checked BEFORE the body is even
// parsed (matches the null-store-503-first ordering the "null store
// answers 503" case above pins), so this needs a real store; see the [pg]
// section below.

TEST_CASE("instruction_routes: GET /fragments/instructions/editor gates on auth_fn THEN "
          "perm_fn -- a perm_fn denial renders 200 + the denied HTML fragment, never a 403",
          "[server][routes][instruction_routes]") {
    Harness h;
    h.wire();

    // auth_fn denial -- the route's own auth_fn stub writes 401.
    h.auth_allow = false;
    auto r1 = h.sink.Get("/fragments/instructions/editor");
    REQUIRE(r1);
    CHECK(r1->status == 401);
    h.auth_allow = true;

    // perm_fn denial -- overridden to 200 + HTML, an HTMX-fragment convention
    // (htmx does not swap a non-2xx response). kInstructionEditorDeniedHtml's
    // actual markup names the required role directly ("requires the
    // PlatformEngineer or Administrator role") -- assert the surrounding
    // denial copy, not an absence of that role name.
    h.perm_allow = false;
    auto r2 = h.sink.Get("/fragments/instructions/editor");
    REQUIRE(r2);
    CHECK(r2->status == 200);
    CHECK(r2->body.find("requires the") != std::string::npos);
    CHECK(r2->body.find("Contact your administrator") != std::string::npos);
    CHECK(h.last_perm_type == "InstructionDefinition");
    CHECK(h.last_perm_op == "Write");
}

TEST_CASE("instruction_routes: GET /fragments/instructions/editor with no id and a null "
          "store renders the new-definition template, not a 503",
          "[server][routes][instruction_routes]") {
    Harness h; // store stays null
    h.wire();
    auto r = h.sink.Get("/fragments/instructions/editor");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("New Definition") != std::string::npos);
}

TEST_CASE("instruction_routes: POST /api/instructions/yaml gates on perm_fn THEN auth_fn, "
          "and a null store degrades to 200 HTML (never 503)",
          "[server][routes][instruction_routes]") {
    Harness h;
    h.wire();

    h.perm_allow = false;
    auto r1 = h.sink.Post("/api/instructions/yaml", "yaml_source=x",
                          "application/x-www-form-urlencoded");
    REQUIRE(r1);
    CHECK(r1->status == 403); // perm_fn's own JSON denial body, gated first
    h.perm_allow = true;

    h.auth_allow = false;
    auto r2 = h.sink.Post("/api/instructions/yaml", "yaml_source=x",
                          "application/x-www-form-urlencoded");
    REQUIRE(r2);
    CHECK(r2->status == 401);
    h.auth_allow = true;

    // store stays null past both gates -- 200 HTML error, an HTMX-fragment
    // convention, not a JSON 503.
    auto r3 = h.sink.Post("/api/instructions/yaml", "yaml_source=x",
                          "application/x-www-form-urlencoded");
    REQUIRE(r3);
    CHECK(r3->status == 200);
    CHECK(r3->body.find("Instruction store not available") != std::string::npos);
}

// NOTE: the YAML save route's own validation-failure ("Cannot save") branch
// runs AFTER the null-store check (same ordering as the JSON create route
// above), so it is NOT reachable with a null store either -- see the [pg]
// section below for the real case.

TEST_CASE("instruction_routes: POST /api/instructions/validate-yaml never needs the "
          "store and reports pass/fail in the HTML body",
          "[server][routes][instruction_routes]") {
    Harness h; // store stays null throughout
    h.wire();

    auto bad = h.sink.Post("/api/instructions/validate-yaml", "yaml_source=",
                           "application/x-www-form-urlencoded");
    REQUIRE(bad);
    CHECK(bad->status == 200);
    CHECK(bad->body.find("Validation errors") != std::string::npos);
    CHECK(h.audits.empty());
}

// ── [pg] cases: real InstructionStore ───────────────────────────────────────

namespace {

// Shares the "instructionstore" template key with test_instruction_store.cpp
// / test_instruction_store_signing.cpp (same store, same migration) — the
// registry builds the named template once per process regardless of which
// file's PgTestTemplate instance triggers it first.
yuzu::test::PgTestTemplate route_instr_tpl{
    "instructionstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instructionstore routes template: store failed to migrate");
    }};

struct PgWired {
    yuzu::server::pg::PgPool pool;
    InstructionStore store;

    explicit PgWired(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
        // #1073: opt out of signature enforcement -- these tests exercise the
        // route/audit contract, not the Ed25519 signing pipeline (already
        // covered by test_instruction_store_signing.cpp).
        store.set_require_signed_definitions(false);
    }
};

} // namespace

TEST_CASE("instruction_routes: POST/GET/PUT/DELETE definition round-trip over HTTP, with "
          "the documented audit shape",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Get Hostname"},
                                   {"plugin", "system_info"},
                                   {"action", "Query"}, // uppercased on input
                                   {"type", "question"}}
                                  .dump());
    REQUIRE(create);
    CHECK(create->status == 200);
    auto id = body(create->body)["id"].get<std::string>();
    REQUIRE(!id.empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.create");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "InstructionDefinition");
    CHECK(h.audits[0].target_id == id);
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "instruction.created");
    CHECK(h.emits[0].payload_data["instruction_id"] == id);

    auto get = h.sink.Get("/api/instructions/" + id);
    REQUIRE(get);
    CHECK(get->status == 200);
    CHECK(body(get->body)["action"] == "query"); // lowercased by the handler
    CHECK(h.audits.size() == 1); // GET is unaudited -- no new row

    auto put = h.sink.Put("/api/instructions/" + id, json{{"description", "updated"}}.dump());
    REQUIRE(put);
    CHECK(put->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "instruction.update");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail.empty()); // padded "" -- the original 4-arg call had no detail
    REQUIRE(h.emits.size() == 2);
    CHECK(h.emits[1].event_type == "instruction.updated");
    CHECK(h.emits[1].payload_data["instruction_id"] == id);

    auto del = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    REQUIRE(h.audits.size() == 3);
    CHECK(h.audits[2].action == "instruction.delete");
    CHECK(h.audits[2].result == "success");
    REQUIRE(h.emits.size() == 3);
    CHECK(h.emits[2].event_type == "instruction.deleted");
    CHECK(h.emits[2].payload_data["instruction_id"] == id);

    auto redelete = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(redelete);
    CHECK(redelete->status == 404);
    REQUIRE(h.audits.size() == 4);
    CHECK(h.audits[3].result == "denied"); // not_found -> "denied", not "error"
}

TEST_CASE("instruction_routes: GET /api/instructions lists real rows and honors the "
          "name/plugin/type/limit query filters, unaudited",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto make = [&](const std::string& name, const std::string& plugin,
                    const std::string& type) {
        auto res = h.sink.Post(
            "/api/instructions",
            json{{"name", name}, {"plugin", plugin}, {"action", "Query"}, {"type", type}}
                .dump());
        REQUIRE(res);
        REQUIRE(res->status == 200);
        return body(res->body)["id"].get<std::string>();
    };
    auto id_a = make("ListTestA", "system_info", "question");
    auto id_b = make("ListTestB", "os_info", "question");
    h.audits.clear();
    h.emits.clear();

    auto all = h.sink.Get("/api/instructions");
    REQUIRE(all);
    CHECK(all->status == 200);
    auto all_body = body(all->body);
    REQUIRE(all_body["definitions"].is_array());
    CHECK(all_body["count"] == all_body["definitions"].size());
    auto has_id = [&](const nlohmann::json& arr, const std::string& id) {
        return std::any_of(arr.begin(), arr.end(),
                            [&](const auto& d) { return d["id"] == id; });
    };
    CHECK(has_id(all_body["definitions"], id_a));
    CHECK(has_id(all_body["definitions"], id_b));

    auto by_plugin = h.sink.Get("/api/instructions?plugin=os_info");
    REQUIRE(by_plugin);
    CHECK(by_plugin->status == 200);
    auto by_plugin_body = body(by_plugin->body);
    CHECK(has_id(by_plugin_body["definitions"], id_b));
    CHECK_FALSE(has_id(by_plugin_body["definitions"], id_a));

    auto by_name = h.sink.Get("/api/instructions?name=ListTestA");
    REQUIRE(by_name);
    CHECK(by_name->status == 200);
    CHECK(has_id(body(by_name->body)["definitions"], id_a));

    auto limited = h.sink.Get("/api/instructions?limit=1");
    REQUIRE(limited);
    CHECK(limited->status == 200);
    CHECK(body(limited->body)["definitions"].size() == 1);

    // Pure reads: never audited, matching the AUDIT ASYMMETRIES header note.
    CHECK(h.audits.empty());
    CHECK(h.emits.empty());
}

TEST_CASE("instruction_routes: POST /api/instructions with a bad approval_mode 400s "
          "(store-open check passed, body validation failed) with no audit row",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Post("/api/instructions",
                         json{{"name", "x"}, {"approval_mode", "bogus"}}.dump());
    REQUIRE(r);
    CHECK(r->status == 400);
    CHECK(h.audits.empty());
}

TEST_CASE("instruction_routes: POST /api/instructions/yaml validation failure renders "
          "200 HTML 'Cannot save', unaudited, once past the store-open check",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // Empty yaml_source fails instruction_yaml::validate_definition_yaml's
    // byte-level checks.
    auto r = h.sink.Post("/api/instructions/yaml", "yaml_source=",
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("Cannot save") != std::string::npos);
    CHECK(h.audits.empty());
}

TEST_CASE("instruction_routes: PUT a genuinely-nonexistent id 404s via the pre-update "
          "read, with NO audit call -- the audited 'denied' not_found is a separate, "
          "TOCTOU-only path (see instruction_routes.hpp's header comment)",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Put("/api/instructions/does-not-exist", json{{"description", "x"}}.dump());
    REQUIRE(r);
    CHECK(r->status == 404);
    CHECK(h.audits.empty()); // the pre-update get_definition 404 never reaches audit_fn
}

TEST_CASE("instruction_routes: a duplicate caller-supplied id conflicts with 409, audited "
          "'denied', body prefix-stripped",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    json def{{"id", "dup.instruction"}, {"name", "First"}, {"plugin", "os_info"},
             {"action", "os_name"}, {"type", "question"}};
    auto first = h.sink.Post("/api/instructions", def.dump());
    REQUIRE(first);
    CHECK(first->status == 200);

    auto second = h.sink.Post("/api/instructions", def.dump());
    REQUIRE(second);
    CHECK(second->status == 409);
    // strip_conflict_prefix -- the body must not carry the raw "conflict:" token.
    CHECK(body(second->body)["error"].get<std::string>().find("conflict:") == std::string::npos);
    REQUIRE(h.audits.size() == 2); // create success (1st) + create denied (2nd)
    CHECK(h.audits[1].action == "instruction.create");
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "duplicate_id");
}

TEST_CASE("instruction_routes: GET export returns the verbatim yaml_source-derived JSON",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto create = h.sink.Post("/api/instructions", json{{"name", "Exportable"},
                                                         {"plugin", "os_info"},
                                                         {"action", "os_name"},
                                                         {"type", "question"}}
                                                        .dump());
    REQUIRE(create);
    auto id = body(create->body)["id"].get<std::string>();

    auto exported = h.sink.Get("/api/instructions/" + id + "/export");
    REQUIRE(exported);
    CHECK(exported->status == 200);
    CHECK(body(exported->body)["id"] == id);
    CHECK(h.audits.size() == 1); // unchanged since create -- export is unaudited
}

TEST_CASE("instruction_routes: POST import success/duplicate both audit, unlike the plain "
          "JSON create route which only audits the duplicate",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string envelope = R"({
        "id":"test.route.import",
        "name":"Route Import Test",
        "version":"1.0",
        "type":"question",
        "plugin":"os_info",
        "action":"os_name",
        "yaml_source":"---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: test.route.import\n  displayName: Route Import Test\n"
    })";

    auto first = h.sink.Post("/api/instructions/import", envelope);
    REQUIRE(first);
    CHECK(first->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.import");
    CHECK(h.audits[0].result == "success");
    CHECK(body(first->body)["audit_emitted"] == true);

    auto second = h.sink.Post("/api/instructions/import", envelope);
    REQUIRE(second);
    CHECK(second->status == 409);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "instruction.import");
    CHECK(h.audits[1].result == "denied"); // EVERY rejection is audited on /import
    CHECK(h.audits[1].detail == "duplicate_id");
    CHECK(body(second->body)["audit_emitted"] == true);
}

TEST_CASE("instruction_routes: instruction-set create/list/delete, with the documented "
          "audit ASYMMETRY -- create audits NOTHING, delete audits denial but not success",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto create = h.sink.Post("/api/instruction-sets",
                              json{{"name", "Route Set"}, {"description", "d"}}.dump());
    REQUIRE(create);
    CHECK(create->status == 200);
    auto id = body(create->body)["id"].get<std::string>();
    REQUIRE(!id.empty());
    CHECK(h.audits.empty()); // create_set: no audit call at all, pre-existing gap

    auto list = h.sink.Get("/api/instruction-sets");
    REQUIRE(list);
    CHECK(list->status == 200);
    bool found = false;
    for (const auto& s : body(list->body)["sets"])
        found = found || (s["id"] == id);
    CHECK(found);
    CHECK(h.audits.empty()); // GET is unaudited too

    auto del = h.sink.Delete("/api/instruction-sets/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(h.audits.empty()); // delete_set SUCCESS is unaudited -- the asymmetry

    auto redelete = h.sink.Delete("/api/instruction-sets/" + id);
    REQUIRE(redelete);
    CHECK(redelete->status == 404);
    REQUIRE(h.audits.size() == 1); // the not-found DENIAL, unlike success, IS audited
    CHECK(h.audits[0].action == "instruction_set.delete");
    CHECK(h.audits[0].result == "denied");
}

TEST_CASE("instruction_routes: instruction-set create with the SAME name twice "
          "succeeds twice, distinct ids -- the route never reads a caller-supplied "
          "'id' field, so the store's id-keyed ON CONFLICT can never fire here",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    json set{{"name", "Dup Set"}, {"description", "d"}};
    auto first = h.sink.Post("/api/instruction-sets", set.dump());
    REQUIRE(first);
    CHECK(first->status == 200);

    auto second = h.sink.Post("/api/instruction-sets", set.dump());
    REQUIRE(second);
    CHECK(second->status == 200); // NOT 409 -- see the TEST_CASE name
    CHECK(body(first->body)["id"] != body(second->body)["id"]);
    CHECK(h.audits.empty()); // still no audit call on this route, either way
}

TEST_CASE("instruction_routes: GET editor fragment pre-fills from a real definition, "
          "unaudited",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto create = h.sink.Post("/api/instructions", json{{"name", "Editable"},
                                                         {"plugin", "os_info"},
                                                         {"action", "os_name"},
                                                         {"type", "question"}}
                                                        .dump());
    REQUIRE(create);
    auto id = body(create->body)["id"].get<std::string>();
    h.audits.clear();

    auto r = h.sink.Get("/fragments/instructions/editor?id=" + id);
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("Editable") != std::string::npos);
    CHECK(r->body.find("Edit Definition") != std::string::npos);
    CHECK(h.audits.empty());
}

TEST_CASE("instruction_routes: POST yaml save create+update round-trip audits success on "
          "both branches, with the documented failure-path silence",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.yaml.save\n  displayName: YAML Save Test\nspec:\n  plugin: "
        "os_info\n  action: os_name\n  type: question\n";
    auto create = h.sink.Post(
        "/api/instructions/yaml",
        "yaml_source=" + url_encode_form(yaml),
        "application/x-www-form-urlencoded");
    REQUIRE(create);
    CHECK(create->status == 200);
    CHECK(create->body.find("Definition created") != std::string::npos);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.create");
    CHECK(h.audits[0].result == "success");
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "instruction.created");
    CHECK(h.emits[0].payload_data["instruction_id"] == "test.route.yaml.save");

    // Same yaml_source, now WITH an id -- update branch.
    auto update = h.sink.Post("/api/instructions/yaml",
                              "id=test.route.yaml.save&yaml_source=" +
                                  url_encode_form(yaml),
                              "application/x-www-form-urlencoded");
    REQUIRE(update);
    CHECK(update->status == 200);
    CHECK(update->body.find("Definition updated") != std::string::npos);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "instruction.update");
    CHECK(h.audits[1].result == "success");
    REQUIRE(h.emits.size() == 2);
    CHECK(h.emits[1].event_type == "instruction.updated");
    CHECK(h.emits[1].payload_data["instruction_id"] == "test.route.yaml.save");

    // metadata.id mismatch guard -- rejected before touching the store,
    // unaudited (matches the plain-validation-failure convention).
    auto mismatch = h.sink.Post("/api/instructions/yaml",
                                "id=some-other-id&yaml_source=" +
                                    url_encode_form(yaml),
                                "application/x-www-form-urlencoded");
    REQUIRE(mismatch);
    CHECK(mismatch->body.find("does not match") != std::string::npos);
    CHECK(h.audits.size() == 2); // unchanged -- the mismatch guard never audits
}

TEST_CASE("instruction_routes: POST validate-yaml against a real store still needs no "
          "store access and passes/fails identically",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.validate\n  displayName: Validate Test\nspec:\n  plugin: os_info\n  "
        "action: os_name\n  type: question\n";
    auto ok = h.sink.Post("/api/instructions/validate-yaml",
                          "yaml_source=" + url_encode_form(yaml),
                          "application/x-www-form-urlencoded");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->body.find("validation passed") != std::string::npos);
    CHECK(h.audits.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_instruction_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_instruction_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s all 13 routes.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("instruction_routes: wiring -- server.cpp still calls "
          "register_instruction_routes",
          "[server][routes][instruction_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_instruction_routes(") != std::string::npos);
}
