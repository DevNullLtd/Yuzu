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

#include "instruction_param_schema.hpp"
#include "instruction_definition_model.hpp" // json_exceeds_value_budget
#include "instruction_referrers.hpp"
#include "instruction_routes.hpp"
#include "instruction_schema_test_util.hpp"
#include "test_instruction_store_faults.hpp" // SqlFault (N1-6b)
#include "test_route_sink.hpp"

#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "policy_store.hpp"
#include "schedule_engine.hpp"
#include "workflow_engine.hpp"

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
    std::string resolve_session_auth_source{"local"}; ///< "api_token" = a token session (not gated)

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    std::vector<EmitRow> emits;

    /// The legacy DELETE's referrer guard. Wired by default to "nothing references it" so every
    /// other case is unaffected; `referrers` overrides, `referrers_wired = false` leaves it unset
    /// (a fail-closed 503 for an existing id). `pack_advisory` is the optional `packs=` note.
    bool referrers_wired{true};
    yuzu::server::DefinitionReferrersFn referrers;
    yuzu::server::DefinitionPackAdvisoryFn pack_advisory;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        instruction::Deps deps;
        deps.store = store;
        if (referrers_wired)
            deps.referrers_fn =
                referrers ? referrers
                          : yuzu::server::DefinitionReferrersFn(
                                [](const std::string&)
                                    -> std::expected<std::vector<yuzu::server::DefinitionReferrer>,
                                                     std::string> {
                                    return std::vector<yuzu::server::DefinitionReferrer>{};
                                });
        deps.pack_advisory_fn = pack_advisory;
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
            s.auth_source = resolve_session_auth_source;
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
        // A browser sends these on every same-origin write; the cross-site tests clear or
        // override them.
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
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

TEST_CASE("instruction_routes: PUT success audit detail records a plugin/action/approval_mode/"
          "enabled change old -> new (#2146 batch C); and stays empty when none changed",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Audited"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"},
                                   {"approval_mode", "always"}}
                                  .dump());
    REQUIRE(create);
    REQUIRE(create->status == 200);
    const auto id = body(create->body)["id"].get<std::string>();
    h.audits.clear();

    auto put = h.sink.Put("/api/instructions/" + id,
                          json{{"approval_mode", "auto"}, {"plugin", "remediation"}, {"enabled", false}}
                              .dump());
    REQUIRE(put);
    CHECK(put->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail ==
          "plugin: os_info -> remediation; approval_mode: always -> auto; enabled: true -> false");

    h.audits.clear();
    auto noop = h.sink.Put("/api/instructions/" + id, json{{"description", "only text"}}.dump());
    REQUIRE(noop);
    CHECK(noop->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].detail.empty());
}

// A present, empty `plugin` on the legacy PUT is a 400 (the v1 and MCP updates refuse it the same
// way): the store's update never checks plugin, so it would blank the column. An absent plugin and
// a same-value plugin still pass. Turns red if the guard in the PUT handler is removed (200, and
// the stored plugin is "").
TEST_CASE("instruction_routes: PUT with an empty plugin is refused 400 and the stored plugin is kept",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Keep plugin"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"}}
                                  .dump());
    REQUIRE(create);
    REQUIRE(create->status == 200);
    const auto id = body(create->body)["id"].get<std::string>();
    h.audits.clear();

    auto blank = h.sink.Put("/api/instructions/" + id, json{{"plugin", ""}}.dump());
    REQUIRE(blank);
    CHECK(blank->status == 400);
    CHECK(blank->body.find("plugin") != std::string::npos);
    auto kept = w.store.get_definition(id);
    REQUIRE(kept.has_value());
    REQUIRE(kept->has_value());
    CHECK((*kept)->plugin == "os_info");

    auto same = h.sink.Put("/api/instructions/" + id,
                           json{{"plugin", "os_info"}, {"description", "ok"}}.dump());
    REQUIRE(same);
    CHECK(same->status == 200);
}

// Review fix: the legacy PUT lowercases a supplied `action`, so restating a stored MIXED-CASE action
// (a legacy row) compared as a change, rewrote the column and cleared the stored YAML. Restating the
// stored value in any case is not a change. Turns red if the handler goes back to comparing the
// lowercased value with the stored spelling.
TEST_CASE("instruction_routes: legacy PUT restating a stored mixed-case action keeps the column and "
          "the stored YAML",
          "[pg][server][routes][instruction_routes][yaml-merge]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.put.case\n  displayName: Put Case\nspec:\n  plugin: "
        "os_info\n  action: os_name\n  type: question\n";
    auto create = h.sink.Post("/api/instructions/yaml", "yaml_source=" + url_encode_form(yaml),
                              "application/x-www-form-urlencoded");
    REQUIRE(create);
    const std::string id = "test.route.put.case";
    REQUIRE((*w.store.get_definition(id)).has_value());
    const std::string yaml_stored = (**w.store.get_definition(id)).yaml_source;
    REQUIRE_FALSE(yaml_stored.empty());
    // A legacy row with a mixed-case action (the create path lowercases, so set it directly).
    {
        pg::PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        REQUIRE(pg::exec_params(c.get(),
                                "UPDATE instruction_store.instruction_definitions SET action = "
                                "'OS_Name' WHERE id = $1",
                                std::vector<std::string>{id})
                    .status() == PGRES_COMMAND_OK);
    }
    REQUIRE((**w.store.get_definition(id)).action == "OS_Name");
    // Restating the stored action in another case: nothing changes, the YAML stays.
    auto put = h.sink.Put("/api/instructions/" + id, json{{"action", "OS_NAME"}}.dump());
    REQUIRE(put);
    CHECK(put->status == 200);
    const auto after = **w.store.get_definition(id);
    CHECK(after.action == "OS_Name");
    CHECK(after.yaml_source == yaml_stored);
}

// Review fix: the dashboard YAML save's CREATE applies the plugin / action identifier rule that
// validate-yaml and the v1 YAML save apply (an update keeps a stored odd row editable).
TEST_CASE("instruction_routes: the YAML save refuses a create whose plugin breaks the identifier rule",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.yaml.badplugin\n  displayName: Bad Plugin\nspec:\n  plugin: "
        "\"a b;c\"\n  action: os_name\n  type: question\n";
    auto r = h.sink.Post("/api/instructions/yaml", "yaml_source=" + url_encode_form(yaml),
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->body.find("Create failed") != std::string::npos);
    CHECK(r->body.find("plugin") != std::string::npos);
    auto stored = w.store.get_definition("test.route.yaml.badplugin");
    REQUIRE(stored.has_value());
    CHECK_FALSE(stored->has_value());
}

// UP-5 on the legacy route (Gate 8 F2). Turns red if the legacy PUT handler stops calling
// clear_stale_yaml_source (the YAML stays stale and a later dashboard YAML round trip reverts the
// edit), or if the predicate grows `enabled` back (the first section).
TEST_CASE("instruction_routes: legacy PUT clears a stored yaml_source on an edit to a column the YAML "
          "merge takes; audits the cleared text's digest; and leaves it for an enabled edit",
          "[pg][server][routes][instruction_routes][yaml-merge]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.put.stale\n  displayName: Put Stale\nspec:\n  plugin: "
        "os_info\n  action: os_name\n  type: question\n";
    // The stored text STATES approval: auto, so a stale copy of it would revert a PUT to `always`.
    auto create = h.sink.Post("/api/instructions/yaml",
                              "yaml_source=" + url_encode_form(yaml + "  approval: auto\n"),
                              "application/x-www-form-urlencoded");
    REQUIRE(create);
    const std::string id = "test.route.put.stale";
    const auto stored = [&] { return *w.store.get_definition(id); };
    REQUIRE(stored().has_value());
    const std::string yaml_stored = (*stored()).yaml_source;
    REQUIRE_FALSE(yaml_stored.empty());

    SECTION("a pure enabled toggle leaves the YAML intact") {
        h.audits.clear();
        auto en = h.sink.Put("/api/instructions/" + id, json{{"enabled", false}}.dump());
        REQUIRE(en);
        CHECK(en->status == 200);
        CHECK((*stored()).yaml_source == yaml_stored);
        CHECK_FALSE((*stored()).enabled);
        for (const auto& a : h.audits)
            CHECK(a.detail.find("yaml_source cleared") == std::string::npos);
    }
    SECTION("a name, description, version or type edit clears it too and the row names which") {
        // M1-5: the YAML merge takes `name` always and the others whenever the YAML states them,
        // so an edit to one left a stale YAML that a dashboard round trip reverted. Turns red if
        // clear_stale_yaml_source drops any of the four.
        struct Edit {
            const char* field;
            json value;
            const char* named;
        };
        const std::vector<Edit> edits = {{"name", "Renamed", "name: Put_Stale -> Renamed"},
                                         {"description", "new words",
                                          "description: changed 0 -> 9 bytes"},
                                         {"version", "9.9", "version: 1.0.0 -> 9.9"},
                                         {"type", "action", "type: question -> action"}};
        for (const auto& e : edits) {
            INFO(e.field);
            // Restore a YAML-authored row each round (the dashboard YAML save is the authority).
            auto back = h.sink.Post("/api/instructions/yaml",
                                    "id=" + id + "&yaml_source=" + url_encode_form(yaml_stored),
                                    "application/x-www-form-urlencoded");
            REQUIRE(back);
            REQUIRE((*stored()).yaml_source == yaml_stored);
            h.audits.clear();
            auto put = h.sink.Put("/api/instructions/" + id, json{{e.field, e.value}}.dump());
            REQUIRE(put);
            CHECK(put->status == 200);
            CHECK((*stored()).yaml_source.empty());
            REQUIRE(h.audits.size() == 1);
            CHECK(h.audits[0].detail.find(e.named) != std::string::npos);
            CHECK(h.audits[0].detail.find("yaml_source cleared") != std::string::npos);
        }
    }
    SECTION("an approval_mode edit clears it and a later YAML save cannot revert the edit") {
        h.audits.clear();
        auto put = h.sink.Put("/api/instructions/" + id, json{{"approval_mode", "always"}}.dump());
        REQUIRE(put);
        CHECK(put->status == 200);
        CHECK((*stored()).yaml_source.empty());
        CHECK((*stored()).approval_mode == "always");
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].detail.find("approval_mode: auto -> always; yaml_source cleared") !=
              std::string::npos);
        CHECK(h.audits[0].detail.find("yaml_source_bytes=" + std::to_string(yaml_stored.size())) !=
              std::string::npos);
        CHECK(h.audits[0].detail.find("yaml_source_sha256=") != std::string::npos);

        // The dashboard YAML save of what the editor pre-fills NOW (the stored text). A missing
        // clear leaves the stale text, which states `approval: auto`, and saving it reverts the
        // PUT (an explicit approval in a YAML IS an edit); a cleared text pre-fills nothing, so
        // the operator's own YAML, stating no approval, keeps the stored 'always'.
        const std::string editor_copy =
            (*stored()).yaml_source.empty() ? yaml : (*stored()).yaml_source;
        auto edit = h.sink.Post("/api/instructions/yaml",
                                "id=" + id + "&yaml_source=" + url_encode_form(editor_copy),
                                "application/x-www-form-urlencoded");
        REQUIRE(edit);
        CHECK(edit->status == 200);
        CHECK(edit->body.find("Definition updated") != std::string::npos);
        CHECK((*stored()).approval_mode == "always");
    }
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

    // #4644: a numeric prefix is not an integer.
    for (const char* bad : {"limit=100abc", "limit=1e3", "limit=0x10", "limit=4294967296"}) {
        INFO(bad);
        auto r = h.sink.Get(std::string("/api/instructions?") + bad);
        REQUIRE(r);
        CHECK(r->status == 400);
    }
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

// M1-7 (a4). The legacy create / PUT / validate-yaml apply the v1 twins' plugin / action identifier
// rule through the shared check_dispatch_identifier. Turns red if the create check, the PUT check
// or the validate-yaml check is removed; the PUT section also pins that an UNCHANGED odd stored
// value stays editable through other fields.
TEST_CASE("instruction_routes: legacy create and PUT and validate-yaml apply the plugin/action "
          "identifier rule; PUT only to a value it changes",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const auto error_of = [](const httplib::Response& r) {
        return body(r.body)["error"].get<std::string>();
    };

    SECTION("create refuses a bad plugin or action, 400, no row, no audit") {
        for (const auto& [field, value] : std::vector<std::pair<std::string, std::string>>{
                 {"plugin", "bad plugin"}, {"plugin", "a/b"}, {"action", "bad action"},
                 {"plugin", std::string(129, 'p')}, {"action", std::string(129, 'a')}}) {
            INFO(field << " size " << value.size());
            json b{{"name", "x"}, {"type", "question"}, {"plugin", "os_info"}, {"action", "os_name"}};
            b[field] = value;
            auto r = h.sink.Post("/api/instructions", b.dump());
            REQUIRE(r);
            CHECK(r->status == 400);
            CHECK(error_of(*r).rfind(field, 0) == 0);
        }
        CHECK(h.audits.empty());
        auto all = w.store.query_definitions();
        REQUIRE(all.has_value());
        CHECK(all->empty());
        // The boundary and the legacy leniencies stay: 128 characters, a dot, an empty action.
        auto ok = h.sink.Post("/api/instructions",
                              json{{"name", "x"}, {"type", "question"},
                                   {"plugin", std::string(128, 'p')}, {"action", ""}}
                                  .dump());
        REQUIRE(ok);
        CHECK(ok->status == 200);
    }
    SECTION("PUT refuses a CHANGED bad plugin or action; an unchanged odd stored value is editable") {
        auto made = h.sink.Post("/api/instructions",
                                json{{"name", "x"}, {"type", "question"}, {"plugin", "os_info"},
                                     {"action", "os_name"}}
                                    .dump());
        REQUIRE(made);
        REQUIRE(made->status == 200);
        const std::string id = body(made->body)["id"].get<std::string>();
        for (const auto& [field, value] : std::vector<std::pair<std::string, std::string>>{
                 {"plugin", "bad plugin"}, {"action", "a/b"}}) {
            INFO(field);
            auto r = h.sink.Put("/api/instructions/" + id, json{{field, value}}.dump());
            REQUIRE(r);
            CHECK(r->status == 400);
            CHECK(error_of(*r).rfind(field, 0) == 0);
        }
        auto row = w.store.get_definition(id);
        REQUIRE(row.has_value());
        REQUIRE(row->has_value());
        CHECK((*row)->plugin == "os_info");
        CHECK((*row)->action == "os_name");

        // A row stored before the rule (written through the store, which does not apply it) with
        // an odd plugin: re-sending that SAME value, or editing another field, still works.
        InstructionDefinition odd;
        odd.id = "legacy.odd";
        odd.name = "odd";
        odd.type = "question";
        odd.plugin = "odd plugin";
        odd.action = "odd action";
        REQUIRE(w.store.create_definition(odd).has_value());
        auto other = h.sink.Put("/api/instructions/legacy.odd", json{{"description", "d"}}.dump());
        REQUIRE(other);
        CHECK(other->status == 200);
        auto same = h.sink.Put("/api/instructions/legacy.odd",
                               json{{"plugin", "odd plugin"}, {"action", "odd action"}}.dump());
        REQUIRE(same);
        CHECK(same->status == 200);
        auto changed = h.sink.Put("/api/instructions/legacy.odd", json{{"plugin", "still odd"}}.dump());
        REQUIRE(changed);
        CHECK(changed->status == 400);
    }
    SECTION("validate-yaml reports a bad plugin or action") {
        const auto yaml = [](const std::string& plugin, const std::string& action) {
            return "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
                   "id: test.route.ident\n  displayName: Ident\nspec:\n  plugin: \"" + plugin +
                   "\"\n  action: \"" + action + "\"\n  type: question\n";
        };
        const auto validate = [&](const std::string& y) {
            auto r = h.sink.Post("/api/instructions/validate-yaml",
                                 "yaml_source=" + url_encode_form(y),
                                 "application/x-www-form-urlencoded");
            REQUIRE(r);
            CHECK(r->status == 200);
            return r->body;
        };
        CHECK(validate(yaml("os_info", "os_name")).find("validation passed") != std::string::npos);
        const auto bad_plugin = validate(yaml("bad plugin", "os_name"));
        CHECK(bad_plugin.find("Validation errors") != std::string::npos);
        CHECK(bad_plugin.find("plugin may only contain") != std::string::npos);
        const auto bad_action = validate(yaml("os_info", "a/b"));
        CHECK(bad_action.find("action may only contain") != std::string::npos);
        CHECK(h.audits.empty());
    }
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

TEST_CASE("instruction_routes: POST import stores the AUTHENTICATED caller as created_by; never the "
          "document's claim",
          "[pg][server][routes][instruction_routes]") {
    // Turns red if `stamp_import_creator` is removed from the import handler (the store would then
    // bind the document's own created_by).
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const auto doc = [](const std::string& id) {
        return json{{"id", id}, {"name", "Creator Stamp"}, {"version", "1.0"},
                    {"type", "question"}, {"plugin", "os_info"}, {"action", "os_name"}};
    };
    const auto created_by = [&](const std::string& id) {
        const auto got = w.store.get_definition(id);
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        return (*got)->created_by;
    };

    json claims = doc("test.route.import.creator.claim");
    claims["created_by"] = "someone-else";
    auto r1 = h.sink.Post("/api/instructions/import", claims.dump());
    REQUIRE(r1);
    CHECK(r1->status == 200);
    CHECK(created_by("test.route.import.creator.claim") == "alice");

    auto r2 = h.sink.Post("/api/instructions/import", doc("test.route.import.creator.none").dump());
    REQUIRE(r2);
    CHECK(r2->status == 200);
    CHECK(created_by("test.route.import.creator.none") == "alice");

    // A non-string claim no longer reaches the store's type gate: the field is ignored.
    json odd = doc("test.route.import.creator.odd");
    odd["created_by"] = 5;
    auto r3 = h.sink.Post("/api/instructions/import", odd.dump());
    REQUIRE(r3);
    CHECK(r3->status == 200);
    CHECK(created_by("test.route.import.creator.odd") == "alice");

    // No resolvable session: the claim is still not trusted (stored empty, as the POST create
    // route does).
    h.resolve_session_username.clear();
    json anon = doc("test.route.import.creator.anon");
    anon["created_by"] = "someone-else";
    auto r4 = h.sink.Post("/api/instructions/import", anon.dump());
    REQUIRE(r4);
    CHECK(r4->status == 200);
    CHECK(created_by("test.route.import.creator.anon").empty());
    h.resolve_session_username = "alice";

    // A malformed body is refused exactly as before: 400, one denied row, nothing stored.
    h.audits.clear();
    for (const char* bad : {"not json", "[1,2]"}) {
        INFO(bad);
        auto r = h.sink.Post("/api/instructions/import", bad);
        REQUIRE(r);
        CHECK(r->status == 400);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "instruction.import");
        CHECK(h.audits[0].result == "denied");
        h.audits.clear();
    }
}

TEST_CASE("instruction_routes: POST import refuses an invalid or over-cap parameter_schema with a "
          "400 and a denied audit row",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const auto envelope = [](const std::string& id, const std::string& schema) {
        return json{{"id", id},
                    {"name", "Schema Gate"},
                    {"version", "1.0"},
                    {"type", "question"},
                    {"plugin", "os_info"},
                    {"action", "os_name"},
                    {"parameter_schema", schema}}
            .dump();
    };

    auto bad = h.sink.Post(
        "/api/instructions/import",
        envelope("test.route.import.badschema",
                 R"({"type":"object","properties":{"p":{"type":"nosuchtype"}}})"));
    REQUIRE(bad);
    CHECK(bad->status == 400);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.import");
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].detail.rfind("parameter_schema is not a valid parameter schema:", 0) == 0);
    CHECK(body(bad->body)["audit_emitted"] == true);
    {
        const auto got = w.store.get_definition("test.route.import.badschema");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }

    auto big = h.sink.Post("/api/instructions/import",
                           envelope("test.route.import.bigschema",
                                    std::string(instr::kMaxParameterSchemaBytes + 1, ' ')));
    REQUIRE(big);
    CHECK(big->status == 400);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "parameter_schema is larger than the 262144-byte limit");
    {
        const auto got = w.store.get_definition("test.route.import.bigschema");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }
}

TEST_CASE("instruction_routes: instruction-set create/list/delete write an attempt row BEFORE "
          "the change and an outcome row after, and a repeated delete audits the not-found denial",
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
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction_set.create");
    CHECK(h.audits[0].result == "attempted"); // before the change, so no id yet
    CHECK(h.audits[0].target_id.empty());
    CHECK(h.audits[1].action == "instruction_set.create");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_type == "InstructionSet");
    CHECK(h.audits[1].target_id == id);

    auto list = h.sink.Get("/api/instruction-sets");
    REQUIRE(list);
    CHECK(list->status == 200);
    bool found = false;
    // Named local, not a range-for over a temporary's operator[]: it dangles before P2718R0 (#5924).
    auto listed = body(list->body);
    for (const auto& s : listed["sets"])
        found = found || (s["id"] == id);
    CHECK(found);
    CHECK(h.audits.size() == 2); // GET stays unaudited

    auto del = h.sink.Delete("/api/instruction-sets/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    REQUIRE(h.audits.size() == 4);
    CHECK(h.audits[2].action == "instruction_set.delete");
    CHECK(h.audits[2].result == "attempted");
    CHECK(h.audits[2].target_id == id);
    CHECK(h.audits[3].action == "instruction_set.delete");
    CHECK(h.audits[3].result == "success");
    CHECK(h.audits[3].target_id == id);

    auto redelete = h.sink.Delete("/api/instruction-sets/" + id);
    REQUIRE(redelete);
    CHECK(redelete->status == 404);
    REQUIRE(h.audits.size() == 6);
    CHECK(h.audits[4].result == "attempted");
    CHECK(h.audits[5].action == "instruction_set.delete");
    CHECK(h.audits[5].result == "denied");
}

TEST_CASE("instruction_routes: a set create/delete whose attempt audit row is not stored is "
          "refused with 503 and changes nothing (ADR-0033 section 9)",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // A set that exists before the audit store fails.
    auto seeded = h.sink.Post("/api/instruction-sets", json{{"name", "Keep Me"}}.dump());
    REQUIRE(seeded);
    auto keep_id = body(seeded->body)["id"].get<std::string>();
    const auto sets_before = w.store.list_sets();
    REQUIRE(sets_before);

    h.audit_succeeds = false;
    auto create = h.sink.Post("/api/instruction-sets", json{{"name", "Never Created"}}.dump());
    REQUIRE(create);
    CHECK(create->status == 503);
    CHECK(create->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(body(create->body)["error"]["code"] == 503);
    auto del = h.sink.Delete("/api/instruction-sets/" + keep_id);
    REQUIRE(del);
    CHECK(del->status == 503);
    CHECK(del->get_header_value("Sec-Audit-Failed") == "true");

    h.audit_succeeds = true;
    const auto sets_after = w.store.list_sets();
    REQUIRE(sets_after);
    CHECK(sets_after->size() == sets_before->size()); // nothing created, nothing deleted
    bool still_there = false;
    for (const auto& s : *sets_after)
        still_there = still_there || s.id == keep_id;
    CHECK(still_there);
}

TEST_CASE("instruction_routes: a set name or description over the page's bounds is a 400",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto long_name = h.sink.Post(
        "/api/instruction-sets",
        json{{"name", std::string(kMaxInstructionSetNameLen + 1, 'n')}}.dump());
    REQUIRE(long_name);
    CHECK(long_name->status == 400);
    auto long_desc = h.sink.Post(
        "/api/instruction-sets",
        json{{"name", "ok"}, {"description", std::string(kMaxInstructionSetDescriptionLen + 1, 'd')}}
            .dump());
    REQUIRE(long_desc);
    CHECK(long_desc->status == 400);
    auto at_limit = h.sink.Post(
        "/api/instruction-sets",
        json{{"name", std::string(kMaxInstructionSetNameLen, 'n')},
             {"description", std::string(kMaxInstructionSetDescriptionLen, 'd')}}
            .dump());
    REQUIRE(at_limit);
    CHECK(at_limit->status == 200);
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
    CHECK(h.audits.size() == 4); // each create is its own attempted + success pair
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

TEST_CASE("instruction_routes: a guardian. id is refused at every YAML authoring path "
          "(validate, create, and a re-save of that same id)",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: guardian.deploy.rules\n  displayName: Reserved\nspec:\n  plugin: "
        "os_info\n  action: os_name\n  type: question\n";
    // The reserved-namespace text names the Guardian deploy approvals; html_escape leaves
    // that fragment untouched, so it identifies the guardian token without the quote marks.
    const std::string marker = "reserved for Guardian deploy approvals";

    auto validate = h.sink.Post("/api/instructions/validate-yaml",
                                "yaml_source=" + url_encode_form(yaml),
                                "application/x-www-form-urlencoded");
    REQUIRE(validate);
    CHECK(validate->body.find(marker) != std::string::npos);

    auto create = h.sink.Post("/api/instructions/yaml", "yaml_source=" + url_encode_form(yaml),
                              "application/x-www-form-urlencoded");
    REQUIRE(create);
    CHECK(create->body.find("Cannot save") != std::string::npos);
    CHECK(create->body.find(marker) != std::string::npos);

    // The re-save (update) branch: an id is supplied, so this is the path an EXISTING
    // definition under the prefix would take. It is refused by the same validation.
    auto resave = h.sink.Post("/api/instructions/yaml",
                              "id=guardian.deploy.rules&yaml_source=" + url_encode_form(yaml),
                              "application/x-www-form-urlencoded");
    REQUIRE(resave);
    CHECK(resave->body.find("Cannot save") != std::string::npos);
    CHECK(resave->body.find(marker) != std::string::npos);

    // Nothing was stored and nothing was audited.
    CHECK(h.audits.empty());
    auto stored = w.store.get_definition("guardian.deploy.rules");
    REQUIRE(stored.has_value());       // the read succeeded...
    CHECK_FALSE(stored->has_value());  // ...and found nothing
}

TEST_CASE("instruction_routes: a JSON PUT and a YAML editor save keep the stored "
          "parameter_schema, even a legacy one the write gate would refuse",
          "[pg][server][routes][instruction_routes][param-schema]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.schema.keep\n  displayName: Schema Keep\nspec:\n  plugin: "
        "os_info\n  action: os_name\n  type: question\n  parameters:\n    type: object\n";
    auto create = h.sink.Post("/api/instructions/yaml", "yaml_source=" + url_encode_form(yaml),
                              "application/x-www-form-urlencoded");
    REQUIRE(create);
    const std::string id = "test.route.schema.keep";
    auto stored = [&] { return (*w.store.get_definition(id))->parameter_schema; };

    const std::string schema = R"({"type":"object","properties":{"p":{"type":"string"}}})";
    yuzu::server::test::force_parameter_schema(w.pool, id, schema);
    auto put = h.sink.Put("/api/instructions/" + id, json{{"description", "via put"}}.dump());
    REQUIRE(put);
    CHECK(put->status == 200);
    CHECK((*w.store.get_definition(id))->description == "via put");
    CHECK(stored() == schema);

    auto edit = h.sink.Post("/api/instructions/yaml",
                            "id=" + id + "&yaml_source=" + url_encode_form(yaml),
                            "application/x-www-form-urlencoded");
    REQUIRE(edit);
    CHECK(edit->body.find("Definition updated") != std::string::npos);
    CHECK(stored() == schema);

    // A legacy row past the 256 KiB cap is still editable through both routes.
    const std::string legacy(instr::kMaxParameterSchemaBytes + 1, ' ');
    yuzu::server::test::force_parameter_schema(w.pool, id, legacy);
    auto put2 = h.sink.Put("/api/instructions/" + id, json{{"description", "legacy put"}}.dump());
    REQUIRE(put2);
    CHECK(put2->status == 200);
    auto edit2 = h.sink.Post("/api/instructions/yaml",
                             "id=" + id + "&yaml_source=" + url_encode_form(yaml),
                             "application/x-www-form-urlencoded");
    REQUIRE(edit2);
    CHECK(edit2->body.find("Definition updated") != std::string::npos);
    CHECK(stored() == legacy);
}

TEST_CASE("instruction_routes: a YAML editor save carries forward every column the YAML does "
          "not express, and audits an approval_mode change",
          "[pg][server][routes][instruction_routes][yaml-merge]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    // Plant a definition created the way JSON/API clients create them: approval
    // 'always', a set, templates, a disabled flag, TTLs.
    auto set_id = w.store.create_set(InstructionSet{.name = "Keep Set"});
    REQUIRE(set_id.has_value());
    InstructionDefinition d;
    d.id = "test.route.yaml.merge";
    d.name = "Merge Test";
    d.version = "2.0.0";
    d.type = "action";
    d.plugin = "os_info";
    d.action = "os_name";
    d.enabled = false;
    d.instruction_set_id = *set_id;
    d.gather_ttl_seconds = 41;
    d.response_ttl_days = 9;
    d.approval_mode = "always";
    d.concurrency_mode = "per-definition";
    d.platforms = "linux";
    d.min_agent_version = "9.9.9";
    d.required_plugins = "os_info";
    d.readable_payload = "Look at it";
    d.result_schema = R"({"columns":["c"]})";
    d.visualization_spec = R"({"kind":"table"})";
    d.response_templates_spec = R"([{"name":"mine"}])";
    d.yaml_source = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
                    "id: test.route.yaml.merge\n  displayName: Merge Test\nspec:\n  plugin: "
                    "os_info\n  action: os_name\n";
    REQUIRE(w.store.create_definition(d).has_value());
    h.audits.clear();

    // Editor YAML carries none of approval / type / version / concurrency.
    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.yaml.merge\n  displayName: Merge Test Renamed\nspec:\n  plugin: "
        "os_info\n  action: os_name\n";
    auto edit = h.sink.Post("/api/instructions/yaml",
                            "id=test.route.yaml.merge&yaml_source=" + url_encode_form(yaml),
                            "application/x-www-form-urlencoded");
    REQUIRE(edit);
    CHECK(edit->body.find("Definition updated") != std::string::npos);

    auto got = w.store.get_definition("test.route.yaml.merge");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    const auto& s = **got;
    CHECK(s.name == "Merge Test Renamed"); // the YAML edit landed
    CHECK(s.approval_mode == "always");    // not downgraded to auto
    CHECK(s.type == "action");             // not reset to question
    CHECK(s.version == "2.0.0");
    CHECK(s.concurrency_mode == "per-definition");
    CHECK(s.instruction_set_id == *set_id);
    CHECK_FALSE(s.enabled);                // not forced back to enabled
    CHECK(s.gather_ttl_seconds == 41);
    CHECK(s.response_ttl_days == 9);
    CHECK(s.platforms == "linux");
    CHECK(s.min_agent_version == "9.9.9");
    CHECK(s.required_plugins == "os_info");
    CHECK(s.readable_payload == "Look at it");
    CHECK(s.result_schema == d.result_schema);
    CHECK(s.visualization_spec == d.visualization_spec);
    CHECK(s.response_templates_spec == d.response_templates_spec);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].detail.empty()); // approval_mode unchanged: no detail

    // An explicit approval in the YAML IS an edit, and is audited with both values.
    const std::string yaml2 = yaml + "  approval: auto\n";
    auto edit2 = h.sink.Post("/api/instructions/yaml",
                             "id=test.route.yaml.merge&yaml_source=" + url_encode_form(yaml2),
                             "application/x-www-form-urlencoded");
    REQUIRE(edit2);
    CHECK(edit2->body.find("Definition updated") != std::string::npos);
    CHECK((**w.store.get_definition("test.route.yaml.merge")).approval_mode == "auto");
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].detail == "approval_mode: always -> auto");
}

TEST_CASE("instruction_routes: a YAML save made against a stale editor copy is a 409 and "
          "changes nothing; one made against the current copy lands",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    InstructionDefinition d;
    d.id = "test.route.yaml.stale";
    d.name = "Stale Test";
    d.version = "1.0.0";
    d.type = "action";
    d.plugin = "os_info";
    d.action = "os_name";
    d.approval_mode = "always";
    d.yaml_source = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
                    "id: test.route.yaml.stale\n  displayName: Stale Test\nspec:\n  plugin: "
                    "os_info\n  action: os_name\n";
    REQUIRE(w.store.create_definition(d).has_value());
    const auto loaded = (**w.store.get_definition("test.route.yaml.stale")).updated_at;

    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.yaml.stale\n  displayName: Renamed\nspec:\n  plugin: os_info\n  "
        "action: os_name\n";
    auto stale = h.sink.Post("/api/instructions/yaml",
                             "id=test.route.yaml.stale&updated_at=" + std::to_string(loaded - 1) +
                                 "&yaml_source=" + url_encode_form(yaml),
                             "application/x-www-form-urlencoded");
    REQUIRE(stale);
    CHECK(stale->status == 409);
    CHECK((**w.store.get_definition("test.route.yaml.stale")).name == "Stale Test");

    auto bad = h.sink.Post("/api/instructions/yaml",
                           "id=test.route.yaml.stale&updated_at=abc&yaml_source=" +
                               url_encode_form(yaml),
                           "application/x-www-form-urlencoded");
    REQUIRE(bad);
    CHECK(bad->status == 400);

    auto fresh = h.sink.Post("/api/instructions/yaml",
                             "id=test.route.yaml.stale&updated_at=" + std::to_string(loaded) +
                                 "&yaml_source=" + url_encode_form(yaml),
                             "application/x-www-form-urlencoded");
    REQUIRE(fresh);
    CHECK(fresh->body.find("Definition updated") != std::string::npos);
    CHECK((**w.store.get_definition("test.route.yaml.stale")).name == "Renamed");
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

TEST_CASE("instruction_routes: a cookie-session write that is cross-site or carries no "
          "Origin/Referer is refused (403, audited) and changes nothing; a token session is not "
          "gated",
          "[pg][server][routes][instruction_routes][csrf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::unordered_map<std::string, std::string> cross_site[] = {
        {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}},
        {{"Host", "yuzu.test"}, {"Referer", "https://evil.test/x"}},
        {{"Host", "yuzu.test"}}, // a browser always sends one on a write
    };
    for (const auto& hdrs : cross_site) {
        h.sink.default_headers = hdrs;
        h.audits.clear();
        auto set = h.sink.Post("/api/instruction-sets", json{{"name", "Evil"}}.dump());
        REQUIRE(set);
        CHECK(set->status == 403);
        auto imp = h.sink.Post("/api/instructions/import", "{}");
        REQUIRE(imp);
        CHECK(imp->status == 403);
        auto yaml = h.sink.Post("/api/instructions/yaml", "yaml_source=x",
                                "application/x-www-form-urlencoded");
        REQUIRE(yaml);
        CHECK(yaml->status == 403);
        auto del = h.sink.Delete("/api/instruction-sets/whatever");
        REQUIRE(del);
        CHECK(del->status == 403);
        REQUIRE(h.audits.size() == 4);
        for (const auto& a : h.audits)
            CHECK(a.action == "csrf.denied"); // refused before any attempt row or change
    }
    const auto sets = w.store.list_sets();
    REQUIRE(sets);
    CHECK(sets->empty());

    // An API/MCP token is not riding a cookie: no Origin is needed.
    h.sink.default_headers.clear();
    h.resolve_session_auth_source = "api_token";
    auto token_write = h.sink.Post("/api/instruction-sets", json{{"name", "Via Token"}}.dump());
    REQUIRE(token_write);
    CHECK(token_write->status == 200);
}

TEST_CASE("instruction_routes: a YAML editor save audits a plugin / action / approval_mode / "
          "concurrency_mode change old -> new; not approval_mode alone (#2146 batch C gov)",
          "[pg][server][routes][instruction_routes][yaml-merge]") {
    // Turns red if the dashboard YAML save goes back to recording only approval_mode: a repoint
    // or a concurrency change would leave an empty detail.
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    InstructionDefinition d;
    d.id = "test.route.yaml.audit";
    d.name = "Audit Me";
    d.type = "question";
    d.plugin = "os_info";
    d.action = "os_name";
    d.approval_mode = "always";
    d.concurrency_mode = "per-device";
    d.yaml_source = "---\nmetadata:\n  id: test.route.yaml.audit\n  displayName: Audit Me\nspec:\n"
                    "  plugin: os_info\n  action: os_name\n";
    REQUIRE(w.store.create_definition(d).has_value());
    h.audits.clear();

    const std::string yaml =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  "
        "id: test.route.yaml.audit\n  displayName: Audit Me\nspec:\n  plugin: remediation\n"
        "  action: other_action\n  concurrency: per-fleet\n";
    auto edit = h.sink.Post("/api/instructions/yaml",
                            "id=test.route.yaml.audit&yaml_source=" + url_encode_form(yaml),
                            "application/x-www-form-urlencoded");
    REQUIRE(edit);
    CHECK(edit->body.find("Definition updated") != std::string::npos);
    REQUIRE(h.audits.size() == 1); // the legacy route writes its single success row, as before
    CHECK(h.audits[0].action == "instruction.update");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail ==
          "plugin: os_info -> remediation; action: os_name -> other_action; "
          "concurrency_mode: per-device -> per-fleet");
}

TEST_CASE("instruction_routes: DELETE success audit detail carries the deleted definition's "
          "dispatch tuple; an absent id keeps its not_found row and 404",
          "[pg][server][routes][instruction_routes]") {
    // Turns red if the pre-read in the legacy DELETE handler is removed: the success row's
    // detail goes back to empty and nothing records what the deleted definition ran.
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Doomed"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"},
                                   {"approval_mode", "always"}}
                                  .dump());
    REQUIRE(create);
    REQUIRE(create->status == 200);
    const auto id = body(create->body)["id"].get<std::string>();
    h.audits.clear();

    auto del = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail == "name=Doomed plugin=os_info action=os_name approval_mode=always "
                                "concurrency_mode=per-device enabled=true");

    h.audits.clear();
    auto again = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(again);
    CHECK(again->status == 404);
    // A stale list (the row is already gone) is also an error toast, not a silent button.
    CHECK(json::parse(again->get_header_value("HX-Trigger"))["showToast"]["level"] == "error");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].detail == "not_found");
}

// M2-1. The released legacy DELETE gets the same referrer guard as the v1 twin. Real stores: a
// schedule that names the definition makes the delete a 409 that lists it, writes one `denied` row
// with detail `referenced`, emits nothing and leaves the definition in place. Turns red if the
// `referrers_fn` block in the legacy DELETE handler (instruction_routes.cpp) is removed.
TEST_CASE("instruction_routes: DELETE a definition that a schedule names is refused 409 with the "
          "referrer listed and nothing deleted; removing the schedule lets it through",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    yuzu::server::ScheduleEngine schedules{w.pool};
    yuzu::server::WorkflowEngine workflows{w.pool};
    yuzu::server::PolicyStore policies{w.pool};
    REQUIRE(schedules.is_open());
    REQUIRE(workflows.is_open());
    REQUIRE(policies.is_open());
    Harness h;
    h.store = &w.store;
    h.referrers = yuzu::server::make_definition_referrers_fn(&schedules, &workflows, &policies);
    h.wire();

    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Pinned"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"}}
                                  .dump());
    REQUIRE(create);
    REQUIRE(create->status == 200);
    const auto id = body(create->body)["id"].get<std::string>();

    yuzu::server::InstructionSchedule sched;
    sched.name = "nightly";
    sched.definition_id = id;
    sched.frequency_type = "interval";
    sched.interval_minutes = 60;
    sched.scope_expression = "ostype = 'linux'";
    sched.created_by = "alice";
    auto sid = schedules.create_schedule(sched);
    REQUIRE(sid.has_value());
    h.audits.clear();
    h.emits.clear();

    auto del = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 409);
    const auto msg = body(del->body)["error"]["message"].get<std::string>();
    CHECK(msg.find("schedule " + *sid) != std::string::npos);
    CHECK(msg.find("NOT deleted") != std::string::npos);
    // The Instructions page's Delete button is a plain hx-delete that swaps no 4xx body, so the
    // refusal is also an error toast (HX-Trigger).
    const auto trigger = json::parse(del->get_header_value("HX-Trigger"));
    CHECK(trigger["showToast"]["level"] == "error");
    CHECK(trigger["showToast"]["message"].get<std::string>().find("schedule " + *sid) !=
          std::string::npos);
    auto still = w.store.get_definition(id);
    REQUIRE(still.has_value());
    CHECK(still->has_value());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.delete");
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].detail == "referenced");
    CHECK(h.emits.empty());

    REQUIRE(schedules.delete_schedule(*sid, "alice"));
    h.audits.clear();
    auto ok = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    // The success keeps the success toast: the error toast is for refusals only.
    CHECK(json::parse(ok->get_header_value("HX-Trigger"))["showToast"]["level"] == "success");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
}

// The toast on a refused legacy DELETE is cut to 600 bytes (plus "...") so a long referrer list cannot
// outgrow a proxy's response-header buffer, while the body keeps the full list. Turns red if the cap
// is removed (the toast is then as long as the body) or if the toast stops being a prefix of it.
TEST_CASE("instruction_routes: a long referrer list is cut in the toast and complete in the body",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.referrers = [](const std::string&)
        -> std::expected<std::vector<yuzu::server::DefinitionReferrer>, std::string> {
        std::vector<yuzu::server::DefinitionReferrer> many;
        for (int i = 0; i < 25; ++i)
            many.push_back({"schedule", std::string(60, static_cast<char>('a' + i % 26)), {}});
        return many;
    };
    h.wire();
    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Many referrers"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"}}
                                  .dump());
    REQUIRE(create);
    const auto id = body(create->body)["id"].get<std::string>();

    auto del = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 409);
    const auto full = body(del->body)["error"]["message"].get<std::string>();
    CHECK(full.size() > 600);
    CHECK(full.find("and 5 more") != std::string::npos);
    const auto toast =
        json::parse(del->get_header_value("HX-Trigger"))["showToast"]["message"].get<std::string>();
    CHECK(toast.size() <= 603);
    REQUIRE(toast.size() > 3);
    CHECK(toast.substr(toast.size() - 3) == "...");
    CHECK(full.rfind(toast.substr(0, toast.size() - 3), 0) == 0);
}

// UP-4. The legacy import refuses a body of more than kMaxDefinitionJsonValues structural values
// (the parse tree of `[],[],...` is hundreds of times the body). stamp_import_creator leaves such a
// body unparsed and the store answers 400. Turns red if either check is removed: the body is then
// parsed (the memory the budget exists to save) or accepted into the store's parse.
TEST_CASE("instruction_routes: the legacy import refuses a body over the value budget with a 400",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    std::string hostile = R"({"a":[)";
    for (int i = 0; i < 60'000; ++i)
        hostile += "[],";
    hostile += "[]]}";
    auto r = h.sink.Post("/api/instructions/import", hostile);
    REQUIRE(r);
    CHECK(r->status == 400);
    CHECK(r->body.find("too many values") != std::string::npos);

    // Duplicate keys collapse on parse and dump, so a body that stamp_import_creator PARSED would
    // fall under the budget and reach the store as a different, tiny document. The store's text
    // ("(at most 100000)") on this body therefore proves the stamp returned it unparsed.
    std::string duplicate_keys = R"({"a":1)";
    for (int i = 0; i < 100'000; ++i)
        duplicate_keys += R"(,"a":1)";
    duplicate_keys += "}";
    auto dup = h.sink.Post("/api/instructions/import", duplicate_keys);
    REQUIRE(dup);
    CHECK(dup->status == 400);
    CHECK(dup->body.find("(at most 100000)") != std::string::npos);
}

// The legacy create and PUT parse their own body, so each refuses one over the budget with a 400.
TEST_CASE("instruction_routes: the legacy create and PUT refuse a body over the value budget",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Budget"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"}}
                                  .dump());
    REQUIRE(create);
    const auto id = body(create->body)["id"].get<std::string>();
    std::string hostile = R"({"a":[)";
    for (int i = 0; i < 60'000; ++i)
        hostile += "[],";
    hostile += "[]]}";
    auto post = h.sink.Post("/api/instructions", hostile);
    REQUIRE(post);
    CHECK(post->status == 400);
    CHECK(post->body.find("too many values") != std::string::npos);
    auto put = h.sink.Put("/api/instructions/" + id, hostile);
    REQUIRE(put);
    CHECK(put->status == 400);
    CHECK(put->body.find("too many values") != std::string::npos);
}

TEST_CASE("json_exceeds_value_budget counts structure outside string literals",
          "[instruction_routes]") {
    using yuzu::server::json_exceeds_value_budget;
    CHECK_FALSE(json_exceeds_value_budget(R"({"a":[1,2,3]})", 100)); // '{' '[' and 2 commas
    CHECK(json_exceeds_value_budget("[1,2,3,4]", 3));                 // '[' and 3 commas
    CHECK_FALSE(json_exceeds_value_budget("[1,2,3,4]", 4));
    // Brackets, braces and commas inside a string literal are not structure, an escaped quote does
    // not end the string.
    CHECK_FALSE(json_exceeds_value_budget(R"(["[,{,,,,,"])", 1));
    CHECK_FALSE(json_exceeds_value_budget(R"(["a\"[[[[,,,"])", 1));
    // An escaped backslash does not escape the closing quote: `[` and `,` outside the string.
    CHECK(json_exceeds_value_budget(R"(["\\",1])", 1));
    // The default budget: exactly kMaxDefinitionJsonValues passes, one more does not.
    const auto at_budget = [](std::size_t values) {
        std::string s = "[";
        for (std::size_t i = 1; i < values; ++i)
            s += "1,";
        s += "1]";
        return s;
    };
    CHECK_FALSE(json_exceeds_value_budget(at_budget(yuzu::server::kMaxDefinitionJsonValues)));
    CHECK(json_exceeds_value_budget(at_budget(yuzu::server::kMaxDefinitionJsonValues + 1)));
    std::string hostile = "[";
    for (int i = 0; i < 150'000; ++i)
        hostile += "[],";
    hostile += "[]]";
    CHECK(json_exceeds_value_budget(hostile));
    CHECK_FALSE(json_exceeds_value_budget(""));
}

// M2-1 fail closed. A failing or unwired lookup is never "no referrers": 503, nothing deleted, an
// `error` row. An id that does not exist keeps its 404 whatever the wiring. Turns red if the handler
// treats an error or an unset function as an empty list.
TEST_CASE("instruction_routes: DELETE with a failing or unwired referrer lookup is a 503 and "
          "deletes nothing; a missing id is still 404",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness maker;
    maker.store = &w.store;
    maker.wire();
    auto create = maker.sink.Post("/api/instructions",
                                  json{{"name", "Keep"},
                                       {"plugin", "os_info"},
                                       {"action", "os_name"},
                                       {"type", "question"}}
                                      .dump());
    REQUIRE(create);
    const auto id = body(create->body)["id"].get<std::string>();

    Harness h;
    h.store = &w.store;
    SECTION("failing") {
        h.referrers = [](const std::string&)
            -> std::expected<std::vector<yuzu::server::DefinitionReferrer>, std::string> {
            return std::unexpected(std::string("schedule read failed"));
        };
    }
    SECTION("unwired") {
        h.referrers_wired = false;
    }
    h.wire();
    auto del = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 503);
    CHECK(del->body.find("nothing was deleted") != std::string::npos);
    CHECK(json::parse(del->get_header_value("HX-Trigger"))["showToast"]["level"] == "error");
    auto still = w.store.get_definition(id);
    REQUIRE(still.has_value());
    CHECK(still->has_value());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.delete");
    CHECK(h.audits[0].result == "error");
    CHECK(h.emits.empty());

    h.audits.clear();
    auto missing = h.sink.Delete("/api/instructions/no.such.definition");
    REQUIRE(missing);
    CHECK(missing->status == 404);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].detail == "not_found");
}

// N1-6b. The legacy DELETE's pre-image read failing is a 503 with ONE `error` row (detail
// `db_error`), nothing deleted and no event; with the sink down the answer carries
// Sec-Audit-Failed. Turns red if the `if (!stored) return refuse(503, "error", "db_error", ...)`
// branch is removed (the delete would then run against an unreadable store and answer from the
// delete's own failure, with a different row and message).
TEST_CASE("instruction_routes: DELETE with an unreadable definition store is a 503 db_error row and "
          "deletes nothing",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Unreadable"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"}}
                                  .dump());
    REQUIRE(create);
    const auto id = body(create->body)["id"].get<std::string>();
    h.audits.clear();
    h.emits.clear();

    yuzu::test::SqlFault broken(
        w.pool,
        "ALTER TABLE instruction_store.instruction_definitions RENAME TO "
        "instruction_definitions_gone",
        "ALTER TABLE instruction_store.instruction_definitions_gone RENAME TO "
        "instruction_definitions");
    broken.arm();
    auto del = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 503);
    CHECK(del->body.find("nothing was deleted") != std::string::npos);
    CHECK(del->get_header_value("Sec-Audit-Failed").empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.delete");
    CHECK(h.audits[0].result == "error");
    CHECK(h.audits[0].detail == "db_error");
    CHECK(h.emits.empty());
    // The sink down: the same 503 now carries the lost-row signal the v1 twin asserts.
    h.audit_succeeds = false;
    auto lost = h.sink.Delete("/api/instructions/" + id);
    broken.repair();
    REQUIRE(lost);
    CHECK(lost->status == 503);
    CHECK(lost->get_header_value("Sec-Audit-Failed") == "true");
    auto still = w.store.get_definition(id);
    REQUIRE(still.has_value());
    CHECK(still->has_value());
}

// M2-3. The packs that contain the deleted definition are noted on the success row, bounded at
// five ids plus `+N`; a failing pack read changes nothing. Turns red if the legacy handler stops
// appending the note, or lets a failing lookup block or alter the delete.
TEST_CASE("instruction_routes: DELETE notes the containing packs on the success row (bounded); a "
          "failing pack lookup neither blocks nor changes the delete",
          "[pg][server][routes][instruction_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    std::string seen_id;
    bool expect_note = false;
    bool existed_at_lookup = false; // N1-5: the pack read happens BEFORE the delete
    SECTION("seven packs") {
        expect_note = true;
        h.pack_advisory = [&](const std::string& id)
            -> std::expected<std::vector<std::string>, std::string> {
            seen_id = id;
            const auto row = w.store.get_definition(id);
            existed_at_lookup = row.has_value() && row->has_value();
            return std::vector<std::string>{"p1", "p2", "p3", "p4", "p5", "p6", "p7"};
        };
    }
    SECTION("failing") {
        h.pack_advisory = [](const std::string&)
            -> std::expected<std::vector<std::string>, std::string> {
            return std::unexpected(std::string("pack read failed"));
        };
    }
    h.wire();
    auto create = h.sink.Post("/api/instructions",
                              json{{"name", "Packed"},
                                   {"plugin", "os_info"},
                                   {"action", "os_name"},
                                   {"type", "question"}}
                                  .dump());
    REQUIRE(create);
    const auto id = body(create->body)["id"].get<std::string>();
    h.audits.clear();
    auto del = h.sink.Delete("/api/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
    if (!expect_note) {
        CHECK(h.audits[0].detail.find("packs=") == std::string::npos);
    } else {
        CHECK(seen_id == id);
        CHECK(existed_at_lookup);
        CHECK(h.audits[0].detail.starts_with("name=Packed plugin=os_info "));
        CHECK(h.audits[0].detail.ends_with(" enabled=true packs=p1,p2,p3,p4,p5,+2"));
        CHECK(h.audits[0].detail.find("p6") == std::string::npos);
    }
}
