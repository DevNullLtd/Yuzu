/**
 * test_instruction_fragment_routes.cpp — route-handler coverage for the
 * 2-route Instructions HTMX fragment pair (#2542 PR-12): the
 * definitions-list fragment and the server-side YAML highlight+validate
 * preview.
 *
 * The yaml-preview route needs no store at all (pure `validate_yaml_source`
 * + the locally-moved `highlight_yaml` — see instruction_fragment_routes.hpp
 * for why those three functions moved rather than being promoted), so its
 * coverage needs no Postgres. The definitions-list fragment's null/degraded
 * "Not available" degrade is likewise Postgres-free; a `[pg]` case proves
 * the real-store rendering path (row content, can_author gating).
 */

#include "instruction_fragment_routes.hpp"
#include "test_route_sink.hpp"

#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include <yuzu/server/auth.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct DenyCall {
    std::string action, message, target_type, target_id;
};

// Minimal application/x-www-form-urlencoded encoder for this file's raw
// multi-line YAML bodies — TestRouteSink's form-body parsing
// (httplib::detail::parse_query_text) expects genuinely percent-encoded
// values, so a literal newline/colon in the body would not round-trip.
std::string url_encode(const std::string& s) {
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else if (c == ' ') {
            out += '+';
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention).
struct Harness {
    InstructionStore* store{nullptr};

    bool deny_service_scoped{false};
    std::vector<DenyCall> deny_calls;

    bool auth_allow{true};
    std::string auth_username{"alice"};
    auth::Role auth_role{auth::Role::user};

    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perm_calls;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        instruction_fragment::Deps deps;
        deps.store = store;
        deps.deny_service_scoped_fn =
            [this](const httplib::Request&, httplib::Response& res, const std::string& action,
                   const std::string& message, const std::string& target_type,
                   const std::string& target_id) -> bool {
            deny_calls.push_back({action, message, target_type, target_id});
            if (deny_service_scoped) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return true;
            }
            return false;
        };
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
            s.role = auth_role;
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
        instruction_fragment::register_instruction_fragment_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("instruction_fragment_routes: registers exactly 2 routes",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 2);
}

// ── GET /fragments/instructions gates ───────────────────────────────────

TEST_CASE("instruction_fragment_routes: GET /fragments/instructions gates on "
          "deny_service_scoped_fn THEN auth_fn (no perm_fn call at all)",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Get("/fragments/instructions");
    REQUIRE(res);
    REQUIRE(h.deny_calls.size() == 1);
    CHECK(h.deny_calls[0].action == "instructions.fragment.access_denied");
    CHECK(h.deny_calls[0].target_type.empty());
    CHECK(h.deny_calls[0].target_id.empty());
    CHECK(h.perm_calls.empty());
}

TEST_CASE("instruction_fragment_routes: a service-scoped-token denial 403s before auth_fn "
          "runs",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.deny_service_scoped = true;
    h.wire();
    auto res = h.sink.Get("/fragments/instructions");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("instruction_fragment_routes: an unauthenticated caller 401s on "
          "/fragments/instructions",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.auth_allow = false;
    h.wire();
    auto res = h.sink.Get("/fragments/instructions");
    REQUIRE(res);
    CHECK(res->status == 401);
}

TEST_CASE("instruction_fragment_routes: a null store degrades to \"Not available\"",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Get("/fragments/instructions");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Not available") != std::string::npos);
}

// ── POST /fragments/instructions/yaml-preview -- no store needed ───────

TEST_CASE("instruction_fragment_routes: POST yaml-preview gates on "
          "InstructionDefinition:Read",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Post("/fragments/instructions/yaml-preview",
                           "yaml_source=name%3A+test", "application/x-www-form-urlencoded");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] ==
          std::pair<std::string, std::string>{"InstructionDefinition", "Read"});
}

TEST_CASE("instruction_fragment_routes: a perm_fn denial on yaml-preview 403s",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.Post("/fragments/instructions/yaml-preview", "yaml_source=x",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("instruction_fragment_routes: yaml-preview renders highlighted spans and an empty "
          "error div for valid YAML",
          "[server][routes][instruction_fragment_routes]") {
    // A genuinely COMPLETE definition (mirrors test_instruction_yaml.cpp's
    // kFlatPanelYaml) -- validate_yaml_source's required-field checks
    // (apiVersion, kind, metadata.id/name, spec.plugin, spec.action) all
    // need to pass for the "no errors" assertion below to mean anything.
    const std::string yaml = "apiVersion: yuzu.io/v1alpha1\n"
                             "kind: InstructionDefinition\n"
                             "metadata:\n"
                             "  id: tutorial.service.inspect\n"
                             "  version: \"1.0.0\"\n"
                             "spec:\n"
                             "  plugin: \"services\"\n"
                             "  action: \"list\"\n"
                             "  type: question\n";
    Harness h;
    h.wire();
    auto res = h.sink.Post("/fragments/instructions/yaml-preview", "yaml_source=" + url_encode(yaml),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("class=\"yl\"") != std::string::npos); // highlighted line wrapper
    CHECK(res->body.find(R"(id="yaml-errors" hx-swap-oob="innerHTML:#yaml-errors"></div>)") !=
          std::string::npos); // no errors -> empty error div
}

TEST_CASE("instruction_fragment_routes: yaml-preview surfaces validate_yaml_source errors "
          "in the error div",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.wire();
    // Empty source is invalid per validate_yaml_source (missing required fields).
    auto res = h.sink.Post("/fragments/instructions/yaml-preview", "yaml_source=",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("class='err'") != std::string::npos);
}

// ── [pg] case: real InstructionStore rendering ──────────────────────────

namespace {

// Shares the "instructionstore" template key with test_instruction_store.cpp
// / test_instruction_routes.cpp (same store, same migration) — the registry
// builds the named template once per process regardless of which file's
// PgTestTemplate instance triggers it first.
yuzu::test::PgTestTemplate route_instr_frag_tpl{
    "instructionstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instructionstore fragment template: store failed to migrate");
    }};

struct PgWired {
    yuzu::server::pg::PgPool pool;
    InstructionStore store;

    explicit PgWired(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
        store.set_require_signed_definitions(false);
    }
};

InstructionDefinition make_def(const std::string& name) {
    InstructionDefinition def;
    def.name = name;
    def.version = "1.0";
    def.plugin = "system_info";
    def.action = "query";
    def.type = "question";
    def.description = "Test definition: " + name;
    def.enabled = true;
    def.platforms = "windows,linux,darwin";
    def.approval_mode = "auto";
    return def;
}

} // namespace

TEST_CASE("instruction_fragment_routes: GET renders the definitions table, escapes content, "
          "and gates the New/Edit buttons on the admin role",
          "[pg][server][routes][instruction_fragment_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_frag_tpl);
    PgWired w{db.dsn()};
    auto created = w.store.create_definition(make_def("Get Hostname"));
    REQUIRE(created.has_value());

    Harness h;
    h.store = &w.store;
    h.auth_role = auth::Role::user;
    h.wire();

    auto viewer_res = h.sink.Get("/fragments/instructions");
    REQUIRE(viewer_res);
    CHECK(viewer_res->status == 200);
    CHECK(viewer_res->body.find("Get Hostname") != std::string::npos);
    CHECK(viewer_res->body.find("1</strong> definitions") != std::string::npos);
    CHECK(viewer_res->body.find("New Definition") == std::string::npos); // viewer: no author UI

    Harness h_admin;
    h_admin.store = &w.store;
    h_admin.auth_role = auth::Role::admin;
    h_admin.wire();
    auto admin_res = h_admin.sink.Get("/fragments/instructions");
    REQUIRE(admin_res);
    CHECK(admin_res->body.find("New Definition") != std::string::npos);
    CHECK(admin_res->body.find("data-def-id=") != std::string::npos); // Edit button present
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("instruction_fragment_routes: wiring -- server.cpp still calls "
          "register_instruction_fragment_routes",
          "[server][routes][instruction_fragment_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_instruction_fragment_routes(") != std::string::npos);
}
