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

#include <algorithm>
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

    // Render-time probe (Deps::probe_perm_fn). Unwired by default so existing
    // cases exercise the byte-identical "cannot decide" path.
    bool probe_wired{false};
    std::vector<std::string> probe_allow; // "Securable:Op" entries that pass
    std::vector<std::string> probe_calls;

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
        if (probe_wired) {
            deps.probe_perm_fn = [this](const httplib::Request&, const std::string& type,
                                        const std::string& op) {
                probe_calls.push_back(type + ":" + op);
                for (const auto& a : probe_allow)
                    if (a == type + ":" + op)
                        return true;
                return false;
            };
        }
        instruction_fragment::register_instruction_fragment_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("instruction_fragment_routes: registers exactly 3 routes",
          "[server][routes][instruction_fragment_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 3);
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

TEST_CASE("instruction_fragment_routes: yaml-preview wraps each line's text in a yt span "
          "that keeps indentation and escapes values",
          "[server][routes][instruction_fragment_routes]") {
    // The .yl row is a flex container, which drops a whitespace-only text node, so the
    // line text (indentation included) must sit inside one .yt span. Validation errors
    // are irrelevant here: the highlighted lines are emitted either way.
    const std::string yaml = "metadata:\n"
                             "  id: a<b&c\n";
    Harness h;
    h.wire();
    auto res = h.sink.Post("/fragments/instructions/yaml-preview", "yaml_source=" + url_encode(yaml),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The wrapper is emitted and closed on a line with no indentation.
    CHECK(res->body.find(R"(<span class="ln">1</span><span class="yt"><span class="yk">metadata)"
                         R"(</span>:</span></div>)") != std::string::npos);
    // Leading indentation is inside the span, ahead of the key; the value is escaped.
    CHECK(res->body.find(R"(<span class="ln">2</span><span class="yt">  <span class="yk">id)"
                         R"(</span>:<span class="yv"> a&lt;b&amp;c</span></span></div>)") !=
          std::string::npos);
    CHECK(res->body.find("a<b") == std::string::npos); // raw markup never reaches the page
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
    // The restyled Delete button keeps its htmx wiring: the DELETE route and the confirm prompt.
    CHECK(admin_res->body.find("hx-delete=\"/api/instructions/" + *created + "\"") !=
          std::string::npos);
    CHECK(admin_res->body.find("hx-confirm=\"Delete definition 'Get Hostname'?\"") !=
          std::string::npos);
}

TEST_CASE("instruction_fragment_routes: filters, limit+1 truncation, approval column and sets "
          "panel behind render-time probes",
          "[pg][server][routes][instruction_fragment_routes][extras]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_frag_tpl);
    PgWired w{db.dsn()};
    auto set_id = w.store.create_set(InstructionSet{.name = "Triage Set"});
    REQUIRE(set_id.has_value());
    for (const char* n : {"Alpha one", "Alpha two", "Beta three"}) {
        auto d = make_def(n);
        d.approval_mode = (std::string(n) == "Beta three") ? "always" : "auto";
        d.instruction_set_id = (std::string(n) == "Beta three") ? *set_id : "";
        REQUIRE(w.store.create_definition(d).has_value());
    }

    SECTION("default call with no probe wired is the legacy table: no approval column, no sets "
            "panel, no foot") {
        Harness h;
        h.store = &w.store;
        h.wire();
        auto res = h.sink.Get("/fragments/instructions");
        REQUIRE(res);
        CHECK(res->body.find("3</strong> definitions") != std::string::npos);
        CHECK(res->body.find("Needs approval") == std::string::npos);
        CHECK(res->body.find("instruction-sets") == std::string::npos);
        CHECK(res->body.find("data-truncated") == std::string::npos);
        CHECK(h.probe_calls.empty());
    }

    SECTION("limit=2 truncates with an honest foot and never renders the sentinel row") {
        Harness h;
        h.store = &w.store;
        h.wire();
        auto res = h.sink.Get("/fragments/instructions?limit=2");
        REQUIRE(res);
        CHECK(res->body.find("2</strong> definitions") != std::string::npos);
        CHECK(res->body.find("Showing the first 2. Narrow the filter.") != std::string::npos);
        CHECK(res->body.find("Alpha one") != std::string::npos);
        CHECK(res->body.find("Alpha two") != std::string::npos);
        CHECK(res->body.find("Beta three") == std::string::npos);
    }

    SECTION("limit equal to the row count is not truncated") {
        Harness h;
        h.store = &w.store;
        h.wire();
        auto res = h.sink.Get("/fragments/instructions?limit=3");
        REQUIRE(res);
        CHECK(res->body.find("data-truncated") == std::string::npos);
        CHECK(res->body.find("Beta three") != std::string::npos);
    }

    SECTION("name and type filters narrow the list") {
        Harness h;
        h.store = &w.store;
        h.wire();
        auto res = h.sink.Get("/fragments/instructions?name=alpha");
        REQUIRE(res);
        CHECK(res->body.find("2</strong> definitions") != std::string::npos);
        CHECK(res->body.find("Beta three") == std::string::npos);
        auto none = h.sink.Get("/fragments/instructions?type=action");
        REQUIRE(none);
        CHECK(none->body.find("0</strong> definitions") != std::string::npos);
    }

    SECTION("an over-long filter is refused, not shortened") {
        Harness h;
        h.store = &w.store;
        h.wire();
        auto res = h.sink.Get("/fragments/instructions?name=" + std::string(129, 'a'));
        REQUIRE(res);
        CHECK(res->body.find("Filter text is too long.") != std::string::npos);
    }

    SECTION("both probes pass: approval column and sets panel with server-computed counts") {
        Harness h;
        h.store = &w.store;
        h.probe_wired = true;
        h.probe_allow = {"InstructionDefinition:Read", "InstructionSet:Read"};
        h.wire();
        auto res = h.sink.Get("/fragments/instructions");
        REQUIRE(res);
        CHECK(res->body.find("<th>Needs approval</th>") != std::string::npos);
        CHECK(res->body.find("<td>Yes</td>") != std::string::npos);
        CHECK(res->body.find("<td>No</td>") != std::string::npos);
        CHECK(res->body.find("Triage Set") != std::string::npos);
        CHECK(res->body.find("<td>1</td></tr>") != std::string::npos); // one member
        // Probed once per capability per render, never per row (three rows rendered).
        REQUIRE(h.probe_calls.size() == 6);
        for (const char* cap :
             {"InstructionDefinition:Read", "InstructionDefinition:Write",
              "InstructionDefinition:Delete", "InstructionSet:Read", "InstructionSet:Write",
              "InstructionSet:Delete"})
            CHECK(std::count(h.probe_calls.begin(), h.probe_calls.end(), std::string(cap)) == 1);
    }

    SECTION("set counts come from the whole library, not the filtered page") {
        Harness h;
        h.store = &w.store;
        h.probe_wired = true;
        h.probe_allow = {"InstructionDefinition:Read", "InstructionSet:Read"};
        h.wire();
        auto res = h.sink.Get("/fragments/instructions?name=alpha");
        REQUIRE(res);
        CHECK(res->body.find("Beta three") == std::string::npos);
        CHECK(res->body.find("Triage Set") != std::string::npos);
        CHECK(res->body.find("<td>1</td></tr>") != std::string::npos);
    }

    SECTION("probes denied: no approval column, no set data, a denied note instead") {
        Harness h;
        h.store = &w.store;
        h.probe_wired = true; // nothing allowed
        h.wire();
        auto res = h.sink.Get("/fragments/instructions");
        REQUIRE(res);
        CHECK(res->body.find("Needs approval") == std::string::npos);
        CHECK(res->body.find("Triage Set") == std::string::npos);
        CHECK(res->body.find("data-denied=\"true\"") != std::string::npos);
        CHECK(res->body.find("Beta three") != std::string::npos); // the list itself is unchanged
    }
}

TEST_CASE("instruction_fragment_routes: probe-stamped controls follow the permission, not the "
          "role",
          "[pg][server][routes][instruction_fragment_routes][extras]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_frag_tpl);
    PgWired w{db.dsn()};
    auto set_id = w.store.create_set(InstructionSet{.name = "Ops"});
    REQUIRE(set_id.has_value());
    auto def_id = w.store.create_definition(make_def("Disk usage"));
    REQUIRE(def_id.has_value());

    Harness h;
    h.store = &w.store;
    h.auth_role = auth::Role::user; // not an admin: the role test would hide every control
    h.probe_wired = true;
    h.probe_allow = {"InstructionDefinition:Read", "InstructionDefinition:Write",
                     "InstructionDefinition:Delete", "InstructionSet:Read", "InstructionSet:Write",
                     "InstructionSet:Delete"};
    h.wire();
    auto res = h.sink.Get("/fragments/instructions");
    REQUIRE(res);
    const auto& b = res->body;
    CHECK(b.find("New Definition") != std::string::npos);
    CHECK(b.find("data-ox=\"import\"") != std::string::npos);
    CHECK(b.find("class=\"ox-filter\"") != std::string::npos);
    CHECK(b.find("data-ox=\"set-assign\"") != std::string::npos);
    CHECK(b.find("data-ox=\"set-new\"") != std::string::npos);
    CHECK(b.find("data-ox=\"set-delete\"") != std::string::npos);
    CHECK(b.find("data-ox=\"export\"") != std::string::npos);
    CHECK(b.find("hx-get=\"/fragments/instructions/templates?id=" + *def_id + "\"") !=
          std::string::npos);
    CHECK(b.find("id=\"ox-templates\"") != std::string::npos);
    CHECK(b.find("hx-delete=\"/api/instructions/" + *def_id + "\"") != std::string::npos);

    SECTION("write denied: no New, Import, set select or set buttons") {
        h.probe_allow = {"InstructionDefinition:Read", "InstructionDefinition:Delete",
                         "InstructionSet:Read"};
        auto r = h.sink.Get("/fragments/instructions");
        REQUIRE(r);
        CHECK(r->body.find("New Definition") == std::string::npos);
        CHECK(r->body.find("data-ox=\"import\"") == std::string::npos);
        CHECK(r->body.find("data-ox=\"set-assign\"") == std::string::npos);
        CHECK(r->body.find("data-ox=\"set-new\"") == std::string::npos);
        CHECK(r->body.find("data-ox=\"set-delete\"") == std::string::npos);
        CHECK(r->body.find("hx-delete=") != std::string::npos);
    }

    SECTION("delete denied: the row Delete button is not rendered") {
        h.probe_allow = {"InstructionDefinition:Read", "InstructionDefinition:Write"};
        auto r = h.sink.Get("/fragments/instructions");
        REQUIRE(r);
        CHECK(r->body.find("hx-delete=") == std::string::npos);
        CHECK(r->body.find("New Definition") != std::string::npos);
    }
}

TEST_CASE("instruction_fragment_routes: GET /fragments/instructions/templates lists, gates and "
          "degrades",
          "[pg][server][routes][instruction_fragment_routes][extras]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_instr_frag_tpl);
    PgWired w{db.dsn()};
    auto def = make_def("With templates");
    def.response_templates_spec =
        R"([{"id":"aa11","name":"Brief <b>view</b>","columns":["a","b"],"sort":{"column":"a","dir":"desc"},"filters":[{"column":"a","op":"equals","value":"x"}],"default":false}])";
    auto def_id = w.store.create_definition(def);
    REQUIRE(def_id.has_value());

    Harness h;
    h.store = &w.store;
    h.probe_wired = true;
    h.probe_allow = {"InstructionDefinition:Read", "InstructionDefinition:Write"};
    h.wire();

    SECTION("denied is an HTTP 200 data-denied note and never lists a template") {
        h.probe_allow.clear();
        auto r = h.sink.Get("/fragments/instructions/templates?id=" + *def_id);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("data-denied=\"true\"") != std::string::npos);
        CHECK(r->body.find("Brief") == std::string::npos);
        CHECK(h.perm_calls.empty()); // the probe is the gate when wired
    }

    SECTION("lists the built-in default first and escapes names; writers get Edit/Delete") {
        auto r = h.sink.Get("/fragments/instructions/templates?id=" + *def_id);
        REQUIRE(r);
        CHECK(r->status == 200);
        const auto dflt = r->body.find("Default (built in)");
        const auto own = r->body.find("Brief &lt;b&gt;view&lt;/b&gt;");
        REQUIRE(dflt != std::string::npos);
        REQUIRE(own != std::string::npos);
        CHECK(dflt < own);
        CHECK(r->body.find("<b>view</b>") == std::string::npos);
        CHECK(r->body.find("data-ox=\"tpl-new\"") != std::string::npos);
        CHECK(r->body.find("data-ox=\"tpl-edit\"") != std::string::npos);
        CHECK(r->body.find("data-ox=\"tpl-delete\"") != std::string::npos);
        // The built-in row has no actions: exactly one Edit and one Delete (the authored row).
        CHECK(r->body.find("data-tpl-id=\"__default__\"") != std::string::npos);
    }

    SECTION("a reader without Write sees the list and no buttons") {
        h.probe_allow = {"InstructionDefinition:Read"};
        auto r = h.sink.Get("/fragments/instructions/templates?id=" + *def_id);
        REQUIRE(r);
        CHECK(r->body.find("Brief") != std::string::npos);
        CHECK(r->body.find("data-ox=\"tpl-") == std::string::npos);
    }

    SECTION("unknown id reads as not found; a malformed id is refused as unavailable") {
        auto r = h.sink.Get("/fragments/instructions/templates?id=nope");
        REQUIRE(r);
        CHECK(r->body.find("was not found") != std::string::npos);
        auto bad = h.sink.Get("/fragments/instructions/templates?id=a%20b");
        REQUIRE(bad);
        CHECK(bad->body.find("data-degraded=\"1\"") != std::string::npos);
    }
}

TEST_CASE("instruction_fragment_routes: templates without a wired probe fall back to perm_fn",
          "[server][routes][instruction_fragment_routes][extras]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    auto r = h.sink.Get("/fragments/instructions/templates?id=x");
    REQUIRE(r);
    CHECK(r->status == 403);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0].first == "InstructionDefinition");
    CHECK(h.perm_calls[0].second == "Read");
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
