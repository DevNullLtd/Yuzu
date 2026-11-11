/// @file test_instruction_authoring_routes.cpp
/// #2146 batch C: the v1 REST twins of the legacy instruction-definition and instruction-set
/// authoring routes (instruction_authoring_routes.cpp), driven in-process through TestRouteSink,
/// plus the shared pure request builders in instruction_definition_model.cpp the MCP twins also
/// call.
///
/// Split by whether a case needs a live Postgres-backed `InstructionStore` (it has no virtual
/// seam: `RouteDeps::store` is a concrete pointer, like the legacy cluster's):
///   - the pure builder cases, the registration shape, the gate pins, the unwired-dependency
///     refusals, the null-store 503 and the whole validate-yaml route (it never touches the
///     store) run WITHOUT Postgres;
///   - everything that reaches a real store is `[pg]`, gated behind YUZU_TEST_POSTGRES_DSN via a
///     pre-migrated PgTestTemplate sharing test_instruction_store.cpp's "instructionstore" key.

#include "instruction_authoring_routes.hpp"
#include "instruction_definition_model.hpp"
#include "test_route_sink.hpp"

#include "instruction_referrers.hpp"
#include "instruction_store.hpp"
#include "mcp_jsonrpc.hpp" // mcp::kMcpMaxJsonDepth
#include "policy_store.hpp"
#include "schedule_engine.hpp"
#include "workflow_engine.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_instruction_store_faults.hpp" // ExistsProbeFault
#include "test_principal_lock_gate.hpp"      // Workers / wait_for_lock_waiter

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <libpq-fe.h>

#include <algorithm>
#include <array>
#include <barrier>
#include <chrono>
#include <expected>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

struct EmitRow {
    std::string event_type;
    json attrs;
    json payload_data;
};

/// Declaration order: `sink` LAST (its handlers capture `this`).
struct Harness {
    InstructionStore* store{nullptr};

    bool perm_wired{true};
    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perms; ///< every (securable, operation) asked

    bool audit_wired{true};
    /// Rows whose 0-based index is >= this answer "not stored". -1 = every row is stored.
    int audit_fail_from{-1};
    /// Rows whose 0-based index is >= this are recorded and then the sink THROWS. -1 = never.
    int audit_throw_from{-1};
    std::vector<AuditRow> audits;

    std::string session_username{"alice"};
    std::vector<EmitRow> emits;
    bool emit_throws{false}; ///< the event hook records the emission, then throws
    yuzu::MetricsRegistry metrics;

    /// The delete guard's referrer lookup (UP-6). Wired by default to "nothing references it";
    /// `referrers` overrides, `referrers_wired = false` leaves it unset (a fail-closed 503).
    bool referrers_wired{true};
    DefinitionReferrersFn referrers;
    /// The advisory pack lookup (M2-3); unset = no `packs=` note.
    DefinitionPackAdvisoryFn pack_advisory;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        instruction_authoring::RouteDeps deps;
        deps.store = store;
        deps.metrics = &metrics;
        if (referrers_wired)
            deps.referrers_fn =
                referrers ? referrers
                          : DefinitionReferrersFn([](const std::string&)
                                                      -> std::expected<std::vector<DefinitionReferrer>,
                                                                       std::string> {
                                return std::vector<DefinitionReferrer>{};
                            });
        deps.pack_advisory_fn = pack_advisory;
        if (perm_wired)
            deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                  const std::string& type, const std::string& op) {
                perms.emplace_back(type, op);
                if (!perm_allow) {
                    res.status = 403;
                    res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                    "application/json");
                    return false;
                }
                return true;
            };
        if (audit_wired)
            deps.audit_fn = [this](const httplib::Request&, const std::string& a,
                                   const std::string& r, const std::string& tt,
                                   const std::string& ti, const std::string& d) -> bool {
                const int index = static_cast<int>(audits.size());
                audits.push_back({a, r, tt, ti, d});
                if (audit_throw_from >= 0 && index >= audit_throw_from)
                    throw std::runtime_error("audit sink down");
                return audit_fail_from < 0 || index < audit_fail_from;
            };
        deps.resolve_session_fn = [this](const httplib::Request&) -> std::optional<auth::Session> {
            if (session_username.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_username;
            return s;
        };
        deps.emit_event_fn = [this](const std::string& event_type, const httplib::Request&,
                                    const json& attrs, const json& payload_data) {
            emits.push_back({event_type, attrs, payload_data});
            if (emit_throws)
                throw std::runtime_error("event bus down");
        };
        instruction_authoring::register_instruction_authoring_routes(sink, deps);
    }
};

json body(const std::string& s) { return json::parse(s); }

/// The A4 envelope's message, for asserting on wording without pinning the whole body.
std::string error_message(const std::string& s) {
    return body(s).at("error").at("message").get<std::string>();
}

/// Calls `fn` with the response to every WRITE route (seven), plus the two non-writing routes
/// (GET sets, validate-yaml) when `with_reads`. Responses are move-only, so no braced list of them.
template <class F>
void for_each_route(Harness& h, bool with_reads, F&& fn) {
    fn(h.sink.Post("/api/v1/instructions", "{}"));
    fn(h.sink.Put("/api/v1/instructions/d1", "{}"));
    fn(h.sink.Delete("/api/v1/instructions/d1"));
    fn(h.sink.Post("/api/v1/instructions/import", "{}"));
    fn(h.sink.Post("/api/v1/instructions/yaml", "{}"));
    fn(h.sink.Post("/api/v1/instruction-sets", "{}"));
    fn(h.sink.Delete("/api/v1/instruction-sets/s1"));
    if (with_reads) {
        fn(h.sink.Post("/api/v1/instructions/validate-yaml", "{}"));
        fn(h.sink.Get("/api/v1/instruction-sets"));
    }
}

constexpr const char* kYaml = "---\n"
                              "apiVersion: yuzu.io/v1alpha1\n"
                              "kind: InstructionDefinition\n"
                              "metadata:\n"
                              "  id: test.authoring.yaml\n"
                              "  displayName: Authoring YAML\n"
                              "spec:\n"
                              "  plugin: os_info\n"
                              "  action: os_name\n"
                              "  type: question\n";

} // namespace

// ── Pure builders (no Postgres) ───────────────────────────────────────────────

TEST_CASE("definition create builder: legacy defaults; lowercased action; created_by stamped",
          "[server][instruction_authoring][builder]") {
    auto def = build_definition_from_create_body(
        json{{"name", "n"}, {"type", "question"}, {"plugin", "os_info"}, {"action", "OS_Name"}},
        "alice");
    REQUIRE(def.has_value());
    CHECK(def->action == "os_name");
    CHECK(def->version == "1.0");
    CHECK(def->enabled);
    CHECK(def->gather_ttl_seconds == 300);
    CHECK(def->response_ttl_days == 90);
    CHECK(def->approval_mode == "auto");
    CHECK(def->created_by == "alice");
    CHECK(def->yaml_source.empty());
    CHECK(def->parameter_schema.empty());
}

TEST_CASE("definition create builder: strict shape refuses what the legacy parser coerces or drops",
          "[server][instruction_authoring][builder]") {
    const auto refused = [](json b) {
        return !build_definition_from_create_body(b, "alice").has_value();
    };
    CHECK(refused(json::array()));                                    // not an object
    CHECK(refused(json{{"name", 5}}));                                // wrong type
    CHECK(refused(json{{"enabled", "true"}}));                        // string for bool
    CHECK(refused(json{{"approval_mode", "sometimes"}}));             // outside the vocabulary
    CHECK(refused(json{{"approval_mode", nullptr}}));                 // null is not a string
    CHECK(refused(json{{"gather_ttl_seconds", 0}}));                  // minimum 1
    CHECK(refused(json{{"gather_ttl_seconds", 86401}}));              // maximum 86400
    CHECK(refused(json{{"gather_ttl_seconds", 1.5}}));                // float
    CHECK(refused(json{{"response_ttl_days", 3651}}));                // maximum 3650
    CHECK(refused(json{{"response_ttl_days", "90"}}));                // string for int
    CHECK(refused(json{{"plugin", "bad plugin"}}));                   // charset
    CHECK(refused(json{{"action", "a/b"}}));                          // charset
    CHECK(refused(json{{"plugin", std::string(129, 'p')}}));          // length
    // Columns the legacy route silently drops are refused, so a caller is never misled.
    CHECK(refused(json{{"parameter_schema", "{}"}}));
    CHECK(refused(json{{"yaml_source", "x"}}));
    CHECK(refused(json{{"result_schema", "{}"}}));
    CHECK(refused(json{{"concurrency_mode", "per-device"}}));

    // The bounds are inclusive.
    CHECK_FALSE(refused(json{{"gather_ttl_seconds", 86400}, {"response_ttl_days", 3650}}));
    CHECK_FALSE(refused(json{{"gather_ttl_seconds", 1}, {"response_ttl_days", 1}}));
    CHECK_FALSE(refused(json{{"plugin", std::string(128, 'p')}}));
}

TEST_CASE("definition builders: name/version/description/instruction_set_id/type bounds; create and "
          "update",
          "[server][instruction_authoring][builder][bounds]") {
    const auto create_refused = [](json b) {
        return !build_definition_from_create_body(b, "alice").has_value();
    };
    const auto update_refused = [](json b) {
        InstructionDefinition def;
        def.id = "d1";
        def.name = "old";
        def.type = "question";
        return !apply_definition_update_body(b, def).has_value();
    };
    const std::string big(1024 * 1024 + 1, 'x'); // multi-megabyte bodies are refused by the builder
    for (const auto& refused : {std::function<bool(json)>(create_refused),
                                std::function<bool(json)>(update_refused)}) {
        CHECK(refused(json{{"name", big}}));
        CHECK(refused(json{{"name", std::string(kMaxDefinitionNameLen + 1, 'n')}}));
        CHECK(refused(json{{"name", ""}})); // an explicitly present empty name
        CHECK(refused(json{{"version", std::string(kMaxDefinitionVersionLen + 1, 'v')}}));
        CHECK(refused(json{{"version", ""}}));
        CHECK(refused(json{{"description", std::string(kMaxDefinitionDescriptionLen + 1, 'd')}}));
        CHECK(refused(json{{"instruction_set_id",
                            std::string(kMaxDefinitionInstructionSetIdLen + 1, 's')}}));
        CHECK(refused(json{{"type", "bogus"}}));
        CHECK(refused(json{{"type", ""}}));
        // Inclusive at the limit; an empty description / set id (clears membership) is allowed.
        CHECK_FALSE(refused(json{{"name", std::string(kMaxDefinitionNameLen, 'n')},
                                 {"version", std::string(kMaxDefinitionVersionLen, 'v')},
                                 {"description", std::string(kMaxDefinitionDescriptionLen, 'd')},
                                 {"instruction_set_id",
                                  std::string(kMaxDefinitionInstructionSetIdLen, 's')},
                                 {"type", "action"}}));
        CHECK_FALSE(refused(json{{"description", ""}, {"instruction_set_id", ""}}));
        CHECK_FALSE(refused(json{{"type", "question"}}));
    }
    // PUT only validates what is present; create does not require name at the builder.
    CHECK_FALSE(update_refused(json::object()));
    CHECK_FALSE(update_refused(json{{"description", "only this"}}));
    CHECK_FALSE(create_refused(json::object()));
    // The refusal names the field and is fixed text.
    InstructionDefinition def;
    auto r = apply_definition_update_body(json{{"name", ""}}, def);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "name must be 1 to 128 characters");
    CHECK(is_valid_definition_type("question"));
    CHECK(is_valid_definition_type("action"));
    CHECK_FALSE(is_valid_definition_type("Question"));
}

TEST_CASE("definition create builder: refusal text is fixed and never echoes caller bytes",
          "[server][instruction_authoring][builder]") {
    const std::string hostile = "evil\r\n\x1b[31m<EVILMARK>";
    auto a = build_definition_from_create_body(json{{"approval_mode", hostile}}, "alice");
    REQUIRE_FALSE(a.has_value());
    CHECK(a.error().find("EVILMARK") == std::string::npos);
    CHECK(a.error().find('\r') == std::string::npos);
    auto b = build_definition_from_create_body(json{{hostile, 1}}, "alice");
    REQUIRE_FALSE(b.has_value());
    CHECK(b.error().find("EVILMARK") == std::string::npos);
    auto c = build_definition_from_create_body(json{{"plugin", hostile}}, "alice");
    REQUIRE_FALSE(c.has_value());
    CHECK(c.error().find("EVILMARK") == std::string::npos);
}

TEST_CASE("definition update builder: applies only present keys; refuses id; reads "
          "expected_updated_at",
          "[server][instruction_authoring][builder]") {
    InstructionDefinition def;
    def.id = "d1";
    def.name = "old";
    def.plugin = "os_info";
    def.approval_mode = "always";
    def.yaml_source = "keep me";
    auto r = apply_definition_update_body(
        json{{"description", "new"}, {"action", "Query"}, {"expected_updated_at", 1700000000}},
        def);
    REQUIRE(r.has_value());
    CHECK(r->expected_updated_at == 1700000000);
    CHECK(def.description == "new");
    CHECK(def.action == "query");
    CHECK(def.name == "old");               // untouched
    CHECK(def.approval_mode == "always");   // untouched
    CHECK(def.yaml_source == "keep me");    // never writable here

    CHECK_FALSE(apply_definition_update_body(json{{"id", "other"}}, def).has_value());
    CHECK_FALSE(apply_definition_update_body(json{{"expected_updated_at", -1}}, def).has_value());
    CHECK_FALSE(apply_definition_update_body(json{{"expected_updated_at", "1"}}, def).has_value());
    auto none = apply_definition_update_body(json::object(), def);
    REQUIRE(none.has_value());
    CHECK_FALSE(none->expected_updated_at.has_value());
}

TEST_CASE("describe_dispatch_binding_change: records plugin/action/approval_mode/concurrency_mode/"
          "enabled old -> new and nothing else",
          "[server][instruction_authoring][builder]") {
    InstructionDefinition a;
    a.plugin = "os_info";
    a.action = "os_name";
    a.approval_mode = "always";
    a.concurrency_mode = "per-device";
    a.enabled = true;
    a.description = "x";
    InstructionDefinition b = a;
    CHECK(describe_dispatch_binding_change(a, b).empty());
    b.description = "changed"; // not one of the five
    CHECK(describe_dispatch_binding_change(a, b).empty());
    b.type = "action"; // display only: deliberately not recorded
    CHECK(describe_dispatch_binding_change(a, b).empty());
    b = a;
    b.concurrency_mode = "per-fleet"; // bound into the effect, so it is recorded (UP-13)
    CHECK(describe_dispatch_binding_change(a, b) == "concurrency_mode: per-device -> per-fleet");
    b = a;
    b.approval_mode = "auto";
    CHECK(describe_dispatch_binding_change(a, b) == "approval_mode: always -> auto");
    b.plugin = "remediation";
    b.enabled = false;
    CHECK(describe_dispatch_binding_change(a, b) ==
          "plugin: os_info -> remediation; approval_mode: always -> auto; enabled: true -> false");
    // A stored value from before the twins' charset bound is neutralised, not echoed raw.
    a.action = "a b\nc";
    b = a;
    b.action = "d";
    const auto d = describe_dispatch_binding_change(a, b);
    CHECK(d.find('\n') == std::string::npos);
    CHECK(d.find("action: ") == 0);
}

TEST_CASE("instruction set builder: name and description strings only",
          "[server][instruction_authoring][builder]") {
    auto s = build_instruction_set_from_body(json{{"name", "n"}, {"description", "d"}}, "bob");
    REQUIRE(s.has_value());
    CHECK(s->name == "n");
    CHECK(s->description == "d");
    CHECK(s->created_by == "bob");
    CHECK_FALSE(build_instruction_set_from_body(json{{"name", 1}}, "bob").has_value());
    CHECK_FALSE(build_instruction_set_from_body(json{{"id", "x"}}, "bob").has_value());
    CHECK_FALSE(build_instruction_set_from_body(json::array(), "bob").has_value());
}

// ── Registration shape, gates, unwired dependencies (no Postgres) ─────────────

TEST_CASE("instruction authoring routes: registers exactly the nine v1 routes; literals before {id}",
          "[server][instruction_authoring]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 9);
    const auto routes = h.sink.registered_routes();
    const auto index_of = [&](const std::string& method, const std::string& pattern) {
        for (std::size_t i = 0; i < routes.size(); ++i)
            if (routes[i].first == method && routes[i].second == pattern)
                return static_cast<int>(i);
        return -1;
    };
    CHECK(index_of("POST", "/api/v1/instructions") >= 0);
    CHECK(index_of("PUT", R"(/api/v1/instructions/([^/]+))") >= 0);
    CHECK(index_of("DELETE", R"(/api/v1/instructions/([^/]+))") >= 0);
    CHECK(index_of("GET", "/api/v1/instruction-sets") >= 0);
    CHECK(index_of("DELETE", R"(/api/v1/instruction-sets/([^/]+))") >= 0);
    // The literal segments register before anything that could read them as an {id}.
    CHECK(index_of("POST", "/api/v1/instructions/import") <
          index_of("POST", "/api/v1/instructions"));
    CHECK(index_of("POST", "/api/v1/instructions/yaml") < index_of("POST", "/api/v1/instructions"));
    CHECK(index_of("POST", "/api/v1/instructions/validate-yaml") <
          index_of("POST", "/api/v1/instructions"));
}

TEST_CASE("instruction authoring routes: each route gates on the documented (securable; operation)",
          "[server][instruction_authoring]") {
    Harness h; // store stays null: a 503 after the gate is fine, the pin is the gate's arguments
    h.wire();
    const auto gate_of = [&](auto&& call) {
        h.perms.clear();
        (void)call();
        REQUIRE(h.perms.size() == 1);
        return h.perms.front();
    };
    using P = std::pair<std::string, std::string>;
    CHECK(gate_of([&] { return h.sink.Post("/api/v1/instructions", "{}"); }) ==
          P{"InstructionDefinition", "Write"});
    CHECK(gate_of([&] { return h.sink.Put("/api/v1/instructions/d1", "{}"); }) ==
          P{"InstructionDefinition", "Write"});
    CHECK(gate_of([&] { return h.sink.Delete("/api/v1/instructions/d1"); }) ==
          P{"InstructionDefinition", "Delete"});
    CHECK(gate_of([&] { return h.sink.Post("/api/v1/instructions/import", "{}"); }) ==
          P{"InstructionDefinition", "Write"});
    CHECK(gate_of([&] { return h.sink.Post("/api/v1/instructions/yaml", "{}"); }) ==
          P{"InstructionDefinition", "Write"});
    CHECK(gate_of([&] {
              return h.sink.Post("/api/v1/instructions/validate-yaml", R"({"yaml_source":"x"})");
          }) == P{"InstructionDefinition", "Read"});
    CHECK(gate_of([&] { return h.sink.Get("/api/v1/instruction-sets"); }) ==
          P{"InstructionSet", "Read"});
    CHECK(gate_of([&] { return h.sink.Post("/api/v1/instruction-sets", "{}"); }) ==
          P{"InstructionSet", "Write"});
    CHECK(gate_of([&] { return h.sink.Delete("/api/v1/instruction-sets/s1"); }) ==
          P{"InstructionSet", "Delete"});
}

TEST_CASE("instruction authoring routes: a gate denial is 403 and touches nothing else",
          "[server][instruction_authoring]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    for_each_route(h, /*with_reads=*/true, [](auto r) {
        REQUIRE(r);
        CHECK(r->status == 403);
    });
    CHECK(h.audits.empty());
    CHECK(h.emits.empty());
}

TEST_CASE("instruction authoring routes: an unwired gate refuses 500; never 'no gate'",
          "[server][instruction_authoring]") {
    Harness h;
    h.perm_wired = false;
    h.wire();
    auto r = h.sink.Post("/api/v1/instructions", R"({"name":"n"})");
    REQUIRE(r);
    CHECK(r->status == 500);
    CHECK(h.audits.empty());
}

TEST_CASE("instruction authoring routes: an unwired audit sink refuses every write 503 "
          "Sec-Audit-Failed; but not the reads",
          "[server][instruction_authoring]") {
    Harness h;
    h.audit_wired = false;
    h.wire();
    for_each_route(h, /*with_reads=*/false, [](auto r) {
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    });
    // validate-yaml needs no audit sink and no store.
    auto v = h.sink.Post("/api/v1/instructions/validate-yaml", json{{"yaml_source", kYaml}}.dump());
    REQUIRE(v);
    CHECK(v->status == 200);
}

TEST_CASE("instruction authoring routes: a missing store is 503 with a retry hint and no audit row",
          "[server][instruction_authoring]") {
    Harness h; // store null
    h.wire();
    for_each_route(h, /*with_reads=*/false, [](auto r) {
        REQUIRE(r);
        CHECK(r->status == 503);
        const auto j = body(r->body);
        CHECK(j["error"]["code"] == 503);
        CHECK(j["error"]["retry_after_ms"] == 5000);
        CHECK(j["error"]["correlation_id"].is_string());
        CHECK(j["meta"]["api_version"] == "v1");
    });
    auto sets = h.sink.Get("/api/v1/instruction-sets");
    REQUIRE(sets);
    CHECK(sets->status == 503);
    CHECK(h.audits.empty());
}

// ── validate-yaml: JSON, never HTML, and never touches the store ─────────────

TEST_CASE("POST /api/v1/instructions/validate-yaml answers JSON {valid; errors}; not HTML",
          "[server][instruction_authoring]") {
    Harness h; // no store
    h.wire();

    auto ok = h.sink.Post("/api/v1/instructions/validate-yaml", json{{"yaml_source", kYaml}}.dump());
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->get_header_value("Content-Type").find("application/json") == 0);
    const auto okj = body(ok->body);
    CHECK(okj["data"]["valid"] == true);
    CHECK(okj["data"]["errors"].is_array());
    CHECK(okj["data"]["errors"].empty());
    CHECK(ok->body.find("<div") == std::string::npos);

    // A hostile value in the document is returned inside a JSON string, never as markup.
    auto bad = h.sink.Post("/api/v1/instructions/validate-yaml",
                           json{{"yaml_source", "kind: <script>alert(1)</script>\n"}}.dump());
    REQUIRE(bad);
    CHECK(bad->status == 200); // a validation result, not a request error
    const auto badj = body(bad->body);
    CHECK(badj["data"]["valid"] == false);
    CHECK(badj["data"]["errors"].size() >= 1);
    CHECK(bad->body.find("<div") == std::string::npos);

    // yaml_source is required: an empty object is a request error, not a validation result.
    auto missing = h.sink.Post("/api/v1/instructions/validate-yaml", "{}");
    REQUIRE(missing);
    CHECK(missing->status == 400);
    CHECK(missing->body.find("yaml_source is required") != std::string::npos);

    CHECK(h.audits.empty()); // a pure read, never audited
}

TEST_CASE("POST /api/v1/instructions/validate-yaml: a plugin or action a save would refuse is not "
          "valid",
          "[server][instruction_authoring]") {
    Harness h; // no store
    h.wire();
    const auto yaml_with = [](const std::string& plugin, const std::string& action) {
        return "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n"
               "  id: test.authoring.validate\n  displayName: V\nspec:\n  plugin: " + plugin +
               "\n  action: " + action + "\n  type: question\n";
    };
    const auto errors_of = [&](const std::string& y) {
        auto r = h.sink.Post("/api/v1/instructions/validate-yaml", json{{"yaml_source", y}}.dump());
        REQUIRE(r);
        REQUIRE(r->status == 200);
        const auto j = body(r->body);
        return std::pair{j["data"]["valid"].get<bool>(), j["data"]["errors"].dump()};
    };
    const auto [ok, ok_errs] = errors_of(yaml_with("os_info", "os_name"));
    CHECK(ok);
    CHECK(ok_errs == "[]");
    const auto [v1, e1] = errors_of(yaml_with("\"my plugin\"", "os_name"));
    CHECK_FALSE(v1);
    CHECK(e1.find("plugin") != std::string::npos);
    const auto [v2, e2] = errors_of(yaml_with(std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'p'), "os_name"));
    CHECK_FALSE(v2);
    CHECK(e2.find("plugin") != std::string::npos);
    const auto [v3, e3] = errors_of(yaml_with("os_info", std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'a')));
    CHECK_FALSE(v3);
    CHECK(e3.find("action") != std::string::npos);
    const auto [v4, e4] = errors_of(yaml_with("os_info", "\"bad action\""));
    CHECK_FALSE(v4);
    CHECK(e4.find("action") != std::string::npos);
    CHECK(h.audits.empty());
}

TEST_CASE("POST /api/v1/instructions/validate-yaml: strict request shape",
          "[server][instruction_authoring]") {
    Harness h;
    h.wire();
    const auto status_of = [&](const std::string& b) {
        auto r = h.sink.Post("/api/v1/instructions/validate-yaml", b);
        REQUIRE(r);
        return r->status;
    };
    CHECK(status_of("not json") == 400);
    CHECK(status_of("[]") == 400);
    CHECK(status_of(R"({"yaml_source":5})") == 400);
    CHECK(status_of(R"({"yaml_source":"x","extra":1})") == 400);
    CHECK(status_of(std::string(200, '[') + std::string(200, ']')) == 400); // nests too deeply
    auto r = h.sink.Post("/api/v1/instructions/validate-yaml", "not json");
    REQUIRE(r);
    CHECK(error_message(r->body) == "request body is not valid JSON");
}

// ── [pg] cases: real InstructionStore ───────────────────────────────────────

namespace {

yuzu::test::PgTestTemplate authoring_tpl{
    "instructionstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instructionstore authoring template: store failed to migrate");
    }};

struct PgWired {
    yuzu::server::pg::PgPool pool;
    InstructionStore store;

    explicit PgWired(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
    }

    /// The stored row for `id`, or nullopt when absent (a read fault fails the test).
    std::optional<InstructionDefinition> get(const std::string& id) {
        auto r = store.get_definition(id);
        REQUIRE(r.has_value());
        return *r;
    }

    /// The stored row for `id`; the row being absent fails the test (no unchecked dereference).
    InstructionDefinition row(const std::string& id) {
        auto r = get(id);
        REQUIRE(r.has_value());
        return *r;
    }
};

std::string create_def(Harness& h, const json& extra = json::object()) {
    json b{{"name", "Hostname"}, {"type", "question"}, {"plugin", "os_info"}, {"action", "os_name"}};
    b.update(extra);
    auto r = h.sink.Post("/api/v1/instructions", b.dump());
    REQUIRE(r);
    REQUIRE(r->status == 201);
    return body(r->body)["data"]["id"].get<std::string>();
}

} // namespace

TEST_CASE("POST /api/v1/instructions: 201 {id}; attempted then success rows; event; created_by",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Post("/api/v1/instructions",
                         json{{"name", "Get Hostname"},
                              {"type", "question"},
                              {"plugin", "os_info"},
                              {"action", "OS_Name"}}
                             .dump());
    REQUIRE(r);
    CHECK(r->status == 201);
    const auto j = body(r->body);
    CHECK(j["meta"]["api_version"] == "v1");
    const auto id = j["data"]["id"].get<std::string>();
    REQUIRE(!id.empty());

    const auto stored = w.get(id);
    REQUIRE(stored.has_value());
    CHECK(stored->action == "os_name");
    CHECK(stored->created_by == "alice");
    CHECK(stored->approval_mode == "auto");
    CHECK(stored->gather_ttl_seconds == 300);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction.create");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_type == "InstructionDefinition");
    CHECK(h.audits[0].detail.find("approval_mode=auto") != std::string::npos);
    CHECK(h.audits[1].action == "instruction.create");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == id);
    CHECK(r->get_header_value("Sec-Audit-Failed").empty());
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "instruction.created");
    CHECK(h.emits[0].payload_data["instruction_id"] == id);
}

TEST_CASE("POST /api/v1/instructions: validation refusals are 400; fixed text; no audit row; no write",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const auto status_of = [&](const std::string& b) {
        auto r = h.sink.Post("/api/v1/instructions", b);
        REQUIRE(r);
        return std::pair{r->status, r->body};
    };
    CHECK(status_of("not json").first == 400);
    CHECK(status_of("[1]").first == 400);
    CHECK(status_of(R"({"name":5})").first == 400);
    CHECK(status_of(R"({"name":"n","approval_mode":"maybe"})").first == 400);
    CHECK(status_of(R"({"name":"n","gather_ttl_seconds":0})").first == 400);
    CHECK(status_of(R"({"name":"n","yaml_source":"x"})").first == 400);
    // A malformed legacy-style body never leaks a parser message (no e.what()).
    const auto [st, raw] = status_of(R"({"name":)");
    CHECK(st == 400);
    CHECK(error_message(raw) == "request body is not valid JSON");

    CHECK(h.audits.empty());
    CHECK(h.emits.empty());
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

TEST_CASE("POST/PUT /api/v1/instructions: the shared bounds are refused 400 before any store call "
          "or audit row",
          "[pg][server][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h, json{{"description", "keep"}});
    const auto before = w.get(id);
    REQUIRE(before.has_value());
    h.audits.clear();
    h.emits.clear();

    const std::vector<json> bad_fields = {
        json{{"name", std::string(1024 * 1024, 'n')}}, json{{"name", ""}},
        json{{"type", "bogus"}},
        json{{"description", std::string(kMaxDefinitionDescriptionLen + 1, 'd')}},
        json{{"version", std::string(kMaxDefinitionVersionLen + 1, 'v')}},
        json{{"instruction_set_id", std::string(kMaxDefinitionInstructionSetIdLen + 1, 's')}}};
    for (const auto& f : bad_fields) {
        auto put = h.sink.Put("/api/v1/instructions/" + id, f.dump());
        REQUIRE(put);
        CHECK(put->status == 400);
        json c = f;
        c["name"] = c.contains("name") ? c["name"] : json("n");
        c["type"] = c.contains("type") ? c["type"] : json("question");
        c["plugin"] = "os_info";
        auto post = h.sink.Post("/api/v1/instructions", c.dump());
        REQUIRE(post);
        CHECK(post->status == 400);
    }
    CHECK(h.audits.empty());
    CHECK(h.emits.empty());
    const auto after = w.get(id);
    REQUIRE(after.has_value());
    CHECK(after->updated_at == before->updated_at);
    CHECK(after->name == before->name);
    CHECK(after->type == before->type);
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->size() == 1); // only the one created above: no create got through
}

TEST_CASE("POST /api/v1/instructions: store refusals are audited denied after the attempt "
          "(duplicate id 409; missing name 400)",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    create_def(h, json{{"id", "authoring.dup"}});
    h.audits.clear();
    auto dup = h.sink.Post("/api/v1/instructions",
                           json{{"id", "authoring.dup"},
                                {"name", "again"},
                                {"type", "question"},
                                {"plugin", "os_info"}}
                               .dump());
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(error_message(dup->body).find("conflict:") == std::string::npos); // prefix stripped
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "duplicate_id");

    h.audits.clear();
    auto nameless = h.sink.Post("/api/v1/instructions",
                                json{{"type", "question"}, {"plugin", "os_info"}}.dump());
    REQUIRE(nameless);
    CHECK(nameless->status == 400);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "invalid");
}

TEST_CASE("POST /api/v1/instructions: an explicit id of '.' or '..' is a controlled 400 and "
          "creates nothing (up-16)",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    for (const char* bad : {".", ".."}) {
        auto r = h.sink.Post("/api/v1/instructions",
                             json{{"id", bad},
                                  {"name", "n"},
                                  {"type", "question"},
                                  {"plugin", "os_info"}}
                                 .dump());
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(error_message(r->body) == "definition id may not be '.' or '..'");
    }
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

TEST_CASE("POST /api/v1/instructions: an attempt row that is not stored refuses 503 and creates "
          "nothing (audit-first)",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.audit_fail_from = 0;
    h.wire();

    auto r = h.sink.Post("/api/v1/instructions",
                         json{{"id", "authoring.refused"},
                              {"name", "n"},
                              {"type", "question"},
                              {"plugin", "os_info"}}
                             .dump());
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(body(r->body)["error"]["retry_after_ms"] == 5000);
    REQUIRE(h.audits.size() == 1); // only the attempt was tried
    CHECK(h.audits[0].result == "attempted");
    CHECK_FALSE(w.get("authoring.refused").has_value()); // no mutation
    CHECK(h.emits.empty());
}

TEST_CASE("POST /api/v1/instructions: an outcome row that is not stored keeps the 201 and flags "
          "Sec-Audit-Failed",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.audit_fail_from = 1; // the attempt is stored, the outcome is not
    h.wire();

    auto r = h.sink.Post("/api/v1/instructions",
                         json{{"id", "authoring.outcome"},
                              {"name", "n"},
                              {"type", "question"},
                              {"plugin", "os_info"}}
                             .dump());
    REQUIRE(r);
    CHECK(r->status == 201);
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(w.get("authoring.outcome").has_value());
}

TEST_CASE("v1 definition and set writes: an attempt row whose sink THROWS refuses 503 like a failed "
          "row and mutates nothing",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h, json{{"approval_mode", "always"}});
    InstructionSet seed_set;
    seed_set.id = "throw-set";
    seed_set.name = "Seed set";
    REQUIRE(w.store.create_set(seed_set).has_value());
    h.audits.clear();
    h.emits.clear();

    h.audit_throw_from = 0; // every row from here on throws (after being recorded)
    const auto refused = [&](auto&& r) {
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(body(r->body)["error"]["retry_after_ms"] == 5000);
        // Same as a returned-false row: exactly the one attempt was tried, no outcome row.
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.emits.empty());
        h.audits.clear();
    };
    refused(h.sink.Post("/api/v1/instructions",
                        json{{"id", "authoring.thrown"}, {"name", "n"}, {"type", "question"},
                             {"plugin", "os_info"}}
                            .dump()));
    refused(h.sink.Put("/api/v1/instructions/" + id, R"({"approval_mode":"auto"})"));
    refused(h.sink.Delete("/api/v1/instructions/" + id));
    refused(h.sink.Post("/api/v1/instruction-sets", R"({"name":"thrown set"})"));
    refused(h.sink.Delete("/api/v1/instruction-sets/throw-set"));

    CHECK_FALSE(w.get("authoring.thrown").has_value());
    REQUIRE(w.get(id).has_value());
    CHECK(w.row(id).approval_mode == "always"); // neither updated nor deleted
    const auto sets = w.store.list_sets();
    REQUIRE(sets.has_value());
    CHECK(sets->size() == 1); // neither created nor deleted
}

TEST_CASE("POST /api/v1/instructions: an outcome row whose sink THROWS keeps the 201 and flags "
          "Sec-Audit-Failed",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.audit_throw_from = 1; // the attempt is stored, the outcome throws
    h.wire();

    auto r = h.sink.Post("/api/v1/instructions",
                         json{{"id", "authoring.outcome.thrown"},
                              {"name", "n"},
                              {"type", "question"},
                              {"plugin", "os_info"}}
                             .dump());
    REQUIRE(r);
    CHECK(r->status == 201); // never an unexplained 500 over a write that completed
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(w.get("authoring.outcome.thrown").has_value());
}

TEST_CASE("v1 definition writes: a throwing event hook never changes the answer and counts under "
          "the event's own series",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.emit_throws = true;
    h.wire();
    const auto count = [&](const char* event) {
        return h.metrics.counter("yuzu_server_event_emit_failed_total", {{"event_type", event}})
            .value();
    };

    const auto id = create_def(h); // 201 despite the throw
    CHECK(count("instruction.created") == 1);
    auto put = h.sink.Put("/api/v1/instructions/" + id, R"({"name":"renamed"})");
    REQUIRE(put);
    CHECK(put->status == 200);
    CHECK(count("instruction.updated") == 1);
    auto del = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(count("instruction.deleted") == 1);
    CHECK(count("other") == 0); // none of the three falls into the catch-all bucket
}

TEST_CASE("PUT /api/v1/instructions/{id}: partial update; approval change recorded old -> new",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const auto id = create_def(h, json{{"approval_mode", "always"}, {"description", "keep"}});
    h.audits.clear();
    h.emits.clear();

    auto r = h.sink.Put("/api/v1/instructions/" + id,
                        json{{"approval_mode", "auto"}, {"plugin", "remediation"}}.dump());
    REQUIRE(r);
    CHECK(r->status == 200);
    const auto j = body(r->body);
    CHECK(j["data"]["id"] == id);
    CHECK(j["data"]["updated"] == true);

    const auto stored = w.get(id);
    REQUIRE(stored.has_value());
    CHECK(stored->approval_mode == "auto");
    CHECK(stored->plugin == "remediation");
    CHECK(stored->description == "keep"); // untouched

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction.update");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_id == id);
    CHECK(h.audits[0].detail == "plugin: os_info -> remediation; approval_mode: always -> auto");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == h.audits[0].detail);
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "instruction.updated");
}

TEST_CASE("PUT /api/v1/instructions/{id}: 404; 400 and expected_updated_at mismatch 409",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto missing = h.sink.Put("/api/v1/instructions/no.such.def", R"({"description":"x"})");
    REQUIRE(missing);
    CHECK(missing->status == 404);
    CHECK(h.audits.empty()); // an unknown id is a plain refusal, as on the legacy route

    const auto id = create_def(h);
    h.audits.clear();

    auto with_id = h.sink.Put("/api/v1/instructions/" + id, R"({"id":"other"})");
    REQUIRE(with_id);
    CHECK(with_id->status == 400);
    auto bad_mode = h.sink.Put("/api/v1/instructions/" + id, R"({"approval_mode":"x"})");
    REQUIRE(bad_mode);
    CHECK(bad_mode->status == 400);
    auto bad_json = h.sink.Put("/api/v1/instructions/" + id, "{");
    REQUIRE(bad_json);
    CHECK(bad_json->status == 400);
    CHECK(h.audits.empty());

    const auto before = w.get(id);
    REQUIRE(before.has_value());
    auto stale = h.sink.Put("/api/v1/instructions/" + id,
                            json{{"description", "x"}, {"expected_updated_at", before->updated_at + 1000}}
                                .dump());
    REQUIRE(stale);
    CHECK(stale->status == 409);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "conflict");
    CHECK(w.row(id).description.empty()); // not applied

    auto fresh = h.sink.Put("/api/v1/instructions/" + id,
                            json{{"description", "y"}, {"expected_updated_at", before->updated_at}}
                                .dump());
    REQUIRE(fresh);
    CHECK(fresh->status == 200);
    CHECK(w.row(id).description == "y");
}

TEST_CASE("PUT/DELETE /api/v1/instructions/{id}: an attempt row that is not stored refuses 503 "
          "and mutates nothing",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h, json{{"approval_mode", "always"}});

    h.audit_fail_from = static_cast<int>(h.audits.size()); // every row from here on is lost
    auto put = h.sink.Put("/api/v1/instructions/" + id, R"({"approval_mode":"auto"})");
    REQUIRE(put);
    CHECK(put->status == 503);
    CHECK(put->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(w.row(id).approval_mode == "always"); // the downgrade did NOT happen

    auto del = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 503);
    CHECK(del->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(w.get(id).has_value()); // still there
}

TEST_CASE("DELETE /api/v1/instructions/{id}: 200 {id; deleted}; attempted then success; event; "
          "unknown id is 404 with a denied row",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h);
    h.audits.clear();
    h.emits.clear();

    auto del = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(body(del->body)["data"]["deleted"] == true);
    CHECK_FALSE(w.get(id).has_value());
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction.delete");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "instruction.deleted");

    h.audits.clear();
    auto again = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(again);
    CHECK(again->status == 404);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "not_found");
}

// M3-5: the optional `expected_updated_at` query parameter. Turns red if the parse block in the
// DELETE handler is removed (a malformed value would delete), if the store call stops passing it
// (a stale one would delete), or if the kConflict arm is removed (a stale one would answer 404).
TEST_CASE("DELETE /api/v1/instructions/{id}?expected_updated_at=: valid deletes; malformed is a "
          "400 that deletes nothing; stale is a 409 and the row survives",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h);
    const std::int64_t token = w.row(id).updated_at;
    const std::string path = "/api/v1/instructions/" + id;

    for (const char* bad : {"abc", "", "-1", "+5", "1.5", "99999999999999999999", "5x", " 5"}) {
        INFO(bad);
        h.audits.clear();
        auto r = h.sink.Delete(path + "?expected_updated_at=" + bad);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(r->body.find("expected_updated_at must be a non-negative integer") !=
              std::string::npos);
        CHECK(h.audits.empty()); // refused before the audit-first attempt row
        CHECK(w.get(id).has_value());
    }
    // A repeated parameter with two values is ambiguous: refused the same way (httplib collapses a
    // repeat of the identical pair, so the values must differ).
    auto twice = h.sink.Delete(path + "?expected_updated_at=" + std::to_string(token) +
                               "&expected_updated_at=" + std::to_string(token + 1));
    REQUIRE(twice);
    CHECK(twice->status == 400);
    CHECK(w.get(id).has_value());

    // Stale: 409, the attempted row then a denied/conflict row, nothing deleted, no event.
    h.audits.clear();
    h.emits.clear();
    auto stale = h.sink.Delete(path + "?expected_updated_at=" + std::to_string(token + 1));
    REQUIRE(stale);
    CHECK(stale->status == 409);
    CHECK(stale->body.find("modified since it was loaded") != std::string::npos);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "conflict");
    CHECK(h.emits.empty());
    CHECK(w.row(id).updated_at == token);

    // Current: deleted; a retry of the landed delete is a 404.
    auto ok = h.sink.Delete(path + "?expected_updated_at=" + std::to_string(token));
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK_FALSE(w.get(id).has_value());
    auto again = h.sink.Delete(path + "?expected_updated_at=" + std::to_string(token));
    REQUIRE(again);
    CHECK(again->status == 404);
}

// UP-6. Real stores: a schedule, a live workflow and a policy fragment that name the definition
// each block its delete with a 409 that lists them, write exactly one `denied`/`referenced` row (no
// attempt, no event) and leave the definition in place; removing the referrer lets the delete
// through. Turns red if the `referrers_fn` block in the DELETE handler is removed.
TEST_CASE("DELETE /api/v1/instructions/{id}: a definition that a schedule; workflow or policy "
          "fragment names is refused 409 with the referrers listed and nothing deleted",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    ScheduleEngine schedules{w.pool};
    WorkflowEngine workflows{w.pool};
    PolicyStore policies{w.pool};
    REQUIRE(schedules.is_open());
    REQUIRE(workflows.is_open());
    REQUIRE(policies.is_open());
    Harness h;
    h.store = &w.store;
    h.referrers = make_definition_referrers_fn(&schedules, &workflows, &policies);
    h.wire();
    const auto id = create_def(h);
    h.audits.clear();
    h.emits.clear();

    const auto refused = [&](const std::string& expect_kind_and_id) {
        auto del = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(del);
        CHECK(del->status == 409);
        const auto msg = body(del->body)["error"]["message"].get<std::string>();
        CHECK(msg.find(expect_kind_and_id) != std::string::npos);
        CHECK(msg.find("NOT deleted") != std::string::npos);
        CHECK(w.get(id).has_value());
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "instruction.delete");
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].detail == "referenced");
        CHECK(h.emits.empty());
        h.audits.clear();
    };

    SECTION("a schedule") {
        InstructionSchedule sched;
        sched.name = "nightly";
        sched.definition_id = id;
        sched.frequency_type = "interval";
        sched.interval_minutes = 60;
        sched.scope_expression = "ostype = 'linux'";
        sched.created_by = "alice";
        auto sid = schedules.create_schedule(sched);
        REQUIRE(sid.has_value());
        refused("schedule " + *sid);
        REQUIRE(schedules.delete_schedule(*sid, "alice"));
        auto ok = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(ok);
        CHECK(ok->status == 200);
    }
    SECTION("a disabled schedule still blocks the delete") {
        InstructionSchedule sched;
        sched.name = "paused";
        sched.definition_id = id;
        sched.frequency_type = "interval";
        sched.interval_minutes = 60;
        sched.scope_expression = "ostype = 'linux'";
        sched.created_by = "alice";
        auto sid = schedules.create_schedule(sched);
        REQUIRE(sid.has_value());
        REQUIRE(schedules.set_enabled(*sid, false, "alice"));
        refused("schedule " + *sid);
        REQUIRE(schedules.delete_schedule(*sid, "alice"));
    }
    SECTION("more referrers than the list shows: the real sources cap and state the rest") {
        // kMaxReferrersListed + 2 schedules: the lookup keeps one past the list length, so the
        // message says it shows 20 and that 1 more exists, without reading the whole population.
        std::vector<std::string> sids;
        for (int i = 0; i < 22; ++i) {
            InstructionSchedule sched;
            sched.name = "bulk-" + std::to_string(i);
            sched.definition_id = id;
            sched.frequency_type = "interval";
            sched.interval_minutes = 60;
            sched.scope_expression = "ostype = 'linux'";
            sched.created_by = "alice";
            auto sid = schedules.create_schedule(sched);
            REQUIRE(sid.has_value());
            sids.push_back(*sid);
        }
        auto del = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(del);
        CHECK(del->status == 409);
        const auto msg = body(del->body)["error"]["message"].get<std::string>();
        CHECK(msg.find("referenced by 21 items") != std::string::npos);
        CHECK(msg.find(", and 1 more") != std::string::npos);
        CHECK(w.get(id).has_value());
        for (const auto& sid : sids)
            REQUIRE(schedules.delete_schedule(sid, "alice"));
    }
    SECTION("a live workflow, but not a soft-deleted one") {
        auto wid = workflows.create_workflow("kind: Workflow\nmetadata:\n  displayName: wf\n"
                                             "spec:\n  steps:\n    - instruction: " + id +
                                             "\n      label: only\n");
        REQUIRE(wid.has_value());
        refused("workflow " + *wid);
        REQUIRE(workflows.delete_workflow(*wid).has_value());
        auto ok = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(ok);
        CHECK(ok->status == 200);
    }
    SECTION("a policy fragment's check, fix or post-check") {
        // The fragment is write-once, so each variant is its own fragment; `other` stands in for
        // the sections that do not name the definition.
        const auto fragment = [&](const std::string& fid, const std::string& check,
                                  const std::string& fix, const std::string& post) {
            std::string y = "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\nid: " + fid +
                            "\ndisplayName: f\nspec:\n  check:\n    instruction: " + check +
                            "\n    compliance: \"true\"\n";
            if (!fix.empty())
                y += "  fix:\n    instruction: " + fix + "\n";
            if (!post.empty())
                y += "  postCheck:\n    instruction: " + post + "\n    compliance: \"true\"\n";
            return y;
        };
        const std::vector<std::string> variants = {fragment("frag-check", id, "", ""),
                                                   fragment("frag-fix", "other", id, ""),
                                                   fragment("frag-post", "other", "other", id)};
        for (const auto& yaml : variants) {
            INFO(yaml);
            auto fid = policies.create_fragment(yaml);
            REQUIRE(fid.has_value());
            refused("policy fragment " + *fid);
            REQUIRE(policies.delete_fragment(*fid));
        }
        auto ok = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(ok);
        CHECK(ok->status == 200);
    }
}

// The two lookups the referrer guard is built on, driven directly (Gate 8 F10). Turns red if
// workflows_referencing_instruction stops excluding soft-deleted workflows, stops honouring the
// limit, or fragments_referencing_instruction stops matching one of the check / fix / post-check
// columns (a fragment pointing at a deleted definition silently stops maturing verdicts).
TEST_CASE("workflows_referencing_instruction and fragments_referencing_instruction: exact matches "
          "on every step / column; soft-deleted excluded; limit honoured",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    WorkflowEngine workflows{w.pool};
    PolicyStore policies{w.pool};
    REQUIRE(workflows.is_open());
    REQUIRE(policies.is_open());
    const std::string target = "ref.lookup.target";
    const auto wf_yaml = [](const std::string& first, const std::string& second) {
        return "kind: Workflow\nmetadata:\n  displayName: wf\nspec:\n  steps:\n    - instruction: " +
               first + "\n      label: one\n    - instruction: " + second + "\n      label: two\n";
    };

    SECTION("workflows: any step matches, a different id and a soft-deleted workflow do not") {
        auto first_step = workflows.create_workflow(wf_yaml(target, "other"));
        auto second_step = workflows.create_workflow(wf_yaml("other", target));
        auto unrelated = workflows.create_workflow(wf_yaml("other", "ref.lookup.targetX"));
        auto gone = workflows.create_workflow(wf_yaml(target, target));
        REQUIRE((first_step && second_step && unrelated && gone));
        REQUIRE(workflows.delete_workflow(*gone).has_value());

        auto all = workflows.workflows_referencing_instruction(target, 10);
        REQUIRE(all.has_value());
        CHECK(all->size() == 2);
        CHECK(std::find(all->begin(), all->end(), *first_step) != all->end());
        CHECK(std::find(all->begin(), all->end(), *second_step) != all->end());
        CHECK(std::find(all->begin(), all->end(), *gone) == all->end());
        CHECK(std::find(all->begin(), all->end(), *unrelated) == all->end());

        auto limited = workflows.workflows_referencing_instruction(target, 1);
        REQUIRE(limited.has_value());
        REQUIRE(limited->size() == 1);
        CHECK((*limited)[0] == (*all)[0]); // oldest first, the same row the full list starts with

        auto none = workflows.workflows_referencing_instruction("ref.lookup.nobody", 10);
        REQUIRE(none.has_value());
        CHECK(none->empty());
    }
    SECTION("workflows: exclusions are applied INSIDE the limit, so an excluded row never takes "
            "a slot") {
        auto a = workflows.create_workflow(wf_yaml(target, "other"));
        auto b = workflows.create_workflow(wf_yaml(target, "other"));
        auto c = workflows.create_workflow(wf_yaml(target, "other"));
        REQUIRE((a && b && c));
        auto all = workflows.workflows_referencing_instruction(target, 10);
        REQUIRE(all.has_value());
        REQUIRE(all->size() == 3);
        // Excluding the row the window would start with yields the NEXT row, not an empty answer
        // (a filter applied after the limit would return nothing here).
        auto skipped = workflows.workflows_referencing_instruction(target, 1, {(*all)[0]});
        REQUIRE(skipped.has_value());
        REQUIRE(skipped->size() == 1);
        CHECK((*skipped)[0] == (*all)[1]);
        auto two = workflows.workflows_referencing_instruction(target, 10, {(*all)[0], (*all)[2]});
        REQUIRE(two.has_value());
        REQUIRE(two->size() == 1);
        CHECK((*two)[0] == (*all)[1]);
        // An id with quote, backslash and comma bytes is just an id to exclude, never array syntax.
        auto odd = workflows.workflows_referencing_instruction(target, 10,
                                                               {"a\"b,c\\d", "{x}", ""});
        REQUIRE(odd.has_value());
        CHECK(odd->size() == 3);
    }
    SECTION("fragments: check, fix and post-check each match; an unrelated id and a deleted "
            "fragment do not; limit honoured") {
        const auto fragment = [](const std::string& fid, const std::string& check,
                                 const std::string& fix, const std::string& post) {
            std::string y = "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\nid: " + fid +
                            "\ndisplayName: " + fid + "\nspec:\n  check:\n    instruction: " + check +
                            "\n    compliance: \"true\"\n";
            if (!fix.empty())
                y += "  fix:\n    instruction: " + fix + "\n";
            if (!post.empty())
                y += "  postCheck:\n    instruction: " + post + "\n    compliance: \"true\"\n";
            return y;
        };
        auto in_check = policies.create_fragment(fragment("lk-check", target, "", ""));
        auto in_fix = policies.create_fragment(fragment("lk-fix", "other", target, ""));
        auto in_post = policies.create_fragment(fragment("lk-post", "other", "other", target));
        auto unrelated = policies.create_fragment(
            fragment("lk-unrelated", "ref.lookup.targetX", "ref.lookup.targe", ""));
        auto removed = policies.create_fragment(fragment("lk-removed", target, "", ""));
        for (const auto* r : {&in_check, &in_fix, &in_post, &unrelated, &removed}) {
            INFO("create_fragment error: " << (r->has_value() ? std::string{} : r->error()));
            REQUIRE(r->has_value());
        }
        REQUIRE(policies.delete_fragment(*removed));

        auto all = policies.fragments_referencing_instruction(target, 10);
        REQUIRE(all.has_value());
        CHECK(all->size() == 3);
        for (const auto& id : {*in_check, *in_fix, *in_post})
            CHECK(std::find(all->begin(), all->end(), id) != all->end());
        CHECK(std::find(all->begin(), all->end(), *unrelated) == all->end());
        CHECK(std::find(all->begin(), all->end(), *removed) == all->end());

        auto limited = policies.fragments_referencing_instruction(target, 2);
        REQUIRE(limited.has_value());
        CHECK(limited->size() == 2);
    }
    SECTION("fragments: exclusions are applied INSIDE the limit, so an excluded row never takes "
            "a slot") {
        const auto fragment = [&](const std::string& fid) {
            return "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\nid: " + fid +
                   "\ndisplayName: " + fid + "\nspec:\n  check:\n    instruction: " + target +
                   "\n    compliance: \"true\"\n";
        };
        for (const char* fid : {"ex-a", "ex-b", "ex-c"})
            REQUIRE(policies.create_fragment(fragment(fid)).has_value());
        auto first = policies.fragments_referencing_instruction(target, 1, {"ex-a"});
        REQUIRE(first.has_value());
        REQUIRE(first->size() == 1);
        CHECK((*first)[0] == "ex-b"); // id order: the excluded ex-a took no slot
        auto rest = policies.fragments_referencing_instruction(target, 10, {"ex-a", "ex-c"});
        REQUIRE(rest.has_value());
        REQUIRE(rest->size() == 1);
        CHECK((*rest)[0] == "ex-b");
        auto none = policies.fragments_referencing_instruction(target, 10, {"ex-a", "ex-b", "ex-c"});
        REQUIRE(none.has_value());
        CHECK(none->empty());
    }
}

TEST_CASE("DELETE /api/v1/instructions/{id}: the referrer list is bounded at 20; ids are folded; "
          "and the count of the rest is stated",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.referrers = [](const std::string&)
        -> std::expected<std::vector<DefinitionReferrer>, std::string> {
        std::vector<DefinitionReferrer> r;
        for (int i = 0; i < 25; ++i)
            r.push_back({"schedule", i == 0 ? std::string("evil\x1b[31m\nid") : "s" + std::to_string(i)});
        return r;
    };
    h.wire();
    const auto id = create_def(h);
    auto del = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 409);
    const auto msg = body(del->body)["error"]["message"].get<std::string>();
    CHECK(msg.find("referenced by 25 items") != std::string::npos);
    CHECK(msg.find("and 5 more") != std::string::npos);
    CHECK(msg.find("s19") != std::string::npos);
    CHECK(msg.find("s20") == std::string::npos); // the 21st is counted, not named
    CHECK(msg.find('\x1b') == std::string::npos);
    CHECK(msg.find('\n') == std::string::npos);
    CHECK(w.get(id).has_value());
}

// UP-6 fail closed: a failing or unwired lookup is never "no referrers". Turns red if the handler
// treats an error or an unset function as an empty list.
TEST_CASE("DELETE /api/v1/instructions/{id}: a failing or unwired referrer lookup is a 503 and "
          "nothing is deleted and one error row is written; a missing id is still 404",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    SECTION("failing") {
        h.referrers = [](const std::string&)
            -> std::expected<std::vector<DefinitionReferrer>, std::string> {
            return std::unexpected(std::string("schedule read failed"));
        };
        h.wire();
        const auto id = create_def(h);
        h.audits.clear();
        auto del = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(del);
        CHECK(del->status == 503);
        CHECK(body(del->body)["error"]["retry_after_ms"] == 5000);
        CHECK(w.get(id).has_value());
        // One `error` row and no attempted row: the vocabulary the legacy DELETE writes (sre F3).
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "instruction.delete");
        CHECK(h.audits[0].result == "error");
        CHECK(h.audits[0].detail == "referrer_check_unavailable");
        CHECK(del->get_header_value("Sec-Audit-Failed").empty());
        // A lost row is flagged on the answer, exactly as the other outcome rows are.
        h.audit_fail_from = 0;
        h.audits.clear();
        auto lost = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(lost);
        CHECK(lost->status == 503);
        CHECK(lost->get_header_value("Sec-Audit-Failed") == "true");
    }
    SECTION("unwired") {
        h.wire();
        const auto id = create_def(h);
        Harness bare;
        bare.store = &w.store;
        bare.referrers_wired = false;
        bare.wire();
        auto del = bare.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(del);
        CHECK(del->status == 503);
        // A configuration fault is not retryable: no hint (the MCP twin agrees, H14).
        CHECK(body(del->body)["error"]["retry_after_ms"].is_null());
        CHECK(w.get(id).has_value());
        REQUIRE(bare.audits.size() == 1);
        CHECK(bare.audits[0].action == "instruction.delete");
        CHECK(bare.audits[0].result == "error");
        CHECK(bare.audits[0].detail == "referrer_check_unwired");
        bare.audits.clear();
        auto missing = bare.sink.Delete("/api/v1/instructions/no.such.definition");
        REQUIRE(missing);
        CHECK(missing->status == 404);
    }
}

// N1-5: an unreadable pre-image on the v1 DELETE is a retryable 503 with one `error` row (detail
// `db_error`, the legacy route's vocabulary), no attempted row, nothing deleted; a lost row is
// flagged Sec-Audit-Failed. Turns red if the `!stored` branch stops writing the row.
TEST_CASE("DELETE /api/v1/instructions/{id}: an unreadable definition store is a 503 with one "
          "db_error row and nothing is deleted",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h);
    yuzu::test::SqlFault broken(
        w.pool,
        "ALTER TABLE instruction_store.instruction_definitions RENAME TO "
        "instruction_definitions_gone",
        "ALTER TABLE instruction_store.instruction_definitions_gone RENAME TO "
        "instruction_definitions");
    h.audits.clear();
    broken.arm();
    auto del = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 503);
    CHECK(body(del->body)["error"]["retry_after_ms"] == 5000);
    CHECK(del->get_header_value("Sec-Audit-Failed").empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "instruction.delete");
    CHECK(h.audits[0].result == "error");
    CHECK(h.audits[0].detail == "db_error");
    h.audit_fail_from = 0;
    auto lost = h.sink.Delete("/api/v1/instructions/" + id);
    broken.repair();
    REQUIRE(lost);
    CHECK(lost->status == 503);
    CHECK(lost->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(w.get(id).has_value());
}

// M2-3 (v1 twin): the success OUTCOME row (not the attempt) notes the packs that contain the
// definition, bounded; a failing pack lookup changes neither the response nor the rows. Turns red if
// the DELETE handler stops appending pack_advisory_note or lets it affect the delete.
TEST_CASE("DELETE /api/v1/instructions/{id}: the success row notes the containing packs (bounded); "
          "a failing pack lookup leaves the delete untouched",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    bool expect_note = false;
    // N1-5: the pack read happens BEFORE the delete, so no lookup sits between the delete and its
    // outcome row (the lost-row window); the definition must still exist when it is asked.
    bool existed_at_lookup = false;
    SECTION("seven packs") {
        h.pack_advisory = [&](const std::string& asked)
            -> std::expected<std::vector<std::string>, std::string> {
            const auto row = w.store.get_definition(asked);
            existed_at_lookup = row.has_value() && row->has_value();
            return std::vector<std::string>{"p1", "p2", "p3", "p4", "p5", "p6", "p7"};
        };
        expect_note = true;
    }
    SECTION("failing") {
        h.pack_advisory = [](const std::string&)
            -> std::expected<std::vector<std::string>, std::string> {
            return std::unexpected(std::string("pack read failed"));
        };
    }
    h.wire();
    const auto id = create_def(h);
    h.audits.clear();
    auto del = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    REQUIRE(h.audits.size() == 2); // attempted, then success
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].detail.find("packs=") == std::string::npos);
    CHECK(h.audits[1].result == "success");
    if (expect_note) {
        CHECK(h.audits[1].detail.ends_with(" enabled=true packs=p1,p2,p3,p4,p5,+2"));
        CHECK(existed_at_lookup);
    } else {
        CHECK(h.audits[1].detail.find("packs=") == std::string::npos);
    }
    CHECK_FALSE(w.get(id).has_value());
}

// The referrer lookup's two call forms and its policy naming. The v1 and MCP deletes call the
// one-argument form; the exclusion form and `held_by` are the library half a caller that removes
// related rows together with the definition uses, so they are pinned here on their own.
TEST_CASE("DefinitionReferrersFn: the two call forms and an empty callable stays unwired",
          "[instruction_authoring][referrers]") {
    SECTION("a one-argument callable ignores the exclusions") {
        int calls = 0;
        DefinitionReferrersFn fn{[&](const std::string& id) -> DefinitionReferrersFn::Result {
            ++calls;
            return std::vector<DefinitionReferrer>{{"schedule", id + "-s", {}}};
        }};
        REQUIRE(static_cast<bool>(fn));
        DefinitionReferrerExclusions ex;
        ex.workflow_ids = {"w1"};
        const auto plain = fn("d1");
        const auto excl = fn("d1", ex);
        REQUIRE((plain && excl));
        CHECK(plain->size() == 1);
        CHECK(excl->size() == 1);
        CHECK(calls == 2);
    }
    SECTION("a two-argument callable receives the exclusions, and fn(id) passes none") {
        DefinitionReferrerExclusions seen;
        bool called = false;
        DefinitionReferrersFn fn{[&](const std::string&, const DefinitionReferrerExclusions& ex)
                                     -> DefinitionReferrersFn::Result {
            called = true;
            seen = ex;
            return std::vector<DefinitionReferrer>{};
        }};
        DefinitionReferrerExclusions ex;
        ex.workflow_ids = {"w1", "w2"};
        ex.fragment_ids = {"f1"};
        REQUIRE(fn("d1", ex).has_value());
        CHECK(called);
        CHECK(seen.workflow_ids == ex.workflow_ids);
        CHECK(seen.fragment_ids == ex.fragment_ids);
        REQUIRE(fn("d1").has_value());
        CHECK(seen.workflow_ids.empty());
        CHECK(seen.fragment_ids.empty());
    }
    SECTION("a default, null, null-function-pointer or empty std::function stays unwired") {
        CHECK_FALSE(static_cast<bool>(DefinitionReferrersFn{}));
        CHECK_FALSE(static_cast<bool>(DefinitionReferrersFn{nullptr}));
        using OneArg = DefinitionReferrersFn::Result (*)(const std::string&);
        CHECK_FALSE(static_cast<bool>(DefinitionReferrersFn{static_cast<OneArg>(nullptr)}));
        CHECK_FALSE(static_cast<bool>(DefinitionReferrersFn{
            std::function<DefinitionReferrersFn::Result(const std::string&)>{}}));
        CHECK_FALSE(static_cast<bool>(DefinitionReferrersFn{
            std::function<DefinitionReferrersFn::Result(const std::string&,
                                                        const DefinitionReferrerExclusions&)>{}}));
    }
}

TEST_CASE("describe_definition_referrers: a held_by list names policies bounded and folded",
          "[instruction_authoring][referrers]") {
    SECTION("no held_by: the plain kind and id list") {
        const auto text = describe_definition_referrers({{"schedule", "s1", {}}});
        CHECK(text.find("schedule s1") != std::string::npos);
        CHECK(text.find("used by policy") == std::string::npos);
    }
    SECTION("up to the cap are named as id (name), the name folded; a nameless policy is its id") {
        const auto text = describe_definition_referrers(
            {{"policy fragment", "f1", {{"p1", "Disk check"}, {"p2", ""}}}});
        CHECK(text.find("policy fragment f1 (used by policy p1 (Disk_check), p2)") !=
              std::string::npos);
        CHECK(text.find("+") == std::string::npos);
    }
    SECTION("past the cap the rest are counted") {
        std::vector<HeldByPolicy> held;
        for (std::size_t i = 0; i < kMaxHeldByPoliciesNamed + 1; ++i)
            held.push_back({"p" + std::to_string(i), ""});
        const auto text = describe_definition_referrers({{"policy fragment", "f1", held}});
        CHECK(text.find(", +1)") != std::string::npos);
        CHECK(text.find("p3") == std::string::npos);
    }
    SECTION("a control byte in a policy name never reaches the text") {
        const auto text = describe_definition_referrers(
            {{"policy fragment", "f1", {{"p1", std::string("a\x1b[31mb\nc")}}}});
        CHECK(text.find('\x1b') == std::string::npos);
        CHECK(text.find('\n') == std::string::npos);
    }
}

// UP-6 wiring tripwire: an unwired referrer lookup fails CLOSED (503), so a server.cpp that stops
// wiring it would not leak a delete, it would make every delete refuse. This pins that both
// transports are handed the SAME lookup built from the real stores.
TEST_CASE("instruction authoring: wiring -- server.cpp builds the referrer lookup from the real "
          "stores and hands it to the v1 routes and the MCP server",
          "[server][instruction_authoring]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const std::array<std::string_view, 5> kNeedles = {
        "make_definition_referrers_fn(\n            schedule_engine_.get(), "
        "workflow_engine_.get(), policy_store_.get())",
        "authoring_deps.referrers_fn = definition_referrers_fn;",
        "mcp_server_->set_definition_referrers_fn(definition_referrers_fn);",
        // The advisory pack lookup reaches both delete paths.
        "authoring_deps.pack_advisory_fn = definition_pack_advisory_fn;",
        "mcp_server_->set_definition_pack_advisory_fn(definition_pack_advisory_fn);"};
    const auto wired = [&](const std::string& text) {
        return std::all_of(kNeedles.begin(), kNeedles.end(), [&](std::string_view n) {
            return text.find(n) != std::string::npos;
        });
    };
    CHECK(wired(src));

    // Mutation: dropping any one of the wiring lines from the source turns the tripwire red
    // (each needle is load-bearing, so a pattern that stopped matching cannot pass vacuously).
    for (const std::string_view needle : kNeedles) {
        SECTION(std::string("mutation: ") + std::string(needle.substr(0, 40))) {
            std::string mutated = src;
            const auto at = mutated.find(needle);
            REQUIRE(at != std::string::npos);
            mutated.erase(at, needle.size());
            CHECK_FALSE(wired(mutated));
        }
    }
}

TEST_CASE("DELETE /api/v1/instructions/{id}: a control byte in the id is refused 400 before the "
          "store or the audit trail",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto r = h.sink.Delete(std::string("/api/v1/instructions/a\x1b[31mb"));
    REQUIRE(r);
    CHECK(r->status == 400);
    CHECK(h.audits.empty());
}

TEST_CASE("POST /api/v1/instructions/import: unsigned is refused by default; accepted only when "
          "the operator opted out; the refusal is audited denied",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    REQUIRE(w.store.require_signed_definitions()); // the default
    Harness h;
    h.store = &w.store;
    h.wire();

    const json envelope{{"id", "authoring.import.unsigned"},
                        {"name", "Unsigned"},
                        {"version", "1.0"},
                        {"type", "question"},
                        {"plugin", "os_info"},
                        {"action", "os_name"},
                        {"yaml_source", kYaml}};
    auto refused = h.sink.Post("/api/v1/instructions/import", envelope.dump());
    REQUIRE(refused);
    CHECK(refused->status == 400);
    CHECK_FALSE(w.get("authoring.import.unsigned").has_value());
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction.import");
    CHECK(h.audits[0].result == "attempted");
    // REST counts the request body (`body_bytes`); MCP's `document_bytes` is the document alone.
    CHECK(h.audits[0].target_id == "authoring.import.unsigned");
    CHECK(h.audits[0].detail == "body_bytes=" + std::to_string(envelope.dump().size()));
    CHECK(h.audits[1].result == "denied");
    CHECK_FALSE(h.audits[1].detail.empty()); // the store's stable error text

    w.store.set_require_signed_definitions(false); // --allow-unsigned-definitions
    h.audits.clear();
    auto ok = h.sink.Post("/api/v1/instructions/import", envelope.dump());
    REQUIRE(ok);
    CHECK(ok->status == 201);
    CHECK(body(ok->body)["data"]["id"] == "authoring.import.unsigned");
    CHECK(w.get("authoring.import.unsigned").has_value());
    // The legacy import route emits no platform event, so neither does its twin (turns red if an
    // emit() is added to the import handler without a matching change to the legacy route).
    CHECK(h.emits.empty());
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == "authoring.import.unsigned");

    h.audits.clear();
    auto dup = h.sink.Post("/api/v1/instructions/import", envelope.dump());
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(h.audits[1].detail == "duplicate_id");
}

namespace {
struct Ed25519Pair {
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> pkey{nullptr, &EVP_PKEY_free};
    std::string public_key_hex;
};

std::string to_hex(const unsigned char* p, std::size_t n) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(hex[p[i] >> 4]);
        out.push_back(hex[p[i] & 0x0F]);
    }
    return out;
}

Ed25519Pair generate_ed25519() {
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> kctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), &EVP_PKEY_CTX_free);
    REQUIRE(kctx);
    REQUIRE(EVP_PKEY_keygen_init(kctx.get()) == 1);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(kctx.get(), &raw) == 1);
    Ed25519Pair p{std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)>(raw, &EVP_PKEY_free), {}};
    unsigned char pub[32];
    std::size_t pub_len = sizeof(pub);
    REQUIRE(EVP_PKEY_get_raw_public_key(p.pkey.get(), pub, &pub_len) == 1);
    p.public_key_hex = to_hex(pub, pub_len);
    return p;
}

std::string sign_hex(EVP_PKEY* pkey, std::string_view content) {
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    REQUIRE(ctx);
    REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey) == 1);
    std::size_t sig_len = 64;
    unsigned char sig[64];
    REQUIRE(EVP_DigestSign(ctx.get(), sig, &sig_len,
                           reinterpret_cast<const unsigned char*>(content.data()),
                           content.size()) == 1);
    return to_hex(sig, sig_len);
}
} // namespace

TEST_CASE("POST /api/v1/instructions/import: a validly signed import is accepted; a tampered "
          "document is refused; an incomplete signature is refused",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    REQUIRE(w.store.require_signed_definitions());
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string yaml = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                             "metadata:\n  id: authoring.signed\n  displayName: Signed\n"
                             "spec:\n  type: question\n  execution:\n    plugin: system_info\n"
                             "    action: os_name\n";
    auto kp = generate_ed25519();
    const auto sig = sign_hex(kp.pkey.get(), yaml);
    const auto envelope = [&](const std::string& id, const std::string& y, const std::string& s,
                              const std::string& pub) {
        json j{{"id", id},      {"name", id},    {"version", "1.0"}, {"type", "question"},
               {"plugin", "system_info"}, {"action", "os_name"}, {"yaml_source", y}};
        if (!s.empty())
            j["signature"] = s;
        if (!pub.empty())
            j["publicKey"] = pub;
        return j.dump();
    };

    auto ok = h.sink.Post("/api/v1/instructions/import",
                          envelope("authoring.signed", yaml, sig, kp.public_key_hex));
    REQUIRE(ok);
    CHECK(ok->status == 201);
    CHECK(w.get("authoring.signed").has_value());

    h.audits.clear();
    auto tampered = h.sink.Post(
        "/api/v1/instructions/import",
        envelope("authoring.tampered", yaml + "  # tampered\n", sig, kp.public_key_hex));
    REQUIRE(tampered);
    CHECK(tampered->status == 400);
    CHECK_FALSE(w.get("authoring.tampered").has_value());
    REQUIRE_FALSE(h.audits.empty());
    CHECK(h.audits.back().result == "denied");

    auto incomplete = h.sink.Post("/api/v1/instructions/import",
                                  envelope("authoring.incomplete", yaml, sig, ""));
    REQUIRE(incomplete);
    CHECK(incomplete->status == 400);
    CHECK_FALSE(w.get("authoring.incomplete").has_value());
}

TEST_CASE("POST /api/v1/instructions/import: shape refusals cost no audit row; a lost attempt row "
          "imports nothing",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();

    auto bad = h.sink.Post("/api/v1/instructions/import", "not json");
    REQUIRE(bad);
    CHECK(bad->status == 400);
    auto arr = h.sink.Post("/api/v1/instructions/import", "[]");
    REQUIRE(arr);
    CHECK(arr->status == 400);
    CHECK(h.audits.empty());

    h.audit_fail_from = 0;
    auto r = h.sink.Post("/api/v1/instructions/import",
                         json{{"id", "authoring.import.refused"},
                              {"name", "n"},
                              {"type", "question"},
                              {"plugin", "os_info"},
                              {"yaml_source", kYaml}}
                             .dump());
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(w.get("authoring.import.refused").has_value());
}

TEST_CASE("POST /api/v1/instructions/import: a wrong-typed field is a 400 with an outcome row; "
          "never an uncaught exception",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();

    const json base{{"id", "authoring.import.badtype"},
                    {"name", "n"},
                    {"type", "question"},
                    {"plugin", "os_info"},
                    {"yaml_source", kYaml}};
    const std::vector<std::pair<std::string, json>> cases{
        {"id", 7},
        {"name", json::object()},
        {"enabled", "yes"},
        {"gather_ttl_seconds", "300"},
        {"response_ttl_days", 1.5},
        {"parameter_schema", json::object()},
        {"approval_mode", nullptr}};
    for (const auto& [field, value] : cases) {
        INFO(field);
        json doc = base;
        doc[field] = value;
        h.audits.clear();
        auto r = h.sink.Post("/api/v1/instructions/import", doc.dump());
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(r->body.find("must be a") != std::string::npos);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].result == "denied");
        CHECK_FALSE(w.get("authoring.import.badtype").has_value());
    }
}

TEST_CASE("POST /api/v1/instructions/yaml: create then update; merge keeps columns the YAML cannot "
          "express; updated_at mismatch is 409",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto created = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", kYaml}}.dump());
    REQUIRE(created);
    CHECK(created->status == 201);
    const auto cj = body(created->body);
    CHECK(cj["data"]["id"] == "test.authoring.yaml");
    CHECK(cj["data"]["created"] == true);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction.create");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");
    REQUIRE(h.emits.size() == 1);
    CHECK(h.emits[0].event_type == "instruction.created");

    // Columns the YAML does not carry are set through the JSON route, then must survive a YAML save.
    auto put = h.sink.Put("/api/v1/instructions/test.authoring.yaml",
                          R"({"enabled":false,"gather_ttl_seconds":42,"description":"d"})");
    REQUIRE(put);
    REQUIRE(put->status == 200);
    const auto before = w.get("test.authoring.yaml");
    REQUIRE(before.has_value());

    h.audits.clear();
    const std::string yaml2 = std::string(kYaml) + "  approval: always\n";
    auto updated = h.sink.Post(
        "/api/v1/instructions/yaml",
        json{{"yaml_source", yaml2}, {"id", "test.authoring.yaml"}, {"updated_at", before->updated_at}}
            .dump());
    REQUIRE(updated);
    CHECK(updated->status == 200);
    CHECK(body(updated->body)["data"]["created"] == false);
    const auto after = w.get("test.authoring.yaml");
    REQUIRE(after.has_value());
    CHECK(after->approval_mode == "always");
    CHECK_FALSE(after->enabled);               // carried forward
    CHECK(after->gather_ttl_seconds == 42);    // carried forward
    CHECK(after->yaml_source == yaml2);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction.update");
    CHECK(h.audits[0].detail == "approval_mode: auto -> always");

    auto stale = h.sink.Post(
        "/api/v1/instructions/yaml",
        json{{"yaml_source", yaml2}, {"id", "test.authoring.yaml"}, {"updated_at", 1}}.dump());
    REQUIRE(stale);
    CHECK(stale->status == 409);
}

// UP-5 / M1-5. A PUT that changes a column the YAML merge takes (plugin, action, approval_mode,
// concurrency_mode, name, description, version, type) on a YAML-authored row clears the stored YAML
// (the columns become the authority) and says so in the audit detail; a PUT that touches none (an
// `enabled` toggle) leaves it; a YAML save is the YAML authority and never clears. Turns red if clear_stale_yaml_source is
// not called by the PUT handler (the YAML stays and a later round trip reverts the edit), or if it
// is also applied to the YAML save (the second section).
TEST_CASE("PUT /api/v1/instructions/{id}: an edit to a column the YAML merge takes clears a stored "
          "yaml_source and audits it; an enabled toggle does not; a YAML save never clears",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto created = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", kYaml}}.dump());
    REQUIRE(created);
    REQUIRE(created->status == 201);
    const std::string id = "test.authoring.yaml";
    REQUIRE_FALSE(w.row(id).yaml_source.empty());

    SECTION("each column the YAML merge takes clears it, and the audit detail names which") {
        // concurrency_mode is not an accepted PUT field; the unit case below covers it.
        // `enabled` is deliberately absent: a YAML round trip cannot revert it (the merge
        // never writes it), so a pure toggle leaves the YAML (see the section below).
        // name, description, version and type are the M1-5 additions: the merge takes `name`
        // always and the others whenever the YAML states them, so an edit left a stale YAML that a
        // round trip reverted. Turns red if clear_stale_yaml_source drops any of the four.
        struct Edit {
            const char* field;
            json value;
            const char* named; ///< what the audit detail must say for this field
        };
        const std::vector<Edit> edits = {
            {"approval_mode", "always", "approval_mode: auto -> always"},
            {"plugin", "hardware", "plugin: os_info -> hardware"},
            {"action", "os_version", "action: os_name -> os_version"},
            {"name", "Renamed", "name: Authoring_YAML -> Renamed"},
            {"version", "9.9", "version: 1.0.0 -> 9.9"},
            {"type", "action", "type: question -> action"},
            {"description", "new words", "description: changed 0 -> 9 bytes"}};
        for (const auto& e : edits) {
            INFO(e.field);
            // Restore a YAML-authored row each round (a YAML save is the YAML authority).
            auto cur = w.get(id);
            auto restore = h.sink.Post("/api/v1/instructions/yaml",
                                       json{{"yaml_source", kYaml},
                                            {"id", id},
                                            {"updated_at", cur->updated_at}}
                                           .dump());
            REQUIRE(restore);
            REQUIRE(restore->status == 200);
            REQUIRE(w.row(id).yaml_source == kYaml);
            h.audits.clear();
            auto r = h.sink.Put("/api/v1/instructions/" + id, json{{e.field, e.value}}.dump());
            REQUIRE(r);
            CHECK(r->status == 200);
            CHECK(w.row(id).yaml_source.empty());
            REQUIRE(h.audits.size() == 2);
            for (const auto& row : h.audits) {
                CHECK(row.detail.find("yaml_source cleared") != std::string::npos);
                CHECK(row.detail.find(e.named) != std::string::npos);
            }
            // The cleared text's size and digest ride the audit detail (matches a backup).
            CHECK(h.audits[1].detail.find("yaml_source_bytes=" + std::to_string(std::string(kYaml).size())) !=
                  std::string::npos);
            CHECK(h.audits[1].detail.find("yaml_source_sha256=") != std::string::npos);
        }
    }
    SECTION("a description edit never echoes the text into the audit detail") {
        const std::string words(kMaxDefinitionDescriptionLen, 'w');
        auto r = h.sink.Put("/api/v1/instructions/" + id, json{{"description", words}}.dump());
        REQUIRE(r);
        CHECK(r->status == 200);
        REQUIRE_FALSE(h.audits.empty());
        CHECK(h.audits.back().detail.find("description: changed 0 -> 512 bytes") !=
              std::string::npos);
        CHECK(h.audits.back().detail.find("wwww") == std::string::npos);
    }
    SECTION("a pure enabled toggle leaves the YAML intact (a round trip cannot revert it)") {
        auto r = h.sink.Put("/api/v1/instructions/" + id, R"({"enabled":false})");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(w.row(id).yaml_source == kYaml);
        CHECK_FALSE(w.row(id).enabled);
        REQUIRE_FALSE(h.audits.empty());
        CHECK(h.audits.back().detail.find("yaml_source cleared") == std::string::npos);
        CHECK(h.audits.back().detail.find("enabled: true -> false") != std::string::npos);
    }
    SECTION("the edit survives a later round trip of the (now empty) row: not reverted to the YAML") {
        auto r = h.sink.Put("/api/v1/instructions/" + id, R"({"approval_mode":"always"})");
        REQUIRE(r);
        REQUIRE(r->status == 200);
        REQUIRE(w.row(id).yaml_source.empty());
        CHECK(w.row(id).approval_mode == "always");
    }
    SECTION("a YAML save that changes approval keeps the YAML it was given") {
        h.audits.clear();
        auto cur = w.get(id);
        const std::string yaml2 = std::string(kYaml) + "  approval: always\n";
        auto r = h.sink.Post("/api/v1/instructions/yaml",
                             json{{"yaml_source", yaml2}, {"id", id}, {"updated_at", cur->updated_at}}
                                 .dump());
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(w.row(id).yaml_source == yaml2);
        CHECK(w.row(id).approval_mode == "always");
        REQUIRE_FALSE(h.audits.empty());
        CHECK(h.audits.back().detail.find("yaml_source cleared") == std::string::npos);
    }
    SECTION("a row with no stored YAML is unchanged by the rule") {
        auto j = h.sink.Post("/api/v1/instructions",
                             R"({"name":"j","type":"question","plugin":"os_info","action":"os_name"})");
        REQUIRE(j);
        REQUIRE(j->status == 201);
        const auto jid = body(j->body)["data"]["id"].get<std::string>();
        h.audits.clear();
        auto r = h.sink.Put("/api/v1/instructions/" + jid, R"({"approval_mode":"always"})");
        REQUIRE(r);
        CHECK(r->status == 200);
        REQUIRE_FALSE(h.audits.empty());
        CHECK(h.audits.back().detail.find("yaml_source cleared") == std::string::npos);
    }
}

TEST_CASE("clear_stale_yaml_source: clears only when a non-empty YAML meets a change to a column "
          "the YAML merge takes",
          "[server][instruction_authoring]") {
    InstructionDefinition before;
    before.plugin = "os_info";
    before.action = "os_name";
    before.approval_mode = "auto";
    before.concurrency_mode = "per-device";
    before.enabled = true;
    before.name = "old name";
    before.version = "1";
    before.type = "question";
    before.yaml_source = "yaml";

    const auto cleared_by = [&](const std::function<void(InstructionDefinition&)>& edit) {
        InstructionDefinition def = before;
        edit(def);
        const bool cleared = clear_stale_yaml_source(before, def);
        CHECK(cleared == def.yaml_source.empty());
        return cleared;
    };
    CHECK(cleared_by([](auto& d) { d.plugin = "other"; }));
    CHECK(cleared_by([](auto& d) { d.action = "other"; }));
    CHECK(cleared_by([](auto& d) { d.approval_mode = "always"; }));
    CHECK(cleared_by([](auto& d) { d.concurrency_mode = "unlimited"; }));
    // enabled is not a stale-YAML trigger: the YAML merge never writes it.
    CHECK_FALSE(cleared_by([](auto& d) { d.enabled = false; }));
    // The YAML merge takes name always and description / version / type when stated, so an edit
    // to any of the four would be reverted by a round trip (M1-5).
    CHECK(cleared_by([](auto& d) { d.name = "n"; }));
    CHECK(cleared_by([](auto& d) { d.description = "d"; }));
    CHECK(cleared_by([](auto& d) { d.version = "2"; }));
    CHECK(cleared_by([](auto& d) { d.type = "action"; }));
    CHECK_FALSE(cleared_by([](auto&) {}));

    // Nothing to clear when the stored row has no YAML.
    InstructionDefinition bare = before;
    bare.yaml_source.clear();
    InstructionDefinition edited = bare;
    edited.approval_mode = "always";
    CHECK_FALSE(clear_stale_yaml_source(bare, edited));
    CHECK(describe_dispatch_binding_change(bare, edited).find("yaml_source cleared") ==
          std::string::npos);

    InstructionDefinition cleared = before;
    cleared.approval_mode = "always";
    REQUIRE(clear_stale_yaml_source(before, cleared));
    const auto described = describe_dispatch_binding_change(before, cleared);
    CHECK(described.starts_with("approval_mode: auto -> always; yaml_source cleared "
                                "yaml_source_bytes=4 yaml_source_sha256="));
    // sha256("yaml")
    CHECK(described.ends_with(
        "yaml_source_sha256=9831daaaa0a94144fc3378fde30109ecfc1639ae1d738f35bedbb6ac80210f85"));

    // M1-5: the four fields the YAML merge also takes are named only when the YAML was cleared,
    // with the description as sizes (never its text) and a long name bounded.
    InstructionDefinition all = before;
    all.name = std::string(300, 'n');
    all.version = "2";
    all.type = "action";
    all.description = std::string(5000, 'd');
    REQUIRE(clear_stale_yaml_source(before, all));
    const auto four = describe_dispatch_binding_change(before, all);
    CHECK(four.find("name: old_name -> ") != std::string::npos);
    CHECK(four.find("version: 1 -> 2") != std::string::npos);
    CHECK(four.find("type: question -> action") != std::string::npos);
    CHECK(four.find("description: changed 0 -> 5000 bytes") != std::string::npos);
    CHECK(four.find("yaml_source cleared") != std::string::npos);
    CHECK(four.size() < 700);
    CHECK(four.find(std::string(200, 'n')) == std::string::npos);
    CHECK(four.find("dddd") == std::string::npos);
    // Without a clear (no stored YAML) the same edits stay unrecorded, as before.
    InstructionDefinition bare_edit = bare;
    bare_edit.name = "n";
    bare_edit.description = "d";
    CHECK(describe_dispatch_binding_change(bare, bare_edit).empty());
}

// Gate 8 F11 (cpp-expert #2): the legacy PUT stores plugin / action / concurrency_mode unbounded, so
// the audit detail bounds what it prints but still compares the whole value. Turns red if the
// values go back to being printed raw (a 1 MiB plugin in one audit row) or are compared bounded
// (a change after byte 128 would vanish from the detail).
TEST_CASE("describe_dispatch_binding_change: free-text values are bounded in the detail but "
          "compared whole",
          "[server][instruction_authoring]") {
    InstructionDefinition before;
    before.plugin = std::string(300, 'p');
    before.action = "os_name";
    before.concurrency_mode = std::string(300, 'c');
    InstructionDefinition after = before;
    after.plugin = std::string(299, 'p') + "q"; // differs only past the display bound
    after.concurrency_mode = std::string(300, 'c') + "x";
    const auto detail = describe_dispatch_binding_change(before, after);
    CHECK(detail.find("plugin: ") != std::string::npos);
    CHECK(detail.find("concurrency_mode: ") != std::string::npos);
    CHECK(detail.size() < 600);
    CHECK(detail.find(std::string(200, 'p')) == std::string::npos);
    CHECK(detail.find("...") != std::string::npos);
}

TEST_CASE("POST /api/v1/instructions/yaml: validation; divergent metadata.id; unknown id; shape",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto invalid = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", "kind: x\n"}}.dump());
    REQUIRE(invalid);
    CHECK(invalid->status == 400);
    const auto ij = body(invalid->body);
    CHECK(ij["error"]["errors"].is_array());
    CHECK(ij["error"]["errors"].size() >= 1);
    CHECK(invalid->get_header_value("Content-Type").find("application/json") == 0);

    // Validate-pass implies save-pass: a plugin/action the validator now flags is refused by the
    // save too, with the same error list, before any attempt row or write.
    for (const std::string& bad :
         {std::string("my plugin"), std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'p')}) {
        const std::string y = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                              "metadata:\n  id: test.authoring.badplugin\n  displayName: B\nspec:\n"
                              "  plugin: \"" + bad + "\"\n  action: os_name\n  type: question\n";
        auto v = h.sink.Post("/api/v1/instructions/validate-yaml", json{{"yaml_source", y}}.dump());
        REQUIRE(v);
        CHECK(body(v->body)["data"]["valid"] == false);
        auto sv = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", y}}.dump());
        REQUIRE(sv);
        CHECK(sv->status == 400);
        const auto sj = body(sv->body);
        CHECK(sj["error"]["errors"].dump().find("plugin") != std::string::npos);
        CHECK(sj["error"]["errors"] == body(v->body)["data"]["errors"]);
    }

    auto diverge = h.sink.Post("/api/v1/instructions/yaml",
                               json{{"yaml_source", kYaml}, {"id", "some.other.id"}}.dump());
    REQUIRE(diverge);
    CHECK(diverge->status == 400); // yaml says test.authoring.yaml, the update targets another id

    // Update of an id that does not exist is a plain 404, not a create.
    const std::string matching = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                                 "metadata:\n  id: no.such.def\n  displayName: X\nspec:\n"
                                 "  plugin: os_info\n  action: os_name\n  type: question\n";
    auto missing = h.sink.Post("/api/v1/instructions/yaml",
                               json{{"yaml_source", matching}, {"id", "no.such.def"}}.dump());
    REQUIRE(missing);
    CHECK(missing->status == 404);

    // The request-shape arms are driven with the VALID fixture, so each is the only reason for the
    // refusal: with an invalid source ("x") a deleted arm would still 400 on the YAML and go
    // unnoticed. Turns red if the unknown-key or `updated_at` arm of parse_yaml_save_body is
    // removed (the valid source would then be saved: a 201, an audit row, a stored definition).
    const std::vector<std::pair<std::string, std::string>> shape_refusals{
        {"not json", "not json"},
        {"yaml_source not a string", json{{"yaml_source", 3}}.dump()},
        {"no yaml_source", "{}"},
        {"unknown key", json{{"yaml_source", kYaml}, {"z", 1}}.dump()},
        {"updated_at is a string", json{{"yaml_source", kYaml}, {"updated_at", "1"}}.dump()},
        {"updated_at is negative", json{{"yaml_source", kYaml}, {"updated_at", -5}}.dump()},
        {"updated_at is a float", json{{"yaml_source", kYaml}, {"updated_at", 1.5}}.dump()},
        {"updated_at is null", json{{"yaml_source", kYaml}, {"updated_at", nullptr}}.dump()},
        {"id is not a string", json{{"yaml_source", kYaml}, {"id", 7}}.dump()}};
    for (const auto& [label, b] : shape_refusals) {
        INFO(label);
        auto r = h.sink.Post("/api/v1/instructions/yaml", b);
        REQUIRE(r);
        CHECK(r->status == 400);
    }
    CHECK(h.audits.empty()); // every one of these refused before the attempt row
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

TEST_CASE("POST /api/v1/instructions/yaml: an attempt row that is not stored refuses 503 and saves "
          "nothing",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.audit_fail_from = 0;
    h.wire();
    auto r = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", kYaml}}.dump());
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(w.get("test.authoring.yaml").has_value());
}

TEST_CASE("instruction sets: create 201; list; delete unsets members and keeps them; 404 and "
          "audit-first refusals",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto created = h.sink.Post("/api/v1/instruction-sets",
                               json{{"name", "Ops"}, {"description", "d"}}.dump());
    REQUIRE(created);
    CHECK(created->status == 201);
    const auto set_id = body(created->body)["data"]["id"].get<std::string>();
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction_set.create");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == set_id);

    auto list = h.sink.Get("/api/v1/instruction-sets");
    REQUIRE(list);
    CHECK(list->status == 200);
    const auto lj = body(list->body);
    CHECK(lj["pagination"]["total"] == 1);
    REQUIRE(lj["data"].size() == 1);
    CHECK(lj["data"][0]["id"] == set_id);
    CHECK(lj["data"][0]["created_by"] == "alice");
    CHECK(h.audits.size() == 2); // the read is unaudited

    const auto member = create_def(h, json{{"instruction_set_id", set_id}});
    REQUIRE(w.row(member).instruction_set_id == set_id);

    h.audits.clear();
    auto del = h.sink.Delete("/api/v1/instruction-sets/" + set_id);
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(body(del->body)["data"]["deleted"] == true);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "instruction_set.delete");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "success");
    const auto after = w.get(member);
    REQUIRE(after.has_value());                      // the member definition survives
    CHECK(after->instruction_set_id.empty());        // and is unset

    h.audits.clear();
    auto again = h.sink.Delete("/api/v1/instruction-sets/" + set_id);
    REQUIRE(again);
    CHECK(again->status == 404);
    REQUIRE_FALSE(h.audits.empty());
    CHECK(h.audits.back().result == "denied");

    // Audit-first: a lost attempt row deletes nothing.
    auto keep = h.sink.Post("/api/v1/instruction-sets", json{{"name", "Keep"}}.dump());
    REQUIRE(keep);
    const auto keep_id = body(keep->body)["data"]["id"].get<std::string>();
    h.audit_fail_from = static_cast<int>(h.audits.size());
    auto refused = h.sink.Delete("/api/v1/instruction-sets/" + keep_id);
    REQUIRE(refused);
    CHECK(refused->status == 503);
    CHECK(refused->get_header_value("Sec-Audit-Failed") == "true");
    auto refused_create = h.sink.Post("/api/v1/instruction-sets", json{{"name", "Nope"}}.dump());
    REQUIRE(refused_create);
    CHECK(refused_create->status == 503);
    auto sets = w.store.list_sets();
    REQUIRE(sets.has_value());
    REQUIRE(sets->size() == 1);
    CHECK((*sets)[0].id == keep_id);
}

TEST_CASE("instruction sets: shape and store-bound refusals",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    for (const auto* b : {"not json", "[]", R"({"name":3})", R"({"name":"x","id":"y"})"}) {
        auto r = h.sink.Post("/api/v1/instruction-sets", b);
        REQUIRE(r);
        CHECK(r->status == 400);
    }
    CHECK(h.audits.empty());

    auto nameless = h.sink.Post("/api/v1/instruction-sets", R"({"description":"d"})");
    REQUIRE(nameless);
    CHECK(nameless->status == 400);
    auto too_long = h.sink.Post("/api/v1/instruction-sets",
                                json{{"name", std::string(kMaxInstructionSetNameLen + 1, 'n')}}.dump());
    REQUIRE(too_long);
    CHECK(too_long->status == 400);
    REQUIRE(h.audits.size() == 4); // two attempted + two denied
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail == "invalid");
}

// ── Version-token integrity: the update CAS is monotonic, not whole-second ──────────────────

namespace {

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Sets the stored row's `updated_at` directly, so a test controls what a "same second" write
/// would collide with, whatever the wall clock does between statements.
void pin_updated_at(PgWired& w, const std::string& id, std::int64_t ts) {
    auto lease = w.pool.acquire();
    REQUIRE(lease);
    yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
        lease.get(),
        "UPDATE instruction_store.instruction_definitions SET updated_at=$1::bigint WHERE id=$2",
        std::vector<std::string>{std::to_string(ts), id});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

/// No Catch macro in here: the two-writer test calls it from worker threads, where a failing
/// REQUIRE is undefined. `status` is -1 when the sink produced no response; the caller asserts.
std::string put_description(Harness& h, const std::string& id, const std::string& description,
                            std::int64_t expected, int& status) {
    auto r = h.sink.Put("/api/v1/instructions/" + id,
                        json{{"description", description}, {"expected_updated_at", expected}}.dump());
    status = r ? r->status : -1;
    return r ? r->body : std::string();
}

} // namespace

TEST_CASE("PUT /api/v1/instructions/{id}: a write inside the same second still moves the version "
          "token; and the stale token is refused",
          "[pg][server][instruction_authoring]") {
    // Turns red if update_definition's `updated_at=GREATEST($11, updated_at + 1)` goes back to
    // `updated_at=$11` (a whole-second clock): the first write would leave the token unchanged.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h);
    pin_updated_at(w, id, now_seconds() + 3600); // above the clock: only the GREATEST bump moves it
    const std::int64_t t0 = w.row(id).updated_at;

    int status = 0;
    put_description(h, id, "first", t0, status);
    CHECK(status == 200);
    const std::int64_t t1 = w.row(id).updated_at;
    CHECK(t1 > t0);

    put_description(h, id, "stale writer", t0, status);
    CHECK(status == 409);
    CHECK(w.row(id).description == "first"); // the stale write changed nothing
    CHECK(w.row(id).updated_at == t1);

    put_description(h, id, "second", t1, status);
    CHECK(status == 200);
    CHECK(w.row(id).updated_at > t1);
}

TEST_CASE("PUT /api/v1/instructions/{id}: two overlapping writers from the same read token cannot "
          "both succeed",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness setup;
    setup.store = &w.store;
    setup.wire();
    // One harness per thread: a Harness records into unsynchronised vectors.
    Harness h1, h2;
    h1.store = &w.store;
    h2.store = &w.store;
    h1.wire();
    h2.wire();

    for (int round = 0; round < 8; ++round) {
        INFO("round " << round);
        const auto id = create_def(setup);
        pin_updated_at(w, id, now_seconds() + 3600); // far above the clock: only the GREATEST bump can move it
        const std::int64_t token = w.row(id).updated_at;

        std::barrier start(2);
        int s1 = -1, s2 = -1;
        {
            // Workers joins on scope exit even if an assertion below throws; the statuses are
            // recorded in the workers and asserted here, on the test thread (Catch macros are
            // not thread-safe to fail from a worker).
            yuzu::test::Workers workers([] {});
            workers.add([&] {
                start.arrive_and_wait();
                put_description(h1, id, "writer one", token, s1);
            });
            workers.add([&] {
                start.arrive_and_wait();
                put_description(h2, id, "writer two", token, s2);
            });
            workers.join_all();
        }

        const int ok = (s1 == 200) + (s2 == 200);
        const int conflict = (s1 == 409) + (s2 == 409);
        CHECK(ok == 1);
        CHECK(conflict == 1); // the loser is told so, not silently overwritten
        const auto stored = w.row(id).description;
        CHECK((stored == "writer one" || stored == "writer two"));
        CHECK(stored == (s1 == 200 ? "writer one" : "writer two"));
    }
}

TEST_CASE("DELETE then re-create of the same id inside one second: a token read before the delete "
          "is refused",
          "[pg][server][instruction_authoring]") {
    // Turns red if the tombstone stops carrying the deleted row's last token (last_version) or
    // insert_definition_row stops flooring updated_at above it.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string id = "authoring.recreate.same.second";

    for (int cycle = 0; cycle < 3; ++cycle) {
        INFO("cycle " << cycle);
        const auto created = create_def(h, json{{"id", id}});
        REQUIRE(created == id);
        pin_updated_at(w, id, now_seconds() + 3600); // above the clock: only the tombstone floor clears it
        const std::int64_t stale = w.row(id).updated_at;

        auto del = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(del);
        REQUIRE(del->status == 200);
        REQUIRE(create_def(h, json{{"id", id}}) == id);
        CHECK(w.row(id).updated_at > stale);

        int status = 0;
        put_description(h, id, "from before the delete", stale, status);
        CHECK(status == 409);
        CHECK(w.row(id).description.empty());

        // Leave the row in place for the next cycle's create to conflict-free delete.
        auto cleanup = h.sink.Delete("/api/v1/instructions/" + id);
        REQUIRE(cleanup);
        REQUIRE(cleanup->status == 200);
    }
}

TEST_CASE("create of an id whose DELETE is still uncommitted lands above the deleted row's token",
          "[pg][server][instruction_authoring]") {
    // Turns red if insert_definition_row's plain-create branch stops taking kSeedCoordLockSql
    // (delete_definition's lock) before the INSERT: that INSERT's `updated_at` floor subquery
    // reads the tombstone in the statement's snapshot, taken BEFORE the statement waits behind the
    // open delete on the unique index, so it would see no tombstone and land BELOW the stale token.
    // The "open delete" is a raw transaction repeating delete_definition's statements (lock,
    // DELETE ... RETURNING updated_at, tombstone upsert) and holding the commit back.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string id = "authoring.recreate.concurrent";
    REQUIRE(create_def(h, json{{"id", id}}) == id);
    // A token far above the wall clock, so a create that ignores the tombstone cannot reach it.
    const std::int64_t stale = now_seconds() + 3600;
    pin_updated_at(w, id, stale);

    namespace pg = yuzu::server::pg;
    auto delete_txn = w.pool.try_acquire_for(std::chrono::seconds(5));
    REQUIRE(delete_txn);
    const auto run = [&](const char* sql, std::vector<std::string> binds, ExecStatusType want) {
        pg::PgResult r = pg::exec_params(delete_txn.get(), sql, binds);
        REQUIRE(r.status() == want);
        return r;
    };
    run("BEGIN", {}, PGRES_COMMAND_OK);
    bool open = true;
    const auto finish = [&](const char* verb) {
        if (!open)
            return;
        open = false;
        pg::PgResult r = pg::exec_params(delete_txn.get(), verb, std::vector<std::string>{});
        (void)r;
    };
    run("SELECT pg_advisory_xact_lock(2037545589, hashtext('instruction_store:seed_coordination'))",
        {}, PGRES_TUPLES_OK);
    auto del = run("DELETE FROM instruction_store.instruction_definitions WHERE id=$1 "
                   "RETURNING updated_at",
                   {id}, PGRES_TUPLES_OK);
    REQUIRE(PQntuples(del.get()) == 1);
    run("INSERT INTO instruction_store.deleted_seed_content (kind, id, deleted_at, last_version) "
        "VALUES ('definition', $1, $2::bigint, $3::bigint) ON CONFLICT (kind, id) DO UPDATE SET "
        "last_version = GREATEST(deleted_seed_content.last_version, EXCLUDED.last_version)",
        {id, std::to_string(now_seconds()), PQgetvalue(del.get(), 0, 0)}, PGRES_COMMAND_OK);

    // Declared after the open transaction it releases (see Workers): a failing REQUIRE rolls the
    // delete back and joins instead of waiting out the create's own timeout.
    yuzu::test::Workers workers([&] { finish("ROLLBACK"); });
    bool created = false;
    workers.add([&] {
        InstructionDefinition def;
        def.id = id;
        def.name = "recreated";
        def.type = "question";
        def.plugin = "os_info";
        def.action = "os_name";
        created = w.store.create_definition(def).has_value(); // no Catch macro off the main thread
    });
    // The create is parked behind the open delete (on the advisory lock; the unlocked code parks
    // on the unique index instead: either way a lock wait).
    REQUIRE(yuzu::test::wait_for_lock_waiter(w.pool));
    finish("COMMIT");
    workers.join_all();

    REQUIRE(created);
    CHECK(w.row(id).updated_at > stale);
    int status = 0;
    put_description(h, id, "from before the delete", stale, status);
    CHECK(status == 409);
    CHECK(w.row(id).description.empty());
}

TEST_CASE("DELETE /api/v1/instruction-sets/{id}: a member definition's token moves; so a stale "
          "update cannot resurrect the deleted set id",
          "[pg][server][instruction_authoring]") {
    // Turns red if delete_set's member-unlink UPDATE stops bumping updated_at.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto created = h.sink.Post("/api/v1/instruction-sets", json{{"name", "Ops"}}.dump());
    REQUIRE(created);
    const auto set_id = body(created->body)["data"]["id"].get<std::string>();
    const auto member = create_def(h, json{{"instruction_set_id", set_id}});
    pin_updated_at(w, member, now_seconds());
    const std::int64_t stale = w.row(member).updated_at;

    auto del = h.sink.Delete("/api/v1/instruction-sets/" + set_id);
    REQUIRE(del);
    REQUIRE(del->status == 200);
    CHECK(w.row(member).instruction_set_id.empty());
    CHECK(w.row(member).updated_at > stale);

    // The editor loaded the member while it still named the set; saving that copy back would
    // restore a set id that no longer exists.
    auto stale_put = h.sink.Put("/api/v1/instructions/" + member,
                                json{{"instruction_set_id", set_id}, {"expected_updated_at", stale}}
                                    .dump());
    REQUIRE(stale_put);
    CHECK(stale_put->status == 409);
    CHECK(w.row(member).instruction_set_id.empty());
}

TEST_CASE("POST /api/v1/instructions/import: a TTL outside the create/update range is a 400 naming "
          "the field; audited; and stores nothing",
          "[pg][server][instruction_authoring]") {
    // Turns red if the range check in InstructionStore::import_definition_json is removed: the
    // int64 would narrow to int (3000000000 stores negative) or 0 / -5 / 86401 would be stored.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();

    const json base{{"id", "authoring.import.ttl"},
                    {"name", "n"},
                    {"type", "question"},
                    {"plugin", "os_info"},
                    {"yaml_source", kYaml}};
    const std::vector<std::pair<std::string, json>> cases{
        {"gather_ttl_seconds", 3000000000LL},
        {"gather_ttl_seconds", 0},
        {"gather_ttl_seconds", -5},
        {"gather_ttl_seconds", 86401},
        {"gather_ttl_seconds", 18446744073709551615ULL},
        {"gather_ttl_seconds", 300.0},
        {"gather_ttl_seconds", nullptr},
        {"response_ttl_days", 0},
        {"response_ttl_days", -1},
        {"response_ttl_days", 3651},
        {"response_ttl_days", 4294967297LL},
        {"response_ttl_days", 90.0},
        {"response_ttl_days", nullptr}};
    for (const auto& [field, value] : cases) {
        INFO(field << " = " << value.dump());
        json doc = base;
        doc[field] = value;
        h.audits.clear();
        auto r = h.sink.Post("/api/v1/instructions/import", doc.dump());
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(error_message(r->body).find("'" + field + "'") != std::string::npos);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].result == "denied");
        CHECK_FALSE(w.get("authoring.import.ttl").has_value());
    }

    // The edges themselves are accepted: the check is the builders' range, no tighter.
    json edge = base;
    edge["gather_ttl_seconds"] = kMaxDefinitionGatherTtlSeconds;
    edge["response_ttl_days"] = kMaxDefinitionResponseTtlDays;
    auto top = h.sink.Post("/api/v1/instructions/import", edge.dump());
    REQUIRE(top);
    CHECK(top->status == 201);
    CHECK(w.row("authoring.import.ttl").gather_ttl_seconds == kMaxDefinitionGatherTtlSeconds);
    CHECK(w.row("authoring.import.ttl").response_ttl_days == kMaxDefinitionResponseTtlDays);
}

TEST_CASE("classify_store_error: every store error shape maps to exactly one fault class",
          "[instruction_authoring][classifier]") {
    // The mapping the REST (404/409/503/400) and MCP (not_found/conflict/store_unavailable/
    // invalid) twins both switch on; a producer renaming a prefix without the classifier would
    // silently change a status. The producers use the same constants.
    struct Row {
        std::string error;
        StoreFault fault;
    };
    const std::vector<Row> rows{
        {std::string(kInstructionStoreDbErrorPrefix) + "pool acquire timeout", StoreFault::kDb},
        {std::string(kInstructionStoreDbErrorPrefix), StoreFault::kDb},
        {std::string(kNotFoundPrefix) + "definition not found: d1", StoreFault::kNotFound},
        {"not_found: instruction set not found: s1", StoreFault::kNotFound},
        {std::string(kConflictPrefix) + " instruction definition 'd1' already exists",
         StoreFault::kConflict},
        {"conflict: instruction definition 'd1' was modified since it was loaded",
         StoreFault::kConflict},
        {"invalid approval_mode: x (must be auto, role-gated, or always)", StoreFault::kInvalid},
        {"id is required for update", StoreFault::kInvalid},
        {"", StoreFault::kInvalid},
        // Near misses are validation text, never a status of their own.
        {"not_found:no-space", StoreFault::kInvalid},
        {"NOT_FOUND: x", StoreFault::kInvalid},
        {"a conflict: in the middle", StoreFault::kInvalid},
    };
    for (const auto& row : rows) {
        INFO("error = '" << row.error << "'");
        CHECK(classify_store_error(row.error) == row.fault);
    }
    // The prefix constants are the literals the producers have always written.
    CHECK(kNotFoundPrefix == "not_found: ");
    CHECK(kConflictPrefix == "conflict:");
}

TEST_CASE("PUT /api/v1/instructions/{id}: a failed existence probe after a zero-row compare-and-set "
          "is a 503 with outcome-unknown wording; never a 404",
          "[pg][server][instruction_authoring]") {
    // Turns red if update_definition goes back to falling through to not_found when the probe
    // statement itself fails (a false "no such definition" for a row that exists).
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h);
    const std::int64_t token = w.row(id).updated_at;
    yuzu::test::ExistsProbeFault fault(w.pool);
    fault.arm();
    h.audits.clear();

    int status = 0;
    const auto text = put_description(h, id, "x", token + 1000, status); // stale -> zero rows
    CHECK(status == 503);
    // Outcome unknown: NO retry hint (a client honouring it would blind-retry). Turns red if
    // fail_write_unknown sends retry_after_ms again.
    CHECK(body(text)["error"]["retry_after_ms"].is_null());
    CHECK(error_message(text).find("outcome unknown: read the definition before retrying") !=
          std::string::npos);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "error");
    CHECK(h.audits[1].detail == "db_error");
    fault.repair();
    CHECK(w.row(id).description.empty());
}

TEST_CASE("DELETE /api/v1/instructions/{id}: the audit rows carry the deleted definition's dispatch "
          "tuple",
          "[pg][server][instruction_authoring]") {
    // Turns red if the route stops reading the pre-image or the rows stop carrying it: once the
    // row is gone nothing else records what it ran.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h, json{{"name", "Pre image"},
                                       {"plugin", "os_info"},
                                       {"action", "os_name"},
                                       {"approval_mode", "role-gated"},
                                       {"enabled", false}});
    h.audits.clear();
    auto del = h.sink.Delete("/api/v1/instructions/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    const std::string tuple = "name=Pre_image plugin=os_info action=os_name "
                              "approval_mode=role-gated concurrency_mode=per-device enabled=false";
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].detail == tuple);
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == tuple);
}

// ── Batch C governance fix round C: audit completeness, validation bounds, hygiene ──────

TEST_CASE("audit_store_error_text: the caller-echoed approval_mode is folded; every fixed text is "
          "kept byte for byte",
          "[server][instruction_authoring][builder][security]") {
    // Fixed store texts, including ones with spaces, quotes, '=' and ',', are unchanged.
    for (const char* fixed :
         {"instruction-import field 'enabled' must be a boolean",
          "invalid approval_mode: sometimes (must be auto, role-gated, or always)",
          "signature verification failed for instruction - content may have been tampered with"})
        CHECK(audit_store_error_text(fixed) == fixed);

    // CR/LF, ESC, DEL, C1 (CSI U+009B, NEL U+0085), U+2028 and U+2029 in the echoed value become
    // '_'; the SIEM-stable prefix and suffix stay.
    const std::string hostile =
        std::string("\r\nforged") + "\x1b[31m" + "\x7f" + "\xc2\x9b" + "\xc2\x85" + "\xe2\x80\xa8" +
        "\xe2\x80\xa9" + "tail";
    const std::string out = audit_store_error_text("invalid approval_mode: " + hostile +
                                                   " (must be auto, role-gated, or always)");
    CHECK(out.rfind("invalid approval_mode: ", 0) == 0);
    CHECK(out.ends_with(" (must be auto, role-gated, or always)"));
    for (const char* bad : {"\r", "\n", "\x1b", "\x7f", "\xc2\x9b", "\xc2\x85", "\xe2\x80\xa8",
                            "\xe2\x80\xa9"})
        CHECK(out.find(bad) == std::string::npos);
    // A value that is huge is bounded, not copied whole.
    CHECK(audit_store_error_text("invalid approval_mode: " + std::string(100000, 'z') +
                                 " (must be auto, role-gated, or always)")
              .size() < 400);

    // Any other text is flattened to one line and cut; one holding a byte that needs it is folded.
    CHECK(audit_store_error_text("a\r\nb") == "a  b");
    CHECK(audit_store_error_text("x\x1b[0my").find('\x1b') == std::string::npos);
    CHECK(audit_store_error_text(std::string(1000, 'q')).size() == 200);
}

TEST_CASE("yaml_source_byte_refusal and validate_yaml_for_authoring: a source refused on its bytes "
          "is never parsed",
          "[server][instruction_authoring][builder][bounds]") {
    // The verdict of the separate predicate, at the edges.
    CHECK_FALSE(yaml_source_byte_refusal(std::string(kMaxDefinitionYamlSourceBytes, 'x')));
    const auto big = yaml_source_byte_refusal(std::string(kMaxDefinitionYamlSourceBytes + 1, 'x'));
    REQUIRE(big.has_value());
    CHECK(*big == "yaml_source too large (max 1MB)");
    const auto nul = yaml_source_byte_refusal(std::string("a\0b", 3));
    REQUIRE(nul.has_value());
    CHECK(*nul == "YAML source contains a NUL byte");
    CHECK_FALSE(yaml_source_byte_refusal(""));

    // The refused source carries a plugin the parser WOULD flag if it ran: one error comes back
    // (the byte refusal), not two. Without the early return the parse adds the plugin error.
    const std::string head = "metadata:\n  id: a\n  displayName: A\nspec:\n  plugin: \"bad plugin\"\n"
                             "  action: os_name\n";
    const auto oversize = validate_yaml_for_authoring(
        head + "# " + std::string(kMaxDefinitionYamlSourceBytes, 'y') + "\n");
    REQUIRE(oversize.size() == 1);
    CHECK(oversize[0] == "yaml_source too large (max 1MB)");
    const auto with_nul = validate_yaml_for_authoring(head + std::string("\0", 1));
    REQUIRE(with_nul.size() == 1);
    CHECK(with_nul[0] == "YAML source contains a NUL byte");
    // A source that is merely invalid still gets the plugin error alongside.
    const auto plain = validate_yaml_for_authoring(head);
    CHECK(std::any_of(plain.begin(), plain.end(),
                      [](const std::string& e) { return e.find("plugin") != std::string::npos; }));
}

TEST_CASE("YAML authoring: name; version and description meet the builders' bounds; one verdict "
          "for validate and save",
          "[server][instruction_authoring][builder][bounds]") {
    const auto doc = [](const std::string& name, const std::string& version,
                        const std::string& description) {
        return "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n"
               "  id: bounds.yaml\n  displayName: \"" + name + "\"\n  version: \"" + version +
               "\"\n  description: \"" + description + "\"\nspec:\n  plugin: os_info\n"
               "  action: os_name\n  type: question\n";
    };
    const auto has = [](const std::vector<std::string>& errs, std::string_view needle) {
        return std::any_of(errs.begin(), errs.end(),
                           [&](const std::string& e) { return e.find(needle) != std::string::npos; });
    };
    CHECK(validate_yaml_for_authoring(doc("n", "1.0", "d")).empty());
    // Inclusive at the limits.
    CHECK(validate_yaml_for_authoring(doc(std::string(kMaxDefinitionNameLen, 'n'),
                                          std::string(kMaxDefinitionVersionLen, 'v'),
                                          std::string(kMaxDefinitionDescriptionLen, 'd')))
              .empty());
    CHECK(has(validate_yaml_for_authoring(doc(std::string(kMaxDefinitionNameLen + 1, 'n'), "1", "d")),
              "name must be 1 to 128 characters"));
    CHECK(has(validate_yaml_for_authoring(
                  doc("n", std::string(kMaxDefinitionVersionLen + 1, 'v'), "d")),
              "version must be 1 to 64 characters"));
    // The YAML path takes the import's wider description bound, not the builders' 512: the
    // bundled content ships descriptions past 512 bytes (Gate 8 F5). Inclusive at the limit.
    // Turns red if check_yaml_field_bounds loses the description check (the over-bound case) or
    // regains the builders' 512 (the in-bound cases).
    CHECK(validate_yaml_for_authoring(
              doc("n", "1", std::string(kMaxDefinitionDescriptionLen * 4, 'd')))
              .empty());
    CHECK(validate_yaml_for_authoring(
              doc("n", "1", std::string(kMaxDefinitionImportDescriptionLen, 'd')))
              .empty());
    CHECK(has(validate_yaml_for_authoring(
                  doc("n", "1", std::string(kMaxDefinitionImportDescriptionLen + 1, 'd'))),
              "description must be at most 16384 bytes"));
    // A 1 MiB name (the finding: it stored and bloated every list page).
    CHECK(has(validate_yaml_for_authoring(doc(std::string(900 * 1024, 'n'), "1", "d")),
              "name must be 1 to 128 characters"));
}

TEST_CASE("POST /api/v1/instructions/yaml: an over-bound name or description is a 400 with the same "
          "error list validate-yaml gives; an id past 128 bytes is a 400",
          "[pg][server][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    const std::string long_name(kMaxDefinitionNameLen + 1, 'n');
    const std::string y = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                          "metadata:\n  id: bounds.save\n  displayName: \"" + long_name +
                          "\"\nspec:\n  plugin: os_info\n  action: os_name\n  type: question\n";
    auto v = h.sink.Post("/api/v1/instructions/validate-yaml", json{{"yaml_source", y}}.dump());
    REQUIRE(v);
    CHECK(body(v->body)["data"]["valid"] == false);
    auto sv = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", y}}.dump());
    REQUIRE(sv);
    CHECK(sv->status == 400);
    CHECK(body(sv->body)["error"]["errors"] == body(v->body)["data"]["errors"]);
    CHECK(h.audits.empty());
    CHECK_FALSE(w.get("bounds.save").has_value());

    // F6: the update id is capped like MCP's (kIdMaxLen), before any row or store read.
    auto longid = h.sink.Post(
        "/api/v1/instructions/yaml",
        json{{"yaml_source", kYaml}, {"id", std::string(kMaxDefinitionIdLen + 1, 'i')}}.dump());
    REQUIRE(longid);
    CHECK(longid->status == 400);
    CHECK(error_message(longid->body) == "id is not a valid definition id");
    CHECK(h.audits.empty());
}

TEST_CASE("PUT/POST /api/v1/instructions: a present but empty plugin is refused 400 (it would blank "
          "the column); an empty action stays storable",
          "[pg][server][instruction_authoring]") {
    // Turns red if the removed `if (!def.plugin.empty())` guard returns in
    // apply_definition_fields: the PUT would answer updated:true with plugin "".
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const auto id = create_def(h);
    h.audits.clear();

    auto blank = h.sink.Put("/api/v1/instructions/" + id, R"({"plugin":""})");
    REQUIRE(blank);
    CHECK(blank->status == 400);
    CHECK(error_message(blank->body) == "plugin must be 1 to 128 characters");
    CHECK(w.row(id).plugin == "os_info"); // unchanged
    CHECK(h.audits.empty());

    // Create: the builder refuses the same value (the store would have said "plugin is required").
    auto create_blank = h.sink.Post(
        "/api/v1/instructions",
        R"({"name":"n","type":"question","plugin":"","action":"os_name"})");
    REQUIRE(create_blank);
    CHECK(create_blank->status == 400);
    CHECK(error_message(create_blank->body) == "plugin must be 1 to 128 characters");
    CHECK(h.audits.empty());

    // action is NOT required: create stores an empty one today (validate_and_prepare requires
    // name, type and plugin only), so an empty action on update stays valid.
    auto action_blank = h.sink.Put("/api/v1/instructions/" + id, R"({"action":""})");
    REQUIRE(action_blank);
    CHECK(action_blank->status == 200);
    CHECK(w.row(id).action.empty());
}

TEST_CASE("POST /api/v1/instructions/import: the operator import bounds name; version; description; "
          "instruction_set_id; plugin and action; lowercases action; the trusted seed is exempt",
          "[pg][server][instruction_authoring][bounds]") {
    // Turns red if the `if (check_signature)` block before validate_and_prepare in
    // InstructionStore::import_definition_json_impl is removed: a 1 MiB name would be stored.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();

    const json base{{"id", "authoring.import.bounds"}, {"name", "n"},         {"version", "1.0"},
                    {"type", "question"},              {"plugin", "os_info"}, {"action", "os_name"},
                    {"yaml_source", kYaml}};
    const std::vector<std::pair<std::string, json>> refused{
        {"name", std::string(1024 * 1024, 'n')},
        {"name", std::string(kMaxDefinitionNameLen + 1, 'n')},
        {"version", std::string(kMaxDefinitionVersionLen + 1, 'v')},
        {"description", std::string(kMaxDefinitionImportDescriptionLen + 1, 'd')},
        {"description", std::string(1024 * 1024, 'd')},
        {"instruction_set_id", std::string(kMaxDefinitionInstructionSetIdLen + 1, 's')},
        {"plugin", "bad plugin"},
        {"plugin", std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'p')},
        {"action", "a/b"},
        {"action", std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'a')}};
    for (const auto& [field, value] : refused) {
        INFO(field << " size " << value.get<std::string>().size());
        json doc = base;
        doc[field] = value;
        h.audits.clear();
        auto r = h.sink.Post("/api/v1/instructions/import", doc.dump());
        REQUIRE(r);
        CHECK(r->status == 400);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[1].result == "denied");
        CHECK_FALSE(w.get("authoring.import.bounds").has_value());
    }

    // Inclusive at the limits; the description's is the wider import bound, not the builders' 512
    // (91 of 296 bundled definitions carry one over 512 bytes, and an export of one must stay
    // importable); an uppercase action is lowercased as every other writer does.
    json ok = base;
    ok["name"] = std::string(kMaxDefinitionNameLen, 'n');
    ok["version"] = std::string(kMaxDefinitionVersionLen, 'v');
    ok["description"] = std::string(kMaxDefinitionImportDescriptionLen, 'd');
    ok["action"] = "OS_Name";
    auto accepted = h.sink.Post("/api/v1/instructions/import", ok.dump());
    REQUIRE(accepted);
    CHECK(accepted->status == 201);
    const auto stored = w.get("authoring.import.bounds");
    REQUIRE(stored.has_value());
    CHECK(stored->action == "os_name");
    CHECK(stored->description.size() == kMaxDefinitionImportDescriptionLen);

    // The trusted boot-seed variant is untouched by the bounds.
    json seed = base;
    seed["id"] = "authoring.import.seed";
    seed["name"] = std::string(kMaxDefinitionNameLen + 50, 's');
    seed["description"] = std::string(kMaxDefinitionImportDescriptionLen + 50, 's');
    auto seeded = w.store.import_definition_json_trusted(seed.dump());
    CHECK(seeded.has_value());
}

TEST_CASE("POST /api/v1/instructions/import: a SIGNED yaml whose plugin or action fails the "
          "identifier check is refused",
          "[pg][server][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto kp = generate_ed25519();
    const auto signed_import = [&](const std::string& plugin, const std::string& action) {
        const std::string yaml = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                                 "metadata:\n  id: authoring.signed.ident\n  displayName: S\n"
                                 "spec:\n  type: question\n  execution:\n    plugin: \"" + plugin +
                                 "\"\n    action: \"" + action + "\"\n";
        // The document states NO plugin or action: they come from the verified YAML alone, so the
        // identifier check under test is the only thing that can refuse the bad ones (a benign
        // document value that disagreed with the YAML would be refused as a mismatch instead).
        json j{{"id", "authoring.signed.ident"}, {"name", "S"}, {"version", "1.0"},
               {"type", "question"},             {"yaml_source", yaml},
               {"signature", sign_hex(kp.pkey.get(), yaml)}, {"publicKey", kp.public_key_hex}};
        return h.sink.Post("/api/v1/instructions/import", j.dump());
    };
    // Turns red if the check_dispatch_identifier calls in the import path are removed: the signed
    // yaml's plugin is taken verbatim by bind_signed_dispatch_columns.
    auto bad_plugin = signed_import("my plugin", "os_name");
    REQUIRE(bad_plugin);
    CHECK(bad_plugin->status == 400);
    CHECK(error_message(bad_plugin->body).find("plugin may only contain") != std::string::npos);
    auto bad_action = signed_import("os_info", "a/b");
    REQUIRE(bad_action);
    CHECK(bad_action->status == 400);
    CHECK(error_message(bad_action->body).find("action may only contain") != std::string::npos);
    CHECK_FALSE(w.get("authoring.signed.ident").has_value());
    auto good = signed_import("os_info", "os_name");
    REQUIRE(good);
    CHECK(good->status == 201);
}

TEST_CASE("POST /api/v1/instructions/import: created_by is the authenticated caller; whatever the "
          "document claims",
          "[pg][server][instruction_authoring][security]") {
    // Turns red if the `(*document)["created_by"] = ...` stamp is removed from the import handler.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.session_username = "alice";
    h.wire();
    const json doc{{"id", "authoring.import.creator"}, {"name", "n"},   {"version", "1.0"},
                   {"type", "question"},               {"plugin", "os_info"}, {"action", "os_name"},
                   {"created_by", "mallory"},          {"yaml_source", kYaml}};
    auto r = h.sink.Post("/api/v1/instructions/import", doc.dump());
    REQUIRE(r);
    CHECK(r->status == 201);
    CHECK(w.row("authoring.import.creator").created_by == "alice");
    // Even a wrong-typed claim is ignored (overwritten before the store's type gate).
    json odd = doc;
    odd["id"] = "authoring.import.creator2";
    odd["created_by"] = 7;
    auto r2 = h.sink.Post("/api/v1/instructions/import", odd.dump());
    REQUIRE(r2);
    CHECK(r2->status == 201);
    CHECK(w.row("authoring.import.creator2").created_by == "alice");
}

TEST_CASE("POST /api/v1/instructions/import: a hostile approval_mode never reaches the audit "
          "detail raw; the stable prefix stays",
          "[pg][server][instruction_authoring][security]") {
    // Turns red if audit_store_error_text is replaced by the old CR/LF-only flatten in the
    // import handler: ESC and U+2028 would persist.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string hostile = std::string("\r\nforged") + "\x1b[31m" + "\xe2\x80\xa8" + "x";
    const json doc{{"id", "authoring.import.hostile"},
                   {"name", "N\r\nforgedname\x1b"},
                   {"version", "1.0"},
                   {"type", "question"},
                   {"plugin", "os_info"},
                   {"action", "os_name"},
                   {"approval_mode", hostile},
                   {"yaml_source", kYaml}};
    auto r = h.sink.Post("/api/v1/instructions/import", doc.dump());
    REQUIRE(r);
    CHECK(r->status == 400);
    REQUIRE(h.audits.size() == 2);
    const std::string& detail = h.audits[1].detail;
    CHECK(h.audits[1].result == "denied");
    CHECK(detail.rfind("invalid approval_mode: ", 0) == 0);
    for (const char* bad : {"\r", "\n", "\x1b", "\xe2\x80\xa8"})
        CHECK(detail.find(bad) == std::string::npos);
    CHECK(detail.find("forgedname") == std::string::npos); // the name is never echoed
    CHECK_FALSE(w.get("authoring.import.hostile").has_value());
}

TEST_CASE("POST /api/v1/instructions/yaml: a concurrency_mode change is in the update audit detail",
          "[pg][server][instruction_authoring]") {
    // Turns red if the concurrency_mode line is removed from describe_dispatch_binding_change.
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    auto created = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", kYaml}}.dump());
    REQUIRE(created);
    REQUIRE(created->status == 201);
    h.audits.clear();
    const std::string yaml2 = std::string(kYaml) + "  concurrency: per-fleet\n";
    auto updated = h.sink.Post(
        "/api/v1/instructions/yaml",
        json{{"yaml_source", yaml2}, {"id", "test.authoring.yaml"}}.dump());
    REQUIRE(updated);
    CHECK(updated->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail == "concurrency_mode: per-device -> per-fleet");
    CHECK(h.audits[1].detail == h.audits[0].detail);
}

// ═══════════════════════════════════════════════════════════════════════════
// Batch C fix round E1: the quality-engineer gaps. Each case below names the production line whose
// removal turns it red.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// A complete definition row for seeding the store directly (the audit sink never sees it).
InstructionDefinition seed_row(const std::string& id) {
    InstructionDefinition d;
    d.id = id;
    d.name = "Seed";
    d.version = "1.0";
    d.type = "question";
    d.plugin = "os_info";
    d.action = "os_name";
    d.approval_mode = "always";
    d.enabled = true;
    d.gather_ttl_seconds = 300;
    d.response_ttl_days = 90;
    return d;
}

void seed_def(PgWired& w, const InstructionDefinition& d) {
    REQUIRE(w.store.create_definition(d).has_value());
}

std::size_t set_count(PgWired& w) {
    auto r = w.store.list_sets();
    REQUIRE(r.has_value());
    return r->size();
}

void seed_set(PgWired& w, const std::string& id) {
    InstructionSet s;
    s.id = id;
    s.name = "Seed set";
    REQUIRE(w.store.create_set(s).has_value());
}

/// kYaml with its metadata.id replaced.
std::string yaml_for(const std::string& id) {
    std::string y = kYaml;
    const std::string from = "test.authoring.yaml";
    y.replace(y.find(from), from.size(), id);
    return y;
}

/// A source of exactly `total` bytes: kYaml followed by a comment line padded to size.
std::string yaml_of_size(std::size_t total) {
    std::string y = kYaml;
    y += "# ";
    REQUIRE(y.size() + 1 < total);
    y.append(total - y.size() - 1, 'y');
    y += "\n";
    REQUIRE(y.size() == total);
    return y;
}

json import_base(const std::string& id) {
    return {{"id", id},
            {"name", "n"},
            {"type", "question"},
            {"plugin", "os_info"},
            {"yaml_source", kYaml}};
}

/// Every JSON key the import scalar gate (InstructionStore::import_definition_json_impl,
/// `kStringFields`) refuses when it is not a string. Keep in step with that array; the direct
/// store case below fails if a key listed here stops being gated.
constexpr auto kImportStringKeys = std::to_array<const char*>(
    {"id",          "name",           "version",           "type",
     "plugin",      "action",         "description",       "instruction_set_id",
     "created_by",  "yaml_source",    "parameter_schema",  "result_schema",
     "approval_mode", "concurrency_mode", "platforms",     "min_agent_version",
     "required_plugins", "readable_payload"});

/// One wrong-typed import document field and a word the refusal text must contain.
struct BadImportField {
    std::string key;
    json value;
    std::string word;
};

/// The whole scalar-type matrix of the import gate. `created_by` is included: the transports
/// overwrite it with the caller, so only the direct store case drives it.
std::vector<BadImportField> bad_import_fields() {
    std::vector<BadImportField> out;
    const std::vector<json> not_strings{7, json::object(), json::array(), nullptr, true};
    for (const char* key : kImportStringKeys)
        for (const auto& v : not_strings)
            out.push_back({key, v, "string"});
    // The signing fields are checked by the signing branch (null there means absent, so it is not
    // in the matrix).
    for (const char* key : {"signature", "publicKey"})
        for (const auto& v : std::vector<json>{7, json::object(), json::array(), true})
            out.push_back({key, v, "string"});
    const std::vector<json> not_ints{"300", nullptr, 1.5, true, json::object(), json::array()};
    for (const char* key : {"gather_ttl_seconds", "response_ttl_days"})
        for (const auto& v : not_ints)
            out.push_back({key, v, "integer"});
    for (const auto& v : std::vector<json>{"yes", nullptr, 1, json::array()})
        out.push_back({"enabled", v, "boolean"});
    return out;
}

/// A line-forging byte: CR, LF, ESC, or a Unicode line/paragraph separator.
bool carries_forgery(const std::string& s) {
    return s.find_first_of("\r\n\x1b") != std::string::npos ||
           s.find("\xe2\x80\xa8") != std::string::npos ||
           s.find("\xe2\x80\xa9") != std::string::npos;
}

void expect_no_forgery(const std::vector<AuditRow>& rows) {
    for (const auto& r : rows) {
        INFO(r.action << "|" << r.result);
        CHECK_FALSE(carries_forgery(r.detail));
        CHECK_FALSE(carries_forgery(r.target_id));
    }
}

/// `depth` nested objects: {"a":{"a":...1...}}.
std::string nested_json(int depth) {
    std::string s;
    for (int i = 0; i < depth; ++i)
        s += "{\"a\":";
    s += "1";
    s.append(static_cast<std::size_t>(depth), '}');
    return s;
}

} // namespace

// 1. The import scalar type gate, every gated key, REST transport. Turns red if any key is dropped
// from kStringFields (that key's wrong-typed values reach get<std::string>() and throw: a bare 500,
// an attempt row without an outcome row), or if the TTL / enabled checks are removed.
TEST_CASE("POST /api/v1/instructions/import: every gated key refuses a wrong-typed value with a 400; "
          "two audit rows and nothing stored",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();

    // Control: the base document imports, so each refusal below is its one wrong-typed key. Then
    // delete it so "nothing stored" is checkable at the end.
    auto ok = h.sink.Post("/api/v1/instructions/import", import_base("authoring.import.control").dump());
    REQUIRE(ok);
    REQUIRE(ok->status == 201);
    CHECK(h.emits.empty()); // an import emits no platform event
    REQUIRE(w.store.delete_definition("authoring.import.control").has_value());

    std::size_t driven = 0;
    for (const auto& c : bad_import_fields()) {
        if (c.key == "created_by")
            continue; // overwritten by the handler; the next case covers it
        INFO(c.key << " = " << c.value.dump());
        json doc = import_base("authoring.import.badtype");
        doc[c.key] = c.value;
        h.audits.clear();
        auto r = h.sink.Post("/api/v1/instructions/import", doc.dump());
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(r->body.find(c.word) != std::string::npos);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].action == "instruction.import");
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].result == "denied");
        ++driven;
    }
    CHECK(driven > 80);
    CHECK(h.emits.empty());
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

// created_by is not gated on the transports: the handler stamps the authenticated caller over
// whatever the document says, so a wrong-typed value is IGNORED (the import succeeds). Turns red if
// the handler stops overwriting it (a number would then reach the store gate and 400).
TEST_CASE("POST /api/v1/instructions/import: a document created_by of any type is ignored; the "
          "caller is stamped",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();
    int n = 0;
    for (const auto& v : std::vector<json>{7, json::object(), json::array(), nullptr, "mallory"}) {
        INFO(v.dump());
        const std::string id = "authoring.import.cb" + std::to_string(n++);
        json doc = import_base(id);
        doc["created_by"] = v;
        auto r = h.sink.Post("/api/v1/instructions/import", doc.dump());
        REQUIRE(r);
        CHECK(r->status == 201);
        CHECK(w.row(id).created_by == "alice");
    }
}

// The store gate itself, for every key and without a transport in front: this is where `created_by`
// is reachable, and it proves the matrix above is not satisfied by a handler-side check.
TEST_CASE("InstructionStore::import_definition_json: the scalar gate refuses every wrong-typed key "
          "and a too-deep body; without throwing",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    for (const auto& c : bad_import_fields()) {
        INFO(c.key << " = " << c.value.dump());
        json doc = import_base("store.gate.badtype");
        doc[c.key] = c.value;
        std::expected<std::string, std::string> r = std::unexpected(std::string("not run"));
        REQUIRE_NOTHROW(r = w.store.import_definition_json(doc.dump()));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find(c.word) != std::string::npos);
    }
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->empty());

    json deep = import_base("store.gate.deep");
    deep["parameter_schema_like"] = json::parse(nested_json(mcp::kMcpMaxJsonDepth));
    const auto refused = w.store.import_definition_json(deep.dump());
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("nests too deeply") != std::string::npos);
}

// 2. parse_yaml_save_body, directly. Each case is the only defect in an otherwise valid request,
// so deleting the matching arm turns exactly that row red.
TEST_CASE("parse_yaml_save_body: strict request shape; every arm on its own",
          "[instruction_authoring][builder]") {
    const std::string y = kYaml;
    const auto refused = [&](const json& b, std::string_view contains) {
        INFO(b.dump().substr(0, 120));
        const auto r = parse_yaml_save_body(b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find(contains) != std::string::npos);
    };
    refused(json::array({y}), "must be a JSON object");
    refused(json("text"), "must be a JSON object");
    refused(json::object(), "yaml_source is required");
    refused(json{{"yaml_source", ""}}, "yaml_source is required");
    refused(json{{"yaml_source", 3}}, "yaml_source must be a string");
    refused(json{{"yaml_source", y}, {"id", 7}}, "id must be a string");
    // The unknown-key arm, with a valid source and every other key valid.
    refused(json{{"yaml_source", y}, {"z", 1}}, "unknown field");
    refused(json{{"yaml_source", y}, {"id", "x"}, {"updated_at", 1}, {"expected_updated_at", 1}},
            "unknown field");
    // The updated_at arm: a non-negative int64 only.
    for (const json& bad : {json("1"), json(-5), json(1.5), json(nullptr), json(true),
                            json::object(), json::array(), json(18446744073709551615ULL)})
        refused(json{{"yaml_source", y}, {"updated_at", bad}}, "updated_at");

    const auto zero = parse_yaml_save_body(json{{"yaml_source", y}, {"updated_at", 0}});
    REQUIRE(zero.has_value());
    REQUIRE(zero->expected_updated_at.has_value());
    CHECK(*zero->expected_updated_at == 0);
    const auto top = parse_yaml_save_body(
        json{{"yaml_source", y}, {"updated_at", std::numeric_limits<std::int64_t>::max()}});
    REQUIRE(top.has_value());
    CHECK(*top->expected_updated_at == std::numeric_limits<std::int64_t>::max());

    const auto full = parse_yaml_save_body(json{{"yaml_source", y}, {"id", "d1"}, {"updated_at", 42}});
    REQUIRE(full.has_value());
    CHECK(full->yaml_source == y);
    CHECK(full->id == "d1");
    CHECK(full->expected_updated_at == std::optional<std::int64_t>(42));
    const auto bare = parse_yaml_save_body(json{{"yaml_source", y}});
    REQUIRE(bare.has_value());
    CHECK(bare->id.empty());
    CHECK_FALSE(bare->expected_updated_at.has_value());
}

// 3a. Audit degradation, outcome row lost AFTER the mutation: the change stands, the answer keeps
// its status, the header says the trail is short. Rows from index 1 on are lost (the attempted row,
// index 0, is stored). Turns red if any handler's Auditor::outcome stops flagging Sec-Audit-Failed,
// or starts undoing / failing the write on a lost row.
namespace {
void check_outcome_row_lost(PgWired& w, Harness& h, bool throws) {
    w.store.set_require_signed_definitions(false);
    seed_def(w, seed_row("lost.update"));
    seed_def(w, seed_row("lost.delete"));
    seed_set(w, "lost-set");
    if (throws)
        h.audit_throw_from = 1;
    else
        h.audit_fail_from = 1;
    const auto lost = [&](auto&& r, int status) {
        REQUIRE(r);
        CHECK(r->status == status);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].result == "success");
        h.audits.clear();
    };
    lost(h.sink.Put("/api/v1/instructions/lost.update", R"({"description":"changed"})"), 200);
    CHECK(w.row("lost.update").description == "changed");
    lost(h.sink.Delete("/api/v1/instructions/lost.delete"), 200);
    CHECK_FALSE(w.get("lost.delete").has_value());
    lost(h.sink.Post("/api/v1/instructions/import", import_base("lost.import").dump()), 201);
    CHECK(w.get("lost.import").has_value());
    lost(h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", yaml_for("lost.yaml")}}.dump()),
         201);
    CHECK(w.get("lost.yaml").has_value());
    lost(h.sink.Post("/api/v1/instructions/yaml",
                     json{{"yaml_source", yaml_for("lost.yaml") + "  approval: auto\n"},
                          {"id", "lost.yaml"}}
                         .dump()),
         200);
    CHECK(w.row("lost.yaml").approval_mode == "auto");
    lost(h.sink.Post("/api/v1/instruction-sets", R"({"name":"lost set"})"), 201);
    CHECK(set_count(w) == 2);
    lost(h.sink.Delete("/api/v1/instruction-sets/lost-set"), 200);
    CHECK(set_count(w) == 1);
}
} // namespace

TEST_CASE("v1 definition and set writes: an outcome row that is not stored keeps the change and "
          "flags Sec-Audit-Failed",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    check_outcome_row_lost(w, h, /*throws=*/false);
}

TEST_CASE("v1 definition and set writes: an outcome row whose sink THROWS keeps the change and "
          "flags Sec-Audit-Failed",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    check_outcome_row_lost(w, h, /*throws=*/true);
}

// 3b. The attempted row is lost (returned false or thrown) on import and on both YAML shapes: 503
// with the retry hint, exactly the one attempt row, nothing stored, nothing changed. The create /
// update / delete / set routes are pinned by the cases above; these two routes were not.
namespace {
void check_attempt_row_lost_import_yaml(PgWired& w, Harness& h, bool throws) {
    w.store.set_require_signed_definitions(false);
    seed_def(w, seed_row("test.authoring.yaml"));
    h.audits.clear();
    if (throws)
        h.audit_throw_from = 0;
    else
        h.audit_fail_from = 0;
    const auto refused = [&](auto&& r) {
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(body(r->body)["error"]["retry_after_ms"] == 5000);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.emits.empty());
        h.audits.clear();
    };
    refused(h.sink.Post("/api/v1/instructions/import", import_base("af.import").dump()));
    refused(h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", yaml_for("af.yaml")}}.dump()));
    refused(h.sink.Post("/api/v1/instructions/yaml",
                        json{{"yaml_source", std::string(kYaml) + "  approval: auto\n"},
                             {"id", "test.authoring.yaml"}}
                            .dump()));
    CHECK_FALSE(w.get("af.import").has_value());
    CHECK_FALSE(w.get("af.yaml").has_value());
    CHECK(w.row("test.authoring.yaml").approval_mode == "always"); // the YAML update did not run
    CHECK(w.row("test.authoring.yaml").name == "Seed");
}
} // namespace

TEST_CASE("POST /api/v1/instructions/import and /yaml: an attempt row that is not stored refuses "
          "503; writes one row and changes nothing",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    check_attempt_row_lost_import_yaml(w, h, /*throws=*/false);
}

TEST_CASE("POST /api/v1/instructions/import and /yaml: an attempt row whose sink THROWS refuses the "
          "same way",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    check_attempt_row_lost_import_yaml(w, h, /*throws=*/true);
}

// 4. CWE-117 through create / update / delete / YAML save. A hostile name, description, plugin or id
// must reach neither the `detail` nor the `target_id` of any audit row raw. Each case first proves
// the hostile bytes survived INTO the store (so the fold, not the input filter, is what is tested),
// then reads every recorded row. Turns red if audit_label / audit_target / log_token is dropped
// from the attempt or outcome detail of the matching route, or from describe_dispatch_binding_change
// / describe_deleted_definition.
TEST_CASE("v1 definition writes: hostile name; description; plugin and id never reach an audit row "
          "raw (CWE-117)",
          "[pg][server][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string hostile_name = "a\r\nforged";
    const std::string hostile_desc = "d\x1b[31m\xe2\x80\xa8x\xe2\x80\xa9y";
    const std::string hostile_plugin = "p\r\nforged\xe2\x80\xa8";

    // Create: name and description in the attempted and success details.
    auto created = h.sink.Post("/api/v1/instructions",
                               json{{"name", hostile_name},
                                    {"description", hostile_desc},
                                    {"type", "question"},
                                    {"plugin", "os_info"},
                                    {"action", "os_name"}}
                                   .dump());
    REQUIRE(created);
    REQUIRE(created->status == 201);
    const auto created_id = body(created->body)["data"]["id"].get<std::string>();
    CHECK(w.row(created_id).name == hostile_name); // raw in the store
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail.find("forged") != std::string::npos); // visible, neutralised
    expect_no_forgery(h.audits);

    // A hostile id: the store refuses its charset (or the builder does); whatever rows exist are clean.
    h.audits.clear();
    auto bad_id = h.sink.Post("/api/v1/instructions",
                              json{{"id", "x\r\nforged"}, {"name", "n"}, {"type", "question"},
                                   {"plugin", "os_info"}}
                                  .dump());
    REQUIRE(bad_id);
    CHECK(bad_id->status == 400);
    expect_no_forgery(h.audits);

    // Update: a stored hostile plugin appears as the OLD value of the binding change.
    InstructionDefinition seeded = seed_row("cwe.seed");
    seeded.name = hostile_name;
    seeded.plugin = hostile_plugin;
    seeded.description = hostile_desc;
    seed_def(w, seeded);
    REQUIRE(w.row("cwe.seed").plugin == hostile_plugin);
    h.audits.clear();
    auto put = h.sink.Put("/api/v1/instructions/cwe.seed",
                          json{{"name", hostile_name}, {"description", hostile_desc},
                               {"plugin", "os_info"}}
                              .dump());
    REQUIRE(put);
    CHECK(put->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail.find("forged") != std::string::npos);
    expect_no_forgery(h.audits);

    // Delete: the pre-image tuple carries the hostile name.
    h.audits.clear();
    auto del = h.sink.Delete("/api/v1/instructions/cwe.seed");
    REQUIRE(del);
    CHECK(del->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail.find("forged") != std::string::npos);
    expect_no_forgery(h.audits);

    // YAML save, create: displayName and description straight from the source. A raw ESC and the
    // two Unicode separators are valid bytes inside a YAML scalar.
    const std::string yaml_create =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n"
        "  id: cwe.yaml\n  displayName: a\x1b[31mforged\xe2\x80\xa8x\n"
        "  description: d\xe2\x80\xa9y\x1b[0m\n"
        "spec:\n  plugin: os_info\n  action: os_name\n  type: question\n";
    h.audits.clear();
    auto y = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", yaml_create}}.dump());
    REQUIRE(y);
    REQUIRE(y->status == 201);
    CHECK(w.row("cwe.yaml").name.find('\x1b') != std::string::npos); // raw in the store
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail.find("forged") != std::string::npos);
    expect_no_forgery(h.audits);

    // YAML save, update: the stored hostile plugin is the old value of the binding change.
    InstructionDefinition ydef = seed_row("cwe.yaml2");
    ydef.plugin = hostile_plugin;
    seed_def(w, ydef);
    h.audits.clear();
    auto yu = h.sink.Post("/api/v1/instructions/yaml",
                          json{{"yaml_source", yaml_for("cwe.yaml2")}, {"id", "cwe.yaml2"}}.dump());
    REQUIRE(yu);
    CHECK(yu->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail.find("forged") != std::string::npos);
    expect_no_forgery(h.audits);
}

// 5. The 1 MiB yaml_source cap at the handler, N and N+1, on every REST route that carries one.
// Turns red if kMaxDefinitionYamlSourceBytes is raised or the cap check is dropped / off by one.
TEST_CASE("REST yaml_source cap: exactly 1 MiB is accepted; one byte more is refused before any "
          "store call (validate-yaml; /yaml) or as a denied import",
          "[pg][server][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string at_cap = yaml_of_size(kMaxDefinitionYamlSourceBytes);
    const std::string over_cap = yaml_of_size(kMaxDefinitionYamlSourceBytes + 1);
    constexpr const char* kTooLarge = "yaml_source too large (max 1MB)";

    // validate-yaml: N validates, N+1 reports the one byte-level error.
    auto v_ok = h.sink.Post("/api/v1/instructions/validate-yaml", json{{"yaml_source", at_cap}}.dump());
    REQUIRE(v_ok);
    CHECK(v_ok->status == 200);
    CHECK(body(v_ok->body)["data"]["valid"] == true);
    auto v_big = h.sink.Post("/api/v1/instructions/validate-yaml", json{{"yaml_source", over_cap}}.dump());
    REQUIRE(v_big);
    CHECK(body(v_big->body)["data"]["valid"] == false);
    REQUIRE(body(v_big->body)["data"]["errors"].size() == 1);
    CHECK(body(v_big->body)["data"]["errors"][0] == kTooLarge);

    // /yaml: N+1 is a 400 carrying the same error list, no audit row, nothing stored; N saves.
    auto big = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", over_cap}}.dump());
    REQUIRE(big);
    CHECK(big->status == 400);
    REQUIRE(body(big->body)["error"]["errors"].size() == 1);
    CHECK(body(big->body)["error"]["errors"][0] == kTooLarge);
    CHECK(h.audits.empty());
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->empty());
    auto fits = h.sink.Post("/api/v1/instructions/yaml", json{{"yaml_source", at_cap}}.dump());
    REQUIRE(fits);
    CHECK(fits->status == 201);
    CHECK(w.row("test.authoring.yaml").yaml_source.size() == kMaxDefinitionYamlSourceBytes);

    // import: the store owns the cap, so N+1 is a denied import (attempted + denied) naming it.
    h.audits.clear();
    json big_doc = import_base("authoring.import.big");
    big_doc["yaml_source"] = over_cap;
    auto imp_big = h.sink.Post("/api/v1/instructions/import", big_doc.dump());
    REQUIRE(imp_big);
    CHECK(imp_big->status == 400);
    CHECK(imp_big->body.find("too large") != std::string::npos);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "denied");
    CHECK_FALSE(w.get("authoring.import.big").has_value());
    json fit_doc = import_base("authoring.import.fits");
    fit_doc["yaml_source"] = at_cap;
    auto imp_ok = h.sink.Post("/api/v1/instructions/import", fit_doc.dump());
    REQUIRE(imp_ok);
    CHECK(imp_ok->status == 201);
    CHECK(w.row("authoring.import.fits").yaml_source.size() == kMaxDefinitionYamlSourceBytes);
}

// 6. The JSON nesting guard on every body-reading REST route. A body nested one level past
// mcp::kMcpMaxJsonDepth is a 400 "nests too deeply" with no audit row and no store effect; one at
// exactly the limit passes the guard (it then fails on its content, with a different message).
// Turns red if parse_object_body's json_exceeds_depth check is removed or moved after the parse.
TEST_CASE("REST write routes: a body nested past kMcpMaxJsonDepth is refused 400 before any audit "
          "row or store call; the limit itself is admitted by the guard",
          "[pg][server][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Harness h;
    h.store = &w.store;
    h.wire();
    const std::string too_deep = nested_json(mcp::kMcpMaxJsonDepth + 1);
    const std::string at_limit = nested_json(mcp::kMcpMaxJsonDepth);
    const auto call = [&](const std::string& route, const std::string& b) {
        if (route == "PUT")
            return h.sink.Put("/api/v1/instructions/d1", b);
        return h.sink.Post(route, b);
    };
    const std::vector<std::string> routes{"/api/v1/instructions",      "PUT",
                                          "/api/v1/instructions/import", "/api/v1/instructions/yaml",
                                          "/api/v1/instruction-sets",    "/api/v1/instructions/validate-yaml"};
    for (const std::string& route : routes) {
        INFO(route);
        auto deep = call(route, too_deep);
        REQUIRE(deep);
        CHECK(deep->status == 400);
        CHECK(error_message(deep->body) == "request body nests too deeply");
    }
    CHECK(h.audits.empty());
    CHECK(h.emits.empty());
    auto all = w.store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->empty());
    // Exactly at the limit the guard admits the body; it is then refused (or not found) on its
    // content, never as "nests too deeply". (These may write denied rows: only the message matters.)
    for (const std::string& route : routes) {
        INFO(route);
        auto limit = call(route, at_limit);
        REQUIRE(limit);
        CHECK(limit->body.find("nests too deeply") == std::string::npos);
    }
}

// 7. The server.cpp wiring of the authoring routes. The route tests above hand the routes a
// Harness whose perm_fn always allows and whose audit_fn always stores, so they cannot see a
// server.cpp that registers the routes with a permissive gate, no gate, or no audit sink. This
// reads server.cpp and checks the registration block, then proves the checker itself by running it
// over mutated copies of the real source (each of which it must flag).
namespace {

/// Text of `src` from `from` up to (not including) the next occurrence of `to` after it.
std::string between(const std::string& src, const std::string& from, const std::string& to) {
    const auto b = src.find(from);
    if (b == std::string::npos)
        return {};
    const auto e = src.find(to, b + from.size());
    return src.substr(b, e == std::string::npos ? std::string::npos : e - b);
}

/// Every defect in server.cpp's batch C authoring wiring (empty = wired as required).
std::vector<std::string> authoring_wiring_defects(const std::string& src) {
    std::vector<std::string> defects;
    const std::string decl = "instruction_authoring::RouteDeps authoring_deps;";
    const std::string reg =
        "yuzu::server::instruction_authoring::register_instruction_authoring_routes(\n"
        "                authoring_sink, std::move(authoring_deps));";
    if (src.find(decl) == std::string::npos) {
        defects.push_back("RouteDeps authoring_deps is not declared");
        return defects;
    }
    if (src.find(reg, src.find(decl)) == std::string::npos)
        defects.push_back("register_instruction_authoring_routes is not called with authoring_deps");

    const std::string perm = between(src, "authoring_deps.perm_fn = ", "authoring_deps.audit_fn = ");
    if (perm.find("return require_permission(req, res, securable_type, operation);") ==
        std::string::npos)
        defects.push_back("perm_fn does not return require_permission(...)");
    if (perm.find("return true") != std::string::npos)
        defects.push_back("perm_fn contains a permissive return");

    const std::string audit =
        between(src, "authoring_deps.audit_fn = ", "authoring_deps.resolve_session_fn = ");
    if (audit.find("return audit_log(req, action, result, target_type, target_id, detail);") ==
        std::string::npos)
        defects.push_back("audit_fn is unset or does not return audit_log(...)");

    for (const char* needed : {"authoring_deps.resolve_session_fn = resolve_session_fn;",
                               "authoring_deps.emit_event_fn = emit_event_fn;",
                               "authoring_deps.store = instruction_store_.get();",
                               "authoring_deps.referrers_fn = definition_referrers_fn;",
                               "authoring_deps.metrics = &metrics_;"})
        if (src.find(needed) == std::string::npos)
            defects.push_back(std::string("missing assignment: ") + needed);
    return defects;
}

/// `src` with the first `from` at or after the `anchor` replaced by `to` (REQUIREs it exists).
std::string mutate(std::string src, const std::string& anchor, const std::string& from,
                   const std::string& to) {
    const auto a = src.find(anchor);
    REQUIRE(a != std::string::npos);
    const auto p = src.find(from, a);
    REQUIRE(p != std::string::npos);
    src.replace(p, from.size(), to);
    return src;
}

} // namespace

TEST_CASE("instruction authoring: wiring -- server.cpp registers the v1 routes behind the real "
          "permission gate and audit sink",
          "[server][instruction_authoring]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};

    const auto real = authoring_wiring_defects(src);
    for (const auto& d : real)
        FAIL_CHECK(d);
    CHECK(real.empty());

    // The checker catches each regression the route tests cannot see.
    const std::string anchor = "authoring_deps;";
    SECTION("the register call is removed") {
        const auto bad = authoring_wiring_defects(
            mutate(src, anchor, "register_instruction_authoring_routes(",
                   "register_instruction_authoring_routes_removed("));
        CHECK_FALSE(bad.empty());
    }
    SECTION("perm_fn is replaced by a lambda that always admits") {
        const auto bad = authoring_wiring_defects(
            mutate(src, "authoring_deps.perm_fn = ",
                   "return require_permission(req, res, securable_type, operation);", "return true;"));
        CHECK_FALSE(bad.empty());
    }
    SECTION("perm_fn is never assigned") {
        const auto bad = authoring_wiring_defects(
            mutate(src, anchor, "authoring_deps.perm_fn = ", "authoring_deps.perm_unused = "));
        CHECK_FALSE(bad.empty());
    }
    SECTION("audit_fn is left unset") {
        const auto bad = authoring_wiring_defects(
            mutate(src, anchor, "authoring_deps.audit_fn = ", "authoring_deps.audit_unused = "));
        CHECK_FALSE(bad.empty());
    }
    SECTION("audit_fn no longer writes the audit log") {
        const auto bad = authoring_wiring_defects(
            mutate(src, "authoring_deps.audit_fn = ",
                   "return audit_log(req, action, result, target_type, target_id, detail);",
                   "return true;"));
        CHECK_FALSE(bad.empty());
    }
    SECTION("the store is not handed over") {
        const auto bad = authoring_wiring_defects(
            mutate(src, anchor, "authoring_deps.store = instruction_store_.get();",
                   "authoring_deps.store = nullptr;"));
        CHECK_FALSE(bad.empty());
    }
}
