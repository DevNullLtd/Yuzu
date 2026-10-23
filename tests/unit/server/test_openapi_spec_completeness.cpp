/**
 * test_openapi_spec_completeness.cpp - #3991 (F1), the in-process unit-test
 * half of ADR-0031 INV-31-4's missing contract test (docs/adr/
 * 0031-presentation-core-engine-decomposition.md: "a contract test ...
 * does not exist today. It is a deliverable of migration step 3.") and the
 * unit-test half of #842.
 *
 * Registers `RestApiV1::register_routes()` against an in-process
 * `TestRouteSink` (PR #438's TSan-safe harness - see test_route_sink.hpp's
 * header comment for its two invariants: declare the sink AFTER the route
 * owner, and pass content-type explicitly on form POSTs; neither applies
 * here since this file never dispatches a request), enumerates the
 * registered (method, pattern) pairs, parses `openapi_spec_json()`'s JSON,
 * and asserts every registered route has a matching `paths` entry - plus a
 * whole-document `$ref` validity check.
 *
 * SCOPE - READ BEFORE TRUSTING THIS FILE AS EXHAUSTIVE. Every store/engine
 * dependency below is passed as `nullptr`/`{}`, so any route registration
 * gated behind `if (<store>)` inside `RestApiV1::register_routes()` never
 * fires - this file sees a SUBSET of the full v1 route table (102 of 173
 * at #3991-time, measured; see the route-count floor below), not all of it. It also
 * covers `RestApiV1` alone, not the several other route-owner files that
 * also register `/api/v1` routes (ca_routes.cpp, auth_routes.cpp,
 * viz_routes.cpp, etc. - `scripts/ci/check-api-parity.py --dump-json` shows
 * the full list). The EXHAUSTIVE, whole-tree gate is
 * `scripts/ci/check-api-parity.py`, run as a CI preflight step: it lexically
 * extracts routes from every source file under server/core/src, not just the ones
 * a `nullptr`-heavy in-process harness can construct. This file exists so
 * the specific, common regression class (a route added to `register_routes`
 * with no matching OpenAPI entry) fails fast in a unit-test loop, not only
 * on the next CI preflight run.
 *
 * ALLOWLIST - kept intentionally small and hand-verified against
 * `scripts/ci/api-parity`'s `ALLOWLIST_OPENAPI_MISSING` (the Python script's
 * list is authoritative and larger - 40 entries as of #3991 - because it
 * sees routes gated behind non-null stores too; this file's list is the
 * subset of those 40 that RestApiV1 registers even with every store
 * `nullptr`, i.e. unconditionally).
 */

#include "crypto_library_model.hpp"
#include "openapi_spec_access.hpp"
#include "rest_api_v1.hpp"
#include "software_catalog_rules.hpp" // kEcosystemFamilies: the published ecosystem vocabulary
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// Mirrors (independently - this file does not share code with the Python
/// script, so a bug in one is unlikely to be masked by the same bug in the
/// other) `canonicalize()` in scripts/ci/check-api-parity.py: collapses a
/// regex capture group (`([^/]+)`, `(\d+)`, ...) or an OpenAPI `{param}`
/// segment into a single `{param}` token, splitting on '/' ONLY outside any
/// `(...)` run so a capture group's own internal '/' (`([^/]+)` is the
/// majority pattern in this codebase) never produces a spurious extra
/// segment.
std::string mask_paren_groups(const std::string& s) {
    std::string out;
    int depth = 0;
    for (char c : s) {
        if (c == '(') {
            if (depth == 0)
                out.push_back('\0');
            ++depth;
        } else if (c == ')') {
            if (depth > 0)
                --depth;
        } else if (depth == 0) {
            out.push_back(c);
        }
    }
    return out;
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

bool has_metachar(const std::string& seg) {
    return seg.find('\0') != std::string::npos ||
           seg.find_first_of("[]*+?|\\") != std::string::npos;
}

bool is_brace_param(const std::string& seg) {
    static const std::regex kBrace(R"(\{[^{}]*\})");
    return !seg.empty() && std::regex_match(seg, kBrace);
}

std::string canonicalize(const std::string& path) {
    auto segs = split(mask_paren_groups(path), '/');
    std::string out;
    for (std::size_t i = 0; i < segs.size(); ++i) {
        if (i)
            out.push_back('/');
        const auto& seg = segs[i];
        if (seg.empty())
            continue;
        if (is_brace_param(seg) || has_metachar(seg))
            out += "{param}";
        else
            out += seg;
    }
    return out;
}

/// Small, hand-verified subset of check-api-parity.py's
/// ALLOWLIST_OPENAPI_MISSING - see file header comment. Cross-check against
/// the Python script's list before adding here. The ten F2-backlog entries
/// this set used to carry (statistics, topology, inventory/evaluate,
/// elevation-eligibility, execution-statistics, sessions, tar purge) were
/// backfilled into openapi_spec() by #3992 (merged 2026-09-06) and pruned
/// here in lockstep with the Python side's own reconciliation
/// (commit 3871688f6) - do not let the two allowlists drift again.
const std::set<std::pair<std::string, std::string>>& allowlisted_missing() {
    static const std::set<std::pair<std::string, std::string>> kAllowlist = {
        // Blanket CORS preflight - every /api/v1/* path answers OPTIONS the
        // same way; not a discrete documentable capability.
        {"OPTIONS", "/api/v1/{param}"},
    };
    return kAllowlist;
}

/// Walks the ENTIRE OpenAPI document collecting every string value that
/// starts with "#/" - not only values under a literal "$ref" key. The
/// `discriminator.mapping` values (rest_api_v1.cpp:713-717) are refs too,
/// and a "$ref"-key-only walk misses them.
void collect_ref_targets(const json& node, std::vector<std::string>& out) {
    if (node.is_object()) {
        for (const auto& [key, value] : node.items()) {
            if (value.is_string() && value.get<std::string>().starts_with("#/")) {
                out.push_back(value.get<std::string>());
            } else {
                collect_ref_targets(value, out);
            }
        }
    } else if (node.is_array()) {
        for (const auto& v : node)
            collect_ref_targets(v, out);
    }
}

/// The node a "#/a/b/c" ref points at, or nullptr when a part is missing.
const json* resolve_ref(const json& spec, const std::string& ref) {
    // ref is "#/a/b/c" -> walk spec["a"]["b"]["c"].
    std::string path = ref.substr(1); // drop leading '#'
    const json* node = &spec;
    for (const auto& part : split(path, '/')) {
        if (part.empty())
            continue;
        if (!node->is_object() || !node->contains(part))
            return nullptr;
        node = &(*node)[part];
    }
    return node;
}

bool ref_resolves(const json& spec, const std::string& ref) {
    return resolve_ref(spec, ref) != nullptr;
}

json param(const json& op, const char* name) {
    // value(), not operator[]: on a const json a missing key asserts and aborts the whole shard.
    for (const auto& p : op.value("parameters", json::array()))
        if (p.value("name", "") == name)
            return p;
    return json();
}

/// One `ecosystem` parameter found in a document: where it sits and its resolved schema.
struct EcosystemParam {
    std::string where;
    json schema;
};

/// Every parameter named `ecosystem` under every path item and operation (path-level
/// `parameters` included). A Parameter Object or a schema that is a `$ref` is resolved BEFORE the
/// name check, since a referenced parameter carries no `name` of its own.
std::vector<EcosystemParam> ecosystem_parameter_schemas(const json& spec) {
    std::vector<EcosystemParam> found;
    const auto collect = [&](const json& params, const std::string& where) {
        if (!params.is_array())
            return;
        for (const auto& p : params) {
            INFO(where);
            const json* node = &p;
            if (p.contains("$ref")) {
                node = resolve_ref(spec, p["$ref"].get<std::string>());
                REQUIRE(node != nullptr);
            }
            if (node->value("name", "") != "ecosystem")
                continue;
            json schema = node->value("schema", json::object());
            if (schema.contains("$ref")) {
                const json* target = resolve_ref(spec, schema["$ref"].get<std::string>());
                REQUIRE(target != nullptr);
                schema = *target;
            }
            found.push_back({where, schema});
        }
    };
    for (const auto& [path, item] : spec["paths"].items()) {
        if (!item.is_object())
            continue;
        for (const auto& [key, node] : item.items()) {
            if (key == "parameters")
                collect(node, path);
            else if (node.is_object() && node.contains("parameters"))
                collect(node["parameters"], key + " " + path);
        }
    }
    return found;
}

} // namespace

TEST_CASE("canonicalize: capture group with internal '/' collapses to one {param}",
          "[openapi][canonicalize]") {
    REQUIRE(canonicalize("/api/v1/policies/([^/]+)") == "/api/v1/policies/{param}");
    REQUIRE(canonicalize("/api/v1/plugin-config/([^/]+)/([^/]+)/secret") ==
            "/api/v1/plugin-config/{param}/{param}/secret");
}

TEST_CASE("canonicalize: OpenAPI {id}-style param matches the same shape",
          "[openapi][canonicalize]") {
    REQUIRE(canonicalize("/api/v1/management-groups/{id}") ==
            canonicalize("/api/v1/management-groups/([a-f0-9]+)"));
}

TEST_CASE("RestApiV1::register_routes vs openapi_spec_json(): every registered "
          "/api/v1 route has a matching OpenAPI paths entry",
          "[openapi][completeness]") {
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    RestApiV1::AuthFn auth_fn = [](const httplib::Request&,
                                   httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "tester";
        s.role = auth::Role::admin;
        return s;
    };
    RestApiV1::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                   const std::string&, const std::string&) { return true; };
    RestApiV1::AuditFn audit_fn = [](const httplib::Request&, const std::string&,
                                     const std::string&, const std::string&,
                                     const std::string&, const std::string&) { return true; };

    // Every store/engine dependency nullptr/{} - see file header SCOPE note.
    // This is the shortest legal call: everything from `service_group_fn`
    // onward in rest_api_v1.hpp's sink-based register_routes overload is
    // trailing-optional.
    api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                        /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                        /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr);

    // Floor, not an exact count: a nullptr-heavy harness registers a real
    // subset (102 of the 173 v1 routes at #3991-time, measured) of the full
    // table - the unconditional registrations plus a few default-true store
    // checks. This floor guards against a wholesale registration collapse
    // going unnoticed (e.g. an exception thrown mid-register_routes silently
    // short-circuiting everything after it) with margin below the measured
    // value so it doesn't flake on an unrelated route addition/removal.
    REQUIRE(sink.route_count() >= 90);

    const auto& spec_json = yuzu::server::openapi_spec_json();
    json spec = json::parse(spec_json, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));
    REQUIRE(spec["paths"].is_object());

    std::set<std::pair<std::string, std::string>> openapi_routes;
    static const std::vector<std::pair<std::string, std::string>> kMethods = {
        {"get", "GET"}, {"post", "POST"}, {"put", "PUT"},
        {"delete", "DELETE"}, {"patch", "PATCH"}, {"options", "OPTIONS"},
    };
    for (const auto& [path, ops] : spec["paths"].items()) {
        if (!ops.is_object())
            continue;
        for (const auto& [lower, upper] : kMethods) {
            if (ops.contains(lower))
                openapi_routes.emplace(upper, canonicalize("/api/v1" + path));
        }
    }

    std::vector<std::pair<std::string, std::string>> missing;
    for (const auto& [method, pattern] : sink.registered_routes()) {
        if (!pattern.starts_with("/api/v1"))
            continue;
        auto key = std::make_pair(method, canonicalize(pattern));
        if (openapi_routes.contains(key))
            continue;
        if (allowlisted_missing().contains(key))
            continue;
        missing.push_back(key);
    }

    // Build ONE joined string rather than one INFO() per loop iteration -
    // each INFO() is a scoped RAII guard that goes out of scope at the end
    // of its own (brace-less) loop body, so per-iteration INFO calls are
    // gone by the time the REQUIRE below runs and would silently print
    // nothing on failure.
    std::string missing_list;
    for (const auto& [m, p] : missing)
        missing_list += "  " + m + " " + p + "\n";
    INFO("Registered /api/v1 routes with no OpenAPI paths entry and not in "
         "the allowlist (cross-check against scripts/ci/check-api-parity.py's "
         "ALLOWLIST_OPENAPI_MISSING before adding here):\n"
         << missing_list);
    REQUIRE(missing.empty());
}

TEST_CASE("openapi_spec_json(): info.description states the cookie-session same-site rule",
          "[openapi]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("info"));
    REQUIRE(spec["info"].contains("description"));
    const std::string description = spec["info"]["description"].get<std::string>();
    CHECK(description.find("authorised by the session cookie must carry an Origin or Referer "
                           "header naming this site") != std::string::npos);
    CHECK(description.find("--csrf-trusted-origin") != std::string::npos);
    CHECK(description.find("cross-site request refused") != std::string::npos);
    CHECK(description.find("Token callers are not affected, except routes "
                           "that keep their own check") != std::string::npos);
    CHECK(description.find("Cookie-session reads that dispatch work, persist state or refresh "
                           "server state") != std::string::npos);
}

TEST_CASE("openapi_spec_json(): the app-usage Forensics path is documented (Wave 7 PR7.2)",
          "[openapi][app_usage]") {
    const auto& spec_json = yuzu::server::openapi_spec_json();
    json spec = json::parse(spec_json, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));

    const auto& paths = spec["paths"];
    REQUIRE(paths.contains("/forensics/agents/{agent_id}/app-usage"));
    const auto& path_obj = paths["/forensics/agents/{agent_id}/app-usage"];
    REQUIRE(path_obj.contains("get"));
    const auto& get_op = path_obj["get"];

    REQUIRE(get_op.contains("tags"));
    CHECK(get_op["tags"][0] == "Forensics");

    REQUIRE(get_op.contains("responses"));
    const auto& responses = get_op["responses"];
    CHECK(responses.contains("200"));
    CHECK(responses.contains("401"));
    CHECK(responses.contains("403"));
    CHECK(responses.contains("503"));
    // The 503 leg must carry the Sec-Audit-Failed header — the fail-closed
    // audit-tier contract every behavioural-data route in this file shares.
    REQUIRE(responses["503"].contains("headers"));
    CHECK(responses["503"]["headers"].contains("Sec-Audit-Failed"));

    // Retained-window honesty (adjudication P3): first_seen/last_seen must
    // never be described as all-time.
    const std::string description = get_op.value("description", "");
    CHECK(description.find("retained") != std::string::npos);
    CHECK(description.find("all-time") == std::string::npos);
}

TEST_CASE("openapi_spec_json(): the /crypto reads pin the family enum and the bounds to the model",
          "[openapi][crypto]") {
    namespace cl = yuzu::server::crypto_library;
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    json ids = json::array();
    for (const auto& f : cl::families())
        ids.push_back(std::string(f.id));

    const auto& summary = spec["paths"]["/crypto/libraries"]["get"];
    const auto& devices = spec["paths"]["/crypto/libraries/devices"]["get"];
    const auto& cbom = spec["paths"]["/crypto/cbom"]["get"];
    CHECK(param(summary, "family")["schema"]["enum"] == ids);
    CHECK(param(cbom, "family")["schema"]["enum"] == ids);
    CHECK(param(cbom, "ecosystem")["schema"]["maxLength"] == cl::kEcosystemMaxBytes);
    CHECK(param(devices, "family")["schema"]["enum"] == ids);
    CHECK(param(summary, "ecosystem")["schema"]["maxLength"] == cl::kEcosystemMaxBytes);
    CHECK(param(devices, "ecosystem")["schema"]["maxLength"] == cl::kEcosystemMaxBytes);
    // The CBOM's Vary header documents what the route actually sets, and its description opens
    // with what the document IS (library components only).
    CHECK(cbom["responses"]["200"]["headers"]["Vary"]["schema"]["enum"][0] ==
          "Authorization, Cookie, X-Yuzu-Token");
    CHECK(cbom["description"].get<std::string>().find(
              "Vary: Authorization, Cookie, X-Yuzu-Token") != std::string::npos);
    CHECK(cbom["description"].get<std::string>().find("cryptographic LIBRARY packages") !=
          std::string::npos);
    // The 8-name cap and the every-family store-ceiling flag are stated, not silent.
    CHECK(summary["description"].get<std::string>().find("package_names_truncated") !=
          std::string::npos);
    CHECK(summary["responses"]["200"]["description"].get<std::string>().find(
              "package_names_truncated") != std::string::npos);
    CHECK(param(devices, "version")["schema"]["maxLength"] == cl::kVersionMaxBytes);
    CHECK(param(devices, "cursor")["schema"]["maxLength"] == cl::kCursorMaxBytes);
    CHECK(param(devices, "limit")["schema"]["maximum"] == cl::kPageMax);
    CHECK(param(devices, "limit")["schema"]["default"] == cl::kDefaultLimit);
    // table_version is documented on both answers; a refused cross-version cursor on the drill.
    CHECK(summary["responses"]["200"]["description"].get<std::string>().find("table_version") !=
          std::string::npos);
    CHECK(devices["responses"]["200"]["description"].get<std::string>().find("table_version") !=
          std::string::npos);
    CHECK(devices["responses"]["400"]["description"].get<std::string>().find("table_version") !=
          std::string::npos);
    // The filter params are EXACT when present (even empty): none says "no filter" for empty.
    for (const json* op : {&summary, &devices}) {
        const auto eco = param(*op, "ecosystem")["description"].get<std::string>();
        CHECK(eco.find("no filter") == std::string::npos);
        CHECK(eco.find("present") != std::string::npos);
    }
    CHECK(param(devices, "version")["description"].get<std::string>().find("present") !=
          std::string::npos);
    // The drill echoes the ecosystem filter the way it echoes version; 503 names the admission bound.
    CHECK(devices["responses"]["200"]["description"].get<std::string>().find("ecosystem|null") !=
          std::string::npos);
    for (const json* op : {&summary, &devices}) {
        // Both 503 causes are named, each with its message; the not-built 503 is gone.
        const auto d503 = (*op)["responses"]["503"]["description"].get<std::string>();
        CHECK(d503.find("capacity in use") != std::string::npos);
        CHECK(d503.find("crypto library read degraded") != std::string::npos);
        CHECK(d503.find("not built") == std::string::npos);
        // The names' source is documented on the 200 body and in the description.
        CHECK((*op)["responses"]["200"]["description"].get<std::string>().find("names_source") !=
              std::string::npos);
        CHECK((*op)["description"].get<std::string>().find("names_source") != std::string::npos);
        CHECK((*op)["description"].get<std::string>().find("live") != std::string::npos);
    }
}

TEST_CASE("openapi_spec_json(): the RBAC role reads document 403/404/503 and the retry semantics",
          "[openapi][rbac]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const auto& paths = spec["paths"];

    auto response_keys = [](const json& op) {
        std::set<std::string> keys;
        for (auto it = op["responses"].begin(); it != op["responses"].end(); ++it)
            keys.insert(it.key());
        return keys;
    };

    REQUIRE(paths.contains("/rbac/roles"));
    const auto& roles = paths["/rbac/roles"]["get"];
    CHECK(response_keys(roles) == std::set<std::string>{"200", "403", "503"});
    CHECK(roles.value("description", "").find("retry_after_ms") != std::string::npos);

    REQUIRE(paths.contains("/rbac/roles/{role}/permissions"));
    const auto& perms = paths["/rbac/roles/{role}/permissions"]["get"];
    CHECK(response_keys(perms) == std::set<std::string>{"200", "403", "404", "503"});
    CHECK(perms.value("description", "").find("retry_after_ms") != std::string::npos);
}

TEST_CASE("openapi_spec_json(): POST /hardware/sync documents the fan-out request and every refusal",
          "[openapi][hardware][sync_fanout]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const auto& paths = spec["paths"];

    // The collection route is its own path, distinct from the per-device one.
    REQUIRE(paths.contains("/hardware/sync"));
    REQUIRE(paths.contains("/hardware/{id}/sync"));
    REQUIRE(paths["/hardware/sync"].contains("post"));
    CHECK_FALSE(paths["/hardware/sync"].contains("get"));
    const auto& op = paths["/hardware/sync"]["post"];

    REQUIRE(op.contains("tags"));
    CHECK(op["tags"][0] == "Hardware");
    const std::string description = op.value("description", "");
    CHECK(description.find("Execution:Execute") != std::string::npos);
    CHECK(description.find("500") != std::string::npos);

    // Request body: required, JSON, with the three documented properties.
    REQUIRE(op.contains("requestBody"));
    CHECK(op["requestBody"]["required"] == true);
    REQUIRE(op["requestBody"]["content"].contains("application/json"));
    const auto& props = op["requestBody"]["content"]["application/json"]["schema"]["properties"];
    REQUIRE(props.contains("scope"));
    REQUIRE(props.contains("scope_expression"));
    REQUIRE(props.contains("source"));
    CHECK(props["scope"]["type"] == "string");
    CHECK(props["scope_expression"]["type"] == "string");
    CHECK(props["scope_expression"]["maxLength"] == 1024);
    CHECK(props["source"]["enum"] == json::array({"installed_software"}));
    CHECK(props.size() == 3);
    // Machine-readable bounds and the exactly-one-selector rule, not prose alone.
    CHECK(props["scope"]["minLength"] == 1);
    CHECK(props["scope"]["maxLength"] == 256);
    CHECK(props["scope_expression"]["minLength"] == 1);
    const auto& req_schema = op["requestBody"]["content"]["application/json"]["schema"];
    CHECK(req_schema["oneOf"] ==
          json::array({json{{"required", json::array({"scope"})}},
                       json{{"required", json::array({"scope_expression"})}}}));

    // Every status the route can answer, no more and no fewer.
    REQUIRE(op.contains("responses"));
    std::set<std::string> keys;
    for (auto it = op["responses"].begin(); it != op["responses"].end(); ++it)
        keys.insert(it.key());
    CHECK(keys == std::set<std::string>{"202", "400", "401", "403", "409", "413", "429", "500", "503"});
    // The 202 shape names the four counts and carries no per-device list.
    const std::string accepted = op["responses"]["202"].value("description", "");
    for (const char* field : {"requested", "agents_reached", "skipped_offline", "skipped_version", "command_id"})
        CHECK(accepted.find(field) != std::string::npos);
    // skipped_offline is defined as "not reached by this server process", not "disconnected", and
    // the counts are said not to be a census of the fleet (in the 202 text and the description).
    CHECK(accepted.find("this server process did not reach") != std::string::npos);
    CHECK(accepted.find("not the fleet") != std::string::npos);
    CHECK(description.find("not a census of the fleet") != std::string::npos);
    CHECK(description.find("the send was refused by the live stream") != std::string::npos);
    // The 429 leg names its Retry-After and the 413 leg its cap.
    CHECK(op["responses"]["429"].value("description", "").find("Retry-After") != std::string::npos);
    CHECK(op["responses"]["413"].value("description", "").find("500") != std::string::npos);
    // The 429 carries a typed integer Retry-After header; the 202 is a typed envelope; every
    // refusal body is the A4 error envelope.
    REQUIRE(op["responses"]["429"].contains("headers"));
    REQUIRE(op["responses"]["429"]["headers"].contains("Retry-After"));
    CHECK(op["responses"]["429"]["headers"]["Retry-After"]["schema"]["type"] == "integer");
    REQUIRE(op["responses"]["202"].contains("content"));
    const auto& accepted_schema =
        op["responses"]["202"]["content"]["application/json"]["schema"];
    REQUIRE(accepted_schema.contains("properties"));
    REQUIRE(accepted_schema["properties"].contains("data"));
    CHECK(accepted_schema["required"] == json::array({"data", "meta"}));
    for (const char* field : {"requested", "agents_reached", "skipped_offline", "skipped_version",
                              "command_id", "source", "requested_at"})
        CHECK(accepted_schema["properties"]["data"]["properties"].contains(field));
    for (const char* code : {"400", "403", "409", "413", "429", "500", "503"}) {
        REQUIRE(op["responses"][code].contains("content"));
        CHECK(op["responses"][code]["content"]["application/json"]["schema"]["$ref"] ==
              "#/components/schemas/A4ErrorEnvelope");
    }
}

TEST_CASE("openapi_spec_json(): the kill-switch routes document the per-OS query parameter and "
          "response shape (#5294)",
          "[openapi][plugin_config][5294]") {
    const auto& spec_json = yuzu::server::openapi_spec_json();
    json spec = json::parse(spec_json, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec["paths"].contains("/plugin-config/{plugin}/kill-switch"));
    const auto& path_obj = spec["paths"]["/plugin-config/{plugin}/kill-switch"];

    for (const char* method : {"get", "put"}) {
        INFO("method: " << method);
        REQUIRE(path_obj.contains(method));
        const auto& op = path_obj[method];

        const json* os_param = nullptr;
        for (const auto& p : op["parameters"])
            if (p.value("name", "") == "os")
                os_param = &p;
        REQUIRE(os_param != nullptr);
        CHECK((*os_param)["in"] == "query");
        CHECK((*os_param)["required"] == false);
        CHECK((*os_param)["schema"]["enum"] == json::array({"windows", "linux", "darwin"}));

        const std::string ok = op["responses"]["200"].value("description", "");
        CHECK(ok.find("os") != std::string::npos);
        CHECK(ok.find("source") != std::string::npos);

        // The protective-set caveat is part of the published contract.
        const std::string desc = op.value("description", "");
        CHECK(desc.find("__guard__.push_rules") != std::string::npos);
        CHECK(desc.find("unquarantine") != std::string::npos);
        CHECK(desc.find(std::string(method) == "get" ? "dispatch still proceeds"
                                                      : "no dispatch effect") !=
              std::string::npos);

        // ...and so are the parameter-level caveats: GET's `os` description and PUT's
        // `enabled` property.
        if (std::string(method) == "get") {
            const std::string os_desc = (*os_param).value("description", "");
            CHECK(os_desc.find("never gates dispatch") != std::string::npos);
        } else {
            const auto& enabled =
                op["requestBody"]["content"]["application/json"]["schema"]["properties"]["enabled"];
            const std::string enabled_desc = enabled.value("description", "");
            CHECK(enabled_desc.find("no dispatch effect") != std::string::npos);
        }
    }
}

TEST_CASE("openapi_spec_json(): the execution-statistics reads document their degraded-read 503 "
          "(A4 envelope, retry_after_ms 2000)",
          "[openapi][execution_statistics]") {
    const auto& spec_json = yuzu::server::openapi_spec_json();
    json spec = json::parse(spec_json, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));

    for (const char* path : {"/execution-statistics", "/execution-statistics/agents",
                             "/execution-statistics/definitions", "/statistics"}) {
        INFO("path: " << path);
        REQUIRE(spec["paths"].contains(path));
        const auto& get_op = spec["paths"][path]["get"];
        REQUIRE(get_op.contains("responses"));
        REQUIRE(get_op["responses"].contains("503"));
        const auto& r503 = get_op["responses"]["503"];
        const std::string desc = r503.value("description", "");
        CHECK(desc.find("retry_after_ms 2000") != std::string::npos);
        REQUIRE(r503.contains("content"));
        CHECK(r503["content"]["application/json"]["schema"]["$ref"] ==
              "#/components/schemas/A4ErrorEnvelope");
    }
}

TEST_CASE("openapi_spec_json(): the stored-response reads document the unresolved-Forensics-authority 503 "
          "(#4990), and only the ones that write a forensics audit row name that audit failure",
          "[openapi][forensics_tier]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const auto desc503 = [&](const char* path) {
        REQUIRE(spec["paths"].contains(path));
        const auto& r = spec["paths"][path]["get"]["responses"];
        REQUIRE(r.contains("503"));
        CHECK(r["503"]["content"]["application/json"]["schema"]["$ref"] ==
              "#/components/schemas/A4ErrorEnvelope");
        return r["503"].value("description", "");
    };
    constexpr std::string_view kAuthority = "Forensics authority could not be determined (retryable)";
    constexpr std::string_view kForensicsAudit = "response.forensics.read audit row could not persist";
    for (const char* path : {"/responses/{id}", "/responses/{id}/export"}) {
        INFO("path: " << path);
        const auto d = desc503(path);
        CHECK(d.find(kAuthority) != std::string::npos);
        CHECK(d.find(kForensicsAudit) != std::string::npos);
    }
    {
        // The aggregate returns only counts and writes no response.forensics.read row, so it names
        // the unresolved authority but not that audit failure.
        const auto d = desc503("/responses/{id}/aggregate");
        CHECK(d.find(kAuthority) != std::string::npos);
        CHECK(d.find(kForensicsAudit) == std::string::npos);
        CHECK(d.find("response.read audit row could not persist") != std::string::npos);
    }
}

TEST_CASE("openapi_spec_json(): every $ref (including discriminator.mapping "
          "values) resolves to an existing component",
          "[openapi][refs]") {
    const auto& spec_json = yuzu::server::openapi_spec_json();
    json spec = json::parse(spec_json, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());

    std::vector<std::string> refs;
    collect_ref_targets(spec, refs);
    REQUIRE_FALSE(refs.empty()); // sanity: the spec does use $ref somewhere

    std::vector<std::string> unresolved;
    for (const auto& ref : refs) {
        if (!ref_resolves(spec, ref))
            unresolved.push_back(ref);
    }
    std::string unresolved_list;
    for (const auto& r : unresolved)
        unresolved_list += "  " + r + "\n";
    INFO("Unresolved $ref targets:\n" << unresolved_list);
    REQUIRE(unresolved.empty());
}

TEST_CASE("openapi_spec_json(): every ecosystem parameter and the pipe-list are generated from "
          "kEcosystemFamilies",
          "[openapi][software][ecosystem]") {
    const std::string raw = yuzu::server::openapi_spec_json();
    json spec = json::parse(raw, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());

    json table = json::array();
    std::string pipes;
    for (const auto& e : yuzu::server::software_catalog::kEcosystemFamilies) {
        table.push_back(std::string(e.ecosystem));
        if (!pipes.empty())
            pipes += '|';
        pipes += e.ecosystem;
    }
    REQUIRE(table.size() > 0);
    json with_empty = json::array({""});
    with_empty.insert(with_empty.end(), table.begin(), table.end());

    for (const char* path : {"/inventory/software", "/inventory/software/catalogue",
                             "/inventory/software/catalogue/versions"}) {
        INFO(path);
        CHECK(param(spec["paths"][path]["get"], "ecosystem")["schema"]["enum"] == table);
    }
    for (const char* path : {"/crypto/libraries", "/crypto/libraries/devices", "/crypto/cbom"}) {
        INFO(path);
        CHECK(param(spec["paths"][path]["get"], "ecosystem")["schema"]["enum"] == with_empty);
    }
    // The six pins above fix WHICH routes serve the with-empty form (those where a present-empty
    // value selects rows with no ecosystem: the /crypto reads); this sweep covers EVERY served
    // `ecosystem` parameter, so a route added later with a stale or divergent enum fails here. A
    // table-equal hand-typed array serves the same values and passes: that provenance is
    // test_software_vocabulary_consistency.py's to catch, in the unexpanded source.
    const auto params = ecosystem_parameter_schemas(spec);
    for (const auto& ep : params) {
        INFO(ep.where);
        REQUIRE(ep.schema.contains("enum"));
        CHECK((ep.schema["enum"] == table || ep.schema["enum"] == with_empty));
    }
    REQUIRE(params.size() >= 6);
    CHECK(spec["paths"]["/inventory/software"]["get"]["description"].get<std::string>().find(
              "ecosystem (" + pipes + ")") != std::string::npos);
    CHECK(raw.find("@@") == std::string::npos);
    // The route handler and discover_routes bind this by reference: it must be one stable object.
    CHECK(&yuzu::server::openapi_spec_json() == &yuzu::server::openapi_spec_json());
    // The expansion reserves the exact final size; a capacity near 2x would mean the ~400 KB
    // string grew through a reallocating replace.
    CHECK(yuzu::server::openapi_spec_json().capacity() - raw.size() < 4096);
}

TEST_CASE("ecosystem_parameter_schemas(): resolves referenced parameters and schemas and "
          "path-level parameters",
          "[openapi][software][ecosystem]") {
    const json spec = json::parse(R"json({
      "components": {
        "parameters": {"Eco": {"name": "ecosystem", "in": "query", "schema": {"enum": ["a"]}}},
        "schemas": {"EcoS": {"enum": ["b"]}}
      },
      "paths": {"/x": {
        "parameters": [{"name": "ecosystem", "schema": {"enum": ["c"]}}],
        "get": {"parameters": [{"$ref": "#/components/parameters/Eco"}]},
        "post": {"parameters": [
          {"name": "other"},
          {"name": "ecosystem", "schema": {"$ref": "#/components/schemas/EcoS"}}]}
      }}
    })json");
    const auto found = ecosystem_parameter_schemas(spec);
    // A name-first filter would skip the referenced parameter and return 2.
    REQUIRE(found.size() == 3);
    std::map<std::string, json> by_where;
    for (const auto& ep : found)
        by_where[ep.where] = ep.schema.at("enum");
    CHECK(by_where["/x"] == json::array({"c"}));
    CHECK(by_where["get /x"] == json::array({"a"}));
    CHECK(by_where["post /x"] == json::array({"b"}));
}
