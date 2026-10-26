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

#include "content_etag.hpp"
#include "crypto_library_model.hpp"
#include "device_token_store.hpp"
#include "license_store.hpp"
#include "openapi_spec_access.hpp"
#include "rest_api_v1.hpp"
#include "software_catalog_rules.hpp" // kEcosystemFamilies: the published ecosystem vocabulary
#include "software_deployment_store.hpp"
#include "pg/pg_pool.hpp" // an unparseable-conninfo pool backs the unopened stand-in stores
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <iterator>
#include <optional>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <thread>
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
    // openapi_spec_json() is the lean copy openapi_strip_guides() builds once and trims with
    // shrink_to_fit(). The standard makes that call a non-binding request, so these two pins
    // are deliberately coarse and detect only a large excess: the check fails only if the
    // capacity is at least 1.5x the size, so it detects a missed trim only when the growth
    // overshot that far, and says nothing about a smaller excess. libstdc++ and libc++ trim
    // to the byte; an STL that rounds
    // up (MSVC's allocation granularity) must still pass, so the bound is half the size, not a
    // byte count. The exact bound lives on the synthetic expand test below.
    CHECK(yuzu::server::openapi_spec_json().capacity() - raw.size() < raw.size() / 2);
    // The guides-included document is the expansion's own string, served as built, so its capacity
    // pins the reserve of the very expand_ecosystem_tokens() that builds the document (the
    // function the test below exercises on a synthetic template, where the exact bound holds).
    const auto& built = yuzu::server::openapi_spec_with_guides_json();
    CHECK(built.capacity() - built.size() < built.size() / 2);
}

TEST_CASE("expand_ecosystem_tokens(): the output is allocated once at its final size",
          "[openapi][software][ecosystem]") {
    // The function rest_api_v1.cpp builds the spec with (it uses this one through a
    // using-declaration, not a copy): reserve(peak) on an empty string, then in-place replaces. A
    // grown table that made the replaces reallocate would show as a capacity well above the size.
    // The template is long enough that reserve() is not satisfied by the small-string buffer.
    const std::string tmpl = std::string(200, 'x') + R"( "@@ECOSYSTEM_ENUM@@" "@@ECOSYSTEM_ENUM_OR_EMPTY@@" )" +
                             "@@ECOSYSTEM_LIST@@ " + std::string(200, 'y');
    const std::string out = yuzu::server::software_catalog::expand_ecosystem_tokens(tmpl);
    CHECK(out.find("@@") == std::string::npos);
    CHECK(out.size() > tmpl.size());
    CHECK(out.capacity() - out.size() < 64);
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

// ── Structural invariants over the whole document ───────────────────────────────────────────────

namespace {

struct SpecOp {
    std::string method; // lower case, as in the document
    std::string path;
    json op;
    std::string where() const { return method + " " + path; }
};

std::vector<SpecOp> all_operations(const json& spec) {
    static const std::set<std::string> kVerbs = {"get", "put", "post", "delete", "options",
                                                 "head", "patch", "trace"};
    std::vector<SpecOp> ops;
    for (const auto& [path, item] : spec.at("paths").items()) {
        for (const auto& [key, op] : item.items()) {
            if (kVerbs.contains(key))
                ops.push_back({key, path, op});
        }
    }
    return ops;
}

std::string upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::string first_tag(const json& op) {
    if (op.contains("tags") && op["tags"].is_array() && !op["tags"].empty())
        return op["tags"][0].get<std::string>();
    return {};
}

RestApiV1::AuthFn admin_auth_fn() {
    return [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "tester";
        s.role = auth::Role::admin;
        return s;
    };
}

RestApiV1::AuditFn ok_audit_fn() {
    return [](const httplib::Request&, const std::string&, const std::string&,
              const std::string&, const std::string&, const std::string&) { return true; };
}

/// Three stores that never opened: real objects built over a pool whose connection string does
/// not parse, so nothing connects (`PgPool::valid()` is false and every acquire returns an empty
/// lease). `register_routes` only tests these pointers for non-null and captures them for the
/// handlers, so an unopened store stands in for a PG-backed one without any cast.
struct UnopenedStores {
    yuzu::server::pg::PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    SoftwareDeploymentStore sw{pool};
    DeviceTokenStore dt{pool};
    LicenseStore lic{pool};
};

/// The routes `register_routes` registers when every store is null except the three whose routes
/// are documented as unavailable, which are `wired` or null as asked.
std::set<std::pair<std::string, std::string>> registered_routes(bool wire_unavailable_stores) {
    std::optional<UnopenedStores> stores;
    if (wire_unavailable_stores)
        stores.emplace();
    auto* sw = stores ? &stores->sw : nullptr;
    auto* dt = stores ? &stores->dt : nullptr;
    auto* lic = stores ? &stores->lic : nullptr;

    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;
    RestApiV1::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                   const std::string&, const std::string&) { return true; };
    api.register_routes(sink, admin_auth_fn(), perm_fn, ok_audit_fn(),
                        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                        /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                        /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                        /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr, sw, dt, lic);
    std::set<std::pair<std::string, std::string>> out;
    for (const auto& [method, pattern] : sink.registered_routes()) {
        if (pattern.starts_with("/api/v1"))
            out.emplace(method, canonicalize(pattern));
    }
    return out;
}

} // namespace

TEST_CASE("openapi_spec_json(): x-yuzu-unavailable marks exactly the operations that wiring "
          "a store adds",
          "[openapi][structure][unavailable]") {
    const json spec = json::parse(yuzu::server::openapi_spec_json());
    const auto ops = all_operations(spec);

    // The groups whose routes exist only when their store is wired, and which production does not
    // wire. A group joining or leaving this set is a decision to make here, on purpose. That
    // production passes a null for each of these stores is not observable from this file;
    // tests/test_unavailable_store_wiring.py reads the call in server.cpp and ties it to the markers.
    const std::set<std::string> kUnavailableGroups = {"License Management", "Device Tokens",
                                                      "Software Deployment"};

    const auto without = registered_routes(/*wire_unavailable_stores=*/false);
    const auto with = registered_routes(/*wire_unavailable_stores=*/true);
    // Wiring a store only adds routes.
    REQUIRE(std::includes(with.begin(), with.end(), without.begin(), without.end()));
    std::set<std::pair<std::string, std::string>> gained;
    std::set_difference(with.begin(), with.end(), without.begin(), without.end(),
                        std::inserter(gained, gained.end()));
    REQUIRE_FALSE(gained.empty()); // the three stores really do gate routes

    std::set<std::string> marked_groups;
    std::size_t marked = 0;
    for (const auto& o : ops) {
        INFO(o.where());
        const auto key = std::make_pair(upper(o.method), canonicalize("/api/v1" + o.path));
        const bool is_marked = o.op.contains("x-yuzu-unavailable");
        const bool only_with_store = gained.contains(key);
        if (is_marked) {
            ++marked;
            marked_groups.insert(first_tag(o.op));
            CHECK(kUnavailableGroups.contains(first_tag(o.op)));
            CHECK(o.op["x-yuzu-unavailable"].is_string());
            CHECK_FALSE(o.op["x-yuzu-unavailable"].get<std::string>().empty());
            // Documented unavailable: it must not be served when the store is null...
            CHECK_FALSE(without.contains(key));
            // ...and it must exist as a route at all, or the marker documents nothing.
            CHECK(only_with_store);
        } else {
            // An unmarked operation is not one that only a wired store would add.
            CHECK_FALSE(only_with_store);
        }
    }
    CHECK(marked_groups == kUnavailableGroups);

    // Every route a wired store adds is documented, and documented as unavailable.
    for (const auto& g : gained) {
        INFO(g.first << " " << g.second);
        bool found = false;
        for (const auto& o : ops) {
            if (upper(o.method) == g.first && canonicalize("/api/v1" + o.path) == g.second) {
                found = true;
                CHECK(o.op.contains("x-yuzu-unavailable"));
            }
        }
        // allowlisted_missing() routes are the exception: they are deliberately undocumented.
        CHECK((found || allowlisted_missing().contains(g)));
    }
}

TEST_CASE("GET /api/v1/openapi.json: gated on Infrastructure:Read for every form of the document",
          "[openapi][security]") {
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;
    std::vector<std::pair<std::string, std::string>> asked;
    bool admit = false;
    RestApiV1::PermFn perm_fn = [&](const httplib::Request&, httplib::Response& res,
                                    const std::string& securable, const std::string& op) {
        asked.emplace_back(securable, op);
        if (admit)
            return true;
        res.status = 403;
        res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
        return false;
    };
    api.register_routes(sink, admin_auth_fn(), perm_fn, ok_audit_fn(),
                        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                        /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                        /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr);

    for (const char* path :
         {"/api/v1/openapi.json", "/api/v1/openapi.json?guides=true",
          "/api/v1/openapi.json?guides=1", "/api/v1/openapi.json?guides=no"}) {
        INFO(path);
        asked.clear();
        admit = false;
        auto denied = sink.Get(path);
        REQUIRE(denied);
        CHECK(denied->status == 403);
        // The refusal is the gate's, and the document is not in it.
        CHECK(denied->body.find("\"openapi\"") == std::string::npos);
        CHECK(denied->body.find("x-yuzu-guide") == std::string::npos);
        REQUIRE(asked.size() == 1);
        CHECK(asked[0] == std::make_pair(std::string("Infrastructure"), std::string("Read")));

        admit = true;
        auto allowed = sink.Get(path);
        REQUIRE(allowed);
        CHECK(allowed->status == 200);
        CHECK_FALSE(allowed->body.empty());
    }
}

TEST_CASE("GET /api/v1/openapi.json: a strong ETag per form and 304 on a matching If-None-Match",
          "[openapi][etag]") {
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;
    bool admit = true;
    RestApiV1::PermFn perm_fn = [&](const httplib::Request&, httplib::Response& res,
                                    const std::string&, const std::string&) {
        if (admit)
            return true;
        res.status = 403;
        res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
        return false;
    };
    api.register_routes(sink, admin_auth_fn(), perm_fn, ok_audit_fn(),
                        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                        /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                        /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr);

    const std::string lean_path = "/api/v1/openapi.json";
    const std::string full_path = "/api/v1/openapi.json?guides=true";

    auto lean = sink.Get(lean_path);
    auto full = sink.Get(full_path);
    REQUIRE(lean);
    REQUIRE(full);
    REQUIRE(lean->status == 200);
    REQUIRE(full->status == 200);

    // A strong (not W/) quoted validator, derived from the exact bytes served, no-cache so every
    // use revalidates through the gate.
    const std::string lean_etag = lean->get_header_value("ETag");
    const std::string full_etag = full->get_header_value("ETag");
    CHECK(lean_etag.size() > 2);
    CHECK(lean_etag.front() == '"');
    CHECK(lean_etag.back() == '"');
    CHECK(lean_etag == yuzu::server::content_etag(lean->body));
    CHECK(full_etag == yuzu::server::content_etag(full->body));
    CHECK(lean_etag == yuzu::server::openapi_spec_etag());
    CHECK(full_etag == yuzu::server::openapi_spec_with_guides_etag());
    CHECK(lean->get_header_value("Cache-Control") == "no-cache, private");
    CHECK(full->get_header_value("Cache-Control") == "no-cache, private");
    // The two forms are different bytes, so they must not share a validator.
    CHECK(lean_etag != full_etag);

    SECTION("a matching If-None-Match is 304 with no body, for the form it names") {
        auto hit = sink.Get(lean_path, {{"If-None-Match", lean_etag}});
        REQUIRE(hit);
        CHECK(hit->status == 304);
        CHECK(hit->body.empty());
        CHECK(hit->get_header_value("ETag") == lean_etag);
        CHECK(hit->get_header_value("Cache-Control") == "no-cache, private");

        auto full_hit = sink.Get(full_path, {{"If-None-Match", full_etag}});
        REQUIRE(full_hit);
        CHECK(full_hit->status == 304);
        CHECK(full_hit->body.empty());
    }

    SECTION("another form's validator, or a stale one, is a full 200") {
        auto crossed = sink.Get(lean_path, {{"If-None-Match", full_etag}});
        REQUIRE(crossed);
        CHECK(crossed->status == 200);
        CHECK(crossed->body == lean->body);

        auto stale = sink.Get(full_path, {{"If-None-Match", "\"0000000000000000\""}});
        REQUIRE(stale);
        CHECK(stale->status == 200);
        CHECK(stale->body == full->body);
    }

    SECTION("the permission gate runs before the validator is looked at") {
        admit = false;
        auto denied = sink.Get(lean_path, {{"If-None-Match", lean_etag}});
        REQUIRE(denied);
        CHECK(denied->status == 403);
        CHECK(denied->get_header_value("ETag").empty());
        CHECK(denied->body.find("\"openapi\"") == std::string::npos);
    }

    SECTION("the comparison is exact: a weak validator, a list or * is a full 200") {
        // The server compares the header to its one ETag as a string. It does not parse the
        // If-None-Match grammar, so each of these revalidates by refetching. That is documented
        // (rest-api.md, the spec text); a proxy that weakens or merges validators costs the
        // 304 saving, never correctness.
        for (const std::string& inm :
             {"W/" + lean_etag, lean_etag + ", \"0000000000000000\"",
              "\"0000000000000000\", " + lean_etag, std::string("*")}) {
            INFO("If-None-Match: " << inm);
            auto r = sink.Get(lean_path, {{"If-None-Match", inm}});
            REQUIRE(r);
            CHECK(r->status == 200);
            CHECK(r->body == lean->body);
            CHECK(r->get_header_value("ETag") == lean_etag);
        }
    }

    SECTION("an unauthenticated caller is refused before the validator, even with the right one") {
        // Production's perm_fn answers 401 for a request with no session; the gate must run
        // first, so the right ETag never becomes a 304 that confirms what the document is.
        RestApiV1 api2;
        yuzu::server::test::TestRouteSink sink2;
        RestApiV1::PermFn no_session = [](const httplib::Request&, httplib::Response& res,
                                          const std::string&, const std::string&) {
            res.status = 401;
            res.set_content(R"({"error":{"code":401,"message":"unauthorized"}})", "application/json");
            return false;
        };
        api2.register_routes(sink2, admin_auth_fn(), no_session, ok_audit_fn(),
                             /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                             /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                             /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                             /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                             /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                             /*audit_store=*/nullptr);
        auto r = sink2.Get(lean_path, {{"If-None-Match", lean_etag}});
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(r->get_header_value("ETag").empty());
        CHECK(r->body.find("\"openapi\"") == std::string::npos);
    }

    SECTION("guides is read as exactly true or 1, and the first value wins") {
        // Anything else, in any case or spelling, is the default (lean) form with a 200: the
        // server does not say which form it chose beyond the ETag and the body.
        for (const char* q : {"true", "1"}) {
            INFO("guides=" << q);
            auto r = sink.Get(std::string(lean_path) + "?guides=" + q);
            REQUIRE(r);
            CHECK(r->body == full->body);
            CHECK(r->get_header_value("ETag") == full_etag);
        }
        for (const char* q : {"TRUE", "True", "yes", "on", "false", "0", ""}) {
            INFO("guides=" << q);
            auto r = sink.Get(std::string(lean_path) + "?guides=" + q);
            REQUIRE(r);
            CHECK(r->status == 200);
            CHECK(r->body == lean->body);
            CHECK(r->get_header_value("ETag") == lean_etag);
        }
        auto first_true = sink.Get(lean_path + "?guides=true&guides=no");
        REQUIRE(first_true);
        CHECK(first_true->body == full->body);
        auto first_no = sink.Get(lean_path + "?guides=no&guides=true");
        REQUIRE(first_no);
        CHECK(first_no->body == lean->body);
    }
}

TEST_CASE("content_etag(): known vectors", "[openapi][etag]") {
    // FNV-1a 64 over the bytes, with the offset constant 1469598103934665603. That constant is
    // the standard offset basis (14695981039346656037) with its last digit dropped, a
    // transcription slip carried by every copy of this function. It is kept on purpose:
    // correcting it would change every ETag the server has handed out, once. These vectors pin
    // the value so the slip is neither "fixed" nor changed by accident, and so the shared
    // implementation and the production handlers cannot drift together unnoticed.
    CHECK(yuzu::server::content_etag("") == "\"14650fb0739d0383\"");
    CHECK(yuzu::server::content_etag("a") == "\"44bd8ad473cd9906\"");
    CHECK(yuzu::server::content_etag("yuzu") == "\"ea31ac803c5388dc\"");
    // A leading zero is kept: the digest is always sixteen hex digits.
    CHECK(yuzu::server::content_etag(R"({"openapi":"3.0.3"})") == "\"0aecba309589115d\"");
    // All 256 byte values: a byte above 0x7f is folded in unsigned, not sign-extended.
    std::string all_bytes;
    for (int c = 0; c < 256; ++c)
        all_bytes.push_back(static_cast<char>(c));
    CHECK(yuzu::server::content_etag(all_bytes) == "\"16d173bdfcdae583\"");
}

TEST_CASE("openapi_strip_guides(): removes the guides and keeps everything else",
          "[openapi][guides]") {
    const std::string full = yuzu::server::openapi_spec_with_guides_json();
    const auto stripped = yuzu::server::openapi_strip_guides(full);
    CHECK_FALSE(stripped.fell_back);
    const std::string& lean = stripped.json;

    json full_doc = json::parse(full);
    const json lean_doc = json::parse(lean);
    REQUIRE(full_doc["tags"].is_array());
    std::size_t with_guide = 0;
    for (auto& tag : full_doc["tags"]) {
        if (tag.contains("x-yuzu-guide"))
            ++with_guide;
        tag.erase("x-yuzu-guide");
    }
    CHECK(with_guide > 0); // the literal does carry guides, or this test proves nothing
    CHECK(lean_doc == full_doc);
    for (const auto& tag : lean_doc["tags"])
        CHECK_FALSE(tag.contains("x-yuzu-guide"));
    CHECK(lean.size() < full.size());
    // The accessor serves exactly this derivation.
    CHECK(lean == yuzu::server::openapi_spec_json());
}

TEST_CASE("openapi_strip_guides(): input it cannot use is returned unchanged and reported",
          "[openapi][guides]") {
    for (const std::string input : {std::string("{not json"), std::string(),
                                    std::string(R"({"openapi":"3.0.3","paths":{}})"),
                                    std::string(R"({"tags":"not-an-array"})")}) {
        INFO("input: " << input);
        const auto stripped = yuzu::server::openapi_strip_guides(input);
        CHECK(stripped.json == input);
        CHECK(stripped.fell_back);
    }
}

namespace {

/// Starts spinning threads behind one flag. The destructor opens the flag and joins every thread,
/// so an exception while the threads are being created cannot leave the earlier ones spinning or
/// reach std::terminate on a joinable thread. std::jthread would do the same, but Apple Clang's
/// libc++ does not provide it.
struct SpinGate {
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    SpinGate() = default;
    SpinGate(const SpinGate&) = delete;
    SpinGate& operator=(const SpinGate&) = delete;
    ~SpinGate() {
        go.store(true, std::memory_order_release);
        for (auto& t : threads) {
            if (t.joinable())
                t.join();
        }
    }
    void wait_for_go() const {
        while (!go.load(std::memory_order_acquire))
            std::this_thread::yield();
    }
};

} // namespace

TEST_CASE("openapi_spec_json(): callers on many threads all get the same object",
          "[openapi][guides][concurrency]") {
    // What this asserts: every thread is handed the one stable string, never a per-call copy.
    // What it does NOT assert: the first-call initialisation race. Earlier cases in this binary
    // have already initialised the function-local static, so no thread here runs the initialiser;
    // that race is covered by the language guarantee for a function-local static (initialised
    // exactly once, concurrent first callers block until it finishes), not by this test.
    constexpr int kThreads = 8;
    std::vector<const std::string*> seen(kThreads, nullptr);
    {
        SpinGate gate;
        gate.threads.reserve(kThreads);
        for (int i = 0; i < kThreads; ++i) {
            gate.threads.emplace_back([&gate, &seen, i] {
                gate.wait_for_go();
                seen[static_cast<std::size_t>(i)] = &yuzu::server::openapi_spec_json();
            });
        }
        // Every thread exists; open the flag, then the gate's destructor joins them.
        gate.go.store(true, std::memory_order_release);
    }
    for (const auto* p : seen) {
        REQUIRE(p != nullptr);
        CHECK(p == &yuzu::server::openapi_spec_json());
    }
}

// ── Both forms of the document, table-driven ────────────────────────────────────────────────────

namespace {

const std::string& document_text(bool with_guides) {
    return with_guides ? yuzu::server::openapi_spec_with_guides_json()
                       : yuzu::server::openapi_spec_json();
}

const char* form_name(bool with_guides) { return with_guides ? "with guides" : "default"; }

/// The node a `$ref` names, or the node itself when it is not a reference.
json resolve_ref(const json& spec, const json& node) {
    if (!node.is_object() || !node.contains("$ref"))
        return node;
    static const std::string kPrefix = "#/components/schemas/";
    const auto ref = node["$ref"].get<std::string>();
    REQUIRE(ref.starts_with(kPrefix));
    return spec.at("components").at("schemas").at(ref.substr(kPrefix.size()));
}

/// True when a 2xx response declares a schema under any media type: the test the /swagger page's
/// "Typed response" filter applies.
bool has_typed_success(const json& op) {
    if (!op.contains("responses"))
        return false;
    for (const auto& [code, resp] : op["responses"].items()) {
        if (code.empty() || code[0] != '2' || !resp.contains("content"))
            continue;
        for (const auto& [media, body] : resp["content"].items()) {
            if (body.contains("schema"))
                return true;
        }
    }
    return false;
}

std::set<std::string> key_set(const json& obj) {
    std::set<std::string> out;
    for (const auto& [k, v] : obj.items())
        out.insert(k);
    return out;
}

} // namespace

TEST_CASE("openapi documents: every operation has a unique, well-formed and pinned operationId in "
          "both forms",
          "[openapi][structure]") {
    // The operationId is the method name an OpenAPI client generator derives (upgrading.md says
    // so), so renaming one is a breaking change for every generated client. The checksum below
    // fails on ANY change to the set of ids: a rename, an addition or a removal.
    //
    // To update it after an intended change: run this test, copy the checksum the failure
    // prints into kOperationIdChecksum, and state the rename in the operationId note of
    // docs/user-manual/upgrading.md and in the change's changelog fragment. The count is
    // derived from the document (it is the number of operations); the one hand-kept number
    // for it lives in the typed-response test's exclusion list, not here.
    static const std::string kOperationIdChecksum = "\"6c0502f0540bc8a1\"";
    static const std::regex kShape("^[a-z][A-Za-z0-9]*$");
    for (const bool with_guides : {false, true}) {
        INFO("form: " << form_name(with_guides));
        const json spec = json::parse(document_text(with_guides));
        const auto ops = all_operations(spec);
        REQUIRE(ops.size() > 100);
        std::map<std::string, std::string> seen; // operationId -> first operation using it
        for (const auto& o : ops) {
            INFO(o.where());
            REQUIRE(o.op.contains("operationId"));
            REQUIRE(o.op["operationId"].is_string());
            const auto id = o.op["operationId"].get<std::string>();
            INFO("operationId " << id);
            CHECK(std::regex_match(id, kShape));
            const auto [it, fresh] = seen.emplace(id, o.where());
            if (!fresh)
                FAIL_CHECK("operationId " << id << " is also used by " << it->second);
        }
        CHECK(seen.size() == ops.size());
        // std::map iterates in key order, so the joined text is the sorted list of ids.
        std::string joined;
        for (const auto& [id, where] : seen) {
            joined += id;
            joined += '\n';
        }
        INFO("sorted operationIds hash to " << yuzu::server::content_etag(joined)
             << " (update kOperationIdChecksum, and see the comment above it)");
        CHECK(yuzu::server::content_etag(joined) == kOperationIdChecksum);
    }
}

TEST_CASE("openapi documents: x-yuzu-unavailable marks exactly the pinned operations",
          "[openapi][structure][unavailable]") {
    // method and path as they appear in the document, without the /api/v1 base.
    const std::set<std::string> kExpected = {
        "get /license",
        "post /license",
        "delete /license/{id}",
        "get /license/alerts",
        "get /device-tokens",
        "post /device-tokens",
        "delete /device-tokens/{token_id}",
        "get /software-packages",
        "post /software-packages",
        "get /software-deployments",
        "post /software-deployments",
        "post /software-deployments/{id}/start",
        "post /software-deployments/{id}/rollback",
        "post /software-deployments/{id}/cancel",
    };
    for (const bool with_guides : {false, true}) {
        INFO("form: " << form_name(with_guides));
        const json spec = json::parse(document_text(with_guides));
        std::set<std::string> marked;
        for (const auto& o : all_operations(spec)) {
            if (o.op.contains("x-yuzu-unavailable"))
                marked.insert(o.where());
        }
        CHECK(marked == kExpected);
    }
}

TEST_CASE("openapi documents: x-yuzu-guide is on every tag in the guides form only",
          "[openapi][structure][guides]") {
    const json lean = json::parse(document_text(false));
    const json full = json::parse(document_text(true));
    REQUIRE(lean["tags"].is_array());
    REQUIRE(full["tags"].is_array());
    CHECK(lean["tags"].size() == full["tags"].size());
    CHECK(full["tags"].size() > 0);
    for (const auto& tag : lean["tags"]) {
        INFO("default form tag: " << tag.value("name", ""));
        CHECK_FALSE(tag.contains("x-yuzu-guide"));
    }
    for (const auto& tag : full["tags"]) {
        INFO("guides form tag: " << tag.value("name", ""));
        REQUIRE(tag.contains("x-yuzu-guide"));
        CHECK(tag["x-yuzu-guide"].is_object());
        CHECK_FALSE(tag["x-yuzu-guide"].empty());
    }
}

TEST_CASE("openapi documents: all but two operations declare a typed success response",
          "[openapi][structure][typed]") {
    // These two answer 204 with no body, so there is nothing to type. A third name here is a
    // regression to a prose-only response, not a quiet addition.
    const std::set<std::string> kUntyped = {"delete /upload-grants/{grant_id}",
                                            "delete /uploads/{upload_id}"};
    for (const bool with_guides : {false, true}) {
        INFO("form: " << form_name(with_guides));
        const json spec = json::parse(document_text(with_guides));
        std::set<std::string> untyped;
        for (const auto& o : all_operations(spec)) {
            if (!has_typed_success(o.op))
                untyped.insert(o.where());
        }
        // Every operation outside the exclusion list is typed: an equal set says exactly that.
        CHECK(untyped == kUntyped);
    }
}

namespace {

/// What one handler emits, read from the handler in rest_api_v1.cpp, for a route whose response
/// schema was corrected to the handler's real envelope.
struct ResponsePin {
    const char* path;
    /// Top-level keys of the response body: ok_json gives data and meta, list_json adds pagination.
    std::set<std::string> envelope;
    bool data_is_array;
    /// Keys the handler writes for each element (an array route) or for data (an object route).
    std::set<std::string> data_keys;
    /// true: the schema's readable properties are exactly data_keys. false: the schema may carry
    /// more (a field only some callers get), but must carry all of data_keys.
    bool exact;
    /// Set when data holds a nested array of objects that the handler writes with these keys.
    const char* nested_array;
    std::set<std::string> nested_keys;
};

} // namespace

TEST_CASE("openapi documents: the corrected success schemas match their handlers",
          "[openapi][structure][envelope]") {
    const std::set<std::string> kList = {"data", "pagination", "meta"};
    const std::set<std::string> kOne = {"data", "meta"};
    // Each key list was read from the named handler, not from the schema:
    //  inventory/tables: JObj of plugin, agent_count, last_collected, through list_json.
    //  rules list: rule_to_jobj (14 fields) through list_json.
    //  rule get: rule_to_jobj through ok_json.
    //  rule status: agent_id, state, updated_at per row, through list_json.
    //  events: 15 fields per row, through list_json.
    //  agents/{id}/rules: agent_id, guards[rule_id, name, state, updated_at], total_guards, ok_json.
    //  status: total_rules, compliant_rules, drifted_rules, errored_rules, note, through ok_json;
    //          the per-agent route adds agent_id.
    //  device-compliance: baseline, deployed, assessable, agent_id, total_guards, snapshot_total,
    //          compliant, drifted, errored, pending, last_updated, guards[], through ok_json.
    const std::vector<ResponsePin> pins = {
        {"/inventory/tables", kList, true, {"plugin", "agent_count", "last_collected"}, true, "", {}},
        {"/guaranteed-state/rules",
         kList,
         true,
         {"rule_id", "name", "yaml_source", "spec_json", "version", "enabled", "enforcement_mode",
          "severity", "os_target", "scope_expr", "created_at", "updated_at", "created_by",
          "updated_by"},
         true,
         "",
         {}},
        {"/guaranteed-state/rules/{rule_id}",
         kOne,
         false,
         {"rule_id", "name", "yaml_source", "spec_json", "version", "enabled", "enforcement_mode",
          "severity", "os_target", "scope_expr", "created_at", "updated_at", "created_by",
          "updated_by"},
         true,
         "",
         {}},
        {"/guaranteed-state/rules/{rule_id}/status",
         kList,
         true,
         {"agent_id", "state", "updated_at"},
         true,
         "",
         {}},
        {"/guaranteed-state/events",
         kList,
         true,
         {"event_id", "rule_id", "agent_id", "event_type", "severity", "guard_type",
          "guard_category", "detected_value", "expected_value", "detail_json",
          "remediation_action", "remediation_success", "detection_latency_us",
          "remediation_latency_us", "timestamp"},
         true,
         "",
         {}},
        {"/guaranteed-state/agents/{agent_id}/rules",
         kOne,
         false,
         {"agent_id", "guards", "total_guards"},
         true,
         "guards",
         {"rule_id", "name", "state", "updated_at"}},
        {"/guaranteed-state/status",
         kOne,
         false,
         {"total_rules", "compliant_rules", "drifted_rules", "errored_rules", "note"},
         false,
         "",
         {}},
        {"/guaranteed-state/status/{agent_id}",
         kOne,
         false,
         {"agent_id", "total_rules", "compliant_rules", "drifted_rules", "errored_rules", "note"},
         false,
         "",
         {}},
        {"/guaranteed-state/device-compliance",
         kOne,
         false,
         {"baseline", "deployed", "assessable", "agent_id", "total_guards", "snapshot_total",
          "compliant", "drifted", "errored", "pending", "last_updated", "guards"},
         true,
         "guards",
         {"rule_id", "name", "status", "updated_at"}},
    };

    // The properties a response can carry: writeOnly ones are input-only and never in a response.
    const auto readable = [](const json& schema) {
        std::set<std::string> out;
        if (!schema.contains("properties"))
            return out;
        for (const auto& [k, v] : schema["properties"].items()) {
            if (!v.value("writeOnly", false))
                out.insert(k);
        }
        return out;
    };

    for (const bool with_guides : {false, true}) {
        const json spec = json::parse(document_text(with_guides));
        for (const auto& pin : pins) {
            INFO("form: " << form_name(with_guides) << ", route: GET " << pin.path);
            REQUIRE(spec["paths"].contains(pin.path));
            const json& get = spec["paths"][pin.path].at("get");
            const json& schema = get.at("responses")
                                     .at("200")
                                     .at("content")
                                     .at("application/json")
                                     .at("schema");

            // The envelope is the response body itself, with exactly these keys, all required.
            REQUIRE(schema.contains("properties"));
            CHECK(key_set(schema["properties"]) == pin.envelope);
            REQUIRE(schema.contains("required"));
            CHECK(std::set<std::string>(schema["required"].begin(), schema["required"].end()) ==
                  pin.envelope);

            const json data = resolve_ref(spec, schema["properties"].at("data"));
            std::set<std::string> have;
            json element = data;
            if (pin.data_is_array) {
                CHECK(data.value("type", "") == "array");
                REQUIRE(data.contains("items"));
                element = resolve_ref(spec, data["items"]);
            } else {
                CHECK(data.value("type", "") == "object");
            }
            have = readable(element);
            if (pin.exact) {
                CHECK(have == pin.data_keys);
            } else {
                for (const auto& k : pin.data_keys) {
                    INFO("data key: " << k);
                    CHECK(have.contains(k));
                }
            }

            if (std::string(pin.nested_array) != "") {
                REQUIRE(element["properties"].contains(pin.nested_array));
                const json nested = resolve_ref(spec, element["properties"][pin.nested_array]);
                CHECK(nested.value("type", "") == "array");
                REQUIRE(nested.contains("items"));
                CHECK(readable(resolve_ref(spec, nested["items"])) == pin.nested_keys);
            }
        }
    }
}
