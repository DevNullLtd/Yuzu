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
#include "dex_read_model.hpp" // the scope tokens and the basis/coverage the builder can emit
#include "dex_score_policy_json.hpp" // the serializer the DexScorePolicyDocument schema mirrors
#include "dex_score_policy_writer.hpp" // dex_score_policy_in_force_json: the data envelope's keys
#include "guaranteed_state_store.hpp" // kUnrepresentedPendingIdCap: the cap the maxItems literals mirror
#include "guardian_backend_fleet_tags.hpp" // #2240: the closed backend token table the device enum mirrors
#include "license_store.hpp"
#include "openapi_spec_access.hpp"
#include "rest_api_v1.hpp"
#include "result_set_model.hpp"
#include "settings_model.hpp"
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
#include <functional>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
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
/// elevation-eligibility, execution-statistics, sessions, echo purge) were
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

TEST_CASE("openapi_spec_json(): the strict instruction create requests are closed schemas",
          "[openapi]") {
    // The routes refuse an unknown key (build_*_from_*_body), so a schema that omits
    // additionalProperties:false would tell a generated client the opposite.
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const auto& schemas = spec["components"]["schemas"];
    for (const char* name : {"InstructionsDefinitionCreateRequest", "InstructionSetCreateRequest"}) {
        INFO(name);
        REQUIRE(schemas.contains(name));
        REQUIRE(schemas[name].contains("additionalProperties"));
        CHECK(schemas[name]["additionalProperties"] == false);
    }
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

TEST_CASE("openapi_spec_json(): POST /instructions/{id}/execute documents the audit header, the "
          "unreadable pending count, the misconfigured arm and the dispatch_exception fields",
          "[openapi][instruction_execute]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec["paths"].contains("/instructions/{id}/execute"));
    const auto& op = spec["paths"]["/instructions/{id}/execute"]["post"];
    const auto& rsp = op["responses"];
    // Sec-Audit-Failed is a typed response header on every status that can carry a lost
    // best-effort row, not prose alone.
    for (const char* code : {"200", "202", "400"}) {
        INFO(code);
        REQUIRE(rsp.contains(code));
        REQUIRE(rsp[code].contains("headers"));
        REQUIRE(rsp[code]["headers"].contains("Sec-Audit-Failed"));
        CHECK(rsp[code]["headers"]["Sec-Audit-Failed"]["schema"]["enum"] == json::array({"true"}));
    }
    REQUIRE(rsp.contains("503"));
    REQUIRE(rsp.contains("500"));
    REQUIRE(rsp.contains("429"));
    const std::string d503 = rsp["503"].value("description", "");
    CHECK(d503.find("pending-approval count unreadable") != std::string::npos);
    CHECK(d503.find("retry_after_ms 5000") != std::string::npos);
    const std::string d500 = rsp["500"].value("description", "");
    CHECK(d500.find("dispatch_unconfigured") != std::string::npos);
    CHECK(d500.find("dispatch_exception") != std::string::npos);
    CHECK(d500.find("error.execution_id") != std::string::npos);
    CHECK(d500.find("error.agents_sent") != std::string::npos);
    // The cap is a soft bound everywhere the manual says so.
    const std::string desc = op.value("description", "");
    CHECK(desc.find("about 25 pending approvals") != std::string::npos);
    CHECK(desc.find("soft bound") != std::string::npos);
    CHECK(rsp["429"].value("description", "").find("about 25 pending approvals") !=
          std::string::npos);
    CHECK(rsp["400"].value("description", "").find("invalid_definition_id") != std::string::npos);
    // The id refusal names invalid UTF-8 beside the control character, in the 400 text and in the
    // "Order:" prose (both were once control-character-only).
    CHECK(rsp["400"].value("description", "").find("invalid UTF-8") != std::string::npos);
    const auto order_at = desc.find("Order: body depth and JSON parse, the definition id");
    REQUIRE(order_at != std::string::npos);
    CHECK(desc.find("invalid_definition_id for a control byte (below 0x20 or 0x7F) or invalid UTF-8", order_at) !=
          std::string::npos);
    // The gateway caveat on the lower-bound count.
    CHECK(desc.find("counts once queued for forwarding, which can still fail") != std::string::npos);
}

// The command twin's 500 carries the same typed fields as the instruction twin's (docs-writer p4-1):
// the sent count is a lower bound recorded as the targeted count only when the write succeeds.
TEST_CASE("openapi_spec_json(): POST /commands documents the dispatch_exception fields and the "
          "lower-bound, write-dependent targeted count",
          "[openapi][command_v1]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec["paths"].contains("/commands"));
    const auto& rsp = spec["paths"]["/commands"]["post"]["responses"];
    REQUIRE(rsp.contains("500"));
    const std::string d500 = rsp["500"].value("description", "");
    CHECK(d500.find("dispatch_exception") != std::string::npos);
    CHECK(d500.find("error.execution_id") != std::string::npos);
    CHECK(d500.find("error.agents_sent") != std::string::npos);
    CHECK(d500.find("lower bound") != std::string::npos);
    CHECK(d500.find("only when the write succeeds") != std::string::npos);
    CHECK(d500.find("cancel_execution") != std::string::npos);
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

TEST_CASE("openapi_spec_json(): /dex/apps documents the platform scope parameter and coverage",
          "[openapi][dex]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec["paths"].contains("/dex/apps"));
    const auto& op = spec["paths"]["/dex/apps"]["get"];

    REQUIRE(op.contains("parameters")); // const operator[] on a missing key asserts
    const json* platform = nullptr;
    for (const auto& p : op["parameters"])
        if (p.value("name", "") == "platform")
            platform = &p;
    REQUIRE(platform != nullptr);
    CHECK((*platform)["in"] == "query");
    CHECK((*platform)["required"] == false);
    CHECK((*platform)["schema"]["enum"] == json::array({"all", "windows", "macos", "linux"}));
    CHECK((*platform)["schema"]["default"] == "all");

    CHECK(op["responses"]["200"].value("description", "").find("crash_source_coverage") !=
          std::string::npos);
    CHECK(op["responses"]["400"].value("description", "").find("invalid platform") !=
          std::string::npos);
}

// A lookup by JSON pointer that yields null for a missing node: a regression that deletes part
// of a schema fails an assertion instead of aborting the whole test binary.
namespace {
json schema_at(const json& node, const std::string& ptr) {
    return node.value(json::json_pointer(ptr), json());
}

bool array_contains(const json& array, const json& v) {
    return std::find(array.begin(), array.end(), v) != array.end();
}

// Sorted key names of an object (empty for a non-object), so key sets compare regardless of order.
std::set<std::string> object_keys(const json& obj) {
    std::set<std::string> keys;
    if (obj.is_object())
        for (const auto& [k, v] : obj.items())
            keys.insert(k);
    return keys;
}
} // namespace

TEST_CASE("openapi_spec_json(): DexAppsList covers every population basis and the coverage the "
          "/dex/apps builder can emit",
          "[openapi][dex]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec["components"]["schemas"].contains("DexAppsList"));
    const auto& list = spec["components"]["schemas"]["DexAppsList"];
    const auto at = [&list](const std::string& ptr) { return schema_at(list, ptr); };

    // The published population vocabulary is exactly the four values, and every `<scope>_online`
    // the builder can publish is inside it.
    const json basis_enum = at("/properties/population_basis/enum");
    CHECK(basis_enum ==
          json::array({"all_online", "windows_online", "macos_online", "linux_online"}));
    for (const char* scope : {yuzu::server::kDexAppsScopeAll, yuzu::server::kDexAppsScopeWindows,
                              yuzu::server::kDexAppsScopeMacos, yuzu::server::kDexAppsScopeLinux})
        CHECK(array_contains(basis_enum, json(yuzu::server::dex_apps_population_basis(scope))));

    // crash_source_coverage is always emitted, so it is a declared and required property, and its
    // schema is a closed object: the three platform keys, each exactly complete|partial.
    CHECK(array_contains(at("/required"), json("crash_source_coverage")));
    const std::string cov = "/properties/crash_source_coverage";
    const json coverage = at(cov);
    REQUIRE(coverage.is_object());
    CHECK(coverage.value("type", "") == "object");
    CHECK(coverage.value("additionalProperties", true) == false); // absent must fail, not assert
    CHECK(at(cov + "/properties").size() == 3);
    for (const char* os : {"windows", "macos", "linux"})
        CHECK(at(cov + "/properties/" + os + "/enum") == json::array({"complete", "partial"}));
    // ... and it covers what the builder can publish under `all`.
    for (const auto& [os, value] :
         yuzu::server::dex_apps_crash_source_coverage(yuzu::server::kDexAppsScopeAll))
        CHECK(array_contains(at(cov + "/properties/" + os + "/enum"), json(value)));

    // The figures are no longer called Windows-only: each description the scope changed names the
    // platform scope and none says Windows (the default scope is every platform).
    const auto scoped = [&at](const std::string& node) {
        const json d = at(node + "/description");
        if (!d.is_string())
            return false;
        const auto text = d.get<std::string>();
        return text.find("scope") != std::string::npos && text.find("Windows") == std::string::npos;
    };
    CHECK(scoped(""));
    CHECK(scoped("/properties/population"));
    CHECK(scoped("/properties/apps_total"));
    CHECK(scoped("/properties/population_basis"));
    const std::string app = "/properties/apps/items/properties/";
    for (const char* key : {"crashes", "hangs", "distinct_devices"}) {
        CHECK(scoped(app + key));
        CHECK(scoped(app + "versions/items/properties/" + key));
    }
}

TEST_CASE("openapi_spec_json(): DexScorePolicyDocument types the stored shape and its model "
          "bounds against the serializer",
          "[openapi][dex][score_policy]") {
    using namespace yuzu::server;
    json spec = json::parse(openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const json& schemas = spec["components"]["schemas"];
    REQUIRE(schemas.contains("DexScorePolicyDocument"));
    REQUIRE(schemas.contains("DexScorePolicyData"));
    REQUIRE(spec["paths"].contains("/dex/score-policy"));
    const std::string ref = "#/components/schemas/DexScorePolicyDocument";
    const auto doc = [&schemas](const std::string& ptr) {
        return schema_at(schemas["DexScorePolicyDocument"], ptr);
    };

    // Both the answer and the request body point at the one typed component.
    CHECK(schema_at(schemas["DexScorePolicyData"],
                    "/properties/data/properties/document/allOf/0/$ref") == ref);
    CHECK(schema_at(spec, "/paths/~1dex~1score-policy/put/requestBody/content/application~1json/"
                          "schema/allOf/0/$ref") == ref);
    CHECK(doc("/properties/version/type") == "integer");
    CHECK(doc("/properties/version/default") == kDexScorePolicyBaseVersion);
    CHECK(doc("/properties/version/enum") ==
          json::array({kDexScorePolicyBaseVersion, kDexScorePolicyVersion}));

    // The model key sets are exactly what the serializer emits.
    DexScorePolicy p;
    p.model.per_device_event_cap = 6;
    DexScoreOverride o;
    o.image = "a.exe";
    o.per_device_event_cap = 2;
    o.regression_start_ratio = 1.5;
    o.regression_full_ratio = 4.0;
    // Every partial override key set, so the override tiers and weights are compared whole.
    o.excellent = 95.0;
    o.good = 80.0;
    o.fair = 60.0;
    o.names = {"A", "B", "C", "D"};
    o.breadth = 1.0;
    o.crashes = 2.0;
    o.hangs = 3.0;
    o.regression = 4.0;
    p.overrides.push_back(o);
    const json emitted = dex_score_policy_to_json(p);
    REQUIRE(emitted.contains("model"));
    REQUIRE(emitted.contains("tiers"));
    REQUIRE(emitted.contains("weights"));
    REQUIRE(emitted.contains("overrides"));
    REQUIRE(emitted["overrides"].size() == 1);
    const json& eov = emitted["overrides"][0];
    REQUIRE(eov.contains("model"));
    REQUIRE(eov.contains("tiers"));
    REQUIRE(eov.contains("weights"));
    CHECK(object_keys(doc("/properties/model/properties")) == object_keys(emitted["model"]));
    const auto override_keys =
        object_keys(doc("/properties/overrides/items/properties/model/properties"));
    CHECK(override_keys == object_keys(eov["model"]));
    CHECK_FALSE(override_keys.contains("interval_confidence"));
    CHECK(doc("/properties/model/additionalProperties") == false);
    CHECK(doc("/properties/overrides/items/properties/model/additionalProperties") == false);
    CHECK(doc("/properties/overrides/maxItems") == kDexPolicyMaxOverrides);

    // An override is read-required on `image` alone (always emitted); no other object has a
    // required key, and every object the parser closes (`unknown_key`) is closed here too.
    const std::string ov = "/properties/overrides/items";
    CHECK(doc(ov + "/required") == json::array({"image"}));
    const std::vector<std::string> closed = {
        "",
        "/properties/tiers",
        "/properties/tiers/properties/edges",
        "/properties/tiers/properties/names",
        "/properties/weights",
        "/properties/model",
        ov,
        ov + "/properties/tiers",
        ov + "/properties/tiers/properties/edges",
        ov + "/properties/tiers/properties/names",
        ov + "/properties/weights",
        ov + "/properties/model"};
    for (const auto& base : closed) {
        INFO("object: " << base);
        CHECK(doc(base + "/additionalProperties") == false);
        if (base != ov)
            CHECK(doc(base + "/required").is_null());
    }

    // The key sets are the serializer's, for the global document and for a fully-set override.
    CHECK(object_keys(doc("/properties")) == object_keys(emitted));
    CHECK(object_keys(doc(ov + "/properties")) == object_keys(eov));
    for (const std::string& base : {std::string(""), ov}) {
        const json& src = base.empty() ? emitted : eov;
        INFO("object: " << base);
        CHECK(object_keys(doc(base + "/properties/tiers/properties")) ==
              object_keys(src["tiers"]));
        CHECK(object_keys(doc(base + "/properties/tiers/properties/edges/properties")) ==
              object_keys(src["tiers"]["edges"]));
        CHECK(object_keys(doc(base + "/properties/tiers/properties/names/properties")) ==
              object_keys(src["tiers"]["names"]));
        CHECK(object_keys(doc(base + "/properties/weights/properties")) ==
              object_keys(src["weights"]));
        // The name length and the non-negative weight bound are the validator's.
        for (const auto& [k, v] : src["tiers"]["names"].items())
            CHECK(doc(base + "/properties/tiers/properties/names/properties/" + k +
                      "/maxLength") == kDexPolicyMaxNameBytes);
        for (const auto& [k, v] : src["weights"].items())
            CHECK(doc(base + "/properties/weights/properties/" + k + "/minimum") == 0);
    }
    CHECK(doc(ov + "/properties/image/maxLength") == kDexPolicyMaxKeyBytes);

    // Type, bounds and defaults are the serializer's and the core constants'. The type comes from
    // what the serializer emits (a whole-number parameter is an integer, a ratio a number).
    const auto bound = [&doc](const std::string& base, const std::string& key, const json& sample,
                              const json& lo, const json& hi, const json* def) {
        INFO("parameter: " << base << key);
        const std::string at = base + key;
        CHECK(doc(at + "/type") == (sample.is_number_integer() ? "integer" : "number"));
        CHECK(doc(at + "/minimum") == lo);
        CHECK(doc(at + "/maximum") == hi);
        CHECK(doc(at + "/default") == (def ? *def : json()));
        // nlohmann compares 5 equal to 5.0, so pin the kind of the default separately.
        if (def) {
            CHECK(doc(at + "/default").is_number_integer() == sample.is_number_integer());
            CHECK(doc(at + "/default").is_number_float() == sample.is_number_float());
        }
    };
    const std::string gm = "/properties/model/properties/";
    const std::string om = "/properties/overrides/items/properties/model/properties/";
    const json& em = emitted["model"];
    const json& eo = eov["model"];
    const json cap_def = kStabilityModel.per_device_event_cap;
    const json start_def = kStabilityModel.regression_start_ratio;
    const json full_def = kStabilityModel.regression_full_ratio;
    const json conf_def = kDexStatsConfidence;
    bound(gm, "per_device_event_cap", em["per_device_event_cap"], 1,
          kStabilityMaxPerDeviceEventCap, &cap_def);
    bound(gm, "regression_start_ratio", em["regression_start_ratio"], 1.0,
          kStabilityMaxRegressionRatio, &start_def);
    bound(gm, "regression_full_ratio", em["regression_full_ratio"], 1.0,
          kStabilityMaxRegressionRatio, &full_def);
    bound(gm, "interval_confidence", em["interval_confidence"], kDexStatsConfidenceMin,
          kDexStatsConfidenceMax, &conf_def);
    bound(om, "per_device_event_cap", eo["per_device_event_cap"], 1,
          kStabilityMaxPerDeviceEventCap, nullptr);
    bound(om, "regression_start_ratio", eo["regression_start_ratio"], 1.0,
          kStabilityMaxRegressionRatio, nullptr);
    bound(om, "regression_full_ratio", eo["regression_full_ratio"], 1.0,
          kStabilityMaxRegressionRatio, nullptr);

    // The data envelope: its required keys are the ones the serializer always emits, and
    // `source` is exactly the two values the store can report.
    const json& data = schemas["DexScorePolicyData"];
    const json required = schema_at(data, "/properties/data/required");
    std::set<std::string> required_keys;
    for (const auto& k : required)
        required_keys.insert(k.get<std::string>());
    CHECK(required_keys == object_keys(dex_score_policy_in_force_json(DexPolicyInForce{})));
    CHECK(schema_at(data, "/properties/data/properties/source/enum") ==
          json::array({"custom", "default"}));

    const std::string put_desc =
        spec["paths"]["/dex/score-policy"]["put"].value("description", "");
    CHECK(put_desc.find("rolling upgrade") != std::string::npos);

    // The GET text and the component agree on when `model` is present.
    const std::string get_desc =
        spec["paths"]["/dex/score-policy"]["get"].value("description", "");
    CHECK(get_desc.find("model only when a parameter is in use") != std::string::npos);
    const json model_desc = doc("/properties/model/description");
    REQUIRE(model_desc.is_string());
    CHECK(model_desc.get<std::string>().find("A parameter is in use when") != std::string::npos);
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

TEST_CASE("openapi_spec_json(): the operations that override the top-level security are exactly "
          "the ones that do not take an operator token (#6508)",
          "[openapi][structure][security]") {
    const json spec = json::parse(yuzu::server::openapi_spec_json());

    // The default: any one of the three operator credentials.
    REQUIRE(spec.contains("security"));
    CHECK(spec["security"] ==
          json::parse(R"([{"bearerAuth":[]},{"apiKeyHeader":[]},{"cookieAuth":[]}])"));

    // Every scheme a requirement names is defined, and each scheme has the transport the handler
    // reads: the upload credentials are headers, the session is a cookie.
    const auto& schemes = spec.at("components").at("securitySchemes");
    CHECK(schemes.size() == 5);
    CHECK(schemes.at("bearerAuth").at("type") == "http");
    CHECK(schemes.at("bearerAuth").at("scheme") == "bearer");
    CHECK(schemes.at("apiKeyHeader").at("type") == "apiKey");
    CHECK(schemes.at("apiKeyHeader").at("in") == "header");
    CHECK(schemes.at("apiKeyHeader").at("name") == "X-Yuzu-Token");
    CHECK(schemes.at("cookieAuth").at("type") == "apiKey");
    CHECK(schemes.at("cookieAuth").at("in") == "cookie");
    CHECK(schemes.at("cookieAuth").at("name") == "yuzu_session");
    CHECK(schemes.at("uploadGrantAuth").at("type") == "apiKey");
    CHECK(schemes.at("uploadGrantAuth").at("in") == "header");
    CHECK(schemes.at("uploadGrantAuth").at("name") == "X-Yuzu-Upload-Grant");
    CHECK(schemes.at("uploadSessionAuth").at("type") == "apiKey");
    CHECK(schemes.at("uploadSessionAuth").at("in") == "header");
    CHECK(schemes.at("uploadSessionAuth").at("name") == "X-Yuzu-Upload-Session");

    // The override set. An operation joining or leaving it is a decision to make here, on purpose:
    // each of these refuses or ignores the credential the default tells a client to send.
    //  - the CA root and CRL are public;
    //  - the elevation and password routes act on the caller's own browser session, so a token is
    //    refused (auth_routes.cpp elevate and revoke read the cookie directly);
    //  - the five upload routes authenticate by a grant or session credential in a header and never
    //    consult an operator credential (file_retrieval_routes.cpp).
    const std::map<std::string, json> kOverrides = {
        {"get /ca/root", json::array()},
        {"get /ca/crl", json::array()},
        {"post /elevate", json::parse(R"([{"cookieAuth":[]}])")},
        {"post /elevate/revoke", json::parse(R"([{"cookieAuth":[]}])")},
        {"post /users/me/password", json::parse(R"([{"cookieAuth":[]}])")},
        {"post /users/{username}/password", json::parse(R"([{"cookieAuth":[]}])")},
        {"post /uploads", json::parse(R"([{"uploadGrantAuth":[]}])")},
        {"put /uploads/{upload_id}/chunk", json::parse(R"([{"uploadSessionAuth":[]}])")},
        {"get /uploads/{upload_id}", json::parse(R"([{"uploadSessionAuth":[]}])")},
        {"delete /uploads/{upload_id}", json::parse(R"([{"uploadSessionAuth":[]}])")},
        {"post /uploads/{upload_id}/commit", json::parse(R"([{"uploadSessionAuth":[]}])")},
    };

    std::map<std::string, json> found;
    for (const auto& o : all_operations(spec)) {
        if (!o.op.contains("security"))
            continue;
        found[o.where()] = o.op["security"];
        // A requirement may name only a defined scheme.
        for (const auto& alt : o.op["security"]) {
            for (const auto& [name, scopes] : alt.items()) {
                INFO(o.where() << " names " << name);
                CHECK(schemes.contains(name));
            }
        }
    }
    CHECK(found == kOverrides);

    // The info text names every exemption, so a reader of it is not told to send a token to a route
    // that refuses one.
    const std::string info = spec.at("info").at("description").get<std::string>();
    for (const char* needle :
         {"GET /ca/root", "GET /ca/crl", "POST /elevate,", "POST /elevate/revoke",
          "POST /users/me/password", "POST /users/{username}/password", "X-Yuzu-Upload-Grant",
          "X-Yuzu-Upload-Session", "with three exceptions"}) {
        INFO(needle);
        CHECK(info.find(needle) != std::string::npos);
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

TEST_CASE("if_none_match_matches: RFC 9110 lists and weak comparison and * alone and any malformed "
          "header matches nothing",
          "[openapi][etag]") {
    // Called directly so whitespace at the ends of the value, which the route test cannot send
    // (httplib drops a field value that starts or ends with a space), is covered.
    using yuzu::server::if_none_match_matches;
    const std::string e = "\"abc\"";
    struct Case {
        const char* header;
        bool matches;
    };
    const Case cases[] = {
        {"\"abc\"", true},          {"W/\"abc\"", true},        {"\"x\", \"abc\"", true},
        {"\"abc\" ,\t\"x\"", true}, {"\"a,b\", \"abc\"", true}, {",,\"abc\",,", true},
        {"\"abc\" ,", true},        {" \"abc\" ", true},        {"*", true},
        {" * ", true},              {"\t*\t", true},            {"", false},
        {" ", false},               {",", false},               {"\"abd\"", false},
        {"W/", false},              {"W/\"", false},             {"\"abc", false},
        {"abc\"", false},            {"garbage", false},         {"*x", false},
        {"* ,\"x\"", false},         {"\"x\", *", false},        {"*, \"abc\"", false},
        {"\"x\" \"abc\"", false},   {"\"abc\"x", false},        {"\"abc\"\"x\"", false},
        {"w/\"abc\"", false},       {"W/ \"abc\"", false},      {"W/W/\"abc\"", false},
        {"\"x\"W/\"abc\"", false},  {"\"x\" , ", false},
        {"\"a,\"abc\"", false},      {"x\"abc\"", false},        {"*,", false},
        {"*,\"abc\"", false},
        // Inside a tag only etagc bytes are legal (RFC 9110 section 8.8.3): no space, control byte
        // or DEL, so one such tag makes the whole header invalid even beside the right tag. Bytes
        // from 0x80 up (obs-text) and punctuation are fine.
        {"\"bad space\", \"abc\"", false},  {"\"abc\", \"bad space\"", false},
        {"\"a\tb\", \"abc\"", false},      {"\"a\x7f\", \"abc\"", false},
        {"\"a\x01\", \"abc\"", false},     {"\"\xc3\xa9\", \"abc\"", true},
        {"\"a!#~\", \"abc\"", true},        {"\"\"", false},
    };
    for (const auto& c : cases) {
        INFO("If-None-Match: [" << c.header << "]");
        CHECK(if_none_match_matches(c.header, e) == c.matches);
    }
    // A NUL byte inside a tag is not an etagc byte: it neither truncates the tag nor matches, and
    // a tag holding one makes the whole header invalid, beside the right tag or not.
    CHECK_FALSE(if_none_match_matches(std::string("\"a\0bc\"", 6), e));
    CHECK_FALSE(if_none_match_matches(std::string("\"a\0bc\", \"abc\"", 13), e));
    const std::string nul_tag("\"a\0bc\"", 6);
    CHECK_FALSE(if_none_match_matches(nul_tag, nul_tag));
    CHECK_FALSE(if_none_match_matches("W/" + nul_tag, nul_tag));
    // A very long list is linear work and answers correctly at both ends.
    std::string big;
    for (int i = 0; i < 4000; ++i)
        big += "\"x\",";
    CHECK_FALSE(if_none_match_matches(big, e));
    CHECK(if_none_match_matches(big + e, e));
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

    SECTION("a weak validator, a list and * revalidate too (RFC 9110 weak comparison)") {
        const std::string stale = "\"0000000000000000\"";
        for (const std::string& header :
             {"W/" + lean_etag, stale + ", " + lean_etag, lean_etag + " ,\t" + stale,
              std::string("\"a,b\", ") + lean_etag, "," + lean_etag + ",", std::string("*")}) {
            INFO(header);
            auto hit = sink.Get(lean_path, {{"If-None-Match", header}});
            REQUIRE(hit);
            CHECK(hit->status == 304);
            CHECK(hit->body.empty());
            CHECK(hit->get_header_value("ETag") == lean_etag);
            CHECK(hit->get_header_value("Cache-Control") == "no-cache, private");
        }
    }

    SECTION("a header that is not a valid If-None-Match is a full 200, never a wrong 304") {
        // Each case holds a complete copy of the right tag, or a `*`, so a substring search or a
        // lenient parser would answer 304. A valid header is `*` alone or a comma-separated list
        // of quoted tags; anything else matches nothing.
        const std::string stale = "\"0000000000000000\"";
        for (const std::string& header :
             {std::string("garbage"), lean_etag.substr(0, lean_etag.size() - 1),
              std::string("W/"), std::string("\"unterminated"), full_etag + "x",
              "\"x" + lean_etag, lean_etag + "x", lean_etag + lean_etag, stale + " " + lean_etag,
              "w/" + lean_etag, "W/ " + lean_etag, std::string("*x"), std::string("* ,") + stale,
              stale + ", *", "*, " + lean_etag, std::string(), "\"bad space\", " + lean_etag,
              lean_etag + ", \"bad space\""}) {
            INFO(header);
            auto miss = sink.Get(lean_path, {{"If-None-Match", header}});
            REQUIRE(miss);
            CHECK(miss->status == 200);
            CHECK(miss->body == lean->body);
            CHECK(miss->get_header_value("ETag") == lean_etag);
        }
    }

    SECTION("a field sent on several lines is read as one comma-joined list (RFC 9110 5.3)") {
        // The occurrences are added in wire order (httplib keeps them in an insertion-ordered
        // multimap), so each case gives the same answer whichever line is read first.
        const std::string stale = "\"0000000000000000\"";
        struct Case {
            std::string first;
            std::string second;
            int status;
        };
        const Case cases[] = {
            {stale, lean_etag, 304},
            {"W/" + lean_etag, stale, 304},
            {stale, full_etag, 200},
            {lean_etag, "garbage", 200},
            {lean_etag, "\"bad space\"", 200},
            {"*", stale, 200},
        };
        for (const auto& c : cases) {
            INFO(c.first << " | " << c.second);
            sink.repeated_headers = {{"If-None-Match", c.first}, {"If-None-Match", c.second}};
            auto r = sink.Get(lean_path);
            sink.repeated_headers.clear();
            REQUIRE(r);
            CHECK(r->status == c.status);
            CHECK(r->body.empty() == (c.status == 304));
        }
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
        for (const std::string& header : {lean_etag, "W/" + lean_etag, "\"x\", " + lean_etag,
                                          std::string("*")}) {
            INFO(header);
            auto denied = sink.Get(lean_path, {{"If-None-Match", header}});
            REQUIRE(denied);
            CHECK(denied->status == 403);
            CHECK(denied->get_header_value("ETag").empty());
            CHECK(denied->body.find("\"openapi\"") == std::string::npos);
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

/// The member names of a JSON object.
std::set<std::string> keys_of(const json& obj) {
    std::set<std::string> out;
    for (auto it = obj.begin(); it != obj.end(); ++it)
        out.insert(it.key());
    return out;
}

/// The elements of a JSON array of strings.
std::set<std::string> set_of(const json& arr) {
    std::set<std::string> out;
    for (const auto& k : arr)
        out.insert(k.get<std::string>());
    return out;
}

/// The node at the end of a chain of object keys, or nullptr when any step is missing or its
/// parent is not an object. Lets a pin report a missing node with CHECK and move on to the next
/// row, where a chain of `.at()` would throw and abandon the rest of the test case.
const json* find_at(const json& root, std::initializer_list<const char*> keys) {
    const json* node = &root;
    for (const char* key : keys) {
        if (!node->is_object())
            return nullptr;
        const auto it = node->find(key);
        if (it == node->end())
            return nullptr;
        node = &*it;
    }
    return node;
}

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
    // fails on ANY change to the id-to-operation pairs: a rename, an addition, a removal, or
    // two operations exchanging their ids (which a hash of the ids alone cannot see).
    //
    // To update it after an intended change: run this test, copy the checksum the failure
    // prints into kOperationIdChecksum, and state the rename in the operationId note of
    // docs/user-manual/upgrading.md and in the change's changelog fragment. The count is
    // derived from the document (it is the number of operations); the one hand-kept number
    // for it lives in the typed-response test's exclusion list, not here.
    static const std::string kOperationIdChecksum = "\"64ad6d3ced74f7e4\"";
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
        // std::map iterates in key order, so the joined text is the sorted "id method path" lines.
        std::string joined;
        for (const auto& [id, where] : seen) {
            joined += id;
            joined += ' ';
            joined += where;
            joined += '\n';
        }
        INFO("sorted operationId pairs hash to " << yuzu::server::content_etag(joined)
             << " (update kOperationIdChecksum, and see the comment above it)");
        CHECK(yuzu::server::content_etag(joined) == kOperationIdChecksum);
    }
}

TEST_CASE("openapi documents: no text cites an issue, an ADR, a build wave or the review process",
          "[openapi][structure]") {
    // The document is read by operators and by agentic workers integrating with the API, on
    // /swagger and in generated clients. It states behaviour; it does not cite the issue, ADR
    // decision, design section, build wave, SOC 2 control, review gate or C++ symbol that shaped
    // it. Every string value in the document is checked, in both forms (keys are not text).
    static const std::regex kInternal(
        R"((^|[^A-Za-z0-9])#[0-9]+\b|\bADR-?[0-9]{4}|\bSOC ?2\b|\b[Ii]ssues? [0-9]|\b[Pp]ull request [0-9]|github\.com|\bmanifest_by_name\b|\bCC-?[0-9]|\bPhase [0-9]|\bWave [0-9]|)"
        R"(\bPRs? ?[0-9]|\bWS-[A-Z][0-9]|\bA2-R[0-9]|\bINV-[0-9]|\bUP-[0-9]+|\bCDX-|[Gg]overnance|)"
        R"(\bGate [0-9]|fix round|re-review|[Aa]pi-parity|API-parity|\bBatch [A-Z]\b|\bsprint\b|§|)"
        R"(decision log|docs/adr/|\badr/[0-9]{4}|[A-Za-z_]+::[A-Za-z_]|\.(hpp|cpp)\b|\b[a-z]+_fn\b|)"
        R"(\bk[A-Z][a-z]+[A-Z]\w*|\(new\)|\([A-B][0-9]\)|\bA4 (error )?envelope|\bB[12]\b|)"
        R"(\b[a-z][a-z_]+\(\)|routed-concerns|parity ledger|\bHermes\b|\bAstra\b|\b(SOLE|sole) (gate|authorization)|)"
        R"([a-z0-9]_fn\b|_(row|detail)_json\b|\bagent_ids_json\b|\bspec_json\b|)"
        R"(\brequire_(fleet_read|scoped_permission)\b|\bis_rbac_administrator\b|\bdispatch_confined|)"
        R"((^|[^/A-Za-z0-9])A[1-5]([^A-Za-z0-9]|$)|A4Error|)"
        R"(\b(ExecutionTracker|WorkflowEngine|SessionStore|TagStore|AuthFn|ExecutionEventBus|MachineNode|ClientValidation)\b|)"
        R"(\(M[0-9]\b|capability [0-9]+\.[0-9]|UAT non-functional|tracked open|\b(shared|same|one|row)( [A-Za-z_]+)? builder\b|)"
        R"(authorization-topology floor|\b(ledger|ladder)\b|docs/[a-z-]*(ladder|invariants)\.md|)"
        R"(\bBRD\b|\bF[0-9]+[a-z]\b|\bSprint\b|\bADR [0-9]|\bGH-[0-9]|\b[Tt]icket [0-9]|\bJira\b|\bEpic [0-9]|\bslice [0-9])");
    // The line an operator reads first is held to more: no control number, gate word or label.
    static const std::regex kSummary(R"(SOC ?2|\bCC-?[0-9]|\bGate\b|\bADR\b|\([A-B][0-9]\)|(^|[^A-Za-z0-9])#[0-9]|\bA[1-5]\b|capability [0-9])");
    for (const bool with_guides : {false, true}) {
        INFO("form: " << form_name(with_guides));
        const json spec = json::parse(document_text(with_guides));
        std::size_t strings = 0;
        const std::function<void(const json&, const std::string&)> walk =
            [&](const json& node, const std::string& where) {
                if (node.is_string()) {
                    ++strings;
                    INFO(where);
                    const std::string text = node.get<std::string>();
                    // The one retained schema reference names A4ErrorEnvelope (renaming it would
                    // change generated clients); no prose may.
                    if (text != "#/components/schemas/A4ErrorEnvelope") {
                        std::smatch hit;
                        const bool internal = std::regex_search(text, hit, kInternal);
                        INFO("matched: " << hit.str());
                        CHECK_FALSE(internal);
                    }
                } else if (node.is_array()) {
                    for (std::size_t i = 0; i < node.size(); ++i)
                        walk(node[i], where + "/" + std::to_string(i));
                } else if (node.is_object()) {
                    for (const auto& [key, value] : node.items())
                        walk(value, where + "/" + key);
                }
            };
        walk(spec, "");
        CHECK(strings > 1000); // the walk really reached the text
        for (const auto& o : all_operations(spec)) {
            INFO(o.where());
            CHECK_FALSE(std::regex_search(o.op.value("summary", std::string()), kSummary));
        }
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

TEST_CASE("openapi documents: every tag an operation uses is declared in the tag list",
          "[openapi][structure][guides]") {
    // An undeclared tag renders in a viewer with no description and, in the guides form, no
    // guide. The Commands tag was used for a release's worth of review before anyone noticed.
    for (const bool with_guides : {false, true}) {
        INFO("form: " << form_name(with_guides));
        const json spec = json::parse(document_text(with_guides));
        std::set<std::string> declared;
        for (const auto& tag : spec["tags"])
            declared.insert(tag.at("name").get<std::string>());
        std::set<std::string> used;
        for (const auto& o : all_operations(spec)) {
            for (const auto& t : o.op.value("tags", json::array()))
                used.insert(t.get<std::string>());
        }
        std::set<std::string> undeclared;
        for (const auto& t : used) {
            if (!declared.contains(t))
                undeclared.insert(t);
        }
        CHECK(undeclared == std::set<std::string>{});
        CHECK(declared.size() == 48);
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
    // Not in this table: the plugin-config value, secret, kill-switch and DELETE responses (pinned
    // by the plugin-config test case further down), GET /plugin-config (a list, not pinned by
    // either), and the upload agent routes, whose 200 bodies are bare objects with no envelope.
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
         {"agent_id", "state", "updated_at", "order_uncertain", "projection_pending"},
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
         {"agent_id", "guards", "total_guards", "unrepresented_pending_guards",
          "unrepresented_pending_rule_ids"},
         true,
         "guards",
         {"rule_id", "name", "state", "updated_at", "order_uncertain", "projection_pending"}},
        {"/guaranteed-state/status",
         kOne,
         false,
         {"total_rules", "compliant_rules", "drifted_rules", "errored_rules", "uncertain_rules",
          "note"},
         false,
         "",
         {}},
        {"/guaranteed-state/status/{agent_id}",
         kOne,
         false,
         {"agent_id", "total_rules", "compliant_rules", "drifted_rules", "errored_rules",
          "uncertain_rules", "note"},
         false,
         "",
         {}},
        {"/guaranteed-state/device-compliance",
         kOne,
         false,
         {"baseline", "deployed", "assessable", "agent_id", "total_guards", "snapshot_total",
          "compliant", "drifted", "errored", "pending", "uncertain_guards",
          "unrepresented_pending_guards", "unrepresented_pending_rule_ids", "last_updated",
          "guards"},
         true,
         "guards",
         {"rule_id", "name", "status", "updated_at", "order_uncertain", "projection_pending"}},
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

// #7217: the per-device reads declare the unrepresented-pending summary with its bounds and the two
// per-guard flags. Neither schema declares a `required` list for its data object (the pin above
// checks the key sets), so what is pinned here is each new property's type and bounds.
TEST_CASE("openapi_spec_json(): the #7217 per-device summary properties are typed and bounded",
          "[openapi][guardian][ordering]") {
    for (const bool with_guides : {false, true}) {
        const json spec = json::parse(document_text(with_guides));
        INFO("form: " << form_name(with_guides));

        const auto check_summary = [&](const json& data) {
            REQUIRE(data.contains("properties"));
            const json& props = data["properties"];
            REQUIRE(props.contains("unrepresented_pending_guards"));
            CHECK(props["unrepresented_pending_guards"].value("type", "") == "integer");
            CHECK(props["unrepresented_pending_guards"].value("minimum", -1) == 0);
            REQUIRE(props.contains("unrepresented_pending_rule_ids"));
            const json& ids = props["unrepresented_pending_rule_ids"];
            CHECK(ids.value("type", "") == "array");
            // The served literal is bound to the store's cap: a change to one without the other fails here.
            CHECK(ids.value("maxItems", std::size_t{0}) == yuzu::server::kUnrepresentedPendingIdCap);
            CHECK(ids.value("uniqueItems", false));
            REQUIRE(ids.contains("items"));
            CHECK(ids["items"].value("type", "") == "string");
        };
        const auto check_flags = [&](const json& guard_items) {
            REQUIRE(guard_items.contains("properties"));
            for (const char* k : {"order_uncertain", "projection_pending"}) {
                INFO("guard flag: " << k);
                REQUIRE(guard_items["properties"].contains(k));
                CHECK(guard_items["properties"][k].value("type", "") == "boolean");
            }
        };

        // device-compliance: the shared component.
        const json& cget = spec["paths"].at("/guaranteed-state/device-compliance").at("get");
        const json cdata = resolve_ref(spec, cget.at("responses")
                                                 .at("200")
                                                 .at("content")
                                                 .at("application/json")
                                                 .at("schema")["properties"]
                                                 .at("data"));
        check_summary(cdata);
        REQUIRE(cdata["properties"].contains("uncertain_guards"));
        CHECK(cdata["properties"]["uncertain_guards"].value("type", "") == "integer");
        CHECK(cdata["properties"]["uncertain_guards"].value("minimum", -1) == 0);
        check_flags(cdata["properties"].at("guards").at("items"));
        // The old caveat that disclaimed these fields is gone from the route text.
        const std::string cdesc = cget.value("description", "");
        CHECK(cdesc.find("do not report ordering uncertainty") == std::string::npos);
        CHECK(cdesc.find("unrepresented_pending_guards") != std::string::npos);
        // A5 machine metadata (#7217 gate 8, CA-7): the consumer rule lives on the `assessable`
        // property, and the per-agent status route points at the per-device reads.
        CHECK(cdata["properties"].at("assessable").value("description", "").find(
                  "Never render a clean state") != std::string::npos);
        CHECK(cdata["properties"].at("assessable").value("description", "").find(
                  "unrepresented_pending_guards") != std::string::npos);
        const std::string sdesc =
            spec["paths"].at("/guaranteed-state/status/{agent_id}").at("get").value("description", "");
        CHECK(sdesc.find("reads all-zero here") != std::string::npos);
        CHECK(sdesc.find("unrepresented_pending_guards") != std::string::npos);
        const std::string fdesc =
            spec["paths"].at("/guaranteed-state/status").at("get").value("description", "");
        CHECK(fdesc.find("counts only pairs that have a census row") != std::string::npos);
        CHECK(fdesc.find("/api/v1/guaranteed-state/agents/{agent_id}/rules") != std::string::npos);
        CHECK(fdesc.find("/api/v1/guaranteed-state/device-compliance") != std::string::npos);

        // all-guards: the inline schema.
        const json& gget = spec["paths"].at("/guaranteed-state/agents/{agent_id}/rules").at("get");
        const json gdata = resolve_ref(spec, gget.at("responses")
                                                 .at("200")
                                                 .at("content")
                                                 .at("application/json")
                                                 .at("schema")["properties"]
                                                 .at("data"));
        check_summary(gdata);
        check_flags(gdata["properties"].at("guards").at("items"));
        CHECK(gget.value("description", "").find("unrepresented_pending_guards") !=
              std::string::npos);
        // The 200 description names the new keys, not only the old three.
        const std::string g200 = gget.at("responses").at("200").value("description", "");
        CHECK(g200.find("unrepresented_pending_guards") != std::string::npos);
        CHECK(g200.find("unrepresented_pending_rule_ids") != std::string::npos);
        // The pending-evidence statement timeout is documented as NOT retryable on both routes, with
        // the metric that counts it; the ordinary degrade keeps its retryable text.
        for (const json* route : {&cget, &gget}) {
            const std::string r503 = route->at("responses").at("503").value("description", "");
            INFO(r503);
            CHECK(r503.find("NOT") != std::string::npos);
            CHECK(r503.find("retry_after_ms is null") != std::string::npos);
            CHECK(r503.find("guardian_census_device") != std::string::npos);
            CHECK(r503.find("statement_timeout") != std::string::npos);
            CHECK(route->value("description", "").find("ascending byte order") !=
                  std::string::npos);
        }
    }
}

TEST_CASE("openapi_spec_json(): the SettingsDataRetention schema matches the response builder",
          "[openapi][retention][echo]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const json& schema = spec.at("components").at("schemas").at("SettingsDataRetention");

    Config cfg;
    const json real = yuzu::server::settings_model::build_data_retention_settings(cfg);
    REQUIRE(real.contains("echo"));
    REQUIRE(real.contains("enforced"));
    REQUIRE(real["echo"].is_object());
    REQUIRE(real["echo"].contains("tick_seconds"));
    REQUIRE(real["echo"].contains("tiers"));
    REQUIRE_FALSE(real["echo"]["tiers"].empty());

    // The JSON type a value has, as the OpenAPI `type` keyword spells it.
    const auto type_of = [](const json& v) -> std::string {
        if (v.is_number_integer())
            return "integer";
        if (v.is_string())
            return "string";
        if (v.is_boolean())
            return "boolean";
        if (v.is_object())
            return "object";
        if (v.is_array())
            return "array";
        return "other";
    };

    // Every key the builder emits is declared; every key declared is emitted.
    const json& props = schema.at("properties");
    CHECK(schema.value("type", "") == type_of(real));
    CHECK_FALSE(schema.value("nullable", false));
    CHECK(keys_of(props) == keys_of(real));
    for (const char* k : {"response_retention_days", "audit_retention_days",
                          "guardian_event_retention_days"}) {
        CHECK(props.at(k).value("type", "") == type_of(real.at(k)));
        CHECK_FALSE(props.at(k).value("nullable", false));
    }

    // `required` is the builder's keys minus `echo`: a server older than this release omits `echo`,
    // and the manual tells clients to treat absent like null.
    auto expected_required = keys_of(real);
    expected_required.erase("echo");
    CHECK(set_of(schema.at("required")) == expected_required);

    // `enforced`: the same three keys, each a nullable integer, all required.
    // With the default (all null) `enforced` the builder emits no integer, so the type is read
    // from a second build whose three windows are set.
    const json& enforced = props.at("enforced");
    const json real_set = yuzu::server::settings_model::build_data_retention_settings(
        cfg, yuzu::server::settings_model::RetentionEnforced{1, 2, 3});
    REQUIRE(real_set.contains("enforced"));
    CHECK(enforced.value("type", "") == type_of(real["enforced"]));
    CHECK_FALSE(enforced.value("nullable", false));
    CHECK(keys_of(enforced.at("properties")) == keys_of(real["enforced"]));
    CHECK(set_of(enforced.at("required")) == keys_of(real["enforced"]));
    for (const auto& k : keys_of(real["enforced"])) {
        INFO("enforced key: " << k);
        CHECK(real["enforced"].at(k).is_null());
        CHECK(enforced.at("properties").at(k).value("type", "") ==
              type_of(real_set["enforced"].at(k)));
        CHECK(enforced.at("properties").at(k).value("nullable", false));
    }

    const json& echo = props.at("echo");
    CHECK(echo.value("type", "") == type_of(real["echo"]));
    CHECK(echo.value("nullable", false));
    CHECK(keys_of(echo.at("properties")) == keys_of(real["echo"]));
    CHECK(set_of(echo.at("required")) == keys_of(real["echo"]));
    CHECK(echo.at("properties").at("tick_seconds").value("type", "") ==
          type_of(real["echo"]["tick_seconds"]));
    CHECK_FALSE(echo.at("properties").at("tick_seconds").value("nullable", false));
    // The byte budget is published once at the echo level, as the agent's default.
    REQUIRE(real["echo"].contains("db_budget_bytes"));
    CHECK(echo.at("properties").at("db_budget_bytes").value("type", "") ==
          type_of(real["echo"]["db_budget_bytes"]));
    CHECK_FALSE(echo.at("properties").at("db_budget_bytes").value("nullable", false));

    // Every real tier: the declared keys, the declared types, and a null depth exactly on rows
    // tiers (so `nullable` is needed and is not decoration).
    const json& tiers = echo.at("properties").at("tiers");
    const json& item = tiers.at("items");
    CHECK(tiers.value("type", "") == type_of(real["echo"]["tiers"]));
    CHECK(item.value("type", "") == type_of(real["echo"]["tiers"][0]));
    CHECK_FALSE(tiers.value("nullable", false));
    CHECK_FALSE(item.value("nullable", false));
    // `tier` and `limit_kind` are open vocabularies: a closed `enum` would make a generated
    // client reject a new value the manual says it must tolerate.
    const json& tier_prop = item.at("properties").at("tier");
    CHECK_FALSE(tier_prop.contains("enum"));
    CHECK_FALSE(item.at("properties").at("limit_kind").contains("enum"));
    CHECK(keys_of(item.at("properties")) == keys_of(real["echo"]["tiers"][0]));
    CHECK(set_of(item.at("required")) == keys_of(real["echo"]["tiers"][0]));
    bool saw_rows = false;
    bool saw_seconds = false;
    for (const auto& tier : real["echo"]["tiers"]) {
        INFO("tier: " << tier.dump());
        CHECK(keys_of(tier) == keys_of(item.at("properties")));
        // The `tier` description lists every tier name the table really uses.
        CHECK(tier_prop.value("description", "").find(tier.at("tier").get<std::string>()) !=
              std::string::npos);
        for (auto it = tier.begin(); it != tier.end(); ++it) {
            if (it.key() == "guaranteed_depth_seconds")
                continue;
            INFO("key: " << it.key());
            CHECK(item.at("properties").at(it.key()).value("type", "") == type_of(it.value()));
            CHECK_FALSE(item.at("properties").at(it.key()).value("nullable", false));
        }
        const std::string kind = tier.at("limit_kind").get<std::string>();
        if (kind == "rows") {
            saw_rows = true;
            CHECK(tier.at("guaranteed_depth_seconds").is_null());
        } else {
            saw_seconds = true;
            CHECK(tier.at("guaranteed_depth_seconds").is_number_integer());
        }
    }
    CHECK(saw_rows);
    CHECK(saw_seconds);
    // Every row says whether the byte budget can shorten it.
    const json& budget_dep = item.at("properties").at("budget_dependent");
    CHECK(budget_dep.value("type", "") == "boolean");
    CHECK_FALSE(budget_dep.value("nullable", false));
    const json& depth = item.at("properties").at("guaranteed_depth_seconds");
    CHECK(depth.value("type", "") == "integer");
    CHECK(depth.value("nullable", false));

    // The builder's `echo: null` branch (no table available) is the case `nullable` exists for.
    const json no_table =
        yuzu::server::settings_model::build_data_retention_settings(cfg, {}, nullptr);
    REQUIRE(no_table.contains("echo"));
    CHECK(no_table["echo"].is_null());
}

TEST_CASE("openapi_spec_json(): the data-retention operation documents the Echo tiers",
          "[openapi][retention][echo]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));
    REQUIRE(spec["paths"].contains("/settings/data-retention"));
    const auto& get_op = spec["paths"]["/settings/data-retention"]["get"];

    const std::string description = get_op.value("description", "");
    for (const char* needle :
         {"tick_seconds", "guaranteed_depth_seconds", "not per-device readings",
          "paused or errored source is never pruned", "outlive their limit",
          "per-pass delete cap", "catch-up window", "not on coverage",
          "null for rows tiers", "tolerate unknown"})
        CHECK(description.find(needle) != std::string::npos);

    const std::string ok = get_op["responses"]["200"].value("description", "");
    CHECK(ok.find("echo: {tick_seconds, tiers") != std::string::npos);
}

TEST_CASE("openapi_spec_json(): the ResultSet schema declares what result_set_json emits",
          "[openapi][result_set][agents_failed]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const json& schema = spec.at("components").at("schemas").at("ResultSet");
    const json real = yuzu::server::result_set_json(yuzu::server::ResultSet{});

    std::set<std::string> emitted;
    for (auto it = real.begin(); it != real.end(); ++it)
        emitted.insert(it.key());
    std::set<std::string> declared;
    for (auto it = schema.at("properties").begin(); it != schema.at("properties").end(); ++it)
        declared.insert(it.key());
    std::set<std::string> required;
    for (const auto& k : schema.at("required"))
        required.insert(k.get<std::string>());
    CHECK(declared == emitted);
    CHECK(required == emitted);

    // The failure signal: a count and a flag derived from it.
    CHECK(schema.at("properties").at("agents_failed").value("type", "") == "integer");
    CHECK(schema.at("properties").at("partial").value("type", "") == "boolean");
    CHECK(real.at("agents_failed").get<long long>() == 0);
    CHECK_FALSE(real.at("partial").get<bool>());
    yuzu::server::ResultSet failed;
    failed.agents_failed = 2;
    const json partial = yuzu::server::result_set_json(failed);
    CHECK(partial.at("agents_failed").get<long long>() == 2);
    CHECK(partial.at("partial").get<bool>());
}

TEST_CASE("openapi_spec_json(): the re-eval and from-echo-query routes document the stale-source refusal",
          "[openapi][result_set][stale_source]") {
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    for (const char* path : {"/result-sets/{id}/re-eval", "/result-sets/from-echo-query"}) {
        INFO(path);
        const json& bad = spec.at("paths").at(path).at("post").at("responses").at("400");
        CHECK(bad.at("description").get<std::string>().find("RESULT_SET_REEVAL_STALE_SOURCE") !=
              std::string::npos);
    }
}

TEST_CASE("openapi documents: the response status set of the hand-checked operations matches "
          "what their handlers return",
          "[openapi][structure][responses]") {
    // Pins WHICH statuses the document declares per route, not their wording. Each expected set
    // below was written from the handler (symbol and file named per row), not from the document.
    //
    struct Row {
        const char* path;
        const char* method;
        std::set<std::string> statuses;
    };
    const std::vector<Row> rows = {
        // register_routes(): sink.Post("/api/v1/quarantine"): 201; 400 (body, whitelist, dispatch
        // check cannot classify); 401 (auth_fn); 403 (scoped gate, dispatch check); 500 (gate or
        // authorizer not wired); 503 (store not open, store fault, attempt audit unavailable).
        {"/quarantine", "post", {"201", "400", "401", "403", "500", "503"}},
        // register_routes(): sink.Delete(R"(/api/v1/quarantine/(.+))"): 200; the same refusals.
        {"/quarantine/{agent_id}", "delete", {"200", "400", "401", "403", "500", "503"}},
        // register_routes(): sink.Delete(R"(/api/v1/engine-principals/([^/]+))"): 200; 401 and
        // 403 (step-up, perm_fn, engine session); 404 (no such principal); 503 (six causes). It
        // has no input-validation 400.
        {"/engine-principals/{id}", "delete", {"200", "401", "403", "404", "503"}},
        // register_routes(): the .../credentials/rotate handler: 200; 400 (body, overlap_secs,
        // engine_store_error_status ClientValidation); 401; 403; 409 (conflict class); 503.
        {"/engine-principals/{id}/credentials/rotate", "post", {"200", "400", "401", "403", "409", "503"}},
        // register_routes(): the .../credentials/confirm handler: 200; 400 (token_id or secret
        // missing, validation class); 401; 403 (also a wrong secret); 409; 503.
        {"/engine-principals/{id}/credentials/confirm", "post", {"200", "400", "401", "403", "409", "503"}},
        // AuthRoutes elevate handler (auth_routes.cpp, sink.Post("/api/v1/elevate")): 200; 400
        // (justification, duration); 401 (session, dead window, step-up); 403 (eligibility,
        // identity source, amr, MFA); 500 (grant audit unrecordable); 503 (auth store).
        {"/elevate", "post", {"200", "400", "401", "403", "500", "503"}},
        // register_routes(): sink.Delete("/api/v1/sessions"): 200; 400 (username missing or
        // malformed); 401 (step-up); 403 (perm_fn); 500 (empty session username); 503
        // (session_revoke_fn not wired).
        {"/sessions", "delete", {"200", "400", "401", "403", "500", "503"}},
        // register_routes(): sink.Delete("/api/v1/sessions/me"): 200; 403 (MCP-tier or
        // service-scoped token); 401 (auth_fn, unauthenticated); 500 (empty session username);
        // 503 (session_revoke_fn not wired).
        {"/sessions/me", "delete", {"200", "401", "403", "500", "503"}},
        // file_retrieval_routes.cpp register_mint(): 201; 400 (invalid JSON body, ttl_secs,
        // expected_sha256, and a MintError that is not kUnavailable); 401 (auth_fn); 403
        // (require_permission UploadGrant:Write); 503 (store or entropy).
        {"/upload-grants", "post", {"201", "400", "401", "403", "503"}},
        // SettingsRoutes sink.Get("/api/v2/agent/plugin-policy") (settings_routes.cpp): 200; 401
        // and 403 (perm_fn_ PluginSigning:Read); 500 (bundle on disk unreadable); 503 (audit
        // unavailable, runtime config store unavailable, bundle changed while serving).
        {"/v2/agent/plugin-policy", "get", {"200", "401", "403", "500", "503"}},
        // plugin_config_routes.cpp, sink.Put(.../([^/]+)/([^/]+)): 200; 400 (JSON body, missing
        // value, parse_plugin_key, value and actor grammar); 413 (parse_json_object_body over
        // kMaxBodyBytes); 500 (set_config WriteFailed); 503 (store not open, Unavailable, attempt
        // audit unavailable). 401 (auth_fn) and 403 (perm_fn) are the auth layer, which the
        // plugin-config rows leave undeclared.
        {"/plugin-config/{plugin}/{key}", "put", {"200", "400", "413", "500", "503"}},
        // plugin_config_routes.cpp, sink.Put(.../([^/]+)/([^/]+)/secret): the same shape as the
        // plain PUT; 503 also covers SecretUnavailable (encrypt failed).
        {"/plugin-config/{plugin}/{key}/secret", "put", {"200", "400", "413", "500", "503"}},
        // plugin_config_routes.cpp, sink.Delete(.../([^/]+)/([^/]+)): 200; 400 (the existence
        // pre-check get_config answers InvalidInput for a bad plugin/key); 404 (pre-check
        // NotFound, or a concurrent delete); 500 (delete_config WriteFailed); 503 (store not
        // open, Unavailable, attempt audit unavailable). 403 (perm_fn) is left undeclared.
        {"/plugin-config/{plugin}/{key}", "delete", {"200", "400", "404", "500", "503"}},
        // plugin_config_routes.cpp, sink.Delete(.../([^/]+)/([^/]+)/secret): 200; 400
        // (parse_plugin_key); 404 (delete_secret NotFound, after the attempted audit row); 500
        // (delete_secret WriteFailed); 503 (store not open, Unavailable, attempt audit
        // unavailable). 403 (perm_fn) is left undeclared.
        {"/plugin-config/{plugin}/{key}/secret", "delete", {"200", "400", "404", "500", "503"}},
        // file_retrieval_routes.cpp register_chunk(): 200; 400 (Content-Range, body length, and
        // the TLS gate, require_tls kTlsRequired); 401 (session_unknown); 409
        // (offset_mismatch, session_terminal); 410 (expired); 413 (chunk_too_large,
        // size_exceeded); 500 (open or write failed); 503 (store null or unavailable,
        // advance_offset error).
        {"/uploads/{upload_id}/chunk",
         "put",
         {"200", "400", "401", "409", "410", "413", "500", "503"}},
        // plugin_config_routes.cpp, sink.Get("/api/v1/plugin-config"): 200; 400 (list_config
        // InvalidInput for a plugin filter that is not a valid identifier); 403 (list_read_fn
        // admitted a management-group-confined grant, refused by design, so it is declared); 503
        // (list_read_fn unwired or degraded, store not open, Unavailable). A 401 from the gate is
        // left undeclared.
        {"/plugin-config", "get", {"200", "400", "403", "503"}},
        // plugin_config_routes.cpp, sink.Get(.../([^/]+)/kill-switch): 200; 400 (get_kill_switch
        // InvalidInput, and a present-but-empty os); 503 (store not open, Unavailable). A missing
        // row reads as enabled=true, so there is no 404. 401 and 403 (perm_fn) are left
        // undeclared.
        {"/plugin-config/{plugin}/kill-switch", "get", {"200", "400", "503"}},
        // plugin_config_routes.cpp, sink.Put(.../([^/]+)/kill-switch): 200; 400 (JSON body,
        // enabled, reason, scope and actor grammar); 413 (parse_json_object_body over
        // kMaxBodyBytes); 500 (set_kill_switch WriteFailed); 503 (store not open, Unavailable,
        // attempt audit unavailable). 401 and 403 are left undeclared.
        {"/plugin-config/{plugin}/kill-switch", "put", {"200", "400", "413", "500", "503"}},
        // file_retrieval_routes.cpp register_status(): 200 (open or terminal session); 400 (TLS
        // gate); 401 (session_unknown); 410 (expired); 503 (store null or unavailable). A
        // terminal session answers 200, so there is no 409.
        {"/uploads/{upload_id}", "get", {"200", "400", "401", "410", "503"}},
        // file_retrieval_routes.cpp register_cancel(): 204; 400 (TLS gate); 401; 409
        // (session_terminal, including a lost cancel race); 410 (expired); 503 (store null or
        // unavailable, cancel_session error).
        {"/uploads/{upload_id}", "delete", {"204", "400", "401", "409", "410", "503"}},
        // file_retrieval_routes.cpp register_commit(): 200; 400 (TLS gate, sha256 missing); 401;
        // 409 (session_terminal); 410 (expired); 422 (hash_mismatch); 500 (blob cannot be read
        // back to verify); 503 (store null or unavailable, cancel_session or commit_session
        // error).
        {"/uploads/{upload_id}/commit",
         "post",
         {"200", "400", "401", "409", "410", "422", "500", "503"}},
    };
    for (const bool with_guides : {false, true}) {
        INFO("form: " << form_name(with_guides));
        const json spec = json::parse(document_text(with_guides));
        for (const auto& row : rows) {
            INFO(row.method << " " << row.path);
            // CHECK, not REQUIRE: a missing route must report itself and let the remaining rows
            // and the second document form still run.
            const bool has_path = spec.at("paths").contains(row.path);
            CHECK(has_path);
            if (!has_path)
                continue;
            const bool has_method = spec.at("paths").at(row.path).contains(row.method);
            CHECK(has_method);
            if (!has_method)
                continue;
            const json* responses = find_at(spec, {"paths", row.path, row.method, "responses"});
            CHECK(responses != nullptr);
            if (responses == nullptr)
                continue;
            CHECK(responses->is_object());
            if (!responses->is_object())
                continue;
            std::set<std::string> declared;
            for (const auto& [code, response] : responses->items())
                declared.insert(code);
            CHECK(declared == row.statuses);
        }
    }
}

TEST_CASE("openapi_spec_json(): DevicesListRow carries a nullable guardian_backend pinned to the token table",
          "[openapi][devices][guardian_backend]") {
    // #2240. OpenAPI 3.0.3 has no `type: [string, null]`: a nullable enum needs BOTH
    // `nullable: true` and `null` among the enum values. The enum is compared against the
    // server's own closed token table, so a fifth token is a red test here, not a client that
    // silently rejects it.
    json spec = json::parse(yuzu::server::openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const auto& row = spec["components"]["schemas"]["DevicesListRow"];
    REQUIRE(row["properties"].contains("guardian_backend"));
    const auto& prop = row["properties"]["guardian_backend"];
    CHECK(prop["type"] == "string");
    CHECK(prop["nullable"] == true);

    json expected = json::array();
    for (const char* t : yuzu::server::detail::kGuardianBackendTokens)
        expected.push_back(t);
    expected.push_back(nullptr);
    CHECK(prop["enum"] == expected);

    // The key is always present in the response, so it is a required property.
    bool required = false;
    for (const auto& r : row["required"])
        required = required || r == "guardian_backend";
    CHECK(required);

    // The detail schema inherits the row via allOf, so it carries the field too.
    CHECK(spec["components"]["schemas"]["DevicesDetail"].dump().find("DevicesListRow") !=
          std::string::npos);

    // The prose that used to say "5 fields" must not.
    const auto desc = spec["paths"]["/devices"]["get"]["description"].get<std::string>();
    CHECK(desc.find("5 fields") == std::string::npos);
    CHECK(desc.find("guardian_backend") != std::string::npos);
}

TEST_CASE("openapi documents: the plugin-config success responses reference the {data, meta} "
          "envelope schemas the handlers return",
          "[openapi][structure][responses]") {
    // plugin_config_routes.cpp answers GET/PUT of a value as {data: <entry>, meta}, the secret
    // PUT as {data: <metadata>, meta}, GET/PUT of a kill switch as {data: <switch>, meta}, and
    // both DELETEs as {deleted: true, meta} (no data wrapper). Each row names the operation, the
    // schema its 200 must reference, and that schema's required members. The schema's property
    // keys must equal its required members exactly, on purpose: a new optional top-level member is
    // an envelope change a client should be told about, so it has to update this table. The 200
    // description must also state the envelope, because a generated client reads that text.
    struct Row {
        const char* path;
        const char* method;
        const char* schema;
        std::set<std::string> required;
    };
    const std::vector<Row> rows = {
        {"/plugin-config/{plugin}/{key}", "get", "PluginConfigEntryResponse", {"data", "meta"}},
        {"/plugin-config/{plugin}/{key}", "put", "PluginConfigEntryResponse", {"data", "meta"}},
        {"/plugin-config/{plugin}/{key}/secret", "put", "PluginConfigSecretMetaResponse",
         {"data", "meta"}},
        {"/plugin-config/{plugin}/{key}", "delete", "PluginConfigDeleteResponse",
         {"deleted", "meta"}},
        {"/plugin-config/{plugin}/{key}/secret", "delete", "PluginConfigDeleteResponse",
         {"deleted", "meta"}},
        {"/plugin-config/{plugin}/kill-switch", "get", "PluginConfigKillSwitchResponse",
         {"data", "meta"}},
        {"/plugin-config/{plugin}/kill-switch", "put", "PluginConfigKillSwitchResponse",
         {"data", "meta"}},
    };
    for (const bool with_guides : {false, true}) {
        INFO("form: " << form_name(with_guides));
        const json spec = json::parse(document_text(with_guides));
        for (const auto& row : rows) {
            INFO(row.method << " " << row.path);
            const json* ok = find_at(spec, {"paths", row.path, row.method, "responses", "200"});
            CHECK(ok != nullptr);
            if (ok == nullptr)
                continue;
            const json* ref_node = find_at(*ok, {"content", "application/json", "schema", "$ref"});
            CHECK((ref_node != nullptr && ref_node->is_string()));
            if (ref_node != nullptr && ref_node->is_string())
                CHECK(ref_node->get<std::string>() ==
                      std::string("#/components/schemas/") + row.schema);
            const json* description = find_at(*ok, {"description"});
            CHECK((description != nullptr && description->is_string()));
            if (description != nullptr && description->is_string())
                CHECK(description->get<std::string>().find("meta: {api_version}") !=
                      std::string::npos);
            const json* required = find_at(spec, {"components", "schemas", row.schema, "required"});
            const json* properties =
                find_at(spec, {"components", "schemas", row.schema, "properties"});
            CHECK((required != nullptr && required->is_array()));
            CHECK((properties != nullptr && properties->is_object()));
            if (required != nullptr && required->is_array())
                CHECK(set_of(*required) == row.required);
            if (properties != nullptr && properties->is_object())
                CHECK(keys_of(*properties) == row.required);
        }
    }
}
