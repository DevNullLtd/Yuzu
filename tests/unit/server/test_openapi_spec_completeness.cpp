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

#include "openapi_spec_access.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
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

bool ref_resolves(const json& spec, const std::string& ref) {
    // ref is "#/a/b/c" -> walk spec["a"]["b"]["c"].
    std::string path = ref.substr(1); // drop leading '#'
    const json* node = &spec;
    for (const auto& part : split(path, '/')) {
        if (part.empty())
            continue;
        if (!node->is_object() || !node->contains(part))
            return false;
        node = &(*node)[part];
    }
    return true;
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
