/**
 * test_inventory_eval.cpp -- Unit tests for the inventory evaluation engine
 *
 * Covers: all operators (==, !=, >, >=, <, <=, contains, exists,
 * version_gte, version_lte), dot-path extraction, array index paths,
 * combine modes (all/any), edge cases, unknown operators, multiple agents.
 */

#include "inventory_eval.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

using Records = std::vector<std::pair<std::string, std::string>>;

// ============================================================================
// Operator: ==
// ============================================================================

TEST_CASE("InventoryEval: operator == exact string match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows", "version": "11"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "==", "Windows"}};
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
    CHECK(results[0].match == true);
    CHECK(results[0].matched_value == "Windows");
    CHECK(results[0].plugin == "hardware");
}

TEST_CASE("InventoryEval: operator == no match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "==", "Windows"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: !=
// ============================================================================

TEST_CASE("InventoryEval: operator != not equal match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "!=", "Windows"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "Linux");
}

TEST_CASE("InventoryEval: operator != no match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "!=", "Windows"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: > (numeric)
// ============================================================================

TEST_CASE("InventoryEval: operator > numeric match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"cpu_count": 8})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "cpu_count", ">", "4"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "8");
}

TEST_CASE("InventoryEval: operator > no match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"cpu_count": 4})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "cpu_count", ">", "4"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: operator > no match when less", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"cpu_count": 2})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "cpu_count", ">", "4"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: >=
// ============================================================================

TEST_CASE("InventoryEval: operator >= match when greater", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"ram_gb": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "ram_gb", ">=", "8"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "16");
}

TEST_CASE("InventoryEval: operator >= match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"ram_gb": 8})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "ram_gb", ">=", "8"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: operator >= no match when less", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"ram_gb": 4})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "ram_gb", ">=", "8"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: <
// ============================================================================

TEST_CASE("InventoryEval: operator < numeric match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"disk_free_gb": 10})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "disk_free_gb", "<", "50"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "10");
}

TEST_CASE("InventoryEval: operator < no match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"disk_free_gb": 50})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "disk_free_gb", "<", "50"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: <=
// ============================================================================

TEST_CASE("InventoryEval: operator <= match when less", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"temp_celsius": 60})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "temp_celsius", "<=", "80"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: operator <= match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"temp_celsius": 80})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "temp_celsius", "<=", "80"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: operator <= no match when greater", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"temp_celsius": 95})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "temp_celsius", "<=", "80"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: contains
// ============================================================================

TEST_CASE("InventoryEval: operator contains substring match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|software", R"({"product": "Microsoft Office Professional"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "product", "contains", "Office"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "Microsoft Office Professional");
}

TEST_CASE("InventoryEval: operator contains no match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|software", R"({"product": "Notepad"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "product", "contains", "Office"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: exists
// ============================================================================

TEST_CASE("InventoryEval: operator exists field present", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"serial": "ABC123", "model": "ThinkPad"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "serial", "exists", ""}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "ABC123");
}

TEST_CASE("InventoryEval: operator exists field missing", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"model": "ThinkPad"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "serial", "exists", ""}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: operator exists field is null", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"serial": null})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "serial", "exists", ""}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: version_gte
// ============================================================================

TEST_CASE("InventoryEval: version_gte match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.3"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.2.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "1.2.3");
}

TEST_CASE("InventoryEval: version_gte no match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.3"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.3.0"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: version_gte equal versions match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "2.0.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

// ============================================================================
// Operator: version_lte
// ============================================================================

TEST_CASE("InventoryEval: version_lte match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_lte", "1.2.3"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "1.2.0");
}

TEST_CASE("InventoryEval: version_lte no match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_lte", "1.9.9"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Version edge cases
// ============================================================================

TEST_CASE("InventoryEval: version padding with zeros", "[inventory_eval][version]") {
    // "1.0" should be treated as "1.0.0"
    Records records = {
        {"agent-1|software", R"({"version": "1.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.0.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);

    // Also verify the reverse: "1.0.0" >= "1.0"
    InventoryEvalRequest req2;
    req2.conditions = {{"software", "version", "version_gte", "1.0"}};

    Records records2 = {
        {"agent-1|software", R"({"version": "1.0.0"})"},
    };
    auto results2 = evaluate_inventory(req2, records2);
    REQUIRE(results2.size() == 1);
}

TEST_CASE("InventoryEval: version with non-numeric segments", "[inventory_eval][version]") {
    // "1.0.0-beta" -- the "-beta" part is non-numeric, parsed as 0
    Records records = {
        {"agent-1|software", R"({"version": "1.0.0-beta"})"},
    };

    // "1.0.0-beta" segments: [1, 0, 0] (the "0-beta" part parses as 0)
    // compared against "1.0.0" segments: [1, 0, 0] -- should be equal
    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.0.0"}};

    auto results = evaluate_inventory(req, records);
    // Non-numeric suffix gets parsed as 0 by from_chars, so 1.0.0 >= 1.0.0 is true
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: version single segment", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "3"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "2"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: version many segments", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.3.4.5"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_lte", "1.2.3.4.6"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

// ============================================================================
// Dot-path field extraction
// ============================================================================

TEST_CASE("InventoryEval: dot-path nested object", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|software", R"({"details": {"version": "1.0", "vendor": "Acme"}})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "details.version", "==", "1.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "1.0");
}

TEST_CASE("InventoryEval: dot-path deeply nested", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|config", R"({"system": {"network": {"dns": "8.8.8.8"}}})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"config", "system.network.dns", "==", "8.8.8.8"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "8.8.8.8");
}

TEST_CASE("InventoryEval: dot-path missing intermediate key", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|config", R"({"system": {"other": "value"}})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"config", "system.network.dns", "==", "8.8.8.8"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Array index in dot-path
// ============================================================================

TEST_CASE("InventoryEval: array index in dot-path", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|inventory", R"({"items": [{"name": "foo"}, {"name": "bar"}]})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"inventory", "items.0.name", "==", "foo"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "foo");
}

TEST_CASE("InventoryEval: array second element", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|inventory", R"({"items": [{"name": "foo"}, {"name": "bar"}]})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"inventory", "items.1.name", "==", "bar"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "bar");
}

TEST_CASE("InventoryEval: array index out of bounds", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|inventory", R"({"items": [{"name": "foo"}]})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"inventory", "items.5.name", "==", "foo"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Combine mode: "all" (AND)
// ============================================================================

TEST_CASE("InventoryEval: combine all -- all match", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows", "cpu_count": 8, "ram_gb": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "cpu_count", ">=", "4"},
        {"hardware", "ram_gb", ">=", "8"},
    };
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: combine all -- one fails", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux", "cpu_count": 8, "ram_gb": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "cpu_count", ">=", "4"},
    };
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Combine mode: "any" (OR)
// ============================================================================

TEST_CASE("InventoryEval: combine any -- one matches", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux", "cpu_count": 2})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "os", "==", "Linux"},
    };
    req.combine = "any";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: combine any -- none match", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "macOS"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "os", "==", "Linux"},
    };
    req.combine = "any";

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Empty conditions
// ============================================================================

TEST_CASE("InventoryEval: empty conditions returns all records", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Windows"})"},
        {"agent-2|hw", R"({"os": "Linux"})"},
        {"agent-3|hw", R"({"os": "macOS"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {};
    req.combine = "all";

    // With combine=all and no conditions, overall_match starts as true for each record
    auto results = evaluate_inventory(req, records);
    CHECK(results.size() == 3);
}

// ============================================================================
// No matching records
// ============================================================================

TEST_CASE("InventoryEval: no matching records returns empty", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Windows"})"},
        {"agent-2|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "FreeBSD"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Multiple agents -- results grouped correctly
// ============================================================================

TEST_CASE("InventoryEval: multiple agents results grouped", "[inventory_eval][multi]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
        {"agent-2|software", R"({"version": "1.5.0"})"},
        {"agent-3|software", R"({"version": "3.0.0"})"},
        {"agent-4|software", R"({"version": "0.9.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.5.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 3);

    // Verify we got the right agents
    bool found_1 = false, found_2 = false, found_3 = false;
    for (const auto& r : results) {
        if (r.agent_id == "agent-1") found_1 = true;
        if (r.agent_id == "agent-2") found_2 = true;
        if (r.agent_id == "agent-3") found_3 = true;
        CHECK(r.plugin == "software");
        CHECK(r.match == true);
    }
    CHECK(found_1);
    CHECK(found_2);
    CHECK(found_3);
}

TEST_CASE("InventoryEval: filter by agent_id", "[inventory_eval][multi]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
        {"agent-2|software", R"({"version": "3.0.0"})"},
    };

    InventoryEvalRequest req;
    req.agent_id = "agent-1";
    req.conditions = {{"software", "version", "version_gte", "1.0.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
}

// ============================================================================
// Unknown operator
// ============================================================================

TEST_CASE("InventoryEval: unknown operator silently returns no match", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "matches_regex", "Lin.*"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Edge cases
// ============================================================================

TEST_CASE("InventoryEval: malformed JSON skipped", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", "not valid json {{{"},
        {"agent-2|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    // #4496: a genuine parse error is a DIFFERENT failure mode from the
    // depth-guard exclusion below - excluded_by_depth must stay 0 here, or a
    // caller surfacing the poison-exclusion signal would fire it on ordinary
    // malformed input too.
    //
    // #4496 follow-up: the malformed record IS counted, via the separate
    // excluded_by_parse_error out-param - the two counters must move
    // independently, never conflated into one signal.
    std::size_t excluded_by_depth = 999;
    std::size_t excluded_by_parse_error = 999;
    auto results = evaluate_inventory(req, records, &excluded_by_depth, &excluded_by_parse_error);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-2");
    CHECK(excluded_by_depth == 0);
    CHECK(excluded_by_parse_error == 1);
}

// #2437-class guard: data_json nesting past kMcpMaxJsonDepth must be skipped
// BEFORE the parse, exactly like a genuine parse error above. Deliberately
// uses "exists" (matches on presence alone, not value) with the deep nesting
// INSIDE the "os" field's own value rather than at the top level - this is
// what makes the test discriminate: json_path would fail to resolve "os" on
// a top-level array (wrong container kind) regardless of the guard, so that
// shape can't prove anything. With "os" holding the deep structure, an
// "exists" check that reaches eval_condition unguarded calls
// json_value_to_string's dump() fallback on the parsed tree - the exact
// unboundedly-recursive call that would SIGSEGV the whole process at the
// real ~100,000-level attack depth - and would spuriously COUNT this record
// as a match. The guard must exclude it before that call is ever made.
// Reachability-proxy depth (36 > kMcpMaxJsonDepth's 32), never the real
// attack depth. This one function backs all three evaluate_inventory()
// callers (REST /api/v1/inventory/evaluate, REST from-inventory-query, and
// the MCP create_result_set_from_inventory_query tool), so this single test
// covers all three.
//
// #4496: also asserts the exclusion is COUNTED via the out-param, since
// every production caller now depends on that count to surface a
// truncation/exclusion signal rather than silently returning fewer matches
// than actually exist.
TEST_CASE("InventoryEval: over-deep data_json skipped before it can spuriously match or "
          "reach the dump() fallback, a healthy matching record is still returned",
          "[inventory_eval][edge][security]") {
    const std::string poisoned = R"({"os":)" + std::string(35, '[') + std::string(35, ']') + "}";
    Records records = {
        {"agent-1|hw", poisoned},
        {"agent-2|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "exists", ""}};

    std::size_t excluded_by_depth = 0;
    auto results = evaluate_inventory(req, records, &excluded_by_depth);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-2");
    CHECK(excluded_by_depth == 1);
}

// #4496: the sibling of the test above - no poisoned record present, so the
// out-param must read back 0, not merely "truthy/absent". A caller building a
// truncation flag off a garbage/uninitialized count would otherwise report a
// false positive on perfectly healthy input.
TEST_CASE("InventoryEval: excluded_by_depth stays zero when no record is poisoned",
          "[inventory_eval][edge][security]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux"})"},
        {"agent-2|hw", R"({"os": "Windows"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "exists", ""}};

    std::size_t excluded_by_depth = 0;
    auto results = evaluate_inventory(req, records, &excluded_by_depth);
    REQUIRE(results.size() == 2);
    CHECK(excluded_by_depth == 0);
}

// #4496 (Gate 7 fix, quality-engineer SHOULD): the out-param must ACCUMULATE
// across records, not saturate at 1 - two independently-poisoned records
// plus a healthy matching record must leave excluded_by_depth at 2, with the
// healthy record's match still returned.
TEST_CASE("InventoryEval: excluded_by_depth accumulates across multiple poisoned records",
          "[inventory_eval][edge][security]") {
    const std::string poisoned = R"({"os":)" + std::string(35, '[') + std::string(35, ']') + "}";
    Records records = {
        {"agent-1|hw", poisoned},
        {"agent-2|hw", poisoned},
        {"agent-3|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "exists", ""}};

    std::size_t excluded_by_depth = 0;
    auto results = evaluate_inventory(req, records, &excluded_by_depth);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-3");
    CHECK(excluded_by_depth == 2);
}

// #4496 (Gate 7 fix, cpp-expert + cpp-safety NICE, independently converged):
// the out-param is zeroed up front so a caller never reads a garbage/stale
// count - but that zeroing must also hold on the kMaxInventoryConditions
// early-return path, not just the normal loop-exit path. Seed a stale
// nonzero value and confirm this specific backstop path clears it too.
TEST_CASE("InventoryEval: excluded_by_depth is zeroed on the kMaxInventoryConditions "
          "early return, not just the loop-exit path",
          "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions.assign(kMaxInventoryConditions + 1, InventoryCondition{"hw", "os", "exists", ""});

    std::size_t excluded_by_depth = 999;
    auto results = evaluate_inventory(req, records, &excluded_by_depth);
    CHECK(results.empty());
    CHECK(excluded_by_depth == 0);
}

// #4496 follow-up: the sibling of the four excluded_by_depth tests above, for
// the excluded_by_parse_error out-param - mirrors their structure exactly,
// substituting a malformed-JSON record for an over-nested one.

// #4496 follow-up: the sibling of "no poisoned record" above - a caller
// building a truncation flag off a garbage/uninitialized count would
// otherwise report a false positive on perfectly healthy input.
TEST_CASE("InventoryEval: excluded_by_parse_error stays zero when no record is malformed",
          "[inventory_eval][edge][security]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux"})"},
        {"agent-2|hw", R"({"os": "Windows"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "exists", ""}};

    std::size_t excluded_by_parse_error = 0;
    auto results = evaluate_inventory(req, records, nullptr, &excluded_by_parse_error);
    REQUIRE(results.size() == 2);
    CHECK(excluded_by_parse_error == 0);
}

// #4496 follow-up (Gate 7 shape from the depth-guard sibling): the out-param
// must ACCUMULATE across records, not saturate at 1 - two independently
// malformed records plus a healthy matching record must leave
// excluded_by_parse_error at 2, with the healthy record's match still
// returned.
TEST_CASE("InventoryEval: excluded_by_parse_error accumulates across multiple malformed "
          "records",
          "[inventory_eval][edge][security]") {
    Records records = {
        {"agent-1|hw", "not valid json {{{"},
        {"agent-2|hw", "also not valid ]]]"},
        {"agent-3|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "exists", ""}};

    std::size_t excluded_by_parse_error = 0;
    auto results = evaluate_inventory(req, records, nullptr, &excluded_by_parse_error);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-3");
    CHECK(excluded_by_parse_error == 2);
}

// #4496 follow-up (Gate 7 shape from the depth-guard sibling): the out-param
// is zeroed up front so a caller never reads a garbage/stale count - that
// zeroing must also hold on the kMaxInventoryConditions early-return path,
// not just the normal loop-exit path.
TEST_CASE("InventoryEval: excluded_by_parse_error is zeroed on the kMaxInventoryConditions "
          "early return, not just the loop-exit path",
          "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions.assign(kMaxInventoryConditions + 1, InventoryCondition{"hw", "os", "exists", ""});

    std::size_t excluded_by_parse_error = 999;
    auto results = evaluate_inventory(req, records, nullptr, &excluded_by_parse_error);
    CHECK(results.empty());
    CHECK(excluded_by_parse_error == 0);
}

// #4496 follow-up (Gate 8 targeted re-review, quality-engineer): the two
// exclusion out-params are documented (inventory_eval.hpp) as "counted
// separately so an operator can tell WHICH guard excluded a record" - a
// claim only actually exercised when BOTH causes are present in the SAME
// call. Every other test in this file (and the REST/MCP route-level tests)
// exercises one cause at a time; this pins that both counters accumulate
// independently within a single evaluate_inventory() call, and that the
// healthy record still matches regardless of which other records were
// excluded and for which reason.
TEST_CASE("InventoryEval: excluded_by_depth and excluded_by_parse_error accumulate "
          "independently when both causes are present in the same call",
          "[inventory_eval][edge][security]") {
    const std::string poisoned = R"({"os":)" + std::string(35, '[') + std::string(35, ']') + "}";
    Records records = {
        {"agent-1|hw", poisoned},
        {"agent-2|hw", "not valid json {{{"},
        {"agent-3|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "exists", ""}};

    std::size_t excluded_by_depth = 0;
    std::size_t excluded_by_parse_error = 0;
    auto results = evaluate_inventory(req, records, &excluded_by_depth, &excluded_by_parse_error);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-3");
    CHECK(excluded_by_depth == 1);
    CHECK(excluded_by_parse_error == 1);
}

// #4541 review (Important finding 1): the fix capped PER-RECORD LOG DETAIL
// at kMaxLoggedExclusionsPerCause (10) but must never cap the COUNT itself -
// the out-param is the caller-facing signal ("N records were excluded"),
// only the log-line volume is a pure implementation detail. Seeds MORE than
// the cap for each cause (12) and asserts both out-params still report the
// real total (12), not the capped log-line count (10) - proves the two are
// genuinely independent, not the same counter reused for both purposes.
TEST_CASE("InventoryEval: excluded_by_depth and excluded_by_parse_error report the real "
          "total even when it exceeds the per-cause log-volume cap",
          "[inventory_eval][edge][security]") {
    const std::string poisoned = R"({"os":)" + std::string(35, '[') + std::string(35, ']') + "}";
    Records records;
    for (int i = 0; i < 12; ++i) {
        records.emplace_back("poisoned-" + std::to_string(i) + "|hw", poisoned);
    }
    for (int i = 0; i < 12; ++i) {
        records.emplace_back("malformed-" + std::to_string(i) + "|hw", "not valid json {{{");
    }
    records.emplace_back("agent-healthy|hw", R"({"os": "Linux"})");

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "exists", ""}};

    std::size_t excluded_by_depth = 0;
    std::size_t excluded_by_parse_error = 0;
    auto results = evaluate_inventory(req, records, &excluded_by_depth, &excluded_by_parse_error);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-healthy");
    CHECK(excluded_by_depth == 12);
    CHECK(excluded_by_parse_error == 12);
}

TEST_CASE("InventoryEval: record key without separator skipped", "[inventory_eval][edge]") {
    Records records = {
        {"badkey_no_pipe", R"({"os": "Linux"})"},
        {"agent-1|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
}

TEST_CASE("InventoryEval: collected_at is extracted", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux", "collected_at": 1711234567})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].collected_at == 1711234567);
}

TEST_CASE("InventoryEval: condition plugin filter skips non-matching plugin", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|network", R"({"ip": "10.0.0.1"})"},
    };

    // Condition targets "hardware" plugin, record is "network" -- AND mode fails
    InventoryEvalRequest req;
    req.conditions = {{"hardware", "ip", "==", "10.0.0.1"}};
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: empty plugin in condition matches any plugin", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|network", R"({"ip": "10.0.0.1"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"", "ip", "==", "10.0.0.1"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].plugin == "network");
}

TEST_CASE("InventoryEval: boolean JSON value converted to string", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"secure_boot": true})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "secure_boot", "==", "true"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "true");
}

TEST_CASE("InventoryEval: integer JSON value compared as number", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"cores": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "cores", ">", "10"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: empty records returns empty", "[inventory_eval][edge]") {
    Records records = {};

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// parse_inventory_condition: the one conditions[] element parser (#4644)
// ============================================================================

TEST_CASE("InventoryEval: parse_inventory_condition renders a numeric operand for comparison ops",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    auto parse = [](const json& c, InventoryCondition& out) {
        return parse_inventory_condition(c, out);
    };
    InventoryCondition c;
    // Strings pass through untouched, including the empty string and an absent value.
    CHECK_FALSE(parse(json{{"plugin", "p"}, {"field", "f"}, {"op", ">"}, {"value", "7"}}, c));
    CHECK(c.plugin == "p");
    CHECK(c.field == "f");
    CHECK(c.op == ">");
    CHECK(c.value == "7");
    c = {};
    CHECK_FALSE(parse(json{{"op", "exists"}}, c));
    CHECK(c.value.empty());

    // Numbers keep their dump() text and set numeric_operand, so ==/!= compare numerically
    // (a string operand leaves the flag clear and stays lexical).
    struct Case { const char* op; const char* json_value; const char* expect; };
    for (const auto& k : {Case{">", "5", "5"}, Case{">=", "-1", "-1"}, Case{"<", "5.5", "5.5"},
                          Case{"<=", "1e3", "1000.0"}, Case{"==", "4294967297", "4294967297"},
                          Case{"!=", "18446744073709551615", "18446744073709551615"},
                          Case{"==", "true", "true"}, Case{"!=", "false", "false"}}) {
        INFO(k.op << " " << k.json_value);
        c = {};
        const auto doc = json::parse(std::string(R"({"op":")") + k.op + R"(","value":)" +
                                     k.json_value + "}");
        CHECK_FALSE(parse(doc, c));
        CHECK(c.value == k.expect);
        CHECK(c.numeric_operand == (std::string(k.json_value) != "true" &&
                                    std::string(k.json_value) != "false"));
    }
}

TEST_CASE("InventoryEval: a JSON-number operand compares numerically under == and !=",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    // Stored side: a float, an int, a non-numeric string, a boolean, a numeric-looking string.
    Records records = {
        {"agent-f|p", R"({"v": 5.5})"},    {"agent-i|p", R"({"v": 5})"},
        {"agent-k|p", R"({"v": 1000})"},   {"agent-s|p", R"({"v": "abc"})"},
        {"agent-b|p", R"({"v": true})"},   {"agent-n|p", R"({"v": "5.50"})"},
    };
    // Build the condition through the real parser, exactly as the three producers do.
    auto matching = [&](const char* op, const char* operand_json) {
        InventoryEvalRequest req;
        InventoryCondition c;
        const auto doc = json::parse(std::string(R"({"plugin":"p","field":"v","op":")") + op +
                                     R"(","value":)" + operand_json + "}");
        REQUIRE_FALSE(parse_inventory_condition(doc, c));
        req.conditions.push_back(c);
        std::vector<std::string> ids;
        for (const auto& r : evaluate_inventory(req, records))
            ids.push_back(r.agent_id);
        std::sort(ids.begin(), ids.end());
        return ids;
    };
    using Ids = std::vector<std::string>;
    // 5.5 == stored float 5.5 (and the numeric-looking string "5.50"); never the others.
    CHECK(matching("==", "5.5") == Ids{"agent-f", "agent-n"});
    // != 5.5 excludes those, and selects the int, the non-numeric string and the boolean.
    CHECK(matching("!=", "5.5") == Ids{"agent-b", "agent-i", "agent-k", "agent-s"});
    // 5.0 equals stored int 5 (and 1000 matches 1e3 below).
    CHECK(matching("==", "5.0") == Ids{"agent-i"});
    CHECK(matching("==", "1e3") == Ids{"agent-k"});
    CHECK(matching("!=", "1e3") == Ids{"agent-b", "agent-f", "agent-i", "agent-n", "agent-s"});
    CHECK(matching("==", "5") == Ids{"agent-i"});
    // A non-numeric stored value is never equal to a numeric operand.
    CHECK(matching("==", "0") == Ids{});
}

TEST_CASE("InventoryEval: numeric == and != compare the raw stored number, not a rendering of it",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    // One record per agent, one stored JSON value each (raw JSON text, so integer width is kept).
    auto matches = [](const char* stored_json, const char* op, const char* operand_json) {
        Records records = {{"agent-a|p", std::string(R"({"v": )") + stored_json + "}"}};
        InventoryEvalRequest req;
        InventoryCondition c;
        const auto doc = json::parse(std::string(R"({"plugin":"p","field":"v","op":")") + op +
                                     R"(","value":)" + operand_json + "}");
        REQUIRE_FALSE(parse_inventory_condition(doc, c));
        req.conditions.push_back(c);
        return !evaluate_inventory(req, records).empty();
    };
    // 6-decimal rendering used to make these equal or unequal wrongly.
    CHECK(matches("0.1234567", "==", "0.1234567"));
    CHECK_FALSE(matches("0.1234567", "!=", "0.1234567"));
    CHECK_FALSE(matches("1e-7", "==", "0"));
    CHECK(matches("1e-7", "!=", "0"));
    CHECK(matches("1e-7", "==", "1e-7"));
    // Integers above 2^53 compare exactly (they used to round through a double).
    CHECK_FALSE(matches("9007199254740993", "==", "9007199254740992"));
    CHECK(matches("9007199254740993", "!=", "9007199254740992"));
    CHECK(matches("9007199254740993", "==", "9007199254740993"));
    CHECK_FALSE(matches("9007199254740992.0", "==", "9007199254740993"));
    // Int vs float spelling of the same value, and plain floats.
    CHECK(matches("5", "==", "5.0"));
    CHECK(matches("5.0", "==", "5"));
    CHECK(matches("5.5", "==", "5.5"));
    CHECK(matches("-0.0", "==", "0"));
    CHECK_FALSE(matches("0.30000000000000004", "==", "0.3"));
    // Unsigned beyond int64 max, and the signed/unsigned mix.
    CHECK(matches("18446744073709551615", "==", "18446744073709551615"));
    CHECK_FALSE(matches("18446744073709551615", "==", "-1"));
    CHECK_FALSE(matches("-1", "==", "18446744073709551615"));
    CHECK(matches("-1", "==", "-1"));
    // Stored numeric strings parse as numbers; a non-numeric string, bool or null never equals.
    CHECK(matches(R"("1.10")", "==", "1.1"));
    CHECK(matches(R"("9007199254740993")", "==", "9007199254740993"));
    CHECK_FALSE(matches(R"("9007199254740993")", "==", "9007199254740992"));
    CHECK_FALSE(matches("true", "==", "1"));
    CHECK(matches("true", "!=", "1"));
    CHECK_FALSE(matches(R"("abc")", "==", "0"));
    CHECK(matches(R"("abc")", "!=", "0"));
    // Forms a number parser could be lenient about are not numbers on any platform.
    for (const char* text : {R"(" 5")", R"("+5")", R"("0x5")", R"("5 ")", R"("nan")", R"("inf")",
                             R"("")"}) {
        INFO(text);
        CHECK_FALSE(matches(text, "==", "5"));
        CHECK(matches(text, "!=", "5"));
    }
    // A negative integer against a double: exact, integral and in range.
    CHECK(matches("-5", "==", "-5.0"));
    CHECK_FALSE(matches("-5", "==", "-5.5"));
    CHECK(matches("-9223372036854775808.0", "==", "-9223372036854775808"));
    CHECK_FALSE(matches("-9223372036854777856.0", "==", "-9223372036854775808"));
    // A stored string that parses as an int64 against a double operand.
    CHECK(matches(R"("5")", "==", "5.0"));
    CHECK_FALSE(matches(R"("9007199254740992.0")", "==", "9007199254740993"));
    // The 2^63 and 2^64 range guards: the double one past the type's max never equals its max.
    CHECK_FALSE(matches("18446744073709551616.0", "==", "18446744073709551615"));
    CHECK_FALSE(matches("9223372036854775808.0", "==", "9223372036854775807"));
    CHECK(matches("9223372036854775808.0", "==", "9223372036854775808"));
    // Stored strings: sign, leading '.', leading zeros, and an out-of-range exponent.
    CHECK(matches(R"("-1")", "==", "-1"));
    CHECK(matches(R"(".5")", "==", "0.5"));
    CHECK(matches(R"("007")", "==", "7"));
    CHECK_FALSE(matches(R"("1e400")", "==", "5"));
    CHECK_FALSE(matches(R"("1e400")", "==", "0"));
    CHECK(matches(R"("1e400")", "!=", "5"));
    // An operand of -0 or 0.0 equals a stored zero in every spelling.
    CHECK(matches("0", "==", "-0"));
    CHECK(matches("0", "==", "0.0"));
    CHECK(matches("-0.0", "==", "0.0"));
    CHECK(matches(R"("0")", "==", "-0.0"));
    // A stored null is "no value": neither == nor != selects it (unchanged).
    CHECK_FALSE(matches("null", "==", "0"));
    CHECK_FALSE(matches("null", "!=", "0"));
    // A string operand stays lexical against a stored string.
    {
        Records records = {{"agent-a|p", R"({"v": "1.10"})"}};
        InventoryEvalRequest req;
        req.conditions = {{"p", "v", "==", "1.1"}};
        CHECK(evaluate_inventory(req, records).empty());
    }
}

TEST_CASE("InventoryEval: numeric > >= < <= compare the raw stored number exactly",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    auto matches = [](const char* stored_json, const char* op, const char* operand_json) {
        Records records = {{"agent-a|p", std::string(R"({"v": )") + stored_json + "}"}};
        InventoryEvalRequest req;
        InventoryCondition c;
        const auto doc = json::parse(std::string(R"({"plugin":"p","field":"v","op":")") + op +
                                     R"(","value":)" + operand_json + "}");
        REQUIRE_FALSE(parse_inventory_condition(doc, c));
        req.conditions.push_back(c);
        return !evaluate_inventory(req, records).empty();
    };
    // Digits a 6-decimal rendering used to drop.
    CHECK_FALSE(matches("0.1234567", ">", "0.1234567"));
    CHECK(matches("0.1234567", ">=", "0.1234567"));
    CHECK(matches("0.1234567", "<=", "0.1234567"));
    CHECK_FALSE(matches("0.1234567", "<", "0.1234567"));
    CHECK(matches("3e-7", ">", "2e-7"));
    CHECK_FALSE(matches("3e-7", "<", "2e-7"));
    CHECK(matches("1e-7", ">", "0"));
    // Unsigned above INT64_MAX no longer wraps negative.
    CHECK(matches("18446744073709551615", ">", "9223372036854775807"));
    CHECK(matches("18446744073709551615", ">", "-1"));
    CHECK_FALSE(matches("18446744073709551615", "<", "9223372036854775807"));
    CHECK(matches("18446744073709551615", ">=", "18446744073709551615"));
    CHECK_FALSE(matches("18446744073709551615", ">", "18446744073709551615"));
    CHECK(matches("-1", "<", "18446744073709551615"));
    CHECK_FALSE(matches("-1", ">", "18446744073709551615"));
    // Integers above 2^53 order exactly, against integer and double operands.
    CHECK(matches("9007199254740993", ">", "9007199254740992"));
    CHECK(matches("9007199254740994.0", ">", "9007199254740993"));
    CHECK_FALSE(matches("9007199254740992.0", ">=", "9007199254740993"));
    CHECK(matches("9007199254740992", "<", "9007199254740993"));
    CHECK(matches("9007199254740992.0", "<", "9007199254740993"));
    // Integer vs double, fraction and range guards.
    CHECK(matches("5", "<", "5.5"));
    CHECK(matches("5", ">", "4.5"));
    CHECK(matches("-5", ">", "-5.5"));
    CHECK(matches("-5", "<", "-4.5"));
    CHECK(matches("18446744073709551616.0", ">", "18446744073709551615"));
    CHECK(matches("9223372036854775808.0", ">", "9223372036854775807"));
    CHECK(matches("-9223372036854777856.0", "<", "-9223372036854775808"));
    CHECK(matches("1e300", ">", "18446744073709551615"));
    CHECK(matches("-1e300", "<", "5"));
    CHECK(matches("0", ">", "-0.5"));
    // Negative numbers and zero spellings.
    CHECK(matches("-3", "<", "-2"));
    CHECK(matches("-3.5", "<", "-3"));
    CHECK(matches("-0.0", ">=", "0"));
    CHECK(matches("-0.0", "<=", "0"));
    CHECK_FALSE(matches("-0.0", ">", "0"));
    CHECK_FALSE(matches("0", "<", "-0"));
    // A stored numeric string orders as a number, not as text ("10" > 9 is true).
    CHECK(matches(R"("10")", ">", "9"));
    CHECK_FALSE(matches(R"("10")", "<", "9"));
    CHECK(matches(R"("1.5")", "<", "10"));
    // A stored value that is not a number never satisfies an ordering against a numeric operand.
    for (const char* op : {">", ">=", "<", "<="}) {
        INFO(op);
        CHECK_FALSE(matches(R"("5 GB")", op, "4"));
        CHECK_FALSE(matches(R"("N/A")", op, "5"));
        CHECK_FALSE(matches(R"("")", op, "5"));
        CHECK_FALSE(matches(R"(" 5")", op, "4"));
        CHECK_FALSE(matches(R"("nan")", op, "5"));
        CHECK_FALSE(matches(R"("1e400")", op, "5"));
        CHECK_FALSE(matches("true", op, "0"));
        CHECK_FALSE(matches("false", op, "-1"));
        CHECK_FALSE(matches("[5]", op, "4"));
        CHECK_FALSE(matches("null", op, "4"));
    }
}

TEST_CASE("InventoryEval: a plain-decimal string operand orders exactly like the JSON number",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    // Run a condition built by parse_inventory_condition (the production path) against one stored
    // value; operand_json is the caller's JSON `value` (a number or a quoted string).
    auto matches = [](const char* stored_json, const char* op, const std::string& operand_json) {
        Records records = {{"agent-a|p", std::string(R"({"v": )") + stored_json + "}"}};
        InventoryEvalRequest req;
        InventoryCondition c;
        const auto doc = json::parse(std::string(R"({"plugin":"p","field":"v","op":")") + op +
                                     R"(","value":)" + operand_json + "}");
        REQUIRE_FALSE(parse_inventory_condition(doc, c));
        req.conditions.push_back(c);
        return !evaluate_inventory(req, records).empty();
    };
    auto quoted = [](const char* n) { return std::string("\"") + n + "\""; };

    // A stored STRING that merely starts with a number keeps the legacy leading-number read
    // (a JSON number operand is strict instead; see the JSON-4 line below).
    CHECK(matches(R"("5 GB")", ">", quoted("4")));
    CHECK_FALSE(matches(R"("5 GB")", "<", quoted("4")));
    CHECK_FALSE(matches(R"("5 GB")", ">", "4"));
    CHECK(matches(R"("1.2.3")", "<", quoted("2.0")));
    CHECK_FALSE(matches(R"("1.2.3")", ">", quoted("2.0")));
    CHECK(matches(R"("10.0.19045")", ">=", quoted("10")));
    // No numeric start (or not a string): never matches, never lexical.
    CHECK_FALSE(matches(R"("N/A")", ">", quoted("5")));
    CHECK_FALSE(matches(R"("")", ">", quoted("5")));
    CHECK_FALSE(matches(R"("v2.1")", ">", quoted("5")));
    CHECK_FALSE(matches(R"("info")", ">", quoted("5")));
    CHECK_FALSE(matches("[5]", ">", quoted("4")));
    CHECK_FALSE(matches(R"({"a":9})", ">", quoted("4")));
    // Digits a 6-decimal rendering used to drop.
    CHECK_FALSE(matches("0.1234567", ">", quoted("0.1234567")));
    CHECK(matches("0.1234567", ">=", quoted("0.1234567")));
    // Exponent forms are plain decimals (from_chars consumes them in full).
    CHECK(matches("3e-7", ">", quoted("2e-7")));
    CHECK_FALSE(matches("3e-7", "<", quoted("2e-7")));
    CHECK(matches("18446744073709551615", ">=", quoted("18446744073709551615")));
    CHECK_FALSE(matches("18446744073709551615", ">", quoted("18446744073709551615")));
    CHECK(matches("9007199254740993", ">", quoted("9007199254740992")));
    // A stored non-number never matches a plain-decimal string operand, not even lexically.
    for (const char* op : {">", ">=", "<", "<="}) {
        INFO(op);
        CHECK_FALSE(matches(R"("N/A")", op, quoted("5")));
        CHECK_FALSE(matches(R"(" 5")", op, quoted("4")));
        CHECK_FALSE(matches("true", op, quoted("0")));
    }

    // The JSON number 4 and the string "4" select the same devices for all four ordering ops.
    const std::vector<std::pair<std::string, std::string>> fixture = {
        {"agent-int", R"({"v": 7})"},
        {"agent-eq", R"({"v": 4})"},
        {"agent-low", R"({"v": 3})"},
        {"agent-float", R"({"v": 4.5})"},
        {"agent-lowfloat", R"({"v": 3.5})"},
        {"agent-numstr", R"({"v": "10"})"},
        {"agent-lownumstr", R"({"v": "2"})"},
        {"agent-bool", R"({"v": true})"},
        {"agent-na", R"({"v": "N/A"})"},
    };
    Records records;
    for (const auto& [id, body] : fixture)
        records.emplace_back(id + "|p", body);
    auto run = [&](const char* op, const char* operand_json) {
        InventoryEvalRequest req;
        InventoryCondition c;
        const auto doc = json::parse(std::string(R"({"plugin":"p","field":"v","op":")") + op +
                                     R"(","value":)" + operand_json + "}");
        REQUIRE_FALSE(parse_inventory_condition(doc, c));
        req.conditions.push_back(c);
        std::vector<std::string> ids;
        for (const auto& r : evaluate_inventory(req, records))
            ids.push_back(r.agent_id);
        std::sort(ids.begin(), ids.end());
        return ids;
    };
    for (const char* op : {">", ">=", "<", "<="}) {
        INFO(op);
        CHECK(run(op, "4") == run(op, "\"4\""));
    }
    // The one deliberate difference: a stored string that only STARTS with a number is read by
    // the string operand (legacy prefix) and refused by the JSON number operand.
    {
        Records prefixed = {{"agent-gb|p", R"({"v": "5 GB"})"}};
        auto count = [&](const char* operand_json) {
            InventoryEvalRequest req;
            InventoryCondition c;
            REQUIRE_FALSE(parse_inventory_condition(
                json::parse(std::string(R"({"plugin":"p","field":"v","op":">","value":)") +
                            operand_json + "}"),
                c));
            req.conditions.push_back(c);
            return evaluate_inventory(req, prefixed).size();
        };
        CHECK(count("\"4\"") == 1);
        CHECK(count("4") == 0);
    }
    using Ids = std::vector<std::string>;
    CHECK(run(">", "\"4\"") == Ids{"agent-float", "agent-int", "agent-numstr"});
    CHECK(run("<=", "\"4\"") ==
          Ids{"agent-eq", "agent-low", "agent-lowfloat", "agent-lownumstr"});

    // == and != keep the exact text compare for a string operand.
    {
        InventoryCondition c;
        REQUIRE_FALSE(parse_inventory_condition(
            json::parse(R"({"plugin":"p","field":"v","op":"==","value":"4"})"), c));
        CHECK_FALSE(c.ordering_numeric);
    }
}

TEST_CASE("InventoryEval: a string operand that is not a plain decimal keeps the legacy ordering",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    auto parsed = [](const char* op, const char* operand) {
        InventoryCondition c;
        const json doc = {{"plugin", "p"}, {"field", "v"}, {"op", op}, {"value", operand}};
        REQUIRE_FALSE(parse_inventory_condition(doc, c));
        return c;
    };
    for (const char* operand : {"abc", "1.2.3", "v2", " 5", "5 GB", "+5", "inf", "nan", "0x10",
                                "5\n", "", "-", "."}) { // "1e400" is refused at admission now
        INFO(operand);
        CHECK_FALSE(parsed(">", operand).ordering_numeric);
    }
    for (const char* operand : {"5", "-5", "5.5", ".5", "3e-7", "1E5", "18446744073709551615",
                                "-9223372036854775808"}) {
        INFO(operand);
        CHECK(parsed(">=", operand).ordering_numeric);
        // Equality never takes the numeric view.
        CHECK_FALSE(parsed("==", operand).ordering_numeric);
        CHECK_FALSE(parsed("!=", operand).ordering_numeric);
    }
    // A non-numeric operand: stored "N/A" still compares lexically ("N/A" > "abc" is false,
    // "N/A" < "abc" is true), exactly as before.
    Records records = {{"agent-a|p", R"({"v": "N/A"})"}};
    auto run = [&](const char* op) {
        InventoryEvalRequest req;
        req.conditions.push_back(parsed(op, "abc"));
        return evaluate_inventory(req, records).size();
    };
    CHECK(run(">") == 0);
    CHECK(run("<") == 1);
    // A version-like operand still uses the legacy numeric-prefix path ("5.9.1" reads as 5.9, the
    // stored "5.10" as 5.1), unchanged.
    Records vrec = {{"agent-a|p", R"({"v": "5.10"})"}};
    InventoryEvalRequest vreq;
    vreq.conditions.push_back(parsed("<", "5.9.1"));
    CHECK(evaluate_inventory(vreq, vrec).size() == 1);
}

TEST_CASE("InventoryEval: a string operand keeps the exact lexical == and !=",
          "[inventory_eval][numeric_params]") {
    Records records = {
        {"agent-a|p", R"({"v": "1.10"})"},
        {"agent-b|p", R"({"v": "1.1"})"},
        {"agent-c|p", R"({"v": 5.5})"},
    };
    auto run = [&](const char* op, const char* operand) {
        InventoryEvalRequest req;
        req.conditions = {{"p", "v", op, operand}};
        std::vector<std::string> ids;
        for (const auto& r : evaluate_inventory(req, records))
            ids.push_back(r.agent_id);
        std::sort(ids.begin(), ids.end());
        return ids;
    };
    using Ids = std::vector<std::string>;
    CHECK(run("==", "1.1") == Ids{"agent-b"});
    CHECK(run("==", "1.10") == Ids{"agent-a"});
    CHECK(run("!=", "1.1") == Ids{"agent-a", "agent-c"});
    // A string operand is NOT numeric: "5.5" does not equal the stored float's "5.500000".
    CHECK(run("==", "5.5") == Ids{});
}

TEST_CASE("InventoryEval: parse_inventory_condition refuses what used to become the empty string",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    for (const char* bad :
         {R"({"op":">","value":null})", R"({"op":">","value":[]})", R"({"op":">","value":{}})",
          R"({"op":">","value":true})", R"({"op":"<=","value":false})",
          R"({"op":"contains","value":5})", R"({"op":"exists","value":5})",
          R"({"op":"version_gte","value":5})", R"({"value":5})", R"({"op":5,"value":"x"})",
          R"({"op":null})", R"({"plugin":5})", R"({"field":["f"]})", R"({"field":{}})"}) {
        INFO(bad);
        InventoryCondition c;
        const auto err = parse_inventory_condition(json::parse(bad), c);
        REQUIRE(err.has_value());
        CHECK(err->find("conditions[]") != std::string::npos);
    }
    InventoryCondition c;
    CHECK(parse_inventory_condition(json::parse("5"), c).has_value());
}

// A decimal operand a double cannot hold exactly (CDX-P1-01): a JSON float arrives already rounded
// (9007199254740993.0 is 2^53 by the time the evaluator sees it), so stored 9007199254740993
// `> 9007199254740993.0` matched while `==` / `<=` did not. Refused at admission instead.
TEST_CASE("InventoryEval: a decimal operand of 2^53 or more is refused at admission",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    const char* const ops[] = {"==", "!=", ">", ">=", "<", "<="};
    auto admit = [](const char* op, const std::string& operand_json) {
        InventoryCondition c;
        return parse_inventory_condition(json::parse(std::string(R"({"plugin":"p","field":"v","op":")") +
                                                     op + R"(","value":)" + operand_json + "}"),
                                         c);
    };
    // JSON floats (the reproduced case first), and exponent forms and ns-scale values, every op.
    for (const char* operand : {"9007199254740993.0", "9007199254740992.0", "-9007199254740993.0",
                                "9.007199254740993e15", "1e16", "1e300", "-1e300",
                                "1700000000000000000.5", "18446744073709551616.0",
                                "100000000000000000000"}) {
        for (const char* op : ops) {
            INFO(op << " " << operand);
            const auto err = admit(op, operand);
            REQUIRE(err.has_value());
            CHECK(err->find("15 significant digits") != std::string::npos);
        }
    }
    // A string operand is read only under the ordering operators; a fraction or exponent form of
    // 2^53 or more is refused there too (== / != with a string stay an exact text compare).
    for (const char* operand : {"\"9007199254740993.5\"", "\"9.007199254740993e15\"", "\"1e16\"",
                                "\"1e300\"", "\"-9007199254740993.5\"",
                                "\"18446744073709551616.0\"", "\"100000000000000000000\""}) {
        for (const char* op : {">", ">=", "<", "<="}) {
            INFO(op << " " << operand);
            const auto err = admit(op, operand);
            REQUIRE(err.has_value());
            CHECK(err->find("15 significant digits") != std::string::npos);
        }
        for (const char* op : {"==", "!="})
            CHECK_FALSE(admit(op, operand).has_value());
    }
    // Accepted: 2^53 and larger WHOLE numbers as integers, small decimals, and exact fractions.
    for (const char* operand : {"9007199254740992", "9007199254740993", "-9007199254740993",
                                "18446744073709551615", "-9223372036854775808", "0.1234567", "5.5",
                                "1e3", "-1e-7", "0", "-0.0"}) {
        for (const char* op : ops) {
            INFO(op << " " << operand);
            CHECK_FALSE(admit(op, operand).has_value());
        }
    }
    for (const char* operand : {"\"9007199254740992\"", "\"0.1234567\"", "\"5.5\"", "\"2e-7\"",
                                "\"9007199254740991.0\""}) {
        for (const char* op : {">", ">=", "<", "<="}) {
            INFO(op << " " << operand);
            CHECK_FALSE(admit(op, operand).has_value());
        }
    }
}

// Gate 8 round 13 (F1/F2): a decimal operand that is not reduced to an exact integer must survive
// the round trip through a double, i.e. have at most 15 significant digits (DBL_DIG), or rounding
// can move it across a stored neighbour even below 2^53; and a plain-decimal STRING outside the
// double range must be refused, not left to a lexical compare (stored 5 satisfied > "1e400").
TEST_CASE("InventoryEval: a decimal operand is admitted only with at most 15 significant digits "
          "and within the double range",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    const char* const ops[] = {"==", "!=", ">", ">=", "<", "<="};
    const char* const ordering[] = {">", ">=", "<", "<="};
    auto admit = [](const char* op, const std::string& operand_json, InventoryCondition& c) {
        return parse_inventory_condition(
            json::parse(std::string(R"({"plugin":"p","field":"v","op":")") + op +
                        R"(","value":)" + operand_json + "}"),
            c);
    };
    auto quoted = [](const std::string& s) { return "\"" + s + "\""; };
    const std::string long_int(400, '9');
    using Strs = std::vector<std::string>;

    SECTION("a JSON float is refused when its shortest round-trip text has over 15 digits") {
        for (const std::string& operand :
             Strs{"123456789012345.6",  // 16 digits
                  "1234567890123456.7", // 17 digits
                  "0.1234567890123456", // 16 digits
                  "4503599627370497.3", "4503599627370497.5", "0.30000000000000004",
                  "9007199254740991.0"}) { // its text has 16 digits (a string spelling is exact)
            for (const char* op : ops) {
                INFO(op << " " << operand);
                InventoryCondition c;
                const auto err = admit(op, operand, c);
                REQUIRE(err.has_value());
                CHECK(err->find("15 significant digits") != std::string::npos);
            }
        }
    }

    SECTION("a string operand under an ordering operator: over-long or out-of-range is refused") {
        for (const std::string& operand :
             Strs{quoted("123456789012345.6"), quoted("1234567890123456.7"),
                  quoted("5.00000000000000001"), quoted("0.1234567890123456"),
                  quoted("4503599627370497.3"), quoted("4503599627370497.5"),
                  quoted("1e400"), quoted("-1e400"), quoted("1e-400"), quoted("-1e-400"),
                  quoted(long_int), quoted("-" + long_int), quoted(long_int + ".5"),
                  quoted("18446744073709551616")}) {
            for (const char* op : ordering) {
                INFO(op << " " << operand.substr(0, 40));
                InventoryCondition c;
                const auto err = admit(op, operand, c);
                REQUIRE(err.has_value());
                CHECK(err->find("15 significant digits") != std::string::npos);
            }
            for (const char* op : {"==", "!="}) { // an exact text compare, never read as a number
                InventoryCondition c;
                CHECK_FALSE(admit(op, operand, c).has_value());
            }
        }
        // The shape check is not widened: a non-plain-decimal string keeps the legacy read.
        for (const std::string& operand : Strs{quoted("1e400x"), quoted("1.2.3"), quoted("5 GB")}) {
            InventoryCondition c;
            CHECK_FALSE(admit(">", operand, c).has_value());
        }
    }

    SECTION("a JSON integer beyond uint64 names the integer range") {
        InventoryCondition c;
        const auto err = admit(">", "18446744073709551616", c);
        REQUIRE(err.has_value());
        CHECK(err->find("18446744073709551615") != std::string::npos);
    }

    SECTION("admitted: 15 digits or fewer, exact integers of any int64/uint64 size") {
        for (const std::string& operand :
             Strs{"12345678901234.5", "0.123456789012345", "0.1234567", "5.5", "0.1", "1e3",
                  "-1e-7", "1.5e10", "-0.0", "0", "0.000000123456789012345",
                  "9007199254740992", "9007199254740993", "-9007199254740993",
                  "9223372036854775807", "-9223372036854775808", "18446744073709551615"}) {
            for (const char* op : ops) {
                INFO(op << " " << operand);
                InventoryCondition c;
                CHECK_FALSE(admit(op, operand, c).has_value());
            }
        }
        for (const std::string& operand :
             Strs{quoted("12345678901234.5"), quoted("0.123456789012345"), quoted("5.5"),
                  quoted("1e3"), quoted("2e-7"), quoted("0.1"), quoted("9007199254740993"),
                  quoted("18446744073709551615"),
                  // a zero fraction is reduced to the exact integer BEFORE the digit rule
                  quoted("9007199254740993.0"), quoted("-9007199254740993.00"),
                  quoted("1234567890123456789.0")}) {
            for (const char* op : ordering) {
                INFO(op << " " << operand);
                InventoryCondition c;
                CHECK_FALSE(admit(op, operand, c).has_value());
            }
        }
    }

    SECTION("what is admitted is what is compared") {
        InventoryCondition c;
        REQUIRE_FALSE(admit(">", quoted("9007199254740993.0"), c).has_value());
        CHECK(std::holds_alternative<std::int64_t>(c.numeric_value));
        CHECK(std::get<std::int64_t>(c.numeric_value) == 9007199254740993LL);
        InventoryCondition d;
        REQUIRE_FALSE(admit(">", "1e3", d).has_value());
        REQUIRE(std::holds_alternative<double>(d.numeric_value));
        CHECK(std::get<double>(d.numeric_value) == 1000.0);
        InventoryCondition e;
        REQUIRE_FALSE(admit(">", quoted("1e3"), e).has_value());
        REQUIRE(std::holds_alternative<double>(e.numeric_value));
        CHECK(std::get<double>(e.numeric_value) == 1000.0);
    }
}

// A whole-number decimal string above 2^53 is read as the exact integer, so the comparison is
// exact where the old double rounding was not.
TEST_CASE("InventoryEval: a whole-number decimal string reads as the exact integer",
          "[inventory_eval][numeric_params]") {
    using nlohmann::json;
    auto matches = [](const char* stored_json, const char* op, const char* operand_json) {
        Records records = {{"agent-a|p", std::string(R"({"v": )") + stored_json + "}"}};
        InventoryEvalRequest req;
        InventoryCondition c;
        const auto doc = json::parse(std::string(R"({"plugin":"p","field":"v","op":")") + op +
                                     R"(","value":)" + operand_json + "}");
        REQUIRE_FALSE(parse_inventory_condition(doc, c));
        req.conditions.push_back(c);
        return !evaluate_inventory(req, records).empty();
    };
    const char* const same = R"("9007199254740993.0")";
    CHECK_FALSE(matches("9007199254740993", ">", same));
    CHECK(matches("9007199254740993", ">=", same));
    CHECK(matches("9007199254740993", "<=", same));
    CHECK_FALSE(matches("9007199254740993", "<", same));
    CHECK(matches("9007199254740994", ">", same));
    CHECK(matches("9007199254740992", "<", same));
    CHECK(matches("5", ">=", R"("5.00")"));
    CHECK_FALSE(matches("5", ">", R"("5.00")"));
    CHECK(matches("-5", "<=", R"("-5.0")"));
    // A stored numeric string spelled with a zero fraction is the exact integer as well.
    CHECK(matches(R"("9007199254740993.0")", ">=", "9007199254740993"));
    CHECK_FALSE(matches(R"("9007199254740993.0")", ">", "9007199254740993"));
    CHECK(matches(R"("9007199254740993.0")", ">", "9007199254740992"));
}

// legacy_leading_number_text is the shared guard in front of the std::stod fallback (Apple Clang),
// which accepts leading whitespace and hex where std::from_chars does not (K2).
TEST_CASE("InventoryEval: the legacy leading-number read refuses whitespace and hex like from_chars",
          "[inventory_eval][numeric_params]") {
    CHECK_FALSE(legacy_leading_number_text(" 10").has_value());
    CHECK_FALSE(legacy_leading_number_text("\t10").has_value());
    CHECK_FALSE(legacy_leading_number_text("\n10").has_value());
    CHECK_FALSE(legacy_leading_number_text("+5").has_value());
    CHECK(legacy_leading_number_text("0x10") == std::string_view("0"));
    CHECK(legacy_leading_number_text("0X1F") == std::string_view("0"));
    CHECK(legacy_leading_number_text("-0x10") == std::string_view("-0"));
    CHECK(legacy_leading_number_text("0") == std::string_view("0"));
    CHECK(legacy_leading_number_text("10") == std::string_view("10"));
    CHECK(legacy_leading_number_text("1.2.3") == std::string_view("1.2.3"));
    CHECK(legacy_leading_number_text("5 GB") == std::string_view("5 GB"));
    CHECK(legacy_leading_number_text("5x") == std::string_view("5x"));
    CHECK(legacy_leading_number_text("-") == std::string_view("-"));
    CHECK(legacy_leading_number_text("").value() == std::string_view(""));

    // End to end on the legacy ordering path (a non-plain-decimal string operand): the same answer
    // on every platform. " 10" < " 9" is a TEXT compare (neither side starts a number) and
    // "0x10" < "0x9" reads 0 against 0.
    auto lt = [](const char* stored, const char* operand) {
        Records records = {{"agent-a|p", std::string(R"({"v": ")") + stored + R"("})"}};
        InventoryEvalRequest req;
        req.conditions = {{"p", "v", "<", operand}};
        return !evaluate_inventory(req, records).empty();
    };
    CHECK(lt(" 10", " 9"));
    CHECK_FALSE(lt("0x10", "0x9"));
    CHECK_FALSE(lt("0x9", "0x10"));
}
