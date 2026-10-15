/**
 * test_bundle_service.cpp — server-side live-query bundle core (ADR-0011).
 *
 * Pure pieces only: step-list validation and the collate/aggregate that matches
 * response rows to the dispatched-step map by command_id. No DB. The dispatch
 * fan-out + persistence + REST/MCP wiring are exercised at the integration/UAT
 * layer.
 */

#include "bundle_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

// ── validate_bundle_steps ────────────────────────────────────────────────────

TEST_CASE("validate_bundle_steps accepts valid steps and lower-cases", "[bundle][validate]") {
    auto r = validate_bundle_steps(
        R"([{"plugin":"OS_Info","action":"UpTime"},{"plugin":"hardware","action":"memory","params":{"k":"v"}}])");
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 2);
    CHECK((*r)[0].plugin == "os_info");
    CHECK((*r)[0].action == "uptime");
    CHECK((*r)[1].plugin == "hardware");
    REQUIRE((*r)[1].params.size() == 1);
    CHECK((*r)[1].params[0].first == "k");
    CHECK((*r)[1].params[0].second == "v");
}

TEST_CASE("validate_bundle_steps coerces non-string param values", "[bundle][validate]") {
    auto r = validate_bundle_steps(R"([{"plugin":"p","action":"a","params":{"n":42,"b":true}}])");
    REQUIRE(r.has_value());
    REQUIRE((*r)[0].params.size() == 2);
    auto find = [&](const std::string& k) {
        for (const auto& [pk, pv] : (*r)[0].params)
            if (pk == k) return pv;
        return std::string("<missing>");
    };
    CHECK(find("n") == "42");
    CHECK(find("b") == "true");
}

TEST_CASE("validate_bundle_steps rejects malformed / unsafe steps", "[bundle][validate][unhappy]") {
    CHECK_FALSE(validate_bundle_steps("not json").has_value());
    CHECK_FALSE(validate_bundle_steps(R"({"plugin":"p","action":"a"})").has_value()); // object
    CHECK_FALSE(validate_bundle_steps("[]").has_value());                              // empty
    CHECK_FALSE(validate_bundle_steps(R"([{"action":"a"}])").has_value());             // no plugin
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p"}])").has_value());             // no action
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":2,"action":"a"}])").has_value());  // plugin !str
    // identifier safety (audit-verb injection attempts)
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p p","action":"a"}])").has_value());
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p","action":"a\nx"}])").has_value());
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p","action":"a","params":[]}])").has_value());
}

TEST_CASE("validate_bundle_steps allows duplicate (plugin,action) in request order",
          "[bundle][validate]") {
    // ADR-0011 §61-64 + governance review #1593 blocker 2: duplicate
    // (plugin,action) is DELIBERATELY allowed — each step gets its own command_id
    // and the ordered step map demuxes them (e.g. two registry reads with
    // different params on one device). The validator must NOT reject them.
    auto dup = validate_bundle_steps(
        R"([{"plugin":"registry","action":"get_value","params":{"path":"A"}},)"
        R"({"plugin":"registry","action":"get_value","params":{"path":"B"}}])");
    REQUIRE(dup.has_value());
    REQUIRE(dup->size() == 2);
    CHECK((*dup)[0].params[0].second == "A"); // request order preserved
    CHECK((*dup)[1].params[0].second == "B");
    // exact duplicate (same params) is also allowed — just redundant
    CHECK(validate_bundle_steps(
              R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"uptime"}])")
              .has_value());
    // same plugin, different action still fine
    auto ok = validate_bundle_steps(
        R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}])");
    REQUIRE(ok.has_value());
    CHECK(ok->size() == 2);
}

// json-dump-depth-guard fix (#2437-class): validate_bundle_steps has its OWN
// raw-text depth check, independent of the REST /api/v1/bundles caller's
// guard - this is the function's OWN falsifier, so the two guards cannot
// mask each other in a single combined test. depth 40 is trivially safe to
// build/dump directly in this test process; the real attack depth this guard
// exists for is many orders of magnitude higher (~100,000 levels).
TEST_CASE("validate_bundle_steps rejects a params value nested past the depth limit, "
          "before its own parse",
          "[bundle][validate][security][depth]") {
    const std::string deep_array = std::string(40, '[') + std::string(40, ']');
    const std::string steps =
        R"([{"plugin":"p","action":"a","params":{"deep":)" + deep_array + "}}]";
    auto r = validate_bundle_steps(steps);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("nests too deeply") != std::string::npos);
}

TEST_CASE("validate_bundle_steps enforces the step cap", "[bundle][validate][unhappy]") {
    std::string over = "[";
    for (std::size_t i = 0; i < kMaxBundleSteps + 1; ++i) {
        if (i) over += ',';
        over += R"({"plugin":"p","action":"a)" + std::to_string(i) + R"("})"; // distinct actions
    }
    over += "]";
    CHECK_FALSE(validate_bundle_steps(over).has_value());
}

// ── aggregate_bundle ─────────────────────────────────────────────────────────

namespace {
DispatchedStep step(std::string cmd, std::string plugin, std::string action) {
    return DispatchedStep{std::move(cmd), std::move(plugin), std::move(action)};
}
BundleResponseRow row(std::string cmd, int status, std::string out) {
    return BundleResponseRow{std::move(cmd), status, std::move(out)};
}
} // namespace

TEST_CASE("aggregate_bundle: all responded → complete, request order preserved", "[bundle][collate]") {
    std::vector<DispatchedStep> steps{step("c1", "os_info", "uptime"),
                                      step("c2", "os_info", "os_name")};
    std::vector<BundleResponseRow> rows{row("c2", 1, "os_name|Win"), row("c1", 1, "up 3d")};
    auto agg = aggregate_bundle(steps, rows);
    CHECK(agg.complete);
    CHECK(agg.received == 2);
    CHECK(agg.expected == 2);
    REQUIRE(agg.steps.size() == 2);
    // request order, not row arrival order
    CHECK(agg.steps[0].action == "uptime");
    CHECK(agg.steps[0].output == "up 3d");
    CHECK(agg.steps[1].action == "os_name");
    CHECK(agg.steps[1].output == "os_name|Win");
}

TEST_CASE("aggregate_bundle: a missing response is Pending → not complete", "[bundle][collate]") {
    std::vector<DispatchedStep> steps{step("c1", "a", "x"), step("c2", "b", "y")};
    std::vector<BundleResponseRow> rows{row("c1", 1, "o1")};
    auto agg = aggregate_bundle(steps, rows);
    CHECK_FALSE(agg.complete);
    CHECK(agg.received == 1);
    CHECK(agg.steps[0].state == BundleStepState::Responded);
    CHECK(agg.steps[1].state == BundleStepState::Pending);
}

TEST_CASE("aggregate_bundle: dispatch-failed step is terminal, not pending-forever", "[bundle][collate]") {
    // c2 never dispatched (empty command_id) → DispatchFailed; with c1 responded
    // and nothing Pending, the bundle is complete.
    std::vector<DispatchedStep> steps{step("c1", "a", "x"), step("", "b", "y")};
    std::vector<BundleResponseRow> rows{row("c1", 1, "o1")};
    auto agg = aggregate_bundle(steps, rows);
    CHECK(agg.steps[1].state == BundleStepState::DispatchFailed);
    CHECK(agg.received == 1);
    CHECK(agg.complete); // dispatch-failed doesn't hold it open
}

TEST_CASE("aggregate_to_json carries flags + per-step state tokens", "[bundle][collate]") {
    std::vector<DispatchedStep> steps{step("c1", "os_info", "uptime"), step("c2", "proc", "list"),
                                      step("", "rdp_control", "status")};
    std::vector<BundleResponseRow> rows{row("c1", 1, "up")};
    auto agg = aggregate_bundle(steps, rows);
    auto j = nlohmann::json::parse(aggregate_to_json(agg));
    CHECK(j.at("complete") == false); // c2 pending
    CHECK(j.at("received") == 1);
    CHECK(j.at("expected") == 3);
    REQUIRE(j.at("steps").size() == 3);
    CHECK(j["steps"][0].at("state") == "responded");
    CHECK(j["steps"][0].at("output") == "up");
    CHECK(j["steps"][1].at("state") == "pending");
    CHECK(j["steps"][2].at("state") == "dispatch_failed");
    CHECK(j["steps"][2].at("plugin") == "rdp_control");
}

// ── Gate-7 governance hardening regressions ─────────────────────────────────

TEST_CASE("aggregate_bundle: a terminal frame wins over a RUNNING frame, any row order",
          "[bundle][service]") {
    // governance cppx-S1 / CH-5: query_by_execution returns rows timestamp-DESC,
    // but BundleResponseRow has no timestamp — so the aggregator must pick the
    // TERMINAL frame status-aware, not order-aware. Assert both orders.
    std::vector<DispatchedStep> steps{{"cmd-a", "os_info", "uptime"}};
    for (bool running_first : {true, false}) {
        std::vector<BundleResponseRow> rows;
        if (running_first) {
            rows.push_back({"cmd-a", 0, "running"}); // RUNNING (status 0)
            rows.push_back({"cmd-a", 1, "up 3d"});   // terminal SUCCESS
        } else {
            rows.push_back({"cmd-a", 1, "up 3d"});
            rows.push_back({"cmd-a", 0, "running"});
        }
        auto agg = aggregate_bundle(steps, rows);
        REQUIRE(agg.steps.size() == 1);
        CHECK(agg.steps[0].status == 1);       // terminal, never the RUNNING 0
        CHECK(agg.steps[0].output == "up 3d");
        CHECK(agg.received == 1);
        CHECK(agg.succeeded == 1);
        CHECK(agg.complete);
    }
}

TEST_CASE("aggregate_bundle: succeeded counts only SUCCESS; complete is not success",
          "[bundle][service]") {
    // governance ER-2 / UP-2 / CH-8.
    std::vector<DispatchedStep> steps{
        {"cmd-ok", "os_info", "uptime"},
        {"cmd-fail", "os_info", "os_name"},
        {std::string{}, "svc", "restart"}, // dispatch-failed (empty command_id)
    };
    std::vector<BundleResponseRow> rows{
        {"cmd-ok", 1, "good"},
        {"cmd-fail", 2, "boom"}, // FAILURE — responded but not succeeded
    };
    auto agg = aggregate_bundle(steps, rows);
    CHECK(agg.expected == 3);
    CHECK(agg.received == 2);  // ok + fail both responded
    CHECK(agg.succeeded == 1); // only the SUCCESS
    CHECK(agg.complete);       // all terminal (2 responded + 1 dispatch-failed)
    CHECK(agg.steps[2].state == BundleStepState::DispatchFailed);
}

TEST_CASE("aggregate_bundle: all-dispatch-failed completes with received=0, succeeded=0",
          "[bundle][service]") {
    std::vector<DispatchedStep> steps{{std::string{}, "p", "a"}, {std::string{}, "p", "b"}};
    auto agg = aggregate_bundle(steps, {});
    CHECK(agg.complete);        // terminal, but NOT success
    CHECK(agg.received == 0);
    CHECK(agg.succeeded == 0);
}

TEST_CASE("aggregate_bundle: a response row matching no step is ignored", "[bundle][service]") {
    // governance QE-N1: a stray command_id must not inflate received / complete.
    std::vector<DispatchedStep> steps{{"cmd-a", "os_info", "uptime"}};
    std::vector<BundleResponseRow> rows{
        {"cmd-a", 1, "up"},
        {"cmd-orphan", 1, "stray"}, // no dispatched step owns this command_id
    };
    auto agg = aggregate_bundle(steps, rows);
    CHECK(agg.received == 1); // not 2
    CHECK(agg.succeeded == 1);
    CHECK(agg.complete);
}

TEST_CASE("validate_bundle_steps: bounds param payload (UP-7)", "[bundle][service][unhappy]") {
    // Oversized value rejected.
    const std::string big(kMaxParamValueLen + 1, 'x');
    const std::string over_value =
        R"([{"plugin":"os_info","action":"uptime","params":{"k":")" + big + R"("}}])";
    CHECK_FALSE(validate_bundle_steps(over_value).has_value());

    // Too many params rejected.
    std::string params;
    for (std::size_t i = 0; i <= kMaxParamCountPerStep; ++i)
        params += (i ? "," : "") + ("\"k" + std::to_string(i) + "\":\"v\"");
    const std::string over_count =
        R"([{"plugin":"os_info","action":"uptime","params":{)" + params + R"(}}])";
    CHECK_FALSE(validate_bundle_steps(over_count).has_value());

    // A normal small param still passes.
    CHECK(validate_bundle_steps(
              R"([{"plugin":"os_info","action":"uptime","params":{"k":"v"}}])")
              .has_value());
}

// ── Governance review #1593 regressions ─────────────────────────────────────

TEST_CASE("aggregate_to_json tolerates non-UTF-8 plugin output (no throw)", "[bundle][collate]") {
    // Blocker 1: plugin output is untrusted and may not be valid UTF-8 (binary,
    // a non-UTF-8 codepage). The default strict dump() THROWS type_error.316 on
    // an invalid byte → the bundle becomes permanently uncollatable. The replace
    // handler must substitute U+FFFD so collate always serializes.
    std::vector<DispatchedStep> steps{step("cmd-a", "files", "read")};
    std::vector<BundleResponseRow> rows{{"cmd-a", 1, std::string(1, '\xff') + "raw"}};
    std::string out;
    REQUIRE_NOTHROW(out = aggregate_to_json(aggregate_bundle(steps, rows)));
    auto j = nlohmann::json::parse(out); // must be valid, parseable JSON
    CHECK(j["steps"][0]["state"] == "responded");
    CHECK(j["received"] == 1);
    // The invalid byte must be REPLACED with U+FFFD (EF BF BD), not dropped —
    // guards against a future regression that silently omits the output instead.
    CHECK(out.find("\xef\xbf\xbd") != std::string::npos);
}

TEST_CASE("aggregate_to_json: a non-UTF-8 step does not corrupt a valid sibling step",
          "[bundle][collate]") {
    // governance re-review QE SHOULD: in a mixed bundle the replace substitution
    // is confined to the offending step; the valid step + counts are intact.
    std::vector<DispatchedStep> steps{step("cmd-bad", "files", "read"),
                                      step("cmd-ok", "os_info", "os_name")};
    std::vector<BundleResponseRow> rows{{"cmd-bad", 1, std::string(1, '\xff') + "bin"},
                                        {"cmd-ok", 1, "Windows 11"}};
    auto j = nlohmann::json::parse(aggregate_to_json(aggregate_bundle(steps, rows)));
    CHECK(j["received"] == 2);
    CHECK(j["succeeded"] == 2);
    CHECK(j["steps"][1]["output"] == "Windows 11"); // valid sibling untouched
    CHECK(j["steps"][0]["state"] == "responded");
}

TEST_CASE("aggregate_bundle demuxes duplicate (plugin,action) steps by command_id",
          "[bundle][collate]") {
    // Blocker 2: two identical (plugin,action) steps (different params) must
    // collate to distinct results in request order, keyed by their command_ids.
    std::vector<DispatchedStep> steps{step("cmd-1", "registry", "get_value"),
                                      step("cmd-2", "registry", "get_value")};
    std::vector<BundleResponseRow> rows{{"cmd-2", 1, "valB"}, {"cmd-1", 1, "valA"}}; // arrival order
    auto agg = aggregate_bundle(steps, rows);
    REQUIRE(agg.steps.size() == 2);
    CHECK(agg.steps[0].output == "valA"); // request order, demuxed by command_id
    CHECK(agg.steps[1].output == "valB");
    CHECK(agg.received == 2);
}
