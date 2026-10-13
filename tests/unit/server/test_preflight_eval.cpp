/**
 * test_preflight_eval.cpp — coverage for the Slice-2 eval glue
 * (server/core/src/preflight_eval.{hpp,cpp}): the JSON (de)serialization that
 * crosses the run-store boundary, the per-check execution-id correlation key, and
 * the applicable-checks selection. These are the contracts the routes (live
 * render) and the runner (persist) both depend on, so a round-trip break here
 * fails the test instead of silently corrupting a stored or revisited run.
 */

#include "preflight_eval.hpp"
#include "preflight_parse.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server::preflight;

TEST_CASE("config_to_json / config_from_json round-trip", "[preflight][eval]") {
    PreflightConfig c;
    c.app_name = "AcmeVPN";
    c.app_min_version = "4.2.0";
    c.app_max_version = "4.9.99";
    c.os_min_version = "10.0.19045";
    c.req_arch = "x86_64";
    c.min_free_gib = 20;
    c.volume = "C:\\";
    c.reboot_block = false;

    auto back = config_from_json(config_to_json(c));
    CHECK(back.app_name == "AcmeVPN");
    CHECK(back.app_min_version == "4.2.0");
    CHECK(back.app_max_version == "4.9.99");
    CHECK(back.os_min_version == "10.0.19045");
    CHECK(back.req_arch == "x86_64");
    CHECK(back.min_free_gib == 20);
    CHECK(back.volume == "C:\\");
    CHECK(back.reboot_block == false);
}

TEST_CASE("config_from_json tolerates garbage", "[preflight][eval]") {
    auto c = config_from_json("not json {{{");
    CHECK(c.app_name.empty());
    CHECK(c.reboot_block == true); // default
    auto c2 = config_from_json("[]"); // wrong shape
    CHECK(c2.app_name.empty());
}

TEST_CASE("checks_to_json / checks_from_json round-trip", "[preflight][eval]") {
    std::vector<PreflightDeviceCheck> checks = {
        {"app", "Target application", Verdict::kFail, "4.1.0"},
        {"osver", "OS version", Verdict::kPass, "10.0.22631"},
        {"reboot", "Pending reboot", Verdict::kWarn, "Pending"},
        {"disk", "Free disk", Verdict::kUnknown, ""},
    };
    auto back = checks_from_json(checks_to_json(checks));
    REQUIRE(back.size() == 4);
    CHECK(back[0].key == "app");
    CHECK(back[0].verdict == Verdict::kFail);
    CHECK(back[0].value == "4.1.0");
    CHECK(back[1].verdict == Verdict::kPass);
    CHECK(back[2].verdict == Verdict::kWarn);
    CHECK(back[2].value == "Pending");
    CHECK(back[3].verdict == Verdict::kUnknown);
    CHECK(back[3].value.empty());
}

TEST_CASE("checks_to_json never throws on odd bytes", "[preflight][eval]") {
    // Agent-derived values can carry invalid UTF-8 — the replace error-handler
    // must keep dump() from throwing (else a persist would lose the whole grid).
    std::vector<PreflightDeviceCheck> checks = {
        {"app", "App", Verdict::kFail, std::string("bad\xff\xfe""byte")},
    };
    std::string j;
    REQUIRE_NOTHROW(j = checks_to_json(checks));
    CHECK_FALSE(j.empty());
    auto back = checks_from_json(j); // still parses
    REQUIRE(back.size() == 1);
    CHECK(back[0].verdict == Verdict::kFail);
}

TEST_CASE("checks_from_json tolerates garbage", "[preflight][eval]") {
    CHECK(checks_from_json("garbage").empty());
    CHECK(checks_from_json("{}").empty()); // object, not array
}

TEST_CASE("checks_from_json clamps out-of-range verdict + survives wrong types", "[preflight][eval]") {
    // out-of-range verdict ints clamp to kUnknown (#governance quality S-1).
    auto over = checks_from_json(R"([{"key":"app","label":"App","v":99,"val":""}])");
    REQUIRE(over.size() == 1);
    CHECK(over[0].verdict == Verdict::kUnknown);
    auto under = checks_from_json(R"([{"key":"app","label":"App","v":-1,"val":""}])");
    REQUIRE(under.size() == 1);
    CHECK(under[0].verdict == Verdict::kUnknown);
    // a wrong-typed key (v as a string) must NOT throw — the element is dropped, not
    // a 500 (#governance cpp-expert: nlohmann .value() type_error guard).
    std::vector<PreflightDeviceCheck> bad;
    REQUIRE_NOTHROW(bad = checks_from_json(R"([{"key":"app","v":"notanint","val":""}])"));
    CHECK(bad.empty());
}

TEST_CASE("config_from_json survives wrong-typed key", "[preflight][eval]") {
    // min_gib as a string must not throw — degrade to defaults.
    PreflightConfig c;
    REQUIRE_NOTHROW(c = config_from_json(R"({"app_name":"X","min_gib":"oops"})"));
    CHECK(c.reboot_block == true); // default-shaped (degraded)
}

TEST_CASE("check_execution_id format", "[preflight][eval]") {
    CHECK(check_execution_id("abc123", "disk") == "preflight-abc123-disk");
    CHECK(check_execution_id("abc123", "osver") == "preflight-abc123-osver");
}

TEST_CASE("applicable_checks gates the app check on a name", "[preflight][eval]") {
    PreflightConfig c; // no app_name
    auto none = applicable_checks(c);
    CHECK(none.size() == 4); // osver, osarch, disk, reboot — no app
    for (const auto& [key, label] : none)
        CHECK(key != "app");

    c.app_name = "AcmeVPN";
    auto with_app = applicable_checks(c);
    CHECK(with_app.size() == 5);
    CHECK(with_app.front().first == "app"); // catalogue order
}

TEST_CASE("dispatch_params per check", "[preflight][eval]") {
    PreflightConfig c;
    c.app_name = "AcmeVPN";
    c.volume = "C:\\";
    CHECK(dispatch_params("app", c).at("name") == "AcmeVPN");
    CHECK(dispatch_params("disk", c).at("path") == "C:\\");
    CHECK(dispatch_params("osver", c).empty());
    c.volume.clear();
    CHECK(dispatch_params("disk", c).empty()); // no path when no volume
}

TEST_CASE("bucket_token / bucket_from_token round-trip", "[preflight][eval]") {
    for (Bucket b : {Bucket::kPass, Bucket::kFailed, Bucket::kWarnOnly, Bucket::kIncomplete})
        CHECK(bucket_from_token(bucket_token(b)) == b);
    CHECK(bucket_from_token("garbage") == Bucket::kIncomplete); // safe default
}

// #4644: a cell with no response in a TRUNCATED fetch window is ambiguous, never a pass.
TEST_CASE("compute_device_results labels an absent agent in a truncated window inconclusive",
          "[preflight][eval][numeric_params]") {
    PreflightCheckResponses c;
    c.key = "disk";
    c.label = "Disk";
    c.by_agent["agent-2"] = {1, "ok"};
    std::vector<PreflightTarget> targets = {{"agent-1", "h1", "windows"}, {"agent-2", "h2", "windows"}};
    PreflightConfig cfg;

    for (const bool truncated : {false, true}) {
        c.truncated = truncated;
        bool any_pending = false;
        const auto grid = compute_device_results(targets, {c}, cfg, &any_pending);
        REQUIRE(grid.size() == 2);
        const auto& cell = grid[0].checks[0]; // agent-1: no response either way
        CHECK(cell.verdict == Verdict::kUnknown);
        CHECK(grid[0].bucket == Bucket::kIncomplete);
        CHECK(any_pending);
        CHECK((cell.value == std::string(kPreflightCapReachedValue)) == truncated);
    }
}

// A device whose RUNNING row IS in the truncated window is simply still pending: only a device
// with NO row at all is ambiguous (its answer may have been evicted), so only it is labelled.
TEST_CASE("compute_device_results does not label a device whose running row is in the window",
          "[preflight][eval][numeric_params]") {
    PreflightCheckResponses c;
    c.key = "disk";
    c.label = "Disk";
    c.truncated = true;
    c.by_agent["agent-1"] = {0, ""}; // RUNNING, no output yet
    std::vector<PreflightTarget> targets = {{"agent-1", "h1", "windows"}, {"agent-2", "h2", "windows"}};
    PreflightConfig cfg;
    bool any_pending = false;
    const auto grid = compute_device_results(targets, {c}, cfg, &any_pending);
    REQUIRE(grid.size() == 2);
    CHECK(any_pending);
    CHECK(grid[0].checks[0].value != std::string(kPreflightCapReachedValue)); // running, in window
    CHECK(grid[1].checks[0].value == std::string(kPreflightCapReachedValue)); // absent: ambiguous
    CHECK(grid[0].checks[0].verdict == Verdict::kUnknown);
    CHECK(grid[1].checks[0].verdict == Verdict::kUnknown);
}
