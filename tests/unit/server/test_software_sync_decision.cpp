/**
 * test_software_sync_decision.cpp — fixture vectors for the pure decision core behind
 * POST /api/v1/hardware/sync (the Software page's "Sync now" for a device / scope / fleet):
 * the request grammar, the target partition, the fleet-wide rule, the 500-target cap, the
 * per-operator cooldown, and the audit/response wording. No process, clock, registry or
 * store — see software_sync_decision.hpp.
 */

#include "hardware_list_model.hpp" // agent_supports_sync_now: the real 0.13.1 floor
#include "software_sync_decision.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
namespace ss = yuzu::server::software_sync;
using nlohmann::json;

namespace {

ss::Candidate cand(std::string id, std::optional<std::string> v) { return {std::move(id), std::move(v)}; }

bool floor_ok(std::string_view v) { return agent_supports_sync_now(v); }

} // namespace

// ── request grammar ───────────────────────────────────────────────────────────────

TEST_CASE("sync request: each scope spelling lands on exactly one arm", "[server][software_sync]") {
    struct Row {
        const char* body;
        DispatchArm arm;
        const char* expr;
    };
    const Row rows[] = {
        {R"({"scope":"__all__"})", DispatchArm::Broadcast, "__all__"},
        {R"({"scope":"group:finance"})", DispatchArm::Group, "group:finance"},
        {R"({"scope":"host-01"})", DispatchArm::Ids, "host-01"},
        {R"({"scope_expression":"ostype == \"windows\""})", DispatchArm::Scope, R"(ostype == "windows")"},
        // An expression spelled as a group or the broadcast word is the same arm as via `scope`.
        {R"({"scope_expression":"group:finance"})", DispatchArm::Group, "group:finance"},
        {R"({"scope_expression":"__all__"})", DispatchArm::Broadcast, "__all__"},
        {R"({"scope":"__all__","source":"installed_software"})", DispatchArm::Broadcast, "__all__"},
    };
    for (const auto& r : rows) {
        INFO(r.body);
        const auto got = ss::parse_request(json::parse(r.body));
        REQUIRE(got.has_value());
        CHECK(got->arm == r.arm);
        CHECK(got->expr == r.expr);
    }
}

TEST_CASE("sync request: ambiguous, empty or mistyped selectors are refused", "[server][software_sync]") {
    const char* bad[] = {
        R"({})",                                                   // names nothing: never "everyone"
        R"({"scope":""})",                                         // present but empty
        R"({"scope_expression":""})",
        R"({"scope":"host-01","scope_expression":"ostype == \"linux\""})", // alternatives, not a precedence
        R"({"scope":"__all__","scope_expression":"__all__"})",
        R"({"scope":123})",                                        // type error, not a throw
        R"({"scope_expression":["a"]})",
        R"({"scope":null})",
        R"({"scope":"group:"})",                                   // group needs an id
        R"({"scope":"a\nb"})",                                     // control byte in an id
        R"({"scope_expression":"ostype\t== x"})",                  // control byte in an expression
        R"({"scope":"__all__","source":"all"})",                   // only installed_software fans out
        R"({"scope":"__all__","source":"device_ci"})",
        R"({"scope":"__all__","source":5})",
    };
    for (const char* b : bad) {
        INFO(b);
        CHECK_FALSE(ss::parse_request(json::parse(b)).has_value());
    }
    // Not an object at all.
    CHECK_FALSE(ss::parse_request(json::parse("[]")).has_value());
    CHECK_FALSE(ss::parse_request(json::parse("\"__all__\"")).has_value());
    CHECK_FALSE(ss::parse_request(json::parse("{not json", nullptr, false)).has_value()); // discarded
}

TEST_CASE("sync request: id and expression length bounds are inclusive", "[server][software_sync]") {
    const std::string id_ok(ss::kMaxIdLen, 'a'), id_long(ss::kMaxIdLen + 1, 'a');
    const std::string ex_ok(ss::kMaxExpressionLen, 'a'), ex_long(ss::kMaxExpressionLen + 1, 'a');
    CHECK(ss::parse_request(json{{"scope", id_ok}}).has_value());
    CHECK_FALSE(ss::parse_request(json{{"scope", id_long}}).has_value());
    CHECK(ss::parse_request(json{{"scope_expression", ex_ok}}).has_value());
    CHECK_FALSE(ss::parse_request(json{{"scope_expression", ex_long}}).has_value());
}

TEST_CASE("sync request: only a group, scope or fleet run needs the run guard", "[server][software_sync]") {
    CHECK_FALSE(ss::needs_run_guard(DispatchArm::Ids));
    CHECK(ss::needs_run_guard(DispatchArm::Group));
    CHECK(ss::needs_run_guard(DispatchArm::Scope));
    CHECK(ss::needs_run_guard(DispatchArm::Broadcast));
}

// ── partition ─────────────────────────────────────────────────────────────────────

TEST_CASE("sync partition: offline, too-old and unparseable versions are counted, not sent",
          "[server][software_sync]") {
    const std::vector<ss::Candidate> in = {
        cand("a", "0.13.1"),   // exactly the floor
        cand("b", std::nullopt), // no live session
        cand("c", "0.13.0"),   // one patch below
        cand("d", "0.14.0"),
        cand("e", "banana"),   // unparseable: never reachable
        cand("f", "1.0.0"),
        cand("g", std::nullopt),
        cand("h", ""),         // live session that reported nothing
    };
    const auto p = ss::partition(in, floor_ok);
    CHECK(p.targets == std::vector<std::string>{"a", "d", "f"}); // input order preserved
    CHECK(p.counts.requested == 8);
    CHECK(p.counts.reached == 3);
    CHECK(p.counts.skipped_offline == 2);
    CHECK(p.counts.skipped_version == 3);
    CHECK(p.counts.requested ==
          p.counts.reached + p.counts.skipped_offline + p.counts.skipped_version);
}

TEST_CASE("sync partition: nothing in, nothing out", "[server][software_sync]") {
    const auto p = ss::partition({}, floor_ok);
    CHECK(p.targets.empty());
    CHECK(p.counts.requested == 0);
    CHECK(p.counts.reached == 0);
}

TEST_CASE("sync finalize: a refused send moves a target to skipped_offline", "[server][software_sync]") {
    ss::Counts planned{.requested = 10, .reached = 6, .skipped_offline = 3, .skipped_version = 1};
    const auto all = ss::finalize(planned, 6);
    CHECK(all.reached == 6);
    CHECK(all.skipped_offline == 3);
    const auto some = ss::finalize(planned, 4);
    CHECK(some.reached == 4);
    CHECK(some.skipped_offline == 5);
    CHECK(some.skipped_version == 1);
    CHECK(some.requested == 10);
    const auto none = ss::finalize(planned, 0);
    CHECK(none.reached == 0);
    CHECK(none.skipped_offline == 9);
    // A dispatcher cannot have reached more than it was handed.
    CHECK(ss::finalize(planned, 99).reached == 6);
    CHECK(ss::finalize(planned, 99).skipped_offline == 3);
}

// ── verdicts ──────────────────────────────────────────────────────────────────────

TEST_CASE("sync decide: only an unfiltered caller may name the whole fleet", "[server][software_sync]") {
    const ss::Counts few{.requested = 3, .reached = 3};
    CHECK(ss::decide(DispatchArm::Broadcast, true, few) == ss::Verdict::Proceed);
    CHECK(ss::decide(DispatchArm::Broadcast, false, few) == ss::Verdict::FleetWideRequired);
    // The other arms never need the fleet-wide grant; their targets are already confined.
    for (const auto arm : {DispatchArm::Group, DispatchArm::Scope, DispatchArm::Ids}) {
        CHECK(ss::decide(arm, false, few) == ss::Verdict::Proceed);
        CHECK(ss::decide(arm, true, few) == ss::Verdict::Proceed);
    }
    CHECK(ss::fleet_wide_denied(DispatchArm::Broadcast, false));
    CHECK_FALSE(ss::fleet_wide_denied(DispatchArm::Broadcast, true));
    CHECK_FALSE(ss::fleet_wide_denied(DispatchArm::Group, false));
}

TEST_CASE("sync decide: the cap is on what is reached, and 500 itself is allowed", "[server][software_sync]") {
    CHECK(ss::kMaxTargets == 500);
    CHECK(ss::decide(DispatchArm::Group, true, {.requested = 500, .reached = 500}) == ss::Verdict::Proceed);
    CHECK(ss::decide(DispatchArm::Group, true, {.requested = 501, .reached = 501}) == ss::Verdict::TooMany);
    CHECK(ss::decide(DispatchArm::Scope, false, {.requested = 9000, .reached = 501}) == ss::Verdict::TooMany);
    // A big named set that is mostly offline still dispatches only what is live.
    CHECK(ss::decide(DispatchArm::Group, true,
                     {.requested = 900, .reached = 400, .skipped_offline = 500}) == ss::Verdict::Proceed);
    // The fleet-wide refusal outranks the cap: a confined caller learns nothing about size.
    CHECK(ss::decide(DispatchArm::Broadcast, false, {.requested = 900, .reached = 900}) ==
          ss::Verdict::FleetWideRequired);
}

// ── cooldown ──────────────────────────────────────────────────────────────────────

TEST_CASE("sync cooldown: 60 s per operator, boundary exact, backwards clock reads as a full wait",
          "[server][software_sync]") {
    CHECK(ss::kCooldownSecs == 60);
    CHECK(ss::cooldown_remaining(std::nullopt, 1000) == 0);       // never ran
    CHECK(ss::cooldown_remaining(1000, 1000) == 60);              // just ran
    CHECK(ss::cooldown_remaining(1000, 1001) == 59);
    CHECK(ss::cooldown_remaining(1000, 1059) == 1);
    CHECK(ss::cooldown_remaining(1000, 1060) == 0);               // boundary: clear at exactly 60
    CHECK(ss::cooldown_remaining(1000, 5000) == 0);
    CHECK(ss::cooldown_remaining(1000, 900) == 60);               // clock stepped back
}

TEST_CASE("sync cooldown state: bounded, oldest stamp evicted, a returning operator never evicts",
          "[server][software_sync]") {
    std::unordered_map<std::string, std::int64_t> state;
    CHECK_FALSE(ss::last_run_of(state, "alice").has_value());
    ss::stamp(state, "alice", 100);
    CHECK(ss::last_run_of(state, "alice") == 100);
    ss::stamp(state, "alice", 200); // restamp replaces
    CHECK(ss::last_run_of(state, "alice") == 200);

    state.clear();
    for (std::size_t i = 0; i < ss::kCooldownStateCap; ++i)
        ss::stamp(state, "u" + std::to_string(i), static_cast<std::int64_t>(1000 + i));
    REQUIRE(state.size() == ss::kCooldownStateCap);
    // At the cap a returning operator is restamped in place, nobody is dropped.
    ss::stamp(state, "u5", 9999);
    CHECK(state.size() == ss::kCooldownStateCap);
    CHECK(state.contains("u0"));
    // A new operator evicts the oldest stamp (u0), and only that one.
    ss::stamp(state, "newcomer", 5000);
    CHECK(state.size() == ss::kCooldownStateCap);
    CHECK_FALSE(state.contains("u0"));
    CHECK(state.contains("u1"));
    CHECK(state.contains("newcomer"));
}

// ── wording ───────────────────────────────────────────────────────────────────────

TEST_CASE("sync audit token: control bytes and field delimiters defanged, length bounded",
          "[server][software_sync]") {
    CHECK(ss::audit_token("plain") == "plain");
    CHECK(ss::audit_token("a\r\nb\tc\x7f") == "a__b_c_");
    CHECK(ss::audit_token("x reached=0, skipped_offline=99") == "x_reached_0__skipped_offline_99");
    const std::string longer(ss::kAuditTokenMax + 50, 'x');
    const auto t = ss::audit_token(longer);
    CHECK(t.size() == ss::kAuditTokenMax + 3);
    CHECK(t.ends_with("..."));
    CHECK(ss::audit_token(std::string(ss::kAuditTokenMax, 'x')) == std::string(ss::kAuditTokenMax, 'x'));
}

TEST_CASE("sync audit target: an expression never becomes an identifier", "[server][software_sync]") {
    CHECK(ss::target_label({DispatchArm::Broadcast, "__all__"}) == "__all__");
    CHECK(ss::target_label({DispatchArm::Scope, "tag:x AND ostype == \"linux\""}) == "expression");
    CHECK(ss::target_label({DispatchArm::Group, "group:finance"}) == "group:finance");
    CHECK(ss::target_label({DispatchArm::Ids, "host-01"}) == "host-01");
}

TEST_CASE("sync audit detail carries scope, arm and all four counts", "[server][software_sync]") {
    ss::Selector sel{DispatchArm::Group, "group:finance"};
    const ss::Counts c{.requested = 12, .reached = 7, .skipped_offline = 3, .skipped_version = 2};
    CHECK(ss::audit_detail(sel, c) ==
          "scope=group:finance arm=group requested=12 reached=7 skipped_offline=3 skipped_version=2");
    // A hostile expression cannot forge a second field or a new line.
    sel = {DispatchArm::Scope, "x\nrequested=0"};
    const auto d = ss::audit_detail(sel, c);
    CHECK(d.find('\n') == std::string::npos);
    CHECK(d.starts_with("scope=x_requested_0 arm=scope "));
    CHECK(std::string(ss::audit_result({.requested = 5, .reached = 1})) == "requested");
    CHECK(std::string(ss::audit_result({.requested = 5, .reached = 0, .skipped_offline = 5})) == "no_agents");
}

TEST_CASE("sync audit detail: a hostile expression cannot forge a neighbouring count field",
          "[server][software_sync][security]") {
    const auto occurrences = [](const std::string& hay, const std::string& needle) {
        std::size_t n = 0;
        for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
            ++n;
        return n;
    };
    ss::Selector sel;
    const ss::Counts c{.requested = 12, .reached = 7, .skipped_offline = 3, .skipped_version = 2};
    for (const char* hostile : {"x reached=0 skipped_offline=99", "x,reached=0,skipped_version=99",
                                "x\treached=0\r\nskipped_offline=99", "reached=0 requested=0 arm=group"}) {
        INFO(hostile);
        sel = {DispatchArm::Scope, hostile};
        const auto d = ss::audit_detail(sel, c);
        // Exactly one of each count key, and it is the real one, after the scope token.
        for (const char* key : {"requested=", "reached=", "skipped_offline=", "skipped_version=", "arm="})
            CHECK(occurrences(d, key) == 1);
        CHECK(d.find("reached=7 skipped_offline=3 skipped_version=2") != std::string::npos);
        CHECK(d.find('\n') == std::string::npos);
        CHECK(d.find('\r') == std::string::npos);
    }
}

TEST_CASE("sync summary: counts only, never a per-device list", "[server][software_sync]") {
    const auto j = ss::summary_json({.requested = 12, .reached = 7, .skipped_offline = 3, .skipped_version = 2},
                                    "__sync__-fleet-1-ab", 1700000000);
    CHECK(j.size() == 7);
    CHECK(j["requested"] == 12);
    CHECK(j["reached"] == 7);
    CHECK(j["skipped_offline"] == 3);
    CHECK(j["skipped_version"] == 2);
    CHECK(j["command_id"] == "__sync__-fleet-1-ab");
    CHECK(j["source"] == "installed_software");
    CHECK(j["requested_at"] == 1700000000);
    for (const auto& [k, v] : j.items())
        CHECK_FALSE(v.is_array());
}
