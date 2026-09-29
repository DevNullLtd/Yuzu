/**
 * test_guardian_push_builder.cpp — Unit tests for the per-agent Guardian push
 * builder (M4 + M7 / #1209).
 *
 * The push fan-out lambda in server.cpp had zero unit coverage; its rule
 * filtering (OS target + per-agent scope) and the spec_json → proto marshal were
 * exercised only by manual Windows UAT. This pins both via the pure helper the
 * lambda now delegates to, with no live AgentRegistry or gRPC stream.
 */

#include "guardian_push_builder.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

GuaranteedStateRuleRow row(std::string id, std::string os, std::string scope,
                           bool enabled = true) {
    GuaranteedStateRuleRow r;
    r.rule_id = id;
    r.name = std::move(id);
    r.enabled = enabled;
    r.enforcement_mode = "enforce";
    r.os_target = std::move(os);
    r.scope_expr = std::move(scope);
    r.spec_json =
        R"({"spark":{"type":"registry-change","params":{"hive":"HKLM"}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"value_name":"Start","expected":"4"}},)"
        R"("remediation":{"type":"alert-only"}})";
    return r;
}

std::vector<std::string> rule_ids(const ::yuzu::guardian::v1::GuaranteedStatePush& push) {
    std::vector<std::string> ids;
    for (const auto& r : push.rules())
        ids.push_back(r.rule_id());
    return ids;
}

const auto always_in_scope = [](const std::string&) { return true; };
const auto never_in_scope = [](const std::string&) { return false; };

} // namespace

TEST_CASE("guardian::os_target_matches", "[guardian_push_builder]") {
    CHECK(guardian::os_target_matches("", "windows"));        // empty target = all OSes
    CHECK(guardian::os_target_matches("windows", "windows"));
    CHECK(guardian::os_target_matches("WINDOWS", "windows"));  // case-insensitive
    CHECK_FALSE(guardian::os_target_matches("windows", "linux"));
    // The agent reports kAgentOs "darwin"; rule os_target authors "macos" — they
    // normalize to the same token so a macOS rule reaches a Darwin agent (#1209).
    CHECK(guardian::os_target_matches("macos", "darwin"));
    // Exact-token, NOT substring: a short/ambiguous target must not cross-match
    // (the old substring match made "win" hit "darwin"). #1209 regression guard.
    CHECK_FALSE(guardian::os_target_matches("win", "darwin"));
    CHECK_FALSE(guardian::os_target_matches("linux", "linuxmint"));
    // Unknown agent OS fails OPEN (send it, agent decides) — never silently drop a
    // guard for an agent whose session has no os. Regression guard for #1209/H1-M4.
    CHECK(guardian::os_target_matches("linux", ""));
}

TEST_CASE("build_agent_push: filters by enabled / OS / scope", "[guardian_push_builder]") {
    std::vector<GuaranteedStateRuleRow> rules = {
        row("win-on", "windows", "tag:a"),
        row("lin-on", "linux", "tag:a"),                 // wrong OS for a windows agent
        row("win-off", "windows", "tag:a", /*enabled=*/false),
        row("all-os", "", "tag:a"),                      // os_target "" = all
    };

    auto push = guardian::build_agent_push(rules, "windows", always_in_scope,
                                           /*full_sync=*/true, /*generation=*/7);

    CHECK(push.full_sync());
    CHECK(push.policy_generation() == 7);
    // Only the enabled rules that target this agent's OS survive.
    CHECK(rule_ids(push) == std::vector<std::string>{"win-on", "all-os"});
}

TEST_CASE("build_agent_push: empty scope_expr is fleet-wide, never consults the oracle",
          "[guardian_push_builder]") {
    std::vector<GuaranteedStateRuleRow> rules = {
        row("scoped", "windows", "tag:a"),  // oracle says no
        row("fleet", "windows", ""),        // empty scope → always included
    };
    // never_in_scope rejects every scope_expr; only the empty-scope rule passes.
    auto push = guardian::build_agent_push(rules, "windows", never_in_scope,
                                           /*full_sync=*/false, /*generation=*/1);
    CHECK_FALSE(push.full_sync());
    CHECK(rule_ids(push) == std::vector<std::string>{"fleet"});
}

TEST_CASE("build_agent_push: spec_json round-trips into typed proto blocks",
          "[guardian_push_builder]") {
    auto push = guardian::build_agent_push({row("r", "windows", "tag:a")}, "windows",
                                           always_in_scope, true, 1);
    REQUIRE(push.rules_size() == 1);
    const auto& pr = push.rules(0);
    CHECK(pr.rule_id() == "r");
    CHECK(pr.enabled());
    CHECK(pr.enforcement_mode() == "enforce");
    CHECK(pr.spark().type() == "registry-change");
    REQUIRE(pr.spark().params().contains("hive"));
    CHECK(pr.spark().params().at("hive") == "HKLM");
    CHECK(pr.assertion().type() == "registry-value-equals");
    CHECK(pr.assertion().params().at("expected") == "4");
    CHECK(pr.remediation().type() == "alert-only");
}

TEST_CASE("build_agent_push: a service guard reaches an agent ONLY via a deployed Baseline",
          "[guardian_push_builder][service][baseline]") {
    // Post-#1281 delivery model: a Guard reaches an agent only as a member of a
    // *deployed* Baseline, and filter_deployed_members is that gate. A standalone
    // service guard pushed with no deployed Baseline silently never armed — caught in
    // Windows UAT, not by the per-type unit tests. This pins a service guard end-to-end
    // through the deployed-member gate AND the spec_json -> proto marshal.
    GuaranteedStateRuleRow svc;
    svc.rule_id = "svc-spooler";
    svc.name = "Spooler running";
    svc.enabled = true;
    svc.enforcement_mode = "enforce";
    svc.os_target = "windows";
    svc.scope_expr = "";
    svc.version = 1;
    svc.spec_json =
        R"({"spark":{"type":"service-status-change","params":{}},)"
        R"("assertion":{"type":"service-running","params":{"service_name":"Spooler"}},)"
        R"("remediation":{"type":"enforce","params":{}}})";
    const std::vector<GuaranteedStateRuleRow> all{svc};

    SECTION("NOT in any deployed Baseline -> full-sync push carries zero rules (disarm)") {
        // Nothing deployed = nothing enforced, but the push is still a *valid*
        // full_sync teardown: the agent must receive full_sync=true + the current
        // generation so it disarms any previously-armed copy of this guard, rather
        // than the header being dropped. The bare empty-filter / empty-input cases
        // are covered by the filter_deployed_members TEST_CASE; what THIS pins is
        // that the push header survives an empty deployed member set.
        auto deployed = guardian::filter_deployed_members(all, /*deployed_rule_ids=*/{});
        CHECK(deployed.empty());
        auto push = guardian::build_agent_push(deployed, "windows", always_in_scope,
                                               /*full_sync=*/true, /*generation=*/9);
        CHECK(push.full_sync());
        CHECK(push.policy_generation() == 9);
        CHECK(push.rules_size() == 0);
    }
    SECTION("member of a deployed Baseline -> included, service spark/assertion intact") {
        auto deployed = guardian::filter_deployed_members(all, {"svc-spooler"});
        REQUIRE(deployed.size() == 1);
        auto push = guardian::build_agent_push(deployed, "windows", always_in_scope, true, 1);
        REQUIRE(push.rules_size() == 1);
        const auto& pr = push.rules(0);
        CHECK(pr.rule_id() == "svc-spooler");
        CHECK(pr.spark().type() == "service-status-change");
        CHECK(pr.assertion().type() == "service-running");
        REQUIRE(pr.assertion().params().contains("service_name"));
        CHECK(pr.assertion().params().at("service_name") == "Spooler");
        CHECK(pr.remediation().type() == "enforce");
        CHECK(pr.enforcement_mode() == "enforce");
    }
    SECTION("member with malformed spec_json -> header-only, never silently dropped") {
        // A truncated/corrupt spec_json (partial write, hand-authored JSON typo) must
        // not make the rule vanish from the push: the agent still needs rule_id +
        // enforcement_mode to reconcile, and an unparseable spec yields a no-op
        // header-only guard the operator can still SEE, rather than a silent
        // disappearance. parse(allow_exceptions=false) returns a discarded value, so
        // !is_object() short-circuits AFTER the header is set — same posture as the
        // empty-spec legacy row. (dangerous_enforce_in_spec also no-ops on malformed
        // JSON, so the enforce mode is NOT spuriously downgraded.)
        GuaranteedStateRuleRow bad = svc;
        bad.spec_json = R"({"spark":{"type":"service-status-change")";  // truncated mid-object
        auto deployed = guardian::filter_deployed_members({bad}, {"svc-spooler"});
        REQUIRE(deployed.size() == 1);
        auto push = guardian::build_agent_push(deployed, "windows", always_in_scope, true, 1);
        REQUIRE(push.rules_size() == 1);
        const auto& pr = push.rules(0);
        CHECK(pr.rule_id() == "svc-spooler");
        CHECK(pr.enforcement_mode() == "enforce");   // header intact, not dropped
        CHECK(pr.spark().type().empty());            // malformed spec → no typed blocks
        CHECK(pr.assertion().type().empty());
    }
    SECTION("well-formed object with a non-string block 'type' -> no throw, inert type (#1946)") {
        // Distinct from the truncated case above: this spec_json PARSES as an object
        // (so fill_block runs) but carries a non-string "type". derive_rule_spec
        // type-checks spark.type/assertion.type before persistence but NOT
        // remediation.type, so a rule authored via REST create with
        // remediation.type as a number/array/object persists and reaches here. A
        // present-non-string type used to throw json::type_error.302 out of
        // fill_block -> escape build_agent_push -> HTTP 500 on every push fan-out
        // (fleet-wide guardian-convergence DoS). It must now marshal to an inert
        // empty type, header intact, never throw.
        GuaranteedStateRuleRow poisoned = svc;
        poisoned.spec_json =
            R"({"spark":{"type":"service-status-change","params":{}},)"
            R"("assertion":{"type":"service-running","params":{"service_name":"Spooler"}},)"
            R"("remediation":{"type":5,"params":{}}})";
        auto deployed = guardian::filter_deployed_members({poisoned}, {"svc-spooler"});
        REQUIRE(deployed.size() == 1);
        // The load-bearing assertion is simply that this call returns without
        // throwing — pre-fix it aborted with type_error.302.
        auto push = guardian::build_agent_push(deployed, "windows", always_in_scope, true, 1);
        REQUIRE(push.rules_size() == 1);
        const auto& pr = push.rules(0);
        CHECK(pr.rule_id() == "svc-spooler");
        CHECK(pr.enforcement_mode() == "enforce");            // header intact
        CHECK(pr.spark().type() == "service-status-change");  // well-typed blocks still marshal
        CHECK(pr.assertion().type() == "service-running");
        CHECK(pr.remediation().type().empty());               // non-string type → inert empty
    }
}

TEST_CASE("build_agent_push: legacy rule with empty spec_json is header-only",
          "[guardian_push_builder]") {
    GuaranteedStateRuleRow legacy;
    legacy.rule_id = "leg";
    legacy.name = "leg";
    legacy.enabled = true;
    legacy.enforcement_mode = "audit";
    legacy.os_target = "";
    legacy.scope_expr = "";
    legacy.spec_json = "";  // pre-migration row — not agent-enforceable

    auto push = guardian::build_agent_push({legacy}, "windows", always_in_scope, true, 1);
    REQUIRE(push.rules_size() == 1);
    CHECK(push.rules(0).rule_id() == "leg");
    CHECK(push.rules(0).enforcement_mode() == "audit");
    CHECK(push.rules(0).spark().type().empty());        // no spec blocks filled
    CHECK(push.rules(0).assertion().type().empty());
}

TEST_CASE("guardian::filter_deployed_members — the Baseline gate", "[guardian_push_builder]") {
    const std::vector<GuaranteedStateRuleRow> rules{
        row("a", "windows", ""), row("b", "windows", ""), row("c", "linux", "")};

    SECTION("keeps only rules whose id is a deployed-baseline member, order preserved") {
        auto out = guardian::filter_deployed_members(rules, {"c", "a"});
        REQUIRE(out.size() == 2);
        CHECK(out[0].rule_id == "a");   // input order, not set order
        CHECK(out[1].rule_id == "c");
    }
    SECTION("empty deployed set yields nothing — nothing deployed = nothing enforced") {
        CHECK(guardian::filter_deployed_members(rules, {}).empty());
    }
    SECTION("ids with no matching rule are ignored") {
        auto out = guardian::filter_deployed_members(rules, {"a", "ghost"});
        REQUIRE(out.size() == 1);
        CHECK(out[0].rule_id == "a");
    }
}

TEST_CASE("build_agent_push: enforce on a denylisted key is downgraded to audit (H1 backstop)",
          "[guardian_push_builder][denylist][h1]") {
    // A rule can reach enforce mode via the dashboard toggle / metadata-only
    // update without re-running the create-time validator; the push boundary is
    // the chokepoint that must neutralise a denylisted enforce-write regardless of
    // how it got into the store. Downgrade-to-audit preserves detection.
    GuaranteedStateRuleRow danger;
    danger.rule_id = "danger";
    danger.name = "danger";
    danger.enabled = true;
    danger.enforcement_mode = "enforce";
    danger.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM",)"
        R"("key":"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",)"
        R"("value_name":"Evil","value_type":"REG_SZ","expected":"C:\\x.exe"}},)"
        R"("remediation":{"type":"enforce"}})";

    GuaranteedStateRuleRow safe;
    safe.rule_id = "safe";
    safe.name = "safe";
    safe.enabled = true;
    safe.enforcement_mode = "enforce";
    safe.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM",)"
        R"("key":"SOFTWARE\\YuzuTest\\Flag","value_name":"X","value_type":"REG_SZ","expected":"1"}},)"
        R"("remediation":{"type":"enforce"}})";

    auto push = guardian::build_agent_push({danger, safe}, "windows", always_in_scope, true, 1);
    std::string danger_mode, safe_mode;
    for (const auto& r : push.rules()) {
        if (r.rule_id() == "danger")
            danger_mode = r.enforcement_mode();
        if (r.rule_id() == "safe")
            safe_mode = r.enforcement_mode();
    }
    CHECK(danger_mode == "audit");  // downgraded — guard still detects, never writes
    CHECK(safe_mode == "enforce");  // benign key keeps enforce
    // The assertion is still marshalled (detection preserved), just not enforced.
    for (const auto& r : push.rules())
        if (r.rule_id() == "danger")
            CHECK(r.assertion().type() == "registry-value-equals");
}

// json-dump-depth-guard fix: build_agent_push is the SOLE function both
// server.cpp:5224 (heartbeat reconcile) and server.cpp:17635 (baseline
// deploy/toggle push fan-out) delegate to for the rule-filtering + spec_json
// -> proto marshal (that split is exactly M7's point, see the file header) -
// neither call site does any further per-rule processing on the result, so
// pinning behaviour here covers both consumer paths with no live server/DB.
// NOTE: this TEST_CASE originates the literal rule_id "poisoned", also
// reused by the later "a repeated attempt against the same poisoned row..."
// TEST_CASE in this file - harmless today since neither asserts on log
// cadence for it, but a future test asserting should_log()/log-line
// behavior for either must pick a distinct rule_id or account for the
// shared g_exclusion_sampler.
TEST_CASE("build_agent_push: a rule nested past the depth guard is excluded; "
          "other rules in the same batch still push normally",
          "[guardian_push_builder][security][depth]") {
    // A raw string, never materialised as a live nlohmann::json object at this
    // depth. kMcpMaxJsonDepth is 32; the 40-deep array below is comfortably
    // past it and still trivially safe to construct/dump directly in this test
    // process, orders of magnitude short of the ~100,000-level depth that
    // actually SIGSEGVs the real fill_block() dump() call this guard exists to
    // prevent.
    GuaranteedStateRuleRow poisoned = row("poisoned", "windows", "");
    poisoned.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM","nested":)" +
        std::string(40, '[') + std::string(40, ']') +
        R"(}},"remediation":{"type":"alert-only"}})";

    GuaranteedStateRuleRow healthy = row("healthy", "windows", "");

    auto push = guardian::build_agent_push({poisoned, healthy}, "windows", always_in_scope,
                                           /*full_sync=*/true, /*generation=*/3);

    // The poisoned rule is excluded ENTIRELY (not even a header-only entry)
    // while the healthy rule still gets its full push treatment.
    CHECK(rule_ids(push) == std::vector<std::string>{"healthy"});
    REQUIRE(push.rules_size() == 1);
    const auto& pr = push.rules(0);
    CHECK(pr.rule_id() == "healthy");
    CHECK(pr.spark().type() == "registry-change");
    CHECK(pr.assertion().type() == "registry-value-equals");
    CHECK(pr.remediation().type() == "alert-only");
}

TEST_CASE("build_agent_push: excluding a poisoned rule increments "
          "yuzu_guardian_push_rule_excluded_total{reason=depth_exceeded}",
          "[guardian_push_builder][security][depth][observability]") {
    // Governance Gate 4/6 finding: a poisoned rule's exclusion previously had
    // no fleet-wide signal beyond an unrated log line - this is the metric
    // that closes that gap. `metrics` is a nullable trailing param
    // (unchanged callers/tests keep compiling) so this test opts in
    // explicitly.
    yuzu::MetricsRegistry metrics;
    GuaranteedStateRuleRow poisoned = row("poisoned2", "windows", "");
    poisoned.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM","nested":)" +
        std::string(40, '[') + std::string(40, ']') +
        R"(}},"remediation":{"type":"alert-only"}})";
    GuaranteedStateRuleRow healthy = row("healthy2", "windows", "");

    CHECK(metrics
              .counter("yuzu_guardian_push_rule_excluded_total", {{"reason", "depth_exceeded"}})
              .value() == 0.0);

    auto push = guardian::build_agent_push({poisoned, healthy}, "windows", always_in_scope,
                                           /*full_sync=*/true, /*generation=*/3, &metrics);

    CHECK(rule_ids(push) == std::vector<std::string>{"healthy2"});
    CHECK(metrics
              .counter("yuzu_guardian_push_rule_excluded_total", {{"reason", "depth_exceeded"}})
              .value() == 1.0);
}

TEST_CASE("build_agent_push: a repeated attempt against the same poisoned row "
          "behaves identically each time, no crash, no growth",
          "[guardian_push_builder][security][depth]") {
    // Models a second (and third) heartbeat/tick reconciling the SAME stored
    // rule: the poisoned row persists in the store (this fix does not heal or
    // rewrite it, see guardian_push_builder.hpp), so every subsequent push
    // must re-derive the same exclusion result and not crash. build_agent_push
    // itself carries no per-call state (its rule filtering/marshal is pure);
    // the only state that survives across calls is the process-wide, bounded
    // (kCapacity-many rule_ids) RuleExclusionSampler used to pace the
    // exclusion log line, which does not affect this test's assertions.
    // NOTE: this TEST_CASE reuses the literal rule_id "poisoned", also used
    // by the earlier "a rule nested past the depth guard is excluded" case in
    // this file - harmless today since neither asserts on log cadence for it,
    // but a future test asserting should_log()/log-line behavior for either
    // must pick a distinct rule_id or account for the shared g_exclusion_sampler.
    GuaranteedStateRuleRow poisoned = row("poisoned", "windows", "");
    poisoned.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM","nested":)" +
        std::string(40, '[') + std::string(40, ']') +
        R"(}},"remediation":{"type":"alert-only"}})";
    GuaranteedStateRuleRow healthy = row("healthy", "windows", "");
    const std::vector<GuaranteedStateRuleRow> rules{poisoned, healthy};

    for (int attempt = 0; attempt < 3; ++attempt) {
        INFO("attempt " << attempt);
        auto push = guardian::build_agent_push(rules, "windows", always_in_scope,
                                               /*full_sync=*/true,
                                               /*generation=*/static_cast<std::uint64_t>(attempt));
        CHECK(rule_ids(push) == std::vector<std::string>{"healthy"});
        REQUIRE(push.rules_size() == 1);
        CHECK(push.rules(0).rule_id() == "healthy");
    }
}

TEST_CASE("guardian_guard_supported_on_platform — type-aware support matrix; unknown is open",
          "[guardian_push_builder][platform]") {
    using guardian::guardian_guard_supported_on_platform;
    // registry-change / file-change: Windows only (RegistryGuard/FileGuard::
    // start() are no-ops on macOS+Linux) — unaffected by #4252's fix.
    CHECK(guardian_guard_supported_on_platform("windows", "registry-change"));
    CHECK(guardian_guard_supported_on_platform("Windows", "registry-change"));  // normalize_os lower-cases
    CHECK_FALSE(guardian_guard_supported_on_platform("darwin", "registry-change"));
    CHECK_FALSE(guardian_guard_supported_on_platform("macos", "registry-change"));  // author/alias token too
    CHECK_FALSE(guardian_guard_supported_on_platform("linux", "registry-change"));
    CHECK(guardian_guard_supported_on_platform("windows", "file-change"));
    CHECK_FALSE(guardian_guard_supported_on_platform("linux", "file-change"));
    CHECK_FALSE(guardian_guard_supported_on_platform("macos", "file-change"));

    // service-status-change: Windows AND Linux (SystemdServiceGuard arms,
    // observe-only) — NOT macOS. This is #4252's fix: Linux was wrongly
    // reported as "not implemented" here before.
    CHECK(guardian_guard_supported_on_platform("windows", "service-status-change"));
    CHECK(guardian_guard_supported_on_platform("linux", "service-status-change"));
    CHECK_FALSE(guardian_guard_supported_on_platform("darwin", "service-status-change"));
    CHECK_FALSE(guardian_guard_supported_on_platform("macos", "service-status-change"));

    // Gate 8 re-review (architect + consistency-auditor): the new schema-catalog
    // CROSS-CHECK test (test_guardian_resilience_schema.cpp) binds
    // guardian::kKnownGuardSparkTypes to the published catalog, but
    // guardian_guard_supported_on_platform's if-chain above is a set of string
    // LITERALS, not a lookup over that array — so the cross-check passing does
    // NOT prove this function has a branch for every entry in it. A 4th type
    // could be added to kKnownGuardSparkTypes (and the schema catalog) with no
    // corresponding branch here, silently falling through to the Windows-only
    // default while the cross-check test stays green. Pin the array itself:
    // every entry must be one of the 3 literals this test already covers above
    // — an unrecognised entry here means a new spark type was added without its
    // platform-support matrix decision (fix: add the CHECK lines above too).
    for (std::string_view t : guardian::kKnownGuardSparkTypes) {
        INFO("kKnownGuardSparkTypes entry not covered by this test's pinned "
             "matrix above: " << t);
        CHECK((t == "registry-change" || t == "file-change" ||
              t == "service-status-change"));
    }

    // Unknown/missing spark_type falls back to the Windows-only rule — never
    // regress a type this function doesn't recognise.
    CHECK(guardian_guard_supported_on_platform("windows", "some-future-type"));
    CHECK_FALSE(guardian_guard_supported_on_platform("linux", "some-future-type"));
    CHECK(guardian_guard_supported_on_platform("windows", ""));
    CHECK_FALSE(guardian_guard_supported_on_platform("linux", ""));
    CHECK_FALSE(guardian_guard_supported_on_platform("macos", ""));

    // Unknown OS (disconnect race / partial registration) must NOT be mislabelled
    // "not implemented" — fail open, same posture as os_target_matches, for
    // every spark_type including Service.
    CHECK(guardian_guard_supported_on_platform("", "registry-change"));
    CHECK(guardian_guard_supported_on_platform("", "service-status-change"));
    CHECK(guardian_guard_supported_on_platform("", ""));
}

TEST_CASE("platform_display_name — raw agent token to operator-facing label",
          "[guardian_push_builder][platform]") {
    using guardian::platform_display_name;
    CHECK(platform_display_name("darwin") == "macOS");  // the case that matters
    CHECK(platform_display_name("windows") == "Windows");
    CHECK(platform_display_name("linux") == "Linux");
    CHECK(platform_display_name("macos") == "macOS");  // alias normalises too
    CHECK(platform_display_name("") == "unknown");
}

// -----------------------------------------------------------------------
// RuleExclusionSampler (#4497/#4499) - per-rule LRU, time-based log pacing
// for the depth-guard exclusion path. These tests construct their OWN
// independently-instantiable sampler with an injectable monotonic clock
// (never the process-wide instance build_agent_push shares, and never a
// real sleep), per the recorded design decision in
// guardian_push_builder.hpp's RuleExclusionSampler doc comment.
// -----------------------------------------------------------------------

TEST_CASE("RuleExclusionSampler: a hot rule cannot mask a distinct rule's own first log",
          "[guardian_push_builder][sampler]") {
    // #4497's cross-rule-masking defect: the OLD single shared sampler could
    // let rule A's ongoing "episode" swallow rule B's first exclusion, so an
    // operator investigating rule B had no guarantee the log ever named it.
    // Per-rule keying fixes this structurally: B's FIRST observation always
    // logs immediately, independent of A's state.
    guardian::RuleExclusionSampler sampler;
    std::chrono::steady_clock::time_point t0{};
    sampler.set_clock_for_test([&t0] { return t0; });

    CHECK(sampler.should_log("rule-a"));        // A's first exclusion: immediate log
    CHECK_FALSE(sampler.should_log("rule-a"));  // A still within its own 60s interval
    CHECK_FALSE(sampler.should_log("rule-a"));
    CHECK(sampler.should_log("rule-b"));        // B's first exclusion: STILL immediate
}

TEST_CASE("RuleExclusionSampler: sustained exclusions on one rule permit once per 60s",
          "[guardian_push_builder][sampler]") {
    guardian::RuleExclusionSampler sampler;
    std::chrono::steady_clock::time_point now{};
    sampler.set_clock_for_test([&now] { return now; });

    CHECK(sampler.should_log("r"));  // initial permit - first observation
    now += std::chrono::seconds(1);
    CHECK_FALSE(sampler.should_log("r"));
    now += std::chrono::seconds(58);  // t=59s since the permitted log: still suppressed
    CHECK_FALSE(sampler.should_log("r"));
    now += std::chrono::seconds(1);   // t=60s: at the boundary, due again
    CHECK(sampler.should_log("r"));
    now += std::chrono::seconds(1);   // right after a fresh permit
    CHECK_FALSE(sampler.should_log("r"));
    now += guardian::RuleExclusionSampler::kRepeatInterval;  // a full interval later
    CHECK(sampler.should_log("r"));
}

TEST_CASE("RuleExclusionSampler: concurrent same-rule calls yield exactly one permit",
          "[guardian_push_builder][sampler][concurrency]") {
    guardian::RuleExclusionSampler sampler;
    std::chrono::steady_clock::time_point now{};
    sampler.set_clock_for_test([&now] { return now; });

    constexpr int kThreads = 16;
    std::atomic<int> permits{0};
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i)
        threads.emplace_back([&] {
            ready.fetch_add(1, std::memory_order_relaxed);
            while (!go.load(std::memory_order_acquire))
                ;  // spin-gate: maximise actual overlap at should_log()
            if (sampler.should_log("hot-rule"))
                permits.fetch_add(1, std::memory_order_relaxed);
        });
    while (ready.load(std::memory_order_relaxed) < kThreads)
        ;  // wait for every thread to reach the gate before releasing them together
    go.store(true, std::memory_order_release);
    for (auto& t : threads)
        t.join();

    // The internal mutex serializes should_log() end-to-end (the decision AND
    // the deadline update happen under the same lock), so exactly one of the
    // 16 racing calls for the SAME rule_id at the SAME injected timestamp can
    // observe "not yet due" turn permitted - never zero, never more than one.
    CHECK(permits.load() == 1);
}

TEST_CASE("RuleExclusionSampler: LRU capacity, eviction, and reappearance (#4497 exception)",
          "[guardian_push_builder][sampler][lru]") {
    guardian::RuleExclusionSampler sampler;
    std::chrono::steady_clock::time_point now{};
    sampler.set_clock_for_test([&now] { return now; });
    constexpr auto kCapacity = guardian::RuleExclusionSampler::kCapacity;

    SECTION("filling to capacity tracks every distinct rule, none evicted yet") {
        for (std::size_t i = 0; i < kCapacity; ++i)
            CHECK(sampler.should_log("rule-" + std::to_string(i)));  // each is a first observation
        CHECK(sampler.tracked_count_for_test() == kCapacity);
    }

    SECTION("a 257th distinct rule evicts the least-recently-observed entry") {
        // Observe kCapacity distinct rules in order 0..255: rule-0 is now the
        // LEAST recently observed (touched first, never touched again).
        for (std::size_t i = 0; i < kCapacity; ++i)
            CHECK(sampler.should_log("rule-" + std::to_string(i)));  // each a first observation
        CHECK(sampler.tracked_count_for_test() == kCapacity);

        // A 257th distinct rule must evict rule-0 to stay within capacity.
        CHECK(sampler.should_log("rule-256"));  // first observation: immediate log
        CHECK(sampler.tracked_count_for_test() == kCapacity);

        // rule-1..rule-255 were never evicted and stay suppressed within
        // their own interval. Checked BEFORE re-touching rule-0 below: an
        // evicted rule_id re-appearing is ITSELF a fresh insertion that would
        // trigger a further eviction (of whatever is then the new
        // least-recently-observed entry) and confound this assertion.
        CHECK_FALSE(sampler.should_log("rule-1"));
        CHECK_FALSE(sampler.should_log("rule-255"));
        CHECK(sampler.tracked_count_for_test() == kCapacity);

        // rule-0 was evicted: encountering it again is a FIRST observation
        // again and logs immediately, even though (had it not been evicted)
        // it would still be well inside its own 60s repeat window. This is
        // the documented, accepted tradeoff (#4497/#4499): an LRU capacity is
        // NOT a global log-rate limit.
        CHECK(sampler.should_log("rule-0"));
        CHECK(sampler.tracked_count_for_test() == kCapacity);
    }

    SECTION("touching an existing rule refreshes its recency, protecting it from eviction") {
        for (std::size_t i = 0; i < kCapacity; ++i)
            CHECK(sampler.should_log("rule-" + std::to_string(i)));  // each a first observation

        // Re-touch rule-0 (a SUPPRESSED call still refreshes LRU recency), so
        // it is no longer the least-recently-observed entry - rule-1 is.
        CHECK_FALSE(sampler.should_log("rule-0"));
        CHECK(sampler.should_log("rule-256"));  // evicts rule-1, not rule-0

        // rule-0 survived (its recency was refreshed above): a further call
        // is still suppressed, not treated as a fresh first-observation.
        CHECK_FALSE(sampler.should_log("rule-0"));
        // rule-1, now the least-recently-observed entry, was evicted instead.
        CHECK(sampler.should_log("rule-1"));
    }
}

TEST_CASE("RuleExclusionSampler: at-capacity paces correctly, kCapacity+1 is a hard "
          "cliff not a gradual leak (#4497/#4499)",
          "[guardian_push_builder][sampler][lru]") {
    // Pins the ACCEPTED LIMITATION's ACTUAL shape (see this class's doc
    // comment and docs/user-manual/guaranteed-state.md): more than kCapacity
    // distinct poisoned rules cycling through the cache in a REPEATING order
    // is not a mild "logs somewhat more often" leak - it is a 0%-suppression
    // cliff at exactly kCapacity+1. Verified directly against this class
    // during governance review before this test was added (257 rule_ids, 5
    // consecutive passes: 257/257 logged on every single pass).
    constexpr auto kCapacity = guardian::RuleExclusionSampler::kCapacity;

    SECTION("at exactly kCapacity, stable-order cycling paces correctly across passes") {
        guardian::RuleExclusionSampler sampler;
        std::chrono::steady_clock::time_point now{};
        sampler.set_clock_for_test([&now] { return now; });

        std::vector<std::string> rules;
        for (std::size_t i = 0; i < kCapacity; ++i)
            rules.push_back("cap-rule-" + std::to_string(i));

        for (auto& r : rules)
            CHECK(sampler.should_log(r));  // pass 0: every rule is a first observation

        for (int pass = 0; pass < 3; ++pass) {
            std::size_t logged = 0;
            for (auto& r : rules)
                if (sampler.should_log(r))
                    ++logged;
            INFO("pass " << pass);
            // None evicted at exactly kCapacity, so every rule stays cached
            // and within its own 60s window: nothing re-logs.
            CHECK(logged == 0);
        }
    }

    SECTION("at kCapacity+1, stable-order cycling is a 0%-suppression cliff") {
        guardian::RuleExclusionSampler sampler;
        std::chrono::steady_clock::time_point now{};
        sampler.set_clock_for_test([&now] { return now; });

        std::vector<std::string> rules;
        for (std::size_t i = 0; i < kCapacity + 1; ++i)
            rules.push_back("cliff-rule-" + std::to_string(i));

        for (int pass = 0; pass < 5; ++pass) {
            std::size_t logged = 0;
            for (auto& r : rules)
                if (sampler.should_log(r))
                    ++logged;
            INFO("pass " << pass);
            // Inserting rule K evicts the slot belonging to the rule visited
            // NEXT in this pass (not a "predecessor"), so that rule is
            // already evicted by the time its own turn comes up - EVERY rule
            // logs on EVERY pass, not "somewhat more often than 60s".
            CHECK(logged == rules.size());
        }
    }
}

TEST_CASE("build_agent_push: excluding the same poisoned rule repeatedly increments the "
          "metric on every call regardless of whether the log line was suppressed",
          "[guardian_push_builder][security][depth][observability][sampler]") {
    // #4497/#4499: the log line is now paced PER RULE via RuleExclusionSampler
    // and will be suppressed on the 2nd/3rd call below (well within its 60s
    // repeat interval, since this test runs in well under 60 real seconds) -
    // the counter increment MUST NOT be coupled to that decision, staying
    // unconditional on every exclusion. Uses a rule_id no other TEST_CASE in
    // this binary touches, since build_agent_push shares ONE process-wide
    // RuleExclusionSampler across the whole test run.
    yuzu::MetricsRegistry metrics;
    GuaranteedStateRuleRow poisoned = row("poisoned-metric-unconditional", "windows", "");
    poisoned.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM","nested":)" +
        std::string(40, '[') + std::string(40, ']') +
        R"(}},"remediation":{"type":"alert-only"}})";

    for (int attempt = 1; attempt <= 3; ++attempt) {
        INFO("attempt " << attempt);
        auto push = guardian::build_agent_push({poisoned}, "windows", always_in_scope,
                                               /*full_sync=*/true,
                                               /*generation=*/static_cast<std::uint64_t>(attempt),
                                               &metrics);
        CHECK(push.rules_size() == 0);  // excluded every time
        CHECK(metrics
                  .counter("yuzu_guardian_push_rule_excluded_total",
                          {{"reason", "depth_exceeded"}})
                  .value() == static_cast<double>(attempt));
    }
}

// #4665 Phase-3 governance (architect/security-guardian/sre/compliance-officer/
// enterprise-readiness/unhappy-path all independently found this gap): before
// this fix, a legacy rule_id violating the post-#4665 charset/length contract
// (creatable only pre-#4665, when creation enforced no such bound) reached
// every agent in its push unfiltered, and the upgraded agent's whole-push-reject
// in apply_rules() then refused the ENTIRE push -- wedging delivery to every
// OTHER rule in scope too, with no server-side signal. Mirrors the depth-guard
// TEST_CASE above: the bad row is excluded entirely, siblings are unaffected.
TEST_CASE("build_agent_push: a rule with a non-conforming rule_id is excluded; "
          "other rules in the same batch still push normally",
          "[guardian_push_builder][security][rule_id]") {
    GuaranteedStateRuleRow legacy_bad = row("legacy bad\nid", "windows", "");
    GuaranteedStateRuleRow healthy = row("healthy2", "windows", "");

    auto push = guardian::build_agent_push({legacy_bad, healthy}, "windows", always_in_scope,
                                           /*full_sync=*/true, /*generation=*/3);

    CHECK(rule_ids(push) == std::vector<std::string>{"healthy2"});
}

TEST_CASE("build_agent_push: excluding a non-conforming rule_id increments its own "
          "metric reason, distinct from depth_exceeded",
          "[guardian_push_builder][security][rule_id][observability]") {
    yuzu::MetricsRegistry metrics;
    GuaranteedStateRuleRow legacy_bad = row("legacy bad id metric", "windows", "");

    auto push = guardian::build_agent_push({legacy_bad}, "windows", always_in_scope,
                                           /*full_sync=*/true, /*generation=*/1, &metrics);

    CHECK(push.rules_size() == 0);
    CHECK(metrics
              .counter("yuzu_guardian_push_rule_excluded_total",
                      {{"reason", "invalid_rule_id"}})
              .value() == 1.0);
    // Never counted under the unrelated depth_exceeded reason.
    CHECK(metrics
              .counter("yuzu_guardian_push_rule_excluded_total",
                      {{"reason", "depth_exceeded"}})
              .value() == 0.0);
}

TEST_CASE("build_agent_push: an over-long rule_id (>256 bytes, charset-clean) is "
          "excluded too -- length-only violations, not just charset ones",
          "[guardian_push_builder][security][rule_id]") {
    GuaranteedStateRuleRow too_long = row(std::string(300, 'a'), "windows", "");
    GuaranteedStateRuleRow healthy = row("healthy3", "windows", "");

    auto push = guardian::build_agent_push({too_long, healthy}, "windows", always_in_scope,
                                           /*full_sync=*/true, /*generation=*/1);

    CHECK(rule_ids(push) == std::vector<std::string>{"healthy3"});
}

// Mirrors the depth_exceeded repeated-call TEST_CASE above (#4665 Phase-3
// governance sre re-verification): the invalid_rule_id counter must increment
// unconditionally on every exclusion, uncoupled from the sampler's log-line
// suppression decision, exactly like its depth_exceeded sibling — a future
// refactor that accidentally couples the two reason branches differently
// would otherwise go uncaught.
TEST_CASE("build_agent_push: excluding the same non-conforming rule_id repeatedly "
          "increments the metric on every call regardless of whether the log line "
          "was suppressed",
          "[guardian_push_builder][security][rule_id][observability][sampler]") {
    yuzu::MetricsRegistry metrics;
    GuaranteedStateRuleRow legacy_bad = row("legacy bad\nid repeated", "windows", "");

    for (int attempt = 1; attempt <= 3; ++attempt) {
        INFO("attempt " << attempt);
        auto push = guardian::build_agent_push({legacy_bad}, "windows", always_in_scope,
                                               /*full_sync=*/true,
                                               /*generation=*/static_cast<std::uint64_t>(attempt),
                                               &metrics);
        CHECK(push.rules_size() == 0);  // excluded every time
        CHECK(metrics
                  .counter("yuzu_guardian_push_rule_excluded_total",
                          {{"reason", "invalid_rule_id"}})
                  .value() == static_cast<double>(attempt));
    }
}
