// test_guardian_spark_bridge.cpp - spark_spec_from_rule + classify() (ADR-0021
// rung 2 slice 2b, extended rung 7). spark_spec_from_rule is inline, so the
// proto Map populate (here in the test EXE) and the lookup (inside the
// converter, also compiled into the test EXE) stay in one image - no #501
// abseil-seed cross-DLL hazard. classify() moved here from the now-deleted
// guardian_spark_consumer.{hpp,cpp} (rung 7 dead-code cleanup) since both
// functions share the single-sourced spark_type_from_token() this header now
// exposes.

#include "guardian_spark_bridge.hpp"

#include "guaranteed_state.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <variant>

using yuzu::agent::AssertionKind;
using yuzu::agent::classify;
using yuzu::agent::FileSparkParams;
using yuzu::agent::kMaxFileHashBytes;
using yuzu::agent::RegistrySparkParams;
using yuzu::agent::RuleAssertion;
using yuzu::agent::rule_assertion_from_rule;
using yuzu::agent::RulePlacement;
using yuzu::agent::ServiceSparkParams;
using yuzu::agent::spark_key;
using yuzu::agent::spark_spec_from_rule;
using yuzu::agent::SparkType;
using Rule = yuzu::guardian::v1::GuaranteedStateRule;

namespace {
Rule make_rule(const std::string& rule_id, const std::string& spark_type,
               const std::string& atype,
               std::initializer_list<std::pair<const char*, const char*>> aparams) {
    Rule r;
    r.set_rule_id(rule_id);
    r.mutable_spark()->set_type(spark_type);
    r.mutable_assertion()->set_type(atype);
    for (const auto& [k, v] : aparams)
        (*r.mutable_assertion()->mutable_params())[k] = v;
    return r;
}

void set_remediation_param(Rule& r, const char* k, const char* v) {
    (*r.mutable_remediation()->mutable_params())[k] = v;
}
} // namespace

TEST_CASE("spark_spec_from_rule: file-change reads path from the assertion", "[spark][bridge]") {
    const Rule r = make_rule("r1", "file-change", "file-hash-equals", {{"path", "/etc/hosts"}});
    const auto spec = spark_spec_from_rule(r);
    REQUIRE(spec.has_value());
    REQUIRE(spec->type == SparkType::File);
    REQUIRE(std::get<FileSparkParams>(spec->params).path == "/etc/hosts");
}

TEST_CASE("spark_spec_from_rule: service-status-change reads service_name", "[spark][bridge]") {
    const Rule r = make_rule("r1", "service-status-change", "service-running",
                             {{"service_name", "sshd"}});
    const auto spec = spark_spec_from_rule(r);
    REQUIRE(spec.has_value());
    REQUIRE(spec->type == SparkType::Service);
    REQUIRE(std::get<ServiceSparkParams>(spec->params).service_name == "sshd");
}

TEST_CASE("spark_spec_from_rule: registry-change reads hive + key", "[spark][bridge]") {
    const Rule r = make_rule("r1", "registry-change", "registry-value-equals",
                             {{"hive", "HKLM"}, {"key", "Software\\Yuzu"}});
    const auto spec = spark_spec_from_rule(r);
    REQUIRE(spec.has_value());
    REQUIRE(spec->type == SparkType::Registry);
    const auto& rp = std::get<RegistrySparkParams>(spec->params);
    REQUIRE(rp.hive == "HKLM");
    REQUIRE(rp.key == "Software\\Yuzu");
}

TEST_CASE("spark_spec_from_rule: missing required target param is nullopt", "[spark][bridge]") {
    // file with no path
    REQUIRE_FALSE(spark_spec_from_rule(make_rule("r", "file-change", "file-exists", {})).has_value());
    // service with no name
    REQUIRE_FALSE(
        spark_spec_from_rule(make_rule("r", "service-status-change", "service-running", {}))
            .has_value());
    // registry with no hive - hive is the one truly required field
    REQUIRE_FALSE(
        spark_spec_from_rule(make_rule("r", "registry-change", "registry-value-equals",
                                       {{"key", "Software\\Yuzu"}}))
            .has_value());
}

TEST_CASE("spark_spec_from_rule: registry hive with an empty key watches the hive root",
          "[spark][bridge]") {
    // `key` is NOT required: an empty key means "watch the hive root", which
    // legacy's RegistryGuard has always accepted (guard_registry.cpp passes an
    // empty subkey as NULL to RegOpenKeyExW/RegCreateKeyExW, opening the hive
    // itself) and the spark mechanism accepts identically (spark_registry.cpp).
    // Rejecting this here made validation - which runs unconditionally, before
    // the prefer_spark_ check - stricter than legacy ever was (governance
    // Gate 4/6 finding).
    const auto r =
        make_rule("r", "registry-change", "registry-value-equals", {{"hive", "HKLM"}});
    const auto spec = spark_spec_from_rule(r);
    REQUIRE(spec.has_value());
    REQUIRE(spec->type == SparkType::Registry);
    const auto& rp = std::get<RegistrySparkParams>(spec->params);
    REQUIRE(rp.hive == "HKLM");
    REQUIRE(rp.key.empty());
}

TEST_CASE("spark_spec_from_rule: an unknown spark type is nullopt", "[spark][bridge]") {
    REQUIRE_FALSE(spark_spec_from_rule(make_rule("r", "banana", "whatever", {{"path", "/x"}}))
                      .has_value());
}

TEST_CASE("spark_spec_from_rule: two rules on the same target dedup to one spark_key", "[spark][bridge]") {
    // The whole point of the shared-watcher model: different rule_ids (even with
    // different assertions) watching the same file resolve to ONE spark_key.
    const Rule a = make_rule("rule-a", "file-change", "file-exists", {{"path", "/etc/passwd"}});
    const Rule b = make_rule("rule-b", "file-change", "file-hash-equals",
                             {{"path", "/etc/passwd"}, {"expected_hash", "deadbeef"}});
    const auto sa = spark_spec_from_rule(a);
    const auto sb = spark_spec_from_rule(b);
    REQUIRE(sa.has_value());
    REQUIRE(sb.has_value());
    REQUIRE(spark_key(*sa) == spark_key(*sb));
}

TEST_CASE("classify: a supported event-driven type arms", "[spark][bridge]") {
    const std::set<SparkType> win_caps{SparkType::File, SparkType::Registry, SparkType::Service};
    REQUIRE(classify("file-change", win_caps) == RulePlacement::Arm);
    REQUIRE(classify("registry-change", win_caps) == RulePlacement::Arm);
    REQUIRE(classify("service-status-change", win_caps) == RulePlacement::Arm);
}

TEST_CASE("classify: a known type with no mechanism here is Unsupported, not errored", "[spark][bridge]") {
    // A Linux host: Service only (systemd), no File/Registry mechanism. A
    // cross-platform Baseline's registry/file rules are a ROUTINE miss here.
    const std::set<SparkType> linux_caps{SparkType::Service};
    REQUIRE(classify("registry-change", linux_caps) == RulePlacement::Unsupported);
    REQUIRE(classify("file-change", linux_caps) == RulePlacement::Unsupported);
    REQUIRE(classify("service-status-change", linux_caps) == RulePlacement::Arm);

    // A macOS host: no event-driven Guardian mechanism at all -> everything is
    // Unsupported, still never errored.
    const std::set<SparkType> mac_caps{};
    REQUIRE(classify("service-status-change", mac_caps) == RulePlacement::Unsupported);
    REQUIRE(classify("file-change", mac_caps) == RulePlacement::Unsupported);
}

TEST_CASE("classify: an unknown spark type token is Unrecognized (errored)", "[spark][bridge]") {
    const std::set<SparkType> win_caps{SparkType::File, SparkType::Registry, SparkType::Service};
    // An authoring fault, distinct from a platform miss, regardless of caps.
    REQUIRE(classify("banana", win_caps) == RulePlacement::Unrecognized);
    REQUIRE(classify("", win_caps) == RulePlacement::Unrecognized);
    REQUIRE(classify("banana", {}) == RulePlacement::Unrecognized);
}

TEST_CASE("classify agrees with spark_spec_from_rule on every recognized token (single-source proof)",
          "[spark][bridge]") {
    // rung 7 fix: both functions now call the SAME spark_type_from_token(), so a
    // rule that builds a valid SparkSpec can never simultaneously classify as
    // Unrecognized - this is the invariant Sol's rev-2 review asked to be
    // guaranteed structurally rather than by convention.
    const std::set<SparkType> all_caps{SparkType::File, SparkType::Registry, SparkType::Service};
    for (const auto& [spark_type, atype, params] :
         {std::tuple{std::string("file-change"), std::string("file-exists"),
                     std::pair{std::string("path"), std::string("/x")}},
          std::tuple{std::string("service-status-change"), std::string("service-running"),
                     std::pair{std::string("service_name"), std::string("sshd")}},
          std::tuple{std::string("registry-change"), std::string("registry-value-equals"),
                     std::pair{std::string("hive"), std::string("HKLM")}}}) {
        Rule r = make_rule("r", spark_type, atype, {});
        (*r.mutable_assertion()->mutable_params())[params.first] = params.second;
        if (spark_type == "registry-change")
            (*r.mutable_assertion()->mutable_params())["key"] = "Software\\Yuzu";
        REQUIRE(spark_spec_from_rule(r).has_value());
        REQUIRE(classify(spark_type, all_caps) != RulePlacement::Unrecognized);
    }
}

// ── rule_assertion_from_rule (rung 7.2) ──────────────────────────────────────

TEST_CASE("rule_assertion_from_rule: file-hash-equals round-trips + lowercases the hash",
          "[spark][bridge][assertion]") {
    Rule r = make_rule("r1", "file-change", "file-hash-equals",
                       {{"expected_hash", "DEADBEEF"}, {"max_bytes", "1048576"}});
    r.set_name("my-rule");
    const auto a = rule_assertion_from_rule(r);
    REQUIRE(a.has_value());
    CHECK(a->rule_id == "r1");
    CHECK(a->rule_name == "my-rule");
    CHECK(a->kind == AssertionKind::FileHashEquals);
    CHECK(a->expected_hash == "deadbeef");
    CHECK(a->max_bytes == 1048576);
}

TEST_CASE("rule_assertion_from_rule: max_bytes=0 normalizes to the default, never <everything-oversize>",
          "[spark][bridge][assertion]") {
    const RuleAssertion default_assertion;
    const Rule r = make_rule("r", "file-change", "file-hash-equals", {{"max_bytes", "0"}});
    const auto a = rule_assertion_from_rule(r);
    REQUIRE(a.has_value());
    CHECK(a->max_bytes == default_assertion.max_bytes);
}

TEST_CASE("rule_assertion_from_rule: a malformed max_bytes falls back to the default (whole-string only)",
          "[spark][bridge][assertion]") {
    const RuleAssertion default_assertion;
    const Rule r = make_rule("r", "file-change", "file-hash-equals", {{"max_bytes", "123abc"}});
    const auto a = rule_assertion_from_rule(r);
    REQUIRE(a.has_value());
    CHECK(a->max_bytes == default_assertion.max_bytes); // "123abc" -> default, NOT 123
}

TEST_CASE("rule_assertion_from_rule: an authored max_bytes over the #2233 item 6 ceiling "
          "is clamped, never accepted unbounded",
          "[spark][bridge][assertion]") {
    const std::string over = std::to_string(kMaxFileHashBytes + 1);
    const Rule r = make_rule("r", "file-change", "file-hash-equals", {{"max_bytes", over.c_str()}});
    const auto a = rule_assertion_from_rule(r);
    REQUIRE(a.has_value());
    CHECK(a->max_bytes == kMaxFileHashBytes);
}

TEST_CASE("rule_assertion_from_rule: an authored max_bytes AT the #2233 item 6 ceiling "
          "passes through unclamped",
          "[spark][bridge][assertion]") {
    const std::string at = std::to_string(kMaxFileHashBytes);
    const Rule r = make_rule("r", "file-change", "file-hash-equals", {{"max_bytes", at.c_str()}});
    const auto a = rule_assertion_from_rule(r);
    REQUIRE(a.has_value());
    CHECK(a->max_bytes == kMaxFileHashBytes);
}

TEST_CASE("rule_assertion_from_rule: file-exists defaults to expect_present, 'absent' flips it",
          "[spark][bridge][assertion]") {
    const auto present = rule_assertion_from_rule(make_rule("r", "file-change", "file-exists", {}));
    REQUIRE(present.has_value());
    CHECK(present->kind == AssertionKind::FileExists);
    CHECK(present->expect_present);

    const auto absent = rule_assertion_from_rule(
        make_rule("r", "file-change", "file-exists", {{"expected", "absent"}}));
    REQUIRE(absent.has_value());
    CHECK_FALSE(absent->expect_present);

    const auto other = rule_assertion_from_rule(
        make_rule("r", "file-change", "file-exists", {{"expected", "whatever"}}));
    REQUIRE(other.has_value());
    CHECK(other->expect_present); // only the literal "absent" flips it
}

TEST_CASE("rule_assertion_from_rule: service-running / service-stopped map to distinct kinds",
          "[spark][bridge][assertion]") {
    const auto running = rule_assertion_from_rule(
        make_rule("r", "service-status-change", "service-running", {}));
    REQUIRE(running.has_value());
    CHECK(running->kind == AssertionKind::ServiceRunning);

    const auto stopped = rule_assertion_from_rule(
        make_rule("r", "service-status-change", "service-stopped", {}));
    REQUIRE(stopped.has_value());
    CHECK(stopped->kind == AssertionKind::ServiceStopped);
}

TEST_CASE("rule_assertion_from_rule: registry-value-equals reads expected + value_name",
          "[spark][bridge][assertion]") {
    const Rule r = make_rule("r", "registry-change", "registry-value-equals",
                             {{"expected", "1"}, {"value_name", "Flag"}});
    const auto a = rule_assertion_from_rule(r);
    REQUIRE(a.has_value());
    CHECK(a->kind == AssertionKind::RegistryEquals);
    CHECK(a->expected_value == "1");
    CHECK(a->value_name == "Flag");
}

TEST_CASE("rule_assertion_from_rule: debounce_ms is sourced from the remediation block",
          "[spark][bridge][assertion]") {
    Rule r = make_rule("r", "file-change", "file-exists", {});
    set_remediation_param(r, "event_debounce_ms", "5000");
    const auto a = rule_assertion_from_rule(r);
    REQUIRE(a.has_value());
    CHECK(a->debounce_ms == 5000);
}

TEST_CASE("rule_assertion_from_rule: absent event_debounce_ms defaults per-lane, not to "
          "legacy's flat 1000ms (#3388)",
          "[spark][bridge][assertion]") {
    // No event_debounce_ms set on any of these - forces the fallback path. Legacy's
    // 1000ms default (still used by every guard_*.cpp call site, unaffected by this
    // change) expires before every convergence sweep (60s/600s), so a persistently-
    // drifted rule re-emitted on every single sweep. The lane-aware default is each
    // lane's own cadence + the scheduler's jitter margin (spark.hpp), so debounce
    // reliably survives at least one full sweep even at the jitter-shortened extreme.
    SECTION("file lane: 600s cadence + 20% jitter margin = 720s") {
        const auto a = rule_assertion_from_rule(make_rule("r", "file-change", "file-exists", {}));
        REQUIRE(a.has_value());
        CHECK(a->debounce_ms == 720'000);
    }
    SECTION("registry lane: 60s cadence + 20% jitter margin = 72s") {
        const auto a = rule_assertion_from_rule(
            make_rule("r", "registry-change", "registry-value-equals",
                     {{"hive", "HKLM"}, {"key", "Software\\Yuzu"}}));
        REQUIRE(a.has_value());
        CHECK(a->debounce_ms == 72'000);
    }
    SECTION("service lane: 60s cadence + 20% jitter margin = 72s") {
        const auto a = rule_assertion_from_rule(
            make_rule("r", "service-status-change", "service-running", {{"service_name", "sshd"}}));
        REQUIRE(a.has_value());
        CHECK(a->debounce_ms == 72'000);
    }
    SECTION("an explicit event_debounce_ms still overrides the lane default") {
        Rule r = make_rule("r", "registry-change", "registry-value-equals",
                          {{"hive", "HKLM"}, {"key", "Software\\Yuzu"}});
        set_remediation_param(r, "event_debounce_ms", "5000");
        const auto a = rule_assertion_from_rule(r);
        REQUIRE(a.has_value());
        CHECK(a->debounce_ms == 5000); // author's explicit value, not the 72s lane default
    }
}

TEST_CASE("rule_assertion_from_rule: an unrecognized spark type is an error",
          "[spark][bridge][assertion]") {
    const auto a = rule_assertion_from_rule(make_rule("r", "banana", "file-exists", {}));
    REQUIRE_FALSE(a.has_value());
}

TEST_CASE("rule_assertion_from_rule: a spark-type/assertion-type mismatch is an error, "
          "never a fabricated FileExists",
          "[spark][bridge][assertion]") {
    // A file-change rule asserting a SERVICE predicate: RuleAssertion::kind
    // defaults to FileExists, so an infallible converter would silently turn
    // this into a real (wrong) file-exists evaluation. It must be rejected.
    const auto a = rule_assertion_from_rule(
        make_rule("r", "file-change", "service-running", {}));
    REQUIRE_FALSE(a.has_value());
}

TEST_CASE("rule_assertion_from_rule: an unrecognized assertion type per spark type is an error",
          "[spark][bridge][assertion]") {
    REQUIRE_FALSE(rule_assertion_from_rule(make_rule("r", "file-change", "bogus", {})).has_value());
    REQUIRE_FALSE(
        rule_assertion_from_rule(make_rule("r", "service-status-change", "bogus", {})).has_value());
    REQUIRE_FALSE(
        rule_assertion_from_rule(make_rule("r", "registry-change", "bogus", {})).has_value());
    REQUIRE_FALSE(
        rule_assertion_from_rule(make_rule("r", "registry-change", "file-exists", {})).has_value());
}
