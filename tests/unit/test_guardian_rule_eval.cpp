// test_guardian_rule_eval.cpp - the per-type Guardian rule evaluators (ADR-0021
// rung 2). Synthetic tri-state reads + injected clock, so every branch is
// exercised off-platform. Asserts the compliant/drift verdict, the emitted
// detected/expected token vocabulary (parity), guard_type, the tri-state Unknown
// path (EmitDeciderState untouched, health detail carried), the recovery-forces-a-
// verdict rule, and per-rule oversize projection off a shared file snapshot.

#include "guardian_rule_eval.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <limits>
#include <string>

using namespace yuzu::agent;

namespace {
using clock = std::chrono::steady_clock;
constexpr clock::time_point kT0{};
clock::time_point at_ms(std::uint64_t ms) { return kT0 + std::chrono::milliseconds(ms); }

RuleAssertion file_exists(bool expect_present) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = "r";
    a.expect_present = expect_present;
    return a;
}
RuleAssertion file_hash(const std::string& expected_hash) {
    RuleAssertion a;
    a.kind = AssertionKind::FileHashEquals;
    a.rule_id = "r";
    a.expected_hash = expected_hash;
    return a;
}
RuleAssertion registry_eq(const std::string& expected) {
    RuleAssertion a;
    a.kind = AssertionKind::RegistryEquals;
    a.rule_id = "r";
    a.expected_value = expected;
    return a;
}
RuleAssertion service(AssertionKind k) {
    RuleAssertion a;
    a.kind = k;
    a.rule_id = "r";
    return a;
}
} // namespace

TEST_CASE("eval_file file-exists: present-as-expected is a compliant edge", "[spark][eval]") {
    const auto a = file_exists(true);
    RuleEvalState s;
    const auto out = eval_file(a, read_known(FileSnapshot{.exists = true}), s, at_ms(0));
    REQUIRE(out.status == EvalStatus::Emit);
    REQUIRE(out.drift.guard_type == "file");
    REQUIRE(out.drift.compliant);
    REQUIRE(out.drift.detected_value == "<present>");
    REQUIRE(out.drift.expected_value == "<present>");
}

TEST_CASE("eval_file file-exists: a missing file drifts", "[spark][eval]") {
    const auto a = file_exists(true);
    RuleEvalState s;
    const auto out = eval_file(a, read_known(FileSnapshot{.exists = false}), s, at_ms(0));
    REQUIRE(out.status == EvalStatus::Emit);
    REQUIRE_FALSE(out.drift.compliant);
    REQUIRE(out.drift.detected_value == "<absent>");
    REQUIRE(out.drift.expected_value == "<present>");
}

TEST_CASE("eval_file file-hash: baseline-on-arm captures + reads compliant, steady is silent",
          "[spark][eval]") {
    const auto a = file_hash(""); // empty -> baseline on arm
    RuleEvalState s;
    const FileSnapshot snap{.exists = true, .size = 10, .hash = "abc123"};
    const auto first = eval_file(a, read_known(snap), s, at_ms(0));
    REQUIRE(first.status == EvalStatus::Emit);
    REQUIRE(first.drift.compliant);
    REQUIRE(first.drift.detected_value == "abc123");
    REQUIRE(first.drift.expected_value == "abc123"); // baseline == the captured hash
    REQUIRE(s.baseline_set);
    // Same hash again -> steady compliant -> silent.
    REQUIRE(eval_file(a, read_known(snap), s, at_ms(10)).status == EvalStatus::Silent);
    // A changed hash drifts against the captured baseline.
    const FileSnapshot changed{.exists = true, .size = 10, .hash = "def456"};
    const auto drift = eval_file(a, read_known(changed), s, at_ms(20));
    REQUIRE(drift.status == EvalStatus::Emit);
    REQUIRE_FALSE(drift.drift.compliant);
    REQUIRE(drift.drift.detected_value == "def456");
    REQUIRE(drift.drift.expected_value == "abc123");
}

TEST_CASE("eval_file file-hash: unreadable / absent surface distinct tokens", "[spark][eval]") {
    const auto a = file_hash("expected");
    {
        RuleEvalState s;
        const auto out =
            eval_file(a, read_known(FileSnapshot{.exists = true, .readable = false}), s, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE(out.drift.detected_value == "<unreadable>");
    }
    {
        RuleEvalState s;
        const auto out = eval_file(a, read_known(FileSnapshot{.exists = false}), s, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE(out.drift.detected_value == "<absent>");
    }
    {
        // Present + readable + admitting size but no digest = "can't verify", not a
        // silent match.
        RuleEvalState s;
        const auto out = eval_file(
            a, read_known(FileSnapshot{.exists = true, .size = 4, .hash = ""}), s, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE(out.drift.detected_value == "<unreadable>");
    }
}

TEST_CASE("eval_file file-hash: oversize is projected PER-RULE off one shared snapshot",
          "[spark][eval]") {
    // One key-relative read (size 100). A rule with a 50-byte cap calls it oversize;
    // a rule with a 200-byte cap admits it and compares the hash.
    const FileSnapshot big{.exists = true, .size = 100, .hash = "sha"};
    {
        auto a = file_hash("sha");
        a.max_bytes = 50;
        RuleEvalState s;
        const auto out = eval_file(a, read_known(big), s, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE_FALSE(out.drift.compliant);
        REQUIRE(out.drift.detected_value == "<oversize>");
    }
    {
        auto a = file_hash("sha");
        a.max_bytes = 200;
        RuleEvalState s;
        const auto out = eval_file(a, read_known(big), s, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE(out.drift.compliant); // admits -> hash matches -> compliant edge
        REQUIRE(out.drift.detected_value == "sha");
    }
}

TEST_CASE("eval_registry: value match is compliant; mismatch/absent/unsupported drift",
          "[spark][eval]") {
    const auto a = registry_eq("1");
    {
        RuleEvalState s;
        const auto out =
            eval_registry(a, read_known(RegistrySnapshot{.present = true, .value = "1"}), s, 42,
                          at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE(out.drift.guard_type == "registry");
        REQUIRE(out.drift.compliant);
        REQUIRE(out.drift.detected_value == "1");
        REQUIRE(out.drift.expected_value == "1");
        REQUIRE(out.drift.detection_latency_us == 42);
    }
    {
        RuleEvalState s;
        const auto out = eval_registry(
            a, read_known(RegistrySnapshot{.present = true, .value = "0"}), s, 0, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE_FALSE(out.drift.compliant);
        REQUIRE(out.drift.detected_value == "0");
    }
    {
        RuleEvalState s;
        const auto out =
            eval_registry(a, read_known(RegistrySnapshot{.present = false}), s, 0, at_ms(0));
        REQUIRE(out.drift.detected_value == "<absent>");
    }
    {
        RuleEvalState s;
        const auto out = eval_registry(
            a, read_known(RegistrySnapshot{.present = true, .supported = false}), s, 0, at_ms(0));
        REQUIRE(out.drift.detected_value == "<unsupported-type>");
    }
}

TEST_CASE("eval_service: running/stopped verdict + tokens", "[spark][eval]") {
    {
        const auto a = service(AssertionKind::ServiceRunning);
        RuleEvalState s;
        const auto out = eval_service(a, read_known(ServiceRunState::Running), s, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE(out.drift.guard_type == "service");
        REQUIRE(out.drift.compliant);
        REQUIRE(out.drift.detected_value == "running");
        REQUIRE(out.drift.expected_value == "running");
        // A stopped service drifts a service-running rule.
        const auto drift = eval_service(a, read_known(ServiceRunState::Stopped), s, at_ms(10));
        REQUIRE(drift.status == EvalStatus::Emit);
        REQUIRE_FALSE(drift.drift.compliant);
        REQUIRE(drift.drift.detected_value == "stopped");
    }
    {
        const auto a = service(AssertionKind::ServiceStopped);
        RuleEvalState s;
        // Paused drifts a service-stopped rule (paused != stopped).
        const auto out = eval_service(a, read_known(ServiceRunState::Paused), s, at_ms(0));
        REQUIRE(out.status == EvalStatus::Emit);
        REQUIRE_FALSE(out.drift.compliant);
        REQUIRE(out.drift.detected_value == "paused");
        REQUIRE(out.drift.expected_value == "stopped");
    }
}

TEST_CASE("eval_service: emit_compliant_edge=false keeps compliant silent (systemd parity)",
          "[spark][eval]") {
    const auto a = service(AssertionKind::ServiceRunning);
    RuleEvalState s;
    REQUIRE(eval_service(a, read_known(ServiceRunState::Running), s, at_ms(0),
                         /*emit_compliant_edge=*/false)
                .status == EvalStatus::Silent);
}

TEST_CASE("Unknown read is Unhealthy and leaves EmitDeciderState untouched", "[spark][eval]") {
    const auto a = file_exists(true);
    RuleEvalState s;
    // Establish a committed compliant verdict first.
    REQUIRE(eval_file(a, read_known(FileSnapshot{.exists = true}), s, at_ms(0)).status ==
            EvalStatus::Emit);
    REQUIRE(s.emit.last_compliant == true);
    // Now a read failure: Unhealthy, detail carried, decider state NOT moved.
    const auto out = eval_file(a, read_unknown<FileSnapshot>("io error"), s, at_ms(10));
    REQUIRE(out.status == EvalStatus::Unhealthy);
    REQUIRE(out.health_detail == "io error");
    REQUIRE(s.emit.last_compliant == true); // untouched
    REQUIRE(s.in_unknown);                  // recovery-force armed
}

TEST_CASE("initial Unknown (never evaluated) is Unhealthy, never a false compliant",
          "[spark][eval]") {
    const auto a = registry_eq("1");
    RuleEvalState s;
    const auto out = eval_registry(a, read_unknown<RegistrySnapshot>("denied"), s, 0, at_ms(0));
    REQUIRE(out.status == EvalStatus::Unhealthy);
    REQUIRE(out.health_detail == "denied");
    REQUIRE_FALSE(s.emit.last_compliant.has_value()); // still never-evaluated
    REQUIRE(s.in_unknown);
}

TEST_CASE("service read failure is Unknown, distinct from a stopped service", "[spark][eval]") {
    const auto a = service(AssertionKind::ServiceRunning);
    RuleEvalState s;
    const auto out = eval_service(a, read_unknown<ServiceRunState>("scm timeout"), s, at_ms(0));
    REQUIRE(out.status == EvalStatus::Unhealthy);
    REQUIRE_FALSE(s.emit.last_compliant.has_value());
}

TEST_CASE("Unknown is edge-flagged: first errors, repeats are not edges, recovery re-arms it (M1)",
          "[spark][eval]") {
    const auto a = file_exists(true);
    RuleEvalState s;
    // First Unknown of an episode -> edge (the runtime emits guard.unhealthy on this one).
    const auto first = eval_file(a, read_unknown<FileSnapshot>("io"), s, at_ms(0));
    REQUIRE(first.status == EvalStatus::Unhealthy);
    REQUIRE(first.unhealthy_edge);
    REQUIRE(s.in_unknown);
    // A repeat Unknown while already errored -> NOT an edge (the runtime suppresses + counts,
    // so a rule stuck errored does not re-mint a health event every ~5s convergence tick).
    const auto again = eval_file(a, read_unknown<FileSnapshot>("io"), s, at_ms(10));
    REQUIRE(again.status == EvalStatus::Unhealthy);
    REQUIRE_FALSE(again.unhealthy_edge);
    REQUIRE(s.in_unknown);
    // Recovery clears the episode; the NEXT Unknown is a fresh edge again, so the health
    // stream re-errors after a recovery instead of staying silent forever.
    REQUIRE(eval_file(a, read_known(FileSnapshot{.exists = true}), s, at_ms(20)).status ==
            EvalStatus::Emit);
    REQUIRE_FALSE(s.in_unknown);
    const auto reerr = eval_file(a, read_unknown<FileSnapshot>("io"), s, at_ms(30));
    REQUIRE(reerr.status == EvalStatus::Unhealthy);
    REQUIRE(reerr.unhealthy_edge);
}

TEST_CASE("recovery from Unknown FORCES a compliant edge even when unchanged", "[spark][eval]") {
    const auto a = file_exists(true);
    RuleEvalState s;
    REQUIRE(eval_file(a, read_known(FileSnapshot{.exists = true}), s, at_ms(0)).status ==
            EvalStatus::Emit); // compliant edge
    // Steady compliant would normally be silent...
    REQUIRE(eval_file(a, read_known(FileSnapshot{.exists = true}), s, at_ms(10)).status ==
            EvalStatus::Silent);
    // ...but after an Unknown gap the next Known compliant re-emits the edge so the
    // server re-learns compliance after the errored gap.
    REQUIRE(eval_file(a, read_unknown<FileSnapshot>("io"), s, at_ms(20)).status ==
            EvalStatus::Unhealthy);
    const auto recovered = eval_file(a, read_known(FileSnapshot{.exists = true}), s, at_ms(30));
    REQUIRE(recovered.status == EvalStatus::Emit);
    REQUIRE(recovered.drift.compliant);
    REQUIRE_FALSE(s.in_unknown); // cleared by the forced verdict
}

TEST_CASE("recovery from Unknown FORCES a drift even inside the debounce window", "[spark][eval]") {
    auto a = file_exists(true);
    a.debounce_ms = 1000;
    // Control: two drifts inside one debounce window fold - the second is silent.
    {
        RuleEvalState s;
        REQUIRE(eval_file(a, read_known(FileSnapshot{.exists = false}), s, at_ms(0)).status ==
                EvalStatus::Emit);
        REQUIRE(eval_file(a, read_known(FileSnapshot{.exists = false}), s, at_ms(100)).status ==
                EvalStatus::Silent);
    }
    // With an Unknown between them, the post-recovery drift emits despite being inside
    // the window.
    {
        RuleEvalState s;
        REQUIRE(eval_file(a, read_known(FileSnapshot{.exists = false}), s, at_ms(0)).status ==
                EvalStatus::Emit);
        REQUIRE(eval_file(a, read_unknown<FileSnapshot>("io"), s, at_ms(50)).status ==
                EvalStatus::Unhealthy);
        const auto recovered =
            eval_file(a, read_known(FileSnapshot{.exists = false}), s, at_ms(100));
        REQUIRE(recovered.status == EvalStatus::Emit);
        REQUIRE_FALSE(recovered.drift.compliant);
    }
}

// ── clamp_max_hash_bytes (#2233 item 6) ──────────────────────────────────────

TEST_CASE("clamp_max_hash_bytes: over the ceiling clamps to it", "[guardian][rule_eval]") {
    CHECK(clamp_max_hash_bytes(kMaxFileHashBytes + 1) == kMaxFileHashBytes);
    CHECK(clamp_max_hash_bytes(std::numeric_limits<std::uint64_t>::max()) == kMaxFileHashBytes);
}

TEST_CASE("clamp_max_hash_bytes: at or under the ceiling passes through unchanged",
          "[guardian][rule_eval]") {
    CHECK(clamp_max_hash_bytes(kMaxFileHashBytes) == kMaxFileHashBytes);
    CHECK(clamp_max_hash_bytes(kMaxFileHashBytes - 1) == kMaxFileHashBytes - 1);
    CHECK(clamp_max_hash_bytes(0) == 0); // the ceiling is not the 0->default normalizer's job
    CHECK(clamp_max_hash_bytes(64ull * 1024 * 1024) == 64ull * 1024 * 1024); // the default itself
}

TEST_CASE("kMaxFileHashBytes: generous relative to the default, bounded well under a "
          "32-bit size_t (guard_file.cpp's static_cast truncation point)",
          "[guardian][rule_eval]") {
    CHECK(kMaxFileHashBytes > 64ull * 1024 * 1024); // strictly above the default - a real ceiling
    CHECK(kMaxFileHashBytes < 4ull * 1024 * 1024 * 1024); // headroom under the 32-bit size_t boundary
}
