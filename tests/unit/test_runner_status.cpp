// runner_status.hpp is the ONE mapping from a bounded-runner outcome to the
// ABI4 plugin->host result seam (Wave 2, ADR-3002). classify_runner_failure
// is pure (no context, no spawn), so every TerminationReason branch is
// fixture-testable here without a live subprocess.
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/runner_status.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.h>

#include <set>
#include <string>

using yuzu::agent::classify_runner_failure;
using yuzu::agent::SubprocessResult;
using yuzu::agent::TerminationReason;

namespace {

SubprocessResult result_with(TerminationReason reason) {
    SubprocessResult r;
    r.termination_reason = reason;
    return r;
}

} // namespace

TEST_CASE("classify_runner_failure: spawn_error -> UNAVAILABLE/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::spawn_error));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:spawn_error");
}

TEST_CASE("classify_runner_failure: deadline -> CONSTRAINED/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::deadline));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:deadline");
}

TEST_CASE("classify_runner_failure: cancelled -> CONSTRAINED/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::cancelled));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:cancelled");
}

TEST_CASE("classify_runner_failure: signaled -> CONSTRAINED/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::signaled));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:signaled");
}

TEST_CASE("classify_runner_failure: exited -> nullopt (caller owns exit-code semantics)",
         "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::exited));
    CHECK_FALSE(s.has_value());
}

TEST_CASE("classify_runner_failure: line_limit -> OK/PARTIAL, reason preserved",
         "[agent][runner_status]") {
    // ADR-3002 "Honest termination reporting" names line_limit in the reason
    // enum and requires the reason to survive to the wire, naming the plugin
    // execute() integer return as the narrowing point that must not flatten
    // it. An earlier cut grouped line_limit with `exited` and returned
    // nullopt, so a run deliberately cut at N lines was indistinguishable
    // from one that completed (/adversarial-review Codex CDX-4, Kimi F7).
    const auto s = classify_runner_failure(result_with(TerminationReason::line_limit));
    REQUIRE(s.has_value());
    // OK, not CONSTRAINED: a bounded stop is a SUCCESSFUL bounded read, and
    // calling it constrained would make every capped request look degraded.
    CHECK(s->status == YUZU_RESULT_STATUS_OK);
    // PARTIAL, because output was deliberately truncated.
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(s->completeness != YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(std::string(s->provenance) == "subprocess_runner:line_limit");
}

TEST_CASE("classify_runner_failure: every non-exited reason carries a distinct provenance",
         "[agent][runner_status]") {
    // The reason enum exists so an autonomous consumer can tell "killed at
    // deadline" (escalate) from "spawn error" (never retry) from a bounded
    // stop. Shared or missing tags collapse those decisions.
    const TerminationReason reasons[] = {
        TerminationReason::spawn_error, TerminationReason::deadline,
        TerminationReason::cancelled,   TerminationReason::signaled,
        TerminationReason::line_limit,
    };
    std::set<std::string> seen;
    for (auto r : reasons) {
        const auto s = classify_runner_failure(result_with(r));
        REQUIRE(s.has_value()); // only `exited` may be nullopt
        CHECK(seen.insert(std::string(s->provenance)).second); // no duplicates
    }
    CHECK(seen.size() == 5);
}
