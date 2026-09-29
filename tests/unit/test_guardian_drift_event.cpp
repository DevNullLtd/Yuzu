// Unit tests for apply_drift_to_event (ADR-0021 rung 7.7b, PR-1 item 1 / #2237): the
// single shared GuardDrift -> GuaranteedStateEvent compliance-field mapping that both
// the legacy GuardianEngine::emit_guard_event path and the spark consumer's Compliance
// branch now call. These pin the 4-way event_type cascade + drift_rate, prove the
// helper leaves the caller-owned idempotency/host fields untouched, and cross-check
// that the spark send path produces the same drift fields (the extraction's whole point).

#include "guardian_drift_event.hpp"
#include "guardian_outbox.hpp"     // OutboxEntry + GuardDrift
#include "guardian_spark_send.hpp" // guardian_outbox_entry_to_event

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::agent;
namespace gpb = ::yuzu::guardian::v1;

namespace {

GuardDrift base_drift() {
    GuardDrift d;
    d.rule_id = "r-1";
    d.rule_name = "No debugger";
    d.guard_type = "registry";
    d.detected_value = "1";
    d.expected_value = "0";
    d.detection_latency_us = 4242;
    return d;
}

} // namespace

TEST_CASE("drift-map: plain drift -> drift.detected, fields copied", "[guardian][driftmap]") {
    gpb::GuaranteedStateEvent ev;
    apply_drift_to_event(base_drift(), ev);

    CHECK(ev.event_type() == "drift.detected");
    CHECK(ev.rule_name() == "No debugger");
    CHECK(ev.guard_type() == "registry");
    CHECK(ev.detected_value() == "1");
    CHECK(ev.expected_value() == "0");
    CHECK(ev.detection_latency_us() == 4242);
    // No remediation attempted -> remediation fields stay default.
    CHECK(ev.remediation_action().empty());
    CHECK_FALSE(ev.remediation_success());
    // collapsed_count 0 -> drift_rate not set (stays 0.0).
    CHECK(ev.drift_rate() == 0.0);
}

TEST_CASE("drift-map: compliant edge -> guard.compliant, no remediation", "[guardian][driftmap]") {
    GuardDrift d = base_drift();
    d.compliant = true;
    d.remediation_attempted = true; // must be IGNORED on a compliant edge
    d.remediation_action = "should-not-appear";

    gpb::GuaranteedStateEvent ev;
    apply_drift_to_event(d, ev);

    CHECK(ev.event_type() == "guard.compliant");
    CHECK(ev.remediation_action().empty()); // compliant branch wins, no write-back fields
}

TEST_CASE("drift-map: remediation success/failure taxonomy", "[guardian][driftmap]") {
    SECTION("success -> drift.remediated") {
        GuardDrift d = base_drift();
        d.remediation_attempted = true;
        d.remediation_success = true;
        d.remediation_action = "set-value";
        d.remediation_latency_us = 99;

        gpb::GuaranteedStateEvent ev;
        apply_drift_to_event(d, ev);

        CHECK(ev.event_type() == "drift.remediated");
        CHECK(ev.remediation_action() == "set-value");
        CHECK(ev.remediation_success());
        CHECK(ev.remediation_latency_us() == 99);
    }
    SECTION("failure -> remediation.failed") {
        GuardDrift d = base_drift();
        d.remediation_attempted = true;
        d.remediation_success = false;

        gpb::GuaranteedStateEvent ev;
        apply_drift_to_event(d, ev);

        CHECK(ev.event_type() == "remediation.failed");
        CHECK_FALSE(ev.remediation_success());
    }
}

TEST_CASE("drift-map: collapsed_count surfaces as drift_rate", "[guardian][driftmap]") {
    GuardDrift d = base_drift();
    d.collapsed_count = 5;

    gpb::GuaranteedStateEvent ev;
    apply_drift_to_event(d, ev);

    CHECK(ev.drift_rate() == 5.0);
}

TEST_CASE("drift-map: leaves the caller-owned idempotency/host fields untouched",
          "[guardian][driftmap]") {
    // Pre-seed the fields each caller stamps itself; the helper must not clobber them.
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id("evt-xyz");
    ev.set_rule_id("caller-rule");
    ev.set_guard_category("event");
    ev.set_platform("linux");
    ev.mutable_timestamp()->set_seconds(1234);

    apply_drift_to_event(base_drift(), ev);

    CHECK(ev.event_id() == "evt-xyz");
    CHECK(ev.rule_id() == "caller-rule");
    CHECK(ev.guard_category() == "event");
    CHECK(ev.platform() == "linux");
    CHECK(ev.timestamp().seconds() == 1234);
}

TEST_CASE("drift-map: spark send path produces the same drift fields", "[guardian][driftmap]") {
    // The extraction's guarantee: the spark Compliance branch and the shared helper
    // agree field-for-field on everything drift-derived. (event_id/rule_id/timestamp/
    // platform differ by design and are asserted untouched above / in [sendmap].)
    GuardDrift d = base_drift();
    d.remediation_attempted = true;
    d.remediation_success = false;
    d.collapsed_count = 3;

    gpb::GuaranteedStateEvent direct;
    apply_drift_to_event(d, direct);

    auto entry = OutboxEntry::compliance("r-1", 7, "evt-abc", 1'609'459'200'500'000'000LL, d);
    gpb::GuaranteedStateEvent via_send = guardian_outbox_entry_to_event(entry, "linux");

    CHECK(direct.event_type() == via_send.event_type());
    CHECK(direct.rule_name() == via_send.rule_name());
    CHECK(direct.guard_type() == via_send.guard_type());
    CHECK(direct.detected_value() == via_send.detected_value());
    CHECK(direct.expected_value() == via_send.expected_value());
    CHECK(direct.detection_latency_us() == via_send.detection_latency_us());
    CHECK(direct.remediation_action() == via_send.remediation_action());
    CHECK(direct.remediation_success() == via_send.remediation_success());
    CHECK(direct.remediation_latency_us() == via_send.remediation_latency_us());
    CHECK(direct.drift_rate() == via_send.drift_rate());
}
