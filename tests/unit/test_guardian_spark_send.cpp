// Unit tests for guardian_outbox_entry_to_event (ADR-0021 rung 7.7a): the pure
// OutboxEntry -> GuaranteedStateEvent mapping. Production never invokes this at 7.7a
// (prefer_spark is false, the outbox stays empty), so these tests ARE the proof the
// send path is correct before rung 7.7b turns on rule placement.

#include "guardian_spark_send.hpp"
#include "guardian_outbox.hpp" // OutboxEntry + GuardDrift (via <yuzu/agent/guard.hpp>)

#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::agent;

namespace {

// A representative wall-clock nanosecond stamp: 2021-01-01T00:00:00.5Z.
constexpr std::int64_t kEnq = 1'609'459'200'000'000'000LL + 500'000'000LL;

} // namespace

TEST_CASE("send-map: common fields are taken verbatim from the entry", "[spark][sendmap]") {
    auto e = OutboxEntry::health("rule-1", 7, "evt-abc", kEnq, /*healthy=*/true, "");
    auto ev = guardian_outbox_entry_to_event(e, "linux");

    // event_id and rule_id are NOT rebuilt - they are the entry's wire-idempotency key.
    CHECK(ev.event_id() == "evt-abc");
    CHECK(ev.rule_id() == "rule-1");
    CHECK(ev.guard_category() == "event");
    CHECK(ev.platform() == "linux");
    // enqueued_ns split into seconds + nanos, NOT a fresh now().
    CHECK(ev.timestamp().seconds() == 1'609'459'200LL);
    CHECK(ev.timestamp().nanos() == 500'000'000);
}

TEST_CASE("send-map: Compliance drift maps like the legacy emit_guard_event", "[spark][sendmap]") {
    GuardDrift d;
    d.rule_id = "r";
    d.rule_name = "No debugger";
    d.guard_type = "registry";
    d.detected_value = "1";
    d.expected_value = "0";
    d.detection_latency_us = 42;

    SECTION("plain drift") {
        auto e = OutboxEntry::compliance("r", 1, "id", kEnq, d);
        auto ev = guardian_outbox_entry_to_event(e, "windows");
        CHECK(ev.event_type() == "drift.detected");
        CHECK(ev.rule_name() == "No debugger");
        CHECK(ev.guard_type() == "registry");
        CHECK(ev.detected_value() == "1");
        CHECK(ev.expected_value() == "0");
        CHECK(ev.detection_latency_us() == 42);
        CHECK(ev.drift_rate() == 0.0); // no collapse
    }

    SECTION("compliant edge carries no remediation") {
        d.compliant = true;
        auto ev = guardian_outbox_entry_to_event(OutboxEntry::compliance("r", 1, "id", kEnq, d),
                                                 "windows");
        CHECK(ev.event_type() == "guard.compliant");
        CHECK(ev.remediation_action().empty());
    }

    SECTION("remediation success -> drift.remediated") {
        d.remediation_attempted = true;
        d.remediation_success = true;
        d.remediation_action = "restore";
        d.remediation_latency_us = 99;
        auto ev = guardian_outbox_entry_to_event(OutboxEntry::compliance("r", 1, "id", kEnq, d),
                                                 "windows");
        CHECK(ev.event_type() == "drift.remediated");
        CHECK(ev.remediation_action() == "restore");
        CHECK(ev.remediation_success() == true);
        CHECK(ev.remediation_latency_us() == 99);
    }

    SECTION("remediation failure -> remediation.failed") {
        d.remediation_attempted = true;
        d.remediation_success = false;
        auto ev = guardian_outbox_entry_to_event(OutboxEntry::compliance("r", 1, "id", kEnq, d),
                                                 "windows");
        CHECK(ev.event_type() == "remediation.failed");
        CHECK(ev.remediation_success() == false);
    }

    SECTION("collapsed_count surfaces as drift_rate") {
        d.collapsed_count = 5;
        auto ev = guardian_outbox_entry_to_event(OutboxEntry::compliance("r", 1, "id", kEnq, d),
                                                 "windows");
        CHECK(ev.drift_rate() == 5.0);
    }
}

TEST_CASE("send-map: Health maps healthy/unhealthy and carries detail only when unhealthy",
          "[spark][sendmap]") {
    SECTION("recovered") {
        auto ev = guardian_outbox_entry_to_event(
            OutboxEntry::health("r", 1, "id", kEnq, /*healthy=*/true, "ignored"), "macos");
        CHECK(ev.event_type() == "guard.healthy");
        CHECK(ev.detail_json().empty()); // detail is not carried on a healthy edge
    }
    SECTION("unhealthy carries the read-error detail as valid JSON") {
        auto ev = guardian_outbox_entry_to_event(
            OutboxEntry::health("r", 1, "id", kEnq, /*healthy=*/false, "EACCES on hive"), "macos");
        CHECK(ev.event_type() == "guard.unhealthy");
        // detail_json is a JSON object, not a bare string - the field is defined as JSON.
        CHECK(ev.detail_json() == R"({"detail":"EACCES on hive"})");
        CHECK(nlohmann::json::parse(ev.detail_json())["detail"] == "EACCES on hive");
    }
    SECTION("unhealthy with empty detail carries no detail_json") {
        auto ev = guardian_outbox_entry_to_event(
            OutboxEntry::health("r", 1, "id", kEnq, /*healthy=*/false, ""), "macos");
        CHECK(ev.event_type() == "guard.unhealthy");
        CHECK(ev.detail_json().empty()); // no {"detail":""} noise
    }
    SECTION("unhealthy detail with non-UTF-8 bytes still serializes (no throw / no outbox jam)") {
        // A Linux filesystem path in a read-error can carry non-UTF-8 bytes; the mapping
        // must not throw (which would jam the outbox drain head permanently).
        std::string bad = "bad path \xff\xfe";
        auto ev = guardian_outbox_entry_to_event(
            OutboxEntry::health("r", 1, "id", kEnq, /*healthy=*/false, bad), "linux");
        CHECK(ev.event_type() == "guard.unhealthy");
        CHECK_FALSE(ev.detail_json().empty());
        CHECK_NOTHROW(nlohmann::json::parse(ev.detail_json())); // valid JSON (U+FFFD substituted)
    }
}

TEST_CASE("send-map: a negative/pre-epoch enqueued_ns yields a valid (non-negative nanos) Timestamp",
          "[spark][sendmap]") {
    // A badly-skewed / pre-1970 wall clock produces a negative enqueued_ns. The
    // well-known Timestamp requires nanos in [0, 1e9): the mapping must normalize
    // rather than emit a negative nanos some consumers reject.
    const std::int64_t neg = -500'000'000; // 0.5s before the epoch
    auto ev = guardian_outbox_entry_to_event(
        OutboxEntry::lifecycle("r", 1, "id", neg, "armed"), "linux");
    CHECK(ev.timestamp().nanos() >= 0);
    CHECK(ev.timestamp().nanos() < 1'000'000'000);
    CHECK(ev.timestamp().seconds() == -1);          // floored
    CHECK(ev.timestamp().nanos() == 500'000'000);   // -0.5s == -1s + 0.5s
}

TEST_CASE("send-map: Lifecycle kind becomes guard.<kind>", "[spark][sendmap]") {
    for (const auto& kind : {"armed", "disarmed", "errored"}) {
        auto ev = guardian_outbox_entry_to_event(
            OutboxEntry::lifecycle("r", 1, "id", kEnq, kind), "linux");
        CHECK(ev.event_type() == std::string("guard.") + kind);
    }
}

TEST_CASE("send-map: Health + Lifecycle carry guard_type/rule_name (PR-1 item 2)",
          "[spark][sendmap]") {
    SECTION("Health") {
        auto ev = guardian_outbox_entry_to_event(
            OutboxEntry::health("r", 1, "id", kEnq, /*healthy=*/false, "EACCES", "file",
                                "Hosts file integrity"),
            "linux");
        CHECK(ev.guard_type() == "file");
        CHECK(ev.rule_name() == "Hosts file integrity");
    }
    SECTION("Lifecycle") {
        auto ev = guardian_outbox_entry_to_event(
            OutboxEntry::lifecycle("r", 1, "id", kEnq, "armed", "registry", "No debugger"),
            "linux");
        CHECK(ev.guard_type() == "registry");
        CHECK(ev.rule_name() == "No debugger");
    }
}

TEST_CASE("send-map: journal-replay provenance NEVER reaches the wire event (item 7 PR-Ag A-2)",
          "[spark][sendmap]") {
    // journal_batch_key / journal_last_in_batch are LOCAL replay provenance for the sent-label. If
    // they ever leaked onto the wire they would flip the server's redelivery compare to a false
    // Conflict on every replay (the M6 channel). Pin that guardian_outbox_entry_to_event ignores
    // them - a guardrail against a future OutboxEntry->event mapping change (architect A-2).
    auto e = OutboxEntry::lifecycle("r", 1, "evt-id", kEnq, "armed", "file", "rule name");
    e.journal_batch_key = "lc:deadbeefdeadbeef:000000000042";
    e.journal_last_in_batch = true;

    auto ev = guardian_outbox_entry_to_event(e, "linux");
    const std::string wire = ev.SerializeAsString();
    CHECK(wire.find("deadbeef") == std::string::npos); // the batch key appears nowhere on the wire
    // Sanity: the legitimate fields DID serialize, so the negative search above is meaningful.
    CHECK(ev.event_id() == "evt-id");
    CHECK(ev.rule_name() == "rule name");
}
