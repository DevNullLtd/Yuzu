/**
 * test_echo_source_health.cpp -- per-source collection health ledger (#1846).
 * Pure: no database, no clock (the epoch is passed in).
 */

#include "echo_schema_registry.hpp"
#include "echo_source_health.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::echo;

TEST_CASE("source health: failure classification is the closed token set", "[echo][health]") {
    for (auto t : {"capture_incomplete", "counters_unavailable", "cursor_lost", "state_unreadable",
                   "insert_failed", "state_save_failed"})
        CHECK(collect_status_is_failure(t));
    for (auto t : {"events_recorded", "baseline", "sample_recorded", "apps_recorded",
                   "cursor_advanced", "baseline_seeded", "source_disabled", "unsupported_platform"})
        CHECK_FALSE(collect_status_is_failure(t));
}

TEST_CASE("source health: streak, latest token and epoch", "[echo][health]") {
    SourceHealthLedger l;
    l.record("process", "insert_failed", 100);
    l.record("process", "insert_failed", 101);
    l.record("process", "state_save_failed", 102);
    auto h = l.get("process");
    REQUIRE(h.has_value());
    CHECK(h->consecutive_failures == 3);
    CHECK(h->last_status == "state_save_failed");
    CHECK(h->last_status_at == 102);

    l.record("process", "events_recorded", 200);
    h = l.get("process");
    CHECK(h->consecutive_failures == 0);
    CHECK(h->last_status == "events_recorded");
    CHECK(h->last_status_at == 200);

    // source_disabled resets the streak; sources are independent.
    l.record("dns", "capture_incomplete", 50);
    l.record("dns", "source_disabled", 60);
    CHECK(l.get("dns")->consecutive_failures == 0);
    CHECK(l.get("process")->last_status == "events_recorded");
    CHECK_FALSE(l.get("service").has_value());
}

TEST_CASE("source health: keyed by registry name, echo_state keys are ignored", "[echo][health]") {
    SourceHealthLedger l;
    l.record("tcp", "events_recorded", 10);
    CHECK(l.get("tcp").has_value());
    l.record("network", "insert_failed", 11); // an echo_state key, not a registry source
    CHECK_FALSE(l.get("network").has_value());
    CHECK(l.get("tcp")->consecutive_failures == 0);
}

TEST_CASE("source health: three config lines per registry source, in registry order",
          "[echo][health]") {
    SourceHealthLedger l;
    const auto& srcs = capture_sources();
    auto lines = format_source_health_lines(l, srcs);
    REQUIRE(lines.size() == srcs.size() * 3);
    for (size_t i = 0; i < srcs.size(); ++i) {
        const std::string n{srcs[i].name};
        CHECK(lines[i * 3] == "config|" + n + "_last_status|never_ran");
        CHECK(lines[i * 3 + 1] == "config|" + n + "_consecutive_failures|0");
        CHECK(lines[i * 3 + 2] == "config|" + n + "_last_status_at|0");
    }

    l.record("perf", "counters_unavailable", 1234);
    l.record("perf", "counters_unavailable", 1300);
    lines = format_source_health_lines(l, srcs);
    bool seen = false;
    for (size_t i = 0; i < srcs.size(); ++i) {
        if (srcs[i].name != "perf")
            continue;
        seen = true;
        CHECK(lines[i * 3] == "config|perf_last_status|counters_unavailable");
        CHECK(lines[i * 3 + 1] == "config|perf_consecutive_failures|2");
        CHECK(lines[i * 3 + 2] == "config|perf_last_status_at|1300");
    }
    CHECK(seen);
}

TEST_CASE("tcp_tick_status: a failed nstat lifecycle insert wins over the poll leg's own outcome",
          "[echo][health]") {
    CHECK(tcp_tick_status(true, "events_recorded") == "insert_failed");
    CHECK(tcp_tick_status(true, "state_save_failed") == "insert_failed");
    CHECK(tcp_tick_status(false, "events_recorded") == "events_recorded");
}

TEST_CASE("source health: a source in backoff prints its next retry time after its three usual lines",
          "[echo][health]") {
    SourceHealthLedger l;
    const auto& srcs = capture_sources();
    l.record("registry", "capture_incomplete", 100);
    l.record("registry", "capture_incomplete", 160);
    l.set_next_retry("registry", 460);
    const auto lines = format_source_health_lines(l, srcs);
    REQUIRE(lines.size() == srcs.size() * 3 + 1);
    std::size_t at = 0;
    for (std::size_t i = 0; i < lines.size(); ++i)
        if (lines[i] == "config|registry_last_status|capture_incomplete")
            at = i;
    REQUIRE(at > 0);
    CHECK(lines[at + 1] == "config|registry_consecutive_failures|2");
    CHECK(lines[at + 2] == "config|registry_last_status_at|160");
    CHECK(lines[at + 3] == "config|registry_next_retry_at|460");
}

TEST_CASE("source health: a source not in backoff prints no retry line and exactly one failure "
          "counter line",
          "[echo][health]") {
    SourceHealthLedger l;
    l.record("registry", "capture_incomplete", 100);
    const auto lines = format_source_health_lines(l, capture_sources());
    std::size_t retry = 0, counters = 0;
    for (const auto& line : lines) {
        retry += line.find("_next_retry_at|") != std::string::npos;
        counters += line.starts_with("config|registry_") &&
                    line.find("_consecutive_failures|") != std::string::npos;
    }
    CHECK(retry == 0);
    CHECK(counters == 1);
}

TEST_CASE("source health: clearing the next retry removes the line and leaves the failure counter "
          "as recorded",
          "[echo][health]") {
    SourceHealthLedger l;
    l.record("registry", "capture_incomplete", 100);
    l.record("registry", "capture_incomplete", 160);
    l.set_next_retry("registry", 460);
    REQUIRE(l.next_retry("registry") == 460);
    l.clear_next_retry("registry");
    CHECK_FALSE(l.next_retry("registry").has_value());
    CHECK(l.get("registry")->consecutive_failures == 2);
    CHECK(format_source_health_lines(l, capture_sources()).size() ==
          capture_sources().size() * 3);
}
