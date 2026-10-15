// Tests for yuzu/agent/es_client.hpp -- pure Endpoint Security helpers
// relocated from tar_proc_es.cpp (A0, macOS Spark/Reflex/DEX programme).
// Every case is pure integer arithmetic, run on every host.

#include <yuzu/agent/es_client.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("es_seq_gap counts only forward jumps and never underflows", "[agent][es_client]") {
    using yuzu::agent::es_seq_gap;
    // Consecutive seq → no gap.
    REQUIRE(es_seq_gap(10, 11) == 0);
    // A forward jump means the kernel dropped the messages in between.
    REQUIRE(es_seq_gap(10, 14) == 3); // 11,12,13 lost
    REQUIRE(es_seq_gap(0, 5) == 4);
    // Duplicate (equal) or a backward jump (a client re-create resets the per-type
    // counter) must yield 0 — never an unsigned underflow into a huge bogus count.
    REQUIRE(es_seq_gap(10, 10) == 0);
    REQUIRE(es_seq_gap(10, 2) == 0);
    REQUIRE(es_seq_gap(10, 0) == 0);
}

TEST_CASE("es_stream_is_stalled measures idle from the later of last-event/start",
          "[agent][es_client]") {
    using yuzu::agent::es_stream_is_stalled;
    const std::int64_t threshold = 3600;
    const std::int64_t start = 1'700'000'000;

    // Fresh start, no event yet (last_event_ts == 0): idle measured from start.
    REQUIRE_FALSE(es_stream_is_stalled(0, start, start + 100, threshold));  // quiet but young
    REQUIRE(es_stream_is_stalled(0, start, start + 3601, threshold));       // silent past threshold

    // Once events have arrived, idle is measured from the LAST event, not start.
    const std::int64_t last = start + 10'000;
    REQUIRE_FALSE(es_stream_is_stalled(last, start, last + 60, threshold)); // recent event
    REQUIRE(es_stream_is_stalled(last, start, last + 3601, threshold));     // silent since last

    // Neither set (clock never initialised) → never stalls (no spurious fallback).
    REQUIRE_FALSE(es_stream_is_stalled(0, 0, 9'999, threshold));
    // Backward clock step (now < since) → negative delta → not stalled (benign).
    REQUIRE_FALSE(es_stream_is_stalled(last, start, last - 500, threshold));
}
